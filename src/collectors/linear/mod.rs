//! The Linear collector: provider `linear`, pulled by the worker through the
//! GraphQL API with a personal API key or an OAuth token (ADR 0008 D8).
//!
//! One instance reads one organization, pinned by its id (the instance's
//! provider scope id, a lowercase UUID), and one container per configured
//! team (`linear.team`, by team id). The credential comes from the
//! environment variable `settings.token_env` names; a personal key
//! (`lin_api_...`) is sent as the `Authorization` header itself, anything else
//! as a `Bearer` token ([`crate::collectors::http`]).
//!
//! # A pass
//!
//! Every pass is a **reconciliation**: each tick sweeps every team for what
//! changed since the last complete sweep, and records coverage.
//!
//! 1. `FleetRecallLinearScope`: the credential's organization must be the
//!    pin, or the pass fails before it reads anything; the same answer gives
//!    each configured team's key and visibility.
//! 2. For each team, in id order: a `public` team is `team_public`; any other
//!    visibility is admitted `operator_declared` only when
//!    `audience.private_containers` lists the team, else the team is never
//!    read and its observation withdraws what was admitted through it (it is
//!    then outside the pass's domain). A configured team the credential
//!    cannot see (deleted, or made private to people the credential's user is
//!    not among) is a narrowing too, unless listed: it is observed as
//!    restricted, which withdraws it, and is outside the domain. A listed one
//!    the credential cannot see is partial. Nothing either held is held
//!    current.
//! 3. The team's issues, then the comments on its issues, are each swept with
//!    `updatedAt` after the sweep's high-water mark less `overlap_seconds`
//!    (the whole team the first time), `orderBy: updatedAt`,
//!    `includeArchived: true`, paged on `endCursor` until `hasNextPage` is
//!    false. Each page is one sink transaction, with the team's cursor: a sweep
//!    cut short (a rate limit, the page budget, a failed page) resumes on the
//!    next pass from the page after the last one staged, under the same
//!    filter. A sweep that reached its end moves the high-water mark to the
//!    newest `updatedAt` it read (never past the pass's instant), unless it
//!    read a node it could not stage: then it is read again from where it
//!    started.
//! 4. Every issue and comment becomes a draft ([`render`]). One whose
//!    content, lifecycle, and team the memory already holds, and that is not
//!    withdrawn, is kept at its known version, even when its `updatedAt`
//!    moved (a label or an assignee changed), so an overlap re-read, or a
//!    change that is not content, mints nothing.
//! 5. **Moves in.** An issue staged live that the memory held in another
//!    team, in the trash, withdrawn, or never (when it is older than the
//!    comment sweep's mark) has comments whose `updatedAt` the comment sweep
//!    has passed: the team's cursor queues it, and after the sweeps each
//!    queued issue's comments are read whole (`issue: { id }`, no time
//!    bound). Past [`MAX_BACKFILL`] queued issues, the team's comment sweep
//!    reads every comment instead.
//! 6. **Moves out.** The sweeps are filtered by team, so they never return an
//!    issue moved into a team the pass does not admit, or one the credential
//!    can no longer see. Each pass checks a rotating batch of the issues the
//!    memory holds in the teams it read that the sweeps did not return
//!    (`FleetRecallLinearIssueTeams`, [`VERIFY_CURSOR_DOMAIN`]): each one now
//!    in a team the pass does not admit, or missing from the answer, is
//!    withdrawn with every comment the memory holds on it, with content-free
//!    observations ([`super::pull::withdrawal`]); a later read of it in an
//!    admitted team lifts that.
//! 7. Every item the memory holds in a team the pass read, and that the
//!    sweeps did not return, is unchanged since the sweeps' start and is held
//!    current too, unless it is withdrawn, so the pass's manifest names every
//!    current item.
//! 8. A team is complete when both sweeps and its queued comment reads
//!    reached their end and everything the pass holds current in it was
//!    admitted.
//!
//! A trashed issue is a `trashed` tombstone, which hides it, and Linear's
//! trash hides everything on it: the comments the memory holds on it are
//! withdrawn, a comment on it is never staged, and restoring it reads its
//! comments whole again, which lifts them. An archived issue stays
//! searchable. A permanently deleted comment is only seen by a webhook.
//!
//! # Partial reads
//!
//! Every call counts against `max_pages_per_tick`. A rate limit (HTTP 429, or
//! `RATELIMITED`) or the page budget ends the pass: the team in progress and
//! every later one are partial, and their sweeps resume on the next pass.
//! Another refusal of one page (`FORBIDDEN`, an unusable cursor) leaves that
//! team partial, and its sweep starts over on the next pass; a failed request
//! (a `5xx`) leaves it partial and resumable. A refused credential
//! (`AUTHENTICATION_ERROR`, HTTP 401 or 403) fails the pass. The
//! `x-ratelimit-*` headers of every answer are reported in the pass's
//! counters: the fewest requests and complexity points Linear said were left.

pub mod fetch;
pub mod graphql;
pub mod push;
pub mod render;

use std::collections::{BTreeMap, BTreeSet};

use async_trait::async_trait;
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{FleetError, Result};
use crate::memory_contracts::collected_item::{
    CollectionModeV1, ContainerKindV1, ObjectKindV1, ProviderKindV1, timestamp_micros,
};
use crate::memory_contracts::coverage::CoverageProofMethodV1;
use crate::memory_contracts::digest::Sha256Digest;
use crate::worker::CollectorSourceV1;

use super::CollectorAdapterV1;
use super::audience::{
    AudienceDecisionV1, AudienceInputV1, KnownContainerV1, ProviderAudienceV1, classify,
};
use super::cockroach::framed_sha256;
use super::draft::CollectedItemDraftV1;
use super::http::{
    AuthSchemeV1, ProviderHttpV1, ProviderTokenV1, validate_provider_api_base,
    validate_token_variable,
};
use super::ingress::PushVerifierV1;
use super::pull::{
    ContainerOutcomeV1, ListingBoundV1, ObjectFetcherV1, PageStager, PartialReasonV1,
    PullCollectorV1, PullPassInputV1, PullPassOutcomeV1, PulledItemV1, WithdrawnItemV1, withdrawal,
};
use super::sink::{ContainerObservationV1, CursorAdvanceV1, DeadLetterReasonV1, KnownVersionV1};
use graphql::{
    LinearApiV1, LinearCallErrorV1, LinearCommentV1, LinearIssueV1, LinearTeamV1,
    MAX_ISSUE_TEAMS_BATCH, PageNodeV1, RateLimitV1,
};
use render::{
    COMMENT_OBJECT_KIND, CommentDraftV1, ISSUE_OBJECT_KIND, LINEAR_PROVIDER, LinearTeamContextV1,
    TEAM_CONTAINER_KIND, comment_draft, is_lowercase_uuid, issue_draft, linear_object_kind,
    linear_order,
};

/// The GraphQL endpoint a collector reads unless its settings say otherwise.
pub const DEFAULT_LINEAR_API_URL: &str = "https://api.linear.app/graphql";

/// The only host a collector sends its credential to, unless its base is
/// loopback (a local fake provider).
pub const LINEAR_API_HOST: &str = "api.linear.app";

/// Seconds a sweep re-reads before its high-water mark, unless the settings
/// say otherwise: what a change committed late with an earlier `updatedAt`
/// needs.
pub const DEFAULT_OVERLAP_SECONDS: u64 = 300;
/// The largest `overlap_seconds`.
pub const MAX_OVERLAP_SECONDS: u64 = 86_400;
/// Calls one pass makes at most, unless the settings say otherwise.
pub const DEFAULT_MAX_PAGES_PER_TICK: u32 = 500;
/// The largest `max_pages_per_tick`.
pub const MAX_PAGES_PER_TICK: u32 = 10_000;
/// Nodes one page asks for, unless the settings say otherwise.
pub const DEFAULT_PAGE_SIZE: u32 = 50;
/// The largest `page_size` Linear accepts.
pub const MAX_PAGE_SIZE: u32 = 250;
/// Teams one instance reads at most.
pub const MAX_TEAMS: usize = 100;

/// The prefix of a Linear personal API key, which is sent without `Bearer`.
const PERSONAL_KEY_PREFIX: &str = "lin_api_";

/// The longest `endCursor` a sweep resumes from; a longer one ends the sweep
/// as unreadable.
const MAX_PAGE_CURSOR_BYTES: usize = 2_048;

const CURSOR_SCHEMA_VERSION: u32 = 1;

/// The cursor domain of one team.
#[must_use]
pub fn team_cursor_domain(team: &str) -> String {
    format!("linear.team:{team}")
}

/// The cursor domain of the rotation that checks where held issues are now.
pub const VERIFY_CURSOR_DOMAIN: &str = "linear.verify";

/// Issues a team's cursor queues for a whole read of their comments, at
/// most; past it, the team's comment sweep reads every comment instead.
const MAX_BACKFILL: usize = 64;

/// Every counter a Linear pass reports.
pub const LINEAR_COUNTERS: [&str; 26] = [
    "api_calls",
    "teams_refused",
    "teams_missing",
    "issues_verified",
    "issues_withdrawn",
    "comments_withdrawn",
    "comment_backfills",
    "comment_sweeps_widened",
    "issues_read",
    "issues_staged",
    "issues_unchanged",
    "comments_read",
    "comments_staged",
    "comments_unchanged",
    "comments_skipped",
    "nodes_dead_lettered",
    "tombstones",
    "sweeps_resumed",
    "rate_limited",
    "provider_refused",
    "http_errors",
    "page_budget_exhausted",
    "cursors_reset",
    "ratelimit_reports",
    "ratelimit_requests_remaining",
    "ratelimit_complexity_remaining",
];

const fn default_overlap_seconds() -> u64 {
    DEFAULT_OVERLAP_SECONDS
}

const fn default_max_pages_per_tick() -> u32 {
    DEFAULT_MAX_PAGES_PER_TICK
}

const fn default_page_size() -> u32 {
    DEFAULT_PAGE_SIZE
}

fn default_api_url() -> String {
    DEFAULT_LINEAR_API_URL.to_owned()
}

/// A Linear organization's settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinearSettingsV1 {
    /// The environment variable holding the credential: a personal API key
    /// (`lin_api_...`) or an OAuth access token.
    pub token_env: String,
    /// The teams to read, by id (lowercase UUIDs), never by key.
    pub teams: Vec<String>,
    /// Seconds each sweep re-reads before its high-water mark.
    #[serde(default = "default_overlap_seconds")]
    pub overlap_seconds: u64,
    /// Calls one pass makes at most.
    #[serde(default = "default_max_pages_per_tick")]
    pub max_pages_per_tick: u32,
    /// Nodes one page asks for.
    #[serde(default = "default_page_size")]
    pub page_size: u32,
    /// The GraphQL endpoint: https, or http to a loopback host.
    #[serde(default = "default_api_url")]
    pub api_url: String,
}

/// Split a GraphQL endpoint into the HTTP seam's API base and the method path
/// under it: `https://api.linear.app/graphql` is `https://api.linear.app/`
/// and `graphql`.
///
/// # Errors
///
/// What [`validate_provider_api_base`] refuses, and an endpoint with no
/// path.
pub fn split_endpoint(raw: &str) -> std::result::Result<(String, String), String> {
    let url = validate_provider_api_base(raw, LINEAR_API_HOST)?;
    let path = url.path().trim_end_matches('/').to_owned();
    let (parent, method) = path.rsplit_once('/').unwrap_or(("", path.as_str()));
    if method.is_empty() {
        return Err("the api url names no GraphQL endpoint path (such as /graphql)".to_owned());
    }
    let mut base = url;
    base.set_path(&format!("{parent}/"));
    Ok((base.to_string(), method.to_owned()))
}

impl LinearSettingsV1 {
    /// Parse and validate one source's settings.
    ///
    /// # Errors
    ///
    /// A message naming the first refused setting.
    pub fn from_source(source: &CollectorSourceV1) -> std::result::Result<Self, String> {
        let settings: Self =
            serde_json::from_value(serde_json::Value::Object(source.settings.clone()))
                .map_err(|error| format!("settings: {error}"))?;
        settings.validate()?;
        Ok(settings)
    }

    fn validate(&self) -> std::result::Result<(), String> {
        validate_token_variable(LINEAR_PROVIDER, &self.token_env)?;
        if self.teams.is_empty() || self.teams.len() > MAX_TEAMS {
            return Err(format!("settings.teams lists 1 to {MAX_TEAMS} team ids"));
        }
        let mut seen = BTreeSet::new();
        for team in &self.teams {
            if !is_lowercase_uuid(team) {
                return Err(format!(
                    "settings.teams: {team:?} is not a team id (a lowercase UUID; a team key \
                     such as ENG is a label, not an id)"
                ));
            }
            if !seen.insert(team) {
                return Err(format!("settings.teams lists {team} twice"));
            }
        }
        if self.overlap_seconds > MAX_OVERLAP_SECONDS {
            return Err(format!(
                "settings.overlap_seconds must be at most {MAX_OVERLAP_SECONDS}"
            ));
        }
        if !(1..=MAX_PAGES_PER_TICK).contains(&self.max_pages_per_tick) {
            return Err(format!(
                "settings.max_pages_per_tick must be between 1 and {MAX_PAGES_PER_TICK}"
            ));
        }
        if !(1..=MAX_PAGE_SIZE).contains(&self.page_size) {
            return Err(format!(
                "settings.page_size must be between 1 and {MAX_PAGE_SIZE}"
            ));
        }
        split_endpoint(&self.api_url).map_err(|error| format!("settings.api_url: {error}"))?;
        Ok(())
    }
}

/// How a credential is presented: a personal key as the header itself, an
/// OAuth token as `Bearer`.
#[must_use]
pub fn auth_scheme(token: &ProviderTokenV1) -> AuthSchemeV1 {
    if token.expose().starts_with(PERSONAL_KEY_PREFIX) {
        AuthSchemeV1::Plain
    } else {
        AuthSchemeV1::Bearer
    }
}

/// The Linear adapter.
#[derive(Debug, Clone, Copy, Default)]
pub struct LinearAdapterV1;

impl CollectorAdapterV1 for LinearAdapterV1 {
    fn provider(&self) -> &'static str {
        LINEAR_PROVIDER
    }

    fn validate(&self, source: &CollectorSourceV1) -> std::result::Result<(), String> {
        LinearSettingsV1::from_source(source)?;
        if !is_lowercase_uuid(source.provider_scope_id.as_str()) {
            return Err(
                "provider_scope_id must be the Linear organization id, a lowercase UUID".to_owned(),
            );
        }
        if source.audience.operator_declared {
            return Err("a Linear organization has an audience per team: leave \
                 audience.operator_declared false, and list private or restricted teams in \
                 audience.private_containers"
                .to_owned());
        }
        if let Some(container) = source
            .audience
            .private_containers
            .iter()
            .find(|container| !is_lowercase_uuid(container))
        {
            return Err(format!(
                "audience.private_containers: {container:?} is not a team id (a lowercase UUID)"
            ));
        }
        Ok(())
    }

    fn pull(
        &self,
        source: &CollectorSourceV1,
        environment: &dyn Fn(&str) -> Option<String>,
    ) -> std::result::Result<Option<Box<dyn PullCollectorV1>>, String> {
        let settings = LinearSettingsV1::from_source(source)?;
        let token = ProviderTokenV1::from_environment(&settings.token_env, environment)
            .map_err(|error| error.to_string())?;
        let (base, endpoint) = split_endpoint(&settings.api_url)?;
        let http = ProviderHttpV1::new(&base, &token, auth_scheme(&token))
            .map_err(|error| error.to_string())?;
        Ok(Some(Box::new(LinearPullV1 {
            api: LinearApiV1::new(http, endpoint, settings.page_size),
            settings,
        })))
    }

    fn fetch_object(
        &self,
        source: &CollectorSourceV1,
        environment: &dyn Fn(&str) -> Option<String>,
    ) -> std::result::Result<Option<Box<dyn ObjectFetcherV1>>, String> {
        let settings = LinearSettingsV1::from_source(source)?;
        let token = ProviderTokenV1::from_environment(&settings.token_env, environment)
            .map_err(|error| error.to_string())?;
        let (base, endpoint) = split_endpoint(&settings.api_url)?;
        let http = ProviderHttpV1::new(&base, &token, auth_scheme(&token))
            .map_err(|error| error.to_string())?;
        let api = LinearApiV1::new(http, endpoint, settings.page_size);
        Ok(Some(Box::new(fetch::LinearFetchV1::new(settings, api))))
    }

    fn push(&self) -> Option<&'static dyn PushVerifierV1> {
        Some(&push::LINEAR_PUSH)
    }
}

/// A sweep cut short, and where it resumes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResumeV1 {
    /// The sweep's lower bound in microseconds (exclusive); `None` reads the
    /// whole team.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    since: Option<u64>,
    /// Linear's `endCursor` of the last page staged.
    after: String,
    /// The newest `updatedAt` the sweep has read, in microseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    newest: Option<u64>,
    /// The sweep read a node it could not stage.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    blemished: bool,
}

/// Where one of a team's sweeps stands.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SweepCursorV1 {
    /// The newest `updatedAt` (microseconds) a complete sweep read, never
    /// past its pass's instant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    high_water: Option<u64>,
    /// A sweep cut short.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resume: Option<ResumeV1>,
}

/// Where one team's sweeps stand.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TeamCursorV1 {
    schema_version: u32,
    #[serde(default)]
    issues: SweepCursorV1,
    #[serde(default)]
    comments: SweepCursorV1,
    /// Issues whose comments must be read whole, by id: an issue that moved
    /// into the team, came back from the trash, or was withdrawn, since its
    /// comments kept an `updatedAt` the comment sweep has passed.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    backfill: BTreeSet<String>,
}

/// Where the rotation that checks held issues stands.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifyCursorV1 {
    schema_version: u32,
    /// The last issue id the rotation checked; the next pass starts after it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    after: Option<String>,
}

impl TeamCursorV1 {
    fn fresh() -> Self {
        Self {
            schema_version: CURSOR_SCHEMA_VERSION,
            ..Self::default()
        }
    }

    const fn sweep(&self, sweep: SweepV1) -> &SweepCursorV1 {
        match sweep {
            SweepV1::Issues => &self.issues,
            SweepV1::Comments => &self.comments,
        }
    }

    const fn sweep_mut(&mut self, sweep: SweepV1) -> &mut SweepCursorV1 {
        match sweep {
            SweepV1::Issues => &mut self.issues,
            SweepV1::Comments => &mut self.comments,
        }
    }

    /// Decode a stored cursor; `None` (counted) when it does not decode, and
    /// the team is then swept as if for the first time, which is safe.
    fn decode(bytes: &[u8], counters: &mut BTreeMap<&'static str, u64>) -> Option<Self> {
        let decoded = serde_json::from_slice::<Self>(bytes)
            .ok()
            .filter(|cursor| cursor.schema_version == CURSOR_SCHEMA_VERSION);
        if decoded.is_none() {
            *counters.entry("cursors_reset").or_insert(0) += 1;
        }
        decoded
    }

    /// Queue issues for a whole read of their comments; whether the queue
    /// changed. Past [`MAX_BACKFILL`], the team's comment sweep reads every
    /// comment instead, from this pass on.
    fn queue(&mut self, issues: &[String], state: &mut PassStateV1) -> bool {
        let mut queued = false;
        for issue in issues {
            queued |= self.backfill.insert(issue.clone());
        }
        if self.backfill.len() > MAX_BACKFILL {
            self.backfill.clear();
            self.comments = SweepCursorV1::default();
            state.bump("comment_sweeps_widened");
        }
        queued
    }

    fn advance(&self, domain_key: &str, pass_seq: u64) -> Result<CursorAdvanceV1> {
        Ok(CursorAdvanceV1 {
            domain_key: domain_key.to_owned(),
            cursor_state: serde_json::to_vec(self)
                .map_err(|error| FleetError::Memory(format!("a Linear cursor: {error}")))?,
            high_water_order: self.issues.high_water,
            pass_seq,
        })
    }
}

/// Where a sweep starts: its filter's lower bound, the page it resumes
/// after, and what it read before it was cut short.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SweepStartV1 {
    since: Option<u64>,
    after: Option<String>,
    newest: Option<u64>,
    blemished: bool,
    resumed: bool,
}

impl SweepCursorV1 {
    fn start(&self, overlap_micros: u64) -> SweepStartV1 {
        self.resume.as_ref().map_or_else(
            || SweepStartV1 {
                since: self
                    .high_water
                    .map(|high_water| high_water.saturating_sub(overlap_micros)),
                after: None,
                newest: None,
                blemished: false,
                resumed: false,
            },
            |resume| SweepStartV1 {
                since: resume.since,
                after: Some(resume.after.clone()),
                newest: resume.newest,
                blemished: resume.blemished,
                resumed: true,
            },
        )
    }
}

/// An instant in microseconds as Linear's filters take it: RFC 3339 in UTC,
/// cut to milliseconds (never later than the instant).
fn linear_instant(micros: u64) -> Option<String> {
    let instant = DateTime::<Utc>::from_timestamp_micros(i64::try_from(micros).ok()?)?;
    Some(instant.to_rfc3339_opts(SecondsFormat::Millis, true))
}

/// An id Linear sent, cut to the characters an id has, for a message.
fn shown_id(value: &str) -> String {
    value
        .chars()
        .filter(|scalar| scalar.is_ascii_alphanumeric() || *scalar == '-')
        .take(64)
        .collect()
}

/// Which of a team's listings a sweep reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SweepV1 {
    Issues,
    Comments,
}

impl SweepV1 {
    /// Its counters: nodes read, staged, and kept unchanged.
    const fn counters(self) -> [&'static str; 3] {
        match self {
            Self::Issues => ["issues_read", "issues_staged", "issues_unchanged"],
            Self::Comments => ["comments_read", "comments_staged", "comments_unchanged"],
        }
    }
}

/// State one pass shares across its teams.
struct PassStateV1 {
    budget: u32,
    stop: Option<PartialReasonV1>,
    counters: BTreeMap<&'static str, u64>,
    /// Issues and comments the sweeps returned, by id.
    seen_issues: BTreeSet<String>,
    seen_comments: BTreeSet<String>,
    /// Issues in the trash, as far as the memory and this pass know.
    trashed_issues: BTreeSet<String>,
    /// Items this pass withdrew: never held current.
    withdrawn_now: BTreeSet<String>,
}

impl PassStateV1 {
    fn new(budget: u32) -> Self {
        Self {
            budget,
            stop: None,
            counters: LINEAR_COUNTERS.iter().map(|key| (*key, 0)).collect(),
            seen_issues: BTreeSet::new(),
            seen_comments: BTreeSet::new(),
            trashed_issues: BTreeSet::new(),
            withdrawn_now: BTreeSet::new(),
        }
    }

    fn bump(&mut self, key: &'static str) {
        *self.counters.entry(key).or_insert(0) += 1;
    }

    /// Spend one call of the budget; `false`, and the pass stops, when it is
    /// spent.
    fn take_call(&mut self) -> bool {
        if self.budget == 0 {
            self.stop = Some(PartialReasonV1::ListingBound);
            self.bump("page_budget_exhausted");
            return false;
        }
        self.budget -= 1;
        self.bump("api_calls");
        true
    }

    /// Keep the fewest requests and complexity points Linear said were left.
    fn rate(&mut self, rate: RateLimitV1) {
        if !rate.reported() {
            return;
        }
        let first = self.counters.get("ratelimit_reports").copied().unwrap_or(0) == 0;
        self.bump("ratelimit_reports");
        for (key, value) in [
            ("ratelimit_requests_remaining", rate.requests_remaining),
            ("ratelimit_complexity_remaining", rate.complexity_remaining),
        ] {
            if let Some(value) = value {
                let entry = self.counters.entry(key).or_insert(value);
                *entry = if first { value } else { (*entry).min(value) };
            }
        }
    }

    /// What a failed call makes of the team in progress; a refused
    /// credential fails the pass.
    fn refusal(&mut self, error: LinearCallErrorV1) -> Result<PartialReasonV1> {
        match error {
            LinearCallErrorV1::RateLimited => {
                self.bump("rate_limited");
                self.stop = Some(PartialReasonV1::RateLimited);
                Ok(PartialReasonV1::RateLimited)
            }
            LinearCallErrorV1::Credential(code) => Err(FleetError::Configuration(format!(
                "Linear refused the collector's credential ({code}); nothing more was read"
            ))),
            LinearCallErrorV1::Refused(_) => {
                self.bump("provider_refused");
                Ok(PartialReasonV1::ProviderRefused)
            }
            LinearCallErrorV1::Http(_) | LinearCallErrorV1::Malformed(_) => {
                self.bump("http_errors");
                Ok(PartialReasonV1::Unreadable)
            }
        }
    }
}

/// What one page's nodes became.
#[derive(Default)]
struct PageItemsV1 {
    items: Vec<PulledItemV1>,
    newest: Option<u64>,
    blemished: bool,
    /// Issues whose comments must be read whole.
    backfill: Vec<String>,
}

/// What the memory holds, as one pass reads it.
struct HeldV1<'k> {
    issues: &'k BTreeMap<String, KnownVersionV1>,
    comments: &'k BTreeMap<String, KnownVersionV1>,
    /// The comments the memory holds on each issue, by issue id.
    comments_by_issue: &'k BTreeMap<String, Vec<String>>,
    /// Every configured team the pass admits, by id.
    admitted_teams: &'k BTreeSet<String>,
}

impl HeldV1<'_> {
    /// A content-free withdrawal of one comment the memory holds, unless it
    /// is withdrawn already; whether one was added.
    fn withdraw_comment(
        &self,
        provider: &ProviderKindV1,
        scope: &str,
        comment: &str,
        state: &mut PassStateV1,
        items: &mut Vec<PulledItemV1>,
    ) -> bool {
        let Some(known) = self
            .comments
            .get(comment)
            .filter(|known| !known.lifecycle.is_tombstone() && !known.withdrawn)
        else {
            return false;
        };
        if !state.withdrawn_now.insert(comment.to_owned()) {
            return false;
        }
        state.bump("comments_withdrawn");
        items.push(withdrawal(
            &WithdrawnItemV1 {
                provider,
                provider_scope_id: scope,
                object_kind: &linear_object_kind(COMMENT_OBJECT_KIND),
                external_id: comment,
                order_micros: known.provider_order,
            },
            None,
        ));
        true
    }

    /// Content-free withdrawals of every comment the memory holds on
    /// `issue`.
    fn withdraw_comments(
        &self,
        provider: &ProviderKindV1,
        scope: &str,
        issue: &str,
        state: &mut PassStateV1,
        items: &mut Vec<PulledItemV1>,
    ) {
        for comment in self.comments_by_issue.get(issue).into_iter().flatten() {
            self.withdraw_comment(provider, scope, comment, state, items);
        }
    }
}

/// One team's read in one pass.
struct TeamReadV1<'k> {
    provider: ProviderKindV1,
    scope: String,
    team: String,
    label: Option<String>,
    key: Sha256Digest,
    audience: ProviderAudienceV1,
    held: &'k HeldV1<'k>,
    /// The comment sweep's lower bound this pass (microseconds), when it
    /// reads only what changed.
    comments_since: Option<u64>,
}

impl TeamReadV1<'_> {
    fn context(&self) -> LinearTeamContextV1<'_> {
        LinearTeamContextV1 {
            provider: &self.provider,
            provider_scope_id: &self.scope,
            team_id: &self.team,
            team_key: self.label.as_deref(),
            admitted_teams: self.held.admitted_teams,
        }
    }

    /// Whether an issue staged live in this team needs its comments read
    /// whole: the memory held it in another team, in the trash, withdrawn, or
    /// never, while the comment sweep reads only what changed since a mark
    /// its comments may be older than.
    fn needs_backfill(&self, held: Option<&KnownVersionV1>, draft: &CollectedItemDraftV1) -> bool {
        held.map_or_else(
            || {
                self.comments_since.is_some_and(|since| {
                    draft
                        .created_at
                        .as_ref()
                        .and_then(|created| timestamp_micros(created).ok())
                        .is_none_or(|created| created <= since)
                })
            },
            |known| {
                known.container_key != Some(self.key)
                    || known.lifecycle.is_tombstone()
                    || known.withdrawn
            },
        )
    }

    /// Dead-letter a node that did not become a draft; the team is partial.
    async fn refuse(
        &self,
        stager: &mut PageStager<'_>,
        state: &mut PassStateV1,
        page: &mut PageItemsV1,
        reason: DeadLetterReasonV1,
        digest: Sha256Digest,
        diagnostic: &str,
    ) -> Result<()> {
        page.blemished = true;
        state.bump("nodes_dead_lettered");
        stager
            .dead_letter(Some(self.key), reason, digest, diagnostic)
            .await
    }

    /// Stage a draft, or keep the version the memory holds when its content,
    /// lifecycle, and team are unchanged and it is not withdrawn (staging is
    /// what lifts a withdrawal).
    ///
    /// Linear's trash hides an issue with everything on it: an issue staged
    /// into the trash withdraws the comments the memory holds on it, and a
    /// comment on an issue in the trash is never staged. An issue staged
    /// live that [`TeamReadV1::needs_backfill`] queues its comments for a
    /// whole read.
    fn consider(
        &self,
        draft: CollectedItemDraftV1,
        sweep: SweepV1,
        stager: &mut PageStager<'_>,
        state: &mut PassStateV1,
        page: &mut PageItemsV1,
    ) {
        let [_, staged_counter, kept_counter] = sweep.counters();
        page.newest = page.newest.max(Some(draft.order_micros));
        let known = match sweep {
            SweepV1::Issues => {
                state.seen_issues.insert(draft.external_id.clone());
                self.held.issues
            }
            SweepV1::Comments => {
                state.seen_comments.insert(draft.external_id.clone());
                self.held.comments
            }
        };
        if sweep == SweepV1::Comments
            && let Some(thread) = &draft.thread
            && state.trashed_issues.contains(&thread.root_external_id)
        {
            if !self.held.withdraw_comment(
                &self.provider,
                &self.scope,
                &draft.external_id,
                state,
                &mut page.items,
            ) {
                state.bump("comments_skipped");
            }
            return;
        }
        let digest = stager.content_digest(&draft);
        if digest.is_none() {
            // Staging will refuse it: the sweep must read it again.
            page.blemished = true;
        }
        let held = known.get(&draft.external_id);
        if let Some(known) = held
            && !known.withdrawn
            && known.lifecycle == draft.lifecycle
            && known.container_key == Some(self.key)
            && digest == Some(known.content_digest)
        {
            state.bump(kept_counter);
            stager.keep(Some(self.key), known);
            return;
        }
        state.bump(staged_counter);
        if sweep == SweepV1::Issues {
            if draft.lifecycle.is_tombstone() {
                state.trashed_issues.insert(draft.external_id.clone());
                self.held.withdraw_comments(
                    &self.provider,
                    &self.scope,
                    &draft.external_id,
                    state,
                    &mut page.items,
                );
            } else {
                state.trashed_issues.remove(&draft.external_id);
                if self.needs_backfill(held, &draft) {
                    page.backfill.push(draft.external_id.clone());
                }
            }
        }
        if draft.lifecycle.is_tombstone() {
            state.bump("tombstones");
        }
        page.items.push(PulledItemV1 {
            draft,
            provider_audience: Some(self.audience),
        });
    }

    async fn issues(
        &self,
        nodes: Vec<PageNodeV1<LinearIssueV1>>,
        stager: &mut PageStager<'_>,
        state: &mut PassStateV1,
    ) -> Result<PageItemsV1> {
        let mut page = PageItemsV1::default();
        for node in nodes {
            let issue = match node {
                PageNodeV1::Node(issue) => issue,
                PageNodeV1::Malformed(digest) => {
                    self.refuse(
                        stager,
                        state,
                        &mut page,
                        DeadLetterReasonV1::ParseFailed,
                        digest,
                        "a Linear issue is not the documented shape",
                    )
                    .await?;
                    continue;
                }
            };
            state.bump(SweepV1::Issues.counters()[0]);
            match issue_draft(&self.context(), &issue) {
                Ok(draft) => self.consider(draft, SweepV1::Issues, stager, state, &mut page),
                Err(diagnostic) => {
                    let digest = node_digest(&self.team, &issue.id, &issue.updated_at);
                    self.refuse(
                        stager,
                        state,
                        &mut page,
                        DeadLetterReasonV1::ValidationFailed,
                        digest,
                        diagnostic,
                    )
                    .await?;
                }
            }
        }
        Ok(page)
    }

    async fn comments(
        &self,
        nodes: Vec<PageNodeV1<LinearCommentV1>>,
        stager: &mut PageStager<'_>,
        state: &mut PassStateV1,
    ) -> Result<PageItemsV1> {
        let mut page = PageItemsV1::default();
        for node in nodes {
            let comment = match node {
                PageNodeV1::Node(comment) => comment,
                PageNodeV1::Malformed(digest) => {
                    self.refuse(
                        stager,
                        state,
                        &mut page,
                        DeadLetterReasonV1::ParseFailed,
                        digest,
                        "a Linear comment is not the documented shape",
                    )
                    .await?;
                    continue;
                }
            };
            state.bump(SweepV1::Comments.counters()[0]);
            match comment_draft(&self.context(), &comment) {
                Ok(CommentDraftV1::Item(draft)) => {
                    self.consider(*draft, SweepV1::Comments, stager, state, &mut page);
                }
                Ok(CommentDraftV1::Skip) => state.bump("comments_skipped"),
                Err(diagnostic) => {
                    let digest = node_digest(&self.team, &comment.id, &comment.updated_at);
                    self.refuse(
                        stager,
                        state,
                        &mut page,
                        DeadLetterReasonV1::ValidationFailed,
                        digest,
                        diagnostic,
                    )
                    .await?;
                }
            }
        }
        Ok(page)
    }
}

/// The digest a refused node is dead-lettered under.
fn node_digest(team: &str, id: &str, updated_at: &str) -> Sha256Digest {
    framed_sha256(
        "ostk-linear-node-v1",
        &[team.as_bytes(), id.as_bytes(), updated_at.as_bytes()],
    )
}

/// What one team's read ended as.
enum TeamEndV1 {
    /// Outside the pass's domain: its audience is refused.
    Outside,
    /// In the domain, read this far.
    Listed(ListingBoundV1),
}

/// Everything one team's read is given.
struct TeamInputV1<'a> {
    input: &'a PullPassInputV1<'a>,
    /// The team id, as the settings name it.
    id: &'a str,
    info: &'a LinearTeamV1,
    key: Sha256Digest,
    held: &'a HeldV1<'a>,
}

/// One page of either listing, fetched and turned into items.
struct SweptPageV1 {
    items: PageItemsV1,
    next_cursor: Option<String>,
    unfinished: bool,
}

/// The Linear pull collector for one configured organization.
#[derive(Debug, Clone)]
pub struct LinearPullV1 {
    settings: LinearSettingsV1,
    api: LinearApiV1,
}

impl LinearPullV1 {
    /// A collector over `settings` through `api`.
    #[must_use]
    pub const fn new(settings: LinearSettingsV1, api: LinearApiV1) -> Self {
        Self { settings, api }
    }

    /// Fetch one page of `sweep` and turn its nodes into items.
    async fn fetch(
        &self,
        sweep: SweepV1,
        read: &TeamReadV1<'_>,
        since: Option<&str>,
        after: Option<&str>,
        state: &mut PassStateV1,
        stager: &mut PageStager<'_>,
    ) -> Result<std::result::Result<SweptPageV1, LinearCallErrorV1>> {
        Ok(match sweep {
            SweepV1::Issues => match self.api.issues_page(&read.team, since, after).await {
                Ok(page) => {
                    state.rate(page.rate);
                    Ok(SweptPageV1 {
                        items: read.issues(page.nodes, stager, state).await?,
                        next_cursor: page.next_cursor,
                        unfinished: page.unfinished,
                    })
                }
                Err(error) => Err(error),
            },
            SweepV1::Comments => match self.api.comments_page(&read.team, since, after).await {
                Ok(page) => {
                    state.rate(page.rate);
                    Ok(SweptPageV1 {
                        items: read.comments(page.nodes, stager, state).await?,
                        next_cursor: page.next_cursor,
                        unfinished: page.unfinished,
                    })
                }
                Err(error) => Err(error),
            },
        })
    }

    /// Sweep one of a team's listings. See the module documentation.
    #[allow(clippy::too_many_arguments)] // one sweep's read, cursor, and pass state
    async fn sweep(
        &self,
        sweep: SweepV1,
        read: &TeamReadV1<'_>,
        cursor: &mut TeamCursorV1,
        domain: &str,
        input: &PullPassInputV1<'_>,
        observation: &mut Option<ContainerObservationV1>,
        state: &mut PassStateV1,
        stager: &mut PageStager<'_>,
    ) -> Result<ListingBoundV1> {
        let start = cursor
            .sweep(sweep)
            .start(self.settings.overlap_seconds.saturating_mul(1_000_000));
        if start.resumed {
            state.bump("sweeps_resumed");
        }
        let since = start.since.and_then(linear_instant);
        let mut after = start.after;
        let mut newest = start.newest;
        let mut blemished = start.blemished;
        loop {
            if !state.take_call() {
                return Ok(ListingBoundV1::Truncated(PartialReasonV1::ListingBound));
            }
            let page = match self
                .fetch(
                    sweep,
                    read,
                    since.as_deref(),
                    after.as_deref(),
                    state,
                    stager,
                )
                .await?
            {
                Ok(page) => page,
                Err(error) => {
                    let restart = matches!(error, LinearCallErrorV1::Refused(_))
                        && cursor.sweep(sweep).resume.is_some();
                    let reason = state.refusal(error)?;
                    if restart {
                        // A cursor Linear refuses will not be accepted later:
                        // the sweep starts over on the next pass.
                        cursor.sweep_mut(sweep).resume = None;
                        let observations: Vec<ContainerObservationV1> =
                            observation.take().into_iter().collect();
                        stager
                            .stage_page(
                                Vec::new(),
                                &[cursor.advance(domain, input.pass_seq)?],
                                &observations,
                            )
                            .await?;
                    }
                    return Ok(ListingBoundV1::Truncated(reason));
                }
            };
            newest = newest.max(page.items.newest);
            blemished |= page.items.blemished;
            let queued = cursor.queue(&page.items.backfill, state);
            let oversized = page
                .next_cursor
                .as_ref()
                .is_some_and(|next| next.len() > MAX_PAGE_CURSOR_BYTES);
            let next = page.next_cursor.filter(|_| !oversized);
            let finished = next.is_none() && !page.unfinished && !oversized;
            let readable = finished || next.is_some();
            if finished && sweep == SweepV1::Comments && start.since.is_none() {
                // Every comment of the team's issues was read: none is owed
                // a whole read any more.
                cursor.backfill.clear();
            }
            let position = cursor.sweep_mut(sweep);
            if finished {
                if !blemished {
                    let reached = newest.map(|newest| newest.min(input.pass_order_micros));
                    position.high_water = position.high_water.max(reached);
                }
                position.resume = None;
            } else if let Some(next) = &next {
                position.resume = Some(ResumeV1 {
                    since: start.since,
                    after: next.clone(),
                    newest,
                    blemished,
                });
            }
            let advances = if readable || queued {
                vec![cursor.advance(domain, input.pass_seq)?]
            } else {
                Vec::new()
            };
            let observations: Vec<ContainerObservationV1> =
                observation.take().into_iter().collect();
            stager
                .stage_page(page.items.items, &advances, &observations)
                .await?;
            if finished {
                return Ok(ListingBoundV1::Complete);
            }
            let Some(next) = next else {
                // More was promised with no usable cursor: the listing
                // cannot be read to its end, and the sweep resumes where the
                // last readable page left it.
                return Ok(ListingBoundV1::Truncated(PartialReasonV1::Unreadable));
            };
            after = Some(next);
        }
    }

    /// Read every comment of each issue the team's cursor queued
    /// ([`TeamCursorV1::backfill`]), each page one sink transaction; an issue
    /// read to its end leaves the queue with its last page.
    #[allow(clippy::too_many_arguments)] // one team's read, cursor, and pass state
    async fn backfill(
        &self,
        read: &TeamReadV1<'_>,
        cursor: &mut TeamCursorV1,
        domain: &str,
        input: &PullPassInputV1<'_>,
        state: &mut PassStateV1,
        stager: &mut PageStager<'_>,
    ) -> Result<ListingBoundV1> {
        let issues: Vec<String> = cursor.backfill.iter().cloned().collect();
        for issue in issues {
            let mut after: Option<String> = None;
            loop {
                if !state.take_call() {
                    return Ok(ListingBoundV1::Truncated(PartialReasonV1::ListingBound));
                }
                let page = match self.api.issue_comments_page(&issue, after.as_deref()).await {
                    Ok(page) => page,
                    Err(error) => return Ok(ListingBoundV1::Truncated(state.refusal(error)?)),
                };
                state.rate(page.rate);
                let items = read.comments(page.nodes, stager, state).await?;
                let next = page
                    .next_cursor
                    .filter(|next| next.len() <= MAX_PAGE_CURSOR_BYTES);
                let finished = next.is_none() && !page.unfinished;
                let advances = if finished && !items.blemished {
                    cursor.backfill.remove(&issue);
                    state.bump("comment_backfills");
                    vec![cursor.advance(domain, input.pass_seq)?]
                } else {
                    Vec::new()
                };
                stager.stage_page(items.items, &advances, &[]).await?;
                if finished {
                    break;
                }
                let Some(next) = next else {
                    return Ok(ListingBoundV1::Truncated(PartialReasonV1::Unreadable));
                };
                after = Some(next);
            }
        }
        Ok(ListingBoundV1::Complete)
    }

    /// Read one team. See the module documentation.
    async fn team(
        &self,
        team: TeamInputV1<'_>,
        state: &mut PassStateV1,
        stager: &mut PageStager<'_>,
    ) -> Result<TeamEndV1> {
        let id = team.id.to_owned();
        let (audience, decision) = team_decision(team.input, &id, team.info);
        let observation = ContainerObservationV1 {
            kind: ContainerKindV1::new(TEAM_CONTAINER_KIND)?,
            id: id.clone(),
            label: team.info.key.clone(),
            provider_audience: audience,
        };
        let scope = team.input.instance.provider_scope_id.as_str();
        if let AudienceDecisionV1::Refuse(_) = decision {
            // Never read; the observation withdraws what was admitted.
            stager.stage_page(Vec::new(), &[], &[observation]).await?;
            state.bump("teams_refused");
            return Ok(TeamEndV1::Outside);
        }
        let domain = team_cursor_domain(&id);
        let mut cursor = match stager.read_cursor(&domain).await? {
            Some(stored) => TeamCursorV1::decode(&stored.cursor_state, &mut state.counters)
                .unwrap_or_else(TeamCursorV1::fresh),
            None => TeamCursorV1::fresh(),
        };
        let read = TeamReadV1 {
            provider: ProviderKindV1::new(LINEAR_PROVIDER)?,
            scope: scope.to_owned(),
            team: id,
            label: team.info.key.clone(),
            key: team.key,
            audience,
            held: team.held,
            comments_since: cursor
                .comments
                .start(self.settings.overlap_seconds.saturating_mul(1_000_000))
                .since,
        };
        let mut observation = Some(observation);
        let mut bound = ListingBoundV1::Complete;
        for sweep in [SweepV1::Issues, SweepV1::Comments] {
            if let Some(reason) = state.stop {
                bound = ListingBoundV1::Truncated(reason);
                break;
            }
            let swept = self
                .sweep(
                    sweep,
                    &read,
                    &mut cursor,
                    &domain,
                    team.input,
                    &mut observation,
                    state,
                    stager,
                )
                .await?;
            if bound == ListingBoundV1::Complete {
                bound = swept;
            }
        }
        if let Some(observation) = observation.take() {
            stager.stage_page(Vec::new(), &[], &[observation]).await?;
        }
        if bound == ListingBoundV1::Complete && !cursor.backfill.is_empty() {
            bound = self
                .backfill(&read, &mut cursor, &domain, team.input, state, stager)
                .await?;
        }
        Ok(TeamEndV1::Listed(bound))
    }

    /// A configured team the credential cannot see: deleted, or made private
    /// to people the credential's user is not among. Unless the operator
    /// listed it, that is a narrowing, not a partial read: its observation
    /// as restricted withdraws what was admitted through it, and it is
    /// outside the pass's domain. A listed one stays in the domain, partial.
    /// Either way nothing it held is vouched for.
    async fn missing_team(
        &self,
        input: &PullPassInputV1<'_>,
        team: &str,
        state: &mut PassStateV1,
        stager: &mut PageStager<'_>,
    ) -> Result<TeamEndV1> {
        state.bump("teams_missing");
        let listed = input
            .source
            .audience
            .private_containers
            .iter()
            .any(|listed| listed.eq_ignore_ascii_case(team));
        if listed {
            return Ok(TeamEndV1::Listed(ListingBoundV1::Truncated(
                PartialReasonV1::ProviderRefused,
            )));
        }
        let observation = ContainerObservationV1 {
            kind: ContainerKindV1::new(TEAM_CONTAINER_KIND)?,
            id: team.to_owned(),
            label: None,
            provider_audience: ProviderAudienceV1::Restricted,
        };
        stager.stage_page(Vec::new(), &[], &[observation]).await?;
        Ok(TeamEndV1::Outside)
    }

    /// Check where a rotating batch of held issues is now
    /// ([`VERIFY_CURSOR_DOMAIN`]): issues the memory holds in a team the pass
    /// read that its sweeps did not return. The sweeps are filtered by team,
    /// so an issue moved into a team the pass does not admit, or one the
    /// credential can no longer see, is never returned by them: each such
    /// issue, and every comment the memory holds on it, is withdrawn
    /// ([`super::pull::withdrawal`]). One call per pass.
    #[allow(clippy::too_many_arguments)] // the pass's held state and its read
    async fn verify(
        &self,
        input: &PullPassInputV1<'_>,
        held: &HeldV1<'_>,
        read_teams: &BTreeSet<Sha256Digest>,
        provider: &ProviderKindV1,
        state: &mut PassStateV1,
        stager: &mut PageStager<'_>,
    ) -> Result<()> {
        let candidates: Vec<&String> = held
            .issues
            .iter()
            .filter(|(id, version)| {
                !version.lifecycle.is_tombstone()
                    && !version.withdrawn
                    && version
                        .container_key
                        .is_some_and(|key| read_teams.contains(&key))
                    && !state.seen_issues.contains(*id)
                    && !state.withdrawn_now.contains(*id)
            })
            .map(|(id, _)| id)
            .collect();
        if candidates.is_empty() {
            return Ok(());
        }
        let after = match stager.read_cursor(VERIFY_CURSOR_DOMAIN).await? {
            Some(stored) => serde_json::from_slice::<VerifyCursorV1>(&stored.cursor_state)
                .ok()
                .filter(|cursor| cursor.schema_version == CURSOR_SCHEMA_VERSION)
                .and_then(|cursor| cursor.after),
            None => None,
        };
        let (batch, next) = rotation(&candidates, after.as_deref());
        if !state.take_call() {
            return Ok(());
        }
        let places = match self.api.issue_places(&batch).await {
            Ok((places, rate)) => {
                state.rate(rate);
                places
            }
            Err(error) => {
                state.refusal(error)?;
                return Ok(());
            }
        };
        *state.counters.entry("issues_verified").or_insert(0) +=
            u64::try_from(batch.len()).unwrap_or(u64::MAX);
        let scope = input.instance.provider_scope_id.as_str();
        let kind = linear_object_kind(ISSUE_OBJECT_KIND);
        let mut items = Vec::new();
        for id in &batch {
            let place = places
                .iter()
                .find(|place| place.id.eq_ignore_ascii_case(id));
            let stays = place
                .and_then(|place| place.team.as_ref())
                .is_some_and(|team| {
                    held.admitted_teams
                        .iter()
                        .any(|admitted| admitted.eq_ignore_ascii_case(&team.id))
                });
            let Some(known) = held.issues.get(id).filter(|_| !stays) else {
                continue;
            };
            let observed = place
                .and_then(|place| place.updated_at.as_deref())
                .and_then(linear_order)
                .unwrap_or(0);
            state.withdrawn_now.insert(id.clone());
            state.bump("issues_withdrawn");
            items.push(withdrawal(
                &WithdrawnItemV1 {
                    provider,
                    provider_scope_id: scope,
                    object_kind: &kind,
                    external_id: id,
                    order_micros: known.provider_order.max(observed),
                },
                None,
            ));
            held.withdraw_comments(provider, scope, id, state, &mut items);
        }
        let advance = CursorAdvanceV1 {
            domain_key: VERIFY_CURSOR_DOMAIN.to_owned(),
            cursor_state: serde_json::to_vec(&VerifyCursorV1 {
                schema_version: CURSOR_SCHEMA_VERSION,
                after: next,
            })
            .map_err(|error| FleetError::Memory(format!("a Linear cursor: {error}")))?,
            high_water_order: None,
            pass_seq: input.pass_seq,
        };
        stager.stage_page(items, &[advance], &[]).await?;
        Ok(())
    }
}

/// The next batch of a rotation over sorted `candidates` after `after`
/// (from the start when nothing is after it), and where the rotation stands
/// after it: `None` when it reached the end.
fn rotation(candidates: &[&String], after: Option<&str>) -> (Vec<String>, Option<String>) {
    let mut start = after.map_or(0, |after| {
        candidates.partition_point(|id| id.as_str() <= after)
    });
    if start >= candidates.len() {
        start = 0;
    }
    let batch: Vec<String> = candidates[start..]
        .iter()
        .take(MAX_ISSUE_TEAMS_BATCH)
        .map(|id| (*id).clone())
        .collect();
    let next = (start + batch.len() < candidates.len())
        .then(|| batch.last().cloned())
        .flatten();
    (batch, next)
}

/// A team's provider audience, and what the instance's policy decides of it.
fn team_decision(
    input: &PullPassInputV1<'_>,
    team: &str,
    info: &LinearTeamV1,
) -> (ProviderAudienceV1, AudienceDecisionV1) {
    let audience = if info.is_public() {
        ProviderAudienceV1::TeamPublic
    } else {
        ProviderAudienceV1::Restricted
    };
    let decision = classify(&AudienceInputV1 {
        mode: CollectionModeV1::Pull,
        provider: LINEAR_PROVIDER,
        provider_scope_id: input.instance.provider_scope_id.as_str(),
        container_id: Some(team),
        provider_audience: Some(audience),
        hint: None,
        policy: &input.source.audience,
        capture_scopes: &[],
        known_container: KnownContainerV1::Unknown,
    });
    (audience, decision)
}

/// The comments the memory holds on each issue, by issue id.
fn comments_by_issue(
    known_comments: &BTreeMap<String, KnownVersionV1>,
) -> BTreeMap<String, Vec<String>> {
    let mut by_issue: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (comment, version) in known_comments {
        if let Some(issue) = &version.thread_root {
            by_issue
                .entry(issue.clone())
                .or_default()
                .push(comment.clone());
        }
    }
    by_issue
}

/// Every configured team the credential sees and the policy admits, by id.
fn admitted_teams(
    input: &PullPassInputV1<'_>,
    teams: &[String],
    scope: &graphql::LinearScopeV1,
) -> BTreeSet<String> {
    teams
        .iter()
        .filter(|team| {
            scope.team(team).is_some_and(|info| {
                matches!(
                    team_decision(input, team, info).1,
                    AudienceDecisionV1::Admit(_)
                )
            })
        })
        .cloned()
        .collect()
}

/// Hold current what the memory knows in a team the pass read and the
/// sweeps did not return: it has not changed since the sweeps' start. A
/// withdrawn item is not current, nor one this pass withdrew.
fn hold_unseen(
    known: &BTreeMap<String, KnownVersionV1>,
    seen: &BTreeSet<String>,
    withdrawn: &BTreeSet<String>,
    listed: &BTreeSet<Sha256Digest>,
    stager: &mut PageStager<'_>,
) {
    for (external_id, version) in known {
        if seen.contains(external_id) || version.withdrawn || withdrawn.contains(external_id) {
            continue;
        }
        if let Some(key) = version.container_key
            && listed.contains(&key)
        {
            stager.keep(Some(key), version);
        }
    }
}

#[async_trait]
impl PullCollectorV1 for LinearPullV1 {
    fn counter_keys(&self) -> &'static [&'static str] {
        &LINEAR_COUNTERS
    }

    fn proof_method(&self) -> CoverageProofMethodV1 {
        CoverageProofMethodV1::ClosedProviderQuery
    }

    fn observation_audience(&self) -> ProviderAudienceV1 {
        // The pass summary names the instance and counts; every member of
        // the organization may read that.
        ProviderAudienceV1::ScopePublic
    }

    #[allow(clippy::too_many_lines)] // one linear scope -> teams -> verify -> hold pass
    async fn pass(
        &self,
        input: &PullPassInputV1<'_>,
        stager: &mut PageStager<'_>,
    ) -> Result<PullPassOutcomeV1> {
        let mut state = PassStateV1::new(self.settings.max_pages_per_tick);
        let mut teams = self.settings.teams.clone();
        teams.sort();
        let kind = ContainerKindV1::new(TEAM_CONTAINER_KIND)?;
        let keys: Vec<Sha256Digest> = teams
            .iter()
            .map(|team| stager.container_key(&kind, team))
            .collect();
        let outcome = |containers: Vec<ContainerOutcomeV1>, state: PassStateV1| PullPassOutcomeV1 {
            containers,
            reconcile: true,
            counters: state.counters,
            window_start: None,
        };

        // The settings allow at least one call.
        state.take_call();
        let scope = match self.api.scope(&teams).await {
            Ok(scope) => scope,
            Err(LinearCallErrorV1::RateLimited) => {
                state.bump("rate_limited");
                let containers = keys
                    .iter()
                    .zip(0_u32..)
                    .map(|(key, ordinal)| ContainerOutcomeV1 {
                        ordinal,
                        container_key: Some(*key),
                        listing: ListingBoundV1::Truncated(PartialReasonV1::RateLimited),
                    })
                    .collect();
                return Ok(outcome(containers, state));
            }
            Err(error) => {
                return Err(FleetError::Configuration(format!(
                    "the Linear organization query failed ({error}); nothing was read"
                )));
            }
        };
        state.rate(scope.rate);
        let pinned = input.instance.provider_scope_id.as_str();
        if !scope.organization.id.eq_ignore_ascii_case(pinned) {
            return Err(FleetError::Configuration(format!(
                "the Linear credential belongs to organization {}, but the collector is pinned \
                 to organization {pinned}; nothing was read",
                shown_id(&scope.organization.id)
            )));
        }

        let known_issues = stager
            .known_versions(&ObjectKindV1::new(ISSUE_OBJECT_KIND)?)
            .await?;
        let known_comments = stager
            .known_versions(&ObjectKindV1::new(COMMENT_OBJECT_KIND)?)
            .await?;
        let comments_by_issue = comments_by_issue(&known_comments);
        state.trashed_issues = known_issues
            .iter()
            .filter(|(_, version)| version.lifecycle.is_tombstone())
            .map(|(id, _)| id.clone())
            .collect();
        let admitted_teams = admitted_teams(input, &teams, &scope);
        let held = HeldV1 {
            issues: &known_issues,
            comments: &known_comments,
            comments_by_issue: &comments_by_issue,
            admitted_teams: &admitted_teams,
        };
        let mut containers = Vec::with_capacity(teams.len());
        let mut listed = BTreeSet::new();
        let mut read_teams = BTreeSet::new();
        for (team, key) in teams.iter().zip(keys) {
            let end = match (state.stop, scope.team(team)) {
                (Some(reason), _) => {
                    listed.insert(key);
                    TeamEndV1::Listed(ListingBoundV1::Truncated(reason))
                }
                (None, None) => self.missing_team(input, team, &mut state, stager).await?,
                (None, Some(info)) => {
                    let end = self
                        .team(
                            TeamInputV1 {
                                input,
                                id: team,
                                info,
                                key,
                                held: &held,
                            },
                            &mut state,
                            stager,
                        )
                        .await?;
                    if matches!(end, TeamEndV1::Listed(_)) {
                        listed.insert(key);
                        read_teams.insert(key);
                    }
                    end
                }
            };
            if let TeamEndV1::Listed(listing) = end {
                containers.push(ContainerOutcomeV1 {
                    ordinal: u32::try_from(containers.len()).unwrap_or(u32::MAX),
                    container_key: Some(key),
                    listing,
                });
            }
        }
        if state.stop.is_none() {
            let provider = ProviderKindV1::new(LINEAR_PROVIDER)?;
            self.verify(input, &held, &read_teams, &provider, &mut state, stager)
                .await?;
        }

        hold_unseen(
            &known_issues,
            &state.seen_issues,
            &state.withdrawn_now,
            &listed,
            stager,
        );
        hold_unseen(
            &known_comments,
            &state.seen_comments,
            &state.withdrawn_now,
            &listed,
            stager,
        );
        Ok(outcome(containers, state))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ORG: &str = "0a9c0000-0000-4000-8000-0000000ac3e1";
    const ENG: &str = "4e6b8d0f-1a2b-4c3d-9e8f-7a6b5c4d3e2f";
    const SEC: &str = "5f7c9e10-2b3c-4d4e-8f90-8b7c6d5e4f30";

    fn source(settings: &serde_json::Value, audience: &serde_json::Value) -> CollectorSourceV1 {
        serde_json::from_value(serde_json::json!({
            "provider": "linear",
            "connector_principal": "principal.linear",
            "connector_instance": "linear.acme",
            "provider_scope_id": ORG,
            "audience": audience,
            "settings": settings
        }))
        .unwrap()
    }

    fn settings(extra: &serde_json::Value) -> serde_json::Value {
        let mut settings = serde_json::json!({
            "token_env": "FLEET_RECALL_LINEAR_API_KEY",
            "teams": [ENG, SEC]
        });
        settings
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        settings
    }

    #[test]
    fn settings_are_closed_bounded_and_default_to_the_public_api() {
        let adapter = LinearAdapterV1;
        let listed = serde_json::json!({"private_containers": [SEC]});
        adapter
            .validate(&source(&settings(&serde_json::json!({})), &listed))
            .unwrap();
        let parsed =
            LinearSettingsV1::from_source(&source(&settings(&serde_json::json!({})), &listed))
                .unwrap();
        assert_eq!(parsed.api_url, DEFAULT_LINEAR_API_URL);
        assert_eq!(parsed.overlap_seconds, DEFAULT_OVERLAP_SECONDS);
        assert_eq!(parsed.page_size, DEFAULT_PAGE_SIZE);
        assert_eq!(
            adapter.reconcile_every_seconds(&source(&settings(&serde_json::json!({})), &listed)),
            None,
            "every pass reconciles"
        );

        for (extra, needle) in [
            (
                serde_json::json!({"api_url": "http://linear.example.com/graphql"}),
                "not loopback",
            ),
            (
                serde_json::json!({"api_url": "https://api.linear.app/"}),
                "no GraphQL endpoint path",
            ),
            (serde_json::json!({"token_env": "lower"}), "token_env"),
            (serde_json::json!({"teams": []}), "settings.teams"),
            (serde_json::json!({"teams": ["ENG"]}), "a label, not an id"),
            (
                serde_json::json!({"teams": [ENG.to_ascii_uppercase()]}),
                "not a team id",
            ),
            (serde_json::json!({"teams": [ENG, ENG]}), "twice"),
            (
                serde_json::json!({"overlap_seconds": 86_401}),
                "overlap_seconds",
            ),
            (serde_json::json!({"page_size": 251}), "page_size"),
            (
                serde_json::json!({"max_pages_per_tick": 0}),
                "max_pages_per_tick",
            ),
            (
                serde_json::json!({"include_private": true}),
                "include_private",
            ),
        ] {
            let message = adapter
                .validate(&source(&settings(&extra), &listed))
                .unwrap_err();
            assert!(message.contains(needle), "{extra}: {message}");
        }
        let loopback = serde_json::json!({"api_url": "http://127.0.0.1:9/graphql"});
        adapter
            .validate(&source(&settings(&loopback), &listed))
            .expect("a loopback fake provider may be plain http");

        let declared = adapter
            .validate(&source(
                &settings(&serde_json::json!({})),
                &serde_json::json!({"operator_declared": true}),
            ))
            .unwrap_err();
        assert!(declared.contains("private_containers"), "{declared}");
        let keyed = adapter
            .validate(&source(
                &settings(&serde_json::json!({})),
                &serde_json::json!({"private_containers": ["SEC"]}),
            ))
            .unwrap_err();
        assert!(keyed.contains("not a team id"), "{keyed}");
        let mut unpinned = source(&settings(&serde_json::json!({})), &listed);
        unpinned.provider_scope_id = serde_json::from_value(serde_json::json!("acme")).unwrap();
        assert!(
            adapter
                .validate(&unpinned)
                .unwrap_err()
                .contains("organization id")
        );
    }

    #[test]
    fn an_endpoint_splits_into_a_base_and_its_method_path() {
        assert_eq!(
            split_endpoint("https://api.linear.app/graphql").unwrap(),
            ("https://api.linear.app/".to_owned(), "graphql".to_owned())
        );
        assert_eq!(
            split_endpoint("http://127.0.0.1:8080/relay/linear/graphql/").unwrap(),
            (
                "http://127.0.0.1:8080/relay/linear/".to_owned(),
                "graphql".to_owned()
            )
        );
        assert!(split_endpoint("https://api.linear.app").is_err());
        assert!(split_endpoint("https://api.linear.app/graphql?x=1").is_err());
    }

    #[test]
    fn a_personal_key_is_its_own_header_and_anything_else_a_bearer_token() {
        let token = |value: &'static str| {
            ProviderTokenV1::from_environment("T", &move |_: &str| Some(value.to_owned())).unwrap()
        };
        assert_eq!(
            auth_scheme(&token("lin_api_EXAMPLENOTAREALKEYEXAMPLENOTAREAL")),
            AuthSchemeV1::Plain
        );
        assert_eq!(
            auth_scheme(&token("lin_oauth_EXAMPLENOTAREALTOKENEXAMPLE")),
            AuthSchemeV1::Bearer
        );
    }

    #[test]
    fn a_missing_credential_fails_the_collector_before_any_request() {
        let error = LinearAdapterV1
            .pull(
                &source(&settings(&serde_json::json!({})), &serde_json::json!({})),
                &|_: &str| None,
            )
            .err()
            .expect("no credential, no collector");
        assert!(error.contains("FLEET_RECALL_LINEAR_API_KEY"), "{error}");
    }

    #[test]
    fn a_sweep_starts_from_its_high_water_less_the_overlap_or_resumes() {
        let overlap = 300 * 1_000_000;
        let fresh = SweepCursorV1::default().start(overlap);
        assert_eq!(fresh.since, None, "the whole team the first time");
        assert!(!fresh.resumed && fresh.after.is_none());
        let swept = SweepCursorV1 {
            high_water: Some(1_790_070_067_113_000),
            resume: None,
        }
        .start(overlap);
        assert_eq!(swept.since, Some(1_790_070_067_113_000 - overlap));
        assert_eq!(
            linear_instant(swept.since.unwrap()).as_deref(),
            Some("2026-09-22T09:36:07.113Z")
        );
        let cut = SweepCursorV1 {
            high_water: Some(1_790_070_067_113_000),
            resume: Some(ResumeV1 {
                since: Some(1_000),
                after: "Y3Vyc29y".into(),
                newest: Some(2_000),
                blemished: true,
            }),
        }
        .start(overlap);
        assert_eq!(
            cut,
            SweepStartV1 {
                since: Some(1_000),
                after: Some("Y3Vyc29y".into()),
                newest: Some(2_000),
                blemished: true,
                resumed: true,
            },
            "a cut sweep resumes under its own filter"
        );
        assert_eq!(
            linear_instant(1_790_070_067_113_999).as_deref(),
            Some("2026-09-22T09:41:07.113Z"),
            "cut to milliseconds, never later"
        );
    }

    #[test]
    fn a_cursor_that_does_not_decode_is_reset_and_counted() {
        let mut counters = BTreeMap::new();
        let mut cursor = TeamCursorV1::fresh();
        cursor.issues.high_water = Some(42);
        cursor.comments.resume = Some(ResumeV1 {
            since: None,
            after: "x".repeat(MAX_PAGE_CURSOR_BYTES),
            newest: None,
            blemished: false,
        });
        cursor.issues.resume = cursor.comments.resume.clone();
        let advance = cursor.advance("linear.team:t", 3).unwrap();
        assert_eq!(advance.high_water_order, Some(42));
        assert!(
            advance.cursor_state.len() < 16_384,
            "the largest cursor fits its column"
        );
        assert_eq!(
            TeamCursorV1::decode(&advance.cursor_state, &mut counters),
            Some(cursor)
        );
        assert!(TeamCursorV1::decode(b"{\"schema_version\":2}", &mut counters).is_none());
        assert!(TeamCursorV1::decode(b"garbage", &mut counters).is_none());
        assert_eq!(counters["cursors_reset"], 2);
    }

    #[test]
    fn the_rate_limit_counters_keep_the_fewest_left() {
        let mut state = PassStateV1::new(3);
        state.rate(RateLimitV1::default());
        assert_eq!(state.counters["ratelimit_reports"], 0);
        state.rate(RateLimitV1 {
            requests_remaining: Some(4_990),
            complexity_remaining: Some(2_000_000),
        });
        state.rate(RateLimitV1 {
            requests_remaining: Some(5_000),
            complexity_remaining: Some(1_500_000),
        });
        assert_eq!(state.counters["ratelimit_reports"], 2);
        assert_eq!(state.counters["ratelimit_requests_remaining"], 4_990);
        assert_eq!(state.counters["ratelimit_complexity_remaining"], 1_500_000);
        assert_eq!(shown_id("0a9c<b>-x y"), "0a9cb-xy");
    }
}
