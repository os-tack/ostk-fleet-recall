//! The Slack collector: provider `slack`, pulled by the worker through the
//! Web API with a bot token (ADR 0008 D8).
//!
//! One instance reads one workspace, pinned by its `team_id` (the instance's
//! provider scope id), and one container per configured channel
//! (`slack.channel`). The token comes from the environment variable
//! `settings.token_env` names; it is only ever an `Authorization` header
//! ([`crate::collectors::http`]).
//!
//! # A pass
//!
//! 1. `auth.test`: the token's `team_id` (and `enterprise_id`, when
//!    `settings.enterprise_id` pins one) must equal the pin, or the pass fails
//!    before it reads anything.
//! 2. The pass is a **reconciliation** when one is under way, or none has
//!    finished within `reconcile_every_seconds` (the `slack.reconcile`
//!    cursor), else an **incremental** pass. Only a reconciliation writes
//!    coverage and the status row's `last_checked_at`. A reconciliation cut
//!    short is continued by the next pass, never started over: a channel its
//!    earlier passes read to its end (its cursor records the reconciliation)
//!    is not read again, and what the memory holds of it is held current, so
//!    the manifest names every current item. It ends, and records its start
//!    as the last complete one, in the pass that reads its last channel.
//! 3. The channels are taken in id order, from the one the last pass was cut
//!    short at, so the budget never starves the later ones. For each,
//!    `conversations.info` gives its name and audience
//!    ([`api::SlackChannelInfoV1::audience`]), recorded as a container
//!    observation. A direct, group-direct, or externally shared conversation,
//!    and a private or org-shared one the operator did not list in
//!    `audience.private_containers`, is never read: its observation withdraws
//!    the container, which hides what was admitted through it, and it is
//!    outside the pass's domain. A channel Slack no longer finds
//!    (`channel_not_found`: deleted, or made private without the app) is a
//!    narrowing too, unless listed: it is observed as restricted, which
//!    withdraws it until a later read finds it readable again.
//! 4. `conversations.history` is paged on `next_cursor` from the window's
//!    start (exclusive): `backfill_since` (else the channel's whole history)
//!    for a reconciliation; for an incremental pass, the trailing
//!    `rescan_days` or the channel's high-water mark, whichever is older, so a
//!    rescan picks up edits (a new `edited.ts`) and a long outage is caught up.
//! 5. After each history page, `conversations.replies` reads that page's
//!    threads, newest first: every thread on a reconciliation, and on an
//!    incremental pass every thread whose `latest_reply` is past the
//!    channel's reply cursor. Every channel-level message and root at or
//!    after the last root whose thread was read (or the page's oldest
//!    message, once its threads are read) is then read whole: that `ts` is
//!    where a read cut short resumes (`latest`, exclusive), recorded in the
//!    channel's cursor with the read's kind. A read of the other kind starts
//!    over.
//! 6. Every message becomes a draft ([`render::message_draft`]); one the
//!    memory already holds at the same version and content, and not
//!    withdrawn, is kept rather than staged. Each API page is one sink
//!    transaction.
//! 7. **Deletions.** A message the memory holds, inside what a read saw
//!    whole, that the read did not return is counted in the channel's
//!    cursor; missing from two consecutive such reads, it gets a `deleted`
//!    tombstone at its own order (a tombstone wins the tie). A read saw whole
//!    the channel-level messages and roots in its window (for a read cut
//!    short, from where it got to), and a reply when its thread was read to
//!    its end, or when its root is in that range and the read returned the
//!    root with no replies left, or did not return the root at all: a thread
//!    whose every reply was deleted is never read again, so its replies are
//!    counted from the root. A read that returned a message it could not
//!    parse counts nothing missing. A `tombstone` message (a root deleted
//!    while its replies remain) hides the root at once.
//! 8. The channel's cursor (high-water marks and missing counts) advances
//!    with its last page when the channel was read to its end, and records
//!    where the read got to when the budget or a rate limit cut it short.
//!
//! # Partial reads
//!
//! Every call counts against `max_pages_per_tick`. `ok: false` for a channel
//! (`not_in_channel`, `missing_scope`, a listed channel not found) leaves that
//! channel partial and the pass goes on. A rate limit (HTTP 429, or
//! `ratelimited`) or the page budget ends the pass: the channel in progress
//! and every later one are partial, what was staged stays staged, and the
//! next pass resumes the channel in progress where it stopped. An unusable
//! credential (`invalid_auth`, `token_revoked`, ...) fails the pass.
//!
//! # Deliberately absent
//!
//! Reactions, reply counts, unfurl text, and presence are never content (an
//! unfurl is at most a link), and a file is a link, never its content. Direct and group-direct conversations are
//! never listed, fetched, or staged.

pub mod api;
pub mod render;

use std::collections::{BTreeMap, BTreeSet};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{FleetError, Result};
use crate::memory_contracts::collected_item::{
    CollectionModeV1, ContainerKindV1, ObjectKindV1, ProviderKindV1,
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
use super::pull::{
    ContainerOutcomeV1, ListingBoundV1, PageStager, PartialReasonV1, PullCollectorV1,
    PullPassInputV1, PullPassOutcomeV1, PulledItemV1,
};
use super::sink::{
    ContainerObservationV1, CursorAdvanceV1, DeadLetterReasonV1, KnownVersionV1, StagedItemV1,
};
use api::{PageMessageV1, SlackApiV1, SlackCallErrorV1};
use render::{
    CHANNEL_CONTAINER_KIND, MESSAGE_OBJECT_KIND, MessageDraftV1, SLACK_PROVIDER,
    SlackChannelContextV1, SlackMessageV1, SlackTsV1, message_draft, message_external_id,
    tombstone_draft,
};

/// The Web API a collector reads unless its settings say otherwise.
pub const DEFAULT_SLACK_API_BASE: &str = "https://slack.com/api";

/// The only host a collector sends its credential to, unless its base is
/// loopback (a local fake provider).
pub const SLACK_API_HOST: &str = "slack.com";

/// The cursor domain of the reconciliation schedule.
pub const RECONCILE_CURSOR_DOMAIN: &str = "slack.reconcile";

/// The cursor domain of one channel.
#[must_use]
pub fn channel_cursor_domain(channel: &str) -> String {
    format!("slack.channel:{channel}")
}

/// Days an incremental pass re-reads, unless the settings say otherwise.
pub const DEFAULT_RESCAN_DAYS: u32 = 7;
/// The largest `rescan_days`.
pub const MAX_RESCAN_DAYS: u32 = 90;
/// Seconds between reconciliations, unless the settings say otherwise.
pub const DEFAULT_RECONCILE_EVERY_SECONDS: u64 = 86_400;
/// Calls one pass makes at most, unless the settings say otherwise.
pub const DEFAULT_MAX_PAGES_PER_TICK: u32 = 500;
/// The largest `max_pages_per_tick`.
pub const MAX_PAGES_PER_TICK: u32 = 10_000;
/// Messages one page asks for, unless the settings say otherwise.
pub const DEFAULT_PAGE_SIZE: u32 = 200;
/// The largest `page_size` Slack accepts.
pub const MAX_PAGE_SIZE: u32 = 999;
/// Channels one instance reads at most.
pub const MAX_CHANNELS: usize = 500;

/// Messages a channel cursor remembers as missing once, at most; a message
/// past it is counted again from its next miss.
const MAX_MISSING: usize = 256;

const CURSOR_SCHEMA_VERSION: u32 = 1;

const MICROS_PER_DAY: u64 = 86_400_000_000;

/// Every counter a Slack pass reports.
pub const SLACK_COUNTERS: [&str; 19] = [
    "reconcile",
    "api_calls",
    "channels_refused",
    "channels_gone",
    "channels_resumed",
    "channels_already_reconciled",
    "messages_read",
    "messages_staged",
    "messages_unchanged",
    "messages_skipped",
    "messages_dead_lettered",
    "threads_read",
    "tombstones",
    "missing_once",
    "rate_limited",
    "provider_refused",
    "http_errors",
    "page_budget_exhausted",
    "cursors_reset",
];

const fn default_rescan_days() -> u32 {
    DEFAULT_RESCAN_DAYS
}

const fn default_reconcile_every_seconds() -> u64 {
    DEFAULT_RECONCILE_EVERY_SECONDS
}

const fn default_max_pages_per_tick() -> u32 {
    DEFAULT_MAX_PAGES_PER_TICK
}

const fn default_page_size() -> u32 {
    DEFAULT_PAGE_SIZE
}

fn default_api_base() -> String {
    DEFAULT_SLACK_API_BASE.to_owned()
}

/// A Slack workspace's settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlackSettingsV1 {
    /// The environment variable holding the bot token (`xoxb-...`).
    pub token_env: String,
    /// The channels to read, by id (`C...`, or a legacy private `G...`).
    pub channels: Vec<String>,
    /// The Enterprise Grid organization `auth.test` must report, when set.
    #[serde(default)]
    pub enterprise_id: Option<String>,
    /// The earliest message a reconciliation reads; unset reads each
    /// channel's whole history.
    #[serde(default)]
    pub backfill_since: Option<DateTime<Utc>>,
    /// Days an incremental pass re-reads for edits and deletions.
    #[serde(default = "default_rescan_days")]
    pub rescan_days: u32,
    /// Seconds between reconciliations.
    #[serde(default = "default_reconcile_every_seconds")]
    pub reconcile_every_seconds: u64,
    /// Calls one pass makes at most.
    #[serde(default = "default_max_pages_per_tick")]
    pub max_pages_per_tick: u32,
    /// Messages one page asks for.
    #[serde(default = "default_page_size")]
    pub page_size: u32,
    /// The Web API base: https, or http to a loopback host.
    #[serde(default = "default_api_base")]
    pub api_base: String,
}

/// Whether `value` is an upper-case Slack id: `prefix`, then 2 to 31
/// letters and digits.
fn is_slack_id(value: &str, prefixes: &[char]) -> bool {
    value.len() >= 3
        && value.len() <= 32
        && value.starts_with(prefixes)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

impl SlackSettingsV1 {
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
        validate_token_variable(SLACK_PROVIDER, &self.token_env)?;
        if self.channels.is_empty() || self.channels.len() > MAX_CHANNELS {
            return Err(format!(
                "settings.channels lists 1 to {MAX_CHANNELS} channel ids"
            ));
        }
        let mut seen = BTreeSet::new();
        for channel in &self.channels {
            if channel.starts_with('D') {
                return Err(format!(
                    "settings.channels: {channel} is a direct conversation, which is never \
                     collected"
                ));
            }
            if !is_slack_id(channel, &['C', 'G']) {
                return Err(format!(
                    "settings.channels: {channel:?} is not a channel id (C... or G...)"
                ));
            }
            if !seen.insert(channel) {
                return Err(format!("settings.channels lists {channel} twice"));
            }
        }
        if let Some(enterprise) = &self.enterprise_id
            && !is_slack_id(enterprise, &['E'])
        {
            return Err(format!(
                "settings.enterprise_id: {enterprise:?} is not an organization id (E...)"
            ));
        }
        if self
            .backfill_since
            .is_some_and(|since| since.timestamp_micros() < 0)
        {
            return Err("settings.backfill_since is before 1970".to_owned());
        }
        if !(1..=MAX_RESCAN_DAYS).contains(&self.rescan_days) {
            return Err(format!(
                "settings.rescan_days must be between 1 and {MAX_RESCAN_DAYS}"
            ));
        }
        if !(crate::collectors::status::MIN_COLLECTOR_STALE_AFTER_SECONDS
            ..=crate::collectors::status::MAX_COLLECTOR_STALE_AFTER_SECONDS)
            .contains(&self.reconcile_every_seconds)
        {
            return Err(format!(
                "settings.reconcile_every_seconds must be between {} and {}",
                crate::collectors::status::MIN_COLLECTOR_STALE_AFTER_SECONDS,
                crate::collectors::status::MAX_COLLECTOR_STALE_AFTER_SECONDS
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
        validate_provider_api_base(&self.api_base, SLACK_API_HOST)
            .map_err(|error| format!("settings.api_base: {error}"))?;
        Ok(())
    }

    fn backfill_micros(&self) -> Option<u64> {
        self.backfill_since
            .and_then(|since| u64::try_from(since.timestamp_micros()).ok())
    }
}

/// The Slack adapter.
#[derive(Debug, Clone, Copy, Default)]
pub struct SlackAdapterV1;

impl CollectorAdapterV1 for SlackAdapterV1 {
    fn provider(&self) -> &'static str {
        SLACK_PROVIDER
    }

    fn validate(&self, source: &CollectorSourceV1) -> std::result::Result<(), String> {
        let settings = SlackSettingsV1::from_source(source)?;
        for listed in &source.audience.private_containers {
            if !is_slack_id(listed, &['C', 'G']) {
                return Err(format!(
                    "audience.private_containers: {listed:?} is not a channel id (C... or G...; \
                     a channel's name is a label, not an id)"
                ));
            }
            if !settings.channels.contains(listed) {
                return Err(format!(
                    "audience.private_containers lists {listed}, which settings.channels does \
                     not"
                ));
            }
        }
        if source.audience.operator_declared {
            return Err(
                "a Slack workspace has an audience per channel: leave audience.operator_declared \
                 false, and list private channels in audience.private_containers"
                    .to_owned(),
            );
        }
        Ok(())
    }

    fn pull(
        &self,
        source: &CollectorSourceV1,
        environment: &dyn Fn(&str) -> Option<String>,
    ) -> std::result::Result<Option<Box<dyn PullCollectorV1>>, String> {
        let settings = SlackSettingsV1::from_source(source)?;
        let token = ProviderTokenV1::from_environment(&settings.token_env, environment)
            .map_err(|error| error.to_string())?;
        let http = ProviderHttpV1::new(&settings.api_base, &token, AuthSchemeV1::Bearer)
            .map_err(|error| error.to_string())?;
        Ok(Some(Box::new(SlackPullV1 {
            api: SlackApiV1::new(http, settings.page_size),
            settings,
        })))
    }

    fn reconcile_every_seconds(&self, source: &CollectorSourceV1) -> Option<u64> {
        SlackSettingsV1::from_source(source)
            .ok()
            .map(|settings| settings.reconcile_every_seconds)
    }
}

/// The reconciliation schedule, and where the last pass stopped.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReconcileCursorV1 {
    schema_version: u32,
    /// When the last reconciliation that ran to its end started.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_complete_micros: Option<u64>,
    /// When the reconciliation under way started. Every pass continues it
    /// until it ends, and none reads again a channel it read to its end.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    under_way: Option<u64>,
    /// The channel the last pass was cut short at: the next pass starts
    /// there, so a budget spent on the first channels never starves the
    /// later ones.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resume_at: Option<String>,
}

/// A channel read cut short by the page budget or a rate limit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChannelProgressV1 {
    /// When the reconciliation the read belongs to started; `None` for an
    /// incremental read. A read of another kind starts over.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    run: Option<u64>,
    /// Every channel-level message and root at or after this `ts`, and the
    /// thread of each, was read: the history resumes before it (`latest`).
    latest: String,
    /// The newest channel-level message or root the read saw.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    newest_top: Option<String>,
    /// The newest `latest_reply` of a root the read saw.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    newest_reply: Option<String>,
    /// The read refused an item, so the channel is partial when it ends.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    refused: bool,
}

/// What one channel's reads left behind.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChannelCursorV1 {
    schema_version: u32,
    /// The newest channel-level message or root read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    history_ts: Option<String>,
    /// The newest `latest_reply` of any root read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reply_ts: Option<String>,
    /// Messages the memory holds that complete reads did not return, by
    /// `ts`: how many consecutive complete reads missed them.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    missing: BTreeMap<String, u8>,
    /// When the reconciliation that last read the channel to its end
    /// started.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reconciled: Option<u64>,
    /// That reconciliation's read refused an item.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    reconciled_refused: bool,
    /// A read cut short, and where it resumes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    progress: Option<ChannelProgressV1>,
}

fn encode_cursor(
    cursor: &impl Serialize,
    domain_key: String,
    high_water_order: Option<u64>,
    pass_seq: u64,
) -> Result<CursorAdvanceV1> {
    Ok(CursorAdvanceV1 {
        domain_key,
        cursor_state: serde_json::to_vec(cursor)
            .map_err(|error| FleetError::Memory(format!("a Slack cursor: {error}")))?,
        high_water_order,
        pass_seq,
    })
}

/// A stored cursor, or `None` (counted) when it does not decode: the
/// channel is then read as if for the first time, which is safe.
fn decode_cursor<T: for<'de> Deserialize<'de>>(
    bytes: &[u8],
    schema_version: impl Fn(&T) -> u32,
    counters: &mut BTreeMap<&'static str, u64>,
) -> Option<T> {
    let decoded = serde_json::from_slice::<T>(bytes)
        .ok()
        .filter(|cursor| schema_version(cursor) == CURSOR_SCHEMA_VERSION);
    if decoded.is_none() {
        *counters.entry("cursors_reset").or_insert(0) += 1;
    }
    decoded
}

/// The Slack pull collector for one configured workspace.
#[derive(Debug, Clone)]
pub struct SlackPullV1 {
    settings: SlackSettingsV1,
    api: SlackApiV1,
}

/// What one channel's read ended as.
enum ChannelEndV1 {
    /// Outside the pass's domain: its audience is refused.
    Outside,
    /// In the domain, read this far.
    Listed(ListingBoundV1),
}

/// State one pass shares across its channels.
struct PassStateV1 {
    budget: u32,
    stop: Option<PartialReasonV1>,
    counters: BTreeMap<&'static str, u64>,
}

impl PassStateV1 {
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

    /// What a failed call makes of the channel in progress; a refused
    /// credential fails the pass.
    fn refusal(&mut self, error: SlackCallErrorV1) -> Result<PartialReasonV1> {
        match error {
            SlackCallErrorV1::RateLimited => {
                self.bump("rate_limited");
                self.stop = Some(PartialReasonV1::RateLimited);
                Ok(PartialReasonV1::RateLimited)
            }
            SlackCallErrorV1::Credential(code) => Err(FleetError::Configuration(format!(
                "Slack refused the collector's token ({code}); nothing more was read"
            ))),
            SlackCallErrorV1::Refused(_) => {
                self.bump("provider_refused");
                Ok(PartialReasonV1::ProviderRefused)
            }
            SlackCallErrorV1::Http(_) | SlackCallErrorV1::Malformed(_) => {
                self.bump("http_errors");
                Ok(PartialReasonV1::Unreadable)
            }
        }
    }
}

/// Which listing a page came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListingV1 {
    History,
    Replies,
}

/// Where the channel-level messages a read saw every one of start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LowerV1 {
    /// None: the read saw no range whole.
    Nothing,
    /// The channel's whole history.
    All,
    /// After this `ts` (exclusive): the window's start.
    After(u64),
    /// From this `ts` (inclusive): where a read cut short got to.
    From(u64),
}

/// The channel-level messages and roots a read saw every one of, by `ts`
/// in microseconds: those from `lower`, and before `before` (where a resumed
/// read began), with the thread of each root that has replies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ViewV1 {
    lower: LowerV1,
    before: Option<u64>,
}

impl ViewV1 {
    fn contains(&self, micros: u64) -> bool {
        let lower = match self.lower {
            LowerV1::Nothing => false,
            LowerV1::All => true,
            LowerV1::After(start) => micros > start,
            LowerV1::From(start) => micros >= start,
        };
        lower && self.before.is_none_or(|before| micros < before)
    }
}

/// One channel's read in one pass.
struct ChannelReadV1<'k> {
    provider: ProviderKindV1,
    scope: String,
    channel: String,
    label: Option<String>,
    workspace: Option<String>,
    key: Sha256Digest,
    audience: ProviderAudienceV1,
    known: &'k BTreeMap<String, KnownVersionV1>,
    /// Every `ts` the read returned.
    seen: BTreeSet<String>,
    /// Roots the history returned with no replies left: a reply the memory
    /// holds on one is missing.
    childless: BTreeSet<String>,
    /// The roots with replies on the history page being read, newest first,
    /// with their newest reply.
    page_roots: Vec<(SlackTsV1, SlackTsV1)>,
    /// The oldest `ts` on the history page being read.
    page_oldest: Option<SlackTsV1>,
    /// The newest channel-level message or root.
    newest_top: Option<SlackTsV1>,
    /// The newest `latest_reply` of a root.
    newest_reply: Option<SlackTsV1>,
    /// Threads read to their end.
    threads_read: BTreeSet<String>,
    /// A message the read returned was not the documented shape: its `ts`
    /// is unknown, so nothing is counted missing.
    malformed: bool,
    /// The read refused an item: the channel is partial.
    refused: bool,
}

impl ChannelReadV1<'_> {
    fn context(&self) -> SlackChannelContextV1<'_> {
        SlackChannelContextV1 {
            provider: &self.provider,
            provider_scope_id: &self.scope,
            channel_id: &self.channel,
            channel_label: self.label.as_deref(),
            workspace_url: self.workspace.as_deref(),
        }
    }

    const fn pulled(&self, draft: CollectedItemDraftV1) -> PulledItemV1 {
        PulledItemV1 {
            draft,
            provider_audience: Some(self.audience),
        }
    }

    /// Stage one page, and remember whether it refused an item.
    async fn stage(
        &mut self,
        stager: &mut PageStager<'_>,
        items: Vec<PulledItemV1>,
        advances: &[CursorAdvanceV1],
        observations: &[ContainerObservationV1],
    ) -> Result<()> {
        let outcome = stager.stage_page(items, advances, observations).await?;
        self.refused |= outcome.items.iter().any(|item| {
            matches!(
                item,
                StagedItemV1::Refused { reason, .. } if *reason != DeadLetterReasonV1::AudienceRefused
            )
        });
        Ok(())
    }

    /// Remember what one history message says about the channel: the
    /// page's oldest `ts`, the newest message, and each root's replies.
    fn note_history(&mut self, message: &SlackMessageV1, ts: &SlackTsV1) {
        if self.page_oldest.as_ref().is_none_or(|oldest| ts < oldest) {
            self.page_oldest = Some(ts.clone());
        }
        if message.is_reply() {
            return;
        }
        if self.newest_top.as_ref().is_none_or(|newest| ts > newest) {
            self.newest_top = Some(ts.clone());
        }
        match message.latest_reply() {
            Some(latest) => {
                if self
                    .newest_reply
                    .as_ref()
                    .is_none_or(|newest| latest > *newest)
                {
                    self.newest_reply = Some(latest.clone());
                }
                self.page_roots.push((ts.clone(), latest));
            }
            None => {
                self.childless.insert(ts.as_str().to_owned());
            }
        }
    }

    /// The items of one page to stage; unchanged messages are kept, and
    /// malformed ones dead-lettered.
    async fn page(
        &mut self,
        stager: &mut PageStager<'_>,
        messages: Vec<PageMessageV1>,
        listing: ListingV1,
        state: &mut PassStateV1,
    ) -> Result<Vec<PulledItemV1>> {
        let mut items = Vec::new();
        for message in messages {
            let message: SlackMessageV1 = match message {
                PageMessageV1::Message(message) => *message,
                PageMessageV1::Malformed(digest) => {
                    self.malformed = true;
                    self.refused = true;
                    state.bump("messages_dead_lettered");
                    stager
                        .dead_letter(
                            Some(self.key),
                            DeadLetterReasonV1::ParseFailed,
                            digest,
                            "a Slack message is not the documented shape",
                        )
                        .await?;
                    continue;
                }
            };
            let Some(ts) = SlackTsV1::parse(&message.ts) else {
                self.malformed = true;
                self.refused = true;
                state.bump("messages_dead_lettered");
                stager
                    .dead_letter(
                        Some(self.key),
                        DeadLetterReasonV1::ValidationFailed,
                        framed_sha256(
                            "ostk-slack-ts-v1",
                            &[self.channel.as_bytes(), message.ts.as_bytes()],
                        ),
                        "a Slack message ts is not <seconds>.<6 digits>",
                    )
                    .await?;
                continue;
            };
            if listing == ListingV1::History {
                self.note_history(&message, &ts);
            } else if !message.is_reply() {
                // The thread's root, which the history already returned.
                continue;
            }
            if !self.seen.insert(ts.as_str().to_owned()) {
                // A thread broadcast is in the history and in its thread.
                continue;
            }
            state.bump("messages_read");
            let external_id = message_external_id(&self.channel, ts.as_str());
            let known = self
                .known
                .get(&external_id)
                .filter(|known| !known.lifecycle.is_tombstone());
            match message_draft(&self.context(), &message) {
                MessageDraftV1::Item(draft) => {
                    if let Some(known) = known
                        && !known.withdrawn
                        && known.provider_order == draft.order_micros
                        && stager.content_digest(&draft) == Some(known.content_digest)
                    {
                        state.bump("messages_unchanged");
                        stager.keep(Some(self.key), known);
                        continue;
                    }
                    state.bump("messages_staged");
                    items.push(self.pulled(*draft));
                }
                MessageDraftV1::Tombstone => {
                    if let Some(known) = known {
                        state.bump("tombstones");
                        items.push(self.pulled(tombstone_draft(
                            &self.context(),
                            &external_id,
                            known.thread_root.as_deref(),
                            known.provider_order,
                        )));
                    } else {
                        state.bump("messages_skipped");
                    }
                }
                MessageDraftV1::Skip => state.bump("messages_skipped"),
            }
        }
        Ok(items)
    }

    /// Whether a message the memory holds was one the read could see: a
    /// channel-level message or root in `view`; a reply in a thread read to
    /// its end, or on a root in `view` that the read returned with no
    /// replies left, or did not return at all.
    fn in_view(
        &self,
        external_id: &str,
        known: &KnownVersionV1,
        ts: &SlackTsV1,
        view: ViewV1,
    ) -> bool {
        let prefix_len = self.channel.len() + 1;
        match known.thread_root.as_deref() {
            Some(root) if root != external_id => root.get(prefix_len..).is_some_and(|root| {
                self.threads_read.contains(root)
                    || (SlackTsV1::parse(root).is_some_and(|root| view.contains(root.micros()))
                        && (self.childless.contains(root) || !self.seen.contains(root)))
            }),
            _ => view.contains(ts.micros()),
        }
    }

    /// After a read of `view`: tombstones for what two consecutive reads
    /// that could see it missed, and the missing counts to keep.
    fn missing(
        &self,
        stored: &BTreeMap<String, u8>,
        view: ViewV1,
        state: &mut PassStateV1,
    ) -> (Vec<PulledItemV1>, BTreeMap<String, u8>) {
        let prefix = format!("{}:", self.channel);
        let mut tombstones = Vec::new();
        let mut kept = BTreeMap::new();
        for (external_id, known) in self
            .known
            .range(prefix.clone()..)
            .take_while(|(external_id, _)| external_id.starts_with(&prefix))
        {
            let ts_text = &external_id[prefix.len()..];
            if known.lifecycle.is_tombstone() || self.seen.contains(ts_text) {
                continue;
            }
            let Some(ts) = SlackTsV1::parse(ts_text) else {
                continue;
            };
            let before = stored.get(ts_text).copied().unwrap_or(0);
            if !self.in_view(external_id, known, &ts, view) {
                if before > 0 {
                    kept.insert(ts_text.to_owned(), before);
                }
                continue;
            }
            let count = before.saturating_add(1);
            if count >= 2 {
                state.bump("tombstones");
                tombstones.push(self.pulled(tombstone_draft(
                    &self.context(),
                    external_id,
                    known.thread_root.as_deref(),
                    known.provider_order,
                )));
            } else {
                state.bump("missing_once");
                kept.insert(ts_text.to_owned(), count);
            }
        }
        while kept.len() > MAX_MISSING {
            kept.pop_last();
        }
        (tombstones, kept)
    }
}

/// Hold current what the memory holds of `channel`: every message whose
/// channel-level message or root is at or after `from` (every one, with no
/// bound), unless it is a tombstone or withdrawn. What a reconciliation read
/// in an earlier pass, so its manifest names every current item.
fn hold_channel(
    known: &BTreeMap<String, KnownVersionV1>,
    channel: &str,
    key: Sha256Digest,
    from: Option<&SlackTsV1>,
    stager: &mut PageStager<'_>,
) {
    let prefix = format!("{channel}:");
    for (external_id, version) in known
        .range(prefix.clone()..)
        .take_while(|(external_id, _)| external_id.starts_with(&prefix))
    {
        if version.lifecycle.is_tombstone() || version.withdrawn {
            continue;
        }
        let top = match version.thread_root.as_deref() {
            Some(root) if root != external_id => root,
            _ => external_id.as_str(),
        };
        let at = top.strip_prefix(&prefix).and_then(SlackTsV1::parse);
        if from.is_none_or(|from| at.is_some_and(|at| at.micros() >= from.micros())) {
            stager.keep(Some(key), version);
        }
    }
}

/// Everything one channel's read is given.
struct ChannelInputV1<'a> {
    input: &'a PullPassInputV1<'a>,
    channel: &'a str,
    key: Sha256Digest,
    workspace: Option<&'a str>,
    /// When the reconciliation this read belongs to started; `None` for an
    /// incremental read.
    run: Option<u64>,
    known: &'a BTreeMap<String, KnownVersionV1>,
    /// The channel's cursor.
    cursor: ChannelCursorV1,
}

impl SlackPullV1 {
    /// A collector over `settings` through `api`.
    #[must_use]
    pub const fn new(settings: SlackSettingsV1, api: SlackApiV1) -> Self {
        Self { settings, api }
    }

    /// Where a channel's history read starts (exclusive); `None` reads it
    /// all.
    fn window(
        &self,
        reconcile: bool,
        cursor: &ChannelCursorV1,
        pass_order_micros: u64,
    ) -> Option<SlackTsV1> {
        let backfill = self.settings.backfill_micros();
        let start = if reconcile {
            None
        } else {
            let rescan = pass_order_micros
                .saturating_sub(u64::from(self.settings.rescan_days) * MICROS_PER_DAY);
            cursor
                .history_ts
                .as_deref()
                .and_then(SlackTsV1::parse)
                .map(|high_water| high_water.micros().min(rescan))
        };
        match (start, backfill) {
            (Some(start), Some(backfill)) => Some(start.max(backfill)),
            (Some(start), None) => Some(start),
            (None, backfill) => backfill,
        }
        .map(SlackTsV1::from_micros)
    }

    /// One channel's cursor.
    async fn channel_cursor(
        stager: &PageStager<'_>,
        channel: &str,
        state: &mut PassStateV1,
    ) -> Result<ChannelCursorV1> {
        Ok(
            match stager.read_cursor(&channel_cursor_domain(channel)).await? {
                Some(stored) => decode_cursor(
                    &stored.cursor_state,
                    |cursor: &ChannelCursorV1| cursor.schema_version,
                    &mut state.counters,
                )
                .unwrap_or_default(),
                None => ChannelCursorV1::default(),
            },
        )
    }

    /// Read one thread to its end: `None` when it was, else why it stopped.
    async fn thread(
        &self,
        read: &mut ChannelReadV1<'_>,
        root: &SlackTsV1,
        state: &mut PassStateV1,
        stager: &mut PageStager<'_>,
    ) -> Result<Option<PartialReasonV1>> {
        let mut page_cursor: Option<String> = None;
        loop {
            if !state.take_call() {
                return Ok(Some(PartialReasonV1::ListingBound));
            }
            let page = match self
                .api
                .replies_page(&read.channel, root.as_str(), page_cursor.as_deref())
                .await
            {
                Ok(page) => page,
                Err(error) => return Ok(Some(state.refusal(error)?)),
            };
            let items = read
                .page(stager, page.messages, ListingV1::Replies, state)
                .await?;
            if !items.is_empty() {
                read.stage(stager, items, &[], &[]).await?;
            }
            if page.unfinished {
                return Ok(Some(PartialReasonV1::Unreadable));
            }
            match page.next_cursor {
                Some(next) => page_cursor = Some(next),
                None => break,
            }
        }
        read.threads_read.insert(root.as_str().to_owned());
        state.bump("threads_read");
        Ok(None)
    }

    /// Read one channel. See the module documentation.
    #[allow(clippy::too_many_lines)] // one linear info -> history and threads -> settle read
    async fn channel(
        &self,
        channel: ChannelInputV1<'_>,
        state: &mut PassStateV1,
        stager: &mut PageStager<'_>,
    ) -> Result<ChannelEndV1> {
        let name = channel.channel;
        let kind = ContainerKindV1::new(CHANNEL_CONTAINER_KIND)?;
        let listed = channel
            .input
            .source
            .audience
            .private_containers
            .iter()
            .any(|listed| listed == name);
        if !state.take_call() {
            return Ok(ChannelEndV1::Listed(ListingBoundV1::Truncated(
                PartialReasonV1::ListingBound,
            )));
        }
        let info = match self.api.conversation_info(name).await {
            Ok(info) => info,
            Err(SlackCallErrorV1::Refused(code)) if code == "channel_not_found" && !listed => {
                // Deleted, or made private without the app in it: a
                // narrowing, never a partial read. Observed as restricted,
                // it withdraws what was admitted through it until a later
                // read finds it readable again.
                stager
                    .stage_page(
                        Vec::new(),
                        &[],
                        &[ContainerObservationV1 {
                            kind,
                            id: name.to_owned(),
                            label: None,
                            provider_audience: ProviderAudienceV1::Restricted,
                        }],
                    )
                    .await?;
                state.bump("channels_gone");
                return Ok(ChannelEndV1::Outside);
            }
            Err(error) => {
                return Ok(ChannelEndV1::Listed(ListingBoundV1::Truncated(
                    state.refusal(error)?,
                )));
            }
        };
        let audience = info.audience();
        let observation = ContainerObservationV1 {
            kind,
            id: name.to_owned(),
            label: info.name.clone(),
            provider_audience: audience,
        };
        let scope = channel.input.instance.provider_scope_id.as_str();
        let decision = classify(&AudienceInputV1 {
            mode: CollectionModeV1::Pull,
            provider: SLACK_PROVIDER,
            provider_scope_id: scope,
            container_id: Some(name),
            provider_audience: Some(audience),
            hint: None,
            policy: &channel.input.source.audience,
            capture_scopes: &[],
            known_container: KnownContainerV1::Unknown,
        });
        if let AudienceDecisionV1::Refuse(_) = decision {
            // Never read; the observation withdraws what was admitted.
            stager.stage_page(Vec::new(), &[], &[observation]).await?;
            state.bump("channels_refused");
            return Ok(ChannelEndV1::Outside);
        }
        let cursor = channel.cursor;
        let run = channel.run;
        let oldest = self.window(run.is_some(), &cursor, channel.input.pass_order_micros);
        // A read of the same kind cut short resumes before where it got to.
        let resumed = cursor
            .progress
            .clone()
            .filter(|progress| progress.run == run);
        let before = resumed
            .as_ref()
            .and_then(|progress| SlackTsV1::parse(&progress.latest));
        if let Some(before) = &before {
            state.bump("channels_resumed");
            if run.is_some() {
                hold_channel(channel.known, name, channel.key, Some(before), stager);
            }
        }
        let parsed = |value: Option<&String>| value.and_then(|value| SlackTsV1::parse(value));
        let mut read = ChannelReadV1 {
            provider: ProviderKindV1::new(SLACK_PROVIDER)?,
            scope: scope.to_owned(),
            channel: name.to_owned(),
            label: info.name,
            workspace: channel.workspace.map(str::to_owned),
            key: channel.key,
            audience,
            known: channel.known,
            seen: BTreeSet::new(),
            childless: BTreeSet::new(),
            page_roots: Vec::new(),
            page_oldest: None,
            newest_top: parsed(resumed.as_ref().and_then(|p| p.newest_top.as_ref())),
            newest_reply: parsed(resumed.as_ref().and_then(|p| p.newest_reply.as_ref())),
            threads_read: BTreeSet::new(),
            malformed: false,
            refused: resumed.as_ref().is_some_and(|progress| progress.refused),
        };
        let reply_mark = cursor.reply_ts.as_deref().and_then(SlackTsV1::parse);
        let mut observation = Some(observation);
        let mut bound = ListingBoundV1::Complete;
        // Every channel-level message and root at or after it, with its
        // thread, has been read.
        let mut boundary = before.clone();

        // The history, newest first, each page's threads read before the
        // next page.
        let mut page_cursor: Option<String> = None;
        'history: loop {
            if !state.take_call() {
                bound = ListingBoundV1::Truncated(PartialReasonV1::ListingBound);
                break;
            }
            let page = match self
                .api
                .history_page(
                    name,
                    oldest.as_ref().map(SlackTsV1::as_str),
                    before.as_ref().map(SlackTsV1::as_str),
                    page_cursor.as_deref(),
                )
                .await
            {
                Ok(page) => page,
                Err(error) => {
                    bound = ListingBoundV1::Truncated(state.refusal(error)?);
                    break;
                }
            };
            read.page_roots.clear();
            read.page_oldest = None;
            let items = read
                .page(stager, page.messages, ListingV1::History, state)
                .await?;
            let observations: Vec<ContainerObservationV1> =
                observation.take().into_iter().collect();
            read.stage(stager, items, &[], &observations).await?;
            let roots: Vec<SlackTsV1> = std::mem::take(&mut read.page_roots)
                .into_iter()
                .filter(|(_, latest)| {
                    run.is_some() || reply_mark.as_ref().is_none_or(|mark| latest > mark)
                })
                .map(|(root, _)| root)
                .collect();
            for root in roots {
                if let Some(reason) = self.thread(&mut read, &root, state, stager).await? {
                    bound = ListingBoundV1::Truncated(reason);
                    break 'history;
                }
                boundary = Some(root);
            }
            if let Some(oldest_on_page) = read.page_oldest.clone() {
                boundary = Some(oldest_on_page);
            }
            if page.unfinished {
                bound = ListingBoundV1::Truncated(PartialReasonV1::Unreadable);
                break;
            }
            match page.next_cursor {
                Some(next) => page_cursor = Some(next),
                None => break,
            }
        }

        // A read that reached its end, or that the budget or a rate limit
        // cut short, settles what it saw whole: tombstones for what two reads
        // that could see it missed, and the cursor. Any other read holds it.
        let observations: Vec<ContainerObservationV1> = observation.take().into_iter().collect();
        let stopped = bound != ListingBoundV1::Complete && state.stop.is_some();
        if bound == ListingBoundV1::Complete || stopped {
            let view = ViewV1 {
                lower: match (stopped, &boundary, &oldest) {
                    (true, Some(boundary), _) => LowerV1::From(boundary.micros()),
                    (true, None, _) => LowerV1::Nothing,
                    (false, _, Some(oldest)) => LowerV1::After(oldest.micros()),
                    (false, _, None) => LowerV1::All,
                },
                before: before.as_ref().map(SlackTsV1::micros),
            };
            let (tombstones, missing) = if read.malformed {
                (Vec::new(), cursor.missing.clone())
            } else {
                read.missing(&cursor.missing, view, state)
            };
            let newest = |stored: Option<&str>, read: Option<&SlackTsV1>| -> Option<SlackTsV1> {
                let stored = stored.and_then(SlackTsV1::parse);
                match (stored, read) {
                    (Some(stored), Some(read)) => Some(stored.max(read.clone())),
                    (stored, read) => stored.or_else(|| read.cloned()),
                }
            };
            let mut next = cursor.clone();
            next.schema_version = CURSOR_SCHEMA_VERSION;
            next.missing = missing;
            if stopped {
                next.progress = boundary.map(|boundary| ChannelProgressV1 {
                    run,
                    latest: boundary.as_str().to_owned(),
                    newest_top: read.newest_top.as_ref().map(|ts| ts.as_str().to_owned()),
                    newest_reply: read.newest_reply.as_ref().map(|ts| ts.as_str().to_owned()),
                    refused: read.refused,
                });
            } else {
                let history_ts = newest(cursor.history_ts.as_deref(), read.newest_top.as_ref());
                next.history_ts = history_ts.as_ref().map(|ts| ts.as_str().to_owned());
                next.reply_ts = newest(cursor.reply_ts.as_deref(), read.newest_reply.as_ref())
                    .map(|ts| ts.as_str().to_owned());
                next.progress = None;
                if let Some(started) = run {
                    next.reconciled = Some(started);
                    next.reconciled_refused = read.refused;
                }
                if read.refused {
                    // A refusal in an earlier pass of this read.
                    stager.mark_partial(Some(channel.key), PartialReasonV1::ItemRefused);
                }
            }
            let high_water = next
                .history_ts
                .as_deref()
                .and_then(SlackTsV1::parse)
                .map(|ts| ts.micros());
            let advance = encode_cursor(
                &next,
                channel_cursor_domain(name),
                high_water,
                channel.input.pass_seq,
            )?;
            read.stage(stager, tombstones, &[advance], &observations)
                .await?;
        } else if !observations.is_empty() {
            stager.stage_page(Vec::new(), &[], &observations).await?;
        }
        Ok(ChannelEndV1::Listed(bound))
    }
}

/// The workspace's `https://host` from `auth.test`'s URL, for permalinks.
fn workspace_origin(url: Option<&str>) -> Option<String> {
    let url = url::Url::parse(url?).ok()?;
    (url.scheme() == "https").then_some(())?;
    let url::Host::Domain(host) = url.host()? else {
        return None;
    };
    Some(format!("https://{host}"))
}

/// An id Slack sent, cut to the characters an id has, for a message.
fn shown_id(value: &str) -> String {
    value
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .take(32)
        .collect()
}

#[async_trait]
impl PullCollectorV1 for SlackPullV1 {
    fn counter_keys(&self) -> &'static [&'static str] {
        &SLACK_COUNTERS
    }

    fn proof_method(&self) -> CoverageProofMethodV1 {
        CoverageProofMethodV1::ClosedProviderQuery
    }

    fn observation_audience(&self) -> ProviderAudienceV1 {
        // The pass summary names the instance and counts; every member of
        // the workspace may read that.
        ProviderAudienceV1::ScopePublic
    }

    #[allow(clippy::too_many_lines)] // one linear auth -> schedule -> channels -> schedule pass
    async fn pass(
        &self,
        input: &PullPassInputV1<'_>,
        stager: &mut PageStager<'_>,
    ) -> Result<PullPassOutcomeV1> {
        let mut state = PassStateV1 {
            budget: self.settings.max_pages_per_tick,
            stop: None,
            counters: SLACK_COUNTERS.iter().map(|key| (*key, 0)).collect(),
        };
        let auth = match self.api.auth_test().await {
            Ok(auth) => auth,
            Err(error) => {
                return Err(FleetError::Configuration(format!(
                    "Slack auth.test failed: {error}"
                )));
            }
        };
        let pinned = input.instance.provider_scope_id.as_str();
        if auth.team_id != pinned {
            return Err(FleetError::Configuration(format!(
                "the Slack token belongs to team {}, but the collector is pinned to team \
                 {pinned}; nothing was read",
                shown_id(&auth.team_id)
            )));
        }
        if let Some(enterprise) = &self.settings.enterprise_id
            && auth.enterprise_id.as_deref() != Some(enterprise.as_str())
        {
            return Err(FleetError::Configuration(format!(
                "the Slack token is not installed in organization {enterprise}; nothing was read"
            )));
        }
        let workspace = workspace_origin(auth.url.as_deref());

        let stored = match stager.read_cursor(RECONCILE_CURSOR_DOMAIN).await? {
            Some(stored) => decode_cursor(
                &stored.cursor_state,
                |cursor: &ReconcileCursorV1| cursor.schema_version,
                &mut state.counters,
            ),
            None => None,
        };
        let schedule = stored.clone().unwrap_or_else(|| ReconcileCursorV1 {
            schema_version: CURSOR_SCHEMA_VERSION,
            ..ReconcileCursorV1::default()
        });
        let every = self
            .settings
            .reconcile_every_seconds
            .saturating_mul(1_000_000);
        let due = schedule
            .last_complete_micros
            .is_none_or(|last| input.pass_order_micros.saturating_sub(last) >= every);
        // A reconciliation under way is continued; one that is due starts.
        let run = schedule
            .under_way
            .or_else(|| due.then_some(input.pass_order_micros));
        let reconcile = run.is_some();
        state.counters.insert("reconcile", u64::from(reconcile));

        let known = stager
            .known_versions(&ObjectKindV1::new(MESSAGE_OBJECT_KIND)?)
            .await?;
        let kind = ContainerKindV1::new(CHANNEL_CONTAINER_KIND)?;
        let mut channels = self.settings.channels.clone();
        channels.sort();
        // Start where the last pass was cut short, so every channel gets its
        // turn at the budget; outcomes keep the channels' sorted order.
        let first = schedule
            .resume_at
            .as_ref()
            .and_then(|at| channels.iter().position(|channel| channel == at))
            .unwrap_or(0);
        let mut ends: Vec<(usize, Sha256Digest, ChannelEndV1)> = Vec::with_capacity(channels.len());
        let mut resume_at: Option<String> = None;
        for index in (first..channels.len()).chain(0..first) {
            let name = &channels[index];
            let key = stager.container_key(&kind, name);
            let end = if let Some(reason) = state.stop {
                resume_at.get_or_insert_with(|| name.clone());
                ChannelEndV1::Listed(ListingBoundV1::Truncated(reason))
            } else {
                let cursor = Self::channel_cursor(stager, name, &mut state).await?;
                if let Some(started) = run
                    && cursor.reconciled == Some(started)
                {
                    // Read to its end earlier in this reconciliation.
                    state.bump("channels_already_reconciled");
                    hold_channel(&known, name, key, None, stager);
                    if cursor.reconciled_refused {
                        stager.mark_partial(Some(key), PartialReasonV1::ItemRefused);
                    }
                    ChannelEndV1::Listed(ListingBoundV1::Complete)
                } else {
                    let end = self
                        .channel(
                            ChannelInputV1 {
                                input,
                                channel: name,
                                key,
                                workspace: workspace.as_deref(),
                                run,
                                known: &known,
                                cursor,
                            },
                            &mut state,
                            stager,
                        )
                        .await?;
                    if state.stop.is_some() {
                        resume_at.get_or_insert_with(|| name.clone());
                    }
                    end
                }
            };
            ends.push((index, key, end));
        }
        ends.sort_by_key(|(index, _, _)| *index);
        let mut containers = Vec::with_capacity(ends.len());
        for (_, key, end) in ends {
            if let ChannelEndV1::Listed(listing) = end {
                containers.push(ContainerOutcomeV1 {
                    ordinal: u32::try_from(containers.len()).unwrap_or(u32::MAX),
                    container_key: Some(key),
                    listing,
                });
            }
        }

        let mut next = schedule;
        next.schema_version = CURSOR_SCHEMA_VERSION;
        if let Some(started) = run {
            if state.stop.is_none() {
                next.last_complete_micros = Some(started);
                next.under_way = None;
            } else {
                next.under_way = Some(started);
            }
        }
        next.resume_at = resume_at;
        if stored.as_ref() != Some(&next) {
            let advance = encode_cursor(
                &next,
                RECONCILE_CURSOR_DOMAIN.to_owned(),
                next.last_complete_micros,
                input.pass_seq,
            )?;
            stager.stage_page(Vec::new(), &[advance], &[]).await?;
        }
        Ok(PullPassOutcomeV1 {
            containers,
            reconcile,
            counters: state.counters,
            window_start: if reconcile {
                self.settings
                    .backfill_micros()
                    .and_then(render::micros_timestamp)
            } else {
                None
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(settings: &serde_json::Value, audience: &serde_json::Value) -> CollectorSourceV1 {
        serde_json::from_value(serde_json::json!({
            "provider": "slack",
            "connector_principal": "principal.slack",
            "connector_instance": "slack.acme",
            "provider_scope_id": "T07ACME0001",
            "audience": audience,
            "settings": settings
        }))
        .unwrap()
    }

    fn settings(extra: &serde_json::Value) -> serde_json::Value {
        let mut settings = serde_json::json!({
            "token_env": "FLEET_RECALL_SLACK_BOT_TOKEN",
            "channels": ["C07PLATENG1", "C07PRIVATE1"]
        });
        settings
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        settings
    }

    #[test]
    fn settings_are_closed_bounded_and_default_to_the_public_api() {
        let adapter = SlackAdapterV1;
        let listed = serde_json::json!({"private_containers": ["C07PRIVATE1"]});
        adapter
            .validate(&source(&settings(&serde_json::json!({})), &listed))
            .unwrap();
        let parsed =
            SlackSettingsV1::from_source(&source(&settings(&serde_json::json!({})), &listed))
                .unwrap();
        assert_eq!(parsed.api_base, DEFAULT_SLACK_API_BASE);
        assert_eq!(parsed.rescan_days, DEFAULT_RESCAN_DAYS);
        assert_eq!(
            parsed.reconcile_every_seconds,
            DEFAULT_RECONCILE_EVERY_SECONDS
        );
        assert_eq!(parsed.backfill_since, None);
        assert_eq!(
            adapter.reconcile_every_seconds(&source(&settings(&serde_json::json!({})), &listed)),
            Some(DEFAULT_RECONCILE_EVERY_SECONDS)
        );

        for (extra, needle) in [
            (
                serde_json::json!({"api_base": "http://slack.example.com/api"}),
                "not loopback",
            ),
            (serde_json::json!({"token_env": "lower"}), "token_env"),
            (serde_json::json!({"channels": []}), "settings.channels"),
            (
                serde_json::json!({"channels": ["D07DIRECT01"]}),
                "direct conversation",
            ),
            (
                serde_json::json!({"channels": ["general"]}),
                "not a channel id",
            ),
            (
                serde_json::json!({"channels": ["C07PLATENG1", "C07PLATENG1"]}),
                "twice",
            ),
            (serde_json::json!({"rescan_days": 0}), "rescan_days"),
            (
                serde_json::json!({"reconcile_every_seconds": 10}),
                "reconcile_every_seconds",
            ),
            (serde_json::json!({"page_size": 1000}), "page_size"),
            (
                serde_json::json!({"max_pages_per_tick": 0}),
                "max_pages_per_tick",
            ),
            (serde_json::json!({"enterprise_id": "T1"}), "enterprise_id"),
            (serde_json::json!({"follow_links": true}), "follow_links"),
        ] {
            let message = adapter
                .validate(&source(&settings(&extra), &listed))
                .unwrap_err();
            assert!(message.contains(needle), "{extra}: {message}");
        }
        let loopback = serde_json::json!({"api_base": "http://127.0.0.1:9/api"});
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
    }

    #[test]
    fn a_missing_token_fails_the_collector_before_any_request() {
        let error = SlackAdapterV1
            .pull(
                &source(&settings(&serde_json::json!({})), &serde_json::json!({})),
                &|_: &str| None,
            )
            .err()
            .expect("no token, no collector");
        assert!(error.contains("FLEET_RECALL_SLACK_BOT_TOKEN"), "{error}");
    }

    #[test]
    fn the_window_is_the_backfill_on_a_reconciliation_and_the_rescan_otherwise() {
        let token = ProviderTokenV1::from_environment("T", &|_: &str| Some("t".into())).unwrap();
        let api = SlackApiV1::new(
            ProviderHttpV1::new("http://127.0.0.1:1/api", &token, AuthSchemeV1::Bearer).unwrap(),
            10,
        );
        let backfill = DateTime::parse_from_rfc3339("2026-09-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut settings: SlackSettingsV1 = serde_json::from_value(settings(&serde_json::json!({
            "rescan_days": 2
        })))
        .unwrap();
        let now = 1_790_000_000_000_000;
        let collector = SlackPullV1::new(settings.clone(), api.clone());
        let fresh = ChannelCursorV1::default();
        assert_eq!(
            collector.window(true, &fresh, now),
            None,
            "the whole history"
        );
        assert_eq!(collector.window(false, &fresh, now), None);
        let recent = ChannelCursorV1 {
            history_ts: Some(SlackTsV1::from_micros(now - 1_000_000).as_str().to_owned()),
            ..ChannelCursorV1::default()
        };
        assert_eq!(
            collector.window(false, &recent, now).unwrap().micros(),
            now - 2 * MICROS_PER_DAY,
            "the trailing rescan"
        );
        let stale = ChannelCursorV1 {
            history_ts: Some(
                SlackTsV1::from_micros(now - 30 * MICROS_PER_DAY)
                    .as_str()
                    .to_owned(),
            ),
            ..ChannelCursorV1::default()
        };
        assert_eq!(
            collector.window(false, &stale, now).unwrap().micros(),
            now - 30 * MICROS_PER_DAY,
            "an outage is caught up from the high-water mark"
        );
        settings.backfill_since = Some(backfill);
        let collector = SlackPullV1::new(settings, api);
        let backfill_micros = u64::try_from(backfill.timestamp_micros()).unwrap();
        assert_eq!(
            collector.window(true, &stale, now).unwrap().micros(),
            backfill_micros
        );
        assert_eq!(
            collector.window(false, &fresh, now).unwrap().micros(),
            backfill_micros
        );
        let ancient = ChannelCursorV1 {
            history_ts: Some("1.000000".to_owned()),
            ..ChannelCursorV1::default()
        };
        assert_eq!(
            collector.window(false, &ancient, now).unwrap().micros(),
            backfill_micros,
            "never before the backfill"
        );
    }

    fn known(
        external_id: &str,
        thread_root: Option<&str>,
        lifecycle: crate::memory_contracts::collected_item::ItemLifecycleV1,
    ) -> (String, KnownVersionV1) {
        (
            external_id.to_owned(),
            KnownVersionV1 {
                item_key: Sha256Digest::from_bytes([1; 32]),
                version_key: Sha256Digest::from_bytes([2; 32]),
                content_digest: Sha256Digest::from_bytes([3; 32]),
                lifecycle,
                provider_order: 42,
                pending: Vec::new(),
                thread_root: thread_root.map(str::to_owned),
                container_key: None,
                withdrawn: false,
            },
        )
    }

    #[test]
    fn a_message_is_tombstoned_only_after_two_complete_reads_that_could_see_it_missed_it() {
        use crate::memory_contracts::collected_item::ItemLifecycleV1::{Deleted, Live};
        let known: BTreeMap<String, KnownVersionV1> = [
            known("C1:1790000010.000000", None, Live),
            known("C1:1790000020.000000", None, Live),
            known("C1:1790000030.000000", Some("C1:1790000020.000000"), Live),
            known("C1:1790000040.000000", Some("C1:1790000099.000000"), Live),
            known("C1:1790000050.000000", None, Deleted),
            known("C1:1700000000.000000", None, Live),
            known("C2:1790000010.000000", None, Live),
        ]
        .into_iter()
        .collect();
        let mut read = read_of("C1", &known);
        // Root 99 was returned with replies, but its thread was not read.
        read.seen = BTreeSet::from([
            "1790000020.000000".to_owned(),
            "1790000099.000000".to_owned(),
        ]);
        read.threads_read = BTreeSet::from(["1790000020.000000".to_owned()]);
        let mut state = state();
        let oldest = ViewV1 {
            lower: LowerV1::After(1_780_000_000_000_000),
            before: None,
        };
        let (tombstones, missing) = read.missing(&BTreeMap::new(), oldest, &mut state);
        assert!(tombstones.is_empty(), "one miss hides nothing");
        assert_eq!(
            missing.keys().collect::<Vec<_>>(),
            ["1790000010.000000", "1790000030.000000"],
            "a root in the window and a reply in a thread read: not a reply in an unread \
             thread, a tombstone, a message before the window, or another channel's"
        );

        let (tombstones, missing) = read.missing(&missing, oldest, &mut state);
        assert!(missing.is_empty());
        let ids: Vec<&str> = tombstones
            .iter()
            .map(|item| item.draft.external_id.as_str())
            .collect();
        assert_eq!(ids, ["C1:1790000010.000000", "C1:1790000030.000000"]);
        for item in &tombstones {
            assert_eq!(item.draft.lifecycle, Deleted);
            assert_eq!(item.draft.order_micros, 42, "at the head's own order");
        }
        assert_eq!(
            tombstones[1]
                .draft
                .thread
                .as_ref()
                .unwrap()
                .root_external_id,
            "C1:1790000020.000000"
        );

        // Seen again before the second miss: the count starts over.
        read.seen.insert("1790000010.000000".to_owned());
        let once = BTreeMap::from([("1790000010.000000".to_owned(), 1)]);
        let (tombstones, missing) = read.missing(&once, oldest, &mut state);
        assert!(
            tombstones
                .iter()
                .all(|item| !item.draft.external_id.ends_with("10.000000"))
        );
        assert!(!missing.contains_key("1790000010.000000"));
        // Out of view, a count is kept, neither advanced nor cleared.
        read.threads_read.clear();
        let held = BTreeMap::from([("1790000030.000000".to_owned(), 1)]);
        let (tombstones, missing) = read.missing(&held, oldest, &mut state);
        assert!(tombstones.is_empty());
        assert_eq!(missing.get("1790000030.000000"), Some(&1));
    }

    fn read_of<'k>(
        channel: &str,
        known: &'k BTreeMap<String, KnownVersionV1>,
    ) -> ChannelReadV1<'k> {
        ChannelReadV1 {
            provider: ProviderKindV1::new("slack").unwrap(),
            scope: "T1".into(),
            channel: channel.into(),
            label: None,
            workspace: None,
            key: Sha256Digest::from_bytes([9; 32]),
            audience: ProviderAudienceV1::ScopePublic,
            known,
            seen: BTreeSet::new(),
            childless: BTreeSet::new(),
            page_roots: Vec::new(),
            page_oldest: None,
            newest_top: None,
            newest_reply: None,
            threads_read: BTreeSet::new(),
            malformed: false,
            refused: false,
        }
    }

    fn state() -> PassStateV1 {
        PassStateV1 {
            budget: 1,
            stop: None,
            counters: BTreeMap::new(),
        }
    }

    #[test]
    fn the_replies_of_a_root_left_with_none_or_gone_are_missing() {
        use crate::memory_contracts::collected_item::ItemLifecycleV1::Live;
        let known: BTreeMap<String, KnownVersionV1> = [
            known("C1:1790000020.000000", None, Live),
            known("C1:1790000021.000000", Some("C1:1790000020.000000"), Live),
            known("C1:1790000030.000000", None, Live),
            known("C1:1790000031.000000", Some("C1:1790000030.000000"), Live),
            known("C1:1790000040.000000", None, Live),
            known("C1:1790000041.000000", Some("C1:1790000040.000000"), Live),
            known("C1:1790000051.000000", Some("C1:1690000050.000000"), Live),
        ]
        .into_iter()
        .collect();
        let mut read = read_of("C1", &known);
        // The history returned root 20 with no replies left, root 40 with
        // replies (its thread not read this time), and not root 30 at all.
        read.seen = BTreeSet::from([
            "1790000020.000000".to_owned(),
            "1790000040.000000".to_owned(),
        ]);
        read.childless = BTreeSet::from(["1790000020.000000".to_owned()]);
        let view = ViewV1 {
            lower: LowerV1::After(1_780_000_000_000_000),
            before: None,
        };
        let (_, missing) = read.missing(&BTreeMap::new(), view, &mut state());
        assert_eq!(
            missing.keys().collect::<Vec<_>>(),
            [
                "1790000021.000000",
                "1790000030.000000",
                "1790000031.000000"
            ],
            "the reply of a childless root, and a gone root with its reply; not the reply \
             of a root whose thread was not read, nor one on a root before the window"
        );

        // A read cut short sees only from where it got to, and before where a
        // resumed read began.
        let cut = ViewV1 {
            lower: LowerV1::From(1_790_000_030_000_000),
            before: Some(1_790_000_040_000_000),
        };
        let (_, missing) = read.missing(&BTreeMap::new(), cut, &mut state());
        assert_eq!(
            missing.keys().collect::<Vec<_>>(),
            ["1790000030.000000", "1790000031.000000"]
        );
        let nothing = ViewV1 {
            lower: LowerV1::Nothing,
            before: None,
        };
        let (_, missing) = read.missing(&BTreeMap::new(), nothing, &mut state());
        assert!(missing.is_empty());
    }

    #[test]
    fn a_cursor_that_does_not_decode_is_reset_and_counted() {
        let mut counters = BTreeMap::new();
        let cursor = ChannelCursorV1 {
            schema_version: CURSOR_SCHEMA_VERSION,
            history_ts: Some("1790000000.000100".into()),
            reply_ts: None,
            missing: BTreeMap::from([("1790000000.000200".into(), 1)]),
            ..ChannelCursorV1::default()
        };
        let bytes = serde_json::to_vec(&cursor).unwrap();
        assert_eq!(
            decode_cursor(
                &bytes,
                |cursor: &ChannelCursorV1| cursor.schema_version,
                &mut counters
            ),
            Some(cursor)
        );
        assert!(
            decode_cursor(
                b"{\"schema_version\":2}",
                |cursor: &ChannelCursorV1| { cursor.schema_version },
                &mut counters
            )
            .is_none()
        );
        assert!(
            decode_cursor(
                b"garbage",
                |cursor: &ChannelCursorV1| cursor.schema_version,
                &mut counters
            )
            .is_none()
        );
        assert_eq!(counters["cursors_reset"], 2);
        let largest = ChannelCursorV1 {
            schema_version: CURSOR_SCHEMA_VERSION,
            history_ts: Some("999999999999.999999".into()),
            reply_ts: Some("999999999999.999999".into()),
            missing: (0..MAX_MISSING)
                .map(|index| (format!("{index:012}.{index:06}"), 1))
                .collect(),
            reconciled: Some(u64::MAX),
            reconciled_refused: true,
            progress: Some(ChannelProgressV1 {
                run: Some(u64::MAX),
                latest: "999999999999.999999".into(),
                newest_top: Some("999999999999.999999".into()),
                newest_reply: Some("999999999999.999999".into()),
                refused: true,
            }),
        };
        assert!(serde_json::to_vec(&largest).unwrap().len() < 16_384);
        // A cursor written before reconciliations could resume still reads.
        let older: ReconcileCursorV1 =
            serde_json::from_slice(br#"{"schema_version":1,"last_complete_micros":42}"#).unwrap();
        assert_eq!(older.last_complete_micros, Some(42));
        assert_eq!(older.under_way, None);
    }

    #[test]
    fn a_listed_private_channel_is_a_configured_channel_id() {
        let adapter = SlackAdapterV1;
        for (listed, needle) in [
            (serde_json::json!(["secret-team"]), "not a channel id"),
            (serde_json::json!(["#plat-sec"]), "not a channel id"),
            (serde_json::json!(["c07private1"]), "not a channel id"),
            (
                serde_json::json!(["C07OTHER001"]),
                "settings.channels does not",
            ),
        ] {
            let message = adapter
                .validate(&source(
                    &settings(&serde_json::json!({})),
                    &serde_json::json!({"private_containers": listed}),
                ))
                .unwrap_err();
            assert!(message.contains(needle), "{listed}: {message}");
        }
    }

    #[test]
    fn the_workspace_origin_is_https_only() {
        assert_eq!(
            workspace_origin(Some("https://acme-robotics.slack.com/")).as_deref(),
            Some("https://acme-robotics.slack.com")
        );
        assert_eq!(workspace_origin(Some("http://acme.slack.com/")), None);
        assert_eq!(workspace_origin(Some("https://10.0.0.1/")), None);
        assert_eq!(workspace_origin(None), None);
        assert_eq!(shown_id("T07<b>OTHER"), "T07bOTHER");
    }
}
