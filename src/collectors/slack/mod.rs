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
//! 2. The pass is a **reconciliation** when none has finished within
//!    `reconcile_every_seconds` (the `slack.reconcile` cursor), else an
//!    **incremental** pass. Only a reconciliation writes coverage and the
//!    status row's `last_checked_at`.
//! 3. For each channel, in id order, `conversations.info` gives its name and
//!    audience ([`api::SlackChannelInfoV1::audience`]), recorded as a
//!    container observation. A direct, group-direct, or externally shared
//!    conversation, and a private or org-shared one the operator did not list
//!    in `audience.private_containers`, is never read: its observation
//!    withdraws the container, which hides what was admitted through it, and
//!    it is outside the pass's domain.
//! 4. `conversations.history` is paged on `next_cursor` from the window's
//!    start (exclusive): `backfill_since` (else the channel's whole history)
//!    for a reconciliation; for an incremental pass, the trailing
//!    `rescan_days` or the channel's high-water mark, whichever is older, so a
//!    rescan picks up edits (a new `edited.ts`) and a long outage is caught up.
//! 5. `conversations.replies` reads every thread in the window on a
//!    reconciliation, and on an incremental pass every thread whose
//!    `latest_reply` is past the channel's reply cursor.
//! 6. Every message becomes a draft ([`render::message_draft`]); one the
//!    memory already holds at the same version and content is kept rather
//!    than staged. Each API page is one sink transaction.
//! 7. **Deletions.** A message the memory holds, inside what a complete read
//!    of the channel could see (a channel-level message or root in the
//!    history window, a reply in a thread read to its end), that the read did
//!    not return is counted in the channel's cursor; missing from two
//!    consecutive complete reads, it gets a `deleted` tombstone at its own
//!    order (a tombstone wins the tie). A read that returned a message it
//!    could not parse counts nothing missing. A `tombstone` message (a root
//!    deleted while its replies remain) hides the root at once.
//! 8. The channel's cursor (high-water marks and missing counts) advances
//!    with its last page, only when the channel was read to its end.
//!
//! # Partial reads
//!
//! Every call counts against `max_pages_per_tick`. `ok: false` for a channel
//! (`not_in_channel`, `missing_scope`, `channel_not_found`) leaves that
//! channel partial and the pass goes on. A rate limit (HTTP 429, or
//! `ratelimited`) or the page budget ends the pass: the channel in progress
//! and every later one are partial, their cursors are held (what was staged
//! stays staged), and a reconciliation cut short is run again on the next
//! pass. An unusable credential (`invalid_auth`, `token_revoked`, ...) fails
//! the pass.
//!
//! # Deliberately absent
//!
//! Reactions, reply counts, unfurls, and presence are never read, and a file
//! is a link, never its content. Direct and group-direct conversations are
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
use super::http::{AuthSchemeV1, ProviderHttpV1, ProviderTokenV1, validate_api_base};
use super::pull::{
    ContainerOutcomeV1, ListingBoundV1, PageStager, PartialReasonV1, PullCollectorV1,
    PullPassInputV1, PullPassOutcomeV1, PulledItemV1,
};
use super::sink::{ContainerObservationV1, CursorAdvanceV1, DeadLetterReasonV1, KnownVersionV1};
use api::{PageMessageV1, SlackApiV1, SlackCallErrorV1};
use render::{
    CHANNEL_CONTAINER_KIND, MESSAGE_OBJECT_KIND, MessageDraftV1, SLACK_PROVIDER,
    SlackChannelContextV1, SlackMessageV1, SlackTsV1, message_draft, message_external_id,
    tombstone_draft,
};

/// The Web API a collector reads unless its settings say otherwise.
pub const DEFAULT_SLACK_API_BASE: &str = "https://slack.com/api";

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
pub const SLACK_COUNTERS: [&str; 16] = [
    "reconcile",
    "api_calls",
    "channels_refused",
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

/// Whether `value` names an environment variable: `[A-Z_][A-Z0-9_]*`.
fn is_variable_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.starts_with(|scalar: char| scalar.is_ascii_digit())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
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
        if !is_variable_name(&self.token_env) {
            return Err(
                "settings.token_env must name an environment variable ([A-Z_][A-Z0-9_]*)"
                    .to_owned(),
            );
        }
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
        validate_api_base(&self.api_base).map_err(|error| format!("settings.api_base: {error}"))?;
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
        SlackSettingsV1::from_source(source)?;
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

/// When the last reconciliation that ran to its end started.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReconcileCursorV1 {
    schema_version: u32,
    last_complete_micros: u64,
}

/// What one channel's complete reads left behind.
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
    /// Roots with replies, and their newest reply.
    roots: Vec<(SlackTsV1, SlackTsV1)>,
    /// The newest channel-level message or root.
    newest_top: Option<SlackTsV1>,
    /// Threads read to their end.
    threads_read: BTreeSet<String>,
    /// A message the read returned was not the documented shape: its `ts`
    /// is unknown, so nothing is counted missing.
    malformed: bool,
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
            if listing == ListingV1::Replies && !message.is_reply() {
                // The thread's root, which the history already returned.
                continue;
            }
            if !self.seen.insert(ts.as_str().to_owned()) {
                // A thread broadcast is in the history and in its thread.
                continue;
            }
            state.bump("messages_read");
            if !message.is_reply() {
                if self.newest_top.as_ref().is_none_or(|newest| ts > *newest) {
                    self.newest_top = Some(ts.clone());
                }
                if let Some(latest) = message.latest_reply() {
                    self.roots.push((ts.clone(), latest));
                }
            }
            let external_id = message_external_id(&self.channel, ts.as_str());
            let known = self
                .known
                .get(&external_id)
                .filter(|known| !known.lifecycle.is_tombstone());
            match message_draft(&self.context(), &message) {
                MessageDraftV1::Item(draft) => {
                    if let Some(known) = known
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

    /// After a complete read: tombstones for what two consecutive complete
    /// reads missed, and the missing counts to keep.
    fn missing(
        &self,
        stored: &BTreeMap<String, u8>,
        oldest: Option<&SlackTsV1>,
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
            let in_view = match known.thread_root.as_deref() {
                Some(root) if root != external_id => root
                    .strip_prefix(&prefix)
                    .is_some_and(|root| self.threads_read.contains(root)),
                _ => oldest.is_none_or(|oldest| ts.micros() > oldest.micros()),
            };
            let before = stored.get(ts_text).copied().unwrap_or(0);
            if !in_view {
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

/// Everything one channel's read is given.
struct ChannelInputV1<'a> {
    input: &'a PullPassInputV1<'a>,
    channel: &'a str,
    key: Sha256Digest,
    workspace: Option<&'a str>,
    reconcile: bool,
    known: &'a BTreeMap<String, KnownVersionV1>,
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

    /// Read one channel. See the module documentation.
    #[allow(clippy::too_many_lines)] // one linear info -> history -> replies -> settle read
    async fn channel(
        &self,
        channel: ChannelInputV1<'_>,
        state: &mut PassStateV1,
        stager: &mut PageStager<'_>,
    ) -> Result<ChannelEndV1> {
        let name = channel.channel;
        if !state.take_call() {
            return Ok(ChannelEndV1::Listed(ListingBoundV1::Truncated(
                PartialReasonV1::ListingBound,
            )));
        }
        let info = match self.api.conversation_info(name).await {
            Ok(info) => info,
            Err(error) => {
                return Ok(ChannelEndV1::Listed(ListingBoundV1::Truncated(
                    state.refusal(error)?,
                )));
            }
        };
        let audience = info.audience();
        let kind = ContainerKindV1::new(CHANNEL_CONTAINER_KIND)?;
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
        let domain = channel_cursor_domain(name);
        let cursor: ChannelCursorV1 = match stager.read_cursor(&domain).await? {
            Some(stored) => decode_cursor(
                &stored.cursor_state,
                |cursor: &ChannelCursorV1| cursor.schema_version,
                &mut state.counters,
            )
            .unwrap_or_default(),
            None => ChannelCursorV1::default(),
        };
        let oldest = self.window(channel.reconcile, &cursor, channel.input.pass_order_micros);
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
            roots: Vec::new(),
            newest_top: None,
            threads_read: BTreeSet::new(),
            malformed: false,
        };
        let mut observation = Some(observation);
        let mut bound = ListingBoundV1::Complete;

        // The history, newest first.
        let mut page_cursor: Option<String> = None;
        loop {
            if !state.take_call() {
                bound = ListingBoundV1::Truncated(PartialReasonV1::ListingBound);
                break;
            }
            let page = match self
                .api
                .history_page(
                    name,
                    oldest.as_ref().map(SlackTsV1::as_str),
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
            let items = read
                .page(stager, page.messages, ListingV1::History, state)
                .await?;
            let observations: Vec<ContainerObservationV1> =
                observation.take().into_iter().collect();
            stager.stage_page(items, &[], &observations).await?;
            if page.unfinished {
                bound = ListingBoundV1::Truncated(PartialReasonV1::Unreadable);
                break;
            }
            match page.next_cursor {
                Some(next) => page_cursor = Some(next),
                None => break,
            }
        }

        // The threads.
        let reply_mark = cursor.reply_ts.as_deref().and_then(SlackTsV1::parse);
        if bound == ListingBoundV1::Complete {
            let threads: Vec<SlackTsV1> = read
                .roots
                .iter()
                .filter(|(_, latest)| {
                    channel.reconcile || reply_mark.as_ref().is_none_or(|mark| latest > mark)
                })
                .map(|(root, _)| root.clone())
                .collect();
            'threads: for root in threads {
                let mut page_cursor: Option<String> = None;
                loop {
                    if !state.take_call() {
                        bound = ListingBoundV1::Truncated(PartialReasonV1::ListingBound);
                        break 'threads;
                    }
                    let page = match self
                        .api
                        .replies_page(name, root.as_str(), page_cursor.as_deref())
                        .await
                    {
                        Ok(page) => page,
                        Err(error) => {
                            bound = ListingBoundV1::Truncated(state.refusal(error)?);
                            break 'threads;
                        }
                    };
                    let items = read
                        .page(stager, page.messages, ListingV1::Replies, state)
                        .await?;
                    if !items.is_empty() {
                        stager.stage_page(items, &[], &[]).await?;
                    }
                    if page.unfinished {
                        bound = ListingBoundV1::Truncated(PartialReasonV1::Unreadable);
                        break 'threads;
                    }
                    match page.next_cursor {
                        Some(next) => page_cursor = Some(next),
                        None => break,
                    }
                }
                read.threads_read.insert(root.as_str().to_owned());
                state.bump("threads_read");
            }
        }

        // A complete read tombstones what two complete reads missed and
        // advances the cursor; a partial one holds it.
        let observations: Vec<ContainerObservationV1> = observation.take().into_iter().collect();
        if bound == ListingBoundV1::Complete {
            let (tombstones, missing) = if read.malformed {
                (Vec::new(), cursor.missing.clone())
            } else {
                read.missing(&cursor.missing, oldest.as_ref(), state)
            };
            let newest = |stored: Option<&str>, read: Option<&SlackTsV1>| -> Option<SlackTsV1> {
                let stored = stored.and_then(SlackTsV1::parse);
                match (stored, read) {
                    (Some(stored), Some(read)) => Some(stored.max(read.clone())),
                    (stored, read) => stored.or_else(|| read.cloned()),
                }
            };
            let history_ts = newest(cursor.history_ts.as_deref(), read.newest_top.as_ref());
            let reply_ts = newest(
                cursor.reply_ts.as_deref(),
                read.roots.iter().map(|(_, latest)| latest).max(),
            );
            let advance = encode_cursor(
                &ChannelCursorV1 {
                    schema_version: CURSOR_SCHEMA_VERSION,
                    history_ts: history_ts.as_ref().map(|ts| ts.as_str().to_owned()),
                    reply_ts: reply_ts.map(|ts| ts.as_str().to_owned()),
                    missing,
                },
                domain,
                history_ts.map(|ts| ts.micros()),
                channel.input.pass_seq,
            )?;
            stager
                .stage_page(tombstones, &[advance], &observations)
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

        let last_complete = match stager.read_cursor(RECONCILE_CURSOR_DOMAIN).await? {
            Some(stored) => decode_cursor(
                &stored.cursor_state,
                |cursor: &ReconcileCursorV1| cursor.schema_version,
                &mut state.counters,
            )
            .map(|cursor| cursor.last_complete_micros),
            None => None,
        };
        let every = self
            .settings
            .reconcile_every_seconds
            .saturating_mul(1_000_000);
        let reconcile =
            last_complete.is_none_or(|last| input.pass_order_micros.saturating_sub(last) >= every);
        state.counters.insert("reconcile", u64::from(reconcile));

        let known = stager
            .known_versions(&ObjectKindV1::new(MESSAGE_OBJECT_KIND)?)
            .await?;
        let kind = ContainerKindV1::new(CHANNEL_CONTAINER_KIND)?;
        let mut channels = self.settings.channels.clone();
        channels.sort();
        let mut containers = Vec::with_capacity(channels.len());
        for name in &channels {
            let key = stager.container_key(&kind, name);
            let end = match state.stop {
                Some(reason) => ChannelEndV1::Listed(ListingBoundV1::Truncated(reason)),
                None => {
                    self.channel(
                        ChannelInputV1 {
                            input,
                            channel: name,
                            key,
                            workspace: workspace.as_deref(),
                            reconcile,
                            known: &known,
                        },
                        &mut state,
                        stager,
                    )
                    .await?
                }
            };
            if let ChannelEndV1::Listed(listing) = end {
                containers.push(ContainerOutcomeV1 {
                    ordinal: u32::try_from(containers.len()).unwrap_or(u32::MAX),
                    container_key: Some(key),
                    listing,
                });
            }
        }
        if reconcile && state.stop.is_none() {
            let advance = encode_cursor(
                &ReconcileCursorV1 {
                    schema_version: CURSOR_SCHEMA_VERSION,
                    last_complete_micros: input.pass_order_micros,
                },
                RECONCILE_CURSOR_DOMAIN.to_owned(),
                Some(input.pass_order_micros),
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
        let mut read = ChannelReadV1 {
            provider: ProviderKindV1::new("slack").unwrap(),
            scope: "T1".into(),
            channel: "C1".into(),
            label: None,
            workspace: None,
            key: Sha256Digest::from_bytes([9; 32]),
            audience: ProviderAudienceV1::ScopePublic,
            known: &known,
            seen: BTreeSet::from(["1790000020.000000".to_owned()]),
            roots: Vec::new(),
            newest_top: None,
            threads_read: BTreeSet::from(["1790000020.000000".to_owned()]),
            malformed: false,
        };
        let mut state = PassStateV1 {
            budget: 1,
            stop: None,
            counters: BTreeMap::new(),
        };
        let oldest = SlackTsV1::parse("1780000000.000000");
        let (tombstones, missing) = read.missing(&BTreeMap::new(), oldest.as_ref(), &mut state);
        assert!(tombstones.is_empty(), "one miss hides nothing");
        assert_eq!(
            missing.keys().collect::<Vec<_>>(),
            ["1790000010.000000", "1790000030.000000"],
            "a root in the window and a reply in a thread read: not a reply in an unread \
             thread, a tombstone, a message before the window, or another channel's"
        );

        let (tombstones, missing) = read.missing(&missing, oldest.as_ref(), &mut state);
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
        let (tombstones, missing) = read.missing(&once, oldest.as_ref(), &mut state);
        assert!(
            tombstones
                .iter()
                .all(|item| !item.draft.external_id.ends_with("10.000000"))
        );
        assert!(!missing.contains_key("1790000010.000000"));
        // Out of view, a count is kept, neither advanced nor cleared.
        read.threads_read.clear();
        let held = BTreeMap::from([("1790000030.000000".to_owned(), 1)]);
        let (tombstones, missing) = read.missing(&held, oldest.as_ref(), &mut state);
        assert!(tombstones.is_empty());
        assert_eq!(missing.get("1790000030.000000"), Some(&1));
    }

    #[test]
    fn a_cursor_that_does_not_decode_is_reset_and_counted() {
        let mut counters = BTreeMap::new();
        let cursor = ChannelCursorV1 {
            schema_version: CURSOR_SCHEMA_VERSION,
            history_ts: Some("1790000000.000100".into()),
            reply_ts: None,
            missing: BTreeMap::from([("1790000000.000200".into(), 1)]),
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
        };
        assert!(serde_json::to_vec(&largest).unwrap().len() < 16_384);
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
