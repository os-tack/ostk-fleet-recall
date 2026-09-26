//! The Granola collector: provider `granola`, pulled by the worker through
//! the official public API with a `grn_` API key (ADR 0008 D8).
//!
//! One instance reads what one key can read. The API names no workspace, so
//! the provider scope id is the operator's own pin for it. The key comes from
//! the environment variable `settings.token_env` names and is only ever a
//! `Bearer` `Authorization` header ([`crate::collectors::http`]). Granola's
//! encrypted desktop cache and its private API are never read.
//!
//! # Audience
//!
//! A key has no provider audience of its own, so the instance must declare
//! itself visible to the project (`audience.operator_declared`), and say
//! which notes: `settings.folders` lists folders (`fol_...`), each one
//! `granola.folder` container, and only a note in a listed folder is staged;
//! or `settings.all_notes_visible_to_key` declares every note the key reads,
//! in one `granola.workspace` container. Every item of a note that leaves
//! the listed folders (its transcript too, whether or not transcripts are
//! still read) is withdrawn and hidden until the note returns; one never in
//! them is never staged.
//! Transcripts are read only with `settings.include_transcript` (off by
//! default); private notes never are.
//!
//! # A pass
//!
//! 1. The pass is a **reconciliation** when none has run to its end within
//!    `reconcile_every_seconds` (the `granola.reconcile` cursor), or one is
//!    under way, else **incremental**. Only a reconciliation writes coverage
//!    and the status row's `last_checked_at`.
//! 2. `notes` is listed to its end: every note on a reconciliation; on an
//!    incremental pass, those updated after the sweep's position less
//!    [`LIST_OVERLAP_SECONDS`]. A listing cut short reads nothing more.
//! 3. **Deletions.** On a reconciliation, a note the memory holds that the
//!    complete listing did not return is counted in the `granola.notes`
//!    cursor; missing from two consecutive complete listings, each of its
//!    items gets a `revoked` tombstone at the order the memory holds. A `404`
//!    for one note never tombstones anything.
//! 4. **The sweep.** The listed notes are taken in `(updated_at, id)` order
//!    from the sweep's position: a reconciliation re-reads every note from
//!    its own position (folder membership and summaries are not in the
//!    listing), an incremental pass every note past the incremental position
//!    and any note in the overlap that neither the memory holds at its listed
//!    `updated_at` nor the cursor remembers settling there. Each note is
//!    `notes/{id}` (with `include=transcript` when transcripts are read; a
//!    `413` reads the note without it, then pages `notes/{id}/transcript`),
//!    and becomes its drafts ([`render`]); an item whose content, lifecycle,
//!    and container the memory already holds is kept, not staged. A note with
//!    something to stage is one sink transaction with the cursor at its
//!    position; notes with nothing to stage move the cursor in batches. So a
//!    pass cut short resumes after the last note it settled. A reconciliation
//!    holds current what it re-read in earlier passes of the same
//!    reconciliation, so its manifest names every current item.
//! 5. A reconciliation that reached the end of its listing is complete: it
//!    moves the incremental position to where it ended and records its start
//!    in the `granola.reconcile` cursor.
//!
//! # Partial reads
//!
//! Every request counts against `max_pages_per_tick` and waits for the
//! client-side pace of [`api::GRANOLA_REQUESTS_PER_SECOND`] per second. A rate
//! limit (`429`), the page budget, or a failed request (`5xx`) ends the pass
//! partial, with the cursor at the last note settled. A `404` for a note, a
//! note that does not parse, or an item the sink refuses leaves its container
//! partial. A refused key (`401`, `403`) fails the pass.

pub mod api;
pub mod render;

use std::collections::{BTreeMap, BTreeSet};

use async_trait::async_trait;
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{FleetError, Result};
use crate::memory_contracts::collected_item::{
    ContainerKindV1, MAX_PART_TEXT_BYTES, MAX_PARTS, ObjectKindV1, ProviderKindV1,
};
use crate::memory_contracts::coverage::CoverageProofMethodV1;
use crate::memory_contracts::digest::Sha256Digest;
use crate::worker::CollectorSourceV1;

use super::CollectorAdapterV1;
use super::audience::ProviderAudienceV1;
use super::cockroach::framed_sha256;
use super::draft::{CollectedItemDraftV1, DraftContainerV1};
use super::http::{
    AuthSchemeV1, ProviderHttpV1, ProviderTokenV1, validate_provider_api_base,
    validate_token_variable,
};
use super::pull::{
    ContainerOutcomeV1, ListingBoundV1, PageStager, PartialReasonV1, PullCollectorV1,
    PullPassInputV1, PullPassOutcomeV1, PulledItemV1, WithdrawnItemV1, withdrawal,
};
use super::sink::{ContainerObservationV1, CursorAdvanceV1, DeadLetterReasonV1, KnownVersionV1};
use api::{GranolaApiV1, GranolaCallErrorV1, GranolaNoteV1, GranolaSegmentV1, ListEntryV1};
use render::{
    FOLDER_CONTAINER_KIND, GRANOLA_PROVIDER, GranolaNoteContextV1, SUMMARY_OBJECT_KIND,
    TRANSCRIPT_OBJECT_KIND, WORKSPACE_CONTAINER_KIND, is_folder_id, is_note_id, summary_draft,
    tombstone_draft, transcript_draft,
};

/// The API a collector reads unless its settings say otherwise.
pub const DEFAULT_GRANOLA_API_BASE: &str = "https://public-api.granola.ai/v1";

/// The only host a collector sends its credential to, unless its base is
/// loopback (a local fake provider).
pub const GRANOLA_API_HOST: &str = "public-api.granola.ai";

/// The cursor domain of the notes sweep.
pub const NOTES_CURSOR_DOMAIN: &str = "granola.notes";

/// The cursor domain of the reconciliation schedule.
pub const RECONCILE_CURSOR_DOMAIN: &str = "granola.reconcile";

/// Seconds between reconciliations, unless the settings say otherwise.
pub const DEFAULT_RECONCILE_EVERY_SECONDS: u64 = 86_400;
/// Requests one pass makes at most, unless the settings say otherwise.
pub const DEFAULT_MAX_PAGES_PER_TICK: u32 = 500;
/// The largest `max_pages_per_tick`.
pub const MAX_PAGES_PER_TICK: u32 = 10_000;
/// Notes one listing page asks for, unless the settings say otherwise.
pub const DEFAULT_PAGE_SIZE: u32 = 30;
/// The largest `page_size` Granola accepts.
pub const MAX_PAGE_SIZE: u32 = 30;
/// Folders one instance lists at most.
pub const MAX_FOLDERS: usize = 100;
/// Seconds an incremental listing re-reads before the sweep's position: a
/// note whose `updated_at` landed late is still listed.
pub const LIST_OVERLAP_SECONDS: u64 = 300;

/// Notes the cursor remembers as missing once, at most.
const MAX_MISSING: usize = 128;
/// Notes the cursor remembers as lately settled, at most.
const MAX_RECENT: usize = 64;
/// Notes settled with nothing to stage between two cursor writes, at most.
const SAVE_EVERY_NOTES: u32 = 25;
/// The most transcript text one note can seal: past it, paging stops and the
/// transcript is dead-lettered as oversize.
const MAX_TRANSCRIPT_BYTES: usize = MAX_PARTS as usize * MAX_PART_TEXT_BYTES;

const CURSOR_SCHEMA_VERSION: u32 = 1;

/// Every counter a Granola pass reports.
pub const GRANOLA_COUNTERS: [&str; 23] = [
    "reconcile",
    "api_calls",
    "notes_listed",
    "notes_fetched",
    "notes_outside_folders",
    "notes_withdrawn",
    "notes_not_found",
    "notes_dead_lettered",
    "summaries_staged",
    "summaries_unchanged",
    "summaries_absent",
    "transcripts_staged",
    "transcripts_unchanged",
    "transcripts_paged",
    "transcript_pages",
    "tombstones",
    "missing_once",
    "rate_limited",
    "http_errors",
    "page_budget_exhausted",
    "paced_waits",
    "cursors_reset",
    "sweeps_resumed",
];

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
    DEFAULT_GRANOLA_API_BASE.to_owned()
}

/// A Granola key's settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GranolaSettingsV1 {
    /// The environment variable holding the API key (`grn_...`).
    pub token_env: String,
    /// The folders whose notes are visible to the project, by id
    /// (`fol_...`). Exclusive with [`Self::all_notes_visible_to_key`].
    #[serde(default)]
    pub folders: Vec<String>,
    /// Every note the key can read is visible to the project.
    #[serde(default)]
    pub all_notes_visible_to_key: bool,
    /// Read each note's transcript as well as its summary.
    #[serde(default)]
    pub include_transcript: bool,
    /// Seconds between reconciliations.
    #[serde(default = "default_reconcile_every_seconds")]
    pub reconcile_every_seconds: u64,
    /// Requests one pass makes at most.
    #[serde(default = "default_max_pages_per_tick")]
    pub max_pages_per_tick: u32,
    /// Notes one listing page asks for.
    #[serde(default = "default_page_size")]
    pub page_size: u32,
    /// The API base: https, or http to a loopback host.
    #[serde(default = "default_api_base")]
    pub api_base: String,
}

impl GranolaSettingsV1 {
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
        validate_token_variable(GRANOLA_PROVIDER, &self.token_env)?;
        match (self.folders.is_empty(), self.all_notes_visible_to_key) {
            (true, false) => {
                return Err(
                    "say which notes are visible to the project: list folders in \
                     settings.folders, or set settings.all_notes_visible_to_key"
                        .to_owned(),
                );
            }
            (false, true) => {
                return Err(
                    "settings.folders and settings.all_notes_visible_to_key are \
                     exclusive: list folders, or declare every note the key reads"
                        .to_owned(),
                );
            }
            _ => {}
        }
        if self.folders.len() > MAX_FOLDERS {
            return Err(format!(
                "settings.folders lists at most {MAX_FOLDERS} folders"
            ));
        }
        let mut seen = BTreeSet::new();
        for folder in &self.folders {
            if !is_folder_id(folder) {
                return Err(format!(
                    "settings.folders: {folder:?} is not a folder id (fol_...; a folder's name \
                     is a label, not an id)"
                ));
            }
            if !seen.insert(folder) {
                return Err(format!("settings.folders lists {folder} twice"));
            }
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
        validate_provider_api_base(&self.api_base, GRANOLA_API_HOST)
            .map_err(|error| format!("settings.api_base: {error}"))?;
        Ok(())
    }
}

/// The Granola adapter.
#[derive(Debug, Clone, Copy, Default)]
pub struct GranolaAdapterV1;

impl CollectorAdapterV1 for GranolaAdapterV1 {
    fn provider(&self) -> &'static str {
        GRANOLA_PROVIDER
    }

    fn validate(&self, source: &CollectorSourceV1) -> std::result::Result<(), String> {
        GranolaSettingsV1::from_source(source)?;
        if !source.audience.operator_declared {
            return Err("a Granola key has no provider audience of its own: set \
                 audience.operator_declared to declare what it reads visible to the project"
                .to_owned());
        }
        if !source.audience.private_containers.is_empty() {
            return Err("list Granola folders in settings.folders, not in \
                 audience.private_containers"
                .to_owned());
        }
        Ok(())
    }

    fn pull(
        &self,
        source: &CollectorSourceV1,
        environment: &dyn Fn(&str) -> Option<String>,
    ) -> std::result::Result<Option<Box<dyn PullCollectorV1>>, String> {
        self.validate(source)?;
        let settings = GranolaSettingsV1::from_source(source)?;
        let token = ProviderTokenV1::from_environment(&settings.token_env, environment)
            .map_err(|error| error.to_string())?;
        let http = ProviderHttpV1::new(&settings.api_base, &token, AuthSchemeV1::Bearer)
            .map_err(|error| error.to_string())?;
        Ok(Some(Box::new(GranolaPullV1 {
            api: GranolaApiV1::new(http, settings.page_size),
            settings,
        })))
    }

    fn reconcile_every_seconds(&self, source: &CollectorSourceV1) -> Option<u64> {
        GranolaSettingsV1::from_source(source)
            .ok()
            .map(|settings| settings.reconcile_every_seconds)
    }
}

/// A note's place in a sweep: its `updated_at` in microseconds, then its id.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PositionV1 {
    order: u64,
    id: String,
}

/// A reconciliation under way.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReconcileProgressV1 {
    /// The instant its first pass started, in microseconds.
    started: u64,
    /// The last note it settled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    position: Option<PositionV1>,
}

/// Where the notes sweep stands.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NotesCursorV1 {
    schema_version: u32,
    /// The last note the incremental sweep settled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    position: Option<PositionV1>,
    /// A reconciliation under way.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reconcile: Option<ReconcileProgressV1>,
    /// Notes the memory holds that complete listings did not return: how
    /// many consecutive complete listings missed them.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    missing: BTreeMap<String, u8>,
    /// Notes an earlier build remembered as withdrawn. A withdrawal is now
    /// read from the memory itself ([`KnownVersionV1::withdrawn`]), which
    /// has no bound; the field is still decoded so an older cursor keeps its
    /// position, and is never written again.
    #[serde(default, rename = "outside", skip_serializing)]
    legacy_outside: BTreeSet<String>,
    /// The notes settled last, within [`LIST_OVERLAP_SECONDS`] of the newest,
    /// by id: the `updated_at` (microseconds) each was settled at. A note an
    /// incremental listing re-reads in its overlap, still at that version, is
    /// not read again.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    recent: BTreeMap<String, u64>,
}

impl NotesCursorV1 {
    fn fresh() -> Self {
        Self {
            schema_version: CURSOR_SCHEMA_VERSION,
            ..Self::default()
        }
    }

    /// Remember a settled note, forgetting what fell out of the overlap
    /// before the newest one, and the oldest past [`MAX_RECENT`].
    fn remember(&mut self, position: &PositionV1) {
        self.recent.insert(position.id.clone(), position.order);
        let newest = self.recent.values().copied().max().unwrap_or(0);
        let floor = newest.saturating_sub(LIST_OVERLAP_SECONDS.saturating_mul(1_000_000));
        self.recent.retain(|_, order| *order >= floor);
        while self.recent.len() > MAX_RECENT {
            let Some(oldest) = self
                .recent
                .iter()
                .min_by_key(|(id, order)| (**order, (*id).clone()))
                .map(|(id, _)| id.clone())
            else {
                break;
            };
            self.recent.remove(&oldest);
        }
    }
}

/// When the last reconciliation that ran to its end started.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReconcileScheduleV1 {
    schema_version: u32,
    last_complete_micros: u64,
}

fn encode_cursor(
    cursor: &impl Serialize,
    domain_key: &str,
    high_water_order: Option<u64>,
    pass_seq: u64,
) -> Result<CursorAdvanceV1> {
    Ok(CursorAdvanceV1 {
        domain_key: domain_key.to_owned(),
        cursor_state: serde_json::to_vec(cursor)
            .map_err(|error| FleetError::Memory(format!("a Granola cursor: {error}")))?,
        high_water_order,
        pass_seq,
    })
}

/// A stored cursor, or `None` (counted) when it does not decode: the sweep
/// then starts as if for the first time, which is safe.
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

/// An instant in microseconds as Granola's filters take it: RFC 3339 in UTC,
/// cut to milliseconds (never later than the instant).
fn granola_instant(micros: u64) -> Option<String> {
    let instant = DateTime::<Utc>::from_timestamp_micros(i64::try_from(micros).ok()?)?;
    Some(instant.to_rfc3339_opts(SecondsFormat::Millis, true))
}

/// The digest a note that did not become drafts is dead-lettered under.
fn note_digest(id: &str, updated_at: &str) -> Sha256Digest {
    framed_sha256(
        "ostk-granola-note-v1",
        &[id.as_bytes(), updated_at.as_bytes()],
    )
}

/// The Granola pull collector for one configured key.
#[derive(Debug, Clone)]
pub struct GranolaPullV1 {
    settings: GranolaSettingsV1,
    api: GranolaApiV1,
}

impl GranolaPullV1 {
    /// A collector over `settings` through `api`.
    #[must_use]
    pub const fn new(settings: GranolaSettingsV1, api: GranolaApiV1) -> Self {
        Self { settings, api }
    }

    /// The folder container kind, and every configured container, by id: the
    /// listed folders, or the key's workspace.
    fn slots(
        &self,
        input: &PullPassInputV1<'_>,
        stager: &PageStager<'_>,
    ) -> Result<(ContainerKindV1, Vec<SlotV1>)> {
        let folder_kind = ContainerKindV1::new(FOLDER_CONTAINER_KIND)?;
        let scope = input.instance.provider_scope_id.as_str();
        let mut slots: Vec<SlotV1> = if self.settings.all_notes_visible_to_key {
            let kind = ContainerKindV1::new(WORKSPACE_CONTAINER_KIND)?;
            vec![SlotV1 {
                key: stager.container_key(&kind, scope),
                container: DraftContainerV1 {
                    kind,
                    id: scope.to_owned(),
                    label: None,
                },
            }]
        } else {
            self.settings
                .folders
                .iter()
                .map(|folder| SlotV1 {
                    key: stager.container_key(&folder_kind, folder),
                    container: DraftContainerV1 {
                        kind: folder_kind.clone(),
                        id: folder.clone(),
                        label: None,
                    },
                })
                .collect()
        };
        slots.sort_by(|left, right| left.container.id.cmp(&right.container.id));
        Ok((folder_kind, slots))
    }
}

/// The notes cursor, and when the last complete reconciliation started.
async fn read_cursors(
    stager: &PageStager<'_>,
    counters: &mut BTreeMap<&'static str, u64>,
) -> Result<(NotesCursorV1, Option<u64>)> {
    let cursor = match stager.read_cursor(NOTES_CURSOR_DOMAIN).await? {
        Some(stored) => decode_cursor(
            &stored.cursor_state,
            |cursor: &NotesCursorV1| cursor.schema_version,
            counters,
        )
        .unwrap_or_else(NotesCursorV1::fresh),
        None => NotesCursorV1::fresh(),
    };
    let last_complete = match stager.read_cursor(RECONCILE_CURSOR_DOMAIN).await? {
        Some(stored) => decode_cursor(
            &stored.cursor_state,
            |cursor: &ReconcileScheduleV1| cursor.schema_version,
            counters,
        )
        .map(|cursor| cursor.last_complete_micros),
        None => None,
    };
    Ok((cursor, last_complete))
}

/// One configured container: a listed folder, or the key's workspace.
#[derive(Clone)]
struct SlotV1 {
    key: Sha256Digest,
    container: DraftContainerV1,
}

/// What reading one note ended as.
enum NoteEndV1 {
    /// Settled: the sweep's position may pass it.
    Settled(Vec<PulledItemV1>),
    /// The pass stops before it, for this reason.
    Stop(PartialReasonV1),
}

/// What paging one transcript gave.
enum TranscriptReadV1 {
    Segments(Vec<GranolaSegmentV1>),
    /// Longer than one item may be.
    Oversize,
    End(NoteEndV1),
}

/// One pass of one collector.
struct GranolaPassV1<'p> {
    collector: &'p GranolaPullV1,
    input: &'p PullPassInputV1<'p>,
    provider: ProviderKindV1,
    folder_kind: ContainerKindV1,
    /// Every configured container, by id.
    slots: Vec<SlotV1>,
    /// The key's workspace, when every note it reads is declared.
    workspace: bool,
    summaries: BTreeMap<String, KnownVersionV1>,
    transcripts: BTreeMap<String, KnownVersionV1>,
    cursor: NotesCursorV1,
    reconcile: bool,
    /// Observations to stage with the next page.
    observations: Vec<ContainerObservationV1>,
    /// Containers observed this pass.
    observed: BTreeSet<Sha256Digest>,
    /// Notes settled since the cursor was last written.
    unsaved: u32,
    budget: u32,
    counters: BTreeMap<&'static str, u64>,
}

impl GranolaPassV1<'_> {
    fn bump(&mut self, key: &'static str) {
        *self.counters.entry(key).or_insert(0) += 1;
    }

    /// Spend one request of the budget; `false` when it is spent.
    fn take_call(&mut self) -> bool {
        if self.budget == 0 {
            self.bump("page_budget_exhausted");
            return false;
        }
        self.budget -= 1;
        self.bump("api_calls");
        true
    }

    fn keys(&self) -> Vec<Sha256Digest> {
        self.slots.iter().map(|slot| slot.key).collect()
    }

    /// The containers the memory holds a note's items in, else every one.
    fn note_keys(&self, id: &str) -> Vec<Sha256Digest> {
        let known: Vec<Sha256Digest> = [&self.summaries, &self.transcripts]
            .iter()
            .filter_map(|known| known.get(id).and_then(|version| version.container_key))
            .collect();
        if known.is_empty() { self.keys() } else { known }
    }

    fn slot(&self, key: Option<Sha256Digest>) -> Option<&SlotV1> {
        key.and_then(|key| self.slots.iter().find(|slot| slot.key == key))
    }

    fn context<'c>(&'c self, container: Option<&'c DraftContainerV1>) -> GranolaNoteContextV1<'c> {
        GranolaNoteContextV1 {
            provider: &self.provider,
            provider_scope_id: self.input.instance.provider_scope_id.as_str(),
            container,
        }
    }

    fn advance(&self) -> Result<CursorAdvanceV1> {
        let position = self.cursor.position.as_ref().map(|position| position.order);
        encode_cursor(
            &self.cursor,
            NOTES_CURSOR_DOMAIN,
            position,
            self.input.pass_seq,
        )
    }

    /// Stage `items` with the notes cursor and every pending observation.
    async fn stage(&mut self, items: Vec<PulledItemV1>, stager: &mut PageStager<'_>) -> Result<()> {
        let advance = self.advance()?;
        let observations = std::mem::take(&mut self.observations);
        stager.stage_page(items, &[advance], &observations).await?;
        self.unsaved = 0;
        Ok(())
    }

    /// Dead-letter a note, or a listed entry, that did not become drafts.
    async fn refuse(
        &mut self,
        stager: &mut PageStager<'_>,
        keys: &[Sha256Digest],
        reason: DeadLetterReasonV1,
        digest: Sha256Digest,
        diagnostic: &str,
    ) -> Result<()> {
        self.bump("notes_dead_lettered");
        stager
            .dead_letter(keys.first().copied(), reason, digest, diagnostic)
            .await?;
        for key in keys {
            stager.mark_partial(Some(*key), PartialReasonV1::ItemRefused);
        }
        Ok(())
    }

    /// What a failed request makes of the pass; a refused key fails it.
    fn failure(&mut self, error: &GranolaCallErrorV1) -> Result<PartialReasonV1> {
        match error {
            GranolaCallErrorV1::RateLimited => {
                self.bump("rate_limited");
                Ok(PartialReasonV1::RateLimited)
            }
            GranolaCallErrorV1::Credential(status) => Err(FleetError::Configuration(format!(
                "Granola refused the collector's API key (HTTP {status}); nothing more was read"
            ))),
            GranolaCallErrorV1::NotFound
            | GranolaCallErrorV1::TooLarge
            | GranolaCallErrorV1::Http(_)
            | GranolaCallErrorV1::Malformed(_) => {
                self.bump("http_errors");
                Ok(PartialReasonV1::Unreadable)
            }
        }
    }

    /// List the notes to the listing's end: `(position, listed updated_at)`
    /// by id, whether an entry did not parse, and how far it reached.
    async fn list(
        &mut self,
        stager: &mut PageStager<'_>,
    ) -> Result<(BTreeMap<String, PositionV1>, bool, ListingBoundV1)> {
        let since = if self.reconcile {
            None
        } else {
            self.cursor.position.as_ref().and_then(|position| {
                granola_instant(
                    position
                        .order
                        .saturating_sub(LIST_OVERLAP_SECONDS.saturating_mul(1_000_000)),
                )
            })
        };
        let keys = self.keys();
        let mut listed: BTreeMap<String, PositionV1> = BTreeMap::new();
        let mut malformed = false;
        let mut page_cursor: Option<String> = None;
        loop {
            if !self.take_call() {
                return Ok((
                    listed,
                    malformed,
                    ListingBoundV1::Truncated(PartialReasonV1::ListingBound),
                ));
            }
            let page = match self
                .collector
                .api
                .notes_page(since.as_deref(), page_cursor.as_deref())
                .await
            {
                Ok(page) => page,
                Err(error) => {
                    let reason = self.failure(&error)?;
                    return Ok((listed, malformed, ListingBoundV1::Truncated(reason)));
                }
            };
            for entry in page.notes {
                let note = match entry {
                    ListEntryV1::Note(note) => note,
                    ListEntryV1::Malformed(digest) => {
                        malformed = true;
                        self.refuse(
                            stager,
                            &keys,
                            DeadLetterReasonV1::ParseFailed,
                            digest,
                            "a listed Granola note is not the documented shape",
                        )
                        .await?;
                        continue;
                    }
                };
                let order = render::clock(&note.updated_at).map(|(_, order)| order);
                let (true, Ok(order)) = (is_note_id(&note.id), order) else {
                    malformed = true;
                    self.refuse(
                        stager,
                        &keys,
                        DeadLetterReasonV1::ValidationFailed,
                        note_digest(&note.id, &note.updated_at),
                        "a listed Granola note has no note id or no updated_at",
                    )
                    .await?;
                    continue;
                };
                self.bump("notes_listed");
                let position = PositionV1 {
                    order,
                    id: note.id.clone(),
                };
                let newest = listed
                    .get(&note.id)
                    .is_none_or(|seen| seen.order < position.order);
                if newest {
                    listed.insert(note.id, position);
                }
            }
            if page.unfinished {
                return Ok((
                    listed,
                    malformed,
                    ListingBoundV1::Truncated(PartialReasonV1::Unreadable),
                ));
            }
            match page.next_cursor {
                Some(next) => page_cursor = Some(next),
                None => return Ok((listed, malformed, ListingBoundV1::Complete)),
            }
        }
    }

    /// After a complete listing: tombstones for what two consecutive
    /// complete listings missed, and the missing counts to keep.
    async fn absence(
        &mut self,
        listed: &BTreeMap<String, PositionV1>,
        stager: &mut PageStager<'_>,
    ) -> Result<()> {
        let held: BTreeSet<String> = [&self.summaries, &self.transcripts]
            .iter()
            .flat_map(|known| {
                known
                    .iter()
                    .filter(|(_, version)| !version.lifecycle.is_tombstone())
                    .map(|(id, _)| id.clone())
            })
            .collect();
        let mut missing = BTreeMap::new();
        let mut tombstones = Vec::new();
        for id in held {
            if listed.contains_key(&id) {
                continue;
            }
            let count = self
                .cursor
                .missing
                .get(&id)
                .copied()
                .unwrap_or(0)
                .saturating_add(1);
            if count < 2 {
                self.bump("missing_once");
                missing.insert(id, count);
                continue;
            }
            self.bump("tombstones");
            for (kind, known) in [
                (SUMMARY_OBJECT_KIND, &self.summaries),
                (TRANSCRIPT_OBJECT_KIND, &self.transcripts),
            ] {
                let Some(version) = known
                    .get(&id)
                    .filter(|version| !version.lifecycle.is_tombstone())
                else {
                    continue;
                };
                let container = self
                    .slot(version.container_key)
                    .map(|slot| slot.container.clone());
                let draft = tombstone_draft(
                    &self.context(container.as_ref()),
                    kind,
                    &id,
                    version.provider_order,
                );
                tombstones.push(PulledItemV1 {
                    draft,
                    provider_audience: Some(ProviderAudienceV1::OperatorScoped),
                });
            }
        }
        while missing.len() > MAX_MISSING {
            missing.pop_last();
        }
        if tombstones.is_empty() && missing == self.cursor.missing {
            return Ok(());
        }
        self.cursor.missing = missing;
        self.stage(tombstones, stager).await
    }

    /// Whether the memory holds a listed note at its listed `updated_at`,
    /// and holds none of its items withdrawn.
    fn held(&self, position: &PositionV1) -> bool {
        let at = |known: &BTreeMap<String, KnownVersionV1>| {
            known.get(&position.id).is_some_and(|version| {
                !version.lifecycle.is_tombstone()
                    && !version.withdrawn
                    && version.provider_order == position.order
            })
        };
        at(&self.summaries)
            && (!self.collector.settings.include_transcript || at(&self.transcripts))
    }

    /// Hold current what the memory holds of a note an earlier pass of this
    /// reconciliation settled; a withdrawn item is not current.
    fn keep_settled(&self, id: &str, stager: &mut PageStager<'_>) {
        let read = [
            (&self.summaries, true),
            (
                &self.transcripts,
                self.collector.settings.include_transcript,
            ),
        ];
        for (known, read) in read {
            if let Some(version) = known
                .get(id)
                .filter(|version| read && !version.lifecycle.is_tombstone() && !version.withdrawn)
            {
                stager.keep(version.container_key, version);
            }
        }
    }

    /// The listed container a note is staged in: the listed folder with the
    /// least id it is in, or the workspace; `None` when it is in no listed
    /// folder.
    fn place(&self, note: &GranolaNoteV1) -> Option<SlotV1> {
        if self.workspace {
            return self.slots.first().cloned();
        }
        note.folders()
            .iter()
            .filter(|folder| self.slots.iter().any(|slot| slot.container.id == folder.id))
            .min_by(|left, right| left.id.cmp(&right.id))
            .and_then(|folder| {
                let slot = self
                    .slots
                    .iter()
                    .find(|slot| slot.container.id == folder.id)?;
                let mut slot = slot.clone();
                slot.container.label.clone_from(&folder.name);
                Some(slot)
            })
    }

    /// Page a transcript that did not come with its note.
    async fn page_transcript(
        &mut self,
        id: &str,
        stager: &mut PageStager<'_>,
    ) -> Result<TranscriptReadV1> {
        let mut segments = Vec::new();
        let mut bytes = 0_usize;
        let mut page_cursor: Option<String> = None;
        loop {
            if !self.take_call() {
                return Ok(TranscriptReadV1::End(NoteEndV1::Stop(
                    PartialReasonV1::ListingBound,
                )));
            }
            let page = match self
                .collector
                .api
                .transcript_page(id, page_cursor.as_deref())
                .await
            {
                Ok(page) => page,
                Err(error) => {
                    return Ok(TranscriptReadV1::End(
                        self.failed(id, &error, stager).await?,
                    ));
                }
            };
            self.bump("transcript_pages");
            bytes += page
                .segments
                .iter()
                .map(|segment| segment.text.as_deref().map_or(0, str::len))
                .sum::<usize>();
            segments.extend(page.segments);
            if bytes > MAX_TRANSCRIPT_BYTES {
                return Ok(TranscriptReadV1::Oversize);
            }
            if page.unfinished {
                self.bump("http_errors");
                return Ok(TranscriptReadV1::End(NoteEndV1::Stop(
                    PartialReasonV1::Unreadable,
                )));
            }
            match page.next_cursor {
                Some(next) => page_cursor = Some(next),
                None => return Ok(TranscriptReadV1::Segments(segments)),
            }
        }
    }

    /// What a failed read of one note makes of it: a `404` or a note that
    /// does not parse is settled (partial, never a tombstone); anything else
    /// stops the pass before it.
    async fn failed(
        &mut self,
        id: &str,
        error: &GranolaCallErrorV1,
        stager: &mut PageStager<'_>,
    ) -> Result<NoteEndV1> {
        let keys = self.note_keys(id);
        match error {
            GranolaCallErrorV1::NotFound => {
                self.bump("notes_not_found");
                for key in keys {
                    stager.mark_partial(Some(key), PartialReasonV1::Unreadable);
                }
                Ok(NoteEndV1::Settled(Vec::new()))
            }
            GranolaCallErrorV1::Malformed(_) | GranolaCallErrorV1::TooLarge => {
                let (reason, diagnostic) = if matches!(error, GranolaCallErrorV1::TooLarge) {
                    (
                        DeadLetterReasonV1::Oversize,
                        "a Granola note is larger than one response",
                    )
                } else {
                    (
                        DeadLetterReasonV1::ParseFailed,
                        "a Granola note is not the documented shape",
                    )
                };
                self.refuse(stager, &keys, reason, note_digest(id, ""), diagnostic)
                    .await?;
                Ok(NoteEndV1::Settled(Vec::new()))
            }
            _ => Ok(NoteEndV1::Stop(self.failure(error)?)),
        }
    }

    /// Read one note and turn it into what to stage.
    async fn note(&mut self, id: &str, stager: &mut PageStager<'_>) -> Result<NoteEndV1> {
        let include = self.collector.settings.include_transcript;
        if !self.take_call() {
            return Ok(NoteEndV1::Stop(PartialReasonV1::ListingBound));
        }
        let (note, segments) = match self.collector.api.note(id, include).await {
            Ok(mut note) => {
                let segments = if include {
                    note.transcript.take().unwrap_or_default()
                } else {
                    Vec::new()
                };
                (note, Some(segments))
            }
            Err(GranolaCallErrorV1::TooLarge) if include => {
                self.bump("transcripts_paged");
                if !self.take_call() {
                    return Ok(NoteEndV1::Stop(PartialReasonV1::ListingBound));
                }
                let note = match self.collector.api.note(id, false).await {
                    Ok(note) => note,
                    Err(error) => return self.failed(id, &error, stager).await,
                };
                match self.page_transcript(id, stager).await? {
                    TranscriptReadV1::Segments(segments) => (note, Some(segments)),
                    TranscriptReadV1::Oversize => (note, None),
                    TranscriptReadV1::End(end) => return Ok(end),
                }
            }
            Err(error) => return self.failed(id, &error, stager).await,
        };
        self.bump("notes_fetched");
        let Some(slot) = self.place(&note) else {
            return Ok(NoteEndV1::Settled(self.outside(&note)));
        };
        if self.observed.insert(slot.key) {
            self.observations.push(ContainerObservationV1 {
                kind: slot.container.kind.clone(),
                id: slot.container.id.clone(),
                label: slot.container.label.clone(),
                provider_audience: ProviderAudienceV1::OperatorScoped,
            });
        }
        let drafts = {
            let context = self.context(Some(&slot.container));
            summary_draft(&context, &note).and_then(|summary| {
                let transcript = match (include, segments.as_deref()) {
                    (true, Some(segments)) => transcript_draft(&context, &note, segments)?,
                    _ => None,
                };
                Ok((summary, transcript))
            })
        };
        let (summary, transcript) = match drafts {
            Ok(drafts) => drafts,
            Err(diagnostic) => {
                self.refuse(
                    stager,
                    &[slot.key],
                    DeadLetterReasonV1::ValidationFailed,
                    note_digest(&note.id, &note.updated_at),
                    diagnostic,
                )
                .await?;
                return Ok(NoteEndV1::Settled(Vec::new()));
            }
        };
        if include && segments.is_none() {
            self.refuse(
                stager,
                &[slot.key],
                DeadLetterReasonV1::Oversize,
                note_digest(&note.id, &note.updated_at),
                "a Granola transcript is longer than one item may be",
            )
            .await?;
        }
        let mut items = Vec::new();
        match summary {
            Some(draft) => self.consider(draft, slot.key, stager, &mut items),
            None => self.bump("summaries_absent"),
        }
        if let Some(draft) = transcript {
            self.consider(draft, slot.key, stager, &mut items);
        }
        Ok(NoteEndV1::Settled(items))
    }

    /// Stage a draft, or keep the version the memory holds when its content,
    /// lifecycle, and container are unchanged and it is not withdrawn (a note
    /// back in a listed folder is staged, which is what lifts its
    /// withdrawal).
    ///
    /// Granola may regenerate a summary without moving `updated_at`. A
    /// changed version at an order no greater than the one the memory holds
    /// would then tie with it, and a tie at the head is broken by digest, not
    /// recency, so the newer content might never be presented: it is ordered
    /// at the pass's instant instead, when it was first observed.
    fn consider(
        &mut self,
        mut draft: CollectedItemDraftV1,
        key: Sha256Digest,
        stager: &mut PageStager<'_>,
        items: &mut Vec<PulledItemV1>,
    ) {
        let summary = draft.object_kind.as_str() == SUMMARY_OBJECT_KIND;
        let known = if summary {
            self.summaries.get(&draft.external_id)
        } else {
            self.transcripts.get(&draft.external_id)
        };
        let digest = stager.content_digest(&draft);
        if let Some(known) = known
            && !known.withdrawn
            && !known.lifecycle.is_tombstone()
            && known.lifecycle == draft.lifecycle
            && known.container_key == Some(key)
            && digest == Some(known.content_digest)
        {
            let known = known.clone();
            stager.keep(Some(key), &known);
            self.bump(if summary {
                "summaries_unchanged"
            } else {
                "transcripts_unchanged"
            });
            return;
        }
        if let Some(known) = known
            && !known.lifecycle.is_tombstone()
            && draft.order_micros <= known.provider_order
        {
            draft.order_micros = if digest == Some(known.content_digest) {
                // The version the memory holds, read again (a withdrawn one
                // back in a listed folder): at its own order, so it is the
                // same version and its staging lifts the withdrawal.
                known.provider_order
            } else {
                self.input
                    .pass_order_micros
                    .max(known.provider_order.saturating_add(1))
            };
        }
        self.bump(if summary {
            "summaries_staged"
        } else {
            "transcripts_staged"
        });
        items.push(PulledItemV1 {
            draft,
            provider_audience: Some(ProviderAudienceV1::OperatorScoped),
        });
    }

    /// A note in no listed folder. Every item the memory holds of it (its
    /// summary, and its transcript whether or not transcripts are read now)
    /// is withdrawn with a content-free observation at the note's listed
    /// order ([`super::pull::withdrawal`]), which hides it until an
    /// admissible read lifts it; a note it never held is not staged at all.
    /// Nothing is rebuilt from the note, so an item whose content could not
    /// be drafted now is withdrawn all the same.
    fn outside(&mut self, note: &GranolaNoteV1) -> Vec<PulledItemV1> {
        let held: Vec<(&'static str, KnownVersionV1)> = [
            (SUMMARY_OBJECT_KIND, &self.summaries),
            (TRANSCRIPT_OBJECT_KIND, &self.transcripts),
        ]
        .into_iter()
        .filter_map(|(kind, known)| {
            known
                .get(&note.id)
                .filter(|version| !version.lifecycle.is_tombstone())
                .map(|version| (kind, version.clone()))
        })
        .collect();
        if held.is_empty() {
            self.bump("notes_outside_folders");
            return Vec::new();
        }
        let mut folders: Vec<&api::GranolaFolderV1> = note
            .folders()
            .iter()
            .filter(|folder| is_folder_id(&folder.id))
            .collect();
        folders.sort_by(|left, right| left.id.cmp(&right.id));
        let container = folders.first().map(|folder| DraftContainerV1 {
            kind: self.folder_kind.clone(),
            id: folder.id.clone(),
            label: None,
        });
        let listed = render::clock(&note.updated_at).map_or(0, |(_, order)| order);
        let scope = self.input.instance.provider_scope_id.as_str();
        let mut items = Vec::new();
        for (kind, version) in held {
            if version.withdrawn {
                continue;
            }
            let Ok(object_kind) = ObjectKindV1::new(kind) else {
                continue;
            };
            items.push(withdrawal(
                &WithdrawnItemV1 {
                    provider: &self.provider,
                    provider_scope_id: scope,
                    object_kind: &object_kind,
                    external_id: &note.id,
                    order_micros: listed.max(version.provider_order),
                },
                container.clone(),
            ));
        }
        if !items.is_empty() {
            self.bump("notes_withdrawn");
        }
        items
    }

    /// List, count what is missing, and sweep. Returns why the pass stopped
    /// short, if it did.
    async fn run(&mut self, stager: &mut PageStager<'_>) -> Result<Option<PartialReasonV1>> {
        let (listed, malformed, listing) = self.list(stager).await?;
        if let ListingBoundV1::Truncated(reason) = listing {
            return Ok(Some(reason));
        }
        if self.reconcile {
            if self.cursor.reconcile.is_none() {
                self.cursor.reconcile = Some(ReconcileProgressV1 {
                    started: self.input.pass_order_micros,
                    position: None,
                });
            }
            // A listing that returned an entry it could not parse counts
            // nothing missing: that entry may be any note.
            if !malformed {
                self.absence(&listed, stager).await?;
            }
        }
        self.sweep(listed, stager).await
    }

    /// Record where the pass ended: the cursor at its last settled note. A
    /// reconciliation that reached its end also moves the incremental
    /// position to where it ended and records its start.
    async fn finish(
        &mut self,
        stop: Option<PartialReasonV1>,
        stager: &mut PageStager<'_>,
    ) -> Result<()> {
        let mut advances = Vec::new();
        if stop.is_none() && self.reconcile {
            let (started, position) = self
                .cursor
                .reconcile
                .take()
                .map_or((self.input.pass_order_micros, None), |progress| {
                    (progress.started, progress.position)
                });
            self.cursor.position = self.cursor.position.clone().max(position);
            advances.push(encode_cursor(
                &ReconcileScheduleV1 {
                    schema_version: CURSOR_SCHEMA_VERSION,
                    last_complete_micros: started,
                },
                RECONCILE_CURSOR_DOMAIN,
                Some(started),
                self.input.pass_seq,
            )?);
        }
        advances.push(self.advance()?);
        let observations = std::mem::take(&mut self.observations);
        stager
            .stage_page(Vec::new(), &advances, &observations)
            .await?;
        self.unsaved = 0;
        Ok(())
    }

    /// The sweep. Returns why it stopped short, if it did.
    async fn sweep(
        &mut self,
        listed: BTreeMap<String, PositionV1>,
        stager: &mut PageStager<'_>,
    ) -> Result<Option<PartialReasonV1>> {
        let mut order: Vec<PositionV1> = listed.into_values().collect();
        order.sort();
        let start = if self.reconcile {
            self.cursor
                .reconcile
                .as_ref()
                .and_then(|progress| progress.position.clone())
        } else {
            self.cursor.position.clone()
        };
        if self.reconcile && start.is_some() {
            self.bump("sweeps_resumed");
        }
        for position in order {
            if position.order > self.input.pass_order_micros {
                // Updated after the pass began: the next pass reads it.
                break;
            }
            let settled = start.as_ref().is_some_and(|start| position <= *start);
            if settled && self.reconcile {
                self.keep_settled(&position.id, stager);
                continue;
            }
            if settled
                && (self.cursor.recent.get(&position.id) == Some(&position.order)
                    || self.held(&position))
            {
                continue;
            }
            let items = match self.note(&position.id, stager).await? {
                NoteEndV1::Settled(items) => items,
                NoteEndV1::Stop(reason) => return Ok(Some(reason)),
            };
            self.cursor.remember(&position);
            if self.reconcile {
                if let Some(progress) = self.cursor.reconcile.as_mut() {
                    progress.position = progress.position.clone().max(Some(position));
                }
            } else {
                self.cursor.position = self.cursor.position.clone().max(Some(position));
            }
            // What a note staged moves the cursor past it in the same
            // transaction; notes with nothing to stage are written in
            // batches, and at the end of the pass.
            self.unsaved += 1;
            if !items.is_empty() || self.unsaved >= SAVE_EVERY_NOTES {
                self.stage(items, stager).await?;
            }
        }
        Ok(None)
    }
}

#[async_trait]
impl PullCollectorV1 for GranolaPullV1 {
    fn counter_keys(&self) -> &'static [&'static str] {
        &GRANOLA_COUNTERS
    }

    fn proof_method(&self) -> CoverageProofMethodV1 {
        CoverageProofMethodV1::ClosedProviderQuery
    }

    fn observation_audience(&self) -> ProviderAudienceV1 {
        // The pass summary names the instance and counts, under the
        // instance's own declaration.
        ProviderAudienceV1::OperatorScoped
    }

    async fn pass(
        &self,
        input: &PullPassInputV1<'_>,
        stager: &mut PageStager<'_>,
    ) -> Result<PullPassOutcomeV1> {
        let mut counters: BTreeMap<&'static str, u64> =
            GRANOLA_COUNTERS.iter().map(|key| (*key, 0)).collect();
        let workspace = self.settings.all_notes_visible_to_key;
        let (folder_kind, slots) = self.slots(input, stager)?;
        let (cursor, last_complete) = read_cursors(stager, &mut counters).await?;
        let every = self
            .settings
            .reconcile_every_seconds
            .saturating_mul(1_000_000);
        let reconcile = cursor.reconcile.is_some()
            || last_complete
                .is_none_or(|last| input.pass_order_micros.saturating_sub(last) >= every);
        counters.insert("reconcile", u64::from(reconcile));
        // The workspace is observed on every pass; a folder when a note in
        // it is read.
        let observations = slots
            .iter()
            .filter(|_| workspace)
            .map(|slot| ContainerObservationV1 {
                kind: slot.container.kind.clone(),
                id: slot.container.id.clone(),
                label: None,
                provider_audience: ProviderAudienceV1::OperatorScoped,
            })
            .collect::<Vec<_>>();
        let mut pass = GranolaPassV1 {
            collector: self,
            input,
            provider: ProviderKindV1::new(GRANOLA_PROVIDER)?,
            folder_kind,
            observed: slots
                .iter()
                .filter(|_| workspace)
                .map(|slot| slot.key)
                .collect(),
            slots,
            workspace,
            summaries: stager
                .known_versions(&ObjectKindV1::new(SUMMARY_OBJECT_KIND)?)
                .await?,
            transcripts: stager
                .known_versions(&ObjectKindV1::new(TRANSCRIPT_OBJECT_KIND)?)
                .await?,
            cursor,
            reconcile,
            observations,
            unsaved: 0,
            budget: self.settings.max_pages_per_tick,
            counters,
        };
        let stop = pass.run(stager).await?;
        pass.finish(stop, stager).await?;
        let listing = stop.map_or(ListingBoundV1::Complete, ListingBoundV1::Truncated);
        let containers = pass
            .slots
            .iter()
            .zip(0_u32..)
            .map(|(slot, ordinal)| ContainerOutcomeV1 {
                ordinal,
                container_key: Some(slot.key),
                listing,
            })
            .collect();
        let mut counters = pass.counters;
        counters.insert("paced_waits", self.api.paced_waits());
        Ok(PullPassOutcomeV1 {
            containers,
            reconcile,
            counters,
            window_start: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FOLDER: &str = "fol_4y6LduVdwSKC27";

    fn source(settings: &serde_json::Value, audience: &serde_json::Value) -> CollectorSourceV1 {
        serde_json::from_value(serde_json::json!({
            "provider": "granola",
            "connector_principal": "principal.granola",
            "connector_instance": "granola.acme",
            "provider_scope_id": "workspace.acme-robotics",
            "audience": audience,
            "settings": settings
        }))
        .unwrap()
    }

    fn settings(extra: &serde_json::Value) -> serde_json::Value {
        let mut settings = serde_json::json!({
            "token_env": "FLEET_RECALL_GRANOLA_API_KEY",
            "folders": [FOLDER]
        });
        settings
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        settings
    }

    fn declared() -> serde_json::Value {
        serde_json::json!({"operator_declared": true})
    }

    #[test]
    fn settings_are_closed_bounded_and_default_to_the_public_api_without_transcripts() {
        let adapter = GranolaAdapterV1;
        adapter
            .validate(&source(&settings(&serde_json::json!({})), &declared()))
            .unwrap();
        let parsed =
            GranolaSettingsV1::from_source(&source(&settings(&serde_json::json!({})), &declared()))
                .unwrap();
        assert_eq!(parsed.api_base, DEFAULT_GRANOLA_API_BASE);
        assert!(!parsed.include_transcript, "transcripts are off by default");
        assert_eq!(parsed.page_size, DEFAULT_PAGE_SIZE);
        assert_eq!(
            adapter
                .reconcile_every_seconds(&source(&settings(&serde_json::json!({})), &declared())),
            Some(DEFAULT_RECONCILE_EVERY_SECONDS)
        );
        let everything = serde_json::json!({
            "token_env": "FLEET_RECALL_GRANOLA_API_KEY",
            "all_notes_visible_to_key": true
        });
        adapter
            .validate(&source(&everything, &declared()))
            .expect("every note the key reads may be declared");

        for (extra, needle) in [
            (
                serde_json::json!({"api_base": "http://public-api.granola.example/v1"}),
                "not loopback",
            ),
            (serde_json::json!({"token_env": "grn_lower"}), "token_env"),
            (serde_json::json!({"folders": []}), "say which notes"),
            (
                serde_json::json!({"all_notes_visible_to_key": true}),
                "exclusive",
            ),
            (
                serde_json::json!({"folders": ["Platform"]}),
                "not a folder id",
            ),
            (serde_json::json!({"folders": [FOLDER, FOLDER]}), "twice"),
            (serde_json::json!({"page_size": 31}), "page_size"),
            (
                serde_json::json!({"reconcile_every_seconds": 59}),
                "reconcile_every_seconds",
            ),
            (
                serde_json::json!({"max_pages_per_tick": 0}),
                "max_pages_per_tick",
            ),
            (
                serde_json::json!({"include_private_notes": true}),
                "include_private_notes",
            ),
        ] {
            let message = adapter
                .validate(&source(&settings(&extra), &declared()))
                .unwrap_err();
            assert!(message.contains(needle), "{extra}: {message}");
        }
        let loopback = serde_json::json!({"api_base": "http://127.0.0.1:9/v1"});
        adapter
            .validate(&source(&settings(&loopback), &declared()))
            .expect("a loopback fake provider may be plain http");
    }

    #[test]
    fn the_instance_is_refused_without_the_operator_declaration() {
        let adapter = GranolaAdapterV1;
        let undeclared = adapter
            .validate(&source(
                &settings(&serde_json::json!({})),
                &serde_json::json!({}),
            ))
            .unwrap_err();
        assert!(undeclared.contains("operator_declared"), "{undeclared}");
        let listed = adapter
            .validate(&source(
                &settings(&serde_json::json!({})),
                &serde_json::json!({"operator_declared": true, "private_containers": [FOLDER]}),
            ))
            .unwrap_err();
        assert!(listed.contains("settings.folders"), "{listed}");
        let refused = adapter
            .pull(
                &source(&settings(&serde_json::json!({})), &serde_json::json!({})),
                &|_: &str| Some("grn_EXAMPLE_NOT_A_KEY".to_owned()),
            )
            .err()
            .expect("an undeclared instance builds no collector");
        assert!(refused.contains("operator_declared"), "{refused}");
    }

    #[test]
    fn a_missing_key_fails_the_collector_before_any_request() {
        let error = GranolaAdapterV1
            .pull(
                &source(&settings(&serde_json::json!({})), &declared()),
                &|_: &str| None,
            )
            .err()
            .expect("no key, no collector");
        assert!(error.contains("FLEET_RECALL_GRANOLA_API_KEY"), "{error}");
    }

    #[test]
    fn positions_order_by_updated_at_then_id() {
        let at = |order: u64, id: &str| PositionV1 {
            order,
            id: id.to_owned(),
        };
        let mut positions = vec![at(2, "not_a"), at(1, "not_z"), at(2, "not_0")];
        positions.sort();
        assert_eq!(positions, [at(1, "not_z"), at(2, "not_0"), at(2, "not_a")]);
        assert!(Some(at(1, "not_z")) > None, "any position is past none");
        assert_eq!(
            granola_instant(1_790_005_269_001_999).as_deref(),
            Some("2026-09-21T15:41:09.001Z"),
            "cut to milliseconds, never later"
        );
    }

    #[test]
    fn the_largest_cursor_fits_its_column_and_a_bad_one_is_reset() {
        let id = |index: usize| format!("not_{index:0>32}");
        let mut cursor = NotesCursorV1::fresh();
        cursor.position = Some(PositionV1 {
            order: u64::MAX,
            id: id(0),
        });
        cursor.reconcile = Some(ReconcileProgressV1 {
            started: u64::MAX,
            position: cursor.position.clone(),
        });
        cursor.missing = (0..MAX_MISSING).map(|index| (id(index), 1)).collect();
        cursor.recent = (0..MAX_RECENT)
            .map(|index| (id(20_000 + index), u64::MAX - 1))
            .collect();
        let advance = encode_cursor(&cursor, NOTES_CURSOR_DOMAIN, Some(1), 3).unwrap();
        assert!(
            advance.cursor_state.len() < 16_384,
            "{} bytes",
            advance.cursor_state.len()
        );
        let mut counters = BTreeMap::new();
        assert_eq!(
            decode_cursor(
                &advance.cursor_state,
                |cursor: &NotesCursorV1| cursor.schema_version,
                &mut counters
            ),
            Some(cursor)
        );
        assert!(
            decode_cursor(
                b"{\"schema_version\":2}",
                |cursor: &NotesCursorV1| cursor.schema_version,
                &mut counters
            )
            .is_none()
        );
        assert!(
            decode_cursor(
                b"garbage",
                |cursor: &ReconcileScheduleV1| cursor.schema_version,
                &mut counters
            )
            .is_none()
        );
        assert_eq!(counters["cursors_reset"], 2);
    }

    #[test]
    fn the_recent_notes_are_those_within_the_overlap_of_the_newest() {
        let second = 1_000_000;
        let at = |seconds: u64, id: &str| PositionV1 {
            order: seconds * second,
            id: id.to_owned(),
        };
        let mut cursor = NotesCursorV1::fresh();
        cursor.remember(&at(1_000, "not_a"));
        cursor.remember(&at(1_200, "not_b"));
        assert_eq!(cursor.recent.len(), 2);
        cursor.remember(&at(1_400, "not_c"));
        assert_eq!(
            cursor.recent.keys().map(String::as_str).collect::<Vec<_>>(),
            ["not_b", "not_c"],
            "not_a is further than the overlap before the newest"
        );
        cursor.remember(&at(1_000, "not_b"));
        assert!(
            !cursor.recent.contains_key("not_b"),
            "a note settled at an older version is forgotten with it"
        );
        for index in 0..MAX_RECENT + 5 {
            let order = 1_400 * second + u64::try_from(index).unwrap();
            cursor.remember(&PositionV1 {
                order,
                id: format!("not_x{index}"),
            });
        }
        assert_eq!(cursor.recent.len(), MAX_RECENT);
        assert!(
            cursor
                .recent
                .contains_key(&format!("not_x{}", MAX_RECENT + 4))
        );
        assert!(!cursor.recent.contains_key("not_c"), "the oldest go first");
    }

    #[test]
    fn the_api_key_placeholder_is_caught_by_the_redactor() {
        // The placeholder the tests use keeps the shape of a Granola key, so a
        // leak of it is exactly what the redactor must catch.
        let findings = super::super::redaction::scan_collected_secrets(
            "pasted grn_EXAMPLE_NOT_A_KEY by mistake",
        );
        assert_eq!(findings.len(), 1);
    }
}
