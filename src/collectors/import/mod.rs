//! Operator imports: a file of items, staged under `connector.collected.import`
//! and recorded as a snapshot (ADR 0008 D9).
//!
//! `ostk-fleet-recall collect import` reads one file for one collector
//! instance, which pins one provider and one provider scope, and stages every
//! item in it through the same sink every collector uses. An import is a
//! *reported* channel: its items are presented only where no verified
//! collector has a head, and its containers are recorded as the operator
//! declared them (`operator_declared`), never re-opening one a verified
//! collector withdrew. Two formats: [`jsonl`], one `CollectedItemInputV1`
//! per line, and [`slack_export`], a Slack workspace export (a directory or a
//! zip) whose channels and messages the Slack collector's renderer reads.
//!
//! # One import
//!
//! 1. The instance must be free for an import: no worker source (git,
//!    transcripts, CI) and no worker or capture collector reports under it,
//!    and an import that already reports under it imports the same provider
//!    scope. `connector.collected.import` is bound from the verified head (a
//!    generation-2 head refuses, naming `--target generation-3`).
//! 2. The file is read twice. The first read hashes it, counts its records
//!    (lines, or an export's messages), and learns its containers; the second
//!    stages it, in sink transactions of at most [`MAX_IMPORT_CHUNK_ITEMS`]
//!    items and about as many parts, each with the observations of the
//!    containers it names. A record the format refuses is a digest-only dead
//!    letter; the delivery of every record is the file's digest and its
//!    number. A file that changed between the reads is refused, and nothing
//!    is recorded as its snapshot. An export's channels are its containers
//!    even when they hold no message, and are recorded before anything is
//!    staged: a private channel the operator did not list as withdrawn.
//! 3. Each line's version marker follows the marker rule (the line's own, else
//!    `o<order>:sha256:<content digest>` at its `updated_at`, else its
//!    `created_at`), so re-importing an unchanged file stages nothing, an
//!    edited line is a new version, and a line that says it was deleted is a
//!    tombstone. An import never infers a deletion from a missing line: an
//!    export can be partial or ranged.
//! 4. The import is settled as far as it can be before a drain: its domain
//!    is every container its items name (items with no container, and lines
//!    no container can be named for, share one more), and a container is
//!    partial when a line in it was refused for anything but its audience, or
//!    when a version it holds was already refused by an earlier drain. Its
//!    `collector_observation` item (external id the instance, marker
//!    `m:<manifest digest>` over the versions it holds) is staged with the
//!    import's **plan** (the `import.snapshot` cursor) and its status row
//!    (`owner = import`, `snapshot`), in one transaction.
//! 5. Then every row the import staged or relies on is drained, unless
//!    `--no-drain` leaves that to the worker, and the plan is finalized
//!    ([`finalize_import`]).
//!
//! # The snapshot receipt
//!
//! A plan waits until its observation and every row the import relies on are
//! settled: the rows its own pass staged (a pending row the same instance
//! staged earlier is adopted into the pass), and the few another instance
//! staged first (named in the plan). The receipt is then one coverage domain,
//! shaped like a pull pass's: target `[0, N + 1)` over the `N` containers and
//! the import itself, observed the import's ordinal and every complete
//! container, proof `coverage.proof.enumerated_snapshot`, window from the
//! earliest provider clock the file holds to the finalization, and evidence
//! the admitted observation. If a row the import relied on was not admitted,
//! only the import's own ordinal is observed. The status row then records the
//! check (`last_checked_at`), which, with the receipt, is what makes an empty
//! answer over the snapshot `absent`. The worker's `collect` step finalizes
//! every waiting plan after its drain, so an import staged with `--no-drain`
//! becomes a complete snapshot on the tick that admits it. A retired import is
//! never re-activated by that finalization, and an observation that was not
//! admitted fails the source and records no receipt.

pub mod jsonl;
pub mod slack_export;

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::coverage_runtime::{
    CoverageObservationOutcome, CoverageRuntimeRepository, SequenceIntervalV1,
};
use crate::error::{FleetError, Result};
use crate::memory_contracts::collected_item::{
    AudienceBasisV1, BoundedTextV1, CollectionModeV1, MAX_PART_TEXT_BYTES, MAX_SCOPE_ID_BYTES,
    ProviderKindV1, derive_observation_manifest, timestamp_micros,
};
use crate::memory_contracts::common::{CanonicalTimestamp, ContractId};
use crate::memory_contracts::coverage::CoverageProofMethodV1;
use crate::memory_contracts::digest::Sha256Digest;
use crate::memory_contracts::evidence::AcceptedEventId;
use crate::memory_contracts::identity::ResourceUri;
use crate::registry_witness::VerifiedWriterAuthority;

use super::audience::{AudiencePolicyV1, ProviderAudienceV1};
use super::binding::{CollectedConnectorBindingV1, CollectorInstanceV1};
use super::coverage::{PassCoverageV1, coverage_ranges, observation_draft, receipt_observations};
use super::draft::{CollectedItemDraftV1, SealContextV1, collection_record, seal};
use super::pull::{PartialReasonV1, PassSettlementV1, SettledContainerV1};
use super::redaction::{CollectorRedactorV1, scan_collected_secrets};
use super::sink::{
    AdoptedRowV1, CollectedDrainContextV1, CollectedDrainReportV1, CollectedItemSink,
    CollectorDeadLetterV1, ContainerObservationV1, CursorAdvanceV1, DeadLetterReasonV1,
    ImportCompletionV1, OutboxRowStateV1, StageContextV1, StageDraftV1, StagedItemV1,
};
use super::status::{
    CollectorOutcomeV1, CollectorOwnerV1, CollectorSourceStatusV1, CoverageRoleV1,
    MAX_COLLECTOR_STALE_AFTER_SECONDS, MIN_COLLECTOR_STALE_AFTER_SECONDS,
};
use jsonl::{ImportItemV1, ImportLineV1, ImportRefusalV1, LineReader, MAX_IMPORT_LINES, RawLineV1};

/// The cursor domain an import's plan is kept under.
pub const IMPORT_PLAN_DOMAIN: &str = "import.snapshot";

/// How long an import's snapshot stays current unless the operator says
/// otherwise: 30 days.
pub const DEFAULT_IMPORT_STALE_AFTER_SECONDS: u64 = 2_592_000;

/// Items one staging transaction of an import holds at most.
pub const MAX_IMPORT_CHUNK_ITEMS: usize = 256;

/// Parts one staging transaction of an import aims to hold at most (an item
/// is never split across transactions).
const MAX_IMPORT_CHUNK_PARTS: usize = 256;

/// Rows another instance staged that a plan names at most; past it, the
/// snapshot is recorded partial rather than unverified.
const MAX_PLAN_BORROWED: usize = 128;

/// Observed runs a plan carries at most; past it (a snapshot that is already
/// partial), only the import's own ordinal is kept.
const MAX_PLAN_RUNS: usize = 128;

/// Plans one page of the worker's listing reads.
const PLAN_PAGE: u32 = 256;

/// Stage ids one drain of an import's rows names at most.
const DRAIN_CHUNK: usize = 1_024;

const IMPORT_PLAN_SCHEMA_VERSION: u32 = 1;

/// Longest cursor state migration 0033 stores.
const MAX_PLAN_BYTES: usize = 16_384;

/// What an import file is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportFileFormatV1 {
    /// `items-jsonl`: one `CollectedItemInputV1` per line.
    ItemsJsonl,
    /// `slack-export`: a Slack workspace export, a directory or a zip.
    SlackExport {
        /// The private channels (`groups.json`) the operator admits.
        private_containers: Vec<String>,
    },
}

/// One `collect import`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemsImportRequestV1 {
    /// The import's collector instance.
    pub instance: ContractId,
    /// The authenticated ingress principal the items are delivered as.
    pub principal: ContractId,
    /// The provider every line must name.
    pub provider: ProviderKindV1,
    /// The provider scope every line must name.
    pub provider_scope_id: BoundedTextV1<MAX_SCOPE_ID_BYTES>,
    /// The file (or, for an export, the directory).
    pub path: PathBuf,
    /// Its format.
    pub format: ImportFileFormatV1,
    /// How long the snapshot stays current.
    pub stale_after_seconds: u64,
}

/// What an import runs against.
pub struct ImportContextV1<'a> {
    /// The sink, bound to the scope.
    pub sink: &'a CollectedItemSink,
    /// The verified head `connector.collected.import` binds from.
    pub verified: &'a VerifiedWriterAuthority,
    /// The coverage runtime the snapshot receipt is recorded in.
    pub coverage: &'a dyn CoverageRuntimeRepository,
    /// The drain; `None` for `--no-drain`, which leaves the rows to the
    /// worker.
    pub drain: Option<&'a CollectedDrainContextV1<'a>>,
}

impl std::fmt::Debug for ImportContextV1<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ImportContextV1")
            .field("sink", self.sink)
            .field("drain", &self.drain.is_some())
            .finish_non_exhaustive()
    }
}

/// Where an import's snapshot stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ImportSnapshotV1 {
    /// The snapshot receipt is recorded.
    Recorded {
        /// Whether every container of the snapshot is complete.
        complete: bool,
        /// Coverage receipts newly written.
        receipts: u64,
    },
    /// Rows the import relies on are not all settled: a worker's `collect`
    /// step drains them and records the receipt.
    AwaitingDrain,
    /// The import's observation was not admitted: no receipt.
    Failed {
        /// Why.
        reason: String,
    },
    /// The import's status row was retired meanwhile: no receipt is recorded
    /// under it.
    Retired,
    /// No plan of the instance awaits a receipt.
    NoPlan,
}

/// What one drain of an import's rows did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct ImportDrainV1 {
    /// Rows newly appended.
    pub appended: u64,
    /// Rows whose event already existed.
    pub replayed: u64,
    /// Rows the ledger quarantined.
    pub quarantined: u64,
    /// Rows admission refused.
    pub dead_lettered: u64,
    /// Rows that failed and will be retried by the worker.
    pub retried: u64,
    /// Rows that failed an eighth time.
    pub retry_exhausted: u64,
    /// Rows the active package cannot admit.
    pub held: u64,
}

impl ImportDrainV1 {
    const fn add(&mut self, report: &CollectedDrainReportV1) {
        self.appended += report.appended;
        self.replayed += report.replayed;
        self.quarantined += report.quarantined;
        self.dead_lettered += report.dead_lettered;
        self.retried += report.retried;
        self.retry_exhausted += report.retry_exhausted;
        self.held += report.held;
    }
}

/// What one import did: counts, digests, and the snapshot; never an item's
/// text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ItemsImportReportV1 {
    /// The collector instance.
    pub instance: String,
    /// The provider.
    pub provider: String,
    /// The provider scope.
    pub provider_scope_id: String,
    /// The import's pass.
    pub pass_seq: u64,
    /// The SHA-256 of the file.
    pub file_sha256: Sha256Digest,
    /// Records read: lines, or an export's messages.
    pub lines: u64,
    /// Records holding nothing to stage: blank lines, or an export's
    /// membership and housekeeping messages and repeats.
    pub blank_lines: u64,
    /// Items staged, newly or already.
    pub items_staged: u64,
    /// Outbox rows newly written, the observation included.
    pub rows_staged: u64,
    /// Rows already staged: a primary-key no-op.
    pub rows_already_staged: u64,
    /// Refused lines and items, by dead-letter reason.
    pub refused: BTreeMap<DeadLetterReasonV1, u64>,
    /// Containers in the snapshot's domain.
    pub containers: u64,
    /// Of those, the ones no refusal left partial before the drain.
    pub containers_complete: u64,
    /// What the inline drain did; `None` with `--no-drain`.
    pub drained: Option<ImportDrainV1>,
    /// Where the snapshot stands.
    pub snapshot: ImportSnapshotV1,
}

// ---------------------------------------------------------------------------
// The plan
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ImportPlanStateV1 {
    /// The import is staging, or stopped while staging: nothing to finalize.
    Staging,
    /// The observation is staged; the receipt waits for the rows.
    AwaitingDrain,
    /// The receipt is recorded.
    Recorded,
    /// The observation was not admitted.
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PlanOutcomeV1 {
    Ok,
    Unchanged,
}

impl PlanOutcomeV1 {
    const fn status(self) -> CollectorOutcomeV1 {
        match self {
            Self::Ok => CollectorOutcomeV1::Ok,
            Self::Unchanged => CollectorOutcomeV1::Unchanged,
        }
    }
}

/// What finalization needs of an import, with no item named: the receipt's
/// shape, and the rows to wait for besides the pass's own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotPlanV1 {
    principal: ContractId,
    provider: ProviderKindV1,
    provider_scope_id: BoundedTextV1<MAX_SCOPE_ID_BYTES>,
    outcome: PlanOutcomeV1,
    window_start: CanonicalTimestamp,
    observation: Vec<Sha256Digest>,
    containers: u64,
    observed: Vec<[u64; 2]>,
    manifest_digest: Sha256Digest,
    manifest_count: u32,
    borrowed: Vec<Sha256Digest>,
    borrowed_overflow: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportPlanV1 {
    schema_version: u32,
    state: ImportPlanStateV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    snapshot: Option<SnapshotPlanV1>,
}

impl ImportPlanV1 {
    const fn staging() -> Self {
        Self {
            schema_version: IMPORT_PLAN_SCHEMA_VERSION,
            state: ImportPlanStateV1::Staging,
            snapshot: None,
        }
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        let plan: Self = serde_json::from_slice(bytes).map_err(|error| {
            FleetError::Memory(format!("a stored import plan does not decode: {error}"))
        })?;
        if plan.schema_version != IMPORT_PLAN_SCHEMA_VERSION {
            return Err(FleetError::Memory(format!(
                "a stored import plan has schema version {}, not {IMPORT_PLAN_SCHEMA_VERSION}",
                plan.schema_version
            )));
        }
        Ok(plan)
    }

    fn advance(&self, pass_seq: u64, high_water_order: Option<u64>) -> Result<CursorAdvanceV1> {
        let cursor_state = serde_json::to_vec(self).map_err(|error| {
            FleetError::Memory(format!("an import plan does not encode: {error}"))
        })?;
        if cursor_state.len() > MAX_PLAN_BYTES {
            return Err(FleetError::Memory(
                "an import plan is past the cursor bound".to_owned(),
            ));
        }
        Ok(CursorAdvanceV1 {
            domain_key: IMPORT_PLAN_DOMAIN.to_owned(),
            cursor_state,
            high_water_order,
            pass_seq,
        })
    }
}

// ---------------------------------------------------------------------------
// Binding and the instance
// ---------------------------------------------------------------------------

/// The redactor and provider-scope URI of an import instance, from
/// `connector.collected.import` of the verified head.
fn bind_import(
    verified: &VerifiedWriterAuthority,
    principal: &ContractId,
    instance: &CollectorInstanceV1,
) -> Result<(CollectorRedactorV1, ResourceUri)> {
    let connector = CollectionModeV1::Import.connector_schema_id();
    let active = verified
        .bind_connector(&ContractId::new(connector)?)
        .map_err(|error| {
            FleetError::Configuration(format!(
                "the active package does not admit {connector} ({error}); run \
                 `ostk-authority-install apply --target generation-3`"
            ))
        })?;
    let redactor = CollectorRedactorV1::from_active_package(&active)
        .map_err(|error| FleetError::Configuration(error.to_string()))?;
    let scope = CollectedConnectorBindingV1::resolve(
        &active,
        CollectionModeV1::Import,
        principal.clone(),
        instance.clone(),
    )
    .and_then(|binding| binding.provider_instance_uri())
    .map_err(|error| FleetError::Configuration(error.to_string()))?;
    Ok((redactor, scope))
}

/// Refuse an instance another owner reports under, or that already imports
/// another provider scope.
async fn claim_instance(sink: &CollectedItemSink, request: &ItemsImportRequestV1) -> Result<()> {
    let instance = &request.instance;
    if sink.worker_source_exists(instance).await? {
        return Err(FleetError::Configuration(format!(
            "instance {instance} is a worker source (git, transcripts, or CI); import under \
             another instance"
        )));
    }
    match sink.collector_source(instance).await? {
        Some(row) if row.owner != CollectorOwnerV1::Import.as_str() => {
            Err(FleetError::Configuration(format!(
                "instance {instance} already reports as a {} collector; import under another \
                 instance",
                row.owner
            )))
        }
        Some(row)
            if row.provider != request.provider.as_str()
                || row.provider_scope_id != request.provider_scope_id.as_str() =>
        {
            Err(FleetError::Configuration(format!(
                "instance {instance} imports provider {} scope {}; import provider {} scope {} \
                 under another instance",
                row.provider, row.provider_scope_id, request.provider, request.provider_scope_id
            )))
        }
        _ => Ok(()),
    }
}

fn validate_request(request: &ItemsImportRequestV1) -> Result<()> {
    if !(MIN_COLLECTOR_STALE_AFTER_SECONDS..=MAX_COLLECTOR_STALE_AFTER_SECONDS)
        .contains(&request.stale_after_seconds)
    {
        return Err(FleetError::Configuration(format!(
            "--stale-after must be between {MIN_COLLECTOR_STALE_AFTER_SECONDS} and \
             {MAX_COLLECTOR_STALE_AFTER_SECONDS} seconds"
        )));
    }
    if !scan_collected_secrets(request.provider_scope_id.as_str()).is_empty() {
        return Err(FleetError::Configuration(
            "--provider-scope holds a secret shape".to_owned(),
        ));
    }
    match &request.format {
        ImportFileFormatV1::ItemsJsonl => {}
        ImportFileFormatV1::SlackExport { private_containers } => {
            if request.provider.as_str() != crate::collectors::slack::render::SLACK_PROVIDER {
                return Err(FleetError::Configuration(format!(
                    "--format {} imports provider slack only",
                    slack_export::SLACK_EXPORT_FORMAT
                )));
            }
            if let Some(bad) = private_containers.iter().find(|id| {
                id.len() < 3
                    || id.len() > 32
                    || !id.starts_with(['C', 'G'])
                    || !id
                        .bytes()
                        .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
            }) {
                return Err(FleetError::Configuration(format!(
                    "--private-container {bad:?} is not a channel id (C... or G...)"
                )));
            }
        }
    }
    Ok(())
}

/// What the first read of an import learned, and how to read it again.
struct PreparedImportV1 {
    /// The digest of everything the first read read.
    digest: Sha256Digest,
    /// The audience policy the import stages under.
    policy: AudiencePolicyV1,
    /// The observations of the containers items name, by key.
    observations: BTreeMap<Sha256Digest, ContainerObservationV1>,
    /// Observations staged once, before any item: an export's every
    /// channel, the ones never read recorded withdrawn.
    standing: Vec<ContainerObservationV1>,
    /// Containers in the snapshot's domain even with no item.
    declared: Vec<Sha256Digest>,
}

/// The second read of an `items-jsonl` file.
struct JsonlRecordsV1 {
    reader: LineReader<BufReader<File>>,
    instance: CollectorInstanceV1,
}

/// The second read of an import, record by record.
enum ImportRecordsV1 {
    Jsonl(Box<JsonlRecordsV1>),
    SlackExport(Box<slack_export::SlackExportRecordsV1>),
}

impl ImportRecordsV1 {
    /// The next record and its number, or `None` at the end.
    fn next_record(&mut self) -> std::io::Result<Option<(u64, ImportLineV1)>> {
        match self {
            Self::Jsonl(jsonl) => {
                let JsonlRecordsV1 { reader, instance } = &mut **jsonl;
                let Some(line) = reader.next_line()? else {
                    return Ok(None);
                };
                if reader.lines() > MAX_IMPORT_LINES {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("an import file holds at most {MAX_IMPORT_LINES} lines"),
                    ));
                }
                Ok(Some(match line {
                    RawLineV1::Oversize { number, digest } => (
                        number,
                        ImportLineV1::Refused(ImportRefusalV1 {
                            reason: DeadLetterReasonV1::ParseFailed,
                            diagnostic: format!(
                                "the line is longer than {} bytes",
                                jsonl::MAX_IMPORT_LINE_BYTES
                            ),
                            payload_digest: digest,
                            container: None,
                        }),
                    ),
                    RawLineV1::Line { number, bytes } => {
                        (number, jsonl::classify_line(&bytes, instance))
                    }
                }))
            }
            Self::SlackExport(records) => records.next_record(),
        }
    }

    /// Records read so far.
    fn records(&self) -> u64 {
        match self {
            Self::Jsonl(jsonl) => jsonl.reader.lines(),
            Self::SlackExport(records) => records.records(),
        }
    }

    /// The digest of everything read.
    fn digest(self) -> Sha256Digest {
        match self {
            Self::Jsonl(jsonl) => jsonl.reader.digest(),
            Self::SlackExport(records) => records.digest(),
        }
    }
}

fn read_error(path: &Path) -> impl Fn(std::io::Error) -> FleetError + '_ {
    move |error| FleetError::Configuration(format!("cannot read {}: {error}", path.display()))
}

/// Read the import once: its digest, its containers, and its policy.
fn prepare(
    request: &ItemsImportRequestV1,
    instance: &CollectorInstanceV1,
) -> Result<PreparedImportV1> {
    match &request.format {
        ImportFileFormatV1::ItemsJsonl => {
            let scan =
                jsonl::scan(open(&request.path)?, instance).map_err(read_error(&request.path))?;
            Ok(PreparedImportV1 {
                digest: scan.file_sha256,
                policy: AudiencePolicyV1 {
                    operator_declared: true,
                    private_containers: Vec::new(),
                },
                observations: scan
                    .containers
                    .iter()
                    .filter_map(|(key, container)| {
                        container
                            .observation()
                            .map(|observation| (*key, observation))
                    })
                    .collect(),
                standing: Vec::new(),
                declared: Vec::new(),
            })
        }
        ImportFileFormatV1::SlackExport { private_containers } => {
            let scan = slack_export::scan(&request.path, instance, private_containers)
                .map_err(read_error(&request.path))?;
            Ok(PreparedImportV1 {
                digest: scan.digest,
                policy: AudiencePolicyV1 {
                    operator_declared: true,
                    private_containers: private_containers.clone(),
                },
                observations: scan
                    .channels
                    .iter()
                    .map(|channel| (channel.key, channel.observation(true)))
                    .collect(),
                standing: scan
                    .channels
                    .iter()
                    .map(|channel| channel.observation(true))
                    .chain(
                        scan.withheld
                            .iter()
                            .map(|channel| channel.observation(false)),
                    )
                    .collect(),
                declared: scan.channels.iter().map(|channel| channel.key).collect(),
            })
        }
    }
}

/// Open the import's second read.
fn records(
    request: &ItemsImportRequestV1,
    instance: &CollectorInstanceV1,
) -> Result<ImportRecordsV1> {
    Ok(match &request.format {
        ImportFileFormatV1::ItemsJsonl => ImportRecordsV1::Jsonl(Box::new(JsonlRecordsV1 {
            reader: LineReader::new(open(&request.path)?),
            instance: instance.clone(),
        })),
        ImportFileFormatV1::SlackExport { private_containers } => {
            ImportRecordsV1::SlackExport(Box::new(
                slack_export::SlackExportRecordsV1::open(
                    &request.path,
                    instance,
                    private_containers,
                )
                .map_err(read_error(&request.path))?,
            ))
        }
    })
}

fn open(path: &Path) -> Result<BufReader<File>> {
    File::open(path).map(BufReader::new).map_err(|error| {
        FleetError::Configuration(format!("cannot read {}: {error}", path.display()))
    })
}

fn micros_timestamp(micros: u64) -> Result<CanonicalTimestamp> {
    let instant = i64::try_from(micros)
        .ok()
        .and_then(DateTime::<Utc>::from_timestamp_micros)
        .ok_or_else(|| FleetError::Memory("a provider order is not an instant".to_owned()))?;
    Ok(CanonicalTimestamp::from_datetime(&instant)?)
}

/// A transport delivery of an import: the file's digest and a line number
/// (0 for the import's own observation).
fn delivery(file_sha256: &Sha256Digest, line: u64) -> Vec<u8> {
    let mut delivery = file_sha256.as_bytes().to_vec();
    delivery.extend_from_slice(&line.to_be_bytes());
    delivery
}

// ---------------------------------------------------------------------------
// Staging
// ---------------------------------------------------------------------------

/// One version the import holds.
struct TrackedVersionV1 {
    container: Option<Sha256Digest>,
    version_key: Sha256Digest,
    stage_ids: Vec<Sha256Digest>,
    order: u64,
    /// Every part was written by this import's pass.
    fully_new: bool,
    /// No part of it is known to be refused.
    admissible: bool,
}

/// Counts of one import.
#[derive(Default)]
struct ImportCountsV1 {
    blank_lines: u64,
    items_staged: u64,
    rows_staged: u64,
    rows_already_staged: u64,
    refused: BTreeMap<DeadLetterReasonV1, u64>,
}

/// Stages one file's lines chunk by chunk and remembers what the snapshot
/// holds.
struct ImportStager<'a> {
    sink: &'a CollectedItemSink,
    instance: &'a CollectorInstanceV1,
    principal: &'a ContractId,
    redactor: &'a CollectorRedactorV1,
    policy: AudiencePolicyV1,
    pass_seq: u64,
    file_sha256: Sha256Digest,
    observations: BTreeMap<Sha256Digest, ContainerObservationV1>,
    chunk: Vec<(StageDraftV1, Option<Sha256Digest>)>,
    chunk_parts: usize,
    tracked: Vec<TrackedVersionV1>,
    domain: BTreeSet<Option<Sha256Digest>>,
    partial: BTreeMap<Option<Sha256Digest>, BTreeSet<PartialReasonV1>>,
    counts: ImportCountsV1,
    /// A row the import relies on was staged earlier and is still pending:
    /// the import brings material the memory has not admitted yet.
    earlier_pending: bool,
    /// The order the memory holds each item at through the import's tier,
    /// by object kind and external id: read once per kind, when a deletion
    /// with no order of its own first needs it.
    held_orders: BTreeMap<String, BTreeMap<String, u64>>,
}

impl ImportStager<'_> {
    const fn context<'c>(
        &'c self,
        observations: &'c [ContainerObservationV1],
        cursor_advances: &'c [CursorAdvanceV1],
        status: Option<&'c CollectorSourceStatusV1>,
    ) -> StageContextV1<'c> {
        StageContextV1 {
            instance: self.instance,
            principal: self.principal,
            mode: CollectionModeV1::Import,
            attester: None,
            via: None,
            redactor: self.redactor,
            policy: &self.policy,
            capture_scopes: &[],
            pass_seq: Some(self.pass_seq),
            container_observations: observations,
            cursor_advances,
            source_status: status,
        }
    }

    fn mark_partial(&mut self, container: Option<Sha256Digest>, reason: PartialReasonV1) {
        self.domain.insert(container);
        self.partial.entry(container).or_default().insert(reason);
    }

    fn refuse_count(&mut self, reason: DeadLetterReasonV1) {
        *self.counts.refused.entry(reason).or_insert(0) += 1;
    }

    async fn record(&mut self, number: u64, record: ImportLineV1) -> Result<()> {
        match record {
            ImportLineV1::Blank => {
                self.counts.blank_lines += 1;
                Ok(())
            }
            ImportLineV1::Refused(refusal) => self.refuse(number, refusal).await,
            ImportLineV1::Item(item) => self.push(number, *item).await,
        }
    }

    /// Stage observations of the containers a format lists before any item:
    /// an export's channels, including those no item is read from (a private
    /// channel the operator did not list).
    async fn observe(&self, observations: &[ContainerObservationV1]) -> Result<()> {
        if observations.is_empty() {
            return Ok(());
        }
        self.sink
            .stage(&[], &self.context(observations, &[], None))
            .await?;
        Ok(())
    }

    /// A line refused before it became a draft: a digest-only dead letter,
    /// and its container is partial.
    async fn refuse(&mut self, number: u64, refusal: ImportRefusalV1) -> Result<()> {
        self.sink
            .record_dead_letter(
                &self.instance.connector_instance_id,
                &self.instance.provider,
                &CollectorDeadLetterV1 {
                    mode: CollectionModeV1::Import,
                    reason: refusal.reason,
                    payload_digest: refusal.payload_digest,
                    delivery_id: Some(delivery(&self.file_sha256, number)),
                    diagnostic: refusal.diagnostic,
                },
            )
            .await?;
        self.refuse_count(refusal.reason);
        self.mark_partial(refusal.container, PartialReasonV1::ItemRefused);
        Ok(())
    }

    /// The order the memory holds `draft`'s item at through the import's
    /// tier, if it holds it.
    async fn held_order(&mut self, draft: &CollectedItemDraftV1) -> Result<Option<u64>> {
        let kind = draft.object_kind.as_str().to_owned();
        if !self.held_orders.contains_key(&kind) {
            let known = self
                .sink
                .known_versions(
                    &self.instance.provider,
                    self.instance.provider_scope_id.as_str(),
                    &draft.object_kind,
                    CollectionModeV1::Import.trust_tier(),
                )
                .await?;
            self.held_orders.insert(
                kind.clone(),
                known
                    .into_iter()
                    .map(|(external_id, version)| (external_id, version.provider_order))
                    .collect(),
            );
        }
        Ok(self
            .held_orders
            .get(&kind)
            .and_then(|held| held.get(&draft.external_id))
            .copied())
    }

    async fn push(&mut self, number: u64, mut item: ImportItemV1) -> Result<()> {
        if item.at_least_held_order
            && let Some(held) = self.held_order(&item.draft).await?
        {
            item.draft.order_micros = item.draft.order_micros.max(held);
        }
        let parts: usize = item
            .draft
            .sections
            .iter()
            .map(|section| section.text.len().div_ceil(MAX_PART_TEXT_BYTES).max(1))
            .sum();
        if !self.chunk.is_empty()
            && (self.chunk.len() >= MAX_IMPORT_CHUNK_ITEMS
                || self.chunk_parts + parts > MAX_IMPORT_CHUNK_PARTS)
        {
            self.flush().await?;
        }
        self.chunk_parts += parts;
        self.chunk.push((
            StageDraftV1 {
                draft: item.draft,
                provider_audience: item.provider_audience,
                delivery_id: delivery(&self.file_sha256, number),
            },
            item.container,
        ));
        Ok(())
    }

    /// Stage the pending chunk with the observations of its containers, in
    /// one sink transaction.
    async fn flush(&mut self) -> Result<()> {
        if self.chunk.is_empty() {
            return Ok(());
        }
        let chunk = std::mem::take(&mut self.chunk);
        self.chunk_parts = 0;
        let observations: Vec<ContainerObservationV1> = chunk
            .iter()
            .filter_map(|(_, container)| *container)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .filter_map(|key| self.observations.get(&key).cloned())
            .collect();
        let (drafts, containers): (Vec<StageDraftV1>, Vec<Option<Sha256Digest>>) =
            chunk.into_iter().unzip();
        let outcome = self
            .sink
            .stage(&drafts, &self.context(&observations, &[], None))
            .await?;
        self.counts.rows_staged += outcome.rows_staged;
        self.counts.rows_already_staged += outcome.rows_already_staged;
        for ((staged, container), draft) in outcome.items.iter().zip(containers).zip(&drafts) {
            match staged {
                StagedItemV1::Staged {
                    version_key,
                    stage_ids,
                    new_rows,
                    ..
                } => {
                    self.counts.items_staged += 1;
                    self.domain.insert(container);
                    self.tracked.push(TrackedVersionV1 {
                        container,
                        version_key: *version_key,
                        stage_ids: stage_ids.clone(),
                        order: draft.draft.order_micros,
                        fully_new: usize::try_from(*new_rows)
                            .is_ok_and(|rows| rows == stage_ids.len()),
                        admissible: true,
                    });
                }
                StagedItemV1::Refused {
                    reason: DeadLetterReasonV1::AudienceRefused,
                    ..
                } => self.refuse_count(DeadLetterReasonV1::AudienceRefused),
                StagedItemV1::Refused { reason, .. } => {
                    self.refuse_count(*reason);
                    self.mark_partial(container, PartialReasonV1::ItemRefused);
                }
            }
        }
        Ok(())
    }

    /// Adopt the pass's pending rows staged earlier, and learn which rows
    /// another instance staged first and which were refused already.
    /// Returns the borrowed rows and whether they overflowed the plan.
    async fn adopt(&mut self) -> Result<(Vec<Sha256Digest>, bool)> {
        let earlier: Vec<Sha256Digest> = self
            .tracked
            .iter()
            .filter(|version| !version.fully_new)
            .flat_map(|version| version.stage_ids.iter().copied())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        if earlier.is_empty() {
            return Ok((Vec::new(), false));
        }
        let states = self
            .sink
            .adopt_rows(
                &self.instance.connector_instance_id,
                self.pass_seq,
                &earlier,
            )
            .await?;
        let mut borrowed = BTreeSet::new();
        let mut refused = Vec::new();
        for version in &mut self.tracked {
            if version.fully_new {
                continue;
            }
            for id in &version.stage_ids {
                match states.get(id) {
                    Some(AdoptedRowV1::Admitted) => {}
                    Some(AdoptedRowV1::Pending) => self.earlier_pending = true,
                    Some(AdoptedRowV1::Borrowed) => {
                        self.earlier_pending = true;
                        borrowed.insert(*id);
                    }
                    Some(AdoptedRowV1::NotAdmitted) | None => version.admissible = false,
                }
            }
            if !version.admissible {
                refused.push(version.container);
            }
        }
        for container in refused {
            self.mark_partial(container, PartialReasonV1::NotAdmitted);
        }
        if borrowed.len() > MAX_PLAN_BORROWED {
            return Ok((Vec::new(), true));
        }
        Ok((borrowed.into_iter().collect(), false))
    }

    /// The snapshot as far as it is known before the drain.
    fn settle(&self) -> PassSettlementV1 {
        let containers = self
            .domain
            .iter()
            .zip(0_u32..)
            .map(|(key, ordinal)| SettledContainerV1 {
                ordinal,
                container_key: *key,
                reasons: self.partial.get(key).cloned().unwrap_or_default(),
            })
            .collect();
        let manifest: Vec<Sha256Digest> = self
            .tracked
            .iter()
            .filter(|version| version.admissible)
            .map(|version| version.version_key)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        PassSettlementV1 {
            containers,
            manifest_digest: derive_observation_manifest(&manifest),
            manifest,
        }
    }

    /// Every row the import staged or relies on.
    fn stage_ids(&self) -> BTreeSet<Sha256Digest> {
        self.tracked
            .iter()
            .flat_map(|version| version.stage_ids.iter().copied())
            .collect()
    }
}

/// Import one file (`items-jsonl`) or export (`slack-export`). See the module
/// documentation.
///
/// # Errors
///
/// [`FleetError::Configuration`] for a request outside its bounds, an
/// instance another owner or another provider scope holds, a head without
/// `connector.collected.import`, an unreadable file, a file past its bounds,
/// or a file that changed while it was read; any database failure. A refused
/// record is not an error: it is dead-lettered and counted.
#[allow(clippy::too_many_lines)] // one linear claim -> scan -> stage -> observe -> drain pipeline
pub async fn import_items(
    request: &ItemsImportRequestV1,
    context: &ImportContextV1<'_>,
) -> Result<ItemsImportReportV1> {
    validate_request(request)?;
    let sink = context.sink;
    let instance = CollectorInstanceV1 {
        connector_instance_id: request.instance.clone(),
        provider: request.provider.clone(),
        provider_scope_id: request.provider_scope_id.clone(),
    };
    claim_instance(sink, request).await?;
    let (redactor, _) = bind_import(context.verified, &request.principal, &instance)?;
    let prepared = prepare(request, &instance)?;

    let pass_seq = sink
        .read_cursor(&request.instance, IMPORT_PLAN_DOMAIN)
        .await?
        .map_or(1, |cursor| cursor.pass_seq.saturating_add(1));
    sink.write_cursor(
        &request.instance,
        &ImportPlanV1::staging().advance(pass_seq, None)?,
    )
    .await?;
    let instant = sink.server_instant().await?;
    let pass_order = timestamp_micros(&instant)?;

    let mut stager = ImportStager {
        sink,
        instance: &instance,
        principal: &request.principal,
        redactor: &redactor,
        policy: prepared.policy.clone(),
        pass_seq,
        file_sha256: prepared.digest,
        observations: prepared.observations.clone(),
        chunk: Vec::new(),
        chunk_parts: 0,
        tracked: Vec::new(),
        domain: prepared.declared.iter().copied().map(Some).collect(),
        partial: BTreeMap::new(),
        counts: ImportCountsV1::default(),
        earlier_pending: false,
        held_orders: BTreeMap::new(),
    };
    stager.observe(&prepared.standing).await?;
    let mut reader = records(request, &instance)?;
    while let Some((number, record)) = reader.next_record().map_err(read_error(&request.path))? {
        stager.record(number, record).await?;
    }
    stager.flush().await?;
    let lines = reader.records();
    if reader.digest() != prepared.digest {
        return Err(FleetError::Configuration(format!(
            "{} changed while it was imported; nothing was recorded as its snapshot, so import \
             it again",
            request.path.display()
        )));
    }
    let (borrowed, borrowed_overflow) = stager.adopt().await?;

    // The observation, the plan, and the status row, in one transaction.
    let settlement = stager.settle();
    let (target, runs) = coverage_ranges(&settlement)
        .map_err(|error| FleetError::Memory(format!("the import's coverage: {error}")))?;
    let mut observed: Vec<[u64; 2]> = runs.iter().map(|run| [run.start, run.end]).collect();
    if observed.len() > MAX_PLAN_RUNS {
        observed = vec![[target.end - 1, target.end]];
    }
    let observation = observation_draft(&instance, &settlement, pass_order)?;
    let collection = collection_record(
        CollectionModeV1::Import,
        request.instance.clone(),
        None,
        None,
    )
    .map_err(|refusal| FleetError::Configuration(refusal.to_string()))?;
    let observation_ids = seal(
        &observation,
        &SealContextV1 {
            redactor: &redactor,
            audience: AudienceBasisV1::OperatorDeclared,
            collection: &collection,
        },
    )
    .map_err(|refusal| {
        FleetError::Configuration(format!("the import's observation does not seal: {refusal}"))
    })?
    .stage_ids();
    let outcome = if stager.counts.rows_staged > 0 || stager.earlier_pending {
        PlanOutcomeV1::Ok
    } else {
        PlanOutcomeV1::Unchanged
    };
    let window_start = micros_timestamp(
        stager
            .tracked
            .iter()
            .map(|version| version.order)
            .min()
            .map_or(pass_order, |earliest| earliest.min(pass_order)),
    )?;
    let plan = ImportPlanV1 {
        schema_version: IMPORT_PLAN_SCHEMA_VERSION,
        state: ImportPlanStateV1::AwaitingDrain,
        snapshot: Some(SnapshotPlanV1 {
            principal: request.principal.clone(),
            provider: request.provider.clone(),
            provider_scope_id: request.provider_scope_id.clone(),
            outcome,
            window_start,
            observation: observation_ids.clone(),
            containers: target.end - 1,
            observed,
            manifest_digest: settlement.manifest_digest,
            manifest_count: u32::try_from(settlement.manifest.len()).unwrap_or(u32::MAX),
            borrowed: borrowed.clone(),
            borrowed_overflow,
        }),
    };
    let status = CollectorSourceStatusV1 {
        instance: request.instance.clone(),
        provider: request.provider.clone(),
        provider_scope_id: request.provider_scope_id.clone(),
        mode: CollectionModeV1::Import,
        coverage_role: CoverageRoleV1::Snapshot,
        owner: CollectorOwnerV1::Import,
        stale_after_seconds: request.stale_after_seconds,
        outcome: outcome.status(),
        reconciled: false,
        error: None,
    };
    let advance = plan.advance(pass_seq, Some(pass_order))?;
    let observation_outcome = sink
        .stage(
            &[StageDraftV1 {
                draft: observation,
                provider_audience: Some(ProviderAudienceV1::OperatorScoped),
                delivery_id: delivery(&prepared.digest, 0),
            }],
            &stager.context(&[], std::slice::from_ref(&advance), Some(&status)),
        )
        .await?;
    stager.counts.rows_staged += observation_outcome.rows_staged;
    stager.counts.rows_already_staged += observation_outcome.rows_already_staged;
    if let Some(StagedItemV1::Refused { reason, diagnostic }) = observation_outcome.items.first() {
        let reason = format!(
            "the import's observation was refused ({}: {diagnostic}); no snapshot receipt was \
             recorded",
            reason.as_str()
        );
        fail_plan(sink, &request.instance, plan, pass_seq, &reason).await?;
        return Err(FleetError::Memory(reason));
    }

    let (drained, snapshot) = if let Some(drain) = context.drain {
        let mut ids = stager.stage_ids();
        ids.extend(borrowed.iter().copied());
        ids.extend(observation_ids.iter().copied());
        let ids: Vec<Sha256Digest> = ids.into_iter().collect();
        let mut drained = ImportDrainV1::default();
        for chunk in ids.chunks(DRAIN_CHUNK) {
            drained.add(&sink.drain_stage_ids(drain, chunk).await?);
        }
        let snapshot = Box::pin(finalize_import(
            sink,
            context.verified,
            context.coverage,
            &request.instance,
        ))
        .await?;
        (Some(drained), snapshot)
    } else {
        (None, ImportSnapshotV1::AwaitingDrain)
    };
    let containers = u64::try_from(settlement.containers.len()).unwrap_or(u64::MAX);
    let containers_complete = u64::try_from(
        settlement
            .containers
            .iter()
            .filter(|container| container.complete())
            .count(),
    )
    .unwrap_or(u64::MAX);
    Ok(ItemsImportReportV1 {
        instance: request.instance.as_str().to_owned(),
        provider: request.provider.as_str().to_owned(),
        provider_scope_id: request.provider_scope_id.as_str().to_owned(),
        pass_seq,
        file_sha256: prepared.digest,
        lines,
        blank_lines: stager.counts.blank_lines,
        items_staged: stager.counts.items_staged,
        rows_staged: stager.counts.rows_staged,
        rows_already_staged: stager.counts.rows_already_staged,
        refused: std::mem::take(&mut stager.counts.refused),
        containers,
        containers_complete,
        drained,
        snapshot,
    })
}

/// Record a plan whose observation was not admitted: the plan fails and the
/// status row says why.
async fn fail_plan(
    sink: &CollectedItemSink,
    instance: &ContractId,
    mut plan: ImportPlanV1,
    pass_seq: u64,
    reason: &str,
) -> Result<()> {
    plan.state = ImportPlanStateV1::Failed;
    sink.complete_import(
        instance,
        &ImportCompletionV1 {
            outcome: CollectorOutcomeV1::Failed.as_str(),
            checked: false,
            error: Some(reason),
            plan: &plan.advance(pass_seq, None)?,
        },
    )
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Finalization
// ---------------------------------------------------------------------------

/// Record the snapshot receipt of `instance`'s waiting plan, once every row
/// it relies on is settled. See the module documentation.
///
/// # Errors
///
/// A stored plan that does not decode, a head without
/// `connector.collected.import`, a receipt the coverage runtime refuses, or
/// a database failure.
#[allow(clippy::too_many_lines)] // one linear plan -> rows -> receipt -> status pipeline
pub async fn finalize_import(
    sink: &CollectedItemSink,
    verified: &VerifiedWriterAuthority,
    coverage: &dyn CoverageRuntimeRepository,
    instance: &ContractId,
) -> Result<ImportSnapshotV1> {
    let Some(cursor) = sink.read_cursor(instance, IMPORT_PLAN_DOMAIN).await? else {
        return Ok(ImportSnapshotV1::NoPlan);
    };
    let plan = ImportPlanV1::decode(&cursor.cursor_state)?;
    if plan.state != ImportPlanStateV1::AwaitingDrain {
        return Ok(ImportSnapshotV1::NoPlan);
    }
    let Some(snapshot) = plan.snapshot.clone() else {
        return Err(FleetError::Memory(
            "an import plan awaiting its drain holds no snapshot".to_owned(),
        ));
    };
    match sink.collector_source(instance).await? {
        Some(row) if row.owner == CollectorOwnerV1::Import.as_str() && row.state == "active" => {}
        _ => return Ok(ImportSnapshotV1::Retired),
    }

    // The observation must be admitted: its event is the receipt's evidence.
    let observed = sink.row_states(&snapshot.observation).await?;
    let mut evidence = None;
    for id in &snapshot.observation {
        match observed.get(id) {
            Some(OutboxRowStateV1::Admitted(event)) => {
                evidence.get_or_insert(*event);
            }
            Some(OutboxRowStateV1::Pending) => return Ok(ImportSnapshotV1::AwaitingDrain),
            Some(OutboxRowStateV1::Quarantined | OutboxRowStateV1::DeadLettered) | None => {
                evidence = None;
                break;
            }
        }
    }
    let Some(evidence) = evidence else {
        let reason = "the import's observation was not admitted; no snapshot receipt was recorded";
        fail_plan(sink, instance, plan, cursor.pass_seq, reason).await?;
        return Ok(ImportSnapshotV1::Failed {
            reason: reason.to_owned(),
        });
    };

    // Every row the import relies on must be settled; one not admitted
    // leaves only the import's own ordinal observed.
    let mut degraded = snapshot.borrowed_overflow;
    let borrowed = sink.row_states(&snapshot.borrowed).await?;
    for id in &snapshot.borrowed {
        match borrowed.get(id) {
            Some(OutboxRowStateV1::Admitted(_)) => {}
            Some(OutboxRowStateV1::Pending) => return Ok(ImportSnapshotV1::AwaitingDrain),
            _ => degraded = true,
        }
    }
    let unsettled = sink.pass_unsettled(instance, cursor.pass_seq).await?;
    if unsettled.pending > 0 {
        return Ok(ImportSnapshotV1::AwaitingDrain);
    }
    degraded |= unsettled.not_admitted > 0;

    let pinned = CollectorInstanceV1 {
        connector_instance_id: instance.clone(),
        provider: snapshot.provider.clone(),
        provider_scope_id: snapshot.provider_scope_id.clone(),
    };
    let (_, scope) = bind_import(verified, &snapshot.principal, &pinned)?;
    let observed_through = sink.server_instant().await?;
    let window_start = if snapshot.window_start < observed_through {
        snapshot.window_start.clone()
    } else {
        let end = timestamp_micros(&observed_through)?;
        micros_timestamp(end.saturating_sub(1))?
    };
    let range = |start: u64, end: u64| {
        SequenceIntervalV1::new(start, end)
            .map_err(|error| FleetError::Memory(format!("an import plan's range: {error}")))
    };
    let target = range(0, snapshot.containers.saturating_add(1))?;
    let runs = if degraded {
        vec![range(
            snapshot.containers,
            snapshot.containers.saturating_add(1),
        )?]
    } else {
        snapshot
            .observed
            .iter()
            .map(|[start, end]| range(*start, *end))
            .collect::<Result<Vec<_>>>()?
    };
    let complete = runs.as_slice() == [target];
    let observations = receipt_observations(
        &PassCoverageV1 {
            instance,
            principal: &snapshot.principal,
            scope,
            window_start,
            observed_through,
            proof_method: CoverageProofMethodV1::EnumeratedSnapshot,
            evidence_id: AcceptedEventId::from_digest(evidence),
        },
        target,
        runs,
        &snapshot.manifest_digest,
        snapshot.manifest_count,
    )?;
    let mut receipts = 0;
    for observation in &observations {
        if let CoverageObservationOutcome::Recorded { .. } = coverage.observe(observation).await? {
            receipts += 1;
        }
    }
    let recorded = ImportPlanV1 {
        state: ImportPlanStateV1::Recorded,
        ..plan
    };
    let updated = sink
        .complete_import(
            instance,
            &ImportCompletionV1 {
                outcome: snapshot.outcome.status().as_str(),
                checked: true,
                error: None,
                plan: &recorded.advance(cursor.pass_seq, cursor.high_water_order)?,
            },
        )
        .await?;
    Ok(if updated {
        ImportSnapshotV1::Recorded { complete, receipts }
    } else {
        ImportSnapshotV1::Retired
    })
}

/// What finalizing the waiting plans of a scope did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportFinalizeTallyV1 {
    /// Snapshots whose receipt was recorded.
    pub recorded: u64,
    /// Plans still waiting for rows to settle.
    pub waiting: u64,
    /// Plans whose observation was not admitted, or that could not be
    /// finalized.
    pub failed: u64,
    /// Why, one line per failed plan (at most 8).
    pub errors: Vec<String>,
}

/// Finalize every waiting import plan of the scope: what the worker's
/// `collect` step runs after its drain.
///
/// # Errors
///
/// A database failure reading the plans. A plan that fails is counted, not
/// an error.
pub async fn finalize_pending_imports(
    sink: &CollectedItemSink,
    verified: &VerifiedWriterAuthority,
    coverage: &dyn CoverageRuntimeRepository,
) -> Result<ImportFinalizeTallyV1> {
    let mut plans = Vec::new();
    loop {
        let page = sink
            .domain_cursors(
                IMPORT_PLAN_DOMAIN,
                plans
                    .last()
                    .map(|(instance, _): &(String, _)| instance.as_str()),
                PLAN_PAGE,
            )
            .await?;
        let last_page = page.len() < usize::try_from(PLAN_PAGE).unwrap_or(usize::MAX);
        plans.extend(page);
        if last_page {
            break;
        }
    }
    let mut tally = ImportFinalizeTallyV1::default();
    let fail = |tally: &mut ImportFinalizeTallyV1, message: String| {
        tally.failed += 1;
        if tally.errors.len() < 8 {
            tally.errors.push(message);
        }
    };
    for (instance, cursor) in plans {
        match ImportPlanV1::decode(&cursor.cursor_state) {
            Ok(plan) if plan.state == ImportPlanStateV1::AwaitingDrain => {}
            Ok(_) => continue,
            Err(error) => {
                fail(&mut tally, format!("import {instance}: {error}"));
                continue;
            }
        }
        let Ok(id) = ContractId::new(&instance) else {
            fail(
                &mut tally,
                format!("import {instance}: the instance id is not a contract id"),
            );
            continue;
        };
        match finalize_import(sink, verified, coverage, &id).await {
            Ok(ImportSnapshotV1::Recorded { .. }) => tally.recorded += 1,
            Ok(ImportSnapshotV1::AwaitingDrain) => tally.waiting += 1,
            Ok(ImportSnapshotV1::Failed { reason }) => {
                fail(&mut tally, format!("import {instance}: {reason}"));
            }
            Ok(ImportSnapshotV1::Retired | ImportSnapshotV1::NoPlan) => {}
            Err(error) => fail(&mut tally, format!("import {instance}: {error}")),
        }
    }
    Ok(tally)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> ImportPlanV1 {
        ImportPlanV1 {
            schema_version: IMPORT_PLAN_SCHEMA_VERSION,
            state: ImportPlanStateV1::AwaitingDrain,
            snapshot: Some(SnapshotPlanV1 {
                principal: ContractId::new("principal.import").unwrap(),
                provider: ProviderKindV1::new("slack").unwrap(),
                provider_scope_id: BoundedTextV1::new("T07ACME0001").unwrap(),
                outcome: PlanOutcomeV1::Ok,
                window_start: CanonicalTimestamp::parse("2026-09-21T16:04:05.000000000Z").unwrap(),
                observation: vec![Sha256Digest::from_bytes([1; 32])],
                containers: 3,
                observed: vec![[0, 1], [2, 4]],
                manifest_digest: Sha256Digest::from_bytes([2; 32]),
                manifest_count: 9,
                borrowed: vec![Sha256Digest::from_bytes([3; 32]); MAX_PLAN_BORROWED],
                borrowed_overflow: false,
            }),
        }
    }

    #[test]
    fn a_plan_round_trips_and_its_largest_form_fits_a_cursor() {
        let mut largest = plan();
        if let Some(snapshot) = largest.snapshot.as_mut() {
            snapshot.observed = (0..MAX_PLAN_RUNS as u64)
                .map(|run| {
                    [
                        run * 2 + u64::from(u32::MAX),
                        run * 2 + 1 + u64::from(u32::MAX),
                    ]
                })
                .collect();
            snapshot.observation = vec![Sha256Digest::from_bytes([4; 32]); 64];
        }
        let advance = largest.advance(7, Some(1)).expect("the plan fits a cursor");
        assert_eq!(advance.domain_key, IMPORT_PLAN_DOMAIN);
        assert_eq!(
            ImportPlanV1::decode(&advance.cursor_state).unwrap(),
            largest
        );

        let staging = ImportPlanV1::staging().advance(1, None).unwrap();
        assert_eq!(
            ImportPlanV1::decode(&staging.cursor_state).unwrap().state,
            ImportPlanStateV1::Staging
        );
        let mut foreign = plan();
        foreign.schema_version = 2;
        let bytes = serde_json::to_vec(&foreign).unwrap();
        assert!(ImportPlanV1::decode(&bytes).is_err());
        assert!(
            ImportPlanV1::decode(b"{\"schema_version\":1,\"state\":\"staging\",\"x\":1}").is_err()
        );
    }

    #[test]
    fn a_delivery_is_the_file_digest_and_the_line() {
        let file = Sha256Digest::from_bytes([9; 32]);
        let first = delivery(&file, 1);
        assert_eq!(first.len(), 40);
        assert_ne!(first, delivery(&file, 2));
        assert!(first.len() <= crate::collectors::binding::MAX_DELIVERY_ID_BYTES);
    }
}
