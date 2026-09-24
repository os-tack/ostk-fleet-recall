//! The ingest steps: transcript, git, and CI sources to accepted evidence,
//! coverage receipts, and one status row per source.
//!
//! Each step is glue over its connector's library, called in the same order
//! the connector's own connected tests call it. Nothing here re-derives an
//! identity, re-decides governance, or classifies an append: admission and the
//! ledger do that, and this module only counts what they report.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Display;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use sha2::{Digest as _, Sha256};
use sqlx::PgPool;

use crate::connectors::ci::{
    CiConnectorBindingV1, CiCoverageBindingV1, CiDrainContextV1, CiIngressClocksV1,
    CiMeasuredWindowRepository as _, CiMeasuredWindowRowV1, CiTextV1, CiWindowObservationLogV1,
    CockroachCiMeasuredWindowRepository, MAX_CI_WINDOW_RUNS, ci_coverage_observation,
    ci_scan_facts, ci_scan_manifest_digest, drain_ci_facts, scan_runs,
};
use crate::connectors::git::{
    GitConnectorBindingV1, GitCoverageBindingV1, GitDrainContextV1, GitFactV1, GitIngressClocksV1,
    GitRefObservationLogV1, GitRepositoryReader, GitScanRequestV1, GitTreeScanModeV1,
    drain_git_facts, git_coverage_observation,
};
use crate::connectors::transcript::{
    CockroachTranscriptOutboxRepository, MAX_TRANSCRIPT_BYTES, RedactionGuaranteeV1,
    TranscriptCollectionRequestV1, TranscriptConnectorBindingV1, TranscriptCoverageBindingV1,
    TranscriptDrainModeV1, TranscriptDrainRequest, TranscriptEnqueueOutcome,
    TranscriptIngressClocksV1, TranscriptOutboxRepository as _, collect_batch, drain_source_outbox,
    transcript_parser_key_v2,
};
use crate::coverage_runtime::{
    CockroachCoverageRuntimeRepository, CoverageObservationOutcome, CoverageRuntimeRepository as _,
    SequenceIntervalV1,
};
use crate::error::{FleetError, Result};
use crate::evidence_ledger::{ActiveStage4Package, ContentKeyEncryptionKey};
use crate::memory_contracts::canonical::decode_strict;
use crate::memory_contracts::common::{
    CanonicalTimestamp, ContractId, HexBytes, RegistryReferenceV1,
};
use crate::memory_contracts::coverage::{
    CoverageFreshnessV1, CoverageProofBasisV1, CoverageProofMethodV1, CoverageScopeV1,
    CoverageWindowV1, FreshnessStateV1, ProducerIdentityV1, ProducerKindV1,
};
use crate::memory_contracts::digest::Sha256Digest;
use crate::memory_contracts::evidence_v2::EvidenceIngressCandidateV2;
use crate::memory_contracts::generation2_registry::{
    CI_CONNECTOR, GIT_CONNECTOR, Generation2ConnectorIds, TRANSCRIPT_CONNECTOR,
};
use crate::registry_witness::{VerifiedWriterAuthority, WriterAuthorityRuntime};
use crate::store::cockroach::{RetryPolicy, with_serializable_retry};

use super::sources::{
    CiSourceV1, GitSourceV1, TranscriptSourceGroupV1, WorkerSourcesV1, transcript_instance_id,
};
use super::{
    MemoryWorker, WorkerAuthorityReportV1, WorkerCountersV1, WorkerSourceKindV1,
    WorkerSourceOutcomeV1, WorkerSourceReportV1, WorkerStepReportV1, WorkerStepStatusV1,
    WorkerStepV1,
};

/// The freshness rule every worker receipt names. A compile-time label: no
/// package registers it, and the coverage runtime does not resolve it.
pub const COVERAGE_FRESHNESS_LABEL: &str = "coverage.freshness.worker_tick";

/// The proof method every worker receipt names.
///
/// A compile-time label, like [`COVERAGE_FRESHNESS_LABEL`]: the worker
/// enumerates what it read (the file bytes past the cursor, the ref, the
/// provider's run listing).
pub const COVERAGE_PROOF_LABEL: &str = "coverage.proof.enumerated_snapshot";

/// Staged transcript rows one drain pass consumes.
pub const TRANSCRIPT_DRAIN_LIMIT: u32 = 512;

/// The locator coordinate the transcript provider-instance recipe hashes,
/// which a transcript file does not itself publish.
const INSTALLATION_COORDINATE: &str = "provider_installation_id";

/// Longest `last_error` migration 0030 stores.
const MAX_LAST_ERROR_BYTES: usize = 2_048;

/// One tick observes each ref once and each CI window once.
const OBSERVATIONS_PER_TICK: usize = 1;

const TRANSCRIPT_COUNTERS: [&str; 9] = [
    "bytes_consumed",
    "turns_parsed",
    "turns_staged",
    "turns_withheld",
    "turns_redacted",
    "records_skipped",
    "appended",
    "replayed",
    "receipts",
];
const GIT_COUNTERS: [&str; 6] = [
    "commits_walked",
    "facts",
    "appended",
    "replayed",
    "quarantined",
    "receipts",
];
const CI_COUNTERS: [&str; 7] = [
    "runs_admitted",
    "runs_failed",
    "facts",
    "appended",
    "replayed",
    "quarantined",
    "receipts",
];

const UPSERT_SOURCE_STATUS_SQL: &str = "INSERT INTO public.memory_worker_sources_v1 (\
     tenant_id, project, connector_instance_id, source_kind, state, stale_after_seconds, \
     last_outcome, last_attempt_at, last_checked_at, last_error, updated_at\
     ) VALUES ($1, $2, $3, $4, 'active', $5, $6, pg_catalog.statement_timestamp(), \
     CASE WHEN $7 THEN pg_catalog.statement_timestamp() END, $8, \
     pg_catalog.statement_timestamp()) \
     ON CONFLICT (tenant_id, project, connector_instance_id) DO UPDATE SET \
     source_kind = excluded.source_kind, state = 'active', \
     stale_after_seconds = excluded.stale_after_seconds, \
     last_outcome = excluded.last_outcome, last_attempt_at = excluded.last_attempt_at, \
     last_checked_at = COALESCE(excluded.last_checked_at, memory_worker_sources_v1.last_checked_at), \
     last_error = excluded.last_error, updated_at = excluded.updated_at";

const RETIRE_SOURCES_SQL: &str = "UPDATE public.memory_worker_sources_v1 SET \
     state = 'retired', updated_at = pg_catalog.statement_timestamp() \
     WHERE tenant_id = $1 AND project = $2 AND state = 'active' \
     AND connector_instance_id <> ALL($3::STRING[])";

/// A per-source failure, already rendered for the report and the status row.
type SourceResult<T> = std::result::Result<T, String>;

fn describe(error: impl Display) -> String {
    error.to_string()
}

/// What the ingest steps did in one tick.
pub(super) struct IngestOutcome {
    pub(super) authority: Option<WorkerAuthorityReportV1>,
    pub(super) steps: Vec<(WorkerStepV1, WorkerStepReportV1)>,
    pub(super) retired_sources: Option<u64>,
}

/// The database's clock. Every canonical instant the worker stamps comes from
/// here, never from the worker host.
pub(super) async fn server_time(pool: &PgPool) -> Result<DateTime<Utc>> {
    Ok(
        sqlx::query_scalar("SELECT pg_catalog.statement_timestamp()")
            .fetch_one(pool)
            .await?,
    )
}

async fn server_instant(pool: &PgPool) -> SourceResult<CanonicalTimestamp> {
    let now = server_time(pool).await.map_err(describe)?;
    CanonicalTimestamp::from_datetime(&now).map_err(describe)
}

/// A registry reference that names a compile-time label. Its digest is the
/// SHA-256 of the label itself, because no registered entry exists to digest.
fn label_reference(label: &str) -> RegistryReferenceV1 {
    RegistryReferenceV1 {
        entry_id: ContractId::new(label)
            .unwrap_or_else(|_| unreachable!("coverage labels are contract ids")),
        version: 1,
        entry_digest: Sha256Digest::from_bytes(Sha256::digest(label.as_bytes()).into()),
    }
}

fn freshness() -> CoverageFreshnessV1 {
    CoverageFreshnessV1 {
        state: FreshnessStateV1::Current,
        freshness_rule: label_reference(COVERAGE_FRESHNESS_LABEL),
    }
}

fn proof_basis() -> CoverageProofBasisV1 {
    CoverageProofBasisV1 {
        method: CoverageProofMethodV1::EnumeratedSnapshot,
        proof_method_registration: label_reference(COVERAGE_PROOF_LABEL),
    }
}

fn producer(principal: &ContractId) -> ProducerIdentityV1 {
    ProducerIdentityV1 {
        schema_version: 1,
        kind: ProducerKindV1::Connector,
        producer_id: principal.clone(),
        version: 1,
    }
}

fn zeroed(keys: &[&'static str]) -> WorkerCountersV1 {
    keys.iter().map(|key| (*key, 0)).collect()
}

fn add(counters: &mut WorkerCountersV1, key: &'static str, value: u64) {
    *counters.entry(key).or_insert(0) += value;
}

fn count(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// `error` cut to what migration 0030 stores, on a character boundary.
fn bounded_error(error: &str) -> String {
    if error.len() <= MAX_LAST_ERROR_BYTES {
        return error.to_owned();
    }
    let mut end = MAX_LAST_ERROR_BYTES;
    while !error.is_char_boundary(end) {
        end -= 1;
    }
    error[..end].to_owned()
}

/// Run the selected ingest steps.
pub(super) async fn run_ingest(worker: &MemoryWorker) -> IngestOutcome {
    let selected: Vec<WorkerStepV1> = WorkerStepV1::INGEST
        .into_iter()
        .filter(|step| worker.steps.contains(step))
        .collect();
    let (Some(runtime), Some(kek)) = (&worker.deps.authority, &worker.drain_kek) else {
        // `MemoryWorker::new` refuses this combination; fail closed anyway.
        return IngestOutcome {
            authority: None,
            steps: selected
                .into_iter()
                .map(|step| {
                    (
                        step,
                        WorkerStepReportV1::failed(
                            "the writer authority or the content key is not configured".into(),
                        ),
                    )
                })
                .collect(),
            retired_sources: None,
        };
    };
    // One verification per tick; every connector binds from this head.
    let verified = runtime
        .verify()
        .await
        .map_err(|error| format!("the writer authority did not verify: {error}"));
    let authority = verified
        .as_ref()
        .ok()
        .map(|verified| WorkerAuthorityReportV1 {
            generation: verified.witness().generation(),
            activation_id: verified.witness().activation_id(),
        });
    let ingest = Ingest {
        pool: &worker.deps.pool,
        worker,
        runtime,
        kek,
        coverage: CockroachCoverageRuntimeRepository::new(
            worker.deps.pool.clone(),
            runtime.control_scope().clone(),
            worker.deps.retry,
        ),
    };

    let mut inventory = Some(BTreeSet::new());
    let mut steps = Vec::with_capacity(selected.len());
    for step in &selected {
        let report = match step {
            WorkerStepV1::Transcript => ingest.transcript_step(&verified, &mut inventory).await,
            WorkerStepV1::Git => ingest.git_step(&verified, &mut inventory).await,
            WorkerStepV1::Ci => ingest.ci_step(&verified, &mut inventory).await,
            _ => continue,
        };
        steps.push((*step, report));
    }

    // Retire only from a complete inventory: a directory that could not be
    // listed must not retire the files it holds.
    let retired_sources = match inventory {
        Some(configured) if selected.len() == WorkerStepV1::INGEST.len() => {
            match ingest.retire_unconfigured(&configured).await {
                Ok(retired) => Some(retired),
                Err(error) => {
                    tracing::warn!(%error, "retiring unconfigured worker sources failed");
                    None
                }
            }
        }
        _ => None,
    };
    IngestOutcome {
        authority,
        steps,
        retired_sources,
    }
}

/// One transcript file found in a configured directory.
struct TranscriptFile<'g> {
    group: &'g TranscriptSourceGroupV1,
    path: PathBuf,
    /// The file name: the transcript cursor's and outbox's `source_id`.
    source_id: String,
    instance: SourceResult<ContractId>,
}

/// Everything the configured directories hold right now.
struct TranscriptInventory<'g> {
    files: Vec<TranscriptFile<'g>>,
    /// Directories that could not be listed.
    errors: Vec<String>,
}

/// List every `*.jsonl` file directly inside every configured directory.
async fn discover_transcripts(sources: &WorkerSourcesV1) -> TranscriptInventory<'_> {
    let mut inventory = TranscriptInventory {
        files: Vec::new(),
        errors: Vec::new(),
    };
    for group in &sources.transcripts {
        for dir in &group.dirs {
            match list_jsonl(dir).await {
                Ok(paths) => {
                    for (path, source_id) in paths {
                        let instance = transcript_instance_id(&group.instance_prefix, &source_id)
                            .map_err(describe);
                        inventory.files.push(TranscriptFile {
                            group,
                            path,
                            source_id,
                            instance,
                        });
                    }
                }
                Err(error) => inventory.errors.push(format!(
                    "transcript directory {} cannot be listed: {error}",
                    dir.display()
                )),
            }
        }
    }
    // A file name is the cursor's key and a derived instance is the coverage
    // and status key, so two files sharing either would read or report as one
    // source. Both are refused rather than one silently shadowing the other.
    let mut source_ids: BTreeMap<String, usize> = BTreeMap::new();
    let mut instances: BTreeMap<String, usize> = BTreeMap::new();
    for file in &inventory.files {
        *source_ids.entry(file.source_id.clone()).or_default() += 1;
        if let Ok(instance) = &file.instance {
            *instances.entry(instance.as_str().to_owned()).or_default() += 1;
        }
    }
    for file in &mut inventory.files {
        let Ok(instance) = &file.instance else {
            continue;
        };
        if source_ids.get(&file.source_id).copied().unwrap_or(0) > 1 {
            file.instance = Err(format!(
                "another configured directory also holds a transcript named {}",
                file.source_id
            ));
        } else if instances.get(instance.as_str()).copied().unwrap_or(0) > 1 {
            file.instance = Err(format!(
                "another transcript file also maps to the connector instance {instance}"
            ));
        }
    }
    inventory
}

/// The `*.jsonl` regular files directly inside `dir`, sorted, with their
/// UTF-8 file names.
async fn list_jsonl(dir: &Path) -> std::io::Result<Vec<(PathBuf, String)>> {
    let mut entries = tokio::fs::read_dir(dir).await?;
    let mut files = Vec::new();
    while let Some(entry) = entries.next_entry().await? {
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if Path::new(&name)
            .extension()
            .is_none_or(|extension| extension != "jsonl")
        {
            continue;
        }
        if tokio::fs::metadata(entry.path()).await?.is_file() {
            files.push((entry.path(), name));
        }
    }
    files.sort();
    Ok(files)
}

/// The instance a transcript file whose derived instance failed reports
/// under, if any: a collision still has an instance; an underivable id has
/// none.
fn colliding_instance(file: &TranscriptFile<'_>) -> Option<ContractId> {
    transcript_instance_id(&file.group.instance_prefix, &file.source_id).ok()
}

struct Ingest<'w> {
    pool: &'w PgPool,
    worker: &'w MemoryWorker,
    runtime: &'w WriterAuthorityRuntime,
    kek: &'w ContentKeyEncryptionKey,
    coverage: CockroachCoverageRuntimeRepository,
}

impl Ingest<'_> {
    const fn sources(&self) -> &WorkerSourcesV1 {
        &self.worker.deps.sources
    }

    const fn retry(&self) -> RetryPolicy {
        self.worker.deps.retry
    }

    fn coverage_window(&self, now: &CanonicalTimestamp) -> CoverageWindowV1 {
        CoverageWindowV1 {
            window_start: self.worker.coverage_since.clone(),
            window_end: now.clone(),
        }
    }

    /// Bind one connector schema from this tick's head.
    fn bind<'v>(
        verified: &'v std::result::Result<VerifiedWriterAuthority, String>,
        connector: &Generation2ConnectorIds,
    ) -> SourceResult<(ActiveStage4Package, &'v VerifiedWriterAuthority)> {
        let verified = verified.as_ref().map_err(Clone::clone)?;
        let schema = ContractId::new(connector.connector_schema).map_err(describe)?;
        let active = verified.bind_connector(&schema).map_err(|error| {
            format!(
                "the active package does not admit {}: {error}",
                connector.connector_schema
            )
        })?;
        Ok((active, verified))
    }

    async fn transcript_step(
        &self,
        verified: &std::result::Result<VerifiedWriterAuthority, String>,
        inventory: &mut Option<BTreeSet<String>>,
    ) -> WorkerStepReportV1 {
        let discovered = discover_transcripts(self.sources()).await;
        if !discovered.errors.is_empty() {
            *inventory = None;
        }
        let bound = Self::bind(verified, &TRANSCRIPT_CONNECTOR).and_then(|(active, verified)| {
            let guarantee = RedactionGuaranteeV1::from_active_package(&active).map_err(describe)?;
            Ok((active, verified, guarantee))
        });
        let mut reports = Vec::with_capacity(discovered.files.len());
        for file in &discovered.files {
            let mut counters = zeroed(&TRANSCRIPT_COUNTERS);
            let (instance, result) = match (&file.instance, &bound) {
                (Ok(instance), Ok((active, verified, guarantee))) => {
                    let result = self
                        .ingest_transcript(
                            active,
                            verified,
                            guarantee,
                            file,
                            instance,
                            &mut counters,
                        )
                        .await;
                    (Some(instance.clone()), result)
                }
                (Ok(instance), Err(error)) => (Some(instance.clone()), Err(error.clone())),
                (Err(error), _) => (colliding_instance(file), Err(error.clone())),
            };
            let stale_after = self.sources().stale_after(file.group.stale_after_seconds);
            let report = self
                .finish_source(
                    instance.as_ref(),
                    WorkerSourceKindV1::Transcript,
                    file.source_id.clone(),
                    stale_after,
                    result,
                    counters,
                    inventory,
                )
                .await;
            reports.push(report);
        }
        step_report(reports, discovered.errors, &TRANSCRIPT_COUNTERS)
    }

    async fn git_step(
        &self,
        verified: &std::result::Result<VerifiedWriterAuthority, String>,
        inventory: &mut Option<BTreeSet<String>>,
    ) -> WorkerStepReportV1 {
        let bound = Self::bind(verified, &GIT_CONNECTOR);
        let mut reports = Vec::with_capacity(self.sources().git.len());
        for source in &self.sources().git {
            let mut counters = zeroed(&GIT_COUNTERS);
            let result = match &bound {
                Ok((active, verified)) => {
                    self.ingest_git(active, verified, source, &mut counters)
                        .await
                }
                Err(error) => Err(error.clone()),
            };
            let report = self
                .finish_source(
                    Some(&source.connector_instance),
                    WorkerSourceKindV1::Git,
                    format!("{} {}", source.git_dir.display(), source.ref_name),
                    self.sources().stale_after(source.stale_after_seconds),
                    result,
                    counters,
                    inventory,
                )
                .await;
            reports.push(report);
        }
        step_report(reports, Vec::new(), &GIT_COUNTERS)
    }

    async fn ci_step(
        &self,
        verified: &std::result::Result<VerifiedWriterAuthority, String>,
        inventory: &mut Option<BTreeSet<String>>,
    ) -> WorkerStepReportV1 {
        let bound = Self::bind(verified, &CI_CONNECTOR);
        let mut reports = Vec::with_capacity(self.sources().ci.len());
        for source in &self.sources().ci {
            let mut counters = zeroed(&CI_COUNTERS);
            let result = match &bound {
                Ok((active, verified)) => {
                    self.ingest_ci(active, verified, source, &mut counters)
                        .await
                }
                Err(error) => Err(error.clone()),
            };
            let report = self
                .finish_source(
                    Some(&source.connector_instance),
                    WorkerSourceKindV1::Ci,
                    format!(
                        "{} {} {}",
                        source.provider_repository, source.workflow, source.branch
                    ),
                    self.sources().stale_after(source.stale_after_seconds),
                    result,
                    counters,
                    inventory,
                )
                .await;
            reports.push(report);
        }
        step_report(reports, Vec::new(), &CI_COUNTERS)
    }

    /// Record one source's outcome in its status row and build its report.
    #[allow(clippy::too_many_arguments)] // one call site per step, all named
    async fn finish_source(
        &self,
        instance: Option<&ContractId>,
        kind: WorkerSourceKindV1,
        source: String,
        stale_after: u64,
        result: SourceResult<WorkerSourceOutcomeV1>,
        counters: WorkerCountersV1,
        inventory: &mut Option<BTreeSet<String>>,
    ) -> WorkerSourceReportV1 {
        let (mut outcome, mut error) = match result {
            Ok(outcome) => (outcome, None),
            Err(error) => (WorkerSourceOutcomeV1::Failed, Some(bounded_error(&error))),
        };
        if let Some(instance) = instance {
            if let Some(configured) = inventory.as_mut() {
                configured.insert(instance.as_str().to_owned());
            }
            if let Err(status_error) = self
                .record_status(instance, kind, stale_after, outcome, error.as_deref())
                .await
            {
                let message = format!("the source status row was not recorded: {status_error}");
                error = Some(bounded_error(&match error {
                    Some(earlier) => format!("{earlier}; {message}"),
                    None => message,
                }));
                outcome = WorkerSourceOutcomeV1::Failed;
            }
        } else {
            *inventory = None;
        }
        WorkerSourceReportV1 {
            connector_instance: instance.map_or_else(String::new, |id| id.as_str().to_owned()),
            kind,
            source,
            outcome,
            error,
            counters,
        }
    }

    async fn record_status(
        &self,
        instance: &ContractId,
        kind: WorkerSourceKindV1,
        stale_after: u64,
        outcome: WorkerSourceOutcomeV1,
        error: Option<&str>,
    ) -> Result<()> {
        let scope = &self.worker.deps.scope;
        let tenant_id = scope.tenant_id;
        let project = scope.project.clone();
        let instance = instance.as_str().to_owned();
        let stale_after = i64::try_from(stale_after)
            .map_err(|_| FleetError::Configuration("stale_after_seconds exceeds INT8".into()))?;
        let checked = outcome != WorkerSourceOutcomeV1::Failed;
        let error = error.map(str::to_owned);
        with_serializable_retry(self.pool, self.retry(), move |transaction| {
            let project = project.clone();
            let instance = instance.clone();
            let error = error.clone();
            Box::pin(async move {
                sqlx::query(UPSERT_SOURCE_STATUS_SQL)
                    .bind(tenant_id)
                    .bind(project)
                    .bind(instance)
                    .bind(kind.as_str())
                    .bind(stale_after)
                    .bind(outcome.as_str())
                    .bind(checked)
                    .bind(error)
                    .execute(&mut **transaction)
                    .await?;
                Ok(())
            })
        })
        .await
    }

    async fn retire_unconfigured(&self, configured: &BTreeSet<String>) -> Result<u64> {
        let scope = &self.worker.deps.scope;
        let tenant_id = scope.tenant_id;
        let project = scope.project.clone();
        let configured: Vec<String> = configured.iter().cloned().collect();
        with_serializable_retry(self.pool, self.retry(), move |transaction| {
            let project = project.clone();
            let configured = configured.clone();
            Box::pin(async move {
                Ok(sqlx::query(RETIRE_SOURCES_SQL)
                    .bind(tenant_id)
                    .bind(project)
                    .bind(configured)
                    .execute(&mut **transaction)
                    .await?
                    .rows_affected())
            })
        })
        .await
    }

    /// Collect one transcript file into the outbox, then drain its pending
    /// turns under this source's own coverage domain.
    async fn ingest_transcript(
        &self,
        active: &ActiveStage4Package,
        verified: &VerifiedWriterAuthority,
        guarantee: &RedactionGuaranteeV1,
        file: &TranscriptFile<'_>,
        instance: &ContractId,
        counters: &mut WorkerCountersV1,
    ) -> SourceResult<WorkerSourceOutcomeV1> {
        let outbox = CockroachTranscriptOutboxRepository::new(
            self.pool.clone(),
            self.runtime.control_scope().clone(),
            self.retry(),
        );
        let collected = self
            .collect_transcript(active, guarantee, file, instance, &outbox, counters)
            .await;
        // The drain runs even when collection failed: turns an earlier window
        // or tick staged are durable, and a bad later line must not strand
        // them in the outbox, where every evidence answer would count them as
        // pending. The source still reports the collection failure.
        let drained = self
            .drain_transcript(active, verified, file, &outbox, counters)
            .await;
        match (collected, drained) {
            (Ok(collected), Ok(drained)) => Ok(if collected || drained {
                WorkerSourceOutcomeV1::Ok
            } else {
                WorkerSourceOutcomeV1::Unchanged
            }),
            (Err(error), Ok(_)) | (Ok(_), Err(error)) => Err(error),
            (Err(collect), Err(drain)) => Err(format!(
                "{collect}; draining its staged turns also failed: {drain}"
            )),
        }
    }

    /// Stage every complete line past the durable cursor, window by window.
    /// Whether the cursor advanced.
    async fn collect_transcript(
        &self,
        active: &ActiveStage4Package,
        guarantee: &RedactionGuaranteeV1,
        file: &TranscriptFile<'_>,
        instance: &ContractId,
        outbox: &CockroachTranscriptOutboxRepository,
        counters: &mut WorkerCountersV1,
    ) -> SourceResult<bool> {
        let group = file.group;
        let source_id = file.source_id.as_str();
        let binding = TranscriptConnectorBindingV1 {
            ingress_principal_id: group.connector_principal.clone(),
            connector_instance_id: instance.clone(),
            instance_coordinates: BTreeMap::from([(
                ContractId::new(INSTALLATION_COORDINATE).map_err(describe)?,
                group.installation_id.to_string(),
            )]),
        };
        let parser_key = transcript_parser_key_v2();
        let mut progressed = false;
        let mut bytes: Option<Vec<u8>> = None;

        // The parser bounds one window, not the file, so a long session file is
        // read in windows behind the advancing durable cursor.
        loop {
            let cursor = outbox.read_cursor(source_id).await.map_err(describe)?;
            let resume = cursor.as_ref().map_or(0, |row| row.byte_offset);
            let length = match &bytes {
                Some(bytes) => count(bytes.len()),
                None => tokio::fs::metadata(&file.path)
                    .await
                    .map_err(|error| format!("{} cannot be read: {error}", file.path.display()))?
                    .len(),
            };
            if resume > length {
                return Err(format!(
                    "{source_id} is shorter than its durable cursor ({length} < {resume} bytes); \
                     it was truncated or replaced"
                ));
            }
            if resume == length {
                break;
            }
            if bytes.is_none() {
                bytes =
                    Some(tokio::fs::read(&file.path).await.map_err(|error| {
                        format!("{} cannot be read: {error}", file.path.display())
                    })?);
            }
            let data = bytes.as_deref().unwrap_or_default();
            let resume_at = usize::try_from(resume).map_err(describe)?;
            let window_end = data.len().min(resume_at.saturating_add(group.window_bytes));
            let now = server_instant(self.pool).await?;
            let (batch, stats) = collect_batch(&TranscriptCollectionRequestV1 {
                active,
                binding: &binding,
                guarantee,
                parser_key: &parser_key,
                source_id,
                bytes: &data[..window_end],
                cursor: cursor.as_ref(),
                clocks: &TranscriptIngressClocksV1 {
                    observed_at: now.clone(),
                    received_at: now,
                },
            })
            .map_err(describe)?;
            add(counters, "turns_parsed", u64::from(stats.turns_parsed));
            add(counters, "turns_withheld", u64::from(stats.turns_withheld));
            add(counters, "turns_redacted", u64::from(stats.turns_redacted));
            add(
                counters,
                "records_skipped",
                u64::from(stats.records_skipped),
            );
            // A window that holds no complete line moves nothing. Decided
            // before the enqueue, which would answer `AlreadyCovered` for a
            // cursor that did not move and so hide a line no window can hold.
            if batch.cursor.byte_offset <= resume {
                if window_end < data.len() {
                    return Err(format!(
                        "{source_id} has a line longer than window_bytes ({}) at byte {resume}; \
                         nothing past it is read until its transcript group's window_bytes \
                         (at most {MAX_TRANSCRIPT_BYTES}) exceeds the line",
                        group.window_bytes
                    ));
                }
                // Only a partial last line is left; the next tick reads it.
                break;
            }
            match outbox.enqueue_batch(&batch).await.map_err(describe)? {
                TranscriptEnqueueOutcome::Enqueued { rows_written, .. } => {
                    add(counters, "turns_staged", rows_written);
                }
                // Another writer moved the durable cursor past this window.
                TranscriptEnqueueOutcome::AlreadyCovered { .. } => break,
            }
            add(
                counters,
                "bytes_consumed",
                batch.cursor.byte_offset - resume,
            );
            progressed = true;
        }
        Ok(progressed)
    }

    /// Drain every pending turn of one file under one coverage domain whose
    /// target is `[lowest pending ordinal, next ordinal)`. Whether anything
    /// was pending.
    async fn drain_transcript(
        &self,
        active: &ActiveStage4Package,
        verified: &VerifiedWriterAuthority,
        file: &TranscriptFile<'_>,
        outbox: &CockroachTranscriptOutboxRepository,
        counters: &mut WorkerCountersV1,
    ) -> SourceResult<bool> {
        let source_id = file.source_id.as_str();
        let Some(lowest) = outbox
            .pending_ordinal_floor(source_id)
            .await
            .map_err(describe)?
        else {
            return Ok(false);
        };
        let next = outbox
            .read_cursor(source_id)
            .await
            .map_err(describe)?
            .map(|cursor| cursor.next_ordinal)
            .ok_or_else(|| format!("{source_id} has pending turns but no durable cursor"))?;
        let target = SequenceIntervalV1::new(u64::from(lowest), u64::from(next))
            .map_err(|error| format!("{source_id} pending turns: {error}"))?;
        let first = outbox
            .staged_rows_for_source(source_id, true, 1)
            .await
            .map_err(describe)?;
        let first = first
            .first()
            .ok_or_else(|| format!("{source_id} lost its pending turns during the tick"))?;
        let candidate: EvidenceIngressCandidateV2 =
            decode_strict(&first.canonical_candidate).map_err(describe)?;
        let now = server_instant(self.pool).await?;
        let coverage_binding = TranscriptCoverageBindingV1 {
            producer: producer(&file.group.connector_principal),
            scope: CoverageScopeV1 {
                scope: candidate.source_fact.provider_instance_id,
                revision: HexBytes::new(source_id.as_bytes().to_vec()).map_err(describe)?,
                window: self.coverage_window(&now),
            },
            target,
            freshness: freshness(),
            proof_basis: proof_basis(),
            observed_through: now,
        };
        loop {
            let summary = drain_source_outbox(
                TranscriptDrainRequest {
                    active,
                    witness: verified.append_witness(),
                    outbox,
                    ledger: self.runtime.ledger().as_ref(),
                    coverage: &self.coverage,
                    trusted_scope: self.runtime.control_scope(),
                    content_key: self.kek,
                    coverage_binding: &coverage_binding,
                    mode: TranscriptDrainModeV1::Pending,
                    limit: TRANSCRIPT_DRAIN_LIMIT,
                },
                source_id,
            )
            .await
            .map_err(describe)?;
            add(counters, "appended", summary.appended);
            add(counters, "replayed", summary.replayed);
            add(counters, "receipts", summary.receipts);
            if summary.rows_read == 0 {
                break;
            }
        }
        Ok(true)
    }

    /// Observe one ref when its target moved since the instance's latest
    /// receipt, and admit the history behind it.
    #[allow(clippy::too_many_lines)] // one linear read -> scan -> drain -> receipt pipeline
    async fn ingest_git(
        &self,
        active: &ActiveStage4Package,
        verified: &VerifiedWriterAuthority,
        source: &GitSourceV1,
        counters: &mut WorkerCountersV1,
    ) -> SourceResult<WorkerSourceOutcomeV1> {
        let instance = &source.connector_instance;
        let ref_name = source.ref_name().map_err(describe)?;
        let reader = GitRepositoryReader::new(
            &source.git_dir,
            source.repository().map_err(describe)?,
            None,
        )
        .map_err(describe)?;
        let target = {
            let reader = reader.clone();
            let ref_name = ref_name.clone();
            tokio::task::spawn_blocking(move || reader.resolve_ref(&ref_name))
                .await
                .map_err(|_| "the git ref read did not finish".to_owned())?
                .map_err(describe)?
        };
        let latest = self
            .coverage
            .latest_receipt_for_instance(instance)
            .await
            .map_err(describe)?;
        if latest.is_some_and(|receipt| receipt.scope.revision.as_bytes() == target.as_bytes()) {
            return Ok(WorkerSourceOutcomeV1::Unchanged);
        }

        let request = GitScanRequestV1 {
            ref_name,
            max_commits: source.max_commits,
            max_facts: source.max_facts,
            tree_mode: GitTreeScanModeV1::CommitsOnly,
        };
        let scan = {
            let reader = reader.clone();
            tokio::task::spawn_blocking(move || reader.scan(&request))
                .await
                .map_err(|_| "the git scan did not finish".to_owned())?
                .map_err(describe)?
        };
        add(counters, "commits_walked", count(scan.commits.len()));
        let binding = GitConnectorBindingV1::resolve(
            active,
            source.connector_principal.clone(),
            instance.clone(),
            source.installation_id,
        )
        .map_err(describe)?;

        // The scan's own target is the one observed: the ref may have moved
        // between the first read and the walk.
        let now = server_instant(self.pool).await?;
        let mut log = GitRefObservationLogV1::new(
            reader.repository().clone(),
            scan.ref_name.clone(),
            instance.clone(),
        )
        .map_err(describe)?;
        log.observe(scan.target.clone(), now.clone(), OBSERVATIONS_PER_TICK)
            .map_err(describe)?;
        let mut facts = scan.facts.clone();
        facts.extend(
            log.observations()
                .iter()
                .cloned()
                .map(GitFactV1::RefObservation),
        );
        add(counters, "facts", count(facts.len()));

        let report = drain_git_facts(
            &GitDrainContextV1 {
                binding: &binding,
                active,
                witness: verified.append_witness(),
                ledger: self.runtime.ledger().as_ref(),
                control_scope: self.runtime.control_scope(),
                kek: self.kek,
                clocks: &GitIngressClocksV1 {
                    received_at: now.clone(),
                },
            },
            &facts,
        )
        .await
        .map_err(describe)?;
        add(counters, "appended", report.appended);
        add(counters, "replayed", report.replayed);
        add(counters, "quarantined", report.quarantined);

        // One observation of one ref: the domain's target and the observed
        // range are both [1, 2), so the receipt claims exactly the observation
        // it binds.
        let one = SequenceIntervalV1::new(1, 2).map_err(describe)?;
        let observation = git_coverage_observation(
            &GitCoverageBindingV1 {
                connector_instance: instance.clone(),
                producer: producer(&source.connector_principal),
                freshness: freshness(),
                proof_basis: proof_basis(),
                window: self.coverage_window(&now),
            },
            binding.provider_instance_uri().map_err(describe)?,
            &scan.target,
            one,
            one,
            &report,
            now,
        )
        .map_err(describe)?;
        self.observe(&observation, counters).await?;
        Ok(WorkerSourceOutcomeV1::Ok)
    }

    /// Read the settled runs past the highest measured window, admit them, and
    /// record the window.
    ///
    /// The next tick resumes after the highest recorded window, so a tick
    /// that fails after appending some runs but before recording its window
    /// reads that range again. A run fact's `observed_at` is the scan's fetch
    /// instant, so the runs already appended then come back as quarantined
    /// preimage disagreements, which the report counts; the events from the
    /// first attempt stand.
    #[allow(clippy::too_many_lines)] // one linear resume -> scan -> drain -> window -> receipt pipeline
    async fn ingest_ci(
        &self,
        active: &ActiveStage4Package,
        verified: &VerifiedWriterAuthority,
        source: &CiSourceV1,
        counters: &mut WorkerCountersV1,
    ) -> SourceResult<WorkerSourceOutcomeV1> {
        let instance = &source.connector_instance;
        let scope = &self.worker.deps.scope;
        let windows = CockroachCiMeasuredWindowRepository::new(
            self.pool.clone(),
            scope.tenant_id,
            scope.project.clone(),
        );
        let resume = windows
            .resume_run_number(
                instance,
                &source.repository_id,
                &CiTextV1::render(&source.workflow).map_err(describe)?,
                &CiTextV1::render(&source.branch).map_err(describe)?,
            )
            .await
            .map_err(describe)?;
        let first = resume.max(source.first_run_number);

        let lookup = {
            let factory = Arc::clone(&self.worker.deps.ci_providers);
            let source = source.clone();
            tokio::task::spawn_blocking(move || factory.provider(&source))
                .await
                .map_err(|_| "the CI provider lookup did not finish".to_owned())?
                .map_err(describe)?
        };
        let Some((provider, high_water)) = lookup else {
            return Ok(WorkerSourceOutcomeV1::Unchanged);
        };
        if high_water < first {
            return Ok(WorkerSourceOutcomeV1::Unchanged);
        }
        let last = high_water.min(first.saturating_add(count(MAX_CI_WINDOW_RUNS) - 1));
        let request = source.scan_request(first, last).map_err(describe)?;
        let fetched_at = server_instant(self.pool).await?;
        let scan = {
            let fetched_at = fetched_at.clone();
            tokio::task::spawn_blocking(move || scan_runs(provider.as_ref(), &request, &fetched_at))
                .await
                .map_err(|_| "the CI scan did not finish".to_owned())?
                .map_err(describe)?
        };
        add(
            counters,
            "runs_admitted",
            u64::from(scan.admitted_run_count()),
        );
        add(counters, "runs_failed", u64::from(scan.failed_run_count()));

        let binding = CiConnectorBindingV1::resolve(
            active,
            source.connector_principal.clone(),
            instance.clone(),
            source.installation_id,
        )
        .map_err(describe)?;
        let mut log = CiWindowObservationLogV1::new(instance.clone());
        let facts = ci_scan_facts(&scan, &mut log, OBSERVATIONS_PER_TICK).map_err(describe)?;
        add(counters, "facts", count(facts.len()));
        let received_at = server_instant(self.pool).await?;
        let report = drain_ci_facts(
            &CiDrainContextV1 {
                binding: &binding,
                active,
                witness: verified.append_witness(),
                ledger: self.runtime.ledger().as_ref(),
                control_scope: self.runtime.control_scope(),
                kek: self.kek,
                clocks: &CiIngressClocksV1 {
                    observed_at: fetched_at,
                    received_at: received_at.clone(),
                },
            },
            &facts,
        )
        .await
        .map_err(describe)?;
        add(counters, "appended", report.appended);
        add(counters, "replayed", report.replayed);
        add(counters, "quarantined", report.quarantined);

        // The domain's target is the range this tick asked for. It equals the
        // window's own range unless the provider's listing was cut short and
        // the window narrowed, in which case the receipt is honestly partial.
        let target = SequenceIntervalV1::new(first, last.saturating_add(1)).map_err(describe)?;
        let observation = ci_coverage_observation(
            &CiCoverageBindingV1 {
                connector_instance: instance.clone(),
                producer: producer(&source.connector_principal),
                freshness: freshness(),
                proof_basis: proof_basis(),
                time_window: self.coverage_window(&received_at),
            },
            binding.provider_instance_uri().map_err(describe)?,
            &scan.window,
            target,
            &report,
            received_at,
        )
        .map_err(describe)?;
        windows
            .record_window(&CiMeasuredWindowRowV1 {
                connector_instance: instance.clone(),
                window: scan.window.clone(),
                window_id: scan.window.window_id().map_err(describe)?,
                admitted_run_count: scan.admitted_run_count(),
                failed_run_count: scan.failed_run_count(),
                source_digest: ci_scan_manifest_digest(&report.admitted_keys),
                evidence_id: observation.evidence_id,
            })
            .await
            .map_err(describe)?;
        self.observe(&observation, counters).await?;
        Ok(WorkerSourceOutcomeV1::Ok)
    }

    async fn observe(
        &self,
        observation: &crate::coverage_runtime::CoverageObservationV1,
        counters: &mut WorkerCountersV1,
    ) -> SourceResult<()> {
        match self.coverage.observe(observation).await.map_err(describe)? {
            CoverageObservationOutcome::Recorded { .. } => add(counters, "receipts", 1),
            CoverageObservationOutcome::AlreadyCovered { .. } => {}
        }
        Ok(())
    }
}

/// Fold per-source reports into one step report.
fn step_report(
    sources: Vec<WorkerSourceReportV1>,
    errors: Vec<String>,
    keys: &[&'static str],
) -> WorkerStepReportV1 {
    let mut counters = zeroed(keys);
    for source in &sources {
        for (key, value) in &source.counters {
            add(&mut counters, key, *value);
        }
    }
    let failed = sources
        .iter()
        .filter(|source| source.outcome == WorkerSourceOutcomeV1::Failed)
        .count();
    counters.insert("sources", count(sources.len()));
    counters.insert("sources_failed", count(failed));
    let mut reasons = errors;
    if failed > 0 {
        reasons.push(format!("{failed} of {} sources failed", sources.len()));
    }
    let (status, reason) = if !reasons.is_empty() {
        (WorkerStepStatusV1::Failed, Some(reasons.join("; ")))
    } else if sources.is_empty() {
        (
            WorkerStepStatusV1::Ok,
            Some("no sources configured".to_owned()),
        )
    } else {
        (WorkerStepStatusV1::Ok, None)
    };
    WorkerStepReportV1 {
        status,
        reason,
        counters,
        sources,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_long_error_is_cut_on_a_character_boundary() {
        let short = "the ref moved";
        assert_eq!(bounded_error(short), short);
        let long = "é".repeat(MAX_LAST_ERROR_BYTES);
        let bounded = bounded_error(&long);
        assert!(bounded.len() <= MAX_LAST_ERROR_BYTES);
        assert!(bounded.len() >= MAX_LAST_ERROR_BYTES - 1);
        assert!(long.starts_with(&bounded));
    }

    #[test]
    fn coverage_labels_are_nonzero_registry_references() {
        for label in [COVERAGE_FRESHNESS_LABEL, COVERAGE_PROOF_LABEL] {
            let reference = label_reference(label);
            assert_eq!(reference.entry_id.as_str(), label);
            assert!(reference.validate().is_ok());
            assert_ne!(reference.entry_digest, Sha256Digest::ZERO);
        }
        assert!(freshness().validate().is_ok());
        assert!(proof_basis().validate().is_ok());
    }

    fn source(outcome: WorkerSourceOutcomeV1, appended: u64) -> WorkerSourceReportV1 {
        let mut counters = zeroed(&GIT_COUNTERS);
        counters.insert("appended", appended);
        WorkerSourceReportV1 {
            connector_instance: "connector.git.main".into(),
            kind: WorkerSourceKindV1::Git,
            source: "repo refs/heads/main".into(),
            outcome,
            error: None,
            counters,
        }
    }

    #[test]
    fn a_step_fails_when_any_source_fails_and_sums_counters() {
        let report = step_report(
            vec![
                source(WorkerSourceOutcomeV1::Ok, 3),
                source(WorkerSourceOutcomeV1::Unchanged, 0),
            ],
            Vec::new(),
            &GIT_COUNTERS,
        );
        assert_eq!(report.status, WorkerStepStatusV1::Ok);
        assert_eq!(report.counters["appended"], 3);
        assert_eq!(report.counters["sources"], 2);

        let report = step_report(
            vec![
                source(WorkerSourceOutcomeV1::Ok, 3),
                source(WorkerSourceOutcomeV1::Failed, 1),
            ],
            Vec::new(),
            &GIT_COUNTERS,
        );
        assert_eq!(report.status, WorkerStepStatusV1::Failed);
        assert_eq!(report.counters["appended"], 4);
        assert_eq!(report.counters["sources_failed"], 1);

        let report = step_report(Vec::new(), vec!["dir".into()], &GIT_COUNTERS);
        assert_eq!(report.status, WorkerStepStatusV1::Failed);
        let report = step_report(Vec::new(), Vec::new(), &GIT_COUNTERS);
        assert_eq!(report.status, WorkerStepStatusV1::Ok);
        assert_eq!(report.counters["appended"], 0);
    }
}
