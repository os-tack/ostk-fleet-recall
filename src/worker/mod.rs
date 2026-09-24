//! The memory worker: every Stage-5 connector and projector for one scope, one
//! tick at a time (ADR 0006).
//!
//! [`MemoryWorker::run_tick`] is the single entry point. Each tick runs the
//! selected steps in a fixed order:
//!
//! ```text
//! transcript -> git -> ci          ingest: provider material -> accepted events
//!   -> bodies -> lexical -> dense  project: accepted events -> recall tiers
//! ```
//!
//! `ostk-fleet-recall worker --once` runs one tick as a process through
//! [`run_command`], which reads the inputs the selected steps need, checks the
//! login's privileges, and prints the tick's [`WorkerTickReportV1`] as one
//! JSON line. There is no long-running loop; a deployment schedules the
//! command.
//!
//! # Authority
//!
//! Every tick that ingests verifies the writer authority afresh
//! ([`WriterAuthorityRuntime::verify`]) and binds each connector schema from
//! that tick's active package; nothing from an earlier tick is reused (D4).
//! Every append then re-reads the head inside its own serializable
//! transaction, so a head that moves during the tick aborts the append rather
//! than being trusted. Server time comes from `statement_timestamp()`, never
//! the worker host's clock.
//!
//! # Coverage domains and status rows
//!
//! Each configured source is its own connector instance, and each instance's
//! newest coverage cursor means something:
//!
//! * **git** observes its ref only when the ref's target differs from the
//!   revision of the instance's latest receipt; a recorded observation covers
//!   `[1, 2)` of a domain whose target is `[1, 2)`, so it is complete.
//! * **transcript** drains one file's pending turns under a domain whose target
//!   is `[lowest pending ordinal, next ordinal)`. A tick that stages new turns
//!   opens a new domain, so the latest cursor says the latest drained slice is
//!   complete, not that the whole file is; older slices keep their own cursors.
//! * **ci** reads from the run after the highest measured window up to the
//!   provider's settled high-water mark, and the domain's target is that run
//!   range.
//!
//! After every attempt the worker upserts the source's row in
//! `memory_worker_sources_v1` (migration 0030): the outcome (`ok`,
//! `unchanged`, or `failed` with a bounded error), when it was attempted, and,
//! for `ok` or `unchanged`, when it was last checked. A source that fails on
//! every tick therefore still reports, which is what lets evidence recall tell
//! "failed" and "stale" apart from "current and complete". When all three
//! ingest steps run and every configured source was enumerated, rows for
//! instances no longer configured are marked `retired`.
//!
//! # Failure isolation
//!
//! A failure is recorded and the tick continues: one source's failure never
//! stops another source, and one step's failure never stops a later step.
//! Every step and source outcome is in the [`WorkerTickReportV1`]; a step with
//! a failed source is `failed`.
//!
//! # What the body plane receives
//!
//! The body projector consumes every `evidence.accepted` event in the scope,
//! not only this worker's. Observer-run records (`ostk-observer-run`,
//! `ostk-spec`) are such events with version-form resources, so they become
//! bodies too, indexed lexically over their raw bytes; recall exposes their
//! media type (`application.ostk-observer-run-record-v1`) so a reader can tell
//! them apart. `memory.claim.accepted` events are not evidence events and never
//! reach the body plane.
//!
//! # Coverage references are labels
//!
//! Receipts name the freshness rule [`COVERAGE_FRESHNESS_LABEL`] and the proof
//! method [`COVERAGE_PROOF_LABEL`]. They are compile-time labels, not entries
//! of the active package: no package registers them yet, and the coverage
//! runtime does not resolve them.

mod command;
mod ingest;
mod privileges;
mod project;
mod sources;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::body_store::{
    CockroachBodyProjectionRepository, GovernedContentResolver, reference_parser_key_v1,
};
use crate::connectors::ci::{
    CiRunProvider, CiScanResult, GhCliRunProvider, SETTLED_HIGH_WATER_LISTING_LIMIT,
};
use crate::context::FleetScope;
use crate::error::{FleetError, Result};
use crate::evidence_ledger::ContentKeyEncryptionKey;
use crate::memory_contracts::common::CanonicalTimestamp;
use crate::memory_contracts::digest::Sha256Digest;
use crate::projectors::EmbeddingProvider;
use crate::registry_witness::WriterAuthorityRuntime;
use crate::store::cockroach::RetryPolicy;

pub use command::{WorkerCommandV1, WorkerProcessV1, run_command};
pub use ingest::{COVERAGE_FRESHNESS_LABEL, COVERAGE_PROOF_LABEL, TRANSCRIPT_DRAIN_LIMIT};
pub use privileges::{RUNTIME_GRANTS_POLICY, probe_worker_privileges};
pub use sources::{
    CiSourceV1, DEFAULT_COVERAGE_SINCE, DEFAULT_GIT_MAX_COMMITS, DEFAULT_GIT_MAX_FACTS,
    DEFAULT_STALE_AFTER_SECONDS, DEFAULT_TRANSCRIPT_INSTANCE_PREFIX,
    DEFAULT_TRANSCRIPT_WINDOW_BYTES, GitSourceV1, MAX_STALE_AFTER_SECONDS, MIN_STALE_AFTER_SECONDS,
    ObserverSourceV1, TranscriptSourceGroupV1, WORKER_SOURCES_SCHEMA_VERSION, WorkerSourcesV1,
    transcript_instance_id,
};

/// Lexical projection batch size.
const LEXICAL_BATCH: u32 = 256;

/// Dense projection batch size: one provider call per body, so smaller.
const DENSE_BATCH: u32 = 64;

/// One step of a tick, in execution order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerStepV1 {
    Transcript,
    Git,
    Ci,
    Bodies,
    Lexical,
    Dense,
}

impl WorkerStepV1 {
    /// Every step, in execution order.
    pub const ALL: [Self; 6] = [
        Self::Transcript,
        Self::Git,
        Self::Ci,
        Self::Bodies,
        Self::Lexical,
        Self::Dense,
    ];

    /// The ingest steps, which append accepted evidence.
    pub const INGEST: [Self; 3] = [Self::Transcript, Self::Git, Self::Ci];

    /// Whether this step appends accepted evidence.
    #[must_use]
    pub const fn is_ingest(self) -> bool {
        matches!(self, Self::Transcript | Self::Git | Self::Ci)
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Transcript => "transcript",
            Self::Git => "git",
            Self::Ci => "ci",
            Self::Bodies => "bodies",
            Self::Lexical => "lexical",
            Self::Dense => "dense",
        }
    }
}

/// Parse a `--steps` value: a comma-separated list of step groups.
///
/// The groups are `all`; `ingest` (transcript, git, ci); `project` (bodies,
/// lexical); and `embed` (dense). Single steps are not selectable: a group is
/// the smallest unit whose inputs and outputs line up.
///
/// # Errors
///
/// [`FleetError::Configuration`] for an empty list or an unknown group.
pub fn parse_steps(value: &str) -> Result<BTreeSet<WorkerStepV1>> {
    let mut steps = BTreeSet::new();
    for group in value.split(',').map(str::trim) {
        match group {
            "all" => steps.extend(WorkerStepV1::ALL),
            "ingest" => steps.extend(WorkerStepV1::INGEST),
            "project" => steps.extend([WorkerStepV1::Bodies, WorkerStepV1::Lexical]),
            "embed" => {
                steps.insert(WorkerStepV1::Dense);
            }
            other => {
                return Err(FleetError::Configuration(format!(
                    "unknown worker step group {other:?}; use a comma-separated list of \
                     all, ingest, project, and embed"
                )));
            }
        }
    }
    Ok(steps)
}

/// Whether a step ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerStepStatusV1 {
    Ok,
    Skipped,
    Failed,
}

/// Which connector a source belongs to. The wire value is the status row's
/// `source_kind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerSourceKindV1 {
    Git,
    Transcript,
    Ci,
}

impl WorkerSourceKindV1 {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Git => "git",
            Self::Transcript => "transcript",
            Self::Ci => "ci",
        }
    }
}

/// What one tick did with one source. The wire value is the status row's
/// `last_outcome`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerSourceOutcomeV1 {
    /// New provider material was admitted, or pending material drained.
    Ok,
    /// The source was checked and had nothing new.
    Unchanged,
    /// The source could not be checked; `error` says why.
    Failed,
}

impl WorkerSourceOutcomeV1 {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Unchanged => "unchanged",
            Self::Failed => "failed",
        }
    }
}

/// Named counters. Every counter a step or source can report is present,
/// zero included, so two reports compare field by field.
pub type WorkerCountersV1 = BTreeMap<&'static str, u64>;

/// One source's outcome in one tick.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WorkerSourceReportV1 {
    /// The source's connector instance (its coverage and status key).
    pub connector_instance: String,
    pub kind: WorkerSourceKindV1,
    /// What the source reads: a git dir and ref, a transcript file name, or a
    /// CI repository, workflow, and branch.
    pub source: String,
    pub outcome: WorkerSourceOutcomeV1,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub counters: WorkerCountersV1,
}

/// One step's outcome in one tick.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WorkerStepReportV1 {
    pub status: WorkerStepStatusV1,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub counters: WorkerCountersV1,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<WorkerSourceReportV1>,
}

impl WorkerStepReportV1 {
    fn skipped(reason: &str) -> Self {
        Self {
            status: WorkerStepStatusV1::Skipped,
            reason: Some(reason.to_owned()),
            counters: WorkerCountersV1::new(),
            sources: Vec::new(),
        }
    }

    const fn failed(reason: String) -> Self {
        Self {
            status: WorkerStepStatusV1::Failed,
            reason: Some(reason),
            counters: WorkerCountersV1::new(),
            sources: Vec::new(),
        }
    }

    const fn ok(counters: WorkerCountersV1) -> Self {
        Self {
            status: WorkerStepStatusV1::Ok,
            reason: None,
            counters,
            sources: Vec::new(),
        }
    }
}

/// The head a tick's ingest steps verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct WorkerAuthorityReportV1 {
    pub generation: u64,
    pub activation_id: Sha256Digest,
}

/// Everything one tick did: one JSON document per tick.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WorkerTickReportV1 {
    /// Server time when the tick started, or the worker host's clock when
    /// the database could not be read (every step then reports why).
    pub tick_started_at: DateTime<Utc>,
    /// The head the ingest steps ran under; `None` when no ingest step ran or
    /// the authority did not verify.
    pub authority: Option<WorkerAuthorityReportV1>,
    /// Every step, in execution order; unselected steps are `skipped`.
    pub steps: BTreeMap<WorkerStepV1, WorkerStepReportV1>,
    /// Status rows marked `retired` because their instance is no longer
    /// configured; `None` when retirement did not run (not every ingest step
    /// was selected, some source could not be enumerated, or the update
    /// failed).
    pub retired_sources: Option<u64>,
}

impl WorkerTickReportV1 {
    /// Whether any step failed.
    #[must_use]
    pub fn failed(&self) -> bool {
        self.steps
            .values()
            .any(|step| step.status == WorkerStepStatusV1::Failed)
    }

    /// One step's report.
    #[must_use]
    pub fn step(&self, step: WorkerStepV1) -> Option<&WorkerStepReportV1> {
        self.steps.get(&step)
    }

    /// The `worker --once` exit status this tick earns: 1 when any step
    /// failed, otherwise 0 (a skipped step is not a failure).
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        u8::from(self.failed())
    }
}

/// Where the CI step gets a provider for one source.
///
/// Returns the provider and the highest run number it may read now (the
/// settled high-water mark), or `None` when no run is settled yet. The call is
/// synchronous (`gh` is a subprocess), so the worker runs it on the blocking
/// pool.
pub trait CiProviderFactory: Send + Sync {
    /// # Errors
    ///
    /// Whatever the provider refuses; the source's outcome is then `failed`.
    fn provider(&self, source: &CiSourceV1) -> CiScanResult<Option<(Box<dyn CiRunProvider>, u64)>>;
}

/// The production CI provider: `gh`, with the operator's ambient credential.
///
/// The high-water mark comes from
/// [`GhCliRunProvider::discover_settled_high_water`]. The provider's listing
/// reaches [`SETTLED_HIGH_WATER_LISTING_LIMIT`] run numbers past it, because
/// runs still in flight above the mark sit at the new end of a newest-first
/// listing; a listing that is still cut short narrows the scanned window, and
/// the receipt then reports the range as partial.
#[derive(Debug, Clone, Copy, Default)]
pub struct GhCliProviderFactory;

impl CiProviderFactory for GhCliProviderFactory {
    fn provider(&self, source: &CiSourceV1) -> CiScanResult<Option<(Box<dyn CiRunProvider>, u64)>> {
        let Some(high_water) = GhCliRunProvider::discover_settled_high_water(
            &source.provider_repository,
            &source.workflow,
            &source.branch,
        )?
        else {
            return Ok(None);
        };
        let provider = GhCliRunProvider::new(
            source.provider_repository.clone(),
            high_water.saturating_add(SETTLED_HIGH_WATER_LISTING_LIMIT),
        )?;
        Ok(Some((Box::new(provider), high_water)))
    }
}

/// What a worker is built from.
pub struct WorkerDeps {
    /// A pool authenticated as the runtime writer login.
    pub pool: PgPool,
    /// The physical `(tenant_id, project)` every step reads and writes.
    pub scope: FleetScope,
    /// The writer authority; required by the ingest steps and bodies.
    pub authority: Option<WriterAuthorityRuntime>,
    pub sources: WorkerSourcesV1,
    /// The dense tier's provider; required by the dense step.
    pub embedding: Option<Arc<dyn EmbeddingProvider>>,
    pub ci_providers: Arc<dyn CiProviderFactory>,
    /// Retry policy for every serializable write (retried only on 40001).
    pub retry: RetryPolicy,
}

impl std::fmt::Debug for WorkerDeps {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WorkerDeps")
            .field("scope", &self.scope)
            .field("authority", &self.authority)
            .field("sources", &self.sources)
            .field("embedding", &self.embedding.is_some())
            .finish_non_exhaustive()
    }
}

/// The memory worker for one scope. See the module documentation.
pub struct MemoryWorker {
    deps: WorkerDeps,
    steps: BTreeSet<WorkerStepV1>,
    coverage_since: CanonicalTimestamp,
    /// Borrowed by every ingest drain to seal governed content.
    drain_kek: Option<ContentKeyEncryptionKey>,
    /// Built once: the resolver owns the second key.
    bodies: Option<Arc<CockroachBodyProjectionRepository>>,
}

impl std::fmt::Debug for MemoryWorker {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MemoryWorker")
            .field("deps", &self.deps)
            .field("steps", &self.steps)
            .finish_non_exhaustive()
    }
}

impl MemoryWorker {
    /// Build a worker that runs `steps`.
    ///
    /// The content key is not `Clone`, so the caller passes two: `drain_kek`
    /// seals what the ingest steps append, and `body_kek` opens it for the body
    /// projector. A key a selected step does not need is dropped.
    ///
    /// # Errors
    ///
    /// [`FleetError::Configuration`] when no step is selected, the sources
    /// file does not validate, the writer authority is bound to a different
    /// scope, or a selected step is missing an input: the ingest steps need
    /// the writer authority and `drain_kek`, bodies needs the writer authority
    /// and `body_kek`, and dense needs an embedding provider.
    pub fn new(
        deps: WorkerDeps,
        steps: BTreeSet<WorkerStepV1>,
        drain_kek: Option<ContentKeyEncryptionKey>,
        body_kek: Option<ContentKeyEncryptionKey>,
    ) -> Result<Self> {
        if steps.is_empty() {
            return Err(FleetError::Configuration(
                "the memory worker needs at least one step".to_owned(),
            ));
        }
        deps.scope.validate()?;
        deps.sources.validate()?;
        let coverage_since = deps.sources.coverage_since_timestamp()?;
        if let Some(authority) = &deps.authority {
            let bound = authority.physical_scope();
            if bound.tenant_id != deps.scope.tenant_id || bound.project != deps.scope.project {
                return Err(FleetError::Configuration(
                    "the writer authority is bound to a different (tenant, project) than the \
                     worker"
                        .to_owned(),
                ));
            }
        }
        require_inputs(&steps, |input| match input {
            WorkerInput::Authority => deps.authority.is_some(),
            WorkerInput::DrainKey => drain_kek.is_some(),
            WorkerInput::BodyKey => body_kek.is_some(),
            WorkerInput::Embedding => deps.embedding.is_some(),
        })?;
        let ingest = steps.iter().any(|step| step.is_ingest());
        let bodies = steps.contains(&WorkerStepV1::Bodies);
        let bodies = match (bodies, &deps.authority, body_kek) {
            (true, Some(authority), Some(kek)) => {
                Some(Arc::new(CockroachBodyProjectionRepository::new(
                    deps.pool.clone(),
                    deps.scope.tenant_id,
                    deps.scope.project.clone(),
                    reference_parser_key_v1(),
                    Arc::new(GovernedContentResolver::new(
                        deps.pool.clone(),
                        deps.scope.tenant_id,
                        deps.scope.project.clone(),
                        authority.semantic_scope().clone(),
                        kek,
                    )),
                    deps.retry,
                )))
            }
            _ => None,
        };
        Ok(Self {
            drain_kek: if ingest { drain_kek } else { None },
            deps,
            steps,
            coverage_since,
            bodies,
        })
    }

    /// The steps this worker runs.
    #[must_use]
    pub const fn steps(&self) -> &BTreeSet<WorkerStepV1> {
        &self.steps
    }

    /// Run every selected step once. Never fails as a whole: every failure is
    /// in the report.
    pub async fn run_tick(&self) -> WorkerTickReportV1 {
        let tick_started_at = ingest::server_time(&self.deps.pool)
            .await
            .unwrap_or_else(|_| Utc::now());
        let mut steps = BTreeMap::new();
        for step in WorkerStepV1::ALL {
            if !self.steps.contains(&step) {
                steps.insert(step, WorkerStepReportV1::skipped("not selected"));
            }
        }
        let mut authority = None;
        let mut retired_sources = None;
        if self.steps.iter().any(|step| step.is_ingest()) {
            let outcome = ingest::run_ingest(self).await;
            authority = outcome.authority;
            retired_sources = outcome.retired_sources;
            steps.extend(outcome.steps);
        }
        if self.steps.contains(&WorkerStepV1::Bodies) {
            steps.insert(WorkerStepV1::Bodies, project::run_bodies(self).await);
        }
        if self.steps.contains(&WorkerStepV1::Lexical) {
            steps.insert(WorkerStepV1::Lexical, project::run_lexical(self).await);
        }
        if self.steps.contains(&WorkerStepV1::Dense) {
            steps.insert(WorkerStepV1::Dense, project::run_dense(self).await);
        }
        WorkerTickReportV1 {
            tick_started_at,
            authority,
            steps,
            retired_sources,
        }
    }
}

/// An input some steps cannot run without.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkerInput {
    /// The writer authority: the ingest steps append under it, and bodies
    /// resolves governed content under its semantic scope.
    Authority,
    /// The content key the ingest drains seal with.
    DrainKey,
    /// The content key the body resolver opens with.
    BodyKey,
    /// The dense tier's provider.
    Embedding,
}

impl WorkerInput {
    const ALL: [Self; 4] = [
        Self::Authority,
        Self::DrainKey,
        Self::BodyKey,
        Self::Embedding,
    ];

    fn needed_by(self, steps: &BTreeSet<WorkerStepV1>) -> bool {
        let ingest = steps.iter().any(|step| step.is_ingest());
        let bodies = steps.contains(&WorkerStepV1::Bodies);
        match self {
            Self::Authority => ingest || bodies,
            Self::DrainKey => ingest,
            Self::BodyKey => bodies,
            Self::Embedding => steps.contains(&WorkerStepV1::Dense),
        }
    }

    fn refusal(self) -> FleetError {
        let (steps, input) = match self {
            Self::Authority => (
                "the ingest and bodies steps",
                "the writer-authority pins (FLEET_RECALL_CONTRACT_TENANT_NAMESPACE, \
                 FLEET_RECALL_CONTRACT_PROJECT_NAMESPACE, FLEET_RECALL_BOOTSTRAP_RECEIPT_DIGEST)",
            ),
            Self::DrainKey => (
                "the ingest steps",
                "the content key (FLEET_RECALL_CONTENT_KEK_HEX)",
            ),
            Self::BodyKey => (
                "the bodies step",
                "the content key (FLEET_RECALL_CONTENT_KEK_HEX)",
            ),
            Self::Embedding => ("the dense step", "an embedding provider"),
        };
        FleetError::Configuration(format!("{steps} need {input}, which is not configured"))
    }
}

/// Refuse, naming the first missing input, a step set some selected step of
/// which lacks an input it needs. `present` says which inputs the caller has.
fn require_inputs(
    steps: &BTreeSet<WorkerStepV1>,
    present: impl Fn(WorkerInput) -> bool,
) -> Result<()> {
    WorkerInput::ALL
        .into_iter()
        .find(|input| input.needed_by(steps) && !present(*input))
        .map_or(Ok(()), |input| Err(input.refusal()))
}

#[cfg(test)]
mod tests {
    use sqlx::postgres::PgPoolOptions;
    use uuid::Uuid;

    use super::*;
    use crate::memory_contracts::common::ContractId;

    fn steps(names: &[WorkerStepV1]) -> BTreeSet<WorkerStepV1> {
        names.iter().copied().collect()
    }

    #[test]
    fn step_groups_expand_to_their_steps() {
        assert_eq!(
            parse_steps("all").unwrap(),
            WorkerStepV1::ALL.into_iter().collect()
        );
        assert_eq!(
            parse_steps("ingest").unwrap(),
            steps(&[
                WorkerStepV1::Transcript,
                WorkerStepV1::Git,
                WorkerStepV1::Ci
            ])
        );
        assert_eq!(
            parse_steps("project, embed").unwrap(),
            steps(&[
                WorkerStepV1::Bodies,
                WorkerStepV1::Lexical,
                WorkerStepV1::Dense
            ])
        );
        assert_eq!(
            parse_steps("ingest,project").unwrap(),
            steps(&[
                WorkerStepV1::Transcript,
                WorkerStepV1::Git,
                WorkerStepV1::Ci,
                WorkerStepV1::Bodies,
                WorkerStepV1::Lexical
            ])
        );
    }

    #[test]
    fn an_unknown_or_single_step_name_is_refused() {
        for value in ["", "git", "ingest,", "everything", "project;embed"] {
            match parse_steps(value) {
                Err(FleetError::Configuration(message)) => {
                    assert!(message.contains("all, ingest, project, and embed"));
                }
                other => panic!("{value:?} must be refused, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_report_serializes_steps_by_name_in_execution_order() {
        let mut report = WorkerTickReportV1 {
            tick_started_at: DateTime::parse_from_rfc3339("2026-09-24T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            authority: None,
            steps: BTreeMap::new(),
            retired_sources: None,
        };
        for step in WorkerStepV1::ALL.into_iter().rev() {
            report
                .steps
                .insert(step, WorkerStepReportV1::skipped("not selected"));
        }
        assert!(!report.failed());
        // The steps map serializes in execution order, so a report reads top
        // to bottom in the order the tick ran.
        let text = serde_json::to_string(&report).unwrap();
        let positions: Vec<usize> = WorkerStepV1::ALL
            .iter()
            .map(|step| text.find(&format!("\"{}\":", step.as_str())).unwrap())
            .collect();
        assert!(positions.windows(2).all(|pair| pair[0] < pair[1]), "{text}");
        report.steps.insert(
            WorkerStepV1::Git,
            WorkerStepReportV1::failed("boom".to_owned()),
        );
        assert!(report.failed());
    }

    struct NoProviders;

    impl CiProviderFactory for NoProviders {
        fn provider(
            &self,
            _source: &CiSourceV1,
        ) -> CiScanResult<Option<(Box<dyn CiRunProvider>, u64)>> {
            Ok(None)
        }
    }

    fn deps() -> WorkerDeps {
        WorkerDeps {
            pool: PgPoolOptions::new()
                .connect_lazy("postgresql://fleet_writer@127.0.0.1:1/fleet_recall")
                .expect("a lazy pool never connects at construction"),
            scope: FleetScope::new(
                Uuid::now_v7(),
                "worker-unit",
                "memory-worker",
                None,
                ostk_recall_core::PrivacyTier::T1Project,
            )
            .unwrap(),
            authority: None,
            sources: WorkerSourcesV1::from_json_slice(br#"{"schema_version": 1}"#).unwrap(),
            embedding: None,
            ci_providers: Arc::new(NoProviders),
            retry: RetryPolicy::default(),
        }
    }

    fn kek() -> ContentKeyEncryptionKey {
        ContentKeyEncryptionKey::from_hex(&"ab".repeat(32)).unwrap()
    }

    fn refusal(
        selected: &[WorkerStepV1],
        drain: Option<ContentKeyEncryptionKey>,
        body: Option<ContentKeyEncryptionKey>,
    ) -> String {
        match MemoryWorker::new(deps(), steps(selected), drain, body) {
            Err(FleetError::Configuration(message)) => message,
            Err(other) => panic!("expected a configuration refusal, got {other}"),
            Ok(_) => panic!("{selected:?} must be refused"),
        }
    }

    #[tokio::test]
    async fn a_step_without_its_inputs_is_refused() {
        assert!(refusal(&[], Some(kek()), Some(kek())).contains("at least one step"));
        for step in WorkerStepV1::INGEST {
            assert!(refusal(&[step], Some(kek()), None).contains("writer-authority pins"));
        }
        assert!(
            refusal(&[WorkerStepV1::Bodies], None, Some(kek())).contains("writer-authority pins")
        );
        assert!(refusal(&[WorkerStepV1::Dense], None, None).contains("embedding provider"));
    }

    #[tokio::test]
    async fn projection_steps_need_no_authority_or_key() {
        let worker = MemoryWorker::new(
            deps(),
            steps(&[WorkerStepV1::Lexical]),
            Some(kek()),
            Some(kek()),
        )
        .expect("the lexical step needs only the pool");
        assert_eq!(worker.steps(), &steps(&[WorkerStepV1::Lexical]));
        assert!(worker.drain_kek.is_none(), "an unneeded key is dropped");
        assert!(worker.bodies.is_none());
    }

    #[tokio::test]
    async fn an_invalid_sources_file_is_refused_at_construction() {
        let mut deps = deps();
        deps.sources.stale_after_seconds = 1;
        deps.sources.ci.push(CiSourceV1 {
            connector_principal: ContractId::new("connector.ci").unwrap(),
            connector_instance: ContractId::new("connector.ci.main").unwrap(),
            installation_id: 1,
            repository_id: ContractId::new("ci.repo").unwrap(),
            provider_repository: "owner/name".to_owned(),
            workflow: "ci.yml".to_owned(),
            branch: "main".to_owned(),
            first_run_number: 1,
            stale_after_seconds: None,
        });
        match MemoryWorker::new(deps, steps(&[WorkerStepV1::Lexical]), None, None) {
            Err(FleetError::Configuration(message)) => {
                assert!(message.contains("stale_after_seconds"));
            }
            other => panic!("an invalid sources file must be refused: {other:?}"),
        }
    }
}
