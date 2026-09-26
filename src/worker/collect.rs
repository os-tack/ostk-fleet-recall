//! The collect step: run every configured collector's pass, then drain the
//! collector outbox under this tick's head (ADR 0008 D4, D8).
//!
//! # Collectors
//!
//! For each collector in the sources file, in order, under the head the tick
//! verified:
//!
//! 1. its provider's adapter builds the pull collector, reading any
//!    credential its settings name from the worker's collector environment
//!    (the process environment unless
//!    [`MemoryWorker::with_collector_environment`] says otherwise), and
//!    `connector.collected.pull` is bound from the head (a head without it
//!    fails the source, naming `ostk-authority-install apply --target
//!    generation-3`), with the collector redactor under the head's guarantee;
//! 2. from schema 36 on, when the adapter verifies webhooks, the collector's
//!    due ingress hints are read first, at most `MAX_HINTS_PER_TICK`, and
//!    each is re-read through the adapter's object fetcher (a deletion
//!    becomes a push tombstone of an item already held) and settled in the
//!    transaction that stages what it caused, or backed off, or after eight
//!    attempts killed with a `retry_exhausted` dead letter (ADR 0008 D12); a
//!    hint writes no coverage, so the pass still runs;
//! 3. the pass runs at a pass instant read from the database, staging page by
//!    page through a [`PageStager`];
//! 4. what the pass staged or relied on is drained, and the pass is settled
//!    against the rows' states: each container is complete only when it was
//!    read to exhaustion and everything the pass holds current in it was
//!    admitted;
//! 5. the pass's `collector_observation` item is staged with the pass cursor
//!    and drained, and a reconciliation pass records its coverage receipt,
//!    bound to that item's event ([`crate::collectors::coverage`]);
//! 6. the collector's row in `memory_collector_sources_v1` is upserted
//!    (`owner = worker`, `live`): `ok` when the pass staged or admitted
//!    anything, else `unchanged`, or `failed` with its error, scrubbed of
//!    every secret shape; only a reconciliation whose receipt was recorded
//!    sets `last_checked_at`. A reconciliation's receipt window starts at the
//!    sources file's `coverage_since`, or later where the collector says it
//!    read from later (a Slack `backfill_since`).
//!
//! A collector whose provider this build has no adapter for is a failed
//! source. One collector's failure never stops the next. On a complete tick
//! (every ingest step and `collect` selected), once every configured
//! collector recorded its row, the rows the worker owns for instances no
//! longer configured are marked `retired`; rows an import or a capture owns
//! are never touched, and a narrower tick (`--steps collect`) retires
//! nothing, as the worker's own retirement.
//!
//! # The drain
//!
//! Then the step reads at most [`COLLECT_DRAIN_LIMIT`] pending parts, oldest
//! first (an import's, a capture's, a row an earlier tick held), and hands
//! each to the sink's drain, which binds `connector.collected.<mode>` from the
//! head the tick verified and appends the part with its item history, links,
//! and head move in one transaction. What the drain cannot append is in the
//! step's report: a row admission refused is dead-lettered and the drain goes
//! on; a row whose append failed is retried on a later tick; a row whose
//! channel the active package does not admit stays pending, and the step
//! fails naming the installer target that admits it.
//!
//! # Imports
//!
//! Last, the step finalizes every operator import whose plan waits for its
//! rows (`collect import --no-drain`, or an import whose inline drain left
//! rows pending): once the import's observation and every row it relies on
//! are settled, its snapshot receipt is recorded and its status row checked
//! ([`crate::collectors::import::finalize_import`]). A plan still waiting is
//! counted (`imports_waiting`); one whose observation was not admitted, or
//! that cannot be read, fails the step.
//!
//! Whether the step can run at all is decided by the schema, read at tick
//! time: before migration 34 (the collected-item tables and their
//! withdrawals) there is nothing to drain, so the step is `skipped`
//! (`schema_below_34`) when no collector is configured and adds no privilege
//! probe, and fails, naming `ostk-fleet-recall migrate`, when one is.

use crate::collectors::adapter;
use crate::collectors::binding::{CollectedConnectorBindingV1, CollectorInstanceV1};
use crate::collectors::coverage::{
    PASS_CURSOR_DOMAIN, PassCoverageV1, coverage_observations, observation_draft, pass_cursor,
};
use crate::collectors::http::scrub_diagnostic;
use crate::collectors::import::{ImportFinalizeTallyV1, finalize_pending_imports};
use crate::collectors::pull::{
    PageStager, PageStagerContextV1, PullCollectorV1, PullPassInputV1, PulledItemV1,
};
use crate::collectors::redaction::CollectorRedactorV1;
use crate::collectors::sink::{
    CollectedDrainContextV1, CollectedDrainReportV1, CollectedItemSink, OutboxRowStateV1,
    StagedItemV1,
};
use crate::collectors::status::{
    CollectorOutcomeV1, CollectorOwnerV1, CollectorSourceStatusV1, CoverageRoleV1,
};
use crate::coverage_runtime::{
    CockroachCoverageRuntimeRepository, CoverageObservationOutcome, CoverageRuntimeRepository as _,
};
use crate::evidence_ledger::ContentKeyEncryptionKey;
use crate::memory_contracts::collected_item::{CollectionModeV1, timestamp_micros};
use crate::memory_contracts::common::ContractId;
use crate::memory_contracts::evidence::AcceptedEventId;
use crate::registry_witness::{VerifiedWriterAuthority, WriterAuthorityRuntime};
use crate::store::cockroach::{
    COLLECTED_ITEMS_SCHEMA_VERSION, COLLECTOR_INGRESS_SCHEMA_VERSION, read_schema_version,
};

use super::hints::{HINT_COUNTERS, HintRunV1};
use super::ingest::{bounded_error, describe, server_instant, zeroed};
use super::sources::CollectorSourceV1;
use super::{
    MemoryWorker, WorkerCountersV1, WorkerSourceKindV1, WorkerSourceOutcomeV1,
    WorkerSourceReportV1, WorkerStepReportV1, WorkerStepStatusV1, WorkerStepV1,
};

/// Staged parts one tick drains at most, after the collectors' passes.
pub const COLLECT_DRAIN_LIMIT: u32 = 1_024;

/// Stage ids one drain of a pass's rows names at most.
const PASS_DRAIN_CHUNK: usize = 1_024;

/// Why the step did not run on an older schema.
const SCHEMA_BELOW_34: &str = "schema_below_34";

const COLLECT_COUNTERS: [&str; 9] = [
    "rows_read",
    "appended",
    "replayed",
    "quarantined",
    "dead_lettered",
    "retried",
    "retry_exhausted",
    "held",
    "collectors_configured",
];

/// What every collector source reports, beside its adapter's own counters.
const COLLECTOR_COUNTERS: [&str; 11] = [
    "pages",
    "rows_staged",
    "rows_already_staged",
    "items_kept",
    "items_refused",
    "items_audience_refused",
    "appended",
    "replayed",
    "containers",
    "containers_complete",
    "receipts",
];

/// Run the collect step.
pub(super) async fn run_collect(
    worker: &MemoryWorker,
    runtime: &WriterAuthorityRuntime,
    kek: &ContentKeyEncryptionKey,
    verified: &std::result::Result<VerifiedWriterAuthority, String>,
) -> WorkerStepReportV1 {
    let configured = worker.deps.sources.collectors.len();
    let schema = match read_schema_version(&worker.deps.pool).await {
        Ok(schema) => schema,
        Err(error) => {
            return WorkerStepReportV1::failed(format!(
                "the schema version could not be read: {error}"
            ));
        }
    };
    if schema < COLLECTED_ITEMS_SCHEMA_VERSION {
        if configured > 0 {
            return WorkerStepReportV1::failed(format!(
                "{configured} collectors are configured, but collected items need the schema \
                 through migration {COLLECTED_ITEMS_SCHEMA_VERSION} and this database has \
                 reached {schema}; run `ostk-fleet-recall migrate`, then re-apply \
                 {}",
                super::RUNTIME_GRANTS_POLICY
            ));
        }
        return WorkerStepReportV1::skipped(SCHEMA_BELOW_34);
    }
    let verified = match verified {
        Ok(verified) => verified,
        Err(error) => return WorkerStepReportV1::failed(error.clone()),
    };
    let sink = match CollectedItemSink::new(
        worker.deps.pool.clone(),
        &worker.deps.scope,
        worker.deps.retry,
    ) {
        Ok(sink) => sink,
        Err(error) => return WorkerStepReportV1::failed(error.to_string()),
    };
    let context = CollectedDrainContextV1 {
        verified,
        ledger: runtime.ledger().as_ref(),
        control_scope: runtime.control_scope(),
        kek,
    };
    let collectors = CollectorPasses {
        worker,
        sink: &sink,
        context: &context,
        verified,
        coverage: CockroachCoverageRuntimeRepository::new(
            worker.deps.pool.clone(),
            runtime.control_scope().clone(),
            worker.deps.retry,
        ),
        hints: schema >= COLLECTOR_INGRESS_SCHEMA_VERSION,
    };
    let mut total = CollectedDrainReportV1::default();
    let mut sources = Vec::with_capacity(configured);
    let mut every_row_recorded = true;
    for source in &worker.deps.sources.collectors {
        let (report, recorded) = Box::pin(collectors.run(source, &mut total)).await;
        every_row_recorded &= recorded;
        sources.push(report);
    }
    let complete_tick = WorkerStepV1::INGEST
        .iter()
        .all(|step| worker.steps.contains(step));
    let retired = if complete_tick && every_row_recorded {
        let instances: Vec<String> = worker
            .deps
            .sources
            .collectors
            .iter()
            .map(|source| source.connector_instance.as_str().to_owned())
            .collect();
        match sink.retire_worker_collectors(&instances).await {
            Ok(retired) => Some(retired),
            Err(error) => {
                tracing::warn!(%error, "retiring unconfigured collectors failed");
                None
            }
        }
    } else {
        None
    };
    // Whatever is still pending: an import's or a capture's rows, and rows an
    // earlier tick held or failed to append.
    let step = match sink.drain(&context, COLLECT_DRAIN_LIMIT).await {
        Ok(report) => {
            merge(&mut total, &report);
            step_report(&total, configured)
        }
        Err(error) => {
            WorkerStepReportV1::failed(format!("the collector outbox drain failed: {error}"))
        }
    };
    // Then the snapshot receipt of every import whose rows are now settled.
    let imports = finalize_pending_imports(&sink, verified, &collectors.coverage).await;
    with_sources(with_imports(step, imports), sources, retired)
}

/// Fold the imports the step finalized into its report: a plan that could
/// not be finalized fails the step.
fn with_imports(
    mut step: WorkerStepReportV1,
    imports: crate::error::Result<ImportFinalizeTallyV1>,
) -> WorkerStepReportV1 {
    let tally = match imports {
        Ok(tally) => tally,
        Err(error) => ImportFinalizeTallyV1 {
            failed: 1,
            errors: vec![format!(
                "the waiting import plans could not be read: {error}"
            )],
            ..ImportFinalizeTallyV1::default()
        },
    };
    step.counters.insert("imports_recorded", tally.recorded);
    step.counters.insert("imports_waiting", tally.waiting);
    step.counters.insert("imports_failed", tally.failed);
    if tally.failed > 0 {
        step.status = WorkerStepStatusV1::Failed;
        let reason = format!(
            "{} collected-item imports could not be finalized: {}",
            tally.failed,
            tally.errors.join("; ")
        );
        step.reason = Some(match step.reason.take() {
            Some(earlier) => format!("{earlier}; {reason}"),
            None => reason,
        });
    }
    step
}

/// Fold per-collector reports and the retirement into the drain's report.
fn with_sources(
    mut step: WorkerStepReportV1,
    sources: Vec<WorkerSourceReportV1>,
    retired: Option<u64>,
) -> WorkerStepReportV1 {
    let failed = sources
        .iter()
        .filter(|source| source.outcome == WorkerSourceOutcomeV1::Failed)
        .count();
    step.counters
        .insert("sources", u64::try_from(sources.len()).unwrap_or(u64::MAX));
    step.counters
        .insert("sources_failed", u64::try_from(failed).unwrap_or(u64::MAX));
    step.counters
        .insert("collectors_retired", retired.unwrap_or(0));
    if failed > 0 {
        step.status = WorkerStepStatusV1::Failed;
        let reason = format!("{failed} of {} collectors failed", sources.len());
        step.reason = Some(match step.reason.take() {
            Some(earlier) => format!("{reason}; {earlier}"),
            None => reason,
        });
    }
    step.sources = sources;
    step
}

/// Add one drain's outcomes to the step's.
pub(super) fn merge(total: &mut CollectedDrainReportV1, report: &CollectedDrainReportV1) {
    total.rows_read += report.rows_read;
    total.appended += report.appended;
    total.replayed += report.replayed;
    total.quarantined += report.quarantined;
    total.dead_lettered += report.dead_lettered;
    total.retried += report.retried;
    total.retry_exhausted += report.retry_exhausted;
    total.held += report.held;
    total
        .held_connectors
        .extend(report.held_connectors.iter().cloned());
    for error in &report.errors {
        if total.errors.len() < 8 && !total.errors.contains(error) {
            total.errors.push(error.clone());
        }
    }
}

/// What one collector's pass ended as.
struct PassEndV1 {
    outcome: CollectorOutcomeV1,
    reconciled: bool,
}

/// Everything the tick's collectors share.
struct CollectorPasses<'a> {
    worker: &'a MemoryWorker,
    sink: &'a CollectedItemSink,
    context: &'a CollectedDrainContextV1<'a>,
    verified: &'a VerifiedWriterAuthority,
    coverage: CockroachCoverageRuntimeRepository,
    /// Whether the schema has the ingress's hint queue (migration 36).
    hints: bool,
}

impl CollectorPasses<'_> {
    /// Run one collector and record its status row: its report, and whether
    /// the row was recorded.
    async fn run(
        &self,
        source: &CollectorSourceV1,
        total: &mut CollectedDrainReportV1,
    ) -> (WorkerSourceReportV1, bool) {
        let mut counters = zeroed(&COLLECTOR_COUNTERS);
        let result = Box::pin(self.pass(source, &mut counters, total)).await;
        let (outcome, reconciled, mut error) = match result {
            Ok(end) => (end.outcome, end.reconciled, None),
            Err(error) => (
                CollectorOutcomeV1::Failed,
                false,
                Some(bounded_error(&scrub_diagnostic(&error))),
            ),
        };
        let status = CollectorSourceStatusV1 {
            instance: source.connector_instance.clone(),
            provider: source.provider.clone(),
            provider_scope_id: source.provider_scope_id.clone(),
            mode: CollectionModeV1::Pull,
            coverage_role: CoverageRoleV1::Live,
            owner: CollectorOwnerV1::Worker,
            stale_after_seconds: self
                .worker
                .deps
                .sources
                .stale_after(source.stale_after_seconds),
            outcome,
            reconciled,
            error: error.clone(),
        };
        let mut outcome = match outcome {
            CollectorOutcomeV1::Ok => WorkerSourceOutcomeV1::Ok,
            CollectorOutcomeV1::Unchanged => WorkerSourceOutcomeV1::Unchanged,
            CollectorOutcomeV1::Failed => WorkerSourceOutcomeV1::Failed,
        };
        let recorded = match self.sink.record_status(&status).await {
            Ok(()) => true,
            Err(status_error) => {
                let message = format!("the collector status row was not recorded: {status_error}");
                error = Some(bounded_error(&match error {
                    Some(earlier) => format!("{earlier}; {message}"),
                    None => message,
                }));
                outcome = WorkerSourceOutcomeV1::Failed;
                false
            }
        };
        (
            WorkerSourceReportV1 {
                connector_instance: source.connector_instance.as_str().to_owned(),
                kind: WorkerSourceKindV1::Collector,
                source: format!("{} {}", source.provider, source.provider_scope_id),
                outcome,
                error,
                counters,
            },
            recorded,
        )
    }

    /// One pass: collector, pass, drain, settlement, observation, coverage.
    #[allow(clippy::too_many_lines)] // one linear bind -> pass -> drain -> observe pipeline
    async fn pass(
        &self,
        source: &CollectorSourceV1,
        counters: &mut WorkerCountersV1,
        total: &mut CollectedDrainReportV1,
    ) -> std::result::Result<PassEndV1, String> {
        let pool = &self.worker.deps.pool;
        let adapter = adapter(source.provider.as_str()).ok_or_else(|| {
            format!(
                "this build has no collector adapter for provider {}",
                source.provider
            )
        })?;
        let collector: Box<dyn PullCollectorV1> = adapter
            .pull(source, &*self.worker.collector_environment)?
            .ok_or_else(|| format!("provider {} has no pull collector", source.provider))?;
        counters.extend(collector.counter_keys().iter().map(|key| (*key, 0)));
        let instance = CollectorInstanceV1 {
            connector_instance_id: source.connector_instance.clone(),
            provider: source.provider.clone(),
            provider_scope_id: source.provider_scope_id.clone(),
        };
        let connector = CollectionModeV1::Pull.connector_schema_id();
        let active = self
            .verified
            .bind_connector(&ContractId::new(connector).map_err(describe)?)
            .map_err(|error| {
                format!(
                    "the active package does not admit {connector} ({error}); run \
                     `ostk-authority-install apply --target generation-3`"
                )
            })?;
        let redactor = CollectorRedactorV1::from_active_package(&active).map_err(describe)?;
        let scope = CollectedConnectorBindingV1::resolve(
            &active,
            CollectionModeV1::Pull,
            source.connector_principal.clone(),
            instance.clone(),
        )
        .and_then(|binding| binding.provider_instance_uri())
        .map_err(describe)?;
        let pass_seq = self
            .sink
            .read_cursor(&instance.connector_instance_id, PASS_CURSOR_DOMAIN)
            .await
            .map_err(describe)?
            .map_or(1, |cursor| cursor.pass_seq.saturating_add(1));
        let pass_instant = server_instant(pool).await?;
        let pass_order_micros = timestamp_micros(&pass_instant).map_err(describe)?;
        let stager_context = PageStagerContextV1 {
            instance: &instance,
            principal: &source.connector_principal,
            redactor: &redactor,
            policy: &source.audience,
            pass_seq,
            pass_order_micros,
        };
        let input = PullPassInputV1 {
            source,
            instance: &instance,
            pass_seq,
            pass_instant: &pass_instant,
            pass_order_micros,
        };

        // The instance's ingress hints first, so the pass sees what they
        // staged as the memory's version (ADR 0008 D12).
        let hinted = if self.hints && adapter.push().is_some() {
            counters.extend(HINT_COUNTERS.iter().map(|key| (*key, 0)));
            let fetcher = adapter.fetch_object(source, &*self.worker.collector_environment)?;
            HintRunV1 {
                sink: self.sink,
                drain: self.context,
                source,
                stager: stager_context,
                input: &input,
                fetcher: fetcher.as_deref(),
            }
            .run(counters, total)
            .await?
        } else {
            false
        };

        let mut stager = PageStager::new(self.sink, &stager_context).map_err(describe)?;
        let outcome = collector
            .pass(&input, &mut stager)
            .await
            .map_err(describe)?;
        counters.extend(outcome.counters.iter().map(|(key, value)| (*key, *value)));
        let pages = stager.stats();
        for (key, value) in [
            ("pages", pages.pages),
            ("rows_staged", pages.rows_staged),
            ("rows_already_staged", pages.rows_already_staged),
            ("items_kept", pages.items_kept),
            ("items_refused", pages.items_refused + pages.dead_letters),
            ("items_audience_refused", pages.items_audience_refused),
        ] {
            counters.insert(key, value);
        }

        // Admit what the pass staged, and what it holds current that an
        // earlier, interrupted pass left pending.
        let held = stager.stage_ids();
        let mut drained = CollectedDrainReportV1::default();
        for chunk in held.chunks(PASS_DRAIN_CHUNK) {
            let report = self
                .sink
                .drain_stage_ids(self.context, chunk)
                .await
                .map_err(describe)?;
            merge(&mut drained, &report);
        }
        merge(total, &drained);
        *counters.entry("appended").or_insert(0) += drained.appended;
        *counters.entry("replayed").or_insert(0) += drained.replayed;
        let changed = hinted || pages.rows_staged > 0 || drained.appended > 0;
        let row_states = self.sink.row_states(&held).await.map_err(describe)?;
        let settlement = stager
            .settle(&outcome.containers, &row_states)
            .map_err(describe)?;
        counters.insert(
            "containers",
            u64::try_from(settlement.containers.len()).unwrap_or(u64::MAX),
        );
        counters.insert(
            "containers_complete",
            u64::try_from(
                settlement
                    .containers
                    .iter()
                    .filter(|container| container.complete())
                    .count(),
            )
            .unwrap_or(u64::MAX),
        );

        // The pass's own observation, with the pass cursor.
        let observation = stager
            .stage_page(
                vec![PulledItemV1 {
                    draft: observation_draft(&instance, &settlement, pass_order_micros)
                        .map_err(describe)?,
                    provider_audience: Some(collector.observation_audience()),
                }],
                &[pass_cursor(&settlement, pass_seq, pass_order_micros)],
                &[],
            )
            .await
            .map_err(describe)?;
        let stage_ids = match observation.items.first() {
            Some(StagedItemV1::Staged { stage_ids, .. }) => stage_ids.clone(),
            Some(StagedItemV1::Refused { reason, diagnostic }) => {
                return Err(format!(
                    "the pass observation was refused ({}: {diagnostic}); no coverage was \
                     recorded",
                    reason.as_str()
                ));
            }
            None => return Err("the pass observation was not staged".to_owned()),
        };
        let drained = self
            .sink
            .drain_stage_ids(self.context, &stage_ids)
            .await
            .map_err(describe)?;
        merge(total, &drained);
        let observed = self.sink.row_states(&stage_ids).await.map_err(describe)?;
        let events: Option<Vec<_>> = stage_ids
            .iter()
            .map(|id| match observed.get(id) {
                Some(OutboxRowStateV1::Admitted(event)) => Some(*event),
                _ => None,
            })
            .collect();
        let Some(evidence) = events.and_then(|events| events.first().copied()) else {
            return Err(
                "the pass observation was not admitted; no coverage was recorded".to_owned(),
            );
        };

        if outcome.reconcile {
            let observations = coverage_observations(
                &PassCoverageV1 {
                    instance: &instance.connector_instance_id,
                    principal: &source.connector_principal,
                    scope,
                    // A collector that reads a window starting later than
                    // the sources file's coverage start covers only that.
                    window_start: outcome
                        .window_start
                        .clone()
                        .filter(|start| *start > self.worker.coverage_since)
                        .unwrap_or_else(|| self.worker.coverage_since.clone()),
                    observed_through: server_instant(pool).await?,
                    proof_method: collector.proof_method(),
                    evidence_id: AcceptedEventId::from_digest(evidence),
                },
                &settlement,
            )
            .map_err(describe)?;
            for observation in &observations {
                match self.coverage.observe(observation).await.map_err(describe)? {
                    CoverageObservationOutcome::Recorded { .. } => {
                        *counters.entry("receipts").or_insert(0) += 1;
                    }
                    CoverageObservationOutcome::AlreadyCovered { .. } => {}
                }
            }
        }
        Ok(PassEndV1 {
            outcome: if changed {
                CollectorOutcomeV1::Ok
            } else {
                CollectorOutcomeV1::Unchanged
            },
            reconciled: outcome.reconcile,
        })
    }
}

/// The step's report for the outbox drains.
fn step_report(report: &CollectedDrainReportV1, configured: usize) -> WorkerStepReportV1 {
    let mut counters = zeroed(&COLLECT_COUNTERS);
    for (key, value) in [
        ("rows_read", report.rows_read),
        ("appended", report.appended),
        ("replayed", report.replayed),
        ("quarantined", report.quarantined),
        ("dead_lettered", report.dead_lettered),
        ("retried", report.retried),
        ("retry_exhausted", report.retry_exhausted),
        ("held", report.held),
        (
            "collectors_configured",
            u64::try_from(configured).unwrap_or(u64::MAX),
        ),
    ] {
        counters.insert(key, value);
    }
    let mut reasons = Vec::new();
    if report.held > 0 {
        reasons.push(format!(
            "{} staged collected items stay pending: the active package does not admit {}; run \
             `ostk-authority-install apply --target generation-3`",
            report.held,
            report
                .held_connectors
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if report.retried > 0 {
        reasons.push(format!(
            "{} staged collected items failed to append and will be retried: {}",
            report.retried,
            report.errors.join("; ")
        ));
    }
    let (status, reason) = if reasons.is_empty() {
        (WorkerStepStatusV1::Ok, None)
    } else {
        (WorkerStepStatusV1::Failed, Some(reasons.join("; ")))
    };
    WorkerStepReportV1 {
        status,
        reason,
        counters,
        sources: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_clean_drain_is_ok_and_counts_every_outcome() {
        let report = CollectedDrainReportV1 {
            rows_read: 5,
            appended: 3,
            replayed: 1,
            dead_lettered: 1,
            ..CollectedDrainReportV1::default()
        };
        let step = step_report(&report, 0);
        assert_eq!(step.status, WorkerStepStatusV1::Ok);
        assert_eq!(step.reason, None);
        assert_eq!(step.counters["appended"], 3);
        assert_eq!(step.counters["dead_lettered"], 1);
        assert_eq!(step.counters["held"], 0);
        assert_eq!(step.counters.len(), COLLECT_COUNTERS.len());
    }

    #[test]
    fn held_rows_fail_the_step_and_name_the_installer_target() {
        let report = CollectedDrainReportV1 {
            rows_read: 2,
            held: 2,
            held_connectors: ["connector.collected.pull".to_owned()].into(),
            ..CollectedDrainReportV1::default()
        };
        let step = step_report(&report, 0);
        assert_eq!(step.status, WorkerStepStatusV1::Failed);
        let reason = step.reason.unwrap();
        assert!(reason.contains("--target generation-3"), "{reason}");
        assert!(reason.contains("connector.collected.pull"), "{reason}");
    }

    #[test]
    fn a_retried_row_fails_the_step_with_its_error() {
        let report = CollectedDrainReportV1 {
            rows_read: 1,
            retried: 1,
            errors: vec!["writer authority is unavailable".to_owned()],
            ..CollectedDrainReportV1::default()
        };
        let step = step_report(&report, 0);
        assert_eq!(step.status, WorkerStepStatusV1::Failed);
        assert!(step.reason.unwrap().contains("will be retried"));
    }

    fn collector(outcome: WorkerSourceOutcomeV1) -> WorkerSourceReportV1 {
        WorkerSourceReportV1 {
            connector_instance: "docs.specs".into(),
            kind: WorkerSourceKindV1::Collector,
            source: "docs specs".into(),
            outcome,
            error: (outcome == WorkerSourceOutcomeV1::Failed).then(|| "boom".to_owned()),
            counters: zeroed(&COLLECTOR_COUNTERS),
        }
    }

    #[test]
    fn a_failed_collector_fails_the_step_and_every_collector_is_listed() {
        let clean = step_report(&CollectedDrainReportV1::default(), 2);
        let step = with_sources(
            clean.clone(),
            vec![
                collector(WorkerSourceOutcomeV1::Ok),
                collector(WorkerSourceOutcomeV1::Unchanged),
            ],
            Some(1),
        );
        assert_eq!(step.status, WorkerStepStatusV1::Ok);
        assert_eq!(step.counters["collectors_configured"], 2);
        assert_eq!(step.counters["sources"], 2);
        assert_eq!(step.counters["collectors_retired"], 1);
        assert_eq!(step.sources.len(), 2);

        let step = with_sources(
            clean,
            vec![
                collector(WorkerSourceOutcomeV1::Failed),
                collector(WorkerSourceOutcomeV1::Ok),
            ],
            None,
        );
        assert_eq!(step.status, WorkerStepStatusV1::Failed);
        assert!(step.reason.unwrap().contains("1 of 2 collectors failed"));
        assert_eq!(step.counters["sources_failed"], 1);
        assert_eq!(step.counters["collectors_retired"], 0);
    }

    #[test]
    fn an_import_that_cannot_be_finalized_fails_the_step_and_waiting_ones_are_counted() {
        let clean = step_report(&CollectedDrainReportV1::default(), 0);
        let step = with_imports(
            clean.clone(),
            Ok(ImportFinalizeTallyV1 {
                recorded: 2,
                waiting: 1,
                ..ImportFinalizeTallyV1::default()
            }),
        );
        assert_eq!(step.status, WorkerStepStatusV1::Ok);
        assert_eq!(
            (
                step.counters["imports_recorded"],
                step.counters["imports_waiting"],
                step.counters["imports_failed"]
            ),
            (2, 1, 0)
        );

        let step = with_imports(
            clean,
            Ok(ImportFinalizeTallyV1 {
                failed: 1,
                errors: vec!["import import.slack: the observation was refused".to_owned()],
                ..ImportFinalizeTallyV1::default()
            }),
        );
        assert_eq!(step.status, WorkerStepStatusV1::Failed);
        assert!(step.reason.unwrap().contains("import.slack"));
    }

    #[test]
    fn drains_add_up() {
        let mut total = CollectedDrainReportV1::default();
        for _ in 0..2 {
            merge(
                &mut total,
                &CollectedDrainReportV1 {
                    rows_read: 3,
                    appended: 2,
                    retried: 1,
                    errors: vec!["same".to_owned()],
                    held_connectors: ["connector.collected.pull".to_owned()].into(),
                    ..CollectedDrainReportV1::default()
                },
            );
        }
        assert_eq!((total.rows_read, total.appended, total.retried), (6, 4, 2));
        assert_eq!(total.errors, ["same"]);
        assert_eq!(total.held_connectors.len(), 1);
    }
}
