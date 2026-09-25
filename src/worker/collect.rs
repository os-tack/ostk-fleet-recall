//! The collect step: drain the collector outbox under this tick's head
//! (ADR 0008 D4).
//!
//! Collectors stage items; this step admits what they staged. It reads at
//! most [`COLLECT_DRAIN_LIMIT`] pending parts, oldest first, and hands each to
//! the sink's drain, which binds `connector.collected.<mode>` from the head the
//! tick verified and appends the part with its item history, links, and head
//! move in one transaction. What the drain cannot append is in the step's
//! report: a row admission refused is dead-lettered and the drain goes on; a
//! row whose append failed is retried on a later tick; a row whose channel the
//! active package does not admit stays pending, and the step fails naming the
//! installer target that admits it.
//!
//! Whether the step can run at all is decided by the schema, read at tick
//! time: before migration 34 (the collected-item tables and their
//! withdrawals) there is nothing to drain, so the step is `skipped`
//! (`schema_below_34`) when no collector is configured and adds no privilege
//! probe, and fails, naming `ostk-fleet-recall migrate`, when one is.

use crate::collectors::sink::{CollectedDrainContextV1, CollectedDrainReportV1, CollectedItemSink};
use crate::evidence_ledger::ContentKeyEncryptionKey;
use crate::registry_witness::{VerifiedWriterAuthority, WriterAuthorityRuntime};
use crate::store::cockroach::{COLLECTED_ITEMS_SCHEMA_VERSION, read_schema_version};

use super::ingest::zeroed;
use super::{MemoryWorker, WorkerStepReportV1, WorkerStepStatusV1};

/// Staged parts one tick drains at most.
pub const COLLECT_DRAIN_LIMIT: u32 = 1_024;

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
    let drained = sink
        .drain(
            &CollectedDrainContextV1 {
                verified,
                ledger: runtime.ledger().as_ref(),
                control_scope: runtime.control_scope(),
                kek,
            },
            COLLECT_DRAIN_LIMIT,
        )
        .await;
    match drained {
        Ok(report) => step_report(&report, configured),
        Err(error) => {
            WorkerStepReportV1::failed(format!("the collector outbox drain failed: {error}"))
        }
    }
}

/// The step's report for one drain.
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
        (
            WorkerStepStatusV1::Ok,
            (configured > 0).then(|| {
                format!(
                    "no provider adapter in this build reads the {configured} configured \
                     collectors; the step drained what was staged"
                )
            }),
        )
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

    #[test]
    fn configured_collectors_are_noted_while_no_adapter_reads_them() {
        let step = step_report(&CollectedDrainReportV1::default(), 2);
        assert_eq!(step.status, WorkerStepStatusV1::Ok);
        assert!(step.reason.unwrap().contains("2 configured collectors"));
        assert_eq!(step.counters["collectors_configured"], 2);
    }
}
