//! Operational worker observations. Report text and source identities never
//! enter telemetry; even counter names must match this module's closed list.

use std::future::Future;

use tracing::Instrument as _;

use crate::error::{FleetError, Result};
use crate::telemetry::{Outcome, add_units, start};

use super::{
    WorkerSourceOutcomeV1, WorkerStepReportV1, WorkerStepStatusV1, WorkerStepV1, WorkerTickReportV1,
};

// Report counters are typed as &'static str, but that alone is not a closed
// vocabulary. Copy the canonical label from here instead of forwarding the
// key supplied by a report or a future provider adapter.
const COUNTER_UNITS: &[&str] = &[
    "bytes_consumed",
    "turns_parsed",
    "turns_staged",
    "turns_withheld",
    "turns_redacted",
    "records_skipped",
    "records_unknown_skipped",
    "appended",
    "replayed",
    "receipts",
    "commits_walked",
    "full_walks",
    "ref_rewritten",
    "facts",
    "facts_redacted",
    "fields_withheld",
    "quarantined",
    "runs_admitted",
    "runs_failed",
    "sources",
    "sources_failed",
    "rows_read",
    "dead_lettered",
    "retried",
    "retry_exhausted",
    "held",
    "collectors_configured",
    "collectors_retired",
    "imports_recorded",
    "imports_waiting",
    "imports_failed",
    "pages",
    "rows_staged",
    "rows_already_staged",
    "items_kept",
    "items_refused",
    "items_audience_refused",
    "containers",
    "containers_complete",
    "events_projected",
    "events_unprojectable",
    "events_superseded_erased",
    "occurrences_derived",
    "shadow_generations_opened",
    "bodies_consumed",
    "rows_indexed",
    "rows_unindexable",
    "rows_reprojected",
];

pub(super) fn command_outcome(result: &Result<WorkerTickReportV1>) -> Outcome {
    match result {
        Ok(report) => tick_outcome(report),
        Err(FleetError::Configuration(_) | FleetError::InvalidScope(_)) => Outcome::Invalid,
        Err(_) => Outcome::Error,
    }
}

pub(super) fn tick_outcome(report: &WorkerTickReportV1) -> Outcome {
    if report.failed() {
        Outcome::Error
    } else {
        Outcome::Success
    }
}

pub(super) async fn step(
    step: WorkerStepV1,
    work: impl Future<Output = WorkerStepReportV1>,
) -> WorkerStepReportV1 {
    let operation = start("worker_step", step.as_str());
    let report = work.instrument(operation.span()).await;
    for_each_unit(step, &report, add_units);
    operation.finish(step_outcome(report.status));
    report
}

const fn step_outcome(status: WorkerStepStatusV1) -> Outcome {
    match status {
        WorkerStepStatusV1::Ok => Outcome::Success,
        WorkerStepStatusV1::Skipped => Outcome::Skipped,
        WorkerStepStatusV1::Failed => Outcome::Error,
    }
}

fn for_each_unit(
    step: WorkerStepV1,
    report: &WorkerStepReportV1,
    mut record: impl FnMut(&'static str, &'static str, &'static str, u64),
) {
    for (key, amount) in &report.counters {
        if let Some(unit) = COUNTER_UNITS.iter().copied().find(|unit| unit == key) {
            record("worker_step", step.as_str(), unit, *amount);
        }
    }
    for source in &report.sources {
        let outcome = match source.outcome {
            WorkerSourceOutcomeV1::Ok => "sources_ok",
            WorkerSourceOutcomeV1::Unchanged => "sources_unchanged",
            WorkerSourceOutcomeV1::Failed => "sources_failed",
        };
        record("worker_source", source.kind.as_str(), outcome, 1);
        // Source work is a separate component because ingest step counters
        // already aggregate their sources, while collected-source counters
        // describe the provider pass before the step drains the outbox.
        for (key, amount) in &source.counters {
            if let Some(unit) = COUNTER_UNITS.iter().copied().find(|unit| unit == key) {
                record("worker_source", source.kind.as_str(), unit, *amount);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::Utc;

    use super::*;
    use crate::worker::{WorkerCountersV1, WorkerSourceKindV1, WorkerSourceReportV1};

    fn tick(status: WorkerStepStatusV1) -> WorkerTickReportV1 {
        WorkerTickReportV1 {
            tick_started_at: Utc::now(),
            redaction_profile: 1,
            authority: None,
            steps: BTreeMap::from([(
                WorkerStepV1::Git,
                WorkerStepReportV1 {
                    status,
                    reason: None,
                    counters: WorkerCountersV1::new(),
                    sources: Vec::new(),
                },
            )]),
            retired_sources: None,
        }
    }

    #[test]
    fn a_returned_tick_with_failed_steps_is_an_operational_error() {
        assert!(matches!(
            command_outcome(&Ok(tick(WorkerStepStatusV1::Failed))),
            Outcome::Error
        ));
        for status in [WorkerStepStatusV1::Ok, WorkerStepStatusV1::Skipped] {
            assert!(matches!(
                command_outcome(&Ok(tick(status))),
                Outcome::Success
            ));
        }
        assert!(matches!(
            command_outcome(&Err(FleetError::Configuration("private config".into()))),
            Outcome::Invalid
        ));
        assert!(matches!(
            command_outcome(&Err(FleetError::Protocol("private output path".into()))),
            Outcome::Error
        ));
    }

    #[test]
    fn observations_keep_counts_but_cannot_carry_report_text_or_new_labels() {
        let mut report = WorkerStepReportV1::failed("secret failure details".into());
        report.counters =
            WorkerCountersV1::from([("rows_indexed", 7), ("secret new counter", 100)]);
        for outcome in [
            WorkerSourceOutcomeV1::Ok,
            WorkerSourceOutcomeV1::Unchanged,
            WorkerSourceOutcomeV1::Failed,
        ] {
            report.sources.push(WorkerSourceReportV1 {
                connector_instance: "secret instance".into(),
                kind: WorkerSourceKindV1::Git,
                source: "secret repository path".into(),
                outcome,
                error: Some("secret provider response".into()),
                counters: WorkerCountersV1::from([("appended", 2), ("secret adapter counter", 99)]),
                skipped_kinds: vec!["secret record kind".into()],
            });
        }
        let mut observations = Vec::new();
        for_each_unit(
            WorkerStepV1::Git,
            &report,
            |component, operation, unit, amount| {
                observations.push((component, operation, unit, amount));
            },
        );
        assert_eq!(
            observations,
            [
                ("worker_step", "git", "rows_indexed", 7),
                ("worker_source", "git", "sources_ok", 1),
                ("worker_source", "git", "appended", 2),
                ("worker_source", "git", "sources_unchanged", 1),
                ("worker_source", "git", "appended", 2),
                ("worker_source", "git", "sources_failed", 1),
                ("worker_source", "git", "appended", 2),
            ]
        );
        assert!(!format!("{observations:?}").contains("secret"));
    }

    #[tokio::test]
    async fn observing_a_step_preserves_its_original_report() {
        let report = WorkerStepReportV1::failed("private failure detail".into());
        let observed = step(WorkerStepV1::Dense, async { report.clone() }).await;
        assert_eq!(observed, report);
        assert!(matches!(step_outcome(observed.status), Outcome::Error));
        assert!(matches!(
            step_outcome(WorkerStepStatusV1::Skipped),
            Outcome::Skipped
        ));
    }
}
