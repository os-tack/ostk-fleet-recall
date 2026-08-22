//! Unit proofs for the provider seam, run against REAL recorded `gh` output.
//!
//! Nothing here opens a socket. Every payload is the byte-exact capture in
//! `fixtures/`, and the two cases the live repository does not currently
//! exhibit — an in-flight run and a cancelled one — are produced by editing
//! those real bytes rather than by inventing a payload.

use super::*;
use crate::connectors::ci::fact::{CiOutcomeV1, CiRunStatusV1};
use crate::memory_contracts::common::ContractId;

fn repository() -> CiRepositoryIdV1 {
    CiRepositoryIdV1::from_trusted_config(ContractId::new("ci.repo.aetia").unwrap(), 4242).unwrap()
}

fn fetched_at() -> CanonicalTimestamp {
    CanonicalTimestamp::parse("2026-08-22T12:00:00.000000000Z").unwrap()
}

fn scan() -> CiScanV1 {
    scan_runs(
        &recorded_provider(),
        &recorded_request(repository()),
        &fetched_at(),
    )
    .expect("the recorded corpus must scan")
}

/// Rewrite one field of one run inside the REAL recorded listing.
fn edited_listing(run_number: u64, field: &str, value: &str) -> Vec<u8> {
    let mut items: Vec<serde_json::Value> = serde_json::from_slice(RECORDED_RUN_LIST).unwrap();
    let target = items
        .iter_mut()
        .find(|item| item["number"].as_u64() == Some(run_number))
        .expect("the recorded corpus must contain the run under test");
    target[field] = serde_json::Value::String(value.to_owned());
    serde_json::to_vec(&items).unwrap()
}

// ---------------------------------------------------------------------------
// The corpus is real, and it parses.
// ---------------------------------------------------------------------------

#[test]
fn the_recorded_corpus_reads_this_repositorys_own_ci() {
    let scan = scan();
    assert_eq!(scan.window.first_run_number, RECORDED_FIRST_RUN);
    assert_eq!(scan.window.last_run_number, RECORDED_LAST_RUN);
    assert_eq!(scan.admitted_run_count(), 8);
    assert_eq!(scan.failed_run_count(), 2, "runs 5 and 8 went red");
    assert_eq!(
        scan.runs
            .iter()
            .map(|run| run.run_number)
            .collect::<Vec<_>>(),
        (1..=8).collect::<Vec<_>>(),
        "the scan is ordered by run number"
    );
}

#[test]
fn the_first_failure_carries_the_failing_job_and_step_as_words() {
    let scan = scan();
    let failing = scan
        .runs
        .iter()
        .find(|run| run.run_number == RECORDED_FIRST_FAILING_RUN)
        .expect("run 5 is in the corpus");
    assert!(failing.failed());
    let docs = failing
        .failed_jobs()
        .next()
        .expect("run 5 failed in exactly one job");
    assert_eq!(docs.name.as_str(), "docs");
    // The step whose failure is the actual answer to "why did CI go red?".
    assert!(
        docs.steps
            .iter()
            .any(|step| step.name.as_str() == "Validate Mermaid diagrams"
                && step.conclusion == CiOutcomeV1::Failure),
        "the failing step name must survive as searchable words"
    );
    // And the provider's own failure annotation came through as prose.
    assert!(
        docs.failure_annotations
            .iter()
            .any(|line| line.as_str().contains("exit code 1")),
        "a failure annotation must be readable text: {:?}",
        docs.failure_annotations
    );
}

#[test]
fn only_failure_level_annotations_are_carried() {
    let scan = scan();
    let failing = scan
        .runs
        .iter()
        .find(|run| run.run_number == RECORDED_FIRST_FAILING_RUN)
        .unwrap();
    let docs = failing.failed_jobs().next().unwrap();
    // The real payload also carries a Node.js deprecation WARNING. Keeping it
    // would bury the one line that says why the job failed.
    assert!(
        !docs
            .failure_annotations
            .iter()
            .any(|line| line.as_str().contains("Node.js 20 is deprecated")),
        "a warning is not evidence about why the job failed"
    );
}

#[test]
fn a_successful_job_costs_no_annotation_round_trip() {
    let scan = scan();
    for run in &scan.runs {
        for job in &run.jobs {
            if !job.failed() {
                assert!(
                    job.failure_annotations.is_empty(),
                    "{} carries annotations it never fetched",
                    job.name.as_str()
                );
            }
        }
    }
    // Proof the round trip really is skipped: the recorded provider holds
    // annotations for exactly the two jobs that failed, and a scan that asked
    // for any other job's annotations would have failed closed above.
    assert_eq!(RECORDED_ANNOTATION_PAYLOADS.len(), 2);
}

#[test]
fn a_rescan_of_the_same_recorded_window_is_byte_identical() {
    assert_eq!(scan(), scan(), "REPLAY-01");
}

#[test]
fn the_clocks_are_three_distinct_values() {
    let scan = scan();
    let run = &scan.runs[0];
    assert_ne!(run.run_started_at, run.settled_at);
    assert!(
        run.settled_at < scan.window.fetched_at,
        "occurred <= observed"
    );
}

// ---------------------------------------------------------------------------
// Fail-closed paths.
// ---------------------------------------------------------------------------

#[test]
fn an_in_flight_run_fails_the_whole_scan_closed() {
    // The exact shape a real in-flight run has: `status` moves off
    // `completed` and `conclusion` becomes the empty string.
    let mut items: Vec<serde_json::Value> = serde_json::from_slice(RECORDED_RUN_LIST).unwrap();
    let target = items
        .iter_mut()
        .find(|item| item["number"].as_u64() == Some(8))
        .unwrap();
    target["status"] = serde_json::Value::String("in_progress".to_owned());
    target["conclusion"] = serde_json::Value::String(String::new());
    let listing = serde_json::to_vec(&items).unwrap();

    let provider = recorded_provider().with_runs(&listing);
    let error = scan_runs(&provider, &recorded_request(repository()), &fetched_at())
        .expect_err("a window containing an unsettled run is not a window");
    assert!(
        matches!(
            error,
            CiScanError::Fact(crate::connectors::ci::CiFactError::UnsettledRun {
                run_number: 8,
                ..
            })
        ),
        "unexpected error: {error}"
    );
}

#[test]
fn a_cancelled_run_fails_the_whole_scan_closed() {
    let listing = edited_listing(8, "conclusion", "cancelled");
    let provider = recorded_provider().with_runs(&listing);
    let error = scan_runs(&provider, &recorded_request(repository()), &fetched_at())
        .expect_err("a cancelled run reports no settled outcome");
    assert!(
        matches!(
            error,
            CiScanError::Fact(crate::connectors::ci::CiFactError::UnsettledRun {
                run_number: 8,
                ..
            })
        ),
        "unexpected error: {error}"
    );
}

#[test]
fn an_unmodelled_conclusion_is_refused_rather_than_mapped() {
    let listing = edited_listing(8, "conclusion", "mostly_fine");
    let provider = recorded_provider().with_runs(&listing);
    let error = scan_runs(&provider, &recorded_request(repository()), &fetched_at())
        .expect_err("an unknown conclusion must not be coerced");
    assert!(matches!(
        error,
        CiScanError::Fact(crate::connectors::ci::CiFactError::Conclusion(_))
    ));
}

#[test]
fn a_hostile_provider_coordinate_never_reaches_argv() {
    for hostile in [
        "--repo=evil",
        "os-tack/ostk-fleet-recall; rm -rf /",
        "os-tack",
        "os-tack/a/b",
        "",
    ] {
        let mut request = recorded_request(repository());
        request.provider_repository = hostile.to_owned();
        assert!(
            request.validate().is_err(),
            "{hostile:?} must be refused before any command is built"
        );
        assert!(GhCliRunProvider::new(hostile, 8).is_err());
    }
    for hostile in ["--json", "../../etc/passwd", "refs/heads/main\nrm"] {
        let mut request = recorded_request(repository());
        request.branch = hostile.to_owned();
        assert!(request.validate().is_err(), "{hostile:?} must be refused");
    }
}

#[test]
fn an_empty_or_inverted_window_is_refused() {
    let mut request = recorded_request(repository());
    request.first_run_number = 0;
    assert!(matches!(request.validate(), Err(CiScanError::EmptyWindow)));

    let mut inverted = recorded_request(repository());
    inverted.first_run_number = 8;
    inverted.last_run_number = 1;
    assert!(matches!(inverted.validate(), Err(CiScanError::EmptyWindow)));
}

#[test]
fn a_window_wider_than_the_scan_bound_is_refused() {
    let mut request = recorded_request(repository());
    request.last_run_number = u64::try_from(MAX_CI_WINDOW_RUNS).unwrap() + 2;
    assert!(matches!(
        request.validate(),
        Err(CiScanError::ScanTooLarge(_))
    ));
}

#[test]
fn a_narrower_window_reads_only_what_it_asked_for() {
    let mut request = recorded_request(repository());
    request.first_run_number = 6;
    let scan = scan_runs(&recorded_provider(), &request, &fetched_at()).unwrap();
    assert_eq!(scan.window.first_run_number, 6);
    assert_eq!(
        scan.runs
            .iter()
            .map(|run| run.run_number)
            .collect::<Vec<_>>(),
        vec![6, 7, 8],
        "runs below the window are not read, so nothing may be claimed about them"
    );
    assert!(!scan.window.starts_at_origin());
}

#[test]
fn a_missing_recorded_job_payload_fails_closed() {
    let provider = RecordedRunProvider::new(RECORDED_RUN_LIST);
    let error = scan_runs(&provider, &recorded_request(repository()), &fetched_at())
        .expect_err("a run with no job payload cannot be rendered");
    assert!(matches!(error, CiScanError::RecordedRunMissing(_)));
}

#[test]
fn an_unparseable_listing_fails_closed() {
    let provider = recorded_provider().with_runs(b"{\"not\":\"an array\"}");
    let error = scan_runs(&provider, &recorded_request(repository()), &fetched_at())
        .expect_err("a payload this reader cannot parse is never guessed at");
    assert!(matches!(error, CiScanError::Payload { .. }));
}

#[test]
fn every_recorded_job_step_carries_a_modelled_status() {
    // A real payload contains skipped jobs and steps with `0001-01-01`
    // timestamps; this asserts the reader handles them rather than assuming
    // every unit ran.
    let scan = scan();
    let modelled = scan
        .runs
        .iter()
        .flat_map(|run| run.jobs.iter())
        .all(|job| job.status == CiRunStatusV1::Completed);
    assert!(modelled, "every job in a settled run has completed");
}
