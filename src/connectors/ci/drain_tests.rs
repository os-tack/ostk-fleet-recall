//! Unit proofs for the drain's pure parts: the fact batch a scan becomes, the
//! manifest a receipt may report, the resume cursor, and the two refusals that
//! keep a coverage receipt from outrunning the ledger.

use super::*;
use crate::connectors::ci::fact::{
    CI_FACT_SCHEMA_VERSION, CiCommitShaV1, CiJobV1, CiOutcomeV1, CiRepositoryIdV1, CiRunStatusV1,
    CiTextV1, CiWorkflowRunFactV1,
};
use crate::coverage_runtime::ObservedRangeV1;
use crate::memory_contracts::common::CanonicalDecimal;
use crate::memory_contracts::common::RegistryReferenceV1;
use crate::memory_contracts::coverage::{
    CoverageCompletenessV1, CoverageProofMethodV1, FreshnessStateV1, ProducerKindV1,
};

fn repository() -> CiRepositoryIdV1 {
    CiRepositoryIdV1::from_trusted_config(ContractId::new("ci.repo.aetia").unwrap(), 4242).unwrap()
}

fn stamp(value: &str) -> CanonicalTimestamp {
    CanonicalTimestamp::parse(value).unwrap()
}

fn text(value: &str) -> CiTextV1 {
    CiTextV1::render(value).unwrap()
}

fn window(first: u64, last: u64) -> CiCoverageWindowV1 {
    CiCoverageWindowV1 {
        schema_version: CI_FACT_SCHEMA_VERSION,
        repository: repository(),
        workflow: text("ci.yml"),
        branch: text("main"),
        first_run_number: first,
        last_run_number: last,
        fetched_at: stamp("2026-08-22T12:00:00.000000000Z"),
    }
}

fn run(number: u64, conclusion: CiOutcomeV1) -> CiWorkflowRunFactV1 {
    CiWorkflowRunFactV1 {
        schema_version: CI_FACT_SCHEMA_VERSION,
        repository: repository(),
        run_id: CanonicalDecimal::parse((31_741_164_100_u64 + number).to_string()).unwrap(),
        run_number: number,
        run_attempt: 1,
        workflow: text("ci.yml"),
        event: text("push"),
        head_branch: text("main"),
        head_sha: CiCommitShaV1::parse("bf34dc1f48624221839c5b7b4ab8dfcd00bed73a").unwrap(),
        display_title: text("ci add the acceptance demo"),
        status: CiRunStatusV1::Completed,
        conclusion,
        run_started_at: stamp("2026-08-13T20:30:00.000000000Z"),
        settled_at: stamp("2026-08-13T20:45:00.000000000Z"),
        jobs: vec![CiJobV1 {
            job_id: CanonicalDecimal::parse("94584609140").unwrap(),
            name: text("docs"),
            status: CiRunStatusV1::Completed,
            conclusion,
            started_at: stamp("2026-08-13T20:30:06.000000000Z"),
            completed_at: stamp("2026-08-13T20:31:06.000000000Z"),
            steps: Vec::new(),
            failure_annotations: Vec::new(),
        }],
    }
}

fn scan() -> CiScanV1 {
    CiScanV1 {
        window: window(1, 8),
        runs: (1..=8)
            .map(|number| {
                run(
                    number,
                    if number == 5 || number == 8 {
                        CiOutcomeV1::Failure
                    } else {
                        CiOutcomeV1::Success
                    },
                )
            })
            .collect(),
        narrowed_from_first_run_number: None,
    }
}

fn log() -> CiWindowObservationLogV1 {
    CiWindowObservationLogV1::new(ContractId::new("connector.ci.instance-1").unwrap())
}

fn event(seed: u8) -> AcceptedEventId {
    AcceptedEventId::from_digest(Sha256Digest::from_bytes([seed; 32]))
}

fn window_resource() -> ResourceUri {
    use std::str::FromStr as _;
    ResourceUri::from_str(&format!(
        "urn:ostk:entity:v1:provider_instance:sha256:{}",
        hex::encode([0xab_u8; 32])
    ))
    .unwrap()
}

fn coverage_binding() -> CiCoverageBindingV1 {
    CiCoverageBindingV1 {
        connector_instance: ContractId::new("connector.ci.instance-1").unwrap(),
        producer: ProducerIdentityV1 {
            schema_version: 1,
            kind: ProducerKindV1::Connector,
            producer_id: ContractId::new("connector.ci").unwrap(),
            version: 1,
        },
        freshness: CoverageFreshnessV1 {
            state: FreshnessStateV1::Current,
            freshness_rule: RegistryReferenceV1 {
                entry_id: ContractId::new("coverage.freshness.default-rule").unwrap(),
                version: 1,
                entry_digest: Sha256Digest::from_bytes([0x0c; 32]),
            },
        },
        proof_basis: CoverageProofBasisV1 {
            method: CoverageProofMethodV1::EnumeratedSnapshot,
            proof_method_registration: RegistryReferenceV1 {
                entry_id: ContractId::new("coverage.proof.enumerated-snapshot").unwrap(),
                version: 1,
                entry_digest: Sha256Digest::from_bytes([0x0d; 32]),
            },
        },
        time_window: CoverageWindowV1 {
            window_start: stamp("2026-08-13T00:00:00.000000000Z"),
            window_end: stamp("2026-08-23T00:00:00.000000000Z"),
        },
    }
}

fn observe(
    report: &CiDrainReportV1,
) -> CiDrainResult<crate::coverage_runtime::CoverageObservationV1> {
    ci_coverage_observation(
        &coverage_binding(),
        window_resource(),
        &window(1, 8),
        SequenceIntervalV1::new(1, 100).unwrap(),
        report,
        stamp("2026-08-22T12:00:00.000000000Z"),
    )
}

// ---------------------------------------------------------------------------
// The fact batch a scan becomes.
// ---------------------------------------------------------------------------

#[test]
fn the_window_observation_is_emitted_last() {
    let facts = ci_scan_facts(&scan(), &mut log(), 16).unwrap();
    assert_eq!(facts.len(), 9, "eight runs plus one window observation");
    assert!(
        facts[..8]
            .iter()
            .all(|fact| matches!(fact, CiFactV1::WorkflowRun(_)))
    );
    let CiFactV1::WindowObservation(observation) = &facts[8] else {
        panic!("the window observation must be last, so no receipt binds it early")
    };
    assert_eq!(observation.admitted_run_count, 8);
    assert_eq!(observation.failed_run_count, 2);
    assert_eq!(observation.observation_seq, 1);
}

#[test]
fn the_observation_counts_come_from_the_scan_not_the_caller() {
    let mut narrow = scan();
    narrow.window = window(6, 8);
    narrow.runs.retain(|run| run.run_number >= 6);
    let facts = ci_scan_facts(&narrow, &mut log(), 16).unwrap();
    let CiFactV1::WindowObservation(observation) = facts.last().unwrap() else {
        panic!("the last fact is the observation")
    };
    assert_eq!(observation.admitted_run_count, 3);
    assert_eq!(observation.failed_run_count, 1, "only run 8 failed in 6..8");
    assert_eq!(observation.window.first_run_number, 6);
}

// ---------------------------------------------------------------------------
// The manifest a receipt may report.
// ---------------------------------------------------------------------------

#[test]
fn the_manifest_digest_names_the_ordered_set() {
    let facts = ci_scan_facts(&scan(), &mut log(), 16).unwrap();
    let keys = ci_fact_manifest_keys(&facts).unwrap();
    let forward = ci_scan_manifest_digest(&keys);
    let mut reversed = keys.clone();
    reversed.reverse();
    assert_ne!(
        forward,
        ci_scan_manifest_digest(&reversed),
        "the manifest is ordered, so a reordering is a different observation"
    );
    assert_eq!(forward, ci_scan_manifest_digest(&keys), "and deterministic");
    assert_ne!(
        forward,
        ci_scan_manifest_digest(&keys[..keys.len() - 1]),
        "dropping a fact must change the manifest"
    );
}

#[test]
fn a_ci_manifest_and_a_git_manifest_of_the_same_keys_differ() {
    // Separate digest domains, so one connector's manifest can never be
    // presented as another's.
    let facts = ci_scan_facts(&scan(), &mut log(), 16).unwrap();
    let keys = ci_fact_manifest_keys(&facts).unwrap();
    assert_ne!(
        ci_scan_manifest_digest(&keys),
        crate::connectors::git::git_scan_manifest_digest(&keys)
    );
}

// ---------------------------------------------------------------------------
// The resume cursor.
// ---------------------------------------------------------------------------

#[test]
fn an_unmeasured_domain_resumes_at_run_one() {
    assert_eq!(ci_resume_run_number(None), 1);
}

#[test]
fn a_measured_domain_resumes_past_its_high_watermark() {
    let mut observed = ObservedRangeV1::default();
    observed
        .insert(SequenceIntervalV1::new(1, 9).unwrap())
        .unwrap();
    let cursor = CoverageCursorRowV1 {
        observed,
        target: SequenceIntervalV1::new(1, 100).unwrap(),
        observation_seq: 1,
        last_completeness: CoverageCompletenessV1::Partial,
        last_receipt_id: None,
        updated_at: chrono::Utc::now(),
    };
    assert_eq!(
        ci_resume_run_number(Some(&cursor)),
        9,
        "the high watermark is already the next unread run number"
    );
}

// ---------------------------------------------------------------------------
// COVER-03: a receipt may never outrun the ledger.
// ---------------------------------------------------------------------------

#[test]
fn a_receipt_needs_a_durable_window_observation() {
    let report = CiDrainReportV1 {
        appended: 8,
        events: vec![event(1)],
        admitted_keys: vec![HexBytes::new(vec![0x01; 32]).unwrap()],
        ..CiDrainReportV1::default()
    };
    assert!(matches!(
        observe(&report),
        Err(CiDrainError::NoWindowObservation)
    ));
}

#[test]
fn a_quarantined_window_voids_the_whole_scope() {
    // The ledger declined the statement of what was measured. Falling back to
    // an older window that survived would claim coverage of a range whose
    // defining evidence the ledger refused.
    let report = CiDrainReportV1 {
        appended: 8,
        quarantined: 1,
        quarantined_window_observations: 1,
        window_observation_event: Some(event(2)),
        events: vec![event(1)],
        admitted_keys: vec![HexBytes::new(vec![0x01; 32]).unwrap()],
        ..CiDrainReportV1::default()
    };
    assert!(matches!(
        observe(&report),
        Err(CiDrainError::WindowObservationQuarantined)
    ));
}

#[test]
fn a_receipt_reports_the_windows_own_run_range() {
    let report = CiDrainReportV1 {
        appended: 9,
        window_observation_event: Some(event(2)),
        events: vec![event(1), event(2)],
        admitted_keys: vec![
            HexBytes::new(vec![0x01; 32]).unwrap(),
            HexBytes::new(vec![0x02; 32]).unwrap(),
        ],
        ..CiDrainReportV1::default()
    };
    let observation = observe(&report).expect("a durable window anchors a receipt");
    assert_eq!(observation.evidence_id, event(2));
    assert_eq!(observation.source_count, 2, "only what the ledger kept");
    assert_eq!(
        observation.source_digest,
        ci_scan_manifest_digest(&report.admitted_keys)
    );
    // The coverage interval is half-open, so an inclusive window of 1..=8 is
    // the interval [1, 9): the epistemic window and the coverage cursor are
    // the same numbers.
    assert_eq!(observation.observed, SequenceIntervalV1::new(1, 9).unwrap());
    assert_eq!(
        observation.scope.revision.as_bytes(),
        window(1, 8).window_id().unwrap().as_bytes(),
        "the receipt is keyed to the exact window that was measured"
    );
}

#[test]
fn a_report_counts_every_verdict_the_ledger_returned() {
    let report = CiDrainReportV1 {
        appended: 5,
        replayed: 3,
        quarantined: 1,
        ..CiDrainReportV1::default()
    };
    assert_eq!(report.total(), 9);
}
