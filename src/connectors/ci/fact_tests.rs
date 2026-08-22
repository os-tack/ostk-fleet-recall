//! Unit proofs for the CI provider-truth model and its bounded epistemics.
//!
//! Every rejection path this connector has is an ordinary negative test here:
//! an unsettled run, a cancelled run, a payload that declares its own scope, a
//! clock that runs backwards, a window that names run zero, and — the one the
//! whole item exists for — a question whose answer lies outside what was
//! measured.

use super::*;
use crate::memory_contracts::canonical::encode_canonical;

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

fn job(name: &str, conclusion: CiOutcomeV1) -> CiJobV1 {
    CiJobV1 {
        job_id: CanonicalDecimal::parse("94584609140").unwrap(),
        name: text(name),
        status: CiRunStatusV1::Completed,
        conclusion,
        started_at: stamp("2026-08-13T20:30:06.000000000Z"),
        completed_at: stamp("2026-08-13T20:31:06.000000000Z"),
        steps: vec![CiStepV1 {
            number: 3,
            name: text("Validate Mermaid diagrams"),
            status: CiRunStatusV1::Completed,
            conclusion,
        }],
        failure_annotations: if conclusion.is_failure() {
            vec![text(".github Process completed with exit code 1.")]
        } else {
            Vec::new()
        },
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
        jobs: vec![job("docs", conclusion)],
    }
}

// ---------------------------------------------------------------------------
// Text: word-searchable bodies, one spelling per value.
// ---------------------------------------------------------------------------

#[test]
fn rendered_text_is_the_words_a_reader_searches_for() {
    // The exact provider job name and step name this repository's first CI
    // failure carried. Neither is hexed, neither is escaped: the body a reader
    // searches is the words themselves.
    assert_eq!(text("docs").as_str(), "docs");
    assert_eq!(
        text("Validate Mermaid diagrams").as_str(),
        "Validate Mermaid diagrams"
    );
}

#[test]
fn render_folds_scalars_the_canonical_profile_refuses() {
    // A real annotation message carries newlines and tabs; the canonical JSON
    // profile refuses both, so they are folded rather than making the whole
    // fact unrepresentable.
    let rendered = text("Process completed\nwith exit\tcode 1.");
    assert_eq!(rendered.as_str(), "Process completed with exit code 1.");
    // And the folded value really does survive canonical encoding, which is
    // the property the folding exists for.
    encode_canonical(&rendered).expect("a rendered string must be canonically encodable");
}

#[test]
fn render_refuses_text_that_renders_to_nothing() {
    assert!(matches!(
        CiTextV1::render("\u{0}\u{9}  "),
        Err(CiFactError::Text(_))
    ));
}

#[test]
fn parse_refuses_a_spelling_render_would_have_changed() {
    // `parse` is the wire decoder. Accepting "  docs  " here would give one
    // value two admissible spellings, and two spellings of one job name are
    // two different bodies with two different content addresses.
    assert!(matches!(
        CiTextV1::parse("  docs  "),
        Err(CiFactError::Text(_))
    ));
    assert!(CiTextV1::parse("docs").is_ok());
}

#[test]
fn a_commit_sha_must_be_forty_lowercase_hex_characters() {
    assert!(CiCommitShaV1::parse("bf34dc1f48624221839c5b7b4ab8dfcd00bed73a").is_ok());
    assert!(CiCommitShaV1::parse("BF34DC1F48624221839C5B7B4AB8DFCD00BED73A").is_err());
    assert!(CiCommitShaV1::parse("bf34dc1").is_err());
}

// ---------------------------------------------------------------------------
// Settledness: the Version-form precondition.
// ---------------------------------------------------------------------------

#[test]
fn an_absent_conclusion_is_not_an_outcome() {
    // The provider spells an absent conclusion as the empty string. Mapping it
    // onto `neutral` would turn "has not concluded" into "concluded
    // neutrally".
    assert!(matches!(
        CiOutcomeV1::parse(""),
        Err(CiFactError::Conclusion(_))
    ));
    assert!(matches!(
        CiOutcomeV1::parse("in_flight"),
        Err(CiFactError::Conclusion(_))
    ));
}

#[test]
fn cancellation_does_not_settle_a_run() {
    assert!(!CiOutcomeV1::Cancelled.settles_a_run());
    assert!(!CiOutcomeV1::Cancelled.is_failure());
    for settled in [
        CiOutcomeV1::Success,
        CiOutcomeV1::Failure,
        CiOutcomeV1::TimedOut,
        CiOutcomeV1::ActionRequired,
        CiOutcomeV1::Neutral,
        CiOutcomeV1::Skipped,
        CiOutcomeV1::StartupFailure,
    ] {
        assert!(settled.settles_a_run(), "{settled:?} must settle a run");
    }
}

#[test]
fn an_in_progress_run_is_refused_with_a_typed_error() {
    let mut in_flight = run(5, CiOutcomeV1::Failure);
    in_flight.status = CiRunStatusV1::InProgress;
    let error = in_flight
        .validate()
        .expect_err("an in-flight run is not immutable");
    assert!(
        matches!(error, CiFactError::UnsettledRun { run_number: 5, .. }),
        "unexpected error: {error}"
    );
    // And no identity is derivable from it either: `canonical_payload`
    // validates first, so an unsettled run cannot reach the ledger by a side
    // door that skips `validate`.
    assert!(
        CiFactV1::WorkflowRun(in_flight)
            .canonical_payload()
            .is_err()
    );
}

#[test]
fn a_queued_run_is_refused_with_a_typed_error() {
    let mut queued = run(6, CiOutcomeV1::Success);
    queued.status = CiRunStatusV1::Queued;
    assert!(matches!(
        queued.validate(),
        Err(CiFactError::UnsettledRun { run_number: 6, .. })
    ));
}

#[test]
fn a_cancelled_run_is_refused_with_a_typed_error() {
    let cancelled = run(7, CiOutcomeV1::Cancelled);
    assert!(matches!(
        cancelled.validate(),
        Err(CiFactError::UnsettledRun { run_number: 7, .. })
    ));
}

#[test]
fn a_run_that_settled_before_it_started_is_refused() {
    let mut backwards = run(5, CiOutcomeV1::Failure);
    backwards.settled_at = stamp("2026-08-13T20:00:00.000000000Z");
    assert!(matches!(
        backwards.validate(),
        Err(CiFactError::Schema("invalid ci workflow run fact"))
    ));
}

// ---------------------------------------------------------------------------
// Identity: one object, many attempts.
// ---------------------------------------------------------------------------

#[test]
fn a_rerun_is_a_new_revision_of_the_same_object() {
    let first = CiFactV1::WorkflowRun(run(5, CiOutcomeV1::Failure));
    let mut second_attempt = run(5, CiOutcomeV1::Success);
    second_attempt.run_attempt = 2;
    second_attempt.settled_at = stamp("2026-08-13T21:00:00.000000000Z");
    let second = CiFactV1::WorkflowRun(second_attempt);

    assert_eq!(
        first.provider_object_id().unwrap(),
        second.provider_object_id().unwrap(),
        "a re-run is the same provider object"
    );
    assert_ne!(
        first.immutable_revision().unwrap(),
        second.immutable_revision().unwrap(),
        "a re-run is a NEW immutable revision, not a rewrite of the old one"
    );
    assert_ne!(
        first.logical_event_key().unwrap(),
        second.logical_event_key().unwrap()
    );
}

#[test]
fn two_runs_of_the_same_workflow_are_different_objects() {
    let five = CiFactV1::WorkflowRun(run(5, CiOutcomeV1::Failure));
    let six = CiFactV1::WorkflowRun(run(6, CiOutcomeV1::Success));
    assert_ne!(
        five.provider_object_id().unwrap(),
        six.provider_object_id().unwrap()
    );
}

#[test]
fn a_rescan_reproduces_byte_identical_facts() {
    let once = CiFactV1::WorkflowRun(run(5, CiOutcomeV1::Failure));
    let twice = CiFactV1::WorkflowRun(run(5, CiOutcomeV1::Failure));
    assert_eq!(
        once.canonical_payload().unwrap(),
        twice.canonical_payload().unwrap(),
        "REPLAY-01: a re-scan must be an exact replay, not a second event"
    );
}

#[test]
fn the_occurrence_clock_is_the_settle_instant_not_the_start() {
    let fact = CiFactV1::WorkflowRun(run(5, CiOutcomeV1::Failure));
    assert_eq!(
        fact.occurred_at().as_str(),
        "2026-08-13T20:45:00.000000000Z",
        "the failure became a fact when the provider settled it"
    );
}

// ---------------------------------------------------------------------------
// EVID-04: a payload cannot declare its own scope.
// ---------------------------------------------------------------------------

#[test]
fn a_payload_that_declares_its_own_scope_is_refused() {
    let fact = CiFactV1::WorkflowRun(run(5, CiOutcomeV1::Failure));
    let canonical = fact.canonical_payload().unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&canonical).unwrap();
    value.as_object_mut().unwrap().insert(
        "scope".to_owned(),
        serde_json::json!({"tenant_id": "attacker", "project_namespace": "attacker"}),
    );
    let forged = serde_json::to_vec(&value).unwrap();
    // `deny_unknown_fields` refuses it structurally: there is no scope field on
    // any CI fact to populate, so scope can only ever come from the witness.
    let decoded: Result<CiFactV1, _> = serde_json::from_slice(&forged);
    assert!(
        decoded.is_err(),
        "a CI fact must have no scope field for a payload to declare"
    );
    // The unmodified bytes still decode, so the refusal is about the injected
    // key and not about the encoding.
    serde_json::from_slice::<CiFactV1>(&canonical).expect("the real fact must decode");
}

// ---------------------------------------------------------------------------
// Windows: what was measured, exactly.
// ---------------------------------------------------------------------------

#[test]
fn a_window_naming_run_zero_is_refused() {
    assert!(window(0, 8).validate().is_err());
}

#[test]
fn an_inverted_window_is_refused() {
    assert!(window(8, 5).validate().is_err());
}

#[test]
fn a_window_wider_than_the_scan_bound_is_refused() {
    let too_wide = window(1, u64::try_from(MAX_CI_WINDOW_RUNS).unwrap() + 1);
    assert!(too_wide.validate().is_err());
}

#[test]
fn containment_is_total_not_overlapping() {
    let measured = window(6, 8);
    assert!(measured.covers(6) && measured.covers(8));
    assert!(!measured.covers(5) && !measured.covers(9));
    assert!(measured.covers_range(6, 8));
    assert!(
        !measured.covers_range(1, 8),
        "an overlap is not containment"
    );
    assert!(!measured.covers_range(6, 9));
    assert!(!measured.starts_at_origin());
    assert!(window(1, 8).starts_at_origin());
}

#[test]
fn two_readings_of_the_same_range_are_two_measurements() {
    let first = window(1, 8);
    let mut later = window(1, 8);
    later.fetched_at = stamp("2026-08-22T13:00:00.000000000Z");
    assert_ne!(
        first.window_id().unwrap(),
        later.window_id().unwrap(),
        "the instant is part of what was measured"
    );
}

#[test]
fn the_observation_log_only_appends() {
    let mut log =
        CiWindowObservationLogV1::new(ContractId::new("connector.ci.instance-1").unwrap());
    let first = log.observe(window(1, 8), 8, 2, 16).unwrap().clone();
    assert_eq!(first.observation_seq, 1);
    assert_eq!(first.previous_range, None);

    let mut later = window(9, 12);
    later.fetched_at = stamp("2026-08-22T13:00:00.000000000Z");
    let second = log.observe(later, 4, 0, 16).unwrap().clone();
    assert_eq!(second.observation_seq, 2);
    assert_eq!(
        second.previous_range,
        Some(CiRunRangeV1 {
            first_run_number: 1,
            last_run_number: 8
        })
    );
    assert_eq!(log.observations().len(), 2);
    assert_eq!(
        log.observations()[0],
        first,
        "an earlier reading is never edited"
    );
    assert_eq!(log.view(), Some(&second));
}

#[test]
fn an_observation_clock_that_runs_backwards_is_refused() {
    let mut log =
        CiWindowObservationLogV1::new(ContractId::new("connector.ci.instance-1").unwrap());
    log.observe(window(1, 8), 8, 2, 16).unwrap();
    let mut stale = window(9, 12);
    stale.fetched_at = stamp("2026-08-22T11:00:00.000000000Z");
    assert!(matches!(
        log.observe(stale, 4, 0, 16),
        Err(CiFactError::ObservationClockRegression)
    ));
}

#[test]
fn an_observation_cannot_report_more_failures_than_runs() {
    let mut log =
        CiWindowObservationLogV1::new(ContractId::new("connector.ci.instance-1").unwrap());
    assert!(matches!(
        log.observe(window(1, 8), 3, 4, 16),
        Err(CiFactError::Schema("invalid ci window observation fact"))
    ));
}

// ---------------------------------------------------------------------------
// The epistemics. This is the item's whole point.
// ---------------------------------------------------------------------------

/// The real shape of this repository's own CI history in runs 1..8: runs 5 and
/// 8 failed, everything else passed.
fn aetia_runs() -> Vec<CiWorkflowRunFactV1> {
    (1..=8)
        .map(|number| {
            let conclusion = if number == 5 || number == 8 {
                CiOutcomeV1::Failure
            } else {
                CiOutcomeV1::Success
            };
            run(number, conclusion)
        })
        .collect()
}

#[test]
fn a_question_inside_the_window_gets_the_earliest_failure() {
    let measured = window(1, 8);
    let answer = answer_first_failure(
        &measured,
        &aetia_runs(),
        CiFailureQuestionV1::since_the_beginning(8),
    )
    .unwrap();
    match answer {
        CiFirstFailureAnswerV1::FirstFailure {
            run_number,
            conclusion,
            ..
        } => {
            assert_eq!(run_number, 5, "run 5 is where CI first went red");
            assert_eq!(conclusion, CiOutcomeV1::Failure);
        }
        other => panic!("expected the first failure, got {other:?}"),
    }
}

#[test]
fn a_question_reaching_below_the_window_is_unknown_not_a_negative() {
    // THE regression this item exists to prevent. Runs 6..8 were measured and
    // run 8 failed. Asking "when did CI FIRST fail?" reaches back to run 1,
    // which was never read — so the honest answer is UNKNOWN. Answering "run
    // 8" would be a false first, and answering "no failure" would be a false
    // negative; neither is reachable.
    let measured = window(6, 8);
    let runs: Vec<_> = aetia_runs()
        .into_iter()
        .filter(|run| measured.covers(run.run_number))
        .collect();
    let answer = answer_first_failure(
        &measured,
        &runs,
        CiFailureQuestionV1::since_the_beginning(8),
    )
    .unwrap();
    assert!(
        matches!(
            answer,
            CiFirstFailureAnswerV1::Unknown {
                reason: CiUnknownReasonV1::QuestionStartsBeforeWindow,
                ..
            }
        ),
        "expected UNKNOWN, got {answer:?}"
    );
    assert!(!answer.is_verified_negative());
    assert_eq!(
        answer.measured_window().first_run_number,
        6,
        "an unknown answer still reports exactly what WAS measured"
    );
}

#[test]
fn a_question_reaching_above_the_window_is_unknown_not_a_negative() {
    let measured = window(1, 4);
    let runs: Vec<_> = aetia_runs()
        .into_iter()
        .filter(|run| measured.covers(run.run_number))
        .collect();
    // Runs 1..4 all passed. Asking about 1..8 must NOT report "no failure":
    // run 5 is outside the window, and it is exactly the run that failed.
    let answer = answer_first_failure(
        &measured,
        &runs,
        CiFailureQuestionV1 {
            first_run_number: 1,
            last_run_number: 8,
        },
    )
    .unwrap();
    assert!(
        matches!(
            answer,
            CiFirstFailureAnswerV1::Unknown {
                reason: CiUnknownReasonV1::QuestionEndsAfterWindow,
                ..
            }
        ),
        "expected UNKNOWN, got {answer:?}"
    );
    assert!(!answer.is_verified_negative());
}

#[test]
fn a_verified_negative_is_only_reachable_inside_the_window() {
    let measured = window(1, 4);
    let runs: Vec<_> = aetia_runs()
        .into_iter()
        .filter(|run| measured.covers(run.run_number))
        .collect();
    let answer = answer_first_failure(
        &measured,
        &runs,
        CiFailureQuestionV1 {
            first_run_number: 1,
            last_run_number: 4,
        },
    )
    .unwrap();
    assert!(matches!(
        answer,
        CiFirstFailureAnswerV1::NoFailureInWindow { .. }
    ));
    assert!(answer.is_verified_negative());
}

#[test]
fn an_empty_question_range_is_unknown() {
    let answer = answer_first_failure(
        &window(1, 8),
        &aetia_runs(),
        CiFailureQuestionV1 {
            first_run_number: 8,
            last_run_number: 1,
        },
    )
    .unwrap();
    assert!(matches!(
        answer,
        CiFirstFailureAnswerV1::Unknown {
            reason: CiUnknownReasonV1::QuestionRangeIsEmpty,
            ..
        }
    ));
}

#[test]
fn a_run_outside_the_window_fails_the_answer_closed() {
    // Silently filtering the stray run would shrink the measured set without
    // shrinking the claim, so it is an error rather than a filter.
    let error = answer_first_failure(
        &window(1, 4),
        &aetia_runs(),
        CiFailureQuestionV1 {
            first_run_number: 1,
            last_run_number: 4,
        },
    )
    .expect_err("a run outside the window is a caller error");
    assert!(matches!(error, CiFactError::RunOutsideWindow { .. }));
}

#[test]
fn a_run_from_another_branch_does_not_belong_to_the_window() {
    let mut other_branch = run(2, CiOutcomeV1::Failure);
    other_branch.head_branch = text("release");
    let error = answer_first_failure(
        &window(1, 4),
        std::slice::from_ref(&other_branch),
        CiFailureQuestionV1 {
            first_run_number: 1,
            last_run_number: 4,
        },
    )
    .expect_err("a run on another branch is not in this coverage domain");
    assert!(matches!(
        error,
        CiFactError::RunOutsideWindow { run_number: 2 }
    ));
}

#[test]
fn an_unsettled_run_can_never_reach_an_answer() {
    let mut runs = aetia_runs();
    runs[4].status = CiRunStatusV1::InProgress;
    let error = answer_first_failure(
        &window(1, 8),
        &runs,
        CiFailureQuestionV1::since_the_beginning(8),
    )
    .expect_err("an unsettled run must not be answerable from");
    assert!(matches!(
        error,
        CiFactError::UnsettledRun { run_number: 5, .. }
    ));
}
