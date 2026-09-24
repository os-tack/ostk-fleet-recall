use super::super::testbed::{
    acknowledge_event, digest, dismiss_event, envelope, resolve_event, source_fact_id, timestamp,
    waive_event,
};
use super::*;
use crate::memory_contracts::canonical::encode_canonical;
use crate::memory_contracts::coverage::{
    CoverageCompletenessV1, CoverageWindowV1, FreshnessStateV1,
};
use crate::memory_contracts::discrepancy::LifecycleState;

fn window(start: &str, end: &str) -> CoverageWindowV1 {
    CoverageWindowV1 {
        window_start: timestamp(start),
        window_end: timestamp(end),
    }
}

fn compared() -> CoverageWindowV1 {
    window(
        "2026-08-15T00:00:00.000000000Z",
        "2026-08-15T06:00:00.000000000Z",
    )
}

/// A side that fully measured the compared interval.
fn complete_side(role: ComparisonSideRoleV1, value_digit: char) -> MeasuredComparisonSideV1 {
    MeasuredComparisonSideV1 {
        role,
        measured_window: window(
            "2026-08-14T00:00:00.000000000Z",
            "2026-08-15T12:00:00.000000000Z",
        ),
        completeness: CoverageCompletenessV1::Complete,
        freshness: FreshnessStateV1::Current,
        value_digest: Some(digest(&value_digit.to_string().repeat(64))),
    }
}

fn observed(value_digit: char) -> MeasuredComparisonSideV1 {
    complete_side(ComparisonSideRoleV1::Observed, value_digit)
}

fn normative(value_digit: char) -> MeasuredComparisonSideV1 {
    complete_side(ComparisonSideRoleV1::Normative, value_digit)
}

// --- both sides fully measured: real verdicts ---

#[test]
fn both_sides_complete_and_agreeing_is_a_verified_negative() {
    let verdict = compare_measured_sides(&compared(), &observed('a'), &normative('a')).unwrap();
    assert_eq!(verdict, ComparisonVerdictV1::NoDiscrepancy);
    assert_eq!(verdict.initial_verification_state(), None);
}

#[test]
fn both_sides_complete_and_disagreeing_is_discrepant() {
    let verdict = compare_measured_sides(&compared(), &observed('a'), &normative('b')).unwrap();
    assert_eq!(verdict, ComparisonVerdictV1::Discrepant);
    assert_eq!(
        verdict.initial_verification_state(),
        Some(crate::memory_contracts::discrepancy::VerificationState::Candidate)
    );
}

// --- an unmeasured or partially measured side poisons the claim ---

/// The single most important assertion in this file: agreeing values under a
/// PARTIAL side must NOT produce `NoDiscrepancy`. Absence of evidence of
/// disagreement is not evidence of agreement.
#[test]
fn partial_observed_side_is_indeterminate_never_a_verified_negative() {
    let mut partial = observed('a');
    partial.completeness = CoverageCompletenessV1::Partial;
    // The values AGREE — the naive implementation would say "no discrepancy".
    let verdict = compare_measured_sides(&compared(), &partial, &normative('a')).unwrap();
    assert_ne!(verdict, ComparisonVerdictV1::NoDiscrepancy);
    assert_ne!(verdict, ComparisonVerdictV1::Discrepant);
    assert_eq!(
        verdict,
        ComparisonVerdictV1::Indeterminate {
            reasons: vec![ComparisonIndeterminacyV1::ObservedPartialCoverage],
        }
    );
    assert_eq!(
        verdict.initial_verification_state(),
        Some(crate::memory_contracts::discrepancy::VerificationState::Indeterminate)
    );
}

#[test]
fn partial_normative_side_is_indeterminate_even_when_values_disagree() {
    let mut partial = normative('b');
    partial.completeness = CoverageCompletenessV1::Partial;
    // Disagreeing values under partial coverage must not confirm a finding.
    let verdict = compare_measured_sides(&compared(), &observed('a'), &partial).unwrap();
    assert_eq!(
        verdict,
        ComparisonVerdictV1::Indeterminate {
            reasons: vec![ComparisonIndeterminacyV1::NormativePartialCoverage],
        }
    );
}

#[test]
fn unmeasured_side_is_indeterminate_never_a_verified_negative() {
    let mut unmeasured = normative('a');
    unmeasured.value_digest = None;
    let verdict = compare_measured_sides(&compared(), &observed('a'), &unmeasured).unwrap();
    assert_ne!(verdict, ComparisonVerdictV1::NoDiscrepancy);
    assert_eq!(
        verdict,
        ComparisonVerdictV1::Indeterminate {
            reasons: vec![ComparisonIndeterminacyV1::NormativeUnmeasured],
        }
    );
}

#[test]
fn unknown_completeness_is_indeterminate() {
    let mut unknown = observed('a');
    unknown.completeness = CoverageCompletenessV1::Unknown;
    let verdict = compare_measured_sides(&compared(), &unknown, &normative('a')).unwrap();
    assert_eq!(
        verdict,
        ComparisonVerdictV1::Indeterminate {
            reasons: vec![ComparisonIndeterminacyV1::ObservedUnknownCoverage],
        }
    );
}

#[test]
fn stale_side_is_indeterminate() {
    let mut stale = observed('a');
    stale.freshness = FreshnessStateV1::Stale;
    let verdict = compare_measured_sides(&compared(), &stale, &normative('a')).unwrap();
    assert_eq!(
        verdict,
        ComparisonVerdictV1::Indeterminate {
            reasons: vec![ComparisonIndeterminacyV1::ObservedStale],
        }
    );
}

/// A side that claims `Complete` over a window that does not CONTAIN the
/// compared interval is still indeterminate: completeness of the wrong
/// window supports nothing about the compared one.
#[test]
fn window_shortfall_is_indeterminate_despite_claimed_completeness() {
    let mut short = normative('a');
    short.measured_window = window(
        "2026-08-15T02:00:00.000000000Z",
        "2026-08-15T04:00:00.000000000Z",
    );
    let verdict = compare_measured_sides(&compared(), &observed('a'), &short).unwrap();
    assert_eq!(
        verdict,
        ComparisonVerdictV1::Indeterminate {
            reasons: vec![ComparisonIndeterminacyV1::NormativeWindowShortfall],
        }
    );
}

#[test]
fn every_failed_conjunct_on_both_sides_is_reported() {
    let mut bad_observed = observed('a');
    bad_observed.completeness = CoverageCompletenessV1::Partial;
    bad_observed.freshness = FreshnessStateV1::Stale;
    let mut bad_normative = normative('a');
    bad_normative.value_digest = None;
    let verdict = compare_measured_sides(&compared(), &bad_observed, &bad_normative).unwrap();
    let ComparisonVerdictV1::Indeterminate { reasons } = verdict else {
        panic!("poisoned comparison must be indeterminate");
    };
    assert_eq!(
        reasons,
        vec![
            ComparisonIndeterminacyV1::NormativeUnmeasured,
            ComparisonIndeterminacyV1::ObservedPartialCoverage,
            ComparisonIndeterminacyV1::ObservedStale,
        ]
    );
}

// --- structural rejections ---

#[test]
fn two_sides_of_the_same_role_are_rejected() {
    assert!(compare_measured_sides(&compared(), &observed('a'), &observed('b')).is_err());
    assert!(compare_measured_sides(&compared(), &normative('a'), &normative('b')).is_err());
    // Swapped positions are also a category error, not a silent re-labelling.
    assert!(compare_measured_sides(&compared(), &normative('a'), &observed('b')).is_err());
}

#[test]
fn empty_compared_window_is_rejected() {
    let degenerate = CoverageWindowV1 {
        window_start: timestamp("2026-08-15T06:00:00.000000000Z"),
        window_end: timestamp("2026-08-15T06:00:00.000000000Z"),
    };
    assert!(compare_measured_sides(&degenerate, &observed('a'), &normative('a')).is_err());
}

#[test]
fn invalid_measured_window_is_rejected() {
    let mut inverted = observed('a');
    inverted.measured_window = CoverageWindowV1 {
        window_start: timestamp("2026-08-15T12:00:00.000000000Z"),
        window_end: timestamp("2026-08-14T00:00:00.000000000Z"),
    };
    assert!(compare_measured_sides(&compared(), &inverted, &normative('a')).is_err());
}

// --- the provider seam ---

/// A provider whose honest answer is "I only read part of that window".
struct PartialProvider;
impl ComparisonSideProvider for PartialProvider {
    fn measure(
        &self,
        compared: &CoverageWindowV1,
    ) -> crate::memory_contracts::ContractResult<MeasuredComparisonSideV1> {
        Ok(MeasuredComparisonSideV1 {
            role: ComparisonSideRoleV1::Observed,
            measured_window: compared.clone(),
            completeness: CoverageCompletenessV1::Partial,
            freshness: FreshnessStateV1::Current,
            value_digest: Some(digest(&"a".repeat(64))),
        })
    }
}

struct CompleteNormativeProvider;
impl ComparisonSideProvider for CompleteNormativeProvider {
    fn measure(
        &self,
        compared: &CoverageWindowV1,
    ) -> crate::memory_contracts::ContractResult<MeasuredComparisonSideV1> {
        Ok(MeasuredComparisonSideV1 {
            role: ComparisonSideRoleV1::Normative,
            measured_window: compared.clone(),
            completeness: CoverageCompletenessV1::Complete,
            freshness: FreshnessStateV1::Current,
            value_digest: Some(digest(&"a".repeat(64))),
        })
    }
}

#[test]
fn provider_reported_partial_coverage_flows_into_the_verdict() {
    let verdict = compare_sides(&compared(), &PartialProvider, &CompleteNormativeProvider).unwrap();
    assert_eq!(
        verdict,
        ComparisonVerdictV1::Indeterminate {
            reasons: vec![ComparisonIndeterminacyV1::ObservedPartialCoverage],
        }
    );
}

// --- opening transition: total order, never receipt order ---

fn candidate(
    effective_at: &str,
    provider_order: u32,
    fact_digit: char,
) -> crate::memory_contracts::discrepancy::OpeningTransitionCandidateV1 {
    crate::memory_contracts::discrepancy::OpeningTransitionCandidateV1 {
        effective_at: timestamp(effective_at),
        provider_order,
        source_fact_id: source_fact_id(fact_digit),
    }
}

/// The negative case the brief names: receipt order and total order DISAGREE
/// — the earliest-by-total-order candidate is received LAST — and the total
/// order wins. Re-ingesting the same facts in any sequence cannot move the
/// fingerprint.
#[test]
fn opening_transition_total_order_beats_receipt_order() {
    let sample = envelope();
    let continuity_key: Vec<_> = vec![super::super::testbed::applicability()[1].clone()];
    let early = candidate("2026-08-15T04:00:00.000000000Z", 7, 'e');
    let late = candidate("2026-08-15T04:30:00.000000000Z", 0, 'a');
    // Receipt order says `late` came first; the total order says `early`
    // opens the episode (effective time dominates provider order).
    let receipt_order = [late.clone(), early.clone()];
    let effective_order = [early.clone(), late.clone()];

    let (winner_a, fingerprint_a) = seed_episode_fingerprint(
        sample.family_fingerprint,
        &continuity_key,
        1,
        &receipt_order,
    )
    .unwrap();
    let (winner_b, fingerprint_b) = seed_episode_fingerprint(
        sample.family_fingerprint,
        &continuity_key,
        1,
        &effective_order,
    )
    .unwrap();
    assert_eq!(winner_a, early);
    assert_eq!(winner_a, winner_b);
    assert_eq!(fingerprint_a, fingerprint_b);
    // And the receipt-first candidate did NOT win despite arriving first.
    assert_ne!(winner_a, late);
}

#[test]
fn opening_transition_breaks_ties_by_provider_order_then_source_fact() {
    let sample = envelope();
    let continuity_key: Vec<_> = vec![super::super::testbed::applicability()[1].clone()];
    let same_time = "2026-08-15T04:00:00.000000000Z";
    let by_provider = [candidate(same_time, 3, 'a'), candidate(same_time, 1, 'f')];
    let (winner, _) =
        seed_episode_fingerprint(sample.family_fingerprint, &continuity_key, 1, &by_provider)
            .unwrap();
    assert_eq!(winner.provider_order, 1);

    let by_fact = [candidate(same_time, 1, 'f'), candidate(same_time, 1, 'a')];
    let (winner, _) =
        seed_episode_fingerprint(sample.family_fingerprint, &continuity_key, 1, &by_fact).unwrap();
    assert_eq!(winner.source_fact_id, source_fact_id('a'));
}

#[test]
fn opening_transition_requires_at_least_one_candidate() {
    let sample = envelope();
    assert!(seed_episode_fingerprint(sample.family_fingerprint, &[], 1, &[]).is_err());
}

// --- deterministic ledger projection (REPLAY-01) ---

#[test]
fn ledger_evaluation_time_is_the_latest_known_instant() {
    let sample = envelope();
    assert_eq!(ledger_evaluation_time(&sample, &[]), sample.detected_at);

    let ack = acknowledge_event(&sample, "2026-08-15T05:00:00.000000000Z");
    let resolve = resolve_event(&sample, "2026-08-15T06:00:00.000000000Z");
    let latest = ledger_evaluation_time(&sample, &[resolve.clone(), ack.clone()]);
    assert_eq!(latest, timestamp("2026-08-15T06:00:00.000000000Z"));
    // Order-independent by construction.
    assert_eq!(latest, ledger_evaluation_time(&sample, &[ack, resolve]));
}

/// REPLAY-01 at the runtime layer: every permutation of the event set —
/// including the one where a LATE event (an `effective_at` before an
/// already-applied event) arrives last — produces byte-identical
/// projections at the identical evaluation instant.
#[test]
fn projection_is_identical_under_every_event_permutation_including_late_arrival() {
    let sample = envelope();
    let ack = acknowledge_event(&sample, "2026-08-15T05:00:00.000000000Z");
    let waive = waive_event(
        &sample,
        "2026-08-15T05:10:00.000000000Z",
        "2026-09-01T00:00:00.000000000Z",
    );
    let resolve = resolve_event(&sample, "2026-08-15T06:00:00.000000000Z");

    let permutations = [
        vec![ack.clone(), waive.clone(), resolve.clone()],
        // The late-arrival case: `ack` (earliest effective_at) arrives LAST,
        // after both later events were already known.
        vec![waive.clone(), resolve.clone(), ack.clone()],
        vec![resolve.clone(), ack.clone(), waive.clone()],
        vec![resolve, waive, ack],
    ];
    let (reference, reference_time) =
        project_ledger_episode(&sample, &permutations[0], &[]).unwrap();
    let reference_bytes = encode_canonical(&reference).unwrap();
    for events in &permutations[1..] {
        let (projection, evaluated_at) = project_ledger_episode(&sample, events, &[]).unwrap();
        assert_eq!(projection, reference);
        assert_eq!(evaluated_at, reference_time);
        assert_eq!(encode_canonical(&projection).unwrap(), reference_bytes);
    }
    // The replay landed on the final transition despite the permutations.
    assert_eq!(reference.lifecycle_state, LifecycleState::Resolved);
}

/// DISC-01/DISC-02 at the runtime layer: the SAME detection replayed under
/// several DIFFERENT lifecycle histories keeps byte-identical family and
/// episode fingerprints — lifecycle state never defines identity.
#[test]
fn fingerprints_are_identical_under_differing_lifecycle_histories() {
    let sample = envelope();
    let histories: Vec<Vec<_>> = vec![
        vec![],
        vec![acknowledge_event(&sample, "2026-08-15T05:00:00.000000000Z")],
        vec![
            acknowledge_event(&sample, "2026-08-15T05:00:00.000000000Z"),
            waive_event(
                &sample,
                "2026-08-15T05:10:00.000000000Z",
                "2026-09-01T00:00:00.000000000Z",
            ),
        ],
        vec![dismiss_event(
            &sample,
            "2026-08-15T05:30:00.000000000Z",
            "principal.on_call",
        )],
        vec![
            acknowledge_event(&sample, "2026-08-15T05:00:00.000000000Z"),
            resolve_event(&sample, "2026-08-15T06:00:00.000000000Z"),
        ],
    ];
    let family = sample.family_fingerprint;
    let episode = sample.episode_fingerprint;
    let envelope_id = sample.envelope_id().unwrap();
    let mut lifecycle_states = Vec::new();
    for history in &histories {
        let (projection, _) = project_ledger_episode(&sample, history, &[]).unwrap();
        // The projection names exactly the same episode every time...
        assert_eq!(projection.episode_fingerprint, episode);
        // ...and the identity recomputed from the envelope has not moved.
        assert_eq!(sample.family_fingerprint, family);
        assert_eq!(sample.envelope_id().unwrap(), envelope_id);
        lifecycle_states.push(projection.lifecycle_state);
    }
    // The histories genuinely differed — this is not five copies of one run.
    assert!(lifecycle_states.contains(&LifecycleState::Open));
    assert!(lifecycle_states.contains(&LifecycleState::Waived));
    assert!(lifecycle_states.contains(&LifecycleState::Dismissed));
    assert!(lifecycle_states.contains(&LifecycleState::Resolved));
}

/// An event the contract's authorization rejects (a self-implicated
/// dismissal) fails the whole projection closed rather than being skipped.
#[test]
fn projection_fails_closed_on_an_unauthorized_event() {
    let sample = envelope();
    let self_dismiss = dismiss_event(
        &sample,
        "2026-08-15T05:30:00.000000000Z",
        "principal.author_a",
    );
    assert!(project_ledger_episode(&sample, &[self_dismiss], &[]).is_err());
}

#[test]
fn every_indeterminacy_reason_has_its_own_snake_case_name() {
    use std::collections::BTreeSet;

    let reasons = [
        ComparisonIndeterminacyV1::ObservedUnmeasured,
        ComparisonIndeterminacyV1::NormativeUnmeasured,
        ComparisonIndeterminacyV1::ObservedPartialCoverage,
        ComparisonIndeterminacyV1::NormativePartialCoverage,
        ComparisonIndeterminacyV1::ObservedUnknownCoverage,
        ComparisonIndeterminacyV1::NormativeUnknownCoverage,
        ComparisonIndeterminacyV1::ObservedStale,
        ComparisonIndeterminacyV1::NormativeStale,
        ComparisonIndeterminacyV1::ObservedWindowShortfall,
        ComparisonIndeterminacyV1::NormativeWindowShortfall,
    ];
    let names: BTreeSet<&str> = reasons.iter().map(|reason| reason.as_str()).collect();
    assert_eq!(names.len(), reasons.len(), "two reasons share a name");
    for reason in reasons {
        let wire = serde_json::to_value(reason).unwrap();
        assert_eq!(
            wire,
            serde_json::json!(reason.as_str()),
            "serde and as_str disagree"
        );
        assert_eq!(
            serde_json::from_value::<ComparisonIndeterminacyV1>(wire).unwrap(),
            reason
        );
    }
    for name in names {
        assert!(
            !name.is_empty()
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_'),
            "{name} is not snake_case"
        );
    }
}
