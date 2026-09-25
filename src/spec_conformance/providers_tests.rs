use super::*;
use crate::memory_contracts::common::ContractId;
use crate::normative_runtime::{
    NORMATIVE_PROJECTION_SCHEMA_VERSION, NormativeResolutionV1, NormativeStatementIntervalV1,
};
use crate::spec_conformance::expectation::ExpectedMembershipV1;
use crate::spec_conformance::testkit::{expectation, label, proposal_for, timestamp};

/// The testkit proposal takes effect here.
const EFFECTIVE_FROM: &str = "2026-09-01T00:00:00.000000000Z";
const COMMIT_AT: &str = "2026-09-02T00:00:00.000000000Z";
const KNOWN_THROUGH: &str = "2026-09-10T00:00:00.000000000Z";

fn statement_id() -> Sha256Digest {
    label("statement")
}

fn interval(statement_id: Sha256Digest) -> NormativeStatementIntervalV1 {
    NormativeStatementIntervalV1 {
        statement_id,
        effective_from: timestamp(EFFECTIVE_FROM),
        effective_until: None,
    }
}

/// The statement alone is live in its family.
fn active_projection() -> NormativeFamilyProjectionV1 {
    NormativeFamilyProjectionV1 {
        schema_version: NORMATIVE_PROJECTION_SCHEMA_VERSION,
        binding_family_id: ContractId::new("spec.remember.no_forget").unwrap(),
        cursor_seq: 1,
        live: vec![interval(statement_id())],
        declared_contested: Vec::new(),
        resolution: NormativeResolutionV1::Active {
            statement_id: statement_id(),
        },
    }
}

/// The statement and another are live and declared contested.
fn contested_projection() -> NormativeFamilyProjectionV1 {
    let mut ids = vec![statement_id(), label("rival statement")];
    ids.sort_unstable();
    NormativeFamilyProjectionV1 {
        schema_version: NORMATIVE_PROJECTION_SCHEMA_VERSION,
        binding_family_id: ContractId::new("spec.remember.no_forget").unwrap(),
        cursor_seq: 3,
        live: ids.iter().copied().map(interval).collect(),
        declared_contested: ids.clone(),
        resolution: NormativeResolutionV1::Unknown {
            contested_statement_ids: ids,
        },
    }
}

fn normative(
    projection: NormativeFamilyProjectionV1,
    expected: ExpectedMembershipV1,
    known_through: &str,
) -> NormativeStatementSide {
    let expectation = RememberActionExpectationV1 {
        expected,
        ..expectation()
    };
    let proposal = proposal_for(&expectation);
    assert_eq!(proposal.effective_from, timestamp(EFFECTIVE_FROM));
    NormativeStatementSide::new(
        projection,
        statement_id(),
        &proposal,
        expectation,
        timestamp(known_through),
    )
}

fn observed(
    evaluated_condition: EvaluatedConditionV1,
    verification_outcome: VerificationOutcomeV1,
    observed_at: &str,
    exhaustive: bool,
) -> ObservedMembershipSide {
    ObservedMembershipSide {
        enum_name: expectation().enum_name,
        member: expectation().member,
        evaluated_condition,
        verification_outcome,
        observed_at: timestamp(observed_at),
        exhaustive,
    }
}

/// The observer found the member.
fn found(exhaustive: bool) -> ObservedMembershipSide {
    observed(
        EvaluatedConditionV1::Present,
        VerificationOutcomeV1::VerifiedPositive,
        COMMIT_AT,
        exhaustive,
    )
}

fn verdict(
    normative: &NormativeStatementSide,
    observed: &ObservedMembershipSide,
) -> ComparisonVerdictV1 {
    compare_spec_sides(normative, observed).unwrap().1
}

fn reasons(verdict: &ComparisonVerdictV1) -> Vec<ComparisonIndeterminacyV1> {
    match verdict {
        ComparisonVerdictV1::Indeterminate { reasons } => reasons.clone(),
        other => panic!("expected an indeterminate comparison, got {other:?}"),
    }
}

#[test]
fn a_verified_member_the_spec_forbids_is_nonconforming() {
    let forbids = normative(
        active_projection(),
        ExpectedMembershipV1::Absent,
        KNOWN_THROUGH,
    );
    let comparison = verdict(&forbids, &found(true));
    assert_eq!(comparison, ComparisonVerdictV1::Discrepant);
    assert_eq!(
        spec_verdict(&comparison),
        (SpecVerdictV1::Nonconforming, Vec::new())
    );
    // Finding a member is a positive observation even a partial read makes.
    assert_eq!(
        verdict(&forbids, &found(false)),
        ComparisonVerdictV1::Discrepant
    );
}

#[test]
fn a_verified_member_the_spec_requires_conforms() {
    let requires = normative(
        active_projection(),
        ExpectedMembershipV1::Present,
        KNOWN_THROUGH,
    );
    let comparison = verdict(&requires, &found(true));
    assert_eq!(comparison, ComparisonVerdictV1::NoDiscrepancy);
    assert_eq!(
        spec_verdict(&comparison),
        (SpecVerdictV1::Conforming, Vec::new())
    );
}

#[test]
fn an_absent_member_is_unknown_because_positive_verified_cannot_verify_absence() {
    // An exhaustive read that did not find the member evaluates it absent,
    // but the positive_verified admission verifies nothing about absence.
    let unverified_absence = observed(
        EvaluatedConditionV1::Absent,
        VerificationOutcomeV1::Indeterminate,
        COMMIT_AT,
        true,
    );
    for expected in [ExpectedMembershipV1::Absent, ExpectedMembershipV1::Present] {
        let comparison = verdict(
            &normative(active_projection(), expected, KNOWN_THROUGH),
            &unverified_absence,
        );
        assert_eq!(
            reasons(&comparison),
            [
                ComparisonIndeterminacyV1::ObservedUnmeasured,
                ComparisonIndeterminacyV1::ObservedUnknownCoverage,
            ]
        );
        assert_eq!(spec_verdict(&comparison).0, SpecVerdictV1::Unknown);
    }
}

#[test]
fn a_partial_read_that_missed_the_member_is_partial_coverage() {
    let partial = observed(
        EvaluatedConditionV1::Indeterminate,
        VerificationOutcomeV1::Indeterminate,
        COMMIT_AT,
        false,
    );
    let comparison = verdict(
        &normative(
            active_projection(),
            ExpectedMembershipV1::Absent,
            KNOWN_THROUGH,
        ),
        &partial,
    );
    assert_eq!(
        reasons(&comparison),
        [
            ComparisonIndeterminacyV1::ObservedUnmeasured,
            ComparisonIndeterminacyV1::ObservedPartialCoverage,
        ]
    );
}

#[test]
fn a_commit_older_than_the_statement_is_judged_when_the_statement_took_effect() {
    let forbids = normative(
        active_projection(),
        ExpectedMembershipV1::Absent,
        KNOWN_THROUGH,
    );
    let old_commit = observed(
        EvaluatedConditionV1::Present,
        VerificationOutcomeV1::VerifiedPositive,
        "2026-06-01T00:00:00.000000000Z",
        true,
    );
    let (compared, comparison) = compare_spec_sides(&forbids, &old_commit).unwrap();
    assert_eq!(compared.window_start, timestamp(EFFECTIVE_FROM));
    assert_eq!(comparison, ComparisonVerdictV1::Discrepant);

    // A commit newer than the statement is judged at its own instant.
    let (compared, _) = compare_spec_sides(&forbids, &found(true)).unwrap();
    assert_eq!(compared.window_start, timestamp(COMMIT_AT));
}

#[test]
fn a_projection_read_before_the_statement_took_effect_is_a_normative_window_shortfall() {
    let unknown_yet = normative(
        active_projection(),
        ExpectedMembershipV1::Absent,
        "2026-08-15T00:00:00.000000000Z",
    );
    let comparison = verdict(&unknown_yet, &found(true));
    assert_eq!(
        reasons(&comparison),
        [ComparisonIndeterminacyV1::NormativeWindowShortfall]
    );

    // Read before the commit it is asked about: also short.
    let read_early = normative(
        active_projection(),
        ExpectedMembershipV1::Absent,
        "2026-09-01T12:00:00.000000000Z",
    );
    assert!(
        reasons(&verdict(&read_early, &found(true)))
            .contains(&ComparisonIndeterminacyV1::NormativeWindowShortfall)
    );
}

#[test]
fn a_contested_family_is_normative_unknown_coverage_never_a_winner() {
    let contested = normative(
        contested_projection(),
        ExpectedMembershipV1::Absent,
        KNOWN_THROUGH,
    );
    let comparison = verdict(&contested, &found(true));
    let reasons = reasons(&comparison);
    assert!(
        reasons.contains(&ComparisonIndeterminacyV1::NormativeUnknownCoverage),
        "{reasons:?}"
    );
    assert!(
        reasons.contains(&ComparisonIndeterminacyV1::NormativeUnmeasured),
        "{reasons:?}"
    );
}
