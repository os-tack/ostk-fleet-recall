use super::*;
use crate::memory_contracts::canonical::decode_typed_canonical;
use crate::spec_conformance::testkit::{label, nonconforming_check, resource};

fn statement() -> Sha256Digest {
    label("statement")
}

/// The same comparison, but the observer could not verify the member.
fn unknown_check(reasons: Vec<ComparisonIndeterminacyV1>) -> SpecCheckRecordV1 {
    SpecCheckRecordV1 {
        observed_condition: EvaluatedConditionV1::Indeterminate,
        verification_outcome: VerificationOutcomeV1::Indeterminate,
        verdict: SpecVerdictV1::Unknown,
        reasons,
        episode: None,
        ..nonconforming_check(statement())
    }
}

#[test]
fn a_consistent_record_has_a_stable_identity_and_round_trips() {
    let check = nonconforming_check(statement());
    let check_id = check.check_id().unwrap();
    assert_eq!(
        check_id,
        nonconforming_check(statement()).check_id().unwrap()
    );
    let decoded: SpecCheckRecordV1 =
        decode_typed_canonical(&check.canonical_bytes().unwrap()).unwrap();
    assert_eq!(decoded, check);
    assert_eq!(decoded.check_id().unwrap(), check_id);
}

#[test]
fn the_check_id_changes_with_the_verdict_or_the_reasons() {
    let nonconforming = nonconforming_check(statement()).check_id().unwrap();
    let conforming = SpecCheckRecordV1 {
        expected: ExpectedMembershipV1::Present,
        verdict: SpecVerdictV1::Conforming,
        episode: None,
        ..nonconforming_check(statement())
    }
    .check_id()
    .unwrap();
    let unmeasured = unknown_check(vec![ComparisonIndeterminacyV1::ObservedUnmeasured])
        .check_id()
        .unwrap();
    let unmeasured_and_unknown_coverage = unknown_check(vec![
        ComparisonIndeterminacyV1::ObservedUnmeasured,
        ComparisonIndeterminacyV1::ObservedUnknownCoverage,
    ])
    .check_id()
    .unwrap();
    let shortfall = unknown_check(vec![ComparisonIndeterminacyV1::NormativeWindowShortfall])
        .check_id()
        .unwrap();
    let ids = [
        nonconforming,
        conforming,
        unmeasured,
        unmeasured_and_unknown_coverage,
        shortfall,
    ];
    let distinct: std::collections::BTreeSet<_> = ids.iter().collect();
    assert_eq!(
        distinct.len(),
        ids.len(),
        "two different checks share an id"
    );

    let other_episode = SpecCheckRecordV1 {
        episode: Some(DiscrepancyEpisodeFingerprintV1::from_digest(label(
            "another episode",
        ))),
        ..nonconforming_check(statement())
    };
    assert_ne!(other_episode.check_id().unwrap(), nonconforming);
}

#[test]
fn a_verified_absence_judges_both_ways() {
    let absent = |expected, verdict, episode| SpecCheckRecordV1 {
        expected,
        observed_condition: EvaluatedConditionV1::Absent,
        verification_outcome: VerificationOutcomeV1::VerifiedNegative,
        verdict,
        episode,
        ..nonconforming_check(statement())
    };
    absent(
        ExpectedMembershipV1::Absent,
        SpecVerdictV1::Conforming,
        None,
    )
    .validate()
    .unwrap();
    absent(
        ExpectedMembershipV1::Present,
        SpecVerdictV1::Nonconforming,
        nonconforming_check(statement()).episode,
    )
    .validate()
    .unwrap();
}

fn assert_refused<const N: usize>(refused: [(&str, SpecCheckRecordV1); N]) {
    for (name, record) in refused {
        assert!(record.validate().is_err(), "{name} must be refused");
        assert!(record.check_id().is_err(), "{name} must have no identity");
    }
}

#[test]
fn a_malformed_record_is_refused() {
    let base = nonconforming_check;
    assert_refused([
        (
            "an unsupported version",
            SpecCheckRecordV1 {
                schema_version: 2,
                ..base(statement())
            },
        ),
        ("a zero statement", base(Sha256Digest::ZERO)),
        (
            "the same observer and blob event",
            SpecCheckRecordV1 {
                blob_event_id: base(statement()).observer_event_id,
                ..base(statement())
            },
        ),
        (
            "an observed revision that is not a version",
            SpecCheckRecordV1 {
                observed_revision_uri: resource("entity", "repository", "repo"),
                ..base(statement())
            },
        ),
        (
            "a member that is not an identifier",
            SpecCheckRecordV1 {
                member: "Forget()".into(),
                ..base(statement())
            },
        ),
        (
            "a verified positive over an absent condition",
            SpecCheckRecordV1 {
                observed_condition: EvaluatedConditionV1::Absent,
                ..base(statement())
            },
        ),
        (
            "an exact-set outcome",
            SpecCheckRecordV1 {
                verification_outcome: VerificationOutcomeV1::VerifiedExactSet,
                ..base(statement())
            },
        ),
    ]);
}

#[test]
fn a_verdict_that_does_not_follow_from_its_observation_is_refused() {
    let base = nonconforming_check;
    assert_refused([
        (
            "a verdict that does not follow from the expectation",
            SpecCheckRecordV1 {
                expected: ExpectedMembershipV1::Present,
                ..base(statement())
            },
        ),
        (
            "a conforming verdict over an unverified observation",
            SpecCheckRecordV1 {
                expected: ExpectedMembershipV1::Present,
                verification_outcome: VerificationOutcomeV1::Candidate,
                verdict: SpecVerdictV1::Conforming,
                episode: None,
                ..base(statement())
            },
        ),
        (
            "a nonconforming check without an episode",
            SpecCheckRecordV1 {
                episode: None,
                ..base(statement())
            },
        ),
        (
            "a nonconforming check with reasons",
            SpecCheckRecordV1 {
                reasons: vec![ComparisonIndeterminacyV1::ObservedStale],
                ..base(statement())
            },
        ),
        (
            "a conforming check with an episode",
            SpecCheckRecordV1 {
                expected: ExpectedMembershipV1::Present,
                verdict: SpecVerdictV1::Conforming,
                ..base(statement())
            },
        ),
        (
            "an unknown check without reasons",
            unknown_check(Vec::new()),
        ),
        (
            "an unknown check with an episode",
            SpecCheckRecordV1 {
                episode: base(statement()).episode,
                ..unknown_check(vec![ComparisonIndeterminacyV1::ObservedUnmeasured])
            },
        ),
        (
            "unsorted reasons",
            unknown_check(vec![
                ComparisonIndeterminacyV1::ObservedUnknownCoverage,
                ComparisonIndeterminacyV1::ObservedUnmeasured,
            ]),
        ),
        (
            "a repeated reason",
            unknown_check(vec![
                ComparisonIndeterminacyV1::ObservedUnmeasured,
                ComparisonIndeterminacyV1::ObservedUnmeasured,
            ]),
        ),
    ]);
}

#[test]
fn verdict_names_round_trip() {
    for verdict in [
        SpecVerdictV1::Nonconforming,
        SpecVerdictV1::Conforming,
        SpecVerdictV1::Unknown,
    ] {
        assert_eq!(SpecVerdictV1::parse(verdict.as_str()).unwrap(), verdict);
        assert_eq!(
            serde_json::to_value(verdict).unwrap(),
            serde_json::json!(verdict.as_str())
        );
    }
    assert!(SpecVerdictV1::parse("conformant").is_err());
}
