use chrono::Utc;

use super::*;
use crate::discrepancy_runtime::ComparisonVerdictV1;
use crate::memory_contracts::common::AuthenticatedProjectScopeV1;
use crate::memory_contracts::discrepancy::LifecycleGapSubtypeV1;
use crate::memory_contracts::evidence::SourceFactId;
use crate::spec_conformance::envelope::{SpecDetectionV1, build_spec_envelope};
use crate::spec_conformance::record::SpecCheckRecordV1;
use crate::spec_conformance::testkit::{
    expectation, label, nonconforming_check, proposal_for, reference, timestamp,
};

/// A recorded statement that `member` must be absent.
fn statement_for(member: &str) -> RecordedSpecStatementV1 {
    let expectation = RememberActionExpectationV1 {
        member: member.into(),
        ..expectation()
    };
    let proposal = proposal_for(&expectation);
    RecordedSpecStatementV1 {
        statement_id: proposal.statement_id().unwrap(),
        proposal,
        expectation,
        recorded_at: Utc::now(),
    }
}

fn envelope_of(statement: &RecordedSpecStatementV1) -> DiscrepancyEnvelopeV1 {
    build_spec_envelope(&SpecDetectionV1 {
        registry: &statement.proposal.registry_head,
        statement_id: statement.statement_id,
        proposal: &statement.proposal,
        expectation: &statement.expectation,
        extractor: &reference("observer.rust_enum"),
        observer_event: AcceptedEventId::from_digest(label("observer")),
        blob_event: AcceptedEventId::from_digest(label("blob")),
        source_fact_id: SourceFactId::from_digest(label("source fact")),
        compared_at: &timestamp("2026-09-02T00:00:00.000000000Z"),
        verdict: &ComparisonVerdictV1::Discrepant,
    })
    .unwrap()
    .envelope
}

#[test]
fn a_spec_episode_is_described_only_by_the_statement_that_opens_it() {
    let forget = statement_for("Forget");
    let envelope = envelope_of(&forget);
    require_episode_of(&envelope, &forget).unwrap();
    assert!(
        require_episode_of(&envelope, &statement_for("Record")).is_err(),
        "another statement derives another family"
    );

    let mut other_family = forget.clone();
    other_family.proposal.binding_family_id = ContractId::new("spec.remember.other").unwrap();
    assert!(require_episode_of(&envelope, &other_family).is_err());

    let mut other_scope = forget;
    other_scope.proposal.scope = AuthenticatedProjectScopeV1::from_trusted_context(
        ContractId::new("tenant.acme").unwrap(),
        ContractId::new("project.other").unwrap(),
    );
    assert!(require_episode_of(&envelope, &other_scope).is_err());
}

/// The testkit's nonconforming check of `statement_id`, as `verdict`.
fn check_of(statement_id: Sha256Digest, verdict: SpecVerdictV1) -> StoredSpecCheckV1 {
    let nonconforming = nonconforming_check(statement_id);
    let record = match verdict {
        SpecVerdictV1::Nonconforming => nonconforming,
        SpecVerdictV1::Conforming => SpecCheckRecordV1 {
            expected: ExpectedMembershipV1::Present,
            verdict,
            episode: None,
            ..nonconforming
        },
        SpecVerdictV1::Unknown => SpecCheckRecordV1 {
            observed_condition: EvaluatedConditionV1::Indeterminate,
            verification_outcome: VerificationOutcomeV1::Indeterminate,
            verdict,
            reasons: vec![
                ComparisonIndeterminacyV1::ObservedUnmeasured,
                ComparisonIndeterminacyV1::ObservedUnknownCoverage,
            ],
            episode: None,
            ..nonconforming
        },
    };
    StoredSpecCheckV1 {
        check_id: record.check_id().unwrap(),
        record,
        recorded_at: Utc::now(),
    }
}

fn live_spec(member: &str, last_check: Option<SpecVerdictV1>) -> LiveSpec {
    effective_spec(member, last_check, SpecEffectV1::InForce)
}

fn effective_spec(
    member: &str,
    last_check: Option<SpecVerdictV1>,
    effect: SpecEffectV1,
) -> LiveSpec {
    let statement = statement_for(member);
    let family = &statement.proposal.binding_family_id;
    LiveSpec {
        resolution: "active",
        effect,
        interval: NormativeStatementIntervalV1 {
            statement_id: statement.statement_id,
            effective_from: statement.proposal.effective_from.clone(),
            effective_until: None,
        },
        binding_family_id: family.clone(),
        family_fingerprint: live_spec_family(&statement, family).unwrap(),
        expectation: SpecExpectationViewV1::of(&statement.expectation),
        last_check: last_check.map(|verdict| check_of(statement.statement_id, verdict)),
    }
}

#[test]
fn every_live_spec_is_counted_by_its_latest_check() {
    let snapshot = SpecSnapshot {
        specs: vec![
            live_spec("Forget", None),
            live_spec("Record", Some(SpecVerdictV1::Unknown)),
            live_spec("Forget", Some(SpecVerdictV1::Nonconforming)),
            live_spec("Record", Some(SpecVerdictV1::Conforming)),
        ],
        standing_statements: BTreeSet::new(),
        statements: BTreeMap::new(),
        truncated: false,
        warnings: Vec::new(),
    };
    assert_eq!(
        snapshot.family_bytes().len(),
        2,
        "one discrepancy family per statement"
    );

    let answer = snapshot.answer(Vec::new(), false);
    assert_eq!(answer.coverage.active_specs, 4);
    assert_eq!(answer.coverage.never_checked_specs, 1);
    assert_eq!(answer.coverage.unknown_specs, 1);
    assert_eq!(answer.coverage.episodes_returned, 0);
    assert!(answer.specs[0].last_check.is_none());
    let unknown = answer.specs[1].last_check.as_ref().unwrap();
    assert_eq!(unknown.verdict, SpecVerdictV1::Unknown);
    assert!(!unknown.reasons.is_empty());
    assert!(unknown.episode_id.is_none());
    let nonconforming = answer.specs[2].last_check.as_ref().unwrap();
    assert!(nonconforming.episode_id.is_some());
}

#[test]
fn a_spec_is_in_force_only_inside_its_effective_interval() {
    let interval = |from: &str, until: Option<&str>| NormativeStatementIntervalV1 {
        statement_id: label("statement"),
        effective_from: timestamp(from),
        effective_until: until.map(timestamp),
    };
    let now = timestamp("2026-09-10T00:00:00.000000000Z");
    for (from, until, effect) in [
        (
            "2026-09-01T00:00:00.000000000Z",
            None,
            SpecEffectV1::InForce,
        ),
        (
            "2026-09-10T00:00:00.000000000Z",
            Some("2026-09-10T00:00:00.000000001Z"),
            SpecEffectV1::InForce,
        ),
        (
            "2026-09-10T00:00:00.000000001Z",
            None,
            SpecEffectV1::Scheduled,
        ),
        (
            "2026-09-01T00:00:00.000000000Z",
            Some("2026-09-10T00:00:00.000000000Z"),
            SpecEffectV1::Expired,
        ),
    ] {
        assert_eq!(
            SpecEffectV1::at(&interval(from, until), &now),
            effect,
            "{from} to {until:?}"
        );
    }
}

#[test]
fn only_specs_in_force_count_as_active_and_expired_ones_list_no_episodes() {
    let in_force = effective_spec("Forget", None, SpecEffectV1::InForce);
    let scheduled = effective_spec("Record", None, SpecEffectV1::Scheduled);
    let expired = effective_spec(
        "Delete",
        Some(SpecVerdictV1::Unknown),
        SpecEffectV1::Expired,
    );
    let listed_families: BTreeSet<Vec<u8>> = [&in_force, &scheduled]
        .iter()
        .map(|spec| spec.family_fingerprint.digest().as_bytes().to_vec())
        .collect();
    let snapshot = SpecSnapshot {
        specs: vec![in_force, scheduled, expired],
        standing_statements: BTreeSet::new(),
        statements: BTreeMap::new(),
        truncated: false,
        warnings: Vec::new(),
    };
    assert_eq!(
        snapshot.family_bytes().into_iter().collect::<BTreeSet<_>>(),
        listed_families,
        "an expired spec's episodes are listed only with include_resolved"
    );

    let answer = snapshot.answer(Vec::new(), false);
    let coverage = &answer.coverage;
    assert_eq!(
        (
            coverage.active_specs,
            coverage.scheduled_specs,
            coverage.expired_specs
        ),
        (1, 1, 1)
    );
    // Only specs in force are counted as never checked or unknown.
    assert_eq!(
        (coverage.never_checked_specs, coverage.unknown_specs),
        (1, 0)
    );
    assert_eq!(
        answer
            .specs
            .iter()
            .map(|spec| spec.effect)
            .collect::<Vec<_>>(),
        [
            SpecEffectV1::InForce,
            SpecEffectV1::Scheduled,
            SpecEffectV1::Expired
        ]
    );
}

#[test]
fn a_live_statement_recorded_for_another_family_is_not_a_spec_of_this_one() {
    let statement = statement_for("Forget");
    assert!(
        live_spec_family(&statement, &ContractId::new("spec.remember.other").unwrap()).is_err()
    );
}

#[test]
fn finding_types_read_as_their_wire_kind() {
    for finding in [
        FindingType::SpecNonconformance,
        FindingType::ClaimConflict,
        FindingType::LifecycleGap {
            subtype: LifecycleGapSubtypeV1::Validation,
        },
    ] {
        let wire = serde_json::to_value(finding).unwrap();
        assert_eq!(wire["kind"], finding_type_name(finding));
    }
}
