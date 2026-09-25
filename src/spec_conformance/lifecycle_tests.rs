use chrono::{DateTime, Utc};

use super::*;
use crate::connectors::git::GitObjectId;
use crate::discrepancy_runtime::ComparisonVerdictV1;
use crate::memory_contracts::common::frozen_profile_reference_v1;
use crate::memory_contracts::discrepancy::project_discrepancy_episode;
use crate::memory_contracts::evidence::SourceFactId;
use crate::memory_contracts::observer::{EvaluatedConditionV1, VerificationOutcomeV1};
use crate::spec_conformance::envelope::{SpecDetectionV1, build_spec_envelope};
use crate::spec_conformance::record::SpecCheckRecordV1;
use crate::spec_conformance::testkit::{
    expectation, label, nonconforming_check, proposal_for, reference, scope, timestamp,
};

const OPENED_AT: &str = "2026-09-02T00:00:00.000000000Z";
const CLOSED_AT: &str = "2026-09-03T00:00:00.000000000Z";

fn event(name: &str) -> AcceptedEventId {
    AcceptedEventId::from_digest(label(name))
}

fn actor(principal: &str) -> DiscrepancyActorV1 {
    DiscrepancyActorV1 {
        principal_id: ContractId::new(principal).unwrap(),
    }
}

/// The envelope a verified nonconformance of the fixture statement opens.
fn spec_envelope() -> DiscrepancyEnvelopeV1 {
    let expectation = expectation();
    let proposal = proposal_for(&expectation);
    build_spec_envelope(&SpecDetectionV1 {
        registry: &proposal.registry_head,
        statement_id: proposal.statement_id().unwrap(),
        proposal: &proposal,
        expectation: &expectation,
        extractor: &reference("observer.rust_enum"),
        observer_event: event("c0 observer"),
        blob_event: event("c0 blob"),
        source_fact_id: SourceFactId::from_digest(label("c0 source fact")),
        compared_at: &timestamp(OPENED_AT),
        verdict: &ComparisonVerdictV1::Discrepant,
    })
    .unwrap()
    .envelope
}

fn lifecycle_event(
    envelope: &DiscrepancyEnvelopeV1,
    transition: LifecycleTransitionV1,
) -> ContractResult<DiscrepancyLifecycleEventV1> {
    spec_lifecycle_event(
        envelope,
        &frozen_profile_reference_v1(),
        &scope(),
        transition,
        timestamp(CLOSED_AT),
    )
}

fn dismissal(rationale: &str) -> LifecycleTransitionV1 {
    LifecycleTransitionV1::Dismiss {
        actor: actor("principal.on_call"),
        reason: DismissalReasonV1 {
            kind: DismissalReasonKindV1::FalsePositive,
            rationale: rationale.into(),
        },
    }
}

#[test]
fn a_spec_episode_names_the_statement_it_violates() {
    let expectation = expectation();
    let proposal = proposal_for(&expectation);
    let envelope = spec_envelope();
    assert_eq!(
        spec_episode_statement(&envelope).unwrap(),
        (
            proposal.binding_family_id.clone(),
            proposal.statement_id().unwrap()
        )
    );

    for finding_type in [FindingType::ClaimConflict, FindingType::DocumentationDrift] {
        let other = DiscrepancyEnvelopeV1 {
            finding_type,
            ..envelope.clone()
        };
        assert!(spec_episode_statement(&other).is_err(), "{finding_type:?}");
    }
    let mut later_policy = envelope;
    later_policy.expectation_policy.version += 1;
    assert!(spec_episode_statement(&later_policy).is_err());
}

#[test]
fn a_resolution_cites_its_evidence_sorted_once_and_closes_the_episode() {
    let envelope = spec_envelope();
    let resolved = lifecycle_event(
        &envelope,
        LifecycleTransitionV1::Resolve {
            actor: actor("principal.on_call"),
            resolution_evidence_ids: vec![
                event("c1 observer"),
                event("c0 blob"),
                event("c1 observer"),
            ],
        },
    )
    .unwrap();
    let mut cited = vec![event("c1 observer"), event("c0 blob")];
    cited.sort_unstable();
    assert!(matches!(
        &resolved.lifecycle_transition,
        Some(LifecycleTransitionV1::Resolve { resolution_evidence_ids, .. })
            if resolution_evidence_ids == &cited
    ));
    assert_eq!(resolved.evidence_event_ids, cited);
    assert_eq!(resolved.episode_fingerprint, envelope.episode_fingerprint);
    assert_eq!(resolved.effective_at, timestamp(CLOSED_AT));

    let projection =
        project_discrepancy_episode(&envelope, &[resolved], &[], &timestamp(CLOSED_AT)).unwrap();
    assert_eq!(projection.lifecycle_state, LifecycleState::Resolved);
    assert_eq!(projection.resolution_evidence_ids, cited);
}

#[test]
fn a_dismissal_needs_a_rationale_and_cites_no_evidence() {
    let envelope = spec_envelope();
    let dismissed = lifecycle_event(&envelope, dismissal("the enum is generated code")).unwrap();
    assert!(dismissed.evidence_event_ids.is_empty());
    let projection =
        project_discrepancy_episode(&envelope, &[dismissed], &[], &timestamp(CLOSED_AT)).unwrap();
    assert_eq!(projection.lifecycle_state, LifecycleState::Dismissed);

    for blank in ["", "   ", "\u{200B}\n"] {
        assert!(
            lifecycle_event(&envelope, dismissal(blank)).is_err(),
            "{blank:?}"
        );
    }
}

#[test]
fn a_resolution_without_evidence_is_refused() {
    let envelope = spec_envelope();
    assert!(
        lifecycle_event(
            &envelope,
            LifecycleTransitionV1::Resolve {
                actor: actor("principal.on_call"),
                resolution_evidence_ids: Vec::new(),
            },
        )
        .is_err()
    );
}

#[test]
fn an_event_is_bound_to_the_envelope_scope_and_profile() {
    let envelope = spec_envelope();
    let elsewhere = AuthenticatedProjectScopeV1::from_trusted_context(
        ContractId::new("tenant.acme").unwrap(),
        ContractId::new("project.elsewhere").unwrap(),
    );
    assert!(
        spec_lifecycle_event(
            &envelope,
            &frozen_profile_reference_v1(),
            &elsewhere,
            dismissal("out of scope"),
            timestamp(CLOSED_AT),
        )
        .is_err()
    );
    let mut other_profile = frozen_profile_reference_v1();
    other_profile.profile_digest = label("another profile");
    assert!(
        spec_lifecycle_event(
            &envelope,
            &other_profile,
            &scope(),
            dismissal("out of scope"),
            timestamp(CLOSED_AT),
        )
        .is_err()
    );
}

#[test]
fn an_implicated_actor_cannot_close_their_own_finding() {
    let mut envelope = spec_envelope();
    envelope.implicated_actor_ids = vec![ContractId::new("principal.on_call").unwrap()];
    assert!(lifecycle_event(&envelope, dismissal("not mine")).is_err());
    assert!(
        lifecycle_event(
            &envelope,
            LifecycleTransitionV1::Resolve {
                actor: actor("principal.on_call"),
                resolution_evidence_ids: vec![event("c1 observer")],
            },
        )
        .is_err()
    );
}

/// `record` as stored at `recorded_at`.
fn stored(record: SpecCheckRecordV1, recorded_at: DateTime<Utc>) -> StoredSpecCheckV1 {
    StoredSpecCheckV1 {
        check_id: record.check_id().unwrap(),
        record,
        recorded_at,
    }
}

#[test]
fn a_resolution_defaults_only_to_a_later_exhaustive_check_of_another_commit() {
    let opened = nonconforming_check(label("statement"));
    let statement_id = opened.statement_id;
    let opened_at = Utc::now();
    let later_at = opened_at + chrono::TimeDelta::seconds(1);
    let opening = stored(opened.clone(), opened_at);

    // Nothing checked, or only the nonconformance itself.
    assert!(default_resolution_evidence(statement_id, None, Some(&opening), false).is_err());
    assert!(
        default_resolution_evidence(statement_id, Some(&opening), Some(&opening), true).is_err()
    );

    let fixing_commit = GitObjectId::parse_hex(&"c1".repeat(20)).unwrap();
    for (verdict, condition, outcome, reasons) in [
        (
            SpecVerdictV1::Unknown,
            EvaluatedConditionV1::Indeterminate,
            VerificationOutcomeV1::Indeterminate,
            vec![
                ComparisonIndeterminacyV1::ObservedUnmeasured,
                ComparisonIndeterminacyV1::ObservedUnknownCoverage,
            ],
        ),
        (
            SpecVerdictV1::Conforming,
            EvaluatedConditionV1::Absent,
            VerificationOutcomeV1::VerifiedNegative,
            Vec::new(),
        ),
    ] {
        let fixed = SpecCheckRecordV1 {
            commit_oid: fixing_commit.clone(),
            observer_event_id: event("c1 observer"),
            observed_condition: condition,
            verification_outcome: outcome,
            verdict,
            reasons,
            episode: None,
            ..opened.clone()
        };
        let later = stored(fixed.clone(), later_at);
        assert_eq!(
            default_resolution_evidence(statement_id, Some(&later), Some(&opening), false).unwrap(),
            event("c1 observer"),
            "{verdict:?}"
        );

        // A re-read of the commit already judged nonconforming, whatever it
        // found, is not a fix.
        assert!(
            default_resolution_evidence(statement_id, Some(&later), Some(&opening), true).is_err()
        );
        // Without the opening check nothing shows the later one follows it.
        assert!(default_resolution_evidence(statement_id, Some(&later), None, false).is_err());
        // A check recorded no later than the opening one, or of a commit
        // that predates the violating one, does not follow it.
        let concurrent = stored(fixed.clone(), opened_at);
        assert!(
            default_resolution_evidence(statement_id, Some(&concurrent), Some(&opening), false)
                .is_err()
        );
        let older = stored(
            SpecCheckRecordV1 {
                compared_at: timestamp("2026-08-31T00:00:00.000000000Z"),
                ..fixed
            },
            later_at,
        );
        assert!(
            default_resolution_evidence(statement_id, Some(&older), Some(&opening), false).is_err()
        );
    }

    // A read cut short by its member bound shows nothing.
    let truncated = stored(
        SpecCheckRecordV1 {
            commit_oid: fixing_commit,
            observer_event_id: event("c1 observer"),
            observed_condition: EvaluatedConditionV1::Indeterminate,
            verification_outcome: VerificationOutcomeV1::Indeterminate,
            verdict: SpecVerdictV1::Unknown,
            reasons: vec![
                ComparisonIndeterminacyV1::ObservedUnmeasured,
                ComparisonIndeterminacyV1::ObservedPartialCoverage,
            ],
            episode: None,
            ..opened
        },
        later_at,
    );
    assert!(
        default_resolution_evidence(statement_id, Some(&truncated), Some(&opening), false).is_err()
    );
}
