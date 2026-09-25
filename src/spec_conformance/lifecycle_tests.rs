use super::*;
use crate::discrepancy_runtime::ComparisonVerdictV1;
use crate::memory_contracts::common::frozen_profile_reference_v1;
use crate::memory_contracts::discrepancy::project_discrepancy_episode;
use crate::memory_contracts::evidence::SourceFactId;
use crate::spec_conformance::envelope::{SpecDetectionV1, build_spec_envelope};
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

#[test]
fn a_resolution_defaults_to_a_later_check_that_is_not_nonconforming() {
    let standing = nonconforming_check(label("statement"));
    let statement_id = standing.statement_id;
    assert!(default_resolution_evidence(statement_id, None).is_err());
    assert!(default_resolution_evidence(statement_id, Some(&standing)).is_err());

    for verdict in [SpecVerdictV1::Unknown, SpecVerdictV1::Conforming] {
        let later = SpecCheckRecordV1 {
            observer_event_id: event("c1 observer"),
            verdict,
            ..standing.clone()
        };
        assert_eq!(
            default_resolution_evidence(statement_id, Some(&later)).unwrap(),
            event("c1 observer"),
            "{verdict:?}"
        );
    }
}
