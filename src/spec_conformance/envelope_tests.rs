use super::*;
use crate::discrepancy_runtime::{DiscrepancyRegistryBindingV1, admit_envelope};
use crate::memory_contracts::discrepancy::FindingType;
use crate::spec_conformance::testkit::{
    expectation, label, proposal_for, reference, scope, timestamp,
};

const COMPARED_AT: &str = "2026-09-02T00:00:00.000000000Z";

/// One commit's detection: its observer event, blob event, and source fact.
struct Commit {
    observer_event: AcceptedEventId,
    blob_event: AcceptedEventId,
    source_fact_id: SourceFactId,
}

fn commit(name: &str) -> Commit {
    Commit {
        observer_event: AcceptedEventId::from_digest(label(&format!("{name} observer"))),
        blob_event: AcceptedEventId::from_digest(label(&format!("{name} blob"))),
        source_fact_id: SourceFactId::from_digest(label(&format!("{name} source fact"))),
    }
}

fn envelope_for(
    proposal: &NormativeBindingProposalV2,
    expectation: &RememberActionExpectationV1,
    commit: &Commit,
    verdict: &ComparisonVerdictV1,
) -> ContractResult<DiscrepancyEnvelopeCandidateV1> {
    build_spec_envelope(&SpecDetectionV1 {
        registry: &proposal.registry_head,
        statement_id: proposal.statement_id().unwrap(),
        proposal,
        expectation,
        extractor: &reference("observer.rust_enum"),
        observer_event: commit.observer_event,
        blob_event: commit.blob_event,
        source_fact_id: commit.source_fact_id,
        compared_at: &timestamp(COMPARED_AT),
        verdict,
    })
}

#[test]
fn the_same_detection_builds_the_same_admissible_envelope() {
    let expectation = expectation();
    let proposal = proposal_for(&expectation);
    let first = envelope_for(
        &proposal,
        &expectation,
        &commit("c0"),
        &ComparisonVerdictV1::Discrepant,
    )
    .unwrap();
    let again = envelope_for(
        &proposal,
        &expectation,
        &commit("c0"),
        &ComparisonVerdictV1::Discrepant,
    )
    .unwrap();
    assert_eq!(
        first.envelope.envelope_id().unwrap(),
        again.envelope.envelope_id().unwrap()
    );
    assert_eq!(first.envelope.finding_type, FindingType::SpecNonconformance);
    assert_eq!(
        first.envelope.canonical_subject,
        proposal.repository_entity_id
    );
    assert_eq!(first.envelope.severity, expectation.severity);

    // It is admissible under the head it names, in the proposal's scope.
    let binding = DiscrepancyRegistryBindingV1 {
        registry_package_digest: proposal.registry_head.head.package_digest,
        activation_policy_digest: proposal.registry_head.head.activation_policy_digest,
    };
    let admitted = admit_envelope(&first, &binding, &scope()).unwrap();
    assert_eq!(
        admitted.family_fingerprint,
        spec_family_fingerprint(
            &scope(),
            proposal.statement_id().unwrap(),
            &proposal,
            &expectation
        )
        .unwrap()
    );
}

#[test]
fn two_commits_under_one_statement_share_a_family_but_not_an_episode() {
    let expectation = expectation();
    let proposal = proposal_for(&expectation);
    let discrepant = ComparisonVerdictV1::Discrepant;
    let first = envelope_for(&proposal, &expectation, &commit("c0"), &discrepant).unwrap();
    let second = envelope_for(&proposal, &expectation, &commit("c1"), &discrepant).unwrap();
    assert_eq!(
        first.envelope.family_fingerprint,
        second.envelope.family_fingerprint
    );
    assert_ne!(
        first.envelope.episode_fingerprint,
        second.envelope.episode_fingerprint
    );

    // Another statement about the same repository is another family.
    let mut other = proposal;
    other.effective_from = timestamp("2026-09-01T00:00:01.000000000Z");
    let third = envelope_for(&other, &expectation, &commit("c0"), &discrepant).unwrap();
    assert_ne!(
        first.envelope.family_fingerprint,
        third.envelope.family_fingerprint
    );
}

#[test]
fn only_a_discrepant_comparison_builds_an_envelope() {
    let expectation = expectation();
    let proposal = proposal_for(&expectation);
    for verdict in [
        ComparisonVerdictV1::NoDiscrepancy,
        ComparisonVerdictV1::Indeterminate {
            reasons: vec![
                crate::discrepancy_runtime::ComparisonIndeterminacyV1::ObservedUnmeasured,
            ],
        },
    ] {
        assert!(envelope_for(&proposal, &expectation, &commit("c0"), &verdict).is_err());
    }
}
