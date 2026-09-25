//! Unit tests for the spec-statement dependencies a rebase checks. The
//! transactional rebase and the installer step are proved in
//! `tests/normative_activation_live.rs` and `tests/spec_conformance_live.rs`.

use super::*;
use crate::memory_contracts::common::CanonicalTimestamp;
use crate::memory_contracts::digest::{DigestDomain, domain_separated_digest};
use crate::memory_contracts::registry::RegistryPackageV1;
use crate::normative_runtime::{
    NormativeFamilyProjectionV1, NormativeRebaseAdmissionV1, NormativeStatementIntervalV1,
    active_binding_set_digest, admit_rebase,
};
use crate::registry_witness::{
    compiled_generation_three_package, compiled_generation_two_package, compiled_genesis_package,
};
use crate::spec_conformance::draft::{spec_applicability_evaluator, spec_predicate};
use crate::spec_conformance::expectation::{RememberActionExpectationV1, repository_selector};
use crate::spec_conformance::testkit::{expectation, proposal_for};

/// A spec statement drafted under `package`, naming the genesis observer's
/// predicate and the genesis applicability evaluator, as `draft_statement`
/// builds one.
fn drafted_under(package: &SemanticallyClosedSuccessorPackage) -> NormativeBindingProposalV2 {
    let genesis = compiled_genesis_package().unwrap();
    let expectation = RememberActionExpectationV1 {
        predicate: spec_predicate(genesis).unwrap(),
        ..expectation()
    };
    let mut proposal = proposal_for(&expectation);
    proposal.applicability_evaluator = spec_applicability_evaluator(genesis).unwrap();
    proposal.applicability_selector = repository_selector(&proposal);
    proposal.registry_head.head.package_digest = package.package_digest();
    proposal
}

fn references(package: &RegistryPackageV1) -> Vec<RegistryReferenceV1> {
    package
        .manifest
        .iter()
        .map(|manifest| RegistryReferenceV1 {
            entry_id: manifest.entry_id.clone(),
            version: manifest.version,
            entry_digest: manifest.entry_digest,
        })
        .collect()
}

/// The generation-3 head as a rebase target: its package's entries and the
/// genesis package's, as `NormativeRebaseTargetV1::from_witness` collects
/// them.
fn generation_three_target() -> NormativeRebaseTargetV1 {
    let generation_three = compiled_generation_three_package().unwrap();
    let genesis = compiled_genesis_package().unwrap();
    NormativeRebaseTargetV1::new(
        NormativeRegistryBindingV1 {
            registry_package_digest: generation_three.package_digest(),
            activation_policy_digest: generation_three
                .activation_policy()
                .registry_reference()
                .entry_digest,
        },
        domain_separated_digest(DigestDomain::RegistryEntry, b"activation-3"),
        references(generation_three.manifest_verified_package().package())
            .into_iter()
            .chain(references(genesis.manifest_verified_package().package())),
    )
    .unwrap()
}

#[test]
fn a_spec_statement_depends_on_its_genesis_entries_and_its_subject_recipe() {
    let generation_two = compiled_generation_two_package().unwrap();
    let proposal = drafted_under(&generation_two);
    let genesis = compiled_genesis_package().unwrap();
    assert_eq!(
        spec_statement_dependencies(&generation_two, &proposal).unwrap(),
        BTreeSet::from([
            spec_predicate(genesis).unwrap(),
            spec_applicability_evaluator(genesis).unwrap(),
            repository_recipe(&generation_two).unwrap(),
        ])
    );
}

#[test]
fn generation_three_carries_every_entry_a_generation_two_spec_statement_depends_on() {
    let generation_two = compiled_generation_two_package().unwrap();
    let proposal = drafted_under(&generation_two);
    let statement_id = domain_separated_digest(DigestDomain::RegistryEntry, b"statement");
    let family = proposal.binding_family_id.clone();
    let dependencies = spec_statement_dependencies(&generation_two, &proposal).unwrap();
    let target = generation_three_target();
    for dependency in &dependencies {
        assert!(
            target.carries(dependency),
            "generation 3 must carry {} v{} byte for byte",
            dependency.entry_id,
            dependency.version
        );
    }

    // So a family last advanced under generation 2 rebases onto it.
    let head = NormativeHeadRowV1 {
        binding_family_id: family.clone(),
        active_binding_set_digest: active_binding_set_digest(&family, &[statement_id]),
        registry_package_digest: generation_two.package_digest(),
        activation_policy_digest: generation_two
            .activation_policy()
            .registry_reference()
            .entry_digest,
        head_revision: 1,
        log_seq: 1,
    };
    let mut projection = NormativeFamilyProjectionV1::empty(family.clone());
    projection.cursor_seq = 1;
    projection.live = vec![NormativeStatementIntervalV1 {
        statement_id,
        effective_from: proposal.effective_from,
        effective_until: None,
    }];
    let admitted = admit_rebase(
        &head,
        &projection,
        &target,
        &NormativeRebaseRequestV1 {
            binding_family_id: family,
            expected_head_revision: 1,
            live_statement_dependencies: BTreeMap::from([(statement_id, dependencies.clone())]),
        },
        CanonicalTimestamp::parse("2026-09-25T12:00:00.000000000Z").unwrap(),
    )
    .unwrap();
    let NormativeRebaseAdmissionV1::Rebase { record, .. } = admitted else {
        panic!("a generation-2 family must rebase onto generation 3: {admitted:?}");
    };
    let crate::normative_runtime::NormativeLogRecordV1::Rebase { rebase } = *record else {
        panic!("a rebase admits a rebase record");
    };
    assert_eq!(
        rebase.carried_entry_digests,
        dependencies
            .iter()
            .map(|dependency| dependency.entry_digest)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
    );
}
