//! Offline proofs for the generation-2 registry package composition.

use super::*;
use crate::memory_contracts::common::frozen_profile_reference_v1;
use crate::memory_contracts::identity::{ValidatedIdentityRecipe, resolve_parent_entity_recipe};
use crate::memory_contracts::successor_generic::StructurallyClosedSuccessorTargetV2;
use crate::memory_contracts::successor_package::SemanticallyClosedSuccessorPackage;

const GENERATION_1_PACKAGE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v2/stage4-successor/registry-package.jsonl");

fn generation_one() -> ManifestVerifiedRegistryPackage {
    let bytes = GENERATION_1_PACKAGE
        .strip_suffix(b"\n")
        .expect("the frozen package has exactly one framing LF");
    ManifestVerifiedRegistryPackage::decode(bytes, &frozen_profile_reference_v1())
        .expect("the frozen generation-1 package must decode")
}

fn generation_two() -> ManifestVerifiedRegistryPackage {
    generation_two_registry_package(&generation_one())
        .expect("the generation-2 composition must close")
}

#[test]
fn every_generation_one_entry_is_carried_forward_byte_for_byte() {
    let one = generation_one();
    let two = generation_two();
    for entry in &one.package().entries {
        let carried = two
            .package()
            .entries
            .iter()
            .find(|candidate| candidate.entry_id == entry.entry_id && candidate.kind == entry.kind)
            .expect("generation 2 must carry every generation-1 entry");
        // Byte identity, not merely "an entry with the same name": every
        // reference already frozen against a generation-1 entry digest still
        // resolves inside generation 2.
        assert_eq!(carried.digest().unwrap(), entry.digest().unwrap());
    }
    assert_eq!(
        two.package().entries.len(),
        one.package().entries.len() + 7 * GENERATION_TWO_CONNECTORS.len()
    );
    // A superset is a new package, never an edit of the old one.
    assert_ne!(two.package_digest(), one.package_digest());
}

#[test]
fn the_composition_is_deterministic() {
    assert_eq!(
        generation_two().package_digest(),
        generation_two().package_digest()
    );
}

#[test]
fn the_generation_two_package_closes_as_a_successor_target() {
    let two = generation_two();
    // The full offline closure the activation runtime runs: every connector
    // reference resolves, every recipe's dependency closure is consistent, and
    // exactly one activation policy is installable.
    SemanticallyClosedSuccessorPackage::from_manifest_verified(two.clone())
        .expect("the composed package must close semantically");
    StructurallyClosedSuccessorTargetV2::from_manifest_verified(&two)
        .expect("the composed package must be an activatable successor target");
}

#[test]
fn both_connector_schemas_name_a_version_form_canonical_resource() {
    let two = generation_two();
    for connector in GENERATION_TWO_CONNECTORS {
        let schema = resolve_connector_schema(&two, connector.connector_schema).unwrap();
        let reference = &schema.schema().canonical_resource_identity_recipe;
        let recipe =
            ValidatedIdentityRecipe::from_package(&two, &reference.entry_id, reference.version)
                .expect("the canonical-resource recipe must resolve inside the package");
        // The whole point of generation 2: what the connector derives is a
        // version-form resource, which is the only form the body plane chunks.
        assert_eq!(recipe.recipe().identity_form, IdentityForm::Version);
        assert_eq!(recipe.recipe().recipe_id.as_str(), connector.version_recipe);
        // And it is derivable: its parent entity resolves, uniquely, inside the
        // same package and the same namespace.
        let parent = resolve_parent_entity_recipe(&two, &recipe)
            .expect("the parent must resolve")
            .expect("a version recipe has a parent");
        assert_eq!(parent.recipe().identity_form, IdentityForm::Entity);
        assert_eq!(parent.recipe().recipe_id.as_str(), connector.entity_recipe);
        assert_eq!(
            parent.authority_namespace_id(),
            recipe.authority_namespace_id()
        );
        assert_eq!(
            parent.recipe().component_rules,
            recipe.recipe().component_rules
        );
    }
}

#[test]
fn the_two_connector_schemas_are_distinct_and_do_not_share_a_resource_space() {
    let two = generation_two();
    let git = resolve_connector_schema(&two, GIT_CONNECTOR.connector_schema).unwrap();
    let transcript = resolve_connector_schema(&two, TRANSCRIPT_CONNECTOR.connector_schema).unwrap();
    assert_ne!(
        git.schema().connector_schema_id,
        transcript.schema().connector_schema_id
    );
    // Distinct recipes mean a git object version and a transcript turn version
    // can never collide into one canonical resource even if their revisions
    // were byte-equal.
    assert_ne!(
        git.schema().canonical_resource_identity_recipe,
        transcript.schema().canonical_resource_identity_recipe
    );
    assert_ne!(
        git.schema().evidence_schema,
        transcript.schema().evidence_schema
    );
}

#[test]
fn generation_one_commit_recipe_has_no_derivable_parent() {
    // The finding this whole module exists because of. `identity.github.commit`
    // is a well-formed version recipe that resolves out of generation 1 — and
    // no locator can ever derive it, because its parent kind (`repository`)
    // has no entity recipe in `namespace.github.commit`. Pointing a connector
    // at it would have moved the failure from "occurrence form" to "no parent",
    // not fixed anything.
    let one = generation_one();
    let commit = ValidatedIdentityRecipe::from_package(
        &one,
        &ContractId::new(GEN1_COMMIT_RECIPE).unwrap(),
        3,
    )
    .expect("the frozen commit recipe resolves");
    assert_eq!(commit.recipe().identity_form, IdentityForm::Version);
    assert!(commit.parent_entity_kind().is_some());
    assert!(matches!(
        resolve_parent_entity_recipe(&one, &commit),
        Err(ContractError::InvalidIdentityRecipe(_))
    ));
}

#[test]
fn an_occurrence_recipe_has_no_parent_to_resolve() {
    let one = generation_one();
    let push = ValidatedIdentityRecipe::from_package(
        &one,
        &ContractId::new("identity.github.push").unwrap(),
        3,
    )
    .unwrap();
    assert_eq!(push.recipe().identity_form, IdentityForm::Occurrence);
    // Not an error: an occurrence has no parent, and asking is answered `None`.
    assert!(resolve_parent_entity_recipe(&one, &push).unwrap().is_none());
}

#[test]
fn composition_fails_closed_when_a_carried_forward_dependency_is_missing() {
    let one = generation_one();
    let mut package = one.package().clone();
    let removed = package
        .entries
        .iter()
        .position(|entry| entry.entry_id.as_str() == "identity.github.provider_instance")
        .unwrap();
    package.entries.remove(removed);
    package.manifest.remove(removed);
    // The mutilated package no longer closes, so it cannot even be
    // manifest-verified; compose from the raw shape to prove the composition
    // itself refuses rather than inventing the missing reference.
    let profile = package.profile.clone();
    let verified = ManifestVerifiedRegistryPackage::new(package, &profile);
    match verified {
        // Package validation caught it first, which is also fail-closed.
        Err(_) => {}
        Ok(verified) => {
            assert!(matches!(
                generation_two_registry_package(&verified),
                Err(ContractError::Schema(_))
            ));
        }
    }
}

#[test]
fn the_composed_evidence_schemas_bind_the_connector_resource_recipe() {
    // `close_connector_v2` requires the evidence schema to name exactly the
    // connector's canonical-resource recipe. If composition ever drifted, the
    // package would stop closing; this asserts the binding directly so the
    // reason is visible rather than hidden behind a generic closure error.
    let two = generation_two();
    for connector in GENERATION_TWO_CONNECTORS {
        let schema = resolve_connector_schema(&two, connector.connector_schema).unwrap();
        let evidence = two
            .package()
            .entries
            .iter()
            .find(|entry| entry.entry_id.as_str() == connector.evidence_schema)
            .unwrap();
        let body: EvidenceSchemaBodyV1 =
            decode_strict(&encode_canonical(&evidence.body).unwrap()).unwrap();
        assert_eq!(
            body.identity_recipe,
            schema.schema().canonical_resource_identity_recipe
        );
        assert!(body.canonical_payload_required);
        assert!(!body.private_raw_default_enabled);
    }
}
