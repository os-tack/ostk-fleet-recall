//! Offline proofs for the generation-3 registry package composition.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use super::*;
use crate::memory_contracts::common::{AuthenticatedProjectScopeV1, frozen_profile_reference_v1};
use crate::memory_contracts::generation2_registry::{
    GENERATION_TWO_CONNECTORS, resolve_connector_schema,
};
use crate::memory_contracts::identity::{
    ValidatedIdentityRecipe, derive_entity_from_components, derive_resource_uri,
    derive_version_parent, locator_from_components, resolve_parent_entity_recipe,
};
use crate::memory_contracts::successor_generic::StructurallyClosedSuccessorTargetV2;
use crate::memory_contracts::successor_package::SemanticallyClosedSuccessorPackage;

/// The checked-in canonical bytes, one LF-framed record.
const GENERATION_3_PACKAGE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v3/collected-items/registry-package.jsonl");

/// Where `regenerate_generation_three_package` writes those bytes.
const GENERATION_3_PACKAGE_PATH: &str =
    "contracts/dynamic-memory/v3/collected-items/registry-package.jsonl";

/// The generation-3 package digest every generation-3 head names.
const FROZEN_GENERATION_THREE_PACKAGE_DIGEST: &str =
    "b5103302073c26cd42d727e1f907acecb9803d7f3da7166dd0f98d29255ac54b";

fn generation_two() -> Arc<SemanticallyClosedSuccessorPackage> {
    crate::registry_witness::compiled_generation_two_package()
        .expect("the compiled generation-2 package closes")
}

fn generation_three() -> ManifestVerifiedRegistryPackage {
    generation_three_registry_package(generation_two().manifest_verified_package())
        .expect("the generation-3 composition must close")
}

fn reference(package: &ManifestVerifiedRegistryPackage, entry_id: &str) -> RegistryReferenceV1 {
    let entry = package
        .package()
        .entries
        .iter()
        .find(|entry| entry.entry_id.as_str() == entry_id)
        .unwrap_or_else(|| panic!("the package must carry {entry_id}"));
    reference_for(entry).unwrap()
}

fn recipe(package: &ManifestVerifiedRegistryPackage, recipe_id: &str) -> ValidatedIdentityRecipe {
    ValidatedIdentityRecipe::from_package(package, &ContractId::new(recipe_id).unwrap(), 1)
        .unwrap_or_else(|error| panic!("{recipe_id} must resolve: {error}"))
}

fn scope() -> AuthenticatedProjectScopeV1 {
    AuthenticatedProjectScopeV1::from_trusted_context(
        ContractId::new("tenant.acme").unwrap(),
        ContractId::new("project.recall").unwrap(),
    )
}

fn provider_scope_components(provider: &str, scope_id: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        (PROVIDER_KIND_COORDINATE.to_owned(), provider.to_owned()),
        (PROVIDER_SCOPE_ID_COORDINATE.to_owned(), scope_id.to_owned()),
    ])
}

#[test]
fn the_composition_reproduces_the_checked_in_bytes_and_the_frozen_digest() {
    let three = generation_three();
    let mut framed = three.canonical_bytes().to_vec();
    framed.push(b'\n');
    // The checked-in bytes are what the witness compiles in; a composition
    // that drifted from them would describe a package no head activates.
    assert!(
        framed == GENERATION_3_PACKAGE,
        "the composition no longer reproduces {GENERATION_3_PACKAGE_PATH}; if the change is \
         intended, it is a new generation, not an edit"
    );
    assert_eq!(
        three.package_digest().to_string(),
        FROZEN_GENERATION_THREE_PACKAGE_DIGEST
    );
    assert_eq!(
        crate::registry_witness::compiled_generation_three_package()
            .expect("the compiled generation-3 package closes")
            .package_digest(),
        three.package_digest()
    );
}

#[test]
fn every_generation_two_entry_is_carried_forward_and_only_the_family_is_new() {
    let two = generation_two();
    let three = generation_three();
    let carried: BTreeMap<_, _> = three
        .package()
        .entries
        .iter()
        .map(|entry| {
            (
                (entry.kind.as_str(), entry.entry_id.clone()),
                entry.digest().unwrap(),
            )
        })
        .collect();
    for entry in &two.manifest_verified_package().package().entries {
        // Byte identity: every reference frozen against a generation-2 entry
        // digest — the connectors, the remember route, the policies — still
        // resolves inside generation 3.
        assert_eq!(
            carried.get(&(entry.kind.as_str(), entry.entry_id.clone())),
            Some(&entry.digest().unwrap()),
            "{} must be carried forward unchanged",
            entry.entry_id
        );
    }
    let generation_two_ids: BTreeSet<&str> = two
        .manifest_verified_package()
        .package()
        .entries
        .iter()
        .map(|entry| entry.entry_id.as_str())
        .collect();
    let added: BTreeSet<&str> = three
        .package()
        .entries
        .iter()
        .map(|entry| entry.entry_id.as_str())
        .filter(|id| !generation_two_ids.contains(id))
        .collect();
    let family = COLLECTED_ITEM_FAMILY;
    let mut expected = BTreeSet::from([
        family.provider_scope_namespace,
        family.provider_scope_kind,
        family.provider_scope_recipe,
        family.item_namespace,
        family.item_revision_kind,
        family.item_version_kind,
        family.item_revision_recipe,
        family.item_version_recipe,
        family.evidence_schema,
    ]);
    expected.extend(family.connectors());
    assert_eq!(
        added, expected,
        "generation 3 adds exactly the collected-item family"
    );
    assert_ne!(three.package_digest(), two.package_digest());
}

#[test]
fn the_generation_three_package_closes_as_a_successor_target() {
    let three = generation_three();
    SemanticallyClosedSuccessorPackage::from_manifest_verified(three.clone())
        .expect("the composed package must close semantically");
    StructurallyClosedSuccessorTargetV2::from_manifest_verified(&three)
        .expect("the composed package must be an activatable successor target");
}

#[test]
fn every_collected_connector_resolves_and_closes_over_the_family() {
    let three = generation_three();
    let closed = SemanticallyClosedSuccessorPackage::from_manifest_verified(three.clone()).unwrap();
    let family = COLLECTED_ITEM_FAMILY;
    for connector in family.connectors() {
        let resolved = resolve_connector_schema(&three, connector)
            .unwrap_or_else(|error| panic!("{connector} must resolve: {error}"));
        assert!(
            closed
                .connector_schema(resolved.registry_reference())
                .is_some(),
            "{connector} must be a closed connector of the package"
        );
        let schema = resolved.schema();
        assert_eq!(
            schema.provider_namespace,
            reference(&three, family.provider_scope_namespace)
        );
        assert_eq!(
            schema.provider_instance_identity_recipe,
            reference(&three, family.provider_scope_recipe)
        );
        assert_eq!(
            schema.canonical_resource_identity_recipe,
            reference(&three, family.item_version_recipe)
        );
        assert_eq!(
            schema.evidence_schema,
            reference(&three, family.evidence_schema)
        );
        assert!(schema.authenticated_scope_required);
        assert!(!schema.delivery_id_in_semantic_identity);
        assert!(schema.immutable_revision_required);
    }
    let channels: BTreeSet<_> = family
        .connectors()
        .into_iter()
        .map(|connector| {
            resolve_connector_schema(&three, connector)
                .unwrap()
                .registry_reference()
                .clone()
        })
        .collect();
    assert_eq!(
        channels.len(),
        family.connectors().len(),
        "each trust channel is its own connector schema"
    );

    let evidence: EvidenceSchemaBodyV1 = decode_strict(
        &encode_canonical(
            &find_entry(three.package(), family.evidence_schema)
                .unwrap()
                .body,
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(evidence.evidence_kind.as_str(), family.evidence_kind);
    assert!(evidence.canonical_payload_required);
    assert!(!evidence.private_raw_default_enabled);
    for (carried, policy) in [
        (evidence.redaction_policy, GEN1_REDACTION_POLICY),
        (evidence.classifier_policy, GEN1_CLASSIFIER_POLICY),
        (evidence.retention_policy, GEN1_RETENTION_POLICY),
        (evidence.publication_rule, GEN1_PUBLICATION_RULE),
    ] {
        assert_eq!(carried, reference(&three, policy), "{policy} is carried");
    }
}

#[test]
fn the_item_version_recipe_is_version_form_and_the_scope_recipe_is_entity_form() {
    let three = generation_three();
    let family = COLLECTED_ITEM_FAMILY;
    let version = recipe(&three, family.item_version_recipe);
    assert_eq!(version.recipe().identity_form, IdentityForm::Version);
    let parent = resolve_parent_entity_recipe(&three, &version)
        .expect("the parent must resolve")
        .expect("a version recipe has a parent");
    assert_eq!(parent.recipe().identity_form, IdentityForm::Entity);
    assert_eq!(
        parent.recipe().recipe_id.as_str(),
        family.item_revision_recipe
    );
    assert_eq!(
        parent.authority_namespace_id(),
        version.authority_namespace_id()
    );

    let scope_recipe = recipe(&three, family.provider_scope_recipe);
    assert_eq!(scope_recipe.recipe().identity_form, IdentityForm::Entity);
    assert_eq!(
        scope_recipe.authority_namespace_id().as_str(),
        family.provider_scope_namespace
    );
}

#[test]
fn a_provider_scope_and_an_item_version_derive_resource_uris() {
    let three = generation_three();
    let family = COLLECTED_ITEM_FAMILY;
    let scope = scope();

    // The provider is data, not a registry entry: one recipe derives every
    // provider's scope, and different providers never share a URI.
    let scope_reference = reference(&three, family.provider_scope_recipe);
    let slack = derive_entity_from_components(
        &three,
        &scope_reference,
        &scope,
        &provider_scope_components("slack", "T0123ABCD"),
    )
    .expect("a Slack workspace derives a provider scope");
    assert_eq!(slack.uri().identity_form(), IdentityForm::Entity);
    assert_eq!(
        slack.uri().resource_kind().as_str(),
        family.provider_scope_kind
    );
    let linear = derive_entity_from_components(
        &three,
        &scope_reference,
        &scope,
        &provider_scope_components("linear", "T0123ABCD"),
    )
    .unwrap();
    assert_ne!(slack.uri(), linear.uri());
    // A coordinate that is not canonical NFC is refused, not normalized.
    assert!(
        derive_entity_from_components(
            &three,
            &scope_reference,
            &scope,
            &provider_scope_components("docs", "cafe\u{301}"),
        )
        .is_err()
    );

    // An item version is a version-form URI whose parent is derived from its
    // own immutable revision, never supplied.
    let version = recipe(&three, family.item_version_recipe);
    let components = BTreeMap::from([(SOURCE_OBJECT_COORDINATE.to_owned(), "ab".repeat(32))]);
    let unparented = locator_from_components(&version, &scope, None, &components).unwrap();
    let parent = derive_version_parent(
        &three,
        &frozen_profile_reference_v1(),
        &scope,
        &version,
        &unparented,
    )
    .unwrap()
    .expect("a version recipe derives its parent");
    assert_eq!(
        parent.uri().resource_kind().as_str(),
        family.item_revision_kind
    );
    let locator =
        locator_from_components(&version, &scope, Some(parent.uri()), &components).unwrap();
    let item = derive_resource_uri(
        &version.derivation_context(&scope),
        &locator,
        &version,
        Some(&parent),
    )
    .expect("an item version derives under its derived parent");
    assert_eq!(item.uri().identity_form(), IdentityForm::Version);
    assert_eq!(
        item.uri().resource_kind().as_str(),
        family.item_version_kind
    );
}

#[test]
fn the_remember_route_and_the_generation_two_connectors_still_resolve() {
    let two = generation_two();
    let three = SemanticallyClosedSuccessorPackage::from_manifest_verified(generation_three())
        .expect("generation 3 closes");
    let predicate = reference(
        three.manifest_verified_package(),
        "mcp.remember.allowed_actions",
    );
    assert!(
        three.remember_predicate(&predicate).is_some(),
        "mcp.remember.allowed_actions must still resolve as a remember predicate"
    );
    let route = three
        .remember_admission(&reference(
            three.manifest_verified_package(),
            "remember.actor_assertion",
        ))
        .expect("remember.actor_assertion must still resolve as a remember route");
    assert_eq!(route.predicate_schema, predicate);
    for connector in GENERATION_TWO_CONNECTORS
        .map(|ids| ids.connector_schema)
        .into_iter()
        .chain([GEN1_CONNECTOR_SCHEMA])
    {
        let before = resolve_connector_schema(two.manifest_verified_package(), connector).unwrap();
        let after = resolve_connector_schema(three.manifest_verified_package(), connector).unwrap();
        assert_eq!(before.registry_reference(), after.registry_reference());
        assert!(three.connector_schema(after.registry_reference()).is_some());
    }
}

#[test]
fn composition_fails_closed_when_a_carried_dependency_is_missing() {
    let mut package = generation_two()
        .manifest_verified_package()
        .package()
        .clone();
    let removed = package
        .entries
        .iter()
        .position(|entry| entry.entry_id.as_str() == GIT_CONNECTOR.version_recipe)
        .unwrap();
    package.entries.remove(removed);
    package.manifest.remove(removed);
    let profile = package.profile.clone();
    match ManifestVerifiedRegistryPackage::new(package, &profile) {
        // Package validation caught it first, which is also fail-closed.
        Err(_) => {}
        Ok(verified) => assert!(matches!(
            generation_three_registry_package(&verified),
            Err(super::super::ContractError::Schema(_))
        )),
    }
}

/// Rewrite the checked-in generation-3 bytes from the composition. Run it only
/// when the composition is deliberately changed before any head names it:
/// `cargo test -- --ignored regenerate_generation_three_package`.
#[test]
#[ignore = "maintainer-only generation-3 package regeneration"]
fn regenerate_generation_three_package() {
    let three = generation_three();
    let mut framed = three.canonical_bytes().to_vec();
    framed.push(b'\n');
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(GENERATION_3_PACKAGE_PATH);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, framed).unwrap();
    println!("PACKAGE_DIGEST {}", three.package_digest());
}
