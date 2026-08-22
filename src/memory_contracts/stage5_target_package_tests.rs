//! Offline closure and fail-closed rejection tests for the generation-2
//! semantically-closed target package (W2-PKG).

use std::str::FromStr;

use super::{
    ParserContractV2, SemanticallyClosedStage5Package, Stage5ComponentRole,
    Stage5PackageComponents, Stage5PackageError, Stage5PackageManifestV1,
};
use crate::memory_contracts::canonical::{CanonicalValue, decode_strict, encode_canonical};
use crate::memory_contracts::chunk_identity::{NormalizationRuleV1, ParserKeyV1};
use crate::memory_contracts::common::{
    CanonicalTimestamp, ContractId, HexBytes, RegistryReferenceV1,
};
use crate::memory_contracts::coverage::{
    ConnectorInstanceCursorV2, CoverageCompletenessV1, CoverageFreshnessV1, CoverageProofBasisV1,
    CoverageProofMethodV1, CoverageProofV2, CoverageScopeV1, CoverageWindowV1, FreshnessStateV1,
    SequenceContinuityV1,
};
use crate::memory_contracts::digest::{DigestDomain, Sha256Digest, domain_separated_digest};
use crate::memory_contracts::evidence_v2::{
    ConnectorInstanceBindingV2, ConnectorSchemaV2, ConsistencyKeyDerivationV1,
    ConsistencyPartitionFamilyV1, ConsistencyPartitionRecipeV1,
    StructurallyResolvedConnectorSchemaV2,
};
use crate::memory_contracts::identity::ResourceUri;
use crate::memory_contracts::registry::{RegistryEntryKind, RegistryEntryV1};

fn d(label: &str) -> Sha256Digest {
    domain_separated_digest(DigestDomain::RegistryEntry, label.as_bytes())
}

fn reg_ref(id: &str, version: u32, label: &str) -> RegistryReferenceV1 {
    RegistryReferenceV1 {
        entry_id: ContractId::new(id).unwrap(),
        version,
        entry_digest: d(label),
    }
}

fn connector_schema(schema_id: &str, scope_ok: bool) -> ConnectorSchemaV2 {
    ConnectorSchemaV2 {
        schema_version: 2,
        connector_schema_id: ContractId::new(schema_id).unwrap(),
        version: 2,
        provider_namespace: reg_ref(&format!("namespace.{schema_id}"), 1, schema_id),
        evidence_schema: reg_ref(&format!("evidence.{schema_id}"), 2, schema_id),
        provider_instance_identity_recipe: reg_ref(
            &format!("identity.{schema_id}.instance"),
            1,
            schema_id,
        ),
        canonical_resource_identity_recipe: reg_ref(
            &format!("identity.{schema_id}.resource"),
            2,
            schema_id,
        ),
        consistency_partition_recipe: ConsistencyPartitionRecipeV1 {
            schema_version: 1,
            recipe_id: ContractId::new("ostk.consistency.source_fact_id").unwrap(),
            recipe_version: 1,
            family: ConsistencyPartitionFamilyV1::SourceFact,
            key_derivation: ConsistencyKeyDerivationV1::SourceFactId,
        },
        // scope_ok == false models a connector that would let an ingress payload
        // select the authenticated scope: the resolver must reject it.
        authenticated_scope_required: scope_ok,
        delivery_id_in_semantic_identity: false,
        immutable_revision_required: true,
    }
}

fn connector_entry(schema: &ConnectorSchemaV2) -> RegistryEntryV1 {
    let body_bytes = encode_canonical(schema).unwrap();
    let body: CanonicalValue = decode_strict(&body_bytes).unwrap();
    RegistryEntryV1 {
        schema_version: 1,
        kind: RegistryEntryKind::ConnectorSchema,
        entry_id: schema.connector_schema_id.clone(),
        version: schema.version,
        entry_schema_id: ContractId::new("registry.connector_schema").unwrap(),
        entry_schema_version: 2,
        body,
        positive_vector_digest: d(&format!("{}-ok", schema.connector_schema_id.as_str())),
        negative_vector_digest: d(&format!("{}-bad", schema.connector_schema_id.as_str())),
    }
}

fn resolved(schema_id: &str) -> StructurallyResolvedConnectorSchemaV2 {
    StructurallyResolvedConnectorSchemaV2::from_registry_entry(&connector_entry(&connector_schema(
        schema_id, true,
    )))
    .unwrap()
}

fn instance(schema_id: &str, instance_id: &str) -> ConnectorInstanceBindingV2 {
    resolved(schema_id)
        .bind_instance(ContractId::new(instance_id).unwrap())
        .unwrap()
}

fn cursor(instance_id: &str, byte: u8) -> ConnectorInstanceCursorV2 {
    ConnectorInstanceCursorV2 {
        connector_instance_id: ContractId::new(instance_id).unwrap(),
        cursor: HexBytes::new(vec![byte, byte, byte]).unwrap(),
        completeness: CoverageCompletenessV1::Complete,
        continuity: SequenceContinuityV1::Contiguous {},
    }
}

fn resource_uri() -> ResourceUri {
    ResourceUri::from_str(&format!(
        "urn:ostk:entity:v1:repository:sha256:{}",
        "1".repeat(64)
    ))
    .unwrap()
}

fn coverage(instances: Vec<ConnectorInstanceCursorV2>) -> CoverageProofV2 {
    CoverageProofV2 {
        schema_version: 2,
        scope: CoverageScopeV1 {
            scope: resource_uri(),
            revision: HexBytes::new(vec![0x22; 32]).unwrap(),
            window: CoverageWindowV1 {
                window_start: CanonicalTimestamp::parse("2026-08-14T00:00:00.000000000Z").unwrap(),
                window_end: CanonicalTimestamp::parse("2026-08-15T00:00:00.000000000Z").unwrap(),
            },
        },
        freshness: CoverageFreshnessV1 {
            state: FreshnessStateV1::Current,
            freshness_rule: reg_ref("coverage.freshness.default_rule", 1, "freshness"),
        },
        proof_basis: CoverageProofBasisV1 {
            method: CoverageProofMethodV1::ClosedCursorInterval,
            proof_method_registration: reg_ref("coverage.proof.cursor_interval", 1, "proof-method"),
        },
        observed_through: CanonicalTimestamp::parse("2026-08-15T00:00:00.000000000Z").unwrap(),
        instances,
    }
}

fn parser(rules: Vec<NormalizationRuleV1>) -> ParserContractV2 {
    ParserContractV2 {
        schema_version: 2,
        parser_contract_id: ContractId::new("parser.transcript_and_history").unwrap(),
        version: 3,
        parser_key: ParserKeyV1 {
            schema_version: 1,
            parser_artifact_digest: d("parser-artifact"),
            parser_version: 4,
            configuration_digest: d("parser-config"),
            declared_normalization_rules: rules,
        },
    }
}

const TRANSCRIPT: &str = "connector.transcript";
const HISTORY: &str = "connector.version_history";
const TRANSCRIPT_INSTANCE: &str = "instance.transcript.main";
const HISTORY_INSTANCE: &str = "instance.history.main";

fn components() -> Stage5PackageComponents {
    Stage5PackageComponents {
        transcript_connector: instance(TRANSCRIPT, TRANSCRIPT_INSTANCE),
        version_history_connector: instance(HISTORY, HISTORY_INSTANCE),
        coverage: coverage(vec![
            cursor(HISTORY_INSTANCE, 0xAB),
            cursor(TRANSCRIPT_INSTANCE, 0xCD),
        ]),
        parser: parser(vec![
            NormalizationRuleV1::NewlineLf,
            NormalizationRuleV1::UnicodeNfc,
        ]),
        remember_predicate: reg_ref("mcp.remember.allowed_actions", 3, "remember-predicate"),
        remember_admission: reg_ref("remember.actor_assertion", 3, "remember-admission"),
        activation_policy: reg_ref("activation.default", 2, "activation-policy"),
        relation_proof: reg_ref("relation.repository_parent", 2, "relation-proof"),
        observer_admission: reg_ref("observer.default", 2, "observer-admission"),
        episode_policy: reg_ref("episode.default", 2, "episode-policy"),
        normative_binding: reg_ref("normative.default", 2, "normative-binding"),
    }
}

#[test]
fn composes_closes_and_round_trips() {
    let package = SemanticallyClosedStage5Package::from_components(components()).unwrap();
    assert_eq!(package.manifest().components.len(), 11);
    assert_eq!(
        package.manifest().components[0].role,
        Stage5ComponentRole::TranscriptConnector
    );
    assert_eq!(
        package.manifest().components[10].role,
        Stage5ComponentRole::NormativeBinding
    );

    // canonical_bytes round-trips to the same content-addressed package digest.
    let verified =
        SemanticallyClosedStage5Package::verify_canonical_bytes(package.canonical_bytes()).unwrap();
    assert_eq!(verified, package.package_digest());

    // Rebuilding the same components yields the same identity (determinism).
    let again = SemanticallyClosedStage5Package::from_components(components()).unwrap();
    assert_eq!(again.package_digest(), package.package_digest());

    // The resolve-against-components activation gate accepts the exact package.
    let resolved = SemanticallyClosedStage5Package::from_canonical_bytes_and_components(
        package.canonical_bytes(),
        components(),
    )
    .unwrap();
    assert_eq!(resolved.package_digest(), package.package_digest());
}

#[test]
fn every_component_digest_is_present_and_nonzero() {
    let package = SemanticallyClosedStage5Package::from_components(components()).unwrap();
    for component in &package.manifest().components {
        assert_ne!(component.component_digest, Sha256Digest::ZERO);
        assert_ne!(component.version, 0);
    }
    // The two connector components carry the two distinct connector instances.
    assert_ne!(
        package.transcript_connector().connector_instance_id(),
        package.version_history_connector().connector_instance_id()
    );
    assert!(
        package
            .coverage_proof()
            .covers_instance(package.transcript_connector().connector_instance_id())
    );
    assert!(
        package
            .coverage_proof()
            .covers_instance(package.version_history_connector().connector_instance_id())
    );
}

#[test]
fn duplicate_connector_instance_is_rejected() {
    let mut parts = components();
    parts.version_history_connector = instance(HISTORY, TRANSCRIPT_INSTANCE);
    // Coverage still covers both ids, but the instance ids now collide.
    parts.coverage = coverage(vec![cursor(TRANSCRIPT_INSTANCE, 0xCD)]);
    assert_eq!(
        SemanticallyClosedStage5Package::from_components(parts),
        Err(Stage5PackageError::DuplicateConnectorInstance)
    );
}

#[test]
fn colliding_connector_schema_is_rejected() {
    let mut parts = components();
    // Same schema id under a different instance id: two instances of one schema
    // is not two connectors.
    parts.version_history_connector = instance(TRANSCRIPT, HISTORY_INSTANCE);
    assert_eq!(
        SemanticallyClosedStage5Package::from_components(parts),
        Err(Stage5PackageError::ConnectorSchemaCollision)
    );
}

#[test]
fn payload_selected_connector_scope_is_rejected_at_resolution() {
    // A connector that would let an ingress payload choose the authenticated
    // scope cannot even resolve, so it can never enter a package or activation.
    let bad = connector_entry(&connector_schema(TRANSCRIPT, false));
    assert!(StructurallyResolvedConnectorSchemaV2::from_registry_entry(&bad).is_err());
}

#[test]
fn coverage_missing_a_connector_is_rejected() {
    let mut parts = components();
    parts.coverage = coverage(vec![cursor(TRANSCRIPT_INSTANCE, 0xCD)]);
    assert_eq!(
        SemanticallyClosedStage5Package::from_components(parts),
        Err(Stage5PackageError::CoverageDoesNotCoverConnectors)
    );
}

#[test]
fn dangling_component_reference_is_rejected() {
    let mut parts = components();
    parts.observer_admission.entry_digest = Sha256Digest::ZERO;
    assert_eq!(
        SemanticallyClosedStage5Package::from_components(parts),
        Err(Stage5PackageError::DanglingComponentReference)
    );
}

#[test]
fn component_digest_mismatch_fails_closed() {
    let package = SemanticallyClosedStage5Package::from_components(components()).unwrap();
    // Same shape, but the parser configuration differs, so its component digest
    // no longer matches the bytes the package committed to.
    let mut tampered = components();
    tampered.parser = parser(vec![NormalizationRuleV1::WhitespaceCollapse]);
    assert_eq!(
        SemanticallyClosedStage5Package::from_canonical_bytes_and_components(
            package.canonical_bytes(),
            tampered,
        ),
        Err(Stage5PackageError::ComponentDigestMismatch)
    );
}

#[test]
fn non_canonical_or_wrong_shape_manifest_is_rejected() {
    // Not canonical JSON at all.
    assert_eq!(
        SemanticallyClosedStage5Package::verify_canonical_bytes(b"{ }"),
        Err(Stage5PackageError::NonCanonicalManifest)
    );
    // Canonical bytes that decode to a manifest of the wrong generation and
    // empty component set are rejected structurally.
    let wrong = Stage5PackageManifestV1 {
        schema_version: 1,
        generation: 3,
        components: Vec::new(),
    };
    let bytes = encode_canonical(&wrong).unwrap();
    assert_eq!(
        SemanticallyClosedStage5Package::verify_canonical_bytes(&bytes),
        Err(Stage5PackageError::NonCanonicalManifest)
    );
}

#[test]
fn parser_contract_identity_binds_normalization_configuration() {
    let a = parser(vec![NormalizationRuleV1::NewlineLf])
        .contract_id()
        .unwrap();
    let b = parser(vec![
        NormalizationRuleV1::NewlineLf,
        NormalizationRuleV1::UnicodeNfc,
    ])
    .contract_id()
    .unwrap();
    assert_ne!(
        a, b,
        "declared normalization rules are part of parser identity"
    );
}

#[test]
fn coverage_proof_requires_sorted_unique_instances() {
    // Reversed order is not strictly ascending by instance id.
    let unsorted = coverage(vec![
        cursor(TRANSCRIPT_INSTANCE, 0xCD),
        cursor(HISTORY_INSTANCE, 0xAB),
    ]);
    assert!(matches!(
        unsorted.proof_id(),
        Err(crate::memory_contracts::ContractError::NonCanonicalSet { .. })
    ));
    // An empty instance set is rejected.
    assert!(coverage(vec![]).proof_id().is_err());
    // A well-formed, sorted set is accepted.
    assert!(
        coverage(vec![
            cursor(HISTORY_INSTANCE, 0xAB),
            cursor(TRANSCRIPT_INSTANCE, 0xCD),
        ])
        .proof_id()
        .is_ok()
    );
}

#[test]
fn changing_any_component_changes_the_package_identity() {
    let base = SemanticallyClosedStage5Package::from_components(components())
        .unwrap()
        .package_digest();
    let mut parts = components();
    parts.activation_policy = reg_ref("activation.default", 3, "activation-policy-v3");
    let moved = SemanticallyClosedStage5Package::from_components(parts)
        .unwrap()
        .package_digest();
    assert_ne!(base, moved);
}
