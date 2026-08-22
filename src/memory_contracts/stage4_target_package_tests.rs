use std::{fs, path::Path};

use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest as _, Sha256};

use super::*;
use crate::memory_contracts::{
    canonical::{CanonicalValue, require_canonical},
    common::frozen_profile_reference_v1,
    digest::{DigestDomain, domain_separated_digest},
    evidence::RetentionClass,
    evidence_v2::{
        ConnectorSchemaV2, ConsistencyKeyDerivationV1, ConsistencyPartitionFamilyV1,
        ConsistencyPartitionRecipeV1,
    },
    genesis::{
        AbsenceSemanticsV1, PredicateComparatorV1, PropositionModalityV1, PublicationDefaultV1,
        RelationMultiplicityV1, SensitivityDefaultV1,
    },
    identity::{AuthorityNamespaceV1, IdentityComponentRuleV1, IdentityForm, LocatorEncoding},
    registry::{ManifestVerifiedRegistryPackage, RegistryManifestEntryV1, RegistryPackageV1},
    relation::RelationAttestationVerdictV1,
    relation_policy_v2::{RelationAdmissionBasisRuleV2, RelationProofEntryV2},
    remember_v2::{
        ApplicabilityDimensionRuleV2, RememberAdmissionBasisRuleV2, RememberAssertionKindV2,
        RememberEffectiveIntervalRuleV2, RememberValueConstraintV2, ResourceIdentityConstraintV2,
    },
};

const ACTIVATION_ENTRY_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v2/successor-policy/activation-policy-v2.jsonl");
const GENESIS_PACKAGE_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v1/genesis-registry-package.jsonl");
const ENTRY_POSITIVE_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v2/stage4-successor/entry-positive-vectors.jsonl"
);
const ENTRY_NEGATIVE_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v2/stage4-successor/entry-negative-vectors.jsonl"
);
const PACKAGE_POSITIVE_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v2/stage4-successor/positive-vectors.jsonl");
const PACKAGE_NEGATIVE_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v2/stage4-successor/negative-vectors.jsonl");
const PACKAGE_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v2/stage4-successor/registry-package.jsonl");
const VECTOR_SUITE_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v2/stage4-successor/vector-suite.jsonl");

const PACKAGE_RAW_SHA256: &str = "6e6a8eafe34913cc472ee9d970ddc23588568e9738040d464e1193d378e9f323";
const ENTRY_POSITIVE_RAW_SHA256: &str =
    "9856ee9037c658687295b02d6463e932fbe569c59842d44876dd370f3f682bb0";
const ENTRY_NEGATIVE_RAW_SHA256: &str =
    "e0fbf541359fa607471675b41abecb23ce6d0a0d9d4358c738f694ec79178e7a";
const PACKAGE_POSITIVE_RAW_SHA256: &str =
    "b3437f8538545b4e32dff8baffa9e3e0006d9cd2c9c5c444425d1a22e431dd8f";
const PACKAGE_NEGATIVE_RAW_SHA256: &str =
    "f0a443ce82917038abfbbce85d2fdfab1d279175e5795da456ab7af5bd744d4b";
const VECTOR_SUITE_DIGEST_HEX: &str =
    "9ea1e713be391b7c510135deb0c53cdb6e709a888f3e50df0f304c2dc940a656";
const VECTOR_SUITE_RAW_SHA256: &str =
    "c6e4b30b0b9d63502e9c5126388ab9f1d75b0d2a495d821d5d7c3072affad4fd";

const FIXTURE_AUTHORITY: &str = "test_only_no_runtime_authority";
const CONSISTENCY_RECIPE_ID: &str = "ostk.consistency.source_fact_id";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EntryCaseManifestV1 {
    schema_version: u32,
    suite_id: ContractId,
    expected_outcome: ContractId,
    fixture_authority: String,
    cases: Vec<ContractId>,
}

impl EntryCaseManifestV1 {
    fn validate(&self) -> ContractResult<()> {
        if self.schema_version != 1
            || !matches!(self.expected_outcome.as_str(), "accept" | "reject")
            || self.fixture_authority != FIXTURE_AUTHORITY
            || self.cases.is_empty()
            || !strictly_sorted(&self.cases)
        {
            return Err(schema("invalid Stage-4 entry-case manifest"));
        }
        encode_canonical(self)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageCaseManifestV1 {
    schema_version: u32,
    suite_id: ContractId,
    expected_outcome: ContractId,
    fixture_authority: String,
    cases: Vec<ContractId>,
    entry_pins: Vec<RegistryManifestEntryV1>,
}

impl PackageCaseManifestV1 {
    fn validate(&self) -> ContractResult<()> {
        if self.schema_version != 1
            || !matches!(self.expected_outcome.as_str(), "accept" | "reject")
            || self.fixture_authority != FIXTURE_AUTHORITY
            || self.cases.is_empty()
            || !strictly_sorted(&self.cases)
            || self.entry_pins.len() != TARGET_ENTRY_COUNT
        {
            return Err(schema("invalid Stage-4 package-case manifest"));
        }
        encode_canonical(self)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stage4VectorSuiteV1 {
    schema_version: u32,
    suite_id: ContractId,
    fixture_authority: String,
    entry_positive_path: String,
    entry_positive_digest: Sha256Digest,
    entry_positive_raw_sha256: String,
    entry_negative_path: String,
    entry_negative_digest: Sha256Digest,
    entry_negative_raw_sha256: String,
    package_positive_path: String,
    package_positive_digest: Sha256Digest,
    package_positive_raw_sha256: String,
    package_negative_path: String,
    package_negative_digest: Sha256Digest,
    package_negative_raw_sha256: String,
    package_path: String,
    package_digest: Sha256Digest,
    package_raw_sha256: String,
    entry_pins: Vec<RegistryManifestEntryV1>,
}

fn record(bytes: &[u8]) -> &[u8] {
    let body = bytes
        .strip_suffix(b"\n")
        .expect("fixture must have exactly one repository-framing LF");
    assert!(!body.ends_with(b"\n"));
    assert!(!body.contains(&b'\r'));
    body
}

fn id(value: &str) -> ContractId {
    ContractId::new(value).unwrap()
}

fn ids(values: &[&str]) -> Vec<ContractId> {
    values.iter().map(|value| id(value)).collect()
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn raw_sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn framed_raw_sha256(bytes: &[u8]) -> String {
    let mut framed = bytes.to_vec();
    framed.push(b'\n');
    raw_sha256(&framed)
}

fn vector_digest<T: Serialize>(value: &T) -> Sha256Digest {
    domain_separated_digest(
        DigestDomain::TestVectorManifest,
        &encode_canonical(value).unwrap(),
    )
}

fn canonical_value<T: Serialize>(value: &T) -> CanonicalValue {
    decode_strict(&encode_canonical(value).unwrap()).unwrap()
}

fn reference(entry: &RegistryEntryV1) -> RegistryReferenceV1 {
    RegistryReferenceV1 {
        entry_id: entry.entry_id.clone(),
        version: entry.version,
        entry_digest: entry.digest().unwrap(),
    }
}

fn entry(
    kind: RegistryEntryKind,
    entry_id: &str,
    version: u32,
    entry_schema_version: u32,
    body: CanonicalValue,
    positive_vector_digest: Sha256Digest,
    negative_vector_digest: Sha256Digest,
) -> RegistryEntryV1 {
    RegistryEntryV1 {
        schema_version: 1,
        kind,
        entry_id: id(entry_id),
        version,
        entry_schema_id: id(schema_id(kind, entry_schema_version)),
        entry_schema_version,
        body,
        positive_vector_digest,
        negative_vector_digest,
    }
}

fn legacy_entry<T: Serialize>(
    kind: RegistryEntryKind,
    entry_id: &str,
    body: &T,
    positive: Sha256Digest,
    negative: Sha256Digest,
) -> RegistryEntryV1 {
    entry(
        kind,
        entry_id,
        3,
        1,
        canonical_value(body),
        positive,
        negative,
    )
}

fn entry_positive_cases() -> EntryCaseManifestV1 {
    EntryCaseManifestV1 {
        schema_version: 1,
        suite_id: id("ostk.stage4.entry.positive.v1"),
        expected_outcome: id("accept"),
        fixture_authority: FIXTURE_AUTHORITY.into(),
        cases: ids(&[
            "exact_body_identity",
            "exact_dependency_digest",
            "fail_closed_governance",
            "frozen_logical_revision",
            "typed_identity_closure",
        ]),
    }
}

fn entry_negative_cases() -> EntryCaseManifestV1 {
    EntryCaseManifestV1 {
        schema_version: 1,
        suite_id: id("ostk.stage4.entry.negative.v1"),
        expected_outcome: id("reject"),
        fixture_authority: FIXTURE_AUTHORITY.into(),
        cases: ids(&[
            "dependency_digest_substitution",
            "fail_open_governance",
            "identity_kind_mismatch",
            "unknown_selector",
            "wrong_logical_revision",
        ]),
    }
}

fn package_positive_cases(entries: &[RegistryEntryV1]) -> PackageCaseManifestV1 {
    PackageCaseManifestV1 {
        schema_version: 1,
        suite_id: id("ostk.stage4.package.positive.v1"),
        expected_outcome: id("accept"),
        fixture_authority: FIXTURE_AUTHORITY.into(),
        cases: ids(&[
            "exact_27_entry_inventory",
            "exact_capability_roots",
            "full_root_reachability",
            "identity_governance_compatibility",
            "no_active_legacy_relation",
            "unique_server_routes",
        ]),
        entry_pins: manifest(entries),
    }
}

fn package_negative_cases(entries: &[RegistryEntryV1]) -> PackageCaseManifestV1 {
    PackageCaseManifestV1 {
        schema_version: 1,
        suite_id: id("ostk.stage4.package.negative.v1"),
        expected_outcome: id("reject"),
        fixture_authority: FIXTURE_AUTHORITY.into(),
        cases: ids(&[
            "active_legacy_relation",
            "ambiguous_connector_route",
            "ambiguous_relation_route",
            "ambiguous_remember_route",
            "entry_pin_mismatch",
            "extra_unreachable_entry",
            "governance_mismatch",
            "missing_reachable_entry",
            "package_pin_mismatch",
        ]),
        entry_pins: manifest(entries),
    }
}

fn component(key: &str, encoding: LocatorEncoding) -> IdentityComponentRuleV1 {
    IdentityComponentRuleV1 {
        key: id(key),
        encoding,
    }
}

fn namespace(
    namespace_id: &str,
    keys: &[&str],
    positive: Sha256Digest,
    negative: Sha256Digest,
) -> RegistryEntryV1 {
    legacy_entry(
        RegistryEntryKind::NamespaceDefinition,
        namespace_id,
        &AuthorityNamespaceV1 {
            schema_version: 1,
            namespace_id: id(namespace_id),
            version: 3,
            immutable_coordinate_keys: ids(keys),
        },
        positive,
        negative,
    )
}

fn resource_kind(
    kind_id: &str,
    identity_form: IdentityForm,
    parent: Option<RegistryReferenceV1>,
    components: Vec<IdentityComponentRuleV1>,
    positive: Sha256Digest,
    negative: Sha256Digest,
) -> RegistryEntryV1 {
    legacy_entry(
        RegistryEntryKind::ResourceKindSchema,
        kind_id,
        &ResourceKindSchemaV1 {
            schema_version: 1,
            resource_kind: id(kind_id),
            version: 3,
            identity_form,
            parent_entity_kind: parent,
            component_rules: components,
        },
        positive,
        negative,
    )
}

fn identity_recipe(
    recipe_id: &str,
    kind: &RegistryEntryV1,
    namespace: &RegistryEntryV1,
    identity_form: IdentityForm,
    components: Vec<IdentityComponentRuleV1>,
    positive: Sha256Digest,
    negative: Sha256Digest,
) -> RegistryEntryV1 {
    legacy_entry(
        RegistryEntryKind::IdentityRecipe,
        recipe_id,
        &IdentityRecipeV1 {
            schema_version: 1,
            recipe_id: id(recipe_id),
            version: 3,
            resource_kind: kind.entry_id.clone(),
            identity_form,
            authority_namespace: reference(namespace),
            resource_kind_schema: reference(kind),
            component_rules: components,
        },
        positive,
        negative,
    )
}

fn identity_constraint(
    kind: &RegistryEntryV1,
    recipe: &RegistryEntryV1,
) -> ResourceIdentityConstraintV2 {
    ResourceIdentityConstraintV2 {
        resource_kind_schema: reference(kind),
        identity_recipe: reference(recipe),
    }
}

#[allow(clippy::too_many_lines)]
fn target_entries() -> Vec<RegistryEntryV1> {
    let positive_cases = entry_positive_cases();
    let negative_cases = entry_negative_cases();
    positive_cases.validate().unwrap();
    negative_cases.validate().unwrap();
    let entry_positive = vector_digest(&positive_cases);
    let entry_negative = vector_digest(&negative_cases);

    let activation: RegistryEntryV1 = decode_strict(record(ACTIVATION_ENTRY_FIXTURE)).unwrap();

    let applicability = legacy_entry(
        RegistryEntryKind::ApplicabilityEvaluator,
        "applicability.default",
        &json!({
            "schema_version": 1,
            "evaluator_id": "applicability.default",
            "version": 3,
            "missing_dimension_outcome": "unknown",
            "null_dimension_outcome": "unknown",
            "explicit_any_enabled": true,
            "same_concrete_context_required": true,
            "receipt_order_tiebreaker_allowed": false
        }),
        entry_positive,
        entry_negative,
    );
    let classifier = legacy_entry(
        RegistryEntryKind::ClassifierPolicy,
        "classifier.default",
        &json!({
            "schema_version": 1,
            "policy_id": "classifier.default",
            "version": 3,
            "server_derived": true,
            "classify_before_projection": true,
            "default_visibility": VisibilityClass::Private,
            "default_publication": PublicationClass::Denied,
            "failure_outcome": "withhold"
        }),
        entry_positive,
        entry_negative,
    );
    let redaction = legacy_entry(
        RegistryEntryKind::RedactionPolicy,
        "redaction.default",
        &json!({
            "schema_version": 1,
            "policy_id": "redaction.default",
            "version": 3,
            "redact_before_durable_outbox": true,
            "secrets_allowed_in_recall": false,
            "failure_outcome": "withhold"
        }),
        entry_positive,
        entry_negative,
    );
    let retention = legacy_entry(
        RegistryEntryKind::RetentionPolicy,
        "retention.default",
        &json!({
            "schema_version": 1,
            "policy_id": "retention.default",
            "version": 3,
            "default_retention": RetentionClass::Governed,
            "erasure_index_required": true,
            "tombstones_before_restore": true,
            "private_raw_separate_key": true,
            "failure_outcome": "withhold"
        }),
        entry_positive,
        entry_negative,
    );
    let exemplar = legacy_entry(
        RegistryEntryKind::ExemplarPolicy,
        "exemplar.private",
        &json!({
            "schema_version": 1,
            "policy_id": "exemplar.private",
            "version": 3,
            "selector": "deterministic_stratified_hash_v1",
            "private_max_count": 8,
            "private_max_each_bytes": 1024,
            "private_max_total_bytes": 8192,
            "public_enabled": false,
            "public_max_count": 0,
            "public_max_each_bytes": 0,
            "public_max_total_bytes": 0,
            "raw_lines_allowed": false,
            "headers_allowed": false
        }),
        entry_positive,
        entry_negative,
    );
    let publication = legacy_entry(
        RegistryEntryKind::PublicationRule,
        "publication.default",
        &json!({
            "schema_version": 1,
            "rule_id": "publication.default",
            "version": 3,
            "exemplar_policy": reference(&exemplar),
            "default_publication": PublicationDefaultV1::Denied,
            "classification_before_projection_required": true,
            "private_material_allowed": false,
            "raw_content_references_allowed": false
        }),
        entry_positive,
        entry_negative,
    );

    let provider_instance_namespace = namespace(
        "namespace.github.provider_instance",
        &["provider_installation_id"],
        entry_positive,
        entry_negative,
    );
    let provider_event_namespace = namespace(
        "namespace.github.push",
        &["immutable_revision", "provider_object_id"],
        entry_positive,
        entry_negative,
    );
    let repository_namespace = namespace(
        "namespace.github.repository",
        &["provider_repository_id"],
        entry_positive,
        entry_negative,
    );
    let commit_namespace = namespace(
        "namespace.github.commit",
        &["commit_oid"],
        entry_positive,
        entry_negative,
    );
    let environment_namespace = namespace(
        "namespace.runtime.environment",
        &["environment_id"],
        entry_positive,
        entry_negative,
    );

    let provider_instance_components = vec![component(
        "provider_installation_id",
        LocatorEncoding::Decimal,
    )];
    let provider_event_components = vec![
        component("immutable_revision", LocatorEncoding::HexBytes),
        component("provider_object_id", LocatorEncoding::HexBytes),
    ];
    let repository_components = vec![component(
        "provider_repository_id",
        LocatorEncoding::Decimal,
    )];
    let commit_components = vec![component("commit_oid", LocatorEncoding::HexBytes)];
    let environment_components = vec![component("environment_id", LocatorEncoding::NfcUtf8)];

    let provider_instance_kind = resource_kind(
        "provider_instance",
        IdentityForm::Entity,
        None,
        provider_instance_components.clone(),
        entry_positive,
        entry_negative,
    );
    let provider_event_kind = resource_kind(
        "provider_event",
        IdentityForm::Occurrence,
        None,
        provider_event_components.clone(),
        entry_positive,
        entry_negative,
    );
    let repository_kind = resource_kind(
        "repository",
        IdentityForm::Entity,
        None,
        repository_components.clone(),
        entry_positive,
        entry_negative,
    );
    let commit_kind = resource_kind(
        "commit",
        IdentityForm::Version,
        Some(reference(&repository_kind)),
        commit_components.clone(),
        entry_positive,
        entry_negative,
    );
    let environment_kind = resource_kind(
        "environment",
        IdentityForm::Entity,
        None,
        environment_components.clone(),
        entry_positive,
        entry_negative,
    );

    let provider_instance_recipe = identity_recipe(
        "identity.github.provider_instance",
        &provider_instance_kind,
        &provider_instance_namespace,
        IdentityForm::Entity,
        provider_instance_components,
        entry_positive,
        entry_negative,
    );
    let provider_event_recipe = identity_recipe(
        "identity.github.push",
        &provider_event_kind,
        &provider_event_namespace,
        IdentityForm::Occurrence,
        provider_event_components,
        entry_positive,
        entry_negative,
    );
    let repository_recipe = identity_recipe(
        "identity.github.repository",
        &repository_kind,
        &repository_namespace,
        IdentityForm::Entity,
        repository_components,
        entry_positive,
        entry_negative,
    );
    let commit_recipe = identity_recipe(
        "identity.github.commit",
        &commit_kind,
        &commit_namespace,
        IdentityForm::Version,
        commit_components,
        entry_positive,
        entry_negative,
    );
    let environment_recipe = identity_recipe(
        "identity.runtime.environment",
        &environment_kind,
        &environment_namespace,
        IdentityForm::Entity,
        environment_components,
        entry_positive,
        entry_negative,
    );

    let evidence = legacy_entry(
        RegistryEntryKind::EvidenceSchema,
        "evidence.github.push",
        &json!({
            "schema_version": 1,
            "evidence_schema_id": "evidence.github.push",
            "version": 3,
            "evidence_kind": "github.push",
            "identity_recipe": reference(&provider_event_recipe),
            "redaction_policy": reference(&redaction),
            "classifier_policy": reference(&classifier),
            "retention_policy": reference(&retention),
            "publication_rule": reference(&publication),
            "canonical_payload_required": true,
            "private_raw_default_enabled": false
        }),
        entry_positive,
        entry_negative,
    );

    let connector = entry(
        RegistryEntryKind::ConnectorSchema,
        "connector.github.push",
        3,
        2,
        canonical_value(&ConnectorSchemaV2 {
            schema_version: 2,
            connector_schema_id: id("connector.github.push"),
            version: 3,
            provider_namespace: reference(&provider_instance_namespace),
            evidence_schema: reference(&evidence),
            provider_instance_identity_recipe: reference(&provider_instance_recipe),
            canonical_resource_identity_recipe: reference(&provider_event_recipe),
            consistency_partition_recipe: ConsistencyPartitionRecipeV1 {
                schema_version: 1,
                recipe_id: id(CONSISTENCY_RECIPE_ID),
                recipe_version: 1,
                family: ConsistencyPartitionFamilyV1::SourceFact,
                key_derivation: ConsistencyKeyDerivationV1::SourceFactId,
            },
            authenticated_scope_required: true,
            delivery_id_in_semantic_identity: false,
            immutable_revision_required: true,
        }),
        entry_positive,
        entry_negative,
    );

    let repository_identity = identity_constraint(&repository_kind, &repository_recipe);
    let dimensions = vec![
        ApplicabilityDimensionRuleV2 {
            dimension_id: id("repository_commit"),
            resource_identity: identity_constraint(&commit_kind, &commit_recipe),
            required: true,
        },
        ApplicabilityDimensionRuleV2 {
            dimension_id: id("runtime_environment"),
            resource_identity: identity_constraint(&environment_kind, &environment_recipe),
            required: true,
        },
    ];
    let predicate = entry(
        RegistryEntryKind::PredicateSchema,
        "mcp.remember.allowed_actions",
        3,
        2,
        canonical_value(&RememberPredicateSchemaV2 {
            schema_version: 2,
            predicate_id: id("mcp.remember.allowed_actions"),
            version: 3,
            subject_identity: repository_identity.clone(),
            value_constraint: RememberValueConstraintV2::Boolean {
                unit_id: id("unit.none"),
            },
            comparator: PredicateComparatorV1::ExactEquality,
            allowed_modalities: vec![
                PropositionModalityV1::Attested,
                PropositionModalityV1::Intended,
            ],
            applicability_evaluator: reference(&applicability),
            applicability_dimensions: dimensions.clone(),
            absence_semantics: AbsenceSemanticsV1::OpenWorld,
            coverage_proof: None,
            publication_default: PublicationDefaultV1::Denied,
            sensitivity_default: SensitivityDefaultV1::Project,
        }),
        entry_positive,
        entry_negative,
    );
    let admission = entry(
        RegistryEntryKind::AuthorityRule,
        "remember.actor_assertion",
        3,
        2,
        canonical_value(&RememberAdmissionRuleV2 {
            schema_version: 2,
            rule_id: id("remember.actor_assertion"),
            version: 3,
            predicate_schema: reference(&predicate),
            applicability_evaluator: reference(&applicability),
            allowed_assertion_kinds: vec![
                RememberAssertionKindV2::Decision,
                RememberAssertionKindV2::Fact,
                RememberAssertionKindV2::Constraint,
                RememberAssertionKindV2::Preference,
                RememberAssertionKindV2::Procedure,
            ],
            basis_rules: vec![RememberAdmissionBasisRuleV2::AuthenticatedActor {
                allowed_modalities: vec![
                    PropositionModalityV1::Attested,
                    PropositionModalityV1::Intended,
                ],
                maximum_support_events: 256,
            }],
            effective_interval_rule: RememberEffectiveIntervalRuleV2 {
                payload_may_select_effective_from: true,
                past_effective_from_allowed: true,
                future_effective_from_allowed: false,
                open_ended_interval_allowed: true,
                bounded_interval_allowed: true,
                microsecond_alignment_required: true,
            },
            classifier_policy: reference(&classifier),
            redaction_policy: reference(&redaction),
            retention_policy: reference(&retention),
            publication_rule: reference(&publication),
            maximum_assertion_text_utf8_bytes: 100_000,
            authenticated_scope_required: true,
            resource_rederivation_required: true,
            support_event_reaudit_required: true,
            server_derived_governance_required: true,
            registered_observer_append_enabled: false,
            normative_binding_append_enabled: false,
            payload_may_select_actor: false,
            payload_may_select_scope: false,
            payload_may_select_registry_head: false,
            payload_may_select_admission_rule: false,
            payload_may_select_admission_outcome: false,
        }),
        entry_positive,
        entry_negative,
    );
    let relation = entry(
        RegistryEntryKind::RelationProof,
        "relation.repository_parent",
        2,
        2,
        canonical_value(&RelationProofEntryV2 {
            schema_version: 2,
            relation_id: id("relation.repository_parent"),
            version: 2,
            source_identity: repository_identity.clone(),
            target_identity: repository_identity,
            applicability_evaluator: reference(&applicability),
            applicability_dimensions: dimensions,
            multiplicity: RelationMultiplicityV1::ManyToMany,
            temporal_overlap_required: false,
            basis_rules: vec![RelationAdmissionBasisRuleV2::Declared {
                allowed_verdicts: vec![RelationAttestationVerdictV1::Supports],
                minimum_support_events: 1,
                maximum_support_events: 256,
                authenticated_actor_required: true,
            }],
            authenticated_scope_required: true,
            resource_rederivation_required: true,
            support_event_reaudit_required: true,
            payload_may_select_attestor: false,
            payload_may_select_registry_head: false,
            payload_may_select_proof: false,
            payload_may_select_verified_state: false,
        }),
        parse_digest(RELATION_POSITIVE_VECTOR_DIGEST_HEX).unwrap(),
        parse_digest(RELATION_NEGATIVE_VECTOR_DIGEST_HEX).unwrap(),
    );

    let mut entries = vec![
        activation,
        applicability,
        admission,
        classifier,
        connector,
        evidence,
        exemplar,
        commit_recipe,
        provider_instance_recipe,
        provider_event_recipe,
        repository_recipe,
        environment_recipe,
        commit_namespace,
        provider_instance_namespace,
        provider_event_namespace,
        repository_namespace,
        environment_namespace,
        predicate,
        publication,
        redaction,
        relation,
        commit_kind,
        environment_kind,
        provider_event_kind,
        provider_instance_kind,
        repository_kind,
        retention,
    ];
    entries.sort_by(|left, right| {
        (left.kind.as_str(), left.entry_id.as_str(), left.version).cmp(&(
            right.kind.as_str(),
            right.entry_id.as_str(),
            right.version,
        ))
    });
    assert_eq!(entries.len(), TARGET_ENTRY_COUNT);
    entries
}

fn manifest(entries: &[RegistryEntryV1]) -> Vec<RegistryManifestEntryV1> {
    entries
        .iter()
        .map(|entry| RegistryManifestEntryV1 {
            kind: entry.kind,
            entry_id: entry.entry_id.clone(),
            version: entry.version,
            entry_digest: entry.digest().unwrap(),
        })
        .collect()
}

fn target_package() -> RegistryPackageV1 {
    let entries = target_entries();
    let positive = package_positive_cases(&entries);
    let negative = package_negative_cases(&entries);
    positive.validate().unwrap();
    negative.validate().unwrap();
    RegistryPackageV1 {
        schema_version: 1,
        profile: frozen_profile_reference_v1(),
        manifest: manifest(&entries),
        entries,
        positive_vector_suite_digest: vector_digest(&positive),
        negative_vector_suite_digest: vector_digest(&negative),
    }
}

fn verified(package: RegistryPackageV1) -> ManifestVerifiedRegistryPackage {
    ManifestVerifiedRegistryPackage::new(package, &frozen_profile_reference_v1()).unwrap()
}

fn closed_unpinned(package: RegistryPackageV1) -> SemanticallyClosedSuccessorPackage {
    SemanticallyClosedSuccessorPackage::from_manifest_verified(verified(package)).unwrap()
}

fn rebuild(mut package: RegistryPackageV1) -> RegistryPackageV1 {
    package.entries.sort_by(|left, right| {
        (left.kind.as_str(), left.entry_id.as_str(), left.version).cmp(&(
            right.kind.as_str(),
            right.entry_id.as_str(),
            right.version,
        ))
    });
    package.manifest = manifest(&package.entries);
    package
}

fn vector_suite() -> Stage4VectorSuiteV1 {
    let package = target_package();
    let package_bytes = encode_canonical(&package).unwrap();
    let entry_positive = entry_positive_cases();
    let entry_negative = entry_negative_cases();
    let package_positive = package_positive_cases(&package.entries);
    let package_negative = package_negative_cases(&package.entries);
    let entry_positive_bytes = encode_canonical(&entry_positive).unwrap();
    let entry_negative_bytes = encode_canonical(&entry_negative).unwrap();
    let package_positive_bytes = encode_canonical(&package_positive).unwrap();
    let package_negative_bytes = encode_canonical(&package_negative).unwrap();
    Stage4VectorSuiteV1 {
        schema_version: 1,
        suite_id: id("ostk.stage4.target.v1"),
        fixture_authority: FIXTURE_AUTHORITY.into(),
        entry_positive_path: "entry-positive-vectors.jsonl".into(),
        entry_positive_digest: vector_digest(&entry_positive),
        entry_positive_raw_sha256: framed_raw_sha256(&entry_positive_bytes),
        entry_negative_path: "entry-negative-vectors.jsonl".into(),
        entry_negative_digest: vector_digest(&entry_negative),
        entry_negative_raw_sha256: framed_raw_sha256(&entry_negative_bytes),
        package_positive_path: "positive-vectors.jsonl".into(),
        package_positive_digest: vector_digest(&package_positive),
        package_positive_raw_sha256: framed_raw_sha256(&package_positive_bytes),
        package_negative_path: "negative-vectors.jsonl".into(),
        package_negative_digest: vector_digest(&package_negative),
        package_negative_raw_sha256: framed_raw_sha256(&package_negative_bytes),
        package_path: "registry-package.jsonl".into(),
        package_digest: domain_separated_digest(DigestDomain::RegistryPackage, &package_bytes),
        package_raw_sha256: framed_raw_sha256(&package_bytes),
        entry_pins: package.manifest,
    }
}

fn decode_fixture_package() -> RegistryPackageV1 {
    require_canonical(record(PACKAGE_FIXTURE)).unwrap();
    decode_strict(record(PACKAGE_FIXTURE)).unwrap()
}

#[test]
fn generated_package_closes_through_every_offline_layer() {
    let package = target_package();
    let generic = closed_unpinned(package);
    let target = SemanticallyClosedStage4Package::from_successor_package(generic).unwrap();
    assert_eq!(
        target.package_digest(),
        parse_digest(PACKAGE_DIGEST_HEX).unwrap()
    );
    assert_eq!(
        target
            .connector_schema()
            .registry_reference()
            .entry_id
            .as_str(),
        "connector.github.push"
    );
    assert_eq!(
        target.remember_predicate().predicate_id.as_str(),
        "mcp.remember.allowed_actions"
    );
    assert_eq!(
        target.remember_admission().rule_id.as_str(),
        "remember.actor_assertion"
    );
    assert_eq!(
        target
            .relation_proof()
            .registry_reference()
            .entry_id
            .as_str(),
        "relation.repository_parent"
    );
    assert_eq!(
        target
            .activation_policy()
            .registry_reference()
            .entry_id
            .as_str(),
        "activation.default"
    );
}

#[test]
fn canonical_artifacts_and_all_digest_layers_are_hard_pinned() {
    for fixture in [
        ENTRY_POSITIVE_FIXTURE,
        ENTRY_NEGATIVE_FIXTURE,
        PACKAGE_POSITIVE_FIXTURE,
        PACKAGE_NEGATIVE_FIXTURE,
        PACKAGE_FIXTURE,
        VECTOR_SUITE_FIXTURE,
    ] {
        require_canonical(record(fixture)).unwrap();
    }
    let entry_positive = entry_positive_cases();
    let entry_negative = entry_negative_cases();
    let package = target_package();
    let package_positive = package_positive_cases(&package.entries);
    let package_negative = package_negative_cases(&package.entries);
    let suite = vector_suite();
    assert_eq!(
        encode_canonical(&entry_positive).unwrap(),
        record(ENTRY_POSITIVE_FIXTURE)
    );
    assert_eq!(
        encode_canonical(&entry_negative).unwrap(),
        record(ENTRY_NEGATIVE_FIXTURE)
    );
    assert_eq!(
        encode_canonical(&package_positive).unwrap(),
        record(PACKAGE_POSITIVE_FIXTURE)
    );
    assert_eq!(
        encode_canonical(&package_negative).unwrap(),
        record(PACKAGE_NEGATIVE_FIXTURE)
    );
    assert_eq!(encode_canonical(&package).unwrap(), record(PACKAGE_FIXTURE));
    assert_eq!(
        encode_canonical(&suite).unwrap(),
        record(VECTOR_SUITE_FIXTURE)
    );
    assert_eq!(
        vector_digest(&entry_positive),
        parse_digest(ENTRY_POSITIVE_VECTOR_DIGEST_HEX).unwrap()
    );
    assert_eq!(
        vector_digest(&entry_negative),
        parse_digest(ENTRY_NEGATIVE_VECTOR_DIGEST_HEX).unwrap()
    );
    assert_eq!(
        vector_digest(&package_positive),
        parse_digest(POSITIVE_VECTOR_DIGEST_HEX).unwrap()
    );
    assert_eq!(
        vector_digest(&package_negative),
        parse_digest(NEGATIVE_VECTOR_DIGEST_HEX).unwrap()
    );
    assert_eq!(
        suite.package_digest,
        parse_digest(PACKAGE_DIGEST_HEX).unwrap()
    );
    assert_eq!(
        vector_digest(&suite),
        parse_digest(VECTOR_SUITE_DIGEST_HEX).unwrap()
    );
    for (entry, expected_digest) in package.entries.iter().zip(EXPECTED_ENTRY_DIGEST_HEX) {
        assert_eq!(
            entry.digest().unwrap(),
            parse_digest(expected_digest).unwrap()
        );
    }
}

#[test]
fn framed_raw_artifacts_are_hard_pinned() {
    for (fixture, expected) in [
        (PACKAGE_FIXTURE, PACKAGE_RAW_SHA256),
        (ENTRY_POSITIVE_FIXTURE, ENTRY_POSITIVE_RAW_SHA256),
        (ENTRY_NEGATIVE_FIXTURE, ENTRY_NEGATIVE_RAW_SHA256),
        (PACKAGE_POSITIVE_FIXTURE, PACKAGE_POSITIVE_RAW_SHA256),
        (PACKAGE_NEGATIVE_FIXTURE, PACKAGE_NEGATIVE_RAW_SHA256),
        (VECTOR_SUITE_FIXTURE, VECTOR_SUITE_RAW_SHA256),
    ] {
        assert_eq!(raw_sha256(fixture), expected);
    }
}

#[test]
fn package_manifests_pin_entries_without_creating_a_digest_cycle() {
    let package = target_package();
    let positive: PackageCaseManifestV1 = decode_strict(record(PACKAGE_POSITIVE_FIXTURE)).unwrap();
    let negative: PackageCaseManifestV1 = decode_strict(record(PACKAGE_NEGATIVE_FIXTURE)).unwrap();
    assert_eq!(positive.entry_pins, package.manifest);
    assert_eq!(negative.entry_pins, package.manifest);
    let package_text = std::str::from_utf8(record(PACKAGE_FIXTURE)).unwrap();
    assert!(!package_text.contains(VECTOR_SUITE_DIGEST_HEX));
}

#[test]
fn extra_missing_and_wrong_revision_inventory_fail_closed() {
    let mut extra = target_package();
    let mut orphan = extra
        .entries
        .iter()
        .find(|entry| entry.kind == RegistryEntryKind::ClassifierPolicy)
        .unwrap()
        .clone();
    orphan.entry_id = id("classifier.orphan");
    if let CanonicalValue::Object(body) = &mut orphan.body {
        body.insert(
            "policy_id".into(),
            CanonicalValue::String("classifier.orphan".into()),
        );
    }
    extra.entries.push(orphan);
    let generic = closed_unpinned(rebuild(extra));
    assert!(SemanticallyClosedStage4Package::from_successor_package(generic).is_err());

    let mut missing = target_package();
    missing
        .entries
        .retain(|entry| entry.entry_id.as_str() != "exemplar.private");
    assert!(
        SemanticallyClosedSuccessorPackage::from_manifest_verified(verified(rebuild(missing)))
            .is_err()
    );

    let mut wrong_revision = target_package();
    let applicability = wrong_revision
        .entries
        .iter_mut()
        .find(|entry| entry.entry_id.as_str() == "applicability.default")
        .unwrap();
    applicability.version = 4;
    if let CanonicalValue::Object(body) = &mut applicability.body {
        body.insert("version".into(), CanonicalValue::Integer(4));
    }
    assert!(
        SemanticallyClosedSuccessorPackage::from_manifest_verified(verified(rebuild(
            wrong_revision
        )))
        .is_err()
    );
}

#[test]
fn alternate_and_ambiguous_routes_fail_closed() {
    let mut alternate = target_package();
    let evidence_index = alternate
        .entries
        .iter()
        .position(|entry| entry.entry_id.as_str() == "evidence.github.push")
        .unwrap();
    let repository_reference = reference(
        alternate
            .entries
            .iter()
            .find(|entry| entry.entry_id.as_str() == "identity.github.repository")
            .unwrap(),
    );
    if let CanonicalValue::Object(body) = &mut alternate.entries[evidence_index].body {
        body.insert(
            "identity_recipe".into(),
            canonical_value(&repository_reference),
        );
    }
    assert!(
        SemanticallyClosedSuccessorPackage::from_manifest_verified(verified(rebuild(alternate)))
            .is_err()
    );

    let mut ambiguous = target_package();
    let source = ambiguous
        .entries
        .iter()
        .find(|entry| entry.entry_id.as_str() == "connector.github.push")
        .unwrap();
    let mut body: ConnectorSchemaV2 = decode_body(source).unwrap();
    body.connector_schema_id = id("connector.github.secondary");
    let duplicate = entry(
        RegistryEntryKind::ConnectorSchema,
        "connector.github.secondary",
        3,
        2,
        canonical_value(&body),
        parse_digest(ENTRY_POSITIVE_VECTOR_DIGEST_HEX).unwrap(),
        parse_digest(ENTRY_NEGATIVE_VECTOR_DIGEST_HEX).unwrap(),
    );
    ambiguous.entries.push(duplicate);
    let generic = closed_unpinned(rebuild(ambiguous));
    assert!(SemanticallyClosedStage4Package::from_successor_package(generic).is_err());

    let mut relation_ambiguous = target_package();
    let source = relation_ambiguous
        .entries
        .iter()
        .find(|entry| entry.entry_id.as_str() == "relation.repository_parent")
        .unwrap();
    let mut body: RelationProofEntryV2 = decode_body(source).unwrap();
    body.relation_id = id("relation.repository_secondary");
    relation_ambiguous.entries.push(entry(
        RegistryEntryKind::RelationProof,
        "relation.repository_secondary",
        2,
        2,
        canonical_value(&body),
        parse_digest(RELATION_POSITIVE_VECTOR_DIGEST_HEX).unwrap(),
        parse_digest(RELATION_NEGATIVE_VECTOR_DIGEST_HEX).unwrap(),
    ));
    let generic = closed_unpinned(rebuild(relation_ambiguous));
    assert!(SemanticallyClosedStage4Package::from_successor_package(generic).is_err());

    let mut remember_ambiguous = target_package();
    let source = remember_ambiguous
        .entries
        .iter()
        .find(|entry| entry.entry_id.as_str() == "remember.actor_assertion")
        .unwrap();
    let mut body: RememberAdmissionRuleV2 = decode_body(source).unwrap();
    body.rule_id = id("remember.actor_assertion_secondary");
    remember_ambiguous.entries.push(entry(
        RegistryEntryKind::AuthorityRule,
        "remember.actor_assertion_secondary",
        3,
        2,
        canonical_value(&body),
        parse_digest(ENTRY_POSITIVE_VECTOR_DIGEST_HEX).unwrap(),
        parse_digest(ENTRY_NEGATIVE_VECTOR_DIGEST_HEX).unwrap(),
    ));
    assert!(
        SemanticallyClosedSuccessorPackage::from_manifest_verified(verified(rebuild(
            remember_ambiguous
        )))
        .is_err()
    );
}

#[test]
fn valid_legacy_relation_inventory_and_governance_drift_fail_closed() {
    let genesis: RegistryPackageV1 = decode_strict(record(GENESIS_PACKAGE_FIXTURE)).unwrap();
    let mut with_legacy = target_package();
    with_legacy.entries.extend(genesis.entries);
    let generic = closed_unpinned(rebuild(with_legacy));
    assert!(SemanticallyClosedStage4Package::from_successor_package(generic).is_err());

    let mut drift = target_package();
    let predicate_index = drift
        .entries
        .iter()
        .position(|entry| entry.entry_id.as_str() == "mcp.remember.allowed_actions")
        .unwrap();
    if let CanonicalValue::Object(body) = &mut drift.entries[predicate_index].body {
        body.insert(
            "publication_default".into(),
            CanonicalValue::String("private_only".into()),
        );
    }
    let predicate_reference = reference(&drift.entries[predicate_index]);
    let admission = drift
        .entries
        .iter_mut()
        .find(|entry| entry.entry_id.as_str() == "remember.actor_assertion")
        .unwrap();
    if let CanonicalValue::Object(body) = &mut admission.body {
        body.insert(
            "predicate_schema".into(),
            canonical_value(&predicate_reference),
        );
    }
    let generic = closed_unpinned(rebuild(drift));
    assert!(SemanticallyClosedStage4Package::from_successor_package(generic).is_err());
}

#[test]
fn public_bytes_and_structural_values_never_create_active_authority() {
    let package = decode_fixture_package();
    let generic = closed_unpinned(package);
    let closed = SemanticallyClosedStage4Package::from_successor_package(generic).unwrap();
    assert_eq!(closed.canonical_bytes(), record(PACKAGE_FIXTURE));
    // There is intentionally no active-head or repository witness API on
    // this type; its exposed values remain offline structural contracts.
    assert_eq!(
        closed
            .successor_package()
            .manifest_verified_package()
            .package()
            .entries
            .len(),
        27
    );
}

#[test]
#[ignore = "maintainer-only deterministic Stage-4 fixture regeneration"]
fn regenerate_stage4_target_artifacts() {
    fn write(output: &Path, name: &str, bytes: &[u8]) {
        let mut framed = bytes.to_vec();
        framed.push(b'\n');
        fs::write(output.join(name), framed).unwrap();
    }

    let output = std::env::var_os("STAGE4_TARGET_OUTPUT")
        .map(std::path::PathBuf::from)
        .expect("STAGE4_TARGET_OUTPUT is required");
    fs::create_dir_all(&output).unwrap();
    let entry_positive = entry_positive_cases();
    let entry_negative = entry_negative_cases();
    let package = target_package();
    let package_positive = package_positive_cases(&package.entries);
    let package_negative = package_negative_cases(&package.entries);
    let suite = vector_suite();
    for (name, bytes) in [
        (
            "entry-positive-vectors.jsonl",
            encode_canonical(&entry_positive).unwrap(),
        ),
        (
            "entry-negative-vectors.jsonl",
            encode_canonical(&entry_negative).unwrap(),
        ),
        (
            "positive-vectors.jsonl",
            encode_canonical(&package_positive).unwrap(),
        ),
        (
            "negative-vectors.jsonl",
            encode_canonical(&package_negative).unwrap(),
        ),
        (
            "registry-package.jsonl",
            encode_canonical(&package).unwrap(),
        ),
        ("vector-suite.jsonl", encode_canonical(&suite).unwrap()),
    ] {
        write(&output, name, &bytes);
    }
    println!("PACKAGE_DIGEST {}", suite.package_digest);
    println!("ENTRY_POSITIVE_DIGEST {}", suite.entry_positive_digest);
    println!("ENTRY_NEGATIVE_DIGEST {}", suite.entry_negative_digest);
    println!("PACKAGE_POSITIVE_DIGEST {}", suite.package_positive_digest);
    println!("PACKAGE_NEGATIVE_DIGEST {}", suite.package_negative_digest);
    println!("VECTOR_SUITE_DIGEST {}", vector_digest(&suite));
    println!("PACKAGE_RAW_SHA256 {}", suite.package_raw_sha256);
    println!(
        "ENTRY_POSITIVE_RAW_SHA256 {}",
        suite.entry_positive_raw_sha256
    );
    println!(
        "ENTRY_NEGATIVE_RAW_SHA256 {}",
        suite.entry_negative_raw_sha256
    );
    println!(
        "PACKAGE_POSITIVE_RAW_SHA256 {}",
        suite.package_positive_raw_sha256
    );
    println!(
        "PACKAGE_NEGATIVE_RAW_SHA256 {}",
        suite.package_negative_raw_sha256
    );
    println!(
        "VECTOR_SUITE_RAW_SHA256 {}",
        framed_raw_sha256(&encode_canonical(&suite).unwrap())
    );
    for pin in &suite.entry_pins {
        println!(
            "ENTRY {} {}@{} {}",
            pin.kind.as_str(),
            pin.entry_id,
            pin.version,
            pin.entry_digest
        );
    }
}
