//! Frozen, authority-free closure for the first Stage-4 successor package.
//!
//! The generic successor package accepts individually closed historical
//! inventory. This wrapper is deliberately narrower: it admits one exact
//! 27-entry package, four exact capability roots, one route per capability,
//! and no unreachable or legacy relation entry. Construction proves offline
//! byte and dependency closure only. It does not prove that the package is the
//! active registry head and exposes no constructor for runtime authority.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::str::FromStr;

use serde::Deserialize;

use super::{
    ContractError, ContractResult,
    canonical::{decode_strict, encode_canonical},
    common::{ContractId, RegistryReferenceV1},
    digest::Sha256Digest,
    evidence::{PublicationClass, VisibilityClass},
    evidence_v2::StructurallyResolvedConnectorSchemaV2,
    genesis::PolicyFailureOutcomeV1,
    identity::{IdentityRecipeV1, ResourceKindSchemaV1},
    registry::{RegistryEntryKind, RegistryEntryV1},
    relation_policy_v2::StructurallyResolvedRelationProofV2,
    remember_v2::{
        RememberAdmissionRuleV2, RememberPredicateSchemaV2, StructurallyResolvedRememberContractsV2,
    },
    successor_package::SemanticallyClosedSuccessorPackage,
    successor_policy::StructurallyResolvedActivationPolicyV2,
};

const TARGET_ENTRY_COUNT: usize = 27;
const PACKAGE_DIGEST_HEX: &str = "16f98d5df93b74dab5b2188274cbd1da21d089ff7a64cd8fc29679946e7fe2c9";
const POSITIVE_VECTOR_DIGEST_HEX: &str =
    "767cc52d3a02d7f2466462f64655df3eaf185f3b9158ddcded0057298795a410";
const NEGATIVE_VECTOR_DIGEST_HEX: &str =
    "e7d1974b23f3b475bc72132852f16e8f73600077e71e59a3683cb2c5301090ec";
const ENTRY_POSITIVE_VECTOR_DIGEST_HEX: &str =
    "43497990630fadf8f6447bd3d83ce815d2b5e2d7df2773de74966f20da1c4740";
const ENTRY_NEGATIVE_VECTOR_DIGEST_HEX: &str =
    "e6e4c7db1c88e5e36f991189b26b0d27d7eb4e511816e89970f285183b3c1f41";
const ACTIVATION_POSITIVE_VECTOR_DIGEST_HEX: &str =
    "f50ab365c5687a2779ff1bf641470ed783f8f084d3d0a916c24c7f95f414dcb0";
const ACTIVATION_NEGATIVE_VECTOR_DIGEST_HEX: &str =
    "f0b39c94ea6994fdb9d275ff30319ae0960e0ca77bf807de59789278c66c537d";
const RELATION_POSITIVE_VECTOR_DIGEST_HEX: &str =
    "3af883800cbe7c4a74ee2d9de570bfdd82a435cef22d11b052271c78aaa72d94";
const RELATION_NEGATIVE_VECTOR_DIGEST_HEX: &str =
    "56170368d04b14a732e4512ce27b4737a801a1911b0a7b39cd17f01204466557";

#[derive(Debug, Clone, Copy)]
struct ExpectedEntry {
    kind: RegistryEntryKind,
    id: &'static str,
    version: u32,
    entry_schema_version: u32,
}

const EXPECTED_ENTRY_DIGEST_HEX: [&str; TARGET_ENTRY_COUNT] = [
    "5611a4fea75d0a8132395bf6e3040ce97638a3447e290f5cabc183c1bb9faa6c",
    "d4cb3a72e3fef6bd33f380b259a6dd95e61c2a1aeb66020ee216d8344121a1b9",
    "98de94b14ed8609bd0f01a8da7312b72079e7750a4be21bf8f2000153fee1a51",
    "1d0ab706db148ba97a198c220c2197a9f5a16998b19fee4e9234eb50b317f392",
    "e66d4cba5ea8e22fa753fcf022756c86e702a18a7a3e7825170f283dc8ae7658",
    "1afd25ccd79d99b86e9e978df5a9bf55e3aca3a76d2aaa81f6a4668458bc63f9",
    "ff17367af8021156df2f916ec170ff6fd843f471a84c24c3ee112935d7f14951",
    "d7a5911bb4298bf93825bdd44b3226fd42ee7842b80e87ed9b8067bd728f9323",
    "ff0a8b5a3df100eebc0364c9c0c879a38c4b1e5e874debe2f1b78d5463dc565d",
    "eda1e898d215ca5e0523308753fa8d154ec69a9085c83f6b4ecfc67131d16ed2",
    "63bf3525b48c9234b8db7ec83c9cb9fcfd84f3a6687d11a41f8d8b3fa57c6cb6",
    "67c53124d064461d7e0d54d608bde72c0012dca821f6c1103bdab2f9383f800f",
    "cf83b6f9f8c89ac8074af5e003d81522932a3199508e67ce37182f413e82aab1",
    "079d764ea2e2902b24189408ffc86f5c910d54dc83674ad74fa97fe3fb757a52",
    "4fb8525f10dec5e096ceb2a8ddf31b5549a9543c192606c4985cac121d416aa0",
    "b4da835643a7c555e00f25d0a62eb0e5f2684182ad69cbf28c96b2465ae2ebd5",
    "5cfc79c2aaceab3c676a5ce536d469557224713b01f0bfa6b732ec706ae673e9",
    "6036ba4bfe6ad9e3fa056175485063c01a046ccf271277a0c262757d645573e3",
    "ede72bc9c761e4bf7daeb60c8a37f0555734566a0a88832654b0a140ff3748b3",
    "e19463eb121131ab6c52ba9b331f8bb25e78907611d4e5342f7532ff8c037fef",
    "23fc7040b583071ab8c0f0d69e2424b833709d386b105af39d636da50d71aaee",
    "4e54e0911cb9ce14bf2b99fb20e5dca639046ba5ff4386038ba2e293e92a5744",
    "1301c19682665a3db826dacc7558e92108653c06008729ce05da39bebf9bf054",
    "fd6aeebe4e6381360dddea0578828a095b1465d70e9a43558566c52d44a29adc",
    "5b478d764159666d1d703f3522ad06597b25af8396470dc88d6908b44ee24164",
    "96232d942f962998f409a5f91d3969df13cc80462de6bad39d78e88da6beae86",
    "c412a7d354e75a6fea8d77a6ab46edee902d1f56500b7401580b9ad0f5696548",
];

const EXPECTED_ENTRIES: [ExpectedEntry; TARGET_ENTRY_COUNT] = [
    expected(
        RegistryEntryKind::ActivationPolicy,
        "activation.default",
        2,
        2,
    ),
    expected(
        RegistryEntryKind::ApplicabilityEvaluator,
        "applicability.default",
        3,
        1,
    ),
    expected(
        RegistryEntryKind::AuthorityRule,
        "remember.actor_assertion",
        3,
        2,
    ),
    expected(
        RegistryEntryKind::ClassifierPolicy,
        "classifier.default",
        3,
        1,
    ),
    expected(
        RegistryEntryKind::ConnectorSchema,
        "connector.github.push",
        3,
        2,
    ),
    expected(
        RegistryEntryKind::EvidenceSchema,
        "evidence.github.push",
        3,
        1,
    ),
    expected(RegistryEntryKind::ExemplarPolicy, "exemplar.private", 3, 1),
    expected(
        RegistryEntryKind::IdentityRecipe,
        "identity.github.commit",
        3,
        1,
    ),
    expected(
        RegistryEntryKind::IdentityRecipe,
        "identity.github.provider_instance",
        3,
        1,
    ),
    expected(
        RegistryEntryKind::IdentityRecipe,
        "identity.github.push",
        3,
        1,
    ),
    expected(
        RegistryEntryKind::IdentityRecipe,
        "identity.github.repository",
        3,
        1,
    ),
    expected(
        RegistryEntryKind::IdentityRecipe,
        "identity.runtime.environment",
        3,
        1,
    ),
    expected(
        RegistryEntryKind::NamespaceDefinition,
        "namespace.github.commit",
        3,
        1,
    ),
    expected(
        RegistryEntryKind::NamespaceDefinition,
        "namespace.github.provider_instance",
        3,
        1,
    ),
    expected(
        RegistryEntryKind::NamespaceDefinition,
        "namespace.github.push",
        3,
        1,
    ),
    expected(
        RegistryEntryKind::NamespaceDefinition,
        "namespace.github.repository",
        3,
        1,
    ),
    expected(
        RegistryEntryKind::NamespaceDefinition,
        "namespace.runtime.environment",
        3,
        1,
    ),
    expected(
        RegistryEntryKind::PredicateSchema,
        "mcp.remember.allowed_actions",
        3,
        2,
    ),
    expected(
        RegistryEntryKind::PublicationRule,
        "publication.default",
        3,
        1,
    ),
    expected(
        RegistryEntryKind::RedactionPolicy,
        "redaction.default",
        3,
        1,
    ),
    expected(
        RegistryEntryKind::RelationProof,
        "relation.repository_parent",
        2,
        2,
    ),
    expected(RegistryEntryKind::ResourceKindSchema, "commit", 3, 1),
    expected(RegistryEntryKind::ResourceKindSchema, "environment", 3, 1),
    expected(
        RegistryEntryKind::ResourceKindSchema,
        "provider_event",
        3,
        1,
    ),
    expected(
        RegistryEntryKind::ResourceKindSchema,
        "provider_instance",
        3,
        1,
    ),
    expected(RegistryEntryKind::ResourceKindSchema, "repository", 3, 1),
    expected(
        RegistryEntryKind::RetentionPolicy,
        "retention.default",
        3,
        1,
    ),
];

const fn expected(
    kind: RegistryEntryKind,
    id: &'static str,
    version: u32,
    entry_schema_version: u32,
) -> ExpectedEntry {
    ExpectedEntry {
        kind,
        id,
        version,
        entry_schema_version,
    }
}

/// The one frozen first Stage-4 package, semantically closed but never active.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticallyClosedStage4Package {
    successor: SemanticallyClosedSuccessorPackage,
    connector_reference: RegistryReferenceV1,
    predicate_reference: RegistryReferenceV1,
    admission_reference: RegistryReferenceV1,
    relation: StructurallyResolvedRelationProofV2,
}

impl SemanticallyClosedStage4Package {
    /// Narrow a generic offline successor closure to the frozen Stage-4 target.
    pub fn from_successor_package(
        successor: SemanticallyClosedSuccessorPackage,
    ) -> ContractResult<Self> {
        validate_inventory(&successor)?;
        validate_vector_roots(&successor)?;

        let activation_reference = reference_for(
            &successor,
            RegistryEntryKind::ActivationPolicy,
            "activation.default",
            2,
        )?;
        if successor.activation_policy().registry_reference() != &activation_reference {
            return Err(ContractError::ManifestMismatch);
        }

        let connector_reference = reference_for(
            &successor,
            RegistryEntryKind::ConnectorSchema,
            "connector.github.push",
            3,
        )?;
        let predicate_reference = reference_for(
            &successor,
            RegistryEntryKind::PredicateSchema,
            "mcp.remember.allowed_actions",
            3,
        )?;
        let admission_reference = reference_for(
            &successor,
            RegistryEntryKind::AuthorityRule,
            "remember.actor_assertion",
            3,
        )?;
        let relation_reference = reference_for(
            &successor,
            RegistryEntryKind::RelationProof,
            "relation.repository_parent",
            2,
        )?;

        require_unique_routes(&successor)?;
        let connector = successor
            .connector_schema(&connector_reference)
            .ok_or_else(|| schema("Stage-4 connector root did not resolve as schema v2"))?;
        let predicate = successor
            .remember_predicate(&predicate_reference)
            .ok_or_else(|| schema("Stage-4 remember predicate did not resolve as schema v2"))?;
        let admission = successor
            .remember_admission(&admission_reference)
            .ok_or_else(|| schema("Stage-4 remember route did not resolve as schema v2"))?;
        let predicate_entry = exact_entry(
            &successor,
            RegistryEntryKind::PredicateSchema,
            &predicate_reference,
        )?;
        let admission_entry = exact_entry(
            &successor,
            RegistryEntryKind::AuthorityRule,
            &admission_reference,
        )?;
        StructurallyResolvedRememberContractsV2::from_registry_entries(
            predicate_entry,
            admission_entry,
        )?;

        let relation = successor
            .relation_proof(&relation_reference)
            .cloned()
            .ok_or_else(|| schema("Stage-4 relation route did not resolve as schema v2"))?;

        validate_dependency_graph(&successor, connector, predicate, admission, &relation)?;
        validate_entry_and_package_pins(&successor)?;

        Ok(Self {
            successor,
            connector_reference,
            predicate_reference,
            admission_reference,
            relation,
        })
    }

    pub const fn successor_package(&self) -> &SemanticallyClosedSuccessorPackage {
        &self.successor
    }

    pub const fn package_digest(&self) -> Sha256Digest {
        self.successor.package_digest()
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        self.successor.canonical_bytes()
    }

    pub fn activation_policy(&self) -> &StructurallyResolvedActivationPolicyV2 {
        self.successor.activation_policy()
    }

    pub fn connector_schema(&self) -> &StructurallyResolvedConnectorSchemaV2 {
        self.successor
            .connector_schema(&self.connector_reference)
            .expect("frozen connector route was closed during construction")
    }

    pub fn remember_predicate(&self) -> &RememberPredicateSchemaV2 {
        self.successor
            .remember_predicate(&self.predicate_reference)
            .expect("frozen remember predicate was closed during construction")
    }

    pub fn remember_admission(&self) -> &RememberAdmissionRuleV2 {
        self.successor
            .remember_admission(&self.admission_reference)
            .expect("frozen remember route was closed during construction")
    }

    pub const fn relation_proof(&self) -> &StructurallyResolvedRelationProofV2 {
        &self.relation
    }
}

impl TryFrom<SemanticallyClosedSuccessorPackage> for SemanticallyClosedStage4Package {
    type Error = ContractError;

    fn try_from(value: SemanticallyClosedSuccessorPackage) -> Result<Self, Self::Error> {
        Self::from_successor_package(value)
    }
}

fn validate_inventory(successor: &SemanticallyClosedSuccessorPackage) -> ContractResult<()> {
    let entries = &successor.manifest_verified_package().package().entries;
    if entries.len() != TARGET_ENTRY_COUNT {
        return Err(schema("Stage-4 target requires exactly 27 entries"));
    }
    for (actual, expected) in entries.iter().zip(EXPECTED_ENTRIES) {
        if actual.kind != expected.kind
            || actual.entry_id.as_str() != expected.id
            || actual.version != expected.version
            || actual.entry_schema_id.as_str()
                != schema_id(expected.kind, expected.entry_schema_version)
            || actual.entry_schema_version != expected.entry_schema_version
        {
            return Err(schema("Stage-4 target inventory or selector differs"));
        }
    }
    Ok(())
}

fn validate_vector_roots(successor: &SemanticallyClosedSuccessorPackage) -> ContractResult<()> {
    let package = successor.manifest_verified_package().package();
    let positive = parse_digest(POSITIVE_VECTOR_DIGEST_HEX)?;
    let negative = parse_digest(NEGATIVE_VECTOR_DIGEST_HEX)?;
    if package.positive_vector_suite_digest != positive
        || package.negative_vector_suite_digest != negative
    {
        return Err(ContractError::ManifestMismatch);
    }
    let generic_positive = parse_digest(ENTRY_POSITIVE_VECTOR_DIGEST_HEX)?;
    let generic_negative = parse_digest(ENTRY_NEGATIVE_VECTOR_DIGEST_HEX)?;
    let activation_positive = parse_digest(ACTIVATION_POSITIVE_VECTOR_DIGEST_HEX)?;
    let activation_negative = parse_digest(ACTIVATION_NEGATIVE_VECTOR_DIGEST_HEX)?;
    let relation_positive = parse_digest(RELATION_POSITIVE_VECTOR_DIGEST_HEX)?;
    let relation_negative = parse_digest(RELATION_NEGATIVE_VECTOR_DIGEST_HEX)?;
    for entry in &package.entries {
        let expected = if entry.kind == RegistryEntryKind::ActivationPolicy {
            (activation_positive, activation_negative)
        } else if entry.kind == RegistryEntryKind::RelationProof {
            (relation_positive, relation_negative)
        } else {
            (generic_positive, generic_negative)
        };
        if (entry.positive_vector_digest, entry.negative_vector_digest) != expected {
            return Err(ContractError::ManifestMismatch);
        }
    }
    Ok(())
}

fn require_unique_routes(successor: &SemanticallyClosedSuccessorPackage) -> ContractResult<()> {
    let entries = &successor.manifest_verified_package().package().entries;
    let connector_count = entries
        .iter()
        .filter(|entry| {
            entry.kind == RegistryEntryKind::ConnectorSchema && entry.entry_schema_version == 2
        })
        .count();
    let remember_count = entries
        .iter()
        .filter(|entry| {
            entry.kind == RegistryEntryKind::AuthorityRule
                && entry.entry_schema_id.as_str() == "registry.remember_admission_rule"
                && entry.entry_schema_version == 2
        })
        .count();
    let relation_v2_count = entries
        .iter()
        .filter(|entry| {
            entry.kind == RegistryEntryKind::RelationProof && entry.entry_schema_version == 2
        })
        .count();
    let legacy_relation_count = entries
        .iter()
        .filter(|entry| {
            entry.kind == RegistryEntryKind::RelationProof && entry.entry_schema_version == 1
        })
        .count();
    if (
        connector_count,
        remember_count,
        relation_v2_count,
        legacy_relation_count,
    ) != (1, 1, 1, 0)
    {
        return Err(schema(
            "Stage-4 routes must be unique and cannot activate a legacy relation",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_dependency_graph(
    successor: &SemanticallyClosedSuccessorPackage,
    connector: &StructurallyResolvedConnectorSchemaV2,
    predicate: &RememberPredicateSchemaV2,
    admission: &RememberAdmissionRuleV2,
    relation: &StructurallyResolvedRelationProofV2,
) -> ContractResult<()> {
    let package = successor.manifest_verified_package().package();
    let mut graph = BTreeMap::<String, Vec<String>>::new();
    for expected in EXPECTED_ENTRIES {
        graph.insert(
            key(expected.kind, expected.id, expected.version),
            Vec::new(),
        );
    }

    let connector_key = key(
        RegistryEntryKind::ConnectorSchema,
        "connector.github.push",
        3,
    );
    add_expected_reference(
        successor,
        &mut graph,
        &connector_key,
        RegistryEntryKind::NamespaceDefinition,
        "namespace.github.provider_instance",
        3,
        &connector.schema().provider_namespace,
    )?;
    add_expected_reference(
        successor,
        &mut graph,
        &connector_key,
        RegistryEntryKind::EvidenceSchema,
        "evidence.github.push",
        3,
        &connector.schema().evidence_schema,
    )?;
    add_expected_reference(
        successor,
        &mut graph,
        &connector_key,
        RegistryEntryKind::IdentityRecipe,
        "identity.github.provider_instance",
        3,
        &connector.schema().provider_instance_identity_recipe,
    )?;
    add_expected_reference(
        successor,
        &mut graph,
        &connector_key,
        RegistryEntryKind::IdentityRecipe,
        "identity.github.push",
        3,
        &connector.schema().canonical_resource_identity_recipe,
    )?;

    let evidence_entry = entry_by_tuple(
        successor,
        RegistryEntryKind::EvidenceSchema,
        "evidence.github.push",
        3,
    )?;
    let evidence: EvidenceClosureV1 = decode_body(evidence_entry)?;
    let evidence_key = key(RegistryEntryKind::EvidenceSchema, "evidence.github.push", 3);
    for (kind, id, reference) in [
        (
            RegistryEntryKind::IdentityRecipe,
            "identity.github.push",
            &evidence.identity_recipe,
        ),
        (
            RegistryEntryKind::RedactionPolicy,
            "redaction.default",
            &evidence.redaction_policy,
        ),
        (
            RegistryEntryKind::ClassifierPolicy,
            "classifier.default",
            &evidence.classifier_policy,
        ),
        (
            RegistryEntryKind::RetentionPolicy,
            "retention.default",
            &evidence.retention_policy,
        ),
        (
            RegistryEntryKind::PublicationRule,
            "publication.default",
            &evidence.publication_rule,
        ),
    ] {
        add_expected_reference(successor, &mut graph, &evidence_key, kind, id, 3, reference)?;
    }
    if evidence.schema_version != 1
        || evidence.evidence_schema_id.as_str() != "evidence.github.push"
        || evidence.version != 3
        || evidence.evidence_kind.as_str() != "github.push"
        || !evidence.canonical_payload_required
        || evidence.private_raw_default_enabled
    {
        return Err(ContractError::ManifestMismatch);
    }

    let publication_entry = entry_by_tuple(
        successor,
        RegistryEntryKind::PublicationRule,
        "publication.default",
        3,
    )?;
    let publication: PublicationClosureV1 = decode_body(publication_entry)?;
    if publication.schema_version != 1
        || publication.rule_id.as_str() != "publication.default"
        || publication.version != 3
        || publication.default_publication != super::genesis::PublicationDefaultV1::Denied
        || !publication.classification_before_projection_required
        || publication.private_material_allowed
        || publication.raw_content_references_allowed
    {
        return Err(ContractError::ManifestMismatch);
    }
    add_expected_reference(
        successor,
        &mut graph,
        &key(RegistryEntryKind::PublicationRule, "publication.default", 3),
        RegistryEntryKind::ExemplarPolicy,
        "exemplar.private",
        3,
        &publication.exemplar_policy,
    )?;

    let classifier_entry = entry_by_tuple(
        successor,
        RegistryEntryKind::ClassifierPolicy,
        "classifier.default",
        3,
    )?;
    let classifier: ClassifierClosureV1 = decode_body(classifier_entry)?;
    if classifier.schema_version != 1
        || classifier.policy_id.as_str() != "classifier.default"
        || classifier.version != 3
        || !classifier.server_derived
        || !classifier.classify_before_projection
        || classifier.default_visibility != VisibilityClass::Private
        || classifier.default_publication != PublicationClass::Denied
        || classifier.failure_outcome != PolicyFailureOutcomeV1::Withhold
        || predicate.publication_default != super::genesis::PublicationDefaultV1::Denied
        || predicate.sensitivity_default != super::genesis::SensitivityDefaultV1::Project
    {
        return Err(schema(
            "Stage-4 remember publication or sensitivity governance is incompatible",
        ));
    }

    for (recipe_id, namespace_id, kind_id) in [
        (
            "identity.github.commit",
            "namespace.github.commit",
            "commit",
        ),
        (
            "identity.github.provider_instance",
            "namespace.github.provider_instance",
            "provider_instance",
        ),
        (
            "identity.github.push",
            "namespace.github.push",
            "provider_event",
        ),
        (
            "identity.github.repository",
            "namespace.github.repository",
            "repository",
        ),
        (
            "identity.runtime.environment",
            "namespace.runtime.environment",
            "environment",
        ),
    ] {
        let recipe_entry =
            entry_by_tuple(successor, RegistryEntryKind::IdentityRecipe, recipe_id, 3)?;
        let recipe: IdentityRecipeV1 = decode_body(recipe_entry)?;
        let recipe_key = key(RegistryEntryKind::IdentityRecipe, recipe_id, 3);
        add_expected_reference(
            successor,
            &mut graph,
            &recipe_key,
            RegistryEntryKind::NamespaceDefinition,
            namespace_id,
            3,
            &recipe.authority_namespace,
        )?;
        add_expected_reference(
            successor,
            &mut graph,
            &recipe_key,
            RegistryEntryKind::ResourceKindSchema,
            kind_id,
            3,
            &recipe.resource_kind_schema,
        )?;
    }

    let commit_entry = entry_by_tuple(
        successor,
        RegistryEntryKind::ResourceKindSchema,
        "commit",
        3,
    )?;
    let commit: ResourceKindSchemaV1 = decode_body(commit_entry)?;
    let parent = commit
        .parent_entity_kind
        .as_ref()
        .ok_or_else(|| schema("Stage-4 commit kind lacks its repository parent"))?;
    add_expected_reference(
        successor,
        &mut graph,
        &key(RegistryEntryKind::ResourceKindSchema, "commit", 3),
        RegistryEntryKind::ResourceKindSchema,
        "repository",
        3,
        parent,
    )?;

    let predicate_key = key(
        RegistryEntryKind::PredicateSchema,
        "mcp.remember.allowed_actions",
        3,
    );
    add_identity_constraint(
        successor,
        &mut graph,
        &predicate_key,
        "repository",
        "identity.github.repository",
        &predicate.subject_identity,
    )?;
    add_expected_reference(
        successor,
        &mut graph,
        &predicate_key,
        RegistryEntryKind::ApplicabilityEvaluator,
        "applicability.default",
        3,
        &predicate.applicability_evaluator,
    )?;
    validate_dimensions(
        successor,
        &mut graph,
        &predicate_key,
        &predicate.applicability_dimensions,
    )?;

    let admission_key = key(
        RegistryEntryKind::AuthorityRule,
        "remember.actor_assertion",
        3,
    );
    for (kind, id, reference) in [
        (
            RegistryEntryKind::PredicateSchema,
            "mcp.remember.allowed_actions",
            &admission.predicate_schema,
        ),
        (
            RegistryEntryKind::ApplicabilityEvaluator,
            "applicability.default",
            &admission.applicability_evaluator,
        ),
        (
            RegistryEntryKind::ClassifierPolicy,
            "classifier.default",
            &admission.classifier_policy,
        ),
        (
            RegistryEntryKind::RedactionPolicy,
            "redaction.default",
            &admission.redaction_policy,
        ),
        (
            RegistryEntryKind::RetentionPolicy,
            "retention.default",
            &admission.retention_policy,
        ),
        (
            RegistryEntryKind::PublicationRule,
            "publication.default",
            &admission.publication_rule,
        ),
    ] {
        add_expected_reference(
            successor,
            &mut graph,
            &admission_key,
            kind,
            id,
            3,
            reference,
        )?;
    }

    let relation_key = key(
        RegistryEntryKind::RelationProof,
        "relation.repository_parent",
        2,
    );
    add_identity_constraint(
        successor,
        &mut graph,
        &relation_key,
        "repository",
        "identity.github.repository",
        &relation.proof().source_identity,
    )?;
    add_identity_constraint(
        successor,
        &mut graph,
        &relation_key,
        "repository",
        "identity.github.repository",
        &relation.proof().target_identity,
    )?;
    add_expected_reference(
        successor,
        &mut graph,
        &relation_key,
        RegistryEntryKind::ApplicabilityEvaluator,
        "applicability.default",
        3,
        &relation.proof().applicability_evaluator,
    )?;
    validate_dimensions(
        successor,
        &mut graph,
        &relation_key,
        &relation.proof().applicability_dimensions,
    )?;

    if package.entries.len() != graph.len() {
        return Err(schema("Stage-4 dependency graph omitted inventory"));
    }
    require_all_reachable(&graph)
}

fn validate_entry_and_package_pins(
    successor: &SemanticallyClosedSuccessorPackage,
) -> ContractResult<()> {
    if successor.package_digest() != parse_digest(PACKAGE_DIGEST_HEX)? {
        return Err(ContractError::ManifestMismatch);
    }
    for (entry, expected_digest) in successor
        .manifest_verified_package()
        .package()
        .entries
        .iter()
        .zip(EXPECTED_ENTRY_DIGEST_HEX)
    {
        if entry.digest()? != parse_digest(expected_digest)? {
            return Err(ContractError::ManifestMismatch);
        }
    }
    Ok(())
}

fn require_all_reachable(graph: &BTreeMap<String, Vec<String>>) -> ContractResult<()> {
    let roots = [
        key(RegistryEntryKind::ActivationPolicy, "activation.default", 2),
        key(
            RegistryEntryKind::ConnectorSchema,
            "connector.github.push",
            3,
        ),
        key(
            RegistryEntryKind::AuthorityRule,
            "remember.actor_assertion",
            3,
        ),
        key(
            RegistryEntryKind::RelationProof,
            "relation.repository_parent",
            2,
        ),
    ];
    let mut queue = VecDeque::from(roots);
    let mut visited = BTreeSet::new();
    while let Some(current) = queue.pop_front() {
        if !visited.insert(current.clone()) {
            continue;
        }
        let dependencies = graph
            .get(&current)
            .ok_or_else(|| schema("Stage-4 dependency graph points outside inventory"))?;
        queue.extend(dependencies.iter().cloned());
    }
    let expected = graph.keys().cloned().collect::<BTreeSet<_>>();
    if visited != expected {
        return Err(schema("Stage-4 target contains unreachable inventory"));
    }
    Ok(())
}

fn add_identity_constraint(
    successor: &SemanticallyClosedSuccessorPackage,
    graph: &mut BTreeMap<String, Vec<String>>,
    from: &str,
    kind_id: &str,
    recipe_id: &str,
    constraint: &super::remember_v2::ResourceIdentityConstraintV2,
) -> ContractResult<()> {
    add_expected_reference(
        successor,
        graph,
        from,
        RegistryEntryKind::ResourceKindSchema,
        kind_id,
        3,
        &constraint.resource_kind_schema,
    )?;
    add_expected_reference(
        successor,
        graph,
        from,
        RegistryEntryKind::IdentityRecipe,
        recipe_id,
        3,
        &constraint.identity_recipe,
    )
}

fn validate_dimensions(
    successor: &SemanticallyClosedSuccessorPackage,
    graph: &mut BTreeMap<String, Vec<String>>,
    from: &str,
    dimensions: &[super::remember_v2::ApplicabilityDimensionRuleV2],
) -> ContractResult<()> {
    if dimensions.len() != 2
        || dimensions[0].dimension_id.as_str() != "repository_commit"
        || dimensions[1].dimension_id.as_str() != "runtime_environment"
        || !dimensions.iter().all(|dimension| dimension.required)
    {
        return Err(ContractError::ManifestMismatch);
    }
    add_identity_constraint(
        successor,
        graph,
        from,
        "commit",
        "identity.github.commit",
        &dimensions[0].resource_identity,
    )?;
    add_identity_constraint(
        successor,
        graph,
        from,
        "environment",
        "identity.runtime.environment",
        &dimensions[1].resource_identity,
    )
}

fn add_expected_reference(
    successor: &SemanticallyClosedSuccessorPackage,
    graph: &mut BTreeMap<String, Vec<String>>,
    from: &str,
    expected_kind: RegistryEntryKind,
    expected_id: &str,
    expected_version: u32,
    reference: &RegistryReferenceV1,
) -> ContractResult<()> {
    if reference.entry_id.as_str() != expected_id || reference.version != expected_version {
        return Err(ContractError::ManifestMismatch);
    }
    exact_entry(successor, expected_kind, reference)?;
    let to = key(expected_kind, expected_id, expected_version);
    let dependencies = graph
        .get_mut(from)
        .ok_or_else(|| schema("Stage-4 dependency source is outside inventory"))?;
    if !dependencies.contains(&to) {
        dependencies.push(to);
    }
    Ok(())
}

fn reference_for(
    successor: &SemanticallyClosedSuccessorPackage,
    kind: RegistryEntryKind,
    id: &str,
    version: u32,
) -> ContractResult<RegistryReferenceV1> {
    let entry = entry_by_tuple(successor, kind, id, version)?;
    Ok(RegistryReferenceV1 {
        entry_id: entry.entry_id.clone(),
        version: entry.version,
        entry_digest: entry.digest()?,
    })
}

fn entry_by_tuple<'a>(
    successor: &'a SemanticallyClosedSuccessorPackage,
    kind: RegistryEntryKind,
    id: &str,
    version: u32,
) -> ContractResult<&'a RegistryEntryV1> {
    successor
        .manifest_verified_package()
        .package()
        .entries
        .iter()
        .find(|entry| {
            entry.kind == kind && entry.entry_id.as_str() == id && entry.version == version
        })
        .ok_or_else(|| schema("Stage-4 target is missing an exact entry"))
}

fn exact_entry<'a>(
    successor: &'a SemanticallyClosedSuccessorPackage,
    kind: RegistryEntryKind,
    reference: &RegistryReferenceV1,
) -> ContractResult<&'a RegistryEntryV1> {
    successor.exact_entry(kind, reference)
}

fn decode_body<T: for<'de> Deserialize<'de>>(entry: &RegistryEntryV1) -> ContractResult<T> {
    decode_strict(&encode_canonical(&entry.body)?)
}

fn key(kind: RegistryEntryKind, id: &str, version: u32) -> String {
    format!("{}:{id}@{version}", kind.as_str())
}

fn schema_id(kind: RegistryEntryKind, entry_schema_version: u32) -> &'static str {
    if kind == RegistryEntryKind::AuthorityRule && entry_schema_version == 2 {
        "registry.remember_admission_rule"
    } else {
        match kind {
            RegistryEntryKind::ActivationPolicy => "registry.activation_policy",
            RegistryEntryKind::ApplicabilityEvaluator => "registry.applicability_evaluator",
            // W0-REG: generation-2-only kinds are outside the frozen 27-entry
            // inventory, so this label can never match an expected entry.
            RegistryEntryKind::ArrowBatchSchema
            | RegistryEntryKind::ComparatorLineage // W0-REG-2
            | RegistryEntryKind::ConsolidationPolicy // W0-REG-2
            | RegistryEntryKind::LogEpochRecipe
            | RegistryEntryKind::ParserContract => {
                "registry.generation2_only_kind_has_no_v1_schema"
            }
            RegistryEntryKind::AuthorityRule => "registry.authority_rule",
            RegistryEntryKind::CausalRatificationPolicy => "registry.causal_ratification_policy",
            RegistryEntryKind::ClassifierPolicy => "registry.classifier_policy",
            RegistryEntryKind::ConnectorSchema => "registry.connector_schema",
            RegistryEntryKind::CoverageProof => "registry.coverage_proof",
            RegistryEntryKind::EpisodePolicy => "registry.episode_policy",
            RegistryEntryKind::EvidenceSchema => "registry.evidence_schema",
            RegistryEntryKind::ExemplarPolicy => "registry.exemplar_policy",
            RegistryEntryKind::IdentityRecipe => "registry.identity_recipe",
            RegistryEntryKind::NamespaceDefinition => "registry.namespace_definition",
            RegistryEntryKind::NormativeBindingSchema => "registry.normative_binding_schema",
            RegistryEntryKind::ObserverAdmission => "registry.observer_admission",
            RegistryEntryKind::PredicateSchema => "registry.predicate_schema",
            RegistryEntryKind::PublicationRule => "registry.publication_rule",
            RegistryEntryKind::RedactionPolicy => "registry.redaction_policy",
            RegistryEntryKind::RelationProof => "registry.relation_proof",
            RegistryEntryKind::ResourceKindSchema => "registry.resource_kind_schema",
            RegistryEntryKind::RetentionPolicy => "registry.retention_policy",
        }
    }
}

fn parse_digest(value: &str) -> ContractResult<Sha256Digest> {
    Sha256Digest::from_str(value)
}

fn schema(message: &str) -> ContractError {
    ContractError::Schema(message.into())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceClosureV1 {
    schema_version: u32,
    evidence_schema_id: ContractId,
    version: u32,
    evidence_kind: ContractId,
    identity_recipe: RegistryReferenceV1,
    redaction_policy: RegistryReferenceV1,
    classifier_policy: RegistryReferenceV1,
    retention_policy: RegistryReferenceV1,
    publication_rule: RegistryReferenceV1,
    canonical_payload_required: bool,
    private_raw_default_enabled: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicationClosureV1 {
    schema_version: u32,
    rule_id: ContractId,
    version: u32,
    exemplar_policy: RegistryReferenceV1,
    default_publication: super::genesis::PublicationDefaultV1,
    classification_before_projection_required: bool,
    private_material_allowed: bool,
    raw_content_references_allowed: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClassifierClosureV1 {
    schema_version: u32,
    policy_id: ContractId,
    version: u32,
    server_derived: bool,
    classify_before_projection: bool,
    default_visibility: VisibilityClass,
    default_publication: PublicationClass,
    failure_outcome: PolicyFailureOutcomeV1,
}

#[cfg(test)]
mod tests {
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
            RememberEffectiveIntervalRuleV2, RememberValueConstraintV2,
            ResourceIdentityConstraintV2,
        },
    };

    const ACTIVATION_ENTRY_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v2/successor-policy/activation-policy-v2.jsonl"
    );
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

    const PACKAGE_RAW_SHA256: &str =
        "6e6a8eafe34913cc472ee9d970ddc23588568e9738040d464e1193d378e9f323";
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
        let positive: PackageCaseManifestV1 =
            decode_strict(record(PACKAGE_POSITIVE_FIXTURE)).unwrap();
        let negative: PackageCaseManifestV1 =
            decode_strict(record(PACKAGE_NEGATIVE_FIXTURE)).unwrap();
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
            SemanticallyClosedSuccessorPackage::from_manifest_verified(verified(rebuild(
                alternate
            )))
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
}
