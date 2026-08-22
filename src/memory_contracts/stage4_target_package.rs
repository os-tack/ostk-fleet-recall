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
#[path = "stage4_target_package_tests.rs"]
mod tests;
