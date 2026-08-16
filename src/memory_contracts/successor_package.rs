//! Offline semantic closure for successor registry packages.
//!
//! [`ManifestVerifiedRegistryPackage`] proves canonical bytes, ordering, and
//! full-entry manifest digests. This module adds exact `(kind, schema ID,
//! schema version)` dispatch and closes every modeled body over exact package
//! membership. It is deliberately not an active-head or repository authority
//! witness: any caller can construct valid offline package bytes.
//!
//! The generic closure intentionally permits closed historical entries that
//! are not reachable from a future Stage-4 target root. Its exact raw and typed
//! lookups let that later target wrapper enumerate its frozen roots and reject
//! unreachable inventory. The modeled dependency directions are type-closed
//! and acyclic; no reference field can point back to a predecessor selector.

use std::collections::BTreeSet;

use serde::{Serialize, de::DeserializeOwned};

use super::{
    ContractError, ContractResult,
    canonical::{decode_strict, encode_canonical},
    common::{ContractId, RegistryReferenceV1},
    digest::Sha256Digest,
    evidence_v2::StructurallyResolvedConnectorSchemaV2,
    genesis::{
        EvidenceSchemaEntryV1, SemanticallyDecodedGenesisEntryV1, decode_entry,
        generation2_only_kind_error, resolve_reference, validate_entry_identity,
        validate_entry_semantics,
    },
    identity::{IdentityForm, IdentityRecipeV1, ResourceKindSchemaV1},
    registry::{
        BodySchemaSlotClassV1, ManifestVerifiedRegistryPackage, RegistryEntryKind, RegistryEntryV1,
        classify_body_schema_triple,
    },
    relation_policy_v2::StructurallyResolvedRelationProofV2,
    remember_v2::{
        RememberAdmissionBasisRuleV2, RememberAdmissionRuleV2, RememberPredicateSchemaV2,
        RememberValueConstraintV2, ResourceIdentityConstraintV2,
        StructurallyResolvedRememberContractsV2,
    },
    successor_policy::StructurallyResolvedActivationPolicyV2,
};

const ACTIVATION_POLICY_SCHEMA_ID: &str = "registry.activation_policy";
const CONNECTOR_SCHEMA_ID: &str = "registry.connector_schema";
const PREDICATE_SCHEMA_ID: &str = "registry.predicate_schema";
const RELATION_PROOF_SCHEMA_ID: &str = "registry.relation_proof";
const REMEMBER_ADMISSION_SCHEMA_ID: &str = "registry.remember_admission_rule";
const LEGACY_SCHEMA_VERSION: u32 = 1;
const SUCCESSOR_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
enum DecodedSuccessorEntry {
    LegacyV1(SemanticallyDecodedGenesisEntryV1),
    ActivationPolicyV2(StructurallyResolvedActivationPolicyV2),
    ConnectorSchemaV2(StructurallyResolvedConnectorSchemaV2),
    RelationProofV2(StructurallyResolvedRelationProofV2),
    RememberPredicateSchemaV2 {
        registry_reference: RegistryReferenceV1,
        schema: RememberPredicateSchemaV2,
    },
    RememberAdmissionRuleV2 {
        registry_reference: RegistryReferenceV1,
        rule: RememberAdmissionRuleV2,
    },
}

/// Manifest-verified successor package with individually body-closed,
/// exact-schema entries and exactly one activation-policy v2 root.
///
/// Legacy relation-proof v1 entries may remain as closed historical data. A
/// relation-proof v2 accessor exposes only its exact offline structural body;
/// it does not create active relation or append authority. Likewise, this
/// generic layer does not reject unreachable historical entries; the frozen
/// Stage-4 target wrapper must enumerate exact capability roots and reject
/// inventory outside their permitted carry-forward set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticallyClosedSuccessorPackage {
    manifest_verified: ManifestVerifiedRegistryPackage,
    entries: Vec<DecodedSuccessorEntry>,
    activation_policy_v2_index: usize,
}

impl SemanticallyClosedSuccessorPackage {
    /// Close one offline package without creating any active-head authority.
    pub fn from_manifest_verified(
        manifest_verified: ManifestVerifiedRegistryPackage,
    ) -> ContractResult<Self> {
        manifest_verified
            .package()
            .profile
            .require_frozen_runtime_profile()?;

        let mut entries = Vec::with_capacity(manifest_verified.package().entries.len());
        for entry in &manifest_verified.package().entries {
            entries.push(decode_successor_entry(entry)?);
        }

        for (raw, decoded) in manifest_verified.package().entries.iter().zip(&entries) {
            if let DecodedSuccessorEntry::LegacyV1(decoded) = decoded {
                validate_entry_identity(raw, decoded)?;
                validate_entry_semantics(&manifest_verified, raw, decoded)?;
            }
        }

        for decoded in &entries {
            match decoded {
                DecodedSuccessorEntry::ConnectorSchemaV2(connector) => {
                    close_connector_v2(&manifest_verified, connector)?;
                }
                DecodedSuccessorEntry::RememberPredicateSchemaV2 { schema, .. } => {
                    close_remember_predicate_v2(&manifest_verified, schema)?;
                }
                DecodedSuccessorEntry::RelationProofV2(relation) => {
                    close_relation_v2(&manifest_verified, relation)?;
                }
                DecodedSuccessorEntry::LegacyV1(_)
                | DecodedSuccessorEntry::ActivationPolicyV2(_)
                | DecodedSuccessorEntry::RememberAdmissionRuleV2 { .. } => {}
            }
        }
        close_remember_admission_routes(&manifest_verified, &entries)?;

        let activation_policy_v2_index = singleton_v2_activation_policy_index(&entries)?;
        Ok(Self {
            manifest_verified,
            entries,
            activation_policy_v2_index,
        })
    }

    pub const fn manifest_verified_package(&self) -> &ManifestVerifiedRegistryPackage {
        &self.manifest_verified
    }

    pub const fn package_digest(&self) -> Sha256Digest {
        self.manifest_verified.package_digest()
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        self.manifest_verified.canonical_bytes()
    }

    pub fn activation_policy(&self) -> &StructurallyResolvedActivationPolicyV2 {
        match &self.entries[self.activation_policy_v2_index] {
            DecodedSuccessorEntry::ActivationPolicyV2(policy) => policy,
            _ => unreachable!("v2 activation-policy index is closed during construction"),
        }
    }

    /// Resolve one exact raw entry from this offline package closure.
    ///
    /// This proves package membership only. A later repository must separately
    /// bind this package to the current durable head before using the entry for
    /// admission.
    pub fn exact_entry(
        &self,
        expected_kind: RegistryEntryKind,
        reference: &RegistryReferenceV1,
    ) -> ContractResult<&RegistryEntryV1> {
        resolve_reference(self.manifest_verified.package(), expected_kind, reference)
    }

    pub fn connector_schema(
        &self,
        reference: &RegistryReferenceV1,
    ) -> Option<&StructurallyResolvedConnectorSchemaV2> {
        self.entries.iter().find_map(|entry| match entry {
            DecodedSuccessorEntry::ConnectorSchemaV2(connector)
                if connector.registry_reference() == reference =>
            {
                Some(connector)
            }
            _ => None,
        })
    }

    pub fn remember_predicate(
        &self,
        reference: &RegistryReferenceV1,
    ) -> Option<&RememberPredicateSchemaV2> {
        self.entries.iter().find_map(|entry| match entry {
            DecodedSuccessorEntry::RememberPredicateSchemaV2 {
                registry_reference,
                schema,
            } if registry_reference == reference => Some(schema),
            _ => None,
        })
    }

    pub fn remember_admission(
        &self,
        reference: &RegistryReferenceV1,
    ) -> Option<&RememberAdmissionRuleV2> {
        self.entries.iter().find_map(|entry| match entry {
            DecodedSuccessorEntry::RememberAdmissionRuleV2 {
                registry_reference,
                rule,
            } if registry_reference == reference => Some(rule),
            _ => None,
        })
    }

    /// Resolve one exact relation-proof v2 structural body from this offline
    /// package closure. Active-head and append authority remain separate.
    pub fn relation_proof(
        &self,
        reference: &RegistryReferenceV1,
    ) -> Option<&StructurallyResolvedRelationProofV2> {
        self.entries.iter().find_map(|entry| match entry {
            DecodedSuccessorEntry::RelationProofV2(relation)
                if relation.registry_reference() == reference =>
            {
                Some(relation)
            }
            _ => None,
        })
    }
}

impl TryFrom<ManifestVerifiedRegistryPackage> for SemanticallyClosedSuccessorPackage {
    type Error = ContractError;

    fn try_from(value: ManifestVerifiedRegistryPackage) -> Result<Self, Self::Error> {
        Self::from_manifest_verified(value)
    }
}

fn decode_successor_entry(entry: &RegistryEntryV1) -> ContractResult<DecodedSuccessorEntry> {
    let schema_id = entry.entry_schema_id.as_str();
    if entry.kind.is_generation2_only() {
        return Err(generation2_only_kind_error(entry));
    }
    if classify_body_schema_triple(entry.kind, schema_id, entry.entry_schema_version)
        == BodySchemaSlotClassV1::Generation2Reserved
    {
        return Err(ContractError::Schema(format!(
            "reserved generation-2 body schema ({}, {}, {}) has no wired typed body",
            entry.kind.as_str(),
            entry.entry_schema_id,
            entry.entry_schema_version
        )));
    }
    match (entry.kind, schema_id, entry.entry_schema_version) {
        (
            RegistryEntryKind::ActivationPolicy,
            ACTIVATION_POLICY_SCHEMA_ID,
            SUCCESSOR_SCHEMA_VERSION,
        ) => {
            let policy = StructurallyResolvedActivationPolicyV2::from_registry_entry(entry)?;
            require_exact_typed_body(entry, policy.policy())?;
            Ok(DecodedSuccessorEntry::ActivationPolicyV2(policy))
        }
        (RegistryEntryKind::ConnectorSchema, CONNECTOR_SCHEMA_ID, SUCCESSOR_SCHEMA_VERSION) => {
            let connector = StructurallyResolvedConnectorSchemaV2::from_registry_entry(entry)?;
            require_exact_typed_body(entry, connector.schema())?;
            Ok(DecodedSuccessorEntry::ConnectorSchemaV2(connector))
        }
        (RegistryEntryKind::RelationProof, RELATION_PROOF_SCHEMA_ID, SUCCESSOR_SCHEMA_VERSION) => {
            let relation = StructurallyResolvedRelationProofV2::from_registry_entry(entry)?;
            require_exact_typed_body(entry, relation.proof())?;
            Ok(DecodedSuccessorEntry::RelationProofV2(relation))
        }
        (RegistryEntryKind::PredicateSchema, PREDICATE_SCHEMA_ID, SUCCESSOR_SCHEMA_VERSION) => {
            let schema: RememberPredicateSchemaV2 = decode_body(entry)?;
            schema.validate_shape()?;
            require_exact_typed_body(entry, &schema)?;
            require_body_identity(entry, &schema.predicate_id, schema.version)?;
            Ok(DecodedSuccessorEntry::RememberPredicateSchemaV2 {
                registry_reference: registry_reference(entry)?,
                schema,
            })
        }
        (
            RegistryEntryKind::AuthorityRule,
            REMEMBER_ADMISSION_SCHEMA_ID,
            SUCCESSOR_SCHEMA_VERSION,
        ) => {
            let rule: RememberAdmissionRuleV2 = decode_body(entry)?;
            rule.validate_shape()?;
            require_exact_typed_body(entry, &rule)?;
            require_body_identity(entry, &rule.rule_id, rule.version)?;
            Ok(DecodedSuccessorEntry::RememberAdmissionRuleV2 {
                registry_reference: registry_reference(entry)?,
                rule,
            })
        }
        (kind, id, LEGACY_SCHEMA_VERSION) if id == legacy_schema_id(kind) => {
            Ok(DecodedSuccessorEntry::LegacyV1(decode_entry(entry)?))
        }
        _ => Err(ContractError::Schema(format!(
            "unsupported successor registry selector ({}, {}, {})",
            entry.kind.as_str(),
            entry.entry_schema_id,
            entry.entry_schema_version
        ))),
    }
}

/// Legacy v1 body-schema ID for one kind.
///
/// Generation-2-only kinds return an ID that no v1 body schema claims, so the
/// legacy fallback arm of [`decode_successor_entry`] can never match them even
/// if the earlier explicit guard were removed.
const fn legacy_schema_id(kind: RegistryEntryKind) -> &'static str {
    match kind {
        RegistryEntryKind::ActivationPolicy => "registry.activation_policy",
        RegistryEntryKind::ApplicabilityEvaluator => "registry.applicability_evaluator",
        RegistryEntryKind::ArrowBatchSchema
        | RegistryEntryKind::LogEpochRecipe
        | RegistryEntryKind::ParserContract => "registry.generation2_only_kind_has_no_v1_schema",
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

fn singleton_v2_activation_policy_index(
    entries: &[DecodedSuccessorEntry],
) -> ContractResult<usize> {
    let mut matches = entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| matches!(entry, DecodedSuccessorEntry::ActivationPolicyV2(_)))
        .map(|(index, _)| index);
    let first = matches.next().ok_or_else(|| {
        ContractError::Schema("successor package lacks an activation-policy v2 root".into())
    })?;
    if matches.next().is_some() {
        return Err(ContractError::Schema(
            "successor package has ambiguous activation-policy v2 roots".into(),
        ));
    }
    Ok(first)
}

fn close_connector_v2(
    package: &ManifestVerifiedRegistryPackage,
    connector: &StructurallyResolvedConnectorSchemaV2,
) -> ContractResult<()> {
    let schema = connector.schema();
    resolve_reference(
        package.package(),
        RegistryEntryKind::NamespaceDefinition,
        &schema.provider_namespace,
    )?;
    let evidence_entry = resolve_reference(
        package.package(),
        RegistryEntryKind::EvidenceSchema,
        &schema.evidence_schema,
    )?;
    let provider_recipe_entry = resolve_reference(
        package.package(),
        RegistryEntryKind::IdentityRecipe,
        &schema.provider_instance_identity_recipe,
    )?;
    resolve_reference(
        package.package(),
        RegistryEntryKind::IdentityRecipe,
        &schema.canonical_resource_identity_recipe,
    )?;

    let evidence: EvidenceSchemaEntryV1 = decode_body(evidence_entry)?;
    let provider_recipe: IdentityRecipeV1 = decode_body(provider_recipe_entry)?;
    let provider_kind_entry = resolve_reference(
        package.package(),
        RegistryEntryKind::ResourceKindSchema,
        &provider_recipe.resource_kind_schema,
    )?;
    let provider_kind: ResourceKindSchemaV1 = decode_body(provider_kind_entry)?;
    if provider_recipe.authority_namespace != schema.provider_namespace
        || provider_recipe.identity_form != IdentityForm::Entity
        || provider_kind.identity_form != IdentityForm::Entity
        || evidence.identity_recipe() != &schema.canonical_resource_identity_recipe
    {
        return Err(ContractError::ManifestMismatch);
    }
    Ok(())
}

fn close_remember_predicate_v2(
    package: &ManifestVerifiedRegistryPackage,
    predicate: &RememberPredicateSchemaV2,
) -> ContractResult<()> {
    close_resource_identity(package, &predicate.subject_identity)?;
    if let RememberValueConstraintV2::ResourceUri { resource_identity } =
        &predicate.value_constraint
    {
        close_resource_identity(package, resource_identity)?;
    }
    for dimension in &predicate.applicability_dimensions {
        close_resource_identity(package, &dimension.resource_identity)?;
    }
    resolve_reference(
        package.package(),
        RegistryEntryKind::ApplicabilityEvaluator,
        &predicate.applicability_evaluator,
    )?;
    if let Some(coverage_proof) = &predicate.coverage_proof {
        resolve_reference(
            package.package(),
            RegistryEntryKind::CoverageProof,
            coverage_proof,
        )?;
    }
    Ok(())
}

fn close_relation_v2(
    package: &ManifestVerifiedRegistryPackage,
    relation: &StructurallyResolvedRelationProofV2,
) -> ContractResult<()> {
    let proof = relation.proof();
    close_resource_identity(package, &proof.source_identity)?;
    close_resource_identity(package, &proof.target_identity)?;
    for dimension in &proof.applicability_dimensions {
        close_resource_identity(package, &dimension.resource_identity)?;
    }
    resolve_reference(
        package.package(),
        RegistryEntryKind::ApplicabilityEvaluator,
        &proof.applicability_evaluator,
    )?;
    Ok(())
}

fn close_resource_identity(
    package: &ManifestVerifiedRegistryPackage,
    constraint: &ResourceIdentityConstraintV2,
) -> ContractResult<()> {
    let kind_entry = resolve_reference(
        package.package(),
        RegistryEntryKind::ResourceKindSchema,
        &constraint.resource_kind_schema,
    )?;
    let recipe_entry = resolve_reference(
        package.package(),
        RegistryEntryKind::IdentityRecipe,
        &constraint.identity_recipe,
    )?;
    let kind: ResourceKindSchemaV1 = decode_body(kind_entry)?;
    let recipe: IdentityRecipeV1 = decode_body(recipe_entry)?;
    if recipe.resource_kind_schema != constraint.resource_kind_schema
        || recipe.resource_kind != kind.resource_kind
        || recipe.identity_form != kind.identity_form
    {
        return Err(ContractError::ManifestMismatch);
    }
    Ok(())
}

fn close_remember_admission_routes(
    package: &ManifestVerifiedRegistryPackage,
    entries: &[DecodedSuccessorEntry],
) -> ContractResult<()> {
    let mut actor_routes = BTreeSet::new();
    for decoded in entries {
        let DecodedSuccessorEntry::RememberAdmissionRuleV2 {
            registry_reference,
            rule,
        } = decoded
        else {
            continue;
        };
        let predicate_entry = resolve_reference(
            package.package(),
            RegistryEntryKind::PredicateSchema,
            &rule.predicate_schema,
        )?;
        let admission_entry = resolve_reference(
            package.package(),
            RegistryEntryKind::AuthorityRule,
            registry_reference,
        )?;
        StructurallyResolvedRememberContractsV2::from_registry_entries(
            predicate_entry,
            admission_entry,
        )?;
        for (kind, reference) in [
            (
                RegistryEntryKind::ApplicabilityEvaluator,
                &rule.applicability_evaluator,
            ),
            (RegistryEntryKind::ClassifierPolicy, &rule.classifier_policy),
            (RegistryEntryKind::RedactionPolicy, &rule.redaction_policy),
            (RegistryEntryKind::RetentionPolicy, &rule.retention_policy),
            (RegistryEntryKind::PublicationRule, &rule.publication_rule),
        ] {
            resolve_reference(package.package(), kind, reference)?;
        }
        if rule.basis_rules.iter().any(|basis| {
            !matches!(
                basis,
                RememberAdmissionBasisRuleV2::AuthenticatedActor { .. }
            )
        }) {
            return Err(ContractError::Schema(
                "successor package does not yet activate observer or normative remember bases"
                    .into(),
            ));
        }
        if !actor_routes.insert(rule.predicate_schema.clone()) {
            return Err(ContractError::Schema(
                "successor package has an ambiguous authenticated-actor remember route".into(),
            ));
        }
    }
    Ok(())
}

fn require_body_identity(
    entry: &RegistryEntryV1,
    body_id: &ContractId,
    body_version: u32,
) -> ContractResult<()> {
    if body_id != &entry.entry_id || body_version != entry.version {
        return Err(ContractError::ManifestMismatch);
    }
    Ok(())
}

fn registry_reference(entry: &RegistryEntryV1) -> ContractResult<RegistryReferenceV1> {
    Ok(RegistryReferenceV1 {
        entry_id: entry.entry_id.clone(),
        version: entry.version,
        entry_digest: entry.digest()?,
    })
}

fn decode_body<T: DeserializeOwned>(entry: &RegistryEntryV1) -> ContractResult<T> {
    decode_strict(&encode_canonical(&entry.body)?)
}

fn require_exact_typed_body<T: Serialize>(
    entry: &RegistryEntryV1,
    typed: &T,
) -> ContractResult<()> {
    if encode_canonical(&entry.body)? != encode_canonical(typed)? {
        return Err(ContractError::Schema(
            "successor registry body is not an exact typed preimage".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory_contracts::{
        canonical::CanonicalValue,
        common::frozen_profile_reference_v1,
        evidence_v2::ConnectorSchemaV2,
        identity::{
            AuthorityNamespaceV1, IdentityComponentRuleV1, LocatorEncoding, ResourceKindSchemaV1,
        },
        registry::{RegistryManifestEntryV1, RegistryPackageV1},
        relation_policy_v2::RelationProofEntryV2,
    };

    const GENESIS_PACKAGE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v1/genesis-registry-package.jsonl");
    const ACTIVATION_POLICY_V2: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v2/successor-policy/activation-policy-v2.jsonl"
    );
    const CONNECTOR_V2: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v2/evidence/connector-schema-v2-entry.jsonl"
    );
    const REMEMBER_PREDICATE_V2: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v2/remember/remember-predicate-schema-v2-entry.jsonl"
    );
    const REMEMBER_ADMISSION_V2: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v2/remember/remember-admission-rule-v2-entry.jsonl"
    );
    const RELATION_PROOF_V2: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v2/relation-policy/relation-proof-v2-entry.jsonl"
    );

    fn record(bytes: &[u8]) -> &[u8] {
        let record = bytes
            .strip_suffix(b"\n")
            .expect("fixture must have exactly one terminal LF");
        assert!(!record.ends_with(b"\n"));
        record
    }

    fn fixture_entry(bytes: &[u8]) -> RegistryEntryV1 {
        decode_strict(record(bytes)).unwrap()
    }

    fn genesis_package() -> RegistryPackageV1 {
        ManifestVerifiedRegistryPackage::decode(
            record(GENESIS_PACKAGE),
            &frozen_profile_reference_v1(),
        )
        .unwrap()
        .package()
        .clone()
    }

    fn rebuild(mut package: RegistryPackageV1) -> ManifestVerifiedRegistryPackage {
        package.entries.sort_by(|left, right| {
            (left.kind.as_str(), left.entry_id.as_str(), left.version).cmp(&(
                right.kind.as_str(),
                right.entry_id.as_str(),
                right.version,
            ))
        });
        package.manifest = package
            .entries
            .iter()
            .map(|entry| RegistryManifestEntryV1 {
                kind: entry.kind,
                entry_id: entry.entry_id.clone(),
                version: entry.version,
                entry_digest: entry.digest().unwrap(),
            })
            .collect();
        ManifestVerifiedRegistryPackage::new(package, &frozen_profile_reference_v1()).unwrap()
    }

    fn package_with(entries: impl IntoIterator<Item = RegistryEntryV1>) -> RegistryPackageV1 {
        let mut package = genesis_package();
        package.entries.push(fixture_entry(ACTIVATION_POLICY_V2));
        package.entries.extend(entries);
        package
    }

    fn exact_reference(
        package: &RegistryPackageV1,
        kind: RegistryEntryKind,
        entry_id: &str,
        version: u32,
    ) -> RegistryReferenceV1 {
        let entry = package
            .entries
            .iter()
            .find(|entry| {
                entry.kind == kind
                    && entry.entry_id.as_str() == entry_id
                    && entry.version == version
            })
            .unwrap();
        registry_reference(entry).unwrap()
    }

    fn replace_body<T: serde::Serialize>(entry: &mut RegistryEntryV1, body: &T) {
        entry.body = decode_strict(&encode_canonical(body).unwrap()).unwrap();
    }

    fn legacy_entry<T: serde::Serialize>(
        package: &RegistryPackageV1,
        kind: RegistryEntryKind,
        entry_id: &str,
        version: u32,
        body: &T,
    ) -> RegistryEntryV1 {
        let vector_source = package.entries.first().unwrap();
        RegistryEntryV1 {
            schema_version: 1,
            kind,
            entry_id: ContractId::new(entry_id).unwrap(),
            version,
            entry_schema_id: ContractId::new(legacy_schema_id(kind)).unwrap(),
            entry_schema_version: 1,
            body: decode_strict(&encode_canonical(body).unwrap()).unwrap(),
            positive_vector_digest: vector_source.positive_vector_digest,
            negative_vector_digest: vector_source.negative_vector_digest,
        }
    }

    fn compatible_connector(package: &RegistryPackageV1) -> RegistryEntryV1 {
        let mut entry = fixture_entry(CONNECTOR_V2);
        let mut connector: ConnectorSchemaV2 = decode_body(&entry).unwrap();
        connector.provider_namespace = exact_reference(
            package,
            RegistryEntryKind::NamespaceDefinition,
            "github.namespace",
            1,
        );
        connector.evidence_schema = exact_reference(
            package,
            RegistryEntryKind::EvidenceSchema,
            "evidence.git_blob",
            1,
        );
        let recipe = exact_reference(
            package,
            RegistryEntryKind::IdentityRecipe,
            "github.repository",
            1,
        );
        connector.provider_instance_identity_recipe = recipe.clone();
        connector.canonical_resource_identity_recipe = recipe;
        replace_body(&mut entry, &connector);
        entry
    }

    fn compatible_predicate(package: &RegistryPackageV1) -> RegistryEntryV1 {
        let mut entry = fixture_entry(REMEMBER_PREDICATE_V2);
        let mut predicate: RememberPredicateSchemaV2 = decode_body(&entry).unwrap();
        let identity = ResourceIdentityConstraintV2 {
            resource_kind_schema: exact_reference(
                package,
                RegistryEntryKind::ResourceKindSchema,
                "repository",
                1,
            ),
            identity_recipe: exact_reference(
                package,
                RegistryEntryKind::IdentityRecipe,
                "github.repository",
                1,
            ),
        };
        predicate.subject_identity = identity.clone();
        for dimension in &mut predicate.applicability_dimensions {
            dimension.resource_identity = identity.clone();
        }
        predicate.applicability_evaluator = exact_reference(
            package,
            RegistryEntryKind::ApplicabilityEvaluator,
            "applicability.default",
            1,
        );
        replace_body(&mut entry, &predicate);
        entry
    }

    fn compatible_admission(
        package: &RegistryPackageV1,
        predicate_entry: &RegistryEntryV1,
    ) -> RegistryEntryV1 {
        let mut entry = fixture_entry(REMEMBER_ADMISSION_V2);
        let mut admission: RememberAdmissionRuleV2 = decode_body(&entry).unwrap();
        admission.predicate_schema = registry_reference(predicate_entry).unwrap();
        admission.applicability_evaluator = exact_reference(
            package,
            RegistryEntryKind::ApplicabilityEvaluator,
            "applicability.default",
            1,
        );
        admission.classifier_policy = exact_reference(
            package,
            RegistryEntryKind::ClassifierPolicy,
            "classifier.default",
            1,
        );
        admission.redaction_policy = exact_reference(
            package,
            RegistryEntryKind::RedactionPolicy,
            "redaction.default",
            1,
        );
        admission.retention_policy = exact_reference(
            package,
            RegistryEntryKind::RetentionPolicy,
            "retention.default",
            1,
        );
        admission.publication_rule = exact_reference(
            package,
            RegistryEntryKind::PublicationRule,
            "publication.default",
            1,
        );
        replace_body(&mut entry, &admission);
        entry
    }

    fn compatible_relation(package: &RegistryPackageV1) -> RegistryEntryV1 {
        let mut entry = fixture_entry(RELATION_PROOF_V2);
        let mut relation: RelationProofEntryV2 = decode_body(&entry).unwrap();
        let identity = ResourceIdentityConstraintV2 {
            resource_kind_schema: exact_reference(
                package,
                RegistryEntryKind::ResourceKindSchema,
                "repository",
                1,
            ),
            identity_recipe: exact_reference(
                package,
                RegistryEntryKind::IdentityRecipe,
                "github.repository",
                1,
            ),
        };
        relation.source_identity = identity.clone();
        relation.target_identity = identity.clone();
        for dimension in &mut relation.applicability_dimensions {
            dimension.resource_identity = identity.clone();
        }
        relation.applicability_evaluator = exact_reference(
            package,
            RegistryEntryKind::ApplicabilityEvaluator,
            "applicability.default",
            1,
        );
        replace_body(&mut entry, &relation);
        entry
    }

    #[test]
    fn exact_legacy_and_activation_v2_tuples_close_without_runtime_authority() {
        let verified = rebuild(package_with([]));
        let closed = SemanticallyClosedSuccessorPackage::from_manifest_verified(verified).unwrap();
        assert_eq!(
            closed.activation_policy().registry_reference().entry_digest,
            fixture_entry(ACTIVATION_POLICY_V2).digest().unwrap()
        );
        assert_eq!(
            closed
                .exact_entry(
                    RegistryEntryKind::ActivationPolicy,
                    closed.activation_policy().registry_reference(),
                )
                .unwrap()
                .entry_schema_version,
            2
        );
    }

    #[test]
    fn policy_only_package_is_generic_offline_closure_not_a_stage4_capability() {
        let mut package = genesis_package();
        package.entries.clear();
        package.entries.push(fixture_entry(ACTIVATION_POLICY_V2));
        let closed =
            SemanticallyClosedSuccessorPackage::from_manifest_verified(rebuild(package)).unwrap();
        assert_eq!(
            closed.manifest_verified_package().package().entries.len(),
            1
        );
        let connector_reference = registry_reference(&fixture_entry(CONNECTOR_V2)).unwrap();
        assert!(
            closed
                .exact_entry(RegistryEntryKind::ConnectorSchema, &connector_reference)
                .is_err()
        );
    }

    #[test]
    fn unreachable_legacy_entry_is_historical_inventory_not_a_capability_root() {
        let mut package = package_with([]);
        let orphan_kind = ResourceKindSchemaV1 {
            schema_version: 1,
            resource_kind: ContractId::new("orphan_resource").unwrap(),
            version: 1,
            identity_form: IdentityForm::Entity,
            parent_entity_kind: None,
            component_rules: vec![IdentityComponentRuleV1 {
                key: ContractId::new("orphan_id").unwrap(),
                encoding: LocatorEncoding::NfcUtf8,
            }],
        };
        let orphan_entry = legacy_entry(
            &package,
            RegistryEntryKind::ResourceKindSchema,
            "orphan_resource",
            1,
            &orphan_kind,
        );
        let orphan_reference = registry_reference(&orphan_entry).unwrap();
        package.entries.push(orphan_entry);
        let closed =
            SemanticallyClosedSuccessorPackage::from_manifest_verified(rebuild(package)).unwrap();
        assert!(
            closed
                .exact_entry(RegistryEntryKind::ResourceKindSchema, &orphan_reference)
                .is_ok()
        );
        assert!(closed.connector_schema(&orphan_reference).is_none());
        assert!(closed.remember_predicate(&orphan_reference).is_none());
        assert!(closed.remember_admission(&orphan_reference).is_none());
        assert!(closed.relation_proof(&orphan_reference).is_none());
    }

    #[test]
    fn exact_relation_v2_tuple_closes_without_active_authority() {
        let relation = compatible_relation(&package_with([]));
        let relation_reference = registry_reference(&relation).unwrap();
        let closed =
            SemanticallyClosedSuccessorPackage::from_manifest_verified(rebuild(package_with([
                relation,
            ])))
            .unwrap();

        let resolved = closed.relation_proof(&relation_reference).unwrap();
        assert_eq!(resolved.registry_reference(), &relation_reference);
        assert_eq!(
            closed
                .exact_entry(RegistryEntryKind::RelationProof, &relation_reference)
                .unwrap()
                .entry_schema_version,
            SUCCESSOR_SCHEMA_VERSION
        );
    }

    #[test]
    fn relation_v2_dependency_references_must_resolve_from_the_same_package() {
        let error =
            SemanticallyClosedSuccessorPackage::from_manifest_verified(rebuild(package_with([
                fixture_entry(RELATION_PROOF_V2),
            ])))
            .unwrap_err();
        assert!(
            matches!(error, ContractError::Schema(message) if message.contains("missing exact"))
        );
    }

    #[test]
    fn relation_v2_selector_and_body_identity_fail_closed() {
        let valid = fixture_entry(RELATION_PROOF_V2);
        let mut wrong_kind = valid.clone();
        wrong_kind.kind = RegistryEntryKind::AuthorityRule;
        let mut wrong_schema_id = valid.clone();
        wrong_schema_id.entry_schema_id = ContractId::new("registry.authority_rule").unwrap();
        let mut wrong_schema_version = valid.clone();
        wrong_schema_version.entry_schema_version = 3;

        for entry in [wrong_kind, wrong_schema_id, wrong_schema_version] {
            let error = decode_successor_entry(&entry).unwrap_err();
            assert!(
                matches!(error, ContractError::Schema(message) if message.contains("unsupported successor registry selector"))
            );
        }

        let mut wrong_body_id = valid.clone();
        let mut body: RelationProofEntryV2 = decode_body(&wrong_body_id).unwrap();
        body.relation_id = ContractId::new("relation.other").unwrap();
        replace_body(&mut wrong_body_id, &body);
        assert_eq!(
            decode_successor_entry(&wrong_body_id),
            Err(ContractError::ManifestMismatch)
        );

        let mut wrong_body_version = valid;
        let mut body: RelationProofEntryV2 = decode_body(&wrong_body_version).unwrap();
        body.version += 1;
        replace_body(&mut wrong_body_version, &body);
        assert_eq!(
            decode_successor_entry(&wrong_body_version),
            Err(ContractError::ManifestMismatch)
        );
    }

    #[test]
    fn landed_v2_selectors_dispatch_then_fail_on_label_derived_missing_dependencies() {
        for entry in [
            fixture_entry(CONNECTOR_V2),
            fixture_entry(REMEMBER_PREDICATE_V2),
            fixture_entry(REMEMBER_ADMISSION_V2),
        ] {
            let error = SemanticallyClosedSuccessorPackage::from_manifest_verified(rebuild(
                package_with([entry]),
            ))
            .unwrap_err();
            let ContractError::Schema(message) = error else {
                panic!("expected exact dependency failure, got {error:?}");
            };
            assert!(message.contains("missing exact"), "{message}");
            assert!(!message.contains("unsupported successor registry selector"));
        }
    }

    #[test]
    fn v2_body_must_be_the_exact_typed_preimage() {
        let mut predicate = compatible_predicate(&package_with([]));
        let CanonicalValue::Object(fields) = &mut predicate.body else {
            panic!("predicate fixture body must be an object");
        };
        assert_eq!(fields.remove("coverage_proof"), Some(CanonicalValue::Null));

        let error =
            SemanticallyClosedSuccessorPackage::from_manifest_verified(rebuild(package_with([
                predicate,
            ])))
            .unwrap_err();
        assert!(
            matches!(error, ContractError::Schema(message) if message.contains("exact typed preimage"))
        );
    }

    #[test]
    fn compatible_connector_and_actor_remember_graph_close_exactly() {
        let mut package = package_with([]);
        let connector = compatible_connector(&package);
        let predicate = compatible_predicate(&package);
        let admission = compatible_admission(&package, &predicate);
        let connector_reference = registry_reference(&connector).unwrap();
        let predicate_reference = registry_reference(&predicate).unwrap();
        let admission_reference = registry_reference(&admission).unwrap();
        package.entries.extend([connector, predicate, admission]);
        let closed =
            SemanticallyClosedSuccessorPackage::from_manifest_verified(rebuild(package)).unwrap();
        assert!(closed.connector_schema(&connector_reference).is_some());
        assert!(closed.remember_predicate(&predicate_reference).is_some());
        assert!(closed.remember_admission(&admission_reference).is_some());
    }

    #[test]
    fn connector_provider_instance_recipe_must_resolve_to_an_entity_kind() {
        let mut package = package_with([]);
        let components = vec![IdentityComponentRuleV1 {
            key: ContractId::new("provider_repository_version_id").unwrap(),
            encoding: LocatorEncoding::NfcUtf8,
        }];
        let namespace = AuthorityNamespaceV1 {
            schema_version: 1,
            namespace_id: ContractId::new("github.version.namespace").unwrap(),
            version: 1,
            immutable_coordinate_keys: vec![
                ContractId::new("provider_repository_version_id").unwrap(),
            ],
        };
        let namespace_entry = legacy_entry(
            &package,
            RegistryEntryKind::NamespaceDefinition,
            "github.version.namespace",
            1,
            &namespace,
        );
        let namespace_reference = registry_reference(&namespace_entry).unwrap();
        let kind = ResourceKindSchemaV1 {
            schema_version: 1,
            resource_kind: ContractId::new("repository_version").unwrap(),
            version: 1,
            identity_form: IdentityForm::Version,
            parent_entity_kind: Some(exact_reference(
                &package,
                RegistryEntryKind::ResourceKindSchema,
                "repository",
                1,
            )),
            component_rules: components.clone(),
        };
        let kind_entry = legacy_entry(
            &package,
            RegistryEntryKind::ResourceKindSchema,
            "repository_version",
            1,
            &kind,
        );
        let kind_reference = registry_reference(&kind_entry).unwrap();
        let recipe = IdentityRecipeV1 {
            schema_version: 1,
            recipe_id: ContractId::new("github.repository_version").unwrap(),
            version: 1,
            resource_kind: ContractId::new("repository_version").unwrap(),
            identity_form: IdentityForm::Version,
            authority_namespace: namespace_reference.clone(),
            resource_kind_schema: kind_reference,
            component_rules: components,
        };
        let recipe_entry = legacy_entry(
            &package,
            RegistryEntryKind::IdentityRecipe,
            "github.repository_version",
            1,
            &recipe,
        );
        let recipe_reference = registry_reference(&recipe_entry).unwrap();
        package
            .entries
            .extend([namespace_entry, kind_entry, recipe_entry]);

        let mut connector = compatible_connector(&package);
        let mut connector_body: ConnectorSchemaV2 = decode_body(&connector).unwrap();
        connector_body.provider_namespace = namespace_reference;
        connector_body.provider_instance_identity_recipe = recipe_reference;
        replace_body(&mut connector, &connector_body);
        package.entries.push(connector);

        assert_eq!(
            SemanticallyClosedSuccessorPackage::from_manifest_verified(rebuild(package)),
            Err(ContractError::ManifestMismatch)
        );
    }

    #[test]
    fn unknown_v2_selector_and_ambiguous_actor_route_fail_closed() {
        let mut wrong_selector = fixture_entry(CONNECTOR_V2);
        wrong_selector.entry_schema_version = 3;
        let error =
            SemanticallyClosedSuccessorPackage::from_manifest_verified(rebuild(package_with([
                wrong_selector,
            ])))
            .unwrap_err();
        assert!(
            matches!(error, ContractError::Schema(message) if message.contains("unsupported successor registry selector"))
        );

        let mut package = package_with([]);
        let predicate = compatible_predicate(&package);
        let admission = compatible_admission(&package, &predicate);
        let mut duplicate_route = admission.clone();
        duplicate_route.entry_id = ContractId::new("remember.actor_assertion.other").unwrap();
        let mut duplicate_rule: RememberAdmissionRuleV2 = decode_body(&duplicate_route).unwrap();
        duplicate_rule.rule_id = duplicate_route.entry_id.clone();
        replace_body(&mut duplicate_route, &duplicate_rule);
        package
            .entries
            .extend([predicate, admission, duplicate_route]);
        let error = SemanticallyClosedSuccessorPackage::from_manifest_verified(rebuild(package))
            .unwrap_err();
        assert!(
            matches!(error, ContractError::Schema(message) if message.contains("ambiguous authenticated-actor remember route"))
        );
    }

    #[test]
    fn successor_requires_exactly_one_v2_activation_policy_root() {
        let error =
            SemanticallyClosedSuccessorPackage::from_manifest_verified(rebuild(genesis_package()))
                .unwrap_err();
        assert!(
            matches!(error, ContractError::Schema(message) if message.contains("lacks an activation-policy v2 root"))
        );

        let mut package = package_with([]);
        let mut second = fixture_entry(ACTIVATION_POLICY_V2);
        second.entry_id = ContractId::new("activation.secondary").unwrap();
        let mut policy: super::super::successor_policy::ActivationPolicyEntryV2 =
            decode_body(&second).unwrap();
        policy.policy_id = second.entry_id.clone();
        replace_body(&mut second, &policy);
        package.entries.push(second);
        let error = SemanticallyClosedSuccessorPackage::from_manifest_verified(rebuild(package))
            .unwrap_err();
        assert!(
            matches!(error, ContractError::Schema(message) if message.contains("ambiguous activation-policy v2 roots"))
        );
    }

    #[test]
    fn programmatic_body_is_still_canonical_value_bounded() {
        let mut entry = fixture_entry(ACTIVATION_POLICY_V2);
        entry.body = CanonicalValue::Array(Vec::new());
        let mut package = genesis_package();
        package.entries.clear();
        package.entries.push(entry);
        assert!(
            ManifestVerifiedRegistryPackage::new(package, &frozen_profile_reference_v1()).is_err()
        );
    }

    #[test]
    fn generation2_only_kinds_and_reserved_triples_have_no_typed_body() {
        let package = genesis_package();
        let body = std::collections::BTreeMap::from([("schema_version".to_owned(), 1_u32)]);

        // A generation-2-only kind is rejected on the kind alone, before any
        // schema selector is consulted.
        for kind in [
            RegistryEntryKind::ArrowBatchSchema,
            RegistryEntryKind::LogEpochRecipe,
            RegistryEntryKind::ParserContract,
        ] {
            let entry = legacy_entry(&package, kind, "generation2.reserved", 1, &body);
            let error = decode_successor_entry(&entry).unwrap_err();
            assert!(
                matches!(&error, ContractError::Schema(message)
                    if message.contains("generation-2-only kind")),
                "{error:?}"
            );
        }

        // A reserved v2 triple names a kind that does exist at v1, so only the
        // closed slot table can tell it apart from a dispatched selector.
        for (kind, schema_id) in [
            (RegistryEntryKind::CoverageProof, "registry.coverage_proof"),
            (RegistryEntryKind::EpisodePolicy, "registry.episode_policy"),
            (
                RegistryEntryKind::NormativeBindingSchema,
                "registry.normative_binding_schema",
            ),
            (
                RegistryEntryKind::ObserverAdmission,
                "registry.observer_admission",
            ),
        ] {
            assert_eq!(
                classify_body_schema_triple(kind, schema_id, SUCCESSOR_SCHEMA_VERSION),
                BodySchemaSlotClassV1::Generation2Reserved
            );
            let mut entry = legacy_entry(&package, kind, "generation2.reserved", 1, &body);
            entry.entry_schema_version = SUCCESSOR_SCHEMA_VERSION;
            let error = decode_successor_entry(&entry).unwrap_err();
            assert!(
                matches!(&error, ContractError::Schema(message)
                    if message.contains("reserved generation-2 body schema")),
                "{error:?}"
            );
        }

        // An unknown triple stays on the existing unsupported-selector path.
        let mut unknown = legacy_entry(
            &package,
            RegistryEntryKind::RetentionPolicy,
            "retention.default",
            1,
            &body,
        );
        unknown.entry_schema_version = SUCCESSOR_SCHEMA_VERSION;
        assert_eq!(
            classify_body_schema_triple(
                RegistryEntryKind::RetentionPolicy,
                "registry.retention_policy",
                SUCCESSOR_SCHEMA_VERSION,
            ),
            BodySchemaSlotClassV1::Unknown
        );
        let error = decode_successor_entry(&unknown).unwrap_err();
        assert!(
            matches!(&error, ContractError::Schema(message)
                if message.contains("unsupported successor registry selector")),
            "{error:?}"
        );
    }
}
