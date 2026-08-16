//! Content-addressed registry packages and ABA-safe activation statements.

use std::{cmp::Ordering, collections::BTreeSet};

use serde::{Deserialize, Serialize};

use super::{
    ContractError, ContractResult,
    canonical::{
        CanonicalBytes, CanonicalValue, canonical_bytes, decode_strict, encode_canonical,
        require_canonical,
    },
    common::{AuthenticatedProjectScopeV1, CanonicalTimestamp, ContractId, ProfileReferenceV1},
    digest::{DigestDomain, Sha256Digest, domain_separated_digest},
};

const PACKAGE_SCHEMA_VERSION: u32 = 1;
const ACTIVATION_SCHEMA_VERSION: u32 = 1;
const MAX_REGISTRY_ENTRIES: usize = 1_024;
const MAX_APPROVALS: usize = 64;

/// Closed entry kinds understood by registry package v1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistryEntryKind {
    ActivationPolicy,
    ApplicabilityEvaluator,
    /// Generation-2 only: Arrow IPC batch schema for transport-plane batches.
    ArrowBatchSchema,
    AuthorityRule,
    CausalRatificationPolicy,
    ClassifierPolicy,
    ConnectorSchema,
    CoverageProof,
    EpisodePolicy,
    EvidenceSchema,
    ExemplarPolicy,
    IdentityRecipe,
    /// Generation-2 only: durable log epoch recipe for the append plane.
    LogEpochRecipe,
    NamespaceDefinition,
    NormativeBindingSchema,
    ObserverAdmission,
    /// Generation-2 only: deterministic parser contract for chunk identity.
    ParserContract,
    PredicateSchema,
    PublicationRule,
    RedactionPolicy,
    RelationProof,
    ResourceKindSchema,
    RetentionPolicy,
}

impl RegistryEntryKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ActivationPolicy => "activation_policy",
            Self::ApplicabilityEvaluator => "applicability_evaluator",
            Self::ArrowBatchSchema => "arrow_batch_schema",
            Self::AuthorityRule => "authority_rule",
            Self::CausalRatificationPolicy => "causal_ratification_policy",
            Self::ClassifierPolicy => "classifier_policy",
            Self::ConnectorSchema => "connector_schema",
            Self::CoverageProof => "coverage_proof",
            Self::EpisodePolicy => "episode_policy",
            Self::EvidenceSchema => "evidence_schema",
            Self::ExemplarPolicy => "exemplar_policy",
            Self::IdentityRecipe => "identity_recipe",
            Self::LogEpochRecipe => "log_epoch_recipe",
            Self::NamespaceDefinition => "namespace_definition",
            Self::NormativeBindingSchema => "normative_binding_schema",
            Self::ObserverAdmission => "observer_admission",
            Self::ParserContract => "parser_contract",
            Self::PredicateSchema => "predicate_schema",
            Self::PublicationRule => "publication_rule",
            Self::RedactionPolicy => "redaction_policy",
            Self::RelationProof => "relation_proof",
            Self::ResourceKindSchema => "resource_kind_schema",
            Self::RetentionPolicy => "retention_policy",
        }
    }

    /// Whether this kind was introduced after the frozen generation-1 registry.
    ///
    /// Generation-1 closures (genesis package, Stage-4 target package) must
    /// reject these kinds outright: their typed bodies do not exist in this
    /// binary, so admitting one would let a package name a contract that no
    /// verifier can close.
    pub const fn is_generation2_only(self) -> bool {
        matches!(
            self,
            Self::ArrowBatchSchema | Self::LogEpochRecipe | Self::ParserContract
        )
    }

    /// Position of this kind in [`ALL_REGISTRY_ENTRY_KINDS`].
    ///
    /// The exhaustive match is the guard that keeps that array honest: adding a
    /// variant fails to compile here, and assigning it an index without listing
    /// it in the array fails the round-trip test. Without this, a new kind could
    /// stay invisible to every coverage assertion over the closed table.
    pub const fn table_index(self) -> usize {
        match self {
            Self::ActivationPolicy => 0,
            Self::ApplicabilityEvaluator => 1,
            Self::ArrowBatchSchema => 2,
            Self::AuthorityRule => 3,
            Self::CausalRatificationPolicy => 4,
            Self::ClassifierPolicy => 5,
            Self::ConnectorSchema => 6,
            Self::CoverageProof => 7,
            Self::EpisodePolicy => 8,
            Self::EvidenceSchema => 9,
            Self::ExemplarPolicy => 10,
            Self::IdentityRecipe => 11,
            Self::LogEpochRecipe => 12,
            Self::NamespaceDefinition => 13,
            Self::NormativeBindingSchema => 14,
            Self::ObserverAdmission => 15,
            Self::ParserContract => 16,
            Self::PredicateSchema => 17,
            Self::PublicationRule => 18,
            Self::RedactionPolicy => 19,
            Self::RelationProof => 20,
            Self::ResourceKindSchema => 21,
            Self::RetentionPolicy => 22,
        }
    }
}

/// Every closed entry kind, in canonical `as_str` order.
pub const ALL_REGISTRY_ENTRY_KINDS: [RegistryEntryKind; 23] = [
    RegistryEntryKind::ActivationPolicy,
    RegistryEntryKind::ApplicabilityEvaluator,
    RegistryEntryKind::ArrowBatchSchema,
    RegistryEntryKind::AuthorityRule,
    RegistryEntryKind::CausalRatificationPolicy,
    RegistryEntryKind::ClassifierPolicy,
    RegistryEntryKind::ConnectorSchema,
    RegistryEntryKind::CoverageProof,
    RegistryEntryKind::EpisodePolicy,
    RegistryEntryKind::EvidenceSchema,
    RegistryEntryKind::ExemplarPolicy,
    RegistryEntryKind::IdentityRecipe,
    RegistryEntryKind::LogEpochRecipe,
    RegistryEntryKind::NamespaceDefinition,
    RegistryEntryKind::NormativeBindingSchema,
    RegistryEntryKind::ObserverAdmission,
    RegistryEntryKind::ParserContract,
    RegistryEntryKind::PredicateSchema,
    RegistryEntryKind::PublicationRule,
    RegistryEntryKind::RedactionPolicy,
    RegistryEntryKind::RelationProof,
    RegistryEntryKind::ResourceKindSchema,
    RegistryEntryKind::RetentionPolicy,
];

/// Dispatch class of one `(kind, entry schema ID, entry schema version)` triple.
///
/// The class is a statement about this binary's typed decoders, never about
/// activation: a dispatched triple is one some closure can decode, not one any
/// package is authorized to carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BodySchemaSlotClassV1 {
    /// Typed generation-1 body dispatched by the genesis closure.
    Generation1Dispatched,
    /// Typed generation-2 body dispatched by the successor closure.
    Generation2Dispatched,
    /// Generation-2 slot reserved by contract whose typed body is not wired.
    Generation2Reserved,
    /// Not a member of the closed table; every consumer must fail closed.
    Unknown,
}

impl BodySchemaSlotClassV1 {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Generation1Dispatched => "generation1_dispatched",
            Self::Generation2Dispatched => "generation2_dispatched",
            Self::Generation2Reserved => "generation2_reserved",
            Self::Unknown => "unknown",
        }
    }
}

/// One closed body-schema slot a registry package is permitted to name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BodySchemaSlotV1 {
    pub kind: RegistryEntryKind,
    pub entry_schema_id: &'static str,
    pub entry_schema_version: u32,
    pub class: BodySchemaSlotClassV1,
}

const fn slot(
    kind: RegistryEntryKind,
    entry_schema_id: &'static str,
    entry_schema_version: u32,
    class: BodySchemaSlotClassV1,
) -> BodySchemaSlotV1 {
    BodySchemaSlotV1 {
        kind,
        entry_schema_id,
        entry_schema_version,
        class,
    }
}

/// Closed table of every `(kind, entry schema ID, entry schema version)` triple
/// a generation-2 registry package may carry, in canonical sorted order.
///
/// The table is exhaustive by construction: any triple outside it classifies as
/// [`BodySchemaSlotClassV1::Unknown`], and every consumer fails closed on both
/// `Unknown` and `Generation2Reserved`.
pub const BODY_SCHEMA_SLOTS: [BodySchemaSlotV1; 32] = [
    slot(
        RegistryEntryKind::ActivationPolicy,
        "registry.activation_policy",
        1,
        BodySchemaSlotClassV1::Generation1Dispatched,
    ),
    slot(
        RegistryEntryKind::ActivationPolicy,
        "registry.activation_policy",
        2,
        BodySchemaSlotClassV1::Generation2Dispatched,
    ),
    slot(
        RegistryEntryKind::ApplicabilityEvaluator,
        "registry.applicability_evaluator",
        1,
        BodySchemaSlotClassV1::Generation1Dispatched,
    ),
    slot(
        RegistryEntryKind::ArrowBatchSchema,
        "registry.arrow_batch_schema",
        1,
        BodySchemaSlotClassV1::Generation2Reserved,
    ),
    slot(
        RegistryEntryKind::AuthorityRule,
        "registry.authority_rule",
        1,
        BodySchemaSlotClassV1::Generation1Dispatched,
    ),
    slot(
        RegistryEntryKind::AuthorityRule,
        "registry.remember_admission_rule",
        2,
        BodySchemaSlotClassV1::Generation2Dispatched,
    ),
    slot(
        RegistryEntryKind::CausalRatificationPolicy,
        "registry.causal_ratification_policy",
        1,
        BodySchemaSlotClassV1::Generation1Dispatched,
    ),
    slot(
        RegistryEntryKind::ClassifierPolicy,
        "registry.classifier_policy",
        1,
        BodySchemaSlotClassV1::Generation1Dispatched,
    ),
    slot(
        RegistryEntryKind::ConnectorSchema,
        "registry.connector_schema",
        1,
        BodySchemaSlotClassV1::Generation1Dispatched,
    ),
    slot(
        RegistryEntryKind::ConnectorSchema,
        "registry.connector_schema",
        2,
        BodySchemaSlotClassV1::Generation2Dispatched,
    ),
    slot(
        RegistryEntryKind::CoverageProof,
        "registry.coverage_proof",
        1,
        BodySchemaSlotClassV1::Generation1Dispatched,
    ),
    slot(
        RegistryEntryKind::CoverageProof,
        "registry.coverage_proof",
        2,
        BodySchemaSlotClassV1::Generation2Reserved,
    ),
    slot(
        RegistryEntryKind::EpisodePolicy,
        "registry.episode_policy",
        1,
        BodySchemaSlotClassV1::Generation1Dispatched,
    ),
    slot(
        RegistryEntryKind::EpisodePolicy,
        "registry.episode_policy",
        2,
        BodySchemaSlotClassV1::Generation2Reserved,
    ),
    slot(
        RegistryEntryKind::EvidenceSchema,
        "registry.evidence_schema",
        1,
        BodySchemaSlotClassV1::Generation1Dispatched,
    ),
    slot(
        RegistryEntryKind::ExemplarPolicy,
        "registry.exemplar_policy",
        1,
        BodySchemaSlotClassV1::Generation1Dispatched,
    ),
    slot(
        RegistryEntryKind::IdentityRecipe,
        "registry.identity_recipe",
        1,
        BodySchemaSlotClassV1::Generation1Dispatched,
    ),
    slot(
        RegistryEntryKind::LogEpochRecipe,
        "registry.log_epoch_recipe",
        1,
        BodySchemaSlotClassV1::Generation2Reserved,
    ),
    slot(
        RegistryEntryKind::NamespaceDefinition,
        "registry.namespace_definition",
        1,
        BodySchemaSlotClassV1::Generation1Dispatched,
    ),
    slot(
        RegistryEntryKind::NormativeBindingSchema,
        "registry.normative_binding_schema",
        1,
        BodySchemaSlotClassV1::Generation1Dispatched,
    ),
    slot(
        RegistryEntryKind::NormativeBindingSchema,
        "registry.normative_binding_schema",
        2,
        BodySchemaSlotClassV1::Generation2Reserved,
    ),
    slot(
        RegistryEntryKind::ObserverAdmission,
        "registry.observer_admission",
        1,
        BodySchemaSlotClassV1::Generation1Dispatched,
    ),
    slot(
        RegistryEntryKind::ObserverAdmission,
        "registry.observer_admission",
        2,
        BodySchemaSlotClassV1::Generation2Reserved,
    ),
    slot(
        RegistryEntryKind::ParserContract,
        "registry.parser_contract",
        1,
        BodySchemaSlotClassV1::Generation2Reserved,
    ),
    slot(
        RegistryEntryKind::PredicateSchema,
        "registry.predicate_schema",
        1,
        BodySchemaSlotClassV1::Generation1Dispatched,
    ),
    slot(
        RegistryEntryKind::PredicateSchema,
        "registry.predicate_schema",
        2,
        BodySchemaSlotClassV1::Generation2Dispatched,
    ),
    slot(
        RegistryEntryKind::PublicationRule,
        "registry.publication_rule",
        1,
        BodySchemaSlotClassV1::Generation1Dispatched,
    ),
    slot(
        RegistryEntryKind::RedactionPolicy,
        "registry.redaction_policy",
        1,
        BodySchemaSlotClassV1::Generation1Dispatched,
    ),
    slot(
        RegistryEntryKind::RelationProof,
        "registry.relation_proof",
        1,
        BodySchemaSlotClassV1::Generation1Dispatched,
    ),
    slot(
        RegistryEntryKind::RelationProof,
        "registry.relation_proof",
        2,
        BodySchemaSlotClassV1::Generation2Dispatched,
    ),
    slot(
        RegistryEntryKind::ResourceKindSchema,
        "registry.resource_kind_schema",
        1,
        BodySchemaSlotClassV1::Generation1Dispatched,
    ),
    slot(
        RegistryEntryKind::RetentionPolicy,
        "registry.retention_policy",
        1,
        BodySchemaSlotClassV1::Generation1Dispatched,
    ),
];

/// Classify one exact body-schema triple against the closed table.
///
/// This is a pure lookup. It proves neither package membership nor activation,
/// and a `Generation2Dispatched` result never means the entry is admissible in
/// a generation-1 package.
#[must_use]
pub fn classify_body_schema_triple(
    kind: RegistryEntryKind,
    entry_schema_id: &str,
    entry_schema_version: u32,
) -> BodySchemaSlotClassV1 {
    BODY_SCHEMA_SLOTS
        .iter()
        .find(|slot| {
            slot.kind == kind
                && slot.entry_schema_id == entry_schema_id
                && slot.entry_schema_version == entry_schema_version
        })
        .map_or(BodySchemaSlotClassV1::Unknown, |slot| slot.class)
}

/// One canonical, independently digestible registry entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryEntryV1 {
    pub schema_version: u32,
    pub kind: RegistryEntryKind,
    pub entry_id: ContractId,
    pub version: u32,
    pub entry_schema_id: ContractId,
    pub entry_schema_version: u32,
    pub body: CanonicalValue,
    pub positive_vector_digest: Sha256Digest,
    pub negative_vector_digest: Sha256Digest,
}

impl RegistryEntryV1 {
    pub fn validate(&self) -> ContractResult<()> {
        if self.schema_version != PACKAGE_SCHEMA_VERSION
            || self.version == 0
            || self.entry_schema_version == 0
            || self.body.as_object().is_none()
        {
            return Err(ContractError::Schema("invalid registry entry".into()));
        }
        // Validate the programmatically constructible body before serde walks
        // it. A deep or inadmissible CanonicalValue must not bypass the bounded
        // profile merely because it is nested inside a typed entry.
        canonical_bytes(&self.body)?;
        Ok(())
    }

    pub fn canonical_bytes(&self) -> ContractResult<Vec<u8>> {
        self.validate()?;
        encode_canonical(self)
    }

    pub fn digest(&self) -> ContractResult<Sha256Digest> {
        Ok(domain_separated_digest(
            DigestDomain::RegistryEntry,
            &self.canonical_bytes()?,
        ))
    }

    fn sort_key(&self) -> (&str, &str, u32) {
        (self.kind.as_str(), self.entry_id.as_str(), self.version)
    }
}

/// Manifest tuple that commits package metadata to one exact entry preimage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryManifestEntryV1 {
    pub kind: RegistryEntryKind,
    pub entry_id: ContractId,
    pub version: u32,
    pub entry_digest: Sha256Digest,
}

impl RegistryManifestEntryV1 {
    fn sort_key(&self) -> (&str, &str, u32, &[u8; 32]) {
        (
            self.kind.as_str(),
            self.entry_id.as_str(),
            self.version,
            self.entry_digest.as_bytes(),
        )
    }
}

/// Complete content-addressed registry package. Remote includes are impossible:
/// every entry preimage is embedded and mapped bijectively by the manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryPackageV1 {
    pub schema_version: u32,
    pub profile: ProfileReferenceV1,
    pub entries: Vec<RegistryEntryV1>,
    pub manifest: Vec<RegistryManifestEntryV1>,
    pub positive_vector_suite_digest: Sha256Digest,
    pub negative_vector_suite_digest: Sha256Digest,
}

/// Package that passed strict parsing, profile pinning, set ordering, and full
/// manifest-to-entry digest verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestVerifiedRegistryPackage {
    package: RegistryPackageV1,
    canonical_bytes: Vec<u8>,
    package_digest: Sha256Digest,
}

impl ManifestVerifiedRegistryPackage {
    pub fn decode(input: &[u8], expected_profile: &ProfileReferenceV1) -> ContractResult<Self> {
        require_canonical(input)?;
        let package: RegistryPackageV1 = decode_strict(input)?;
        Self::new(package, expected_profile)
    }

    pub fn new(
        package: RegistryPackageV1,
        expected_profile: &ProfileReferenceV1,
    ) -> ContractResult<Self> {
        validate_package(&package, expected_profile)?;
        let canonical_bytes = encode_canonical(&package)?;
        let package_digest =
            domain_separated_digest(DigestDomain::RegistryPackage, &canonical_bytes);
        Ok(Self {
            package,
            canonical_bytes,
            package_digest,
        })
    }

    pub const fn package(&self) -> &RegistryPackageV1 {
        &self.package
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub const fn package_digest(&self) -> Sha256Digest {
        self.package_digest
    }
}

/// Validate the package closure without silently sorting or materializing
/// missing defaults.
pub fn validate_package(
    package: &RegistryPackageV1,
    expected_profile: &ProfileReferenceV1,
) -> ContractResult<()> {
    expected_profile.validate()?;
    package.profile.validate()?;
    if package.schema_version != PACKAGE_SCHEMA_VERSION || package.profile != *expected_profile {
        return Err(ContractError::ProfileMismatch);
    }
    if package.entries.is_empty() || package.entries.len() > MAX_REGISTRY_ENTRIES {
        return Err(ContractError::Schema(
            "registry entry count is invalid".into(),
        ));
    }
    if package.entries.len() != package.manifest.len() {
        return Err(ContractError::ManifestMismatch);
    }
    for entry in &package.entries {
        entry.validate()?;
    }
    if !package
        .entries
        .windows(2)
        .all(|pair| compare_entry(&pair[0], &pair[1]) == Ordering::Less)
    {
        return Err(ContractError::NonCanonicalSet { field: "entries" });
    }
    if !package
        .manifest
        .windows(2)
        .all(|pair| pair[0].sort_key() < pair[1].sort_key())
    {
        return Err(ContractError::NonCanonicalSet { field: "manifest" });
    }
    for (entry, manifest) in package.entries.iter().zip(&package.manifest) {
        if entry.kind != manifest.kind
            || entry.entry_id != manifest.entry_id
            || entry.version != manifest.version
            || entry.digest()? != manifest.entry_digest
        {
            return Err(ContractError::ManifestMismatch);
        }
    }
    Ok(())
}

fn compare_entry(left: &RegistryEntryV1, right: &RegistryEntryV1) -> Ordering {
    left.sort_key().cmp(&right.sort_key())
}

/// Exact active pointer used for compare-and-swap. Binding the activation ID as
/// well as its package/policy digests prevents stale proposals after A→B→A.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryHeadV1 {
    pub activation_id: Sha256Digest,
    pub package_digest: Sha256Digest,
    pub activation_policy_digest: Sha256Digest,
}

/// Unsigned semantic statement approved separately by governance principals.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryActivationProposalV1 {
    pub schema_version: u32,
    pub profile: ProfileReferenceV1,
    pub scope: AuthenticatedProjectScopeV1,
    pub package_digest: Sha256Digest,
    pub expected_active_head: RegistryHeadV1,
    pub effective_from: CanonicalTimestamp,
    pub effective_until: Option<CanonicalTimestamp>,
    pub test_vector_result_digest: Sha256Digest,
    pub proposer_principal_id: ContractId,
    pub package_author_principal_id: ContractId,
}

impl RegistryActivationProposalV1 {
    pub fn validate(&self) -> ContractResult<()> {
        self.profile.validate()?;
        if self.schema_version != ACTIVATION_SCHEMA_VERSION
            || self
                .effective_until
                .as_ref()
                .is_some_and(|until| until <= &self.effective_from)
        {
            return Err(ContractError::Schema(
                "invalid registry activation proposal".into(),
            ));
        }
        Ok(())
    }

    pub fn statement_id(&self) -> ContractResult<Sha256Digest> {
        self.validate()?;
        Ok(domain_separated_digest(
            DigestDomain::RegistryActivationStatement,
            &encode_canonical(self)?,
        ))
    }

    pub fn require_current_head(&self, current: &RegistryHeadV1) -> ContractResult<()> {
        if &self.expected_active_head != current {
            return Err(ContractError::StaleRegistryHead);
        }
        Ok(())
    }
}

/// Structural approval binding included in a receipt preimage.
///
/// This public wire value does not prove signature verification or eligibility;
/// Stage 3 must construct the published receipt from private verified-attestation
/// and exact-current-head witnesses.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EligibleApprovalV1 {
    pub attestation_id: Sha256Digest,
    pub principal_id: ContractId,
    pub signer_key_id: ContractId,
}

/// Canonical registry-activation receipt preimage.
///
/// `validate` establishes shape, unique principal/key bindings, threshold, and
/// separation-of-duty fields only. It grants no activation authority by itself;
/// Stage 3 must verify signatures, signer eligibility, proposal binding, and the
/// exact active head before publishing this receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryActivationReceiptV1 {
    pub schema_version: u32,
    pub statement_id: Sha256Digest,
    pub predecessor_head: RegistryHeadV1,
    pub activated_package_digest: Sha256Digest,
    pub eligible_approvals: Vec<EligibleApprovalV1>,
    pub required_threshold: u16,
    pub separation_of_duty_satisfied: bool,
    pub accepted_at: CanonicalTimestamp,
}

impl RegistryActivationReceiptV1 {
    pub fn validate(&self) -> ContractResult<()> {
        if self.schema_version != ACTIVATION_SCHEMA_VERSION
            || self.required_threshold == 0
            || usize::from(self.required_threshold) > self.eligible_approvals.len()
            || self.eligible_approvals.len() > MAX_APPROVALS
            || !strictly_sorted(&self.eligible_approvals)
            || !self.separation_of_duty_satisfied
            || !approval_bindings_are_unique(&self.eligible_approvals)
        {
            return Err(ContractError::Schema(
                "invalid registry activation receipt".into(),
            ));
        }
        Ok(())
    }

    pub fn activation_id(&self) -> ContractResult<Sha256Digest> {
        self.validate()?;
        Ok(domain_separated_digest(
            DigestDomain::RegistryActivationReceipt,
            &encode_canonical(self)?,
        ))
    }
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn approval_bindings_are_unique(values: &[EligibleApprovalV1]) -> bool {
    let principals = values
        .iter()
        .map(|approval| &approval.principal_id)
        .collect::<BTreeSet<_>>();
    let keys = values
        .iter()
        .map(|approval| &approval.signer_key_id)
        .collect::<BTreeSet<_>>();
    principals.len() == values.len() && keys.len() == values.len()
}

/// Decode an already canonical package and retain its typed preimage.
pub fn decode_canonical_package(
    input: &[u8],
    expected_profile: &ProfileReferenceV1,
) -> ContractResult<CanonicalBytes<RegistryPackageV1>> {
    let decoded = CanonicalBytes::decode(input)?;
    validate_package(decoded.value(), expected_profile)?;
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::memory_contracts::{
        common::ContractId,
        digest::{DigestDomain, domain_separated_digest},
    };

    fn digest(domain: DigestDomain, label: &str) -> Sha256Digest {
        domain_separated_digest(domain, label.as_bytes())
    }

    fn profile() -> ProfileReferenceV1 {
        ProfileReferenceV1 {
            profile_id: ContractId::new("ostk-canonical-json-v1").unwrap(),
            profile_digest: digest(DigestDomain::CanonicalProfile, "profile"),
            vector_manifest_digest: digest(DigestDomain::TestVectorManifest, "vectors"),
        }
    }

    fn entry(id: &str, body_value: i64) -> RegistryEntryV1 {
        RegistryEntryV1 {
            schema_version: 1,
            kind: RegistryEntryKind::PredicateSchema,
            entry_id: ContractId::new(id).unwrap(),
            version: 1,
            entry_schema_id: ContractId::new("registry.predicate_schema").unwrap(),
            entry_schema_version: 1,
            body: CanonicalValue::Object(BTreeMap::from([(
                "value".to_owned(),
                CanonicalValue::Integer(body_value),
            )])),
            positive_vector_digest: digest(DigestDomain::TestVectorManifest, "positive"),
            negative_vector_digest: digest(DigestDomain::TestVectorManifest, "negative"),
        }
    }

    fn package(entries: Vec<RegistryEntryV1>) -> RegistryPackageV1 {
        let manifest = entries
            .iter()
            .map(|entry| RegistryManifestEntryV1 {
                kind: entry.kind,
                entry_id: entry.entry_id.clone(),
                version: entry.version,
                entry_digest: entry.digest().unwrap(),
            })
            .collect();
        RegistryPackageV1 {
            schema_version: 1,
            profile: profile(),
            entries,
            manifest,
            positive_vector_suite_digest: digest(
                DigestDomain::TestVectorManifest,
                "suite-positive",
            ),
            negative_vector_suite_digest: digest(
                DigestDomain::TestVectorManifest,
                "suite-negative",
            ),
        }
    }

    #[test]
    fn every_kind_has_one_wire_name_and_a_stable_generation() {
        assert_eq!(ALL_REGISTRY_ENTRY_KINDS.len(), 23);
        for (index, kind) in ALL_REGISTRY_ENTRY_KINDS.into_iter().enumerate() {
            let wire = serde_json::to_string(&kind).unwrap();
            assert_eq!(wire, format!("\"{}\"", kind.as_str()));
            let decoded: RegistryEntryKind = serde_json::from_str(&wire).unwrap();
            assert_eq!(decoded, kind);
            // A kind that was given a table index but never listed above would
            // index past the end here instead of silently escaping coverage.
            assert_eq!(kind.table_index(), index);
            assert_eq!(ALL_REGISTRY_ENTRY_KINDS[kind.table_index()], kind);
        }
        assert!(
            ALL_REGISTRY_ENTRY_KINDS
                .windows(2)
                .all(|pair| pair[0].as_str() < pair[1].as_str())
        );
        let generation2_only = ALL_REGISTRY_ENTRY_KINDS
            .iter()
            .filter(|kind| kind.is_generation2_only())
            .map(|kind| kind.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            generation2_only,
            ["arrow_batch_schema", "log_epoch_recipe", "parser_contract"]
        );
        // A name outside the closed set can never decode into a kind.
        assert!(serde_json::from_str::<RegistryEntryKind>("\"transcript_session\"").is_err());
    }

    #[test]
    fn body_schema_slot_table_is_closed_sorted_and_exhaustive() {
        let keys = BODY_SCHEMA_SLOTS
            .iter()
            .map(|slot| {
                (
                    slot.kind.as_str(),
                    slot.entry_schema_id,
                    slot.entry_schema_version,
                )
            })
            .collect::<Vec<_>>();
        assert!(
            keys.windows(2).all(|pair| pair[0] < pair[1]),
            "body-schema slots must be strictly sorted and unique"
        );
        assert!(
            BODY_SCHEMA_SLOTS
                .iter()
                .all(|slot| slot.entry_schema_version > 0
                    && slot.class != BodySchemaSlotClassV1::Unknown)
        );
        for kind in ALL_REGISTRY_ENTRY_KINDS {
            let slots = BODY_SCHEMA_SLOTS
                .iter()
                .filter(|slot| slot.kind == kind)
                .collect::<Vec<_>>();
            assert!(!slots.is_empty(), "{} has no slot", kind.as_str());
            // A generation-2-only kind may never claim a dispatched body.
            assert_eq!(
                kind.is_generation2_only(),
                slots
                    .iter()
                    .all(|slot| slot.class == BodySchemaSlotClassV1::Generation2Reserved)
            );
        }
        let counts = |class: BodySchemaSlotClassV1| {
            BODY_SCHEMA_SLOTS
                .iter()
                .filter(|slot| slot.class == class)
                .count()
        };
        assert_eq!(counts(BodySchemaSlotClassV1::Generation1Dispatched), 20);
        assert_eq!(counts(BodySchemaSlotClassV1::Generation2Dispatched), 5);
        assert_eq!(counts(BodySchemaSlotClassV1::Generation2Reserved), 7);
    }

    #[test]
    fn triple_classification_vectors_fail_closed_outside_the_table() {
        for (kind, schema_id, version, expected) in [
            (
                RegistryEntryKind::PredicateSchema,
                "registry.predicate_schema",
                1,
                BodySchemaSlotClassV1::Generation1Dispatched,
            ),
            (
                RegistryEntryKind::AuthorityRule,
                "registry.remember_admission_rule",
                2,
                BodySchemaSlotClassV1::Generation2Dispatched,
            ),
            (
                RegistryEntryKind::ConnectorSchema,
                "registry.connector_schema",
                2,
                BodySchemaSlotClassV1::Generation2Dispatched,
            ),
            (
                RegistryEntryKind::CoverageProof,
                "registry.coverage_proof",
                2,
                BodySchemaSlotClassV1::Generation2Reserved,
            ),
            (
                RegistryEntryKind::ParserContract,
                "registry.parser_contract",
                1,
                BodySchemaSlotClassV1::Generation2Reserved,
            ),
            // A reserved triple at the wrong version is not the reserved slot.
            (
                RegistryEntryKind::ParserContract,
                "registry.parser_contract",
                2,
                BodySchemaSlotClassV1::Unknown,
            ),
            // A v1-only kind claimed at v2 has no typed decoder.
            (
                RegistryEntryKind::RetentionPolicy,
                "registry.retention_policy",
                2,
                BodySchemaSlotClassV1::Unknown,
            ),
            // The schema ID is part of the key, not a label.
            (
                RegistryEntryKind::AuthorityRule,
                "registry.authority_rule",
                2,
                BodySchemaSlotClassV1::Unknown,
            ),
            (
                RegistryEntryKind::ConnectorSchema,
                "registry.transcript_session_connector",
                2,
                BodySchemaSlotClassV1::Unknown,
            ),
        ] {
            assert_eq!(
                classify_body_schema_triple(kind, schema_id, version),
                expected,
                "{} {schema_id}@{version}",
                kind.as_str()
            );
        }
    }

    #[test]
    fn package_manifest_is_bijective_and_ordered() {
        let valid = package(vec![entry("a", 1), entry("b", 2)]);
        assert!(ManifestVerifiedRegistryPackage::new(valid.clone(), &profile()).is_ok());

        let mut reordered = valid.clone();
        reordered.entries.swap(0, 1);
        assert!(matches!(
            validate_package(&reordered, &profile()),
            Err(ContractError::NonCanonicalSet { field: "entries" })
        ));

        let mut substituted = valid;
        substituted.entries[0].body = CanonicalValue::Object(BTreeMap::new());
        assert!(matches!(
            validate_package(&substituted, &profile()),
            Err(ContractError::ManifestMismatch)
        ));
    }

    #[test]
    fn manifest_verified_decode_rejects_noncanonical_wire_bytes() {
        let value = package(vec![entry("a", 1)]);
        let canonical = encode_canonical(&value).unwrap();
        assert!(ManifestVerifiedRegistryPackage::decode(&canonical, &profile()).is_ok());
        assert!(decode_canonical_package(&canonical, &profile()).is_ok());

        let mut noncanonical = Vec::with_capacity(canonical.len() + 1);
        noncanonical.push(b' ');
        noncanonical.extend_from_slice(&canonical);
        assert!(ManifestVerifiedRegistryPackage::decode(&noncanonical, &profile()).is_err());
        assert!(decode_canonical_package(&noncanonical, &profile()).is_err());
    }

    #[test]
    fn exact_head_binding_rejects_aba() {
        let package_a = digest(DigestDomain::RegistryPackage, "A");
        let policy = digest(DigestDomain::RegistryEntry, "policy");
        let original_a = RegistryHeadV1 {
            activation_id: digest(DigestDomain::RegistryActivationReceipt, "activation-A1"),
            package_digest: package_a,
            activation_policy_digest: policy,
        };
        let proposal = RegistryActivationProposalV1 {
            schema_version: 1,
            profile: profile(),
            scope: AuthenticatedProjectScopeV1::from_trusted_context(
                ContractId::new("tenant.test").unwrap(),
                ContractId::new("project.test").unwrap(),
            ),
            package_digest: digest(DigestDomain::RegistryPackage, "successor"),
            expected_active_head: original_a.clone(),
            effective_from: CanonicalTimestamp::parse("2026-08-14T12:00:00.000000000Z").unwrap(),
            effective_until: None,
            test_vector_result_digest: digest(DigestDomain::TestVectorManifest, "pass"),
            proposer_principal_id: ContractId::new("principal.proposer").unwrap(),
            package_author_principal_id: ContractId::new("principal.author").unwrap(),
        };
        assert!(proposal.require_current_head(&original_a).is_ok());

        let reverted_a = RegistryHeadV1 {
            activation_id: digest(DigestDomain::RegistryActivationReceipt, "activation-A2"),
            package_digest: package_a,
            activation_policy_digest: policy,
        };
        assert_eq!(
            proposal.require_current_head(&reverted_a),
            Err(ContractError::StaleRegistryHead)
        );
    }
}
