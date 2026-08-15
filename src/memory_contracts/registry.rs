//! Content-addressed registry packages and ABA-safe activation statements.

use std::cmp::Ordering;

use serde::{Deserialize, Serialize};

use super::{
    ContractError, ContractResult,
    canonical::{CanonicalBytes, CanonicalValue, decode_strict, encode_canonical},
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
    AuthorityRule,
    CausalRatificationPolicy,
    CoverageProof,
    EpisodePolicy,
    ExemplarPolicy,
    IdentityRecipe,
    NamespaceDefinition,
    NormativeBindingSchema,
    ObserverAdmission,
    PredicateSchema,
    PublicationRule,
    RelationProof,
    ResourceKindSchema,
}

impl RegistryEntryKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ActivationPolicy => "activation_policy",
            Self::ApplicabilityEvaluator => "applicability_evaluator",
            Self::AuthorityRule => "authority_rule",
            Self::CausalRatificationPolicy => "causal_ratification_policy",
            Self::CoverageProof => "coverage_proof",
            Self::EpisodePolicy => "episode_policy",
            Self::ExemplarPolicy => "exemplar_policy",
            Self::IdentityRecipe => "identity_recipe",
            Self::NamespaceDefinition => "namespace_definition",
            Self::NormativeBindingSchema => "normative_binding_schema",
            Self::ObserverAdmission => "observer_admission",
            Self::PredicateSchema => "predicate_schema",
            Self::PublicationRule => "publication_rule",
            Self::RelationProof => "relation_proof",
            Self::ResourceKindSchema => "resource_kind_schema",
        }
    }
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
pub struct ValidatedRegistryPackage {
    package: RegistryPackageV1,
    canonical_bytes: Vec<u8>,
    package_digest: Sha256Digest,
}

impl ValidatedRegistryPackage {
    pub fn decode(input: &[u8], expected_profile: &ProfileReferenceV1) -> ContractResult<Self> {
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

/// Server-derived acceptance receipt. Approval rows remain separate signed
/// attestations; this projection never accepts a caller-provided verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryActivationReceiptV1 {
    pub schema_version: u32,
    pub statement_id: Sha256Digest,
    pub predecessor_head: RegistryHeadV1,
    pub activated_package_digest: Sha256Digest,
    pub approval_attestation_ids: Vec<Sha256Digest>,
    pub eligible_principal_ids: Vec<ContractId>,
    pub required_threshold: u16,
    pub separation_of_duty_satisfied: bool,
    pub accepted_at: CanonicalTimestamp,
}

impl RegistryActivationReceiptV1 {
    pub fn validate(&self) -> ContractResult<()> {
        if self.schema_version != ACTIVATION_SCHEMA_VERSION
            || self.required_threshold == 0
            || usize::from(self.required_threshold) > self.eligible_principal_ids.len()
            || self.approval_attestation_ids.len() > MAX_APPROVALS
            || self.eligible_principal_ids.len() > MAX_APPROVALS
            || !strictly_sorted(&self.approval_attestation_ids)
            || !strictly_sorted(&self.eligible_principal_ids)
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
    fn package_manifest_is_bijective_and_ordered() {
        let valid = package(vec![entry("a", 1), entry("b", 2)]);
        assert!(ValidatedRegistryPackage::new(valid.clone(), &profile()).is_ok());

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
