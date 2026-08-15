//! Key-complete successor activation policy and the one-time genesis key bridge.
//!
//! This contract module is wired into the crate but deliberately grants no
//! repository authority. Canonical policy and bridge bytes are structural data
//! only: neither can authorize a registry transition. A later repository seam
//! must resolve the exact active genesis package and head, obtain the deployment
//! pin, prove that generation zero is still unconsumed, verify fresh approvals,
//! and consume the bridge in the same transaction that installs the first
//! successor head.

use std::{collections::BTreeSet, fmt};

use super::{
    ContractError, ContractResult,
    canonical::{decode_strict, encode_canonical, require_canonical},
    common::{
        AuthenticatedProjectScopeV1, ContractId, FixedHex32, ProfileReferenceV1,
        RegistryReferenceV1,
    },
    digest::{DigestDomain, Sha256Digest, domain_separated_digest},
    evidence_v2::RegistryHeadBindingV1,
    registry::{RegistryEntryKind, RegistryEntryV1},
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[cfg(test)]
use super::genesis::SemanticallyClosedGenesisPackage;

const ACTIVATION_POLICY_SCHEMA_VERSION: u32 = 2;
const ACTIVATION_POLICY_ENTRY_SCHEMA_ID: &str = "registry.activation_policy";
const GENESIS_SUCCESSOR_KEY_BRIDGE_SCHEMA_VERSION: u32 = 1;
const GENESIS_GENERATION: u32 = 0;
const FIRST_SUCCESSOR_GENERATION: u32 = 1;
const MAX_ACTIVATION_SIGNERS: usize = 64;

macro_rules! digest_newtype {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(Sha256Digest);

        impl $name {
            pub const fn from_digest(digest: Sha256Digest) -> Self {
                Self(digest)
            }

            pub const fn digest(self) -> Sha256Digest {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                self.0.serialize(serializer)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                Sha256Digest::deserialize(deserializer).map(Self)
            }
        }
    };
}

digest_newtype!(GenesisSuccessorKeyBridgeDigest);

/// Only signature algorithm admitted by the successor-policy v2 profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivationSignatureAlgorithmV2 {
    Ed25519,
}

/// Exact one-to-one governance-principal to public-key binding.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationSignerBindingV2 {
    pub principal_id: ContractId,
    pub algorithm: ActivationSignatureAlgorithmV2,
    pub public_key: FixedHex32,
}

impl ActivationSignerBindingV2 {
    /// Receipt-facing key ID derived from the exact public key rather than
    /// accepted as a second caller-controlled identifier.
    pub fn signer_key_id(&self) -> ContractResult<ContractId> {
        ContractId::new(format!(
            "ed25519.{}",
            hex::encode(self.public_key.as_bytes())
        ))
    }
}

/// Closed strong separation-of-duty rule for successor activation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivationSeparationOfDutyV2 {
    AuthorAndProposerDistinctNeitherMayApprove,
}

/// Exact separation-of-duty semantics inherited by the first successor from
/// the semantically closed activation-policy v1 entry.
///
/// The v1 rule is intentionally weaker than [`ActivationSeparationOfDutyV2`]:
/// at least one eligible approval must come from a principal other than the
/// package author. An otherwise eligible author approval may still count, and
/// the proposer is not excluded merely for being the proposer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GenesisTransitionSeparationOfDutyV1 {
    IndependentApprovalFromPackageAuthor,
}

impl GenesisTransitionSeparationOfDutyV1 {
    #[cfg(test)]
    const fn from_semantically_closed_genesis(_package: &SemanticallyClosedGenesisPackage) -> Self {
        // Semantic closure admits activation-policy v1 only with its required
        // separation-of-duty flag enabled and both fail-open flags disabled.
        // The v1 profile fixes that flag's meaning to this existential rule.
        Self::IndependentApprovalFromPackageAuthor
    }

    fn is_satisfied_by(
        self,
        package_author_principal_id: &ContractId,
        approving_principal_ids: &[ContractId],
    ) -> bool {
        match self {
            Self::IndependentApprovalFromPackageAuthor => approving_principal_ids
                .iter()
                .any(|principal| principal != package_author_principal_id),
        }
    }
}

/// Key-complete activation policy for successor registry packages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationPolicyEntryV2 {
    pub schema_version: u32,
    pub policy_id: ContractId,
    pub version: u32,
    pub eligible_signers: Vec<ActivationSignerBindingV2>,
    pub approval_threshold: u16,
    pub separation_of_duty: ActivationSeparationOfDutyV2,
    pub self_authorization_allowed: bool,
    pub break_glass_enabled: bool,
}

impl ActivationPolicyEntryV2 {
    pub fn validate(&self) -> ContractResult<()> {
        validate_signer_bindings(&self.eligible_signers)?;
        if self.schema_version != ACTIVATION_POLICY_SCHEMA_VERSION
            || self.version == 0
            || self.approval_threshold == 0
            || usize::from(self.approval_threshold) > self.eligible_signers.len()
            || self.separation_of_duty
                != ActivationSeparationOfDutyV2::AuthorAndProposerDistinctNeitherMayApprove
            || self.self_authorization_allowed
            || self.break_glass_enabled
        {
            return Err(ContractError::InvalidSignerPolicy(
                "invalid successor activation policy v2".into(),
            ));
        }
        Ok(())
    }

    /// Check only canonical principal selection and the strong `SoD` rule.
    /// Signature verification and active-policy authority belong to the later
    /// successor-activation verifier.
    pub fn validate_approval_principal_set(
        &self,
        package_author_principal_id: &ContractId,
        proposer_principal_id: &ContractId,
        approving_principal_ids: &[ContractId],
    ) -> ContractResult<()> {
        self.validate()?;
        if package_author_principal_id == proposer_principal_id
            || approving_principal_ids.iter().any(|principal| {
                principal == package_author_principal_id || principal == proposer_principal_id
            })
        {
            return Err(ContractError::Schema(
                "successor activation violates strong separation of duty".into(),
            ));
        }
        if approving_principal_ids.len() > self.eligible_signers.len()
            || !strictly_sorted(approving_principal_ids)
        {
            return Err(ContractError::NonCanonicalSet {
                field: "approving_principal_ids",
            });
        }
        if approving_principal_ids.iter().any(|principal| {
            !self
                .eligible_signers
                .iter()
                .any(|binding| &binding.principal_id == principal)
        }) {
            return Err(ContractError::InvalidSignerPolicy(
                "approval principal is not eligible".into(),
            ));
        }
        if approving_principal_ids.len() < usize::from(self.approval_threshold) {
            return Err(ContractError::ApprovalThresholdNotMet);
        }
        Ok(())
    }
}

/// One structurally closed activation-policy registry entry.
///
/// This type proves only that an exact [`RegistryEntryV1`] preimage has the
/// activation-policy v2 schema and that its outer identity agrees with its
/// body. Any caller can construct such bytes. Active-package membership and
/// successor-transition authority remain separate runtime obligations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructurallyResolvedActivationPolicyV2 {
    registry_reference: RegistryReferenceV1,
    policy: ActivationPolicyEntryV2,
}

impl StructurallyResolvedActivationPolicyV2 {
    pub fn from_registry_entry(entry: &RegistryEntryV1) -> ContractResult<Self> {
        entry.validate()?;
        if entry.kind != RegistryEntryKind::ActivationPolicy
            || entry.entry_schema_id.as_str() != ACTIVATION_POLICY_ENTRY_SCHEMA_ID
            || entry.entry_schema_version != ACTIVATION_POLICY_SCHEMA_VERSION
        {
            return Err(ContractError::Schema(
                "registry entry is not an activation policy v2 body".into(),
            ));
        }
        let policy: ActivationPolicyEntryV2 = decode_strict(&encode_canonical(&entry.body)?)?;
        policy.validate()?;
        if policy.policy_id != entry.entry_id {
            return Err(ContractError::ManifestMismatch);
        }
        if policy.version != entry.version {
            return Err(ContractError::ManifestMismatch);
        }
        Ok(Self {
            registry_reference: RegistryReferenceV1 {
                entry_id: entry.entry_id.clone(),
                version: entry.version,
                entry_digest: entry.digest()?,
            },
            policy,
        })
    }

    pub const fn registry_reference(&self) -> &RegistryReferenceV1 {
        &self.registry_reference
    }

    pub const fn policy(&self) -> &ActivationPolicyEntryV2 {
        &self.policy
    }
}

/// One-time, deployment-pinned map that gives the active genesis v1 policy
/// exact Ed25519 verification keys for authorizing generation 0 -> 1.
///
/// The map cannot add, omit, or rename an eligible v1 principal. That equality
/// requires a separate active-genesis witness and is not implied by these
/// public bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisSuccessorKeyBridgeV1 {
    pub schema_version: u32,
    pub profile: ProfileReferenceV1,
    pub scope: AuthenticatedProjectScopeV1,
    pub genesis_registry_head: RegistryHeadBindingV1,
    pub current_v1_activation_policy: RegistryReferenceV1,
    pub from_generation: u32,
    pub to_generation: u32,
    pub key_map: Vec<ActivationSignerBindingV2>,
}

impl GenesisSuccessorKeyBridgeV1 {
    pub fn validate_shape(&self) -> ContractResult<()> {
        self.profile.require_frozen_runtime_profile()?;
        self.genesis_registry_head.validate_shape()?;
        self.current_v1_activation_policy.validate()?;
        validate_signer_bindings(&self.key_map)?;
        if self.schema_version != GENESIS_SUCCESSOR_KEY_BRIDGE_SCHEMA_VERSION
            || self.from_generation != GENESIS_GENERATION
            || self.to_generation != FIRST_SUCCESSOR_GENERATION
            || self.current_v1_activation_policy.version != 1
            || self.genesis_registry_head.effective_until.is_some()
            || self.current_v1_activation_policy.entry_digest
                != self.genesis_registry_head.head.activation_policy_digest
        {
            return Err(ContractError::Schema(
                "invalid genesis successor key bridge v1".into(),
            ));
        }
        Ok(())
    }

    pub fn bridge_digest(&self) -> ContractResult<GenesisSuccessorKeyBridgeDigest> {
        self.validate_shape()?;
        Ok(GenesisSuccessorKeyBridgeDigest::from_digest(
            domain_separated_digest(
                DigestDomain::GenesisSuccessorKeyBridgeV1,
                &encode_canonical(self)?,
            ),
        ))
    }
}

/// Digest supplied by deployment configuration, never by bridge bytes or the
/// database row being checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenesisSuccessorKeyBridgePin(GenesisSuccessorKeyBridgeDigest);

impl GenesisSuccessorKeyBridgePin {
    pub const fn from_trusted_config(digest: GenesisSuccessorKeyBridgeDigest) -> Self {
        Self(digest)
    }
}

/// Opaque active-genesis facts reserved for a later same-transaction repository
/// audit.
///
/// There is intentionally no production constructor in this contract module:
/// offline package closure and caller-supplied head fields cannot prove that a
/// durable database head is current, locked, and uncontested or that the
/// one-shot bridge remains unconsumed.
#[derive(Debug, Clone)]
#[allow(dead_code)] // intentionally unwired until the successor repository exists
pub(crate) struct ActiveGenesisSuccessorWitness {
    profile: ProfileReferenceV1,
    scope: AuthenticatedProjectScopeV1,
    genesis_registry_head: RegistryHeadBindingV1,
    current_v1_activation_policy: RegistryReferenceV1,
    eligible_v1_principal_ids: Vec<ContractId>,
    required_v1_threshold: u16,
    v1_separation_of_duty: GenesisTransitionSeparationOfDutyV1,
    current_generation: u32,
    bridge_already_consumed: bool,
}

#[cfg(test)]
impl ActiveGenesisSuccessorWitness {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_test_fixture(
        profile: ProfileReferenceV1,
        scope: AuthenticatedProjectScopeV1,
        genesis_registry_head: RegistryHeadBindingV1,
        current_v1_activation_policy: RegistryReferenceV1,
        genesis_package: &SemanticallyClosedGenesisPackage,
        current_generation: u32,
        bridge_already_consumed: bool,
    ) -> ContractResult<Self> {
        profile.require_frozen_runtime_profile()?;
        genesis_registry_head.validate_shape()?;
        current_v1_activation_policy.validate()?;

        let package = genesis_package.manifest_verified_package().package();
        package.profile.require_frozen_runtime_profile()?;
        let mut policy_entries = package
            .entries
            .iter()
            .filter(|entry| entry.kind == RegistryEntryKind::ActivationPolicy);
        let policy_entry = policy_entries
            .next()
            .ok_or(ContractError::ManifestMismatch)?;
        if policy_entries.next().is_some() {
            return Err(ContractError::ManifestMismatch);
        }
        let exact_policy_reference = RegistryReferenceV1 {
            entry_id: policy_entry.entry_id.clone(),
            version: policy_entry.version,
            entry_digest: policy_entry.digest()?,
        };
        let active_policy = genesis_package.activation_policy();
        let eligible_v1_principal_ids = active_policy.eligible_principal_ids().to_vec();
        let required_v1_threshold = active_policy.approval_threshold();
        let v1_separation_of_duty =
            GenesisTransitionSeparationOfDutyV1::from_semantically_closed_genesis(genesis_package);
        if package.profile != profile
            || genesis_package.package_digest() != genesis_registry_head.head.package_digest
            || exact_policy_reference != current_v1_activation_policy
            || current_v1_activation_policy.entry_digest
                != genesis_registry_head.head.activation_policy_digest
            || genesis_registry_head.effective_until.is_some()
            || eligible_v1_principal_ids.is_empty()
            || !strictly_sorted(&eligible_v1_principal_ids)
            || required_v1_threshold == 0
            || usize::from(required_v1_threshold) > eligible_v1_principal_ids.len()
        {
            return Err(ContractError::ManifestMismatch);
        }

        Ok(Self {
            profile,
            scope,
            genesis_registry_head,
            current_v1_activation_policy,
            eligible_v1_principal_ids,
            required_v1_threshold,
            v1_separation_of_duty,
            current_generation,
            bridge_already_consumed,
        })
    }
}

/// Canonical and deployment-pinned bridge candidate closed over the exact v1
/// eligible principal set.
///
/// This typestate still cannot activate a successor:
/// durable bridge consumption, statement signatures, package closure, and head
/// CAS remain later repository obligations.
#[derive(Debug, Clone)]
pub struct PinnedGenesisSuccessorKeyBridge {
    bridge: GenesisSuccessorKeyBridgeV1,
    canonical_bytes: Vec<u8>,
    bridge_digest: GenesisSuccessorKeyBridgeDigest,
    required_v1_threshold: u16,
    v1_separation_of_duty: GenesisTransitionSeparationOfDutyV1,
}

impl PinnedGenesisSuccessorKeyBridge {
    pub const fn bridge(&self) -> &GenesisSuccessorKeyBridgeV1 {
        &self.bridge
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub const fn bridge_digest(&self) -> GenesisSuccessorKeyBridgeDigest {
        self.bridge_digest
    }

    pub const fn required_v1_threshold(&self) -> u16 {
        self.required_v1_threshold
    }

    pub const fn v1_separation_of_duty(&self) -> GenesisTransitionSeparationOfDutyV1 {
        self.v1_separation_of_duty
    }

    /// Validate the canonical eligible-principal set for generation `0 -> 1`.
    ///
    /// This applies the active v1 threshold and its existential package-author
    /// independence rule. There is deliberately no proposer argument: v1 does
    /// not exclude an otherwise eligible signer merely for being the trusted
    /// proposer. Signature verification remains a later repository obligation.
    pub fn validate_first_successor_approval_principal_set(
        &self,
        package_author_principal_id: &ContractId,
        approving_principal_ids: &[ContractId],
    ) -> ContractResult<()> {
        if approving_principal_ids.len() > self.bridge.key_map.len()
            || !strictly_sorted(approving_principal_ids)
        {
            return Err(ContractError::NonCanonicalSet {
                field: "approving_principal_ids",
            });
        }
        if approving_principal_ids.iter().any(|principal| {
            !self
                .bridge
                .key_map
                .iter()
                .any(|binding| &binding.principal_id == principal)
        }) {
            return Err(ContractError::InvalidSignerPolicy(
                "first-successor approval principal is not eligible".into(),
            ));
        }
        if approving_principal_ids.len() < usize::from(self.required_v1_threshold) {
            return Err(ContractError::ApprovalThresholdNotMet);
        }
        if !self
            .v1_separation_of_duty
            .is_satisfied_by(package_author_principal_id, approving_principal_ids)
        {
            return Err(ContractError::Schema(
                "first-successor activation lacks an approval independent of the package author"
                    .into(),
            ));
        }
        Ok(())
    }
}

/// Check the exact canonical bridge against a deployment pin and a separately
/// obtained active-genesis witness. Pin verification happens before typed
/// decoding so caller-controlled bytes cannot select their own expected digest.
#[allow(dead_code)] // intentionally unwired until the successor repository exists
pub(crate) fn verify_pinned_genesis_successor_key_bridge(
    input: &[u8],
    pin: GenesisSuccessorKeyBridgePin,
    witness: &ActiveGenesisSuccessorWitness,
) -> ContractResult<PinnedGenesisSuccessorKeyBridge> {
    let bridge_digest = GenesisSuccessorKeyBridgeDigest::from_digest(domain_separated_digest(
        DigestDomain::GenesisSuccessorKeyBridgeV1,
        input,
    ));
    if bridge_digest != pin.0 {
        return Err(ContractError::ManifestMismatch);
    }
    require_canonical(input)?;
    let bridge: GenesisSuccessorKeyBridgeV1 = decode_strict(input)?;
    bridge.validate_shape()?;
    if encode_canonical(&bridge)? != input {
        return Err(ContractError::NotCanonical);
    }
    if bridge.genesis_registry_head != witness.genesis_registry_head {
        return Err(ContractError::StaleRegistryHead);
    }
    if bridge.profile != witness.profile
        || bridge.scope != witness.scope
        || bridge.current_v1_activation_policy != witness.current_v1_activation_policy
        || binding_principal_ids(&bridge.key_map) != witness.eligible_v1_principal_ids
    {
        return Err(ContractError::ManifestMismatch);
    }
    if witness.current_generation != GENESIS_GENERATION
        || witness.bridge_already_consumed
        || bridge.from_generation != witness.current_generation
        || bridge.to_generation != witness.current_generation + 1
    {
        return Err(ContractError::Schema(
            "genesis successor key bridge was reused or has the wrong generation".into(),
        ));
    }

    Ok(PinnedGenesisSuccessorKeyBridge {
        bridge,
        canonical_bytes: input.to_vec(),
        bridge_digest,
        required_v1_threshold: witness.required_v1_threshold,
        v1_separation_of_duty: witness.v1_separation_of_duty,
    })
}

fn validate_signer_bindings(bindings: &[ActivationSignerBindingV2]) -> ContractResult<()> {
    if bindings.is_empty()
        || bindings.len() > MAX_ACTIVATION_SIGNERS
        || !bindings
            .windows(2)
            .all(|pair| pair[0].principal_id < pair[1].principal_id)
    {
        return Err(ContractError::InvalidSignerPolicy(
            "signer bindings must be a non-empty principal-sorted set".into(),
        ));
    }
    let principals = bindings
        .iter()
        .map(|binding| &binding.principal_id)
        .collect::<BTreeSet<_>>();
    let keys = bindings
        .iter()
        .map(|binding| binding.public_key)
        .collect::<BTreeSet<_>>();
    if principals.len() != bindings.len() || keys.len() != bindings.len() {
        return Err(ContractError::InvalidSignerPolicy(
            "governance principals and Ed25519 public keys must each be unique".into(),
        ));
    }
    if bindings
        .iter()
        .any(|binding| binding.public_key.as_bytes().iter().all(|byte| *byte == 0))
    {
        return Err(ContractError::InvalidSignerPolicy(
            "Ed25519 public keys must not be all zero".into(),
        ));
    }
    Ok(())
}

#[allow(dead_code)] // used by the unwired bridge verifier above
fn binding_principal_ids(bindings: &[ActivationSignerBindingV2]) -> Vec<ContractId> {
    bindings
        .iter()
        .map(|binding| binding.principal_id.clone())
        .collect()
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use serde::{Deserialize, Serialize};
    use sha2::{Digest as _, Sha256};

    use super::*;
    use crate::memory_contracts::{
        canonical::{CanonicalValue, require_canonical},
        common::frozen_profile_reference_v1,
        digest::{DigestDomain, domain_separated_digest},
        registry::ManifestVerifiedRegistryPackage,
    };

    const GENESIS_PACKAGE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v1/genesis-registry-package.jsonl");
    const POLICY_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v2/successor-policy/activation-policy-v2.jsonl"
    );
    const BRIDGE_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v2/successor-policy/genesis-successor-key-bridge-v1.jsonl"
    );
    const POSITIVE_VECTORS_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v2/successor-policy/positive-vectors.jsonl");
    const NEGATIVE_VECTORS_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v2/successor-policy/negative-vectors.jsonl");
    const VECTOR_SUITE_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v2/successor-policy/vector-suite.jsonl");

    const EXPECTED_POLICY_DIGEST: &str =
        "5611a4fea75d0a8132395bf6e3040ce97638a3447e290f5cabc183c1bb9faa6c";
    const EXPECTED_BRIDGE_DIGEST: &str =
        "e15309eba5118e21996a7cee6b3780c1a237982bdf4f22460bca4da189ef6592";
    const EXPECTED_VECTOR_SUITE_DIGEST: &str =
        "d7ffc6a9057be669ea0a297d02515b61f2609c6bb782489fae3016be86587033";
    const EXPECTED_POSITIVE_VECTOR_DIGEST: &str =
        "f50ab365c5687a2779ff1bf641470ed783f8f084d3d0a916c24c7f95f414dcb0";
    const EXPECTED_NEGATIVE_VECTOR_DIGEST: &str =
        "f0b39c94ea6994fdb9d275ff30319ae0960e0ca77bf807de59789278c66c537d";
    const EXPECTED_POLICY_RAW_SHA256: &str =
        "8b35043e259472ef444ac4203160269fc62d69ab2af71cb4c13888b4a8ef2f1a";
    const EXPECTED_BRIDGE_RAW_SHA256: &str =
        "e008106413023eb6e9da0e9e200d8b8f58b4cae7434a723a9e2e56f357c3b25b";
    const EXPECTED_POSITIVE_VECTORS_RAW_SHA256: &str =
        "da8e12c77785a5cfbd130790cc7fe193585962c111c07de7e3e70d449c67e19f";
    const EXPECTED_NEGATIVE_VECTORS_RAW_SHA256: &str =
        "157619270955455725cee486e0e232d0312bba209c916ed77bbb96686aceb6a0";
    const EXPECTED_VECTOR_SUITE_RAW_SHA256: &str =
        "8b6c2ac601cf5a26e9fd1eab6de3c7616e1bb42ba552cb444ea6b81becb8d18b";

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RawFixtureHashesV1 {
        activation_policy_v2: String,
        genesis_successor_key_bridge_v1: String,
        negative_vectors: String,
        positive_vectors: String,
    }

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct SuccessorPolicyCaseManifestV1 {
        cases: Vec<String>,
        fixture_authority: String,
        polarity: String,
        schema_version: u32,
        suite_id: ContractId,
    }

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct SuccessorPolicyVectorSuiteV1 {
        activation_policy_digest: Sha256Digest,
        activation_policy_path: String,
        bridge_digest: GenesisSuccessorKeyBridgeDigest,
        bridge_path: String,
        fixture_authority: String,
        from_generation: u32,
        genesis_separation_of_duty: GenesisTransitionSeparationOfDutyV1,
        genesis_activation_id: Sha256Digest,
        negative_vector_digest: Sha256Digest,
        negative_cases: Vec<String>,
        positive_vector_digest: Sha256Digest,
        raw_sha256: RawFixtureHashesV1,
        schema_version: u32,
        suite_id: ContractId,
        to_generation: u32,
    }

    fn record(artifact: &'static [u8]) -> &'static [u8] {
        let record = artifact
            .strip_suffix(b"\n")
            .expect("fixture must end in exactly one LF");
        assert!(!record.ends_with(b"\n"));
        record
    }

    fn digest(value: &str) -> Sha256Digest {
        Sha256Digest::from_str(value).unwrap()
    }

    fn raw_sha256(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    fn framed_raw_sha256(record: &[u8]) -> String {
        let mut framed = record.to_vec();
        framed.push(b'\n');
        raw_sha256(&framed)
    }

    fn public_key(value: &str) -> FixedHex32 {
        FixedHex32::from_bytes(hex::decode(value).unwrap().try_into().unwrap())
    }

    fn binding(principal: &str, key: &str) -> ActivationSignerBindingV2 {
        ActivationSignerBindingV2 {
            principal_id: ContractId::new(principal).unwrap(),
            algorithm: ActivationSignatureAlgorithmV2::Ed25519,
            public_key: public_key(key),
        }
    }

    fn signer_bindings() -> Vec<ActivationSignerBindingV2> {
        vec![
            binding(
                "principal.alice",
                "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",
            ),
            binding(
                "principal.bob",
                "8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394",
            ),
        ]
    }

    fn policy() -> ActivationPolicyEntryV2 {
        ActivationPolicyEntryV2 {
            schema_version: 2,
            policy_id: ContractId::new("activation.default").unwrap(),
            version: 2,
            eligible_signers: signer_bindings(),
            approval_threshold: 2,
            separation_of_duty:
                ActivationSeparationOfDutyV2::AuthorAndProposerDistinctNeitherMayApprove,
            self_authorization_allowed: false,
            break_glass_enabled: false,
        }
    }

    fn positive_vectors() -> SuccessorPolicyCaseManifestV1 {
        SuccessorPolicyCaseManifestV1 {
            cases: vec![
                "bridge_exact_v1_principal_closure".into(),
                "first_successor_author_plus_independent_approval".into(),
                "first_successor_proposer_approval_allowed".into(),
                "strong_separation_of_duty".into(),
                "structural_policy_resolution".into(),
            ],
            fixture_authority: "test_only_no_runtime_authority".into(),
            polarity: "positive".into(),
            schema_version: 1,
            suite_id: ContractId::new("ostk.successor-policy.positive.v1").unwrap(),
        }
    }

    fn negative_vectors() -> SuccessorPolicyCaseManifestV1 {
        SuccessorPolicyCaseManifestV1 {
            cases: vec![
                "break_glass".into(),
                "bridge_pin_mismatch".into(),
                "bridge_reuse".into(),
                "duplicate_key".into(),
                "duplicate_principal".into(),
                "extra_v1_principal".into(),
                "first_successor_author_only_approval".into(),
                "head_mismatch".into(),
                "invalid_generation".into(),
                "missing_v1_principal".into(),
                "policy_mismatch".into(),
                "profile_mismatch".into(),
                "scope_mismatch".into(),
                "self_authorization".into(),
                "separation_of_duty".into(),
                "threshold".into(),
                "zero_key".into(),
            ],
            fixture_authority: "test_only_no_runtime_authority".into(),
            polarity: "negative".into(),
            schema_version: 1,
            suite_id: ContractId::new("ostk.successor-policy.negative.v1").unwrap(),
        }
    }

    fn vector_digest(manifest: &SuccessorPolicyCaseManifestV1) -> Sha256Digest {
        domain_separated_digest(
            DigestDomain::TestVectorManifest,
            &encode_canonical(manifest).unwrap(),
        )
    }

    fn policy_entry() -> RegistryEntryV1 {
        let body: CanonicalValue = decode_strict(&encode_canonical(&policy()).unwrap()).unwrap();
        RegistryEntryV1 {
            schema_version: 1,
            kind: RegistryEntryKind::ActivationPolicy,
            entry_id: ContractId::new("activation.default").unwrap(),
            version: 2,
            entry_schema_id: ContractId::new(ACTIVATION_POLICY_ENTRY_SCHEMA_ID).unwrap(),
            entry_schema_version: 2,
            body,
            positive_vector_digest: vector_digest(&positive_vectors()),
            negative_vector_digest: vector_digest(&negative_vectors()),
        }
    }

    fn vector_suite() -> SuccessorPolicyVectorSuiteV1 {
        let policy_bytes = encode_canonical(&policy_entry()).unwrap();
        let bridge_bytes = encode_canonical(&bridge()).unwrap();
        let positive_bytes = encode_canonical(&positive_vectors()).unwrap();
        let negative_bytes = encode_canonical(&negative_vectors()).unwrap();
        SuccessorPolicyVectorSuiteV1 {
            activation_policy_digest: policy_entry().digest().unwrap(),
            activation_policy_path: "activation-policy-v2.jsonl".into(),
            bridge_digest: bridge().bridge_digest().unwrap(),
            bridge_path: "genesis-successor-key-bridge-v1.jsonl".into(),
            fixture_authority: "test_only_no_runtime_authority".into(),
            from_generation: 0,
            genesis_separation_of_duty:
                GenesisTransitionSeparationOfDutyV1::IndependentApprovalFromPackageAuthor,
            genesis_activation_id: genesis_head().head.activation_id,
            negative_vector_digest: vector_digest(&negative_vectors()),
            negative_cases: negative_vectors().cases,
            positive_vector_digest: vector_digest(&positive_vectors()),
            raw_sha256: RawFixtureHashesV1 {
                activation_policy_v2: framed_raw_sha256(&policy_bytes),
                genesis_successor_key_bridge_v1: framed_raw_sha256(&bridge_bytes),
                negative_vectors: framed_raw_sha256(&negative_bytes),
                positive_vectors: framed_raw_sha256(&positive_bytes),
            },
            schema_version: 1,
            suite_id: ContractId::new("ostk.successor-policy.v1").unwrap(),
            to_generation: 1,
        }
    }

    fn scope() -> AuthenticatedProjectScopeV1 {
        AuthenticatedProjectScopeV1::from_trusted_context(
            ContractId::new("tenant.fixture").unwrap(),
            ContractId::new("project.fixture").unwrap(),
        )
    }

    fn genesis_head() -> RegistryHeadBindingV1 {
        RegistryHeadBindingV1 {
            head: super::super::registry::RegistryHeadV1 {
                activation_id: digest(
                    "5a7263f5c98e75b94e82341d2a7729e9578d4691691b5a8401e1c37a83931261",
                ),
                package_digest: digest(
                    "5a931fd5551bec47f83adb019f3e794d1b6a759f4501e7ea26a83076d9518177",
                ),
                activation_policy_digest: digest(
                    "6f92f99ff35969845f08f9b64cee7d86fa42dc6165ebc617d950be8960b86968",
                ),
            },
            effective_from: super::super::common::CanonicalTimestamp::parse(
                "2026-08-15T03:00:00.000000000Z",
            )
            .unwrap(),
            effective_until: None,
        }
    }

    fn current_v1_policy_reference() -> RegistryReferenceV1 {
        RegistryReferenceV1 {
            entry_id: ContractId::new("activation.default").unwrap(),
            version: 1,
            entry_digest: genesis_head().head.activation_policy_digest,
        }
    }

    fn bridge() -> GenesisSuccessorKeyBridgeV1 {
        GenesisSuccessorKeyBridgeV1 {
            schema_version: 1,
            profile: frozen_profile_reference_v1(),
            scope: scope(),
            genesis_registry_head: genesis_head(),
            current_v1_activation_policy: current_v1_policy_reference(),
            from_generation: 0,
            to_generation: 1,
            key_map: signer_bindings(),
        }
    }

    fn package() -> SemanticallyClosedGenesisPackage {
        let verified = ManifestVerifiedRegistryPackage::decode(
            record(GENESIS_PACKAGE),
            &frozen_profile_reference_v1(),
        )
        .unwrap();
        SemanticallyClosedGenesisPackage::from_manifest_verified(verified).unwrap()
    }

    fn witness(
        expected_scope: AuthenticatedProjectScopeV1,
        expected_head: RegistryHeadBindingV1,
        current_generation: u32,
        already_consumed: bool,
    ) -> ActiveGenesisSuccessorWitness {
        ActiveGenesisSuccessorWitness::from_test_fixture(
            frozen_profile_reference_v1(),
            expected_scope,
            expected_head,
            current_v1_policy_reference(),
            &package(),
            current_generation,
            already_consumed,
        )
        .unwrap()
    }

    fn pin_for_bytes(bytes: &[u8]) -> GenesisSuccessorKeyBridgePin {
        GenesisSuccessorKeyBridgePin::from_trusted_config(
            GenesisSuccessorKeyBridgeDigest::from_digest(domain_separated_digest(
                DigestDomain::GenesisSuccessorKeyBridgeV1,
                bytes,
            )),
        )
    }

    #[test]
    fn authoritative_fixtures_and_hard_coded_digests_are_frozen() {
        for (framed, expected_raw) in [
            (POLICY_FIXTURE, EXPECTED_POLICY_RAW_SHA256),
            (BRIDGE_FIXTURE, EXPECTED_BRIDGE_RAW_SHA256),
            (
                POSITIVE_VECTORS_FIXTURE,
                EXPECTED_POSITIVE_VECTORS_RAW_SHA256,
            ),
            (
                NEGATIVE_VECTORS_FIXTURE,
                EXPECTED_NEGATIVE_VECTORS_RAW_SHA256,
            ),
            (VECTOR_SUITE_FIXTURE, EXPECTED_VECTOR_SUITE_RAW_SHA256),
        ] {
            assert_eq!(raw_sha256(framed), expected_raw);
            require_canonical(record(framed)).unwrap();
        }

        let fixture_policy: RegistryEntryV1 = decode_strict(record(POLICY_FIXTURE)).unwrap();
        let fixture_bridge: GenesisSuccessorKeyBridgeV1 =
            decode_strict(record(BRIDGE_FIXTURE)).unwrap();
        let fixture_positive: SuccessorPolicyCaseManifestV1 =
            decode_strict(record(POSITIVE_VECTORS_FIXTURE)).unwrap();
        let fixture_negative: SuccessorPolicyCaseManifestV1 =
            decode_strict(record(NEGATIVE_VECTORS_FIXTURE)).unwrap();
        assert_eq!(fixture_policy, policy_entry());
        assert_eq!(fixture_bridge, bridge());
        assert_eq!(fixture_positive, positive_vectors());
        assert_eq!(fixture_negative, negative_vectors());
        assert!(strictly_sorted(&fixture_positive.cases));
        assert!(strictly_sorted(&fixture_negative.cases));
        assert_eq!(
            encode_canonical(&policy_entry()).unwrap(),
            record(POLICY_FIXTURE)
        );
        assert_eq!(encode_canonical(&bridge()).unwrap(), record(BRIDGE_FIXTURE));
        assert_eq!(
            encode_canonical(&positive_vectors()).unwrap(),
            record(POSITIVE_VECTORS_FIXTURE)
        );
        assert_eq!(
            encode_canonical(&negative_vectors()).unwrap(),
            record(NEGATIVE_VECTORS_FIXTURE)
        );
        assert_eq!(
            policy_entry().digest().unwrap().to_string(),
            EXPECTED_POLICY_DIGEST
        );
        assert_eq!(
            bridge().bridge_digest().unwrap().to_string(),
            EXPECTED_BRIDGE_DIGEST
        );
        assert_eq!(
            vector_digest(&fixture_positive).to_string(),
            EXPECTED_POSITIVE_VECTOR_DIGEST
        );
        assert_eq!(
            vector_digest(&fixture_negative).to_string(),
            EXPECTED_NEGATIVE_VECTOR_DIGEST
        );
    }

    #[test]
    fn aggregate_vector_suite_is_frozen() {
        let suite: SuccessorPolicyVectorSuiteV1 =
            decode_strict(record(VECTOR_SUITE_FIXTURE)).unwrap();
        assert_eq!(
            encode_canonical(&suite).unwrap(),
            record(VECTOR_SUITE_FIXTURE)
        );
        assert_eq!(suite.schema_version, 1);
        assert_eq!(suite, vector_suite());
        assert_eq!(
            suite.activation_policy_digest,
            policy_entry().digest().unwrap()
        );
        assert_eq!(suite.bridge_digest, bridge().bridge_digest().unwrap());
        assert_eq!(
            suite.positive_vector_digest,
            vector_digest(&positive_vectors())
        );
        assert_eq!(
            suite.negative_vector_digest,
            vector_digest(&negative_vectors())
        );
        assert_eq!(suite.from_generation, 0);
        assert_eq!(suite.to_generation, 1);
        assert_eq!(
            suite.genesis_activation_id,
            genesis_head().head.activation_id
        );
        assert_eq!(
            suite.raw_sha256.activation_policy_v2,
            EXPECTED_POLICY_RAW_SHA256
        );
        assert_eq!(
            suite.raw_sha256.genesis_successor_key_bridge_v1,
            EXPECTED_BRIDGE_RAW_SHA256
        );
        assert_eq!(
            suite.raw_sha256.positive_vectors,
            EXPECTED_POSITIVE_VECTORS_RAW_SHA256
        );
        assert_eq!(
            suite.raw_sha256.negative_vectors,
            EXPECTED_NEGATIVE_VECTORS_RAW_SHA256
        );
        assert_eq!(
            domain_separated_digest(
                DigestDomain::TestVectorManifest,
                record(VECTOR_SUITE_FIXTURE)
            )
            .to_string(),
            EXPECTED_VECTOR_SUITE_DIGEST
        );
    }

    #[test]
    fn activation_policy_artifact_resolves_without_granting_authority() {
        let entry = policy_entry();
        let resolved = StructurallyResolvedActivationPolicyV2::from_registry_entry(&entry).unwrap();
        assert_eq!(resolved.policy(), &policy());
        assert_eq!(
            resolved.registry_reference().entry_digest,
            entry.digest().unwrap()
        );
        assert_eq!(
            entry.positive_vector_digest,
            vector_digest(&positive_vectors())
        );
        assert_eq!(
            entry.negative_vector_digest,
            vector_digest(&negative_vectors())
        );

        let mut wrong_kind = entry.clone();
        wrong_kind.kind = RegistryEntryKind::AuthorityRule;
        assert!(StructurallyResolvedActivationPolicyV2::from_registry_entry(&wrong_kind).is_err());
        let mut wrong_schema = entry;
        wrong_schema.entry_schema_version = 1;
        assert!(
            StructurallyResolvedActivationPolicyV2::from_registry_entry(&wrong_schema).is_err()
        );
        let mut mismatched_body = policy();
        mismatched_body.policy_id = ContractId::new("activation.other").unwrap();
        entry_body_replace(&mut wrong_schema, &mismatched_body);
        wrong_schema.entry_schema_version = 2;
        assert!(matches!(
            StructurallyResolvedActivationPolicyV2::from_registry_entry(&wrong_schema),
            Err(ContractError::ManifestMismatch)
        ));
    }

    fn entry_body_replace(entry: &mut RegistryEntryV1, body: &ActivationPolicyEntryV2) {
        entry.body = decode_strict(&encode_canonical(body).unwrap()).unwrap();
    }

    #[test]
    fn v2_policy_is_key_complete_and_enforces_strong_separation_of_duty() {
        let policy = policy();
        policy.validate().unwrap();
        assert_eq!(
            policy.eligible_signers[0].signer_key_id().unwrap().as_str(),
            "ed25519.8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c"
        );
        let author = ContractId::new("principal.author").unwrap();
        let proposer = ContractId::new("principal.proposer").unwrap();
        let approvals = vec![
            ContractId::new("principal.alice").unwrap(),
            ContractId::new("principal.bob").unwrap(),
        ];
        policy
            .validate_approval_principal_set(&author, &proposer, &approvals)
            .unwrap();

        assert!(
            policy
                .validate_approval_principal_set(&author, &author, &approvals)
                .is_err()
        );
        for excluded in [&author, &proposer] {
            let approvals = vec![
                ContractId::new("principal.alice").unwrap(),
                excluded.clone(),
            ];
            assert!(
                policy
                    .validate_approval_principal_set(&author, &proposer, &approvals)
                    .is_err()
            );
        }
    }

    #[test]
    fn v2_policy_rejects_duplicate_bindings_fail_open_flags_and_threshold_errors() {
        let mut duplicate_principal = policy();
        duplicate_principal.eligible_signers[1].principal_id =
            duplicate_principal.eligible_signers[0].principal_id.clone();
        assert!(duplicate_principal.validate().is_err());

        let mut duplicate_key = policy();
        duplicate_key.eligible_signers[1].public_key = duplicate_key.eligible_signers[0].public_key;
        assert!(duplicate_key.validate().is_err());

        let mut zero_key = policy();
        zero_key.eligible_signers[1].public_key = FixedHex32::from_bytes([0; 32]);
        assert!(zero_key.validate().is_err());

        for threshold in [0, 3] {
            let mut invalid = policy();
            invalid.approval_threshold = threshold;
            assert!(invalid.validate().is_err());
        }
        let mut self_authorizing = policy();
        self_authorizing.self_authorization_allowed = true;
        assert!(self_authorizing.validate().is_err());
        let mut break_glass = policy();
        break_glass.break_glass_enabled = true;
        assert!(break_glass.validate().is_err());

        let insufficient = vec![ContractId::new("principal.alice").unwrap()];
        assert_eq!(
            policy().validate_approval_principal_set(
                &ContractId::new("principal.author").unwrap(),
                &ContractId::new("principal.proposer").unwrap(),
                &insufficient,
            ),
            Err(ContractError::ApprovalThresholdNotMet)
        );
    }

    #[test]
    fn bridge_pin_and_active_v1_policy_close_the_exact_principal_set() {
        let bytes = encode_canonical(&bridge()).unwrap();
        let verified = verify_pinned_genesis_successor_key_bridge(
            &bytes,
            pin_for_bytes(&bytes),
            &witness(scope(), genesis_head(), 0, false),
        )
        .unwrap();
        assert_eq!(verified.bridge(), &bridge());
        assert_eq!(verified.canonical_bytes(), bytes);
        assert_eq!(verified.required_v1_threshold(), 2);
        assert_eq!(
            verified.v1_separation_of_duty(),
            GenesisTransitionSeparationOfDutyV1::IndependentApprovalFromPackageAuthor
        );
        assert_eq!(verified.bridge().from_generation, 0);
        assert_eq!(verified.bridge().to_generation, 1);

        let wrong_pin = GenesisSuccessorKeyBridgePin::from_trusted_config(
            GenesisSuccessorKeyBridgeDigest::from_digest(Sha256Digest::ZERO),
        );
        assert!(matches!(
            verify_pinned_genesis_successor_key_bridge(
                &bytes,
                wrong_pin,
                &witness(scope(), genesis_head(), 0, false),
            ),
            Err(ContractError::ManifestMismatch)
        ));

        let mut noncanonical = bytes;
        noncanonical.push(b' ');
        assert!(matches!(
            verify_pinned_genesis_successor_key_bridge(
                &noncanonical,
                wrong_pin,
                &witness(scope(), genesis_head(), 0, false),
            ),
            Err(ContractError::ManifestMismatch)
        ));
        assert!(matches!(
            verify_pinned_genesis_successor_key_bridge(
                &noncanonical,
                pin_for_bytes(&noncanonical),
                &witness(scope(), genesis_head(), 0, false),
            ),
            Err(ContractError::NotCanonical)
        ));
    }

    #[test]
    fn first_successor_uses_v1_existential_author_independence_without_proposer_exclusion() {
        let bytes = encode_canonical(&bridge()).unwrap();
        let verified = verify_pinned_genesis_successor_key_bridge(
            &bytes,
            pin_for_bytes(&bytes),
            &witness(scope(), genesis_head(), 0, false),
        )
        .unwrap();
        let alice = ContractId::new("principal.alice").unwrap();
        let bob = ContractId::new("principal.bob").unwrap();

        // The eligible package author may count when an independent approval
        // is also present.
        verified
            .validate_first_successor_approval_principal_set(&alice, &[alice.clone(), bob.clone()])
            .unwrap();

        // Treat Alice as the trusted proposer and an unrelated principal as
        // package author. The v1 API deliberately does not exclude Alice merely
        // because she is proposer, so both eligible approvals still count.
        verified
            .validate_first_successor_approval_principal_set(
                &ContractId::new("principal.author").unwrap(),
                &[alice.clone(), bob.clone()],
            )
            .unwrap();

        assert_eq!(
            verified.validate_first_successor_approval_principal_set(
                &alice,
                std::slice::from_ref(&alice),
            ),
            Err(ContractError::ApprovalThresholdNotMet)
        );
        let mut threshold_one = verified.clone();
        threshold_one.required_v1_threshold = 1;
        assert!(matches!(
            threshold_one.validate_first_successor_approval_principal_set(
                &alice,
                std::slice::from_ref(&alice),
            ),
            Err(ContractError::Schema(_))
        ));
        assert_eq!(
            verified.validate_first_successor_approval_principal_set(
                &alice,
                std::slice::from_ref(&bob),
            ),
            Err(ContractError::ApprovalThresholdNotMet)
        );
        assert!(matches!(
            verified
                .validate_first_successor_approval_principal_set(&alice, &[bob, alice.clone()],),
            Err(ContractError::NonCanonicalSet {
                field: "approving_principal_ids"
            })
        ));
        assert!(matches!(
            verified.validate_first_successor_approval_principal_set(
                &alice,
                &[alice.clone(), ContractId::new("principal.carol").unwrap()],
            ),
            Err(ContractError::InvalidSignerPolicy(_))
        ));
    }

    #[test]
    fn bridge_rejects_missing_extra_duplicate_principals_and_keys() {
        let active = witness(scope(), genesis_head(), 0, false);
        let mut cases = Vec::new();

        let mut missing = bridge();
        missing.key_map.pop();
        cases.push(missing);

        let mut extra = bridge();
        extra.key_map.push(binding(
            "principal.carol",
            "ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1",
        ));
        cases.push(extra);

        for invalid in cases {
            let bytes = encode_canonical(&invalid).unwrap();
            assert!(matches!(
                verify_pinned_genesis_successor_key_bridge(&bytes, pin_for_bytes(&bytes), &active,),
                Err(ContractError::ManifestMismatch)
            ));
        }

        let mut duplicate_principal = bridge();
        duplicate_principal.key_map[1].principal_id =
            duplicate_principal.key_map[0].principal_id.clone();
        assert!(duplicate_principal.validate_shape().is_err());
        let mut duplicate_key = bridge();
        duplicate_key.key_map[1].public_key = duplicate_key.key_map[0].public_key;
        assert!(duplicate_key.validate_shape().is_err());
        let mut zero_key = bridge();
        zero_key.key_map[1].public_key = FixedHex32::from_bytes([0; 32]);
        assert!(zero_key.validate_shape().is_err());
    }

    #[test]
    fn bridge_rejects_profile_scope_head_and_policy_mismatches() {
        let active = witness(scope(), genesis_head(), 0, false);

        let mut wrong_profile = bridge();
        wrong_profile.profile.profile_digest =
            digest("1111111111111111111111111111111111111111111111111111111111111111");
        let bytes = encode_canonical(&wrong_profile).unwrap();
        assert!(matches!(
            verify_pinned_genesis_successor_key_bridge(&bytes, pin_for_bytes(&bytes), &active,),
            Err(ContractError::ProfileMismatch)
        ));

        let mut wrong_scope = bridge();
        wrong_scope.scope = AuthenticatedProjectScopeV1::from_trusted_context(
            ContractId::new("tenant.fixture").unwrap(),
            ContractId::new("project.other").unwrap(),
        );
        let bytes = encode_canonical(&wrong_scope).unwrap();
        assert!(matches!(
            verify_pinned_genesis_successor_key_bridge(&bytes, pin_for_bytes(&bytes), &active,),
            Err(ContractError::ManifestMismatch)
        ));

        let mut wrong_head = bridge();
        wrong_head.genesis_registry_head.head.activation_id =
            digest("2222222222222222222222222222222222222222222222222222222222222222");
        let bytes = encode_canonical(&wrong_head).unwrap();
        assert!(matches!(
            verify_pinned_genesis_successor_key_bridge(&bytes, pin_for_bytes(&bytes), &active,),
            Err(ContractError::StaleRegistryHead)
        ));

        let mut wrong_policy = bridge();
        wrong_policy.current_v1_activation_policy.entry_id =
            ContractId::new("activation.other").unwrap();
        let bytes = encode_canonical(&wrong_policy).unwrap();
        assert!(matches!(
            verify_pinned_genesis_successor_key_bridge(&bytes, pin_for_bytes(&bytes), &active,),
            Err(ContractError::ManifestMismatch)
        ));
    }

    #[test]
    fn bridge_reuse_and_every_non_zero_to_one_generation_fail_closed() {
        let bytes = encode_canonical(&bridge()).unwrap();
        for active in [
            witness(scope(), genesis_head(), 1, false),
            witness(scope(), genesis_head(), 0, true),
        ] {
            assert!(
                verify_pinned_genesis_successor_key_bridge(&bytes, pin_for_bytes(&bytes), &active,)
                    .is_err()
            );
        }

        for (from_generation, to_generation) in [(1, 2), (0, 2), (1, 1)] {
            let mut invalid = bridge();
            invalid.from_generation = from_generation;
            invalid.to_generation = to_generation;
            assert!(invalid.validate_shape().is_err());
        }
    }

    #[test]
    #[ignore = "fixture generator; non-ignored tests pin authoritative bytes"]
    fn print_fixture_records() {
        let policy_bytes = encode_canonical(&policy_entry()).unwrap();
        let bridge_bytes = encode_canonical(&bridge()).unwrap();
        let positive_bytes = encode_canonical(&positive_vectors()).unwrap();
        let negative_bytes = encode_canonical(&negative_vectors()).unwrap();
        let vector_suite_bytes = encode_canonical(&vector_suite()).unwrap();
        println!(
            "FIXTURE activation-policy-v2.jsonl {}",
            String::from_utf8(policy_bytes).unwrap()
        );
        println!(
            "FIXTURE genesis-successor-key-bridge-v1.jsonl {}",
            String::from_utf8(bridge_bytes).unwrap()
        );
        println!(
            "FIXTURE positive-vectors.jsonl {}",
            String::from_utf8(positive_bytes).unwrap()
        );
        println!(
            "FIXTURE negative-vectors.jsonl {}",
            String::from_utf8(negative_bytes).unwrap()
        );
        println!(
            "FIXTURE vector-suite.jsonl {}",
            String::from_utf8(vector_suite_bytes.clone()).unwrap()
        );
        println!("POLICY_DIGEST {}", policy_entry().digest().unwrap());
        println!("BRIDGE_DIGEST {}", bridge().bridge_digest().unwrap());
        println!(
            "POSITIVE_VECTOR_DIGEST {}",
            vector_digest(&positive_vectors())
        );
        println!(
            "NEGATIVE_VECTOR_DIGEST {}",
            vector_digest(&negative_vectors())
        );
        println!(
            "VECTOR_SUITE_DIGEST {}",
            domain_separated_digest(DigestDomain::TestVectorManifest, &vector_suite_bytes)
        );
    }
}
