//! Out-of-band-pinned genesis authority and deterministic log-epoch contracts.

use std::{collections::BTreeSet, fmt};

use ring::signature;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

use super::{
    ContractError, ContractResult,
    canonical::{decode_strict, encode_canonical, require_canonical},
    common::{
        AuthenticatedProjectScopeV1, CanonicalDecimal, ContractId, FixedHex32, FixedHex64,
        ProfileReferenceV1,
    },
    digest::{DigestDomain, Sha256Digest, domain_separated_digest, framed_digest},
    genesis::SemanticallyClosedGenesisPackage,
};

const BOOTSTRAP_SCHEMA_VERSION: u32 = 1;
const MAX_BOOTSTRAP_SIGNERS: usize = 64;
const MAX_SHARDS: u16 = 4_096;
const BOOTSTRAP_APPROVAL_PREFIX: &[u8] = b"ostk-bootstrap-approval-v1\0";

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

digest_newtype!(BootstrapStatementId);
digest_newtype!(BootstrapReceiptDigest);
digest_newtype!(EpochId);

/// Only signature algorithm admitted by the v1 bootstrap profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootstrapSignatureAlgorithm {
    Ed25519,
}

/// One principal-to-key mapping in the out-of-band bootstrap root.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapSignerV1 {
    pub principal_id: ContractId,
    pub algorithm: BootstrapSignatureAlgorithm,
    pub public_key: FixedHex32,
}

/// Immutable signer set. Threshold counts unique principals, never keys or rows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapSignerPolicyV1 {
    pub schema_version: u32,
    pub signers: Vec<BootstrapSignerV1>,
    pub threshold: u16,
}

impl BootstrapSignerPolicyV1 {
    pub fn validate(&self) -> ContractResult<()> {
        if self.schema_version != BOOTSTRAP_SCHEMA_VERSION
            || self.signers.is_empty()
            || self.signers.len() > MAX_BOOTSTRAP_SIGNERS
            || self.threshold == 0
            || usize::from(self.threshold) > self.signers.len()
            || !strictly_sorted(&self.signers)
        {
            return Err(ContractError::InvalidSignerPolicy(
                "invalid signer ordering, count, or threshold".into(),
            ));
        }
        let keys = self
            .signers
            .iter()
            .map(|signer| signer.public_key)
            .collect::<BTreeSet<_>>();
        let principals = self
            .signers
            .iter()
            .map(|signer| &signer.principal_id)
            .collect::<BTreeSet<_>>();
        if keys.len() != self.signers.len() || principals.len() != self.signers.len() {
            return Err(ContractError::InvalidSignerPolicy(
                "principals and public keys must each be unique".into(),
            ));
        }
        Ok(())
    }

    pub fn digest(&self) -> ContractResult<Sha256Digest> {
        self.validate()?;
        Ok(domain_separated_digest(
            DigestDomain::BootstrapSignerPolicy,
            &encode_canonical(self)?,
        ))
    }
}

/// Built-in partition formula. New formulas require a new recipe version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PartitionAlgorithm {
    Sha256Prefix64Modulo,
}

/// Genesis log partition parameters. Seed is non-secret and identity-bearing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PartitionRecipeV1 {
    pub schema_version: u32,
    pub recipe_id: ContractId,
    pub recipe_version: u32,
    pub algorithm: PartitionAlgorithm,
    pub seed: FixedHex32,
    pub shard_count: u16,
}

impl PartitionRecipeV1 {
    pub fn validate(&self) -> ContractResult<()> {
        if self.schema_version != BOOTSTRAP_SCHEMA_VERSION
            || self.recipe_id.as_str() != "ostk.partition.sha256_prefix64_modulo"
            || self.recipe_version != 1
            || self.shard_count == 0
            || self.shard_count > MAX_SHARDS
        {
            return Err(ContractError::Schema("invalid partition recipe".into()));
        }
        Ok(())
    }
}

/// Dedicated genesis epoch: no fake ordinal or predecessor sentinel exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisLogEpochV1 {
    pub schema_version: u32,
    pub profile: ProfileReferenceV1,
    pub scope: AuthenticatedProjectScopeV1,
    pub partition_recipe: PartitionRecipeV1,
}

impl GenesisLogEpochV1 {
    pub fn validate(&self) -> ContractResult<()> {
        self.profile.validate()?;
        self.partition_recipe.validate()?;
        if self.schema_version != BOOTSTRAP_SCHEMA_VERSION {
            return Err(ContractError::Schema("invalid genesis log epoch".into()));
        }
        Ok(())
    }

    pub fn epoch_id(&self) -> ContractResult<EpochId> {
        self.validate()?;
        Ok(EpochId::from_digest(domain_separated_digest(
            DigestDomain::Epoch,
            &encode_canonical(self)?,
        )))
    }
}

/// Unsigned semantic bootstrap statement. The genesis package does not sign or
/// authorize itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapStatementV1 {
    pub schema_version: u32,
    pub profile: ProfileReferenceV1,
    pub scope: AuthenticatedProjectScopeV1,
    pub genesis_registry_package_digest: Sha256Digest,
    pub genesis_epoch: GenesisLogEpochV1,
    pub signer_policy: BootstrapSignerPolicyV1,
    pub signer_policy_digest: Sha256Digest,
}

impl BootstrapStatementV1 {
    pub fn validate(&self) -> ContractResult<()> {
        self.profile.validate()?;
        self.genesis_epoch.validate()?;
        self.signer_policy.validate()?;
        if self.schema_version != BOOTSTRAP_SCHEMA_VERSION
            || self.genesis_epoch.profile != self.profile
            || self.genesis_epoch.scope != self.scope
            || self.signer_policy.digest()? != self.signer_policy_digest
        {
            return Err(ContractError::BootstrapBindingMismatch);
        }
        Ok(())
    }

    pub fn statement_id(&self) -> ContractResult<BootstrapStatementId> {
        self.validate()?;
        Ok(BootstrapStatementId::from_digest(domain_separated_digest(
            DigestDomain::BootstrapStatement,
            &encode_canonical(self)?,
        )))
    }
}

/// One detached Ed25519 approval over the fixed bootstrap message framing.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapAttestationV1 {
    pub schema_version: u32,
    pub statement_id: BootstrapStatementId,
    pub signer_principal_id: ContractId,
    pub signature: FixedHex64,
}

impl BootstrapAttestationV1 {
    pub fn validate_shape(&self) -> ContractResult<()> {
        if self.schema_version != BOOTSTRAP_SCHEMA_VERSION {
            return Err(ContractError::Schema(
                "invalid bootstrap attestation".into(),
            ));
        }
        Ok(())
    }

    pub fn attestation_id(&self) -> ContractResult<Sha256Digest> {
        self.validate_shape()?;
        Ok(domain_separated_digest(
            DigestDomain::BootstrapAttestation,
            &encode_canonical(self)?,
        ))
    }
}

/// Complete approval set pinned by deployment configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapReceiptV1 {
    pub schema_version: u32,
    pub statement: BootstrapStatementV1,
    pub attestations: Vec<BootstrapAttestationV1>,
}

/// Digest supplied only by trusted process configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootstrapPin(BootstrapReceiptDigest);

impl BootstrapPin {
    pub const fn from_trusted_config(digest: BootstrapReceiptDigest) -> Self {
        Self(digest)
    }
}

/// Authority token produced only after canonical parsing, exact binding, pin,
/// signature, and threshold verification.
#[derive(Debug, Clone)]
pub struct VerifiedBootstrapReceipt {
    receipt: BootstrapReceiptV1,
    canonical_bytes: Vec<u8>,
    receipt_digest: BootstrapReceiptDigest,
    statement_id: BootstrapStatementId,
    epoch_id: EpochId,
}

impl VerifiedBootstrapReceipt {
    pub const fn receipt(&self) -> &BootstrapReceiptV1 {
        &self.receipt
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub const fn receipt_digest(&self) -> BootstrapReceiptDigest {
        self.receipt_digest
    }

    pub const fn statement_id(&self) -> BootstrapStatementId {
        self.statement_id
    }

    pub const fn epoch_id(&self) -> EpochId {
        self.epoch_id
    }

    pub fn partition_for(&self, key: &ConsistencyPartitionKeyV1) -> ContractResult<u16> {
        partition_for_epoch(&self.receipt.statement.genesis_epoch, key)
    }

    pub fn genesis_chain_digest(&self, shard: u16) -> ContractResult<Sha256Digest> {
        let epoch = &self.receipt.statement.genesis_epoch;
        if shard >= epoch.partition_recipe.shard_count {
            return Err(ContractError::Schema(
                "genesis chain shard is outside the epoch".into(),
            ));
        }
        Ok(framed_digest(
            DigestDomain::GenesisChain,
            &[
                self.receipt_digest.digest().as_bytes(),
                self.epoch_id.digest().as_bytes(),
                &shard.to_be_bytes(),
            ],
        ))
    }
}

/// Verify one exact canonical bootstrap artifact against the deployment pin.
pub fn verify_pinned_bootstrap(
    input: &[u8],
    pin: BootstrapPin,
    expected_profile: &ProfileReferenceV1,
    expected_scope: &AuthenticatedProjectScopeV1,
    genesis_package: &SemanticallyClosedGenesisPackage,
) -> ContractResult<VerifiedBootstrapReceipt> {
    expected_profile.validate()?;
    require_canonical(input)?;
    let receipt: BootstrapReceiptV1 = decode_strict(input)?;
    if receipt.schema_version != BOOTSTRAP_SCHEMA_VERSION {
        return Err(ContractError::Schema("invalid bootstrap receipt".into()));
    }
    let canonical_bytes = encode_canonical(&receipt)?;
    if canonical_bytes != input {
        return Err(ContractError::NotCanonical);
    }
    let receipt_digest = BootstrapReceiptDigest::from_digest(domain_separated_digest(
        DigestDomain::BootstrapReceipt,
        &canonical_bytes,
    ));
    if receipt_digest != pin.0 {
        return Err(ContractError::BootstrapPinMismatch);
    }

    receipt.statement.validate()?;
    let statement_id = receipt.statement.statement_id()?;
    let expected_package_digest = genesis_package.package_digest();
    if receipt.statement.profile != *expected_profile
        || receipt.statement.scope != *expected_scope
        || genesis_package
            .manifest_verified_package()
            .package()
            .profile
            != *expected_profile
        || receipt.statement.genesis_registry_package_digest != expected_package_digest
    {
        return Err(ContractError::BootstrapBindingMismatch);
    }
    if receipt.attestations.len() > MAX_BOOTSTRAP_SIGNERS
        || !receipt
            .attestations
            .windows(2)
            .all(|pair| pair[0].signer_principal_id < pair[1].signer_principal_id)
    {
        return Err(ContractError::Schema(
            "bootstrap attestations are not a canonical set".into(),
        ));
    }

    let message = bootstrap_approval_message(statement_id);
    let mut verified_principals = BTreeSet::new();
    for attestation in &receipt.attestations {
        attestation.validate_shape()?;
        if attestation.statement_id != statement_id {
            return Err(ContractError::SignatureVerification);
        }
        let signer = receipt
            .statement
            .signer_policy
            .signers
            .iter()
            .find(|signer| signer.principal_id == attestation.signer_principal_id)
            .ok_or(ContractError::SignatureVerification)?;
        signature::UnparsedPublicKey::new(&signature::ED25519, signer.public_key.as_bytes())
            .verify(&message, attestation.signature.as_bytes())
            .map_err(|_| ContractError::SignatureVerification)?;
        verified_principals.insert(&signer.principal_id);
    }
    if verified_principals.len() < usize::from(receipt.statement.signer_policy.threshold) {
        return Err(ContractError::ApprovalThresholdNotMet);
    }

    let epoch_id = receipt.statement.genesis_epoch.epoch_id()?;
    Ok(VerifiedBootstrapReceipt {
        receipt,
        canonical_bytes,
        receipt_digest,
        statement_id,
        epoch_id,
    })
}

fn bootstrap_approval_message(statement_id: BootstrapStatementId) -> Vec<u8> {
    let mut message = Vec::with_capacity(BOOTSTRAP_APPROVAL_PREFIX.len() + 32);
    message.extend_from_slice(BOOTSTRAP_APPROVAL_PREFIX);
    message.extend_from_slice(statement_id.digest().as_bytes());
    message
}

/// Registry-derived consistency family plus stable key digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsistencyPartitionKeyV1 {
    pub family: ContractId,
    pub key_digest: Sha256Digest,
}

/// Positive signed 64-bit database offset with a canonical decimal-string wire form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CommittedOffsetV1(u64);

impl CommittedOffsetV1 {
    pub fn new(value: u64) -> ContractResult<Self> {
        if value == 0 || value > i64::MAX as u64 {
            return Err(ContractError::Schema(
                "committed offset is outside the positive INT8 range".into(),
            ));
        }
        Ok(Self(value))
    }

    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl Serialize for CommittedOffsetV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for CommittedOffsetV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = CanonicalDecimal::deserialize(deserializer)?;
        let offset = value.as_str().parse::<u64>().map_err(D::Error::custom)?;
        Self::new(offset).map_err(D::Error::custom)
    }
}

/// Physical append coordinate. It is never part of an accepted event ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppendPositionV1 {
    pub epoch_id: EpochId,
    pub shard: u16,
    pub committed_offset: CommittedOffsetV1,
}

impl AppendPositionV1 {
    pub fn validate_for(&self, bootstrap: &VerifiedBootstrapReceipt) -> ContractResult<()> {
        let epoch = &bootstrap.receipt.statement.genesis_epoch;
        if self.epoch_id != bootstrap.epoch_id || self.shard >= epoch.partition_recipe.shard_count {
            return Err(ContractError::Schema("invalid append position".into()));
        }
        Ok(())
    }
}

/// Derive a bounded shard number. Epoch, scope, family, and key are all framed;
/// no physical position enters semantic event identity.
fn partition_for_epoch(
    epoch: &GenesisLogEpochV1,
    key: &ConsistencyPartitionKeyV1,
) -> ContractResult<u16> {
    epoch.validate()?;
    let epoch_id = epoch.epoch_id()?;
    let scope_bytes = encode_canonical(&epoch.scope)?;
    let digest = framed_digest(
        DigestDomain::Partition,
        &[
            epoch_id.digest().as_bytes(),
            &scope_bytes,
            key.family.as_str().as_bytes(),
            key.key_digest.as_bytes(),
        ],
    );
    let prefix = u64::from_be_bytes(digest.as_bytes()[..8].try_into().map_err(|_| {
        ContractError::Schema("partition digest prefix has an invalid length".into())
    })?);
    let shard = prefix % u64::from(epoch.partition_recipe.shard_count);
    u16::try_from(shard).map_err(|_| ContractError::Schema("partition overflow".into()))
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

#[cfg(test)]
mod tests {
    use ring::signature::{Ed25519KeyPair, KeyPair};

    use super::*;
    use crate::memory_contracts::genesis::{
        SemanticallyClosedGenesisPackage, fixture_closed_package,
    };

    fn digest(domain: DigestDomain, label: &str) -> Sha256Digest {
        domain_separated_digest(domain, label.as_bytes())
    }

    fn profile() -> ProfileReferenceV1 {
        let profile_bytes =
            include_bytes!("../../contracts/dynamic-memory/v1/canonical-profile.jsonl")
                .strip_suffix(b"\n")
                .unwrap();
        let vector_bytes =
            include_bytes!("../../contracts/dynamic-memory/v1/conformance-manifest.jsonl")
                .strip_suffix(b"\n")
                .unwrap();
        ProfileReferenceV1 {
            profile_id: ContractId::new("ostk-canonical-json-v1").unwrap(),
            profile_digest: domain_separated_digest(DigestDomain::CanonicalProfile, profile_bytes),
            vector_manifest_digest: domain_separated_digest(
                DigestDomain::TestVectorManifest,
                vector_bytes,
            ),
        }
    }

    fn scope() -> AuthenticatedProjectScopeV1 {
        AuthenticatedProjectScopeV1::from_trusted_context(
            ContractId::new("tenant.fixture").unwrap(),
            ContractId::new("project.fixture").unwrap(),
        )
    }

    fn package() -> SemanticallyClosedGenesisPackage {
        fixture_closed_package()
    }

    fn key_pair(seed_byte: u8) -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[seed_byte; 32]).unwrap()
    }

    fn unsigned_statement(package: &SemanticallyClosedGenesisPackage) -> BootstrapStatementV1 {
        let pairs = [key_pair(1), key_pair(2), key_pair(3)];
        let signers = pairs
            .iter()
            .enumerate()
            .map(|(index, pair)| BootstrapSignerV1 {
                principal_id: ContractId::new(format!("principal.{}", index + 1)).unwrap(),
                algorithm: BootstrapSignatureAlgorithm::Ed25519,
                public_key: FixedHex32::from_bytes(pair.public_key().as_ref().try_into().unwrap()),
            })
            .collect::<Vec<_>>();
        let signer_policy = BootstrapSignerPolicyV1 {
            schema_version: 1,
            signers,
            threshold: 2,
        };
        BootstrapStatementV1 {
            schema_version: 1,
            profile: profile(),
            scope: scope(),
            genesis_registry_package_digest: package.package_digest(),
            genesis_epoch: GenesisLogEpochV1 {
                schema_version: 1,
                profile: profile(),
                scope: scope(),
                partition_recipe: PartitionRecipeV1 {
                    schema_version: 1,
                    recipe_id: ContractId::new("ostk.partition.sha256_prefix64_modulo").unwrap(),
                    recipe_version: 1,
                    algorithm: PartitionAlgorithm::Sha256Prefix64Modulo,
                    seed: FixedHex32::from_bytes([7; 32]),
                    shard_count: 16,
                },
            },
            signer_policy_digest: signer_policy.digest().unwrap(),
            signer_policy,
        }
    }

    fn signed_receipt(package: &SemanticallyClosedGenesisPackage) -> BootstrapReceiptV1 {
        let statement = unsigned_statement(package);
        let statement_id = statement.statement_id().unwrap();
        let message = bootstrap_approval_message(statement_id);
        let attestations = [1_u8, 2]
            .into_iter()
            .enumerate()
            .map(|(index, seed)| {
                let signature = key_pair(seed).sign(&message);
                BootstrapAttestationV1 {
                    schema_version: 1,
                    statement_id,
                    signer_principal_id: ContractId::new(format!("principal.{}", index + 1))
                        .unwrap(),
                    signature: FixedHex64::from_bytes(signature.as_ref().try_into().unwrap()),
                }
            })
            .collect();
        BootstrapReceiptV1 {
            schema_version: 1,
            statement,
            attestations,
        }
    }

    #[test]
    fn exact_pin_and_two_of_three_signatures_verify() {
        let package = package();
        let receipt = signed_receipt(&package);
        let bytes = encode_canonical(&receipt).unwrap();
        let receipt_digest = BootstrapReceiptDigest::from_digest(domain_separated_digest(
            DigestDomain::BootstrapReceipt,
            &bytes,
        ));
        let verified = verify_pinned_bootstrap(
            &bytes,
            BootstrapPin::from_trusted_config(receipt_digest),
            &profile(),
            &scope(),
            &package,
        )
        .unwrap();
        assert_eq!(verified.receipt_digest(), receipt_digest);
        assert_eq!(
            verified.statement_id(),
            receipt.statement.statement_id().unwrap()
        );
    }

    #[test]
    fn pin_signature_threshold_and_scope_fail_closed() {
        let package = package();
        let mut receipt = signed_receipt(&package);
        let bytes = encode_canonical(&receipt).unwrap();
        let receipt_digest = BootstrapReceiptDigest::from_digest(domain_separated_digest(
            DigestDomain::BootstrapReceipt,
            &bytes,
        ));
        assert_ne!(
            receipt_digest.digest(),
            digest(DigestDomain::BootstrapReceipt, "wrong")
        );
        let wrong_pin = BootstrapPin::from_trusted_config(BootstrapReceiptDigest::from_digest(
            digest(DigestDomain::BootstrapReceipt, "wrong"),
        ));
        assert!(
            verify_pinned_bootstrap(&bytes, wrong_pin, &profile(), &scope(), &package).is_err()
        );

        receipt.attestations.truncate(1);
        let bytes = encode_canonical(&receipt).unwrap();
        let pin = BootstrapPin::from_trusted_config(BootstrapReceiptDigest::from_digest(
            domain_separated_digest(DigestDomain::BootstrapReceipt, &bytes),
        ));
        assert_eq!(
            verify_pinned_bootstrap(&bytes, pin, &profile(), &scope(), &package).unwrap_err(),
            ContractError::ApprovalThresholdNotMet
        );
    }

    #[test]
    fn partition_is_deterministic_and_bounded() {
        let package = package();
        let statement = unsigned_statement(&package);
        let key = ConsistencyPartitionKeyV1 {
            family: ContractId::new("control.bootstrap").unwrap(),
            key_digest: digest(DigestDomain::EvidenceSourceFact, "scope"),
        };
        let first = partition_for_epoch(&statement.genesis_epoch, &key).unwrap();
        assert_eq!(
            first,
            partition_for_epoch(&statement.genesis_epoch, &key).unwrap()
        );
        assert!(first < statement.genesis_epoch.partition_recipe.shard_count);
    }
}
