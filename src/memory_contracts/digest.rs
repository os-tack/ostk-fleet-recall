//! Typed SHA-256 identities with fixed, domain-separated preimages.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use sha2::{Digest as _, Sha256};

use super::{ContractError, ContractResult, canonical::CanonicalValue};

/// Raw SHA-256 bytes with one lowercase-hex wire representation.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    pub const ZERO: Self = Self([0; 32]);

    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("Sha256Digest")
            .field(&self.to_hex())
            .finish()
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

impl FromStr for Sha256Digest {
    type Err = ContractError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ContractError::InvalidDigest);
        }
        let decoded = hex::decode(value).map_err(|_| ContractError::InvalidDigest)?;
        let bytes: [u8; 32] = decoded
            .try_into()
            .map_err(|_| ContractError::InvalidDigest)?;
        Ok(Self(bytes))
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(D::Error::custom)
    }
}

/// Closed set of v1 digest preimage domains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestDomain {
    CanonicalProfile,
    TestVectorManifest,
    RegistryEntry,
    RegistryPackage,
    RegistryActivationStatement,
    RegistryActivationApproval,
    RegistryActivationReceipt,
    RegistryActivationStream,
    RegistryTestResult,
    ResourceLocator,
    EvidenceSourceFact,
    EvidenceSourceFactV2,
    EvidenceRepresentation,
    EvidenceRepresentationV2,
    EvidenceEnvelope,
    RelationFingerprint,
    NormativeBindingStatement,
    NormativeBindingReceipt,
    BootstrapSignerPolicy,
    BootstrapStatement,
    BootstrapReceipt,
    BootstrapAttestation,
    Epoch,
    Partition,
    AcceptedEvent,
    GenesisChain,
    AppendChain,
    Body,
}

impl DigestDomain {
    /// Immutable ASCII prefix included in every v1 digest preimage.
    pub const fn prefix(self) -> &'static str {
        match self {
            Self::CanonicalProfile => "ostk-canonical-profile-v1",
            Self::TestVectorManifest => "ostk-test-vector-manifest-v1",
            Self::RegistryEntry => "ostk-registry-entry-v1",
            Self::RegistryPackage => "ostk-registry-package-v1",
            Self::RegistryActivationStatement => "ostk-registry-activation-statement-v1",
            Self::RegistryActivationApproval => "ostk-registry-activation-approval-v1",
            Self::RegistryActivationReceipt => "ostk-registry-activation-receipt-v1",
            Self::RegistryActivationStream => "ostk-registry-activation-stream-v1",
            Self::RegistryTestResult => "ostk-registry-test-result-v1",
            Self::ResourceLocator => "ostk-resource-locator-v1",
            Self::EvidenceSourceFact => "ostk-source-fact-v1",
            Self::EvidenceSourceFactV2 => "ostk-source-fact-v2",
            Self::EvidenceRepresentation => "ostk-representation-v1",
            Self::EvidenceRepresentationV2 => "ostk-representation-v2",
            Self::EvidenceEnvelope => "ostk-evidence-envelope-v1",
            Self::RelationFingerprint => "ostk-relation-fingerprint-v1",
            Self::NormativeBindingStatement => "ostk-normative-binding-statement-v1",
            Self::NormativeBindingReceipt => "ostk-normative-binding-receipt-v1",
            Self::BootstrapSignerPolicy => "ostk-bootstrap-signer-policy-v1",
            Self::BootstrapStatement => "ostk-bootstrap-statement-v1",
            Self::BootstrapReceipt => "ostk-bootstrap-receipt-v1",
            Self::BootstrapAttestation => "ostk-bootstrap-attestation-v1",
            Self::Epoch => "ostk-log-epoch-v1",
            Self::Partition => "ostk-log-partition-v1",
            Self::AcceptedEvent => "ostk-accepted-event-v1",
            Self::GenesisChain => "ostk-genesis-chain-v1",
            Self::AppendChain => "ostk-append-chain-v1",
            Self::Body => "ostk-body-v1",
        }
    }
}

/// Hash one exact byte string under a fixed domain.
pub fn domain_separated_digest(domain: DigestDomain, bytes: &[u8]) -> Sha256Digest {
    let mut hash = Sha256::new();
    hash.update(domain.prefix().as_bytes());
    hash.update([0]);
    hash.update(bytes);
    Sha256Digest::from_bytes(hash.finalize().into())
}

/// Hash unambiguous length-framed parts under a fixed domain.
pub fn framed_digest(domain: DigestDomain, parts: &[&[u8]]) -> Sha256Digest {
    let mut hash = Sha256::new();
    hash.update(domain.prefix().as_bytes());
    hash.update([0]);
    for part in parts {
        hash.update(u64::try_from(part.len()).unwrap_or(u64::MAX).to_be_bytes());
        hash.update(part);
    }
    Sha256Digest::from_bytes(hash.finalize().into())
}

/// Hash one canonical JSON value under a fixed domain.
pub fn digest_canonical(
    domain: DigestDomain,
    value: &CanonicalValue,
) -> ContractResult<Sha256Digest> {
    let bytes = super::canonical::canonical_bytes(value)?;
    Ok(domain_separated_digest(domain, &bytes))
}

/// Body identity uses exact bytes and explicit byte length, not JSON framing.
pub fn body_digest(bytes: &[u8]) -> Sha256Digest {
    let mut hash = Sha256::new();
    hash.update(DigestDomain::Body.prefix().as_bytes());
    hash.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    hash.update(bytes);
    Sha256Digest::from_bytes(hash.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_wire_form_is_strict_lowercase_hex() {
        let digest = domain_separated_digest(DigestDomain::RegistryPackage, b"{}");
        assert_eq!(digest.to_string().len(), 64);
        assert_eq!(digest.to_string().parse::<Sha256Digest>().unwrap(), digest);
        assert!(
            digest
                .to_string()
                .to_uppercase()
                .parse::<Sha256Digest>()
                .is_err()
        );
        assert!("00".parse::<Sha256Digest>().is_err());
    }

    #[test]
    fn domains_and_framing_are_not_interchangeable() {
        let package = domain_separated_digest(DigestDomain::RegistryPackage, b"same");
        let entry = domain_separated_digest(DigestDomain::RegistryEntry, b"same");
        assert_ne!(package, entry);
        assert_ne!(
            framed_digest(DigestDomain::Partition, &[b"ab", b"c"]),
            framed_digest(DigestDomain::Partition, &[b"a", b"bc"])
        );
    }

    #[test]
    fn body_identity_commits_to_length_and_exact_bytes() {
        assert_eq!(body_digest(b"same"), body_digest(b"same"));
        assert_ne!(body_digest(b"same"), body_digest(b"same\n"));
    }
}
