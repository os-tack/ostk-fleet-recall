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

/// Closed set of versioned digest preimage domains.
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
    RegistrySuccessorActivationStatementV1,
    RegistrySuccessorActivationApprovalV1,
    RegistrySuccessorActivationReceiptV1,
    RegistryTestResult,
    GenesisSuccessorKeyBridgeV1,
    ResourceLocator,
    EvidenceSourceFact,
    EvidenceSourceFactV2,
    EvidenceRepresentation,
    EvidenceRepresentationV2,
    EvidenceEnvelope,
    RelationFingerprint,
    RememberClaimCoordinateV2,
    RememberSemanticClaimV2,
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
    // --- W0-REG domains ---
    /// W0-REG. Generation-2 registry composition manifest preimage.
    Generation2CompositionManifestV1,
    /// W0-REG. One closed `(kind, entry schema ID, entry schema version)` slot.
    RegistryBodySchemaSlotV1,
    /// W0-REG. Consolidation statement preimage for the consolidation lane.
    ConsolidationStatementV1,
    /// W0-REG. Consolidation receipt preimage for the consolidation lane.
    ConsolidationReceiptV1,
    /// W0-REG. Consolidation policy preimage for the consolidation lane.
    ConsolidationPolicyV1,
    /// REG (integrator, 2026-08-16). Exact authored summary-text bytes committed to by a
    /// consolidation receipt; enrichment never enters statement identity.
    ConsolidationSummaryEnrichmentV1,
    // --- W0-SUCC domains ---

    // --- W0-COVER domains ---

    // --- W0-CHUNK domains ---

    // --- W0-EPIS domains ---

    // --- W0-OBS domains ---

    // --- W0-ERASE domains ---

    // --- W0-LOG domains ---

    // --- W0-NORM domains ---

    // --- W0-QUAR domains ---

    // --- W0-TELEM domains ---

    // --- W0-CAUSE domains ---

    // --- W0-ACT domains ---
}

impl DigestDomain {
    /// Immutable ASCII prefix included in every domain-separated preimage.
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
            Self::RegistrySuccessorActivationStatementV1 => {
                "ostk-registry-successor-activation-statement-v1"
            }
            Self::RegistrySuccessorActivationApprovalV1 => {
                "ostk-registry-successor-activation-approval-v1"
            }
            Self::RegistrySuccessorActivationReceiptV1 => {
                "ostk-registry-successor-activation-receipt-v1"
            }
            Self::RegistryTestResult => "ostk-registry-test-result-v1",
            Self::GenesisSuccessorKeyBridgeV1 => "ostk-genesis-successor-key-bridge-v1",
            Self::ResourceLocator => "ostk-resource-locator-v1",
            Self::EvidenceSourceFact => "ostk-source-fact-v1",
            Self::EvidenceSourceFactV2 => "ostk-source-fact-v2",
            Self::EvidenceRepresentation => "ostk-representation-v1",
            Self::EvidenceRepresentationV2 => "ostk-representation-v2",
            Self::EvidenceEnvelope => "ostk-evidence-envelope-v1",
            Self::RelationFingerprint => "ostk-relation-fingerprint-v1",
            Self::RememberClaimCoordinateV2 => "ostk-remember-claim-coordinate-v2",
            Self::RememberSemanticClaimV2 => "ostk-remember-semantic-claim-v2",
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
            // --- W0-REG prefixes ---
            Self::Generation2CompositionManifestV1 => "ostk-generation2-composition-manifest-v1",
            Self::RegistryBodySchemaSlotV1 => "ostk-registry-body-schema-slot-v1",
            Self::ConsolidationStatementV1 => "ostk-consolidation-statement-v1",
            Self::ConsolidationReceiptV1 => "ostk-consolidation-receipt-v1",
            Self::ConsolidationPolicyV1 => "ostk-consolidation-policy-v1",
            Self::ConsolidationSummaryEnrichmentV1 => "ostk-consolidation-summary-enrichment-v1",
            // --- W0-SUCC prefixes ---

            // --- W0-COVER prefixes ---

            // --- W0-CHUNK prefixes ---

            // --- W0-EPIS prefixes ---

            // --- W0-OBS prefixes ---

            // --- W0-ERASE prefixes ---

            // --- W0-LOG prefixes ---

            // --- W0-NORM prefixes ---

            // --- W0-QUAR prefixes ---

            // --- W0-TELEM prefixes ---

            // --- W0-CAUSE prefixes ---

            // --- W0-ACT prefixes ---
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
