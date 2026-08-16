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
    /// Unsigned generic generation `N -> N+1` activation statement.
    RegistrySuccessorActivationStatementV2, // W0-SUCC
    /// One detached generic successor activation approval attestation.
    RegistrySuccessorActivationApprovalV2, // W0-SUCC
    /// Server-derived generic successor activation receipt and identity.
    RegistrySuccessorActivationReceiptV2, // W0-SUCC
    /// Unsigned statement selecting one member of an exact contested set.
    RegistryContestedResolutionStatementV1, // W0-SUCC
    /// One detached contested-set resolution approval attestation.
    RegistryContestedResolutionApprovalV1, // W0-SUCC
    /// Server-derived contested-set resolution receipt and identity.
    RegistryContestedResolutionReceiptV1, // W0-SUCC
    // W0-SUCC
    /// Immutable record of two or more incompatible successors of one head.
    RegistryContestedSetV1,
    // --- W0-COVER domains ---
    /// `CoverageReceiptV1` (COVER-01..03): connector/observer coverage receipts.
    CoverageReceipt,

    // --- W0-CHUNK domains ---
    /// W0-CHUNK. Chunk-occurrence identity preimage (source URI + parser key + spans).
    ChunkOccurrenceV1,
    /// W0-CHUNK. Parse-run manifest preimage (parser key + ordered occurrence IDs).
    ParseManifestV1,
    /// W0-CHUNK. Parser/extractor key preimage (artifact + version + configuration).
    ParserKeyV1,
    /// W0-CHUNK. Raw source-byte span preimage, distinct from extracted body identity.
    SourceSpanV1,
    /// W0-CHUNK. Supersession link between one predecessor and successor manifest.
    ManifestSupersessionV1,
    /// W0-CHUNK. Current-generation parser pointer, used in a CAS switch preimage.
    GenerationPointerV1,
    /// W0-CHUNK. Embedding identity preimage (input selector + model + tokenization).
    EmbeddingIdentityV1,
    /// W0-CHUNK. Protection-domain-keyed external storage identity preimage.
    StorageIdentityV1,
    // --- W0-EPIS domains ---
    /// Discrepancy-family fingerprint preimage (`DiscrepancyFamilyPreimageV1`). // W0-EPIS
    DiscrepancyFamilyV1, // W0-EPIS
    /// Discrepancy-episode fingerprint preimage (`DiscrepancyEpisodePreimageV1`). // W0-EPIS
    DiscrepancyEpisodeV1, // W0-EPIS
    /// Immutable discrepancy-detection envelope (`DiscrepancyEnvelopeV1`). // W0-EPIS
    DiscrepancyEnvelopeV1, // W0-EPIS
    /// Comparator-lineage identity (`ComparatorLineageV1`). // W0-EPIS
    ComparatorLineageV1, // W0-EPIS
    /// Append-only discrepancy lifecycle transition (`DiscrepancyLifecycleEventV1`). // W0-EPIS
    DiscrepancyLifecycleEventV1, // W0-EPIS

    // --- W0-OBS domains ---
    /// `ObserverAdmissionV2` body identity.
    ObserverAdmissionV2, // W0-OBS
    /// `ObserverRunReceiptV1` identity.
    ObserverRunReceiptV1, // W0-OBS
    /// `ObserverResultV1` content identity (separate from its accepted-event ID).
    ObserverResultV1, // W0-OBS
    /// `ObserverDerivationDisagreementV1` finding identity.
    ObserverDisagreementV1, // W0-OBS

                                 // --- W0-ERASE domains ---

    // --- W0-LOG domains ---
    /// W0-LOG. `SuccessorLogEpochV1` identity.
    LogEpochV2,
    /// W0-LOG. `EvidenceCompactionCheckpointV1` identity.
    EvidenceCompactionCheckpointV1,
    /// W0-LOG. `ProjectorCheckpointV1` identity; never accepted as evidence authority.
    ProjectorCheckpointV1,
    /// W0-LOG. `ArchiveSegmentManifestV1` identity.
    ArchiveSegmentManifestV1,
    /// W0-LOG. `CursorVectorBarrierV1` identity for cross-shard join projectors.
    CursorVectorV1,
    /// W0-LOG. `ProjectionGenerationV1` identity: one generation per closed barrier.
    ProjectionGenerationV1,
    /// W0-LOG. `ProjectionGenerationV1` record digest: names exactly one
    /// publication record (identity + barrier + `generation_sequence` +
    /// `supersedes`), unlike `ProjectionGenerationV1` above which deliberately
    /// coalesces every record sharing the same published facts. `supersedes`
    /// must point at a predecessor's digest under THIS domain, never the
    /// other one.
    ProjectionGenerationRecordV1, // W0-LOG

    // --- W0-NORM domains ---
    /// Unsigned `NormativeBindingProposalV2` statement preimage.
    NormativeBindingStatementV2,
    /// `NormativeActivationReceiptV2` preimage (eligibility/threshold/`SoD`).
    NormativeBindingReceiptV2,
    /// `NormativeLifecycleEventV1` preimage: activation, retirement,
    /// retraction, expiry, or supersession, each governed by active policy.
    NormativeLifecycleEventV1,
    /// `ContestedBindingV1` preimage for unorderable independently accepted
    /// or late/corrective normative evidence.
    NormativeContestedV1,
    // --- W0-QUAR domains ---
    /// Bounded dead-letter record for one rejected/quarantined delivery.
    QuarantineRecordV1,
    // --- W0-TELEM domains ---
    /// Bounded telemetry measurement receipt identity (RUN-01..03).
    MeasurementReceiptV1,
    /// SLO/rule evaluation identity, distinct from its cited receipts.
    SloEvaluationV1,
    /// Exemplar content identity and `deterministic_stratified_hash_v1`
    /// per-record ordering-key preimage.
    ExemplarSelectionV1,
    // --- W0-CAUSE domains ---
    CausalHypothesisV1,          // W0-CAUSE
    CausalMechanismCommitmentV1, // W0-CAUSE
    InterventionSupportV1,       // W0-CAUSE
    CausalRatificationV1,        // W0-CAUSE

    // --- W0-ACT domains ---
    /// `ActionProposalV1` immutable proposal digest (ACT-02).
    ActionProposalV1,
    /// `AuthorizationV1` authorization digest bound by an execution request (ACT-02).
    ActionAuthorizationV1,
    /// `ExecutionRequestV1` attempt identity: proposal + authorization + idempotency key (ACT-03).
    ActionAttemptV1,
    /// `ExecutionReceiptV1` receipt identity (ACT-03).
    ActionReceiptV1,
    /// `VerificationV1` verification identity (ACT-04).
    ActionVerificationV1,
    /// `ProviderAttestedRelationCandidateV2` admission-candidate identity (PROV-01, REL-01).
    RelationAdmissionV2,
    /// Full-`ExecutionAttemptV1` binding digest carried by
    /// `RevalidatedAuthorizationV1` (AUTH-03, ACT-03): distinct from
    /// [`Self::ActionAttemptV1`], which frames only the request-derived
    /// `AttemptIdV1` and is invariant across retries by design. This domain
    /// frames the *entire* canonical attempt — scope, profile, revalidated
    /// state/preconditions/timestamp, provider request ID, and started time
    /// — so `reconcile_receipt` can reject an attempt whose observational
    /// fields were swapped after revalidation even though it kept the same
    /// request (and therefore the same `AttemptIdV1`).
    ActionAttemptRevalidationV1,
    // --- W1 domains (evidence ledger, head witness, remember/evidence/relation runtime) ---
    /// W1-APPEND. Offset-zero chain digest of one lazily seeded evidence shard
    /// head, framed over the genesis log-epoch ID and the shard number.
    ///
    /// This domain is deliberately NOT [`DigestDomain::GenesisChain`]: the
    /// control ledger's genesis chain frames the bootstrap receipt digest, the
    /// epoch ID, and a `u16` shard, and its heads are seeded eagerly by the
    /// bootstrap ceremony. The evidence ledger's heads are seeded lazily by the
    /// appender inside the append transaction (ADR 0002 D1), so a head row is
    /// fully determined by `(epoch, shard)` and can grant no forgeable
    /// authority. Sharing one domain across the two ledgers would make an
    /// evidence offset-zero digest replayable as a control one.
    EvidenceGenesisChainV1, // W1-APPEND
    /// W1-IMPORT. Content-addressed digest of one `BootstrapManifestV1`
    /// enumeration of legacy `memory_chunks`/`memory_claims`/
    /// `memory_conflicts`/`memory_conflict_members`/`memory_mutation_receipts`
    /// rows. Distinct from [`DigestDomain::AcceptedEvent`], which frames the
    /// full `bootstrap.manifest.accepted` preimage (profile, scope, registry
    /// head, and this digest together); this domain frames only the sorted
    /// row enumeration itself.
    BootstrapManifestV1, // W1-IMPORT
}

impl DigestDomain {
    /// Immutable ASCII prefix included in every domain-separated preimage.
    // Integrator: DigestDomain is a closed set that grows one arm per merged
    // workstream; the union of all Wave-0/Wave-1 domains pushes this exhaustive
    // match past clippy's default line cap. One arm per domain is the intended
    // shape (no sub-dispatch), so allow the length here.
    #[allow(clippy::too_many_lines)]
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
            Self::RegistrySuccessorActivationStatementV2 => {
                "ostk-registry-successor-activation-statement-v2"
            } // W0-SUCC
            Self::RegistrySuccessorActivationApprovalV2 => {
                "ostk-registry-successor-activation-approval-v2"
            } // W0-SUCC
            Self::RegistrySuccessorActivationReceiptV2 => {
                "ostk-registry-successor-activation-receipt-v2"
            } // W0-SUCC
            Self::RegistryContestedResolutionStatementV1 => {
                "ostk-registry-contested-resolution-statement-v1"
            } // W0-SUCC
            Self::RegistryContestedResolutionApprovalV1 => {
                "ostk-registry-contested-resolution-approval-v1"
            } // W0-SUCC
            Self::RegistryContestedResolutionReceiptV1 => {
                "ostk-registry-contested-resolution-receipt-v1"
            } // W0-SUCC
            // W0-SUCC
            Self::RegistryContestedSetV1 => "ostk-registry-contested-set-v1",
            // --- W0-COVER prefixes ---
            Self::CoverageReceipt => "ostk-coverage-receipt-v1",

            // --- W0-CHUNK prefixes ---
            Self::ChunkOccurrenceV1 => "ostk-chunk-occurrence-v1",
            Self::ParseManifestV1 => "ostk-parse-manifest-v1",
            Self::ParserKeyV1 => "ostk-parser-key-v1",
            Self::SourceSpanV1 => "ostk-source-span-v1",
            Self::ManifestSupersessionV1 => "ostk-manifest-supersession-v1",
            Self::GenerationPointerV1 => "ostk-generation-pointer-v1",
            Self::EmbeddingIdentityV1 => "ostk-embedding-identity-v1",
            Self::StorageIdentityV1 => "ostk-storage-identity-v1",
            // --- W0-EPIS prefixes ---
            Self::DiscrepancyFamilyV1 => "ostk-discrepancy-family-v1",
            Self::DiscrepancyEpisodeV1 => "ostk-discrepancy-episode-v1",
            Self::DiscrepancyEnvelopeV1 => "ostk-discrepancy-envelope-v1",
            Self::ComparatorLineageV1 => "ostk-comparator-lineage-v1",
            Self::DiscrepancyLifecycleEventV1 => "ostk-discrepancy-lifecycle-event-v1",
            // --- W0-OBS prefixes ---
            Self::ObserverAdmissionV2 => "ostk-observer-admission-v2", // W0-OBS
            Self::ObserverRunReceiptV1 => "ostk-observer-run-receipt-v1", // W0-OBS
            Self::ObserverResultV1 => "ostk-observer-result-v1",       // W0-OBS
            Self::ObserverDisagreementV1 => "ostk-observer-disagreement-v1", // W0-OBS

            // --- W0-ERASE prefixes ---

            // --- W0-LOG prefixes ---
            Self::LogEpochV2 => "ostk-log-epoch-v2",
            Self::EvidenceCompactionCheckpointV1 => "ostk-evidence-compaction-checkpoint-v1",
            Self::ProjectorCheckpointV1 => "ostk-projector-checkpoint-v1",
            Self::ArchiveSegmentManifestV1 => "ostk-archive-segment-manifest-v1",
            Self::CursorVectorV1 => "ostk-cursor-vector-v1",
            Self::ProjectionGenerationV1 => "ostk-projection-generation-v1",
            Self::ProjectionGenerationRecordV1 => "ostk-projection-generation-record-v1", // W0-LOG
            // --- W0-NORM prefixes ---
            Self::NormativeBindingStatementV2 => "ostk-normative-binding-statement-v2",
            Self::NormativeBindingReceiptV2 => "ostk-normative-binding-receipt-v2",
            Self::NormativeLifecycleEventV1 => "ostk-normative-lifecycle-event-v1",
            Self::NormativeContestedV1 => "ostk-normative-contested-v1",
            // --- W0-QUAR prefixes ---
            Self::QuarantineRecordV1 => "ostk-quarantine-record-v1",
            // --- W0-TELEM prefixes ---
            Self::MeasurementReceiptV1 => "ostk-measurement-receipt-v1",
            Self::SloEvaluationV1 => "ostk-slo-evaluation-v1",
            Self::ExemplarSelectionV1 => "ostk-exemplar-selection-v1",
            // --- W0-CAUSE prefixes ---
            Self::CausalHypothesisV1 => "ostk-causal-hypothesis-v1",
            Self::CausalMechanismCommitmentV1 => "ostk-causal-mechanism-commitment-v1",
            Self::InterventionSupportV1 => "ostk-intervention-support-v1",
            Self::CausalRatificationV1 => "ostk-causal-ratification-v1",
            // --- W0-ACT prefixes ---
            Self::ActionProposalV1 => "ostk-action-proposal-v1",
            Self::ActionAuthorizationV1 => "ostk-action-authorization-v1",
            Self::ActionAttemptV1 => "ostk-action-attempt-v1",
            Self::ActionReceiptV1 => "ostk-action-receipt-v1",
            Self::ActionVerificationV1 => "ostk-action-verification-v1",
            Self::RelationAdmissionV2 => "ostk-relation-admission-v2",
            Self::ActionAttemptRevalidationV1 => "ostk-action-attempt-revalidation-v1",
            // --- W1 prefixes ---
            Self::EvidenceGenesisChainV1 => "ostk-evidence-genesis-chain-v1", // W1-APPEND
            Self::BootstrapManifestV1 => "ostk-bootstrap-manifest-v1",        // W1-IMPORT
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
