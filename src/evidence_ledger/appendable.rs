//! The only way to reach the general accepted-event append seam.
//!
//! An [`AppendableAcceptedEvent`] carries exactly the row the evidence ledger
//! stores plus the semantic bindings the append transaction must re-check. It
//! is constructible only from a contract-validated Stage-4 statement whose own
//! registry-head binding equals the supplied [`WriterAuthorityWitness`], so no
//! caller can reach the ledger with a payload-selected kind, scope, shard key,
//! or head (EVID-04, ADR 0002 D4).
//!
//! # Governance kinds are unconstructible
//!
//! [`AcceptedEventKindV1`] is a closed three-variant enum and `event_kind` is
//! derived from the variant, never from caller input. There is no variant for
//! `control.bootstrap.accepted`, `registry.genesis.activated`, or
//! `registry.successor.activated`, and no constructor accepts a free-form kind
//! string, so a governance append cannot be *expressed* in this crate — a
//! compile error, not a runtime check. Migration 0018's
//! `memory_evidence_event_governance_exclusion` CHECK and the D2 grant boundary
//! are the two independent backstops behind it (ADR 0002 D1).

use crate::memory_contracts::ContractError;
use crate::memory_contracts::bootstrap::ConsistencyPartitionKeyV1;
use crate::memory_contracts::canonical::encode_canonical;
use crate::memory_contracts::common::{AuthenticatedProjectScopeV1, ContractId, HexBytes};
use crate::memory_contracts::digest::Sha256Digest;
use crate::memory_contracts::evidence::AcceptedEventId;
use crate::memory_contracts::evidence_v2::{
    EvidenceStatementV2, StructurallyResolvedConnectorSchemaV2,
};
use crate::memory_contracts::quarantine::MAX_ATTEMPT_COUNT;
use crate::memory_contracts::registry::RegistryHeadV1;
use crate::memory_contracts::relation::{
    AdmittedRelationAttestation, RelationAttestationEventV1, VerifiedRelationBasis,
};
use crate::memory_contracts::remember_v2::{
    AdmittedRememberStatementV2, RememberAcceptedStatementV2,
};

use super::error::{EvidenceAppendError, EvidenceAppendResult, WitnessMismatchKind};
use super::witness::WriterAuthorityWitness;

/// Closed set of general accepted-event kinds the evidence ledger admits.
///
/// Adding a kind is a deliberate edit here plus a matching `event_kind` string;
/// there is no open string path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AcceptedEventKindV1 {
    /// `evidence.accepted` — one admitted [`EvidenceStatementV2`].
    Evidence,
    /// `relation.attestation.accepted` — one admitted relation attestation.
    RelationAttestation,
    /// `memory.claim.accepted` — one admitted remember assertion.
    MemoryClaim,
}

impl AcceptedEventKindV1 {
    /// The exact `event_kind` string stored in `memory_evidence_events`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Evidence => "evidence.accepted",
            Self::RelationAttestation => "relation.attestation.accepted",
            Self::MemoryClaim => "memory.claim.accepted",
        }
    }

    /// How this kind's `semantic_object_digest` participates in replay
    /// classification. See [`SemanticIdentityRuleV1`].
    #[must_use]
    pub const fn semantic_identity_rule(self) -> SemanticIdentityRuleV1 {
        match self {
            Self::Evidence => SemanticIdentityRuleV1::UniquePreimage,
            Self::RelationAttestation | Self::MemoryClaim => SemanticIdentityRuleV1::Cumulative,
        }
    }
}

/// Per-kind meaning of `semantic_object_digest` during replay classification.
///
/// EVENT-01 states the rule for evidence literally: *"Different canonical bytes
/// under the same source-fact and representation identity are quarantined as an
/// integrity collision."* That is [`Self::UniquePreimage`], with the
/// representation key as the digest (a representation identity already commits
/// to its source-fact ID, so the pair is covered by the one digest).
///
/// Relation attestations and remember assertions are deliberately
/// [`Self::Cumulative`]: REL-01 makes relation state a projection over an
/// append-only stream of many attestations of one edge, and two actors may
/// legitimately assert the same proposition. Quarantining the second event
/// would suppress genuine, independent evidence, so for those kinds the stored
/// digest is a projector coordinate (relation fingerprint / semantic claim
/// fingerprint) and only exact-event-ID byte divergence is an integrity fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SemanticIdentityRuleV1 {
    /// At most one accepted event may exist per `semantic_object_digest`.
    UniquePreimage,
    /// Many accepted events may share one `semantic_object_digest`.
    Cumulative,
}

/// Connector-delivery metadata required to write a bounded quarantine receipt.
///
/// An `evidence.accepted` append may end in a `W0-QUAR` dead-letter row, and
/// [`crate::memory_contracts::quarantine::QuarantineRecordV1`] requires the
/// authenticated connector principal/instance, the transport delivery ID, and
/// the attempt count. These are supplied by trusted ingress, never parsed from
/// the delivery payload (EVID-04).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceDeliveryContextV1 {
    /// Authenticated connector principal.
    pub connector_principal_id: ContractId,
    /// Authenticated connector instance.
    pub connector_instance_id: ContractId,
    /// Bounded transport delivery ID (at most 64 bytes).
    pub transport_delivery_id: HexBytes,
    /// One-based delivery attempt counter.
    pub attempt_count: u32,
}

/// The evidence-only identity pair EVENT-01 names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvidenceIdentityLinks {
    pub source_fact_id: Sha256Digest,
    pub representation_key: Sha256Digest,
}

/// A contract-admitted accepted event ready for exactly one physical append.
///
/// Cloning is cheap enough for the retry loop and does not weaken the
/// construction gate: every clone still descends from an admitted statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendableAcceptedEvent {
    kind: AcceptedEventKindV1,
    event_kind: ContractId,
    event_schema_version: u32,
    canonical_event: Vec<u8>,
    accepted_event_id: AcceptedEventId,
    semantic_object_digest: Sha256Digest,
    consistency: ConsistencyPartitionKeyV1,
    scope: AuthenticatedProjectScopeV1,
    evidence_identity: Option<EvidenceIdentityLinks>,
    delivery: Option<EvidenceDeliveryContextV1>,
}

impl AppendableAcceptedEvent {
    /// Admit one `evidence.accepted` statement for append.
    ///
    /// `connector` must already have been resolved from the *active* registry
    /// package by the evidence ingress stage (`W1-EVID`); this seam proves only
    /// the structural closure between the statement and that connector entry,
    /// derives the registry-controlled consistency key from it, and binds the
    /// statement to `witness`.
    pub fn evidence(
        statement: &EvidenceStatementV2,
        connector: &StructurallyResolvedConnectorSchemaV2,
        delivery: EvidenceDeliveryContextV1,
        witness: &WriterAuthorityWitness,
    ) -> EvidenceAppendResult<Self> {
        statement.validate_against_structural_connector(connector)?;
        require_bound(&statement.scope, &statement.registry_head.head, witness)?;
        // Bound the delivery counter here rather than discovering it inside the
        // append transaction, where a quarantine record would fail to validate.
        if delivery.attempt_count == 0 || delivery.attempt_count > MAX_ATTEMPT_COUNT {
            return Err(EvidenceAppendError::Contract(ContractError::Schema(
                "evidence delivery attempt count is outside the quarantine-record bound".into(),
            )));
        }
        Ok(Self {
            kind: AcceptedEventKindV1::Evidence,
            event_kind: require_kind(&statement.event_kind, AcceptedEventKindV1::Evidence)?,
            event_schema_version: statement.schema_version,
            canonical_event: encode_canonical(statement)?,
            accepted_event_id: statement.accepted_event_id()?,
            // EVENT-01's identity: the representation key already commits to
            // the source-fact ID through `RepresentationIdentityV2`.
            semantic_object_digest: statement.representation_key.digest(),
            consistency: statement.consistency_partition_key(connector)?,
            scope: statement.scope.clone(),
            evidence_identity: Some(EvidenceIdentityLinks {
                source_fact_id: statement.source_fact_id.digest(),
                representation_key: statement.representation_key.digest(),
            }),
            delivery: Some(delivery),
        })
    }

    /// Admit one `relation.attestation.accepted` event for append.
    ///
    /// The relation admission stage (`W1-REL`) owns proving scope, actor,
    /// proof closure, referenced evidence, and supersession authorization; once
    /// it can mint an [`AdmittedRelationAttestation`] or
    /// [`VerifiedRelationBasis`], prefer
    /// [`Self::admitted_relation_attestation`] or
    /// [`Self::verified_relation_basis`], which delegate here. Those contract
    /// typestates currently expose only `#[cfg(test)]` constructors, so this
    /// event-plus-witness entry point is the production admission seam and is
    /// deliberately *not* a way to bypass one that exists.
    pub fn relation_attestation(
        event: &RelationAttestationEventV1,
        witness: &WriterAuthorityWitness,
    ) -> EvidenceAppendResult<Self> {
        event.validate_shape()?;
        require_bound(&event.scope, &event.edge.registry.head, witness)?;
        Ok(Self {
            kind: AcceptedEventKindV1::RelationAttestation,
            event_kind: require_kind(&event.event_kind, AcceptedEventKindV1::RelationAttestation)?,
            event_schema_version: event.schema_version,
            canonical_event: encode_canonical(event)?,
            accepted_event_id: event.accepted_event_id()?,
            // The projector coordinate, not a uniqueness key: REL-01 expects
            // many attestations per fingerprint.
            semantic_object_digest: event.relation_fingerprint.digest(),
            consistency: event.edge.consistency_partition_key()?,
            scope: event.scope.clone(),
            evidence_identity: None,
            delivery: None,
        })
    }

    /// Admit one `memory.claim.accepted` statement for append (ADR 0002 D3).
    pub fn memory_claim(
        statement: &RememberAcceptedStatementV2,
        witness: &WriterAuthorityWitness,
    ) -> EvidenceAppendResult<Self> {
        statement.validate_shape()?;
        require_bound(&statement.scope, &statement.registry.head, witness)?;
        Ok(Self {
            kind: AcceptedEventKindV1::MemoryClaim,
            event_kind: require_kind(&statement.event_kind, AcceptedEventKindV1::MemoryClaim)?,
            event_schema_version: statement.schema_version,
            canonical_event: encode_canonical(statement)?,
            accepted_event_id: statement.accepted_event_id()?,
            // The proposition coordinate. Two actors may legitimately assert
            // the same claim, so this is cumulative, not unique.
            semantic_object_digest: statement.claim_fingerprint.digest(),
            consistency: statement.consistency_partition_key()?,
            scope: statement.scope.clone(),
            evidence_identity: None,
            delivery: None,
        })
    }

    /// Admit a declared or inferred relation attestation from its capability.
    pub fn admitted_relation_attestation(
        attestation: &AdmittedRelationAttestation,
        witness: &WriterAuthorityWitness,
    ) -> EvidenceAppendResult<Self> {
        Self::relation_attestation(attestation.event(), witness)
    }

    /// Admit a provider-attested or verifier-result attestation from its
    /// capability.
    pub fn verified_relation_basis(
        basis: &VerifiedRelationBasis,
        witness: &WriterAuthorityWitness,
    ) -> EvidenceAppendResult<Self> {
        Self::relation_attestation(basis.event(), witness)
    }

    /// Admit a remember assertion from its capability.
    pub fn admitted_memory_claim(
        admitted: &AdmittedRememberStatementV2,
        witness: &WriterAuthorityWitness,
    ) -> EvidenceAppendResult<Self> {
        Self::memory_claim(admitted.statement(), witness)
    }

    /// Which of the three Stage-4 kinds this is.
    #[must_use]
    pub const fn kind(&self) -> AcceptedEventKindV1 {
        self.kind
    }

    /// The `event_kind` string stored with the row.
    #[must_use]
    pub const fn event_kind(&self) -> &ContractId {
        &self.event_kind
    }

    /// The contract-declared schema version of the accepted statement.
    #[must_use]
    pub const fn event_schema_version(&self) -> u32 {
        self.event_schema_version
    }

    /// Exact canonical accepted-event bytes.
    #[must_use]
    pub fn canonical_event(&self) -> &[u8] {
        &self.canonical_event
    }

    /// Semantic accepted-event identity, as the kind's contract defines it.
    #[must_use]
    pub const fn accepted_event_id(&self) -> AcceptedEventId {
        self.accepted_event_id
    }

    /// Per-kind semantic object coordinate. See [`SemanticIdentityRuleV1`].
    #[must_use]
    pub const fn semantic_object_digest(&self) -> Sha256Digest {
        self.semantic_object_digest
    }

    /// Registry-controlled consistency family and logical key.
    #[must_use]
    pub const fn consistency(&self) -> &ConsistencyPartitionKeyV1 {
        &self.consistency
    }

    /// Semantic scope copied from the admitted statement.
    #[must_use]
    pub const fn scope(&self) -> &AuthenticatedProjectScopeV1 {
        &self.scope
    }

    /// Replay classification rule for this kind.
    #[must_use]
    pub const fn semantic_identity_rule(&self) -> SemanticIdentityRuleV1 {
        self.kind.semantic_identity_rule()
    }

    pub(crate) const fn evidence_identity(&self) -> Option<EvidenceIdentityLinks> {
        self.evidence_identity
    }

    pub(crate) const fn delivery(&self) -> Option<&EvidenceDeliveryContextV1> {
        self.delivery.as_ref()
    }
}

/// Require the statement's own head binding and scope to be the witnessed ones.
fn require_bound(
    scope: &AuthenticatedProjectScopeV1,
    head: &RegistryHeadV1,
    witness: &WriterAuthorityWitness,
) -> EvidenceAppendResult<()> {
    if scope != witness.semantic_scope() {
        return Err(EvidenceAppendError::StatementAuthority(
            WitnessMismatchKind::ContractNamespaces,
        ));
    }
    if head.activation_id != witness.head().activation_id {
        return Err(EvidenceAppendError::StatementAuthority(
            WitnessMismatchKind::ActivationId,
        ));
    }
    if head.package_digest != witness.head().package_digest {
        return Err(EvidenceAppendError::StatementAuthority(
            WitnessMismatchKind::PackageDigest,
        ));
    }
    if head.activation_policy_digest != witness.head().activation_policy_digest {
        return Err(EvidenceAppendError::StatementAuthority(
            WitnessMismatchKind::ActivationPolicyDigest,
        ));
    }
    Ok(())
}

/// Defensively re-derive the stored `event_kind` from the closed enum.
///
/// The statement's own `validate_shape` already pins its kind string, so this
/// can only fail if a contract changed under us; it exists so the value written
/// to `memory_evidence_events` provably comes from [`AcceptedEventKindV1`].
fn require_kind(
    declared: &ContractId,
    kind: AcceptedEventKindV1,
) -> EvidenceAppendResult<ContractId> {
    if declared.as_str() != kind.as_str() {
        return Err(EvidenceAppendError::LedgerIntegrity(format!(
            "accepted statement declares event kind {declared} but was admitted as {}",
            kind.as_str()
        )));
    }
    Ok(ContractId::new(kind.as_str())?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepted_event_kinds_are_the_three_stage4_general_kinds() {
        let kinds = [
            AcceptedEventKindV1::Evidence,
            AcceptedEventKindV1::RelationAttestation,
            AcceptedEventKindV1::MemoryClaim,
        ];
        let labels: Vec<&str> = kinds.iter().map(|kind| kind.as_str()).collect();
        assert_eq!(
            labels,
            vec![
                "evidence.accepted",
                "relation.attestation.accepted",
                "memory.claim.accepted"
            ]
        );
        // Compile-time governance exclusion: the closed enum has no variant a
        // governance kind could name, so the strings below cannot be produced
        // by any constructor in this module. Uncommenting
        // `AcceptedEventKindV1::ControlBootstrap` is a compile error.
        for governance in [
            "control.bootstrap.accepted",
            "registry.genesis.activated",
            "registry.successor.activated",
        ] {
            assert!(!labels.contains(&governance));
        }
    }

    #[test]
    fn only_evidence_carries_the_unique_preimage_rule() {
        assert_eq!(
            AcceptedEventKindV1::Evidence.semantic_identity_rule(),
            SemanticIdentityRuleV1::UniquePreimage
        );
        assert_eq!(
            AcceptedEventKindV1::RelationAttestation.semantic_identity_rule(),
            SemanticIdentityRuleV1::Cumulative
        );
        assert_eq!(
            AcceptedEventKindV1::MemoryClaim.semantic_identity_rule(),
            SemanticIdentityRuleV1::Cumulative
        );
    }

    #[test]
    fn declared_kind_must_equal_the_admitted_kind() {
        let declared = ContractId::new("evidence.accepted").unwrap();
        assert!(require_kind(&declared, AcceptedEventKindV1::Evidence).is_ok());
        assert!(matches!(
            require_kind(&declared, AcceptedEventKindV1::MemoryClaim),
            Err(EvidenceAppendError::LedgerIntegrity(_))
        ));
    }
}
