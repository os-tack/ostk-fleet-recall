//! Successor log epoch, evidence-compaction and projector checkpoints,
//! archive segments, and cross-shard replay barriers.
//!
//! Invariants enforced here: **REPLAY-01** (replaying accepted events with
//! the same registry/projector versions yields identical semantic
//! identities; nondeterministic enrichment cannot affect them), **REPLAY-02**
//! (every projector advances its own cursor atomically with that stage's
//! complete durable output), **EVENT-03** (evidence is accepted before or
//! atomically with its projection; this module never fakes the append
//! seam), and **EVID-01** (the accepted envelope is append-only; a
//! compaction checkpoint accounts for retained evidence and tombstones, it
//! never authorizes silently discarding either).
//!
//! A log epoch's shard count and partition recipe are fixed at genesis
//! (`bootstrap::GenesisLogEpochV1`). Changing either mints a *successor* log
//! epoch: a new deterministic partition-hash recipe bound to its exact
//! predecessor epoch and the closed shard-head vector the predecessor was
//! fenced at ([`SuccessorLogEpochV1`]). Evidence identity
//! (`evidence::AcceptedEventId`) never contains an epoch, shard, or offset —
//! only `bootstrap::AppendPositionV1` does — and every contract in this
//! module is built so a physical coordinate cannot leak into a semantic
//! digest: [`LostFenceRetryV1`] carries exactly one `accepted_event_id`
//! field shared by both the losing and the retried physical position, so
//! "same identity, different position" is a structural guarantee rather than
//! a convention any caller could violate.
//!
//! Two checkpoint kinds are kept nominally distinct so neither can be
//! presented as the other: [`EvidenceCompactionCheckpointV1`] is a
//! projector-neutral evidence-authority anchor that may anchor a
//! [`ReplayHorizonV1`] only through [`VerifiedReplayAnchorV1`] — the only
//! constructor for that proof accepts an `&EvidenceCompactionCheckpointV1`
//! and nothing else compiles in its place — while [`ProjectorCheckpointV1`]
//! is a performance cache valid only for one exact projector and registry
//! digest and can never anchor a replay horizon. Their canonical field sets
//! also do not overlap, so decoding one artifact's bytes as the other type
//! fails closed at the schema boundary, not merely by convention.
//!
//! Wave-0 stub owned by W0-LOG; the owning workstream replaces this file.
//! No runtime authority is implied by an empty module.

use serde::{Deserialize, Serialize};

use super::{
    ContractError, ContractResult,
    bootstrap::{
        AppendPositionV1, CommittedOffsetV1, ConsistencyPartitionKeyV1, EpochId, PartitionRecipeV1,
    },
    canonical::encode_canonical,
    common::{AuthenticatedProjectScopeV1, CanonicalTimestamp, ContractId, ProfileReferenceV1},
    digest::{DigestDomain, Sha256Digest, domain_separated_digest, framed_digest},
    evidence::AcceptedEventId,
};

const LEDGER_EPOCH_SCHEMA_VERSION: u32 = 1;
/// Mirrors `bootstrap::MAX_SHARDS`; kept as a separate constant because that
/// one is private to its own module.
const MAX_VECTOR_SHARDS: usize = 4_096;

// ---------------------------------------------------------------------
// Closed shard-head vectors
// ---------------------------------------------------------------------

/// One shard's closed state at a fence: its last committed offset and the
/// append-chain digest that offset produced.
///
/// Both are physical facts about the predecessor epoch; neither ever enters
/// a semantic evidence identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClosedShardHeadV1 {
    pub shard: u16,
    pub last_committed_offset: CommittedOffsetV1,
    pub chain_digest: Sha256Digest,
}

/// Sorted, unique-by-shard closure of every shard head in one epoch.
///
/// Vector identity is a pure function of the sorted entries: replaying the
/// same tail through a different shard schedule, or observing shard heads
/// arrive in a different order, reproduces the same vector (REPLAY-01).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClosedHeadVectorV1 {
    pub schema_version: u32,
    pub epoch_id: EpochId,
    pub heads: Vec<ClosedShardHeadV1>,
}

impl ClosedHeadVectorV1 {
    pub fn validate(&self) -> ContractResult<()> {
        if self.schema_version != LEDGER_EPOCH_SCHEMA_VERSION
            || self.heads.is_empty()
            || self.heads.len() > MAX_VECTOR_SHARDS
        {
            return Err(ContractError::Schema("invalid closed head vector".into()));
        }
        if !self
            .heads
            .windows(2)
            .all(|pair| pair[0].shard < pair[1].shard)
        {
            return Err(ContractError::NonCanonicalSet { field: "heads" });
        }
        Ok(())
    }

    /// Reject a vector that closes a shard number the epoch's own recipe
    /// never assigned.
    pub fn validate_bounded_by(&self, shard_count: u16) -> ContractResult<()> {
        self.validate()?;
        if self.heads.iter().any(|head| head.shard >= shard_count) {
            return Err(ContractError::Schema(
                "closed head vector names a shard outside its epoch".into(),
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------
// Successor log epoch and activation fence
// ---------------------------------------------------------------------

/// What one epoch cutover commits to: the exact predecessor epoch and the
/// closed vector every one of its shard heads was fenced at.
///
/// Folding both into one nested struct (rather than two independent
/// top-level fields) makes "the closed vector belongs to this predecessor" a
/// schema-level fact instead of a cross-field convention two
/// independently-mutable fields could drift apart on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpochActivationBindingV1 {
    pub schema_version: u32,
    pub predecessor_epoch_id: EpochId,
    pub closed_predecessor_head: ClosedHeadVectorV1,
}

impl EpochActivationBindingV1 {
    pub fn validate(&self) -> ContractResult<()> {
        if self.schema_version != LEDGER_EPOCH_SCHEMA_VERSION {
            return Err(ContractError::Schema(
                "invalid epoch activation binding".into(),
            ));
        }
        self.closed_predecessor_head.validate()?;
        if self.closed_predecessor_head.epoch_id != self.predecessor_epoch_id {
            return Err(ContractError::Schema(
                "closed head vector does not close the named predecessor epoch".into(),
            ));
        }
        Ok(())
    }
}

/// A new deterministic partition-hash recipe minted because the shard count
/// or seed changed.
///
/// Binds its exact predecessor epoch and the closed vector that predecessor
/// was fenced at; evidence IDs accepted under either epoch are unaffected by
/// this cutover.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuccessorLogEpochV1 {
    pub schema_version: u32,
    pub profile: ProfileReferenceV1,
    pub scope: AuthenticatedProjectScopeV1,
    pub partition_recipe: PartitionRecipeV1,
    pub activation_binding: EpochActivationBindingV1,
}

impl SuccessorLogEpochV1 {
    pub fn validate(&self) -> ContractResult<()> {
        self.profile.validate()?;
        self.partition_recipe.validate()?;
        self.activation_binding.validate()?;
        if self.schema_version != LEDGER_EPOCH_SCHEMA_VERSION {
            return Err(ContractError::Schema("invalid successor log epoch".into()));
        }
        Ok(())
    }

    pub const fn predecessor_epoch_id(&self) -> EpochId {
        self.activation_binding.predecessor_epoch_id
    }

    pub const fn closed_predecessor_head(&self) -> &ClosedHeadVectorV1 {
        &self.activation_binding.closed_predecessor_head
    }

    /// `SHA-256("ostk-log-epoch-v2" || 0x00 || canonical_bytes(self))`.
    pub fn epoch_id(&self) -> ContractResult<EpochId> {
        self.validate()?;
        Ok(EpochId::from_digest(domain_separated_digest(
            DigestDomain::LogEpochV2,
            &encode_canonical(self)?,
        )))
    }
}

/// Deterministic shard selection under a successor epoch.
///
/// Mirrors `bootstrap::partition_for_epoch`'s math exactly, so partition
/// assignment stays reproducible across epoch generations under the shared,
/// domain-separated `Partition` preimage; only the epoch identity bytes fed
/// into that hash change from one generation to the next.
pub fn partition_for_successor_epoch(
    epoch: &SuccessorLogEpochV1,
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

/// One atomic activation transaction: fences every predecessor shard head at
/// `successor_epoch.closed_predecessor_head()` and admits the successor
/// epoch in the same transaction.
///
/// A concurrent append that still targets the now-fenced predecessor epoch
/// must be rejected and retried under the successor epoch (see
/// [`LostFenceRetryV1`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpochFenceV1 {
    pub schema_version: u32,
    pub successor_epoch: SuccessorLogEpochV1,
}

impl EpochFenceV1 {
    pub fn validate(&self) -> ContractResult<()> {
        if self.schema_version != LEDGER_EPOCH_SCHEMA_VERSION {
            return Err(ContractError::Schema("invalid epoch fence".into()));
        }
        self.successor_epoch.validate()?;
        Ok(())
    }

    pub const fn predecessor_epoch_id(&self) -> EpochId {
        self.successor_epoch.predecessor_epoch_id()
    }

    pub fn successor_epoch_id(&self) -> ContractResult<EpochId> {
        self.successor_epoch.epoch_id()
    }

    /// The pure fencing rule: an append still coordinate-bound to the
    /// predecessor epoch after this fence has committed can never succeed
    /// there — every shard head in that epoch is already closed.
    pub fn reject_append_after_fence(&self, position: &AppendPositionV1) -> ContractResult<()> {
        if position.epoch_id == self.predecessor_epoch_id() {
            return Err(ContractError::Schema(
                "append targets a shard fenced by a newer log epoch".into(),
            ));
        }
        Ok(())
    }
}

/// A losing append under the fenced predecessor epoch, and the retry that
/// must supersede it.
///
/// `accepted_event_id` is a single shared field — the type cannot even
/// represent two different semantic identities for a losing/retry pair, so
/// "same event ID, different physical position" is structural, not
/// conventional (EVENT-03).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LostFenceRetryV1 {
    pub schema_version: u32,
    pub accepted_event_id: AcceptedEventId,
    pub consistency_partition_key: ConsistencyPartitionKeyV1,
    pub losing_position: AppendPositionV1,
    pub retry_position: AppendPositionV1,
}

impl LostFenceRetryV1 {
    pub fn validate_against(&self, fence: &EpochFenceV1) -> ContractResult<()> {
        if self.schema_version != LEDGER_EPOCH_SCHEMA_VERSION {
            return Err(ContractError::Schema("invalid lost-fence retry".into()));
        }
        fence.validate()?;
        if self.losing_position.epoch_id != fence.predecessor_epoch_id() {
            return Err(ContractError::Schema(
                "losing position does not target the fenced predecessor epoch".into(),
            ));
        }
        let successor_epoch_id = fence.successor_epoch_id()?;
        if self.retry_position.epoch_id != successor_epoch_id {
            return Err(ContractError::Schema(
                "retry position does not target the successor epoch".into(),
            ));
        }
        if self.losing_position.shard == self.retry_position.shard
            && self.losing_position.committed_offset == self.retry_position.committed_offset
        {
            return Err(ContractError::Schema(
                "retry must occupy a different physical position than the losing append".into(),
            ));
        }
        let expected_shard =
            partition_for_successor_epoch(&fence.successor_epoch, &self.consistency_partition_key)?;
        if self.retry_position.shard != expected_shard {
            return Err(ContractError::Schema(
                "retry position uses the wrong successor shard for its consistency key".into(),
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------
// Evidence-compaction checkpoint (evidence authority)
// ---------------------------------------------------------------------

/// Everything an independent verifier reproduces before a checkpoint may
/// anchor a replay horizon.
///
/// The replay-verification receipt is deliberately excluded from this
/// preimage so a verifier can compute `core_digest` without first trusting
/// the receipt it is about to produce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceCompactionCheckpointCoreV1 {
    pub schema_version: u32,
    pub epoch_id: EpochId,
    pub retained_evidence_manifest_root: Sha256Digest,
    pub tombstone_set_root: Sha256Digest,
    pub closed_shard_positions: ClosedHeadVectorV1,
    pub append_chain_root: Sha256Digest,
    pub segment_manifest_root: Sha256Digest,
    pub retained_snapshot_digest: Sha256Digest,
}

impl EvidenceCompactionCheckpointCoreV1 {
    pub fn validate(&self) -> ContractResult<()> {
        if self.schema_version != LEDGER_EPOCH_SCHEMA_VERSION {
            return Err(ContractError::Schema(
                "invalid evidence-compaction checkpoint core".into(),
            ));
        }
        self.closed_shard_positions.validate()?;
        if self.closed_shard_positions.epoch_id != self.epoch_id {
            return Err(ContractError::Schema(
                "checkpoint core closed-shard positions do not match its epoch".into(),
            ));
        }
        Ok(())
    }

    /// `SHA-256("ostk-evidence-compaction-checkpoint-v1" || 0x00 || canonical_bytes(self))`.
    pub fn core_digest(&self) -> ContractResult<Sha256Digest> {
        self.validate()?;
        Ok(domain_separated_digest(
            DigestDomain::EvidenceCompactionCheckpointV1,
            &encode_canonical(self)?,
        ))
    }
}

/// Independent proof that a checkpoint core reflects a complete replay: the
/// verifier reproduces `core_digest` from the evidence authority, never from
/// the checkpoint's own bytes.
///
/// Reused for both an evidence-compaction checkpoint and an archive move;
/// either use binds `verified_subject_digest` to the exact subject digest
/// being verified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayVerificationReceiptV1 {
    pub schema_version: u32,
    pub verifier_id: ContractId,
    pub verified_subject_digest: Sha256Digest,
    pub verified_at: CanonicalTimestamp,
}

impl ReplayVerificationReceiptV1 {
    pub fn validate(&self) -> ContractResult<()> {
        if self.schema_version != LEDGER_EPOCH_SCHEMA_VERSION {
            return Err(ContractError::Schema(
                "invalid replay-verification receipt".into(),
            ));
        }
        Ok(())
    }
}

/// A projector-neutral, content-addressed manifest of retained immutable
/// evidence, tombstones, closed shard positions, and append/segment roots.
///
/// May anchor the declared evidence replay horizon only through
/// [`VerifiedReplayAnchorV1`], never directly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceCompactionCheckpointV1 {
    pub schema_version: u32,
    pub core: EvidenceCompactionCheckpointCoreV1,
    pub replay_verification_receipt: ReplayVerificationReceiptV1,
}

impl EvidenceCompactionCheckpointV1 {
    pub fn validate(&self) -> ContractResult<()> {
        if self.schema_version != LEDGER_EPOCH_SCHEMA_VERSION {
            return Err(ContractError::Schema(
                "invalid evidence-compaction checkpoint".into(),
            ));
        }
        self.replay_verification_receipt.validate()?;
        let core_digest = self.core.core_digest()?;
        if self.replay_verification_receipt.verified_subject_digest != core_digest {
            return Err(ContractError::Schema(
                "replay-verification receipt does not match the checkpoint core".into(),
            ));
        }
        Ok(())
    }
}

/// Only proof that an evidence-compaction checkpoint may anchor a replay
/// horizon: completeness has been independently replay-verified.
///
/// Private fields mean this cannot be built from unchecked bytes, and its
/// sole public constructor accepts only `&EvidenceCompactionCheckpointV1` —
/// a `ProjectorCheckpointV1` does not have a `core_digest` at all, so it
/// cannot even be offered to this function, let alone accepted by it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedReplayAnchorV1 {
    checkpoint_digest: Sha256Digest,
    epoch_id: EpochId,
}

impl VerifiedReplayAnchorV1 {
    pub fn from_checkpoint(checkpoint: &EvidenceCompactionCheckpointV1) -> ContractResult<Self> {
        checkpoint.validate()?;
        Ok(Self {
            checkpoint_digest: checkpoint.core.core_digest()?,
            epoch_id: checkpoint.core.epoch_id,
        })
    }

    pub const fn checkpoint_digest(&self) -> Sha256Digest {
        self.checkpoint_digest
    }

    pub const fn epoch_id(&self) -> EpochId {
        self.epoch_id
    }

    #[cfg(test)]
    pub(crate) const fn from_parts_for_test(
        checkpoint_digest: Sha256Digest,
        epoch_id: EpochId,
    ) -> Self {
        Self {
            checkpoint_digest,
            epoch_id,
        }
    }
}

// ---------------------------------------------------------------------
// Cursor vectors, projector checkpoints, and projection generations
// ---------------------------------------------------------------------

/// One shard's cursor progress: a cache position, never an evidence-closure
/// proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShardCursorEntryV1 {
    pub shard: u16,
    pub last_processed_offset: CommittedOffsetV1,
}

/// Sorted, unique-by-shard cursor vector.
///
/// Used both as one projector's own per-shard progress and as the closed
/// input barrier a cross-shard join projector consumes before publishing one
/// generation: identity is a pure function of the sorted `(shard, offset)`
/// pairs, so the same closed facts reduce to the same vector regardless of
/// processing or arrival order (REPLAY-01, REPLAY-02).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CursorVectorBarrierV1 {
    pub schema_version: u32,
    pub epoch_id: EpochId,
    pub cursors: Vec<ShardCursorEntryV1>,
}

impl CursorVectorBarrierV1 {
    pub fn validate(&self) -> ContractResult<()> {
        if self.schema_version != LEDGER_EPOCH_SCHEMA_VERSION
            || self.cursors.is_empty()
            || self.cursors.len() > MAX_VECTOR_SHARDS
        {
            return Err(ContractError::Schema(
                "invalid cursor vector barrier".into(),
            ));
        }
        if !self
            .cursors
            .windows(2)
            .all(|pair| pair[0].shard < pair[1].shard)
        {
            return Err(ContractError::NonCanonicalSet { field: "cursors" });
        }
        Ok(())
    }

    /// `SHA-256("ostk-cursor-vector-v1" || 0x00 || canonical_bytes(self))`.
    pub fn barrier_digest(&self) -> ContractResult<Sha256Digest> {
        self.validate()?;
        Ok(domain_separated_digest(
            DigestDomain::CursorVectorV1,
            &encode_canonical(self)?,
        ))
    }
}

/// A performance cache valid only for one exact projector and registry
/// digest.
///
/// It can never justify pruning evidence, and — being a distinct nominal
/// type from [`EvidenceCompactionCheckpointV1`] with a disjoint canonical
/// field set — it can never be accepted where this crate requires evidence
/// authority: decoding these bytes as that type fails at the schema
/// boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectorCheckpointV1 {
    pub schema_version: u32,
    pub projector_id: ContractId,
    pub projector_version: u32,
    pub registry_digest: Sha256Digest,
    pub cursor_vector: CursorVectorBarrierV1,
    pub output_digest: Sha256Digest,
    pub verification_receipt: ReplayVerificationReceiptV1,
}

impl ProjectorCheckpointV1 {
    pub fn validate(&self) -> ContractResult<()> {
        if self.schema_version != LEDGER_EPOCH_SCHEMA_VERSION || self.projector_version == 0 {
            return Err(ContractError::Schema("invalid projector checkpoint".into()));
        }
        self.cursor_vector.validate()?;
        self.verification_receipt.validate()?;
        Ok(())
    }

    /// `SHA-256("ostk-projector-checkpoint-v1" || 0x00 || canonical_bytes(self))`.
    pub fn checkpoint_digest(&self) -> ContractResult<Sha256Digest> {
        self.validate()?;
        Ok(domain_separated_digest(
            DigestDomain::ProjectorCheckpointV1,
            &encode_canonical(self)?,
        ))
    }
}

/// One generation published for one closed cursor-vector barrier.
///
/// Barrier identity alone determines generation identity, so the same
/// closed facts always publish under the same generation regardless of
/// shard schedule or arrival order. Late evidence publishes a strictly
/// later generation that names the one it `supersedes`; the earlier
/// generation's record and output are never deleted (REPLAY-01, REPLAY-02).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionGenerationV1 {
    pub schema_version: u32,
    pub projector_id: ContractId,
    pub projector_version: u32,
    pub barrier: CursorVectorBarrierV1,
    pub generation_sequence: u64,
    pub output_digest: Sha256Digest,
    pub supersedes: Option<Sha256Digest>,
}

impl ProjectionGenerationV1 {
    pub fn validate(&self) -> ContractResult<()> {
        if self.schema_version != LEDGER_EPOCH_SCHEMA_VERSION || self.projector_version == 0 {
            return Err(ContractError::Schema(
                "invalid projection generation record".into(),
            ));
        }
        self.barrier.validate()?;
        let has_predecessor = self.supersedes.is_some();
        if has_predecessor != (self.generation_sequence > 0) {
            return Err(ContractError::Schema(
                "generation sequence and supersession must agree on whether a predecessor exists"
                    .into(),
            ));
        }
        Ok(())
    }

    /// `SHA-256("ostk-projection-generation-v1" || 0x00 || canonical_bytes(self))`.
    pub fn generation_id(&self) -> ContractResult<Sha256Digest> {
        self.validate()?;
        Ok(domain_separated_digest(
            DigestDomain::ProjectionGenerationV1,
            &encode_canonical(self)?,
        ))
    }
}

// ---------------------------------------------------------------------
// Archive segments
// ---------------------------------------------------------------------

/// A closed, content-addressed evidence segment ready to leave the hot
/// ledger. `segment_start..=segment_end` and both chain digests bind the
/// exact byte range being moved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveSegmentManifestV1 {
    pub schema_version: u32,
    pub epoch_id: EpochId,
    pub shard: u16,
    pub segment_start: CommittedOffsetV1,
    pub segment_end: CommittedOffsetV1,
    pub segment_content_digest: Sha256Digest,
    pub previous_chain_digest: Sha256Digest,
    pub closing_chain_digest: Sha256Digest,
}

impl ArchiveSegmentManifestV1 {
    pub fn validate(&self) -> ContractResult<()> {
        if self.schema_version != LEDGER_EPOCH_SCHEMA_VERSION
            || self.segment_end.as_u64() < self.segment_start.as_u64()
        {
            return Err(ContractError::Schema(
                "invalid archive segment manifest".into(),
            ));
        }
        Ok(())
    }

    /// `SHA-256("ostk-archive-segment-manifest-v1" || 0x00 || canonical_bytes(self))`.
    pub fn manifest_digest(&self) -> ContractResult<Sha256Digest> {
        self.validate()?;
        Ok(domain_separated_digest(
            DigestDomain::ArchiveSegmentManifestV1,
            &encode_canonical(self)?,
        ))
    }
}

/// Proof that a segment's exact bytes were durably copied to a private
/// object archive. Bound to one manifest digest, so a receipt for different
/// bytes can never be substituted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableCopyReceiptV1 {
    pub schema_version: u32,
    pub segment_manifest_digest: Sha256Digest,
    pub storage_id: ContractId,
    pub object_digest: Sha256Digest,
    pub copied_at: CanonicalTimestamp,
}

impl DurableCopyReceiptV1 {
    pub fn validate(&self) -> ContractResult<()> {
        if self.schema_version != LEDGER_EPOCH_SCHEMA_VERSION {
            return Err(ContractError::Schema("invalid durable-copy receipt".into()));
        }
        Ok(())
    }
}

/// The complete move-admission rule: a closed segment manifest, its
/// durable-copy receipt, and independent replay verification, all bound to
/// the exact same manifest digest and exact object bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveMoveAdmissionV1 {
    pub schema_version: u32,
    pub manifest: ArchiveSegmentManifestV1,
    pub durable_copy_receipt: DurableCopyReceiptV1,
    pub replay_verification_receipt: ReplayVerificationReceiptV1,
}

impl ArchiveMoveAdmissionV1 {
    pub fn validate(&self) -> ContractResult<()> {
        if self.schema_version != LEDGER_EPOCH_SCHEMA_VERSION {
            return Err(ContractError::Schema(
                "invalid archive move admission".into(),
            ));
        }
        self.durable_copy_receipt.validate()?;
        self.replay_verification_receipt.validate()?;
        let manifest_digest = self.manifest.manifest_digest()?;
        if self.durable_copy_receipt.segment_manifest_digest != manifest_digest
            || self.durable_copy_receipt.object_digest != self.manifest.segment_content_digest
            || self.replay_verification_receipt.verified_subject_digest != manifest_digest
        {
            return Err(ContractError::Schema(
                "archive move is missing a required admission binding".into(),
            ));
        }
        Ok(())
    }
}

/// Only proof that a closed segment may leave the hot ledger.
///
/// Unconstructible except via [`Self::from_admission`], which requires the
/// manifest, durable-copy receipt, and replay-verification receipt to all
/// agree on one exact manifest digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmittedArchiveMoveV1 {
    manifest_digest: Sha256Digest,
}

impl AdmittedArchiveMoveV1 {
    pub fn from_admission(admission: &ArchiveMoveAdmissionV1) -> ContractResult<Self> {
        admission.validate()?;
        Ok(Self {
            manifest_digest: admission.manifest.manifest_digest()?,
        })
    }

    pub const fn manifest_digest(&self) -> Sha256Digest {
        self.manifest_digest
    }

    #[cfg(test)]
    pub(crate) const fn from_parts_for_test(manifest_digest: Sha256Digest) -> Self {
        Self { manifest_digest }
    }
}

// ---------------------------------------------------------------------
// Replay horizon
// ---------------------------------------------------------------------

/// A replay origin a projection must state explicitly.
///
/// There is no silent "unbounded"/default variant: every [`ReplayHorizonV1`]
/// names one of these two forms for both its semantic and
/// historical-content bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReplayFrom {
    Genesis,
    Checkpoint { checkpoint_digest: Sha256Digest },
}

/// `semantic_replay_from` is the earliest point full semantic identity can
/// be reproduced; `historical_content_available_from` is the earliest point
/// raw historical content is still materializable.
///
/// The historical bound may be strictly later than the semantic one
/// (private raw payloads and archive tiers can retire before semantic
/// identity does). Neither field may be omitted or defaulted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayHorizonV1 {
    pub schema_version: u32,
    pub semantic_replay_from: ReplayFrom,
    pub historical_content_available_from: ReplayFrom,
}

impl ReplayHorizonV1 {
    pub fn validate(&self) -> ContractResult<()> {
        if self.schema_version != LEDGER_EPOCH_SCHEMA_VERSION {
            return Err(ContractError::Schema("invalid replay horizon".into()));
        }
        Ok(())
    }

    /// Bound `semantic_replay_from` to one independently replay-verified
    /// checkpoint. This is the only constructor that can produce a
    /// `Checkpoint` semantic bound, and it requires a
    /// [`VerifiedReplayAnchorV1`] — obtainable only from an
    /// [`EvidenceCompactionCheckpointV1`] whose receipt already checked out.
    pub const fn anchored(
        anchor: &VerifiedReplayAnchorV1,
        historical_content_available_from: ReplayFrom,
    ) -> Self {
        Self {
            schema_version: LEDGER_EPOCH_SCHEMA_VERSION,
            semantic_replay_from: ReplayFrom::Checkpoint {
                checkpoint_digest: anchor.checkpoint_digest,
            },
            historical_content_available_from,
        }
    }

    /// Explicitly state genesis replayability; never the implicit default.
    pub const fn genesis(historical_content_available_from: ReplayFrom) -> Self {
        Self {
            schema_version: LEDGER_EPOCH_SCHEMA_VERSION,
            semantic_replay_from: ReplayFrom::Genesis,
            historical_content_available_from,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::memory_contracts::{
        bootstrap::PartitionAlgorithm,
        canonical::{decode_strict, require_canonical},
        common::FixedHex32,
    };

    const SUCCESSOR_LOG_EPOCH: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v3/ledger-epoch/successor-log-epoch.jsonl");
    const EVIDENCE_COMPACTION_CHECKPOINT: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/ledger-epoch/evidence-compaction-checkpoint.jsonl"
    );
    const PROJECTOR_CHECKPOINT: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v3/ledger-epoch/projector-checkpoint.jsonl");
    const ARCHIVE_MOVE_ADMISSION: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/ledger-epoch/archive-move-admission.jsonl"
    );
    const CURSOR_VECTOR_BARRIER: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/ledger-epoch/cursor-vector-barrier.jsonl"
    );
    const NEGATIVE_UNSORTED_HEAD_VECTOR: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/ledger-epoch/negative-unsorted-head-vector.jsonl"
    );
    const NEGATIVE_MISSING_PREDECESSOR: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/ledger-epoch/negative-missing-predecessor.jsonl"
    );
    const NEGATIVE_SEED_SHAPE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v3/ledger-epoch/negative-seed-shape.jsonl");
    const SUCCESSOR_LOG_EPOCH_ID: &str =
        "1f8c197c5854fed8980db82d88f82f568ba7005da4ed6096a935b6d02e8429c2";

    fn record(artifact: &'static [u8]) -> &'static [u8] {
        let body = artifact
            .strip_suffix(b"\n")
            .expect("contract artifact must have one repository-framing LF");
        assert!(!body.ends_with(b"\n"));
        assert!(!body.contains(&b'\r'));
        body
    }

    fn digest(value: &str) -> Sha256Digest {
        Sha256Digest::from_str(value).expect("hard-coded digest must be lowercase SHA-256")
    }

    fn profile() -> ProfileReferenceV1 {
        ProfileReferenceV1 {
            profile_id: ContractId::new("ostk-canonical-json-v1").unwrap(),
            profile_digest: digest(
                "cf22991a86bfc560556c7d04efa4ee6b7b1ee0f49c919b257ea7b4f30f8e4a29",
            ),
            vector_manifest_digest: digest(
                "f984f62866fc769df3a5617a2247e3ade694827c1de69e615a7bda68858b4174",
            ),
        }
    }

    fn scope() -> AuthenticatedProjectScopeV1 {
        AuthenticatedProjectScopeV1::from_trusted_context(
            ContractId::new("tenant.fixture").unwrap(),
            ContractId::new("project.fixture").unwrap(),
        )
    }

    fn predecessor_epoch_id() -> EpochId {
        EpochId::from_digest(digest(
            "d35655f3297e1c5eb4503443befb956f93dc5210b46cdc1a4d7d9f2746b8fab2",
        ))
    }

    fn closed_predecessor_head() -> ClosedHeadVectorV1 {
        ClosedHeadVectorV1 {
            schema_version: 1,
            epoch_id: predecessor_epoch_id(),
            heads: vec![
                ClosedShardHeadV1 {
                    shard: 0,
                    last_committed_offset: CommittedOffsetV1::new(11).unwrap(),
                    chain_digest: digest(
                        "1111111111111111111111111111111111111111111111111111111111111111",
                    ),
                },
                ClosedShardHeadV1 {
                    shard: 5,
                    last_committed_offset: CommittedOffsetV1::new(2).unwrap(),
                    chain_digest: digest(
                        "2222222222222222222222222222222222222222222222222222222222222222",
                    ),
                },
            ],
        }
    }

    fn successor_partition_recipe() -> PartitionRecipeV1 {
        PartitionRecipeV1 {
            schema_version: 1,
            recipe_id: ContractId::new("ostk.partition.sha256_prefix64_modulo").unwrap(),
            recipe_version: 1,
            algorithm: PartitionAlgorithm::Sha256Prefix64Modulo,
            seed: FixedHex32::from_bytes([9; 32]),
            shard_count: 32,
        }
    }

    fn successor_epoch() -> SuccessorLogEpochV1 {
        SuccessorLogEpochV1 {
            schema_version: 1,
            profile: profile(),
            scope: scope(),
            partition_recipe: successor_partition_recipe(),
            activation_binding: EpochActivationBindingV1 {
                schema_version: 1,
                predecessor_epoch_id: predecessor_epoch_id(),
                closed_predecessor_head: closed_predecessor_head(),
            },
        }
    }

    #[test]
    fn successor_epoch_matches_golden_bytes_and_id() {
        let epoch = successor_epoch();
        let golden = record(SUCCESSOR_LOG_EPOCH);
        require_canonical(golden).unwrap();
        assert_eq!(encode_canonical(&epoch).unwrap(), golden);

        let decoded: SuccessorLogEpochV1 = decode_strict(golden).unwrap();
        assert_eq!(decoded, epoch);
        decoded.validate().unwrap();
        assert_eq!(
            decoded.epoch_id().unwrap().digest(),
            digest(SUCCESSOR_LOG_EPOCH_ID)
        );

        // The epoch's own identity is deterministic under replay: decoding
        // the same bytes twice reproduces the same ID (REPLAY-01).
        let redecoded: SuccessorLogEpochV1 = decode_strict(golden).unwrap();
        assert_eq!(redecoded.epoch_id().unwrap(), decoded.epoch_id().unwrap());
    }

    #[test]
    fn epoch_missing_predecessor_fails_closed() {
        assert!(
            decode_strict::<SuccessorLogEpochV1>(record(NEGATIVE_MISSING_PREDECESSOR)).is_err()
        );
    }

    #[test]
    fn seed_shape_fails_closed() {
        assert!(decode_strict::<SuccessorLogEpochV1>(record(NEGATIVE_SEED_SHAPE)).is_err());
    }

    #[test]
    fn unsorted_head_vector_fails_closed() {
        let decoded: ClosedHeadVectorV1 = decode_strict(record(NEGATIVE_UNSORTED_HEAD_VECTOR))
            .expect("shape is well-formed JSON; only ordering is invalid");
        assert_eq!(
            decoded.validate(),
            Err(ContractError::NonCanonicalSet { field: "heads" })
        );
    }

    #[test]
    fn shard_count_change_keeps_evidence_ids_unchanged() {
        let epoch = successor_epoch();
        let mut wider = epoch.clone();
        wider.partition_recipe.shard_count = 64;
        // Changing the shard count mints a different log epoch...
        assert_ne!(epoch.epoch_id().unwrap(), wider.epoch_id().unwrap());

        // ...but the very same accepted-event ID validates a retry under
        // either epoch generation: LostFenceRetryV1 has exactly one
        // accepted_event_id field, so nothing about the shard count or
        // epoch identity can ever flow into it.
        let event_id = AcceptedEventId::from_digest(digest(
            "4444444444444444444444444444444444444444444444444444444444444444",
        ));
        for candidate in [epoch, wider] {
            let fence = EpochFenceV1 {
                schema_version: 1,
                successor_epoch: candidate.clone(),
            };
            let key = ConsistencyPartitionKeyV1 {
                family: ContractId::new("evidence.retry").unwrap(),
                key_digest: digest(
                    "3333333333333333333333333333333333333333333333333333333333333333",
                ),
            };
            let shard = partition_for_successor_epoch(&candidate, &key).unwrap();
            let retry = LostFenceRetryV1 {
                schema_version: 1,
                accepted_event_id: event_id,
                consistency_partition_key: key,
                losing_position: AppendPositionV1 {
                    epoch_id: predecessor_epoch_id(),
                    shard: 0,
                    committed_offset: CommittedOffsetV1::new(12).unwrap(),
                },
                retry_position: AppendPositionV1 {
                    epoch_id: candidate.epoch_id().unwrap(),
                    shard,
                    committed_offset: CommittedOffsetV1::new(1).unwrap(),
                },
            };
            retry.validate_against(&fence).unwrap();
            assert_eq!(retry.accepted_event_id, event_id);
        }
    }

    #[test]
    fn epoch_fence_rejects_append_at_predecessor_and_admits_retry() {
        let epoch = successor_epoch();
        let successor_id = epoch.epoch_id().unwrap();
        let fence = EpochFenceV1 {
            schema_version: 1,
            successor_epoch: epoch.clone(),
        };
        fence.validate().unwrap();

        let losing_position = AppendPositionV1 {
            epoch_id: predecessor_epoch_id(),
            shard: 0,
            committed_offset: CommittedOffsetV1::new(12).unwrap(),
        };
        assert!(fence.reject_append_after_fence(&losing_position).is_err());

        let key = ConsistencyPartitionKeyV1 {
            family: ContractId::new("evidence.retry").unwrap(),
            key_digest: digest("3333333333333333333333333333333333333333333333333333333333333333"),
        };
        let expected_shard = partition_for_successor_epoch(&epoch, &key).unwrap();
        let retry_position = AppendPositionV1 {
            epoch_id: successor_id,
            shard: expected_shard,
            committed_offset: CommittedOffsetV1::new(1).unwrap(),
        };
        assert!(fence.reject_append_after_fence(&retry_position).is_ok());

        let event_id = AcceptedEventId::from_digest(digest(
            "4444444444444444444444444444444444444444444444444444444444444444",
        ));
        let retry = LostFenceRetryV1 {
            schema_version: 1,
            accepted_event_id: event_id,
            consistency_partition_key: key,
            losing_position,
            retry_position,
        };
        retry.validate_against(&fence).unwrap();
        // The retry keeps exactly one accepted_event_id; before and after
        // retry, the semantic identity is the same struct field.
        assert_eq!(retry.accepted_event_id, event_id);

        let mut same_position_retry = retry.clone();
        same_position_retry.retry_position = same_position_retry.losing_position;
        assert!(same_position_retry.validate_against(&fence).is_err());

        let mut wrong_predecessor = retry;
        wrong_predecessor.losing_position.epoch_id = successor_id;
        assert!(wrong_predecessor.validate_against(&fence).is_err());
    }

    #[test]
    fn evidence_compaction_and_projector_checkpoints_are_not_interchangeable() {
        let golden = record(EVIDENCE_COMPACTION_CHECKPOINT);
        require_canonical(golden).unwrap();
        let checkpoint: EvidenceCompactionCheckpointV1 = decode_strict(golden).unwrap();
        checkpoint.validate().unwrap();
        assert_eq!(encode_canonical(&checkpoint).unwrap(), golden);

        let anchor = VerifiedReplayAnchorV1::from_checkpoint(&checkpoint).unwrap();
        assert_eq!(anchor.epoch_id(), checkpoint.core.epoch_id);

        let horizon = ReplayHorizonV1::anchored(
            &anchor,
            ReplayFrom::Checkpoint {
                checkpoint_digest: anchor.checkpoint_digest(),
            },
        );
        horizon.validate().unwrap();
        assert_eq!(
            horizon.semantic_replay_from,
            ReplayFrom::Checkpoint {
                checkpoint_digest: anchor.checkpoint_digest()
            }
        );

        // A projector checkpoint's canonical bytes cannot decode as an
        // evidence-compaction checkpoint: the field sets are disjoint, so
        // this fails at the schema boundary, not merely by convention.
        let projector_golden = record(PROJECTOR_CHECKPOINT);
        require_canonical(projector_golden).unwrap();
        let projector: ProjectorCheckpointV1 = decode_strict(projector_golden).unwrap();
        projector.validate().unwrap();
        assert!(decode_strict::<EvidenceCompactionCheckpointV1>(projector_golden).is_err());
        assert!(decode_strict::<ProjectorCheckpointV1>(golden).is_err());
    }

    #[test]
    fn checkpoint_receipt_mismatch_fails_closed() {
        let checkpoint: EvidenceCompactionCheckpointV1 =
            decode_strict(record(EVIDENCE_COMPACTION_CHECKPOINT)).unwrap();
        let mut wrong = checkpoint;
        wrong.replay_verification_receipt.verified_subject_digest =
            digest("5555555555555555555555555555555555555555555555555555555555555555");
        assert!(wrong.validate().is_err());
        assert!(VerifiedReplayAnchorV1::from_checkpoint(&wrong).is_err());
    }

    #[test]
    fn cursor_vector_barrier_is_order_independent() {
        let golden = record(CURSOR_VECTOR_BARRIER);
        require_canonical(golden).unwrap();
        let barrier: CursorVectorBarrierV1 = decode_strict(golden).unwrap();
        barrier.validate().unwrap();
        let first_digest = barrier.barrier_digest().unwrap();

        // Simulate reversed shard arrival: build the same closed facts with
        // entries swapped before validation re-sorts nothing (validate only
        // *checks* sortedness — it is the producer's job to sort). Two
        // producers who observed the same shards in a different arrival
        // order must still emit the same sorted vector to agree on a
        // digest; this exercises that the digest depends only on the
        // sorted content, not on any hidden construction order.
        let mut reversed = barrier.clone();
        reversed.cursors.reverse();
        reversed.cursors.sort_by_key(|entry| entry.shard);
        assert_eq!(reversed.barrier_digest().unwrap(), first_digest);

        let generation = ProjectionGenerationV1 {
            schema_version: 1,
            projector_id: ContractId::new("projector.join.fixture").unwrap(),
            projector_version: 1,
            barrier,
            generation_sequence: 0,
            output_digest: digest(
                "6666666666666666666666666666666666666666666666666666666666666666",
            ),
            supersedes: None,
        };
        generation.validate().unwrap();
        let first_generation_id = generation.generation_id().unwrap();

        let same_facts_reversed = ProjectionGenerationV1 {
            barrier: reversed,
            ..generation.clone()
        };
        assert_eq!(
            same_facts_reversed.generation_id().unwrap(),
            first_generation_id
        );

        let mut later = generation.clone();
        later.generation_sequence = 1;
        later.supersedes = Some(first_generation_id);
        later.output_digest =
            digest("7777777777777777777777777777777777777777777777777777777777777777");
        later.validate().unwrap();
        assert_ne!(later.generation_id().unwrap(), first_generation_id);

        let mut inconsistent = generation;
        inconsistent.generation_sequence = 1;
        assert!(inconsistent.validate().is_err());
    }

    #[test]
    fn archive_move_requires_every_admission_binding() {
        let golden = record(ARCHIVE_MOVE_ADMISSION);
        require_canonical(golden).unwrap();
        let admission: ArchiveMoveAdmissionV1 = decode_strict(golden).unwrap();
        admission.validate().unwrap();
        assert_eq!(encode_canonical(&admission).unwrap(), golden);

        let admitted = AdmittedArchiveMoveV1::from_admission(&admission).unwrap();
        assert_eq!(
            admitted.manifest_digest(),
            admission.manifest.manifest_digest().unwrap()
        );

        let mut missing_replay_verification = admission.clone();
        missing_replay_verification
            .replay_verification_receipt
            .verified_subject_digest =
            digest("8888888888888888888888888888888888888888888888888888888888888888");
        assert!(missing_replay_verification.validate().is_err());
        assert!(AdmittedArchiveMoveV1::from_admission(&missing_replay_verification).is_err());

        let mut wrong_copy = admission;
        wrong_copy.durable_copy_receipt.object_digest =
            digest("9999999999999999999999999999999999999999999999999999999999999999");
        assert!(wrong_copy.validate().is_err());
    }

    #[test]
    fn verified_replay_anchor_test_constructor_matches_from_checkpoint() {
        let checkpoint: EvidenceCompactionCheckpointV1 =
            decode_strict(record(EVIDENCE_COMPACTION_CHECKPOINT)).unwrap();
        let anchor = VerifiedReplayAnchorV1::from_checkpoint(&checkpoint).unwrap();
        let rebuilt = VerifiedReplayAnchorV1::from_parts_for_test(
            anchor.checkpoint_digest(),
            anchor.epoch_id(),
        );
        assert_eq!(rebuilt, anchor);
    }

    #[test]
    fn admitted_archive_move_test_constructor_matches_from_admission() {
        let admission: ArchiveMoveAdmissionV1 =
            decode_strict(record(ARCHIVE_MOVE_ADMISSION)).unwrap();
        let admitted = AdmittedArchiveMoveV1::from_admission(&admission).unwrap();
        let rebuilt = AdmittedArchiveMoveV1::from_parts_for_test(admitted.manifest_digest());
        assert_eq!(rebuilt, admitted);
    }

    #[test]
    fn replay_horizon_states_bounded_replay_explicitly() {
        let genesis_only = ReplayHorizonV1::genesis(ReplayFrom::Genesis);
        genesis_only.validate().unwrap();
        assert_eq!(genesis_only.semantic_replay_from, ReplayFrom::Genesis);
        assert_eq!(
            genesis_only.historical_content_available_from,
            ReplayFrom::Genesis
        );

        let checkpoint: EvidenceCompactionCheckpointV1 =
            decode_strict(record(EVIDENCE_COMPACTION_CHECKPOINT)).unwrap();
        let anchor = VerifiedReplayAnchorV1::from_checkpoint(&checkpoint).unwrap();
        let bounded = ReplayHorizonV1::anchored(&anchor, ReplayFrom::Genesis);
        bounded.validate().unwrap();
        assert_ne!(bounded.semantic_replay_from, ReplayFrom::Genesis);
        assert_eq!(
            bounded.semantic_replay_from,
            ReplayFrom::Checkpoint {
                checkpoint_digest: anchor.checkpoint_digest()
            }
        );
    }
}
