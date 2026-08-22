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
//! Owned by W0-LOG. No runtime authority is implied by these types alone:
//! callers must invoke the paired validation methods documented on each type
//! (in particular [`ReplayHorizonV1::validate_semantic_anchor`] and
//! [`ProjectionGenerationV1::validate_supersession`]) before treating a
//! decoded record as admitted.

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

    /// Normalize shard heads observed in arbitrary arrival order into the
    /// canonical sorted-by-shard vector.
    ///
    /// Two producers who fence the same shards in a different order must
    /// still emit byte-identical `ClosedHeadVectorV1`s so their digests
    /// agree (REPLAY-01): this is the constructor that guarantees it, rather
    /// than delegating "sort before you build one" to every caller by
    /// convention. Duplicate shards — which can never legitimately arise
    /// from one fence — are rejected rather than silently deduplicated.
    pub fn from_heads(
        epoch_id: EpochId,
        mut heads: Vec<ClosedShardHeadV1>,
    ) -> ContractResult<Self> {
        heads.sort_by_key(|head| head.shard);
        if heads.windows(2).any(|pair| pair[0].shard == pair[1].shard) {
            return Err(ContractError::NonCanonicalSet { field: "heads" });
        }
        let vector = Self {
            schema_version: LEDGER_EPOCH_SCHEMA_VERSION,
            epoch_id,
            heads,
        };
        vector.validate()?;
        Ok(vector)
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

    /// The pure fencing rule: an allow-list, not a deny-list. Every shard
    /// head in the predecessor epoch is closed by this fence, so the only
    /// coordinate an append may legally target afterward is a shard within
    /// this exact successor epoch. Any other epoch id — the fenced
    /// predecessor, an earlier ancestor from a prior cutover, or an unknown
    /// or fabricated epoch id an attacker supplies — is rejected, as is a
    /// shard number the successor epoch's own partition recipe never
    /// assigned.
    pub fn reject_append_after_fence(&self, position: &AppendPositionV1) -> ContractResult<()> {
        let successor_epoch_id = self.successor_epoch_id()?;
        if position.epoch_id != successor_epoch_id {
            return Err(ContractError::Schema(
                "append does not target the fence's successor epoch".into(),
            ));
        }
        if position.shard >= self.successor_epoch.partition_recipe.shard_count {
            return Err(ContractError::Schema(
                "append targets a shard outside the successor epoch's partition recipe".into(),
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

    /// Fold a tail of shard heads observed *after* this checkpoint onto its
    /// closed shard positions, producing the closed head vector a semantic
    /// replay starting from this checkpoint (checkpoint + tail) would reach.
    ///
    /// Every tail entry must not regress a shard the checkpoint already
    /// closed (its offset must be `>=` the checkpoint's), and may introduce
    /// a shard the checkpoint had not yet closed. A tail entry naming a
    /// shard the checkpoint already closed at the identical offset is
    /// accepted only when its `chain_digest` also matches exactly (an
    /// idempotent no-op re-observation); the same offset with a *different*
    /// chain digest is a forked append chain — contested input, not an
    /// advance — and is rejected rather than silently substituted, so a
    /// replayer can never be made to adopt a different history for a shard
    /// the checkpoint already closed while reporting the same offset
    /// (REPLAY-01, EVID-01). The result is built with
    /// [`ClosedHeadVectorV1::from_heads`], so it is sorted and
    /// deduplicated-by-shard the same way a from-genesis replay's vector
    /// would be — proving "checkpoint + tail replay reproduces the same
    /// closed vector" a full replay reaching the same final shard state
    /// would produce (REPLAY-01).
    pub fn replay_tail(&self, tail: &[ClosedShardHeadV1]) -> ContractResult<ClosedHeadVectorV1> {
        self.validate()?;
        let mut by_shard: std::collections::BTreeMap<u16, ClosedShardHeadV1> = self
            .closed_shard_positions
            .heads
            .iter()
            .map(|head| (head.shard, *head))
            .collect();
        for advance in tail {
            if let Some(existing) = by_shard.get(&advance.shard) {
                let existing_offset = existing.last_committed_offset.as_u64();
                let advance_offset = advance.last_committed_offset.as_u64();
                if advance_offset < existing_offset {
                    return Err(ContractError::Schema(
                        "replay tail regresses a shard the checkpoint already closed".into(),
                    ));
                }
                if advance_offset == existing_offset
                    && advance.chain_digest != existing.chain_digest
                {
                    return Err(ContractError::Schema(
                        "replay tail forks a shard the checkpoint already closed: same offset, \
                         different chain digest"
                            .into(),
                    ));
                }
            }
            by_shard.insert(advance.shard, *advance);
        }
        ClosedHeadVectorV1::from_heads(self.epoch_id, by_shard.into_values().collect())
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

    /// Normalize per-shard cursor observations collected in arbitrary
    /// arrival order into the canonical sorted-by-shard barrier.
    ///
    /// This is the API a cross-shard join projector actually has: shard
    /// cursors close independently and arrive at the projector in whatever
    /// order their underlying shard processes happen to finish in. Two
    /// projectors that observed the same closed shards under a different
    /// arrival order must still emit byte-identical barriers so their
    /// digests — and every `ProjectionGenerationV1` built from them — agree
    /// (REPLAY-01, REPLAY-02). Duplicate shards are rejected rather than
    /// silently deduplicated.
    pub fn from_observations(
        epoch_id: EpochId,
        mut cursors: Vec<ShardCursorEntryV1>,
    ) -> ContractResult<Self> {
        cursors.sort_by_key(|entry| entry.shard);
        if cursors
            .windows(2)
            .any(|pair| pair[0].shard == pair[1].shard)
        {
            return Err(ContractError::NonCanonicalSet { field: "cursors" });
        }
        let barrier = Self {
            schema_version: LEDGER_EPOCH_SCHEMA_VERSION,
            epoch_id,
            cursors,
        };
        barrier.validate()?;
        Ok(barrier)
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
        // Bind the receipt to this checkpoint's exact durable output, the
        // same way EvidenceCompactionCheckpointV1 binds its receipt to
        // core_digest — otherwise the receipt certifies nothing about this
        // checkpoint in particular (REPLAY-02: a cursor advances atomically
        // with that stage's complete durable output).
        if self.verification_receipt.verified_subject_digest != self.output_digest {
            return Err(ContractError::Schema(
                "projector checkpoint receipt does not match its output digest".into(),
            ));
        }
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
/// Identity ([`Self::generation_id`]) is a pure function of *what was
/// published* — `schema_version`, `projector_id`, `projector_version`, and
/// `output_digest` — and deliberately excludes `barrier`, `generation_sequence`,
/// and `supersedes`. All three are shard-schedule artifacts, not published
/// facts: `barrier` is a physical coordinate outright, and
/// `generation_sequence`/`supersedes` record *how many intermediate
/// generations this schedule needed* to reach the published facts — which
/// itself depends on the shard schedule, because a finer-grained schedule
/// can require an extra intermediate generation to cover the identical
/// total facts a coarser schedule reaches in one (e.g. a two-shard schedule
/// publishing generation 1, superseding generation 0, over the same total
/// facts a one-shard schedule publishes as generation 0 with no
/// predecessor). REPLAY-01's "same facts under a different shard schedule
/// must produce the same generation" is a statement about `output_digest`
/// — the actual published facts — so only fields that are themselves a
/// function of the published facts (plus the fixed projector identity)
/// belong in identity. `barrier`, `generation_sequence`, and `supersedes`
/// remain on the record as bound *evidence of closure and chaining*,
/// checked structurally — never as part of identity — by every caller
/// before admission: [`Self::validate_supersession`] requires a superseding
/// generation to (a) name its exact predecessor's [`Self::record_digest`],
/// (b) share that predecessor's `projector_id` and `projector_version`
/// exactly (a generation is never superseded by a different projector or a
/// different version of the same one), (c) carry `generation_sequence`
/// exactly one past the predecessor's, and (d) strictly advance the
/// predecessor's barrier. Late evidence publishes a strictly later
/// generation over a strictly advanced barrier; the earlier generation's
/// record and output are never deleted (REPLAY-01, REPLAY-02).
///
/// `supersedes` deliberately does **not** name a predecessor's
/// [`Self::generation_id`]: because `generation_id` is schedule-independent
/// by design (see above), two *different* records — e.g. the same total
/// facts published as one generation under a coarse schedule and as a later
/// generation over a smaller barrier under a finer one, or a strictly
/// earlier generation and a later one that happens to reach the same
/// output — can share one `generation_id`. If `supersedes` named that
/// shared id, either record could satisfy a lookup for the other: a
/// caller could name a low-barrier record as predecessor and have the
/// check silently resolve against a different, higher-barrier record with
/// the identical id, admitting a rewritten `output_digest` over a barrier
/// that record had already closed. `supersedes` instead names
/// [`Self::record_digest`], a digest over the full record — including
/// `barrier`, `generation_sequence`, and `supersedes` itself — that
/// therefore names exactly one publication record, never an equivalence
/// class. This also makes self-reference cryptographically, not just
/// conventionally, impossible: `record_digest` is a function of `self`
/// *including* its own `supersedes` field, so a record cannot choose a
/// `supersedes` value equal to its own `record_digest()` without first
/// knowing the output of a hash that itself depends on that same value —
/// the classic hash-pointer non-self-reference argument, not a special-cased
/// check.
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

/// The identity-only projection hashed by [`ProjectionGenerationV1::generation_id`].
///
/// Exists solely to keep `barrier`, `generation_sequence`, and `supersedes`
/// — each a shard-schedule artifact rather than a published fact — out of
/// the identity preimage; see the type-level doc on [`ProjectionGenerationV1`]
/// for why all three are excluded. Serialize-only: this type is never
/// decoded, only built from an already-validated [`ProjectionGenerationV1`]
/// and canonically encoded.
#[derive(Serialize)]
struct ProjectionGenerationIdentityV1<'a> {
    schema_version: u32,
    projector_id: &'a ContractId,
    projector_version: u32,
    output_digest: &'a Sha256Digest,
}

/// The full-record projection hashed by [`ProjectionGenerationV1::record_digest`].
///
/// Distinct from [`ProjectionGenerationIdentityV1`]: `record_digest` names
/// exactly *one publication record* — this record's own `generation_id()`
/// plus `barrier`, `generation_sequence`, and `supersedes` — whereas
/// `generation_id` deliberately coalesces every record that published the
/// same facts. `supersedes` is checked against a predecessor's
/// `record_digest`, never its `generation_id` — see the type-level docs on
/// [`ProjectionGenerationV1`] for why naming the schedule-independent id
/// would let two different records substitute for one another. Serialize
/// -only: this type is never decoded, only built from an already-validated
/// `ProjectionGenerationV1` and canonically encoded.
#[derive(Serialize)]
struct ProjectionGenerationRecordV1<'a> {
    generation_id: &'a Sha256Digest,
    barrier: &'a CursorVectorBarrierV1,
    generation_sequence: u64,
    supersedes: &'a Option<Sha256Digest>,
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

    /// `SHA-256("ostk-projection-generation-v1" || 0x00 || canonical_bytes(identity))`
    /// where `identity` is [`ProjectionGenerationIdentityV1`] — `self` minus
    /// `barrier`, `generation_sequence`, and `supersedes`. See the
    /// type-level docs for why all three are excluded from identity.
    pub fn generation_id(&self) -> ContractResult<Sha256Digest> {
        self.validate()?;
        let identity = ProjectionGenerationIdentityV1 {
            schema_version: self.schema_version,
            projector_id: &self.projector_id,
            projector_version: self.projector_version,
            output_digest: &self.output_digest,
        };
        Ok(domain_separated_digest(
            DigestDomain::ProjectionGenerationV1,
            &encode_canonical(&identity)?,
        ))
    }

    /// `SHA-256("ostk-projection-generation-record-v1" || 0x00 || canonical_bytes(record))`
    /// where `record` is [`ProjectionGenerationRecordV1`] — this record's
    /// [`Self::generation_id`] plus `barrier`, `generation_sequence`, and
    /// `supersedes`. Unlike `generation_id`, this names exactly one
    /// publication record: two records that publish the same facts under a
    /// different shard schedule share a `generation_id` but never a
    /// `record_digest`, because their `barrier`/`generation_sequence` differ.
    /// [`Self::validate_supersession`] checks `supersedes` against a
    /// predecessor's `record_digest`, never its `generation_id` — see the
    /// type-level docs for why the id alone is not a safe supersession
    /// target. Because the preimage includes this record's own `supersedes`
    /// field, no record can be constructed whose `supersedes` equals its own
    /// `record_digest()`: doing so would require choosing a `supersedes`
    /// value equal to the SHA-256 output of a preimage that already contains
    /// that same value, a hash fixed point, not a value a caller can pick.
    pub fn record_digest(&self) -> ContractResult<Sha256Digest> {
        let generation_id = self.generation_id()?;
        let record = ProjectionGenerationRecordV1 {
            generation_id: &generation_id,
            barrier: &self.barrier,
            generation_sequence: self.generation_sequence,
            supersedes: &self.supersedes,
        };
        Ok(domain_separated_digest(
            DigestDomain::ProjectionGenerationRecordV1,
            &encode_canonical(&record)?,
        ))
    }

    /// The cross-record half of "one generation per closed barrier": a
    /// superseding generation must name its exact predecessor, share that
    /// predecessor's exact projector identity and version, carry a sequence
    /// exactly one past it, and its barrier must strictly dominate that
    /// predecessor's — same epoch, the same shard set, every cursor at or
    /// past the predecessor's offset, and at least one strictly past it.
    ///
    /// `validate()` alone cannot enforce any of this: it is a single-record
    /// shape check, so two *different* records can each independently pass
    /// `validate()` while disagreeing on projector, sequence, or barrier
    /// with a named predecessor. Naming the predecessor also cannot use
    /// `generation_id()`: that identity deliberately excludes `barrier`,
    /// `generation_sequence`, and `supersedes` (see the type-level docs), so
    /// two different records — e.g. the same total facts published under two
    /// different shard schedules, or a strictly earlier and a strictly later
    /// generation that happen to reach the same output — can share one
    /// `generation_id`. If `supersedes` were checked against that shared id,
    /// either record could satisfy a lookup for the other, letting a
    /// superseding generation reference a low-barrier record's id while
    /// actually being checked against — and admitted as a rewrite over — a
    /// different, higher-barrier record that happens to share it. This
    /// method instead resolves `supersedes` against [`Self::record_digest`],
    /// which names exactly one record, so no such substitution is possible.
    /// Without this method (and without the `record_digest` resolution) a
    /// caller could publish a generation naming an unrelated projector's
    /// output as its successor, skip or regress `generation_sequence`, or
    /// publish a different `output_digest` over the identical closed barrier
    /// (rewriting "what happened" instead of recomputing it after strictly
    /// more evidence closed) by way of an id-colliding substitute
    /// predecessor. This method is the required second check a runtime
    /// performs before admitting a superseding generation; a cross-projector,
    /// cross-version, non-consecutive-sequence, or same-or-earlier-barrier
    /// successor is rejected regardless of what `output_digest` it carries,
    /// and no record — including `self` itself — can satisfy this check by
    /// naming a predecessor's `generation_id` in place of its `record_digest`.
    pub fn validate_supersession(&self, predecessor: &Self) -> ContractResult<()> {
        self.validate()?;
        predecessor.validate()?;
        let predecessor_record_digest = predecessor.record_digest()?;
        if self.supersedes != Some(predecessor_record_digest) {
            return Err(ContractError::Schema(
                "superseding generation does not name its exact predecessor".into(),
            ));
        }
        if self.projector_id != predecessor.projector_id {
            return Err(ContractError::Schema(
                "superseding generation belongs to a different projector".into(),
            ));
        }
        if self.projector_version != predecessor.projector_version {
            return Err(ContractError::Schema(
                "superseding generation belongs to a different projector version; a deliberate \
                 projector-version bump must be an explicit, separately named admission rule, \
                 never this default supersession check"
                    .into(),
            ));
        }
        let expected_sequence =
            predecessor
                .generation_sequence
                .checked_add(1)
                .ok_or_else(|| {
                    ContractError::Schema(
                        "predecessor generation sequence would overflow on supersession".into(),
                    )
                })?;
        if self.generation_sequence != expected_sequence {
            return Err(ContractError::Schema(
                "superseding generation sequence must be exactly one past its predecessor's; \
                 a lower, equal, or skipped sequence is rejected"
                    .into(),
            ));
        }
        if self.barrier.epoch_id != predecessor.barrier.epoch_id {
            return Err(ContractError::Schema(
                "superseding generation's barrier belongs to a different epoch".into(),
            ));
        }
        if self.barrier.cursors.len() != predecessor.barrier.cursors.len() {
            return Err(ContractError::Schema(
                "superseding generation's barrier does not cover the same shard set".into(),
            ));
        }
        let mut strictly_advanced = false;
        for (next, previous) in self
            .barrier
            .cursors
            .iter()
            .zip(predecessor.barrier.cursors.iter())
        {
            if next.shard != previous.shard {
                return Err(ContractError::Schema(
                    "superseding generation's barrier does not cover the same shard set".into(),
                ));
            }
            let next_offset = next.last_processed_offset.as_u64();
            let previous_offset = previous.last_processed_offset.as_u64();
            if next_offset < previous_offset {
                return Err(ContractError::Schema(
                    "superseding generation's barrier regresses a shard cursor".into(),
                ));
            }
            if next_offset > previous_offset {
                strictly_advanced = true;
            }
        }
        if !strictly_advanced {
            return Err(ContractError::Schema(
                "superseding generation must strictly advance the barrier it supersedes; \
                 late evidence means an advanced cursor vector, not a rewritten output over \
                 the same closed vector"
                    .into(),
            ));
        }
        Ok(())
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
///
/// `Genesis` is deliberately the empty *struct* variant `Genesis {}`, not a
/// unit variant. Serde's `#[serde(deny_unknown_fields)]` on an internally
/// tagged enum (`#[serde(tag = "kind")]`) has no effect on a unit variant —
/// it is deserialized by a `void` visitor that never inspects a payload, so
/// `{"kind":"genesis","evil":"payload"}` would decode successfully with a
/// unit `Genesis` and silently drop the unknown field. A struct variant,
/// even an empty one, IS deserialized through serde's normal
/// field-checking machinery, so `deny_unknown_fields` applies exactly as it
/// does to `Checkpoint`. This changes nothing on the wire: an empty struct
/// variant serializes identically to a unit variant under internal tagging
/// — `{"kind":"genesis"}` — so every existing fixture byte is unaffected;
/// see `replay_from_genesis_unit_variant_rejects_unknown_fields` for the
/// pinned proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReplayFrom {
    Genesis {},
    Checkpoint { checkpoint_digest: Sha256Digest },
}

/// `semantic_replay_from` is the earliest point full semantic identity can
/// be reproduced; `historical_content_available_from` is the earliest point
/// raw historical content is still materializable.
///
/// The historical bound may be strictly later than the semantic one
/// (private raw payloads and archive tiers can retire before semantic
/// identity does). Neither field may be omitted or defaulted.
///
/// A decoded `ReplayHorizonV1` is schema-shaped bytes, not an admitted
/// claim: `semantic_replay_from` is a bare digest on the wire, and this
/// crate is a pure leaf with no ambient authority to look up whether that
/// digest actually names a real, independently verified evidence-compaction
/// checkpoint. The private `validate_shape` helper therefore checks only
/// well-formedness and is deliberately not `pub`. The only public entry
/// point that decides
/// whether a horizon may be trusted is [`Self::validate_semantic_anchor`],
/// which requires a [`VerifiedReplayAnchorV1`] whenever
/// `semantic_replay_from` names a checkpoint — and a `VerifiedReplayAnchorV1`
/// is obtainable only from [`VerifiedReplayAnchorV1::from_checkpoint`], which
/// only compiles against an `&EvidenceCompactionCheckpointV1`. A
/// `ProjectorCheckpointV1`'s digest can be written into the wire bytes by an
/// attacker, but it can never satisfy `validate_semantic_anchor`: the
/// independently-derived anchor digest it is compared against cannot equal a
/// digest produced under a different digest domain except by a SHA-256
/// preimage collision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayHorizonV1 {
    pub schema_version: u32,
    pub semantic_replay_from: ReplayFrom,
    pub historical_content_available_from: ReplayFrom,
}

impl ReplayHorizonV1 {
    /// Schema well-formedness only. Not sufficient on its own to trust a
    /// decoded horizon — see [`Self::validate_semantic_anchor`].
    fn validate_shape(&self) -> ContractResult<()> {
        if self.schema_version != LEDGER_EPOCH_SCHEMA_VERSION {
            return Err(ContractError::Schema("invalid replay horizon".into()));
        }
        Ok(())
    }

    /// The only admission check a runtime should treat as "this horizon may
    /// be trusted." A `Genesis` semantic bound needs no anchor. A
    /// `Checkpoint` semantic bound requires `anchor` to be present and its
    /// independently-derived [`VerifiedReplayAnchorV1::checkpoint_digest`] to
    /// equal the digest carried on the wire; anything else — including a
    /// missing anchor, or an anchor derived from a different checkpoint —
    /// fails closed.
    pub fn validate_semantic_anchor(
        &self,
        anchor: Option<&VerifiedReplayAnchorV1>,
    ) -> ContractResult<()> {
        self.validate_shape()?;
        match self.semantic_replay_from {
            ReplayFrom::Genesis {} => Ok(()),
            ReplayFrom::Checkpoint { checkpoint_digest } => {
                let anchor = anchor.ok_or_else(|| {
                    ContractError::Schema(
                        "checkpoint-anchored semantic replay requires an independently \
                         verified replay anchor"
                            .into(),
                    )
                })?;
                if anchor.checkpoint_digest() != checkpoint_digest {
                    return Err(ContractError::Schema(
                        "semantic replay checkpoint digest is not backed by the supplied \
                         verified replay anchor"
                            .into(),
                    ));
                }
                Ok(())
            }
        }
    }

    /// Bound `semantic_replay_from` to one independently replay-verified
    /// checkpoint. This is the only constructor that can produce a
    /// `Checkpoint` semantic bound, and it requires a
    /// [`VerifiedReplayAnchorV1`] — obtainable only from an
    /// [`EvidenceCompactionCheckpointV1`] whose receipt already checked out.
    /// A horizon built this way always passes
    /// `validate_semantic_anchor(Some(anchor))` against that same anchor.
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
            semantic_replay_from: ReplayFrom::Genesis {},
            historical_content_available_from,
        }
    }
}

#[cfg(test)]
#[path = "ledger_epoch_tests.rs"]
mod tests;
