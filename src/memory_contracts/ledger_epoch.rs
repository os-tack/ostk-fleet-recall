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
/// generation to (a) name its exact predecessor's `generation_id`, (b) share
/// that predecessor's `projector_id` and `projector_version` exactly (a
/// generation is never superseded by a different projector or a different
/// version of the same one), (c) carry `generation_sequence` exactly one
/// past the predecessor's, and (d) strictly advance the predecessor's
/// barrier. Late evidence publishes a strictly later generation over a
/// strictly advanced barrier; the earlier generation's record and output are
/// never deleted (REPLAY-01, REPLAY-02).
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
    /// with a named predecessor — and `generation_id()` deliberately
    /// excludes `barrier`, `generation_sequence`, and `supersedes` from
    /// identity (see the type-level docs), so naming the right predecessor
    /// id alone says nothing about barrier dominance. Without this method a
    /// caller could publish a generation
    /// naming an unrelated projector's output as its successor, skip or
    /// regress `generation_sequence`, or publish a different `output_digest`
    /// over the identical closed barrier (rewriting "what happened" instead
    /// of recomputing it after strictly more evidence closed). This method
    /// is the required second check a runtime performs before admitting a
    /// superseding generation; a cross-projector, cross-version,
    /// non-consecutive-sequence, or same-or-earlier-barrier successor is
    /// rejected regardless of what `output_digest` it carries.
    pub fn validate_supersession(&self, predecessor: &Self) -> ContractResult<()> {
        self.validate()?;
        predecessor.validate()?;
        let predecessor_id = predecessor.generation_id()?;
        if self.supersedes != Some(predecessor_id) {
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
    const PROJECTION_GENERATION: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/ledger-epoch/projection-generation.jsonl"
    );
    const VECTOR_SUITE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v3/ledger-epoch/vector-suite.jsonl");
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
    const PROJECTOR_CHECKPOINT_DIGEST: &str =
        "8a44db6d8037225760678ea51a8f55db2fd6be63c0202cead1f2405e39fd333d";
    const CURSOR_BARRIER_DIGEST: &str =
        "231b09eb8bb020d4e7fa5fb6d17bac004e67d2d3a7ca912b805f71ec408252c4";
    const PROJECTION_GENERATION_ID: &str =
        "5d619c49cfceb87413a7dfb437feb0ab90ed5901918b9afc400b664b442dac82";

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
    fn epoch_fence_is_an_allow_list_not_a_deny_list() {
        let epoch = successor_epoch();
        let successor_id = epoch.epoch_id().unwrap();
        let fence = EpochFenceV1 {
            schema_version: 1,
            successor_epoch: epoch.clone(),
        };
        fence.validate().unwrap();

        // Attack B: an unknown/fabricated epoch id is not the fenced
        // predecessor, so a deny-list of exactly the predecessor would admit
        // it. The allow-list rejects anything that is not the successor.
        let fabricated = AppendPositionV1 {
            epoch_id: EpochId::from_digest(digest(
                "abababababababababababababababababababababababababababababababab",
            )),
            shard: 0,
            committed_offset: CommittedOffsetV1::new(7).unwrap(),
        };
        assert!(fence.reject_append_after_fence(&fabricated).is_err());

        // A grand-predecessor epoch (two cutovers back) is neither the
        // fenced predecessor nor the successor, and must also be rejected —
        // the "concurrent old-epoch append that loses the fence" case
        // applies to every earlier generation, not only the immediate one.
        let grand_predecessor = AppendPositionV1 {
            epoch_id: EpochId::from_digest(digest(
                "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
            )),
            shard: 0,
            committed_offset: CommittedOffsetV1::new(3).unwrap(),
        };
        assert!(fence.reject_append_after_fence(&grand_predecessor).is_err());

        // The fenced predecessor itself is still rejected.
        let at_predecessor = AppendPositionV1 {
            epoch_id: fence.predecessor_epoch_id(),
            shard: 0,
            committed_offset: CommittedOffsetV1::new(9).unwrap(),
        };
        assert!(fence.reject_append_after_fence(&at_predecessor).is_err());

        // A shard the successor epoch's own partition recipe never assigned
        // (shard_count is 32 here) is rejected even though the epoch id
        // matches.
        let shard_out_of_range = AppendPositionV1 {
            epoch_id: successor_id,
            shard: epoch.partition_recipe.shard_count,
            committed_offset: CommittedOffsetV1::new(1).unwrap(),
        };
        assert!(
            fence
                .reject_append_after_fence(&shard_out_of_range)
                .is_err()
        );

        // Only a position naming exactly the successor epoch and a shard
        // within its recipe is admitted.
        let admitted = AppendPositionV1 {
            epoch_id: successor_id,
            shard: epoch.partition_recipe.shard_count - 1,
            committed_offset: CommittedOffsetV1::new(1).unwrap(),
        };
        assert!(fence.reject_append_after_fence(&admitted).is_ok());
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
        horizon.validate_semantic_anchor(Some(&anchor)).unwrap();
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
        assert_eq!(encode_canonical(&projector).unwrap(), projector_golden);
        assert!(decode_strict::<EvidenceCompactionCheckpointV1>(projector_golden).is_err());
        assert!(decode_strict::<ProjectorCheckpointV1>(golden).is_err());
    }

    #[test]
    fn projector_checkpoint_digest_can_never_satisfy_a_semantic_replay_anchor() {
        // Attack: take a real ProjectorCheckpointV1's checkpoint_digest() and
        // present it as a ReplayHorizonV1's semantic_replay_from, then round
        // trip through the exact wire path a runtime uses (encode -> decode
        // -> validate). The bare digest decodes fine — it is schema-valid
        // bytes — but the type-level guarantee lives in
        // validate_semantic_anchor, not in decode_strict/validate_shape.
        let projector: ProjectorCheckpointV1 = decode_strict(record(PROJECTOR_CHECKPOINT)).unwrap();
        let forged_digest = projector.checkpoint_digest().unwrap();

        let forged_horizon = ReplayHorizonV1 {
            schema_version: LEDGER_EPOCH_SCHEMA_VERSION,
            semantic_replay_from: ReplayFrom::Checkpoint {
                checkpoint_digest: forged_digest,
            },
            historical_content_available_from: ReplayFrom::Genesis {},
        };
        let wire_bytes = encode_canonical(&forged_horizon).unwrap();
        let redecoded: ReplayHorizonV1 = decode_strict(&wire_bytes).unwrap();
        assert_eq!(redecoded, forged_horizon);

        // No anchor at all: rejected, not silently accepted as genesis.
        assert!(redecoded.validate_semantic_anchor(None).is_err());

        // A real anchor, but for a *different* (evidence-compaction)
        // checkpoint: the digests disagree, so this is rejected too. This is
        // the only anchor obtainable from this crate's public API — there is
        // no way to construct a VerifiedReplayAnchorV1 whose
        // checkpoint_digest() equals a ProjectorCheckpointV1's, short of a
        // SHA-256 preimage collision across the two digest domains.
        let checkpoint: EvidenceCompactionCheckpointV1 =
            decode_strict(record(EVIDENCE_COMPACTION_CHECKPOINT)).unwrap();
        let real_anchor = VerifiedReplayAnchorV1::from_checkpoint(&checkpoint).unwrap();
        assert_ne!(real_anchor.checkpoint_digest(), forged_digest);
        assert!(
            redecoded
                .validate_semantic_anchor(Some(&real_anchor))
                .is_err()
        );
    }

    #[test]
    fn replay_from_genesis_unit_variant_rejects_unknown_fields() {
        // Before this fix, serde's `#[serde(deny_unknown_fields)]` had no
        // effect on the unit variant of an internally tagged enum: the
        // variant is deserialized by a `void` visitor that never inspects a
        // payload, so an unknown field smuggled into a `"kind":"genesis"`
        // object decoded successfully and was silently dropped. `Genesis`
        // is now the empty struct variant `Genesis {}`, which goes through
        // serde's normal field-checking machinery -- exactly like
        // `Checkpoint` already did -- so the same attack must now fail
        // closed through the exact runtime decode path (`decode_strict`).
        let honest = br#"{"historical_content_available_from":{"kind":"genesis"},"schema_version":1,"semantic_replay_from":{"kind":"genesis"}}"#;
        let decoded: ReplayHorizonV1 = decode_strict(honest).unwrap();
        assert_eq!(decoded.semantic_replay_from, ReplayFrom::Genesis {});
        assert_eq!(
            decoded.historical_content_available_from,
            ReplayFrom::Genesis {}
        );
        // The wire bytes for the empty struct variant are identical to the
        // unit-variant bytes it replaces: `{"kind":"genesis"}`, no change
        // to any existing fixture.
        assert_eq!(encode_canonical(&decoded).unwrap(), honest);

        let smuggled_semantic = br#"{"historical_content_available_from":{"kind":"genesis"},"schema_version":1,"semantic_replay_from":{"evil":"payload","kind":"genesis"}}"#;
        assert!(decode_strict::<ReplayHorizonV1>(smuggled_semantic).is_err());

        // Both positions a `ReplayFrom::Genesis {}` can appear in are
        // covered, not just `semantic_replay_from`.
        let smuggled_historical = br#"{"historical_content_available_from":{"evil":"payload","kind":"genesis"},"schema_version":1,"semantic_replay_from":{"kind":"genesis"}}"#;
        assert!(decode_strict::<ReplayHorizonV1>(smuggled_historical).is_err());

        // The struct variant `Checkpoint` was already protected; pinned
        // here for parity so both arms of the enum are proven under one
        // test.
        let smuggled_checkpoint = br#"{"historical_content_available_from":{"kind":"genesis"},"schema_version":1,"semantic_replay_from":{"checkpoint_digest":"1111111111111111111111111111111111111111111111111111111111111111","evil":"payload","kind":"checkpoint"}}"#;
        assert!(decode_strict::<ReplayHorizonV1>(smuggled_checkpoint).is_err());
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
        assert_eq!(encode_canonical(&barrier).unwrap(), golden);
        let first_digest = barrier.barrier_digest().unwrap();

        // Genuinely reversed arrival: feed the same per-shard observations
        // to the normalizing constructor in the opposite order the golden
        // fixture lists them in. Unlike reversing an already-sorted vector
        // and resorting it (which is the identity function on sorted input),
        // this exercises a real different construction order through the
        // one API a projector actually has for turning arrival-order
        // observations into a canonical barrier.
        let mut scrambled_order: Vec<ShardCursorEntryV1> = barrier.cursors.clone();
        scrambled_order.reverse();
        assert_ne!(
            scrambled_order.first().unwrap().shard,
            barrier.cursors.first().unwrap().shard,
            "the golden fixture must have more than one shard for this to be a real reversal"
        );
        let from_scrambled =
            CursorVectorBarrierV1::from_observations(barrier.epoch_id, scrambled_order).unwrap();
        assert_eq!(from_scrambled, barrier);
        assert_eq!(from_scrambled.barrier_digest().unwrap(), first_digest);

        // Duplicate shards can never legitimately arise from one fence.
        let mut duplicated = barrier.cursors.clone();
        duplicated.push(duplicated[0]);
        assert_eq!(
            CursorVectorBarrierV1::from_observations(barrier.epoch_id, duplicated),
            Err(ContractError::NonCanonicalSet { field: "cursors" })
        );

        let generation: ProjectionGenerationV1 =
            decode_strict(record(PROJECTION_GENERATION)).unwrap();
        generation.validate().unwrap();
        assert_eq!(generation.barrier, barrier);
        let first_generation_id = generation.generation_id().unwrap();

        let same_facts_reversed = ProjectionGenerationV1 {
            barrier: from_scrambled,
            ..generation.clone()
        };
        assert_eq!(
            same_facts_reversed.generation_id().unwrap(),
            first_generation_id
        );

        // Attack J reproduction, now as a passing rejection: a "later"
        // generation over the identical closed barrier — different output,
        // same facts — must be rejected. Late evidence means an advanced
        // cursor vector, never a rewritten output over the same closed one.
        let mut same_barrier_rewrite = generation.clone();
        same_barrier_rewrite.generation_sequence = 1;
        same_barrier_rewrite.supersedes = Some(first_generation_id);
        same_barrier_rewrite.output_digest =
            digest("7777777777777777777777777777777777777777777777777777777777777777");
        same_barrier_rewrite.validate().unwrap();
        assert!(
            same_barrier_rewrite
                .validate_supersession(&generation)
                .is_err()
        );

        // A genuinely advanced barrier — one shard strictly past its
        // predecessor's offset, the other unchanged, same shard set and
        // epoch — is accepted, and the earlier generation's own record and
        // id remain valid and unaffected.
        let mut advanced_cursors = barrier.cursors.clone();
        advanced_cursors[0].last_processed_offset =
            CommittedOffsetV1::new(advanced_cursors[0].last_processed_offset.as_u64() + 1).unwrap();
        let advanced_barrier =
            CursorVectorBarrierV1::from_observations(barrier.epoch_id, advanced_cursors).unwrap();
        let mut later = generation.clone();
        later.generation_sequence = 1;
        later.supersedes = Some(first_generation_id);
        later.barrier = advanced_barrier;
        later.output_digest =
            digest("7777777777777777777777777777777777777777777777777777777777777777");
        later.validate().unwrap();
        later.validate_supersession(&generation).unwrap();
        assert_ne!(later.generation_id().unwrap(), first_generation_id);
        // The earlier generation is preserved, not superseded away: its own
        // digest and validation are unaffected by the later record existing.
        assert_eq!(generation.generation_id().unwrap(), first_generation_id);
        generation.validate().unwrap();

        // A barrier that regresses any shard is rejected outright.
        let mut regressed_cursors = barrier.cursors.clone();
        regressed_cursors[0].last_processed_offset = CommittedOffsetV1::new(1).unwrap();
        let regressed_barrier =
            CursorVectorBarrierV1::from_observations(barrier.epoch_id, regressed_cursors).unwrap();
        let mut regressed = generation.clone();
        regressed.generation_sequence = 1;
        regressed.supersedes = Some(first_generation_id);
        regressed.barrier = regressed_barrier;
        regressed.output_digest =
            digest("7777777777777777777777777777777777777777777777777777777777777777");
        regressed.validate().unwrap();
        assert!(regressed.validate_supersession(&generation).is_err());

        let mut inconsistent = generation;
        inconsistent.generation_sequence = 1;
        assert!(inconsistent.validate().is_err());
    }

    #[test]
    fn projection_generation_supersession_binds_projector_identity_and_sequence() {
        // Attack 1 reproduction, now as a passing rejection: a hostile
        // projector must never be able to supersede another projector's
        // generation, even with a strictly-advanced barrier and the correct
        // predecessor id.
        let g0: ProjectionGenerationV1 = decode_strict(record(PROJECTION_GENERATION)).unwrap();
        let g0_id = g0.generation_id().unwrap();

        let mut advanced_cursors = g0.barrier.cursors.clone();
        advanced_cursors[0].last_processed_offset =
            CommittedOffsetV1::new(advanced_cursors[0].last_processed_offset.as_u64() + 1).unwrap();
        let advanced_barrier =
            CursorVectorBarrierV1::from_observations(g0.barrier.epoch_id, advanced_cursors)
                .unwrap();

        let hostile_projector = ProjectionGenerationV1 {
            projector_id: ContractId::new("projector.hostile.other").unwrap(),
            barrier: advanced_barrier.clone(),
            generation_sequence: 1,
            output_digest: digest(
                "7777777777777777777777777777777777777777777777777777777777777777",
            ),
            supersedes: Some(g0_id),
            ..g0
        };
        hostile_projector.validate().unwrap();
        assert!(
            hostile_projector.validate_supersession(&g0).is_err(),
            "a different projector must never supersede another projector's generation"
        );

        // A projector-version bump is not, by default, an admitted
        // supersession either. If a future workstream wants to allow one, it
        // must be an explicit, separately named and separately tested
        // admission rule, never this default check.
        let hostile_version = ProjectionGenerationV1 {
            projector_version: g0.projector_version + 1,
            barrier: advanced_barrier.clone(),
            generation_sequence: 1,
            output_digest: digest(
                "7777777777777777777777777777777777777777777777777777777777777777",
            ),
            supersedes: Some(g0_id),
            ..g0.clone()
        };
        hostile_version.validate().unwrap();
        assert!(
            hostile_version.validate_supersession(&g0).is_err(),
            "a differing projector_version must never supersede by default"
        );

        // Attack 2 reproduction, now as a passing rejection: build a
        // legitimate predecessor `mid` at a high sequence number, then show
        // a lower, equal, and skipped sequence are all rejected as its
        // successor — not just a same-or-earlier barrier.
        let mid = ProjectionGenerationV1 {
            barrier: advanced_barrier.clone(),
            generation_sequence: 50,
            output_digest: digest(
                "7777777777777777777777777777777777777777777777777777777777777777",
            ),
            supersedes: Some(g0_id),
            ..g0.clone()
        };
        mid.validate().unwrap();
        let mid_id = mid.generation_id().unwrap();

        let mut further_cursors = advanced_barrier.cursors;
        further_cursors[1].last_processed_offset =
            CommittedOffsetV1::new(further_cursors[1].last_processed_offset.as_u64() + 1).unwrap();
        let further_barrier =
            CursorVectorBarrierV1::from_observations(g0.barrier.epoch_id, further_cursors).unwrap();

        let build_successor = |generation_sequence: u64| ProjectionGenerationV1 {
            barrier: further_barrier.clone(),
            generation_sequence,
            output_digest: digest(
                "8888888888888888888888888888888888888888888888888888888888888888",
            ),
            supersedes: Some(mid_id),
            ..g0.clone()
        };

        // Regression: mid's own predecessor sequence (should be 51).
        let regressed_sequence = build_successor(1);
        regressed_sequence.validate().unwrap();
        assert!(
            regressed_sequence.validate_supersession(&mid).is_err(),
            "sequence regression (50 -> 1) must be rejected"
        );

        // Equal: repeating mid's own sequence is not an advance.
        let equal_sequence = build_successor(50);
        equal_sequence.validate().unwrap();
        assert!(
            equal_sequence.validate_supersession(&mid).is_err(),
            "an equal sequence must be rejected"
        );

        // Skipped: 52 instead of the required 51.
        let skipped_sequence = build_successor(52);
        skipped_sequence.validate().unwrap();
        assert!(
            skipped_sequence.validate_supersession(&mid).is_err(),
            "a skipped sequence must be rejected"
        );

        // Exactly one past mid's sequence, correct projector, strictly
        // advanced barrier: accepted.
        let correct_sequence = build_successor(51);
        correct_sequence.validate().unwrap();
        correct_sequence.validate_supersession(&mid).unwrap();
    }

    #[test]
    fn projection_generation_identity_is_independent_of_shard_schedule() {
        // REPLAY-01: "Processing the same facts in a different shard
        // schedule must produce the same generation." A genuine schedule
        // difference is not only a different `barrier`: it can change HOW
        // MANY intermediate generations a schedule needed to publish before
        // reaching the same total facts (a finer-grained shard schedule can
        // require an extra generation a coarser one does not). A test that
        // varies only `barrier` while holding `generation_sequence` and
        // `supersedes` fixed proves barrier-exclusion, which is true by
        // construction and cannot fail — it does not prove
        // schedule-independence. This test varies the publication history
        // itself: a one-generation schedule (sequence 0, no predecessor)
        // and a two-generation schedule's final record (sequence 1,
        // superseding an earlier generation) that reach the identical total
        // facts (`output_digest`) must produce the identical `generation_id`.
        let single_generation_schedule: ProjectionGenerationV1 =
            decode_strict(record(PROJECTION_GENERATION)).unwrap();
        single_generation_schedule.validate().unwrap();
        assert_eq!(
            single_generation_schedule.generation_sequence, 0,
            "the golden fixture must be an unsuperseded first generation"
        );
        assert_eq!(single_generation_schedule.supersedes, None);
        assert_eq!(
            single_generation_schedule.barrier.cursors.len(),
            2,
            "the golden fixture must be a genuine multi-shard barrier"
        );

        // A different shard schedule (different epoch, different shard
        // count/cursor set — a genuinely different barrier, not the same
        // one relabeled) whose SECOND published generation reaches the
        // SAME total facts as the golden schedule's ONLY generation.
        let one_shard_epoch = EpochId::from_digest(digest(
            "1111111111111111111111111111111111111111111111111111111111111111",
        ));
        let one_shard_barrier = CursorVectorBarrierV1::from_observations(
            one_shard_epoch,
            vec![ShardCursorEntryV1 {
                shard: 0,
                last_processed_offset: CommittedOffsetV1::new(14).unwrap(),
            }],
        )
        .unwrap();
        assert_ne!(
            one_shard_barrier.barrier_digest().unwrap(),
            single_generation_schedule.barrier.barrier_digest().unwrap(),
            "the two schedules must be genuinely different barriers, not the same one relabeled"
        );

        // Stand-in for "an earlier generation this schedule published
        // before reaching the golden total facts". Its own identity is
        // irrelevant beyond being distinct from the golden record's, since
        // this test's claim is about the SECOND (final) generation's id.
        let arbitrary_earlier_generation_id =
            digest("6666666666666666666666666666666666666666666666666666666666666666");

        let two_generation_schedule_final_record = ProjectionGenerationV1 {
            barrier: one_shard_barrier,
            generation_sequence: 1,
            supersedes: Some(arbitrary_earlier_generation_id),
            ..single_generation_schedule.clone()
        };
        two_generation_schedule_final_record.validate().unwrap();
        assert_ne!(
            two_generation_schedule_final_record.generation_sequence,
            single_generation_schedule.generation_sequence,
            "the two schedules must genuinely differ in publication history, not just barrier"
        );
        assert_ne!(
            two_generation_schedule_final_record.supersedes,
            single_generation_schedule.supersedes
        );

        assert_eq!(
            two_generation_schedule_final_record
                .generation_id()
                .unwrap(),
            single_generation_schedule.generation_id().unwrap(),
            "same total facts (same output_digest) under a different shard schedule -- including \
             a different number of intermediate generations needed to reach them -- must produce \
             the same generation id"
        );
    }

    #[test]
    fn projection_generation_matches_golden_bytes_and_id() {
        let golden = record(PROJECTION_GENERATION);
        require_canonical(golden).unwrap();
        let generation: ProjectionGenerationV1 = decode_strict(golden).unwrap();
        generation.validate().unwrap();
        assert_eq!(encode_canonical(&generation).unwrap(), golden);
        assert_eq!(
            generation.generation_id().unwrap(),
            digest(PROJECTION_GENERATION_ID)
        );
    }

    #[test]
    fn closed_head_vector_from_heads_normalizes_and_rejects_duplicates() {
        let closed = closed_predecessor_head();
        let mut scrambled = closed.heads.clone();
        scrambled.reverse();
        let from_scrambled = ClosedHeadVectorV1::from_heads(closed.epoch_id, scrambled).unwrap();
        assert_eq!(from_scrambled, closed);

        let mut duplicated = closed.heads.clone();
        duplicated.push(duplicated[0]);
        assert_eq!(
            ClosedHeadVectorV1::from_heads(closed.epoch_id, duplicated),
            Err(ContractError::NonCanonicalSet { field: "heads" })
        );
    }

    #[test]
    fn checkpoint_plus_tail_replay_reproduces_the_same_closed_vector() {
        let checkpoint: EvidenceCompactionCheckpointV1 =
            decode_strict(record(EVIDENCE_COMPACTION_CHECKPOINT)).unwrap();
        let epoch_id = checkpoint.core.epoch_id;

        // Tail: shard 0 advances past the checkpoint (11 -> 15), shard 5 is
        // untouched, and a shard the checkpoint had not yet closed (7)
        // closes for the first time in the tail.
        let tail = vec![
            ClosedShardHeadV1 {
                shard: 0,
                last_committed_offset: CommittedOffsetV1::new(15).unwrap(),
                chain_digest: digest(
                    "3333333333333333333333333333333333333333333333333333333333333333",
                ),
            },
            ClosedShardHeadV1 {
                shard: 7,
                last_committed_offset: CommittedOffsetV1::new(3).unwrap(),
                chain_digest: digest(
                    "4444444444444444444444444444444444444444444444444444444444444444",
                ),
            },
        ];
        let replayed = checkpoint.core.replay_tail(&tail).unwrap();

        // A from-genesis full replay reaching the identical final shard
        // state builds the same vector directly.
        let full_replay = ClosedHeadVectorV1::from_heads(
            epoch_id,
            vec![
                ClosedShardHeadV1 {
                    shard: 0,
                    last_committed_offset: CommittedOffsetV1::new(15).unwrap(),
                    chain_digest: digest(
                        "3333333333333333333333333333333333333333333333333333333333333333",
                    ),
                },
                ClosedShardHeadV1 {
                    shard: 5,
                    last_committed_offset: CommittedOffsetV1::new(2).unwrap(),
                    chain_digest: digest(
                        "2222222222222222222222222222222222222222222222222222222222222222",
                    ),
                },
                ClosedShardHeadV1 {
                    shard: 7,
                    last_committed_offset: CommittedOffsetV1::new(3).unwrap(),
                    chain_digest: digest(
                        "4444444444444444444444444444444444444444444444444444444444444444",
                    ),
                },
            ],
        )
        .unwrap();
        assert_eq!(replayed, full_replay);
        assert_eq!(
            encode_canonical(&replayed).unwrap(),
            encode_canonical(&full_replay).unwrap()
        );

        // A tail that regresses a shard the checkpoint already closed fails
        // closed rather than silently rewriting history.
        let regressing_tail = vec![ClosedShardHeadV1 {
            shard: 0,
            last_committed_offset: CommittedOffsetV1::new(1).unwrap(),
            chain_digest: digest(
                "3333333333333333333333333333333333333333333333333333333333333333",
            ),
        }];
        assert!(checkpoint.core.replay_tail(&regressing_tail).is_err());

        // A tail entry naming a shard the checkpoint already closed, at the
        // IDENTICAL offset the checkpoint already recorded, but with a
        // DIFFERENT chain digest, is a forked append chain -- contested
        // input, not an advance -- and must fail closed rather than being
        // silently substituted for the checkpoint's own closed head.
        let honest_shard0 = checkpoint
            .core
            .closed_shard_positions
            .heads
            .iter()
            .find(|head| head.shard == 0)
            .copied()
            .unwrap();
        let forked_tail = vec![ClosedShardHeadV1 {
            shard: 0,
            last_committed_offset: honest_shard0.last_committed_offset,
            chain_digest: digest(
                "dead00000000000000000000000000000000000000000000000000000000beef",
            ),
        }];
        assert_ne!(forked_tail[0].chain_digest, honest_shard0.chain_digest);
        assert!(checkpoint.core.replay_tail(&forked_tail).is_err());

        // Equal offset AND equal chain digest is an idempotent no-op: the
        // checkpoint's own closed head, re-observed, is accepted and leaves
        // the resulting vector unchanged.
        let idempotent_tail = vec![honest_shard0];
        let replayed_noop = checkpoint.core.replay_tail(&idempotent_tail).unwrap();
        assert_eq!(replayed_noop, checkpoint.core.closed_shard_positions);
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
        let genesis_only = ReplayHorizonV1::genesis(ReplayFrom::Genesis {});
        // A genesis semantic bound needs no anchor at all.
        genesis_only.validate_semantic_anchor(None).unwrap();
        assert_eq!(genesis_only.semantic_replay_from, ReplayFrom::Genesis {});
        assert_eq!(
            genesis_only.historical_content_available_from,
            ReplayFrom::Genesis {}
        );

        let checkpoint: EvidenceCompactionCheckpointV1 =
            decode_strict(record(EVIDENCE_COMPACTION_CHECKPOINT)).unwrap();
        let anchor = VerifiedReplayAnchorV1::from_checkpoint(&checkpoint).unwrap();
        let bounded = ReplayHorizonV1::anchored(&anchor, ReplayFrom::Genesis {});
        // A checkpoint semantic bound is rejected without its anchor...
        assert!(bounded.validate_semantic_anchor(None).is_err());
        // ...and accepted with the exact anchor it was built from.
        bounded.validate_semantic_anchor(Some(&anchor)).unwrap();
        assert_ne!(bounded.semantic_replay_from, ReplayFrom::Genesis {});
        assert_eq!(
            bounded.semantic_replay_from,
            ReplayFrom::Checkpoint {
                checkpoint_digest: anchor.checkpoint_digest()
            }
        );
    }

    /// A record decoded from a `.jsonl` fixture, matching the shape
    /// `vector-suite.jsonl` itself advertises. Keys are sorted for the same
    /// reason every other fixture's keys are: this is a canonical JSON
    /// document like any other, and it is round-tripped through
    /// `encode_canonical`/`decode_strict` below.
    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LedgerEpochVectorSuiteV1 {
        archive_segment_manifest_digest: Sha256Digest,
        cursor_vector_barrier_digest: Sha256Digest,
        evidence_compaction_core_digest: Sha256Digest,
        fixture_authority: String,
        invariants: Vec<String>,
        negative_fixtures: Vec<String>,
        positive_fixtures: Vec<String>,
        projection_generation_id: Sha256Digest,
        projector_checkpoint_digest: Sha256Digest,
        schema_version: u32,
        successor_log_epoch_id: Sha256Digest,
        topic: String,
    }

    #[test]
    fn every_w0_log_digest_domain_is_pinned_by_a_hard_coded_hex_constant() {
        // Every one of the six digest domains this workstream reserved
        // (LogEpochV2, EvidenceCompactionCheckpointV1, ProjectorCheckpointV1,
        // ArchiveSegmentManifestV1, CursorVectorV1, ProjectionGenerationV1)
        // is exercised here by recomputing its golden fixture's digest and
        // comparing it to a hard-coded hex constant. Renaming any one of the
        // six `DigestDomain::prefix()` strings changes exactly one of these
        // recomputed digests and fails this test.
        let epoch: SuccessorLogEpochV1 = decode_strict(record(SUCCESSOR_LOG_EPOCH)).unwrap();
        assert_eq!(
            epoch.epoch_id().unwrap().digest(),
            digest(SUCCESSOR_LOG_EPOCH_ID)
        );

        let checkpoint: EvidenceCompactionCheckpointV1 =
            decode_strict(record(EVIDENCE_COMPACTION_CHECKPOINT)).unwrap();
        assert_eq!(
            checkpoint.core.core_digest().unwrap(),
            digest("8db62c9381cc2a2e47855015adfe85baee5ab5a6980d3f7142e2c82499b83eef")
        );

        let projector: ProjectorCheckpointV1 = decode_strict(record(PROJECTOR_CHECKPOINT)).unwrap();
        assert_eq!(
            projector.checkpoint_digest().unwrap(),
            digest(PROJECTOR_CHECKPOINT_DIGEST)
        );

        let admission: ArchiveMoveAdmissionV1 =
            decode_strict(record(ARCHIVE_MOVE_ADMISSION)).unwrap();
        assert_eq!(
            admission.manifest.manifest_digest().unwrap(),
            digest("13269e974c56de1985af23bf0ce1ab8c048ef676d2ef8eac1182838de0d95086")
        );

        let barrier: CursorVectorBarrierV1 = decode_strict(record(CURSOR_VECTOR_BARRIER)).unwrap();
        assert_eq!(
            barrier.barrier_digest().unwrap(),
            digest(CURSOR_BARRIER_DIGEST)
        );

        let generation: ProjectionGenerationV1 =
            decode_strict(record(PROJECTION_GENERATION)).unwrap();
        generation.validate().unwrap();
        assert_eq!(
            generation.barrier.barrier_digest().unwrap(),
            digest(CURSOR_BARRIER_DIGEST)
        );
        assert_eq!(
            generation.generation_id().unwrap(),
            digest(PROJECTION_GENERATION_ID)
        );
    }

    #[test]
    fn vector_suite_is_byte_frozen_and_advertises_every_pinned_digest() {
        let golden = record(VECTOR_SUITE);
        require_canonical(golden).unwrap();

        let expected = LedgerEpochVectorSuiteV1 {
            archive_segment_manifest_digest: digest(
                "13269e974c56de1985af23bf0ce1ab8c048ef676d2ef8eac1182838de0d95086",
            ),
            cursor_vector_barrier_digest: digest(CURSOR_BARRIER_DIGEST),
            evidence_compaction_core_digest: digest(
                "8db62c9381cc2a2e47855015adfe85baee5ab5a6980d3f7142e2c82499b83eef",
            ),
            fixture_authority:
                "none; structural fixtures are byte-exact contract vectors, not activated state"
                    .into(),
            invariants: ["REPLAY-01", "REPLAY-02", "EVENT-03", "EVID-01"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            negative_fixtures: [
                "negative-unsorted-head-vector.jsonl",
                "negative-missing-predecessor.jsonl",
                "negative-seed-shape.jsonl",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            positive_fixtures: [
                "successor-log-epoch.jsonl",
                "evidence-compaction-checkpoint.jsonl",
                "cursor-vector-barrier.jsonl",
                "projection-generation.jsonl",
                "projector-checkpoint.jsonl",
                "archive-move-admission.jsonl",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            projection_generation_id: digest(PROJECTION_GENERATION_ID),
            projector_checkpoint_digest: digest(PROJECTOR_CHECKPOINT_DIGEST),
            schema_version: 1,
            successor_log_epoch_id: digest(SUCCESSOR_LOG_EPOCH_ID),
            topic: "ledger-epoch".into(),
        };
        assert_eq!(encode_canonical(&expected).unwrap(), golden);

        let suite: LedgerEpochVectorSuiteV1 = decode_strict(golden).unwrap();
        assert_eq!(suite, expected);

        // Every digest the suite advertises is independently re-derived from
        // its own golden fixture (not merely copied) in
        // `every_w0_log_digest_domain_is_pinned_by_a_hard_coded_hex_constant`
        // above; this test additionally proves the suite file itself is
        // exactly reproducible and every field in it agrees with the
        // constants that test uses.
        assert!(
            suite
                .positive_fixtures
                .contains(&"projection-generation.jsonl".to_string())
        );
    }
}
