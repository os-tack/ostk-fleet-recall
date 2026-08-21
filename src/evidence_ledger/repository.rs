//! Repository contract for the general accepted-event ledger.
//!
//! The repository binds its physical tenant/project coordinates and its exact
//! semantic scope once at construction, exactly like the control-log
//! repositories: a request-time routing field would be a payload-selected
//! authority path (EVID-04).

use std::sync::Arc;

use async_trait::async_trait;
use futures::future::BoxFuture;
use sqlx::{Postgres, Transaction};

use crate::memory_contracts::bootstrap::{AppendPositionV1, EpochId};
use crate::memory_contracts::digest::Sha256Digest;
use crate::memory_contracts::evidence::AcceptedEventId;
use crate::memory_contracts::quarantine::{QuarantineReasonV1, QuarantineRecordId};

use super::appendable::{AcceptedEventKindV1, AppendableAcceptedEvent};
use super::error::EvidenceAppendResult;
use super::witness::WriterAuthorityWitness;

/// What one `append` call did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppendOutcome {
    /// A new accepted event was written, the caller's projection ran, and the
    /// shard head advanced — all inside one serializable transaction
    /// (EVENT-03).
    Appended {
        /// `(epoch, shard, committed offset)` of the new event.
        position: AppendPositionV1,
        /// Shard chain digest after the append.
        chain_digest: Sha256Digest,
    },
    /// An event with this exact accepted-event ID and byte-identical canonical
    /// bytes already exists (EVENT-01: exact replay is a no-op).
    ///
    /// The projection closure is deliberately NOT re-run: EVENT-03 commits the
    /// projection in the same transaction as the original append, so it is
    /// already durable at the returned position. Re-running it would let a
    /// retried delivery repeat a lifecycle effect that the accepted event only
    /// ever had once. A projector that needs to rebuild state must replay from
    /// `memory_evidence_events`, which is the only authority (REPLAY-01).
    Replayed {
        /// `(epoch, shard, committed offset)` of the original append.
        position: AppendPositionV1,
    },
    /// The append was refused and a bounded dead-letter receipt was written to
    /// `memory_evidence_quarantine`. No event row was written and the shard
    /// head did not advance.
    Quarantined {
        /// Deterministic identity of the quarantine record.
        quarantine_id: QuarantineRecordId,
        /// Closed rejection cause.
        reason: QuarantineReasonV1,
    },
}

/// Bindings handed to a projection so it can key its rows by the accepted
/// event that produced them (ADR 0002 D3 writes `accepted_event_id`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProjectionContext {
    /// Which of the four Stage-4 kinds is being appended.
    pub kind: AcceptedEventKindV1,
    /// Semantic identity of the event being appended.
    pub accepted_event_id: AcceptedEventId,
    /// Physical coordinate the event is taking.
    pub position: AppendPositionV1,
    /// Shard chain digest after this append.
    pub chain_digest: Sha256Digest,
}

/// A caller-supplied projection committed atomically with its accepted event.
///
/// This is a trait rather than a bare closure because the append runs inside
/// [`crate::store::cockroach::with_serializable_retry`], whose operation is
/// `FnMut` and may re-run after a retryable serialization failure; a `FnOnce`
/// closure could not survive that. Implementations must therefore be
/// idempotent *within* one logical append: the transaction they wrote to is
/// rolled back before they are called again.
#[async_trait]
pub trait AppendProjection: Send + Sync {
    /// Write this stage's complete durable outputs, in this transaction only.
    ///
    /// REPLAY-02: a projector that maintains a cursor must advance it here, so
    /// the cursor and the output commit together.
    async fn project(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        context: ProjectionContext,
    ) -> EvidenceAppendResult<()>;
}

/// A projection that writes nothing.
///
/// Used by appenders whose only durable output is the accepted event itself,
/// and by the connected proofs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NoProjection;

#[async_trait]
impl AppendProjection for NoProjection {
    async fn project(
        &self,
        _transaction: &mut Transaction<'_, Postgres>,
        _context: ProjectionContext,
    ) -> EvidenceAppendResult<()> {
        Ok(())
    }
}

/// Adapter turning a plain function pointer into an [`AppendProjection`].
pub struct FnProjection<F>(pub F);

impl<F> std::fmt::Debug for FnProjection<F> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FnProjection")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl<F> AppendProjection for FnProjection<F>
where
    F: for<'transaction> Fn(
            &'transaction mut Transaction<'_, Postgres>,
            ProjectionContext,
        ) -> BoxFuture<'transaction, EvidenceAppendResult<()>>
        + Send
        + Sync,
{
    async fn project(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        context: ProjectionContext,
    ) -> EvidenceAppendResult<()> {
        (self.0)(transaction, context).await
    }
}

/// Exactly where a shard's stored chain first stops being self-consistent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShardChainDivergenceKind {
    /// No head row exists, so the shard has no auditable state at all. This is
    /// also what an audit of a never-seeded shard reports: the audit refuses to
    /// call an absent chain intact.
    MissingHead,
    /// Offsets are not the contiguous sequence `1..=head`.
    OffsetGap,
    /// A row's `previous_chain_digest` is not its predecessor's digest.
    PreviousChainMismatch,
    /// A row's `chain_digest` is not the recomputed append-chain digest.
    ChainDigestMismatch,
    /// A row's `event_id` is not the accepted-event digest of its own bytes.
    EventIdMismatch,
    /// The head's `last_committed_offset` does not equal the last event.
    HeadOffsetMismatch,
    /// The head's `chain_digest` does not equal the last recomputed digest.
    HeadChainMismatch,
}

impl ShardChainDivergenceKind {
    /// Stable diagnostic label. Exhaustive over the closed enum.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MissingHead => "missing_head",
            Self::OffsetGap => "offset_gap",
            Self::PreviousChainMismatch => "previous_chain_mismatch",
            Self::ChainDigestMismatch => "chain_digest_mismatch",
            Self::EventIdMismatch => "event_id_mismatch",
            Self::HeadOffsetMismatch => "head_offset_mismatch",
            Self::HeadChainMismatch => "head_chain_mismatch",
        }
    }
}

/// The first divergence an audit found, with the offset it was found at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShardChainDivergence {
    /// Offset of the first non-reproducing row, or the head's offset when the
    /// divergence is in the head row itself.
    pub committed_offset: u64,
    /// What did not reproduce.
    pub kind: ShardChainDivergenceKind,
}

/// Result of re-deriving one evidence shard's chain from offset one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShardChainAudit {
    /// Epoch the shard belongs to.
    pub epoch_id: EpochId,
    /// Shard number audited.
    pub shard: u16,
    /// `last_committed_offset` the head reports.
    pub head_offset: u64,
    /// `chain_digest` the head reports.
    pub head_chain_digest: Sha256Digest,
    /// Offset-zero digest the audit derived independently.
    pub genesis_chain_digest: Sha256Digest,
    /// How many rows reproduced before the first divergence (or in total).
    pub verified_events: u64,
    /// `None` when every row and the head reproduce exactly.
    pub divergence: Option<ShardChainDivergence>,
}

impl ShardChainAudit {
    /// Whether the whole shard reproduced.
    #[must_use]
    pub const fn is_intact(&self) -> bool {
        self.divergence.is_none()
    }
}

/// Append and audit surface of the general accepted-event ledger.
#[async_trait]
pub trait AcceptedEventRepository: Send + Sync {
    /// Append one admitted accepted event and its projection atomically.
    ///
    /// The whole sequence — head witness re-read, shard derivation, lazy head
    /// seed, `FOR UPDATE` head lock, replay classification, event insert,
    /// caller projection, and head compare-and-swap — runs inside ONE
    /// serializable transaction (EVENT-03). Any failure rolls the whole thing
    /// back; a failed transaction publishes neither row nor offset.
    async fn append(
        &self,
        witness: &WriterAuthorityWitness,
        appendable: &AppendableAcceptedEvent,
        projection: Arc<dyn AppendProjection>,
    ) -> EvidenceAppendResult<AppendOutcome>;

    /// Re-derive one shard's chain from offset one and report the first
    /// divergence. This reads only the evidence plane, so it runs under the
    /// runtime's own least-privilege grants.
    async fn audit_shard_chain(
        &self,
        epoch_id: EpochId,
        shard: u16,
    ) -> EvidenceAppendResult<ShardChainAudit>;
}
