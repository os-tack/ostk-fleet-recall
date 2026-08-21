//! Repository contract for materializing migration 0018's
//! `memory_relation_projection_v1` and its watermark.

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::evidence_ledger::{AppendOutcome, EvidenceAppendResult, WriterAuthorityWitness};
use crate::memory_contracts::evidence::AcceptedEventId;
use crate::memory_contracts::relation::{
    RelationAttestationBasisV1, RelationAttestationEventV1, RelationAttestationVerdictV1,
    RelationFingerprint, RelationProjectionV1,
};

/// The `ledger_family` value every relation-projection watermark carries.
///
/// Relation attestations are appended only through the general accepted-event
/// (evidence) ledger, never the control ledger, so this is the only value
/// this module ever writes; the column's CHECK constraint also admits
/// `'control'` for a lane this module does not use.
pub const WATERMARK_LEDGER_FAMILY: &str = "evidence";

/// One persisted `memory_relation_projection_v1` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelationProjectionRowV1 {
    pub relation_fingerprint: RelationFingerprint,
    pub state: crate::memory_contracts::relation::RelationProjectionStateV1,
    /// Verdict of the attestation that produced this row's current
    /// `generation` (the most recently appended attestation for this
    /// fingerprint, not necessarily the currently active/verified one:
    /// `state` is the aggregate; these three fields are a compact pointer
    /// to what just happened).
    pub last_verdict: RelationAttestationVerdictV1,
    pub last_basis: RelationAttestationBasisV1,
    pub last_event_id: AcceptedEventId,
    pub generation: u64,
    pub updated_at: DateTime<Utc>,
}

/// One persisted `memory_relation_projection_watermarks_v1` row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelationProjectionWatermarkV1 {
    pub shard: u16,
    pub last_committed_offset: u64,
    pub updated_at: DateTime<Utc>,
}

/// Append and read surface for the relation-attestation projection.
///
/// Bound once to physical and semantic scope, exactly like
/// [`crate::evidence_ledger::AcceptedEventRepository`].
#[async_trait]
pub trait RelationProjectionRepository: Send + Sync {
    /// Append one `relation.attestation.accepted` event to the shared general
    /// accepted-event ledger and, in the SAME serializable transaction,
    /// re-derive and materialize `memory_relation_projection_v1` plus advance
    /// `memory_relation_projection_watermarks_v1` (EVENT-03, REPLAY-02).
    ///
    /// The projection is re-derived from the COMPLETE admitted history for
    /// `event.relation_fingerprint` read back from `memory_evidence_events`
    /// inside the same transaction, not folded incrementally from the prior
    /// persisted row — so every append is already the REPLAY-01 rebuild.
    async fn append_attestation(
        &self,
        witness: &WriterAuthorityWitness,
        event: &RelationAttestationEventV1,
    ) -> EvidenceAppendResult<AppendOutcome>;

    /// Read the current persisted projection row for one fingerprint.
    async fn read_projection(
        &self,
        relation_fingerprint: RelationFingerprint,
    ) -> EvidenceAppendResult<Option<RelationProjectionRowV1>>;

    /// Read the current persisted watermark for one shard.
    async fn read_watermark(
        &self,
        shard: u16,
    ) -> EvidenceAppendResult<Option<RelationProjectionWatermarkV1>>;

    /// Independently rebuild the full projection for one fingerprint directly
    /// from `memory_evidence_events`, outside any append transaction and
    /// without consulting the persisted row at all.
    ///
    /// REPLAY-01: after any committed append, this must agree with
    /// [`Self::read_projection`]'s `state` for the same fingerprint.
    async fn rebuild_projection(
        &self,
        relation_fingerprint: RelationFingerprint,
    ) -> EvidenceAppendResult<RelationProjectionV1>;
}
