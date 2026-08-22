//! Repository contract and value shapes for the coverage runtime (COVER-01..03).
//!
//! The coverage runtime persists, per connector instance and coverage domain,
//! a durable cursor (the merged [`ObservedRangeV1`] of everything observed so
//! far) and, each time an observation extends that range, a coverage receipt
//! row (COVER-01). A cursor advance and its receipt row are written in ONE
//! serializable transaction, exactly as [`crate::relation_projection`] advances
//! its projection and watermark together (EVENT-03, REPLAY-02): a crash leaves
//! neither. Re-observing an already-covered range is idempotent — no duplicate
//! receipt and no cursor regression.

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::Result;
use crate::memory_contracts::common::{CanonicalTimestamp, ContractId};
use crate::memory_contracts::coverage::{
    CoverageCompletenessV1, CoverageProofBasisV1, CoverageReceiptId, CoverageReceiptV1,
    CoverageScopeV1, CoverageWatermarkV1, ProducerIdentityV1,
};
use crate::memory_contracts::digest::Sha256Digest;
use crate::memory_contracts::evidence::AcceptedEventId;

use super::observed_range::{ObservedRangeV1, SequenceIntervalV1};

/// The `schema_version` every coverage receipt this runtime mints carries.
pub const COVERAGE_RECEIPT_SCHEMA_VERSION: u32 = 1;

/// One observation delivered by a connector instance.
///
/// The observation names the coverage *domain* (which connector instance, which
/// scope/revision/window, and the full target provider-sequence range it is
/// expected to cover) plus the sub-range `observed` this delivery, and the
/// receipt evidence and proof metadata the resulting receipt is stamped with.
///
/// `evidence_id` binds the receipt to an accepted event minted by the W1-APPEND
/// accepted-event path; a zero digest is rejected closed, exactly as the
/// coverage contract rejects a zero `evidence_id` (COVER-03).
#[derive(Debug, Clone)]
pub struct CoverageObservationV1 {
    /// Exact connector instance the cursor and receipt are keyed to.
    pub connector_instance: ContractId,
    /// Producer identity stamped into the receipt (exact executable/version).
    pub producer: ProducerIdentityV1,
    /// Scope, revision, and covered time window.
    pub scope: CoverageScopeV1,
    /// The full provider-sequence range this domain is expected to cover.
    pub target: SequenceIntervalV1,
    /// The provider-sequence sub-range observed by this delivery.
    pub observed: SequenceIntervalV1,
    /// Freshness state under a registered rule.
    pub freshness: crate::memory_contracts::coverage::CoverageFreshnessV1,
    /// Coverage proof basis under a registered method.
    pub proof_basis: CoverageProofBasisV1,
    /// Digest of the observed source material.
    pub source_digest: Sha256Digest,
    /// Count of observed source records.
    pub source_count: u32,
    /// Accepted event this observation was derived from.
    pub evidence_id: AcceptedEventId,
    /// Clock the observation ran through (must reach the window end).
    pub observed_through: CanonicalTimestamp,
}

/// What one [`CoverageRuntimeRepository::observe`] call did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoverageObservationOutcome {
    /// The observation extended coverage: the cursor advanced and a receipt
    /// row was written in the same transaction.
    Recorded {
        /// Identity of the minted receipt.
        receipt_id: CoverageReceiptId,
        /// Completeness the receipt records after this advance.
        completeness: CoverageCompletenessV1,
        /// Whether the receipt records a detected sequence gap (COVER-03).
        gap_detected: bool,
        /// The cursor's advance counter after this observation.
        observation_seq: u64,
    },
    /// The observation was already wholly covered: no receipt was written and
    /// the cursor did not move (idempotent re-observation).
    AlreadyCovered {
        /// The cursor's unchanged advance counter.
        observation_seq: u64,
    },
}

/// A persisted coverage-cursor row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageCursorRowV1 {
    /// The merged union of every observed interval for this domain.
    pub observed: ObservedRangeV1,
    /// The target provider-sequence range the cursor tracks.
    pub target: SequenceIntervalV1,
    /// How many observations have advanced this cursor.
    pub observation_seq: u64,
    /// Completeness recorded by the most recent advance.
    pub last_completeness: CoverageCompletenessV1,
    /// Identity of the most recent receipt, if any advance has happened.
    pub last_receipt_id: Option<CoverageReceiptId>,
    /// Server clock of the most recent write.
    pub updated_at: DateTime<Utc>,
}

/// A persisted coverage-receipt row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageReceiptRowV1 {
    /// Identity of the receipt (the coverage contract's `receipt_id`).
    pub receipt_id: CoverageReceiptId,
    /// Completeness recorded by the receipt.
    pub completeness: CoverageCompletenessV1,
    /// Accepted event the receipt binds.
    pub evidence_id: AcceptedEventId,
    /// Count of observed source records at the time of the receipt.
    pub source_count: u32,
    /// The cursor advance counter that produced this receipt.
    pub observation_seq: u64,
    /// The full canonical receipt bytes (its `receipt_id` preimage).
    pub canonical_receipt: Vec<u8>,
    /// Server clock at which the receipt row was written.
    pub created_at: DateTime<Utc>,
}

/// Coverage runtime append and read surface, bound once to physical and
/// semantic scope exactly like [`crate::evidence_ledger::AcceptedEventRepository`].
#[async_trait]
pub trait CoverageRuntimeRepository: Send + Sync {
    /// Apply one observation. In ONE serializable transaction this locks the
    /// domain's cursor row, merges the observed interval, and — only when that
    /// extends coverage — writes a coverage receipt row and advances the
    /// cursor together (COVER-01, EVENT-03). A wholly-covered observation is an
    /// idempotent no-op ([`CoverageObservationOutcome::AlreadyCovered`]).
    async fn observe(
        &self,
        observation: &CoverageObservationV1,
    ) -> Result<CoverageObservationOutcome>;

    /// Read the persisted cursor for one coverage domain, if it exists.
    async fn read_cursor(
        &self,
        connector_instance: &ContractId,
        scope: &CoverageScopeV1,
        target: SequenceIntervalV1,
    ) -> Result<Option<CoverageCursorRowV1>>;

    /// Read one persisted receipt row by its identity, if it exists.
    async fn read_receipt(
        &self,
        receipt_id: CoverageReceiptId,
    ) -> Result<Option<CoverageReceiptRowV1>>;

    /// Count the receipt rows written for one connector instance. Used by the
    /// idempotency proof: re-observing a covered range must not grow this.
    async fn count_receipts_for_instance(&self, connector_instance: &ContractId) -> Result<u64>;
}

/// Build the canonical coverage receipt for `observation` given the merged
/// observed range AFTER this observation was inserted.
///
/// The completeness and continuity are derived from the merged range against
/// the target (never from a caller-supplied field), and the receipt's own
/// [`CoverageReceiptV1::validate`] is run via `receipt_id`, so a receipt whose
/// `observed_through` does not reach the window end, or that carries a zero
/// source/evidence digest, fails closed here (COVER-02, COVER-03) rather than
/// reaching the database.
pub(super) fn build_receipt(
    observation: &CoverageObservationV1,
    merged: &ObservedRangeV1,
) -> Result<(CoverageReceiptV1, CoverageReceiptId)> {
    let completeness = merged.completeness_over(observation.target);
    let continuity = merged.continuity_over(observation.target);
    let sequence = merged.high_watermark().unwrap_or(observation.observed.end);
    let receipt = CoverageReceiptV1 {
        schema_version: COVERAGE_RECEIPT_SCHEMA_VERSION,
        producer: observation.producer.clone(),
        scope: observation.scope.clone(),
        watermark: CoverageWatermarkV1::ProviderSequence { sequence },
        completeness,
        freshness: observation.freshness.clone(),
        continuity,
        observed_through: observation.observed_through.clone(),
        proof_basis: observation.proof_basis.clone(),
        source_digest: observation.source_digest,
        source_count: observation.source_count,
        evidence_id: observation.evidence_id,
    };
    let receipt_id = receipt.receipt_id()?;
    Ok((receipt, receipt_id))
}
