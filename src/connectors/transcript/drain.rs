//! Drain the transcript outbox through the W1-EVID admission seam.
//!
//! ```text
//! staged outbox row
//!   -> decode candidate + locators   (strict canonical decode; no re-derivation)
//!   -> admit_evidence(ACTIVE package) (connector, identities, governance, scope)
//!   -> AppendableAcceptedEvent        (bound to the head witness)
//!   -> AcceptedEventRepository::append
//!        + GovernedContentProjection  (encrypted body)
//!        + mark the outbox row drained   <- SAME transaction (EVENT-03)
//!   -> CoverageRuntimeRepository::observe (COVER-01 receipt for the turn range)
//! ```
//!
//! # What this loop deliberately does not do
//!
//! It does not re-derive identity, re-classify, or re-decide governance: those
//! belong to [`admit_evidence`], which resolves them from the ACTIVE package.
//! The drain's job is to hand a staged candidate to that seam and to make the
//! ledger effect and the outbox state change atomic. A connector that is not in
//! the active package is refused there, not here — which is exactly why the
//! "connector not in the active package" case fails closed with nothing written.
//!
//! # Idempotency
//!
//! Re-draining an already-appended row re-derives the byte-identical accepted
//! event, so the ledger classifies it [`AppendOutcome::Replayed`] and does NOT
//! re-run the projection (EVENT-01). The row is then marked drained by a
//! separate idempotent update, because the projection that would have marked it
//! did not run. No duplicate event, no duplicate content object, no duplicate
//! coverage receipt.

use std::sync::Arc;

use crate::control_log::TrustedControlScope;
use crate::coverage_runtime::{CoverageObservationOutcome, CoverageRuntimeRepository};
use crate::evidence_ledger::{
    AcceptedEventRepository, ActiveStage4Package, AppendOutcome, AppendProjection,
    ContentKeyEncryptionKey, EvidenceAdmissionRequestV1, EvidenceDeliveryContextV1,
    EvidenceIngressLocatorsV1, GovernedContentProjection, ProjectionContext,
    WriterAuthorityWitness, admit_evidence,
};
use crate::memory_contracts::canonical::decode_strict;
use crate::memory_contracts::common::ContractId;
use crate::memory_contracts::coverage::{
    CoverageFreshnessV1, CoverageProofBasisV1, CoverageScopeV1, ProducerIdentityV1,
};
use crate::memory_contracts::digest::Sha256Digest;
use crate::memory_contracts::evidence::AcceptedEventId;
use crate::memory_contracts::evidence_v2::{EvidenceIngressCandidateV2, RepresentationLineageV2};

use super::cockroach::{CockroachTranscriptOutboxRepository, MARK_DRAINED_SQL};
use super::error::{TranscriptConnectorError, TranscriptConnectorResult};
use super::outbox::{TranscriptOutboxRepository, TranscriptOutboxRowV1};

/// Which staged rows one drain pass consumes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TranscriptDrainModeV1 {
    /// Production: only rows that have not been drained yet.
    Pending,
    /// Replay: every staged row, drained or not. Used to prove a re-drain is a
    /// no-op against the ledger rather than merely being skipped by a state
    /// column.
    ReplayAll,
}

/// Coverage metadata one drain pass stamps into the receipts it emits.
///
/// Every field here names a registered rule or method; the drain never invents
/// one, and the coverage runtime's own contract validation runs before any
/// receipt row is written (COVER-01..03).
#[derive(Debug, Clone)]
pub struct TranscriptCoverageBindingV1 {
    /// Producer identity stamped into every receipt.
    pub producer: ProducerIdentityV1,
    /// Scope, revision, and covered window of the coverage domain.
    pub scope: CoverageScopeV1,
    /// The full turn-ordinal range this connector instance is expected to cover.
    pub target: crate::coverage_runtime::SequenceIntervalV1,
    /// Freshness state under a registered rule.
    pub freshness: CoverageFreshnessV1,
    /// Coverage proof basis under a registered method.
    pub proof_basis: CoverageProofBasisV1,
    /// Clock the observation ran through.
    pub observed_through: crate::memory_contracts::common::CanonicalTimestamp,
}

/// What one drain pass did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TranscriptDrainSummaryV1 {
    /// Rows considered.
    pub rows_read: u64,
    /// Rows whose accepted event was newly appended.
    pub appended: u64,
    /// Rows the ledger classified as an exact replay (EVENT-01).
    pub replayed: u64,
    /// Coverage receipts written.
    pub receipts: u64,
    /// Coverage observations that were already wholly covered.
    ///
    /// A dead-lettered row has no counter here on purpose: a quarantine fails
    /// the whole pass with [`TranscriptConnectorError::Quarantined`], so it can
    /// never be a number an operator scrolls past.
    pub coverage_already_covered: u64,
}

/// The projection the append transaction runs: encrypt and store the governed
/// content object, then mark the staged row drained.
///
/// Both effects live in the append's own transaction, so the accepted event, its
/// content object, and the outbox state change are one atomic fact. A crash
/// between them is not expressible.
struct TranscriptDrainProjection {
    content: GovernedContentProjection,
    tenant_id: uuid::Uuid,
    project: String,
    outbox_id: Sha256Digest,
}

#[async_trait::async_trait]
impl AppendProjection for TranscriptDrainProjection {
    async fn project(
        &self,
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        context: ProjectionContext,
    ) -> crate::evidence_ledger::EvidenceAppendResult<()> {
        self.content.project(transaction, context).await?;
        let now: chrono::DateTime<chrono::Utc> =
            sqlx::query_scalar("SELECT pg_catalog.statement_timestamp()")
                .fetch_one(&mut **transaction)
                .await
                .map_err(|error| {
                    crate::evidence_ledger::EvidenceAppendError::Storage(
                        crate::FleetError::Database(error),
                    )
                })?;
        sqlx::query(MARK_DRAINED_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(self.outbox_id.as_bytes().to_vec())
            .bind(now)
            .execute(&mut **transaction)
            .await
            .map_err(|error| {
                crate::evidence_ledger::EvidenceAppendError::Storage(crate::FleetError::Database(
                    error,
                ))
            })?;
        Ok(())
    }
}

/// Everything one drain pass needs, bundled so adding an input is a visible,
/// reviewable change to a named contract.
pub struct TranscriptDrainRequest<'request> {
    /// The active package every candidate is admitted against.
    pub active: &'request ActiveStage4Package,
    /// The head witness the append re-reads under serializable isolation.
    pub witness: &'request WriterAuthorityWitness,
    /// The outbox holding the staged candidates.
    pub outbox: &'request CockroachTranscriptOutboxRepository,
    /// The accepted-event ledger.
    pub ledger: &'request dyn AcceptedEventRepository,
    /// The coverage runtime receipts are emitted through.
    pub coverage: &'request dyn CoverageRuntimeRepository,
    /// Physical and semantic scope of the governed content projection.
    pub trusted_scope: &'request TrustedControlScope,
    /// Key-encryption key for the governed content object.
    pub content_key: &'request ContentKeyEncryptionKey,
    /// Coverage metadata for the receipts this pass emits.
    pub coverage_binding: &'request TranscriptCoverageBindingV1,
    /// Which rows to consume.
    pub mode: TranscriptDrainModeV1,
    /// Upper bound on rows consumed in this pass.
    pub limit: u32,
}

/// Drain staged transcript candidates into accepted evidence events.
pub async fn drain_outbox(
    request: TranscriptDrainRequest<'_>,
) -> TranscriptConnectorResult<TranscriptDrainSummaryV1> {
    let rows = request
        .outbox
        .staged_rows(
            request.mode == TranscriptDrainModeV1::Pending,
            request.limit,
        )
        .await?;
    let mut summary = TranscriptDrainSummaryV1 {
        rows_read: u64::try_from(rows.len()).unwrap_or(u64::MAX),
        ..TranscriptDrainSummaryV1::default()
    };
    for row in &rows {
        let (outcome, accepted_event_id) = drain_one(&request, row).await?;
        match outcome {
            AppendOutcome::Appended { .. } => summary.appended += 1,
            AppendOutcome::Replayed { .. } => {
                summary.replayed += 1;
                // The projection did not re-run, so the state change it would
                // have made is applied here. Idempotent by construction: the
                // UPDATE only matches a row still marked pending.
                request.outbox.mark_drained(row.outbox_id).await?;
            }
            AppendOutcome::Quarantined {
                quarantine_id,
                reason,
            } => {
                // The ledger dead-lettered the event: no event row, no head
                // advance, no projection. The staged row therefore stays
                // PENDING and no coverage receipt is emitted — a quarantined
                // turn must never look covered. Fail the whole pass closed so
                // the operator sees it rather than a silently short summary.
                return Err(TranscriptConnectorError::Quarantined {
                    outbox_id: row.outbox_id,
                    quarantine_id,
                    reason,
                });
            }
        }
        match emit_coverage(&request, row, accepted_event_id).await? {
            CoverageObservationOutcome::Recorded { .. } => summary.receipts += 1,
            CoverageObservationOutcome::AlreadyCovered { .. } => {
                summary.coverage_already_covered += 1;
            }
        }
    }
    Ok(summary)
}

async fn drain_one(
    request: &TranscriptDrainRequest<'_>,
    row: &TranscriptOutboxRowV1,
) -> TranscriptConnectorResult<(AppendOutcome, AcceptedEventId)> {
    let candidate: EvidenceIngressCandidateV2 = decode_strict(&row.canonical_candidate)?;
    let locators: EvidenceIngressLocatorsV1 = decode_strict(&row.canonical_locators)?;
    let admitted = admit_evidence(
        request.active,
        EvidenceAdmissionRequestV1 {
            candidate: &candidate,
            locators: &locators,
            canonical_payload: &row.canonical_payload,
            delivery: EvidenceDeliveryContextV1 {
                connector_principal_id: candidate.authenticated_ingress_principal_id.clone(),
                connector_instance_id: candidate.connector_instance_id.clone(),
                transport_delivery_id: candidate.provider_delivery_id.clone(),
                attempt_count: 1,
            },
            lineage: RepresentationLineageV2::Origin,
        },
    )?;
    let accepted_event_id = admitted.statement().accepted_event_id()?;
    let appendable = admitted.appendable(request.witness)?;
    let projection = Arc::new(TranscriptDrainProjection {
        content: GovernedContentProjection::new(
            request.trusted_scope,
            admitted.content(),
            request.content_key,
        )?,
        tenant_id: request.trusted_scope.tenant_id(),
        project: request.trusted_scope.project().to_owned(),
        outbox_id: row.outbox_id,
    });
    let outcome = request
        .ledger
        .append(request.witness, &appendable, projection)
        .await?;
    Ok((outcome, accepted_event_id))
}

/// Emit the coverage receipt for one drained turn: the half-open ordinal range
/// `[ordinal, ordinal + 1)` of the connector instance's coverage domain.
async fn emit_coverage(
    request: &TranscriptDrainRequest<'_>,
    row: &TranscriptOutboxRowV1,
    accepted_event_id: AcceptedEventId,
) -> TranscriptConnectorResult<CoverageObservationOutcome> {
    let candidate: EvidenceIngressCandidateV2 = decode_strict(&row.canonical_candidate)?;
    // The coverage receipt's source digest names the exact staged candidate
    // bytes this receipt attests, and its evidence_id is the accepted event the
    // append just made durable — never a synthetic stand-in (COVER-03).
    let source_digest = Sha256Digest::from_bytes(
        <sha2::Sha256 as sha2::Digest>::digest(&row.canonical_candidate).into(),
    );
    let observed = crate::coverage_runtime::SequenceIntervalV1::new(
        u64::from(row.turn_ordinal),
        u64::from(row.turn_ordinal) + 1,
    )
    .map_err(|error| TranscriptConnectorError::LedgerIntegrity(error.to_string()))?;
    let binding = request.coverage_binding;
    let observation = crate::coverage_runtime::CoverageObservationV1 {
        connector_instance: ContractId::new(candidate.connector_instance_id.as_str())?,
        producer: binding.producer.clone(),
        scope: binding.scope.clone(),
        target: binding.target,
        observed,
        freshness: binding.freshness.clone(),
        proof_basis: binding.proof_basis.clone(),
        source_digest,
        source_count: 1,
        evidence_id: accepted_event_id,
        observed_through: binding.observed_through.clone(),
    };
    Ok(request.coverage.observe(&observation).await?)
}
