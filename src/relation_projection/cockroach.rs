//! `CockroachDB` implementation of the relation-projection repository.
//!
//! Every statement here touches only relations `fleet_runtime` already holds
//! a grant on per `deploy/cockroach/runtime-role-grants.sql`:
//! `memory_evidence_events` (read-only, via the shared evidence ledger's own
//! grant), `memory_relation_projection_v1`, and
//! `memory_relation_projection_watermarks_v1` (SELECT/INSERT/UPDATE). No new
//! grant is required (ADR 0002 D2's writer grants already include
//! relation-projection RW for `fleet_runtime`, verified against that file).

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::postgres::{PgPool, PgRow};
use sqlx::{Postgres, Row as _, Transaction};

use crate::control_log::TrustedControlScope;
use crate::evidence_ledger::{
    AcceptedEventKindV1, AcceptedEventRepository, AppendOutcome, AppendProjection,
    AppendableAcceptedEvent, CockroachAcceptedEventRepository, EvidenceAppendError,
    EvidenceAppendResult, ProjectionContext, WriterAuthorityWitness,
};
use crate::memory_contracts::canonical::decode_strict;
use crate::memory_contracts::digest::Sha256Digest;
use crate::memory_contracts::evidence::AcceptedEventId;
use crate::memory_contracts::relation::{
    RelationAttestationBasisV1, RelationAttestationEventV1, RelationAttestationVerdictV1,
    RelationFingerprint, RelationProjectionStateV1, RelationProjectionV1,
};
use crate::store::cockroach::RetryPolicy;

use super::projector::project_relation_events;
use super::repository::{
    RelationProjectionRepository, RelationProjectionRowV1, RelationProjectionWatermarkV1,
    WATERMARK_LEDGER_FAMILY,
};

const RELATION_EVENT_KIND: &str = "relation.attestation.accepted";
const RELATION_CONSISTENCY_FAMILY: &str = "relation";

const SELECT_EVENT_BY_ID_SQL: &str = "SELECT canonical_event FROM public.memory_evidence_events \
     WHERE tenant_id = $1 AND project = $2 AND event_id = $3";

/// Bounded only by `(tenant_id, project)`, NOT by the primary-key prefix
/// `(tenant, project, epoch, shard)` the way `memory_evidence_events`' other
/// lookups are: there is no secondary index on `consistency_key_digest`, so
/// this is a full scan of every relation-attestation row for the tenant and
/// project. Correct, not free — flagged in the W1-REL handoff as a request to
/// the migration owner for a partial index on
/// `(tenant_id, project, consistency_family, consistency_key_digest)`.
const SELECT_EVENTS_BY_FINGERPRINT_SQL: &str = "SELECT canonical_event FROM public.memory_evidence_events \
     WHERE tenant_id = $1 AND project = $2 AND consistency_family = $3 \
       AND consistency_key_digest = $4 AND event_kind = $5";

const UPSERT_PROJECTION_SQL: &str = "INSERT INTO public.memory_relation_projection_v1 (\
     tenant_id, project, relation_fingerprint, projection_state, last_verdict, last_basis, \
     last_event_id, generation, updated_at\
     ) VALUES ($1, $2, $3, $4, $5, $6, $7, 1, $8) \
     ON CONFLICT (tenant_id, project, relation_fingerprint) DO UPDATE SET \
     projection_state = excluded.projection_state, \
     last_verdict = excluded.last_verdict, \
     last_basis = excluded.last_basis, \
     last_event_id = excluded.last_event_id, \
     generation = public.memory_relation_projection_v1.generation + 1, \
     updated_at = excluded.updated_at";

const SELECT_PROJECTION_SQL: &str = "SELECT projection_state, last_verdict, last_basis, last_event_id, generation, updated_at \
     FROM public.memory_relation_projection_v1 \
     WHERE tenant_id = $1 AND project = $2 AND relation_fingerprint = $3";

/// `WHERE ... last_committed_offset < excluded.last_committed_offset` makes
/// this upsert monotonic even under a `with_serializable_retry` re-run: the
/// clause simply skips the write if a later commit already advanced past this
/// attempt's offset, rather than regressing it.
const UPSERT_WATERMARK_SQL: &str = "INSERT INTO public.memory_relation_projection_watermarks_v1 (\
     tenant_id, project, ledger_family, shard, last_committed_offset, updated_at\
     ) VALUES ($1, $2, $3, $4, $5, $6) \
     ON CONFLICT (tenant_id, project, ledger_family, shard) DO UPDATE SET \
     last_committed_offset = excluded.last_committed_offset, \
     updated_at = excluded.updated_at \
     WHERE public.memory_relation_projection_watermarks_v1.last_committed_offset \
       < excluded.last_committed_offset";

const SELECT_WATERMARK_SQL: &str = "SELECT last_committed_offset, updated_at \
     FROM public.memory_relation_projection_watermarks_v1 \
     WHERE tenant_id = $1 AND project = $2 AND ledger_family = $3 AND shard = $4";

/// Private relation-projection repository bound once to physical and
/// semantic scope, exactly like [`CockroachAcceptedEventRepository`].
#[derive(Clone)]
pub struct CockroachRelationProjectionRepository {
    pool: PgPool,
    trusted_scope: TrustedControlScope,
    events: Arc<CockroachAcceptedEventRepository>,
}

impl std::fmt::Debug for CockroachRelationProjectionRepository {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CockroachRelationProjectionRepository")
            .field("trusted_scope", &self.trusted_scope)
            .finish_non_exhaustive()
    }
}

impl CockroachRelationProjectionRepository {
    /// Bind one pool, one physical/semantic scope, and one retry policy.
    ///
    /// Constructs its own [`CockroachAcceptedEventRepository`] over the same
    /// pool, scope, and retry policy so the SAME serializable transaction
    /// that appends the accepted event also runs this module's projection
    /// (EVENT-03).
    #[must_use]
    pub fn new(
        pool: PgPool,
        trusted_scope: TrustedControlScope,
        retry_policy: RetryPolicy,
    ) -> Self {
        let events = Arc::new(CockroachAcceptedEventRepository::new(
            pool.clone(),
            trusted_scope.clone(),
            retry_policy,
        ));
        Self {
            pool,
            trusted_scope,
            events,
        }
    }

    /// The general accepted-event repository this module appends through, so
    /// a caller can also mix relation-attestation appends with evidence and
    /// remember-claim appends against the same live head witness.
    #[must_use]
    pub fn accepted_event_repository(&self) -> Arc<CockroachAcceptedEventRepository> {
        Arc::clone(&self.events)
    }
}

#[async_trait]
impl RelationProjectionRepository for CockroachRelationProjectionRepository {
    async fn append_attestation(
        &self,
        witness: &WriterAuthorityWitness,
        event: &RelationAttestationEventV1,
    ) -> EvidenceAppendResult<AppendOutcome> {
        let appendable = AppendableAcceptedEvent::relation_attestation(event, witness)?;
        let projection = Arc::new(RelationProjectionAppend {
            trusted_scope: self.trusted_scope.clone(),
        });
        self.events.append(witness, &appendable, projection).await
    }

    async fn read_projection(
        &self,
        relation_fingerprint: RelationFingerprint,
    ) -> EvidenceAppendResult<Option<RelationProjectionRowV1>> {
        let row: Option<PgRow> = sqlx::query(SELECT_PROJECTION_SQL)
            .bind(self.trusted_scope.tenant_id())
            .bind(self.trusted_scope.project())
            .bind(bytes(relation_fingerprint.digest()))
            .fetch_optional(&self.pool)
            .await?;
        row.map(|row| decode_projection_row(relation_fingerprint, &row))
            .transpose()
    }

    async fn read_watermark(
        &self,
        shard: u16,
    ) -> EvidenceAppendResult<Option<RelationProjectionWatermarkV1>> {
        let row: Option<PgRow> = sqlx::query(SELECT_WATERMARK_SQL)
            .bind(self.trusted_scope.tenant_id())
            .bind(self.trusted_scope.project())
            .bind(WATERMARK_LEDGER_FAMILY)
            .bind(i32::from(shard))
            .fetch_optional(&self.pool)
            .await?;
        row.map(|row| decode_watermark_row(shard, &row)).transpose()
    }

    async fn rebuild_projection(
        &self,
        relation_fingerprint: RelationFingerprint,
    ) -> EvidenceAppendResult<RelationProjectionV1> {
        let canonical_events = fetch_fingerprint_history(
            &self.pool,
            self.trusted_scope.tenant_id(),
            self.trusted_scope.project(),
            relation_fingerprint,
        )
        .await?;
        decode_and_project(relation_fingerprint, &canonical_events)
    }
}

/// The [`AppendProjection`] adapter: materializes
/// `memory_relation_projection_v1` and its watermark inside the SAME
/// transaction the general accepted-event ledger appended the relation
/// attestation event in (EVENT-03, REPLAY-02).
struct RelationProjectionAppend {
    trusted_scope: TrustedControlScope,
}

#[async_trait]
impl AppendProjection for RelationProjectionAppend {
    async fn project(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        context: ProjectionContext,
    ) -> EvidenceAppendResult<()> {
        if context.kind != AcceptedEventKindV1::RelationAttestation {
            // Defensive: this adapter must never be attached to any other
            // accepted-event kind's append.
            return Err(EvidenceAppendError::LedgerIntegrity(format!(
                "relation projection adapter received a {} accepted event",
                context.kind.as_str()
            )));
        }

        let row: PgRow = sqlx::query(SELECT_EVENT_BY_ID_SQL)
            .bind(self.trusted_scope.tenant_id())
            .bind(self.trusted_scope.project())
            .bind(bytes(context.accepted_event_id.digest()))
            .fetch_optional(&mut **transaction)
            .await?
            .ok_or_else(|| {
                EvidenceAppendError::LedgerIntegrity(
                    "relation attestation event vanished immediately after its own insert".into(),
                )
            })?;
        let canonical: Vec<u8> = row.try_get("canonical_event")?;
        let event: RelationAttestationEventV1 = decode_strict(&canonical)?;
        event.validate_shape()?;
        let relation_fingerprint = event.relation_fingerprint;
        // `RelationEdgeV1::consistency_partition_key`'s `key_digest` IS
        // `self.fingerprint()?.digest()` (see relation.rs), so the stored
        // `consistency_key_digest` column is exactly the fingerprint's own
        // digest; no separate re-derivation from the edge is needed here.

        let history_rows: Vec<PgRow> = sqlx::query(SELECT_EVENTS_BY_FINGERPRINT_SQL)
            .bind(self.trusted_scope.tenant_id())
            .bind(self.trusted_scope.project())
            .bind(RELATION_CONSISTENCY_FAMILY)
            .bind(bytes(relation_fingerprint.digest()))
            .bind(RELATION_EVENT_KIND)
            .fetch_all(&mut **transaction)
            .await?;
        let mut history = Vec::with_capacity(history_rows.len());
        for row in &history_rows {
            let canonical: Vec<u8> = row.try_get("canonical_event")?;
            let decoded: RelationAttestationEventV1 = decode_strict(&canonical)?;
            history.push(decoded);
        }
        let refs: Vec<&RelationAttestationEventV1> = history.iter().collect();
        let projected = project_relation_events(relation_fingerprint, &refs)?;

        upsert_projection(transaction, &self.trusted_scope, &event, &projected).await?;
        upsert_watermark(
            transaction,
            &self.trusted_scope,
            context.position.shard,
            context.position.committed_offset.as_u64(),
        )
        .await?;
        Ok(())
    }
}

async fn upsert_projection(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    event: &RelationAttestationEventV1,
    projected: &RelationProjectionV1,
) -> EvidenceAppendResult<()> {
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT pg_catalog.statement_timestamp()")
        .fetch_one(&mut **transaction)
        .await?;
    let last_event_id = event.accepted_event_id()?;
    sqlx::query(UPSERT_PROJECTION_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(bytes(projected.relation_fingerprint.digest()))
        .bind(state_str(projected.state))
        .bind(verdict_str(event.verdict))
        .bind(basis_str(event.basis))
        .bind(bytes(last_event_id.digest()))
        .bind(now)
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

async fn upsert_watermark(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    shard: u16,
    last_committed_offset: u64,
) -> EvidenceAppendResult<()> {
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT pg_catalog.statement_timestamp()")
        .fetch_one(&mut **transaction)
        .await?;
    let offset = i64::try_from(last_committed_offset).map_err(|_| {
        EvidenceAppendError::LedgerIntegrity(
            "relation projection watermark offset exceeds INT8".into(),
        )
    })?;
    sqlx::query(UPSERT_WATERMARK_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(WATERMARK_LEDGER_FAMILY)
        .bind(i32::from(shard))
        .bind(offset)
        .bind(now)
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

async fn fetch_fingerprint_history(
    pool: &PgPool,
    tenant_id: uuid::Uuid,
    project: &str,
    relation_fingerprint: RelationFingerprint,
) -> EvidenceAppendResult<Vec<Vec<u8>>> {
    // Deliberately re-derives the consistency key digest the SAME way the
    // append path does (`RelationEdgeV1::consistency_partition_key`) rather
    // than trusting a caller-supplied digest, so a caller cannot point this
    // read at a different edge's history under a mismatched fingerprint.
    // Since the key digest is a pure function of the fingerprint's own
    // preimage (see `RelationEdgeV1::consistency_partition_key`), and we do
    // not have the edge here (only its fingerprint), bind the fingerprint's
    // digest directly: `consistency_partition_key`'s `key_digest` IS
    // `self.fingerprint()?.digest()` (see relation.rs), so the two are the
    // same bytes.
    let rows: Vec<PgRow> = sqlx::query(SELECT_EVENTS_BY_FINGERPRINT_SQL)
        .bind(tenant_id)
        .bind(project)
        .bind(RELATION_CONSISTENCY_FAMILY)
        .bind(bytes(relation_fingerprint.digest()))
        .bind(RELATION_EVENT_KIND)
        .fetch_all(pool)
        .await?;
    let mut canonical_events = Vec::with_capacity(rows.len());
    for row in &rows {
        canonical_events.push(row.try_get::<Vec<u8>, _>("canonical_event")?);
    }
    Ok(canonical_events)
}

fn decode_and_project(
    relation_fingerprint: RelationFingerprint,
    canonical_events: &[Vec<u8>],
) -> EvidenceAppendResult<RelationProjectionV1> {
    let mut events = Vec::with_capacity(canonical_events.len());
    for canonical in canonical_events {
        let decoded: RelationAttestationEventV1 = decode_strict(canonical)?;
        events.push(decoded);
    }
    let refs: Vec<&RelationAttestationEventV1> = events.iter().collect();
    Ok(project_relation_events(relation_fingerprint, &refs)?)
}

fn decode_projection_row(
    relation_fingerprint: RelationFingerprint,
    row: &PgRow,
) -> EvidenceAppendResult<RelationProjectionRowV1> {
    let state: String = row.try_get("projection_state")?;
    let verdict: String = row.try_get("last_verdict")?;
    let basis: String = row.try_get("last_basis")?;
    let generation: i64 = row.try_get("generation")?;
    Ok(RelationProjectionRowV1 {
        relation_fingerprint,
        state: parse_state(&state)?,
        last_verdict: parse_verdict(&verdict)?,
        last_basis: parse_basis(&basis)?,
        last_event_id: AcceptedEventId::from_digest(digest32(row.try_get("last_event_id")?)?),
        generation: u64::try_from(generation).map_err(|_| {
            EvidenceAppendError::LedgerIntegrity(
                "stored relation projection generation is negative".into(),
            )
        })?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn decode_watermark_row(
    shard: u16,
    row: &PgRow,
) -> EvidenceAppendResult<RelationProjectionWatermarkV1> {
    let offset: i64 = row.try_get("last_committed_offset")?;
    Ok(RelationProjectionWatermarkV1 {
        shard,
        last_committed_offset: u64::try_from(offset).map_err(|_| {
            EvidenceAppendError::LedgerIntegrity(
                "stored relation projection watermark offset is negative".into(),
            )
        })?,
        updated_at: row.try_get("updated_at")?,
    })
}

const fn state_str(state: RelationProjectionStateV1) -> &'static str {
    match state {
        RelationProjectionStateV1::Declared => "declared",
        RelationProjectionStateV1::Verified => "verified",
        RelationProjectionStateV1::Refuted => "refuted",
        RelationProjectionStateV1::Contested => "contested",
    }
}

fn parse_state(value: &str) -> EvidenceAppendResult<RelationProjectionStateV1> {
    match value {
        "declared" => Ok(RelationProjectionStateV1::Declared),
        "verified" => Ok(RelationProjectionStateV1::Verified),
        "refuted" => Ok(RelationProjectionStateV1::Refuted),
        "contested" => Ok(RelationProjectionStateV1::Contested),
        other => Err(EvidenceAppendError::LedgerIntegrity(format!(
            "unrecognized stored relation projection_state {other}"
        ))),
    }
}

const fn verdict_str(verdict: RelationAttestationVerdictV1) -> &'static str {
    match verdict {
        RelationAttestationVerdictV1::Supports => "supports",
        RelationAttestationVerdictV1::Refutes => "refutes",
    }
}

fn parse_verdict(value: &str) -> EvidenceAppendResult<RelationAttestationVerdictV1> {
    match value {
        "supports" => Ok(RelationAttestationVerdictV1::Supports),
        "refutes" => Ok(RelationAttestationVerdictV1::Refutes),
        other => Err(EvidenceAppendError::LedgerIntegrity(format!(
            "unrecognized stored relation last_verdict {other}"
        ))),
    }
}

const fn basis_str(basis: RelationAttestationBasisV1) -> &'static str {
    match basis {
        RelationAttestationBasisV1::Declared => "declared",
        RelationAttestationBasisV1::Inferred => "inferred",
        RelationAttestationBasisV1::ProviderAttested => "provider_attested",
        RelationAttestationBasisV1::VerifierResult => "verifier_result",
    }
}

fn parse_basis(value: &str) -> EvidenceAppendResult<RelationAttestationBasisV1> {
    match value {
        "declared" => Ok(RelationAttestationBasisV1::Declared),
        "inferred" => Ok(RelationAttestationBasisV1::Inferred),
        "provider_attested" => Ok(RelationAttestationBasisV1::ProviderAttested),
        "verifier_result" => Ok(RelationAttestationBasisV1::VerifierResult),
        other => Err(EvidenceAppendError::LedgerIntegrity(format!(
            "unrecognized stored relation last_basis {other}"
        ))),
    }
}

fn bytes(digest: Sha256Digest) -> Vec<u8> {
    digest.as_bytes().to_vec()
}

fn digest32(value: Vec<u8>) -> EvidenceAppendResult<Sha256Digest> {
    let bytes: [u8; 32] = value.try_into().map_err(|_| {
        EvidenceAppendError::LedgerIntegrity("stored digest column is not 32 bytes".into())
    })?;
    Ok(Sha256Digest::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_str_round_trips_every_closed_variant() {
        for state in [
            RelationProjectionStateV1::Declared,
            RelationProjectionStateV1::Verified,
            RelationProjectionStateV1::Refuted,
            RelationProjectionStateV1::Contested,
        ] {
            assert_eq!(parse_state(state_str(state)).unwrap(), state);
        }
    }

    #[test]
    fn verdict_str_round_trips_every_closed_variant() {
        for verdict in [
            RelationAttestationVerdictV1::Supports,
            RelationAttestationVerdictV1::Refutes,
        ] {
            assert_eq!(parse_verdict(verdict_str(verdict)).unwrap(), verdict);
        }
    }

    #[test]
    fn basis_str_round_trips_every_closed_variant() {
        for basis in [
            RelationAttestationBasisV1::Declared,
            RelationAttestationBasisV1::Inferred,
            RelationAttestationBasisV1::ProviderAttested,
            RelationAttestationBasisV1::VerifierResult,
        ] {
            assert_eq!(parse_basis(basis_str(basis)).unwrap(), basis);
        }
    }

    #[test]
    fn parse_state_rejects_unrecognized_strings() {
        // Kills a mutant that widens the match to a catch-all `Ok`: an
        // unrecognized stored string must fail closed, never silently decode
        // as some default state.
        assert!(matches!(
            parse_state("unknown"),
            Err(EvidenceAppendError::LedgerIntegrity(_))
        ));
    }

    #[test]
    fn parse_verdict_rejects_unrecognized_strings() {
        assert!(matches!(
            parse_verdict("unknown"),
            Err(EvidenceAppendError::LedgerIntegrity(_))
        ));
    }

    #[test]
    fn parse_basis_rejects_unrecognized_strings() {
        assert!(matches!(
            parse_basis("unknown"),
            Err(EvidenceAppendError::LedgerIntegrity(_))
        ));
    }
}
