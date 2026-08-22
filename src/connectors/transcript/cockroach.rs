//! `CockroachDB` implementation of the transcript outbox and source cursor.
//!
//! Every statement here touches only migration 0021's two tables,
//! `memory_transcript_outbox_v1` and `memory_transcript_cursors_v1`, both keyed
//! by the trusted `(tenant_id, project)` pair bound at construction. Neither is a
//! publication-reader table (PUBLIC-03/04): both are private-plane staging rows.
//!
//! [`CockroachTranscriptOutboxRepository::enqueue_batch`] runs the whole
//! seed → lock → insert-rows → advance-cursor sequence inside ONE serializable
//! transaction via [`with_serializable_retry`]. Rows and the cursor therefore
//! commit together or not at all (EVENT-03): a crash — or the fault injected by
//! [`TranscriptFaultInjection::AbortAfterWrites`] — leaves neither, and the
//! batch is simply re-collected. A batch whose byte range the cursor already
//! covers writes nothing and moves nothing.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::postgres::{PgPool, PgRow};
use sqlx::{Postgres, Row as _, Transaction};

use crate::control_log::TrustedControlScope;
use crate::error::FleetError;
use crate::memory_contracts::digest::Sha256Digest;
use crate::store::cockroach::{RetryPolicy, is_retryable, is_retryable_fleet_error};

use super::error::{TranscriptConnectorError, TranscriptConnectorResult};
use super::outbox::{
    TranscriptBatchV1, TranscriptCursorRowV1, TranscriptEnqueueOutcome, TranscriptFaultInjection,
    TranscriptOutboxRepository, TranscriptOutboxRowV1, TranscriptOutboxStateV1,
};

const SEED_CURSOR_SQL: &str = "INSERT INTO public.memory_transcript_cursors_v1 (\
     tenant_id, project, source_id, byte_offset, line_ordinal, next_ordinal, batch_seq, \
     source_digest, updated_at\
     ) VALUES ($1, $2, $3, 0, 0, 0, 0, $4, $5) \
     ON CONFLICT (tenant_id, project, source_id) DO NOTHING";

const SELECT_CURSOR_FOR_UPDATE_SQL: &str = "SELECT byte_offset, line_ordinal, next_ordinal, batch_seq, source_digest \
     FROM public.memory_transcript_cursors_v1 \
     WHERE tenant_id = $1 AND project = $2 AND source_id = $3 FOR UPDATE";

const SELECT_CURSOR_SQL: &str = "SELECT byte_offset, line_ordinal, next_ordinal, batch_seq, source_digest \
     FROM public.memory_transcript_cursors_v1 \
     WHERE tenant_id = $1 AND project = $2 AND source_id = $3";

const ADVANCE_CURSOR_SQL: &str = "UPDATE public.memory_transcript_cursors_v1 SET \
     byte_offset = $4, line_ordinal = $5, next_ordinal = $6, batch_seq = $7, \
     source_digest = $8, updated_at = $9 \
     WHERE tenant_id = $1 AND project = $2 AND source_id = $3";

const INSERT_ROW_SQL: &str = "INSERT INTO public.memory_transcript_outbox_v1 (\
     tenant_id, project, outbox_id, source_id, session_id, turn_ordinal, batch_seq, \
     canonical_candidate, canonical_locators, canonical_payload, state, created_at, drained_at\
     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'pending', $11, NULL) \
     ON CONFLICT (tenant_id, project, outbox_id) DO NOTHING";

const SELECT_PENDING_SQL: &str = "SELECT outbox_id, source_id, session_id, turn_ordinal, \
     batch_seq, canonical_candidate, canonical_locators, canonical_payload, state \
     FROM public.memory_transcript_outbox_v1 \
     WHERE tenant_id = $1 AND project = $2 AND state = 'pending' \
     ORDER BY batch_seq, turn_ordinal, outbox_id LIMIT $3";

const SELECT_ALL_SQL: &str = "SELECT outbox_id, source_id, session_id, turn_ordinal, \
     batch_seq, canonical_candidate, canonical_locators, canonical_payload, state \
     FROM public.memory_transcript_outbox_v1 \
     WHERE tenant_id = $1 AND project = $2 \
     ORDER BY batch_seq, turn_ordinal, outbox_id LIMIT $3";

/// Also used inside the append transaction by the drain projection, so a row is
/// marked drained in the very transaction that made its accepted event durable.
pub(super) const MARK_DRAINED_SQL: &str = "UPDATE public.memory_transcript_outbox_v1 \
     SET state = 'drained', drained_at = $4 \
     WHERE tenant_id = $1 AND project = $2 AND outbox_id = $3 AND state = 'pending'";

const COUNT_ROWS_SQL: &str = "SELECT count(*) FROM public.memory_transcript_outbox_v1 \
     WHERE tenant_id = $1 AND project = $2 AND source_id = $3";

/// Transcript outbox bound once to physical and semantic scope, exactly like
/// [`crate::evidence_ledger::CockroachAcceptedEventRepository`].
#[derive(Clone)]
pub struct CockroachTranscriptOutboxRepository {
    pool: PgPool,
    trusted_scope: TrustedControlScope,
    retry_policy: RetryPolicy,
}

impl std::fmt::Debug for CockroachTranscriptOutboxRepository {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CockroachTranscriptOutboxRepository")
            .field("trusted_scope", &self.trusted_scope)
            .finish_non_exhaustive()
    }
}

impl CockroachTranscriptOutboxRepository {
    /// Bind one pool, one physical/semantic scope, and one retry policy.
    #[must_use]
    pub const fn new(
        pool: PgPool,
        trusted_scope: TrustedControlScope,
        retry_policy: RetryPolicy,
    ) -> Self {
        Self {
            pool,
            trusted_scope,
            retry_policy,
        }
    }

    /// The scope every statement is bound to. Used by the drain projection so it
    /// writes its `mark drained` update under the same scope.
    #[must_use]
    pub const fn trusted_scope(&self) -> &TrustedControlScope {
        &self.trusted_scope
    }

    /// Stage one batch, optionally forcing a fault to prove atomicity.
    ///
    /// [`TranscriptFaultInjection::None`] is the production path
    /// ([`TranscriptOutboxRepository::enqueue_batch`] delegates here). The fault
    /// variant exists only so the connected proof can assert that a failure
    /// after the writes but before commit leaves neither the rows nor the cursor
    /// advance durable.
    pub async fn enqueue_batch_with_fault_injection(
        &self,
        batch: &TranscriptBatchV1,
        fault: TranscriptFaultInjection,
    ) -> TranscriptConnectorResult<TranscriptEnqueueOutcome> {
        for row in &batch.rows {
            if row.source_id != batch.cursor.source_id {
                return Err(TranscriptConnectorError::CursorRegression {
                    source_id: batch.cursor.source_id.clone(),
                });
            }
        }
        // A hand-rolled retry loop rather than `with_serializable_retry`: that
        // helper's closure must return `FleetError`, which would collapse a
        // closed refusal (a regressed cursor) into an opaque storage failure.
        // The typed rejection is the point of this seam, so it is preserved.
        let mut attempt = 0_u32;
        loop {
            attempt += 1;
            let mut transaction = self.pool.begin().await.map_err(FleetError::from)?;
            sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
                .execute(&mut *transaction)
                .await?;
            match enqueue_in_transaction(&mut transaction, &self.trusted_scope, batch, fault).await
            {
                Ok(outcome) => match transaction.commit().await {
                    Ok(()) => return Ok(outcome),
                    Err(error)
                        if is_retryable(&error) && attempt < self.retry_policy.max_attempts =>
                    {
                        tokio::time::sleep(self.retry_policy.delay_for_retry(attempt - 1)).await;
                    }
                    Err(error) => return Err(TranscriptConnectorError::from(error)),
                },
                Err(TranscriptConnectorError::Storage(error))
                    if is_retryable_fleet_error(&error)
                        && attempt < self.retry_policy.max_attempts =>
                {
                    drop(transaction);
                    tokio::time::sleep(self.retry_policy.delay_for_retry(attempt - 1)).await;
                }
                Err(error) => return Err(error),
            }
        }
    }
}

#[async_trait]
impl TranscriptOutboxRepository for CockroachTranscriptOutboxRepository {
    async fn enqueue_batch(
        &self,
        batch: &TranscriptBatchV1,
    ) -> TranscriptConnectorResult<TranscriptEnqueueOutcome> {
        self.enqueue_batch_with_fault_injection(batch, TranscriptFaultInjection::None)
            .await
    }

    async fn read_cursor(
        &self,
        source_id: &str,
    ) -> TranscriptConnectorResult<Option<TranscriptCursorRowV1>> {
        let row: Option<PgRow> = sqlx::query(SELECT_CURSOR_SQL)
            .bind(self.trusted_scope.tenant_id())
            .bind(self.trusted_scope.project())
            .bind(source_id)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref()
            .map(|row| decode_cursor_row(source_id, row))
            .transpose()
    }

    async fn staged_rows(
        &self,
        pending_only: bool,
        limit: u32,
    ) -> TranscriptConnectorResult<Vec<TranscriptOutboxRowV1>> {
        let sql = if pending_only {
            SELECT_PENDING_SQL
        } else {
            SELECT_ALL_SQL
        };
        let rows: Vec<PgRow> = sqlx::query(sql)
            .bind(self.trusted_scope.tenant_id())
            .bind(self.trusted_scope.project())
            .bind(i64::from(limit))
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(decode_outbox_row).collect()
    }

    async fn mark_drained(&self, outbox_id: Sha256Digest) -> TranscriptConnectorResult<()> {
        let now: DateTime<Utc> = sqlx::query_scalar("SELECT pg_catalog.statement_timestamp()")
            .fetch_one(&self.pool)
            .await?;
        sqlx::query(MARK_DRAINED_SQL)
            .bind(self.trusted_scope.tenant_id())
            .bind(self.trusted_scope.project())
            .bind(outbox_id.as_bytes().to_vec())
            .bind(now)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn count_rows(&self, source_id: &str) -> TranscriptConnectorResult<u64> {
        let count: i64 = sqlx::query_scalar(COUNT_ROWS_SQL)
            .bind(self.trusted_scope.tenant_id())
            .bind(self.trusted_scope.project())
            .bind(source_id)
            .fetch_one(&self.pool)
            .await?;
        u64::try_from(count).map_err(|_| {
            TranscriptConnectorError::LedgerIntegrity("outbox row count is negative".into())
        })
    }
}

async fn enqueue_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    batch: &TranscriptBatchV1,
    fault: TranscriptFaultInjection,
) -> TranscriptConnectorResult<TranscriptEnqueueOutcome> {
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT pg_catalog.statement_timestamp()")
        .fetch_one(&mut **transaction)
        .await?;

    // Lazy seed so the FOR UPDATE below always locks a row (mirrors the evidence
    // ledger's offset-zero head seed). An existing row is untouched.
    sqlx::query(SEED_CURSOR_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(&batch.cursor.source_id)
        .bind(Sha256Digest::ZERO.as_bytes().to_vec())
        .bind(now)
        .execute(&mut **transaction)
        .await?;

    let locked: PgRow = sqlx::query(SELECT_CURSOR_FOR_UPDATE_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(&batch.cursor.source_id)
        .fetch_one(&mut **transaction)
        .await?;
    let current = decode_cursor_row(&batch.cursor.source_id, &locked)?;

    // Idempotent re-collection: the durable cursor already covers this batch's
    // byte range, so write nothing and move nothing.
    if batch.cursor.byte_offset <= current.byte_offset {
        return Ok(TranscriptEnqueueOutcome::AlreadyCovered {
            batch_seq: current.batch_seq,
        });
    }
    // A batch built against a cursor other than the durable one would re-mint
    // turn ordinals. Fail closed rather than stage a renumbered stream.
    if batch.cursor.batch_seq != current.batch_seq.saturating_add(1)
        || batch.cursor.next_ordinal < current.next_ordinal
    {
        return Err(TranscriptConnectorError::CursorRegression {
            source_id: batch.cursor.source_id.clone(),
        });
    }

    let mut rows_written = 0_u64;
    for row in &batch.rows {
        let written = sqlx::query(INSERT_ROW_SQL)
            .bind(scope.tenant_id())
            .bind(scope.project())
            .bind(row.outbox_id.as_bytes().to_vec())
            .bind(&row.source_id)
            .bind(&row.session_id)
            .bind(i64::from(row.turn_ordinal))
            .bind(i64::try_from(row.batch_seq).map_err(|_| {
                TranscriptConnectorError::LedgerIntegrity("batch sequence is out of range".into())
            })?)
            .bind(&row.canonical_candidate)
            .bind(&row.canonical_locators)
            .bind(&row.canonical_payload)
            .bind(now)
            .execute(&mut **transaction)
            .await?
            .rows_affected();
        rows_written = rows_written.saturating_add(written);
    }

    sqlx::query(ADVANCE_CURSOR_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(&batch.cursor.source_id)
        .bind(i64::try_from(batch.cursor.byte_offset).map_err(|_| {
            TranscriptConnectorError::LedgerIntegrity("byte offset is out of range".into())
        })?)
        .bind(i64::from(batch.cursor.line_ordinal))
        .bind(i64::from(batch.cursor.next_ordinal))
        .bind(i64::try_from(batch.cursor.batch_seq).map_err(|_| {
            TranscriptConnectorError::LedgerIntegrity("batch sequence is out of range".into())
        })?)
        .bind(batch.cursor.source_digest.as_bytes().to_vec())
        .bind(now)
        .execute(&mut **transaction)
        .await?;

    if fault == TranscriptFaultInjection::AbortAfterWrites {
        return Err(TranscriptConnectorError::LedgerIntegrity(
            "deliberate transcript enqueue failure".into(),
        ));
    }

    Ok(TranscriptEnqueueOutcome::Enqueued {
        rows_written,
        batch_seq: batch.cursor.batch_seq,
    })
}

fn decode_cursor_row(
    source_id: &str,
    row: &PgRow,
) -> TranscriptConnectorResult<TranscriptCursorRowV1> {
    let byte_offset: i64 = row.try_get("byte_offset")?;
    let line_ordinal: i64 = row.try_get("line_ordinal")?;
    let next_ordinal: i64 = row.try_get("next_ordinal")?;
    let batch_seq: i64 = row.try_get("batch_seq")?;
    let source_digest: Vec<u8> = row.try_get("source_digest")?;
    let digest: [u8; 32] = source_digest.as_slice().try_into().map_err(|_| {
        TranscriptConnectorError::LedgerIntegrity("stored source digest is not 32 bytes".into())
    })?;
    Ok(TranscriptCursorRowV1 {
        source_id: source_id.to_owned(),
        byte_offset: u64::try_from(byte_offset).map_err(|_| {
            TranscriptConnectorError::LedgerIntegrity("stored byte offset is negative".into())
        })?,
        line_ordinal: u32::try_from(line_ordinal).map_err(|_| {
            TranscriptConnectorError::LedgerIntegrity("stored line ordinal is out of range".into())
        })?,
        next_ordinal: u32::try_from(next_ordinal).map_err(|_| {
            TranscriptConnectorError::LedgerIntegrity("stored turn ordinal is out of range".into())
        })?,
        batch_seq: u64::try_from(batch_seq).map_err(|_| {
            TranscriptConnectorError::LedgerIntegrity("stored batch sequence is negative".into())
        })?,
        source_digest: Sha256Digest::from_bytes(digest),
    })
}

fn decode_outbox_row(row: &PgRow) -> TranscriptConnectorResult<TranscriptOutboxRowV1> {
    let outbox_id: Vec<u8> = row.try_get("outbox_id")?;
    let outbox_id: [u8; 32] = outbox_id.as_slice().try_into().map_err(|_| {
        TranscriptConnectorError::LedgerIntegrity("stored outbox id is not 32 bytes".into())
    })?;
    let turn_ordinal: i64 = row.try_get("turn_ordinal")?;
    let batch_seq: i64 = row.try_get("batch_seq")?;
    let state: String = row.try_get("state")?;
    let state = TranscriptOutboxStateV1::parse(&state).ok_or_else(|| {
        TranscriptConnectorError::LedgerIntegrity("stored outbox state is not a known state".into())
    })?;
    Ok(TranscriptOutboxRowV1 {
        outbox_id: Sha256Digest::from_bytes(outbox_id),
        source_id: row.try_get("source_id")?,
        session_id: row.try_get("session_id")?,
        turn_ordinal: u32::try_from(turn_ordinal).map_err(|_| {
            TranscriptConnectorError::LedgerIntegrity("stored turn ordinal is out of range".into())
        })?,
        canonical_candidate: row.try_get("canonical_candidate")?,
        canonical_locators: row.try_get("canonical_locators")?,
        canonical_payload: row.try_get("canonical_payload")?,
        state,
        batch_seq: u64::try_from(batch_seq).map_err(|_| {
            TranscriptConnectorError::LedgerIntegrity("stored batch sequence is negative".into())
        })?,
    })
}
