//! `CockroachDB` implementation of the lexical-first / dense-later recall
//! projection (W2-PROJ).
//!
//! Three runtimes live here, all bound once to one physical `(tenant_id,
//! project)` scope:
//!
//! * [`CockroachLexicalProjector`] — reads `memory_body_objects_v1` and writes
//!   `memory_body_lexical_projection_v1`, advancing the `'lexical'` cursor row.
//! * [`CockroachDenseProjector`] — the background worker: reads the lexical
//!   rows, calls the [`EmbeddingProvider`], and writes
//!   `memory_body_dense_projection_v1`, advancing the `'dense'` cursor row.
//! * [`CockroachRecallReader`] — the read side, which answers with both lane
//!   scores and the readiness that produced them.
//!
//! # Invariants enforced here
//!
//! * **Cursor atomicity (REPLAY-02).** Each batch's output rows AND its
//!   cursor advance are one serializable transaction. A crash or rollback
//!   between them leaves BOTH unwritten, so no cursor ever names a body whose
//!   row was not durably written.
//! * **Independent cursors.** The two projectors write different tables and
//!   different cursor rows (`projector = 'lexical'` / `'dense'`). Nothing the
//!   dense worker does — a provider outage, a rejected vector, a kill mid-batch
//!   — can remove a lexical row, roll the lexical cursor back, or make an
//!   already-projected body stop answering lexical queries.
//! * **Replay stability (REPLAY-01).** Rows are content-addressed and both
//!   derivations are pure, so re-running from the body tables rebuilds
//!   byte-identical rows.
//! * **Fail closed on identity drift.** A lexical text digest or an embedding
//!   identity that disagrees with the row already stored under the same body
//!   content address aborts the batch with a typed error and writes nothing.
//! * **Scope binding.** `(tenant_id, project)` is bound at construction; every
//!   read and write is filtered by that exact pair, so no stored row and no
//!   caller-supplied query can redirect a read or a write to another tenant or
//!   project.
//! * **Private plane.** Migration 0021 adds none of these tables to the
//!   publication grant list, and no public route reaches the dense worker.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::postgres::{PgPool, PgRow};
use sqlx::{Postgres, Row as _, Transaction};
use uuid::Uuid;

use crate::FleetError;
use crate::memory_contracts::digest::Sha256Digest;
use crate::store::cockroach::{
    RetryPolicy, is_retryable, is_retryable_fleet_error, serialize_vector,
};

use super::dense::{
    DerivedEmbeddingV1, EMBEDDING_DIMENSIONS, EmbeddingProvider, admit_embedding,
    distance_metric_label,
};
use super::error::{RecallProjectionError, RecallProjectionResult};
use super::lexical::{LexicalProjectionV1, LexicalStateV1, derive_lexical_projection};
use super::repository::{
    BodyPositionV1, DenseProjector, LexicalProjector, ProjectionCursorV1, ProjectionPassSummaryV1,
    ProjectorKindV1, RecallCompletenessV1, RecallHitV1, RecallProjectionSnapshotV1, RecallResultV1,
    RecallTierV1,
};

/// Bodies consumed per transaction when none is configured.
pub const DEFAULT_PROJECTION_BATCH: u32 = 64;

const MAX_RECALL_LIMIT: usize = 10_000;

const SELECT_CURSOR_SQL: &str = "SELECT last_body_created_at, last_body_content_id, bodies_projected \
     FROM public.memory_recall_projection_cursors_v1 \
     WHERE tenant_id = $1 AND project = $2 AND projector = $3";

// The cursor only ever moves FORWARD: the WHERE guard on the UPDATE arm makes a
// stale or replayed batch a no-op instead of a rollback of durable progress.
const UPSERT_CURSOR_SQL: &str = "INSERT INTO public.memory_recall_projection_cursors_v1 (\
     tenant_id, project, projector, last_body_created_at, last_body_content_id, \
     bodies_projected, updated_at\
     ) VALUES ($1, $2, $3, $4, $5, $6, $7) \
     ON CONFLICT (tenant_id, project, projector) DO UPDATE SET \
     last_body_created_at = excluded.last_body_created_at, \
     last_body_content_id = excluded.last_body_content_id, \
     bodies_projected = public.memory_recall_projection_cursors_v1.bodies_projected \
         + excluded.bodies_projected, \
     updated_at = excluded.updated_at \
     WHERE (public.memory_recall_projection_cursors_v1.last_body_created_at, \
            public.memory_recall_projection_cursors_v1.last_body_content_id) \
         < (excluded.last_body_created_at, excluded.last_body_content_id)";

const SELECT_BODIES_FROM_START_SQL: &str = "SELECT content_sha256, body_bytes, created_at \
     FROM public.memory_body_objects_v1 \
     WHERE tenant_id = $1 AND project = $2 \
     ORDER BY created_at, content_sha256 LIMIT $3";

const SELECT_BODIES_AFTER_SQL: &str = "SELECT content_sha256, body_bytes, created_at \
     FROM public.memory_body_objects_v1 \
     WHERE tenant_id = $1 AND project = $2 \
       AND (created_at, content_sha256) > ($3, $4) \
     ORDER BY created_at, content_sha256 LIMIT $5";

const INSERT_LEXICAL_SQL: &str = "INSERT INTO public.memory_body_lexical_projection_v1 (\
     tenant_id, project, body_content_id, body_created_at, lexical_state, \
     unindexable_reason, normalization_version, lexical_text, lexical_text_digest\
     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
     ON CONFLICT (tenant_id, project, body_content_id) DO NOTHING";

const SELECT_LEXICAL_DIGEST_SQL: &str = "SELECT lexical_text_digest \
     FROM public.memory_body_lexical_projection_v1 \
     WHERE tenant_id = $1 AND project = $2 AND body_content_id = $3";

const SELECT_LEXICAL_FROM_START_SQL: &str = "SELECT body_content_id, body_created_at, \
     lexical_state, unindexable_reason, lexical_text \
     FROM public.memory_body_lexical_projection_v1 \
     WHERE tenant_id = $1 AND project = $2 \
     ORDER BY body_created_at, body_content_id LIMIT $3";

const SELECT_LEXICAL_AFTER_SQL: &str = "SELECT body_content_id, body_created_at, \
     lexical_state, unindexable_reason, lexical_text \
     FROM public.memory_body_lexical_projection_v1 \
     WHERE tenant_id = $1 AND project = $2 \
       AND (body_created_at, body_content_id) > ($3, $4) \
     ORDER BY body_created_at, body_content_id LIMIT $5";

const INSERT_DENSE_SQL: &str = "INSERT INTO public.memory_body_dense_projection_v1 (\
     tenant_id, project, body_content_id, body_created_at, embedding_identity_id, \
     model_digest, tokenization_version, preprocessing_version, distance_metric, \
     dimensions, embedding\
     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::VECTOR(512)) \
     ON CONFLICT (tenant_id, project, body_content_id) DO NOTHING";

const SELECT_DENSE_IDENTITY_SQL: &str = "SELECT embedding_identity_id \
     FROM public.memory_body_dense_projection_v1 \
     WHERE tenant_id = $1 AND project = $2 AND body_content_id = $3";

// Scope columns lead, exactly like LEXICAL_SEARCH_SQL over memory_chunks, so
// the inverted index stays selective inside one project.
const LEXICAL_RECALL_SQL: &str = "SELECT body_content_id, \
     ts_rank(search_document, plainto_tsquery('english', $3))::FLOAT4 AS score \
     FROM public.memory_body_lexical_projection_v1 \
     WHERE tenant_id = $1 AND project = $2 \
       AND search_document @@ plainto_tsquery('english', $3) \
     ORDER BY score DESC, body_content_id LIMIT $4";

// C-SPANN equality prefix: tenant_id and project are the only columns ahead of
// `embedding` in memory_body_dense_projection_semantic_idx, and both are bound
// with equality here, so CockroachDB can serve the ANN portion of the scan.
const DENSE_RECALL_SQL: &str = "SELECT body_content_id, \
     (embedding <=> $3::VECTOR(512))::FLOAT4 AS distance \
     FROM public.memory_body_dense_projection_v1 \
     WHERE tenant_id = $1 AND project = $2 \
     ORDER BY embedding <=> $3::VECTOR(512) LIMIT $4";

const COMPLETENESS_SQL: &str = "SELECT \
     (SELECT count(*) FROM public.memory_body_objects_v1 \
        WHERE tenant_id = $1 AND project = $2) AS bodies_total, \
     (SELECT count(*) FROM public.memory_body_lexical_projection_v1 \
        WHERE tenant_id = $1 AND project = $2 AND lexical_state = 'indexed') AS lexically_indexed, \
     (SELECT count(*) FROM public.memory_body_lexical_projection_v1 \
        WHERE tenant_id = $1 AND project = $2 AND lexical_state = 'unindexable') \
        AS lexically_unindexable, \
     (SELECT count(*) FROM public.memory_body_dense_projection_v1 \
        WHERE tenant_id = $1 AND project = $2) AS densely_embedded";

/// One body row the lexical projector consumes.
#[derive(Debug, Clone)]
struct BodyRowV1 {
    position: BodyPositionV1,
    body_bytes: Vec<u8>,
}

/// One lexical row the dense worker consumes.
#[derive(Debug, Clone)]
struct LexicalRowV1 {
    position: BodyPositionV1,
    state: LexicalStateV1,
    text: String,
}

/// Physical scope plus pool, shared by all three runtimes in this module.
#[derive(Clone)]
struct ScopeBinding {
    pool: PgPool,
    tenant_id: Uuid,
    project: String,
}

impl ScopeBinding {
    async fn read_cursor(
        &self,
        projector: ProjectorKindV1,
    ) -> RecallProjectionResult<Option<ProjectionCursorV1>> {
        let row: Option<PgRow> = sqlx::query(SELECT_CURSOR_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(projector.as_str())
            .fetch_optional(&self.pool)
            .await?;
        row.map(|row| {
            let bodies_projected = u64::try_from(row.try_get::<i64, _>("bodies_projected")?)
                .map_err(|_| {
                    RecallProjectionError::ProjectionIntegrity(
                        "stored cursor carries a negative projected count".into(),
                    )
                })?;
            Ok(ProjectionCursorV1 {
                projector,
                position: BodyPositionV1 {
                    created_at: row.try_get("last_body_created_at")?,
                    content_id: digest32(row.try_get("last_body_content_id")?)?,
                },
                bodies_projected,
            })
        })
        .transpose()
    }

    async fn advance_cursor(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        projector: ProjectorKindV1,
        position: BodyPositionV1,
        consumed: u64,
        now: DateTime<Utc>,
    ) -> RecallProjectionResult<()> {
        let consumed = i64::try_from(consumed).map_err(|_| {
            RecallProjectionError::ProjectionIntegrity("batch size exceeds INT8".into())
        })?;
        sqlx::query(UPSERT_CURSOR_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(projector.as_str())
            .bind(position.created_at)
            .bind(bytes(position.content_id))
            .bind(consumed)
            .bind(now)
            .execute(&mut **transaction)
            .await?;
        Ok(())
    }
}

/// Open one serializable transaction on `pool`.
async fn begin_serializable(
    pool: &PgPool,
) -> RecallProjectionResult<Transaction<'static, Postgres>> {
    let mut transaction = pool.begin().await.map_err(FleetError::from)?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        .execute(&mut *transaction)
        .await?;
    Ok(transaction)
}

/// Decide what a failed batch attempt should do next.
///
/// `CockroachDB` reports every transaction restart as SQLSTATE 40001; those are
/// safe to replay because both projectors' batches are idempotent (every row
/// they write is content-addressed and every derivation is pure). Anything else
/// is a closed rejection and is returned to the caller unchanged.
enum BatchRetry {
    /// Sleep and re-run the batch against a fresh transaction.
    Again(std::time::Duration),
    /// Give up with this error.
    Fail(RecallProjectionError),
}

fn classify_batch_failure(
    error: RecallProjectionError,
    retry_policy: RetryPolicy,
    attempt: u32,
) -> BatchRetry {
    let retryable = match &error {
        RecallProjectionError::Storage(inner) => is_retryable_fleet_error(inner),
        _ => false,
    };
    if retryable && attempt < retry_policy.max_attempts {
        BatchRetry::Again(retry_policy.delay_for_retry(attempt - 1))
    } else {
        BatchRetry::Fail(error)
    }
}

fn classify_commit_failure(
    error: sqlx::Error,
    retry_policy: RetryPolicy,
    attempt: u32,
) -> BatchRetry {
    if is_retryable(&error) && attempt < retry_policy.max_attempts {
        BatchRetry::Again(retry_policy.delay_for_retry(attempt - 1))
    } else {
        BatchRetry::Fail(RecallProjectionError::from(error))
    }
}

// ---------------------------------------------------------------------------
// Lexical tier.
// ---------------------------------------------------------------------------

/// Lexical projector, bound once to physical scope.
#[derive(Clone)]
pub struct CockroachLexicalProjector {
    scope: ScopeBinding,
    batch: u32,
    retry_policy: RetryPolicy,
}

impl std::fmt::Debug for CockroachLexicalProjector {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CockroachLexicalProjector")
            .field("tenant_id", &self.scope.tenant_id)
            .field("project", &self.scope.project)
            .finish_non_exhaustive()
    }
}

impl CockroachLexicalProjector {
    /// Bind one pool, one physical scope, and a batch size.
    ///
    /// A zero `batch` is coerced to [`DEFAULT_PROJECTION_BATCH`] rather than
    /// silently making the projector a no-op.
    #[must_use]
    pub const fn new(
        pool: PgPool,
        tenant_id: Uuid,
        project: String,
        batch: u32,
        retry_policy: RetryPolicy,
    ) -> Self {
        Self {
            scope: ScopeBinding {
                pool,
                tenant_id,
                project,
            },
            batch: if batch == 0 {
                DEFAULT_PROJECTION_BATCH
            } else {
                batch
            },
            retry_policy,
        }
    }

    /// Read this scope's persisted lexical cursor.
    pub async fn read_cursor(&self) -> RecallProjectionResult<Option<ProjectionCursorV1>> {
        self.scope.read_cursor(ProjectorKindV1::Lexical).await
    }

    async fn scan_bodies(
        &self,
        after: Option<BodyPositionV1>,
    ) -> RecallProjectionResult<Vec<BodyRowV1>> {
        let limit = i64::from(self.batch);
        let rows: Vec<PgRow> = match after {
            Some(position) => {
                sqlx::query(SELECT_BODIES_AFTER_SQL)
                    .bind(self.scope.tenant_id)
                    .bind(&self.scope.project)
                    .bind(position.created_at)
                    .bind(bytes(position.content_id))
                    .bind(limit)
                    .fetch_all(&self.scope.pool)
                    .await?
            }
            None => {
                sqlx::query(SELECT_BODIES_FROM_START_SQL)
                    .bind(self.scope.tenant_id)
                    .bind(&self.scope.project)
                    .bind(limit)
                    .fetch_all(&self.scope.pool)
                    .await?
            }
        };
        rows.iter()
            .map(|row| {
                Ok(BodyRowV1 {
                    position: BodyPositionV1 {
                        created_at: row.try_get("created_at")?,
                        content_id: digest32(row.try_get("content_sha256")?)?,
                    },
                    body_bytes: row.try_get("body_bytes")?,
                })
            })
            .collect()
    }

    /// Write one batch's lexical rows AND advance the lexical cursor in one
    /// transaction.
    async fn apply_batch(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        batch: &[BodyRowV1],
    ) -> RecallProjectionResult<ProjectionPassSummaryV1> {
        let now: DateTime<Utc> = sqlx::query_scalar("SELECT pg_catalog.statement_timestamp()")
            .fetch_one(&mut **transaction)
            .await?;
        let mut summary = ProjectionPassSummaryV1::default();
        let mut last = None;
        for body in batch {
            // Fails closed if the stored bytes do not reproduce the address.
            let derived = derive_lexical_projection(body.position.content_id, &body.body_bytes)?;
            self.write_lexical(transaction, body.position, &derived)
                .await?;
            summary.bodies_consumed += 1;
            if derived.state.is_indexed() {
                summary.rows_indexed += 1;
            } else {
                summary.rows_unindexable += 1;
            }
            last = Some(body.position);
        }
        if let Some(position) = last {
            self.scope
                .advance_cursor(
                    transaction,
                    ProjectorKindV1::Lexical,
                    position,
                    summary.bodies_consumed,
                    now,
                )
                .await?;
        }
        Ok(summary)
    }

    async fn write_lexical(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        position: BodyPositionV1,
        derived: &LexicalProjectionV1,
    ) -> RecallProjectionResult<()> {
        sqlx::query(INSERT_LEXICAL_SQL)
            .bind(self.scope.tenant_id)
            .bind(&self.scope.project)
            .bind(bytes(derived.body_content_id))
            .bind(position.created_at)
            .bind(derived.state.as_str())
            .bind(derived.state.reason_str())
            .bind(i64::from(derived.normalization_version))
            .bind(&derived.text)
            .bind(bytes(derived.text_digest))
            .execute(&mut **transaction)
            .await?;

        // A row already stored under this content address must agree with the
        // one just derived; otherwise the normalizer or the row changed under a
        // fixed normalization version. Fail closed rather than overwrite.
        let stored: Vec<u8> = sqlx::query_scalar(SELECT_LEXICAL_DIGEST_SQL)
            .bind(self.scope.tenant_id)
            .bind(&self.scope.project)
            .bind(bytes(derived.body_content_id))
            .fetch_one(&mut **transaction)
            .await?;
        if stored != derived.text_digest.as_bytes() {
            return Err(RecallProjectionError::LexicalDigestCollision);
        }
        Ok(())
    }

    async fn run_pass(&self, from_cursor: bool) -> RecallProjectionResult<ProjectionPassSummaryV1> {
        let mut position = if from_cursor {
            self.read_cursor().await?.map(|cursor| cursor.position)
        } else {
            None
        };
        let mut summary = ProjectionPassSummaryV1::default();
        loop {
            let batch = self.scan_bodies(position).await?;
            let Some(last) = batch.last().map(|row| row.position) else {
                break;
            };
            summary.absorb(self.commit_batch(&batch).await?);
            position = Some(last);
        }
        Ok(summary)
    }

    /// One batch, one bounded serializable-transaction retry loop.
    async fn commit_batch(
        &self,
        batch: &[BodyRowV1],
    ) -> RecallProjectionResult<ProjectionPassSummaryV1> {
        let mut attempt = 0_u32;
        loop {
            attempt += 1;
            let mut transaction = begin_serializable(&self.scope.pool).await?;
            let outcome = match self.apply_batch(&mut transaction, batch).await {
                Ok(outcome) => outcome,
                Err(error) => match classify_batch_failure(error, self.retry_policy, attempt) {
                    BatchRetry::Again(delay) => {
                        drop(transaction);
                        tokio::time::sleep(delay).await;
                        continue;
                    }
                    BatchRetry::Fail(error) => return Err(error),
                },
            };
            match transaction.commit().await {
                Ok(()) => return Ok(outcome),
                Err(error) => match classify_commit_failure(error, self.retry_policy, attempt) {
                    BatchRetry::Again(delay) => tokio::time::sleep(delay).await,
                    BatchRetry::Fail(error) => return Err(error),
                },
            }
        }
    }

    /// Test/inspection helper: apply the first pending batch inside one
    /// serializable transaction and then ROLL BACK.
    ///
    /// This proves cursor atomicity directly: the rows and the cursor advance
    /// are the same transaction, so a rollback — the model of a crash between
    /// output and cursor commit — leaves BOTH unwritten. Returns whether a
    /// pending batch was found.
    pub async fn probe_apply_first_batch_then_rollback(&self) -> RecallProjectionResult<bool> {
        let position = self.read_cursor().await?.map(|cursor| cursor.position);
        let batch = self.scan_bodies(position).await?;
        if batch.is_empty() {
            return Ok(false);
        }
        let mut transaction = begin_serializable(&self.scope.pool).await?;
        self.apply_batch(&mut transaction, &batch).await?;
        // Deliberately drop without commit: rolls rows AND cursor back together.
        drop(transaction);
        Ok(true)
    }
}

#[async_trait]
impl LexicalProjector for CockroachLexicalProjector {
    async fn project_pending(&self) -> RecallProjectionResult<ProjectionPassSummaryV1> {
        self.run_pass(true).await
    }

    async fn reproject_all(&self) -> RecallProjectionResult<ProjectionPassSummaryV1> {
        self.run_pass(false).await
    }
}

// ---------------------------------------------------------------------------
// Dense tier (background worker, private plane only).
// ---------------------------------------------------------------------------

/// Dense (embedding) worker, bound once to physical scope and one provider.
#[derive(Clone)]
pub struct CockroachDenseProjector {
    scope: ScopeBinding,
    provider: Arc<dyn EmbeddingProvider>,
    batch: u32,
    retry_policy: RetryPolicy,
}

impl std::fmt::Debug for CockroachDenseProjector {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CockroachDenseProjector")
            .field("tenant_id", &self.scope.tenant_id)
            .field("project", &self.scope.project)
            .finish_non_exhaustive()
    }
}

impl CockroachDenseProjector {
    /// Bind one pool, one physical scope, one embedding provider, and a batch
    /// size.
    #[must_use]
    pub fn new(
        pool: PgPool,
        tenant_id: Uuid,
        project: String,
        provider: Arc<dyn EmbeddingProvider>,
        batch: u32,
        retry_policy: RetryPolicy,
    ) -> Self {
        Self {
            scope: ScopeBinding {
                pool,
                tenant_id,
                project,
            },
            provider,
            batch: if batch == 0 {
                DEFAULT_PROJECTION_BATCH
            } else {
                batch
            },
            retry_policy,
        }
    }

    /// Read this scope's persisted dense cursor.
    pub async fn read_cursor(&self) -> RecallProjectionResult<Option<ProjectionCursorV1>> {
        self.scope.read_cursor(ProjectorKindV1::Dense).await
    }

    async fn scan_lexical(
        &self,
        after: Option<BodyPositionV1>,
    ) -> RecallProjectionResult<Vec<LexicalRowV1>> {
        let limit = i64::from(self.batch);
        let rows: Vec<PgRow> = match after {
            Some(position) => {
                sqlx::query(SELECT_LEXICAL_AFTER_SQL)
                    .bind(self.scope.tenant_id)
                    .bind(&self.scope.project)
                    .bind(position.created_at)
                    .bind(bytes(position.content_id))
                    .bind(limit)
                    .fetch_all(&self.scope.pool)
                    .await?
            }
            None => {
                sqlx::query(SELECT_LEXICAL_FROM_START_SQL)
                    .bind(self.scope.tenant_id)
                    .bind(&self.scope.project)
                    .bind(limit)
                    .fetch_all(&self.scope.pool)
                    .await?
            }
        };
        rows.iter()
            .map(|row| {
                let state = LexicalStateV1::parse(
                    row.try_get::<String, _>("lexical_state")?.as_str(),
                    row.try_get::<String, _>("unindexable_reason")?.as_str(),
                )?;
                Ok(LexicalRowV1 {
                    position: BodyPositionV1 {
                        created_at: row.try_get("body_created_at")?,
                        content_id: digest32(row.try_get("body_content_id")?)?,
                    },
                    state,
                    text: row.try_get("lexical_text")?,
                })
            })
            .collect()
    }

    /// Call the provider for every indexable row in the batch BEFORE opening a
    /// transaction.
    ///
    /// Keeping the model call outside the transaction is deliberate: a slow or
    /// failing provider must not hold a serializable transaction open, and a
    /// provider failure must abort the batch before any row is written.
    async fn embed_batch(
        &self,
        batch: &[LexicalRowV1],
    ) -> RecallProjectionResult<(Vec<(BodyPositionV1, DerivedEmbeddingV1)>, u64)> {
        let descriptor = self.provider.descriptor();
        let mut embedded = Vec::with_capacity(batch.len());
        let mut unindexable = 0_u64;
        for row in batch {
            if !row.state.is_indexed() {
                unindexable += 1;
                continue;
            }
            let vector = self.provider.embed(&row.text).await?;
            let admitted = admit_embedding(descriptor, row.position.content_id, vector)?;
            embedded.push((row.position, admitted));
        }
        Ok((embedded, unindexable))
    }

    /// Write one batch's dense rows AND advance the dense cursor in one
    /// transaction.
    async fn apply_batch(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        embedded: &[(BodyPositionV1, DerivedEmbeddingV1)],
        last: BodyPositionV1,
        consumed: u64,
    ) -> RecallProjectionResult<()> {
        let now: DateTime<Utc> = sqlx::query_scalar("SELECT pg_catalog.statement_timestamp()")
            .fetch_one(&mut **transaction)
            .await?;
        let descriptor = self.provider.descriptor();
        for (position, admitted) in embedded {
            let encoded = serialize_vector(&admitted.vector)?;
            sqlx::query(INSERT_DENSE_SQL)
                .bind(self.scope.tenant_id)
                .bind(&self.scope.project)
                .bind(bytes(admitted.body_content_id))
                .bind(position.created_at)
                .bind(bytes(admitted.identity.digest()))
                .bind(bytes(descriptor.model_digest))
                .bind(i64::from(descriptor.tokenization_version))
                .bind(i64::from(descriptor.preprocessing_version))
                .bind(distance_metric_label(descriptor.distance_metric))
                .bind(i64::from(descriptor.dimensions))
                .bind(encoded)
                .execute(&mut **transaction)
                .await?;

            let stored: Vec<u8> = sqlx::query_scalar(SELECT_DENSE_IDENTITY_SQL)
                .bind(self.scope.tenant_id)
                .bind(&self.scope.project)
                .bind(bytes(admitted.body_content_id))
                .fetch_one(&mut **transaction)
                .await?;
            if stored != admitted.identity.digest().as_bytes() {
                return Err(RecallProjectionError::EmbeddingIdentityCollision);
            }
        }
        self.scope
            .advance_cursor(transaction, ProjectorKindV1::Dense, last, consumed, now)
            .await?;
        Ok(())
    }

    async fn run_pass(&self, from_cursor: bool) -> RecallProjectionResult<ProjectionPassSummaryV1> {
        let mut position = if from_cursor {
            self.read_cursor().await?.map(|cursor| cursor.position)
        } else {
            None
        };
        let mut summary = ProjectionPassSummaryV1::default();
        loop {
            let batch = self.scan_lexical(position).await?;
            let Some(last) = batch.last().map(|row| row.position) else {
                break;
            };
            let consumed = u64::try_from(batch.len()).map_err(|_| {
                RecallProjectionError::ProjectionIntegrity("batch size exceeds u64".into())
            })?;
            // The provider is called BEFORE the transaction opens, so a
            // provider failure aborts the batch without any row being written
            // and without holding a serializable transaction open.
            let (embedded, unindexable) = self.embed_batch(&batch).await?;
            let indexed = u64::try_from(embedded.len()).map_err(|_| {
                RecallProjectionError::ProjectionIntegrity("batch size exceeds u64".into())
            })?;
            self.commit_batch(&embedded, last, consumed).await?;
            summary.absorb(ProjectionPassSummaryV1 {
                bodies_consumed: consumed,
                rows_indexed: indexed,
                rows_unindexable: unindexable,
            });
            position = Some(last);
        }
        Ok(summary)
    }

    /// One batch, one bounded serializable-transaction retry loop.
    async fn commit_batch(
        &self,
        embedded: &[(BodyPositionV1, DerivedEmbeddingV1)],
        last: BodyPositionV1,
        consumed: u64,
    ) -> RecallProjectionResult<()> {
        let mut attempt = 0_u32;
        loop {
            attempt += 1;
            let mut transaction = begin_serializable(&self.scope.pool).await?;
            if let Err(error) = self
                .apply_batch(&mut transaction, embedded, last, consumed)
                .await
            {
                match classify_batch_failure(error, self.retry_policy, attempt) {
                    BatchRetry::Again(delay) => {
                        drop(transaction);
                        tokio::time::sleep(delay).await;
                        continue;
                    }
                    BatchRetry::Fail(error) => return Err(error),
                }
            }
            match transaction.commit().await {
                Ok(()) => return Ok(()),
                Err(error) => match classify_commit_failure(error, self.retry_policy, attempt) {
                    BatchRetry::Again(delay) => tokio::time::sleep(delay).await,
                    BatchRetry::Fail(error) => return Err(error),
                },
            }
        }
    }

    /// Test/inspection helper: embed and write the first pending batch inside
    /// one serializable transaction, then ROLL BACK — the model of the worker
    /// being killed mid-batch. Returns whether a pending batch was found.
    pub async fn probe_apply_first_batch_then_rollback(&self) -> RecallProjectionResult<bool> {
        let position = self.read_cursor().await?.map(|cursor| cursor.position);
        let batch = self.scan_lexical(position).await?;
        let Some(last) = batch.last().map(|row| row.position) else {
            return Ok(false);
        };
        let consumed = u64::try_from(batch.len()).map_err(|_| {
            RecallProjectionError::ProjectionIntegrity("batch size exceeds u64".into())
        })?;
        let (embedded, _) = self.embed_batch(&batch).await?;
        let mut transaction = begin_serializable(&self.scope.pool).await?;
        self.apply_batch(&mut transaction, &embedded, last, consumed)
            .await?;
        drop(transaction);
        Ok(true)
    }
}

#[async_trait]
impl DenseProjector for CockroachDenseProjector {
    async fn embed_pending(&self) -> RecallProjectionResult<ProjectionPassSummaryV1> {
        self.run_pass(true).await
    }

    async fn reembed_all(&self) -> RecallProjectionResult<ProjectionPassSummaryV1> {
        self.run_pass(false).await
    }
}

// ---------------------------------------------------------------------------
// Read side.
// ---------------------------------------------------------------------------

/// Recall over the projection, bound once to physical scope.
#[derive(Clone)]
pub struct CockroachRecallReader {
    scope: ScopeBinding,
}

impl std::fmt::Debug for CockroachRecallReader {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CockroachRecallReader")
            .field("tenant_id", &self.scope.tenant_id)
            .field("project", &self.scope.project)
            .finish_non_exhaustive()
    }
}

impl CockroachRecallReader {
    /// Bind one pool and one physical scope.
    #[must_use]
    pub const fn new(pool: PgPool, tenant_id: Uuid, project: String) -> Self {
        Self {
            scope: ScopeBinding {
                pool,
                tenant_id,
                project,
            },
        }
    }

    /// Read how complete each tier is for this scope.
    pub async fn completeness(&self) -> RecallProjectionResult<RecallCompletenessV1> {
        let row: PgRow = sqlx::query(COMPLETENESS_SQL)
            .bind(self.scope.tenant_id)
            .bind(&self.scope.project)
            .fetch_one(&self.scope.pool)
            .await?;
        Ok(RecallCompletenessV1 {
            bodies_total: count(&row, "bodies_total")?,
            lexically_indexed: count(&row, "lexically_indexed")?,
            lexically_unindexable: count(&row, "lexically_unindexable")?,
            densely_embedded: count(&row, "densely_embedded")?,
        })
    }

    /// Recall bodies for `query_text`, optionally topped up by a dense lane.
    ///
    /// The lexical lane always runs. The dense lane runs only when a query
    /// vector is supplied AND the dense tier has rows; a scope whose dense
    /// worker has never run — or has failed every attempt — still answers from
    /// the lexical lane, and says so through [`RecallResultV1::tier`] and
    /// [`RecallResultV1::completeness`].
    pub async fn recall(
        &self,
        query_text: &str,
        query_vector: Option<&[f32]>,
        limit: usize,
    ) -> RecallProjectionResult<RecallResultV1> {
        if limit == 0 || limit > MAX_RECALL_LIMIT {
            return Err(RecallProjectionError::InvalidRequest(format!(
                "recall limit must be between 1 and {MAX_RECALL_LIMIT}"
            )));
        }
        let limit_i64 = i64::try_from(limit).map_err(|_| {
            RecallProjectionError::InvalidRequest("recall limit exceeds INT8".into())
        })?;

        let lexical = self.lexical_lane(query_text, limit_i64).await?;
        let dense = match query_vector {
            Some(vector) => self.dense_lane(vector, limit_i64).await?,
            None => Vec::new(),
        };

        let tier = match (lexical.is_empty(), dense.is_empty()) {
            (true, true) => RecallTierV1::None,
            (false, true) => RecallTierV1::Lexical,
            (true, false) => RecallTierV1::Dense,
            (false, false) => RecallTierV1::Hybrid,
        };

        let dense_by_body: HashMap<[u8; 32], f32> = dense
            .iter()
            .map(|(body, distance)| (*body.as_bytes(), *distance))
            .collect();
        let lexical_bodies: Vec<[u8; 32]> = lexical
            .iter()
            .map(|(body, _)| *body.as_bytes())
            .collect::<Vec<_>>();

        let mut hits: Vec<RecallHitV1> = lexical
            .iter()
            .map(|(body, score)| RecallHitV1 {
                body_content_id: *body,
                lexical_score: Some(*score),
                dense_distance: dense_by_body.get(body.as_bytes()).copied(),
            })
            .collect();
        hits.extend(
            dense
                .iter()
                .filter(|(body, _)| !lexical_bodies.contains(body.as_bytes()))
                .map(|(body, distance)| RecallHitV1 {
                    body_content_id: *body,
                    lexical_score: None,
                    dense_distance: Some(*distance),
                }),
        );
        hits.truncate(limit);

        Ok(RecallResultV1 {
            hits,
            tier,
            completeness: self.completeness().await?,
        })
    }

    async fn lexical_lane(
        &self,
        query_text: &str,
        limit: i64,
    ) -> RecallProjectionResult<Vec<(Sha256Digest, f32)>> {
        if query_text.trim().is_empty() {
            return Ok(Vec::new());
        }
        let rows: Vec<PgRow> = sqlx::query(LEXICAL_RECALL_SQL)
            .bind(self.scope.tenant_id)
            .bind(&self.scope.project)
            .bind(query_text)
            .bind(limit)
            .fetch_all(&self.scope.pool)
            .await?;
        rows.iter()
            .map(|row| {
                Ok((
                    digest32(row.try_get("body_content_id")?)?,
                    row.try_get("score")?,
                ))
            })
            .collect()
    }

    async fn dense_lane(
        &self,
        query_vector: &[f32],
        limit: i64,
    ) -> RecallProjectionResult<Vec<(Sha256Digest, f32)>> {
        if query_vector.len() != EMBEDDING_DIMENSIONS as usize {
            return Err(RecallProjectionError::InvalidRequest(format!(
                "recall query vector must have {EMBEDDING_DIMENSIONS} components, got {}",
                query_vector.len()
            )));
        }
        let encoded = serialize_vector(query_vector)?;
        let rows: Vec<PgRow> = sqlx::query(DENSE_RECALL_SQL)
            .bind(self.scope.tenant_id)
            .bind(&self.scope.project)
            .bind(encoded)
            .bind(limit)
            .fetch_all(&self.scope.pool)
            .await?;
        rows.iter()
            .map(|row| {
                Ok((
                    digest32(row.try_get("body_content_id")?)?,
                    row.try_get("distance")?,
                ))
            })
            .collect()
    }

    /// Read the full, deterministically ordered projection snapshot for this
    /// scope. Two snapshots taken after two independent replays compare equal
    /// iff the projectors rebuilt byte-identical rows (REPLAY-01).
    pub async fn snapshot(&self) -> RecallProjectionResult<RecallProjectionSnapshotV1> {
        let mut snapshot = RecallProjectionSnapshotV1::default();

        let lexical_rows: Vec<PgRow> = sqlx::query(
            "SELECT body_content_id, lexical_state, unindexable_reason, normalization_version, \
                    lexical_text, lexical_text_digest \
             FROM public.memory_body_lexical_projection_v1 \
             WHERE tenant_id = $1 AND project = $2 ORDER BY body_content_id",
        )
        .bind(self.scope.tenant_id)
        .bind(&self.scope.project)
        .fetch_all(&self.scope.pool)
        .await?;
        for row in &lexical_rows {
            snapshot.lexical.push((
                row.try_get("body_content_id")?,
                row.try_get("lexical_state")?,
                row.try_get("unindexable_reason")?,
                row.try_get("normalization_version")?,
                row.try_get("lexical_text")?,
                row.try_get("lexical_text_digest")?,
            ));
        }

        let dense_rows: Vec<PgRow> = sqlx::query(
            "SELECT body_content_id, embedding_identity_id, model_digest, distance_metric, \
                    dimensions, embedding::STRING AS embedding_text \
             FROM public.memory_body_dense_projection_v1 \
             WHERE tenant_id = $1 AND project = $2 ORDER BY body_content_id",
        )
        .bind(self.scope.tenant_id)
        .bind(&self.scope.project)
        .fetch_all(&self.scope.pool)
        .await?;
        for row in &dense_rows {
            snapshot.dense.push((
                row.try_get("body_content_id")?,
                row.try_get("embedding_identity_id")?,
                row.try_get("model_digest")?,
                row.try_get("distance_metric")?,
                row.try_get("dimensions")?,
                row.try_get("embedding_text")?,
            ));
        }

        Ok(snapshot)
    }
}

fn bytes(digest: Sha256Digest) -> Vec<u8> {
    digest.as_bytes().to_vec()
}

fn digest32(value: Vec<u8>) -> RecallProjectionResult<Sha256Digest> {
    let bytes: [u8; 32] = value.try_into().map_err(|_| {
        RecallProjectionError::ProjectionIntegrity("stored digest column is not 32 bytes".into())
    })?;
    Ok(Sha256Digest::from_bytes(bytes))
}

fn count(row: &PgRow, column: &str) -> RecallProjectionResult<u64> {
    let value: i64 = row.try_get(column)?;
    u64::try_from(value).map_err(|_| {
        RecallProjectionError::ProjectionIntegrity(format!("{column} returned a negative count"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_projection_statement_binds_scope_first() {
        // Scope binding is the security boundary: a statement that reads or
        // writes without tenant_id AND project equality could cross tenants.
        for statement in [
            SELECT_CURSOR_SQL,
            SELECT_BODIES_FROM_START_SQL,
            SELECT_BODIES_AFTER_SQL,
            SELECT_LEXICAL_DIGEST_SQL,
            SELECT_LEXICAL_FROM_START_SQL,
            SELECT_LEXICAL_AFTER_SQL,
            SELECT_DENSE_IDENTITY_SQL,
            LEXICAL_RECALL_SQL,
            DENSE_RECALL_SQL,
            COMPLETENESS_SQL,
        ] {
            assert!(
                statement.contains("tenant_id = $1") && statement.contains("project = $2"),
                "statement must bind scope first: {statement}"
            );
        }
        // The INSERTs bind scope as their first two values, and every one of
        // their conflict targets is scope-led, so an upsert can never adopt
        // another tenant's row.
        for statement in [INSERT_LEXICAL_SQL, INSERT_DENSE_SQL, UPSERT_CURSOR_SQL] {
            assert!(statement.contains("tenant_id, project,"), "{statement}");
            assert!(statement.contains("VALUES ($1, $2,"), "{statement}");
            assert!(
                statement.contains("ON CONFLICT (tenant_id, project,"),
                "{statement}"
            );
        }
    }

    #[test]
    fn the_dense_recall_query_keeps_the_c_spann_equality_prefix() {
        // memory_body_dense_projection_semantic_idx is
        // (tenant_id, project, embedding vector_cosine_ops). CockroachDB can
        // only serve the ANN portion when every column ahead of the vector is
        // an equality predicate, so the dense query must never grow a range
        // filter or an extra prefix column.
        assert!(DENSE_RECALL_SQL.contains("WHERE tenant_id = $1 AND project = $2 "));
        assert!(DENSE_RECALL_SQL.contains("ORDER BY embedding <=> $3::VECTOR(512)"));
        assert!(!DENSE_RECALL_SQL.contains(" AND ("));
    }

    #[test]
    fn the_cursor_upsert_only_ever_moves_forward() {
        // A replayed or out-of-order batch must not roll durable progress back.
        assert!(
            UPSERT_CURSOR_SQL.contains("ON CONFLICT (tenant_id, project, projector) DO UPDATE")
        );
        assert!(UPSERT_CURSOR_SQL.contains("< (excluded.last_body_created_at,"));
    }

    #[test]
    fn neither_projection_table_is_readable_through_the_public_plane() {
        // The projection carries text and vectors derived from governed private
        // bodies. The publication reader's table inventory is the public
        // plane's whole surface, so absence from it is the guarantee.
        for table in [
            "memory_body_lexical_projection_v1",
            "memory_body_dense_projection_v1",
            "memory_recall_projection_cursors_v1",
        ] {
            assert!(
                !crate::store::cockroach::PUBLICATION_READ_TABLES.contains(&table),
                "{table} must stay off the public plane"
            );
        }
    }

    #[test]
    fn the_two_tiers_write_disjoint_tables() {
        // The physical reason a dense failure cannot remove lexical
        // availability: no statement writes both tables.
        assert!(INSERT_LEXICAL_SQL.contains("memory_body_lexical_projection_v1"));
        assert!(!INSERT_LEXICAL_SQL.contains("memory_body_dense_projection_v1"));
        assert!(INSERT_DENSE_SQL.contains("memory_body_dense_projection_v1"));
        assert!(!INSERT_DENSE_SQL.contains("memory_body_lexical_projection_v1"));
    }
}
