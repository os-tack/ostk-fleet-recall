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
//! * **Visibility binding (W2-VIS).** Every projection row carries the
//!   read-plane class of the accepted evidence event that produced its body,
//!   defaulting to `'private'` at the column level. The recall predicate lives
//!   INSIDE the SQL — the publication plane reads views whose own WHERE clause
//!   is the restriction — so a private row is excluded before ranking, before
//!   `LIMIT`, and before any count. Nothing here post-filters in Rust.
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
use super::visibility::{RecallPlaneV1, RowVisibilityClassV1};

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

// The body scan carries the visibility decision with it. The LEFT JOIN plus
// COALESCE is the fail-closed default (W2-VIS): a body with no
// memory_body_visibility_v1 row — one projected before migration 0023, or one
// whose decision was never recorded — is PRIVATE, never publication-safe by
// omission.
const SELECT_BODIES_FROM_START_SQL: &str = "SELECT body.content_sha256, body.body_bytes, \
            body.media_type, body.created_at, \
            COALESCE(visibility.visibility_class, 'private') AS visibility_class \
     FROM public.memory_body_objects_v1 AS body \
     LEFT JOIN public.memory_body_visibility_v1 AS visibility \
       ON visibility.tenant_id = body.tenant_id \
      AND visibility.project = body.project \
      AND visibility.body_content_id = body.content_sha256 \
     WHERE body.tenant_id = $1 AND body.project = $2 \
     ORDER BY body.created_at, body.content_sha256 LIMIT $3";

const SELECT_BODIES_AFTER_SQL: &str = "SELECT body.content_sha256, body.body_bytes, \
            body.media_type, body.created_at, \
            COALESCE(visibility.visibility_class, 'private') AS visibility_class \
     FROM public.memory_body_objects_v1 AS body \
     LEFT JOIN public.memory_body_visibility_v1 AS visibility \
       ON visibility.tenant_id = body.tenant_id \
      AND visibility.project = body.project \
      AND visibility.body_content_id = body.content_sha256 \
     WHERE body.tenant_id = $1 AND body.project = $2 \
       AND (body.created_at, body.content_sha256) > ($3, $4) \
     ORDER BY body.created_at, body.content_sha256 LIMIT $5";

// The conflict arm is a DOWNGRADE-ONLY reconciliation: a body whose recorded
// decision has since collapsed to private demotes its already-written lexical
// row, and no arm here ever writes 'publication_safe' over a stored row.
const INSERT_LEXICAL_SQL: &str = "INSERT INTO public.memory_body_lexical_projection_v1 (\
     tenant_id, project, body_content_id, body_created_at, lexical_state, \
     unindexable_reason, normalization_version, lexical_text, lexical_text_digest, \
     visibility_class\
     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
     ON CONFLICT (tenant_id, project, body_content_id) DO UPDATE SET \
     visibility_class = 'private' \
     WHERE public.memory_body_lexical_projection_v1.visibility_class \
         IS DISTINCT FROM excluded.visibility_class";

const SELECT_LEXICAL_DIGEST_SQL: &str = "SELECT lexical_text_digest \
     FROM public.memory_body_lexical_projection_v1 \
     WHERE tenant_id = $1 AND project = $2 AND body_content_id = $3";

// The dense tier takes its visibility from the lexical row rather than
// re-deriving it, so the two tiers cannot disagree about one body.
const SELECT_LEXICAL_FROM_START_SQL: &str = "SELECT body_content_id, body_created_at, \
     lexical_state, unindexable_reason, lexical_text, visibility_class \
     FROM public.memory_body_lexical_projection_v1 \
     WHERE tenant_id = $1 AND project = $2 \
     ORDER BY body_created_at, body_content_id LIMIT $3";

const SELECT_LEXICAL_AFTER_SQL: &str = "SELECT body_content_id, body_created_at, \
     lexical_state, unindexable_reason, lexical_text, visibility_class \
     FROM public.memory_body_lexical_projection_v1 \
     WHERE tenant_id = $1 AND project = $2 \
       AND (body_created_at, body_content_id) > ($3, $4) \
     ORDER BY body_created_at, body_content_id LIMIT $5";

const INSERT_DENSE_SQL: &str = "INSERT INTO public.memory_body_dense_projection_v1 (\
     tenant_id, project, body_content_id, body_created_at, embedding_identity_id, \
     model_digest, tokenization_version, preprocessing_version, distance_metric, \
     dimensions, embedding, visibility_class\
     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::VECTOR(512), $12) \
     ON CONFLICT (tenant_id, project, body_content_id) DO UPDATE SET \
     visibility_class = 'private' \
     WHERE public.memory_body_dense_projection_v1.visibility_class \
         IS DISTINCT FROM excluded.visibility_class";

// Downgrade-only reconciliation, run at the end of every pass. A body whose
// recorded decision collapsed to private AFTER its projection row was written
// leaves the publication plane here; neither statement can move a row the other
// way, because 'private' is the only value either one assigns.
const DEMOTE_LEXICAL_SQL: &str = "UPDATE public.memory_body_lexical_projection_v1 AS lexical \
     SET visibility_class = 'private' \
     WHERE lexical.tenant_id = $1 AND lexical.project = $2 \
       AND lexical.visibility_class = 'publication_safe' \
       AND NOT EXISTS (SELECT 1 FROM public.memory_body_visibility_v1 AS visibility \
             WHERE visibility.tenant_id = lexical.tenant_id \
               AND visibility.project = lexical.project \
               AND visibility.body_content_id = lexical.body_content_id \
               AND visibility.visibility_class = 'publication_safe')";

const DEMOTE_DENSE_SQL: &str = "UPDATE public.memory_body_dense_projection_v1 AS dense \
     SET visibility_class = 'private' \
     WHERE dense.tenant_id = $1 AND dense.project = $2 \
       AND dense.visibility_class = 'publication_safe' \
       AND NOT EXISTS (SELECT 1 FROM public.memory_body_lexical_projection_v1 AS lexical \
             WHERE lexical.tenant_id = dense.tenant_id \
               AND lexical.project = dense.project \
               AND lexical.body_content_id = dense.body_content_id \
               AND lexical.visibility_class = 'publication_safe')";

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

// The publication plane's lexical lane. It reads the VIEW, whose own WHERE
// clause is the visibility predicate, so the restriction is applied before
// ts_rank orders anything: a private row never occupies a rank slot, never
// shifts an offset, and never contributes to a count. The public database role
// holds SELECT on this view and on nothing else, so the same restriction also
// holds for any direct SQL that role can write (PUBLIC-03, PUBLIC-04).
const LEXICAL_RECALL_PUBLICATION_SQL: &str = "SELECT body_content_id, \
     ts_rank(search_document, plainto_tsquery('english', $3))::FLOAT4 AS score \
     FROM public.memory_body_lexical_publication_v1 \
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

// The publication plane's dense lane. Inlining the view adds
// `visibility_class = 'publication_safe'`, which is why migration 0023 builds
// memory_body_dense_projection_publication_idx with visibility_class in the
// equality prefix: the restriction is part of the index prefix rather than a
// post-filter that could truncate an ANN top-k.
const DENSE_RECALL_PUBLICATION_SQL: &str = "SELECT body_content_id, \
     (embedding <=> $3::VECTOR(512))::FLOAT4 AS distance \
     FROM public.memory_body_dense_publication_v1 \
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

// Publication-plane readiness counts only publication-safe rows, and counts
// them through the views. `bodies_total` is the publication-safe lexical
// population rather than the body-plane total: the publication plane must not
// be able to learn how many private bodies exist by subtracting one readiness
// number from another. It also has no privilege on memory_body_objects_v1, so
// the private total is not merely hidden here, it is unreachable.
const COMPLETENESS_PUBLICATION_SQL: &str = "SELECT \
     (SELECT count(*) FROM public.memory_body_lexical_publication_v1 \
        WHERE tenant_id = $1 AND project = $2) AS bodies_total, \
     (SELECT count(*) FROM public.memory_body_lexical_publication_v1 \
        WHERE tenant_id = $1 AND project = $2 AND lexical_state = 'indexed') AS lexically_indexed, \
     (SELECT count(*) FROM public.memory_body_lexical_publication_v1 \
        WHERE tenant_id = $1 AND project = $2 AND lexical_state = 'unindexable') \
        AS lexically_unindexable, \
     (SELECT count(*) FROM public.memory_body_dense_publication_v1 \
        WHERE tenant_id = $1 AND project = $2) AS densely_embedded";

/// One body row the lexical projector consumes.
#[derive(Debug, Clone)]
struct BodyRowV1 {
    position: BodyPositionV1,
    body_bytes: Vec<u8>,
    /// The body row's own stored media type, which selects the lexical
    /// rendering. Read from the body table, never from a request.
    media_type: String,
    visibility: RowVisibilityClassV1,
}

/// One lexical row the dense worker consumes.
#[derive(Debug, Clone)]
struct LexicalRowV1 {
    position: BodyPositionV1,
    state: LexicalStateV1,
    text: String,
    visibility: RowVisibilityClassV1,
}

/// One embedded body waiting to be written, carrying the read plane it
/// inherited from its lexical row.
#[derive(Debug, Clone)]
struct EmbeddedRowV1 {
    position: BodyPositionV1,
    visibility: RowVisibilityClassV1,
    admitted: DerivedEmbeddingV1,
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
                    media_type: row.try_get("media_type")?,
                    visibility: RowVisibilityClassV1::parse(
                        row.try_get::<String, _>("visibility_class")?.as_str(),
                    )?,
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
            let derived = derive_lexical_projection(
                body.position.content_id,
                &body.body_bytes,
                &body.media_type,
            )?;
            self.write_lexical(transaction, body.position, body.visibility, &derived)
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
        visibility: RowVisibilityClassV1,
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
            .bind(visibility.as_str())
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
        self.reconcile_visibility().await?;
        Ok(summary)
    }

    /// Demote every lexical row whose body is no longer recorded as
    /// publication-safe, and report how many rows left the publication plane.
    ///
    /// Bodies are content-addressed and therefore shared, so a body admitted
    /// under an approved event and later re-admitted under a private one has
    /// its recorded decision collapsed to private by the body projector. This
    /// statement propagates that collapse to a lexical row that was already
    /// written. It only ever assigns `'private'`, so running it more often than
    /// necessary is safe and running it can never widen the publication plane.
    pub async fn reconcile_visibility(&self) -> RecallProjectionResult<u64> {
        let demoted = sqlx::query(DEMOTE_LEXICAL_SQL)
            .bind(self.scope.tenant_id)
            .bind(&self.scope.project)
            .execute(&self.scope.pool)
            .await?
            .rows_affected();
        Ok(demoted)
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
                    visibility: RowVisibilityClassV1::parse(
                        row.try_get::<String, _>("visibility_class")?.as_str(),
                    )?,
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
    ) -> RecallProjectionResult<(Vec<EmbeddedRowV1>, u64)> {
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
            embedded.push(EmbeddedRowV1 {
                position: row.position,
                // Copied from the lexical row, never re-derived: the two tiers
                // cannot disagree about one body's read plane.
                visibility: row.visibility,
                admitted,
            });
        }
        Ok((embedded, unindexable))
    }

    /// Write one batch's dense rows AND advance the dense cursor in one
    /// transaction.
    async fn apply_batch(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        embedded: &[EmbeddedRowV1],
        last: BodyPositionV1,
        consumed: u64,
    ) -> RecallProjectionResult<()> {
        let now: DateTime<Utc> = sqlx::query_scalar("SELECT pg_catalog.statement_timestamp()")
            .fetch_one(&mut **transaction)
            .await?;
        let descriptor = self.provider.descriptor();
        for row in embedded {
            let admitted = &row.admitted;
            let encoded = serialize_vector(&admitted.vector)?;
            sqlx::query(INSERT_DENSE_SQL)
                .bind(self.scope.tenant_id)
                .bind(&self.scope.project)
                .bind(bytes(admitted.body_content_id))
                .bind(row.position.created_at)
                .bind(bytes(admitted.identity.digest()))
                .bind(bytes(descriptor.model_digest))
                .bind(i64::from(descriptor.tokenization_version))
                .bind(i64::from(descriptor.preprocessing_version))
                .bind(distance_metric_label(descriptor.distance_metric))
                .bind(i64::from(descriptor.dimensions))
                .bind(encoded)
                .bind(row.visibility.as_str())
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
        self.reconcile_visibility().await?;
        Ok(summary)
    }

    /// Demote every dense row whose lexical row is no longer publication-safe,
    /// and report how many rows left the publication plane.
    ///
    /// The dense tier follows the lexical tier rather than the body table, for
    /// the same reason [`Self::embed_batch`] copies the class instead of
    /// re-deriving it: one source of truth per body. Like its lexical
    /// counterpart it only ever assigns `'private'`.
    pub async fn reconcile_visibility(&self) -> RecallProjectionResult<u64> {
        let demoted = sqlx::query(DEMOTE_DENSE_SQL)
            .bind(self.scope.tenant_id)
            .bind(&self.scope.project)
            .execute(&self.scope.pool)
            .await?
            .rows_affected();
        Ok(demoted)
    }

    /// One batch, one bounded serializable-transaction retry loop.
    async fn commit_batch(
        &self,
        embedded: &[EmbeddedRowV1],
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

/// Recall over the projection, bound once to physical scope AND one read plane.
///
/// The plane is chosen at construction and is not a request parameter: a
/// publication reader has no method that reaches a private row, and a caller
/// holding one cannot widen it (W2-VIS).
#[derive(Clone)]
pub struct CockroachRecallReader {
    scope: ScopeBinding,
    plane: RecallPlaneV1,
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
    /// Bind one pool and one physical scope on the PRIVATE plane, which sees
    /// both visibility classes.
    #[must_use]
    pub const fn new(pool: PgPool, tenant_id: Uuid, project: String) -> Self {
        Self {
            scope: ScopeBinding {
                pool,
                tenant_id,
                project,
            },
            plane: RecallPlaneV1::Private,
        }
    }

    /// Bind one pool and one physical scope on the PUBLICATION plane.
    ///
    /// Every statement this reader issues names a publication view, never a
    /// base table, so the reader is safe to hand a pool authenticated as the
    /// public database role — which holds SELECT on exactly those views. The
    /// restriction does not depend on that role, though: the same reader over
    /// an admin pool still cannot return a private row, because the views
    /// themselves cannot name one.
    #[must_use]
    pub const fn publication(pool: PgPool, tenant_id: Uuid, project: String) -> Self {
        Self {
            scope: ScopeBinding {
                pool,
                tenant_id,
                project,
            },
            plane: RecallPlaneV1::Publication,
        }
    }

    /// Which read plane this reader answers for.
    #[must_use]
    pub const fn plane(&self) -> RecallPlaneV1 {
        self.plane
    }

    /// Read how complete each tier is for this scope.
    ///
    /// On the publication plane every count is taken through the publication
    /// views, so the readiness numbers carry no information about how many
    /// private rows exist.
    pub async fn completeness(&self) -> RecallProjectionResult<RecallCompletenessV1> {
        let statement = match self.plane {
            RecallPlaneV1::Private => COMPLETENESS_SQL,
            RecallPlaneV1::Publication => COMPLETENESS_PUBLICATION_SQL,
        };
        let row: PgRow = sqlx::query(statement)
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
        let statement = match self.plane {
            RecallPlaneV1::Private => LEXICAL_RECALL_SQL,
            RecallPlaneV1::Publication => LEXICAL_RECALL_PUBLICATION_SQL,
        };
        let rows: Vec<PgRow> = sqlx::query(statement)
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
        let statement = match self.plane {
            RecallPlaneV1::Private => DENSE_RECALL_SQL,
            RecallPlaneV1::Publication => DENSE_RECALL_PUBLICATION_SQL,
        };
        let rows: Vec<PgRow> = sqlx::query(statement)
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
        // The snapshot reads base tables, which is a private-plane capability
        // by construction. Refuse it on the publication plane rather than
        // issuing a statement the public role has no privilege for.
        if !self.plane.admits_private_rows() {
            return Err(RecallProjectionError::InvalidRequest(
                "the publication plane cannot snapshot the private projection tables".into(),
            ));
        }
        let mut snapshot = RecallProjectionSnapshotV1::default();

        let lexical_rows: Vec<PgRow> = sqlx::query(
            "SELECT body_content_id, lexical_state, unindexable_reason, normalization_version, \
                    lexical_text, lexical_text_digest, visibility_class \
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
                row.try_get("visibility_class")?,
            ));
        }

        let dense_rows: Vec<PgRow> = sqlx::query(
            "SELECT body_content_id, embedding_identity_id, model_digest, distance_metric, \
                    dimensions, embedding::STRING AS embedding_text, visibility_class \
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
                row.try_get("visibility_class")?,
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
            SELECT_LEXICAL_DIGEST_SQL,
            SELECT_LEXICAL_FROM_START_SQL,
            SELECT_LEXICAL_AFTER_SQL,
            SELECT_DENSE_IDENTITY_SQL,
            LEXICAL_RECALL_SQL,
            LEXICAL_RECALL_PUBLICATION_SQL,
            DENSE_RECALL_SQL,
            DENSE_RECALL_PUBLICATION_SQL,
            COMPLETENESS_SQL,
            COMPLETENESS_PUBLICATION_SQL,
        ] {
            assert!(
                statement.contains("tenant_id = $1") && statement.contains("project = $2"),
                "statement must bind scope first: {statement}"
            );
        }
        // The body scan and the two demotions qualify their scope columns with
        // a table alias, because they join a second relation; the binding is
        // the same equality pair.
        for statement in [
            SELECT_BODIES_FROM_START_SQL,
            SELECT_BODIES_AFTER_SQL,
            DEMOTE_LEXICAL_SQL,
            DEMOTE_DENSE_SQL,
        ] {
            assert!(
                statement.contains(".tenant_id = $1") && statement.contains(".project = $2"),
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
        for statement in [DENSE_RECALL_SQL, DENSE_RECALL_PUBLICATION_SQL] {
            assert!(statement.contains("WHERE tenant_id = $1 AND project = $2 "));
            assert!(statement.contains("ORDER BY embedding <=> $3::VECTOR(512)"));
            assert!(!statement.contains(" AND ("));
        }
        // The publication lane binds its third equality column by reading the
        // view; migration 0023 gives that shape its own index prefix
        // (tenant_id, project, visibility_class, embedding).
        assert!(DENSE_RECALL_PUBLICATION_SQL.contains("memory_body_dense_publication_v1"));
    }

    #[test]
    fn the_visibility_predicate_lives_inside_the_sql_not_in_rust() {
        // The whole point of W2-VIS: the restriction is a SQL relation, applied
        // before ts_rank/ANN ordering and before LIMIT, so a private row never
        // occupies a rank slot, shifts an offset, or contributes to a count.
        // Nothing in this module filters hits after the query returns.
        for statement in [
            LEXICAL_RECALL_PUBLICATION_SQL,
            DENSE_RECALL_PUBLICATION_SQL,
            COMPLETENESS_PUBLICATION_SQL,
        ] {
            // Every publication statement reads publication views only. A base
            // table here would be both a leak and an unprivileged statement for
            // the public database role.
            for private in crate::projectors::PRIVATE_PLANE_RECALL_TABLES {
                assert!(
                    !statement.contains(private),
                    "publication statement must not name {private}: {statement}"
                );
            }
        }
        assert!(LEXICAL_RECALL_PUBLICATION_SQL.contains("memory_body_lexical_publication_v1"));
        assert!(COMPLETENESS_PUBLICATION_SQL.contains("memory_body_lexical_publication_v1"));
        assert!(COMPLETENESS_PUBLICATION_SQL.contains("memory_body_dense_publication_v1"));
        // The private plane keeps reading the base tables and therefore still
        // sees both classes: it carries no visibility predicate at all.
        for statement in [LEXICAL_RECALL_SQL, DENSE_RECALL_SQL, COMPLETENESS_SQL] {
            assert!(
                !statement.contains("publication_safe"),
                "the private plane must not filter by class: {statement}"
            );
        }
    }

    #[test]
    fn publication_readiness_counts_cannot_reveal_the_private_population() {
        // A count/offset probe is the cheapest existence oracle. Every
        // publication readiness count is taken through a publication view, and
        // bodies_total is the publication-safe population -- not the body-plane
        // total, whose difference would be the private count.
        assert!(!COMPLETENESS_PUBLICATION_SQL.contains("memory_body_objects_v1"));
        assert_eq!(
            COMPLETENESS_PUBLICATION_SQL
                .matches("memory_body_lexical_publication_v1")
                .count(),
            3
        );
        assert_eq!(
            COMPLETENESS_PUBLICATION_SQL
                .matches("memory_body_dense_publication_v1")
                .count(),
            1
        );
    }

    #[test]
    fn every_visibility_write_can_only_demote() {
        // The projection's class is never widened by any statement here: the
        // two conflict arms and the two reconciliation statements assign the
        // literal 'private' and nothing else.
        for statement in [
            INSERT_LEXICAL_SQL,
            INSERT_DENSE_SQL,
            DEMOTE_LEXICAL_SQL,
            DEMOTE_DENSE_SQL,
        ] {
            assert!(
                statement.contains("visibility_class = 'private'"),
                "{statement}"
            );
            // The only assignment either statement makes is to 'private': the
            // SET clause is `visibility_class = 'private'` and no SET clause
            // anywhere mentions the publication class.
            assert!(
                !statement.contains("SET visibility_class = 'publication_safe'"),
                "no statement may assign publication_safe: {statement}"
            );
        }
        // The two INSERTs carry the derived class as a bound parameter, so
        // 'private' is the only class literal either can ever WRITE.
        for statement in [INSERT_LEXICAL_SQL, INSERT_DENSE_SQL] {
            assert!(statement.contains("visibility_class"), "{statement}");
            assert_eq!(statement.matches("'publication_safe'").count(), 0);
        }
    }

    #[test]
    fn the_body_scan_defaults_an_unrecorded_body_to_private() {
        // Fail closed on a missing decision: a body with no
        // memory_body_visibility_v1 row (projected before migration 0023, or
        // never classified) is private, not publication-safe by omission.
        for statement in [SELECT_BODIES_FROM_START_SQL, SELECT_BODIES_AFTER_SQL] {
            assert!(statement.contains("LEFT JOIN public.memory_body_visibility_v1"));
            assert!(
                statement.contains("COALESCE(visibility.visibility_class, 'private')"),
                "{statement}"
            );
        }
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
        // The public plane reaches body recall through the two views of
        // migration 0023 instead, which are not tables and hold no private row.
        for view in crate::projectors::PUBLICATION_PLANE_VIEWS {
            assert!(!crate::store::cockroach::PUBLICATION_READ_TABLES.contains(&view));
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
