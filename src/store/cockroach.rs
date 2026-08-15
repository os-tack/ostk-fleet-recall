//! `CockroachDB` connection, corpus retrieval, and retry support.
//!
//! The SQL is deliberately runtime-checked. `sqlx`'s compile-time macros
//! require a live database (or checked-in offline metadata), neither of which
//! should be required to build this crate.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::time::Duration;

use crate::{FleetError, FleetScope, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use futures::future::BoxFuture;
use ostk_recall_core::{
    Chunk, CorpusFilter, CorpusLaneHit, CorpusReadError, CorpusReader, FacetSet, HydratedChunk,
    Links, Source, is_archive_parent,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::migrate::{Migration, MigrationType, Migrator};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgRow};
use sqlx::{ConnectOptions, PgPool, Postgres, Row, Transaction};

/// Embedding width used by Recall's `minishlab/potion-retrieval-32M` model.
pub const EMBEDDING_DIMENSION: usize = 512;
/// Largest integer every supported JavaScript/JSON client can represent
/// without precision loss.
pub const MAX_PUBLIC_NUMERIC_ID: i64 = 9_007_199_254_740_991;
/// Oldest additive database schema supported by the existing recall, remember,
/// ingestion, and public-demo paths.
pub const MINIMUM_RECALL_SCHEMA_VERSION: i64 = 2;

const INITIAL_MIGRATION_SQL: &str = include_str!("../../migrations/0001_fleet_memory.sql");
const CLAIM_SUPPORT_CHUNK_MIGRATION_SQL: &str =
    include_str!("../../migrations/0002_claim_support_chunk_lookup.sql");
const CONTROL_EVENT_LEDGER_MIGRATION_SQL: &str =
    include_str!("../../migrations/0003_control_event_ledger.sql");
const GENESIS_REGISTRY_ACTIVATION_MIGRATION_SQL: &str =
    include_str!("../../migrations/0004_genesis_registry_activation.sql");

fn embedded_migrator() -> Migrator {
    Migrator {
        migrations: Cow::Owned(vec![
            Migration::new(
                1,
                Cow::Borrowed("fleet memory substrate"),
                MigrationType::Simple,
                Cow::Borrowed(INITIAL_MIGRATION_SQL),
                // CockroachDB 26.2 cannot build vector indexes through its
                // legacy transactional schema changer (SQLSTATE 0A000).
                // Execute this DDL migration outside one SQL transaction.
                true,
            ),
            Migration::new(
                2,
                Cow::Borrowed("claim support chunk lookup"),
                MigrationType::Simple,
                Cow::Borrowed(CLAIM_SUPPORT_CHUNK_MIGRATION_SQL),
                // Keep every CockroachDB schema change outside SQLx's
                // PostgreSQL-oriented transaction wrapper.
                true,
            ),
            Migration::new(
                3,
                Cow::Borrowed("append-only control event ledger"),
                MigrationType::Simple,
                Cow::Borrowed(CONTROL_EVENT_LEDGER_MIGRATION_SQL),
                // Keep every CockroachDB schema change outside SQLx's
                // PostgreSQL-oriented transaction wrapper.
                true,
            ),
            Migration::new(
                4,
                Cow::Borrowed("genesis registry activation"),
                MigrationType::Simple,
                Cow::Borrowed(GENESIS_REGISTRY_ACTIVATION_MIGRATION_SQL),
                // Keep every CockroachDB schema change outside SQLx's
                // PostgreSQL-oriented transaction wrapper.
                true,
            ),
        ]),
        ignore_missing: false,
        // SQLx's PostgreSQL lock uses `pg_advisory_lock`, which CockroachDB
        // intentionally does not implement. CockroachDB's schema changer
        // serializes the DDL; deployment tooling must ensure only one migrator
        // starts at a time.
        locking: false,
        no_tx: true,
    }
}

/// Maximum ANN candidates examined before applying a time-range filter.
///
/// `CockroachDB` 26.2 accelerates a vector query only when every non-vector
/// predicate is an equality constraint on a vector-index prefix column. We
/// A source equality uses its own prefixed vector index. Time ranges cannot be
/// vector-index prefixes, so we select a bounded nearest-neighbour set first
/// and apply time predicates to only those IDs in a second,
/// primary-key-bounded query.
pub const FILTERED_VECTOR_CANDIDATE_CAP: usize = 1_000;
const FILTERED_VECTOR_OVERSAMPLE_FACTOR: usize = 8;
/// Search hydration needs one look-ahead character so Recall's canonical
/// 400-character snippet projection can distinguish a truncated row.
const RETRIEVAL_TEXT_CHARS: usize = 401;
/// Preserve ordinary hit metadata while preventing one candidate from moving
/// an ingestion-line-sized JSON document across the SQL boundary.
const RETRIEVAL_JSON_BYTES: usize = 8 * 1024;
const MAX_RETRIEVAL_METADATA_ROWS: usize = 100;

/// Minimum native cosine similarity accepted by the fleet chunk-recall dense
/// lane for the pinned `minishlab/potion-retrieval-32M` generation.
///
/// A deterministic sweep over the checked-in 548-row demo corpus placed the
/// best clearly off-domain probes at 0.142 similarity, while broad in-domain
/// questions started at 0.205 and the project-purpose query reached 0.290.
/// The deliberately conservative 0.18 boundary removes nearest-neighbour
/// padding without requiring lexical hits to clear a dense threshold.
pub(crate) const RETRIEVAL_DENSE_MIN_COSINE_SIMILARITY: f32 = 0.18;

const INSERT_ACTIVE_MODEL_SQL: &str = r"
INSERT INTO memory_corpus_models (tenant_id, project, embedding_model)
VALUES ($1, $2, $3)
ON CONFLICT (tenant_id, project) DO NOTHING
";

const READ_ACTIVE_MODEL_SQL: &str = r"
SELECT embedding_model
FROM memory_corpus_models
WHERE tenant_id = $1 AND project = $2
";

const ROTATE_ACTIVE_MODEL_SQL: &str = r"
UPDATE memory_corpus_models
SET embedding_model = $4, updated_at = now()
WHERE tenant_id = $1
  AND project = $2
  AND embedding_model = $3
  AND NOT EXISTS (
      SELECT 1
      FROM memory_chunks
      WHERE tenant_id = $1 AND project = $2
  )
  AND NOT EXISTS (
      SELECT 1
      FROM memory_claim_embeddings
      WHERE tenant_id = $1 AND project = $2
  )
RETURNING embedding_model
";

const UPSERT_ACTIVE_CHUNK_SQL: &str = r"
INSERT INTO memory_chunks (
    tenant_id, project, chunk_id, source, source_id, source_config_id,
    chunk_index, source_timestamp, role, text, content_sha256,
    embedding_input_sha256, embedding_model, embedding, facets, links, extra
)
VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
    $14::VECTOR(512), $15, $16, $17
)
ON CONFLICT (tenant_id, project, chunk_id) DO UPDATE SET
    source = excluded.source,
    source_id = excluded.source_id,
    source_config_id = excluded.source_config_id,
    chunk_index = excluded.chunk_index,
    source_timestamp = excluded.source_timestamp,
    role = excluded.role,
    text = excluded.text,
    content_sha256 = excluded.content_sha256,
    embedding_input_sha256 = excluded.embedding_input_sha256,
    embedding_model = excluded.embedding_model,
    embedding = excluded.embedding,
    facets = excluded.facets,
    links = excluded.links,
    extra = excluded.extra,
    updated_at = now()
";

const UPSERT_HISTORY_CHUNK_SQL: &str = r"
INSERT INTO memory_chunk_history (
    tenant_id, project, chunk_id, source, source_id, source_config_id,
    chunk_index, source_timestamp, role, text, content_sha256,
    embedding_input_sha256, embedding_model, embedding, facets, links, extra,
    history_reason
)
VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
    $14::VECTOR(512), $15, $16, $17, $18
)
ON CONFLICT (tenant_id, project, chunk_id) DO UPDATE SET
    source = excluded.source,
    source_id = excluded.source_id,
    source_config_id = excluded.source_config_id,
    chunk_index = excluded.chunk_index,
    source_timestamp = excluded.source_timestamp,
    role = excluded.role,
    text = excluded.text,
    content_sha256 = excluded.content_sha256,
    embedding_input_sha256 = excluded.embedding_input_sha256,
    embedding_model = excluded.embedding_model,
    embedding = excluded.embedding,
    facets = excluded.facets,
    links = excluded.links,
    extra = excluded.extra,
    history_reason = excluded.history_reason,
    updated_at = now()
";

const VECTOR_SEARCH_SQL: &str = r"
SELECT chunk_id, (embedding <=> $3::VECTOR(512))::FLOAT4 AS score
FROM memory_chunks
WHERE tenant_id = $1
  AND project = $2
ORDER BY embedding <=> $3::VECTOR(512)
LIMIT $4
";

const SOURCE_VECTOR_SEARCH_SQL: &str = r"
SELECT chunk_id, (embedding <=> $4::VECTOR(512))::FLOAT4 AS score
FROM memory_chunks
WHERE tenant_id = $1
  AND project = $2
  AND source = $3
ORDER BY embedding <=> $4::VECTOR(512)
LIMIT $5
";

const FILTER_VECTOR_CANDIDATES_SQL: &str = r"
SELECT chunk_id
FROM memory_chunks@{NO_FULL_SCAN}
WHERE tenant_id = $1
  AND project = $2
  AND chunk_id = ANY($3)
  AND ($4::STRING IS NULL OR source = $4)
  AND ($5::TIMESTAMPTZ IS NULL OR source_timestamp >= $5)
  AND ($6::TIMESTAMPTZ IS NULL OR source_timestamp < $6)
";

const LEXICAL_SEARCH_SQL: &str = r"
SELECT chunk_id,
       ts_rank(search_document, plainto_tsquery('english', $3))::FLOAT4 AS score
FROM memory_chunks
WHERE tenant_id = $1
  AND project = $2
  AND search_document @@ plainto_tsquery('english', $3)
  AND ($4::STRING IS NULL OR source = $4)
  AND ($5::TIMESTAMPTZ IS NULL OR source_timestamp >= $5)
  AND ($6::TIMESTAMPTZ IS NULL OR source_timestamp < $6)
ORDER BY score DESC, chunk_id
LIMIT $7
";

const FETCH_CHUNKS_SQL_PREFIX: &str = r"
SELECT chunk_id, source, source_id, source_config_id, chunk_index,
       source_timestamp, role, text, content_sha256,
       embedding_input_sha256, facets, links, extra, project,
       embedding::STRING AS embedding_text
FROM memory_chunks@{NO_FULL_SCAN}
WHERE tenant_id = $1
  AND project = $2
  AND chunk_id = ANY($3)
  AND ($4::STRING IS NULL OR source = $4)
  AND ($5::TIMESTAMPTZ IS NULL OR source_timestamp >= $5)
  AND ($6::TIMESTAMPTZ IS NULL OR source_timestamp < $6)
";

// Hybrid ranking consumes lane scores plus a short text prefix. It does not
// consume stored vectors, facets, identity hashes, links, or extra metadata.
// Metadata for only the final result page is hydrated by the second query
// below. Full get uses FETCH_CHUNKS_SQL_PREFIX.
const FETCH_RETRIEVAL_CHUNKS_SQL: &str = r"
SELECT chunk_id, source, source_id, source_timestamp, role,
       left(text, $7) AS text, project
FROM memory_chunks@{NO_FULL_SCAN}
WHERE tenant_id = $1
  AND project = $2
  AND chunk_id = ANY($3)
  AND ($4::STRING IS NULL OR source = $4)
  AND ($5::TIMESTAMPTZ IS NULL OR source_timestamp >= $5)
  AND ($6::TIMESTAMPTZ IS NULL OR source_timestamp < $6)
";

const FETCH_RETRIEVAL_METADATA_SQL: &str = r"
SELECT chunk_id,
       CASE WHEN octet_length(links::STRING) <= $4
            THEN links ELSE '{}'::JSONB END AS links,
       CASE WHEN octet_length(extra::STRING) <= $4
            THEN extra ELSE '{}'::JSONB END AS extra,
       octet_length(links::STRING) > $4 AS links_elided,
       octet_length(extra::STRING) > $4 AS extra_elided
FROM memory_chunks@{NO_FULL_SCAN}
WHERE tenant_id = $1
  AND project = $2
  AND chunk_id = ANY($3)
";

/// Connection-pool settings with conservative defaults for a horizontally
/// scaled fleet. Every process gets its own pool, so the default is small.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolConfig {
    pub max_connections: u32,
    pub min_connections: u32,
    pub acquire_timeout: Duration,
    pub idle_timeout: Duration,
    pub max_lifetime: Duration,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_connections: 16,
            min_connections: 0,
            acquire_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_mins(10),
            max_lifetime: Duration::from_mins(30),
        }
    }
}

/// Outcome of the database capability probe used by startup and health APIs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // independent readiness facts are serialized for operators
pub struct DatabaseCapabilities {
    pub version: String,
    pub vector_index_enabled: bool,
    pub lexical_index_enabled: bool,
    pub conflict_membership_index_enabled: bool,
    pub claim_support_chunk_index_enabled: bool,
    pub cosine_distance_supported: bool,
    pub schema_version: i64,
}

impl DatabaseCapabilities {
    /// Whether this database has reached a command's minimum additive schema.
    ///
    /// Callers that depend on newer tables must supply their own higher floor;
    /// a later migration must not make the established schema-2 paths unhealthy.
    #[must_use]
    pub const fn supports_schema_version(&self, minimum: i64) -> bool {
        self.schema_version >= minimum
    }
}

/// The model coordinate registered for this trusted corpus, if ingestion has
/// initialized it. A configured service must not query with a different model.
pub async fn active_embedding_model(pool: &PgPool, scope: &FleetScope) -> Result<Option<String>> {
    scope.validate()?;
    Ok(sqlx::query_scalar::<_, String>(READ_ACTIVE_MODEL_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .fetch_optional(pool)
        .await?)
}

/// Execution strategy used by a dense query.
///
/// Time-range predicates cannot be pushed into `CockroachDB`'s C-SPANN vector
/// index. Their results are therefore approximate: the predicates are applied
/// to a bounded ANN candidate window and matching rows outside that window are
/// intentionally not scanned. Source-only queries use an exact prefixed ANN
/// path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VectorSearchMode {
    /// Project-wide ANN search with no post-filtering.
    ProjectAnn,
    /// Source-specific ANN search using an equality-prefixed vector index.
    SourceAnn,
    /// ANN search followed by bounded time filtering by primary key.
    BoundedPostFilter {
        candidate_limit: usize,
        candidate_cap: usize,
    },
}

/// Dense hits together with a diagnostic describing exact versus bounded
/// post-filter execution.
#[derive(Debug, Clone, PartialEq)]
pub struct VectorSearchOutcome {
    pub hits: Vec<CorpusLaneHit>,
    pub mode: VectorSearchMode,
}

/// A row ready for scoped, idempotent corpus upsert.
#[derive(Debug, Clone)]
pub struct ScopedChunk {
    pub scope: FleetScope,
    pub chunk: Chunk,
    pub embedding_model: String,
    pub embedding: Vec<f32>,
    pub stale: bool,
}

impl ScopedChunk {
    pub fn validate(&self) -> Result<()> {
        self.scope.validate()?;
        if self.chunk.chunk_id.trim().is_empty() {
            return Err(FleetError::Memory("chunk_id must not be empty".into()));
        }
        if self.chunk.source_id.trim().is_empty() {
            return Err(FleetError::Memory("source_id must not be empty".into()));
        }
        if let Some(project) = self.chunk.project.as_deref()
            && !project.is_empty()
            && project != self.scope.project
        {
            return Err(FleetError::InvalidScope(
                "chunk project does not match its fleet scope".into(),
            ));
        }
        if self.embedding_model.trim().is_empty() {
            return Err(FleetError::Memory(
                "embedding_model must not be empty".into(),
            ));
        }
        validate_embedding(&self.embedding)
    }
}

/// Cockroach-backed corpus scoped to one trusted tenant/project boundary.
///
/// Agent and session scope are retained for adjacent ledger/attention stores;
/// corpus rows intentionally share at project scope.
#[derive(Debug, Clone)]
pub struct CockroachStore {
    pool: PgPool,
    scope: FleetScope,
}

/// Deliberately bounded view for the portable hybrid retrieval pipeline.
///
/// Keeping this as a separate reader leaves [`CockroachStore`]'s
/// [`CorpusReader::fetch_chunks`] implementation lossless for direct callers.
#[derive(Debug, Clone, Copy)]
pub(crate) struct CockroachRetrievalReader<'store> {
    store: &'store CockroachStore,
}

/// Bounded public-hit metadata, hydrated only after ranking/diversification.
#[derive(Debug)]
pub(crate) struct RetrievalHitMetadata {
    pub chunk_id: String,
    pub links: Links,
    pub extra: Value,
    pub links_elided: bool,
    pub extra_elided: bool,
}

impl CockroachStore {
    /// Connect without applying migrations. Deployment/startup code can choose
    /// when the schema-management identity is used.
    pub async fn connect(
        database_url: &str,
        scope: FleetScope,
        config: PoolConfig,
    ) -> Result<Self> {
        scope.validate()?;
        if config.max_connections == 0 {
            return Err(FleetError::Configuration(
                "database pool max_connections must be greater than zero".into(),
            ));
        }
        let options: PgConnectOptions = database_url.parse()?;
        let options = options
            .application_name("ostk-fleet-recall")
            .log_statements(tracing::log::LevelFilter::Debug)
            .log_slow_statements(tracing::log::LevelFilter::Warn, Duration::from_secs(1));
        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .min_connections(config.min_connections.min(config.max_connections))
            .acquire_timeout(config.acquire_timeout)
            .idle_timeout(config.idle_timeout)
            .max_lifetime(config.max_lifetime)
            .connect_with(options)
            .await?;
        Ok(Self { pool, scope })
    }

    /// Wrap an existing pool, primarily for composed services and integration
    /// tests. The trusted scope is always validated before it reaches SQL.
    pub fn from_pool(pool: PgPool, scope: FleetScope) -> Result<Self> {
        scope.validate()?;
        Ok(Self { pool, scope })
    }

    #[must_use]
    pub const fn pool(&self) -> &PgPool {
        &self.pool
    }

    #[must_use]
    pub const fn scope(&self) -> &FleetScope {
        &self.scope
    }

    /// Construct the bounded reader appropriate for hybrid search.
    #[must_use]
    pub(crate) const fn retrieval_reader(&self) -> CockroachRetrievalReader<'_> {
        CockroachRetrievalReader { store: self }
    }

    pub async fn migrate(&self) -> Result<()> {
        // Constructing the migration from `include_str!` keeps deployment
        // single-binary without enabling SQLx's unrelated query macros.
        embedded_migrator().run(&self.pool).await?;
        Ok(())
    }

    /// Initialize or verify the immutable embedding generation for this
    /// tenant/project. Deployment calls this once after migration; concurrent
    /// callers converge on the same value and conflicting identities fail.
    pub async fn initialize_embedding_model(&self, model: &str) -> Result<()> {
        let model = model.trim();
        if model.is_empty() {
            return Err(FleetError::Configuration(
                "embedding model identity must not be empty".into(),
            ));
        }
        sqlx::query(INSERT_ACTIVE_MODEL_SQL)
            .bind(self.scope.tenant_id)
            .bind(&self.scope.project)
            .bind(model)
            .execute(&self.pool)
            .await?;
        let active = active_embedding_model(&self.pool, &self.scope)
            .await?
            .ok_or_else(|| FleetError::Memory("embedding model registration failed".into()))?;
        if active != model {
            return Err(FleetError::Configuration(format!(
                "configured embedding model '{model}' does not match active corpus model '{active}'"
            )));
        }
        Ok(())
    }

    /// Validate connectivity and features on which the corpus implementation
    /// depends. This is intentionally read-only and safe for a runtime role.
    pub async fn capabilities(&self) -> Result<DatabaseCapabilities> {
        let mut connection = self.pool.acquire().await?;
        let version: String = sqlx::query_scalar("SELECT version()")
            .fetch_one(&mut *connection)
            .await?;
        // Inspect the application schema rather than `SHOW CLUSTER SETTING`:
        // the latter requires a cluster-level privilege that a least-privilege
        // runtime role should not have.
        let vector_index_enabled: bool = sqlx::query_scalar(
            "SELECT \
                 (SELECT count(DISTINCT index_name) = 2 \
                  FROM [SHOW INDEXES FROM memory_chunks] \
                  WHERE index_name IN (\
                      'memory_chunks_semantic_idx', \
                      'memory_chunks_source_semantic_idx'\
                  )) \
                 AND EXISTS(\
                     SELECT 1 FROM [SHOW INDEXES FROM memory_claim_embeddings] \
                     WHERE index_name = 'memory_claim_embeddings_semantic_idx'\
                 )",
        )
        .fetch_one(&mut *connection)
        .await?;
        let lexical_index_enabled: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM [SHOW INDEXES FROM memory_chunks] \
             WHERE index_name = 'memory_chunks_lexical_idx')",
        )
        .fetch_one(&mut *connection)
        .await?;
        let conflict_membership_index_enabled: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM [SHOW INDEXES FROM memory_conflict_members] \
             WHERE index_name = 'memory_conflict_members_claim_idx')",
        )
        .fetch_one(&mut *connection)
        .await?;
        let claim_support_chunk_index_enabled: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM [SHOW INDEXES FROM memory_claim_support] \
             WHERE index_name = 'memory_claim_support_chunk_idx')",
        )
        .fetch_one(&mut *connection)
        .await?;
        let cosine_distance_supported: bool =
            sqlx::query_scalar("SELECT ('[1,0]'::VECTOR(2) <=> '[1,0]'::VECTOR(2))::FLOAT8 = 0.0")
                .fetch_one(&mut *connection)
                .await?;
        let schema_version: Option<i64> =
            sqlx::query_scalar("SELECT MAX(version)::INT8 FROM _sqlx_migrations WHERE success")
                .fetch_optional(&mut *connection)
                .await?
                .flatten();

        Ok(DatabaseCapabilities {
            version,
            vector_index_enabled,
            lexical_index_enabled,
            conflict_membership_index_enabled,
            claim_support_chunk_index_enabled,
            cosine_distance_supported,
            schema_version: schema_version.unwrap_or(0),
        })
    }

    /// Lightweight liveness/readiness check that also verifies the scoped
    /// corpus table is present.
    pub async fn health_check(&self) -> Result<()> {
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM memory_chunks WHERE tenant_id = $1 AND project = $2 LIMIT 1)",
        )
        .bind(self.scope.tenant_id)
        .bind(&self.scope.project)
        .fetch_one(&self.pool)
        .await?;
        let capabilities = self.capabilities().await?;
        if !capabilities.supports_schema_version(MINIMUM_RECALL_SCHEMA_VERSION)
            || !capabilities.vector_index_enabled
            || !capabilities.lexical_index_enabled
            || !capabilities.conflict_membership_index_enabled
            || !capabilities.claim_support_chunk_index_enabled
            || !capabilities.cosine_distance_supported
        {
            return Err(FleetError::Configuration(
                "CockroachDB schema is incomplete; run the single-migrator deployment job".into(),
            ));
        }
        Ok(())
    }

    /// Idempotently insert or replace a chunk at its stable Recall ID.
    ///
    /// Searchable rows live exclusively in `memory_chunks`; stale projections
    /// and lossless archive parents are atomically moved to
    /// `memory_chunk_history`. This is a physical query-planning invariant,
    /// not a best-effort predicate on ANN reads.
    pub async fn upsert_chunk(&self, row: &ScopedChunk) -> Result<()> {
        row.validate()?;
        self.ensure_same_scope(&row.scope)?;

        let vector = serialize_vector(&row.embedding)?;
        let facets = serde_json::to_value(&row.chunk.facets)
            .map_err(|error| FleetError::Memory(format!("serialize facets: {error}")))?;
        let links = serde_json::to_value(&row.chunk.links)
            .map_err(|error| FleetError::Memory(format!("serialize links: {error}")))?;
        let chunk_index = i64::from(row.chunk.chunk_index);

        let history_reason = if row.stale {
            Some("stale")
        } else if is_archive_parent(&row.chunk) {
            Some("archive_parent")
        } else {
            None
        };
        let row = row.clone();
        with_serializable_retry(&self.pool, RetryPolicy::default(), move |transaction| {
            let row = row.clone();
            let vector = vector.clone();
            let facets = facets.clone();
            let links = links.clone();
            Box::pin(async move {
                write_chunk_transaction(
                    transaction,
                    &row,
                    &vector,
                    &facets,
                    &links,
                    chunk_index,
                    history_reason,
                )
                .await
            })
        })
        .await?;
        Ok(())
    }

    /// Dense cosine lane. For execution-strategy diagnostics, use
    /// [`Self::vector_search_diagnosed`].
    pub async fn vector_search(
        &self,
        embedding: &[f32],
        filter: &CorpusFilter,
        limit: usize,
    ) -> Result<Vec<CorpusLaneHit>> {
        if filter_has_time_bounds(filter) {
            return Err(FleetError::Memory(
                "time-filtered dense search is bounded and may be incomplete; call vector_search_diagnosed to opt in and inspect its execution mode"
                    .into(),
            ));
        }
        Ok(self
            .vector_search_diagnosed(embedding, filter, limit)
            .await?
            .hits)
    }

    /// Dense cosine lane with an explicit exact/bounded execution diagnostic.
    ///
    /// The unfiltered path contains only tenant/project equality predicates,
    /// vector ordering, and a limit so `CockroachDB` can select C-SPANN. Source
    /// predicates use a second source-prefixed ANN index. Time predicates use
    /// the applicable ANN statement with an oversampled, bounded candidate
    /// limit, then filter only those IDs via the primary key. The bounded mode
    /// can omit matching rows outside its candidate window; callers can expose
    /// that trade-off instead of implying an exact filtered nearest-neighbour
    /// result.
    pub async fn vector_search_diagnosed(
        &self,
        embedding: &[f32],
        filter: &CorpusFilter,
        limit: usize,
    ) -> Result<VectorSearchOutcome> {
        enforce_filter_scope(filter, &self.scope)?;
        validate_limit(limit)?;
        let vector = serialize_vector(embedding)?;
        let needs_post_filter = filter_has_time_bounds(filter);
        if needs_post_filter && limit > FILTERED_VECTOR_CANDIDATE_CAP {
            return Err(FleetError::Memory(format!(
                "filtered dense search limit must not exceed the bounded candidate cap of {FILTERED_VECTOR_CANDIDATE_CAP}"
            )));
        }
        let candidate_limit = if needs_post_filter {
            filtered_vector_candidate_limit(limit)
        } else {
            limit
        };
        let rows = if let Some(source) = filter.source.as_deref() {
            sqlx::query(SOURCE_VECTOR_SEARCH_SQL)
                .bind(self.scope.tenant_id)
                .bind(&self.scope.project)
                .bind(source)
                .bind(vector)
                .bind(limit_as_i64(candidate_limit)?)
                .fetch_all(&self.pool)
                .await?
        } else {
            sqlx::query(VECTOR_SEARCH_SQL)
                .bind(self.scope.tenant_id)
                .bind(&self.scope.project)
                .bind(vector)
                .bind(limit_as_i64(candidate_limit)?)
                .fetch_all(&self.pool)
                .await?
        };
        let mut hits = lane_hits(rows)?;

        let mode = if needs_post_filter {
            let candidate_ids = hits
                .iter()
                .map(|hit| hit.chunk_id.clone())
                .collect::<Vec<_>>();
            if candidate_ids.is_empty() {
                hits.clear();
            } else {
                let allowed_ids = sqlx::query_scalar::<_, String>(FILTER_VECTOR_CANDIDATES_SQL)
                    .bind(self.scope.tenant_id)
                    .bind(&self.scope.project)
                    .bind(&candidate_ids)
                    .bind(filter.source.as_deref())
                    .bind(filter.since)
                    .bind(filter.before)
                    .fetch_all(&self.pool)
                    .await?
                    .into_iter()
                    .collect::<HashSet<_>>();
                hits.retain(|hit| allowed_ids.contains(&hit.chunk_id));
                hits.truncate(limit);
                for (rank, hit) in hits.iter_mut().enumerate() {
                    hit.rank = u32::try_from(rank)
                        .map_err(|_| FleetError::Memory("result rank exceeded u32".into()))?;
                }
            }
            VectorSearchMode::BoundedPostFilter {
                candidate_limit,
                candidate_cap: FILTERED_VECTOR_CANDIDATE_CAP,
            }
        } else if filter.source.is_some() {
            VectorSearchMode::SourceAnn
        } else {
            VectorSearchMode::ProjectAnn
        };

        Ok(VectorSearchOutcome { hits, mode })
    }

    /// Change the project's active embedding generation after all searchable
    /// corpus and claim vectors have been fully evacuated. This guard prevents
    /// a rolling model change from mixing incomparable vectors in one ANN
    /// result set or making durable claims disappear from semantic recall.
    pub async fn rotate_active_embedding_model(
        &self,
        expected_current: &str,
        new_model: &str,
    ) -> Result<()> {
        let expected_current = expected_current.trim();
        let new_model = new_model.trim();
        if expected_current.is_empty() || new_model.is_empty() {
            return Err(FleetError::Memory(
                "embedding model identifiers must not be empty".into(),
            ));
        }
        if expected_current == new_model {
            return Ok(());
        }

        let rotated = sqlx::query_scalar::<_, String>(ROTATE_ACTIVE_MODEL_SQL)
            .bind(self.scope.tenant_id)
            .bind(&self.scope.project)
            .bind(expected_current)
            .bind(new_model)
            .fetch_optional(&self.pool)
            .await?;
        if rotated.is_none() {
            return Err(FleetError::Memory(
                "embedding model rotation requires the expected current model and no active corpus or claim vectors"
                    .into(),
            ));
        }
        Ok(())
    }

    /// Indexed PostgreSQL-style full-text lane, ranked by `ts_rank`.
    pub async fn lexical_search_scoped(
        &self,
        query: &str,
        filter: &CorpusFilter,
        limit: usize,
    ) -> Result<Vec<CorpusLaneHit>> {
        enforce_filter_scope(filter, &self.scope)?;
        validate_limit(limit)?;
        if query.trim().is_empty() {
            return Ok(Vec::new());
        }
        let rows = sqlx::query(LEXICAL_SEARCH_SQL)
            .bind(self.scope.tenant_id)
            .bind(&self.scope.project)
            .bind(query)
            .bind(filter.source.as_deref())
            .bind(filter.since)
            .bind(filter.before)
            .bind(limit_as_i64(limit)?)
            .fetch_all(&self.pool)
            .await?;
        lane_hits(rows)
    }

    /// Fetch rows by stable Recall chunk IDs, never crossing the store scope.
    pub async fn fetch_chunks_scoped(
        &self,
        chunk_ids: &[String],
        filter: &CorpusFilter,
    ) -> Result<Vec<HydratedChunk>> {
        enforce_filter_scope(filter, &self.scope)?;
        if chunk_ids.is_empty() {
            return Ok(Vec::new());
        }
        if chunk_ids.len() > 10_000 {
            return Err(FleetError::Memory(
                "fetch_chunks accepts at most 10,000 ids".into(),
            ));
        }

        let rows = sqlx::query(FETCH_CHUNKS_SQL_PREFIX)
            .bind(self.scope.tenant_id)
            .bind(&self.scope.project)
            .bind(chunk_ids)
            .bind(filter.source.as_deref())
            .bind(filter.since)
            .bind(filter.before)
            .fetch_all(&self.pool)
            .await?;
        let mut fetched = rows
            .iter()
            .map(decode_chunk)
            .map(|result| result.map(|hydrated| (hydrated.chunk.chunk_id.clone(), hydrated)))
            .collect::<Result<HashMap<_, _>>>()?;
        Ok(chunk_ids
            .iter()
            .filter_map(|chunk_id| fetched.remove(chunk_id))
            .collect())
    }

    /// Hydrate only fields consumed by portable hybrid ranking.
    /// Text is bounded in SQL; JSON and stored vectors are never selected.
    async fn fetch_retrieval_chunks_scoped(
        &self,
        chunk_ids: &[String],
        filter: &CorpusFilter,
    ) -> Result<Vec<HydratedChunk>> {
        enforce_filter_scope(filter, &self.scope)?;
        if chunk_ids.is_empty() {
            return Ok(Vec::new());
        }
        if chunk_ids.len() > 10_000 {
            return Err(FleetError::Memory(
                "retrieval hydration accepts at most 10,000 ids".into(),
            ));
        }

        let rows = sqlx::query(FETCH_RETRIEVAL_CHUNKS_SQL)
            .bind(self.scope.tenant_id)
            .bind(&self.scope.project)
            .bind(chunk_ids)
            .bind(filter.source.as_deref())
            .bind(filter.since)
            .bind(filter.before)
            .bind(
                i64::try_from(RETRIEVAL_TEXT_CHARS)
                    .map_err(|_| FleetError::Memory("retrieval text bound exceeds INT8".into()))?,
            )
            .fetch_all(&self.pool)
            .await?;
        let mut fetched = rows
            .iter()
            .map(decode_retrieval_chunk)
            .map(|result| result.map(|hydrated| (hydrated.chunk.chunk_id.clone(), hydrated)))
            .collect::<Result<HashMap<_, _>>>()?;
        Ok(chunk_ids
            .iter()
            .filter_map(|chunk_id| fetched.remove(chunk_id))
            .collect())
    }

    /// Hydrate bounded metadata only for the final diversified result page.
    pub(crate) async fn fetch_retrieval_hit_metadata(
        &self,
        chunk_ids: &[String],
    ) -> Result<Vec<RetrievalHitMetadata>> {
        if chunk_ids.is_empty() {
            return Ok(Vec::new());
        }
        if chunk_ids.len() > MAX_RETRIEVAL_METADATA_ROWS {
            return Err(FleetError::Memory(format!(
                "retrieval metadata accepts at most {MAX_RETRIEVAL_METADATA_ROWS} ids"
            )));
        }
        let json_bound = i64::try_from(RETRIEVAL_JSON_BYTES)
            .map_err(|_| FleetError::Memory("retrieval JSON bound exceeds INT8".into()))?;
        let rows = sqlx::query(FETCH_RETRIEVAL_METADATA_SQL)
            .bind(self.scope.tenant_id)
            .bind(&self.scope.project)
            .bind(chunk_ids)
            .bind(json_bound)
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(decode_retrieval_metadata).collect()
    }

    fn ensure_same_scope(&self, scope: &FleetScope) -> Result<()> {
        if self.scope.tenant_id != scope.tenant_id || self.scope.project != scope.project {
            return Err(FleetError::InvalidScope(
                "chunk tenant/project does not match this store".into(),
            ));
        }
        Ok(())
    }
}

async fn write_chunk_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    row: &ScopedChunk,
    vector: &str,
    facets: &Value,
    links: &Value,
    chunk_index: i64,
    history_reason: Option<&str>,
) -> Result<()> {
    if let Some(history_reason) = history_reason {
        sqlx::query(
            "DELETE FROM memory_chunks \
             WHERE tenant_id = $1 AND project = $2 AND chunk_id = $3",
        )
        .bind(row.scope.tenant_id)
        .bind(&row.scope.project)
        .bind(&row.chunk.chunk_id)
        .execute(&mut **transaction)
        .await?;

        bind_history_chunk(
            sqlx::query(UPSERT_HISTORY_CHUNK_SQL),
            row,
            vector,
            facets,
            links,
            chunk_index,
            history_reason,
        )
        .execute(&mut **transaction)
        .await?;
    } else {
        let registered_model = ensure_active_model(transaction, row).await?;
        if registered_model != row.embedding_model {
            return Err(FleetError::Memory(format!(
                "embedding model '{}' does not match active model '{registered_model}' for tenant/project; evacuate and re-embed the active corpus before changing generations",
                row.embedding_model,
            )));
        }

        sqlx::query(
            "DELETE FROM memory_chunk_history \
             WHERE tenant_id = $1 AND project = $2 AND chunk_id = $3",
        )
        .bind(row.scope.tenant_id)
        .bind(&row.scope.project)
        .bind(&row.chunk.chunk_id)
        .execute(&mut **transaction)
        .await?;

        bind_active_chunk(
            sqlx::query(UPSERT_ACTIVE_CHUNK_SQL),
            row,
            vector,
            facets,
            links,
            chunk_index,
        )
        .execute(&mut **transaction)
        .await?;
    }
    Ok(())
}

async fn ensure_active_model(
    transaction: &mut Transaction<'_, Postgres>,
    row: &ScopedChunk,
) -> Result<String> {
    let mut registered_model = sqlx::query_scalar::<_, String>(READ_ACTIVE_MODEL_SQL)
        .bind(row.scope.tenant_id)
        .bind(&row.scope.project)
        .fetch_optional(&mut **transaction)
        .await?;
    if registered_model.is_none() {
        sqlx::query(INSERT_ACTIVE_MODEL_SQL)
            .bind(row.scope.tenant_id)
            .bind(&row.scope.project)
            .bind(&row.embedding_model)
            .execute(&mut **transaction)
            .await?;
        registered_model = sqlx::query_scalar::<_, String>(READ_ACTIVE_MODEL_SQL)
            .bind(row.scope.tenant_id)
            .bind(&row.scope.project)
            .fetch_optional(&mut **transaction)
            .await?;
    }
    registered_model.ok_or_else(|| {
        FleetError::Memory("active embedding model registration disappeared during upsert".into())
    })
}

fn bind_active_chunk<'query>(
    query: sqlx::query::Query<'query, Postgres, sqlx::postgres::PgArguments>,
    row: &'query ScopedChunk,
    vector: &'query str,
    facets: &'query Value,
    links: &'query Value,
    chunk_index: i64,
) -> sqlx::query::Query<'query, Postgres, sqlx::postgres::PgArguments> {
    query
        .bind(row.scope.tenant_id)
        .bind(&row.scope.project)
        .bind(&row.chunk.chunk_id)
        .bind(row.chunk.source.as_str())
        .bind(&row.chunk.source_id)
        .bind(&row.chunk.source_config_id)
        .bind(chunk_index)
        .bind(row.chunk.ts)
        .bind(&row.chunk.role)
        .bind(&row.chunk.text)
        .bind(&row.chunk.sha256)
        .bind(&row.chunk.embedding_input_sha256)
        .bind(&row.embedding_model)
        .bind(vector)
        .bind(facets)
        .bind(links)
        .bind(&row.chunk.extra)
}

fn bind_history_chunk<'query>(
    query: sqlx::query::Query<'query, Postgres, sqlx::postgres::PgArguments>,
    row: &'query ScopedChunk,
    vector: &'query str,
    facets: &'query Value,
    links: &'query Value,
    chunk_index: i64,
    history_reason: &'query str,
) -> sqlx::query::Query<'query, Postgres, sqlx::postgres::PgArguments> {
    bind_active_chunk(query, row, vector, facets, links, chunk_index).bind(history_reason)
}

#[async_trait]
impl CorpusReader for CockroachStore {
    async fn lexical_search(
        &self,
        query: &str,
        filter: &CorpusFilter,
        limit: usize,
    ) -> std::result::Result<Vec<CorpusLaneHit>, CorpusReadError> {
        self.lexical_search_scoped(query, filter, limit)
            .await
            .map_err(|error| corpus_error("lexical_search", error))
    }

    async fn dense_search(
        &self,
        embedding: &[f32],
        filter: &CorpusFilter,
        limit: usize,
    ) -> std::result::Result<Vec<CorpusLaneHit>, CorpusReadError> {
        self.vector_search(embedding, filter, limit)
            .await
            .map_err(|error| corpus_error("dense_search", error))
    }

    async fn fetch_chunks(
        &self,
        chunk_ids: &[String],
        filter: &CorpusFilter,
    ) -> std::result::Result<Vec<HydratedChunk>, CorpusReadError> {
        self.fetch_chunks_scoped(chunk_ids, filter)
            .await
            .map_err(|error| corpus_error("fetch_chunks", error))
    }
}

#[async_trait]
impl CorpusReader for CockroachRetrievalReader<'_> {
    async fn lexical_search(
        &self,
        query: &str,
        filter: &CorpusFilter,
        limit: usize,
    ) -> std::result::Result<Vec<CorpusLaneHit>, CorpusReadError> {
        self.store
            .lexical_search_scoped(query, filter, limit)
            .await
            .map_err(|error| corpus_error("lexical_search", error))
    }

    async fn dense_search(
        &self,
        embedding: &[f32],
        filter: &CorpusFilter,
        limit: usize,
    ) -> std::result::Result<Vec<CorpusLaneHit>, CorpusReadError> {
        // The portable engine uses zero to disable its optional stratified
        // code prefetch. Treat that as an empty lane instead of forwarding an
        // invalid physical limit to CockroachDB.
        if limit == 0 {
            enforce_filter_scope(filter, &self.store.scope)
                .map_err(|error| corpus_error("dense_search", error))?;
            return Ok(Vec::new());
        }
        let hits = self
            .store
            .vector_search(embedding, filter, limit)
            .await
            .map_err(|error| corpus_error("dense_search", error))?;
        apply_retrieval_dense_floor(hits)
            .map_err(|error| corpus_error("dense_relevance_floor", error))
    }

    async fn fetch_chunks(
        &self,
        chunk_ids: &[String],
        filter: &CorpusFilter,
    ) -> std::result::Result<Vec<HydratedChunk>, CorpusReadError> {
        self.store
            .fetch_retrieval_chunks_scoped(chunk_ids, filter)
            .await
            .map_err(|error| corpus_error("fetch_retrieval_chunks", error))
    }
}

fn corpus_error(operation: &'static str, error: impl std::fmt::Display) -> CorpusReadError {
    CorpusReadError::new("cockroachdb", operation, error)
}

fn enforce_filter_scope(filter: &CorpusFilter, scope: &FleetScope) -> Result<()> {
    if let Some(projects) = &filter.projects
        && (projects.len() != 1 || projects[0] != scope.project)
    {
        return Err(FleetError::InvalidScope(
            "fleet corpus reads must target exactly the configured project".into(),
        ));
    }
    Ok(())
}

const fn filter_has_time_bounds(filter: &CorpusFilter) -> bool {
    filter.since.is_some() || filter.before.is_some()
}

fn filtered_vector_candidate_limit(limit: usize) -> usize {
    limit
        .saturating_mul(FILTERED_VECTOR_OVERSAMPLE_FACTOR)
        .max(limit)
        .min(FILTERED_VECTOR_CANDIDATE_CAP)
}

fn lane_hits(rows: Vec<PgRow>) -> Result<Vec<CorpusLaneHit>> {
    rows.into_iter()
        .enumerate()
        .map(|(rank, row)| {
            let rank = u32::try_from(rank)
                .map_err(|_| FleetError::Memory("result rank exceeded u32".into()))?;
            Ok(CorpusLaneHit {
                chunk_id: row.try_get("chunk_id")?,
                score: row.try_get("score")?,
                rank,
            })
        })
        .collect()
}

fn apply_retrieval_dense_floor(hits: Vec<CorpusLaneHit>) -> Result<Vec<CorpusLaneHit>> {
    let max_distance = 1.0 - RETRIEVAL_DENSE_MIN_COSINE_SIMILARITY;
    hits.into_iter()
        .filter(|hit| hit.score.is_finite() && hit.score <= max_distance)
        .enumerate()
        .map(|(rank, mut hit)| {
            // The input is nearest-first, so filtering normally removes only
            // a tail. Re-stamping keeps the lane contract exact even if a
            // backend ever returns a non-finite value in the middle.
            hit.rank = u32::try_from(rank)
                .map_err(|_| FleetError::Memory("result rank exceeded u32".into()))?;
            Ok(hit)
        })
        .collect()
}

fn decode_chunk(row: &PgRow) -> Result<HydratedChunk> {
    let source_name: String = row.try_get("source")?;
    let source = Source::parse_str(&source_name).ok_or_else(|| {
        FleetError::Memory(format!(
            "unknown source value in memory_chunks: {source_name}"
        ))
    })?;
    let facets_value: Value = row.try_get("facets")?;
    let links_value: Value = row.try_get("links")?;
    let facets: FacetSet = serde_json::from_value(facets_value)
        .map_err(|error| FleetError::Memory(format!("decode facets: {error}")))?;
    let links: Links = serde_json::from_value(links_value)
        .map_err(|error| FleetError::Memory(format!("decode links: {error}")))?;
    let chunk_index: i64 = row.try_get("chunk_index")?;
    let chunk_index = u32::try_from(chunk_index)
        .map_err(|_| FleetError::Memory("chunk_index is outside u32 range".into()))?;
    let embedding_text: String = row.try_get("embedding_text")?;

    Ok(HydratedChunk {
        chunk: Chunk {
            chunk_id: row.try_get("chunk_id")?,
            source,
            project: Some(row.try_get("project")?),
            source_id: row.try_get("source_id")?,
            source_config_id: row.try_get("source_config_id")?,
            chunk_index,
            ts: row.try_get::<Option<DateTime<Utc>>, _>("source_timestamp")?,
            role: row.try_get("role")?,
            text: row.try_get("text")?,
            sha256: row.try_get("content_sha256")?,
            links,
            facets,
            embedding_input_sha256: row.try_get("embedding_input_sha256")?,
            extra: row.try_get("extra")?,
        },
        embedding: Some(parse_vector(&embedding_text)?),
    })
}

fn decode_retrieval_chunk(row: &PgRow) -> Result<HydratedChunk> {
    let source_name: String = row.try_get("source")?;
    let source = Source::parse_str(&source_name).ok_or_else(|| {
        FleetError::Memory(format!(
            "unknown source value in memory_chunks: {source_name}"
        ))
    })?;
    Ok(HydratedChunk {
        chunk: Chunk {
            chunk_id: row.try_get("chunk_id")?,
            source,
            project: Some(row.try_get("project")?),
            source_id: row.try_get("source_id")?,
            source_config_id: String::new(),
            chunk_index: 0,
            ts: row.try_get::<Option<DateTime<Utc>>, _>("source_timestamp")?,
            role: row.try_get("role")?,
            text: row.try_get("text")?,
            sha256: String::new(),
            links: Links::default(),
            facets: FacetSet::default(),
            embedding_input_sha256: String::new(),
            extra: Value::Null,
        },
        embedding: None,
    })
}

fn decode_retrieval_metadata(row: &PgRow) -> Result<RetrievalHitMetadata> {
    let links_value: Value = row.try_get("links")?;
    let links: Links = serde_json::from_value(links_value)
        .map_err(|error| FleetError::Memory(format!("decode retrieval links: {error}")))?;
    Ok(RetrievalHitMetadata {
        chunk_id: row.try_get("chunk_id")?,
        links,
        extra: row.try_get("extra")?,
        links_elided: row.try_get("links_elided")?,
        extra_elided: row.try_get("extra_elided")?,
    })
}

fn validate_limit(limit: usize) -> Result<()> {
    if limit == 0 || limit > 10_000 {
        return Err(FleetError::Memory(
            "search limit must be between 1 and 10,000".into(),
        ));
    }
    Ok(())
}

fn limit_as_i64(limit: usize) -> Result<i64> {
    i64::try_from(limit).map_err(|_| FleetError::Memory("search limit exceeds INT8".into()))
}

fn validate_embedding(embedding: &[f32]) -> Result<()> {
    if embedding.len() != EMBEDDING_DIMENSION {
        return Err(FleetError::Memory(format!(
            "embedding dimension mismatch: expected {EMBEDDING_DIMENSION}, got {}",
            embedding.len()
        )));
    }
    if embedding.iter().any(|component| !component.is_finite()) {
        return Err(FleetError::Memory(
            "embedding contains a non-finite component".into(),
        ));
    }
    let norm_squared = embedding
        .iter()
        .map(|component| f64::from(*component).powi(2))
        .sum::<f64>();
    if norm_squared == 0.0 {
        return Err(FleetError::Memory(
            "embedding must have a non-zero norm for cosine distance".into(),
        ));
    }
    Ok(())
}

/// Encode a vector using pgvector's documented text representation.
///
/// Binding it as `STRING` and casting in SQL avoids relying on extension OIDs
/// while remaining compatible with `CockroachDB`'s built-in `VECTOR` type.
pub fn serialize_vector(embedding: &[f32]) -> Result<String> {
    validate_embedding(embedding)?;
    let mut encoded = String::with_capacity(embedding.len() * 10 + 2);
    encoded.push('[');
    for (index, component) in embedding.iter().enumerate() {
        if index > 0 {
            encoded.push(',');
        }
        write!(encoded, "{component}")
            .map_err(|error| FleetError::Memory(format!("encode embedding: {error}")))?;
    }
    encoded.push(']');
    Ok(encoded)
}

fn parse_vector(encoded: &str) -> Result<Vec<f32>> {
    let encoded = encoded
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .ok_or_else(|| FleetError::Memory("database returned malformed vector".into()))?;
    let values = if encoded.is_empty() {
        Vec::new()
    } else {
        encoded
            .split(',')
            .map(|value| {
                value.parse::<f32>().map_err(|error| {
                    FleetError::Memory(format!("database returned malformed vector: {error}"))
                })
            })
            .collect::<Result<Vec<_>>>()?
    };
    validate_embedding(&values)?;
    Ok(values)
}

/// Retry policy for idempotent, serializable application-level transactions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Total executions, including the initial attempt.
    pub max_attempts: u32,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            initial_backoff: Duration::from_millis(10),
            max_backoff: Duration::from_millis(500),
        }
    }
}

impl RetryPolicy {
    fn validate(self) -> Result<()> {
        if self.max_attempts == 0 {
            return Err(FleetError::Configuration(
                "retry max_attempts must be greater than zero".into(),
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn delay_for_retry(self, retry_index: u32) -> Duration {
        let multiplier = 1_u32.checked_shl(retry_index.min(31)).unwrap_or(u32::MAX);
        self.initial_backoff
            .saturating_mul(multiplier)
            .min(self.max_backoff)
    }
}

/// Return true only for CockroachDB/PostgreSQL serialization failures.
#[must_use]
pub fn is_retryable(error: &sqlx::Error) -> bool {
    matches!(error, sqlx::Error::Database(database) if is_retryable_sqlstate(database.code().as_deref()))
}

/// Return true only when a fleet operation wraps `CockroachDB` SQLSTATE 40001.
#[must_use]
pub fn is_retryable_fleet_error(error: &FleetError) -> bool {
    matches!(error, FleetError::Database(database) if is_retryable(database))
}

/// `CockroachDB` reports every transaction-restart condition as SQLSTATE
/// `40001`. Other transient-looking errors are not safe to replay blindly.
#[must_use]
pub fn is_retryable_sqlstate(code: Option<&str>) -> bool {
    code == Some("40001")
}

/// Execute a bounded serializable transaction retry loop.
///
/// The closure may run more than once and therefore **must be idempotent**.
/// Put an idempotency-receipt read/write in the same transaction as any
/// externally meaningful mutation. Each retry uses a fresh transaction,
/// avoiding reuse of an aborted `SQLx` transaction after a `40001` error.
pub async fn with_serializable_retry<T, F>(
    pool: &PgPool,
    policy: RetryPolicy,
    mut operation: F,
) -> Result<T>
where
    F: for<'transaction> FnMut(
        &'transaction mut Transaction<'_, Postgres>,
    ) -> BoxFuture<'transaction, Result<T>>,
{
    policy.validate()?;
    let mut attempt = 0_u32;
    loop {
        attempt += 1;
        let mut transaction = pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
            .execute(&mut *transaction)
            .await?;
        let outcome = operation(&mut transaction).await;
        match outcome {
            Ok(value) => match transaction.commit().await {
                Ok(()) => return Ok(value),
                Err(error) if is_retryable(&error) && attempt < policy.max_attempts => {
                    tokio::time::sleep(policy.delay_for_retry(attempt - 1)).await;
                }
                Err(error) => return Err(error.into()),
            },
            Err(error) if is_retryable_fleet_error(&error) && attempt < policy.max_attempts => {
                // Dropping rolls the aborted transaction back before retrying.
                drop(transaction);
                tokio::time::sleep(policy.delay_for_retry(attempt - 1)).await;
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ostk_recall_core::{ChunkEmbedder, PrivacyTier, RecallParams};
    use uuid::Uuid;

    static LIVE_DATABASE_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    struct FixedEmbedder;

    impl ChunkEmbedder for FixedEmbedder {
        fn dim(&self) -> usize {
            EMBEDDING_DIMENSION
        }

        fn model_id(&self) -> &'static str {
            "live-test"
        }

        fn encode_batch(&self, texts: &[&str]) -> Vec<Vec<f32>> {
            texts
                .iter()
                .map(|_| {
                    let mut embedding = vec![0.0; EMBEDDING_DIMENSION];
                    embedding[0] = 1.0;
                    embedding
                })
                .collect()
        }
    }

    fn scope(project: &str) -> FleetScope {
        FleetScope::new(
            Uuid::parse_str("0198a849-f6ae-7d61-9800-000000000001").unwrap(),
            project,
            "agent",
            Some("session".into()),
            PrivacyTier::T1Project,
        )
        .unwrap()
    }

    #[test]
    fn vector_serialization_round_trips_without_special_values() {
        let embedding = (0..EMBEDDING_DIMENSION)
            .map(|index| f32::from(u16::try_from(index).unwrap()) / 17.0 - 4.0)
            .collect::<Vec<_>>();
        let encoded = serialize_vector(&embedding).unwrap();
        assert!(encoded.starts_with('['));
        assert!(encoded.ends_with(']'));
        assert_eq!(parse_vector(&encoded).unwrap(), embedding);
    }

    #[test]
    fn vector_serialization_rejects_dimension_non_finite_and_zero_norm() {
        assert!(serialize_vector(&[0.0; 4]).is_err());
        let mut embedding = vec![0.0; EMBEDDING_DIMENSION];
        embedding[3] = f32::NAN;
        assert!(serialize_vector(&embedding).is_err());
        assert!(serialize_vector(&vec![0.0; EMBEDDING_DIMENSION]).is_err());
    }

    #[test]
    fn fleet_dense_floor_drops_weak_neighbors_and_restamps_rank() {
        let hits = vec![
            CorpusLaneHit {
                chunk_id: "strong".into(),
                score: 0.4,
                rank: 4,
            },
            CorpusLaneHit {
                chunk_id: "boundary".into(),
                score: 0.819,
                rank: 7,
            },
            CorpusLaneHit {
                chunk_id: "weak".into(),
                score: 0.821,
                rank: 8,
            },
            CorpusLaneHit {
                chunk_id: "invalid".into(),
                score: f32::NAN,
                rank: 9,
            },
        ];

        let filtered = apply_retrieval_dense_floor(hits).unwrap();
        assert_eq!(
            filtered
                .iter()
                .map(|hit| (hit.chunk_id.as_str(), hit.rank))
                .collect::<Vec<_>>(),
            [("strong", 0), ("boundary", 1)]
        );
        assert!((RETRIEVAL_DENSE_MIN_COSINE_SIMILARITY - 0.18).abs() < f32::EPSILON);
    }

    #[test]
    fn retry_backoff_is_exponential_and_capped() {
        let policy = RetryPolicy {
            max_attempts: 8,
            initial_backoff: Duration::from_millis(10),
            max_backoff: Duration::from_millis(50),
        };
        assert_eq!(policy.delay_for_retry(0), Duration::from_millis(10));
        assert_eq!(policy.delay_for_retry(1), Duration::from_millis(20));
        assert_eq!(policy.delay_for_retry(2), Duration::from_millis(40));
        assert_eq!(policy.delay_for_retry(3), Duration::from_millis(50));
        assert_eq!(policy.delay_for_retry(31), Duration::from_millis(50));
    }

    #[test]
    fn database_schema_compatibility_is_a_minimum_floor() {
        for (schema_version, minimum, expected) in [
            (1, MINIMUM_RECALL_SCHEMA_VERSION, false),
            (2, MINIMUM_RECALL_SCHEMA_VERSION, true),
            (3, MINIMUM_RECALL_SCHEMA_VERSION, true),
            (2, 3, false),
            (3, 3, true),
        ] {
            let capabilities = DatabaseCapabilities {
                version: "CockroachDB test".into(),
                vector_index_enabled: true,
                lexical_index_enabled: true,
                conflict_membership_index_enabled: true,
                claim_support_chunk_index_enabled: true,
                cosine_distance_supported: true,
                schema_version,
            };
            assert_eq!(capabilities.supports_schema_version(minimum), expected);
        }
    }

    #[test]
    fn retries_only_cockroach_serialization_sqlstate() {
        assert!(is_retryable_sqlstate(Some("40001")));
        assert!(!is_retryable_sqlstate(Some("40P01")));
        assert!(!is_retryable_sqlstate(Some("08006")));
        assert!(!is_retryable_sqlstate(None));
    }

    #[test]
    fn query_lanes_bind_scope_before_user_inputs() {
        for sql in [
            VECTOR_SEARCH_SQL,
            SOURCE_VECTOR_SEARCH_SQL,
            FILTER_VECTOR_CANDIDATES_SQL,
            LEXICAL_SEARCH_SQL,
            FETCH_CHUNKS_SQL_PREFIX,
            FETCH_RETRIEVAL_CHUNKS_SQL,
            FETCH_RETRIEVAL_METADATA_SQL,
        ] {
            assert!(sql.contains("tenant_id = $1"));
            assert!(sql.contains("project = $2"));
        }
        assert!(VECTOR_SEARCH_SQL.contains("embedding <=> $3::VECTOR(512)"));
        assert!(!VECTOR_SEARCH_SQL.contains("source ="));
        assert!(!VECTOR_SEARCH_SQL.contains("source_timestamp"));
        assert!(!VECTOR_SEARCH_SQL.contains("stale"));
        assert!(!VECTOR_SEARCH_SQL.contains("archive_parent"));
        assert!(SOURCE_VECTOR_SEARCH_SQL.contains("source = $3"));
        assert!(SOURCE_VECTOR_SEARCH_SQL.contains("embedding <=> $4::VECTOR(512)"));
        assert!(LEXICAL_SEARCH_SQL.contains("plainto_tsquery('english', $3)"));
        for sql in [
            FILTER_VECTOR_CANDIDATES_SQL,
            LEXICAL_SEARCH_SQL,
            FETCH_CHUNKS_SQL_PREFIX,
            FETCH_RETRIEVAL_CHUNKS_SQL,
        ] {
            assert!(sql.contains("source = $4"));
            assert!(sql.contains("source_timestamp >= $5"));
            assert!(sql.contains("source_timestamp < $6"));
        }
        assert!(FILTER_VECTOR_CANDIDATES_SQL.contains("@{NO_FULL_SCAN}"));
        assert!(FETCH_CHUNKS_SQL_PREFIX.contains("@{NO_FULL_SCAN}"));
        assert!(FETCH_RETRIEVAL_CHUNKS_SQL.contains("@{NO_FULL_SCAN}"));
        assert!(FETCH_RETRIEVAL_METADATA_SQL.contains("@{NO_FULL_SCAN}"));
    }

    #[test]
    fn retrieval_hydration_is_projected_and_bounded_before_transfer() {
        assert!(FETCH_RETRIEVAL_CHUNKS_SQL.contains("left(text, $7) AS text"));
        for omitted in [
            "embedding::STRING",
            "embedding_input_sha256",
            "content_sha256",
            "source_config_id",
            "facets,",
            "links",
            "extra",
        ] {
            assert!(!FETCH_RETRIEVAL_CHUNKS_SQL.contains(omitted));
        }
        assert!(FETCH_RETRIEVAL_METADATA_SQL.contains("octet_length(links::STRING) <= $4"));
        assert!(FETCH_RETRIEVAL_METADATA_SQL.contains("octet_length(extra::STRING) <= $4"));
        for omitted in ["text", "embedding", "facets"] {
            assert!(!FETCH_RETRIEVAL_METADATA_SQL.contains(omitted));
        }
        assert!(FETCH_CHUNKS_SQL_PREFIX.contains("embedding::STRING"));
        assert_eq!(RETRIEVAL_TEXT_CHARS, 401);
        assert_eq!(RETRIEVAL_JSON_BYTES, 8 * 1024);
        assert_eq!(MAX_RETRIEVAL_METADATA_ROWS, 100);
    }

    #[test]
    fn model_rotation_requires_every_searchable_vector_plane_to_be_empty() {
        assert!(ROTATE_ACTIVE_MODEL_SQL.contains("FROM memory_chunks"));
        assert!(ROTATE_ACTIVE_MODEL_SQL.contains("FROM memory_claim_embeddings"));
        assert_eq!(ROTATE_ACTIVE_MODEL_SQL.matches("NOT EXISTS").count(), 2);
        assert_eq!(ROTATE_ACTIVE_MODEL_SQL.matches("tenant_id = $1").count(), 3);
        assert_eq!(ROTATE_ACTIVE_MODEL_SQL.matches("project = $2").count(), 3);
    }

    #[test]
    fn filtered_vector_candidate_window_is_bounded() {
        assert_eq!(filtered_vector_candidate_limit(1), 8);
        assert_eq!(filtered_vector_candidate_limit(100), 800);
        assert_eq!(
            filtered_vector_candidate_limit(FILTERED_VECTOR_CANDIDATE_CAP),
            FILTERED_VECTOR_CANDIDATE_CAP
        );
    }

    #[test]
    fn corpus_filter_cannot_cross_project_scope() {
        let valid = CorpusFilter {
            projects: Some(vec!["alpha".into()]),
            ..CorpusFilter::default()
        };
        assert!(enforce_filter_scope(&valid, &scope("alpha")).is_ok());

        let cross_project = CorpusFilter {
            projects: Some(vec!["beta".into()]),
            ..CorpusFilter::default()
        };
        assert!(matches!(
            enforce_filter_scope(&cross_project, &scope("alpha")),
            Err(FleetError::InvalidScope(_))
        ));
    }

    #[test]
    fn embedded_schema_reserves_all_durable_layers() {
        let migration = include_str!("../../migrations/0001_fleet_memory.sql");
        for table in [
            "memory_corpus_models",
            "memory_chunks",
            "memory_chunk_history",
            "memory_claims",
            "memory_claim_embeddings",
            "memory_conflicts",
            "memory_events",
            "memory_attention",
            "memory_mutation_receipts",
        ] {
            assert!(migration.contains(&format!("CREATE TABLE {table}")));
        }
        assert!(migration.contains("vector_cosine_ops"));
        assert!(migration.contains("ON memory_chunks (tenant_id, project, embedding"));
        assert!(migration.contains(
            "ON memory_chunks (tenant_id, project, source, embedding vector_cosine_ops)"
        ));
        assert!(migration.contains(
            "ON memory_claim_embeddings (tenant_id, project, model, vector vector_cosine_ops)"
        ));
        assert!(!migration.contains("unique_rowid()"));
        for sequence in [
            "memory_claim_id_seq",
            "memory_claim_support_id_seq",
            "memory_conflict_id_seq",
            "memory_claim_link_id_seq",
        ] {
            assert!(migration.contains(&format!(
                "CREATE SEQUENCE {sequence} START 1 MINVALUE 1 MAXVALUE {MAX_PUBLIC_NUMERIC_ID}"
            )));
        }
        assert_eq!(
            migration
                .matches("CHECK (id BETWEEN 1 AND 9007199254740991)")
                .count(),
            4
        );
    }

    #[test]
    fn support_chunk_migration_adds_the_scoped_point_lookup() {
        let migration = include_str!("../../migrations/0002_claim_support_chunk_lookup.sql");
        assert!(migration.contains("CREATE INDEX memory_claim_support_chunk_idx"));
        assert!(
            migration.contains(
                "ON memory_claim_support (tenant_id, project, chunk_id, state, claim_id)"
            )
        );
        assert!(!migration.contains("DROP "));
    }

    #[test]
    fn control_event_ledger_migration_is_scoped_bounded_and_additive() {
        let migration = CONTROL_EVENT_LEDGER_MIGRATION_SQL;
        let tables = [
            "memory_control_bootstraps",
            "memory_control_log_epochs",
            "memory_control_shard_heads",
            "memory_control_events",
        ];
        assert_eq!(migration.matches("CREATE TABLE ").count(), tables.len());
        for table in tables {
            assert!(migration.contains(&format!("CREATE TABLE {table}")));
            assert!(migration.contains(&format!("CREATE TABLE {table} (\n    tenant_id")));
        }

        for scope_leading_key in [
            "PRIMARY KEY (tenant_id, project)",
            "PRIMARY KEY (tenant_id, project, epoch_id)",
            "PRIMARY KEY (tenant_id, project, epoch_id, shard)",
            "PRIMARY KEY (tenant_id, project, epoch_id, shard, committed_offset)",
            "UNIQUE (tenant_id, project, receipt_digest)",
            "UNIQUE (tenant_id, project, bootstrap_event_id)",
            "UNIQUE (tenant_id, project, event_id)",
        ] {
            assert!(migration.contains(scope_leading_key));
        }

        assert!(migration.contains("CHECK (bootstrap_offset = 1)"));
        assert!(migration.contains("CHECK (committed_offset > 0)"));
        assert!(migration.contains("CHECK (last_committed_offset >= 0)"));
        assert!(migration.contains("CHECK (approval_threshold BETWEEN 1 AND signer_count)"));
        assert_eq!(migration.matches("BETWEEN 1 AND 1048576").count(), 4);
        assert!(migration.contains("CHECK (shard_count BETWEEN 1 AND 4096)"));
        assert!(
            migration
                .contains("CHECK (partition_recipe_id = 'ostk.partition.sha256_prefix64_modulo')")
        );
        assert!(migration.contains("CHECK (partition_recipe_version = 1)"));
        assert!(migration.contains("CHECK (octet_length(event_id) = 32)"));
        assert!(migration.contains("CHECK (octet_length(chain_digest) = 32)"));
        assert!(migration.contains("canonical_receipt                 BYTES NOT NULL"));
        assert!(migration.contains("canonical_genesis_package         BYTES NOT NULL"));
        assert!(migration.contains("canonical_event              BYTES NOT NULL"));
        for scoped_foreign_key in [
            "FOREIGN KEY (tenant_id, project, bootstrap_receipt_digest)",
            "FOREIGN KEY (tenant_id, project, epoch_id, shard_count)",
            "FOREIGN KEY (tenant_id, project, epoch_id, shard)",
        ] {
            assert!(migration.contains(scoped_foreign_key));
        }
        assert_eq!(migration.matches("CREATE INDEX ").count(), 0);
        assert_eq!(migration.matches("CREATE SEQUENCE ").count(), 0);
        assert!(!migration.contains("JSONB"));

        let uppercase = migration.to_ascii_uppercase();
        for forbidden in ["ALTER ", "DROP ", "UPDATE ", "DELETE "] {
            assert!(!uppercase.contains(forbidden));
        }
        assert!(!migration.contains("memory_events"));
    }

    #[test]
    fn genesis_registry_activation_migration_is_scoped_bounded_and_additive() {
        let migration = GENESIS_REGISTRY_ACTIVATION_MIGRATION_SQL;
        let tables = ["memory_registry_activations", "memory_registry_heads"];
        assert_eq!(migration.matches("CREATE TABLE ").count(), tables.len());
        for table in tables {
            assert!(migration.contains(&format!("CREATE TABLE {table}")));
            assert!(migration.contains(&format!("CREATE TABLE {table} (\n    tenant_id")));
        }

        assert!(migration.contains("PRIMARY KEY (tenant_id, project, activation_id)"));
        assert!(migration.contains("PRIMARY KEY (tenant_id, project)"));
        for scope_leading_key in [
            "UNIQUE (tenant_id, project, statement_id)",
            "UNIQUE (tenant_id, project, accepted_event_id)",
        ] {
            assert!(migration.contains(scope_leading_key));
        }
        for canonical_projection in [
            "canonical_statement",
            "canonical_approval_set",
            "canonical_test_result",
            "canonical_receipt",
            "canonical_event",
            "canonical_head",
        ] {
            assert!(migration.contains(canonical_projection));
        }
        for scoped_foreign_key in [
            "memory_registry_activation_bootstrap_anchor_fk",
            "FOREIGN KEY (tenant_id, project, genesis_epoch_id)",
            "REFERENCES memory_registry_activations",
            "REFERENCES memory_control_events",
        ] {
            assert!(migration.contains(scoped_foreign_key));
        }

        assert!(migration.contains("approval_ids_packed                BYTES NOT NULL"));
        assert!(migration.contains("CHECK (approval_count BETWEEN 1 AND 64)"));
        assert!(
            migration.contains("CHECK (octet_length(approval_ids_packed) = approval_count * 32)")
        );
        assert!(migration.contains("CHECK (required_threshold BETWEEN 1 AND approval_count)"));
        assert!(migration.contains("CHECK (separation_of_duty_satisfied)"));
        assert!(migration.contains("CHECK (effective_until IS NULL)"));
        assert!(migration.contains("CHECK (effective_from >= bootstrap_accepted_at)"));
        assert!(migration.contains("CHECK (accepted_at >= effective_from)"));
        assert!(migration.contains("CHECK (control_epoch_id = genesis_epoch_id)"));
        assert!(migration.contains("CHECK (activated_package_digest = genesis_package_digest)"));
        assert!(migration.contains("CHECK (head_state = 'active')"));
        assert_eq!(migration.matches("BETWEEN 1 AND 1048576").count(), 6);
        assert_eq!(migration.matches("CREATE UNIQUE INDEX ").count(), 2);
        assert!(
            migration.contains("CREATE UNIQUE INDEX memory_control_bootstraps_registry_anchor_idx")
        );
        assert!(
            migration.contains("CREATE UNIQUE INDEX memory_control_events_registry_source_idx")
        );
        assert!(
            migration
                .contains("accepted_event_id,\n            control_epoch_id,\n            control_shard,\n            control_committed_offset,\n            activation_id,\n            accepted_at\n        )")
        );
        assert!(migration.contains("semantic_object_digest,"));
        for normalized_event_field in [
            "event_schema_version               INT4 NOT NULL",
            "event_kind                         STRING NOT NULL",
            "consistency_family                 STRING NOT NULL",
            "consistency_key_digest             BYTES NOT NULL",
            "previous_chain_digest              BYTES NOT NULL",
            "append_chain_digest                BYTES NOT NULL",
        ] {
            assert!(!migration.contains(normalized_event_field));
        }
        assert!(!migration.contains("memory_registry_head_control_source_fk"));
        assert_eq!(migration.matches("CREATE SEQUENCE ").count(), 0);
        assert!(!migration.contains("JSONB"));

        let uppercase = migration.to_ascii_uppercase();
        for forbidden in ["ALTER ", "DROP ", "UPDATE ", "DELETE ", "GRANT ", "REVOKE "] {
            assert!(!uppercase.contains(forbidden));
        }
        assert!(!migration.contains("memory_events"));
    }

    #[test]
    fn embedded_migrator_registers_private_ledgers_as_no_transaction_versions_three_and_four() {
        let migrator = embedded_migrator();
        assert_eq!(
            migrator
                .migrations
                .iter()
                .map(|migration| migration.version)
                .collect::<Vec<_>>(),
            vec![1, 2, 3, 4]
        );
        let control_ledger = migrator
            .migrations
            .iter()
            .find(|migration| migration.version == 3)
            .unwrap();
        assert_eq!(
            control_ledger.sql.as_ref(),
            CONTROL_EVENT_LEDGER_MIGRATION_SQL
        );
        assert!(control_ledger.no_tx);
        let registry_activation = migrator
            .migrations
            .iter()
            .find(|migration| migration.version == 4)
            .unwrap();
        assert_eq!(
            registry_activation.sql.as_ref(),
            GENESIS_REGISTRY_ACTIVATION_MIGRATION_SQL
        );
        assert!(registry_activation.no_tx);
        assert!(migrator.no_tx);
        assert!(!migrator.locking);
    }

    /// Set `FLEET_RECALL_TEST_DATABASE_URL` to a disposable `CockroachDB` 26.2
    /// database to exercise migrations, type casts, and index-backed lanes.
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn live_cockroach_round_trip_when_configured() {
        let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
            return;
        };
        let _live_database_guard = LIVE_DATABASE_TEST_LOCK.lock().await;

        let scope = scope("live-store-test");
        let store = CockroachStore::connect(&database_url, scope.clone(), PoolConfig::default())
            .await
            .unwrap();
        store.migrate().await.unwrap();
        store.health_check().await.unwrap();
        let capabilities = store.capabilities().await.unwrap();
        assert!(capabilities.version.contains("CockroachDB"));
        assert!(capabilities.vector_index_enabled);
        assert!(capabilities.lexical_index_enabled);
        assert!(capabilities.conflict_membership_index_enabled);
        assert!(capabilities.claim_support_chunk_index_enabled);
        assert!(capabilities.cosine_distance_supported);
        assert!(capabilities.supports_schema_version(MINIMUM_RECALL_SCHEMA_VERSION));

        let cleanup = sqlx::query(
            "WITH deleted_active AS (\
                 DELETE FROM memory_chunks WHERE tenant_id = $1 AND project = $2 RETURNING chunk_id\
             ), deleted_history AS (\
                 DELETE FROM memory_chunk_history WHERE tenant_id = $1 AND project = $2 RETURNING chunk_id\
             ) \
             DELETE FROM memory_corpus_models WHERE tenant_id = $1 AND project = $2",
        )
            .bind(scope.tenant_id)
            .bind(&scope.project)
            .execute(store.pool())
            .await;
        cleanup.unwrap();

        let mut facets = FacetSet::new();
        facets.insert("project".into(), [scope.project.clone()].into());
        let chunk = Chunk {
            chunk_id: "fleet-live-chunk".into(),
            source: Source::Markdown,
            project: Some(scope.project.clone()),
            source_id: "docs/live.md".into(),
            source_config_id: "live-config".into(),
            chunk_index: 0,
            ts: Some(Utc::now()),
            role: None,
            text: "Capybaras remember distributed semantic decisions.".into(),
            sha256: "content-sha".into(),
            links: Links {
                file_path: Some("docs/live.md".into()),
                ..Links::default()
            },
            facets,
            embedding_input_sha256: "embedding-sha".into(),
            extra: serde_json::json!({ "symbols": ["Capybara"] }),
        };
        let mut embedding = vec![0.0; EMBEDDING_DIMENSION];
        embedding[0] = 1.0;
        store
            .upsert_chunk(&ScopedChunk {
                scope: scope.clone(),
                chunk: chunk.clone(),
                embedding_model: "live-test".into(),
                embedding: embedding.clone(),
                stale: false,
            })
            .await
            .unwrap();

        let filter = CorpusFilter::default();
        let dense = store.vector_search(&embedding, &filter, 5).await.unwrap();
        assert_eq!(dense[0].chunk_id, "fleet-live-chunk");
        assert!(dense[0].score.abs() < f32::EPSILON);

        let mut weak_chunk = chunk.clone();
        weak_chunk.chunk_id = "fleet-live-weak-neighbor".into();
        weak_chunk.source_id = "docs/weak-neighbor.md".into();
        weak_chunk.text = "Unrelated nearest-neighbour padding.".into();
        let mut opposite_embedding = vec![0.0; EMBEDDING_DIMENSION];
        opposite_embedding[0] = -1.0;
        store
            .upsert_chunk(&ScopedChunk {
                scope: scope.clone(),
                chunk: weak_chunk,
                embedding_model: "live-test".into(),
                embedding: opposite_embedding,
                stale: false,
            })
            .await
            .unwrap();
        let retrieval_dense = store
            .retrieval_reader()
            .dense_search(&embedding, &filter, 5)
            .await
            .unwrap();
        assert_eq!(retrieval_dense.len(), 1);
        assert_eq!(retrieval_dense[0].chunk_id, "fleet-live-chunk");
        assert!(
            store
                .retrieval_reader()
                .dense_search(&embedding, &filter, 0)
                .await
                .unwrap()
                .is_empty()
        );

        let lexical = store
            .lexical_search_scoped("capybara semantic", &filter, 5)
            .await
            .unwrap();
        assert_eq!(lexical[0].chunk_id, "fleet-live-chunk");

        let hydrated = store
            .fetch_chunks_scoped(&["fleet-live-chunk".into()], &filter)
            .await
            .unwrap();
        assert_eq!(hydrated.len(), 1);
        assert_eq!(
            hydrated[0].chunk.project.as_deref(),
            Some("live-store-test")
        );
        assert_eq!(hydrated[0].embedding.as_ref(), Some(&embedding));

        let mut pathological_chunk = chunk.clone();
        pathological_chunk.chunk_id = "fleet-live-pathological".into();
        pathological_chunk.source_id = "docs/pathological.md".into();
        pathological_chunk.text = format!(
            "Capybaras remember distributed semantic decisions. {}",
            "é ".repeat(50_000)
        );
        pathological_chunk.links.parent_ids = (0..3)
            .map(|index| format!("parent-{index}-{}", "p".repeat(4_000)))
            .collect();
        pathological_chunk.extra =
            serde_json::json!({ "payload": "x".repeat(RETRIEVAL_JSON_BYTES + 1_000) });
        pathological_chunk.facets.insert(
            "topic".into(),
            ["y".repeat(RETRIEVAL_JSON_BYTES + 1_000)].into(),
        );
        store
            .upsert_chunk(&ScopedChunk {
                scope: scope.clone(),
                chunk: pathological_chunk.clone(),
                embedding_model: "live-test".into(),
                embedding: embedding.clone(),
                stale: false,
            })
            .await
            .unwrap();

        let full = store
            .fetch_chunks_scoped(&[pathological_chunk.chunk_id.clone()], &filter)
            .await
            .unwrap();
        assert_eq!(full[0].chunk.text, pathological_chunk.text);
        assert_eq!(full[0].chunk.extra, pathological_chunk.extra);
        assert_eq!(full[0].chunk.facets, pathological_chunk.facets);
        assert_eq!(full[0].chunk.links.parent_ids.len(), 3);
        assert_eq!(full[0].embedding.as_ref(), Some(&embedding));

        let projected = store
            .retrieval_reader()
            .fetch_chunks(&[pathological_chunk.chunk_id.clone()], &filter)
            .await
            .unwrap();
        assert_eq!(projected.len(), 1);
        assert_eq!(
            projected[0].chunk.text.chars().count(),
            RETRIEVAL_TEXT_CHARS
        );
        assert!(
            pathological_chunk
                .text
                .starts_with(&projected[0].chunk.text)
        );
        assert_eq!(projected[0].chunk.project, pathological_chunk.project);
        assert_eq!(projected[0].chunk.source_id, pathological_chunk.source_id);
        assert!(projected[0].chunk.facets.is_empty());
        assert!(projected[0].chunk.links.parent_ids.is_empty());
        assert_eq!(projected[0].chunk.extra, Value::Null);
        assert!(projected[0].embedding.is_none());

        let metadata = store
            .fetch_retrieval_hit_metadata(&[pathological_chunk.chunk_id.clone()])
            .await
            .unwrap();
        assert_eq!(metadata.len(), 1);
        assert_eq!(metadata[0].chunk_id, pathological_chunk.chunk_id);
        assert!(metadata[0].links_elided);
        assert!(metadata[0].extra_elided);
        assert!(metadata[0].links.parent_ids.is_empty());
        assert_eq!(metadata[0].extra, serde_json::json!({}));

        let hits = ostk_recall_retrieval::recall(
            &store.retrieval_reader(),
            &FixedEmbedder,
            None,
            &RecallParams {
                query: "capybaras".into(),
                project: Some(scope.project.clone()),
                limit: Some(5),
                ..RecallParams::default()
            },
        )
        .await
        .unwrap();
        let pathological_hit = hits
            .iter()
            .find(|hit| hit.chunk_id == pathological_chunk.chunk_id)
            .unwrap();
        assert_eq!(pathological_hit.snippet.chars().count(), 400);
        assert!(
            pathological_chunk
                .text
                .starts_with(&pathological_hit.snippet)
        );
        assert!(pathological_hit.extra.is_null());
        assert!(pathological_hit.links.parent_ids.is_empty());

        let ordinary_metadata = store
            .fetch_retrieval_hit_metadata(std::slice::from_ref(&chunk.chunk_id))
            .await
            .unwrap();
        assert_eq!(ordinary_metadata.len(), 1);
        assert!(!ordinary_metadata[0].links_elided);
        assert!(!ordinary_metadata[0].extra_elided);
        assert_eq!(
            serde_json::to_value(&ordinary_metadata[0].links).unwrap(),
            serde_json::to_value(&chunk.links).unwrap()
        );
        assert_eq!(ordinary_metadata[0].extra, chunk.extra);

        let mut stale_chunk = chunk.clone();
        stale_chunk.chunk_id = "fleet-live-stale".into();
        stale_chunk.source_id = "docs/stale.md".into();
        store
            .upsert_chunk(&ScopedChunk {
                scope: scope.clone(),
                chunk: stale_chunk.clone(),
                embedding_model: "live-test".into(),
                embedding: embedding.clone(),
                stale: true,
            })
            .await
            .unwrap();
        let in_hot: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM memory_chunks \
             WHERE tenant_id = $1 AND project = $2 AND chunk_id = $3)",
        )
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(&stale_chunk.chunk_id)
        .fetch_one(store.pool())
        .await
        .unwrap();
        let in_history: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM memory_chunk_history \
             WHERE tenant_id = $1 AND project = $2 AND chunk_id = $3)",
        )
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(&stale_chunk.chunk_id)
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert!(!in_hot);
        assert!(in_history);

        store
            .upsert_chunk(&ScopedChunk {
                scope: scope.clone(),
                chunk: stale_chunk.clone(),
                embedding_model: "live-test".into(),
                embedding: embedding.clone(),
                stale: false,
            })
            .await
            .unwrap();
        let in_history: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM memory_chunk_history \
             WHERE tenant_id = $1 AND project = $2 AND chunk_id = $3)",
        )
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(&stale_chunk.chunk_id)
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert!(!in_history);
        let ordered = store
            .fetch_chunks_scoped(
                &[
                    stale_chunk.chunk_id.clone(),
                    chunk.chunk_id.clone(),
                    stale_chunk.chunk_id.clone(),
                ],
                &filter,
            )
            .await
            .unwrap();
        assert_eq!(
            ordered
                .iter()
                .map(|hydrated| hydrated.chunk.chunk_id.as_str())
                .collect::<Vec<_>>(),
            ["fleet-live-stale", "fleet-live-chunk"]
        );

        let mut archive_chunk = chunk.clone();
        archive_chunk.chunk_id = "fleet-live-archive".into();
        archive_chunk.source_id = "transcript/archive".into();
        archive_chunk.extra = serde_json::json!({"transcript_projection": "archive_parent"});
        store
            .upsert_chunk(&ScopedChunk {
                scope: scope.clone(),
                chunk: archive_chunk.clone(),
                embedding_model: "live-test".into(),
                embedding: embedding.clone(),
                stale: false,
            })
            .await
            .unwrap();
        let archive_reason: String = sqlx::query_scalar(
            "SELECT history_reason FROM memory_chunk_history \
             WHERE tenant_id = $1 AND project = $2 AND chunk_id = $3",
        )
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(&archive_chunk.chunk_id)
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(archive_reason, "archive_parent");

        let incompatible = store
            .upsert_chunk(&ScopedChunk {
                scope: scope.clone(),
                chunk: Chunk {
                    chunk_id: "fleet-live-wrong-model".into(),
                    ..chunk.clone()
                },
                embedding_model: "different-model".into(),
                embedding: embedding.clone(),
                stale: false,
            })
            .await;
        assert!(matches!(incompatible, Err(FleetError::Memory(_))));

        let wrong_source = CorpusFilter {
            source: Some("code".into()),
            ..CorpusFilter::default()
        };
        assert!(
            store
                .lexical_search_scoped("capybara", &wrong_source, 5)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            store
                .fetch_chunks_scoped(&["fleet-live-chunk".into()], &wrong_source)
                .await
                .unwrap()
                .is_empty()
        );

        let source_dense = store
            .vector_search(&embedding, &wrong_source, 5)
            .await
            .unwrap();
        assert!(source_dense.is_empty());
        let diagnosed = store
            .vector_search_diagnosed(&embedding, &wrong_source, 5)
            .await
            .unwrap();
        assert_eq!(diagnosed.mode, VectorSearchMode::SourceAnn);

        let time_filter = CorpusFilter {
            since: Some(Utc::now()),
            ..CorpusFilter::default()
        };
        assert!(
            store
                .vector_search(&embedding, &time_filter, 5)
                .await
                .is_err()
        );
        let diagnosed = store
            .vector_search_diagnosed(&embedding, &time_filter, 5)
            .await
            .unwrap();
        assert!(matches!(
            diagnosed.mode,
            VectorSearchMode::BoundedPostFilter {
                candidate_limit: 40,
                candidate_cap: FILTERED_VECTOR_CANDIDATE_CAP
            }
        ));

        for sequence in [
            "memory_claim_id_seq",
            "memory_claim_support_id_seq",
            "memory_conflict_id_seq",
            "memory_claim_link_id_seq",
        ] {
            let id: i64 = sqlx::query_scalar(&format!("SELECT nextval('{sequence}')::INT8"))
                .fetch_one(store.pool())
                .await
                .unwrap();
            assert!((1..=MAX_PUBLIC_NUMERIC_ID).contains(&id));
        }

        assert!(
            store
                .rotate_active_embedding_model("live-test", "next-model")
                .await
                .is_err()
        );

        let concurrent_scope = FleetScope::new(
            scope.tenant_id,
            "live-concurrent-model-test",
            scope.agent.clone(),
            scope.session_id.clone(),
            scope.privacy_tier,
        )
        .unwrap();
        let concurrent_store =
            CockroachStore::from_pool(store.pool().clone(), concurrent_scope.clone()).unwrap();
        sqlx::query("DELETE FROM memory_chunks WHERE tenant_id = $1 AND project = $2")
            .bind(concurrent_scope.tenant_id)
            .bind(&concurrent_scope.project)
            .execute(store.pool())
            .await
            .unwrap();
        sqlx::query("DELETE FROM memory_corpus_models WHERE tenant_id = $1 AND project = $2")
            .bind(concurrent_scope.tenant_id)
            .bind(&concurrent_scope.project)
            .execute(store.pool())
            .await
            .unwrap();
        let mut chunk_a = chunk.clone();
        chunk_a.chunk_id = "concurrent-a".into();
        chunk_a.source_id = "concurrent/a".into();
        chunk_a.project = Some(concurrent_scope.project.clone());
        let mut chunk_b = chunk_a.clone();
        chunk_b.chunk_id = "concurrent-b".into();
        chunk_b.source_id = "concurrent/b".into();
        let row_a = ScopedChunk {
            scope: concurrent_scope.clone(),
            chunk: chunk_a,
            embedding_model: "concurrent-model".into(),
            embedding: embedding.clone(),
            stale: false,
        };
        let row_b = ScopedChunk {
            scope: concurrent_scope.clone(),
            chunk: chunk_b,
            embedding_model: "concurrent-model".into(),
            embedding: embedding.clone(),
            stale: false,
        };
        let (upsert_a, upsert_b) = tokio::join!(
            concurrent_store.upsert_chunk(&row_a),
            concurrent_store.upsert_chunk(&row_b)
        );
        upsert_a.unwrap();
        upsert_b.unwrap();
        let concurrent_rows: i64 = sqlx::query_scalar(
            "SELECT count(*)::INT8 FROM memory_chunks \
             WHERE tenant_id = $1 AND project = $2",
        )
        .bind(concurrent_scope.tenant_id)
        .bind(&concurrent_scope.project)
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(concurrent_rows, 2);

        sqlx::query("DELETE FROM memory_chunks WHERE tenant_id = $1 AND project = $2")
            .bind(scope.tenant_id)
            .bind(&scope.project)
            .execute(store.pool())
            .await
            .unwrap();

        let rotation_claim_id: i64 = sqlx::query_scalar(
            "INSERT INTO memory_claims (tenant_id, project, kind, text) \
             VALUES ($1, $2, 'note', 'model rotation guard') RETURNING id",
        )
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .fetch_one(store.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO memory_claim_embeddings (\
                 tenant_id, project, claim_id, passage_index, passage_text, model, vector\
             ) VALUES ($1, $2, $3, 0, 'model rotation guard', 'live-test', $4::VECTOR(512))",
        )
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(rotation_claim_id)
        .bind(serialize_vector(&embedding).unwrap())
        .execute(store.pool())
        .await
        .unwrap();
        assert!(
            store
                .rotate_active_embedding_model("live-test", "next-model")
                .await
                .is_err(),
            "claim passage vectors must prevent generation rotation even after the corpus is empty"
        );
        sqlx::query("DELETE FROM memory_claims WHERE tenant_id = $1 AND project = $2 AND id = $3")
            .bind(scope.tenant_id)
            .bind(&scope.project)
            .bind(rotation_claim_id)
            .execute(store.pool())
            .await
            .unwrap();
        store
            .rotate_active_embedding_model("live-test", "next-model")
            .await
            .unwrap();
        let rotated_model: String = sqlx::query_scalar(READ_ACTIVE_MODEL_SQL)
            .bind(scope.tenant_id)
            .bind(&scope.project)
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(rotated_model, "next-model");
    }

    /// A one-row smoke test cannot distinguish C-SPANN from a cheap primary
    /// scan. Populate a realistic project and prove `CockroachDB` 26.2 selects
    /// the vector-search operator for the exact SQL used by production.
    #[tokio::test]
    #[allow(clippy::too_many_lines)] // one fixture proves all three retrieval index plans
    async fn live_cockroach_dense_plan_uses_vector_index_when_configured() {
        let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
            return;
        };
        let _live_database_guard = LIVE_DATABASE_TEST_LOCK.lock().await;
        // A unique project avoids a prohibitively expensive bulk delete from
        // two C-SPANN indexes when a disposable integration database is
        // reused. The environment contract already requires that database to
        // be throwaway.
        let project = format!("live-vector-plan-test-{}", Uuid::now_v7());
        let scope = scope(&project);
        let store = CockroachStore::connect(&database_url, scope.clone(), PoolConfig::default())
            .await
            .unwrap();
        store.migrate().await.unwrap();

        sqlx::query(INSERT_ACTIVE_MODEL_SQL)
            .bind(scope.tenant_id)
            .bind(&scope.project)
            .bind("live-plan-model")
            .execute(store.pool())
            .await
            .unwrap();

        let mut embedding = vec![0.0; EMBEDDING_DIMENSION];
        embedding[0] = 1.0;
        let vector = serialize_vector(&embedding).unwrap();
        sqlx::query(
            r"
INSERT INTO memory_chunks (
    tenant_id, project, chunk_id, source, source_id, source_config_id,
    chunk_index, text, content_sha256, embedding_input_sha256,
    embedding_model, embedding
)
SELECT $1, $2, 'plan-' || g::STRING, 'markdown', 'plan/' || g::STRING,
       'plan-config', g,
       CASE WHEN g = 1 THEN 'semantictalisman selective lexical sentinel'
            ELSE 'vector plan corpus row' END,
       'content-' || g::STRING,
       'input-' || g::STRING, 'live-plan-model', $3::VECTOR(512)
FROM generate_series(1, 10001) AS g
",
        )
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(&vector)
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query("ANALYZE memory_chunks")
            .execute(store.pool())
            .await
            .unwrap();

        let explain_project_sql = format!("EXPLAIN {VECTOR_SEARCH_SQL}");
        let plan = sqlx::query_scalar::<_, String>(&explain_project_sql)
            .bind(scope.tenant_id)
            .bind(&scope.project)
            .bind(&vector)
            .bind(10_i64)
            .fetch_all(store.pool())
            .await
            .unwrap()
            .join("\n")
            .to_ascii_lowercase();
        assert!(
            plan.contains("vector search"),
            "expected C-SPANN vector search, got:\n{plan}"
        );
        assert!(
            plan.contains("memory_chunks_semantic_idx"),
            "expected semantic index in plan, got:\n{plan}"
        );

        let explain_source_sql = format!("EXPLAIN {SOURCE_VECTOR_SEARCH_SQL}");
        let source_plan = sqlx::query_scalar::<_, String>(&explain_source_sql)
            .bind(scope.tenant_id)
            .bind(&scope.project)
            .bind("markdown")
            .bind(&vector)
            .bind(10_i64)
            .fetch_all(store.pool())
            .await
            .unwrap()
            .join("\n")
            .to_ascii_lowercase();
        assert!(
            source_plan.contains("vector search"),
            "expected source C-SPANN vector search, got:\n{source_plan}"
        );
        assert!(
            source_plan.contains("memory_chunks_source_semantic_idx"),
            "expected source semantic index in plan, got:\n{source_plan}"
        );

        let explain_lexical_sql = format!("EXPLAIN {LEXICAL_SEARCH_SQL}");
        let lexical_plan = sqlx::query_scalar::<_, String>(&explain_lexical_sql)
            .bind(scope.tenant_id)
            .bind(&scope.project)
            .bind("semantictalisman")
            .bind(Option::<String>::None)
            .bind(Option::<DateTime<Utc>>::None)
            .bind(Option::<DateTime<Utc>>::None)
            .bind(10_i64)
            .fetch_all(store.pool())
            .await
            .unwrap()
            .join("\n")
            .to_ascii_lowercase();
        assert!(
            lexical_plan.contains("memory_chunks_lexical_idx"),
            "expected selective lexical index plan, got:\n{lexical_plan}"
        );
    }
}
