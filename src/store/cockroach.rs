//! `CockroachDB` connection, corpus retrieval, and retry support.
//!
//! The SQL is deliberately runtime-checked. `sqlx`'s compile-time macros
//! require a live database (or checked-in offline metadata), neither of which
//! should be required to build this crate.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::time::Duration;

use crate::private_postgres::{
    MIGRATOR_POSTGRES_APPLICATION_NAME, MIGRATOR_POSTGRES_USER, PRIVATE_RUNTIME_POSTGRES_DATABASE,
    PUBLICATION_POSTGRES_APPLICATION_NAME, PUBLICATION_POSTGRES_DATABASE,
    PUBLICATION_POSTGRES_USER, PrivatePostgresSslPolicy, WRITER_POSTGRES_APPLICATION_NAME,
    WRITER_POSTGRES_USER, migrator_postgres_connect_options, publication_postgres_connect_options,
    writer_postgres_connect_options,
};
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
use sqlx::migrate::{Migrate, MigrateError, Migration, MigrationType, Migrator};
use sqlx::postgres::{PgConnectOptions, PgConnection, PgPoolOptions, PgRow};
use sqlx::{ConnectOptions, PgPool, Postgres, Row, Transaction};

/// Embedding width used by Recall's `minishlab/potion-retrieval-32M` model.
pub const EMBEDDING_DIMENSION: usize = 512;
/// Largest integer every supported JavaScript/JSON client can represent
/// without precision loss.
pub const MAX_PUBLIC_NUMERIC_ID: i64 = 9_007_199_254_740_991;
/// Oldest complete additive database schema supported by the current recall,
/// remember, conflict-projection, ingestion, and public-demo paths.
pub const MINIMUM_RECALL_SCHEMA_VERSION: i64 = 18;

/// Exact application tables reachable from public health/status/recall SQL.
///
/// This is a fixed publication contract, not a schema-wide grant request. In
/// particular it intentionally excludes every sequence, mutation/event table,
/// historical corpus table, and dynamic-control table.
pub const PUBLICATION_READ_TABLES: [&str; 8] = [
    "_sqlx_migrations",
    "memory_corpus_models",
    "memory_chunks",
    "memory_claim_embeddings",
    "memory_claim_support",
    "memory_claims",
    "memory_conflict_members",
    "memory_conflicts",
];

/// Deterministic schema resolution for all publication sessions.
///
/// `CockroachDB` renders `search_path` with a space after each comma. Keeping
/// the expected value in that canonical form makes the set-and-witness query
/// exact instead of rejecting every otherwise-correct pooled connection.
pub const PUBLICATION_SEARCH_PATH: &str = "pg_catalog, public, pg_temp";
const PUBLICATION_CURRENT_USER_SQL: &str = "SELECT pg_catalog.current_user()";
const PUBLICATION_CURRENT_DATABASE_SQL: &str = "SELECT pg_catalog.current_database()";
const PUBLICATION_CURRENT_APPLICATION_NAME_SQL: &str =
    "SELECT pg_catalog.current_setting('application_name')";
const PUBLICATION_SET_SEARCH_PATH_SQL: &str =
    "SELECT pg_catalog.set_config('search_path', $1, false)";

async fn pin_publication_session(connection: &mut PgConnection) -> sqlx::Result<()> {
    let current_user = sqlx::query_scalar::<_, String>(PUBLICATION_CURRENT_USER_SQL)
        .fetch_one(&mut *connection)
        .await?;
    if current_user != PUBLICATION_POSTGRES_USER {
        return Err(sqlx::Error::Protocol(
            "public PostgreSQL connection authenticated an unexpected principal".into(),
        ));
    }
    let current_database = sqlx::query_scalar::<_, String>(PUBLICATION_CURRENT_DATABASE_SQL)
        .fetch_one(&mut *connection)
        .await?;
    if current_database != PUBLICATION_POSTGRES_DATABASE {
        return Err(sqlx::Error::Protocol(
            "public PostgreSQL connection selected an unexpected database".into(),
        ));
    }
    let application_name =
        sqlx::query_scalar::<_, String>(PUBLICATION_CURRENT_APPLICATION_NAME_SQL)
            .fetch_one(&mut *connection)
            .await?;
    if application_name != PUBLICATION_POSTGRES_APPLICATION_NAME {
        return Err(sqlx::Error::Protocol(
            "public PostgreSQL connection did not retain its fixed application name".into(),
        ));
    }
    let search_path = sqlx::query_scalar::<_, String>(PUBLICATION_SET_SEARCH_PATH_SQL)
        .bind(PUBLICATION_SEARCH_PATH)
        .fetch_one(&mut *connection)
        .await?;
    if search_path != PUBLICATION_SEARCH_PATH {
        return Err(sqlx::Error::Protocol(
            "public PostgreSQL connection did not retain its fixed search path".into(),
        ));
    }
    Ok(())
}

/// Deterministic schema resolution for writer and migrator sessions.
pub const PRIVATE_RUNTIME_SEARCH_PATH: &str = "pg_catalog, public, pg_temp";
const PRIVATE_RUNTIME_CURRENT_USER_SQL: &str = "SELECT pg_catalog.current_user()";
const PRIVATE_RUNTIME_CURRENT_DATABASE_SQL: &str = "SELECT pg_catalog.current_database()";
const PRIVATE_RUNTIME_CURRENT_APPLICATION_NAME_SQL: &str =
    "SELECT pg_catalog.current_setting('application_name')";
const PRIVATE_RUNTIME_SET_SEARCH_PATH_SQL: &str =
    "SELECT pg_catalog.set_config('search_path', $1, false)";
const PRIVATE_RUNTIME_CURRENT_SEARCH_PATH_SQL: &str =
    "SELECT pg_catalog.current_setting('search_path')";

#[derive(Clone, Copy)]
enum PrivateRuntimeSessionIdentity {
    Writer,
    Migrator,
}

impl PrivateRuntimeSessionIdentity {
    const fn expected_user(self) -> &'static str {
        match self {
            Self::Writer => WRITER_POSTGRES_USER,
            Self::Migrator => MIGRATOR_POSTGRES_USER,
        }
    }

    const fn expected_application_name(self) -> &'static str {
        match self {
            Self::Writer => WRITER_POSTGRES_APPLICATION_NAME,
            Self::Migrator => MIGRATOR_POSTGRES_APPLICATION_NAME,
        }
    }
}

async fn pin_private_runtime_session(
    connection: &mut PgConnection,
    identity: PrivateRuntimeSessionIdentity,
) -> sqlx::Result<()> {
    let current_user = sqlx::query_scalar::<_, String>(PRIVATE_RUNTIME_CURRENT_USER_SQL)
        .fetch_one(&mut *connection)
        .await?;
    if current_user != identity.expected_user() {
        return Err(sqlx::Error::Protocol(
            "private PostgreSQL session authenticated an unexpected principal; connection details are redacted"
                .into(),
        ));
    }
    let current_database = sqlx::query_scalar::<_, String>(PRIVATE_RUNTIME_CURRENT_DATABASE_SQL)
        .fetch_one(&mut *connection)
        .await?;
    if current_database != PRIVATE_RUNTIME_POSTGRES_DATABASE {
        return Err(sqlx::Error::Protocol(
            "private PostgreSQL session selected an unexpected database; connection details are redacted"
                .into(),
        ));
    }
    let application_name =
        sqlx::query_scalar::<_, String>(PRIVATE_RUNTIME_CURRENT_APPLICATION_NAME_SQL)
            .fetch_one(&mut *connection)
            .await?;
    if application_name != identity.expected_application_name() {
        return Err(sqlx::Error::Protocol(
            "private PostgreSQL session did not retain its fixed application name; connection details are redacted"
                .into(),
        ));
    }
    sqlx::query_scalar::<_, String>(PRIVATE_RUNTIME_SET_SEARCH_PATH_SQL)
        .bind(PRIVATE_RUNTIME_SEARCH_PATH)
        .fetch_one(&mut *connection)
        .await?;
    let search_path = sqlx::query_scalar::<_, String>(PRIVATE_RUNTIME_CURRENT_SEARCH_PATH_SQL)
        .fetch_one(&mut *connection)
        .await?;
    if search_path != PRIVATE_RUNTIME_SEARCH_PATH {
        return Err(sqlx::Error::Protocol(
            "private PostgreSQL session did not retain its fixed search path; connection details are redacted"
                .into(),
        ));
    }
    Ok(())
}

const CONTIGUOUS_SCHEMA_VERSION_SQL: &str = "SELECT COALESCE(MAX(CASE \
         WHEN prefix_success AND version = ordinal THEN version \
         ELSE 0 \
       END), 0)::INT8 \
     FROM (\
       SELECT version, \
              ROW_NUMBER() OVER (ORDER BY version) AS ordinal, \
              BOOL_AND(success) OVER (\
                ORDER BY version ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW\
              ) AS prefix_success \
       FROM _sqlx_migrations\
     ) AS ordered_migrations";

const INITIAL_MIGRATION_SQL: &str = include_str!("../../migrations/0001_fleet_memory.sql");
const CLAIM_SUPPORT_CHUNK_MIGRATION_SQL: &str =
    include_str!("../../migrations/0002_claim_support_chunk_lookup.sql");
const CONTROL_EVENT_LEDGER_MIGRATION_SQL: &str =
    include_str!("../../migrations/0003_control_event_ledger.sql");
const GENESIS_REGISTRY_ACTIVATION_MIGRATION_SQL: &str =
    include_str!("../../migrations/0004_genesis_registry_activation.sql");
const CONTROL_LEDGER_INVARIANTS_MIGRATION_SQL: &str =
    include_str!("../../migrations/0005_control_ledger_invariants.sql");
const CONTROL_BOOTSTRAP_EXPLICIT_ACCEPTANCE_TIME_MIGRATION_SQL: &str =
    include_str!("../../migrations/0006_control_bootstrap_explicit_acceptance_time.sql");
const CONTROL_EPOCH_EXPLICIT_CREATION_TIME_MIGRATION_SQL: &str =
    include_str!("../../migrations/0007_control_epoch_explicit_creation_time.sql");
const CONTROL_HEAD_EXPLICIT_ADVANCE_TIME_MIGRATION_SQL: &str =
    include_str!("../../migrations/0008_control_head_explicit_advance_time.sql");
const CONTROL_EVENT_EXPLICIT_ACCEPTANCE_TIME_MIGRATION_SQL: &str =
    include_str!("../../migrations/0009_control_event_explicit_acceptance_time.sql");
const REGISTRY_GENESIS_HEAD_ROOT_INDEX_MIGRATION_SQL: &str =
    include_str!("../../migrations/0010_registry_genesis_head_root_index.sql");
const REGISTRY_GENESIS_ACTIVATION_ROOT_INDEX_MIGRATION_SQL: &str =
    include_str!("../../migrations/0011_registry_genesis_activation_root_index.sql");
const REGISTRY_TRANSITION_HISTORY_MIGRATION_SQL: &str =
    include_str!("../../migrations/0012_registry_transition_history.sql");
const REGISTRY_GENESIS_BRIDGE_CONSUMPTION_MIGRATION_SQL: &str =
    include_str!("../../migrations/0013_registry_genesis_bridge_consumption.sql");
const REGISTRY_CURRENT_HEAD_V2_MIGRATION_SQL: &str =
    include_str!("../../migrations/0014_registry_current_head_v2.sql");
const CONFLICT_DETECTOR_UNIQUENESS_MIGRATION_SQL: &str =
    include_str!("../../migrations/0015_conflict_detector_uniqueness.sql");
const CLAIM_TRANSITION_PROVENANCE_INDEX_MIGRATION_SQL: &str =
    include_str!("../../migrations/0016_claim_transition_provenance_index.sql");
const CONFLICT_DETECTOR_PROJECTION_INDEX_MIGRATION_SQL: &str =
    include_str!("../../migrations/0017_conflict_detector_projection_index.sql");
const STAGE4_EVIDENCE_LEDGER_MIGRATION_SQL: &str =
    include_str!("../../migrations/0018_stage4_evidence_ledger.sql");
const BODY_PROJECTION_MIGRATION_SQL: &str =
    include_str!("../../migrations/0019_body_projection.sql");
const COVERAGE_RUNTIME_MIGRATION_SQL: &str =
    include_str!("../../migrations/0020_coverage_runtime.sql");
const RECALL_PROJECTION_MIGRATION_SQL: &str =
    include_str!("../../migrations/0021_recall_projection.sql");
const TRANSCRIPT_CONNECTOR_MIGRATION_SQL: &str =
    include_str!("../../migrations/0022_transcript_connector.sql");

fn successor_transition_migrations() -> [Migration; 5] {
    [
        Migration::new(
            10,
            Cow::Borrowed("exact genesis registry-head root index"),
            MigrationType::Simple,
            Cow::Borrowed(REGISTRY_GENESIS_HEAD_ROOT_INDEX_MIGRATION_SQL),
            true,
        ),
        Migration::new(
            11,
            Cow::Borrowed("exact genesis registry-activation root index"),
            MigrationType::Simple,
            Cow::Borrowed(REGISTRY_GENESIS_ACTIVATION_ROOT_INDEX_MIGRATION_SQL),
            true,
        ),
        Migration::new(
            12,
            Cow::Borrowed("append-only registry transition history"),
            MigrationType::Simple,
            Cow::Borrowed(REGISTRY_TRANSITION_HISTORY_MIGRATION_SQL),
            false,
        ),
        Migration::new(
            13,
            Cow::Borrowed("one-shot genesis bridge consumption"),
            MigrationType::Simple,
            Cow::Borrowed(REGISTRY_GENESIS_BRIDGE_CONSUMPTION_MIGRATION_SQL),
            false,
        ),
        Migration::new(
            14,
            Cow::Borrowed("successor registry current head"),
            MigrationType::Simple,
            Cow::Borrowed(REGISTRY_CURRENT_HEAD_V2_MIGRATION_SQL),
            false,
        ),
    ]
}

fn post_transactional_online_migrations() -> [Migration; 7] {
    [
        Migration::new(
            15,
            Cow::Borrowed("detector-versioned conflict uniqueness"),
            MigrationType::Simple,
            Cow::Borrowed(CONFLICT_DETECTOR_UNIQUENESS_MIGRATION_SQL),
            true,
        ),
        Migration::new(
            16,
            Cow::Borrowed("exact claim-transition provenance index"),
            MigrationType::Simple,
            Cow::Borrowed(CLAIM_TRANSITION_PROVENANCE_INDEX_MIGRATION_SQL),
            true,
        ),
        Migration::new(
            17,
            Cow::Borrowed("exact conflict-detector projection index"),
            MigrationType::Simple,
            Cow::Borrowed(CONFLICT_DETECTOR_PROJECTION_INDEX_MIGRATION_SQL),
            true,
        ),
        Migration::new(
            18,
            Cow::Borrowed("stage-4 evidence ledger and writer authority"),
            MigrationType::Simple,
            Cow::Borrowed(STAGE4_EVIDENCE_LEDGER_MIGRATION_SQL),
            // Additive tables plus two online ADD COLUMN transitions on
            // schema-locked tables; CockroachDB requires DDL autocommit here.
            true,
        ),
        Migration::new(
            19,
            Cow::Borrowed("content-addressed body/occurrence/manifest projection"),
            MigrationType::Simple,
            Cow::Borrowed(BODY_PROJECTION_MIGRATION_SQL),
            // W2-BODY. Additive new tables only; online DDL like migration 0018,
            // so CockroachDB requires DDL autocommit here.
            true,
        ),
        Migration::new(
            20,
            Cow::Borrowed("coverage runtime cursors and receipts"),
            MigrationType::Simple,
            Cow::Borrowed(COVERAGE_RUNTIME_MIGRATION_SQL),
            // Additive CREATE TABLE/INDEX DDL; CockroachDB requires it outside
            // SQLx's transaction wrapper, like every other schema change here.
            true,
        ),
        Migration::new(
            21,
            Cow::Borrowed("lexical and dense recall projection"),
            MigrationType::Simple,
            Cow::Borrowed(RECALL_PROJECTION_MIGRATION_SQL),
            // W2-PROJ. Additive new tables plus an inverted and a VECTOR index;
            // CockroachDB 26.2 cannot build a vector index through its legacy
            // transactional schema changer, so this must run with DDL
            // autocommit like migration 0001.
            true,
        ),
        Migration::new(
            22,
            Cow::Borrowed("transcript connector outbox and source cursors"),
            MigrationType::Simple,
            Cow::Borrowed(TRANSCRIPT_CONNECTOR_MIGRATION_SQL),
            // W2-TRANS. Additive CREATE TABLE/INDEX DDL only; CockroachDB
            // requires it outside SQLx's transaction wrapper, like 0018-0020.
            true,
        ),
    ]
}

fn base_embedded_migrator() -> Migrator {
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
            Migration::new(
                5,
                Cow::Borrowed("unique control-event predecessors"),
                MigrationType::Simple,
                Cow::Borrowed(CONTROL_LEDGER_INVARIANTS_MIGRATION_SQL),
                // Keep each CockroachDB schema-change job in its own SQLx
                // migration so success metadata cannot cover partial DDL.
                true,
            ),
            Migration::new(
                6,
                Cow::Borrowed("explicit control-bootstrap acceptance time"),
                MigrationType::Simple,
                Cow::Borrowed(CONTROL_BOOTSTRAP_EXPLICIT_ACCEPTANCE_TIME_MIGRATION_SQL),
                true,
            ),
            Migration::new(
                7,
                Cow::Borrowed("explicit control-epoch creation time"),
                MigrationType::Simple,
                Cow::Borrowed(CONTROL_EPOCH_EXPLICIT_CREATION_TIME_MIGRATION_SQL),
                true,
            ),
            Migration::new(
                8,
                Cow::Borrowed("explicit control-head advance time"),
                MigrationType::Simple,
                Cow::Borrowed(CONTROL_HEAD_EXPLICIT_ADVANCE_TIME_MIGRATION_SQL),
                true,
            ),
            Migration::new(
                9,
                Cow::Borrowed("explicit control-event acceptance time"),
                MigrationType::Simple,
                Cow::Borrowed(CONTROL_EVENT_EXPLICIT_ACCEPTANCE_TIME_MIGRATION_SQL),
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

fn embedded_migrator() -> Migrator {
    let mut migrator = base_embedded_migrator();
    migrator
        .migrations
        .to_mut()
        .extend(successor_transition_migrations());
    migrator
        .migrations
        .to_mut()
        .extend(post_transactional_online_migrations());
    migrator
}

fn pre_transactional_embedded_migrator() -> Migrator {
    let mut migrator = embedded_migrator();
    for migration in migrator.migrations.to_mut() {
        // Recognize applied versions 12-18 during fail-closed history
        // validation, but leave them for their later transaction-policy phase.
        if migration.version >= 12 {
            migration.migration_type = MigrationType::ReversibleDown;
        }
    }
    migrator
}

fn transactional_embedded_migrator() -> Migrator {
    let mut migrator = embedded_migrator();
    for migration in migrator.migrations.to_mut() {
        // Versions 15-18 are resumable online schema changes and must wait for
        // the post-transactional phase with CockroachDB's DDL autocommit.
        if migration.version >= 15 {
            migration.migration_type = MigrationType::ReversibleDown;
        }
    }
    migrator
}

async fn validate_embedded_migration_history(connection: &mut PgConnection) -> Result<()> {
    connection.ensure_migrations_table().await?;
    if let Some(version) = connection.dirty_version().await? {
        return Err(MigrateError::Dirty(version).into());
    }

    let applied = connection.list_applied_migrations().await?;
    let embedded = embedded_migrator();
    let expected = embedded
        .migrations
        .iter()
        .map(|migration| (migration.version, migration))
        .collect::<HashMap<_, _>>();
    for applied_migration in applied {
        let Some(expected_migration) = expected.get(&applied_migration.version) else {
            return Err(MigrateError::VersionMissing(applied_migration.version).into());
        };
        if expected_migration.checksum.as_ref() != applied_migration.checksum.as_ref() {
            return Err(MigrateError::VersionMismatch(applied_migration.version).into());
        }
    }
    Ok(())
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
    /// Private staged commands with deliberately narrower contracts supply
    /// their own floors; the serving/runtime floor tracks the current public
    /// recall and conflict-projection surface.
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

    /// Connect the long-lived DML runtime as exactly `fleet_writer`.
    pub async fn connect_writer(
        database_url: &str,
        database_ssl_policy: PrivatePostgresSslPolicy,
        scope: FleetScope,
        config: PoolConfig,
    ) -> Result<Self> {
        Self::connect_private_runtime(
            database_url,
            database_ssl_policy,
            scope,
            config,
            PrivateRuntimeSessionIdentity::Writer,
        )
        .await
    }

    /// Connect the one-shot schema path as exactly `fleet_migrator`.
    pub async fn connect_migrator(
        database_url: &str,
        database_ssl_policy: PrivatePostgresSslPolicy,
        scope: FleetScope,
        config: PoolConfig,
    ) -> Result<Self> {
        Self::connect_private_runtime(
            database_url,
            database_ssl_policy,
            scope,
            config,
            PrivateRuntimeSessionIdentity::Migrator,
        )
        .await
    }

    async fn connect_private_runtime(
        database_url: &str,
        database_ssl_policy: PrivatePostgresSslPolicy,
        scope: FleetScope,
        config: PoolConfig,
        identity: PrivateRuntimeSessionIdentity,
    ) -> Result<Self> {
        scope.validate()?;
        if config.max_connections == 0 {
            return Err(FleetError::Configuration(
                "database pool max_connections must be greater than zero".into(),
            ));
        }
        let options = match identity {
            PrivateRuntimeSessionIdentity::Writer => {
                writer_postgres_connect_options(database_url, database_ssl_policy)?
            }
            PrivateRuntimeSessionIdentity::Migrator => {
                migrator_postgres_connect_options(database_url, database_ssl_policy)?
            }
        }
        .log_statements(tracing::log::LevelFilter::Debug)
        .log_slow_statements(tracing::log::LevelFilter::Warn, Duration::from_secs(1));
        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .min_connections(config.min_connections.min(config.max_connections))
            .acquire_timeout(config.acquire_timeout)
            .idle_timeout(config.idle_timeout)
            .max_lifetime(config.max_lifetime)
            .after_connect(move |connection, _metadata| {
                Box::pin(async move { pin_private_runtime_session(connection, identity).await })
            })
            .before_acquire(move |connection, _metadata| {
                Box::pin(async move {
                    pin_private_runtime_session(connection, identity).await?;
                    Ok(true)
                })
            })
            .connect_with(options)
            .await
            .map_err(|_| {
                FleetError::Database(sqlx::Error::Protocol(
                    "private PostgreSQL connection failed; connection details are redacted".into(),
                ))
            })?;
        Ok(Self { pool, scope })
    }

    /// Connect the bounded publication reader without applying migrations.
    ///
    /// Driver options are closed before the pool is constructed. Every new
    /// pooled connection then proves the authenticated principal and selected
    /// database, and pins the only admitted schema resolution order before
    /// application SQL can run.
    pub async fn connect_publication(
        database_url: &str,
        database_ssl_policy: PrivatePostgresSslPolicy,
        scope: FleetScope,
        config: PoolConfig,
    ) -> Result<Self> {
        scope.validate()?;
        if config.max_connections == 0 {
            return Err(FleetError::Configuration(
                "database pool max_connections must be greater than zero".into(),
            ));
        }
        let options = publication_postgres_connect_options(database_url, database_ssl_policy)?
            .log_statements(tracing::log::LevelFilter::Debug)
            .log_slow_statements(tracing::log::LevelFilter::Warn, Duration::from_secs(1));
        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .min_connections(config.min_connections.min(config.max_connections))
            .acquire_timeout(config.acquire_timeout)
            .idle_timeout(config.idle_timeout)
            .max_lifetime(config.max_lifetime)
            .after_connect(|connection, _metadata| {
                Box::pin(async move { pin_publication_session(connection).await })
            })
            .before_acquire(|connection, _metadata| {
                Box::pin(async move {
                    pin_publication_session(connection).await?;
                    Ok(true)
                })
            })
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
        // CockroachDB defaults `autocommit_before_ddl` to true, which would
        // commit a CREATE TABLE before SQLx inserts the matching migration
        // history row even though SQLx opened a transaction. Versions 1-11
        // require that default for online/legacy schema changes; versions
        // 12-14 require it disabled for genuinely atomic DDL plus bookkeeping.
        // Versions 15-18 return to CockroachDB's online-DDL autocommit policy
        // in a third phase after the transactional successor tables are durable.
        let mut connection = self.pool.acquire().await?;
        let migration_result: Result<()> = async {
            sqlx::query("SET autocommit_before_ddl = true")
                .execute(connection.as_mut())
                .await?;
            validate_embedded_migration_history(connection.as_mut()).await?;
            pre_transactional_embedded_migrator()
                .run(connection.as_mut())
                .await?;
            sqlx::query("SET autocommit_before_ddl = false")
                .execute(connection.as_mut())
                .await?;
            transactional_embedded_migrator()
                .run(connection.as_mut())
                .await?;
            sqlx::query("SET autocommit_before_ddl = true")
                .execute(connection.as_mut())
                .await?;
            embedded_migrator().run(connection.as_mut()).await?;
            Ok(())
        }
        .await;

        // Do not return a session with the transactional-DDL override to the
        // shared pool. If close itself fails, retain any primary migration
        // failure because it carries the actionable schema/version evidence.
        let close_result = connection.close().await.map_err(FleetError::from);
        match migration_result {
            Err(error) => Err(error),
            Ok(()) => close_result,
        }
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
        // Report only the highest uninterrupted successful prefix. A failed or
        // missing intermediate migration cannot be hidden by a later success.
        let schema_version: i64 = sqlx::query_scalar(CONTIGUOUS_SCHEMA_VERSION_SQL)
            .fetch_one(&mut *connection)
            .await?;

        Ok(DatabaseCapabilities {
            version,
            vector_index_enabled,
            lexical_index_enabled,
            conflict_membership_index_enabled,
            claim_support_chunk_index_enabled,
            cosine_distance_supported,
            schema_version,
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
    use sha2::{Digest, Sha256};
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
    fn publication_read_inventory_and_session_authority_are_exact() {
        let source = include_str!("cockroach.rs");

        assert_eq!(
            PUBLICATION_READ_TABLES,
            [
                "_sqlx_migrations",
                "memory_corpus_models",
                "memory_chunks",
                "memory_claim_embeddings",
                "memory_claim_support",
                "memory_claims",
                "memory_conflict_members",
                "memory_conflicts",
            ]
        );
        assert!(
            PUBLICATION_READ_TABLES
                .iter()
                .all(|table| !table.ends_with("_seq"))
        );
        assert_eq!(PUBLICATION_POSTGRES_USER, "fleet_publication");
        assert_eq!(
            PUBLICATION_CURRENT_USER_SQL,
            "SELECT pg_catalog.current_user()"
        );
        assert_eq!(
            PUBLICATION_CURRENT_DATABASE_SQL,
            "SELECT pg_catalog.current_database()"
        );
        assert_eq!(
            PUBLICATION_CURRENT_APPLICATION_NAME_SQL,
            "SELECT pg_catalog.current_setting('application_name')"
        );
        assert_eq!(
            PUBLICATION_SET_SEARCH_PATH_SQL,
            "SELECT pg_catalog.set_config('search_path', $1, false)"
        );
        assert_eq!(PUBLICATION_SEARCH_PATH, "pg_catalog, public, pg_temp");
        for hook in [
            ".after_connect(|connection, _metadata| {",
            ".before_acquire(|connection, _metadata| {",
        ] {
            assert!(
                source.contains(hook),
                "publication pool must retain session hook {hook}"
            );
        }
        let witness_call = ["pin_publication_session(connection)", ".await"].concat();
        assert_eq!(
            source.matches(&witness_call).count(),
            2,
            "new and reused publication connections must share the authority witness"
        );
        for authority_guard in [
            "current_user != PUBLICATION_POSTGRES_USER",
            "current_database != PUBLICATION_POSTGRES_DATABASE",
            "application_name != PUBLICATION_POSTGRES_APPLICATION_NAME",
            "search_path != PUBLICATION_SEARCH_PATH",
        ] {
            assert!(
                source.contains(authority_guard),
                "publication authority witness must retain guard {authority_guard}"
            );
        }
    }

    #[test]
    fn private_writer_and_migrator_pool_authority_is_exact() {
        let source = include_str!("cockroach.rs");

        assert_eq!(WRITER_POSTGRES_USER, "fleet_writer");
        assert_eq!(MIGRATOR_POSTGRES_USER, "fleet_migrator");
        assert_ne!(WRITER_POSTGRES_USER, MIGRATOR_POSTGRES_USER);
        assert_eq!(PRIVATE_RUNTIME_POSTGRES_DATABASE, "fleet_recall");
        assert_eq!(
            PRIVATE_RUNTIME_CURRENT_USER_SQL,
            "SELECT pg_catalog.current_user()"
        );
        assert_eq!(
            PRIVATE_RUNTIME_CURRENT_DATABASE_SQL,
            "SELECT pg_catalog.current_database()"
        );
        assert_eq!(
            PRIVATE_RUNTIME_CURRENT_APPLICATION_NAME_SQL,
            "SELECT pg_catalog.current_setting('application_name')"
        );
        assert_eq!(
            PRIVATE_RUNTIME_SET_SEARCH_PATH_SQL,
            "SELECT pg_catalog.set_config('search_path', $1, false)"
        );
        assert_eq!(
            PRIVATE_RUNTIME_CURRENT_SEARCH_PATH_SQL,
            "SELECT pg_catalog.current_setting('search_path')"
        );
        assert_eq!(PRIVATE_RUNTIME_SEARCH_PATH, "pg_catalog, public, pg_temp");
        assert!(source.contains("pub async fn connect_writer("));
        assert!(source.contains("pub async fn connect_migrator("));
        let witness_call = [
            "pin_private_runtime_session(connection, identity)",
            ".await",
        ]
        .concat();
        assert_eq!(
            source.matches(&witness_call).count(),
            2,
            "new and reused private connections must share the authority witness"
        );
        for authority_guard in [
            "current_user != identity.expected_user()",
            "current_database != PRIVATE_RUNTIME_POSTGRES_DATABASE",
            "application_name != identity.expected_application_name()",
            "search_path != PRIVATE_RUNTIME_SEARCH_PATH",
        ] {
            assert!(
                source.contains(authority_guard),
                "private authority witness must retain guard {authority_guard}"
            );
        }
        for generic_error in [
            "unexpected principal; connection details are redacted",
            "unexpected database; connection details are redacted",
            "fixed application name; connection details are redacted",
            "fixed search path; connection details are redacted",
            "private PostgreSQL connection failed; connection details are redacted",
        ] {
            assert!(source.contains(generic_error));
        }
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
            (17, MINIMUM_RECALL_SCHEMA_VERSION, false),
            (18, MINIMUM_RECALL_SCHEMA_VERSION, true),
            (19, MINIMUM_RECALL_SCHEMA_VERSION, true),
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
    fn schema_capability_requires_an_uninterrupted_successful_prefix() {
        assert!(CONTIGUOUS_SCHEMA_VERSION_SQL.contains("ROW_NUMBER() OVER (ORDER BY version)"));
        assert!(CONTIGUOUS_SCHEMA_VERSION_SQL.contains("BOOL_AND(success) OVER"));
        assert!(CONTIGUOUS_SCHEMA_VERSION_SQL.contains("version = ordinal"));
        assert!(!CONTIGUOUS_SCHEMA_VERSION_SQL.contains("MAX(version)::INT8 WHERE success"));
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
    fn committed_migration_history_one_through_eighteen_is_byte_immutable() {
        for (migration, expected_sha256) in [
            (
                INITIAL_MIGRATION_SQL,
                "3f9e52abeea37504b5c2d49f3924056985f5620767243f602cf8a2da90e759c0",
            ),
            (
                CLAIM_SUPPORT_CHUNK_MIGRATION_SQL,
                "ccd955e4baee671703ab5c60cd4bf9f64c3f6b7328843bbea9f124fc70b6e090",
            ),
            (
                CONTROL_EVENT_LEDGER_MIGRATION_SQL,
                "c81f282f0d5c19bfe6bec8891dc9662be8126a8ef6c7d9fe01517a0021f461bd",
            ),
            (
                GENESIS_REGISTRY_ACTIVATION_MIGRATION_SQL,
                "631cfca494f9b16631738acd237b3990095641c04c6bfb4eaf922df5d6cae75c",
            ),
            (
                CONTROL_LEDGER_INVARIANTS_MIGRATION_SQL,
                "edba0f35853283b2c1d8c0513afb41d7176270d9f61de12d6665adfb087fdd51",
            ),
            (
                CONTROL_BOOTSTRAP_EXPLICIT_ACCEPTANCE_TIME_MIGRATION_SQL,
                "7da6ee8bc1e32c0fce8773b4bec750f90a07ca24ae565d9a862a9563540358e6",
            ),
            (
                CONTROL_EPOCH_EXPLICIT_CREATION_TIME_MIGRATION_SQL,
                "1039393df1722688a14cb37814f3b0f4bf49829415ca929dff83a7e9ad74a71e",
            ),
            (
                CONTROL_HEAD_EXPLICIT_ADVANCE_TIME_MIGRATION_SQL,
                "904893672a282c2cb43ae2da1bbca3f536916f86326eea6814e6107ba8e44faa",
            ),
            (
                CONTROL_EVENT_EXPLICIT_ACCEPTANCE_TIME_MIGRATION_SQL,
                "c2188da4eb821a748e403def9178500f81e74098a9030c06e49b6e5c212107e8",
            ),
            (
                REGISTRY_GENESIS_HEAD_ROOT_INDEX_MIGRATION_SQL,
                "f7175b6ccbc53cb1c2464e272d9b9e737a3f12dddb5f1e9aa52f7f26fd82743d",
            ),
            (
                REGISTRY_GENESIS_ACTIVATION_ROOT_INDEX_MIGRATION_SQL,
                "7cc8007d9064e11a6f1c977b1cc64dfbe993107d8378676802e346fc5118e2bd",
            ),
            (
                REGISTRY_TRANSITION_HISTORY_MIGRATION_SQL,
                "a4355a1a0949a60722aa50a5cbb733cdcb7242d637d3f461e8195aca57dedf67",
            ),
            (
                REGISTRY_GENESIS_BRIDGE_CONSUMPTION_MIGRATION_SQL,
                "e18ad0e1ae1f068b39eabe198e359253fe4826f74929fe35daa4539e42e1f60f",
            ),
            (
                REGISTRY_CURRENT_HEAD_V2_MIGRATION_SQL,
                "87f92385b350352de665642c80a9e0008dc3e129c287718e346d3c525023357d",
            ),
            (
                CONFLICT_DETECTOR_UNIQUENESS_MIGRATION_SQL,
                "f2a9bf1e1b2a4a76f8138c29ea41d78a7571bffd9b7c9b90ed6fab68de4ad2af",
            ),
            (
                CLAIM_TRANSITION_PROVENANCE_INDEX_MIGRATION_SQL,
                "5f7367e6b42e5eaa834914ef724146694dfbb06541dfd1b67cc24a51dbcb9637",
            ),
            (
                CONFLICT_DETECTOR_PROJECTION_INDEX_MIGRATION_SQL,
                "3fc6c7cbad7cb709238236672cde66870b42b580a0553dd14b375a5ee5bf9754",
            ),
            (
                STAGE4_EVIDENCE_LEDGER_MIGRATION_SQL,
                "69110b020468aae79a4bdce21ece9a9d8c66cce7bfd5ed39288af464a1e4960b",
            ),
        ] {
            assert_eq!(format!("{:x}", Sha256::digest(migration)), expected_sha256);
        }
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
        assert_eq!(migration.matches("CREATE INDEX ").count(), 1);
        assert!(
            migration.contains("CREATE UNIQUE INDEX memory_control_bootstraps_registry_anchor_idx")
        );
        assert!(
            migration.contains("CREATE UNIQUE INDEX memory_control_events_registry_source_idx")
        );
        assert!(migration.contains("CREATE INDEX memory_control_events_consistency_stream_idx"));
        assert!(migration.contains(
            "consistency_key_digest,\n        shard,\n        committed_offset\n    ) STORING (event_id)"
        ));
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
    fn control_ledger_hardening_migrations_are_single_ordered_schema_changes() {
        let migrations = [
            CONTROL_LEDGER_INVARIANTS_MIGRATION_SQL,
            CONTROL_BOOTSTRAP_EXPLICIT_ACCEPTANCE_TIME_MIGRATION_SQL,
            CONTROL_EPOCH_EXPLICIT_CREATION_TIME_MIGRATION_SQL,
            CONTROL_HEAD_EXPLICIT_ADVANCE_TIME_MIGRATION_SQL,
            CONTROL_EVENT_EXPLICIT_ACCEPTANCE_TIME_MIGRATION_SQL,
        ];
        for migration in migrations {
            assert!(migration.starts_with("-- no-transaction\n"));
            let sql = migration
                .lines()
                .filter(|line| !line.trim_start().starts_with("--"))
                .collect::<Vec<_>>()
                .join("\n");
            assert_eq!(sql.matches(';').count(), 1);
            assert!(!sql.contains("IF NOT EXISTS"));
            assert!(!sql.contains("UPDATE "));
            assert!(!sql.contains("DELETE "));
            assert!(!sql.contains("GRANT "));
            assert!(!sql.contains("REVOKE "));
        }

        assert_eq!(
            CONTROL_LEDGER_INVARIANTS_MIGRATION_SQL
                .matches("CREATE UNIQUE INDEX ")
                .count(),
            1
        );
        assert!(
            CONTROL_LEDGER_INVARIANTS_MIGRATION_SQL
                .contains("CREATE UNIQUE INDEX memory_control_events_predecessor_unique_idx")
        );
        assert!(CONTROL_LEDGER_INVARIANTS_MIGRATION_SQL.contains(
            "ON memory_control_events (\n        tenant_id,\n        project,\n        epoch_id,\n        shard,\n        previous_chain_digest\n    )"
        ));
        for (migration, timestamp_change) in [
            (
                CONTROL_BOOTSTRAP_EXPLICIT_ACCEPTANCE_TIME_MIGRATION_SQL,
                "ALTER TABLE memory_control_bootstraps\n    ALTER COLUMN accepted_at DROP DEFAULT",
            ),
            (
                CONTROL_EPOCH_EXPLICIT_CREATION_TIME_MIGRATION_SQL,
                "ALTER TABLE memory_control_log_epochs\n    ALTER COLUMN created_at DROP DEFAULT",
            ),
            (
                CONTROL_HEAD_EXPLICIT_ADVANCE_TIME_MIGRATION_SQL,
                "ALTER TABLE memory_control_shard_heads\n    ALTER COLUMN advanced_at DROP DEFAULT",
            ),
            (
                CONTROL_EVENT_EXPLICIT_ACCEPTANCE_TIME_MIGRATION_SQL,
                "ALTER TABLE memory_control_events\n    ALTER COLUMN accepted_at DROP DEFAULT",
            ),
        ] {
            assert_eq!(migration.matches("ALTER COLUMN ").count(), 1);
            assert!(migration.contains(timestamp_change));
        }
    }

    fn assert_transactional_single_additive_schema_change(migration: &str) {
        assert!(!migration.starts_with("-- no-transaction\n"));
        let sql = migration
            .lines()
            .filter(|line| !line.trim_start().starts_with("--"))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(sql.matches(';').count(), 1);
        assert_eq!(sql.matches("CREATE ").count(), 1);
        let uppercase = sql.to_ascii_uppercase();
        for forbidden in [
            "IF NOT EXISTS",
            "INSERT ",
            "UPDATE ",
            "DELETE ",
            "ALTER ",
            "DROP ",
            "GRANT ",
            "REVOKE ",
        ] {
            assert!(!uppercase.contains(forbidden));
        }
    }

    fn assert_resumable_exact_index_migration(migration: &str, table_name: &str, index_name: &str) {
        assert!(migration.starts_with("-- no-transaction\n"));
        let sql = migration
            .lines()
            .filter(|line| !line.trim_start().starts_with("--"))
            .collect::<Vec<_>>()
            .join("\n");
        let create = format!("CREATE UNIQUE INDEX IF NOT EXISTS {index_name}");
        assert_eq!(
            sql.lines().filter(|line| line.starts_with(&create)).count(),
            1
        );
        assert_eq!(sql.matches("DO $$").count(), 1);
        assert_eq!(sql.matches("COMMIT;").count(), 1);
        assert_eq!(sql.matches("FROM pg_catalog.pg_indexes").count(), 1);
        assert!(sql.find(&create).unwrap() < sql.find("DO $$").unwrap());
        assert!(sql.find(&create).unwrap() < sql.find("COMMIT;").unwrap());
        assert!(sql.find("COMMIT;").unwrap() < sql.find("DO $$").unwrap());
        assert!(sql.contains("current_database()"));
        assert!(sql.contains(&format!("tablename = '{table_name}'")));
        assert!(sql.contains(&format!("indexname = '{index_name}'")));
        assert!(sql.contains("IF exact_index IS DISTINCT FROM true THEN"));
        assert!(sql.contains("ERRCODE = '55000'"));
        assert!(sql.contains("catalog shape mismatch"));
        let uppercase = sql.to_ascii_uppercase();
        for forbidden in [
            "INSERT ", "UPDATE ", "DELETE ", "ALTER ", "DROP ", "GRANT ", "REVOKE ",
        ] {
            assert!(!uppercase.contains(forbidden));
        }
    }

    fn assert_resumable_exact_covering_index_migration(
        migration: &str,
        table_name: &str,
        index_name: &str,
        exact_catalog_definition: &str,
    ) {
        assert!(migration.starts_with("-- no-transaction\n"));
        let sql = migration
            .lines()
            .filter(|line| !line.trim_start().starts_with("--"))
            .collect::<Vec<_>>()
            .join("\n");
        let create = format!("CREATE INDEX IF NOT EXISTS {index_name}");
        assert_eq!(
            sql.lines().filter(|line| line.starts_with(&create)).count(),
            1
        );
        assert_eq!(sql.matches("DO $$").count(), 1);
        assert_eq!(sql.matches("COMMIT;").count(), 1);
        assert_eq!(sql.matches("FROM pg_catalog.pg_indexes").count(), 1);
        assert_eq!(sql.matches("ERRCODE = '55000'").count(), 1);
        assert!(sql.find(&create).unwrap() < sql.find("COMMIT;").unwrap());
        assert!(sql.find("COMMIT;").unwrap() < sql.find("DO $$").unwrap());
        assert!(sql.contains("current_database()"));
        assert!(sql.contains(&format!("tablename = '{table_name}'")));
        assert!(sql.contains(&format!("indexname = '{index_name}'")));
        assert!(sql.contains(exact_catalog_definition));
        assert!(sql.contains("IF exact_index IS DISTINCT FROM true THEN"));
        assert!(sql.contains("catalog shape mismatch"));
        assert!(sql.contains(" STORING ("));
        assert!(!sql.contains("CREATE UNIQUE INDEX"));
        let uppercase = sql.to_ascii_uppercase();
        for forbidden in [
            "INSERT ", "UPDATE ", "DELETE ", "ALTER ", "DROP ", "GRANT ", "REVOKE ",
        ] {
            assert!(!uppercase.contains(forbidden));
        }
    }

    fn assert_resumable_conflict_detector_uniqueness_migration() {
        let migration = CONFLICT_DETECTOR_UNIQUENESS_MIGRATION_SQL;
        assert!(migration.starts_with("-- no-transaction\n"));
        let sql = migration
            .lines()
            .filter(|line| !line.trim_start().starts_with("--"))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(sql.matches("DO $$").count(), 3);
        assert_eq!(sql.matches("COMMIT;").count(), 2);
        assert_eq!(
            sql.matches(
                "CREATE UNIQUE INDEX IF NOT EXISTS memory_conflicts_scope_key_detector_unique_idx"
            )
            .count(),
            1
        );
        assert_eq!(
            sql.matches(
                "DROP INDEX IF EXISTS memory_conflicts@memory_conflicts_tenant_id_project_claim_key_key CASCADE;"
            )
            .count(),
            1
        );
        assert!(sql.contains("(tenant_id ASC, project ASC, claim_key ASC, detector ASC)'"));
        assert!(sql.contains("(tenant_id ASC, project ASC, claim_key ASC)'"));
        assert!(sql.contains(
            "(old_present AND old_exact AND NOT new_present)\n        OR (old_present AND old_exact AND new_present AND new_exact)\n        OR (NOT old_present AND new_present AND new_exact)"
        ));
        assert!(sql.contains("catalog shape mismatch before legacy drop"));
        assert!(sql.contains("detector unique index final catalog state mismatch"));
        assert_eq!(sql.matches("ERRCODE = '55000'").count(), 6);
        assert!(
            sql.find("CREATE UNIQUE INDEX IF NOT EXISTS")
                .expect("detector index creation")
                < sql
                    .find("DROP INDEX IF EXISTS")
                    .expect("legacy index removal")
        );
        let uppercase = sql.to_ascii_uppercase();
        for forbidden in [
            "INSERT ",
            "UPDATE ",
            "DELETE ",
            "ALTER ",
            "CREATE TABLE ",
            "GRANT ",
            "REVOKE ",
        ] {
            assert!(!uppercase.contains(forbidden));
        }
    }

    fn assert_exact_genesis_root_indexes() {
        assert!(
            REGISTRY_GENESIS_HEAD_ROOT_INDEX_MIGRATION_SQL.contains(
                "CREATE UNIQUE INDEX IF NOT EXISTS memory_registry_heads_genesis_root_idx"
            )
        );
        assert!(REGISTRY_GENESIS_HEAD_ROOT_INDEX_MIGRATION_SQL.contains(
            "source_event_id,\n        source_epoch_id,\n        source_shard,\n        source_committed_offset,\n        activated_at"
        ));
        assert!(
            REGISTRY_GENESIS_ACTIVATION_ROOT_INDEX_MIGRATION_SQL.contains(
                "CREATE UNIQUE INDEX IF NOT EXISTS memory_registry_activations_genesis_root_idx"
            )
        );
        assert!(REGISTRY_GENESIS_ACTIVATION_ROOT_INDEX_MIGRATION_SQL.contains(
            "profile_id,\n        profile_digest,\n        vector_manifest_digest,\n        contract_tenant_namespace,\n        contract_project_namespace,\n        effective_from"
        ));
    }

    fn assert_transition_history_schema() {
        let transitions = REGISTRY_TRANSITION_HISTORY_MIGRATION_SQL;
        assert_eq!(transitions.matches("CREATE TABLE ").count(), 1);
        assert!(transitions.contains("CREATE TABLE memory_registry_transitions"));
        assert!(transitions.contains("OPEN-HEAD-ONLY SCHEMA CONTRACT"));
        assert!(transitions.contains("canonical RegistryHeadBindingV1 preimage"));
        assert!(transitions.contains("never byte-copy the narrower legacy canonical_head"));
        assert!(
            GENESIS_REGISTRY_ACTIVATION_MIGRATION_SQL.contains("CHECK (effective_until IS NULL)")
        );
        let transition_sql = transitions
            .lines()
            .filter(|line| !line.trim_start().starts_with("--"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(!transition_sql.contains("effective_until"));
        assert!(transitions.contains("PRIMARY KEY (tenant_id, project, generation)"));
        for exact_anchor in [
            "memory_registry_transition_genesis_head_fk",
            "REFERENCES memory_registry_heads",
            "memory_registry_transition_genesis_activation_fk",
            "REFERENCES memory_registry_activations",
            "memory_registry_transition_control_source_fk",
            "REFERENCES memory_control_events",
            "memory_registry_transition_predecessor_fk",
            "REFERENCES memory_registry_transitions",
        ] {
            assert!(transitions.contains(exact_anchor));
        }
        assert!(transitions.contains("generation = 0"));
        assert!(transitions.contains("package_digest = root_package_digest"));
        assert!(transitions.contains("predecessor_generation IS NULL"));
        assert!(transitions.contains("predecessor_generation = generation - 1"));
        for required_predecessor in [
            "predecessor_generation",
            "predecessor_activation_id",
            "predecessor_package_digest",
            "predecessor_activation_policy_digest",
            "predecessor_profile_id",
            "predecessor_profile_digest",
            "predecessor_vector_manifest_digest",
            "predecessor_contract_tenant_namespace",
            "predecessor_contract_project_namespace",
            "predecessor_effective_from",
            "predecessor_accepted_at",
            "predecessor_source_event_id",
            "predecessor_source_epoch_id",
            "predecessor_source_shard",
            "predecessor_source_committed_offset",
        ] {
            assert!(transitions.contains(&format!("{required_predecessor} IS NOT NULL")));
        }
        assert!(transitions.contains("predecessor_source_committed_offset > 0"));
        assert!(transitions.contains("profile_digest = root_profile_digest"));
        assert!(
            transitions.contains("contract_project_namespace = root_contract_project_namespace")
        );
        assert_eq!(transitions.matches("BETWEEN 1 AND 1048576").count(), 7);
        assert!(!transitions.contains(" DEFAULT "));
    }

    fn assert_bridge_and_current_head_schemas() {
        let bridge = REGISTRY_GENESIS_BRIDGE_CONSUMPTION_MIGRATION_SQL;
        assert_eq!(bridge.matches("CREATE TABLE ").count(), 1);
        assert!(bridge.contains("PRIMARY KEY (tenant_id, project)"));
        assert_eq!(
            bridge
                .matches("REFERENCES memory_registry_transitions")
                .count(),
            2
        );
        assert!(bridge.contains("CHECK (from_generation = 0 AND to_generation = 1)"));
        assert!(bridge.contains("OPEN-HEAD-ONLY SCHEMA"));
        assert!(bridge.contains("consumed_at = successor_accepted_at"));
        assert!(bridge.contains("octet_length(canonical_bridge) BETWEEN 1 AND 1048576"));
        assert!(!bridge.contains(" DEFAULT "));

        let current_head = REGISTRY_CURRENT_HEAD_V2_MIGRATION_SQL;
        assert_eq!(current_head.matches("CREATE TABLE ").count(), 1);
        assert!(current_head.contains("CREATE TABLE memory_registry_current_heads_v2"));
        assert!(current_head.contains("OPEN-HEAD-ONLY SCHEMA CONTRACT"));
        assert!(current_head.contains("exact canonical RegistryHeadBindingV1 preimage"));
        assert!(current_head.contains("never the narrower legacy RegistryHeadV1 bytes"));
        assert!(current_head.contains("PRIMARY KEY (tenant_id, project)"));
        assert!(current_head.contains("memory_registry_current_head_transition_fk"));
        assert!(current_head.contains("REFERENCES memory_registry_transitions"));
        assert!(current_head.contains("CHECK (head_state = 'active')"));
        assert!(current_head.contains("octet_length(canonical_head) BETWEEN 1 AND 1048576"));
        assert!(!current_head.contains(" DEFAULT "));
    }

    #[test]
    fn successor_transition_migrations_use_recoverable_transaction_policy() {
        assert_resumable_exact_index_migration(
            REGISTRY_GENESIS_HEAD_ROOT_INDEX_MIGRATION_SQL,
            "memory_registry_heads",
            "memory_registry_heads_genesis_root_idx",
        );
        assert_resumable_exact_index_migration(
            REGISTRY_GENESIS_ACTIVATION_ROOT_INDEX_MIGRATION_SQL,
            "memory_registry_activations",
            "memory_registry_activations_genesis_root_idx",
        );
        for migration in [
            REGISTRY_TRANSITION_HISTORY_MIGRATION_SQL,
            REGISTRY_GENESIS_BRIDGE_CONSUMPTION_MIGRATION_SQL,
            REGISTRY_CURRENT_HEAD_V2_MIGRATION_SQL,
        ] {
            assert_transactional_single_additive_schema_change(migration);
        }
        assert_exact_genesis_root_indexes();
        assert_transition_history_schema();
        assert_bridge_and_current_head_schemas();
        assert_resumable_conflict_detector_uniqueness_migration();
        assert_resumable_exact_covering_index_migration(
            CLAIM_TRANSITION_PROVENANCE_INDEX_MIGRATION_SQL,
            "memory_claim_events",
            "memory_claim_events_transition_provenance_idx",
            "USING btree (tenant_id ASC, project ASC, claim_id ASC, event_kind ASC, created_at DESC, event_id DESC) STORING (reason, from_state, to_state, payload)",
        );
        assert_resumable_exact_covering_index_migration(
            CONFLICT_DETECTOR_PROJECTION_INDEX_MIGRATION_SQL,
            "memory_conflicts",
            "memory_conflicts_scope_detector_state_recency_idx",
            "USING btree (tenant_id ASC, project ASC, detector ASC, state ASC, last_seen_at DESC, id ASC) STORING (claim_key, kind, rationale, revision, detected_at, resolved_at, resolution_kind, resolution_reason)",
        );
    }

    /// Migration 0018 is the physical boundary ADR 0002 D1/D2/D5 rely on. The
    /// evidence ledger must mirror the control ledger without inheriting its
    /// governance kinds, and it must never become a second log epoch.
    #[test]
    #[allow(clippy::too_many_lines)] // one shape contract, asserted in one place
    fn stage4_evidence_ledger_migration_is_additive_bounded_and_governance_free() {
        let migration = STAGE4_EVIDENCE_LEDGER_MIGRATION_SQL;
        let tables = [
            "memory_evidence_shard_heads",
            "memory_evidence_events",
            "memory_evidence_quarantine",
            "memory_content_objects",
            "memory_relation_projection_v1",
            "memory_relation_projection_watermarks_v1",
        ];
        assert_eq!(
            migration.matches("CREATE TABLE IF NOT EXISTS ").count(),
            tables.len()
        );
        assert_eq!(migration.matches("CREATE TABLE ").count(), tables.len());
        for table in tables {
            assert!(
                migration.contains(&format!(
                    "CREATE TABLE IF NOT EXISTS {table} (\n    tenant_id"
                )),
                "{table} must be scoped by tenant_id first"
            );
        }
        assert_eq!(migration.matches("CREATE VIEW ").count(), 1);
        assert!(migration.contains("CREATE VIEW IF NOT EXISTS memory_writer_authority_v1 AS"));

        // ADR 0002 D1 amendment (2026-08-16): the evidence head table carries
        // NO foreign key at all, and no relation in this migration may target a
        // control or registry parent. CockroachDB v26.2.3 evaluates a
        // foreign-key check with the INSERTING role's privileges, so a
        // control-plane parent would make D1's lazy head seed impossible for a
        // role that D2 denies every control grant (observed SQLSTATE 42501),
        // and that grant is not durable either: control-role-grants.sql REVOKEs
        // ALL on memory_control_log_epochs FROM fleet_runtime on every reapply.
        // The events -> heads edge stays, inside the evidence plane.
        assert!(
            !migration.contains("REFERENCES memory_control_"),
            "no evidence-plane foreign key may target a control-plane table"
        );
        assert!(
            !migration.contains("REFERENCES memory_registry_"),
            "no evidence-plane foreign key may target a registry table"
        );
        // One declared foreign key (events -> heads), the closing catalog
        // assertion that pins its exact definition, and the same edge inside
        // the complete constraint-set fingerprint of memory_evidence_events.
        assert_eq!(migration.matches("FOREIGN KEY ").count(), 3);
        assert_eq!(
            migration
                .matches("        FOREIGN KEY (tenant_id, project, epoch_id, shard)\n")
                .count(),
            1
        );
        assert!(migration.contains("epoch_id                    BYTES NOT NULL"));
        assert!(migration.contains("CONSTRAINT memory_evidence_head_epoch_id_shape"));
        assert!(migration.contains("CONSTRAINT memory_evidence_head_shard_count_bound"));
        assert!(migration.contains(
            "REFERENCES memory_evidence_shard_heads (tenant_id, project, epoch_id, shard)"
        ));
        assert!(migration.contains("UNIQUE (tenant_id, project, event_id)"));
        assert!(migration.contains(
            "CREATE UNIQUE INDEX IF NOT EXISTS memory_evidence_events_predecessor_unique_idx"
        ));

        // D1: no governance kind or family can be appended to this ledger.
        for governance_kind in [
            "'control.bootstrap.accepted'",
            "'registry.genesis.activated'",
            "'registry.successor.activated'",
        ] {
            assert!(
                migration.contains(governance_kind),
                "governance exclusion must name {governance_kind}"
            );
        }
        assert!(migration.contains("event_kind NOT IN ("));
        assert!(migration.contains("consistency_family <> 'registry.activation'"));

        // D5 and REPLAY-02 shapes.
        assert!(migration.contains("retention_class IN ('ephemeral', 'governed', 'immutable')"));
        for erasure_axis in [
            "erasure_representation_digest",
            "erasure_source_fact_digest",
            "erasure_resource_digest",
            "erasure_privacy_subject_digest",
        ] {
            assert!(migration.contains(erasure_axis));
        }
        assert!(
            !migration.contains("    payload "),
            "quarantine must retain a digest and bounded diagnostic, never payload bytes"
        );
        assert!(migration.contains("octet_length(diagnostic) BETWEEN 1 AND 4096"));
        assert!(migration.contains("ledger_family IN ('control', 'evidence')"));
        assert!(migration.contains("PRIMARY KEY (tenant_id, project, ledger_family, shard)"));
        assert!(
            migration
                .contains("projection_state IN ('declared', 'verified', 'refuted', 'contested')")
        );

        // D3: the accepted-event coordinate is additive, nullable, and shaped.
        assert_eq!(migration.matches("ADD COLUMN IF NOT EXISTS ").count(), 2);
        assert_eq!(
            migration.matches("ADD CONSTRAINT IF NOT EXISTS ").count(),
            2
        );
        assert_eq!(
            migration
                .matches(
                    "CHECK (accepted_event_id IS NULL OR octet_length(accepted_event_id) = 32)"
                )
                .count(),
            2
        );

        // Additive only: no destructive verb may enter an applied migration.
        for destructive in ["DROP ", "TRUNCATE", "DELETE FROM", "UPDATE "] {
            assert!(
                !migration.contains(destructive),
                "migration 0018 must stay additive; found {destructive}"
            );
        }
        assert!(!migration.contains(" DEFAULT "));

        // Same-name drift must fail closed rather than be adopted. IF NOT
        // EXISTS alone would record a forged authority view or a quarantine
        // table carrying a payload column as a successful version 18.
        assert_eq!(migration.matches("ERRCODE = '55000'").count(), 8);
        for drift_assertion in [
            "migration 0018 same-name relation drift: ",
            "memory_writer_authority_v1 is not a view",
            "memory_writer_authority_v1 is not owned by this migrator",
            "memory_writer_authority_v1 catalog definition mismatch",
            "memory_evidence_shard_heads must carry no foreign key",
            "memory_evidence_event_head_fk does not bind the evidence shard head",
            "migration 0018 relation constraint drift: ",
            "migration 0018 accepted-event column constraint drift: ",
        ] {
            assert!(
                migration.contains(drift_assertion),
                "migration 0018 must fail closed with {drift_assertion}"
            );
        }
        for relation in tables
            .iter()
            .chain(std::iter::once(&"memory_writer_authority_v1"))
        {
            assert!(
                migration.contains(&format!("        ('{relation}',")),
                "{relation} must be covered by the same-name drift assertion"
            );
        }

        // A column-shape-only assertion is not enough: an adopted
        // memory_evidence_events with the exact fifteen columns and the exact
        // events -> heads foreign key, but WITHOUT the governance CHECK and
        // WITHOUT UNIQUE (tenant_id, project, event_id), was recorded as a
        // successful version 18 and then accepted a
        // 'registry.successor.activated' row (blocking review finding,
        // 2026-08-16). Every created relation therefore pins its COMPLETE
        // committed constraint set, ordered by (contype, name).
        assert_eq!(
            migration
                .matches("|| constraint_object.conname || ':'")
                .count(),
            1
        );
        for relation in tables {
            assert!(
                migration.contains(&format!("p:{relation}_pkey:PRIMARY KEY (")),
                "{relation} must pin its primary key in the constraint fingerprint"
            );
        }
        for constraint_fingerprint in [
            "c:memory_evidence_event_governance_exclusion:CHECK (((event_kind NOT IN (",
            "u:memory_evidence_events_tenant_id_project_event_id_key:UNIQUE (tenant_id ASC, \
             project ASC, event_id ASC)",
            "u:memory_evidence_events_predecessor_unique_idx:UNIQUE (tenant_id ASC, project ASC, \
             epoch_id ASC, shard ASC, previous_chain_digest ASC)",
            "f:memory_evidence_event_head_fk:FOREIGN KEY (tenant_id, project, epoch_id, shard)",
            "c:memory_evidence_quarantine_diagnostic_bound:",
            "c:memory_content_object_retention_class:",
            "c:memory_relation_projection_state:",
            "c:memory_relation_watermark_ledger_family:",
        ] {
            assert!(
                migration.contains(constraint_fingerprint),
                "the constraint fingerprint must pin {constraint_fingerprint}"
            );
        }
        for accepted_event_constraint in [
            "('memory_claims', 'memory_claim_accepted_event_id_shape',",
            "('memory_mutation_receipts', 'memory_mutation_receipt_accepted_event_id_shape',",
        ] {
            assert!(
                migration.contains(accepted_event_constraint),
                "the accepted-event constraint assertion must pin \
                 {accepted_event_constraint}"
            );
        }
    }

    #[test]
    fn embedded_migrator_registers_mixed_transaction_policy_through_twenty_one() {
        let migrator = embedded_migrator();
        assert_eq!(
            migrator
                .migrations
                .iter()
                .map(|migration| migration.version)
                .collect::<Vec<_>>(),
            (1..=21).collect::<Vec<_>>()
        );
        assert_eq!(
            migrator
                .migrations
                .iter()
                .map(|migration| migration.no_tx)
                .collect::<Vec<_>>(),
            [vec![true; 11], vec![false; 3], vec![true; 7]].concat()
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
        for (version, sql, expected_no_tx) in [
            (5, CONTROL_LEDGER_INVARIANTS_MIGRATION_SQL, true),
            (
                6,
                CONTROL_BOOTSTRAP_EXPLICIT_ACCEPTANCE_TIME_MIGRATION_SQL,
                true,
            ),
            (7, CONTROL_EPOCH_EXPLICIT_CREATION_TIME_MIGRATION_SQL, true),
            (8, CONTROL_HEAD_EXPLICIT_ADVANCE_TIME_MIGRATION_SQL, true),
            (
                9,
                CONTROL_EVENT_EXPLICIT_ACCEPTANCE_TIME_MIGRATION_SQL,
                true,
            ),
            (10, REGISTRY_GENESIS_HEAD_ROOT_INDEX_MIGRATION_SQL, true),
            (
                11,
                REGISTRY_GENESIS_ACTIVATION_ROOT_INDEX_MIGRATION_SQL,
                true,
            ),
            (12, REGISTRY_TRANSITION_HISTORY_MIGRATION_SQL, false),
            (13, REGISTRY_GENESIS_BRIDGE_CONSUMPTION_MIGRATION_SQL, false),
            (14, REGISTRY_CURRENT_HEAD_V2_MIGRATION_SQL, false),
            (15, CONFLICT_DETECTOR_UNIQUENESS_MIGRATION_SQL, true),
            (16, CLAIM_TRANSITION_PROVENANCE_INDEX_MIGRATION_SQL, true),
            (17, CONFLICT_DETECTOR_PROJECTION_INDEX_MIGRATION_SQL, true),
            (18, STAGE4_EVIDENCE_LEDGER_MIGRATION_SQL, true),
            (19, BODY_PROJECTION_MIGRATION_SQL, true),
            (20, COVERAGE_RUNTIME_MIGRATION_SQL, true),
            (21, RECALL_PROJECTION_MIGRATION_SQL, true),
        ] {
            let migration = migrator
                .migrations
                .iter()
                .find(|migration| migration.version == version)
                .unwrap();
            assert_eq!(migration.sql.as_ref(), sql);
            assert_eq!(migration.no_tx, expected_no_tx);
        }
        assert!(migrator.no_tx);
        assert!(!migrator.locking);
    }

    #[test]
    fn embedded_migrator_registers_three_execution_phases() {
        let pre_transactional = pre_transactional_embedded_migrator();
        assert!(!pre_transactional.ignore_missing);
        assert_eq!(
            pre_transactional
                .migrations
                .iter()
                .map(|migration| migration.version)
                .collect::<Vec<_>>(),
            (1..=21).collect::<Vec<_>>()
        );
        for version in 10..=21 {
            let migration = pre_transactional
                .migrations
                .iter()
                .find(|migration| migration.version == version)
                .unwrap();
            let expected_type = if version <= 11 {
                MigrationType::Simple
            } else {
                MigrationType::ReversibleDown
            };
            assert_eq!(migration.migration_type, expected_type);
        }

        let transactional = transactional_embedded_migrator();
        assert!(!transactional.ignore_missing);
        assert_eq!(
            transactional
                .migrations
                .iter()
                .map(|migration| migration.version)
                .collect::<Vec<_>>(),
            (1..=21).collect::<Vec<_>>()
        );
        for migration in transactional.migrations.iter() {
            let expected_type = if migration.version >= 15 {
                MigrationType::ReversibleDown
            } else {
                MigrationType::Simple
            };
            assert_eq!(migration.migration_type, expected_type);
        }
    }

    async fn assert_exact_successful_migration_prefix_through_eighteen(pool: &PgPool) {
        let actual = sqlx::query_as::<_, (i64, bool, Vec<u8>)>(
            "SELECT version, success, checksum FROM _sqlx_migrations ORDER BY version",
        )
        .fetch_all(pool)
        .await
        .unwrap();
        let expected = embedded_migrator()
            .migrations
            .iter()
            .map(|migration| {
                (
                    migration.version,
                    true,
                    migration.checksum.as_ref().to_vec(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(actual, expected);
    }

    async fn assert_online_projection_indexes_are_covering(pool: &PgPool) {
        let provenance_plan = sqlx::query_scalar::<_, String>(
            "EXPLAIN SELECT event_id, reason, from_state, to_state, payload, created_at \
             FROM memory_claim_events@memory_claim_events_transition_provenance_idx \
             WHERE tenant_id = $1 AND project = $2 AND claim_id = $3 \
               AND event_kind = $4 \
             ORDER BY created_at DESC, event_id DESC LIMIT 1",
        )
        .bind(Uuid::nil())
        .bind("online-index-plan-proof")
        .bind(1_i64)
        .bind("claim_state_changed")
        .fetch_all(pool)
        .await
        .unwrap()
        .join("\n");
        assert!(provenance_plan.contains("memory_claim_events_transition_provenance_idx"));
        assert!(!provenance_plan.contains("index join"));
        assert!(provenance_plan.contains("limit: 1"));

        let conflict_plan = sqlx::query_scalar::<_, String>(
            "EXPLAIN SELECT id, claim_key, kind, state, detector, rationale, revision, \
                    detected_at, last_seen_at, resolved_at, resolution_kind, resolution_reason \
             FROM memory_conflicts@memory_conflicts_scope_detector_state_recency_idx \
             WHERE tenant_id = $1 AND project = $2 AND detector = $3 AND state = $4 \
             ORDER BY last_seen_at DESC, id LIMIT 257",
        )
        .bind(Uuid::nil())
        .bind("online-index-plan-proof")
        .bind("same_key_typed_value_v2")
        .bind("open")
        .fetch_all(pool)
        .await
        .unwrap()
        .join("\n");
        assert!(conflict_plan.contains("memory_conflicts_scope_detector_state_recency_idx"));
        assert!(!conflict_plan.contains("index join"));
        assert!(conflict_plan.contains("limit: 257"));
    }

    /// The online index phase must recover from every catalog-only interruption,
    /// reject history drift before DDL, and finish with one exact successful
    /// migration prefix. The configured database must be disposable.
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn live_online_index_migrations_recover_and_reject_drift_when_configured() {
        let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
            return;
        };
        let _live_database_guard = LIVE_DATABASE_TEST_LOCK.lock().await;
        let store = CockroachStore::connect(
            &database_url,
            scope("live-online-index-migration-test"),
            PoolConfig::default(),
        )
        .await
        .unwrap();

        store.migrate().await.unwrap();
        assert_exact_successful_migration_prefix_through_eighteen(store.pool()).await;
        assert_online_projection_indexes_are_covering(store.pool()).await;

        // Process death after both backfills but before either SQLx history row.
        sqlx::query("DELETE FROM _sqlx_migrations WHERE version IN (16, 17)")
            .execute(store.pool())
            .await
            .unwrap();
        store.migrate().await.unwrap();
        assert_exact_successful_migration_prefix_through_eighteen(store.pool()).await;

        // Missing version 16 must be repairable even when exact version 17 is
        // already recorded, and an absent index must be rebuilt online.
        sqlx::query("DELETE FROM _sqlx_migrations WHERE version = 16")
            .execute(store.pool())
            .await
            .unwrap();
        sqlx::query("DROP INDEX memory_claim_events@memory_claim_events_transition_provenance_idx")
            .execute(store.pool())
            .await
            .unwrap();
        store.migrate().await.unwrap();
        assert_exact_successful_migration_prefix_through_eighteen(store.pool()).await;

        // The same absent-index recovery applies to the tail migration.
        sqlx::query("DELETE FROM _sqlx_migrations WHERE version = 17")
            .execute(store.pool())
            .await
            .unwrap();
        sqlx::query(
            "DROP INDEX memory_conflicts@memory_conflicts_scope_detector_state_recency_idx",
        )
        .execute(store.pool())
        .await
        .unwrap();
        store.migrate().await.unwrap();
        assert_exact_successful_migration_prefix_through_eighteen(store.pool()).await;

        for (version, table_name, index_name) in [
            (
                16_i64,
                "memory_claim_events",
                "memory_claim_events_transition_provenance_idx",
            ),
            (
                17_i64,
                "memory_conflicts",
                "memory_conflicts_scope_detector_state_recency_idx",
            ),
        ] {
            sqlx::query("DELETE FROM _sqlx_migrations WHERE version = $1")
                .bind(version)
                .execute(store.pool())
                .await
                .unwrap();
            sqlx::query(&format!("DROP INDEX {table_name}@{index_name}"))
                .execute(store.pool())
                .await
                .unwrap();
            sqlx::query(&format!(
                "CREATE INDEX {index_name} ON {table_name} (tenant_id)"
            ))
            .execute(store.pool())
            .await
            .unwrap();

            let error = store.migrate().await.unwrap_err();
            assert!(error.to_string().contains("catalog shape mismatch"));
            assert!(error.to_string().contains(&format!("migration {version}")));
            let history_count: i64 = sqlx::query_scalar(
                "SELECT count(*)::INT8 FROM _sqlx_migrations WHERE version = $1",
            )
            .bind(version)
            .fetch_one(store.pool())
            .await
            .unwrap();
            assert_eq!(history_count, 0);

            sqlx::query(&format!("DROP INDEX {table_name}@{index_name}"))
                .execute(store.pool())
                .await
                .unwrap();
            store.migrate().await.unwrap();
            assert_exact_successful_migration_prefix_through_eighteen(store.pool()).await;
        }

        sqlx::query("UPDATE _sqlx_migrations SET success = false WHERE version = 17")
            .execute(store.pool())
            .await
            .unwrap();
        let dirty_error = store.migrate().await.unwrap_err();
        assert!(matches!(
            dirty_error,
            FleetError::Migration(MigrateError::Dirty(17))
        ));
        sqlx::query("UPDATE _sqlx_migrations SET success = true WHERE version = 17")
            .execute(store.pool())
            .await
            .unwrap();

        sqlx::query(
            "INSERT INTO _sqlx_migrations \
                 (version, description, success, checksum, execution_time) \
             VALUES (19, 'unknown migration', true, $1, 0)",
        )
        .bind(vec![0_u8])
        .execute(store.pool())
        .await
        .unwrap();
        let unknown_error = store.migrate().await.unwrap_err();
        assert!(matches!(
            unknown_error,
            FleetError::Migration(MigrateError::VersionMissing(19))
        ));
        sqlx::query("DELETE FROM _sqlx_migrations WHERE version = 19")
            .execute(store.pool())
            .await
            .unwrap();

        let correct_checksum = embedded_migrator()
            .migrations
            .iter()
            .find(|migration| migration.version == 17)
            .unwrap()
            .checksum
            .as_ref()
            .to_vec();
        sqlx::query("UPDATE _sqlx_migrations SET checksum = $1 WHERE version = 17")
            .bind(vec![0_u8])
            .execute(store.pool())
            .await
            .unwrap();
        let checksum_error = store.migrate().await.unwrap_err();
        assert!(matches!(
            checksum_error,
            FleetError::Migration(MigrateError::VersionMismatch(17))
        ));
        sqlx::query("UPDATE _sqlx_migrations SET checksum = $1 WHERE version = 17")
            .bind(correct_checksum)
            .execute(store.pool())
            .await
            .unwrap();

        store.migrate().await.unwrap();
        assert_exact_successful_migration_prefix_through_eighteen(store.pool()).await;
        assert_online_projection_indexes_are_covering(store.pool()).await;
    }

    /// `SQLx` must commit each transactional successor table and its migration
    /// history row together. Reusing version 14 forces the history insert to
    /// fail after the probe DDL has executed and proves the DDL is rolled back.
    #[tokio::test]
    async fn live_transactional_migration_rolls_back_ddl_on_history_conflict_when_configured() {
        let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
            return;
        };
        let _live_database_guard = LIVE_DATABASE_TEST_LOCK.lock().await;
        let store = CockroachStore::connect(
            &database_url,
            scope("live-migration-atomicity-test"),
            PoolConfig::default(),
        )
        .await
        .unwrap();
        store.migrate().await.unwrap();
        let pooled_default: bool =
            sqlx::query_scalar("SELECT current_setting('autocommit_before_ddl')::BOOL")
                .fetch_one(store.pool())
                .await
                .unwrap();
        assert!(pooled_default);

        let probe_table = format!(
            "successor_transaction_rollback_probe_{}",
            Uuid::now_v7().to_string().replace('-', "")
        );
        let probe_sql = format!("CREATE TABLE {probe_table} (id INT8 PRIMARY KEY)");
        let migration = Migration::new(
            14,
            Cow::Borrowed("forced successor history conflict"),
            MigrationType::Simple,
            Cow::Owned(probe_sql),
            false,
        );
        let mut connection = store.pool().acquire().await.unwrap();
        sqlx::query("SET autocommit_before_ddl = false")
            .execute(connection.as_mut())
            .await
            .unwrap();
        let error = connection.as_mut().apply(&migration).await.unwrap_err();
        assert!(error.to_string().contains("duplicate key"));

        let object_count: i64 = sqlx::query_scalar(
            "SELECT count(*)::INT8 FROM information_schema.tables \
             WHERE table_schema = 'public' AND table_name = $1",
        )
        .bind(&probe_table)
        .fetch_one(connection.as_mut())
        .await
        .unwrap();
        let history_count: i64 =
            sqlx::query_scalar("SELECT count(*)::INT8 FROM _sqlx_migrations WHERE version = 14")
                .fetch_one(connection.as_mut())
                .await
                .unwrap();
        assert_eq!(object_count, 0);
        assert_eq!(history_count, 1);
        connection.close().await.unwrap();
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
