//! Connected proof for the bounded public recall identity.
//!
//! The official wrapper must provide exactly these production inputs:
//! `FLEET_RECALL_PUBLICATION_DATABASE_URL` (whose decoded username is exactly
//! `fleet_publication`), `FLEET_RECALL_TENANT_ID` (a fresh UUID),
//! `FLEET_RECALL_PROJECT` (a unique `publication-live-*` value),
//! `FLEET_RECALL_AGENT`, `FLEET_RECALL_MAX_CONNECTIONS`,
//! `FLEET_RECALL_EMBEDDING_MODEL`, `FLEET_RECALL_EMBEDDING_MODEL_PATH`, and
//! `FLEET_RECALL_EMBEDDING_MODEL_SHA256`. Local plaintext proof additionally
//! requires `FLEET_RECALL_ALLOW_INSECURE_LOCAL_DATABASE=1`. The wrapper must
//! leave `FLEET_RECALL_DATABASE_URL` and every case-insensitive `PG*` variable
//! unset. `FLEET_RECALL_PUBLICATION_TEST_ADMIN_SECRET_FILE` is a test-only path
//! whose contents are an admin setup URL using a principal distinct from
//! `fleet_publication`; that identity may seed and clean up only the unique
//! test scope.

use std::env;
use std::fs;
use std::sync::Arc;

use anyhow::{Context as _, ensure};
use ostk_fleet_recall::CockroachMemoryService;
use ostk_fleet_recall::config::PublicationConfig;
use ostk_fleet_recall::ledger::{
    CockroachClaimLedger, FUNCTIONAL_VALUE_CONFLICT_DETECTOR_V2,
    FUNCTIONAL_VALUE_CONFLICT_RATIONALE_V2,
};
use ostk_fleet_recall::private_postgres::PUBLICATION_POSTGRES_USER;
use ostk_fleet_recall::service::{FleetRecallService, RecallAction, RecallRequest, RecallResult};
use ostk_fleet_recall::store::cockroach::{
    CockroachStore, EMBEDDING_DIMENSION, PUBLICATION_READ_TABLES, PoolConfig, RetryPolicy,
};
use ostk_recall_core::ChunkEmbedder;
use serde_json::{Map, Value, json};
use sqlx::PgPool;

const ADMIN_SECRET_FILE_ENV: &str = "FLEET_RECALL_PUBLICATION_TEST_ADMIN_SECRET_FILE";
const CHUNK_ID: &str = "publication-live-chunk";
const SOURCE_CONFIG_ID: &str = "publication-live:v1";
const SOURCE_ID: &str = "publication/live.md";
const CONTENT_SHA256: &str = "3bcd6ad4093b971a4f1d75197b3c479a95c6f8200813525ee78aaebbf4c8be9d";

struct FixedEmbedder {
    model: String,
}

impl ChunkEmbedder for FixedEmbedder {
    fn dim(&self) -> usize {
        EMBEDDING_DIMENSION
    }

    fn model_id(&self) -> &str {
        &self.model
    }

    fn encode_batch(&self, texts: &[&str]) -> Vec<Vec<f32>> {
        texts.iter().map(|_| unit_vector()).collect()
    }
}

fn unit_vector() -> Vec<f32> {
    let mut vector = vec![0.0; EMBEDDING_DIMENSION];
    vector[0] = 1.0;
    vector
}

fn serialized_unit_vector() -> String {
    let mut vector = String::from("[1");
    for _ in 1..EMBEDDING_DIMENSION {
        vector.push_str(",0");
    }
    vector.push(']');
    vector
}

async fn clean_scope(pool: &PgPool, config: &PublicationConfig) -> anyhow::Result<()> {
    let scope = config.default_scope();
    let mut transaction = pool.begin().await?;
    for statement in [
        "DELETE FROM public.memory_conflict_members WHERE tenant_id = $1 AND project = $2",
        "DELETE FROM public.memory_conflicts WHERE tenant_id = $1 AND project = $2",
        "DELETE FROM public.memory_claim_support WHERE tenant_id = $1 AND project = $2",
        "DELETE FROM public.memory_claim_embeddings WHERE tenant_id = $1 AND project = $2",
        "DELETE FROM public.memory_claims WHERE tenant_id = $1 AND project = $2",
        "DELETE FROM public.memory_chunks WHERE tenant_id = $1 AND project = $2",
        "DELETE FROM public.memory_corpus_models WHERE tenant_id = $1 AND project = $2",
    ] {
        sqlx::query(statement)
            .bind(scope.tenant_id)
            .bind(&scope.project)
            .execute(&mut *transaction)
            .await?;
    }
    transaction.commit().await?;
    Ok(())
}

async fn seed_scope(pool: &PgPool, config: &PublicationConfig) -> anyhow::Result<()> {
    let model = config.embedding_model_identity();
    let vector = serialized_unit_vector();
    let mut transaction = pool.begin().await?;

    seed_corpus(&mut transaction, config, &model, &vector).await?;
    seed_claim_projection(&mut transaction, config, &model, &vector).await?;
    transaction.commit().await?;
    Ok(())
}

async fn seed_corpus(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    config: &PublicationConfig,
    model: &str,
    vector: &str,
) -> anyhow::Result<()> {
    let scope = config.default_scope();

    sqlx::query(
        "INSERT INTO public.memory_corpus_models (tenant_id, project, embedding_model) \
         VALUES ($1, $2, $3)",
    )
    .bind(scope.tenant_id)
    .bind(&scope.project)
    .bind(model)
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "INSERT INTO public.memory_chunks (\
             tenant_id, project, chunk_id, source, source_id, source_config_id, chunk_index, \
             text, content_sha256, embedding_input_sha256, embedding_model, embedding, \
             facets, links, extra\
         ) VALUES ($1, $2, $3, 'markdown', $4, $5, 0, $6, $7, $8, $9, \
                   $10::VECTOR(512), '{}'::JSONB, '{}'::JSONB, '{}'::JSONB)",
    )
    .bind(scope.tenant_id)
    .bind(&scope.project)
    .bind(CHUNK_ID)
    .bind(SOURCE_ID)
    .bind(SOURCE_CONFIG_ID)
    .bind("CockroachDB publication readers expose bounded recall without mutation authority.")
    .bind(CONTENT_SHA256)
    .bind(CONTENT_SHA256)
    .bind(model)
    .bind(vector)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn seed_claim_projection(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    config: &PublicationConfig,
    model: &str,
    vector: &str,
) -> anyhow::Result<()> {
    let scope = config.default_scope();
    let first_claim_id = insert_claim(
        transaction,
        config,
        "reader-policy",
        json!("read_only"),
        "The publication identity is read only.",
    )
    .await?;
    let second_claim_id = insert_claim(
        transaction,
        config,
        "reader-policy",
        json!("writer"),
        "The publication identity can write.",
    )
    .await?;

    for (claim_id, passage) in [
        (first_claim_id, "publication identity read only"),
        (second_claim_id, "publication identity writer"),
    ] {
        sqlx::query(
            "INSERT INTO public.memory_claim_embeddings (\
                 tenant_id, project, claim_id, passage_index, passage_text, model, vector\
             ) VALUES ($1, $2, $3, 0, $4, $5, $6::VECTOR(512))",
        )
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(claim_id)
        .bind(passage)
        .bind(model)
        .bind(vector)
        .execute(&mut **transaction)
        .await?;
    }

    sqlx::query(
        "INSERT INTO public.memory_claim_support (\
             tenant_id, project, claim_id, source_config_id, source, source_id, chunk_id, \
             content_sha256, excerpt, relation\
         ) VALUES ($1, $2, $3, $4, 'markdown', $5, $6, $7, $8, 'supports')",
    )
    .bind(scope.tenant_id)
    .bind(&scope.project)
    .bind(first_claim_id)
    .bind(SOURCE_CONFIG_ID)
    .bind(SOURCE_ID)
    .bind(CHUNK_ID)
    .bind(CONTENT_SHA256)
    .bind("publication readers expose bounded recall")
    .execute(&mut **transaction)
    .await?;

    let conflict_id: i64 = sqlx::query_scalar(
        "INSERT INTO public.memory_conflicts (\
             tenant_id, project, claim_key, detector, rationale\
         ) VALUES ($1, $2, 'reader-policy', $3, $4) RETURNING id",
    )
    .bind(scope.tenant_id)
    .bind(&scope.project)
    .bind(FUNCTIONAL_VALUE_CONFLICT_DETECTOR_V2)
    .bind(FUNCTIONAL_VALUE_CONFLICT_RATIONALE_V2)
    .fetch_one(&mut **transaction)
    .await?;
    for claim_id in [first_claim_id, second_claim_id] {
        sqlx::query(
            "INSERT INTO public.memory_conflict_members (\
                 tenant_id, project, conflict_id, claim_id\
             ) VALUES ($1, $2, $3, $4)",
        )
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(conflict_id)
        .bind(claim_id)
        .execute(&mut **transaction)
        .await?;
    }
    Ok(())
}

async fn insert_claim(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    config: &PublicationConfig,
    claim_key: &str,
    value: Value,
    text: &str,
) -> anyhow::Result<i64> {
    let scope = config.default_scope();
    Ok(sqlx::query_scalar(
        "INSERT INTO public.memory_claims (\
             tenant_id, project, kind, claim_key, subject, predicate, value, text, state, \
             origin, actor, conflict_eligible\
         ) VALUES ($1, $2, 'fact', $3, 'publication', 'database_role', $4, $5, \
                   'disputed', 'operator_asserted', $6, true) RETURNING id",
    )
    .bind(scope.tenant_id)
    .bind(&scope.project)
    .bind(claim_key)
    .bind(value)
    .bind(text)
    .bind(&scope.agent)
    .fetch_one(&mut **transaction)
    .await?)
}

async fn recall(
    service: &dyn FleetRecallService,
    config: &PublicationConfig,
    action: RecallAction,
    arguments: Map<String, Value>,
) -> anyhow::Result<RecallResult> {
    service
        .recall(
            config.default_scope().clone(),
            RecallRequest::new(action, arguments),
        )
        .await
        .map_err(anyhow::Error::msg)
}

fn require_hits(result: &RecallResult, label: &str) -> anyhow::Result<()> {
    ensure!(
        result
            .data
            .get("hits")
            .and_then(Value::as_array)
            .is_some_and(|hits| !hits.is_empty()),
        "{label} returned no hits"
    );
    Ok(())
}

fn publication_admin_url() -> anyhow::Result<String> {
    let admin_secret_file =
        env::var(ADMIN_SECRET_FILE_ENV).context(format!("{ADMIN_SECRET_FILE_ENV} is required"))?;
    let admin_url = fs::read_to_string(&admin_secret_file)
        .with_context(|| format!("read admin setup secret file {admin_secret_file}"))?;
    ensure!(
        admin_url.len() <= 16 * 1024 && !admin_url.trim().is_empty(),
        "admin setup secret file must contain one bounded URL"
    );
    Ok(admin_url.trim().to_owned())
}

async fn connect_admin_store(config: &PublicationConfig) -> anyhow::Result<CockroachStore> {
    let admin_url = publication_admin_url()?;
    let store = CockroachStore::connect(
        &admin_url,
        config.default_scope().clone(),
        PoolConfig {
            max_connections: 1,
            min_connections: 0,
            ..PoolConfig::default()
        },
    )
    .await?;
    let database: String = sqlx::query_scalar("SELECT pg_catalog.current_database()")
        .fetch_one(store.pool())
        .await?;
    ensure!(
        database == "fleet_recall",
        "admin setup URL selected the wrong database"
    );
    let current_user: String = sqlx::query_scalar("SELECT pg_catalog.current_user()")
        .fetch_one(store.pool())
        .await?;
    ensure!(
        current_user != PUBLICATION_POSTGRES_USER,
        "admin setup URL must authenticate a principal distinct from the publication reader"
    );
    Ok(store)
}

async fn build_real_publication_service(
    config: &PublicationConfig,
) -> anyhow::Result<CockroachMemoryService> {
    let store = Arc::new(
        CockroachStore::connect_publication(
            config.database_url(),
            config.database_ssl_policy(),
            config.default_scope().clone(),
            PoolConfig {
                max_connections: config.max_connections(),
                min_connections: 0,
                ..PoolConfig::default()
            },
        )
        .await?,
    );
    store.health_check().await?;
    let embedder: Arc<dyn ChunkEmbedder> = Arc::new(FixedEmbedder {
        model: config.embedding_model_identity(),
    });
    let ledger = Arc::new(CockroachClaimLedger::new(
        store.pool().clone(),
        config.default_scope().clone(),
        embedder.clone(),
        RetryPolicy::default(),
    )?);
    let service =
        CockroachMemoryService::new(config.default_scope().clone(), store, ledger, embedder)?;
    service.verify_embedding_generation().await?;
    Ok(service)
}

async fn assert_real_recall_surface(
    service: &CockroachMemoryService,
    config: &PublicationConfig,
) -> anyhow::Result<()> {
    let service: &dyn FleetRecallService = service;
    let status = recall(service, config, RecallAction::Status, Map::new()).await?;
    ensure!(
        status.data.get("status") == Some(&json!("ready")),
        "status was not ready"
    );

    let chunk = recall(
        service,
        config,
        RecallAction::Search,
        Map::from_iter([
            ("query".into(), json!("publication recall boundary")),
            ("kind".into(), json!("chunk")),
            ("limit".into(), json!(10)),
        ]),
    )
    .await?;
    require_hits(&chunk, "chunk recall")?;
    ensure!(
        !chunk.conflicts.is_empty(),
        "chunk recall omitted conflict projection"
    );

    let claim = recall(
        service,
        config,
        RecallAction::Search,
        Map::from_iter([
            ("query".into(), json!("publication identity")),
            ("kind".into(), json!("claim")),
            ("limit".into(), json!(10)),
        ]),
    )
    .await?;
    require_hits(&claim, "claim recall")?;
    ensure!(
        !claim.conflicts.is_empty(),
        "claim recall omitted conflict projection"
    );

    let conflicts = recall(service, config, RecallAction::Conflicts, Map::new()).await?;
    ensure!(
        conflicts
            .data
            .get("conflicts")
            .and_then(Value::as_array)
            .is_some_and(|rows| !rows.is_empty()),
        "conflict list returned no rows"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires the exact publication-reader live-test environment documented above"]
async fn publication_reader_executes_the_real_recall_surface() -> anyhow::Result<()> {
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
    let config = PublicationConfig::from_env()?;
    ensure!(
        config
            .default_scope()
            .project
            .starts_with("publication-live-"),
        "FLEET_RECALL_PROJECT must be a unique publication-live-* scope"
    );
    let admin_store = connect_admin_store(&config).await?;

    clean_scope(admin_store.pool(), &config).await?;
    let proof = async {
        seed_scope(admin_store.pool(), &config).await?;
        let service = build_real_publication_service(&config).await?;
        assert_real_recall_surface(&service, &config).await?;
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let cleanup = clean_scope(admin_store.pool(), &config).await;
    proof?;
    cleanup?;
    Ok(())
}
