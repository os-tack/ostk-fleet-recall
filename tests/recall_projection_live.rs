//! Connected tests for the lexical-first / dense-later recall projection
//! (W2-PROJ).
//!
//! Every `#[tokio::test]` here exercises the real `CockroachDB` runtime and runs
//! only when `FLEET_RECALL_TEST_DATABASE_URL` points at a disposable single-node
//! instance (see the fleet worker protocol section 3, `crdb-up.sh`); otherwise
//! it returns early. The pure derivation and rejection classes are covered by
//! ordinary unit tests in `src/projectors/`.
//!
//! The projection's upstream is W2-BODY's `memory_body_objects_v1`. Most tests
//! here get there the real way: seed the accepted evidence log with genuine,
//! contract-validated `EvidenceStatementV2` canonical bytes, run the body
//! projector over it, and then run the recall projectors over the body rows it
//! produced. The evidence fixture mirrors `tests/body_projection_live.rs`, which
//! is the shape the W1-EVID append seam actually stores.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sha2::{Digest as _, Sha256};
use sqlx::PgPool;
use tokio::sync::Mutex;
use uuid::Uuid;

use ostk_fleet_recall::FleetScope;
use ostk_fleet_recall::body_store::{
    BodyProjectionError, BodyProjectionRepository, CockroachBodyProjectionRepository,
    SourceContentResolver, reference_parser_key_v1,
};
use ostk_fleet_recall::memory_contracts::canonical::encode_canonical;
use ostk_fleet_recall::memory_contracts::chunk_identity::DistanceMetricV1;
use ostk_fleet_recall::memory_contracts::common::{
    AuthenticatedProjectScopeV1, CanonicalDecimal, CanonicalTimestamp, ContractId, HexBytes,
    RegistryReferenceV1, frozen_profile_reference_v1,
};
use ostk_fleet_recall::memory_contracts::digest::{
    DigestDomain, Sha256Digest, body_digest, domain_separated_digest,
};
use ostk_fleet_recall::memory_contracts::evidence::{
    ErasureScopeKind, ErasureScopeReferenceV1, GovernedContentIdentityV1, IntegrityState,
    PublicationClass, RetentionClass, VisibilityClass,
};
use ostk_fleet_recall::memory_contracts::evidence_v2::{
    EvidenceStatementV2, RegistryHeadBindingV1, RepresentationIdentityV2, RepresentationLineageV2,
    SourceFactIdentityV2, derive_representation_key_v2, derive_source_fact_id_v2,
};
use ostk_fleet_recall::memory_contracts::identity::{IdentityForm, ResourceUri};
use ostk_fleet_recall::memory_contracts::registry::RegistryHeadV1;
use ostk_fleet_recall::projectors::{
    CockroachDenseProjector, CockroachLexicalProjector, CockroachRecallReader, DenseProjector,
    EMBEDDING_DIMENSIONS, EmbeddingModelDescriptorV1, EmbeddingProvider, LexicalProjector,
    RecallProjectionError, RecallProjectionResult, RecallTierV1,
};
use ostk_fleet_recall::store::cockroach::{CockroachStore, PoolConfig, RetryPolicy};
use ostk_recall_core::PrivacyTier;

static MIGRATED: Mutex<bool> = Mutex::const_new(false);

const EVIDENCE_ACCEPTED_EVENT_KIND: &str = "evidence.accepted";

const PROJECTION_TABLES: [&str; 3] = [
    "memory_body_lexical_projection_v1",
    "memory_body_dense_projection_v1",
    "memory_recall_projection_cursors_v1",
];

// ---------------------------------------------------------------------------
// Evidence fixture (mirrors tests/body_projection_live.rs).
// ---------------------------------------------------------------------------

fn plain_sha256(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}

fn label_digest(label: &str) -> Sha256Digest {
    domain_separated_digest(DigestDomain::ResourceLocator, label.as_bytes())
}

fn reference(id: &str, version: u32) -> RegistryReferenceV1 {
    RegistryReferenceV1 {
        entry_id: ContractId::new(id).unwrap(),
        version,
        entry_digest: domain_separated_digest(
            DigestDomain::RegistryEntry,
            format!("{id}-{version}").as_bytes(),
        ),
    }
}

fn resource(form: IdentityForm, resource_kind: &str, label: &str) -> ResourceUri {
    format!(
        "urn:ostk:{}:v1:{resource_kind}:sha256:{}",
        form.as_str(),
        label_digest(label)
    )
    .parse()
    .unwrap()
}

fn registry_head_binding() -> RegistryHeadBindingV1 {
    RegistryHeadBindingV1 {
        head: RegistryHeadV1 {
            activation_id: domain_separated_digest(
                DigestDomain::RegistryActivationReceipt,
                b"activation-a",
            ),
            package_digest: domain_separated_digest(DigestDomain::RegistryPackage, b"package-a"),
            activation_policy_digest: domain_separated_digest(
                DigestDomain::RegistryEntry,
                b"activation-policy-a",
            ),
        },
        effective_from: CanonicalTimestamp::parse("2026-08-15T12:00:00.000000000Z").unwrap(),
        effective_until: None,
    }
}

fn semantic_scope() -> AuthenticatedProjectScopeV1 {
    AuthenticatedProjectScopeV1::from_trusted_context(
        ContractId::new("tenant.fixture").unwrap(),
        ContractId::new("project.fixture").unwrap(),
    )
}

fn source_fact(label: &str) -> SourceFactIdentityV2 {
    SourceFactIdentityV2 {
        schema_version: 2,
        scope: semantic_scope(),
        provider_namespace: reference("namespace.github", 1),
        provider_instance_id: resource(IdentityForm::Entity, "provider_instance", "instance-a"),
        logical_event_key: HexBytes::new(format!("ref:{label}").into_bytes()).unwrap(),
        provider_object_id: HexBytes::new(format!("obj:{label}").into_bytes()).unwrap(),
        immutable_revision: HexBytes::new(format!("commit:{label}").into_bytes()).unwrap(),
        canonical_resource_id: resource(IdentityForm::Version, "git_blob", label),
    }
}

fn representation(label: &str) -> RepresentationIdentityV2 {
    let source_fact = source_fact(label);
    let source_fact_id = derive_source_fact_id_v2(&source_fact).unwrap();
    RepresentationIdentityV2 {
        schema_version: 2,
        source_fact_id,
        registry_head: registry_head_binding(),
        connector_schema: reference("connector.github.push-v2", 2),
        evidence_schema: reference("evidence.github.push", 2),
        canonicalization_profile: frozen_profile_reference_v1(),
        provider_instance_identity_recipe: reference("identity.github.provider_instance", 1),
        canonical_resource_identity_recipe: reference("identity.github.push", 2),
        redaction_policy: reference("redaction.default", 2),
        classifier_policy: reference("classifier.default", 3),
        retention_policy: reference("retention.default", 2),
        publication_policy: reference("publication.default", 2),
        integrity_state: IntegrityState::ProviderVerified,
        visibility_class: VisibilityClass::Private,
        retention_class: RetentionClass::Governed,
        publication_class: PublicationClass::Denied,
        erasure_scopes: vec![ErasureScopeReferenceV1 {
            kind: ErasureScopeKind::SourceFact,
            target_digest: source_fact_id.digest(),
        }],
        lineage: RepresentationLineageV2::Origin,
    }
}

/// A genuine, contract-valid accepted evidence statement whose governed content
/// digest is the plain SHA-256 of `source_bytes`.
fn build_statement(label: &str, source_bytes: &[u8]) -> EvidenceStatementV2 {
    let representation = representation(label);
    let source_fact = source_fact(label);
    let source_fact_id = derive_source_fact_id_v2(&source_fact).unwrap();
    let representation_key = derive_representation_key_v2(&representation).unwrap();
    let byte_length = CanonicalDecimal::parse(source_bytes.len().to_string()).unwrap();
    EvidenceStatementV2 {
        schema_version: 2,
        event_kind: ContractId::new(EVIDENCE_ACCEPTED_EVENT_KIND).unwrap(),
        profile: representation.canonicalization_profile.clone(),
        scope: source_fact.scope.clone(),
        registry_head: representation.registry_head.clone(),
        source_fact,
        source_fact_id,
        representation: representation.clone(),
        representation_key,
        provider_actor_id: None,
        occurred_at: CanonicalTimestamp::parse("2026-08-15T12:30:00.000000000Z").unwrap(),
        observed_at: CanonicalTimestamp::parse("2026-08-15T12:30:01.000000000Z").unwrap(),
        canonical_content: GovernedContentIdentityV1 {
            protection_domain_id: ContractId::new("project.fixture").unwrap(),
            media_type: ContractId::new("text.plain").unwrap(),
            byte_length,
            content_digest: plain_sha256(source_bytes),
        },
        integrity_state: representation.integrity_state,
        visibility_class: representation.visibility_class,
        classifier_policy: representation.classifier_policy.clone(),
        retention_class: representation.retention_class,
        retention_policy: representation.retention_policy.clone(),
        erasure_scopes: representation.erasure_scopes.clone(),
        publication_class: representation.publication_class,
        publication_policy: representation.publication_policy,
    }
}

#[derive(Default)]
struct MapResolver {
    by_content_digest: HashMap<[u8; 32], Vec<u8>>,
}

#[async_trait]
impl SourceContentResolver for MapResolver {
    async fn resolve(
        &self,
        statement: &EvidenceStatementV2,
    ) -> Result<Vec<u8>, BodyProjectionError> {
        self.by_content_digest
            .get(statement.canonical_content.content_digest.as_bytes())
            .cloned()
            .ok_or(BodyProjectionError::MissingSourceContent)
    }
}

// ---------------------------------------------------------------------------
// Deterministic in-process embedding model.
// ---------------------------------------------------------------------------

fn descriptor() -> EmbeddingModelDescriptorV1 {
    EmbeddingModelDescriptorV1 {
        model_digest: domain_separated_digest(DigestDomain::RegistryEntry, b"fixture-model-v1"),
        tokenization_version: 1,
        preprocessing_version: 1,
        distance_metric: DistanceMetricV1::Cosine,
        dimensions: EMBEDDING_DIMENSIONS,
    }
}

/// Deterministic pseudo-embedding: every component is a multiple of 1/256, so
/// it is exactly representable in `f32` and survives the text round trip through
/// `CockroachDB` unchanged. Two runs over the same text produce byte-identical
/// vectors, which is what makes the replay comparison meaningful.
fn fixture_vector(text: &str) -> Vec<f32> {
    let seed = Sha256::digest(text.as_bytes());
    let mut state = u64::from_be_bytes(seed[0..8].try_into().unwrap()) | 1;
    let mut vector = Vec::with_capacity(EMBEDDING_DIMENSIONS as usize);
    for _ in 0..EMBEDDING_DIMENSIONS {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let bucket = u32::try_from((state >> 33) % 257).unwrap();
        vector.push(f32::from(u16::try_from(bucket).unwrap()) / 256.0 - 0.5);
    }
    if vector.iter().all(|component| *component == 0.0) {
        vector[0] = 1.0;
    }
    vector
}

/// The fixture model, optionally broken in one specific way.
struct FixtureProvider {
    descriptor: EmbeddingModelDescriptorV1,
    failure: Option<ProviderFailure>,
    called: AtomicBool,
}

#[derive(Debug, Clone, Copy)]
enum ProviderFailure {
    /// The model is unreachable.
    Outage,
    /// The model answers, but with a vector no index may store.
    Degenerate,
}

impl FixtureProvider {
    fn healthy() -> Arc<Self> {
        Arc::new(Self {
            descriptor: descriptor(),
            failure: None,
            called: AtomicBool::new(false),
        })
    }

    fn broken(failure: ProviderFailure) -> Arc<Self> {
        Arc::new(Self {
            descriptor: descriptor(),
            failure: Some(failure),
            called: AtomicBool::new(false),
        })
    }
}

#[async_trait]
impl EmbeddingProvider for FixtureProvider {
    fn descriptor(&self) -> &EmbeddingModelDescriptorV1 {
        &self.descriptor
    }

    async fn embed(&self, lexical_text: &str) -> RecallProjectionResult<Vec<f32>> {
        self.called.store(true, Ordering::SeqCst);
        match self.failure {
            None => Ok(fixture_vector(lexical_text)),
            Some(ProviderFailure::Outage) => Err(RecallProjectionError::EmbeddingProvider(
                "fixture model is unreachable".into(),
            )),
            Some(ProviderFailure::Degenerate) => Ok(vec![0.0_f32; EMBEDDING_DIMENSIONS as usize]),
        }
    }
}

// ---------------------------------------------------------------------------
// Harness.
// ---------------------------------------------------------------------------

const fn retry_policy() -> RetryPolicy {
    RetryPolicy {
        max_attempts: 16,
        initial_backoff: std::time::Duration::from_millis(1),
        max_backoff: std::time::Duration::from_millis(60),
    }
}

fn physical_scope(project: &str) -> FleetScope {
    FleetScope::new(
        Uuid::now_v7(),
        project.to_string(),
        "recall-projection-connected-test",
        None,
        PrivacyTier::T1Project,
    )
    .expect("connected-test scope must be valid")
}

async fn live_pool(database_url: &str, scope: FleetScope) -> PgPool {
    let store = CockroachStore::connect(
        database_url,
        scope,
        PoolConfig {
            max_connections: 8,
            ..PoolConfig::default()
        },
    )
    .await
    .expect("connected test must reach the disposable database");
    {
        let mut migrated = MIGRATED.lock().await;
        if !*migrated {
            store.migrate().await.expect("migration prefix must apply");
            *migrated = true;
        }
    }
    store.pool().clone()
}

/// Seed a single-shard evidence log with genuine accepted-evidence canonical
/// bytes.
async fn seed_evidence_log(
    pool: &PgPool,
    tenant_id: Uuid,
    project: &str,
    statements: &[EvidenceStatementV2],
) {
    let epoch_id = vec![0x5a_u8; 32];
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT pg_catalog.statement_timestamp()")
        .fetch_one(pool)
        .await
        .unwrap();
    let event_count = i64::try_from(statements.len()).unwrap();
    sqlx::query(
        "INSERT INTO public.memory_evidence_shard_heads (\
             tenant_id, project, epoch_id, shard, shard_count, last_committed_offset, \
             chain_digest, advanced_at) VALUES ($1,$2,$3,0,1,$4,$5,$6)",
    )
    .bind(tenant_id)
    .bind(project)
    .bind(&epoch_id)
    .bind(event_count)
    .bind(vec![0x11_u8; 32])
    .bind(now)
    .execute(pool)
    .await
    .unwrap();

    for (index, statement) in statements.iter().enumerate() {
        let offset = i64::try_from(index + 1).unwrap();
        let canonical = encode_canonical(statement).unwrap();
        let event_id = statement
            .accepted_event_id()
            .unwrap()
            .digest()
            .as_bytes()
            .to_vec();
        let position = u8::try_from(index & 0xff).unwrap();
        let mut previous_chain = vec![0x22_u8; 32];
        previous_chain[0] = position;
        let mut chain = vec![0x33_u8; 32];
        chain[0] = 0x80 | position;
        sqlx::query(
            "INSERT INTO public.memory_evidence_events (\
                 tenant_id, project, epoch_id, shard, committed_offset, event_id, \
                 event_schema_version, event_kind, semantic_object_digest, consistency_family, \
                 consistency_key_digest, canonical_event, previous_chain_digest, chain_digest, \
                 accepted_at) \
                 VALUES ($1,$2,$3,0,$4,$5,2,$6,$7,'source_fact',$8,$9,$10,$11,$12)",
        )
        .bind(tenant_id)
        .bind(project)
        .bind(&epoch_id)
        .bind(offset)
        .bind(&event_id)
        .bind(EVIDENCE_ACCEPTED_EVENT_KIND)
        .bind(statement.representation_key.digest().as_bytes().to_vec())
        .bind(statement.source_fact_id.digest().as_bytes().to_vec())
        .bind(&canonical)
        .bind(previous_chain)
        .bind(chain)
        .bind(now)
        .execute(pool)
        .await
        .unwrap();
    }
}

/// Seed the body plane the real way: genuine evidence events, projected by
/// W2-BODY's own projector.
async fn seed_body_plane(pool: &PgPool, tenant_id: Uuid, project: &str, sources: &[&[u8]]) {
    let mut resolver = MapResolver::default();
    let mut statements = Vec::with_capacity(sources.len());
    for (index, source) in sources.iter().enumerate() {
        resolver
            .by_content_digest
            .insert(*plain_sha256(source).as_bytes(), (*source).to_vec());
        statements.push(build_statement(&format!("src-{index}"), source));
    }
    seed_evidence_log(pool, tenant_id, project, &statements).await;

    let bodies = CockroachBodyProjectionRepository::new(
        pool.clone(),
        tenant_id,
        project.to_string(),
        reference_parser_key_v1(),
        Arc::new(resolver),
        retry_policy(),
    );
    bodies.project_pending().await.unwrap();
}

/// Append one more content-addressed body directly, standing in for a later
/// evidence event landing while the projectors are already running.
async fn append_body(pool: &PgPool, tenant_id: Uuid, project: &str, body_bytes: &[u8]) {
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT pg_catalog.statement_timestamp()")
        .fetch_one(pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO public.memory_body_objects_v1 (\
             tenant_id, project, content_sha256, byte_length, body_bytes, media_type, \
             protection_domain_id, first_accepted_event_id, created_at) \
             VALUES ($1,$2,$3,$4,$5,'text.plain','project.fixture',$6,$7)",
    )
    .bind(tenant_id)
    .bind(project)
    .bind(body_digest(body_bytes).as_bytes().to_vec())
    .bind(i64::try_from(body_bytes.len()).unwrap())
    .bind(body_bytes.to_vec())
    .bind(vec![0x66_u8; 32])
    .bind(now)
    .execute(pool)
    .await
    .unwrap();
}

fn lexical_projector(pool: &PgPool, tenant_id: Uuid, project: &str) -> CockroachLexicalProjector {
    CockroachLexicalProjector::new(
        pool.clone(),
        tenant_id,
        project.to_string(),
        2,
        retry_policy(),
    )
}

fn dense_projector(
    pool: &PgPool,
    tenant_id: Uuid,
    project: &str,
    provider: Arc<FixtureProvider>,
) -> CockroachDenseProjector {
    CockroachDenseProjector::new(
        pool.clone(),
        tenant_id,
        project.to_string(),
        provider,
        2,
        retry_policy(),
    )
}

fn reader(pool: &PgPool, tenant_id: Uuid, project: &str) -> CockroachRecallReader {
    CockroachRecallReader::new(pool.clone(), tenant_id, project.to_string())
}

async fn count(pool: &PgPool, table: &str, tenant_id: Uuid, project: &str) -> i64 {
    let sql = format!("SELECT count(*) FROM public.{table} WHERE tenant_id = $1 AND project = $2");
    sqlx::query_scalar(&sql)
        .bind(tenant_id)
        .bind(project)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn clear_projections(pool: &PgPool, tenant_id: Uuid, project: &str) {
    for table in PROJECTION_TABLES {
        let sql = format!("DELETE FROM public.{table} WHERE tenant_id = $1 AND project = $2");
        sqlx::query(&sql)
            .bind(tenant_id)
            .bind(project)
            .execute(pool)
            .await
            .unwrap();
    }
}

/// Two paragraphs each, so the reference parser yields several distinct bodies
/// with disjoint vocabulary.
const SOURCE_A: &[u8] =
    b"the selective capybara tends a semantic orchard\n\nbeta paragraph about aqueducts";
const SOURCE_B: &[u8] = b"unrelated marmalade of tessellated basalt\n\nsecond marmalade paragraph";

// ---------------------------------------------------------------------------
// DoD 1: bodies become lexically searchable with no embedding present.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn body_rows_become_lexically_searchable_without_any_embedding() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let project = format!("lex-{}", Uuid::now_v7());
    let scope = physical_scope(&project);
    let tenant_id = scope.tenant_id;
    let pool = live_pool(&database_url, scope).await;
    seed_body_plane(&pool, tenant_id, &project, &[SOURCE_A, SOURCE_B]).await;

    let bodies = count(&pool, "memory_body_objects_v1", tenant_id, &project).await;
    assert!(bodies >= 4, "fixture must produce several bodies");

    let projector = lexical_projector(&pool, tenant_id, &project);
    let summary = projector.project_pending().await.unwrap();
    assert_eq!(i64::try_from(summary.bodies_consumed).unwrap(), bodies);
    assert_eq!(i64::try_from(summary.rows_indexed).unwrap(), bodies);
    assert_eq!(summary.rows_unindexable, 0);

    // No dense worker has ever run in this scope.
    assert_eq!(
        count(
            &pool,
            "memory_body_dense_projection_v1",
            tenant_id,
            &project
        )
        .await,
        0
    );

    let reader = reader(&pool, tenant_id, &project);
    let result = reader.recall("capybara orchard", None, 10).await.unwrap();
    assert_eq!(result.tier, RecallTierV1::Lexical);
    assert!(!result.hits.is_empty(), "lexical lane must answer");
    assert!(result.hits.iter().all(|hit| hit.lexical_score.is_some()));
    assert!(result.hits.iter().all(|hit| hit.dense_distance.is_none()));

    // Readiness says exactly what answered: lexical complete, dense empty.
    assert!(result.completeness.lexical_complete());
    assert!(!result.completeness.dense_complete());
    assert_eq!(result.completeness.densely_embedded, 0);
    assert_eq!(
        i64::try_from(result.completeness.bodies_total).unwrap(),
        bodies
    );

    // The lexical cursor advanced with the rows it wrote.
    let cursor = projector.read_cursor().await.unwrap().unwrap();
    assert_eq!(i64::try_from(cursor.bodies_projected).unwrap(), bodies);

    // A second pass consumes nothing.
    let again = projector.project_pending().await.unwrap();
    assert_eq!(again.bodies_consumed, 0);
}

// ---------------------------------------------------------------------------
// DoD 2: the dense worker backfills later and dense search then works.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_dense_worker_backfills_later_and_dense_search_then_works() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let project = format!("dense-{}", Uuid::now_v7());
    let scope = physical_scope(&project);
    let tenant_id = scope.tenant_id;
    let pool = live_pool(&database_url, scope).await;
    seed_body_plane(&pool, tenant_id, &project, &[SOURCE_A, SOURCE_B]).await;

    lexical_projector(&pool, tenant_id, &project)
        .project_pending()
        .await
        .unwrap();
    let reader = reader(&pool, tenant_id, &project);

    // Before the dense worker: a query vector finds nothing dense.
    let probe = fixture_vector("the selective capybara tends a semantic orchard");
    let before = reader.recall("capybara", Some(&probe), 10).await.unwrap();
    assert_eq!(before.tier, RecallTierV1::Lexical);
    assert!(!before.completeness.dense_complete());

    let dense = dense_projector(&pool, tenant_id, &project, FixtureProvider::healthy());
    let summary = dense.embed_pending().await.unwrap();
    assert!(summary.rows_indexed > 0);

    let after = reader.recall("capybara", Some(&probe), 10).await.unwrap();
    assert_eq!(after.tier, RecallTierV1::Hybrid);
    assert!(after.completeness.dense_complete());
    // The exact body whose text was embedded is the nearest dense neighbour.
    let nearest = reader.recall("", Some(&probe), 1).await.unwrap();
    assert_eq!(nearest.tier, RecallTierV1::Dense);
    assert_eq!(nearest.hits.len(), 1);
    let nearest_hit = &nearest.hits[0];
    assert_eq!(
        nearest_hit.body_content_id,
        body_digest(b"the selective capybara tends a semantic orchard")
    );
    assert!(nearest_hit.dense_distance.unwrap() < 1e-5);

    // The dense cursor is its OWN row: advancing it did not disturb lexical.
    let lexical_cursor = lexical_projector(&pool, tenant_id, &project)
        .read_cursor()
        .await
        .unwrap()
        .unwrap();
    let dense_cursor = dense.read_cursor().await.unwrap().unwrap();
    assert_eq!(
        lexical_cursor.bodies_projected,
        dense_cursor.bodies_projected
    );
    assert_eq!(lexical_cursor.position, dense_cursor.position);
    assert_ne!(lexical_cursor.projector, dense_cursor.projector);
}

// ---------------------------------------------------------------------------
// DoD 3: killing the dense worker mid-batch.
// ---------------------------------------------------------------------------

#[tokio::test]
// One linear scenario: catch both tiers up, land a new body, kill the dense
// batch, then check every consequence. Splitting it would hide the ordering the
// assertions depend on.
#[allow(clippy::too_many_lines)]
async fn killing_the_dense_worker_mid_batch_leaves_lexical_intact_and_the_dense_cursor_consistent()
{
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let project = format!("kill-{}", Uuid::now_v7());
    let scope = physical_scope(&project);
    let tenant_id = scope.tenant_id;
    let pool = live_pool(&database_url, scope).await;
    seed_body_plane(&pool, tenant_id, &project, &[SOURCE_A, SOURCE_B]).await;

    let lexical = lexical_projector(&pool, tenant_id, &project);
    lexical.project_pending().await.unwrap();
    let lexical_rows = count(
        &pool,
        "memory_body_lexical_projection_v1",
        tenant_id,
        &project,
    )
    .await;
    let lexical_cursor_before = lexical.read_cursor().await.unwrap().unwrap();

    let dense = dense_projector(&pool, tenant_id, &project, FixtureProvider::healthy());
    // Catch the dense tier up first, so there IS durable dense progress to
    // compare against after the kill.
    dense.embed_pending().await.unwrap();
    let dense_rows_before = count(
        &pool,
        "memory_body_dense_projection_v1",
        tenant_id,
        &project,
    )
    .await;
    let dense_cursor_before = dense.read_cursor().await.unwrap().unwrap();
    assert!(dense_rows_before > 0);

    // A new body lands and is lexically projected — available immediately.
    append_body(
        &pool,
        tenant_id,
        &project,
        b"a late arriving marmalade paragraph",
    )
    .await;
    lexical.project_pending().await.unwrap();
    let lexical_rows_after_arrival = count(
        &pool,
        "memory_body_lexical_projection_v1",
        tenant_id,
        &project,
    )
    .await;
    assert_eq!(lexical_rows_after_arrival, lexical_rows + 1);
    let lexical_cursor_after_arrival = lexical.read_cursor().await.unwrap().unwrap();

    // The dense worker starts that batch and is killed mid-flight: the batch's
    // rows AND its cursor advance are one transaction, so both vanish together.
    let killed = dense.probe_apply_first_batch_then_rollback().await.unwrap();
    assert!(killed, "there must be a pending batch to kill");

    // Lexical is untouched in every respect, including the body that arrived
    // after the last committed dense batch.
    assert_eq!(
        count(
            &pool,
            "memory_body_lexical_projection_v1",
            tenant_id,
            &project
        )
        .await,
        lexical_rows_after_arrival
    );
    assert_eq!(
        lexical.read_cursor().await.unwrap().unwrap(),
        lexical_cursor_after_arrival
    );
    assert_ne!(lexical_cursor_before, lexical_cursor_after_arrival);
    let reader = reader(&pool, tenant_id, &project);
    let result = reader
        .recall("late arriving marmalade", None, 10)
        .await
        .unwrap();
    assert_eq!(result.tier, RecallTierV1::Lexical);
    assert!(
        !result.hits.is_empty(),
        "the new body is searchable already"
    );

    // The dense tier is exactly where its last COMMITTED batch left it, and the
    // dense cursor names a body whose dense row is durably present.
    assert_eq!(
        count(
            &pool,
            "memory_body_dense_projection_v1",
            tenant_id,
            &project
        )
        .await,
        dense_rows_before
    );
    let dense_cursor = dense.read_cursor().await.unwrap().unwrap();
    assert_eq!(dense_cursor, dense_cursor_before);
    let cursor_row_present: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.memory_body_dense_projection_v1 \
         WHERE tenant_id = $1 AND project = $2 AND body_content_id = $3",
    )
    .bind(tenant_id)
    .bind(&project)
    .bind(dense_cursor.position.content_id.as_bytes().to_vec())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        cursor_row_present, 1,
        "the dense cursor must never name a body whose row was not committed"
    );

    // And resuming finishes the job.
    dense.embed_pending().await.unwrap();
    assert!(reader.completeness().await.unwrap().dense_complete());
}

/// A provider outage aborts the dense batch and reaches nothing else.
#[tokio::test]
async fn a_failing_embedding_provider_never_removes_lexical_availability() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let project = format!("outage-{}", Uuid::now_v7());
    let scope = physical_scope(&project);
    let tenant_id = scope.tenant_id;
    let pool = live_pool(&database_url, scope).await;
    seed_body_plane(&pool, tenant_id, &project, &[SOURCE_A]).await;

    let lexical = lexical_projector(&pool, tenant_id, &project);
    lexical.project_pending().await.unwrap();
    let lexical_rows = count(
        &pool,
        "memory_body_lexical_projection_v1",
        tenant_id,
        &project,
    )
    .await;
    let lexical_cursor = lexical.read_cursor().await.unwrap().unwrap();

    let broken = dense_projector(
        &pool,
        tenant_id,
        &project,
        FixtureProvider::broken(ProviderFailure::Outage),
    );
    assert!(matches!(
        broken.embed_pending().await,
        Err(RecallProjectionError::EmbeddingProvider(_))
    ));

    // No dense row, no dense cursor, and the lexical tier is untouched.
    assert_eq!(
        count(
            &pool,
            "memory_body_dense_projection_v1",
            tenant_id,
            &project
        )
        .await,
        0
    );
    assert!(broken.read_cursor().await.unwrap().is_none());
    assert_eq!(
        count(
            &pool,
            "memory_body_lexical_projection_v1",
            tenant_id,
            &project
        )
        .await,
        lexical_rows
    );
    assert_eq!(
        lexical.read_cursor().await.unwrap().unwrap(),
        lexical_cursor
    );

    let reader = reader(&pool, tenant_id, &project);
    let result = reader.recall("capybara orchard", None, 10).await.unwrap();
    assert_eq!(result.tier, RecallTierV1::Lexical);
    assert!(!result.hits.is_empty());
    assert!(result.completeness.lexical_complete());

    // A later healthy worker still catches up: the failure left no poison.
    dense_projector(&pool, tenant_id, &project, FixtureProvider::healthy())
        .embed_pending()
        .await
        .unwrap();
    assert!(reader.completeness().await.unwrap().dense_complete());
}

/// A model that answers with a vector no index may store is refused, and the
/// refusal is contained to the dense tier.
#[tokio::test]
async fn a_degenerate_provider_vector_is_refused_and_writes_no_dense_row() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let project = format!("degenerate-{}", Uuid::now_v7());
    let scope = physical_scope(&project);
    let tenant_id = scope.tenant_id;
    let pool = live_pool(&database_url, scope).await;
    seed_body_plane(&pool, tenant_id, &project, &[SOURCE_A]).await;

    lexical_projector(&pool, tenant_id, &project)
        .project_pending()
        .await
        .unwrap();

    let broken = dense_projector(
        &pool,
        tenant_id,
        &project,
        FixtureProvider::broken(ProviderFailure::Degenerate),
    );
    assert!(matches!(
        broken.embed_pending().await,
        Err(RecallProjectionError::DegenerateEmbedding)
    ));
    assert_eq!(
        count(
            &pool,
            "memory_body_dense_projection_v1",
            tenant_id,
            &project
        )
        .await,
        0
    );
    assert!(broken.read_cursor().await.unwrap().is_none());
    assert!(
        reader(&pool, tenant_id, &project)
            .completeness()
            .await
            .unwrap()
            .lexical_complete()
    );
}

// ---------------------------------------------------------------------------
// DoD 4: replay from the body tables rebuilds byte-identical projections.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn replay_from_the_body_tables_rebuilds_byte_identical_projections() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let project = format!("replay-{}", Uuid::now_v7());
    let scope = physical_scope(&project);
    let tenant_id = scope.tenant_id;
    let pool = live_pool(&database_url, scope).await;
    seed_body_plane(&pool, tenant_id, &project, &[SOURCE_A, SOURCE_B]).await;

    let lexical = lexical_projector(&pool, tenant_id, &project);
    let dense = dense_projector(&pool, tenant_id, &project, FixtureProvider::healthy());
    let reader = reader(&pool, tenant_id, &project);

    lexical.project_pending().await.unwrap();
    dense.embed_pending().await.unwrap();
    let first = reader.snapshot().await.unwrap();
    assert!(!first.lexical.is_empty());
    assert!(!first.dense.is_empty());

    // Wipe both tiers and both cursors; rebuild from the body tables alone.
    clear_projections(&pool, tenant_id, &project).await;
    assert!(reader.snapshot().await.unwrap().lexical.is_empty());
    lexical.reproject_all().await.unwrap();
    dense.reembed_all().await.unwrap();
    let second = reader.snapshot().await.unwrap();
    assert_eq!(first, second);

    // Re-running over an already-complete projection changes nothing either.
    lexical.reproject_all().await.unwrap();
    dense.reembed_all().await.unwrap();
    assert_eq!(reader.snapshot().await.unwrap(), second);
}

/// The lexical batch's rows and its cursor advance are one transaction.
#[tokio::test]
async fn the_lexical_cursor_advances_atomically_with_its_rows() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let project = format!("atomic-{}", Uuid::now_v7());
    let scope = physical_scope(&project);
    let tenant_id = scope.tenant_id;
    let pool = live_pool(&database_url, scope).await;
    seed_body_plane(&pool, tenant_id, &project, &[SOURCE_A]).await;

    let lexical = lexical_projector(&pool, tenant_id, &project);
    assert!(
        lexical
            .probe_apply_first_batch_then_rollback()
            .await
            .unwrap()
    );
    // Rolled back together: no rows, no cursor.
    assert_eq!(
        count(
            &pool,
            "memory_body_lexical_projection_v1",
            tenant_id,
            &project
        )
        .await,
        0
    );
    assert!(lexical.read_cursor().await.unwrap().is_none());
}

// ---------------------------------------------------------------------------
// Security boundary: identity, scope, and the private/public plane split.
// ---------------------------------------------------------------------------

/// A body row whose stored bytes do not reproduce its content address fails the
/// projection closed, writes no lexical row, and leaves the cursor unadvanced.
#[tokio::test]
async fn a_body_row_whose_bytes_do_not_match_its_address_fails_the_projection_closed() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let project = format!("tamper-{}", Uuid::now_v7());
    let scope = physical_scope(&project);
    let tenant_id = scope.tenant_id;
    let pool = live_pool(&database_url, scope).await;

    // Address of "alpha", bytes of "gamma" — same length, so the body table's
    // own length CHECK cannot catch the swap. Only the content address can.
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT pg_catalog.statement_timestamp()")
        .fetch_one(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO public.memory_body_objects_v1 (\
             tenant_id, project, content_sha256, byte_length, body_bytes, media_type, \
             protection_domain_id, first_accepted_event_id, created_at) \
             VALUES ($1,$2,$3,5,$4,'text.plain','project.fixture',$5,$6)",
    )
    .bind(tenant_id)
    .bind(&project)
    .bind(body_digest(b"alpha").as_bytes().to_vec())
    .bind(b"gamma".to_vec())
    .bind(vec![0x44_u8; 32])
    .bind(now)
    .execute(&pool)
    .await
    .unwrap();

    let lexical = lexical_projector(&pool, tenant_id, &project);
    assert!(matches!(
        lexical.project_pending().await,
        Err(RecallProjectionError::BodyIntegrityMismatch)
    ));
    assert_eq!(
        count(
            &pool,
            "memory_body_lexical_projection_v1",
            tenant_id,
            &project
        )
        .await,
        0
    );
    assert!(lexical.read_cursor().await.unwrap().is_none());
}

/// Every read and write stays inside the scope bound at construction.
#[tokio::test]
async fn the_projection_never_crosses_the_scope_it_was_bound_to() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let owner = format!("owner-{}", Uuid::now_v7());
    let neighbour = format!("neighbour-{}", Uuid::now_v7());
    let scope = physical_scope(&owner);
    let tenant_id = scope.tenant_id;
    let pool = live_pool(&database_url, scope).await;
    seed_body_plane(&pool, tenant_id, &owner, &[SOURCE_A]).await;

    lexical_projector(&pool, tenant_id, &owner)
        .project_pending()
        .await
        .unwrap();
    dense_projector(&pool, tenant_id, &owner, FixtureProvider::healthy())
        .embed_pending()
        .await
        .unwrap();

    // A projector bound to another project in the SAME tenant sees no bodies.
    let stranger = lexical_projector(&pool, tenant_id, &neighbour);
    assert_eq!(stranger.project_pending().await.unwrap().bodies_consumed, 0);
    assert!(stranger.read_cursor().await.unwrap().is_none());

    // And a reader bound there recalls nothing, with an empty completeness.
    let probe = fixture_vector("the selective capybara tends a semantic orchard");
    let stranger_reader = reader(&pool, tenant_id, &neighbour);
    let result = stranger_reader
        .recall("capybara orchard", Some(&probe), 10)
        .await
        .unwrap();
    assert_eq!(result.tier, RecallTierV1::None);
    assert!(result.hits.is_empty());
    assert_eq!(result.completeness.bodies_total, 0);
    assert_eq!(result.completeness.lexically_indexed, 0);
    assert_eq!(result.completeness.densely_embedded, 0);

    // A different TENANT with the same project name is equally invisible.
    let other_tenant = reader(&pool, Uuid::now_v7(), &owner);
    assert!(
        other_tenant
            .recall("capybara orchard", Some(&probe), 10)
            .await
            .unwrap()
            .hits
            .is_empty()
    );
}

/// The dense vector index keeps the C-SPANN equality prefix migration 0001
/// requires, and the dense recall query binds exactly that prefix.
#[tokio::test]
async fn the_dense_vector_index_keeps_the_c_spann_equality_prefix() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let project = format!("cspann-{}", Uuid::now_v7());
    let scope = physical_scope(&project);
    let pool = live_pool(&database_url, scope).await;

    let columns: Vec<String> = sqlx::query_scalar(
        "SELECT column_name FROM information_schema.statistics \
         WHERE table_schema = 'public' \
           AND table_name = 'memory_body_dense_projection_v1' \
           AND index_name = 'memory_body_dense_projection_semantic_idx' \
         ORDER BY seq_in_index",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(columns.len() >= 3, "vector index must exist: {columns:?}");
    assert_eq!(
        &columns[..3],
        [
            "tenant_id".to_string(),
            "project".to_string(),
            "embedding".to_string()
        ],
        "the vector column must sit directly behind the two equality-bound \
         scope columns; anything else makes the ANN portion unusable"
    );
}

/// The projection is private-plane only: no publication grant on any of its
/// tables.
#[tokio::test]
async fn no_projection_table_is_granted_to_the_publication_role() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let project = format!("plane-{}", Uuid::now_v7());
    let scope = physical_scope(&project);
    let pool = live_pool(&database_url, scope).await;

    let granted: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM information_schema.role_table_grants \
         WHERE table_schema = 'public' AND grantee = 'fleet_publication' \
           AND table_name = ANY($1)",
    )
    .bind(PROJECTION_TABLES.map(String::from).to_vec())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        granted, 0,
        "recall projection tables must stay off the public plane"
    );
}
