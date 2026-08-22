//! Connected proof of the private/publication read-plane boundary (W2-VIS).
//!
//! Every `#[tokio::test]` here exercises the real `CockroachDB` runtime and runs
//! only when `FLEET_RECALL_TEST_DATABASE_URL` points at a disposable single-node
//! instance whose principal may create roles (see the fleet worker protocol
//! section 3, `crdb-up.sh`); otherwise it returns early. The pure
//! classification and its rejection classes are covered by ordinary unit tests
//! in `src/projectors/visibility.rs`.
//!
//! The interesting tests here are the NEGATIVE ones. This module's claim is not
//! "the publication plane returns the right rows" but "the publication plane
//! cannot return a private row, by any query it is able to write". So the
//! boundary is attacked three ways:
//!
//! * through the runtime — recall on the publication plane,
//! * through direct SQL as the real restricted database role — `SELECT`,
//!   `count(*)`, `LIMIT/OFFSET`, and an attempt to build a fresh view over the
//!   base table,
//! * through ranking — a private body engineered to outrank every public one,
//!   asked for with `LIMIT 1`.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sha2::{Digest as _, Sha256};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
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
    PRIVATE_PLANE_RECALL_TABLES, RecallPlaneV1, RecallProjectionResult,
    publication_plane_grant_statements,
};
use ostk_fleet_recall::store::cockroach::{CockroachStore, PoolConfig, RetryPolicy};
use ostk_recall_core::PrivacyTier;

static MIGRATED: Mutex<bool> = Mutex::const_new(false);

const EVIDENCE_ACCEPTED_EVENT_KIND: &str = "evidence.accepted";
const PROJECT_NAMESPACE: &str = "project.fixture";
const FOREIGN_NAMESPACE: &str = "project.other";

// ---------------------------------------------------------------------------
// Governance envelopes under test.
// ---------------------------------------------------------------------------

/// The three contract-valid governance envelopes the fixture builds, plus the
/// protection domain the content claims.
#[derive(Debug, Clone, Copy)]
struct EnvelopeV1 {
    visibility: VisibilityClass,
    publication: PublicationClass,
    protection_domain: &'static str,
}

impl EnvelopeV1 {
    /// The only envelope that reaches the publication plane.
    const APPROVED: Self = Self {
        visibility: VisibilityClass::PublicationApproved,
        publication: PublicationClass::PublicationApproved,
        protection_domain: PROJECT_NAMESPACE,
    };
    /// Ordinary project-visible evidence.
    const PROJECT: Self = Self {
        visibility: VisibilityClass::Project,
        publication: PublicationClass::PrivateOnly,
        protection_domain: PROJECT_NAMESPACE,
    };
    /// Approved for visibility but never approved for publication: conjunct 2.
    const VISIBLE_NOT_PUBLISHABLE: Self = Self {
        visibility: VisibilityClass::PublicationApproved,
        publication: PublicationClass::PrivateOnly,
        protection_domain: PROJECT_NAMESPACE,
    };
    /// Fully approved, but under a protection domain this scope does not speak
    /// for: conjunct 3.
    const FOREIGN_DOMAIN: Self = Self {
        visibility: VisibilityClass::PublicationApproved,
        publication: PublicationClass::PublicationApproved,
        protection_domain: FOREIGN_NAMESPACE,
    };
}

// ---------------------------------------------------------------------------
// Evidence fixture (mirrors tests/recall_projection_live.rs).
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
        ContractId::new(PROJECT_NAMESPACE).unwrap(),
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

fn representation(label: &str, envelope: EnvelopeV1) -> RepresentationIdentityV2 {
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
        visibility_class: envelope.visibility,
        retention_class: RetentionClass::Governed,
        publication_class: envelope.publication,
        erasure_scopes: vec![ErasureScopeReferenceV1 {
            kind: ErasureScopeKind::SourceFact,
            target_digest: source_fact_id.digest(),
        }],
        lineage: RepresentationLineageV2::Origin,
    }
}

/// A genuine, contract-valid accepted evidence statement carrying `envelope`.
fn build_statement(label: &str, source_bytes: &[u8], envelope: EnvelopeV1) -> EvidenceStatementV2 {
    let representation = representation(label, envelope);
    let source_fact = source_fact(label);
    let source_fact_id = derive_source_fact_id_v2(&source_fact).unwrap();
    let representation_key = derive_representation_key_v2(&representation).unwrap();
    let byte_length = CanonicalDecimal::parse(source_bytes.len().to_string()).unwrap();
    let statement = EvidenceStatementV2 {
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
            protection_domain_id: ContractId::new(envelope.protection_domain).unwrap(),
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
    };
    // The fixture must be a statement the contract itself accepts; otherwise a
    // "private" outcome below could be an artifact of an invalid fixture rather
    // than of the classification under test.
    statement
        .validate_shape()
        .expect("fixture statement must be contract-valid");
    statement
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

/// Deterministic pseudo-embedding whose components are multiples of 1/256, so
/// the vector survives the text round trip through `CockroachDB` unchanged.
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

struct FixtureProvider {
    descriptor: EmbeddingModelDescriptorV1,
}

impl FixtureProvider {
    fn healthy() -> Arc<Self> {
        Arc::new(Self {
            descriptor: descriptor(),
        })
    }
}

#[async_trait]
impl EmbeddingProvider for FixtureProvider {
    fn descriptor(&self) -> &EmbeddingModelDescriptorV1 {
        &self.descriptor
    }

    async fn embed(&self, lexical_text: &str) -> RecallProjectionResult<Vec<f32>> {
        Ok(fixture_vector(lexical_text))
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
        "visibility-connected-test",
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

/// Seed accepted-evidence events at `start_offset`, upserting the shard head so
/// a later batch can land after the body projector has already consumed the
/// earlier one.
async fn seed_evidence_log(
    pool: &PgPool,
    tenant_id: Uuid,
    project: &str,
    statements: &[EvidenceStatementV2],
    start_offset: i64,
) {
    let epoch_id = vec![0x5a_u8; 32];
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT pg_catalog.statement_timestamp()")
        .fetch_one(pool)
        .await
        .unwrap();
    let head_offset = start_offset + i64::try_from(statements.len()).unwrap() - 1;
    sqlx::query(
        "INSERT INTO public.memory_evidence_shard_heads (\
             tenant_id, project, epoch_id, shard, shard_count, last_committed_offset, \
             chain_digest, advanced_at) VALUES ($1,$2,$3,0,1,$4,$5,$6) \
             ON CONFLICT (tenant_id, project, epoch_id, shard) DO UPDATE SET \
             last_committed_offset = excluded.last_committed_offset, \
             advanced_at = excluded.advanced_at",
    )
    .bind(tenant_id)
    .bind(project)
    .bind(&epoch_id)
    .bind(head_offset)
    .bind(vec![0x11_u8; 32])
    .bind(now)
    .execute(pool)
    .await
    .unwrap();

    for (index, statement) in statements.iter().enumerate() {
        let offset = start_offset + i64::try_from(index).unwrap();
        let canonical = encode_canonical(statement).unwrap();
        let event_id = statement
            .accepted_event_id()
            .unwrap()
            .digest()
            .as_bytes()
            .to_vec();
        let position = u8::try_from(usize::try_from(offset).unwrap() & 0xff).unwrap();
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

/// One labelled source: its bytes and the envelope its evidence carries.
struct SeedV1 {
    label: &'static str,
    bytes: &'static [u8],
    envelope: EnvelopeV1,
}

/// Seed the body plane the real way: genuine evidence events, projected by
/// W2-BODY's own projector, which is also what writes `memory_body_visibility_v1`.
async fn project_bodies(pool: &PgPool, tenant_id: Uuid, project: &str, seeds: &[SeedV1]) {
    project_bodies_at(pool, tenant_id, project, seeds, 1).await;
}

async fn project_bodies_at(
    pool: &PgPool,
    tenant_id: Uuid,
    project: &str,
    seeds: &[SeedV1],
    start_offset: i64,
) {
    let mut resolver = MapResolver::default();
    let mut statements = Vec::with_capacity(seeds.len());
    for seed in seeds {
        resolver
            .by_content_digest
            .insert(*plain_sha256(seed.bytes).as_bytes(), seed.bytes.to_vec());
        statements.push(build_statement(seed.label, seed.bytes, seed.envelope));
    }
    seed_evidence_log(pool, tenant_id, project, &statements, start_offset).await;

    CockroachBodyProjectionRepository::new(
        pool.clone(),
        tenant_id,
        project.to_string(),
        reference_parser_key_v1(),
        Arc::new(resolver),
        retry_policy(),
    )
    .project_pending()
    .await
    .unwrap();
}

async fn project_recall(pool: &PgPool, tenant_id: Uuid, project: &str) {
    CockroachLexicalProjector::new(
        pool.clone(),
        tenant_id,
        project.to_string(),
        2,
        retry_policy(),
    )
    .project_pending()
    .await
    .unwrap();
    CockroachDenseProjector::new(
        pool.clone(),
        tenant_id,
        project.to_string(),
        FixtureProvider::healthy(),
        2,
        retry_policy(),
    )
    .embed_pending()
    .await
    .unwrap();
}

fn private_reader(pool: &PgPool, tenant_id: Uuid, project: &str) -> CockroachRecallReader {
    CockroachRecallReader::new(pool.clone(), tenant_id, project.to_string())
}

fn publication_reader(pool: &PgPool, tenant_id: Uuid, project: &str) -> CockroachRecallReader {
    CockroachRecallReader::publication(pool.clone(), tenant_id, project.to_string())
}

fn body_id(bytes: &[u8]) -> Sha256Digest {
    body_digest(bytes)
}

async fn stored_class(pool: &PgPool, table: &str, tenant_id: Uuid, project: &str) -> Vec<String> {
    let sql = format!(
        "SELECT visibility_class FROM public.{table} \
         WHERE tenant_id = $1 AND project = $2 ORDER BY body_content_id"
    );
    sqlx::query_scalar(&sql)
        .bind(tenant_id)
        .bind(project)
        .fetch_all(pool)
        .await
        .unwrap()
}

// ---------------------------------------------------------------------------
// The mixed corpus every test starts from.
// ---------------------------------------------------------------------------

const PUBLIC_BODY: &[u8] = b"orbital telemetry summary for the public digest";
const PRIVATE_BODY: &[u8] = b"orbital orbital orbital orbital orbital orbital incident postmortem";
const PROJECT_BODY: &[u8] = b"orbital maintenance rota, project only";
const FOREIGN_BODY: &[u8] = b"orbital notes governed by another protection domain";

fn mixed_corpus() -> Vec<SeedV1> {
    vec![
        SeedV1 {
            label: "public-approved",
            bytes: PUBLIC_BODY,
            envelope: EnvelopeV1::APPROVED,
        },
        SeedV1 {
            label: "private-visible-not-publishable",
            bytes: PRIVATE_BODY,
            envelope: EnvelopeV1::VISIBLE_NOT_PUBLISHABLE,
        },
        SeedV1 {
            label: "private-project",
            bytes: PROJECT_BODY,
            envelope: EnvelopeV1::PROJECT,
        },
        SeedV1 {
            label: "private-foreign-domain",
            bytes: FOREIGN_BODY,
            envelope: EnvelopeV1::FOREIGN_DOMAIN,
        },
    ]
}

fn database_url() -> Option<String> {
    std::env::var("FLEET_RECALL_TEST_DATABASE_URL").ok()
}

/// Rebuild the connection URL for a password-authenticated restricted role,
/// dropping the admin client certificate but keeping the CA so TLS still
/// verifies the node.
fn restricted_role_url(admin_url: &str, role: &str, password: &str) -> String {
    let (base, query) = admin_url.split_once('?').unwrap_or((admin_url, ""));
    let authority_start = base.find("//").expect("URL must have an authority") + 2;
    let rest = &base[authority_start..];
    let host_start = rest.find('@').map_or(0, |at| at + 1);
    let scheme_and_slashes = &base[..authority_start];
    let host_and_path = &rest[host_start..];
    let kept: Vec<&str> = query
        .split('&')
        .filter(|parameter| {
            parameter.starts_with("sslmode=") || parameter.starts_with("sslrootcert=")
        })
        .collect();
    format!(
        "{scheme_and_slashes}{role}:{password}@{host_and_path}?{}",
        kept.join("&")
    )
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_private_plane_sees_both_classes_and_the_publication_plane_sees_only_public_rows() {
    let Some(url) = database_url() else {
        return;
    };
    let project = format!("visibility-mixed-{}", Uuid::now_v7());
    let scope = physical_scope(&project);
    let tenant_id = scope.tenant_id;
    let pool = live_pool(&url, scope).await;

    project_bodies(&pool, tenant_id, &project, &mixed_corpus()).await;
    project_recall(&pool, tenant_id, &project).await;

    // Exactly one of the four bodies is publication-safe, and it is the one
    // whose evidence carried the exact approved triple.
    let mut lexical_classes = stored_class(
        &pool,
        "memory_body_lexical_projection_v1",
        tenant_id,
        &project,
    )
    .await;
    lexical_classes.sort_unstable();
    assert_eq!(
        lexical_classes,
        vec![
            "private".to_string(),
            "private".to_string(),
            "private".to_string(),
            "publication_safe".to_string(),
        ]
    );
    let mut dense_classes = stored_class(
        &pool,
        "memory_body_dense_projection_v1",
        tenant_id,
        &project,
    )
    .await;
    dense_classes.sort_unstable();
    assert_eq!(dense_classes, lexical_classes);

    let private = private_reader(&pool, tenant_id, &project);
    assert_eq!(private.plane(), RecallPlaneV1::Private);
    let private_hits = private.recall("orbital", None, 50).await.unwrap();
    assert_eq!(
        private_hits.hits.len(),
        4,
        "the private plane sees all four"
    );

    let publication = publication_reader(&pool, tenant_id, &project);
    assert_eq!(publication.plane(), RecallPlaneV1::Publication);
    let public_hits = publication.recall("orbital", None, 50).await.unwrap();
    assert_eq!(public_hits.hits.len(), 1);
    assert_eq!(public_hits.hits[0].body_content_id, body_id(PUBLIC_BODY));

    // The dense lane obeys the same boundary.
    let vector = fixture_vector("orbital telemetry summary for the public digest");
    let public_dense = publication
        .recall("orbital", Some(&vector), 50)
        .await
        .unwrap();
    assert!(
        public_dense
            .hits
            .iter()
            .all(|hit| hit.body_content_id == body_id(PUBLIC_BODY))
    );
    let private_dense = private.recall("orbital", Some(&vector), 50).await.unwrap();
    assert_eq!(private_dense.hits.len(), 4);
}

#[tokio::test]
async fn ranking_count_and_offset_probes_never_reveal_a_private_row() {
    let Some(url) = database_url() else {
        return;
    };
    let project = format!("visibility-rank-{}", Uuid::now_v7());
    let scope = physical_scope(&project);
    let tenant_id = scope.tenant_id;
    let pool = live_pool(&url, scope).await;

    project_bodies(&pool, tenant_id, &project, &mixed_corpus()).await;
    project_recall(&pool, tenant_id, &project).await;

    // PRIVATE_BODY repeats the query term six times, so it outranks the public
    // body by ts_rank. If the visibility predicate ran after ranking, LIMIT 1
    // on the publication plane would return nothing (the one slot consumed by a
    // private row) or, worse, the private row itself.
    let private = private_reader(&pool, tenant_id, &project);
    let top_private = private.recall("orbital", None, 1).await.unwrap();
    assert_eq!(top_private.hits.len(), 1);
    assert_eq!(
        top_private.hits[0].body_content_id,
        body_id(PRIVATE_BODY),
        "the fixture must actually rank a private body first"
    );

    let publication = publication_reader(&pool, tenant_id, &project);
    let top_public = publication.recall("orbital", None, 1).await.unwrap();
    assert_eq!(top_public.hits.len(), 1);
    assert_eq!(top_public.hits[0].body_content_id, body_id(PUBLIC_BODY));

    // Count probe: publication readiness is computed over the publication views
    // only, so no arithmetic on it yields the private population.
    let private_readiness = private.completeness().await.unwrap();
    let public_readiness = publication.completeness().await.unwrap();
    assert_eq!(private_readiness.bodies_total, 4);
    assert_eq!(private_readiness.lexically_indexed, 4);
    assert_eq!(public_readiness.bodies_total, 1);
    assert_eq!(public_readiness.lexically_indexed, 1);
    assert_eq!(public_readiness.densely_embedded, 1);

    // Offset probe: asking for far more rows than exist still yields exactly
    // the publication-safe population, with no gap where a private row was.
    let deep = publication.recall("orbital", None, 500).await.unwrap();
    assert_eq!(deep.hits.len(), 1);

    // The publication plane cannot ask for the private snapshot either.
    assert!(publication.snapshot().await.is_err());
    assert_eq!(private.snapshot().await.unwrap().lexical.len(), 4);
}

#[tokio::test]
async fn the_real_publication_role_has_no_sql_path_to_a_private_row() {
    let Some(url) = database_url() else {
        return;
    };
    let project = format!("visibility-role-{}", Uuid::now_v7());
    let scope = physical_scope(&project);
    let tenant_id = scope.tenant_id;
    let pool = live_pool(&url, scope).await;

    project_bodies(&pool, tenant_id, &project, &mixed_corpus()).await;
    project_recall(&pool, tenant_id, &project).await;

    // Install the exact deployment grant surface: CONNECT, schema USAGE, and
    // the two publication VIEWS. No base table appears here, and the statements
    // come from the runtime rather than being retyped.
    let role = "w2vis_publication_probe";
    let password = "w2visprobepassword";
    let database: String = sqlx::query_scalar("SELECT pg_catalog.current_database()")
        .fetch_one(&pool)
        .await
        .unwrap();
    for statement in [
        format!("CREATE ROLE IF NOT EXISTS {role} LOGIN PASSWORD '{password}'"),
        format!("GRANT CONNECT ON DATABASE {database} TO {role}"),
        format!("GRANT USAGE ON SCHEMA public TO {role}"),
    ] {
        sqlx::query(&statement).execute(&pool).await.unwrap();
    }
    for statement in publication_plane_grant_statements(role) {
        assert!(
            PRIVATE_PLANE_RECALL_TABLES
                .iter()
                .all(|table| !statement.contains(table)),
            "the grant surface must name no base table: {statement}"
        );
        sqlx::query(&statement).execute(&pool).await.unwrap();
    }

    let restricted: PgPool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&restricted_role_url(&url, role, password))
        .await
        .expect("the restricted role must be able to connect");

    // 1. The runtime's publication reader, over the restricted connection,
    //    answers with the public row and nothing else.
    let publication = publication_reader(&restricted, tenant_id, &project);
    let hits = publication.recall("orbital", None, 100).await.unwrap();
    assert_eq!(hits.hits.len(), 1);
    assert_eq!(hits.hits[0].body_content_id, body_id(PUBLIC_BODY));

    // 2. Direct SQL as that role cannot reach a base table at all -- not to
    //    select, not to count, not to page through with LIMIT/OFFSET.
    for table in PRIVATE_PLANE_RECALL_TABLES {
        for probe in [
            format!("SELECT * FROM public.{table} LIMIT 1"),
            format!("SELECT count(*) FROM public.{table}"),
            format!("SELECT 1 FROM public.{table} LIMIT 1 OFFSET 1"),
        ] {
            let error = sqlx::query(&probe)
                .execute(&restricted)
                .await
                .expect_err(&format!("{probe} must be refused"));
            assert!(
                error.to_string().contains("privilege"),
                "{probe} must fail on privilege, got: {error}"
            );
        }
    }
    // The body plane itself is equally out of reach.
    assert!(
        sqlx::query("SELECT count(*) FROM public.memory_body_objects_v1")
            .execute(&restricted)
            .await
            .is_err()
    );

    // 3. It cannot build its own view over a base table either, so it cannot
    //    manufacture the path the grant withheld.
    assert!(
        sqlx::query(
            "CREATE VIEW public.w2vis_leak AS \
             SELECT * FROM public.memory_body_lexical_projection_v1"
        )
        .execute(&restricted)
        .await
        .is_err()
    );

    // 4. What it CAN read returns exactly the publication-safe population, and
    //    the private texts are absent from it.
    let visible: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.memory_body_lexical_publication_v1 \
         WHERE tenant_id = $1 AND project = $2",
    )
    .bind(tenant_id)
    .bind(&project)
    .fetch_one(&restricted)
    .await
    .unwrap();
    assert_eq!(visible, 1);
    let texts: Vec<String> = sqlx::query_scalar(
        "SELECT lexical_text FROM public.memory_body_lexical_publication_v1 \
         WHERE tenant_id = $1 AND project = $2",
    )
    .bind(tenant_id)
    .bind(&project)
    .fetch_all(&restricted)
    .await
    .unwrap();
    assert_eq!(texts.len(), 1);
    assert!(texts[0].contains("public digest"));
    assert!(texts.iter().all(|text| !text.contains("postmortem")));

    restricted.close().await;
}

#[tokio::test]
async fn a_body_with_no_recorded_decision_projects_as_private() {
    let Some(url) = database_url() else {
        return;
    };
    let project = format!("visibility-default-{}", Uuid::now_v7());
    let scope = physical_scope(&project);
    let tenant_id = scope.tenant_id;
    let pool = live_pool(&url, scope).await;

    // A body row written without a companion visibility row -- the shape a
    // pre-migration-0023 body has. The LEFT JOIN's COALESCE must classify it
    // private rather than letting it default into the publication plane.
    let orphan = b"orbital body with no recorded governance decision";
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT pg_catalog.statement_timestamp()")
        .fetch_one(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO public.memory_body_objects_v1 (\
             tenant_id, project, content_sha256, byte_length, body_bytes, media_type, \
             protection_domain_id, first_accepted_event_id, created_at) \
             VALUES ($1,$2,$3,$4,$5,'text.plain','project.fixture',$6,$7)",
    )
    .bind(tenant_id)
    .bind(&project)
    .bind(body_digest(orphan).as_bytes().to_vec())
    .bind(i64::try_from(orphan.len()).unwrap())
    .bind(orphan.to_vec())
    .bind(vec![0x66_u8; 32])
    .bind(now)
    .execute(&pool)
    .await
    .unwrap();

    project_recall(&pool, tenant_id, &project).await;

    assert_eq!(
        stored_class(
            &pool,
            "memory_body_lexical_projection_v1",
            tenant_id,
            &project
        )
        .await,
        vec!["private".to_string()]
    );
    let publication = publication_reader(&pool, tenant_id, &project);
    assert!(
        publication
            .recall("orbital", None, 10)
            .await
            .unwrap()
            .hits
            .is_empty()
    );
    assert_eq!(
        private_reader(&pool, tenant_id, &project)
            .recall("orbital", None, 10)
            .await
            .unwrap()
            .hits
            .len(),
        1
    );
}

#[tokio::test]
async fn a_later_private_event_over_the_same_bytes_demotes_an_already_public_row() {
    let Some(url) = database_url() else {
        return;
    };
    let project = format!("visibility-demote-{}", Uuid::now_v7());
    let scope = physical_scope(&project);
    let tenant_id = scope.tenant_id;
    let pool = live_pool(&url, scope).await;

    // Bodies are content-addressed, so two events with different governance
    // envelopes can produce the same body. Publication safety therefore has to
    // be unanimous, and the collapse has to propagate to rows already written.
    project_bodies(
        &pool,
        tenant_id,
        &project,
        &[SeedV1 {
            label: "shared-approved",
            bytes: PUBLIC_BODY,
            envelope: EnvelopeV1::APPROVED,
        }],
    )
    .await;
    project_recall(&pool, tenant_id, &project).await;

    let publication = publication_reader(&pool, tenant_id, &project);
    assert_eq!(
        publication
            .recall("orbital", None, 10)
            .await
            .unwrap()
            .hits
            .len(),
        1,
        "the approved body starts out visible to the publication plane"
    );

    project_bodies_at(
        &pool,
        tenant_id,
        &project,
        &[SeedV1 {
            label: "shared-private",
            bytes: PUBLIC_BODY,
            envelope: EnvelopeV1::PROJECT,
        }],
        2,
    )
    .await;

    let recorded: String = sqlx::query_scalar(
        "SELECT visibility_class FROM public.memory_body_visibility_v1 \
         WHERE tenant_id = $1 AND project = $2",
    )
    .bind(tenant_id)
    .bind(&project)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(recorded, "private", "disagreement collapses to private");

    // The projectors' end-of-pass reconciliation propagates the collapse.
    project_recall(&pool, tenant_id, &project).await;
    assert_eq!(
        stored_class(
            &pool,
            "memory_body_lexical_projection_v1",
            tenant_id,
            &project
        )
        .await,
        vec!["private".to_string()]
    );
    assert_eq!(
        stored_class(
            &pool,
            "memory_body_dense_projection_v1",
            tenant_id,
            &project
        )
        .await,
        vec!["private".to_string()]
    );
    assert!(
        publication
            .recall("orbital", None, 10)
            .await
            .unwrap()
            .hits
            .is_empty(),
        "the body has left the publication plane"
    );
    assert_eq!(
        private_reader(&pool, tenant_id, &project)
            .recall("orbital", None, 10)
            .await
            .unwrap()
            .hits
            .len(),
        1,
        "and is still fully available on the private plane"
    );
}

#[tokio::test]
async fn the_database_itself_refuses_an_unapproved_publication_safe_row() {
    let Some(url) = database_url() else {
        return;
    };
    let project = format!("visibility-constraint-{}", Uuid::now_v7());
    let scope = physical_scope(&project);
    let tenant_id = scope.tenant_id;
    let pool = live_pool(&url, scope).await;

    let now: DateTime<Utc> = sqlx::query_scalar("SELECT pg_catalog.statement_timestamp()")
        .fetch_one(&pool)
        .await
        .unwrap();
    let insert = "INSERT INTO public.memory_body_visibility_v1 (\
         tenant_id, project, body_content_id, visibility_class, protection_domain_id, \
         source_visibility_class, source_publication_class, first_accepted_event_id, updated_at\
         ) VALUES ($1,$2,$3,$4,'project.fixture',$5,$6,$7,$8)";

    // Every unapproved source pair is refused by the CHECK constraint, so a
    // runtime bug cannot store an approval the evidence never granted.
    for (source_visibility, source_publication) in [
        ("private", "denied"),
        ("project", "private_only"),
        ("publication_approved", "private_only"),
        ("project", "denied"),
    ] {
        let error = sqlx::query(insert)
            .bind(tenant_id)
            .bind(&project)
            .bind(vec![0x77_u8; 32])
            .bind("publication_safe")
            .bind(source_visibility)
            .bind(source_publication)
            .bind(vec![0x88_u8; 32])
            .bind(now)
            .execute(&pool)
            .await
            .expect_err("an unapproved publication-safe row must be refused");
        let message = error.to_string();
        assert!(
            message.contains("CHECK constraint")
                && message.contains("source_publication_class = 'publication_approved'"),
            "expected the approval CHECK to be the refusal, got: {error}"
        );
    }

    // An unknown class string is refused as well: the column is a closed set.
    assert!(
        sqlx::query(insert)
            .bind(tenant_id)
            .bind(&project)
            .bind(vec![0x79_u8; 32])
            .bind("public")
            .bind("publication_approved")
            .bind("publication_approved")
            .bind(vec![0x88_u8; 32])
            .bind(now)
            .execute(&pool)
            .await
            .is_err()
    );

    // The exact approved pair is accepted -- the constraint restricts, it does
    // not simply forbid.
    sqlx::query(insert)
        .bind(tenant_id)
        .bind(&project)
        .bind(vec![0x7a_u8; 32])
        .bind("publication_safe")
        .bind("publication_approved")
        .bind("publication_approved")
        .bind(vec![0x88_u8; 32])
        .bind(now)
        .execute(&pool)
        .await
        .unwrap();
}
