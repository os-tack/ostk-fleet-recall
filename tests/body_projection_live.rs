//! Connected and offline tests for the content-addressed body projection
//! (W2-BODY).
//!
//! The `#[test]` functions here are pure and always run: they cover the
//! fail-closed rejection classes and REPLAY-01 byte-stability at the derivation
//! layer with no database. The `#[tokio::test]` functions exercise the real
//! `CockroachDB` runtime and run only when `FLEET_RECALL_TEST_DATABASE_URL`
//! points at a disposable single-node instance (see the fleet worker protocol
//! section 3, `crdb-up.sh`); otherwise they return early.
//!
//! Every database-gated test in this file is named `live_*`: that prefix is
//! how the authoritative official-binary lane
//! (`deploy/cockroach/tests/registry-activation-cli.sh`) discovers the suite,
//! so a database-gated test without it would silently never run in CI.
//!
//! The projector consumes ACCEPTED evidence events from `memory_evidence_events`
//! (`event_kind = 'evidence.accepted'`). These tests seed that log directly with
//! genuine, contract-validated `EvidenceStatementV2` canonical bytes — the exact
//! bytes the W1-EVID append seam stores — so the projector's real behavior is
//! exercised against a real evidence log without standing up the full admission
//! and registry-activation stack (which owns its own connected tests). Source
//! bytes are supplied through an in-memory [`SourceContentResolver`], the one
//! seam production wires to the governed content store.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sha2::{Digest as _, Sha256};
use sqlx::PgPool;
use tokio::sync::Mutex;
use uuid::Uuid;

use ostk_fleet_recall::FleetScope;
use ostk_fleet_recall::body_store::{
    BodyProjectionError, BodyProjectionRepository, CockroachBodyProjectionRepository,
    SourceContentResolver, derive_parse_run, reference_parser_key_v1, reference_parser_key_v2,
};
use ostk_fleet_recall::memory_contracts::canonical::encode_canonical;
use ostk_fleet_recall::memory_contracts::common::{
    AuthenticatedProjectScopeV1, CanonicalDecimal, CanonicalTimestamp, ContractId, HexBytes,
    RegistryReferenceV1, frozen_profile_reference_v1,
};
use ostk_fleet_recall::memory_contracts::digest::{
    DigestDomain, Sha256Digest, domain_separated_digest,
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
use ostk_fleet_recall::store::cockroach::{CockroachStore, PoolConfig, RetryPolicy};
use ostk_recall_core::PrivacyTier;

static MIGRATED: Mutex<bool> = Mutex::const_new(false);

// ---------------------------------------------------------------------------
// Fixture: genuine EvidenceStatementV2 construction.
// ---------------------------------------------------------------------------

const EVIDENCE_ACCEPTED_EVENT_KIND: &str = "evidence.accepted";

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

fn source_fact(label: &str, resource_form: IdentityForm) -> SourceFactIdentityV2 {
    SourceFactIdentityV2 {
        schema_version: 2,
        scope: semantic_scope(),
        provider_namespace: reference("namespace.github", 1),
        provider_instance_id: resource(IdentityForm::Entity, "provider_instance", "instance-a"),
        logical_event_key: HexBytes::new(format!("ref:{label}").into_bytes()).unwrap(),
        provider_object_id: HexBytes::new(format!("obj:{label}").into_bytes()).unwrap(),
        immutable_revision: HexBytes::new(format!("commit:{label}").into_bytes()).unwrap(),
        canonical_resource_id: resource(resource_form, "git_blob", label),
    }
}

fn representation(label: &str, resource_form: IdentityForm) -> RepresentationIdentityV2 {
    let source_fact = source_fact(label, resource_form);
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

/// Build a genuine, contract-valid accepted evidence statement whose governed
/// content digest is the plain SHA-256 of `source_bytes`.
fn build_statement(
    label: &str,
    source_bytes: &[u8],
    resource_form: IdentityForm,
) -> EvidenceStatementV2 {
    let representation = representation(label, resource_form);
    let source_fact = source_fact(label, resource_form);
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

// ---------------------------------------------------------------------------
// In-memory source-content resolver (the production seam is the content store).
// ---------------------------------------------------------------------------

#[derive(Default)]
struct MapResolver {
    by_content_digest: HashMap<[u8; 32], Vec<u8>>,
}

impl MapResolver {
    fn insert(&mut self, source_bytes: &[u8]) {
        self.by_content_digest.insert(
            *plain_sha256(source_bytes).as_bytes(),
            source_bytes.to_vec(),
        );
    }
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
// Offline rejection-class and replay-stability tests (always run).
// ---------------------------------------------------------------------------

#[test]
fn derive_rejects_a_non_versioned_source_uri() {
    // A git-blob evidence event that names an occurrence-form (not version-form)
    // resource has no immutable source-object version to chunk: fail closed.
    let source = b"alpha\n\nbeta";
    let statement = build_statement("occ-source", source, IdentityForm::Occurrence);
    let result = derive_parse_run(&statement, source, &reference_parser_key_v1());
    assert!(matches!(
        result,
        Err(BodyProjectionError::NonVersionedSource(_))
    ));
}

#[test]
fn derive_rejects_source_bytes_that_do_not_match_the_attested_digest() {
    // The evidence attests SHA-256("alpha..."); handing the projector different
    // bytes must fail closed before any identity is minted.
    let attested = b"alpha\n\nbeta";
    let statement = build_statement("mismatch", attested, IdentityForm::Version);
    let tampered = b"alpha\n\nGAMMA";
    let result = derive_parse_run(&statement, tampered, &reference_parser_key_v1());
    assert!(matches!(
        result,
        Err(BodyProjectionError::SourceIntegrityMismatch)
    ));
}

#[test]
fn derive_rejects_a_source_that_parses_to_no_chunk() {
    // Only blank lines: the parser yields nothing, so no manifest can cite an
    // occurrence. Fail closed rather than mint an empty manifest.
    let source = b"\n\n\n\n";
    let statement = build_statement("empty", source, IdentityForm::Version);
    let result = derive_parse_run(&statement, source, &reference_parser_key_v1());
    assert!(matches!(result, Err(BodyProjectionError::EmptyParse)));
}

#[test]
fn derivation_is_replay_stable_byte_for_byte() {
    let source = b"alpha\n\nbeta\n\ngamma";
    let statement = build_statement("stable", source, IdentityForm::Version);
    let first = derive_parse_run(&statement, source, &reference_parser_key_v1()).unwrap();
    let second = derive_parse_run(&statement, source, &reference_parser_key_v1()).unwrap();
    assert_eq!(first, second);
    // Three paragraphs => three occurrences and one manifest.
    assert_eq!(first.occurrences.len(), 3);
    assert_eq!(first.bodies.len(), 3);
}

#[test]
fn a_parser_upgrade_changes_every_derived_identity() {
    let source = b"alpha\n\nbeta";
    let statement = build_statement("upgrade", source, IdentityForm::Version);
    let v1 = derive_parse_run(&statement, source, &reference_parser_key_v1()).unwrap();
    let v2 = derive_parse_run(&statement, source, &reference_parser_key_v2()).unwrap();
    // The manifest and occurrence identities are different under the new parser
    // key, so v2 rows are a SHADOW generation that coexists with v1's rather
    // than colliding with it.
    assert_ne!(v1.manifest.manifest_id, v2.manifest.manifest_id);
    assert_ne!(v1.parser_key_id, v2.parser_key_id);
    let v1_ids: Vec<_> = v1.occurrences.iter().map(|o| o.occurrence_id).collect();
    let v2_ids: Vec<_> = v2.occurrences.iter().map(|o| o.occurrence_id).collect();
    for id in &v2_ids {
        assert!(!v1_ids.contains(id));
    }
}

// ---------------------------------------------------------------------------
// Connected CockroachDB tests.
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
        "body-projection-connected-test",
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
/// bytes. Returns the (offset, statement) pairs written.
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
        // The evidence ledger enforces a unique previous_chain_digest per
        // (tenant, project, epoch, shard); vary the seeded chain digests per
        // offset so a multi-event shard satisfies that index.
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

fn resolver_for(sources: &[&[u8]]) -> Arc<MapResolver> {
    let mut resolver = MapResolver::default();
    for source in sources {
        resolver.insert(source);
    }
    Arc::new(resolver)
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

async fn clear_body_plane(pool: &PgPool, tenant_id: Uuid, project: &str) {
    for table in [
        "memory_body_objects_v1",
        "memory_chunk_occurrences_v1",
        "memory_chunk_occurrence_spans_v1",
        "memory_parse_run_manifests_v1",
        "memory_source_commit_membership_v1",
        "memory_generation_pointers_v1",
        "memory_body_projection_watermarks_v1",
    ] {
        let sql = format!("DELETE FROM public.{table} WHERE tenant_id = $1 AND project = $2");
        sqlx::query(&sql)
            .bind(tenant_id)
            .bind(project)
            .execute(pool)
            .await
            .unwrap();
    }
}

/// REPLAY-01: replaying the accepted-event log from empty rebuilds byte-identical
/// body/occurrence/manifest rows.
#[tokio::test]
async fn live_replay_from_empty_rebuilds_byte_identical_rows() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let project = format!("replay-{}", Uuid::now_v7());
    let scope = physical_scope(&project);
    let tenant_id = scope.tenant_id;
    let pool = live_pool(&database_url, scope).await;

    let source_a: &[u8] = b"alpha\n\nbeta\n\ngamma";
    let source_b: &[u8] = b"one\n\ntwo";
    let statements = vec![
        build_statement("replay-a", source_a, IdentityForm::Version),
        build_statement("replay-b", source_b, IdentityForm::Version),
    ];
    seed_evidence_log(&pool, tenant_id, &project, &statements).await;

    let repository = CockroachBodyProjectionRepository::new(
        pool.clone(),
        tenant_id,
        project.clone(),
        reference_parser_key_v1(),
        resolver_for(&[source_a, source_b]),
        retry_policy(),
    );

    let summary = repository.project_pending().await.unwrap();
    assert_eq!(summary.events_projected, 2);
    let first = repository.snapshot().await.unwrap();
    assert!(!first.occurrences.is_empty());
    assert!(!first.bodies.is_empty());
    // Cursor advanced to the last offset.
    assert_eq!(
        repository
            .read_watermark(0)
            .await
            .unwrap()
            .unwrap()
            .last_committed_offset,
        2
    );

    // Rebuild from empty and prove byte-identity.
    clear_body_plane(&pool, tenant_id, &project).await;
    let rebuilt = repository.project_pending().await.unwrap();
    assert_eq!(rebuilt.events_projected, 2);
    let second = repository.snapshot().await.unwrap();
    assert_eq!(first, second);
}

/// Re-projecting an already-consumed log is a no-op: no new rows, cursor
/// unchanged, snapshot byte-identical.
#[tokio::test]
async fn live_reprojection_is_idempotent() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let project = format!("idem-{}", Uuid::now_v7());
    let scope = physical_scope(&project);
    let tenant_id = scope.tenant_id;
    let pool = live_pool(&database_url, scope).await;

    let source: &[u8] = b"alpha\n\nbeta";
    let statements = vec![build_statement("idem-a", source, IdentityForm::Version)];
    seed_evidence_log(&pool, tenant_id, &project, &statements).await;

    let repository = CockroachBodyProjectionRepository::new(
        pool.clone(),
        tenant_id,
        project.clone(),
        reference_parser_key_v1(),
        resolver_for(&[source]),
        retry_policy(),
    );

    repository.project_pending().await.unwrap();
    let after_first = repository.snapshot().await.unwrap();

    // A second full pass must not change anything.
    repository.reproject_all().await.unwrap();
    let after_second = repository.snapshot().await.unwrap();
    assert_eq!(after_first, after_second);
}

/// A body content address presented over different bytes than the ones durably
/// stored fails the whole event closed: no occurrence rows, cursor unadvanced.
#[tokio::test]
async fn live_body_content_collision_fails_closed() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let project = format!("collide-{}", Uuid::now_v7());
    let scope = physical_scope(&project);
    let tenant_id = scope.tenant_id;
    let pool = live_pool(&database_url, scope).await;

    let source: &[u8] = b"alpha\n\nbeta";
    let statement = build_statement("collide-a", source, IdentityForm::Version);
    // Derive offline to learn the content address the projector will use.
    let derived = derive_parse_run(&statement, source, &reference_parser_key_v1()).unwrap();
    let target = &derived.bodies[0];

    seed_evidence_log(&pool, tenant_id, &project, &[statement]).await;

    // Pre-seed a TAMPERED body row at that exact content address: same
    // content_sha256, different bytes. The projector must refuse.
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT pg_catalog.statement_timestamp()")
        .fetch_one(&pool)
        .await
        .unwrap();
    let tampered = b"tampered-body-bytes".to_vec();
    sqlx::query(
        "INSERT INTO public.memory_body_objects_v1 (\
             tenant_id, project, content_sha256, byte_length, body_bytes, media_type, \
             protection_domain_id, first_accepted_event_id, created_at) \
             VALUES ($1,$2,$3,$4,$5,'text.plain','project.fixture',$6,$7)",
    )
    .bind(tenant_id)
    .bind(&project)
    .bind(target.content_sha256.as_bytes().to_vec())
    .bind(i64::try_from(tampered.len()).unwrap())
    .bind(&tampered)
    .bind(vec![0x44_u8; 32])
    .bind(now)
    .execute(&pool)
    .await
    .unwrap();

    let repository = CockroachBodyProjectionRepository::new(
        pool.clone(),
        tenant_id,
        project.clone(),
        reference_parser_key_v1(),
        resolver_for(&[source]),
        retry_policy(),
    );

    let result = repository.project_pending().await;
    assert!(
        matches!(
            result,
            Err(BodyProjectionError::IntegrityCollision(_)
                | BodyProjectionError::LedgerIntegrity(_))
        ),
        "expected a fail-closed collision, got {result:?}"
    );
    // Fail closed: no occurrence/manifest rows and no cursor advance.
    assert_eq!(
        count(&pool, "memory_chunk_occurrences_v1", tenant_id, &project).await,
        0
    );
    assert_eq!(
        count(&pool, "memory_parse_run_manifests_v1", tenant_id, &project).await,
        0
    );
    assert!(repository.read_watermark(0).await.unwrap().is_none());
}

/// An occurrence id presented over a different canonical preimage than the one
/// already stored fails the event closed.
#[tokio::test]
async fn live_occurrence_preimage_collision_fails_closed() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let project = format!("occ-collide-{}", Uuid::now_v7());
    let scope = physical_scope(&project);
    let tenant_id = scope.tenant_id;
    let pool = live_pool(&database_url, scope).await;

    let source: &[u8] = b"alpha\n\nbeta";
    let statement = build_statement("occ-collide-a", source, IdentityForm::Version);
    let derived = derive_parse_run(&statement, source, &reference_parser_key_v1()).unwrap();
    let occurrence = &derived.occurrences[0];

    seed_evidence_log(&pool, tenant_id, &project, &[statement]).await;

    // Pre-seed the occurrence id with a DIFFERENT canonical preimage.
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT pg_catalog.statement_timestamp()")
        .fetch_one(&pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO public.memory_chunk_occurrences_v1 (\
             tenant_id, project, occurrence_id, source_object_version_uri, parser_key_id, \
             body_content_id, occurrence_ordinal, redaction_policy_version, \
             publication_classifier_version, generation_sequence, canonical_preimage, \
             accepted_event_id, created_at) \
             VALUES ($1,$2,$3,'urn:ostk:version:v1:git_blob:sha256:0000000000000000000000000000000000000000000000000000000000000000',\
             $4,$5,0,1,1,1,$6,$7,$8)",
    )
    .bind(tenant_id)
    .bind(&project)
    .bind(occurrence.occurrence_id.digest().as_bytes().to_vec())
    .bind(vec![0x55_u8; 32])
    .bind(occurrence.body_content_id.as_bytes().to_vec())
    .bind(b"tampered-preimage".to_vec())
    .bind(vec![0x66_u8; 32])
    .bind(now)
    .execute(&pool)
    .await
    .unwrap();

    let repository = CockroachBodyProjectionRepository::new(
        pool.clone(),
        tenant_id,
        project.clone(),
        reference_parser_key_v1(),
        resolver_for(&[source]),
        retry_policy(),
    );

    let result = repository.project_pending().await;
    assert!(
        matches!(result, Err(BodyProjectionError::PreimageCollision { .. })),
        "expected an occurrence preimage collision, got {result:?}"
    );
    assert!(repository.read_watermark(0).await.unwrap().is_none());
}

/// A parser-key upgrade opens a shadow generation without mutating the prior
/// generation's rows.
#[tokio::test]
async fn live_parser_upgrade_opens_a_shadow_generation() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let project = format!("shadow-{}", Uuid::now_v7());
    let scope = physical_scope(&project);
    let tenant_id = scope.tenant_id;
    let pool = live_pool(&database_url, scope).await;

    let source: &[u8] = b"alpha\n\nbeta";
    let statement = build_statement("shadow-a", source, IdentityForm::Version);
    let source_uri = statement.source_fact.canonical_resource_id.to_string();
    seed_evidence_log(&pool, tenant_id, &project, &[statement]).await;
    let resolver = resolver_for(&[source]);

    // Generation 1 under the paragraph parser.
    let generation_one = CockroachBodyProjectionRepository::new(
        pool.clone(),
        tenant_id,
        project.clone(),
        reference_parser_key_v1(),
        resolver.clone(),
        retry_policy(),
    );
    generation_one.project_pending().await.unwrap();
    let after_v1 = generation_one.snapshot().await.unwrap();
    assert_eq!(
        generation_one
            .read_generation_pointer(&source_uri)
            .await
            .unwrap()
            .unwrap()
            .generation_sequence,
        1
    );
    let v1_occurrences = after_v1.occurrences.clone();
    let v1_manifests = after_v1.manifests.clone();

    // Upgrade the parser: re-derive over the whole log under the line parser.
    let generation_two = CockroachBodyProjectionRepository::new(
        pool.clone(),
        tenant_id,
        project.clone(),
        reference_parser_key_v2(),
        resolver,
        retry_policy(),
    );
    let summary = generation_two.reproject_all().await.unwrap();
    assert_eq!(summary.shadow_generations_opened, 1);

    // The pointer advanced to generation 2.
    assert_eq!(
        generation_two
            .read_generation_pointer(&source_uri)
            .await
            .unwrap()
            .unwrap()
            .generation_sequence,
        2
    );

    let after_v2 = generation_two.snapshot().await.unwrap();
    // Every generation-1 occurrence and manifest row is still present, byte for
    // byte: the shadow generation added rows, it did not mutate the prior ones.
    for row in &v1_occurrences {
        assert!(
            after_v2.occurrences.contains(row),
            "gen-1 occurrence was mutated or removed"
        );
    }
    for row in &v1_manifests {
        assert!(
            after_v2.manifests.contains(row),
            "gen-1 manifest was mutated or removed"
        );
    }
    // And the shadow generation genuinely added new manifest rows.
    assert!(after_v2.manifests.len() > v1_manifests.len());
}

/// Cursor atomicity: rows and the cursor advance in ONE transaction, so a
/// rollback (a crash between output and cursor commit) leaves BOTH unadvanced.
#[tokio::test]
async fn live_cursor_atomicity_rollback_leaves_both_unadvanced() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let project = format!("atomic-{}", Uuid::now_v7());
    let scope = physical_scope(&project);
    let tenant_id = scope.tenant_id;
    let pool = live_pool(&database_url, scope).await;

    let source: &[u8] = b"alpha\n\nbeta";
    let statement = build_statement("atomic-a", source, IdentityForm::Version);
    seed_evidence_log(&pool, tenant_id, &project, &[statement]).await;

    let repository = CockroachBodyProjectionRepository::new(
        pool.clone(),
        tenant_id,
        project.clone(),
        reference_parser_key_v1(),
        resolver_for(&[source]),
        retry_policy(),
    );

    // Apply the first event inside a transaction, then roll back.
    let applied = repository
        .probe_apply_first_pending_then_rollback()
        .await
        .unwrap();
    assert!(applied);

    // Rolled back: no rows AND no cursor advance (they are the same transaction).
    assert_eq!(
        count(&pool, "memory_body_objects_v1", tenant_id, &project).await,
        0
    );
    assert_eq!(
        count(&pool, "memory_chunk_occurrences_v1", tenant_id, &project).await,
        0
    );
    assert!(repository.read_watermark(0).await.unwrap().is_none());

    // A committed pass then durably writes both.
    repository.project_pending().await.unwrap();
    assert!(count(&pool, "memory_body_objects_v1", tenant_id, &project).await > 0);
    assert_eq!(
        repository
            .read_watermark(0)
            .await
            .unwrap()
            .unwrap()
            .last_committed_offset,
        1
    );
}
