//! Connected proof for the private Stage-2 genesis control repository.
//!
//! Set `FLEET_RECALL_TEST_DATABASE_URL` to a disposable `CockroachDB` 26.2
//! database. The test is inert otherwise and never targets a cloud service.

use std::str::FromStr;
use std::time::Duration;

use chrono::{DateTime, Utc};
use futures::future::join_all;
use ostk_fleet_recall::control_log::{
    CockroachGenesisRepository, GenesisBootstrapOutcome, GenesisInspection, GenesisRepository,
    TrustedControlScope,
};
use ostk_fleet_recall::memory_contracts::bootstrap::{
    AppendPositionV1, BootstrapAttestationV1, BootstrapPin, BootstrapReceiptDigest,
    BootstrapReceiptV1, CommittedOffsetV1, VerifiedBootstrapReceipt, verify_pinned_bootstrap,
};
use ostk_fleet_recall::memory_contracts::canonical::{decode_strict, encode_canonical};
use ostk_fleet_recall::memory_contracts::common::{
    AuthenticatedProjectScopeV1, ContractId, FixedHex32, FixedHex64, ProfileReferenceV1,
};
use ostk_fleet_recall::memory_contracts::control::GenesisBootstrapAppendV1;
use ostk_fleet_recall::memory_contracts::digest::{
    DigestDomain, Sha256Digest, domain_separated_digest, framed_digest,
};
use ostk_fleet_recall::memory_contracts::evidence::AcceptedEventId;
use ostk_fleet_recall::memory_contracts::genesis::SemanticallyClosedGenesisPackage;
use ostk_fleet_recall::memory_contracts::registry::ManifestVerifiedRegistryPackage;
use ostk_fleet_recall::store::cockroach::{CockroachStore, PoolConfig, RetryPolicy};
use ostk_fleet_recall::{FleetError, FleetScope};
use ostk_recall_core::PrivacyTier;
use ring::signature::Ed25519KeyPair;
use sqlx::{PgPool, Row};
use uuid::Uuid;

const GENESIS_PACKAGE: &[u8] =
    include_bytes!("../contracts/dynamic-memory/v1/genesis-registry-package.jsonl");
const BOOTSTRAP_RECEIPT: &[u8] =
    include_bytes!("../contracts/dynamic-memory/v1/bootstrap-receipt.jsonl");
const PROFILE_DIGEST: &str = "cf22991a86bfc560556c7d04efa4ee6b7b1ee0f49c919b257ea7b4f30f8e4a29";
const VECTOR_MANIFEST_DIGEST: &str =
    "f984f62866fc769df3a5617a2247e3ade694827c1de69e615a7bda68858b4174";
const BOOTSTRAP_RECEIPT_DIGEST: &str =
    "084ee06ea7ebf3b1d592d6e5843584485144c0ee5720fcc2124a61a7fcde48f0";

struct GenesisFixture {
    semantic_scope: AuthenticatedProjectScopeV1,
    package: SemanticallyClosedGenesisPackage,
    bootstrap: VerifiedBootstrapReceipt,
    append: GenesisBootstrapAppendV1,
}

fn record(artifact: &'static [u8]) -> &'static [u8] {
    let body = artifact
        .strip_suffix(b"\n")
        .expect("contract JSONL must end in exactly one repository-framing LF");
    assert!(!body.ends_with(b"\n"));
    assert!(!body.contains(&b'\r'));
    body
}

fn digest(value: &str) -> Sha256Digest {
    Sha256Digest::from_str(value).expect("fixture digest must be lowercase SHA-256")
}

fn fixture() -> GenesisFixture {
    let profile = ProfileReferenceV1 {
        profile_id: ContractId::new("ostk-canonical-json-v1").unwrap(),
        profile_digest: digest(PROFILE_DIGEST),
        vector_manifest_digest: digest(VECTOR_MANIFEST_DIGEST),
    };
    let semantic_scope = AuthenticatedProjectScopeV1::from_trusted_context(
        ContractId::new("tenant.fixture").unwrap(),
        ContractId::new("project.fixture").unwrap(),
    );
    let manifest_verified =
        ManifestVerifiedRegistryPackage::decode(record(GENESIS_PACKAGE), &profile).unwrap();
    let package =
        SemanticallyClosedGenesisPackage::from_manifest_verified(manifest_verified).unwrap();
    let pin = BootstrapPin::from_trusted_config(BootstrapReceiptDigest::from_digest(digest(
        BOOTSTRAP_RECEIPT_DIGEST,
    )));
    let bootstrap = verify_pinned_bootstrap(
        record(BOOTSTRAP_RECEIPT),
        pin,
        &profile,
        &semantic_scope,
        &package,
    )
    .unwrap();
    let append = GenesisBootstrapAppendV1::from_verified(&bootstrap, &package).unwrap();
    GenesisFixture {
        semantic_scope,
        package,
        bootstrap,
        append,
    }
}

fn independently_signed_bootstrap(fixture: &GenesisFixture) -> VerifiedBootstrapReceipt {
    let mut receipt: BootstrapReceiptV1 =
        decode_strict(fixture.bootstrap.canonical_bytes()).unwrap();
    receipt.statement.genesis_epoch.partition_recipe.seed = FixedHex32::from_bytes([8; 32]);
    let statement_id = receipt.statement.statement_id().unwrap();
    let mut message = b"ostk-bootstrap-approval-v1\0".to_vec();
    message.extend_from_slice(statement_id.digest().as_bytes());
    receipt.attestations = [1_u8, 2]
        .into_iter()
        .enumerate()
        .map(|(index, seed)| BootstrapAttestationV1 {
            schema_version: 1,
            statement_id,
            signer_principal_id: ContractId::new(format!("principal.{}", index + 1)).unwrap(),
            signature: FixedHex64::from_bytes(
                Ed25519KeyPair::from_seed_unchecked(&[seed; 32])
                    .unwrap()
                    .sign(&message)
                    .as_ref()
                    .try_into()
                    .unwrap(),
            ),
        })
        .collect();
    let canonical = encode_canonical(&receipt).unwrap();
    let pin = BootstrapPin::from_trusted_config(BootstrapReceiptDigest::from_digest(
        domain_separated_digest(DigestDomain::BootstrapReceipt, &canonical),
    ));
    verify_pinned_bootstrap(
        &canonical,
        pin,
        &receipt.statement.profile,
        &fixture.semantic_scope,
        &fixture.package,
    )
    .unwrap()
}

fn physical_scope(label: &str) -> FleetScope {
    FleetScope::new(
        Uuid::now_v7(),
        format!("stage2-{label}-{}", Uuid::now_v7()),
        "stage2-connected-test",
        None,
        PrivacyTier::T1Project,
    )
    .unwrap()
}

fn repository(
    pool: PgPool,
    physical: &FleetScope,
    semantic: AuthenticatedProjectScopeV1,
) -> CockroachGenesisRepository {
    let trusted = TrustedControlScope::from_trusted_context(physical, semantic).unwrap();
    CockroachGenesisRepository::new(
        pool,
        trusted,
        RetryPolicy {
            max_attempts: 20,
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(50),
        },
    )
}

async fn scoped_count(pool: &PgPool, table: &str, scope: &FleetScope) -> i64 {
    let query = format!("SELECT count(*)::INT8 FROM {table} WHERE tenant_id = $1 AND project = $2");
    sqlx::query_scalar(&query)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn append_synthetic_control_suffix(
    pool: &PgPool,
    scope: &FleetScope,
    fixture: &GenesisFixture,
    shard: u16,
    marker: &str,
) {
    let mut transaction = pool.begin().await.unwrap();
    let current = sqlx::query(
        "SELECT last_committed_offset, chain_digest FROM memory_control_shard_heads \
         WHERE tenant_id = $1 AND project = $2 AND epoch_id = $3 AND shard = $4 FOR UPDATE",
    )
    .bind(scope.tenant_id)
    .bind(&scope.project)
    .bind(fixture.bootstrap.epoch_id().digest().as_bytes().to_vec())
    .bind(i32::from(shard))
    .fetch_one(&mut *transaction)
    .await
    .unwrap();
    let previous_offset: i64 = current.get("last_committed_offset");
    let previous_chain = Sha256Digest::from_bytes(
        current
            .get::<Vec<u8>, _>("chain_digest")
            .try_into()
            .unwrap(),
    );
    let next_offset = previous_offset.checked_add(1).unwrap();
    let append_position = AppendPositionV1 {
        epoch_id: fixture.bootstrap.epoch_id(),
        shard,
        committed_offset: CommittedOffsetV1::new(u64::try_from(next_offset).unwrap()).unwrap(),
    };
    let accepted_event_id = AcceptedEventId::from_digest(domain_separated_digest(
        DigestDomain::AcceptedEvent,
        marker.as_bytes(),
    ));
    let position_bytes = encode_canonical(&append_position).unwrap();
    let append_chain = framed_digest(
        DigestDomain::AppendChain,
        &[
            previous_chain.as_bytes(),
            &position_bytes,
            accepted_event_id.digest().as_bytes(),
        ],
    );
    let canonical_event = format!("{{\"marker\":\"{marker}\"}}").into_bytes();
    let accepted_at: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("SELECT statement_timestamp()")
            .fetch_one(&mut *transaction)
            .await
            .unwrap();

    sqlx::query(
        "INSERT INTO memory_control_events (\
             tenant_id, project, epoch_id, shard, committed_offset, event_id, \
             event_schema_version, event_kind, semantic_object_digest, consistency_family, \
             consistency_key_digest, canonical_event, previous_chain_digest, chain_digest, \
             accepted_at\
         ) VALUES ($1, $2, $3, $4, $5, $6, 1, 'test.control.suffix', $7, \
                   'test.control.suffix', $8, $9, $10, $11, $12)",
    )
    .bind(scope.tenant_id)
    .bind(&scope.project)
    .bind(fixture.bootstrap.epoch_id().digest().as_bytes().to_vec())
    .bind(i32::from(shard))
    .bind(next_offset)
    .bind(accepted_event_id.digest().as_bytes().to_vec())
    .bind(accepted_event_id.digest().as_bytes().to_vec())
    .bind(
        domain_separated_digest(DigestDomain::Body, marker.as_bytes())
            .as_bytes()
            .to_vec(),
    )
    .bind(canonical_event)
    .bind(previous_chain.as_bytes().to_vec())
    .bind(append_chain.as_bytes().to_vec())
    .bind(accepted_at)
    .execute(&mut *transaction)
    .await
    .unwrap();
    let advanced = sqlx::query(
        "UPDATE memory_control_shard_heads \
         SET last_committed_offset = $5, chain_digest = $6, advanced_at = $7 \
         WHERE tenant_id = $1 AND project = $2 AND epoch_id = $3 AND shard = $4 \
           AND last_committed_offset = $8 AND chain_digest = $9",
    )
    .bind(scope.tenant_id)
    .bind(&scope.project)
    .bind(fixture.bootstrap.epoch_id().digest().as_bytes().to_vec())
    .bind(i32::from(shard))
    .bind(next_offset)
    .bind(append_chain.as_bytes().to_vec())
    .bind(accepted_at)
    .bind(previous_offset)
    .bind(previous_chain.as_bytes().to_vec())
    .execute(&mut *transaction)
    .await
    .unwrap();
    assert_eq!(advanced.rows_affected(), 1);
    transaction.commit().await.unwrap();
}

async fn assert_duplicate_predecessor_rejected(
    pool: &PgPool,
    scope: &FleetScope,
    fixture: &GenesisFixture,
) {
    let shard = fixture.append.append_position.shard;
    let mut transaction = pool.begin().await.unwrap();
    let head = sqlx::query(
        "SELECT last_committed_offset, chain_digest FROM memory_control_shard_heads \
         WHERE tenant_id = $1 AND project = $2 AND epoch_id = $3 AND shard = $4 FOR UPDATE",
    )
    .bind(scope.tenant_id)
    .bind(&scope.project)
    .bind(fixture.bootstrap.epoch_id().digest().as_bytes().to_vec())
    .bind(i32::from(shard))
    .fetch_one(&mut *transaction)
    .await
    .unwrap();
    let previous_offset: i64 = head.get("last_committed_offset");
    let previous_chain =
        Sha256Digest::from_bytes(head.get::<Vec<u8>, _>("chain_digest").try_into().unwrap());
    let accepted_at: DateTime<Utc> = sqlx::query_scalar("SELECT statement_timestamp()")
        .fetch_one(&mut *transaction)
        .await
        .unwrap();

    for index in 1_i64..=2 {
        let offset = previous_offset + index;
        let position = AppendPositionV1 {
            epoch_id: fixture.bootstrap.epoch_id(),
            shard,
            committed_offset: CommittedOffsetV1::new(u64::try_from(offset).unwrap()).unwrap(),
        };
        let marker = format!("duplicate-predecessor-{index}");
        let event_id = AcceptedEventId::from_digest(domain_separated_digest(
            DigestDomain::AcceptedEvent,
            marker.as_bytes(),
        ));
        let chain = framed_digest(
            DigestDomain::AppendChain,
            &[
                previous_chain.as_bytes(),
                &encode_canonical(&position).unwrap(),
                event_id.digest().as_bytes(),
            ],
        );
        let result = sqlx::query(
            "INSERT INTO memory_control_events (\
                 tenant_id, project, epoch_id, shard, committed_offset, event_id, \
                 event_schema_version, event_kind, semantic_object_digest, consistency_family, \
                 consistency_key_digest, canonical_event, previous_chain_digest, chain_digest, \
                 accepted_at\
             ) VALUES ($1, $2, $3, $4, $5, $6, 1, 'test.duplicate.predecessor', $7, \
                       'test.duplicate.predecessor', $8, $9, $10, $11, $12)",
        )
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(fixture.bootstrap.epoch_id().digest().as_bytes().to_vec())
        .bind(i32::from(shard))
        .bind(offset)
        .bind(event_id.digest().as_bytes().to_vec())
        .bind(event_id.digest().as_bytes().to_vec())
        .bind(
            domain_separated_digest(DigestDomain::Partition, marker.as_bytes())
                .as_bytes()
                .to_vec(),
        )
        .bind(format!("{{\"marker\":\"{marker}\"}}").into_bytes())
        .bind(previous_chain.as_bytes().to_vec())
        .bind(chain.as_bytes().to_vec())
        .bind(accepted_at)
        .execute(&mut *transaction)
        .await;
        if index == 1 {
            result.unwrap();
        } else {
            let error = result.unwrap_err();
            let database = error.as_database_error().unwrap();
            assert_eq!(database.code().as_deref(), Some("23505"));
            assert_eq!(
                database.constraint(),
                Some("memory_control_events_predecessor_unique_idx")
            );
        }
    }
    transaction.rollback().await.unwrap();
}

#[allow(clippy::too_many_lines)] // one bounded helper independently audits every genesis row family
async fn assert_complete_database_shape(
    pool: &PgPool,
    scope: &FleetScope,
    fixture: &GenesisFixture,
) {
    assert_eq!(
        scoped_count(pool, "memory_control_bootstraps", scope).await,
        1
    );
    assert_eq!(
        scoped_count(pool, "memory_control_log_epochs", scope).await,
        1
    );
    assert_eq!(scoped_count(pool, "memory_control_events", scope).await, 1);

    let statement = &fixture.bootstrap.receipt().statement;
    let bootstrap = sqlx::query(
        "SELECT receipt_digest, statement_id, bootstrap_event_id, epoch_id, shard_count, \
                bootstrap_shard, bootstrap_offset, canonical_receipt, canonical_genesis_package, \
                accepted_at \
         FROM memory_control_bootstraps WHERE tenant_id = $1 AND project = $2",
    )
    .bind(scope.tenant_id)
    .bind(&scope.project)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(
        bootstrap.get::<Vec<u8>, _>("receipt_digest"),
        fixture.bootstrap.receipt_digest().digest().as_bytes()
    );
    assert_eq!(
        bootstrap.get::<Vec<u8>, _>("statement_id"),
        fixture.bootstrap.statement_id().digest().as_bytes()
    );
    assert_eq!(
        bootstrap.get::<Vec<u8>, _>("bootstrap_event_id"),
        fixture.append.accepted_event_id.digest().as_bytes()
    );
    assert_eq!(
        bootstrap.get::<Vec<u8>, _>("epoch_id"),
        fixture.bootstrap.epoch_id().digest().as_bytes()
    );
    assert_eq!(
        bootstrap.get::<i32, _>("shard_count"),
        i32::from(statement.genesis_epoch.partition_recipe.shard_count)
    );
    assert_eq!(
        bootstrap.get::<i32, _>("bootstrap_shard"),
        i32::from(fixture.append.append_position.shard)
    );
    assert_eq!(bootstrap.get::<i64, _>("bootstrap_offset"), 1);
    assert_eq!(
        bootstrap.get::<Vec<u8>, _>("canonical_receipt"),
        fixture.bootstrap.canonical_bytes()
    );
    assert_eq!(
        bootstrap.get::<Vec<u8>, _>("canonical_genesis_package"),
        fixture.package.canonical_bytes()
    );
    let accepted_at = bootstrap.get::<DateTime<Utc>, _>("accepted_at");

    let epoch_created_at: DateTime<Utc> = sqlx::query_scalar(
        "SELECT created_at FROM memory_control_log_epochs \
         WHERE tenant_id = $1 AND project = $2 AND epoch_id = $3",
    )
    .bind(scope.tenant_id)
    .bind(&scope.project)
    .bind(fixture.bootstrap.epoch_id().digest().as_bytes().to_vec())
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(epoch_created_at, accepted_at);

    let heads = sqlx::query(
        "SELECT shard, shard_count, last_committed_offset, chain_digest, advanced_at \
         FROM memory_control_shard_heads \
         WHERE tenant_id = $1 AND project = $2 AND epoch_id = $3 ORDER BY shard",
    )
    .bind(scope.tenant_id)
    .bind(&scope.project)
    .bind(fixture.bootstrap.epoch_id().digest().as_bytes().to_vec())
    .fetch_all(pool)
    .await
    .unwrap();
    let shard_count = statement.genesis_epoch.partition_recipe.shard_count;
    assert_eq!(heads.len(), usize::from(shard_count));
    for (expected_shard, row) in (0..shard_count).zip(&heads) {
        assert_eq!(row.get::<i32, _>("shard"), i32::from(expected_shard));
        assert_eq!(row.get::<i32, _>("shard_count"), i32::from(shard_count));
        let selected = expected_shard == fixture.append.append_position.shard;
        assert_eq!(
            row.get::<i64, _>("last_committed_offset"),
            i64::from(selected)
        );
        let expected_chain = if selected {
            fixture.append.append_chain_digest
        } else {
            fixture
                .bootstrap
                .genesis_chain_digest(expected_shard)
                .unwrap()
        };
        assert_eq!(
            row.get::<Vec<u8>, _>("chain_digest"),
            expected_chain.as_bytes()
        );
        assert_eq!(row.get::<DateTime<Utc>, _>("advanced_at"), accepted_at);
    }

    let event = sqlx::query(
        "SELECT shard, committed_offset, event_id, semantic_object_digest, canonical_event, \
                previous_chain_digest, chain_digest, accepted_at \
         FROM memory_control_events WHERE tenant_id = $1 AND project = $2",
    )
    .bind(scope.tenant_id)
    .bind(&scope.project)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(
        event.get::<i32, _>("shard"),
        i32::from(fixture.append.append_position.shard)
    );
    assert_eq!(event.get::<i64, _>("committed_offset"), 1);
    assert_eq!(
        event.get::<Vec<u8>, _>("event_id"),
        fixture.append.accepted_event_id.digest().as_bytes()
    );
    assert_eq!(
        event.get::<Vec<u8>, _>("semantic_object_digest"),
        fixture.bootstrap.receipt_digest().digest().as_bytes()
    );
    assert_eq!(
        event.get::<Vec<u8>, _>("canonical_event"),
        encode_canonical(&fixture.append.event).unwrap()
    );
    assert_eq!(
        event.get::<Vec<u8>, _>("previous_chain_digest"),
        fixture.append.previous_chain_digest.as_bytes()
    );
    assert_eq!(
        event.get::<Vec<u8>, _>("chain_digest"),
        fixture.append.append_chain_digest.as_bytes()
    );
    assert_eq!(event.get::<DateTime<Utc>, _>("accepted_at"), accepted_at);
}

async fn cleanup_control_scope(pool: &PgPool, scope: &FleetScope) {
    for statement in [
        "DELETE FROM memory_control_events WHERE tenant_id = $1 AND project = $2",
        "DELETE FROM memory_control_shard_heads WHERE tenant_id = $1 AND project = $2",
        "DELETE FROM memory_control_log_epochs WHERE tenant_id = $1 AND project = $2",
        "DELETE FROM memory_control_bootstraps WHERE tenant_id = $1 AND project = $2",
    ] {
        sqlx::query(statement)
            .bind(scope.tenant_id)
            .bind(&scope.project)
            .execute(pool)
            .await
            .unwrap();
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn live_stage2_genesis_repository_when_configured() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let fixture = fixture();
    let migration_scope = physical_scope("migration");
    let store = CockroachStore::connect(&database_url, migration_scope, PoolConfig::default())
        .await
        .unwrap();
    store.migrate().await.unwrap();
    let pool = store.pool().clone();
    let version: String = sqlx::query_scalar("SELECT version()")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(version.contains("CockroachDB"));

    // A direct first acceptance is distinguishable from a byte-exact replay,
    // and every materialized row independently matches H0/H1 contract math.
    let replay_scope = physical_scope("replay");
    assert_eq!(scoped_count(&pool, "memory_events", &replay_scope).await, 0);
    let replay_repository = repository(pool.clone(), &replay_scope, fixture.semantic_scope.clone());
    let first = replay_repository
        .bootstrap_genesis(&fixture.bootstrap, &fixture.package)
        .await
        .unwrap();
    let GenesisBootstrapOutcome::Inserted(first_inspection) = first else {
        panic!("a fresh physical scope must perform the first insert");
    };
    let replay = replay_repository
        .bootstrap_genesis(&fixture.bootstrap, &fixture.package)
        .await
        .unwrap();
    assert_eq!(
        replay,
        GenesisBootstrapOutcome::ExactReplay(first_inspection.clone())
    );
    assert_eq!(
        replay_repository
            .inspect_genesis(&fixture.bootstrap, &fixture.package)
            .await
            .unwrap(),
        GenesisInspection::Complete(first_inspection.clone())
    );
    assert_complete_database_shape(&pool, &replay_scope, &fixture).await;

    // Stage 2 remains a durable prefix after later repositories append valid
    // events. Advance both the bootstrap shard and an independently initialized
    // shard so H1/H2 and H0/H1 suffix shapes are covered.
    let shard_count = fixture
        .bootstrap
        .receipt()
        .statement
        .genesis_epoch
        .partition_recipe
        .shard_count;
    let bootstrap_shard = fixture.append.append_position.shard;
    let other_shard = (bootstrap_shard + 1) % shard_count;
    append_synthetic_control_suffix(
        &pool,
        &replay_scope,
        &fixture,
        bootstrap_shard,
        "same-shard-suffix",
    )
    .await;
    append_synthetic_control_suffix(
        &pool,
        &replay_scope,
        &fixture,
        other_shard,
        "other-shard-suffix",
    )
    .await;
    assert_eq!(
        replay_repository
            .bootstrap_genesis(&fixture.bootstrap, &fixture.package)
            .await
            .unwrap(),
        GenesisBootstrapOutcome::ExactReplay(first_inspection.clone())
    );
    assert_eq!(
        replay_repository
            .inspect_genesis(&fixture.bootstrap, &fixture.package)
            .await
            .unwrap(),
        GenesisInspection::Complete(first_inspection)
    );
    assert_eq!(
        scoped_count(&pool, "memory_control_events", &replay_scope).await,
        3
    );
    assert_eq!(scoped_count(&pool, "memory_events", &replay_scope).await, 0);

    // Identical contenders converge on one atomic append rather than creating
    // offsets, partially materialized children, or update-style overwrites.
    let concurrent_scope = physical_scope("concurrent");
    let concurrent_repository = repository(
        pool.clone(),
        &concurrent_scope,
        fixture.semantic_scope.clone(),
    );
    let outcomes =
        join_all((0..16).map(|_| {
            concurrent_repository.bootstrap_genesis(&fixture.bootstrap, &fixture.package)
        }))
        .await;
    let mut inserted = 0;
    let mut replayed = 0;
    for outcome in outcomes {
        match outcome.unwrap() {
            GenesisBootstrapOutcome::Inserted(_) => inserted += 1,
            GenesisBootstrapOutcome::ExactReplay(_) => replayed += 1,
        }
    }
    assert_eq!((inserted, replayed), (1, 15));
    assert_complete_database_shape(&pool, &concurrent_scope, &fixture).await;
    assert_eq!(
        scoped_count(&pool, "memory_events", &concurrent_scope).await,
        0
    );

    // A second, independently signed and pinned authority for the same
    // semantic scope/package is valid in isolation, but cannot replace a
    // complete prior bootstrap in the singleton physical scope.
    let conflicting_bootstrap = independently_signed_bootstrap(&fixture);
    assert_ne!(
        conflicting_bootstrap.receipt_digest(),
        fixture.bootstrap.receipt_digest()
    );
    let conflict_scope = physical_scope("conflict");
    let conflict_repository = repository(
        pool.clone(),
        &conflict_scope,
        fixture.semantic_scope.clone(),
    );
    conflict_repository
        .bootstrap_genesis(&fixture.bootstrap, &fixture.package)
        .await
        .unwrap();
    let conflict = conflict_repository
        .bootstrap_genesis(&conflicting_bootstrap, &fixture.package)
        .await
        .unwrap_err();
    assert!(matches!(conflict, FleetError::GenesisBootstrapConflict(_)));
    assert_complete_database_shape(&pool, &conflict_scope, &fixture).await;
    assert_eq!(
        scoped_count(&pool, "memory_events", &conflict_scope).await,
        0
    );

    // A missing immutable child is corruption, not an invitation to heal or
    // silently reserve another event position.
    let corrupt_scope = physical_scope("corrupt");
    let corrupt_repository =
        repository(pool.clone(), &corrupt_scope, fixture.semantic_scope.clone());
    corrupt_repository
        .bootstrap_genesis(&fixture.bootstrap, &fixture.package)
        .await
        .unwrap();
    sqlx::query("DELETE FROM memory_control_events WHERE tenant_id = $1 AND project = $2")
        .bind(corrupt_scope.tenant_id)
        .bind(&corrupt_scope.project)
        .execute(&pool)
        .await
        .unwrap();
    let error = corrupt_repository
        .bootstrap_genesis(&fixture.bootstrap, &fixture.package)
        .await
        .unwrap_err();
    assert!(matches!(error, FleetError::ControlLogCorrupt(_)));
    assert_eq!(
        scoped_count(&pool, "memory_control_events", &corrupt_scope).await,
        0
    );
    assert_eq!(
        scoped_count(&pool, "memory_events", &corrupt_scope).await,
        0
    );

    // Advancing beyond the prefix is valid, but a selected head that moves
    // behind the immutable bootstrap event makes the prefix incomplete.
    let rewound_scope = physical_scope("rewound-head");
    let rewound_repository =
        repository(pool.clone(), &rewound_scope, fixture.semantic_scope.clone());
    rewound_repository
        .bootstrap_genesis(&fixture.bootstrap, &fixture.package)
        .await
        .unwrap();
    let bootstrap_shard = fixture.append.append_position.shard;
    let genesis_chain = fixture
        .bootstrap
        .genesis_chain_digest(bootstrap_shard)
        .unwrap();
    sqlx::query(
        "UPDATE memory_control_shard_heads \
         SET last_committed_offset = 0, chain_digest = $5 \
         WHERE tenant_id = $1 AND project = $2 AND epoch_id = $3 AND shard = $4",
    )
    .bind(rewound_scope.tenant_id)
    .bind(&rewound_scope.project)
    .bind(fixture.bootstrap.epoch_id().digest().as_bytes().to_vec())
    .bind(i32::from(bootstrap_shard))
    .bind(genesis_chain.as_bytes().to_vec())
    .execute(&pool)
    .await
    .unwrap();
    let rewound_error = rewound_repository
        .inspect_genesis(&fixture.bootstrap, &fixture.package)
        .await
        .unwrap_err();
    assert!(matches!(rewound_error, FleetError::ControlLogCorrupt(_)));

    // The immutable bootstrap row and its accepted event were committed by
    // one transaction timestamp. Divergence is prefix corruption even when all
    // canonical bytes and chain digests still match.
    let timestamp_scope = physical_scope("timestamp-corrupt");
    let timestamp_repository = repository(
        pool.clone(),
        &timestamp_scope,
        fixture.semantic_scope.clone(),
    );
    timestamp_repository
        .bootstrap_genesis(&fixture.bootstrap, &fixture.package)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE memory_control_events SET accepted_at = accepted_at + INTERVAL '1 microsecond' \
         WHERE tenant_id = $1 AND project = $2",
    )
    .bind(timestamp_scope.tenant_id)
    .bind(&timestamp_scope.project)
    .execute(&pool)
    .await
    .unwrap();
    let timestamp_error = timestamp_repository
        .inspect_genesis(&fixture.bootstrap, &fixture.package)
        .await
        .unwrap_err();
    assert!(matches!(timestamp_error, FleetError::ControlLogCorrupt(_)));

    // The schema independently rejects a fork that reuses one predecessor
    // chain digest even when both event positions and IDs differ.
    let duplicate_scope = physical_scope("duplicate-predecessor");
    let duplicate_repository = repository(
        pool.clone(),
        &duplicate_scope,
        fixture.semantic_scope.clone(),
    );
    duplicate_repository
        .bootstrap_genesis(&fixture.bootstrap, &fixture.package)
        .await
        .unwrap();
    assert_duplicate_predecessor_rejected(&pool, &duplicate_scope, &fixture).await;
    assert_eq!(
        scoped_count(&pool, "memory_control_events", &duplicate_scope).await,
        1
    );

    for scope in [
        &replay_scope,
        &concurrent_scope,
        &conflict_scope,
        &corrupt_scope,
        &rewound_scope,
        &timestamp_scope,
        &duplicate_scope,
    ] {
        cleanup_control_scope(&pool, scope).await;
    }
}
