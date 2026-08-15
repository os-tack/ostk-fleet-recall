//! Connected proof for the private Stage-3 genesis activation repository.
//!
//! Set `FLEET_RECALL_TEST_DATABASE_URL` to a disposable `CockroachDB` 26.2
//! database. The test is inert otherwise and never targets a cloud service.

use std::str::FromStr;
use std::time::Duration;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use futures::future::join_all;
use ostk_fleet_recall::control_log::{
    CockroachGenesisRepository, GenesisRepository, TrustedControlScope,
};
use ostk_fleet_recall::error::{GenesisActivationConflictKind, GenesisActivationTimingKind};
use ostk_fleet_recall::memory_contracts::bootstrap::{
    AppendPositionV1, BootstrapAttestationV1, BootstrapPin, BootstrapReceiptDigest,
    BootstrapReceiptV1, CommittedOffsetV1, VerifiedBootstrapReceipt, verify_pinned_bootstrap,
};
use ostk_fleet_recall::memory_contracts::canonical::{decode_strict, encode_canonical};
use ostk_fleet_recall::memory_contracts::common::{
    AuthenticatedProjectScopeV1, CanonicalTimestamp, ContractId, FixedHex32, FixedHex64,
    ProfileReferenceV1, frozen_profile_reference_v1,
};
use ostk_fleet_recall::memory_contracts::control::GenesisBootstrapAppendV1;
use ostk_fleet_recall::memory_contracts::digest::{
    DigestDomain, Sha256Digest, domain_separated_digest, framed_digest,
};
use ostk_fleet_recall::memory_contracts::evidence::AcceptedEventId;
use ostk_fleet_recall::memory_contracts::genesis::SemanticallyClosedGenesisPackage;
use ostk_fleet_recall::memory_contracts::genesis_activation::{
    GenesisActivationPrincipalBinding, GenesisRegistryActivationApprovalSetV1,
    GenesisRegistryActivationApprovalV1, GenesisRegistryActivationStatementV1,
    GenesisRegistryAnchorV1, RegistryTestResultDigest, RegistryTestRunnerPin,
    VerifiedGenesisRegistryActivationRequest, VerifiedRegistryTestResult,
    genesis_activation_policy_digest, registry_activation_consistency_partition_key,
    verify_genesis_registry_activation, verify_registry_test_result,
};
use ostk_fleet_recall::memory_contracts::registry::ManifestVerifiedRegistryPackage;
use ostk_fleet_recall::registry_activation::{
    CockroachGenesisActivationRepository, GenesisActivationInspection, GenesisActivationOutcome,
    GenesisActivationRepository,
};
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
const TEST_RESULT: &[u8] =
    include_bytes!("../contracts/dynamic-memory/v1/genesis-activation/registry-test-result.jsonl");
const TEST_RESULT_DIGEST: &str = "e91e08070250a722446195b76ee685a9697298b9fdce9809027f120c829b679d";
const TEST_RUNNER_ARTIFACT: &str =
    "c2e5b0653471d35e54600a8d3fbe5613aff4c04e911787c09a25e2b327d4bbbd";
const TEST_RUNNER_CONFIGURATION: &str =
    "1d12aabe349fd0013389f93bf1917b0de6bbd5d2bd7156c85faff0b97360686d";

struct ContractFixture {
    profile: ProfileReferenceV1,
    semantic_scope: AuthenticatedProjectScopeV1,
    package: SemanticallyClosedGenesisPackage,
    test_result: VerifiedRegistryTestResult,
    principal_binding: GenesisActivationPrincipalBinding,
}

struct BootstrapAuthority {
    bootstrap: VerifiedBootstrapReceipt,
    append: GenesisBootstrapAppendV1,
}

fn record(artifact: &'static [u8]) -> &'static [u8] {
    let body = artifact
        .strip_suffix(b"\n")
        .expect("contract JSONL must have exactly one framing LF");
    assert!(!body.ends_with(b"\n"));
    assert!(!body.contains(&b'\r'));
    body
}

fn digest(value: &str) -> Sha256Digest {
    Sha256Digest::from_str(value).expect("fixture digest must be lowercase SHA-256")
}

fn fixture() -> ContractFixture {
    let profile = frozen_profile_reference_v1();
    let bootstrap_value: BootstrapReceiptV1 = decode_strict(record(BOOTSTRAP_RECEIPT)).unwrap();
    let semantic_scope = bootstrap_value.statement.scope;
    let manifest = ManifestVerifiedRegistryPackage::decode(record(GENESIS_PACKAGE), &profile)
        .expect("fixture package must use the frozen profile");
    let package = SemanticallyClosedGenesisPackage::from_manifest_verified(manifest).unwrap();
    let runner_pin = RegistryTestRunnerPin::from_trusted_config(
        digest(TEST_RUNNER_ARTIFACT),
        digest(TEST_RUNNER_CONFIGURATION),
        RegistryTestResultDigest::from_digest(digest(TEST_RESULT_DIGEST)),
    );
    let test_result =
        verify_registry_test_result(record(TEST_RESULT), runner_pin, &profile, &package).unwrap();
    ContractFixture {
        profile,
        semantic_scope,
        package,
        test_result,
        principal_binding: GenesisActivationPrincipalBinding::from_trusted_config(
            ContractId::new("principal.operator").unwrap(),
            ContractId::new("principal.author").unwrap(),
        ),
    }
}

fn signed_bootstrap(fixture: &ContractFixture, seed_byte: u8) -> BootstrapAuthority {
    let mut receipt: BootstrapReceiptV1 = decode_strict(record(BOOTSTRAP_RECEIPT)).unwrap();
    receipt.statement.genesis_epoch.partition_recipe.seed = FixedHex32::from_bytes([seed_byte; 32]);
    let statement_id = receipt.statement.statement_id().unwrap();
    let mut message = b"ostk-bootstrap-approval-v1\0".to_vec();
    message.extend_from_slice(statement_id.digest().as_bytes());
    receipt.attestations = [1_u8, 2]
        .into_iter()
        .enumerate()
        .map(|(index, signer_seed)| BootstrapAttestationV1 {
            schema_version: 1,
            statement_id,
            signer_principal_id: ContractId::new(format!("principal.{}", index + 1)).unwrap(),
            signature: FixedHex64::from_bytes(
                Ed25519KeyPair::from_seed_unchecked(&[signer_seed; 32])
                    .unwrap()
                    .sign(&message)
                    .as_ref()
                    .try_into()
                    .unwrap(),
            ),
        })
        .collect();
    let canonical = encode_canonical(&receipt).unwrap();
    let receipt_digest = BootstrapReceiptDigest::from_digest(domain_separated_digest(
        DigestDomain::BootstrapReceipt,
        &canonical,
    ));
    let bootstrap = verify_pinned_bootstrap(
        &canonical,
        BootstrapPin::from_trusted_config(receipt_digest),
        &fixture.profile,
        &fixture.semantic_scope,
        &fixture.package,
    )
    .unwrap();
    let append = GenesisBootstrapAppendV1::from_verified(&bootstrap, &fixture.package).unwrap();
    BootstrapAuthority { bootstrap, append }
}

fn bootstrap_for_shard_relation(fixture: &ContractFixture, same_shard: bool) -> BootstrapAuthority {
    let key = registry_activation_consistency_partition_key(&fixture.semantic_scope).unwrap();
    (4_u8..=u8::MAX)
        .map(|seed| signed_bootstrap(fixture, seed))
        .find(|authority| {
            let registry_shard = authority.bootstrap.partition_for(&key).unwrap();
            (registry_shard == authority.append.append_position.shard) == same_shard
        })
        .expect("public fixture seeds must cover both shard relationships")
}

fn activation_approval(
    statement_id: ostk_fleet_recall::memory_contracts::genesis_activation::GenesisRegistryActivationStatementId,
    signer_seed: u8,
) -> GenesisRegistryActivationApprovalV1 {
    let principal = ContractId::new(format!("principal.{signer_seed}")).unwrap();
    let mut message = b"ostk-registry-activation-approval-signature-v1\0".to_vec();
    message.extend_from_slice(statement_id.digest().as_bytes());
    let key = Ed25519KeyPair::from_seed_unchecked(&[signer_seed; 32]).unwrap();
    GenesisRegistryActivationApprovalV1 {
        schema_version: 1,
        statement_id,
        signer_principal_id: principal,
        signature: FixedHex64::from_bytes(key.sign(&message).as_ref().try_into().unwrap()),
    }
}

fn activation_request(
    fixture: &ContractFixture,
    authority: &BootstrapAuthority,
    effective_from: CanonicalTimestamp,
    signer_seeds: [u8; 2],
) -> VerifiedGenesisRegistryActivationRequest {
    let statement = GenesisRegistryActivationStatementV1 {
        schema_version: 1,
        profile: fixture.profile.clone(),
        scope: fixture.semantic_scope.clone(),
        expected_anchor: GenesisRegistryAnchorV1::from_verified(
            &authority.bootstrap,
            &fixture.package,
        )
        .unwrap(),
        package_digest: fixture.package.package_digest(),
        resulting_activation_policy_digest: genesis_activation_policy_digest(&fixture.package)
            .unwrap(),
        effective_from,
        effective_until: None,
        test_vector_result_digest: fixture.test_result.result_digest(),
        proposer_principal_id: ContractId::new("principal.operator").unwrap(),
        package_author_principal_id: ContractId::new("principal.author").unwrap(),
    };
    let statement_id = statement.statement_id().unwrap();
    let mut approvals = signer_seeds
        .into_iter()
        .map(|seed| activation_approval(statement_id, seed))
        .collect::<Vec<_>>();
    approvals.sort_unstable();
    let approval_set = GenesisRegistryActivationApprovalSetV1 {
        schema_version: 1,
        statement_id,
        approvals,
    };
    verify_genesis_registry_activation(
        &encode_canonical(&statement).unwrap(),
        &encode_canonical(&approval_set).unwrap(),
        &authority.bootstrap,
        &fixture.package,
        &fixture.test_result,
        &fixture.principal_binding,
    )
    .unwrap()
}

fn physical_scope(label: &str) -> FleetScope {
    FleetScope::new(
        Uuid::now_v7(),
        format!("stage3-{label}-{}", Uuid::now_v7()),
        "stage3-connected-test",
        None,
        PrivacyTier::T1Project,
    )
    .unwrap()
}

fn trusted_scope(physical: &FleetScope, fixture: &ContractFixture) -> TrustedControlScope {
    TrustedControlScope::from_trusted_context(physical, fixture.semantic_scope.clone()).unwrap()
}

const fn retry_policy() -> RetryPolicy {
    RetryPolicy {
        max_attempts: 20,
        initial_backoff: Duration::from_millis(1),
        max_backoff: Duration::from_millis(50),
    }
}

fn bootstrap_repository(
    pool: PgPool,
    physical: &FleetScope,
    fixture: &ContractFixture,
) -> CockroachGenesisRepository {
    CockroachGenesisRepository::new(pool, trusted_scope(physical, fixture), retry_policy())
}

fn activation_repository(
    pool: PgPool,
    physical: &FleetScope,
    fixture: &ContractFixture,
    authority: &BootstrapAuthority,
) -> CockroachGenesisActivationRepository {
    CockroachGenesisActivationRepository::new(
        pool,
        trusted_scope(physical, fixture),
        retry_policy(),
        authority.bootstrap.clone(),
        fixture.package.clone(),
        fixture.test_result.clone(),
        fixture.principal_binding.clone(),
    )
    .unwrap()
}

async fn server_time(pool: &PgPool) -> DateTime<Utc> {
    sqlx::query_scalar("SELECT statement_timestamp()")
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn bootstrap_time(pool: &PgPool, scope: &FleetScope) -> DateTime<Utc> {
    sqlx::query_scalar(
        "SELECT accepted_at FROM memory_control_bootstraps \
         WHERE tenant_id = $1 AND project = $2",
    )
    .bind(scope.tenant_id)
    .bind(&scope.project)
    .fetch_one(pool)
    .await
    .unwrap()
}

fn canonical_time(value: DateTime<Utc>) -> CanonicalTimestamp {
    CanonicalTimestamp::from_datetime(&value).unwrap()
}

fn append_chain(
    previous: Sha256Digest,
    event_id: AcceptedEventId,
    position: &AppendPositionV1,
) -> Sha256Digest {
    let position_bytes = encode_canonical(position).unwrap();
    framed_digest(
        DigestDomain::AppendChain,
        &[
            previous.as_bytes(),
            &position_bytes,
            event_id.digest().as_bytes(),
        ],
    )
}

async fn bootstrap_scope(
    pool: &PgPool,
    scope: &FleetScope,
    fixture: &ContractFixture,
    authority: &BootstrapAuthority,
) {
    bootstrap_repository(pool.clone(), scope, fixture)
        .bootstrap_genesis(&authority.bootstrap, &fixture.package)
        .await
        .unwrap();
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

async fn append_control_event(
    pool: &PgPool,
    scope: &FleetScope,
    authority: &BootstrapAuthority,
    shard: u16,
    marker: &str,
    registry_stream: bool,
) -> AppendPositionV1 {
    let mut transaction = pool.begin().await.unwrap();
    let current = sqlx::query(
        "SELECT last_committed_offset, chain_digest FROM memory_control_shard_heads \
         WHERE tenant_id = $1 AND project = $2 AND epoch_id = $3 AND shard = $4 FOR UPDATE",
    )
    .bind(scope.tenant_id)
    .bind(&scope.project)
    .bind(authority.bootstrap.epoch_id().digest().as_bytes().to_vec())
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
    let position = AppendPositionV1 {
        epoch_id: authority.bootstrap.epoch_id(),
        shard,
        committed_offset: CommittedOffsetV1::new(u64::try_from(next_offset).unwrap()).unwrap(),
    };
    let event_id = AcceptedEventId::from_digest(domain_separated_digest(
        DigestDomain::AcceptedEvent,
        marker.as_bytes(),
    ));
    let chain = append_chain(previous_chain, event_id, &position);
    let accepted_at: DateTime<Utc> = sqlx::query_scalar("SELECT statement_timestamp()")
        .fetch_one(&mut *transaction)
        .await
        .unwrap();
    let (family, key_digest) = if registry_stream {
        let key = registry_activation_consistency_partition_key(
            &authority.bootstrap.receipt().statement.scope,
        )
        .unwrap();
        (key.family.as_str().to_owned(), key.key_digest)
    } else {
        (
            "test.unrelated.control".to_owned(),
            domain_separated_digest(DigestDomain::Partition, marker.as_bytes()),
        )
    };
    sqlx::query(
        "INSERT INTO memory_control_events (\
             tenant_id, project, epoch_id, shard, committed_offset, event_id, \
             event_schema_version, event_kind, semantic_object_digest, consistency_family, \
             consistency_key_digest, canonical_event, previous_chain_digest, chain_digest, \
             accepted_at\
         ) VALUES ($1, $2, $3, $4, $5, $6, 1, 'test.synthetic.event', $7, $8, $9, \
                   $10, $11, $12, $13)",
    )
    .bind(scope.tenant_id)
    .bind(&scope.project)
    .bind(authority.bootstrap.epoch_id().digest().as_bytes().to_vec())
    .bind(i32::from(shard))
    .bind(next_offset)
    .bind(event_id.digest().as_bytes().to_vec())
    .bind(event_id.digest().as_bytes().to_vec())
    .bind(family)
    .bind(key_digest.as_bytes().to_vec())
    .bind(format!("{{\"marker\":\"{marker}\"}}").into_bytes())
    .bind(previous_chain.as_bytes().to_vec())
    .bind(chain.as_bytes().to_vec())
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
    .bind(authority.bootstrap.epoch_id().digest().as_bytes().to_vec())
    .bind(i32::from(shard))
    .bind(next_offset)
    .bind(chain.as_bytes().to_vec())
    .bind(accepted_at)
    .bind(previous_offset)
    .bind(previous_chain.as_bytes().to_vec())
    .execute(&mut *transaction)
    .await
    .unwrap();
    assert_eq!(advanced.rows_affected(), 1);
    transaction.commit().await.unwrap();
    position
}

async fn plant_event_ahead_of_head(
    pool: &PgPool,
    scope: &FleetScope,
    fixture: &ContractFixture,
    authority: &BootstrapAuthority,
    marker: &str,
) -> AppendPositionV1 {
    let shard = activation_shard(fixture, authority);
    let head = sqlx::query(
        "SELECT last_committed_offset, chain_digest FROM memory_control_shard_heads \
         WHERE tenant_id = $1 AND project = $2 AND epoch_id = $3 AND shard = $4",
    )
    .bind(scope.tenant_id)
    .bind(&scope.project)
    .bind(authority.bootstrap.epoch_id().digest().as_bytes().to_vec())
    .bind(i32::from(shard))
    .fetch_one(pool)
    .await
    .unwrap();
    let head_offset: i64 = head.get("last_committed_offset");
    let previous_chain =
        Sha256Digest::from_bytes(head.get::<Vec<u8>, _>("chain_digest").try_into().unwrap());
    let orphan_offset = head_offset.checked_add(2).unwrap();
    let position = AppendPositionV1 {
        epoch_id: authority.bootstrap.epoch_id(),
        shard,
        committed_offset: CommittedOffsetV1::new(u64::try_from(orphan_offset).unwrap()).unwrap(),
    };
    let event_id = AcceptedEventId::from_digest(domain_separated_digest(
        DigestDomain::AcceptedEvent,
        marker.as_bytes(),
    ));
    let chain = append_chain(previous_chain, event_id, &position);
    let accepted_at: DateTime<Utc> = sqlx::query_scalar("SELECT statement_timestamp()")
        .fetch_one(pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO memory_control_events (\
             tenant_id, project, epoch_id, shard, committed_offset, event_id, \
             event_schema_version, event_kind, semantic_object_digest, consistency_family, \
             consistency_key_digest, canonical_event, previous_chain_digest, chain_digest, \
             accepted_at\
         ) VALUES ($1, $2, $3, $4, $5, $6, 1, 'test.orphan.ahead', $7, \
                   'test.orphan.ahead', $8, $9, $10, $11, $12)",
    )
    .bind(scope.tenant_id)
    .bind(&scope.project)
    .bind(position.epoch_id.digest().as_bytes().to_vec())
    .bind(i32::from(position.shard))
    .bind(orphan_offset)
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
    .execute(pool)
    .await
    .unwrap();
    position
}

async fn plant_extra_activation_projection(
    pool: &PgPool,
    scope: &FleetScope,
    fixture: &ContractFixture,
    authority: &BootstrapAuthority,
) {
    let marker = "rogue-extra-activation-projection";
    let position = append_control_event(
        pool,
        scope,
        authority,
        activation_shard(fixture, authority),
        marker,
        false,
    )
    .await;
    let activation_id = domain_separated_digest(DigestDomain::AcceptedEvent, marker.as_bytes());
    let statement_id = domain_separated_digest(DigestDomain::Body, marker.as_bytes());
    let offset = i64::try_from(position.committed_offset.as_u64()).unwrap();
    let accepted_at: DateTime<Utc> = sqlx::query_scalar(
        "SELECT accepted_at FROM memory_control_events \
         WHERE tenant_id = $1 AND project = $2 AND epoch_id = $3 \
           AND shard = $4 AND committed_offset = $5",
    )
    .bind(scope.tenant_id)
    .bind(&scope.project)
    .bind(position.epoch_id.digest().as_bytes().to_vec())
    .bind(i32::from(position.shard))
    .bind(offset)
    .fetch_one(pool)
    .await
    .unwrap();

    let inserted = sqlx::query(
        "INSERT INTO memory_registry_activations (\
             tenant_id, project, activation_id, statement_id, bootstrap_statement_id, \
             bootstrap_receipt_digest, bootstrap_event_id, genesis_epoch_id, \
             genesis_package_digest, bootstrap_signer_policy_digest, profile_id, profile_digest, \
             vector_manifest_digest, contract_tenant_namespace, contract_project_namespace, \
             activated_package_digest, activated_policy_digest, test_result_digest, \
             proposer_principal_id, package_author_principal_id, approval_ids_packed, \
             approval_count, required_threshold, separation_of_duty_satisfied, \
             bootstrap_accepted_at, effective_from, effective_until, accepted_at, \
             accepted_event_id, control_epoch_id, control_shard, control_committed_offset, \
             canonical_statement, canonical_approval_set, canonical_test_result, \
             canonical_receipt, canonical_event\
         ) SELECT tenant_id, project, $3, $4, bootstrap_statement_id, \
                  bootstrap_receipt_digest, bootstrap_event_id, genesis_epoch_id, \
                  genesis_package_digest, bootstrap_signer_policy_digest, profile_id, \
                  profile_digest, vector_manifest_digest, contract_tenant_namespace, \
                  contract_project_namespace, activated_package_digest, \
                  activated_policy_digest, test_result_digest, proposer_principal_id, \
                  package_author_principal_id, approval_ids_packed, approval_count, \
                  required_threshold, separation_of_duty_satisfied, bootstrap_accepted_at, \
                  effective_from, effective_until, $5, $6, $7, $8, $9, canonical_statement, \
                  canonical_approval_set, canonical_test_result, canonical_receipt, canonical_event \
         FROM memory_registry_activations \
         WHERE tenant_id = $1 AND project = $2 LIMIT 1",
    )
    .bind(scope.tenant_id)
    .bind(&scope.project)
    .bind(activation_id.as_bytes().to_vec())
    .bind(statement_id.as_bytes().to_vec())
    .bind(accepted_at)
    .bind(activation_id.as_bytes().to_vec())
    .bind(position.epoch_id.digest().as_bytes().to_vec())
    .bind(i32::from(position.shard))
    .bind(offset)
    .execute(pool)
    .await
    .unwrap();
    assert_eq!(inserted.rows_affected(), 1);
}

async fn plant_max_offset_tail(
    pool: &PgPool,
    scope: &FleetScope,
    fixture: &ContractFixture,
    authority: &BootstrapAuthority,
) {
    let shard = activation_shard(fixture, authority);
    let epoch_id = authority.bootstrap.epoch_id();
    let arbitrary_previous = domain_separated_digest(
        DigestDomain::AppendChain,
        b"detached-max-offset-predecessor",
    );
    let accepted_at: DateTime<Utc> = sqlx::query_scalar("SELECT statement_timestamp()")
        .fetch_one(pool)
        .await
        .unwrap();
    let mut previous_chain = arbitrary_previous;
    let mut final_chain = arbitrary_previous;
    for (offset, marker) in [
        (i64::MAX - 1, "max-offset-predecessor"),
        (i64::MAX, "max-offset-tip"),
    ] {
        let position = AppendPositionV1 {
            epoch_id,
            shard,
            committed_offset: CommittedOffsetV1::new(u64::try_from(offset).unwrap()).unwrap(),
        };
        let event_id = AcceptedEventId::from_digest(domain_separated_digest(
            DigestDomain::AcceptedEvent,
            marker.as_bytes(),
        ));
        let chain = append_chain(previous_chain, event_id, &position);
        sqlx::query(
            "INSERT INTO memory_control_events (\
                 tenant_id, project, epoch_id, shard, committed_offset, event_id, \
                 event_schema_version, event_kind, semantic_object_digest, consistency_family, \
                 consistency_key_digest, canonical_event, previous_chain_digest, chain_digest, \
                 accepted_at\
             ) VALUES ($1, $2, $3, $4, $5, $6, 1, 'test.detached.max', $7, \
                       'test.detached.max', $8, $9, $10, $11, $12)",
        )
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(epoch_id.digest().as_bytes().to_vec())
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
        .execute(pool)
        .await
        .unwrap();
        previous_chain = chain;
        final_chain = chain;
    }
    let updated = sqlx::query(
        "UPDATE memory_control_shard_heads \
         SET last_committed_offset = $5, chain_digest = $6, advanced_at = $7 \
         WHERE tenant_id = $1 AND project = $2 AND epoch_id = $3 AND shard = $4",
    )
    .bind(scope.tenant_id)
    .bind(&scope.project)
    .bind(epoch_id.digest().as_bytes().to_vec())
    .bind(i32::from(shard))
    .bind(i64::MAX)
    .bind(final_chain.as_bytes().to_vec())
    .bind(accepted_at)
    .execute(pool)
    .await
    .unwrap();
    assert_eq!(updated.rows_affected(), 1);
}

fn activation_shard(fixture: &ContractFixture, authority: &BootstrapAuthority) -> u16 {
    authority
        .bootstrap
        .partition_for(
            &registry_activation_consistency_partition_key(&fixture.semantic_scope).unwrap(),
        )
        .unwrap()
}

async fn assert_single_timestamp_receipt(
    pool: &PgPool,
    scope: &FleetScope,
    outcome: &GenesisActivationOutcome,
) {
    let accepted = match outcome {
        GenesisActivationOutcome::Inserted(value)
        | GenesisActivationOutcome::ExactReplay(value) => value,
    };
    let expected = DateTime::parse_from_rfc3339(accepted.accepted_at.as_str())
        .unwrap()
        .with_timezone(&Utc);
    let row = sqlx::query(
        "SELECT a.accepted_at, e.accepted_at AS event_accepted_at, \
                h.activated_at, s.advanced_at \
         FROM memory_registry_activations AS a \
         JOIN memory_control_events AS e ON e.tenant_id = a.tenant_id \
          AND e.project = a.project AND e.event_id = a.accepted_event_id \
         JOIN memory_registry_heads AS h ON h.tenant_id = a.tenant_id \
          AND h.project = a.project AND h.activation_id = a.activation_id \
         JOIN memory_control_shard_heads AS s ON s.tenant_id = a.tenant_id \
          AND s.project = a.project AND s.epoch_id = a.control_epoch_id \
          AND s.shard = a.control_shard \
         WHERE a.tenant_id = $1 AND a.project = $2",
    )
    .bind(scope.tenant_id)
    .bind(&scope.project)
    .fetch_one(pool)
    .await
    .unwrap();
    for column in [
        "accepted_at",
        "event_accepted_at",
        "activated_at",
        "advanced_at",
    ] {
        assert_eq!(row.get::<DateTime<Utc>, _>(column), expected);
    }
}

async fn cleanup_scope(pool: &PgPool, scope: &FleetScope) {
    for statement in [
        "DELETE FROM memory_registry_heads WHERE tenant_id = $1 AND project = $2",
        "DELETE FROM memory_registry_activations WHERE tenant_id = $1 AND project = $2",
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

async fn assert_registry_endpoint_plans(
    pool: &PgPool,
    scope: &FleetScope,
    fixture: &ContractFixture,
    authority: &BootstrapAuthority,
) {
    let key = registry_activation_consistency_partition_key(&fixture.semantic_scope).unwrap();
    for order in [
        "ORDER BY shard, committed_offset LIMIT 2",
        "ORDER BY shard DESC, committed_offset DESC LIMIT 2",
    ] {
        let query = format!(
            "EXPLAIN (OPT) SELECT event_id, shard, committed_offset \
             FROM memory_control_events \
             WHERE tenant_id = $1 AND project = $2 AND epoch_id = $3 \
               AND consistency_family = $4 AND consistency_key_digest = $5 {order}"
        );
        let plan = sqlx::query_scalar::<_, String>(&query)
            .bind(scope.tenant_id)
            .bind(&scope.project)
            .bind(authority.bootstrap.epoch_id().digest().as_bytes().to_vec())
            .bind("registry.activation")
            .bind(key.key_digest.as_bytes().to_vec())
            .fetch_all(pool)
            .await
            .unwrap()
            .join("\n");
        assert!(plan.contains("memory_control_events_consistency_stream_idx"));
        assert!(plan.contains("limit: 2"));
    }

    let selected_shard = activation_shard(fixture, authority);
    let ahead_plan = sqlx::query_scalar::<_, String>(
        "EXPLAIN (OPT, VERBOSE) SELECT event_id FROM memory_control_events \
         WHERE tenant_id = $1 AND project = $2 AND epoch_id = $3 AND shard = $4 \
           AND committed_offset > $5 ORDER BY committed_offset LIMIT 1",
    )
    .bind(scope.tenant_id)
    .bind(&scope.project)
    .bind(authority.bootstrap.epoch_id().digest().as_bytes().to_vec())
    .bind(i32::from(selected_shard))
    .bind(0_i64)
    .fetch_all(pool)
    .await
    .unwrap()
    .join("\n");
    assert!(ahead_plan.contains("scan memory_control_events"));
    assert!(ahead_plan.contains("constraint: /1/2/3/4/5"));
    assert!(ahead_plan.contains("limit: 1"));
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn live_genesis_registry_activation_when_configured() {
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

    let same_authority = bootstrap_for_shard_relation(&fixture, true);
    let different_authority = bootstrap_for_shard_relation(&fixture, false);
    assert_eq!(
        activation_shard(&fixture, &same_authority),
        same_authority.append.append_position.shard
    );
    assert_ne!(
        activation_shard(&fixture, &different_authority),
        different_authority.append.append_position.shard
    );

    // The complete successful migration prefix through 9 is an exact authority
    // preflight: neither a later row nor any failed predecessor opens this repository.
    let schema_scope = physical_scope("schema-preflight");
    let schema_repository =
        activation_repository(pool.clone(), &schema_scope, &fixture, &same_authority);
    let schema_request = activation_request(
        &fixture,
        &same_authority,
        canonical_time(server_time(&pool).await),
        [1, 2],
    );
    assert_registry_endpoint_plans(&pool, &schema_scope, &fixture, &same_authority).await;
    sqlx::query("UPDATE _sqlx_migrations SET version = 9999 WHERE version = 9")
        .execute(&pool)
        .await
        .unwrap();
    let v8_only = schema_repository
        .inspect_genesis_activation(&schema_request)
        .await
        .unwrap_err();
    assert!(matches!(
        v8_only,
        FleetError::GenesisActivationSchemaUnavailable
    ));
    sqlx::query(
        "INSERT INTO _sqlx_migrations \
             (version, description, installed_on, success, checksum, execution_time) \
         SELECT 9, description, installed_on, false, checksum, execution_time \
         FROM _sqlx_migrations WHERE version = 9999",
    )
    .execute(&pool)
    .await
    .unwrap();
    let failed_v9 = schema_repository
        .inspect_genesis_activation(&schema_request)
        .await
        .unwrap_err();
    assert!(matches!(
        failed_v9,
        FleetError::GenesisActivationSchemaUnavailable
    ));
    assert_eq!(store.capabilities().await.unwrap().schema_version, 8);
    sqlx::query("DELETE FROM _sqlx_migrations WHERE version = 9")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE _sqlx_migrations SET version = 9 WHERE version = 9999")
        .execute(&pool)
        .await
        .unwrap();

    for failed_version in [5_i64, 4] {
        sqlx::query("UPDATE _sqlx_migrations SET success = false WHERE version = $1")
            .bind(failed_version)
            .execute(&pool)
            .await
            .unwrap();
        let failed_prefix = schema_repository
            .inspect_genesis_activation(&schema_request)
            .await
            .unwrap_err();
        assert!(matches!(
            failed_prefix,
            FleetError::GenesisActivationSchemaUnavailable
        ));
        sqlx::query("UPDATE _sqlx_migrations SET success = true WHERE version = $1")
            .bind(failed_version)
            .execute(&pool)
            .await
            .unwrap();
    }
    let not_ready = schema_repository
        .inspect_genesis_activation(&schema_request)
        .await
        .unwrap_err();
    assert!(matches!(not_ready, FleetError::GenesisActivationNotReady));

    let mut cleanup = Vec::new();
    for (label, authority) in [
        ("same-shard", &same_authority),
        ("different-shard", &different_authority),
    ] {
        let scope = physical_scope(label);
        cleanup.push(scope.clone());
        bootstrap_scope(&pool, &scope, &fixture, authority).await;
        let repository = activation_repository(pool.clone(), &scope, &fixture, authority);
        let effective = canonical_time(server_time(&pool).await);
        let request = activation_request(&fixture, authority, effective, [1, 2]);
        assert!(matches!(
            repository
                .inspect_genesis_activation(&request)
                .await
                .unwrap(),
            GenesisActivationInspection::PinnedInactive(_)
        ));

        let selected_shard = activation_shard(&fixture, authority);
        append_control_event(
            &pool,
            &scope,
            authority,
            selected_shard,
            &format!("{label}-unrelated-predecessor"),
            false,
        )
        .await;
        let first = repository.activate_genesis(&request).await.unwrap();
        let GenesisActivationOutcome::Inserted(inserted) = &first else {
            panic!("fresh activation must insert");
        };
        assert!(inserted.append_position.committed_offset.as_u64() >= 2);
        assert_single_timestamp_receipt(&pool, &scope, &first).await;
        assert_eq!(
            repository.activate_genesis(&request).await.unwrap(),
            GenesisActivationOutcome::ExactReplay(inserted.clone())
        );
        assert_eq!(
            repository
                .inspect_genesis_activation(&request)
                .await
                .unwrap(),
            GenesisActivationInspection::Accepted(inserted.clone())
        );

        append_control_event(
            &pool,
            &scope,
            authority,
            selected_shard,
            &format!("{label}-later-control-suffix"),
            false,
        )
        .await;
        assert_eq!(
            repository.activate_genesis(&request).await.unwrap(),
            GenesisActivationOutcome::ExactReplay(inserted.clone())
        );
        assert_eq!(
            scoped_count(&pool, "memory_registry_activations", &scope).await,
            1
        );
        assert_eq!(
            scoped_count(&pool, "memory_registry_heads", &scope).await,
            1
        );
        assert_eq!(scoped_count(&pool, "memory_events", &scope).await, 0);
    }

    // Identical contenders converge; distinct, independently valid statements
    // serialize on the stable registry shard and exactly one becomes genesis.
    let concurrent_scope = physical_scope("concurrent-identical");
    cleanup.push(concurrent_scope.clone());
    bootstrap_scope(&pool, &concurrent_scope, &fixture, &same_authority).await;
    let concurrent_repository =
        activation_repository(pool.clone(), &concurrent_scope, &fixture, &same_authority);
    let concurrent_request = activation_request(
        &fixture,
        &same_authority,
        canonical_time(server_time(&pool).await),
        [1, 2],
    );
    let outcomes =
        join_all((0..16).map(|_| concurrent_repository.activate_genesis(&concurrent_request)))
            .await;
    let mut inserted = 0;
    let mut replayed = 0;
    for outcome in outcomes {
        match outcome.unwrap() {
            GenesisActivationOutcome::Inserted(_) => inserted += 1,
            GenesisActivationOutcome::ExactReplay(_) => replayed += 1,
        }
    }
    assert_eq!((inserted, replayed), (1, 15));

    let race_scope = physical_scope("concurrent-distinct");
    cleanup.push(race_scope.clone());
    bootstrap_scope(&pool, &race_scope, &fixture, &different_authority).await;
    let race_repository =
        activation_repository(pool.clone(), &race_scope, &fixture, &different_authority);
    let race_now = server_time(&pool).await;
    let first_request = activation_request(
        &fixture,
        &different_authority,
        canonical_time(race_now - ChronoDuration::microseconds(1)),
        [1, 2],
    );
    let second_request = activation_request(
        &fixture,
        &different_authority,
        canonical_time(race_now),
        [1, 2],
    );
    let (left, right) = tokio::join!(
        race_repository.activate_genesis(&first_request),
        race_repository.activate_genesis(&second_request)
    );
    let results: [_; 2] = (left, right).into();
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Ok(GenesisActivationOutcome::Inserted(_))))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(FleetError::GenesisActivationStale)))
            .count(),
        1
    );

    // One statement digest cannot be replayed with a different valid approval
    // ceremony, and verified statements still obey durable/server time bounds.
    let conflict_scope = physical_scope("approval-conflict");
    cleanup.push(conflict_scope.clone());
    bootstrap_scope(&pool, &conflict_scope, &fixture, &same_authority).await;
    let conflict_repository =
        activation_repository(pool.clone(), &conflict_scope, &fixture, &same_authority);
    let conflict_effective = canonical_time(server_time(&pool).await);
    let first_approvals = activation_request(
        &fixture,
        &same_authority,
        conflict_effective.clone(),
        [1, 2],
    );
    let changed_approvals =
        activation_request(&fixture, &same_authority, conflict_effective, [1, 3]);
    conflict_repository
        .activate_genesis(&first_approvals)
        .await
        .unwrap();
    let approval_error = conflict_repository
        .activate_genesis(&changed_approvals)
        .await
        .unwrap_err();
    assert!(matches!(
        approval_error,
        FleetError::GenesisActivationConflict(GenesisActivationConflictKind::ApprovalSet)
    ));

    let timing_scope = physical_scope("timing");
    cleanup.push(timing_scope.clone());
    bootstrap_scope(&pool, &timing_scope, &fixture, &different_authority).await;
    let timing_repository =
        activation_repository(pool.clone(), &timing_scope, &fixture, &different_authority);
    let accepted_bootstrap_at = bootstrap_time(&pool, &timing_scope).await;
    let before_bootstrap = activation_request(
        &fixture,
        &different_authority,
        canonical_time(accepted_bootstrap_at - ChronoDuration::microseconds(1)),
        [1, 2],
    );
    assert!(matches!(
        timing_repository
            .activate_genesis(&before_bootstrap)
            .await
            .unwrap_err(),
        FleetError::GenesisActivationTiming(GenesisActivationTimingKind::BeforeBootstrap)
    ));
    let future_effective = activation_request(
        &fixture,
        &different_authority,
        canonical_time(server_time(&pool).await + ChronoDuration::minutes(5)),
        [1, 2],
    );
    assert!(matches!(
        timing_repository
            .activate_genesis(&future_effective)
            .await
            .unwrap_err(),
        FleetError::GenesisActivationTiming(GenesisActivationTimingKind::FutureEffective)
    ));
    assert_eq!(
        scoped_count(&pool, "memory_registry_activations", &timing_scope).await,
        0
    );

    // The repository is physically and semantically construction-bound; an
    // active neighboring scope supplies no authority or visibility.
    let isolated_scope = physical_scope("scope-isolation");
    let isolated_repository =
        activation_repository(pool.clone(), &isolated_scope, &fixture, &same_authority);
    let isolated_error = isolated_repository
        .inspect_genesis_activation(&first_approvals)
        .await
        .unwrap_err();
    assert!(matches!(
        isolated_error,
        FleetError::GenesisActivationNotReady
    ));
    assert_eq!(
        scoped_count(&pool, "memory_registry_heads", &isolated_scope).await,
        0
    );

    // An accepted historical prefix still requires its exact current head in
    // the genesis-only schema. Missing projections and unprojected stream
    // events are corruption, never replay or repair invitations.
    let missing_head_scope = physical_scope("missing-head");
    cleanup.push(missing_head_scope.clone());
    bootstrap_scope(&pool, &missing_head_scope, &fixture, &same_authority).await;
    let missing_head_repository =
        activation_repository(pool.clone(), &missing_head_scope, &fixture, &same_authority);
    let missing_head_request = activation_request(
        &fixture,
        &same_authority,
        canonical_time(server_time(&pool).await),
        [1, 2],
    );
    missing_head_repository
        .activate_genesis(&missing_head_request)
        .await
        .unwrap();
    sqlx::query("DELETE FROM memory_registry_heads WHERE tenant_id = $1 AND project = $2")
        .bind(missing_head_scope.tenant_id)
        .bind(&missing_head_scope.project)
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(
        missing_head_repository
            .activate_genesis(&missing_head_request)
            .await
            .unwrap_err(),
        FleetError::RegistryActivationCorrupt(_)
    ));

    let extra_projection_scope = physical_scope("extra-activation-projection");
    cleanup.push(extra_projection_scope.clone());
    bootstrap_scope(&pool, &extra_projection_scope, &fixture, &same_authority).await;
    let extra_projection_repository = activation_repository(
        pool.clone(),
        &extra_projection_scope,
        &fixture,
        &same_authority,
    );
    let extra_projection_request = activation_request(
        &fixture,
        &same_authority,
        canonical_time(server_time(&pool).await),
        [1, 2],
    );
    extra_projection_repository
        .activate_genesis(&extra_projection_request)
        .await
        .unwrap();
    plant_extra_activation_projection(&pool, &extra_projection_scope, &fixture, &same_authority)
        .await;
    assert_eq!(
        scoped_count(
            &pool,
            "memory_registry_activations",
            &extra_projection_scope,
        )
        .await,
        2
    );
    assert!(matches!(
        extra_projection_repository
            .inspect_genesis_activation(&extra_projection_request)
            .await
            .unwrap_err(),
        FleetError::RegistryActivationCorrupt(_)
    ));

    let orphan_tip_scope = physical_scope("orphan-registry-tip");
    cleanup.push(orphan_tip_scope.clone());
    bootstrap_scope(&pool, &orphan_tip_scope, &fixture, &same_authority).await;
    let orphan_tip_repository =
        activation_repository(pool.clone(), &orphan_tip_scope, &fixture, &same_authority);
    let orphan_tip_request = activation_request(
        &fixture,
        &same_authority,
        canonical_time(server_time(&pool).await),
        [1, 2],
    );
    orphan_tip_repository
        .activate_genesis(&orphan_tip_request)
        .await
        .unwrap();
    append_control_event(
        &pool,
        &orphan_tip_scope,
        &same_authority,
        activation_shard(&fixture, &same_authority),
        "orphan-latest-registry-event",
        true,
    )
    .await;
    assert!(matches!(
        orphan_tip_repository
            .inspect_genesis_activation(&orphan_tip_request)
            .await
            .unwrap_err(),
        FleetError::RegistryActivationCorrupt(_)
    ));

    let wrong_shard_scope = physical_scope("wrong-shard-stream");
    cleanup.push(wrong_shard_scope.clone());
    bootstrap_scope(&pool, &wrong_shard_scope, &fixture, &different_authority).await;
    let wrong_shard_repository = activation_repository(
        pool.clone(),
        &wrong_shard_scope,
        &fixture,
        &different_authority,
    );
    let wrong_shard_request = activation_request(
        &fixture,
        &different_authority,
        canonical_time(server_time(&pool).await),
        [1, 2],
    );
    wrong_shard_repository
        .activate_genesis(&wrong_shard_request)
        .await
        .unwrap();
    let expected_shard = activation_shard(&fixture, &different_authority);
    let shard_count = different_authority
        .bootstrap
        .receipt()
        .statement
        .genesis_epoch
        .partition_recipe
        .shard_count;
    append_control_event(
        &pool,
        &wrong_shard_scope,
        &different_authority,
        (expected_shard + 1) % shard_count,
        "wrong-shard-registry-event",
        true,
    )
    .await;
    assert!(matches!(
        wrong_shard_repository
            .activate_genesis(&wrong_shard_request)
            .await
            .unwrap_err(),
        FleetError::RegistryActivationCorrupt(_)
    ));

    // A malicious future-dated unrelated tail is internally consistent but
    // cannot force a newly chosen server acceptance time backward.
    let future_tail_scope = physical_scope("future-tail");
    cleanup.push(future_tail_scope.clone());
    bootstrap_scope(&pool, &future_tail_scope, &fixture, &same_authority).await;
    let future_tail_shard = activation_shard(&fixture, &same_authority);
    let future_position = append_control_event(
        &pool,
        &future_tail_scope,
        &same_authority,
        future_tail_shard,
        "future-unrelated-tail",
        false,
    )
    .await;
    sqlx::query(
        "UPDATE memory_control_events SET accepted_at = accepted_at + INTERVAL '1 hour' \
         WHERE tenant_id = $1 AND project = $2 AND epoch_id = $3 AND shard = $4 \
           AND committed_offset = $5",
    )
    .bind(future_tail_scope.tenant_id)
    .bind(&future_tail_scope.project)
    .bind(future_position.epoch_id.digest().as_bytes().to_vec())
    .bind(i32::from(future_position.shard))
    .bind(i64::try_from(future_position.committed_offset.as_u64()).unwrap())
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE memory_control_shard_heads SET advanced_at = advanced_at + INTERVAL '1 hour' \
         WHERE tenant_id = $1 AND project = $2 AND epoch_id = $3 AND shard = $4",
    )
    .bind(future_tail_scope.tenant_id)
    .bind(&future_tail_scope.project)
    .bind(future_position.epoch_id.digest().as_bytes().to_vec())
    .bind(i32::from(future_position.shard))
    .execute(&pool)
    .await
    .unwrap();
    let future_tail_repository =
        activation_repository(pool.clone(), &future_tail_scope, &fixture, &same_authority);
    let future_tail_request = activation_request(
        &fixture,
        &same_authority,
        canonical_time(server_time(&pool).await),
        [1, 2],
    );
    assert!(matches!(
        future_tail_repository
            .activate_genesis(&future_tail_request)
            .await
            .unwrap_err(),
        FleetError::RegistryActivationCorrupt(_)
    ));

    // A detached event beyond the authoritative head wedges the selected
    // append range even when it is unrelated to the registry stream. Both a
    // fresh ceremony and replay detect the bounded PK-range orphan.
    let orphan_ahead_fresh_scope = physical_scope("orphan-ahead-fresh");
    cleanup.push(orphan_ahead_fresh_scope.clone());
    bootstrap_scope(&pool, &orphan_ahead_fresh_scope, &fixture, &same_authority).await;
    plant_event_ahead_of_head(
        &pool,
        &orphan_ahead_fresh_scope,
        &fixture,
        &same_authority,
        "orphan-ahead-fresh",
    )
    .await;
    let orphan_ahead_fresh_repository = activation_repository(
        pool.clone(),
        &orphan_ahead_fresh_scope,
        &fixture,
        &same_authority,
    );
    let orphan_ahead_fresh_request = activation_request(
        &fixture,
        &same_authority,
        canonical_time(server_time(&pool).await),
        [1, 2],
    );
    assert!(matches!(
        orphan_ahead_fresh_repository
            .activate_genesis(&orphan_ahead_fresh_request)
            .await
            .unwrap_err(),
        FleetError::RegistryActivationCorrupt(_)
    ));
    assert_eq!(
        scoped_count(
            &pool,
            "memory_registry_activations",
            &orphan_ahead_fresh_scope,
        )
        .await,
        0
    );

    let orphan_ahead_replay_scope = physical_scope("orphan-ahead-replay");
    cleanup.push(orphan_ahead_replay_scope.clone());
    bootstrap_scope(
        &pool,
        &orphan_ahead_replay_scope,
        &fixture,
        &different_authority,
    )
    .await;
    let orphan_ahead_replay_repository = activation_repository(
        pool.clone(),
        &orphan_ahead_replay_scope,
        &fixture,
        &different_authority,
    );
    let orphan_ahead_replay_request = activation_request(
        &fixture,
        &different_authority,
        canonical_time(server_time(&pool).await),
        [1, 2],
    );
    orphan_ahead_replay_repository
        .activate_genesis(&orphan_ahead_replay_request)
        .await
        .unwrap();
    plant_event_ahead_of_head(
        &pool,
        &orphan_ahead_replay_scope,
        &fixture,
        &different_authority,
        "orphan-ahead-replay",
    )
    .await;
    assert!(matches!(
        orphan_ahead_replay_repository
            .inspect_genesis_activation(&orphan_ahead_replay_request)
            .await
            .unwrap_err(),
        FleetError::RegistryActivationCorrupt(_)
    ));

    // Stored replay re-audits the activation's immediate predecessor and the
    // current control append point. Timestamp inversion, broken chain math,
    // and a missing immediate event all fail closed.
    let predecessor_time_scope = physical_scope("predecessor-time");
    cleanup.push(predecessor_time_scope.clone());
    bootstrap_scope(
        &pool,
        &predecessor_time_scope,
        &fixture,
        &different_authority,
    )
    .await;
    let predecessor_shard = activation_shard(&fixture, &different_authority);
    let predecessor_position = append_control_event(
        &pool,
        &predecessor_time_scope,
        &different_authority,
        predecessor_shard,
        "activation-predecessor-time",
        false,
    )
    .await;
    let predecessor_time_repository = activation_repository(
        pool.clone(),
        &predecessor_time_scope,
        &fixture,
        &different_authority,
    );
    let predecessor_time_request = activation_request(
        &fixture,
        &different_authority,
        canonical_time(server_time(&pool).await),
        [1, 2],
    );
    predecessor_time_repository
        .activate_genesis(&predecessor_time_request)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE memory_control_events \
         SET accepted_at = (\
             SELECT accepted_at + INTERVAL '1 microsecond' \
             FROM memory_registry_activations WHERE tenant_id = $1 AND project = $2\
         ) WHERE tenant_id = $1 AND project = $2 AND epoch_id = $3 AND shard = $4 \
             AND committed_offset = $5",
    )
    .bind(predecessor_time_scope.tenant_id)
    .bind(&predecessor_time_scope.project)
    .bind(predecessor_position.epoch_id.digest().as_bytes().to_vec())
    .bind(i32::from(predecessor_position.shard))
    .bind(i64::try_from(predecessor_position.committed_offset.as_u64()).unwrap())
    .execute(&pool)
    .await
    .unwrap();
    assert!(matches!(
        predecessor_time_repository
            .activate_genesis(&predecessor_time_request)
            .await
            .unwrap_err(),
        FleetError::RegistryActivationCorrupt(_)
    ));

    let broken_tip_scope = physical_scope("broken-control-tip");
    cleanup.push(broken_tip_scope.clone());
    bootstrap_scope(&pool, &broken_tip_scope, &fixture, &same_authority).await;
    let broken_tip_repository =
        activation_repository(pool.clone(), &broken_tip_scope, &fixture, &same_authority);
    let broken_tip_request = activation_request(
        &fixture,
        &same_authority,
        canonical_time(server_time(&pool).await),
        [1, 2],
    );
    broken_tip_repository
        .activate_genesis(&broken_tip_request)
        .await
        .unwrap();
    let broken_tip_position = append_control_event(
        &pool,
        &broken_tip_scope,
        &same_authority,
        activation_shard(&fixture, &same_authority),
        "broken-control-tip",
        false,
    )
    .await;
    sqlx::query(
        "UPDATE memory_control_events SET previous_chain_digest = $6 \
         WHERE tenant_id = $1 AND project = $2 AND epoch_id = $3 AND shard = $4 \
           AND committed_offset = $5",
    )
    .bind(broken_tip_scope.tenant_id)
    .bind(&broken_tip_scope.project)
    .bind(broken_tip_position.epoch_id.digest().as_bytes().to_vec())
    .bind(i32::from(broken_tip_position.shard))
    .bind(i64::try_from(broken_tip_position.committed_offset.as_u64()).unwrap())
    .bind(
        domain_separated_digest(DigestDomain::AppendChain, b"tampered-tip-previous")
            .as_bytes()
            .to_vec(),
    )
    .execute(&pool)
    .await
    .unwrap();
    assert!(matches!(
        broken_tip_repository
            .inspect_genesis_activation(&broken_tip_request)
            .await
            .unwrap_err(),
        FleetError::RegistryActivationCorrupt(_)
    ));

    let missing_gap_scope = physical_scope("missing-control-gap");
    cleanup.push(missing_gap_scope.clone());
    bootstrap_scope(&pool, &missing_gap_scope, &fixture, &same_authority).await;
    let missing_gap_repository =
        activation_repository(pool.clone(), &missing_gap_scope, &fixture, &same_authority);
    let missing_gap_request = activation_request(
        &fixture,
        &same_authority,
        canonical_time(server_time(&pool).await),
        [1, 2],
    );
    missing_gap_repository
        .activate_genesis(&missing_gap_request)
        .await
        .unwrap();
    let missing_position = append_control_event(
        &pool,
        &missing_gap_scope,
        &same_authority,
        activation_shard(&fixture, &same_authority),
        "missing-gap-predecessor",
        false,
    )
    .await;
    append_control_event(
        &pool,
        &missing_gap_scope,
        &same_authority,
        activation_shard(&fixture, &same_authority),
        "missing-gap-tip",
        false,
    )
    .await;
    sqlx::query(
        "DELETE FROM memory_control_events \
         WHERE tenant_id = $1 AND project = $2 AND epoch_id = $3 AND shard = $4 \
           AND committed_offset = $5",
    )
    .bind(missing_gap_scope.tenant_id)
    .bind(&missing_gap_scope.project)
    .bind(missing_position.epoch_id.digest().as_bytes().to_vec())
    .bind(i32::from(missing_position.shard))
    .bind(i64::try_from(missing_position.committed_offset.as_u64()).unwrap())
    .execute(&pool)
    .await
    .unwrap();
    assert!(matches!(
        missing_gap_repository
            .activate_genesis(&missing_gap_request)
            .await
            .unwrap_err(),
        FleetError::RegistryActivationCorrupt(_)
    ));

    // A validly shaped stored INT8 tip at the numerical ceiling is database
    // corruption, not a candidate contract error or a wrapped offset.
    let overflow_scope = physical_scope("offset-overflow");
    cleanup.push(overflow_scope.clone());
    bootstrap_scope(&pool, &overflow_scope, &fixture, &different_authority).await;
    plant_max_offset_tail(&pool, &overflow_scope, &fixture, &different_authority).await;
    let overflow_repository = activation_repository(
        pool.clone(),
        &overflow_scope,
        &fixture,
        &different_authority,
    );
    let overflow_request = activation_request(
        &fixture,
        &different_authority,
        canonical_time(server_time(&pool).await),
        [1, 2],
    );
    assert!(matches!(
        overflow_repository
            .activate_genesis(&overflow_request)
            .await
            .unwrap_err(),
        FleetError::RegistryActivationCorrupt(_)
    ));

    for scope in &cleanup {
        cleanup_scope(&pool, scope).await;
    }
}
