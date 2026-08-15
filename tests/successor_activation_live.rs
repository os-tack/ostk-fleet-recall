//! Connected proof for the private first-successor activation repository.
//!
//! Set the exact `FLEET_RECALL_TEST_DATABASE_URL` variable to a disposable
//! `CockroachDB` 26.2 database. The test is inert otherwise. It never starts a
//! database process, invokes Docker, or targets a cloud service.

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use futures::future::join_all;
use ostk_fleet_recall::control_log::{
    CockroachGenesisRepository, GenesisRepository, TrustedControlScope,
};
use ostk_fleet_recall::error::SuccessorActivationTimingKind;
use ostk_fleet_recall::memory_contracts::bootstrap::{
    AppendPositionV1, BootstrapAttestationV1, BootstrapPin, BootstrapReceiptDigest,
    BootstrapReceiptV1, CommittedOffsetV1, VerifiedBootstrapReceipt, verify_pinned_bootstrap,
};
use ostk_fleet_recall::memory_contracts::canonical::{decode_strict, encode_canonical};
use ostk_fleet_recall::memory_contracts::common::{
    AuthenticatedProjectScopeV1, CanonicalTimestamp, ContractId, FixedHex32, FixedHex64,
    ProfileReferenceV1, RegistryReferenceV1, frozen_profile_reference_v1,
};
use ostk_fleet_recall::memory_contracts::digest::{
    DigestDomain, Sha256Digest, domain_separated_digest, framed_digest,
};
use ostk_fleet_recall::memory_contracts::evidence_v2::RegistryHeadBindingV1;
use ostk_fleet_recall::memory_contracts::genesis::SemanticallyClosedGenesisPackage;
use ostk_fleet_recall::memory_contracts::genesis_activation::{
    GenesisActivationPrincipalBinding, GenesisRegistryActivationApprovalSetV1,
    GenesisRegistryActivationApprovalV1, GenesisRegistryActivationStatementV1,
    GenesisRegistryAnchorV1, RegistryTestResultDigest, RegistryTestRunnerPin,
    VerifiedRegistryTestResult, genesis_activation_policy_digest,
    registry_activation_consistency_partition_key, verify_genesis_registry_activation,
    verify_registry_test_result,
};
use ostk_fleet_recall::memory_contracts::registry::{
    ManifestVerifiedRegistryPackage, RegistryEntryKind,
};
use ostk_fleet_recall::memory_contracts::stage4_target_package::SemanticallyClosedStage4Package;
use ostk_fleet_recall::memory_contracts::successor_activation::{
    SuccessorActivationPrincipalBinding, SuccessorRegistryActivationApprovalSetV1,
    SuccessorRegistryActivationApprovalV1, SuccessorRegistryActivationStatementV1,
    SuccessorRegistryTestRunnerPin, verify_successor_registry_test_result,
};
use ostk_fleet_recall::memory_contracts::successor_package::SemanticallyClosedSuccessorPackage;
use ostk_fleet_recall::memory_contracts::successor_policy::{
    ActivationSignatureAlgorithmV2, ActivationSignerBindingV2, GenesisSuccessorKeyBridgeDigest,
    GenesisSuccessorKeyBridgePin, GenesisSuccessorKeyBridgeV1,
};
use ostk_fleet_recall::registry_activation::{
    CockroachGenesisActivationRepository, CockroachSuccessorActivationRepository,
    GenesisActivationOutcome, GenesisActivationRepository, SuccessorActivationCandidate,
    SuccessorActivationInspection, SuccessorActivationOutcome, SuccessorActivationRepository,
};
use ostk_fleet_recall::store::cockroach::{CockroachStore, PoolConfig, RetryPolicy};
use ostk_fleet_recall::{FleetError, FleetScope};
use ostk_recall_core::PrivacyTier;
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use sqlx::{PgPool, Row};
use tokio::sync::Barrier;
use uuid::Uuid;

const GENESIS_PACKAGE: &[u8] =
    include_bytes!("../contracts/dynamic-memory/v1/genesis-registry-package.jsonl");
const BOOTSTRAP_RECEIPT: &[u8] =
    include_bytes!("../contracts/dynamic-memory/v1/bootstrap-receipt.jsonl");
const GENESIS_TEST_RESULT: &[u8] =
    include_bytes!("../contracts/dynamic-memory/v1/genesis-activation/registry-test-result.jsonl");
const TARGET_PACKAGE: &[u8] =
    include_bytes!("../contracts/dynamic-memory/v2/stage4-successor/registry-package.jsonl");
const SUCCESSOR_TEST_RESULT: &[u8] = include_bytes!(
    "../contracts/dynamic-memory/v2/successor-activation/registry-test-result.jsonl"
);

const GENESIS_TEST_RESULT_DIGEST: &str =
    "e91e08070250a722446195b76ee685a9697298b9fdce9809027f120c829b679d";
const GENESIS_RUNNER_ARTIFACT: &str =
    "c2e5b0653471d35e54600a8d3fbe5613aff4c04e911787c09a25e2b327d4bbbd";
const GENESIS_RUNNER_CONFIGURATION: &str =
    "1d12aabe349fd0013389f93bf1917b0de6bbd5d2bd7156c85faff0b97360686d";
const SUCCESSOR_TEST_RESULT_DIGEST: &str =
    "e6783b2a018957a5861fe4e0670f55613d1ace35e381a6a9f5190ea9d7fbff8d";
const SUCCESSOR_RUNNER_ARTIFACT: &str =
    "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
const SUCCESSOR_RUNNER_CONFIGURATION: &str =
    "a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2";

#[derive(Clone)]
struct ContractFixture {
    profile: ProfileReferenceV1,
    semantic_scope: AuthenticatedProjectScopeV1,
    genesis_package: SemanticallyClosedGenesisPackage,
    genesis_test_result: VerifiedRegistryTestResult,
    genesis_principal_binding: GenesisActivationPrincipalBinding,
    target: SemanticallyClosedStage4Package,
}

#[derive(Clone)]
struct BootstrapAuthority {
    bootstrap: VerifiedBootstrapReceipt,
}

struct ActivatedGenesis {
    physical_scope: FleetScope,
    authority: BootstrapAuthority,
    head: RegistryHeadBindingV1,
    accepted_at: CanonicalTimestamp,
}

struct SuccessorCeremony {
    bridge_bytes: Vec<u8>,
    bridge_pin: GenesisSuccessorKeyBridgePin,
    bridge_digest: GenesisSuccessorKeyBridgeDigest,
    candidate: SuccessorActivationCandidate,
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
    let genesis_manifest =
        ManifestVerifiedRegistryPackage::decode(record(GENESIS_PACKAGE), &profile).unwrap();
    let genesis_package =
        SemanticallyClosedGenesisPackage::from_manifest_verified(genesis_manifest).unwrap();
    let genesis_runner_pin = RegistryTestRunnerPin::from_trusted_config(
        digest(GENESIS_RUNNER_ARTIFACT),
        digest(GENESIS_RUNNER_CONFIGURATION),
        RegistryTestResultDigest::from_digest(digest(GENESIS_TEST_RESULT_DIGEST)),
    );
    let genesis_test_result = verify_registry_test_result(
        record(GENESIS_TEST_RESULT),
        genesis_runner_pin,
        &profile,
        &genesis_package,
    )
    .unwrap();
    let target_manifest =
        ManifestVerifiedRegistryPackage::decode(record(TARGET_PACKAGE), &profile).unwrap();
    let target_successor =
        SemanticallyClosedSuccessorPackage::from_manifest_verified(target_manifest).unwrap();
    let target = SemanticallyClosedStage4Package::from_successor_package(target_successor).unwrap();
    ContractFixture {
        profile,
        semantic_scope,
        genesis_package,
        genesis_test_result,
        genesis_principal_binding: GenesisActivationPrincipalBinding::from_trusted_config(
            ContractId::new("principal.operator").unwrap(),
            ContractId::new("principal.author").unwrap(),
        ),
        target,
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
        &fixture.genesis_package,
    )
    .unwrap();
    BootstrapAuthority { bootstrap }
}

fn physical_scope(label: &str) -> FleetScope {
    FleetScope::new(
        Uuid::now_v7(),
        format!("successor-{label}-{}", Uuid::now_v7()),
        "successor-connected-test",
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

async fn server_time(pool: &PgPool) -> DateTime<Utc> {
    sqlx::query_scalar("SELECT statement_timestamp()")
        .fetch_one(pool)
        .await
        .unwrap()
}

fn canonical_time(value: DateTime<Utc>) -> CanonicalTimestamp {
    CanonicalTimestamp::from_datetime(&value).unwrap()
}

fn genesis_approval(
    statement_id: ostk_fleet_recall::memory_contracts::genesis_activation::GenesisRegistryActivationStatementId,
    principal: &str,
    signer_seed: u8,
) -> GenesisRegistryActivationApprovalV1 {
    let mut message = b"ostk-registry-activation-approval-signature-v1\0".to_vec();
    message.extend_from_slice(statement_id.digest().as_bytes());
    let key = Ed25519KeyPair::from_seed_unchecked(&[signer_seed; 32]).unwrap();
    GenesisRegistryActivationApprovalV1 {
        schema_version: 1,
        statement_id,
        signer_principal_id: ContractId::new(principal).unwrap(),
        signature: FixedHex64::from_bytes(key.sign(&message).as_ref().try_into().unwrap()),
    }
}

fn genesis_request(
    fixture: &ContractFixture,
    authority: &BootstrapAuthority,
    effective_from: CanonicalTimestamp,
) -> ostk_fleet_recall::memory_contracts::genesis_activation::VerifiedGenesisRegistryActivationRequest
{
    let statement = GenesisRegistryActivationStatementV1 {
        schema_version: 1,
        profile: fixture.profile.clone(),
        scope: fixture.semantic_scope.clone(),
        expected_anchor: GenesisRegistryAnchorV1::from_verified(
            &authority.bootstrap,
            &fixture.genesis_package,
        )
        .unwrap(),
        package_digest: fixture.genesis_package.package_digest(),
        resulting_activation_policy_digest: genesis_activation_policy_digest(
            &fixture.genesis_package,
        )
        .unwrap(),
        effective_from,
        effective_until: None,
        test_vector_result_digest: fixture.genesis_test_result.result_digest(),
        proposer_principal_id: ContractId::new("principal.operator").unwrap(),
        package_author_principal_id: ContractId::new("principal.author").unwrap(),
    };
    let statement_id = statement.statement_id().unwrap();
    let mut approvals = vec![
        genesis_approval(statement_id, "principal.1", 1),
        genesis_approval(statement_id, "principal.2", 2),
    ];
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
        &fixture.genesis_package,
        &fixture.genesis_test_result,
        &fixture.genesis_principal_binding,
    )
    .unwrap()
}

async fn activate_genesis(
    pool: &PgPool,
    fixture: &ContractFixture,
    label: &str,
    seed: u8,
) -> ActivatedGenesis {
    let physical_scope = physical_scope(label);
    let authority = signed_bootstrap(fixture, seed);
    let bootstrap_repository = CockroachGenesisRepository::new(
        pool.clone(),
        trusted_scope(&physical_scope, fixture),
        retry_policy(),
    );
    bootstrap_repository
        .bootstrap_genesis(&authority.bootstrap, &fixture.genesis_package)
        .await
        .unwrap();
    let effective_from = canonical_time(server_time(pool).await);
    let request = genesis_request(fixture, &authority, effective_from.clone());
    let repository = CockroachGenesisActivationRepository::new(
        pool.clone(),
        trusted_scope(&physical_scope, fixture),
        retry_policy(),
        authority.bootstrap.clone(),
        fixture.genesis_package.clone(),
        fixture.genesis_test_result.clone(),
        fixture.genesis_principal_binding.clone(),
    )
    .unwrap();
    let accepted = match repository.activate_genesis(&request).await.unwrap() {
        GenesisActivationOutcome::Inserted(accepted)
        | GenesisActivationOutcome::ExactReplay(accepted) => accepted,
    };
    ActivatedGenesis {
        physical_scope,
        authority,
        head: RegistryHeadBindingV1 {
            head: accepted.registry_head,
            effective_from,
            effective_until: None,
        },
        accepted_at: accepted.accepted_at,
    }
}

fn current_v1_policy_reference(fixture: &ContractFixture) -> RegistryReferenceV1 {
    let entry = fixture
        .genesis_package
        .manifest_verified_package()
        .package()
        .entries
        .iter()
        .find(|entry| entry.kind == RegistryEntryKind::ActivationPolicy)
        .unwrap();
    RegistryReferenceV1 {
        entry_id: entry.entry_id.clone(),
        version: entry.version,
        entry_digest: entry.digest().unwrap(),
    }
}

fn successor_runner_pin() -> SuccessorRegistryTestRunnerPin {
    SuccessorRegistryTestRunnerPin::from_trusted_config(
        digest(SUCCESSOR_RUNNER_ARTIFACT),
        digest(SUCCESSOR_RUNNER_CONFIGURATION),
        RegistryTestResultDigest::from_digest(digest(SUCCESSOR_TEST_RESULT_DIGEST)),
    )
}

fn successor_principal_binding() -> SuccessorActivationPrincipalBinding {
    SuccessorActivationPrincipalBinding::from_trusted_config(
        ContractId::new("principal.operator").unwrap(),
        ContractId::new("principal.author").unwrap(),
    )
}

fn bridge_for(
    fixture: &ContractFixture,
    genesis: &ActivatedGenesis,
) -> (
    Vec<u8>,
    GenesisSuccessorKeyBridgePin,
    GenesisSuccessorKeyBridgeDigest,
) {
    let signer = |principal: &str, seed: u8| {
        let pair = Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap();
        ActivationSignerBindingV2 {
            principal_id: ContractId::new(principal).unwrap(),
            algorithm: ActivationSignatureAlgorithmV2::Ed25519,
            public_key: FixedHex32::from_bytes(pair.public_key().as_ref().try_into().unwrap()),
        }
    };
    let bridge = GenesisSuccessorKeyBridgeV1 {
        schema_version: 1,
        profile: fixture.profile.clone(),
        scope: fixture.semantic_scope.clone(),
        genesis_registry_head: genesis.head.clone(),
        current_v1_activation_policy: current_v1_policy_reference(fixture),
        from_generation: 0,
        to_generation: 1,
        key_map: vec![signer("principal.alice", 1), signer("principal.bob", 2)],
    };
    let bridge_digest = bridge.bridge_digest().unwrap();
    (
        encode_canonical(&bridge).unwrap(),
        GenesisSuccessorKeyBridgePin::from_trusted_config(bridge_digest),
        bridge_digest,
    )
}

fn successor_approval(
    statement_id: ostk_fleet_recall::memory_contracts::successor_activation::SuccessorRegistryActivationStatementId,
    principal: &str,
    seed: u8,
) -> SuccessorRegistryActivationApprovalV1 {
    let mut message = b"ostk-registry-successor-activation-approval-signature-v1\0".to_vec();
    message.extend_from_slice(statement_id.digest().as_bytes());
    let pair = Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap();
    SuccessorRegistryActivationApprovalV1 {
        schema_version: 1,
        statement_id,
        signer_principal_id: ContractId::new(principal).unwrap(),
        signature: FixedHex64::from_bytes(pair.sign(&message).as_ref().try_into().unwrap()),
    }
}

fn candidate_for(
    fixture: &ContractFixture,
    genesis: &ActivatedGenesis,
    bridge_digest: GenesisSuccessorKeyBridgeDigest,
    effective_from: CanonicalTimestamp,
) -> SuccessorActivationCandidate {
    let test_result = verify_successor_registry_test_result(
        record(SUCCESSOR_TEST_RESULT),
        successor_runner_pin(),
        &fixture.target,
    )
    .unwrap();
    let statement = SuccessorRegistryActivationStatementV1 {
        schema_version: 1,
        profile: fixture.profile.clone(),
        scope: fixture.semantic_scope.clone(),
        expected_predecessor_head: genesis.head.clone(),
        current_v1_activation_policy: current_v1_policy_reference(fixture),
        target_package_digest: fixture.target.package_digest(),
        target_activation_policy: fixture
            .target
            .activation_policy()
            .registry_reference()
            .clone(),
        test_vector_result_digest: test_result.result_digest(),
        genesis_successor_key_bridge_digest: bridge_digest,
        from_generation: 0,
        to_generation: 1,
        effective_from,
        effective_until: None,
        proposer_principal_id: ContractId::new("principal.operator").unwrap(),
        package_author_principal_id: ContractId::new("principal.author").unwrap(),
    };
    let statement_id = statement.statement_id().unwrap();
    let approval_set = SuccessorRegistryActivationApprovalSetV1 {
        schema_version: 1,
        statement_id,
        approvals: vec![
            successor_approval(statement_id, "principal.alice", 1),
            successor_approval(statement_id, "principal.bob", 2),
        ],
    };
    SuccessorActivationCandidate::from_bounded_canonical_bytes(
        encode_canonical(&statement).unwrap(),
        encode_canonical(&approval_set).unwrap(),
    )
    .unwrap()
}

fn ceremony_for(
    fixture: &ContractFixture,
    genesis: &ActivatedGenesis,
    effective_from: CanonicalTimestamp,
) -> SuccessorCeremony {
    let (bridge_bytes, bridge_pin, bridge_digest) = bridge_for(fixture, genesis);
    SuccessorCeremony {
        candidate: candidate_for(fixture, genesis, bridge_digest, effective_from),
        bridge_bytes,
        bridge_pin,
        bridge_digest,
    }
}

fn successor_repository(
    pool: PgPool,
    physical_scope: &FleetScope,
    fixture: &ContractFixture,
    genesis: &ActivatedGenesis,
    ceremony: &SuccessorCeremony,
) -> CockroachSuccessorActivationRepository {
    CockroachSuccessorActivationRepository::new(
        pool,
        trusted_scope(physical_scope, fixture),
        retry_policy(),
        genesis.authority.bootstrap.clone(),
        fixture.genesis_package.clone(),
        fixture.genesis_test_result.clone(),
        fixture.genesis_principal_binding.clone(),
        fixture.target.clone(),
        record(SUCCESSOR_TEST_RESULT),
        successor_runner_pin(),
        ceremony.bridge_bytes.clone(),
        ceremony.bridge_pin,
        successor_principal_binding(),
    )
    .unwrap()
}

fn canonical_datetime(value: &CanonicalTimestamp) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(value.as_str())
        .unwrap()
        .with_timezone(&Utc)
}

fn append_chain(
    previous: Sha256Digest,
    event_id: ostk_fleet_recall::memory_contracts::evidence::AcceptedEventId,
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

fn activation_shard(fixture: &ContractFixture, genesis: &ActivatedGenesis) -> u16 {
    let key = registry_activation_consistency_partition_key(&fixture.semantic_scope).unwrap();
    genesis.authority.bootstrap.partition_for(&key).unwrap()
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

async fn cleanup_scope(pool: &PgPool, scope: &FleetScope) {
    for statement in [
        "DELETE FROM memory_registry_current_heads_v2 \
         WHERE tenant_id = $1 AND project = $2",
        "DELETE FROM memory_registry_genesis_bridge_consumptions \
         WHERE tenant_id = $1 AND project = $2",
        "DELETE FROM memory_registry_transitions \
         WHERE tenant_id = $1 AND project = $2 AND generation = 1",
        "DELETE FROM memory_registry_transitions \
         WHERE tenant_id = $1 AND project = $2 AND generation = 0",
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

async fn append_control_event(
    pool: &PgPool,
    fixture: &ContractFixture,
    genesis: &ActivatedGenesis,
    marker: &str,
    registry_stream: bool,
) -> AppendPositionV1 {
    let shard = activation_shard(fixture, genesis);
    let epoch_id = genesis.authority.bootstrap.epoch_id();
    let mut transaction = pool.begin().await.unwrap();
    let row = sqlx::query(
        "SELECT last_committed_offset, chain_digest FROM memory_control_shard_heads \
         WHERE tenant_id = $1 AND project = $2 AND epoch_id = $3 AND shard = $4 FOR UPDATE",
    )
    .bind(genesis.physical_scope.tenant_id)
    .bind(&genesis.physical_scope.project)
    .bind(epoch_id.digest().as_bytes().to_vec())
    .bind(i32::from(shard))
    .fetch_one(&mut *transaction)
    .await
    .unwrap();
    let previous_offset: i64 = row.get("last_committed_offset");
    let previous_chain =
        Sha256Digest::from_bytes(row.get::<Vec<u8>, _>("chain_digest").try_into().unwrap());
    let next_offset = previous_offset.checked_add(1).unwrap();
    let position = AppendPositionV1 {
        epoch_id,
        shard,
        committed_offset: CommittedOffsetV1::new(u64::try_from(next_offset).unwrap()).unwrap(),
    };
    let event_id = ostk_fleet_recall::memory_contracts::evidence::AcceptedEventId::from_digest(
        domain_separated_digest(DigestDomain::AcceptedEvent, marker.as_bytes()),
    );
    let chain = append_chain(previous_chain, event_id, &position);
    let accepted_at: DateTime<Utc> = sqlx::query_scalar("SELECT statement_timestamp()")
        .fetch_one(&mut *transaction)
        .await
        .unwrap();
    let (family, key_digest) = if registry_stream {
        let key = registry_activation_consistency_partition_key(&fixture.semantic_scope).unwrap();
        (key.family.as_str().to_owned(), key.key_digest)
    } else {
        (
            "test.successor.unrelated".to_owned(),
            domain_separated_digest(DigestDomain::Partition, marker.as_bytes()),
        )
    };
    sqlx::query(
        "INSERT INTO memory_control_events (tenant_id, project, epoch_id, shard, \
         committed_offset, event_id, event_schema_version, event_kind, semantic_object_digest, \
         consistency_family, consistency_key_digest, canonical_event, previous_chain_digest, \
         chain_digest, accepted_at) VALUES ($1, $2, $3, $4, $5, $6, 1, \
         'test.successor.synthetic', $7, $8, $9, $10, $11, $12, $13)",
    )
    .bind(genesis.physical_scope.tenant_id)
    .bind(&genesis.physical_scope.project)
    .bind(epoch_id.digest().as_bytes().to_vec())
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
        "UPDATE memory_control_shard_heads SET last_committed_offset = $5, chain_digest = $6, \
         advanced_at = $7 WHERE tenant_id = $1 AND project = $2 AND epoch_id = $3 AND shard = $4 \
         AND last_committed_offset = $8 AND chain_digest = $9",
    )
    .bind(genesis.physical_scope.tenant_id)
    .bind(&genesis.physical_scope.project)
    .bind(epoch_id.digest().as_bytes().to_vec())
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
    fixture: &ContractFixture,
    genesis: &ActivatedGenesis,
    marker: &str,
) {
    let shard = activation_shard(fixture, genesis);
    let epoch_id = genesis.authority.bootstrap.epoch_id();
    let row = sqlx::query(
        "SELECT last_committed_offset, chain_digest FROM memory_control_shard_heads \
         WHERE tenant_id = $1 AND project = $2 AND epoch_id = $3 AND shard = $4",
    )
    .bind(genesis.physical_scope.tenant_id)
    .bind(&genesis.physical_scope.project)
    .bind(epoch_id.digest().as_bytes().to_vec())
    .bind(i32::from(shard))
    .fetch_one(pool)
    .await
    .unwrap();
    let head_offset: i64 = row.get("last_committed_offset");
    let previous_chain =
        Sha256Digest::from_bytes(row.get::<Vec<u8>, _>("chain_digest").try_into().unwrap());
    let orphan_offset = head_offset.checked_add(2).unwrap();
    let position = AppendPositionV1 {
        epoch_id,
        shard,
        committed_offset: CommittedOffsetV1::new(u64::try_from(orphan_offset).unwrap()).unwrap(),
    };
    let event_id = ostk_fleet_recall::memory_contracts::evidence::AcceptedEventId::from_digest(
        domain_separated_digest(DigestDomain::AcceptedEvent, marker.as_bytes()),
    );
    let chain = append_chain(previous_chain, event_id, &position);
    sqlx::query(
        "INSERT INTO memory_control_events (tenant_id, project, epoch_id, shard, \
         committed_offset, event_id, event_schema_version, event_kind, semantic_object_digest, \
         consistency_family, consistency_key_digest, canonical_event, previous_chain_digest, \
         chain_digest, accepted_at) VALUES ($1, $2, $3, $4, $5, $6, 1, \
         'test.successor.ahead', $7, 'test.successor.ahead', $8, $9, $10, $11, \
         statement_timestamp())",
    )
    .bind(genesis.physical_scope.tenant_id)
    .bind(&genesis.physical_scope.project)
    .bind(epoch_id.digest().as_bytes().to_vec())
    .bind(i32::from(shard))
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
    .execute(pool)
    .await
    .unwrap();
}

async fn assert_bounded_successor_state_plans(pool: &PgPool, genesis: &ActivatedGenesis) {
    for (query, table, explicit_limit) in [
        (
            "EXPLAIN (OPT, VERBOSE) SELECT generation FROM memory_registry_transitions \
             WHERE tenant_id = $1 AND project = $2 ORDER BY generation LIMIT 3",
            "memory_registry_transitions",
            Some("limit: 3"),
        ),
        (
            "EXPLAIN (OPT, VERBOSE) SELECT bridge_digest \
             FROM memory_registry_genesis_bridge_consumptions \
             WHERE tenant_id = $1 AND project = $2 LIMIT 2",
            "memory_registry_genesis_bridge_consumptions",
            None,
        ),
        (
            "EXPLAIN (OPT, VERBOSE) SELECT generation FROM memory_registry_current_heads_v2 \
             WHERE tenant_id = $1 AND project = $2 LIMIT 2",
            "memory_registry_current_heads_v2",
            None,
        ),
    ] {
        let plan = sqlx::query_scalar::<_, String>(query)
            .bind(genesis.physical_scope.tenant_id)
            .bind(&genesis.physical_scope.project)
            .fetch_all(pool)
            .await
            .unwrap()
            .join("\n");
        assert!(
            plan.contains(&format!("scan {table}")),
            "wrong state plan:\n{plan}"
        );
        assert!(
            plan.contains("constraint: /1/2"),
            "unscoped state plan:\n{plan}"
        );
        if let Some(limit) = explicit_limit {
            assert!(plan.contains(limit), "unbounded state plan:\n{plan}");
        } else {
            // Both tables have a scope singleton primary key. Cockroach may
            // remove the redundant LIMIT 2 and prove the stronger bound in
            // optimizer cardinality instead.
            assert!(
                plan.contains("cardinality: [0 - 1]"),
                "unbounded singleton state plan:\n{plan}"
            );
        }
    }
}

async fn assert_bounded_plans(
    pool: &PgPool,
    fixture: &ContractFixture,
    genesis: &ActivatedGenesis,
) {
    assert_bounded_successor_state_plans(pool, genesis).await;

    let key = registry_activation_consistency_partition_key(&fixture.semantic_scope).unwrap();
    let stream_plan = sqlx::query_scalar::<_, String>(
        "EXPLAIN (OPT, VERBOSE) SELECT event_id, shard, committed_offset \
         FROM memory_control_events \
         WHERE tenant_id = $1 AND project = $2 AND epoch_id = $3 \
         AND consistency_family = $4 AND consistency_key_digest = $5 \
         ORDER BY shard, committed_offset LIMIT 3",
    )
    .bind(genesis.physical_scope.tenant_id)
    .bind(&genesis.physical_scope.project)
    .bind(
        genesis
            .authority
            .bootstrap
            .epoch_id()
            .digest()
            .as_bytes()
            .to_vec(),
    )
    .bind("registry.activation")
    .bind(key.key_digest.as_bytes().to_vec())
    .fetch_all(pool)
    .await
    .unwrap()
    .join("\n");
    assert!(stream_plan.contains("memory_control_events_consistency_stream_idx"));
    // The consistency index orders table columns 1/2/3/10/11 before the
    // shard/offset suffix; require the exact fixed scope+stream prefix.
    assert!(
        stream_plan.contains("constraint: /1/2/3/10/11"),
        "unscoped registry stream plan:\n{stream_plan}"
    );
    assert!(stream_plan.contains("limit: 3"));

    let ahead_plan = sqlx::query_scalar::<_, String>(
        "EXPLAIN (OPT, VERBOSE) SELECT event_id FROM memory_control_events \
         WHERE tenant_id = $1 AND project = $2 AND epoch_id = $3 AND shard = $4 \
         AND committed_offset > $5 ORDER BY committed_offset LIMIT 1",
    )
    .bind(genesis.physical_scope.tenant_id)
    .bind(&genesis.physical_scope.project)
    .bind(
        genesis
            .authority
            .bootstrap
            .epoch_id()
            .digest()
            .as_bytes()
            .to_vec(),
    )
    .bind(i32::from(activation_shard(fixture, genesis)))
    .bind(0_i64)
    .fetch_all(pool)
    .await
    .unwrap()
    .join("\n");
    assert!(ahead_plan.contains("scan memory_control_events"));
    assert!(ahead_plan.contains("constraint: /1/2/3/4/5"));
    assert!(ahead_plan.contains("limit: 1"));
}

#[allow(clippy::too_many_lines)] // one joined assertion keeps the durable graph coordinates visible
async fn assert_exact_accepted_graph(
    pool: &PgPool,
    fixture: &ContractFixture,
    genesis: &ActivatedGenesis,
    accepted: &ostk_fleet_recall::registry_activation::AcceptedSuccessorActivation,
) {
    assert_eq!(
        scoped_count(pool, "memory_registry_transitions", &genesis.physical_scope).await,
        2
    );
    assert_eq!(
        scoped_count(
            pool,
            "memory_registry_genesis_bridge_consumptions",
            &genesis.physical_scope,
        )
        .await,
        1
    );
    assert_eq!(
        scoped_count(
            pool,
            "memory_registry_current_heads_v2",
            &genesis.physical_scope,
        )
        .await,
        1
    );

    let key = registry_activation_consistency_partition_key(&fixture.semantic_scope).unwrap();
    let stream_count: i64 = sqlx::query_scalar(
        "SELECT count(*)::INT8 FROM memory_control_events WHERE tenant_id = $1 AND project = $2 \
         AND epoch_id = $3 AND consistency_family = $4 AND consistency_key_digest = $5",
    )
    .bind(genesis.physical_scope.tenant_id)
    .bind(&genesis.physical_scope.project)
    .bind(
        accepted
            .append_position
            .epoch_id
            .digest()
            .as_bytes()
            .to_vec(),
    )
    .bind("registry.activation")
    .bind(key.key_digest.as_bytes().to_vec())
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(stream_count, 2);

    let row = sqlx::query(
        "SELECT g.generation AS genesis_generation, s.generation AS successor_generation, \
         b.from_generation, b.to_generation, c.generation AS current_generation, \
         s.activation_id, s.source_event_id, s.source_epoch_id, s.source_shard, \
         s.source_committed_offset, s.accepted_at, b.successor_accepted_at, b.consumed_at, \
         c.accepted_at AS current_accepted_at, e.accepted_at AS event_accepted_at, \
         h.advanced_at FROM memory_registry_transitions AS g \
         JOIN memory_registry_transitions AS s ON s.tenant_id = g.tenant_id \
          AND s.project = g.project AND s.generation = 1 \
         JOIN memory_registry_genesis_bridge_consumptions AS b ON b.tenant_id = s.tenant_id \
          AND b.project = s.project AND b.successor_activation_id = s.activation_id \
         JOIN memory_registry_current_heads_v2 AS c ON c.tenant_id = s.tenant_id \
          AND c.project = s.project AND c.activation_id = s.activation_id \
         JOIN memory_control_events AS e ON e.tenant_id = s.tenant_id AND e.project = s.project \
          AND e.event_id = s.source_event_id AND e.epoch_id = s.source_epoch_id \
          AND e.shard = s.source_shard AND e.committed_offset = s.source_committed_offset \
         JOIN memory_control_shard_heads AS h ON h.tenant_id = s.tenant_id \
          AND h.project = s.project AND h.epoch_id = s.source_epoch_id AND h.shard = s.source_shard \
         WHERE g.tenant_id = $1 AND g.project = $2 AND g.generation = 0",
    )
    .bind(genesis.physical_scope.tenant_id)
    .bind(&genesis.physical_scope.project)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(row.get::<i64, _>("genesis_generation"), 0);
    assert_eq!(row.get::<i64, _>("successor_generation"), 1);
    assert_eq!(row.get::<i64, _>("from_generation"), 0);
    assert_eq!(row.get::<i64, _>("to_generation"), 1);
    assert_eq!(row.get::<i64, _>("current_generation"), 1);
    assert_eq!(
        row.get::<Vec<u8>, _>("activation_id"),
        accepted.activation_id.digest().as_bytes()
    );
    assert_eq!(
        row.get::<Vec<u8>, _>("source_event_id"),
        accepted.accepted_event_id.digest().as_bytes()
    );
    assert_eq!(
        row.get::<Vec<u8>, _>("source_epoch_id"),
        accepted.append_position.epoch_id.digest().as_bytes()
    );
    assert_eq!(
        row.get::<i32, _>("source_shard"),
        i32::from(accepted.append_position.shard)
    );
    assert_eq!(
        row.get::<i64, _>("source_committed_offset"),
        i64::try_from(accepted.append_position.committed_offset.as_u64()).unwrap()
    );
    let expected = canonical_datetime(&accepted.accepted_at);
    for column in [
        "accepted_at",
        "successor_accepted_at",
        "consumed_at",
        "current_accepted_at",
        "event_accepted_at",
        "advanced_at",
    ] {
        assert_eq!(row.get::<DateTime<Utc>, _>(column), expected);
    }
}

#[test]
fn frozen_first_successor_authority_has_one_canonical_approval_ceremony() {
    let fixture = fixture();
    let policy = fixture.genesis_package.activation_policy();
    assert_eq!(policy.eligible_principal_ids().len(), 2);
    assert_eq!(policy.approval_threshold(), 2);
    assert_eq!(
        policy
            .eligible_principal_ids()
            .iter()
            .map(ContractId::as_str)
            .collect::<Vec<_>>(),
        ["principal.alice", "principal.bob"]
    );

    let statement_id = ostk_fleet_recall::memory_contracts::successor_activation::SuccessorRegistryActivationStatementId::from_digest(
        domain_separated_digest(DigestDomain::Body, b"fixed-successor-statement"),
    );
    let ceremony = || SuccessorRegistryActivationApprovalSetV1 {
        schema_version: 1,
        statement_id,
        approvals: vec![
            successor_approval(statement_id, "principal.alice", 1),
            successor_approval(statement_id, "principal.bob", 2),
        ],
    };
    assert_eq!(
        encode_canonical(&ceremony()).unwrap(),
        encode_canonical(&ceremony()).unwrap()
    );
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn live_first_successor_activation_when_configured() {
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
    let migration_prefix: Vec<i64> = sqlx::query_scalar(
        "SELECT version FROM _sqlx_migrations WHERE version BETWEEN 1 AND 14 AND success \
         ORDER BY version",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(migration_prefix, (1_i64..=14).collect::<Vec<_>>());

    let main = activate_genesis(&pool, &fixture, "main", 31).await;
    tokio::time::sleep(Duration::from_millis(2)).await;
    let main_effective = server_time(&pool).await;
    let main_ceremony = ceremony_for(&fixture, &main, canonical_time(main_effective));
    let main_repository = successor_repository(
        pool.clone(),
        &main.physical_scope,
        &fixture,
        &main,
        &main_ceremony,
    );

    // The complete prefix is mandatory even when a later, unrelated migration
    // row exists. Move the genuine row instead of synthesizing its checksum,
    // then restore it before any assertion can abort the shared process proof.
    let moved = sqlx::query("UPDATE _sqlx_migrations SET version = 9999 WHERE version = 14")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(moved.rows_affected(), 1);
    let missing_prefix = main_repository
        .activate_first_successor(&main_ceremony.candidate)
        .await;
    let restored = sqlx::query("UPDATE _sqlx_migrations SET version = 14 WHERE version = 9999")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(restored.rows_affected(), 1);
    assert!(matches!(
        missing_prefix,
        Err(FleetError::SuccessorActivationSchemaUnavailable)
    ));

    // A present but failed required row is also closed. Restoration occurs
    // before the assertion so later cases never inherit the deliberate fault.
    let changed = sqlx::query("UPDATE _sqlx_migrations SET success = false WHERE version = 14")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(changed.rows_affected(), 1);
    let failed_prefix = main_repository
        .activate_first_successor(&main_ceremony.candidate)
        .await;
    let restored = sqlx::query("UPDATE _sqlx_migrations SET success = true WHERE version = 14")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(restored.rows_affected(), 1);
    assert!(matches!(
        failed_prefix,
        Err(FleetError::SuccessorActivationSchemaUnavailable)
    ));
    for table in [
        "memory_registry_transitions",
        "memory_registry_genesis_bridge_consumptions",
        "memory_registry_current_heads_v2",
    ] {
        assert_eq!(
            scoped_count(&pool, table, &main.physical_scope).await,
            0,
            "schema rejection wrote {table}"
        );
    }

    // A neighboring physical scope cannot borrow the durable genesis authority.
    let isolated_scope = physical_scope("not-ready-isolation");
    let isolated_repository = successor_repository(
        pool.clone(),
        &isolated_scope,
        &fixture,
        &main,
        &main_ceremony,
    );
    assert!(matches!(
        isolated_repository
            .inspect_first_successor(&main_ceremony.candidate)
            .await,
        Err(FleetError::SuccessorActivationNotReady)
    ));
    assert_eq!(
        scoped_count(&pool, "memory_registry_transitions", &isolated_scope).await,
        0
    );

    assert_bounded_plans(&pool, &fixture, &main).await;
    assert!(matches!(
        main_repository
            .inspect_first_successor(&main_ceremony.candidate)
            .await
            .unwrap(),
        SuccessorActivationInspection::Ready(_)
    ));
    let inserted = match main_repository
        .activate_first_successor(&main_ceremony.candidate)
        .await
        .unwrap()
    {
        SuccessorActivationOutcome::Inserted(value) => value,
        SuccessorActivationOutcome::ExactReplay(_) => panic!("fresh successor must insert"),
    };
    assert_exact_accepted_graph(&pool, &fixture, &main, &inserted).await;
    assert_eq!(
        main_repository
            .inspect_first_successor(&main_ceremony.candidate)
            .await
            .unwrap(),
        SuccessorActivationInspection::Accepted(inserted.clone())
    );
    assert_eq!(
        main_repository
            .activate_first_successor(&main_ceremony.candidate)
            .await
            .unwrap(),
        SuccessorActivationOutcome::ExactReplay(inserted.clone())
    );

    let stale_candidate = candidate_for(
        &fixture,
        &main,
        main_ceremony.bridge_digest,
        canonical_time(main_effective + ChronoDuration::microseconds(1)),
    );
    assert!(matches!(
        main_repository
            .activate_first_successor(&stale_candidate)
            .await,
        Err(FleetError::SuccessorActivationStale)
    ));

    // Both closed timing errors are checked while generation zero is still current.
    let timing = activate_genesis(&pool, &fixture, "timing", 32).await;
    let before_ceremony = ceremony_for(
        &fixture,
        &timing,
        canonical_time(canonical_datetime(&timing.accepted_at) - ChronoDuration::microseconds(1)),
    );
    let timing_repository = successor_repository(
        pool.clone(),
        &timing.physical_scope,
        &fixture,
        &timing,
        &before_ceremony,
    );
    assert!(matches!(
        timing_repository
            .activate_first_successor(&before_ceremony.candidate)
            .await,
        Err(FleetError::SuccessorActivationTiming(
            SuccessorActivationTimingKind::BeforePredecessorAcceptance
        ))
    ));
    let future_ceremony = ceremony_for(
        &fixture,
        &timing,
        canonical_time(server_time(&pool).await + ChronoDuration::minutes(5)),
    );
    assert!(matches!(
        timing_repository
            .activate_first_successor(&future_ceremony.candidate)
            .await,
        Err(FleetError::SuccessorActivationTiming(
            SuccessorActivationTimingKind::FutureEffective
        ))
    ));
    assert_eq!(
        scoped_count(
            &pool,
            "memory_registry_genesis_bridge_consumptions",
            &timing.physical_scope,
        )
        .await,
        0
    );

    // A pre-existing event on the exact registry.activation stream means
    // genesis is no longer the fresh 0->1 insertion point, even when all
    // successor projection tables are still empty.
    let prefixed = activate_genesis(&pool, &fixture, "prefixed-stream", 39).await;
    append_control_event(&pool, &fixture, &prefixed, "prefixed-registry-stream", true).await;
    let prefixed_ceremony = ceremony_for(
        &fixture,
        &prefixed,
        canonical_time(server_time(&pool).await),
    );
    let prefixed_repository = successor_repository(
        pool.clone(),
        &prefixed.physical_scope,
        &fixture,
        &prefixed,
        &prefixed_ceremony,
    );
    assert!(matches!(
        prefixed_repository
            .activate_first_successor(&prefixed_ceremony.candidate)
            .await,
        Err(FleetError::SuccessorActivationCorrupt(_))
    ));
    for table in [
        "memory_registry_transitions",
        "memory_registry_genesis_bridge_consumptions",
        "memory_registry_current_heads_v2",
    ] {
        assert_eq!(
            scoped_count(&pool, table, &prefixed.physical_scope).await,
            0,
            "prefixed stream wrote {table}"
        );
    }

    // Identical contenders converge to one insert and exact replays.
    let identical = activate_genesis(&pool, &fixture, "concurrent-identical", 33).await;
    tokio::time::sleep(Duration::from_millis(2)).await;
    let identical_ceremony = ceremony_for(
        &fixture,
        &identical,
        canonical_time(server_time(&pool).await),
    );
    let identical_repository = successor_repository(
        pool.clone(),
        &identical.physical_scope,
        &fixture,
        &identical,
        &identical_ceremony,
    );
    let identical_barrier = Arc::new(Barrier::new(8));
    let identical_results = join_all((0..8).map(|_| {
        let barrier = Arc::clone(&identical_barrier);
        let repository = identical_repository.clone();
        let candidate = identical_ceremony.candidate.clone();
        async move {
            barrier.wait().await;
            repository.activate_first_successor(&candidate).await
        }
    }))
    .await;
    assert_eq!(
        identical_results
            .iter()
            .filter(|result| matches!(result, Ok(SuccessorActivationOutcome::Inserted(_))))
            .count(),
        1
    );
    assert_eq!(
        identical_results
            .iter()
            .filter(|result| matches!(result, Ok(SuccessorActivationOutcome::ExactReplay(_))))
            .count(),
        7
    );

    // Distinct valid contenders serialize on one stable shard: one wins and
    // every other independently verified statement is deterministically stale.
    let distinct = activate_genesis(&pool, &fixture, "concurrent-distinct", 34).await;
    tokio::time::sleep(Duration::from_millis(3)).await;
    let distinct_base = server_time(&pool).await;
    let distinct_ceremony = ceremony_for(&fixture, &distinct, canonical_time(distinct_base));
    let distinct_repository = successor_repository(
        pool.clone(),
        &distinct.physical_scope,
        &fixture,
        &distinct,
        &distinct_ceremony,
    );
    let distinct_barrier = Arc::new(Barrier::new(8));
    let distinct_results = join_all((0_i64..8).map(|delta| {
        let candidate = candidate_for(
            &fixture,
            &distinct,
            distinct_ceremony.bridge_digest,
            canonical_time(distinct_base - ChronoDuration::microseconds(delta)),
        );
        let barrier = Arc::clone(&distinct_barrier);
        let repository = distinct_repository.clone();
        async move {
            barrier.wait().await;
            repository.activate_first_successor(&candidate).await
        }
    }))
    .await;
    assert_eq!(
        distinct_results
            .iter()
            .filter(|result| matches!(result, Ok(SuccessorActivationOutcome::Inserted(_))))
            .count(),
        1
    );
    assert_eq!(
        distinct_results
            .iter()
            .filter(|result| matches!(result, Err(FleetError::SuccessorActivationStale)))
            .count(),
        7
    );

    // Partial durable state is corruption, never a repair invitation.
    let partial = activate_genesis(&pool, &fixture, "partial", 35).await;
    tokio::time::sleep(Duration::from_millis(2)).await;
    let partial_ceremony =
        ceremony_for(&fixture, &partial, canonical_time(server_time(&pool).await));
    let partial_repository = successor_repository(
        pool.clone(),
        &partial.physical_scope,
        &fixture,
        &partial,
        &partial_ceremony,
    );
    partial_repository
        .activate_first_successor(&partial_ceremony.candidate)
        .await
        .unwrap();
    sqlx::query(
        "DELETE FROM memory_registry_current_heads_v2 WHERE tenant_id = $1 AND project = $2",
    )
    .bind(partial.physical_scope.tenant_id)
    .bind(&partial.physical_scope.project)
    .execute(&pool)
    .await
    .unwrap();
    assert!(matches!(
        partial_repository
            .inspect_first_successor(&partial_ceremony.candidate)
            .await,
        Err(FleetError::SuccessorActivationCorrupt(_))
    ));

    // A later event in the exact registry stream invalidates the accepted pair.
    let orphan = activate_genesis(&pool, &fixture, "orphan-stream", 36).await;
    tokio::time::sleep(Duration::from_millis(2)).await;
    let orphan_ceremony = ceremony_for(&fixture, &orphan, canonical_time(server_time(&pool).await));
    let orphan_repository = successor_repository(
        pool.clone(),
        &orphan.physical_scope,
        &fixture,
        &orphan,
        &orphan_ceremony,
    );
    orphan_repository
        .activate_first_successor(&orphan_ceremony.candidate)
        .await
        .unwrap();
    append_control_event(&pool, &fixture, &orphan, "orphan-stream-suffix", true).await;
    assert!(matches!(
        orphan_repository
            .activate_first_successor(&orphan_ceremony.candidate)
            .await,
        Err(FleetError::SuccessorActivationCorrupt(_))
    ));

    // A row physically ahead of the selected locked head wedges fresh state closed.
    let ahead = activate_genesis(&pool, &fixture, "ahead", 37).await;
    tokio::time::sleep(Duration::from_millis(2)).await;
    let ahead_ceremony = ceremony_for(&fixture, &ahead, canonical_time(server_time(&pool).await));
    let ahead_repository = successor_repository(
        pool.clone(),
        &ahead.physical_scope,
        &fixture,
        &ahead,
        &ahead_ceremony,
    );
    plant_event_ahead_of_head(&pool, &fixture, &ahead, "detached-ahead").await;
    assert!(matches!(
        ahead_repository
            .activate_first_successor(&ahead_ceremony.candidate)
            .await,
        Err(FleetError::SuccessorActivationCorrupt(_))
    ));

    // Stored canonical bytes are re-decoded and re-verified on every replay.
    let tamper = activate_genesis(&pool, &fixture, "tamper", 38).await;
    tokio::time::sleep(Duration::from_millis(2)).await;
    let tamper_ceremony = ceremony_for(&fixture, &tamper, canonical_time(server_time(&pool).await));
    let tamper_repository = successor_repository(
        pool.clone(),
        &tamper.physical_scope,
        &fixture,
        &tamper,
        &tamper_ceremony,
    );
    tamper_repository
        .activate_first_successor(&tamper_ceremony.candidate)
        .await
        .unwrap();
    let tampered = sqlx::query(
        "UPDATE memory_registry_transitions SET canonical_receipt = $3 \
         WHERE tenant_id = $1 AND project = $2 AND generation = 1",
    )
    .bind(tamper.physical_scope.tenant_id)
    .bind(&tamper.physical_scope.project)
    .bind(b"{}".as_slice())
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(tampered.rows_affected(), 1);
    assert!(matches!(
        tamper_repository
            .activate_first_successor(&tamper_ceremony.candidate)
            .await,
        Err(FleetError::SuccessorActivationCorrupt(_))
    ));

    for scope in [
        &main.physical_scope,
        &timing.physical_scope,
        &prefixed.physical_scope,
        &identical.physical_scope,
        &distinct.physical_scope,
        &partial.physical_scope,
        &orphan.physical_scope,
        &ahead.physical_scope,
        &tamper.physical_scope,
    ] {
        cleanup_scope(&pool, scope).await;
    }
}
