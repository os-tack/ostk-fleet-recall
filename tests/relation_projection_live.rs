//! Connected proof for relation attestation append plus durable projection
//! (W1-REL).
//!
//! Set the exact `FLEET_RECALL_TEST_DATABASE_URL` variable to a disposable
//! `CockroachDB` 26.2 database. Every test here is inert otherwise. Nothing in
//! this file starts a database process, invokes Docker, or targets a cloud
//! service.
//!
//! The bootstrap -> genesis -> successor activation ceremony below is copied
//! from `tests/evidence_ledger_live.rs` (per the W1-REL brief) so every append
//! here runs against a head that is the Stage-4 package at generation one,
//! exactly like that file's own connected proofs.

use std::str::FromStr as _;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use futures::future::join_all;
use ostk_fleet_recall::FleetScope;
use ostk_fleet_recall::control_log::{
    CockroachGenesisRepository, GenesisRepository, TrustedControlScope,
};
use ostk_fleet_recall::evidence_ledger::{
    AcceptedEventRepository, AppendOutcome, EvidenceAppendError, WriterAuthorityWitness,
};
use ostk_fleet_recall::memory_contracts::bootstrap::{
    BootstrapAttestationV1, BootstrapPin, BootstrapReceiptDigest, BootstrapReceiptV1, EpochId,
    GenesisLogEpochV1, VerifiedBootstrapReceipt, verify_pinned_bootstrap,
};
use ostk_fleet_recall::memory_contracts::canonical::{decode_strict, encode_canonical};
use ostk_fleet_recall::memory_contracts::common::{
    CanonicalTimestamp, ContractId, FixedHex32, FixedHex64, ProfileReferenceV1,
    RegistryReferenceV1, frozen_profile_reference_v1,
};
use ostk_fleet_recall::memory_contracts::digest::{
    DigestDomain, Sha256Digest, domain_separated_digest,
};
use ostk_fleet_recall::memory_contracts::evidence::AcceptedEventId;
use ostk_fleet_recall::memory_contracts::evidence_v2::RegistryHeadBindingV1;
use ostk_fleet_recall::memory_contracts::genesis::SemanticallyClosedGenesisPackage;
use ostk_fleet_recall::memory_contracts::genesis_activation::{
    GenesisActivationPrincipalBinding, GenesisRegistryActivationApprovalSetV1,
    GenesisRegistryActivationApprovalV1, GenesisRegistryActivationStatementV1,
    GenesisRegistryAnchorV1, RegistryTestResultDigest, RegistryTestRunnerPin,
    VerifiedRegistryTestResult, genesis_activation_policy_digest,
    verify_genesis_registry_activation, verify_registry_test_result,
};
use ostk_fleet_recall::memory_contracts::registry::{
    ManifestVerifiedRegistryPackage, RegistryEntryKind,
};
use ostk_fleet_recall::memory_contracts::relation::{
    RelationAttestationBasisV1, RelationAttestationEventV1, RelationAttestationVerdictV1,
    RelationAttestorIdentityV1, RelationProjectionStateV1,
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
    SuccessorActivationOutcome, SuccessorActivationRepository,
};
use ostk_fleet_recall::relation_projection::{
    CockroachRelationProjectionRepository, RelationProjectionRepository,
};
use ostk_fleet_recall::store::cockroach::{CockroachStore, PoolConfig, RetryPolicy};
use ostk_recall_core::PrivacyTier;
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use sqlx::PgPool;
use tokio::sync::Mutex;
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
const DECLARED_ATTESTATION: &[u8] =
    include_bytes!("../contracts/dynamic-memory/v2/relation/declared-attestation-event.jsonl");
const VERIFIED_SUPPORT_ATTESTATION: &[u8] = include_bytes!(
    "../contracts/dynamic-memory/v2/relation/verifier-support-attestation-event.jsonl"
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

/// Each `#[tokio::test]` gets its own runtime, and a `PgPool` is bound to the
/// runtime that created it, so pools are never shared across tests. The
/// schema is shared, so migration is serialized and run exactly once per
/// process.
static MIGRATED: Mutex<bool> = Mutex::const_new(false);

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

const fn retry_policy() -> RetryPolicy {
    RetryPolicy {
        max_attempts: 24,
        initial_backoff: Duration::from_millis(1),
        max_backoff: Duration::from_millis(60),
    }
}

fn physical_scope(label: &str) -> FleetScope {
    FleetScope::new(
        Uuid::now_v7(),
        format!("relation-projection-{label}-{}", Uuid::now_v7()),
        "relation-projection-connected-test",
        None,
        PrivacyTier::T1Project,
    )
    .expect("connected-test scope must be valid")
}

async fn live_pool(database_url: &str) -> PgPool {
    let store = CockroachStore::connect(
        database_url,
        physical_scope("pool"),
        PoolConfig {
            max_connections: 10,
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

async fn server_time(pool: &PgPool) -> DateTime<Utc> {
    sqlx::query_scalar("SELECT statement_timestamp()")
        .fetch_one(pool)
        .await
        .expect("database clock must be readable")
}

fn canonical_time(value: DateTime<Utc>) -> CanonicalTimestamp {
    CanonicalTimestamp::from_datetime(&value).expect("database clock must be canonical")
}

// ---------------------------------------------------------------------------
// Frozen contract fixtures and the bootstrap -> genesis -> successor ceremony.
// Copied from tests/evidence_ledger_live.rs, trimmed to what relation
// attestation append needs (no evidence connector, no remember statement).
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct ContractFixture {
    profile: ProfileReferenceV1,
    semantic_scope: ostk_fleet_recall::memory_contracts::common::AuthenticatedProjectScopeV1,
    genesis_package: SemanticallyClosedGenesisPackage,
    genesis_test_result: VerifiedRegistryTestResult,
    genesis_principal_binding: GenesisActivationPrincipalBinding,
    target: SemanticallyClosedStage4Package,
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

fn signed_bootstrap(fixture: &ContractFixture, seed_byte: u8) -> VerifiedBootstrapReceipt {
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
    verify_pinned_bootstrap(
        &canonical,
        BootstrapPin::from_trusted_config(receipt_digest),
        &fixture.profile,
        &fixture.semantic_scope,
        &fixture.genesis_package,
    )
    .unwrap()
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

/// One live scope whose registry head is the Stage-4 package at generation
/// one, bound to a [`CockroachRelationProjectionRepository`].
struct Stage4RelationScope {
    #[allow(dead_code)] // Kept for parity with the ceremony this is copied from.
    pool: PgPool,
    physical_scope: FleetScope,
    #[allow(dead_code)] // Kept for parity with the ceremony this is copied from.
    trusted_scope: TrustedControlScope,
    #[allow(dead_code)]
    bootstrap: VerifiedBootstrapReceipt,
    #[allow(dead_code)]
    genesis_epoch: GenesisLogEpochV1,
    head: RegistryHeadBindingV1,
    repository: Arc<CockroachRelationProjectionRepository>,
    witness: WriterAuthorityWitness,
}

impl Stage4RelationScope {
    const fn epoch_id(&self) -> EpochId {
        self.witness.epoch_id()
    }
}

#[allow(clippy::too_many_lines)] // One linear ceremony; splitting it hides it.
async fn activate_stage4(
    pool: &PgPool,
    fixture: &ContractFixture,
    label: &str,
    seed: u8,
) -> Stage4RelationScope {
    let physical_scope = physical_scope(label);
    let bootstrap = signed_bootstrap(fixture, seed);
    let trusted_scope =
        TrustedControlScope::from_trusted_context(&physical_scope, fixture.semantic_scope.clone())
            .unwrap();

    CockroachGenesisRepository::new(pool.clone(), trusted_scope.clone(), retry_policy())
        .bootstrap_genesis(&bootstrap, &fixture.genesis_package)
        .await
        .unwrap();

    let genesis_effective = canonical_time(server_time(pool).await);
    let statement = GenesisRegistryActivationStatementV1 {
        schema_version: 1,
        profile: fixture.profile.clone(),
        scope: fixture.semantic_scope.clone(),
        expected_anchor: GenesisRegistryAnchorV1::from_verified(
            &bootstrap,
            &fixture.genesis_package,
        )
        .unwrap(),
        package_digest: fixture.genesis_package.package_digest(),
        resulting_activation_policy_digest: genesis_activation_policy_digest(
            &fixture.genesis_package,
        )
        .unwrap(),
        effective_from: genesis_effective.clone(),
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
    let request = verify_genesis_registry_activation(
        &encode_canonical(&statement).unwrap(),
        &encode_canonical(&GenesisRegistryActivationApprovalSetV1 {
            schema_version: 1,
            statement_id,
            approvals,
        })
        .unwrap(),
        &bootstrap,
        &fixture.genesis_package,
        &fixture.genesis_test_result,
        &fixture.genesis_principal_binding,
    )
    .unwrap();
    let genesis_accepted = match CockroachGenesisActivationRepository::new(
        pool.clone(),
        trusted_scope.clone(),
        retry_policy(),
        bootstrap.clone(),
        fixture.genesis_package.clone(),
        fixture.genesis_test_result.clone(),
        fixture.genesis_principal_binding.clone(),
    )
    .unwrap()
    .activate_genesis(&request)
    .await
    .unwrap()
    {
        GenesisActivationOutcome::Inserted(accepted)
        | GenesisActivationOutcome::ExactReplay(accepted) => accepted,
    };
    let genesis_head = RegistryHeadBindingV1 {
        head: genesis_accepted.registry_head,
        effective_from: genesis_effective,
        effective_until: None,
    };

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
        genesis_registry_head: genesis_head.clone(),
        current_v1_activation_policy: current_v1_policy_reference(fixture),
        from_generation: 0,
        to_generation: 1,
        key_map: vec![signer("principal.alice", 1), signer("principal.bob", 2)],
    };
    let bridge_digest: GenesisSuccessorKeyBridgeDigest = bridge.bridge_digest().unwrap();
    let bridge_bytes = encode_canonical(&bridge).unwrap();

    tokio::time::sleep(Duration::from_millis(2)).await;
    let successor_effective = canonical_time(server_time(pool).await);
    let successor_runner_pin = SuccessorRegistryTestRunnerPin::from_trusted_config(
        digest(SUCCESSOR_RUNNER_ARTIFACT),
        digest(SUCCESSOR_RUNNER_CONFIGURATION),
        RegistryTestResultDigest::from_digest(digest(SUCCESSOR_TEST_RESULT_DIGEST)),
    );
    let successor_test_result = verify_successor_registry_test_result(
        record(SUCCESSOR_TEST_RESULT),
        successor_runner_pin,
        &fixture.target,
    )
    .unwrap();
    let successor_statement = SuccessorRegistryActivationStatementV1 {
        schema_version: 1,
        profile: fixture.profile.clone(),
        scope: fixture.semantic_scope.clone(),
        expected_predecessor_head: genesis_head,
        current_v1_activation_policy: current_v1_policy_reference(fixture),
        target_package_digest: fixture.target.package_digest(),
        target_activation_policy: fixture
            .target
            .activation_policy()
            .registry_reference()
            .clone(),
        test_vector_result_digest: successor_test_result.result_digest(),
        genesis_successor_key_bridge_digest: bridge_digest,
        from_generation: 0,
        to_generation: 1,
        effective_from: successor_effective.clone(),
        effective_until: None,
        proposer_principal_id: ContractId::new("principal.operator").unwrap(),
        package_author_principal_id: ContractId::new("principal.author").unwrap(),
    };
    let successor_statement_id = successor_statement.statement_id().unwrap();
    let candidate = SuccessorActivationCandidate::from_bounded_canonical_bytes(
        encode_canonical(&successor_statement).unwrap(),
        encode_canonical(&SuccessorRegistryActivationApprovalSetV1 {
            schema_version: 1,
            statement_id: successor_statement_id,
            approvals: vec![
                successor_approval(successor_statement_id, "principal.alice", 1),
                successor_approval(successor_statement_id, "principal.bob", 2),
            ],
        })
        .unwrap(),
    )
    .unwrap();
    let accepted = match CockroachSuccessorActivationRepository::new(
        pool.clone(),
        trusted_scope.clone(),
        retry_policy(),
        bootstrap.clone(),
        fixture.genesis_package.clone(),
        fixture.genesis_test_result.clone(),
        fixture.genesis_principal_binding.clone(),
        fixture.target.clone(),
        record(SUCCESSOR_TEST_RESULT),
        successor_runner_pin,
        bridge_bytes,
        GenesisSuccessorKeyBridgePin::from_trusted_config(bridge_digest),
        SuccessorActivationPrincipalBinding::from_trusted_config(
            ContractId::new("principal.operator").unwrap(),
            ContractId::new("principal.author").unwrap(),
        ),
    )
    .unwrap()
    .activate_first_successor(&candidate)
    .await
    .unwrap()
    {
        SuccessorActivationOutcome::Inserted(accepted)
        | SuccessorActivationOutcome::ExactReplay(accepted) => accepted,
    };
    let head = accepted.registry_head;
    assert_eq!(head.effective_from, successor_effective);

    let repository = Arc::new(CockroachRelationProjectionRepository::new(
        pool.clone(),
        trusted_scope.clone(),
        retry_policy(),
    ));
    let witness = repository
        .accepted_event_repository()
        .read_writer_authority_witness()
        .await
        .unwrap();
    assert_eq!(witness.generation(), 1, "the head must be generation one");
    assert_eq!(witness.head(), &head.head);

    Stage4RelationScope {
        genesis_epoch: bootstrap.receipt().statement.genesis_epoch.clone(),
        pool: pool.clone(),
        physical_scope,
        trusted_scope,
        bootstrap,
        head,
        repository,
        witness,
    }
}

// ---------------------------------------------------------------------------
// Relation attestation event builders bound to the live head.
// ---------------------------------------------------------------------------

/// Base declared attestation, rebound to the live head. Every builder below
/// starts here or from [`base_verified_support`] and mutates only
/// non-`edge` fields, so all variants share one `relation_fingerprint`.
fn base_declared(head: &RegistryHeadBindingV1) -> RelationAttestationEventV1 {
    let mut event: RelationAttestationEventV1 =
        decode_strict(record(DECLARED_ATTESTATION)).unwrap();
    event.edge.registry = head.clone();
    event.relation_fingerprint = event.edge.fingerprint().unwrap();
    event.validate_shape().unwrap();
    event
}

fn base_verified_support(head: &RegistryHeadBindingV1) -> RelationAttestationEventV1 {
    let mut event: RelationAttestationEventV1 =
        decode_strict(record(VERIFIED_SUPPORT_ATTESTATION)).unwrap();
    event.edge.registry = head.clone();
    event.relation_fingerprint = event.edge.fingerprint().unwrap();
    event.validate_shape().unwrap();
    event
}

fn evidence_id(marker: &str) -> AcceptedEventId {
    AcceptedEventId::from_digest(domain_separated_digest(
        DigestDomain::AcceptedEvent,
        marker.as_bytes(),
    ))
}

fn with_evidence(
    mut event: RelationAttestationEventV1,
    marker: &str,
) -> RelationAttestationEventV1 {
    event.evidence_event_ids = vec![evidence_id(marker)];
    event
}

fn with_declared_attestor(
    mut event: RelationAttestationEventV1,
    principal: &str,
) -> RelationAttestationEventV1 {
    event.attestor = RelationAttestorIdentityV1::AuthenticatedActor {
        principal_id: ContractId::new(principal).unwrap(),
    };
    event
}

fn with_effective_offset(
    mut event: RelationAttestationEventV1,
    minutes_after_five: u32,
) -> RelationAttestationEventV1 {
    event.effective_at = CanonicalTimestamp::parse(format!(
        "2026-08-15T04:{:02}:00.000000000Z",
        5 + minutes_after_five
    ))
    .unwrap();
    event
}

// ---------------------------------------------------------------------------
// Small SQL helpers (root only; never used by any least-privilege probe).
// ---------------------------------------------------------------------------

async fn scoped_count(pool: &PgPool, table: &str, scope: &FleetScope) -> i64 {
    let query = format!("SELECT count(*)::INT8 FROM {table} WHERE tenant_id = $1 AND project = $2");
    sqlx::query_scalar(&query)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .fetch_one(pool)
        .await
        .unwrap()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn live_attest_produces_projection_row_and_watermark_in_one_transaction() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let fixture = fixture();
    let scope = activate_stage4(&pool, &fixture, "attest", 1).await;

    let event = base_declared(&scope.head);
    let fingerprint = event.relation_fingerprint;

    let outcome = scope
        .repository
        .append_attestation(&scope.witness, &event)
        .await
        .unwrap();
    let AppendOutcome::Appended { position, .. } = outcome else {
        panic!("first attestation on a fresh fingerprint must append, got {outcome:?}");
    };

    let projection = scope
        .repository
        .read_projection(fingerprint)
        .await
        .unwrap()
        .expect("projection row must exist after a committed append");
    assert_eq!(projection.state, RelationProjectionStateV1::Declared);
    assert_eq!(
        projection.last_verdict,
        RelationAttestationVerdictV1::Supports
    );
    assert_eq!(projection.last_basis, RelationAttestationBasisV1::Declared);
    assert_eq!(projection.last_event_id, event.accepted_event_id().unwrap());
    assert_eq!(projection.generation, 1);

    let watermark = scope
        .repository
        .read_watermark(position.shard)
        .await
        .unwrap()
        .expect("watermark row must exist after a committed append");
    assert_eq!(
        watermark.last_committed_offset,
        position.committed_offset.as_u64()
    );

    // Atomicity: exactly one relation-attestation row in the shared ledger,
    // and it is the SAME transaction the projection committed in (there is
    // no way to observe the ledger row without the projection row here,
    // since both come from one committed transaction).
    assert_eq!(
        scoped_count(&pool, "memory_evidence_events", &scope.physical_scope).await,
        1
    );
}

#[tokio::test]
async fn live_refute_flips_state_and_retains_the_prior_event() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let fixture = fixture();
    let scope = activate_stage4(&pool, &fixture, "refute", 2).await;

    let support = with_evidence(base_verified_support(&scope.head), "support-evidence");
    let fingerprint = support.relation_fingerprint;
    scope
        .repository
        .append_attestation(&scope.witness, &support)
        .await
        .unwrap();
    assert_eq!(
        scope
            .repository
            .read_projection(fingerprint)
            .await
            .unwrap()
            .unwrap()
            .state,
        RelationProjectionStateV1::Verified
    );

    let mut refute = with_evidence(support.clone(), "refute-evidence");
    refute.verdict = RelationAttestationVerdictV1::Refutes;
    refute.supersedes_attestation_id = Some(support.accepted_event_id().unwrap());

    let outcome = scope
        .repository
        .append_attestation(&scope.witness, &refute)
        .await
        .unwrap();
    assert!(matches!(outcome, AppendOutcome::Appended { .. }));

    let projection = scope
        .repository
        .read_projection(fingerprint)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(projection.state, RelationProjectionStateV1::Refuted);
    assert_eq!(
        projection.last_event_id,
        refute.accepted_event_id().unwrap()
    );
    assert_eq!(projection.generation, 2);

    // Prior event retained: both rows are still in the ledger.
    assert_eq!(
        scoped_count(&pool, "memory_evidence_events", &scope.physical_scope).await,
        2
    );
}

#[tokio::test]
async fn live_unauthorized_supersession_is_rejected_and_nothing_is_written() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let fixture = fixture();
    let scope = activate_stage4(&pool, &fixture, "unauthorized", 3).await;

    let original = with_declared_attestor(
        with_evidence(base_declared(&scope.head), "original-evidence"),
        "principal.connector",
    );
    let fingerprint = original.relation_fingerprint;
    scope
        .repository
        .append_attestation(&scope.witness, &original)
        .await
        .unwrap();

    // A different principal attempts to supersede `original`. This is
    // structurally valid (`validate_shape` does not check cross-authority
    // supersession — only `project_relation_events`/`project_relation` does,
    // at PROJECTION time), so it passes ledger admission and is inserted into
    // `memory_evidence_events` BEFORE the projector rejects it — proving the
    // rollback covers the ledger insert too, not just the projection write.
    let forged = with_declared_attestor(
        {
            let mut event = with_evidence(original.clone(), "forged-evidence");
            event.supersedes_attestation_id = Some(original.accepted_event_id().unwrap());
            event
        },
        "principal.someone-else",
    );

    let error = scope
        .repository
        .append_attestation(&scope.witness, &forged)
        .await
        .unwrap_err();
    // The rejection originates as `EvidenceAppendError::Contract` inside
    // `RelationProjectionAppend::project`, but `append_in_transaction`
    // (shared evidence-ledger machinery, not owned by this module) converts
    // any non-`Storage` `AppendProjection` error to `FleetError::Memory` and
    // the outer retry loop's `storage_or_integrity` then re-wraps that as
    // `EvidenceAppendError::Storage(FleetError::Memory(..))` — so the
    // original message survives, but only inside that wrapper shape.
    let message = error.to_string();
    assert!(
        matches!(error, EvidenceAppendError::Storage(_)),
        "unauthorized supersession must fail closed, got {error:?}"
    );
    assert!(
        message.contains("unauthorized or cross-authority relation supersession"),
        "rejection must name the actual cause, got {message}"
    );

    // Nothing written: the ledger still holds only `original`, and the
    // projection row still reflects only `original` at generation one.
    assert_eq!(
        scoped_count(&pool, "memory_evidence_events", &scope.physical_scope).await,
        1
    );
    let projection = scope
        .repository
        .read_projection(fingerprint)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(projection.generation, 1);
    assert_eq!(
        projection.last_event_id,
        original.accepted_event_id().unwrap()
    );
}

#[tokio::test]
async fn live_exact_replay_is_a_no_op_and_the_watermark_is_unchanged() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let fixture = fixture();
    let scope = activate_stage4(&pool, &fixture, "replay", 4).await;

    let event = base_declared(&scope.head);
    let fingerprint = event.relation_fingerprint;
    let first = scope
        .repository
        .append_attestation(&scope.witness, &event)
        .await
        .unwrap();
    let AppendOutcome::Appended { position, .. } = first else {
        panic!("first append must append");
    };
    let watermark_before = scope
        .repository
        .read_watermark(position.shard)
        .await
        .unwrap()
        .unwrap();
    let projection_before = scope
        .repository
        .read_projection(fingerprint)
        .await
        .unwrap()
        .unwrap();

    let replayed = scope
        .repository
        .append_attestation(&scope.witness, &event)
        .await
        .unwrap();
    assert!(matches!(replayed, AppendOutcome::Replayed { .. }));

    let watermark_after = scope
        .repository
        .read_watermark(position.shard)
        .await
        .unwrap()
        .unwrap();
    let projection_after = scope
        .repository
        .read_projection(fingerprint)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(watermark_before, watermark_after);
    assert_eq!(projection_before, projection_after);
    assert_eq!(
        scoped_count(&pool, "memory_evidence_events", &scope.physical_scope).await,
        1
    );
}

const CONCURRENCY: usize = 6;

#[tokio::test]
async fn live_concurrent_attestations_on_one_edge_form_one_chain_with_a_monotonic_watermark() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let fixture = fixture();
    let scope = Arc::new(activate_stage4(&pool, &fixture, "concurrent", 5).await);

    let fingerprint = base_declared(&scope.head).relation_fingerprint;
    let tasks = (0..CONCURRENCY).map(|index| {
        let scope = Arc::clone(&scope);
        tokio::spawn(async move {
            let minutes_after_five =
                u32::try_from(index).expect("CONCURRENCY is a small compile-time constant") + 1;
            let event = with_declared_attestor(
                with_evidence(
                    with_effective_offset(base_declared(&scope.head), minutes_after_five),
                    &format!("concurrent-evidence-{index}"),
                ),
                &format!("principal.concurrent-{index}"),
            );
            scope
                .repository
                .append_attestation(&scope.witness, &event)
                .await
        })
    });
    let outcomes: Vec<_> = join_all(tasks)
        .await
        .into_iter()
        .map(Result::unwrap)
        .collect();
    for outcome in &outcomes {
        assert!(
            matches!(outcome, Ok(AppendOutcome::Appended { .. })),
            "every distinct concurrent attestation must append: {outcome:?}"
        );
    }
    let shard = match outcomes[0].as_ref().unwrap() {
        AppendOutcome::Appended { position, .. } => position.shard,
        other => panic!("unexpected outcome {other:?}"),
    };
    // Same edge -> same fingerprint -> same consistency key digest -> same
    // shard for every one of these appends (one chain).
    for outcome in &outcomes {
        let AppendOutcome::Appended { position, .. } = outcome.as_ref().unwrap() else {
            unreachable!();
        };
        assert_eq!(
            position.shard, shard,
            "all attestations on one edge must land on one shard"
        );
    }

    let audit = scope
        .repository
        .accepted_event_repository()
        .audit_shard_chain(scope.epoch_id(), shard)
        .await
        .unwrap();
    assert!(audit.is_intact(), "shard chain must audit clean: {audit:?}");
    assert_eq!(audit.verified_events, CONCURRENCY as u64);

    let watermark = scope
        .repository
        .read_watermark(shard)
        .await
        .unwrap()
        .expect("watermark must exist");
    assert_eq!(
        watermark.last_committed_offset, CONCURRENCY as u64,
        "watermark must equal the shard's final committed offset (monotonic, one per append)"
    );

    let projection = scope
        .repository
        .read_projection(fingerprint)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(projection.generation, CONCURRENCY as u64);
    assert_eq!(projection.state, RelationProjectionStateV1::Declared);
}

#[tokio::test]
async fn live_replay01_rebuild_from_event_rows_equals_the_incremental_projection() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let fixture = fixture();
    let scope = activate_stage4(&pool, &fixture, "replay01", 6).await;

    // Build a small, non-trivial history: a verified support, then a verified
    // refute superseding it (state flips to Refuted), plus one independent
    // declared attestation on the SAME edge that stays active throughout
    // (state contribution stays Refuted because only verified results decide
    // the state lattice, but the declared attestation is part of the active
    // set REPLAY-01 must also reproduce).
    let support = with_evidence(base_verified_support(&scope.head), "support-evidence");
    let fingerprint = support.relation_fingerprint;
    scope
        .repository
        .append_attestation(&scope.witness, &support)
        .await
        .unwrap();

    let mut refute = with_evidence(support.clone(), "refute-evidence");
    refute.verdict = RelationAttestationVerdictV1::Refutes;
    refute.supersedes_attestation_id = Some(support.accepted_event_id().unwrap());
    scope
        .repository
        .append_attestation(&scope.witness, &refute)
        .await
        .unwrap();

    let independent = with_declared_attestor(
        with_evidence(base_declared(&scope.head), "independent-evidence"),
        "principal.independent",
    );
    scope
        .repository
        .append_attestation(&scope.witness, &independent)
        .await
        .unwrap();

    let persisted = scope
        .repository
        .read_projection(fingerprint)
        .await
        .unwrap()
        .expect("projection row must exist");
    let rebuilt = scope
        .repository
        .rebuild_projection(fingerprint)
        .await
        .expect("an independent rebuild from memory_evidence_events must succeed");

    assert_eq!(
        persisted.state, rebuilt.state,
        "REPLAY-01: rebuild must equal the incremental projection"
    );
    assert_eq!(rebuilt.state, RelationProjectionStateV1::Refuted);
    assert!(
        rebuilt
            .active_attestation_ids
            .contains(&independent.accepted_event_id().unwrap())
    );
    assert!(
        rebuilt
            .active_attestation_ids
            .contains(&refute.accepted_event_id().unwrap())
    );
    assert!(
        rebuilt
            .superseded_attestation_ids
            .contains(&support.accepted_event_id().unwrap())
    );
}
