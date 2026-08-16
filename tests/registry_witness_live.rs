//! Connected proof for the writer-side active registry head witness (D4).
//!
//! Set the exact `FLEET_RECALL_TEST_DATABASE_URL` variable to a disposable
//! `CockroachDB` 26.2 database. Every live test is inert otherwise. Nothing
//! here starts a database process, invokes Docker, or targets a cloud service.
//!
//! The chain each live test needs is the same one the successor-activation
//! proof builds: a signed bootstrap, a genesis activation, and the one
//! first-successor activation, which leaves the head at generation 1 with the
//! frozen Stage-4 package active.

use std::str::FromStr;
use std::time::Duration;

use chrono::{DateTime, Utc};
use ostk_fleet_recall::FleetScope;
use ostk_fleet_recall::config::WriterAuthorityConfig;
use ostk_fleet_recall::control_log::{
    CockroachGenesisRepository, GenesisRepository, TrustedControlScope,
};
use ostk_fleet_recall::memory_contracts::bootstrap::{
    BootstrapAttestationV1, BootstrapPin, BootstrapReceiptDigest, BootstrapReceiptV1,
    VerifiedBootstrapReceipt, verify_pinned_bootstrap,
};
use ostk_fleet_recall::memory_contracts::canonical::{decode_strict, encode_canonical};
use ostk_fleet_recall::memory_contracts::common::{
    AuthenticatedProjectScopeV1, CanonicalTimestamp, ContractId, FixedHex32, FixedHex64,
    ProfileReferenceV1, RegistryReferenceV1, frozen_profile_reference_v1,
};
use ostk_fleet_recall::memory_contracts::digest::{
    DigestDomain, Sha256Digest, domain_separated_digest,
};
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
use ostk_fleet_recall::registry_witness::{
    WriterAuthorityError, WriterAuthorityRejection, load_and_verify, materialize_active_package,
    verify_within,
};
use ostk_fleet_recall::store::cockroach::{CockroachStore, PoolConfig, RetryPolicy};
use ostk_recall_core::PrivacyTier;
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use sqlx::{PgPool, Row};
use tokio::sync::OnceCell;
use url::Url;
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

/// Exact table privileges deploy/cockroach/runtime-role-grants.sql installs for
/// `fleet_runtime` on the Stage-4 evidence plane (ADR 0002 D2). The probe role
/// in this file receives these and nothing else: no privilege on any
/// `memory_control_*` or `memory_registry_*` base table.
const RUNTIME_EVIDENCE_GRANTS: [(&str, &str); 3] = [
    (
        "SELECT, INSERT",
        "public.memory_evidence_events, public.memory_evidence_quarantine, \
         public.memory_content_objects",
    ),
    (
        "SELECT, INSERT, UPDATE",
        "public.memory_evidence_shard_heads, public.memory_relation_projection_v1, \
         public.memory_relation_projection_watermarks_v1",
    ),
    ("SELECT", "public.memory_writer_authority_v1"),
];

/// Base tables the runtime identity must never be able to read directly.
const FORBIDDEN_BASE_TABLES: [&str; 4] = [
    "public.memory_control_bootstraps",
    "public.memory_control_log_epochs",
    "public.memory_registry_current_heads_v2",
    "public.memory_registry_transitions",
];

static MIGRATED: OnceCell<()> = OnceCell::const_new();

#[derive(Clone)]
struct ContractFixture {
    profile: ProfileReferenceV1,
    semantic_scope: AuthenticatedProjectScopeV1,
    genesis_package: SemanticallyClosedGenesisPackage,
    genesis_test_result: VerifiedRegistryTestResult,
    genesis_principal_binding: GenesisActivationPrincipalBinding,
    target: SemanticallyClosedStage4Package,
}

struct ActivatedGenesis {
    physical_scope: FleetScope,
    bootstrap: VerifiedBootstrapReceipt,
    head: RegistryHeadBindingV1,
}

/// A scope whose durable state is exactly what the writer witness expects.
struct ActiveHead {
    physical_scope: FleetScope,
    config: WriterAuthorityConfig,
    activation_id: Sha256Digest,
    package_digest: Sha256Digest,
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
    let bootstrap_value: BootstrapReceiptV1 =
        decode_strict(record(BOOTSTRAP_RECEIPT)).expect("bootstrap fixture");
    let semantic_scope = bootstrap_value.statement.scope;
    let genesis_manifest =
        ManifestVerifiedRegistryPackage::decode(record(GENESIS_PACKAGE), &profile)
            .expect("genesis package");
    let genesis_package =
        SemanticallyClosedGenesisPackage::from_manifest_verified(genesis_manifest)
            .expect("genesis closure");
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
    .expect("genesis test result");
    let target_manifest = ManifestVerifiedRegistryPackage::decode(record(TARGET_PACKAGE), &profile)
        .expect("target package");
    let target_successor =
        SemanticallyClosedSuccessorPackage::from_manifest_verified(target_manifest)
            .expect("successor closure");
    let target = SemanticallyClosedStage4Package::from_successor_package(target_successor)
        .expect("Stage-4 closure");
    ContractFixture {
        profile,
        semantic_scope,
        genesis_package,
        genesis_test_result,
        genesis_principal_binding: GenesisActivationPrincipalBinding::from_trusted_config(
            ContractId::new("principal.operator").expect("principal"),
            ContractId::new("principal.author").expect("principal"),
        ),
        target,
    }
}

fn signed_bootstrap(fixture: &ContractFixture, seed_byte: u8) -> VerifiedBootstrapReceipt {
    let mut receipt: BootstrapReceiptV1 =
        decode_strict(record(BOOTSTRAP_RECEIPT)).expect("bootstrap fixture");
    receipt.statement.genesis_epoch.partition_recipe.seed = FixedHex32::from_bytes([seed_byte; 32]);
    let statement_id = receipt.statement.statement_id().expect("statement id");
    let mut message = b"ostk-bootstrap-approval-v1\0".to_vec();
    message.extend_from_slice(statement_id.digest().as_bytes());
    receipt.attestations = [1_u8, 2]
        .into_iter()
        .enumerate()
        .map(|(index, signer_seed)| BootstrapAttestationV1 {
            schema_version: 1,
            statement_id,
            signer_principal_id: ContractId::new(format!("principal.{}", index + 1))
                .expect("principal"),
            signature: FixedHex64::from_bytes(
                Ed25519KeyPair::from_seed_unchecked(&[signer_seed; 32])
                    .expect("key")
                    .sign(&message)
                    .as_ref()
                    .try_into()
                    .expect("signature"),
            ),
        })
        .collect();
    let canonical = encode_canonical(&receipt).expect("canonical receipt");
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
    .expect("verified bootstrap")
}

fn physical_scope(label: &str) -> FleetScope {
    FleetScope::new(
        Uuid::now_v7(),
        format!("witness-{label}-{}", Uuid::now_v7()),
        "registry-witness-connected-test",
        None,
        PrivacyTier::T1Project,
    )
    .expect("physical scope")
}

fn trusted_scope(physical: &FleetScope, fixture: &ContractFixture) -> TrustedControlScope {
    TrustedControlScope::from_trusted_context(physical, fixture.semantic_scope.clone())
        .expect("trusted scope")
}

const fn retry_policy() -> RetryPolicy {
    RetryPolicy {
        max_attempts: 20,
        initial_backoff: Duration::from_millis(1),
        max_backoff: Duration::from_millis(50),
    }
}

const fn pool_config() -> PoolConfig {
    PoolConfig {
        max_connections: 4,
        min_connections: 0,
        acquire_timeout: Duration::from_secs(10),
        idle_timeout: Duration::from_secs(60),
        max_lifetime: Duration::from_secs(300),
    }
}

async fn server_time(pool: &PgPool) -> DateTime<Utc> {
    sqlx::query_scalar("SELECT statement_timestamp()")
        .fetch_one(pool)
        .await
        .expect("server time")
}

fn canonical_time(value: DateTime<Utc>) -> CanonicalTimestamp {
    CanonicalTimestamp::from_datetime(&value).expect("canonical timestamp")
}

/// Connect and migrate exactly once per test binary, then hand each test its
/// own pool. The migration is the same embedded one production runs.
async fn migrated_pool() -> Option<PgPool> {
    let database_url = std::env::var("FLEET_RECALL_TEST_DATABASE_URL").ok()?;
    let store = CockroachStore::connect(&database_url, physical_scope("migration"), pool_config())
        .await
        .expect("connect");
    MIGRATED
        .get_or_init(|| async {
            store.migrate().await.expect("migrate");
        })
        .await;
    Some(store.pool().clone())
}

fn genesis_approval(
    statement_id: ostk_fleet_recall::memory_contracts::genesis_activation::GenesisRegistryActivationStatementId,
    principal: &str,
    signer_seed: u8,
) -> GenesisRegistryActivationApprovalV1 {
    let mut message = b"ostk-registry-activation-approval-signature-v1\0".to_vec();
    message.extend_from_slice(statement_id.digest().as_bytes());
    let key = Ed25519KeyPair::from_seed_unchecked(&[signer_seed; 32]).expect("key");
    GenesisRegistryActivationApprovalV1 {
        schema_version: 1,
        statement_id,
        signer_principal_id: ContractId::new(principal).expect("principal"),
        signature: FixedHex64::from_bytes(key.sign(&message).as_ref().try_into().expect("sig")),
    }
}

async fn activate_genesis(
    pool: &PgPool,
    fixture: &ContractFixture,
    label: &str,
    seed: u8,
) -> ActivatedGenesis {
    let physical_scope = physical_scope(label);
    let bootstrap = signed_bootstrap(fixture, seed);
    CockroachGenesisRepository::new(
        pool.clone(),
        trusted_scope(&physical_scope, fixture),
        retry_policy(),
    )
    .bootstrap_genesis(&bootstrap, &fixture.genesis_package)
    .await
    .expect("bootstrap genesis");

    let effective_from = canonical_time(server_time(pool).await);
    let statement = GenesisRegistryActivationStatementV1 {
        schema_version: 1,
        profile: fixture.profile.clone(),
        scope: fixture.semantic_scope.clone(),
        expected_anchor: GenesisRegistryAnchorV1::from_verified(
            &bootstrap,
            &fixture.genesis_package,
        )
        .expect("anchor"),
        package_digest: fixture.genesis_package.package_digest(),
        resulting_activation_policy_digest: genesis_activation_policy_digest(
            &fixture.genesis_package,
        )
        .expect("policy digest"),
        effective_from: effective_from.clone(),
        effective_until: None,
        test_vector_result_digest: fixture.genesis_test_result.result_digest(),
        proposer_principal_id: ContractId::new("principal.operator").expect("principal"),
        package_author_principal_id: ContractId::new("principal.author").expect("principal"),
    };
    let statement_id = statement.statement_id().expect("statement id");
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
    let request = verify_genesis_registry_activation(
        &encode_canonical(&statement).expect("canonical statement"),
        &encode_canonical(&approval_set).expect("canonical approvals"),
        &bootstrap,
        &fixture.genesis_package,
        &fixture.genesis_test_result,
        &fixture.genesis_principal_binding,
    )
    .expect("verified genesis request");

    let repository = CockroachGenesisActivationRepository::new(
        pool.clone(),
        trusted_scope(&physical_scope, fixture),
        retry_policy(),
        bootstrap.clone(),
        fixture.genesis_package.clone(),
        fixture.genesis_test_result.clone(),
        fixture.genesis_principal_binding.clone(),
    )
    .expect("genesis activation repository");
    let accepted = match repository
        .activate_genesis(&request)
        .await
        .expect("activate genesis")
    {
        GenesisActivationOutcome::Inserted(accepted)
        | GenesisActivationOutcome::ExactReplay(accepted) => accepted,
    };
    ActivatedGenesis {
        physical_scope,
        bootstrap,
        head: RegistryHeadBindingV1 {
            head: accepted.registry_head,
            effective_from,
            effective_until: None,
        },
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
        .expect("activation policy entry");
    RegistryReferenceV1 {
        entry_id: entry.entry_id.clone(),
        version: entry.version,
        entry_digest: entry.digest().expect("entry digest"),
    }
}

fn successor_runner_pin() -> SuccessorRegistryTestRunnerPin {
    SuccessorRegistryTestRunnerPin::from_trusted_config(
        digest(SUCCESSOR_RUNNER_ARTIFACT),
        digest(SUCCESSOR_RUNNER_CONFIGURATION),
        RegistryTestResultDigest::from_digest(digest(SUCCESSOR_TEST_RESULT_DIGEST)),
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
        let pair = Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).expect("key");
        ActivationSignerBindingV2 {
            principal_id: ContractId::new(principal).expect("principal"),
            algorithm: ActivationSignatureAlgorithmV2::Ed25519,
            public_key: FixedHex32::from_bytes(
                pair.public_key().as_ref().try_into().expect("public key"),
            ),
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
    let bridge_digest = bridge.bridge_digest().expect("bridge digest");
    (
        encode_canonical(&bridge).expect("canonical bridge"),
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
    let pair = Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).expect("key");
    SuccessorRegistryActivationApprovalV1 {
        schema_version: 1,
        statement_id,
        signer_principal_id: ContractId::new(principal).expect("principal"),
        signature: FixedHex64::from_bytes(pair.sign(&message).as_ref().try_into().expect("sig")),
    }
}

/// Run the real bootstrap -> genesis -> first-successor chain and return the
/// pins a writer would be configured with.
async fn activate_first_successor(
    pool: &PgPool,
    fixture: &ContractFixture,
    label: &str,
    seed: u8,
) -> ActiveHead {
    let genesis = activate_genesis(pool, fixture, label, seed).await;
    let (bridge_bytes, bridge_pin, bridge_digest) = bridge_for(fixture, &genesis);
    let effective_from = canonical_time(server_time(pool).await);
    let test_result = verify_successor_registry_test_result(
        record(SUCCESSOR_TEST_RESULT),
        successor_runner_pin(),
        &fixture.target,
    )
    .expect("successor test result");
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
        proposer_principal_id: ContractId::new("principal.operator").expect("principal"),
        package_author_principal_id: ContractId::new("principal.author").expect("principal"),
    };
    let statement_id = statement.statement_id().expect("statement id");
    let approval_set = SuccessorRegistryActivationApprovalSetV1 {
        schema_version: 1,
        statement_id,
        approvals: vec![
            successor_approval(statement_id, "principal.alice", 1),
            successor_approval(statement_id, "principal.bob", 2),
        ],
    };
    let candidate = SuccessorActivationCandidate::from_bounded_canonical_bytes(
        encode_canonical(&statement).expect("canonical statement"),
        encode_canonical(&approval_set).expect("canonical approvals"),
    )
    .expect("successor candidate");

    let repository = CockroachSuccessorActivationRepository::new(
        pool.clone(),
        trusted_scope(&genesis.physical_scope, fixture),
        retry_policy(),
        genesis.bootstrap.clone(),
        fixture.genesis_package.clone(),
        fixture.genesis_test_result.clone(),
        fixture.genesis_principal_binding.clone(),
        fixture.target.clone(),
        record(SUCCESSOR_TEST_RESULT),
        successor_runner_pin(),
        bridge_bytes,
        bridge_pin,
        SuccessorActivationPrincipalBinding::from_trusted_config(
            ContractId::new("principal.operator").expect("principal"),
            ContractId::new("principal.author").expect("principal"),
        ),
    )
    .expect("successor repository");
    let accepted = match repository
        .activate_first_successor(&candidate)
        .await
        .expect("activate first successor")
    {
        SuccessorActivationOutcome::Inserted(accepted)
        | SuccessorActivationOutcome::ExactReplay(accepted) => accepted,
    };

    ActiveHead {
        physical_scope: genesis.physical_scope,
        config: WriterAuthorityConfig::from_trusted_context(
            fixture.semantic_scope.clone(),
            genesis.bootstrap.receipt_digest(),
            None,
        ),
        activation_id: accepted.activation_id.digest(),
        package_digest: fixture.target.package_digest(),
    }
}

const fn rejection(error: &WriterAuthorityError) -> Option<WriterAuthorityRejection> {
    match error {
        WriterAuthorityError::Rejected(rejection) => Some(*rejection),
        WriterAuthorityError::Database(_) | WriterAuthorityError::Contract(_) => None,
    }
}

#[tokio::test]
async fn live_writer_authority_witness_materializes_the_stage4_head_when_configured() {
    let Some(pool) = migrated_pool().await else {
        return;
    };
    let fixture = fixture();
    let head = activate_first_successor(&pool, &fixture, "materialize", 41).await;

    let witness = load_and_verify(&pool, &head.physical_scope, &head.config)
        .await
        .expect("writer authority witness");

    assert_eq!(witness.activation_id(), head.activation_id);
    assert_eq!(witness.generation(), 1);
    assert_eq!(witness.package_digest(), head.package_digest);
    assert_eq!(
        witness.package().package_digest(),
        fixture.target.package_digest(),
        "the witness must materialize the exact compiled-in Stage-4 package"
    );
    assert_eq!(witness.shard_count(), 16);
    assert_eq!(
        witness.partition_recipe_id().as_str(),
        "ostk.partition.sha256_prefix64_modulo"
    );
    assert_eq!(witness.partition_recipe_version(), 1);
    assert_eq!(witness.partition_seed(), &[41_u8; 32]);
    assert_eq!(
        witness.log_epoch_id().digest(),
        head_epoch(&pool, &head.physical_scope).await
    );
    assert_eq!(
        witness.contract_tenant_namespace().as_str(),
        fixture.semantic_scope.tenant_namespace.as_str()
    );
    assert_eq!(
        witness.head_binding().head.activation_id,
        head.activation_id
    );
    assert_eq!(
        witness.canonical_head(),
        encode_canonical(witness.head_binding()).expect("canonical head")
    );

    // D4: nothing is cached across calls; the second read is a fresh SELECT.
    let again = load_and_verify(&pool, &head.physical_scope, &head.config)
        .await
        .expect("second writer authority witness");
    assert_eq!(again.activation_id(), witness.activation_id());
}

async fn head_epoch(pool: &PgPool, scope: &FleetScope) -> Sha256Digest {
    let row = sqlx::query(
        "SELECT log_epoch_id FROM public.memory_writer_authority_v1 \
         WHERE tenant_id = $1 AND project = $2",
    )
    .bind(scope.tenant_id)
    .bind(&scope.project)
    .fetch_one(pool)
    .await
    .expect("authority row");
    let bytes: Vec<u8> = row.get("log_epoch_id");
    Sha256Digest::from_bytes(bytes.try_into().expect("32-byte epoch id"))
}

#[tokio::test]
async fn live_writer_authority_rejects_a_mismatched_bootstrap_receipt_pin_when_configured() {
    let Some(pool) = migrated_pool().await else {
        return;
    };
    let fixture = fixture();
    let head = activate_first_successor(&pool, &fixture, "receipt-pin", 42).await;
    let other = signed_bootstrap(&fixture, 43);
    let forged = WriterAuthorityConfig::from_trusted_context(
        fixture.semantic_scope.clone(),
        other.receipt_digest(),
        None,
    );

    let error = load_and_verify(&pool, &head.physical_scope, &forged)
        .await
        .expect_err("a mismatched receipt pin must fail closed");
    assert_eq!(
        rejection(&error),
        Some(WriterAuthorityRejection::BootstrapPin),
        "unexpected rejection: {error}"
    );
}

#[tokio::test]
async fn live_writer_authority_rejects_mismatched_contract_namespaces_when_configured() {
    let Some(pool) = migrated_pool().await else {
        return;
    };
    let fixture = fixture();
    let head = activate_first_successor(&pool, &fixture, "namespace", 44).await;

    for scope in [
        AuthenticatedProjectScopeV1::from_trusted_context(
            ContractId::new("tenant.other").expect("namespace"),
            fixture.semantic_scope.project_namespace.clone(),
        ),
        AuthenticatedProjectScopeV1::from_trusted_context(
            fixture.semantic_scope.tenant_namespace.clone(),
            ContractId::new("project.other").expect("namespace"),
        ),
    ] {
        let forged = WriterAuthorityConfig::from_trusted_context(
            scope,
            head.config.bootstrap_receipt_digest(),
            None,
        );
        let error = load_and_verify(&pool, &head.physical_scope, &forged)
            .await
            .expect_err("a mismatched contract namespace must fail closed");
        assert_eq!(
            rejection(&error),
            Some(WriterAuthorityRejection::ContractNamespace),
            "unexpected rejection: {error}"
        );
    }
}

#[tokio::test]
async fn live_writer_authority_rejects_a_break_glass_activation_id_mismatch_when_configured() {
    let Some(pool) = migrated_pool().await else {
        return;
    };
    let fixture = fixture();
    let head = activate_first_successor(&pool, &fixture, "break-glass", 45).await;

    let exact = WriterAuthorityConfig::from_trusted_context(
        fixture.semantic_scope.clone(),
        head.config.bootstrap_receipt_digest(),
        Some(head.activation_id),
    );
    assert_eq!(
        load_and_verify(&pool, &head.physical_scope, &exact)
            .await
            .expect("the exact break-glass activation ID must be admitted")
            .activation_id(),
        head.activation_id
    );

    let wrong = WriterAuthorityConfig::from_trusted_context(
        fixture.semantic_scope.clone(),
        head.config.bootstrap_receipt_digest(),
        Some(Sha256Digest::from_bytes([0x9c; 32])),
    );
    let error = load_and_verify(&pool, &head.physical_scope, &wrong)
        .await
        .expect_err("a break-glass activation ID mismatch must fail closed");
    assert_eq!(
        rejection(&error),
        Some(WriterAuthorityRejection::ExpectedActivationId),
        "unexpected rejection: {error}"
    );
}

#[tokio::test]
async fn live_writer_authority_fails_closed_without_an_active_head_when_configured() {
    let Some(pool) = migrated_pool().await else {
        return;
    };
    let fixture = fixture();

    // A scope with a durable bootstrap and a genesis activation but no
    // successor has no row in the current-head projection, so the authority
    // view is empty. Migration 0014 CHECKs head_state = 'active', so a
    // non-active head cannot exist at all; absence is the reachable case.
    let genesis = activate_genesis(&pool, &fixture, "no-head", 46).await;
    let config = WriterAuthorityConfig::from_trusted_context(
        fixture.semantic_scope.clone(),
        genesis.bootstrap.receipt_digest(),
        None,
    );
    let error = load_and_verify(&pool, &genesis.physical_scope, &config)
        .await
        .expect_err("a scope without an active head must fail closed");
    assert_eq!(
        rejection(&error),
        Some(WriterAuthorityRejection::Absent),
        "unexpected rejection: {error}"
    );

    // A scope with no durable control state at all is equally closed; there is
    // no last-known-head fallback.
    let unknown = physical_scope("never-bootstrapped");
    let error = load_and_verify(&pool, &unknown, &config)
        .await
        .expect_err("an unknown scope must fail closed");
    assert_eq!(
        rejection(&error),
        Some(WriterAuthorityRejection::Absent),
        "unexpected rejection: {error}"
    );
}

/// What serializable isolation actually guarantees for the D4 witness.
///
/// A concurrent activation does NOT necessarily abort an in-flight append on
/// `CockroachDB` v26.2.3: the appender's reads of the head are recorded in the
/// timestamp cache, the activation's later write sits above them, and the
/// appender commits at its own earlier timestamp. That is exactly
/// serializable — the append is equivalent to having run entirely before the
/// activation, under the head it observed — and it is the property D4 needs.
/// An abort is possible (a pushed commit timestamp forces a read refresh that
/// the changed head fails) but is not deterministic, so this test asserts the
/// properties that always hold:
///
/// 1. one transaction never observes two different heads (no torn head);
/// 2. an append that commits is attributable to the head it observed, and an
///    append that aborts leaves nothing durable;
/// 3. any transaction that starts after the change fails closed, with no
///    last-known-head fallback and with the ABA rollback caught on the exact
///    activation ID rather than on the restored package digest.
#[tokio::test]
#[allow(clippy::too_many_lines)] // one linear race narrative reads better whole
async fn live_writer_authority_never_observes_a_torn_head_across_a_concurrent_rollback_when_configured()
 {
    let Some(pool) = migrated_pool().await else {
        return;
    };
    let fixture = fixture();
    let head = activate_first_successor(&pool, &fixture, "race", 47).await;

    let mut appender = pool.begin().await.expect("begin");
    sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        .execute(&mut *appender)
        .await
        .expect("serializable");
    let observed = verify_within(&mut appender, &head.physical_scope, &head.config)
        .await
        .expect("witness inside the append transaction");
    assert_eq!(observed.activation_id(), head.activation_id);

    // The append this transaction would perform: lazily seed the evidence
    // shard head bound to the epoch the witness carries (ADR 0002 D1). The
    // transaction is therefore read-write, exactly as a real append is.
    sqlx::query(
        "INSERT INTO public.memory_evidence_shard_heads (tenant_id, project, epoch_id, shard, \
         shard_count, last_committed_offset, chain_digest, advanced_at) \
         VALUES ($1, $2, $3, 0, $4, 0, $5, statement_timestamp()) ON CONFLICT DO NOTHING",
    )
    .bind(head.physical_scope.tenant_id)
    .bind(&head.physical_scope.project)
    .bind(observed.log_epoch_id().digest().as_bytes().to_vec())
    .bind(i32::from(observed.shard_count()))
    .bind(vec![0x11_u8; 32])
    .execute(&mut *appender)
    .await
    .expect("lazy evidence head seed");

    // Concurrently, an activation rolls the head back to generation 0. Every
    // one of migration 0014's seventeen foreign-key columns is copied from the
    // durable genesis transition, so the forged head is fully self-consistent
    // and the composite view still joins.
    let rolled_back = sqlx::query(
        "UPDATE public.memory_registry_current_heads_v2 AS h SET generation = t.generation, \
         activation_id = t.activation_id, package_digest = t.package_digest, \
         activation_policy_digest = t.activation_policy_digest, profile_id = t.profile_id, \
         profile_digest = t.profile_digest, vector_manifest_digest = t.vector_manifest_digest, \
         contract_tenant_namespace = t.contract_tenant_namespace, \
         contract_project_namespace = t.contract_project_namespace, \
         effective_from = t.effective_from, accepted_at = t.accepted_at, \
         source_event_id = t.source_event_id, source_epoch_id = t.source_epoch_id, \
         source_shard = t.source_shard, source_committed_offset = t.source_committed_offset, \
         canonical_head = t.canonical_head \
         FROM public.memory_registry_transitions AS t \
         WHERE t.tenant_id = h.tenant_id AND t.project = h.project AND t.generation = 0 \
           AND h.tenant_id = $1 AND h.project = $2",
    )
    .bind(head.physical_scope.tenant_id)
    .bind(&head.physical_scope.project)
    .execute(&pool)
    .await
    .expect("head rollback");
    assert_eq!(rolled_back.rows_affected(), 1);

    let recheck = verify_within(&mut appender, &head.physical_scope, &head.config).await;
    if let Ok(rechecked) = &recheck {
        assert_eq!(
            rechecked.activation_id(),
            head.activation_id,
            "an in-transaction re-read must never observe the rolled-back activation as its own"
        );
        assert_eq!(rechecked.generation(), observed.generation());
        assert_eq!(rechecked.canonical_head(), observed.canonical_head());
    }
    let committed = appender.commit().await;

    // Either the append was serialized before the rollback, under exactly the
    // head it observed, or its read refresh failed and nothing is durable.
    let seeded: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT epoch_id FROM public.memory_evidence_shard_heads \
         WHERE tenant_id = $1 AND project = $2",
    )
    .bind(head.physical_scope.tenant_id)
    .bind(&head.physical_scope.project)
    .fetch_all(&pool)
    .await
    .expect("evidence heads");
    if committed.is_ok() && recheck.is_ok() {
        assert_eq!(
            seeded,
            vec![observed.log_epoch_id().digest().as_bytes().to_vec()],
            "a committed append must bind exactly the epoch its witness observed"
        );
    } else {
        assert!(
            seeded.is_empty(),
            "an aborted append must not seed an evidence head"
        );
    }

    // ABA safety: after the rollback the exact activation ID differs and the
    // generation is below the first activated generation, so a fresh witness
    // read fails closed rather than silently accepting the restored package.
    let error = load_and_verify(&pool, &head.physical_scope, &head.config)
        .await
        .expect_err("a rolled-back head must fail closed");
    assert_eq!(
        rejection(&error),
        Some(WriterAuthorityRejection::Generation),
        "unexpected rejection: {error}"
    );
}

#[tokio::test]
async fn live_writer_authority_runs_under_the_runtime_grant_matrix_without_control_access_when_configured()
 {
    let Some(pool) = migrated_pool().await else {
        return;
    };
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let fixture = fixture();
    let head = activate_first_successor(&pool, &fixture, "least-privilege", 48).await;

    let role = format!("witness_probe_{}", Uuid::now_v7().simple());
    let password = Uuid::now_v7().simple().to_string();
    sqlx::query(&format!(
        "CREATE ROLE {role} WITH LOGIN PASSWORD '{password}'"
    ))
    .execute(&pool)
    .await
    .expect("create probe role");
    sqlx::query(&format!("GRANT CONNECT ON DATABASE fleet_recall TO {role}"))
        .execute(&pool)
        .await
        .expect("grant connect");
    sqlx::query(&format!("GRANT USAGE ON SCHEMA public TO {role}"))
        .execute(&pool)
        .await
        .expect("grant schema usage");
    for (privileges, relations) in RUNTIME_EVIDENCE_GRANTS {
        sqlx::query(&format!(
            "GRANT {privileges} ON TABLE {relations} TO {role}"
        ))
        .execute(&pool)
        .await
        .expect("grant runtime privileges");
    }

    let probe_pool = CockroachStore::connect(
        &probe_database_url(&database_url, &role, &password),
        head.physical_scope.clone(),
        pool_config(),
    )
    .await
    .expect("connect probe pool")
    .pool()
    .clone();

    let witness = load_and_verify(&probe_pool, &head.physical_scope, &head.config)
        .await
        .expect("the runtime grant matrix must suffice for the head witness");
    assert_eq!(witness.activation_id(), head.activation_id);
    assert_eq!(witness.package_digest(), head.package_digest);

    for table in FORBIDDEN_BASE_TABLES {
        let error = sqlx::query(&format!("SELECT count(*) FROM {table}"))
            .execute(&probe_pool)
            .await
            .expect_err("the runtime identity must not read a control or registry base table");
        assert_eq!(
            error
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::code)
                .as_deref(),
            Some("42501"),
            "unexpected error reading {table}: {error}"
        );
    }

    // The lazy evidence head seed needs no control-table privilege, which is
    // exactly why migration 0018 gives the evidence head table no foreign key
    // into the control plane (ADR 0002 D1 amendment).
    sqlx::query(
        "INSERT INTO public.memory_evidence_shard_heads (tenant_id, project, epoch_id, shard, \
         shard_count, last_committed_offset, chain_digest, advanced_at) \
         VALUES ($1, $2, $3, 0, $4, 0, $5, statement_timestamp()) ON CONFLICT DO NOTHING",
    )
    .bind(head.physical_scope.tenant_id)
    .bind(&head.physical_scope.project)
    .bind(witness.log_epoch_id().digest().as_bytes().to_vec())
    .bind(i32::from(witness.shard_count()))
    .bind(vec![0x22_u8; 32])
    .execute(&probe_pool)
    .await
    .expect("the runtime identity must be able to seed an evidence shard head");
}

/// Rewrite the root test URL into a password-authenticated URL for the probe
/// role: the client certificate is dropped, TLS verification is kept.
fn probe_database_url(database_url: &str, role: &str, password: &str) -> String {
    let parsed = Url::parse(database_url).expect("test database URL");
    let retained = parsed
        .query_pairs()
        .filter(|(name, _)| name == "sslmode" || name == "sslrootcert")
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    let mut probe = parsed;
    probe.set_username(role).expect("probe username");
    probe.set_password(Some(password)).expect("probe password");
    probe.query_pairs_mut().clear();
    for (name, value) in retained {
        probe.query_pairs_mut().append_pair(&name, &value);
    }
    probe.into()
}

#[test]
fn writer_authority_materialization_rejects_an_unknown_package_digest() {
    let fixture = fixture();
    assert_eq!(
        materialize_active_package(fixture.target.package_digest())
            .expect("the frozen Stage-4 digest materializes")
            .package_digest(),
        fixture.target.package_digest()
    );

    for unknown in [
        Sha256Digest::ZERO,
        fixture.genesis_package.package_digest(),
        Sha256Digest::from_bytes([0x7e; 32]),
    ] {
        let error = materialize_active_package(unknown)
            .expect_err("an unknown active package digest must fail closed");
        assert_eq!(
            rejection(&error),
            Some(WriterAuthorityRejection::UnknownActivePackage),
            "unexpected rejection: {error}"
        );
    }
}

// ---------------------------------------------------------------------------
// Negative vectors for the three checks a root UPDATE can reach
// ---------------------------------------------------------------------------

/// One head-binding forgery: an edit of the decoded binding, re-encoded
/// canonically and stored under an untouched projection.
type HeadMutation = fn(&mut RegistryHeadBindingV1, Sha256Digest);

const fn is_contract_error(error: &WriterAuthorityError) -> bool {
    matches!(error, WriterAuthorityError::Contract(_))
}

/// Exact bytes the view currently projects as the active head.
async fn canonical_head_bytes(pool: &PgPool, scope: &FleetScope) -> Vec<u8> {
    sqlx::query_scalar(
        "SELECT canonical_head FROM public.memory_writer_authority_v1 \
         WHERE tenant_id = $1 AND project = $2",
    )
    .bind(scope.tenant_id)
    .bind(&scope.project)
    .fetch_one(pool)
    .await
    .expect("projected canonical head")
}

/// Replace the stored canonical head as root. `canonical_head` is not one of
/// the seventeen columns migration 0014's foreign key covers and is not a view
/// join column, so the composite join still succeeds and the tampered head
/// reaches the witness rather than disappearing from the projection.
async fn store_canonical_head(pool: &PgPool, scope: &FleetScope, bytes: Vec<u8>) {
    let updated = sqlx::query(
        "UPDATE public.memory_registry_current_heads_v2 SET canonical_head = $3 \
         WHERE tenant_id = $1 AND project = $2",
    )
    .bind(scope.tenant_id)
    .bind(&scope.project)
    .bind(bytes)
    .execute(pool)
    .await
    .expect("store the tampered canonical head");
    assert_eq!(updated.rows_affected(), 1);
}

/// REPLAY-01. The durable log epoch must equal the pinned receipt's genesis
/// epoch, because the evidence ledger's head rows carry no foreign key to the
/// control epoch (ADR 0002 D1 amendment) and this comparison is what replaces
/// it. `partition_seed` is the one epoch column a root UPDATE can reach —
/// `shard_count` is held by `memory_control_head_epoch_fk` and
/// `partition_recipe_version` by a CHECK — and it is precisely the value the
/// shard recipe depends on. The remaining seven fields `verify_epoch` compares
/// are covered offline by
/// `registry_witness::tests::epoch_verification_binds_every_field_of_the_receipts_genesis_epoch`.
#[tokio::test]
async fn live_writer_authority_rejects_a_durable_log_epoch_drift_when_configured() {
    let Some(pool) = migrated_pool().await else {
        return;
    };
    let fixture = fixture();
    let head = activate_first_successor(&pool, &fixture, "epoch-drift", 71).await;
    load_and_verify(&pool, &head.physical_scope, &head.config)
        .await
        .expect("the untampered head must verify");

    let updated = sqlx::query(
        "UPDATE public.memory_control_log_epochs SET partition_seed = $3 \
         WHERE tenant_id = $1 AND project = $2",
    )
    .bind(head.physical_scope.tenant_id)
    .bind(&head.physical_scope.project)
    .bind(vec![0x40_u8; 32])
    .execute(&pool)
    .await
    .expect("a root UPDATE of the partition seed must be possible");
    assert_eq!(updated.rows_affected(), 1);

    let error = load_and_verify(&pool, &head.physical_scope, &head.config)
        .await
        .expect_err("a durable epoch that disagrees with the receipt must fail closed");
    assert_eq!(
        rejection(&error),
        Some(WriterAuthorityRejection::LogEpoch),
        "unexpected rejection: {error}"
    );

    // D4: the in-transaction re-check is the same code path, so it reaches the
    // same verdict rather than trusting an earlier successful read.
    let mut transaction = pool.begin().await.expect("begin");
    let error = verify_within(&mut transaction, &head.physical_scope, &head.config)
        .await
        .expect_err("the in-transaction re-check must fail closed too");
    assert_eq!(
        rejection(&error),
        Some(WriterAuthorityRejection::LogEpoch),
        "unexpected in-transaction rejection: {error}"
    );
    transaction.rollback().await.expect("rollback");

    // The two epoch columns the schema itself holds. Either verdict is
    // acceptable; silently verifying is not.
    for (column, value) in [("shard_count", "8"), ("partition_recipe_version", "2")] {
        let attempt = sqlx::query(&format!(
            "UPDATE public.memory_control_log_epochs SET {column} = {value} \
             WHERE tenant_id = $1 AND project = $2"
        ))
        .bind(head.physical_scope.tenant_id)
        .bind(&head.physical_scope.project)
        .execute(&pool)
        .await;
        match attempt {
            Ok(updated) => {
                assert_eq!(updated.rows_affected(), 1, "column {column}");
                let error = load_and_verify(&pool, &head.physical_scope, &head.config)
                    .await
                    .expect_err("a tampered epoch column must fail closed");
                assert_eq!(
                    rejection(&error),
                    Some(WriterAuthorityRejection::LogEpoch),
                    "column {column}: unexpected rejection {error}"
                );
            }
            Err(error) => {
                println!("epoch column {column} is held by the schema: {error}");
            }
        }
    }
}

/// D4. The canonical head bytes are the preimage an appended statement binds,
/// so they must agree with every projected column the head carries. Each case
/// re-encodes a cleanly decodable binding, so nothing but `verify_head_binding`
/// can catch it.
#[tokio::test]
async fn live_writer_authority_rejects_a_canonical_head_that_misbinds_the_projection_when_configured()
 {
    let Some(pool) = migrated_pool().await else {
        return;
    };
    let fixture = fixture();
    let head = activate_first_successor(&pool, &fixture, "head-binding", 72).await;
    let original = canonical_head_bytes(&pool, &head.physical_scope).await;
    load_and_verify(&pool, &head.physical_scope, &head.config)
        .await
        .expect("the untampered head must verify");

    let foreign = Sha256Digest::from_bytes([0xab; 32]);
    let mutations: [(&str, HeadMutation); 5] = [
        ("activation_id", |binding, foreign| {
            binding.head.activation_id = foreign;
        }),
        ("package_digest", |binding, foreign| {
            binding.head.package_digest = foreign;
        }),
        ("activation_policy_digest", |binding, foreign| {
            binding.head.activation_policy_digest = foreign;
        }),
        ("effective_from", |binding, _| {
            binding.effective_from = CanonicalTimestamp::parse("2031-01-01T00:00:00.000000000Z")
                .expect("canonical timestamp");
        }),
        ("effective_until", |binding, _| {
            binding.effective_until = Some(
                CanonicalTimestamp::parse("2031-01-01T00:00:00.000000000Z")
                    .expect("canonical timestamp"),
            );
        }),
    ];

    for (label, mutate) in mutations {
        let mut binding: RegistryHeadBindingV1 =
            decode_strict(&original).expect("the projected head decodes");
        mutate(&mut binding, foreign);
        let forged = encode_canonical(&binding).expect("forged canonical head");
        assert_ne!(forged, original, "{label}: the forgery must differ");
        store_canonical_head(&pool, &head.physical_scope, forged).await;

        let error = load_and_verify(&pool, &head.physical_scope, &head.config)
            .await
            .expect_err("a canonical head that misbinds the projection must fail closed");
        assert_eq!(
            rejection(&error),
            Some(WriterAuthorityRejection::HeadBinding),
            "{label}: unexpected rejection {error}"
        );
    }

    // Restoring the exact bytes restores authority: the rejection is a verdict
    // about this read, never a latched state.
    store_canonical_head(&pool, &head.physical_scope, original).await;
    let witness = load_and_verify(&pool, &head.physical_scope, &head.config)
        .await
        .expect("the restored head must verify again");
    assert_eq!(witness.activation_id(), head.activation_id);
}

/// D4. A stored head that is valid JSON but not already in canonical byte form
/// is a contract failure, not a rejection: the writer would otherwise bind a
/// preimage no other participant can reproduce. Whitespace is caught by
/// `require_canonical`; a dropped `effective_until` member is canonical JSON
/// that decodes cleanly and is caught only by the re-encode comparison.
#[tokio::test]
async fn live_writer_authority_rejects_noncanonical_head_bytes_when_configured() {
    let Some(pool) = migrated_pool().await else {
        return;
    };
    let fixture = fixture();
    let head = activate_first_successor(&pool, &fixture, "noncanonical", 73).await;
    let original = canonical_head_bytes(&pool, &head.physical_scope).await;

    let value: serde_json::Value =
        serde_json::from_slice(&original).expect("the projected head is JSON");
    let pretty = serde_json::to_vec_pretty(&value).expect("pretty printed head");
    assert_ne!(pretty, original);
    store_canonical_head(&pool, &head.physical_scope, pretty).await;
    let error = load_and_verify(&pool, &head.physical_scope, &head.config)
        .await
        .expect_err("a pretty printed head must fail closed");
    assert!(
        is_contract_error(&error),
        "expected a canonicality contract error, got {error}"
    );

    let text = String::from_utf8(original.clone()).expect("canonical JSON is UTF-8");
    let trimmed = text.replace("\"effective_until\":null,", "");
    assert_ne!(
        trimmed, text,
        "the projected head must carry effective_until"
    );
    store_canonical_head(&pool, &head.physical_scope, trimmed.into_bytes()).await;
    let error = load_and_verify(&pool, &head.physical_scope, &head.config)
        .await
        .expect_err("a head whose bytes do not re-encode must fail closed");
    assert!(
        is_contract_error(&error),
        "expected a canonicality contract error, got {error}"
    );

    store_canonical_head(&pool, &head.physical_scope, original).await;
    load_and_verify(&pool, &head.physical_scope, &head.config)
        .await
        .expect("the restored head must verify again");
}

/// AUTH-04 descent, and the reason its negative vectors are offline.
///
/// `verify_descent` requires the transition's root columns to be the genesis
/// the pinned receipt names. This test establishes that no root UPDATE can
/// produce a head that reaches that check with a foreign root: migration
/// 0012's `memory_registry_transition_genesis_head_fk` and
/// `memory_registry_transition_genesis_activation_fk` hold every root column,
/// and its predecessor foreign key holds the predecessor columns. If a schema
/// change ever makes one reachable, this test stops passing quietly and starts
/// asserting the rejection instead. The negative vectors themselves live in
/// `registry_witness::tests::descent_verification_requires_the_pinned_genesis_root`.
#[tokio::test]
async fn live_writer_authority_descent_columns_are_held_by_the_schema_when_configured() {
    let Some(pool) = migrated_pool().await else {
        return;
    };
    let fixture = fixture();
    let head = activate_first_successor(&pool, &fixture, "descent", 74).await;
    load_and_verify(&pool, &head.physical_scope, &head.config)
        .await
        .expect("the untampered head must verify");

    let mut refusals = 0_u32;
    for column in [
        "root_package_digest",
        "root_activation_policy_digest",
        "root_activation_id",
        "predecessor_activation_id",
        "predecessor_package_digest",
    ] {
        let attempt = sqlx::query(&format!(
            "UPDATE public.memory_registry_transitions SET {column} = $3 \
             WHERE tenant_id = $1 AND project = $2 AND generation = 1"
        ))
        .bind(head.physical_scope.tenant_id)
        .bind(&head.physical_scope.project)
        .bind(vec![0xc7_u8; 32])
        .execute(&pool)
        .await;
        match attempt {
            Ok(updated) => {
                assert_eq!(updated.rows_affected(), 1, "column {column}");
                let error = load_and_verify(&pool, &head.physical_scope, &head.config)
                    .await
                    .expect_err("a forged descent must fail closed");
                assert_eq!(
                    rejection(&error),
                    Some(WriterAuthorityRejection::Descent),
                    "column {column}: unexpected rejection {error}"
                );
            }
            Err(error) => {
                refusals += 1;
                println!("descent column {column} is held by the schema: {error}");
            }
        }
    }
    assert!(
        refusals > 0,
        "at least one descent column is expected to be held by a foreign key; \
         if none are, the offline vectors are the only descent coverage and \
         this test should be tightened"
    );
}

/// D4. Serializable isolation is the ENTIRE fence: `verify_within` issues no
/// CAS, takes no lock, and reads no base table, so a transaction running at a
/// weaker level can read the head, watch another session activate a different
/// one, read it again, and still commit — binding an append to a head it was
/// never serialized under. The fence is therefore asserted rather than
/// assumed. This test drives the exact downgrade: `SET TRANSACTION ISOLATION
/// LEVEL READ COMMITTED` inside the caller's own transaction, which
/// `CockroachDB` v26.2 accepts, and requires
/// `WriterAuthorityRejection::IsolationLevel` from every subsequent
/// `verify_within` — so no witness exists to bind an append with, and the
/// two-heads-one-transaction hazard is unreachable through this module.
#[tokio::test]
async fn live_writer_authority_rejects_a_non_serializable_transaction_when_configured() {
    let Some(pool) = migrated_pool().await else {
        return;
    };
    let fixture = fixture();
    let head = activate_first_successor(&pool, &fixture, "isolation", 75).await;

    // The default transaction is serializable, and the assertion is not a
    // blanket refusal: it mints a witness exactly as before.
    let mut serializable = pool.begin().await.expect("begin");
    let level: String = sqlx::query_scalar("SHOW transaction_isolation")
        .fetch_one(&mut *serializable)
        .await
        .expect("the transaction reports its own isolation level");
    assert_eq!(level, "serializable");
    let witness = verify_within(&mut serializable, &head.physical_scope, &head.config)
        .await
        .expect("a serializable transaction must still mint a witness");
    assert_eq!(witness.activation_id(), head.activation_id);
    serializable.rollback().await.expect("rollback");

    // Downgrading the same transaction removes the fence.
    let mut unfenced = pool.begin().await.expect("begin");
    sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .execute(&mut *unfenced)
        .await
        .expect("the cluster accepts a read committed transaction");
    let level: String = sqlx::query_scalar("SHOW transaction_isolation")
        .fetch_one(&mut *unfenced)
        .await
        .expect("the transaction reports its own isolation level");
    assert_eq!(
        level, "read committed",
        "the downgrade must actually take effect, or this test proves nothing"
    );

    for attempt in 0..2 {
        let error = verify_within(&mut unfenced, &head.physical_scope, &head.config)
            .await
            .expect_err("an unfenced transaction must never mint a witness");
        assert_eq!(
            rejection(&error),
            Some(WriterAuthorityRejection::IsolationLevel),
            "attempt {attempt}: unexpected rejection {error}"
        );
    }
    unfenced.rollback().await.expect("rollback");

    // The pool read is unchanged: an autocommit statement needs no fence, and
    // the startup check must keep working.
    load_and_verify(&pool, &head.physical_scope, &head.config)
        .await
        .expect("the out-of-transaction read is unaffected");
}

/// Scope binding. A bootstrap receipt binds the SEMANTIC namespaces, not the
/// physical scope, so one receipt — and therefore one `WriterAuthorityConfig`
/// — legitimately covers two different physical scopes. Every other field the
/// witness carries is then identical between them: same log epoch, same
/// partition recipe, same package. This test activates exactly that pair from
/// one re-signed receipt and requires the witness to name the physical scope
/// its row was read for, so a caller that appends into a scope it did not
/// verify can assert the mismatch instead of trusting argument order.
#[tokio::test]
async fn live_writer_authority_binds_the_witness_to_the_physical_scope_it_read_when_configured() {
    let Some(pool) = migrated_pool().await else {
        return;
    };
    let fixture = fixture();
    let first = activate_first_successor(&pool, &fixture, "scope-first", 76).await;
    let second = activate_first_successor(&pool, &fixture, "scope-second", 76).await;
    assert_eq!(
        first.config.bootstrap_receipt_digest().digest(),
        second.config.bootstrap_receipt_digest().digest(),
        "the two physical scopes must share one bootstrap receipt for this to be a test"
    );
    assert_ne!(first.physical_scope.project, second.physical_scope.project);

    // ONE config verifies BOTH scopes; nothing in the pins distinguishes them.
    let witness = load_and_verify(&pool, &first.physical_scope, &first.config)
        .await
        .expect("first witness");
    let elsewhere = load_and_verify(&pool, &second.physical_scope, &first.config)
        .await
        .expect("second witness under the same config");

    assert_eq!(
        witness.log_epoch_id().digest(),
        elsewhere.log_epoch_id().digest(),
        "the shared receipt means the epoch cannot distinguish the scopes"
    );
    assert_eq!(witness.package_digest(), elsewhere.package_digest());
    assert_eq!(witness.partition_seed(), elsewhere.partition_seed());

    assert_eq!(witness.tenant_id(), first.physical_scope.tenant_id);
    assert_eq!(witness.project(), first.physical_scope.project);
    assert!(witness.certifies_scope(&first.physical_scope));
    assert!(
        !witness.certifies_scope(&second.physical_scope),
        "a witness must not certify a scope it was not read for"
    );
    assert!(elsewhere.certifies_scope(&second.physical_scope));
    assert!(!elsewhere.certifies_scope(&first.physical_scope));
}
