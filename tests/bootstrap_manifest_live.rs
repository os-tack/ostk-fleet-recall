//! Connected proof for the bootstrap-manifest import (W1-IMPORT).
//!
//! Set the exact `FLEET_RECALL_TEST_DATABASE_URL` variable to a disposable
//! `CockroachDB` 26.2 database. Every test here is inert otherwise. Nothing in
//! this file starts a database process, invokes Docker, or targets a cloud
//! service. Bring up your own instance per
//! `.fleet-recall/fleet/WORKER_PROTOCOL.md` section 3 and tear it down when
//! done.
//!
//! # The proposed side table
//!
//! `memory_bootstrap_import_rows` is a proposed table the SCHEMA lane has not
//! migrated in yet (see the W1-IMPORT handoff `requests` for its exact DDL).
//! Every test that needs the projection to actually run checks
//! [`import_rows_table_exists`] first and skips with a clear message when the
//! table is absent, rather than adding a migration itself (`WORKER_PROTOCOL.md`
//! section 5: "SCHEMA lane owns 0019+").
//!
//! # Setup boilerplate
//!
//! `record`, `digest`, `retry_policy`, `physical_scope`, `live_pool`,
//! `server_time`, `canonical_time`, `ContractFixture`/`fixture`,
//! `signed_bootstrap`, `current_v1_policy_reference`, `genesis_approval`,
//! `successor_approval`, `Stage4Scope`/`activate_stage4`, `scoped_count`, and
//! `head_offset` are copied from `tests/evidence_ledger_live.rs`, exactly as
//! that file's own header describes copying from `successor_activation_live.rs`
//! — integration-test binaries cannot share a module, so every connected-proof
//! file repeats this ceremony.

use std::str::FromStr as _;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use ostk_fleet_recall::FleetScope;
use ostk_fleet_recall::control_log::{
    CockroachGenesisRepository, GenesisRepository, TrustedControlScope,
};
use ostk_fleet_recall::evidence_ledger::{
    AcceptedEventRepository, AppendOutcome, AppendProjection, AppendableAcceptedEvent,
    BootstrapImportProjection, CockroachAcceptedEventRepository, EvidenceAppendError,
    EvidenceAppendResult, ProjectionContext, WitnessMismatchKind, WriterAuthorityWitness,
    import_rows_table_exists,
};
use ostk_fleet_recall::memory_contracts::bootstrap::{
    BootstrapAttestationV1, BootstrapPin, BootstrapReceiptDigest, BootstrapReceiptV1, EpochId,
    VerifiedBootstrapReceipt, verify_pinned_bootstrap,
};
use ostk_fleet_recall::memory_contracts::bootstrap_manifest::{
    BootstrapManifestAcceptedStatementV1, BootstrapManifestRowV1, BootstrapManifestV1,
    LegacyPrimaryKeyComponentV1, LegacyTableV1, legacy_row_digest,
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
    ManifestVerifiedRegistryPackage, RegistryEntryKind, RegistryEntryV1,
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
const CONNECTOR_ENTRY: &[u8] =
    include_bytes!("../contracts/dynamic-memory/v2/evidence/connector-schema-v2-entry.jsonl");

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
        format!("bootstrap-import-{label}-{}", Uuid::now_v7()),
        "bootstrap-manifest-import-connected-test",
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
// Copied from tests/evidence_ledger_live.rs so every append below runs
// against a head that is the Stage-4 package at generation one. The
// `connector` field is unused by this file (bootstrap-manifest events do not
// go through a connector schema) but stays for parity with the source file.
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct ContractFixture {
    profile: ProfileReferenceV1,
    semantic_scope: AuthenticatedProjectScopeV1,
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
    // Decoded only to prove the fixture corpus this file shares with
    // evidence_ledger_live.rs still parses; bootstrap-manifest events never
    // reference a connector.
    let _connector_entry: RegistryEntryV1 = decode_strict(record(CONNECTOR_ENTRY)).unwrap();
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

/// One live scope whose registry head is the Stage-4 package at generation one.
struct Stage4Scope {
    physical_scope: FleetScope,
    trusted_scope: TrustedControlScope,
    head: RegistryHeadBindingV1,
    repository: Arc<CockroachAcceptedEventRepository>,
    witness: WriterAuthorityWitness,
}

impl Stage4Scope {
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
) -> Stage4Scope {
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

    let repository = Arc::new(CockroachAcceptedEventRepository::new(
        pool.clone(),
        trusted_scope.clone(),
        retry_policy(),
    ));
    let witness = repository.read_writer_authority_witness().await.unwrap();
    assert_eq!(witness.generation(), 1, "the head must be generation one");
    assert_eq!(witness.head(), &head.head);

    Stage4Scope {
        physical_scope,
        trusted_scope,
        head,
        repository,
        witness,
    }
}

// ---------------------------------------------------------------------------
// Bootstrap-manifest fixtures rebound to the live head.
// ---------------------------------------------------------------------------

fn manifest_row(table: LegacyTableV1, key: &str, content: &str) -> BootstrapManifestRowV1 {
    BootstrapManifestRowV1 {
        table,
        primary_key: vec![LegacyPrimaryKeyComponentV1::Text { value: key.into() }],
        row_digest: legacy_row_digest(content.as_bytes()),
    }
}

/// Two rows, already in canonical `(table, primary_key)` order.
fn two_rows(marker: &str) -> Vec<BootstrapManifestRowV1> {
    vec![
        manifest_row(
            LegacyTableV1::MemoryChunks,
            "chunk-1",
            &format!("chunk-{marker}"),
        ),
        manifest_row(LegacyTableV1::MemoryClaims, "1", &format!("claim-{marker}")),
    ]
}

fn manifest(fixture: &ContractFixture, rows: Vec<BootstrapManifestRowV1>) -> BootstrapManifestV1 {
    BootstrapManifestV1 {
        schema_version: 1,
        scope: fixture.semantic_scope.clone(),
        provenance_kind: ContractId::new("legacy_import").unwrap(),
        rows,
    }
}

fn bootstrap_manifest_statement(
    fixture: &ContractFixture,
    head: &RegistryHeadBindingV1,
    rows: Vec<BootstrapManifestRowV1>,
) -> BootstrapManifestAcceptedStatementV1 {
    let manifest = manifest(fixture, rows);
    let manifest_digest = manifest.manifest_digest().unwrap();
    let statement = BootstrapManifestAcceptedStatementV1 {
        schema_version: 1,
        event_kind: ContractId::new("bootstrap.manifest.accepted").unwrap(),
        profile: fixture.profile.clone(),
        scope: fixture.semantic_scope.clone(),
        registry: head.clone(),
        manifest,
        manifest_digest,
    };
    statement.validate_shape().unwrap();
    statement
}

fn appendable_bootstrap_manifest(
    statement: &BootstrapManifestAcceptedStatementV1,
    witness: &WriterAuthorityWitness,
) -> AppendableAcceptedEvent {
    AppendableAcceptedEvent::bootstrap_manifest(statement, witness).unwrap()
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

async fn import_row_count(pool: &PgPool, scope: &FleetScope) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*)::INT8 FROM public.memory_bootstrap_import_rows \
         WHERE tenant_id = $1 AND project = $2",
    )
    .bind(scope.tenant_id)
    .bind(&scope.project)
    .fetch_one(pool)
    .await
    .unwrap()
}

/// A projection that panics if it ever runs. Passing it to a replay proves the
/// replay branch never repeats the lifecycle effect the original append
/// already committed (EVENT-01, EVENT-03).
struct NeverRuns;

#[async_trait::async_trait]
impl AppendProjection for NeverRuns {
    async fn project(
        &self,
        _transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        _context: ProjectionContext,
    ) -> EvidenceAppendResult<()> {
        panic!("exact replay must not re-run the projection");
    }
}

// ---------------------------------------------------------------------------
// Connected tests.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn live_bootstrap_manifest_determinism_replay_and_chain_audit_when_configured() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    if !import_rows_table_exists(&pool).await {
        eprintln!(
            "skipping live_bootstrap_manifest_determinism_replay_and_chain_audit_when_configured: \
             memory_bootstrap_import_rows does not exist yet (SCHEMA lane migration pending)"
        );
        return;
    }
    let fixture = fixture();
    let scope = activate_stage4(&pool, &fixture, "determinism", 51).await;

    // Two independent enumerations of the same rows, in the one canonical
    // sort order, are byte-identical manifests: identical accepted-event ID.
    let first_statement = bootstrap_manifest_statement(&fixture, &scope.head, two_rows("a"));
    let second_statement = bootstrap_manifest_statement(&fixture, &scope.head, two_rows("a"));
    assert_eq!(
        first_statement.accepted_event_id().unwrap(),
        second_statement.accepted_event_id().unwrap(),
        "two enumerations of the same rows must produce the same manifest digest"
    );

    let appendable = appendable_bootstrap_manifest(&first_statement, &scope.witness);
    let projection: Arc<dyn AppendProjection> = Arc::new(BootstrapImportProjection {
        scope: scope.trusted_scope.clone(),
        rows: first_statement.manifest.rows.clone(),
    });
    let outcome = scope
        .repository
        .append(&scope.witness, &appendable, projection)
        .await
        .unwrap();
    let AppendOutcome::Appended {
        position,
        chain_digest,
    } = outcome
    else {
        panic!("first append must be Appended, got {outcome:?}");
    };
    assert_eq!(position.committed_offset.as_u64(), 1);
    assert_eq!(
        import_row_count(&pool, &scope.physical_scope).await,
        2,
        "the projection must record one row per imported legacy identity"
    );

    // Exact replay: same accepted bytes, second append. The projection must
    // NOT re-run (EVENT-01/EVENT-03) -- NeverRuns would panic if it did.
    let replay_appendable = appendable_bootstrap_manifest(&second_statement, &scope.witness);
    assert_eq!(
        replay_appendable.canonical_event(),
        appendable.canonical_event(),
        "two independent enumerations of the same rows must produce byte-identical accepted events"
    );
    let replay_outcome = scope
        .repository
        .append(&scope.witness, &replay_appendable, Arc::new(NeverRuns))
        .await
        .unwrap();
    assert_eq!(replay_outcome, AppendOutcome::Replayed { position });
    assert_eq!(
        import_row_count(&pool, &scope.physical_scope).await,
        2,
        "an exact replay must not duplicate or re-run the projection"
    );

    let audit = scope
        .repository
        .audit_shard_chain(scope.epoch_id(), position.shard)
        .await
        .unwrap();
    assert!(audit.is_intact(), "fresh shard must audit clean: {audit:?}");
    assert_eq!(audit.verified_events, 1);
    assert_eq!(audit.head_chain_digest, chain_digest);
}

#[tokio::test]
async fn live_bootstrap_manifest_row_collision_is_refused_with_no_head_advance_when_configured() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    if !import_rows_table_exists(&pool).await {
        eprintln!(
            "skipping live_bootstrap_manifest_row_collision_is_refused_with_no_head_advance_when_configured: \
             memory_bootstrap_import_rows does not exist yet (SCHEMA lane migration pending)"
        );
        return;
    }
    let fixture = fixture();
    let scope = activate_stage4(&pool, &fixture, "collision", 52).await;

    let first_statement = bootstrap_manifest_statement(&fixture, &scope.head, two_rows("first"));
    let first_appendable = appendable_bootstrap_manifest(&first_statement, &scope.witness);
    let first_projection: Arc<dyn AppendProjection> = Arc::new(BootstrapImportProjection {
        scope: scope.trusted_scope.clone(),
        rows: first_statement.manifest.rows.clone(),
    });
    let first_outcome = scope
        .repository
        .append(&scope.witness, &first_appendable, first_projection)
        .await
        .unwrap();
    let AppendOutcome::Appended { position, .. } = first_outcome else {
        panic!("first append must be Appended, got {first_outcome:?}");
    };
    assert_eq!(
        scoped_count(&pool, "memory_evidence_events", &scope.physical_scope).await,
        1
    );

    // A second manifest that is a genuinely different accepted event (a third
    // row makes the manifest digest, and therefore the accepted-event ID,
    // different) but claims the SAME memory_chunks/"chunk-1" identity with
    // DIFFERENT bytes.
    let mut colliding_rows = two_rows("second");
    colliding_rows[0] = manifest_row(
        LegacyTableV1::MemoryChunks,
        "chunk-1",
        "chunk-DIFFERENT-BYTES",
    );
    colliding_rows.push(manifest_row(
        LegacyTableV1::MemoryConflicts,
        "1",
        "conflict-second",
    ));
    // The same `(table, primary_key)` order `BootstrapManifestV1::validate_shape`
    // requires: `LegacyTableV1`/`LegacyPrimaryKeyComponentV1` both derive `Ord`.
    colliding_rows.sort_by(|left, right| {
        (left.table, &left.primary_key).cmp(&(right.table, &right.primary_key))
    });
    let second_statement = bootstrap_manifest_statement(&fixture, &scope.head, colliding_rows);
    assert_ne!(
        second_statement.accepted_event_id().unwrap(),
        first_statement.accepted_event_id().unwrap(),
        "the colliding manifest must be a genuinely different accepted event"
    );
    let second_appendable = appendable_bootstrap_manifest(&second_statement, &scope.witness);
    let second_projection: Arc<dyn AppendProjection> = Arc::new(BootstrapImportProjection {
        scope: scope.trusted_scope.clone(),
        rows: second_statement.manifest.rows.clone(),
    });
    let failure = scope
        .repository
        .append(&scope.witness, &second_appendable, second_projection)
        .await;
    // `BootstrapImportProjection::project` returns
    // `EvidenceAppendError::LedgerIntegrity`, but the `AppendProjection` trait
    // boundary converts any projection error through the generic
    // `EvidenceAppendError -> FleetError -> EvidenceAppendError::Storage`
    // round trip (only `FleetError::ControlLogCorrupt`, raised directly
    // inside the append machinery itself, survives back out as
    // `LedgerIntegrity`) — so the message, not the outer variant, is what
    // this projection controls.
    let failure_message = match &failure {
        Err(error) => error.to_string(),
        Ok(outcome) => panic!("a row collision must fail the whole append closed, got {outcome:?}"),
    };
    assert!(
        failure_message.contains("bootstrap import row collision")
            && failure_message.contains("already imported with different bytes"),
        "a row collision must fail the whole append closed, got {failure_message}"
    );

    // No event row, no head advance, and no import row from the second
    // (rejected) manifest.
    assert_eq!(
        scoped_count(&pool, "memory_evidence_events", &scope.physical_scope).await,
        1,
        "the rejected second manifest must not have inserted an event row"
    );
    assert_eq!(
        import_row_count(&pool, &scope.physical_scope).await,
        2,
        "the rejected second manifest must not have written any import rows"
    );
    let audit = scope
        .repository
        .audit_shard_chain(scope.epoch_id(), position.shard)
        .await
        .unwrap();
    assert_eq!(
        audit.head_offset, 1,
        "the shard head must not have advanced past the first, accepted manifest"
    );
    assert!(audit.is_intact());
}

#[tokio::test]
async fn live_bootstrap_manifest_scope_binding_when_configured() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let fixture = fixture();
    let scope = activate_stage4(&pool, &fixture, "scope", 53).await;

    let foreign_scope = AuthenticatedProjectScopeV1::from_trusted_context(
        ContractId::new("tenant.foreign").unwrap(),
        ContractId::new("project.foreign").unwrap(),
    );
    let foreign_manifest = BootstrapManifestV1 {
        schema_version: 1,
        scope: foreign_scope.clone(),
        provenance_kind: ContractId::new("legacy_import").unwrap(),
        rows: two_rows("foreign"),
    };
    let foreign_manifest_digest = foreign_manifest.manifest_digest().unwrap();
    let foreign = BootstrapManifestAcceptedStatementV1 {
        schema_version: 1,
        event_kind: ContractId::new("bootstrap.manifest.accepted").unwrap(),
        profile: fixture.profile.clone(),
        scope: foreign_scope,
        registry: scope.head.clone(),
        manifest: foreign_manifest,
        manifest_digest: foreign_manifest_digest,
    };
    // The statement is still internally self-consistent (scope ==
    // manifest.scope, manifest_digest recomputed for that scope), so
    // `validate_shape` alone cannot catch a foreign scope; only the
    // witness-bound construction gate can (EVID-04).
    foreign.validate_shape().unwrap();

    let result = AppendableAcceptedEvent::bootstrap_manifest(&foreign, &scope.witness);
    assert!(
        matches!(
            result,
            Err(EvidenceAppendError::StatementAuthority(
                WitnessMismatchKind::ContractNamespaces
            ))
        ),
        "a manifest statement scoped to another tenant/project must be refused \
         before any transaction opens, got {result:?}"
    );
    assert_eq!(
        scoped_count(&pool, "memory_evidence_events", &scope.physical_scope).await,
        0
    );
}
