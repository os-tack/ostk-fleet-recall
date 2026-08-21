//! Connected proof for evidence v2 admission plus the governed content store
//! (W1-EVID).
//!
//! Set the exact `FLEET_RECALL_TEST_DATABASE_URL` variable to a disposable
//! `CockroachDB` 26.2 database. Every test here is inert otherwise. Nothing in
//! this file starts a database process, invokes Docker, or targets a cloud
//! service.
//!
//! The bootstrap -> genesis -> successor ceremony is copied from
//! `tests/evidence_ledger_live.rs` so every admission below runs against a head
//! that is the Stage-4 package at generation one. What is new here is what
//! happens after admission: the admitted statement and its governed content
//! object commit in ONE serializable transaction, and the rollback, replay,
//! quarantine, and rejection paths are each proven to leave no content row.

use std::str::FromStr as _;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use ostk_fleet_recall::FleetScope;
use ostk_fleet_recall::control_log::{
    CockroachGenesisRepository, GenesisRepository, TrustedControlScope,
};
use ostk_fleet_recall::evidence_ledger::{
    AcceptedEventRepository, ActiveStage4Package, AdmittedEvidenceStatementV2, AppendOutcome,
    AppendProjection, CockroachAcceptedEventRepository, ContentKeyEncryptionKey,
    EvidenceAdmissionError, EvidenceAdmissionRequestV1, EvidenceAppendError, EvidenceAppendResult,
    EvidenceDeliveryContextV1, EvidenceIngressLocatorsV1, GovernedContentProjection,
    ProjectionContext, SealedContentObject, WriterAuthorityWitness, admit_evidence,
    fetch_governed_content,
};
use ostk_fleet_recall::memory_contracts::bootstrap::{
    BootstrapAttestationV1, BootstrapPin, BootstrapReceiptDigest, BootstrapReceiptV1, EpochId,
    VerifiedBootstrapReceipt, verify_pinned_bootstrap,
};
use ostk_fleet_recall::memory_contracts::canonical::{decode_strict, encode_canonical};
use ostk_fleet_recall::memory_contracts::chunk_identity::StorageIdentityPreimageV1;
use ostk_fleet_recall::memory_contracts::common::{
    AuthenticatedProjectScopeV1, CanonicalDecimal, CanonicalTimestamp, ContractId, FixedHex32,
    FixedHex64, HexBytes, ProfileReferenceV1, RegistryReferenceV1, frozen_profile_reference_v1,
};
use ostk_fleet_recall::memory_contracts::digest::{
    DigestDomain, Sha256Digest, domain_separated_digest,
};
use ostk_fleet_recall::memory_contracts::evidence_v2::{
    EvidenceIngressCandidateV2, EvidenceStatementV2, RegistryHeadBindingV1, RepresentationLineageV2,
};
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
use ostk_fleet_recall::store::cockroach::{CockroachStore, PoolConfig, RetryPolicy};
use ostk_recall_core::PrivacyTier;
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use sha2::{Digest as _, Sha256};
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
/// runtime that created it, so pools are never shared across tests. The schema
/// is shared, so migration is serialized and run exactly once per process.
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
        format!("evidence-{label}-{}", Uuid::now_v7()),
        "evidence-ledger-connected-test",
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
// This mirrors tests/successor_activation_live.rs so every append below runs
// against a head that is the Stage-4 package at generation one.
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
    pool: PgPool,
    physical_scope: FleetScope,
    trusted_scope: TrustedControlScope,
    bootstrap: VerifiedBootstrapReceipt,
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
    assert_eq!(
        witness.head().package_digest,
        fixture.target.package_digest(),
        "the activated package must be the Stage-4 target"
    );

    Stage4Scope {
        pool: pool.clone(),
        physical_scope,
        trusted_scope,
        bootstrap,
        head,
        repository,
        witness,
    }
}

// Small SQL helpers (root only; never used by the least-privilege probe).
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

async fn head_offset(pool: &PgPool, scope: &Stage4Scope, shard: u16) -> Option<i64> {
    sqlx::query_scalar(
        "SELECT last_committed_offset FROM memory_evidence_shard_heads \
         WHERE tenant_id = $1 AND project = $2 AND epoch_id = $3 AND shard = $4",
    )
    .bind(scope.physical_scope.tenant_id)
    .bind(&scope.physical_scope.project)
    .bind(scope.epoch_id().digest().as_bytes().to_vec())
    .bind(i32::from(shard))
    .fetch_optional(pool)
    .await
    .unwrap()
}
/// A projection that panics if it ever runs. Passing it to a replay proves the
/// replay branch never repeats the lifecycle effect the original append already
/// committed (EVENT-01, EVENT-03).
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
// Admission fixtures (W1-EVID) and the governed content key.
// ---------------------------------------------------------------------------

const INGRESS_CANDIDATE: &[u8] =
    include_bytes!("../contracts/dynamic-memory/v3/evidence-admission/ingress-candidate.jsonl");
const INGRESS_LOCATORS: &[u8] =
    include_bytes!("../contracts/dynamic-memory/v3/evidence-admission/ingress-locators.jsonl");
const NEGATIVE_PAYLOAD_SCOPE: &[u8] = include_bytes!(
    "../contracts/dynamic-memory/v3/evidence-admission/negative-payload-scope.jsonl"
);
const NEGATIVE_FOREIGN_CONNECTOR: &[u8] = include_bytes!(
    "../contracts/dynamic-memory/v3/evidence-admission/negative-foreign-connector.jsonl"
);
const NEGATIVE_RESOURCE_IDENTITY: &[u8] = include_bytes!(
    "../contracts/dynamic-memory/v3/evidence-admission/negative-resource-identity.jsonl"
);

/// Exact canonical redacted bytes the frozen candidate declares.
const CANONICAL_PAYLOAD: &[u8] = br#"{"provider_event":"push","revision":"sha256:abc"}"#;
/// Same length, different bytes: the integrity-collision probe.
const OTHER_PAYLOAD: &[u8] = br#"{"provider_event":"push","revision":"sha256:xyz"}"#;

/// A disposable test key. Production keys arrive through
/// `FLEET_RECALL_CONTENT_KEK_HEX`; this file never reads that variable.
fn content_key() -> ContentKeyEncryptionKey {
    ContentKeyEncryptionKey::from_hex(&"ab".repeat(32)).unwrap()
}

fn ingress_candidate() -> EvidenceIngressCandidateV2 {
    decode_strict(record(INGRESS_CANDIDATE)).unwrap()
}

fn ingress_locators() -> EvidenceIngressLocatorsV1 {
    decode_strict(record(INGRESS_LOCATORS)).unwrap()
}

fn active_package(fixture: &ContractFixture, scope: &Stage4Scope) -> ActiveStage4Package {
    ActiveStage4Package::bind(fixture.target.clone(), scope.head.clone(), &scope.witness).unwrap()
}

fn admission_delivery(attempt: u32) -> EvidenceDeliveryContextV1 {
    EvidenceDeliveryContextV1 {
        connector_principal_id: ContractId::new("connector.github").unwrap(),
        connector_instance_id: ContractId::new("connector.github.instance-1").unwrap(),
        transport_delivery_id: HexBytes::new(b"delivery-1".to_vec()).unwrap(),
        attempt_count: attempt,
    }
}

fn admit(
    active: &ActiveStage4Package,
    candidate: &EvidenceIngressCandidateV2,
    payload: &'static [u8],
) -> Result<AdmittedEvidenceStatementV2, EvidenceAdmissionError> {
    let locators = ingress_locators();
    admit_evidence(
        active,
        EvidenceAdmissionRequestV1 {
            candidate,
            locators: &locators,
            canonical_payload: payload,
            delivery: admission_delivery(1),
            lineage: RepresentationLineageV2::Origin,
        },
    )
}

/// Rebind the frozen candidate to different canonical bytes, deriving the new
/// storage identity exactly as admission will.
fn candidate_for_payload(scope: &Stage4Scope, payload: &[u8]) -> EvidenceIngressCandidateV2 {
    let mut candidate = ingress_candidate();
    let content_digest = Sha256Digest::from_bytes(Sha256::digest(payload).into());
    candidate.canonical_payload.content_digest = content_digest;
    candidate.canonical_payload.byte_length =
        CanonicalDecimal::parse(payload.len().to_string()).unwrap();
    candidate.canonical_payload.storage_identity = StorageIdentityPreimageV1 {
        schema_version: 1,
        protection_domain_id: scope.witness.semantic_scope().project_namespace.clone(),
        body_content_id: content_digest,
    }
    .storage_identity()
    .unwrap()
    .digest();
    candidate
}

async fn content_object(
    scope: &Stage4Scope,
    storage_identity: Sha256Digest,
) -> Option<SealedContentObject> {
    fetch_governed_content(
        &scope.pool,
        scope.physical_scope.tenant_id,
        &scope.physical_scope.project,
        scope.witness.semantic_scope(),
        storage_identity,
    )
    .await
    .unwrap()
}

/// A projection that writes the governed content object and then fails, so the
/// rollback can be observed to take the event, the head advance, and the
/// content row with it (EVENT-03, REPLAY-02).
struct FailAfterContent(GovernedContentProjection);

#[async_trait::async_trait]
impl AppendProjection for FailAfterContent {
    async fn project(
        &self,
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        context: ProjectionContext,
    ) -> EvidenceAppendResult<()> {
        self.0.project(transaction, context).await?;
        Err(EvidenceAppendError::LedgerIntegrity(
            "deliberate projection failure".into(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Connected tests.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn live_admission_appends_event_and_content_atomically_when_configured() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let fixture = fixture();
    let scope = activate_stage4(&pool, &fixture, "admit", 61).await;
    let active = active_package(&fixture, &scope);

    let candidate = ingress_candidate();
    let admitted = admit(&active, &candidate, CANONICAL_PAYLOAD).unwrap();
    let storage_identity = admitted.content().storage_identity();
    assert_eq!(content_object(&scope, storage_identity).await, None);

    let appendable = admitted.appendable(&scope.witness).unwrap();
    let projection = Arc::new(
        GovernedContentProjection::new(&scope.trusted_scope, admitted.content(), &content_key())
            .unwrap(),
    );
    let outcome = scope
        .repository
        .append(&scope.witness, &appendable, projection)
        .await
        .unwrap();
    assert!(matches!(outcome, AppendOutcome::Appended { .. }));

    assert_eq!(
        scoped_count(&pool, "memory_evidence_events", &scope.physical_scope).await,
        1
    );
    assert_eq!(
        scoped_count(&pool, "memory_content_objects", &scope.physical_scope).await,
        1
    );

    // The declared digest, and a decrypt round trip under the KEK.
    let stored = content_object(&scope, storage_identity).await.unwrap();
    assert_eq!(
        stored.content().content_digest,
        admitted.statement().canonical_content.content_digest
    );
    assert_eq!(stored.content(), &admitted.statement().canonical_content);
    assert_eq!(stored.open(&content_key()).unwrap(), CANONICAL_PAYLOAD);
    // A different key cannot open it.
    assert!(
        stored
            .open(&ContentKeyEncryptionKey::from_hex(&"cd".repeat(32)).unwrap())
            .is_err()
    );

    // The four erasure axes stay NULL: a storage identity is
    // f(protection domain, content digest), so it deduplicates across
    // representations and source facts and has no single axis to name. The
    // accepted event keeps the representation-to-content binding, and W0-ERASE
    // owns the reference-counted mapping that would populate these columns.
    let populated_erasure_axes: i64 = sqlx::query_scalar(
        "SELECT ((erasure_representation_digest IS NOT NULL)::INT8 \
         + (erasure_source_fact_digest IS NOT NULL)::INT8 \
         + (erasure_resource_digest IS NOT NULL)::INT8 \
         + (erasure_privacy_subject_digest IS NOT NULL)::INT8) \
         FROM memory_content_objects \
         WHERE tenant_id = $1 AND project = $2 AND storage_identity = $3",
    )
    .bind(scope.physical_scope.tenant_id)
    .bind(&scope.physical_scope.project)
    .bind(storage_identity.as_bytes().to_vec())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(populated_erasure_axes, 0);

    // The stored bytes are not the plaintext.
    let ciphertext: Vec<u8> = sqlx::query_scalar(
        "SELECT encrypted_bytes FROM memory_content_objects \
         WHERE tenant_id = $1 AND project = $2 AND storage_identity = $3",
    )
    .bind(scope.physical_scope.tenant_id)
    .bind(&scope.physical_scope.project)
    .bind(storage_identity.as_bytes().to_vec())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        !ciphertext
            .windows(CANONICAL_PAYLOAD.len())
            .any(|window| window == CANONICAL_PAYLOAD)
    );
}

#[tokio::test]
async fn live_failing_projection_leaves_no_event_head_or_content_when_configured() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let fixture = fixture();
    let scope = activate_stage4(&pool, &fixture, "rollback", 62).await;
    let active = active_package(&fixture, &scope);

    let admitted = admit(&active, &ingress_candidate(), CANONICAL_PAYLOAD).unwrap();
    let appendable = admitted.appendable(&scope.witness).unwrap();
    let shard = scope
        .bootstrap
        .partition_for(appendable.consistency())
        .unwrap();
    assert_eq!(head_offset(&pool, &scope, shard).await, None);

    let projection = Arc::new(FailAfterContent(
        GovernedContentProjection::new(&scope.trusted_scope, admitted.content(), &content_key())
            .unwrap(),
    ));
    let failure = scope
        .repository
        .append(&scope.witness, &appendable, projection)
        .await;
    assert!(
        failure.is_err(),
        "the projection failure must fail the append"
    );

    assert_eq!(
        scoped_count(&pool, "memory_evidence_events", &scope.physical_scope).await,
        0
    );
    assert_eq!(
        scoped_count(&pool, "memory_content_objects", &scope.physical_scope).await,
        0
    );
    // The lazily seeded head may exist at offset zero, but it must not have
    // advanced: a failed transaction publishes neither row nor offset.
    assert!(matches!(
        head_offset(&pool, &scope, shard).await,
        None | Some(0)
    ));

    // The same append succeeds afterwards, proving the rollback left no
    // poisoned state behind.
    let projection = Arc::new(
        GovernedContentProjection::new(&scope.trusted_scope, admitted.content(), &content_key())
            .unwrap(),
    );
    assert!(matches!(
        scope
            .repository
            .append(&scope.witness, &appendable, projection)
            .await
            .unwrap(),
        AppendOutcome::Appended { .. }
    ));
    assert_eq!(
        scoped_count(&pool, "memory_content_objects", &scope.physical_scope).await,
        1
    );
}

#[tokio::test]
async fn live_exact_replay_writes_no_second_content_row_when_configured() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let fixture = fixture();
    let scope = activate_stage4(&pool, &fixture, "replay", 63).await;
    let active = active_package(&fixture, &scope);

    let admitted = admit(&active, &ingress_candidate(), CANONICAL_PAYLOAD).unwrap();
    let appendable = admitted.appendable(&scope.witness).unwrap();
    let first = scope
        .repository
        .append(
            &scope.witness,
            &appendable,
            Arc::new(
                GovernedContentProjection::new(
                    &scope.trusted_scope,
                    admitted.content(),
                    &content_key(),
                )
                .unwrap(),
            ),
        )
        .await
        .unwrap();
    let AppendOutcome::Appended { position, .. } = first else {
        panic!("first append must insert");
    };

    // A retried delivery re-admits to byte-identical bytes: transport delivery
    // IDs and receipt clocks are outside the accepted preimage (EVID-03).
    let mut retried = ingress_candidate();
    retried.provider_delivery_id = HexBytes::new(b"delivery-2".to_vec()).unwrap();
    retried.received_at = CanonicalTimestamp::parse("2026-08-15T13:00:00.000000000Z").unwrap();
    let readmitted = admit(&active, &retried, CANONICAL_PAYLOAD).unwrap();
    assert_eq!(
        encode_canonical(readmitted.statement()).unwrap(),
        encode_canonical(admitted.statement()).unwrap()
    );

    let replay = scope
        .repository
        .append(
            &scope.witness,
            &readmitted.appendable(&scope.witness).unwrap(),
            Arc::new(NeverRuns),
        )
        .await
        .unwrap();
    assert_eq!(replay, AppendOutcome::Replayed { position });
    assert_eq!(
        scoped_count(&pool, "memory_evidence_events", &scope.physical_scope).await,
        1
    );
    assert_eq!(
        scoped_count(&pool, "memory_content_objects", &scope.physical_scope).await,
        1
    );
}

#[tokio::test]
async fn live_same_representation_other_bytes_is_quarantined_when_configured() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let fixture = fixture();
    let scope = activate_stage4(&pool, &fixture, "collision", 64).await;
    let active = active_package(&fixture, &scope);

    let admitted = admit(&active, &ingress_candidate(), CANONICAL_PAYLOAD).unwrap();
    scope
        .repository
        .append(
            &scope.witness,
            &admitted.appendable(&scope.witness).unwrap(),
            Arc::new(
                GovernedContentProjection::new(
                    &scope.trusted_scope,
                    admitted.content(),
                    &content_key(),
                )
                .unwrap(),
            ),
        )
        .await
        .unwrap();

    // Same source fact, same representation identity, different accepted bytes
    // and different governed content. EVENT-01 calls this an integrity
    // collision; nothing about it may reach the ledger or the content store.
    let colliding = candidate_for_payload(&scope, OTHER_PAYLOAD);
    let second = admit(&active, &colliding, OTHER_PAYLOAD).unwrap();
    assert_eq!(
        second.statement().representation_key,
        admitted.statement().representation_key
    );
    assert_ne!(
        second.statement().accepted_event_id().unwrap(),
        admitted.statement().accepted_event_id().unwrap()
    );

    let outcome = scope
        .repository
        .append(
            &scope.witness,
            &second.appendable(&scope.witness).unwrap(),
            Arc::new(
                GovernedContentProjection::new(
                    &scope.trusted_scope,
                    second.content(),
                    &content_key(),
                )
                .unwrap(),
            ),
        )
        .await
        .unwrap();
    assert!(matches!(outcome, AppendOutcome::Quarantined { .. }));
    assert_eq!(
        scoped_count(&pool, "memory_evidence_events", &scope.physical_scope).await,
        1
    );
    assert_eq!(
        scoped_count(&pool, "memory_content_objects", &scope.physical_scope).await,
        1
    );
    assert_eq!(
        content_object(&scope, second.content().storage_identity()).await,
        None,
        "a quarantined delivery must not leave governed bytes behind"
    );
}

#[tokio::test]
async fn live_rejections_happen_before_any_write_when_configured() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let fixture = fixture();
    let scope = activate_stage4(&pool, &fixture, "reject", 65).await;
    let active = active_package(&fixture, &scope);

    let scope_negative: EvidenceIngressCandidateV2 =
        decode_strict(record(NEGATIVE_PAYLOAD_SCOPE)).unwrap();
    assert!(matches!(
        admit(&active, &scope_negative, CANONICAL_PAYLOAD),
        Err(EvidenceAdmissionError::PayloadSelectedScope)
    ));

    let connector_negative: EvidenceIngressCandidateV2 =
        decode_strict(record(NEGATIVE_FOREIGN_CONNECTOR)).unwrap();
    assert!(matches!(
        admit(&active, &connector_negative, CANONICAL_PAYLOAD),
        Err(EvidenceAdmissionError::ConnectorNotInActivePackage)
    ));

    let resource_negative: EvidenceIngressCandidateV2 =
        decode_strict(record(NEGATIVE_RESOURCE_IDENTITY)).unwrap();
    assert!(matches!(
        admit(&active, &resource_negative, CANONICAL_PAYLOAD),
        Err(EvidenceAdmissionError::ResourceIdentityMismatch(_))
    ));

    // A package that is not the activated one cannot even become active.
    let mut stale_head = scope.head.clone();
    stale_head.head.activation_id = Sha256Digest::from_bytes([0x77; 32]);
    assert!(matches!(
        ActiveStage4Package::bind(fixture.target.clone(), stale_head, &scope.witness),
        Err(EvidenceAdmissionError::PackageNotActive)
    ));

    assert_eq!(
        scoped_count(&pool, "memory_evidence_events", &scope.physical_scope).await,
        0
    );
    assert_eq!(
        scoped_count(&pool, "memory_content_objects", &scope.physical_scope).await,
        0
    );
    assert_eq!(
        scoped_count(&pool, "memory_evidence_quarantine", &scope.physical_scope).await,
        0
    );
}

#[tokio::test]
async fn live_late_arrival_preserves_provider_clocks_when_configured() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let fixture = fixture();
    let scope = activate_stage4(&pool, &fixture, "late", 66).await;
    let active = active_package(&fixture, &scope);

    // The delivery arrives long after the fact occurred and was observed.
    let mut late = ingress_candidate();
    late.received_at = CanonicalTimestamp::parse("2026-08-20T00:00:00.000000000Z").unwrap();
    let admitted = admit(&active, &late, CANONICAL_PAYLOAD).unwrap();
    assert_eq!(
        admitted.statement().occurred_at,
        ingress_candidate().occurred_at
    );
    assert_eq!(
        admitted.statement().observed_at,
        ingress_candidate().observed_at
    );

    scope
        .repository
        .append(
            &scope.witness,
            &admitted.appendable(&scope.witness).unwrap(),
            Arc::new(
                GovernedContentProjection::new(
                    &scope.trusted_scope,
                    admitted.content(),
                    &content_key(),
                )
                .unwrap(),
            ),
        )
        .await
        .unwrap();

    // EVID-03: accepted/system time is the ledger's own clock and is strictly
    // separate from the provider's occurrence and observation times.
    let accepted_at: DateTime<Utc> = sqlx::query_scalar(
        "SELECT accepted_at FROM memory_evidence_events \
         WHERE tenant_id = $1 AND project = $2 AND event_id = $3",
    )
    .bind(scope.physical_scope.tenant_id)
    .bind(&scope.physical_scope.project)
    .bind(
        admitted
            .statement()
            .accepted_event_id()
            .unwrap()
            .digest()
            .as_bytes()
            .to_vec(),
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let occurred = DateTime::parse_from_rfc3339(admitted.statement().occurred_at.as_str())
        .unwrap()
        .with_timezone(&Utc);
    assert!(
        accepted_at > occurred,
        "accepted time must be later than the occurrence it records"
    );

    let stored: Vec<u8> = sqlx::query_scalar(
        "SELECT canonical_event FROM memory_evidence_events \
         WHERE tenant_id = $1 AND project = $2 AND event_id = $3",
    )
    .bind(scope.physical_scope.tenant_id)
    .bind(&scope.physical_scope.project)
    .bind(
        admitted
            .statement()
            .accepted_event_id()
            .unwrap()
            .digest()
            .as_bytes()
            .to_vec(),
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let replayed: EvidenceStatementV2 = decode_strict(&stored).unwrap();
    assert_eq!(&replayed, admitted.statement());
    // Receipt time is transport metadata: it never entered the stored bytes.
    assert!(!String::from_utf8(stored).unwrap().contains("2026-08-20"));
}

#[tokio::test]
async fn live_second_representation_reuses_one_content_object_when_configured() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let fixture = fixture();
    let scope = activate_stage4(&pool, &fixture, "supersede", 67).await;
    let active = active_package(&fixture, &scope);

    let candidate = ingress_candidate();
    let locators = ingress_locators();
    let origin = admit(&active, &candidate, CANONICAL_PAYLOAD).unwrap();
    scope
        .repository
        .append(
            &scope.witness,
            &origin.appendable(&scope.witness).unwrap(),
            Arc::new(
                GovernedContentProjection::new(
                    &scope.trusted_scope,
                    origin.content(),
                    &content_key(),
                )
                .unwrap(),
            ),
        )
        .await
        .unwrap();

    let successor = admit_evidence(
        &active,
        EvidenceAdmissionRequestV1 {
            candidate: &candidate,
            locators: &locators,
            canonical_payload: CANONICAL_PAYLOAD,
            delivery: admission_delivery(1),
            lineage: RepresentationLineageV2::Supersedes {
                predecessor_representation_key: origin.statement().representation_key,
            },
        },
    )
    .unwrap();
    assert_eq!(
        successor.statement().source_fact_id,
        origin.statement().source_fact_id
    );
    assert_ne!(
        successor.statement().representation_key,
        origin.statement().representation_key
    );

    let outcome = scope
        .repository
        .append(
            &scope.witness,
            &successor.appendable(&scope.witness).unwrap(),
            Arc::new(
                GovernedContentProjection::new(
                    &scope.trusted_scope,
                    successor.content(),
                    &content_key(),
                )
                .unwrap(),
            ),
        )
        .await
        .unwrap();
    assert!(matches!(outcome, AppendOutcome::Appended { .. }));
    assert_eq!(
        scoped_count(&pool, "memory_evidence_events", &scope.physical_scope).await,
        2
    );
    // One governed payload, one content row: the second representation
    // references the same bytes and must not duplicate them (EVID-01).
    assert_eq!(
        scoped_count(&pool, "memory_content_objects", &scope.physical_scope).await,
        1
    );
}

#[tokio::test]
async fn live_a_tampered_content_row_fails_the_next_append_closed_when_configured() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let fixture = fixture();
    let scope = activate_stage4(&pool, &fixture, "tamper", 68).await;
    let active = active_package(&fixture, &scope);

    let candidate = ingress_candidate();
    let locators = ingress_locators();
    let origin = admit(&active, &candidate, CANONICAL_PAYLOAD).unwrap();
    scope
        .repository
        .append(
            &scope.witness,
            &origin.appendable(&scope.witness).unwrap(),
            Arc::new(
                GovernedContentProjection::new(
                    &scope.trusted_scope,
                    origin.content(),
                    &content_key(),
                )
                .unwrap(),
            ),
        )
        .await
        .unwrap();

    // Tamper with the stored governed row's retention binding, out of band.
    let affected = sqlx::query(
        "UPDATE memory_content_objects \
         SET retention_policy_entry_version = retention_policy_entry_version + 1 \
         WHERE tenant_id = $1 AND project = $2 AND storage_identity = $3",
    )
    .bind(scope.physical_scope.tenant_id)
    .bind(&scope.physical_scope.project)
    .bind(origin.content().storage_identity().as_bytes().to_vec())
    .execute(&pool)
    .await
    .unwrap()
    .rows_affected();
    assert_eq!(affected, 1);

    // A second representation of the same source fact reaches the same storage
    // identity. The already-stored row no longer matches the admitted object,
    // so the append must fail closed rather than accept a divergent governed
    // binding (EVID-01).
    let successor = admit_evidence(
        &active,
        EvidenceAdmissionRequestV1 {
            candidate: &candidate,
            locators: &locators,
            canonical_payload: CANONICAL_PAYLOAD,
            delivery: admission_delivery(1),
            lineage: RepresentationLineageV2::Supersedes {
                predecessor_representation_key: origin.statement().representation_key,
            },
        },
    )
    .unwrap();
    let outcome = scope
        .repository
        .append(
            &scope.witness,
            &successor.appendable(&scope.witness).unwrap(),
            Arc::new(
                GovernedContentProjection::new(
                    &scope.trusted_scope,
                    successor.content(),
                    &content_key(),
                )
                .unwrap(),
            ),
        )
        .await;
    assert!(
        outcome.is_err(),
        "a divergent stored content object must fail the append closed"
    );
    assert_eq!(
        scoped_count(&pool, "memory_evidence_events", &scope.physical_scope).await,
        1
    );
}
