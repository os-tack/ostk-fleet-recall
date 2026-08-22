//! Connected proof for the local transcript collector (W2-TRANS).
//!
//! Set `FLEET_RECALL_TEST_DATABASE_URL` to a disposable `CockroachDB` 26.2
//! database. Every test here is inert otherwise. Nothing in this file starts a
//! database process, invokes Docker, or targets a cloud service.
//!
//! The bootstrap -> genesis -> successor ceremony is copied from
//! `tests/evidence_admission_live.rs` so every batch below is staged and drained
//! against a head that is genuinely the Stage-4 package at generation one — the
//! connector's unit tests run the same pipeline against a synthesized head, so
//! the two halves meet here.
//!
//! What these tests prove, end to end, against real tables:
//!
//! * a fixture transcript DIRECTORY flows to accepted evidence events and
//!   governed content objects, with coverage receipts for every drained turn;
//! * **the killer test** — a transcript carrying planted secret-shaped strings
//!   puts those bytes in NO outbox row, NO accepted event, and NO content
//!   object, encrypted or decrypted (EVID-05, PRED-03);
//! * a batch and its source cursor are one atomic unit: a fault injected after
//!   both writes and before commit leaves NEITHER durable (EVENT-03);
//! * re-collecting the same bytes is idempotent, and a re-drain is `Replayed`
//!   with no duplicate event, content object, or receipt (EVENT-01);
//! * a staged candidate naming a connector outside the ACTIVE package, or a
//!   scope the credential did not authorize, is refused closed with nothing
//!   appended (AUTH-04/EVID-02, EVID-04).

use std::collections::BTreeMap;
use std::str::FromStr as _;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use ostk_fleet_recall::FleetScope;
use ostk_fleet_recall::connectors::transcript::{
    CockroachTranscriptOutboxRepository, RedactionGuaranteeV1, TranscriptBatchV1,
    TranscriptCollectionRequestV1, TranscriptCollectionStatsV1, TranscriptConnectorBindingV1,
    TranscriptConnectorError, TranscriptCoverageBindingV1, TranscriptDrainModeV1,
    TranscriptDrainRequest, TranscriptDrainSummaryV1, TranscriptEnqueueOutcome,
    TranscriptFaultInjection, TranscriptIngressClocksV1, TranscriptOutboxRepository,
    TranscriptOutboxStateV1, collect_batch, drain_outbox, transcript_parser_key_v2,
};
use ostk_fleet_recall::control_log::{
    CockroachGenesisRepository, GenesisRepository, TrustedControlScope,
};
use ostk_fleet_recall::coverage_runtime::{CockroachCoverageRuntimeRepository, SequenceIntervalV1};
use ostk_fleet_recall::evidence_ledger::{
    ActiveStage4Package, CockroachAcceptedEventRepository, ContentKeyEncryptionKey,
    EvidenceAdmissionError, WriterAuthorityWitness, fetch_governed_content,
};
use ostk_fleet_recall::memory_contracts::bootstrap::{
    BootstrapAttestationV1, BootstrapPin, BootstrapReceiptDigest, BootstrapReceiptV1,
    VerifiedBootstrapReceipt, verify_pinned_bootstrap,
};
use ostk_fleet_recall::memory_contracts::canonical::{decode_strict, encode_canonical};
use ostk_fleet_recall::memory_contracts::common::{
    AuthenticatedProjectScopeV1, CanonicalTimestamp, ContractId, FixedHex32, FixedHex64, HexBytes,
    ProfileReferenceV1, RegistryReferenceV1, frozen_profile_reference_v1,
};
use ostk_fleet_recall::memory_contracts::coverage::{
    CoverageFreshnessV1, CoverageProofBasisV1, CoverageProofMethodV1, CoverageScopeV1,
    CoverageWindowV1, FreshnessStateV1, ProducerIdentityV1, ProducerKindV1,
};
use ostk_fleet_recall::memory_contracts::digest::{
    DigestDomain, Sha256Digest, domain_separated_digest,
};
use ostk_fleet_recall::memory_contracts::evidence_v2::{
    EvidenceIngressCandidateV2, RegistryHeadBindingV1,
};
use ostk_fleet_recall::memory_contracts::genesis::SemanticallyClosedGenesisPackage;
use ostk_fleet_recall::memory_contracts::genesis_activation::{
    GenesisActivationPrincipalBinding, GenesisRegistryActivationApprovalSetV1,
    GenesisRegistryActivationApprovalV1, GenesisRegistryActivationStatementV1,
    GenesisRegistryAnchorV1, RegistryTestResultDigest, RegistryTestRunnerPin,
    VerifiedRegistryTestResult, genesis_activation_policy_digest,
    verify_genesis_registry_activation, verify_registry_test_result,
};
use ostk_fleet_recall::memory_contracts::identity::ResourceUri;
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
use ostk_fleet_recall::store::cockroach::{
    CockroachStore, PUBLICATION_READ_TABLES, PoolConfig, RetryPolicy,
};
use ostk_recall_core::PrivacyTier;
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use sha2::{Digest as _, Sha256};
use sqlx::PgPool;
use tokio::sync::Mutex;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Frozen contract fixtures and the bootstrap -> genesis -> successor ceremony.
// ---------------------------------------------------------------------------

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

/// The single installation coordinate the frozen gen-1 provider-instance recipe
/// requires. The RECIPE decides which coordinates exist; the connector binding
/// only supplies values for them.
const INSTALLATION_COORDINATE: &str = "provider_installation_id";

/// Each `#[tokio::test]` gets its own runtime, and a `PgPool` is bound to the
/// runtime that created it, so pools are never shared across tests. The schema
/// is shared, so migration is serialized and run exactly once per process.
static MIGRATED: Mutex<bool> = Mutex::const_new(false);

fn record(artifact: &'static [u8]) -> &'static [u8] {
    artifact
        .strip_suffix(b"\n")
        .expect("contract JSONL must have exactly one framing LF")
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
        format!("transcript-{label}-{}", Uuid::now_v7()),
        "transcript-connector-connected-test",
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

/// A live transcript connector bound to a unique project whose registry head is
/// the Stage-4 package at generation one.
struct LiveConnector {
    pool: PgPool,
    physical_scope: FleetScope,
    active: ActiveStage4Package,
    witness: WriterAuthorityWitness,
    ledger: Arc<CockroachAcceptedEventRepository>,
    outbox: CockroachTranscriptOutboxRepository,
    coverage: CockroachCoverageRuntimeRepository,
}

#[allow(clippy::too_many_lines)] // One linear ceremony; splitting it hides it.
async fn live_connector(pool: &PgPool, fixture: &ContractFixture, label: &str) -> LiveConnector {
    let physical_scope = physical_scope(label);
    let bootstrap = signed_bootstrap(fixture, 7);
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
        bootstrap,
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

    let ledger = Arc::new(CockroachAcceptedEventRepository::new(
        pool.clone(),
        trusted_scope.clone(),
        retry_policy(),
    ));
    let witness = ledger.read_writer_authority_witness().await.unwrap();
    assert_eq!(witness.generation(), 1, "the head must be generation one");
    assert_eq!(
        witness.head().package_digest,
        fixture.target.package_digest(),
        "the activated package must be the Stage-4 target"
    );
    let active = ActiveStage4Package::bind(fixture.target.clone(), head, &witness).unwrap();

    LiveConnector {
        outbox: CockroachTranscriptOutboxRepository::new(
            pool.clone(),
            trusted_scope.clone(),
            retry_policy(),
        ),
        coverage: CockroachCoverageRuntimeRepository::new(
            pool.clone(),
            trusted_scope,
            retry_policy(),
        ),
        pool: pool.clone(),
        physical_scope,
        active,
        witness,
        ledger,
    }
}

// ---------------------------------------------------------------------------
// Transcript fixtures. A directory of Claude session JSONL files, built on disk
// so the connector reads real bytes off a real filesystem.
// ---------------------------------------------------------------------------

/// The literal redactable secret planted in [`secret_transcript`]. Its turn is
/// staged with the secret replaced; these exact bytes must appear nowhere
/// durable.
const PLANTED_REDACTABLE_SECRET: &str = "AKIAIOSFODNN7EXAMPLE";
/// The literal unredactable key material planted in [`secret_transcript`]. Its
/// whole turn is withheld; these exact bytes must appear nowhere durable.
const PLANTED_KEY_MATERIAL: &str = "MIIEowIBAAKCAQEAxWITNESSxKEY";
/// The exact text every redacted range is replaced with.
const REDACTION_PLACEHOLDER: &str = "[REDACTED]";

fn line(kind: &str, session: &str, uid: &str, timestamp: &str, text: &str) -> String {
    format!(
        r#"{{"type":"{kind}","sessionId":"{session}","uuid":"{uid}","timestamp":"{timestamp}","message":{{"role":"{kind}","content":[{{"type":"text","text":{}}}]}}}}"#,
        serde_json::to_string(text).unwrap()
    )
}

fn clean_transcript(session: &str) -> String {
    format!(
        "{}\n{}\n",
        line(
            "user",
            session,
            "turn-1",
            "2026-08-15T12:30:00.000Z",
            "please check the failing auth test"
        ),
        line(
            "assistant",
            session,
            "turn-2",
            "2026-08-15T12:30:01.000Z",
            "the failure is a missing scope binding"
        )
    )
}

/// Four turns: two clean, one carrying unredactable PEM key material (withheld
/// whole), and one carrying a redactable AWS access key id (staged redacted).
fn secret_transcript(session: &str) -> String {
    format!(
        "{}\n{}\n{}\n{}\n",
        line(
            "user",
            session,
            "turn-1",
            "2026-08-15T12:30:00.000Z",
            "here is the config"
        ),
        line(
            "assistant",
            session,
            "turn-2",
            "2026-08-15T12:30:01.000Z",
            &format!(
                "-----BEGIN RSA PRIVATE KEY-----\n{PLANTED_KEY_MATERIAL}\n-----END RSA PRIVATE KEY-----"
            )
        ),
        line(
            "user",
            session,
            "turn-3",
            "2026-08-15T12:30:02.000Z",
            &format!("the access key is {PLANTED_REDACTABLE_SECRET} in the env")
        ),
        line(
            "assistant",
            session,
            "turn-4",
            "2026-08-15T12:30:03.000Z",
            "understood, moving on"
        )
    )
}

/// Write a transcript directory and return the `.jsonl` files in sorted order,
/// exactly as a collector walking the directory would see them.
fn transcript_directory(files: &[(&str, String)]) -> (tempfile::TempDir, Vec<std::path::PathBuf>) {
    let directory = tempfile::tempdir().expect("a transcript fixture directory must be creatable");
    for (name, body) in files {
        std::fs::write(directory.path().join(name), body).expect("fixture file must be writable");
    }
    let mut sources: Vec<std::path::PathBuf> = std::fs::read_dir(directory.path())
        .expect("the fixture directory must be readable")
        .map(|entry| entry.expect("directory entry must be readable").path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "jsonl")
        })
        .collect();
    sources.sort();
    (directory, sources)
}

// ---------------------------------------------------------------------------
// Connector wiring: binding, clocks, coverage metadata, and the two-step
// collect -> stage -> drain pipeline the tests drive.
// ---------------------------------------------------------------------------

/// A disposable test key. Production keys arrive through
/// `FLEET_RECALL_CONTENT_KEK_HEX`; this file never reads that variable.
fn content_key() -> ContentKeyEncryptionKey {
    ContentKeyEncryptionKey::from_hex(&"ab".repeat(32)).unwrap()
}

/// One connector instance per transcript source.
///
/// Turn ordinals are per-source (the cursor numbers each source independently),
/// while a coverage domain is per connector instance — so two sources sharing
/// one instance would report the second source's turn 0 as already covered.
/// Binding an instance to a source is what keeps the two numbering schemes
/// aligned, and it is how a real deployment names a collector anyway.
fn binding(source_id: &str) -> TranscriptConnectorBindingV1 {
    let mut instance_coordinates = BTreeMap::new();
    instance_coordinates.insert(
        ContractId::new(INSTALLATION_COORDINATE).unwrap(),
        "4242".to_owned(),
    );
    TranscriptConnectorBindingV1 {
        ingress_principal_id: ContractId::new("connector.transcript").unwrap(),
        connector_instance_id: ContractId::new(format!("connector.transcript.{source_id}"))
            .unwrap(),
        instance_coordinates,
    }
}

const COVERAGE_SCOPE_URI: &str = "urn:ostk:entity:v1:repository:sha256:1111111111111111111111111111111111111111111111111111111111111111";
const COVERAGE_REVISION_HEX: &str =
    "2222222222222222222222222222222222222222222222222222222222222222";
const FRESHNESS_RULE_DIGEST: &str =
    "3333333333333333333333333333333333333333333333333333333333333333";
const PROOF_METHOD_DIGEST: &str =
    "4444444444444444444444444444444444444444444444444444444444444444";
const COVERAGE_WINDOW_START: &str = "2026-08-14T00:00:00.000000000Z";
const COVERAGE_WINDOW_END: &str = "2026-08-15T00:00:00.000000000Z";

fn coverage_contract_scope() -> CoverageScopeV1 {
    CoverageScopeV1 {
        scope: ResourceUri::from_str(COVERAGE_SCOPE_URI).unwrap(),
        revision: HexBytes::new(hex::decode(COVERAGE_REVISION_HEX).unwrap()).unwrap(),
        window: CoverageWindowV1 {
            window_start: CanonicalTimestamp::parse(COVERAGE_WINDOW_START).unwrap(),
            window_end: CanonicalTimestamp::parse(COVERAGE_WINDOW_END).unwrap(),
        },
    }
}

fn registry_reference(id: &str, digest_hex: &str) -> RegistryReferenceV1 {
    RegistryReferenceV1 {
        entry_id: ContractId::new(id).unwrap(),
        version: 1,
        entry_digest: digest(digest_hex),
    }
}

/// The coverage domain every drained turn reports into: turn ordinals `[0, 64)`
/// of one connector instance.
fn coverage_binding() -> TranscriptCoverageBindingV1 {
    TranscriptCoverageBindingV1 {
        producer: ProducerIdentityV1 {
            schema_version: 1,
            kind: ProducerKindV1::Connector,
            producer_id: ContractId::new("connector.transcript").unwrap(),
            version: 1,
        },
        scope: coverage_contract_scope(),
        target: SequenceIntervalV1::new(0, 64).unwrap(),
        freshness: CoverageFreshnessV1 {
            state: FreshnessStateV1::Current,
            freshness_rule: registry_reference(
                "coverage.freshness.default_rule",
                FRESHNESS_RULE_DIGEST,
            ),
        },
        proof_basis: CoverageProofBasisV1 {
            method: CoverageProofMethodV1::ClosedProviderQuery,
            proof_method_registration: registry_reference(
                "coverage.proof.closed_provider_query",
                PROOF_METHOD_DIGEST,
            ),
        },
        observed_through: CanonicalTimestamp::parse(COVERAGE_WINDOW_END).unwrap(),
    }
}

impl LiveConnector {
    /// The ingress clocks one collection pass is stamped with, read from the
    /// DATABASE clock rather than from the transcript.
    async fn clocks(&self) -> TranscriptIngressClocksV1 {
        let observed = canonical_time(server_time(&self.pool).await);
        TranscriptIngressClocksV1 {
            received_at: observed.clone(),
            observed_at: observed,
        }
    }

    /// Parse, redact, canonicalize and stage one source, resuming from whatever
    /// durable cursor that source already has.
    async fn collect(
        &self,
        source_id: &str,
        bytes: &[u8],
    ) -> (TranscriptBatchV1, TranscriptCollectionStatsV1) {
        let cursor = self.outbox.read_cursor(source_id).await.unwrap();
        let guarantee = RedactionGuaranteeV1::from_active_package(&self.active)
            .expect("the activated package must promise redaction before the durable outbox");
        let binding = binding(source_id);
        let parser_key = transcript_parser_key_v2();
        let clocks = self.clocks().await;
        collect_batch(&TranscriptCollectionRequestV1 {
            active: &self.active,
            binding: &binding,
            guarantee: &guarantee,
            parser_key: &parser_key,
            source_id,
            bytes,
            cursor: cursor.as_ref(),
            clocks: &clocks,
        })
        .unwrap()
    }

    async fn stage(
        &self,
        source_id: &str,
        bytes: &[u8],
    ) -> (TranscriptEnqueueOutcome, TranscriptCollectionStatsV1) {
        let (batch, stats) = self.collect(source_id, bytes).await;
        let outcome = self.outbox.enqueue_batch(&batch).await.unwrap();
        (outcome, stats)
    }

    async fn drain(
        &self,
        mode: TranscriptDrainModeV1,
    ) -> Result<TranscriptDrainSummaryV1, TranscriptConnectorError> {
        drain_outbox(TranscriptDrainRequest {
            active: &self.active,
            witness: &self.witness,
            outbox: &self.outbox,
            ledger: self.ledger.as_ref(),
            coverage: &self.coverage,
            trusted_scope: self.outbox.trusted_scope(),
            content_key: &content_key(),
            coverage_binding: &coverage_binding(),
            mode,
            limit: 256,
        })
        .await
    }

    async fn scoped_count(&self, table: &str) -> i64 {
        let query =
            format!("SELECT count(*)::INT8 FROM {table} WHERE tenant_id = $1 AND project = $2");
        sqlx::query_scalar(&query)
            .bind(self.physical_scope.tenant_id)
            .bind(&self.physical_scope.project)
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }

    /// Every byte this connector made durable, in one place: the outbox row
    /// columns, the accepted-event canonical bytes, the stored ciphertext, and
    /// the DECRYPTED governed content. A secret scan that only read the
    /// plaintext columns would miss a leak into the ciphertext's plaintext.
    async fn durable_bytes(&self) -> Vec<Vec<u8>> {
        let mut collected: Vec<Vec<u8>> = Vec::new();
        for (candidate, locators, payload) in sqlx::query_as::<_, (Vec<u8>, Vec<u8>, Vec<u8>)>(
            "SELECT canonical_candidate, canonical_locators, canonical_payload \
             FROM memory_transcript_outbox_v1 WHERE tenant_id = $1 AND project = $2",
        )
        .bind(self.physical_scope.tenant_id)
        .bind(&self.physical_scope.project)
        .fetch_all(&self.pool)
        .await
        .unwrap()
        {
            collected.push(candidate);
            collected.push(locators);
            collected.push(payload);
        }
        collected.extend(
            sqlx::query_scalar::<_, Vec<u8>>(
                "SELECT canonical_event FROM memory_evidence_events \
                 WHERE tenant_id = $1 AND project = $2",
            )
            .bind(self.physical_scope.tenant_id)
            .bind(&self.physical_scope.project)
            .fetch_all(&self.pool)
            .await
            .unwrap(),
        );
        for (storage_identity, encrypted) in sqlx::query_as::<_, (Vec<u8>, Vec<u8>)>(
            "SELECT storage_identity, encrypted_bytes FROM memory_content_objects \
             WHERE tenant_id = $1 AND project = $2",
        )
        .bind(self.physical_scope.tenant_id)
        .bind(&self.physical_scope.project)
        .fetch_all(&self.pool)
        .await
        .unwrap()
        {
            collected.push(encrypted);
            let identity: [u8; 32] = storage_identity
                .as_slice()
                .try_into()
                .expect("a stored storage identity is 32 bytes");
            collected.push(
                self.governed_content(Sha256Digest::from_bytes(identity))
                    .await,
            );
        }
        collected
    }

    /// The decrypted governed content object for one storage identity.
    async fn governed_content(&self, storage_identity: Sha256Digest) -> Vec<u8> {
        fetch_governed_content(
            &self.pool,
            self.physical_scope.tenant_id,
            &self.physical_scope.project,
            self.witness.semantic_scope(),
            storage_identity,
        )
        .await
        .unwrap()
        .expect("an appended event must have its governed content object")
        .open(&content_key())
        .unwrap()
    }

    /// Assert a literal appears in NOTHING this connector made durable.
    async fn assert_never_durable(&self, needle: &str) {
        let needle = needle.as_bytes();
        for (index, bytes) in self.durable_bytes().await.iter().enumerate() {
            assert!(
                !bytes.windows(needle.len()).any(|window| window == needle),
                "durable artifact {index} contains the planted secret"
            );
        }
    }

    /// Decode the staged candidate of one outbox row.
    async fn staged_candidate(&self, ordinal: u32) -> EvidenceIngressCandidateV2 {
        let rows = self.outbox.staged_rows(false, 256).await.unwrap();
        let row = rows
            .iter()
            .find(|row| row.turn_ordinal == ordinal)
            .expect("the requested turn must be staged");
        decode_strict(&row.canonical_candidate).unwrap()
    }
}

/// Re-stage one already-collected batch with its candidate replaced by
/// `tampered`, keeping the row's identity the digest of its own bytes.
///
/// This is how the two "refused closed" proofs manufacture a staged row the
/// ACTIVE package will not admit. The collector cannot produce one — every
/// candidate it builds names `active.connector()` and carries `active.scope()`
/// — so the tamper happens at the outbox, which is exactly the boundary the
/// drain is supposed to defend.
fn retamper(batch: &TranscriptBatchV1, tampered: &EvidenceIngressCandidateV2) -> TranscriptBatchV1 {
    let mut tampered_batch = batch.clone();
    let canonical = encode_canonical(tampered).unwrap();
    let row = tampered_batch
        .rows
        .first_mut()
        .expect("the batch must have a row to tamper");
    row.outbox_id = Sha256Digest::from_bytes(Sha256::digest(&canonical).into());
    row.canonical_candidate = canonical;
    tampered_batch.rows.truncate(1);
    tampered_batch
}

/// Stage one clean two-turn transcript file and assert the durable cursor it
/// leaves behind names exactly the bytes it consumed.
async fn stage_one_clean_source(connector: &LiveConnector, path: &std::path::Path) {
    let source_id = path.file_name().unwrap().to_string_lossy().into_owned();
    let bytes = std::fs::read(path).unwrap();
    let (outcome, stats) = connector.stage(&source_id, &bytes).await;
    assert_eq!(stats.turns_parsed, 2);
    assert_eq!(stats.turns_staged, 2);
    assert_eq!(stats.turns_withheld, 0);
    assert!(
        stats.classes_detected.is_empty(),
        "a clean transcript detects no secret class"
    );
    assert_eq!(
        outcome,
        TranscriptEnqueueOutcome::Enqueued {
            rows_written: 2,
            batch_seq: 1,
        }
    );
    let cursor = connector
        .outbox
        .read_cursor(&source_id)
        .await
        .unwrap()
        .expect("a staged batch leaves a durable cursor");
    assert_eq!(cursor.byte_offset, u64::try_from(bytes.len()).unwrap());
    assert_eq!(cursor.line_ordinal, 2);
    assert_eq!(cursor.next_ordinal, 2);
    assert_eq!(
        cursor.source_digest,
        Sha256Digest::from_bytes(Sha256::digest(&bytes).into()),
        "the cursor digest covers exactly the consumed bytes"
    );
    assert_eq!(connector.outbox.count_rows(&source_id).await.unwrap(), 2);
}

// ---------------------------------------------------------------------------
// Connected tests.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn live_a_transcript_directory_flows_to_accepted_events_and_content_objects() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let connector = live_connector(&pool, &fixture(), "end-to-end").await;
    let (_directory, sources) = transcript_directory(&[
        (
            "session-a.jsonl",
            clean_transcript("01931f2c-0000-7000-8000-00000000000a"),
        ),
        (
            "session-b.jsonl",
            clean_transcript("01931f2c-0000-7000-8000-00000000000b"),
        ),
    ]);
    assert_eq!(sources.len(), 2, "the fixture directory holds two sources");

    for path in &sources {
        stage_one_clean_source(&connector, path).await;
    }

    // Nothing is in the ledger until the drain runs: staging and admitting are
    // deliberately two failures apart.
    assert_eq!(connector.scoped_count("memory_evidence_events").await, 0);

    let summary = connector
        .drain(TranscriptDrainModeV1::Pending)
        .await
        .unwrap();
    assert_eq!(summary.rows_read, 4);
    assert_eq!(summary.appended, 4);
    assert_eq!(summary.replayed, 0);
    assert_eq!(
        summary.receipts, 4,
        "every drained turn emits its own coverage receipt"
    );
    assert_eq!(summary.coverage_already_covered, 0);

    assert_eq!(connector.scoped_count("memory_evidence_events").await, 4);
    assert_eq!(connector.scoped_count("memory_content_objects").await, 4);
    assert_eq!(
        connector.scoped_count("memory_coverage_receipts_v1").await,
        4
    );
    assert_eq!(
        connector.scoped_count("memory_evidence_quarantine").await,
        0
    );

    // Every staged row is drained, and its governed content object holds the
    // exact canonical body the candidate declared.
    let rows = connector.outbox.staged_rows(false, 256).await.unwrap();
    assert_eq!(rows.len(), 4);
    for row in &rows {
        assert_eq!(row.state, TranscriptOutboxStateV1::Drained);
        let candidate: EvidenceIngressCandidateV2 =
            decode_strict(&row.canonical_candidate).unwrap();
        let stored = connector
            .governed_content(candidate.canonical_payload.storage_identity)
            .await;
        assert_eq!(
            stored, row.canonical_payload,
            "the stored body is the exact canonical payload the row staged"
        );
        let body: serde_json::Value = serde_json::from_slice(&stored).unwrap();
        assert!(
            [
                "please check the failing auth test",
                "the failure is a missing scope binding"
            ]
            .contains(&body["text"].as_str().unwrap()),
            "the stored body is the transcript turn's own text"
        );
    }
    assert!(
        connector
            .outbox
            .staged_rows(true, 256)
            .await
            .unwrap()
            .is_empty(),
        "no pending rows remain"
    );
}

/// PUBLIC-03/04. Both connector tables are private-plane staging rows: neither
/// is one of the publication reader's eight tables, so nothing staged here is
/// reachable from the public plane even before the drain admits anything.
///
/// No database is involved — the reader's table set is a compile-time constant,
/// and this is the assertion that keeps a future migration from quietly adding
/// one of these two to it.
#[test]
fn the_transcript_connector_tables_are_not_on_the_public_plane() {
    for table in [
        "memory_transcript_outbox_v1",
        "memory_transcript_cursors_v1",
    ] {
        assert!(
            !PUBLICATION_READ_TABLES.contains(&table),
            "{table} must not be readable from the public plane"
        );
    }
}

/// THE KILLER TEST. A transcript carrying planted secret-shaped strings must
/// put those bytes in no outbox row, no accepted event, and no content object —
/// neither the stored ciphertext nor its decrypted plaintext (EVID-05,
/// PRED-03).
#[tokio::test]
async fn live_a_planted_secret_never_reaches_the_outbox_the_ledger_or_the_content_store() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let connector = live_connector(&pool, &fixture(), "planted-secret").await;
    let session = "01931f2c-0000-7000-8000-00000000000c";
    let (_directory, sources) =
        transcript_directory(&[("session-secret.jsonl", secret_transcript(session))]);
    let path = &sources[0];
    let source_id = path.file_name().unwrap().to_string_lossy().into_owned();
    let bytes = std::fs::read(path).unwrap();
    assert!(
        String::from_utf8(bytes.clone())
            .unwrap()
            .contains(PLANTED_REDACTABLE_SECRET),
        "the fixture on disk really does carry the planted secret"
    );

    let (outcome, stats) = connector.stage(&source_id, &bytes).await;
    assert_eq!(stats.turns_parsed, 4);
    assert_eq!(
        stats.turns_staged, 3,
        "the PEM key-material turn is withheld whole"
    );
    assert_eq!(stats.turns_withheld, 1);
    assert_eq!(stats.turns_redacted, 1);
    assert_eq!(
        outcome,
        TranscriptEnqueueOutcome::Enqueued {
            rows_written: 3,
            batch_seq: 1,
        }
    );

    // The secret is already absent BEFORE the drain: redaction happens before
    // anything durable exists, not on the way out of the outbox.
    connector
        .assert_never_durable(PLANTED_REDACTABLE_SECRET)
        .await;
    connector.assert_never_durable(PLANTED_KEY_MATERIAL).await;
    connector
        .assert_never_durable("BEGIN RSA PRIVATE KEY")
        .await;

    let summary = connector
        .drain(TranscriptDrainModeV1::Pending)
        .await
        .unwrap();
    assert_eq!(summary.appended, 3);
    assert_eq!(summary.receipts, 3);

    // And absent after it, through the accepted events and the content store,
    // ciphertext and decrypted plaintext alike.
    connector
        .assert_never_durable(PLANTED_REDACTABLE_SECRET)
        .await;
    connector.assert_never_durable(PLANTED_KEY_MATERIAL).await;
    connector
        .assert_never_durable("BEGIN RSA PRIVATE KEY")
        .await;

    // The redactable turn IS present — with a placeholder where the secret was.
    // This is what separates "redacted" from "silently dropped everything".
    let redacted = connector.staged_candidate(2).await;
    let body = String::from_utf8(
        connector
            .governed_content(redacted.canonical_payload.storage_identity)
            .await,
    )
    .unwrap();
    assert!(
        body.contains(REDACTION_PLACEHOLDER),
        "the redacted turn is stored with the placeholder"
    );
    assert!(body.contains("the access key is"));
    assert!(body.contains("in the env"));

    // The withheld turn left a HOLE in the ordinals rather than renumbering the
    // stream: a withheld turn is a visible absence, not an invisible shift.
    let mut ordinals: Vec<u32> = connector
        .outbox
        .staged_rows(false, 256)
        .await
        .unwrap()
        .iter()
        .map(|row| row.turn_ordinal)
        .collect();
    ordinals.sort_unstable();
    assert_eq!(ordinals, vec![0, 2, 3]);
    assert_eq!(connector.scoped_count("memory_evidence_events").await, 3);
    assert_eq!(connector.scoped_count("memory_content_objects").await, 3);
}

#[tokio::test]
async fn live_a_batch_and_its_source_cursor_advance_atomically() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let connector = live_connector(&pool, &fixture(), "atomic").await;
    let source_id = "session-atomic.jsonl";
    let bytes = clean_transcript("01931f2c-0000-7000-8000-00000000000d").into_bytes();

    let (batch, _) = connector.collect(source_id, &bytes).await;
    assert_eq!(batch.rows.len(), 2);

    // Fail AFTER the rows are inserted and the cursor is advanced, but BEFORE
    // the transaction commits. Neither may survive (EVENT-03).
    let faulted = connector
        .outbox
        .enqueue_batch_with_fault_injection(&batch, TranscriptFaultInjection::AbortAfterWrites)
        .await;
    assert!(
        faulted.is_err(),
        "the injected fault must abort the enqueue"
    );

    assert_eq!(
        connector.outbox.count_rows(source_id).await.unwrap(),
        0,
        "the aborted row inserts left no trace"
    );
    let cursor = connector.outbox.read_cursor(source_id).await.unwrap();
    assert!(
        cursor.is_none_or(|cursor| cursor.byte_offset == 0 && cursor.batch_seq == 0),
        "the aborted cursor advance left the cursor unadvanced"
    );

    // The clean retry stages exactly the same batch, once.
    let outcome = connector.outbox.enqueue_batch(&batch).await.unwrap();
    assert_eq!(
        outcome,
        TranscriptEnqueueOutcome::Enqueued {
            rows_written: 2,
            batch_seq: 1,
        }
    );
    assert_eq!(connector.outbox.count_rows(source_id).await.unwrap(), 2);
    let cursor = connector
        .outbox
        .read_cursor(source_id)
        .await
        .unwrap()
        .expect("the committed batch left its cursor");
    assert_eq!(cursor.byte_offset, u64::try_from(bytes.len()).unwrap());
    assert_eq!(cursor.batch_seq, 1);
}

#[tokio::test]
async fn live_re_collecting_a_source_and_re_draining_are_both_idempotent() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let connector = live_connector(&pool, &fixture(), "idempotent").await;
    let source_id = "session-idempotent.jsonl";
    let bytes = clean_transcript("01931f2c-0000-7000-8000-00000000000e").into_bytes();

    connector.stage(source_id, &bytes).await;
    let first = connector
        .drain(TranscriptDrainModeV1::Pending)
        .await
        .unwrap();
    assert_eq!(first.appended, 2);
    assert_eq!(first.receipts, 2);

    // Re-collecting the SAME bytes: the durable cursor already covers this byte
    // range, so the resumed parse emits no turns at all and the enqueue writes
    // nothing and moves nothing. The cursor — not a dedupe pass over rows — is
    // what makes a repeated collection free.
    let (again, stats) = connector.stage(source_id, &bytes).await;
    assert_eq!(
        again,
        TranscriptEnqueueOutcome::AlreadyCovered { batch_seq: 1 }
    );
    assert_eq!(
        stats.turns_parsed, 0,
        "every byte of this source is behind the durable cursor"
    );
    assert_eq!(stats.turns_staged, 0);
    assert_eq!(connector.outbox.count_rows(source_id).await.unwrap(), 2);
    let cursor = connector
        .outbox
        .read_cursor(source_id)
        .await
        .unwrap()
        .expect("the cursor survives an already-covered re-collection");
    assert_eq!(cursor.batch_seq, 1, "the cursor did not advance");
    assert_eq!(cursor.next_ordinal, 2, "turn numbering did not restart");

    // A re-drain over EVERY row, drained or not: the ledger re-derives
    // byte-identical accepted events and classifies them Replayed (EVENT-01).
    let replay = connector
        .drain(TranscriptDrainModeV1::ReplayAll)
        .await
        .unwrap();
    assert_eq!(replay.rows_read, 2);
    assert_eq!(replay.appended, 0, "no duplicate event was appended");
    assert_eq!(replay.replayed, 2);
    assert_eq!(replay.receipts, 0, "no duplicate coverage receipt");
    assert_eq!(replay.coverage_already_covered, 2);

    assert_eq!(connector.scoped_count("memory_evidence_events").await, 2);
    assert_eq!(connector.scoped_count("memory_content_objects").await, 2);
    assert_eq!(
        connector.scoped_count("memory_coverage_receipts_v1").await,
        2
    );
    for row in connector.outbox.staged_rows(false, 256).await.unwrap() {
        assert_eq!(row.state, TranscriptOutboxStateV1::Drained);
    }
}

#[tokio::test]
async fn live_a_connector_outside_the_active_package_is_refused_closed() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let connector = live_connector(&pool, &fixture(), "foreign-connector").await;
    let source_id = "session-foreign-connector.jsonl";
    let bytes = clean_transcript("01931f2c-0000-7000-8000-00000000000f").into_bytes();

    let (batch, _) = connector.collect(source_id, &bytes).await;
    let mut candidate: EvidenceIngressCandidateV2 =
        decode_strict(&batch.rows[0].canonical_candidate).unwrap();
    candidate.connector_schema.entry_id = ContractId::new("connector.not-in-this-package").unwrap();
    connector
        .outbox
        .enqueue_batch(&retamper(&batch, &candidate))
        .await
        .unwrap();

    let refused = connector.drain(TranscriptDrainModeV1::Pending).await;
    assert!(
        matches!(
            refused,
            Err(TranscriptConnectorError::Admission(
                EvidenceAdmissionError::ConnectorNotInActivePackage
            ))
        ),
        "a connector outside the active package must be refused closed, got {refused:?}"
    );

    assert_eq!(
        connector.scoped_count("memory_evidence_events").await,
        0,
        "a refused candidate appends no event"
    );
    assert_eq!(connector.scoped_count("memory_content_objects").await, 0);
    assert_eq!(
        connector.scoped_count("memory_coverage_receipts_v1").await,
        0
    );
    assert_eq!(
        connector.scoped_count("memory_evidence_quarantine").await,
        0
    );
    let pending = connector.outbox.staged_rows(true, 256).await.unwrap();
    assert_eq!(
        pending.len(),
        1,
        "the refused row stays PENDING for an operator, never silently drained"
    );
}

#[tokio::test]
async fn live_a_candidate_selecting_a_foreign_scope_is_refused_closed() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let connector = live_connector(&pool, &fixture(), "foreign-scope").await;
    let source_id = "session-foreign-scope.jsonl";
    let bytes = clean_transcript("01931f2c-0000-7000-8000-000000000010").into_bytes();

    // EVID-04: the statement's scope is the credential-bound one. A candidate
    // that declares a different tenant/project is refused, never rescoped.
    let (batch, _) = connector.collect(source_id, &bytes).await;
    let mut candidate: EvidenceIngressCandidateV2 =
        decode_strict(&batch.rows[0].canonical_candidate).unwrap();
    candidate.scope = AuthenticatedProjectScopeV1::from_trusted_context(
        ContractId::new("tenant.somebody-else").unwrap(),
        ContractId::new("project.somebody-else").unwrap(),
    );
    connector
        .outbox
        .enqueue_batch(&retamper(&batch, &candidate))
        .await
        .unwrap();

    let refused = connector.drain(TranscriptDrainModeV1::Pending).await;
    assert!(
        matches!(
            refused,
            Err(TranscriptConnectorError::Admission(
                EvidenceAdmissionError::PayloadSelectedScope
            ))
        ),
        "a payload-selected scope must be refused closed, got {refused:?}"
    );

    assert_eq!(connector.scoped_count("memory_evidence_events").await, 0);
    assert_eq!(connector.scoped_count("memory_content_objects").await, 0);
    assert_eq!(
        connector.scoped_count("memory_coverage_receipts_v1").await,
        0
    );
    assert_eq!(
        connector.outbox.staged_rows(true, 256).await.unwrap().len(),
        1
    );
}
