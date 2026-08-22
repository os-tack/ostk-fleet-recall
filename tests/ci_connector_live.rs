//! Connected proof for the CI-evidence connector (W3-CIEV).
//!
//! Set `FLEET_RECALL_TEST_DATABASE_URL` to a disposable `CockroachDB` 26.2
//! database. Every test here is inert otherwise. Nothing in this file starts a
//! database process, invokes Docker, targets a cloud service, or opens a
//! network socket: the CI provider is the RECORDED one, replaying byte-exact
//! `gh` output captured from this repository's own Actions history and shipped
//! in `src/connectors/ci/fixtures/`.
//!
//! The bootstrap -> genesis -> generation-1 -> generation-2 ceremony is copied
//! from `tests/dogfood_live.rs`, which owns it. Generation 2 is activated
//! BEFORE anything is ingested, because that is what makes a CI run's canonical
//! resource Version-form and therefore chunkable.
//!
//! What is new is what the CI connector does against that head:
//!
//! * eight real workflow runs and one window observation become accepted
//!   events, bodies, and lexical rows, with the chain CLOSING — event count,
//!   body count, and lexical-row count all agree and nothing is unprojectable;
//! * a lexical recall for `Mermaid` — a word from the step that actually failed
//!   — returns the failing run;
//! * the measured window is durable, and the operator's question resolves to
//!   run 5 inside it and to UNKNOWN outside it;
//! * a provider answer cut off by its own `--limit` narrows the window it
//!   mints, and the narrowing survives into durable state, so the question
//!   below the cut resolves to UNKNOWN rather than naming a later run as the
//!   first failure;
//! * a re-drain of the same recorded window is an exact replay;
//! * an unsettled run is refused, and a candidate whose scope is not the
//!   witness's is refused closed before anything is written.

use std::str::FromStr as _;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use ostk_fleet_recall::FleetScope;
use ostk_fleet_recall::body_store::{
    BodyProjectionRepository, CockroachBodyProjectionRepository, GovernedContentResolver,
    reference_parser_key_v1,
};
use ostk_fleet_recall::connectors::ci::CiFactError;
use ostk_fleet_recall::connectors::ci::fact::CiWorkflowRunFactV1;
use ostk_fleet_recall::connectors::ci::ingress::CiConnectorBindingV1;
use ostk_fleet_recall::connectors::ci::scan::{
    CiScanV1, RECORDED_BRANCH, RECORDED_FIRST_FAILING_RUN, RECORDED_FIRST_RUN, RECORDED_LAST_RUN,
    RECORDED_RUN_LIST, RECORDED_WORKFLOW, recorded_provider, recorded_request, scan_runs,
};
use ostk_fleet_recall::connectors::ci::{
    CiCoverageBindingV1, CiDrainContextV1, CiDrainError, CiFactV1, CiFailureQuestionV1,
    CiFirstFailureAnswerV1, CiIngressClocksV1, CiMeasuredWindowRepository, CiMeasuredWindowRowV1,
    CiRepositoryIdV1, CiScanError, CiTextV1, CiUnknownReasonV1, CiWindowObservationLogV1,
    CockroachCiMeasuredWindowRepository, answer_first_failure, ci_coverage_observation,
    ci_scan_facts, ci_scan_manifest_digest, drain_ci_facts,
};
use ostk_fleet_recall::control_log::{
    CockroachGenesisRepository, GenesisRepository, TrustedControlScope,
};
use ostk_fleet_recall::coverage_runtime::{
    CockroachCoverageRuntimeRepository, CoverageObservationOutcome, CoverageRuntimeRepository,
    SequenceIntervalV1,
};
use ostk_fleet_recall::evidence_ledger::{
    ActiveStage4Package, CockroachAcceptedEventRepository, ContentKeyEncryptionKey,
    EvidenceAdmissionRequestV1, WriterAuthorityWitness, admit_evidence,
};
use ostk_fleet_recall::memory_contracts::bootstrap::{
    BootstrapAttestationV1, BootstrapPin, BootstrapReceiptDigest, BootstrapReceiptV1,
    verify_pinned_bootstrap,
};
use ostk_fleet_recall::memory_contracts::canonical::{decode_strict, encode_canonical};
use ostk_fleet_recall::memory_contracts::common::{
    AuthenticatedProjectScopeV1, CanonicalTimestamp, ContractId, FixedHex32, FixedHex64,
    ProfileReferenceV1, RegistryReferenceV1, frozen_profile_reference_v1,
};
use ostk_fleet_recall::memory_contracts::coverage::{
    CoverageFreshnessV1, CoverageProofBasisV1, CoverageProofMethodV1, CoverageWindowV1,
    FreshnessStateV1, ProducerIdentityV1, ProducerKindV1,
};
use ostk_fleet_recall::memory_contracts::digest::{
    DigestDomain, Sha256Digest, domain_separated_digest,
};
use ostk_fleet_recall::memory_contracts::evidence_v2::{
    EvidenceStatementV2, RegistryHeadBindingV1, RepresentationLineageV2,
};
use ostk_fleet_recall::memory_contracts::generation2_registry::{
    CI_CONNECTOR, generation_two_registry_package,
};
use ostk_fleet_recall::memory_contracts::genesis::SemanticallyClosedGenesisPackage;
use ostk_fleet_recall::memory_contracts::genesis_activation::{
    GenesisActivationPrincipalBinding, GenesisRegistryActivationApprovalSetV1,
    GenesisRegistryActivationApprovalV1, GenesisRegistryActivationStatementV1,
    GenesisRegistryAnchorV1, RegistryTestOutcomeV1, RegistryTestResultDigest, RegistryTestResultV1,
    RegistryTestRunnerPin, VerifiedRegistryTestResult, genesis_activation_policy_digest,
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
    SuccessorRegistryTestRunnerPin,
};
use ostk_fleet_recall::memory_contracts::successor_generic::{
    GenericSuccessorActivationApprovalSetV2, GenericSuccessorActivationApprovalV2,
    GenericSuccessorActivationStatementId, GenericSuccessorActivationStatementV2,
    GenericSuccessorPrincipalBinding, GenericSuccessorTestRunnerPin,
    StructurallyClosedSuccessorTargetV2,
};
use ostk_fleet_recall::memory_contracts::successor_package::SemanticallyClosedSuccessorPackage;
use ostk_fleet_recall::memory_contracts::successor_policy::{
    ActivationSignatureAlgorithmV2, ActivationSignerBindingV2, GenesisSuccessorKeyBridgePin,
    GenesisSuccessorKeyBridgeV1,
};
use ostk_fleet_recall::projectors::{
    CockroachLexicalProjector, CockroachRecallReader, LexicalProjector,
};
use ostk_fleet_recall::registry_activation::{
    CockroachGenericSuccessorRepository, CockroachGenesisActivationRepository,
    CockroachSuccessorActivationRepository, GenericSuccessorActivationCandidate,
    GenericSuccessorActivationOutcome, GenericSuccessorRepository, GenesisActivationOutcome,
    GenesisActivationRepository, SuccessorActivationCandidate, SuccessorActivationOutcome,
    SuccessorActivationRepository,
};
use ostk_fleet_recall::store::cockroach::{CockroachStore, PoolConfig, RetryPolicy};
use ostk_recall_core::PrivacyTier;
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use sqlx::PgPool;
use tokio::sync::Mutex;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Frozen contract artifacts. Identical pins to the proofs that own each step.
// ---------------------------------------------------------------------------

const GENESIS_PACKAGE: &[u8] =
    include_bytes!("../contracts/dynamic-memory/v1/genesis-registry-package.jsonl");
const BOOTSTRAP_RECEIPT: &[u8] =
    include_bytes!("../contracts/dynamic-memory/v1/bootstrap-receipt.jsonl");
const GENESIS_TEST_RESULT: &[u8] =
    include_bytes!("../contracts/dynamic-memory/v1/genesis-activation/registry-test-result.jsonl");
const GENERATION_1_PACKAGE: &[u8] =
    include_bytes!("../contracts/dynamic-memory/v2/stage4-successor/registry-package.jsonl");
const GENERATION_1_TEST_RESULT: &[u8] = include_bytes!(
    "../contracts/dynamic-memory/v2/successor-activation/registry-test-result.jsonl"
);

const GENESIS_TEST_RESULT_DIGEST: &str =
    "e91e08070250a722446195b76ee685a9697298b9fdce9809027f120c829b679d";
const GENESIS_RUNNER_ARTIFACT: &str =
    "c2e5b0653471d35e54600a8d3fbe5613aff4c04e911787c09a25e2b327d4bbbd";
const GENESIS_RUNNER_CONFIGURATION: &str =
    "1d12aabe349fd0013389f93bf1917b0de6bbd5d2bd7156c85faff0b97360686d";
const GENERATION_1_TEST_RESULT_DIGEST: &str =
    "e6783b2a018957a5861fe4e0670f55613d1ace35e381a6a9f5190ea9d7fbff8d";
const SUCCESSOR_RUNNER_ARTIFACT: &str =
    "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
const SUCCESSOR_RUNNER_CONFIGURATION: &str =
    "a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2";
const GENERIC_APPROVAL_PREFIX: &[u8] =
    b"ostk-registry-successor-activation-approval-signature-v2\0";
const BRIDGE_APPROVAL_PREFIX: &[u8] = b"ostk-registry-successor-activation-approval-signature-v1\0";
const PROPOSER: &str = "principal.operator";
const AUTHOR: &str = "principal.author";

/// Fixed so the composed generation-2 conformance result is reproducible.
const GENERATION_2_TEST_COMPLETED_AT: &str = "2026-08-22T04:00:00.000000000Z";

/// The frozen provider-instance recipe hashes exactly this decimal coordinate.
const INSTALLATION_ID: u64 = 4242;
const CONNECTOR_PRINCIPAL: &str = "connector.ci";
const CONNECTOR_INSTANCE: &str = "connector.ci.aetia";
const REPOSITORY_ID: &str = "ci.repo.aetia";

/// Nine facts: eight settled runs plus one window observation.
const EXPECTED_FACTS: u64 = 9;

/// Each `#[tokio::test]` gets its own runtime, and a `PgPool` is bound to the
/// runtime that created it, so pools are never shared across tests. The schema
/// is shared, so migration is serialized and run exactly once per process.
static MIGRATED: Mutex<bool> = Mutex::const_new(false);

// ---------------------------------------------------------------------------
// Live plumbing.
// ---------------------------------------------------------------------------

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
        format!("ci-{label}-{}", Uuid::now_v7()),
        "ci-connector-connected-test",
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

fn signer(principal: &str, seed: u8) -> ActivationSignerBindingV2 {
    let pair = Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap();
    ActivationSignerBindingV2 {
        principal_id: ContractId::new(principal).unwrap(),
        algorithm: ActivationSignatureAlgorithmV2::Ed25519,
        public_key: FixedHex32::from_bytes(pair.public_key().as_ref().try_into().unwrap()),
    }
}

fn detached_signature(prefix: &[u8], statement_id: Sha256Digest, seed: u8) -> FixedHex64 {
    let mut message = prefix.to_vec();
    message.extend_from_slice(statement_id.as_bytes());
    let pair = Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap();
    FixedHex64::from_bytes(pair.sign(&message).as_ref().try_into().unwrap())
}

#[derive(Clone)]
struct ContractFixture {
    profile: ProfileReferenceV1,
    semantic_scope: AuthenticatedProjectScopeV1,
    genesis_package: SemanticallyClosedGenesisPackage,
    genesis_test_result: VerifiedRegistryTestResult,
    genesis_principal_binding: GenesisActivationPrincipalBinding,
    stage4: SemanticallyClosedStage4Package,
    generation_2: ManifestVerifiedRegistryPackage,
    generation_2_closed: SemanticallyClosedSuccessorPackage,
    generation_2_target: StructurallyClosedSuccessorTargetV2,
    generation_2_test_result: Vec<u8>,
    generation_2_test_result_digest: RegistryTestResultDigest,
}

fn fixture() -> ContractFixture {
    let profile = frozen_profile_reference_v1();
    let bootstrap_value: BootstrapReceiptV1 = decode_strict(record(BOOTSTRAP_RECEIPT)).unwrap();
    let semantic_scope = bootstrap_value.statement.scope;
    let genesis_manifest =
        ManifestVerifiedRegistryPackage::decode(record(GENESIS_PACKAGE), &profile).unwrap();
    let genesis_package =
        SemanticallyClosedGenesisPackage::from_manifest_verified(genesis_manifest).unwrap();
    let genesis_test_result = verify_registry_test_result(
        record(GENESIS_TEST_RESULT),
        RegistryTestRunnerPin::from_trusted_config(
            digest(GENESIS_RUNNER_ARTIFACT),
            digest(GENESIS_RUNNER_CONFIGURATION),
            RegistryTestResultDigest::from_digest(digest(GENESIS_TEST_RESULT_DIGEST)),
        ),
        &profile,
        &genesis_package,
    )
    .unwrap();
    let stage4_manifest =
        ManifestVerifiedRegistryPackage::decode(record(GENERATION_1_PACKAGE), &profile).unwrap();
    let stage4 = SemanticallyClosedStage4Package::from_successor_package(
        SemanticallyClosedSuccessorPackage::from_manifest_verified(stage4_manifest).unwrap(),
    )
    .unwrap();
    let generation_2 = generation_two_registry_package(
        &ManifestVerifiedRegistryPackage::decode(record(GENERATION_1_PACKAGE), &profile).unwrap(),
    )
    .expect("the generation-2 composition must close");
    let generation_2_closed =
        SemanticallyClosedSuccessorPackage::from_manifest_verified(generation_2.clone()).unwrap();
    let generation_2_target =
        StructurallyClosedSuccessorTargetV2::from_manifest_verified(&generation_2).unwrap();
    let generation_2_test_result = encode_canonical(&RegistryTestResultV1 {
        schema_version: 1,
        profile: profile.clone(),
        package_digest: generation_2.package_digest(),
        positive_vector_suite_digest: generation_2.package().positive_vector_suite_digest,
        negative_vector_suite_digest: generation_2.package().negative_vector_suite_digest,
        executed_vector_manifest_digest: profile.vector_manifest_digest,
        runner_artifact_digest: digest(SUCCESSOR_RUNNER_ARTIFACT),
        runner_configuration_digest: digest(SUCCESSOR_RUNNER_CONFIGURATION),
        passed_case_count: 1,
        failed_case_count: 0,
        outcome: RegistryTestOutcomeV1::Passed,
        completed_at: CanonicalTimestamp::parse(GENERATION_2_TEST_COMPLETED_AT).unwrap(),
    })
    .unwrap();
    let generation_2_test_result_digest = RegistryTestResultDigest::from_digest(
        domain_separated_digest(DigestDomain::RegistryTestResult, &generation_2_test_result),
    );
    ContractFixture {
        profile,
        semantic_scope,
        genesis_package,
        genesis_test_result,
        genesis_principal_binding: GenesisActivationPrincipalBinding::from_trusted_config(
            ContractId::new(PROPOSER).unwrap(),
            ContractId::new(AUTHOR).unwrap(),
        ),
        stage4,
        generation_2,
        generation_2_closed,
        generation_2_target,
        generation_2_test_result,
        generation_2_test_result_digest,
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

/// One live scope whose registry head is the composed generation-2 package,
/// narrowed to the CI connector schema.
struct ActivatedMemory {
    physical_scope: FleetScope,
    trusted_scope: TrustedControlScope,
    active: ActiveStage4Package,
    witness: WriterAuthorityWitness,
    ledger: Arc<CockroachAcceptedEventRepository>,
    coverage: CockroachCoverageRuntimeRepository,
}

#[allow(clippy::too_many_lines)] // one linear ceremony; splitting it hides it
async fn activate(
    pool: &PgPool,
    fixture: &ContractFixture,
    label: &str,
    seed: u8,
) -> ActivatedMemory {
    let physical = physical_scope(label);
    let control =
        TrustedControlScope::from_trusted_context(&physical, fixture.semantic_scope.clone())
            .unwrap();

    let mut receipt: BootstrapReceiptV1 = decode_strict(record(BOOTSTRAP_RECEIPT)).unwrap();
    receipt.statement.genesis_epoch.partition_recipe.seed = FixedHex32::from_bytes([seed; 32]);
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
    let bootstrap_receipt_digest = BootstrapReceiptDigest::from_digest(domain_separated_digest(
        DigestDomain::BootstrapReceipt,
        &canonical,
    ));
    let bootstrap = verify_pinned_bootstrap(
        &canonical,
        BootstrapPin::from_trusted_config(bootstrap_receipt_digest),
        &fixture.profile,
        &fixture.semantic_scope,
        &fixture.genesis_package,
    )
    .unwrap();

    CockroachGenesisRepository::new(pool.clone(), control.clone(), retry_policy())
        .bootstrap_genesis(&bootstrap, &fixture.genesis_package)
        .await
        .unwrap();

    let genesis_effective = canonical_time(server_time(pool).await);
    let genesis_statement = GenesisRegistryActivationStatementV1 {
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
        proposer_principal_id: ContractId::new(PROPOSER).unwrap(),
        package_author_principal_id: ContractId::new(AUTHOR).unwrap(),
    };
    let genesis_statement_id = genesis_statement.statement_id().unwrap();
    let mut genesis_approvals = ["principal.1", "principal.2"]
        .into_iter()
        .zip([1_u8, 2])
        .map(
            |(principal, approval_seed)| GenesisRegistryActivationApprovalV1 {
                schema_version: 1,
                statement_id: genesis_statement_id,
                signer_principal_id: ContractId::new(principal).unwrap(),
                signature: detached_signature(
                    b"ostk-registry-activation-approval-signature-v1\0",
                    genesis_statement_id.digest(),
                    approval_seed,
                ),
            },
        )
        .collect::<Vec<_>>();
    genesis_approvals.sort_unstable();
    let genesis_request = verify_genesis_registry_activation(
        &encode_canonical(&genesis_statement).unwrap(),
        &encode_canonical(&GenesisRegistryActivationApprovalSetV1 {
            schema_version: 1,
            statement_id: genesis_statement_id,
            approvals: genesis_approvals,
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
        control.clone(),
        retry_policy(),
        bootstrap.clone(),
        fixture.genesis_package.clone(),
        fixture.genesis_test_result.clone(),
        fixture.genesis_principal_binding.clone(),
    )
    .unwrap()
    .activate_genesis(&genesis_request)
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
    let bridge_digest = bridge.bridge_digest().unwrap();
    let bridge_bytes = encode_canonical(&bridge).unwrap();

    tokio::time::sleep(Duration::from_millis(2)).await;
    let successor_effective = canonical_time(server_time(pool).await);
    let successor_statement = SuccessorRegistryActivationStatementV1 {
        schema_version: 1,
        profile: fixture.profile.clone(),
        scope: fixture.semantic_scope.clone(),
        expected_predecessor_head: genesis_head,
        current_v1_activation_policy: current_v1_policy_reference(fixture),
        target_package_digest: fixture.stage4.package_digest(),
        target_activation_policy: fixture
            .stage4
            .activation_policy()
            .registry_reference()
            .clone(),
        test_vector_result_digest: RegistryTestResultDigest::from_digest(digest(
            GENERATION_1_TEST_RESULT_DIGEST,
        )),
        genesis_successor_key_bridge_digest: bridge_digest,
        from_generation: 0,
        to_generation: 1,
        effective_from: successor_effective,
        effective_until: None,
        proposer_principal_id: ContractId::new(PROPOSER).unwrap(),
        package_author_principal_id: ContractId::new(AUTHOR).unwrap(),
    };
    let successor_statement_id = successor_statement.statement_id().unwrap();
    let candidate = SuccessorActivationCandidate::from_bounded_canonical_bytes(
        encode_canonical(&successor_statement).unwrap(),
        encode_canonical(&SuccessorRegistryActivationApprovalSetV1 {
            schema_version: 1,
            statement_id: successor_statement_id,
            approvals: vec![
                SuccessorRegistryActivationApprovalV1 {
                    schema_version: 1,
                    statement_id: successor_statement_id,
                    signer_principal_id: ContractId::new("principal.alice").unwrap(),
                    signature: detached_signature(
                        BRIDGE_APPROVAL_PREFIX,
                        successor_statement_id.digest(),
                        1,
                    ),
                },
                SuccessorRegistryActivationApprovalV1 {
                    schema_version: 1,
                    statement_id: successor_statement_id,
                    signer_principal_id: ContractId::new("principal.bob").unwrap(),
                    signature: detached_signature(
                        BRIDGE_APPROVAL_PREFIX,
                        successor_statement_id.digest(),
                        2,
                    ),
                },
            ],
        })
        .unwrap(),
    )
    .unwrap();
    let accepted = match CockroachSuccessorActivationRepository::new(
        pool.clone(),
        control.clone(),
        retry_policy(),
        bootstrap,
        fixture.genesis_package.clone(),
        fixture.genesis_test_result.clone(),
        fixture.genesis_principal_binding.clone(),
        fixture.stage4.clone(),
        record(GENERATION_1_TEST_RESULT),
        SuccessorRegistryTestRunnerPin::from_trusted_config(
            digest(SUCCESSOR_RUNNER_ARTIFACT),
            digest(SUCCESSOR_RUNNER_CONFIGURATION),
            RegistryTestResultDigest::from_digest(digest(GENERATION_1_TEST_RESULT_DIGEST)),
        ),
        bridge_bytes,
        GenesisSuccessorKeyBridgePin::from_trusted_config(bridge_digest),
        SuccessorActivationPrincipalBinding::from_trusted_config(
            ContractId::new(PROPOSER).unwrap(),
            ContractId::new(AUTHOR).unwrap(),
        ),
    )
    .unwrap()
    .activate_first_successor(&candidate)
    .await
    .unwrap()
    {
        SuccessorActivationOutcome::Inserted(accepted) => accepted,
        SuccessorActivationOutcome::ExactReplay(_) => panic!("a fresh first successor must insert"),
    };
    let generation_1_head = accepted.registry_head;

    let ledger = Arc::new(CockroachAcceptedEventRepository::new(
        pool.clone(),
        control.clone(),
        retry_policy(),
    ));
    assert_eq!(
        ledger
            .read_writer_authority_witness()
            .await
            .unwrap()
            .generation(),
        1
    );

    let generation_2_head = activate_generation_two(
        pool,
        &control,
        bootstrap_receipt_digest,
        &generation_1_head,
        fixture,
    )
    .await;
    let witness = ledger.read_writer_authority_witness().await.unwrap();
    assert_eq!(
        witness.generation(),
        2,
        "CI ingestion runs under the generation-2 head, whose canonical resources are \
         version-form"
    );
    let active = ActiveStage4Package::bind_connector(
        fixture.generation_2_closed.clone(),
        &ContractId::new(CI_CONNECTOR.connector_schema).unwrap(),
        generation_2_head,
        &witness,
    )
    .expect("the generation-2 head activated the package carrying the CI connector");

    ActivatedMemory {
        coverage: CockroachCoverageRuntimeRepository::new(
            pool.clone(),
            control.clone(),
            retry_policy(),
        ),
        physical_scope: physical,
        trusted_scope: control,
        active,
        witness,
        ledger,
    }
}

async fn activate_generation_two(
    pool: &PgPool,
    control: &TrustedControlScope,
    bootstrap_receipt_digest: BootstrapReceiptDigest,
    generation_1_head: &RegistryHeadBindingV1,
    fixture: &ContractFixture,
) -> RegistryHeadBindingV1 {
    let repository = CockroachGenericSuccessorRepository::new(
        pool.clone(),
        control.clone(),
        retry_policy(),
        bootstrap_receipt_digest,
        fixture.generation_2.canonical_bytes().to_vec(),
        &fixture.generation_2_test_result,
        GenericSuccessorTestRunnerPin::from_trusted_config(
            digest(SUCCESSOR_RUNNER_ARTIFACT),
            digest(SUCCESSOR_RUNNER_CONFIGURATION),
            fixture.generation_2_test_result_digest,
        ),
        GenericSuccessorPrincipalBinding::from_trusted_config(
            ContractId::new(PROPOSER).unwrap(),
            ContractId::new(AUTHOR).unwrap(),
        ),
        generation_1_head.clone(),
    )
    .unwrap();

    tokio::time::sleep(Duration::from_millis(2)).await;
    let statement = GenericSuccessorActivationStatementV2 {
        schema_version: 2,
        profile: fixture.profile.clone(),
        scope: fixture.semantic_scope.clone(),
        expected_predecessor_head: generation_1_head.clone(),
        current_activation_policy: fixture
            .generation_2_target
            .activation_policy()
            .registry_reference()
            .clone(),
        target_package_digest: fixture.generation_2_target.package_digest(),
        target_activation_policy: fixture
            .generation_2_target
            .activation_policy()
            .registry_reference()
            .clone(),
        test_vector_result_digest: fixture.generation_2_test_result_digest,
        from_generation: 1,
        to_generation: 2,
        effective_from: canonical_time(server_time(pool).await),
        effective_until: None,
        proposer_principal_id: ContractId::new(PROPOSER).unwrap(),
        package_author_principal_id: ContractId::new(AUTHOR).unwrap(),
    };
    let statement_id: GenericSuccessorActivationStatementId = statement.statement_id().unwrap();
    let candidate = GenericSuccessorActivationCandidate::from_bounded_canonical_bytes(
        encode_canonical(&statement).unwrap(),
        encode_canonical(&GenericSuccessorActivationApprovalSetV2 {
            schema_version: 2,
            statement_id,
            approvals: vec![
                GenericSuccessorActivationApprovalV2 {
                    schema_version: 2,
                    statement_id,
                    signer_principal_id: ContractId::new("principal.alice").unwrap(),
                    signature: detached_signature(
                        GENERIC_APPROVAL_PREFIX,
                        statement_id.digest(),
                        1,
                    ),
                },
                GenericSuccessorActivationApprovalV2 {
                    schema_version: 2,
                    statement_id,
                    signer_principal_id: ContractId::new("principal.bob").unwrap(),
                    signature: detached_signature(
                        GENERIC_APPROVAL_PREFIX,
                        statement_id.digest(),
                        2,
                    ),
                },
            ],
        })
        .unwrap(),
    )
    .unwrap();

    match repository.activate_generic_successor(&candidate).await {
        Ok(GenericSuccessorActivationOutcome::Inserted(accepted)) => accepted.registry_head,
        Ok(GenericSuccessorActivationOutcome::ExactReplay(_)) => {
            panic!("a fresh generation-2 activation must insert")
        }
        Err(error) => panic!("the generation-2 activation must succeed: {error}"),
    }
}

async fn scoped_count(pool: &PgPool, table: &str, scope: &FleetScope) -> i64 {
    let query = format!("SELECT count(*)::INT8 FROM {table} WHERE tenant_id = $1 AND project = $2");
    sqlx::query_scalar(&query)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .fetch_one(pool)
        .await
        .expect("scoped count must succeed")
}

// ---------------------------------------------------------------------------
// CI-connector wiring on top of the activated head.
// ---------------------------------------------------------------------------

fn content_key() -> ContentKeyEncryptionKey {
    ContentKeyEncryptionKey::from_hex(&"ab".repeat(32)).unwrap()
}

fn repository_id() -> CiRepositoryIdV1 {
    CiRepositoryIdV1::from_trusted_config(ContractId::new(REPOSITORY_ID).unwrap(), INSTALLATION_ID)
        .unwrap()
}

fn binding(memory: &ActivatedMemory) -> CiConnectorBindingV1 {
    CiConnectorBindingV1::resolve(
        &memory.active,
        ContractId::new(CONNECTOR_PRINCIPAL).unwrap(),
        ContractId::new(CONNECTOR_INSTANCE).unwrap(),
        INSTALLATION_ID,
    )
    .expect("the CI connector must resolve from the active generation-2 package")
}

/// The scan's fetch instant. Fixed rather than a wall clock: `observed_at` is
/// inside the accepted-event preimage, so a value that changed per call would
/// make two drains of one recorded scan two different events for one source
/// fact instead of an exact replay.
fn fetched_at() -> CanonicalTimestamp {
    CanonicalTimestamp::parse("2026-08-22T12:00:00.000000000Z").unwrap()
}

fn clocks(received_at: CanonicalTimestamp) -> CiIngressClocksV1 {
    CiIngressClocksV1 {
        observed_at: fetched_at(),
        received_at,
    }
}

fn recorded_scan() -> CiScanV1 {
    scan_runs(
        &recorded_provider(),
        &recorded_request(repository_id()),
        &fetched_at(),
    )
    .expect("the recorded corpus must scan")
}

/// `window_end` is the drain's own `observed_through`: the coverage runtime
/// refuses a receipt whose observation does not reach the end of the window it
/// claims, which is the same rule in the time dimension that
/// `answer_first_failure` enforces in the run-number dimension.
fn coverage_binding(window_end: CanonicalTimestamp) -> CiCoverageBindingV1 {
    CiCoverageBindingV1 {
        connector_instance: ContractId::new(CONNECTOR_INSTANCE).unwrap(),
        producer: ProducerIdentityV1 {
            schema_version: 1,
            kind: ProducerKindV1::Connector,
            producer_id: ContractId::new(CONNECTOR_PRINCIPAL).unwrap(),
            version: 1,
        },
        freshness: CoverageFreshnessV1 {
            state: FreshnessStateV1::Current,
            freshness_rule: RegistryReferenceV1 {
                entry_id: ContractId::new("coverage.freshness.default-rule").unwrap(),
                version: 1,
                entry_digest: Sha256Digest::from_bytes([0x33; 32]),
            },
        },
        proof_basis: CoverageProofBasisV1 {
            method: CoverageProofMethodV1::EnumeratedSnapshot,
            proof_method_registration: RegistryReferenceV1 {
                entry_id: ContractId::new("coverage.proof.enumerated-snapshot").unwrap(),
                version: 1,
                entry_digest: Sha256Digest::from_bytes([0x44; 32]),
            },
        },
        time_window: CoverageWindowV1 {
            window_start: CanonicalTimestamp::parse("2026-08-01T00:00:00.000000000Z").unwrap(),
            window_end,
        },
    }
}

fn coverage_scope_uri() -> ResourceUri {
    ResourceUri::from_str(&format!(
        "urn:ostk:entity:v1:provider_instance:sha256:{}",
        hex::encode([0x77_u8; 32])
    ))
    .unwrap()
}

// ---------------------------------------------------------------------------
// The connected proofs.
// ---------------------------------------------------------------------------

/// The whole item, end to end: real recorded CI -> admission -> accepted events
/// -> bodies -> lexical rows -> a recall that answers the operator's question,
/// with an honest, bounded coverage statement.
#[tokio::test]
#[allow(clippy::too_many_lines)] // one linear pipeline; splitting it hides it
async fn live_the_recorded_ci_window_closes_the_chain_to_recall() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let fixture = fixture();
    let memory = activate(&pool, &fixture, "chain", 0x31).await;
    let binding = binding(&memory);

    // 1. Read the recorded window and turn it into an ordered fact batch.
    let scan = recorded_scan();
    assert_eq!(scan.admitted_run_count(), 8);
    assert_eq!(scan.failed_run_count(), 2);
    let mut log = CiWindowObservationLogV1::new(ContractId::new(CONNECTOR_INSTANCE).unwrap());
    let facts = ci_scan_facts(&scan, &mut log, 16).expect("the scan must become a fact batch");
    assert_eq!(u64::try_from(facts.len()).unwrap(), EXPECTED_FACTS);

    // 2. Drain it through the W1-EVID admission seam.
    let received_at = canonical_time(server_time(&pool).await);
    let context = CiDrainContextV1 {
        binding: &binding,
        active: &memory.active,
        witness: &memory.witness,
        ledger: memory.ledger.as_ref(),
        control_scope: &memory.trusted_scope,
        kek: &content_key(),
        clocks: &clocks(received_at.clone()),
    };
    let report = drain_ci_facts(&context, &facts)
        .await
        .expect("every settled run must be admissible");
    assert_eq!(report.appended, EXPECTED_FACTS);
    assert_eq!(report.quarantined, 0);
    assert_eq!(report.quarantined_window_observations, 0);
    assert!(report.window_observation_event.is_some());
    assert_eq!(
        scoped_count(&pool, "memory_evidence_events", &memory.physical_scope).await,
        i64::try_from(EXPECTED_FACTS).unwrap(),
        "every fact must be one accepted event"
    );

    // 3. EVID-03 on the DURABLE statement: three clocks, three values, in
    //    order. `accepted_at` is the server's, so it is later than both.
    let (canonical_event, accepted_at): (Vec<u8>, DateTime<Utc>) = sqlx::query_as(
        "SELECT canonical_event, accepted_at FROM memory_evidence_events \
         WHERE tenant_id = $1 AND project = $2 ORDER BY committed_offset LIMIT 1",
    )
    .bind(memory.physical_scope.tenant_id)
    .bind(&memory.physical_scope.project)
    .fetch_one(&pool)
    .await
    .expect("the first accepted event must be readable");
    let statement: EvidenceStatementV2 =
        decode_strict(&canonical_event).expect("the stored event must decode");
    assert!(
        statement.occurred_at < statement.observed_at,
        "the provider's settle instant precedes the connector's fetch instant: {} vs {}",
        statement.occurred_at,
        statement.observed_at
    );
    assert!(
        CanonicalTimestamp::from_datetime(&accepted_at).unwrap() > statement.observed_at,
        "admission happened after the observation"
    );

    // 4. Bodies. The chain either closes here or the connector is unretrievable.
    let bodies = CockroachBodyProjectionRepository::new(
        pool.clone(),
        memory.physical_scope.tenant_id,
        memory.physical_scope.project.clone(),
        reference_parser_key_v1(),
        Arc::new(GovernedContentResolver::new(
            pool.clone(),
            memory.physical_scope.tenant_id,
            memory.physical_scope.project.clone(),
            memory.witness.semantic_scope().clone(),
            content_key(),
        )),
        retry_policy(),
    );
    let body_run = bodies
        .project_pending()
        .await
        .expect("the body plane must consume every accepted event");
    assert_eq!(
        body_run.events_unprojectable, 0,
        "a CI run is Version-form-addressable, so NOTHING may be unprojectable"
    );
    assert_eq!(
        body_run.events_projected, EXPECTED_FACTS,
        "every accepted event must produce a body"
    );
    assert_eq!(
        scoped_count(&pool, "memory_body_objects_v1", &memory.physical_scope).await,
        i64::try_from(EXPECTED_FACTS).unwrap(),
        "event count and body count must agree"
    );

    // 5. Lexical rows.
    let lexical = CockroachLexicalProjector::new(
        pool.clone(),
        memory.physical_scope.tenant_id,
        memory.physical_scope.project.clone(),
        256,
        retry_policy(),
    );
    let mut indexed = 0_u64;
    loop {
        let pass = lexical.project_pending().await.expect("lexical projection");
        if pass.bodies_consumed == 0 {
            break;
        }
        indexed += pass.rows_indexed;
        assert_eq!(
            pass.rows_unindexable, 0,
            "a canonical JSON body always has text"
        );
    }
    assert_eq!(
        indexed, EXPECTED_FACTS,
        "body count and lexical row count must agree"
    );
    assert_eq!(
        scoped_count(
            &pool,
            "memory_body_lexical_projection_v1",
            &memory.physical_scope
        )
        .await,
        i64::try_from(EXPECTED_FACTS).unwrap()
    );

    // 6. RECALL. A word from the step that actually failed must return the run.
    let reader = CockroachRecallReader::new(
        pool.clone(),
        memory.physical_scope.tenant_id,
        memory.physical_scope.project.clone(),
    );
    let snapshot = reader.snapshot().await.expect("projection snapshot");
    let failing_body_text = snapshot
        .lexical
        .iter()
        .map(|row| row.4.clone())
        .find(|text| text.contains("Mermaid"))
        .expect("the failing step name must be indexed as words");
    assert!(
        failing_body_text.contains("docs"),
        "the failing job name must be searchable too: {failing_body_text}"
    );

    for probe in ["Mermaid", "docs", "failure"] {
        let hits = reader
            .recall(probe, None, 10)
            .await
            .unwrap_or_else(|error| panic!("recall for {probe:?} must succeed: {error}"));
        assert!(
            !hits.hits.is_empty(),
            "a lexical recall for {probe:?} must return the failing run"
        );
    }

    // 7. The measured window is durable, and it BOUNDS the answer.
    let windows = CockroachCiMeasuredWindowRepository::new(
        pool.clone(),
        memory.physical_scope.tenant_id,
        memory.physical_scope.project.clone(),
    );
    let row = CiMeasuredWindowRowV1 {
        connector_instance: ContractId::new(CONNECTOR_INSTANCE).unwrap(),
        window: scan.window.clone(),
        window_id: scan.window.window_id().unwrap(),
        admitted_run_count: scan.admitted_run_count(),
        failed_run_count: scan.failed_run_count(),
        source_digest: ci_scan_manifest_digest(&report.admitted_keys),
        evidence_id: report.window_observation_event.unwrap(),
    };
    windows
        .record_window(&row)
        .await
        .expect("the measured window must be recordable");
    // Idempotent: recording the same window twice changes nothing.
    windows.record_window(&row).await.unwrap();
    let recorded = windows
        .measured_windows(&ContractId::new(CONNECTOR_INSTANCE).unwrap())
        .await
        .expect("the measured window must be readable");
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0], row, "the window round-trips exactly");
    assert_eq!(
        windows
            .resume_run_number(
                &ContractId::new(CONNECTOR_INSTANCE).unwrap(),
                &ContractId::new(REPOSITORY_ID).unwrap(),
                &CiTextV1::render(RECORDED_WORKFLOW).unwrap(),
                &CiTextV1::render(RECORDED_BRANCH).unwrap(),
            )
            .await
            .unwrap(),
        RECORDED_LAST_RUN + 1,
        "the next scan resumes past what was measured, so each settled run is observed once"
    );

    // 8. THE OPERATOR'S QUESTION, answered from durable state.
    let measured = &recorded[0].window;
    let answer = answer_first_failure(
        measured,
        &scan.runs,
        CiFailureQuestionV1::since_the_beginning(RECORDED_LAST_RUN),
    )
    .expect("the question must resolve");
    match &answer {
        CiFirstFailureAnswerV1::FirstFailure {
            run_number,
            occurred_at,
            ..
        } => {
            assert_eq!(
                *run_number, RECORDED_FIRST_FAILING_RUN,
                "CI first failed on run 5 of this repository's own history"
            );
            assert!(
                measured.starts_at_origin(),
                "and the window reaches the origin"
            );
            assert!(!occurred_at.as_str().is_empty());
        }
        other => panic!("expected a real first failure, got {other:?}"),
    }

    // And the same question against a NARROWER window must be UNKNOWN, not a
    // negative and not a false first.
    let narrow_scan = {
        let mut request = recorded_request(repository_id());
        request.first_run_number = 6;
        scan_runs(&recorded_provider(), &request, &fetched_at()).unwrap()
    };
    let narrow_answer = answer_first_failure(
        &narrow_scan.window,
        &narrow_scan.runs,
        CiFailureQuestionV1::since_the_beginning(RECORDED_LAST_RUN),
    )
    .unwrap();
    assert!(
        matches!(
            narrow_answer,
            CiFirstFailureAnswerV1::Unknown {
                reason: CiUnknownReasonV1::QuestionStartsBeforeWindow,
                ..
            }
        ),
        "a question reaching outside the window must be UNKNOWN: {narrow_answer:?}"
    );
    assert!(!narrow_answer.is_verified_negative());

    // 9. The coverage receipt binds the durable window observation.
    let observation = ci_coverage_observation(
        &coverage_binding(received_at.clone()),
        coverage_scope_uri(),
        &scan.window,
        SequenceIntervalV1::new(1, 1_000).unwrap(),
        &report,
        received_at,
    )
    .expect("a durable window observation anchors a receipt");
    assert_eq!(
        observation.observed,
        SequenceIntervalV1::new(RECORDED_FIRST_RUN, RECORDED_LAST_RUN + 1).unwrap()
    );
    match memory
        .coverage
        .observe(&observation)
        .await
        .expect("the receipt must be recordable")
    {
        CoverageObservationOutcome::Recorded { .. } => {}
        CoverageObservationOutcome::AlreadyCovered { .. } => {
            panic!("a first observation must extend coverage")
        }
    }
}

/// A re-drain of the SAME recorded window is an exact replay: no second event,
/// no second body, no second lexical row.
#[tokio::test]
async fn live_a_redrain_of_the_same_window_is_an_exact_replay() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let fixture = fixture();
    let memory = activate(&pool, &fixture, "replay", 0x32).await;
    let binding = binding(&memory);
    let scan = recorded_scan();

    let received_at = canonical_time(server_time(&pool).await);
    let drain = |facts: Vec<CiFactV1>, received_at: CanonicalTimestamp| {
        let binding = &binding;
        let memory = &memory;
        async move {
            let context = CiDrainContextV1 {
                binding,
                active: &memory.active,
                witness: &memory.witness,
                ledger: memory.ledger.as_ref(),
                control_scope: &memory.trusted_scope,
                kek: &content_key(),
                clocks: &clocks(received_at),
            };
            drain_ci_facts(&context, &facts).await
        }
    };

    let mut log = CiWindowObservationLogV1::new(ContractId::new(CONNECTOR_INSTANCE).unwrap());
    let facts = ci_scan_facts(&scan, &mut log, 16).unwrap();
    let first = drain(facts.clone(), received_at.clone()).await.unwrap();
    assert_eq!(first.appended, EXPECTED_FACTS);

    // A LATER `received_at`: it is deliberately not part of the accepted-event
    // preimage, so the replay must still be exact.
    let later = canonical_time(server_time(&pool).await);
    let second = drain(facts, later).await.unwrap();
    assert_eq!(second.appended, 0, "a re-drain must append nothing");
    assert_eq!(second.replayed, EXPECTED_FACTS, "EVENT-01");
    assert_eq!(second.quarantined, 0);
    assert_eq!(
        scoped_count(&pool, "memory_evidence_events", &memory.physical_scope).await,
        i64::try_from(EXPECTED_FACTS).unwrap(),
        "a replay writes no second event"
    );
}

/// An unsettled run is refused before admission, with a typed error, and
/// nothing is written.
#[tokio::test]
async fn live_an_unsettled_run_is_refused_before_anything_is_written() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let fixture = fixture();
    let memory = activate(&pool, &fixture, "unsettled", 0x33).await;
    let binding = binding(&memory);

    // The scan itself refuses a window that contains an in-flight run: the
    // exact shape a real one has, produced by editing the REAL recorded bytes.
    let mut items: Vec<serde_json::Value> = serde_json::from_slice(RECORDED_RUN_LIST).unwrap();
    let target = items
        .iter_mut()
        .find(|item| item["number"].as_u64() == Some(RECORDED_LAST_RUN))
        .unwrap();
    target["status"] = serde_json::Value::String("in_progress".to_owned());
    target["conclusion"] = serde_json::Value::String(String::new());
    let edited = serde_json::to_vec(&items).unwrap();
    let provider = recorded_provider().with_runs(&edited);
    let scan_error = scan_runs(&provider, &recorded_request(repository_id()), &fetched_at())
        .expect_err("a window containing an unsettled run is not a window");
    assert!(
        matches!(
            scan_error,
            CiScanError::Fact(CiFactError::UnsettledRun { .. })
        ),
        "unexpected scan error: {scan_error}"
    );

    // And the ingress refuses one directly, so a caller that built a fact by
    // hand cannot reach admission either.
    let scan = recorded_scan();
    let mut in_flight: CiWorkflowRunFactV1 = scan.runs[0].clone();
    in_flight.status = ostk_fleet_recall::connectors::ci::fact::CiRunStatusV1::InProgress;
    let received_at = canonical_time(server_time(&pool).await);
    let context = CiDrainContextV1 {
        binding: &binding,
        active: &memory.active,
        witness: &memory.witness,
        ledger: memory.ledger.as_ref(),
        control_scope: &memory.trusted_scope,
        kek: &content_key(),
        clocks: &clocks(received_at),
    };
    let error = drain_ci_facts(&context, &[CiFactV1::WorkflowRun(in_flight)])
        .await
        .expect_err("an unsettled run has no immutable revision to address");
    assert!(
        matches!(
            error,
            CiDrainError::Ingress(ostk_fleet_recall::connectors::ci::CiIngressError::Fact(
                CiFactError::UnsettledRun { .. }
            ))
        ),
        "unexpected drain error: {error}"
    );
    assert_eq!(
        scoped_count(&pool, "memory_evidence_events", &memory.physical_scope).await,
        0,
        "a refused run writes no event"
    );
    assert_eq!(
        scoped_count(&pool, "memory_content_objects", &memory.physical_scope).await,
        0,
        "and no governed content object"
    );
}

/// A candidate whose scope is not the witness's is refused closed, before any
/// database work. Scope comes from the active package, never from a payload.
#[tokio::test]
async fn live_a_candidate_that_declares_a_foreign_scope_is_refused() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let fixture = fixture();
    let memory = activate(&pool, &fixture, "scope", 0x34).await;
    let binding = binding(&memory);
    let scan = recorded_scan();

    let received_at = canonical_time(server_time(&pool).await);
    let ingress = binding
        .build_ingress(
            &CiFactV1::WorkflowRun(scan.runs[0].clone()),
            &clocks(received_at),
            1,
        )
        .expect("the honest candidate must build");
    assert_eq!(
        &ingress.candidate.scope,
        memory.active.scope(),
        "an honestly built candidate carries the credential-bound scope"
    );

    // Now forge one. The fact itself has no scope field, so the only place a
    // scope can be tampered with is the candidate envelope — which admission
    // compares against the ACTIVE package's scope.
    let mut forged = ingress.candidate.clone();
    forged.scope.project_namespace = ContractId::new("project.attacker").unwrap();
    forged.source_fact.scope = forged.scope.clone();
    let error = admit_evidence(
        &memory.active,
        EvidenceAdmissionRequestV1 {
            candidate: &forged,
            locators: &ingress.locators,
            canonical_payload: &ingress.canonical_payload,
            delivery: ingress.delivery.clone(),
            lineage: RepresentationLineageV2::Origin,
        },
    )
    .expect_err("a candidate that declares its own scope must be refused");
    assert!(
        format!("{error}").to_ascii_lowercase().contains("scope"),
        "unexpected admission error: {error}"
    );
    assert_eq!(
        scoped_count(&pool, "memory_evidence_events", &memory.physical_scope).await,
        0,
        "a refused candidate writes nothing"
    );
}

/// A provider answer cut off by its own `--limit` narrows the window, and the
/// narrowing survives all the way into durable state.
///
/// This is the failure the window discipline exists to stop. `gh run list` is
/// newest-first behind a limit; when the limit does not reach the oldest run
/// the request names, the payload holds only the newest slice and says nothing
/// about the rest. Minting the requested window over that answer would record
/// a durable claim to have measured runs 1..8 while having read only 6..8 —
/// and this repository's real first CI failure is run 5, below the cut. The
/// question would then answer "run 8 was the first failure", which is false.
#[tokio::test]
async fn live_a_truncated_provider_listing_records_only_the_range_it_reached() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let fixture = fixture();
    let memory = activate(&pool, &fixture, "cutoff", 0x35).await;
    let binding = binding(&memory);

    // The REAL recorded listing, cut the way a short `--limit` cuts one.
    let mut items: Vec<serde_json::Value> = serde_json::from_slice(RECORDED_RUN_LIST).unwrap();
    items.retain(|item| item["number"].as_u64().unwrap() >= 6);
    items.sort_by_key(|item| std::cmp::Reverse(item["number"].as_u64().unwrap()));
    let cut = serde_json::to_vec(&items).unwrap();
    let provider = recorded_provider()
        .with_runs(&cut)
        .with_listing_bound(u64::try_from(items.len()).unwrap());

    // The request still asks for the whole history.
    let request = recorded_request(repository_id());
    assert_eq!(request.first_run_number, RECORDED_FIRST_RUN);
    let scan = scan_runs(&provider, &request, &fetched_at()).expect("the reached part is readable");
    assert_eq!(
        scan.window.first_run_number, 6,
        "the window may only claim the range the provider's answer reached"
    );
    assert_eq!(
        scan.narrowed_from_first_run_number,
        Some(RECORDED_FIRST_RUN)
    );
    assert_eq!(scan.admitted_run_count(), 3);

    // Drain it: three runs plus one window observation.
    let mut log = CiWindowObservationLogV1::new(ContractId::new(CONNECTOR_INSTANCE).unwrap());
    let facts = ci_scan_facts(&scan, &mut log, 16).expect("the scan must become a fact batch");
    let received_at = canonical_time(server_time(&pool).await);
    let context = CiDrainContextV1 {
        binding: &binding,
        active: &memory.active,
        witness: &memory.witness,
        ledger: memory.ledger.as_ref(),
        control_scope: &memory.trusted_scope,
        kek: &content_key(),
        clocks: &clocks(received_at),
    };
    let report = drain_ci_facts(&context, &facts)
        .await
        .expect("the reached runs are admissible");
    assert_eq!(report.appended, 4);
    assert_eq!(report.quarantined, 0);

    // The DURABLE window states the narrowed range, not the requested one.
    let windows = CockroachCiMeasuredWindowRepository::new(
        pool.clone(),
        memory.physical_scope.tenant_id,
        memory.physical_scope.project.clone(),
    );
    let row = CiMeasuredWindowRowV1 {
        connector_instance: ContractId::new(CONNECTOR_INSTANCE).unwrap(),
        window: scan.window.clone(),
        window_id: scan.window.window_id().unwrap(),
        admitted_run_count: scan.admitted_run_count(),
        failed_run_count: scan.failed_run_count(),
        source_digest: ci_scan_manifest_digest(&report.admitted_keys),
        evidence_id: report.window_observation_event.unwrap(),
    };
    windows
        .record_window(&row)
        .await
        .expect("the measured window must be recordable");
    let recorded = windows
        .measured_windows(&ContractId::new(CONNECTOR_INSTANCE).unwrap())
        .await
        .expect("the measured window must be readable");
    assert_eq!(recorded.len(), 1);
    let measured = &recorded[0].window;
    assert_eq!(
        measured.first_run_number, 6,
        "durable state must not claim a range the provider never showed"
    );
    assert!(
        !measured.starts_at_origin(),
        "a cut-off window cannot support the origin question"
    );

    // And the operator's question, asked against that durable window, is
    // UNKNOWN — never a negative and never a false first.
    let answer = answer_first_failure(
        measured,
        &scan.runs,
        CiFailureQuestionV1::since_the_beginning(RECORDED_LAST_RUN),
    )
    .expect("the question must resolve");
    assert!(
        matches!(
            answer,
            CiFirstFailureAnswerV1::Unknown {
                reason: CiUnknownReasonV1::QuestionStartsBeforeWindow,
                ..
            }
        ),
        "a question below the measured window must be UNKNOWN: {answer:?}"
    );
    assert!(!answer.is_verified_negative());
    assert_ne!(
        RECORDED_FIRST_FAILING_RUN, 8,
        "run 5 is the real first failure, and it is below the cut"
    );
}
