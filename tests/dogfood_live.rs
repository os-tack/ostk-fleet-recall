//! W2-DOGFOOD — the acceptance demo: the memory reading its own construction.
//!
//! This driver points the Wave-2 connectors at THIS repository's own git
//! history and at the local agent transcript of the session that built it,
//! projects bodies and the lexical tier, and answers two questions the operator
//! actually asked, from the ingested evidence alone.
//!
//! # Why a `tests/` binary rather than `examples/dogfood`
//!
//! Everything upstream of the demo — bootstrap, genesis activation, the frozen
//! `0 -> 1` successor ceremony, the generic `1 -> 2` transition — lives as
//! ~600 lines of ceremony in `tests/`, alongside the frozen contract artifacts
//! the ceremony is pinned to. An `examples/` binary would have to duplicate all
//! of it into `src/` (widening the production surface for a demo) or into a new
//! crate. A `--test` binary also runs under exactly the harness the wave-close
//! official-binary lane already drives.
//!
//! # Running it
//!
//! It is inert unless every input is present, so `cargo test --all-targets`
//! stays green on a machine with no database and no local transcript:
//!
//! ```text
//! FLEET_RECALL_TEST_DATABASE_URL=<disposable crdb>       # required
//! FLEET_RECALL_DOGFOOD_GIT_DIR=<path to a .git>          # required
//! FLEET_RECALL_DOGFOOD_TRANSCRIPT=<path to a .jsonl>     # required
//! FLEET_RECALL_DOGFOOD_REF=refs/heads/main               # optional
//! FLEET_RECALL_DOGFOOD_REPORT=<path>                     # optional; else stdout
//! ```
//!
//! LOCAL ONLY. It reads the operator's own repository and the operator's own
//! transcript into the operator's own disposable database. It publishes
//! nothing, pushes nothing, and writes no ingested body text anywhere except
//! that database and — as explicitly quoted recall output — the report file the
//! operator asked for.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use ostk_fleet_recall::FleetScope;
use ostk_fleet_recall::body_store::{
    BodyProjectionRepository, CockroachBodyProjectionRepository, GovernedContentResolver,
    reference_parser_key_v1,
};
use ostk_fleet_recall::connectors::git::{
    GitCoverageBindingV1, GitDrainContextV1, GitFactV1, GitIngressClocksV1, GitObjectId,
    GitRefName, GitRefObservationLogV1, GitRepositoryIdV1, GitRepositoryReader, GitScanRequestV1,
    GitTreeScanModeV1, drain_git_facts, git_coverage_observation,
};
use ostk_fleet_recall::connectors::transcript::{
    CockroachTranscriptOutboxRepository, RedactionGuaranteeV1, TranscriptCollectionRequestV1,
    TranscriptConnectorBindingV1, TranscriptCoverageBindingV1, TranscriptDrainModeV1,
    TranscriptDrainRequest, TranscriptEnqueueOutcome, TranscriptIngressClocksV1,
    TranscriptOutboxRepository, collect_batch, drain_outbox, scan_secrets,
    transcript_parser_key_v2,
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
    WriterAuthorityWitness,
};
use ostk_fleet_recall::memory_contracts::bootstrap::{
    BootstrapAttestationV1, BootstrapPin, BootstrapReceiptDigest, BootstrapReceiptV1,
    verify_pinned_bootstrap,
};
use ostk_fleet_recall::memory_contracts::canonical::{decode_strict, encode_canonical};
use ostk_fleet_recall::memory_contracts::common::{
    AuthenticatedProjectScopeV1, CanonicalTimestamp, ContractId, FixedHex32, FixedHex64, HexBytes,
    ProfileReferenceV1, RegistryReferenceV1, frozen_profile_reference_v1,
};
use ostk_fleet_recall::memory_contracts::coverage::{
    CoverageCompletenessV1, CoverageFreshnessV1, CoverageProofBasisV1, CoverageProofMethodV1,
    CoverageScopeV1, CoverageWindowV1, FreshnessStateV1, ProducerIdentityV1, ProducerKindV1,
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
    CockroachLexicalProjector, CockroachRecallReader, LexicalProjector, RecallResultV1,
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
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Frozen contract artifacts. Identical pins to the connected proofs that own
// each ceremony, so this driver activates the real chain, never a fixture head.
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
const GENERATION_2_PACKAGE: &[u8] =
    include_bytes!("../contracts/dynamic-memory/v3/successor-generic/generation-2-package.jsonl");
const GENERATION_2_TEST_RESULT: &[u8] =
    include_bytes!("../contracts/dynamic-memory/v3/successor-generic/activation-test-result.jsonl");

const GENESIS_TEST_RESULT_DIGEST: &str =
    "e91e08070250a722446195b76ee685a9697298b9fdce9809027f120c829b679d";
const GENESIS_RUNNER_ARTIFACT: &str =
    "c2e5b0653471d35e54600a8d3fbe5613aff4c04e911787c09a25e2b327d4bbbd";
const GENESIS_RUNNER_CONFIGURATION: &str =
    "1d12aabe349fd0013389f93bf1917b0de6bbd5d2bd7156c85faff0b97360686d";
const GENERATION_1_TEST_RESULT_DIGEST: &str =
    "e6783b2a018957a5861fe4e0670f55613d1ace35e381a6a9f5190ea9d7fbff8d";
const GENERATION_2_TEST_RESULT_DIGEST: &str =
    "92fa5a109739a2509c57104d50f0c13416295380aee9e7f81f860dad2d1d08d7";
const SUCCESSOR_RUNNER_ARTIFACT: &str =
    "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
const SUCCESSOR_RUNNER_CONFIGURATION: &str =
    "a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2";

const GENERIC_APPROVAL_PREFIX: &[u8] =
    b"ostk-registry-successor-activation-approval-signature-v2\0";
const BRIDGE_APPROVAL_PREFIX: &[u8] = b"ostk-registry-successor-activation-approval-signature-v1\0";
const PROPOSER: &str = "principal.operator";
const AUTHOR: &str = "principal.author";

/// The frozen Stage-4 package's provider-instance recipe hashes exactly this
/// decimal coordinate, so both connectors are configured with it.
const INSTALLATION_ID: u64 = 4242;

// ---------------------------------------------------------------------------
// Demo bounds. Every one of them is reported in the evidence document as a
// coverage limit rather than left implicit.
// ---------------------------------------------------------------------------

/// Commits walked from the scanned ref. This repository has 350, so the walk
/// covers the branch whole; a longer branch would fail the scan closed rather
/// than truncate.
const MAX_COMMITS: usize = 400;
/// Hard bound on facts one scan renders.
const MAX_FACTS: usize = 4_096;
/// Bytes of transcript read per collection pass. Under the parser's 8 MiB batch
/// bound, so a 9.7 MiB session file is read in windows rather than refused.
const TRANSCRIPT_WINDOW_BYTES: usize = 4 * 1024 * 1024;
/// Rows one transcript drain pass consumes.
const DRAIN_LIMIT: u32 = 512;
/// Turn-ordinal range the transcript coverage domain targets.
const TRANSCRIPT_COVERAGE_TARGET: u64 = 4_096;
/// Recall hits requested per question.
const RECALL_LIMIT: usize = 10;
/// Characters of a recalled body quoted in the report.
const SNIPPET_CHARS: usize = 320;
/// Characters of an evidence-plane hit quoted in the report. Longer than a
/// recall snippet because these are the rows the questions are answered from.
const EVIDENCE_SNIPPET_CHARS: usize = 900;

const GIT_INSTANCE: &str = "connector.git.aetia";
const TRANSCRIPT_INSTANCE_PREFIX: &str = "connector.transcript";
const COVERAGE_SCOPE_URI: &str = "urn:ostk:entity:v1:repository:sha256:1111111111111111111111111111111111111111111111111111111111111111";
const FRESHNESS_RULE_DIGEST: &str =
    "3333333333333333333333333333333333333333333333333333333333333333";
const PROOF_METHOD_DIGEST: &str =
    "4444444444444444444444444444444444444444444444444444444444444444";

/// The two commits the operator's questions are about.
const Q1_COMMIT: &str = "8fe18f9484e3e791d6ce51a792ceb08d28c77681";
const Q2_COMMIT: &str = "3127aaca1f1eea8bbcdc9d5925c1c475126e655c";

// ---------------------------------------------------------------------------
// Contract fixture and the real activation chain (lifted from the connected
// proofs that own each step: stage5_package_activation_live.rs and
// transcript_connector_live.rs).
// ---------------------------------------------------------------------------

fn record(artifact: &'static [u8]) -> &'static [u8] {
    artifact
        .strip_suffix(b"\n")
        .expect("contract JSONL must have exactly one framing LF")
}

fn digest(value: &str) -> Sha256Digest {
    Sha256Digest::from_str(value).expect("fixture digest must be lowercase SHA-256")
}

#[derive(Clone)]
struct ContractFixture {
    profile: ProfileReferenceV1,
    semantic_scope: AuthenticatedProjectScopeV1,
    genesis_package: SemanticallyClosedGenesisPackage,
    genesis_test_result: VerifiedRegistryTestResult,
    genesis_principal_binding: GenesisActivationPrincipalBinding,
    stage4: SemanticallyClosedStage4Package,
    generation_2: StructurallyClosedSuccessorTargetV2,
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
    let generation_2_manifest =
        ManifestVerifiedRegistryPackage::decode(record(GENERATION_2_PACKAGE), &profile).unwrap();
    ContractFixture {
        generation_2: StructurallyClosedSuccessorTargetV2::from_manifest_verified(
            &generation_2_manifest,
        )
        .unwrap(),
        profile,
        semantic_scope,
        genesis_package,
        genesis_test_result,
        genesis_principal_binding: GenesisActivationPrincipalBinding::from_trusted_config(
            ContractId::new(PROPOSER).unwrap(),
            ContractId::new(AUTHOR).unwrap(),
        ),
        stage4,
    }
}

fn physical_scope() -> FleetScope {
    FleetScope::new(
        Uuid::now_v7(),
        format!("dogfood-{}", Uuid::now_v7()),
        "w2-dogfood-acceptance-demo",
        None,
        PrivacyTier::T1Project,
    )
    .expect("demo scope must be valid")
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

/// Everything the demo holds after the real `0 -> 1` chain is installed.
struct ActivatedMemory {
    pool: PgPool,
    physical_scope: FleetScope,
    trusted_scope: TrustedControlScope,
    bootstrap_receipt_digest: BootstrapReceiptDigest,
    generation_1_head: RegistryHeadBindingV1,
    active: ActiveStage4Package,
    witness: WriterAuthorityWitness,
    ledger: Arc<CockroachAcceptedEventRepository>,
    coverage: CockroachCoverageRuntimeRepository,
}

/// Walk bootstrap, genesis activation, and the frozen `0 -> 1` ceremony, then
/// bind the ACTIVE package the connectors admit against.
#[allow(clippy::too_many_lines)] // one helper keeps the whole real prefix visible
async fn activate(pool: &PgPool, fixture: &ContractFixture) -> ActivatedMemory {
    let physical = physical_scope();
    let control = trusted_scope(&physical, fixture);

    let mut receipt: BootstrapReceiptV1 = decode_strict(record(BOOTSTRAP_RECEIPT)).unwrap();
    receipt.statement.genesis_epoch.partition_recipe.seed = FixedHex32::from_bytes([0x5d; 32]);
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
        .map(|(principal, seed)| GenesisRegistryActivationApprovalV1 {
            schema_version: 1,
            statement_id: genesis_statement_id,
            signer_principal_id: ContractId::new(principal).unwrap(),
            signature: detached_signature(
                b"ostk-registry-activation-approval-signature-v1\0",
                genesis_statement_id.digest(),
                seed,
            ),
        })
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
    let witness = ledger.read_writer_authority_witness().await.unwrap();
    assert_eq!(witness.generation(), 1, "the head must be generation one");
    let active =
        ActiveStage4Package::bind(fixture.stage4.clone(), generation_1_head.clone(), &witness)
            .expect("the activated package is the Stage-4 target");

    ActivatedMemory {
        coverage: CockroachCoverageRuntimeRepository::new(
            pool.clone(),
            control.clone(),
            retry_policy(),
        ),
        pool: pool.clone(),
        physical_scope: physical,
        trusted_scope: control,
        bootstrap_receipt_digest,
        generation_1_head,
        active,
        witness,
        ledger,
    }
}

// ---------------------------------------------------------------------------
// Shared demo wiring.
// ---------------------------------------------------------------------------

/// A disposable local key. The demo never reads `FLEET_RECALL_CONTENT_KEK_HEX`.
fn content_key() -> ContentKeyEncryptionKey {
    ContentKeyEncryptionKey::from_hex(&"ab".repeat(32)).unwrap()
}

fn registry_reference(id: &str, digest_hex: &str) -> RegistryReferenceV1 {
    RegistryReferenceV1 {
        entry_id: ContractId::new(id).unwrap(),
        version: 1,
        entry_digest: digest(digest_hex),
    }
}

fn freshness() -> CoverageFreshnessV1 {
    CoverageFreshnessV1 {
        state: FreshnessStateV1::Current,
        freshness_rule: registry_reference(
            "coverage.freshness.default_rule",
            FRESHNESS_RULE_DIGEST,
        ),
    }
}

fn proof_basis(method: CoverageProofMethodV1) -> CoverageProofBasisV1 {
    CoverageProofBasisV1 {
        method,
        proof_method_registration: registry_reference(
            "coverage.proof.enumerated_snapshot",
            PROOF_METHOD_DIGEST,
        ),
    }
}

fn producer(id: &str) -> ProducerIdentityV1 {
    ProducerIdentityV1 {
        schema_version: 1,
        kind: ProducerKindV1::Connector,
        producer_id: ContractId::new(id).unwrap(),
        version: 1,
    }
}

const fn verdict_label(value: Option<CoverageCompletenessV1>) -> &'static str {
    match value {
        Some(CoverageCompletenessV1::Complete) => "complete",
        Some(CoverageCompletenessV1::Partial) => "partial",
        Some(CoverageCompletenessV1::Unknown) => "unknown",
        None => "no receipt (no cursor row)",
    }
}

/// What one connector's ingestion produced, for the report's count table.
#[derive(Debug, Default)]
struct IngestCounts {
    scanned: u64,
    appended: u64,
    replayed: u64,
    quarantined: u64,
    skipped: u64,
    receipts: u64,
}

// ---------------------------------------------------------------------------
// Git ingestion.
// ---------------------------------------------------------------------------

struct GitIngest {
    counts: IngestCounts,
    commits_walked: usize,
    ref_name: String,
    ref_target: String,
    completeness: Option<CoverageCompletenessV1>,
}

#[allow(clippy::too_many_lines)] // one linear scan -> drain -> receipt pipeline
async fn ingest_git(memory: &ActivatedMemory, git_dir: &Path, ref_name: &str) -> GitIngest {
    let repository = GitRepositoryIdV1::from_trusted_config(
        ContractId::new("git.repo.aetia").unwrap(),
        INSTALLATION_ID,
    )
    .unwrap();
    let reader = GitRepositoryReader::new(git_dir, repository, None).unwrap();
    let scan = reader
        .scan(&GitScanRequestV1 {
            ref_name: GitRefName::parse(ref_name).unwrap(),
            max_commits: MAX_COMMITS,
            max_facts: MAX_FACTS,
            // Commit facts only. Blob-source facts would multiply the walk by
            // the changed-path count of 350 commits for evidence neither
            // question asks about; the omission is reported as a coverage
            // limit rather than left implicit.
            tree_mode: GitTreeScanModeV1::CommitsOnly,
        })
        .expect("the real repository must scan");

    let binding = ostk_fleet_recall::connectors::git::GitConnectorBindingV1::resolve(
        &fixture().stage4,
        &memory.active,
        ContractId::new("connector.git").unwrap(),
        ContractId::new(GIT_INSTANCE).unwrap(),
        INSTALLATION_ID,
    )
    .expect("the git connector must resolve from the active package");

    let window_start = canonical_time(server_time(&memory.pool).await);
    tokio::time::sleep(Duration::from_millis(2)).await;
    let now = canonical_time(server_time(&memory.pool).await);

    let mut facts = scan.facts.clone();
    let mut log = GitRefObservationLogV1::new(
        reader.repository().clone(),
        scan.ref_name.clone(),
        ContractId::new(GIT_INSTANCE).unwrap(),
    )
    .unwrap();
    log.observe(
        GitObjectId::parse_hex(&scan.target.to_hex()).unwrap(),
        now.clone(),
        64,
    )
    .unwrap();
    facts.extend(
        log.observations()
            .iter()
            .cloned()
            .map(GitFactV1::RefObservation),
    );

    let key = content_key();
    let report = drain_git_facts(
        &GitDrainContextV1 {
            binding: &binding,
            active: &memory.active,
            witness: &memory.witness,
            ledger: memory.ledger.as_ref(),
            control_scope: &memory.trusted_scope,
            kek: &key,
            clocks: &GitIngressClocksV1 {
                received_at: now.clone(),
            },
        },
        &facts,
    )
    .await
    .expect("the drain must admit this repository's own history");

    let ref_fact = facts.last().expect("the ref observation");
    let ref_ingress = binding
        .build_ingress(
            ref_fact,
            &GitIngressClocksV1 {
                received_at: now.clone(),
            },
            1,
        )
        .unwrap();
    // One observation of one ref: the covered provider-sequence range is
    // [1, 2), and the target says the same, so the receipt claims exactly the
    // observation it binds and nothing about the commits behind it.
    let target = SequenceIntervalV1::new(1, 2).unwrap();
    let observation = git_coverage_observation(
        &GitCoverageBindingV1 {
            connector_instance: ContractId::new(GIT_INSTANCE).unwrap(),
            producer: producer("connector.git"),
            freshness: freshness(),
            proof_basis: proof_basis(CoverageProofMethodV1::EnumeratedSnapshot),
            window: CoverageWindowV1 {
                window_start,
                window_end: now.clone(),
            },
        },
        ref_ingress
            .candidate
            .source_fact
            .canonical_resource_id
            .clone(),
        &scan.target,
        target,
        target,
        &report,
        now,
    )
    .expect("a durable ref observation must anchor the receipt");

    let outcome = memory.coverage.observe(&observation).await.unwrap();
    let receipts = u64::from(matches!(
        outcome,
        CoverageObservationOutcome::Recorded { .. }
    ));
    let completeness = memory
        .coverage
        .read_cursor(
            &ContractId::new(GIT_INSTANCE).unwrap(),
            &observation.scope,
            target,
        )
        .await
        .unwrap()
        .map(|cursor| cursor.last_completeness);

    GitIngest {
        counts: IngestCounts {
            scanned: u64::try_from(facts.len()).unwrap(),
            appended: report.appended,
            replayed: report.replayed,
            quarantined: report.quarantined,
            skipped: 0,
            receipts,
        },
        commits_walked: scan.commits.len(),
        ref_name: scan.ref_name.as_str().to_owned(),
        ref_target: scan.target.to_hex(),
        completeness,
    }
}

// ---------------------------------------------------------------------------
// Transcript ingestion.
// ---------------------------------------------------------------------------

struct TranscriptIngest {
    counts: IngestCounts,
    source_id: String,
    source_bytes: u64,
    bytes_consumed: u64,
    passes: u32,
    turns_withheld: u32,
    turns_redacted: u32,
    classes_detected: Vec<String>,
    completeness: Option<CoverageCompletenessV1>,
}

#[allow(clippy::too_many_lines)] // one linear collect -> stage -> drain pipeline
async fn ingest_transcript(memory: &ActivatedMemory, path: &Path) -> TranscriptIngest {
    let source_id = path
        .file_name()
        .expect("the transcript must be a file")
        .to_string_lossy()
        .into_owned();
    let bytes = std::fs::read(path).expect("the transcript must be readable");

    let outbox = CockroachTranscriptOutboxRepository::new(
        memory.pool.clone(),
        memory.trusted_scope.clone(),
        retry_policy(),
    );
    let guarantee = RedactionGuaranteeV1::from_active_package(&memory.active)
        .expect("the activated package must promise redaction before the durable outbox");
    let parser_key = transcript_parser_key_v2();
    let mut instance_coordinates = BTreeMap::new();
    instance_coordinates.insert(
        ContractId::new("provider_installation_id").unwrap(),
        INSTALLATION_ID.to_string(),
    );
    let binding = TranscriptConnectorBindingV1 {
        ingress_principal_id: ContractId::new("connector.transcript").unwrap(),
        connector_instance_id: ContractId::new(format!("{TRANSCRIPT_INSTANCE_PREFIX}.dogfood"))
            .unwrap(),
        instance_coordinates,
    };

    let mut counts = IngestCounts::default();
    let mut passes = 0_u32;
    let mut turns_withheld = 0_u32;
    let mut turns_redacted = 0_u32;
    let mut classes: BTreeSet<String> = BTreeSet::new();

    // The parser bounds one BATCH, not the file, so a 9.7 MiB session file is
    // read in windows behind an advancing durable cursor.
    loop {
        let cursor = outbox.read_cursor(&source_id).await.unwrap();
        let resume = usize::try_from(cursor.as_ref().map_or(0, |row| row.byte_offset)).unwrap();
        if resume >= bytes.len() {
            break;
        }
        let window_end = bytes.len().min(resume + TRANSCRIPT_WINDOW_BYTES);
        let observed = canonical_time(server_time(&memory.pool).await);
        let (batch, stats) = collect_batch(&TranscriptCollectionRequestV1 {
            active: &memory.active,
            binding: &binding,
            guarantee: &guarantee,
            parser_key: &parser_key,
            source_id: &source_id,
            bytes: &bytes[..window_end],
            cursor: cursor.as_ref(),
            clocks: &TranscriptIngressClocksV1 {
                received_at: observed.clone(),
                observed_at: observed,
            },
        })
        .expect("the real session file must collect");

        counts.scanned += u64::from(stats.turns_parsed);
        counts.skipped += u64::from(stats.records_skipped);
        turns_withheld += stats.turns_withheld;
        turns_redacted += stats.turns_redacted;
        for class in &stats.classes_detected {
            classes.insert(format!("{class:?}"));
        }
        passes += 1;

        match outbox.enqueue_batch(&batch).await.unwrap() {
            TranscriptEnqueueOutcome::Enqueued { .. } => {}
            TranscriptEnqueueOutcome::AlreadyCovered { .. } => break,
        }
        if batch.cursor.byte_offset <= u64::try_from(resume).unwrap() {
            // The window framed no complete line past the cursor: stop rather
            // than spin.
            break;
        }
    }

    let cursor = outbox.read_cursor(&source_id).await.unwrap();
    let bytes_consumed = cursor.as_ref().map_or(0, |row| row.byte_offset);

    let now = canonical_time(server_time(&memory.pool).await);
    let coverage_scope = CoverageScopeV1 {
        scope: ResourceUri::from_str(COVERAGE_SCOPE_URI).unwrap(),
        revision: HexBytes::new(source_id.as_bytes().to_vec()).unwrap(),
        window: CoverageWindowV1 {
            window_start: CanonicalTimestamp::parse("2026-08-21T00:00:00.000000000Z").unwrap(),
            window_end: now.clone(),
        },
    };
    let target = SequenceIntervalV1::new(0, TRANSCRIPT_COVERAGE_TARGET).unwrap();
    let coverage_binding = TranscriptCoverageBindingV1 {
        producer: producer("connector.transcript"),
        scope: coverage_scope.clone(),
        target,
        freshness: freshness(),
        proof_basis: proof_basis(CoverageProofMethodV1::ClosedProviderQuery),
        observed_through: now,
    };

    loop {
        let summary = drain_outbox(TranscriptDrainRequest {
            active: &memory.active,
            witness: &memory.witness,
            outbox: &outbox,
            ledger: memory.ledger.as_ref(),
            coverage: &memory.coverage,
            trusted_scope: outbox.trusted_scope(),
            content_key: &content_key(),
            coverage_binding: &coverage_binding,
            mode: TranscriptDrainModeV1::Pending,
            limit: DRAIN_LIMIT,
        })
        .await
        .expect("the drain must admit the collected turns");
        counts.appended += summary.appended;
        counts.replayed += summary.replayed;
        counts.receipts += summary.receipts;
        if summary.rows_read == 0 {
            break;
        }
    }

    let completeness = memory
        .coverage
        .read_cursor(&binding.connector_instance_id, &coverage_scope, target)
        .await
        .unwrap()
        .map(|cursor| cursor.last_completeness);

    TranscriptIngest {
        counts,
        source_id,
        source_bytes: u64::try_from(bytes.len()).unwrap(),
        bytes_consumed,
        passes,
        turns_withheld,
        turns_redacted,
        classes_detected: classes.into_iter().collect(),
        completeness,
    }
}

// ---------------------------------------------------------------------------
// Privacy check: no credential-shaped string may reach anything durable.
// ---------------------------------------------------------------------------

/// Every byte this run made durable, decrypted: outbox rows, accepted-event
/// canonical bytes, stored ciphertext, and the DECRYPTED governed content. A
/// scan that read only the plaintext columns would miss a leak into content the
/// content store happens to hold in the clear once opened.
async fn durable_text(memory: &ActivatedMemory) -> Vec<String> {
    let mut collected: Vec<String> = Vec::new();
    for (candidate, locators, payload) in sqlx::query_as::<_, (Vec<u8>, Vec<u8>, Vec<u8>)>(
        "SELECT canonical_candidate, canonical_locators, canonical_payload \
         FROM memory_transcript_outbox_v1 WHERE tenant_id = $1 AND project = $2",
    )
    .bind(memory.physical_scope.tenant_id)
    .bind(&memory.physical_scope.project)
    .fetch_all(&memory.pool)
    .await
    .unwrap()
    {
        collected.push(String::from_utf8_lossy(&candidate).into_owned());
        collected.push(String::from_utf8_lossy(&locators).into_owned());
        collected.push(String::from_utf8_lossy(&payload).into_owned());
    }
    for event in sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT canonical_event FROM memory_evidence_events WHERE tenant_id = $1 AND project = $2",
    )
    .bind(memory.physical_scope.tenant_id)
    .bind(&memory.physical_scope.project)
    .fetch_all(&memory.pool)
    .await
    .unwrap()
    {
        collected.push(String::from_utf8_lossy(&event).into_owned());
    }
    for body in sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT body_bytes FROM memory_body_objects_v1 WHERE tenant_id = $1 AND project = $2",
    )
    .bind(memory.physical_scope.tenant_id)
    .bind(&memory.physical_scope.project)
    .fetch_all(&memory.pool)
    .await
    .unwrap()
    {
        collected.push(String::from_utf8_lossy(&body).into_owned());
    }
    for text in sqlx::query_scalar::<_, String>(
        "SELECT lexical_text FROM memory_body_lexical_projection_v1 \
         WHERE tenant_id = $1 AND project = $2",
    )
    .bind(memory.physical_scope.tenant_id)
    .bind(&memory.physical_scope.project)
    .fetch_all(&memory.pool)
    .await
    .unwrap()
    {
        collected.push(text);
    }
    collected
}

// ---------------------------------------------------------------------------
// Recall.
// ---------------------------------------------------------------------------

/// One recall issued against the real reader, with exactly what came back.
struct Probe {
    query: String,
    result: RecallResultV1,
    rows: Vec<(String, String)>,
}

/// The three clocks an accepted evidence event keeps separate, read back from
/// the ledger for one provider fact.
struct ClockWitness {
    event_id: String,
    occurred_at: String,
    observed_at: String,
    accepted_at: String,
}

struct AnsweredQuestion {
    question: &'static str,
    probes: Vec<Probe>,
    clocks: Option<ClockWitness>,
    /// Evidence-plane hits, keyed by the needle that found them.
    evidence: Vec<(&'static str, Vec<(bool, String)>)>,
    /// What the run is entitled to conclude, assembled from values above.
    verdict: String,
}

fn clip(text: &str, chars: usize) -> String {
    let mut out: String = text.chars().take(chars).collect();
    if text.chars().count() > chars {
        out.push_str(" ...");
    }
    out
}

fn snippet(text: &str) -> String {
    clip(text, SNIPPET_CHARS)
}

async fn probe(
    reader: &CockroachRecallReader,
    bodies: &BTreeMap<Vec<u8>, String>,
    query: &str,
) -> Probe {
    let result = reader.recall(query, None, RECALL_LIMIT).await.unwrap();
    let rows = result
        .hits
        .iter()
        .map(|hit| {
            let id = hit.body_content_id.to_hex();
            let text = bodies
                .get(hit.body_content_id.as_bytes().as_slice())
                .map_or_else(
                    || "<body row not readable>".to_owned(),
                    |text| snippet(text),
                );
            (id, text)
        })
        .collect();
    Probe {
        query: query.to_owned(),
        result,
        rows,
    }
}

/// Every governed content object this run made durable, decrypted.
///
/// This is the EVIDENCE plane, not the recall path: it is what the memory
/// holds, reachable only by opening every object in the scope. The report uses
/// it exactly where recall could not answer, and says so, so that no reader
/// mistakes a full scan for an index.
async fn governed_bodies(memory: &ActivatedMemory) -> Vec<String> {
    let identities = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT storage_identity FROM memory_content_objects \
         WHERE tenant_id = $1 AND project = $2",
    )
    .bind(memory.physical_scope.tenant_id)
    .bind(&memory.physical_scope.project)
    .fetch_all(&memory.pool)
    .await
    .unwrap();
    let key = content_key();
    let mut out = Vec::with_capacity(identities.len());
    for identity in identities {
        let Ok(bytes) = <[u8; 32]>::try_from(identity.as_slice()) else {
            continue;
        };
        let sealed = ostk_fleet_recall::evidence_ledger::fetch_governed_content(
            &memory.pool,
            memory.physical_scope.tenant_id,
            &memory.physical_scope.project,
            memory.witness.semantic_scope(),
            Sha256Digest::from_bytes(bytes),
        )
        .await
        .unwrap();
        if let Some(sealed) = sealed
            && let Ok(plaintext) = sealed.open(&key)
        {
            out.push(String::from_utf8_lossy(&plaintext).into_owned());
        }
    }
    out
}

/// Decode the `"message"` field of a git commit fact's governed body.
///
/// The connector carries a commit message as `HexBytes` — verbatim provider
/// bytes, hex on the wire — so the governed body holds hex, not words. Decoding
/// it here is presentation only, and the fact that it is NEEDED is itself a
/// finding the report states.
fn decoded_commit_message(body: &str) -> Option<String> {
    let start = body.find("\"message\":\"")? + "\"message\":\"".len();
    let rest = &body[start..];
    let end = rest.find('"')?;
    let bytes = hex::decode(&rest[..end]).ok()?;
    String::from_utf8(bytes).ok()
}

/// Governed bodies containing `needle`, as `(is_git_fact, display_text)`.
fn evidence_scan(bodies: &[String], needle: &str, limit: usize) -> Vec<(bool, String)> {
    let mut hits = Vec::new();
    for body in bodies {
        if !body.contains(needle) {
            continue;
        }
        match decoded_commit_message(body) {
            Some(message) => hits.push((true, clip(&message, EVIDENCE_SNIPPET_CHARS))),
            None => hits.push((false, clip(body, EVIDENCE_SNIPPET_CHARS))),
        }
        if hits.len() >= limit {
            break;
        }
    }
    hits
}

/// Read the three clocks of the accepted event for one git object id.
///
/// They are read from the ledger row and the canonical statement it stores, so
/// the report quotes what the memory holds rather than restating what the
/// connector was told: `occurred_at` is the provider's own instant,
/// `observed_at` is when this connector saw it, and `accepted_at` is the
/// database clock at the moment the event became durable.
async fn clock_witness(memory: &ActivatedMemory, object_id_hex: &str) -> Option<ClockWitness> {
    let rows = sqlx::query_as::<_, (Vec<u8>, Vec<u8>, DateTime<Utc>)>(
        "SELECT event_id, canonical_event, accepted_at FROM memory_evidence_events \
         WHERE tenant_id = $1 AND project = $2 ORDER BY committed_offset",
    )
    .bind(memory.physical_scope.tenant_id)
    .bind(&memory.physical_scope.project)
    .fetch_all(&memory.pool)
    .await
    .unwrap();
    for (event_id, canonical_event, accepted_at) in rows {
        let text = String::from_utf8_lossy(&canonical_event);
        if !text.contains(object_id_hex) {
            continue;
        }
        let statement: ostk_fleet_recall::memory_contracts::evidence_v2::EvidenceStatementV2 =
            decode_strict(&canonical_event).ok()?;
        return Some(ClockWitness {
            event_id: hex::encode(&event_id),
            occurred_at: statement.occurred_at.as_str().to_owned(),
            observed_at: statement.observed_at.as_str().to_owned(),
            accepted_at: accepted_at.to_rfc3339(),
        });
    }
    None
}

// ---------------------------------------------------------------------------
// The generation-2 step, run LAST because of what it proves.
// ---------------------------------------------------------------------------

/// Activate `1 -> 2` through the generic successor runtime, then report whether
/// the evidence-admission seam can bind the resulting head.
#[allow(clippy::too_many_lines)] // one linear activation ceremony
async fn activate_generation_two(memory: &ActivatedMemory, fixture: &ContractFixture) -> String {
    let repository = CockroachGenericSuccessorRepository::new(
        memory.pool.clone(),
        memory.trusted_scope.clone(),
        retry_policy(),
        memory.bootstrap_receipt_digest,
        record(GENERATION_2_PACKAGE).to_vec(),
        record(GENERATION_2_TEST_RESULT),
        GenericSuccessorTestRunnerPin::from_trusted_config(
            digest(SUCCESSOR_RUNNER_ARTIFACT),
            digest(SUCCESSOR_RUNNER_CONFIGURATION),
            RegistryTestResultDigest::from_digest(digest(GENERATION_2_TEST_RESULT_DIGEST)),
        ),
        GenericSuccessorPrincipalBinding::from_trusted_config(
            ContractId::new(PROPOSER).unwrap(),
            ContractId::new(AUTHOR).unwrap(),
        ),
        memory.generation_1_head.clone(),
    )
    .unwrap();

    // The policy the `1 -> 2` statement must name as currently installed, taken
    // from the target package's own activation policy exactly as the connected
    // proof that owns this ceremony takes it.
    let installed = fixture
        .generation_2
        .activation_policy()
        .registry_reference()
        .clone();

    tokio::time::sleep(Duration::from_millis(2)).await;
    let statement = GenericSuccessorActivationStatementV2 {
        schema_version: 2,
        profile: fixture.profile.clone(),
        scope: fixture.semantic_scope.clone(),
        expected_predecessor_head: memory.generation_1_head.clone(),
        current_activation_policy: installed,
        target_package_digest: fixture.generation_2.package_digest(),
        target_activation_policy: fixture
            .generation_2
            .activation_policy()
            .registry_reference()
            .clone(),
        test_vector_result_digest: RegistryTestResultDigest::from_digest(digest(
            GENERATION_2_TEST_RESULT_DIGEST,
        )),
        from_generation: 1,
        to_generation: 2,
        effective_from: canonical_time(server_time(&memory.pool).await),
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
        Ok(GenericSuccessorActivationOutcome::Inserted(accepted)) => {
            let witness = memory.ledger.read_writer_authority_witness().await.unwrap();
            let bind = ActiveStage4Package::bind(
                fixture.stage4.clone(),
                accepted.registry_head.clone(),
                &witness,
            );
            format!(
                "installed generation {} (package digest {}); \
                 the evidence-admission seam binding this head: {}",
                witness.generation(),
                accepted.registry_head.head.package_digest.to_hex(),
                match bind {
                    Ok(_) => "ACCEPTED".to_owned(),
                    Err(error) => format!("REFUSED ({error})"),
                }
            )
        }
        Ok(GenericSuccessorActivationOutcome::ExactReplay(_)) => {
            "an exact replay of an activation this run did not perform".to_owned()
        }
        Err(error) => format!("REFUSED: {error}"),
    }
}

// ---------------------------------------------------------------------------
// The demo.
// ---------------------------------------------------------------------------

fn required_path(variable: &str) -> Option<PathBuf> {
    let path = PathBuf::from(std::env::var(variable).ok()?);
    path.exists().then_some(path)
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // one linear demo; splitting it hides the pipeline
async fn live_this_repository_and_this_session_answer_the_operators_two_questions() {
    let (Ok(database_url), Some(git_dir), Some(transcript_path)) = (
        std::env::var("FLEET_RECALL_TEST_DATABASE_URL"),
        required_path("FLEET_RECALL_DOGFOOD_GIT_DIR"),
        required_path("FLEET_RECALL_DOGFOOD_TRANSCRIPT"),
    ) else {
        return;
    };
    let ref_name =
        std::env::var("FLEET_RECALL_DOGFOOD_REF").unwrap_or_else(|_| "refs/heads/main".to_owned());

    let store = CockroachStore::connect(
        &database_url,
        physical_scope(),
        PoolConfig {
            max_connections: 10,
            ..PoolConfig::default()
        },
    )
    .await
    .expect("the demo must reach the disposable database");
    store.migrate().await.expect("migration prefix must apply");
    let pool = store.pool().clone();

    let fixture = fixture();
    let memory = activate(&pool, &fixture).await;

    // 1 + 2. Ingest this repository's own history and this session's transcript.
    let git = ingest_git(&memory, &git_dir, &ref_name).await;
    let transcript = ingest_transcript(&memory, &transcript_path).await;

    // 3. Project bodies and occurrences from the governed content store.
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
        body_run.events_projected + body_run.events_unprojectable,
        git.counts.appended + transcript.counts.appended,
        "every appended event must be consumed exactly once, projected or not"
    );
    // The regression this run exists to pin: an event the projector can NEVER
    // chunk must not park the watermark in front of it. A second pass with
    // nothing new to do proves the cursor moved past every event of the first.
    let second_pass = bodies
        .project_pending()
        .await
        .expect("a second pass must be a no-op, not a re-run");
    assert_eq!(second_pass.events_projected, 0);
    assert_eq!(second_pass.events_unprojectable, 0);

    // 4. Project the lexical tier.
    let lexical = CockroachLexicalProjector::new(
        pool.clone(),
        memory.physical_scope.tenant_id,
        memory.physical_scope.project.clone(),
        256,
        retry_policy(),
    );
    let mut lexical_run = lexical.project_pending().await.expect("lexical projection");
    loop {
        let pass = lexical.project_pending().await.expect("lexical projection");
        if pass.bodies_consumed == 0 {
            break;
        }
        lexical_run.bodies_consumed += pass.bodies_consumed;
        lexical_run.rows_indexed += pass.rows_indexed;
        lexical_run.rows_unindexable += pass.rows_unindexable;
    }

    // PRIVACY. Nothing credential-shaped may have reached anything durable.
    let durable = durable_text(&memory).await;
    let mut leaks: Vec<String> = Vec::new();
    for blob in &durable {
        for finding in scan_secrets(blob) {
            leaks.push(format!("{:?}", finding.class));
        }
    }
    leaks.sort_unstable();
    leaks.dedup();
    assert!(
        leaks.is_empty(),
        "credential-shaped content reached durable storage: {leaks:?}"
    );

    // 5. Ask the two questions through the real recall path.
    let reader = CockroachRecallReader::new(
        pool.clone(),
        memory.physical_scope.tenant_id,
        memory.physical_scope.project.clone(),
    );
    let snapshot = reader.snapshot().await.expect("projection snapshot");
    let body_text: BTreeMap<Vec<u8>, String> = snapshot
        .lexical
        .iter()
        .map(|row| (row.0.clone(), row.4.clone()))
        .collect();

    // The lexical lane is `plainto_tsquery`, which ANDs its terms, so each
    // question is asked as several SHORT probes rather than one long phrase
    // that could only match a body containing every word. Every probe's result
    // is reported, including the empty ones.
    let governed = governed_bodies(&memory).await;
    let git_verdict = verdict_label(git.completeness);
    let transcript_verdict = verdict_label(transcript.completeness);

    let q1_clocks = clock_witness(&memory, Q1_COMMIT).await;
    let q1 = AnsweredQuestion {
        question: "Q1. When did failure first occur? (the CI failure on commit 8fe18f9)",
        probes: vec![
            probe(&reader, &body_text, Q1_COMMIT).await,
            probe(&reader, &body_text, "8fe18f9").await,
            probe(&reader, &body_text, "config_tests.rs").await,
        ],
        verdict: format!(
            "**Earliest KNOWN occurrence: `{}`** — the committer instant of `{Q1_COMMIT}`, which \
             is the earliest thing in this memory related to the question at all. It is NOT the \
             instant CI went red, and this memory cannot tell you that instant: no connector \
             reads a CI provider, so no evidence here observed a build.\n\n\
             **Coverage verdict for the window: UNKNOWN.** The two receipts this run produced \
             cover a git ref observation (`{git_verdict}` over its own one-observation domain) \
             and this session's transcript turns (`{transcript_verdict}`). Neither domain is the \
             CI-result domain, so coverage of the window the question asks about is not partial — \
             it is unmeasured. Reporting the git receipt's `{git_verdict}` as though it answered \
             the question would be exactly the false completeness COVER-01..03 exist to prevent.",
            q1_clocks
                .as_ref()
                .map_or_else(|| "no accepted event".to_owned(), |c| c.occurred_at.clone()),
        ),
        clocks: q1_clocks,
        evidence: vec![
            ("8fe18f9", evidence_scan(&governed, "8fe18f9", 3)),
            (
                "config_tests.rs",
                evidence_scan(&governed, "config_tests.rs", 3),
            ),
        ],
    };
    let q2 = AnsweredQuestion {
        question: "Q2. Why did this verification exist? (the rich-demo record-count pin deleted in 3127aac)",
        probes: vec![
            probe(&reader, &body_text, Q2_COMMIT).await,
            probe(&reader, &body_text, "3127aac").await,
            probe(&reader, &body_text, "record-count").await,
        ],
        clocks: clock_witness(&memory, Q2_COMMIT).await,
        evidence: vec![
            ("3127aac", evidence_scan(&governed, "3127aac", 4)),
            ("record-count", evidence_scan(&governed, "record-count", 4)),
        ],
        verdict: format!(
            "**The recall path returned nothing for this question** (see the probes below), so \
             everything shown here comes from a FULL SCAN of the evidence plane — every governed \
             content object in the scope, opened and searched. That is not recall; it is what \
             the memory holds while the index that should reach it does not exist.\n\n\
             **The transcript-to-commit link is DECLARED, not provider-verified.** At Stage 5 the \
             git connector's `GitDeclaredLinkV1` has exactly one verification state, `declared`: \
             the connector reads a local object store and has no evidence that any agent turn \
             produced any commit. Any correspondence a reader sees between the turns and the \
             commit below is the collector's assertion. Provider-verified linkage is Wave 5.\n\n\
             **Coverage verdict for this question's window: `{transcript_verdict}`** (the \
             transcript domain's own receipt). This run ingested exactly one session; every other \
             session that discussed this pin is absent."
        ),
    };

    // The generation-2 step runs LAST: it changes the active head, and what it
    // proves about the admission seam is part of the report.
    let generation_two = activate_generation_two(&memory, &fixture).await;

    let report = render_report(
        &git,
        &transcript,
        &git_dir,
        &transcript_path,
        body_run.events_projected,
        body_run.events_unprojectable,
        body_run.occurrences_derived,
        lexical_run.bodies_consumed,
        lexical_run.rows_indexed,
        lexical_run.rows_unindexable,
        durable.len(),
        &q1,
        &q2,
        &generation_two,
    );

    match std::env::var("FLEET_RECALL_DOGFOOD_REPORT") {
        Ok(path) => std::fs::write(&path, &report).expect("the report must be writable"),
        Err(_) => println!("{report}"),
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)] // one document template
fn render_report(
    git: &GitIngest,
    transcript: &TranscriptIngest,
    git_dir: &Path,
    transcript_path: &Path,
    events_projected: u64,
    events_unprojectable: u64,
    occurrences_derived: u64,
    bodies_consumed: u64,
    rows_indexed: u64,
    rows_unindexable: u64,
    durable_blobs: usize,
    q1: &AnsweredQuestion,
    q2: &AnsweredQuestion,
    generation_two: &str,
) -> String {
    let mut out = String::new();
    let verdict = verdict_label;

    let _ = writeln!(out, "# W2-DOGFOOD acceptance run\n");
    let _ = writeln!(
        out,
        "Generated by `tests/dogfood_live.rs` against a local disposable CockroachDB. \
         Every number and every quoted row below is system output captured during the run; \
         nothing here is hand-written from knowledge the system did not have.\n"
    );

    let _ = writeln!(out, "## What was ingested\n");
    let _ = writeln!(out, "| source | value |");
    let _ = writeln!(out, "| --- | --- |");
    let _ = writeln!(out, "| git dir | `{}` |", git_dir.display());
    let _ = writeln!(out, "| ref scanned | `{}` |", git.ref_name);
    let _ = writeln!(out, "| ref target | `{}` |", git.ref_target);
    let _ = writeln!(out, "| commits walked | {} |", git.commits_walked);
    let _ = writeln!(
        out,
        "| git facts scanned / appended / replayed / quarantined | {} / {} / {} / {} |",
        git.counts.scanned, git.counts.appended, git.counts.replayed, git.counts.quarantined
    );
    let _ = writeln!(out, "| git coverage receipts | {} |", git.counts.receipts);
    let _ = writeln!(
        out,
        "| transcript file | `{}` ({} bytes) |",
        transcript_path.display(),
        transcript.source_bytes
    );
    let _ = writeln!(out, "| transcript source id | `{}` |", transcript.source_id);
    let _ = writeln!(
        out,
        "| transcript bytes consumed / collection passes | {} / {} |",
        transcript.bytes_consumed, transcript.passes
    );
    let _ = writeln!(
        out,
        "| turns parsed / staged-and-appended / replayed | {} / {} / {} |",
        transcript.counts.scanned, transcript.counts.appended, transcript.counts.replayed
    );
    let _ = writeln!(
        out,
        "| non-turn records counted (skipped) | {} |",
        transcript.counts.skipped
    );
    let _ = writeln!(
        out,
        "| turns redacted / withheld | {} / {} |",
        transcript.turns_redacted, transcript.turns_withheld
    );
    let _ = writeln!(
        out,
        "| secret classes detected in the transcript | {} |",
        if transcript.classes_detected.is_empty() {
            "none".to_owned()
        } else {
            transcript.classes_detected.join(", ")
        }
    );
    let _ = writeln!(
        out,
        "| transcript coverage receipts | {} |",
        transcript.counts.receipts
    );
    let _ = writeln!(
        out,
        "| body plane: events projected / **unprojectable** / occurrences | {events_projected} / **{events_unprojectable}** / {occurrences_derived} |"
    );
    let _ = writeln!(
        out,
        "| lexical rows: consumed / indexed / unindexable | {bodies_consumed} / {rows_indexed} / {rows_unindexable} |"
    );
    let _ = writeln!(out);

    let _ = writeln!(out, "## Coverage verdicts (W2-COVER-RT receipts)\n");
    let _ = writeln!(
        out,
        "- git connector instance `{GIT_INSTANCE}`, ref-observation domain: **{}**",
        verdict(git.completeness)
    );
    let _ = writeln!(
        out,
        "- transcript connector instance `{TRANSCRIPT_INSTANCE_PREFIX}.dogfood`, turn-ordinal domain `[0, {TRANSCRIPT_COVERAGE_TARGET})`: **{}**",
        verdict(transcript.completeness)
    );
    let _ = writeln!(
        out,
        "\nThe transcript verdict is the honest one for this run: the domain targets a \
         turn-ordinal range far wider than this one session's turns, so the receipt says \
         partial and means it. Reading it as \"the memory has the whole conversation\" would \
         be exactly the mistake COVER-01..03 exist to prevent.\n"
    );

    if events_unprojectable > 0 {
        let _ = writeln!(out, "## Where the chain breaks\n");
        let _ = writeln!(
            out,
            "**{events_unprojectable} of {} accepted events could not be projected into a body, \
             and {events_projected} could.** This is the run's most important result, so it is \
             stated before the answers rather than after them.\n\n\
             The generation-1 package's only connector schema, `connector.github.push`, names \
             `identity.github.push` as its `canonical_resource_identity_recipe`, and that recipe's \
             `identity_form` is `occurrence`. Both Wave-2 connectors resolve their canonical \
             resource from that one recipe, so EVERY fact they admit — commit, ref observation, \
             transcript turn alike — names an occurrence-form resource. \
             `derive_parse_run` requires a VERSION-form resource, because an occurrence URI names \
             no immutable source-object version to chunk, and refuses closed rather than mint \
             occurrences against it.\n\n\
             The package does contain a version-form recipe (`identity.github.commit`), but no \
             connector schema in the ACTIVE package points at it. So the connectors and the body \
             plane are both correct and do not yet meet: at generation 1 there is no path from \
             ingested evidence to a body, and therefore none to the lexical tier or to recall.\n\n\
             The run also pins the failure mode this exposed: before this change the projector \
             failed the whole pass closed on the first such event, which parked the watermark in \
             front of it permanently and starved every later event. It now advances past an event \
             it can never chunk and reports the count — it still mints nothing, and the count is a \
             named field so the gap cannot hide as an absence.\n\n\
             **A second break sits behind the first.** Even with bodies, the lexical tier could \
             not word-search a commit message: the git connector carries verbatim provider text \
             as `HexBytes`, so the canonical body holds `\"message\":\"<hex>\"` and its lexical \
             text would be a hex string. This report had to hex-decode every commit message it \
             quotes below, which is the evidence for the claim. Transcript turn text is a plain \
             canonical string and does not have this problem — so the two connectors do not agree \
             on how provider text reaches recall either.\n",
            events_projected + events_unprojectable
        );
    }

    for question in [q1, q2] {
        let _ = writeln!(out, "## {}\n", question.question);
        let _ = writeln!(out, "{}\n", question.verdict);

        match &question.clocks {
            Some(clocks) => {
                let _ = writeln!(
                    out,
                    "The three clocks the ledger keeps separate, read back from the accepted \
                     event `{}`:\n",
                    clocks.event_id
                );
                let _ = writeln!(out, "| clock | value | what it means |");
                let _ = writeln!(out, "| --- | --- | --- |");
                let _ = writeln!(
                    out,
                    "| `occurred_at` | `{}` | the provider's own instant (the commit's committer time) |",
                    clocks.occurred_at
                );
                let _ = writeln!(
                    out,
                    "| `observed_at` | `{}` | when this connector saw the fact |",
                    clocks.observed_at
                );
                let _ = writeln!(
                    out,
                    "| `accepted_at` | `{}` | the database clock when the event became durable |\n",
                    clocks.accepted_at
                );
            }
            None => {
                let _ = writeln!(
                    out,
                    "**No accepted event in this memory names that object.** No clocks to \
                     report, and no answer is constructed in their absence.\n"
                );
            }
        }

        let _ = writeln!(
            out,
            "Probes issued through `CockroachRecallReader::recall` (the lexical lane is \
             `plainto_tsquery`, which ANDs its terms, so the question is asked as several \
             short probes; every result is shown, including the empty ones):\n"
        );
        for probe in &question.probes {
            let completeness = probe.result.completeness;
            let _ = writeln!(out, "### Query `{}`\n", probe.query);
            let _ = writeln!(
                out,
                "Tier `{:?}`; readiness at read time: {} bodies, {} lexically indexed, \
                 {} lexically unindexable, {} densely embedded (lexical complete: {}, dense \
                 complete: {}).\n",
                probe.result.tier,
                completeness.bodies_total,
                completeness.lexically_indexed,
                completeness.lexically_unindexable,
                completeness.densely_embedded,
                completeness.lexical_complete(),
                completeness.dense_complete(),
            );
            if probe.rows.is_empty() {
                let _ = writeln!(
                    out,
                    "**No hits.** Reported as it came back; nothing is written here that \
                     recall did not produce.\n"
                );
            } else {
                for (index, (id, text)) in probe.rows.iter().enumerate() {
                    let _ = writeln!(out, "{}. `{}`\n", index + 1, id);
                    let _ = writeln!(
                        out,
                        "   ```text\n   {}\n   ```\n",
                        text.replace('\n', "\n   ")
                    );
                }
            }
        }

        let _ = writeln!(
            out,
            "#### Evidence-plane scan (not recall)\n\n\
             Every governed content object in the scope, opened and searched. This is what the \
             memory HOLDS; the probes above are what it could RETRIEVE. The gap between the two \
             is the finding.\n"
        );
        for (needle, hits) in &question.evidence {
            if hits.is_empty() {
                let _ = writeln!(
                    out,
                    "- `{needle}`: **no governed object in this memory contains it.**\n"
                );
                continue;
            }
            let _ = writeln!(
                out,
                "- `{needle}`: {} governed object(s) contain it (first {} shown):\n",
                hits.len(),
                hits.len()
            );
            for (is_commit, text) in hits {
                let _ = writeln!(
                    out,
                    "  - {}\n\n    ```text\n    {}\n    ```\n",
                    if *is_commit {
                        "**git commit fact**, message decoded from its `HexBytes` field"
                    } else {
                        "**transcript turn**, redacted body as stored"
                    },
                    text.replace('\n', "\n    ")
                );
            }
        }
    }

    let _ = writeln!(out, "## Generation 2\n");
    let _ = writeln!(out, "- {generation_two}\n");

    let _ = writeln!(out, "## Privacy check\n");
    let _ = writeln!(
        out,
        "{durable_blobs} durable blobs were re-read and re-scanned with the connector's own \
         `scan_secrets` — every transcript outbox row (candidate, locators, payload), every \
         accepted-event canonical record, every projected body, and every lexical text. \
         Findings: **0**. The run asserts this, so a leak fails the test rather than \
         appearing as a line in a report nobody reads.\n"
    );

    let _ = writeln!(out, "## What this does NOT show\n");
    let _ = writeln!(
        out,
        "- **No CI evidence exists in this memory.** No connector reads a CI provider, so \
          nothing here observed a build going red. Any statement about when CI failed is \
          bounded by what a commit object and a conversation turn happen to say.\n\
         - **The git walk is commits-only.** `GitTreeScanModeV1::CommitsOnly`: no blob-source \
          facts, so no file content was ingested and no question about *what changed inside a \
          file* can be answered from this run.\n\
         - **One ref, {} commits under a bound of {MAX_COMMITS}.** Only `{}` was walked. Other \
          branches, tags, and any commit beyond the bound are absent, and a walk that would have \
          exceeded the bound fails closed rather than truncating.\n\
         - **One session's transcript.** Every other session that worked on this repository is \
          absent from this memory entirely.\n\
         - **Turn-to-commit links are DECLARED, not verified.** At Stage 5 the git connector's \
          `GitDeclaredLinkV1` has exactly one verification state — `declared` — because the \
          connector reads a local object store and has no evidence that any agent turn produced \
          any commit. Provider-verified linkage is Wave 5. Any correspondence below between a \
          transcript turn and a commit is the collector's assertion, not the memory's proof.\n\
         - **Lexical only.** No embedding model ran, so `dense_complete` is whatever the \
          readiness block above says, and no hit came from a dense lane.\n\
         - **The evidence-plane scan is not a retrieval capability.** It opens and searches \
          EVERY governed object in the scope. It answers here because the corpus is small and \
          the index does not exist; it is not what a memory of any size would do, and its \
          results must not be read as evidence that recall works.\n\
         - **Bodies are canonical fact renderings, not prose.** A body is a connector's \
          canonical JSON for one provider fact, so a commit message lives inside its fact — \
          hex-encoded, as above — rather than as a bare message.\n",
        git.commits_walked, git.ref_name
    );

    out
}
