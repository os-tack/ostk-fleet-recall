//! Connected proof for the git history connector (W2-GIT).
//!
//! Set the exact `FLEET_RECALL_TEST_DATABASE_URL` variable to a disposable
//! `CockroachDB` 26.2 database. Every test here is inert otherwise. Nothing in
//! this file starts a database process, invokes Docker, or targets a cloud
//! service.
//!
//! Each test builds its OWN scratch git repository with plumbing commands
//! (`hash-object`, `mktree`, `commit-tree`, `update-ref`, `tag`) under a
//! `tempfile::TempDir`, so the objects are deterministic and nothing depends on
//! the checkout this test runs from.
//!
//! The bootstrap -> genesis -> successor ceremony is copied from
//! `tests/evidence_admission_live.rs` so every drain below runs against a head
//! that is the Stage-4 package at generation one. What is new here is what the
//! git connector does against that head: a scratch repository's commits, blobs,
//! and refs become accepted events; a force push mints a NEW ref observation
//! and leaves the old one intact; a tag and a rename are covered; a re-scan is
//! an exact replay; and a candidate whose scope is not the witness's is
//! rejected closed before anything is written.

use std::io::Write as _;
use std::process::{Command, Stdio};
use std::str::FromStr as _;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use ostk_fleet_recall::FleetScope;
use ostk_fleet_recall::connectors::git::{
    GitConnectorBindingV1, GitCoverageBindingV1, GitDrainContextV1, GitFactV1, GitIngressClocksV1,
    GitObjectId, GitRefName, GitRefObservationLogV1, GitRepositoryIdV1, GitRepositoryReader,
    GitScanRequestV1, GitTreeScanModeV1, drain_git_facts, git_coverage_observation,
    git_resume_sequence,
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
    EvidenceAdmissionError, EvidenceAdmissionRequestV1, WriterAuthorityWitness, admit_evidence,
    fetch_governed_content,
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
use ostk_fleet_recall::memory_contracts::coverage::{
    CoverageFreshnessV1, CoverageProofBasisV1, CoverageProofMethodV1, CoverageWindowV1,
    FreshnessStateV1, ProducerIdentityV1, ProducerKindV1,
};
use ostk_fleet_recall::memory_contracts::digest::{
    DigestDomain, Sha256Digest, domain_separated_digest,
};
use ostk_fleet_recall::memory_contracts::evidence_v2::{
    IngressContentReferenceV1, RegistryHeadBindingV1, RepresentationLineageV2,
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

/// Fixed identity and clock for every scratch commit, so the objects a test
/// builds are byte-deterministic and a re-scan is a true replay.
const FIXED_NAME: &str = "Ada Lovelace";
const FIXED_EMAIL: &str = "ada@example.test";
const FIXED_DATE: &str = "1755259200 +0000";

/// The frozen Stage-4 package's provider-instance recipe hashes exactly this
/// decimal coordinate, so the connector is configured with it.
const INSTALLATION_ID: u64 = 4242;

/// Each `#[tokio::test]` gets its own runtime, and a `PgPool` is bound to the
/// runtime that created it, so pools are never shared across tests. The schema
/// is shared, so migration is serialized and run exactly once per process.
static MIGRATED: Mutex<bool> = Mutex::const_new(false);

// ---------------------------------------------------------------------------
// Scratch git repository, built entirely with plumbing.
// ---------------------------------------------------------------------------

/// One bare scratch repository plus its reader.
struct ScratchRepository {
    directory: tempfile::TempDir,
    repository: GitRepositoryIdV1,
}

impl ScratchRepository {
    fn init(label: &str) -> Self {
        let directory = tempfile::tempdir().expect("scratch repository directory");
        let status = Command::new("git")
            .args(["init", "--bare", "--quiet"])
            .arg(directory.path())
            .status()
            .expect("git must be on PATH for the git connector proof");
        assert!(status.success(), "git init --bare must succeed");
        let repository = GitRepositoryIdV1::from_trusted_config(
            ContractId::new(format!("git.repo.{label}")).expect("repository id"),
            INSTALLATION_ID,
        )
        .expect("repository identity");
        Self {
            directory,
            repository,
        }
    }

    fn reader(&self) -> GitRepositoryReader {
        GitRepositoryReader::new(self.directory.path(), self.repository.clone(), None)
            .expect("reader must bind")
    }

    fn git(&self, args: &[&str], stdin: Option<&[u8]>) -> String {
        let mut command = Command::new("git");
        command
            .arg(format!("--git-dir={}", self.directory.path().display()))
            .args(args)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_AUTHOR_NAME", FIXED_NAME)
            .env("GIT_AUTHOR_EMAIL", FIXED_EMAIL)
            .env("GIT_AUTHOR_DATE", FIXED_DATE)
            .env("GIT_COMMITTER_NAME", FIXED_NAME)
            .env("GIT_COMMITTER_EMAIL", FIXED_EMAIL)
            .env("GIT_COMMITTER_DATE", FIXED_DATE)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().expect("git must spawn");
        if let Some(bytes) = stdin {
            child
                .stdin
                .as_mut()
                .expect("piped stdin")
                .write_all(bytes)
                .expect("git stdin");
        }
        let output = child.wait_with_output().expect("git must finish");
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .expect("plumbing output is ASCII here")
            .trim()
            .to_owned()
    }

    fn blob(&self, content: &[u8]) -> String {
        self.git(&["hash-object", "-w", "--stdin"], Some(content))
    }

    /// Build a flat tree from `(path, blob oid)` pairs.
    fn tree(&self, entries: &[(&str, &str)]) -> String {
        let spec = entries.iter().fold(String::new(), |mut spec, (path, oid)| {
            use std::fmt::Write as _;
            let _ = writeln!(spec, "100644 blob {oid}\t{path}");
            spec
        });
        self.git(&["mktree"], Some(spec.as_bytes()))
    }

    fn commit(&self, tree: &str, parent: Option<&str>, message: &str) -> String {
        let mut args = vec!["commit-tree", tree, "-m", message];
        if let Some(parent) = parent {
            args.push("-p");
            args.push(parent);
        }
        self.git(&args, None)
    }

    fn update_ref(&self, name: &str, target: &str) {
        self.git(&["update-ref", name, target], None);
    }

    fn annotated_tag(&self, name: &str, target: &str, message: &str) {
        self.git(&["tag", "-a", "-m", message, name, target], None);
    }
}

/// One README-only history: root commit, then a commit that renames the file.
struct ScratchHistory {
    first_commit: String,
    renamed_commit: String,
}

fn build_history(repository: &ScratchRepository) -> ScratchHistory {
    let readme = repository.blob(b"hello evidence\n");
    let first_tree = repository.tree(&[("README.md", &readme)]);
    let first_commit = repository.commit(&first_tree, None, "root commit");
    // A rename: the same blob at a new path, which must be a DIFFERENT source
    // fact even though the content identity is unchanged.
    let renamed_tree = repository.tree(&[("DOCS.md", &readme)]);
    let renamed_commit = repository.commit(&renamed_tree, Some(&first_commit), "rename readme");
    repository.update_ref("refs/heads/main", &renamed_commit);
    ScratchHistory {
        first_commit,
        renamed_commit,
    }
}

// ---------------------------------------------------------------------------
// Live plumbing shared with the other connected proofs.
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
        format!("git-{label}-{}", Uuid::now_v7()),
        "git-connector-connected-test",
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

/// One live scope whose registry head is the Stage-4 package at generation one.
struct Stage4Scope {
    physical_scope: FleetScope,
    trusted_scope: TrustedControlScope,
    head: RegistryHeadBindingV1,
    repository: Arc<CockroachAcceptedEventRepository>,
    witness: WriterAuthorityWitness,
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

    let repository = Arc::new(CockroachAcceptedEventRepository::new(
        pool.clone(),
        trusted_scope.clone(),
        retry_policy(),
    ));
    let witness = repository.read_writer_authority_witness().await.unwrap();
    assert_eq!(witness.generation(), 1, "the head must be generation one");
    assert_eq!(
        witness.head().package_digest,
        fixture.target.package_digest(),
        "the activated package must be the Stage-4 target"
    );

    Stage4Scope {
        physical_scope,
        trusted_scope,
        head,
        repository,
        witness,
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
// Git-connector wiring on top of the activated head.
// ---------------------------------------------------------------------------

fn content_key() -> ContentKeyEncryptionKey {
    ContentKeyEncryptionKey::from_hex(&"ab".repeat(32)).unwrap()
}

fn active_package(fixture: &ContractFixture, scope: &Stage4Scope) -> ActiveStage4Package {
    ActiveStage4Package::bind(fixture.target.clone(), scope.head.clone(), &scope.witness).unwrap()
}

fn binding(fixture: &ContractFixture, scope: &Stage4Scope) -> GitConnectorBindingV1 {
    GitConnectorBindingV1::resolve(
        &fixture.target,
        &active_package(fixture, scope),
        ContractId::new("connector.git").unwrap(),
        ContractId::new("connector.git.instance-1").unwrap(),
        INSTALLATION_ID,
    )
    .expect("the git connector must resolve from the active package")
}

fn clocks(now: &CanonicalTimestamp) -> GitIngressClocksV1 {
    GitIngressClocksV1 {
        received_at: now.clone(),
    }
}

fn scan_request(ref_name: &str) -> GitScanRequestV1 {
    GitScanRequestV1 {
        ref_name: GitRefName::parse(ref_name).unwrap(),
        max_commits: 64,
        max_facts: 512,
        tree_mode: GitTreeScanModeV1::ChangedPaths,
    }
}

/// One observation of `ref_name` at `target`, minted through the append-only
/// observation log so the sequence and the previous target are the log's, not
/// the caller's.
fn observation_fact(
    repository: &GitRepositoryIdV1,
    ref_name: &GitRefName,
    targets: &[(&str, &CanonicalTimestamp)],
) -> Vec<GitFactV1> {
    let mut log = GitRefObservationLogV1::new(
        repository.clone(),
        ref_name.clone(),
        ContractId::new("connector.git.instance-1").unwrap(),
    )
    .unwrap();
    for (target, observed_at) in targets {
        log.observe(
            GitObjectId::parse_hex(target).unwrap(),
            (*observed_at).clone(),
            64,
        )
        .unwrap();
    }
    log.observations()
        .iter()
        .cloned()
        .map(GitFactV1::RefObservation)
        .collect()
}

fn coverage_binding(window: CoverageWindowV1) -> GitCoverageBindingV1 {
    GitCoverageBindingV1 {
        connector_instance: ContractId::new("connector.git.instance-1").unwrap(),
        producer: ProducerIdentityV1 {
            schema_version: 1,
            kind: ProducerKindV1::Connector,
            producer_id: ContractId::new("connector.git").unwrap(),
            version: 1,
        },
        freshness: CoverageFreshnessV1 {
            state: FreshnessStateV1::Current,
            freshness_rule: RegistryReferenceV1 {
                entry_id: ContractId::new("coverage.freshness.default-rule").unwrap(),
                version: 1,
                entry_digest: Sha256Digest::from_bytes([0x0c; 32]),
            },
        },
        proof_basis: CoverageProofBasisV1 {
            method: CoverageProofMethodV1::EnumeratedSnapshot,
            proof_method_registration: RegistryReferenceV1 {
                entry_id: ContractId::new("coverage.proof.enumerated-snapshot").unwrap(),
                version: 1,
                entry_digest: Sha256Digest::from_bytes([0x0d; 32]),
            },
        },
        window,
    }
}

// ---------------------------------------------------------------------------
// Connected tests.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn live_a_scratch_repository_flows_to_accepted_events_when_configured() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let fixture = fixture();
    let scope = activate_stage4(&pool, &fixture, "flow", 71).await;
    let active = active_package(&fixture, &scope);
    let binding = binding(&fixture, &scope);

    let repository = ScratchRepository::init("flow");
    let history = build_history(&repository);
    let reader = repository.reader();
    let scan = reader.scan(&scan_request("refs/heads/main")).unwrap();
    assert_eq!(scan.commits.len(), 2, "root plus rename");
    assert_eq!(
        scan.target.to_hex(),
        history.renamed_commit,
        "the ref observation names what the ref points at"
    );

    let now = canonical_time(server_time(&pool).await);
    let mut facts = scan.facts.clone();
    facts.extend(observation_fact(
        reader.repository(),
        &scan.ref_name,
        &[(&scan.target.to_hex(), &now)],
    ));

    let key = content_key();
    let context = GitDrainContextV1 {
        binding: &binding,
        active: &active,
        witness: &scope.witness,
        ledger: scope.repository.as_ref(),
        control_scope: &scope.trusted_scope,
        kek: &key,
        clocks: &clocks(&now),
    };
    let report = drain_git_facts(&context, &facts).await.unwrap();

    // Two commits, two blob-source facts (one per commit's changed path), one
    // ref observation.
    assert_eq!(report.appended, 5, "{report:?}");
    assert_eq!(report.replayed, 0);
    assert_eq!(report.quarantined, 0);
    assert!(report.ref_observation_event.is_some());
    assert_eq!(
        scoped_count(&pool, "memory_evidence_events", &scope.physical_scope).await,
        5
    );

    // The governed rendering of the first commit is durable and decrypts to the
    // exact canonical bytes the connector hashed.
    let commit_fact = facts
        .iter()
        .find(|fact| matches!(fact, GitFactV1::Commit(commit) if commit.commit_id.to_hex() == history.first_commit))
        .expect("the root commit fact");
    let ingress = binding
        .build_ingress(commit_fact, &clocks(&now), 1)
        .unwrap();
    let stored = fetch_governed_content(
        &pool,
        scope.physical_scope.tenant_id,
        &scope.physical_scope.project,
        scope.witness.semantic_scope(),
        ingress.candidate.canonical_payload.storage_identity,
    )
    .await
    .unwrap()
    .expect("the governed content object must be durable");
    assert_eq!(stored.open(&key).unwrap(), ingress.canonical_payload);
}

#[tokio::test]
async fn live_a_force_push_produces_a_new_observation_and_preserves_history_when_configured() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let fixture = fixture();
    let scope = activate_stage4(&pool, &fixture, "force", 72).await;
    let active = active_package(&fixture, &scope);
    let binding = binding(&fixture, &scope);

    let repository = ScratchRepository::init("force");
    let history = build_history(&repository);
    let reader = repository.reader();
    let ref_name = GitRefName::parse("refs/heads/main").unwrap();

    let first_seen = canonical_time(server_time(&pool).await);
    let key = content_key();
    let first_clocks = clocks(&first_seen);
    let first_context = GitDrainContextV1 {
        binding: &binding,
        active: &active,
        witness: &scope.witness,
        ledger: scope.repository.as_ref(),
        control_scope: &scope.trusted_scope,
        kek: &key,
        clocks: &first_clocks,
    };

    let first_batch = observation_fact(
        reader.repository(),
        &ref_name,
        &[(&history.renamed_commit, &first_seen)],
    );
    let first = drain_git_facts(&first_context, &first_batch).await.unwrap();
    assert_eq!(first.appended, 1);

    // The force push: the branch is moved back to the root commit.
    repository.update_ref("refs/heads/main", &history.first_commit);
    assert_eq!(
        reader.resolve_ref(&ref_name).unwrap().to_hex(),
        history.first_commit
    );

    tokio::time::sleep(Duration::from_millis(2)).await;
    let second_seen = canonical_time(server_time(&pool).await);
    let second_clocks = clocks(&second_seen);
    // The log replays the first observation and appends the second, so the
    // batch carries BOTH: the old one must come back as an exact replay and the
    // new one as a fresh append.
    let second_batch = observation_fact(
        reader.repository(),
        &ref_name,
        &[
            (&history.renamed_commit, &first_seen),
            (&history.first_commit, &second_seen),
        ],
    );
    let second_context = GitDrainContextV1 {
        clocks: &second_clocks,
        ..first_context
    };
    let second = drain_git_facts(&second_context, &second_batch)
        .await
        .unwrap();
    assert_eq!(
        second.replayed, 1,
        "the earlier observation is byte-identical, so it replays"
    );
    assert_eq!(second.appended, 1, "the force push is a NEW observation");
    assert_eq!(second.quarantined, 0, "nothing was rewritten");
    assert_eq!(
        second.events[0], first.events[0],
        "the old observation keeps its exact accepted-event identity"
    );
    assert_ne!(second.events[1], first.events[0]);
    assert_eq!(
        scoped_count(&pool, "memory_evidence_events", &scope.physical_scope).await,
        2,
        "two observations, no rewrite"
    );

    // The newest observation is the view, and it names its predecessor.
    let GitFactV1::RefObservation(newest) = &second_batch[1] else {
        panic!("the second batch entry must be a ref observation")
    };
    assert_eq!(newest.observation_seq, 2);
    assert_eq!(
        newest.previous_target.as_ref().map(GitObjectId::to_hex),
        Some(history.renamed_commit)
    );
}

#[tokio::test]
async fn live_a_tag_and_a_rename_are_covered_when_configured() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let fixture = fixture();
    let scope = activate_stage4(&pool, &fixture, "tag", 73).await;
    let active = active_package(&fixture, &scope);
    let binding = binding(&fixture, &scope);

    let repository = ScratchRepository::init("tag");
    let history = build_history(&repository);
    repository.annotated_tag("v1", &history.renamed_commit, "release one");
    let reader = repository.reader();

    let refs = reader.list_refs().unwrap();
    let names: Vec<&str> = refs.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(names, vec!["refs/heads/main", "refs/tags/v1"]);

    // An annotated tag ref points at a TAG object, not at the commit, and the
    // observation records exactly what the ref points at.
    let tag_ref = GitRefName::parse("refs/tags/v1").unwrap();
    let tag_target = reader.resolve_ref(&tag_ref).unwrap();
    assert_ne!(tag_target.to_hex(), history.renamed_commit);

    // The tag's history still walks to the same commits: `rev-list` peels it.
    let tag_scan = reader.scan(&scan_request("refs/tags/v1")).unwrap();
    assert_eq!(tag_scan.commits.len(), 2);

    let now = canonical_time(server_time(&pool).await);
    let mut facts = tag_scan.facts.clone();
    facts.extend(observation_fact(
        reader.repository(),
        &tag_ref,
        &[(&tag_target.to_hex(), &now)],
    ));

    let key = content_key();
    let context = GitDrainContextV1 {
        binding: &binding,
        active: &active,
        witness: &scope.witness,
        ledger: scope.repository.as_ref(),
        control_scope: &scope.trusted_scope,
        kek: &key,
        clocks: &clocks(&now),
    };
    let report = drain_git_facts(&context, &facts).await.unwrap();
    assert_eq!(report.appended, 5, "{report:?}");

    // The rename: the same blob at two paths is two distinct source facts, and
    // the ledger accepted both.
    let blobs: Vec<&GitFactV1> = facts
        .iter()
        .filter(|fact| matches!(fact, GitFactV1::BlobSource(_)))
        .collect();
    assert_eq!(blobs.len(), 2);
    let ingresses: Vec<_> = blobs
        .iter()
        .map(|fact| binding.build_ingress(fact, &clocks(&now), 1).unwrap())
        .collect();
    assert_eq!(
        ingresses[0].candidate.source_fact.immutable_revision,
        ingresses[1].candidate.source_fact.immutable_revision,
        "content identity is the blob id, and the rename did not change it"
    );
    assert_ne!(
        ingresses[0].candidate.source_fact.canonical_resource_id,
        ingresses[1].candidate.source_fact.canonical_resource_id,
        "but the tree entry at each path is its own source fact"
    );
}

#[tokio::test]
async fn live_a_re_scan_is_an_exact_replay_when_configured() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let fixture = fixture();
    let scope = activate_stage4(&pool, &fixture, "rescan", 74).await;
    let active = active_package(&fixture, &scope);
    let binding = binding(&fixture, &scope);

    let repository = ScratchRepository::init("rescan");
    build_history(&repository);
    let reader = repository.reader();
    let scan = reader.scan(&scan_request("refs/heads/main")).unwrap();

    let now = canonical_time(server_time(&pool).await);
    let key = content_key();
    let context = GitDrainContextV1 {
        binding: &binding,
        active: &active,
        witness: &scope.witness,
        ledger: scope.repository.as_ref(),
        control_scope: &scope.trusted_scope,
        kek: &key,
        clocks: &clocks(&now),
    };
    let first = drain_git_facts(&context, &scan.facts).await.unwrap();
    assert_eq!(first.appended, 4);
    let after_first = scoped_count(&pool, "memory_evidence_events", &scope.physical_scope).await;

    // Re-read the repository from scratch: the objects are unchanged, so the
    // facts are byte-identical and every one of them is an exact replay.
    let rescan = reader.scan(&scan_request("refs/heads/main")).unwrap();
    assert_eq!(rescan.facts, scan.facts, "a re-scan reproduces the objects");
    tokio::time::sleep(Duration::from_millis(2)).await;
    let later = canonical_time(server_time(&pool).await);
    let later_clocks = clocks(&later);
    let second_context = GitDrainContextV1 {
        clocks: &later_clocks,
        ..context
    };
    let second = drain_git_facts(&second_context, &rescan.facts)
        .await
        .unwrap();
    assert_eq!(second.appended, 0, "{second:?}");
    assert_eq!(second.replayed, 4);
    assert_eq!(second.quarantined, 0);
    assert_eq!(second.events, first.events);
    assert_eq!(
        scoped_count(&pool, "memory_evidence_events", &scope.physical_scope).await,
        after_first,
        "a re-scan writes no second event"
    );
    assert_eq!(
        scoped_count(&pool, "memory_content_objects", &scope.physical_scope).await,
        4,
        "and no second governed content row"
    );
}

#[tokio::test]
async fn live_a_cross_tenant_candidate_is_rejected_closed_when_configured() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let fixture = fixture();
    let scope = activate_stage4(&pool, &fixture, "scope", 75).await;
    let active = active_package(&fixture, &scope);
    let binding = binding(&fixture, &scope);

    let repository = ScratchRepository::init("scope");
    build_history(&repository);
    let reader = repository.reader();
    let scan = reader.scan(&scan_request("refs/heads/main")).unwrap();
    let now = canonical_time(server_time(&pool).await);
    let ingress = binding
        .build_ingress(&scan.facts[0], &clocks(&now), 1)
        .unwrap();

    // The connector took its scope from the witness, so the honest candidate is
    // in-scope and admissible.
    assert_eq!(ingress.candidate.scope, *scope.witness.semantic_scope());

    let foreign = AuthenticatedProjectScopeV1::from_trusted_context(
        ContractId::new("tenant.attacker").unwrap(),
        ContractId::new("project.attacker").unwrap(),
    );

    // (1) A candidate that rewrites BOTH scope fields to a foreign tenant.
    let mut both = ingress.candidate.clone();
    both.scope = foreign.clone();
    both.source_fact.scope = foreign.clone();
    let refused = admit_evidence(
        &active,
        EvidenceAdmissionRequestV1 {
            candidate: &both,
            locators: &ingress.locators,
            canonical_payload: &ingress.canonical_payload,
            delivery: ingress.delivery.clone(),
            lineage: RepresentationLineageV2::Origin,
        },
    );
    assert!(matches!(
        refused,
        Err(EvidenceAdmissionError::PayloadSelectedScope)
    ));

    // (2) A candidate that rewrites only the source fact's scope, to prove the
    // envelope alone is not what binds.
    let mut inner = ingress.candidate.clone();
    inner.source_fact.scope = foreign;
    let refused = admit_evidence(
        &active,
        EvidenceAdmissionRequestV1 {
            candidate: &inner,
            locators: &ingress.locators,
            canonical_payload: &ingress.canonical_payload,
            delivery: ingress.delivery.clone(),
            lineage: RepresentationLineageV2::Origin,
        },
    );
    assert!(matches!(
        refused,
        Err(EvidenceAdmissionError::PayloadSelectedScope)
    ));

    // (3) A candidate that smuggles a private raw artifact onto the public
    // plane: the connector never emits one, and admission refuses it.
    let mut private = ingress.candidate.clone();
    private.private_raw_artifact = Some(IngressContentReferenceV1 {
        asserted_media_type: ContractId::new("application.octet-stream").unwrap(),
        byte_length: ingress.candidate.canonical_payload.byte_length.clone(),
        content_digest: ingress.candidate.canonical_payload.content_digest,
        storage_identity: ingress.candidate.canonical_payload.storage_identity,
    });
    let refused = admit_evidence(
        &active,
        EvidenceAdmissionRequestV1 {
            candidate: &private,
            locators: &ingress.locators,
            canonical_payload: &ingress.canonical_payload,
            delivery: ingress.delivery.clone(),
            lineage: RepresentationLineageV2::Origin,
        },
    );
    assert!(matches!(
        refused,
        Err(EvidenceAdmissionError::PrivateRawArtifactUnsupported)
    ));

    // Every rejection happened before any write.
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
#[allow(clippy::too_many_lines)] // One linear proof: drain, receipt, idempotent re-observe, cursor.
async fn live_a_coverage_receipt_binds_the_ref_observation_and_is_idempotent_when_configured() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let fixture = fixture();
    let scope = activate_stage4(&pool, &fixture, "cover", 76).await;
    let active = active_package(&fixture, &scope);
    let binding = binding(&fixture, &scope);

    let repository = ScratchRepository::init("cover");
    build_history(&repository);
    let reader = repository.reader();
    let scan = reader.scan(&scan_request("refs/heads/main")).unwrap();

    let window_start = canonical_time(server_time(&pool).await);
    tokio::time::sleep(Duration::from_millis(2)).await;
    let now = canonical_time(server_time(&pool).await);
    let mut facts = scan.facts.clone();
    facts.extend(observation_fact(
        reader.repository(),
        &scan.ref_name,
        &[(&scan.target.to_hex(), &now)],
    ));

    let key = content_key();
    let context = GitDrainContextV1 {
        binding: &binding,
        active: &active,
        witness: &scope.witness,
        ledger: scope.repository.as_ref(),
        control_scope: &scope.trusted_scope,
        kek: &key,
        clocks: &clocks(&now),
    };
    let report = drain_git_facts(&context, &facts).await.unwrap();
    assert_eq!(report.appended, 5);

    let ref_fact = facts.last().expect("the ref observation");
    let ref_ingress = binding.build_ingress(ref_fact, &clocks(&now), 1).unwrap();
    let coverage = coverage_binding(CoverageWindowV1 {
        window_start,
        window_end: now.clone(),
    });
    // The scan walked two commits, so the covered provider-sequence range is
    // [1, 3) out of a target that also stops there.
    let target = SequenceIntervalV1::new(1, 3).unwrap();
    let observation = git_coverage_observation(
        &coverage,
        ref_ingress
            .candidate
            .source_fact
            .canonical_resource_id
            .clone(),
        &scan.target,
        target,
        target,
        &facts,
        &report,
        now,
    )
    .unwrap();
    assert_eq!(
        observation.evidence_id,
        report.ref_observation_event.unwrap(),
        "the receipt binds the ref-observation accepted event"
    );

    let coverage_repository = CockroachCoverageRuntimeRepository::new(
        pool.clone(),
        scope.trusted_scope.clone(),
        retry_policy(),
    );
    let first = coverage_repository.observe(&observation).await.unwrap();
    let CoverageObservationOutcome::Recorded {
        observation_seq, ..
    } = first
    else {
        panic!("the first observation must extend coverage: {first:?}")
    };
    assert_eq!(observation_seq, 1);
    let receipts_after_first = coverage_repository
        .count_receipts_for_instance(&coverage.connector_instance)
        .await
        .unwrap();
    assert_eq!(receipts_after_first, 1);

    // Re-observing the same range is idempotent: no second receipt, no cursor
    // regression, and the resume point is unchanged.
    let second = coverage_repository.observe(&observation).await.unwrap();
    assert_eq!(
        second,
        CoverageObservationOutcome::AlreadyCovered { observation_seq: 1 }
    );
    assert_eq!(
        coverage_repository
            .count_receipts_for_instance(&coverage.connector_instance)
            .await
            .unwrap(),
        receipts_after_first
    );

    let cursor = coverage_repository
        .read_cursor(&coverage.connector_instance, &observation.scope, target)
        .await
        .unwrap()
        .expect("the repository+ref cursor must be durable");
    assert_eq!(
        git_resume_sequence(Some(&cursor)),
        3,
        "the next scan resumes at the cursor's exclusive high watermark"
    );
    assert_eq!(git_resume_sequence(None), 1, "an unseen ref starts at one");
}
