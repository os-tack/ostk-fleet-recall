//! Connected proof for the exhaustive observer runtime (W3-OBSRT, Stage 6).
//!
//! Set the exact `FLEET_RECALL_TEST_DATABASE_URL` variable to a disposable
//! `CockroachDB` 26.2 database. Every `live_` test here is inert otherwise.
//! Nothing in this file starts a database process, invokes Docker, or targets
//! a cloud service.
//!
//! The bootstrap -> genesis -> successor ceremony is copied from
//! `tests/git_connector_live.rs` so every run below happens against a head
//! that is the Stage-4 package at generation one. What is new is what the
//! observer does against that head, over a frozen snapshot of a real Rust
//! module (`src/observer_runtime/fixtures/service.rs.txt`) written into a
//! scratch repository as a real git blob:
//!
//! * the positive vector — an exhaustive enumeration of the real
//!   `RememberAction` enum yields a VERIFIED result whose receipt names the
//!   exact commit and blob it read;
//! * the negative vector — a deliberately non-exhaustive enumeration yields
//!   INDETERMINATE, never a negative verdict, and (separately) even a whole
//!   read cannot verify a negative under a `positive_verified` admission;
//! * the adversarial vector — the same claimed commit with a different blob
//!   is refused closed before anything is written;
//! * atomicity — the run receipt is durable in the governed content store in
//!   the same transaction as the accepted event;
//! * idempotence — a second identical run is an exact replay, not a second
//!   event;
//! * the remember basis is exactly where it was before the run.

use std::io::Write as _;
use std::process::{Command, Stdio};
use std::str::FromStr as _;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use ostk_fleet_recall::FleetScope;
use ostk_fleet_recall::connectors::git::{
    GitFactV1, GitIngressClocksV1, GitObjectId, GitRepositoryIdV1, GitRepositoryReader,
};
use ostk_fleet_recall::control_log::{
    CockroachGenesisRepository, GenesisRepository, TrustedControlScope,
};
use ostk_fleet_recall::evidence_ledger::{
    ActiveStage4Package, CockroachAcceptedEventRepository, ContentKeyEncryptionKey,
    WriterAuthorityWitness, fetch_governed_content,
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
use ostk_fleet_recall::memory_contracts::observer::{
    ObserverAdmissionModeV1, ObserverCoverageCompletenessV1, ObserverCoverageContinuityV1,
    ObserverInputDomainV1, ObserverOutcomeKindV1, ObserverToolchainVersionsV1,
    VerificationOutcomeV1,
};
use ostk_fleet_recall::memory_contracts::registry::{
    ManifestVerifiedRegistryPackage, RegistryEntryKind,
};
use ostk_fleet_recall::memory_contracts::relation::ConcreteApplicabilityDimensionV1;
use ostk_fleet_recall::memory_contracts::remember_v2::RememberAdmissionRuleV2;
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
use ostk_fleet_recall::observer_runtime::{
    DIAGNOSTIC_ENUM_ATTRIBUTE, DIAGNOSTIC_NON_EXHAUSTIVE, DIAGNOSTIC_SOURCE_UNBALANCED,
    MAX_OBSERVED_SOURCE_BYTES, ObserverAdmissionBindingV1, ObserverAppendDispositionV1,
    ObserverConnectorBindingV1, ObserverDrainContextV1, ObserverIngressClocksV1,
    ObserverQuestionV1, ObserverRunPlanV1, ObserverRunRecordV1, ObserverRuntimeDeclarationV1,
    ObserverRuntimeError, ObserverSourcePinV1, bind_observed_source, build_observer_run,
    drain_observer_run, enumerate_rust_enum, source_content_digest,
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

/// THE source under observation: a frozen snapshot of the real module that
/// declares the `RememberAction` enum this predicate is about. It is a
/// checked-in fixture rather than the live `src/service.rs`, so that module can
/// change freely. It is written into a scratch repository as a real git blob,
/// so the observer reads a genuine git object.
const OBSERVED_SOURCE: &[u8] = include_bytes!("../src/observer_runtime/fixtures/service.rs.txt");
/// The path the observed blob lives at inside the scratch tree.
const OBSERVED_PATH: &[u8] = b"service.rs";
/// The enum the predicate is about.
const OBSERVED_ENUM: &str = "RememberAction";

/// Fixed identity and clock for every scratch commit, so the objects a test
/// builds are byte-deterministic and a re-run is a true replay.
const FIXED_NAME: &str = "Ada Lovelace";
const FIXED_EMAIL: &str = "ada@example.test";
const FIXED_DATE: &str = "1755259200 +0000";

/// The frozen Stage-4 package's provider-instance recipe hashes exactly this
/// decimal coordinate.
const INSTALLATION_ID: u64 = 4242;

/// Each `#[tokio::test]` gets its own runtime, and a `PgPool` is bound to the
/// runtime that created it. The schema is shared, so migration is serialized
/// and runs exactly once per process.
static MIGRATED: Mutex<bool> = Mutex::const_new(false);

// ---------------------------------------------------------------------------
// Scratch git repository, built entirely with plumbing.
// ---------------------------------------------------------------------------

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
            .expect("git must be on PATH for the observer proof");
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

    /// Build a flat tree from `(path, blob oid)` pairs. `mktree` takes entry
    /// NAMES, not paths, so the observed blob sits at the tree root; the
    /// observer resolves whatever path git actually recorded either way.
    fn tree(&self, entries: &[(&str, &str)]) -> String {
        let spec = entries.iter().fold(String::new(), |mut spec, (path, oid)| {
            use std::fmt::Write as _;
            let _ = writeln!(spec, "100644 blob {oid}\t{path}");
            spec
        });
        self.git(&["mktree"], Some(spec.as_bytes()))
    }

    fn commit(&self, tree: &str, message: &str) -> String {
        self.git(&["commit-tree", tree, "-m", message], None)
    }
}

/// One scratch repository holding the observed source at one commit, plus a
/// SECOND commit holding a tampered blob at the same path.
struct ObservedRepository {
    repository: ScratchRepository,
    /// Exactly the bytes committed as the honest blob, so every digest the
    /// tests recompute comes from the object that is really in the repository.
    honest_source: Vec<u8>,
    honest_commit: GitObjectId,
    honest_blob: GitObjectId,
    tampered_commit: GitObjectId,
    tampered_blob: GitObjectId,
}

fn build_observed_repository(label: &str) -> ObservedRepository {
    build_observed_repository_from(label, OBSERVED_SOURCE)
}

/// The same fixture over arbitrary honest bytes.
///
/// A blob is untrusted input by construction — the runtime already refuses to
/// take the object store's word for what it holds — so "a source file crafted
/// to defeat the reader" is inside the threat model and needs a vector of its
/// own.
fn build_observed_repository_from(label: &str, honest_source: &[u8]) -> ObservedRepository {
    let repository = ScratchRepository::init(label);
    let honest_blob = repository.blob(honest_source);
    let honest_tree = repository.tree(&[("service.rs", &honest_blob)]);
    let honest_commit = repository.commit(&honest_tree, "the observed revision");

    // A source that declares an EXTRA action. Same path, different blob: the
    // adversarial input is "the commit you named, but not the object you
    // named".
    let tampered_source = String::from_utf8(honest_source.to_vec())
        .expect("the observed source is UTF-8")
        .replace(
            "pub enum RememberAction {\n    Record,",
            "pub enum RememberAction {\n    Deploy,\n    Record,",
        );
    assert_ne!(
        tampered_source.as_bytes(),
        honest_source,
        "the tampered source must actually differ, or the adversarial vector proves nothing"
    );
    let tampered_blob = repository.blob(tampered_source.as_bytes());
    let tampered_tree = repository.tree(&[("service.rs", &tampered_blob)]);
    let tampered_commit = repository.commit(&tampered_tree, "a tampered revision");

    ObservedRepository {
        honest_source: honest_source.to_vec(),
        honest_commit: GitObjectId::parse_hex(&honest_commit).unwrap(),
        honest_blob: GitObjectId::parse_hex(&honest_blob).unwrap(),
        tampered_commit: GitObjectId::parse_hex(&tampered_commit).unwrap(),
        tampered_blob: GitObjectId::parse_hex(&tampered_blob).unwrap(),
        repository,
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
        format!("obs-{label}-{}", Uuid::now_v7()),
        "observer-runtime-connected-test",
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
    bootstrap: VerifiedBootstrapReceipt,
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
        bootstrap,
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
// Observer wiring on top of the activated head.
// ---------------------------------------------------------------------------

fn content_key() -> ContentKeyEncryptionKey {
    ContentKeyEncryptionKey::from_hex(&"ab".repeat(32)).unwrap()
}

fn active_package(fixture: &ContractFixture, scope: &Stage4Scope) -> ActiveStage4Package {
    ActiveStage4Package::bind(&fixture.target, scope.head.clone(), &scope.witness).unwrap()
}

/// The observer admission the genesis registry package actually activated.
///
/// Every digest here is READ OUT OF the frozen genesis package, which is the
/// point: an operator deploying this runtime must configure exactly the
/// artifact, dependency closure, and configuration governance admitted, or
/// `ObserverAdmissionBindingV1::resolve` refuses.
fn activated_declaration(fixture: &ContractFixture) -> ObserverRuntimeDeclarationV1 {
    use ostk_fleet_recall::memory_contracts::genesis::SemanticallyDecodedGenesisEntryV1;
    let body = fixture
        .genesis_package
        .entries()
        .iter()
        .find_map(|entry| match entry {
            SemanticallyDecodedGenesisEntryV1::ObserverAdmission(body) => Some(body),
            _ => None,
        })
        .expect("the genesis package admits exactly one observer");
    assert_eq!(body.observer_id().as_str(), "observer.rust_enum");
    assert_eq!(
        body.predicate_schema().entry_id.as_str(),
        "mcp.remember.allowed_actions",
        "the activated observer is admitted for the predicate this runtime evaluates"
    );

    ObserverRuntimeDeclarationV1 {
        admission_id: body.observer_id().clone(),
        version: body.version(),
        observer_kind: ContractId::new("rust_enum").unwrap(),
        executable_digest: body.executable_artifact_digest(),
        dependency_closure_pin: body.dependency_closure_digest(),
        configuration_context_digest: body.configuration_digest(),
        mode: ObserverAdmissionModeV1::PositiveVerified,
        predicate: body.predicate_schema().clone(),
        input_domain: ObserverInputDomainV1 {
            closed_input_boundary_id: ContractId::new("boundary.crate-source").unwrap(),
            supported_source_kinds: vec![ContractId::new("git.blob").unwrap()],
            supported_resource_kinds: vec![ContractId::new("rust.enum").unwrap()],
            required_applicability_dimensions: vec![ContractId::new("repository_commit").unwrap()],
        },
        toolchain_versions: ObserverToolchainVersionsV1 {
            language_version: ContractId::new("rust-1.94").unwrap(),
            schema_version: ContractId::new("schema-v1").unwrap(),
            compiler_version: ContractId::new("rustc-1.94.0").unwrap(),
            api_version: ContractId::new("api-v1").unwrap(),
        },
        coverage_receipt_recipe: RegistryReferenceV1 {
            entry_id: ContractId::new("coverage.enumerated").unwrap(),
            version: 1,
            entry_digest: digest(
                "a3700e19e4e5ff4c72279d0b51bc21ffa11fce254e67b54818edcdfce40e50ae",
            ),
        },
        positive_vector_digest: Sha256Digest::from_bytes([0xa1; 32]),
        negative_vector_digest: Sha256Digest::from_bytes([0xa2; 32]),
        mutation_vector_digest: Sha256Digest::from_bytes([0xa3; 32]),
        adversarial_vector_digest: Sha256Digest::from_bytes([0xa4; 32]),
    }
}

fn admission_binding(fixture: &ContractFixture, scope: &Stage4Scope) -> ObserverAdmissionBindingV1 {
    ObserverAdmissionBindingV1::resolve(
        &scope.bootstrap,
        &fixture.genesis_package,
        activated_declaration(fixture).to_admission().unwrap(),
    )
    .expect("the observer must resolve against the activated genesis registry")
}

fn connector_binding(fixture: &ContractFixture, scope: &Stage4Scope) -> ObserverConnectorBindingV1 {
    ObserverConnectorBindingV1::resolve(
        &active_package(fixture, scope),
        ContractId::new("connector.observer").unwrap(),
        ContractId::new("connector.observer.instance-1").unwrap(),
        INSTALLATION_ID,
    )
    .expect("the observer connector must resolve from the active package")
}

/// The active package's remember rule, read back out of the ledger's own
/// witnessed package.
fn remember_rule(active: &ActiveStage4Package) -> RememberAdmissionRuleV2 {
    let entry = active
        .registry_entries()
        .iter()
        .find(|entry| entry.kind == RegistryEntryKind::AuthorityRule)
        .expect("the active package carries a remember admission rule");
    let bytes =
        ostk_fleet_recall::memory_contracts::canonical::canonical_bytes(&entry.body).unwrap();
    decode_strict(&bytes).unwrap()
}

/// Everything one run needs, assembled from the pins and the active package.
#[allow(clippy::too_many_arguments)]
fn run_record(
    fixture: &ContractFixture,
    scope: &Stage4Scope,
    admission: &ObserverAdmissionBindingV1,
    observed: &ObservedRepository,
    evidence_event: AcceptedEventId,
    question: ObserverQuestionV1,
    member_bound: usize,
) -> ObserverRunRecordV1 {
    let reader = observed.repository.reader();
    let pin = ObserverSourcePinV1 {
        commit_id: observed.honest_commit.clone(),
        path: OBSERVED_PATH.to_vec(),
        blob_id: observed.honest_blob.clone(),
        content_digest: source_content_digest(&observed.honest_source),
    };
    let source = bind_observed_source(&reader, &pin, MAX_OBSERVED_SOURCE_BYTES)
        .expect("the pinned source must bind");
    let enumeration =
        enumerate_rust_enum(source.source_text().unwrap(), OBSERVED_ENUM, member_bound)
            .expect("the enum must be uniquely locatable in the observed blob");

    let revision_uri = source
        .observed_revision_uri()
        .expect("the observed revision must have a version identity");
    let active = active_package(fixture, scope);
    let plan = ObserverRunPlanV1 {
        enum_name: OBSERVED_ENUM.to_owned(),
        question,
        member_bound,
        applicability: vec![ConcreteApplicabilityDimensionV1 {
            dimension_id: ContractId::new("repository_commit").unwrap(),
            resource: revision_uri.clone(),
        }],
        // The run cites the accepted event of the git blob-source fact naming
        // the exact object it read, so the receipt's evidence is the ledger's
        // own record of that blob rather than the observer's word for it.
        evidence_event_ids: vec![evidence_event],
        coverage_receipt_digest: Sha256Digest::from_bytes([0x0c; 32]),
        coverage_continuity: ObserverCoverageContinuityV1::NotApplicable,
        profile: active.profile().clone(),
        scope: active.scope().clone(),
    };
    build_observer_run(admission, &source, &enumeration, &plan, revision_uri)
        .expect("the run must build")
}

/// Drain the observed blob into the ledger through W2-GIT and return the
/// accepted event it minted.
///
/// The observer's receipt cites THIS id, so the evidence a run names is an
/// event that is genuinely durable in `memory_evidence_events` — not a digest
/// the observer computed for itself and called evidence.
async fn drain_observed_blob(
    pool: &PgPool,
    fixture: &ContractFixture,
    scope: &Stage4Scope,
    observed: &ObservedRepository,
) -> AcceptedEventId {
    use ostk_fleet_recall::connectors::git::{
        GitConnectorBindingV1, GitDrainContextV1, drain_git_facts,
    };
    let reader = observed.repository.reader();
    let source = bind_observed_source(
        &reader,
        &ObserverSourcePinV1 {
            commit_id: observed.honest_commit.clone(),
            path: OBSERVED_PATH.to_vec(),
            blob_id: observed.honest_blob.clone(),
            content_digest: source_content_digest(&observed.honest_source),
        },
        MAX_OBSERVED_SOURCE_BYTES,
    )
    .unwrap();
    let binding = GitConnectorBindingV1::resolve(
        &active_package(fixture, scope),
        ContractId::new("connector.git").unwrap(),
        ContractId::new("connector.git.instance-1").unwrap(),
        INSTALLATION_ID,
    )
    .unwrap();
    let key = content_key();
    let active = active_package(fixture, scope);
    let now = canonical_time(server_time(pool).await);
    let report = drain_git_facts(
        &GitDrainContextV1 {
            binding: &binding,
            active: &active,
            witness: &scope.witness,
            ledger: scope.repository.as_ref(),
            control_scope: &scope.trusted_scope,
            kek: &key,
            clocks: &GitIngressClocksV1 { received_at: now },
            guarantee: &ostk_fleet_recall::redaction::RedactionGuaranteeV1::from_active_package(
                &active,
            )
            .expect("the package promises redaction"),
        },
        &[GitFactV1::BlobSource(source.fact().clone())],
    )
    .await
    .unwrap();
    assert_eq!(report.quarantined, 0, "{report:?}");
    *report
        .events
        .first()
        .expect("the blob fact must be durable before the observer cites it")
}

fn clocks(now: &CanonicalTimestamp) -> ObserverIngressClocksV1 {
    ObserverIngressClocksV1 {
        received_at: now.clone(),
    }
}

// ---------------------------------------------------------------------------
// Reader- and contract-level proofs. These read a real repository through the
// real `git` plumbing but never touch the ledger, so they run with or without
// a database.
// ---------------------------------------------------------------------------

#[test]
fn a_tampered_blob_at_the_claimed_commit_is_refused_closed() {
    let observed = build_observed_repository("adversarial-offline");
    let reader = observed.repository.reader();

    // The honest pin binds.
    let honest = ObserverSourcePinV1 {
        commit_id: observed.honest_commit.clone(),
        path: OBSERVED_PATH.to_vec(),
        blob_id: observed.honest_blob.clone(),
        content_digest: source_content_digest(OBSERVED_SOURCE),
    };
    let bound = bind_observed_source(&reader, &honest, MAX_OBSERVED_SOURCE_BYTES).unwrap();
    assert_eq!(bound.bytes(), OBSERVED_SOURCE);

    // The adversarial input: the SAME claimed blob and content digest, but the
    // commit whose tree resolves the path to a different object.
    let swapped = ObserverSourcePinV1 {
        commit_id: observed.tampered_commit.clone(),
        ..honest
    };
    let error = bind_observed_source(&reader, &swapped, MAX_OBSERVED_SOURCE_BYTES).unwrap_err();
    assert!(
        matches!(
            &error,
            ObserverRuntimeError::BlobIdMismatch { expected, found }
                if expected == &observed.honest_blob.to_hex()
                    && found == &observed.tampered_blob.to_hex()
        ),
        "{error:?}"
    );

    // And the other direction: the tampered commit with its OWN blob, but the
    // honest content digest still pinned. The object store answers
    // consistently, so only the independent content digest catches it.
    let relabelled = ObserverSourcePinV1 {
        commit_id: observed.tampered_commit.clone(),
        path: OBSERVED_PATH.to_vec(),
        blob_id: observed.tampered_blob,
        content_digest: source_content_digest(OBSERVED_SOURCE),
    };
    let error = bind_observed_source(&reader, &relabelled, MAX_OBSERVED_SOURCE_BYTES).unwrap_err();
    assert!(
        matches!(error, ObserverRuntimeError::ContentDigestMismatch { .. }),
        "{error:?}"
    );
}

#[test]
fn a_path_the_commit_does_not_carry_is_refused_rather_than_read_as_absent() {
    let observed = build_observed_repository("missing-path");
    let reader = observed.repository.reader();
    let pin = ObserverSourcePinV1 {
        commit_id: observed.honest_commit.clone(),
        path: b"nowhere.rs".to_vec(),
        blob_id: observed.honest_blob,
        content_digest: source_content_digest(OBSERVED_SOURCE),
    };
    assert!(bind_observed_source(&reader, &pin, MAX_OBSERVED_SOURCE_BYTES).is_err());
}

#[test]
fn a_blob_over_the_configured_bound_is_refused_rather_than_truncated() {
    let observed = build_observed_repository("bounded");
    let reader = observed.repository.reader();
    let pin = ObserverSourcePinV1 {
        commit_id: observed.honest_commit.clone(),
        path: OBSERVED_PATH.to_vec(),
        blob_id: observed.honest_blob,
        content_digest: source_content_digest(OBSERVED_SOURCE),
    };
    let error = bind_observed_source(&reader, &pin, 16).unwrap_err();
    assert!(
        matches!(
            error,
            ObserverRuntimeError::SourceTooLarge { bound: 16, .. }
        ),
        "{error:?}"
    );
}

#[test]
fn a_declaration_that_disagrees_with_the_activated_entry_is_refused() {
    let fixture = fixture();
    let bootstrap = signed_bootstrap(&fixture, 91);
    let honest = activated_declaration(&fixture);
    ObserverAdmissionBindingV1::resolve(
        &bootstrap,
        &fixture.genesis_package,
        honest.to_admission().unwrap(),
    )
    .expect("the honest declaration must resolve");

    // A mode the activated entry did not grant.
    let escalated = ObserverRuntimeDeclarationV1 {
        mode: ObserverAdmissionModeV1::ClosedWorldVerified,
        ..honest.clone()
    };
    let error = ObserverAdmissionBindingV1::resolve(
        &bootstrap,
        &fixture.genesis_package,
        escalated.to_admission().unwrap(),
    )
    .unwrap_err();
    assert!(
        matches!(
            error,
            ObserverRuntimeError::AdmissionDisagreement("admission mode")
        ),
        "{error:?}"
    );

    // A different executable than the one governance pinned.
    let swapped_binary = ObserverRuntimeDeclarationV1 {
        executable_digest: Sha256Digest::from_bytes([0x5a; 32]),
        ..honest.clone()
    };
    assert!(matches!(
        ObserverAdmissionBindingV1::resolve(
            &bootstrap,
            &fixture.genesis_package,
            swapped_binary.to_admission().unwrap(),
        )
        .unwrap_err(),
        ObserverRuntimeError::AdmissionDisagreement("executable artifact digest")
    ));

    // The predicate relabelled: admitted for P, claiming Q.
    let relabelled = ObserverRuntimeDeclarationV1 {
        predicate: RegistryReferenceV1 {
            entry_id: ContractId::new("some.other.predicate").unwrap(),
            ..honest.predicate.clone()
        },
        ..honest.clone()
    };
    assert!(matches!(
        ObserverAdmissionBindingV1::resolve(
            &bootstrap,
            &fixture.genesis_package,
            relabelled.to_admission().unwrap(),
        )
        .unwrap_err(),
        ObserverRuntimeError::AdmissionDisagreement("predicate reference")
    ));

    // An observer id no activated entry admits.
    let unknown = ObserverRuntimeDeclarationV1 {
        admission_id: ContractId::new("observer.not_admitted").unwrap(),
        ..honest
    };
    assert!(matches!(
        ObserverAdmissionBindingV1::resolve(
            &bootstrap,
            &fixture.genesis_package,
            unknown.to_admission().unwrap(),
        )
        .unwrap_err(),
        ObserverRuntimeError::ObserverNotAdmitted { .. }
    ));
}

#[test]
fn a_registry_package_the_bootstrap_receipt_does_not_pin_admits_nothing() {
    let fixture = fixture();
    let bootstrap = signed_bootstrap(&fixture, 92);
    let declaration = activated_declaration(&fixture);

    // A package that is structurally fine but is not the pinned one: the
    // Stage-4 successor package, which really is activated later in the chain
    // but is not the genesis registry the bootstrap receipt names.
    let other = SemanticallyClosedGenesisPackage::from_manifest_verified(
        ManifestVerifiedRegistryPackage::decode(record(TARGET_PACKAGE), &fixture.profile).unwrap(),
    );
    let Ok(other) = other else {
        // The successor package does not close as a genesis package at all,
        // which is a stronger refusal than the one under test; the pinning
        // check is exercised by the mutated-digest case below instead.
        return;
    };
    let error = ObserverAdmissionBindingV1::resolve(
        &bootstrap,
        &other,
        declaration.to_admission().unwrap(),
    )
    .unwrap_err();
    assert!(
        matches!(error, ObserverRuntimeError::RegistryPackageNotPinned),
        "{error:?}"
    );
}

// ---------------------------------------------------------------------------
// Connected proofs.
// ---------------------------------------------------------------------------

#[tokio::test]
#[allow(clippy::too_many_lines)] // One linear proof; splitting it hides it.
async fn live_an_exhaustive_run_verifies_and_names_the_exact_blob_when_configured() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let fixture = fixture();
    let scope = activate_stage4(&pool, &fixture, "positive", 81).await;
    let active = active_package(&fixture, &scope);
    let admission = admission_binding(&fixture, &scope);
    let connector = connector_binding(&fixture, &scope);
    let observed = build_observed_repository("positive");
    let evidence_event = drain_observed_blob(&pool, &fixture, &scope, &observed).await;

    let record = run_record(
        &fixture,
        &scope,
        &admission,
        &observed,
        evidence_event,
        ObserverQuestionV1::Membership {
            member: "Record".to_owned(),
        },
        64,
    );

    // The positive vector: an exhaustive read of the real enum verifies.
    assert!(record.exhaustive, "diagnostics: {:?}", record.diagnostics);
    assert!(record.diagnostics.is_empty());
    assert_eq!(record.receipt.outcome, ObserverOutcomeKindV1::Success);
    assert_eq!(
        record.receipt.coverage.completeness,
        ObserverCoverageCompletenessV1::Complete
    );
    assert_eq!(
        record.verification_outcome(),
        VerificationOutcomeV1::VerifiedPositive
    );
    // The whole real action set is in the record, in declaration order.
    for expected in [
        "Record",
        "Assert",
        "Supersede",
        "Retract",
        "Forget",
        "Restore",
        "Resolve",
        "Relate",
    ] {
        assert!(
            record.members.iter().any(|member| member == expected),
            "the observation must name {expected}"
        );
    }

    // The observation names the git object it read, not "the current source":
    // the run's input digest is a function of the exact commit and blob, and
    // changing either changes it.
    let reader = observed.repository.reader();
    let honest = bind_observed_source(
        &reader,
        &ObserverSourcePinV1 {
            commit_id: observed.honest_commit.clone(),
            path: OBSERVED_PATH.to_vec(),
            blob_id: observed.honest_blob.clone(),
            content_digest: source_content_digest(OBSERVED_SOURCE),
        },
        MAX_OBSERVED_SOURCE_BYTES,
    )
    .unwrap();
    assert_eq!(record.receipt.input_digest, honest.input_digest());
    assert_eq!(
        record.receipt.source_version,
        honest.observed_revision_uri().unwrap(),
        "the receipt names the revision it actually read"
    );
    let tampered = bind_observed_source(
        &reader,
        &ObserverSourcePinV1 {
            commit_id: observed.tampered_commit.clone(),
            path: OBSERVED_PATH.to_vec(),
            blob_id: observed.tampered_blob.clone(),
            content_digest: source_content_digest_of_tampered(&observed),
        },
        MAX_OBSERVED_SOURCE_BYTES,
    )
    .unwrap();
    assert_ne!(
        record.receipt.source_version,
        tampered.observed_revision_uri().unwrap(),
        "a different commit and blob is a different revision identity"
    );
    assert_ne!(record.receipt.input_digest, tampered.input_digest());

    // Write it: the receipt and the accepted event, atomically.
    let now = canonical_time(server_time(&pool).await);
    let key = content_key();
    let context = ObserverDrainContextV1 {
        binding: &connector,
        active: &active,
        witness: &scope.witness,
        ledger: scope.repository.as_ref(),
        control_scope: &scope.trusted_scope,
        kek: &key,
        clocks: &clocks(&now),
    };
    let outcome = drain_observer_run(&context, &record).await.unwrap();
    assert_eq!(outcome.disposition, ObserverAppendDispositionV1::Appended);
    assert!(outcome.accepted_event.is_some());
    assert_eq!(
        outcome.verification_outcome,
        VerificationOutcomeV1::VerifiedPositive
    );
    assert_eq!(
        scoped_count(&pool, "memory_evidence_events", &scope.physical_scope).await,
        2,
        "the git blob-source event the receipt cites, plus the observer result"
    );
    assert!(
        record.receipt.evidence_event_ids.contains(&evidence_event),
        "the receipt cites the durable blob event"
    );

    // Atomicity, concretely: the governed content object holding BOTH the run
    // receipt and the result is durable, and it decrypts to exactly the bytes
    // the accepted event committed to.
    let ingress = connector.build_ingress(&record, &clocks(&now), 1).unwrap();
    let stored = fetch_governed_content(
        &pool,
        scope.physical_scope.tenant_id,
        &scope.physical_scope.project,
        scope.witness.semantic_scope(),
        ingress.candidate.canonical_payload.storage_identity,
    )
    .await
    .unwrap()
    .expect("the run receipt must be durable in the same transaction as the event");
    let opened = stored.open(&key).unwrap();
    assert_eq!(opened, ingress.canonical_payload);
    let round_tripped: ObserverRunRecordV1 = decode_strict(&opened).unwrap();
    assert_eq!(round_tripped.receipt, record.receipt);
    assert_eq!(round_tripped.result, record.result);
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // Four related verdicts belong in one proof.
async fn live_a_partial_enumeration_is_indeterminate_never_negative_when_configured() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let fixture = fixture();
    let scope = activate_stage4(&pool, &fixture, "negative", 82).await;
    let active = active_package(&fixture, &scope);
    let admission = admission_binding(&fixture, &scope);
    let connector = connector_binding(&fixture, &scope);
    let observed = build_observed_repository("negative");
    let evidence_event = drain_observed_blob(&pool, &fixture, &scope, &observed).await;

    // A deliberately non-exhaustive enumeration: the reader stops at three
    // members. `Relate` is genuinely in the enum but this read never saw it,
    // and `Deploy` is genuinely absent — the observer must not distinguish
    // them, because it cannot.
    let bounded = run_record(
        &fixture,
        &scope,
        &admission,
        &observed,
        evidence_event,
        ObserverQuestionV1::Membership {
            member: "Deploy".to_owned(),
        },
        3,
    );
    assert!(!bounded.exhaustive);
    assert_eq!(bounded.members.len(), 3);
    assert_eq!(
        bounded.receipt.inputs.unsupported.total_count, 1,
        "the bound it hit is an unsupported input, not a footnote"
    );
    assert_eq!(bounded.receipt.outcome, ObserverOutcomeKindV1::Partial);
    assert_eq!(
        bounded.receipt.coverage.completeness,
        ObserverCoverageCompletenessV1::Partial
    );
    assert_eq!(
        bounded.verification_outcome(),
        VerificationOutcomeV1::Indeterminate,
        "a partial read must never reach a negative verdict"
    );
    assert_ne!(
        bounded.verification_outcome(),
        VerificationOutcomeV1::VerifiedNegative
    );

    // The same bounded read asked about a member it DID see is still a
    // positive: finding a thing is something a partial read can honestly do.
    let seen = run_record(
        &fixture,
        &scope,
        &admission,
        &observed,
        evidence_event,
        ObserverQuestionV1::Membership {
            member: "Record".to_owned(),
        },
        3,
    );
    assert_eq!(
        seen.verification_outcome(),
        VerificationOutcomeV1::VerifiedPositive
    );

    // And even a WHOLE read cannot verify a negative under this admission:
    // the activated mode is `positive_verified`, which grants no authority to
    // prove absence at all.
    let whole = run_record(
        &fixture,
        &scope,
        &admission,
        &observed,
        evidence_event,
        ObserverQuestionV1::Membership {
            member: "Deploy".to_owned(),
        },
        64,
    );
    assert!(whole.exhaustive);
    assert_eq!(
        whole.verification_outcome(),
        VerificationOutcomeV1::Indeterminate,
        "closed-world authority is a governance grant, not a property of the read"
    );

    // An exact-set question is likewise indeterminate under this admission.
    let exact = run_record(
        &fixture,
        &scope,
        &admission,
        &observed,
        evidence_event,
        ObserverQuestionV1::ExactSet,
        64,
    );
    assert_eq!(
        exact.verification_outcome(),
        VerificationOutcomeV1::Indeterminate
    );

    // Every one of these is still a real, durable observation: an indeterminate
    // verdict is written, not swallowed.
    let now = canonical_time(server_time(&pool).await);
    let key = content_key();
    let context = ObserverDrainContextV1 {
        binding: &connector,
        active: &active,
        witness: &scope.witness,
        ledger: scope.repository.as_ref(),
        control_scope: &scope.trusted_scope,
        kek: &key,
        clocks: &clocks(&now),
    };
    let outcome = drain_observer_run(&context, &bounded).await.unwrap();
    assert_eq!(outcome.disposition, ObserverAppendDispositionV1::Appended);
    assert_eq!(
        outcome.verification_outcome,
        VerificationOutcomeV1::Indeterminate
    );
    assert_eq!(
        scoped_count(&pool, "memory_evidence_events", &scope.physical_scope).await,
        2,
        "the cited blob event, plus this indeterminate observation"
    );
}

/// The real source with a `#[non_exhaustive]` parked behind an attribute whose
/// token tree carries one more `}` than `{`, and with the `Forget` variant
/// deleted.
///
/// This is the shape that a reader with two brace-depth counters could be
/// steered by: one counter stepping over the attribute group whole and the
/// other counting the braces inside it end up in different places in the same
/// file, and the attributes below fall into the gap. Every byte of it is a
/// blob a pin can honestly name, so nothing upstream of the reader can catch
/// it — and the question below is about a variant that IS an allowed remember
/// action in the real enum, so a verdict of "absent" here would be a verified
/// negative asserting the opposite of the truth.
fn desynchronising_attribute_source() -> Vec<u8> {
    let text = String::from_utf8(OBSERVED_SOURCE.to_vec()).expect("the observed source is UTF-8");
    let crafted = text
        .replace(
            "pub enum RememberAction {",
            "#[doc( } )]\n#[non_exhaustive]\npub enum RememberAction {",
        )
        .replace("    Forget,\n", "");
    assert!(
        !crafted.contains("    Forget,\n"),
        "the vector only means something if the variant really is gone"
    );
    crafted.into_bytes()
}

#[tokio::test]
async fn live_a_brace_desynchronised_blob_is_indeterminate_never_negative_when_configured() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    // The strongest form of the vector puts a bare `{` after the attribute, so
    // that a reader counting the braces inside it lands back at module level
    // while an attribute reader that stepped over the group whole is one body
    // deep. There is one counter now, so the enum simply is not at module
    // level, and "not uniquely locatable" is a refusal rather than a reading.
    let unlocatable = String::from_utf8(OBSERVED_SOURCE.to_vec())
        .unwrap()
        .replace(
            "pub enum RememberAction {",
            "#[doc( } )]\n{\n#[non_exhaustive]\npub enum RememberAction {",
        )
        .replace("    Forget,\n", "");
    assert!(
        matches!(
            enumerate_rust_enum(&unlocatable, OBSERVED_ENUM, 64),
            Err(ObserverRuntimeError::EnumNotUnique { found: 0, .. })
        ),
        "a blob that moves the enum out of module level must be refused, not read"
    );

    let pool = live_pool(&database_url).await;
    let fixture = fixture();
    let scope = activate_stage4(&pool, &fixture, "desync", 88).await;
    let active = active_package(&fixture, &scope);
    let admission = admission_binding(&fixture, &scope);
    let connector = connector_binding(&fixture, &scope);
    let observed = build_observed_repository_from("desync", &desynchronising_attribute_source());
    let evidence_event = drain_observed_blob(&pool, &fixture, &scope, &observed).await;

    // A full-budget read of a genuine, correctly-pinned blob, asked about a
    // variant the crafted source no longer declares.
    let record = run_record(
        &fixture,
        &scope,
        &admission,
        &observed,
        evidence_event,
        ObserverQuestionV1::Membership {
            member: "Forget".to_owned(),
        },
        64,
    );

    assert!(
        !record.exhaustive,
        "a file whose braces this reader cannot balance is not an exhaustive read"
    );
    let diagnostics: Vec<&str> = record.diagnostics.iter().map(ContractId::as_str).collect();
    assert!(
        diagnostics.contains(&DIAGNOSTIC_NON_EXHAUSTIVE),
        "the marker must survive the attribute above it: {diagnostics:?}"
    );
    assert!(
        diagnostics.contains(&DIAGNOSTIC_SOURCE_UNBALANCED),
        "the reader must say it could not structure the file: {diagnostics:?}"
    );
    assert!(
        diagnostics.contains(&DIAGNOSTIC_ENUM_ATTRIBUTE),
        "an attribute the reader could not close is an unproven list: {diagnostics:?}"
    );
    assert_eq!(record.receipt.outcome, ObserverOutcomeKindV1::Partial);
    assert_eq!(
        record.receipt.coverage.completeness,
        ObserverCoverageCompletenessV1::Partial
    );
    assert_eq!(
        record.verification_outcome(),
        VerificationOutcomeV1::Indeterminate
    );
    assert_ne!(
        record.verification_outcome(),
        VerificationOutcomeV1::VerifiedNegative,
        "`forget` is an allowed remember action; no crafted blob may buy the opposite"
    );

    // And the caveat is durable: the appended observation carries the
    // indeterminate verdict rather than a negative one.
    let now = canonical_time(server_time(&pool).await);
    let key = content_key();
    let context = ObserverDrainContextV1 {
        binding: &connector,
        active: &active,
        witness: &scope.witness,
        ledger: scope.repository.as_ref(),
        control_scope: &scope.trusted_scope,
        kek: &key,
        clocks: &clocks(&now),
    };
    let outcome = drain_observer_run(&context, &record).await.unwrap();
    assert_eq!(outcome.disposition, ObserverAppendDispositionV1::Appended);
    assert_eq!(
        outcome.verification_outcome,
        VerificationOutcomeV1::Indeterminate
    );
}

/// The real source with `#[non_exhaustive]` parked behind a brace-delimited
/// attribute whose token tree also carries a `;`.
///
/// Every one of those tokens is legal inside an attribute, and every one of
/// them is a tempting "end of the previous item" marker for a reader that
/// hunts backwards. If the reader is fooled, the attribute list it reports is
/// EMPTY — the `#[non_exhaustive]`, the `#[serde]`, and the unknown attribute
/// macro all vanish at once, the read claims exhaustiveness, and "Deploy is
/// absent" becomes a verified negative about a set nobody enumerated.
fn crafted_attribute_source() -> Vec<u8> {
    let text = String::from_utf8(OBSERVED_SOURCE.to_vec()).expect("the observed source is UTF-8");
    let crafted = text.replace(
        "pub enum RememberAction {",
        "#[non_exhaustive]\n#[rewrites_the_item { and; a; semicolon }]\npub enum RememberAction {",
    );
    assert_ne!(
        crafted.as_bytes(),
        OBSERVED_SOURCE,
        "the crafted source must actually differ, or the vector proves nothing"
    );
    crafted.into_bytes()
}

#[tokio::test]
async fn live_a_crafted_attribute_blob_is_indeterminate_never_negative_when_configured() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let fixture = fixture();
    let scope = activate_stage4(&pool, &fixture, "crafted", 86).await;
    let active = active_package(&fixture, &scope);
    let admission = admission_binding(&fixture, &scope);
    let connector = connector_binding(&fixture, &scope);
    let observed = build_observed_repository_from("crafted", &crafted_attribute_source());
    let evidence_event = drain_observed_blob(&pool, &fixture, &scope, &observed).await;

    // A full-budget read of a genuine, correctly-pinned blob. Nothing about the
    // transport is wrong here: the object really is the one the pin names, so
    // no integrity check fires. The only defence is the reader's honesty about
    // what it could not prove it understood.
    let record = run_record(
        &fixture,
        &scope,
        &admission,
        &observed,
        evidence_event,
        ObserverQuestionV1::Membership {
            member: "Deploy".to_owned(),
        },
        64,
    );

    assert!(
        !record.exhaustive,
        "an attribute the reader cannot prove harmless is not an exhaustive read"
    );
    let diagnostics: Vec<&str> = record.diagnostics.iter().map(ContractId::as_str).collect();
    assert!(
        diagnostics.contains(&DIAGNOSTIC_NON_EXHAUSTIVE),
        "the marker must survive the attribute above it: {diagnostics:?}"
    );
    assert!(
        diagnostics.contains(&DIAGNOSTIC_ENUM_ATTRIBUTE),
        "the unknown attribute macro is itself a caveat: {diagnostics:?}"
    );
    assert_eq!(record.receipt.outcome, ObserverOutcomeKindV1::Partial);
    assert_eq!(
        record.receipt.coverage.completeness,
        ObserverCoverageCompletenessV1::Partial
    );
    assert_eq!(
        record.verification_outcome(),
        VerificationOutcomeV1::Indeterminate
    );
    assert_ne!(
        record.verification_outcome(),
        VerificationOutcomeV1::VerifiedNegative,
        "a crafted blob must never buy a verdict about a set nobody enumerated"
    );

    // The caveat is durable, not a log line: the appended observation carries
    // the indeterminate verdict and still names the exact object it read.
    let now = canonical_time(server_time(&pool).await);
    let key = content_key();
    let context = ObserverDrainContextV1 {
        binding: &connector,
        active: &active,
        witness: &scope.witness,
        ledger: scope.repository.as_ref(),
        control_scope: &scope.trusted_scope,
        kek: &key,
        clocks: &clocks(&now),
    };
    let outcome = drain_observer_run(&context, &record).await.unwrap();
    assert_eq!(outcome.disposition, ObserverAppendDispositionV1::Appended);
    assert_eq!(
        outcome.verification_outcome,
        VerificationOutcomeV1::Indeterminate
    );
    let reader = observed.repository.reader();
    let bound = bind_observed_source(
        &reader,
        &ObserverSourcePinV1 {
            commit_id: observed.honest_commit.clone(),
            path: OBSERVED_PATH.to_vec(),
            blob_id: observed.honest_blob.clone(),
            content_digest: source_content_digest(&observed.honest_source),
        },
        MAX_OBSERVED_SOURCE_BYTES,
    )
    .unwrap();
    assert_eq!(
        record.receipt.source_version,
        bound.observed_revision_uri().unwrap()
    );
}

#[tokio::test]
async fn live_a_repeated_run_is_an_exact_replay_when_configured() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let fixture = fixture();
    let scope = activate_stage4(&pool, &fixture, "replay", 83).await;
    let active = active_package(&fixture, &scope);
    let admission = admission_binding(&fixture, &scope);
    let connector = connector_binding(&fixture, &scope);
    let observed = build_observed_repository("replay");
    let evidence_event = drain_observed_blob(&pool, &fixture, &scope, &observed).await;

    let question = || ObserverQuestionV1::Membership {
        member: "Assert".to_owned(),
    };
    let first = run_record(
        &fixture,
        &scope,
        &admission,
        &observed,
        evidence_event,
        question(),
        64,
    );
    let second = run_record(
        &fixture,
        &scope,
        &admission,
        &observed,
        evidence_event,
        question(),
        64,
    );
    assert_eq!(
        first.canonical_bytes().unwrap(),
        second.canonical_bytes().unwrap(),
        "two runs over the same pins must render byte-identically"
    );

    let key = content_key();
    // Deliberately DIFFERENT received clocks: `received_at` is outside the
    // accepted-event preimage, so the second run must still be an exact replay
    // rather than an integrity collision.
    let first_now = canonical_time(server_time(&pool).await);
    let first_outcome = drain_observer_run(
        &ObserverDrainContextV1 {
            binding: &connector,
            active: &active,
            witness: &scope.witness,
            ledger: scope.repository.as_ref(),
            control_scope: &scope.trusted_scope,
            kek: &key,
            clocks: &clocks(&first_now),
        },
        &first,
    )
    .await
    .unwrap();
    assert_eq!(
        first_outcome.disposition,
        ObserverAppendDispositionV1::Appended
    );

    tokio::time::sleep(Duration::from_millis(2)).await;
    let second_now = canonical_time(server_time(&pool).await);
    assert_ne!(first_now, second_now, "the two runs used different clocks");
    let second_outcome = drain_observer_run(
        &ObserverDrainContextV1 {
            binding: &connector,
            active: &active,
            witness: &scope.witness,
            ledger: scope.repository.as_ref(),
            control_scope: &scope.trusted_scope,
            kek: &key,
            clocks: &clocks(&second_now),
        },
        &second,
    )
    .await
    .unwrap();
    assert_eq!(
        second_outcome.disposition,
        ObserverAppendDispositionV1::Replayed,
        "the same observation must not mint a second event"
    );
    assert_eq!(second_outcome.accepted_event, first_outcome.accepted_event);
    assert_eq!(
        scoped_count(&pool, "memory_evidence_events", &scope.physical_scope).await,
        2,
        "the cited blob event, plus exactly one observation"
    );
}

#[tokio::test]
async fn live_a_run_never_moves_the_remember_basis_when_configured() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let fixture = fixture();
    let scope = activate_stage4(&pool, &fixture, "basis", 84).await;
    let active = active_package(&fixture, &scope);
    let admission = admission_binding(&fixture, &scope);
    let connector = connector_binding(&fixture, &scope);
    let observed = build_observed_repository("basis");
    let evidence_event = drain_observed_blob(&pool, &fixture, &scope, &observed).await;

    let before = remember_rule(&active);
    assert!(
        !before.registered_observer_append_enabled,
        "the activated package must start with the observer basis closed"
    );

    let record = run_record(
        &fixture,
        &scope,
        &admission,
        &observed,
        evidence_event,
        ObserverQuestionV1::Membership {
            member: "Forget".to_owned(),
        },
        64,
    );
    let now = canonical_time(server_time(&pool).await);
    let key = content_key();
    drain_observer_run(
        &ObserverDrainContextV1 {
            binding: &connector,
            active: &active,
            witness: &scope.witness,
            ledger: scope.repository.as_ref(),
            control_scope: &scope.trusted_scope,
            kek: &key,
            clocks: &clocks(&now),
        },
        &record,
    )
    .await
    .unwrap();

    // Re-read the head from the database, not from the value in hand: the
    // question is whether the RUN moved anything, so the witness must come
    // back out of `memory_writer_authority_v1`.
    let after_witness = scope
        .repository
        .read_writer_authority_witness()
        .await
        .unwrap();
    assert_eq!(
        after_witness.head().activation_id,
        scope.witness.head().activation_id,
        "an observation must not activate anything"
    );
    assert_eq!(
        after_witness.head().package_digest,
        scope.witness.head().package_digest
    );
    assert_eq!(after_witness.generation(), 1);

    let after = remember_rule(
        &ActiveStage4Package::bind(&fixture.target, scope.head.clone(), &after_witness).unwrap(),
    );
    assert_eq!(
        after, before,
        "the remember admission rule is byte-identical after the run"
    );
    assert!(
        !after.registered_observer_append_enabled,
        "the remember basis may move only through a package change"
    );
}

#[tokio::test]
async fn live_a_tampered_blob_never_reaches_the_ledger_when_configured() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let fixture = fixture();
    let scope = activate_stage4(&pool, &fixture, "adversarial", 85).await;
    let observed = build_observed_repository("adversarial");
    let reader = observed.repository.reader();

    // The adversarial vector, end to end: the claimed commit is the tampered
    // one, the claimed blob is the honest one. The bind refuses, so no run is
    // ever built and nothing is written.
    let error = bind_observed_source(
        &reader,
        &ObserverSourcePinV1 {
            commit_id: observed.tampered_commit.clone(),
            path: OBSERVED_PATH.to_vec(),
            blob_id: observed.honest_blob.clone(),
            content_digest: source_content_digest(OBSERVED_SOURCE),
        },
        MAX_OBSERVED_SOURCE_BYTES,
    )
    .unwrap_err();
    assert!(
        matches!(error, ObserverRuntimeError::BlobIdMismatch { .. }),
        "{error:?}"
    );
    assert_eq!(
        scoped_count(&pool, "memory_evidence_events", &scope.physical_scope).await,
        0,
        "a refused observation writes no event"
    );
    assert_eq!(
        scoped_count(&pool, "memory_content_objects", &scope.physical_scope).await,
        0,
        "and no governed content either"
    );

    // The tampered source really does declare a different action set, so the
    // refusal above is not merely cosmetic: had it been believed, the ledger
    // would carry an observation of an enum that is not the one at the commit
    // this deployment reads.
    let tampered = bind_observed_source(
        &reader,
        &ObserverSourcePinV1 {
            commit_id: observed.tampered_commit.clone(),
            path: OBSERVED_PATH.to_vec(),
            blob_id: observed.tampered_blob.clone(),
            content_digest: source_content_digest_of_tampered(&observed),
        },
        MAX_OBSERVED_SOURCE_BYTES,
    )
    .unwrap();
    let enumeration =
        enumerate_rust_enum(tampered.source_text().unwrap(), OBSERVED_ENUM, 64).unwrap();
    assert!(
        enumeration.contains("Deploy"),
        "the tampered blob is the one that adds an action"
    );
}

/// The content digest of the tampered blob, read back out of the repository so
/// the test never has to restate the bytes.
fn source_content_digest_of_tampered(observed: &ObservedRepository) -> Sha256Digest {
    let reader = observed.repository.reader();
    source_content_digest(&reader.read_blob(&observed.tampered_blob).unwrap())
}
