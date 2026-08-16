//! Workstation-only, deployment-authorized generic `N -> N+1` registry
//! activation (`N >= 1`).
//!
//! This binary has no public server route. Physical scope, semantic scope, the
//! bootstrap-receipt pin, the conformance-runner identity, and the ceremony
//! principals come only from the dedicated successor environment configuration,
//! which the one-time `0 -> 1` CLI already owns; this ceremony deliberately
//! reuses that closed namespace instead of opening a second one. The CLI
//! accepts paths to the six canonical ceremony artifacts and no authority or
//! transport override.
//!
//! Unlike the frozen `0 -> 1` ceremony there is no key bridge: the keys that
//! authorize this transition are the ones the **currently active** package
//! already installed. The operator therefore supplies that active package as an
//! artifact so the complete ceremony — including every approval signature, the
//! installed threshold, and the strong separation-of-duty rule — closes offline
//! before any database URL is parsed. The repository independently rebuilds the
//! same policy from durable bytes under its stream lock, and the expected-head
//! artifact binds the two together: its package digest is the active package's.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, anyhow, ensure};
use clap::{Args, Parser, Subcommand};
use ostk_fleet_recall::config::{SuccessorActivationConfig, SuccessorActivationRuntimeConfig};
use ostk_fleet_recall::memory_contracts::bootstrap::BootstrapReceiptDigest;
use ostk_fleet_recall::memory_contracts::canonical::{
    MAX_INPUT_BYTES, decode_strict, encode_canonical, require_canonical,
};
use ostk_fleet_recall::memory_contracts::common::{
    AuthenticatedProjectScopeV1, CanonicalTimestamp, ProfileReferenceV1, RegistryReferenceV1,
    frozen_profile_reference_v1,
};
use ostk_fleet_recall::memory_contracts::evidence_v2::RegistryHeadBindingV1;
use ostk_fleet_recall::memory_contracts::registry::ManifestVerifiedRegistryPackage;
use ostk_fleet_recall::memory_contracts::successor_generic::{
    GenericSuccessorActivationApprovalSetV2, GenericSuccessorActivationStatementV2,
    GenericSuccessorPrincipalBinding, GenericSuccessorTestRunnerPin,
    StructurallyClosedSuccessorTargetV2, VerifiedGenericSuccessorTestResult,
    verify_generic_successor_test_result,
};
use ostk_fleet_recall::memory_contracts::successor_policy::ActivationSignatureAlgorithmV2;
use ostk_fleet_recall::private_postgres::{
    PrivatePostgresSslPolicy, private_postgres_connect_options,
};
use ostk_fleet_recall::registry_activation::{
    AcceptedGenericSuccessorActivation, CockroachGenericSuccessorRepository,
    GenericSuccessorActivationCandidate, GenericSuccessorActivationInspection,
    GenericSuccessorActivationOutcome, GenericSuccessorRepository, ReadyGenericSuccessor,
};
use ostk_fleet_recall::store::cockroach::RetryPolicy;
use ring::signature;
use serde_json::{Value, json};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

const APPLICATION_NAME: &str = "ostk-registry-generic-successor-activate";
const MAX_CONNECTIONS: u32 = 2;
const GENERIC_APPROVAL_SIGNATURE_PREFIX: &[u8] =
    b"ostk-registry-successor-activation-approval-signature-v2\0";

#[derive(Debug, Parser)]
#[command(
    name = "ostk-registry-generic-successor-activate",
    version,
    about = "Private, workstation-authorized generic N -> N+1 registry activation"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Audit the open registry head and atomically install its successor.
    Apply(ArtifactArgs),
    /// Audit the open registry head and report readiness or acceptance.
    Inspect(ArtifactArgs),
}

#[derive(Debug, Args)]
struct ArtifactArgs {
    /// Canonical currently active generation-N package plus one LF.
    #[arg(long, value_name = "PATH")]
    current_package: PathBuf,
    /// Canonical expected open head (`RegistryHeadBindingV1`) plus one LF.
    #[arg(long, value_name = "PATH")]
    expected_head: PathBuf,
    /// Canonical target generation-N+1 package plus one LF.
    #[arg(long, value_name = "PATH")]
    target_package: PathBuf,
    /// Canonical, deployment-pinned target conformance result plus one LF.
    #[arg(long, value_name = "PATH")]
    target_test_result: PathBuf,
    /// Canonical generic activation statement plus one LF.
    #[arg(long, value_name = "PATH")]
    activation_statement: PathBuf,
    /// Canonical detached generic approval set plus one LF.
    #[arg(long, value_name = "PATH")]
    activation_approval_set: PathBuf,
}

struct ArtifactAuthority<'a> {
    semantic_scope: &'a AuthenticatedProjectScopeV1,
    bootstrap_receipt_digest: BootstrapReceiptDigest,
    target_test_runner_pin: GenericSuccessorTestRunnerPin,
    principal_binding: GenericSuccessorPrincipalBinding,
}

impl<'a> ArtifactAuthority<'a> {
    fn from_config(config: &'a SuccessorActivationConfig) -> Self {
        Self {
            semantic_scope: config.trusted_scope().semantic_scope(),
            bootstrap_receipt_digest: config.bootstrap_receipt_digest(),
            target_test_runner_pin: config.generic_target_test_runner_pin(),
            principal_binding: config.generic_principal_binding(),
        }
    }
}

struct VerifiedArtifacts {
    canonical_target_package: Vec<u8>,
    canonical_target_test_result: Vec<u8>,
    expected_head: RegistryHeadBindingV1,
    target_generation: u32,
    candidate: GenericSuccessorActivationCandidate,
}

struct PreparedExecution {
    artifacts: VerifiedArtifacts,
    connect_options: PgConnectOptions,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let config = SuccessorActivationRuntimeConfig::from_env()?;
    let args = match &cli.command {
        Command::Apply(args) | Command::Inspect(args) => args,
    };
    let authority = ArtifactAuthority::from_config(config.authority());

    // This is the pre-connect trust boundary. All six files are bounded,
    // canonically decoded, cross-bound, and every approval signature is checked
    // against the installed policy before sqlx options are parsed.
    let prepared = prepare_execution(args, &authority, config.database_url())?;
    let artifacts = prepared.artifacts;
    let pool = PgPoolOptions::new()
        .max_connections(MAX_CONNECTIONS)
        .min_connections(0)
        .acquire_timeout(Duration::from_secs(10))
        .connect_lazy_with(prepared.connect_options);
    let repository = CockroachGenericSuccessorRepository::new(
        pool.clone(),
        config.authority().trusted_scope().clone(),
        RetryPolicy::default(),
        authority.bootstrap_receipt_digest,
        artifacts.canonical_target_package,
        &artifacts.canonical_target_test_result,
        authority.target_test_runner_pin,
        authority.principal_binding,
        artifacts.expected_head,
    )?;

    // Constructing the lazy pool and repository opens no socket. This explicit
    // acquire is the first network operation, after every offline constructor
    // has succeeded; its error deliberately reveals no URL or credential.
    let connection = pool
        .acquire()
        .await
        .map_err(|_| anyhow!("connect private generic successor activation database failed"))?;
    drop(connection);

    // Offline signature checks authenticate the candidate against the supplied
    // active package. Only this repository call authenticates that package
    // against the durable open head and re-verifies signatures in the same
    // SERIALIZABLE transaction as freshness and the head CAS.
    let output = match cli.command {
        Command::Apply(_) => match repository
            .activate_generic_successor(&artifacts.candidate)
            .await?
        {
            GenericSuccessorActivationOutcome::Inserted(accepted) => {
                accepted_output("apply", "inserted", &accepted)
            }
            GenericSuccessorActivationOutcome::ExactReplay(accepted) => {
                accepted_output("apply", "exact_replay", &accepted)
            }
        },
        Command::Inspect(_) => match repository
            .inspect_generic_successor(artifacts.target_generation)
            .await?
        {
            GenericSuccessorActivationInspection::Ready(ready) => ready_output(&ready),
            GenericSuccessorActivationInspection::Accepted(accepted) => {
                accepted_output("inspect", "accepted", &accepted)
            }
        },
    };
    println!("{}", serde_json::to_string(&output)?);
    Ok(())
}

fn prepare_execution(
    paths: &ArtifactArgs,
    authority: &ArtifactAuthority<'_>,
    database_url: &str,
) -> anyhow::Result<PreparedExecution> {
    let artifacts = verify_artifacts(paths, authority)?;
    let connect_options = private_postgres_connect_options(
        database_url,
        APPLICATION_NAME,
        PrivatePostgresSslPolicy::VerifyFull,
    )?;
    Ok(PreparedExecution {
        artifacts,
        connect_options,
    })
}

fn verify_artifacts(
    paths: &ArtifactArgs,
    authority: &ArtifactAuthority<'_>,
) -> anyhow::Result<VerifiedArtifacts> {
    let expected_profile = frozen_profile_reference_v1();

    let expected_head_bytes = read_framed_canonical_record(&paths.expected_head)?;
    let expected_head: RegistryHeadBindingV1 = decode_strict(&expected_head_bytes)?;
    expected_head.validate_shape()?;
    ensure!(
        encode_canonical(&expected_head)? == expected_head_bytes,
        "expected registry head did not round-trip canonically"
    );
    ensure!(
        expected_head.effective_until.is_none(),
        "expected registry head is not an open head"
    );

    let current_package_bytes = read_framed_canonical_record(&paths.current_package)?;
    let current_manifest =
        ManifestVerifiedRegistryPackage::decode(&current_package_bytes, &expected_profile)?;
    let installed = StructurallyClosedSuccessorTargetV2::from_manifest_verified(&current_manifest)?;
    ensure!(
        installed.package_digest() == expected_head.head.package_digest
            && installed
                .activation_policy()
                .registry_reference()
                .entry_digest
                == expected_head.head.activation_policy_digest
            && *installed.profile() == expected_profile,
        "active package is not the package the expected open head installs"
    );

    let target_package_bytes = read_framed_canonical_record(&paths.target_package)?;
    let target_manifest =
        ManifestVerifiedRegistryPackage::decode(&target_package_bytes, &expected_profile)?;
    let target = StructurallyClosedSuccessorTargetV2::from_manifest_verified(&target_manifest)?;

    let target_test_result_bytes = read_framed_canonical_record(&paths.target_test_result)?;
    let target_test_result = verify_generic_successor_test_result(
        &target_test_result_bytes,
        authority.target_test_runner_pin,
        &target,
    )?;

    let statement_bytes = read_framed_canonical_record(&paths.activation_statement)?;
    let approval_set_bytes = read_framed_canonical_record(&paths.activation_approval_set)?;
    let target_generation = verify_offline_generic_candidate(
        &statement_bytes,
        &approval_set_bytes,
        authority,
        &installed,
        &target,
        &target_test_result,
        &expected_head,
        &expected_profile,
    )?;
    let candidate = GenericSuccessorActivationCandidate::from_bounded_canonical_bytes(
        statement_bytes,
        approval_set_bytes,
    )?;

    Ok(VerifiedArtifacts {
        canonical_target_package: target_package_bytes,
        canonical_target_test_result: target_test_result_bytes,
        expected_head,
        target_generation,
        candidate,
    })
}

/// Close the whole ceremony offline and return its target generation.
///
/// This mirrors `verify_generic_successor_activation` field for field against
/// the *installed* policy, so a package can neither lower the threshold, widen
/// the signer set, nor relax separation of duty to admit itself.
#[allow(clippy::too_many_arguments)]
fn verify_offline_generic_candidate(
    canonical_statement: &[u8],
    canonical_approval_set: &[u8],
    authority: &ArtifactAuthority<'_>,
    installed: &StructurallyClosedSuccessorTargetV2,
    target: &StructurallyClosedSuccessorTargetV2,
    test_result: &VerifiedGenericSuccessorTestResult,
    expected_head: &RegistryHeadBindingV1,
    expected_profile: &ProfileReferenceV1,
) -> anyhow::Result<u32> {
    require_canonical(canonical_statement)?;
    let statement: GenericSuccessorActivationStatementV2 = decode_strict(canonical_statement)?;
    statement.validate_shape()?;
    ensure!(
        encode_canonical(&statement)? == canonical_statement,
        "generic activation statement did not round-trip canonically"
    );

    let statement_binding = GenericSuccessorPrincipalBinding::from_trusted_config(
        statement.proposer_principal_id.clone(),
        statement.package_author_principal_id.clone(),
    );
    ensure!(
        statement.profile == *expected_profile
            && statement.profile == *target.profile()
            && statement.profile == *installed.profile()
            && statement.scope == *authority.semantic_scope
            && statement.expected_predecessor_head == *expected_head
            && statement.current_activation_policy
                == *installed.activation_policy().registry_reference()
            && statement.target_package_digest == target.package_digest()
            && statement.target_activation_policy
                == *target.activation_policy().registry_reference()
            && statement.test_vector_result_digest == test_result.result_digest()
            && test_result.result().profile == statement.profile
            && test_result.result().package_digest == statement.target_package_digest
            && test_result.result().completed_at <= statement.effective_from
            && statement_binding == authority.principal_binding,
        "generic activation statement is not closed over the deployment-bound offline authority"
    );

    require_canonical(canonical_approval_set)?;
    let approval_set: GenericSuccessorActivationApprovalSetV2 =
        decode_strict(canonical_approval_set)?;
    approval_set.validate_shape()?;
    ensure!(
        encode_canonical(&approval_set)? == canonical_approval_set,
        "generic approval set did not round-trip canonically"
    );
    let statement_id = statement.statement_id()?;
    let policy = installed.activation_policy().policy();
    policy.validate()?;
    ensure!(
        approval_set.statement_id == statement_id
            && approval_set.approvals.len() <= policy.eligible_signers.len(),
        "generic approval set does not bind the exact statement and installed policy"
    );

    let mut signature_message = GENERIC_APPROVAL_SIGNATURE_PREFIX.to_vec();
    signature_message.extend_from_slice(statement_id.digest().as_bytes());
    let mut approving_principals = Vec::with_capacity(approval_set.approvals.len());
    for approval in &approval_set.approvals {
        let signer = policy
            .eligible_signers
            .iter()
            .find(|binding| binding.principal_id == approval.signer_principal_id)
            .ok_or_else(|| anyhow!("generic approval signer is not in the installed policy"))?;
        match signer.algorithm {
            ActivationSignatureAlgorithmV2::Ed25519 => {
                signature::UnparsedPublicKey::new(
                    &signature::ED25519,
                    signer.public_key.as_bytes(),
                )
                .verify(&signature_message, approval.signature.as_bytes())
                .map_err(|_| anyhow!("generic approval signature is invalid"))?;
            }
        }
        approving_principals.push(signer.principal_id.clone());
    }
    policy.validate_approval_principal_set(
        &statement.package_author_principal_id,
        &statement.proposer_principal_id,
        &approving_principals,
    )?;
    Ok(statement.to_generation)
}

fn read_framed_canonical_record(path: &Path) -> anyhow::Result<Vec<u8>> {
    let mut file =
        File::open(path).with_context(|| format!("open canonical artifact {}", path.display()))?;
    let mut framed = Vec::new();
    file.by_ref()
        .take(u64::try_from(MAX_INPUT_BYTES + 2).unwrap_or(u64::MAX))
        .read_to_end(&mut framed)
        .with_context(|| format!("read canonical artifact {}", path.display()))?;
    ensure!(
        framed.len() <= MAX_INPUT_BYTES + 1,
        "canonical artifact {} exceeds the bounded record size",
        path.display()
    );
    ensure!(
        framed.last() == Some(&b'\n'),
        "canonical artifact {} must end with exactly one LF",
        path.display()
    );
    framed.pop();
    ensure!(
        !framed.is_empty(),
        "canonical artifact {} contains an empty record",
        path.display()
    );
    require_canonical(&framed)
        .with_context(|| format!("validate canonical artifact {}", path.display()))?;
    Ok(framed)
}

fn ready_output(ready: &ReadyGenericSuccessor) -> Value {
    json!({
        "operation": "inspect",
        "state": "ready",
        "current_generation": ready.current_generation,
        "next_generation": ready.next_generation,
        "current_head": registry_head_output(&ready.current_head),
        "current_activation_policy": registry_reference_output(&ready.current_activation_policy),
    })
}

fn accepted_output(
    operation: &'static str,
    state: &'static str,
    accepted: &AcceptedGenericSuccessorActivation,
) -> Value {
    json!({
        "operation": operation,
        "state": state,
        "statement_id": accepted.statement_id.to_string(),
        "activation_id": accepted.activation_id.to_string(),
        "accepted_event_id": accepted.accepted_event_id.to_string(),
        "from_generation": accepted.from_generation,
        "to_generation": accepted.to_generation,
        "predecessor_head": registry_head_output(&accepted.predecessor_head),
        "registry_head": registry_head_output(&accepted.registry_head),
        "epoch_id": accepted.append_position.epoch_id.to_string(),
        "control_shard": accepted.append_position.shard,
        "committed_offset": accepted.append_position.committed_offset.as_u64().to_string(),
        "accepted_at": accepted.accepted_at.as_str(),
    })
}

fn registry_head_output(head: &RegistryHeadBindingV1) -> Value {
    json!({
        "activation_id": head.head.activation_id.to_string(),
        "package_digest": head.head.package_digest.to_string(),
        "activation_policy_digest": head.head.activation_policy_digest.to_string(),
        "effective_from": head.effective_from.as_str(),
        "effective_until": head.effective_until.as_ref().map(CanonicalTimestamp::as_str),
    })
}

fn registry_reference_output(reference: &RegistryReferenceV1) -> Value {
    json!({
        "entry_id": reference.entry_id.as_str(),
        "version": reference.version,
        "entry_digest": reference.entry_digest.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::ffi::OsStr;
    use std::fs;
    use std::io::Write as _;
    use std::process::Command as ProcessCommand;
    use std::str::FromStr as _;

    use clap::Parser as _;
    use ostk_fleet_recall::memory_contracts::bootstrap::{
        AppendPositionV1, CommittedOffsetV1, EpochId,
    };
    use ostk_fleet_recall::memory_contracts::common::ContractId;
    use ostk_fleet_recall::memory_contracts::digest::Sha256Digest;
    use ostk_fleet_recall::memory_contracts::evidence::AcceptedEventId;
    use ostk_fleet_recall::memory_contracts::genesis_activation::RegistryTestResultDigest;
    use ostk_fleet_recall::memory_contracts::registry::RegistryHeadV1;
    use ostk_fleet_recall::memory_contracts::successor_generic::{
        GenericSuccessorActivationId, GenericSuccessorActivationStatementId,
    };
    use sqlx::ConnectOptions as _;

    use super::*;

    const CURRENT_PACKAGE: &str =
        "contracts/dynamic-memory/v2/stage4-successor/registry-package.jsonl";
    const EXPECTED_HEAD: &str =
        "contracts/dynamic-memory/v2/successor-activation/activated-head.jsonl";
    const TARGET_PACKAGE: &str =
        "contracts/dynamic-memory/v3/successor-generic/generation-2-package.jsonl";
    const TARGET_TEST_RESULT: &str =
        "contracts/dynamic-memory/v3/successor-generic/activation-test-result.jsonl";
    const STATEMENT: &str =
        "contracts/dynamic-memory/v3/successor-generic/activation-statement.jsonl";
    const APPROVAL_SET: &str =
        "contracts/dynamic-memory/v3/successor-generic/activation-approval-set.jsonl";

    const BOOTSTRAP_RECEIPT_DIGEST: &str =
        "084ee06ea7ebf3b1d592d6e5843584485144c0ee5720fcc2124a61a7fcde48f0";
    const TARGET_TEST_RESULT_DIGEST: &str =
        "92fa5a109739a2509c57104d50f0c13416295380aee9e7f81f860dad2d1d08d7";
    const TARGET_RUNNER_ARTIFACT_DIGEST: &str =
        "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
    const TARGET_RUNNER_CONFIGURATION_DIGEST: &str =
        "a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2";
    const GENERATION_2_PACKAGE_DIGEST: &str =
        "49fb2c6db81008b5ed8acd781e297e7d0a3ed49f6b1ff639618cd7d83296190a";
    const EXPLICIT_URL: &str = "postgresql://generic:explicit-secret@cluster.example:26257/fleet_recall?sslmode=verify-full";
    const SUBPROCESS_CASE: &str = "FLEET_RECALL_GENERIC_SUCCESSOR_SUBPROCESS_CASE";

    fn digest(value: &str) -> Sha256Digest {
        Sha256Digest::from_str(value).unwrap()
    }

    fn artifact_args() -> ArtifactArgs {
        ArtifactArgs {
            current_package: CURRENT_PACKAGE.into(),
            expected_head: EXPECTED_HEAD.into(),
            target_package: TARGET_PACKAGE.into(),
            target_test_result: TARGET_TEST_RESULT.into(),
            activation_statement: STATEMENT.into(),
            activation_approval_set: APPROVAL_SET.into(),
        }
    }

    fn fixture_scope() -> AuthenticatedProjectScopeV1 {
        let statement: GenericSuccessorActivationStatementV2 =
            decode_strict(&read_framed_canonical_record(Path::new(STATEMENT)).unwrap()).unwrap();
        statement.scope
    }

    fn fixture_authority(scope: &AuthenticatedProjectScopeV1) -> ArtifactAuthority<'_> {
        ArtifactAuthority {
            semantic_scope: scope,
            bootstrap_receipt_digest: BootstrapReceiptDigest::from_digest(digest(
                BOOTSTRAP_RECEIPT_DIGEST,
            )),
            target_test_runner_pin: GenericSuccessorTestRunnerPin::from_trusted_config(
                digest(TARGET_RUNNER_ARTIFACT_DIGEST),
                digest(TARGET_RUNNER_CONFIGURATION_DIGEST),
                RegistryTestResultDigest::from_digest(digest(TARGET_TEST_RESULT_DIGEST)),
            ),
            principal_binding: GenericSuccessorPrincipalBinding::from_trusted_config(
                ContractId::new("principal.proposer").unwrap(),
                ContractId::new("principal.author").unwrap(),
            ),
        }
    }

    fn assert_exact_keys(value: &Value, expected: &[&str]) {
        let object = value.as_object().unwrap();
        let actual: BTreeSet<&str> = object.keys().map(String::as_str).collect();
        let expected: BTreeSet<&str> = expected.iter().copied().collect();
        assert_eq!(actual, expected);
    }

    #[test]
    fn accepts_all_six_bounded_framed_canonical_fixtures() {
        for path in [
            CURRENT_PACKAGE,
            EXPECTED_HEAD,
            TARGET_PACKAGE,
            TARGET_TEST_RESULT,
            STATEMENT,
            APPROVAL_SET,
        ] {
            let record = read_framed_canonical_record(Path::new(path)).unwrap();
            assert_eq!(record.last(), Some(&b'}'));
            require_canonical(&record).unwrap();
        }
    }

    #[test]
    fn rejects_missing_additional_or_oversize_record_framing() {
        for value in [b"{}".as_slice(), b"{}\r\n", b"{}\n\n"] {
            let mut file = tempfile::NamedTempFile::new().unwrap();
            file.write_all(value).unwrap();
            assert!(read_framed_canonical_record(file.path()).is_err());
        }
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&vec![b' '; MAX_INPUT_BYTES + 1]).unwrap();
        file.write_all(b"\n").unwrap();
        assert!(read_framed_canonical_record(file.path()).is_err());
    }

    #[test]
    fn closes_the_complete_generic_ceremony_before_connect() {
        let scope = fixture_scope();
        let verified = verify_artifacts(&artifact_args(), &fixture_authority(&scope)).unwrap();
        assert_eq!(verified.target_generation, 2);
        assert_eq!(
            verified.expected_head.head.package_digest.to_string(),
            "16f98d5df93b74dab5b2188274cbd1da21d089ff7a64cd8fc29679946e7fe2c9"
        );
        let target: GenericSuccessorActivationStatementV2 =
            decode_strict(verified.candidate.canonical_statement()).unwrap();
        assert_eq!(
            target.target_package_digest.to_string(),
            GENERATION_2_PACKAGE_DIGEST
        );
    }

    #[test]
    fn raw_deployment_pins_fail_closed() {
        let scope = fixture_scope();
        let mut authority = fixture_authority(&scope);
        authority.target_test_runner_pin = GenericSuccessorTestRunnerPin::from_trusted_config(
            digest(TARGET_RUNNER_ARTIFACT_DIGEST),
            digest(TARGET_RUNNER_CONFIGURATION_DIGEST),
            RegistryTestResultDigest::from_digest(digest(&"00".repeat(32))),
        );
        assert!(verify_artifacts(&artifact_args(), &authority).is_err());

        let mut authority = fixture_authority(&scope);
        authority.principal_binding = GenericSuccessorPrincipalBinding::from_trusted_config(
            ContractId::new("principal.intruder").unwrap(),
            ContractId::new("principal.author").unwrap(),
        );
        let error = verify_artifacts(&artifact_args(), &authority)
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("not closed over the deployment-bound offline authority"));
    }

    #[test]
    fn active_package_must_be_the_package_the_expected_head_installs() {
        let scope = fixture_scope();
        let mut paths = artifact_args();
        // The generation-2 package is a real package, but it is not the one the
        // frozen generation-1 head installs.
        paths.current_package = TARGET_PACKAGE.into();
        let error = verify_artifacts(&paths, &fixture_authority(&scope))
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("not the package the expected open head installs"));
    }

    #[test]
    fn approval_set_must_bind_the_exact_statement_before_connection() {
        let scope = fixture_scope();
        let mut approval_set: GenericSuccessorActivationApprovalSetV2 =
            decode_strict(&read_framed_canonical_record(Path::new(APPROVAL_SET)).unwrap()).unwrap();
        let other_id = GenericSuccessorActivationStatementId::from_digest(digest(&"aa".repeat(32)));
        approval_set.statement_id = other_id;
        for approval in &mut approval_set.approvals {
            approval.statement_id = other_id;
        }
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("wrong-approval-set.jsonl");
        let mut bytes = encode_canonical(&approval_set).unwrap();
        bytes.push(b'\n');
        fs::write(&path, bytes).unwrap();
        let mut paths = artifact_args();
        paths.activation_approval_set = path;
        let error = verify_artifacts(&paths, &fixture_authority(&scope))
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("does not bind the exact statement"));
    }

    #[test]
    fn tampered_approval_signature_fails_before_connection() {
        let scope = fixture_scope();
        let mut approval_set: GenericSuccessorActivationApprovalSetV2 =
            decode_strict(&read_framed_canonical_record(Path::new(APPROVAL_SET)).unwrap()).unwrap();
        let mut flipped = *approval_set.approvals[0].signature.as_bytes();
        flipped[0] ^= 0x01;
        approval_set.approvals[0].signature =
            ostk_fleet_recall::memory_contracts::common::FixedHex64::from_bytes(flipped);
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("tampered-approval-set.jsonl");
        let mut bytes = encode_canonical(&approval_set).unwrap();
        bytes.push(b'\n');
        fs::write(&path, bytes).unwrap();
        let mut paths = artifact_args();
        paths.activation_approval_set = path;
        let error = verify_artifacts(&paths, &fixture_authority(&scope))
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("generic approval signature is invalid"));
    }

    #[test]
    fn malformed_artifact_fails_before_database_url_parsing() {
        let scope = fixture_scope();
        let mut paths = artifact_args();
        let malformed = tempfile::NamedTempFile::new().unwrap();
        fs::write(malformed.path(), b"not-json\n").unwrap();
        paths.activation_statement = malformed.path().to_owned();
        let error = prepare_execution(&paths, &fixture_authority(&scope), "not-a-database-url")
            .err()
            .unwrap()
            .to_string();
        assert!(!error.contains("PostgreSQL"));
        assert!(!error.contains("database URL"));
    }

    #[test]
    fn source_keeps_lazy_repository_construction_before_the_first_acquire() {
        let source = include_str!("ostk-registry-generic-successor-activate.rs");
        let prepare = source.find("fn prepare_execution(").unwrap();
        let prepare_source = &source[prepare..];
        let verify = prepare_source
            .find("let artifacts = verify_artifacts")
            .unwrap();
        let options = prepare_source
            .find("let connect_options = private_postgres_connect_options(")
            .unwrap();
        assert!(verify < options);

        let main = source.find("async fn main()").unwrap();
        let main_source = &source[main..prepare];
        let lazy = main_source.find(".connect_lazy_with(").unwrap();
        let repository = main_source
            .find("CockroachGenericSuccessorRepository::new(")
            .unwrap();
        let acquire = main_source.find("let connection = pool").unwrap();
        assert!(lazy < repository && repository < acquire);
        let eager_pool_helper = [".connect_", "with("].concat();
        assert!(!source.contains(&eager_pool_helper));
        assert!(source.contains(".max_connections(MAX_CONNECTIONS)"));
        assert!(source.contains(".min_connections(0)"));
    }

    #[test]
    fn parser_exposes_only_apply_and_inspect() {
        assert!(Cli::try_parse_from(["ostk-registry-generic-successor-activate", "emit"]).is_err());
        assert!(Cli::try_parse_from(["ostk-registry-generic-successor-activate", "sign"]).is_err());
        assert!(
            Cli::try_parse_from(["ostk-registry-generic-successor-activate", "resolve"]).is_err()
        );
    }

    #[test]
    fn output_is_exact_bounded_and_redacted() {
        let head = |seed: &str| RegistryHeadBindingV1 {
            head: RegistryHeadV1 {
                activation_id: digest(&seed.repeat(32)),
                package_digest: digest(&"22".repeat(32)),
                activation_policy_digest: digest(&"33".repeat(32)),
            },
            effective_from: CanonicalTimestamp::parse("2026-08-15T04:10:00.000000000Z").unwrap(),
            effective_until: None,
        };
        let ready = ready_output(&ReadyGenericSuccessor {
            current_generation: 1,
            next_generation: 2,
            current_head: head("11"),
            current_activation_policy: RegistryReferenceV1 {
                entry_id: ContractId::new("activation.default").unwrap(),
                version: 2,
                entry_digest: digest(&"33".repeat(32)),
            },
        });
        assert_exact_keys(
            &ready,
            &[
                "operation",
                "state",
                "current_generation",
                "next_generation",
                "current_head",
                "current_activation_policy",
            ],
        );
        assert_exact_keys(
            &ready["current_head"],
            &[
                "activation_id",
                "package_digest",
                "activation_policy_digest",
                "effective_from",
                "effective_until",
            ],
        );
        assert_eq!(ready["state"], "ready");
        assert!(serde_json::to_string(&ready).unwrap().len() < 4_096);

        let accepted = AcceptedGenericSuccessorActivation {
            statement_id: GenericSuccessorActivationStatementId::from_digest(digest(
                &"55".repeat(32),
            )),
            activation_id: GenericSuccessorActivationId::from_digest(digest(&"66".repeat(32))),
            accepted_event_id: AcceptedEventId::from_digest(digest(&"77".repeat(32))),
            from_generation: 1,
            to_generation: 2,
            predecessor_head: head("11"),
            registry_head: head("99"),
            append_position: AppendPositionV1 {
                epoch_id: EpochId::from_digest(digest(&"88".repeat(32))),
                shard: 7,
                committed_offset: CommittedOffsetV1::new(42).unwrap(),
            },
            accepted_at: CanonicalTimestamp::parse("2026-08-16T04:11:00.000000000Z").unwrap(),
        };
        for (operation, state) in [
            ("inspect", "accepted"),
            ("apply", "inserted"),
            ("apply", "exact_replay"),
        ] {
            let output = accepted_output(operation, state, &accepted);
            assert_exact_keys(
                &output,
                &[
                    "operation",
                    "state",
                    "statement_id",
                    "activation_id",
                    "accepted_event_id",
                    "from_generation",
                    "to_generation",
                    "predecessor_head",
                    "registry_head",
                    "epoch_id",
                    "control_shard",
                    "committed_offset",
                    "accepted_at",
                ],
            );
            assert_eq!(output["operation"], operation);
            assert_eq!(output["state"], state);
            assert_eq!(output["committed_offset"], "42");
            assert!(output["control_shard"].is_number());
            let serialized = serde_json::to_string(&output).unwrap();
            assert!(serialized.len() < 4_096);
            for forbidden in [
                "postgresql://",
                "explicit-secret",
                "signature",
                "canonical",
                "artifact",
                "principal.",
            ] {
                assert!(!serialized.contains(forbidden));
            }
        }
    }

    #[test]
    fn postgres_environment_and_pgpass_are_isolated_in_subprocesses() {
        let test_executable = std::env::current_exe().unwrap();

        let mut pg = ProcessCommand::new(&test_executable);
        remove_inherited_pg_environment(&mut pg);
        pg.arg("--exact")
            .arg("tests::postgres_environment_subprocess_probe")
            .arg("--nocapture")
            .env(SUBPROCESS_CASE, "pg")
            .env("PGOPTIONS", "-c search_path=attacker")
            .env("pGsSlKeY", "super-secret-poison");
        let output = pg.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );

        let home = tempfile::tempdir().unwrap();
        let pgpass_path = home.path().join(".pgpass");
        fs::write(
            &pgpass_path,
            "cluster.example:26257:fleet_recall:generic:poisoned-passfile-secret\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            fs::set_permissions(&pgpass_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let mut pgpass = ProcessCommand::new(test_executable);
        remove_inherited_pg_environment(&mut pgpass);
        pgpass
            .arg("--exact")
            .arg("tests::postgres_environment_subprocess_probe")
            .arg("--nocapture")
            .env(SUBPROCESS_CASE, "pgpass")
            .env("HOME", home.path());
        let output = pgpass.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn remove_inherited_pg_environment(command: &mut ProcessCommand) {
        for (name, _) in std::env::vars_os() {
            if has_pg_prefix(&name) {
                command.env_remove(name);
            }
        }
    }

    fn has_pg_prefix(name: &OsStr) -> bool {
        let bytes = name.as_encoded_bytes();
        bytes.len() >= 2
            && bytes[0].eq_ignore_ascii_case(&b'p')
            && bytes[1].eq_ignore_ascii_case(&b'g')
    }

    #[test]
    fn postgres_environment_subprocess_probe() {
        let Ok(case) = std::env::var(SUBPROCESS_CASE) else {
            return;
        };
        match case.as_str() {
            "pg" => {
                let scope = fixture_scope();
                let error = prepare_execution(
                    &artifact_args(),
                    &fixture_authority(&scope),
                    "not-a-database-url",
                )
                .err()
                .unwrap()
                .to_string();
                assert!(error.contains("\"PGOPTIONS\""));
                assert!(error.contains("\"pGsSlKeY\""));
                assert!(!error.contains("database URL"));
                assert!(!error.contains("attacker"));
                assert!(!error.contains("super-secret-poison"));
            }
            "pgpass" => {
                let options = private_postgres_connect_options(
                    EXPLICIT_URL,
                    APPLICATION_NAME,
                    PrivatePostgresSslPolicy::VerifyFull,
                )
                .unwrap();
                let rendered = options.to_url_lossy();
                assert_eq!(rendered.password(), Some("explicit%2Dsecret"));
                assert!(!rendered.as_str().contains("poisoned"));
                assert_eq!(options.get_application_name(), Some(APPLICATION_NAME));
            }
            other => panic!("unknown subprocess case {other}"),
        }
    }
}
