//! Workstation-only, deployment-authorized first-successor registry activation.
//!
//! This binary has no public server route. Physical scope, semantic scope,
//! artifact pins, conformance-runner identities, and ceremony principals come
//! only from the dedicated successor environment configuration. The CLI
//! accepts paths to the eight canonical ceremony artifacts and no authority or
//! transport overrides.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, anyhow, ensure};
use clap::{Args, Parser, Subcommand};
use ostk_fleet_recall::config::{SuccessorActivationConfig, SuccessorActivationRuntimeConfig};
use ostk_fleet_recall::memory_contracts::bootstrap::{
    BootstrapPin, BootstrapReceiptDigest, BootstrapReceiptV1, VerifiedBootstrapReceipt,
    verify_pinned_bootstrap,
};
use ostk_fleet_recall::memory_contracts::canonical::{
    MAX_INPUT_BYTES, decode_strict, encode_canonical, require_canonical,
};
use ostk_fleet_recall::memory_contracts::common::{
    AuthenticatedProjectScopeV1, CanonicalTimestamp, ProfileReferenceV1, RegistryReferenceV1,
    frozen_profile_reference_v1,
};
use ostk_fleet_recall::memory_contracts::digest::{DigestDomain, domain_separated_digest};
use ostk_fleet_recall::memory_contracts::genesis::SemanticallyClosedGenesisPackage;
use ostk_fleet_recall::memory_contracts::genesis_activation::{
    GenesisActivationPrincipalBinding, RegistryTestRunnerPin, VerifiedRegistryTestResult,
    verify_registry_test_result,
};
use ostk_fleet_recall::memory_contracts::registry::{
    ManifestVerifiedRegistryPackage, RegistryEntryKind,
};
use ostk_fleet_recall::memory_contracts::stage4_target_package::SemanticallyClosedStage4Package;
use ostk_fleet_recall::memory_contracts::successor_activation::{
    SuccessorActivationPrincipalBinding, SuccessorRegistryActivationApprovalSetV1,
    SuccessorRegistryActivationStatementV1, SuccessorRegistryTestRunnerPin,
    VerifiedSuccessorRegistryTestResult, verify_successor_registry_test_result,
};
use ostk_fleet_recall::memory_contracts::successor_package::SemanticallyClosedSuccessorPackage;
use ostk_fleet_recall::memory_contracts::successor_policy::{
    ActivationSignatureAlgorithmV2, GenesisSuccessorKeyBridgeDigest, GenesisSuccessorKeyBridgePin,
    GenesisSuccessorKeyBridgeV1,
};
use ostk_fleet_recall::private_postgres::{
    PrivatePostgresSslPolicy, private_postgres_connect_options,
};
use ostk_fleet_recall::registry_activation::{
    AcceptedSuccessorActivation, CockroachSuccessorActivationRepository, ReadySuccessorActivation,
    SuccessorActivationCandidate, SuccessorActivationInspection, SuccessorActivationOutcome,
    SuccessorActivationRepository,
};
use ostk_fleet_recall::store::cockroach::RetryPolicy;
use ring::signature;
use serde_json::{Value, json};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

const APPLICATION_NAME: &str = "ostk-registry-successor-activate";
const MAX_CONNECTIONS: u32 = 2;
const SUCCESSOR_APPROVAL_SIGNATURE_PREFIX: &[u8] =
    b"ostk-registry-successor-activation-approval-signature-v1\0";

#[derive(Debug, Parser)]
#[command(
    name = "ostk-registry-successor-activate",
    version,
    about = "Private, workstation-authorized first-successor registry activation"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Audit the bound registry and atomically install its first successor.
    Apply(ArtifactArgs),
    /// Audit the bound registry and report successor readiness or acceptance.
    Inspect(ArtifactArgs),
}

#[derive(Debug, Args)]
struct ArtifactArgs {
    /// Canonical bootstrap receipt encoded as one JSON record plus one LF.
    #[arg(long, value_name = "PATH")]
    bootstrap_receipt: PathBuf,
    /// Canonical, semantically closed genesis package as one JSON record plus one LF.
    #[arg(long, value_name = "PATH")]
    genesis_package: PathBuf,
    /// Canonical, deployment-pinned genesis test result as one JSON record plus one LF.
    #[arg(long, value_name = "PATH")]
    genesis_test_result: PathBuf,
    /// Canonical, semantically closed Stage-4 target package as one JSON record plus one LF.
    #[arg(long, value_name = "PATH")]
    target_package: PathBuf,
    /// Canonical, deployment-pinned target test result as one JSON record plus one LF.
    #[arg(long, value_name = "PATH")]
    target_test_result: PathBuf,
    /// Canonical, deployment-pinned one-time genesis key bridge plus one LF.
    #[arg(long, value_name = "PATH")]
    genesis_key_bridge: PathBuf,
    /// Canonical successor-activation statement as one JSON record plus one LF.
    #[arg(long, value_name = "PATH")]
    activation_statement: PathBuf,
    /// Canonical detached successor approval set as one JSON record plus one LF.
    #[arg(long, value_name = "PATH")]
    activation_approval_set: PathBuf,
}

struct ArtifactAuthority<'a> {
    semantic_scope: &'a AuthenticatedProjectScopeV1,
    bootstrap_receipt_digest: BootstrapReceiptDigest,
    bootstrap_pin: BootstrapPin,
    genesis_test_runner_pin: RegistryTestRunnerPin,
    target_test_runner_pin: SuccessorRegistryTestRunnerPin,
    bridge_digest: GenesisSuccessorKeyBridgeDigest,
    bridge_pin: GenesisSuccessorKeyBridgePin,
    genesis_principal_binding: GenesisActivationPrincipalBinding,
    successor_principal_binding: SuccessorActivationPrincipalBinding,
}

impl<'a> ArtifactAuthority<'a> {
    fn from_config(config: &'a SuccessorActivationConfig) -> Self {
        Self {
            semantic_scope: config.trusted_scope().semantic_scope(),
            bootstrap_receipt_digest: config.bootstrap_receipt_digest(),
            bootstrap_pin: config.bootstrap_pin(),
            genesis_test_runner_pin: config.genesis_test_runner_pin(),
            target_test_runner_pin: config.target_test_runner_pin(),
            bridge_digest: config.genesis_key_bridge_digest(),
            bridge_pin: config.genesis_key_bridge_pin(),
            genesis_principal_binding: config.genesis_principal_binding(),
            successor_principal_binding: config.successor_principal_binding(),
        }
    }
}

struct VerifiedArtifacts {
    bootstrap: VerifiedBootstrapReceipt,
    genesis_package: SemanticallyClosedGenesisPackage,
    genesis_test_result: VerifiedRegistryTestResult,
    target_package: SemanticallyClosedStage4Package,
    canonical_target_test_result: Vec<u8>,
    canonical_bridge: Vec<u8>,
    candidate: SuccessorActivationCandidate,
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

    // This is the pre-connect trust boundary. All eight files are bounded,
    // raw-pin checked where deployment pins exist, canonically decoded,
    // semantically closed, and cross-bound before sqlx options are parsed.
    let prepared = prepare_execution(args, &authority, config.database_url())?;
    let artifacts = prepared.artifacts;
    let pool = PgPoolOptions::new()
        .max_connections(MAX_CONNECTIONS)
        .min_connections(0)
        .acquire_timeout(Duration::from_secs(10))
        .connect_lazy_with(prepared.connect_options);
    let repository = CockroachSuccessorActivationRepository::new(
        pool.clone(),
        config.authority().trusted_scope().clone(),
        RetryPolicy::default(),
        artifacts.bootstrap,
        artifacts.genesis_package,
        artifacts.genesis_test_result,
        authority.genesis_principal_binding,
        artifacts.target_package,
        &artifacts.canonical_target_test_result,
        authority.target_test_runner_pin,
        artifacts.canonical_bridge,
        authority.bridge_pin,
        authority.successor_principal_binding,
    )?;

    // Constructing the lazy pool and repository opens no socket. This explicit
    // acquire is the first network operation, after every offline constructor
    // has succeeded; its error deliberately reveals no URL or credential.
    let connection = pool
        .acquire()
        .await
        .map_err(|_| anyhow!("connect private successor activation database failed"))?;
    drop(connection);

    // Offline signature checks authenticate the candidate against the pinned
    // bridge bytes. Only this repository call authenticates that bridge
    // against the locked durable genesis root and re-verifies signatures in
    // the same SERIALIZABLE transaction as freshness and the head CAS.
    let output = match cli.command {
        Command::Apply(_) => match repository
            .activate_first_successor(&artifacts.candidate)
            .await?
        {
            SuccessorActivationOutcome::Inserted(accepted) => {
                accepted_output("apply", "inserted", &accepted)
            }
            SuccessorActivationOutcome::ExactReplay(accepted) => {
                accepted_output("apply", "exact_replay", &accepted)
            }
        },
        Command::Inspect(_) => match repository
            .inspect_first_successor(&artifacts.candidate)
            .await?
        {
            SuccessorActivationInspection::Ready(ready) => ready_output(&ready),
            SuccessorActivationInspection::Accepted(accepted) => {
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
    // Authenticate raw receipt bytes before trusting decoded selectors. The LF
    // framing is deliberately excluded from the contract digest.
    let receipt_bytes = read_framed_canonical_record(&paths.bootstrap_receipt)?;
    let actual_receipt_digest = BootstrapReceiptDigest::from_digest(domain_separated_digest(
        DigestDomain::BootstrapReceipt,
        &receipt_bytes,
    ));
    ensure!(
        actual_receipt_digest == authority.bootstrap_receipt_digest,
        "bootstrap receipt does not match the deployment pin"
    );
    let receipt: BootstrapReceiptV1 = decode_strict(&receipt_bytes)?;
    let expected_profile = frozen_profile_reference_v1();
    ensure!(
        receipt.statement.profile == expected_profile,
        "bootstrap receipt names a canonical profile this binary does not implement"
    );

    let genesis_package_bytes = read_framed_canonical_record(&paths.genesis_package)?;
    let genesis_manifest =
        ManifestVerifiedRegistryPackage::decode(&genesis_package_bytes, &expected_profile)?;
    let genesis_package =
        SemanticallyClosedGenesisPackage::from_manifest_verified(genesis_manifest)?;
    let bootstrap = verify_pinned_bootstrap(
        &receipt_bytes,
        authority.bootstrap_pin,
        &expected_profile,
        authority.semantic_scope,
        &genesis_package,
    )?;

    let genesis_test_result_bytes = read_framed_canonical_record(&paths.genesis_test_result)?;
    let genesis_test_result = verify_registry_test_result(
        &genesis_test_result_bytes,
        authority.genesis_test_runner_pin,
        &expected_profile,
        &genesis_package,
    )?;

    let target_package_bytes = read_framed_canonical_record(&paths.target_package)?;
    let target_manifest =
        ManifestVerifiedRegistryPackage::decode(&target_package_bytes, &expected_profile)?;
    let generic_target =
        SemanticallyClosedSuccessorPackage::from_manifest_verified(target_manifest)?;
    let target_package = SemanticallyClosedStage4Package::from_successor_package(generic_target)?;

    let target_test_result_bytes = read_framed_canonical_record(&paths.target_test_result)?;
    let target_test_result = verify_successor_registry_test_result(
        &target_test_result_bytes,
        authority.target_test_runner_pin,
        &target_package,
    )?;

    let bridge_bytes = read_framed_canonical_record(&paths.genesis_key_bridge)?;
    let bridge = verify_offline_bridge_candidate(
        &bridge_bytes,
        authority,
        &genesis_package,
        &expected_profile,
    )?;

    let statement_bytes = read_framed_canonical_record(&paths.activation_statement)?;
    let approval_set_bytes = read_framed_canonical_record(&paths.activation_approval_set)?;
    verify_offline_successor_candidate(
        &statement_bytes,
        &approval_set_bytes,
        authority,
        &genesis_package,
        &target_package,
        &target_test_result,
        &bridge,
        &expected_profile,
    )?;
    let candidate = SuccessorActivationCandidate::from_bounded_canonical_bytes(
        statement_bytes,
        approval_set_bytes,
    )?;

    Ok(VerifiedArtifacts {
        bootstrap,
        genesis_package,
        genesis_test_result,
        target_package,
        canonical_target_test_result: target_test_result_bytes,
        canonical_bridge: bridge_bytes,
        candidate,
    })
}

fn verify_offline_bridge_candidate(
    input: &[u8],
    authority: &ArtifactAuthority<'_>,
    genesis_package: &SemanticallyClosedGenesisPackage,
    expected_profile: &ProfileReferenceV1,
) -> anyhow::Result<GenesisSuccessorKeyBridgeV1> {
    let actual_digest = GenesisSuccessorKeyBridgeDigest::from_digest(domain_separated_digest(
        DigestDomain::GenesisSuccessorKeyBridgeV1,
        input,
    ));
    ensure!(
        actual_digest == authority.bridge_digest,
        "genesis successor key bridge does not match the deployment pin"
    );
    require_canonical(input)?;
    let bridge: GenesisSuccessorKeyBridgeV1 = decode_strict(input)?;
    bridge.validate_shape()?;
    ensure!(
        encode_canonical(&bridge)? == input,
        "genesis successor key bridge did not round-trip canonically"
    );

    let registry = genesis_package.manifest_verified_package().package();
    let policy_entry = registry
        .entries
        .iter()
        .find(|entry| entry.kind == RegistryEntryKind::ActivationPolicy)
        .ok_or_else(|| anyhow!("genesis activation policy is missing"))?;
    let expected_policy = RegistryReferenceV1 {
        entry_id: policy_entry.entry_id.clone(),
        version: policy_entry.version,
        entry_digest: policy_entry.digest()?,
    };
    let bridge_principals = bridge
        .key_map
        .iter()
        .map(|binding| &binding.principal_id)
        .collect::<Vec<_>>();
    let genesis_principals = genesis_package
        .activation_policy()
        .eligible_principal_ids()
        .iter()
        .collect::<Vec<_>>();
    ensure!(
        bridge.profile == *expected_profile
            && bridge.scope == *authority.semantic_scope
            && bridge.genesis_registry_head.head.package_digest == genesis_package.package_digest()
            && bridge.current_v1_activation_policy == expected_policy
            && bridge_principals == genesis_principals,
        "genesis successor key bridge is not closed over the bound offline genesis authority"
    );
    Ok(bridge)
}

#[allow(clippy::too_many_arguments)]
fn verify_offline_successor_candidate(
    canonical_statement: &[u8],
    canonical_approval_set: &[u8],
    authority: &ArtifactAuthority<'_>,
    genesis_package: &SemanticallyClosedGenesisPackage,
    target: &SemanticallyClosedStage4Package,
    test_result: &VerifiedSuccessorRegistryTestResult,
    bridge: &GenesisSuccessorKeyBridgeV1,
    expected_profile: &ProfileReferenceV1,
) -> anyhow::Result<()> {
    require_canonical(canonical_statement)?;
    let statement: SuccessorRegistryActivationStatementV1 = decode_strict(canonical_statement)?;
    statement.validate_shape()?;
    ensure!(
        encode_canonical(&statement)? == canonical_statement,
        "successor activation statement did not round-trip canonically"
    );

    let statement_binding = SuccessorActivationPrincipalBinding::from_trusted_config(
        statement.proposer_principal_id.clone(),
        statement.package_author_principal_id.clone(),
    );
    let target_registry = target
        .successor_package()
        .manifest_verified_package()
        .package();
    ensure!(
        statement.profile == *expected_profile
            && statement.profile == target_registry.profile
            && statement.scope == *authority.semantic_scope
            && statement.scope == bridge.scope
            && statement.expected_predecessor_head == bridge.genesis_registry_head
            && statement.current_v1_activation_policy == bridge.current_v1_activation_policy
            && statement.target_package_digest == target.package_digest()
            && statement.target_activation_policy
                == *target.activation_policy().registry_reference()
            && statement.test_vector_result_digest == test_result.result_digest()
            && statement.genesis_successor_key_bridge_digest == authority.bridge_digest
            && statement.from_generation == bridge.from_generation
            && statement.to_generation == bridge.to_generation
            && test_result.result().profile == statement.profile
            && test_result.result().package_digest == statement.target_package_digest
            && test_result.result().completed_at <= statement.effective_from
            && statement_binding == authority.successor_principal_binding,
        "successor activation statement is not closed over the deployment-bound offline authority"
    );

    require_canonical(canonical_approval_set)?;
    let approval_set: SuccessorRegistryActivationApprovalSetV1 =
        decode_strict(canonical_approval_set)?;
    approval_set.validate_shape()?;
    ensure!(
        encode_canonical(&approval_set)? == canonical_approval_set,
        "successor approval set did not round-trip canonically"
    );
    let statement_id = statement.statement_id()?;
    ensure!(
        approval_set.statement_id == statement_id
            && approval_set.approvals.len() <= bridge.key_map.len(),
        "successor approval set does not bind the exact statement and bridge"
    );

    let mut signature_message = SUCCESSOR_APPROVAL_SIGNATURE_PREFIX.to_vec();
    signature_message.extend_from_slice(statement_id.digest().as_bytes());
    let mut approving_principals = Vec::with_capacity(approval_set.approvals.len());
    for approval in &approval_set.approvals {
        let signer = bridge
            .key_map
            .iter()
            .find(|binding| binding.principal_id == approval.signer_principal_id)
            .ok_or_else(|| anyhow!("successor approval signer is not in the pinned bridge"))?;
        match signer.algorithm {
            ActivationSignatureAlgorithmV2::Ed25519 => {
                signature::UnparsedPublicKey::new(
                    &signature::ED25519,
                    signer.public_key.as_bytes(),
                )
                .verify(&signature_message, approval.signature.as_bytes())
                .map_err(|_| anyhow!("successor approval signature is invalid"))?;
            }
        }
        approving_principals.push(signer.principal_id.clone());
    }
    let policy = genesis_package.activation_policy();
    ensure!(
        approving_principals.len() >= usize::from(policy.approval_threshold())
            && approving_principals
                .iter()
                .any(|principal| principal != &statement.package_author_principal_id),
        "successor approval set does not satisfy the offline genesis policy"
    );
    Ok(())
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

fn ready_output(ready: &ReadySuccessorActivation) -> Value {
    json!({
        "operation": "inspect",
        "state": "ready",
        "genesis_head": registry_head_output(&ready.genesis_head),
        "genesis_key_bridge_digest": ready.bridge_digest.to_string(),
    })
}

fn accepted_output(
    operation: &'static str,
    state: &'static str,
    accepted: &AcceptedSuccessorActivation,
) -> Value {
    json!({
        "operation": operation,
        "state": state,
        "statement_id": accepted.statement_id.to_string(),
        "activation_id": accepted.activation_id.to_string(),
        "accepted_event_id": accepted.accepted_event_id.to_string(),
        "registry_head": registry_head_output(&accepted.registry_head),
        "epoch_id": accepted.append_position.epoch_id.to_string(),
        "control_shard": accepted.append_position.shard,
        "committed_offset": accepted.append_position.committed_offset.as_u64().to_string(),
        "genesis_key_bridge_digest": accepted.bridge_digest.to_string(),
        "accepted_at": accepted.accepted_at.as_str(),
    })
}

fn registry_head_output(
    head: &ostk_fleet_recall::memory_contracts::evidence_v2::RegistryHeadBindingV1,
) -> Value {
    json!({
        "activation_id": head.head.activation_id.to_string(),
        "package_digest": head.head.package_digest.to_string(),
        "activation_policy_digest": head.head.activation_policy_digest.to_string(),
        "effective_from": head.effective_from.as_str(),
        "effective_until": head.effective_until.as_ref().map(CanonicalTimestamp::as_str),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::ffi::{OsStr, OsString};
    use std::fs::{self, OpenOptions};
    use std::io::Write as _;
    use std::process::Command as ProcessCommand;
    use std::str::FromStr as _;

    use clap::Parser as _;
    use ostk_fleet_recall::memory_contracts::bootstrap::{
        AppendPositionV1, CommittedOffsetV1, EpochId,
    };
    use ostk_fleet_recall::memory_contracts::common::{CanonicalTimestamp, ContractId, FixedHex64};
    use ostk_fleet_recall::memory_contracts::digest::Sha256Digest;
    use ostk_fleet_recall::memory_contracts::evidence::AcceptedEventId;
    use ostk_fleet_recall::memory_contracts::evidence_v2::RegistryHeadBindingV1;
    use ostk_fleet_recall::memory_contracts::genesis_activation::RegistryTestResultDigest;
    use ostk_fleet_recall::memory_contracts::registry::RegistryHeadV1;
    use ostk_fleet_recall::memory_contracts::successor_activation::{
        SuccessorRegistryActivationApprovalV1, SuccessorRegistryActivationId,
        SuccessorRegistryActivationStatementId,
    };
    use ring::signature::{Ed25519KeyPair, KeyPair as _};
    use sha2::{Digest as _, Sha256};
    use sqlx::ConnectOptions as _;

    use super::*;

    const RECEIPT: &str = "contracts/dynamic-memory/v1/bootstrap-receipt.jsonl";
    const GENESIS_PACKAGE: &str = "contracts/dynamic-memory/v1/genesis-registry-package.jsonl";
    const GENESIS_TEST_RESULT: &str =
        "contracts/dynamic-memory/v1/genesis-activation/registry-test-result.jsonl";
    const TARGET_PACKAGE: &str =
        "contracts/dynamic-memory/v2/stage4-successor/registry-package.jsonl";
    const TARGET_TEST_RESULT: &str =
        "contracts/dynamic-memory/v2/successor-activation/registry-test-result.jsonl";
    const BRIDGE: &str =
        "contracts/dynamic-memory/v2/successor-policy/genesis-successor-key-bridge-v1.jsonl";
    const STATEMENT: &str =
        "contracts/dynamic-memory/v2/successor-activation/activation-statement.jsonl";
    const APPROVAL_SET: &str =
        "contracts/dynamic-memory/v2/successor-activation/activation-approval-set.jsonl";
    const RECEIPT_DIGEST: &str = "084ee06ea7ebf3b1d592d6e5843584485144c0ee5720fcc2124a61a7fcde48f0";
    const GENESIS_TEST_RESULT_DIGEST: &str =
        "e91e08070250a722446195b76ee685a9697298b9fdce9809027f120c829b679d";
    const GENESIS_RUNNER_ARTIFACT_DIGEST: &str =
        "c2e5b0653471d35e54600a8d3fbe5613aff4c04e911787c09a25e2b327d4bbbd";
    const GENESIS_RUNNER_CONFIGURATION_DIGEST: &str =
        "1d12aabe349fd0013389f93bf1917b0de6bbd5d2bd7156c85faff0b97360686d";
    const TARGET_TEST_RESULT_DIGEST: &str =
        "e6783b2a018957a5861fe4e0670f55613d1ace35e381a6a9f5190ea9d7fbff8d";
    const TARGET_RUNNER_ARTIFACT_DIGEST: &str =
        "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
    const TARGET_RUNNER_CONFIGURATION_DIGEST: &str =
        "a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2";
    const BRIDGE_DIGEST: &str = "e15309eba5118e21996a7cee6b3780c1a237982bdf4f22460bca4da189ef6592";
    const EXPLICIT_URL: &str = "postgresql://successor:explicit-secret@cluster.example:26257/fleet_recall?sslmode=verify-full";
    const SUBPROCESS_CASE: &str = "FLEET_RECALL_SUCCESSOR_SUBPROCESS_CASE";
    const SUCCESSOR_FIXTURE_ENV_PREFIX: &str = "FLEET_RECALL_SUCCESSOR_CLI_";
    const SUCCESSOR_FIXTURE_DIR_ENV: &str = "FLEET_RECALL_SUCCESSOR_CLI_FIXTURE_DIR";
    const SUCCESSOR_FIXTURE_GENESIS_ACTIVATION_ID_ENV: &str =
        "FLEET_RECALL_SUCCESSOR_CLI_GENESIS_ACTIVATION_ID";
    const SUCCESSOR_FIXTURE_GENESIS_PACKAGE_DIGEST_ENV: &str =
        "FLEET_RECALL_SUCCESSOR_CLI_GENESIS_PACKAGE_DIGEST";
    const SUCCESSOR_FIXTURE_GENESIS_ACTIVATION_POLICY_DIGEST_ENV: &str =
        "FLEET_RECALL_SUCCESSOR_CLI_GENESIS_ACTIVATION_POLICY_DIGEST";
    const SUCCESSOR_FIXTURE_GENESIS_EFFECTIVE_FROM_ENV: &str =
        "FLEET_RECALL_SUCCESSOR_CLI_GENESIS_EFFECTIVE_FROM";
    const SUCCESSOR_FIXTURE_EFFECTIVE_FROM_ENV: &str = "FLEET_RECALL_SUCCESSOR_CLI_EFFECTIVE_FROM";
    const SUCCESSOR_FIXTURE_STALE_EFFECTIVE_FROM_ENV: &str =
        "FLEET_RECALL_SUCCESSOR_CLI_STALE_EFFECTIVE_FROM";
    const SUCCESSOR_FIXTURE_ENV_NAMES: [&str; 7] = [
        SUCCESSOR_FIXTURE_DIR_ENV,
        SUCCESSOR_FIXTURE_GENESIS_ACTIVATION_ID_ENV,
        SUCCESSOR_FIXTURE_GENESIS_PACKAGE_DIGEST_ENV,
        SUCCESSOR_FIXTURE_GENESIS_ACTIVATION_POLICY_DIGEST_ENV,
        SUCCESSOR_FIXTURE_GENESIS_EFFECTIVE_FROM_ENV,
        SUCCESSOR_FIXTURE_EFFECTIVE_FROM_ENV,
        SUCCESSOR_FIXTURE_STALE_EFFECTIVE_FROM_ENV,
    ];
    const MAX_SUCCESSOR_FIXTURE_PATH_BYTES: usize = 4_096;

    const EMITTED_BRIDGE: &str = "genesis-successor-key-bridge.jsonl";
    const EMITTED_BRIDGE_DIGEST: &str = "genesis-successor-key-bridge-digest.txt";
    const EMITTED_STATEMENT: &str = "activation-statement.jsonl";
    const EMITTED_APPROVAL_SET: &str = "activation-approval-set.jsonl";
    const EMITTED_STALE_STATEMENT: &str = "activation-statement-stale.jsonl";
    const EMITTED_STALE_APPROVAL_SET: &str = "activation-approval-set-stale.jsonl";

    fn digest(value: &str) -> Sha256Digest {
        Sha256Digest::from_str(value).unwrap()
    }

    fn artifact_args() -> ArtifactArgs {
        ArtifactArgs {
            bootstrap_receipt: RECEIPT.into(),
            genesis_package: GENESIS_PACKAGE.into(),
            genesis_test_result: GENESIS_TEST_RESULT.into(),
            target_package: TARGET_PACKAGE.into(),
            target_test_result: TARGET_TEST_RESULT.into(),
            genesis_key_bridge: BRIDGE.into(),
            activation_statement: STATEMENT.into(),
            activation_approval_set: APPROVAL_SET.into(),
        }
    }

    fn fixture_receipt() -> BootstrapReceiptV1 {
        decode_strict(&read_framed_canonical_record(Path::new(RECEIPT)).unwrap()).unwrap()
    }

    fn fixture_authority(receipt: &BootstrapReceiptV1) -> ArtifactAuthority<'_> {
        let receipt_digest = BootstrapReceiptDigest::from_digest(digest(RECEIPT_DIGEST));
        let bridge_digest = GenesisSuccessorKeyBridgeDigest::from_digest(digest(BRIDGE_DIGEST));
        ArtifactAuthority {
            semantic_scope: &receipt.statement.scope,
            bootstrap_receipt_digest: receipt_digest,
            bootstrap_pin: BootstrapPin::from_trusted_config(receipt_digest),
            genesis_test_runner_pin: RegistryTestRunnerPin::from_trusted_config(
                digest(GENESIS_RUNNER_ARTIFACT_DIGEST),
                digest(GENESIS_RUNNER_CONFIGURATION_DIGEST),
                RegistryTestResultDigest::from_digest(digest(GENESIS_TEST_RESULT_DIGEST)),
            ),
            target_test_runner_pin: SuccessorRegistryTestRunnerPin::from_trusted_config(
                digest(TARGET_RUNNER_ARTIFACT_DIGEST),
                digest(TARGET_RUNNER_CONFIGURATION_DIGEST),
                RegistryTestResultDigest::from_digest(digest(TARGET_TEST_RESULT_DIGEST)),
            ),
            bridge_digest,
            bridge_pin: GenesisSuccessorKeyBridgePin::from_trusted_config(bridge_digest),
            genesis_principal_binding: GenesisActivationPrincipalBinding::from_trusted_config(
                ContractId::new("principal.operator").unwrap(),
                ContractId::new("principal.author").unwrap(),
            ),
            successor_principal_binding: SuccessorActivationPrincipalBinding::from_trusted_config(
                ContractId::new("principal.proposer").unwrap(),
                ContractId::new("principal.author").unwrap(),
            ),
        }
    }

    #[derive(Debug, Clone)]
    struct DynamicSuccessorFixtureInput {
        output_directory: PathBuf,
        genesis_head: RegistryHeadBindingV1,
        effective_from: CanonicalTimestamp,
        stale_effective_from: CanonicalTimestamp,
    }

    #[derive(Debug)]
    struct DynamicSuccessorFixture {
        canonical_bridge: Vec<u8>,
        bridge_digest: GenesisSuccessorKeyBridgeDigest,
        canonical_statement: Vec<u8>,
        canonical_approval_set: Vec<u8>,
        canonical_stale_statement: Vec<u8>,
        canonical_stale_approval_set: Vec<u8>,
    }

    fn dynamic_successor_fixture_input_from_env() -> anyhow::Result<DynamicSuccessorFixtureInput> {
        let variables = std::env::vars_os().filter(|(name, _)| {
            name.as_encoded_bytes()
                .starts_with(SUCCESSOR_FIXTURE_ENV_PREFIX.as_bytes())
        });
        dynamic_successor_fixture_input_from_variables(variables)
    }

    fn dynamic_successor_fixture_input_from_variables(
        variables: impl IntoIterator<Item = (OsString, OsString)>,
    ) -> anyhow::Result<DynamicSuccessorFixtureInput> {
        let mut values = BTreeMap::new();
        for (name, value) in variables {
            let name = name
                .into_string()
                .map_err(|_| anyhow!("successor fixture environment name is not UTF-8"))?;
            ensure!(
                SUCCESSOR_FIXTURE_ENV_NAMES.contains(&name.as_str()),
                "unexpected successor fixture environment variable {name}"
            );
            let value = value
                .into_string()
                .map_err(|_| anyhow!("successor fixture environment value is not UTF-8"))?;
            ensure!(
                values.insert(name.clone(), value).is_none(),
                "duplicate successor fixture environment variable {name}"
            );
        }
        ensure!(
            values.len() == SUCCESSOR_FIXTURE_ENV_NAMES.len(),
            "successor fixture environment contract is incomplete"
        );

        let directory = take_fixture_env_value(&mut values, SUCCESSOR_FIXTURE_DIR_ENV)?;
        ensure!(
            !directory.is_empty() && directory.len() <= MAX_SUCCESSOR_FIXTURE_PATH_BYTES,
            "successor fixture directory path is empty or exceeds its bound"
        );
        let directory = PathBuf::from(directory);
        ensure!(
            directory.is_absolute(),
            "successor fixture directory must be an absolute path"
        );
        let output_directory =
            fs::canonicalize(&directory).context("canonicalize successor fixture directory")?;
        ensure!(
            output_directory.as_os_str().as_encoded_bytes().len()
                <= MAX_SUCCESSOR_FIXTURE_PATH_BYTES
                && output_directory.parent().is_some()
                && fs::metadata(&output_directory)
                    .context("inspect successor fixture directory")?
                    .is_dir(),
            "successor fixture directory is invalid or exceeds its bound"
        );

        let activation_id =
            parse_fixture_digest(&mut values, SUCCESSOR_FIXTURE_GENESIS_ACTIVATION_ID_ENV)?;
        let package_digest =
            parse_fixture_digest(&mut values, SUCCESSOR_FIXTURE_GENESIS_PACKAGE_DIGEST_ENV)?;
        let activation_policy_digest = parse_fixture_digest(
            &mut values,
            SUCCESSOR_FIXTURE_GENESIS_ACTIVATION_POLICY_DIGEST_ENV,
        )?;
        let genesis_effective_from =
            parse_fixture_timestamp(&mut values, SUCCESSOR_FIXTURE_GENESIS_EFFECTIVE_FROM_ENV)?;
        let effective_from =
            parse_fixture_timestamp(&mut values, SUCCESSOR_FIXTURE_EFFECTIVE_FROM_ENV)?;
        let stale_effective_from =
            parse_fixture_timestamp(&mut values, SUCCESSOR_FIXTURE_STALE_EFFECTIVE_FROM_ENV)?;
        ensure!(
            effective_from != stale_effective_from,
            "successor fixture statements must have distinct effective timestamps"
        );
        ensure!(
            values.is_empty(),
            "successor fixture environment contract was not consumed exactly"
        );

        let genesis_head = RegistryHeadBindingV1 {
            head: RegistryHeadV1 {
                activation_id,
                package_digest,
                activation_policy_digest,
            },
            effective_from: genesis_effective_from,
            effective_until: None,
        };
        genesis_head.validate_shape()?;
        Ok(DynamicSuccessorFixtureInput {
            output_directory,
            genesis_head,
            effective_from,
            stale_effective_from,
        })
    }

    fn take_fixture_env_value(
        values: &mut BTreeMap<String, String>,
        name: &'static str,
    ) -> anyhow::Result<String> {
        values
            .remove(name)
            .ok_or_else(|| anyhow!("successor fixture environment contract is missing {name}"))
    }

    fn parse_fixture_digest(
        values: &mut BTreeMap<String, String>,
        name: &'static str,
    ) -> anyhow::Result<Sha256Digest> {
        let value = take_fixture_env_value(values, name)?;
        ensure!(value.len() == 64, "{name} must be one bounded digest");
        value
            .parse()
            .with_context(|| format!("parse successor fixture digest {name}"))
    }

    fn parse_fixture_timestamp(
        values: &mut BTreeMap<String, String>,
        name: &'static str,
    ) -> anyhow::Result<CanonicalTimestamp> {
        let value = take_fixture_env_value(values, name)?;
        ensure!(value.len() == 30, "{name} must be one bounded timestamp");
        CanonicalTimestamp::parse(value)
            .with_context(|| format!("parse successor fixture timestamp {name}"))
    }

    fn dynamic_successor_fixture(
        input: &DynamicSuccessorFixtureInput,
    ) -> anyhow::Result<DynamicSuccessorFixture> {
        let mut bridge: GenesisSuccessorKeyBridgeV1 =
            decode_strict(&read_framed_canonical_record(Path::new(BRIDGE))?)?;
        bridge.genesis_registry_head = input.genesis_head.clone();
        bridge.validate_shape()?;
        let canonical_bridge = encode_canonical(&bridge)?;
        ensure!(
            canonical_bridge.len() <= MAX_INPUT_BYTES,
            "generated successor bridge exceeds the canonical input bound"
        );
        let bridge_digest = GenesisSuccessorKeyBridgeDigest::from_digest(domain_separated_digest(
            DigestDomain::GenesisSuccessorKeyBridgeV1,
            &canonical_bridge,
        ));
        ensure!(
            bridge.bridge_digest()? == bridge_digest,
            "generated successor bridge digest is not canonical"
        );

        let template: SuccessorRegistryActivationStatementV1 =
            decode_strict(&read_framed_canonical_record(Path::new(STATEMENT))?)?;
        let (canonical_statement, canonical_approval_set) = dynamic_successor_statement(
            &template,
            &bridge,
            bridge_digest,
            input.effective_from.clone(),
        )?;
        let (canonical_stale_statement, canonical_stale_approval_set) =
            dynamic_successor_statement(
                &template,
                &bridge,
                bridge_digest,
                input.stale_effective_from.clone(),
            )?;
        ensure!(
            canonical_statement != canonical_stale_statement
                && canonical_approval_set != canonical_stale_approval_set,
            "generated successor fixture ceremonies must be distinct"
        );

        Ok(DynamicSuccessorFixture {
            canonical_bridge,
            bridge_digest,
            canonical_statement,
            canonical_approval_set,
            canonical_stale_statement,
            canonical_stale_approval_set,
        })
    }

    fn dynamic_successor_statement(
        template: &SuccessorRegistryActivationStatementV1,
        bridge: &GenesisSuccessorKeyBridgeV1,
        bridge_digest: GenesisSuccessorKeyBridgeDigest,
        effective_from: CanonicalTimestamp,
    ) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        let mut statement = template.clone();
        statement.expected_predecessor_head = bridge.genesis_registry_head.clone();
        statement.genesis_successor_key_bridge_digest = bridge_digest;
        statement.effective_from = effective_from;
        statement.validate_shape()?;
        let canonical_statement = encode_canonical(&statement)?;
        ensure!(
            canonical_statement.len() <= MAX_INPUT_BYTES,
            "generated successor statement exceeds the canonical input bound"
        );
        let statement_id = statement.statement_id()?;
        let mut signature_message = SUCCESSOR_APPROVAL_SIGNATURE_PREFIX.to_vec();
        signature_message.extend_from_slice(statement_id.digest().as_bytes());

        let mut approvals = Vec::with_capacity(2);
        for (principal, seed) in [("principal.alice", 1_u8), ("principal.bob", 2_u8)] {
            let principal_id = ContractId::new(principal)?;
            let key_pair = Ed25519KeyPair::from_seed_unchecked(&[seed; 32])
                .map_err(|_| anyhow!("construct deterministic successor fixture signer"))?;
            let bridge_signer = bridge
                .key_map
                .iter()
                .find(|binding| binding.principal_id == principal_id)
                .ok_or_else(|| anyhow!("successor fixture signer is absent from the bridge"))?;
            ensure!(
                bridge_signer.algorithm == ActivationSignatureAlgorithmV2::Ed25519
                    && bridge_signer.public_key.as_bytes() == key_pair.public_key().as_ref(),
                "successor fixture signer key does not match the bridge"
            );
            let signature: [u8; 64] = key_pair
                .sign(&signature_message)
                .as_ref()
                .try_into()
                .map_err(|_| anyhow!("successor fixture signature has the wrong length"))?;
            approvals.push(SuccessorRegistryActivationApprovalV1 {
                schema_version: 1,
                statement_id,
                signer_principal_id: principal_id,
                signature: FixedHex64::from_bytes(signature),
            });
        }
        approvals.sort_unstable_by(|left, right| {
            left.signer_principal_id.cmp(&right.signer_principal_id)
        });
        let approval_set = SuccessorRegistryActivationApprovalSetV1 {
            schema_version: 1,
            statement_id,
            approvals,
        };
        approval_set.validate_shape()?;
        let canonical_approval_set = encode_canonical(&approval_set)?;
        ensure!(
            canonical_approval_set.len() <= MAX_INPUT_BYTES,
            "generated successor approval set exceeds the canonical input bound"
        );
        Ok((canonical_statement, canonical_approval_set))
    }

    fn verify_dynamic_successor_fixture(fixture: &DynamicSuccessorFixture) -> anyhow::Result<()> {
        let staging = tempfile::tempdir().context("create successor fixture verification area")?;
        let bridge = staging.path().join(EMITTED_BRIDGE);
        let statement = staging.path().join(EMITTED_STATEMENT);
        let approval_set = staging.path().join(EMITTED_APPROVAL_SET);
        let stale_statement = staging.path().join(EMITTED_STALE_STATEMENT);
        let stale_approval_set = staging.path().join(EMITTED_STALE_APPROVAL_SET);
        write_framed_fixture_record(&bridge, &fixture.canonical_bridge, false)?;
        write_framed_fixture_record(&statement, &fixture.canonical_statement, false)?;
        write_framed_fixture_record(&approval_set, &fixture.canonical_approval_set, false)?;
        write_framed_fixture_record(&stale_statement, &fixture.canonical_stale_statement, false)?;
        write_framed_fixture_record(
            &stale_approval_set,
            &fixture.canonical_stale_approval_set,
            false,
        )?;

        let receipt = fixture_receipt();
        let mut authority = fixture_authority(&receipt);
        authority.bridge_digest = fixture.bridge_digest;
        authority.bridge_pin =
            GenesisSuccessorKeyBridgePin::from_trusted_config(fixture.bridge_digest);
        let mut paths = artifact_args();
        paths.genesis_key_bridge = bridge;
        paths.activation_statement = statement;
        paths.activation_approval_set = approval_set;
        verify_artifacts(&paths, &authority)
            .context("verify generated current successor fixture ceremony")?;
        paths.activation_statement = stale_statement;
        paths.activation_approval_set = stale_approval_set;
        verify_artifacts(&paths, &authority)
            .context("verify generated stale successor fixture ceremony")?;
        Ok(())
    }

    fn emit_dynamic_successor_fixture(
        input: &DynamicSuccessorFixtureInput,
        fixture: &DynamicSuccessorFixture,
    ) -> anyhow::Result<()> {
        // No destination artifact is created until both generated ceremonies
        // pass the same complete offline verifier used by the production CLI.
        verify_dynamic_successor_fixture(fixture)?;

        let outputs = [
            EMITTED_BRIDGE,
            EMITTED_BRIDGE_DIGEST,
            EMITTED_STATEMENT,
            EMITTED_APPROVAL_SET,
            EMITTED_STALE_STATEMENT,
            EMITTED_STALE_APPROVAL_SET,
        ];
        for name in outputs {
            ensure!(
                !input.output_directory.join(name).exists(),
                "successor fixture output already exists: {name}"
            );
        }

        write_framed_fixture_record(
            &input.output_directory.join(EMITTED_BRIDGE),
            &fixture.canonical_bridge,
            true,
        )?;
        write_new_fixture_bytes(
            &input.output_directory.join(EMITTED_BRIDGE_DIGEST),
            format!("{}\n", fixture.bridge_digest).as_bytes(),
        )?;
        write_framed_fixture_record(
            &input.output_directory.join(EMITTED_STATEMENT),
            &fixture.canonical_statement,
            true,
        )?;
        write_framed_fixture_record(
            &input.output_directory.join(EMITTED_APPROVAL_SET),
            &fixture.canonical_approval_set,
            true,
        )?;
        write_framed_fixture_record(
            &input.output_directory.join(EMITTED_STALE_STATEMENT),
            &fixture.canonical_stale_statement,
            true,
        )?;
        write_framed_fixture_record(
            &input.output_directory.join(EMITTED_STALE_APPROVAL_SET),
            &fixture.canonical_stale_approval_set,
            true,
        )?;
        Ok(())
    }

    fn write_framed_fixture_record(
        path: &Path,
        canonical_record: &[u8],
        create_new: bool,
    ) -> anyhow::Result<()> {
        ensure!(
            !canonical_record.is_empty() && canonical_record.len() <= MAX_INPUT_BYTES,
            "successor fixture canonical record exceeds its bound"
        );
        require_canonical(canonical_record)?;
        let mut framed = Vec::with_capacity(canonical_record.len() + 1);
        framed.extend_from_slice(canonical_record);
        framed.push(b'\n');
        if create_new {
            write_new_fixture_bytes(path, &framed)
        } else {
            fs::write(path, framed)
                .with_context(|| format!("write staged successor fixture {}", path.display()))
        }
    }

    fn write_new_fixture_bytes(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
        ensure!(
            bytes.len() <= MAX_INPUT_BYTES + 1,
            "successor fixture output exceeds its bound"
        );
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .with_context(|| format!("create successor fixture output {}", path.display()))?;
        file.write_all(bytes)
            .with_context(|| format!("write successor fixture output {}", path.display()))?;
        file.flush()
            .with_context(|| format!("flush successor fixture output {}", path.display()))
    }

    fn raw_sha256(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    fn checked_in_dynamic_fixture_input(output_directory: PathBuf) -> DynamicSuccessorFixtureInput {
        let bridge: GenesisSuccessorKeyBridgeV1 =
            decode_strict(&read_framed_canonical_record(Path::new(BRIDGE)).unwrap()).unwrap();
        DynamicSuccessorFixtureInput {
            output_directory,
            genesis_head: bridge.genesis_registry_head,
            effective_from: CanonicalTimestamp::parse("2026-08-15T04:10:00.000000000Z").unwrap(),
            stale_effective_from: CanonicalTimestamp::parse("2026-08-15T04:11:00.000000000Z")
                .unwrap(),
        }
    }

    fn complete_fixture_environment(directory: &Path) -> Vec<(OsString, OsString)> {
        vec![
            (
                SUCCESSOR_FIXTURE_DIR_ENV.into(),
                directory.as_os_str().to_owned(),
            ),
            (
                SUCCESSOR_FIXTURE_GENESIS_ACTIVATION_ID_ENV.into(),
                "5a7263f5c98e75b94e82341d2a7729e9578d4691691b5a8401e1c37a83931261".into(),
            ),
            (
                SUCCESSOR_FIXTURE_GENESIS_PACKAGE_DIGEST_ENV.into(),
                "5a931fd5551bec47f83adb019f3e794d1b6a759f4501e7ea26a83076d9518177".into(),
            ),
            (
                SUCCESSOR_FIXTURE_GENESIS_ACTIVATION_POLICY_DIGEST_ENV.into(),
                "6f92f99ff35969845f08f9b64cee7d86fa42dc6165ebc617d950be8960b86968".into(),
            ),
            (
                SUCCESSOR_FIXTURE_GENESIS_EFFECTIVE_FROM_ENV.into(),
                "2026-08-15T03:00:00.000000000Z".into(),
            ),
            (
                SUCCESSOR_FIXTURE_EFFECTIVE_FROM_ENV.into(),
                "2026-08-15T04:10:00.000000000Z".into(),
            ),
            (
                SUCCESSOR_FIXTURE_STALE_EFFECTIVE_FROM_ENV.into(),
                "2026-08-15T04:11:00.000000000Z".into(),
            ),
        ]
    }

    fn assert_exact_keys(value: &Value, expected: &[&str]) {
        let actual = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let expected = expected.iter().copied().collect::<BTreeSet<_>>();
        assert_eq!(actual, expected);
    }

    #[test]
    fn parser_exposes_only_two_commands_and_eight_artifact_paths() {
        for command in ["inspect", "apply"] {
            let cli = Cli::try_parse_from([
                "ostk-registry-successor-activate",
                command,
                "--bootstrap-receipt",
                RECEIPT,
                "--genesis-package",
                GENESIS_PACKAGE,
                "--genesis-test-result",
                GENESIS_TEST_RESULT,
                "--target-package",
                TARGET_PACKAGE,
                "--target-test-result",
                TARGET_TEST_RESULT,
                "--genesis-key-bridge",
                BRIDGE,
                "--activation-statement",
                STATEMENT,
                "--activation-approval-set",
                APPROVAL_SET,
            ])
            .unwrap();
            assert!(matches!(
                cli.command,
                Command::Inspect(_) | Command::Apply(_)
            ));
        }
        for forbidden in ["emit", "serve", "mcp"] {
            assert!(Cli::try_parse_from(["ostk-registry-successor-activate", forbidden]).is_err());
        }
        assert!(
            Cli::try_parse_from([
                "ostk-registry-successor-activate",
                "inspect",
                "--database-url",
                EXPLICIT_URL,
            ])
            .is_err()
        );
    }

    #[test]
    fn dynamic_fixture_environment_is_closed_exact_and_bounded() {
        let directory = tempfile::tempdir().unwrap();
        let variables = complete_fixture_environment(directory.path());
        let parsed = dynamic_successor_fixture_input_from_variables(variables.clone()).unwrap();
        assert_eq!(
            parsed.output_directory,
            directory.path().canonicalize().unwrap()
        );
        assert_eq!(
            parsed.genesis_head.head.activation_id.to_string(),
            "5a7263f5c98e75b94e82341d2a7729e9578d4691691b5a8401e1c37a83931261"
        );
        assert_ne!(parsed.effective_from, parsed.stale_effective_from);

        let mut incomplete = variables.clone();
        incomplete.pop();
        assert!(dynamic_successor_fixture_input_from_variables(incomplete).is_err());

        let mut extended = variables.clone();
        extended.push((
            "FLEET_RECALL_SUCCESSOR_CLI_UNREVIEWED_INPUT".into(),
            "attacker-selected".into(),
        ));
        assert!(dynamic_successor_fixture_input_from_variables(extended).is_err());

        let mut relative = variables;
        relative[0].1 = "relative/output".into();
        assert!(dynamic_successor_fixture_input_from_variables(relative).is_err());
    }

    #[test]
    fn dynamic_fixture_bytes_are_canonical_distinct_and_frozen() {
        let directory = tempfile::tempdir().unwrap();
        let input = checked_in_dynamic_fixture_input(directory.path().to_owned());
        let fixture = dynamic_successor_fixture(&input).unwrap();
        assert_eq!(
            fixture.canonical_bridge,
            read_framed_canonical_record(Path::new(BRIDGE)).unwrap()
        );
        assert_eq!(fixture.bridge_digest.to_string(), BRIDGE_DIGEST);
        assert_eq!(
            fixture.canonical_statement,
            read_framed_canonical_record(Path::new(STATEMENT)).unwrap()
        );
        assert_eq!(
            fixture.canonical_approval_set,
            read_framed_canonical_record(Path::new(APPROVAL_SET)).unwrap()
        );

        let current: SuccessorRegistryActivationStatementV1 =
            decode_strict(&fixture.canonical_statement).unwrap();
        let stale: SuccessorRegistryActivationStatementV1 =
            decode_strict(&fixture.canonical_stale_statement).unwrap();
        assert_ne!(
            current.statement_id().unwrap(),
            stale.statement_id().unwrap()
        );
        verify_dynamic_successor_fixture(&fixture).unwrap();

        let framed_hash = |record: &[u8]| {
            let mut framed = record.to_vec();
            framed.push(b'\n');
            raw_sha256(&framed)
        };
        assert_eq!(
            framed_hash(&fixture.canonical_bridge),
            "e008106413023eb6e9da0e9e200d8b8f58b4cae7434a723a9e2e56f357c3b25b"
        );
        assert_eq!(
            raw_sha256(format!("{}\n", fixture.bridge_digest).as_bytes()),
            "9cfc18e9360cd36aa018be314a63a6f17e3f2686d51bb1304c7ad4de88e7316c"
        );
        assert_eq!(
            framed_hash(&fixture.canonical_statement),
            "8ff1523115d72b131f7ae7c65089d48fc0235e6ac53d743bfe3734a144f981a9"
        );
        assert_eq!(
            framed_hash(&fixture.canonical_approval_set),
            "6f4979d161e5b43c50dfe441095b4682d2b9c523042b87789172ea62f2f59a11"
        );
        assert_eq!(
            framed_hash(&fixture.canonical_stale_statement),
            "1c00146ff9c1f0ab8c12d0ad067125b8bee5663472db474d9d58bc653f99d83a"
        );
        assert_eq!(
            framed_hash(&fixture.canonical_stale_approval_set),
            "8b324b85cade594ef5a611460c8820d488d1bb68fd3a1e46df5f3aecd5a27590"
        );
    }

    #[test]
    fn dynamic_fixture_rebinds_fresh_head_and_recomputes_all_ids() {
        let directory = tempfile::tempdir().unwrap();
        let mut input = checked_in_dynamic_fixture_input(directory.path().to_owned());
        input.genesis_head.head.activation_id = digest(&"ab".repeat(32));
        input.genesis_head.effective_from =
            CanonicalTimestamp::parse("2026-08-16T03:00:00.000000000Z").unwrap();
        input.effective_from = CanonicalTimestamp::parse("2026-08-16T04:10:00.000000000Z").unwrap();
        input.stale_effective_from =
            CanonicalTimestamp::parse("2026-08-16T04:11:00.000000000Z").unwrap();

        let fixture = dynamic_successor_fixture(&input).unwrap();
        assert_ne!(fixture.bridge_digest.to_string(), BRIDGE_DIGEST);
        let bridge: GenesisSuccessorKeyBridgeV1 = decode_strict(&fixture.canonical_bridge).unwrap();
        assert_eq!(bridge.genesis_registry_head, input.genesis_head);

        let current: SuccessorRegistryActivationStatementV1 =
            decode_strict(&fixture.canonical_statement).unwrap();
        let stale: SuccessorRegistryActivationStatementV1 =
            decode_strict(&fixture.canonical_stale_statement).unwrap();
        let current_approvals: SuccessorRegistryActivationApprovalSetV1 =
            decode_strict(&fixture.canonical_approval_set).unwrap();
        let stale_approvals: SuccessorRegistryActivationApprovalSetV1 =
            decode_strict(&fixture.canonical_stale_approval_set).unwrap();
        assert_eq!(current.expected_predecessor_head, input.genesis_head);
        assert_eq!(stale.expected_predecessor_head, input.genesis_head);
        assert_eq!(
            current.genesis_successor_key_bridge_digest,
            fixture.bridge_digest
        );
        assert_eq!(
            stale.genesis_successor_key_bridge_digest,
            fixture.bridge_digest
        );
        assert_eq!(
            current_approvals.statement_id,
            current.statement_id().unwrap()
        );
        assert_eq!(stale_approvals.statement_id, stale.statement_id().unwrap());
        assert_ne!(current_approvals.statement_id, stale_approvals.statement_id);
        verify_dynamic_successor_fixture(&fixture).unwrap();
    }

    #[test]
    fn dynamic_fixture_emitter_has_no_production_surface() {
        let source = include_str!("ostk-registry-successor-activate.rs");
        let test_module = source.find("#[cfg(test)]").unwrap();
        let emitter = source
            .rfind("fn emit_dynamic_successor_fixture_for_connected_proof()")
            .unwrap();
        assert!(test_module < emitter);
        assert!(source[test_module..emitter].ends_with(
            "#[ignore = \"test-harness-only; requires the closed successor fixture environment\"]\n    #[test]\n    "
        ));
        assert!(Cli::try_parse_from(["ostk-registry-successor-activate", "emit"]).is_err());
    }

    /// Test-harness-only emitter for a disposable connected role proof. The
    /// production parser exposes no signing or artifact-generation command.
    #[ignore = "test-harness-only; requires the closed successor fixture environment"]
    #[test]
    fn emit_dynamic_successor_fixture_for_connected_proof() -> anyhow::Result<()> {
        let input = dynamic_successor_fixture_input_from_env()?;
        let fixture = dynamic_successor_fixture(&input)?;
        emit_dynamic_successor_fixture(&input, &fixture)
    }

    #[test]
    fn accepts_all_eight_bounded_framed_canonical_fixtures() {
        for path in [
            RECEIPT,
            GENESIS_PACKAGE,
            GENESIS_TEST_RESULT,
            TARGET_PACKAGE,
            TARGET_TEST_RESULT,
            BRIDGE,
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
    fn closes_the_complete_successor_ceremony_before_connect() {
        let receipt = fixture_receipt();
        let verified = verify_artifacts(&artifact_args(), &fixture_authority(&receipt)).unwrap();
        assert_eq!(
            verified.target_package.package_digest().to_string(),
            "16f98d5df93b74dab5b2188274cbd1da21d089ff7a64cd8fc29679946e7fe2c9"
        );
        assert_eq!(
            verified.candidate.canonical_statement(),
            read_framed_canonical_record(Path::new(STATEMENT)).unwrap()
        );
    }

    #[test]
    fn raw_deployment_pins_fail_closed() {
        let receipt = fixture_receipt();
        let mut authority = fixture_authority(&receipt);
        authority.bridge_digest =
            GenesisSuccessorKeyBridgeDigest::from_digest(digest(&"00".repeat(32)));
        let error = verify_artifacts(&artifact_args(), &authority)
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("key bridge does not match the deployment pin"));

        let mut authority = fixture_authority(&receipt);
        authority.bootstrap_receipt_digest =
            BootstrapReceiptDigest::from_digest(digest(&"00".repeat(32)));
        let error = verify_artifacts(&artifact_args(), &authority)
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("bootstrap receipt does not match the deployment pin"));
    }

    #[test]
    fn approval_set_must_bind_the_exact_statement_before_connection() {
        let receipt = fixture_receipt();
        let mut approval_set: SuccessorRegistryActivationApprovalSetV1 =
            decode_strict(&read_framed_canonical_record(Path::new(APPROVAL_SET)).unwrap()).unwrap();
        let other_id =
            SuccessorRegistryActivationStatementId::from_digest(digest(&"aa".repeat(32)));
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
        let error = verify_artifacts(&paths, &fixture_authority(&receipt))
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("does not bind the exact statement"));
    }

    #[test]
    fn malformed_artifact_fails_before_database_url_parsing() {
        let receipt = fixture_receipt();
        let mut paths = artifact_args();
        let malformed = tempfile::NamedTempFile::new().unwrap();
        fs::write(malformed.path(), b"not-json\n").unwrap();
        paths.activation_statement = malformed.path().to_owned();
        let error = prepare_execution(&paths, &fixture_authority(&receipt), "not-a-database-url")
            .err()
            .unwrap()
            .to_string();
        assert!(!error.contains("PostgreSQL"));
        assert!(!error.contains("database URL"));
    }

    #[test]
    fn source_keeps_lazy_repository_construction_before_the_first_acquire() {
        let source = include_str!("ostk-registry-successor-activate.rs");
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
            .find("CockroachSuccessorActivationRepository::new(")
            .unwrap();
        let acquire = main_source.find("let connection = pool").unwrap();
        assert!(lazy < repository && repository < acquire);
        let eager_pool_helper = [".connect_", "with("].concat();
        assert!(!source.contains(&eager_pool_helper));
        assert!(source.contains(".max_connections(MAX_CONNECTIONS)"));
        assert!(source.contains(".min_connections(0)"));
    }

    #[test]
    fn output_is_exact_bounded_and_redacted() {
        let head = RegistryHeadBindingV1 {
            head: RegistryHeadV1 {
                activation_id: digest(&"11".repeat(32)),
                package_digest: digest(&"22".repeat(32)),
                activation_policy_digest: digest(&"33".repeat(32)),
            },
            effective_from: CanonicalTimestamp::parse("2026-08-15T04:10:00.000000000Z").unwrap(),
            effective_until: None,
        };
        let bridge_digest = GenesisSuccessorKeyBridgeDigest::from_digest(digest(&"44".repeat(32)));
        let ready = ready_output(&ReadySuccessorActivation {
            genesis_head: head.clone(),
            bridge_digest,
        });
        assert_exact_keys(
            &ready,
            &[
                "operation",
                "state",
                "genesis_head",
                "genesis_key_bridge_digest",
            ],
        );
        assert_exact_keys(
            &ready["genesis_head"],
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

        let accepted = AcceptedSuccessorActivation {
            statement_id: SuccessorRegistryActivationStatementId::from_digest(digest(
                &"55".repeat(32),
            )),
            activation_id: SuccessorRegistryActivationId::from_digest(digest(&"66".repeat(32))),
            accepted_event_id: AcceptedEventId::from_digest(digest(&"77".repeat(32))),
            registry_head: head,
            append_position: AppendPositionV1 {
                epoch_id: EpochId::from_digest(digest(&"88".repeat(32))),
                shard: 7,
                committed_offset: CommittedOffsetV1::new(42).unwrap(),
            },
            bridge_digest,
            accepted_at: CanonicalTimestamp::parse("2026-08-15T04:11:00.000000000Z").unwrap(),
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
                    "registry_head",
                    "epoch_id",
                    "control_shard",
                    "committed_offset",
                    "genesis_key_bridge_digest",
                    "accepted_at",
                ],
            );
            assert_exact_keys(
                &output["registry_head"],
                &[
                    "activation_id",
                    "package_digest",
                    "activation_policy_digest",
                    "effective_from",
                    "effective_until",
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
            "cluster.example:26257:fleet_recall:successor:poisoned-passfile-secret\n",
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
                let receipt = fixture_receipt();
                let error = prepare_execution(
                    &artifact_args(),
                    &fixture_authority(&receipt),
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
