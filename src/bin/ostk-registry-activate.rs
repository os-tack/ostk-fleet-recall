//! Workstation-only, deployment-authorized genesis-registry activation.
//!
//! This binary has no public server route. Physical scope, semantic scope,
//! artifact pins, conformance-runner identity, and principal identities come
//! only from its dedicated environment configuration. The CLI accepts only
//! paths to the five canonical ceremony artifacts.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, anyhow, ensure};
use clap::{Args, Parser, Subcommand};
use ostk_fleet_recall::config::{RegistryActivationConfig, RegistryActivationRuntimeConfig};
use ostk_fleet_recall::memory_contracts::bootstrap::{
    BootstrapPin, BootstrapReceiptDigest, BootstrapReceiptV1, VerifiedBootstrapReceipt,
    verify_pinned_bootstrap,
};
use ostk_fleet_recall::memory_contracts::canonical::{
    MAX_INPUT_BYTES, decode_strict, require_canonical,
};
use ostk_fleet_recall::memory_contracts::common::{
    AuthenticatedProjectScopeV1, frozen_profile_reference_v1,
};
use ostk_fleet_recall::memory_contracts::digest::{DigestDomain, domain_separated_digest};
use ostk_fleet_recall::memory_contracts::genesis::SemanticallyClosedGenesisPackage;
use ostk_fleet_recall::memory_contracts::genesis_activation::{
    GenesisActivationPrincipalBinding, RegistryTestRunnerPin,
    VerifiedGenesisRegistryActivationRequest, VerifiedRegistryTestResult,
    verify_genesis_registry_activation, verify_registry_test_result,
};
use ostk_fleet_recall::memory_contracts::registry::ManifestVerifiedRegistryPackage;
use ostk_fleet_recall::registry_activation::{
    AcceptedGenesisActivation, CockroachGenesisActivationRepository, GenesisActivationInspection,
    GenesisActivationOutcome, GenesisActivationRepository, PinnedInactiveGenesis,
};
use ostk_fleet_recall::store::cockroach::RetryPolicy;
use serde_json::{Value, json};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

const MAX_CONNECTIONS: u32 = 2;

#[derive(Debug, Parser)]
#[command(
    name = "ostk-registry-activate",
    version,
    about = "Private, workstation-authorized genesis registry activation"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Verify the complete ceremony and atomically install the genesis head.
    Apply(ArtifactArgs),
    /// Verify the complete ceremony and audit the bound registry state read-only.
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
    /// Canonical, deployment-pinned registry test result as one JSON record plus one LF.
    #[arg(long, value_name = "PATH")]
    registry_test_result: PathBuf,
    /// Canonical genesis-activation statement as one JSON record plus one LF.
    #[arg(long, value_name = "PATH")]
    activation_statement: PathBuf,
    /// Canonical detached activation approval set as one JSON record plus one LF.
    #[arg(long, value_name = "PATH")]
    activation_approval_set: PathBuf,
}

struct ArtifactAuthority<'a> {
    semantic_scope: &'a AuthenticatedProjectScopeV1,
    bootstrap_receipt_digest: BootstrapReceiptDigest,
    bootstrap_pin: BootstrapPin,
    test_runner_pin: RegistryTestRunnerPin,
    principal_binding: GenesisActivationPrincipalBinding,
}

impl<'a> ArtifactAuthority<'a> {
    fn from_config(config: &'a RegistryActivationConfig) -> Self {
        Self {
            semantic_scope: config.trusted_scope().semantic_scope(),
            bootstrap_receipt_digest: config.bootstrap_receipt_digest(),
            bootstrap_pin: config.bootstrap_pin(),
            test_runner_pin: config.test_runner_pin(),
            principal_binding: config.principal_binding(),
        }
    }
}

struct VerifiedArtifacts {
    bootstrap: VerifiedBootstrapReceipt,
    package: SemanticallyClosedGenesisPackage,
    test_result: VerifiedRegistryTestResult,
    request: VerifiedGenesisRegistryActivationRequest,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let config = RegistryActivationRuntimeConfig::from_env()?;
    let args = match &cli.command {
        Command::Apply(args) | Command::Inspect(args) => args,
    };

    // This is the trust boundary: all five files and every deployment pin are
    // fully checked before driver options are constructed or a socket opens.
    let artifacts = verify_artifacts(args, &ArtifactAuthority::from_config(config.authority()))?;

    let options: PgConnectOptions = config
        .database_url()
        .parse()
        .map_err(|_| anyhow!("invalid private registry activation database URL"))?;
    let pool = PgPoolOptions::new()
        .max_connections(MAX_CONNECTIONS)
        .min_connections(0)
        .acquire_timeout(Duration::from_secs(10))
        .connect_with(options.application_name("ostk-registry-activate"))
        .await
        .map_err(|_| anyhow!("connect private registry activation database failed"))?;
    let repository = CockroachGenesisActivationRepository::new(
        pool,
        config.authority().trusted_scope().clone(),
        RetryPolicy::default(),
        artifacts.bootstrap,
        artifacts.package,
        artifacts.test_result,
        config.authority().principal_binding(),
    )?;

    let output = match cli.command {
        Command::Apply(_) => match repository.activate_genesis(&artifacts.request).await? {
            GenesisActivationOutcome::Inserted(accepted) => {
                accepted_output("apply", "inserted", &accepted)
            }
            GenesisActivationOutcome::ExactReplay(accepted) => {
                accepted_output("apply", "exact_replay", &accepted)
            }
        },
        Command::Inspect(_) => match repository
            .inspect_genesis_activation(&artifacts.request)
            .await?
        {
            GenesisActivationInspection::PinnedInactive(pinned) => pinned_output(&pinned),
            GenesisActivationInspection::Accepted(accepted) => {
                accepted_output("inspect", "accepted", &accepted)
            }
        },
    };
    println!("{}", serde_json::to_string(&output)?);
    Ok(())
}

fn verify_artifacts(
    paths: &ArtifactArgs,
    authority: &ArtifactAuthority<'_>,
) -> anyhow::Result<VerifiedArtifacts> {
    // Authenticate the raw receipt bytes before trusting any profile or scope
    // selector decoded from them.
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

    let package_bytes = read_framed_canonical_record(&paths.genesis_package)?;
    let manifest_verified =
        ManifestVerifiedRegistryPackage::decode(&package_bytes, &expected_profile)?;
    let package = SemanticallyClosedGenesisPackage::from_manifest_verified(manifest_verified)?;
    let bootstrap = verify_pinned_bootstrap(
        &receipt_bytes,
        authority.bootstrap_pin,
        &expected_profile,
        authority.semantic_scope,
        &package,
    )?;

    let test_result_bytes = read_framed_canonical_record(&paths.registry_test_result)?;
    let test_result = verify_registry_test_result(
        &test_result_bytes,
        authority.test_runner_pin,
        &expected_profile,
        &package,
    )?;

    let statement_bytes = read_framed_canonical_record(&paths.activation_statement)?;
    let approval_set_bytes = read_framed_canonical_record(&paths.activation_approval_set)?;
    let request = verify_genesis_registry_activation(
        &statement_bytes,
        &approval_set_bytes,
        &bootstrap,
        &package,
        &test_result,
        &authority.principal_binding,
    )?;

    Ok(VerifiedArtifacts {
        bootstrap,
        package,
        test_result,
        request,
    })
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

fn pinned_output(pinned: &PinnedInactiveGenesis) -> Value {
    json!({
        "operation": "inspect",
        "state": "pinned_inactive",
        "bootstrap_receipt_digest": pinned.bootstrap_receipt_digest.to_string(),
        "bootstrap_event_id": pinned.bootstrap_event_id.to_string(),
        "epoch_id": pinned.epoch_id.to_string(),
        "bootstrap_accepted_at": pinned.bootstrap_accepted_at.as_str(),
    })
}

fn accepted_output(
    operation: &'static str,
    state: &'static str,
    accepted: &AcceptedGenesisActivation,
) -> Value {
    json!({
        "operation": operation,
        "state": state,
        "statement_id": accepted.statement_id.to_string(),
        "activation_id": accepted.activation_id.to_string(),
        "accepted_event_id": accepted.accepted_event_id.to_string(),
        "registry_head": {
            "activation_id": accepted.registry_head.activation_id.to_string(),
            "package_digest": accepted.registry_head.package_digest.to_string(),
            "activation_policy_digest": accepted.registry_head.activation_policy_digest.to_string(),
        },
        "epoch_id": accepted.append_position.epoch_id.to_string(),
        "control_shard": accepted.append_position.shard,
        "committed_offset": accepted.append_position.committed_offset.as_u64().to_string(),
        "bootstrap_receipt_digest": accepted.bootstrap_receipt_digest.to_string(),
        "effective_from": accepted.effective_from.as_str(),
        "accepted_at": accepted.accepted_at.as_str(),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::fs;
    use std::io::Write as _;
    use std::str::FromStr as _;

    use ostk_fleet_recall::memory_contracts::bootstrap::{
        AppendPositionV1, CommittedOffsetV1, EpochId,
    };
    use ostk_fleet_recall::memory_contracts::canonical::encode_canonical;
    use ostk_fleet_recall::memory_contracts::common::{CanonicalTimestamp, ContractId, FixedHex64};
    use ostk_fleet_recall::memory_contracts::digest::Sha256Digest;
    use ostk_fleet_recall::memory_contracts::evidence::AcceptedEventId;
    use ostk_fleet_recall::memory_contracts::genesis_activation::{
        GenesisRegistryActivationApprovalSetV1, GenesisRegistryActivationApprovalV1,
        GenesisRegistryActivationId, GenesisRegistryActivationStatementId,
        GenesisRegistryActivationStatementV1, RegistryTestResultDigest,
    };
    use ostk_fleet_recall::memory_contracts::registry::RegistryHeadV1;
    use ring::signature::Ed25519KeyPair;

    use super::*;

    const RECEIPT: &str = "contracts/dynamic-memory/v1/bootstrap-receipt.jsonl";
    const PACKAGE: &str = "contracts/dynamic-memory/v1/genesis-registry-package.jsonl";
    const TEST_RESULT: &str =
        "contracts/dynamic-memory/v1/genesis-activation/registry-test-result.jsonl";
    const STATEMENT: &str =
        "contracts/dynamic-memory/v1/genesis-activation/activation-statement.jsonl";
    const APPROVAL_SET: &str =
        "contracts/dynamic-memory/v1/genesis-activation/activation-approval-set.jsonl";
    const RECEIPT_DIGEST: &str = "084ee06ea7ebf3b1d592d6e5843584485144c0ee5720fcc2124a61a7fcde48f0";
    const TEST_RESULT_DIGEST: &str =
        "e91e08070250a722446195b76ee685a9697298b9fdce9809027f120c829b679d";
    const RUNNER_ARTIFACT_DIGEST: &str =
        "c2e5b0653471d35e54600a8d3fbe5613aff4c04e911787c09a25e2b327d4bbbd";
    const RUNNER_CONFIGURATION_DIGEST: &str =
        "1d12aabe349fd0013389f93bf1917b0de6bbd5d2bd7156c85faff0b97360686d";

    fn artifact_args() -> ArtifactArgs {
        ArtifactArgs {
            bootstrap_receipt: RECEIPT.into(),
            genesis_package: PACKAGE.into(),
            registry_test_result: TEST_RESULT.into(),
            activation_statement: STATEMENT.into(),
            activation_approval_set: APPROVAL_SET.into(),
        }
    }

    fn digest(value: &str) -> Sha256Digest {
        Sha256Digest::from_str(value).unwrap()
    }

    fn fixture_authority(receipt: &BootstrapReceiptV1) -> ArtifactAuthority<'_> {
        ArtifactAuthority {
            semantic_scope: &receipt.statement.scope,
            bootstrap_receipt_digest: BootstrapReceiptDigest::from_digest(digest(RECEIPT_DIGEST)),
            bootstrap_pin: BootstrapPin::from_trusted_config(BootstrapReceiptDigest::from_digest(
                digest(RECEIPT_DIGEST),
            )),
            test_runner_pin: RegistryTestRunnerPin::from_trusted_config(
                digest(RUNNER_ARTIFACT_DIGEST),
                digest(RUNNER_CONFIGURATION_DIGEST),
                RegistryTestResultDigest::from_digest(digest(TEST_RESULT_DIGEST)),
            ),
            principal_binding: GenesisActivationPrincipalBinding::from_trusted_config(
                ContractId::new("principal.operator").unwrap(),
                ContractId::new("principal.author").unwrap(),
            ),
        }
    }

    fn time_bound_ceremony(
        effective_from: CanonicalTimestamp,
        signer_seeds: [u8; 2],
    ) -> (Vec<u8>, Vec<u8>) {
        let mut statement: GenesisRegistryActivationStatementV1 =
            decode_strict(&read_framed_canonical_record(Path::new(STATEMENT)).unwrap()).unwrap();
        statement.effective_from = effective_from;
        let statement_id = statement.statement_id().unwrap();
        let mut message = b"ostk-registry-activation-approval-signature-v1\0".to_vec();
        message.extend_from_slice(statement_id.digest().as_bytes());
        let mut approvals = signer_seeds
            .into_iter()
            .map(|seed| GenesisRegistryActivationApprovalV1 {
                schema_version: 1,
                statement_id,
                signer_principal_id: ContractId::new(format!("principal.{seed}")).unwrap(),
                signature: FixedHex64::from_bytes(
                    Ed25519KeyPair::from_seed_unchecked(&[seed; 32])
                        .unwrap()
                        .sign(&message)
                        .as_ref()
                        .try_into()
                        .unwrap(),
                ),
            })
            .collect::<Vec<_>>();
        approvals.sort_unstable();
        let approval_set = GenesisRegistryActivationApprovalSetV1 {
            schema_version: 1,
            statement_id,
            approvals,
        };
        (
            encode_canonical(&statement).unwrap(),
            encode_canonical(&approval_set).unwrap(),
        )
    }

    fn write_framed_record(path: &Path, mut record: Vec<u8>) {
        record.push(b'\n');
        fs::write(path, record).unwrap();
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
    fn accepts_all_five_framed_canonical_fixtures() {
        for path in [RECEIPT, PACKAGE, TEST_RESULT, STATEMENT, APPROVAL_SET] {
            let record = read_framed_canonical_record(Path::new(path)).unwrap();
            assert_eq!(record.last(), Some(&b'}'));
            require_canonical(&record).unwrap();
        }
    }

    #[test]
    fn rejects_missing_or_additional_record_framing() {
        for value in [b"{}".as_slice(), b"{}\r\n", b"{}\n\n"] {
            let mut file = tempfile::NamedTempFile::new().unwrap();
            file.write_all(value).unwrap();
            assert!(read_framed_canonical_record(file.path()).is_err());
        }
    }

    #[test]
    fn verifies_the_complete_public_ceremony_offline() {
        let receipt_bytes = read_framed_canonical_record(Path::new(RECEIPT)).unwrap();
        let receipt: BootstrapReceiptV1 = decode_strict(&receipt_bytes).unwrap();
        let authority = fixture_authority(&receipt);

        let verified = verify_artifacts(&artifact_args(), &authority).unwrap();
        assert_eq!(
            verified.bootstrap.receipt_digest().to_string(),
            RECEIPT_DIGEST
        );
        assert_eq!(
            verified.test_result.result_digest().to_string(),
            TEST_RESULT_DIGEST
        );
        assert_eq!(
            verified
                .request
                .statement()
                .statement_id()
                .unwrap()
                .to_string(),
            "e9c20de2b02cfb1776ee28cacf9a84aa81706c86b5421aa092396b98a2b83993"
        );
    }

    #[test]
    fn generates_a_time_bound_ceremony_without_changing_frozen_vectors() {
        let directory = tempfile::tempdir().unwrap();
        let (statement, approvals) = time_bound_ceremony(
            CanonicalTimestamp::parse("2026-08-15T04:00:00.000000000Z").unwrap(),
            [1, 2],
        );
        let statement_path = directory.path().join("activation-statement.jsonl");
        let approvals_path = directory.path().join("activation-approval-set.jsonl");
        write_framed_record(&statement_path, statement);
        write_framed_record(&approvals_path, approvals);

        let receipt_bytes = read_framed_canonical_record(Path::new(RECEIPT)).unwrap();
        let receipt: BootstrapReceiptV1 = decode_strict(&receipt_bytes).unwrap();
        let mut paths = artifact_args();
        paths.activation_statement = statement_path;
        paths.activation_approval_set = approvals_path;
        let verified = verify_artifacts(&paths, &fixture_authority(&receipt)).unwrap();
        assert_eq!(
            verified.request.statement().effective_from.as_str(),
            "2026-08-15T04:00:00.000000000Z"
        );
    }

    /// Test-harness-only emitter used by the disposable connected CLI proof.
    /// The production parser has no signing or artifact-generation command.
    #[test]
    fn emit_time_bound_ceremony_for_connected_proof() {
        let Ok(directory) = std::env::var("FLEET_RECALL_REGISTRY_CLI_FIXTURE_DIR") else {
            return;
        };
        let effective_from = std::env::var("FLEET_RECALL_REGISTRY_CLI_EFFECTIVE_FROM")
            .expect("connected proof must bind one server timestamp");
        let effective_from = CanonicalTimestamp::parse(effective_from).unwrap();
        let stale_effective_from = std::env::var("FLEET_RECALL_REGISTRY_CLI_STALE_EFFECTIVE_FROM")
            .expect("connected proof must bind a distinct proposal timestamp");
        let stale_effective_from = CanonicalTimestamp::parse(stale_effective_from).unwrap();
        let (statement, approvals) = time_bound_ceremony(effective_from.clone(), [1, 2]);
        let (_, alternate_approvals) = time_bound_ceremony(effective_from, [1, 3]);
        let (stale_statement, stale_approvals) = time_bound_ceremony(stale_effective_from, [1, 2]);
        let directory = Path::new(&directory);
        write_framed_record(&directory.join("activation-statement.jsonl"), statement);
        write_framed_record(&directory.join("activation-approval-set.jsonl"), approvals);
        write_framed_record(
            &directory.join("activation-approval-set-alternate.jsonl"),
            alternate_approvals,
        );
        write_framed_record(
            &directory.join("activation-statement-stale.jsonl"),
            stale_statement,
        );
        write_framed_record(
            &directory.join("activation-approval-set-stale.jsonl"),
            stale_approvals,
        );
    }

    #[test]
    fn authority_and_transport_are_not_cli_routing_inputs() {
        let valid = [
            "ostk-registry-activate",
            "inspect",
            "--bootstrap-receipt",
            "bootstrap.jsonl",
            "--genesis-package",
            "package.jsonl",
            "--registry-test-result",
            "result.jsonl",
            "--activation-statement",
            "statement.jsonl",
            "--activation-approval-set",
            "approvals.jsonl",
        ];
        assert!(Cli::try_parse_from(valid).is_ok());

        for forbidden in [
            "--database-url",
            "--tenant-id",
            "--project",
            "--bootstrap-receipt-digest",
            "--runner-artifact-digest",
            "--proposer-principal-id",
            "--statement-json",
        ] {
            let mut rerouted = valid.to_vec();
            rerouted.extend([forbidden, "attacker-selected"]);
            assert!(
                Cli::try_parse_from(rerouted).is_err(),
                "accepted {forbidden}"
            );
        }
        assert!(Cli::try_parse_from(["ostk-registry-activate", "serve"]).is_err());
        assert!(Cli::try_parse_from(["ostk-registry-activate", "mcp"]).is_err());
    }

    fn accepted_fixture() -> AcceptedGenesisActivation {
        let digest = digest(&"ab".repeat(32));
        AcceptedGenesisActivation {
            statement_id: GenesisRegistryActivationStatementId::from_digest(digest),
            activation_id: GenesisRegistryActivationId::from_digest(digest),
            accepted_event_id: AcceptedEventId::from_digest(digest),
            registry_head: RegistryHeadV1 {
                activation_id: digest,
                package_digest: digest,
                activation_policy_digest: digest,
            },
            append_position: AppendPositionV1 {
                epoch_id: EpochId::from_digest(digest),
                shard: 7,
                committed_offset: CommittedOffsetV1::new(i64::MAX as u64).unwrap(),
            },
            bootstrap_receipt_digest: BootstrapReceiptDigest::from_digest(digest),
            effective_from: CanonicalTimestamp::parse("2026-08-15T03:00:00.000000000Z").unwrap(),
            accepted_at: CanonicalTimestamp::parse("2026-08-15T04:00:00.000000000Z").unwrap(),
        }
    }

    #[test]
    fn accepted_receipt_is_bounded_redacted_and_string_offsets() {
        let value = accepted_output("apply", "inserted", &accepted_fixture());
        assert_exact_keys(
            &value,
            &[
                "accepted_at",
                "accepted_event_id",
                "activation_id",
                "bootstrap_receipt_digest",
                "committed_offset",
                "control_shard",
                "effective_from",
                "epoch_id",
                "operation",
                "registry_head",
                "state",
                "statement_id",
            ],
        );
        assert_exact_keys(
            &value["registry_head"],
            &[
                "activation_id",
                "activation_policy_digest",
                "package_digest",
            ],
        );
        assert_eq!(value["committed_offset"], i64::MAX.to_string());
        assert!(value["committed_offset"].is_string());
        let encoded = serde_json::to_string(&value).unwrap();
        for forbidden in [
            "signature",
            "canonical_statement",
            "canonical_approval",
            "canonical_receipt",
            "database_url",
            "postgresql://",
        ] {
            assert!(!encoded.contains(forbidden));
        }
        assert!(encoded.len() < 2_048);
    }

    #[test]
    fn pinned_inactive_receipt_is_bounded_and_named_exactly() {
        let digest = digest(&"cd".repeat(32));
        let value = pinned_output(&PinnedInactiveGenesis {
            bootstrap_receipt_digest: BootstrapReceiptDigest::from_digest(digest),
            bootstrap_event_id: AcceptedEventId::from_digest(digest),
            epoch_id: EpochId::from_digest(digest),
            bootstrap_accepted_at: CanonicalTimestamp::parse("2026-08-15T03:00:00.000000000Z")
                .unwrap(),
        });
        assert_exact_keys(
            &value,
            &[
                "bootstrap_accepted_at",
                "bootstrap_event_id",
                "bootstrap_receipt_digest",
                "epoch_id",
                "operation",
                "state",
            ],
        );
        assert_eq!(value["operation"], "inspect");
        assert_eq!(value["state"], "pinned_inactive");
        assert!(serde_json::to_string(&value).unwrap().len() < 1_024);
    }
}
