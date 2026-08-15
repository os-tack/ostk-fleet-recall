//! One-shot, deployment-authorized genesis control-ledger bootstrap.
//!
//! This binary is deliberately separate from the public HTTP demo and MCP
//! server. Physical scope, semantic scope, and the receipt pin come only from
//! deployment environment configuration; artifact paths are the only CLI
//! inputs.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, ensure};
use clap::{Args, Parser, Subcommand};
use ostk_fleet_recall::config::ControlBootstrapRuntimeConfig;
use ostk_fleet_recall::control_log::{
    CockroachGenesisRepository, GenesisBootstrapInspection, GenesisBootstrapOutcome,
    GenesisInspection, GenesisRepository,
};
use ostk_fleet_recall::memory_contracts::bootstrap::{
    BootstrapReceiptDigest, BootstrapReceiptV1, verify_pinned_bootstrap,
};
use ostk_fleet_recall::memory_contracts::canonical::{
    MAX_INPUT_BYTES, decode_strict, require_canonical,
};
use ostk_fleet_recall::memory_contracts::common::frozen_profile_reference_v1;
use ostk_fleet_recall::memory_contracts::digest::{DigestDomain, domain_separated_digest};
use ostk_fleet_recall::memory_contracts::genesis::SemanticallyClosedGenesisPackage;
use ostk_fleet_recall::memory_contracts::registry::ManifestVerifiedRegistryPackage;
use ostk_fleet_recall::store::cockroach::RetryPolicy;
use serde_json::{Value, json};
use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions};

const MAX_CONNECTIONS: u32 = 2;
const REQUIRED_SCHEMA_VERSION: i64 = 3;
const CONTROL_SCHEMA_READY_SQL: &str =
    "SELECT EXISTS (SELECT 1 FROM _sqlx_migrations WHERE version = $1 AND success)";

#[derive(Debug, Parser)]
#[command(
    name = "ostk-control-bootstrap",
    version,
    about = "Private, deployment-authorized genesis control-ledger bootstrap"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Verify and atomically accept the pinned genesis receipt exactly once.
    Apply(ArtifactArgs),
    /// Verify authority and audit the complete stored genesis shape read-only.
    Inspect(ArtifactArgs),
}

#[derive(Debug, Args)]
struct ArtifactArgs {
    /// Canonical bootstrap receipt encoded as one JSON record plus one LF.
    #[arg(long, value_name = "PATH")]
    receipt: PathBuf,
    /// Canonical, semantically closed genesis package as one JSON record plus one LF.
    #[arg(long, value_name = "PATH")]
    genesis_package: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let config = ControlBootstrapRuntimeConfig::from_env()?;
    let authority = config.authority();
    let args = match &cli.command {
        Command::Apply(args) | Command::Inspect(args) => args,
    };

    // Check the out-of-band authority pin before decoding a profile reference
    // out of the receipt or doing any database work.
    let receipt_bytes = read_framed_canonical_record(&args.receipt)?;
    let actual_receipt_digest = BootstrapReceiptDigest::from_digest(domain_separated_digest(
        DigestDomain::BootstrapReceipt,
        &receipt_bytes,
    ));
    ensure!(
        actual_receipt_digest == authority.receipt_digest(),
        "bootstrap receipt does not match the deployment pin"
    );
    let receipt: BootstrapReceiptV1 = decode_strict(&receipt_bytes)?;
    let expected_profile = frozen_profile_reference_v1();
    ensure!(
        receipt.statement.profile == expected_profile,
        "bootstrap receipt names a canonical profile this binary does not implement"
    );

    let package_bytes = read_framed_canonical_record(&args.genesis_package)?;
    let manifest_verified =
        ManifestVerifiedRegistryPackage::decode(&package_bytes, &expected_profile)?;
    let package = SemanticallyClosedGenesisPackage::from_manifest_verified(manifest_verified)?;
    let verified = verify_pinned_bootstrap(
        &receipt_bytes,
        authority.receipt_pin(),
        &expected_profile,
        authority.trusted_scope().semantic_scope(),
        &package,
    )?;

    let options: PgConnectOptions = config
        .database_url()
        .parse()
        .context("invalid bootstrap database URL")?;
    let pool = PgPoolOptions::new()
        .max_connections(MAX_CONNECTIONS)
        .min_connections(0)
        .acquire_timeout(Duration::from_secs(10))
        .connect_with(options.application_name("ostk-control-bootstrap"))
        .await
        .context("connect private control bootstrap database")?;
    require_control_schema(&pool).await?;
    let repository = CockroachGenesisRepository::new(
        pool,
        authority.trusted_scope().clone(),
        RetryPolicy::default(),
    );

    let output = match cli.command {
        Command::Apply(_) => match repository.bootstrap_genesis(&verified, &package).await? {
            GenesisBootstrapOutcome::Inserted(inspection) => {
                output("apply", "inserted", &inspection)
            }
            GenesisBootstrapOutcome::ExactReplay(inspection) => {
                output("apply", "exact_replay", &inspection)
            }
        },
        Command::Inspect(_) => match repository.inspect_genesis(&verified, &package).await? {
            GenesisInspection::Absent => json!({
                "operation": "inspect",
                "state": "absent",
                "receipt_digest": verified.receipt_digest().to_string(),
            }),
            GenesisInspection::Complete(inspection) => output("inspect", "complete", &inspection),
        },
    };
    println!("{}", serde_json::to_string(&output)?);
    Ok(())
}

async fn require_control_schema(pool: &PgPool) -> anyhow::Result<()> {
    let installed = sqlx::query_scalar::<_, bool>(CONTROL_SCHEMA_READY_SQL)
        .bind(REQUIRED_SCHEMA_VERSION)
        .fetch_one(pool)
        .await
        .context("read SQLx migration state for private control bootstrap")?;
    ensure!(
        installed,
        "private control bootstrap requires successful database migration {REQUIRED_SCHEMA_VERSION}"
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

fn output(
    operation: &'static str,
    state: &'static str,
    inspection: &GenesisBootstrapInspection,
) -> Value {
    json!({
        "operation": operation,
        "state": state,
        "receipt_digest": inspection.receipt_digest.to_string(),
        "epoch_id": inspection.epoch_id.to_string(),
        "accepted_event_id": inspection.accepted_event_id.to_string(),
        "shard_count": inspection.shard_count,
        "head_count": inspection.head_count,
        "event_shard": inspection.event_shard,
        "committed_offset": inspection.committed_offset.as_u64().to_string(),
    })
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::str::FromStr as _;

    use super::*;
    use ostk_fleet_recall::memory_contracts::bootstrap::{CommittedOffsetV1, EpochId};
    use ostk_fleet_recall::memory_contracts::digest::Sha256Digest;
    use ostk_fleet_recall::memory_contracts::evidence::AcceptedEventId;

    #[test]
    fn accepts_exact_one_lf_fixture_framing() {
        let path = Path::new("contracts/dynamic-memory/v1/bootstrap-receipt.jsonl");
        let record = read_framed_canonical_record(path).unwrap();
        assert_eq!(record.last(), Some(&b'}'));
        require_canonical(&record).unwrap();
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
    fn scope_and_pin_are_not_cli_routing_inputs() {
        let parsed = Cli::try_parse_from([
            "ostk-control-bootstrap",
            "inspect",
            "--receipt",
            "receipt.jsonl",
            "--genesis-package",
            "package.jsonl",
        ]);
        assert!(parsed.is_ok());
        let rerouted = Cli::try_parse_from([
            "ostk-control-bootstrap",
            "inspect",
            "--receipt",
            "receipt.jsonl",
            "--genesis-package",
            "package.jsonl",
            "--project",
            "attacker-selected",
        ]);
        assert!(rerouted.is_err());
    }

    #[test]
    fn append_offset_is_emitted_as_a_decimal_string() {
        let digest = Sha256Digest::from_str(&"ab".repeat(32)).unwrap();
        let inspection = GenesisBootstrapInspection {
            receipt_digest: BootstrapReceiptDigest::from_digest(digest),
            epoch_id: EpochId::from_digest(digest),
            accepted_event_id: AcceptedEventId::from_digest(digest),
            shard_count: 16,
            head_count: 16,
            event_shard: 5,
            committed_offset: CommittedOffsetV1::new(i64::MAX as u64).unwrap(),
        };
        let value = output("inspect", "complete", &inspection);
        assert_eq!(value["committed_offset"], i64::MAX.to_string());
        assert!(value["committed_offset"].is_string());
    }
}
