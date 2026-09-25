//! Workstation-only writer-authority installer.
//!
//! `ostk-authority-install apply` gives the configured physical
//! `(tenant_id, project)` an active generation-2 registry head bound to the
//! configured contract namespaces, then prints one JSON report whose `pins`
//! object is the writer-authority pin group every event-first writer for that
//! physical scope exports. It is idempotent: a re-run skips every durable step
//! and prints the same pins and activation.
//!
//! `apply --target generation-3` goes one generation further, to the
//! generation-3 collected-items package the collected-item connectors need
//! (ADR 0008). The default stays `generation-2`, so upgrading the binary moves
//! no scope. `--target` only chooses which compiled-in package to install; it
//! is not an authority override, and a head already at or past the target is
//! left where it is: a generation-3 head is never moved back to generation 2.
//!
//! Environment (nothing else, and no CLI authority override):
//!
//! - `FLEET_RECALL_DATABASE_URL`: the schema owner/migrator login, the same
//!   credential convention as `ostk-fleet-recall migrate`, because the steps
//!   write the control and registry tables no application role may write.
//!   `FLEET_RECALL_ALLOW_INSECURE_LOCAL_DATABASE=1` is the loopback escape;
//! - `FLEET_RECALL_TENANT_ID` and `FLEET_RECALL_PROJECT`: the physical scope;
//! - `FLEET_RECALL_CONTRACT_TENANT_NAMESPACE` and
//!   `FLEET_RECALL_CONTRACT_PROJECT_NAMESPACE`: the semantic scope.
//!
//! The ceremony signatures are the public fixture keys and are nominal (D4);
//! see `ostk_fleet_recall::registry_activation::install`. Like the other
//! activation CLIs, this binary is not in the production image.

use clap::{Parser, Subcommand, ValueEnum};
use ostk_fleet_recall::config::{WriterProcessConfig, contract_semantic_scope_from_env};
use ostk_fleet_recall::registry_activation::install::{
    AuthorityInstallRequestV1, InstallTargetV1, install_writer_authority,
};
use ostk_fleet_recall::store::cockroach::{CockroachStore, PoolConfig, RetryPolicy};

const APPLICATION_NAME: &str = "ostk-authority-install";
const MAX_CONNECTIONS: u32 = 2;
/// Each step is one serializable transaction; retry only its 40001 aborts.
const RETRY: RetryPolicy = RetryPolicy {
    max_attempts: 10,
    initial_backoff: std::time::Duration::from_millis(10),
    max_backoff: std::time::Duration::from_millis(500),
};

#[derive(Debug, Parser)]
#[command(
    name = "ostk-authority-install",
    version,
    about = "Private, workstation-only writer-authority installer (generation 2, or 3 on request)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Install, or finish installing, the writer authority for the configured
    /// physical scope and print its pins.
    Apply {
        /// The registry package the head ends at. A head already at or past
        /// it is left where it is.
        #[arg(long, value_enum, default_value_t = Target::Generation2)]
        target: Target,
    },
}

/// The packages `--target` names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Target {
    /// The generation-2 connector package (git, transcript, CI).
    #[value(name = "generation-2")]
    Generation2,
    /// The generation-3 collected-items package (generation 2 plus the
    /// collected-item connectors).
    #[value(name = "generation-3")]
    Generation3,
}

impl From<Target> for InstallTargetV1 {
    fn from(target: Target) -> Self {
        match target {
            Target::Generation2 => Self::Generation2,
            Target::Generation3 => Self::Generation3,
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let Cli {
        command: Command::Apply { target },
    } = Cli::parse();
    let process = WriterProcessConfig::from_migrator_env(APPLICATION_NAME)?;
    let semantic_scope = contract_semantic_scope_from_env()?;
    let store = CockroachStore::connect_migrator(
        process.database_url(),
        process.database_ssl_policy(),
        process.physical_scope().clone(),
        PoolConfig {
            max_connections: MAX_CONNECTIONS,
            ..PoolConfig::default()
        },
    )
    .await?;
    let report = install_writer_authority(
        store.pool(),
        &AuthorityInstallRequestV1 {
            physical_scope: process.physical_scope().clone(),
            semantic_scope,
            target: target.into(),
        },
        RETRY,
    )
    .await?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(arguments: &[&str]) -> Result<Target, clap::Error> {
        let Cli {
            command: Command::Apply { target },
        } = Cli::try_parse_from(
            std::iter::once("ostk-authority-install").chain(arguments.iter().copied()),
        )?;
        Ok(target)
    }

    #[test]
    fn apply_defaults_to_generation_two_and_names_generation_three_on_request() {
        assert_eq!(
            InstallTargetV1::from(parse(&["apply"]).unwrap()),
            InstallTargetV1::Generation2
        );
        assert_eq!(
            InstallTargetV1::from(parse(&["apply", "--target", "generation-2"]).unwrap()),
            InstallTargetV1::Generation2
        );
        assert_eq!(
            InstallTargetV1::from(parse(&["apply", "--target", "generation-3"]).unwrap()),
            InstallTargetV1::Generation3
        );
        for unknown in ["generation-4", "3", "generation3"] {
            assert!(
                parse(&["apply", "--target", unknown]).is_err(),
                "{unknown} is not a target"
            );
        }
    }
}
