//! Private, apply-only at-rest supersession of pre-profile-3 git facts
//! (ADR 0006 D9, amendment of 2026-09-27).
//!
//! The sources file and a dry-run switch are the only CLI inputs. Database
//! identity and fleet scope come exclusively from the dedicated
//! `FLEET_RECALL_SUPERSESSION_*` variables; the writer-authority pins and the
//! content key come from their own variables, exactly as the worker reads
//! them. This process has no server, inspection, or routing surface, prints
//! one JSON line, and exits 1 when the ledger quarantined a successor.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context as _, anyhow};
use clap::{Args, Parser, Subcommand};
use ostk_fleet_recall::config::{
    SupersessionRuntimeConfig, WriterAuthorityConfig, content_key_encryption_key,
};
use ostk_fleet_recall::evidence_supersession::{
    SupersessionReportV1, SupersessionRequestV1, run_supersession,
};
use ostk_fleet_recall::private_postgres::{
    PrivatePostgresSslPolicy, private_postgres_connect_options,
};
use ostk_fleet_recall::registry_witness::WriterAuthorityRuntime;
use ostk_fleet_recall::store::cockroach::RetryPolicy;
use ostk_fleet_recall::worker::WorkerSourcesV1;
use sqlx::postgres::PgPoolOptions;

const APPLICATION_NAME: &str = "ostk-evidence-supersede";
const MAX_CONNECTIONS: u32 = 2;

#[derive(Parser)]
#[command(
    name = "ostk-evidence-supersede",
    version,
    about = "Private, deployment-authorized at-rest supersession of pre-profile-3 git facts"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Append the redacted successor of every raw git fact and erase the raw
    /// representation, or report what would be done.
    Apply(ApplyArgs),
}

#[derive(Args)]
struct ApplyArgs {
    /// The worker's sources file: every git source it names is bound to the
    /// active package, and a fact is re-rendered only under the source it was
    /// admitted from.
    #[arg(long, value_name = "PATH")]
    sources: PathBuf,
    /// Compute every decision and write nothing.
    #[arg(long)]
    dry_run: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<ExitCode> {
    let cli = Cli::parse();
    let Command::Apply(args) = &cli.command;
    let sources = WorkerSourcesV1::load(&args.sources)
        .with_context(|| format!("loading the sources file {}", args.sources.display()))?;
    let config = SupersessionRuntimeConfig::from_env()?;
    // The pass appends under the active head and opens the raw content it
    // rewrites, so both the pins and the key are required, not optional.
    let authority = WriterAuthorityConfig::from_env()?.ok_or_else(|| {
        anyhow!(
            "the writer-authority pin group (FLEET_RECALL_CONTRACT_TENANT_NAMESPACE, \
             FLEET_RECALL_CONTRACT_PROJECT_NAMESPACE, FLEET_RECALL_BOOTSTRAP_RECEIPT_DIGEST) \
             is required"
        )
    })?;
    let kek = content_key_encryption_key()?;

    // CLI values and the complete dedicated runtime configuration have both
    // been validated before sqlx parses options or can consult ambient state.
    let connect_options = private_postgres_connect_options(
        config.database_url(),
        APPLICATION_NAME,
        PrivatePostgresSslPolicy::VerifyFull,
    )?;
    let pool = PgPoolOptions::new()
        .max_connections(MAX_CONNECTIONS)
        .min_connections(0)
        .acquire_timeout(Duration::from_secs(10))
        .connect_lazy_with(connect_options);

    // Lazy construction above opens no socket. This is the first network
    // action, and its error intentionally contains no URL, host, or credential.
    let connection = pool
        .acquire()
        .await
        .map_err(|_| anyhow!("connect private evidence supersession database failed"))?;
    drop(connection);

    let (runtime, _startup) = WriterAuthorityRuntime::start(
        pool.clone(),
        config.trusted_scope().clone(),
        authority,
        RetryPolicy::default(),
    )
    .await?;
    let report = run_supersession(
        &pool,
        &runtime,
        &kek,
        SupersessionRequestV1 {
            sources: &sources,
            dry_run: args.dry_run,
        },
    )
    .await?;
    println!("{}", serde_json::to_string(&report)?);
    Ok(exit_code(&report))
}

/// A quarantined successor is a refusal the operator must see: exit 1.
fn exit_code(report: &SupersessionReportV1) -> ExitCode {
    if report.quarantined > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::{OsStr, OsString};
    use std::process::Command as ProcessCommand;

    use clap::error::ErrorKind;

    use super::*;

    const EXPLICIT_URL: &str = "postgresql://superseder:explicit-secret@cluster.example:26257/fleet_recall?sslmode=verify-full";
    const SUBPROCESS_CASE: &str = "OSTK_EVIDENCE_SUPERSESSION_TEST_CASE";

    fn valid_cli() -> [&'static str; 4] {
        [
            "ostk-evidence-supersede",
            "apply",
            "--sources",
            "/etc/ostk/sources.json",
        ]
    }

    fn parsed_apply_args(
        values: impl IntoIterator<Item = impl Into<OsString> + Clone>,
    ) -> ApplyArgs {
        let cli = Cli::try_parse_from(values).expect("syntactically complete apply command");
        let Command::Apply(args) = cli.command;
        args
    }

    #[test]
    fn cli_is_apply_only_and_has_no_authority_or_transport_inputs() {
        assert!(Cli::try_parse_from(valid_cli()).is_ok());
        let mut dry = valid_cli().to_vec();
        dry.push("--dry-run");
        assert!(parsed_apply_args(dry).dry_run);
        assert!(!parsed_apply_args(valid_cli()).dry_run);
        assert!(Cli::try_parse_from(["ostk-evidence-supersede", "inspect"]).is_err());
        assert!(Cli::try_parse_from(["ostk-evidence-supersede", "serve"]).is_err());

        let missing = Cli::try_parse_from(["ostk-evidence-supersede", "apply"])
            .err()
            .unwrap();
        assert_eq!(missing.kind(), ErrorKind::MissingRequiredArgument);
        assert_eq!(missing.exit_code(), 2);

        for forbidden in [
            "--database-url",
            "--tenant-id",
            "--project",
            "--agent",
            "--session-id",
            "--privacy-tier",
            "--kek",
            "--bootstrap-receipt-digest",
            "--event-id",
        ] {
            let mut rerouted = valid_cli().to_vec();
            rerouted.extend([forbidden, "attacker-selected"]);
            assert!(
                Cli::try_parse_from(rerouted).is_err(),
                "accepted forbidden input {forbidden}"
            );
        }
    }

    #[test]
    fn output_is_one_bounded_line_with_no_secret_and_exit_follows_quarantine() {
        let mut report = SupersessionReportV1::new(false);
        report.events_scanned = 12;
        report.git_facts_scanned = 9;
        report.superseded = 2;
        report
            .rows_removed
            .insert("memory_body_objects_v1".into(), 2);
        let encoded = serde_json::to_string(&report).unwrap();
        assert!(!encoded.contains('\n'));
        assert!(encoded.len() < 1_024);
        let value: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        assert_eq!(value["operation"], "apply");
        assert_eq!(value["state"], "applied");
        assert_eq!(value["superseded"], 2);
        assert_eq!(value["rows_removed"]["memory_body_objects_v1"], 2);
        for forbidden in [
            "postgresql://",
            "explicit-secret",
            "sources",
            "FLEET_RECALL",
            "kek",
        ] {
            assert!(!encoded.contains(forbidden), "output exposed {forbidden}");
        }
        assert_eq!(exit_code(&report), ExitCode::SUCCESS);
        report.quarantined = 1;
        assert_eq!(exit_code(&report), ExitCode::from(1));
    }

    #[test]
    fn postgres_environment_is_rejected_without_exposing_values() {
        let test_executable = std::env::current_exe().unwrap();
        let mut command = ProcessCommand::new(test_executable);
        remove_inherited_pg_environment(&mut command);
        command
            .arg("--exact")
            .arg("tests::postgres_environment_subprocess_probe")
            .arg("--nocapture")
            .env(SUBPROCESS_CASE, "pg")
            .env("PGOPTIONS", "-c search_path=attacker")
            .env("pGsSlKeY", "super-secret-poison");
        let output = command.output().unwrap();
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
        assert_eq!(case, "pg");
        let error = private_postgres_connect_options(
            EXPLICIT_URL,
            APPLICATION_NAME,
            PrivatePostgresSslPolicy::VerifyFull,
        )
        .expect_err("ambient PostgreSQL variables must be rejected")
        .to_string();
        assert!(error.contains("\"PGOPTIONS\""));
        assert!(error.contains("\"pGsSlKeY\""));
        for secret in [
            "search_path=attacker",
            "super-secret-poison",
            "explicit-secret",
            EXPLICIT_URL,
        ] {
            assert!(!error.contains(secret), "error exposed {secret}");
        }
    }
}
