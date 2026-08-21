//! Private, workstation-only bootstrap-manifest import (W1-IMPORT).
//!
//! This binary has no public server route. It admits exactly one
//! `bootstrap.manifest.accepted` accepted event: the signed, content-addressed
//! enumeration `docs/DYNAMIC_MEMORY_ARCHITECTURE.md`'s "Staged implementation"
//! section names as the way "existing chunks, claims, conflicts, and receipts
//! enter the new history."
//!
//! # Offline preflight before any database URL
//!
//! [`verify_artifacts`] reads the canonical accepted-statement artifact, an
//! operator-supplied dump of the exact legacy rows it claims, and
//! independently recomputes the manifest digest from that dump using
//! [`legacy_row_digest`] — the same recipe
//! [`BootstrapManifestRowV1::row_digest`] pins. A mismatch refuses before the
//! database URL environment variable is even read, exactly like
//! `ostk-registry-generic-successor-activate` closes its ceremony before
//! `sqlx` options are parsed.
//!
//! # Projection
//!
//! The append's projection ([`BootstrapImportProjection`]) writes one row per
//! imported legacy identity to a proposed side table,
//! `memory_bootstrap_import_rows` (`tenant_id`, `project`, `table_name`,
//! `row_key`, `row_digest`, `accepted_event_id`; `PRIMARY KEY (tenant_id,
//! project, table_name, row_key)`), which the SCHEMA lane has not yet
//! migrated in. A
//! second manifest naming an already-imported row with different bytes fails
//! the whole append transaction closed — no event row, no head advance —
//! exactly like a stored-bytes divergence under one accepted-event ID does
//! for `RelationAttestation`/`MemoryClaim` (see
//! `evidence_ledger::appendable`'s module documentation).

use std::fs::File;
use std::io::{BufRead as _, BufReader, Read as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, anyhow, ensure};
use clap::{Args, Parser, Subcommand};
use ostk_fleet_recall::FleetScope;
use ostk_fleet_recall::control_log::TrustedControlScope;
use ostk_fleet_recall::evidence_ledger::{
    AcceptedEventRepository, AppendOutcome, AppendProjection, AppendableAcceptedEvent,
    BootstrapImportProjection, CockroachAcceptedEventRepository,
};
use ostk_fleet_recall::memory_contracts::bootstrap_manifest::{
    BootstrapManifestAcceptedStatementV1, BootstrapManifestRowV1, LegacyPrimaryKeyComponentV1,
    LegacyTableV1, legacy_row_digest,
};
use ostk_fleet_recall::memory_contracts::canonical::{
    MAX_INPUT_BYTES, decode_strict, encode_canonical, require_canonical,
};
use ostk_fleet_recall::memory_contracts::common::ContractId;
use ostk_fleet_recall::private_postgres::{
    PrivatePostgresSslPolicy, private_postgres_connect_options,
};
use ostk_fleet_recall::store::cockroach::RetryPolicy;
use ostk_recall_core::PrivacyTier;
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

const APPLICATION_NAME: &str = "ostk-bootstrap-manifest-import";
const MAX_CONNECTIONS: u32 = 2;

#[derive(Debug, Parser)]
#[command(
    name = "ostk-bootstrap-manifest-import",
    version,
    about = "Private, workstation-authorized bootstrap-manifest import of legacy chunks, claims, conflicts, and receipts"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Verify the offline artifacts and append the bootstrap-manifest event.
    Apply(ArtifactArgs),
    /// Verify the offline artifacts only; do not connect to a database.
    Preflight(ArtifactArgs),
}

#[derive(Debug, Args)]
struct ArtifactArgs {
    /// Canonical `BootstrapManifestAcceptedStatementV1` plus one LF.
    #[arg(long, value_name = "PATH")]
    manifest_statement: PathBuf,
    /// One JSON object per line: `{"table":..., "primary_key":[...],
    /// "row_bytes_hex":...}` for every legacy row the statement's manifest
    /// claims. `row_bytes_hex` is the operator's own canonical row encoding —
    /// see [`legacy_row_digest`].
    #[arg(long, value_name = "PATH")]
    legacy_row_dump: PathBuf,
}

/// One dumped legacy row: identity plus its own canonical byte encoding.
#[derive(Debug, Deserialize)]
struct DumpedLegacyRow {
    table: LegacyTableV1,
    primary_key: Vec<LegacyPrimaryKeyComponentV1>,
    row_bytes_hex: String,
}

#[derive(Debug)]
struct VerifiedArtifacts {
    statement: BootstrapManifestAcceptedStatementV1,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let args = match &cli.command {
        Command::Apply(args) | Command::Preflight(args) => args,
    };

    // Pre-connect trust boundary: the artifact and the dumped row set are
    // fully cross-verified, offline, before any database URL is read.
    let artifacts = verify_artifacts(args)?;

    if matches!(cli.command, Command::Preflight(_)) {
        println!(
            "{}",
            serde_json::to_string(&preflight_output(&artifacts.statement))?
        );
        return Ok(());
    }

    let scope = trusted_scope_from_env()?;
    let database_url = std::env::var("FLEET_RECALL_BOOTSTRAP_IMPORT_DATABASE_URL")
        .context("FLEET_RECALL_BOOTSTRAP_IMPORT_DATABASE_URL is required")?;
    let connect_options = private_postgres_connect_options(
        &database_url,
        APPLICATION_NAME,
        PrivatePostgresSslPolicy::VerifyFull,
    )?;
    let pool = PgPoolOptions::new()
        .max_connections(MAX_CONNECTIONS)
        .min_connections(0)
        .acquire_timeout(Duration::from_secs(10))
        .connect_lazy_with(connect_options);
    let repository =
        CockroachAcceptedEventRepository::new(pool.clone(), scope.clone(), RetryPolicy::default());

    // Constructing the lazy pool and repository opens no socket. This
    // explicit acquire is the first network operation, after every offline
    // constructor has succeeded.
    let connection = pool
        .acquire()
        .await
        .map_err(|_| anyhow!("connect private bootstrap-manifest import database failed"))?;
    drop(connection);

    ensure!(
        artifacts.statement.scope == *scope.semantic_scope(),
        "manifest statement scope does not match the deployment-bound semantic scope"
    );

    let witness = repository.read_writer_authority_witness().await?;
    let appendable = AppendableAcceptedEvent::bootstrap_manifest(&artifacts.statement, &witness)?;
    let projection: Arc<dyn AppendProjection> = Arc::new(BootstrapImportProjection {
        scope: scope.clone(),
        rows: artifacts.statement.manifest.rows.clone(),
    });
    let outcome = repository.append(&witness, &appendable, projection).await?;
    println!(
        "{}",
        serde_json::to_string(&outcome_output(&artifacts.statement, &outcome))?
    );
    Ok(())
}

fn verify_artifacts(args: &ArtifactArgs) -> anyhow::Result<VerifiedArtifacts> {
    let statement_bytes = read_framed_canonical_record(&args.manifest_statement)?;
    let statement: BootstrapManifestAcceptedStatementV1 = decode_strict(&statement_bytes)?;
    statement.validate_shape()?;
    ensure!(
        encode_canonical(&statement)? == statement_bytes,
        "manifest statement did not round-trip canonically"
    );

    let recomputed = recompute_manifest_from_dump(&statement, &args.legacy_row_dump)?;
    ensure!(
        recomputed.manifest_digest()? == statement.manifest.manifest_digest()?,
        "dumped legacy rows do not reproduce the manifest digest the statement claims"
    );

    Ok(VerifiedArtifacts { statement })
}

/// Independently rebuild the claimed manifest from a dumped row set.
///
/// Every row's digest is recomputed from its own dumped bytes via
/// [`legacy_row_digest`] — never trusted from the dump — so a dump that
/// merely repeats the statement's own `row_digest` values cannot pass this
/// check.
fn recompute_manifest_from_dump(
    statement: &BootstrapManifestAcceptedStatementV1,
    dump_path: &Path,
) -> anyhow::Result<ostk_fleet_recall::memory_contracts::bootstrap_manifest::BootstrapManifestV1> {
    let file = File::open(dump_path)
        .with_context(|| format!("open legacy row dump {}", dump_path.display()))?;
    let mut rows = Vec::new();
    for (index, line) in BufReader::new(file).lines().enumerate() {
        let line = line.with_context(|| format!("read dump line {}", index + 1))?;
        if line.trim().is_empty() {
            continue;
        }
        let dumped: DumpedLegacyRow = serde_json::from_str(&line)
            .with_context(|| format!("parse dump line {}", index + 1))?;
        let row_bytes = hex::decode(&dumped.row_bytes_hex)
            .with_context(|| format!("decode row_bytes_hex on dump line {}", index + 1))?;
        rows.push(BootstrapManifestRowV1 {
            table: dumped.table,
            primary_key: dumped.primary_key,
            row_digest: legacy_row_digest(&row_bytes),
        });
    }
    rows.sort_by_key(row_identity_key);
    Ok(
        ostk_fleet_recall::memory_contracts::bootstrap_manifest::BootstrapManifestV1 {
            schema_version: statement.manifest.schema_version,
            scope: statement.manifest.scope.clone(),
            provenance_kind: statement.manifest.provenance_kind.clone(),
            rows,
        },
    )
}

fn row_identity_key(row: &BootstrapManifestRowV1) -> (LegacyTableV1, Vec<u8>) {
    // A stable, comparable proxy for `(table, primary_key)`: canonical JSON
    // encoding is deterministic, so byte comparison here matches the
    // contract's own `(table, primary_key)` ordering exactly on any input
    // this function accepts (it never runs on a value that already failed
    // `encode_canonical`, since `legacy_row_digest` cannot fail).
    let key_bytes = encode_canonical(&row.primary_key).unwrap_or_default();
    (row.table, key_bytes)
}

fn trusted_scope_from_env() -> anyhow::Result<TrustedControlScope> {
    let tenant_id = env_var("FLEET_RECALL_BOOTSTRAP_IMPORT_TENANT_ID")?;
    let tenant_id: Uuid = tenant_id
        .parse()
        .context("FLEET_RECALL_BOOTSTRAP_IMPORT_TENANT_ID must be a UUID")?;
    let project = env_var("FLEET_RECALL_BOOTSTRAP_IMPORT_PROJECT")?;
    let tenant_namespace = env_var("FLEET_RECALL_BOOTSTRAP_IMPORT_TENANT_NAMESPACE")?;
    let project_namespace = env_var("FLEET_RECALL_BOOTSTRAP_IMPORT_PROJECT_NAMESPACE")?;

    let deployment_scope = FleetScope::new(
        tenant_id,
        project,
        "private-bootstrap-manifest-import",
        None,
        PrivacyTier::T1Project,
    )
    .map_err(|error| anyhow!("FLEET_RECALL_BOOTSTRAP_IMPORT_PROJECT is invalid: {error}"))?;
    let semantic_scope =
        ostk_fleet_recall::memory_contracts::common::AuthenticatedProjectScopeV1::from_trusted_context(
            ContractId::new(tenant_namespace)
                .map_err(|error| anyhow!("FLEET_RECALL_BOOTSTRAP_IMPORT_TENANT_NAMESPACE is invalid: {error}"))?,
            ContractId::new(project_namespace).map_err(|error| {
                anyhow!("FLEET_RECALL_BOOTSTRAP_IMPORT_PROJECT_NAMESPACE is invalid: {error}")
            })?,
        );
    TrustedControlScope::from_trusted_context(&deployment_scope, semantic_scope).map_err(|error| {
        anyhow!("FLEET_RECALL_BOOTSTRAP_IMPORT physical scope is invalid: {error}")
    })
}

fn env_var(name: &'static str) -> anyhow::Result<String> {
    std::env::var(name).with_context(|| format!("{name} is required"))
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

fn preflight_output(statement: &BootstrapManifestAcceptedStatementV1) -> Value {
    json!({
        "operation": "preflight",
        "state": "verified",
        "row_count": statement.manifest.rows.len(),
        "manifest_digest": statement.manifest_digest.to_string(),
        "accepted_event_id": statement
            .accepted_event_id()
            .map(|id| id.to_string())
            .unwrap_or_default(),
    })
}

fn outcome_output(
    statement: &BootstrapManifestAcceptedStatementV1,
    outcome: &AppendOutcome,
) -> Value {
    let (state, position, chain_digest) = match outcome {
        AppendOutcome::Appended {
            position,
            chain_digest,
        } => ("appended", Some(*position), Some(*chain_digest)),
        AppendOutcome::Replayed { position } => ("exact_replay", Some(*position), None),
        AppendOutcome::Quarantined { reason, .. } => {
            return json!({
                "operation": "apply",
                "state": "quarantined",
                "reason": format!("{reason:?}"),
                "manifest_digest": statement.manifest_digest.to_string(),
            });
        }
    };
    json!({
        "operation": "apply",
        "state": state,
        "row_count": statement.manifest.rows.len(),
        "manifest_digest": statement.manifest_digest.to_string(),
        "accepted_event_id": statement
            .accepted_event_id()
            .map(|id| id.to_string())
            .unwrap_or_default(),
        "epoch_id": position.map(|position| position.epoch_id.to_string()),
        "shard": position.map(|position| position.shard),
        "committed_offset": position.map(|position| position.committed_offset.as_u64().to_string()),
        "chain_digest": chain_digest.map(|digest| digest.to_string()),
    })
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;
    use std::io::Write as _;

    use clap::Parser as _;
    use ostk_fleet_recall::memory_contracts::bootstrap_manifest::BootstrapManifestV1;
    use ostk_fleet_recall::memory_contracts::common::{
        AuthenticatedProjectScopeV1, CanonicalTimestamp, frozen_profile_reference_v1,
    };
    use ostk_fleet_recall::memory_contracts::digest::Sha256Digest;
    use ostk_fleet_recall::memory_contracts::evidence_v2::RegistryHeadBindingV1;
    use ostk_fleet_recall::memory_contracts::registry::RegistryHeadV1;

    use super::*;

    fn scope() -> AuthenticatedProjectScopeV1 {
        AuthenticatedProjectScopeV1::from_trusted_context(
            ContractId::new("tenant.w1-import-cli").unwrap(),
            ContractId::new("project.fleet-recall").unwrap(),
        )
    }

    fn row_bytes(label: &str) -> Vec<u8> {
        label.as_bytes().to_vec()
    }

    fn manifest_and_dump() -> (BootstrapManifestAcceptedStatementV1, String) {
        let chunk_bytes = row_bytes("chunk-one");
        let claim_bytes = row_bytes("claim-one");
        let manifest = BootstrapManifestV1 {
            schema_version: 1,
            scope: scope(),
            provenance_kind: ContractId::new("legacy_import").unwrap(),
            rows: vec![
                BootstrapManifestRowV1 {
                    table: LegacyTableV1::MemoryChunks,
                    primary_key: vec![LegacyPrimaryKeyComponentV1::Text {
                        value: "chunk-1".into(),
                    }],
                    row_digest: legacy_row_digest(&chunk_bytes),
                },
                BootstrapManifestRowV1 {
                    table: LegacyTableV1::MemoryClaims,
                    primary_key: vec![LegacyPrimaryKeyComponentV1::Integer { value: 1 }],
                    row_digest: legacy_row_digest(&claim_bytes),
                },
            ],
        };
        let manifest_digest = manifest.manifest_digest().unwrap();
        let statement = BootstrapManifestAcceptedStatementV1 {
            schema_version: 1,
            event_kind: ContractId::new("bootstrap.manifest.accepted").unwrap(),
            profile: frozen_profile_reference_v1(),
            scope: scope(),
            registry: RegistryHeadBindingV1 {
                head: RegistryHeadV1 {
                    activation_id: Sha256Digest::from_bytes([0xaa; 32]),
                    package_digest: Sha256Digest::from_bytes([0xbb; 32]),
                    activation_policy_digest: Sha256Digest::from_bytes([0xcc; 32]),
                },
                effective_from: CanonicalTimestamp::parse("2026-08-14T00:00:00.000000000Z")
                    .unwrap(),
                effective_until: None,
            },
            manifest,
            manifest_digest,
        };

        let mut dump = String::new();
        let _ = writeln!(
            dump,
            "{{\"table\":\"memory_chunks\",\"primary_key\":[{{\"kind\":\"text\",\"value\":\"chunk-1\"}}],\"row_bytes_hex\":\"{}\"}}",
            hex::encode(&chunk_bytes)
        );
        let _ = writeln!(
            dump,
            "{{\"table\":\"memory_claims\",\"primary_key\":[{{\"kind\":\"integer\",\"value\":1}}],\"row_bytes_hex\":\"{}\"}}",
            hex::encode(&claim_bytes)
        );
        (statement, dump)
    }

    fn write_statement(
        statement: &BootstrapManifestAcceptedStatementV1,
    ) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        let mut bytes = encode_canonical(statement).unwrap();
        bytes.push(b'\n');
        file.write_all(&bytes).unwrap();
        file
    }

    fn write_dump(dump: &str) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(dump.as_bytes()).unwrap();
        file
    }

    #[test]
    fn verifies_a_matching_artifact_and_dump() {
        let (statement, dump) = manifest_and_dump();
        let statement_file = write_statement(&statement);
        let dump_file = write_dump(&dump);
        let artifacts = verify_artifacts(&ArtifactArgs {
            manifest_statement: statement_file.path().to_owned(),
            legacy_row_dump: dump_file.path().to_owned(),
        })
        .unwrap();
        assert_eq!(
            artifacts.statement.accepted_event_id().unwrap(),
            statement.accepted_event_id().unwrap()
        );
    }

    #[test]
    fn refuses_a_dump_missing_a_row() {
        let (statement, dump) = manifest_and_dump();
        let statement_file = write_statement(&statement);
        // Keep only the first line: the claim row is missing from the dump.
        let truncated: String = dump.lines().next().unwrap().to_owned() + "\n";
        let dump_file = write_dump(&truncated);
        let error = verify_artifacts(&ArtifactArgs {
            manifest_statement: statement_file.path().to_owned(),
            legacy_row_dump: dump_file.path().to_owned(),
        })
        .unwrap_err()
        .to_string();
        assert!(error.contains("do not reproduce the manifest digest"));
    }

    #[test]
    fn refuses_a_dump_with_one_flipped_byte() {
        let (statement, dump) = manifest_and_dump();
        let statement_file = write_statement(&statement);
        // Flip one hex nibble inside the first row's `row_bytes_hex` value
        // (the plaintext "chunk-one" never appears in the dump — only its hex
        // encoding does).
        let prefix = "\"row_bytes_hex\":\"";
        let value_start = dump.find(prefix).unwrap() + prefix.len();
        let mut tampered = dump.into_bytes();
        tampered[value_start] = if tampered[value_start] == b'0' {
            b'1'
        } else {
            b'0'
        };
        let dump_file = write_dump(std::str::from_utf8(&tampered).unwrap());
        let error = verify_artifacts(&ArtifactArgs {
            manifest_statement: statement_file.path().to_owned(),
            legacy_row_dump: dump_file.path().to_owned(),
        })
        .unwrap_err()
        .to_string();
        assert!(error.contains("do not reproduce the manifest digest"));
    }

    #[test]
    fn refuses_a_dump_that_only_repeats_the_claimed_digest() {
        // A dump cannot pass by copying the statement's own row_digest values:
        // recompute_manifest_from_dump always rederives digests from
        // row_bytes_hex, never trusts a caller-declared digest field (there is
        // none in `DumpedLegacyRow`), so this is really the same property as
        // the flipped-byte case, stated for the "declared vs enforced"
        // pre-flight item.
        let (statement, _dump) = manifest_and_dump();
        let statement_file = write_statement(&statement);
        let dump_file = write_dump(
            "{\"table\":\"memory_chunks\",\"primary_key\":[{\"kind\":\"text\",\"value\":\"chunk-1\"}],\"row_bytes_hex\":\"00\"}\n",
        );
        let error = verify_artifacts(&ArtifactArgs {
            manifest_statement: statement_file.path().to_owned(),
            legacy_row_dump: dump_file.path().to_owned(),
        })
        .unwrap_err()
        .to_string();
        assert!(error.contains("do not reproduce the manifest digest"));
    }

    #[test]
    fn malformed_statement_fails_before_env_or_database_url() {
        let mut malformed = tempfile::NamedTempFile::new().unwrap();
        malformed.write_all(b"not-json\n").unwrap();
        let (_statement, dump) = manifest_and_dump();
        let dump_file = write_dump(&dump);
        let error = verify_artifacts(&ArtifactArgs {
            manifest_statement: malformed.path().to_owned(),
            legacy_row_dump: dump_file.path().to_owned(),
        })
        .unwrap_err()
        .to_string();
        assert!(!error.to_lowercase().contains("database"));
        assert!(!error.contains("FLEET_RECALL_BOOTSTRAP_IMPORT"));
    }

    #[test]
    fn parser_exposes_only_apply_and_preflight() {
        assert!(Cli::try_parse_from(["ostk-bootstrap-manifest-import", "emit"]).is_err());
        assert!(Cli::try_parse_from(["ostk-bootstrap-manifest-import", "inspect"]).is_err());
    }

    #[test]
    fn preflight_output_is_bounded_and_redacted() {
        let (statement, _dump) = manifest_and_dump();
        let output = preflight_output(&statement);
        assert_eq!(output["state"], "verified");
        assert_eq!(output["row_count"], 2);
        let serialized = serde_json::to_string(&output).unwrap();
        assert!(serialized.len() < 4_096);
        for forbidden in ["postgresql://", "FLEET_RECALL_BOOTSTRAP_IMPORT"] {
            assert!(!serialized.contains(forbidden));
        }
    }

    #[test]
    fn source_verifies_artifacts_before_any_env_read() {
        let source = include_str!("ostk-bootstrap-manifest-import.rs");
        let main = source.find("async fn main()").unwrap();
        let main_source = &source[main..];
        let verify = main_source.find("verify_artifacts(args)").unwrap();
        let env_scope = main_source.find("trusted_scope_from_env()").unwrap();
        let env_db = main_source
            .find("FLEET_RECALL_BOOTSTRAP_IMPORT_DATABASE_URL")
            .unwrap();
        assert!(verify < env_scope);
        assert!(verify < env_db);
    }
}
