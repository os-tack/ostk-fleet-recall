//! Private, apply-only reconciliation of one legacy conflict lineage.
//!
//! The durable coordinate and replay key are the only CLI inputs. Database
//! identity and fleet scope come exclusively from dedicated deployment
//! configuration; this process has no server, inspection, or routing surface.

use std::time::Duration;

use anyhow::{anyhow, ensure};
use clap::{Args, Parser, Subcommand};
use ostk_fleet_recall::config::ConflictReconciliationRuntimeConfig;
use ostk_fleet_recall::ledger::{
    CockroachConflictReconciliationRepository, ConflictDetectorReconciliation,
};
use ostk_fleet_recall::private_postgres::{
    PrivatePostgresSslPolicy, private_postgres_connect_options,
};
use ostk_fleet_recall::store::cockroach::RetryPolicy;
use serde_json::{Value, json};
use sqlx::postgres::PgPoolOptions;

const APPLICATION_NAME: &str = "ostk-conflict-reconcile";
const MAX_CONNECTIONS: u32 = 2;
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 256;
const MAX_RECONCILIATION_CLAIMS: usize = 256;
const MAX_RECONCILIATION_PAIRS: usize =
    MAX_RECONCILIATION_CLAIMS * (MAX_RECONCILIATION_CLAIMS - 1) / 2;
const RECONCILIATION_OPERATION: &str = "reconcile_conflict_detector_v2";
const RECONCILIATION_REQUEST_VERSION: u8 = 1;

#[derive(Parser)]
#[command(
    name = "ostk-conflict-reconcile",
    version,
    about = "Private, deployment-authorized conflict-detector reconciliation"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Atomically materialize the v2 lineage for one immutable legacy revision.
    Apply(ApplyArgs),
}

#[derive(Args)]
struct ApplyArgs {
    /// Positive durable ID of the legacy conflict lineage.
    #[arg(long, value_name = "INT8", allow_hyphen_values = true)]
    legacy_conflict_id: String,
    /// Positive immutable revision expected on the legacy conflict.
    #[arg(long, value_name = "INT8", allow_hyphen_values = true)]
    expected_legacy_revision: String,
    /// Bounded replay key dedicated to this mutation request.
    #[arg(long, value_name = "KEY", allow_hyphen_values = true)]
    idempotency_key: String,
}

struct ValidatedApplyArgs {
    legacy_conflict_id: i64,
    expected_legacy_revision: i64,
    idempotency_key: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let Command::Apply(raw_args) = &cli.command;
    let args = validate_apply_args(raw_args)?;
    let config = ConflictReconciliationRuntimeConfig::from_env()?;

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
    let repository = CockroachConflictReconciliationRepository::new(
        pool.clone(),
        config.trusted_scope().clone(),
        RetryPolicy::default(),
    )?;

    // Lazy construction above opens no socket. This is the first network
    // action, and its error intentionally contains no URL, host, or credential.
    let connection = pool
        .acquire()
        .await
        .map_err(|_| anyhow!("connect private conflict reconciliation database failed"))?;
    drop(connection);

    let result = repository
        .reconcile_legacy_conflict(
            config.trusted_scope(),
            args.legacy_conflict_id,
            args.expected_legacy_revision,
            &args.idempotency_key,
        )
        .await?;
    println!(
        "{}",
        serde_json::to_string(&reconciliation_output(&args, &result)?)?
    );
    Ok(())
}

fn validate_apply_args(raw: &ApplyArgs) -> anyhow::Result<ValidatedApplyArgs> {
    let legacy_conflict_id = raw
        .legacy_conflict_id
        .parse::<i64>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| anyhow!("--legacy-conflict-id must be a positive signed 64-bit integer"))?;
    let expected_legacy_revision = raw
        .expected_legacy_revision
        .parse::<i64>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| {
            anyhow!("--expected-legacy-revision must be a positive signed 64-bit integer")
        })?;
    ensure!(
        !raw.idempotency_key.is_empty()
            && raw.idempotency_key.len() <= MAX_IDEMPOTENCY_KEY_BYTES
            && raw.idempotency_key == raw.idempotency_key.trim()
            && !raw.idempotency_key.chars().any(char::is_control),
        "--idempotency-key must be 1 to {MAX_IDEMPOTENCY_KEY_BYTES} bytes with no surrounding whitespace or control characters"
    );
    Ok(ValidatedApplyArgs {
        legacy_conflict_id,
        expected_legacy_revision,
        idempotency_key: raw.idempotency_key.clone(),
    })
}

fn reconciliation_output(
    request: &ValidatedApplyArgs,
    result: &ConflictDetectorReconciliation,
) -> anyhow::Result<Value> {
    let v2_state = validate_reconciliation_projection(request, result)?;
    let state = if result.idempotent_replay {
        "exact_replay"
    } else {
        "materialized"
    };

    Ok(json!({
        "operation": "apply",
        "state": state,
        "legacy_conflict_id": result.legacy_conflict_id.to_string(),
        "legacy_conflict_revision": result.legacy_conflict_revision.to_string(),
        "conflict_id": result.conflict_id.to_string(),
        "reconciliation_event_id": result.reconciliation_event_id.to_string(),
        "v2_state": v2_state,
        "candidate_count": result.candidate_count,
        "incompatibility_pair_count": result.incompatibility_pair_count,
        "v2_member_count": result.v2_member_ids.len(),
        "newly_disputed_claim_count": result.newly_disputed_claim_ids.len(),
        "restored_claim_count": result.restored_claim_ids.len(),
        "retained_disputed_claim_count": result.retained_disputed_claim_ids.len(),
        "provenance_ambiguous_claim_count": result.provenance_ambiguous_claim_ids.len(),
    }))
}

fn validate_reconciliation_projection(
    request: &ValidatedApplyArgs,
    result: &ConflictDetectorReconciliation,
) -> anyhow::Result<&'static str> {
    ensure!(
        result.operation == RECONCILIATION_OPERATION
            && result.request_version == RECONCILIATION_REQUEST_VERSION
            && result.legacy_conflict_id == request.legacy_conflict_id
            && result.legacy_conflict_revision == request.expected_legacy_revision
            && result.legacy_conflict_id > 0
            && result.legacy_conflict_revision > 0
            && result.conflict_id > 0
            && result.conflict_id != result.legacy_conflict_id
            && !result.reconciliation_event_id.is_nil()
            && result.reconciliation_event_id.get_version_num() == 7
            && result.reconciliation_event_id.get_variant() == uuid::Variant::RFC4122,
        "conflict reconciliation returned an invalid durable coordinate"
    );
    ensure!(
        result.candidate_count <= MAX_RECONCILIATION_CLAIMS
            && result.incompatibility_pair_count <= MAX_RECONCILIATION_PAIRS
            && result.v2_member_ids.len() <= MAX_RECONCILIATION_CLAIMS
            && result.newly_disputed_claim_ids.len() <= MAX_RECONCILIATION_CLAIMS
            && result.restored_claim_ids.len() <= MAX_RECONCILIATION_CLAIMS
            && result.retained_disputed_claim_ids.len() <= MAX_RECONCILIATION_CLAIMS
            && result.provenance_ambiguous_claim_ids.len() <= MAX_RECONCILIATION_CLAIMS,
        "conflict reconciliation returned an out-of-bounds projection"
    );
    ensure!(
        ids_are_strictly_increasing_positive(&result.v2_member_ids)
            && ids_are_strictly_increasing_positive(&result.newly_disputed_claim_ids)
            && ids_are_strictly_increasing_positive(&result.restored_claim_ids)
            && ids_are_strictly_increasing_positive(&result.retained_disputed_claim_ids)
            && ids_are_strictly_increasing_positive(&result.provenance_ambiguous_claim_ids),
        "conflict reconciliation returned an invalid claim coordinate"
    );
    ensure!(
        ids_are_subset(
            &result.provenance_ambiguous_claim_ids,
            &result.retained_disputed_claim_ids,
        ) && ids_are_pairwise_disjoint(
            &result.newly_disputed_claim_ids,
            &result.restored_claim_ids,
        ) && ids_are_pairwise_disjoint(
            &result.newly_disputed_claim_ids,
            &result.retained_disputed_claim_ids,
        ) && ids_are_pairwise_disjoint(
            &result.restored_claim_ids,
            &result.retained_disputed_claim_ids,
        ) && ids_are_subset(&result.newly_disputed_claim_ids, &result.v2_member_ids,)
            && ids_are_pairwise_disjoint(&result.restored_claim_ids, &result.v2_member_ids)
            && result.v2_member_ids.iter().all(|id| {
                result.newly_disputed_claim_ids.binary_search(id).is_ok()
                    || result.retained_disputed_claim_ids.binary_search(id).is_ok()
            }),
        "conflict reconciliation returned an inconsistent claim projection"
    );
    let transition_count = result.newly_disputed_claim_ids.len()
        + result.restored_claim_ids.len()
        + result.retained_disputed_claim_ids.len();
    let max_candidate_pairs = result
        .candidate_count
        .saturating_mul(result.candidate_count.saturating_sub(1))
        / 2;
    let max_member_pairs = result
        .v2_member_ids
        .len()
        .saturating_mul(result.v2_member_ids.len().saturating_sub(1))
        / 2;
    ensure!(
        transition_count <= result.candidate_count
            && result.v2_member_ids.len() <= result.candidate_count
            && result.incompatibility_pair_count <= max_candidate_pairs
            && result.incompatibility_pair_count <= max_member_pairs,
        "conflict reconciliation returned impossible candidate counts"
    );
    let v2_state = match result.v2_state.as_str() {
        "open"
            if result.incompatibility_pair_count > 0
                && result.v2_member_ids.len() >= 2
                && result.v2_member_ids.len()
                    <= result
                        .incompatibility_pair_count
                        .saturating_mul(2)
                        .min(result.candidate_count) =>
        {
            "open"
        }
        "dismissed"
            if result.incompatibility_pair_count == 0
                && result.v2_member_ids.is_empty()
                && result.newly_disputed_claim_ids.is_empty() =>
        {
            "dismissed"
        }
        _ => {
            return Err(anyhow!(
                "conflict reconciliation returned an invalid v2 state projection"
            ));
        }
    };
    Ok(v2_state)
}

fn ids_are_strictly_increasing_positive(ids: &[i64]) -> bool {
    ids.first().is_none_or(|id| *id > 0)
        && ids.windows(2).all(|pair| pair[0] > 0 && pair[0] < pair[1])
}

fn ids_are_subset(subset: &[i64], superset: &[i64]) -> bool {
    subset.iter().all(|id| superset.binary_search(id).is_ok())
}

fn ids_are_pairwise_disjoint(left: &[i64], right: &[i64]) -> bool {
    left.iter().all(|id| right.binary_search(id).is_err())
}

#[cfg(test)]
mod tests {
    use std::ffi::{OsStr, OsString};
    use std::process::Command as ProcessCommand;

    use clap::error::ErrorKind;
    use uuid::Uuid;

    use super::*;

    const EXPLICIT_URL: &str = "postgresql://reconciler:explicit-secret@cluster.example:26257/fleet_recall?sslmode=verify-full";
    const SUBPROCESS_CASE: &str = "OSTK_CONFLICT_RECONCILIATION_TEST_CASE";

    fn valid_cli() -> [&'static str; 8] {
        [
            "ostk-conflict-reconcile",
            "apply",
            "--legacy-conflict-id",
            "41",
            "--expected-legacy-revision",
            "7",
            "--idempotency-key",
            "reconcile-41-r7",
        ]
    }

    fn request() -> ValidatedApplyArgs {
        ValidatedApplyArgs {
            legacy_conflict_id: 41,
            expected_legacy_revision: 7,
            idempotency_key: "reconcile-41-r7".into(),
        }
    }

    fn result(idempotent_replay: bool) -> ConflictDetectorReconciliation {
        ConflictDetectorReconciliation {
            operation: RECONCILIATION_OPERATION.into(),
            request_version: RECONCILIATION_REQUEST_VERSION,
            legacy_conflict_id: 41,
            legacy_conflict_revision: 7,
            conflict_id: 73,
            reconciliation_event_id: Uuid::parse_str("0198a849-f6ae-7d61-9800-000000000073")
                .unwrap(),
            v2_state: "dismissed".into(),
            candidate_count: 3,
            incompatibility_pair_count: 0,
            v2_member_ids: vec![],
            newly_disputed_claim_ids: vec![],
            restored_claim_ids: vec![11],
            retained_disputed_claim_ids: vec![12, 13],
            provenance_ambiguous_claim_ids: vec![13],
            idempotent_replay,
        }
    }

    fn open_result() -> ConflictDetectorReconciliation {
        let mut result = result(false);
        result.v2_state = "open".into();
        result.candidate_count = 4;
        result.incompatibility_pair_count = 1;
        result.v2_member_ids = vec![11, 12];
        result.newly_disputed_claim_ids = vec![11];
        result.restored_claim_ids = vec![13];
        result.retained_disputed_claim_ids = vec![12, 14];
        result.provenance_ambiguous_claim_ids = vec![14];
        result
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
        assert!(Cli::try_parse_from(["ostk-conflict-reconcile", "inspect"]).is_err());
        assert!(Cli::try_parse_from(["ostk-conflict-reconcile", "serve"]).is_err());

        for forbidden in [
            "--database-url",
            "--tenant-id",
            "--project",
            "--agent",
            "--session-id",
            "--privacy-tier",
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
    fn cli_rejects_missing_invalid_and_unbounded_mutation_coordinates() {
        let missing = Cli::try_parse_from([
            "ostk-conflict-reconcile",
            "apply",
            "--legacy-conflict-id",
            "41",
        ])
        .err()
        .unwrap();
        assert_eq!(missing.kind(), ErrorKind::MissingRequiredArgument);
        assert_eq!(missing.exit_code(), 2);

        for invalid in ["0", "-1", "9223372036854775808", "not-an-integer"] {
            for flag in ["--legacy-conflict-id", "--expected-legacy-revision"] {
                let mut values = valid_cli().to_vec();
                let position = values.iter().position(|value| *value == flag).unwrap() + 1;
                values[position] = invalid;
                let raw = parsed_apply_args(values);
                let error = validate_apply_args(&raw).err().unwrap().to_string();
                assert!(error.starts_with(flag));
                assert!(!error.contains(invalid));
                assert!(!error.contains('\n'));
            }
        }

        for invalid in [
            "",
            " replay-key",
            "replay-key ",
            "secret-replay\nforged-line",
        ] {
            let mut values = valid_cli().to_vec();
            values[7] = invalid;
            let raw = parsed_apply_args(values);
            let error = validate_apply_args(&raw).err().unwrap().to_string();
            assert_eq!(
                error,
                "--idempotency-key must be 1 to 256 bytes with no surrounding whitespace or control characters"
            );
            if !invalid.is_empty() {
                assert!(!error.contains(invalid));
            }
            assert!(!error.contains('\n'));
        }
        let oversized = "x".repeat(MAX_IDEMPOTENCY_KEY_BYTES + 1);
        let mut values = valid_cli()
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        values[7].clone_from(&oversized);
        let raw = parsed_apply_args(values);
        let error = validate_apply_args(&raw).err().unwrap().to_string();
        assert_eq!(
            error,
            "--idempotency-key must be 1 to 256 bytes with no surrounding whitespace or control characters"
        );
        assert!(!error.contains(&oversized));
    }

    #[test]
    fn source_orders_validation_and_lazy_construction_before_redacted_acquire() {
        let source = include_str!("ostk-conflict-reconcile.rs");
        let main = source.find("async fn main()").unwrap();
        let main_source = &source[main..source.find("fn validate_apply_args(").unwrap()];
        let cli = main_source.find("let cli = Cli::parse();").unwrap();
        let input_validation = main_source.find("validate_apply_args(raw_args)?").unwrap();
        let config = main_source
            .find("ConflictReconciliationRuntimeConfig::from_env()")
            .unwrap();
        let options = main_source
            .find("private_postgres_connect_options(")
            .unwrap();
        let lazy = main_source.find(".connect_lazy_with(").unwrap();
        let repository = main_source
            .find("CockroachConflictReconciliationRepository::new(")
            .unwrap();
        let acquire = main_source.find("let connection = pool").unwrap();
        let apply = main_source.find(".reconcile_legacy_conflict(").unwrap();

        assert!(cli < input_validation && input_validation < config && config < options);
        assert!(options < lazy && lazy < repository && repository < acquire && acquire < apply);
        assert!(source.contains(".min_connections(0)"));
        assert!(source.contains("connect private conflict reconciliation database failed"));
        let eager_pool_helper = [".connect_", "with("].concat();
        assert!(!source.contains(&eager_pool_helper));
    }

    #[test]
    fn output_is_exact_bounded_redacted_and_uses_decimal_string_ids() {
        let value = reconciliation_output(&request(), &result(false)).unwrap();
        let mut keys = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "candidate_count",
                "conflict_id",
                "incompatibility_pair_count",
                "legacy_conflict_id",
                "legacy_conflict_revision",
                "newly_disputed_claim_count",
                "operation",
                "provenance_ambiguous_claim_count",
                "reconciliation_event_id",
                "restored_claim_count",
                "retained_disputed_claim_count",
                "state",
                "v2_member_count",
                "v2_state",
            ]
        );
        assert_eq!(value["operation"], "apply");
        assert_eq!(value["state"], "materialized");
        assert_eq!(value["legacy_conflict_id"], "41");
        assert_eq!(value["legacy_conflict_revision"], "7");
        assert_eq!(value["conflict_id"], "73");
        assert!(value["legacy_conflict_id"].is_string());
        assert!(value["conflict_id"].is_string());
        assert_eq!(value["restored_claim_count"], 1);
        assert_eq!(value["provenance_ambiguous_claim_count"], 1);

        let open = reconciliation_output(&request(), &open_result()).unwrap();
        assert_eq!(open["v2_state"], "open");
        assert_eq!(open["incompatibility_pair_count"], 1);
        assert_eq!(open["v2_member_count"], 2);

        let replay = reconciliation_output(&request(), &result(true)).unwrap();
        assert_eq!(replay["state"], "exact_replay");
        let encoded = serde_json::to_string(&replay).unwrap();
        assert!(encoded.len() < 1_024);
        for forbidden in [
            "postgresql://",
            "explicit-secret",
            "idempotency_key",
            "reconcile-41-r7",
            "request_version",
            RECONCILIATION_OPERATION,
        ] {
            assert!(!encoded.contains(forbidden), "output exposed {forbidden}");
        }
    }

    #[test]
    fn output_fails_closed_on_durable_coordinate_and_bound_violations() {
        let mut invalid = result(false);
        invalid.operation = "future-operation".into();
        assert!(reconciliation_output(&request(), &invalid).is_err());

        let mut invalid = result(false);
        invalid.request_version = RECONCILIATION_REQUEST_VERSION + 1;
        assert!(reconciliation_output(&request(), &invalid).is_err());

        let mut invalid = result(false);
        invalid.legacy_conflict_id = 42;
        assert!(reconciliation_output(&request(), &invalid).is_err());

        let mut invalid = result(false);
        invalid.legacy_conflict_revision = 0;
        assert!(reconciliation_output(&request(), &invalid).is_err());

        let mut invalid = result(false);
        invalid.conflict_id = 0;
        assert!(reconciliation_output(&request(), &invalid).is_err());

        let mut invalid = result(false);
        invalid.candidate_count = MAX_RECONCILIATION_CLAIMS + 1;
        assert!(reconciliation_output(&request(), &invalid).is_err());

        let mut invalid = result(false);
        invalid.legacy_conflict_revision = 8;
        assert!(reconciliation_output(&request(), &invalid).is_err());

        let mut invalid = result(false);
        invalid.v2_state = "future-state".into();
        assert!(reconciliation_output(&request(), &invalid).is_err());

        let mut invalid = result(false);
        invalid.conflict_id = invalid.legacy_conflict_id;
        assert!(reconciliation_output(&request(), &invalid).is_err());

        let mut invalid = result(false);
        invalid.reconciliation_event_id = Uuid::nil();
        assert!(reconciliation_output(&request(), &invalid).is_err());

        let mut invalid = result(false);
        invalid.reconciliation_event_id =
            Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        assert!(reconciliation_output(&request(), &invalid).is_err());

        let mut invalid = result(false);
        invalid.reconciliation_event_id =
            Uuid::parse_str("0198a849-f6ae-7d61-f800-000000000073").unwrap();
        assert_eq!(invalid.reconciliation_event_id.get_version_num(), 7);
        assert_ne!(
            invalid.reconciliation_event_id.get_variant(),
            uuid::Variant::RFC4122
        );
        assert!(reconciliation_output(&request(), &invalid).is_err());

        for vector_index in 0..5 {
            let oversized =
                (1..=i64::try_from(MAX_RECONCILIATION_CLAIMS + 1).unwrap()).collect::<Vec<_>>();
            let mut invalid = open_result();
            replace_id_vector(&mut invalid, vector_index, oversized);
            assert!(
                reconciliation_output(&request(), &invalid).is_err(),
                "accepted oversized ID vector {vector_index}"
            );
        }
    }

    #[test]
    fn every_output_id_vector_must_be_strictly_increasing_unique_and_positive() {
        assert!(ids_are_strictly_increasing_positive(&[]));
        assert!(ids_are_strictly_increasing_positive(&[1, 2, 3]));
        for invalid_ids in [vec![0], vec![-1], vec![11, 11], vec![12, 11]] {
            assert!(!ids_are_strictly_increasing_positive(&invalid_ids));
            for vector_index in 0..5 {
                let mut invalid = open_result();
                replace_id_vector(&mut invalid, vector_index, invalid_ids.clone());
                assert!(
                    reconciliation_output(&request(), &invalid).is_err(),
                    "accepted invalid ID vector {vector_index}: {invalid_ids:?}"
                );
            }
        }
    }

    #[test]
    fn output_rejects_impossible_transition_set_relationships() {
        let mut invalid = open_result();
        invalid.provenance_ambiguous_claim_ids = vec![15];
        assert!(reconciliation_output(&request(), &invalid).is_err());

        let mut invalid = open_result();
        invalid.restored_claim_ids = vec![11];
        assert!(reconciliation_output(&request(), &invalid).is_err());

        let mut invalid = open_result();
        invalid.retained_disputed_claim_ids = vec![11, 14];
        invalid.provenance_ambiguous_claim_ids = vec![14];
        assert!(reconciliation_output(&request(), &invalid).is_err());

        let mut invalid = open_result();
        invalid.retained_disputed_claim_ids = vec![13, 14];
        invalid.provenance_ambiguous_claim_ids = vec![14];
        assert!(reconciliation_output(&request(), &invalid).is_err());

        let mut invalid = open_result();
        invalid.candidate_count = 5;
        invalid.newly_disputed_claim_ids = vec![15];
        invalid.retained_disputed_claim_ids = vec![11, 12, 14];
        assert!(reconciliation_output(&request(), &invalid).is_err());

        let mut invalid = open_result();
        invalid.restored_claim_ids = vec![12];
        invalid.retained_disputed_claim_ids = vec![14];
        invalid.provenance_ambiguous_claim_ids = vec![14];
        assert!(reconciliation_output(&request(), &invalid).is_err());

        let mut invalid = open_result();
        invalid.retained_disputed_claim_ids = vec![14];
        invalid.provenance_ambiguous_claim_ids = vec![14];
        assert!(reconciliation_output(&request(), &invalid).is_err());

        let mut invalid = open_result();
        invalid.candidate_count = 3;
        assert!(reconciliation_output(&request(), &invalid).is_err());
    }

    #[test]
    fn output_rejects_impossible_pair_member_and_state_shapes() {
        let mut invalid = open_result();
        invalid.incompatibility_pair_count = 7;
        assert!(reconciliation_output(&request(), &invalid).is_err());

        let mut invalid = open_result();
        invalid.incompatibility_pair_count = 2;
        assert!(reconciliation_output(&request(), &invalid).is_err());

        let mut invalid = open_result();
        invalid.incompatibility_pair_count = 0;
        assert!(reconciliation_output(&request(), &invalid).is_err());

        let mut invalid = open_result();
        invalid.v2_member_ids = vec![11];
        invalid.retained_disputed_claim_ids = vec![14];
        invalid.provenance_ambiguous_claim_ids = vec![14];
        assert!(reconciliation_output(&request(), &invalid).is_err());

        let mut invalid = open_result();
        invalid.v2_member_ids = vec![11, 12, 14];
        assert!(reconciliation_output(&request(), &invalid).is_err());

        let mut invalid = result(false);
        invalid.incompatibility_pair_count = 1;
        assert!(reconciliation_output(&request(), &invalid).is_err());

        let mut invalid = result(false);
        invalid.v2_member_ids = vec![12];
        invalid.newly_disputed_claim_ids = vec![12];
        assert!(reconciliation_output(&request(), &invalid).is_err());
    }

    fn replace_id_vector(
        result: &mut ConflictDetectorReconciliation,
        vector_index: usize,
        replacement: Vec<i64>,
    ) {
        match vector_index {
            0 => result.v2_member_ids = replacement,
            1 => result.newly_disputed_claim_ids = replacement,
            2 => result.restored_claim_ids = replacement,
            3 => result.retained_disputed_claim_ids = replacement,
            4 => result.provenance_ambiguous_claim_ids = replacement,
            _ => panic!("invalid vector index"),
        }
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
