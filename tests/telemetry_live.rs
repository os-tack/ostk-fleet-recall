//! Live proof that real `CockroachDB` serialization failures reach the exported
//! retry counters and yield exactly one terminal logical-operation outcome.
//!
//! Set `FLEET_RECALL_TEST_DATABASE_URL` to a disposable `CockroachDB` 26.2
//! database, using a test login allowed to enable `allow_unsafe_internals`.
//! Without it this test is inert. No migrations, tables, or durable writes are
//! needed. Keep this a single test: its before/after metric snapshots use the
//! process registry, which is private to this integration-test binary.

mod common;

use std::collections::BTreeMap;
use std::time::Duration;

use ostk_fleet_recall::Result;
use ostk_fleet_recall::store::cockroach::{
    RetryPolicy, is_retryable_fleet_error, with_serializable_retry,
};
use ostk_fleet_recall::telemetry;
use sqlx::postgres::PgPoolOptions;
use sqlx::{Postgres, Transaction};

const TRANSACTION_DEADLINE: Duration = Duration::from_secs(15);

/// Consume a result first, so the server cannot transparently replay the
/// transaction. The forced 40001 must cross the wire to the Rust retry loop.
async fn force_body_retry(transaction: &mut Transaction<'_, Postgres>) -> Result<()> {
    let value: i64 = sqlx::query_scalar("SELECT 1::INT8")
        .fetch_one(&mut **transaction)
        .await?;
    assert_eq!(value, 1);
    sqlx::query("SET LOCAL allow_unsafe_internals = true")
        .execute(&mut **transaction)
        .await?;
    sqlx::query("SELECT crdb_internal.force_retry('1h':::INTERVAL)")
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

/// Read a fixed-label numeric sample without depending on label order in the
/// Prometheus text encoder. A counter not yet instantiated has value zero.
fn sample(text: &str, metric: &str, extra_label: Option<(&str, &str)>) -> u64 {
    let prefix = format!("{metric}{{");
    let extra = extra_label.map(|(name, value)| format!("{name}=\"{value}\""));
    text.lines()
        .find(|line| {
            line.starts_with(&prefix)
                && line.contains("component=\"database\"")
                && line.contains("operation=\"serializable_transaction\"")
                && extra.as_ref().is_none_or(|label| line.contains(label))
        })
        .map_or(0, |line| {
            line.rsplit_once(' ')
                .expect("Prometheus samples contain a numeric value")
                .1
                .parse()
                .expect("these samples are integer counters or gauges")
        })
}

fn transaction_counters() -> BTreeMap<&'static str, u64> {
    let text = telemetry::render().expect("the telemetry registry must encode");
    let mut counters = BTreeMap::new();
    for unit in [
        "attempts",
        "retries_body",
        "retries_commit",
        "retries_exhausted",
    ] {
        counters.insert(
            unit,
            sample(&text, "fleet_recall_units_total", Some(("unit", unit))),
        );
    }
    for outcome in ["success", "error", "cancelled"] {
        counters.insert(
            outcome,
            sample(
                &text,
                "fleet_recall_operations_total",
                Some(("outcome", outcome)),
            ),
        );
    }
    counters.insert(
        "duration_count",
        sample(&text, "fleet_recall_operation_duration_seconds_count", None),
    );
    assert_eq!(
        sample(&text, "fleet_recall_operations_in_flight", None),
        0,
        "every finished logical transaction must release its in-flight gauge"
    );
    counters
}

fn delta(before: &BTreeMap<&'static str, u64>) -> BTreeMap<&'static str, u64> {
    transaction_counters()
        .into_iter()
        .map(|(name, value)| (name, value - before[name]))
        .collect()
}

#[tokio::test]
async fn real_body_retries_export_success_and_exhaustion_once_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&database_url)
        .await
        .expect("the live telemetry test must reach its disposable database");
    let policy = RetryPolicy {
        max_attempts: 3,
        initial_backoff: Duration::ZERO,
        max_backoff: Duration::ZERO,
    };

    let before_success = transaction_counters();
    let mut success_executions = 0;
    let value = tokio::time::timeout(
        TRANSACTION_DEADLINE,
        with_serializable_retry(&pool, policy, |transaction| {
            success_executions += 1;
            let must_retry = success_executions == 1;
            Box::pin(async move {
                if must_retry {
                    force_body_retry(transaction).await?;
                }
                let value: i64 = sqlx::query_scalar("SELECT 1::INT8")
                    .fetch_one(&mut **transaction)
                    .await?;
                Ok(value)
            })
        }),
    )
    .await
    .expect("a forced retry must return to the client promptly")
    .expect("the fresh second transaction must commit");
    assert_eq!(value, 1);
    assert_eq!(success_executions, 2);
    assert_eq!(
        delta(&before_success),
        BTreeMap::from([
            ("attempts", 2),
            ("retries_body", 1),
            ("retries_commit", 0),
            ("retries_exhausted", 0),
            ("success", 1),
            ("error", 0),
            ("cancelled", 0),
            ("duration_count", 1),
        ])
    );

    let before_exhaustion = transaction_counters();
    let mut exhausted_executions = 0;
    let error = tokio::time::timeout(
        TRANSACTION_DEADLINE,
        with_serializable_retry(&pool, policy, |transaction| {
            exhausted_executions += 1;
            Box::pin(force_body_retry(transaction))
        }),
    )
    .await
    .expect("exhaustion must not wait for the force_retry interval to elapse")
    .expect_err("forcing a 40001 on every attempt must exhaust the retry policy");
    assert!(is_retryable_fleet_error(&error));
    assert_eq!(exhausted_executions, policy.max_attempts);
    assert_eq!(
        delta(&before_exhaustion),
        BTreeMap::from([
            ("attempts", 3),
            ("retries_body", 2),
            ("retries_commit", 0),
            ("retries_exhausted", 1),
            ("success", 0),
            ("error", 1),
            ("cancelled", 0),
            ("duration_count", 1),
        ])
    );
    pool.close().await;
}
