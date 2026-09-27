//! Exercise the real command lifecycle, stderr protocol boundary, and batch
//! export without a model, database, or network listener.

use std::process::Command;

use serde_json::Value;

fn command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ostk-fleet-recall"));
    command.env_clear();
    command
}

fn completions(stderr: &[u8]) -> Vec<Value> {
    std::str::from_utf8(stderr)
        .unwrap()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|event| event["fields"]["event"] == "operation.completed")
        .collect()
}

#[test]
fn successful_command_keeps_stdout_clean_and_publishes_terminal_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    for file in ["config.json", "model.safetensors", "tokenizer.json"] {
        std::fs::write(dir.path().join(file), "digest-only-fixture").unwrap();
    }
    let expected = ostk_fleet_recall::config::model_bundle_sha256(dir.path()).unwrap();
    let snapshot = dir.path().join("job.prom");
    let result = command()
        .env("FLEET_RECALL_METRICS_TEXTFILE", &snapshot)
        .arg("model-digest")
        .arg(dir.path())
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        String::from_utf8(result.stdout).unwrap(),
        format!("{expected}\n")
    );
    let events = completions(&result.stderr);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["fields"]["operation"], "model_digest");
    assert_eq!(events[0]["fields"]["outcome"], "success");
    assert!(events[0]["span"]["operation_id"].is_string());
    let metrics = std::fs::read_to_string(snapshot).unwrap();
    assert!(metrics.contains("fleet_recall_operations_total{component=\"process\",operation=\"model_digest\",outcome=\"success\"} 1"));
    assert!(metrics.contains(
        "fleet_recall_operations_in_flight{component=\"process\",operation=\"model_digest\"} 0"
    ));
    assert!(metrics.contains("fleet_recall_snapshot_time_seconds"));
    assert!(!metrics.contains("digest-only-fixture"));
}

#[test]
fn failed_worker_startup_also_publishes_a_failed_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let snapshot = dir.path().join("worker.prom");
    let result = command()
        .env("FLEET_RECALL_METRICS_TEXTFILE", &snapshot)
        .args(["worker", "--once", "--sources", "private-sources-path"])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    let events = completions(&result.stderr);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["fields"]["operation"], "worker");
    assert_eq!(events[0]["fields"]["outcome"], "error");
    assert!(!events[0].to_string().contains("private-sources-path"));
    let metrics = std::fs::read_to_string(snapshot).unwrap();
    assert!(metrics.contains("fleet_recall_operations_total{component=\"process\",operation=\"worker\",outcome=\"error\"} 1"));
}

#[test]
fn invalid_exporter_setup_is_a_structured_process_failure() {
    let result = command()
        .env("FLEET_RECALL_METRICS_LISTEN", "0.0.0.0:9091")
        .args(["model-digest", "private-bundle-path"])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    let events = completions(&result.stderr);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["fields"]["outcome"], "error");
    assert!(!events[0].to_string().contains("private-bundle-path"));
}
