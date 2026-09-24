//! `ostk-fleet-recall worker --once`: one memory-worker tick as a process.
//!
//! [`run_command`] is the whole command once the process configuration is
//! loaded. The binary only loads [`FleetConfig`](crate::FleetConfig) (the
//! command runs as the private writer login), supplies the process-bound
//! pieces in [`WorkerProcessV1`] and a writer connection, and turns the
//! returned report into its exit status ([`WorkerTickReportV1::exit_code`]).
//! Tests drive the same function with an injected environment and pool.
//!
//! # What one run does
//!
//! 1. Refuses a run without `--once`: there is no long-running loop, so a
//!    deployment schedules the command (cron, a systemd timer, or a scheduled
//!    task) instead of supervising a daemon.
//! 2. Parses `--steps` ([`parse_steps`]) and the sources file
//!    ([`WorkerSourcesV1::load`]).
//! 3. Reads what the selected steps need, and nothing else: the
//!    writer-authority pins for the ingest and bodies steps, the content key
//!    (`FLEET_RECALL_CONTENT_KEK_HEX`, one parse per holder) for the ingest
//!    steps and for bodies, and the pinned model bundle, as
//!    [`ChunkEmbedderProvider`] under `FLEET_RECALL_EMBEDDING_MODEL_SHA256`,
//!    for dense. A selected step whose input is absent is refused here, with
//!    the message [`MemoryWorker::new`] would give.
//! 4. Connects, then checks every privilege the selected steps use
//!    ([`probe_worker_privileges`]).
//! 5. Starts the writer authority under the pins, which refuses a head the
//!    pins do not verify, and builds the [`MemoryWorker`].
//! 6. Runs one tick and writes its report as one JSON line.
//!
//! Every configuration problem in 1–3 stops the run before it connects. A
//! problem in 4–5 stops it before anything is appended. Neither prints a
//! report. Once the tick runs, every failure is in the report instead, and the
//! exit status is 1 when any step failed.
//!
//! # Where to run which steps
//!
//! The git step shells out to `git` and the CI step to `gh`, and the
//! production image carries neither, so the ingest steps run on a host that
//! has both (and the sources' git directories and transcript files).
//! `--steps project,embed` needs neither and is safe in the container. Every
//! step that ingests or projects bodies needs the writer-authority pins and
//! the content key, so the host that runs them holds the writer login and the
//! key. Run one worker per `(tenant, project)` at a time.

use std::future::Future;
use std::io::Write;
use std::path::PathBuf;
use std::str::FromStr as _;
use std::sync::Arc;

use ostk_recall_core::ChunkEmbedder;
use sqlx::PgPool;

use crate::config::WriterAuthorityConfig;
use crate::context::FleetScope;
use crate::error::{FleetError, Result};
use crate::evidence_ledger::content_kek_from_lookup;
use crate::memory_contracts::digest::Sha256Digest;
use crate::projectors::{ChunkEmbedderProvider, EmbeddingProvider};
use crate::registry_witness::WriterAuthorityRuntime;
use crate::store::cockroach::{DatabaseCapabilities, RetryPolicy};

use super::{
    CiProviderFactory, MemoryWorker, WorkerDeps, WorkerInput, WorkerSourcesV1, WorkerStepV1,
    WorkerTickReportV1, parse_steps, probe_worker_privileges, require_inputs,
};

/// The variable the dense tier's model digest comes from.
const EMBEDDING_MODEL_SHA256_ENV: &str = "FLEET_RECALL_EMBEDDING_MODEL_SHA256";

/// The arguments of `ostk-fleet-recall worker`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerCommandV1 {
    /// The sources file ([`WorkerSourcesV1`]).
    pub sources: PathBuf,
    /// Run exactly one tick. Required: see the module documentation.
    pub once: bool,
    /// The `--steps` value ([`parse_steps`]).
    pub steps: String,
}

/// What the process gives the command besides its arguments.
pub struct WorkerProcessV1<'a> {
    /// The physical `(tenant_id, project)` every step reads and writes
    /// (`FLEET_RECALL_TENANT_ID`, `FLEET_RECALL_PROJECT`, `FLEET_RECALL_AGENT`).
    pub scope: FleetScope,
    /// `FLEET_RECALL_EMBEDDING_MODEL_SHA256`: the model digest every dense row
    /// records. Read only when the dense step is selected.
    pub embedding_model_sha256: &'a str,
    /// Loads and verifies the pinned model bundle. Called only when the dense
    /// step is selected.
    pub load_embedder: &'a (dyn Fn() -> Result<Arc<dyn ChunkEmbedder>> + Sync),
    /// Reads one deployment variable: the writer-authority pins and the
    /// content key. The process environment in production.
    pub lookup: &'a (dyn Fn(&str) -> Option<String> + Sync),
    /// Where the CI step gets a provider: `gh` in production.
    pub ci_providers: Arc<dyn CiProviderFactory>,
    /// Retry policy for every serializable write (retried only on 40001).
    pub retry: RetryPolicy,
}

impl std::fmt::Debug for WorkerProcessV1<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WorkerProcessV1")
            .field("scope", &self.scope)
            .field("embedding_model_sha256", &self.embedding_model_sha256)
            .field("retry", &self.retry)
            .finish_non_exhaustive()
    }
}

/// A worker without `--once` would suggest a supervised loop that does not
/// exist.
const ONCE_REQUIRED: &str = "the worker runs exactly one tick per invocation and has no \
     long-running loop: pass --once, and schedule the command (cron, a systemd timer, or a \
     scheduled task)";

/// Run `ostk-fleet-recall worker`: one tick, reported as one JSON line on
/// `out`. See the module documentation for the order of work.
///
/// `connect` is called once, after every configuration input has been read,
/// and returns a pool authenticated as the private writer login with that
/// pool's schema snapshot.
///
/// Returns the tick's report, which `out` also received; a tick with a failed
/// step is still `Ok` ([`WorkerTickReportV1::exit_code`] is then 1).
///
/// # Errors
///
/// [`FleetError::Configuration`] for a run without `--once`, an unknown step
/// group, an unreadable or invalid sources file, a partial or malformed pin
/// group or content key, an unusable model bundle or digest, a login missing a
/// privilege, or a selected step missing its input; whatever `connect`
/// returns; the writer authority's refusal of the active head; and a failure
/// to write the report.
pub async fn run_command<Connect, Connecting>(
    command: &WorkerCommandV1,
    process: WorkerProcessV1<'_>,
    connect: Connect,
    out: &mut (impl Write + Send),
) -> Result<WorkerTickReportV1>
where
    Connect: FnOnce() -> Connecting + Send,
    Connecting: Future<Output = Result<(PgPool, DatabaseCapabilities)>> + Send,
{
    if !command.once {
        return Err(FleetError::Configuration(ONCE_REQUIRED.to_owned()));
    }
    let steps = parse_steps(&command.steps)?;
    let sources = WorkerSourcesV1::load(&command.sources)?;
    let ingest = steps.iter().any(|step| step.is_ingest());
    let bodies = steps.contains(&WorkerStepV1::Bodies);
    let pins = if ingest || bodies {
        WriterAuthorityConfig::from_lookup(process.lookup)?
    } else {
        None
    };
    // The key is not `Clone`: the drains and the body resolver each own one.
    let drain_kek = if ingest {
        content_kek_from_lookup(process.lookup)?
    } else {
        None
    };
    let body_kek = if bodies {
        content_kek_from_lookup(process.lookup)?
    } else {
        None
    };
    let embedding = if steps.contains(&WorkerStepV1::Dense) {
        Some(dense_provider(&process)?)
    } else {
        None
    };
    // The same check `MemoryWorker::new` makes, before any connection.
    require_inputs(&steps, |input| match input {
        WorkerInput::Authority => pins.is_some(),
        WorkerInput::DrainKey => drain_kek.is_some(),
        WorkerInput::BodyKey => body_kek.is_some(),
        WorkerInput::Embedding => embedding.is_some(),
    })?;

    let (pool, capabilities) = connect().await?;
    probe_worker_privileges(&pool, &capabilities, &steps).await?;
    let authority = match pins {
        Some(config) => {
            let (runtime, startup) = WriterAuthorityRuntime::start(
                pool.clone(),
                process.scope.clone(),
                config,
                process.retry,
            )
            .await?;
            tracing::info!(
                generation = startup.generation,
                package = ?startup.package,
                "the memory worker verified the writer authority"
            );
            Some(runtime)
        }
        None => None,
    };
    let worker = MemoryWorker::new(
        WorkerDeps {
            pool,
            scope: process.scope,
            authority,
            sources,
            embedding,
            ci_providers: process.ci_providers,
            retry: process.retry,
        },
        steps,
        drain_kek,
        body_kek,
    )?;

    let report = worker.run_tick().await;
    let line = serde_json::to_string(&report).map_err(|error| {
        FleetError::Protocol(format!("the worker report does not serialize: {error}"))
    })?;
    writeln!(out, "{line}")
        .and_then(|()| out.flush())
        .map_err(|error| {
            FleetError::Protocol(format!("the worker report could not be written: {error}"))
        })?;
    Ok(report)
}

/// The dense tier's provider: the pinned model under its configured digest.
fn dense_provider(process: &WorkerProcessV1<'_>) -> Result<Arc<dyn EmbeddingProvider>> {
    let digest = Sha256Digest::from_str(process.embedding_model_sha256).map_err(|error| {
        FleetError::Configuration(format!(
            "{EMBEDDING_MODEL_SHA256_ENV} must be a lowercase 64-character hex digest: {error}"
        ))
    })?;
    let embedder = (process.load_embedder)()?;
    let provider = ChunkEmbedderProvider::new(embedder, digest).map_err(|error| {
        FleetError::Configuration(format!(
            "the dense step cannot embed with the pinned model: {error}"
        ))
    })?;
    Ok(Arc::new(provider))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, Ordering};

    use uuid::Uuid;

    use super::*;
    use crate::connectors::ci::{CiRunProvider, CiScanResult};
    use crate::worker::CiSourceV1;

    struct NoProviders;

    impl CiProviderFactory for NoProviders {
        fn provider(
            &self,
            _source: &CiSourceV1,
        ) -> CiScanResult<Option<(Box<dyn CiRunProvider>, u64)>> {
            Ok(None)
        }
    }

    /// What a unit run needs: an empty but valid sources file and a variable
    /// map standing in for the process environment.
    struct Harness {
        directory: tempfile::TempDir,
        variables: HashMap<&'static str, String>,
    }

    /// The sentinel a unit test's `connect` returns, so reaching the database
    /// is observable without one.
    const CONNECTED: &str = "connect was called";

    impl Harness {
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            std::fs::write(
                directory.path().join("sources.json"),
                br#"{"schema_version": 1}"#,
            )
            .unwrap();
            Self {
                directory,
                variables: HashMap::from([
                    (
                        "FLEET_RECALL_CONTRACT_TENANT_NAMESPACE",
                        "tenant.acme".into(),
                    ),
                    (
                        "FLEET_RECALL_CONTRACT_PROJECT_NAMESPACE",
                        "project.recall".into(),
                    ),
                    ("FLEET_RECALL_BOOTSTRAP_RECEIPT_DIGEST", "ab".repeat(32)),
                    ("FLEET_RECALL_CONTENT_KEK_HEX", "cd".repeat(32)),
                ]),
            }
        }

        fn command(&self, steps: &str) -> WorkerCommandV1 {
            WorkerCommandV1 {
                sources: self.directory.path().join("sources.json"),
                once: true,
                steps: steps.to_owned(),
            }
        }

        /// Run `command` with a `connect` that records the call and stops the
        /// run with [`CONNECTED`], and an embedder loader that records its
        /// call and refuses. Returns the error and whether each was called.
        async fn run(&self, command: &WorkerCommandV1) -> (String, bool, bool) {
            let (connected, loaded) = (AtomicBool::new(false), AtomicBool::new(false));
            let connected_flag = &connected;
            let lookup = |name: &str| self.variables.get(name).cloned();
            let load_embedder = || -> Result<Arc<dyn ChunkEmbedder>> {
                loaded.store(true, Ordering::SeqCst);
                Err(FleetError::Configuration("no model bundle here".into()))
            };
            let mut out = Vec::new();
            let outcome = run_command(
                command,
                WorkerProcessV1 {
                    scope: FleetScope::new(
                        Uuid::now_v7(),
                        "worker-command",
                        "memory-worker",
                        None,
                        ostk_recall_core::PrivacyTier::T1Project,
                    )
                    .unwrap(),
                    embedding_model_sha256: &"5a".repeat(32),
                    load_embedder: &load_embedder,
                    lookup: &lookup,
                    ci_providers: Arc::new(NoProviders),
                    retry: RetryPolicy::default(),
                },
                move || async move {
                    connected_flag.store(true, Ordering::SeqCst);
                    Err(FleetError::Configuration(CONNECTED.into()))
                },
                &mut out,
            )
            .await;
            assert!(out.is_empty(), "a run that never ticked prints no report");
            let message = match outcome {
                Err(FleetError::Configuration(message)) => message,
                other => panic!("expected a configuration error, got {other:?}"),
            };
            (
                message,
                connected.load(Ordering::SeqCst),
                loaded.load(Ordering::SeqCst),
            )
        }
    }

    #[tokio::test]
    async fn a_run_without_once_is_refused_before_connecting() {
        let harness = Harness::new();
        let command = WorkerCommandV1 {
            once: false,
            ..harness.command("all")
        };
        let (message, connected, _) = harness.run(&command).await;
        assert!(
            message.contains("--once") && message.contains("cron"),
            "{message}"
        );
        assert!(!connected);
    }

    #[tokio::test]
    async fn configuration_problems_stop_the_run_before_it_connects() {
        let harness = Harness::new();
        let (message, connected, _) = harness.run(&harness.command("ingest,git")).await;
        assert!(message.contains("unknown worker step group"), "{message}");
        assert!(!connected);

        let missing = WorkerCommandV1 {
            sources: harness.directory.path().join("absent.json"),
            ..harness.command("all")
        };
        let (message, connected, _) = harness.run(&missing).await;
        assert!(message.contains("absent.json"), "{message}");
        assert!(!connected);

        let mut partial = Harness::new();
        partial
            .variables
            .remove("FLEET_RECALL_BOOTSTRAP_RECEIPT_DIGEST");
        let (message, connected, _) = partial.run(&partial.command("ingest")).await;
        assert!(
            message.contains("missing FLEET_RECALL_BOOTSTRAP_RECEIPT_DIGEST"),
            "{message}"
        );
        assert!(!connected);

        let mut absent = Harness::new();
        absent.variables.clear();
        let (message, connected, _) = absent.run(&absent.command("ingest")).await;
        assert!(message.contains("writer-authority pins"), "{message}");
        assert!(!connected);
        let mut keyless = Harness::new();
        keyless.variables.remove("FLEET_RECALL_CONTENT_KEK_HEX");
        let (message, connected, _) = keyless.run(&keyless.command("project")).await;
        assert!(
            message.contains("FLEET_RECALL_CONTENT_KEK_HEX"),
            "{message}"
        );
        assert!(!connected);

        let mut bad_key = Harness::new();
        bad_key
            .variables
            .insert("FLEET_RECALL_CONTENT_KEK_HEX", "not-hex".into());
        let (_, connected, _) = bad_key.run(&bad_key.command("project")).await;
        assert!(!connected, "a mis-set key never reads as absent");
    }

    #[tokio::test]
    async fn only_the_dense_step_loads_the_model() {
        let harness = Harness::new();
        let (message, connected, loaded) = harness.run(&harness.command("ingest,project")).await;
        assert_eq!(message, CONNECTED);
        assert!(connected && !loaded);

        let (message, connected, loaded) = harness.run(&harness.command("embed")).await;
        assert!(message.contains("no model bundle here"), "{message}");
        assert!(loaded && !connected);
    }

    #[tokio::test]
    async fn the_example_sources_file_reaches_the_connection() {
        let harness = Harness::new();
        let command = WorkerCommandV1 {
            sources: Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/worker-sources.json"),
            ..harness.command("ingest,project")
        };
        let (message, connected, _) = harness.run(&command).await;
        assert_eq!(message, CONNECTED, "the documented file configures a run");
        assert!(connected);
    }

    #[tokio::test]
    async fn steps_that_neither_ingest_nor_project_bodies_ignore_the_pins() {
        let mut harness = Harness::new();
        harness
            .variables
            .remove("FLEET_RECALL_CONTRACT_TENANT_NAMESPACE");
        harness.variables.remove("FLEET_RECALL_CONTENT_KEK_HEX");
        // A partial pin group and no key: fatal for ingest, irrelevant here.
        let (message, connected, _) = harness.run(&harness.command("embed")).await;
        assert!(message.contains("no model bundle here"), "{message}");
        assert!(!connected);
    }
}
