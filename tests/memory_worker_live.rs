//! Connected proof for the memory worker (`ostk_fleet_recall::worker`).
//!
//! Set `FLEET_RECALL_TEST_DATABASE_URL` to a disposable `CockroachDB` 26.2
//! database; every test here is inert otherwise. Each test installs a real
//! generation-2 writer authority into a fresh physical tenant through the
//! shared `tests/common` fixture, and feeds the worker a scratch git
//! repository, a scratch transcript directory, and the recorded CI corpus.
//!
//! What it proves is the behavior a scheduled runner depends on: one tick
//! takes all three connectors through admission and every projection tier,
//! so recall finds each source; a second tick is a replay that appends,
//! projects, and opens nothing; one broken source fails alone, with its error
//! in the report and in its status row; and the whole tick, including the
//! governed-content dedup path, runs under nothing but the runtime role's
//! grants, while a login without the Stage-5 grants is refused by the
//! preflight before anything runs. The `worker --once` command
//! (`worker::run_command`, the code path `ostk-fleet-recall worker` runs) reads
//! its pins and key from its environment, prints each tick's report as one
//! JSON line, and earns exit status 1 exactly when a step failed.

mod common;

use std::collections::{BTreeSet, HashMap};
use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;

use common::authority::{InstalledAuthority, install_generation_two, retry_policy};
use common::runtime_role::RuntimeProbeRole;
use ostk_fleet_recall::FleetError;
use ostk_fleet_recall::connectors::ci::scan::{
    RECORDED_BRANCH, RECORDED_REPOSITORY, RECORDED_WORKFLOW, recorded_provider,
};
use ostk_fleet_recall::connectors::ci::{CiRunProvider, CiScanResult};
use ostk_fleet_recall::control_log::TrustedControlScope;
use ostk_fleet_recall::coverage_runtime::CockroachCoverageRuntimeRepository;
use ostk_fleet_recall::memory_contracts::canonical::decode_strict;
use ostk_fleet_recall::memory_contracts::common::ContractId;
use ostk_fleet_recall::memory_contracts::coverage::CoverageCompletenessV1;
use ostk_fleet_recall::memory_contracts::digest::Sha256Digest;
use ostk_fleet_recall::memory_contracts::evidence_v2::EvidenceStatementV2;
use ostk_fleet_recall::projectors::{ChunkEmbedderProvider, CockroachRecallReader};
use ostk_fleet_recall::store::cockroach::{
    CockroachStore, DatabaseCapabilities, PoolConfig, RetryPolicy,
};
use ostk_fleet_recall::worker::{
    CiProviderFactory, CiSourceV1, MemoryWorker, WorkerCommandV1, WorkerDeps, WorkerProcessV1,
    WorkerSourceOutcomeV1, WorkerSourcesV1, WorkerStepStatusV1, WorkerStepV1, WorkerTickReportV1,
    parse_steps, probe_worker_privileges, run_command,
};
use ostk_recall_core::ChunkEmbedder;
use sha2::{Digest as _, Sha256};
use sqlx::PgPool;

/// The provider-installation coordinate every source is configured with.
const INSTALLATION_ID: u64 = 4242;

const GIT_INSTANCE: &str = "connector.git.worker";
const CI_INSTANCE: &str = "connector.ci.worker";
const TRANSCRIPT_PREFIX: &str = "connector.transcript";

/// A word that occurs only in the scratch repository's second commit.
const COMMIT_WORD: &str = "zephyrine";
/// A word that occurs only in the scratch transcript's first turn.
const TRANSCRIPT_WORD: &str = "quillback";
/// The step that failed in the recorded CI corpus.
const FAILING_STEP_WORD: &str = "Mermaid";

/// Fixed past commit instants, so every scan of the scratch repository
/// renders byte-identical commit facts.
const FIRST_COMMIT_DATE: &str = "1755259200 +0000";
const SECOND_COMMIT_DATE: &str = "1755345600 +0000";

// ---------------------------------------------------------------------------
// Scratch sources.
// ---------------------------------------------------------------------------

/// A bare scratch repository whose `refs/heads/main` has two commits.
struct ScratchRepository {
    directory: tempfile::TempDir,
}

impl ScratchRepository {
    fn with_two_commits() -> Self {
        let directory = tempfile::tempdir().expect("scratch repository directory");
        let status = Command::new("git")
            .args(["init", "--bare", "--quiet"])
            .arg(directory.path())
            .status()
            .expect("git must be on PATH for the memory worker proof");
        assert!(status.success(), "git init --bare must succeed");
        let repository = Self { directory };
        let readme = repository.git(&["hash-object", "-w", "--stdin"], Some(b"worker\n"), None);
        let tree = repository.git(
            &["mktree"],
            Some(format!("100644 blob {readme}\tREADME.md\n").as_bytes()),
            None,
        );
        let first = repository.git(
            &["commit-tree", &tree, "-m", "seed the worker fixture"],
            None,
            Some(FIRST_COMMIT_DATE),
        );
        let second = repository.git(
            &[
                "commit-tree",
                &tree,
                "-p",
                &first,
                "-m",
                &format!("document the {COMMIT_WORD} cache eviction"),
            ],
            None,
            Some(SECOND_COMMIT_DATE),
        );
        repository.git(&["update-ref", "refs/heads/main", &second], None, None);
        repository
    }

    fn path(&self) -> &Path {
        self.directory.path()
    }

    fn git(&self, args: &[&str], stdin: Option<&[u8]>, date: Option<&str>) -> String {
        let date = date.unwrap_or(FIRST_COMMIT_DATE);
        let mut child = Command::new("git")
            .arg(format!("--git-dir={}", self.directory.path().display()))
            .args(args)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_AUTHOR_NAME", "Worker Fixture")
            .env("GIT_AUTHOR_EMAIL", "worker@example.invalid")
            .env("GIT_AUTHOR_DATE", date)
            .env("GIT_COMMITTER_NAME", "Worker Fixture")
            .env("GIT_COMMITTER_EMAIL", "worker@example.invalid")
            .env("GIT_COMMITTER_DATE", date)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("git must spawn");
        if let Some(bytes) = stdin {
            child
                .stdin
                .as_mut()
                .expect("piped stdin")
                .write_all(bytes)
                .expect("git stdin");
        }
        let output = child.wait_with_output().expect("git must finish");
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .expect("plumbing output is ASCII")
            .trim()
            .to_owned()
    }
}

const SESSION: &str = "0f3a8c5e-worker-session";

fn line(kind: &str, uid: &str, timestamp: &str, text: &str) -> String {
    format!(
        r#"{{"type":"{kind}","sessionId":"{SESSION}","uuid":"{uid}","timestamp":"{timestamp}","message":{{"role":"{kind}","content":[{{"type":"text","text":{}}}]}}}}"#,
        serde_json::to_string(text).unwrap()
    )
}

fn first_turn_text() -> String {
    format!("why does the {TRANSCRIPT_WORD} importer drop rows")
}

/// A scratch transcript directory.
///
/// `session.jsonl` holds two turns. `session-resumed.jsonl` repeats the first
/// turn exactly as a resumed session file does, but with its own timestamp:
/// the line differs, so the turn is a second source fact, while its redacted
/// body is byte-identical, so its append deduplicates onto the governed
/// content object the first file already wrote.
fn transcript_directory() -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("transcript directory");
    let first = line(
        "user",
        "turn-1",
        "2026-08-15T12:30:00.000Z",
        &first_turn_text(),
    );
    std::fs::write(
        directory.path().join("session.jsonl"),
        format!(
            "{first}\n{}\n",
            line(
                "assistant",
                "turn-2",
                "2026-08-15T12:30:01.000Z",
                "the importer skips rows whose checksum collides"
            )
        ),
    )
    .unwrap();
    std::fs::write(
        directory.path().join("session-resumed.jsonl"),
        format!(
            "{}\n",
            line(
                "user",
                "turn-1",
                "2026-08-16T09:00:00.000Z",
                &first_turn_text()
            )
        ),
    )
    .unwrap();
    directory
}

/// The recorded CI corpus, settled through run 8.
struct RecordedCi;

impl CiProviderFactory for RecordedCi {
    fn provider(
        &self,
        _source: &CiSourceV1,
    ) -> CiScanResult<Option<(Box<dyn CiRunProvider>, u64)>> {
        Ok(Some((Box::new(recorded_provider()), 8)))
    }
}

/// A deterministic 512-component embedder with no zero component.
struct StubEmbedder;

impl ChunkEmbedder for StubEmbedder {
    fn dim(&self) -> usize {
        512
    }

    fn model_id(&self) -> &'static str {
        "stub-model2vec-512"
    }

    fn encode_batch(&self, texts: &[&str]) -> Vec<Vec<f32>> {
        texts
            .iter()
            .map(|text| {
                let seed = Sha256::digest(text.as_bytes());
                (0..512)
                    .map(|index| f32::from(seed[index % seed.len()]) - 127.5)
                    .collect()
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Worker wiring.
// ---------------------------------------------------------------------------

/// One installed scope and the sources a worker runs for it.
struct Fixture {
    installed: InstalledAuthority,
    repository: ScratchRepository,
    transcripts: tempfile::TempDir,
}

impl Fixture {
    async fn install(pool: &PgPool, label: &str) -> Self {
        Self {
            installed: install_generation_two(pool, label).await,
            repository: ScratchRepository::with_two_commits(),
            transcripts: transcript_directory(),
        }
    }

    fn sources(&self) -> WorkerSourcesV1 {
        WorkerSourcesV1::from_json_slice(&serde_json::to_vec(&self.sources_json()).unwrap())
            .expect("the fixture sources file is valid")
    }

    /// The sources file, as an operator would write it.
    fn sources_json(&self) -> serde_json::Value {
        serde_json::json!({
                "schema_version": 1,
                "coverage_since": "2026-08-01T00:00:00Z",
                "git": [{
                    "connector_principal": "connector.git",
                    "connector_instance": GIT_INSTANCE,
                    "installation_id": INSTALLATION_ID,
                    "repository_id": "git.repo.worker",
                    "git_dir": self.repository.path(),
                    "ref_name": "refs/heads/main"
                }],
                "transcripts": [{
                    "connector_principal": "connector.transcript",
                    "instance_prefix": TRANSCRIPT_PREFIX,
                    "installation_id": INSTALLATION_ID,
                    "dirs": [self.transcripts.path()]
                }],
                "ci": [{
                    "connector_principal": "connector.ci",
                    "connector_instance": CI_INSTANCE,
                    "installation_id": INSTALLATION_ID,
                    "repository_id": "ci.repo.worker",
                    "provider_repository": RECORDED_REPOSITORY,
                    "workflow": RECORDED_WORKFLOW,
                    "branch": RECORDED_BRANCH
                }]
        })
    }

    /// `worker --once --sources <file> --steps all` for this scope over
    /// `pool`, with the installed pins and key as the command's environment.
    /// Returns the command's outcome and what it printed.
    async fn run_command(
        &self,
        pool: &PgPool,
        capabilities: &DatabaseCapabilities,
        sources: &Path,
    ) -> (ostk_fleet_recall::Result<WorkerTickReportV1>, String) {
        let mut variables: HashMap<String, String> = serde_json::from_value(
            serde_json::to_value(&self.installed.report.pins).expect("the pins serialize"),
        )
        .expect("the pins are one string per variable");
        variables.insert(
            "FLEET_RECALL_CONTENT_KEK_HEX".into(),
            self.installed.kek_hex.clone(),
        );
        let lookup = |name: &str| variables.get(name).cloned();
        let load_embedder =
            || -> ostk_fleet_recall::Result<Arc<dyn ChunkEmbedder>> { Ok(Arc::new(StubEmbedder)) };
        let connection = (pool.clone(), capabilities.clone());
        let mut out = Vec::new();
        let outcome = run_command(
            &WorkerCommandV1 {
                sources: sources.to_path_buf(),
                once: true,
                steps: "all".into(),
            },
            WorkerProcessV1 {
                scope: self.installed.scope.clone(),
                embedding_model_sha256: &"5a".repeat(32),
                load_embedder: &load_embedder,
                lookup: &lookup,
                ci_providers: Arc::new(RecordedCi),
                retry: retry_policy(),
            },
            move || async move { Ok(connection) },
            &mut out,
        )
        .await;
        (
            outcome,
            String::from_utf8(out).expect("the report is UTF-8"),
        )
    }

    /// A worker running `steps` over `pool` (the owner, or a probe login).
    async fn worker(&self, pool: &PgPool, steps: &str) -> MemoryWorker {
        let embedding = ChunkEmbedderProvider::new(
            Arc::new(StubEmbedder),
            Sha256Digest::from_bytes([0x5a; 32]),
        )
        .expect("the stub embedder is 512 wide");
        MemoryWorker::new(
            WorkerDeps {
                pool: pool.clone(),
                scope: self.installed.scope.clone(),
                authority: Some(self.installed.runtime(pool).await),
                sources: self.sources(),
                embedding: Some(Arc::new(embedding)),
                ci_providers: Arc::new(RecordedCi),
                retry: retry_policy(),
            },
            parse_steps(steps).unwrap(),
            Some(self.installed.kek()),
            Some(self.installed.kek()),
        )
        .expect("every selected step has its inputs")
    }

    fn coverage(&self, pool: &PgPool) -> CockroachCoverageRuntimeRepository {
        CockroachCoverageRuntimeRepository::new(
            pool.clone(),
            TrustedControlScope::from_trusted_context(
                &self.installed.scope,
                self.installed.semantic_scope.clone(),
            )
            .unwrap(),
            RetryPolicy::default(),
        )
    }

    fn reader(&self, pool: &PgPool) -> CockroachRecallReader {
        CockroachRecallReader::new(
            pool.clone(),
            self.installed.scope.tenant_id,
            self.installed.scope.project.clone(),
        )
    }

    /// Every status row: `(instance, outcome, error, checked)`.
    async fn statuses(&self, pool: &PgPool) -> Vec<(String, String, Option<String>, bool)> {
        sqlx::query_as(
            "SELECT connector_instance_id, last_outcome, last_error, \
             last_checked_at IS NOT NULL FROM memory_worker_sources_v1 \
             WHERE tenant_id = $1 AND project = $2 AND state = 'active' \
             ORDER BY connector_instance_id",
        )
        .bind(self.installed.scope.tenant_id)
        .bind(&self.installed.scope.project)
        .fetch_all(pool)
        .await
        .unwrap()
    }

    /// Every coverage domain the scope has opened.
    async fn coverage_domains(&self, pool: &PgPool) -> BTreeSet<(String, Vec<u8>)> {
        sqlx::query_as::<_, (String, Vec<u8>)>(
            "SELECT connector_instance_id, coverage_key_digest FROM memory_coverage_cursors_v1 \
             WHERE tenant_id = $1 AND project = $2",
        )
        .bind(self.installed.scope.tenant_id)
        .bind(&self.installed.scope.project)
        .fetch_all(pool)
        .await
        .unwrap()
        .into_iter()
        .collect()
    }

    /// The resource kinds of every accepted evidence event in the scope.
    async fn evidence_kinds(&self, pool: &PgPool) -> BTreeSet<String> {
        sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT canonical_event FROM memory_evidence_events \
             WHERE tenant_id = $1 AND project = $2 AND event_kind = 'evidence.accepted'",
        )
        .bind(self.installed.scope.tenant_id)
        .bind(&self.installed.scope.project)
        .fetch_all(pool)
        .await
        .unwrap()
        .iter()
        .map(|bytes| {
            let statement: EvidenceStatementV2 = decode_strict(bytes).unwrap();
            let uri = statement.source_fact.canonical_resource_id.to_string();
            uri.split(':').nth(4).unwrap().to_owned()
        })
        .collect()
    }
}

async fn capabilities(database_url: &str) -> DatabaseCapabilities {
    CockroachStore::connect(
        database_url,
        common::fresh_scope("worker-capabilities"),
        PoolConfig::default(),
    )
    .await
    .expect("the owner must connect")
    .capabilities()
    .await
    .expect("the owner reads capabilities")
}

fn status(report: &WorkerTickReportV1, step: WorkerStepV1) -> WorkerStepStatusV1 {
    report.step(step).expect("every step is reported").status
}

fn counter(report: &WorkerTickReportV1, step: WorkerStepV1, key: &str) -> u64 {
    report.step(step).expect("every step is reported").counters[key]
}

fn assert_all_ok(report: &WorkerTickReportV1) {
    for step in WorkerStepV1::ALL {
        assert_eq!(
            status(report, step),
            WorkerStepStatusV1::Ok,
            "{step:?} must succeed: {}",
            serde_json::to_string_pretty(report).unwrap()
        );
    }
}

// ---------------------------------------------------------------------------
// The connected proofs.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn live_worker_tick_ingests_projects_and_embeds_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let fixture = Fixture::install(&pool, "worker-tick").await;
    let report = fixture.worker(&pool, "all").await.run_tick().await;

    assert_all_ok(&report);
    let authority = report.authority.expect("the tick verified a head");
    assert_eq!(authority.generation, 2);
    for step in WorkerStepV1::INGEST {
        assert!(
            counter(&report, step, "appended") > 0,
            "{step:?} must append evidence"
        );
    }
    assert_eq!(
        report.retired_sources,
        Some(0),
        "every status row belongs to a configured source"
    );

    let kinds = fixture.evidence_kinds(&pool).await;
    for kind in [
        "git_source_object_version",
        "transcript_turn_version",
        "ci_workflow_run_version",
    ] {
        assert!(
            kinds.contains(kind),
            "no accepted event from the {kind} connector: {kinds:?}"
        );
    }

    let reader = fixture.reader(&pool);
    let completeness = reader.completeness().await.unwrap();
    assert!(completeness.lexical_complete(), "{completeness:?}");
    assert!(completeness.dense_complete(), "{completeness:?}");
    assert!(completeness.densely_embedded > 0);
    for word in [COMMIT_WORD, TRANSCRIPT_WORD, FAILING_STEP_WORD] {
        let hits = reader.recall(word, None, 10).await.unwrap();
        assert!(!hits.hits.is_empty(), "recall must find {word:?}");
    }

    let statuses = fixture.statuses(&pool).await;
    let instances: BTreeSet<&str> = statuses.iter().map(|row| row.0.as_str()).collect();
    assert_eq!(
        instances,
        BTreeSet::from([
            CI_INSTANCE,
            GIT_INSTANCE,
            "connector.transcript.session",
            "connector.transcript.session-resumed",
        ])
    );
    for (instance, outcome, error, checked) in &statuses {
        assert_eq!(outcome, "ok", "{instance}: {error:?}");
        assert!(error.is_none() && *checked, "{instance}");
    }

    let coverage = fixture.coverage(&pool);
    for instance in &instances {
        let receipt = coverage
            .latest_receipt_for_instance(&ContractId::new(*instance).unwrap())
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("{instance} has no receipt"));
        assert_eq!(
            receipt.completeness,
            CoverageCompletenessV1::Complete,
            "{instance}'s latest cursor must be complete"
        );
    }
}

#[tokio::test]
async fn live_worker_second_tick_is_a_replay_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let fixture = Fixture::install(&pool, "worker-replay").await;
    let worker = fixture.worker(&pool, "all").await;
    assert_all_ok(&worker.run_tick().await);
    let domains = fixture.coverage_domains(&pool).await;

    let replay = worker.run_tick().await;
    assert_all_ok(&replay);
    for step in WorkerStepV1::INGEST {
        assert_eq!(counter(&replay, step, "appended"), 0, "{step:?}");
        assert_eq!(counter(&replay, step, "receipts"), 0, "{step:?}");
        for source in &replay.step(step).unwrap().sources {
            assert_eq!(
                source.outcome,
                WorkerSourceOutcomeV1::Unchanged,
                "{}",
                source.connector_instance
            );
        }
    }
    assert_eq!(
        counter(&replay, WorkerStepV1::Bodies, "events_projected"),
        0
    );
    for step in [WorkerStepV1::Lexical, WorkerStepV1::Dense] {
        assert_eq!(counter(&replay, step, "bodies_consumed"), 0, "{step:?}");
    }
    assert_eq!(
        fixture.coverage_domains(&pool).await,
        domains,
        "a replay must open no coverage domain"
    );
    for (instance, outcome, _, checked) in fixture.statuses(&pool).await {
        assert_eq!(outcome, "unchanged", "{instance}");
        assert!(checked, "an unchanged check still counts as checked");
    }
}

#[tokio::test]
async fn live_worker_isolates_step_failures_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let fixture = Fixture::install(&pool, "worker-isolation").await;
    std::fs::write(
        fixture.transcripts.path().join("broken.jsonl"),
        format!(
            "{}\n",
            r#"{"type":"telemetry-burst","sessionId":"s","uuid":"u","timestamp":"2026-08-15T12:30:00.000Z"}"#
        ),
    )
    .unwrap();
    let report = fixture.worker(&pool, "all").await.run_tick().await;

    assert_eq!(
        status(&report, WorkerStepV1::Transcript),
        WorkerStepStatusV1::Failed
    );
    for step in [
        WorkerStepV1::Git,
        WorkerStepV1::Ci,
        WorkerStepV1::Bodies,
        WorkerStepV1::Lexical,
        WorkerStepV1::Dense,
    ] {
        assert_eq!(status(&report, step), WorkerStepStatusV1::Ok, "{step:?}");
    }
    let transcripts = &report.step(WorkerStepV1::Transcript).unwrap().sources;
    for source in transcripts {
        if source.source == "broken.jsonl" {
            assert_eq!(source.outcome, WorkerSourceOutcomeV1::Failed);
            assert!(
                source
                    .error
                    .as_deref()
                    .is_some_and(|error| error.contains("broken.jsonl")),
                "{source:?}"
            );
        } else {
            assert_eq!(source.outcome, WorkerSourceOutcomeV1::Ok, "{source:?}");
        }
    }
    assert_eq!(
        report.retired_sources,
        Some(0),
        "a failed source is still a configured one"
    );

    let broken = fixture
        .statuses(&pool)
        .await
        .into_iter()
        .find(|row| row.0 == "connector.transcript.broken")
        .expect("a failed source still reports");
    assert_eq!(broken.1, "failed");
    assert!(broken.2.is_some(), "the status row carries the error");
    assert!(!broken.3, "a source that never completed was never checked");
    assert!(
        !fixture
            .reader(&pool)
            .recall(TRANSCRIPT_WORD, None, 10)
            .await
            .unwrap()
            .hits
            .is_empty(),
        "the healthy transcript is still recallable"
    );
}

#[tokio::test]
async fn live_worker_runs_under_runtime_grants_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let owner = common::migrated_pool(&database_url).await;
    let capabilities = capabilities(&database_url).await;
    let fixture = Fixture::install(&owner, "worker-grants").await;
    let all = parse_steps("all").unwrap();

    let without = RuntimeProbeRole::create_worker(&owner, &database_url, false).await;
    let refusal = probe_worker_privileges(&without.pool, &capabilities, &all).await;
    without.drop_role(&owner).await;
    match refusal {
        Err(FleetError::Configuration(message)) => {
            assert!(
                message.contains("runtime-role-grants.sql") && message.contains("public.memory_"),
                "the refusal must name the table and the policy: {message}"
            );
        }
        other => panic!("a login without the Stage-5 grants must be refused: {other:?}"),
    }

    let role = RuntimeProbeRole::create_worker(&owner, &database_url, true).await;
    let preflight = probe_worker_privileges(&role.pool, &capabilities, &all).await;
    // The resumed transcript repeats a turn body, so this tick deduplicates a
    // governed content object and takes its `FOR UPDATE` lock.
    let report = if preflight.is_ok() {
        Some(fixture.worker(&role.pool, "all").await.run_tick().await)
    } else {
        None
    };
    role.drop_role(&owner).await;
    preflight.expect("the runtime grants pass the preflight");
    let report = report.expect("the tick ran");
    assert_all_ok(&report);
    for step in WorkerStepV1::INGEST {
        assert!(counter(&report, step, "appended") > 0, "{step:?}");
    }
}

/// The one line a `worker --once` run printed, parsed; it must be the report
/// the run returned.
fn printed_report(printed: &str, report: &WorkerTickReportV1) -> serde_json::Value {
    assert!(printed.ends_with('\n'), "the report line is terminated");
    assert_eq!(
        printed.lines().count(),
        1,
        "one tick prints one line: {printed}"
    );
    let parsed: serde_json::Value = serde_json::from_str(printed).expect("the line is JSON");
    assert_eq!(parsed, serde_json::to_value(report).unwrap());
    parsed
}

#[tokio::test]
async fn live_worker_command_once_writes_one_report_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let owner = common::migrated_pool(&database_url).await;
    let capabilities = capabilities(&database_url).await;
    let fixture = Fixture::install(&owner, "worker-command").await;
    let directory = tempfile::tempdir().expect("sources directory");
    let sources = directory.path().join("worker-sources.json");
    std::fs::write(
        &sources,
        serde_json::to_vec_pretty(&fixture.sources_json()).unwrap(),
    )
    .unwrap();

    // A login without the Stage-5 grants is refused before the tick, so
    // nothing is printed and nothing is appended.
    let without = RuntimeProbeRole::create_worker(&owner, &database_url, false).await;
    let (refused, printed) = fixture
        .run_command(&without.pool, &capabilities, &sources)
        .await;
    without.drop_role(&owner).await;
    match refused {
        Err(FleetError::Configuration(message)) => {
            assert!(message.contains("runtime-role-grants.sql"), "{message}");
        }
        other => panic!("the preflight must refuse the login: {other:?}"),
    }
    assert!(printed.is_empty(), "a refused run prints no report");
    assert!(fixture.evidence_kinds(&owner).await.is_empty());

    let (outcome, printed) = fixture.run_command(&owner, &capabilities, &sources).await;
    let report = outcome.expect("a healthy tick completes");
    assert_all_ok(&report);
    assert_eq!(report.exit_code(), 0);
    let parsed = printed_report(&printed, &report);
    assert_eq!(parsed["authority"]["generation"], 2);

    std::fs::write(
        fixture.transcripts.path().join("broken.jsonl"),
        format!(
            "{}\n",
            r#"{"type":"telemetry-burst","sessionId":"s","uuid":"u","timestamp":"2026-08-15T12:30:00.000Z"}"#
        ),
    )
    .unwrap();
    let (outcome, printed) = fixture.run_command(&owner, &capabilities, &sources).await;
    let report = outcome.expect("a tick with a failed step still reports");
    assert_eq!(report.exit_code(), 1, "a failed step fails the process");
    let parsed = printed_report(&printed, &report);
    assert_eq!(parsed["steps"]["transcript"]["status"], "failed");
    for step in ["git", "ci", "bodies", "lexical", "dense"] {
        assert_eq!(parsed["steps"][step]["status"], "ok", "{step}");
    }
}
