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
//!
//! A generation-3 head (ADR 0008) changes none of that: a tick on a scope
//! installed straight to generation 3 ingests, projects, and embeds all three
//! connectors, and a scope moved from generation 2 to 3 keeps its sources,
//! cursors, and recall, and ingests what arrives after the move.

mod common;

use std::collections::{BTreeSet, HashMap};
use std::path::Path;
use std::sync::Arc;

use common::authority::retry_policy;
use common::runtime_role::RuntimeProbeRole;
use common::worker::{
    BROKEN_TRANSCRIPT_LINE, CI_INSTANCE, COMMIT_WORD, FAILING_STEP_WORD, GIT_INSTANCE, RecordedCi,
    RecordedCiSettledThrough, SECOND_COMMIT_DATE, StubEmbedder, TRANSCRIPT_WORD,
    WorkerFixture as Fixture, line,
};
use ostk_fleet_recall::FleetError;
use ostk_fleet_recall::connectors::ci::MAX_CI_WINDOW_RUNS;
use ostk_fleet_recall::memory_contracts::canonical::decode_strict;
use ostk_fleet_recall::memory_contracts::common::ContractId;
use ostk_fleet_recall::memory_contracts::coverage::CoverageCompletenessV1;
use ostk_fleet_recall::memory_contracts::evidence_v2::EvidenceStatementV2;
use ostk_fleet_recall::registry_activation::install::{
    InstallStepOutcomeV1, InstallStepV1, InstallTargetV1, install_writer_authority,
};
use ostk_fleet_recall::registry_witness::KnownRegistryPackage;
use ostk_fleet_recall::store::cockroach::{CockroachStore, DatabaseCapabilities, PoolConfig};
use ostk_fleet_recall::worker::{
    WorkerCommandV1, WorkerProcessV1, WorkerSourceOutcomeV1, WorkerStepStatusV1, WorkerStepV1,
    WorkerTickReportV1, parse_steps, probe_worker_privileges, run_command,
};
use ostk_recall_core::ChunkEmbedder;
use sqlx::PgPool;

// ---------------------------------------------------------------------------
// Test-only views of the fixture scope.
// ---------------------------------------------------------------------------

impl Fixture {
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
        format!("{BROKEN_TRANSCRIPT_LINE}\n"),
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

/// Append `lines` to one of the fixture's transcript files.
fn append_transcript(fixture: &Fixture, file: &str, lines: &[String]) {
    use std::io::Write as _;
    let mut handle = std::fs::OpenOptions::new()
        .append(true)
        .open(fixture.transcripts.path().join(file))
        .unwrap();
    for line in lines {
        writeln!(handle, "{line}").unwrap();
    }
}

/// The report of one transcript file in a tick.
fn transcript_source<'r>(
    report: &'r WorkerTickReportV1,
    file: &str,
) -> &'r ostk_fleet_recall::worker::WorkerSourceReportV1 {
    report
        .step(WorkerStepV1::Transcript)
        .unwrap()
        .sources
        .iter()
        .find(|source| source.source == file)
        .unwrap_or_else(|| panic!("{file} is not reported"))
}

#[tokio::test]
async fn live_worker_fails_a_transcript_line_longer_than_its_window_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let fixture = Fixture::install(&pool, "worker-long-line").await;
    let mut sources = fixture.sources_json();
    sources["transcripts"][0]["window_bytes"] = serde_json::json!(1024);
    let worker = fixture
        .worker_with(&pool, "all", &sources, Arc::new(RecordedCi))
        .await;
    assert_all_ok(&worker.run_tick().await);

    // After a drained slice: one line no 1 KiB window can hold, then a turn
    // behind it.
    append_transcript(
        &fixture,
        "session.jsonl",
        &[
            line(
                "assistant",
                "turn-3",
                "2026-08-15T12:30:02.000Z",
                &"the importer log ".repeat(200),
            ),
            line(
                "user",
                "turn-4",
                "2026-08-15T12:30:03.000Z",
                "and what about the marmalizard rows",
            ),
        ],
    );
    let report = worker.run_tick().await;

    // The source fails, naming the window, instead of reporting a stalled
    // file as unchanged; the other steps are untouched.
    let session = transcript_source(&report, "session.jsonl");
    assert_eq!(
        session.outcome,
        WorkerSourceOutcomeV1::Failed,
        "{session:?}"
    );
    assert!(
        session
            .error
            .as_deref()
            .is_some_and(|error| error.contains("window_bytes")),
        "{session:?}"
    );
    assert_eq!(
        status(&report, WorkerStepV1::Transcript),
        WorkerStepStatusV1::Failed
    );
    for step in [WorkerStepV1::Git, WorkerStepV1::Ci, WorkerStepV1::Bodies] {
        assert_eq!(status(&report, step), WorkerStepStatusV1::Ok, "{step:?}");
    }
    let row = fixture
        .statuses(&pool)
        .await
        .into_iter()
        .find(|row| row.0 == "connector.transcript.session")
        .expect("the source reports");
    assert_eq!(
        row.1, "failed",
        "evidence recall must not trust this source"
    );
    assert!(row.2.is_some_and(|error| error.contains("window_bytes")));

    // A second attempt fails the same way: the file never silently resumes
    // past the line.
    let again = worker.run_tick().await;
    assert_eq!(
        transcript_source(&again, "session.jsonl").outcome,
        WorkerSourceOutcomeV1::Failed
    );
}

#[tokio::test]
async fn live_worker_admits_staged_turns_when_a_later_line_fails_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let fixture = Fixture::install(&pool, "worker-staged-then-broken").await;
    let staged = format!(
        "{}\n{}\n",
        line(
            "user",
            "big-1",
            "2026-08-17T10:00:00.000Z",
            &format!(
                "where does the gallimaufry ledger live {}",
                "while the batch settles ".repeat(12)
            ),
        ),
        line(
            "assistant",
            "big-2",
            "2026-08-17T10:00:01.000Z",
            &format!(
                "it lives in the archive {}",
                "once the batch settles ".repeat(12)
            ),
        ),
    );
    std::fs::write(
        fixture.transcripts.path().join("big.jsonl"),
        format!("{staged}{BROKEN_TRANSCRIPT_LINE}\n"),
    )
    .unwrap();
    // The first window of big.jsonl holds exactly its two good turns, so
    // they are staged before the next window reaches the line the parser
    // refuses. Every other fixture file fits one window.
    let mut sources = fixture.sources_json();
    sources["transcripts"][0]["window_bytes"] = serde_json::json!(staged.len());
    let report = fixture
        .worker_with(&pool, "all", &sources, Arc::new(RecordedCi))
        .await
        .run_tick()
        .await;

    let big = transcript_source(&report, "big.jsonl");
    assert_eq!(big.outcome, WorkerSourceOutcomeV1::Failed, "{big:?}");
    assert!(
        big.error
            .as_deref()
            .is_some_and(|error| error.contains("big.jsonl")),
        "{big:?}"
    );
    assert!(
        big.counters["appended"] > 0,
        "the staged turns are admitted despite the bad line: {big:?}"
    );
    let pending: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM memory_transcript_outbox_v1 \
         WHERE tenant_id = $1 AND project = $2 AND source_id = 'big.jsonl' \
         AND state = 'pending')",
    )
    .bind(fixture.installed.scope.tenant_id)
    .bind(&fixture.installed.scope.project)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!pending, "no staged turn is stranded in the outbox");
    assert!(
        !fixture
            .reader(&pool)
            .recall("gallimaufry", None, 10)
            .await
            .unwrap()
            .hits
            .is_empty(),
        "a turn staged before the bad line is recallable"
    );
}

#[tokio::test]
async fn live_worker_ci_receipt_is_partial_until_the_settled_head_is_read_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let fixture = Fixture::install(&pool, "worker-ci-backlog").await;
    // A settled head more than one window past the resume point.
    let head = u64::try_from(MAX_CI_WINDOW_RUNS).unwrap() + 88;
    let worker = fixture
        .worker_with(
            &pool,
            "ingest",
            &fixture.sources_json(),
            Arc::new(RecordedCiSettledThrough(head)),
        )
        .await;
    let coverage = fixture.coverage(&pool);
    let ci = ContractId::new(CI_INSTANCE).unwrap();

    let report = worker.run_tick().await;
    assert_eq!(status(&report, WorkerStepV1::Ci), WorkerStepStatusV1::Ok);
    let receipt = coverage
        .latest_receipt_for_instance(&ci)
        .await
        .unwrap()
        .expect("the first window has a receipt");
    assert_eq!(
        receipt.completeness,
        CoverageCompletenessV1::Partial,
        "one window cannot claim the runs past it"
    );

    let report = worker.run_tick().await;
    assert_eq!(status(&report, WorkerStepV1::Ci), WorkerStepStatusV1::Ok);
    let receipt = coverage
        .latest_receipt_for_instance(&ci)
        .await
        .unwrap()
        .expect("the second window has a receipt");
    assert_eq!(
        receipt.completeness,
        CoverageCompletenessV1::Complete,
        "the tick that reaches the head is complete"
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
        format!("{BROKEN_TRANSCRIPT_LINE}\n"),
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

// ---------------------------------------------------------------------------
// Generation 3 (ADR 0008).
// ---------------------------------------------------------------------------

/// A word that occurs only in a commit made after a scope moved to
/// generation 3.
const AFTER_MOVE_WORD: &str = "tessellate";

#[tokio::test]
async fn live_worker_tick_on_a_generation_three_head_ingests_projects_and_embeds_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let fixture = Fixture::install_at(
        &pool,
        "worker-generation-three",
        InstallTargetV1::Generation3,
    )
    .await;
    assert_eq!(
        fixture.installed.report.package,
        KnownRegistryPackage::CollectedItemsGeneration3
    );
    let report = fixture.worker(&pool, "all").await.run_tick().await;

    assert_all_ok(&report);
    let authority = report.authority.expect("the tick verified a head");
    assert_eq!(authority.generation, 3);
    for step in WorkerStepV1::INGEST {
        assert!(
            counter(&report, step, "appended") > 0,
            "{step:?} must append evidence under generation 3"
        );
    }
    let kinds = fixture.evidence_kinds(&pool).await;
    for kind in [
        "git_source_object_version",
        "transcript_turn_version",
        "ci_workflow_run_version",
    ] {
        assert!(kinds.contains(kind), "no {kind} event: {kinds:?}");
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
}

#[tokio::test]
async fn live_worker_keeps_its_sources_across_a_move_to_generation_three_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let fixture = Fixture::install(&pool, "worker-two-to-three").await;
    assert_all_ok(&fixture.worker(&pool, "all").await.run_tick().await);

    // The operator moves the scope; the writer's pins do not change.
    let mut request = fixture.installed.request();
    request.target = InstallTargetV1::Generation3;
    let moved = install_writer_authority(&pool, &request, retry_policy())
        .await
        .expect("the scope moves to generation 3");
    assert_eq!(moved.pins, fixture.installed.report.pins);
    assert_eq!(
        moved
            .steps
            .iter()
            .find(|step| step.step == InstallStepV1::GenerationThree)
            .map(|step| step.outcome),
        Some(InstallStepOutcomeV1::Inserted)
    );

    // The durable cursors still hold: nothing already read is read again.
    let after_move = fixture.worker(&pool, "all").await.run_tick().await;
    assert_all_ok(&after_move);
    assert_eq!(after_move.authority.expect("a verified head").generation, 3);
    for step in WorkerStepV1::INGEST {
        assert_eq!(counter(&after_move, step, "appended"), 0, "{step:?}");
    }
    let reader = fixture.reader(&pool);
    for word in [COMMIT_WORD, TRANSCRIPT_WORD, FAILING_STEP_WORD] {
        assert!(
            !reader.recall(word, None, 10).await.unwrap().hits.is_empty(),
            "evidence admitted under generation 2 must stay recallable: {word:?}"
        );
    }

    // What arrives after the move is admitted under generation 3.
    let head = fixture.repository.head();
    fixture.repository.commit(
        Some(&head),
        &format!("record the {AFTER_MOVE_WORD} rollout"),
        SECOND_COMMIT_DATE,
    );
    let later = fixture.worker(&pool, "all").await.run_tick().await;
    assert_all_ok(&later);
    assert!(counter(&later, WorkerStepV1::Git, "appended") > 0);
    let completeness = reader.completeness().await.unwrap();
    assert!(completeness.lexical_complete(), "{completeness:?}");
    assert!(completeness.dense_complete(), "{completeness:?}");
    assert!(
        !reader
            .recall(AFTER_MOVE_WORD, None, 10)
            .await
            .unwrap()
            .hits
            .is_empty(),
        "a commit made after the move must be recallable"
    );
}
