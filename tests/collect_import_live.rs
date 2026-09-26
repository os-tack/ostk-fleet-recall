//! Connected proofs of operator imports and the `collect` command (ADR 0008
//! D9): `collect import` stages a file of items under
//! `connector.collected.import`, drains it, and records a snapshot, so that
//! item and evidence recall read the items back, re-importing stages nothing,
//! edits supersede, deleted lines hide, refused lines are digest-only dead
//! letters, `--no-drain` leaves absence unknown until a worker tick drains and
//! finalizes the import, and `collect retire` retires only an import.
//!
//! Every import runs through `run_collect_command`, the code path
//! `ostk-fleet-recall collect` runs, with the installed pins (and, unless a
//! test withholds it, the content key) as its environment. Every test needs
//! `FLEET_RECALL_TEST_DATABASE_URL` and returns at once without it.

mod common;

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ostk_fleet_recall::FleetScope;
use ostk_fleet_recall::collectors::command::{
    CollectCommandV1, CollectImportV1, CollectProcessV1, ImportAudienceV1, ImportFormatV1,
    run_collect_command,
};
use ostk_fleet_recall::evidence_recall::{
    AbsenceReasonV1, AbsenceVerdictV1, CockroachEvidenceRecall, EvidenceRecall as _,
    EvidenceSearchV1, probe_evidence_recall,
};
use ostk_fleet_recall::item_recall::{
    CockroachItemRecall, ItemGetV1, ItemRecall as _, ItemReferenceV1, ItemSearchRequestV1,
    ItemSearchV1, ItemSuppressionV1, probe_item_recall,
};
use ostk_fleet_recall::memory_contracts::collected_item::{
    ObjectKindV1, ProviderKindV1, TrustTierV1, derive_item_key,
};
use ostk_fleet_recall::memory_contracts::coverage::CoverageCompletenessV1;
use ostk_fleet_recall::memory_contracts::digest::Sha256Digest;
use ostk_fleet_recall::registry_activation::install::InstallTargetV1;
use ostk_fleet_recall::store::cockroach::{CockroachStore, DatabaseCapabilities};
use ostk_fleet_recall::worker::{WorkerStepV1, WorkerTickReportV1};
use serde_json::{Value, json};
use sqlx::PgPool;

use common::authority::retry_policy;
use common::worker::{GIT_INSTANCE, RecordedCi, STUB_MODEL_DIGEST, WorkerFixture};

const MISSING: &str = "unfindable marmoset";

/// One fixture file and the instance that imports it.
struct Source {
    name: &'static str,
    provider: &'static str,
    scope: &'static str,
}

const DOCS: Source = Source {
    name: "docs",
    provider: "docs",
    scope: "docs.acme.specs",
};
const SLACK: Source = Source {
    name: "slack",
    provider: "slack",
    scope: "T07ACME0001",
};
const LINEAR: Source = Source {
    name: "linear",
    provider: "linear",
    scope: "0a9c0000-0000-4000-8000-0000000ac3e1",
};
const GRANOLA: Source = Source {
    name: "granola",
    provider: "granola",
    scope: "workspace.acme-robotics",
};

impl Source {
    fn instance(&self) -> String {
        format!("import.{}", self.name)
    }

    fn fixture(&self) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/collected")
            .join(format!("items-{}.jsonl", self.name))
    }

    fn lines(&self) -> Vec<String> {
        std::fs::read_to_string(self.fixture())
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    fn import(&self, path: &Path, no_drain: bool) -> CollectCommandV1 {
        CollectCommandV1::Import(CollectImportV1 {
            instance: self.instance(),
            principal: "principal.import".into(),
            provider: self.provider.into(),
            provider_scope: self.scope.into(),
            audience: ImportAudienceV1::OperatorDeclared,
            format: ImportFormatV1::ItemsJsonl,
            path: path.to_path_buf(),
            no_drain,
            stale_after_seconds: None,
        })
    }

    fn provider(&self) -> ProviderKindV1 {
        ProviderKindV1::new(self.provider).unwrap()
    }
}

// ---------------------------------------------------------------------------
// The command, ticks, and rows
// ---------------------------------------------------------------------------

async fn fixture_at(pool: &PgPool, label: &str) -> WorkerFixture {
    WorkerFixture::install_at(pool, label, InstallTargetV1::Generation3).await
}

async fn capabilities(pool: &PgPool, scope: &FleetScope) -> DatabaseCapabilities {
    CockroachStore::from_pool(pool.clone(), scope.clone())
        .unwrap()
        .capabilities()
        .await
        .unwrap()
}

/// `ostk-fleet-recall collect ...` for the fixture scope, with the installed
/// pins, and the content key when `with_key`, as its environment.
async fn collect(
    fixture: &WorkerFixture,
    pool: &PgPool,
    command: &CollectCommandV1,
    with_key: bool,
) -> ostk_fleet_recall::Result<Value> {
    let mut variables: HashMap<String, String> = serde_json::from_value(
        serde_json::to_value(&fixture.installed.report.pins).expect("the pins serialize"),
    )
    .expect("the pins are one string per variable");
    if with_key {
        variables.insert(
            "FLEET_RECALL_CONTENT_KEK_HEX".into(),
            fixture.installed.kek_hex.clone(),
        );
    }
    let lookup = |name: &str| variables.get(name).cloned();
    let connection = (
        pool.clone(),
        capabilities(pool, &fixture.installed.scope).await,
    );
    let mut out = Vec::new();
    let outcome = Box::pin(run_collect_command(
        command,
        CollectProcessV1 {
            scope: fixture.installed.scope.clone(),
            lookup: &lookup,
            retry: retry_policy(),
        },
        move || async move { Ok(connection) },
        &mut out,
    ))
    .await;
    if let Ok(document) = &outcome {
        let printed: Value = serde_json::from_slice(&out).expect("one JSON document is printed");
        assert_eq!(&printed, document);
    }
    outcome
}

/// An import that must succeed: its report.
async fn import(
    fixture: &WorkerFixture,
    pool: &PgPool,
    source: &Source,
    path: &Path,
    no_drain: bool,
) -> Value {
    collect(fixture, pool, &source.import(path, no_drain), !no_drain)
        .await
        .unwrap_or_else(|error| panic!("the {} import must succeed: {error}", source.name))
}

/// A sources file that configures no connector, so a tick drains and projects
/// only what the imports staged.
fn no_sources() -> Value {
    json!({"schema_version": 1})
}

/// A tick that must not fail.
async fn tick(
    fixture: &WorkerFixture,
    pool: &PgPool,
    sources: &Value,
    steps: &str,
) -> WorkerTickReportV1 {
    let report = fixture
        .worker_with(pool, steps, sources, Arc::new(RecordedCi))
        .await
        .run_tick()
        .await;
    assert!(
        !report.failed(),
        "the {steps} tick must succeed: {}",
        serde_json::to_string_pretty(&report).unwrap()
    );
    report
}

async fn scalar(pool: &PgPool, fixture: &WorkerFixture, sql: &str) -> i64 {
    sqlx::query_scalar(sql)
        .bind(fixture.installed.scope.tenant_id)
        .bind(&fixture.installed.scope.project)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn outbox_rows(pool: &PgPool, fixture: &WorkerFixture) -> i64 {
    scalar(
        pool,
        fixture,
        "SELECT count(*) FROM memory_collector_outbox_v1 WHERE tenant_id = $1 AND project = $2",
    )
    .await
}

async fn pending_rows(pool: &PgPool, fixture: &WorkerFixture) -> i64 {
    scalar(
        pool,
        fixture,
        "SELECT count(*) FROM memory_collector_outbox_v1 \
         WHERE tenant_id = $1 AND project = $2 AND state = 'pending'",
    )
    .await
}

/// An import's status row: state, last outcome, and whether it was checked.
async fn source_row(
    pool: &PgPool,
    fixture: &WorkerFixture,
    instance: &str,
) -> (String, String, bool) {
    sqlx::query_as(
        "SELECT state, last_outcome, last_checked_at IS NOT NULL \
         FROM memory_collector_sources_v1 \
         WHERE tenant_id = $1 AND project = $2 AND collector_instance_id = $3",
    )
    .bind(fixture.installed.scope.tenant_id)
    .bind(&fixture.installed.scope.project)
    .bind(instance)
    .fetch_one(pool)
    .await
    .unwrap()
}

/// `collect retire --instance <instance>`.
async fn retire(
    fixture: &WorkerFixture,
    pool: &PgPool,
    instance: &str,
) -> ostk_fleet_recall::Result<Value> {
    let command = CollectCommandV1::Retire {
        instance: instance.to_owned(),
    };
    collect(fixture, pool, &command, false).await
}

fn write_lines(directory: &Path, name: &str, lines: &[String]) -> PathBuf {
    let path = directory.join(name);
    std::fs::write(&path, lines.join("\n") + "\n").unwrap();
    path
}

// ---------------------------------------------------------------------------
// Recall
// ---------------------------------------------------------------------------

async fn items(pool: &PgPool, fixture: &WorkerFixture) -> CockroachItemRecall {
    let scope = &fixture.installed.scope;
    let capability = probe_item_recall(
        pool,
        &capabilities(pool, scope).await,
        scope,
        Sha256Digest::from_bytes(STUB_MODEL_DIGEST),
    )
    .await
    .expect("the probe runs")
    .expect("the owner may read every item-recall table");
    CockroachItemRecall::new(capability, pool.clone())
}

async fn evidence(pool: &PgPool, fixture: &WorkerFixture) -> CockroachEvidenceRecall {
    let scope = &fixture.installed.scope;
    let capability = probe_evidence_recall(
        pool,
        &capabilities(pool, scope).await,
        scope,
        Sha256Digest::from_bytes(STUB_MODEL_DIGEST),
    )
    .await
    .expect("the probe runs")
    .expect("the owner may read every evidence table");
    CockroachEvidenceRecall::new(capability, pool.clone())
}

async fn search(
    recall: &CockroachItemRecall,
    query: &str,
    provider: Option<&Source>,
) -> ItemSearchV1 {
    recall
        .search(
            &ItemSearchRequestV1 {
                query: query.to_owned(),
                provider: provider.map(Source::provider),
                include_history: false,
                limit: 50,
            },
            None,
        )
        .await
        .unwrap()
}

async fn evidence_search(recall: &CockroachEvidenceRecall, query: &str) -> EvidenceSearchV1 {
    recall.search(query, None, 50).await.unwrap()
}

async fn get(
    recall: &CockroachItemRecall,
    source: &Source,
    object_kind: &str,
    external_id: &str,
) -> ItemGetV1 {
    let key = derive_item_key(
        &source.provider(),
        source.scope,
        &ObjectKindV1::new(object_kind).unwrap(),
        external_id,
    );
    recall
        .get(&ItemReferenceV1::Item(key))
        .await
        .unwrap()
        .expect("the item exists")
}

// ---------------------------------------------------------------------------
// Proofs
// ---------------------------------------------------------------------------

#[tokio::test]
async fn live_import_of_the_four_files_recalls_the_retry_budget_in_both_kinds_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let fixture = fixture_at(&pool, "import-four").await;
    for source in [&DOCS, &SLACK, &LINEAR, &GRANOLA] {
        let report = import(&fixture, &pool, source, &source.fixture(), false).await;
        let lines = u64::try_from(source.lines().len()).unwrap();
        assert_eq!(report["items_staged"], json!(lines), "{report}");
        assert_eq!(report["refused"], json!({}), "{report}");
        assert_eq!(
            report["snapshot"],
            json!({"state": "recorded", "complete": true, "receipts": 1}),
            "{report}"
        );
        assert_eq!(report["drained"]["dead_lettered"], json!(0), "{report}");
    }
    assert_eq!(pending_rows(&pool, &fixture).await, 0);
    tick(&fixture, &pool, &no_sources(), "project").await;

    // "retry budget" is in every source, as an item and as evidence.
    let recall = items(&pool, &fixture).await;
    let found = search(&recall, "retry budget", None).await;
    let providers: BTreeSet<&str> = found.hits.iter().map(|hit| hit.provider.as_str()).collect();
    assert_eq!(
        providers,
        BTreeSet::from(["docs", "granola", "linear", "slack"])
    );
    assert!(
        found
            .hits
            .iter()
            .all(|hit| hit.trust == TrustTierV1::Reported)
    );
    let evidence_recall = evidence(&pool, &fixture).await;
    let answer = evidence_search(&evidence_recall, "retry budget").await;
    let providers: BTreeSet<String> = answer
        .hits
        .iter()
        .filter_map(|hit| hit.item.as_ref().map(|item| item.provider.clone()))
        .collect();
    assert_eq!(
        providers,
        BTreeSet::from(["docs", "granola", "linear", "slack"].map(str::to_owned))
    );

    // Four complete snapshots and nothing pending: a missing word is absent,
    // in both kinds.
    let missing = search(&recall, MISSING, None).await;
    assert!(missing.hits.is_empty());
    assert_eq!(
        (missing.absence.verdict, missing.absence.reasons),
        (AbsenceVerdictV1::Absent, Vec::new())
    );
    let missing = evidence_search(&evidence_recall, MISSING).await;
    assert_eq!(
        (missing.absence.verdict, missing.absence.reasons),
        (AbsenceVerdictV1::Absent, Vec::new())
    );
    let imports: Vec<_> = missing
        .sources
        .active
        .iter()
        .filter(|source| source.connector_instance.starts_with("import."))
        .collect();
    assert_eq!(imports.len(), 4);
    assert!(imports.iter().all(|source| {
        source
            .coverage
            .as_ref()
            .is_some_and(|coverage| coverage.completeness == CoverageCompletenessV1::Complete)
    }));

    // `collect status` names every import with its row, outbox, and plan.
    let status = collect(&fixture, &pool, &CollectCommandV1::Status, false)
        .await
        .unwrap();
    let listed = status["instances"].as_array().unwrap();
    assert_eq!(listed.len(), 4, "{status}");
    for instance in listed {
        assert_eq!(instance["source"]["owner"], "import", "{instance}");
        assert_eq!(instance["source"]["coverage_role"], "snapshot");
        assert_eq!(instance["source"]["state"], "active");
        assert!(instance["outbox"]["admitted"].as_u64().unwrap() >= 2);
        assert_eq!(instance["cursors"][0]["domain_key"], "import.snapshot");
        assert!(instance["cursors"][0].get("cursor_state").is_none());
    }
}

#[tokio::test]
async fn live_reimport_stages_nothing_an_edit_supersedes_and_a_deleted_line_hides_when_configured()
{
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let fixture = fixture_at(&pool, "import-edit").await;
    let directory = tempfile::tempdir().unwrap();
    import(&fixture, &pool, &SLACK, &SLACK.fixture(), false).await;
    let rows = outbox_rows(&pool, &fixture).await;

    // The same file again: nothing is staged, and the snapshot is re-checked.
    let again = import(&fixture, &pool, &SLACK, &SLACK.fixture(), false).await;
    assert_eq!(again["rows_staged"], json!(0), "{again}");
    assert_eq!(again["items_staged"], json!(5), "{again}");
    assert_eq!(again["snapshot"]["state"], "recorded", "{again}");
    assert_eq!(outbox_rows(&pool, &fixture).await, rows);
    assert_eq!(
        source_row(&pool, &fixture, &SLACK.instance()).await,
        ("active".to_owned(), "unchanged".to_owned(), true)
    );

    // The decision is edited, and the Linear bot's message is deleted.
    let mut lines = SLACK.lines();
    lines[2] = lines[2]
        .replace(
            r#""version":{"marker":"1790007122.004300","order_micros":1790007122004300},"lifecycle":"live""#,
            r#""version":{"marker":"1790009000.000000","order_micros":1790009000000000},"lifecycle":"edited""#,
        )
        .replace(
            r#""created_at":"2026-09-21T16:12:02.004300Z","#,
            r#""created_at":"2026-09-21T16:12:02.004300Z","updated_at":"2026-09-21T16:43:20Z","#,
        )
        .replace("retry budget is 5 attempts", "retry budget is 4 attempts");
    assert!(lines[2].contains("4 attempts") && lines[2].contains("16:43:20"));
    let deleted: Value = {
        let mut line: Value = serde_json::from_str(&lines[3]).unwrap();
        line["version"] =
            json!({"marker": "1790012000.000000", "order_micros": 1_790_012_000_000_000_u64});
        line["lifecycle"] = json!("deleted");
        line["updated_at"] = json!("2026-09-21T17:33:20Z");
        line["text"] = json!("");
        line
    };
    lines[3] = deleted.to_string();
    let edited = write_lines(directory.path(), "slack-edited.jsonl", &lines);
    let report = import(&fixture, &pool, &SLACK, &edited, false).await;
    assert_eq!(
        report["rows_staged"],
        json!(3),
        "two versions and the observation: {report}"
    );
    assert_eq!(
        report["snapshot"],
        json!({"state": "recorded", "complete": true, "receipts": 1})
    );
    tick(&fixture, &pool, &no_sources(), "project").await;

    let recall = items(&pool, &fixture).await;
    let decision = get(&recall, &SLACK, "message", "C07PLATENG1:1790007122.004300").await;
    let text = decision.current.parts[0].text.clone().unwrap_or_default();
    assert!(text.contains("4 attempts"), "{text}");
    assert_eq!(decision.history.len(), 1);
    let hits = search(&recall, "attempts jitter", Some(&SLACK)).await.hits;
    assert_eq!(hits.len(), 1, "only the presented version: {hits:?}");
    assert!(hits[0].current);

    let bot = get(&recall, &SLACK, "message", "C07PLATENG1:1790011800.000900").await;
    assert_eq!(bot.suppressed, Some(ItemSuppressionV1::Deleted));
    assert!(
        bot.current
            .parts
            .iter()
            .all(|part| part.text.as_deref().unwrap_or_default().is_empty())
    );
    assert!(
        search(&recall, "Cap worker retries", Some(&SLACK))
            .await
            .hits
            .is_empty()
    );
    let evidence_recall = evidence(&pool, &fixture).await;
    assert!(
        evidence_search(&evidence_recall, "Cap worker retries")
            .await
            .hits
            .is_empty(),
        "deleted text is withheld from evidence recall too"
    );
    // The earlier decision is still evidence, as a superseded version.
    let answer = evidence_search(&evidence_recall, "5 attempts with jitter").await;
    assert!(answer.hits.iter().any(|hit| {
        hit.item
            .as_ref()
            .is_some_and(|item| item.provider == "slack" && !item.current)
    }));
}

#[tokio::test]
async fn live_refused_lines_are_digest_only_dead_letters_and_leave_the_snapshot_partial_when_configured()
 {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let fixture = fixture_at(&pool, "import-refused").await;
    let directory = tempfile::tempdir().unwrap();
    let mut lines = GRANOLA.lines();
    // A Slack line in a Granola import, and a note the importer marked direct.
    lines.push(SLACK.lines()[0].clone());
    let mut direct: Value = serde_json::from_str(&lines[0]).unwrap();
    direct["external_id"] = json!("not_privatequokka");
    direct["text"] = json!("The quokka budget is private.");
    direct["visibility"] = json!("dm");
    lines.push(direct.to_string());
    let path = write_lines(directory.path(), "granola-mixed.jsonl", &lines);

    let report = import(&fixture, &pool, &GRANOLA, &path, false).await;
    assert_eq!(
        report["refused"],
        json!({"audience_refused": 1, "validation_failed": 1}),
        "{report}"
    );
    assert_eq!(report["items_staged"], json!(2));
    assert_eq!(
        report["snapshot"],
        json!({"state": "recorded", "complete": false, "receipts": 1}),
        "a line the snapshot names but did not admit leaves it partial: {report}"
    );

    let letters = collect(
        &fixture,
        &pool,
        &CollectCommandV1::DeadLetters {
            since: None,
            instance: Some(GRANOLA.instance()),
        },
        false,
    )
    .await
    .unwrap();
    let listed = letters["dead_letters"].as_array().unwrap();
    let reasons: BTreeSet<&str> = listed
        .iter()
        .map(|letter| letter["reason"].as_str().unwrap())
        .collect();
    assert_eq!(
        reasons,
        BTreeSet::from(["audience_refused", "validation_failed"])
    );
    assert!(listed.iter().any(|letter| {
        letter["diagnostic"]
            .as_str()
            .unwrap()
            .starts_with("provider_scope_mismatch")
    }));
    assert!(listed.iter().all(|letter| {
        letter["payload_digest"].as_str().unwrap().len() == 64
            && letter["delivery_id"].as_str().unwrap().len() == 80
    }));
    let printed = letters.to_string();
    for text in ["quokka", "retry budget", "Should the ingest worker"] {
        assert!(!printed.contains(text), "no provider text: {printed}");
    }
    // Re-importing the same file records the same refusals once.
    import(&fixture, &pool, &GRANOLA, &path, false).await;
    let again = collect(
        &fixture,
        &pool,
        &CollectCommandV1::DeadLetters {
            since: None,
            instance: Some(GRANOLA.instance()),
        },
        false,
    )
    .await
    .unwrap();
    assert_eq!(again["dead_letters"].as_array().unwrap().len(), 2);

    tick(&fixture, &pool, &no_sources(), "project").await;
    let recall = items(&pool, &fixture).await;
    assert!(search(&recall, "quokka", None).await.hits.is_empty());
    assert!(
        evidence_search(&evidence(&pool, &fixture).await, "quokka")
            .await
            .hits
            .is_empty()
    );
    let missing = search(&recall, MISSING, Some(&GRANOLA)).await;
    assert_eq!(missing.absence.verdict, AbsenceVerdictV1::Unknown);
    assert_eq!(
        missing.absence.reasons,
        [AbsenceReasonV1::IncompleteCoverage]
    );
}

#[tokio::test]
async fn live_no_drain_leaves_absence_unknown_until_a_worker_drains_the_import_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let fixture = fixture_at(&pool, "import-no-drain").await;

    // Staging only: no content key is read.
    let report = import(&fixture, &pool, &LINEAR, &LINEAR.fixture(), true).await;
    assert_eq!(report["drained"], Value::Null, "{report}");
    assert_eq!(report["snapshot"], json!({"state": "awaiting_drain"}));
    assert_eq!(pending_rows(&pool, &fixture).await, 4);
    assert_eq!(
        source_row(&pool, &fixture, &LINEAR.instance()).await,
        ("active".to_owned(), "ok".to_owned(), false)
    );
    let recall = items(&pool, &fixture).await;
    let missing = search(&recall, MISSING, Some(&LINEAR)).await;
    assert_eq!(missing.absence.verdict, AbsenceVerdictV1::Unknown);
    assert!(
        missing
            .absence
            .reasons
            .contains(&AbsenceReasonV1::IngestOutboxPending),
        "{:?}",
        missing.absence.reasons
    );
    let evidence_recall = evidence(&pool, &fixture).await;
    let answer = evidence_search(&evidence_recall, MISSING).await;
    assert_eq!(answer.absence.verdict, AbsenceVerdictV1::Unknown);
    assert!(
        answer
            .absence
            .reasons
            .contains(&AbsenceReasonV1::IngestOutboxPending)
    );

    // A worker tick drains the rows and records the import's snapshot.
    let ticked = tick(&fixture, &pool, &no_sources(), "collect,project").await;
    let step = ticked.step(WorkerStepV1::Collect).unwrap();
    assert_eq!(step.counters["imports_recorded"], 1, "{step:?}");
    assert_eq!(step.counters["imports_waiting"], 0);
    assert_eq!(pending_rows(&pool, &fixture).await, 0);
    assert_eq!(
        source_row(&pool, &fixture, &LINEAR.instance()).await,
        ("active".to_owned(), "ok".to_owned(), true)
    );

    let missing = search(&recall, MISSING, Some(&LINEAR)).await;
    assert_eq!(
        (missing.absence.verdict, missing.absence.reasons.clone()),
        (AbsenceVerdictV1::Absent, Vec::new())
    );
    assert!(missing.absence.as_of.is_some());
    let snapshot = missing
        .sources
        .active
        .iter()
        .find(|source| source.connector_instance == LINEAR.instance())
        .expect("the import is a source");
    assert!(snapshot.last_checked_at.is_some());
    assert_eq!(
        snapshot
            .coverage
            .as_ref()
            .map(|coverage| coverage.completeness),
        Some(CoverageCompletenessV1::Complete)
    );
    assert_eq!(
        evidence_search(&evidence_recall, MISSING)
            .await
            .absence
            .verdict,
        AbsenceVerdictV1::Absent
    );
    assert!(
        !search(&recall, "retry budget", Some(&LINEAR))
            .await
            .hits
            .is_empty()
    );

    // A later tick has nothing left to finalize.
    let later = tick(&fixture, &pool, &no_sources(), "collect").await;
    let step = later.step(WorkerStepV1::Collect).unwrap();
    assert_eq!(
        (
            step.counters["imports_recorded"],
            step.counters["imports_waiting"]
        ),
        (0, 0)
    );
}

#[tokio::test]
async fn live_collect_retire_retires_only_an_import_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let fixture = fixture_at(&pool, "import-retire").await;
    let root = tempfile::tempdir().unwrap();
    std::fs::write(
        root.path().join("notes.md"),
        b"# Notes\nThe heron ledger.\n",
    )
    .unwrap();
    let mut sources = fixture.sources_json();
    sources["collectors"] = json!([{
        "provider": "docs",
        "connector_principal": "principal.docs",
        "connector_instance": "docs.specs",
        "provider_scope_id": "specs",
        "audience": {"operator_declared": true},
        "settings": {"root": root.path(), "extensions": ["md"],
                     "max_file_bytes": 65_536, "max_files": 100}
    }]);
    tick(&fixture, &pool, &sources, "all").await;

    // An import never takes a worker source's or a worker collector's name.
    for taken in [GIT_INSTANCE, "docs.specs"] {
        let command = CollectCommandV1::Import(CollectImportV1 {
            instance: taken.into(),
            ..match DOCS.import(&DOCS.fixture(), false) {
                CollectCommandV1::Import(arguments) => arguments,
                _ => unreachable!(),
            }
        });
        let error = collect(&fixture, &pool, &command, true)
            .await
            .expect_err("the instance is taken");
        assert!(error.to_string().contains(taken), "{error}");
    }
    let error = retire(&fixture, &pool, "docs.specs")
        .await
        .expect_err("a worker collector is not an import");
    assert!(error.to_string().contains("worker"), "{error}");
    assert_eq!(source_row(&pool, &fixture, "docs.specs").await.0, "active");

    import(&fixture, &pool, &DOCS, &DOCS.fixture(), false).await;
    tick(&fixture, &pool, &no_sources(), "project").await;
    let retired = retire(&fixture, &pool, &DOCS.instance()).await.unwrap();
    assert_eq!(
        retired,
        json!({"instance": DOCS.instance(), "retired": true})
    );
    assert_eq!(
        source_row(&pool, &fixture, &DOCS.instance()).await.0,
        "retired"
    );
    let answer = evidence_search(&evidence(&pool, &fixture).await, "retry budget").await;
    assert!(
        answer
            .sources
            .active
            .iter()
            .all(|source| source.connector_instance != DOCS.instance()),
        "a retired import is no longer a source"
    );
    assert!(
        answer.hits.iter().any(|hit| hit
            .item
            .as_ref()
            .is_some_and(|item| item.provider == "docs")),
        "its items stay recallable"
    );
    // A later tick leaves it retired; retiring again says so.
    tick(&fixture, &pool, &no_sources(), "collect").await;
    assert_eq!(
        source_row(&pool, &fixture, &DOCS.instance()).await.0,
        "retired"
    );
    let again = retire(&fixture, &pool, &DOCS.instance()).await.unwrap();
    assert_eq!(again["already_retired"], json!(true));
    assert!(retire(&fixture, &pool, "import.nothing").await.is_err());

    // Importing again re-activates it.
    import(&fixture, &pool, &DOCS, &DOCS.fixture(), false).await;
    assert_eq!(
        source_row(&pool, &fixture, &DOCS.instance()).await,
        ("active".to_owned(), "unchanged".to_owned(), true)
    );
}
