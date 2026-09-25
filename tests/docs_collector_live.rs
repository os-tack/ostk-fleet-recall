//! Connected proofs of the documents-directory collector (ADR 0008 D8): a
//! worker tick lists a scratch root, stages each changed file as sectioned
//! parts, drains them, and records the pass's coverage, so that item and
//! evidence recall read the documents back, edits supersede, deletes hide,
//! and absence is sound only over a complete enumeration.
//!
//! Every test needs `FLEET_RECALL_TEST_DATABASE_URL` and returns at once
//! without it.

mod common;

use std::path::Path;
use std::sync::Arc;

use ostk_fleet_recall::FleetScope;
use ostk_fleet_recall::collectors::binding::CollectorInstanceV1;
use ostk_fleet_recall::collectors::docs::{DocsPullV1, DocsSettingsV1};
use ostk_fleet_recall::collectors::pull::{
    PageStager, PageStagerContextV1, PullCollectorV1 as _, PullPassInputV1,
};
use ostk_fleet_recall::collectors::redaction::CollectorRedactorV1;
use ostk_fleet_recall::collectors::sink::CollectedItemSink;
use ostk_fleet_recall::evidence_recall::{
    AbsenceReasonV1, AbsenceVerdictV1, CockroachEvidenceRecall, EvidenceRecall as _,
    EvidenceSearchV1, probe_evidence_recall,
};
use ostk_fleet_recall::item_recall::{
    CockroachItemRecall, ItemGetV1, ItemRecall as _, ItemReferenceV1, ItemSearchRequestV1,
    ItemSearchV1, ItemSuppressionV1, probe_item_recall,
};
use ostk_fleet_recall::memory_contracts::collected_item::{
    ObjectKindV1, ProviderKindV1, derive_item_key, timestamp_micros,
};
use ostk_fleet_recall::memory_contracts::common::{CanonicalTimestamp, ContractId};
use ostk_fleet_recall::memory_contracts::digest::Sha256Digest;
use ostk_fleet_recall::registry_activation::install::InstallTargetV1;
use ostk_fleet_recall::store::cockroach::{CockroachStore, DatabaseCapabilities};
use ostk_fleet_recall::worker::{
    CollectorSourceV1, WorkerSourceOutcomeV1, WorkerSourceReportV1, WorkerStepV1,
    WorkerTickReportV1,
};
use serde_json::{Value, json};
use sqlx::PgPool;

use common::authority::retry_policy;
use common::worker::{RecordedCi, STUB_MODEL_DIGEST, WorkerFixture};

const INSTANCE: &str = "docs.specs";
const ROOT_ID: &str = "specs";
const MISSING: &str = "unfindable marmoset";

/// A spec with front matter and three headings: four parts.
const RETRY_DOC: &str = "---\ntitle: Retry budgets\nstatus: accepted\n---\n\
                         # Retry\nThe fleet retry budget is five attempts.\n\
                         ## Backoff\nUse a quokka jitter between attempts.\n\
                         ## Limits\nNever exceed ten attempts in a window.\n";

// ---------------------------------------------------------------------------
// Sources, ticks, and rows
// ---------------------------------------------------------------------------

fn collector(root: &Path, max_files: usize) -> Value {
    json!({
        "provider": "docs",
        "connector_principal": "principal.docs",
        "connector_instance": INSTANCE,
        "provider_scope_id": ROOT_ID,
        "audience": {"operator_declared": true},
        "settings": {
            "root": root,
            "extensions": ["md", "txt"],
            "max_file_bytes": 65_536,
            "max_files": max_files
        }
    })
}

/// A sources file with the documents collector alone.
fn sources(root: &Path, max_files: usize) -> Value {
    json!({
        "schema_version": 1,
        "coverage_since": "2026-08-01T00:00:00Z",
        "collectors": [collector(root, max_files)]
    })
}

async fn fixture_at(pool: &PgPool, label: &str) -> WorkerFixture {
    WorkerFixture::install_at(pool, label, InstallTargetV1::Generation3).await
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

/// The documents collector's report in a tick.
fn docs(report: &WorkerTickReportV1) -> &WorkerSourceReportV1 {
    report
        .step(WorkerStepV1::Collect)
        .expect("the collect step ran")
        .sources
        .iter()
        .find(|source| source.connector_instance == INSTANCE)
        .expect("the documents collector reported")
}

fn item(external_id: &str) -> Sha256Digest {
    derive_item_key(
        &ProviderKindV1::new("docs").unwrap(),
        ROOT_ID,
        &ObjectKindV1::new("document").unwrap(),
        external_id,
    )
}

async fn scalar(pool: &PgPool, fixture: &WorkerFixture, sql: &str) -> i64 {
    sqlx::query_scalar(sql)
        .bind(fixture.installed.scope.tenant_id)
        .bind(&fixture.installed.scope.project)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// Admitted parts of documents.
async fn document_parts(pool: &PgPool, fixture: &WorkerFixture) -> i64 {
    scalar(
        pool,
        fixture,
        "SELECT count(*) FROM memory_collected_items_v1 \
         WHERE tenant_id = $1 AND project = $2 AND object_kind = 'document'",
    )
    .await
}

/// Every outbox row, settled or not.
async fn outbox_rows(pool: &PgPool, fixture: &WorkerFixture) -> i64 {
    scalar(
        pool,
        fixture,
        "SELECT count(*) FROM memory_collector_outbox_v1 WHERE tenant_id = $1 AND project = $2",
    )
    .await
}

/// Parts staged and not yet admitted.
async fn pending_rows(pool: &PgPool, fixture: &WorkerFixture) -> i64 {
    scalar(
        pool,
        fixture,
        "SELECT count(*) FROM memory_collector_outbox_v1 \
         WHERE tenant_id = $1 AND project = $2 AND state = 'pending'",
    )
    .await
}

/// One document's verified head: its lifecycle and how many versions it saw.
async fn head(pool: &PgPool, fixture: &WorkerFixture, external_id: &str) -> (String, i64) {
    sqlx::query_as(
        "SELECT lifecycle, version_count FROM memory_collected_item_heads_v1 \
         WHERE tenant_id = $1 AND project = $2 AND object_kind = 'document' \
           AND external_id = $3 AND trust_tier = 'verified'",
    )
    .bind(fixture.installed.scope.tenant_id)
    .bind(&fixture.installed.scope.project)
    .bind(external_id)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn dead_letter_reasons(pool: &PgPool, fixture: &WorkerFixture) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT reason FROM memory_collector_dead_letters_v1 \
         WHERE tenant_id = $1 AND project = $2 ORDER BY reason",
    )
    .bind(fixture.installed.scope.tenant_id)
    .bind(&fixture.installed.scope.project)
    .fetch_all(pool)
    .await
    .unwrap()
}

/// The collector's status row: state, last outcome, and whether it was ever
/// checked.
async fn collector_row(pool: &PgPool, fixture: &WorkerFixture) -> (String, String, bool) {
    sqlx::query_as(
        "SELECT state, last_outcome, last_checked_at IS NOT NULL \
         FROM memory_collector_sources_v1 \
         WHERE tenant_id = $1 AND project = $2 AND collector_instance_id = $3",
    )
    .bind(fixture.installed.scope.tenant_id)
    .bind(&fixture.installed.scope.project)
    .bind(INSTANCE)
    .fetch_one(pool)
    .await
    .unwrap()
}

// ---------------------------------------------------------------------------
// Recall
// ---------------------------------------------------------------------------

async fn capabilities(pool: &PgPool, scope: &FleetScope) -> DatabaseCapabilities {
    CockroachStore::from_pool(pool.clone(), scope.clone())
        .unwrap()
        .capabilities()
        .await
        .unwrap()
}

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

async fn search(recall: &CockroachItemRecall, query: &str) -> ItemSearchV1 {
    recall
        .search(
            &ItemSearchRequestV1 {
                query: query.to_owned(),
                provider: Some(ProviderKindV1::new("docs").unwrap()),
                include_history: false,
                limit: 20,
            },
            None,
        )
        .await
        .unwrap()
}

async fn evidence_search(recall: &CockroachEvidenceRecall, query: &str) -> EvidenceSearchV1 {
    recall.search(query, None, 20).await.unwrap()
}

async fn get(recall: &CockroachItemRecall, external_id: &str) -> ItemGetV1 {
    recall
        .get(&ItemReferenceV1::Item(item(external_id)))
        .await
        .unwrap()
        .expect("the document is an item")
}

fn part_texts(got: &ItemGetV1) -> Vec<String> {
    got.current
        .parts
        .iter()
        .map(|part| part.text.clone().unwrap_or_default())
        .collect()
}

/// Absence of a word no document holds, in both kinds.
async fn absence(
    pool: &PgPool,
    fixture: &WorkerFixture,
) -> (
    (AbsenceVerdictV1, Vec<AbsenceReasonV1>),
    (AbsenceVerdictV1, Vec<AbsenceReasonV1>),
) {
    let items = search(&items(pool, fixture).await, MISSING).await;
    let evidence = evidence_search(&evidence(pool, fixture).await, MISSING).await;
    assert!(items.hits.is_empty() && evidence.hits.is_empty());
    (
        (items.absence.verdict, items.absence.reasons),
        (evidence.absence.verdict, evidence.absence.reasons),
    )
}

fn write(root: &Path, relative: &str, text: &[u8]) {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, text).unwrap();
}

// ---------------------------------------------------------------------------
// Proofs
// ---------------------------------------------------------------------------

#[tokio::test]
async fn live_docs_first_tick_admits_every_section_and_a_second_stages_nothing_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let fixture = fixture_at(&pool, "docs-first").await;
    let root = tempfile::tempdir().unwrap();
    write(root.path(), "adr/retry.md", RETRY_DOC.as_bytes());
    write(
        root.path(),
        "notes.txt",
        b"The quarterly budget review is on Tuesday.\n",
    );
    let sources = sources(root.path(), 100);

    let first = tick(&fixture, &pool, &sources, "collect,project").await;
    let report = docs(&first);
    assert_eq!(report.outcome, WorkerSourceOutcomeV1::Ok, "{report:?}");
    assert_eq!(report.counters["files_listed"], 2);
    assert_eq!(report.counters["files_staged"], 2);
    assert_eq!(report.counters["containers_complete"], 1);
    assert!(report.counters["receipts"] >= 1);

    // Every section is a part, anchored at its heading path.
    let recall = items(&pool, &fixture).await;
    let got = get(&recall, "adr/retry.md").await;
    let anchors: Vec<Option<&str>> = got
        .current
        .parts
        .iter()
        .map(|part| part.anchor.as_deref())
        .collect();
    assert_eq!(
        anchors,
        [
            None,
            Some("Retry"),
            Some("Retry > Backoff"),
            Some("Retry > Limits")
        ]
    );
    assert_eq!(
        got.current.title.as_deref(),
        Some("Retry budgets (status: accepted)")
    );
    assert!(part_texts(&got)[2].contains("quokka jitter"));
    let hits = search(&recall, "quokka").await.hits;
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].external_id, "adr/retry.md");
    assert_eq!(hits[0].part.anchor.as_deref(), Some("Retry > Backoff"));
    assert_eq!(
        search(&recall, "quarterly review").await.hits[0].external_id,
        "notes.txt"
    );

    // A complete enumeration proves a missing word absent, in both kinds.
    assert_eq!(
        absence(&pool, &fixture).await,
        (
            (AbsenceVerdictV1::Absent, Vec::new()),
            (AbsenceVerdictV1::Absent, Vec::new())
        )
    );
    assert_eq!(
        collector_row(&pool, &fixture).await,
        ("active".to_owned(), "ok".to_owned(), true)
    );

    // An unchanged root stages nothing, and still reconciles.
    let (parts, rows) = (
        document_parts(&pool, &fixture).await,
        outbox_rows(&pool, &fixture).await,
    );
    let second = tick(&fixture, &pool, &sources, "collect,project").await;
    let report = docs(&second);
    assert_eq!(
        report.outcome,
        WorkerSourceOutcomeV1::Unchanged,
        "{report:?}"
    );
    assert_eq!(report.counters["rows_staged"], 0);
    assert_eq!(report.counters["files_unchanged"], 2);
    assert_eq!(report.counters["files_staged"], 0);
    assert_eq!(document_parts(&pool, &fixture).await, parts);
    assert_eq!(
        outbox_rows(&pool, &fixture).await,
        rows,
        "nothing was staged"
    );
    assert_eq!(
        collector_row(&pool, &fixture).await,
        ("active".to_owned(), "unchanged".to_owned(), true)
    );
    assert_eq!(absence(&pool, &fixture).await.0.0, AbsenceVerdictV1::Absent);
}

#[tokio::test]
async fn live_docs_an_edit_moves_every_part_and_a_revert_is_a_third_version_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let fixture = fixture_at(&pool, "docs-edit").await;
    let root = tempfile::tempdir().unwrap();
    let text = |budget: &str| {
        format!("# Policy\nThe budget is {budget}.\n## Scope\nApplies to the albatross fleet.\n")
    };
    let sources = sources(root.path(), 100);

    write(root.path(), "policy.md", text("three").as_bytes());
    tick(&fixture, &pool, &sources, "collect,project").await;
    let recall = items(&pool, &fixture).await;
    let first = get(&recall, "policy.md").await;
    assert_eq!(first.current.parts.len(), 2);

    // Editing one section is a new version of the whole document: every part
    // of the presented head is the new version's.
    write(root.path(), "policy.md", text("five").as_bytes());
    let report = tick(&fixture, &pool, &sources, "collect,project").await;
    assert_eq!(docs(&report).counters["files_staged"], 1);
    let edited = get(&recall, "policy.md").await;
    assert_ne!(edited.current.version_id, first.current.version_id);
    assert_eq!(edited.current.parts.len(), 2);
    for (now, before) in edited.current.parts.iter().zip(&first.current.parts) {
        assert_ne!(now.accepted_event_id, before.accepted_event_id);
        assert_ne!(now.uri, before.uri);
    }
    assert!(part_texts(&edited)[0].contains("five"));
    assert_eq!(edited.history.len(), 1);
    assert_eq!(edited.history[0].version_id, first.current.version_id);
    assert!(search(&recall, "budget five").await.hits.len() == 1);

    // Back to the first content: a third version, presented, with A's text.
    write(root.path(), "policy.md", text("three").as_bytes());
    tick(&fixture, &pool, &sources, "collect,project").await;
    let reverted = get(&recall, "policy.md").await;
    assert_ne!(reverted.current.version_id, first.current.version_id);
    assert_ne!(reverted.current.version_id, edited.current.version_id);
    assert!(part_texts(&reverted)[0].contains("three"));
    assert_eq!(reverted.history.len(), 2);
    assert_eq!(
        head(&pool, &fixture, "policy.md").await,
        ("live".to_owned(), 3)
    );
}

#[tokio::test]
async fn live_docs_a_deleted_file_is_tombstoned_and_hidden_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let fixture = fixture_at(&pool, "docs-delete").await;
    let root = tempfile::tempdir().unwrap();
    let sources = sources(root.path(), 100);
    write(root.path(), "keep.md", b"# Keep\nThe heron stays.\n");
    write(root.path(), "gone.md", b"# Gone\nThe pelican leaves.\n");
    tick(&fixture, &pool, &sources, "collect,project").await;
    let (recall, evidence) = (
        items(&pool, &fixture).await,
        evidence(&pool, &fixture).await,
    );
    assert_eq!(search(&recall, "pelican").await.hits.len(), 1);
    assert!(!evidence_search(&evidence, "pelican").await.hits.is_empty());

    std::fs::remove_file(root.path().join("gone.md")).unwrap();
    let report = tick(&fixture, &pool, &sources, "collect,project").await;
    assert_eq!(docs(&report).counters["files_deleted"], 1);
    assert_eq!(
        head(&pool, &fixture, "gone.md").await,
        ("deleted".to_owned(), 2)
    );
    assert!(search(&recall, "pelican").await.hits.is_empty());
    assert!(evidence_search(&evidence, "pelican").await.hits.is_empty());
    let gone = get(&recall, "gone.md").await;
    assert_eq!(gone.suppressed, Some(ItemSuppressionV1::Deleted));
    assert!(part_texts(&gone).iter().all(String::is_empty));
    assert_eq!(search(&recall, "heron").await.hits.len(), 1);
    assert_eq!(absence(&pool, &fixture).await.0.0, AbsenceVerdictV1::Absent);
}

#[tokio::test]
async fn live_docs_an_escaping_symlink_is_ignored_and_a_non_utf8_file_leaves_coverage_partial_when_configured()
 {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let fixture = fixture_at(&pool, "docs-escape").await;
    let outside = tempfile::tempdir().unwrap();
    write(
        outside.path(),
        "secret.md",
        b"# Secret\nThe cassowary plan.\n",
    );
    let root = tempfile::tempdir().unwrap();
    write(root.path(), "good.md", b"# Good\nThe kestrel note.\n");
    write(root.path(), "bad.md", &[b'#', b' ', 0xff, 0xfe, b'\n']);
    std::os::unix::fs::symlink(
        outside.path().join("secret.md"),
        root.path().join("escape.md"),
    )
    .unwrap();
    let sources = sources(root.path(), 100);

    let report = tick(&fixture, &pool, &sources, "collect,project").await;
    let report = docs(&report);
    assert_eq!(report.outcome, WorkerSourceOutcomeV1::Ok, "{report:?}");
    assert_eq!(report.counters["symlinks_skipped"], 1);
    assert_eq!(report.counters["files_dead_lettered"], 1);
    assert_eq!(report.counters["files_staged"], 1);
    assert_eq!(report.counters["containers_complete"], 0);

    let recall = items(&pool, &fixture).await;
    assert!(search(&recall, "cassowary").await.hits.is_empty());
    assert!(
        evidence_search(&evidence(&pool, &fixture).await, "cassowary")
            .await
            .hits
            .is_empty()
    );
    assert_eq!(search(&recall, "kestrel").await.hits.len(), 1);
    assert_eq!(dead_letter_reasons(&pool, &fixture).await, ["parse_failed"]);

    // The root was read, but not all of it was admitted: absence is unknown.
    let ((items_verdict, items_reasons), (evidence_verdict, evidence_reasons)) =
        absence(&pool, &fixture).await;
    assert_eq!(items_verdict, AbsenceVerdictV1::Unknown);
    assert_eq!(items_reasons, [AbsenceReasonV1::IncompleteCoverage]);
    assert_eq!(evidence_verdict, AbsenceVerdictV1::Unknown);
    assert_eq!(evidence_reasons, [AbsenceReasonV1::IncompleteCoverage]);

    // The same refusal on the next pass is the same dead letter.
    tick(&fixture, &pool, &sources, "collect,project").await;
    assert_eq!(dead_letter_reasons(&pool, &fixture).await, ["parse_failed"]);
}

#[tokio::test]
async fn live_docs_a_truncated_listing_is_partial_and_tombstones_nothing_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let fixture = fixture_at(&pool, "docs-truncated").await;
    let root = tempfile::tempdir().unwrap();
    write(root.path(), "a.md", b"# A\nThe alpha osprey.\n");
    write(root.path(), "b.md", b"# B\nThe beta osprey.\n");
    write(root.path(), "c.md", b"# C\nThe gamma puffin.\n");

    tick(&fixture, &pool, &sources(root.path(), 3), "collect,project").await;
    assert_eq!(absence(&pool, &fixture).await.0.0, AbsenceVerdictV1::Absent);

    // The same root under a lower bound: the listing stops before c.md,
    // which is therefore neither read nor tombstoned.
    let report = tick(&fixture, &pool, &sources(root.path(), 2), "collect,project").await;
    let report = docs(&report);
    assert_eq!(report.counters["listing_truncated"], 1);
    assert_eq!(report.counters["files_deleted"], 0);
    assert_eq!(report.counters["containers_complete"], 0);
    assert_eq!(head(&pool, &fixture, "c.md").await.0, "live");
    assert_eq!(
        search(&items(&pool, &fixture).await, "puffin")
            .await
            .hits
            .len(),
        1
    );
    let ((items_verdict, items_reasons), (evidence_verdict, evidence_reasons)) =
        absence(&pool, &fixture).await;
    assert_eq!(items_verdict, AbsenceVerdictV1::Unknown);
    assert_eq!(items_reasons, [AbsenceReasonV1::IncompleteCoverage]);
    assert_eq!(evidence_verdict, AbsenceVerdictV1::Unknown);
    assert_eq!(evidence_reasons, [AbsenceReasonV1::IncompleteCoverage]);
}

#[tokio::test]
async fn live_docs_a_removed_collector_is_retired_and_the_worker_rows_stay_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let fixture = fixture_at(&pool, "docs-retire").await;
    let root = tempfile::tempdir().unwrap();
    write(root.path(), "doc.md", b"# Doc\nThe grebe ledger.\n");
    let mut with_docs = fixture.sources_json();
    with_docs["collectors"] = json!([collector(root.path(), 100)]);
    tick(&fixture, &pool, &with_docs, "all").await;
    assert_eq!(collector_row(&pool, &fixture).await.0, "active");

    // A narrower tick never retires, whatever its sources file says.
    let without = fixture.sources_json();
    let narrow = tick(&fixture, &pool, &without, "collect").await;
    assert_eq!(
        narrow.step(WorkerStepV1::Collect).unwrap().counters["collectors_retired"],
        0
    );
    assert_eq!(collector_row(&pool, &fixture).await.0, "active");

    // A complete tick without the collector retires its row, and only it.
    let complete = tick(&fixture, &pool, &without, "all").await;
    assert_eq!(
        complete.step(WorkerStepV1::Collect).unwrap().counters["collectors_retired"],
        1
    );
    assert_eq!(collector_row(&pool, &fixture).await.0, "retired");
    let worker_rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT connector_instance_id, state FROM memory_worker_sources_v1 \
         WHERE tenant_id = $1 AND project = $2 ORDER BY connector_instance_id",
    )
    .bind(fixture.installed.scope.tenant_id)
    .bind(&fixture.installed.scope.project)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(worker_rows.len(), 4, "{worker_rows:?}");
    assert!(
        worker_rows.iter().all(|(_, state)| state == "active"),
        "{worker_rows:?}"
    );
    let listed = evidence_search(&evidence(&pool, &fixture).await, "grebe").await;
    assert!(
        listed
            .sources
            .active
            .iter()
            .all(|source| source.connector_instance != INSTANCE),
        "a retired collector is no longer a source"
    );
}

#[tokio::test]
async fn live_docs_a_killed_tick_resumes_without_duplicate_events_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let fixture = fixture_at(&pool, "docs-resume").await;
    let root = tempfile::tempdir().unwrap();
    write(root.path(), "adr/retry.md", RETRY_DOC.as_bytes());
    write(root.path(), "plain.txt", b"A plain note about the loon.\n");
    let sources = sources(root.path(), 100);

    // A pass that staged its pages and was killed before its drain.
    let source: CollectorSourceV1 = serde_json::from_value(collector(root.path(), 100)).unwrap();
    let instance = CollectorInstanceV1 {
        connector_instance_id: source.connector_instance.clone(),
        provider: source.provider.clone(),
        provider_scope_id: source.provider_scope_id.clone(),
    };
    let verified = fixture
        .installed
        .runtime(&pool)
        .await
        .verify()
        .await
        .expect("the installed head verifies");
    let active = verified
        .bind_connector(&ContractId::new("connector.collected.pull").unwrap())
        .expect("generation 3 carries the pull connector");
    let redactor = CollectorRedactorV1::from_active_package(&active).unwrap();
    let sink =
        CollectedItemSink::new(pool.clone(), &fixture.installed.scope, retry_policy()).unwrap();
    let instant = CanonicalTimestamp::parse("2026-09-01T00:00:00.000000000Z").unwrap();
    let order = timestamp_micros(&instant).unwrap();
    let mut stager = PageStager::new(
        &sink,
        &PageStagerContextV1 {
            instance: &instance,
            principal: &source.connector_principal,
            redactor: &redactor,
            policy: &source.audience,
            pass_seq: 1,
            pass_order_micros: order,
        },
    )
    .unwrap();
    DocsPullV1::new(DocsSettingsV1::from_source(&source).unwrap())
        .pass(
            &PullPassInputV1 {
                source: &source,
                instance: &instance,
                pass_seq: 1,
                pass_instant: &instant,
                pass_order_micros: order,
            },
            &mut stager,
        )
        .await
        .expect("the pass stages its pages");
    assert_eq!(pending_rows(&pool, &fixture).await, 5);
    assert_eq!(document_parts(&pool, &fixture).await, 0);

    // The next tick relies on what the killed pass staged: it stages nothing
    // new and admits each part once.
    let report = tick(&fixture, &pool, &sources, "collect,project").await;
    let report = docs(&report);
    assert_eq!(report.counters["rows_staged"], 0, "{report:?}");
    assert_eq!(report.counters["files_unchanged"], 2);
    assert_eq!(report.counters["appended"], 5);
    assert_eq!(report.counters["containers_complete"], 1);
    assert_eq!(pending_rows(&pool, &fixture).await, 0);
    assert_eq!(document_parts(&pool, &fixture).await, 5);
    for external_id in ["adr/retry.md", "plain.txt"] {
        assert_eq!(
            head(&pool, &fixture, external_id).await,
            ("live".to_owned(), 1)
        );
    }
    let again = tick(&fixture, &pool, &sources, "collect,project").await;
    assert_eq!(docs(&again).outcome, WorkerSourceOutcomeV1::Unchanged);
    assert_eq!(document_parts(&pool, &fixture).await, 5);
    assert_eq!(
        get(&items(&pool, &fixture).await, "plain.txt")
            .await
            .current
            .parts
            .len(),
        1
    );
}
