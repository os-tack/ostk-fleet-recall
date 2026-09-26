//! Connected proofs of the Granola collector (ADR 0008 D8): a worker tick
//! pulls a fake Granola account through the public API's `notes`,
//! `notes/{id}`, and `notes/{id}/transcript`, served by a local fake provider,
//! and item and evidence recall read the notes back. Each note in a listed
//! folder becomes its AI summary and, when transcripts are read, its
//! transcript; a `413` pages the transcript; an updated note is a new version
//! that an incremental pass picks up without writing coverage; a single `404`
//! tombstones nothing while two complete listings without the note do; a note
//! that leaves the listed folders is withdrawn, and lifted when it returns; a
//! rate limit leaves the pass partial and the next one resumes after the last
//! note it settled; without transcripts no segment is staged; the key, the
//! private notes, and the attendees are found in no table.
//!
//! Every connected test needs `FLEET_RECALL_TEST_DATABASE_URL` and returns at
//! once without it. No test reaches Granola.

mod common;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, SecondsFormat, Utc};
use ostk_fleet_recall::FleetScope;
use ostk_fleet_recall::evidence_recall::{
    AbsenceReasonV1, AbsenceVerdictV1, CockroachEvidenceRecall, EvidenceRecall as _,
    EvidenceSearchV1, probe_evidence_recall,
};
use ostk_fleet_recall::item_recall::{
    CockroachItemRecall, ItemGetV1, ItemRecall as _, ItemReferenceV1, ItemSearchRequestV1,
    ItemSearchV1, ItemSuppressionV1, probe_item_recall,
};
use ostk_fleet_recall::memory_contracts::collected_item::{
    ObjectKindV1, ProviderKindV1, derive_item_key,
};
use ostk_fleet_recall::memory_contracts::digest::Sha256Digest;
use ostk_fleet_recall::registry_activation::install::InstallTargetV1;
use ostk_fleet_recall::store::cockroach::{CockroachStore, DatabaseCapabilities};
use ostk_fleet_recall::worker::{
    WorkerSourceOutcomeV1, WorkerSourceReportV1, WorkerSourcesV1, WorkerStepV1, WorkerTickReportV1,
};
use serde_json::{Value, json};
use sqlx::PgPool;

use common::fake_provider::{FakeProvider, FakeReply, FakeRequest};
use common::worker::{RecordedCi, STUB_MODEL_DIGEST, WorkerFixture};

const INSTANCE: &str = "granola.acme";
const SCOPE: &str = "workspace.acme-robotics";
const PLATFORM: &str = "fol_4y6LduVdwSKC27";
const PEOPLE: &str = "fol_9pEopLeFoLdEr1";
const TOKEN_ENV: &str = "FLEET_RECALL_GRANOLA_TEST_API_KEY";
const MISSING: &str = "unfindable marmoset";

/// The API key the fake expects: an obvious placeholder, never a real
/// credential, that still has the `grn_` shape the redactor catches anywhere
/// it leaks into text.
const API_KEY: &str = "grn_EXAMPLE_NOT_A_KEY";

/// Planted in every note's private notes, which the collector never reads.
const PRIVATE_MARKER: &str = "PRIVATE-NOTES-MARKER-never-collected";

/// An attendee's address, which the collector never reads.
const ATTENDEE: &str = "dana.attendee@acme-robotics.example";

// ---------------------------------------------------------------------------
// The fake account
// ---------------------------------------------------------------------------

/// Whole seconds three days ago: every note is behind the database's clock.
fn base_seconds() -> i64 {
    Utc::now().timestamp() - 3 * 86_400
}

/// A Granola timestamp `offset` seconds (and as many milliseconds) after
/// `base`.
fn at(base: i64, offset: i64) -> String {
    DateTime::<Utc>::from_timestamp(base + offset, u32::try_from(offset).unwrap() * 1_000_000)
        .unwrap()
        .to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn instant(value: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(value)
        .unwrap()
        .with_timezone(&Utc)
}

fn note_id(index: u32) -> String {
    format!("not_{index:014}")
}

#[derive(Debug, Clone)]
struct Note {
    title: String,
    created_at: String,
    updated_at: String,
    folders: Vec<(String, String)>,
    summary: String,
    /// `(start offset in seconds, speaker, text)`.
    segments: Vec<(i64, String, String)>,
    /// A transcript too large to come with the note: `413`.
    too_large: bool,
    /// Listed, but `404` for the key.
    not_found: bool,
}

#[derive(Debug, Clone)]
struct World {
    base: i64,
    notes: BTreeMap<String, Note>,
}

impl World {
    const fn new(base: i64) -> Self {
        Self {
            base,
            notes: BTreeMap::new(),
        }
    }

    fn note(&mut self, index: u32, folder: &str, title: &str, summary: &str, updated: i64) {
        let name = if folder == PLATFORM {
            "Platform"
        } else {
            "People"
        };
        self.notes.insert(
            note_id(index),
            Note {
                title: title.to_owned(),
                created_at: at(self.base, updated),
                updated_at: at(self.base, updated),
                folders: vec![(folder.to_owned(), name.to_owned())],
                summary: summary.to_owned(),
                segments: Vec::new(),
                too_large: false,
                not_found: false,
            },
        );
    }

    fn segments(&mut self, index: u32, segments: &[(i64, &str, &str)]) {
        self.note_mut(index).segments = segments
            .iter()
            .map(|(offset, speaker, text)| (*offset, (*speaker).to_owned(), (*text).to_owned()))
            .collect();
    }

    fn note_mut(&mut self, index: u32) -> &mut Note {
        self.notes.get_mut(&note_id(index)).unwrap()
    }
}

fn segment_json(base: i64, (offset, speaker, text): &(i64, String, String)) -> Value {
    let mut speaker_json = json!({"source": "speaker", "attribution": "them"});
    if speaker == "me" {
        speaker_json = json!({"source": "microphone", "attribution": "me", "name": "Carol Diaz"});
    } else if !speaker.is_empty() {
        speaker_json["diarization_label"] = json!(speaker);
    }
    json!({
        "speaker": speaker_json,
        "text": text,
        "start_time": at(base, *offset),
        "end_time": at(base, *offset + 3),
    })
}

fn note_json(base: i64, id: &str, note: &Note, transcript: bool) -> Value {
    json!({
        "id": id,
        "object": "note",
        "title": note.title,
        "owner": {"name": "Carol Diaz", "email": "carol@acme-robotics.example"},
        "created_at": note.created_at,
        "updated_at": note.updated_at,
        "web_url": format!("https://notes.granola.ai/d/{id}"),
        "calendar_event": {
            "event_title": note.title,
            "invitees": [{"email": ATTENDEE}],
            "organiser": "carol@acme-robotics.example",
            "calendar_event_id": format!("cal{id}"),
            "scheduled_start_time": note.created_at,
            "scheduled_end_time": note.updated_at
        },
        "attendees": [{"name": "Dana Attendee", "email": ATTENDEE}],
        "folder_membership": note.folders.iter().map(|(folder, name)| json!({
            "id": folder, "object": "folder", "name": name, "parent_folder_id": null
        })).collect::<Vec<_>>(),
        "summary_text": note.summary.replace(['#', '*'], ""),
        "summary_markdown": note.summary,
        "private_notes_text": PRIVATE_MARKER,
        "private_notes_markdown": format!("**{PRIVATE_MARKER}**"),
        "transcript": if transcript {
            Value::Array(note.segments.iter().map(|segment| segment_json(base, segment)).collect())
        } else {
            Value::Null
        }
    })
}

/// The public API over `world`.
fn respond(world: &World, request: &FakeRequest) -> FakeReply {
    if request.method != "GET" {
        return FakeReply::status(405, "GET only");
    }
    let path = request.path.as_str();
    if path == "/v1/notes" {
        let mut notes: Vec<(&String, &Note)> = world
            .notes
            .iter()
            .filter(|(_, note)| {
                request
                    .param("updated_after")
                    .is_none_or(|after| instant(&note.updated_at) > instant(after))
            })
            .collect();
        // Newest created first, as a listing would.
        notes.sort_by(|left, right| {
            instant(&right.1.created_at)
                .cmp(&instant(&left.1.created_at))
                .then_with(|| left.0.cmp(right.0))
        });
        let size: usize = request
            .param("page_size")
            .and_then(|size| size.parse().ok())
            .unwrap_or(10);
        let start: usize = request
            .param("cursor")
            .and_then(|cursor| cursor.strip_prefix("offset:"))
            .and_then(|offset| offset.parse().ok())
            .unwrap_or(0);
        let end = (start + size).min(notes.len());
        let page: Vec<Value> = notes[start.min(end)..end]
            .iter()
            .map(|(id, note)| {
                json!({"id": id, "object": "note", "title": note.title,
                       "owner": {"name": "Carol Diaz", "email": "carol@acme-robotics.example"},
                       "created_at": note.created_at, "updated_at": note.updated_at})
            })
            .collect();
        let more = end < notes.len();
        return FakeReply::json(&json!({
            "notes": page,
            "hasMore": more,
            "cursor": if more { Value::from(format!("offset:{end}")) } else { Value::Null }
        }));
    }
    let Some(rest) = path.strip_prefix("/v1/notes/") else {
        return FakeReply::status(404, "no such route");
    };
    let (id, transcript_page) = rest
        .strip_suffix("/transcript")
        .map_or((rest, false), |id| (id, true));
    let Some(note) = world.notes.get(id).filter(|note| !note.not_found) else {
        return FakeReply::status(404, r#"{"error":"not_found"}"#);
    };
    if transcript_page {
        let start: usize = request
            .param("cursor")
            .and_then(|cursor| cursor.strip_prefix("seg:"))
            .and_then(|offset| offset.parse().ok())
            .unwrap_or(0);
        let end = (start + 2).min(note.segments.len());
        let more = end < note.segments.len();
        return FakeReply::json(&json!({
            "transcript": note.segments[start.min(end)..end]
                .iter()
                .map(|segment| segment_json(world.base, segment))
                .collect::<Vec<_>>(),
            "hasMore": more,
            "cursor": if more { Value::from(format!("seg:{end}")) } else { Value::Null }
        }));
    }
    let include = request.param("include") == Some("transcript");
    if include && note.too_large {
        return FakeReply::status(413, r#"{"error":"TRANSCRIPT_TOO_LARGE"}"#);
    }
    FakeReply::json(&note_json(world.base, id, note, include))
}

// ---------------------------------------------------------------------------
// The harness
// ---------------------------------------------------------------------------

struct Harness {
    pool: PgPool,
    fixture: WorkerFixture,
    world: Arc<Mutex<World>>,
    fake: FakeProvider,
}

impl Harness {
    async fn new(label: &str, world: World) -> Option<Self> {
        let database_url = common::test_database_url()?;
        let pool = common::migrated_pool(&database_url).await;
        let fixture = WorkerFixture::install_at(&pool, label, InstallTargetV1::Generation3).await;
        let world = Arc::new(Mutex::new(world));
        let served = Arc::clone(&world);
        let fake =
            FakeProvider::start(move |request| respond(&served.lock().unwrap(), request)).await;
        Some(Self {
            pool,
            fixture,
            world,
            fake,
        })
    }

    fn world(&self) -> std::sync::MutexGuard<'_, World> {
        self.world.lock().unwrap()
    }

    /// Change one note of the fake account.
    fn edit(&self, index: u32, change: impl FnOnce(&mut Note)) {
        change(self.world().note_mut(index));
    }

    fn sources(&self, extra: &Value) -> Value {
        let mut settings = json!({
            "token_env": TOKEN_ENV,
            "folders": [PLATFORM],
            "include_transcript": true,
            "page_size": 2,
            "api_base": format!("{}/v1", self.fake.base)
        });
        settings
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        json!({
            "schema_version": 1,
            "coverage_since": "2026-08-01T00:00:00Z",
            "collectors": [{
                "provider": "granola",
                "connector_principal": "principal.granola",
                "connector_instance": INSTANCE,
                "provider_scope_id": SCOPE,
                "audience": {"operator_declared": true},
                "settings": settings
            }]
        })
    }

    async fn tick(&self, sources: &Value) -> WorkerTickReportV1 {
        self.fixture
            .worker_with(&self.pool, "collect,project", sources, Arc::new(RecordedCi))
            .await
            .with_collector_environment(Arc::new(move |name: &str| {
                (name == TOKEN_ENV).then(|| API_KEY.to_owned())
            }))
            .run_tick()
            .await
    }

    async fn ok_tick(&self, sources: &Value) -> WorkerTickReportV1 {
        let report = self.tick(sources).await;
        assert!(
            !report.failed(),
            "the tick must succeed: {}",
            serde_json::to_string_pretty(&report).unwrap()
        );
        report
    }

    fn source(report: &WorkerTickReportV1) -> &WorkerSourceReportV1 {
        report
            .step(WorkerStepV1::Collect)
            .expect("the collect step ran")
            .sources
            .iter()
            .find(|source| source.connector_instance == INSTANCE)
            .expect("the Granola collector reported")
    }

    /// Every request to a path ending in `suffix`.
    fn calls(&self, suffix: &str) -> Vec<FakeRequest> {
        self.fake
            .requests()
            .into_iter()
            .filter(|request| request.path.ends_with(suffix))
            .collect()
    }

    /// Let the next pass reconcile, as if `reconcile_every_seconds` had
    /// passed: forget when the last reconciliation ran.
    async fn reconcile_due(&self) {
        sqlx::query(
            "DELETE FROM memory_collector_cursors_v1 \
             WHERE tenant_id = $1 AND project = $2 AND collector_instance_id = $3 \
               AND domain_key = 'granola.reconcile'",
        )
        .bind(self.fixture.installed.scope.tenant_id)
        .bind(&self.fixture.installed.scope.project)
        .bind(INSTANCE)
        .execute(&self.pool)
        .await
        .unwrap();
    }

    async fn scalar(&self, sql: &str) -> i64 {
        sqlx::query_scalar(sql)
            .bind(self.fixture.installed.scope.tenant_id)
            .bind(&self.fixture.installed.scope.project)
            .bind(INSTANCE)
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }

    async fn receipts(&self) -> i64 {
        self.scalar(
            "SELECT count(*) FROM memory_coverage_receipts_v1 \
             WHERE tenant_id = $1 AND project = $2 AND connector_instance_id = $3",
        )
        .await
    }

    async fn last_checked_at(&self) -> Option<DateTime<Utc>> {
        sqlx::query_scalar(
            "SELECT last_checked_at FROM memory_collector_sources_v1 \
             WHERE tenant_id = $1 AND project = $2 AND collector_instance_id = $3",
        )
        .bind(self.fixture.installed.scope.tenant_id)
        .bind(&self.fixture.installed.scope.project)
        .bind(INSTANCE)
        .fetch_one(&self.pool)
        .await
        .unwrap()
    }

    /// An item's verified head: its lifecycle and how many versions it saw.
    async fn head(&self, object_kind: &str, external_id: &str) -> (String, i64) {
        sqlx::query_as(
            "SELECT lifecycle, version_count FROM memory_collected_item_heads_v1 \
             WHERE tenant_id = $1 AND project = $2 AND provider = 'granola' \
               AND object_kind = $3 AND external_id = $4 AND trust_tier = 'verified'",
        )
        .bind(self.fixture.installed.scope.tenant_id)
        .bind(&self.fixture.installed.scope.project)
        .bind(object_kind)
        .bind(external_id)
        .fetch_one(&self.pool)
        .await
        .unwrap()
    }

    async fn heads_of(&self, object_kind: &str) -> i64 {
        sqlx::query_scalar(
            "SELECT count(*) FROM memory_collected_item_heads_v1 \
             WHERE tenant_id = $1 AND project = $2 AND provider = 'granola' \
               AND object_kind = $3",
        )
        .bind(self.fixture.installed.scope.tenant_id)
        .bind(&self.fixture.installed.scope.project)
        .bind(object_kind)
        .fetch_one(&self.pool)
        .await
        .unwrap()
    }

    async fn items(&self) -> CockroachItemRecall {
        let scope = &self.fixture.installed.scope;
        let capability = probe_item_recall(
            &self.pool,
            &capabilities(&self.pool, scope).await,
            scope,
            Sha256Digest::from_bytes(STUB_MODEL_DIGEST),
        )
        .await
        .expect("the probe runs")
        .expect("the owner may read every item-recall table");
        CockroachItemRecall::new(capability, self.pool.clone())
    }

    async fn search(&self, query: &str) -> ItemSearchV1 {
        self.items()
            .await
            .search(
                &ItemSearchRequestV1 {
                    query: query.to_owned(),
                    provider: Some(ProviderKindV1::new("granola").unwrap()),
                    include_history: false,
                    limit: 20,
                },
                None,
            )
            .await
            .unwrap()
    }

    async fn evidence(&self, query: &str) -> EvidenceSearchV1 {
        let scope = &self.fixture.installed.scope;
        let capability = probe_evidence_recall(
            &self.pool,
            &capabilities(&self.pool, scope).await,
            scope,
            Sha256Digest::from_bytes(STUB_MODEL_DIGEST),
        )
        .await
        .expect("the probe runs")
        .expect("the owner may read every evidence table");
        CockroachEvidenceRecall::new(capability, self.pool.clone())
            .search(query, None, 20)
            .await
            .unwrap()
    }

    async fn get(&self, object_kind: &str, external_id: &str) -> ItemGetV1 {
        let item = derive_item_key(
            &ProviderKindV1::new("granola").unwrap(),
            SCOPE,
            &ObjectKindV1::new(object_kind).unwrap(),
            external_id,
        );
        self.items()
            .await
            .get(&ItemReferenceV1::Item(item))
            .await
            .unwrap()
            .expect("the summary or transcript is an item")
    }
}

async fn capabilities(pool: &PgPool, scope: &FleetScope) -> DatabaseCapabilities {
    CockroachStore::from_pool(pool.clone(), scope.clone())
        .unwrap()
        .capabilities()
        .await
        .unwrap()
}

/// Every hit as `(object kind, external id)`.
fn hits(search: &ItemSearchV1) -> Vec<(String, String)> {
    search
        .hits
        .iter()
        .map(|hit| (hit.object_kind.clone(), hit.external_id.clone()))
        .collect()
}

fn summary_hit(index: u32) -> (String, String) {
    ("note_summary".to_owned(), note_id(index))
}

fn transcript_hit(index: u32) -> (String, String) {
    ("transcript".to_owned(), note_id(index))
}

fn part_text(got: &ItemGetV1) -> String {
    got.current
        .parts
        .iter()
        .map(|part| part.text.clone().unwrap_or_default())
        .collect()
}

/// Every row of every table scoped by `(tenant_id, project)` as JSON text.
async fn scoped_rows(pool: &PgPool, fixture: &WorkerFixture) -> Vec<(String, String)> {
    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT tenant.table_name FROM information_schema.columns AS tenant \
         JOIN information_schema.columns AS project \
           ON project.table_schema = tenant.table_schema \
          AND project.table_name = tenant.table_name AND project.column_name = 'project' \
         JOIN information_schema.tables AS kind \
           ON kind.table_schema = tenant.table_schema AND kind.table_name = tenant.table_name \
          AND kind.table_type = 'BASE TABLE' \
         WHERE tenant.table_schema = 'public' AND tenant.column_name = 'tenant_id' \
           AND tenant.data_type = 'uuid' \
         ORDER BY 1",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    assert!(tables.len() > 20, "{tables:?}");
    let mut rows = Vec::new();
    for table in tables {
        let texts: Vec<String> = sqlx::query_scalar(&format!(
            "SELECT row_to_json(t)::STRING FROM public.{table} AS t \
             WHERE t.tenant_id = $1 AND t.project = $2"
        ))
        .bind(fixture.installed.scope.tenant_id)
        .bind(&fixture.installed.scope.project)
        .fetch_all(pool)
        .await
        .unwrap();
        rows.extend(texts.into_iter().map(|text| (table.clone(), text)));
    }
    rows
}

/// `needle` is in no row, as text, as hex, or as the hex of hex (an
/// envelope's text inside a stored envelope's bytes).
async fn assert_nowhere(pool: &PgPool, fixture: &WorkerFixture, needle: &str) {
    let once = hex::encode(needle);
    let twice = hex::encode(&once);
    let rows = scoped_rows(pool, fixture).await;
    assert!(!rows.is_empty());
    for (table, row) in rows {
        let lowered = row.to_ascii_lowercase();
        assert!(
            !row.contains(needle)
                && !lowered.contains(&needle.to_ascii_lowercase())
                && !lowered.contains(&once)
                && !lowered.contains(&twice),
            "{needle} is in a row of {table}"
        );
    }
}

// ---------------------------------------------------------------------------
// The pull collector
// ---------------------------------------------------------------------------

/// Two notes in the listed Platform folder, one with a transcript, and one in
/// the People folder, which is not listed.
fn meetings_world(base: i64) -> World {
    let mut world = World::new(base);
    world.note(
        1,
        PLATFORM,
        "Ingest reliability sync",
        "### Decisions\n- The quokka retry budget is **5** attempts, full jitter",
        10,
    );
    world.segments(
        1,
        &[
            (
                2,
                "me",
                "Okay, the platypus budget. Alice, you wanted five?",
            ),
            (6, "", "Five with jitter, three was too aggressive."),
            (12, "Speaker B", "I'm worried about p99, but fine for now."),
        ],
    );
    world.note(
        2,
        PLATFORM,
        "Heron rollout review",
        "The heron rollout moves to Tuesday.",
        20,
    );
    world.note(
        3,
        PEOPLE,
        "Compensation review",
        "The kestrel compensation bands are confidential.",
        30,
    );
    world
}

#[tokio::test]
async fn live_granola_each_listed_note_is_a_summary_and_a_transcript_and_a_reconciliation_is_complete_when_configured()
 {
    let base = base_seconds();
    let Some(harness) = Harness::new("granola-notes", meetings_world(base)).await else {
        return;
    };
    let sources = harness.sources(&json!({}));
    let report = harness.ok_tick(&sources).await;
    let source = Harness::source(&report);
    assert_eq!(source.outcome, WorkerSourceOutcomeV1::Ok, "{source:?}");
    assert_eq!(source.counters["reconcile"], 1);
    assert_eq!(source.counters["notes_listed"], 3);
    assert_eq!(harness.calls("/v1/notes").len(), 2, "two pages of two");
    assert_eq!(source.counters["notes_fetched"], 3);
    assert_eq!(source.counters["summaries_staged"], 2);
    assert_eq!(source.counters["transcripts_staged"], 1);
    assert_eq!(source.counters["notes_outside_folders"], 1);
    assert_eq!(source.counters["containers"], 1);
    assert_eq!(source.counters["containers_complete"], 1);
    assert!(source.counters["receipts"] >= 1);

    assert_eq!(hits(&harness.search("quokka").await), [summary_hit(1)]);
    assert_eq!(hits(&harness.search("platypus").await), [transcript_hit(1)]);
    assert_eq!(hits(&harness.search("heron").await), [summary_hit(2)]);
    assert!(
        harness.search("kestrel").await.hits.is_empty(),
        "a note outside the listed folders is never staged"
    );
    assert!(harness.evidence("kestrel").await.hits.is_empty());
    assert!(!harness.evidence("platypus").await.hits.is_empty());

    let summary = harness.get("note_summary", &note_id(1)).await;
    assert_eq!(
        summary.current.title.as_deref(),
        Some("Ingest reliability sync")
    );
    let author = summary.current.author.as_ref().unwrap();
    assert_eq!(
        (author.id.as_str(), author.kind.as_str()),
        ("carol@acme-robotics.example", "ai_summary")
    );
    assert_eq!(
        summary.item.container.as_ref().unwrap().label.as_deref(),
        Some("Platform")
    );
    assert_eq!(
        summary.item.provider_url.as_deref(),
        Some(format!("https://notes.granola.ai/d/{}", note_id(1)).as_str())
    );
    assert!(part_text(&summary).contains("quokka retry budget is **5**"));
    let transcript = harness.get("transcript", &note_id(1)).await;
    let clock = |offset: i64| instant(&at(base, offset)).format("%H:%M:%S").to_string();
    assert_eq!(
        part_text(&transcript),
        format!(
            "[{}] Carol Diaz: Okay, the platypus budget. Alice, you wanted five?\n\
             [{}] Them: Five with jitter, three was too aggressive.\n\
             [{}] Speaker B: I'm worried about p99, but fine for now.",
            clock(2),
            clock(6),
            clock(12)
        )
    );
    assert_eq!(
        transcript.current.author.as_ref().unwrap().kind,
        "human",
        "a transcript is people speaking"
    );

    // A reconciliation read the listing to its end.
    let absent = harness.search(MISSING).await;
    assert_eq!(absent.absence.verdict, AbsenceVerdictV1::Absent);
    assert!(harness.last_checked_at().await.is_some());
    harness
        .fake
        .assert_credential_confined(&format!("Bearer {API_KEY}"), API_KEY);
}

#[tokio::test]
async fn live_granola_a_413_pages_the_transcript_when_configured() {
    let base = base_seconds();
    let mut world = World::new(base);
    world.note(4, PLATFORM, "All-hands", "The all-hands recap.", 10);
    world.segments(
        4,
        &[
            (1, "me", "First, the osprey launch."),
            (5, "", "Second, the pelican migration."),
            (9, "Speaker B", "Third, the heron budget."),
            (13, "", "Fourth, the kestrel hiring plan."),
            (17, "me", "Last, the wombat offsite."),
        ],
    );
    world.note_mut(4).too_large = true;
    let Some(harness) = Harness::new("granola-413", world).await else {
        return;
    };
    let report = harness.ok_tick(&harness.sources(&json!({}))).await;
    let source = Harness::source(&report);
    assert_eq!(source.counters["transcripts_paged"], 1);
    assert_eq!(
        source.counters["transcript_pages"], 3,
        "five segments, two a page"
    );
    assert_eq!(source.counters["transcripts_staged"], 1);
    assert_eq!(source.counters["containers_complete"], 1);

    let id = note_id(4);
    let gets: Vec<Option<String>> = harness
        .calls(&id)
        .iter()
        .map(|request| request.param("include").map(str::to_owned))
        .collect();
    assert_eq!(
        gets,
        [Some("transcript".to_owned()), None],
        "the note is read again without its transcript after the 413"
    );
    let pages: Vec<Option<String>> = harness
        .calls(&format!("{id}/transcript"))
        .iter()
        .map(|request| request.param("cursor").map(str::to_owned))
        .collect();
    assert_eq!(
        pages,
        [None, Some("seg:2".to_owned()), Some("seg:4".to_owned())]
    );
    let transcript = part_text(&harness.get("transcript", &id).await);
    let order: Vec<usize> = ["osprey", "pelican", "heron", "kestrel", "wombat"]
        .iter()
        .map(|word| transcript.find(word).unwrap())
        .collect();
    assert!(
        order.is_sorted(),
        "the pages keep their order: {transcript}"
    );
    assert_eq!(hits(&harness.search("wombat").await), [transcript_hit(4)]);
}

#[tokio::test]
async fn live_granola_an_updated_note_is_a_new_version_and_an_incremental_pass_writes_no_coverage_when_configured()
 {
    let base = base_seconds();
    let Some(harness) = Harness::new("granola-update", meetings_world(base)).await else {
        return;
    };
    let sources = harness.sources(&json!({}));
    harness.ok_tick(&sources).await;
    let receipts = harness.receipts().await;
    let checked = harness.last_checked_at().await;
    assert!(receipts >= 1 && checked.is_some());
    assert_eq!(
        harness.head("note_summary", &note_id(2)).await,
        ("live".to_owned(), 1)
    );

    // Nothing changed: an incremental pass lists only what is new, and
    // fetches nothing.
    harness.fake.clear_requests();
    let report = harness.ok_tick(&sources).await;
    let source = Harness::source(&report);
    assert_eq!(
        source.counters["reconcile"], 0,
        "within the reconcile interval"
    );
    assert_eq!(source.counters["notes_fetched"], 0);
    assert_eq!(source.outcome, WorkerSourceOutcomeV1::Unchanged);
    let listing = &harness.calls("/v1/notes")[0];
    assert!(
        listing.param("updated_after").is_some(),
        "an incremental listing starts after the sweep's position"
    );

    // The summary is regenerated: a newer updated_at, new content.
    harness.edit(2, |note| {
        note.summary = "The heron rollout moves to Thursday, after the freeze.".to_owned();
        note.updated_at = at(base, 120);
    });
    let report = harness.ok_tick(&sources).await;
    let source = Harness::source(&report);
    assert_eq!(source.counters["reconcile"], 0);
    assert_eq!(source.counters["notes_fetched"], 1, "only the changed note");
    assert_eq!(source.counters["summaries_staged"], 1);
    assert_eq!(source.counters["receipts"], 0);
    assert_eq!(
        harness.receipts().await,
        receipts,
        "an incremental pass writes no receipt"
    );
    assert_eq!(
        harness.last_checked_at().await,
        checked,
        "nor last_checked_at"
    );
    assert_eq!(
        harness.head("note_summary", &note_id(2)).await,
        ("live".to_owned(), 2)
    );
    let got = harness.get("note_summary", &note_id(2)).await;
    assert!(part_text(&got).contains("Thursday, after the freeze"));
    assert!(
        got.current.marker.starts_with('o'),
        "{}",
        got.current.marker
    );
    assert_eq!(
        got.history.len(),
        1,
        "the first version is superseded, not lost"
    );

    // A reconciliation re-reads every note and stages nothing new.
    harness.reconcile_due().await;
    let report = harness.ok_tick(&sources).await;
    let source = Harness::source(&report);
    assert_eq!(source.counters["reconcile"], 1);
    assert_eq!(source.counters["notes_fetched"], 3);
    assert_eq!(source.counters["rows_staged"], 0);
    assert_eq!(source.counters["containers_complete"], 1);
}

#[tokio::test]
async fn live_granola_a_404_tombstones_nothing_and_two_complete_listings_without_the_note_do_when_configured()
 {
    let base = base_seconds();
    let Some(harness) = Harness::new("granola-absent", meetings_world(base)).await else {
        return;
    };
    let sources = harness.sources(&json!({}));
    harness.ok_tick(&sources).await;
    assert_eq!(hits(&harness.search("heron").await), [summary_hit(2)]);

    // Listed, but the key cannot read it: never a tombstone.
    harness.world().note_mut(2).not_found = true;
    harness.reconcile_due().await;
    let report = harness.ok_tick(&sources).await;
    let source = Harness::source(&report);
    assert_eq!(source.counters["notes_not_found"], 1);
    assert_eq!(source.counters["tombstones"], 0);
    assert_eq!(
        source.counters["containers_complete"], 0,
        "the note was unreadable"
    );
    assert_eq!(hits(&harness.search("heron").await), [summary_hit(2)]);

    // Gone from the listing: one complete listing without it hides nothing.
    harness.world().notes.remove(&note_id(2));
    harness.reconcile_due().await;
    let report = harness.ok_tick(&sources).await;
    assert_eq!(Harness::source(&report).counters["missing_once"], 1);
    assert_eq!(Harness::source(&report).counters["tombstones"], 0);
    assert_eq!(hits(&harness.search("heron").await), [summary_hit(2)]);

    // The second complete listing without it tombstones it.
    harness.reconcile_due().await;
    let report = harness.ok_tick(&sources).await;
    assert_eq!(Harness::source(&report).counters["tombstones"], 1);
    assert!(harness.search("heron").await.hits.is_empty());
    assert!(harness.evidence("heron").await.hits.is_empty());
    let gone = harness.get("note_summary", &note_id(2)).await;
    assert_eq!(gone.suppressed, Some(ItemSuppressionV1::Deleted));
    assert_eq!(
        harness.head("note_summary", &note_id(2)).await,
        ("revoked".to_owned(), 2)
    );
    assert_eq!(
        hits(&harness.search("quokka").await),
        [summary_hit(1)],
        "the rest of the folder stays"
    );
    assert_eq!(
        harness.search(MISSING).await.absence.verdict,
        AbsenceVerdictV1::Absent
    );
}

#[tokio::test]
async fn live_granola_a_note_that_leaves_the_listed_folders_is_withdrawn_and_lifted_when_it_returns_when_configured()
 {
    let base = base_seconds();
    let Some(harness) = Harness::new("granola-folders", meetings_world(base)).await else {
        return;
    };
    let sources = harness.sources(&json!({}));
    harness.ok_tick(&sources).await;
    assert_eq!(hits(&harness.search("heron").await), [summary_hit(2)]);

    // Moved to People, which is not listed; its updated_at does not move.
    harness.world().note_mut(2).folders = vec![(PEOPLE.to_owned(), "People".to_owned())];
    harness.reconcile_due().await;
    let report = harness.ok_tick(&sources).await;
    assert_eq!(Harness::source(&report).counters["notes_withdrawn"], 1);
    assert!(harness.search("heron").await.hits.is_empty());
    assert!(harness.evidence("heron").await.hits.is_empty());
    assert_eq!(
        harness.get("note_summary", &note_id(2)).await.suppressed,
        Some(ItemSuppressionV1::ItemWithdrawn)
    );

    // Back in Platform: the next reconciliation lifts the withdrawal.
    harness.world().note_mut(2).folders = vec![(PLATFORM.to_owned(), "Platform".to_owned())];
    harness.reconcile_due().await;
    let report = harness.ok_tick(&sources).await;
    assert_eq!(Harness::source(&report).counters["notes_withdrawn"], 0);
    assert_eq!(hits(&harness.search("heron").await), [summary_hit(2)]);
    assert_eq!(
        harness.get("note_summary", &note_id(2)).await.suppressed,
        None
    );

    // Every note the key reads, declared: the People note is admitted too.
    let everything = harness.sources(&json!({"folders": [], "all_notes_visible_to_key": true}));
    harness.reconcile_due().await;
    harness.ok_tick(&everything).await;
    assert_eq!(hits(&harness.search("kestrel").await), [summary_hit(3)]);
    let kestrel = harness.get("note_summary", &note_id(3)).await;
    assert_eq!(
        kestrel.item.container.as_ref().unwrap().kind,
        "granola.workspace"
    );
}

#[tokio::test]
async fn live_granola_a_rate_limit_is_partial_and_the_next_pass_resumes_after_the_last_note_settled_when_configured()
 {
    let base = base_seconds();
    let mut world = World::new(base);
    for (index, word) in (10..).zip(["alpha", "bravo", "charlie", "delta"]) {
        world.note(
            index,
            PLATFORM,
            &format!("The {word} standup"),
            &format!("Notes on the {word} osprey."),
            i64::from(index) * 10,
        );
    }
    let Some(harness) = Harness::new("granola-rate-limit", world).await else {
        return;
    };
    let third = note_id(12);
    harness.fake.script(
        move |request| request.path.ends_with(&third),
        FakeReply::rate_limited(1),
    );
    let sources = harness.sources(&json!({}));
    let report = harness.ok_tick(&sources).await;
    let source = Harness::source(&report);
    assert_eq!(source.counters["rate_limited"], 1);
    assert_eq!(source.counters["notes_fetched"], 2, "in updated_at order");
    assert_eq!(source.counters["containers_complete"], 0);
    assert_eq!(hits(&harness.search("alpha").await).len(), 1);
    assert_eq!(hits(&harness.search("bravo").await).len(), 1);
    assert!(harness.search("charlie").await.hits.is_empty());
    let partial = harness.search(MISSING).await;
    assert_eq!(partial.absence.verdict, AbsenceVerdictV1::Unknown);
    assert_eq!(
        partial.absence.reasons,
        [AbsenceReasonV1::IncompleteCoverage]
    );

    harness.fake.clear_requests();
    let report = harness.ok_tick(&sources).await;
    let source = Harness::source(&report);
    assert_eq!(
        source.counters["reconcile"], 1,
        "the cut reconciliation goes on"
    );
    assert_eq!(source.counters["sweeps_resumed"], 1);
    assert_eq!(
        source.counters["notes_fetched"], 2,
        "the notes settled before the rate limit are not read again"
    );
    assert!(harness.calls(&note_id(10)).is_empty());
    assert_eq!(source.counters["containers_complete"], 1);
    for word in ["alpha", "bravo", "charlie", "delta"] {
        assert_eq!(hits(&harness.search(word).await).len(), 1, "{word}");
    }
    assert_eq!(
        harness.search(MISSING).await.absence.verdict,
        AbsenceVerdictV1::Absent
    );
}

#[tokio::test]
async fn live_granola_without_transcripts_no_segment_is_staged_when_configured() {
    let base = base_seconds();
    let Some(harness) = Harness::new("granola-no-transcript", meetings_world(base)).await else {
        return;
    };
    let sources = harness.sources(&json!({"include_transcript": false}));
    let report = harness.ok_tick(&sources).await;
    let source = Harness::source(&report);
    assert_eq!(source.counters["summaries_staged"], 2);
    assert_eq!(source.counters["transcripts_staged"], 0);
    assert!(
        harness
            .calls(&note_id(1))
            .iter()
            .all(|request| request.param("include").is_none()),
        "the transcript is never asked for"
    );
    assert!(harness.calls("/transcript").is_empty());
    assert_eq!(harness.heads_of("transcript").await, 0);
    assert!(harness.search("platypus").await.hits.is_empty());
    assert_eq!(hits(&harness.search("quokka").await), [summary_hit(1)]);
    assert_nowhere(&harness.pool, &harness.fixture, "platypus budget").await;
}

#[tokio::test]
async fn live_granola_the_key_the_private_notes_and_the_attendees_appear_nowhere_when_configured() {
    let base = base_seconds();
    let mut world = meetings_world(base);
    world.note(
        5,
        PLATFORM,
        "Pasted by mistake",
        &format!("Rotate {API_KEY} today; the retry plan stands."),
        40,
    );
    let Some(harness) = Harness::new("granola-secrets", world).await else {
        return;
    };
    // A failing read on the way: a 5xx whose body echoes the key.
    let first = note_id(1);
    harness.fake.script(
        move |request| request.path.ends_with(&first),
        FakeReply::status(
            502,
            &format!("upstream saw Authorization: Bearer {API_KEY}"),
        ),
    );
    let sources = harness.sources(&json!({}));
    let report = harness.ok_tick(&sources).await;
    assert_eq!(Harness::source(&report).counters["http_errors"], 1);
    assert_eq!(Harness::source(&report).counters["containers_complete"], 0);
    let report = harness.ok_tick(&sources).await;
    assert_eq!(Harness::source(&report).counters["containers_complete"], 1);

    let pasted = part_text(&harness.get("note_summary", &note_id(5)).await);
    assert!(pasted.contains("the retry plan stands"));
    assert!(!pasted.contains(API_KEY));
    assert_nowhere(&harness.pool, &harness.fixture, API_KEY).await;
    assert_nowhere(&harness.pool, &harness.fixture, PRIVATE_MARKER).await;
    assert_nowhere(&harness.pool, &harness.fixture, ATTENDEE).await;
    harness
        .fake
        .assert_credential_confined(&format!("Bearer {API_KEY}"), API_KEY);
}

#[test]
fn granola_an_undeclared_instance_or_an_http_api_base_off_loopback_is_refused_when_the_sources_file_is_read()
 {
    let sources = |audience: &Value, api_base: &str| {
        json!({
            "schema_version": 1,
            "collectors": [{
                "provider": "granola", "connector_principal": "principal.granola",
                "connector_instance": INSTANCE, "provider_scope_id": SCOPE,
                "audience": audience,
                "settings": {"token_env": TOKEN_ENV, "folders": [PLATFORM], "api_base": api_base}
            }]
        })
    };
    let read = |value: &Value| {
        WorkerSourcesV1::from_json_slice(&serde_json::to_vec(value).unwrap())
            .map(|_| ())
            .map_err(|error| error.to_string())
    };
    let declared = json!({"operator_declared": true});
    let undeclared = read(&sources(&json!({}), "https://public-api.granola.ai/v1")).unwrap_err();
    assert!(undeclared.contains("operator_declared"), "{undeclared}");
    let plain = read(&sources(&declared, "http://public-api.granola.example/v1")).unwrap_err();
    assert!(plain.contains("not loopback"), "{plain}");
    for accepted in [
        "https://public-api.granola.ai/v1",
        "http://127.0.0.1:8080/v1",
    ] {
        read(&sources(&declared, accepted)).unwrap_or_else(|error| panic!("{accepted}: {error}"));
    }
}
