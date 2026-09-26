//! Connected proofs of the Slack collector and the Slack export import (ADR
//! 0008 D8, D9): a worker tick pulls a fake workspace through the Web API
//! methods Slack documents, served by a local fake provider, and item and
//! evidence recall read the messages back with their threads; edits
//! supersede, deletions need two complete reads, a refusing or rate-limiting
//! channel leaves coverage partial, a token of another team reads nothing, a
//! channel made private is withdrawn, and the token is found in no table. An
//! export directory and a zip import as complete snapshots, private channels
//! only when listed, with file tokens stripped.
//!
//! Every connected test needs `FLEET_RECALL_TEST_DATABASE_URL` and returns at
//! once without it. No test reaches Slack.

mod common;

use std::collections::{BTreeMap, HashMap};
use std::io::Write as _;
use std::path::Path;
use std::sync::{Arc, Mutex};

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
    ObjectKindV1, ProviderKindV1, derive_item_key,
};
use ostk_fleet_recall::memory_contracts::digest::Sha256Digest;
use ostk_fleet_recall::registry_activation::install::InstallTargetV1;
use ostk_fleet_recall::store::cockroach::{CockroachStore, DatabaseCapabilities};
use ostk_fleet_recall::worker::{
    WorkerSourceOutcomeV1, WorkerSourceReportV1, WorkerSourcesV1, WorkerStepStatusV1, WorkerStepV1,
    WorkerTickReportV1,
};
use serde_json::{Value, json};
use sqlx::PgPool;

use common::authority::retry_policy;
use common::fake_provider::{FakeProvider, FakeReply, FakeRequest};
use common::worker::{RecordedCi, STUB_MODEL_DIGEST, WorkerFixture};

const INSTANCE: &str = "slack.acme";
const TEAM: &str = "T07ACME0001";
const TOKEN_ENV: &str = "FLEET_RECALL_SLACK_TEST_TOKEN";
const PLATENG: &str = "C07PLATENG1";
const RANDOM: &str = "C07RANDOM01";
const MISSING: &str = "unfindable marmoset";

/// The bot token the fake expects: an obvious placeholder, never a real
/// credential, that still has the `xoxb-` shape the redactor catches anywhere
/// it leaks into text.
const BOT_TOKEN: &str = "xoxb-EXAMPLE-NOT-A-TOKEN";

/// A file link's own token, as Slack puts it in `url_private`: a placeholder
/// with the `xoxe-` shape.
const FILE_TOKEN: &str = "xoxe-EXAMPLE-NOT-A-FILE-TOKEN";

// ---------------------------------------------------------------------------
// The fake workspace
// ---------------------------------------------------------------------------

/// Whole seconds three days ago: every message is inside the default
/// seven-day rescan and behind the database's clock.
fn base_seconds() -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    now - 3 * 86_400
}

fn ts(base: u64, offset: u64) -> String {
    format!("{}.{:06}", base + offset, 100 + offset)
}

fn ts_micros(ts: &str) -> u64 {
    let (seconds, fraction) = ts.split_once('.').unwrap();
    seconds.parse::<u64>().unwrap() * 1_000_000 + fraction.parse::<u64>().unwrap()
}

fn message(ts: &str, text: &str) -> Value {
    json!({"type": "message", "user": "U07ALICE001", "ts": ts, "text": text,
           "client_msg_id": "0f9d8c7b-6a5e-4d3c-2b1a-0e9f8d7c6b5a", "team": TEAM})
}

fn root(ts: &str, text: &str, latest_reply: &str, replies: u64) -> Value {
    json!({"type": "message", "user": "U07ALICE001", "ts": ts, "thread_ts": ts, "text": text,
           "reply_count": replies, "latest_reply": latest_reply, "reply_users": ["U07BOB0002"]})
}

fn reply(ts: &str, root: &str, text: &str) -> Value {
    json!({"type": "message", "user": "U07BOB0002", "ts": ts, "thread_ts": root, "text": text,
           "parent_user_id": "U07ALICE001"})
}

fn broadcast(ts: &str, root: &str, text: &str) -> Value {
    json!({"type": "message", "subtype": "thread_broadcast", "user": "U07CAROL003", "ts": ts,
           "thread_ts": root, "text": text, "parent_user_id": "U07ALICE001"})
}

#[derive(Debug, Clone, Default)]
struct Channel {
    name: String,
    private: bool,
    history_error: Option<String>,
    /// Channel-level messages, roots, and broadcasts.
    top: Vec<Value>,
    /// Replies by their root's ts.
    threads: BTreeMap<String, Vec<Value>>,
}

#[derive(Debug, Clone)]
struct World {
    team_id: String,
    channels: BTreeMap<String, Channel>,
}

impl World {
    fn new() -> Self {
        Self {
            team_id: TEAM.to_owned(),
            channels: BTreeMap::new(),
        }
    }

    fn channel(&mut self, id: &str, name: &str) -> &mut Channel {
        self.channels
            .entry(id.to_owned())
            .or_insert_with(|| Channel {
                name: name.to_owned(),
                ..Channel::default()
            })
    }
}

fn message_ts(value: &Value) -> u64 {
    ts_micros(value["ts"].as_str().unwrap())
}

/// One page of `messages`, paged by `limit` on an `o<offset>` cursor.
fn page(messages: &[Value], request: &FakeRequest) -> FakeReply {
    let limit: usize = request
        .param("limit")
        .and_then(|limit| limit.parse().ok())
        .unwrap_or(100);
    let offset: usize = request
        .param("cursor")
        .and_then(|cursor| cursor.strip_prefix('o'))
        .and_then(|offset| offset.parse().ok())
        .unwrap_or(0);
    let end = (offset + limit).min(messages.len());
    let more = end < messages.len();
    FakeReply::json(&json!({
        "ok": true,
        "messages": messages.get(offset..end).unwrap_or_default(),
        "has_more": more,
        "response_metadata": {"next_cursor": if more { format!("o{end}") } else { String::new() }}
    }))
}

/// The Web API over `world`, as Slack documents it.
fn respond(world: &World, request: &FakeRequest) -> FakeReply {
    let method = request.path.rsplit('/').next().unwrap_or_default();
    let channel = request
        .param("channel")
        .and_then(|id| world.channels.get(id).map(|channel| (id, channel)));
    match (method, channel) {
        ("auth.test", _) => FakeReply::json(&json!({
            "ok": true, "url": "https://acme-robotics.slack.com/", "team": "Acme Robotics",
            "user": "fleet-recall", "team_id": world.team_id, "user_id": "U07BOT0001",
            "bot_id": "B07BOT0001", "is_enterprise_install": false
        })),
        ("conversations.info", Some((id, channel))) => FakeReply::json(&json!({
            "ok": true,
            "channel": {"id": id, "name": channel.name, "is_channel": true, "is_group": false,
                        "is_im": false, "is_mpim": false, "is_private": channel.private,
                        "is_archived": false, "is_ext_shared": false, "is_org_shared": false,
                        "is_shared": false, "is_pending_ext_shared": false}
        })),
        ("conversations.history", Some((_, channel))) => {
            if let Some(error) = &channel.history_error {
                return FakeReply::json(&json!({"ok": false, "error": error}));
            }
            let oldest = request.param("oldest").map(ts_micros);
            let mut messages: Vec<Value> = channel
                .top
                .iter()
                .filter(|message| oldest.is_none_or(|oldest| message_ts(message) > oldest))
                .cloned()
                .collect();
            messages.sort_by_key(|message| std::cmp::Reverse(message_ts(message)));
            page(&messages, request)
        }
        ("conversations.replies", Some((_, channel))) => {
            let root_ts = request.param("ts").unwrap_or_default();
            let Some(root) = channel
                .top
                .iter()
                .find(|message| message["ts"] == root_ts)
                .cloned()
            else {
                return FakeReply::json(&json!({"ok": false, "error": "thread_not_found"}));
            };
            let mut replies = channel.threads.get(root_ts).cloned().unwrap_or_default();
            replies.sort_by_key(message_ts);
            replies.insert(0, root);
            page(&replies, request)
        }
        (_, None) if method.starts_with("conversations.") => {
            FakeReply::json(&json!({"ok": false, "error": "channel_not_found"}))
        }
        _ => FakeReply::status(404, "unknown method"),
    }
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

    /// Change one channel-level message of the fake workspace.
    fn edit(&self, channel: &str, index: usize, change: impl FnOnce(&mut Value)) {
        change(&mut self.world().channels.get_mut(channel).unwrap().top[index]);
    }

    fn collector(&self, channels: &[&str], extra: &Value) -> Value {
        let mut settings = json!({
            "token_env": TOKEN_ENV,
            "channels": channels,
            "api_base": format!("{}/api", self.fake.base),
            "page_size": 2
        });
        settings
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        json!({
            "provider": "slack",
            "connector_principal": "principal.slack",
            "connector_instance": INSTANCE,
            "provider_scope_id": TEAM,
            "audience": {"private_containers": extra.get("listed").cloned().unwrap_or(json!([]))},
            "settings": settings
        })
    }

    fn sources(&self, channels: &[&str], extra: &Value) -> Value {
        let mut collector = self.collector(channels, extra);
        collector["settings"]
            .as_object_mut()
            .unwrap()
            .remove("listed");
        json!({
            "schema_version": 1,
            "coverage_since": "2026-08-01T00:00:00Z",
            "collectors": [collector]
        })
    }

    async fn tick(&self, sources: &Value) -> WorkerTickReportV1 {
        self.fixture
            .worker_with(&self.pool, "collect,project", sources, Arc::new(RecordedCi))
            .await
            .with_collector_environment(Arc::new(move |name: &str| {
                (name == TOKEN_ENV).then(|| BOT_TOKEN.to_owned())
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

    async fn scalar(&self, sql: &str, bind: &str) -> i64 {
        sqlx::query_scalar(sql)
            .bind(self.fixture.installed.scope.tenant_id)
            .bind(&self.fixture.installed.scope.project)
            .bind(bind)
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }

    async fn receipts(&self) -> i64 {
        self.scalar(
            "SELECT count(*) FROM memory_coverage_receipts_v1 \
             WHERE tenant_id = $1 AND project = $2 AND connector_instance_id = $3",
            INSTANCE,
        )
        .await
    }

    async fn cursors(&self, domain_key: &str) -> i64 {
        sqlx::query_scalar(
            "SELECT count(*) FROM memory_collector_cursors_v1 \
             WHERE tenant_id = $1 AND project = $2 AND collector_instance_id = $3 \
               AND domain_key = $4",
        )
        .bind(self.fixture.installed.scope.tenant_id)
        .bind(&self.fixture.installed.scope.project)
        .bind(INSTANCE)
        .bind(domain_key)
        .fetch_one(&self.pool)
        .await
        .unwrap()
    }

    async fn last_checked_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
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

    /// A message's verified head: its lifecycle and how many versions it saw.
    async fn head(&self, external_id: &str) -> (String, i64) {
        head(&self.pool, &self.fixture, external_id, "verified").await
    }

    async fn container(&self, id: &str) -> (String, Option<String>) {
        container(&self.pool, &self.fixture, id).await
    }

    async fn items(&self) -> CockroachItemRecall {
        items(&self.pool, &self.fixture).await
    }

    async fn search(&self, query: &str) -> ItemSearchV1 {
        search(&self.items().await, query).await
    }

    async fn evidence(&self, query: &str) -> EvidenceSearchV1 {
        evidence(&self.pool, &self.fixture, query).await
    }

    async fn get(&self, external_id: &str) -> ItemGetV1 {
        get(&self.items().await, external_id).await
    }

    fn source(report: &WorkerTickReportV1) -> &WorkerSourceReportV1 {
        report
            .step(WorkerStepV1::Collect)
            .expect("the collect step ran")
            .sources
            .iter()
            .find(|source| source.connector_instance == INSTANCE)
            .expect("the Slack collector reported")
    }
}

async fn head(
    pool: &PgPool,
    fixture: &WorkerFixture,
    external_id: &str,
    tier: &str,
) -> (String, i64) {
    sqlx::query_as(
        "SELECT lifecycle, version_count FROM memory_collected_item_heads_v1 \
         WHERE tenant_id = $1 AND project = $2 AND object_kind = 'message' \
           AND external_id = $3 AND trust_tier = $4",
    )
    .bind(fixture.installed.scope.tenant_id)
    .bind(&fixture.installed.scope.project)
    .bind(external_id)
    .bind(tier)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn container(pool: &PgPool, fixture: &WorkerFixture, id: &str) -> (String, Option<String>) {
    sqlx::query_as(
        "SELECT access, label FROM memory_collector_containers_v1 \
         WHERE tenant_id = $1 AND project = $2 AND container_id = $3",
    )
    .bind(fixture.installed.scope.tenant_id)
    .bind(&fixture.installed.scope.project)
    .bind(id)
    .fetch_one(pool)
    .await
    .unwrap()
}

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

async fn search(recall: &CockroachItemRecall, query: &str) -> ItemSearchV1 {
    recall
        .search(
            &ItemSearchRequestV1 {
                query: query.to_owned(),
                provider: Some(ProviderKindV1::new("slack").unwrap()),
                include_history: false,
                limit: 20,
            },
            None,
        )
        .await
        .unwrap()
}

async fn evidence(pool: &PgPool, fixture: &WorkerFixture, query: &str) -> EvidenceSearchV1 {
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
        .search(query, None, 20)
        .await
        .unwrap()
}

fn item_key(external_id: &str) -> Sha256Digest {
    derive_item_key(
        &ProviderKindV1::new("slack").unwrap(),
        TEAM,
        &ObjectKindV1::new("message").unwrap(),
        external_id,
    )
}

async fn get(recall: &CockroachItemRecall, external_id: &str) -> ItemGetV1 {
    recall
        .get(&ItemReferenceV1::Item(item_key(external_id)))
        .await
        .unwrap()
        .expect("the message is an item")
}

fn external(channel: &str, ts: &str) -> String {
    format!("{channel}:{ts}")
}

fn hits(search: &ItemSearchV1) -> Vec<&str> {
    search
        .hits
        .iter()
        .map(|hit| hit.external_id.as_str())
        .collect()
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

/// `secret` is in no row, as text, as hex, or as the hex of hex (an
/// envelope's text inside a stored envelope's bytes).
async fn assert_nowhere(pool: &PgPool, fixture: &WorkerFixture, secret: &str) {
    let once = hex::encode(secret);
    let twice = hex::encode(&once);
    let rows = scoped_rows(pool, fixture).await;
    assert!(!rows.is_empty());
    for (table, row) in rows {
        let lowered = row.to_ascii_lowercase();
        assert!(
            !row.contains(secret) && !lowered.contains(&once) && !lowered.contains(&twice),
            "the secret is in a row of {table}"
        );
    }
}

// ---------------------------------------------------------------------------
// The pull collector
// ---------------------------------------------------------------------------

/// Plat-eng: a standalone message and a thread whose root has one plain
/// reply and one broadcast.
fn thread_world(base: u64) -> World {
    let mut world = World::new();
    let channel = world.channel(PLATENG, "plat-eng");
    let (root_ts, reply_ts, broadcast_ts) = (ts(base, 0), ts(base, 10), ts(base, 20));
    channel.top = vec![
        root(
            &root_ts,
            "Should the quokka retry budget be 3 or 5? cc <!subteam^S07PLAT001>",
            &broadcast_ts,
            2,
        ),
        broadcast(
            &broadcast_ts,
            &root_ts,
            "Decision: five attempts with pelican jitter; <@U07ALICE001> will update \
             <https://linear.app/acme/issue/ENG-412|ENG-412>",
        ),
        message(&ts(base, 30), "A standalone kestrel note"),
    ];
    channel.threads.insert(
        root_ts.clone(),
        vec![
            reply(&reply_ts, &root_ts, "Three, says the heron"),
            broadcast(
                &broadcast_ts,
                &root_ts,
                "Decision: five attempts with pelican jitter; <@U07ALICE001> will update \
                 <https://linear.app/acme/issue/ENG-412|ENG-412>",
            ),
        ],
    );
    world
}

#[tokio::test]
async fn live_slack_roots_and_replies_are_admitted_with_their_thread_and_reconciled_when_configured()
 {
    let base = base_seconds();
    let Some(harness) = Harness::new("slack-threads", thread_world(base)).await else {
        return;
    };
    let sources = harness.sources(&[PLATENG], &json!({}));
    let report = harness.ok_tick(&sources).await;
    let source = Harness::source(&report);
    assert_eq!(source.outcome, WorkerSourceOutcomeV1::Ok, "{source:?}");
    assert_eq!(source.counters["reconcile"], 1);
    assert_eq!(source.counters["threads_read"], 1);
    assert_eq!(
        source.counters["messages_read"], 4,
        "the broadcast is read once, although both listings carry it"
    );
    assert_eq!(source.counters["containers_complete"], 1);
    assert!(source.counters["receipts"] >= 1);

    let (root_ts, reply_ts, broadcast_ts) = (ts(base, 0), ts(base, 10), ts(base, 20));
    assert_eq!(
        hits(&harness.search("heron").await),
        [external(PLATENG, &reply_ts)]
    );
    assert_eq!(
        hits(&harness.search("pelican").await),
        [external(PLATENG, &broadcast_ts)]
    );
    let reply = harness.get(&external(PLATENG, &reply_ts)).await;
    assert_eq!(
        reply.item.thread_root_external_id.as_deref(),
        Some(external(PLATENG, &root_ts).as_str()),
        "the reply is linked to its thread's root"
    );
    let root = harness.get(&external(PLATENG, &root_ts)).await;
    assert_eq!(root.item.thread_root_external_id, None);
    assert_eq!(
        part_text(&root),
        "Should the quokka retry budget be 3 or 5? cc @S07PLAT001"
    );
    assert_eq!(
        root.item.provider_url.as_deref(),
        Some(
            format!(
                "https://acme-robotics.slack.com/archives/{PLATENG}/p{}",
                root_ts.replace('.', "")
            )
            .as_str()
        )
    );
    let decision = harness.get(&external(PLATENG, &broadcast_ts)).await;
    assert_eq!(
        decision
            .links_out
            .iter()
            .map(|link| link.target.as_str())
            .collect::<Vec<_>>(),
        ["https://linear.app/acme/issue/ENG-412"]
    );
    assert_eq!(
        decision.item.container.as_ref().unwrap().label.as_deref(),
        Some("plat-eng")
    );
    assert!(
        !harness.evidence("kestrel").await.hits.is_empty(),
        "evidence recall reads the messages too"
    );

    // The reconciliation read every channel to its end: absence is sound.
    let absent = harness.search(MISSING).await;
    assert!(absent.hits.is_empty());
    assert_eq!(absent.absence.verdict, AbsenceVerdictV1::Absent);
    assert!(harness.last_checked_at().await.is_some());
    harness
        .fake
        .assert_credential_confined(&format!("Bearer {BOT_TOKEN}"), BOT_TOKEN);
}

#[tokio::test]
async fn live_slack_an_incremental_rescan_supersedes_an_edit_and_writes_no_coverage_when_configured()
 {
    let base = base_seconds();
    let Some(harness) = Harness::new("slack-edit", thread_world(base)).await else {
        return;
    };
    let sources = harness.sources(&[PLATENG], &json!({}));
    harness.ok_tick(&sources).await;
    let receipts = harness.receipts().await;
    let checked = harness.last_checked_at().await;
    assert!(receipts >= 1 && checked.is_some());

    // The root is edited: a newer `edited.ts`, new text.
    let root_ts = ts(base, 0);
    harness.edit(PLATENG, 0, |message| {
        message["text"] = json!("Should the quokka retry budget be five? Edited.");
        message["edited"] = json!({"user": "U07ALICE001", "ts": ts(base, 100)});
    });
    let report = harness.ok_tick(&sources).await;
    let source = Harness::source(&report);
    assert_eq!(
        source.counters["reconcile"], 0,
        "within the reconcile interval"
    );
    assert_eq!(source.counters["messages_staged"], 1);
    assert!(source.counters["messages_unchanged"] >= 2);
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

    let edited = harness.get(&external(PLATENG, &root_ts)).await;
    assert_eq!(
        part_text(&edited),
        "Should the quokka retry budget be five? Edited."
    );
    assert_eq!(edited.current.marker, ts(base, 100));
    assert_eq!(
        edited.history.len(),
        1,
        "the first version is superseded, not lost"
    );
    assert_eq!(
        harness.head(&external(PLATENG, &root_ts)).await,
        ("edited".to_owned(), 2)
    );
}

#[tokio::test]
async fn live_slack_a_deleted_message_is_tombstoned_after_two_complete_rescans_when_configured() {
    let base = base_seconds();
    let Some(harness) = Harness::new("slack-delete", thread_world(base)).await else {
        return;
    };
    let sources = harness.sources(&[PLATENG], &json!({}));
    harness.ok_tick(&sources).await;
    let standalone = external(PLATENG, &ts(base, 30));
    assert_eq!(
        hits(&harness.search("kestrel").await),
        std::slice::from_ref(&standalone)
    );

    harness.world().channels.get_mut(PLATENG).unwrap().top.pop();
    let first = harness.ok_tick(&sources).await;
    assert_eq!(Harness::source(&first).counters["missing_once"], 1);
    assert_eq!(Harness::source(&first).counters["tombstones"], 0);
    assert_eq!(
        hits(&harness.search("kestrel").await),
        std::slice::from_ref(&standalone),
        "one complete rescan without it hides nothing"
    );

    let second = harness.ok_tick(&sources).await;
    assert_eq!(Harness::source(&second).counters["tombstones"], 1);
    assert!(harness.search("kestrel").await.hits.is_empty());
    assert!(harness.evidence("kestrel").await.hits.is_empty());
    let gone = harness.get(&standalone).await;
    assert_eq!(gone.suppressed, Some(ItemSuppressionV1::Deleted));
    assert_eq!(harness.head(&standalone).await, ("deleted".to_owned(), 2));
    assert_eq!(
        hits(&harness.search("heron").await).len(),
        1,
        "the rest of the channel stays"
    );
}

#[tokio::test]
async fn live_slack_a_channel_the_bot_is_not_in_is_partial_when_configured() {
    let base = base_seconds();
    let mut world = thread_world(base);
    let random = world.channel(RANDOM, "random");
    random.history_error = Some("not_in_channel".to_owned());
    let Some(harness) = Harness::new("slack-not-in-channel", world).await else {
        return;
    };
    let sources = harness.sources(&[PLATENG, RANDOM], &json!({}));
    let report = harness.ok_tick(&sources).await;
    let source = Harness::source(&report);
    assert_eq!(source.counters["provider_refused"], 1);
    assert_eq!(source.counters["containers"], 2);
    assert_eq!(source.counters["containers_complete"], 1);
    assert_eq!(hits(&harness.search("heron").await).len(), 1);
    let absent = harness.search(MISSING).await;
    assert_eq!(absent.absence.verdict, AbsenceVerdictV1::Unknown);
    assert_eq!(
        absent.absence.reasons,
        [AbsenceReasonV1::IncompleteCoverage]
    );
}

#[tokio::test]
async fn live_slack_a_rate_limit_on_page_two_keeps_page_one_holds_the_cursor_and_the_next_tick_completes_when_configured()
 {
    let base = base_seconds();
    let mut world = World::new();
    world.channel(PLATENG, "plat-eng").top = ["alpha", "bravo", "charlie", "delta", "echo"]
        .iter()
        .zip(0..)
        .map(|(word, offset)| message(&ts(base, offset), &format!("the {word} osprey note")))
        .collect();
    let Some(harness) = Harness::new("slack-rate-limit", world).await else {
        return;
    };
    harness.fake.script(
        |request| {
            request.path.ends_with("/conversations.history") && request.param("cursor").is_some()
        },
        FakeReply::rate_limited(30),
    );
    let sources = harness.sources(&[PLATENG], &json!({}));
    let report = harness.ok_tick(&sources).await;
    let source = Harness::source(&report);
    assert_eq!(source.counters["rate_limited"], 1);
    assert_eq!(source.counters["containers_complete"], 0);
    assert_eq!(
        source.counters["messages_read"], 2,
        "page one, newest first"
    );
    assert_eq!(hits(&harness.search("echo").await).len(), 1);
    assert_eq!(hits(&harness.search("delta").await).len(), 1);
    assert!(harness.search("alpha").await.hits.is_empty());
    assert_eq!(
        harness.cursors(&format!("slack.channel:{PLATENG}")).await,
        0,
        "the channel's cursor is held"
    );
    assert_eq!(harness.cursors("slack.reconcile").await, 0);
    let partial = harness.search(MISSING).await;
    assert_eq!(partial.absence.verdict, AbsenceVerdictV1::Unknown);
    assert_eq!(
        partial.absence.reasons,
        [AbsenceReasonV1::IncompleteCoverage]
    );

    let report = harness.ok_tick(&sources).await;
    let source = Harness::source(&report);
    assert_eq!(
        source.counters["reconcile"], 1,
        "the cut reconciliation runs again"
    );
    assert_eq!(source.counters["containers_complete"], 1);
    assert_eq!(
        source.counters["messages_unchanged"], 2,
        "page one is not staged twice"
    );
    for word in ["alpha", "bravo", "charlie"] {
        assert_eq!(hits(&harness.search(word).await).len(), 1, "{word}");
    }
    assert_eq!(
        harness.cursors(&format!("slack.channel:{PLATENG}")).await,
        1
    );
    assert_eq!(harness.cursors("slack.reconcile").await, 1);
    assert_eq!(
        harness.search(MISSING).await.absence.verdict,
        AbsenceVerdictV1::Absent
    );
}

#[tokio::test]
async fn live_slack_a_token_of_another_team_fails_the_source_and_reads_nothing_when_configured() {
    let base = base_seconds();
    let mut world = thread_world(base);
    world.team_id = "T07OTHER001".to_owned();
    let Some(harness) = Harness::new("slack-other-team", world).await else {
        return;
    };
    let report = harness.tick(&harness.sources(&[PLATENG], &json!({}))).await;
    let collect = report.step(WorkerStepV1::Collect).unwrap();
    assert_eq!(
        collect.status,
        WorkerStepStatusV1::Failed,
        "{}",
        serde_json::to_string(&report).unwrap()
    );
    let source = Harness::source(&report);
    assert_eq!(source.outcome, WorkerSourceOutcomeV1::Failed);
    let error = source.error.as_deref().unwrap();
    assert!(
        error.contains("T07OTHER001") && error.contains(TEAM),
        "{error}"
    );
    let paths: Vec<String> = harness
        .fake
        .requests()
        .iter()
        .map(|request| request.path.clone())
        .collect();
    assert_eq!(paths, ["/api/auth.test"], "nothing but auth.test was read");
    assert_eq!(
        harness
            .scalar(
                "SELECT count(*) FROM memory_collector_outbox_v1 \
                 WHERE tenant_id = $1 AND project = $2 AND collector_instance_id = $3",
                INSTANCE,
            )
            .await,
        0
    );
}

#[tokio::test]
async fn live_slack_a_channel_made_private_and_unlisted_is_withdrawn_and_hidden_when_configured() {
    let base = base_seconds();
    let Some(harness) = Harness::new("slack-private", thread_world(base)).await else {
        return;
    };
    let sources = harness.sources(&[PLATENG], &json!({}));
    harness.ok_tick(&sources).await;
    assert_eq!(hits(&harness.search("heron").await).len(), 1);
    assert_eq!(
        harness.container(PLATENG).await,
        ("ok".to_owned(), Some("plat-eng".to_owned()))
    );

    harness.world().channels.get_mut(PLATENG).unwrap().private = true;
    harness.fake.clear_requests();
    let report = harness.ok_tick(&sources).await;
    assert_eq!(Harness::source(&report).counters["channels_refused"], 1);
    assert!(
        harness
            .fake
            .requests()
            .iter()
            .all(|request| !request.path.ends_with("/conversations.history")),
        "a channel the project may not read is never read"
    );
    assert_eq!(harness.container(PLATENG).await.0, "withdrawn");
    assert!(harness.search("heron").await.hits.is_empty());
    assert!(harness.evidence("heron").await.hits.is_empty());
    let hidden = harness.get(&external(PLATENG, &ts(base, 10))).await;
    assert_eq!(
        hidden.suppressed,
        Some(ItemSuppressionV1::ContainerWithdrawn)
    );

    // Listing it re-opens it: a pull may lift what a pull withdrew.
    let listed = harness.sources(&[PLATENG], &json!({"listed": [PLATENG]}));
    harness.ok_tick(&listed).await;
    assert_eq!(harness.container(PLATENG).await.0, "ok");
    assert_eq!(hits(&harness.search("heron").await).len(), 1);
}

#[tokio::test]
async fn live_slack_the_token_is_in_no_table_when_configured() {
    let base = base_seconds();
    let mut world = thread_world(base);
    let channel = world.channels.get_mut(PLATENG).unwrap();
    channel.top.push(json!({
        "type": "message", "subtype": "file_share", "user": "U07BOB0002", "ts": ts(base, 40),
        "text": format!("Pasted by mistake: {BOT_TOKEN} and the retry plan"),
        "files": [{"id": "F07SPEC0001", "name": "retry-plan.md",
                   "url_private": format!(
                       "https://files.slack.com/files-pri/{TEAM}-F07SPEC0001/retry-plan.md?t={FILE_TOKEN}"
                   )}]
    }));
    world.channel(RANDOM, "random");
    let Some(harness) = Harness::new("slack-token", world).await else {
        return;
    };
    // A failing call on the way: a 5xx whose body echoes the credential.
    harness.fake.script(
        |request| {
            request.path.ends_with("/conversations.info")
                && request.param("channel") == Some(RANDOM)
        },
        FakeReply::status(
            502,
            &format!("upstream saw Authorization: Bearer {BOT_TOKEN}"),
        ),
    );
    let sources = harness.sources(&[PLATENG, RANDOM], &json!({}));
    let report = harness.ok_tick(&sources).await;
    assert_eq!(Harness::source(&report).counters["http_errors"], 1);
    harness.ok_tick(&sources).await;

    let pasted = harness.get(&external(PLATENG, &ts(base, 40))).await;
    assert!(part_text(&pasted).contains("the retry plan"));
    assert_eq!(
        pasted
            .links_out
            .iter()
            .map(|link| link.target.as_str())
            .collect::<Vec<_>>(),
        [format!("https://files.slack.com/files-pri/{TEAM}-F07SPEC0001/retry-plan.md").as_str()],
        "the file link keeps no token"
    );
    assert_nowhere(&harness.pool, &harness.fixture, BOT_TOKEN).await;
    assert_nowhere(&harness.pool, &harness.fixture, FILE_TOKEN).await;
    harness
        .fake
        .assert_credential_confined(&format!("Bearer {BOT_TOKEN}"), BOT_TOKEN);
}

#[test]
fn slack_an_http_api_base_off_loopback_is_refused_when_the_sources_file_is_read() {
    let sources = |api_base: &str| {
        json!({
            "schema_version": 1,
            "collectors": [{
                "provider": "slack", "connector_principal": "principal.slack",
                "connector_instance": INSTANCE, "provider_scope_id": TEAM,
                "settings": {"token_env": TOKEN_ENV, "channels": [PLATENG], "api_base": api_base}
            }]
        })
    };
    let refused = WorkerSourcesV1::from_json_slice(
        &serde_json::to_vec(&sources("http://slack.example.com/api")).unwrap(),
    )
    .unwrap_err()
    .to_string();
    assert!(refused.contains("not loopback"), "{refused}");
    for accepted in ["https://slack.com/api", "http://127.0.0.1:8080/api"] {
        WorkerSourcesV1::from_json_slice(&serde_json::to_vec(&sources(accepted)).unwrap())
            .unwrap_or_else(|error| panic!("{accepted}: {error}"));
    }
}

// ---------------------------------------------------------------------------
// The export import
// ---------------------------------------------------------------------------

/// A small export: two public channels, a listed and an unlisted private
/// channel, and a direct conversation, with a file whose link carries its
/// own token.
fn export_entries() -> Vec<(String, String)> {
    let file_link =
        format!("https://files.slack.com/files-pri/{TEAM}-F07PLAN0001/plan.md?t={FILE_TOKEN}");
    vec![
        (
            "channels.json".into(),
            json!([{"id": PLATENG, "name": "plat-eng", "created": 1_780_000_000},
                   {"id": "C07GENERAL1", "name": "general", "created": 1_780_000_000}])
            .to_string(),
        ),
        (
            "groups.json".into(),
            json!([{"id": "G07SECRET01", "name": "secret-team"},
                   {"id": "G07LISTED01", "name": "listed-team"}])
            .to_string(),
        ),
        (
            "dms.json".into(),
            json!([{"id": "D07DIRECT01", "members": ["U07ALICE001", "U07BOB0002"]}]).to_string(),
        ),
        (
            "users.json".into(),
            json!([{"id": "U07ALICE001", "team_id": TEAM, "name": "alice"}]).to_string(),
        ),
        (
            "plat-eng/2026-09-21.json".into(),
            json!([
                root("1790006645.000200", "Should the retry budget be 3 or 5?", "1790006860.001100", 1),
                reply("1790006860.001100", "1790006645.000200", "Three, says the albatross"),
                {"type": "message", "subtype": "channel_join", "user": "U07CAROL003",
                 "ts": "1790006700.000000", "text": "<@U07CAROL003> has joined the channel"},
                {"type": "message", "subtype": "file_share", "user": "U07BOB0002",
                 "ts": "1790068531.002000", "text": "The cormorant plan is attached",
                 "files": [{"id": "F07PLAN0001", "name": "plan.md", "url_private": file_link}]}
            ])
            .to_string(),
        ),
        (
            "general/2026-09-20.json".into(),
            json!([message("1790000000.000100", "A general puffin announcement")]).to_string(),
        ),
        (
            "listed-team/2026-09-21.json".into(),
            json!([message("1790006800.000000", "The listed grebe channel talks")]).to_string(),
        ),
        (
            "secret-team/2026-09-21.json".into(),
            json!([message("1790006900.000000", "The unlisted cassowary secret")]).to_string(),
        ),
        (
            "D07DIRECT01/2026-09-21.json".into(),
            json!([message("1790007000.000000", "A direct flamingo whisper")]).to_string(),
        ),
    ]
}

fn export_directory() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    for (name, text) in export_entries() {
        let path = root.path().join(&name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }
    root
}

fn export_zip() -> tempfile::NamedTempFile {
    let file = tempfile::Builder::new().suffix(".zip").tempfile().unwrap();
    let mut writer = zip::ZipWriter::new(file.reopen().unwrap());
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    for (name, text) in export_entries() {
        writer
            .start_file(format!("Acme Robotics Slack export/{name}"), options)
            .unwrap();
        writer.write_all(text.as_bytes()).unwrap();
    }
    writer.finish().unwrap();
    file
}

/// `collect import --format slack-export` of `path` into a fresh scope, then
/// a projecting tick.
async fn import_export(pool: &PgPool, label: &str, path: &Path) -> (WorkerFixture, Value) {
    let fixture = WorkerFixture::install_at(pool, label, InstallTargetV1::Generation3).await;
    let mut variables: HashMap<String, String> =
        serde_json::from_value(serde_json::to_value(&fixture.installed.report.pins).unwrap())
            .unwrap();
    variables.insert(
        "FLEET_RECALL_CONTENT_KEK_HEX".into(),
        fixture.installed.kek_hex.clone(),
    );
    let lookup = |name: &str| variables.get(name).cloned();
    let connection = (
        pool.clone(),
        capabilities(pool, &fixture.installed.scope).await,
    );
    let command = CollectCommandV1::Import(CollectImportV1 {
        instance: "import.slack-export".into(),
        principal: "principal.import".into(),
        provider: "slack".into(),
        provider_scope: TEAM.into(),
        audience: ImportAudienceV1::OperatorDeclared,
        format: ImportFormatV1::SlackExport {
            private_containers: vec!["G07LISTED01".into()],
        },
        path: path.to_path_buf(),
        no_drain: false,
        stale_after_seconds: None,
    });
    let mut out = Vec::new();
    let report = Box::pin(run_collect_command(
        &command,
        CollectProcessV1 {
            scope: fixture.installed.scope.clone(),
            lookup: &lookup,
            retry: retry_policy(),
        },
        move || async move { Ok(connection) },
        &mut out,
    ))
    .await
    .unwrap_or_else(|error| panic!("the export import must succeed: {error}"));
    let projected = fixture
        .worker_with(
            pool,
            "project",
            &json!({"schema_version": 1}),
            Arc::new(RecordedCi),
        )
        .await
        .run_tick()
        .await;
    assert!(!projected.failed());
    (fixture, report)
}

#[tokio::test]
async fn live_slack_an_export_directory_and_zip_import_as_complete_snapshots_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let directory = export_directory();
    let zip = export_zip();
    for (label, path) in [
        ("slack-export-dir", directory.path()),
        ("slack-export-zip", zip.path()),
    ] {
        let (fixture, report) = import_export(&pool, label, path).await;
        assert_eq!(report["snapshot"]["state"], "recorded", "{label}: {report}");
        assert_eq!(report["snapshot"]["complete"], true, "{label}: {report}");
        assert_eq!(
            report["containers"], 3,
            "{label}: the public channels and the listed private one"
        );
        assert_eq!(report["refused"], json!({}), "{label}: {report}");

        let recall = items(&pool, &fixture).await;
        for word in ["albatross", "cormorant", "puffin", "grebe"] {
            assert_eq!(search(&recall, word).await.hits.len(), 1, "{label}: {word}");
        }
        for word in ["cassowary", "flamingo"] {
            assert!(
                search(&recall, word).await.hits.is_empty(),
                "{label}: {word}"
            );
            assert!(
                evidence(&pool, &fixture, word).await.hits.is_empty(),
                "{label}: {word}"
            );
        }
        assert_eq!(
            container(&pool, &fixture, "G07SECRET01").await,
            ("withdrawn".to_owned(), None),
            "{label}: an unlisted private channel is recorded withdrawn, unlabelled"
        );
        let reply = get(&recall, &external(PLATENG, "1790006860.001100")).await;
        assert_eq!(
            reply.item.thread_root_external_id.as_deref(),
            Some(external(PLATENG, "1790006645.000200").as_str())
        );
        assert_eq!(
            head(
                &pool,
                &fixture,
                &external(PLATENG, "1790006860.001100"),
                "reported"
            )
            .await,
            ("live".to_owned(), 1)
        );
        let plan = get(&recall, &external(PLATENG, "1790068531.002000")).await;
        assert_eq!(
            plan.links_out
                .iter()
                .map(|link| link.target.as_str())
                .collect::<Vec<_>>(),
            [format!("https://files.slack.com/files-pri/{TEAM}-F07PLAN0001/plan.md").as_str()],
            "{label}: the file link keeps no token"
        );
        assert_nowhere(&pool, &fixture, FILE_TOKEN).await;
        let absent = search(&recall, MISSING).await;
        assert_eq!(
            absent.absence.verdict,
            AbsenceVerdictV1::Absent,
            "{label}: the snapshot is complete"
        );
    }
}
