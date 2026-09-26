//! Connected proofs of the stage-7 ingress (ADR 0008 D12): signed Slack,
//! Linear, and Granola webhooks posted to the receiver's router, which runs
//! under a login holding exactly the ingress receiver's grants, become hints
//! (ids only); a worker tick re-reads each hinted object from a local fake
//! provider through the collector's own pull adapter, or tombstones a deleted
//! one, and settles the hint in the transaction that stages what it caused.
//!
//! A replay adds nothing; a bad or stale signature, an oversize body, and a
//! delivery of another team or organization are refused with at most one
//! dead letter per instance, reason, and minute; Slack's URL verification is
//! echoed; a direct message is kept with no ids; a Granola edit leaves an
//! empty answer unknown until the worker reads the note; only the hints of a
//! collector the worker runs count, and a login that cannot read the queue
//! gets `unknown`, never `absent`; a hint whose fetch keeps failing dies after
//! eight attempts and `collect retry` reopens it; a hint never writes
//! coverage; the receiver cannot read evidence, content, items, or the
//! outbox; a database failure answers 503; and the binary refuses a listen
//! address that is not loopback unless allowed.
//!
//! Every connected test needs `FLEET_RECALL_TEST_DATABASE_URL` and returns at
//! once without it. No test reaches a provider.

mod common;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::Request;
use chrono::{DateTime, SecondsFormat, TimeZone as _, Utc};
use ostk_fleet_recall::collectors::command::{
    CollectCommandV1, CollectProcessV1, run_collect_command,
};
use ostk_fleet_recall::collectors::ingress::base64;
use ostk_fleet_recall::collectors::ingress::deliveries::IngressStoreV1;
use ostk_fleet_recall::collectors::ingress::server::{IngressInstancesV1, router, validate_listen};
use ostk_fleet_recall::collectors::ingress::signature::{sign, standard_webhooks_key};
use ostk_fleet_recall::evidence_recall::{
    AbsenceReasonV1, AbsenceVerdictV1, CockroachEvidenceRecall, EvidenceRecall as _,
    EvidenceSearchV1, probe_evidence_recall,
};
use ostk_fleet_recall::item_recall::{
    CockroachItemRecall, ItemRecall as _, ItemSearchRequestV1, ItemSearchV1, probe_item_recall,
};
use ostk_fleet_recall::memory_contracts::collected_item::ProviderKindV1;
use ostk_fleet_recall::memory_contracts::digest::Sha256Digest;
use ostk_fleet_recall::registry_activation::install::InstallTargetV1;
use ostk_fleet_recall::store::cockroach::{CockroachStore, DatabaseCapabilities, RetryPolicy};
use ostk_fleet_recall::worker::{WorkerSourcesV1, WorkerStepV1, WorkerTickReportV1};
use serde_json::{Value, json};
use sqlx::PgPool;
use tower::ServiceExt as _;

use common::fake_provider::{FakeProvider, FakeReply, FakeRequest};
use common::runtime_role::RuntimeProbeRole;
use common::worker::{RecordedCi, STUB_MODEL_DIGEST, WorkerFixture};

const SLACK: &str = "slack.acme";
const LINEAR: &str = "linear.acme";
const GRANOLA: &str = "granola.acme";
const TEAM: &str = "T07ACME0001";
const PLATENG: &str = "C07PLATENG1";
const ORG: &str = "0a9c0000-0000-4000-8000-0000000ac3e1";
const ENG: &str = "4e6b8d0f-1a2b-4c3d-9e8f-7a6b5c4d3e2f";
const GRANOLA_SCOPE: &str = "workspace.acme-robotics";
const PLATFORM: &str = "fol_4y6LduVdwSKC27";
const ISSUE: &str = "1550e000-0000-4000-8000-000000000001";
const COMMENT: &str = "c0770000-0000-4000-8000-000000000001";
const NOTE: &str = "not_00000000000001";
const MISSING: &str = "unfindable marmoset";

const SLACK_TOKEN_ENV: &str = "FLEET_RECALL_SLACK_TEST_TOKEN";
const LINEAR_TOKEN_ENV: &str = "FLEET_RECALL_LINEAR_TEST_API_KEY";
const GRANOLA_TOKEN_ENV: &str = "FLEET_RECALL_GRANOLA_TEST_API_KEY";
const SLACK_SECRET_ENV: &str = "FLEET_RECALL_SLACK_TEST_SIGNING_SECRET";
const LINEAR_SECRET_ENV: &str = "FLEET_RECALL_LINEAR_TEST_WEBHOOK_SECRET";
const GRANOLA_SECRET_ENV: &str = "FLEET_RECALL_GRANOLA_TEST_WEBHOOK_SECRET";

// Obvious placeholders, never real credentials, each with the shape the
// collector redactor catches wherever it leaks into text.
const SLACK_TOKEN: &str = "xoxb-EXAMPLE-NOT-A-TOKEN";
const LINEAR_KEY: &str = "lin_api_EXAMPLENOTAREALKEYEXAMPLENOTAREAL";
const GRANOLA_KEY: &str = "grn_EXAMPLE_NOT_A_KEY";
const SLACK_SECRET: &str = "EXAMPLE-NOT-A-SIGNING-SECRET";
const LINEAR_SECRET: &str = "lin_wh_EXAMPLENOTASIGNINGSECRET";
const GRANOLA_SECRET: &str = "whsec_EXAMPLEEXAMPLEEXAMPLEEXAMPLE";

fn environment(name: &str) -> Option<String> {
    let value = match name {
        SLACK_TOKEN_ENV => SLACK_TOKEN,
        LINEAR_TOKEN_ENV => LINEAR_KEY,
        GRANOLA_TOKEN_ENV => GRANOLA_KEY,
        SLACK_SECRET_ENV => SLACK_SECRET,
        LINEAR_SECRET_ENV => LINEAR_SECRET,
        GRANOLA_SECRET_ENV => GRANOLA_SECRET,
        _ => return None,
    };
    Some(value.to_owned())
}

// ---------------------------------------------------------------------------
// One fake provider for all three APIs
// ---------------------------------------------------------------------------

/// Whole seconds three days ago: everything the fakes hold is behind the
/// database's clock.
fn base_seconds() -> i64 {
    Utc::now().timestamp() - 3 * 86_400
}

fn slack_ts(seconds: i64, micros: u32) -> String {
    format!("{seconds}.{micros:06}")
}

fn ts_micros(ts: &str) -> i64 {
    let (seconds, fraction) = ts.split_once('.').unwrap();
    seconds.parse::<i64>().unwrap() * 1_000_000 + fraction.parse::<i64>().unwrap()
}

fn iso(seconds: i64) -> String {
    Utc.timestamp_opt(seconds, 0)
        .unwrap()
        .to_rfc3339_opts(SecondsFormat::Millis, true)
}

#[derive(Debug, Default)]
struct World {
    /// Slack: the channel's messages.
    messages: Vec<Value>,
    /// Slack: answer a read bounded to one `ts` (what only a hint sends)
    /// with a 500.
    fail_hinted_reads: bool,
    /// Linear: the issue and its comments.
    issue: Option<Value>,
    comments: Vec<Value>,
    /// Granola: notes by id.
    notes: BTreeMap<String, Value>,
}

impl World {
    fn new(base: i64) -> Self {
        let mut world = Self {
            messages: vec![json!({
                "type": "message", "user": "U07ALICE001", "ts": slack_ts(base + 10, 100),
                "text": "the ingest retry budget is three attempts"
            })],
            ..Self::default()
        };
        world.issue = Some(json!({
            "id": ISSUE, "identifier": "ENG-412", "number": 412, "title": "Cap worker retries",
            "description": "Retry budget for the ingest worker.", "priority": 2,
            "url": "https://linear.app/acme-robotics/issue/ENG-412/cap-worker-retries",
            "createdAt": iso(base + 20), "updatedAt": iso(base + 20), "archivedAt": null,
            "trashed": null, "state": {"name": "In Progress", "type": "started"},
            "team": {"id": ENG}, "creator": {"id": "a11ce000-0000-4000-8000-000000000001"},
            "botActor": null, "externalUserCreator": null, "parent": null, "project": null
        }));
        world.comments.push(json!({
            "id": COMMENT, "body": "a quokka says three keeps p99 under the objective",
            "createdAt": iso(base + 30), "updatedAt": iso(base + 30), "editedAt": null,
            "archivedAt": null, "url": "https://linear.app/acme-robotics/issue/ENG-412#comment-1",
            "issue": {"id": ISSUE}, "parent": null,
            "user": {"id": "b0b00000-0000-4000-8000-000000000002"},
            "botActor": null, "externalUser": null
        }));
        world.notes.insert(
            NOTE.to_owned(),
            json!({
                "id": NOTE, "object": "note", "title": "Retry budget sync",
                "owner": {"name": "Carol Diaz", "email": "carol@acme-robotics.example"},
                "created_at": iso(base + 40), "updated_at": iso(base + 40),
                "web_url": format!("https://notes.granola.ai/d/{NOTE}"),
                "folder_membership": [{"id": PLATFORM, "object": "folder", "name": "Platform",
                                       "parent_folder_id": null}],
                "summary_text": "We keep the retry budget at three.",
                "summary_markdown": "We keep the retry budget at three.",
                "transcript": null
            }),
        );
        world
    }
}

fn slack_page(messages: &[Value]) -> FakeReply {
    FakeReply::json(&json!({
        "ok": true, "messages": messages, "has_more": false,
        "response_metadata": {"next_cursor": ""}
    }))
}

/// The messages in the window a read names, newest first.
fn window(world: &World, request: &FakeRequest) -> Vec<Value> {
    let inclusive = request.param("inclusive") == Some("true");
    let oldest = request.param("oldest").map(ts_micros);
    let latest = request.param("latest").map(ts_micros);
    let mut messages: Vec<Value> = world
        .messages
        .iter()
        .filter(|message| {
            let at = ts_micros(message["ts"].as_str().unwrap());
            oldest.is_none_or(|oldest| if inclusive { at >= oldest } else { at > oldest })
                && latest.is_none_or(|latest| if inclusive { at <= latest } else { at < latest })
        })
        .cloned()
        .collect();
    messages.sort_by_key(|message| std::cmp::Reverse(ts_micros(message["ts"].as_str().unwrap())));
    messages
}

fn slack(world: &World, request: &FakeRequest) -> FakeReply {
    let method = request.path.rsplit('/').next().unwrap_or_default();
    if method.starts_with("conversations.") && request.param("channel") != Some(PLATENG) {
        return FakeReply::json(&json!({"ok": false, "error": "channel_not_found"}));
    }
    match method {
        "auth.test" => FakeReply::json(&json!({
            "ok": true, "url": "https://acme-robotics.slack.com/", "team": "Acme Robotics",
            "team_id": TEAM, "user_id": "U07BOT0001", "bot_id": "B07BOT0001"
        })),
        "conversations.info" => FakeReply::json(&json!({
            "ok": true,
            "channel": {"id": PLATENG, "name": "plat-eng", "is_channel": true, "is_im": false,
                        "is_mpim": false, "is_private": false, "is_ext_shared": false,
                        "is_org_shared": false, "is_pending_ext_shared": false}
        })),
        "conversations.history" => {
            if world.fail_hinted_reads && request.param("inclusive") == Some("true") {
                return FakeReply::status(500, "the history is unavailable");
            }
            slack_page(&window(world, request))
        }
        "conversations.replies" => {
            let root = request.param("ts").unwrap_or_default();
            if !world.messages.iter().any(|message| message["ts"] == root) {
                return FakeReply::json(&json!({"ok": false, "error": "thread_not_found"}));
            }
            slack_page(
                &window(world, request)
                    .into_iter()
                    .filter(|message| message["ts"] == root)
                    .collect::<Vec<_>>(),
            )
        }
        _ => FakeReply::status(404, "unknown method"),
    }
}

fn connection(field: &str, nodes: &[Value]) -> FakeReply {
    FakeReply::json(&json!({"data": {field: {
        "nodes": nodes, "pageInfo": {"hasNextPage": false, "endCursor": null}
    }}}))
}

fn linear(world: &World, request: &FakeRequest) -> FakeReply {
    let body: Value = serde_json::from_slice(&request.body).unwrap_or(Value::Null);
    let filter = &body["variables"]["filter"];
    let issues: Vec<Value> = world.issue.iter().cloned().collect();
    match body["operationName"].as_str().unwrap_or_default() {
        "FleetRecallLinearScope" => FakeReply::json(&json!({"data": {
            "organization": {"id": ORG},
            "teams": {"nodes": [{"id": ENG, "key": "ENG", "name": "Engineering",
                                 "visibility": "public"}]}
        }})),
        "FleetRecallLinearIssues" => connection(
            "issues",
            &issues
                .into_iter()
                .filter(|issue| {
                    filter["id"]["eq"]
                        .as_str()
                        .is_none_or(|id| issue["id"] == id)
                })
                .collect::<Vec<_>>(),
        ),
        "FleetRecallLinearComments" => connection(
            "comments",
            &world
                .comments
                .iter()
                .filter(|comment| {
                    filter["id"]["eq"]
                        .as_str()
                        .is_none_or(|id| comment["id"] == id)
                })
                .cloned()
                .collect::<Vec<_>>(),
        ),
        "FleetRecallLinearIssueTeams" => connection(
            "issues",
            &issues
                .iter()
                .map(|issue| {
                    json!({"id": issue["id"], "updatedAt": issue["updatedAt"],
                           "trashed": null, "team": {"id": ENG}})
                })
                .collect::<Vec<_>>(),
        ),
        _ => FakeReply::status(400, "unknown operation"),
    }
}

fn granola(world: &World, request: &FakeRequest) -> FakeReply {
    if request.path == "/v1/notes" {
        let notes: Vec<Value> = world
            .notes
            .values()
            .map(|note| {
                json!({"id": note["id"], "object": "note", "title": note["title"],
                       "owner": note["owner"], "created_at": note["created_at"],
                       "updated_at": note["updated_at"]})
            })
            .collect();
        return FakeReply::json(&json!({"notes": notes, "hasMore": false, "cursor": null}));
    }
    let id = request.path.strip_prefix("/v1/notes/").unwrap_or_default();
    world.notes.get(id).map_or_else(
        || FakeReply::status(404, r#"{"error":"not_found"}"#),
        FakeReply::json,
    )
}

fn respond(world: &World, request: &FakeRequest) -> FakeReply {
    if request.path.starts_with("/api/") {
        slack(world, request)
    } else if request.path == "/graphql" {
        linear(world, request)
    } else if request.path.starts_with("/v1/notes") {
        granola(world, request)
    } else {
        FakeReply::status(404, "no such route")
    }
}

// ---------------------------------------------------------------------------
// The harness
// ---------------------------------------------------------------------------

struct Harness {
    owner: PgPool,
    database_url: String,
    fixture: WorkerFixture,
    world: Arc<Mutex<World>>,
    fake: FakeProvider,
    receiver: RuntimeProbeRole,
    router: Router,
    /// The receiver's clock, fixed for the test, so every refusal of one
    /// reason falls in one minute.
    now: DateTime<Utc>,
    base: i64,
}

impl Harness {
    async fn new(label: &str) -> Option<Self> {
        let database_url = common::test_database_url()?;
        let owner = common::migrated_pool(&database_url).await;
        let fixture = WorkerFixture::install_at(&owner, label, InstallTargetV1::Generation3).await;
        let base = base_seconds();
        let world = Arc::new(Mutex::new(World::new(base)));
        let served = Arc::clone(&world);
        let fake =
            FakeProvider::start(move |request| respond(&served.lock().unwrap(), request)).await;
        let receiver = RuntimeProbeRole::create_ingress_receiver(&owner, &database_url).await;
        let now = Utc.timestamp_opt(Utc::now().timestamp(), 0).unwrap();
        let mut harness = Self {
            owner,
            database_url,
            fixture,
            world,
            fake,
            receiver,
            router: Router::new(),
            now,
            base,
        };
        harness.router = harness.router_with_limit(1_048_576);
        Some(harness)
    }

    fn world(&self) -> std::sync::MutexGuard<'_, World> {
        self.world.lock().unwrap()
    }

    /// Change the fake providers' world.
    fn change(&self, change: impl FnOnce(&mut World)) {
        change(&mut self.world());
    }

    fn router_with_limit(&self, limit: usize) -> Router {
        let scope = &self.fixture.installed.scope;
        let store =
            IngressStoreV1::new(self.receiver.pool.clone(), scope.tenant_id, &scope.project)
                .unwrap();
        let sources = WorkerSourcesV1::from_json_slice(
            &serde_json::to_vec(&self.sources(&[SLACK, LINEAR, GRANOLA])).unwrap(),
        )
        .unwrap();
        let instances = IngressInstancesV1::from_sources(&sources, &environment).unwrap();
        let now = self.now;
        router(store, instances, Arc::new(move || now), limit)
    }

    /// A sources file configuring `instances`, each with its webhook.
    fn sources(&self, instances: &[&str]) -> Value {
        let base = &self.fake.base;
        let mut collectors = Vec::new();
        if instances.contains(&SLACK) {
            collectors.push(json!({
                "provider": "slack", "connector_principal": "principal.slack",
                "connector_instance": SLACK, "provider_scope_id": TEAM,
                "settings": {"token_env": SLACK_TOKEN_ENV, "channels": [PLATENG],
                             "api_base": format!("{base}/api")},
                "push": {"signing_secret_env": SLACK_SECRET_ENV}
            }));
        }
        if instances.contains(&LINEAR) {
            collectors.push(json!({
                "provider": "linear", "connector_principal": "principal.linear",
                "connector_instance": LINEAR, "provider_scope_id": ORG,
                "settings": {"token_env": LINEAR_TOKEN_ENV, "teams": [ENG],
                             "api_url": format!("{base}/graphql")},
                "push": {"signing_secret_env": LINEAR_SECRET_ENV}
            }));
        }
        if instances.contains(&GRANOLA) {
            collectors.push(json!({
                "provider": "granola", "connector_principal": "principal.granola",
                "connector_instance": GRANOLA, "provider_scope_id": GRANOLA_SCOPE,
                "audience": {"operator_declared": true},
                "settings": {"token_env": GRANOLA_TOKEN_ENV, "folders": [PLATFORM],
                             "api_base": format!("{base}/v1")},
                "push": {"signing_secret_env": GRANOLA_SECRET_ENV}
            }));
        }
        json!({"schema_version": 1, "coverage_since": "2026-08-01T00:00:00Z",
               "collectors": collectors})
    }

    async fn tick_as(&self, pool: &PgPool, instances: &[&str]) -> WorkerTickReportV1 {
        let report = self
            .fixture
            .worker_with(
                pool,
                "collect,project",
                &self.sources(instances),
                Arc::new(RecordedCi),
            )
            .await
            .with_collector_environment(Arc::new(environment))
            .run_tick()
            .await;
        assert!(
            !report.failed(),
            "the tick must succeed: {}",
            serde_json::to_string_pretty(&report).unwrap()
        );
        report
    }

    async fn tick(&self, instances: &[&str]) -> WorkerTickReportV1 {
        self.tick_as(&self.owner, instances).await
    }

    async fn post_to(
        &self,
        router: &Router,
        instance: &str,
        headers: &[(&str, String)],
        body: Vec<u8>,
    ) -> (u16, Vec<u8>) {
        let mut request = Request::builder()
            .method("POST")
            .uri(format!("/v1/hooks/{instance}"))
            .header("content-type", "application/json");
        for (name, value) in headers {
            request = request.header(*name, value);
        }
        let response = router
            .clone()
            .oneshot(request.body(Body::from(body)).unwrap())
            .await
            .unwrap();
        let status = response.status().as_u16();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        (status, body.to_vec())
    }

    async fn post(&self, instance: &str, headers: &[(&str, String)], body: Vec<u8>) -> u16 {
        self.post_to(&self.router, instance, headers, body).await.0
    }

    /// A Slack delivery of `body`, signed at `at` (seconds) with `secret`.
    fn slack_signed(body: &Value, at: i64, secret: &str) -> (Vec<(&'static str, String)>, Vec<u8>) {
        let body = serde_json::to_vec(body).unwrap();
        let timestamp = at.to_string();
        let mut message = format!("v0:{timestamp}:").into_bytes();
        message.extend_from_slice(&body);
        let signature = format!("v0={}", hex::encode(sign(secret.as_bytes(), &message)));
        (
            vec![
                ("x-slack-request-timestamp", timestamp),
                ("x-slack-signature", signature),
            ],
            body,
        )
    }

    fn slack_event(&self, event_id: &str, team: &str, event: &Value) -> Value {
        json!({"token": "XXYYZZ-legacy-verification-token-do-not-use", "team_id": team,
               "api_app_id": "A07RECALL01", "event": event, "type": "event_callback",
               "event_id": event_id, "event_time": self.now.timestamp()})
    }

    async fn post_slack(&self, body: &Value) -> u16 {
        let (headers, body) = Self::slack_signed(body, self.now.timestamp(), SLACK_SECRET);
        self.post(SLACK, &headers, body).await
    }

    async fn post_linear(&self, body: &Value) -> u16 {
        let body = serde_json::to_vec(body).unwrap();
        let signature = hex::encode(sign(LINEAR_SECRET.as_bytes(), &body));
        self.post(LINEAR, &[("linear-signature", signature)], body)
            .await
    }

    async fn post_granola(&self, id: &str, body: &Value) -> u16 {
        let body = serde_json::to_vec(body).unwrap();
        let timestamp = self.now.timestamp().to_string();
        let key = standard_webhooks_key(GRANOLA_SECRET).unwrap();
        let mut message = format!("{id}.{timestamp}.").into_bytes();
        message.extend_from_slice(&body);
        let signature = format!("v1,{}", base64::encode(&sign(&key, &message)));
        self.post(
            GRANOLA,
            &[
                ("webhook-id", id.to_owned()),
                ("webhook-timestamp", timestamp),
                ("webhook-signature", signature),
            ],
            body,
        )
        .await
    }

    /// The message the Slack fake holds first.
    fn message_ts(&self) -> String {
        self.world().messages[0]["ts"].as_str().unwrap().to_owned()
    }

    async fn count(&self, sql: &str, instance: &str) -> i64 {
        sqlx::query_scalar(sql)
            .bind(self.fixture.installed.scope.tenant_id)
            .bind(&self.fixture.installed.scope.project)
            .bind(instance)
            .fetch_one(&self.owner)
            .await
            .unwrap()
    }

    async fn deliveries(&self, instance: &str) -> i64 {
        self.count(
            "SELECT count(*) FROM memory_ingress_deliveries_v1 \
             WHERE tenant_id = $1 AND project = $2 AND collector_instance_id = $3",
            instance,
        )
        .await
    }

    async fn dead_letters(&self, instance: &str, reason: &str) -> i64 {
        sqlx::query_scalar(
            "SELECT count(*) FROM memory_collector_dead_letters_v1 \
             WHERE tenant_id = $1 AND project = $2 AND collector_instance_id = $3 \
               AND reason = $4",
        )
        .bind(self.fixture.installed.scope.tenant_id)
        .bind(&self.fixture.installed.scope.project)
        .bind(instance)
        .bind(reason)
        .fetch_one(&self.owner)
        .await
        .unwrap()
    }

    async fn receipts(&self, instance: &str) -> i64 {
        self.count(
            "SELECT count(*) FROM memory_coverage_receipts_v1 \
             WHERE tenant_id = $1 AND project = $2 AND connector_instance_id = $3",
            instance,
        )
        .await
    }

    /// Every delivery of `instance`: `(key, disposition, state, attempts,
    /// external id, container id)`.
    async fn rows(
        &self,
        instance: &str,
    ) -> Vec<(Vec<u8>, String, String, i64, Option<String>, Option<String>)> {
        sqlx::query_as(
            "SELECT delivery_key, disposition, state, attempts, external_id, container_id \
             FROM memory_ingress_deliveries_v1 \
             WHERE tenant_id = $1 AND project = $2 AND collector_instance_id = $3 \
             ORDER BY received_at, delivery_key",
        )
        .bind(self.fixture.installed.scope.tenant_id)
        .bind(&self.fixture.installed.scope.project)
        .bind(instance)
        .fetch_all(&self.owner)
        .await
        .unwrap()
    }

    /// An item's verified head: its lifecycle and how many versions it saw.
    async fn head(&self, object_kind: &str, external_id: &str) -> (String, i64) {
        sqlx::query_as(
            "SELECT lifecycle, version_count FROM memory_collected_item_heads_v1 \
             WHERE tenant_id = $1 AND project = $2 AND object_kind = $3 AND external_id = $4 \
               AND trust_tier = 'verified'",
        )
        .bind(self.fixture.installed.scope.tenant_id)
        .bind(&self.fixture.installed.scope.project)
        .bind(object_kind)
        .bind(external_id)
        .fetch_one(&self.owner)
        .await
        .unwrap()
    }

    async fn capabilities(&self) -> DatabaseCapabilities {
        CockroachStore::from_pool(self.owner.clone(), self.fixture.installed.scope.clone())
            .unwrap()
            .capabilities()
            .await
            .unwrap()
    }

    async fn items(&self, provider: &str, query: &str) -> ItemSearchV1 {
        self.items_as(&self.owner, provider, query).await
    }

    async fn items_as(&self, pool: &PgPool, provider: &str, query: &str) -> ItemSearchV1 {
        let scope = &self.fixture.installed.scope;
        let capability = probe_item_recall(
            pool,
            &self.capabilities().await,
            scope,
            Sha256Digest::from_bytes(STUB_MODEL_DIGEST),
        )
        .await
        .unwrap()
        .expect("the login may read every item-recall table");
        CockroachItemRecall::new(capability, pool.clone())
            .search(
                &ItemSearchRequestV1 {
                    query: query.to_owned(),
                    provider: Some(ProviderKindV1::new(provider).unwrap()),
                    include_history: false,
                    limit: 20,
                },
                None,
            )
            .await
            .unwrap()
    }

    async fn evidence(&self, query: &str) -> EvidenceSearchV1 {
        self.evidence_as(&self.owner, query).await
    }

    async fn evidence_as(&self, pool: &PgPool, query: &str) -> EvidenceSearchV1 {
        let scope = &self.fixture.installed.scope;
        let capability = probe_evidence_recall(
            pool,
            &self.capabilities().await,
            scope,
            Sha256Digest::from_bytes(STUB_MODEL_DIGEST),
        )
        .await
        .unwrap()
        .expect("the login may read every evidence table");
        CockroachEvidenceRecall::new(capability, pool.clone())
            .search(query, None, 20)
            .await
            .unwrap()
    }

    async fn finish(self) {
        self.receiver.drop_role(&self.owner).await;
    }
}

fn counter(report: &WorkerTickReportV1, instance: &str, key: &str) -> u64 {
    report
        .step(WorkerStepV1::Collect)
        .expect("the collect step ran")
        .sources
        .iter()
        .find(|source| source.connector_instance == instance)
        .expect("the collector reported")
        .counters
        .get(key)
        .copied()
        .unwrap_or(0)
}

fn hits(search: &ItemSearchV1) -> Vec<&str> {
    search
        .hits
        .iter()
        .map(|hit| hit.external_id.as_str())
        .collect()
}

// ---------------------------------------------------------------------------
// Slack: an edit re-read, a replay, a deletion, and no coverage
// ---------------------------------------------------------------------------

#[tokio::test]
#[allow(clippy::too_many_lines)] // one flow: pull, edit hint, delete hint, stray delete
async fn live_slack_hints_re_read_edits_and_tombstone_deletions_when_configured() {
    let Some(harness) = Harness::new("ingress-slack").await else {
        return;
    };
    // The worker runs under the runtime role's grants: SELECT and UPDATE on
    // the hint queue suffice to settle hints.
    let worker = RuntimeProbeRole::create_worker(&harness.owner, &harness.database_url, true).await;
    harness.tick_as(&worker.pool, &[SLACK]).await;
    let ts = harness.message_ts();
    let external = format!("{PLATENG}:{ts}");
    assert_eq!(harness.head("message", &external).await, ("live".into(), 1));
    let receipts = harness.receipts(SLACK).await;
    assert!(receipts > 0, "the first pass reconciles");

    // The message is edited, and Slack says so.
    let edited = slack_ts(harness.base + 500, 300);
    harness.change(|world| {
        world.messages[0]["text"] =
            json!("the ingest retry budget is five attempts, a pangolin said");
        world.messages[0]["edited"] = json!({"user": "U07ALICE001", "ts": edited});
    });
    let changed = harness.slack_event(
        "Ev07CHG00001",
        TEAM,
        &json!({"type": "message", "subtype": "message_changed", "hidden": true,
                "channel": PLATENG, "channel_type": "channel", "ts": edited, "event_ts": edited,
                "message": {"type": "message", "user": "U07ALICE001", "ts": ts,
                            "text": "the ingest retry budget is five attempts",
                            "edited": {"user": "U07ALICE001", "ts": edited}}}),
    );
    assert_eq!(harness.post_slack(&changed).await, 200);
    assert_eq!(
        harness.post_slack(&changed).await,
        200,
        "a replay is accepted"
    );
    let rows = harness.rows(SLACK).await;
    assert_eq!(rows.len(), 1, "a replay adds no row");
    let (key, disposition, state, attempts, hinted, container) = rows[0].clone();
    assert_eq!(
        (disposition.as_str(), state.as_str(), attempts),
        ("hint", "pending", 0)
    );
    assert_eq!(hinted.as_deref(), Some(external.as_str()));
    assert_eq!(container.as_deref(), Some(PLATENG));

    harness.fake.clear_requests();
    let report = harness.tick_as(&worker.pool, &[SLACK]).await;
    assert_eq!(counter(&report, SLACK, "hints_settled"), 1);
    assert_eq!(counter(&report, SLACK, "hints_staged"), 1);
    assert_eq!(harness.rows(SLACK).await[0].2, "settled");
    assert_eq!(
        harness.head("message", &external).await,
        ("edited".into(), 2)
    );
    // The hint read exactly the one message, bounded to its ts.
    assert!(harness.fake.requests().iter().any(|request| {
        request.path.ends_with("conversations.history")
            && request.param("inclusive") == Some("true")
            && request.param("oldest") == Some(ts.as_str())
            && request.param("latest") == Some(ts.as_str())
    }));
    // What the hint staged carries its key as its transport delivery.
    let staged_by_hint: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM memory_collector_outbox_v1 \
         WHERE tenant_id = $1 AND project = $2 AND delivery_id = $3 \
           AND collection_mode = 'pull' AND pass_seq IS NULL",
    )
    .bind(harness.fixture.installed.scope.tenant_id)
    .bind(&harness.fixture.installed.scope.project)
    .bind(&key)
    .fetch_one(&harness.owner)
    .await
    .unwrap();
    assert_eq!(staged_by_hint, 1);
    assert_eq!(
        hits(&harness.items("slack", "pangolin").await),
        [external.as_str()]
    );

    // Slack deletes it: a push tombstone hides it at once.
    let deleted = slack_ts(harness.now.timestamp(), 100);
    let removal = harness.slack_event(
        "Ev07DEL00001",
        TEAM,
        &json!({"type": "message", "subtype": "message_deleted", "hidden": true,
                "channel": PLATENG, "channel_type": "channel", "ts": deleted,
                "event_ts": deleted, "deleted_ts": ts,
                "previous_message": {"type": "message", "ts": ts, "text": ""}}),
    );
    assert_eq!(harness.post_slack(&removal).await, 200);
    harness.change(|world| world.messages.clear());
    let report = harness.tick_as(&worker.pool, &[SLACK]).await;
    assert_eq!(counter(&report, SLACK, "hints_tombstones"), 1);
    assert_eq!(harness.head("message", &external).await.0, "deleted");
    assert!(harness.items("slack", "pangolin").await.hits.is_empty());
    assert!(harness.evidence("pangolin").await.hits.is_empty());
    let pushed: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM memory_collected_items_v1 \
         WHERE tenant_id = $1 AND project = $2 AND external_id = $3 \
           AND collection_mode = 'push' AND lifecycle = 'deleted'",
    )
    .bind(harness.fixture.installed.scope.tenant_id)
    .bind(&harness.fixture.installed.scope.project)
    .bind(&external)
    .fetch_one(&harness.owner)
    .await
    .unwrap();
    assert_eq!(pushed, 1);
    // A hint never writes coverage: only the first pass's reconciliation did.
    assert_eq!(harness.receipts(SLACK).await, receipts);
    // A deletion of something the memory never held mints nothing.
    let unknown = harness.slack_event(
        "Ev07DEL00002",
        TEAM,
        &json!({"type": "message", "subtype": "message_deleted", "channel": PLATENG,
                "channel_type": "channel", "ts": deleted, "event_ts": deleted,
                "deleted_ts": slack_ts(harness.base + 9, 1)}),
    );
    assert_eq!(harness.post_slack(&unknown).await, 200);
    let report = harness.tick_as(&worker.pool, &[SLACK]).await;
    assert_eq!(counter(&report, SLACK, "hints_settled"), 1);
    assert_eq!(counter(&report, SLACK, "hints_tombstones"), 0);

    worker.drop_role(&harness.owner).await;
    harness.finish().await;
}

// ---------------------------------------------------------------------------
// Linear: a comment removal is a push tombstone; another organization is 403
// ---------------------------------------------------------------------------

#[tokio::test]
async fn live_linear_hints_re_read_an_issue_and_tombstone_a_removed_comment_when_configured() {
    let Some(harness) = Harness::new("ingress-linear").await else {
        return;
    };
    harness.tick(&[LINEAR]).await;
    assert_eq!(harness.head("comment", COMMENT).await, ("live".into(), 1));
    assert_eq!(hits(&harness.items("linear", "quokka").await), [COMMENT]);

    // An issue update: the hint re-reads the issue by id, before the sweep.
    let updated = iso(harness.base + 950);
    harness.change(|world| {
        let issue = world.issue.as_mut().unwrap();
        issue["description"] =
            json!("Retry budget for the ingest worker is five, says an axolotl.");
        issue["updatedAt"] = json!(updated);
    });
    let update = json!({"action": "update", "type": "Issue", "createdAt": updated,
                        "organizationId": ORG, "webhookTimestamp": harness.now.timestamp_millis(),
                        "data": {"id": ISSUE, "identifier": "ENG-412", "teamId": ENG,
                                 "title": "Cap worker retries", "updatedAt": updated}});
    assert_eq!(harness.post_linear(&update).await, 200);
    let report = harness.tick(&[LINEAR]).await;
    assert_eq!(counter(&report, LINEAR, "hints_staged"), 1);
    assert_eq!(harness.head("issue", ISSUE).await, ("live".into(), 2));
    assert_eq!(hits(&harness.items("linear", "axolotl").await), [ISSUE]);
    let by_id = harness.fake.requests().iter().any(|request| {
        let body: Value = serde_json::from_slice(&request.body).unwrap_or(Value::Null);
        body["operationName"] == "FleetRecallLinearIssues"
            && body["variables"]["filter"]["id"]["eq"] == ISSUE
    });
    assert!(by_id, "the hint read the one issue by its id");

    let removal = |organization: &str| {
        json!({"action": "remove", "type": "Comment", "createdAt": iso(harness.now.timestamp()),
               "organizationId": organization,
               "webhookId": "3eb40000-0000-4000-8000-000000000001",
               "webhookTimestamp": harness.now.timestamp_millis(),
               "url": "https://linear.app/acme-robotics/issue/ENG-412#comment-1",
               "data": {"id": COMMENT, "body": "a quokka says three", "issueId": ISSUE,
                        "createdAt": iso(harness.base + 30),
                        "updatedAt": iso(harness.now.timestamp())}})
    };
    assert_eq!(
        harness
            .post_linear(&removal("1b2c0000-0000-4000-8000-000000000bad"))
            .await,
        403,
        "another organization"
    );
    assert_eq!(harness.dead_letters(LINEAR, "unauthorized_scope").await, 1);
    assert_eq!(
        harness.deliveries(LINEAR).await,
        1,
        "the refusal is no delivery: only the update is"
    );

    assert_eq!(harness.post_linear(&removal(ORG)).await, 200);
    harness.change(|world| world.comments.clear());
    let report = harness.tick(&[LINEAR]).await;
    assert_eq!(counter(&report, LINEAR, "hints_tombstones"), 1);
    assert_eq!(harness.head("comment", COMMENT).await.0, "deleted");
    assert!(harness.items("linear", "quokka").await.hits.is_empty());
    assert!(harness.evidence("quokka").await.hits.is_empty());
    assert_eq!(harness.rows(LINEAR).await[0].2, "settled");
    harness.finish().await;
}

// ---------------------------------------------------------------------------
// Granola: a pending hint keeps an empty answer unknown until it is read
// ---------------------------------------------------------------------------

#[tokio::test]
async fn live_granola_edit_keeps_absence_unknown_until_the_note_is_read_when_configured() {
    let Some(harness) = Harness::new("ingress-granola").await else {
        return;
    };
    harness.tick(&[GRANOLA]).await;
    let before = harness.evidence(MISSING).await;
    assert_eq!(before.readiness.hints_awaiting_fetch, Some(0));
    assert!(
        !before
            .absence
            .reasons
            .contains(&AbsenceReasonV1::IngestOutboxPending)
    );

    harness.change(|world| {
        let note = world.notes.get_mut(NOTE).unwrap();
        note["updated_at"] = json!(iso(harness.base + 900));
        note["summary_markdown"] = json!("We raise the retry budget to five, the narwhal agreed.");
        note["summary_text"] = json!("We raise the retry budget to five, the narwhal agreed.");
    });
    let edited = json!({"event_id": "evt_01J8ZC7Q2M5N8P3R6T9V1W4X7Y", "event_type": "note.edited",
                        "note_id": NOTE, "occurred_at": iso(harness.now.timestamp()),
                        "data": {"changed_fields": ["summary"]}});
    assert_eq!(
        harness
            .post_granola("msg_EXAMPLE0000000000000001", &edited)
            .await,
        200
    );
    let waiting = harness.evidence(MISSING).await;
    assert_eq!(waiting.readiness.hints_awaiting_fetch, Some(1));
    assert!(
        waiting
            .absence
            .reasons
            .contains(&AbsenceReasonV1::IngestOutboxPending),
        "{:?}",
        waiting.absence
    );
    let items = harness.items("granola", MISSING).await;
    assert_eq!(items.readiness.hints_awaiting_fetch, Some(1));
    assert!(
        items
            .absence
            .reasons
            .contains(&AbsenceReasonV1::IngestOutboxPending)
    );

    let report = harness.tick(&[GRANOLA]).await;
    assert_eq!(counter(&report, GRANOLA, "hints_settled"), 1);
    assert_eq!(counter(&report, GRANOLA, "hints_staged"), 1);
    let read = harness.evidence(MISSING).await;
    assert_eq!(read.readiness.hints_awaiting_fetch, Some(0));
    assert!(
        !read
            .absence
            .reasons
            .contains(&AbsenceReasonV1::IngestOutboxPending)
    );
    assert_eq!(hits(&harness.items("granola", "narwhal").await), [NOTE]);
    harness.finish().await;
}

// ---------------------------------------------------------------------------
// A fetch that keeps failing: eight attempts, dead, retried
// ---------------------------------------------------------------------------

#[tokio::test]
async fn live_a_hint_whose_fetch_keeps_failing_dies_and_is_retried_when_configured() {
    let Some(harness) = Harness::new("ingress-dead").await else {
        return;
    };
    harness.tick(&[SLACK]).await;
    let ts = harness.message_ts();
    harness.change(|world| world.fail_hinted_reads = true);
    let changed = harness.slack_event(
        "Ev07CHG00002",
        TEAM,
        &json!({"type": "message", "subtype": "message_changed", "channel": PLATENG,
                "channel_type": "channel", "ts": slack_ts(harness.base + 600, 1),
                "message": {"type": "message", "ts": ts, "text": "x"}}),
    );
    assert_eq!(harness.post_slack(&changed).await, 200);
    let key = harness.rows(SLACK).await[0].0.clone();
    let due = || async {
        sqlx::query(
            "UPDATE memory_ingress_deliveries_v1 SET next_attempt_at = NULL \
             WHERE tenant_id = $1 AND project = $2 AND delivery_key = $3",
        )
        .bind(harness.fixture.installed.scope.tenant_id)
        .bind(&harness.fixture.installed.scope.project)
        .bind(&key)
        .execute(&harness.owner)
        .await
        .unwrap();
    };
    for attempt in 1..=8_i64 {
        let report = harness.tick(&[SLACK]).await;
        let (_, _, state, attempts, _, _) = harness.rows(SLACK).await[0].clone();
        assert_eq!(attempts, attempt);
        if attempt < 8 {
            assert_eq!(state, "pending");
            assert_eq!(counter(&report, SLACK, "hints_retried"), 1);
            // Backed off: the next tick does not read it until it is due.
            due().await;
        } else {
            assert_eq!(state, "dead");
            assert_eq!(counter(&report, SLACK, "hints_dead"), 1);
        }
    }
    assert_eq!(harness.dead_letters(SLACK, "retry_exhausted").await, 1);
    let letter: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT delivery_id FROM memory_collector_dead_letters_v1 \
         WHERE tenant_id = $1 AND project = $2 AND reason = 'retry_exhausted'",
    )
    .bind(harness.fixture.installed.scope.tenant_id)
    .bind(&harness.fixture.installed.scope.project)
    .fetch_one(&harness.owner)
    .await
    .unwrap();
    assert_eq!(letter.as_deref(), Some(key.as_slice()));

    // `collect retry --delivery` reopens it; the next tick reads it.
    let capabilities = harness.capabilities().await;
    let lookup = |_: &str| None::<String>;
    let mut out = Vec::new();
    let owner = harness.owner.clone();
    let document = run_collect_command(
        &CollectCommandV1::Retry {
            delivery: hex::encode(&key),
        },
        CollectProcessV1 {
            scope: harness.fixture.installed.scope.clone(),
            lookup: &lookup,
            retry: RetryPolicy::default(),
        },
        move || async move { Ok((owner, capabilities)) },
        &mut out,
    )
    .await
    .unwrap();
    assert_eq!(document["reopened"], true);
    assert_eq!(document["instance"], SLACK);
    let (_, _, state, attempts, _, _) = harness.rows(SLACK).await[0].clone();
    assert_eq!((state.as_str(), attempts), ("pending", 0));
    harness.change(|world| world.fail_hinted_reads = false);
    let report = harness.tick(&[SLACK]).await;
    assert_eq!(counter(&report, SLACK, "hints_settled"), 1);
    assert_eq!(harness.rows(SLACK).await[0].2, "settled");
    harness.finish().await;
}

// ---------------------------------------------------------------------------
// What the receiver refuses, and what its login cannot do
// ---------------------------------------------------------------------------

#[tokio::test]
#[allow(clippy::too_many_lines)] // every refusal and grant boundary on one receiver
async fn live_the_receiver_refuses_what_it_cannot_verify_when_configured() {
    let Some(harness) = Harness::new("ingress-refusals").await else {
        return;
    };
    let scope = &harness.fixture.installed.scope;
    IngressStoreV1::new(
        harness.receiver.pool.clone(),
        scope.tenant_id,
        &scope.project,
    )
    .unwrap()
    .probe()
    .await
    .expect("the receiver's grants pass its probe");
    let message = |id: &str| {
        harness.slack_event(
            id,
            TEAM,
            &json!({"type": "message", "channel": PLATENG, "channel_type": "channel",
                    "ts": slack_ts(harness.base + 700, 1), "text": "hello"}),
        )
    };

    // An instance that takes no webhook: 404, nothing written.
    let (headers, body) =
        Harness::slack_signed(&message("Ev07X"), harness.now.timestamp(), SLACK_SECRET);
    assert_eq!(harness.post("docs.specs", &headers, body).await, 404);

    // A bad signature, three times in one minute: 401, one dead letter.
    for index in 0..3 {
        let (headers, body) = Harness::slack_signed(
            &message(&format!("Ev07BAD{index}")),
            harness.now.timestamp(),
            "EXAMPLE-NOT-THE-SIGNING-SECRET",
        );
        assert_eq!(harness.post(SLACK, &headers, body).await, 401);
    }
    assert_eq!(harness.dead_letters(SLACK, "invalid_signature").await, 1);
    // Signed ten minutes ago: stale.
    let (headers, body) = Harness::slack_signed(
        &message("Ev07OLD"),
        harness.now.timestamp() - 600,
        SLACK_SECRET,
    );
    assert_eq!(harness.post(SLACK, &headers, body).await, 401);
    assert_eq!(harness.dead_letters(SLACK, "stale_signature").await, 1);
    // Another team: 403.
    assert_eq!(
        harness
            .post_slack(&harness.slack_event(
                "Ev07OTHER",
                "T07OTHER001",
                &json!({"type": "message", "channel": PLATENG, "ts": slack_ts(harness.base, 1)}),
            ))
            .await,
        403
    );
    assert_eq!(harness.dead_letters(SLACK, "unauthorized_scope").await, 1);
    assert_eq!(
        harness.deliveries(SLACK).await,
        0,
        "no refusal is a delivery"
    );

    // Larger than the body limit: 413 and an oversize dead letter.
    let small = harness.router_with_limit(256);
    let (headers, body) = Harness::slack_signed(
        &json!({"type": "event_callback", "padding": "x".repeat(1_024)}),
        harness.now.timestamp(),
        SLACK_SECRET,
    );
    assert_eq!(harness.post_to(&small, SLACK, &headers, body).await.0, 413);
    assert_eq!(harness.dead_letters(SLACK, "oversize").await, 1);

    // URL verification is echoed once its signature verifies.
    let (headers, body) = Harness::slack_signed(
        &json!({"token": "XXYYZZ-legacy-verification-token-do-not-use",
                "challenge": "EXAMPLE-CHALLENGE-NOT-A-SECRET", "type": "url_verification"}),
        harness.now.timestamp(),
        SLACK_SECRET,
    );
    let (status, echoed) = harness
        .post_to(&harness.router, SLACK, &headers, body)
        .await;
    assert_eq!(status, 200);
    assert_eq!(echoed, b"EXAMPLE-CHALLENGE-NOT-A-SECRET");

    // A direct message is kept only as a replay guard, with no ids.
    let direct = harness.slack_event(
        "Ev07DM00001",
        TEAM,
        &json!({"type": "message", "channel": "D07DIRECT01", "channel_type": "im",
                "ts": slack_ts(harness.base + 800, 1), "text": "a private word"}),
    );
    assert_eq!(harness.post_slack(&direct).await, 200);
    let rows = harness.rows(SLACK).await;
    let dispositions: Vec<(&str, &str, Option<&str>, Option<&str>)> = rows
        .iter()
        .map(|(_, disposition, state, _, external, container)| {
            (
                disposition.as_str(),
                state.as_str(),
                external.as_deref(),
                container.as_deref(),
            )
        })
        .collect();
    assert!(dispositions.contains(&("challenge", "none", None, None)));
    assert!(dispositions.contains(&("ignored", "none", None, None)));
    assert_eq!(dispositions.len(), 2);
    let hint_kinds: i64 = harness
        .count(
            "SELECT count(*) FROM memory_ingress_deliveries_v1 \
             WHERE tenant_id = $1 AND project = $2 AND collector_instance_id = $3 \
               AND (hint_kind IS NOT NULL OR object_kind IS NOT NULL \
                    OR provider_event_at IS NOT NULL)",
            SLACK,
        )
        .await;
    assert_eq!(hint_kinds, 0, "an ignored delivery keeps no ids");

    // The receiver's login reads and inserts deliveries and dead letters,
    // and nothing else.
    for table in [
        "memory_evidence_events",
        "memory_content_objects",
        "memory_collected_items_v1",
        "memory_collected_item_heads_v1",
        "memory_collector_outbox_v1",
        "memory_claims",
    ] {
        let refused = sqlx::query(&format!("SELECT 1 FROM public.{table} LIMIT 1"))
            .execute(&harness.receiver.pool)
            .await
            .unwrap_err();
        assert_eq!(
            refused
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::code)
                .as_deref(),
            Some("42501"),
            "the receiver must not read {table}"
        );
    }
    let settle = sqlx::query(
        "UPDATE memory_ingress_deliveries_v1 SET state = 'settled' WHERE tenant_id = $1",
    )
    .bind(scope.tenant_id)
    .execute(&harness.receiver.pool)
    .await
    .unwrap_err();
    assert_eq!(
        settle
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .as_deref(),
        Some("42501"),
        "only the worker settles a hint"
    );
    let reader =
        RuntimeProbeRole::create_publication_reader(&harness.owner, &harness.database_url).await;
    let public = sqlx::query("SELECT 1 FROM public.memory_ingress_deliveries_v1 LIMIT 1")
        .execute(&reader.pool)
        .await;
    reader.drop_role(&harness.owner).await;
    assert_eq!(
        public
            .unwrap_err()
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .as_deref(),
        Some("42501"),
        "the publication reader never reads the hint queue"
    );

    // The database fails before the commit: 503, so the provider retries.
    harness.receiver.pool.close().await;
    assert_eq!(harness.post_slack(&message("Ev07LATE")).await, 503);
    harness.finish().await;
}

// ---------------------------------------------------------------------------
// Readiness: only hints a worker collector reads count; an unreadable queue
// is unknown
// ---------------------------------------------------------------------------

#[tokio::test]
async fn live_hint_readiness_counts_worker_collectors_and_fails_closed_when_configured() {
    let Some(harness) = Harness::new("ingress-readiness").await else {
        return;
    };
    harness.tick(&[SLACK]).await;
    let ts = harness.message_ts();
    let changed = harness.slack_event(
        "Ev07CHG00010",
        TEAM,
        &json!({"type": "message", "subtype": "message_changed", "channel": PLATENG,
                "channel_type": "channel", "ts": slack_ts(harness.base + 600, 1),
                "message": {"type": "message", "ts": ts, "text": "x"}}),
    );
    assert_eq!(harness.post_slack(&changed).await, 200);
    // A hint for an instance the worker never ran is never read: not counted.
    let edited = json!({"event_id": "evt_01J8ZC7Q2M5N8P3R6T9V1W4X70", "event_type": "note.edited",
                        "note_id": NOTE, "occurred_at": iso(harness.now.timestamp())});
    assert_eq!(
        harness
            .post_granola("msg_EXAMPLE0000000000000010", &edited)
            .await,
        200
    );
    let waiting = harness.evidence(MISSING).await;
    assert_eq!(waiting.readiness.hints_awaiting_fetch, Some(1));
    assert!(!waiting.readiness.hints_unreadable);

    // The worker retires the Slack collector: its hint is never read, so it
    // no longer keeps every empty answer unknown, and still waits.
    let retire = |state: &'static str| {
        let owner = harness.owner.clone();
        let scope = harness.fixture.installed.scope.clone();
        async move {
            sqlx::query(
                "UPDATE memory_collector_sources_v1 SET state = $4 \
                 WHERE tenant_id = $1 AND project = $2 AND collector_instance_id = $3",
            )
            .bind(scope.tenant_id)
            .bind(&scope.project)
            .bind(SLACK)
            .bind(state)
            .execute(&owner)
            .await
            .unwrap();
        }
    };
    retire("retired").await;
    let retired = harness.evidence(MISSING).await;
    assert_eq!(retired.readiness.hints_awaiting_fetch, Some(0));
    assert!(
        !retired
            .absence
            .reasons
            .contains(&AbsenceReasonV1::IngestOutboxPending),
        "{:?}",
        retired.absence
    );
    assert_eq!(harness.rows(SLACK).await[0].2, "pending");
    retire("active").await;
    assert_eq!(
        harness
            .items("slack", MISSING)
            .await
            .readiness
            .hints_awaiting_fetch,
        Some(1),
        "configured again, it counts again"
    );

    // A login that cannot read the queue never reads it as empty.
    let serve = RuntimeProbeRole::create_serve_writer(&harness.owner, &harness.database_url).await;
    sqlx::query(&format!(
        "REVOKE ALL ON TABLE public.memory_ingress_deliveries_v1 FROM {}",
        serve.name()
    ))
    .execute(&harness.owner)
    .await
    .unwrap();
    let blind = harness.evidence_as(&serve.pool, MISSING).await;
    assert!(blind.readiness.hints_unreadable);
    assert_eq!(blind.readiness.hints_awaiting_fetch, None);
    assert_eq!(blind.absence.verdict, AbsenceVerdictV1::Unknown);
    assert!(
        blind
            .absence
            .reasons
            .contains(&AbsenceReasonV1::CollectorStateUnreadable),
        "{:?}",
        blind.absence
    );
    let items = harness.items_as(&serve.pool, "slack", MISSING).await;
    assert!(items.readiness.hints_unreadable);
    assert!(
        items
            .absence
            .reasons
            .contains(&AbsenceReasonV1::CollectorStateUnreadable),
        "{:?}",
        items.absence
    );
    serve.drop_role(&harness.owner).await;
    harness.finish().await;
}

// ---------------------------------------------------------------------------
// The binary
// ---------------------------------------------------------------------------

#[test]
fn a_listen_address_that_is_not_loopback_is_refused_without_the_flag() {
    assert!(validate_listen("0.0.0.0:8787".parse().unwrap(), false).is_err());
    assert!(validate_listen("0.0.0.0:8787".parse().unwrap(), true).is_ok());
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_ostk-fleet-recall"))
        .args([
            "ingress",
            "--sources",
            "/nonexistent/worker-sources.json",
            "--listen",
            "0.0.0.0:8787",
        ])
        .env_clear()
        .output()
        .expect("the binary runs");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--allow-non-loopback"), "{stderr}");
}
