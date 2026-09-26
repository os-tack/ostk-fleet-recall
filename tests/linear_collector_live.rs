//! Connected proofs of the Linear collector (ADR 0008 D8): a worker tick
//! pulls a fake organization through the GraphQL operations the collector
//! sends, served by a local fake provider, and item and evidence recall read
//! the issues and comments back. A sweep of two pages is complete and makes
//! absence sound; a rate limit on page two leaves the team partial and the
//! next tick resumes from the page after the last one staged; a newer
//! `updatedAt` with new content moves the head, while an overlap re-read or a
//! change that is not content stages nothing; a private team is read only
//! when listed; a trashed issue is hidden and an archived one stays; a key of
//! another organization reads nothing; the key is found in no table.
//!
//! Every connected test needs `FLEET_RECALL_TEST_DATABASE_URL` and returns at
//! once without it. No test reaches Linear.

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
    WorkerSourceOutcomeV1, WorkerSourceReportV1, WorkerSourcesV1, WorkerStepStatusV1, WorkerStepV1,
    WorkerTickReportV1,
};
use serde_json::{Value, json};
use sqlx::PgPool;

use common::fake_provider::{FakeProvider, FakeReply, FakeRequest};
use common::worker::{RecordedCi, STUB_MODEL_DIGEST, WorkerFixture};

const INSTANCE: &str = "linear.acme";
const ORG: &str = "0a9c0000-0000-4000-8000-0000000ac3e1";
const ENG: &str = "4e6b8d0f-1a2b-4c3d-9e8f-7a6b5c4d3e2f";
const SEC: &str = "5f7c9e10-2b3c-4d4e-8f90-8b7c6d5e4f30";
const TOKEN_ENV: &str = "FLEET_RECALL_LINEAR_TEST_API_KEY";
const MISSING: &str = "unfindable marmoset";

/// The personal API key the fake expects: an obvious placeholder, never a
/// real credential, that still has the `lin_api_` shape the redactor catches
/// anywhere it leaks into text. A personal key is sent as the header itself.
const API_KEY: &str = "lin_api_EXAMPLENOTAREALKEYEXAMPLENOTAREAL";

const ISSUES: &str = "FleetRecallLinearIssues";
const COMMENTS: &str = "FleetRecallLinearComments";
const SCOPE: &str = "FleetRecallLinearScope";

// ---------------------------------------------------------------------------
// The fake organization
// ---------------------------------------------------------------------------

/// Whole seconds three days ago: every issue is behind the database's clock.
fn base_seconds() -> i64 {
    Utc::now().timestamp() - 3 * 86_400
}

/// A Linear timestamp `offset` seconds (and as many milliseconds) after
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

fn uuid(prefix: &str, index: u32) -> String {
    format!("{prefix}-0000-4000-8000-{index:012}")
}

fn issue_id(index: u32) -> String {
    uuid("1550e000", index)
}

fn comment_id(index: u32) -> String {
    uuid("c0770000", index)
}

#[derive(Debug, Clone)]
struct Team {
    key: String,
    visibility: String,
}

#[derive(Debug, Clone)]
struct World {
    organization: String,
    teams: BTreeMap<String, Team>,
    /// Issues by id, with their team.
    issues: BTreeMap<String, (String, Value)>,
    /// Comments by id, with their issue.
    comments: BTreeMap<String, (String, Value)>,
    requests_remaining: u64,
}

impl World {
    fn new() -> Self {
        let mut teams = BTreeMap::new();
        teams.insert(
            ENG.to_owned(),
            Team {
                key: "ENG".into(),
                visibility: "public".into(),
            },
        );
        teams.insert(
            SEC.to_owned(),
            Team {
                key: "SEC".into(),
                visibility: "private".into(),
            },
        );
        Self {
            organization: ORG.to_owned(),
            teams,
            issues: BTreeMap::new(),
            comments: BTreeMap::new(),
            requests_remaining: 5_000,
        }
    }

    fn issue(&mut self, team: &str, index: u32, title: &str, description: &str, updated: &str) {
        let key = &self.teams[team].key;
        let identifier = format!("{key}-{}", 400 + index);
        let id = issue_id(index);
        self.issues.insert(
            id.clone(),
            (
                team.to_owned(),
                json!({
                    "id": id, "identifier": identifier, "number": 400 + index, "title": title,
                    "description": description, "priority": 2,
                    "url": format!("https://linear.app/acme-robotics/issue/{identifier}/slug"),
                    "createdAt": updated, "updatedAt": updated, "archivedAt": null,
                    "trashed": null, "state": {"name": "In Progress", "type": "started"},
                    "creator": {"id": "a11ce000-0000-4000-8000-000000000001"},
                    "botActor": null, "externalUserCreator": null, "parent": null,
                    "project": null
                }),
            ),
        );
    }

    fn comment(&mut self, issue: u32, index: u32, body: &str, updated: &str) {
        let id = comment_id(index);
        self.comments.insert(
            id.clone(),
            (
                issue_id(issue),
                json!({
                    "id": id, "body": body, "createdAt": updated, "updatedAt": updated,
                    "editedAt": null, "archivedAt": null,
                    "url": format!("https://linear.app/acme-robotics/issue/x#comment-{index}"),
                    "issue": {"id": issue_id(issue)}, "parent": null,
                    "user": {"id": "b0b00000-0000-4000-8000-000000000002"},
                    "botActor": null, "externalUser": null
                }),
            ),
        );
    }

    fn issue_mut(&mut self, index: u32) -> &mut Value {
        &mut self.issues.get_mut(&issue_id(index)).unwrap().1
    }
}

/// A request's GraphQL operation and variables.
fn operation(request: &FakeRequest) -> (String, Value) {
    let body: Value = serde_json::from_slice(&request.body).unwrap_or(Value::Null);
    (
        body["operationName"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
        body["variables"].clone(),
    )
}

fn graphql_error(code: &str) -> FakeReply {
    let mut reply =
        FakeReply::json(&json!({"errors": [{"message": code, "extensions": {"code": code}}]}));
    reply.status = 400;
    reply
}

/// One page of `nodes` (newest first), paged by `first` on a cursor naming
/// the last node served.
fn connection(field: &str, mut nodes: Vec<Value>, variables: &Value) -> Value {
    nodes.sort_by(|left, right| {
        instant(right["updatedAt"].as_str().unwrap())
            .cmp(&instant(left["updatedAt"].as_str().unwrap()))
            .then_with(|| left["id"].as_str().cmp(&right["id"].as_str()))
    });
    let first = usize::try_from(variables["first"].as_u64().unwrap_or(50)).unwrap();
    let start = variables["after"].as_str().map_or(0, |after| {
        let id = after.strip_prefix("cursor:").unwrap_or_default();
        nodes
            .iter()
            .position(|node| node["id"] == id)
            .map_or(nodes.len(), |position| position + 1)
    });
    let end = (start + first).min(nodes.len());
    let page: Vec<Value> = nodes.get(start..end).unwrap_or_default().to_vec();
    let more = end < nodes.len();
    json!({"data": {field: {
        "nodes": page,
        "pageInfo": {
            "hasNextPage": more,
            "endCursor": page.last().map(|node| format!("cursor:{}", node["id"].as_str().unwrap()))
        }
    }}})
}

fn after_since(node: &Value, filter: &Value) -> bool {
    filter["updatedAt"]["gt"]
        .as_str()
        .is_none_or(|since| instant(node["updatedAt"].as_str().unwrap()) > instant(since))
}

/// The GraphQL API over `world`, for the operations the collector sends.
fn respond(world: &mut World, request: &FakeRequest) -> FakeReply {
    if request.method != "POST" || request.path != "/graphql" {
        return FakeReply::status(404, "not the GraphQL endpoint");
    }
    world.requests_remaining = world.requests_remaining.saturating_sub(1);
    let (name, variables) = operation(request);
    let filter = &variables["filter"];
    let body = match name.as_str() {
        SCOPE => {
            let wanted: Vec<&str> = variables["teams"]
                .as_array()
                .map(|teams| teams.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            let teams: Vec<Value> = world
                .teams
                .iter()
                .filter(|(id, _)| wanted.contains(&id.as_str()))
                .map(|(id, team)| {
                    json!({"id": id, "key": team.key, "name": team.key,
                           "visibility": team.visibility})
                })
                .collect();
            json!({"data": {"organization": {"id": world.organization},
                            "teams": {"nodes": teams}}})
        }
        ISSUES => {
            let team = filter["team"]["id"]["eq"].as_str().unwrap_or_default();
            let nodes = world
                .issues
                .values()
                .filter(|(owner, node)| owner == team && after_since(node, filter))
                .map(|(_, node)| node.clone())
                .collect();
            connection("issues", nodes, &variables)
        }
        COMMENTS => {
            let team = filter["issue"]["team"]["id"]["eq"]
                .as_str()
                .unwrap_or_default();
            let nodes = world
                .comments
                .values()
                .filter(|(issue, node)| {
                    world
                        .issues
                        .get(issue)
                        .is_some_and(|(owner, _)| owner == team)
                        && after_since(node, filter)
                })
                .map(|(_, node)| node.clone())
                .collect();
            connection("comments", nodes, &variables)
        }
        _ => return graphql_error("GRAPHQL_VALIDATION_FAILED"),
    };
    let mut reply = FakeReply::json(&body);
    reply.headers.extend([
        (
            "x-ratelimit-requests-remaining".to_owned(),
            world.requests_remaining.to_string(),
        ),
        (
            "x-ratelimit-complexity-remaining".to_owned(),
            "2999000".to_owned(),
        ),
    ]);
    reply
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
            FakeProvider::start(move |request| respond(&mut served.lock().unwrap(), request)).await;
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

    /// Change one issue of the fake organization.
    fn edit_issue(&self, index: u32, change: impl FnOnce(&mut Value)) {
        change(self.world().issue_mut(index));
    }

    fn sources(&self, teams: &[&str], listed: &[&str], extra: &Value) -> Value {
        let mut settings = json!({
            "token_env": TOKEN_ENV,
            "teams": teams,
            "api_url": format!("{}/graphql", self.fake.base),
            "page_size": 2
        });
        settings
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        json!({
            "schema_version": 1,
            "coverage_since": "2026-08-01T00:00:00Z",
            "collectors": [{
                "provider": "linear",
                "connector_principal": "principal.linear",
                "connector_instance": INSTANCE,
                "provider_scope_id": ORG,
                "audience": {"private_containers": listed},
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
            .expect("the Linear collector reported")
    }

    /// Every request the fake received for `operation`, with its variables.
    fn calls(&self, name: &str) -> Vec<Value> {
        self.fake
            .requests()
            .iter()
            .map(operation)
            .filter(|(operation, _)| operation == name)
            .map(|(_, variables)| variables)
            .collect()
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

    async fn team_cursors(&self) -> i64 {
        self.scalar(
            "SELECT count(*) FROM memory_collector_cursors_v1 \
             WHERE tenant_id = $1 AND project = $2 AND domain_key = $3",
            &format!("linear.team:{ENG}"),
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

    /// An issue's verified head: its lifecycle and how many versions it saw.
    async fn head(&self, external_id: &str) -> (String, i64) {
        sqlx::query_as(
            "SELECT lifecycle, version_count FROM memory_collected_item_heads_v1 \
             WHERE tenant_id = $1 AND project = $2 AND provider = 'linear' \
               AND external_id = $3 AND trust_tier = 'verified'",
        )
        .bind(self.fixture.installed.scope.tenant_id)
        .bind(&self.fixture.installed.scope.project)
        .bind(external_id)
        .fetch_one(&self.pool)
        .await
        .unwrap()
    }

    async fn container(&self, id: &str) -> String {
        sqlx::query_scalar(
            "SELECT access FROM memory_collector_containers_v1 \
             WHERE tenant_id = $1 AND project = $2 AND container_id = $3",
        )
        .bind(self.fixture.installed.scope.tenant_id)
        .bind(&self.fixture.installed.scope.project)
        .bind(id)
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
                    provider: Some(ProviderKindV1::new("linear").unwrap()),
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
            &ProviderKindV1::new("linear").unwrap(),
            ORG,
            &ObjectKindV1::new(object_kind).unwrap(),
            external_id,
        );
        self.items()
            .await
            .get(&ItemReferenceV1::Item(item))
            .await
            .unwrap()
            .expect("the issue or comment is an item")
    }
}

async fn capabilities(pool: &PgPool, scope: &FleetScope) -> DatabaseCapabilities {
    CockroachStore::from_pool(pool.clone(), scope.clone())
        .unwrap()
        .capabilities()
        .await
        .unwrap()
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
            !row.contains(secret)
                && !lowered.contains(&secret.to_ascii_lowercase())
                && !lowered.contains(&once)
                && !lowered.contains(&twice),
            "the secret is in a row of {table}"
        );
    }
}

// ---------------------------------------------------------------------------
// The pull collector
// ---------------------------------------------------------------------------

/// Engineering: three issues (two pages of two), two comments on the first.
fn sweep_world(base: i64) -> World {
    let mut world = World::new();
    world.issue(
        ENG,
        12,
        "Cap worker retries",
        "The quokka retry budget is **3** attempts; see \
         [the thread](https://acme-robotics.slack.com/archives/C07PLATENG1/p1790006645000200).",
        &at(base, 10),
    );
    world.issue(
        ENG,
        13,
        "Heron jitter",
        "Add full jitter to the heron backoff.",
        &at(base, 20),
    );
    world.issue(
        ENG,
        14,
        "Kestrel alerts",
        "Page on kestrel budget burn.",
        &at(base, 30),
    );
    world.comment(12, 1, "The pelican thread concluded five.", &at(base, 40));
    world.comment(
        12,
        2,
        "Disagree: three keeps the osprey p99 under SLO.",
        &at(base, 50),
    );
    world
}

#[tokio::test]
async fn live_linear_a_two_page_sweep_is_complete_and_a_miss_is_absent_when_configured() {
    let base = base_seconds();
    let Some(harness) = Harness::new("linear-sweep", sweep_world(base)).await else {
        return;
    };
    let sources = harness.sources(&[ENG], &[], &json!({}));
    let report = harness.ok_tick(&sources).await;
    let source = Harness::source(&report);
    assert_eq!(source.outcome, WorkerSourceOutcomeV1::Ok, "{source:?}");
    assert_eq!(source.counters["issues_read"], 3);
    assert_eq!(source.counters["comments_read"], 2);
    assert_eq!(harness.calls(ISSUES).len(), 2, "two pages of issues");
    assert_eq!(source.counters["containers_complete"], 1);
    assert!(source.counters["receipts"] >= 1);
    assert!(source.counters["ratelimit_reports"] >= 4);
    assert!(source.counters["ratelimit_requests_remaining"] < 5_000);

    let quokka = issue_id(12);
    assert_eq!(hits(&harness.search("quokka").await), [quokka.as_str()]);
    assert_eq!(
        hits(&harness.search("kestrel").await),
        [issue_id(14).as_str()]
    );
    let issue = harness.get("issue", &quokka).await;
    assert_eq!(
        issue.current.title.as_deref(),
        Some("ENG-412 Cap worker retries"),
        "the identifier is a label in the title"
    );
    assert_eq!(
        issue.item.container.as_ref().unwrap().label.as_deref(),
        Some("ENG")
    );
    assert!(part_text(&issue).starts_with("State: In Progress\n\nThe quokka retry budget"));
    assert_eq!(
        issue
            .links_out
            .iter()
            .map(|link| (link.rel.as_str(), link.target.as_str()))
            .collect::<Vec<_>>(),
        [(
            "url",
            "https://acme-robotics.slack.com/archives/C07PLATENG1/p1790006645000200"
        )]
    );
    let comment = harness.get("comment", &comment_id(2)).await;
    assert_eq!(
        comment.item.thread_root_external_id.as_deref(),
        Some(quokka.as_str()),
        "a comment's thread root is its issue"
    );
    assert_eq!(
        hits(&harness.search("osprey").await),
        [comment_id(2).as_str()]
    );
    assert!(
        !harness.evidence("pelican").await.hits.is_empty(),
        "evidence recall reads the comments too"
    );

    // Every tick reconciles: the sweep read the team to its end.
    let absent = harness.search(MISSING).await;
    assert!(absent.hits.is_empty());
    assert_eq!(absent.absence.verdict, AbsenceVerdictV1::Absent);
    assert!(harness.last_checked_at().await.is_some());
    harness.fake.assert_credential_confined(API_KEY, API_KEY);
}

#[tokio::test]
async fn live_linear_a_rate_limit_on_page_two_is_partial_and_the_next_tick_resumes_when_configured()
{
    let base = base_seconds();
    let mut world = World::new();
    for (index, word) in (0..).zip(["alpha", "bravo", "charlie", "delta", "echo"]) {
        world.issue(
            ENG,
            20 + index,
            &format!("The {word} osprey"),
            &format!("Notes on the {word} osprey."),
            &at(base, i64::from(index) * 10),
        );
    }
    let Some(harness) = Harness::new("linear-rate-limit", world).await else {
        return;
    };
    harness.fake.script(
        |request| {
            let (name, variables) = operation(request);
            name == ISSUES && variables["after"].is_string()
        },
        FakeReply::rate_limited(30),
    );
    let sources = harness.sources(&[ENG], &[], &json!({}));
    let report = harness.ok_tick(&sources).await;
    let source = Harness::source(&report);
    assert_eq!(source.counters["rate_limited"], 1);
    assert_eq!(source.counters["containers_complete"], 0);
    assert_eq!(source.counters["issues_read"], 2, "page one, newest first");
    assert_eq!(hits(&harness.search("echo").await).len(), 1);
    assert_eq!(hits(&harness.search("delta").await).len(), 1);
    assert!(harness.search("alpha").await.hits.is_empty());
    assert!(
        harness.calls(COMMENTS).is_empty(),
        "a rate limit ends the pass"
    );
    let partial = harness.search(MISSING).await;
    assert_eq!(partial.absence.verdict, AbsenceVerdictV1::Unknown);
    assert_eq!(
        partial.absence.reasons,
        [AbsenceReasonV1::IncompleteCoverage]
    );
    assert_eq!(harness.team_cursors().await, 1, "the resume point is held");

    harness.fake.clear_requests();
    let report = harness.ok_tick(&sources).await;
    let source = Harness::source(&report);
    assert_eq!(source.counters["sweeps_resumed"], 1);
    assert_eq!(
        harness.calls(ISSUES)[0]["after"],
        json!(format!("cursor:{}", issue_id(23))),
        "the sweep resumes after the last page staged"
    );
    assert_eq!(
        source.counters["issues_read"], 3,
        "page one is not read again"
    );
    assert_eq!(source.counters["containers_complete"], 1);
    for word in ["alpha", "bravo", "charlie", "delta", "echo"] {
        assert_eq!(hits(&harness.search(word).await).len(), 1, "{word}");
    }
    assert_eq!(
        harness.search(MISSING).await.absence.verdict,
        AbsenceVerdictV1::Absent
    );
}

#[tokio::test]
async fn live_linear_a_newer_updated_at_moves_the_head_and_an_overlap_re_read_is_a_no_op_when_configured()
 {
    let base = base_seconds();
    let mut world = World::new();
    world.issue(
        ENG,
        30,
        "Quokka budget",
        "The quokka budget is three.",
        &at(base, 10),
    );
    let Some(harness) = Harness::new("linear-head", world).await else {
        return;
    };
    let quokka = issue_id(30);
    let sources = harness.sources(&[ENG], &[], &json!({"overlap_seconds": 86_400}));
    harness.ok_tick(&sources).await;
    assert_eq!(harness.head(&quokka).await, ("live".to_owned(), 1));

    // The overlap reads the issue again: nothing is staged.
    let report = harness.ok_tick(&sources).await;
    let source = Harness::source(&report);
    assert_eq!(source.counters["issues_read"], 1, "the overlap re-read it");
    assert_eq!(source.counters["issues_unchanged"], 1);
    assert_eq!(source.counters["rows_staged"], 0);
    assert_eq!(source.outcome, WorkerSourceOutcomeV1::Unchanged);
    assert_eq!(harness.head(&quokka).await, ("live".to_owned(), 1));

    // A change that is not content (its priority) moves updatedAt only.
    harness.edit_issue(30, |issue| {
        issue["priority"] = json!(1);
        issue["updatedAt"] = json!(at(base, 60));
    });
    let report = harness.ok_tick(&sources).await;
    assert_eq!(Harness::source(&report).counters["issues_unchanged"], 1);
    assert_eq!(Harness::source(&report).counters["rows_staged"], 0);
    assert_eq!(harness.head(&quokka).await, ("live".to_owned(), 1));

    // New content at a newer updatedAt is a new version, and it heads.
    let updated = at(base, 120);
    harness.edit_issue(30, |issue| {
        issue["description"] = json!("The quokka budget is five, with jitter.");
        issue["updatedAt"] = json!(updated);
    });
    let report = harness.ok_tick(&sources).await;
    assert_eq!(Harness::source(&report).counters["issues_staged"], 1);
    assert_eq!(harness.head(&quokka).await, ("live".to_owned(), 2));
    let got = harness.get("issue", &quokka).await;
    assert_eq!(got.current.marker, updated);
    assert!(part_text(&got).contains("five, with jitter"));
    assert_eq!(
        got.history.len(),
        1,
        "the first version is superseded, not lost"
    );
}

#[tokio::test]
async fn live_linear_a_private_team_is_refused_unless_listed_when_configured() {
    let base = base_seconds();
    let mut world = World::new();
    world.issue(
        ENG,
        40,
        "Heron rollout",
        "The heron rollout plan.",
        &at(base, 10),
    );
    world.issue(
        SEC,
        41,
        "Osprey incident",
        "The secret osprey incident review.",
        &at(base, 20),
    );
    let Some(harness) = Harness::new("linear-private", world).await else {
        return;
    };
    let sources = harness.sources(&[ENG, SEC], &[], &json!({}));
    let report = harness.ok_tick(&sources).await;
    let source = Harness::source(&report);
    assert_eq!(source.counters["teams_refused"], 1);
    assert_eq!(
        source.counters["containers"], 1,
        "the private team is outside"
    );
    assert_eq!(source.counters["containers_complete"], 1);
    let teams_read: Vec<Value> = harness
        .calls(ISSUES)
        .iter()
        .chain(&harness.calls(COMMENTS))
        .map(|variables| variables["filter"].clone())
        .collect();
    assert!(
        teams_read
            .iter()
            .all(|filter| !filter.to_string().contains(SEC)),
        "a team the project may not read is never read: {teams_read:?}"
    );
    assert_eq!(harness.container(SEC).await, "withdrawn");
    assert!(harness.search("osprey").await.hits.is_empty());
    assert_eq!(hits(&harness.search("heron").await).len(), 1);
    assert_eq!(
        harness.search(MISSING).await.absence.verdict,
        AbsenceVerdictV1::Absent
    );

    // Listed, it is read.
    let listed = harness.sources(&[ENG, SEC], &[SEC], &json!({}));
    harness.ok_tick(&listed).await;
    assert_eq!(harness.container(SEC).await, "ok");
    assert_eq!(
        hits(&harness.search("osprey").await),
        [issue_id(41).as_str()]
    );

    // A public team made restricted, and not listed, is withdrawn and hidden.
    harness.world().teams.get_mut(ENG).unwrap().visibility = "restricted".to_owned();
    harness.ok_tick(&listed).await;
    assert_eq!(harness.container(ENG).await, "withdrawn");
    assert!(harness.search("heron").await.hits.is_empty());
    assert!(harness.evidence("heron").await.hits.is_empty());
    assert_eq!(
        harness.get("issue", &issue_id(40)).await.suppressed,
        Some(ItemSuppressionV1::ContainerWithdrawn)
    );
}

#[tokio::test]
async fn live_linear_a_trashed_issue_is_hidden_and_an_archived_one_stays_when_configured() {
    let base = base_seconds();
    let mut world = World::new();
    world.issue(
        ENG,
        50,
        "Kestrel cleanup",
        "Archive the kestrel dashboards.",
        &at(base, 10),
    );
    world.issue(
        ENG,
        51,
        "Pelican spike",
        "A pelican spike that went nowhere.",
        &at(base, 20),
    );
    let Some(harness) = Harness::new("linear-lifecycle", world).await else {
        return;
    };
    let sources = harness.sources(&[ENG], &[], &json!({}));
    harness.ok_tick(&sources).await;
    assert_eq!(hits(&harness.search("pelican").await).len(), 1);
    harness.edit_issue(50, |archived| {
        archived["archivedAt"] = json!(at(base, 100));
        archived["updatedAt"] = json!(at(base, 100));
    });
    harness.edit_issue(51, |trashed| {
        trashed["trashed"] = json!(true);
        trashed["archivedAt"] = json!(at(base, 110));
        trashed["updatedAt"] = json!(at(base, 110));
    });
    let report = harness.ok_tick(&sources).await;
    assert_eq!(Harness::source(&report).counters["tombstones"], 1);
    assert_eq!(
        harness.head(&issue_id(50)).await,
        ("archived".to_owned(), 2)
    );
    assert_eq!(
        hits(&harness.search("kestrel").await),
        [issue_id(50).as_str()]
    );
    assert_eq!(harness.head(&issue_id(51)).await, ("trashed".to_owned(), 2));
    assert!(harness.search("pelican").await.hits.is_empty());
    assert!(harness.evidence("pelican").await.hits.is_empty());
    assert_eq!(
        harness.get("issue", &issue_id(51)).await.suppressed,
        Some(ItemSuppressionV1::Deleted)
    );
}

#[tokio::test]
async fn live_linear_a_key_of_another_organization_fails_the_source_and_reads_nothing_when_configured()
 {
    let base = base_seconds();
    let mut world = sweep_world(base);
    world.organization = "0bbb0000-0000-4000-8000-000000000999".to_owned();
    let Some(harness) = Harness::new("linear-other-org", world).await else {
        return;
    };
    let report = harness
        .tick(&harness.sources(&[ENG], &[], &json!({})))
        .await;
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
        error.contains("0bbb0000-0000-4000-8000-000000000999") && error.contains(ORG),
        "{error}"
    );
    let operations: Vec<String> = harness
        .fake
        .requests()
        .iter()
        .map(|request| operation(request).0)
        .collect();
    assert_eq!(operations, [SCOPE], "nothing but the scope was read");
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
async fn live_linear_the_key_appears_nowhere_when_configured() {
    let base = base_seconds();
    let mut world = sweep_world(base);
    world.issue(
        ENG,
        15,
        "Pasted by mistake",
        &format!("Pasted by mistake: {API_KEY} and the retry plan"),
        &at(base, 35),
    );
    world.comment(15, 3, &format!("Rotate {API_KEY} today"), &at(base, 60));
    let Some(harness) = Harness::new("linear-token", world).await else {
        return;
    };
    // A failing call on the way: a 5xx whose body echoes the credential.
    harness.fake.script(
        |request| operation(request).0 == COMMENTS,
        FakeReply::status(502, &format!("upstream saw Authorization: {API_KEY}")),
    );
    let sources = harness.sources(&[ENG], &[], &json!({}));
    let report = harness.ok_tick(&sources).await;
    assert_eq!(Harness::source(&report).counters["http_errors"], 1);
    assert_eq!(Harness::source(&report).counters["containers_complete"], 0);
    let report = harness.ok_tick(&sources).await;
    assert_eq!(Harness::source(&report).counters["containers_complete"], 1);

    let pasted = harness.get("issue", &issue_id(15)).await;
    assert!(part_text(&pasted).contains("and the retry plan"));
    assert!(!part_text(&pasted).contains(API_KEY));
    assert_nowhere(&harness.pool, &harness.fixture, API_KEY).await;
    harness.fake.assert_credential_confined(API_KEY, API_KEY);
}

#[test]
fn linear_an_http_api_url_off_loopback_is_refused_when_the_sources_file_is_read() {
    let sources = |api_url: &str| {
        json!({
            "schema_version": 1,
            "collectors": [{
                "provider": "linear", "connector_principal": "principal.linear",
                "connector_instance": INSTANCE, "provider_scope_id": ORG,
                "settings": {"token_env": TOKEN_ENV, "teams": [ENG], "api_url": api_url}
            }]
        })
    };
    let refused = WorkerSourcesV1::from_json_slice(
        &serde_json::to_vec(&sources("http://linear.example.com/graphql")).unwrap(),
    )
    .unwrap_err()
    .to_string();
    assert!(refused.contains("not loopback"), "{refused}");
    for accepted in [
        "https://api.linear.app/graphql",
        "http://127.0.0.1:8080/graphql",
    ] {
        WorkerSourcesV1::from_json_slice(&serde_json::to_vec(&sources(accepted)).unwrap())
            .unwrap_or_else(|error| panic!("{accepted}: {error}"));
    }
}
