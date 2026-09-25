//! Connected proofs of the collected-item sink (ADR 0008 D4-D6): drafts staged
//! through the library, drained by the worker's `collect` step, projected into
//! bodies, lexical, and dense tiers, and recalled with a sound verdict; the
//! current view's move rule; read-time suppression of deleted items and
//! withdrawn containers; and what a login without the collector grants sees.
//!
//! Every test needs `FLEET_RECALL_TEST_DATABASE_URL` and returns at once
//! without it.

mod common;

use std::collections::BTreeSet;
use std::sync::Arc;

use ostk_fleet_recall::FleetScope;
use ostk_fleet_recall::collectors::audience::{
    AudiencePolicyV1, CaptureContainersV1, CaptureScopeV1, ProviderAudienceV1,
};
use ostk_fleet_recall::collectors::binding::CollectorInstanceV1;
use ostk_fleet_recall::collectors::draft::{
    CollectedItemDraftV1, DraftContainerV1, DraftSectionV1,
};
use ostk_fleet_recall::collectors::redaction::CollectorRedactorV1;
use ostk_fleet_recall::collectors::sink::{
    CollectedItemSink, ContainerObservationV1, DeadLetterReasonV1, StageContextV1, StageDraftV1,
    StageOutcomeV1, StagedItemV1,
};
use ostk_fleet_recall::collectors::status::{
    CollectorOutcomeV1, CollectorOwnerV1, CollectorSourceStatusV1, CoverageRoleV1,
};
use ostk_fleet_recall::evidence_recall::{
    AbsenceReasonV1, AbsenceVerdictV1, CockroachEvidenceRecall, EvidenceRecall as _,
    EvidenceSourceKindV1, probe_evidence_recall,
};
use ostk_fleet_recall::memory_contracts::collected_item::{
    BoundedTextV1, COLLECTED_ITEM_MEDIA_TYPE, CollectedItemInputV1, CollectionModeV1,
    ContainerKindV1, ItemLifecycleV1, ObjectKindV1, ProviderKindV1, TextFormatV1,
};
use ostk_fleet_recall::memory_contracts::common::ContractId;
use ostk_fleet_recall::memory_contracts::digest::Sha256Digest;
use ostk_fleet_recall::memory_contracts::generation2_registry::GIT_CONNECTOR;
use ostk_fleet_recall::registry_activation::install::{InstallTargetV1, install_writer_authority};
use ostk_fleet_recall::store::cockroach::{
    COLLECTED_ITEMS_SCHEMA_VERSION, CockroachStore, DatabaseCapabilities,
};
use ostk_fleet_recall::worker::{
    WorkerStepReportV1, WorkerStepStatusV1, WorkerStepV1, WorkerTickReportV1, parse_steps,
    probe_worker_privileges,
};
use ostk_recall_core::ChunkEmbedder as _;
use sha2::{Digest as _, Sha256};
use sqlx::PgPool;

use common::authority::retry_policy;
use common::runtime_role::RuntimeProbeRole;
use common::worker::{RecordedCi, STUB_MODEL_DIGEST, StubEmbedder, WorkerFixture};

const SLACK_TEAM: &str = "T07ACME0001";
const SLACK_CHANNEL: &str = "C07PLATENG1";
const DOCS_ROOT: &str = "docs.acme.specs";
const LINEAR_ORG: &str = "5a1c0de2-7f3b-4c1e-9d2a-0b6f4e8c1a37";

// ---------------------------------------------------------------------------
// Collectors, drafts, and staging
// ---------------------------------------------------------------------------

/// One collector instance as a test stages through it.
struct Collector {
    instance: CollectorInstanceV1,
    principal: ContractId,
    mode: CollectionModeV1,
    policy: AudiencePolicyV1,
    container: ContainerObservationV1,
}

fn instance(id: &str, provider: &str, scope: &str) -> CollectorInstanceV1 {
    CollectorInstanceV1 {
        connector_instance_id: ContractId::new(id).unwrap(),
        provider: ProviderKindV1::new(provider).unwrap(),
        provider_scope_id: BoundedTextV1::new(scope).unwrap(),
    }
}

/// A Slack pull collector over one public channel.
fn slack() -> Collector {
    Collector {
        instance: instance("slack.acme", "slack", SLACK_TEAM),
        principal: ContractId::new("principal.slack").unwrap(),
        mode: CollectionModeV1::Pull,
        policy: AudiencePolicyV1::default(),
        container: ContainerObservationV1 {
            kind: ContainerKindV1::new("slack.channel").unwrap(),
            id: SLACK_CHANNEL.to_owned(),
            label: Some("plat-eng".to_owned()),
            provider_audience: ProviderAudienceV1::ScopePublic,
        },
    }
}

/// A documents-directory pull collector the operator declared.
fn docs() -> Collector {
    Collector {
        instance: instance("docs.specs", "docs", DOCS_ROOT),
        principal: ContractId::new("principal.docs").unwrap(),
        mode: CollectionModeV1::Pull,
        policy: AudiencePolicyV1 {
            operator_declared: true,
            private_containers: Vec::new(),
        },
        container: ContainerObservationV1 {
            kind: ContainerKindV1::new("docs.root").unwrap(),
            id: DOCS_ROOT.to_owned(),
            label: Some("specs".to_owned()),
            provider_audience: ProviderAudienceV1::OperatorScoped,
        },
    }
}

/// An operator import of the same documents root: a reported channel.
fn docs_import() -> Collector {
    Collector {
        instance: instance("docs.import", "docs", DOCS_ROOT),
        mode: CollectionModeV1::Import,
        ..docs()
    }
}

/// An operator import of a Slack export that lists the channel as public.
fn slack_import() -> Collector {
    Collector {
        instance: instance("slack.export", "slack", SLACK_TEAM),
        principal: ContractId::new("principal.slack.export").unwrap(),
        mode: CollectionModeV1::Import,
        policy: AudiencePolicyV1 {
            operator_declared: true,
            private_containers: Vec::new(),
        },
        ..slack()
    }
}

/// A Linear pull collector observing one team.
fn linear(team: &str, audience: ProviderAudienceV1) -> Collector {
    Collector {
        instance: instance("linear.acme", "linear", LINEAR_ORG),
        principal: ContractId::new("principal.linear").unwrap(),
        mode: CollectionModeV1::Pull,
        policy: AudiencePolicyV1::default(),
        container: ContainerObservationV1 {
            kind: ContainerKindV1::new("linear.team").unwrap(),
            id: team.to_owned(),
            label: None,
            provider_audience: audience,
        },
    }
}

/// An operator import of a Linear export that lists `team` as public.
fn linear_export(team: &str) -> Collector {
    Collector {
        instance: instance("linear.export", "linear", LINEAR_ORG),
        mode: CollectionModeV1::Import,
        policy: AudiencePolicyV1 {
            operator_declared: true,
            private_containers: Vec::new(),
        },
        ..linear(team, ProviderAudienceV1::TeamPublic)
    }
}

/// A Linear issue in `team`, at `updated_at` µs.
fn issue(id: &str, team: &str, text: &str, order: u64) -> CollectedItemDraftV1 {
    CollectedItemDraftV1 {
        provider: ProviderKindV1::new("linear").unwrap(),
        provider_scope_id: LINEAR_ORG.into(),
        object_kind: ObjectKindV1::new("issue").unwrap(),
        external_id: id.into(),
        marker: Some(format!("u{order}")),
        order_micros: order,
        lifecycle: ItemLifecycleV1::Live,
        container: Some(DraftContainerV1 {
            kind: ContainerKindV1::new("linear.team").unwrap(),
            id: team.into(),
            label: None,
        }),
        thread: None,
        author: None,
        created_at: None,
        updated_at: None,
        title: Some(format!("Issue {id}")),
        sections: vec![DraftSectionV1::whole(text.into())],
        text_format: TextFormatV1::Markdown,
        links: Vec::new(),
        provider_url: None,
        visibility: None,
    }
}

/// Stage `drafts` as agent captures under `capture_scopes`. A capture records
/// no container.
async fn capture(
    pool: &PgPool,
    fixture: &WorkerFixture,
    drafts: Vec<CollectedItemDraftV1>,
    capture_scopes: &[CaptureScopeV1],
) -> StageOutcomeV1 {
    let redactor = redactor(
        pool,
        fixture,
        CollectionModeV1::Capture.connector_schema_id(),
    )
    .await;
    let agent = ContractId::new("agent.scout").unwrap();
    let staged: Vec<StageDraftV1> = drafts
        .into_iter()
        .map(|draft| StageDraftV1 {
            delivery_id: Sha256::digest(draft.external_id.as_bytes()).to_vec(),
            provider_audience: None,
            draft,
        })
        .collect();
    sink(pool, fixture)
        .stage(
            &staged,
            &StageContextV1 {
                instance: &instance("capture.scout", "slack", SLACK_TEAM),
                principal: &agent,
                mode: CollectionModeV1::Capture,
                attester: Some(&agent),
                via: None,
                redactor: &redactor,
                policy: &AudiencePolicyV1::default(),
                capture_scopes,
                pass_seq: None,
                container_observations: &[],
                cursor_advances: &[],
                source_status: None,
            },
        )
        .await
        .expect("staging runs")
}

/// The one refusal a staging call made.
fn refusal(outcome: &StageOutcomeV1) -> (DeadLetterReasonV1, String) {
    match outcome.items.as_slice() {
        [StagedItemV1::Refused { reason, diagnostic }] => (*reason, diagnostic.clone()),
        other => panic!("one refused item expected: {other:?}"),
    }
}

/// Hits for `word`.
async fn hits(recall: &CockroachEvidenceRecall, word: &str) -> usize {
    recall.search(word, None, 10).await.unwrap().hits.len()
}

/// The drafts of one fixture file, `tests/fixtures/collected/items-<name>.jsonl`.
fn fixture_drafts(name: &str) -> Vec<CollectedItemDraftV1> {
    let path = format!(
        "{}/tests/fixtures/collected/items-{name}.jsonl",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(|line| {
            let input = CollectedItemInputV1::parse(line.as_bytes()).unwrap();
            CollectedItemDraftV1::from_input(input).unwrap()
        })
        .collect()
}

/// A document in the fixture root.
fn doc(
    external_id: &str,
    text: &str,
    order: u64,
    lifecycle: ItemLifecycleV1,
) -> CollectedItemDraftV1 {
    CollectedItemDraftV1 {
        provider: ProviderKindV1::new("docs").unwrap(),
        provider_scope_id: DOCS_ROOT.into(),
        object_kind: ObjectKindV1::new("document").unwrap(),
        external_id: external_id.into(),
        marker: None,
        order_micros: order,
        lifecycle,
        container: Some(DraftContainerV1 {
            kind: ContainerKindV1::new("docs.root").unwrap(),
            id: DOCS_ROOT.into(),
            label: Some("specs".into()),
        }),
        thread: None,
        author: None,
        created_at: None,
        updated_at: None,
        title: Some(format!("About {external_id}")),
        sections: vec![DraftSectionV1::whole(text.into())],
        text_format: TextFormatV1::Markdown,
        links: Vec::new(),
        provider_url: None,
        visibility: None,
    }
}

/// A Slack message in `channel`.
fn message(channel: &str, ts: &str, text: &str, order: u64) -> CollectedItemDraftV1 {
    CollectedItemDraftV1 {
        provider: ProviderKindV1::new("slack").unwrap(),
        provider_scope_id: SLACK_TEAM.into(),
        object_kind: ObjectKindV1::new("message").unwrap(),
        external_id: format!("{channel}:{ts}"),
        marker: Some(ts.into()),
        order_micros: order,
        lifecycle: ItemLifecycleV1::Live,
        container: Some(DraftContainerV1 {
            kind: ContainerKindV1::new("slack.channel").unwrap(),
            id: channel.into(),
            label: None,
        }),
        thread: None,
        author: None,
        created_at: None,
        updated_at: None,
        title: None,
        sections: vec![DraftSectionV1::whole(text.into())],
        text_format: TextFormatV1::SlackMrkdwnRendered,
        links: Vec::new(),
        provider_url: None,
        visibility: None,
    }
}

fn sink(pool: &PgPool, fixture: &WorkerFixture) -> CollectedItemSink {
    CollectedItemSink::new(pool.clone(), &fixture.installed.scope, retry_policy())
        .expect("the fixture scope is valid")
}

/// The redactor under the active head's guarantee, read as a collector reads
/// it: through the connector its channel binds, or, on a head that has no
/// collected connector, through the git connector.
async fn redactor(pool: &PgPool, fixture: &WorkerFixture, connector: &str) -> CollectorRedactorV1 {
    let verified = fixture
        .installed
        .runtime(pool)
        .await
        .verify()
        .await
        .expect("the installed head verifies");
    let active = verified
        .bind_connector(&ContractId::new(connector).unwrap())
        .expect("the active package carries the connector");
    CollectorRedactorV1::from_active_package(&active).expect("the package promises redaction")
}

/// Stage `drafts` through `collector`, observing its container.
async fn stage_with(
    pool: &PgPool,
    fixture: &WorkerFixture,
    collector: &Collector,
    drafts: Vec<CollectedItemDraftV1>,
    status: Option<&CollectorSourceStatusV1>,
) -> StageOutcomeV1 {
    stage_through(
        pool,
        fixture,
        collector,
        drafts,
        status,
        collector.mode.connector_schema_id(),
    )
    .await
}

async fn stage_through(
    pool: &PgPool,
    fixture: &WorkerFixture,
    collector: &Collector,
    drafts: Vec<CollectedItemDraftV1>,
    status: Option<&CollectorSourceStatusV1>,
    redaction_connector: &str,
) -> StageOutcomeV1 {
    let redactor = redactor(pool, fixture, redaction_connector).await;
    let staged: Vec<StageDraftV1> = drafts
        .into_iter()
        .map(|draft| StageDraftV1 {
            delivery_id: Sha256::digest(
                format!("{}:{}", draft.external_id, draft.order_micros).as_bytes(),
            )
            .to_vec(),
            provider_audience: None,
            draft,
        })
        .collect();
    let observations = [collector.container.clone()];
    sink(pool, fixture)
        .stage(
            &staged,
            &StageContextV1 {
                instance: &collector.instance,
                principal: &collector.principal,
                mode: collector.mode,
                attester: None,
                via: None,
                redactor: &redactor,
                policy: &collector.policy,
                capture_scopes: &[],
                pass_seq: None,
                container_observations: &observations,
                cursor_advances: &[],
                source_status: status,
            },
        )
        .await
        .expect("staging runs")
}

async fn stage(
    pool: &PgPool,
    fixture: &WorkerFixture,
    collector: &Collector,
    drafts: Vec<CollectedItemDraftV1>,
) -> StageOutcomeV1 {
    stage_with(pool, fixture, collector, drafts, None).await
}

/// The version key of the one item a staging call staged.
fn staged_version(outcome: &StageOutcomeV1) -> Sha256Digest {
    match outcome.items.as_slice() {
        [StagedItemV1::Staged { version_key, .. }] => *version_key,
        other => panic!("one staged item expected: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Ticks, recall, and reads
// ---------------------------------------------------------------------------

/// A sources file that configures no connector at all, so a tick's appends
/// are exactly the collected ones.
fn no_sources() -> serde_json::Value {
    serde_json::json!({"schema_version": 1})
}

async fn tick(fixture: &WorkerFixture, pool: &PgPool, steps: &str) -> WorkerTickReportV1 {
    fixture
        .worker_with(pool, steps, &no_sources(), Arc::new(RecordedCi))
        .await
        .run_tick()
        .await
}

fn step(report: &WorkerTickReportV1, step: WorkerStepV1) -> &WorkerStepReportV1 {
    report.step(step).expect("every step is reported")
}

fn counter(report: &WorkerTickReportV1, which: WorkerStepV1, key: &str) -> u64 {
    step(report, which).counters.get(key).copied().unwrap_or(0)
}

/// A tick that must not fail.
async fn drain(fixture: &WorkerFixture, pool: &PgPool, steps: &str) -> WorkerTickReportV1 {
    let report = tick(fixture, pool, steps).await;
    assert!(
        !report.failed(),
        "the {steps} tick must succeed: {}",
        serde_json::to_string_pretty(&report).unwrap()
    );
    report
}

async fn capabilities(pool: &PgPool, scope: &FleetScope) -> DatabaseCapabilities {
    CockroachStore::from_pool(pool.clone(), scope.clone())
        .unwrap()
        .capabilities()
        .await
        .unwrap()
}

async fn recall_over(pool: &PgPool, owner: &PgPool, scope: &FleetScope) -> CockroachEvidenceRecall {
    let capabilities = capabilities(owner, scope).await;
    let capability = probe_evidence_recall(
        pool,
        &capabilities,
        scope,
        Sha256Digest::from_bytes(STUB_MODEL_DIGEST),
    )
    .await
    .expect("the probe runs")
    .expect("the login may read every evidence table");
    CockroachEvidenceRecall::new(capability, pool.clone())
}

async fn recall(pool: &PgPool, fixture: &WorkerFixture) -> CockroachEvidenceRecall {
    recall_over(pool, pool, &fixture.installed.scope).await
}

/// A scope-bound count.
async fn count(pool: &PgPool, fixture: &WorkerFixture, sql: &str) -> i64 {
    sqlx::query_scalar(sql)
        .bind(fixture.installed.scope.tenant_id)
        .bind(&fixture.installed.scope.project)
        .fetch_one(pool)
        .await
        .unwrap_or_else(|error| panic!("{sql}: {error}"))
}

/// The providers of the collected items a set of bodies belongs to.
async fn providers_of(
    pool: &PgPool,
    fixture: &WorkerFixture,
    bodies: &[Sha256Digest],
) -> BTreeSet<String> {
    let ids: Vec<Vec<u8>> = bodies.iter().map(|id| id.as_bytes().to_vec()).collect();
    sqlx::query_scalar::<_, String>(
        "SELECT provider FROM memory_collected_items_v1 \
         WHERE tenant_id = $1 AND project = $2 AND body_content_id = ANY($3::BYTES[])",
    )
    .bind(fixture.installed.scope.tenant_id)
    .bind(&fixture.installed.scope.project)
    .bind(&ids)
    .fetch_all(pool)
    .await
    .unwrap()
    .into_iter()
    .collect()
}

/// One head row of one item: `(tier, presented, version_key, version_count,
/// lifecycle, disagreement)`.
type HeadRow = (String, bool, Vec<u8>, i64, String, bool);

async fn heads(pool: &PgPool, fixture: &WorkerFixture, external_id: &str) -> Vec<HeadRow> {
    sqlx::query_as(
        "SELECT trust_tier, presented, version_key_digest, version_count, lifecycle, \
                disagreement \
         FROM memory_collected_item_heads_v1 \
         WHERE tenant_id = $1 AND project = $2 AND external_id = $3 ORDER BY trust_tier",
    )
    .bind(fixture.installed.scope.tenant_id)
    .bind(&fixture.installed.scope.project)
    .bind(external_id)
    .fetch_all(pool)
    .await
    .unwrap()
}

/// The embedding the dense projector stored for a body's recall text, so a
/// dense query can aim at exactly that body.
async fn body_vector(pool: &PgPool, fixture: &WorkerFixture, body: Sha256Digest) -> Vec<f32> {
    let text: String = sqlx::query_scalar(
        "SELECT lexical_text FROM memory_body_lexical_projection_v1 \
         WHERE tenant_id = $1 AND project = $2 AND body_content_id = $3",
    )
    .bind(fixture.installed.scope.tenant_id)
    .bind(&fixture.installed.scope.project)
    .bind(body.as_bytes().as_slice())
    .fetch_one(pool)
    .await
    .unwrap();
    StubEmbedder.encode_batch(&[text.as_str()]).remove(0)
}

async fn fixture_at(pool: &PgPool, label: &str) -> WorkerFixture {
    WorkerFixture::install_at(pool, label, InstallTargetV1::Generation3).await
}

const EVENTS_SQL: &str = "SELECT count(*)::INT8 FROM memory_evidence_events \
     WHERE tenant_id = $1 AND project = $2 AND event_kind = 'evidence.accepted'";
const ITEMS_SQL: &str = "SELECT count(*)::INT8 FROM memory_collected_items_v1 \
     WHERE tenant_id = $1 AND project = $2";
const BODIES_SQL: &str = "SELECT count(*)::INT8 FROM memory_body_objects_v1 \
     WHERE tenant_id = $1 AND project = $2";
const LEXICAL_SQL: &str = "SELECT count(*)::INT8 FROM memory_body_lexical_projection_v1 \
     WHERE tenant_id = $1 AND project = $2";
const PENDING_SQL: &str = "SELECT count(*)::INT8 FROM memory_collector_outbox_v1 \
     WHERE tenant_id = $1 AND project = $2 AND state = 'pending'";

// ---------------------------------------------------------------------------
// The connected proofs
// ---------------------------------------------------------------------------

#[tokio::test]
async fn live_stage_drain_project_recall_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let fixture = fixture_at(&pool, "collected-drain").await;

    let slack_staged = stage(&pool, &fixture, &slack(), fixture_drafts("slack")).await;
    assert_eq!(slack_staged.rows_staged, 5, "{slack_staged:?}");
    assert_eq!(slack_staged.containers_recorded, 1);
    let docs_staged = stage(&pool, &fixture, &docs(), fixture_drafts("docs")).await;
    assert_eq!(docs_staged.rows_staged, 1, "{docs_staged:?}");

    let report = drain(&fixture, &pool, "collect,project,embed").await;
    assert_eq!(counter(&report, WorkerStepV1::Collect, "appended"), 6);
    assert_eq!(
        counter(&report, WorkerStepV1::Bodies, "events_unprojectable"),
        0
    );
    let events = count(&pool, &fixture, EVENTS_SQL).await;
    assert_eq!(events, 6);
    assert_eq!(count(&pool, &fixture, ITEMS_SQL).await, events);
    assert_eq!(count(&pool, &fixture, BODIES_SQL).await, events);
    assert_eq!(count(&pool, &fixture, LEXICAL_SQL).await, events);
    assert_eq!(count(&pool, &fixture, PENDING_SQL).await, 0);
    let presented = count(
        &pool,
        &fixture,
        "SELECT count(*)::INT8 FROM memory_collected_item_heads_v1 \
         WHERE tenant_id = $1 AND project = $2 AND presented",
    )
    .await;
    assert_eq!(presented, 6, "every item has one presented head");

    let answer = recall(&pool, &fixture)
        .await
        .search("jitter", None, 10)
        .await
        .unwrap();
    assert_eq!(answer.absence.verdict, AbsenceVerdictV1::Present);
    assert!(
        answer
            .hits
            .iter()
            .all(|hit| hit.media_type == COLLECTED_ITEM_MEDIA_TYPE)
    );
    let bodies: Vec<Sha256Digest> = answer.hits.iter().map(|hit| hit.id).collect();
    let providers = providers_of(&pool, &fixture, &bodies).await;
    assert!(
        providers.contains("slack") && providers.contains("docs"),
        "jitter is in the Slack decision and the retry-budget spec: {providers:?}"
    );
    assert_eq!(answer.readiness.items_awaiting_admission, Some(0));
    assert!(!answer.readiness.collector_state_unreadable);
}

#[tokio::test]
async fn live_restage_is_noop_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let fixture = fixture_at(&pool, "collected-restage").await;
    let first = stage(&pool, &fixture, &slack(), fixture_drafts("slack")).await;
    assert_eq!(first.rows_staged, 5);
    // Before a drain, re-reading the same page stages nothing new.
    let again = stage(&pool, &fixture, &slack(), fixture_drafts("slack")).await;
    assert_eq!((again.rows_staged, again.rows_already_staged), (0, 5));
    drain(&fixture, &pool, "collect").await;
    let events = count(&pool, &fixture, EVENTS_SQL).await;

    // After it, too: the stage ids are the settled rows' own.
    let after = stage(&pool, &fixture, &slack(), fixture_drafts("slack")).await;
    assert_eq!((after.rows_staged, after.rows_already_staged), (0, 5));
    let report = drain(&fixture, &pool, "collect").await;
    assert_eq!(counter(&report, WorkerStepV1::Collect, "rows_read"), 0);
    assert_eq!(count(&pool, &fixture, EVENTS_SQL).await, events);
    assert_eq!(count(&pool, &fixture, ITEMS_SQL).await, events);
}

#[tokio::test]
async fn live_edit_moves_head_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let fixture = fixture_at(&pool, "collected-edit").await;
    let first = stage(
        &pool,
        &fixture,
        &docs(),
        vec![doc(
            "threshold.md",
            "the wombat threshold is three",
            1_000,
            ItemLifecycleV1::Live,
        )],
    )
    .await;
    drain(&fixture, &pool, "collect").await;
    let edited = stage(
        &pool,
        &fixture,
        &docs(),
        vec![doc(
            "threshold.md",
            "the wombat threshold is five",
            2_000,
            ItemLifecycleV1::Edited,
        )],
    )
    .await;
    assert_ne!(staged_version(&first), staged_version(&edited));
    drain(&fixture, &pool, "collect,project").await;

    let rows = heads(&pool, &fixture, "threshold.md").await;
    assert_eq!(rows.len(), 1, "one tier: {rows:?}");
    let (tier, presented, version, versions, lifecycle, disagreement) = &rows[0];
    assert_eq!(tier, "verified");
    assert!(*presented && !*disagreement);
    assert_eq!(version.as_slice(), staged_version(&edited).as_bytes());
    assert_eq!((*versions, lifecycle.as_str()), (2, "edited"));

    // The edit supersedes; the earlier version stays in the history and in
    // evidence recall.
    let recall = recall(&pool, &fixture).await;
    for word in ["three", "five"] {
        let answer = recall
            .search(&format!("wombat {word}"), None, 10)
            .await
            .unwrap();
        assert_eq!(answer.hits.len(), 1, "{word}: {:?}", answer.hits);
    }
}

#[tokio::test]
async fn live_older_version_late_keeps_head_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let fixture = fixture_at(&pool, "collected-late").await;
    let newer = stage(
        &pool,
        &fixture,
        &docs(),
        vec![doc(
            "late.md",
            "the gecko quota is nine",
            5_000,
            ItemLifecycleV1::Edited,
        )],
    )
    .await;
    drain(&fixture, &pool, "collect").await;
    stage(
        &pool,
        &fixture,
        &docs(),
        vec![doc(
            "late.md",
            "the gecko quota is two",
            4_000,
            ItemLifecycleV1::Live,
        )],
    )
    .await;
    drain(&fixture, &pool, "collect").await;
    let rows = heads(&pool, &fixture, "late.md").await;
    assert_eq!(rows.len(), 1);
    let (_, presented, version, versions, _, _) = &rows[0];
    assert!(*presented);
    assert_eq!(
        version.as_slice(),
        staged_version(&newer).as_bytes(),
        "the provider's order decides, never the arrival"
    );
    assert_eq!(*versions, 2);
}

#[tokio::test]
async fn live_verified_head_is_presented_over_a_newer_report_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let fixture = fixture_at(&pool, "collected-tiers").await;
    // An operator import reports a version first; it is presented alone.
    let reported = stage(
        &pool,
        &fixture,
        &docs_import(),
        vec![doc(
            "tiers.md",
            "the heron budget is four",
            3_000,
            ItemLifecycleV1::Edited,
        )],
    )
    .await;
    drain(&fixture, &pool, "collect").await;
    let rows = heads(&pool, &fixture, "tiers.md").await;
    assert_eq!(rows.len(), 1);
    assert_eq!((rows[0].0.as_str(), rows[0].1), ("reported", true));

    // A verified pull of an older, different version displaces it: one row
    // is demoted and the other promoted in one transaction, and the newer
    // report is a disagreement.
    let verified = stage(
        &pool,
        &fixture,
        &docs(),
        vec![doc(
            "tiers.md",
            "the heron budget is six",
            2_000,
            ItemLifecycleV1::Live,
        )],
    )
    .await;
    drain(&fixture, &pool, "collect").await;
    let rows = heads(&pool, &fixture, "tiers.md").await;
    assert_eq!(rows.len(), 2, "{rows:?}");
    let (reported_row, verified_row) = (&rows[0], &rows[1]);
    assert_eq!(reported_row.0, "reported");
    assert!(!reported_row.1 && !reported_row.5);
    assert_eq!(
        reported_row.2.as_slice(),
        staged_version(&reported).as_bytes()
    );
    assert_eq!(verified_row.0, "verified");
    assert!(verified_row.1, "a verified head is presented");
    assert!(verified_row.5, "the newer report differs: disagreement");
    assert_eq!(
        verified_row.2.as_slice(),
        staged_version(&verified).as_bytes()
    );
}

#[tokio::test]
async fn live_tombstone_suppresses_in_evidence_lexical_dense_and_get_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let fixture = fixture_at(&pool, "collected-tombstone").await;
    stage(
        &pool,
        &fixture,
        &docs(),
        vec![doc(
            "gone.md",
            "the narwhal ledger closes at noon",
            1_000,
            ItemLifecycleV1::Live,
        )],
    )
    .await;
    stage(
        &pool,
        &fixture,
        &slack(),
        vec![message(
            SLACK_CHANNEL,
            "1790000000.000100",
            "okapi rollout is paused",
            1_790_000_000_000_100,
        )],
    )
    .await;
    drain(&fixture, &pool, "collect,project,embed").await;

    let recall = recall(&pool, &fixture).await;
    let found = recall.search("narwhal", None, 10).await.unwrap();
    assert_eq!(found.hits.len(), 1);
    let body = found.hits[0].id;
    assert!(recall.get(body).await.unwrap().is_some());
    let vector = body_vector(&pool, &fixture, body).await;
    let dense = recall
        .search("zyzzyva quixotic", Some(vector.clone()), 10)
        .await
        .unwrap();
    assert!(
        dense.hits.iter().any(|hit| hit.id == body),
        "the dense lane finds the body before the delete"
    );
    let okapi = recall.search("okapi", None, 10).await.unwrap();
    assert_eq!(okapi.hits.len(), 1);
    let okapi_body = okapi.hits[0].id;

    // The provider deletes the document: a tombstone version heads the item.
    stage(
        &pool,
        &fixture,
        &docs(),
        vec![doc("gone.md", "", 2_000, ItemLifecycleV1::Deleted)],
    )
    .await;
    drain(&fixture, &pool, "collect,project,embed").await;
    let rows = heads(&pool, &fixture, "gone.md").await;
    assert_eq!(rows[0].4, "deleted");
    assert!(
        recall
            .search("narwhal", None, 10)
            .await
            .unwrap()
            .hits
            .is_empty()
    );
    assert!(recall.get(body).await.unwrap().is_none());
    let dense = recall
        .search("zyzzyva quixotic", Some(vector), 10)
        .await
        .unwrap();
    assert!(
        dense.hits.iter().all(|hit| hit.id != body),
        "the dense lane withholds the deleted body"
    );
    // The delete hid only its own item.
    assert_eq!(
        recall.search("okapi", None, 10).await.unwrap().hits.len(),
        1
    );

    // The channel turns private and is not listed: its container is
    // withdrawn, and everything in it is hidden at once.
    let mut private = slack();
    private.container.provider_audience = ProviderAudienceV1::Restricted;
    let withdrawn = stage(&pool, &fixture, &private, Vec::new()).await;
    assert_eq!(withdrawn.containers_withdrawn, 1);
    assert!(
        recall
            .search("okapi", None, 10)
            .await
            .unwrap()
            .hits
            .is_empty()
    );
    assert!(recall.get(okapi_body).await.unwrap().is_none());
}

#[tokio::test]
async fn live_tombstone_at_the_live_order_hides_every_item_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let fixture = fixture_at(&pool, "collected-tied-tombstone").await;
    // An export that marks an item deleted without moving its clock: the
    // delete shares the live version's order. Whichever version key is the
    // greater, the delete must head the item.
    let words = ["bison", "ferret", "lemur", "marten", "otter", "shrew"];
    let live: Vec<CollectedItemDraftV1> = words
        .iter()
        .map(|word| {
            doc(
                &format!("{word}.md"),
                &format!("the {word} ledger"),
                5_000,
                ItemLifecycleV1::Live,
            )
        })
        .collect();
    stage(&pool, &fixture, &docs(), live).await;
    drain(&fixture, &pool, "collect,project").await;
    let recall = recall(&pool, &fixture).await;
    for word in words {
        assert_eq!(
            recall.search(word, None, 10).await.unwrap().hits.len(),
            1,
            "{word} is recalled before the delete"
        );
    }

    let deleted: Vec<CollectedItemDraftV1> = words
        .iter()
        .map(|word| doc(&format!("{word}.md"), "", 5_000, ItemLifecycleV1::Deleted))
        .collect();
    stage(&pool, &fixture, &docs(), deleted).await;
    drain(&fixture, &pool, "collect,project").await;
    for word in words {
        let rows = heads(&pool, &fixture, &format!("{word}.md")).await;
        assert_eq!(rows[0].4, "deleted", "{word}: {rows:?}");
        assert!(
            recall.search(word, None, 10).await.unwrap().hits.is_empty(),
            "{word} is hidden after a delete at its own order"
        );
    }
}

#[tokio::test]
async fn live_recall_probed_before_the_collector_schema_reads_it_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let fixture = fixture_at(&pool, "collected-stale-probe").await;
    let scope = &fixture.installed.scope;
    // A serve that started before migrations 33 and 34: its startup probe
    // saw no collector state. The rollout migrates, installs, and configures
    // collectors while it keeps running.
    let mut before = capabilities(&pool, scope).await;
    before.schema_version = COLLECTED_ITEMS_SCHEMA_VERSION - 1;
    let capability = probe_evidence_recall(
        &pool,
        &before,
        scope,
        Sha256Digest::from_bytes(STUB_MODEL_DIGEST),
    )
    .await
    .unwrap()
    .expect("evidence recall is served before the collector schema");
    let early = CockroachEvidenceRecall::new(capability, pool.clone());

    stage(
        &pool,
        &fixture,
        &docs(),
        vec![doc(
            "numbat.md",
            "the numbat roster",
            1_000,
            ItemLifecycleV1::Live,
        )],
    )
    .await;
    let pending = early.search("numbat", None, 10).await.unwrap();
    assert_eq!(pending.readiness.items_awaiting_admission, Some(1));
    assert!(
        pending
            .absence
            .reasons
            .contains(&AbsenceReasonV1::IngestOutboxPending),
        "{:?}",
        pending.absence
    );

    drain(&fixture, &pool, "collect,project").await;
    let found = early.search("numbat", None, 10).await.unwrap();
    assert_eq!(found.hits.len(), 1);
    let body = found.hits[0].id;
    assert!(early.get(body).await.unwrap().is_some());

    stage(
        &pool,
        &fixture,
        &docs(),
        vec![doc("numbat.md", "", 2_000, ItemLifecycleV1::Deleted)],
    )
    .await;
    drain(&fixture, &pool, "collect,project").await;
    assert!(
        early
            .search("numbat", None, 10)
            .await
            .unwrap()
            .hits
            .is_empty(),
        "the deleted text is hidden from the early process too"
    );
    assert!(early.get(body).await.unwrap().is_none());
}

#[tokio::test]
async fn live_import_never_reopens_a_channel_a_pull_withdrew_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let fixture = fixture_at(&pool, "collected-stale-export").await;
    stage(
        &pool,
        &fixture,
        &slack(),
        vec![message(
            SLACK_CHANNEL,
            "1790000100.000100",
            "numbat migration is scheduled",
            1_790_000_100_000_100,
        )],
    )
    .await;
    drain(&fixture, &pool, "collect,project").await;
    let recall = recall(&pool, &fixture).await;
    assert_eq!(hits(&recall, "numbat").await, 1);

    // The channel goes private and is not listed: the pull withdraws it.
    let mut private = slack();
    private.container.provider_audience = ProviderAudienceV1::Restricted;
    assert_eq!(
        stage(&pool, &fixture, &private, Vec::new())
            .await
            .containers_withdrawn,
        1
    );
    assert_eq!(hits(&recall, "numbat").await, 0);

    // An operator imports an older export in which it was still public. The
    // export neither re-opens the channel nor stages into it.
    let imported = stage(
        &pool,
        &fixture,
        &slack_import(),
        vec![message(
            SLACK_CHANNEL,
            "1790000050.000100",
            "numbat rollback drill",
            1_790_000_050_000_100,
        )],
    )
    .await;
    assert_eq!(imported.containers_recorded, 0, "{imported:?}");
    assert_eq!(
        refusal(&imported),
        (
            DeadLetterReasonV1::AudienceRefused,
            "container_withdrawn".to_owned()
        )
    );
    drain(&fixture, &pool, "collect,project").await;
    assert_eq!(hits(&recall, "numbat").await, 0);

    // The pull seeing it public again is what re-opens it.
    assert_eq!(
        stage(&pool, &fixture, &slack(), Vec::new())
            .await
            .containers_recorded,
        1
    );
    assert_eq!(hits(&recall, "numbat").await, 1);
}

#[tokio::test]
async fn live_pull_withdraws_a_channel_only_captures_reached_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let fixture = fixture_at(&pool, "collected-shared-channel").await;
    let scopes = [CaptureScopeV1 {
        provider: "slack".into(),
        provider_scope_id: SLACK_TEAM.into(),
        containers: CaptureContainersV1::All,
    }];
    let shared = "C07SHARED01";
    // No collector has seen the channel; the operator's capture scope admits
    // an agent's capture of it.
    let captured = capture(
        &pool,
        &fixture,
        vec![message(
            shared,
            "1790000200.000100",
            "pangolin contract terms",
            1_790_000_200_000_100,
        )],
        &scopes,
    )
    .await;
    assert_eq!(captured.rows_staged, 1, "{captured:?}");
    drain(&fixture, &pool, "collect,project").await;
    let recall = recall(&pool, &fixture).await;
    assert_eq!(hits(&recall, "pangolin").await, 1);

    // The pull learns it is a Slack Connect channel. Nothing was ever
    // recorded for it, and it is recorded withdrawn now.
    let mut connect = slack();
    connect.container.id = shared.to_owned();
    connect.container.label = Some("acme-partner".to_owned());
    connect.container.provider_audience = ProviderAudienceV1::ExternallyShared;
    let observed = stage(&pool, &fixture, &connect, Vec::new()).await;
    assert_eq!(observed.containers_withdrawn, 1, "{observed:?}");
    assert_eq!(hits(&recall, "pangolin").await, 0);
    let label: Option<String> = sqlx::query_scalar(
        "SELECT label FROM memory_collector_containers_v1 \
         WHERE tenant_id = $1 AND project = $2 AND container_id = $3",
    )
    .bind(fixture.installed.scope.tenant_id)
    .bind(&fixture.installed.scope.project)
    .bind(shared)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(label, None, "a never-admitted container keeps no label");

    // The capture scope no longer admits captures into it.
    let again = capture(
        &pool,
        &fixture,
        vec![message(
            shared,
            "1790000300.000100",
            "pangolin renewal",
            1_790_000_300_000_100,
        )],
        &scopes,
    )
    .await;
    assert_eq!(
        refusal(&again),
        (
            DeadLetterReasonV1::AudienceRefused,
            "container_withdrawn".to_owned()
        )
    );
}

#[tokio::test]
async fn live_item_moved_into_an_unlisted_private_team_is_withdrawn_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let fixture = fixture_at(&pool, "collected-moved-item").await;
    let (public_team, private_team) = ("TEAMPUB", "TEAMSEC");
    let issue_id = "7c2e9f40-1d3b-4a55-8e6f-2b9d0c4a1e11";
    stage(
        &pool,
        &fixture,
        &linear(public_team, ProviderAudienceV1::TeamPublic),
        vec![issue(
            issue_id,
            public_team,
            "the quokka parser drops frames",
            1_000,
        )],
    )
    .await;
    drain(&fixture, &pool, "collect,project").await;
    let recall = recall(&pool, &fixture).await;
    assert_eq!(hits(&recall, "quokka").await, 1);

    // An issue first seen in the private team is only a dead letter.
    let unlisted = linear(private_team, ProviderAudienceV1::Restricted);
    let first_sighting = stage(
        &pool,
        &fixture,
        &unlisted,
        vec![issue(
            "0d1e2f3a-4b5c-4d6e-8f70-8192a3b4c5d6",
            private_team,
            "the wallaby incident",
            1_500,
        )],
    )
    .await;
    assert_eq!(first_sighting.items_withdrawn, 0);

    // The issue is triaged into the private team. The public team is still
    // public, so no container is withdrawn; the item is.
    let moved = stage(
        &pool,
        &fixture,
        &unlisted,
        vec![issue(
            issue_id,
            private_team,
            "the quokka parser leaks keys",
            2_000,
        )],
    )
    .await;
    assert_eq!(
        refusal(&moved),
        (
            DeadLetterReasonV1::AudienceRefused,
            "restricted_unlisted".to_owned()
        )
    );
    assert_eq!(
        (moved.containers_withdrawn, moved.items_withdrawn),
        (0, 1),
        "{moved:?}"
    );
    assert_eq!(hits(&recall, "quokka").await, 0);
    // An import of an older export cannot lift a pull's withdrawal.
    let older = issue(
        issue_id,
        public_team,
        "the quokka parser drops frames",
        1_000,
    );
    let exported = stage(&pool, &fixture, &linear_export(public_team), vec![older]).await;
    assert_eq!(exported.item_withdrawals_lifted, 0, "{exported:?}");
    drain(&fixture, &pool, "collect,project").await;
    assert_eq!(hits(&recall, "quokka").await, 0);

    // The operator lists the private team: the next read of the issue, at
    // the same order, admits it and lifts the withdrawal.
    let listed = Collector {
        policy: AudiencePolicyV1 {
            operator_declared: false,
            private_containers: vec![private_team.to_owned()],
        },
        ..linear(private_team, ProviderAudienceV1::Restricted)
    };
    let admitted = stage(
        &pool,
        &fixture,
        &listed,
        vec![issue(
            issue_id,
            private_team,
            "the quokka parser leaks keys",
            2_000,
        )],
    )
    .await;
    assert_eq!(admitted.item_withdrawals_lifted, 1, "{admitted:?}");
    drain(&fixture, &pool, "collect,project").await;
    assert_eq!(hits(&recall, "quokka leaks").await, 1);
}

/// Fake credentials, assembled at runtime so no credential-shaped literal
/// sits in the source.
fn planted_secrets() -> Vec<String> {
    let body = |length: usize| -> String {
        "A1b2C3d4E5f6G7h8J9k0"
            .chars()
            .cycle()
            .take(length)
            .collect()
    };
    vec![
        ["xox", "b-", &body(24)].concat(),
        ["lin_", "api_", &body(32)].concat(),
        ["grn", "_", &body(24)].concat(),
        ["AKI", "A", "Z7Q2X9W4R6T1Y8U3"].concat(),
        ["whs", "ec_", &body(24)].concat(),
    ]
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Every stored byte string of a scope's collector and body planes that
/// could carry text.
async fn stored_bytes(pool: &PgPool, fixture: &WorkerFixture) -> Vec<Vec<u8>> {
    let mut stored = Vec::new();
    for sql in [
        "SELECT COALESCE(canonical_envelope, ''::BYTES) FROM memory_collector_outbox_v1 \
         WHERE tenant_id = $1 AND project = $2",
        "SELECT COALESCE(last_error, '')::BYTES FROM memory_collector_outbox_v1 \
         WHERE tenant_id = $1 AND project = $2",
        "SELECT diagnostic::BYTES FROM memory_collector_dead_letters_v1 \
         WHERE tenant_id = $1 AND project = $2",
        "SELECT body_bytes FROM memory_body_objects_v1 WHERE tenant_id = $1 AND project = $2",
        "SELECT lexical_text::BYTES FROM memory_body_lexical_projection_v1 \
         WHERE tenant_id = $1 AND project = $2",
        "SELECT (external_id || COALESCE(provider_url, '') || version_marker)::BYTES \
         FROM memory_collected_items_v1 WHERE tenant_id = $1 AND project = $2",
        "SELECT target::BYTES FROM memory_collected_item_links_v1 \
         WHERE tenant_id = $1 AND project = $2",
    ] {
        let rows: Vec<Vec<u8>> = sqlx::query_scalar(sql)
            .bind(fixture.installed.scope.tenant_id)
            .bind(&fixture.installed.scope.project)
            .fetch_all(pool)
            .await
            .unwrap_or_else(|error| panic!("{sql}: {error}"));
        stored.extend(rows);
    }
    stored
}

#[tokio::test]
async fn live_planted_secrets_absent_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let fixture = fixture_at(&pool, "collected-secrets").await;
    let secrets = planted_secrets();
    let text = format!("rotate the pelican credentials: {}", secrets.join(" and "));
    let mut linked = doc("secrets.md", &text, 1_000, ItemLifecycleV1::Live);
    linked
        .links
        .push(ostk_fleet_recall::collectors::draft::DraftLinkV1 {
            rel: ostk_fleet_recall::memory_contracts::collected_item::LinkRelV1::new("url")
                .unwrap(),
            target: format!("https://hooks.example.test/in?key={}", secrets[4]),
            label: None,
        });
    // A secret in an id cannot be redacted: that item is withheld.
    let withheld = doc(
        &format!("{}.md", secrets[1]),
        "pelican id",
        1_000,
        ItemLifecycleV1::Live,
    );
    let staged = stage(&pool, &fixture, &docs(), vec![linked, withheld]).await;
    assert!(matches!(staged.items[0], StagedItemV1::Staged { .. }));
    assert!(matches!(
        staged.items[1],
        StagedItemV1::Refused {
            reason: DeadLetterReasonV1::RedactionWithheld,
            ..
        }
    ));

    let check = |stored: &[Vec<u8>], when: &str| {
        for secret in &secrets {
            let hexed = hex::encode(secret.as_bytes());
            for value in stored {
                assert!(
                    !contains(value, secret.as_bytes()) && !contains(value, hexed.as_bytes()),
                    "a planted credential is stored {when}"
                );
            }
        }
    };
    // Pending: the outbox holds the redacted envelope.
    check(&stored_bytes(&pool, &fixture).await, "in the staged outbox");
    drain(&fixture, &pool, "collect,project,embed").await;
    let stored = stored_bytes(&pool, &fixture).await;
    check(&stored, "after admission and projection");
    let answer = recall(&pool, &fixture)
        .await
        .search("pelican", None, 10)
        .await
        .unwrap();
    assert_eq!(answer.hits.len(), 1, "the redacted item is recalled");
    assert!(answer.hits[0].snippet.contains("pelican"));
}

/// `(state, canonical_envelope, envelope_sha256, accepted_event_id)`.
type SettledRow = (String, Option<Vec<u8>>, Vec<u8>, Option<Vec<u8>>);

#[tokio::test]
async fn live_envelope_nulled_after_settle_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let fixture = fixture_at(&pool, "collected-envelope").await;
    stage(&pool, &fixture, &slack(), fixture_drafts("slack")).await;
    let held = count(
        &pool,
        &fixture,
        "SELECT count(*)::INT8 FROM memory_collector_outbox_v1 \
         WHERE tenant_id = $1 AND project = $2 AND canonical_envelope IS NOT NULL",
    )
    .await;
    assert_eq!(held, 5, "a pending row holds its envelope");
    drain(&fixture, &pool, "collect").await;
    let settled: Vec<SettledRow> = sqlx::query_as(
        "SELECT state, canonical_envelope, envelope_sha256, accepted_event_id \
         FROM memory_collector_outbox_v1 WHERE tenant_id = $1 AND project = $2",
    )
    .bind(fixture.installed.scope.tenant_id)
    .bind(&fixture.installed.scope.project)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(settled.len(), 5);
    for (state, envelope, digest, event) in settled {
        assert_eq!(state, "admitted");
        assert!(envelope.is_none(), "a settled row keeps no redacted text");
        assert_eq!(digest.len(), 32, "only its digest remains");
        assert!(event.is_some());
    }
}

#[tokio::test]
async fn live_pending_rows_make_absence_unknown_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let fixture = fixture_at(&pool, "collected-pending").await;
    let collector = docs();
    let status = CollectorSourceStatusV1 {
        instance: collector.instance.connector_instance_id.clone(),
        provider: collector.instance.provider.clone(),
        provider_scope_id: collector.instance.provider_scope_id.clone(),
        mode: CollectionModeV1::Pull,
        coverage_role: CoverageRoleV1::Live,
        owner: CollectorOwnerV1::Worker,
        stale_after_seconds: 86_400,
        outcome: CollectorOutcomeV1::Ok,
        reconciled: true,
        error: None,
    };
    stage_with(
        &pool,
        &fixture,
        &collector,
        vec![doc(
            "pending.md",
            "the ibis roster",
            1_000,
            ItemLifecycleV1::Live,
        )],
        Some(&status),
    )
    .await;

    let recall = recall(&pool, &fixture).await;
    let answer = recall
        .search("unfindable marmoset", None, 10)
        .await
        .unwrap();
    assert_eq!(answer.absence.verdict, AbsenceVerdictV1::Unknown);
    assert!(
        answer
            .absence
            .reasons
            .contains(&AbsenceReasonV1::IngestOutboxPending),
        "{:?}",
        answer.absence
    );
    assert_eq!(answer.readiness.items_awaiting_admission, Some(1));
    // The collector is listed beside the worker's sources, by provider.
    let listed = answer
        .sources
        .active
        .iter()
        .find(|source| source.connector_instance == "docs.specs")
        .expect("the collector's status row is listed");
    assert_eq!(listed.kind, EvidenceSourceKindV1::Collector);
    assert_eq!(listed.provider.as_deref(), Some("docs"));
    assert!(listed.last_checked_at.is_some(), "a reconciliation checks");

    drain(&fixture, &pool, "collect,project").await;
    let answer = recall
        .search("unfindable marmoset", None, 10)
        .await
        .unwrap();
    assert_eq!(answer.readiness.items_awaiting_admission, Some(0));
    assert!(
        !answer
            .absence
            .reasons
            .contains(&AbsenceReasonV1::IngestOutboxPending),
        "{:?}",
        answer.absence
    );
    // It has no coverage receipt yet, so an empty answer is still unknown.
    assert!(
        answer
            .absence
            .reasons
            .contains(&AbsenceReasonV1::IncompleteCoverage)
    );
}

#[tokio::test]
async fn live_generation_two_head_holds_rows_pending_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let fixture = WorkerFixture::install(&pool, "collected-generation-two").await;
    // Generation 2 promises redaction, so a collector can stage; it carries
    // no collected connector, so nothing it staged can be admitted.
    stage_through(
        &pool,
        &fixture,
        &docs(),
        vec![doc(
            "held.md",
            "the tapir schedule",
            1_000,
            ItemLifecycleV1::Live,
        )],
        None,
        GIT_CONNECTOR.connector_schema,
    )
    .await;
    let report = tick(&fixture, &pool, "collect").await;
    let collect = step(&report, WorkerStepV1::Collect);
    assert_eq!(collect.status, WorkerStepStatusV1::Failed);
    let reason = collect.reason.as_deref().unwrap();
    assert!(reason.contains("--target generation-3"), "{reason}");
    assert_eq!(counter(&report, WorkerStepV1::Collect, "held"), 1);
    assert_eq!(count(&pool, &fixture, PENDING_SQL).await, 1);
    assert_eq!(count(&pool, &fixture, EVENTS_SQL).await, 0);

    // Once the operator moves the scope, the held row drains.
    let mut request = fixture.installed.request();
    request.target = InstallTargetV1::Generation3;
    install_writer_authority(&pool, &request, retry_policy())
        .await
        .expect("the scope moves to generation 3");
    let report = drain(&fixture, &pool, "collect").await;
    assert_eq!(counter(&report, WorkerStepV1::Collect, "appended"), 1);
    assert_eq!(count(&pool, &fixture, PENDING_SQL).await, 0);
}

#[tokio::test]
async fn live_bad_row_dead_letters_rest_drain_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let fixture = fixture_at(&pool, "collected-bad-row").await;
    let staged = stage(
        &pool,
        &fixture,
        &docs(),
        vec![
            doc("a.md", "the first quail", 1_000, ItemLifecycleV1::Live),
            doc("b.md", "the second quail", 1_000, ItemLifecycleV1::Live),
            doc("c.md", "the third quail", 1_000, ItemLifecycleV1::Live),
        ],
    )
    .await;
    let StagedItemV1::Staged { stage_ids, .. } = &staged.items[1] else {
        panic!("b.md stages");
    };
    // A row whose stored scope no longer matches its envelope: admission
    // refuses it.
    sqlx::query(
        "UPDATE memory_collector_outbox_v1 SET provider_scope_id = 'docs.elsewhere' \
         WHERE tenant_id = $1 AND project = $2 AND stage_id = $3",
    )
    .bind(fixture.installed.scope.tenant_id)
    .bind(&fixture.installed.scope.project)
    .bind(stage_ids[0].as_bytes().as_slice())
    .execute(&pool)
    .await
    .unwrap();

    let report = drain(&fixture, &pool, "collect").await;
    assert_eq!(counter(&report, WorkerStepV1::Collect, "dead_lettered"), 1);
    assert_eq!(counter(&report, WorkerStepV1::Collect, "appended"), 2);
    assert_eq!(count(&pool, &fixture, ITEMS_SQL).await, 2);
    let (state, envelope): (String, Option<Vec<u8>>) = sqlx::query_as(
        "SELECT state, canonical_envelope FROM memory_collector_outbox_v1 \
         WHERE tenant_id = $1 AND project = $2 AND stage_id = $3",
    )
    .bind(fixture.installed.scope.tenant_id)
    .bind(&fixture.installed.scope.project)
    .bind(stage_ids[0].as_bytes().as_slice())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(state, "dead_lettered");
    assert!(envelope.is_none());
    let (reason, stage_id): (String, Option<Vec<u8>>) = sqlx::query_as(
        "SELECT reason, stage_id FROM memory_collector_dead_letters_v1 \
         WHERE tenant_id = $1 AND project = $2",
    )
    .bind(fixture.installed.scope.tenant_id)
    .bind(&fixture.installed.scope.project)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(reason, "admission_refused");
    assert_eq!(
        stage_id.as_deref(),
        Some(stage_ids[0].as_bytes().as_slice())
    );
}

#[tokio::test]
async fn live_collector_tables_unreadable_is_unknown_not_absent_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let owner = common::migrated_pool(&database_url).await;
    let fixture = fixture_at(&owner, "collected-unreadable").await;
    stage(
        &owner,
        &fixture,
        &docs(),
        vec![doc(
            "seen.md",
            "the axolotl charter",
            1_000,
            ItemLifecycleV1::Live,
        )],
    )
    .await;
    drain(&fixture, &owner, "collect,project").await;
    let found = recall(&owner, &fixture)
        .await
        .search("axolotl", None, 10)
        .await
        .unwrap();
    assert_eq!(found.hits.len(), 1);
    let body = found.hits[0].id;

    // A login with the Stage-5 grants but not the collector grants.
    let role = RuntimeProbeRole::create_worker_with(&owner, &database_url, true, false).await;
    let reads = async {
        let recall = recall_over(&role.pool, &owner, &fixture.installed.scope).await;
        let answer = recall.search("axolotl", None, 10).await?;
        let got = recall.get(body).await?;
        ostk_fleet_recall::Result::Ok((answer, got))
    }
    .await;
    role.drop_role(&owner).await;
    let (answer, got) = reads.expect("evidence recall is still served");
    assert!(answer.hits.is_empty(), "a collected body is withheld");
    assert!(got.is_none());
    assert_eq!(answer.absence.verdict, AbsenceVerdictV1::Unknown);
    assert!(
        answer
            .absence
            .reasons
            .contains(&AbsenceReasonV1::CollectorStateUnreadable)
    );
    assert!(answer.readiness.collector_state_unreadable);
    assert_eq!(answer.readiness.items_awaiting_admission, None);
}

#[tokio::test]
async fn live_collect_runs_under_a_runtime_member_role_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let owner = common::migrated_pool(&database_url).await;
    let fixture = fixture_at(&owner, "collected-member").await;
    stage(&owner, &fixture, &slack(), fixture_drafts("slack")).await;
    let capabilities = capabilities(&owner, &fixture.installed.scope).await;
    let all = parse_steps("all").unwrap();

    // Without the collector grants the preflight names a collector table.
    let without = RuntimeProbeRole::create_worker_with(&owner, &database_url, true, false).await;
    let refusal = probe_worker_privileges(&without.pool, &capabilities, &all).await;
    // On a schema before the collector tables the same login passes: nothing
    // to drain.
    let mut older = capabilities.clone();
    older.schema_version = COLLECTED_ITEMS_SCHEMA_VERSION - 1;
    let older_preflight = probe_worker_privileges(&without.pool, &older, &all).await;
    without.drop_role(&owner).await;
    let message = refusal
        .expect_err("the collector grants are required")
        .to_string();
    assert!(
        message.contains("memory_collect") && message.contains("runtime-role-grants.sql"),
        "{message}"
    );
    older_preflight.expect("below the collector schema the collect step probes nothing");

    let member = RuntimeProbeRole::create_worker_member(&owner, &database_url).await;
    let preflight = probe_worker_privileges(&member.pool, &capabilities, &all).await;
    let report = if preflight.is_ok() {
        Some(tick(&fixture, &member.pool, "collect,project").await)
    } else {
        None
    };
    member.drop_role(&owner).await;
    preflight.expect("the runtime grants cover the collect step");
    let report = report.expect("the tick ran");
    assert!(
        !report.failed(),
        "{}",
        serde_json::to_string_pretty(&report).unwrap()
    );
    assert_eq!(counter(&report, WorkerStepV1::Collect, "appended"), 5);
}

/// Mark migration 34's history row failed, so the schema reads as 33 although
/// the tables exist, run `body`, and mark it successful again whatever
/// `body` did. The database is shared: every live test binary runs alone, and
/// this binary runs its tests on one thread, so no other test sees the window.
async fn with_schema_below_collected_items<F>(pool: &PgPool, body: F)
where
    F: std::future::Future<Output = ()>,
{
    use futures::FutureExt as _;

    let mark = |success: bool| {
        sqlx::query("UPDATE _sqlx_migrations SET success = $1 WHERE version = $2")
            .bind(success)
            .bind(COLLECTED_ITEMS_SCHEMA_VERSION)
            .execute(pool)
    };
    mark(false).await.unwrap();
    let outcome = std::panic::AssertUnwindSafe(body).catch_unwind().await;
    mark(true).await.unwrap();
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

#[tokio::test]
async fn live_steps_all_skips_collect_below_the_collector_schema_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let fixture = WorkerFixture::install(&pool, "collected-below-schema").await;
    with_schema_below_collected_items(
        &pool,
        Box::pin(async {
            assert_eq!(
                capabilities(&pool, &fixture.installed.scope)
                    .await
                    .schema_version,
                COLLECTED_ITEMS_SCHEMA_VERSION - 1
            );
            let report = fixture.worker(&pool, "all").await.run_tick().await;
            for which in WorkerStepV1::ALL {
                let expected = if which == WorkerStepV1::Collect {
                    WorkerStepStatusV1::Skipped
                } else {
                    WorkerStepStatusV1::Ok
                };
                assert_eq!(
                    step(&report, which).status,
                    expected,
                    "{which:?}: {}",
                    serde_json::to_string_pretty(&report).unwrap()
                );
            }
            assert_eq!(
                step(&report, WorkerStepV1::Collect).reason.as_deref(),
                Some("schema_below_34")
            );

            // With a collector configured, the same schema is a failure that
            // names the fix.
            let mut sources = fixture.sources_json();
            sources["collectors"] = serde_json::json!([{
                "provider": "docs",
                "connector_principal": "principal.docs",
                "connector_instance": "docs.specs",
                "provider_scope_id": DOCS_ROOT,
                "audience": {"operator_declared": true}
            }]);
            let report = fixture
                .worker_with(&pool, "collect", &sources, Arc::new(RecordedCi))
                .await
                .run_tick()
                .await;
            let collect = step(&report, WorkerStepV1::Collect);
            assert_eq!(collect.status, WorkerStepStatusV1::Failed);
            assert!(
                collect
                    .reason
                    .as_deref()
                    .is_some_and(|reason| reason.contains("ostk-fleet-recall migrate")),
                "{collect:?}"
            );
        }),
    )
    .await;
}
