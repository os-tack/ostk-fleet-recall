//! Connected proofs of agent capture (ADR 0008 D10): `remember(action=
//! "capture")` relays what an agent read through its own connectors into the
//! collected-item sink as reported items it attests. The server alone decides
//! each item's audience; `enabled` admits in the call and `stage_only` leaves
//! admission to the worker; the receipt keeps a digest and never the text; a
//! key replays its answer and a new key stages nothing new; a second agent is
//! a second attestation; a capture never displaces a verified head; and a
//! writer with capture disabled, or unable to serve it, changes nothing.
//!
//! Every test needs `FLEET_RECALL_TEST_DATABASE_URL` and returns at once
//! without it.

mod common;

use std::collections::HashMap;
use std::sync::Arc;

use ostk_fleet_recall::application::LifecycleServing;
use ostk_fleet_recall::collectors::audience::{AudiencePolicyV1, ProviderAudienceV1};
use ostk_fleet_recall::collectors::binding::CollectorInstanceV1;
use ostk_fleet_recall::collectors::draft::{
    CollectedItemDraftV1, DraftContainerV1, DraftSectionV1,
};
use ostk_fleet_recall::collectors::redaction::CollectorRedactorV1;
use ostk_fleet_recall::collectors::sink::{
    CollectedItemSink, ContainerObservationV1, StageContextV1, StageDraftV1,
};
use ostk_fleet_recall::config::CollectedCaptureModeV1;
use ostk_fleet_recall::evidence_recall::{
    AbsenceReasonV1, AbsenceVerdictV1, CockroachEvidenceRecall, EvidenceRecall as _,
    probe_evidence_recall,
};
use ostk_fleet_recall::item_recall::{
    CockroachItemRecall, ItemGetV1, ItemRecall as _, ItemReferenceV1, ItemSearchRequestV1,
    probe_item_recall,
};
use ostk_fleet_recall::ledger::CockroachClaimLedger;
use ostk_fleet_recall::mcp::tool_list_for_surfaces;
use ostk_fleet_recall::memory_contracts::collected_item::{
    BoundedTextV1, CollectionModeV1, ContainerKindV1, ItemLifecycleV1, ObjectKindV1,
    ProviderKindV1, TextFormatV1, TrustTierV1,
};
use ostk_fleet_recall::memory_contracts::common::ContractId;
use ostk_fleet_recall::memory_contracts::digest::Sha256Digest;
use ostk_fleet_recall::registry_activation::install::InstallTargetV1;
use ostk_fleet_recall::remember_runtime::{
    CaptureDispositionV1, CaptureRequestV1, CaptureResponseV1, CaptureStartup, CaptureStatusV1,
    CockroachCapture, ItemCapture as _, PreparedCaptureV1, start_collected_capture_with,
};
use ostk_fleet_recall::service::{
    FleetMemoryService as _, RecallAction, RecallRequest, RememberAction, RememberRequest,
    RememberSurface, ServiceError,
};
use ostk_fleet_recall::store::cockroach::{CockroachStore, DatabaseCapabilities};
use ostk_fleet_recall::{CockroachMemoryService, FleetError, FleetScope};
use ostk_recall_core::PrivacyTier;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use sqlx::PgPool;

use common::authority::retry_policy;
use common::runtime_role::RuntimeProbeRole;
use common::worker::{RecordedCi, STUB_MODEL_DIGEST, StubEmbedder, WorkerFixture};

const SLACK_TEAM: &str = "T07ACME0001";
const SLACK_CHANNEL: &str = "C07PLATENG1";
const LINEAR_ORG: &str = "5b0c7f1e-8d2a-4c61-9f3e-2a7d4b9c1e05";
/// The message a verified Slack pull reads first, and its provider order.
const PULL_TS: &str = "1790006860.001100";
const PULL_ORDER: u64 = 1_790_006_860_001_100;
/// A second fleet agent in the same scope.
const AGENT_B: &str = "fleet-recall-live-test-b";

const CAPTURE_ENV: &str = "FLEET_RECALL_COLLECTED_CAPTURE";
const SCOPES_ENV: &str = "FLEET_RECALL_COLLECTED_CAPTURE_SCOPES";
const KEK_ENV: &str = "FLEET_RECALL_CONTENT_KEK_HEX";

const EVENTS_SQL: &str = "SELECT count(*)::INT8 FROM memory_evidence_events \
     WHERE tenant_id = $1 AND project = $2 AND event_kind = 'evidence.accepted'";

// ---------------------------------------------------------------------------
// A verified collector, so a container is recorded as readable
// ---------------------------------------------------------------------------

fn slack_instance() -> CollectorInstanceV1 {
    CollectorInstanceV1 {
        connector_instance_id: ContractId::new("slack.acme").unwrap(),
        provider: ProviderKindV1::new("slack").unwrap(),
        provider_scope_id: BoundedTextV1::new(SLACK_TEAM).unwrap(),
    }
}

/// The message a Slack pull reads in the fixture channel.
fn pulled_message(text: &str) -> CollectedItemDraftV1 {
    CollectedItemDraftV1 {
        provider: ProviderKindV1::new("slack").unwrap(),
        provider_scope_id: SLACK_TEAM.into(),
        object_kind: ObjectKindV1::new("message").unwrap(),
        external_id: format!("{SLACK_CHANNEL}:{PULL_TS}"),
        marker: Some(PULL_TS.into()),
        order_micros: PULL_ORDER,
        lifecycle: ItemLifecycleV1::Live,
        container: Some(DraftContainerV1 {
            kind: ContainerKindV1::new("slack.channel").unwrap(),
            id: SLACK_CHANNEL.into(),
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

/// Stage `drafts` through a Slack pull that observes the fixture channel with
/// `audience`: a public channel is recorded readable, a restricted one it
/// does not list is withdrawn.
async fn pull(
    pool: &PgPool,
    fixture: &WorkerFixture,
    drafts: Vec<CollectedItemDraftV1>,
    audience: ProviderAudienceV1,
) {
    let verified = fixture
        .installed
        .runtime(pool)
        .await
        .verify()
        .await
        .expect("the installed head verifies");
    let active = verified
        .bind_connector(&ContractId::new(CollectionModeV1::Pull.connector_schema_id()).unwrap())
        .expect("the active package carries the pull connector");
    let redactor =
        CollectorRedactorV1::from_active_package(&active).expect("the package promises redaction");
    let staged: Vec<StageDraftV1> = drafts
        .into_iter()
        .map(|draft| StageDraftV1 {
            delivery_id: Sha256::digest(draft.external_id.as_bytes()).to_vec(),
            provider_audience: None,
            draft,
        })
        .collect();
    let observations = [ContainerObservationV1 {
        kind: ContainerKindV1::new("slack.channel").unwrap(),
        id: SLACK_CHANNEL.to_owned(),
        label: Some("plat-eng".to_owned()),
        provider_audience: audience,
    }];
    CollectedItemSink::new(pool.clone(), &fixture.installed.scope, retry_policy())
        .unwrap()
        .stage(
            &staged,
            &StageContextV1 {
                instance: &slack_instance(),
                principal: &ContractId::new("principal.slack").unwrap(),
                mode: CollectionModeV1::Pull,
                attester: None,
                via: None,
                redactor: &redactor,
                policy: &AudiencePolicyV1::default(),
                capture_scopes: &[],
                pass_seq: None,
                container_observations: &observations,
                cursor_advances: &[],
                source_status: None,
            },
        )
        .await
        .expect("the pull stages");
}

// ---------------------------------------------------------------------------
// Capture
// ---------------------------------------------------------------------------

/// One capture item as an agent sends it: a Slack message in the fixture
/// channel, with `overrides` applied (a `null` removes a field).
fn item(external_id: &str, text: &str, overrides: &Value) -> Value {
    let mut item = json!({
        "provider": "slack",
        "provider_scope_id": SLACK_TEAM,
        "object_kind": "message",
        "external_id": external_id,
        "container": { "kind": "slack.channel", "id": SLACK_CHANNEL },
        "updated_at": "2026-09-22T10:00:00Z",
        "text": text,
        "url": format!(
            "https://acme.slack.com/archives/{SLACK_CHANNEL}/p{}",
            external_id.rsplit(':').next().unwrap().replace('.', "")
        ),
    });
    for (name, value) in overrides.as_object().unwrap() {
        if value.is_null() {
            item.as_object_mut().unwrap().remove(name);
        } else {
            item[name] = value.clone();
        }
    }
    item
}

fn request(items: &[Value]) -> CaptureRequestV1 {
    serde_json::from_value(json!({ "items": items })).expect("a capture request")
}

/// The variables `serve` would run with: the installer's pins, the capture
/// switch, and, for `enabled` only, the content key.
fn variables(fixture: &WorkerFixture, mode: &str) -> HashMap<String, String> {
    let mut variables: HashMap<String, String> =
        serde_json::from_value(serde_json::to_value(&fixture.installed.report.pins).unwrap())
            .expect("the pins are one string per variable");
    variables.insert(CAPTURE_ENV.into(), mode.into());
    if mode == "enabled" {
        variables.insert(KEK_ENV.into(), fixture.installed.kek_hex.clone());
    }
    variables
}

/// The fixture's scope, as `agent` runs in it.
fn scope_of(fixture: &WorkerFixture, agent: &str) -> FleetScope {
    let scope = &fixture.installed.scope;
    FleetScope::new(
        scope.tenant_id,
        scope.project.clone(),
        agent,
        None,
        PrivacyTier::T1Project,
    )
    .unwrap()
}

async fn capabilities(pool: &PgPool, scope: &FleetScope) -> DatabaseCapabilities {
    CockroachStore::from_pool(pool.clone(), scope.clone())
        .unwrap()
        .capabilities()
        .await
        .unwrap()
}

/// Start capture as `serve` does, over `pool` and `variables`.
async fn start(
    pool: &PgPool,
    scope: &FleetScope,
    variables: &HashMap<String, String>,
) -> CaptureStartup {
    start_over(pool, pool, scope, variables).await
}

/// [`start`] over a login `pool`, with the schema snapshot read through the
/// `owner` pool.
async fn start_over(
    pool: &PgPool,
    owner: &PgPool,
    scope: &FleetScope,
    variables: &HashMap<String, String>,
) -> CaptureStartup {
    let capabilities = capabilities(owner, scope).await;
    start_collected_capture_with(pool.clone(), &capabilities, scope, retry_policy(), |name| {
        variables.get(name).cloned()
    })
    .await
}

fn served(startup: CaptureStartup) -> (Arc<CockroachCapture>, CaptureStatusV1) {
    match startup {
        CaptureStartup::Served(capture, status) => {
            assert!(status.served);
            assert!(status.reason.is_none());
            (capture, status)
        }
        other => panic!("capture must be served: {other:?}"),
    }
}

fn off(startup: CaptureStartup) -> CaptureStatusV1 {
    match startup {
        CaptureStartup::Off(status) => {
            assert!(!status.served);
            assert!(status.identity.is_none());
            status
        }
        other => panic!("capture must be off: {other:?}"),
    }
}

/// One capture: its typed answer, the answer as `remember` returns it, and
/// whether it replayed a committed receipt.
async fn capture(
    runtime: &CockroachCapture,
    scope: &FleetScope,
    items: &[Value],
    key: &str,
) -> (CaptureResponseV1, Value, bool) {
    let prepared = PreparedCaptureV1::prepare(&request(items)).expect("the request is valid");
    let outcome = runtime
        .capture(scope, &prepared, key)
        .await
        .expect("the capture runs");
    (
        serde_json::from_value(outcome.response.clone()).expect("a capture response"),
        outcome.response,
        outcome.replayed,
    )
}

fn dispositions(answer: &CaptureResponseV1) -> Vec<(CaptureDispositionV1, Option<&str>)> {
    answer
        .items
        .iter()
        .map(|item| (item.disposition, item.withheld_reason.as_deref()))
        .collect()
}

// ---------------------------------------------------------------------------
// Worker ticks and reads
// ---------------------------------------------------------------------------

async fn fixture_at(pool: &PgPool, label: &str) -> WorkerFixture {
    WorkerFixture::install_at(pool, label, InstallTargetV1::Generation3).await
}

/// A worker tick over no sources but the collector outbox, that must succeed.
async fn drain(fixture: &WorkerFixture, pool: &PgPool, steps: &str) {
    let report = fixture
        .worker_with(
            pool,
            steps,
            &json!({"schema_version": 1}),
            Arc::new(RecordedCi),
        )
        .await
        .run_tick()
        .await;
    assert!(
        !report.failed(),
        "the {steps} tick must succeed: {}",
        serde_json::to_string_pretty(&report).unwrap()
    );
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
    .expect("the login may read every item-recall table");
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
    .expect("the login may read every evidence table");
    CockroachEvidenceRecall::new(capability, pool.clone())
}

async fn get(pool: &PgPool, fixture: &WorkerFixture, item: Sha256Digest) -> ItemGetV1 {
    items(pool, fixture)
        .await
        .get(&ItemReferenceV1::Item(item))
        .await
        .unwrap()
        .expect("the item is presented")
}

/// The attesters of every capture of `version`'s parts.
fn attesters(version: &ostk_fleet_recall::item_recall::ItemVersionRecordV1) -> Vec<String> {
    let mut attesters: Vec<String> = version
        .provenance
        .iter()
        .filter(|provenance| provenance.mode == CollectionModeV1::Capture)
        .filter_map(|provenance| provenance.attester.clone())
        .collect();
    attesters.sort();
    attesters
}

/// `recall` and `remember` as the private writer composes them, with no
/// capability but what the caller adds.
fn service_over(pool: &PgPool, scope: &FleetScope) -> CockroachMemoryService {
    let embedder = Arc::new(StubEmbedder);
    let ledger = CockroachClaimLedger::new(
        pool.clone(),
        scope.clone(),
        embedder.clone(),
        retry_policy(),
    )
    .expect("claim ledger");
    CockroachMemoryService::new(
        scope.clone(),
        Arc::new(CockroachStore::from_pool(pool.clone(), scope.clone()).expect("store scope")),
        Arc::new(ledger),
        embedder,
    )
    .expect("memory service")
}

fn arguments(value: Value) -> serde_json::Map<String, Value> {
    let Value::Object(arguments) = value else {
        panic!("arguments are an object");
    };
    arguments
}

async fn status_of(service: &CockroachMemoryService, scope: &FleetScope) -> Value {
    service
        .recall(
            scope.clone(),
            RecallRequest::new(RecallAction::Status, serde_json::Map::new()),
        )
        .await
        .expect("recall(status) is served")
        .data
}

fn tools_of(service: &CockroachMemoryService) -> Vec<u8> {
    serde_json::to_vec(&tool_list_for_surfaces(
        service.remember_surface(),
        service.recall_surface(),
    ))
    .unwrap()
}

// ---------------------------------------------------------------------------
// The connected proofs
// ---------------------------------------------------------------------------

#[tokio::test]
#[allow(clippy::too_many_lines)] // one capture followed through its receipt, replays, and a second agent
async fn live_capture_admits_redacted_items_and_replays_by_key_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let fixture = fixture_at(&pool, "capture-admit").await;
    // A verified pull records the channel as readable by the project.
    pull(
        &pool,
        &fixture,
        vec![pulled_message("the heron retry budget is four")],
        ProviderAudienceV1::ScopePublic,
    )
    .await;
    let scope = fixture.installed.scope.clone();
    let (runtime, status) = served(start(&pool, &scope, &variables(&fixture, "enabled")).await);
    assert_eq!(status.mode, Some(CollectedCaptureModeV1::Enabled));
    let identity = status
        .identity
        .clone()
        .expect("a served capture names itself");
    assert_eq!(identity.principal.as_str(), "agent.fleet-recall-live-test");
    assert_eq!(identity.instance.as_str(), "capture.fleet-recall-live-test");

    // An obviously fake token in the Slack detector's shape: no scanner or
    // reader mistakes it for a credential, and the redactor still catches it.
    let secret = "xoxb-EXAMPLE-NOT-A-TOKEN".to_owned();
    let captured = [
        item(
            &format!("{SLACK_CHANNEL}:1790071200.000100"),
            "the heron retry budget is five",
            &json!({}),
        ),
        item(
            &format!("{SLACK_CHANNEL}:1790071260.000200"),
            &format!("rotate the pelican token {secret} before friday"),
            &json!({}),
        ),
    ];
    let events_before = count(&pool, &fixture, EVENTS_SQL).await;
    let (first, first_value, replayed) =
        capture(&runtime, &scope, &captured, "capture/heron").await;
    assert!(!replayed);
    assert!(!first.idempotent_replay);
    assert_eq!(first.operation, "capture");
    assert_eq!(
        dispositions(&first),
        [
            (CaptureDispositionV1::Admitted, None),
            (CaptureDispositionV1::Admitted, None)
        ]
    );
    for item in &first.items {
        assert_eq!(item.accepted_event_ids.len(), 1, "one part, one event");
        assert!(item.version_id.is_some());
        assert!(item.uri.as_deref().unwrap().starts_with("urn:"));
    }
    assert_eq!(first.items[0].redacted_ranges, 0);
    assert!(first.items[1].redacted_ranges >= 1, "the token is redacted");
    let events_after = count(&pool, &fixture, EVENTS_SQL).await;
    assert_eq!(events_after - events_before, 2);

    // The receipt keeps the trusted scope and a digest, never an item's text.
    let (operation, stored_request, stored_response): (String, Value, Value) = sqlx::query_as(
        "SELECT operation, request, response FROM memory_mutation_receipts \
         WHERE tenant_id = $1 AND idempotency_key = $2",
    )
    .bind(scope.tenant_id)
    .bind("capture/heron")
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(operation, "capture");
    let mut fields: Vec<&String> = stored_request.as_object().unwrap().keys().collect();
    fields.sort();
    assert_eq!(fields, ["request_digest", "scope"]);
    for stored in [stored_request.to_string(), stored_response.to_string()] {
        for text in ["heron", "pelican", secret.as_str()] {
            assert!(!stored.contains(text), "the receipt holds {text:?}");
        }
    }
    assert_eq!(stored_response, first_value);

    // The same key replays the committed answer, byte for byte.
    let (_, replay, replayed) = capture(&runtime, &scope, &captured, "capture/heron").await;
    assert!(replayed);
    let mut expected = first_value.clone();
    expected["idempotent_replay"] = json!(true);
    assert_eq!(
        serde_json::to_vec(&replay).unwrap(),
        serde_json::to_vec(&expected).unwrap()
    );
    let (_, again, _) = capture(&runtime, &scope, &captured, "capture/heron").await;
    assert_eq!(
        serde_json::to_vec(&again).unwrap(),
        serde_json::to_vec(&replay).unwrap()
    );
    // Another request under a used key is an idempotency conflict.
    let other = PreparedCaptureV1::prepare(&request(&captured[..1])).unwrap();
    let error = runtime
        .capture(&scope, &other, "capture/heron")
        .await
        .unwrap_err();
    assert!(
        matches!(error, FleetError::IdempotencyConflict(_)),
        "{error}"
    );

    // The same items under a new key stage nothing and append nothing: they
    // replay the events the first capture appended.
    let (renewed, _, replayed) = capture(&runtime, &scope, &captured, "capture/heron-2").await;
    assert!(!replayed, "a new key is a new receipt");
    for (renewed, original) in renewed.items.iter().zip(&first.items) {
        assert_eq!(renewed.disposition, CaptureDispositionV1::Replayed);
        assert_eq!(renewed.item_id, original.item_id);
        assert_eq!(renewed.version_id, original.version_id);
        assert_eq!(renewed.accepted_event_ids, original.accepted_event_ids);
    }
    assert_eq!(count(&pool, &fixture, EVENTS_SQL).await, events_after);

    // Admitted items project and recall like any other: redacted, reported,
    // and attested by the agent.
    drain(&fixture, &pool, "project").await;
    let got = get(&pool, &fixture, first.items[1].item_id).await;
    assert_eq!(got.item.trust, TrustTierV1::Reported);
    assert_eq!(got.current.version_id, first.items[1].version_id.unwrap());
    let text = got.current.parts[0]
        .text
        .clone()
        .expect("the part is projected");
    assert!(text.contains("pelican"), "{text}");
    assert!(!text.contains(&secret), "the token is never recalled");
    assert_eq!(
        got.current.parts[0].accepted_event_id,
        first.items[1].accepted_event_ids[0]
    );
    assert_eq!(attesters(&got.current), [identity.principal.to_string()]);
    let projected: Vec<String> = sqlx::query_scalar(
        "SELECT lexical_text FROM memory_body_lexical_projection_v1 \
         WHERE tenant_id = $1 AND project = $2",
    )
    .bind(scope.tenant_id)
    .bind(&scope.project)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(projected.iter().any(|text| text.contains("pelican")));
    assert!(projected.iter().all(|text| !text.contains(&secret)));

    // A second agent capturing the same item is a second attestation: its
    // own event, beside the first agent's.
    let scope_b = scope_of(&fixture, AGENT_B);
    let (runtime_b, status_b) =
        served(start(&pool, &scope_b, &variables(&fixture, "enabled")).await);
    let identity_b = status_b.identity.clone().unwrap();
    assert_ne!(identity_b, identity);
    let (second, _, _) = capture(&runtime_b, &scope_b, &captured[..1], "capture/heron-b").await;
    assert_eq!(
        dispositions(&second),
        [(CaptureDispositionV1::Admitted, None)]
    );
    assert_eq!(second.items[0].item_id, first.items[0].item_id);
    assert_eq!(second.items[0].version_id, first.items[0].version_id);
    assert_ne!(
        second.items[0].accepted_event_ids,
        first.items[0].accepted_event_ids
    );
    drain(&fixture, &pool, "project").await;
    let got = get(&pool, &fixture, first.items[0].item_id).await;
    let mut expected = vec![
        identity.principal.to_string(),
        identity_b.principal.to_string(),
    ];
    expected.sort();
    assert_eq!(attesters(&got.current), expected);
    // An agent captures only in its own name.
    let prepared = PreparedCaptureV1::prepare(&request(&captured[..1])).unwrap();
    assert!(
        runtime_b
            .capture(&scope, &prepared, "capture/impostor")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn live_capture_audience_is_the_servers_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let fixture = fixture_at(&pool, "capture-audience").await;
    pull(&pool, &fixture, Vec::new(), ProviderAudienceV1::ScopePublic).await;
    let scope = fixture.installed.scope.clone();
    let mut variables = variables(&fixture, "enabled");
    variables.insert(
        SCOPES_ENV.into(),
        json!([{ "provider": "linear", "provider_scope_id": LINEAR_ORG, "containers": "*" }])
            .to_string(),
    );
    let (runtime, status) = served(start(&pool, &scope, &variables).await);
    assert_eq!(status.capture_scopes, Some(1));

    let captured = [
        // A readable channel, but the agent saw it in a direct message: the
        // hint can only narrow.
        item(
            &format!("{SLACK_CHANNEL}:1790071200.000100"),
            "the heron roster, from a direct message",
            &json!({ "visibility": "dm" }),
        ),
        // A channel nothing verified and no capture scope covers.
        item(
            "C07UNSEEN01:1790071200.000100",
            "the heron roster, from an unseen channel",
            &json!({ "container": { "kind": "slack.channel", "id": "C07UNSEEN01" } }),
        ),
        // A Linear issue in a scope the operator listed for capture.
        json!({
            "provider": "linear",
            "provider_scope_id": LINEAR_ORG,
            "object_kind": "issue",
            "external_id": "0f6d9a52-3c1b-4e7a-b8d4-6e2f1a9c7b30",
            "container": { "kind": "linear.team", "id": "team-plat" },
            "updated_at": "2026-09-22T11:00:00Z",
            "title": "ENG-412 retry budget",
            "text": "the heron retry budget is five, per the incident review",
            "url": "https://linear.app/acme/issue/ENG-412",
        }),
    ];
    let (answer, _, _) = capture(&runtime, &scope, &captured, "capture/audience").await;
    assert_eq!(
        dispositions(&answer),
        [
            (CaptureDispositionV1::Withheld, Some("audience_refused")),
            (CaptureDispositionV1::Withheld, Some("audience_unverified")),
            (CaptureDispositionV1::Admitted, None),
        ]
    );
    // Nothing of a withheld item is staged, admitted, or named.
    for withheld in &answer.items[..2] {
        assert!(withheld.version_id.is_none() && withheld.uri.is_none());
        assert!(withheld.accepted_event_ids.is_empty());
        let staged: i64 = sqlx::query_scalar(
            "SELECT count(*)::INT8 FROM memory_collector_outbox_v1 \
             WHERE tenant_id = $1 AND project = $2 AND item_key_digest = $3",
        )
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(withheld.item_id.as_bytes().as_slice())
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(staged, 0);
    }
    // Each refusal is a digest-only dead letter under the capture instance.
    let letters: Vec<(String, String)> = sqlx::query_as(
        "SELECT reason, diagnostic FROM memory_collector_dead_letters_v1 \
         WHERE tenant_id = $1 AND project = $2 AND collector_instance_id = $3 \
         ORDER BY diagnostic",
    )
    .bind(scope.tenant_id)
    .bind(&scope.project)
    .bind(status.identity.as_ref().unwrap().instance.as_str())
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        letters,
        [
            ("audience_refused".to_owned(), "audience_refused".to_owned()),
            (
                "audience_refused".to_owned(),
                "audience_unverified".to_owned()
            ),
        ]
    );

    // Once a verified pull sees the channel go private, a capture into it is
    // refused: a withdrawal is never the agent's to lift.
    pull(&pool, &fixture, Vec::new(), ProviderAudienceV1::Restricted).await;
    let (withdrawn, _, _) = capture(
        &runtime,
        &scope,
        &[item(
            &format!("{SLACK_CHANNEL}:1790071300.000300"),
            "the heron roster, after the channel went private",
            &json!({}),
        )],
        "capture/withdrawn",
    )
    .await;
    assert_eq!(
        dispositions(&withdrawn),
        [(CaptureDispositionV1::Withheld, Some("container_withdrawn"))]
    );
}

#[tokio::test]
async fn live_a_capture_never_displaces_a_verified_head_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let fixture = fixture_at(&pool, "capture-head").await;
    pull(
        &pool,
        &fixture,
        vec![pulled_message("the heron retry budget is four")],
        ProviderAudienceV1::ScopePublic,
    )
    .await;
    drain(&fixture, &pool, "collect,project").await;
    let scope = fixture.installed.scope.clone();
    let (runtime, _) = served(start(&pool, &scope, &variables(&fixture, "enabled")).await);
    // The agent read a newer, edited version of the message the pull read.
    let (answer, _, _) = capture(
        &runtime,
        &scope,
        &[item(
            &format!("{SLACK_CHANNEL}:{PULL_TS}"),
            "the heron retry budget is five",
            &json!({ "lifecycle": "edited" }),
        )],
        "capture/newer",
    )
    .await;
    assert_eq!(
        dispositions(&answer),
        [(CaptureDispositionV1::Admitted, None)]
    );
    drain(&fixture, &pool, "project").await;
    let got = get(&pool, &fixture, answer.items[0].item_id).await;
    // The verified head stays presented, and the newer report disagrees.
    assert_eq!(got.item.trust, TrustTierV1::Verified);
    assert!(got.item.disagreement);
    assert_ne!(Some(got.current.version_id), answer.items[0].version_id);
    assert!(
        got.current.parts[0]
            .text
            .as_deref()
            .unwrap()
            .contains("four")
    );
    let reported = got
        .history
        .iter()
        .find(|version| Some(version.version_id) == answer.items[0].version_id)
        .expect("the captured version is in the history");
    assert!(reported.parts[0].text.as_deref().unwrap().contains("five"));
}

#[tokio::test]
async fn live_stage_only_leaves_admission_to_the_worker_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let fixture = fixture_at(&pool, "capture-stage-only").await;
    pull(&pool, &fixture, Vec::new(), ProviderAudienceV1::ScopePublic).await;
    let scope = fixture.installed.scope.clone();
    let variables = variables(&fixture, "stage_only");
    assert!(!variables.contains_key(KEK_ENV), "stage_only holds no key");
    let (runtime, status) = served(start(&pool, &scope, &variables).await);
    assert_eq!(status.mode, Some(CollectedCaptureModeV1::StageOnly));

    let captured = [item(
        &format!("{SLACK_CHANNEL}:1790071200.000100"),
        "the ibis roster lists nine",
        &json!({}),
    )];
    let (answer, answer_value, _) = capture(&runtime, &scope, &captured, "capture/ibis").await;
    assert_eq!(
        dispositions(&answer),
        [(CaptureDispositionV1::Staged, None)]
    );
    assert!(answer.items[0].accepted_event_ids.is_empty());
    assert!(answer.items[0].version_id.is_some());

    // The staged row waits for the worker, so no absence is sound yet.
    let recall = evidence(&pool, &fixture).await;
    let pending = recall
        .search("unfindable marmoset", None, 10)
        .await
        .unwrap();
    assert_eq!(pending.absence.verdict, AbsenceVerdictV1::Unknown);
    assert!(
        pending
            .absence
            .reasons
            .contains(&AbsenceReasonV1::IngestOutboxPending),
        "{:?}",
        pending.absence
    );
    assert_eq!(pending.readiness.items_awaiting_admission, Some(1));
    // The key replays the staged answer.
    let (_, replay, replayed) = capture(&runtime, &scope, &captured, "capture/ibis").await;
    assert!(replayed);
    let mut expected = answer_value;
    expected["idempotent_replay"] = json!(true);
    assert_eq!(replay, expected);

    // The worker's collect step admits it, and it recalls as a reported item.
    drain(&fixture, &pool, "collect,project").await;
    let drained = recall
        .search("unfindable marmoset", None, 10)
        .await
        .unwrap();
    assert_eq!(drained.readiness.items_awaiting_admission, Some(0));
    assert!(
        !drained
            .absence
            .reasons
            .contains(&AbsenceReasonV1::IngestOutboxPending),
        "{:?}",
        drained.absence
    );
    let found = items(&pool, &fixture)
        .await
        .search(
            &ItemSearchRequestV1 {
                query: "ibis roster".into(),
                provider: None,
                include_history: false,
                limit: 10,
            },
            None,
        )
        .await
        .unwrap();
    assert_eq!(found.hits.len(), 1);
    assert_eq!(found.hits[0].item_id, answer.items[0].item_id);
    assert_eq!(found.hits[0].trust, TrustTierV1::Reported);
    assert_eq!(found.hits[0].collection_modes, [CollectionModeV1::Capture]);
    // Captured again under a new key, it is already admitted.
    let (renewed, _, _) = capture(&runtime, &scope, &captured, "capture/ibis-2").await;
    assert_eq!(
        dispositions(&renewed),
        [(CaptureDispositionV1::Replayed, None)]
    );
    assert_eq!(
        renewed.items[0].accepted_event_ids,
        [found.hits[0].accepted_event_id]
    );
}

#[tokio::test]
async fn live_capture_disabled_or_off_changes_nothing_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let fixture = fixture_at(&pool, "capture-off").await;
    let scope = fixture.installed.scope.clone();

    // Disabled, the default: nothing is started, reported, or advertised,
    // and a capture is refused before any I/O.
    let startup = start(&pool, &scope, &variables(&fixture, "disabled")).await;
    assert!(matches!(startup, CaptureStartup::NotConfigured));
    let (capture, status) = startup.into_parts();
    assert!(capture.is_none() && status.is_none());
    let baseline = service_over(&pool, &scope);
    let service = service_over(&pool, &scope).with_capture(capture, status);
    assert_eq!(tools_of(&service), tools_of(&baseline));
    assert!(
        status_of(&service, &scope)
            .await
            .get("remember_capture")
            .is_none()
    );
    let refused = service
        .remember(
            scope.clone(),
            RememberRequest::new(
                RememberAction::Capture,
                Some("capture/disabled".into()),
                arguments(json!({ "items": [item(
                    &format!("{SLACK_CHANNEL}:1790071200.000100"),
                    "the heron roster",
                    &json!({}),
                )] })),
            ),
        )
        .await
        .unwrap_err();
    let ServiceError::Refused(refusal) = refused else {
        panic!("an unserved capture is refused: {refused}");
    };
    assert_eq!(refusal.code, "capture_unavailable");

    // A generation-2 head cannot bind the capture connector: capture is off
    // and says how to fix it; the writer still starts.
    let generation2 =
        WorkerFixture::install_at(&pool, "capture-gen2", InstallTargetV1::Generation2).await;
    let status = off(start(
        &pool,
        &generation2.installed.scope,
        &variables(&generation2, "enabled"),
    )
    .await);
    assert_eq!(status.mode, Some(CollectedCaptureModeV1::Enabled));
    let reason = status.reason.clone().unwrap();
    assert!(reason.contains("--target generation-3"), "{reason}");
    // Its reason is what recall(status) reports.
    let reported =
        service_over(&pool, &generation2.installed.scope).with_capture(None, Some(status));
    let block = &status_of(&reported, &generation2.installed.scope).await["remember_capture"];
    assert_eq!(block["served"], false);
    assert_eq!(block["mode"], "enabled");
    assert_eq!(block["reason"], json!(reason));

    // A login without capture's grants: off, naming the first one missing.
    let worker = RuntimeProbeRole::create_worker_with(&pool, &database_url, true, true).await;
    let status = off(start_over(
        &worker.pool,
        &pool,
        &scope,
        &variables(&fixture, "stage_only"),
    )
    .await);
    let reason = status.reason.unwrap();
    assert!(reason.contains("memory_mutation_receipts"), "{reason}");
    worker.drop_role(&pool).await;
}

#[tokio::test]
async fn live_capture_serves_remember_under_the_runtime_grants_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let fixture = fixture_at(&pool, "capture-serve").await;
    pull(&pool, &fixture, Vec::new(), ProviderAudienceV1::ScopePublic).await;
    let scope = fixture.installed.scope.clone();
    // Serve's login holds the runtime policy's grants and nothing more.
    let writer = RuntimeProbeRole::create_serve_writer(&pool, &database_url).await;
    let (capture, status) =
        start_over(&writer.pool, &pool, &scope, &variables(&fixture, "enabled"))
            .await
            .into_parts();
    assert!(capture.is_some(), "{status:?}");
    let service = service_over(&pool, &scope)
        .with_capture(capture, status)
        .with_lifecycle(LifecycleServing {
            surface: RememberSurface {
                capture: true,
                ..RememberSurface::RECORD_ONLY
            },
            ..LifecycleServing::default()
        });
    let tools = tool_list_for_surfaces(service.remember_surface(), service.recall_surface());
    assert_eq!(
        tools[1]["inputSchema"]["properties"]["action"]["enum"],
        json!(["record", "capture"])
    );
    let block = &status_of(&service, &scope).await["remember_capture"];
    assert_eq!(block["served"], true);
    assert_eq!(block["mode"], "enabled");
    assert_eq!(
        block["identity"]["principal"],
        "agent.fleet-recall-live-test"
    );

    let captured = item(
        &format!("{SLACK_CHANNEL}:1790071200.000100"),
        "the heron retry budget is five",
        &json!({}),
    );
    let remember = |key: Option<&str>, value: Value| {
        service.remember(
            scope.clone(),
            RememberRequest::new(
                RememberAction::Capture,
                key.map(str::to_owned),
                arguments(value),
            ),
        )
    };
    let result = remember(
        Some("capture/serve"),
        json!({ "items": [captured.clone()], "via": "slack.conversations_history" }),
    )
    .await
    .expect("the capture is served");
    assert_eq!(result.data["operation"], "capture");
    assert_eq!(result.data["items"][0]["disposition"], "admitted");
    assert_eq!(
        result.data["items"][0]["accepted_event_ids"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    // A claim field, a missing key, and an item without its URL are refused
    // before any I/O.
    for (key, value) in [
        (
            Some("capture/claim"),
            json!({ "items": [captured.clone()], "kind": "fact" }),
        ),
        (None, json!({ "items": [captured.clone()] })),
        (
            Some("capture/no-url"),
            json!({ "items": [item(
                &format!("{SLACK_CHANNEL}:1790071201.000100"),
                "the heron roster",
                &json!({ "url": null }),
            )] }),
        ),
    ] {
        let error = remember(key, value).await.unwrap_err();
        assert!(matches!(error, ServiceError::InvalidRequest(_)), "{error}");
    }
    writer.drop_role(&pool).await;
}

#[tokio::test]
async fn live_a_replay_finishes_a_capture_interrupted_after_staging_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let fixture = fixture_at(&pool, "capture-interrupted").await;
    pull(&pool, &fixture, Vec::new(), ProviderAudienceV1::ScopePublic).await;
    let scope = fixture.installed.scope.clone();
    let captured = [item(
        &format!("{SLACK_CHANNEL}:1790071200.000100"),
        "the egret runbook moved",
        &json!({}),
    )];
    let (staging, _) = served(start(&pool, &scope, &variables(&fixture, "stage_only")).await);
    let (staged, _, _) = capture(&staging, &scope, &captured, "capture/egret").await;
    assert_eq!(
        dispositions(&staged),
        [(CaptureDispositionV1::Staged, None)]
    );

    // A capture whose process stopped after its staging transaction
    // committed leaves the receipt provisional, naming the rows it staged.
    let stage_ids: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT stage_id FROM memory_collector_outbox_v1 \
         WHERE tenant_id = $1 AND project = $2 AND item_key_digest = $3 ORDER BY part_ordinal",
    )
    .bind(scope.tenant_id)
    .bind(&scope.project)
    .bind(staged.items[0].item_id.as_bytes().as_slice())
    .fetch_all(&pool)
    .await
    .unwrap();
    let stage_ids: Vec<Value> = stage_ids
        .into_iter()
        .map(|id| json!(Sha256Digest::from_bytes(id.try_into().unwrap())))
        .collect();
    let provisional = json!({ "provisional": {
        "schema_version": 1,
        "items": [{
            "item_id": staged.items[0].item_id,
            "version_id": staged.items[0].version_id,
            "uri": staged.items[0].uri,
            "stage_ids": stage_ids,
            "already_admitted": false,
            "redacted_ranges": 0,
        }],
    } });
    let interrupted = sqlx::query(
        "UPDATE memory_mutation_receipts SET response = $3 \
         WHERE tenant_id = $1 AND idempotency_key = $2",
    )
    .bind(scope.tenant_id)
    .bind("capture/egret")
    .bind(&provisional)
    .execute(&pool)
    .await
    .unwrap()
    .rows_affected();
    assert_eq!(interrupted, 1);

    // The retry under the same key drains the listed rows and finalizes the
    // receipt once; every later replay returns that answer.
    let (enabled, _) = served(start(&pool, &scope, &variables(&fixture, "enabled")).await);
    let (finished, finished_value, replayed) =
        capture(&enabled, &scope, &captured, "capture/egret").await;
    assert!(!replayed, "the retry finished the capture");
    assert_eq!(
        dispositions(&finished),
        [(CaptureDispositionV1::Admitted, None)]
    );
    assert_eq!(finished.items[0].item_id, staged.items[0].item_id);
    assert_eq!(finished.items[0].accepted_event_ids.len(), 1);
    let (_, replay, replayed) = capture(&enabled, &scope, &captured, "capture/egret").await;
    assert!(replayed);
    let mut expected = finished_value;
    expected["idempotent_replay"] = json!(true);
    assert_eq!(replay, expected);
}
