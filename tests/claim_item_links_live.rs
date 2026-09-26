//! Connected proofs of claims that cite collected items (ADR 0008 D11,
//! migration 0035): `remember(assert)`'s `support_items` resolve, in the
//! claim's own scope, to the accepted events of the cited item's presented
//! version (or of the exact version named) and are cited through them;
//! `record`'s item support entries write an opaque support row plus private
//! links; an unknown, pending, or deleted item is refused and nothing is
//! written; the private claim get expands what a claim cites, counting
//! identical text once; item get lists the claims that cite an item; the
//! publication reader never sees which item a claim cites; and the claim
//! lifecycle is unchanged on a claim that cites items.
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
    CollectedItemSink, ContainerObservationV1, StageContextV1, StageDraftV1, StagedItemV1,
};
use ostk_fleet_recall::item_recall::{
    CockroachItemRecall, ItemGetV1, ItemRecall as _, ItemReferenceV1, ItemSuppressionV1,
    probe_item_recall,
};
use ostk_fleet_recall::ledger::{
    AssertedClaimMutation, ClaimInput, ClaimItemSupportV1, ClaimKind, ClaimLedger as _, ClaimState,
    ClaimTarget, CockroachClaimLedger, ConflictTarget, ItemRefV1, ItemSupportInputV1,
    LifecycleRefusal, RefusalCode, SupportInputV1,
};
use ostk_fleet_recall::mcp::tool_list_for_surfaces;
use ostk_fleet_recall::memory_contracts::collected_item::{
    BoundedTextV1, CollectionModeV1, ContainerKindV1, ItemLifecycleV1, ObjectKindV1,
    ProviderKindV1, TextFormatV1, TrustTierV1,
};
use ostk_fleet_recall::memory_contracts::common::ContractId;
use ostk_fleet_recall::memory_contracts::digest::Sha256Digest;
use ostk_fleet_recall::memory_contracts::evidence::AcceptedEventId;
use ostk_fleet_recall::registry_activation::install::InstallTargetV1;
use ostk_fleet_recall::remember_runtime::{
    CaptureDispositionV1, CaptureRequestV1, CaptureResponseV1, CaptureStartup, EventFirstAssert,
    ItemCapture as _, PreparedCaptureV1, RememberAssertInputV1, start_collected_capture_with,
};
use ostk_fleet_recall::service::{
    FleetMemoryService as _, RecallAction, RecallRequest, RecallSurface, RememberAction,
    RememberRequest, RememberSurface, ServiceError,
};
use ostk_fleet_recall::store::cockroach::{
    ClaimItemLinksCapability, CockroachStore, ConflictLifecycleCapability, DatabaseCapabilities,
    probe_claim_item_links, probe_conflict_lifecycle,
};
use ostk_fleet_recall::{CockroachMemoryService, FleetError, FleetScope};
use ostk_recall_core::{ChunkEmbedder as _, PrivacyTier};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use sqlx::postgres::PgRow;
use sqlx::{PgPool, Row as _};

use common::authority::retry_policy;
use common::runtime_role::RuntimeProbeRole;
use common::worker::{RecordedCi, STUB_MODEL_DIGEST, StubEmbedder, WorkerFixture};

const SLACK_TEAM: &str = "T07ACME0001";
const SLACK_CHANNEL: &str = "C07PLATENG1";
/// The fixture's own agent, and a second one in the same scope.
const AGENT_A: &str = common::LIVE_TEST_AGENT;
const AGENT_B: &str = "fleet-recall-live-test-b";

/// One pulled Slack message: its timestamp, provider order, and text.
struct Message {
    ts: &'static str,
    order: u64,
    text: &'static str,
}

const HERON: Message = Message {
    ts: "1790006860.001100",
    order: 1_790_006_860_001_100,
    text: "the heron retry budget is four attempts",
};
/// The same words in another message: an echo of [`HERON`].
const HERON_ECHO: Message = Message {
    ts: "1790006861.001200",
    order: 1_790_006_861_001_200,
    text: "the heron retry budget is four attempts",
};
const PELICAN: Message = Message {
    ts: "1790006862.001300",
    order: 1_790_006_862_001_300,
    text: "the pelican deploy window closes at noon",
};
/// Later edits of [`HERON`] and [`PELICAN`]: the same messages, other words.
const HERON_EDIT: Message = Message {
    ts: "1790006860.001100",
    order: 1_790_006_900_000_000,
    text: "the heron retry budget is five attempts",
};
const PELICAN_EDIT: Message = Message {
    ts: "1790006862.001300",
    order: 1_790_006_950_000_000,
    text: "the pelican deploy window closes at one",
};

fn permalink(ts: &str) -> String {
    format!(
        "https://acme.slack.com/archives/{SLACK_CHANNEL}/p{}",
        ts.replace('.', "")
    )
}

// ---------------------------------------------------------------------------
// Collected items
// ---------------------------------------------------------------------------

fn slack_instance() -> CollectorInstanceV1 {
    CollectorInstanceV1 {
        connector_instance_id: ContractId::new("slack.acme").unwrap(),
        provider: ProviderKindV1::new("slack").unwrap(),
        provider_scope_id: BoundedTextV1::new(SLACK_TEAM).unwrap(),
    }
}

/// `message` as a Slack pull reads it, at `lifecycle`.
fn draft(message: &Message, lifecycle: ItemLifecycleV1, order: u64) -> CollectedItemDraftV1 {
    let text = if lifecycle.is_tombstone() {
        String::new()
    } else {
        message.text.to_owned()
    };
    CollectedItemDraftV1 {
        provider: ProviderKindV1::new("slack").unwrap(),
        provider_scope_id: SLACK_TEAM.into(),
        object_kind: ObjectKindV1::new("message").unwrap(),
        external_id: format!("{SLACK_CHANNEL}:{}", message.ts),
        marker: Some(format!("{}:{order}", message.ts)),
        order_micros: order,
        lifecycle,
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
        sections: vec![DraftSectionV1::whole(text)],
        text_format: TextFormatV1::SlackMrkdwnRendered,
        links: Vec::new(),
        provider_url: Some(permalink(message.ts)),
        visibility: None,
    }
}

/// One staged item version: its item and version ids.
#[derive(Debug, Clone, Copy)]
struct Staged {
    item: Sha256Digest,
    version: Sha256Digest,
}

/// Stage `drafts` through a verified Slack pull of the public fixture
/// channel; the rows wait for a drain.
async fn pull(
    pool: &PgPool,
    fixture: &WorkerFixture,
    drafts: Vec<CollectedItemDraftV1>,
) -> Vec<Staged> {
    pull_observing(
        pool,
        fixture,
        drafts,
        &[(SLACK_CHANNEL, ProviderAudienceV1::ScopePublic)],
    )
    .await
}

/// Stage `drafts` through a verified Slack pull that observed each channel
/// of `channels` at its audience.
async fn pull_observing(
    pool: &PgPool,
    fixture: &WorkerFixture,
    drafts: Vec<CollectedItemDraftV1>,
    channels: &[(&str, ProviderAudienceV1)],
) -> Vec<Staged> {
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
            delivery_id: Sha256::digest(
                format!("{}:{}", draft.external_id, draft.order_micros).as_bytes(),
            )
            .to_vec(),
            provider_audience: None,
            draft,
        })
        .collect();
    let observations: Vec<ContainerObservationV1> = channels
        .iter()
        .map(|(id, audience)| ContainerObservationV1 {
            kind: ContainerKindV1::new("slack.channel").unwrap(),
            id: (*id).to_owned(),
            label: Some("plat-eng".to_owned()),
            provider_audience: *audience,
        })
        .collect();
    let outcome = CollectedItemSink::new(pool.clone(), &fixture.installed.scope, retry_policy())
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
    outcome
        .items
        .iter()
        .map(|item| match item {
            StagedItemV1::Staged {
                item_key,
                version_key,
                ..
            } => Staged {
                item: *item_key,
                version: *version_key,
            },
            refused @ StagedItemV1::Refused { .. } => panic!("the pull refused {refused:?}"),
        })
        .collect()
}

/// A worker tick that drains the outbox and projects what it admitted.
async fn drain(fixture: &WorkerFixture, pool: &PgPool) {
    let report = fixture
        .worker_with(
            pool,
            "collect,project",
            &json!({"schema_version": 1}),
            Arc::new(RecordedCi),
        )
        .await
        .run_tick()
        .await;
    assert!(
        !report.failed(),
        "the tick must succeed: {}",
        serde_json::to_string_pretty(&report).unwrap()
    );
}

// ---------------------------------------------------------------------------
// The fleet: one generation-3 scope, its claim ledgers, and its readers
// ---------------------------------------------------------------------------

struct Fleet {
    pool: PgPool,
    database_url: String,
    fixture: WorkerFixture,
    links: ClaimItemLinksCapability,
    conflict_lifecycle: ConflictLifecycleCapability,
}

impl Fleet {
    async fn new(database_url: &str, label: &str) -> Self {
        let pool = common::migrated_pool(database_url).await;
        let fixture = WorkerFixture::install_at(&pool, label, InstallTargetV1::Generation3).await;
        let store = CockroachStore::from_pool(pool.clone(), fixture.installed.scope.clone())
            .expect("the installed scope is a valid store scope");
        store
            .initialize_embedding_model(StubEmbedder.model_id())
            .await
            .expect("register the fixture embedding model");
        let capabilities = store.capabilities().await.expect("capabilities");
        let links = probe_claim_item_links(&pool, &capabilities)
            .await
            .expect("the probe runs")
            .expect("a migrated database's owner may link claims to items");
        let conflict_lifecycle = probe_conflict_lifecycle(&pool, &capabilities)
            .await
            .expect("the probe runs")
            .expect("a migrated database's owner may use the lifecycle log");
        Self {
            pool,
            database_url: database_url.to_owned(),
            fixture,
            links,
            conflict_lifecycle,
        }
    }

    fn scope(&self, agent: &str) -> FleetScope {
        let scope = &self.fixture.installed.scope;
        FleetScope::new(
            scope.tenant_id,
            scope.project.clone(),
            agent,
            None,
            PrivacyTier::T1Project,
        )
        .expect("agent scope")
    }

    async fn capabilities(&self) -> DatabaseCapabilities {
        CockroachStore::from_pool(self.pool.clone(), self.fixture.installed.scope.clone())
            .unwrap()
            .capabilities()
            .await
            .unwrap()
    }

    /// `agent`'s ledger over `pool`, serving assert, the conflict lifecycle,
    /// and, when `links` holds, claim item links.
    async fn ledger_over(
        &self,
        pool: &PgPool,
        agent: &str,
        links: Option<ClaimItemLinksCapability>,
    ) -> CockroachClaimLedger {
        let runtime = self.fixture.installed.runtime(pool).await;
        let assert = EventFirstAssert::for_agent(runtime, agent).expect("agent actor");
        let mut ledger = CockroachClaimLedger::new(
            pool.clone(),
            self.scope(agent),
            Arc::new(StubEmbedder),
            retry_policy(),
        )
        .expect("claim ledger")
        .with_event_first_assert(Arc::new(assert))
        .expect("the authority is bound to the ledger's scope and agent")
        .with_conflict_lifecycle(self.conflict_lifecycle);
        if let Some(links) = links {
            ledger = ledger.with_claim_item_links(links);
        }
        ledger
    }

    async fn ledger(&self, agent: &str) -> CockroachClaimLedger {
        self.ledger_over(&self.pool, agent, Some(self.links)).await
    }

    async fn items(&self) -> CockroachItemRecall {
        let scope = &self.fixture.installed.scope;
        let capability = probe_item_recall(
            &self.pool,
            &self.capabilities().await,
            scope,
            Sha256Digest::from_bytes(STUB_MODEL_DIGEST),
        )
        .await
        .expect("the probe runs")
        .expect("the owner may read every item-recall table");
        CockroachItemRecall::new(capability, self.pool.clone()).with_claim_citations(self.links)
    }

    async fn get_item(&self, item: Sha256Digest) -> ItemGetV1 {
        self.items()
            .await
            .get(&ItemReferenceV1::Item(item))
            .await
            .unwrap()
            .expect("the item is presented")
    }

    /// `agent`'s writer service, composed as `serve` composes it where
    /// claims cite items: the ledger with the links, item recall listing
    /// citations, and the surface that says so.
    async fn service(&self, agent: &str) -> CockroachMemoryService {
        let scope = self.scope(agent);
        CockroachMemoryService::new(
            scope.clone(),
            Arc::new(CockroachStore::from_pool(self.pool.clone(), scope).unwrap()),
            Arc::new(self.ledger(agent).await),
            Arc::new(StubEmbedder),
        )
        .expect("memory service")
        .with_item_recall(Arc::new(self.items().await))
        .with_lifecycle(LifecycleServing {
            surface: RememberSurface {
                claim_lifecycle: true,
                conflict_lifecycle: true,
                assert: true,
                item_support: true,
                ..RememberSurface::RECORD_ONLY
            },
            hide_non_current_claim_chunks: true,
            lifecycle_overlay: true,
        })
    }

    /// A scope-bound count.
    async fn count(&self, sql: &str) -> i64 {
        let scope = &self.fixture.installed.scope;
        sqlx::query_scalar(sql)
            .bind(scope.tenant_id)
            .bind(&scope.project)
            .fetch_one(&self.pool)
            .await
            .unwrap_or_else(|error| panic!("{sql}: {error}"))
    }

    async fn links_of(&self, claim_id: i64) -> Vec<LinkRow> {
        let scope = &self.fixture.installed.scope;
        let rows: Vec<PgRow> = sqlx::query(
            "SELECT support_event_id, link_id, via, claim_event_id, item_key_digest, \
                    version_key_digest, part_ordinal, relation \
             FROM memory_claim_item_links_v1 \
             WHERE tenant_id = $1 AND project = $2 AND claim_id = $3 \
             ORDER BY support_event_id",
        )
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(claim_id)
        .fetch_all(&self.pool)
        .await
        .expect("the claim's links");
        rows.iter()
            .map(|row| LinkRow {
                support_event_id: row.get("support_event_id"),
                link_id: row.get("link_id"),
                via: row.get("via"),
                claim_event_id: row.get("claim_event_id"),
                item_key_digest: row.get("item_key_digest"),
                version_key_digest: row.get("version_key_digest"),
                part_ordinal: row.get("part_ordinal"),
                relation: row.get("relation"),
            })
            .collect()
    }

    /// Pull the fixture messages and admit them.
    async fn admit(&self, messages: &[&Message]) -> Vec<Staged> {
        let staged = pull(
            &self.pool,
            &self.fixture,
            messages
                .iter()
                .map(|message| draft(message, ItemLifecycleV1::Live, message.order))
                .collect(),
        )
        .await;
        drain(&self.fixture, &self.pool).await;
        staged
    }
}

/// One link row, as stored.
#[derive(Debug)]
struct LinkRow {
    support_event_id: Vec<u8>,
    link_id: Vec<u8>,
    via: String,
    claim_event_id: Option<Vec<u8>>,
    item_key_digest: Vec<u8>,
    version_key_digest: Vec<u8>,
    part_ordinal: i64,
    relation: String,
}

/// An assertion over the one active route, citing `support_items`.
fn assertion(value: bool, support_items: &[Value]) -> RememberAssertInputV1 {
    serde_json::from_value(json!({
        "kind": "decision",
        "text": format!("remember(assert) allowed is {value} at this commit in production."),
        "modality": "attested",
        "value": { "kind": "boolean", "value": value },
        "subject": { "provider_repository_id": "908172635" },
        "applicability": {
            "repository_commit": { "commit_oid": "3d99ec111a583e80533cbbc0c06798bb628e0979" },
            "runtime_environment": { "environment_id": "production" },
        },
        "support_items": support_items,
    }))
    .expect("the fixture assertion parses as the MCP input")
}

/// A recorded claim about the heron retry budget, citing `support`.
fn recorded(text: &str, value: i64, support: Vec<SupportInputV1>) -> ClaimInput {
    ClaimInput {
        kind: ClaimKind::Fact,
        text: text.to_owned(),
        subject: Some("heron".into()),
        predicate: Some("retry-budget".into()),
        value: Some(json!(value)),
        polarity: 1,
        origin: "operator_asserted".into(),
        actor: None,
        confidence: 1.0,
        valid_from: None,
        valid_to: None,
        support,
    }
}

fn cites(item: ItemRefV1) -> SupportInputV1 {
    SupportInputV1::Item(ItemSupportInputV1 {
        item,
        relation: "supports".into(),
    })
}

fn refusal<T: std::fmt::Debug>(result: ostk_fleet_recall::Result<T>) -> LifecycleRefusal {
    match result {
        Err(FleetError::LifecycleRefused(refusal)) => *refusal,
        Err(other) => panic!("expected a typed refusal, got {other}"),
        Ok(value) => panic!("expected a refusal, got {value:?}"),
    }
}

fn event_ids(asserted: &AssertedClaimMutation) -> Vec<u8> {
    asserted
        .accepted_event
        .event_id
        .digest()
        .as_bytes()
        .to_vec()
}

fn arguments(value: Value) -> serde_json::Map<String, Value> {
    let Value::Object(arguments) = value else {
        panic!("arguments are an object");
    };
    arguments
}

/// The claim get of `claim_id` through `service` as `scope`.
async fn claim_get(service: &CockroachMemoryService, scope: &FleetScope, claim_id: i64) -> Value {
    service
        .recall(
            scope.clone(),
            RecallRequest::new(
                RecallAction::Get,
                arguments(json!({ "kind": "claim", "id": claim_id })),
            ),
        )
        .await
        .expect("claim get")
        .data
}

// ---------------------------------------------------------------------------
// The connected proofs
// ---------------------------------------------------------------------------

/// An assertion that cites items is admitted citing their events: its links
/// name the claim's own accepted event and each cited part, its claim get
/// expands the citations with trust and currency and counts an echo once,
/// the cited item lists the claim, and its key replays with nothing new.
#[tokio::test]
#[allow(clippy::too_many_lines)] // one assertion followed through its links, reads, and replay
async fn live_assert_cites_items_through_their_events_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let fleet = Fleet::new(&database_url, "claim-links-assert").await;
    let [heron, echo] = fleet.admit(&[&HERON, &HERON_ECHO]).await[..] else {
        panic!("two items are staged");
    };
    let heron_item = fleet.get_item(heron.item).await;
    let heron_event = heron_item.current.parts[0].accepted_event_id;
    let echo_event = fleet.get_item(echo.item).await.current.parts[0].accepted_event_id;

    let scope = fleet.scope(AGENT_A);
    let ledger = fleet.ledger(AGENT_A).await;
    let input = assertion(
        true,
        &[
            json!({ "item_id": heron.item }),
            json!({ "version_id": echo.version }),
            // The same item again, by its provider URL: cited once.
            json!({ "url": permalink(HERON.ts) }),
        ],
    );
    let asserted = ledger
        .assert_claim(&scope, &input, "claim-links-assert-1")
        .await
        .expect("an assertion citing admitted items is admitted");
    let claim_id = asserted.mutation.claim.id;

    // One link per cited part, each naming the claim's own accepted event.
    let links = fleet.links_of(claim_id).await;
    let mut linked: Vec<Vec<u8>> = links
        .iter()
        .map(|link| link.support_event_id.clone())
        .collect();
    linked.sort();
    let mut expected = vec![
        heron_event.as_bytes().to_vec(),
        echo_event.as_bytes().to_vec(),
    ];
    expected.sort();
    assert_eq!(linked, expected);
    for link in &links {
        assert_eq!(link.via, "assert");
        assert_eq!(
            link.claim_event_id.as_deref(),
            Some(&event_ids(&asserted)[..])
        );
        assert_eq!(link.relation, "supports");
        assert_eq!(link.part_ordinal, 0);
        assert_eq!(link.link_id.len(), 16);
    }
    let heron_link = links
        .iter()
        .find(|link| link.item_key_digest == heron.item.as_bytes())
        .expect("the heron item is linked");
    assert_eq!(heron_link.version_key_digest, heron.version.as_bytes());

    // The accepted statement cites both events: an unchanged ledger check
    // (the in-transaction audit) accepted them, and the event carries them.
    let cited: bool = sqlx::query_scalar(
        "SELECT count(*) = 1 FROM memory_evidence_events \
         WHERE tenant_id = $1 AND project = $2 AND event_id = $3",
    )
    .bind(scope.tenant_id)
    .bind(&scope.project)
    .bind(event_ids(&asserted))
    .fetch_one(&fleet.pool)
    .await
    .unwrap();
    assert!(cited);

    // The private claim get expands the citations; the echo counts once.
    let service = fleet.service(AGENT_A).await;
    let got = claim_get(&service, &scope, claim_id).await;
    let support: ClaimItemSupportV1Wire = serde_json::from_value(got.clone()).unwrap();
    assert_eq!(support.support_items.len(), 2, "{got}");
    assert_eq!(support.independent_sources, 1, "an echo counts once: {got}");
    for item in &support.support_items {
        assert_eq!(item["via"], "assert");
        assert_eq!(item["trust"], json!(TrustTierV1::Verified));
        assert_eq!(item["current"], true);
        assert_eq!(item["provider"], "slack");
        assert!(item.get("suppressed").is_none());
    }
    assert_eq!(
        got["accepted_event_id"],
        json!(asserted.accepted_event.event_id)
    );

    // The cited item lists the claim.
    let cited_by = fleet
        .get_item(heron.item)
        .await
        .cited_by
        .expect("citations are listed where claims cite items");
    assert_eq!(cited_by.len(), 1);
    assert_eq!(cited_by[0].claim_id, claim_id);
    assert_eq!(cited_by[0].via, "assert");
    assert_eq!(cited_by[0].version_id, heron.version);
    assert_eq!(cited_by[0].claim_state, "active");

    // The key replays its answer, and nothing new is linked.
    let replayed = ledger
        .assert_claim(&scope, &input, "claim-links-assert-1")
        .await
        .expect("the key replays");
    assert!(replayed.mutation.idempotent_replay);
    assert_eq!(replayed.accepted_event, asserted.accepted_event);
    assert_eq!(replayed.mutation.claim.id, claim_id);
    assert_eq!(fleet.links_of(claim_id).await.len(), links.len());

    // The receipt binds the request as sent, citations included; an
    // assertion without citations binds exactly what it always did.
    let plain = assertion(false, &[]);
    let plain_asserted = fleet
        .ledger(AGENT_B)
        .await
        .assert_claim(&fleet.scope(AGENT_B), &plain, "claim-links-assert-plain")
        .await
        .expect("an assertion that cites nothing is admitted as before");
    let requests: Vec<Value> = sqlx::query_scalar(
        "SELECT request FROM memory_mutation_receipts \
         WHERE tenant_id = $1 AND idempotency_key = ANY($2) ORDER BY idempotency_key",
    )
    .bind(scope.tenant_id)
    .bind(["claim-links-assert-1", "claim-links-assert-plain"].as_slice())
    .fetch_all(&fleet.pool)
    .await
    .unwrap();
    assert_eq!(
        requests[0]["assertion"]["support_items"],
        json!([
            { "item_id": heron.item },
            { "version_id": echo.version },
            { "url": permalink(HERON.ts) },
        ])
    );
    assert_eq!(
        requests[1]["assertion"],
        serde_json::to_value(&plain).unwrap()
    );
    assert!(requests[1]["assertion"].get("support_items").is_none());
    assert!(
        fleet
            .links_of(plain_asserted.mutation.claim.id)
            .await
            .is_empty()
    );
    assert!(
        claim_get(&service, &scope, plain_asserted.mutation.claim.id)
            .await
            .get("support_items")
            .is_none(),
        "a claim that cites no item reads as before"
    );
}

/// The claim get's citation fields, as the private writer returns them.
#[derive(Debug, serde::Deserialize)]
struct ClaimItemSupportV1Wire {
    support_items: Vec<Value>,
    independent_sources: u64,
}

/// A reference that names nothing, an item still staged, and a deleted item
/// are each refused, through assert and record, and nothing is written; once
/// the worker admits the staged item it is cited.
#[tokio::test]
#[allow(clippy::too_many_lines)] // every refusal through both actions, then the admitted item
async fn live_uncitable_items_are_refused_and_nothing_is_written_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let fleet = Fleet::new(&database_url, "claim-links-refused").await;
    let [pelican] = fleet.admit(&[&PELICAN]).await[..] else {
        panic!("one item is staged");
    };
    // The provider deletes the message: a tombstone heads it.
    pull(
        &fleet.pool,
        &fleet.fixture,
        vec![draft(&PELICAN, ItemLifecycleV1::Deleted, PELICAN.order + 1)],
    )
    .await;
    drain(&fleet.fixture, &fleet.pool).await;

    // An agent captures an item in stage_only mode: staged, not admitted.
    let mut variables: HashMap<String, String> =
        serde_json::from_value(serde_json::to_value(&fleet.fixture.installed.report.pins).unwrap())
            .unwrap();
    variables.insert("FLEET_RECALL_COLLECTED_CAPTURE".into(), "stage_only".into());
    let scope = fleet.scope(AGENT_A);
    let capabilities = fleet.capabilities().await;
    let CaptureStartup::Served(capture, _) = start_collected_capture_with(
        fleet.pool.clone(),
        &capabilities,
        &scope,
        retry_policy(),
        None,
        |name| variables.get(name).cloned(),
    )
    .await
    else {
        panic!("stage_only capture is served");
    };
    let request: CaptureRequestV1 = serde_json::from_value(json!({ "items": [{
        "provider": "slack",
        "provider_scope_id": SLACK_TEAM,
        "object_kind": "message",
        "external_id": format!("{SLACK_CHANNEL}:1790006870.004400"),
        "container": { "kind": "slack.channel", "id": SLACK_CHANNEL },
        "updated_at": "2026-09-22T10:00:00Z",
        "text": "the ibis rollback needs two approvals",
        "url": permalink("1790006870.004400"),
    }]}))
    .unwrap();
    let captured: CaptureResponseV1 = serde_json::from_value(
        capture
            .capture(
                &scope,
                &PreparedCaptureV1::prepare(&request).unwrap(),
                "claim-links-capture",
            )
            .await
            .expect("the capture stages")
            .response,
    )
    .unwrap();
    assert_eq!(captured.items[0].disposition, CaptureDispositionV1::Staged);
    let staged = captured.items[0].item_id;
    let staged_version = captured.items[0].version_id.expect("a staged version");

    let ledger = fleet.ledger(AGENT_A).await;
    let unknown = Sha256Digest::from_bytes([0x42; 32]);
    let cases = [
        (
            json!({ "item_id": unknown }),
            RefusalCode::SupportItemUnknown,
        ),
        (
            json!({ "version_id": unknown }),
            RefusalCode::SupportItemUnknown,
        ),
        (
            json!({ "url": permalink("1790009999.000100") }),
            RefusalCode::SupportItemUnknown,
        ),
        (
            json!({ "item_id": staged }),
            RefusalCode::SupportItemPending,
        ),
        (
            json!({ "version_id": staged_version }),
            RefusalCode::SupportItemPending,
        ),
        (
            json!({ "item_id": pelican.item }),
            RefusalCode::SupportItemWithdrawn,
        ),
        // The version that was live before the delete is hidden with it.
        (
            json!({ "version_id": pelican.version }),
            RefusalCode::SupportItemWithdrawn,
        ),
    ];
    for (index, (reference, code)) in cases.iter().enumerate() {
        let key = format!("claim-links-refused-assert-{index}");
        let refused = refusal(
            ledger
                .assert_claim(
                    &scope,
                    &assertion(true, std::slice::from_ref(reference)),
                    &key,
                )
                .await,
        );
        assert_eq!(refused.code, *code, "assert citing {reference}");
        assert_eq!(refused.details["field"], "support_items[0]");
        if *code == RefusalCode::SupportItemWithdrawn {
            assert_eq!(refused.details["suppressed"], "deleted");
        }
        let item: ItemRefV1 = serde_json::from_value(reference.clone()).unwrap();
        let key = format!("claim-links-refused-record-{index}");
        let refused = refusal(
            ledger
                .record_claim(
                    &scope,
                    &recorded("The heron retry budget is four.", 4, vec![cites(item)]),
                    &key,
                )
                .await,
        );
        assert_eq!(refused.code, *code, "record citing {reference}");
        assert_eq!(refused.details["field"], "support[0].item");
    }
    // A reference that is not one is the assertion's own error.
    let refused = refusal(
        ledger
            .assert_claim(
                &scope,
                &assertion(true, &[json!({ "url": "http://acme.example/p1" })]),
                "claim-links-refused-malformed",
            )
            .await,
    );
    assert_eq!(refused.code, RefusalCode::AssertionNotAdmitted);
    assert_eq!(refused.details["reason"], "support_invalid");
    // Nothing was written: no claim, event, support row, link, or receipt.
    for sql in [
        "SELECT count(*)::INT8 FROM memory_claims WHERE tenant_id = $1 AND project = $2",
        "SELECT count(*)::INT8 FROM memory_claim_support WHERE tenant_id = $1 AND project = $2",
        "SELECT count(*)::INT8 FROM memory_claim_item_links_v1 \
         WHERE tenant_id = $1 AND project = $2",
        "SELECT count(*)::INT8 FROM memory_evidence_events \
         WHERE tenant_id = $1 AND project = $2 AND event_kind = 'memory.claim.accepted'",
        "SELECT count(*)::INT8 FROM memory_mutation_receipts \
         WHERE tenant_id = $1 AND project = $2 AND operation <> 'capture'",
    ] {
        assert_eq!(fleet.count(sql).await, 0, "{sql}");
    }

    // A ledger that does not serve claim item links refuses a citation
    // before anything else, and serves every claim that cites nothing.
    let unlinked = fleet.ledger_over(&fleet.pool, AGENT_A, None).await;
    let refused = refusal(
        unlinked
            .assert_claim(
                &scope,
                &assertion(true, &[json!({ "item_id": unknown })]),
                "claim-links-unserved",
            )
            .await,
    );
    assert_eq!(refused.code, RefusalCode::ItemSupportUnavailable);
    assert!(
        unlinked
            .claim_item_support(&scope, 1)
            .await
            .unwrap()
            .is_none()
    );

    // Once the worker admits the staged item, it is cited.
    drain(&fleet.fixture, &fleet.pool).await;
    let asserted = ledger
        .assert_claim(
            &scope,
            &assertion(true, &[json!({ "item_id": staged })]),
            "claim-links-admitted",
        )
        .await
        .expect("an admitted capture is cited");
    let links = fleet.links_of(asserted.mutation.claim.id).await;
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].version_key_digest, staged_version.as_bytes());
    let support: Option<ClaimItemSupportV1> = ledger
        .claim_item_support(&scope, asserted.mutation.claim.id)
        .await
        .unwrap();
    let support = support.expect("the ledger expands citations");
    assert_eq!(support.items[0].trust, TrustTierV1::Reported);
    assert_eq!(
        support.items[0].provider_url,
        Some(permalink("1790006870.004400"))
    );
}

/// A record that cites an item writes one opaque support row (`fleet.item`,
/// `item-link`, a random link id) and private links sharing that id; its key
/// replays; the item lists it beside an assertion that cites the same item;
/// the private claim get expands it; and the publication reader, connected
/// with only its grants, shows no trace of the citation.
#[tokio::test]
#[allow(clippy::too_many_lines)] // one record followed through every reader
async fn live_record_cites_an_item_through_an_opaque_support_row_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let fleet = Fleet::new(&database_url, "claim-links-record").await;
    let [heron] = fleet.admit(&[&HERON]).await[..] else {
        panic!("one item is staged");
    };
    let scope = fleet.scope(AGENT_A);
    let service = fleet.service(AGENT_A).await;

    // The surface advertises citations on record's support and the
    // assertion, and nothing else changes in the recall tool.
    let tools = tool_list_for_surfaces(service.remember_surface(), service.recall_surface());
    let remember = &tools[1]["inputSchema"]["properties"];
    assert!(remember["assertion"]["properties"]["support_items"].is_object());
    assert_eq!(
        remember["support"]["items"]["anyOf"][1]["required"],
        json!(["item"])
    );
    assert_eq!(
        tools[0],
        tool_list_for_surfaces(
            RememberSurface {
                item_support: false,
                ..service.remember_surface()
            },
            service.recall_surface(),
        )[0]
    );
    assert_eq!(
        service.recall_surface(),
        RecallSurface {
            items: true,
            ..RecallSurface::NONE
        }
    );

    // Record through remember, as an agent sends it.
    let record = |key: &str| {
        RememberRequest::new(
            RememberAction::Record,
            Some(key.to_owned()),
            arguments(json!({
                "kind": "fact",
                "text": "The heron retry budget is four attempts.",
                "subject": "heron",
                "predicate": "retry-budget",
                "value": 4,
                "support": [
                    { "item": { "url": permalink(HERON.ts) }, "relation": "quotes" },
                    {
                        "source_config_id": "runbooks",
                        "source": "markdown",
                        "source_id": "runbooks/heron.md"
                    }
                ]
            })),
        )
    };
    let recorded = service
        .remember(scope.clone(), record("claim-links-record-1"))
        .await
        .expect("a record citing an admitted item is written");
    let claim = &recorded.data["claim"];
    let claim_id = claim["id"].as_i64().unwrap();
    let support = claim["support"].as_array().unwrap();
    assert_eq!(support.len(), 2);
    let opaque = &support[0];
    assert_eq!(opaque["source_config_id"], "fleet.item");
    assert_eq!(opaque["source"], "item-link");
    assert_eq!(opaque["relation"], "quotes");
    for field in ["chunk_id", "content_sha256", "excerpt"] {
        assert!(opaque[field].is_null(), "{field}: {opaque}");
    }
    let link_hex = opaque["source_id"].as_str().unwrap();
    assert_eq!(link_hex.len(), 32);
    assert!(link_hex.bytes().all(|byte| byte.is_ascii_hexdigit()));
    // Nothing in the support row names the item.
    let wire = opaque.to_string();
    for secret in [
        heron.item.to_string(),
        HERON.ts.to_owned(),
        SLACK_CHANNEL.to_owned(),
    ] {
        assert!(!wire.contains(&secret), "{wire}");
    }
    assert_eq!(support[1]["source_config_id"], "runbooks");
    let links = fleet.links_of(claim_id).await;
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].via, "record");
    assert!(links[0].claim_event_id.is_none());
    assert_eq!(hex::encode(&links[0].link_id), link_hex);
    assert_eq!(links[0].relation, "quotes");
    assert_eq!(links[0].item_key_digest, heron.item.as_bytes());

    // The key replays byte for byte, and nothing new is written.
    let replayed = service
        .remember(scope.clone(), record("claim-links-record-1"))
        .await
        .expect("the key replays");
    let mut replayed_data = replayed.data.clone();
    replayed_data["idempotent_replay"] = json!(false);
    assert_eq!(replayed_data, recorded.data);
    assert_eq!(replayed.data["idempotent_replay"], true);
    assert_eq!(fleet.links_of(claim_id).await.len(), 1);

    // An assertion cites the same item; the item lists both claims.
    let asserted = service
        .remember(
            scope.clone(),
            RememberRequest::new(
                RememberAction::Assert,
                Some("claim-links-record-assert".into()),
                arguments(json!({ "assertion": serde_json::to_value(assertion(
                    true,
                    &[json!({ "item_id": heron.item })],
                ))
                .unwrap() })),
            ),
        )
        .await
        .expect("the assertion is admitted");
    let asserted_id = asserted.data["claim"]["id"].as_i64().unwrap();
    let cited_by = fleet.get_item(heron.item).await.cited_by.unwrap();
    let mut citing: Vec<(i64, String)> = cited_by
        .iter()
        .map(|citation| (citation.claim_id, citation.via.clone()))
        .collect();
    citing.sort();
    assert_eq!(
        citing,
        [
            (claim_id, "record".to_owned()),
            (asserted_id, "assert".to_owned())
        ]
    );
    // Through recall as an agent reads it, too.
    let item = service
        .recall(
            scope.clone(),
            RecallRequest::new(
                RecallAction::Get,
                arguments(json!({ "kind": "item", "id": heron.item })),
            ),
        )
        .await
        .expect("item get")
        .data;
    assert_eq!(
        item["item"]["cited_by"].as_array().unwrap().len(),
        2,
        "{item}"
    );

    // The private claim get expands the citation behind the opaque row.
    let got = claim_get(&service, &scope, claim_id).await;
    let items = got["support_items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{got}");
    assert_eq!(items[0]["link_id"], link_hex);
    assert_eq!(items[0]["via"], "record");
    assert_eq!(items[0]["relation"], "quotes");
    assert_eq!(items[0]["item_id"], json!(heron.item));
    assert_eq!(items[0]["version_id"], json!(heron.version));
    assert_eq!(
        items[0]["external_id"],
        format!("{SLACK_CHANNEL}:{}", HERON.ts)
    );
    assert_eq!(got["independent_sources"], 1);
    // The citation names the cited bytes: the version's uri and each cited
    // part's content digest, and `get` with that uri or with the version id
    // returns exactly that version.
    let cited_uri = items[0]["uri"].as_str().unwrap().to_owned();
    assert!(cited_uri.starts_with("urn:"), "{cited_uri}");
    let digests = items[0]["content_digests"].as_array().unwrap();
    assert_eq!(digests.len(), 1, "{}", items[0]);
    assert_eq!(digests[0].as_str().unwrap().len(), 64);
    for reference in [json!(cited_uri), json!(heron.version)] {
        let by_version = service
            .recall(
                scope.clone(),
                RecallRequest::new(
                    RecallAction::Get,
                    arguments(json!({ "kind": "item", "id": reference })),
                ),
            )
            .await
            .expect("item get by the cited version")
            .data;
        assert_eq!(
            by_version["item"]["item"]["item_id"],
            json!(heron.item),
            "{reference}"
        );
        assert_eq!(
            by_version["item"]["requested_version_id"],
            json!(heron.version),
            "{reference}"
        );
        assert_eq!(
            by_version["item"]["current"]["parts"][0]["uri"],
            json!(cited_uri),
            "{reference}"
        );
    }

    // The public reader: its claim get keeps the claim and drops the
    // citation row, and it cannot read the links at all.
    let reader =
        RuntimeProbeRole::create_publication_reader(&fleet.pool, &fleet.database_url).await;
    let visitor = fleet.scope("demo");
    let embedder = Arc::new(StubEmbedder);
    let publication = CockroachMemoryService::publication(
        visitor.clone(),
        Arc::new(CockroachStore::from_pool(reader.pool.clone(), visitor.clone()).unwrap()),
        Arc::new(
            CockroachClaimLedger::new(
                reader.pool.clone(),
                visitor.clone(),
                embedder.clone(),
                retry_policy(),
            )
            .unwrap(),
        ),
        embedder,
    )
    .unwrap();
    let public = publication
        .recall(
            visitor.clone(),
            RecallRequest::new(
                RecallAction::Get,
                arguments(json!({ "kind": "claim", "id": claim_id })),
            ),
        )
        .await;
    let links_read = sqlx::query("SELECT 1 FROM public.memory_claim_item_links_v1 LIMIT 1")
        .execute(&reader.pool)
        .await;
    reader.drop_role(&fleet.pool).await;
    let public = public.expect("the public claim get runs under the reader's grants");
    let public_claim = &public.data["claim"];
    assert_eq!(public_claim["id"], claim_id);
    let public_support = public_claim["support"].as_array().unwrap();
    assert_eq!(public_support.len(), 1, "{public_claim}");
    assert_eq!(public_support[0]["source_config_id"], "runbooks");
    let public_wire = serde_json::to_string(&public.data).unwrap();
    for hidden in ["fleet.item", "item-link", link_hex, "support_items"] {
        assert!(!public_wire.contains(hidden), "{hidden}: {public_wire}");
    }
    match links_read {
        Err(sqlx::Error::Database(error)) => assert_eq!(error.code().as_deref(), Some("42501")),
        other => panic!("the publication reader must not read the links: {other:?}"),
    }

    // A second citation of one version in one record is refused whole.
    let refused = service
        .remember(
            scope.clone(),
            RememberRequest::new(
                RememberAction::Record,
                Some("claim-links-record-twice".into()),
                arguments(json!({
                    "kind": "note",
                    "text": "The heron budget, cited twice.",
                    "support": [
                        { "item": { "item_id": heron.item } },
                        { "item": { "url": permalink(HERON.ts) } }
                    ]
                })),
            ),
        )
        .await;
    let Err(ServiceError::Refused(refused)) = refused else {
        panic!("a version cited twice is refused: {refused:?}");
    };
    assert_eq!(refused.code, "support_item_duplicate");
    assert_eq!(refused.details["field"], "support[1].item");
}

/// Supersede, retract, and resolve act on claims that cite items exactly as
/// on any other: a successor cites items of its own, a retracted claim keeps
/// its citations as history, and a concession closes the conflict.
#[tokio::test]
#[allow(clippy::too_many_lines)] // the claim lifecycle, then the conflict lifecycle
async fn live_lifecycle_is_unchanged_on_claims_that_cite_items_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let fleet = Fleet::new(&database_url, "claim-links-lifecycle").await;
    let [heron, echo] = fleet.admit(&[&HERON, &HERON_ECHO]).await[..] else {
        panic!("two items are staged");
    };
    let scope_a = fleet.scope(AGENT_A);
    let ledger_a = fleet.ledger(AGENT_A).await;

    // Supersede a claim that cites an item with one that cites another.
    let first = ledger_a
        .record_claim(
            &scope_a,
            &recorded(
                "The heron retry budget is three attempts.",
                3,
                vec![cites(ItemRefV1::ItemId(heron.item))],
            ),
            "claim-links-lifecycle-first",
        )
        .await
        .expect("record");
    let successor = ledger_a
        .supersede_claim(
            &scope_a,
            ClaimTarget {
                claim_id: first.claim.id,
                expected_revision: first.claim.revision,
            },
            Some("corrected"),
            &recorded(
                "The heron retry budget is four attempts.",
                4,
                vec![cites(ItemRefV1::VersionId(echo.version))],
            ),
            "claim-links-lifecycle-supersede",
        )
        .await
        .expect("a claim that cites an item is superseded");
    let predecessor = successor.superseded.expect("the predecessor");
    assert_eq!(predecessor.state, ClaimState::Superseded);
    assert_eq!(fleet.links_of(first.claim.id).await.len(), 1);
    let successor_links = fleet.links_of(successor.claim.id).await;
    assert_eq!(successor_links.len(), 1);
    assert_eq!(
        successor_links[0].version_key_digest,
        echo.version.as_bytes()
    );

    // Retract the successor: its citations stay, as history.
    let retracted = ledger_a
        .retract_claim(
            &scope_a,
            ClaimTarget {
                claim_id: successor.claim.id,
                expected_revision: successor.claim.revision,
            },
            Some("withdrawn"),
            "claim-links-lifecycle-retract",
        )
        .await
        .expect("a claim that cites an item is retracted");
    assert_eq!(retracted.claim.state, ClaimState::Retracted);
    let kept = ledger_a
        .claim_item_support(&scope_a, successor.claim.id)
        .await
        .unwrap()
        .expect("expanded");
    assert_eq!(kept.items.len(), 1);
    let cited_by = fleet.get_item(echo.item).await.cited_by.unwrap();
    assert_eq!(cited_by[0].claim_state, "retracted");

    // Two agents disagree; A's claim cites an item. A concedes, and the
    // conflict closes as it always does.
    let a = ledger_a
        .assert_claim(
            &scope_a,
            &assertion(true, &[json!({ "item_id": heron.item })]),
            "claim-links-lifecycle-a",
        )
        .await
        .expect("A asserts");
    let scope_b = fleet.scope(AGENT_B);
    let ledger_b = fleet.ledger(AGENT_B).await;
    let b = ledger_b
        .assert_claim(&scope_b, &assertion(false, &[]), "claim-links-lifecycle-b")
        .await
        .expect("B asserts");
    let [conflict_id] = b.mutation.conflicts_opened.as_slice() else {
        panic!("the two assertions open one conflict");
    };
    let conflict = ledger_a
        .get_conflicts(&scope_a, &[*conflict_id])
        .await
        .unwrap()
        .remove(0);
    let resolved = ledger_a
        .resolve_conflict(
            &scope_a,
            ConflictTarget {
                conflict_id: *conflict_id,
                expected_revision: conflict.revision,
                expected_member_count: Some(i64::try_from(conflict.member_count).unwrap()),
            },
            &[a.mutation.claim.id],
            Some("conceding"),
            "claim-links-lifecycle-resolve",
        )
        .await
        .expect("A concedes");
    assert_eq!(resolved.conflict_state, "resolved");
    assert_eq!(resolved.claims_retracted, [a.mutation.claim.id]);
    assert_eq!(resolved.claims_restored, [b.mutation.claim.id]);
    let a_claim = ledger_a
        .get_claim(&scope_a, a.mutation.claim.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(a_claim.state, ClaimState::Retracted);
    assert_eq!(fleet.links_of(a.mutation.claim.id).await.len(), 1);
}

/// The claim links run under exactly the runtime policy's grants, and a
/// login without the link grant is not offered them.
#[tokio::test]
async fn live_claim_item_links_run_under_the_runtime_grants_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let fleet = Fleet::new(&database_url, "claim-links-grants").await;
    let [heron] = fleet.admit(&[&HERON]).await[..] else {
        panic!("one item is staged");
    };
    let capabilities = fleet.capabilities().await;
    let writer = RuntimeProbeRole::create_serve_writer(&fleet.pool, &database_url).await;
    let claim_only = RuntimeProbeRole::create_claim_writer(&fleet.pool, &database_url).await;
    let probed = probe_claim_item_links(&writer.pool, &capabilities).await;
    let refused = probe_claim_item_links(&claim_only.pool, &capabilities).await;
    let outcome = async {
        let links = probed
            .map_err(|error| format!("probe: {error}"))?
            .ok_or("the serve writer's grants cover claim item links")?;
        let scope = fleet.scope(AGENT_A);
        let ledger = fleet.ledger_over(&writer.pool, AGENT_A, Some(links)).await;
        let asserted = ledger
            .assert_claim(
                &scope,
                &assertion(true, &[json!({ "item_id": heron.item })]),
                "claim-links-grants-assert",
            )
            .await
            .map_err(|error| format!("assert: {error}"))?;
        let recorded = ledger
            .record_claim(
                &scope,
                &recorded(
                    "The heron retry budget is four attempts.",
                    4,
                    vec![cites(ItemRefV1::ItemId(heron.item))],
                ),
                "claim-links-grants-record",
            )
            .await
            .map_err(|error| format!("record: {error}"))?;
        for claim_id in [asserted.mutation.claim.id, recorded.claim.id] {
            let support = ledger
                .claim_item_support(&scope, claim_id)
                .await
                .map_err(|error| format!("expand: {error}"))?
                .ok_or("expanded")?;
            if support.items.len() != 1 {
                return Err(format!("claim {claim_id} cites {support:?}"));
            }
        }
        Ok::<_, String>(())
    }
    .await;
    writer.drop_role(&fleet.pool).await;
    claim_only.drop_role(&fleet.pool).await;
    outcome.unwrap();
    assert!(
        refused.expect("the probe runs").is_none(),
        "a login without the collector and link grants is not offered claim item links"
    );
}

/// The variables `serve` runs with where capture is `enabled`.
fn enabled_capture(fleet: &Fleet) -> HashMap<String, String> {
    let mut variables: HashMap<String, String> =
        serde_json::from_value(serde_json::to_value(&fleet.fixture.installed.report.pins).unwrap())
            .unwrap();
    variables.insert("FLEET_RECALL_COLLECTED_CAPTURE".into(), "enabled".into());
    variables.insert(
        "FLEET_RECALL_CONTENT_KEK_HEX".into(),
        fleet.fixture.installed.kek_hex.clone(),
    );
    variables
}

/// A capture that claims a collected item's permalink never takes it over:
/// a claim citing the URL, through assert or record, and item get by the
/// URL still name the item the verified pull admitted under it.
#[tokio::test]
async fn live_a_captured_permalink_never_displaces_the_collected_item_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let fleet = Fleet::new(&database_url, "claim-links-permalink").await;
    let [heron] = fleet.admit(&[&HERON]).await[..] else {
        panic!("one item is staged");
    };

    // Agent B relays another "message" under the real message's permalink,
    // newer and with other words.
    let variables = enabled_capture(&fleet);
    let scope_b = fleet.scope(AGENT_B);
    let capabilities = fleet.capabilities().await;
    let CaptureStartup::Served(capture, _) = start_collected_capture_with(
        fleet.pool.clone(),
        &capabilities,
        &scope_b,
        retry_policy(),
        None,
        |name| variables.get(name).cloned(),
    )
    .await
    else {
        panic!("enabled capture is served");
    };
    let request: CaptureRequestV1 = serde_json::from_value(json!({ "items": [{
        "provider": "slack",
        "provider_scope_id": SLACK_TEAM,
        "object_kind": "message",
        "external_id": format!("{SLACK_CHANNEL}:1790071999.000100"),
        "container": { "kind": "slack.channel", "id": SLACK_CHANNEL },
        "updated_at": "2026-09-25T10:00:00Z",
        "text": "the heron retry budget is ninety attempts",
        "url": permalink(HERON.ts),
    }]}))
    .unwrap();
    let captured: CaptureResponseV1 = serde_json::from_value(
        capture
            .capture(
                &scope_b,
                &PreparedCaptureV1::prepare(&request).unwrap(),
                "claim-links-permalink-capture",
            )
            .await
            .expect("the capture runs")
            .response,
    )
    .unwrap();
    assert_eq!(
        captured.items[0].disposition,
        CaptureDispositionV1::Admitted
    );
    assert_ne!(captured.items[0].item_id, heron.item);

    // Agent A cites the permalink.
    let scope = fleet.scope(AGENT_A);
    let ledger = fleet.ledger(AGENT_A).await;
    let asserted = ledger
        .assert_claim(
            &scope,
            &assertion(true, &[json!({ "url": permalink(HERON.ts) })]),
            "claim-links-permalink-assert",
        )
        .await
        .expect("the permalink is cited");
    let links = fleet.links_of(asserted.mutation.claim.id).await;
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].item_key_digest, heron.item.as_bytes());
    let recorded = ledger
        .record_claim(
            &scope,
            &recorded(
                "The heron retry budget is four attempts.",
                4,
                vec![cites(ItemRefV1::Url(permalink(HERON.ts)))],
            ),
            "claim-links-permalink-record",
        )
        .await
        .expect("the permalink is cited");
    let support = ledger
        .claim_item_support(&scope, recorded.claim.id)
        .await
        .unwrap()
        .expect("the ledger expands citations");
    assert_eq!(support.items[0].item_id, heron.item);
    assert_eq!(support.items[0].trust, TrustTierV1::Verified);
    // Item get by the permalink names the collected item too.
    let got = fleet
        .items()
        .await
        .get(&ItemReferenceV1::ProviderUrl(permalink(HERON.ts)))
        .await
        .unwrap()
        .expect("the permalink names an item");
    assert_eq!(got.item.item_id, heron.item);
}

/// An assertion that lists a collected item's accepted event directly is
/// audited like a citation: a deleted item's event is refused and nothing
/// is written, and a visible item's event is linked, so the item lists the
/// claim.
#[tokio::test]
async fn live_a_directly_listed_item_event_is_audited_and_linked_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let fleet = Fleet::new(&database_url, "claim-links-direct").await;
    let [heron, pelican] = fleet.admit(&[&HERON, &PELICAN]).await[..] else {
        panic!("two items are staged");
    };
    let heron_event = fleet.get_item(heron.item).await.current.parts[0].accepted_event_id;
    let pelican_event = fleet.get_item(pelican.item).await.current.parts[0].accepted_event_id;
    // The provider deletes the pelican message.
    pull(
        &fleet.pool,
        &fleet.fixture,
        vec![draft(&PELICAN, ItemLifecycleV1::Deleted, PELICAN.order + 1)],
    )
    .await;
    drain(&fleet.fixture, &fleet.pool).await;

    let scope = fleet.scope(AGENT_A);
    let ledger = fleet.ledger(AGENT_A).await;
    let listing = |event: Sha256Digest| {
        let mut input = assertion(true, &[]);
        input.support_evidence_event_ids = vec![AcceptedEventId::from_digest(event)];
        input
    };
    let refused = refusal(
        ledger
            .assert_claim(
                &scope,
                &listing(pelican_event),
                "claim-links-direct-deleted",
            )
            .await,
    );
    assert_eq!(refused.code, RefusalCode::SupportItemWithdrawn);
    assert_eq!(refused.details["suppressed"], "deleted");
    assert_eq!(refused.details["item_id"], json!(pelican.item));
    for sql in [
        "SELECT count(*)::INT8 FROM memory_claims WHERE tenant_id = $1 AND project = $2",
        "SELECT count(*)::INT8 FROM memory_claim_item_links_v1 \
         WHERE tenant_id = $1 AND project = $2",
        "SELECT count(*)::INT8 FROM memory_evidence_events \
         WHERE tenant_id = $1 AND project = $2 AND event_kind = 'memory.claim.accepted'",
    ] {
        assert_eq!(fleet.count(sql).await, 0, "{sql}");
    }

    let asserted = ledger
        .assert_claim(&scope, &listing(heron_event), "claim-links-direct-visible")
        .await
        .expect("a visible item's event is cited");
    let links = fleet.links_of(asserted.mutation.claim.id).await;
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].support_event_id, heron_event.as_bytes());
    assert_eq!(links[0].item_key_digest, heron.item.as_bytes());
    assert_eq!(links[0].version_key_digest, heron.version.as_bytes());
    assert_eq!(links[0].via, "assert");
    let cited_by = fleet
        .get_item(heron.item)
        .await
        .cited_by
        .expect("citations are listed where claims cite items");
    assert_eq!(cited_by.len(), 1);
    assert_eq!(cited_by[0].claim_id, asserted.mutation.claim.id);
}

/// A version admitted in a channel since made private is withheld wherever
/// it is read, though its item moved to a public channel: item get shows
/// none of its text, citing it is refused, and a claim that cited it before
/// reports it suppressed. Two versions of one visible item are one
/// independent source, and each cited item is labelled untrusted
/// third-party content.
#[tokio::test]
#[allow(clippy::too_many_lines)] // one move followed through every reader, then one item cited twice
async fn live_a_version_in_a_withdrawn_container_is_withheld_everywhere_when_configured() {
    const CHANNEL_A: &str = "C07AAAAAAA1";
    const CHANNEL_B: &str = "C07BBBBBBB2";
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let fleet = Fleet::new(&database_url, "claim-links-moved").await;
    let in_channel = |message: &Message, lifecycle: ItemLifecycleV1, channel: &str| {
        let mut moved = draft(message, lifecycle, message.order);
        moved.container.as_mut().unwrap().id = channel.to_owned();
        moved
    };
    let [v1] = pull_observing(
        &fleet.pool,
        &fleet.fixture,
        vec![in_channel(&HERON, ItemLifecycleV1::Live, CHANNEL_A)],
        &[(CHANNEL_A, ProviderAudienceV1::ScopePublic)],
    )
    .await[..] else {
        panic!("one version is staged");
    };
    drain(&fleet.fixture, &fleet.pool).await;
    let scope = fleet.scope(AGENT_A);
    let ledger = fleet.ledger(AGENT_A).await;
    let before = ledger
        .record_claim(
            &scope,
            &recorded(
                "The heron retry budget is four attempts.",
                4,
                vec![cites(ItemRefV1::VersionId(v1.version))],
            ),
            "claim-links-moved-before",
        )
        .await
        .expect("the version is cited while its channel is public");

    // The message is edited into channel B, and channel A goes private.
    let [v2] = pull_observing(
        &fleet.pool,
        &fleet.fixture,
        vec![in_channel(&HERON_EDIT, ItemLifecycleV1::Edited, CHANNEL_B)],
        &[
            (CHANNEL_A, ProviderAudienceV1::Restricted),
            (CHANNEL_B, ProviderAudienceV1::ScopePublic),
        ],
    )
    .await[..] else {
        panic!("one version is staged");
    };
    drain(&fleet.fixture, &fleet.pool).await;
    assert_eq!(v1.item, v2.item);

    // Item get presents the edit and withholds the first version's text.
    let got = fleet.get_item(v1.item).await;
    assert_eq!(got.suppressed, None);
    assert_eq!(got.current.version_id, v2.version);
    assert_eq!(got.current.parts[0].text.as_deref(), Some(HERON_EDIT.text));
    let first = got
        .history
        .iter()
        .find(|version| version.version_id == v1.version)
        .expect("the first version is in the history");
    assert_eq!(
        first.suppressed,
        Some(ItemSuppressionV1::ContainerWithdrawn)
    );
    assert!(first.parts.iter().all(|part| part.text.is_none()));

    // Citing the first version now is refused through both actions.
    let refused = refusal(
        ledger
            .assert_claim(
                &scope,
                &assertion(true, &[json!({ "version_id": v1.version })]),
                "claim-links-moved-assert",
            )
            .await,
    );
    assert_eq!(refused.code, RefusalCode::SupportItemWithdrawn);
    assert_eq!(refused.details["suppressed"], "container_withdrawn");
    let refused = refusal(
        ledger
            .record_claim(
                &scope,
                &recorded(
                    "The heron retry budget is four attempts.",
                    4,
                    vec![cites(ItemRefV1::VersionId(v1.version))],
                ),
                "claim-links-moved-record",
            )
            .await,
    );
    assert_eq!(refused.code, RefusalCode::SupportItemWithdrawn);
    // The claim that cited it before reports it withheld, and counts it not.
    let support = ledger
        .claim_item_support(&scope, before.claim.id)
        .await
        .unwrap()
        .expect("the ledger expands citations");
    assert_eq!(
        support.items[0].suppressed,
        Some(ItemSuppressionV1::ContainerWithdrawn)
    );
    assert_eq!(support.independent_sources, 0);

    // One visible item cited by two of its versions is one source.
    let [pelican] = fleet.admit(&[&PELICAN]).await[..] else {
        panic!("one item is staged");
    };
    let [pelican_edit] = pull(
        &fleet.pool,
        &fleet.fixture,
        vec![draft(
            &PELICAN_EDIT,
            ItemLifecycleV1::Edited,
            PELICAN_EDIT.order,
        )],
    )
    .await[..] else {
        panic!("one version is staged");
    };
    drain(&fleet.fixture, &fleet.pool).await;
    let twice = ledger
        .record_claim(
            &scope,
            &recorded(
                "The pelican deploy window closes at one.",
                1,
                vec![
                    cites(ItemRefV1::VersionId(pelican.version)),
                    cites(ItemRefV1::ItemId(pelican.item)),
                ],
            ),
            "claim-links-moved-twice",
        )
        .await
        .expect("two versions of one item are cited");
    let service = fleet.service(AGENT_A).await;
    let got = claim_get(&service, &scope, twice.claim.id).await;
    let support: ClaimItemSupportV1Wire = serde_json::from_value(got.clone()).unwrap();
    assert_eq!(support.support_items.len(), 2, "{got}");
    assert_eq!(
        support.independent_sources, 1,
        "one message is one source: {got}"
    );
    let mut versions: Vec<&Value> = support
        .support_items
        .iter()
        .map(|item| &item["version_id"])
        .collect();
    versions.sort_by_key(ToString::to_string);
    let mut expected = [json!(pelican.version), json!(pelican_edit.version)];
    expected.sort_by_key(ToString::to_string);
    assert_eq!(versions, expected.iter().collect::<Vec<_>>());
    for item in &support.support_items {
        assert_eq!(item["content_trust"], "untrusted_third_party", "{got}");
    }
}
