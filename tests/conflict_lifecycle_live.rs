//! Connected proof for the serving claim lifecycle (ADR 0004, slice 1):
//! owner `retract`, detector-verified conflict close with member restore,
//! conflict lookup by id, and private search hiding retired claim chunks.
//!
//! Set `FLEET_RECALL_TEST_DATABASE_URL` to a disposable `CockroachDB` 26.2
//! database; every test is inert otherwise. Each test migrates, works in a
//! fresh tenant and project, and deletes every row it wrote.

use std::sync::Arc;
use std::time::Duration;

use ostk_fleet_recall::application::LifecycleServing;
use ostk_fleet_recall::ledger::{
    ClaimInput, ClaimKind, ClaimLedger, ClaimMutation, ClaimState, ClaimTarget,
    CockroachClaimLedger, CockroachConflictReconciliationRepository, LifecycleRefusal, RefusalCode,
};
use ostk_fleet_recall::service::{
    FleetMemoryService, RecallAction, RecallRequest, RecallResult, RememberAction, RememberRequest,
    RememberResult, RememberSurface, ServiceError,
};
use ostk_fleet_recall::store::cockroach::{
    CockroachStore, EMBEDDING_DIMENSION, PoolConfig, RetryPolicy,
};
use ostk_fleet_recall::{CockroachMemoryService, FleetError, FleetScope};
use ostk_recall_core::{ChunkEmbedder, PrivacyTier};
use serde_json::{Map, Value, json};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use tokio::sync::{Barrier, Mutex};
use uuid::Uuid;

const MODEL: &str = "lifecycle-live-512";
const AGENT_A: &str = "agent-a";
const AGENT_B: &str = "agent-b";
const AGENT_C: &str = "agent-c";

/// What the private writer serves unless `FLEET_RECALL_REMEMBER_LIFECYCLE=disabled`.
const PRIVATE_WRITER: LifecycleServing = LifecycleServing {
    surface: RememberSurface {
        claim_lifecycle: true,
    },
    hide_non_current_claim_chunks: true,
};

/// The schema is shared, so migration runs once per test process.
static MIGRATED: Mutex<bool> = Mutex::const_new(false);

struct UnitEmbedder;

impl ChunkEmbedder for UnitEmbedder {
    fn dim(&self) -> usize {
        EMBEDDING_DIMENSION
    }

    fn model_id(&self) -> &'static str {
        MODEL
    }

    fn encode_batch(&self, texts: &[&str]) -> Vec<Vec<f32>> {
        texts
            .iter()
            .map(|_| {
                let mut vector = vec![0.0; EMBEDDING_DIMENSION];
                vector[0] = 1.0;
                vector
            })
            .collect()
    }
}

/// Places every text at the query's direction except those containing
/// `trailing`, which sit at cosine 0.6: still inside the dense lane, but ranked
/// after every other chunk, so a test can fix which hits lead the fused page.
struct RankingEmbedder;

impl ChunkEmbedder for RankingEmbedder {
    fn dim(&self) -> usize {
        EMBEDDING_DIMENSION
    }

    fn model_id(&self) -> &'static str {
        MODEL
    }

    fn encode_batch(&self, texts: &[&str]) -> Vec<Vec<f32>> {
        texts
            .iter()
            .map(|text| {
                let mut vector = vec![0.0; EMBEDDING_DIMENSION];
                if text.contains("trailing") {
                    vector[0] = 0.6;
                    vector[1] = 0.8;
                } else {
                    vector[0] = 1.0;
                }
                vector
            })
            .collect()
    }
}

/// One fresh tenant/project with agents A, B, and C writing into it.
struct Fleet {
    store: CockroachStore,
    tenant: Uuid,
    project: String,
}

impl Fleet {
    async fn new(database_url: &str, label: &str) -> Self {
        let tenant = Uuid::now_v7();
        let project = format!("lifecycle-{label}-{}", Uuid::now_v7().simple());
        let scope = FleetScope::new(tenant, &project, AGENT_A, None, PrivacyTier::T1Project)
            .expect("fixture scope");
        let store = CockroachStore::connect(
            database_url,
            scope,
            PoolConfig {
                max_connections: 8,
                ..PoolConfig::default()
            },
        )
        .await
        .expect("connected test must reach the disposable database");
        {
            let mut migrated = MIGRATED.lock().await;
            if !*migrated {
                store.migrate().await.expect("migrations apply");
                *migrated = true;
            }
        }
        store
            .initialize_embedding_model(MODEL)
            .await
            .expect("register the fixture embedding model");
        Self {
            store,
            tenant,
            project,
        }
    }

    const fn pool(&self) -> &PgPool {
        self.store.pool()
    }

    fn scope(&self, agent: &str) -> FleetScope {
        FleetScope::new(
            self.tenant,
            &self.project,
            agent,
            None,
            PrivacyTier::T1Project,
        )
        .expect("agent scope")
    }

    fn ledger(&self, agent: &str) -> CockroachClaimLedger {
        self.ledger_on(self.pool(), agent, RetryPolicy::default())
    }

    fn ledger_on(&self, pool: &PgPool, agent: &str, policy: RetryPolicy) -> CockroachClaimLedger {
        CockroachClaimLedger::new(
            pool.clone(),
            self.scope(agent),
            Arc::new(UnitEmbedder),
            policy,
        )
        .expect("agent ledger")
    }

    /// The memory service `agent`'s writer composes, serving `lifecycle`.
    fn service(&self, agent: &str, lifecycle: LifecycleServing) -> CockroachMemoryService {
        self.service_embedding(agent, lifecycle, Arc::new(UnitEmbedder))
    }

    fn service_embedding(
        &self,
        agent: &str,
        lifecycle: LifecycleServing,
        embedder: Arc<dyn ChunkEmbedder>,
    ) -> CockroachMemoryService {
        let ledger = CockroachClaimLedger::new(
            self.pool().clone(),
            self.scope(agent),
            embedder.clone(),
            RetryPolicy::default(),
        )
        .expect("agent ledger");
        CockroachMemoryService::new(
            self.scope(agent),
            Arc::new(self.store.clone()),
            Arc::new(ledger),
            embedder,
        )
        .expect("memory service")
        .with_lifecycle(lifecycle)
    }

    async fn record(&self, agent: &str, input: &ClaimInput, key: &str) -> ClaimMutation {
        self.ledger(agent)
            .record_claim(&self.scope(agent), input, &self.key(key))
            .await
            .expect("record succeeds")
    }

    async fn retract(
        &self,
        agent: &str,
        claim_id: i64,
        expected_revision: i64,
        key: &str,
    ) -> ostk_fleet_recall::Result<ClaimMutation> {
        self.ledger(agent)
            .retract_claim(
                &self.scope(agent),
                ClaimTarget {
                    claim_id,
                    expected_revision,
                },
                None,
                &self.key(key),
            )
            .await
    }

    async fn claim(&self, claim_id: i64) -> ostk_fleet_recall::ledger::Claim {
        self.ledger(AGENT_A)
            .get_claim(&self.scope(AGENT_A), claim_id)
            .await
            .expect("claim read")
            .expect("claim exists")
    }

    async fn conflict(&self, conflict_id: i64) -> ostk_fleet_recall::ledger::Conflict {
        let mut conflicts = self
            .ledger(AGENT_C)
            .get_conflicts(&self.scope(AGENT_C), &[conflict_id])
            .await
            .expect("conflict lookup");
        assert_eq!(conflicts.len(), 1, "conflict {conflict_id} exists");
        conflicts.remove(0)
    }

    /// Idempotency keys are tenant-wide; the fresh tenant already isolates
    /// them, and the project suffix keeps them readable in failures.
    fn key(&self, label: &str) -> String {
        format!("{}/{label}", self.project)
    }

    async fn receipt_count(&self, key: &str) -> i64 {
        sqlx::query_scalar(
            "SELECT count(*)::INT8 FROM memory_mutation_receipts \
             WHERE tenant_id = $1 AND idempotency_key = $2",
        )
        .bind(self.tenant)
        .bind(self.key(key))
        .fetch_one(self.pool())
        .await
        .unwrap()
    }

    async fn keyed_events(&self, key: &str) -> Vec<(String, Value)> {
        sqlx::query_as(
            "SELECT event_kind, payload FROM memory_events \
             WHERE tenant_id = $1 AND idempotency_key = $2",
        )
        .bind(self.tenant)
        .bind(self.key(key))
        .fetch_all(self.pool())
        .await
        .unwrap()
    }

    async fn transitions(&self, claim_id: i64) -> Vec<(String, String, String, Value)> {
        sqlx::query_as(
            "SELECT reason, from_state, to_state, payload FROM memory_claim_events \
             WHERE tenant_id = $1 AND project = $2 AND claim_id = $3 \
               AND event_kind = 'state_transition' \
             ORDER BY created_at, event_id",
        )
        .bind(self.tenant)
        .bind(&self.project)
        .bind(claim_id)
        .fetch_all(self.pool())
        .await
        .unwrap()
    }

    /// Seed a raw claim row the serving writer could not have produced.
    async fn raw_claim(
        &self,
        project: &str,
        subject: &str,
        kind: &str,
        origin: &str,
        actor: Option<&str>,
    ) -> i64 {
        let eligible = kind == "decision";
        sqlx::query_scalar(
            "INSERT INTO memory_claims (\
                 tenant_id, project, kind, claim_key, subject, predicate, value, text, \
                 polarity, state, origin, actor, conflict_eligible\
             ) VALUES ($1, $2, $3, $4, $5, 'database-choice', $6, 'raw lifecycle fixture', \
                 1, 'active', $7, $8, $9) \
             RETURNING id",
        )
        .bind(self.tenant)
        .bind(project)
        .bind(kind)
        .bind(format!("{subject}::database-choice"))
        .bind(subject)
        .bind(json!("cockroachdb"))
        .bind(origin)
        .bind(actor)
        .bind(eligible)
        .fetch_one(self.pool())
        .await
        .unwrap()
    }

    /// Seed a legacy-era disputed decision on `{subject}::database-choice`, as
    /// the retired typed-value detector left them before reconciliation.
    async fn legacy_disputed_decision(&self, subject: &str, value: &str, actor: &str) -> i64 {
        sqlx::query_scalar(
            "INSERT INTO memory_claims (\
                 tenant_id, project, kind, claim_key, subject, predicate, value, text, \
                 polarity, state, origin, actor, conflict_eligible\
             ) VALUES ($1, $2, 'decision', $3, $4, 'database-choice', $5, \
                 'legacy lifecycle fixture', 1, 'disputed', 'operator_asserted', $6, true) \
             RETURNING id",
        )
        .bind(self.tenant)
        .bind(&self.project)
        .bind(format!("{subject}::database-choice"))
        .bind(subject)
        .bind(json!(value))
        .bind(actor)
        .fetch_one(self.pool())
        .await
        .unwrap()
    }

    async fn conflict_row(&self, conflict_id: i64) -> (String, i64) {
        sqlx::query_as(
            "SELECT state, revision FROM memory_conflicts \
             WHERE tenant_id = $1 AND project = $2 AND id = $3",
        )
        .bind(self.tenant)
        .bind(&self.project)
        .bind(conflict_id)
        .fetch_one(self.pool())
        .await
        .unwrap()
    }

    async fn claim_state(&self, claim_id: i64) -> String {
        sqlx::query_scalar(
            "SELECT state FROM memory_claims WHERE tenant_id = $1 AND project = $2 AND id = $3",
        )
        .bind(self.tenant)
        .bind(&self.project)
        .bind(claim_id)
        .fetch_one(self.pool())
        .await
        .unwrap()
    }

    async fn legacy_conflict(&self, claim_key: &str, members: &[i64]) -> i64 {
        let conflict_id: i64 = sqlx::query_scalar(
            "INSERT INTO memory_conflicts (tenant_id, project, claim_key, detector, rationale) \
             VALUES ($1, $2, $3, 'same_key_typed_value', 'legacy lifecycle fixture') \
             RETURNING id",
        )
        .bind(self.tenant)
        .bind(&self.project)
        .bind(claim_key)
        .fetch_one(self.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO memory_conflict_members (tenant_id, project, conflict_id, claim_id) \
             SELECT $1, $2, $3, claim_id FROM unnest($4::INT8[]) AS members(claim_id)",
        )
        .bind(self.tenant)
        .bind(&self.project)
        .bind(conflict_id)
        .bind(members)
        .execute(self.pool())
        .await
        .unwrap();
        conflict_id
    }

    /// A refused key is still free: the same key then commits another mutation.
    async fn assert_key_unconsumed(&self, key: &str) {
        assert_eq!(self.receipt_count(key).await, 0, "{key} left a receipt");
        assert!(
            self.keyed_events(key).await.is_empty(),
            "{key} left an event"
        );
        let reuse = self
            .ledger(AGENT_A)
            .record_claim(
                &self.scope(AGENT_A),
                &note(&format!("reusing refused key {key}")),
                &self.key(key),
            )
            .await
            .expect("a refused key is reusable");
        assert!(!reuse.idempotent_replay);
    }

    /// The lifecycle invariants every committed interleaving must preserve.
    ///
    /// A key's lineage follows the read side's precedence: once the key has a
    /// v2 lineage, its preserved legacy row is history, not a current lineage.
    async fn assert_lifecycle_invariants(&self) {
        let orphaned_disputes: Vec<i64> = sqlx::query_scalar(
            "SELECT c.id FROM memory_claims AS c \
             WHERE c.tenant_id = $1 AND c.project = $2 AND c.state = 'disputed' \
               AND NOT EXISTS (\
                 SELECT 1 FROM memory_conflict_members AS m \
                 JOIN memory_conflicts AS k \
                   ON k.tenant_id = m.tenant_id AND k.project = m.project \
                  AND k.id = m.conflict_id \
                 WHERE m.tenant_id = $1 AND m.project = $2 AND m.claim_id = c.id \
                   AND k.state = 'open' \
                   AND (k.detector = 'same_key_functional_value_v2' OR NOT EXISTS (\
                     SELECT 1 FROM memory_conflicts AS v2 \
                     WHERE v2.tenant_id = k.tenant_id AND v2.project = k.project \
                       AND v2.claim_key = k.claim_key \
                       AND v2.detector = 'same_key_functional_value_v2')))",
        )
        .bind(self.tenant)
        .bind(&self.project)
        .fetch_all(self.pool())
        .await
        .unwrap();
        assert!(
            orphaned_disputes.is_empty(),
            "disputed claims outside every open current lineage: {orphaned_disputes:?}"
        );

        let unjustified_open: Vec<i64> = sqlx::query_scalar(
            "SELECT k.id FROM memory_conflicts AS k \
             WHERE k.tenant_id = $1 AND k.project = $2 \
               AND k.detector = 'same_key_functional_value_v2' AND k.state = 'open' \
               AND NOT EXISTS (\
                 SELECT 1 FROM memory_claims AS a \
                 JOIN memory_claims AS b \
                   ON b.tenant_id = a.tenant_id AND b.project = a.project \
                  AND b.claim_key = a.claim_key AND a.id < b.id \
                 WHERE a.tenant_id = $1 AND a.project = $2 AND a.claim_key = k.claim_key \
                   AND a.state IN ('active', 'disputed') AND b.state IN ('active', 'disputed') \
                   AND a.conflict_eligible AND b.conflict_eligible \
                   AND ((a.polarity = 1 AND b.polarity = 1 AND a.value IS DISTINCT FROM b.value) \
                        OR (a.polarity <> b.polarity AND a.value IS NOT DISTINCT FROM b.value)) \
                   AND (a.valid_to IS NULL OR b.valid_from IS NULL OR b.valid_from < a.valid_to) \
                   AND (b.valid_to IS NULL OR a.valid_from IS NULL OR a.valid_from < b.valid_to))",
        )
        .bind(self.tenant)
        .bind(&self.project)
        .fetch_all(self.pool())
        .await
        .unwrap();
        assert!(
            unjustified_open.is_empty(),
            "open v2 conflicts without an incompatible current pair: {unjustified_open:?}"
        );

        let bad_receipts: Vec<String> = sqlx::query_scalar(
            "SELECT r.idempotency_key FROM memory_mutation_receipts AS r \
             WHERE r.tenant_id = $1 AND r.project = $2 \
               AND (r.response IS NULL OR (\
                 SELECT count(*) FROM memory_events AS e \
                 WHERE e.tenant_id = r.tenant_id AND e.idempotency_key = r.idempotency_key\
               ) <> 1)",
        )
        .bind(self.tenant)
        .bind(&self.project)
        .fetch_all(self.pool())
        .await
        .unwrap();
        assert!(
            bad_receipts.is_empty(),
            "receipts without a response or exactly one keyed event: {bad_receipts:?}"
        );
    }

    async fn cleanup(self) {
        for statement in [
            "DELETE FROM memory_mutation_receipts WHERE tenant_id = $1",
            "DELETE FROM memory_events WHERE tenant_id = $1",
            "DELETE FROM memory_conflicts WHERE tenant_id = $1",
            "DELETE FROM memory_claims WHERE tenant_id = $1",
            "DELETE FROM memory_chunks WHERE tenant_id = $1",
            "DELETE FROM memory_corpus_models WHERE tenant_id = $1",
        ] {
            sqlx::query(statement)
                .bind(self.tenant)
                .execute(self.pool())
                .await
                .unwrap();
        }
        let residue: i64 = sqlx::query_scalar(
            "SELECT \
                 (SELECT count(*) FROM memory_mutation_receipts WHERE tenant_id = $1) + \
                 (SELECT count(*) FROM memory_events WHERE tenant_id = $1) + \
                 (SELECT count(*) FROM memory_claim_events WHERE tenant_id = $1) + \
                 (SELECT count(*) FROM memory_claim_embeddings WHERE tenant_id = $1) + \
                 (SELECT count(*) FROM memory_conflict_members WHERE tenant_id = $1) + \
                 (SELECT count(*) FROM memory_conflicts WHERE tenant_id = $1) + \
                 (SELECT count(*) FROM memory_claims WHERE tenant_id = $1) + \
                 (SELECT count(*) FROM memory_chunks WHERE tenant_id = $1) + \
                 (SELECT count(*) FROM memory_corpus_models WHERE tenant_id = $1)",
        )
        .bind(self.tenant)
        .fetch_one(self.pool())
        .await
        .unwrap();
        assert_eq!(residue, 0, "lifecycle test leaked tenant rows");
    }
}

fn decision(subject: &str, value: &Value, polarity: i16) -> ClaimInput {
    ClaimInput {
        kind: ClaimKind::Decision,
        text: format!("lifecycle fixture {subject} chooses {value} with polarity {polarity}"),
        subject: Some(subject.into()),
        predicate: Some("database-choice".into()),
        value: Some(value.clone()),
        polarity,
        origin: "operator_asserted".into(),
        actor: None,
        confidence: 1.0,
        valid_from: None,
        valid_to: None,
        support: Vec::new(),
    }
}

fn note(text: &str) -> ClaimInput {
    ClaimInput {
        kind: ClaimKind::Note,
        text: text.into(),
        subject: None,
        predicate: None,
        value: None,
        polarity: 1,
        origin: "operator_asserted".into(),
        actor: None,
        confidence: 1.0,
        valid_from: None,
        valid_to: None,
        support: Vec::new(),
    }
}

fn refusal(result: ostk_fleet_recall::Result<ClaimMutation>) -> LifecycleRefusal {
    match result {
        Err(FleetError::LifecycleRefused(refusal)) => *refusal,
        other => panic!("expected a typed lifecycle refusal, got {other:?}"),
    }
}

fn database_url() -> Option<String> {
    std::env::var("FLEET_RECALL_TEST_DATABASE_URL").ok()
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // one scenario proves the whole close/restore/reopen cycle
async fn live_retract_closes_two_party_conflict_and_restores_peer_when_configured() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fleet = Fleet::new(&database_url, "two-party").await;
    let x = fleet
        .record(AGENT_A, &decision("two-party", &json!("x"), 1), "a/x")
        .await;
    let y = fleet
        .record(AGENT_B, &decision("two-party", &json!("y"), 1), "b/y")
        .await;
    let conflict_id = y.claim.conflict_ids[0];
    let before = fleet.conflict(conflict_id).await;
    assert_eq!(before.state, "open");
    let x_before = fleet.claim(x.claim.id).await;
    assert_eq!(x_before.state, ClaimState::Disputed);

    let retracted = fleet
        .retract(AGENT_A, x.claim.id, x_before.revision, "a/retract-x")
        .await
        .expect("owner retract succeeds");
    assert_eq!(retracted.operation, "retract");
    assert!(!retracted.idempotent_replay);
    assert_eq!(retracted.claim.state, ClaimState::Retracted);
    assert_eq!(retracted.claim.revision, x_before.revision + 1);
    // Lineage membership is historical: the retracted claim stays a member.
    assert_eq!(retracted.claim.conflict_ids, [conflict_id]);
    assert_eq!(retracted.conflicts_resolved, [conflict_id]);
    assert!(retracted.conflicts_opened.is_empty());
    assert_eq!(retracted.claims_restored, [y.claim.id]);
    let reevaluation = retracted.reevaluation.as_ref().expect("re-evaluated");
    assert_eq!(reevaluation.conflict_id, conflict_id);
    assert_eq!(reevaluation.outcome, "closed");
    assert_eq!(reevaluation.conflict_revision, before.revision + 1);
    assert_eq!(reevaluation.remaining_pair_count, 0);

    let after = fleet.conflict(conflict_id).await;
    assert_eq!(after.state, "resolved");
    assert_eq!(after.revision, before.revision + 1);
    assert_eq!(
        after.resolution_kind.as_deref(),
        Some("no_current_incompatibility")
    );
    assert!(after.resolved_at.is_some());
    assert_eq!(
        after.resolution_reason.as_deref(),
        Some(
            format!(
                "no lifecycle-current incompatible pair remains after retract of claim {}",
                x.claim.id
            )
            .as_str()
        )
    );
    assert_eq!(after.member_count, 2);

    let peer = fleet.claim(y.claim.id).await;
    assert_eq!(peer.state, ClaimState::Active);
    assert_eq!(peer.revision, y.claim.revision + 1);
    let peer_transitions = fleet.transitions(y.claim.id).await;
    let restore = peer_transitions.last().expect("restore event");
    assert_eq!(
        (restore.0.as_str(), restore.1.as_str(), restore.2.as_str()),
        ("conflict_resolved", "disputed", "active")
    );
    assert_eq!(restore.3["conflict_id"], conflict_id);
    assert_eq!(restore.3["conflict_revision"], after.revision);
    assert_eq!(restore.3["idempotency_key"], fleet.key("a/retract-x"));
    let author_transitions = fleet.transitions(x.claim.id).await;
    let retire = author_transitions.last().expect("retract event");
    assert_eq!(
        (retire.0.as_str(), retire.1.as_str(), retire.2.as_str()),
        ("retracted_by_author", "disputed", "retracted")
    );
    assert_eq!(retire.3["revision_before"], x_before.revision);

    let events = fleet.keyed_events("a/retract-x").await;
    assert_eq!(events.len(), 1, "exactly one keyed event");
    assert_eq!(events[0].0, "claim_retracted");
    assert_eq!(events[0].1["to_state"], "retracted");
    assert_eq!(
        events[0].1["conflict_reevaluation"]["outcome"],
        json!("closed")
    );
    assert_eq!(fleet.receipt_count("a/retract-x").await, 1);
    fleet.assert_lifecycle_invariants().await;

    // The record path is untouched: a new incompatible value reopens the
    // resolved lineage and disputes the restored peer again.
    let z = fleet
        .record(AGENT_C, &decision("two-party", &json!("z"), 1), "c/z")
        .await;
    assert_eq!(z.claim.conflict_ids, [conflict_id]);
    assert_eq!(z.conflicts_opened, [conflict_id]);
    let reopened = fleet.conflict(conflict_id).await;
    assert_eq!(reopened.state, "open");
    assert_eq!(reopened.revision, after.revision + 1);
    assert_eq!(fleet.claim(y.claim.id).await.state, ClaimState::Disputed);
    assert_eq!(fleet.claim(x.claim.id).await.state, ClaimState::Retracted);
    fleet.assert_lifecycle_invariants().await;

    fleet.cleanup().await;
}

#[tokio::test]
async fn live_retract_three_way_keeps_open_until_last_incompatibility_when_configured() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fleet = Fleet::new(&database_url, "three-way").await;
    let x = fleet
        .record(AGENT_A, &decision("three-way", &json!("x"), 1), "a/x")
        .await;
    let y = fleet
        .record(AGENT_B, &decision("three-way", &json!("y"), 1), "b/y")
        .await;
    let z = fleet
        .record(AGENT_C, &decision("three-way", &json!("z"), 1), "c/z")
        .await;
    let conflict_id = z.claim.conflict_ids[0];
    let open = fleet.conflict(conflict_id).await;

    let first = fleet
        .retract(
            AGENT_A,
            x.claim.id,
            fleet.claim(x.claim.id).await.revision,
            "a/retract",
        )
        .await
        .unwrap();
    let reevaluation = first.reevaluation.as_ref().unwrap();
    assert_eq!(reevaluation.outcome, "still_open");
    assert_eq!(reevaluation.conflict_revision, open.revision);
    assert_eq!(reevaluation.remaining_pair_count, 1);
    assert_eq!(reevaluation.remaining_pairs, [[y.claim.id, z.claim.id]]);
    assert!(first.conflicts_resolved.is_empty());
    assert!(first.claims_restored.is_empty());
    let still_open = fleet.conflict(conflict_id).await;
    assert_eq!(still_open.state, "open");
    assert_eq!(still_open.revision, open.revision);
    assert_eq!(fleet.claim(y.claim.id).await.state, ClaimState::Disputed);
    fleet.assert_lifecycle_invariants().await;

    let last = fleet
        .retract(
            AGENT_B,
            y.claim.id,
            fleet.claim(y.claim.id).await.revision,
            "b/retract",
        )
        .await
        .unwrap();
    assert_eq!(last.reevaluation.as_ref().unwrap().outcome, "closed");
    assert_eq!(last.conflicts_resolved, [conflict_id]);
    assert_eq!(last.claims_restored, [z.claim.id]);
    assert_eq!(fleet.conflict(conflict_id).await.state, "resolved");
    assert_eq!(fleet.claim(z.claim.id).await.state, ClaimState::Active);
    fleet.assert_lifecycle_invariants().await;

    // +x, -x, +y: once +x is retracted, -x and +y are compatible.
    let affirmed = fleet
        .record(AGENT_A, &decision("polarity", &json!("x"), 1), "a/+x")
        .await;
    let negated = fleet
        .record(AGENT_B, &decision("polarity", &json!("x"), -1), "b/-x")
        .await;
    let other = fleet
        .record(AGENT_C, &decision("polarity", &json!("y"), 1), "c/+y")
        .await;
    assert_eq!(
        fleet.claim(negated.claim.id).await.state,
        ClaimState::Disputed
    );
    let closed = fleet
        .retract(
            AGENT_A,
            affirmed.claim.id,
            fleet.claim(affirmed.claim.id).await.revision,
            "a/retract-+x",
        )
        .await
        .unwrap();
    assert_eq!(closed.reevaluation.as_ref().unwrap().outcome, "closed");
    assert_eq!(closed.claims_restored, [negated.claim.id, other.claim.id]);
    fleet.assert_lifecycle_invariants().await;

    fleet.cleanup().await;
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // every refusal code with its no-residue proof
async fn live_retract_refusals_leave_no_receipt_or_rows_when_configured() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fleet = Fleet::new(&database_url, "refusals").await;
    let x = fleet
        .record(AGENT_A, &decision("refusals", &json!("x"), 1), "a/x")
        .await;
    fleet
        .record(AGENT_B, &decision("refusals", &json!("y"), 1), "b/y")
        .await;
    let x_disputed = fleet.claim(x.claim.id).await;

    let not_owner = refusal(
        fleet
            .retract(AGENT_B, x.claim.id, x_disputed.revision, "b/not-owner")
            .await,
    );
    assert_eq!(not_owner.code, RefusalCode::NotOwner);
    fleet.assert_key_unconsumed("b/not-owner").await;

    let stale = refusal(
        fleet
            .retract(AGENT_A, x.claim.id, x_disputed.revision - 1, "a/stale")
            .await,
    );
    assert_eq!(stale.code, RefusalCode::StaleRevision);
    assert_eq!(stale.details["current_revision"], x_disputed.revision);
    assert_eq!(stale.details["current_state"], "disputed");
    fleet.assert_key_unconsumed("a/stale").await;
    let unchanged = fleet.claim(x.claim.id).await;
    assert_eq!(
        (unchanged.state, unchanged.revision),
        (x_disputed.state, x_disputed.revision)
    );
    assert_eq!(
        fleet.transitions(x.claim.id).await.len(),
        1,
        "only the record-time dispute transition exists"
    );

    fleet
        .retract(AGENT_A, x.claim.id, x_disputed.revision, "a/retract")
        .await
        .expect("corrected retract commits");
    let not_current = refusal(
        fleet
            .retract(AGENT_A, x.claim.id, x_disputed.revision + 1, "a/again")
            .await,
    );
    assert_eq!(not_current.code, RefusalCode::NotCurrent);
    assert_eq!(not_current.details["current_state"], "retracted");
    fleet.assert_key_unconsumed("a/again").await;

    let elsewhere_project = format!("{}-elsewhere", fleet.project);
    let elsewhere = fleet
        .raw_claim(
            &elsewhere_project,
            "elsewhere",
            "decision",
            "operator_asserted",
            Some(AGENT_A),
        )
        .await;
    for (claim_id, key) in [
        (elsewhere, "a/elsewhere"),
        (9_007_199_254_740_990, "a/none"),
    ] {
        let not_found = refusal(fleet.retract(AGENT_A, claim_id, 1, key).await);
        assert_eq!(not_found.code, RefusalCode::NotFound);
        fleet.assert_key_unconsumed(key).await;
    }

    let legacy_claim = fleet
        .raw_claim(
            &fleet.project,
            "legacy-guard",
            "decision",
            "operator_asserted",
            Some(AGENT_A),
        )
        .await;
    fleet
        .legacy_conflict("legacy-guard::database-choice", &[legacy_claim])
        .await;
    let legacy = refusal(fleet.retract(AGENT_A, legacy_claim, 1, "a/legacy").await);
    assert_eq!(legacy.code, RefusalCode::LegacyLineage);
    fleet.assert_key_unconsumed("a/legacy").await;
    assert_eq!(fleet.claim(legacy_claim).await.state, ClaimState::Active);

    let derived = fleet
        .raw_claim(
            &fleet.project,
            "derived",
            "note",
            "source_derived",
            Some(AGENT_A),
        )
        .await;
    let derived_refusal = refusal(fleet.retract(AGENT_A, derived, 1, "a/derived").await);
    assert_eq!(derived_refusal.code, RefusalCode::NotOperatorAsserted);
    fleet.assert_key_unconsumed("a/derived").await;

    let unattributed = fleet
        .raw_claim(
            &fleet.project,
            "unattributed",
            "note",
            "operator_asserted",
            None,
        )
        .await;
    let unattributed_refusal = refusal(
        fleet
            .retract(AGENT_A, unattributed, 1, "a/unattributed")
            .await,
    );
    assert_eq!(unattributed_refusal.code, RefusalCode::NotOwner);
    fleet.assert_key_unconsumed("a/unattributed").await;
    assert_eq!(fleet.claim(unattributed).await.state, ClaimState::Active);

    // Cleanup is tenant-wide, so it also removes the other project's claim.
    fleet.cleanup().await;
}

#[tokio::test]
async fn live_retract_replay_and_cross_operation_reuse_when_configured() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fleet = Fleet::new(&database_url, "replay").await;
    let x = fleet
        .record(AGENT_A, &decision("replay", &json!("x"), 1), "a/x")
        .await;
    fleet
        .record(AGENT_B, &decision("replay", &json!("y"), 1), "b/y")
        .await;
    let revision = fleet.claim(x.claim.id).await.revision;
    let first = fleet
        .retract(AGENT_A, x.claim.id, revision, "a/retract")
        .await
        .unwrap();

    // Later state changes: C reopens the lineage.
    fleet
        .record(AGENT_C, &decision("replay", &json!("z"), 1), "c/z")
        .await;

    let replay = fleet
        .retract(AGENT_A, x.claim.id, revision, "a/retract")
        .await
        .expect("an identical request replays");
    assert!(replay.idempotent_replay);
    let mut normalized = replay.clone();
    normalized.idempotent_replay = false;
    assert_eq!(normalized, first, "replay returns the stored result");
    assert_eq!(fleet.keyed_events("a/retract").await.len(), 1);

    let ledger = fleet.ledger(AGENT_A);
    let scope = fleet.scope(AGENT_A);
    let different_request = ledger
        .retract_claim(
            &scope,
            ClaimTarget {
                claim_id: x.claim.id,
                expected_revision: revision,
            },
            Some("a different audit note"),
            &fleet.key("a/retract"),
        )
        .await;
    assert!(matches!(
        different_request,
        Err(FleetError::IdempotencyConflict(_))
    ));
    let other_session = FleetScope::new(
        fleet.tenant,
        &fleet.project,
        AGENT_A,
        Some("another-session".into()),
        PrivacyTier::T1Project,
    )
    .unwrap();
    let session_reuse = ledger
        .retract_claim(
            &other_session,
            ClaimTarget {
                claim_id: x.claim.id,
                expected_revision: revision,
            },
            None,
            &fleet.key("a/retract"),
        )
        .await;
    assert!(matches!(
        session_reuse,
        Err(FleetError::IdempotencyConflict(_))
    ));

    // A record key cannot be reused for retract, nor a retract key for record.
    let recorded = fleet.record(AGENT_A, &note("a plain note"), "a/note").await;
    let cross = fleet.retract(AGENT_A, recorded.claim.id, 1, "a/note").await;
    assert!(matches!(cross, Err(FleetError::IdempotencyConflict(_))));
    let cross = ledger
        .record_claim(&scope, &note("reuse"), &fleet.key("a/retract"))
        .await;
    assert!(matches!(cross, Err(FleetError::IdempotencyConflict(_))));
    fleet.assert_lifecycle_invariants().await;

    fleet.cleanup().await;
}

fn retract_request(key: String, claim_id: i64, expected_revision: i64) -> RememberRequest {
    RememberRequest::new(
        RememberAction::Retract,
        Some(key),
        Map::from_iter([
            ("claim_id".into(), json!(claim_id)),
            ("expected_revision".into(), json!(expected_revision)),
        ]),
    )
}

fn refusal_code(result: Result<RememberResult, ServiceError>) -> &'static str {
    match result {
        Err(ServiceError::Refused(refusal)) => refusal.code,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn live_retract_replays_on_record_only_writer_when_configured() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fleet = Fleet::new(&database_url, "surface-replay").await;
    let scope = fleet.scope(AGENT_A);
    let enabled = fleet.service(AGENT_A, PRIVATE_WRITER);
    // The same writer after FLEET_RECALL_REMEMBER_LIFECYCLE=disabled.
    let disabled = fleet.service(AGENT_A, LifecycleServing::default());
    let x = fleet
        .record(AGENT_A, &decision("surface-replay", &json!("x"), 1), "a/x")
        .await;
    let y = fleet
        .record(AGENT_B, &decision("surface-replay", &json!("y"), 1), "b/y")
        .await;
    let revision = fleet.claim(x.claim.id).await.revision;
    let committed = FleetMemoryService::remember(
        &enabled,
        scope.clone(),
        retract_request(fleet.key("a/retract"), x.claim.id, revision),
    )
    .await
    .expect("the enabled writer commits the retract");
    assert_eq!(committed.data["idempotent_replay"], false);

    // A retry whose response was lost reaches the disabled writer: it gets
    // the stored result, not a refusal claiming nothing was committed.
    let replay = FleetMemoryService::remember(
        &disabled,
        scope.clone(),
        retract_request(fleet.key("a/retract"), x.claim.id, revision),
    )
    .await
    .expect("a committed retract replays where retract is no longer served");
    assert_eq!(replay.data["idempotent_replay"], true);
    let mut normalized = replay.data.clone();
    normalized["idempotent_replay"] = json!(false);
    assert_eq!(normalized, committed.data);
    assert_eq!(replay.data["claims_restored"], json!([y.claim.id]));
    assert_eq!(replay.conflicts[0]["state"], "resolved");
    assert_eq!(fleet.receipt_count("a/retract").await, 1);
    assert_eq!(fleet.keyed_events("a/retract").await.len(), 1);

    // Any other use of a consumed key is an idempotency conflict, never a
    // refusal saying the key is free.
    fleet.record(AGENT_A, &note("a plain note"), "a/note").await;
    for (key, request) in [
        (
            "a/retract",
            retract_request(fleet.key("a/retract"), x.claim.id, revision + 1),
        ),
        (
            "a/retract",
            retract_request(fleet.key("a/retract"), 0, revision),
        ),
        (
            "a/note",
            retract_request(fleet.key("a/note"), x.claim.id, revision),
        ),
        (
            "a/retract",
            RememberRequest::new(
                RememberAction::Supersede,
                Some(fleet.key("a/retract")),
                Map::new(),
            ),
        ),
    ] {
        let error = FleetMemoryService::remember(&disabled, scope.clone(), request)
            .await
            .unwrap_err();
        assert!(
            matches!(&error, ServiceError::InvalidRequest(message)
                if message.contains("already used for a different mutation")),
            "{key}: {error}"
        );
    }

    // Only a key no receipt holds is refused as not served, and it stays free.
    let unused = FleetMemoryService::remember(
        &disabled,
        scope.clone(),
        retract_request(fleet.key("a/unused"), y.claim.id, 1),
    )
    .await;
    assert_eq!(refusal_code(unused), "lifecycle_unavailable");
    fleet.assert_key_unconsumed("a/unused").await;
    fleet.assert_lifecycle_invariants().await;

    fleet.cleanup().await;
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // reconcile, close, and read back one legacy-era key
async fn live_restore_after_reconciliation_ignores_preserved_legacy_row_when_configured() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fleet = Fleet::new(&database_url, "restore-guard").await;
    let claim_key = "restore-guard::database-choice";
    // Legacy-era state: x and y disputed under the retired typed-value lineage.
    let x = fleet
        .legacy_disputed_decision("restore-guard", "x", AGENT_A)
        .await;
    let y = fleet
        .legacy_disputed_decision("restore-guard", "y", AGENT_B)
        .await;
    let legacy = fleet.legacy_conflict(claim_key, &[x, y]).await;
    let legacy_before = fleet.conflict_row(legacy).await;

    // The step a legacy_lineage refusal points to: reconciliation preserves
    // the legacy row unchanged and hands the key's disputes to a v2 lineage.
    let reconciled = CockroachConflictReconciliationRepository::new(
        fleet.pool().clone(),
        fleet.scope(AGENT_C),
        RetryPolicy::default(),
    )
    .unwrap()
    .reconcile_legacy_conflict(
        &fleet.scope(AGENT_C),
        legacy,
        legacy_before.1,
        &fleet.key("c/reconcile"),
    )
    .await
    .expect("reconciliation succeeds");
    assert_eq!(reconciled.v2_state, "open");
    assert_eq!(reconciled.v2_member_ids, [x, y]);
    let v2_conflict = reconciled.conflict_id;
    assert_eq!(fleet.conflict_row(legacy).await, legacy_before);
    assert_eq!(fleet.claim(y).await.conflict_ids, [v2_conflict]);

    let retracted = fleet
        .retract(AGENT_A, x, fleet.claim(x).await.revision, "a/retract")
        .await
        .unwrap();
    assert_eq!(retracted.conflicts_resolved, [v2_conflict]);
    assert_eq!(
        retracted.claims_restored,
        [y],
        "the preserved legacy row does not hold a reconciled key's member"
    );
    assert_eq!(retracted.reevaluation.as_ref().unwrap().outcome, "closed");
    assert_eq!(fleet.conflict(v2_conflict).await.state, "resolved");
    assert_eq!(fleet.claim(y).await.state, ClaimState::Active);
    // History is append-only: the legacy row is still exactly as it was.
    assert_eq!(fleet.conflict_row(legacy).await, legacy_before);
    // No reader sees a dispute: nothing open is listed or projected for y.
    let ledger = fleet.ledger(AGENT_C);
    let scope = fleet.scope(AGENT_C);
    assert!(
        ledger
            .list_conflicts(&scope, false, 10)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        ledger
            .conflicts_for_claim_ids(&scope, &[y], 10)
            .await
            .unwrap()
            .is_empty()
    );
    fleet.assert_lifecycle_invariants().await;

    // Any other open conflict still holds its member: here an open lineage on
    // another key that also lists z keeps z disputed after z's key closes.
    let w = fleet
        .record(AGENT_A, &decision("restore-hold", &json!("w"), 1), "a/w")
        .await;
    let z = fleet
        .record(AGENT_B, &decision("restore-hold", &json!("z"), 1), "b/z")
        .await;
    let held_conflict = z.claim.conflict_ids[0];
    let holder = fleet
        .legacy_conflict("restore-hold-elsewhere::database-choice", &[z.claim.id])
        .await;
    let closed = fleet
        .retract(
            AGENT_A,
            w.claim.id,
            fleet.claim(w.claim.id).await.revision,
            "a/retract-w",
        )
        .await
        .unwrap();
    assert_eq!(closed.conflicts_resolved, [held_conflict]);
    assert!(
        closed.claims_restored.is_empty(),
        "an open conflict on another key still holds z"
    );
    // Read the row itself: claim reads fail closed on a cross-key membership.
    assert_eq!(fleet.claim_state(z.claim.id).await, "disputed");
    assert_eq!(fleet.conflict_row(holder).await.0, "open");
    fleet.assert_lifecycle_invariants().await;

    fleet.cleanup().await;
}

async fn recall(
    service: &CockroachMemoryService,
    scope: &FleetScope,
    action: RecallAction,
    arguments: Value,
) -> Result<RecallResult, ServiceError> {
    FleetMemoryService::recall(
        service,
        scope.clone(),
        RecallRequest::new(action, arguments.as_object().cloned().unwrap_or_default()),
    )
    .await
}

fn hit_ids(result: &RecallResult) -> Vec<String> {
    result.data["hits"]
        .as_array()
        .unwrap()
        .iter()
        .map(|hit| hit["chunk_id"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // private and publication surfaces over one corpus
async fn live_private_search_hides_retracted_synthetic_chunk_publication_unchanged_when_configured()
{
    let Some(database_url) = database_url() else {
        return;
    };
    let fleet = Fleet::new(&database_url, "search").await;
    let scope = fleet.scope(AGENT_A);
    let private = fleet.service(AGENT_A, PRIVATE_WRITER);
    let record_only = fleet.service(AGENT_A, LifecycleServing::default());

    let x = fleet
        .record(AGENT_A, &decision("quokkaledger", &json!("x"), 1), "a/x")
        .await;
    let y = fleet
        .record(AGENT_B, &decision("quokkaledger", &json!("y"), 1), "b/y")
        .await;
    let x_chunk = format!("claim:{}", x.claim.id);
    let y_chunk = format!("claim:{}", y.claim.id);
    let query = json!({ "query": "quokkaledger", "kind": "chunk", "limit": 10 });

    let before = recall(&private, &scope, RecallAction::Search, query.clone())
        .await
        .unwrap();
    assert!(hit_ids(&before).contains(&x_chunk));
    assert!(hit_ids(&before).contains(&y_chunk));
    assert_eq!(
        before.diagnostics["retrieval"]["lifecycle_hidden_claim_ids"],
        json!([])
    );

    // Retract through the service: the response carries the closed conflict.
    let revision = fleet.claim(x.claim.id).await.revision;
    let remembered = FleetMemoryService::remember(
        &private,
        scope.clone(),
        RememberRequest::new(
            RememberAction::Retract,
            Some(fleet.key("a/retract")),
            Map::from_iter([
                ("claim_id".into(), json!(x.claim.id)),
                ("expected_revision".into(), json!(revision)),
                ("reason".into(), json!("superseded by the storage review")),
            ]),
        ),
    )
    .await
    .unwrap();
    let conflict_id = y.claim.conflict_ids[0];
    assert_eq!(remembered.data["operation"], "retract");
    assert_eq!(remembered.data["conflicts_resolved"], json!([conflict_id]));
    assert_eq!(remembered.conflicts.len(), 1);
    assert_eq!(remembered.conflicts[0]["state"], "resolved");
    assert_eq!(remembered.conflict_coverage.status, "complete");

    let after = recall(&private, &scope, RecallAction::Search, query.clone())
        .await
        .unwrap();
    assert!(!hit_ids(&after).contains(&x_chunk));
    assert!(hit_ids(&after).contains(&y_chunk));
    assert_eq!(
        after.diagnostics["retrieval"]["lifecycle_hidden_claim_ids"],
        json!([x.claim.id])
    );
    assert!(after.conflicts.is_empty(), "no open conflict is projected");

    let publication = recall(&record_only, &scope, RecallAction::Search, query)
        .await
        .unwrap();
    assert!(hit_ids(&publication).contains(&x_chunk));
    assert!(
        publication.diagnostics["retrieval"]
            .get("lifecycle_hidden_claim_ids")
            .is_none()
    );

    // Conflict lookup by id is part of the lifecycle surface only.
    let lookup = recall(
        &private,
        &scope,
        RecallAction::Get,
        json!({ "kind": "conflict", "id": conflict_id }),
    )
    .await
    .unwrap();
    assert_eq!(lookup.data["conflict"]["state"], "resolved");
    let member_states = lookup.data["conflict"]["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|member| member["state"].as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(member_states, ["retracted", "active"]);
    assert_eq!(lookup.conflict_coverage.status, "complete");
    assert!(matches!(
        recall(
            &record_only,
            &scope,
            RecallAction::Get,
            json!({ "kind": "conflict", "id": conflict_id }),
        )
        .await,
        Err(ServiceError::InvalidRequest(_))
    ));

    // Claim search keeps its history contract.
    let current = recall(
        &private,
        &scope,
        RecallAction::Search,
        json!({ "query": "quokkaledger", "kind": "claim", "limit": 10 }),
    )
    .await
    .unwrap();
    assert!(
        current.data["hits"]
            .as_array()
            .unwrap()
            .iter()
            .all(|hit| hit["claim"]["id"] != x.claim.id)
    );
    let history = recall(
        &private,
        &scope,
        RecallAction::Search,
        json!({ "query": "quokkaledger", "kind": "claim", "limit": 10, "include_history": true }),
    )
    .await
    .unwrap();
    assert!(
        history.data["hits"]
            .as_array()
            .unwrap()
            .iter()
            .any(|hit| hit["claim"]["id"] == x.claim.id && hit["claim"]["state"] == "retracted")
    );

    let status = recall(&private, &scope, RecallAction::Status, json!({}))
        .await
        .unwrap();
    assert_eq!(status.data["remember_surface"]["claim_lifecycle"], true);
    let status = recall(&record_only, &scope, RecallAction::Status, json!({}))
        .await
        .unwrap();
    assert!(status.data.get("remember_surface").is_none());

    fleet.cleanup().await;
}

#[tokio::test]
async fn live_private_search_refills_page_past_retracted_hits_when_configured() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fleet = Fleet::new(&database_url, "search-refill").await;
    let scope = fleet.scope(AGENT_A);
    let embedder: Arc<dyn ChunkEmbedder> = Arc::new(RankingEmbedder);
    let private = fleet.service_embedding(AGENT_A, PRIVATE_WRITER, embedder.clone());
    let record_only = fleet.service_embedding(AGENT_A, LifecycleServing::default(), embedder);
    let remember = |request: RememberRequest| {
        let private = &private;
        let scope = scope.clone();
        async move { FleetMemoryService::remember(private, scope, request).await }
    };

    // Seven notes that outrank the current one in both lanes, then retracted.
    let mut retracted = Vec::new();
    for index in 0..7 {
        let recorded = remember(RememberRequest::new(
            RememberAction::Record,
            Some(fleet.key(&format!("a/note-{index}"))),
            Map::from_iter([
                ("kind".into(), json!("note")),
                (
                    "text".into(),
                    json!(format!(
                        "zebrafinch zebrafinch zebrafinch migration note {index}"
                    )),
                ),
            ]),
        ))
        .await
        .unwrap();
        let claim_id = recorded.data["claim"]["id"].as_i64().unwrap();
        remember(retract_request(
            fleet.key(&format!("a/retract-{index}")),
            claim_id,
            1,
        ))
        .await
        .unwrap();
        retracted.push(claim_id);
    }
    let current = remember(RememberRequest::new(
        RememberAction::Record,
        Some(fleet.key("a/current")),
        Map::from_iter([
            ("kind".into(), json!("note")),
            ("text".into(), json!("zebrafinch migration note, trailing")),
        ]),
    ))
    .await
    .unwrap();
    let current_chunk = format!("claim:{}", current.data["claim"]["id"]);
    let query = json!({ "query": "zebrafinch migration note", "kind": "chunk", "limit": 3 });

    // Retracted notes fill the whole first retrieval window; the page is
    // refilled from a larger one instead of coming back empty.
    let page = recall(&private, &scope, RecallAction::Search, query.clone())
        .await
        .unwrap();
    assert_eq!(hit_ids(&page), std::slice::from_ref(&current_chunk));
    assert_eq!(
        page.diagnostics["retrieval"]["lifecycle_hidden_claim_ids"],
        json!(retracted)
    );
    assert!(page.warnings.is_empty(), "{:?}", page.warnings);

    // The record-only surface is unfiltered: the same query's top three are
    // exactly the retracted notes that the private page skipped.
    let publication = recall(&record_only, &scope, RecallAction::Search, query)
        .await
        .unwrap();
    assert_eq!(hit_ids(&publication).len(), 3);
    assert!(!hit_ids(&publication).contains(&current_chunk));

    fleet.cleanup().await;
}

/// The runtime writer's exact table grants from
/// `deploy/cockroach/runtime-role-grants.sql`, with no lifecycle additions.
const RUNTIME_GRANTS: &[(&str, &[&str])] = &[
    (
        "SELECT",
        &[
            "_sqlx_migrations",
            "memory_corpus_models",
            "memory_chunks",
            "memory_chunk_history",
            "memory_claims",
            "memory_claim_embeddings",
            "memory_claim_support",
            "memory_conflict_members",
            "memory_conflicts",
            "memory_claim_links",
            "memory_mutation_receipts",
            "memory_evidence_events",
            "memory_evidence_quarantine",
            "memory_content_objects",
            "memory_evidence_shard_heads",
            "memory_relation_projection_v1",
            "memory_relation_projection_watermarks_v1",
            "memory_writer_authority_v1",
        ],
    ),
    (
        "INSERT",
        &[
            "memory_corpus_models",
            "memory_chunks",
            "memory_claims",
            "memory_claim_embeddings",
            "memory_claim_support",
            "memory_claim_events",
            "memory_conflict_members",
            "memory_conflicts",
            "memory_mutation_receipts",
            "memory_events",
            "memory_evidence_events",
            "memory_evidence_quarantine",
            "memory_content_objects",
            "memory_evidence_shard_heads",
            "memory_relation_projection_v1",
            "memory_relation_projection_watermarks_v1",
        ],
    ),
    (
        "UPDATE",
        &[
            "memory_chunks",
            "memory_claims",
            "memory_conflicts",
            "memory_mutation_receipts",
            "memory_evidence_shard_heads",
            "memory_relation_projection_v1",
            "memory_relation_projection_watermarks_v1",
        ],
    ),
    ("DELETE", &["memory_chunk_history"]),
];
const RUNTIME_SEQUENCES: &[&str] = &[
    "memory_claim_id_seq",
    "memory_claim_support_id_seq",
    "memory_conflict_id_seq",
];

fn qualified(tables: &[&str]) -> String {
    tables
        .iter()
        .map(|table| format!("public.{table}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Rewrite the disposable root URL for the password-authenticated probe role:
/// same host, port, database, and CA, but no client certificate.
fn probe_database_url(database_url: &str, role: &str, password: &str) -> String {
    let mut url = url::Url::parse(database_url).expect("test URL is a URL");
    let preserved: Vec<(String, String)> = url
        .query_pairs()
        .filter(|(key, _)| key == "sslmode" || key == "sslrootcert")
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    url.set_username(role).expect("username");
    url.set_password(Some(password)).expect("password");
    url.query_pairs_mut().clear().extend_pairs(preserved);
    url.to_string()
}

async fn run_probe_role(fleet: &Fleet, probe_url: &str, role: &str) -> Result<(), String> {
    for (privilege, tables) in RUNTIME_GRANTS {
        sqlx::query(&format!(
            "GRANT {privilege} ON TABLE {} TO {role}",
            qualified(tables)
        ))
        .execute(fleet.pool())
        .await
        .map_err(|error| format!("grant {privilege}: {error}"))?;
    }
    for statement in [
        format!("GRANT CONNECT ON DATABASE fleet_recall TO {role}"),
        format!("GRANT USAGE ON SCHEMA public TO {role}"),
        format!(
            "GRANT USAGE ON SEQUENCE {} TO {role}",
            qualified(RUNTIME_SEQUENCES)
        ),
    ] {
        sqlx::query(&statement)
            .execute(fleet.pool())
            .await
            .map_err(|error| format!("{statement}: {error}"))?;
    }

    let probe_pool = PgPoolOptions::new()
        .max_connections(4)
        .acquire_timeout(Duration::from_secs(10))
        .connect(probe_url)
        .await
        .map_err(|error| format!("probe role could not connect: {error}"))?;
    let result = async {
        let ledger = |agent| fleet.ledger_on(&probe_pool, agent, RetryPolicy::default());
        let x = ledger(AGENT_A)
            .record_claim(
                &fleet.scope(AGENT_A),
                &decision("grant-probe", &json!("x"), 1),
                &fleet.key("probe/x"),
            )
            .await
            .map_err(|error| format!("probe record x: {error}"))?;
        let y = ledger(AGENT_B)
            .record_claim(
                &fleet.scope(AGENT_B),
                &decision("grant-probe", &json!("y"), 1),
                &fleet.key("probe/y"),
            )
            .await
            .map_err(|error| format!("probe record y: {error}"))?;
        let states = ledger(AGENT_A)
            .claim_states(&fleet.scope(AGENT_A), &[x.claim.id])
            .await
            .map_err(|error| format!("probe claim states: {error}"))?;
        if states != [(x.claim.id, ClaimState::Disputed)] {
            return Err(format!("probe read the wrong claim state: {states:?}"));
        }
        let current = ledger(AGENT_A)
            .get_claim(&fleet.scope(AGENT_A), x.claim.id)
            .await
            .map_err(|error| format!("probe claim read: {error}"))?
            .ok_or("probe could not read its claim")?;
        let retracted = ledger(AGENT_A)
            .retract_claim(
                &fleet.scope(AGENT_A),
                ClaimTarget {
                    claim_id: x.claim.id,
                    expected_revision: current.revision,
                },
                Some("probe retract"),
                &fleet.key("probe/retract"),
            )
            .await
            .map_err(|error| format!("probe retract: {error}"))?;
        if retracted.claims_restored != [y.claim.id] {
            return Err(format!("probe retract did not restore: {retracted:?}"));
        }
        let conflicts = ledger(AGENT_A)
            .get_conflicts(&fleet.scope(AGENT_A), &retracted.conflicts_resolved)
            .await
            .map_err(|error| format!("probe conflict lookup: {error}"))?;
        if conflicts.len() != 1 || conflicts[0].state != "resolved" {
            return Err(format!(
                "probe read the wrong conflict state: {conflicts:?}"
            ));
        }
        Ok(())
    }
    .await;
    probe_pool.close().await;
    result
}

#[tokio::test]
async fn live_runtime_grant_probe_role_can_retract_when_configured() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fleet = Fleet::new(&database_url, "grant-probe").await;
    let role = format!("lifecycle_probe_{}", Uuid::now_v7().simple());
    let password = format!("probe-{}", Uuid::now_v7().simple());
    sqlx::query(&format!(
        "CREATE ROLE {role} WITH LOGIN PASSWORD '{password}'"
    ))
    .execute(fleet.pool())
    .await
    .unwrap();

    let probe = run_probe_role(
        &fleet,
        &probe_database_url(&database_url, &role, &password),
        &role,
    )
    .await;

    let every_table = RUNTIME_GRANTS
        .iter()
        .flat_map(|(_, tables)| tables.iter().copied())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    for statement in [
        format!(
            "REVOKE ALL ON TABLE {} FROM {role}",
            qualified(&every_table)
        ),
        format!(
            "REVOKE ALL ON SEQUENCE {} FROM {role}",
            qualified(RUNTIME_SEQUENCES)
        ),
        format!("REVOKE ALL ON SCHEMA public FROM {role}"),
        format!("REVOKE ALL ON DATABASE fleet_recall FROM {role}"),
        format!("DROP ROLE IF EXISTS {role}"),
    ] {
        sqlx::query(&statement).execute(fleet.pool()).await.unwrap();
    }
    fleet.cleanup().await;
    probe.unwrap();
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RaceOutcome {
    Committed,
    Stale,
}

fn race_outcome(result: ostk_fleet_recall::Result<ClaimMutation>) -> RaceOutcome {
    match result {
        Ok(mutation) => {
            assert_eq!(mutation.claim.state, ClaimState::Retracted);
            RaceOutcome::Committed
        }
        Err(FleetError::LifecycleRefused(refusal))
            if refusal.code == RefusalCode::StaleRevision =>
        {
            RaceOutcome::Stale
        }
        Err(error) => panic!("race produced an unexpected failure: {error}"),
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // two race shapes share one fixture and one invariant check
async fn live_concurrent_retracts_serialize_without_deadlock_when_configured() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fleet = Fleet::new(&database_url, "race").await;
    let second = CockroachStore::connect(
        &database_url,
        fleet.scope(AGENT_B),
        PoolConfig {
            max_connections: 8,
            ..PoolConfig::default()
        },
    )
    .await
    .unwrap();
    // Contention is the point here, so allow more serializable restarts.
    let policy = RetryPolicy {
        max_attempts: 32,
        ..RetryPolicy::default()
    };
    let author_a = fleet.ledger_on(fleet.pool(), AGENT_A, policy);
    let author_b = fleet.ledger_on(second.pool(), AGENT_B, policy);
    let author_c = fleet.ledger_on(second.pool(), AGENT_C, policy);
    let (scope_a, scope_b, scope_c) = (
        fleet.scope(AGENT_A),
        fleet.scope(AGENT_B),
        fleet.scope(AGENT_C),
    );

    for round in 0..50 {
        let subject = format!("race-{round}");
        let x = author_a
            .record_claim(
                &scope_a,
                &decision(&subject, &json!("x"), 1),
                &fleet.key(&format!("{round}/x")),
            )
            .await
            .unwrap();
        let y = author_b
            .record_claim(
                &scope_b,
                &decision(&subject, &json!("y"), 1),
                &fleet.key(&format!("{round}/y")),
            )
            .await
            .unwrap();
        let conflict_id = y.claim.conflict_ids[0];
        let x_revision = fleet.claim(x.claim.id).await.revision;
        let y_revision = y.claim.revision;
        let barrier = Barrier::new(2);
        let retract_x = async {
            barrier.wait().await;
            author_a
                .retract_claim(
                    &scope_a,
                    ClaimTarget {
                        claim_id: x.claim.id,
                        expected_revision: x_revision,
                    },
                    None,
                    &fleet.key(&format!("{round}/retract-x")),
                )
                .await
        };
        if round % 2 == 0 {
            // Both authors retract at once. The first close restores the
            // other claim, so the second author's revision is stale.
            let retract_y = async {
                barrier.wait().await;
                author_b
                    .retract_claim(
                        &scope_b,
                        ClaimTarget {
                            claim_id: y.claim.id,
                            expected_revision: y_revision,
                        },
                        None,
                        &fleet.key(&format!("{round}/retract-y")),
                    )
                    .await
            };
            let (x_result, y_result) = tokio::join!(retract_x, retract_y);
            let outcomes = (race_outcome(x_result), race_outcome(y_result));
            let (winner, loser) = match outcomes {
                (RaceOutcome::Committed, RaceOutcome::Stale) => (x.claim.id, y.claim.id),
                (RaceOutcome::Stale, RaceOutcome::Committed) => (y.claim.id, x.claim.id),
                other => panic!("round {round}: exactly one retract commits, got {other:?}"),
            };
            assert_eq!(fleet.conflict(conflict_id).await.state, "resolved");
            assert_eq!(fleet.claim(winner).await.state, ClaimState::Retracted);
            assert_eq!(fleet.claim(loser).await.state, ClaimState::Active);
        } else {
            // A retract races a record that brings in a third value. Either
            // order leaves y and z in the open conflict and x retracted.
            let record_z = async {
                barrier.wait().await;
                author_c
                    .record_claim(
                        &scope_c,
                        &decision(&subject, &json!("z"), 1),
                        &fleet.key(&format!("{round}/z")),
                    )
                    .await
            };
            let (x_result, z_result) = tokio::join!(retract_x, record_z);
            assert_eq!(race_outcome(x_result), RaceOutcome::Committed);
            let z = z_result.expect("the racing record commits");
            assert_eq!(fleet.conflict(conflict_id).await.state, "open");
            assert_eq!(fleet.claim(y.claim.id).await.state, ClaimState::Disputed);
            assert_eq!(fleet.claim(z.claim.id).await.state, ClaimState::Disputed);
            assert_eq!(fleet.claim(x.claim.id).await.state, ClaimState::Retracted);
        }
    }
    fleet.assert_lifecycle_invariants().await;

    second.pool().close().await;
    fleet.cleanup().await;
}

#[tokio::test]
async fn live_get_conflict_returns_any_state_when_configured() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fleet = Fleet::new(&database_url, "get-conflict").await;
    let ledger = fleet.ledger(AGENT_C);
    let scope = fleet.scope(AGENT_C);
    let x = fleet
        .record(AGENT_A, &decision("lookup", &json!("x"), 1), "a/x")
        .await;
    let y = fleet
        .record(AGENT_B, &decision("lookup", &json!("y"), 1), "b/y")
        .await;
    let conflict_id = y.claim.conflict_ids[0];

    let open = ledger
        .get_conflicts(&scope, &[conflict_id, conflict_id])
        .await
        .unwrap();
    assert_eq!(open.len(), 1, "duplicate ids hydrate once");
    assert_eq!(open[0].state, "open");
    assert_eq!(open[0].member_count, 2);
    assert_eq!(
        open[0]
            .members
            .iter()
            .map(|member| member.id)
            .collect::<Vec<_>>(),
        [x.claim.id, y.claim.id]
    );
    assert_eq!(
        ledger
            .claim_states(&scope, &[y.claim.id, x.claim.id, 9_007_199_254_740_990])
            .await
            .unwrap(),
        [
            (x.claim.id, ClaimState::Disputed),
            (y.claim.id, ClaimState::Disputed)
        ]
    );

    fleet
        .retract(
            AGENT_A,
            x.claim.id,
            fleet.claim(x.claim.id).await.revision,
            "a/retract",
        )
        .await
        .unwrap();
    let resolved = ledger.get_conflicts(&scope, &[conflict_id]).await.unwrap();
    assert_eq!(resolved[0].state, "resolved");
    assert_eq!(resolved[0].members[0].state, ClaimState::Retracted);
    assert_eq!(resolved[0].members[1].state, ClaimState::Active);

    assert!(
        ledger
            .get_conflicts(&scope, &[9_007_199_254_740_990])
            .await
            .unwrap()
            .is_empty()
    );
    let elsewhere = FleetScope::new(
        fleet.tenant,
        format!("{}-elsewhere", fleet.project),
        AGENT_C,
        None,
        PrivacyTier::T1Project,
    )
    .unwrap();
    let elsewhere_ledger = CockroachClaimLedger::new(
        fleet.pool().clone(),
        elsewhere.clone(),
        Arc::new(UnitEmbedder),
        RetryPolicy::default(),
    )
    .unwrap();
    assert!(
        elsewhere_ledger
            .get_conflicts(&elsewhere, &[conflict_id])
            .await
            .unwrap()
            .is_empty(),
        "another project cannot read this conflict"
    );
    let too_many = (1..=101).collect::<Vec<i64>>();
    assert!(ledger.get_conflicts(&scope, &too_many).await.is_err());
    assert!(ledger.claim_states(&scope, &too_many).await.is_err());

    fleet.cleanup().await;
}
