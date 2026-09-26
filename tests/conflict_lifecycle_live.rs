//! Connected proof for the serving claim and conflict lifecycle (ADR 0004):
//! owner `retract` and `supersede`, detector-verified conflict close with
//! member restore, conflict lookup by id, private search hiding retired claim
//! chunks, and (with the migration-29 lifecycle log) `acknowledge`,
//! concession `resolve`, logged closes, the lifecycle overlay, and history,
//! and (with adjudication enabled) `dismiss`, `waive`, and dismissed-pair
//! exclusion.
//!
//! Set `FLEET_RECALL_TEST_DATABASE_URL` to a disposable `CockroachDB` 26.2
//! database; every test is inert otherwise. Each test migrates, works in a
//! fresh tenant and project, and deletes every row it wrote.

use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::time::Duration;

use futures::FutureExt as _;

use ostk_fleet_recall::application::LifecycleServing;
use ostk_fleet_recall::ledger::{
    ClaimInput, ClaimKind, ClaimLedger, ClaimMutation, ClaimState, ClaimTarget,
    CockroachClaimLedger, CockroachConflictReconciliationRepository, ConflictMutation,
    ConflictTarget, DismissalTerms, LifecycleRefusal, MAX_CONFLICT_LIFECYCLE_EVENTS,
    MAX_CONFLICT_MEMBER_COUNT, RefusalCode, SupersededClaim, WaiverTerms,
};
use ostk_fleet_recall::mcp::McpServer;
use ostk_fleet_recall::memory_contracts::discrepancy::{DismissalReasonKindV1, WaiverReasonKindV1};
use ostk_fleet_recall::service::{
    FleetMemoryService, RecallAction, RecallRequest, RecallResult, RememberAction, RememberRequest,
    RememberResult, RememberSurface, ServiceError,
};
use ostk_fleet_recall::store::cockroach::{
    CONFLICT_LIFECYCLE_SCHEMA_VERSION, CockroachStore, ConflictLifecycleCapability,
    EMBEDDING_DIMENSION, PUBLICATION_READ_TABLES, PoolConfig, RetryPolicy,
    probe_conflict_lifecycle,
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
const AGENT_D: &str = "agent-d";

/// What the private writer serves unless `FLEET_RECALL_REMEMBER_LIFECYCLE=disabled`,
/// when its startup probe finds no conflict lifecycle log (a schema before
/// migration 29, or grants applied before it).
const PRIVATE_WRITER: LifecycleServing = LifecycleServing {
    surface: RememberSurface {
        claim_lifecycle: true,
        conflict_lifecycle: false,
        adjudication: false,
        assert: false,
        capture: false,
        item_support: false,
    },
    hide_non_current_claim_chunks: true,
    lifecycle_overlay: false,
};

/// What the private writer serves once its startup probe finds the
/// migration-29 lifecycle log and its grants.
const FULL_WRITER: LifecycleServing = LifecycleServing {
    surface: RememberSurface {
        claim_lifecycle: true,
        conflict_lifecycle: true,
        adjudication: false,
        assert: false,
        capture: false,
        item_support: false,
    },
    hide_non_current_claim_chunks: true,
    lifecycle_overlay: true,
};

/// The fully probed private writer of a deployment that also enables
/// adjudication (`FLEET_RECALL_CONFLICT_ADJUDICATION=enabled`).
const ADJUDICATING_WRITER: LifecycleServing = LifecycleServing {
    surface: RememberSurface {
        claim_lifecycle: true,
        conflict_lifecycle: true,
        adjudication: true,
        assert: false,
        capture: false,
        item_support: false,
    },
    hide_non_current_claim_chunks: true,
    lifecycle_overlay: true,
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

/// Embeds every text at the query direction except one containing
/// `zeppelin`, which it embeds as the zero vector, as model2vec does a text
/// made only of tokens its vocabulary lacks.
struct UnknownWordEmbedder;

impl ChunkEmbedder for UnknownWordEmbedder {
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
                if !text.contains("zeppelin") {
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
    /// The disposable database's root role may use the lifecycle log.
    conflict_lifecycle: ConflictLifecycleCapability,
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
        let capabilities = store.capabilities().await.expect("capabilities");
        let conflict_lifecycle = probe_conflict_lifecycle(store.pool(), &capabilities)
            .await
            .expect("the capability probe runs")
            .expect("a migrated database's root role may use the lifecycle log");
        Self {
            store,
            tenant,
            project,
            conflict_lifecycle,
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

    /// `agent`'s ledger holding the conflict lifecycle capability.
    fn conflict_ledger(&self, agent: &str) -> CockroachClaimLedger {
        self.ledger(agent)
            .with_conflict_lifecycle(self.conflict_lifecycle)
    }

    /// The memory service `agent`'s writer composes, serving `lifecycle`.
    fn service(&self, agent: &str, lifecycle: LifecycleServing) -> CockroachMemoryService {
        self.service_embedding(agent, lifecycle, Arc::new(UnitEmbedder))
    }

    /// The fully probed private writer: conflict lifecycle and overlay on.
    fn full_service(&self, agent: &str) -> CockroachMemoryService {
        CockroachMemoryService::new(
            self.scope(agent),
            Arc::new(self.store.clone()),
            Arc::new(self.conflict_ledger(agent)),
            Arc::new(UnitEmbedder),
        )
        .expect("memory service")
        .with_lifecycle(FULL_WRITER)
    }

    async fn acknowledge(
        &self,
        agent: &str,
        conflict_id: i64,
        expected_revision: i64,
        key: &str,
    ) -> ostk_fleet_recall::Result<ConflictMutation> {
        self.conflict_ledger(agent)
            .acknowledge_conflict(
                &self.scope(agent),
                ConflictTarget {
                    conflict_id,
                    expected_revision,
                    expected_member_count: None,
                },
                Some(&format!("{agent} is looking")),
                &self.key(key),
            )
            .await
    }

    async fn resolve(
        &self,
        agent: &str,
        conflict: (i64, i64, i64),
        retract_claim_ids: &[i64],
        key: &str,
    ) -> ostk_fleet_recall::Result<ConflictMutation> {
        let (conflict_id, expected_revision, expected_member_count) = conflict;
        self.conflict_ledger(agent)
            .resolve_conflict(
                &self.scope(agent),
                ConflictTarget {
                    conflict_id,
                    expected_revision,
                    expected_member_count: Some(expected_member_count),
                },
                retract_claim_ids,
                Some("conceding"),
                &self.key(key),
            )
            .await
    }

    /// `(id, revision, member_count)` of a conflict as a caller reads it.
    async fn conflict_view(&self, conflict_id: i64) -> (i64, i64, i64) {
        let conflict = self.conflict(conflict_id).await;
        (
            conflict.id,
            conflict.revision,
            i64::try_from(conflict.member_count).unwrap(),
        )
    }

    /// The conflict's lifecycle log, oldest first.
    async fn lifecycle_log(&self, conflict_id: i64) -> Vec<LoggedEvent> {
        sqlx::query_as(
            "SELECT event_seq, event_kind, episode_revision, result_revision, actor_kind, \
                    actor, operation, idempotency_key, payload \
             FROM memory_conflict_lifecycle_events_v1 \
             WHERE tenant_id = $1 AND project = $2 AND conflict_id = $3 ORDER BY event_seq",
        )
        .bind(self.tenant)
        .bind(&self.project)
        .bind(conflict_id)
        .fetch_all(self.pool())
        .await
        .unwrap()
    }

    async fn tenant_lifecycle_rows(&self) -> i64 {
        sqlx::query_scalar(
            "SELECT count(*)::INT8 FROM memory_conflict_lifecycle_events_v1 WHERE tenant_id = $1",
        )
        .bind(self.tenant)
        .fetch_one(self.pool())
        .await
        .unwrap()
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

    async fn supersede(
        &self,
        agent: &str,
        claim_id: i64,
        expected_revision: i64,
        successor: &ClaimInput,
        key: &str,
    ) -> ostk_fleet_recall::Result<ClaimMutation> {
        self.ledger(agent)
            .supersede_claim(
                &self.scope(agent),
                ClaimTarget {
                    claim_id,
                    expected_revision,
                },
                None,
                successor,
                &self.key(key),
            )
            .await
    }

    /// Every claim row in the tenant, so a refusal can prove it wrote none.
    async fn tenant_claim_count(&self) -> i64 {
        sqlx::query_scalar("SELECT count(*)::INT8 FROM memory_claims WHERE tenant_id = $1")
            .bind(self.tenant)
            .fetch_one(self.pool())
            .await
            .unwrap()
    }

    async fn superseded_by(&self, claim_id: i64) -> Option<i64> {
        sqlx::query_scalar(
            "SELECT superseded_by FROM memory_claims \
             WHERE tenant_id = $1 AND project = $2 AND id = $3",
        )
        .bind(self.tenant)
        .bind(&self.project)
        .bind(claim_id)
        .fetch_one(self.pool())
        .await
        .unwrap()
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
    #[allow(clippy::too_many_lines)] // one SQL check per invariant
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

        // A superseded claim, and only a superseded claim, names its
        // successor, which its author wrote on the same kind, key, and
        // detector eligibility.
        let broken_links: Vec<i64> = sqlx::query_scalar(
            "SELECT p.id FROM memory_claims AS p \
             LEFT JOIN memory_claims AS s \
               ON s.tenant_id = p.tenant_id AND s.project = p.project AND s.id = p.superseded_by \
             WHERE p.tenant_id = $1 AND p.project = $2 \
               AND ((p.state = 'superseded') <> (p.superseded_by IS NOT NULL) \
                    OR (p.superseded_by IS NOT NULL AND (s.id IS NULL OR s.id <= p.id \
                        OR s.kind <> p.kind \
                        OR s.claim_key IS DISTINCT FROM p.claim_key \
                        OR s.conflict_eligible <> p.conflict_eligible \
                        OR s.actor IS DISTINCT FROM p.actor)))",
        )
        .bind(self.tenant)
        .bind(&self.project)
        .fetch_all(self.pool())
        .await
        .unwrap();
        assert!(
            broken_links.is_empty(),
            "superseded claims without a same-shape successor: {broken_links:?}"
        );

        // The lifecycle log numbers each conflict's events from 1 without
        // gaps, logs at most one close per resulting revision, never runs
        // ahead of the conflict row, and every event belongs to a committed
        // receipt.
        let broken_logs: Vec<String> = sqlx::query_scalar(
            "SELECT 'sequence ' || conflict_id::STRING \
             FROM memory_conflict_lifecycle_events_v1 \
             WHERE tenant_id = $1 AND project = $2 \
             GROUP BY conflict_id HAVING min(event_seq) <> 1 OR max(event_seq) <> count(*) \
             UNION ALL \
             SELECT 'double close ' || conflict_id::STRING \
             FROM memory_conflict_lifecycle_events_v1 \
             WHERE tenant_id = $1 AND project = $2 AND event_kind IN ('resolved', 'dismissed') \
             GROUP BY conflict_id, result_revision HAVING count(*) > 1 \
             UNION ALL \
             SELECT 'ahead of row ' || e.conflict_id::STRING \
             FROM memory_conflict_lifecycle_events_v1 AS e \
             JOIN memory_conflicts AS k \
               ON k.tenant_id = e.tenant_id AND k.project = e.project AND k.id = e.conflict_id \
             WHERE e.tenant_id = $1 AND e.project = $2 AND e.result_revision > k.revision \
             UNION ALL \
             SELECT 'unreceipted ' || e.idempotency_key \
             FROM memory_conflict_lifecycle_events_v1 AS e \
             WHERE e.tenant_id = $1 AND e.project = $2 AND NOT EXISTS (\
               SELECT 1 FROM memory_mutation_receipts AS r \
               WHERE r.tenant_id = e.tenant_id AND r.idempotency_key = e.idempotency_key \
                 AND r.response IS NOT NULL)",
        )
        .bind(self.tenant)
        .bind(&self.project)
        .fetch_all(self.pool())
        .await
        .unwrap();
        assert!(
            broken_logs.is_empty(),
            "lifecycle log violations: {broken_logs:?}"
        );
    }

    async fn cleanup(self) {
        for statement in [
            // No foreign key cascades into the lifecycle log.
            "DELETE FROM memory_conflict_lifecycle_events_v1 WHERE tenant_id = $1",
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
                 (SELECT count(*) FROM memory_corpus_models WHERE tenant_id = $1) + \
                 (SELECT count(*) FROM memory_conflict_lifecycle_events_v1 WHERE tenant_id = $1)",
        )
        .bind(self.tenant)
        .fetch_one(self.pool())
        .await
        .unwrap();
        assert_eq!(residue, 0, "lifecycle test leaked tenant rows");
    }
}

/// One lifecycle log row: `(seq, kind, episode_revision, result_revision,
/// actor_kind, actor, operation, idempotency_key, payload)`.
type LoggedEvent = (i64, String, i64, i64, String, String, String, String, Value);

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

fn refusal<T: std::fmt::Debug>(result: ostk_fleet_recall::Result<T>) -> LifecycleRefusal {
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

/// A query is words, whatever punctuation `CockroachDB`'s `plainto_tsquery`
/// would parse as syntax, and a query the model cannot embed is answered by
/// the lanes that can run, with a warning, rather than refused as internal.
#[tokio::test]
async fn live_search_answers_query_syntax_and_unembeddable_queries_when_configured() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fleet = Fleet::new(&database_url, "query-text").await;
    let scope = fleet.scope(AGENT_A);
    let service = fleet.service_embedding(AGENT_A, PRIVATE_WRITER, Arc::new(UnknownWordEmbedder));
    let noted = fleet
        .record(
            AGENT_A,
            &note("zeppelin hangar(one) inspection note"),
            "a/note",
        )
        .await;
    let chunk = format!("claim:{}", noted.claim.id);
    let warning_codes = |result: &RecallResult| {
        result
            .warnings
            .iter()
            .map(|warning| warning["code"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>()
    };

    // Operators are punctuation; the embedded query runs both lanes.
    for query in [
        "hangar(one) inspection",
        "hangar & !inspection",
        "what is it",
    ] {
        let found = recall(
            &service,
            &scope,
            RecallAction::Search,
            json!({ "query": query, "kind": "chunk", "limit": 5 }),
        )
        .await
        .unwrap_or_else(|error| panic!("{query:?}: {error:?}"));
        assert!(hit_ids(&found).contains(&chunk), "{query:?}");
        assert_eq!(
            found.diagnostics["retrieval"]["lanes"],
            json!(["lexical", "dense"])
        );
    }

    // A query with no embedding still finds the note lexically, and says the
    // dense lane did not run.
    let lexical = recall(
        &service,
        &scope,
        RecallAction::Search,
        json!({ "query": "zeppelin (hangar)", "kind": "chunk", "limit": 5 }),
    )
    .await
    .unwrap();
    assert!(hit_ids(&lexical).contains(&chunk));
    assert_eq!(
        lexical.diagnostics["retrieval"]["lanes"],
        json!(["lexical"])
    );
    assert_eq!(warning_codes(&lexical), ["query_not_embedded"]);

    // Claim search is dense only, so the same query matches no claim.
    let claims = recall(
        &service,
        &scope,
        RecallAction::Search,
        json!({ "query": "zeppelin", "kind": "claim", "limit": 5 }),
    )
    .await
    .unwrap();
    assert_eq!(claims.data["hits"], json!([]));
    assert_eq!(warning_codes(&claims), ["query_not_embedded"]);
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

/// The runtime writer's table grants from
/// `deploy/cockroach/runtime-role-grants.sql` on the legacy corpus and claim
/// tables and the Stage-4 evidence plane, without the lifecycle log. The
/// policy's Stage-5 and Stage-6 rows and its UPDATE on
/// `memory_content_objects` are left out: no conflict lifecycle path needs
/// them.
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

#[allow(clippy::too_many_lines)] // grants, then every lifecycle write under exactly them
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
        // Supersede writes the successor and links the predecessor to it
        // through the self-referencing foreign key, with the same grants.
        let restored = ledger(AGENT_B)
            .get_claim(&fleet.scope(AGENT_B), y.claim.id)
            .await
            .map_err(|error| format!("probe claim read: {error}"))?
            .ok_or("probe could not read the restored claim")?;
        let superseded = ledger(AGENT_B)
            .supersede_claim(
                &fleet.scope(AGENT_B),
                ClaimTarget {
                    claim_id: y.claim.id,
                    expected_revision: restored.revision,
                },
                Some("probe supersede"),
                &decision("grant-probe", &json!("z"), 1),
                &fleet.key("probe/supersede"),
            )
            .await
            .map_err(|error| format!("probe supersede: {error}"))?;
        if superseded
            .superseded
            .map(|predecessor| predecessor.superseded_by)
            != Some(superseded.claim.id)
        {
            return Err(format!("probe supersede did not link: {superseded:?}"));
        }
        Ok(())
    }
    .await;
    probe_pool.close().await;
    result
}

#[tokio::test]
async fn live_runtime_grant_probe_role_can_retract_and_supersede_when_configured() {
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

/// `remember(supersede)` arguments: the successor's claim fields beside the
/// predecessor target, as an MCP client sends them.
fn supersede_request(
    key: String,
    claim_id: i64,
    expected_revision: i64,
    successor: &ClaimInput,
) -> RememberRequest {
    let mut arguments = serde_json::to_value(successor)
        .unwrap()
        .as_object()
        .cloned()
        .unwrap();
    arguments.insert("claim_id".into(), json!(claim_id));
    arguments.insert("expected_revision".into(), json!(expected_revision));
    RememberRequest::new(RememberAction::Supersede, Some(key), arguments)
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // one concession proves rows, events, replay, and search
async fn live_supersede_to_compatible_value_resolves_when_configured() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fleet = Fleet::new(&database_url, "supersede-close").await;
    let scope = fleet.scope(AGENT_A);
    let private = fleet.service(AGENT_A, PRIVATE_WRITER);
    let x = fleet
        .record(AGENT_A, &decision("supersede-close", &json!("x"), 1), "a/x")
        .await;
    let y = fleet
        .record(AGENT_B, &decision("supersede-close", &json!("y"), 1), "b/y")
        .await;
    let conflict_id = y.claim.conflict_ids[0];
    let before = fleet.conflict(conflict_id).await;
    let x_before = fleet.claim(x.claim.id).await;
    assert_eq!(x_before.state, ClaimState::Disputed);

    // A concedes: its successor states y, on the same key spelled differently.
    let mut successor = decision("  Supersede   Close ", &json!("y"), 1);
    successor.text = "lifecycle fixture concedes y after review".into();
    let request = || {
        supersede_request(
            fleet.key("a/supersede"),
            x.claim.id,
            x_before.revision,
            &successor,
        )
    };
    let committed = FleetMemoryService::remember(&private, scope.clone(), request())
        .await
        .expect("an owner supersede commits");
    let mutation: ClaimMutation = serde_json::from_value(committed.data.clone()).unwrap();
    assert_eq!(mutation.operation, "supersede");
    assert!(!mutation.idempotent_replay);
    let successor_id = mutation.claim.id;
    assert!(successor_id > y.claim.id);
    assert_eq!(mutation.claim.state, ClaimState::Active);
    assert_eq!(mutation.claim.revision, 1);
    assert_eq!(mutation.claim.claim_key, x.claim.claim_key);
    assert_eq!(mutation.claim.actor.as_deref(), Some(AGENT_A));
    assert_eq!(mutation.claim.value, Some(json!("y")));
    assert!(
        mutation.claim.conflict_ids.is_empty(),
        "a compatible successor never joins the conflict"
    );
    assert_eq!(
        mutation.superseded,
        Some(SupersededClaim {
            id: x.claim.id,
            state: ClaimState::Superseded,
            revision: x_before.revision + 1,
            superseded_by: successor_id,
        })
    );
    assert!(mutation.conflicts_opened.is_empty());
    assert_eq!(mutation.conflicts_resolved, [conflict_id]);
    assert_eq!(mutation.claims_restored, [y.claim.id]);
    let reevaluation = mutation.reevaluation.as_ref().expect("re-evaluated");
    assert_eq!(reevaluation.outcome, "closed");
    assert_eq!(reevaluation.conflict_revision, before.revision + 1);
    assert_eq!(reevaluation.remaining_pair_count, 0);
    assert_eq!(committed.conflicts.len(), 1);
    assert_eq!(committed.conflicts[0]["state"], "resolved");
    assert_eq!(committed.conflict_coverage.status, "complete");

    let predecessor = fleet.claim(x.claim.id).await;
    assert_eq!(predecessor.state, ClaimState::Superseded);
    assert_eq!(predecessor.revision, x_before.revision + 1);
    assert_eq!(predecessor.superseded_by, Some(successor_id));
    let retire = fleet
        .transitions(x.claim.id)
        .await
        .pop()
        .expect("retire event");
    assert_eq!(
        (retire.0.as_str(), retire.1.as_str(), retire.2.as_str()),
        ("superseded_by_author", "disputed", "superseded")
    );
    assert_eq!(retire.3["successor_claim_id"], successor_id);
    assert_eq!(retire.3["revision_before"], x_before.revision);
    let after = fleet.conflict(conflict_id).await;
    assert_eq!(after.state, "resolved");
    assert_eq!(after.revision, before.revision + 1);
    assert_eq!(
        after.resolution_kind.as_deref(),
        Some("no_current_incompatibility")
    );
    assert_eq!(
        after.resolution_reason,
        Some(format!(
            "no lifecycle-current incompatible pair remains after supersede of claim {} by claim {successor_id}",
            x.claim.id
        ))
    );
    assert_eq!(after.member_count, 2);
    let peer = fleet.claim(y.claim.id).await;
    assert_eq!(peer.state, ClaimState::Active);
    let restore = fleet.transitions(y.claim.id).await.pop().unwrap();
    assert_eq!(restore.0, "conflict_resolved");
    assert_eq!(restore.3["idempotency_key"], fleet.key("a/supersede"));

    // One keyed event per call; the successor's own audit event is unkeyed.
    let keyed = fleet.keyed_events("a/supersede").await;
    assert_eq!(keyed.len(), 1);
    assert_eq!(keyed[0].0, "claim_superseded");
    assert_eq!(keyed[0].1["successor_claim_id"], successor_id);
    assert_eq!(keyed[0].1["conflict_reevaluation"]["outcome"], "closed");
    let recorded: Vec<(Option<String>, Value)> = sqlx::query_as(
        "SELECT idempotency_key, payload FROM memory_events \
         WHERE tenant_id = $1 AND project = $2 AND event_kind = 'claim_recorded' \
           AND entity_id = $3",
    )
    .bind(fleet.tenant)
    .bind(&fleet.project)
    .bind(successor_id.to_string())
    .fetch_all(fleet.pool())
    .await
    .unwrap();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].0, None);
    assert_eq!(recorded[0].1["supersedes"], x.claim.id);
    assert_eq!(
        recorded[0].1["conflict_detection"]["incompatible_claim_ids"],
        json!([])
    );
    let receipt_claim: Option<i64> = sqlx::query_scalar(
        "SELECT claim_id FROM memory_mutation_receipts \
         WHERE tenant_id = $1 AND idempotency_key = $2 AND operation = 'supersede'",
    )
    .bind(fleet.tenant)
    .bind(fleet.key("a/supersede"))
    .fetch_one(fleet.pool())
    .await
    .unwrap();
    assert_eq!(receipt_claim, Some(successor_id));
    fleet.assert_lifecycle_invariants().await;

    // A later reopen does not change the stored result a retry receives.
    fleet
        .record(AGENT_C, &decision("supersede-close", &json!("z"), 1), "c/z")
        .await;
    let replay = FleetMemoryService::remember(&private, scope.clone(), request())
        .await
        .unwrap();
    assert_eq!(replay.data["idempotent_replay"], true);
    let mut normalized = replay.data.clone();
    normalized["idempotent_replay"] = json!(false);
    assert_eq!(normalized, committed.data);
    assert_eq!(fleet.keyed_events("a/supersede").await.len(), 1);
    // Another successor under the key, or another operation, is a conflict.
    let mut other = successor.clone();
    other.text = "a different successor".into();
    for result in [
        fleet
            .supersede(
                AGENT_A,
                x.claim.id,
                x_before.revision,
                &other,
                "a/supersede",
            )
            .await,
        fleet
            .supersede(AGENT_A, x.claim.id, x_before.revision, &successor, "a/x")
            .await,
        fleet
            .retract(AGENT_A, x.claim.id, x_before.revision, "a/supersede")
            .await,
        fleet
            .ledger(AGENT_A)
            .record_claim(&scope, &successor, &fleet.key("a/supersede"))
            .await,
    ] {
        assert!(
            matches!(result, Err(FleetError::IdempotencyConflict(_))),
            "{result:?}"
        );
    }

    // Reads: the claim names its successor, and private chunk search hides
    // the retired predecessor while the successor's chunk stays visible.
    let got = recall(
        &private,
        &scope,
        RecallAction::Get,
        json!({ "kind": "claim", "id": x.claim.id }),
    )
    .await
    .unwrap();
    assert_eq!(got.data["claim"]["state"], "superseded");
    assert_eq!(got.data["claim"]["superseded_by"], successor_id);
    let page = recall(
        &private,
        &scope,
        RecallAction::Search,
        json!({ "query": "lifecycle fixture", "kind": "chunk", "limit": 10 }),
    )
    .await
    .unwrap();
    assert!(!hit_ids(&page).contains(&format!("claim:{}", x.claim.id)));
    assert!(hit_ids(&page).contains(&format!("claim:{successor_id}")));
    assert!(
        page.diagnostics["retrieval"]["lifecycle_hidden_claim_ids"]
            .as_array()
            .unwrap()
            .contains(&json!(x.claim.id))
    );
    fleet.assert_lifecycle_invariants().await;

    fleet.cleanup().await;
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // join, concede, open, and keyless shapes on one fixture
async fn live_supersede_to_incompatible_value_replaces_member_when_configured() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fleet = Fleet::new(&database_url, "supersede-join").await;
    let x = fleet
        .record(AGENT_A, &decision("supersede-join", &json!("x"), 1), "a/x")
        .await;
    let y = fleet
        .record(AGENT_B, &decision("supersede-join", &json!("y"), 1), "b/y")
        .await;
    let conflict_id = y.claim.conflict_ids[0];
    let open = fleet.conflict(conflict_id).await;

    // A changes its value to z, which still contradicts y: the successor
    // takes the predecessor's place in the same open conflict.
    let replaced = fleet
        .supersede(
            AGENT_A,
            x.claim.id,
            fleet.claim(x.claim.id).await.revision,
            &decision("supersede-join", &json!("z"), 1),
            "a/supersede",
        )
        .await
        .unwrap();
    let successor = replaced.claim.id;
    assert_eq!(replaced.claim.state, ClaimState::Disputed);
    assert_eq!(replaced.claim.conflict_ids, [conflict_id]);
    assert!(
        replaced.conflicts_opened.is_empty(),
        "an open conflict is joined, not reopened"
    );
    assert!(replaced.conflicts_resolved.is_empty());
    assert!(replaced.claims_restored.is_empty());
    let reevaluation = replaced.reevaluation.as_ref().unwrap();
    assert_eq!(reevaluation.outcome, "still_open");
    assert_eq!(reevaluation.conflict_revision, open.revision);
    assert_eq!(reevaluation.remaining_pairs, [[y.claim.id, successor]]);
    let joined = fleet.conflict(conflict_id).await;
    assert_eq!(joined.state, "open");
    assert_eq!(joined.revision, open.revision);
    assert_eq!(
        joined
            .members
            .iter()
            .map(|member| (member.id, member.state))
            .collect::<Vec<_>>(),
        [
            (x.claim.id, ClaimState::Superseded),
            (y.claim.id, ClaimState::Disputed),
            (successor, ClaimState::Disputed),
        ]
    );
    fleet.assert_lifecycle_invariants().await;

    // B concedes to z in turn: nothing incompatible is left, so the conflict
    // closes and A's disputed successor is restored.
    let conceded = fleet
        .supersede(
            AGENT_B,
            y.claim.id,
            fleet.claim(y.claim.id).await.revision,
            &decision("supersede-join", &json!("z"), 1),
            "b/supersede",
        )
        .await
        .unwrap();
    assert_eq!(conceded.claim.state, ClaimState::Active);
    assert_eq!(conceded.conflicts_resolved, [conflict_id]);
    assert_eq!(conceded.claims_restored, [successor]);
    assert_eq!(fleet.conflict(conflict_id).await.state, "resolved");
    assert_eq!(fleet.claim(successor).await.state, ClaimState::Active);
    fleet.assert_lifecycle_invariants().await;

    // A supersede can also open a conflict: w1 and w2 agree until A's
    // successor changes the value.
    let w1 = fleet
        .record(AGENT_A, &decision("supersede-open", &json!("w"), 1), "a/w")
        .await;
    let w2 = fleet
        .record(AGENT_B, &decision("supersede-open", &json!("w"), 1), "b/w")
        .await;
    assert!(w2.claim.conflict_ids.is_empty());
    let opened = fleet
        .supersede(
            AGENT_A,
            w1.claim.id,
            w1.claim.revision,
            &decision("supersede-open", &json!("v"), 1),
            "a/supersede-open",
        )
        .await
        .unwrap();
    assert_eq!(opened.conflicts_opened.len(), 1);
    let opened_id = opened.conflicts_opened[0];
    assert_eq!(opened.claim.conflict_ids, [opened_id]);
    assert_eq!(opened.reevaluation.as_ref().unwrap().outcome, "still_open");
    assert_eq!(fleet.claim(w2.claim.id).await.state, ClaimState::Disputed);
    assert_eq!(
        fleet
            .conflict(opened_id)
            .await
            .members
            .iter()
            .map(|member| member.id)
            .collect::<Vec<_>>(),
        [w2.claim.id, opened.claim.id],
        "the superseded predecessor never joins"
    );
    fleet.assert_lifecycle_invariants().await;

    // A keyless note has no lineage to re-evaluate.
    let draft = fleet
        .record(AGENT_A, &note("first draft of the failover runbook"), "a/n")
        .await;
    let revised = fleet
        .supersede(
            AGENT_A,
            draft.claim.id,
            draft.claim.revision,
            &note("second draft of the failover runbook"),
            "a/supersede-note",
        )
        .await
        .unwrap();
    assert_eq!(revised.claim.kind, ClaimKind::Note);
    assert_eq!(revised.claim.state, ClaimState::Active);
    assert!(revised.reevaluation.is_none());
    assert!(revised.conflicts_opened.is_empty() && revised.conflicts_resolved.is_empty());
    assert_eq!(
        fleet.superseded_by(draft.claim.id).await,
        Some(revised.claim.id)
    );
    fleet.assert_lifecycle_invariants().await;

    fleet.cleanup().await;
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // every supersede refusal with its no-residue proof
async fn live_supersede_refusals_when_configured() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fleet = Fleet::new(&database_url, "supersede-refusals").await;
    let subject = "supersede-refusals";
    let x = fleet
        .record(AGENT_A, &decision(subject, &json!("x"), 1), "a/x")
        .await;
    fleet
        .record(AGENT_B, &decision(subject, &json!("y"), 1), "b/y")
        .await;
    let x_disputed = fleet.claim(x.claim.id).await;
    let valid = decision(subject, &json!("y"), 1);
    let mut fact = valid.clone();
    fact.kind = ClaimKind::Fact;
    let mut valueless = valid.clone();
    valueless.value = None;

    let cases = [
        (
            AGENT_B,
            x.claim.id,
            x_disputed.revision,
            valid.clone(),
            "b/not-owner",
            RefusalCode::NotOwner,
        ),
        (
            AGENT_A,
            x.claim.id,
            x_disputed.revision - 1,
            valid.clone(),
            "a/stale",
            RefusalCode::StaleRevision,
        ),
        (
            AGENT_A,
            x.claim.id,
            x_disputed.revision,
            fact,
            "a/kind",
            RefusalCode::SuccessorKindMismatch,
        ),
        (
            AGENT_A,
            x.claim.id,
            x_disputed.revision,
            decision("another-key", &json!("y"), 1),
            "a/key",
            RefusalCode::SuccessorKeyMismatch,
        ),
        (
            AGENT_A,
            x.claim.id,
            x_disputed.revision,
            valueless,
            "a/eligibility",
            RefusalCode::SuccessorEligibilityMismatch,
        ),
        (
            AGENT_A,
            9_007_199_254_740_990,
            1,
            valid.clone(),
            "a/none",
            RefusalCode::NotFound,
        ),
    ];
    for (agent, claim_id, revision, successor, key, code) in cases {
        let claims_before = fleet.tenant_claim_count().await;
        let refused = refusal(
            fleet
                .supersede(agent, claim_id, revision, &successor, key)
                .await,
        );
        assert_eq!(refused.code, code, "{key}");
        assert_eq!(
            fleet.tenant_claim_count().await,
            claims_before,
            "{key} wrote a successor"
        );
        fleet.assert_key_unconsumed(key).await;
    }
    let unchanged = fleet.claim(x.claim.id).await;
    assert_eq!(
        (unchanged.state, unchanged.revision, unchanged.superseded_by),
        (x_disputed.state, x_disputed.revision, None)
    );

    // Once superseded, the predecessor is no longer current.
    fleet
        .supersede(
            AGENT_A,
            x.claim.id,
            x_disputed.revision,
            &valid,
            "a/supersede",
        )
        .await
        .expect("the corrected supersede commits");
    let again = refusal(
        fleet
            .supersede(
                AGENT_A,
                x.claim.id,
                x_disputed.revision + 1,
                &valid,
                "a/again",
            )
            .await,
    );
    assert_eq!(again.code, RefusalCode::NotCurrent);
    assert_eq!(again.details["current_state"], "superseded");
    fleet.assert_key_unconsumed("a/again").await;

    // An unreconciled legacy key is refused before anything is written.
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
    let claims_before = fleet.tenant_claim_count().await;
    let legacy = refusal(
        fleet
            .supersede(
                AGENT_A,
                legacy_claim,
                1,
                &decision("legacy-guard", &json!("postgres"), 1),
                "a/legacy",
            )
            .await,
    );
    assert_eq!(legacy.code, RefusalCode::LegacyLineage);
    assert_eq!(fleet.tenant_claim_count().await, claims_before);
    fleet.assert_key_unconsumed("a/legacy").await;

    // Only authored operator assertions have an owner who may replace them.
    let derived = fleet
        .raw_claim(
            &fleet.project,
            "derived",
            "note",
            "source_derived",
            Some(AGENT_A),
        )
        .await;
    let mut derived_successor = note("a corrected derived note");
    derived_successor.subject = Some("derived".into());
    derived_successor.predicate = Some("database-choice".into());
    let derived_refusal = refusal(
        fleet
            .supersede(AGENT_A, derived, 1, &derived_successor, "a/derived")
            .await,
    );
    assert_eq!(derived_refusal.code, RefusalCode::NotOperatorAsserted);
    fleet.assert_key_unconsumed("a/derived").await;
    fleet.assert_lifecycle_invariants().await;

    fleet.cleanup().await;
}

#[tokio::test]
async fn live_supersede_replays_on_record_only_writer_when_configured() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fleet = Fleet::new(&database_url, "supersede-surface").await;
    let scope = fleet.scope(AGENT_A);
    let enabled = fleet.service(AGENT_A, PRIVATE_WRITER);
    let disabled = fleet.service(AGENT_A, LifecycleServing::default());
    let x = fleet
        .record(
            AGENT_A,
            &decision("supersede-surface", &json!("x"), 1),
            "a/x",
        )
        .await;
    let successor = decision("supersede-surface", &json!("x2"), 1);
    let request = |key: &str, successor: &ClaimInput| {
        supersede_request(fleet.key(key), x.claim.id, 1, successor)
    };
    let committed =
        FleetMemoryService::remember(&enabled, scope.clone(), request("a/supersede", &successor))
            .await
            .unwrap();

    let replay =
        FleetMemoryService::remember(&disabled, scope.clone(), request("a/supersede", &successor))
            .await
            .expect("a committed supersede replays where supersede is no longer served");
    assert_eq!(replay.data["idempotent_replay"], true);
    let mut normalized = replay.data.clone();
    normalized["idempotent_replay"] = json!(false);
    assert_eq!(normalized, committed.data);

    let mut other = successor.clone();
    other.text = "another successor".into();
    let error =
        FleetMemoryService::remember(&disabled, scope.clone(), request("a/supersede", &other))
            .await
            .unwrap_err();
    assert!(
        matches!(&error, ServiceError::InvalidRequest(message)
            if message.contains("already used for a different mutation")),
        "{error}"
    );
    let unused =
        FleetMemoryService::remember(&disabled, scope, request("a/unused", &successor)).await;
    assert_eq!(refusal_code(unused), "lifecycle_unavailable");
    fleet.assert_key_unconsumed("a/unused").await;
    fleet.assert_lifecycle_invariants().await;

    fleet.cleanup().await;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SupersedeRace {
    Committed(i64),
    Stale,
}

fn supersede_race(result: ostk_fleet_recall::Result<ClaimMutation>) -> SupersedeRace {
    match result {
        Ok(mutation) => {
            assert_eq!(mutation.operation, "supersede");
            SupersedeRace::Committed(mutation.claim.id)
        }
        Err(FleetError::LifecycleRefused(refusal))
            if refusal.code == RefusalCode::StaleRevision =>
        {
            SupersedeRace::Stale
        }
        Err(error) => panic!("race produced an unexpected failure: {error}"),
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // two race shapes share one fixture and one invariant check
async fn live_supersede_vs_concurrent_record_converges_when_configured() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fleet = Fleet::new(&database_url, "supersede-race").await;
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

    for round in 0..40 {
        let subject = format!("supersede-race-{round}");
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
        let barrier = Barrier::new(2);
        // A concedes to y.
        let supersede_x = async {
            barrier.wait().await;
            author_a
                .supersede_claim(
                    &scope_a,
                    ClaimTarget {
                        claim_id: x.claim.id,
                        expected_revision: x_revision,
                    },
                    None,
                    &decision(&subject, &json!("y"), 1),
                    &fleet.key(&format!("{round}/supersede-x")),
                )
                .await
        };
        if round % 2 == 0 {
            // C records a third value at the same moment. Either order ends
            // with z contradicting both y and A's successor.
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
            let (x_result, z_result) = tokio::join!(supersede_x, record_z);
            let SupersedeRace::Committed(successor) = supersede_race(x_result) else {
                panic!("round {round}: the supersede must commit");
            };
            let z = z_result.expect("the racing record commits");
            let conflict = fleet.conflict(conflict_id).await;
            assert_eq!(conflict.state, "open", "round {round}");
            for claim_id in [y.claim.id, successor, z.claim.id] {
                assert_eq!(
                    fleet.claim(claim_id).await.state,
                    ClaimState::Disputed,
                    "round {round}: claim {claim_id}"
                );
            }
            assert_eq!(fleet.claim(x.claim.id).await.state, ClaimState::Superseded);
        } else {
            // B retracts y at the same moment. Each close restores the other
            // author's claim, so exactly one of the two commits.
            let y_revision = y.claim.revision;
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
            let (x_result, y_result) = tokio::join!(supersede_x, retract_y);
            match (supersede_race(x_result), race_outcome(y_result)) {
                (SupersedeRace::Committed(successor), RaceOutcome::Stale) => {
                    assert_eq!(fleet.claim(y.claim.id).await.state, ClaimState::Active);
                    assert_eq!(fleet.claim(successor).await.state, ClaimState::Active);
                    assert_eq!(fleet.claim(x.claim.id).await.state, ClaimState::Superseded);
                }
                (SupersedeRace::Stale, RaceOutcome::Committed) => {
                    assert_eq!(fleet.claim(x.claim.id).await.state, ClaimState::Active);
                    assert_eq!(fleet.claim(y.claim.id).await.state, ClaimState::Retracted);
                }
                other => panic!("round {round}: exactly one mutation commits, got {other:?}"),
            }
            assert_eq!(fleet.conflict(conflict_id).await.state, "resolved");
        }
    }
    fleet.assert_lifecycle_invariants().await;

    second.pool().close().await;
    fleet.cleanup().await;
}

// ---------------------------------------------------------------------------
// Slice 3: the conflict lifecycle log (migration 29), acknowledge, concession
// resolve, logged closes, and the lifecycle overlay and history.
// ---------------------------------------------------------------------------

/// A two-party conflict on `{subject}::database-choice`: A's x against B's y.
async fn two_party(fleet: &Fleet, subject: &str) -> (ClaimMutation, ClaimMutation, i64) {
    let x = fleet
        .record(
            AGENT_A,
            &decision(subject, &json!("x"), 1),
            &format!("{subject}/a/x"),
        )
        .await;
    let y = fleet
        .record(
            AGENT_B,
            &decision(subject, &json!("y"), 1),
            &format!("{subject}/b/y"),
        )
        .await;
    let conflict_id = y.claim.conflict_ids[0];
    (x, y, conflict_id)
}

async fn get_conflict(
    service: &CockroachMemoryService,
    scope: &FleetScope,
    conflict_id: i64,
) -> RecallResult {
    recall(
        service,
        scope,
        RecallAction::Get,
        json!({ "kind": "conflict", "id": conflict_id }),
    )
    .await
    .expect("conflict lookup succeeds")
}

/// Fill `conflict_id`'s lifecycle log with `count` acknowledgements of its
/// episode `revision` by distinct agents, as a long-lived busy conflict
/// accumulates them.
async fn seed_acknowledgements(
    fleet: &Fleet,
    conflict_id: i64,
    revision: i64,
    count: i64,
    rationale: Option<&str>,
) {
    sqlx::query(
        "INSERT INTO memory_conflict_lifecycle_events_v1 (\
             tenant_id, project, conflict_id, event_seq, event_kind, episode_revision, \
             result_revision, from_state, to_state, actor_kind, actor, operation, \
             idempotency_key, member_count, rationale\
         ) SELECT $1, $2, $3, seq, 'acknowledged', $4, $4, 'open', 'open', 'agent', \
                  'seeded-agent-' || seq::STRING, 'conflict_acknowledge', \
                  $5 || '/seeded-ack/' || seq::STRING, 2, $6 \
           FROM generate_series(1, $7::INT8) AS seq",
    )
    .bind(fleet.tenant)
    .bind(&fleet.project)
    .bind(conflict_id)
    .bind(revision)
    .bind(&fleet.project)
    .bind(rationale)
    .bind(count)
    .execute(fleet.pool())
    .await
    .unwrap();
}

/// Add `count` retracted members to `conflict_id` on `claim_key`, as years of
/// supersedes on a hot key leave behind: membership is never deleted.
async fn seed_retired_members(fleet: &Fleet, claim_key: &str, conflict_id: i64, count: i64) {
    let retired: Vec<i64> = sqlx::query_scalar(
        "INSERT INTO memory_claims (\
             tenant_id, project, kind, claim_key, subject, predicate, value, text, \
             polarity, state, origin, actor, conflict_eligible\
         ) SELECT $1, $2, 'decision', $3, 'retired', 'database-choice', \
                  to_jsonb('retired-' || n::STRING), 'retired lifecycle fixture', 1, \
                  'retracted', 'operator_asserted', $4, true \
           FROM generate_series(1, $5::INT8) AS n \
         RETURNING id",
    )
    .bind(fleet.tenant)
    .bind(&fleet.project)
    .bind(claim_key)
    .bind(AGENT_A)
    .bind(count)
    .fetch_all(fleet.pool())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO memory_conflict_members (tenant_id, project, conflict_id, claim_id) \
         SELECT $1, $2, $3, claim_id FROM unnest($4::INT8[]) AS members(claim_id)",
    )
    .bind(fleet.tenant)
    .bind(&fleet.project)
    .bind(conflict_id)
    .bind(&retired)
    .execute(fleet.pool())
    .await
    .unwrap();
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // a full log and a crowded conflict, each closed by its owner
async fn live_log_bounds_never_refuse_a_verified_close_when_configured() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fleet = Fleet::new(&database_url, "log-bounds").await;
    let service = fleet.full_service(AGENT_C);
    let scope = fleet.scope(AGENT_C);

    // A conflict whose log is full: acknowledge, which writes nothing but its
    // event, is refused and leaves the key free.
    let (x, y, full) = two_party(&fleet, "bounds-full").await;
    let revision = fleet.conflict_row(full).await.1;
    seed_acknowledgements(&fleet, full, revision, MAX_CONFLICT_LIFECYCLE_EVENTS, None).await;
    let refused = refusal(
        fleet
            .acknowledge(AGENT_C, full, revision, "c/ack-full")
            .await,
    );
    assert_eq!(refused.code, RefusalCode::BoundExceeded);
    fleet.assert_key_unconsumed("c/ack-full").await;

    // The owner's retract still closes it, as on a writer without the log.
    let retracted = fleet
        .conflict_ledger(AGENT_A)
        .retract_claim(
            &fleet.scope(AGENT_A),
            ClaimTarget {
                claim_id: x.claim.id,
                expected_revision: fleet.claim(x.claim.id).await.revision,
            },
            Some("wrong database"),
            &fleet.key("a/retract-full"),
        )
        .await
        .expect("a full lifecycle log never refuses the owner's retract");
    assert_eq!(retracted.conflicts_resolved, [full]);
    assert_eq!(retracted.claims_restored, [y.claim.id]);
    assert_eq!(
        fleet.conflict_row(full).await,
        ("resolved".to_owned(), revision + 1)
    );
    assert_eq!(fleet.claim_state(y.claim.id).await, "active");
    assert!(
        fleet
            .lifecycle_log(full)
            .await
            .iter()
            .all(|event| event.1 == "acknowledged"),
        "the close commits without an event the log cannot hold"
    );
    // Reads report the close as unlogged, and history shows the newest events.
    let lookup = get_conflict(&service, &scope, full).await;
    let lifecycle = &lookup.data["conflict"]["lifecycle"];
    assert_eq!(lifecycle["state"], "resolved");
    assert_eq!(lifecycle["read_side"], "clear");
    assert_eq!(lifecycle["closed_unlogged"], true);
    assert_eq!(lookup.data["history_truncated"], true);
    assert_eq!(
        lookup.data["history"].as_array().unwrap().last().unwrap()["seq"],
        MAX_CONFLICT_LIFECYCLE_EVENTS
    );
    assert_eq!(
        lookup.data["unlogged_transitions"],
        json!([{ "from_revision": revision, "to_revision": revision + 1 }])
    );

    // A concession on a full log closes the same way, with no event.
    let (kept, conceding, conceded) = two_party(&fleet, "bounds-concede").await;
    let view = fleet.conflict_view(conceded).await;
    seed_acknowledgements(
        &fleet,
        conceded,
        view.1,
        MAX_CONFLICT_LIFECYCLE_EVENTS,
        None,
    )
    .await;
    let resolved = fleet
        .resolve(AGENT_B, view, &[conceding.claim.id], "b/concede-full")
        .await
        .expect("a full lifecycle log never refuses a verified concession");
    assert_eq!(resolved.conflict_state, "resolved");
    assert_eq!(resolved.claims_restored, [kept.claim.id]);
    assert!(resolved.lifecycle_event.is_none());
    assert_eq!(fleet.conflict_row(conceded).await.0, "resolved");

    // A conflict with more members than an event records: acknowledge is
    // refused, and the owner's supersede to the peer's value still closes it.
    let (author, peer, crowded) = two_party(&fleet, "bounds-members").await;
    let claim_key = author.claim.claim_key.clone().expect("a keyed decision");
    seed_retired_members(&fleet, &claim_key, crowded, MAX_CONFLICT_MEMBER_COUNT).await;
    let view = fleet.conflict_view(crowded).await;
    assert!(view.2 > MAX_CONFLICT_MEMBER_COUNT);
    let refused = refusal(
        fleet
            .acknowledge(AGENT_C, crowded, view.1, "c/ack-crowded")
            .await,
    );
    assert_eq!(refused.code, RefusalCode::BoundExceeded);
    fleet.assert_key_unconsumed("c/ack-crowded").await;
    let successor = fleet
        .conflict_ledger(AGENT_A)
        .supersede_claim(
            &fleet.scope(AGENT_A),
            ClaimTarget {
                claim_id: author.claim.id,
                expected_revision: fleet.claim(author.claim.id).await.revision,
            },
            None,
            &decision("bounds-members", &json!("y"), 1),
            &fleet.key("a/supersede-crowded"),
        )
        .await
        .expect("a crowded conflict never refuses the owner's supersede");
    assert_eq!(successor.conflicts_resolved, [crowded]);
    assert_eq!(successor.claims_restored, [peer.claim.id]);
    assert!(fleet.lifecycle_log(crowded).await.is_empty());
    let lookup = get_conflict(&service, &scope, crowded).await;
    assert_eq!(
        lookup.data["conflict"]["lifecycle"]["closed_unlogged"],
        true
    );
    assert_eq!(
        lookup.data["unlogged_transitions"],
        json!([{ "from_revision": 1, "to_revision": view.1 + 1 }])
    );

    fleet.cleanup().await;
}

#[tokio::test]
async fn live_long_conflict_history_fits_one_mcp_response_when_configured() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fleet = Fleet::new(&database_url, "history-budget").await;
    let (_, _, conflict_id) = two_party(&fleet, "history-budget").await;
    let revision = fleet.conflict_row(conflict_id).await.1;
    // More schema-valid notes of 1,000 three-byte characters than one
    // response can carry.
    let note = "\u{8a3c}".repeat(1_000);
    seed_acknowledgements(&fleet, conflict_id, revision, 300, Some(&note)).await;

    let server =
        McpServer::new(Arc::new(fleet.full_service(AGENT_C)), fleet.scope(AGENT_C)).unwrap();
    let response = server
        .handle_value(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "recall",
                "arguments": { "action": "get", "kind": "conflict", "id": conflict_id },
            },
        }))
        .await
        .expect("a request has a response");
    let result = response.result.expect("tools/call answers");
    assert_eq!(result["isError"], false, "{}", result["content"][0]["text"]);
    let data = &result["structuredContent"]["data"];
    assert_eq!(data["conflict"]["id"], conflict_id);
    assert_eq!(data["history_truncated"], true);
    // The newest events are kept, in order, with their notes intact.
    let history = data["history"].as_array().unwrap();
    assert!(!history.is_empty());
    assert_eq!(history.last().unwrap()["seq"], 300);
    assert!(
        history
            .windows(2)
            .all(|pair| pair[0]["seq"].as_i64() < pair[1]["seq"].as_i64())
    );
    assert!(history.iter().all(|event| event["rationale"] == note));
    assert_eq!(data["unlogged_transitions"], json!([]));

    fleet.cleanup().await;
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // one episode's acknowledgements from open through reopen
async fn live_acknowledge_is_episode_bound_and_deduplicated_when_configured() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fleet = Fleet::new(&database_url, "acknowledge").await;
    let (x, _y, conflict_id) = two_party(&fleet, "acknowledge").await;
    let before = fleet.conflict_row(conflict_id).await;
    assert_eq!(before.0, "open");
    let revision = before.1;

    let first = fleet
        .acknowledge(AGENT_A, conflict_id, revision, "a/ack")
        .await
        .expect("an implicated agent may acknowledge");
    assert_eq!(first.operation, "acknowledge");
    assert!(first.applied);
    assert_eq!(first.status.as_deref(), Some("acknowledged"));
    assert_eq!(
        (first.conflict_state.as_str(), first.conflict_revision),
        ("open", revision)
    );
    assert_eq!(first.member_count, 2);
    let event = first
        .lifecycle_event
        .as_ref()
        .expect("an acknowledged event");
    assert_eq!(
        (event.seq, event.kind.as_str(), event.actor.as_str()),
        (1, "acknowledged", AGENT_A)
    );
    assert_eq!(
        (event.episode_revision, event.result_revision),
        (revision, revision)
    );
    assert_eq!(event.rationale.as_deref(), Some("agent-a is looking"));
    // Acknowledgement is overlay metadata: the conflict row never changes.
    assert_eq!(fleet.conflict_row(conflict_id).await, before);
    assert_eq!(fleet.keyed_events("a/ack").await.len(), 1);
    assert_eq!(
        fleet.keyed_events("a/ack").await[0].0,
        "conflict_acknowledged"
    );

    // A second acknowledgement of the same episode commits and changes nothing.
    let again = fleet
        .acknowledge(AGENT_A, conflict_id, revision, "a/ack-again")
        .await
        .unwrap();
    assert!(!again.applied);
    assert_eq!(again.status.as_deref(), Some("already_acknowledged"));
    assert!(again.lifecycle_event.is_none());
    assert_eq!(fleet.receipt_count("a/ack-again").await, 1);
    assert_eq!(fleet.keyed_events("a/ack-again").await.len(), 1);
    // The first key replays its stored result.
    let replay = fleet
        .acknowledge(AGENT_A, conflict_id, revision, "a/ack")
        .await
        .unwrap();
    assert!(replay.idempotent_replay);
    assert_eq!(
        ConflictMutation {
            idempotent_replay: false,
            ..replay
        },
        first
    );
    // Other agents acknowledge the same episode independently.
    for (agent, key) in [(AGENT_B, "b/ack"), (AGENT_C, "c/ack")] {
        assert!(
            fleet
                .acknowledge(agent, conflict_id, revision, key)
                .await
                .unwrap()
                .applied
        );
    }
    assert_eq!(fleet.lifecycle_log(conflict_id).await.len(), 3);

    // Refusals leave nothing behind and keep the key free.
    let stale = refusal(
        fleet
            .acknowledge(AGENT_C, conflict_id, revision + 1, "c/stale")
            .await,
    );
    assert_eq!(stale.code, RefusalCode::StaleRevision);
    assert_eq!(stale.details["current_revision"], revision);
    fleet.assert_key_unconsumed("c/stale").await;
    let missing = refusal(
        fleet
            .acknowledge(AGENT_C, 9_007_199_254_740_990, 1, "c/missing")
            .await,
    );
    assert_eq!(missing.code, RefusalCode::NotFound);
    fleet.assert_key_unconsumed("c/missing").await;
    let legacy_claim = fleet
        .legacy_disputed_decision("acknowledge-legacy", "x", AGENT_A)
        .await;
    let legacy = fleet
        .legacy_conflict("acknowledge-legacy::database-choice", &[legacy_claim])
        .await;
    let legacy_refusal = refusal(fleet.acknowledge(AGENT_C, legacy, 1, "c/legacy").await);
    assert_eq!(legacy_refusal.code, RefusalCode::LegacyLineage);
    fleet.assert_key_unconsumed("c/legacy").await;

    // The overlay reads the episode's acknowledgers; the read side stays open.
    let service = fleet.full_service(AGENT_C);
    let scope = fleet.scope(AGENT_C);
    let lookup = get_conflict(&service, &scope, conflict_id).await;
    let lifecycle = &lookup.data["conflict"]["lifecycle"];
    assert_eq!(lifecycle["state"], "acknowledged");
    assert_eq!(lifecycle["read_side"], "open");
    assert_eq!(lifecycle["episode_revision"], revision);
    assert_eq!(
        lifecycle["acknowledged_by"]
            .as_array()
            .unwrap()
            .iter()
            .map(|ack| ack["actor"].as_str().unwrap())
            .collect::<Vec<_>>(),
        [AGENT_A, AGENT_B, AGENT_C]
    );
    assert_eq!(
        lookup.conflict_coverage.details["lifecycle_overlay"],
        "evaluated"
    );

    // A closed conflict cannot be acknowledged.
    let x_revision = fleet.claim(x.claim.id).await.revision;
    fleet
        .retract(AGENT_A, x.claim.id, x_revision, "a/retract")
        .await
        .unwrap();
    let closed = fleet.conflict_row(conflict_id).await;
    assert_eq!(closed.0, "resolved");
    let not_open = refusal(
        fleet
            .acknowledge(AGENT_B, conflict_id, closed.1, "b/closed")
            .await,
    );
    assert_eq!(not_open.code, RefusalCode::NotOpen);
    assert_eq!(not_open.details["current_state"], "resolved");
    fleet.assert_key_unconsumed("b/closed").await;

    // Once record reopens the lineage, the earlier acknowledgements belong
    // to the previous episode and no longer apply.
    fleet
        .record(AGENT_C, &decision("acknowledge", &json!("z"), 1), "c/z")
        .await;
    let reopened = fleet.conflict_row(conflict_id).await;
    assert_eq!(reopened.0, "open");
    assert_eq!(reopened.1, closed.1 + 1);
    let lookup = get_conflict(&service, &scope, conflict_id).await;
    let lifecycle = &lookup.data["conflict"]["lifecycle"];
    assert_eq!(lifecycle["state"], "open");
    assert_eq!(lifecycle["episode_revision"], reopened.1);
    assert_eq!(lifecycle["acknowledged_by"], json!([]));
    let renewed = fleet
        .acknowledge(AGENT_A, conflict_id, reopened.1, "a/ack-reopened")
        .await
        .unwrap();
    assert!(renewed.applied, "a new episode takes a new acknowledgement");
    fleet.assert_lifecycle_invariants().await;

    fleet.cleanup().await;
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // concession outcomes and every refusal on one fixture
async fn live_resolve_by_concession_closes_or_refuses_still_incompatible_when_configured() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fleet = Fleet::new(&database_url, "concede").await;

    // Two-party: B concedes y, so x is the only current value left.
    let (x, y, conflict_id) = two_party(&fleet, "concede-two").await;
    let view = fleet.conflict_view(conflict_id).await;
    let x_before = fleet.claim(x.claim.id).await;
    let y_before = fleet.claim(y.claim.id).await;

    // Refusals first: each leaves every row and the key as they were.
    let not_owner = refusal(
        fleet
            .resolve(AGENT_A, view, &[y.claim.id], "a/not-owner")
            .await,
    );
    assert_eq!(not_owner.code, RefusalCode::NotOwner, "DISC-03");
    assert_eq!(fleet.claim(y.claim.id).await, y_before);
    fleet.assert_key_unconsumed("a/not-owner").await;
    let stale_count = refusal(
        fleet
            .resolve(
                AGENT_B,
                (view.0, view.1, view.2 + 1),
                &[y.claim.id],
                "b/count",
            )
            .await,
    );
    assert_eq!(stale_count.code, RefusalCode::StaleMemberCount);
    assert_eq!(stale_count.details["current_member_count"], view.2);
    fleet.assert_key_unconsumed("b/count").await;
    let stale_revision = refusal(
        fleet
            .resolve(
                AGENT_B,
                (view.0, view.1 + 1, view.2),
                &[y.claim.id],
                "b/revision",
            )
            .await,
    );
    assert_eq!(stale_revision.code, RefusalCode::StaleRevision);
    fleet.assert_key_unconsumed("b/revision").await;
    let elsewhere = fleet
        .record(AGENT_B, &decision("concede-other", &json!("w"), 1), "b/w")
        .await;
    let not_member = refusal(
        fleet
            .resolve(AGENT_B, view, &[elsewhere.claim.id], "b/not-member")
            .await,
    );
    assert_eq!(not_member.code, RefusalCode::NotMember);
    fleet.assert_key_unconsumed("b/not-member").await;
    // Re-verification alone cannot close a live incompatibility.
    let live = refusal(fleet.resolve(AGENT_C, view, &[], "c/verify").await);
    assert_eq!(live.code, RefusalCode::StillIncompatible);
    assert_eq!(live.details["pairs"], json!([[x.claim.id, y.claim.id]]));
    fleet.assert_key_unconsumed("c/verify").await;
    // No refusal changed a claim, the conflict, or the log.
    assert_eq!(fleet.claim(x.claim.id).await, x_before);
    assert_eq!(fleet.claim(y.claim.id).await, y_before);
    assert_eq!(fleet.conflict_view(conflict_id).await, view);
    assert_eq!(fleet.conflict_row(conflict_id).await.0, "open");
    assert!(fleet.lifecycle_log(conflict_id).await.is_empty());

    let conceded = fleet
        .resolve(AGENT_B, view, &[y.claim.id], "b/concede")
        .await
        .expect("the author concedes its own claim");
    assert_eq!(conceded.operation, "resolve");
    assert!(conceded.applied);
    assert_eq!(conceded.conflict_state, "resolved");
    assert_eq!(conceded.conflict_revision, view.1 + 1);
    assert_eq!(conceded.claims_retracted, [y.claim.id]);
    assert_eq!(conceded.claims_restored, [x.claim.id]);
    assert_eq!(conceded.conflicts_resolved, [conflict_id]);
    let event = conceded.lifecycle_event.as_ref().expect("a logged close");
    assert_eq!(
        (
            event.kind.as_str(),
            event.actor_kind.as_str(),
            event.actor.as_str()
        ),
        ("resolved", "detector", "same_key_functional_value_v2")
    );
    assert_eq!(event.operation, "conflict_resolve");
    assert_eq!(
        event.reason_kind.as_deref(),
        Some("no_current_incompatibility")
    );
    let payload = event.payload.as_ref().unwrap();
    assert_eq!(payload["cause"]["agent"], AGENT_B);
    assert_eq!(payload["cause"]["claims_retracted"], json!([y.claim.id]));
    assert_eq!(payload["restored_claim_ids"], json!([x.claim.id]));
    assert_eq!(fleet.claim(y.claim.id).await.state, ClaimState::Retracted);
    assert_eq!(fleet.claim(x.claim.id).await.state, ClaimState::Active);
    let row = fleet.conflict(conflict_id).await;
    assert_eq!(row.state, "resolved");
    assert_eq!(
        row.resolution_kind.as_deref(),
        Some("no_current_incompatibility")
    );
    assert_eq!(
        row.resolution_reason.as_deref(),
        Some(
            format!(
                "no lifecycle-current incompatible pair remains after concession retracting claims {}",
                y.claim.id
            )
            .as_str()
        )
    );
    let keyed = fleet.keyed_events("b/concede").await;
    assert_eq!(keyed.len(), 1);
    assert_eq!(keyed[0].0, "conflict_resolved");
    let receipt_conflict: Option<i64> = sqlx::query_scalar(
        "SELECT conflict_id FROM memory_mutation_receipts \
         WHERE tenant_id = $1 AND idempotency_key = $2",
    )
    .bind(fleet.tenant)
    .bind(fleet.key("b/concede"))
    .fetch_one(fleet.pool())
    .await
    .unwrap();
    assert_eq!(receipt_conflict, Some(conflict_id));
    // A retry after later changes returns the stored result.
    let replay = fleet
        .resolve(AGENT_B, view, &[y.claim.id], "b/concede")
        .await
        .unwrap();
    assert!(replay.idempotent_replay);
    assert_eq!(replay.claims_retracted, conceded.claims_retracted);

    // Three-way: conceding x leaves y against z, so nothing changes at all.
    let x3 = fleet
        .record(AGENT_A, &decision("concede-three", &json!("x"), 1), "a/x3")
        .await;
    let y3 = fleet
        .record(AGENT_B, &decision("concede-three", &json!("y"), 1), "b/y3")
        .await;
    let z3 = fleet
        .record(AGENT_C, &decision("concede-three", &json!("z"), 1), "c/z3")
        .await;
    let three = y3.claim.conflict_ids[0];
    let three_view = fleet.conflict_view(three).await;
    assert_eq!(three_view.2, 3);
    let conceded_before = fleet.claim(x3.claim.id).await;
    let still = refusal(
        fleet
            .resolve(AGENT_A, three_view, &[x3.claim.id], "a/concede-three")
            .await,
    );
    assert_eq!(still.code, RefusalCode::StillIncompatible);
    assert_eq!(still.details["pair_count"], 1);
    assert_eq!(still.details["pairs"], json!([[y3.claim.id, z3.claim.id]]));
    assert_eq!(
        fleet.claim(x3.claim.id).await,
        conceded_before,
        "rolled back"
    );
    assert_eq!(fleet.conflict_view(three).await, three_view);
    assert!(fleet.lifecycle_log(three).await.is_empty());
    fleet.assert_key_unconsumed("a/concede-three").await;

    // When the data already agrees (here z stopped being current outside the
    // lifecycle), any agent may have the detector verify and close.
    sqlx::query(
        "UPDATE memory_claims SET state = 'expired', revision = revision + 1 \
         WHERE tenant_id = $1 AND project = $2 AND id = ANY($3)",
    )
    .bind(fleet.tenant)
    .bind(&fleet.project)
    .bind(vec![x3.claim.id, z3.claim.id])
    .execute(fleet.pool())
    .await
    .unwrap();
    let verified = fleet
        .resolve(AGENT_C, three_view, &[], "c/verify-three")
        .await
        .expect("an uninvolved agent may trigger the verified close");
    assert!(verified.claims_retracted.is_empty());
    assert_eq!(verified.claims_restored, [y3.claim.id]);
    assert_eq!(fleet.conflict_row(three).await.0, "resolved");
    assert_eq!(
        fleet.conflict(three).await.resolution_reason.as_deref(),
        Some("no lifecycle-current incompatible pair remains on re-verification")
    );
    fleet.assert_lifecycle_invariants().await;

    fleet.cleanup().await;
}

#[tokio::test]
async fn live_derived_close_logs_detector_event_with_capability_when_configured() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fleet = Fleet::new(&database_url, "derived-close").await;

    // Retract through a ledger that holds the capability.
    let (x, y, conflict_id) = two_party(&fleet, "derived-retract").await;
    let revision = fleet.conflict_row(conflict_id).await.1;
    let retracted = fleet
        .conflict_ledger(AGENT_A)
        .retract_claim(
            &fleet.scope(AGENT_A),
            ClaimTarget {
                claim_id: x.claim.id,
                expected_revision: fleet.claim(x.claim.id).await.revision,
            },
            Some("wrong database"),
            &fleet.key("a/retract"),
        )
        .await
        .unwrap();
    assert_eq!(retracted.conflicts_resolved, [conflict_id]);
    let log = fleet.lifecycle_log(conflict_id).await;
    assert_eq!(log.len(), 1);
    let (seq, kind, episode, result, actor_kind, actor, operation, key, payload) = &log[0];
    assert_eq!((*seq, kind.as_str()), (1, "resolved"));
    assert_eq!((*episode, *result), (revision, revision + 1));
    assert_eq!(
        (actor_kind.as_str(), actor.as_str(), operation.as_str()),
        ("detector", "same_key_functional_value_v2", "retract")
    );
    assert_eq!(*key, fleet.key("a/retract"));
    assert_eq!(payload["cause"]["agent"], AGENT_A);
    assert_eq!(payload["cause"]["claims_retracted"], json!([x.claim.id]));
    assert_eq!(payload["cause"]["reason"], "wrong database");
    assert_eq!(payload["restored_claim_ids"], json!([y.claim.id]));
    assert_eq!(payload["remaining_current_claim_ids"], json!([y.claim.id]));

    // Supersede to the peer's value: the logged close names both claims.
    let (predecessor, peer, supersede_conflict) = two_party(&fleet, "derived-supersede").await;
    let successor = fleet
        .conflict_ledger(AGENT_A)
        .supersede_claim(
            &fleet.scope(AGENT_A),
            ClaimTarget {
                claim_id: predecessor.claim.id,
                expected_revision: fleet.claim(predecessor.claim.id).await.revision,
            },
            None,
            &decision("derived-supersede", &json!("y"), 1),
            &fleet.key("a/supersede"),
        )
        .await
        .unwrap();
    assert_eq!(successor.conflicts_resolved, [supersede_conflict]);
    let log = fleet.lifecycle_log(supersede_conflict).await;
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].6, "supersede");
    assert_eq!(log[0].8["cause"]["claim_superseded"], predecessor.claim.id);
    assert_eq!(log[0].8["cause"]["successor_claim_id"], successor.claim.id);
    assert_eq!(log[0].8["restored_claim_ids"], json!([peer.claim.id]));

    // Without the capability a close is audited in memory_events only, as
    // before migration 29.
    let (author, _, unlogged) = two_party(&fleet, "derived-unlogged").await;
    fleet
        .retract(
            AGENT_A,
            author.claim.id,
            fleet.claim(author.claim.id).await.revision,
            "a/retract-unlogged",
        )
        .await
        .unwrap();
    assert_eq!(fleet.conflict_row(unlogged).await.0, "resolved");
    assert!(fleet.lifecycle_log(unlogged).await.is_empty());
    fleet.assert_lifecycle_invariants().await;

    fleet.cleanup().await;
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // one conflict's log across a logged close and an unlogged reopen
async fn live_overlay_and_history_report_unlogged_reopen_when_configured() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fleet = Fleet::new(&database_url, "history").await;
    let service = fleet.full_service(AGENT_C);
    let scope = fleet.scope(AGENT_C);
    let (x, y, conflict_id) = two_party(&fleet, "history").await;
    let first = fleet.conflict_row(conflict_id).await.1;

    fleet
        .acknowledge(AGENT_A, conflict_id, first, "a/ack")
        .await
        .unwrap();
    // A logged close by the author's retract...
    fleet
        .conflict_ledger(AGENT_A)
        .retract_claim(
            &fleet.scope(AGENT_A),
            ClaimTarget {
                claim_id: x.claim.id,
                expected_revision: fleet.claim(x.claim.id).await.revision,
            },
            None,
            &fleet.key("a/retract"),
        )
        .await
        .unwrap();
    // ...then an old-style reopen through record, which is never logged.
    fleet
        .record(AGENT_C, &decision("history", &json!("z"), 1), "c/z")
        .await;
    let reopened = fleet.conflict_row(conflict_id).await.1;
    assert_eq!(reopened, first + 2);
    fleet
        .acknowledge(AGENT_B, conflict_id, reopened, "b/ack")
        .await
        .unwrap();

    let lookup = get_conflict(&service, &scope, conflict_id).await;
    let history = lookup.data["history"].as_array().unwrap();
    assert_eq!(
        history
            .iter()
            .map(|event| (
                event["seq"].as_i64().unwrap(),
                event["kind"].as_str().unwrap(),
                event["episode_revision"].as_i64().unwrap(),
                event["result_revision"].as_i64().unwrap(),
            ))
            .collect::<Vec<_>>(),
        [
            (1, "acknowledged", first, first),
            (2, "resolved", first, first + 1),
            (3, "acknowledged", reopened, reopened),
        ]
    );
    assert_eq!(
        history[1]["payload"]["cause"]["claims_retracted"],
        json!([x.claim.id])
    );
    assert!(history[0].get("idempotency_key").is_none());
    assert_eq!(lookup.data["history_truncated"], false);
    assert_eq!(
        lookup.data["unlogged_transitions"],
        json!([{ "from_revision": first + 1, "to_revision": reopened }])
    );
    let lifecycle = &lookup.data["conflict"]["lifecycle"];
    assert_eq!(lifecycle["state"], "acknowledged");
    assert_eq!(lifecycle["acknowledged_by"][0]["actor"], AGENT_B);
    assert_eq!(lookup.conflicts[0]["lifecycle"], *lifecycle);

    // A conflict closed without the log reads clear and reports the gap.
    let (u, _v, unlogged) = two_party(&fleet, "history-unlogged").await;
    fleet
        .retract(
            AGENT_A,
            u.claim.id,
            fleet.claim(u.claim.id).await.revision,
            "a/retract-unlogged",
        )
        .await
        .unwrap();
    let closed = get_conflict(&service, &scope, unlogged).await;
    let lifecycle = &closed.data["conflict"]["lifecycle"];
    assert_eq!(lifecycle["state"], "resolved");
    assert_eq!(lifecycle["read_side"], "clear");
    assert_eq!(lifecycle["closed_unlogged"], true);
    assert_eq!(lifecycle["closed_by"], Value::Null);
    assert_eq!(closed.data["history"], json!([]));
    assert_eq!(
        closed.data["unlogged_transitions"],
        json!([{ "from_revision": 1, "to_revision": 2 }])
    );

    // Every read path on the private writer carries the overlay.
    let listed = recall(
        &service,
        &scope,
        RecallAction::Conflicts,
        json!({ "include_resolved": true, "limit": 10 }),
    )
    .await
    .unwrap();
    assert_eq!(
        listed.conflict_coverage.details["lifecycle_overlay"],
        "evaluated"
    );
    let by_id = |id: i64| {
        listed
            .conflicts
            .iter()
            .find(|conflict| conflict["id"] == id)
            .unwrap_or_else(|| panic!("conflict {id} is listed"))
            .clone()
    };
    assert_eq!(by_id(conflict_id)["lifecycle"]["state"], "acknowledged");
    assert_eq!(by_id(unlogged)["lifecycle"]["state"], "resolved");
    let claim = recall(
        &service,
        &scope,
        RecallAction::Get,
        json!({ "kind": "claim", "id": y.claim.id }),
    )
    .await
    .unwrap();
    assert_eq!(claim.conflicts[0]["lifecycle"]["state"], "acknowledged");
    let search = recall(
        &service,
        &scope,
        RecallAction::Search,
        json!({ "query": "history", "kind": "claim", "limit": 10 }),
    )
    .await
    .unwrap();
    assert!(
        search
            .conflicts
            .iter()
            .any(|conflict| conflict["lifecycle"]["state"] == "acknowledged")
    );
    assert_eq!(
        search.conflict_coverage.details["lifecycle_overlay"],
        "evaluated"
    );
    let chunks = recall(
        &service,
        &scope,
        RecallAction::Search,
        json!({ "query": "history", "kind": "chunk", "limit": 10 }),
    )
    .await
    .unwrap();
    assert_eq!(
        chunks.conflict_coverage.details["lifecycle_overlay"],
        "evaluated"
    );
    assert!(
        chunks
            .conflicts
            .iter()
            .all(|conflict| conflict.get("lifecycle").is_some())
    );

    // So do remember responses, and the acknowledge response itself.
    let remembered = FleetMemoryService::remember(
        &service,
        scope.clone(),
        RememberRequest::new(
            RememberAction::Acknowledge,
            Some(fleet.key("c/ack-service")),
            Map::from_iter([
                ("conflict_id".into(), json!(conflict_id)),
                ("expected_revision".into(), json!(reopened)),
            ]),
        ),
    )
    .await
    .unwrap();
    assert_eq!(remembered.data["applied"], true);
    assert_eq!(
        remembered.conflicts[0]["lifecycle"]["acknowledged_by"][1]["actor"],
        AGENT_C
    );
    assert_eq!(remembered.conflict_coverage.status, "complete");
    assert_eq!(
        remembered.conflict_coverage.details["lifecycle_overlay"],
        "evaluated"
    );
    let recorded = FleetMemoryService::remember(
        &service,
        scope.clone(),
        RememberRequest::new(
            RememberAction::Record,
            Some(fleet.key("c/w")),
            serde_json::to_value(decision("history", &json!("w"), 1))
                .unwrap()
                .as_object()
                .cloned()
                .unwrap(),
        ),
    )
    .await
    .unwrap();
    assert_eq!(recorded.conflicts[0]["lifecycle"]["state"], "acknowledged");
    fleet.assert_lifecycle_invariants().await;

    fleet.cleanup().await;
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // publication, record-only, and unprobed writers over one log
async fn live_publication_and_unprobed_writers_are_unchanged_with_lifecycle_rows_when_configured() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fleet = Fleet::new(&database_url, "unchanged").await;
    let (x, _y, conflict_id) = two_party(&fleet, "unchanged").await;
    let revision = fleet.conflict_row(conflict_id).await.1;
    fleet
        .acknowledge(AGENT_A, conflict_id, revision, "a/ack")
        .await
        .unwrap();
    let scope = fleet.scope(AGENT_A);
    let lifecycle_rows = fleet.tenant_lifecycle_rows().await;
    assert_eq!(lifecycle_rows, 1);

    // The publication surface and a writer whose probe found no lifecycle
    // log (PRIVATE_WRITER) never show a lifecycle key or overlay coverage.
    for (label, serving) in [
        ("record-only", LifecycleServing::default()),
        ("unprobed", PRIVATE_WRITER),
    ] {
        let service = fleet.service(AGENT_A, serving);
        for (action, arguments) in [
            (RecallAction::Conflicts, json!({ "include_resolved": true })),
            (
                RecallAction::Get,
                json!({ "kind": "claim", "id": x.claim.id }),
            ),
            (
                RecallAction::Search,
                json!({ "query": "unchanged", "kind": "chunk" }),
            ),
            (
                RecallAction::Search,
                json!({ "query": "unchanged", "kind": "claim" }),
            ),
        ] {
            let result = recall(&service, &scope, action, arguments.clone())
                .await
                .unwrap();
            assert!(!result.conflicts.is_empty(), "{arguments}");
            assert!(
                result
                    .conflicts
                    .iter()
                    .all(|conflict| conflict.get("lifecycle").is_none()),
                "{serving:?} {arguments}"
            );
            assert!(
                result
                    .conflict_coverage
                    .details
                    .get("lifecycle_overlay")
                    .is_none()
            );
            assert!(
                !serde_json::to_string(&result.data)
                    .unwrap()
                    .contains("lifecycle\"")
            );
        }
        let status = recall(&service, &scope, RecallAction::Status, json!({}))
            .await
            .unwrap();
        if serving == PRIVATE_WRITER {
            assert_eq!(status.data["remember_surface"]["conflict_lifecycle"], false);
        } else {
            assert!(status.data.get("remember_surface").is_none());
        }
        // Neither surface serves the conflict actions; an unused key stays free.
        let unserved = format!("a/unserved-{label}");
        let refused = FleetMemoryService::remember(
            &service,
            scope.clone(),
            RememberRequest::new(
                RememberAction::Acknowledge,
                Some(fleet.key(&unserved)),
                Map::from_iter([
                    ("conflict_id".into(), json!(conflict_id)),
                    ("expected_revision".into(), json!(revision)),
                ]),
            ),
        )
        .await;
        assert_eq!(refusal_code(refused), "lifecycle_unavailable");
        fleet.assert_key_unconsumed(&unserved).await;
    }

    // A committed acknowledgement still replays where it is no longer served.
    let unprobed = fleet.service(AGENT_A, PRIVATE_WRITER);
    let replay = FleetMemoryService::remember(
        &unprobed,
        scope.clone(),
        RememberRequest::new(
            RememberAction::Acknowledge,
            Some(fleet.key("a/ack")),
            Map::from_iter([
                ("conflict_id".into(), json!(conflict_id)),
                ("expected_revision".into(), json!(revision)),
                ("reason".into(), json!("agent-a is looking")),
            ]),
        ),
    )
    .await
    .expect("a committed acknowledgement replays");
    assert_eq!(replay.data["idempotent_replay"], true);
    assert_eq!(replay.data["applied"], true);
    assert!(replay.conflicts[0].get("lifecycle").is_none());

    // A ledger without the capability refuses before writing anything, and
    // its closes add nothing to the log.
    let unprobed_ledger = fleet.ledger(AGENT_B);
    let refused = unprobed_ledger
        .acknowledge_conflict(
            &fleet.scope(AGENT_B),
            ConflictTarget {
                conflict_id,
                expected_revision: revision,
                expected_member_count: None,
            },
            None,
            &fleet.key("b/unprobed"),
        )
        .await;
    assert_eq!(refusal(refused).code, RefusalCode::LifecycleUnavailable);
    fleet.assert_key_unconsumed("b/unprobed").await;
    fleet
        .retract(
            AGENT_A,
            x.claim.id,
            fleet.claim(x.claim.id).await.revision,
            "a/retract",
        )
        .await
        .unwrap();
    assert_eq!(fleet.conflict_row(conflict_id).await.0, "resolved");
    assert_eq!(fleet.tenant_lifecycle_rows().await, lifecycle_rows);
    fleet.assert_lifecycle_invariants().await;

    fleet.cleanup().await;
}

/// Grant `role` the runtime writer's table, sequence, schema, and database
/// privileges, without the lifecycle log.
async fn grant_runtime_matrix(fleet: &Fleet, role: &str) {
    for (privilege, tables) in RUNTIME_GRANTS {
        sqlx::query(&format!(
            "GRANT {privilege} ON TABLE {} TO {role}",
            qualified(tables)
        ))
        .execute(fleet.pool())
        .await
        .unwrap();
    }
    for statement in [
        format!("GRANT CONNECT ON DATABASE fleet_recall TO {role}"),
        format!("GRANT USAGE ON SCHEMA public TO {role}"),
        format!(
            "GRANT USAGE ON SEQUENCE {} TO {role}",
            qualified(RUNTIME_SEQUENCES)
        ),
    ] {
        sqlx::query(&statement).execute(fleet.pool()).await.unwrap();
    }
}

async fn create_probe_role(fleet: &Fleet, label: &str) -> (String, String) {
    let role = format!("lifecycle_{label}_{}", Uuid::now_v7().simple());
    let password = format!("probe-{}", Uuid::now_v7().simple());
    sqlx::query(&format!(
        "CREATE ROLE {role} WITH LOGIN PASSWORD '{password}'"
    ))
    .execute(fleet.pool())
    .await
    .unwrap();
    (role, password)
}

async fn drop_probe_role(fleet: &Fleet, role: &str) {
    let mut tables = RUNTIME_GRANTS
        .iter()
        .flat_map(|(_, tables)| tables.iter().copied())
        .chain(PUBLICATION_READ_TABLES)
        .chain(["memory_conflict_lifecycle_events_v1"])
        .collect::<Vec<_>>();
    tables.sort_unstable();
    tables.dedup();
    for statement in [
        format!("REVOKE ALL ON TABLE {} FROM {role}", qualified(&tables)),
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
}

async fn probe_pool(database_url: &str, role: &str, password: &str) -> PgPool {
    PgPoolOptions::new()
        .max_connections(4)
        .acquire_timeout(Duration::from_secs(10))
        .connect(&probe_database_url(database_url, role, password))
        .await
        .expect("the probe role connects")
}

fn sqlstate(error: &sqlx::Error) -> Option<String> {
    match error {
        sqlx::Error::Database(error) => error.code().map(std::borrow::Cow::into_owned),
        _ => None,
    }
}

/// Every lifecycle action and read, under exactly the probed role's grants.
#[allow(clippy::too_many_lines)] // the whole lifecycle surface under one role
async fn run_conflict_lifecycle_as(
    fleet: &Fleet,
    pool: &PgPool,
    capability: ConflictLifecycleCapability,
) -> Result<(), String> {
    let ledger = |agent| {
        fleet
            .ledger_on(pool, agent, RetryPolicy::default())
            .with_conflict_lifecycle(capability)
    };
    let record = |agent: &'static str, subject: &'static str, value: &'static str| {
        let ledger = ledger(agent);
        let scope = fleet.scope(agent);
        let key = fleet.key(&format!("probe/{agent}/{subject}/{value}"));
        async move {
            ledger
                .record_claim(&scope, &decision(subject, &json!(value), 1), &key)
                .await
                .map_err(|error| format!("probe record: {error}"))
        }
    };
    let x = record(AGENT_A, "probe-concede", "x").await?;
    let y = record(AGENT_B, "probe-concede", "y").await?;
    let conflict_id = y.claim.conflict_ids[0];
    let view = fleet.conflict_view(conflict_id).await;
    let target = |expected_member_count| ConflictTarget {
        conflict_id,
        expected_revision: view.1,
        expected_member_count,
    };
    let acknowledged = ledger(AGENT_C)
        .acknowledge_conflict(
            &fleet.scope(AGENT_C),
            target(None),
            None,
            &fleet.key("probe/ack"),
        )
        .await
        .map_err(|error| format!("probe acknowledge: {error}"))?;
    if !acknowledged.applied {
        return Err(format!("probe acknowledge did not apply: {acknowledged:?}"));
    }
    let resolved = ledger(AGENT_B)
        .resolve_conflict(
            &fleet.scope(AGENT_B),
            target(Some(view.2)),
            &[y.claim.id],
            None,
            &fleet.key("probe/resolve"),
        )
        .await
        .map_err(|error| format!("probe resolve: {error}"))?;
    if resolved.claims_restored != [x.claim.id] {
        return Err(format!("probe resolve did not restore: {resolved:?}"));
    }
    let history = ledger(AGENT_C)
        .conflict_lifecycle_history(&fleet.scope(AGENT_C), conflict_id)
        .await
        .map_err(|error| format!("probe history: {error}"))?;
    if history.events.len() != 2 {
        return Err(format!("probe history is incomplete: {history:?}"));
    }
    let overlay = ledger(AGENT_C)
        .conflict_lifecycle_rows(&fleet.scope(AGENT_C), &[(conflict_id, view.1)])
        .await
        .map_err(|error| format!("probe overlay: {error}"))?;
    if overlay.events.get(&conflict_id).map(Vec::len) != Some(2) {
        return Err(format!("probe overlay is incomplete: {overlay:?}"));
    }
    // Logged closes from retract and supersede under the same grants.
    let p = record(AGENT_A, "probe-retract", "x").await?;
    record(AGENT_B, "probe-retract", "y").await?;
    let retracted = ledger(AGENT_A)
        .retract_claim(
            &fleet.scope(AGENT_A),
            ClaimTarget {
                claim_id: p.claim.id,
                expected_revision: fleet.claim(p.claim.id).await.revision,
            },
            None,
            &fleet.key("probe/retract"),
        )
        .await
        .map_err(|error| format!("probe retract: {error}"))?;
    let s = record(AGENT_A, "probe-supersede", "x").await?;
    record(AGENT_B, "probe-supersede", "y").await?;
    let superseded = ledger(AGENT_A)
        .supersede_claim(
            &fleet.scope(AGENT_A),
            ClaimTarget {
                claim_id: s.claim.id,
                expected_revision: fleet.claim(s.claim.id).await.revision,
            },
            None,
            &decision("probe-supersede", &json!("y"), 1),
            &fleet.key("probe/supersede"),
        )
        .await
        .map_err(|error| format!("probe supersede: {error}"))?;
    for (label, closed) in [
        ("retract", &retracted.conflicts_resolved),
        ("supersede", &superseded.conflicts_resolved),
    ] {
        let [conflict] = closed.as_slice() else {
            return Err(format!("probe {label} did not close: {closed:?}"));
        };
        if fleet.lifecycle_log(*conflict).await.len() != 1 {
            return Err(format!("probe {label} close was not logged"));
        }
    }
    // Adjudication needs no grant beyond the runtime policy's lifecycle-log
    // SELECT and INSERT.
    let adjudicator = || ledger(AGENT_C).with_conflict_adjudication();
    record(AGENT_A, "probe-dismiss", "x").await?;
    let dismissed = record(AGENT_B, "probe-dismiss", "y")
        .await?
        .claim
        .conflict_ids[0];
    let view = fleet.conflict_view(dismissed).await;
    let dismissal = adjudicator()
        .dismiss_conflict(
            &fleet.scope(AGENT_C),
            ConflictTarget {
                conflict_id: dismissed,
                expected_revision: view.1,
                expected_member_count: Some(view.2),
            },
            false_positive("probe dismissal"),
            &fleet.key("probe/dismiss"),
        )
        .await
        .map_err(|error| format!("probe dismiss: {error}"))?;
    if dismissal.conflict_state != "dismissed" || dismissal.claims_restored.len() != 2 {
        return Err(format!("probe dismiss did not close: {dismissal:?}"));
    }
    record(AGENT_A, "probe-waive", "x").await?;
    let probe_waive = record(AGENT_B, "probe-waive", "y")
        .await?
        .claim
        .conflict_ids[0];
    let view = fleet.conflict_view(probe_waive).await;
    let waiver = adjudicator()
        .waive_conflict(
            &fleet.scope(AGENT_C),
            ConflictTarget {
                conflict_id: probe_waive,
                expected_revision: view.1,
                expected_member_count: Some(view.2),
            },
            capacity_deferred("probe waiver", 24, None),
            &fleet.key("probe/waive"),
        )
        .await
        .map_err(|error| format!("probe waive: {error}"))?;
    if waiver.status.as_deref() != Some("waived") {
        return Err(format!("probe waive did not apply: {waiver:?}"));
    }
    Ok(())
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // probe outcomes across grant sets, then every action under them
async fn live_capability_probe_false_without_grants_true_with_them_when_configured() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fleet = Fleet::new(&database_url, "capability").await;
    let capabilities = fleet.store.capabilities().await.unwrap();
    assert!(capabilities.supports_schema_version(CONFLICT_LIFECYCLE_SCHEMA_VERSION));
    // A schema before migration 29 is never probed.
    let mut before_29 = capabilities.clone();
    before_29.schema_version = CONFLICT_LIFECYCLE_SCHEMA_VERSION - 1;
    assert!(
        probe_conflict_lifecycle(fleet.pool(), &before_29)
            .await
            .unwrap()
            .is_none()
    );

    let (role, password) = create_probe_role(&fleet, "capability").await;
    let outcome = AssertUnwindSafe(async {
        // The runtime grants of a policy applied before migration 29.
        grant_runtime_matrix(&fleet, &role).await;
        let pool = probe_pool(&database_url, &role, &password).await;
        let without = probe_conflict_lifecycle(&pool, &capabilities).await;
        pool.close().await;
        assert!(
            matches!(without, Ok(None)),
            "no lifecycle grants: {without:?}"
        );

        // SELECT alone is not enough to append.
        sqlx::query(&format!(
            "GRANT SELECT ON TABLE public.memory_conflict_lifecycle_events_v1 TO {role}"
        ))
        .execute(fleet.pool())
        .await
        .unwrap();
        let pool = probe_pool(&database_url, &role, &password).await;
        let select_only = probe_conflict_lifecycle(&pool, &capabilities).await;
        pool.close().await;
        assert!(matches!(select_only, Ok(None)), "{select_only:?}");

        // The runtime policy's lifecycle-log grant: SELECT and INSERT.
        sqlx::query(&format!(
            "GRANT INSERT ON TABLE public.memory_conflict_lifecycle_events_v1 TO {role}"
        ))
        .execute(fleet.pool())
        .await
        .unwrap();
        let pool = probe_pool(&database_url, &role, &password).await;
        let capability = probe_conflict_lifecycle(&pool, &capabilities)
            .await
            .expect("the probe runs")
            .expect("the runtime policy's lifecycle grant may use the lifecycle log");
        // The probe wrote nothing.
        assert_eq!(fleet.tenant_lifecycle_rows().await, 0);
        let actions = run_conflict_lifecycle_as(&fleet, &pool, capability).await;
        pool.close().await;
        actions
    })
    .catch_unwind()
    .await;
    drop_probe_role(&fleet, &role).await;
    let outcome = outcome.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    fleet.assert_lifecycle_invariants().await;
    fleet.cleanup().await;
    outcome.unwrap();
}

#[tokio::test]
async fn live_lifecycle_log_is_append_only_and_private_when_configured() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fleet = Fleet::new(&database_url, "append-only").await;
    let (_x, _y, conflict_id) = two_party(&fleet, "append-only").await;
    let revision = fleet.conflict_row(conflict_id).await.1;
    fleet
        .acknowledge(AGENT_A, conflict_id, revision, "a/ack")
        .await
        .unwrap();

    let (runtime, runtime_password) = create_probe_role(&fleet, "runtime").await;
    let (reader, reader_password) = create_probe_role(&fleet, "reader").await;
    let outcome = AssertUnwindSafe(async {
        grant_runtime_matrix(&fleet, &runtime).await;
        sqlx::query(&format!(
            "GRANT SELECT, INSERT ON TABLE public.memory_conflict_lifecycle_events_v1 TO {runtime}"
        ))
        .execute(fleet.pool())
        .await
        .unwrap();
        // The publication reader's exact table surface.
        for statement in [
            format!(
                "GRANT SELECT ON TABLE {} TO {reader}",
                qualified(&PUBLICATION_READ_TABLES)
            ),
            format!("GRANT CONNECT ON DATABASE fleet_recall TO {reader}"),
            format!("GRANT USAGE ON SCHEMA public TO {reader}"),
        ] {
            sqlx::query(&statement).execute(fleet.pool()).await.unwrap();
        }

        let runtime_pool = probe_pool(&database_url, &runtime, &runtime_password).await;
        let visible: i64 = sqlx::query_scalar(
            "SELECT count(*)::INT8 FROM public.memory_conflict_lifecycle_events_v1 \
             WHERE tenant_id = $1",
        )
        .bind(fleet.tenant)
        .fetch_one(&runtime_pool)
        .await
        .expect("the runtime reads the log");
        assert_eq!(visible, 1);
        for statement in [
            "UPDATE public.memory_conflict_lifecycle_events_v1 SET rationale = 'rewritten' \
             WHERE tenant_id = $1",
            "DELETE FROM public.memory_conflict_lifecycle_events_v1 WHERE tenant_id = $1",
        ] {
            let error = sqlx::query(statement)
                .bind(fleet.tenant)
                .execute(&runtime_pool)
                .await
                .expect_err("the log is append-only for the runtime");
            assert_eq!(sqlstate(&error).as_deref(), Some("42501"), "{statement}");
        }
        runtime_pool.close().await;

        let reader_pool = probe_pool(&database_url, &reader, &reader_password).await;
        let error = sqlx::query("SELECT 1 FROM public.memory_conflict_lifecycle_events_v1 LIMIT 1")
            .fetch_optional(&reader_pool)
            .await
            .expect_err("the publication reader never sees the log");
        assert_eq!(sqlstate(&error).as_deref(), Some("42501"));
        reader_pool.close().await;
    })
    .catch_unwind()
    .await;
    drop_probe_role(&fleet, &runtime).await;
    drop_probe_role(&fleet, &reader).await;
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
    assert_eq!(fleet.lifecycle_log(conflict_id).await.len(), 1);
    fleet.cleanup().await;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConcessionRace {
    /// The concession committed first; the racing record reopened the lineage.
    ConcededThenReopened,
    /// The record joined first; the concession saw a stale member count.
    JoinedFirst,
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // three race shapes share one fixture and one invariant check
async fn live_concurrent_conflict_lifecycle_serializes_when_configured() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fleet = Fleet::new(&database_url, "lifecycle-race").await;
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
    let policy = RetryPolicy {
        max_attempts: 32,
        ..RetryPolicy::default()
    };
    let on = |pool: &PgPool, agent| {
        fleet
            .ledger_on(pool, agent, policy)
            .with_conflict_lifecycle(fleet.conflict_lifecycle)
    };
    let (author_a, author_b) = (on(fleet.pool(), AGENT_A), on(second.pool(), AGENT_B));
    let (author_c, author_a2) = (on(second.pool(), AGENT_C), on(second.pool(), AGENT_A));
    let (scope_a, scope_b, scope_c) = (
        fleet.scope(AGENT_A),
        fleet.scope(AGENT_B),
        fleet.scope(AGENT_C),
    );
    let mut outcomes = Vec::new();

    for round in 0..30 {
        let subject = format!("lifecycle-race-{round}");
        let (x, y, conflict_id) = two_party(&fleet, &subject).await;
        let view = fleet.conflict_view(conflict_id).await;
        let target = |expected_member_count| ConflictTarget {
            conflict_id,
            expected_revision: view.1,
            expected_member_count,
        };
        let barrier = Barrier::new(2);
        match round % 3 {
            0 => {
                // B concedes y while C records a third value. Record does
                // more work before its lineage lock, so every other round
                // starts the concession late to let the join land first.
                let stagger = Duration::from_millis(if round % 6 == 3 { 250 } else { 0 });
                let concede = async {
                    barrier.wait().await;
                    tokio::time::sleep(stagger).await;
                    author_b
                        .resolve_conflict(
                            &scope_b,
                            target(Some(view.2)),
                            &[y.claim.id],
                            None,
                            &fleet.key(&format!("{round}/concede")),
                        )
                        .await
                };
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
                let (conceded, recorded) = tokio::join!(concede, record_z);
                let z = recorded.expect("the racing record commits");
                let outcome = match conceded {
                    Ok(mutation) => {
                        assert_eq!(mutation.claims_retracted, [y.claim.id]);
                        assert_eq!(fleet.claim(y.claim.id).await.state, ClaimState::Retracted);
                        ConcessionRace::ConcededThenReopened
                    }
                    Err(FleetError::LifecycleRefused(refusal))
                        if refusal.code == RefusalCode::StaleMemberCount =>
                    {
                        assert_eq!(fleet.claim(y.claim.id).await.state, ClaimState::Disputed);
                        ConcessionRace::JoinedFirst
                    }
                    Err(error) => panic!("round {round}: unexpected concession failure: {error}"),
                };
                outcomes.push(outcome);
                // Either order leaves x and z disagreeing in the open lineage.
                assert_eq!(fleet.conflict_row(conflict_id).await.0, "open");
                assert_eq!(fleet.claim(x.claim.id).await.state, ClaimState::Disputed);
                assert_eq!(fleet.claim(z.claim.id).await.state, ClaimState::Disputed);
            }
            1 => {
                // The same agent acknowledges twice at once under two keys.
                let first = async {
                    barrier.wait().await;
                    author_a
                        .acknowledge_conflict(
                            &scope_a,
                            target(None),
                            None,
                            &fleet.key(&format!("{round}/ack-1")),
                        )
                        .await
                };
                let again = async {
                    barrier.wait().await;
                    author_a2
                        .acknowledge_conflict(
                            &scope_a,
                            target(None),
                            None,
                            &fleet.key(&format!("{round}/ack-2")),
                        )
                        .await
                };
                let (first, again) = tokio::join!(first, again);
                let applied = [first.unwrap(), again.unwrap()]
                    .iter()
                    .filter(|mutation| mutation.applied)
                    .count();
                assert_eq!(applied, 1, "round {round}: one acknowledgement per episode");
                assert_eq!(fleet.lifecycle_log(conflict_id).await.len(), 1);
            }
            _ => {
                // C acknowledges while B concedes: the acknowledgement either
                // lands in the open episode or is refused as not open.
                let acknowledge = async {
                    barrier.wait().await;
                    author_c
                        .acknowledge_conflict(
                            &scope_c,
                            target(None),
                            None,
                            &fleet.key(&format!("{round}/ack")),
                        )
                        .await
                };
                let concede = async {
                    barrier.wait().await;
                    author_b
                        .resolve_conflict(
                            &scope_b,
                            target(Some(view.2)),
                            &[y.claim.id],
                            None,
                            &fleet.key(&format!("{round}/concede")),
                        )
                        .await
                };
                let (acknowledged, conceded) = tokio::join!(acknowledge, concede);
                conceded.expect("an acknowledgement never blocks a concession");
                let log = fleet.lifecycle_log(conflict_id).await;
                match acknowledged {
                    Ok(mutation) => {
                        assert!(mutation.applied);
                        assert_eq!(
                            log.iter().map(|event| event.1.as_str()).collect::<Vec<_>>(),
                            ["acknowledged", "resolved"]
                        );
                    }
                    Err(FleetError::LifecycleRefused(refusal))
                        if refusal.code == RefusalCode::NotOpen =>
                    {
                        assert_eq!(log.len(), 1);
                        assert_eq!(log[0].1, "resolved");
                    }
                    Err(error) => panic!("round {round}: unexpected acknowledge failure: {error}"),
                }
                assert_eq!(fleet.conflict_row(conflict_id).await.0, "resolved");
            }
        }
    }
    assert!(!outcomes.is_empty());
    fleet.assert_lifecycle_invariants().await;

    second.pool().close().await;
    fleet.cleanup().await;
}

// ---------------------------------------------------------------------------
// Slice 4: adjudication (`dismiss` and `waive` by an agent that authored none
// of a conflict's members) and dismissed-pair exclusion.
// ---------------------------------------------------------------------------

const fn false_positive(rationale: &str) -> DismissalTerms<'_> {
    DismissalTerms {
        reason_kind: DismissalReasonKindV1::FalsePositive,
        rationale,
    }
}

const fn capacity_deferred(
    rationale: &str,
    expires_in_hours: u16,
    review_in_hours: Option<u16>,
) -> WaiverTerms<'_> {
    WaiverTerms {
        reason_kind: WaiverReasonKindV1::CapacityDeferred,
        rationale,
        expires_in_hours,
        review_in_hours,
    }
}

const DISMISSAL_RATIONALE: &str = "the two values describe different deployments";
const WAIVER_RATIONALE: &str = "the migration review is scheduled for the next window";

impl Fleet {
    /// `agent`'s ledger on a deployment that enabled adjudication.
    fn adjudicating_ledger(&self, agent: &str) -> CockroachClaimLedger {
        self.conflict_ledger(agent).with_conflict_adjudication()
    }

    /// The private writer of a deployment that enabled adjudication.
    fn adjudicating_service(&self, agent: &str) -> CockroachMemoryService {
        CockroachMemoryService::new(
            self.scope(agent),
            Arc::new(self.store.clone()),
            Arc::new(self.adjudicating_ledger(agent)),
            Arc::new(UnitEmbedder),
        )
        .expect("memory service")
        .with_lifecycle(ADJUDICATING_WRITER)
    }

    const fn conflict_target(conflict: (i64, i64, i64)) -> ConflictTarget {
        let (conflict_id, expected_revision, expected_member_count) = conflict;
        ConflictTarget {
            conflict_id,
            expected_revision,
            expected_member_count: Some(expected_member_count),
        }
    }

    async fn dismiss(
        &self,
        agent: &str,
        conflict: (i64, i64, i64),
        key: &str,
    ) -> ostk_fleet_recall::Result<ConflictMutation> {
        self.adjudicating_ledger(agent)
            .dismiss_conflict(
                &self.scope(agent),
                Self::conflict_target(conflict),
                false_positive(DISMISSAL_RATIONALE),
                &self.key(key),
            )
            .await
    }

    async fn waive(
        &self,
        agent: &str,
        conflict: (i64, i64, i64),
        expires_in_hours: u16,
        key: &str,
    ) -> ostk_fleet_recall::Result<ConflictMutation> {
        self.adjudicating_ledger(agent)
            .waive_conflict(
                &self.scope(agent),
                Self::conflict_target(conflict),
                capacity_deferred(WAIVER_RATIONALE, expires_in_hours, Some(1)),
                &self.key(key),
            )
            .await
    }

    /// `(state, revision, resolution_kind, resolution_reason)` of a conflict row.
    async fn conflict_resolution(
        &self,
        conflict_id: i64,
    ) -> (String, i64, Option<String>, Option<String>) {
        sqlx::query_as(
            "SELECT state, revision, resolution_kind, resolution_reason FROM memory_conflicts \
             WHERE tenant_id = $1 AND project = $2 AND id = $3",
        )
        .bind(self.tenant)
        .bind(&self.project)
        .bind(conflict_id)
        .fetch_one(self.pool())
        .await
        .unwrap()
    }

    async fn add_member(&self, conflict_id: i64, claim_id: i64) {
        sqlx::query(
            "INSERT INTO memory_conflict_members (tenant_id, project, conflict_id, claim_id) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(self.tenant)
        .bind(&self.project)
        .bind(conflict_id)
        .bind(claim_id)
        .execute(self.pool())
        .await
        .unwrap();
    }
}

fn dismiss_arguments(conflict: (i64, i64, i64)) -> Map<String, Value> {
    let (conflict_id, expected_revision, expected_member_count) = conflict;
    Map::from_iter([
        ("conflict_id".into(), json!(conflict_id)),
        ("expected_revision".into(), json!(expected_revision)),
        ("expected_member_count".into(), json!(expected_member_count)),
        ("reason_kind".into(), json!("false_positive")),
        ("rationale".into(), json!(DISMISSAL_RATIONALE)),
    ])
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // the gates, the dismissal, and its reads on one fixture
async fn live_dismiss_requires_enabled_non_implicated_adjudicator_when_configured() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fleet = Fleet::new(&database_url, "dismiss").await;
    let (x, y, conflict_id) = two_party(&fleet, "dismiss").await;
    let view = fleet.conflict_view(conflict_id).await;
    let before = fleet.conflict_resolution(conflict_id).await;
    let scope_c = fleet.scope(AGENT_C);

    // Adjudication is off by default: the fully probed writer refuses it,
    // with or without a key, and so does a ledger the deployment did not
    // enable. Nothing is written and the key stays free.
    let full = fleet.full_service(AGENT_C);
    for key in [None, Some(fleet.key("c/disabled"))] {
        let result = FleetMemoryService::remember(
            &full,
            scope_c.clone(),
            RememberRequest::new(RememberAction::Dismiss, key, dismiss_arguments(view)),
        )
        .await;
        assert_eq!(refusal_code(result), "adjudication_disabled");
    }
    let disabled = refusal(
        fleet
            .conflict_ledger(AGENT_C)
            .dismiss_conflict(
                &scope_c,
                Fleet::conflict_target(view),
                false_positive(DISMISSAL_RATIONALE),
                &fleet.key("c/disabled"),
            )
            .await,
    );
    assert_eq!(disabled.code, RefusalCode::AdjudicationDisabled);
    fleet.assert_key_unconsumed("c/disabled").await;

    // An author of any member is implicated and may neither dismiss nor
    // waive (AUTH-03).
    for (agent, key) in [(AGENT_A, "a/adjudicate"), (AGENT_B, "b/adjudicate")] {
        let implicated = refusal(fleet.dismiss(agent, view, key).await);
        assert_eq!(implicated.code, RefusalCode::Implicated);
        assert_eq!(implicated.details["implicated_members"], 1);
        let implicated = refusal(fleet.waive(agent, view, 24, key).await);
        assert_eq!(implicated.code, RefusalCode::Implicated);
        fleet.assert_key_unconsumed(key).await;
    }
    // The caller's view of the conflict is checked.
    let stale = refusal(
        fleet
            .dismiss(AGENT_C, (view.0, view.1 + 1, view.2), "c/stale")
            .await,
    );
    assert_eq!(stale.code, RefusalCode::StaleRevision);
    let stale_count = refusal(
        fleet
            .dismiss(AGENT_C, (view.0, view.1, view.2 + 1), "c/stale")
            .await,
    );
    assert_eq!(stale_count.code, RefusalCode::StaleMemberCount);
    assert_eq!(stale_count.details["current_member_count"], view.2);
    fleet.assert_key_unconsumed("c/stale").await;
    assert_eq!(fleet.conflict_resolution(conflict_id).await, before);
    assert!(fleet.lifecycle_log(conflict_id).await.is_empty());

    // An uninvolved agent dismisses the conflict.
    let dismissed = fleet
        .dismiss(AGENT_C, view, "c/dismiss")
        .await
        .expect("an uninvolved adjudicator may dismiss");
    assert_eq!(dismissed.operation, "dismiss");
    assert_eq!(
        (
            dismissed.conflict_state.as_str(),
            dismissed.conflict_revision
        ),
        ("dismissed", view.1 + 1)
    );
    assert_eq!(dismissed.status.as_deref(), Some("dismissed"));
    assert!(dismissed.applied);
    assert_eq!(dismissed.member_count, view.2);
    assert_eq!(dismissed.claims_restored, [x.claim.id, y.claim.id]);
    assert!(dismissed.claims_retracted.is_empty());
    let event = dismissed
        .lifecycle_event
        .as_ref()
        .expect("a dismissed event");
    assert_eq!(
        (
            event.kind.as_str(),
            event.actor_kind.as_str(),
            event.actor.as_str(),
            event.operation.as_str()
        ),
        ("dismissed", "agent", AGENT_C, "conflict_dismiss")
    );
    assert_eq!(event.reason_kind.as_deref(), Some("false_positive"));
    assert_eq!(event.rationale.as_deref(), Some(DISMISSAL_RATIONALE));
    assert_eq!(
        (event.episode_revision, event.result_revision),
        (view.1, view.1 + 1)
    );
    assert_eq!(
        event.payload.as_ref().unwrap()["dismissed_pairs"],
        json!([[x.claim.id, y.claim.id]])
    );
    // The conflict row names the closed reason vocabulary; the rationale
    // stays in the private lifecycle log.
    let (row_state, revision, kind, reason) = fleet.conflict_resolution(conflict_id).await;
    assert_eq!((row_state.as_str(), revision), ("dismissed", view.1 + 1));
    assert_eq!(kind.as_deref(), Some("dismissed:false_positive"));
    assert!(!reason.unwrap().contains(DISMISSAL_RATIONALE));
    // Both members return to active, and nothing else about them changes
    // (DISC-03).
    for claim in [&x.claim, &y.claim] {
        let now = fleet.claim(claim.id).await;
        assert_eq!(now.state, ClaimState::Active);
        assert_eq!(
            (now.value.as_ref(), now.actor.as_deref(), now.superseded_by),
            (claim.value.as_ref(), claim.actor.as_deref(), None)
        );
        let transitions = fleet.transitions(claim.id).await;
        let last = transitions.last().unwrap();
        assert_eq!(
            (last.0.as_str(), last.1.as_str(), last.2.as_str()),
            ("conflict_dismissed", "disputed", "active")
        );
    }
    let keyed = fleet.keyed_events("c/dismiss").await;
    assert_eq!(keyed.len(), 1);
    assert_eq!(keyed[0].0, "conflict_dismissed");

    // The key replays its stored result, and serves no other mutation.
    let replay = fleet.dismiss(AGENT_C, view, "c/dismiss").await.unwrap();
    assert!(replay.idempotent_replay);
    assert_eq!(
        ConflictMutation {
            idempotent_replay: false,
            ..replay
        },
        dismissed
    );
    assert!(matches!(
        fleet.waive(AGENT_C, view, 24, "c/dismiss").await,
        Err(FleetError::IdempotencyConflict(_))
    ));
    // A writer that no longer serves adjudication still replays it.
    let replayed = FleetMemoryService::remember(
        &full,
        scope_c.clone(),
        RememberRequest::new(
            RememberAction::Dismiss,
            Some(fleet.key("c/dismiss")),
            dismiss_arguments(view),
        ),
    )
    .await
    .expect("a committed dismissal replays where adjudication is off");
    assert_eq!(replayed.data["idempotent_replay"], true);
    assert_eq!(replayed.data["conflict_state"], "dismissed");
    assert_eq!(replayed.conflicts[0]["lifecycle"]["state"], "dismissed");
    // A dismissed conflict is closed to further adjudication.
    let closed = (view.0, view.1 + 1, view.2);
    for result in [
        fleet.dismiss(AGENT_C, closed, "c/again").await,
        fleet.waive(AGENT_C, closed, 24, "c/again").await,
    ] {
        let refused = refusal(result);
        assert_eq!(refused.code, RefusalCode::NotOpen);
        assert_eq!(refused.details["current_state"], "dismissed");
    }
    fleet.assert_key_unconsumed("c/again").await;

    // Reads name the adjudicator and keep the rationale in history.
    let service = fleet.adjudicating_service(AGENT_C);
    let lookup = get_conflict(&service, &scope_c, conflict_id).await;
    let lifecycle = &lookup.data["conflict"]["lifecycle"];
    assert_eq!(lifecycle["state"], "dismissed");
    assert_eq!(lifecycle["read_side"], "clear");
    assert_eq!(lifecycle["closed_unlogged"], false);
    assert_eq!(
        lifecycle["closed_by"],
        json!({
            "actor_kind": "agent",
            "actor": AGENT_C,
            "operation": "conflict_dismiss",
            "reason_kind": "false_positive",
            "at": lifecycle["closed_by"]["at"],
        })
    );
    let history = lookup.data["history"].as_array().unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0]["rationale"], DISMISSAL_RATIONALE);
    assert_eq!(lookup.data["unlogged_transitions"], json!([]));

    // A member with no recorded author could be anyone's, so no agent can be
    // shown to be uninvolved: the adjudication fails closed.
    let (_, _, anonymous_conflict) = two_party(&fleet, "dismiss-unattributed").await;
    let anonymous = fleet
        .raw_claim(
            &fleet.project,
            "dismiss-unattributed",
            "note",
            "operator_asserted",
            None,
        )
        .await;
    fleet.add_member(anonymous_conflict, anonymous).await;
    let anonymous_view = fleet.conflict_view(anonymous_conflict).await;
    assert_eq!(anonymous_view.2, 3);
    let unattributed = refusal(
        fleet
            .dismiss(AGENT_C, anonymous_view, "c/unattributed")
            .await,
    );
    assert_eq!(unattributed.code, RefusalCode::UnattributedMember);
    assert_eq!(unattributed.details["unattributed_members"], 1);
    let unattributed = refusal(
        fleet
            .waive(AGENT_C, anonymous_view, 24, "c/unattributed")
            .await,
    );
    assert_eq!(unattributed.code, RefusalCode::UnattributedMember);
    fleet.assert_key_unconsumed("c/unattributed").await;

    // Over MCP, an adjudicating writer advertises both actions, and an
    // implicated author's dismissal is invalid_params and not applied.
    let server = McpServer::new(
        Arc::new(fleet.adjudicating_service(AGENT_A)),
        fleet.scope(AGENT_A),
    )
    .unwrap();
    let listed = server
        .handle_value(json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}))
        .await
        .unwrap()
        .result
        .unwrap();
    let actions = &listed["tools"][1]["inputSchema"]["properties"]["action"]["enum"];
    assert!(actions.as_array().unwrap().contains(&json!("dismiss")));
    assert!(actions.as_array().unwrap().contains(&json!("waive")));
    let mut arguments = dismiss_arguments(anonymous_view);
    arguments.insert("action".into(), json!("dismiss"));
    arguments.insert("idempotency_key".into(), json!(fleet.key("a/mcp-dismiss")));
    let response = server
        .handle_value(json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": { "name": "remember", "arguments": arguments },
        }))
        .await
        .unwrap();
    let error = response.error.expect("an implicated dismissal is refused");
    assert_eq!(error.code, -32602);
    let data = error.data.unwrap();
    assert_eq!(data["code"], "implicated");
    assert_eq!(data["outcome"], "not_applied");
    fleet.assert_key_unconsumed("a/mcp-dismiss").await;

    fleet.assert_lifecycle_invariants().await;
    fleet.cleanup().await;
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // three reopen shapes after one dismissal each
async fn live_dismissed_pair_does_not_keep_reopened_conflict_open_when_configured() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fleet = Fleet::new(&database_url, "dismissed-pair").await;

    // Dismiss x/y, then D's z reopens the conflict and disputes x and y again.
    let (x, y, conflict_id) = two_party(&fleet, "dismissed-retract").await;
    let view = fleet.conflict_view(conflict_id).await;
    fleet.dismiss(AGENT_C, view, "c/dismiss").await.unwrap();
    let z = fleet
        .record(
            AGENT_D,
            &decision("dismissed-retract", &json!("z"), 1),
            "d/z",
        )
        .await;
    assert_eq!(z.conflicts_opened, [conflict_id]);
    let reopened = fleet.conflict_row(conflict_id).await;
    assert_eq!(reopened, ("open".to_owned(), view.1 + 2));
    assert_eq!(fleet.claim(x.claim.id).await.state, ClaimState::Disputed);

    // Once D retracts z, only the dismissed pair is left, so the detector
    // closes the conflict instead of re-arguing it.
    let retracted = fleet
        .conflict_ledger(AGENT_D)
        .retract_claim(
            &fleet.scope(AGENT_D),
            ClaimTarget {
                claim_id: z.claim.id,
                expected_revision: fleet.claim(z.claim.id).await.revision,
            },
            None,
            &fleet.key("d/retract"),
        )
        .await
        .unwrap();
    assert_eq!(retracted.conflicts_resolved, [conflict_id]);
    assert_eq!(retracted.claims_restored, [x.claim.id, y.claim.id]);
    let reevaluation = retracted.reevaluation.as_ref().unwrap();
    assert_eq!(reevaluation.outcome, "closed");
    assert_eq!(reevaluation.excluded_dismissed_pairs, 1);
    // x and y are both current and still incompatible to the detector, so
    // the close must not claim that no current incompatibility remains, on
    // the row or on any read of it.
    let (state, _, kind, reason) = fleet.conflict_resolution(conflict_id).await;
    assert_eq!(state, "resolved");
    assert_eq!(kind.as_deref(), Some("no_undismissed_incompatibility"));
    assert!(
        reason
            .unwrap()
            .contains("1 pair(s) an adjudicator dismissed")
    );
    let read = fleet.conflict(conflict_id).await;
    assert_eq!(
        read.resolution_kind.as_deref(),
        Some("no_undismissed_incompatibility")
    );
    for claim in [x.claim.id, y.claim.id] {
        assert_eq!(fleet.claim(claim).await.state, ClaimState::Active);
    }
    let log = fleet.lifecycle_log(conflict_id).await;
    assert_eq!(
        log.iter().map(|event| event.1.as_str()).collect::<Vec<_>>(),
        ["dismissed", "resolved"]
    );
    assert_eq!(log[1].8["excluded_dismissed_pairs"], 1);

    // A pair nobody dismissed still keeps the conflict open: after the same
    // reopen, A's retract of x leaves y against z.
    let (x, y, conflict_id) = two_party(&fleet, "dismissed-new-pair").await;
    let view = fleet.conflict_view(conflict_id).await;
    fleet.dismiss(AGENT_C, view, "c/dismiss-2").await.unwrap();
    let z = fleet
        .record(
            AGENT_D,
            &decision("dismissed-new-pair", &json!("z"), 1),
            "d/z-2",
        )
        .await;
    let still_open = fleet
        .conflict_ledger(AGENT_A)
        .retract_claim(
            &fleet.scope(AGENT_A),
            ClaimTarget {
                claim_id: x.claim.id,
                expected_revision: fleet.claim(x.claim.id).await.revision,
            },
            None,
            &fleet.key("a/retract-2"),
        )
        .await
        .unwrap();
    let reevaluation = still_open.reevaluation.as_ref().unwrap();
    assert_eq!(reevaluation.outcome, "still_open");
    assert_eq!(reevaluation.remaining_pairs, [[y.claim.id, z.claim.id]]);
    assert_eq!(reevaluation.excluded_dismissed_pairs, 0);
    assert_eq!(fleet.conflict_row(conflict_id).await.0, "open");

    // A writer without the lifecycle log cannot read dismissals, so it
    // excludes none: the conservative outcome keeps the conflict open. A
    // re-verification on a writer with the log closes it, even one that does
    // not serve dismiss itself: recorded dismissals count wherever they can
    // be read, as every conflict surface's resolve text says.
    let (_, _, conflict_id) = two_party(&fleet, "dismissed-unprobed").await;
    let view = fleet.conflict_view(conflict_id).await;
    fleet.dismiss(AGENT_C, view, "c/dismiss-3").await.unwrap();
    let z = fleet
        .record(
            AGENT_D,
            &decision("dismissed-unprobed", &json!("z"), 1),
            "d/z-3",
        )
        .await;
    let unprobed = fleet
        .retract(
            AGENT_D,
            z.claim.id,
            fleet.claim(z.claim.id).await.revision,
            "d/retract-3",
        )
        .await
        .unwrap();
    let reevaluation = unprobed.reevaluation.as_ref().unwrap();
    assert_eq!(reevaluation.outcome, "still_open");
    assert_eq!(reevaluation.excluded_dismissed_pairs, 0);
    let reopened = fleet.conflict_view(conflict_id).await;
    let verified = fleet
        .resolve(AGENT_C, reopened, &[], "c/verify-3")
        .await
        .expect("re-verification leaves out the dismissed pair");
    assert_eq!(verified.conflict_state, "resolved");
    assert_eq!(
        verified
            .reevaluation
            .as_ref()
            .unwrap()
            .excluded_dismissed_pairs,
        1
    );
    let event = verified.lifecycle_event.as_ref().unwrap();
    assert_eq!(
        event.payload.as_ref().unwrap()["excluded_dismissed_pairs"],
        1
    );
    // The log's CHECK fixes a detector close's reason kind; the row names the
    // exclusion instead.
    assert_eq!(
        event.reason_kind.as_deref(),
        Some("no_current_incompatibility")
    );
    assert_eq!(
        fleet.conflict_resolution(conflict_id).await.2.as_deref(),
        Some("no_undismissed_incompatibility")
    );

    fleet.assert_lifecycle_invariants().await;
    fleet.cleanup().await;
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // one waiver's whole read-side life
async fn live_waiver_expires_and_voids_on_member_join_when_configured() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fleet = Fleet::new(&database_url, "waive").await;
    let (x, y, conflict_id) = two_party(&fleet, "waive").await;
    let view = fleet.conflict_view(conflict_id).await;
    let before = fleet.conflict_resolution(conflict_id).await;
    let x_before = fleet.claim(x.claim.id).await;

    let waived = fleet
        .adjudicating_ledger(AGENT_C)
        .waive_conflict(
            &fleet.scope(AGENT_C),
            Fleet::conflict_target(view),
            capacity_deferred(WAIVER_RATIONALE, 72, Some(24)),
            &fleet.key("c/waive"),
        )
        .await
        .expect("an uninvolved adjudicator may waive");
    assert_eq!(waived.operation, "waive");
    assert_eq!(waived.status.as_deref(), Some("waived"));
    assert_eq!(
        (waived.conflict_state.as_str(), waived.conflict_revision),
        ("open", view.1)
    );
    let event = waived.lifecycle_event.as_ref().unwrap();
    assert_eq!(event.kind, "waived");
    assert_eq!(event.reason_kind.as_deref(), Some("capacity_deferred"));
    assert_eq!(event.member_count, view.2);
    // The database clock sets the expiry and review time.
    assert_eq!(
        event.expires_at.unwrap() - event.created_at,
        chrono::Duration::hours(72)
    );
    assert_eq!(
        event.review_by.unwrap() - event.created_at,
        chrono::Duration::hours(24)
    );
    // A waiver changes no row: the conflict and its members are as they were.
    assert_eq!(fleet.conflict_resolution(conflict_id).await, before);
    assert_eq!(fleet.claim(x.claim.id).await, x_before);
    assert_eq!(fleet.keyed_events("c/waive").await[0].0, "conflict_waived");

    // A waived conflict still surfaces, with its waiver's context (DISC-04).
    let service = fleet.adjudicating_service(AGENT_C);
    let scope = fleet.scope(AGENT_C);
    let listed = recall(&service, &scope, RecallAction::Conflicts, json!({}))
        .await
        .unwrap();
    let lifecycle = &listed.conflicts[0]["lifecycle"];
    assert_eq!(listed.conflicts[0]["id"], conflict_id);
    assert_eq!(lifecycle["state"], "waived");
    assert_eq!(lifecycle["read_side"], "waived");
    let context = &lifecycle["waiver"];
    assert_eq!(context["actor"], AGENT_C);
    assert_eq!(context["reason_kind"], "capacity_deferred");
    assert_eq!(context["rationale"], WAIVER_RATIONALE);
    assert_eq!(context["active"], true);
    assert_eq!(context["review_due"], false);
    assert_eq!(context["void_reason"], Value::Null);
    let searched = recall(
        &service,
        &scope,
        RecallAction::Search,
        json!({ "query": "lifecycle fixture waive", "kind": "claim" }),
    )
    .await
    .unwrap();
    assert!(
        searched
            .conflicts
            .iter()
            .any(|conflict| conflict["id"] == conflict_id
                && conflict["lifecycle"]["read_side"] == "waived"),
        "claim search surfaces the waived conflict"
    );
    let claim_lookup = recall(
        &service,
        &scope,
        RecallAction::Get,
        json!({ "kind": "claim", "id": y.claim.id }),
    )
    .await
    .unwrap();
    assert_eq!(claim_lookup.conflicts[0]["lifecycle"]["state"], "waived");

    // Seventy-three hours later the waiver has lapsed: the same episode reads
    // open again, and the waiver stays as context.
    sqlx::query(
        "UPDATE memory_conflict_lifecycle_events_v1 \
         SET created_at = created_at - INTERVAL '73 hours', \
             expires_at = expires_at - INTERVAL '73 hours', \
             review_by = review_by - INTERVAL '73 hours' \
         WHERE tenant_id = $1 AND project = $2 AND conflict_id = $3",
    )
    .bind(fleet.tenant)
    .bind(&fleet.project)
    .bind(conflict_id)
    .execute(fleet.pool())
    .await
    .unwrap();
    let lookup = get_conflict(&service, &scope, conflict_id).await;
    let lifecycle = &lookup.data["conflict"]["lifecycle"];
    assert_eq!(lifecycle["state"], "open");
    assert_eq!(lifecycle["read_side"], "open");
    assert_eq!(lifecycle["episode_revision"], view.1);
    assert_eq!(lifecycle["waiver"]["active"], false);
    assert_eq!(lifecycle["waiver"]["void_reason"], "expired");
    assert_eq!(lifecycle["waiver"]["reason_kind"], "capacity_deferred");

    // A new waiver applies again, until a member joins: the waiver covered
    // the members it was granted against, not the newcomer.
    fleet
        .waive(AGENT_C, view, 72, "c/waive-again")
        .await
        .unwrap();
    let lookup = get_conflict(&service, &scope, conflict_id).await;
    assert_eq!(lookup.data["conflict"]["lifecycle"]["state"], "waived");
    fleet
        .record(AGENT_D, &decision("waive", &json!("z"), 1), "d/z")
        .await;
    let joined = fleet.conflict_view(conflict_id).await;
    assert_eq!((joined.1, joined.2), (view.1, view.2 + 1));
    let lookup = get_conflict(&service, &scope, conflict_id).await;
    let lifecycle = &lookup.data["conflict"]["lifecycle"];
    assert_eq!(lifecycle["state"], "open");
    assert_eq!(lifecycle["read_side"], "open");
    assert_eq!(lifecycle["waiver"]["active"], false);
    assert_eq!(lifecycle["waiver"]["void_reason"], "membership_changed");
    assert_eq!(lifecycle["waiver"]["member_count"], view.2);

    // D is now implicated too; the stale view is refused either way.
    let implicated = refusal(fleet.waive(AGENT_D, joined, 24, "d/waive").await);
    assert_eq!(implicated.code, RefusalCode::Implicated);
    let stale = refusal(fleet.waive(AGENT_C, view, 24, "c/stale").await);
    assert_eq!(stale.code, RefusalCode::StaleMemberCount);
    fleet.assert_key_unconsumed("d/waive").await;
    fleet.assert_key_unconsumed("c/stale").await;
    fleet.assert_lifecycle_invariants().await;

    // More acknowledgements than the overlay reads, all newer than the
    // waiver, do not hide it: the conflict still reads waived.
    let (_, _, crowded) = two_party(&fleet, "waive-crowded").await;
    let crowded_view = fleet.conflict_view(crowded).await;
    fleet
        .waive(AGENT_C, crowded_view, 72, "c/waive-crowded")
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO memory_conflict_lifecycle_events_v1 (\
             tenant_id, project, conflict_id, event_seq, event_kind, episode_revision, \
             result_revision, from_state, to_state, actor_kind, actor, operation, \
             idempotency_key, member_count\
         ) SELECT $1, $2, $3, seq, 'acknowledged', $4, $4, 'open', 'open', 'agent', \
                  'seeded-agent-' || seq::STRING, 'conflict_acknowledge', \
                  $2 || '/seeded-crowd/' || seq::STRING, 2 \
           FROM generate_series(2, 41) AS seq",
    )
    .bind(fleet.tenant)
    .bind(&fleet.project)
    .bind(crowded)
    .bind(crowded_view.1)
    .execute(fleet.pool())
    .await
    .unwrap();
    let lookup = get_conflict(&service, &scope, crowded).await;
    let lifecycle = &lookup.data["conflict"]["lifecycle"];
    assert_eq!(lifecycle["state"], "waived");
    assert_eq!(lifecycle["read_side"], "waived");
    assert_eq!(lifecycle["waiver"]["actor"], AGENT_C);
    assert_eq!(lifecycle["acknowledgers_truncated"], true);

    fleet.cleanup().await;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdjudicationRace {
    /// The dismissal committed first; the racing record reopened the lineage.
    DismissedThenReopened,
    /// The record joined first; the dismissal saw a stale member count.
    JoinedFirst,
    /// The dismissal committed first; the owner's retract read a revision
    /// the dismissal's restore had moved.
    DismissedThenRetracted,
    /// The retract closed the conflict first; the dismissal found it closed.
    RetractedFirst,
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // two race shapes share one fixture and one invariant check
async fn live_concurrent_dismiss_and_join_refuses_stale_member_count_when_configured() {
    let Some(database_url) = database_url() else {
        return;
    };
    let fleet = Fleet::new(&database_url, "adjudication-race").await;
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
    let policy = RetryPolicy {
        max_attempts: 32,
        ..RetryPolicy::default()
    };
    let adjudicator = fleet
        .ledger_on(fleet.pool(), AGENT_C, policy)
        .with_conflict_lifecycle(fleet.conflict_lifecycle)
        .with_conflict_adjudication();
    let (joiner, owner) = (
        fleet.ledger_on(second.pool(), AGENT_D, policy),
        fleet
            .ledger_on(second.pool(), AGENT_A, policy)
            .with_conflict_lifecycle(fleet.conflict_lifecycle),
    );
    let (scope_a, scope_c, scope_d) = (
        fleet.scope(AGENT_A),
        fleet.scope(AGENT_C),
        fleet.scope(AGENT_D),
    );
    let mut outcomes = Vec::new();

    for round in 0..24 {
        let subject = format!("adjudication-race-{round}");
        let (x, y, conflict_id) = two_party(&fleet, &subject).await;
        let view = fleet.conflict_view(conflict_id).await;
        let barrier = Barrier::new(2);
        // Record and retract do more work before their lineage lock, so
        // every other round of each shape starts the dismissal late.
        let stagger = Duration::from_millis(if round % 4 >= 2 { 250 } else { 0 });
        let dismiss = async {
            barrier.wait().await;
            tokio::time::sleep(stagger).await;
            adjudicator
                .dismiss_conflict(
                    &scope_c,
                    Fleet::conflict_target(view),
                    false_positive(DISMISSAL_RATIONALE),
                    &fleet.key(&format!("{round}/dismiss")),
                )
                .await
        };
        if round % 2 == 0 {
            // D records a third value while C dismisses.
            let record_z = async {
                barrier.wait().await;
                joiner
                    .record_claim(
                        &scope_d,
                        &decision(&subject, &json!("z"), 1),
                        &fleet.key(&format!("{round}/z")),
                    )
                    .await
            };
            let (dismissed, recorded) = tokio::join!(dismiss, record_z);
            let z = recorded.expect("the racing record commits");
            let (state, revision) = fleet.conflict_row(conflict_id).await;
            assert_eq!(state, "open", "round {round}: z keeps the lineage open");
            let outcome = match dismissed {
                Ok(mutation) => {
                    assert_eq!(mutation.conflict_revision, view.1 + 1);
                    assert_eq!(revision, view.1 + 2, "round {round}: z reopened it");
                    assert_eq!(z.conflicts_opened, [conflict_id]);
                    AdjudicationRace::DismissedThenReopened
                }
                Err(FleetError::LifecycleRefused(refusal))
                    if refusal.code == RefusalCode::StaleMemberCount =>
                {
                    assert_eq!(revision, view.1, "round {round}: z joined the open episode");
                    assert!(fleet.lifecycle_log(conflict_id).await.is_empty());
                    AdjudicationRace::JoinedFirst
                }
                Err(error) => panic!("round {round}: unexpected dismissal failure: {error}"),
            };
            outcomes.push(outcome);
            for claim in [x.claim.id, y.claim.id, z.claim.id] {
                assert_eq!(fleet.claim(claim).await.state, ClaimState::Disputed);
            }
        } else {
            // A retracts x while C dismisses: exactly one of them commits.
            // A dismissal first restores x, which moves the revision A read.
            let x_revision = fleet.claim(x.claim.id).await.revision;
            let retract = async {
                barrier.wait().await;
                owner
                    .retract_claim(
                        &scope_a,
                        ClaimTarget {
                            claim_id: x.claim.id,
                            expected_revision: x_revision,
                        },
                        None,
                        &fleet.key(&format!("{round}/retract")),
                    )
                    .await
            };
            let (dismissed, retracted) = tokio::join!(dismiss, retract);
            let (state, _) = fleet.conflict_row(conflict_id).await;
            let outcome = match (dismissed, retracted) {
                (Ok(_), Err(FleetError::LifecycleRefused(refusal)))
                    if refusal.code == RefusalCode::StaleRevision =>
                {
                    assert_eq!(state, "dismissed");
                    assert_eq!(fleet.claim(x.claim.id).await.state, ClaimState::Active);
                    fleet
                        .assert_key_unconsumed(&format!("{round}/retract"))
                        .await;
                    AdjudicationRace::DismissedThenRetracted
                }
                (Err(FleetError::LifecycleRefused(refusal)), Ok(retracted))
                    if refusal.code == RefusalCode::NotOpen =>
                {
                    assert_eq!(state, "resolved");
                    assert_eq!(retracted.conflicts_resolved, [conflict_id]);
                    assert_eq!(fleet.claim(x.claim.id).await.state, ClaimState::Retracted);
                    AdjudicationRace::RetractedFirst
                }
                (dismissed, retracted) => panic!(
                    "round {round}: exactly one of dismiss and retract commits: {dismissed:?} / {retracted:?}"
                ),
            };
            outcomes.push(outcome);
            assert_eq!(fleet.claim(y.claim.id).await.state, ClaimState::Active);
        }
    }
    assert_eq!(outcomes.len(), 24);
    fleet.assert_lifecycle_invariants().await;

    second.pool().close().await;
    fleet.cleanup().await;
}
