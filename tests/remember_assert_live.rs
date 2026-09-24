//! Connected proof for the event-first `remember(action="assert")` at the
//! ledger level (ADR 0002 D3, EVENT-03).
//!
//! Set `FLEET_RECALL_TEST_DATABASE_URL` to a disposable `CockroachDB` 26.2
//! database; every test here is inert otherwise. Each test installs a real
//! generation-2 writer authority into a fresh physical tenant through the
//! shared `tests/common` fixture, so nothing here depends on another test's
//! rows.
//!
//! What it proves is behavior a fleet depends on: an assert commits its
//! accepted event, its claim projection, and its receipt together, all naming
//! one event; a key replays and is never reused for another request; an
//! identical statement under a new key is not written twice; two agents'
//! incompatible assertions open one conflict that the unchanged lifecycle
//! acknowledges, while an intention never conflicts with an attestation; a
//! refusal writes nothing and leaves its key free; the runtime role's
//! existing grants suffice; and `record` is unchanged.

mod common;

use std::sync::Arc;

use chrono::{DateTime, Duration, SubsecRound as _, Utc};
use common::authority::{InstalledAuthority, install_generation_two, retry_policy};
use common::runtime_role::RuntimeProbeRole;
use ostk_fleet_recall::ledger::{
    AssertedClaimMutation, ClaimInput, ClaimKind, ClaimLedger, ClaimState, CockroachClaimLedger,
    ConflictTarget, LifecycleRefusal, RefusalCode,
};
use ostk_fleet_recall::remember_runtime::{EventFirstAssert, RememberAssertInputV1};
use ostk_fleet_recall::store::cockroach::{
    CockroachStore, ConflictLifecycleCapability, EMBEDDING_DIMENSION, probe_conflict_lifecycle,
};
use ostk_fleet_recall::{FleetError, FleetScope};
use ostk_recall_core::{ChunkEmbedder, PrivacyTier};
use serde_json::{Value, json};
use sqlx::PgPool;

const MODEL: &str = "remember-assert-live-512";
const AGENT_A: &str = "agent-a";
const AGENT_B: &str = "agent-b";
const CLAIM_ACCEPTED: &str = "memory.claim.accepted";

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

/// One installed generation-2 physical scope, with the corpus model
/// initialized, that agents A and B assert into.
struct AssertFleet {
    owner: PgPool,
    authority: InstalledAuthority,
    conflict_lifecycle: ConflictLifecycleCapability,
}

impl AssertFleet {
    async fn new(database_url: &str, label: &str) -> Self {
        let owner = common::migrated_pool(database_url).await;
        let authority = install_generation_two(&owner, label).await;
        let store = CockroachStore::from_pool(owner.clone(), authority.scope.clone())
            .expect("the installed scope is a valid store scope");
        store
            .initialize_embedding_model(MODEL)
            .await
            .expect("register the fixture embedding model");
        let capabilities = store.capabilities().await.expect("capabilities");
        let conflict_lifecycle = probe_conflict_lifecycle(&owner, &capabilities)
            .await
            .expect("the capability probe runs")
            .expect("a migrated database's owner may use the lifecycle log");
        Self {
            owner,
            authority,
            conflict_lifecycle,
        }
    }

    fn scope(&self, agent: &str) -> FleetScope {
        FleetScope::new(
            self.authority.scope.tenant_id,
            &self.authority.scope.project,
            agent,
            None,
            PrivacyTier::T1Project,
        )
        .expect("agent scope")
    }

    /// `agent`'s claim ledger over `pool`, without the event-first assert.
    fn plain_ledger(&self, pool: &PgPool, agent: &str) -> CockroachClaimLedger {
        CockroachClaimLedger::new(
            pool.clone(),
            self.scope(agent),
            Arc::new(UnitEmbedder),
            retry_policy(),
        )
        .expect("agent ledger")
    }

    /// `agent`'s claim ledger over `pool`, serving the event-first assert
    /// through a writer-authority runtime started over that same pool.
    async fn assert_ledger(&self, pool: &PgPool, agent: &str) -> CockroachClaimLedger {
        let runtime = self.authority.runtime(pool).await;
        let assert = EventFirstAssert::for_agent(runtime, agent).expect("agent actor");
        self.plain_ledger(pool, agent)
            .with_event_first_assert(Arc::new(assert))
            .expect("the authority is bound to the ledger's scope and agent")
    }

    /// The owner's ledger for `agent`, serving assert and the conflict
    /// lifecycle.
    async fn ledger(&self, agent: &str) -> CockroachClaimLedger {
        self.assert_ledger(&self.owner, agent)
            .await
            .with_conflict_lifecycle(self.conflict_lifecycle)
    }

    async fn scalar_bool(&self, sql: &str, extra: Option<&[u8]>) -> bool {
        let query = sqlx::query_scalar::<_, bool>(sql)
            .bind(self.authority.scope.tenant_id)
            .bind(&self.authority.scope.project);
        match extra {
            Some(bytes) => query.bind(bytes),
            None => query,
        }
        .fetch_one(&self.owner)
        .await
        .unwrap_or_else(|error| panic!("{sql}: {error}"))
    }

    async fn has_claims(&self) -> bool {
        self.scalar_bool(
            "SELECT EXISTS (SELECT 1 FROM memory_claims WHERE tenant_id = $1 AND project = $2)",
            None,
        )
        .await
    }

    async fn has_claim_events(&self) -> bool {
        self.scalar_bool(
            "SELECT EXISTS (SELECT 1 FROM memory_evidence_events \
             WHERE tenant_id = $1 AND project = $2 AND event_kind = 'memory.claim.accepted')",
            None,
        )
        .await
    }

    /// Whether any claim event other than `event_id` is in the ledger.
    async fn has_other_claim_events(&self, event_id: &[u8]) -> bool {
        self.scalar_bool(
            "SELECT EXISTS (SELECT 1 FROM memory_evidence_events \
             WHERE tenant_id = $1 AND project = $2 AND event_kind = 'memory.claim.accepted' \
               AND event_id <> $3)",
            Some(event_id),
        )
        .await
    }

    /// The payloads of a claim's `recorded` claim event and its
    /// `claim_recorded` audit event.
    async fn audit_payloads(&self, claim_id: i64) -> (Value, Value) {
        let scope = &self.authority.scope;
        let claim_event = sqlx::query_scalar(
            "SELECT payload FROM memory_claim_events \
             WHERE tenant_id = $1 AND project = $2 AND claim_id = $3 AND event_kind = 'recorded'",
        )
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(claim_id)
        .fetch_one(&self.owner)
        .await
        .expect("the claim's recorded event");
        let recorded = sqlx::query_scalar(
            "SELECT payload FROM memory_events WHERE tenant_id = $1 AND project = $2 \
               AND event_kind = 'claim_recorded' AND entity_id = $3",
        )
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(claim_id.to_string())
        .fetch_one(&self.owner)
        .await
        .expect("the claim_recorded audit event");
        (claim_event, recorded)
    }

    async fn has_receipt(&self, key: &str) -> bool {
        sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM memory_mutation_receipts \
             WHERE tenant_id = $1 AND idempotency_key = $2)",
        )
        .bind(self.authority.scope.tenant_id)
        .bind(key)
        .fetch_one(&self.owner)
        .await
        .expect("receipt lookup")
    }
}

/// An assertion over the one active route: agent-facing JSON exactly as the
/// MCP input carries it.
fn assertion(value: bool, modality: &str) -> RememberAssertInputV1 {
    serde_json::from_value(json!({
        "kind": "decision",
        "text": format!("remember(assert) allowed is {value} at this commit in production."),
        "modality": modality,
        "value": { "kind": "boolean", "value": value },
        "subject": { "provider_repository_id": "908172635" },
        "applicability": {
            "repository_commit": { "commit_oid": "3d99ec111a583e80533cbbc0c06798bb628e0979" },
            "runtime_environment": { "environment_id": "production" },
        },
    }))
    .expect("the fixture assertion parses as the MCP input")
}

fn attested(value: bool) -> RememberAssertInputV1 {
    assertion(value, "attested")
}

fn event_bytes(asserted: &AssertedClaimMutation) -> Vec<u8> {
    asserted
        .accepted_event
        .event_id
        .digest()
        .as_bytes()
        .to_vec()
}

fn refusal(result: ostk_fleet_recall::Result<AssertedClaimMutation>) -> LifecycleRefusal {
    match result {
        Err(FleetError::LifecycleRefused(refusal)) => *refusal,
        Err(other) => panic!("expected a typed refusal, got {other}"),
        Ok(asserted) => panic!("expected a refusal, got {asserted:?}"),
    }
}

/// A past, whole-second `effective_from`, so an identical input admits an
/// identical statement.
fn pinned_effective_from() -> DateTime<Utc> {
    (Utc::now() - Duration::hours(1)).trunc_subsecs(0)
}

#[tokio::test]
async fn live_assert_appends_event_and_projection_atomically_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let fleet = AssertFleet::new(&database_url, "assert-atomic").await;
    let scope = fleet.scope(AGENT_A);
    let ledger = fleet.ledger(AGENT_A).await;

    let asserted = ledger
        .assert_claim(&scope, &attested(true), "assert-atomic-1")
        .await
        .expect("an admissible assertion commits");
    let claim = &asserted.mutation.claim;
    assert_eq!(asserted.mutation.operation, "assert");
    assert!(!asserted.mutation.idempotent_replay);
    assert_eq!(claim.kind, ClaimKind::Decision);
    assert_eq!(claim.state, ClaimState::Active);
    assert_eq!(claim.origin, "operator_asserted");
    assert_eq!(claim.actor.as_deref(), Some(AGENT_A));
    assert_eq!(
        claim.value,
        Some(json!({ "kind": "boolean", "value": true }))
    );
    assert!(claim.conflict_eligible);
    let claim_key = claim
        .claim_key
        .as_deref()
        .expect("an asserted claim is keyed");
    assert!(claim_key.starts_with("claim-v2:") && claim_key.ends_with(":attested"));
    assert!(claim.valid_from.is_some());

    // The event, the claim row, and the receipt all name one accepted event.
    let event_id = asserted.accepted_event.event_id;
    assert_eq!(
        ledger
            .claim_accepted_event_id(&scope, claim.id)
            .await
            .unwrap(),
        Some(event_id)
    );
    let (event_kind, epoch_id, shard, committed_offset): (String, Vec<u8>, i32, i64) =
        sqlx::query_as(
            "SELECT event_kind, epoch_id, shard, committed_offset FROM memory_evidence_events \
             WHERE tenant_id = $1 AND project = $2 AND event_id = $3",
        )
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(event_bytes(&asserted))
        .fetch_one(&fleet.owner)
        .await
        .expect("the accepted event is in the ledger");
    assert_eq!(event_kind, CLAIM_ACCEPTED);
    assert_eq!(
        epoch_id,
        asserted
            .accepted_event
            .epoch_id
            .digest()
            .as_bytes()
            .to_vec()
    );
    assert_eq!(i64::from(shard), i64::from(asserted.accepted_event.shard));
    assert_eq!(
        u64::try_from(committed_offset).unwrap(),
        asserted.accepted_event.committed_offset
    );
    let (receipt_event, receipt_claim): (Option<Vec<u8>>, Option<i64>) = sqlx::query_as(
        "SELECT accepted_event_id, claim_id FROM memory_mutation_receipts \
         WHERE tenant_id = $1 AND idempotency_key = $2",
    )
    .bind(scope.tenant_id)
    .bind("assert-atomic-1")
    .fetch_one(&fleet.owner)
    .await
    .expect("the receipt committed with the event");
    assert_eq!(receipt_event, Some(event_bytes(&asserted)));
    assert_eq!(receipt_claim, Some(claim.id));

    // Both audit trails name the event too.
    let (claim_event, recorded) = fleet.audit_payloads(claim.id).await;
    assert_eq!(claim_event["accepted_event_id"], json!(event_id));
    assert_eq!(recorded["accepted_event_id"], json!(event_id));
    assert_eq!(recorded["claim_key"], json!(claim_key));

    // The projection reads back like any claim.
    let fetched = ledger
        .get_claim(&scope, claim.id)
        .await
        .unwrap()
        .expect("the asserted claim is readable");
    assert_eq!(fetched.claim_key, claim.claim_key);
    assert_eq!(fetched.subject, claim.subject);
}

#[tokio::test]
async fn live_assert_replays_by_idempotency_key_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let fleet = AssertFleet::new(&database_url, "assert-replay").await;
    let scope = fleet.scope(AGENT_A);
    let ledger = fleet.ledger(AGENT_A).await;

    let first = ledger
        .assert_claim(&scope, &attested(true), "assert-replay-1")
        .await
        .unwrap();
    let replayed = ledger
        .assert_claim(&scope, &attested(true), "assert-replay-1")
        .await
        .expect("the same key and request replay");
    assert!(replayed.mutation.idempotent_replay);
    assert_eq!(replayed.mutation.claim.id, first.mutation.claim.id);
    assert_eq!(replayed.accepted_event, first.accepted_event);
    assert!(
        !fleet.has_other_claim_events(&event_bytes(&first)).await,
        "a replay appends no second accepted event"
    );

    // The key is bound to its request: another assertion under it is refused.
    let reused = ledger
        .assert_claim(&scope, &attested(false), "assert-replay-1")
        .await;
    assert!(
        matches!(reused, Err(FleetError::IdempotencyConflict(_))),
        "{reused:?}"
    );

    // And to its operation: a record key does not replay as an assert.
    ledger
        .record_claim(
            &scope,
            &ClaimInput {
                kind: ClaimKind::Note,
                text: "a recorded note".into(),
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
            },
            "assert-replay-record",
        )
        .await
        .unwrap();
    let crossed = ledger
        .assert_claim(&scope, &attested(true), "assert-replay-record")
        .await;
    assert!(
        matches!(crossed, Err(FleetError::IdempotencyConflict(_))),
        "{crossed:?}"
    );
}

#[tokio::test]
async fn live_concurrent_asserts_under_one_key_commit_once_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let fleet = AssertFleet::new(&database_url, "assert-race").await;
    let scope = fleet.scope(AGENT_A);
    let ledger = fleet.ledger(AGENT_A).await;

    // Each request is admitted at its own server clock, so the two admit
    // different statements; only the key decides which one commits.
    let request = attested(true);
    let (left, right) = tokio::join!(
        ledger.assert_claim(&scope, &request, "assert-race-1"),
        ledger.assert_claim(&scope, &request, "assert-race-1"),
    );
    let (left, right) = (left.unwrap(), right.unwrap());
    assert_eq!(left.mutation.claim.id, right.mutation.claim.id);
    assert_eq!(left.accepted_event, right.accepted_event);
    assert_ne!(
        left.mutation.idempotent_replay, right.mutation.idempotent_replay,
        "exactly one of the two committed; the other replayed its receipt"
    );
    assert!(
        !fleet.has_other_claim_events(&event_bytes(&left)).await,
        "the losing request's accepted event rolled back with its reservation"
    );
}

#[tokio::test]
async fn live_identical_assertion_under_a_new_key_is_already_asserted_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let fleet = AssertFleet::new(&database_url, "assert-duplicate").await;
    let scope = fleet.scope(AGENT_A);
    let ledger = fleet.ledger(AGENT_A).await;
    let mut pinned = attested(true);
    pinned.effective_from = Some(pinned_effective_from());

    let first = ledger
        .assert_claim(&scope, &pinned, "assert-duplicate-1")
        .await
        .unwrap();
    let duplicate = refusal(
        ledger
            .assert_claim(&scope, &pinned, "assert-duplicate-2")
            .await,
    );
    assert_eq!(duplicate.code, RefusalCode::AlreadyAsserted);
    assert_eq!(
        duplicate.details["claim_id"],
        json!(first.mutation.claim.id)
    );
    assert_eq!(
        duplicate.details["accepted_event_id"],
        json!(first.accepted_event.event_id)
    );
    assert!(
        !fleet.has_receipt("assert-duplicate-2").await,
        "the refused key stays unconsumed"
    );

    // The unconsumed key then serves a different assertion.
    let fresh = ledger
        .assert_claim(&scope, &attested(true), "assert-duplicate-2")
        .await
        .expect("the refused key is free");
    assert_ne!(fresh.accepted_event.event_id, first.accepted_event.event_id);
}

#[tokio::test]
async fn live_incompatible_assertions_by_two_agents_open_one_conflict_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let fleet = AssertFleet::new(&database_url, "assert-conflict").await;
    let (scope_a, scope_b) = (fleet.scope(AGENT_A), fleet.scope(AGENT_B));
    let (ledger_a, ledger_b) = (fleet.ledger(AGENT_A).await, fleet.ledger(AGENT_B).await);

    let yes = ledger_a
        .assert_claim(&scope_a, &attested(true), "assert-conflict-a")
        .await
        .unwrap();
    assert!(yes.mutation.conflicts_opened.is_empty());
    let no = ledger_b
        .assert_claim(&scope_b, &attested(false), "assert-conflict-b")
        .await
        .unwrap();
    assert_eq!(
        yes.mutation.claim.claim_key, no.mutation.claim.claim_key,
        "two agents asserting about one repository, commit, and environment share a key"
    );
    let [conflict_id] = no.mutation.conflicts_opened.as_slice() else {
        panic!(
            "the incompatible assertion opens one conflict: {:?}",
            no.mutation.conflicts_opened
        );
    };
    assert_eq!(no.mutation.claim.state, ClaimState::Disputed);
    let states = ledger_a
        .claim_states(&scope_a, &[yes.mutation.claim.id, no.mutation.claim.id])
        .await
        .unwrap();
    assert!(
        states
            .iter()
            .all(|(_, state)| *state == ClaimState::Disputed),
        "{states:?}"
    );

    let conflicts = ledger_a
        .conflicts_for_claim_ids(&scope_a, &[yes.mutation.claim.id, no.mutation.claim.id], 10)
        .await
        .unwrap();
    let [conflict] = conflicts.as_slice() else {
        panic!("both claims belong to one conflict: {conflicts:?}");
    };
    assert_eq!(conflict.id, *conflict_id);
    let mut members = conflict
        .members
        .iter()
        .map(|member| member.id)
        .collect::<Vec<_>>();
    members.sort_unstable();
    let mut expected = vec![yes.mutation.claim.id, no.mutation.claim.id];
    expected.sort_unstable();
    assert_eq!(members, expected);

    // The unchanged conflict lifecycle acts on it.
    let acknowledged = ledger_b
        .acknowledge_conflict(
            &scope_b,
            ConflictTarget {
                conflict_id: conflict.id,
                expected_revision: conflict.revision,
                expected_member_count: None,
            },
            Some("looking into the disagreement"),
            "assert-conflict-ack",
        )
        .await
        .expect("an implicated agent may acknowledge");
    assert!(acknowledged.applied);
    assert_eq!(acknowledged.conflict_state, "open");
}

#[tokio::test]
async fn live_intention_does_not_conflict_with_attestation_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let fleet = AssertFleet::new(&database_url, "assert-modality").await;
    let (scope_a, scope_b) = (fleet.scope(AGENT_A), fleet.scope(AGENT_B));

    let attestation = fleet
        .ledger(AGENT_A)
        .await
        .assert_claim(&scope_a, &attested(true), "assert-modality-a")
        .await
        .unwrap();
    let intention = fleet
        .ledger(AGENT_B)
        .await
        .assert_claim(&scope_b, &assertion(false, "intended"), "assert-modality-b")
        .await
        .unwrap();
    assert!(intention.mutation.conflicts_opened.is_empty());
    assert_eq!(intention.mutation.claim.state, ClaimState::Active);
    assert_ne!(
        attestation.mutation.claim.claim_key,
        intention.mutation.claim.claim_key
    );
    assert!(
        intention
            .mutation
            .claim
            .claim_key
            .as_deref()
            .is_some_and(|key| key.ends_with(":intended"))
    );
    let conflicts = fleet
        .ledger(AGENT_A)
        .await
        .conflicts_for_claim_ids(
            &scope_a,
            &[attestation.mutation.claim.id, intention.mutation.claim.id],
            10,
        )
        .await
        .unwrap();
    assert!(conflicts.is_empty(), "{conflicts:?}");
}

#[tokio::test]
async fn live_unknown_support_event_is_refused_and_writes_nothing_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let fleet = AssertFleet::new(&database_url, "assert-support").await;
    let scope = fleet.scope(AGENT_A);
    let ledger = fleet.ledger(AGENT_A).await;
    let unknown = "1111111111111111111111111111111111111111111111111111111111111111";

    let mut unsupported = attested(true);
    unsupported.support_evidence_event_ids = vec![serde_json::from_value(json!(unknown)).unwrap()];
    let refused = refusal(
        ledger
            .assert_claim(&scope, &unsupported, "assert-support-1")
            .await,
    );
    assert_eq!(refused.code, RefusalCode::SupportEventUnknown);
    assert_eq!(refused.details["unknown_event_ids"], json!([unknown]));

    // An inadmissible assertion is refused before anything is appended too.
    let mut untrimmed = attested(true);
    untrimmed.text.push(' ');
    let inadmissible = refusal(
        ledger
            .assert_claim(&scope, &untrimmed, "assert-support-1")
            .await,
    );
    assert_eq!(inadmissible.code, RefusalCode::AssertionNotAdmitted);
    assert_eq!(inadmissible.details["reason"], json!("text_invalid"));

    // Neither refusal wrote an event, a claim, or a receipt.
    assert!(!fleet.has_claim_events().await);
    assert!(!fleet.has_claims().await);
    assert!(!fleet.has_receipt("assert-support-1").await);

    // The key is free, and an event this project accepted supports a claim.
    let supported_by = ledger
        .assert_claim(&scope, &attested(true), "assert-support-1")
        .await
        .expect("the refused key is free");
    let mut supported = assertion(true, "intended");
    supported.support_evidence_event_ids = vec![supported_by.accepted_event.event_id];
    ledger
        .assert_claim(&scope, &supported, "assert-support-2")
        .await
        .expect("an accepted event in this project is known support");
}

#[tokio::test]
async fn live_assert_runs_under_existing_runtime_grants_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let fleet = AssertFleet::new(&database_url, "assert-grants").await;
    let probe = RuntimeProbeRole::create_claim_writer(&fleet.owner, &database_url).await;
    let (scope_a, scope_b) = (fleet.scope(AGENT_A), fleet.scope(AGENT_B));

    let outcome = async {
        let ledger_a = fleet.assert_ledger(&probe.pool, AGENT_A).await;
        let ledger_b = fleet.assert_ledger(&probe.pool, AGENT_B).await;
        let yes = ledger_a
            .assert_claim(&scope_a, &attested(true), "assert-grants-a")
            .await?;
        let no = ledger_b
            .assert_claim(&scope_b, &attested(false), "assert-grants-b")
            .await?;
        let replayed = ledger_a
            .assert_claim(&scope_a, &attested(true), "assert-grants-a")
            .await?;
        let accepted = ledger_a
            .claim_accepted_event_id(&scope_a, yes.mutation.claim.id)
            .await?;
        Ok::<_, FleetError>((yes, no, replayed, accepted))
    }
    .await;
    probe.drop_role(&fleet.owner).await;

    let (yes, no, replayed, accepted) =
        outcome.expect("assert runs under the runtime role's existing grants");
    assert_eq!(no.mutation.conflicts_opened.len(), 1);
    assert!(replayed.mutation.idempotent_replay);
    assert_eq!(accepted, Some(yes.accepted_event.event_id));
}

#[tokio::test]
async fn live_record_is_unaffected_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let fleet = AssertFleet::new(&database_url, "assert-record").await;
    let scope = fleet.scope(AGENT_A);
    let ledger = fleet.ledger(AGENT_A).await;

    let recorded = ledger
        .record_claim(
            &scope,
            &ClaimInput {
                kind: ClaimKind::Decision,
                text: "the fleet records decisions".into(),
                subject: Some("fleet".into()),
                predicate: Some("records".into()),
                value: Some(json!(true)),
                polarity: 1,
                origin: "operator_asserted".into(),
                actor: None,
                confidence: 1.0,
                valid_from: None,
                valid_to: None,
                support: Vec::new(),
            },
            "assert-record-1",
        )
        .await
        .unwrap();
    let wire = serde_json::to_value(&recorded).unwrap();
    assert!(wire.get("accepted_event").is_none(), "{wire}");
    assert!(wire["claim"].get("accepted_event_id").is_none(), "{wire}");
    let stored: Value = sqlx::query_scalar(
        "SELECT response FROM memory_mutation_receipts \
         WHERE tenant_id = $1 AND idempotency_key = $2",
    )
    .bind(scope.tenant_id)
    .bind("assert-record-1")
    .fetch_one(&fleet.owner)
    .await
    .unwrap();
    assert!(stored.get("accepted_event").is_none(), "{stored}");
    assert_eq!(
        ledger
            .claim_accepted_event_id(&scope, recorded.claim.id)
            .await
            .unwrap(),
        None
    );
    assert!(!fleet.has_claim_events().await, "record appends no event");

    // A ledger without the event-first path refuses assert, before any write.
    let unserved = refusal(
        fleet
            .plain_ledger(&fleet.owner, AGENT_A)
            .assert_claim(&scope, &attested(true), "assert-record-2")
            .await,
    );
    assert_eq!(unserved.code, RefusalCode::AssertUnavailable);
    assert!(!fleet.has_receipt("assert-record-2").await);

    // An authority asserting as another agent is never attached to a ledger.
    let runtime = fleet.authority.runtime(&fleet.owner).await;
    let foreign = EventFirstAssert::for_agent(runtime, AGENT_B).expect("agent actor");
    let attached = fleet
        .plain_ledger(&fleet.owner, AGENT_A)
        .with_event_first_assert(Arc::new(foreign));
    assert!(
        matches!(attached, Err(FleetError::Configuration(_))),
        "{attached:?}"
    );
}
