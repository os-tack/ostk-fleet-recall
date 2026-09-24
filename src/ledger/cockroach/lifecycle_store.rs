//! Serializable claim lifecycle transactions (`retract`, `supersede`) for the
//! `CockroachDB` claim ledger, and the receipt, lock, and verified-close steps
//! the conflict lifecycle (`conflict_store`) shares with them.
//!
//! Every statement is keyed on the trusted `(tenant_id, project)` and locks in
//! the record path's order: the key's conflict lineage rows first, then its
//! lifecycle-current claims in ascending id order. A supersede writes its
//! successor through the same helpers record uses. A refusal is an error from
//! inside the retried closure, so the transaction rolls back with its receipt
//! reservation and the idempotency key stays free.

use std::sync::Arc;

use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use sqlx::postgres::PgRow;
use sqlx::{Row, Transaction};

use super::conflict_store::{
    self, LifecycleEventDraft, acknowledge_request, append_close_event, resolve_request,
};
use super::{
    ClaimPassage, CockroachClaimLedger, MAX_CURRENT_CLAIMS_PER_KEY_COMPARISON, MAX_LEDGER_RESULTS,
    claim_recorded_event_payload, detect_and_observe, fetch_claim, hydrate_conflicts,
    insert_claim_projection, insert_claim_recorded_event, parse_claim_kind, parse_claim_state,
    protocol_error, require_active_model,
};
use crate::ledger::lifecycle::{
    ClaimShape, ConflictRowState, LifecycleRefusal, LockedKeyClaim, MAX_REPORTED_REMAINING_PAIRS,
    OPERATOR_ASSERTED_ORIGIN, Reevaluation, RefusalCode, V2Lineage, check_owner_transition,
    check_successor, classify_lineages, lifecycle_request_identity, plan_reevaluation,
    validate_reason,
};
use crate::ledger::types::PreparedClaim;
use crate::ledger::{
    ClaimInput, ClaimKind, ClaimMutation, ClaimState, ClaimTarget, Conflict,
    ConflictLifecycleEvent, ConflictMutation, ConflictReevaluation,
    FUNCTIONAL_VALUE_CONFLICT_DETECTOR_V2, LifecycleMutation, LifecycleReplayRequest,
    SupersededClaim,
};
use crate::store::cockroach::with_serializable_retry;
use crate::{FleetError, FleetScope, Result};

const RETRACT_OPERATION: &str = "retract";
const SUPERSEDE_OPERATION: &str = "supersede";
pub(super) const ACKNOWLEDGE_OPERATION: &str = "conflict_acknowledge";
pub(super) const RESOLVE_OPERATION: &str = "conflict_resolve";
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 256;
pub(super) const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
/// Every pair among 256 locked claims plus one sentinel row.
const MAX_KEY_INCOMPATIBLE_PAIRS: usize =
    MAX_CURRENT_CLAIMS_PER_KEY_COMPARISON * (MAX_CURRENT_CLAIMS_PER_KEY_COMPARISON - 1) / 2;
const RESOLVED_STATE: &str = "resolved";
const NO_CURRENT_INCOMPATIBILITY: &str = "no_current_incompatibility";

const SELECT_RECEIPT_SQL: &str = "SELECT project, operation, request, response \
     FROM memory_mutation_receipts \
     WHERE tenant_id = $1 AND idempotency_key = $2";
const RESERVE_RECEIPT_SQL: &str = "INSERT INTO memory_mutation_receipts (\
         tenant_id, idempotency_key, project, request, operation\
     ) VALUES ($1, $2, $3, $4, $5) \
     ON CONFLICT (tenant_id, idempotency_key) DO NOTHING \
     RETURNING idempotency_key";
const FINISH_CLAIM_RECEIPT_SQL: &str = "UPDATE memory_mutation_receipts \
     SET claim_id = $6, response = $7 \
     WHERE tenant_id = $1 AND idempotency_key = $2 \
       AND project = $3 AND request = $4 AND operation = $5";

const LIFECYCLE_TARGET_CLAIM_SQL: &str = "SELECT id, kind, claim_key, state, origin, actor, \
            revision, polarity, valid_from, valid_to, conflict_eligible, value \
     FROM memory_claims@primary WHERE tenant_id = $1 AND project = $2 AND id = $3";
const LOCK_LIFECYCLE_TARGET_CLAIM_SQL: &str = "SELECT id, kind, claim_key, state, origin, actor, \
            revision, polarity, valid_from, valid_to, conflict_eligible, value \
     FROM memory_claims@primary WHERE tenant_id = $1 AND project = $2 AND id = $3 \
     FOR UPDATE";
/// The same row set as the record path's detector write probe, so lifecycle
/// and record serialize on one lock before either touches a claim.
const LOCK_LIFECYCLE_LINEAGES_SQL: &str = "SELECT id, CASE detector \
              WHEN 'same_key_functional_value_v2' THEN 2::INT8 \
              WHEN 'same_key_typed_value' THEN 1::INT8 \
              ELSE 0::INT8 END AS detector_class, \
            state, revision \
     FROM memory_conflicts@memory_conflicts_scope_key_detector_unique_idx \
     WHERE tenant_id = $1 AND project = $2 AND claim_key = $3 \
     ORDER BY detector LIMIT 3 FOR UPDATE";
const LOCK_LIFECYCLE_CURRENT_CLAIMS_SQL: &str = "WITH candidate_ids AS MATERIALIZED (\
       SELECT id FROM memory_claims@memory_claims_scope_key_idx \
       WHERE tenant_id = $1 AND project = $2 AND claim_key = $3 \
         AND state IN ('active', 'disputed') \
       ORDER BY state, id LIMIT $4\
     ) \
     SELECT c.id, c.state, c.origin, c.actor, c.revision, c.polarity, c.valid_from, \
            c.valid_to, c.conflict_eligible, c.value \
     FROM candidate_ids AS bounded \
     JOIN memory_claims@primary AS c \
       ON c.tenant_id = $1 AND c.project = $2 AND c.id = bounded.id \
     ORDER BY c.id FOR UPDATE";
/// The database's own pair computation, with the record detector's exact
/// predicate, cross-checked against the Rust pair graph before any close.
const KEY_INCOMPATIBLE_PAIRS_SQL: &str = "WITH candidate_ids AS MATERIALIZED (\
       SELECT id FROM memory_claims@memory_claims_scope_key_idx \
       WHERE tenant_id = $1 AND project = $2 AND claim_key = $3 \
         AND state IN ('active', 'disputed') \
       ORDER BY state, id LIMIT $4\
     ), current_claims AS MATERIALIZED (\
       SELECT c.id, c.value, c.polarity, c.valid_from, c.valid_to \
       FROM candidate_ids AS bounded \
       JOIN memory_claims@primary AS c \
         ON c.tenant_id = $1 AND c.project = $2 AND c.id = bounded.id \
       WHERE c.conflict_eligible\
     ) \
     SELECT a.id, b.id \
     FROM current_claims AS a JOIN current_claims AS b ON a.id < b.id \
     WHERE ((a.polarity = 1 AND b.polarity = 1 AND a.value IS DISTINCT FROM b.value) \
            OR (a.polarity <> b.polarity AND a.value IS NOT DISTINCT FROM b.value)) \
       AND (a.valid_to IS NULL OR b.valid_from IS NULL OR b.valid_from < a.valid_to) \
       AND (b.valid_to IS NULL OR a.valid_from IS NULL OR a.valid_from < b.valid_to) \
     ORDER BY 1, 2 LIMIT $5";
/// The `WHERE` clause repeats every owner-authority predicate the planner
/// already checked against the locked row.
const TRANSITION_OWNED_CLAIM_SQL: &str = "UPDATE memory_claims \
     SET state = $5, revision = revision + 1, updated_at = now() \
     WHERE tenant_id = $1 AND project = $2 AND id = $3 AND revision = $4 \
       AND state IN ('active', 'disputed') AND actor = $6 \
       AND origin = 'operator_asserted' \
     RETURNING revision";
const CLOSE_CONFLICT_SQL: &str = "UPDATE memory_conflicts \
     SET state = $5, resolved_at = now(), resolution_kind = $6, \
         resolution_reason = $7, revision = revision + 1 \
     WHERE tenant_id = $1 AND project = $2 AND id = $3 \
       AND detector = 'same_key_functional_value_v2' AND state = 'open' AND revision = $4 \
     RETURNING revision";
/// A disputed member returns to `active` only when no other open conflict
/// still holds it. The legacy row on the closing lineage's own key (`$5`) is
/// not such a conflict: a key only gains its v2 lineage beside a legacy row
/// through reconciliation, which preserves that row unchanged and hands the
/// key's disputes to v2, exactly as every current-facing read already treats
/// it. Any other open membership, of any detector, still holds the claim.
const RESTORE_DISPUTED_MEMBERS_SQL: &str = "UPDATE memory_claims AS claim \
     SET state = 'active', revision = claim.revision + 1, updated_at = now() \
     WHERE claim.tenant_id = $1 AND claim.project = $2 AND claim.id = ANY($4) \
       AND claim.state = 'disputed' \
       AND EXISTS (\
         SELECT 1 FROM memory_conflict_members@primary AS m \
         WHERE m.tenant_id = $1 AND m.project = $2 AND m.conflict_id = $3 \
           AND m.claim_id = claim.id\
       ) \
       AND NOT EXISTS (\
         SELECT 1 FROM memory_conflict_members@memory_conflict_members_claim_idx AS o \
         JOIN memory_conflicts@primary AS c \
           ON c.tenant_id = o.tenant_id AND c.project = o.project AND c.id = o.conflict_id \
         WHERE o.tenant_id = $1 AND o.project = $2 AND o.claim_id = claim.id \
           AND o.conflict_id <> $3 AND c.state = 'open' \
           AND NOT (c.detector = 'same_key_typed_value' AND c.claim_key = $5)\
       ) \
     RETURNING claim.id, claim.revision";
const INSERT_TRANSITION_EVENT_SQL: &str = "INSERT INTO memory_claim_events (\
         tenant_id, project, claim_id, event_kind, actor, reason, from_state, to_state, payload\
     ) VALUES ($1, $2, $3, 'state_transition', $4, $5, $6, $7, $8)";
/// Link a predecessor this transaction just superseded to its successor.
const SET_SUPERSEDED_BY_SQL: &str = "UPDATE memory_claims SET superseded_by = $4 \
     WHERE tenant_id = $1 AND project = $2 AND id = $3 \
       AND state = 'superseded' AND superseded_by IS NULL \
     RETURNING revision";
/// The one keyed `memory_events` row of a claim lifecycle mutation.
const INSERT_KEYED_CLAIM_EVENT_SQL: &str = "INSERT INTO memory_events (\
         tenant_id, project, agent, session_id, event_kind, entity_kind, \
         entity_id, idempotency_key, payload\
     ) VALUES ($1, $2, $3, $4, $5, 'claim', $6, $7, $8)";
const GET_CONFLICTS_BY_ID_SQL: &str = "SELECT id, project, claim_key, kind, state, detector, \
            rationale, revision, detected_at, last_seen_at, resolved_at, resolution_kind, \
            resolution_reason \
     FROM memory_conflicts@primary \
     WHERE tenant_id = $1 AND project = $2 AND id = ANY($3) ORDER BY id LIMIT $4";
const CLAIM_STATES_SQL: &str = "SELECT id, state FROM memory_claims@primary \
     WHERE tenant_id = $1 AND project = $2 AND id = ANY($3) ORDER BY id LIMIT $4";

/// A stored lifecycle response that can be returned again as a replay.
pub(super) trait Replayable {
    fn mark_replayed(&mut self);
}

impl Replayable for ClaimMutation {
    fn mark_replayed(&mut self) {
        self.idempotent_replay = true;
    }
}

impl Replayable for ConflictMutation {
    fn mark_replayed(&mut self) {
        self.idempotent_replay = true;
    }
}

struct TargetRow {
    claim: LockedKeyClaim,
    kind: ClaimKind,
    claim_key: Option<String>,
}

impl TargetRow {
    fn shape(&self) -> ClaimShape {
        ClaimShape {
            kind: self.kind,
            claim_key: self.claim_key.clone(),
            conflict_eligible: self.claim.conflict_eligible,
        }
    }
}

/// A lifecycle target locked in record's order and checked for owner
/// authority.
struct LockedTarget {
    claim: LockedKeyClaim,
    /// The key the detector compares the target on; `None` when the target is
    /// not conflict-eligible, so no lineage or peer claim was locked.
    conflict_key: Option<String>,
    lineage: Option<V2Lineage>,
    /// The key's other lifecycle-current claims, locked in ascending id order.
    remaining: Vec<LockedKeyClaim>,
}

/// The lineage and lifecycle-current claims of one key, as locked for R8.
struct ReevaluationScope<'a> {
    lineage: Option<V2Lineage>,
    claim_key: &'a str,
    current: &'a [LockedKeyClaim],
}

/// What R8 changed and what it reports.
#[derive(Debug, Default)]
pub(super) struct ReevaluationEffect {
    pub(super) conflicts_resolved: Vec<i64>,
    pub(super) claims_restored: Vec<i64>,
    pub(super) reevaluation: Option<ConflictReevaluation>,
    /// The detector-attributed `resolved` event a logged close appended.
    pub(super) lifecycle_event: Option<ConflictLifecycleEvent>,
}

/// How a detector-verified close is audited. Every close writes its fixed
/// `resolution_reason` template; with the conflict lifecycle capability it
/// also appends a detector-attributed `resolved` event to the lifecycle log.
pub(super) struct CloseAudit<'a> {
    /// The mutation that caused the close: `retract`, `supersede`, or
    /// `conflict_resolve`.
    pub(super) operation: &'a str,
    pub(super) key: &'a str,
    /// Why the key's incompatibility ended, as the event payload's `cause`.
    pub(super) cause: Value,
    /// Append to the lifecycle log (the ledger holds the capability).
    pub(super) log: bool,
}

pub(super) async fn retract_claim(
    ledger: &CockroachClaimLedger,
    scope: &FleetScope,
    target: ClaimTarget,
    reason: Option<&str>,
    idempotency_key: &str,
) -> Result<ClaimMutation> {
    ledger.ensure_scope(scope)?;
    let key = validated_idempotency_key(idempotency_key)?;
    validate_claim_target(target)?;
    if let Some(reason) = reason {
        validate_reason(reason).map_err(FleetError::Memory)?;
    }
    let request = retract_request(scope, target, reason);
    let scope = scope.clone();
    let reason = reason.map(str::to_owned);
    let key = key.to_owned();
    let log_closes = ledger.serves_conflict_lifecycle();
    with_serializable_retry(&ledger.pool, ledger.retry_policy, move |transaction| {
        let scope = scope.clone();
        let reason = reason.clone();
        let key = key.clone();
        let request = request.clone();
        Box::pin(async move {
            retract_once(
                transaction,
                &scope,
                RetractWrite {
                    target,
                    reason: reason.as_deref(),
                    key: &key,
                    request: &request,
                    log_closes,
                },
            )
            .await
        })
    })
    .await
}

/// One retract request, as the retried transaction body sees it.
struct RetractWrite<'a> {
    target: ClaimTarget,
    reason: Option<&'a str>,
    key: &'a str,
    request: &'a Value,
    log_closes: bool,
}

/// The canonical request identity a `retract` receipt stores.
fn retract_request(scope: &FleetScope, target: ClaimTarget, reason: Option<&str>) -> Value {
    lifecycle_request_identity(
        RETRACT_OPERATION,
        scope,
        &json!({
            "claim_id": target.claim_id,
            "expected_revision": target.expected_revision,
            "reason": reason,
        }),
    )
}

/// The canonical request identity a `supersede` receipt stores. The successor
/// is bound exactly as record binds its input.
fn supersede_request(
    scope: &FleetScope,
    target: ClaimTarget,
    reason: Option<&str>,
    successor: &ClaimInput,
) -> Value {
    lifecycle_request_identity(
        SUPERSEDE_OPERATION,
        scope,
        &json!({
            "claim_id": target.claim_id,
            "expected_revision": target.expected_revision,
            "reason": reason,
            "successor": successor,
        }),
    )
}

/// R1 for a deployment that does not serve the request's action: a committed
/// request still replays, so a refusal is only ever returned for a key that no
/// receipt holds. One autocommit read; nothing is locked or written.
pub(super) async fn replay_unserved_lifecycle(
    ledger: &CockroachClaimLedger,
    scope: &FleetScope,
    idempotency_key: &str,
    request: Option<LifecycleReplayRequest<'_>>,
) -> Result<Option<LifecycleMutation>> {
    ledger.ensure_scope(scope)?;
    // A key no mutation accepts can hold no receipt.
    let Ok(key) = validated_idempotency_key(idempotency_key) else {
        return Ok(None);
    };
    let Some(row) = sqlx::query(SELECT_RECEIPT_SQL)
        .bind(scope.tenant_id)
        .bind(key)
        .fetch_optional(&ledger.pool)
        .await?
    else {
        return Ok(None);
    };
    // Arguments that do not name a lifecycle request cannot equal a committed one.
    let Some(request) = request else {
        return Err(FleetError::IdempotencyConflict(
            "idempotency key was already used for a different mutation".into(),
        ));
    };
    let claim = |operation, identity: Value| {
        decode_receipt_parts(&row, scope, operation, &identity).map(LifecycleMutation::Claim)
    };
    let conflict = |operation, identity: Value| {
        decode_receipt_parts(&row, scope, operation, &identity).map(LifecycleMutation::Conflict)
    };
    match request {
        LifecycleReplayRequest::Retract { target, reason } => {
            claim(RETRACT_OPERATION, retract_request(scope, target, reason))
        }
        LifecycleReplayRequest::Supersede {
            target,
            reason,
            successor,
        } => claim(
            SUPERSEDE_OPERATION,
            supersede_request(scope, target, reason, successor),
        ),
        LifecycleReplayRequest::Acknowledge { target, reason } => conflict(
            ACKNOWLEDGE_OPERATION,
            acknowledge_request(scope, target, reason),
        ),
        LifecycleReplayRequest::Resolve {
            target,
            retract_claim_ids,
            reason,
        } => conflict(
            RESOLVE_OPERATION,
            resolve_request(scope, target, retract_claim_ids, reason),
        ),
    }
    .map(Some)
}

#[allow(clippy::too_many_lines)] // one serializable unit, kept in its lock order
async fn retract_once(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    scope: &FleetScope,
    write: RetractWrite<'_>,
) -> Result<ClaimMutation> {
    let RetractWrite {
        target,
        reason,
        key,
        request,
        log_closes,
    } = write;
    // R1/R2: a committed request replays before any precondition, so a
    // retried retract returns its stored result rather than `not_current`.
    if let Some(replay) =
        replay_or_reserve(transaction, scope, key, request, RETRACT_OPERATION).await?
    {
        return Ok(replay);
    }

    // R3: plain read of the target.
    let Some(target_row) = read_target(transaction, scope, target.claim_id, false).await? else {
        return Err(not_found(target.claim_id).into());
    };

    // R4-R6: lineage lock, the key's current claims in id order, owner authority.
    let locked = lock_owned_target(transaction, scope, target, &target_row).await?;

    // R7: the transition and its claim event.
    let revision =
        transition_owned_claim(transaction, scope, &locked.claim, ClaimState::Retracted).await?;
    insert_transition_event(
        transaction,
        scope,
        locked.claim.id,
        "retracted_by_author",
        locked.claim.state,
        ClaimState::Retracted,
        json!({
            "idempotency_key": key,
            "reason": reason,
            "revision_before": locked.claim.revision,
        }),
    )
    .await?;

    // R8: re-evaluate the key's open v2 conflict over what remains current.
    let effect = match locked.conflict_key.as_deref() {
        Some(claim_key) => {
            reevaluate_key(
                transaction,
                scope,
                ReevaluationScope {
                    lineage: locked.lineage,
                    claim_key,
                    current: &locked.remaining,
                },
                &format!(
                    "no lifecycle-current incompatible pair remains after retract of claim {}",
                    locked.claim.id
                ),
                &CloseAudit {
                    operation: RETRACT_OPERATION,
                    key,
                    cause: json!({
                        "agent": scope.agent,
                        "operation": RETRACT_OPERATION,
                        "claims_retracted": [locked.claim.id],
                        "reason": reason,
                    }),
                    log: log_closes,
                },
            )
            .await?
        }
        None => ReevaluationEffect::default(),
    };

    // R9: the claim as committed, and the one keyed event.
    let claim = fetch_claim(transaction, scope, locked.claim.id)
        .await?
        .ok_or_else(|| protocol_error("retracted claim disappeared inside its transaction"))?;
    if claim.revision != revision || claim.state != ClaimState::Retracted {
        return Err(protocol_error(
            "retracted claim did not read back its committed transition",
        ));
    }
    insert_keyed_claim_event(
        transaction,
        scope,
        "claim_retracted",
        claim.id,
        key,
        json!({
            "claim_key": claim.claim_key,
            "from_state": locked.claim.state.as_str(),
            "to_state": ClaimState::Retracted.as_str(),
            "revision": revision,
            "conflict_reevaluation": effect.reevaluation,
        }),
    )
    .await?;

    let mutation = ClaimMutation {
        operation: RETRACT_OPERATION.into(),
        claim,
        superseded: None,
        idempotent_replay: false,
        conflicts_opened: Vec::new(),
        conflicts_resolved: effect.conflicts_resolved,
        claims_restored: effect.claims_restored,
        reevaluation: effect.reevaluation,
    };
    // R10: finish the reservation this transaction made.
    finish_claim_receipt(
        transaction,
        scope,
        key,
        request,
        RETRACT_OPERATION,
        &mutation,
    )
    .await?;
    Ok(mutation)
}

/// Everything a supersede transaction writes, prepared and embedded before
/// the transaction starts so no model call ever holds a lock.
struct SupersedeWrite {
    target: ClaimTarget,
    reason: Option<String>,
    successor: ClaimInput,
    prepared: PreparedClaim,
    passages: Vec<ClaimPassage>,
    model: String,
    key: String,
    request: Value,
    log_closes: bool,
}

pub(super) async fn supersede_claim(
    ledger: &CockroachClaimLedger,
    scope: &FleetScope,
    target: ClaimTarget,
    reason: Option<&str>,
    successor: &ClaimInput,
    idempotency_key: &str,
) -> Result<ClaimMutation> {
    ledger.ensure_scope(scope)?;
    let key = validated_idempotency_key(idempotency_key)?;
    validate_claim_target(target)?;
    if let Some(reason) = reason {
        validate_reason(reason).map_err(FleetError::Memory)?;
    }
    if successor
        .actor
        .as_deref()
        .is_some_and(|actor| actor != scope.agent)
    {
        return Err(FleetError::InvalidScope(
            "claim actor must match the authenticated fleet agent".into(),
        ));
    }
    let prepared = successor.prepare()?;
    if successor.origin != OPERATOR_ASSERTED_ORIGIN {
        return Err(FleetError::Memory(
            "a supersede successor must be an operator_asserted claim".into(),
        ));
    }
    let request = supersede_request(scope, target, reason, successor);
    // As for record, a non-transactional fast path avoids embedding a known
    // replay; the transaction checks the receipt again before anything else.
    if let Some(row) = sqlx::query(SELECT_RECEIPT_SQL)
        .bind(scope.tenant_id)
        .bind(key)
        .fetch_optional(&ledger.pool)
        .await?
    {
        return decode_receipt_parts(&row, scope, SUPERSEDE_OPERATION, &request);
    }
    let passages = ledger.embed_claim_passages(scope, successor, &prepared)?;
    let write = Arc::new(SupersedeWrite {
        target,
        reason: reason.map(str::to_owned),
        successor: successor.clone(),
        prepared,
        passages,
        model: ledger.claim_model.clone(),
        key: key.to_owned(),
        request,
        log_closes: ledger.serves_conflict_lifecycle(),
    });
    let scope = scope.clone();
    with_serializable_retry(&ledger.pool, ledger.retry_policy, move |transaction| {
        let scope = scope.clone();
        let write = Arc::clone(&write);
        Box::pin(async move { supersede_once(transaction, &scope, &write).await })
    })
    .await
}

#[allow(clippy::too_many_lines)] // one serializable unit, kept in its lock order
async fn supersede_once(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    scope: &FleetScope,
    write: &SupersedeWrite,
) -> Result<ClaimMutation> {
    let SupersedeWrite {
        target,
        reason,
        successor,
        prepared,
        passages,
        model,
        key,
        request,
        log_closes,
    } = write;
    let (target, reason, key) = (*target, reason.as_deref(), key.as_str());

    // R1/R2, before any precondition, exactly as for retract.
    if let Some(replay) =
        replay_or_reserve(transaction, scope, key, request, SUPERSEDE_OPERATION).await?
    {
        return Ok(replay);
    }

    // R3: plain read; the successor must keep the predecessor's kind, key,
    // and conflict eligibility, which never change after a claim is written.
    let Some(target_row) = read_target(transaction, scope, target.claim_id, false).await? else {
        return Err(not_found(target.claim_id).into());
    };
    check_successor(
        target.claim_id,
        &target_row.shape(),
        &ClaimShape {
            kind: successor.kind,
            claim_key: prepared.claim_key.clone(),
            conflict_eligible: prepared.conflict_eligible,
        },
    )?;

    // R4-R6: the same locks and owner checks as retract.
    let locked = lock_owned_target(transaction, scope, target, &target_row).await?;
    let predecessor = &locked.claim;

    // R7: retire the predecessor first, so the successor's detection below
    // compares it only with the claims that stay lifecycle-current.
    let revision =
        transition_owned_claim(transaction, scope, predecessor, ClaimState::Superseded).await?;

    // The successor is written exactly as record writes a claim.
    require_active_model(transaction, scope, model).await?;
    let mut claim = insert_claim_projection(
        transaction,
        scope,
        successor,
        prepared,
        passages,
        model,
        json!({ "idempotency_key": key, "supersedes": predecessor.id }),
    )
    .await?;
    let (conflicts_opened, detection) =
        detect_and_observe(transaction, scope, &mut claim, successor, prepared).await?;

    let linked_revision = sqlx::query_scalar::<_, i64>(SET_SUPERSEDED_BY_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(predecessor.id)
        .bind(claim.id)
        .fetch_optional(&mut **transaction)
        .await?;
    if linked_revision != Some(revision) {
        return Err(protocol_error(
            "superseded claim changed before its successor link",
        ));
    }
    insert_transition_event(
        transaction,
        scope,
        predecessor.id,
        "superseded_by_author",
        predecessor.state,
        ClaimState::Superseded,
        json!({
            "idempotency_key": key,
            "reason": reason,
            "revision_before": predecessor.revision,
            "successor_claim_id": claim.id,
        }),
    )
    .await?;
    // The successor's own audit event is unkeyed: the one keyed event of this
    // mutation is `claim_superseded` below.
    let mut recorded = claim_recorded_event_payload(claim.claim_key.as_deref(), detection);
    if let Some(recorded) = recorded.as_object_mut() {
        recorded.insert("supersedes".into(), json!(predecessor.id));
    }
    insert_claim_recorded_event(transaction, scope, claim.id, None, recorded).await?;

    // R8: the successor's detection may have inserted, reopened, or joined the
    // key's lineage, so lock it and the current claims again, then re-evaluate
    // over what is current now. A compatible successor lets the conflict
    // close; an incompatible one has replaced its predecessor as a member.
    let effect = match locked.conflict_key.as_deref() {
        Some(claim_key) => {
            let lineage = lock_lineages(transaction, scope, claim_key).await?;
            let current = if lineage.is_some_and(|lineage| lineage.state == ConflictRowState::Open)
            {
                lock_current_claims(transaction, scope, claim_key).await?
            } else {
                Vec::new()
            };
            reevaluate_key(
                transaction,
                scope,
                ReevaluationScope {
                    lineage,
                    claim_key,
                    current: &current,
                },
                &format!(
                    "no lifecycle-current incompatible pair remains after supersede of claim {} by claim {}",
                    predecessor.id, claim.id
                ),
                &CloseAudit {
                    operation: SUPERSEDE_OPERATION,
                    key,
                    cause: json!({
                        "agent": scope.agent,
                        "operation": SUPERSEDE_OPERATION,
                        "claim_superseded": predecessor.id,
                        "successor_claim_id": claim.id,
                        "reason": reason,
                    }),
                    log: *log_closes,
                },
            )
            .await?
        }
        None => ReevaluationEffect::default(),
    };

    insert_keyed_claim_event(
        transaction,
        scope,
        "claim_superseded",
        predecessor.id,
        key,
        json!({
            "claim_key": claim.claim_key,
            "from_state": predecessor.state.as_str(),
            "to_state": ClaimState::Superseded.as_str(),
            "revision": revision,
            "successor_claim_id": claim.id,
            "conflicts_opened": conflicts_opened,
            "conflict_reevaluation": effect.reevaluation,
        }),
    )
    .await?;

    let successor_id = claim.id;
    let claim = fetch_claim(transaction, scope, successor_id)
        .await?
        .ok_or_else(|| protocol_error("successor claim disappeared inside its transaction"))?;
    if !claim.state.is_current() {
        return Err(protocol_error(
            "successor claim is not lifecycle-current inside its transaction",
        ));
    }
    let mutation = ClaimMutation {
        operation: SUPERSEDE_OPERATION.into(),
        claim,
        superseded: Some(SupersededClaim {
            id: predecessor.id,
            state: ClaimState::Superseded,
            revision,
            superseded_by: successor_id,
        }),
        idempotent_replay: false,
        conflicts_opened,
        conflicts_resolved: effect.conflicts_resolved,
        claims_restored: effect.claims_restored,
        reevaluation: effect.reevaluation,
    };
    // R10: the receipt names the successor.
    finish_claim_receipt(
        transaction,
        scope,
        key,
        request,
        SUPERSEDE_OPERATION,
        &mutation,
    )
    .await?;
    Ok(mutation)
}

pub(super) async fn get_conflicts(
    ledger: &CockroachClaimLedger,
    scope: &FleetScope,
    conflict_ids: &[i64],
) -> Result<Vec<Conflict>> {
    ledger.ensure_scope(scope)?;
    let ids = bounded_ids(conflict_ids, "conflict")?;
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let scope = scope.clone();
    with_serializable_retry(&ledger.pool, ledger.retry_policy, move |transaction| {
        let scope = scope.clone();
        let ids = ids.clone();
        Box::pin(async move {
            let rows = sqlx::query(GET_CONFLICTS_BY_ID_SQL)
                .bind(scope.tenant_id)
                .bind(&scope.project)
                .bind(&ids)
                .bind(sentinel_limit(MAX_LEDGER_RESULTS)?)
                .fetch_all(&mut **transaction)
                .await?;
            if rows.len() > ids.len() {
                return Err(protocol_error(
                    "conflict lookup returned more rows than requested ids",
                ));
            }
            hydrate_conflicts(transaction, &scope, rows).await
        })
    })
    .await
}

pub(super) async fn claim_states(
    ledger: &CockroachClaimLedger,
    scope: &FleetScope,
    claim_ids: &[i64],
) -> Result<Vec<(i64, ClaimState)>> {
    ledger.ensure_scope(scope)?;
    let ids = bounded_ids(claim_ids, "claim")?;
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let rows = sqlx::query_as::<_, (i64, String)>(CLAIM_STATES_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(&ids)
        .bind(sentinel_limit(MAX_LEDGER_RESULTS)?)
        .fetch_all(&ledger.pool)
        .await?;
    if rows.len() > ids.len() {
        return Err(protocol_error(
            "claim state lookup returned more rows than requested ids",
        ));
    }
    rows.into_iter()
        .map(|(id, state)| Ok((id, parse_claim_state(&state)?)))
        .collect()
}

/// Decode a committed receipt for `operation`, refusing reuse of the key for
/// another project, operation, or canonical request.
pub(super) fn decode_receipt_parts<T: DeserializeOwned + Replayable>(
    row: &PgRow,
    scope: &FleetScope,
    operation: &str,
    request: &Value,
) -> Result<T> {
    let receipt_project: String = row.try_get("project")?;
    let receipt_operation: String = row.try_get("operation")?;
    let original_request: Value = row.try_get("request")?;
    let response: Option<Value> = row.try_get("response")?;
    decode_receipt_values(
        &receipt_project,
        &receipt_operation,
        &original_request,
        response,
        scope,
        operation,
        request,
    )
}

pub(super) fn decode_receipt_values<T: DeserializeOwned + Replayable>(
    receipt_project: &str,
    receipt_operation: &str,
    original_request: &Value,
    response: Option<Value>,
    scope: &FleetScope,
    operation: &str,
    request: &Value,
) -> Result<T> {
    if receipt_project != scope.project
        || receipt_operation != operation
        || original_request != request
    {
        return Err(FleetError::IdempotencyConflict(
            "idempotency key was already used for a different mutation".into(),
        ));
    }
    let mut decoded: T = serde_json::from_value(response.ok_or_else(|| {
        FleetError::Memory("committed idempotency receipt has no response".into())
    })?)
    .map_err(|error| FleetError::Memory(format!("decode idempotency receipt: {error}")))?;
    decoded.mark_replayed();
    Ok(decoded)
}

/// R1/R2: replay a receipt committed under the key, or reserve the key for
/// this mutation. `Some` is the stored result; `None` means this transaction
/// now holds the reservation.
pub(super) async fn replay_or_reserve<T: DeserializeOwned + Replayable>(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    scope: &FleetScope,
    key: &str,
    request: &Value,
    operation: &str,
) -> Result<Option<T>> {
    if let Some(row) = select_receipt(transaction, scope, key).await? {
        return decode_receipt_parts(&row, scope, operation, request).map(Some);
    }
    if !reserve_receipt(transaction, scope, key, request, operation).await? {
        let row = select_receipt(transaction, scope, key)
            .await?
            .ok_or_else(|| protocol_error("conflicting idempotency receipt disappeared"))?;
        return decode_receipt_parts(&row, scope, operation, request).map(Some);
    }
    Ok(None)
}

/// R4-R6: lock the target's lineage and its key's lifecycle-current claims in
/// ascending id order (or the target alone when the detector does not compare
/// it), then check owner authority against the locked row.
async fn lock_owned_target(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    scope: &FleetScope,
    target: ClaimTarget,
    target_row: &TargetRow,
) -> Result<LockedTarget> {
    let conflict_key = target_row
        .claim
        .conflict_eligible
        .then(|| target_row.claim_key.clone())
        .flatten();
    let (claim, lineage, remaining) = if let Some(claim_key) = conflict_key.as_deref() {
        let lineage = lock_lineages(transaction, scope, claim_key).await?;
        let mut locked = lock_current_claims(transaction, scope, claim_key).await?;
        let Some(position) = locked.iter().position(|claim| claim.id == target.claim_id) else {
            // The plain read already shows why it is not current; the owner
            // checks report it in their normal order.
            check_owner_transition(&target_row.claim, &scope.agent, target.expected_revision)?;
            return Err(protocol_error(
                "lifecycle target left the locked current claim set",
            ));
        };
        let claim = locked.remove(position);
        (claim, lineage, locked)
    } else {
        let locked = read_target(transaction, scope, target.claim_id, true)
            .await?
            .ok_or_else(|| not_found(target.claim_id))?;
        (locked.claim, None, Vec::new())
    };
    check_owner_transition(&claim, &scope.agent, target.expected_revision)?;
    Ok(LockedTarget {
        claim,
        conflict_key,
        lineage,
        remaining,
    })
}

/// R7: move a locked, owner-checked claim out of the current states.
pub(super) async fn transition_owned_claim(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    scope: &FleetScope,
    claim: &LockedKeyClaim,
    to_state: ClaimState,
) -> Result<i64> {
    sqlx::query_scalar::<_, i64>(TRANSITION_OWNED_CLAIM_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(claim.id)
        .bind(claim.revision)
        .bind(to_state.as_str())
        .bind(&scope.agent)
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or_else(|| protocol_error("owned claim changed during its locked transition"))
}

/// R8: when the key's v2 conflict is open, recompute its incompatible pairs
/// over the locked lifecycle-current claims, in Rust and in SQL, and close it
/// only when both agree that none remains. The close restores the disputed
/// members no other open conflict still holds.
async fn reevaluate_key(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    scope: &FleetScope,
    key_scope: ReevaluationScope<'_>,
    resolution_reason: &str,
    audit: &CloseAudit<'_>,
) -> Result<ReevaluationEffect> {
    let ReevaluationScope {
        lineage,
        claim_key,
        current,
    } = key_scope;
    let Some(lineage) = lineage.filter(|lineage| lineage.state == ConflictRowState::Open) else {
        return Ok(ReevaluationEffect::default());
    };
    let sql_pairs = key_incompatible_pairs(transaction, scope, claim_key).await?;
    match plan_reevaluation(Some(lineage), current, &sql_pairs) {
        Reevaluation::Close {
            conflict_id,
            revision: conflict_revision,
            restore_candidates,
        } => {
            apply_verified_close(
                transaction,
                scope,
                VerifiedClose {
                    conflict_id,
                    conflict_revision,
                    claim_key,
                    restore_candidates: &restore_candidates,
                    current,
                    resolution_reason,
                },
                audit,
            )
            .await
        }
        Reevaluation::StillOpen {
            conflict_id,
            revision: conflict_revision,
            pairs,
        } => Ok(ReevaluationEffect {
            reevaluation: Some(reevaluation_report(
                conflict_id,
                "still_open",
                conflict_revision,
                &pairs,
            )),
            ..ReevaluationEffect::default()
        }),
        Reevaluation::Divergent {
            conflict_id,
            revision: conflict_revision,
            rust_pairs,
            sql_pairs,
        } => {
            tracing::error!(
                conflict_id,
                rust_pairs = rust_pairs.len(),
                sql_pairs = sql_pairs.len(),
                "lifecycle re-evaluation diverged between Rust and SQL; the conflict stays open"
            );
            Ok(ReevaluationEffect {
                reevaluation: Some(reevaluation_report(
                    conflict_id,
                    "divergent",
                    conflict_revision,
                    &sql_pairs,
                )),
                ..ReevaluationEffect::default()
            })
        }
        Reevaluation::NoLineage | Reevaluation::NotOpen => Ok(ReevaluationEffect::default()),
    }
}

/// A close the detector verified over the key's locked current claims.
pub(super) struct VerifiedClose<'a> {
    pub(super) conflict_id: i64,
    /// The open revision the close is decided against.
    pub(super) conflict_revision: i64,
    pub(super) claim_key: &'a str,
    /// The remaining disputed claims, ascending.
    pub(super) restore_candidates: &'a [i64],
    /// The key's remaining lifecycle-current claims.
    pub(super) current: &'a [LockedKeyClaim],
    pub(super) resolution_reason: &'a str,
}

/// Close the key's v2 conflict as `resolved`, restore the disputed members no
/// other open conflict holds, and, with the capability, log the close as a
/// detector-attributed `resolved` event.
pub(super) async fn apply_verified_close(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    scope: &FleetScope,
    close: VerifiedClose<'_>,
    audit: &CloseAudit<'_>,
) -> Result<ReevaluationEffect> {
    let VerifiedClose {
        conflict_id,
        conflict_revision,
        claim_key,
        restore_candidates,
        current,
        resolution_reason,
    } = close;
    let closed_revision = close_conflict(
        transaction,
        scope,
        conflict_id,
        conflict_revision,
        resolution_reason,
    )
    .await?;
    let claims_restored = restore_disputed_members(
        transaction,
        scope,
        RestoreScope {
            conflict_id,
            conflict_revision: closed_revision,
            claim_key,
        },
        restore_candidates,
        audit.key,
    )
    .await?;
    // The log records the close when it can; its capacity never refuses it.
    let lifecycle_event = if audit.log {
        let member_count =
            conflict_store::bounded_member_count(transaction, scope, conflict_id).await?;
        let mut remaining = current.iter().map(|claim| claim.id).collect::<Vec<_>>();
        remaining.sort_unstable();
        append_close_event(
            transaction,
            scope,
            LifecycleEventDraft {
                conflict_id,
                kind: "resolved",
                episode_revision: conflict_revision,
                result_revision: closed_revision,
                to_state: "resolved",
                actor_kind: "detector",
                actor: FUNCTIONAL_VALUE_CONFLICT_DETECTOR_V2,
                operation: audit.operation,
                key: audit.key,
                member_count,
                reason_kind: Some(NO_CURRENT_INCOMPATIBILITY),
                rationale: None,
                payload: json!({
                    "cause": audit.cause,
                    "restored_claim_ids": claims_restored,
                    "remaining_current_claim_ids": remaining,
                }),
            },
        )
        .await?
    } else {
        None
    };
    Ok(ReevaluationEffect {
        conflicts_resolved: vec![conflict_id],
        claims_restored,
        reevaluation: Some(reevaluation_report(
            conflict_id,
            "closed",
            closed_revision,
            &[],
        )),
        lifecycle_event,
    })
}

/// The one keyed `memory_events` row of a claim lifecycle mutation.
async fn insert_keyed_claim_event(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    scope: &FleetScope,
    event_kind: &str,
    claim_id: i64,
    key: &str,
    payload: Value,
) -> Result<()> {
    sqlx::query(INSERT_KEYED_CLAIM_EVENT_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(&scope.agent)
        .bind(&scope.session_id)
        .bind(event_kind)
        .bind(claim_id.to_string())
        .bind(key)
        .bind(payload)
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

async fn select_receipt(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    scope: &FleetScope,
    key: &str,
) -> Result<Option<PgRow>> {
    Ok(sqlx::query(SELECT_RECEIPT_SQL)
        .bind(scope.tenant_id)
        .bind(key)
        .fetch_optional(&mut **transaction)
        .await?)
}

async fn reserve_receipt(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    scope: &FleetScope,
    key: &str,
    request: &Value,
    operation: &str,
) -> Result<bool> {
    Ok(sqlx::query_scalar::<_, String>(RESERVE_RECEIPT_SQL)
        .bind(scope.tenant_id)
        .bind(key)
        .bind(&scope.project)
        .bind(request)
        .bind(operation)
        .fetch_optional(&mut **transaction)
        .await?
        .is_some())
}

async fn finish_claim_receipt(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    scope: &FleetScope,
    key: &str,
    request: &Value,
    operation: &str,
    mutation: &ClaimMutation,
) -> Result<()> {
    let response = serde_json::to_value(mutation)
        .map_err(|error| protocol_error(format!("serialize idempotency response: {error}")))?;
    let receipt = sqlx::query(FINISH_CLAIM_RECEIPT_SQL)
        .bind(scope.tenant_id)
        .bind(key)
        .bind(&scope.project)
        .bind(request)
        .bind(operation)
        .bind(mutation.claim.id)
        .bind(response)
        .execute(&mut **transaction)
        .await?;
    if receipt.rows_affected() != 1 {
        return Err(protocol_error(
            "idempotency receipt reservation disappeared during mutation",
        ));
    }
    Ok(())
}

async fn read_target(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    scope: &FleetScope,
    claim_id: i64,
    lock: bool,
) -> Result<Option<TargetRow>> {
    let sql = if lock {
        LOCK_LIFECYCLE_TARGET_CLAIM_SQL
    } else {
        LIFECYCLE_TARGET_CLAIM_SQL
    };
    let Some(row) = sqlx::query(sql)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(claim_id)
        .fetch_optional(&mut **transaction)
        .await?
    else {
        return Ok(None);
    };
    let kind: String = row.try_get("kind")?;
    Ok(Some(TargetRow {
        kind: parse_claim_kind(&kind)?,
        claim_key: row.try_get("claim_key")?,
        claim: decode_locked_claim(&row)?,
    }))
}

pub(super) async fn lock_lineages(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    scope: &FleetScope,
    claim_key: &str,
) -> Result<Option<V2Lineage>> {
    let rows = sqlx::query_as::<_, (i64, i64, String, i64)>(LOCK_LIFECYCLE_LINEAGES_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(claim_key)
        .fetch_all(&mut **transaction)
        .await?;
    classify_lineages(&rows)
}

pub(super) async fn lock_current_claims(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    scope: &FleetScope,
    claim_key: &str,
) -> Result<Vec<LockedKeyClaim>> {
    let rows = sqlx::query(LOCK_LIFECYCLE_CURRENT_CLAIMS_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(claim_key)
        .bind(sentinel_limit(MAX_CURRENT_CLAIMS_PER_KEY_COMPARISON)?)
        .fetch_all(&mut **transaction)
        .await?;
    if rows.len() > MAX_CURRENT_CLAIMS_PER_KEY_COMPARISON {
        return Err(LifecycleRefusal::new(
            RefusalCode::BoundExceeded,
            format!(
                "the claim key has more than {MAX_CURRENT_CLAIMS_PER_KEY_COMPARISON} lifecycle-current claims"
            ),
            json!({ "bound": MAX_CURRENT_CLAIMS_PER_KEY_COMPARISON }),
        )
        .into());
    }
    let claims = rows
        .iter()
        .map(decode_locked_claim)
        .collect::<Result<Vec<_>>>()?;
    if claims.iter().any(|claim| !claim.state.is_current())
        || claims.windows(2).any(|pair| pair[0].id >= pair[1].id)
    {
        return Err(protocol_error(
            "locked current claim set was not current or not in ascending id order",
        ));
    }
    Ok(claims)
}

pub(super) async fn key_incompatible_pairs(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    scope: &FleetScope,
    claim_key: &str,
) -> Result<Vec<(i64, i64)>> {
    let pairs = sqlx::query_as::<_, (i64, i64)>(KEY_INCOMPATIBLE_PAIRS_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(claim_key)
        .bind(sentinel_limit(MAX_CURRENT_CLAIMS_PER_KEY_COMPARISON)?)
        .bind(sentinel_limit(MAX_KEY_INCOMPATIBLE_PAIRS)?)
        .fetch_all(&mut **transaction)
        .await?;
    if pairs.len() > MAX_KEY_INCOMPATIBLE_PAIRS {
        return Err(protocol_error(
            "key incompatibility cross-check exceeded its pair bound",
        ));
    }
    Ok(pairs)
}

async fn close_conflict(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    scope: &FleetScope,
    conflict_id: i64,
    expected_revision: i64,
    resolution_reason: &str,
) -> Result<i64> {
    sqlx::query_scalar::<_, i64>(CLOSE_CONFLICT_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(conflict_id)
        .bind(expected_revision)
        .bind(RESOLVED_STATE)
        .bind(NO_CURRENT_INCOMPATIBILITY)
        .bind(resolution_reason)
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or_else(|| protocol_error("locked open conflict changed before its verified close"))
}

/// The closed v2 lineage whose disputed members a verified close restores.
struct RestoreScope<'a> {
    conflict_id: i64,
    conflict_revision: i64,
    claim_key: &'a str,
}

async fn restore_disputed_members(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    scope: &FleetScope,
    lineage: RestoreScope<'_>,
    candidates: &[i64],
    key: &str,
) -> Result<Vec<i64>> {
    let RestoreScope {
        conflict_id,
        conflict_revision,
        claim_key,
    } = lineage;
    if candidates.is_empty() {
        return Ok(Vec::new());
    }
    let restored = sqlx::query_as::<_, (i64, i64)>(RESTORE_DISPUTED_MEMBERS_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(conflict_id)
        .bind(candidates)
        .bind(claim_key)
        .fetch_all(&mut **transaction)
        .await?;
    let mut restored_ids = Vec::with_capacity(restored.len());
    for (claim_id, _) in restored {
        if candidates.binary_search(&claim_id).is_err() {
            return Err(protocol_error("restore escaped its locked candidate set"));
        }
        insert_transition_event(
            transaction,
            scope,
            claim_id,
            "conflict_resolved",
            ClaimState::Disputed,
            ClaimState::Active,
            json!({
                "conflict_id": conflict_id,
                "conflict_revision": conflict_revision,
                "idempotency_key": key,
            }),
        )
        .await?;
        restored_ids.push(claim_id);
    }
    restored_ids.sort_unstable();
    Ok(restored_ids)
}

pub(super) async fn insert_transition_event(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    scope: &FleetScope,
    claim_id: i64,
    reason: &str,
    from_state: ClaimState,
    to_state: ClaimState,
    payload: Value,
) -> Result<()> {
    sqlx::query(INSERT_TRANSITION_EVENT_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(claim_id)
        .bind(&scope.agent)
        .bind(reason)
        .bind(from_state.as_str())
        .bind(to_state.as_str())
        .bind(payload)
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

fn decode_locked_claim(row: &PgRow) -> Result<LockedKeyClaim> {
    let state: String = row.try_get("state")?;
    Ok(LockedKeyClaim {
        id: row.try_get("id")?,
        state: parse_claim_state(&state)?,
        origin: row.try_get("origin")?,
        actor: row.try_get("actor")?,
        revision: row.try_get("revision")?,
        polarity: row.try_get("polarity")?,
        valid_from: row.try_get("valid_from")?,
        valid_to: row.try_get("valid_to")?,
        conflict_eligible: row.try_get("conflict_eligible")?,
        value: row.try_get("value")?,
    })
}

fn reevaluation_report(
    conflict_id: i64,
    outcome: &str,
    conflict_revision: i64,
    pairs: &[(i64, i64)],
) -> ConflictReevaluation {
    ConflictReevaluation {
        conflict_id,
        outcome: outcome.into(),
        conflict_revision,
        remaining_pair_count: pairs.len(),
        remaining_pairs: pairs
            .iter()
            .take(MAX_REPORTED_REMAINING_PAIRS)
            .map(|(left, right)| [*left, *right])
            .collect(),
    }
}

fn not_found(claim_id: i64) -> LifecycleRefusal {
    LifecycleRefusal::new(
        RefusalCode::NotFound,
        format!("claim {claim_id} does not exist in this project"),
        json!({ "claim_id": claim_id }),
    )
}

pub(super) fn validated_idempotency_key(key: &str) -> Result<&str> {
    let key = key.trim();
    if key.is_empty() || key.len() > MAX_IDEMPOTENCY_KEY_BYTES {
        return Err(FleetError::Memory(format!(
            "idempotency_key must be between 1 and {MAX_IDEMPOTENCY_KEY_BYTES} bytes"
        )));
    }
    Ok(key)
}

fn validate_claim_target(target: ClaimTarget) -> Result<()> {
    if !(1..=MAX_SAFE_INTEGER).contains(&target.claim_id)
        || !(1..=MAX_SAFE_INTEGER).contains(&target.expected_revision)
    {
        return Err(FleetError::Memory(format!(
            "claim_id and expected_revision must be between 1 and {MAX_SAFE_INTEGER}"
        )));
    }
    Ok(())
}

fn bounded_ids(ids: &[i64], label: &str) -> Result<Vec<i64>> {
    if ids.len() > MAX_LEDGER_RESULTS {
        return Err(FleetError::Memory(format!(
            "{label} id lookup accepts at most {MAX_LEDGER_RESULTS} ids"
        )));
    }
    if ids.iter().any(|id| !(1..=MAX_SAFE_INTEGER).contains(id)) {
        return Err(FleetError::Memory(format!(
            "{label} ids must be between 1 and {MAX_SAFE_INTEGER}"
        )));
    }
    let mut ids = ids.to_vec();
    ids.sort_unstable();
    ids.dedup();
    Ok(ids)
}

pub(super) fn sentinel_limit(bound: usize) -> Result<i64> {
    bound
        .checked_add(1)
        .and_then(|limit| i64::try_from(limit).ok())
        .ok_or_else(|| protocol_error("lifecycle bound is outside INT8 range"))
}

#[cfg(test)]
mod tests {
    use ostk_recall_core::PrivacyTier;
    use uuid::Uuid;

    use super::*;

    fn scope(project: &str) -> FleetScope {
        FleetScope::new(
            Uuid::from_u128(1),
            project,
            "agent-a",
            None,
            PrivacyTier::T1Project,
        )
        .unwrap()
    }

    fn stored_retract() -> Value {
        json!({
            "operation": "retract",
            "claim": {
                "id": 41, "project": "project", "kind": "fact",
                "claim_key": "fleet::database", "subject": "fleet", "predicate": "database",
                "value": "cockroachdb", "text": "fixture", "polarity": 1, "state": "retracted",
                "origin": "operator_asserted", "actor": "agent-a", "confidence": 1.0,
                "valid_from": null, "valid_to": null, "superseded_by": null, "revision": 3,
                "conflict_eligible": true,
                "created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-01T00:00:00Z",
            },
            "idempotent_replay": false,
            "conflicts_opened": [],
            "conflicts_resolved": [9],
            "claims_restored": [42],
        })
    }

    #[test]
    fn decode_receipt_parts_refuses_cross_operation_project_and_request_reuse() {
        let scope = scope("project");
        let request = lifecycle_request_identity(
            RETRACT_OPERATION,
            &scope,
            &json!({ "claim_id": 41, "expected_revision": 2, "reason": null }),
        );

        let replay: ClaimMutation = decode_receipt_values(
            "project",
            RETRACT_OPERATION,
            &request,
            Some(stored_retract()),
            &scope,
            RETRACT_OPERATION,
            &request,
        )
        .unwrap();
        assert!(replay.idempotent_replay);
        assert_eq!(replay.claims_restored, [42]);
        assert_eq!(replay.conflicts_resolved, [9]);

        let other_request = lifecycle_request_identity(
            RETRACT_OPERATION,
            &scope,
            &json!({ "claim_id": 41, "expected_revision": 3, "reason": null }),
        );
        for (project, operation, stored_request) in [
            ("project", "record", &request),
            ("other-project", RETRACT_OPERATION, &request),
            ("project", RETRACT_OPERATION, &other_request),
        ] {
            let error = decode_receipt_values::<ClaimMutation>(
                project,
                operation,
                stored_request,
                Some(stored_retract()),
                &scope,
                RETRACT_OPERATION,
                &request,
            )
            .unwrap_err();
            assert!(
                matches!(error, FleetError::IdempotencyConflict(_)),
                "{project}/{operation} reuse must be an idempotency conflict"
            );
        }

        assert!(matches!(
            decode_receipt_values::<ClaimMutation>(
                "project",
                RETRACT_OPERATION,
                &request,
                None,
                &scope,
                RETRACT_OPERATION,
                &request,
            ),
            Err(FleetError::Memory(_))
        ));
    }

    fn successor(text: &str) -> ClaimInput {
        serde_json::from_value(json!({
            "kind": "fact", "text": text, "subject": "fleet", "predicate": "database",
            "value": "cockroachdb",
        }))
        .unwrap()
    }

    #[test]
    fn supersede_receipts_bind_the_successor_and_never_serve_another_operation() {
        let scope = scope("project");
        let target = ClaimTarget {
            claim_id: 41,
            expected_revision: 2,
        };
        let request = supersede_request(&scope, target, None, &successor("CockroachDB 26"));
        let mut stored = stored_retract();
        stored["operation"] = json!("supersede");
        stored["superseded"] = json!({
            "id": 41, "state": "superseded", "revision": 3, "superseded_by": 42,
        });

        let replay: ClaimMutation = decode_receipt_values(
            "project",
            SUPERSEDE_OPERATION,
            &request,
            Some(stored.clone()),
            &scope,
            SUPERSEDE_OPERATION,
            &request,
        )
        .unwrap();
        assert!(replay.idempotent_replay);
        assert_eq!(replay.superseded.unwrap().superseded_by, 42);

        // Another successor under the same key and target is a different
        // request, and so is the same target as a retract.
        for (operation, other) in [
            (
                SUPERSEDE_OPERATION,
                supersede_request(&scope, target, None, &successor("CockroachDB 27")),
            ),
            (
                SUPERSEDE_OPERATION,
                supersede_request(&scope, target, Some("note"), &successor("CockroachDB 26")),
            ),
            (RETRACT_OPERATION, retract_request(&scope, target, None)),
        ] {
            assert!(matches!(
                decode_receipt_values::<ClaimMutation>(
                    "project",
                    SUPERSEDE_OPERATION,
                    &request,
                    Some(stored.clone()),
                    &scope,
                    operation,
                    &other,
                ),
                Err(FleetError::IdempotencyConflict(_))
            ));
        }
    }

    #[test]
    fn lifecycle_ids_are_bounded_positive_and_deduplicated() {
        assert_eq!(bounded_ids(&[5, 3, 5], "claim").unwrap(), [3, 5]);
        assert!(bounded_ids(&[0], "claim").is_err());
        assert!(bounded_ids(&[MAX_SAFE_INTEGER + 1], "claim").is_err());
        let too_many = (1..=i64::try_from(MAX_LEDGER_RESULTS + 1).unwrap()).collect::<Vec<_>>();
        assert!(bounded_ids(&too_many, "conflict").is_err());
        assert!(
            validate_claim_target(ClaimTarget {
                claim_id: 1,
                expected_revision: 0,
            })
            .is_err()
        );
        assert!(validated_idempotency_key(" ").is_err());
        assert_eq!(validated_idempotency_key(" key ").unwrap(), "key");
    }
}
