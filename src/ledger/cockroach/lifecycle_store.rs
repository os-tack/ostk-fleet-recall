//! Serializable lifecycle transactions for the `CockroachDB` claim ledger.
//!
//! Every statement is keyed on the trusted `(tenant_id, project)` and locks in
//! the record path's order: the key's conflict lineage rows first, then its
//! lifecycle-current claims in ascending id order. A refusal is an error from
//! inside the retried closure, so the transaction rolls back with its receipt
//! reservation and the idempotency key stays free.

use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use sqlx::postgres::PgRow;
use sqlx::{Row, Transaction};

use super::{
    CockroachClaimLedger, MAX_CURRENT_CLAIMS_PER_KEY_COMPARISON, MAX_LEDGER_RESULTS, fetch_claim,
    hydrate_conflicts, parse_claim_state, protocol_error,
};
use crate::ledger::lifecycle::{
    ConflictRowState, LifecycleRefusal, LockedKeyClaim, MAX_REPORTED_REMAINING_PAIRS, Reevaluation,
    RefusalCode, V2Lineage, check_owner_transition, classify_lineages, lifecycle_request_identity,
    plan_reevaluation, validate_reason,
};
use crate::ledger::{ClaimMutation, ClaimState, ClaimTarget, Conflict, ConflictReevaluation};
use crate::store::cockroach::with_serializable_retry;
use crate::{FleetError, FleetScope, Result};

const RETRACT_OPERATION: &str = "retract";
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 256;
const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
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

const LIFECYCLE_TARGET_CLAIM_SQL: &str = "SELECT id, claim_key, state, origin, actor, revision, \
            polarity, valid_from, valid_to, conflict_eligible, value \
     FROM memory_claims@primary WHERE tenant_id = $1 AND project = $2 AND id = $3";
const LOCK_LIFECYCLE_TARGET_CLAIM_SQL: &str = "SELECT id, claim_key, state, origin, actor, \
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
const INSERT_CLAIM_RETRACTED_EVENT_SQL: &str = "INSERT INTO memory_events (\
         tenant_id, project, agent, session_id, event_kind, entity_kind, \
         entity_id, idempotency_key, payload\
     ) VALUES ($1, $2, $3, $4, 'claim_retracted', 'claim', $5, $6, $7)";
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

struct TargetRow {
    claim: LockedKeyClaim,
    claim_key: Option<String>,
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
    with_serializable_retry(&ledger.pool, ledger.retry_policy, move |transaction| {
        let scope = scope.clone();
        let reason = reason.clone();
        let key = key.clone();
        let request = request.clone();
        Box::pin(async move {
            retract_once(
                transaction,
                &scope,
                target,
                reason.as_deref(),
                &key,
                &request,
            )
            .await
        })
    })
    .await
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

/// R1 for a deployment that does not serve the request's action: a committed
/// request still replays, so a refusal is only ever returned for a key that no
/// receipt holds. One autocommit read; nothing is locked or written.
pub(super) async fn replay_unserved_lifecycle(
    ledger: &CockroachClaimLedger,
    scope: &FleetScope,
    idempotency_key: &str,
    retract: Option<(ClaimTarget, Option<&str>)>,
) -> Result<Option<ClaimMutation>> {
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
    let Some((target, reason)) = retract else {
        // Arguments that do not name a retract cannot equal a committed one.
        return Err(FleetError::IdempotencyConflict(
            "idempotency key was already used for a different mutation".into(),
        ));
    };
    decode_receipt_parts(
        &row,
        scope,
        RETRACT_OPERATION,
        &retract_request(scope, target, reason),
    )
    .map(Some)
}

#[allow(clippy::too_many_lines)] // one serializable unit, kept in its lock order
async fn retract_once(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    scope: &FleetScope,
    target: ClaimTarget,
    reason: Option<&str>,
    key: &str,
    request: &Value,
) -> Result<ClaimMutation> {
    // R1/R2: a committed request replays before any precondition, so a
    // retried retract returns its stored result rather than `not_current`.
    if let Some(row) = select_receipt(transaction, scope, key).await? {
        return decode_receipt_parts(&row, scope, RETRACT_OPERATION, request);
    }
    if !reserve_receipt(transaction, scope, key, request, RETRACT_OPERATION).await? {
        let row = select_receipt(transaction, scope, key)
            .await?
            .ok_or_else(|| protocol_error("conflicting idempotency receipt disappeared"))?;
        return decode_receipt_parts(&row, scope, RETRACT_OPERATION, request);
    }

    // R3: plain read of the target.
    let Some(target_row) = read_target(transaction, scope, target.claim_id, false).await? else {
        return Err(not_found(target.claim_id).into());
    };

    // R4/R5: lineage lock, then the key's current claims in id order.
    let conflict_key = target_row
        .claim
        .conflict_eligible
        .then_some(target_row.claim_key.as_deref())
        .flatten();
    let (locked_target, lineage, remaining) = if let Some(claim_key) = conflict_key {
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
        let locked_target = locked.remove(position);
        (locked_target, lineage, locked)
    } else {
        let locked = read_target(transaction, scope, target.claim_id, true)
            .await?
            .ok_or_else(|| not_found(target.claim_id))?;
        (locked.claim, None, Vec::new())
    };

    // R6: owner authority against the locked row.
    check_owner_transition(&locked_target, &scope.agent, target.expected_revision)?;

    // R7: the transition and its claim event.
    let revision = sqlx::query_scalar::<_, i64>(TRANSITION_OWNED_CLAIM_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(locked_target.id)
        .bind(locked_target.revision)
        .bind(ClaimState::Retracted.as_str())
        .bind(&scope.agent)
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or_else(|| protocol_error("owned claim changed during its locked transition"))?;
    insert_transition_event(
        transaction,
        scope,
        locked_target.id,
        "retracted_by_author",
        locked_target.state,
        ClaimState::Retracted,
        json!({
            "idempotency_key": key,
            "reason": reason,
            "revision_before": locked_target.revision,
        }),
    )
    .await?;

    // R8: re-evaluate the key's open v2 conflict over what remains current.
    let open_lineage = lineage.filter(|lineage| lineage.state == ConflictRowState::Open);
    let plan = match (open_lineage, conflict_key) {
        (Some(lineage), Some(claim_key)) => {
            let sql_pairs = key_incompatible_pairs(transaction, scope, claim_key).await?;
            Some((
                claim_key,
                plan_reevaluation(Some(lineage), &remaining, &sql_pairs),
            ))
        }
        _ => None,
    };
    let mut conflicts_resolved = Vec::new();
    let mut claims_restored = Vec::new();
    let reevaluation = match plan {
        Some((
            claim_key,
            Reevaluation::Close {
                conflict_id,
                revision: conflict_revision,
                restore_candidates,
            },
        )) => {
            let closed_revision = close_conflict(
                transaction,
                scope,
                conflict_id,
                conflict_revision,
                &format!(
                    "no lifecycle-current incompatible pair remains after retract of claim {}",
                    locked_target.id
                ),
            )
            .await?;
            claims_restored = restore_disputed_members(
                transaction,
                scope,
                RestoreScope {
                    conflict_id,
                    conflict_revision: closed_revision,
                    claim_key,
                },
                &restore_candidates,
                key,
            )
            .await?;
            conflicts_resolved.push(conflict_id);
            Some(reevaluation_report(
                conflict_id,
                "closed",
                closed_revision,
                &[],
            ))
        }
        Some((
            _,
            Reevaluation::StillOpen {
                conflict_id,
                revision: conflict_revision,
                pairs,
            },
        )) => Some(reevaluation_report(
            conflict_id,
            "still_open",
            conflict_revision,
            &pairs,
        )),
        Some((
            _,
            Reevaluation::Divergent {
                conflict_id,
                revision: conflict_revision,
                rust_pairs,
                sql_pairs,
            },
        )) => {
            tracing::error!(
                conflict_id,
                rust_pairs = rust_pairs.len(),
                sql_pairs = sql_pairs.len(),
                "lifecycle re-evaluation diverged between Rust and SQL; the conflict stays open"
            );
            Some(reevaluation_report(
                conflict_id,
                "divergent",
                conflict_revision,
                &sql_pairs,
            ))
        }
        Some((_, Reevaluation::NoLineage | Reevaluation::NotOpen)) | None => None,
    };

    // R9: the claim as committed, and the one keyed event.
    let claim = fetch_claim(transaction, scope, locked_target.id)
        .await?
        .ok_or_else(|| protocol_error("retracted claim disappeared inside its transaction"))?;
    if claim.revision != revision || claim.state != ClaimState::Retracted {
        return Err(protocol_error(
            "retracted claim did not read back its committed transition",
        ));
    }
    sqlx::query(INSERT_CLAIM_RETRACTED_EVENT_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(&scope.agent)
        .bind(&scope.session_id)
        .bind(claim.id.to_string())
        .bind(key)
        .bind(json!({
            "claim_key": claim.claim_key,
            "from_state": locked_target.state.as_str(),
            "to_state": ClaimState::Retracted.as_str(),
            "revision": revision,
            "conflict_reevaluation": reevaluation,
        }))
        .execute(&mut **transaction)
        .await?;

    let mutation = ClaimMutation {
        operation: RETRACT_OPERATION.into(),
        claim,
        idempotent_replay: false,
        conflicts_opened: Vec::new(),
        conflicts_resolved,
        claims_restored,
        reevaluation,
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

fn decode_receipt_values<T: DeserializeOwned + Replayable>(
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
    Ok(Some(TargetRow {
        claim_key: row.try_get("claim_key")?,
        claim: decode_locked_claim(&row)?,
    }))
}

async fn lock_lineages(
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

async fn lock_current_claims(
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

async fn key_incompatible_pairs(
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

async fn insert_transition_event(
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

fn validated_idempotency_key(key: &str) -> Result<&str> {
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

fn sentinel_limit(bound: usize) -> Result<i64> {
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
