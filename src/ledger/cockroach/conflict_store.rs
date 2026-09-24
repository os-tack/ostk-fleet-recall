//! Serializable conflict lifecycle transactions (`acknowledge` and concession
//! `resolve`) and the lifecycle log reads (overlay and history) for the
//! `CockroachDB` claim ledger (ADR 0004, migration 0029).
//!
//! Every mutation replays or reserves its receipt first, then locks in the
//! record path's order: the key's conflict lineage rows, then (for `resolve`)
//! the key's lifecycle-current claims in ascending id order. The lifecycle
//! log is appended only while the conflict row is locked, so its `event_seq`
//! has no gaps. `memory_conflicts` changes only through a detector-verified
//! close. Reads of the log are single autocommit statements, kept out of
//! every read transaction so a failure can only degrade the overlay.

use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use sqlx::postgres::PgRow;
use sqlx::{Row, Transaction};

use super::lifecycle_store::{
    ACKNOWLEDGE_OPERATION, CloseAudit, MAX_SAFE_INTEGER, RESOLVE_OPERATION, VerifiedClose,
    apply_verified_close, insert_transition_event, key_incompatible_pairs, lock_current_claims,
    lock_lineages, replay_or_reserve, sentinel_limit, transition_owned_claim,
    validated_idempotency_key,
};
use super::{CockroachClaimLedger, MAX_LEDGER_RESULTS, parse_claim_state, protocol_error};
use crate::ledger::lifecycle::{
    ConflictRowState, LifecycleRefusal, MAX_CONCESSION_CLAIMS, MAX_CONFLICT_LIFECYCLE_EVENTS,
    MAX_CONFLICT_MEMBER_COUNT, MAX_HISTORY_EVENTS, MAX_OVERLAY_EPISODE_EVENTS,
    MAX_REPORTED_REMAINING_PAIRS, Reevaluation, RefusalCode, V2Lineage, lifecycle_request_identity,
    plan_concession, plan_reevaluation, validate_reason,
};
use crate::ledger::{
    ClaimState, ConflictHistory, ConflictLifecycleEvent, ConflictLifecycleRows, ConflictMutation,
    ConflictTarget,
};
use crate::store::cockroach::with_serializable_retry;
use crate::{FleetError, FleetScope, Result};

const ACKNOWLEDGE_ACTION: &str = "acknowledge";
const RESOLVE_ACTION: &str = "resolve";
/// History payloads above this many bytes are elided, so a bounded history
/// stays within one tool response.
const MAX_HISTORY_PAYLOAD_BYTES: usize = 4_096;

const CONFLICT_TARGET_SQL: &str = "SELECT id, claim_key, CASE detector \
              WHEN 'same_key_functional_value_v2' THEN 2::INT8 \
              WHEN 'same_key_typed_value' THEN 1::INT8 \
              ELSE 0::INT8 END AS detector_class, \
            state, revision \
     FROM memory_conflicts@primary WHERE tenant_id = $1 AND project = $2 AND id = $3";
/// Durable members, counted up to one sentinel past the log's bound.
const MEMBER_COUNT_SQL: &str = "SELECT count(*)::INT8 FROM (\
       SELECT claim_id FROM memory_conflict_members@primary \
       WHERE tenant_id = $1 AND project = $2 AND conflict_id = $3 LIMIT $4\
     ) AS bounded";
/// The named claims that are members of the conflict, with their plain state.
const MEMBERS_AMONG_SQL: &str = "SELECT m.claim_id, c.state, c.revision \
     FROM memory_conflict_members@primary AS m \
     JOIN memory_claims@primary AS c \
       ON c.tenant_id = m.tenant_id AND c.project = m.project AND c.id = m.claim_id \
     WHERE m.tenant_id = $1 AND m.project = $2 AND m.conflict_id = $3 \
       AND m.claim_id = ANY($4) \
     ORDER BY m.claim_id";
const LAST_EVENT_SEQ_SQL: &str = "SELECT event_seq \
     FROM memory_conflict_lifecycle_events_v1@primary \
     WHERE tenant_id = $1 AND project = $2 AND conflict_id = $3 \
     ORDER BY event_seq DESC LIMIT 1";
const ACK_EXISTS_SQL: &str = "SELECT event_seq \
     FROM memory_conflict_lifecycle_events_v1@memory_conflict_lifecycle_v1_ack_once_idx \
     WHERE tenant_id = $1 AND project = $2 AND conflict_id = $3 AND episode_revision = $4 \
       AND actor = $5 AND event_kind = 'acknowledged' \
     LIMIT 1";
/// Expiry and review times are computed from the database clock only.
const INSERT_LIFECYCLE_EVENT_SQL: &str = "INSERT INTO memory_conflict_lifecycle_events_v1 (\
         tenant_id, project, conflict_id, event_seq, event_kind, episode_revision, \
         result_revision, from_state, to_state, actor_kind, actor, session_id, operation, \
         idempotency_key, member_count, reason_kind, rationale, expires_at, review_by, payload\
     ) VALUES ($1, $2, $3, $4, $5, $6, $7, 'open', $8, $9, $10, $11, $12, $13, $14, $15, $16, \
         CASE WHEN $17::INT8 IS NULL THEN NULL ELSE now() + ($17::INT8 * INTERVAL '1 hour') END, \
         CASE WHEN $18::INT8 IS NULL THEN NULL ELSE now() + ($18::INT8 * INTERVAL '1 hour') END, \
         $19) \
     RETURNING expires_at, review_by, created_at";
/// The one keyed `memory_events` row of a conflict lifecycle mutation.
const INSERT_KEYED_CONFLICT_EVENT_SQL: &str = "INSERT INTO memory_events (\
         tenant_id, project, agent, session_id, event_kind, entity_kind, \
         entity_id, idempotency_key, payload\
     ) VALUES ($1, $2, $3, $4, $5, 'conflict', $6, $7, $8)";
const FINISH_CONFLICT_RECEIPT_SQL: &str = "UPDATE memory_mutation_receipts \
     SET conflict_id = $6, response = $7 \
     WHERE tenant_id = $1 AND idempotency_key = $2 \
       AND project = $3 AND request = $4 AND operation = $5";
/// The newest events of each requested episode. The outer join keeps a row
/// for an episode with no events, so the read always reports its time.
const LIFECYCLE_OVERLAY_SQL: &str = "SELECT wanted.conflict_id AS wanted_conflict_id, \
            e.event_seq, e.event_kind, e.episode_revision, e.result_revision, e.actor_kind, \
            e.actor, e.operation, e.reason_kind, e.rationale, e.expires_at, e.review_by, \
            e.member_count, e.created_at, now() AS evaluated_at \
     FROM unnest($3::INT8[], $4::INT8[]) AS wanted (conflict_id, episode_revision) \
     LEFT JOIN LATERAL (\
       SELECT event_seq, event_kind, episode_revision, result_revision, actor_kind, actor, \
              operation, reason_kind, rationale, expires_at, review_by, member_count, created_at \
       FROM memory_conflict_lifecycle_events_v1@memory_conflict_lifecycle_v1_episode_idx \
       WHERE tenant_id = $1 AND project = $2 AND conflict_id = wanted.conflict_id \
         AND episode_revision = wanted.episode_revision \
       ORDER BY event_seq DESC LIMIT $5\
     ) AS e ON true";
const LIFECYCLE_HISTORY_SQL: &str = "SELECT event_seq, event_kind, episode_revision, \
            result_revision, actor_kind, actor, operation, reason_kind, rationale, expires_at, \
            review_by, member_count, created_at, \
            CASE WHEN octet_length(payload::STRING) <= $5 THEN payload END AS payload, \
            octet_length(payload::STRING) > $5 AS payload_elided \
     FROM memory_conflict_lifecycle_events_v1@primary \
     WHERE tenant_id = $1 AND project = $2 AND conflict_id = $3 \
     ORDER BY event_seq LIMIT $4";

const V2_DETECTOR_CLASS: i64 = 2;
const LEGACY_DETECTOR_CLASS: i64 = 1;

/// One lifecycle event to append; the database assigns its time.
pub(super) struct LifecycleEventDraft<'a> {
    pub(super) conflict_id: i64,
    pub(super) kind: &'a str,
    pub(super) episode_revision: i64,
    pub(super) result_revision: i64,
    pub(super) to_state: &'a str,
    pub(super) actor_kind: &'a str,
    pub(super) actor: &'a str,
    pub(super) operation: &'a str,
    pub(super) key: &'a str,
    pub(super) member_count: i64,
    pub(super) reason_kind: Option<&'a str>,
    pub(super) rationale: Option<&'a str>,
    pub(super) payload: Value,
}

/// An open v2 conflict locked in record's order and checked against the
/// caller's view.
struct LockedConflict {
    lineage: V2Lineage,
    claim_key: String,
    member_count: i64,
}

/// The canonical request identity an `acknowledge` receipt stores.
pub(super) fn acknowledge_request(
    scope: &FleetScope,
    target: ConflictTarget,
    reason: Option<&str>,
) -> Value {
    lifecycle_request_identity(
        ACKNOWLEDGE_OPERATION,
        scope,
        &json!({
            "conflict_id": target.conflict_id,
            "expected_revision": target.expected_revision,
            "reason": reason,
        }),
    )
}

/// The canonical request identity a concession `resolve` receipt stores. The
/// claim ids are bound sorted and deduplicated.
pub(super) fn resolve_request(
    scope: &FleetScope,
    target: ConflictTarget,
    retract_claim_ids: &[i64],
    reason: Option<&str>,
) -> Value {
    lifecycle_request_identity(
        RESOLVE_OPERATION,
        scope,
        &json!({
            "conflict_id": target.conflict_id,
            "expected_revision": target.expected_revision,
            "expected_member_count": target.expected_member_count,
            "retract_claim_ids": normalized_ids(retract_claim_ids),
            "reason": reason,
        }),
    )
}

fn normalized_ids(ids: &[i64]) -> Vec<i64> {
    let mut ids = ids.to_vec();
    ids.sort_unstable();
    ids.dedup();
    ids
}

fn require_capability(ledger: &CockroachClaimLedger) -> Result<()> {
    if ledger.serves_conflict_lifecycle() {
        return Ok(());
    }
    Err(LifecycleRefusal::new(
        RefusalCode::LifecycleUnavailable,
        "the conflict lifecycle log is not available to this deployment",
        json!({}),
    )
    .into())
}

fn validate_conflict_target(target: ConflictTarget, member_count_required: bool) -> Result<()> {
    if !(1..=MAX_SAFE_INTEGER).contains(&target.conflict_id)
        || !(1..=MAX_SAFE_INTEGER).contains(&target.expected_revision)
    {
        return Err(FleetError::Memory(format!(
            "conflict_id and expected_revision must be between 1 and {MAX_SAFE_INTEGER}"
        )));
    }
    match target.expected_member_count {
        None if member_count_required => Err(FleetError::Memory(
            "expected_member_count is required".into(),
        )),
        Some(count) if !(1..=MAX_CONFLICT_MEMBER_COUNT).contains(&count) => {
            Err(FleetError::Memory(format!(
                "expected_member_count must be between 1 and {MAX_CONFLICT_MEMBER_COUNT}"
            )))
        }
        _ => Ok(()),
    }
}

pub(super) async fn acknowledge_conflict(
    ledger: &CockroachClaimLedger,
    scope: &FleetScope,
    target: ConflictTarget,
    reason: Option<&str>,
    idempotency_key: &str,
) -> Result<ConflictMutation> {
    ledger.ensure_scope(scope)?;
    require_capability(ledger)?;
    let key = validated_idempotency_key(idempotency_key)?.to_owned();
    validate_conflict_target(target, false)?;
    if let Some(reason) = reason {
        validate_reason(reason).map_err(FleetError::Memory)?;
    }
    let request = acknowledge_request(scope, target, reason);
    let scope = scope.clone();
    let reason = reason.map(str::to_owned);
    with_serializable_retry(&ledger.pool, ledger.retry_policy, move |transaction| {
        let scope = scope.clone();
        let reason = reason.clone();
        let key = key.clone();
        let request = request.clone();
        Box::pin(async move {
            acknowledge_once(
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

async fn acknowledge_once(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    scope: &FleetScope,
    target: ConflictTarget,
    reason: Option<&str>,
    key: &str,
    request: &Value,
) -> Result<ConflictMutation> {
    if let Some(replay) =
        replay_or_reserve(transaction, scope, key, request, ACKNOWLEDGE_OPERATION).await?
    {
        return Ok(replay);
    }
    let locked = lock_open_conflict(transaction, scope, target).await?;
    let conflict_id = locked.lineage.id;
    let revision = locked.lineage.revision;

    // One acknowledgement per agent per episode; a second one commits its
    // receipt and changes nothing.
    let existing = sqlx::query_scalar::<_, i64>(ACK_EXISTS_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(conflict_id)
        .bind(revision)
        .bind(&scope.agent)
        .fetch_optional(&mut **transaction)
        .await?;
    let lifecycle_event = if existing.is_some() {
        None
    } else {
        Some(
            append_lifecycle_event(
                transaction,
                scope,
                LifecycleEventDraft {
                    conflict_id,
                    kind: "acknowledged",
                    episode_revision: revision,
                    result_revision: revision,
                    to_state: "open",
                    actor_kind: "agent",
                    actor: &scope.agent,
                    operation: ACKNOWLEDGE_OPERATION,
                    key,
                    member_count: locked.member_count,
                    reason_kind: None,
                    rationale: reason,
                    payload: json!({}),
                },
            )
            .await?,
        )
    };
    let applied = lifecycle_event.is_some();
    let status = if applied {
        "acknowledged"
    } else {
        "already_acknowledged"
    };
    insert_keyed_conflict_event(
        transaction,
        scope,
        "conflict_acknowledged",
        conflict_id,
        key,
        json!({
            "claim_key": locked.claim_key,
            "episode_revision": revision,
            "applied": applied,
            "status": status,
            "event_seq": lifecycle_event.as_ref().map(|event| event.seq),
        }),
    )
    .await?;

    let mutation = ConflictMutation {
        operation: ACKNOWLEDGE_ACTION.into(),
        conflict_id,
        conflict_state: "open".into(),
        conflict_revision: revision,
        member_count: locked.member_count,
        applied,
        status: Some(status.into()),
        lifecycle_event,
        claims_retracted: Vec::new(),
        claims_restored: Vec::new(),
        conflicts_resolved: Vec::new(),
        reevaluation: None,
        idempotent_replay: false,
    };
    finish_conflict_receipt(
        transaction,
        scope,
        key,
        request,
        ACKNOWLEDGE_OPERATION,
        &mutation,
    )
    .await?;
    Ok(mutation)
}

/// One concession `resolve` request, as the retried transaction sees it.
struct ResolveWrite<'a> {
    target: ConflictTarget,
    retract_claim_ids: &'a [i64],
    reason: Option<&'a str>,
    key: &'a str,
    request: &'a Value,
}

pub(super) async fn resolve_conflict(
    ledger: &CockroachClaimLedger,
    scope: &FleetScope,
    target: ConflictTarget,
    retract_claim_ids: &[i64],
    reason: Option<&str>,
    idempotency_key: &str,
) -> Result<ConflictMutation> {
    ledger.ensure_scope(scope)?;
    require_capability(ledger)?;
    let key = validated_idempotency_key(idempotency_key)?.to_owned();
    validate_conflict_target(target, true)?;
    if let Some(reason) = reason {
        validate_reason(reason).map_err(FleetError::Memory)?;
    }
    let retract_claim_ids = normalized_ids(retract_claim_ids);
    if retract_claim_ids.len() > MAX_CONCESSION_CLAIMS
        || retract_claim_ids
            .iter()
            .any(|id| !(1..=MAX_SAFE_INTEGER).contains(id))
    {
        return Err(FleetError::Memory(format!(
            "retract_claim_ids must name at most {MAX_CONCESSION_CLAIMS} claims between 1 and {MAX_SAFE_INTEGER}"
        )));
    }
    let request = resolve_request(scope, target, &retract_claim_ids, reason);
    let scope = scope.clone();
    let reason = reason.map(str::to_owned);
    with_serializable_retry(&ledger.pool, ledger.retry_policy, move |transaction| {
        let scope = scope.clone();
        let reason = reason.clone();
        let key = key.clone();
        let request = request.clone();
        let retract_claim_ids = retract_claim_ids.clone();
        Box::pin(async move {
            resolve_once(
                transaction,
                &scope,
                ResolveWrite {
                    target,
                    retract_claim_ids: &retract_claim_ids,
                    reason: reason.as_deref(),
                    key: &key,
                    request: &request,
                },
            )
            .await
        })
    })
    .await
}

#[allow(clippy::too_many_lines)] // one serializable unit, kept in its lock order
async fn resolve_once(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    scope: &FleetScope,
    write: ResolveWrite<'_>,
) -> Result<ConflictMutation> {
    let ResolveWrite {
        target,
        retract_claim_ids,
        reason,
        key,
        request,
    } = write;
    if let Some(replay) =
        replay_or_reserve(transaction, scope, key, request, RESOLVE_OPERATION).await?
    {
        return Ok(replay);
    }
    // Lineage first, then the key's current claims in id order, as record.
    let locked = lock_open_conflict(transaction, scope, target).await?;
    let conflict_id = locked.lineage.id;
    let current = lock_current_claims(transaction, scope, &locked.claim_key).await?;
    let members = members_among(transaction, scope, conflict_id, retract_claim_ids).await?;
    let concession = plan_concession(
        conflict_id,
        &scope.agent,
        retract_claim_ids,
        &members,
        current,
    )?;

    // The caller's own claims leave the current set first, exactly as a
    // retract moves them; nothing else is changed on any other agent's claim.
    for claim in &concession.retracted {
        transition_owned_claim(transaction, scope, claim, ClaimState::Retracted).await?;
        insert_transition_event(
            transaction,
            scope,
            claim.id,
            "retracted_by_author",
            claim.state,
            ClaimState::Retracted,
            json!({
                "conflict_id": conflict_id,
                "idempotency_key": key,
                "reason": reason,
                "revision_before": claim.revision,
            }),
        )
        .await?;
    }
    let claims_retracted = concession
        .retracted
        .iter()
        .map(|claim| claim.id)
        .collect::<Vec<_>>();

    // The conflict closes only when the detector, in Rust and in SQL, finds
    // no incompatible current pair left; otherwise everything rolls back.
    let sql_pairs = key_incompatible_pairs(transaction, scope, &locked.claim_key).await?;
    let restore_candidates = match plan_reevaluation(
        Some(locked.lineage),
        &concession.remaining,
        &sql_pairs,
    ) {
        Reevaluation::Close {
            restore_candidates, ..
        } => restore_candidates,
        Reevaluation::StillOpen { pairs, .. } => {
            return Err(LifecycleRefusal::new(
                    RefusalCode::StillIncompatible,
                    format!(
                        "conflict {conflict_id} would keep {} incompatible current pair(s); nothing was retracted",
                        pairs.len()
                    ),
                    json!({
                        "conflict_id": conflict_id,
                        "pair_count": pairs.len(),
                        "pairs": pairs
                            .iter()
                            .take(MAX_REPORTED_REMAINING_PAIRS)
                            .map(|(left, right)| [*left, *right])
                            .collect::<Vec<_>>(),
                    }),
                )
                .into());
        }
        Reevaluation::Divergent {
            rust_pairs,
            sql_pairs,
            ..
        } => {
            tracing::error!(
                conflict_id,
                rust_pairs = rust_pairs.len(),
                sql_pairs = sql_pairs.len(),
                "concession verification diverged between Rust and SQL; nothing was changed"
            );
            return Err(LifecycleRefusal::new(
                    RefusalCode::VerificationDivergence,
                    format!(
                        "the detector could not verify conflict {conflict_id} consistently; nothing was changed"
                    ),
                    json!({ "conflict_id": conflict_id }),
                )
                .into());
        }
        Reevaluation::NoLineage | Reevaluation::NotOpen => {
            return Err(protocol_error(
                "locked open conflict was not open during its concession",
            ));
        }
    };
    let resolution_reason = if claims_retracted.is_empty() {
        "no lifecycle-current incompatible pair remains on re-verification".to_owned()
    } else {
        format!(
            "no lifecycle-current incompatible pair remains after concession retracting claims {}",
            claims_retracted
                .iter()
                .map(i64::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    let effect = apply_verified_close(
        transaction,
        scope,
        VerifiedClose {
            conflict_id,
            conflict_revision: locked.lineage.revision,
            claim_key: &locked.claim_key,
            restore_candidates: &restore_candidates,
            current: &concession.remaining,
            resolution_reason: &resolution_reason,
        },
        &CloseAudit {
            operation: RESOLVE_OPERATION,
            key,
            cause: json!({
                "agent": scope.agent,
                "operation": RESOLVE_OPERATION,
                "claims_retracted": claims_retracted,
                "reason": reason,
            }),
            log: true,
        },
    )
    .await?;
    let conflict_revision = effect
        .reevaluation
        .as_ref()
        .map(|reevaluation| reevaluation.conflict_revision)
        .ok_or_else(|| protocol_error("verified close reported no revision"))?;
    insert_keyed_conflict_event(
        transaction,
        scope,
        "conflict_resolved",
        conflict_id,
        key,
        json!({
            "claim_key": locked.claim_key,
            "episode_revision": locked.lineage.revision,
            "conflict_revision": conflict_revision,
            "claims_retracted": claims_retracted,
            "claims_restored": effect.claims_restored,
        }),
    )
    .await?;

    let mutation = ConflictMutation {
        operation: RESOLVE_ACTION.into(),
        conflict_id,
        conflict_state: "resolved".into(),
        conflict_revision,
        member_count: locked.member_count,
        applied: true,
        status: Some("resolved".into()),
        lifecycle_event: effect.lifecycle_event,
        claims_retracted,
        claims_restored: effect.claims_restored,
        conflicts_resolved: effect.conflicts_resolved,
        reevaluation: effect.reevaluation,
        idempotent_replay: false,
    };
    finish_conflict_receipt(
        transaction,
        scope,
        key,
        request,
        RESOLVE_OPERATION,
        &mutation,
    )
    .await?;
    Ok(mutation)
}

/// Plain-read the target conflict, lock its key's lineage rows as record
/// does, and check that it is the key's open v2 conflict at the caller's
/// revision (and member count, when given).
async fn lock_open_conflict(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    scope: &FleetScope,
    target: ConflictTarget,
) -> Result<LockedConflict> {
    let conflict_id = target.conflict_id;
    let Some((_, claim_key, detector_class, _, _)) =
        sqlx::query_as::<_, (i64, String, i64, String, i64)>(CONFLICT_TARGET_SQL)
            .bind(scope.tenant_id)
            .bind(&scope.project)
            .bind(conflict_id)
            .fetch_optional(&mut **transaction)
            .await?
    else {
        return Err(LifecycleRefusal::new(
            RefusalCode::NotFound,
            format!("conflict {conflict_id} does not exist in this project"),
            json!({ "conflict_id": conflict_id }),
        )
        .into());
    };
    match detector_class {
        V2_DETECTOR_CLASS => {}
        LEGACY_DETECTOR_CLASS => {
            return Err(LifecycleRefusal::new(
                RefusalCode::LegacyLineage,
                format!(
                    "conflict {conflict_id} is an unreconciled legacy lineage; run conflict reconciliation first"
                ),
                json!({ "conflict_id": conflict_id }),
            )
            .into());
        }
        _ => {
            return Err(protocol_error(
                "database returned an unadmitted conflict detector",
            ));
        }
    }
    let lineage = lock_lineages(transaction, scope, &claim_key)
        .await?
        .filter(|lineage| lineage.id == conflict_id)
        .ok_or_else(|| protocol_error("conflict left its key's locked lineage"))?;
    let current_state = match lineage.state {
        ConflictRowState::Open => "open",
        ConflictRowState::Resolved => "resolved",
        ConflictRowState::Dismissed => "dismissed",
    };
    let details = json!({
        "conflict_id": conflict_id,
        "current_revision": lineage.revision,
        "current_state": current_state,
    });
    if lineage.state != ConflictRowState::Open {
        return Err(LifecycleRefusal::new(
            RefusalCode::NotOpen,
            format!(
                "conflict {conflict_id} is {current_state} at revision {}",
                lineage.revision
            ),
            details,
        )
        .into());
    }
    if lineage.revision != target.expected_revision {
        return Err(LifecycleRefusal::new(
            RefusalCode::StaleRevision,
            format!(
                "conflict {conflict_id} is at revision {} ({current_state})",
                lineage.revision
            ),
            details,
        )
        .into());
    }
    let member_count = member_count(transaction, scope, conflict_id).await?;
    if let Some(expected) = target.expected_member_count
        && expected != member_count
    {
        return Err(LifecycleRefusal::new(
            RefusalCode::StaleMemberCount,
            format!("conflict {conflict_id} has {member_count} members, not {expected}"),
            json!({
                "conflict_id": conflict_id,
                "current_member_count": member_count,
                "current_revision": lineage.revision,
            }),
        )
        .into());
    }
    Ok(LockedConflict {
        lineage,
        claim_key,
        member_count,
    })
}

/// The conflict's durable member count, refused past the log's bound.
pub(super) async fn member_count(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    scope: &FleetScope,
    conflict_id: i64,
) -> Result<i64> {
    let bound = usize::try_from(MAX_CONFLICT_MEMBER_COUNT)
        .map_err(|_| protocol_error("conflict member bound is outside usize range"))?;
    let count = sqlx::query_scalar::<_, i64>(MEMBER_COUNT_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(conflict_id)
        .bind(sentinel_limit(bound)?)
        .fetch_one(&mut **transaction)
        .await?;
    if count > MAX_CONFLICT_MEMBER_COUNT {
        return Err(LifecycleRefusal::new(
            RefusalCode::BoundExceeded,
            format!("conflict {conflict_id} has more than {MAX_CONFLICT_MEMBER_COUNT} members"),
            json!({ "conflict_id": conflict_id, "bound": MAX_CONFLICT_MEMBER_COUNT }),
        )
        .into());
    }
    Ok(count)
}

async fn members_among(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    scope: &FleetScope,
    conflict_id: i64,
    claim_ids: &[i64],
) -> Result<Vec<(i64, ClaimState, i64)>> {
    if claim_ids.is_empty() {
        return Ok(Vec::new());
    }
    sqlx::query_as::<_, (i64, String, i64)>(MEMBERS_AMONG_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(conflict_id)
        .bind(claim_ids)
        .fetch_all(&mut **transaction)
        .await?
        .into_iter()
        .map(|(id, state, revision)| Ok((id, parse_claim_state(&state)?, revision)))
        .collect()
}

/// Append one event to a conflict's lifecycle log at the next sequence. The
/// caller holds the conflict row lock, so no other writer can take the same
/// sequence; the primary key backstops that.
pub(super) async fn append_lifecycle_event(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    scope: &FleetScope,
    draft: LifecycleEventDraft<'_>,
) -> Result<ConflictLifecycleEvent> {
    let last = sqlx::query_scalar::<_, i64>(LAST_EVENT_SEQ_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(draft.conflict_id)
        .fetch_optional(&mut **transaction)
        .await?
        .unwrap_or(0);
    let seq = last + 1;
    if seq > MAX_CONFLICT_LIFECYCLE_EVENTS {
        return Err(LifecycleRefusal::new(
            RefusalCode::BoundExceeded,
            format!(
                "conflict {} already has {MAX_CONFLICT_LIFECYCLE_EVENTS} lifecycle events",
                draft.conflict_id
            ),
            json!({
                "conflict_id": draft.conflict_id,
                "bound": MAX_CONFLICT_LIFECYCLE_EVENTS,
            }),
        )
        .into());
    }
    let row = sqlx::query(INSERT_LIFECYCLE_EVENT_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(draft.conflict_id)
        .bind(seq)
        .bind(draft.kind)
        .bind(draft.episode_revision)
        .bind(draft.result_revision)
        .bind(draft.to_state)
        .bind(draft.actor_kind)
        .bind(draft.actor)
        .bind(&scope.session_id)
        .bind(draft.operation)
        .bind(draft.key)
        .bind(draft.member_count)
        .bind(draft.reason_kind)
        .bind(draft.rationale)
        // Waiver expiry and review hours; this slice appends no waiver.
        .bind(None::<i64>)
        .bind(None::<i64>)
        .bind(&draft.payload)
        .fetch_one(&mut **transaction)
        .await?;
    Ok(ConflictLifecycleEvent {
        seq,
        kind: draft.kind.into(),
        actor_kind: draft.actor_kind.into(),
        actor: draft.actor.into(),
        operation: draft.operation.into(),
        episode_revision: draft.episode_revision,
        result_revision: draft.result_revision,
        reason_kind: draft.reason_kind.map(str::to_owned),
        rationale: draft.rationale.map(str::to_owned),
        expires_at: row.try_get("expires_at")?,
        review_by: row.try_get("review_by")?,
        member_count: draft.member_count,
        created_at: row.try_get("created_at")?,
        payload: Some(draft.payload),
        payload_elided: false,
    })
}

async fn insert_keyed_conflict_event(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    scope: &FleetScope,
    event_kind: &str,
    conflict_id: i64,
    key: &str,
    payload: Value,
) -> Result<()> {
    sqlx::query(INSERT_KEYED_CONFLICT_EVENT_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(&scope.agent)
        .bind(&scope.session_id)
        .bind(event_kind)
        .bind(conflict_id.to_string())
        .bind(key)
        .bind(payload)
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

async fn finish_conflict_receipt(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    scope: &FleetScope,
    key: &str,
    request: &Value,
    operation: &str,
    mutation: &ConflictMutation,
) -> Result<()> {
    let response = serde_json::to_value(mutation)
        .map_err(|error| protocol_error(format!("serialize idempotency response: {error}")))?;
    let receipt = sqlx::query(FINISH_CONFLICT_RECEIPT_SQL)
        .bind(scope.tenant_id)
        .bind(key)
        .bind(&scope.project)
        .bind(request)
        .bind(operation)
        .bind(mutation.conflict_id)
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

/// The newest events of each `(conflict_id, episode_revision)`, in one
/// autocommit statement outside any read transaction.
pub(super) async fn conflict_lifecycle_rows(
    ledger: &CockroachClaimLedger,
    scope: &FleetScope,
    episodes: &[(i64, i64)],
) -> Result<ConflictLifecycleRows> {
    ledger.ensure_scope(scope)?;
    require_capability(ledger)?;
    if episodes.len() > MAX_LEDGER_RESULTS {
        return Err(FleetError::Memory(format!(
            "the lifecycle overlay reads at most {MAX_LEDGER_RESULTS} conflicts"
        )));
    }
    if episodes.iter().any(|(id, revision)| {
        !(1..=MAX_SAFE_INTEGER).contains(id) || !(1..=MAX_SAFE_INTEGER).contains(revision)
    }) {
        return Err(FleetError::Memory(
            "lifecycle overlay coordinates must be positive safe integers".into(),
        ));
    }
    let (ids, revisions): (Vec<i64>, Vec<i64>) = episodes.iter().copied().unzip();
    let rows = sqlx::query(LIFECYCLE_OVERLAY_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(&ids)
        .bind(&revisions)
        .bind(sentinel_limit(MAX_OVERLAY_EPISODE_EVENTS)?)
        .fetch_all(&ledger.pool)
        .await?;
    let mut evaluated_at = None;
    let mut events = std::collections::HashMap::<i64, Vec<ConflictLifecycleEvent>>::new();
    for row in &rows {
        evaluated_at = Some(row.try_get::<DateTime<Utc>, _>("evaluated_at")?);
        let conflict_id: i64 = row.try_get("wanted_conflict_id")?;
        let entry = events.entry(conflict_id).or_default();
        if row.try_get::<Option<i64>, _>("event_seq")?.is_some() {
            entry.push(decode_lifecycle_event(row, false)?);
        }
    }
    let evaluated_at = match evaluated_at {
        Some(at) => at,
        None if episodes.is_empty() => Utc::now(),
        None => return Err(protocol_error("lifecycle overlay returned no rows")),
    };
    Ok(ConflictLifecycleRows {
        events,
        evaluated_at,
    })
}

/// A conflict's lifecycle log, oldest first, bounded to 256 events.
pub(super) async fn conflict_lifecycle_history(
    ledger: &CockroachClaimLedger,
    scope: &FleetScope,
    conflict_id: i64,
) -> Result<ConflictHistory> {
    ledger.ensure_scope(scope)?;
    require_capability(ledger)?;
    if !(1..=MAX_SAFE_INTEGER).contains(&conflict_id) {
        return Err(FleetError::Memory(format!(
            "conflict_id must be between 1 and {MAX_SAFE_INTEGER}"
        )));
    }
    let rows = sqlx::query(LIFECYCLE_HISTORY_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(conflict_id)
        .bind(sentinel_limit(MAX_HISTORY_EVENTS)?)
        .bind(
            i64::try_from(MAX_HISTORY_PAYLOAD_BYTES)
                .map_err(|_| protocol_error("history payload bound is outside INT8 range"))?,
        )
        .fetch_all(&ledger.pool)
        .await?;
    let truncated = rows.len() > MAX_HISTORY_EVENTS;
    let events = rows
        .iter()
        .take(MAX_HISTORY_EVENTS)
        .map(|row| decode_lifecycle_event(row, true))
        .collect::<Result<Vec<_>>>()?;
    if events.windows(2).any(|pair| pair[0].seq >= pair[1].seq) {
        return Err(protocol_error("lifecycle history was not in event order"));
    }
    Ok(ConflictHistory { events, truncated })
}

fn decode_lifecycle_event(row: &PgRow, with_payload: bool) -> Result<ConflictLifecycleEvent> {
    let (payload, payload_elided) = if with_payload {
        (
            row.try_get::<Option<Value>, _>("payload")?,
            row.try_get::<bool, _>("payload_elided")?,
        )
    } else {
        (None, false)
    };
    Ok(ConflictLifecycleEvent {
        seq: row.try_get("event_seq")?,
        kind: row.try_get("event_kind")?,
        actor_kind: row.try_get("actor_kind")?,
        actor: row.try_get("actor")?,
        operation: row.try_get("operation")?,
        episode_revision: row.try_get("episode_revision")?,
        result_revision: row.try_get("result_revision")?,
        reason_kind: row.try_get("reason_kind")?,
        rationale: row.try_get("rationale")?,
        expires_at: row.try_get("expires_at")?,
        review_by: row.try_get("review_by")?,
        member_count: row.try_get("member_count")?,
        created_at: row.try_get("created_at")?,
        payload,
        payload_elided,
    })
}

#[cfg(test)]
mod tests {
    use ostk_recall_core::PrivacyTier;
    use uuid::Uuid;

    use super::super::lifecycle_store::decode_receipt_values;
    use super::*;

    fn scope() -> FleetScope {
        FleetScope::new(
            Uuid::from_u128(1),
            "project",
            "agent-a",
            Some("turn-3".into()),
            PrivacyTier::T1Project,
        )
        .unwrap()
    }

    fn target(expected_member_count: Option<i64>) -> ConflictTarget {
        ConflictTarget {
            conflict_id: 9,
            expected_revision: 3,
            expected_member_count,
        }
    }

    #[test]
    fn resolve_identity_binds_the_normalized_concession() {
        let scope = scope();
        let request = resolve_request(&scope, target(Some(2)), &[42, 41, 42], Some("wrong"));
        assert_eq!(request["action"], RESOLVE_OPERATION);
        assert_eq!(request["input"]["retract_claim_ids"], json!([41, 42]));
        assert_eq!(request["input"]["expected_member_count"], 2);
        assert_eq!(
            request,
            resolve_request(&scope, target(Some(2)), &[41, 42], Some("wrong")),
            "order and duplicates do not change the request"
        );
        for other in [
            resolve_request(&scope, target(Some(3)), &[41, 42], Some("wrong")),
            resolve_request(&scope, target(Some(2)), &[41], Some("wrong")),
            resolve_request(&scope, target(Some(2)), &[41, 42], None),
            acknowledge_request(&scope, target(None), Some("wrong")),
        ] {
            assert_ne!(other, request);
        }
        assert_eq!(
            acknowledge_request(&scope, target(None), None)["action"],
            ACKNOWLEDGE_OPERATION
        );
    }

    #[test]
    fn conflict_receipts_replay_only_their_own_operation() {
        let scope = scope();
        let request = acknowledge_request(&scope, target(None), None);
        let stored = json!({
            "operation": "acknowledge", "conflict_id": 9, "conflict_state": "open",
            "conflict_revision": 3, "member_count": 2, "applied": true,
            "status": "acknowledged", "lifecycle_event": null,
            "claims_retracted": [], "claims_restored": [], "conflicts_resolved": [],
            "idempotent_replay": false,
        });
        let replay: ConflictMutation = decode_receipt_values(
            "project",
            ACKNOWLEDGE_OPERATION,
            &request,
            Some(stored.clone()),
            &scope,
            ACKNOWLEDGE_OPERATION,
            &request,
        )
        .unwrap();
        assert!(replay.idempotent_replay);
        assert!(replay.applied);
        // The same key under another conflict operation is a different mutation.
        assert!(matches!(
            decode_receipt_values::<ConflictMutation>(
                "project",
                ACKNOWLEDGE_OPERATION,
                &request,
                Some(stored),
                &scope,
                RESOLVE_OPERATION,
                &resolve_request(&scope, target(Some(2)), &[], None),
            ),
            Err(FleetError::IdempotencyConflict(_))
        ));
    }

    #[test]
    fn conflict_targets_are_bounded_before_io() {
        assert!(validate_conflict_target(target(None), false).is_ok());
        assert!(validate_conflict_target(target(Some(2)), true).is_ok());
        assert!(validate_conflict_target(target(None), true).is_err());
        for bad in [
            ConflictTarget {
                conflict_id: 0,
                ..target(None)
            },
            ConflictTarget {
                expected_revision: MAX_SAFE_INTEGER + 1,
                ..target(None)
            },
            target(Some(0)),
            target(Some(MAX_CONFLICT_MEMBER_COUNT + 1)),
        ] {
            assert!(validate_conflict_target(bad, false).is_err(), "{bad:?}");
        }
    }
}
