//! Audit-trail reads beside the ledger's mutations: the claims on one exact
//! key, the conflicts detected on it, one claim's lifecycle history, the
//! open conflicts `recall(status)` counts, and the two claim listings
//! `recall(brief)` composes: the scope's most recently changed claims and a
//! subject's claims.
//!
//! Every read is bounded before transfer, seeks an existing index, and
//! projects only what its public answer carries. None of them writes.

use std::collections::HashMap;

use serde_json::Value;
use sqlx::postgres::PgRow;
use sqlx::{Postgres, Row, Transaction};

use super::lifecycle_store::{MAX_SAFE_INTEGER, sentinel_limit};
use super::{
    CockroachClaimLedger, decode_claim, decode_support, fetch_current_claim_conflict_ids,
    protocol_error,
};
use crate::ledger::{
    ClaimHistoryV1, ClaimLifecycleEventV1, ClaimsForKeyV1, KeyClaimV1, MAX_BRIEF_CLAIMS,
    MAX_CLAIM_HISTORY_EVENTS, MAX_KEY_LOOKUP_CLAIMS, MAX_KEY_LOOKUP_VALUE_BYTES,
    MAX_OPEN_CONFLICT_ROWS, OpenConflictRowV1, OpenConflictsV1, RecentClaimsV1, normalize_key_part,
};
use crate::store::cockroach::with_serializable_retry;
use crate::{FleetError, FleetScope, Result};

/// Longest stored claim key one lookup accepts: the detector's own bound
/// on `subject::predicate` and `claim-v2:` keys, generously.
pub(super) const MAX_LOOKUP_CLAIM_KEY_BYTES: usize = 2_048;

/// Support rows one key lookup reads: the record bound of 32 per claim over
/// the claim bound, plus a sentinel.
const MAX_KEY_LOOKUP_SUPPORT_ROWS: usize = MAX_KEY_LOOKUP_CLAIMS * 32;

/// A claim history payload larger than this is not transferred; the event's
/// derived fields are then absent and `payload_elided` says so.
const MAX_CLAIM_HISTORY_PAYLOAD_BYTES: usize = 4_096;

/// The claims carrying one stored key, in id (recording) order, through the
/// scoped key index; `$4` widens the read from lifecycle-current states to
/// every state. Values are projected only up to the lookup's bound.
const KEY_CLAIMS_SQL: &str = "SELECT id, project, kind, claim_key, subject, predicate, \
            CASE WHEN value IS NULL OR octet_length(value::STRING) > $6 \
                 THEN NULL ELSE value END AS value, \
            text, polarity, state, origin, actor, confidence, valid_from, valid_to, \
            superseded_by, revision, conflict_eligible, created_at, updated_at, \
            (value IS NOT NULL AND octet_length(value::STRING) > $6) AS value_elided \
     FROM memory_claims@memory_claims_scope_key_idx \
     WHERE tenant_id = $1 AND project = $2 AND claim_key = $3 \
       AND ($4 OR state IN ('active', 'disputed')) \
     ORDER BY id LIMIT $5";

/// The support rows of the looked-up claims, in each claim's `get` order.
const KEY_SUPPORT_SQL: &str = "SELECT claim_id, id, source_config_id, source, source_id, chunk_id, \
            content_sha256, excerpt, relation, state, observed_at, invalidated_at \
     FROM memory_claim_support \
     WHERE tenant_id = $1 AND project = $2 AND claim_id = ANY($3) \
     ORDER BY claim_id, observed_at, id LIMIT $4";

/// The scope's most recently changed lifecycle-current claims: one bounded
/// seek of the scoped state index per current state, in the index's own
/// `updated_at DESC` order, merged and cut to the bound, then each claim's
/// projection through the primary. Values are projected only up to the
/// lookup's bound.
const RECENT_CLAIMS_SQL: &str = "WITH active_rows AS MATERIALIZED (\
       SELECT id, updated_at FROM memory_claims@memory_claims_scope_state_idx \
       WHERE tenant_id = $1 AND project = $2 AND state = 'active' \
       ORDER BY updated_at DESC, id LIMIT $3\
     ), disputed_rows AS MATERIALIZED (\
       SELECT id, updated_at FROM memory_claims@memory_claims_scope_state_idx \
       WHERE tenant_id = $1 AND project = $2 AND state = 'disputed' \
       ORDER BY updated_at DESC, id LIMIT $3\
     ), recent AS (\
       SELECT id, updated_at FROM (\
         SELECT id, updated_at FROM active_rows \
         UNION ALL SELECT id, updated_at FROM disputed_rows\
       ) AS merged ORDER BY updated_at DESC, id LIMIT $3\
     ) \
     SELECT claim.id, claim.project, claim.kind, claim.claim_key, claim.subject, \
            claim.predicate, \
            CASE WHEN claim.value IS NULL OR octet_length(claim.value::STRING) > $4 \
                 THEN NULL ELSE claim.value END AS value, \
            claim.text, claim.polarity, claim.state, claim.origin, claim.actor, \
            claim.confidence, claim.valid_from, claim.valid_to, claim.superseded_by, \
            claim.revision, claim.conflict_eligible, claim.created_at, claim.updated_at, \
            (claim.value IS NOT NULL AND octet_length(claim.value::STRING) > $4) AS value_elided \
     FROM recent \
     JOIN memory_claims@primary AS claim \
       ON claim.tenant_id = $1 AND claim.project = $2 AND claim.id = recent.id \
     ORDER BY recent.updated_at DESC, recent.id";

/// A subject's lifecycle-current claims: the keys in the two half-open
/// spans `[subject::, subject::\u{10FFFF})` and `[subject-, subject-\u{10FFFF})`
/// of the scoped key index (`$3..$6`), in key then recording order. Values
/// are projected only up to the lookup's bound.
const SUBJECT_CLAIMS_SQL: &str = "SELECT id, project, kind, claim_key, subject, predicate, \
            CASE WHEN value IS NULL OR octet_length(value::STRING) > $8 \
                 THEN NULL ELSE value END AS value, \
            text, polarity, state, origin, actor, confidence, valid_from, valid_to, \
            superseded_by, revision, conflict_eligible, created_at, updated_at, \
            (value IS NOT NULL AND octet_length(value::STRING) > $8) AS value_elided \
     FROM memory_claims@memory_claims_scope_key_idx \
     WHERE tenant_id = $1 AND project = $2 \
       AND ((claim_key >= $3 AND claim_key < $4) OR (claim_key >= $5 AND claim_key < $6)) \
       AND state IN ('active', 'disputed') \
     ORDER BY claim_key, id LIMIT $7";

/// The conflicts detected on one key: one per detector through the v15
/// unique index, so a third row is an unknown lineage the read reports.
const CONFLICT_IDS_FOR_KEY_SQL: &str = "SELECT id \
     FROM memory_conflicts@memory_conflicts_scope_key_detector_unique_idx \
     WHERE tenant_id = $1 AND project = $2 AND claim_key = $3 \
     ORDER BY detector LIMIT 3";

/// A claim's newest lifecycle events through the claim index, payload
/// transferred only within the bound. Events of one transaction share its
/// `created_at`, so within a tie the claim's birth sorts before its
/// transition (a `record` disputed in the call, a successor that joins the
/// conflict); event ids are random and break no further tie.
const CLAIM_HISTORY_SQL: &str = "SELECT event_id, event_kind, actor, reason, from_state, to_state, \
            created_at, \
            CASE WHEN octet_length(payload::STRING) <= $5 THEN payload END AS payload, \
            octet_length(payload::STRING) > $5 AS payload_elided \
     FROM memory_claim_events@memory_claim_events_claim_idx \
     WHERE tenant_id = $1 AND project = $2 AND claim_id = $3 \
     ORDER BY created_at DESC, (event_kind = 'recorded') ASC, event_id DESC LIMIT $4";

/// The stored key of one claim, for the predecessor seek below.
const CLAIM_KEY_SQL: &str = "SELECT claim_key FROM memory_claims@primary \
     WHERE tenant_id = $1 AND project = $2 AND id = $3";

/// The same key's superseded claim whose successor link names `$4`: the
/// predecessor of a successor. Two would break the supersede invariant.
const PREDECESSOR_SQL: &str = "SELECT id FROM memory_claims@memory_claims_scope_key_idx \
     WHERE tenant_id = $1 AND project = $2 AND claim_key = $3 \
       AND state = 'superseded' AND superseded_by = $4 \
     ORDER BY id LIMIT 2";

/// The open conflicts of both admitted detector lineages, each branch an
/// exact seek of the v17 recency index bounded by the sentinel, then the
/// oldest first with each conflict's durable member count.
const OPEN_CONFLICTS_SQL: &str = "WITH v2_open AS MATERIALIZED (\
       SELECT id, revision, detected_at \
       FROM memory_conflicts@memory_conflicts_scope_detector_state_recency_idx \
       WHERE tenant_id = $1 AND project = $2 \
         AND detector = 'same_key_functional_value_v2' AND state = 'open' \
       ORDER BY last_seen_at DESC, id LIMIT $3\
     ), v1_open AS MATERIALIZED (\
       SELECT id, revision, detected_at \
       FROM memory_conflicts@memory_conflicts_scope_detector_state_recency_idx \
       WHERE tenant_id = $1 AND project = $2 \
         AND detector = 'same_key_typed_value' AND state = 'open' \
       ORDER BY last_seen_at DESC, id LIMIT $3\
     ), open_rows AS (\
       SELECT id, revision, detected_at FROM v2_open \
       UNION ALL SELECT id, revision, detected_at FROM v1_open\
     ) \
     SELECT open_rows.id, open_rows.revision, open_rows.detected_at, \
            (SELECT count(*)::INT8 FROM memory_conflict_members@primary AS member \
             WHERE member.tenant_id = $1 AND member.project = $2 \
               AND member.conflict_id = open_rows.id) AS member_count \
     FROM open_rows ORDER BY detected_at, id LIMIT $3";

/// A stored key a lookup can seek: non-empty, trimmed by the caller, and
/// within the bound.
pub(super) fn validated_claim_key(claim_key: &str) -> Result<&str> {
    if claim_key.is_empty() || claim_key.len() > MAX_LOOKUP_CLAIM_KEY_BYTES {
        return Err(FleetError::Memory(format!(
            "claim_key must be between 1 and {MAX_LOOKUP_CLAIM_KEY_BYTES} bytes"
        )));
    }
    Ok(claim_key)
}

/// Every claim on `claim_key` (see [`crate::ledger::ClaimLedger::claims_for_key`]).
pub(super) async fn claims_for_key(
    ledger: &CockroachClaimLedger,
    scope: &FleetScope,
    claim_key: &str,
    include_history: bool,
) -> Result<ClaimsForKeyV1> {
    ledger.ensure_scope(scope)?;
    let claim_key = validated_claim_key(claim_key)?.to_owned();
    let scope = scope.clone();
    with_serializable_retry(&ledger.pool, ledger.retry_policy, move |transaction| {
        let scope = scope.clone();
        let claim_key = claim_key.clone();
        Box::pin(async move {
            let rows = sqlx::query(KEY_CLAIMS_SQL)
                .bind(scope.tenant_id)
                .bind(&scope.project)
                .bind(&claim_key)
                .bind(include_history)
                .bind(sentinel_limit(MAX_KEY_LOOKUP_CLAIMS)?)
                .bind(
                    i64::try_from(MAX_KEY_LOOKUP_VALUE_BYTES)
                        .map_err(|_| protocol_error("key lookup value bound exceeds INT8"))?,
                )
                .fetch_all(&mut **transaction)
                .await?;
            let mut truncated = rows.len() > MAX_KEY_LOOKUP_CLAIMS;
            let mut claims = Vec::with_capacity(rows.len().min(MAX_KEY_LOOKUP_CLAIMS));
            for row in rows.iter().take(MAX_KEY_LOOKUP_CLAIMS) {
                let entry = decode_key_claim(row)?;
                if entry.claim.claim_key.as_deref() != Some(claim_key.as_str()) {
                    return Err(protocol_error(
                        "key lookup returned a claim carrying another key",
                    ));
                }
                claims.push(entry);
            }
            truncated |= attach_support_and_conflicts(transaction, &scope, &mut claims).await?;
            Ok(ClaimsForKeyV1 { claims, truncated })
        })
    })
    .await
}

/// One projected claim row with its `value_elided` flag.
fn decode_key_claim(row: &PgRow) -> Result<KeyClaimV1> {
    Ok(KeyClaimV1 {
        value_elided: row.try_get("value_elided")?,
        claim: decode_claim(row)?,
    })
}

/// Attach each claim's support rows (`KEY_SUPPORT_SQL`, in `get` order) and
/// current conflict ids, in the lookup's own transaction; `true` when more
/// support rows existed than the bound transfers.
async fn attach_support_and_conflicts(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &FleetScope,
    claims: &mut [KeyClaimV1],
) -> Result<bool> {
    let claim_ids = claims
        .iter()
        .map(|entry| entry.claim.id)
        .collect::<Vec<_>>();
    if claim_ids.is_empty() {
        return Ok(false);
    }
    let support_rows = sqlx::query(KEY_SUPPORT_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(&claim_ids)
        .bind(sentinel_limit(MAX_KEY_LOOKUP_SUPPORT_ROWS)?)
        .fetch_all(&mut **transaction)
        .await?;
    let truncated = support_rows.len() > MAX_KEY_LOOKUP_SUPPORT_ROWS;
    let mut support_by_claim: HashMap<i64, Vec<_>> = HashMap::new();
    for row in support_rows.iter().take(MAX_KEY_LOOKUP_SUPPORT_ROWS) {
        let claim_id: i64 = row.try_get("claim_id")?;
        support_by_claim
            .entry(claim_id)
            .or_default()
            .push(decode_support(row)?);
    }
    let mut conflict_ids = fetch_current_claim_conflict_ids(transaction, scope, &claim_ids).await?;
    for entry in claims.iter_mut() {
        if let Some(support) = support_by_claim.remove(&entry.claim.id) {
            entry.claim.support = support;
        }
        if let Some(ids) = conflict_ids.remove(&entry.claim.id) {
            entry.claim.conflict_ids = ids;
        }
    }
    Ok(truncated)
}

/// A brief's claim bound: `1..=MAX_BRIEF_CLAIMS`.
fn validated_brief_limit(limit: usize) -> Result<usize> {
    if !(1..=MAX_BRIEF_CLAIMS).contains(&limit) {
        return Err(FleetError::Memory(format!(
            "brief claim limit must be between 1 and {MAX_BRIEF_CLAIMS}"
        )));
    }
    Ok(limit)
}

/// The value bound of a claim projection, as `INT8`.
fn lookup_value_bound() -> Result<i64> {
    i64::try_from(MAX_KEY_LOOKUP_VALUE_BYTES)
        .map_err(|_| protocol_error("key lookup value bound exceeds INT8"))
}

/// The scope's most recently changed current claims (see
/// [`crate::ledger::ClaimLedger::recent_claims`]).
pub(super) async fn recent_claims(
    ledger: &CockroachClaimLedger,
    scope: &FleetScope,
    limit: usize,
) -> Result<RecentClaimsV1> {
    ledger.ensure_scope(scope)?;
    let limit = validated_brief_limit(limit)?;
    let scope = scope.clone();
    with_serializable_retry(&ledger.pool, ledger.retry_policy, move |transaction| {
        let scope = scope.clone();
        Box::pin(async move {
            let rows = sqlx::query(RECENT_CLAIMS_SQL)
                .bind(scope.tenant_id)
                .bind(&scope.project)
                .bind(sentinel_limit(limit)?)
                .bind(lookup_value_bound()?)
                .fetch_all(&mut **transaction)
                .await?;
            let mut truncated = rows.len() > limit;
            let mut claims = rows
                .iter()
                .take(limit)
                .map(decode_key_claim)
                .collect::<Result<Vec<_>>>()?;
            truncated |= attach_support_and_conflicts(transaction, &scope, &mut claims).await?;
            Ok(RecentClaimsV1 { claims, truncated })
        })
    })
    .await
}

/// The two half-open key spans a subject's claims lie in: the subject's own
/// keys (`subject::…`) and the keys of subjects that continue its words
/// (`subject-…`), each `[lower, upper)` with `\u{10FFFF}`, the largest
/// scalar, closing it in UTF-8 byte order. `None` when the subject
/// normalizes to nothing.
fn subject_spans(subject: &str) -> Option<[(String, String); 2]> {
    let subject = normalize_key_part(subject);
    if subject.is_empty() {
        return None;
    }
    Some(["::", "-"].map(|separator| {
        (
            format!("{subject}{separator}"),
            format!("{subject}{separator}\u{10FFFF}"),
        )
    }))
}

/// A subject's lifecycle-current claims (see
/// [`crate::ledger::ClaimLedger::claims_for_subject`]).
pub(super) async fn claims_for_subject(
    ledger: &CockroachClaimLedger,
    scope: &FleetScope,
    subject: &str,
    limit: usize,
) -> Result<ClaimsForKeyV1> {
    ledger.ensure_scope(scope)?;
    let limit = validated_brief_limit(limit)?;
    let spans = subject_spans(subject)
        .ok_or_else(|| FleetError::Memory("subject must contain at least one word".into()))?;
    for (lower, _) in &spans {
        validated_claim_key(lower)?;
    }
    let scope = scope.clone();
    with_serializable_retry(&ledger.pool, ledger.retry_policy, move |transaction| {
        let scope = scope.clone();
        let spans = spans.clone();
        Box::pin(async move {
            let [(own_lower, own_upper), (continued_lower, continued_upper)] = spans;
            let rows = sqlx::query(SUBJECT_CLAIMS_SQL)
                .bind(scope.tenant_id)
                .bind(&scope.project)
                .bind(&own_lower)
                .bind(&own_upper)
                .bind(&continued_lower)
                .bind(&continued_upper)
                .bind(sentinel_limit(limit)?)
                .bind(lookup_value_bound()?)
                .fetch_all(&mut **transaction)
                .await?;
            let mut truncated = rows.len() > limit;
            let mut claims = Vec::with_capacity(rows.len().min(limit));
            for row in rows.iter().take(limit) {
                let entry = decode_key_claim(row)?;
                let within = entry.claim.claim_key.as_deref().is_some_and(|key| {
                    key.starts_with(own_lower.as_str()) || key.starts_with(continued_lower.as_str())
                });
                if !within {
                    return Err(protocol_error(
                        "subject lookup returned a claim outside the subject's spans",
                    ));
                }
                claims.push(entry);
            }
            truncated |= attach_support_and_conflicts(transaction, &scope, &mut claims).await?;
            Ok(ClaimsForKeyV1 { claims, truncated })
        })
    })
    .await
}

/// The conflicts detected on `claim_key`, any state, at most one per
/// detector.
pub(super) async fn conflict_ids_for_key(
    ledger: &CockroachClaimLedger,
    scope: &FleetScope,
    claim_key: &str,
) -> Result<Vec<i64>> {
    ledger.ensure_scope(scope)?;
    let claim_key = validated_claim_key(claim_key)?;
    let ids = sqlx::query_scalar::<_, i64>(CONFLICT_IDS_FOR_KEY_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(claim_key)
        .fetch_all(&ledger.pool)
        .await?;
    if ids.len() > 2 {
        return Err(protocol_error(
            "a claim key carries more conflict lineages than the two admitted detectors",
        ));
    }
    Ok(ids)
}

/// One claim's lifecycle history (see
/// [`crate::ledger::ClaimLedger::claim_lifecycle_history`]).
pub(super) async fn claim_lifecycle_history(
    ledger: &CockroachClaimLedger,
    scope: &FleetScope,
    claim_id: i64,
) -> Result<ClaimHistoryV1> {
    ledger.ensure_scope(scope)?;
    if !(1..=MAX_SAFE_INTEGER).contains(&claim_id) {
        return Err(FleetError::Memory(format!(
            "claim_id must be between 1 and {MAX_SAFE_INTEGER}"
        )));
    }
    let rows = sqlx::query(CLAIM_HISTORY_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(claim_id)
        .bind(sentinel_limit(MAX_CLAIM_HISTORY_EVENTS)?)
        .bind(
            i64::try_from(MAX_CLAIM_HISTORY_PAYLOAD_BYTES)
                .map_err(|_| protocol_error("claim history payload bound exceeds INT8"))?,
        )
        .fetch_all(&ledger.pool)
        .await?;
    let truncated = rows.len() > MAX_CLAIM_HISTORY_EVENTS;
    let mut events = rows
        .iter()
        .take(MAX_CLAIM_HISTORY_EVENTS)
        .map(decode_claim_event)
        .collect::<Result<Vec<_>>>()?;
    events.reverse();

    // A successor's predecessor is the same key's superseded claim that
    // names it; a keyless claim cannot be superseded.
    let claim_key: Option<Option<String>> = sqlx::query_scalar(CLAIM_KEY_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(claim_id)
        .fetch_optional(&ledger.pool)
        .await?;
    let supersedes = match claim_key.flatten() {
        Some(claim_key) => {
            let predecessors = sqlx::query_scalar::<_, i64>(PREDECESSOR_SQL)
                .bind(scope.tenant_id)
                .bind(&scope.project)
                .bind(&claim_key)
                .bind(claim_id)
                .fetch_all(&ledger.pool)
                .await?;
            if predecessors.len() > 1 {
                return Err(protocol_error("two superseded claims name one successor"));
            }
            predecessors.first().copied()
        }
        None => None,
    };
    Ok(ClaimHistoryV1 {
        events,
        truncated,
        supersedes,
    })
}

fn decode_claim_event(row: &PgRow) -> Result<ClaimLifecycleEventV1> {
    let event_id: uuid::Uuid = row.try_get("event_id")?;
    let payload: Option<Value> = row.try_get("payload")?;
    let payload_elided: bool = row.try_get("payload_elided")?;
    let field = |name: &str| payload.as_ref().and_then(|payload| payload.get(name));
    let integer = |name: &str| field(name).and_then(Value::as_i64);
    Ok(ClaimLifecycleEventV1 {
        event_id: event_id.to_string(),
        kind: row.try_get("event_kind")?,
        actor: row.try_get("actor")?,
        reason: row.try_get("reason")?,
        from_state: row.try_get("from_state")?,
        to_state: row.try_get("to_state")?,
        revision_before: integer("revision_before"),
        successor_claim_id: integer("successor_claim_id"),
        conflict_id: integer("conflict_id"),
        supersedes: integer("supersedes"),
        note: field("reason").and_then(Value::as_str).map(str::to_owned),
        created_at: row.try_get("created_at")?,
        payload_elided,
    })
}

/// The project's open conflicts (see
/// [`crate::ledger::ClaimLedger::open_conflicts`]).
pub(super) async fn open_conflicts(
    ledger: &CockroachClaimLedger,
    scope: &FleetScope,
) -> Result<OpenConflictsV1> {
    ledger.ensure_scope(scope)?;
    let rows = sqlx::query(OPEN_CONFLICTS_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(sentinel_limit(MAX_OPEN_CONFLICT_ROWS)?)
        .fetch_all(&ledger.pool)
        .await?;
    let bound_exceeded = rows.len() > MAX_OPEN_CONFLICT_ROWS;
    let rows = rows
        .iter()
        .take(MAX_OPEN_CONFLICT_ROWS)
        .map(|row| {
            Ok(OpenConflictRowV1 {
                id: row.try_get("id")?,
                revision: row.try_get("revision")?,
                member_count: row.try_get("member_count")?,
                detected_at: row.try_get("detected_at")?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(OpenConflictsV1 {
        rows,
        bound_exceeded,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_reads_seek_indexes_and_bound_transfer() {
        assert!(KEY_CLAIMS_SQL.contains("memory_claims@memory_claims_scope_key_idx"));
        assert!(KEY_CLAIMS_SQL.contains("claim_key = $3"));
        assert!(KEY_CLAIMS_SQL.contains("($4 OR state IN ('active', 'disputed'))"));
        assert!(KEY_CLAIMS_SQL.contains("ORDER BY id LIMIT $5"));
        assert!(KEY_CLAIMS_SQL.contains("octet_length(value::STRING) > $6"));
        assert!(KEY_CLAIMS_SQL.contains("AS value_elided"));
        assert!(!KEY_CLAIMS_SQL.contains("SELECT *"));

        assert!(KEY_SUPPORT_SQL.contains("claim_id = ANY($3)"));
        assert!(KEY_SUPPORT_SQL.contains("LIMIT $4"));

        assert!(
            CONFLICT_IDS_FOR_KEY_SQL
                .contains("memory_conflicts@memory_conflicts_scope_key_detector_unique_idx")
        );
        assert!(CONFLICT_IDS_FOR_KEY_SQL.contains("ORDER BY detector LIMIT 3"));

        assert!(CLAIM_HISTORY_SQL.contains("memory_claim_events@memory_claim_events_claim_idx"));
        assert!(CLAIM_HISTORY_SQL.contains(
            "ORDER BY created_at DESC, (event_kind = 'recorded') ASC, event_id DESC LIMIT $4"
        ));
        assert!(CLAIM_HISTORY_SQL.contains("octet_length(payload::STRING) <= $5"));

        assert!(PREDECESSOR_SQL.contains("memory_claims@memory_claims_scope_key_idx"));
        assert!(PREDECESSOR_SQL.contains("superseded_by = $4"));
        assert!(PREDECESSOR_SQL.contains("LIMIT 2"));

        assert!(
            OPEN_CONFLICTS_SQL
                .contains("memory_conflicts@memory_conflicts_scope_detector_state_recency_idx")
        );
        assert!(
            OPEN_CONFLICTS_SQL
                .contains("detector = 'same_key_functional_value_v2' AND state = 'open'")
        );
        assert!(
            OPEN_CONFLICTS_SQL.contains("detector = 'same_key_typed_value' AND state = 'open'")
        );
        assert!(OPEN_CONFLICTS_SQL.contains("memory_conflict_members@primary"));
        assert!(OPEN_CONFLICTS_SQL.contains("ORDER BY detected_at, id LIMIT $3"));
    }

    #[test]
    fn brief_reads_seek_indexes_and_bound_transfer() {
        // The recency listing: one seek of the scoped state index per
        // current state, each in the index's order and bounded, merged
        // under the same bound, then the primary for the projection.
        assert_eq!(
            RECENT_CLAIMS_SQL
                .matches("FROM memory_claims@memory_claims_scope_state_idx")
                .count(),
            2
        );
        assert!(
            RECENT_CLAIMS_SQL
                .contains("AND state = 'active' ORDER BY updated_at DESC, id LIMIT $3")
        );
        assert!(
            RECENT_CLAIMS_SQL
                .contains("AND state = 'disputed' ORDER BY updated_at DESC, id LIMIT $3")
        );
        assert!(RECENT_CLAIMS_SQL.contains(") AS merged ORDER BY updated_at DESC, id LIMIT $3"));
        assert!(RECENT_CLAIMS_SQL.contains("JOIN memory_claims@primary AS claim"));
        assert!(
            RECENT_CLAIMS_SQL
                .contains("claim.tenant_id = $1 AND claim.project = $2 AND claim.id = recent.id")
        );
        assert!(RECENT_CLAIMS_SQL.contains("octet_length(claim.value::STRING) > $4"));
        assert!(RECENT_CLAIMS_SQL.contains("AS value_elided"));
        assert!(RECENT_CLAIMS_SQL.contains("ORDER BY recent.updated_at DESC, recent.id"));
        assert!(!RECENT_CLAIMS_SQL.contains("SELECT *"));
        assert!(!RECENT_CLAIMS_SQL.contains("state IN"));

        // The subject listing: two key spans of the scoped key index,
        // current states, key then recording order, bounded.
        assert!(SUBJECT_CLAIMS_SQL.contains("memory_claims@memory_claims_scope_key_idx"));
        assert!(SUBJECT_CLAIMS_SQL.contains(
            "((claim_key >= $3 AND claim_key < $4) OR (claim_key >= $5 AND claim_key < $6))"
        ));
        assert!(SUBJECT_CLAIMS_SQL.contains("AND state IN ('active', 'disputed')"));
        assert!(SUBJECT_CLAIMS_SQL.contains("ORDER BY claim_key, id LIMIT $7"));
        assert!(SUBJECT_CLAIMS_SQL.contains("octet_length(value::STRING) > $8"));
        assert!(SUBJECT_CLAIMS_SQL.contains("AS value_elided"));
        assert!(!SUBJECT_CLAIMS_SQL.contains("LIKE"));
        assert!(!SUBJECT_CLAIMS_SQL.contains("SELECT *"));
    }

    #[test]
    fn subject_spans_cover_the_subject_and_its_continuations_only() {
        let spans = subject_spans(" Final Round ").unwrap();
        assert_eq!(spans[0].0, "final-round::");
        assert_eq!(spans[0].1, "final-round::\u{10FFFF}");
        assert_eq!(spans[1].0, "final-round-");
        assert_eq!(spans[1].1, "final-round-\u{10FFFF}");
        let within = |key: &str| {
            spans
                .iter()
                .any(|(lower, upper)| lower.as_str() <= key && key < upper.as_str())
        };
        assert!(within("final-round::batch-size"));
        assert!(within("final-round::\u{10FFFE}"));
        assert!(within("final-round-2::x"));
        assert!(!within("final::x"));
        assert!(!within("final-roundabout::x"));
        assert!(!within("final-round"));
        assert!(!within("claim-v2:final-round"));
        assert_eq!(subject_spans(" _- "), None);
        assert_eq!(subject_spans(""), None);

        assert!(validated_brief_limit(0).is_err());
        assert!(validated_brief_limit(MAX_BRIEF_CLAIMS + 1).is_err());
        assert_eq!(validated_brief_limit(MAX_BRIEF_CLAIMS).unwrap(), 64);
    }

    #[test]
    fn lookup_keys_are_bounded() {
        assert!(validated_claim_key("").is_err());
        assert!(validated_claim_key(&"k".repeat(MAX_LOOKUP_CLAIM_KEY_BYTES + 1)).is_err());
        assert_eq!(
            validated_claim_key("merged-build::rollout-mode").unwrap(),
            "merged-build::rollout-mode"
        );
    }
}
