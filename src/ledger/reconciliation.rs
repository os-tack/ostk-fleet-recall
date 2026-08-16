//! History-preserving reconciliation of legacy conflict detector lineages.
//!
//! This repository is intentionally separate from the steady-state claim
//! writer. Reconciliation is an explicit, idempotent administrative mutation:
//! it preserves the legacy conflict and memberships byte-for-byte, derives a
//! complete bounded v2 pair graph, writes a distinct v2 lineage, and records
//! every claim-state change in the same serializable transaction.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPool;
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use crate::ledger::{
    FUNCTIONAL_VALUE_CONFLICT_DETECTOR_V2, FUNCTIONAL_VALUE_CONFLICT_RATIONALE_V2, canonical_json,
    functional_values_are_incompatible, intervals_overlap,
};
use crate::store::cockroach::{RetryPolicy, with_serializable_retry};
use crate::{FleetError, FleetScope, Result};

pub const LEGACY_TYPED_VALUE_CONFLICT_DETECTOR: &str = "same_key_typed_value";
pub const CONFLICT_RECONCILIATION_OPERATION: &str = "reconcile_conflict_detector_v2";
pub const NO_V2_INCOMPATIBILITY_RESOLUTION_KIND: &str = "no_v2_incompatibility_at_reconciliation";

const MAX_IDEMPOTENCY_KEY_BYTES: usize = 256;
const MAX_CURRENT_CLAIMS_PER_KEY: usize = 256;
const CURRENT_CLAIM_SENTINEL_LIMIT: usize = MAX_CURRENT_CLAIMS_PER_KEY + 1;
const MAX_LEGACY_MEMBERS_PER_CONFLICT: usize = 256;
const LEGACY_MEMBER_SENTINEL_LIMIT: usize = MAX_LEGACY_MEMBERS_PER_CONFLICT + 1;
const MAX_PRE_V2_MEMBERSHIPS_PER_LEGACY_MEMBER: usize = 1;
const LEGACY_MEMBER_INVERSE_SENTINEL_LIMIT: usize = MAX_PRE_V2_MEMBERSHIPS_PER_LEGACY_MEMBER + 1;
const MAX_LEGACY_MEMBER_INVERSE_ROWS: usize =
    MAX_LEGACY_MEMBERS_PER_CONFLICT * LEGACY_MEMBER_INVERSE_SENTINEL_LIMIT;
const MAX_TRANSITION_PROVENANCE_ROWS: usize = MAX_CURRENT_CLAIMS_PER_KEY * 2;
const MAX_UNORDERED_PAIRS: usize =
    MAX_CURRENT_CLAIMS_PER_KEY * (MAX_CURRENT_CLAIMS_PER_KEY - 1) / 2;
const REQUIRED_SCHEMA_VERSION: i64 = 16;
const RECONCILIATION_REQUEST_VERSION: u8 = 1;
const RECONCILIATION_AUDIT_VERSION: u8 = 1;

const REQUIRED_SCHEMA_PREFIX_SQL: &str = r"
SELECT count(*) = $1
   AND min(version) = 1
   AND max(version) = $1
   AND coalesce(bool_and(success), false)
FROM _sqlx_migrations
WHERE version BETWEEN 1 AND $1
";

const LOCK_LEGACY_CONFLICT_SQL: &str = r"
SELECT id, claim_key, state, detector, revision
FROM memory_conflicts@primary
WHERE tenant_id = $1 AND project = $2 AND id = $3
FOR UPDATE
";

const LOCK_CONFLICT_LINEAGES_SQL: &str = r"
SELECT id, detector, state, revision
FROM memory_conflicts@memory_conflicts_scope_key_detector_unique_idx
WHERE tenant_id = $1 AND project = $2 AND claim_key = $3
ORDER BY detector
LIMIT 3
FOR UPDATE
";

/// The first phase is index-only and materialized before values are hydrated.
/// That makes the 257th row a real sentinel instead of applying `LIMIT` after
/// an unbounded index join on non-stored JSONB and interval columns.
const LOCK_CURRENT_CLAIMS_SQL: &str = r"
WITH candidate_ids AS MATERIALIZED (
    SELECT id
    FROM memory_claims@memory_claims_scope_key_idx
    WHERE tenant_id = $1
      AND project = $2
      AND claim_key = $3
      AND state IN ('active', 'disputed')
    ORDER BY state, id
    LIMIT $4
)
SELECT c.id, c.revision, c.state, c.polarity, c.valid_from, c.valid_to,
       c.conflict_eligible, c.value
FROM candidate_ids AS bounded
JOIN memory_claims@primary AS c
  ON c.tenant_id = $1
 AND c.project = $2
 AND c.id = bounded.id
ORDER BY c.id
FOR UPDATE
";

const LOCK_LEGACY_MEMBERS_SQL: &str = r"
SELECT claim_id, role
FROM memory_conflict_members@primary
WHERE tenant_id = $1
  AND project = $2
  AND conflict_id = $3
ORDER BY claim_id
LIMIT 257
FOR UPDATE
";

const LOCK_LEGACY_MEMBER_CLAIMS_SQL: &str = r"
WITH wanted AS MATERIALIZED (
    SELECT claim_id
    FROM unnest($3::INT8[]) AS legacy_members(claim_id)
    ORDER BY claim_id
    LIMIT 256
)
SELECT c.id, c.claim_key, c.state
FROM wanted
JOIN memory_claims@primary AS c
  ON c.tenant_id = $1
 AND c.project = $2
 AND c.id = wanted.claim_id
ORDER BY c.id
FOR UPDATE
";

const LOCK_LEGACY_MEMBER_INVERSE_SQL: &str = r"
WITH wanted AS MATERIALIZED (
    SELECT claim_id
    FROM unnest($3::INT8[]) AS legacy_members(claim_id)
    ORDER BY claim_id
    LIMIT 256
)
SELECT wanted.claim_id, membership.conflict_id AS member_conflict_id,
       lineage.id AS actual_conflict_id, lineage.claim_key, lineage.detector
FROM wanted
JOIN LATERAL (
    SELECT conflict_id
    FROM memory_conflict_members@memory_conflict_members_claim_idx
    WHERE tenant_id = $1
      AND project = $2
      AND claim_id = wanted.claim_id
    ORDER BY conflict_id
    LIMIT 2
) AS membership ON true
LEFT JOIN memory_conflicts@primary AS lineage
  ON lineage.tenant_id = $1
 AND lineage.project = $2
 AND lineage.id = membership.conflict_id
ORDER BY wanted.claim_id, membership.conflict_id
";

/// One bounded index seek returns at most the two newest state transitions for
/// each restoration candidate. The second row detects equal-timestamp ties:
/// event UUID order must never arbitrarily authorize restoration.
const LATEST_TRANSITION_PROVENANCE_SQL: &str = r"
WITH wanted AS MATERIALIZED (
    SELECT claim_id
    FROM unnest($3::INT8[]) AS restoration_candidates(claim_id)
    ORDER BY claim_id
    LIMIT 256
)
SELECT wanted.claim_id, latest.event_id, latest.reason,
       latest.from_state, latest.to_state, latest.payload, latest.created_at
FROM wanted
LEFT JOIN LATERAL (
    SELECT event_id, reason, from_state, to_state, payload, created_at
    FROM memory_claim_events@memory_claim_events_transition_provenance_idx
    WHERE tenant_id = $1
      AND project = $2
      AND claim_id = wanted.claim_id
      AND event_kind = 'state_transition'
    ORDER BY created_at DESC, event_id DESC
    LIMIT 2
) AS latest ON true
ORDER BY wanted.claim_id, latest.created_at DESC, latest.event_id DESC
";

const INSERT_V2_CONFLICT_SQL: &str = r"
INSERT INTO memory_conflicts (
    tenant_id, project, claim_key, kind, state, detector, rationale,
    resolved_at, resolution_kind, resolution_reason
)
VALUES (
    $1, $2, $3, 'contradiction', $4, $5, $6,
    CASE WHEN $4 = 'dismissed' THEN now() ELSE NULL END,
    $7,
    CASE WHEN $4 = 'dismissed'
         THEN 'the complete bounded current-claim graph has no v2 incompatibility'
         ELSE NULL END
)
ON CONFLICT (tenant_id, project, claim_key, detector) DO NOTHING
RETURNING id
";

const INSERT_V2_MEMBERS_SQL: &str = r"
INSERT INTO memory_conflict_members (
    tenant_id, project, conflict_id, claim_id, role
)
SELECT $1, $2, $3, member_id, 'claim'
FROM unnest($4::INT8[]) AS members(member_id)
ON CONFLICT DO NOTHING
";

const UPDATE_CLAIMS_TO_DISPUTED_SQL: &str = r"
UPDATE memory_claims
SET state = 'disputed', revision = revision + 1, updated_at = now()
WHERE tenant_id = $1
  AND project = $2
  AND id = ANY($3)
  AND state = 'active'
RETURNING id
";

const UPDATE_CLAIMS_TO_ACTIVE_SQL: &str = r"
UPDATE memory_claims
SET state = 'active', revision = revision + 1, updated_at = now()
WHERE tenant_id = $1
  AND project = $2
  AND id = ANY($3)
  AND state = 'disputed'
RETURNING id
";

const INSERT_CLAIM_TRANSITIONS_SQL: &str = r"
INSERT INTO memory_claim_events (
    tenant_id, project, claim_id, event_kind, actor, reason,
    from_state, to_state, payload
)
SELECT $1, $2, claim_id, 'state_transition', $4, $5, $6, $7, $8::JSONB
FROM unnest($3::INT8[]) AS transitioned(claim_id)
";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConflictDetectorReconciliation {
    pub operation: String,
    pub request_version: u8,
    pub legacy_conflict_id: i64,
    pub legacy_conflict_revision: i64,
    /// The new v2 conflict lineage. This is also the conflict referenced by
    /// the idempotency receipt's `conflict_id` foreign key.
    pub conflict_id: i64,
    pub reconciliation_event_id: Uuid,
    pub v2_state: String,
    pub candidate_count: usize,
    pub incompatibility_pair_count: usize,
    pub v2_member_ids: Vec<i64>,
    pub newly_disputed_claim_ids: Vec<i64>,
    pub restored_claim_ids: Vec<i64>,
    pub retained_disputed_claim_ids: Vec<i64>,
    pub provenance_ambiguous_claim_ids: Vec<i64>,
    pub idempotent_replay: bool,
}

/// Repository bound to one construction-trusted fleet identity.
#[derive(Clone)]
pub struct CockroachConflictReconciliationRepository {
    pool: PgPool,
    trusted_scope: FleetScope,
    retry_policy: RetryPolicy,
}

impl std::fmt::Debug for CockroachConflictReconciliationRepository {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CockroachConflictReconciliationRepository")
            .field("trusted_scope", &self.trusted_scope)
            .field("retry_policy", &self.retry_policy)
            .finish_non_exhaustive()
    }
}

impl CockroachConflictReconciliationRepository {
    pub fn new(pool: PgPool, trusted_scope: FleetScope, retry_policy: RetryPolicy) -> Result<Self> {
        trusted_scope.validate()?;
        Ok(Self {
            pool,
            trusted_scope,
            retry_policy,
        })
    }

    /// Reconcile exactly one immutable legacy conflict revision.
    ///
    /// The caller supplies only the durable legacy coordinate and replay key.
    /// Detector, claim key, pair graph, v2 state, and claim transitions are all
    /// derived under locks inside one serializable transaction.
    pub async fn reconcile_legacy_conflict(
        &self,
        scope: &FleetScope,
        legacy_conflict_id: i64,
        expected_legacy_revision: i64,
        idempotency_key: &str,
    ) -> Result<ConflictDetectorReconciliation> {
        self.ensure_scope(scope)?;
        if legacy_conflict_id <= 0 {
            return Err(FleetError::Memory(
                "legacy_conflict_id must be a positive integer".into(),
            ));
        }
        if expected_legacy_revision <= 0 {
            return Err(FleetError::Memory(
                "expected_legacy_revision must be a positive integer".into(),
            ));
        }
        let idempotency_key = idempotency_key.trim();
        if idempotency_key.is_empty() || idempotency_key.len() > MAX_IDEMPOTENCY_KEY_BYTES {
            return Err(FleetError::Memory(format!(
                "idempotency_key must be between 1 and {MAX_IDEMPOTENCY_KEY_BYTES} bytes"
            )));
        }

        // The durable receipt is tenant-keyed and project-bound in its own
        // column. Session is operational attribution, not mutation identity,
        // so an identical retry may safely arrive from a replacement session.
        let request = reconciliation_request(legacy_conflict_id, expected_legacy_revision);
        let pool = self.pool.clone();
        let policy = self.retry_policy;
        let scope = scope.clone();
        let idempotency_key = idempotency_key.to_string();

        with_serializable_retry(&pool, policy, move |transaction| {
            let scope = scope.clone();
            let request = request.clone();
            let idempotency_key = idempotency_key.clone();
            Box::pin(async move {
                reconcile_once(
                    transaction,
                    &scope,
                    legacy_conflict_id,
                    expected_legacy_revision,
                    &idempotency_key,
                    &request,
                )
                .await
            })
        })
        .await
    }

    fn ensure_scope(&self, scope: &FleetScope) -> Result<()> {
        scope.validate()?;
        if scope.tenant_id != self.trusted_scope.tenant_id
            || scope.project != self.trusted_scope.project
            || scope.agent != self.trusted_scope.agent
            || scope.privacy_tier != self.trusted_scope.privacy_tier
        {
            return Err(FleetError::InvalidScope(
                "conflict reconciliation is outside this repository's trusted fleet identity"
                    .into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LockedLegacyConflict {
    id: i64,
    claim_key: String,
    state: String,
    detector: String,
    revision: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LockedLegacyMember {
    claim_id: i64,
    role: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LockedLegacyMemberClaim {
    id: i64,
    claim_key: Option<String>,
    state: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LockedLegacyMemberInverse {
    claim_id: i64,
    member_conflict_id: i64,
    actual_conflict_id: Option<i64>,
    claim_key: Option<String>,
    detector: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct LegacyMemberAudit {
    claim_id: i64,
    role: String,
    state: String,
    classification: LegacyMemberClassification,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum LegacyMemberClassification {
    CurrentCandidate,
    Historical,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidatedLegacyMembers {
    ids: BTreeSet<i64>,
    audit: Vec<LegacyMemberAudit>,
}

#[derive(Debug, Clone, PartialEq)]
struct LockedCandidate {
    id: i64,
    revision: i64,
    state: String,
    polarity: i16,
    valid_from: Option<DateTime<Utc>>,
    valid_to: Option<DateTime<Utc>>,
    conflict_eligible: bool,
    value: Option<Value>,
    legacy_member: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct CandidateAudit {
    id: i64,
    revision: i64,
    state: String,
    polarity: i16,
    valid_from: Option<DateTime<Utc>>,
    valid_to: Option<DateTime<Utc>>,
    conflict_eligible: bool,
    legacy_member: bool,
    value_sha256: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
struct ConflictPairAudit {
    left_claim_id: i64,
    right_claim_id: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct TransitionPlan {
    newly_disputed: Vec<i64>,
    restored: Vec<i64>,
    retained_disputed: Vec<i64>,
    provenance_ambiguous: Vec<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LatestTransitionProvenance {
    evidence: Vec<TransitionEvidence>,
    authorizing_event: Option<TransitionCoordinate>,
    decision: TransitionProvenanceDecision,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TransitionEvidence {
    event_id: Uuid,
    created_at: DateTime<Utc>,
    exact_legacy_conflict: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
struct TransitionCoordinate {
    event_id: Uuid,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransitionProvenanceDecision {
    RestoreExactUniqueLatest,
    RetainNoEvidence,
    RetainLatestNonmatching,
    RetainLatestTimestampTie,
}

impl TransitionProvenanceDecision {
    const fn audit_name(self) -> &'static str {
        match self {
            Self::RestoreExactUniqueLatest => "restore_exact_unique_latest",
            Self::RetainNoEvidence => "retain_no_evidence",
            Self::RetainLatestNonmatching => "retain_latest_nonmatching",
            Self::RetainLatestTimestampTie => "retain_latest_timestamp_tie",
        }
    }
}

impl LatestTransitionProvenance {
    const fn authorizes_restoration(&self) -> bool {
        matches!(
            self.decision,
            TransitionProvenanceDecision::RestoreExactUniqueLatest
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct TransitionEvidenceAudit {
    event_id: Uuid,
    created_at: DateTime<Utc>,
    classification: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct RestorationProvenanceAudit {
    claim_id: i64,
    decision: &'static str,
    authorizing_event: Option<TransitionCoordinate>,
    evidence: Vec<TransitionEvidenceAudit>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConflictReconciliationRequest {
    version: u8,
    legacy_conflict_id: i64,
    expected_legacy_revision: i64,
}

fn classify_latest_transition(
    mut evidence: Vec<TransitionEvidence>,
) -> Result<LatestTransitionProvenance> {
    if evidence.len() > 2 {
        return Err(protocol_error(
            "latest-transition projection exceeded its two-row bound",
        ));
    }
    evidence.sort_by(|left, right| {
        right
            .created_at
            .cmp(&left.created_at)
            .then_with(|| right.event_id.cmp(&left.event_id))
    });
    if evidence
        .windows(2)
        .any(|pair| pair[0].event_id == pair[1].event_id)
    {
        return Err(protocol_error(
            "latest-transition projection returned a duplicate event coordinate",
        ));
    }
    let latest_is_tied = evidence
        .get(1)
        .is_some_and(|second| second.created_at == evidence[0].created_at);
    let (authorizing_event, decision) = match evidence.first() {
        None => (None, TransitionProvenanceDecision::RetainNoEvidence),
        Some(_) if latest_is_tied => (None, TransitionProvenanceDecision::RetainLatestTimestampTie),
        Some(latest) if !latest.exact_legacy_conflict => {
            (None, TransitionProvenanceDecision::RetainLatestNonmatching)
        }
        Some(latest) => (
            Some(TransitionCoordinate {
                event_id: latest.event_id,
                created_at: latest.created_at,
            }),
            TransitionProvenanceDecision::RestoreExactUniqueLatest,
        ),
    };
    Ok(LatestTransitionProvenance {
        evidence,
        authorizing_event,
        decision,
    })
}

fn reconciliation_request(legacy_conflict_id: i64, expected_legacy_revision: i64) -> Value {
    serde_json::json!({
        "version": RECONCILIATION_REQUEST_VERSION,
        "legacy_conflict_id": legacy_conflict_id,
        "expected_legacy_revision": expected_legacy_revision,
    })
}

fn decode_reconciliation_request(request: &Value) -> Result<ConflictReconciliationRequest> {
    let decoded: ConflictReconciliationRequest = serde_json::from_value(request.clone())
        .map_err(|error| protocol_error(format!("invalid reconciliation request: {error}")))?;
    if decoded.version != RECONCILIATION_REQUEST_VERSION
        || decoded.legacy_conflict_id <= 0
        || decoded.expected_legacy_revision <= 0
    {
        return Err(protocol_error(
            "reconciliation request has an unsupported version or invalid legacy coordinate",
        ));
    }
    Ok(decoded)
}

fn validate_stored_reconciliation_response(
    decoded: &ConflictDetectorReconciliation,
    request: &Value,
    stored_conflict_id: Option<i64>,
) -> Result<()> {
    let request = decode_reconciliation_request(request)?;
    if decoded.operation != CONFLICT_RECONCILIATION_OPERATION
        || decoded.request_version != request.version
        || decoded.legacy_conflict_id != request.legacy_conflict_id
        || decoded.legacy_conflict_revision != request.expected_legacy_revision
        || stored_conflict_id != Some(decoded.conflict_id)
        || decoded.conflict_id <= 0
        || decoded.idempotent_replay
    {
        return Err(protocol_error(
            "reconciliation receipt response is cross-wired or inconsistent with its request coordinate",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn reconcile_once(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &FleetScope,
    legacy_conflict_id: i64,
    expected_legacy_revision: i64,
    idempotency_key: &str,
    request: &Value,
) -> Result<ConflictDetectorReconciliation> {
    // This must remain the first SQL action, including on receipt replay. A
    // missing lineage index is a schema-readiness failure, not an opaque query
    // planner or uniqueness error halfway through the mutation.
    require_schema_prefix(transaction).await?;
    if let Some(row) = select_receipt(transaction, scope, idempotency_key).await? {
        return decode_receipt(&row, scope, request);
    }
    if let Some(response) = reserve_receipt(transaction, scope, idempotency_key, request).await? {
        return Ok(response);
    }

    let legacy = lock_legacy_conflict(transaction, scope, legacy_conflict_id).await?;
    if legacy.detector != LEGACY_TYPED_VALUE_CONFLICT_DETECTOR {
        return Err(FleetError::Memory(format!(
            "conflict {} is not a {LEGACY_TYPED_VALUE_CONFLICT_DETECTOR} lineage",
            legacy.id
        )));
    }
    if legacy.revision != expected_legacy_revision {
        return Err(FleetError::Memory(format!(
            "legacy conflict revision changed: expected {expected_legacy_revision}, found {}",
            legacy.revision
        )));
    }
    lock_and_validate_lineages(transaction, scope, &legacy).await?;

    let legacy_members = lock_and_validate_legacy_members(transaction, scope, &legacy).await?;
    let mut candidates = lock_current_candidates(transaction, scope, &legacy.claim_key).await?;
    for candidate in &mut candidates {
        candidate.legacy_member = legacy_members.ids.contains(&candidate.id);
    }

    validate_candidates(&candidates)?;
    validate_current_legacy_member_intersection(&legacy_members.audit, &candidates)?;
    let pairs = build_pair_graph(&candidates);
    if pairs.len() > MAX_UNORDERED_PAIRS {
        return Err(protocol_error(
            "v2 pair graph exceeded its mathematical maximum",
        ));
    }
    let v2_members = pair_endpoints(&pairs);

    let restoration_candidates = candidates
        .iter()
        .filter(|candidate| {
            candidate.state == "disputed"
                && candidate.legacy_member
                && !v2_members.contains(&candidate.id)
        })
        .map(|candidate| candidate.id)
        .collect::<Vec<_>>();
    let provenance =
        latest_transition_provenance(transaction, scope, legacy.id, &restoration_candidates)
            .await?;
    let transition_plan = plan_transitions(&candidates, &v2_members, &provenance);

    let v2_state = if pairs.is_empty() {
        "dismissed"
    } else {
        "open"
    };
    let v2_conflict_id =
        insert_v2_conflict(transaction, scope, &legacy.claim_key, v2_state).await?;
    let v2_member_ids = v2_members.iter().copied().collect::<Vec<_>>();
    insert_and_verify_v2_members(transaction, scope, v2_conflict_id, &v2_member_ids).await?;

    let candidate_audit = candidates
        .iter()
        .map(candidate_audit)
        .collect::<Result<Vec<_>>>()?;
    let reconciliation_event_id = Uuid::now_v7();
    let audit_payload = reconciliation_audit_payload(
        &legacy,
        v2_conflict_id,
        v2_state,
        &candidate_audit,
        &pairs,
        &v2_member_ids,
        &transition_plan,
        &legacy_members.audit,
        &provenance,
    )?;
    insert_aggregate_event(
        transaction,
        scope,
        reconciliation_event_id,
        v2_conflict_id,
        idempotency_key,
        &audit_payload,
    )
    .await?;

    let transition_payload = serde_json::json!({
        "reconciliation_event_id": reconciliation_event_id,
        "legacy_conflict": {
            "id": legacy.id,
            "detector": LEGACY_TYPED_VALUE_CONFLICT_DETECTOR,
        },
        "v2_conflict": {
            "id": v2_conflict_id,
            "detector": FUNCTIONAL_VALUE_CONFLICT_DETECTOR_V2,
        },
    });
    apply_claim_transitions(transaction, scope, &transition_plan, &transition_payload).await?;

    let response = ConflictDetectorReconciliation {
        operation: CONFLICT_RECONCILIATION_OPERATION.into(),
        request_version: RECONCILIATION_REQUEST_VERSION,
        legacy_conflict_id: legacy.id,
        legacy_conflict_revision: legacy.revision,
        conflict_id: v2_conflict_id,
        reconciliation_event_id,
        v2_state: v2_state.into(),
        candidate_count: candidates.len(),
        incompatibility_pair_count: pairs.len(),
        v2_member_ids,
        newly_disputed_claim_ids: transition_plan.newly_disputed,
        restored_claim_ids: transition_plan.restored,
        retained_disputed_claim_ids: transition_plan.retained_disputed,
        provenance_ambiguous_claim_ids: transition_plan.provenance_ambiguous,
        idempotent_replay: false,
    };
    finish_receipt(transaction, scope, idempotency_key, request, &response).await?;
    Ok(response)
}

async fn require_schema_prefix(transaction: &mut Transaction<'_, Postgres>) -> Result<()> {
    let ready = sqlx::query_scalar::<_, bool>(REQUIRED_SCHEMA_PREFIX_SQL)
        .bind(REQUIRED_SCHEMA_VERSION)
        .fetch_one(&mut **transaction)
        .await?;
    if !ready {
        return Err(FleetError::Memory(format!(
            "conflict reconciliation requires the complete successful schema prefix through {REQUIRED_SCHEMA_VERSION}"
        )));
    }
    Ok(())
}

async fn select_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &FleetScope,
    idempotency_key: &str,
) -> Result<Option<sqlx::postgres::PgRow>> {
    Ok(sqlx::query(
        "SELECT project, operation, request, conflict_id, response \
         FROM memory_mutation_receipts \
         WHERE tenant_id = $1 AND idempotency_key = $2",
    )
    .bind(scope.tenant_id)
    .bind(idempotency_key)
    .fetch_optional(&mut **transaction)
    .await?)
}

async fn reserve_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &FleetScope,
    idempotency_key: &str,
    request: &Value,
) -> Result<Option<ConflictDetectorReconciliation>> {
    let inserted = sqlx::query_scalar::<_, String>(
        "INSERT INTO memory_mutation_receipts (\
             tenant_id, idempotency_key, project, request, operation\
         ) VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (tenant_id, idempotency_key) DO NOTHING \
         RETURNING idempotency_key",
    )
    .bind(scope.tenant_id)
    .bind(idempotency_key)
    .bind(&scope.project)
    .bind(request)
    .bind(CONFLICT_RECONCILIATION_OPERATION)
    .fetch_optional(&mut **transaction)
    .await?;
    if inserted.is_some() {
        return Ok(None);
    }

    let row = select_receipt(transaction, scope, idempotency_key)
        .await?
        .ok_or_else(|| protocol_error("idempotency receipt disappeared after key conflict"))?;
    Ok(Some(decode_receipt(&row, scope, request)?))
}

fn decode_receipt(
    row: &sqlx::postgres::PgRow,
    scope: &FleetScope,
    request: &Value,
) -> Result<ConflictDetectorReconciliation> {
    let project: String = row.try_get("project")?;
    let operation: String = row.try_get("operation")?;
    let stored_request: Value = row.try_get("request")?;
    if project != scope.project
        || operation != CONFLICT_RECONCILIATION_OPERATION
        || stored_request != *request
    {
        return Err(FleetError::IdempotencyConflict(
            "idempotency key was already used for a different mutation".into(),
        ));
    }
    let stored_conflict_id: Option<i64> = row.try_get("conflict_id")?;
    let response: Option<Value> = row.try_get("response")?;
    let response = response.ok_or_else(|| {
        protocol_error("committed reconciliation receipt has no response payload")
    })?;
    let mut decoded: ConflictDetectorReconciliation = serde_json::from_value(response)
        .map_err(|error| protocol_error(format!("invalid reconciliation receipt: {error}")))?;
    validate_stored_reconciliation_response(&decoded, request, stored_conflict_id)?;
    decoded.idempotent_replay = true;
    Ok(decoded)
}

async fn lock_legacy_conflict(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &FleetScope,
    legacy_conflict_id: i64,
) -> Result<LockedLegacyConflict> {
    let row = sqlx::query(LOCK_LEGACY_CONFLICT_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(legacy_conflict_id)
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or_else(|| FleetError::Memory("legacy conflict does not exist in this scope".into()))?;
    Ok(LockedLegacyConflict {
        id: row.try_get("id")?,
        claim_key: row.try_get("claim_key")?,
        state: row.try_get("state")?,
        detector: row.try_get("detector")?,
        revision: row.try_get("revision")?,
    })
}

async fn lock_and_validate_lineages(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &FleetScope,
    legacy: &LockedLegacyConflict,
) -> Result<()> {
    let rows = sqlx::query(LOCK_CONFLICT_LINEAGES_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(&legacy.claim_key)
        .fetch_all(&mut **transaction)
        .await?;
    if rows.len() > 2 {
        return Err(protocol_error(
            "claim key has more than the two admitted conflict detector lineages",
        ));
    }
    let mut saw_legacy = false;
    for row in rows {
        let id: i64 = row.try_get("id")?;
        let detector: String = row.try_get("detector")?;
        let _state: String = row.try_get("state")?;
        let _revision: i64 = row.try_get("revision")?;
        match detector.as_str() {
            LEGACY_TYPED_VALUE_CONFLICT_DETECTOR if id == legacy.id && !saw_legacy => {
                saw_legacy = true;
            }
            LEGACY_TYPED_VALUE_CONFLICT_DETECTOR => {
                return Err(protocol_error(
                    "claim key has a duplicate legacy conflict lineage",
                ));
            }
            FUNCTIONAL_VALUE_CONFLICT_DETECTOR_V2 => {
                return Err(FleetError::Memory(
                    "legacy conflict already has a v2 reconciliation lineage; replay its original idempotency key"
                        .into(),
                ));
            }
            _ => {
                return Err(protocol_error(
                    "claim key has an unknown conflict detector lineage",
                ));
            }
        }
    }
    if !saw_legacy {
        return Err(protocol_error(
            "locked legacy conflict was absent from its claim-key lineages",
        ));
    }
    Ok(())
}

async fn lock_current_candidates(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &FleetScope,
    claim_key: &str,
) -> Result<Vec<LockedCandidate>> {
    let limit = i64::try_from(CURRENT_CLAIM_SENTINEL_LIMIT)
        .map_err(|_| protocol_error("current-claim sentinel exceeds INT8"))?;
    let rows = sqlx::query(LOCK_CURRENT_CLAIMS_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(claim_key)
        .bind(limit)
        .fetch_all(&mut **transaction)
        .await?;
    if rows.len() > MAX_CURRENT_CLAIMS_PER_KEY {
        return Err(FleetError::Memory(format!(
            "conflict reconciliation exceeds the bounded limit of {MAX_CURRENT_CLAIMS_PER_KEY} lifecycle-current claims"
        )));
    }
    rows.into_iter()
        .map(|row| {
            Ok(LockedCandidate {
                id: row.try_get("id")?,
                revision: row.try_get("revision")?,
                state: row.try_get("state")?,
                polarity: row.try_get("polarity")?,
                valid_from: row.try_get("valid_from")?,
                valid_to: row.try_get("valid_to")?,
                conflict_eligible: row.try_get("conflict_eligible")?,
                value: row.try_get("value")?,
                legacy_member: false,
            })
        })
        .collect()
}

async fn lock_and_validate_legacy_members(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &FleetScope,
    legacy: &LockedLegacyConflict,
) -> Result<ValidatedLegacyMembers> {
    let rows = sqlx::query(LOCK_LEGACY_MEMBERS_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(legacy.id)
        .fetch_all(&mut **transaction)
        .await?;
    let members = rows
        .into_iter()
        .map(|row| {
            Ok(LockedLegacyMember {
                claim_id: row.try_get("claim_id")?,
                role: row.try_get("role")?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let member_ids = validate_legacy_member_rows(&members)?;
    if member_ids.is_empty() {
        return Ok(ValidatedLegacyMembers {
            ids: member_ids,
            audit: Vec::new(),
        });
    }

    let member_ids_vec = member_ids.iter().copied().collect::<Vec<_>>();
    let claim_rows = sqlx::query(LOCK_LEGACY_MEMBER_CLAIMS_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(&member_ids_vec)
        .fetch_all(&mut **transaction)
        .await?;
    let member_claims = claim_rows
        .into_iter()
        .map(|row| {
            Ok(LockedLegacyMemberClaim {
                id: row.try_get("id")?,
                claim_key: row.try_get("claim_key")?,
                state: row.try_get("state")?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let member_audit =
        validate_legacy_member_claims(&members, &member_ids, &member_claims, &legacy.claim_key)?;

    let inverse_rows = sqlx::query(LOCK_LEGACY_MEMBER_INVERSE_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(&member_ids_vec)
        .fetch_all(&mut **transaction)
        .await?;
    let inverse_memberships = inverse_rows
        .into_iter()
        .map(|row| {
            Ok(LockedLegacyMemberInverse {
                claim_id: row.try_get("claim_id")?,
                member_conflict_id: row.try_get("member_conflict_id")?,
                actual_conflict_id: row.try_get("actual_conflict_id")?,
                claim_key: row.try_get("claim_key")?,
                detector: row.try_get("detector")?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    validate_legacy_member_inverse_memberships(&member_ids, legacy, &inverse_memberships)?;
    Ok(ValidatedLegacyMembers {
        ids: member_ids,
        audit: member_audit,
    })
}

fn validate_legacy_member_rows(members: &[LockedLegacyMember]) -> Result<BTreeSet<i64>> {
    if members.len() > MAX_LEGACY_MEMBERS_PER_CONFLICT {
        return Err(FleetError::Memory(format!(
            "legacy conflict membership exceeds the bounded limit of {MAX_LEGACY_MEMBERS_PER_CONFLICT} claims"
        )));
    }
    let mut ids = BTreeSet::new();
    let mut previous_id = None;
    for member in members {
        if member.claim_id <= 0 {
            return Err(protocol_error(
                "legacy conflict membership has a non-positive claim id",
            ));
        }
        if previous_id.is_some_and(|previous| previous >= member.claim_id)
            || !ids.insert(member.claim_id)
        {
            return Err(protocol_error(
                "legacy conflict memberships were not locked in a unique stable order",
            ));
        }
        if member.role != "claim" {
            return Err(protocol_error(
                "legacy conflict membership has a role outside the exact claim contract",
            ));
        }
        previous_id = Some(member.claim_id);
    }
    Ok(ids)
}

fn validate_legacy_member_claims(
    members: &[LockedLegacyMember],
    expected_ids: &BTreeSet<i64>,
    claims: &[LockedLegacyMemberClaim],
    expected_claim_key: &str,
) -> Result<Vec<LegacyMemberAudit>> {
    if members.len() != expected_ids.len() || claims.len() != expected_ids.len() {
        return Err(protocol_error(
            "legacy conflict membership references a missing scoped claim",
        ));
    }
    let mut audit = Vec::with_capacity(expected_ids.len());
    for ((expected_id, member), claim) in expected_ids.iter().zip(members).zip(claims) {
        if member.claim_id != *expected_id || claim.id != *expected_id {
            return Err(protocol_error(
                "legacy member claims were not hydrated in exact membership order",
            ));
        }
        if claim.claim_key.as_deref() != Some(expected_claim_key) {
            return Err(protocol_error(
                "legacy conflict membership references a claim outside its exact claim key",
            ));
        }
        let classification = match claim.state.as_str() {
            "active" | "disputed" => LegacyMemberClassification::CurrentCandidate,
            "unsupported" | "superseded" | "retracted" | "suppressed" | "expired" => {
                LegacyMemberClassification::Historical
            }
            _ => {
                return Err(protocol_error(
                    "legacy conflict membership references a claim with an unknown lifecycle state",
                ));
            }
        };
        audit.push(LegacyMemberAudit {
            claim_id: claim.id,
            role: member.role.clone(),
            state: claim.state.clone(),
            classification,
        });
    }
    Ok(audit)
}

fn validate_legacy_member_inverse_memberships(
    expected_claim_ids: &BTreeSet<i64>,
    legacy: &LockedLegacyConflict,
    memberships: &[LockedLegacyMemberInverse],
) -> Result<()> {
    if memberships.len() > MAX_LEGACY_MEMBER_INVERSE_ROWS {
        return Err(protocol_error(
            "legacy inverse-membership projection exceeded its aggregate sentinel bound",
        ));
    }
    let mut by_claim = expected_claim_ids
        .iter()
        .copied()
        .map(|claim_id| (claim_id, Vec::new()))
        .collect::<BTreeMap<_, _>>();
    let mut previous = None;
    for membership in memberships {
        if membership.claim_id <= 0 || membership.member_conflict_id <= 0 {
            return Err(protocol_error(
                "legacy inverse membership has a non-positive durable coordinate",
            ));
        }
        let coordinate = (membership.claim_id, membership.member_conflict_id);
        if previous.is_some_and(|previous| previous >= coordinate) {
            return Err(protocol_error(
                "legacy inverse memberships were not locked in a unique stable order",
            ));
        }
        if membership.actual_conflict_id != Some(membership.member_conflict_id) {
            return Err(protocol_error(
                "legacy inverse membership references a missing scoped conflict",
            ));
        }
        if membership.claim_key.as_deref() != Some(legacy.claim_key.as_str())
            || membership.detector.as_deref() != Some(LEGACY_TYPED_VALUE_CONFLICT_DETECTOR)
        {
            return Err(protocol_error(
                "legacy inverse membership references a cross-key or unknown conflict lineage",
            ));
        }
        by_claim
            .get_mut(&membership.claim_id)
            .ok_or_else(|| {
                protocol_error("legacy inverse-membership projection escaped its requested ids")
            })?
            .push(membership.member_conflict_id);
        previous = Some(coordinate);
    }
    for conflict_ids in by_claim.into_values() {
        if conflict_ids.as_slice() != [legacy.id] {
            return Err(protocol_error(
                "legacy member has a missing, second, or non-legacy conflict membership",
            ));
        }
    }
    Ok(())
}

fn validate_candidates(candidates: &[LockedCandidate]) -> Result<()> {
    let mut previous_id = None;
    for candidate in candidates {
        if candidate.id <= 0 || candidate.revision <= 0 {
            return Err(protocol_error(
                "current claim has an invalid durable identity or revision",
            ));
        }
        if previous_id.is_some_and(|previous| previous >= candidate.id) {
            return Err(protocol_error(
                "current claims were not locked in a unique stable order",
            ));
        }
        previous_id = Some(candidate.id);
        if !matches!(candidate.state.as_str(), "active" | "disputed") {
            return Err(protocol_error(
                "current-claim query returned a non-current lifecycle state",
            ));
        }
        if !matches!(candidate.polarity, -1 | 1) {
            return Err(protocol_error(
                "current claim has a polarity outside the durable +/-1 contract",
            ));
        }
        if candidate.conflict_eligible && candidate.value.is_none() {
            return Err(protocol_error(
                "conflict-eligible current claim has no typed value",
            ));
        }
    }
    Ok(())
}

fn validate_current_legacy_member_intersection(
    legacy_members: &[LegacyMemberAudit],
    candidates: &[LockedCandidate],
) -> Result<()> {
    let candidate_ids = candidates
        .iter()
        .map(|candidate| candidate.id)
        .collect::<BTreeSet<_>>();
    for member in legacy_members {
        match (
            member.classification,
            candidate_ids.contains(&member.claim_id),
        ) {
            (LegacyMemberClassification::CurrentCandidate, true)
            | (LegacyMemberClassification::Historical, false) => {}
            (LegacyMemberClassification::CurrentCandidate, false) => {
                return Err(protocol_error(
                    "lifecycle-current legacy member was absent from the exact current candidate set",
                ));
            }
            (LegacyMemberClassification::Historical, true) => {
                return Err(protocol_error(
                    "historical legacy member appeared in the current candidate set",
                ));
            }
        }
    }
    Ok(())
}

fn build_pair_graph(candidates: &[LockedCandidate]) -> Vec<ConflictPairAudit> {
    let mut pairs = Vec::new();
    for (left_index, left) in candidates.iter().enumerate() {
        if !left.conflict_eligible {
            continue;
        }
        let Some(left_value) = left.value.as_ref() else {
            continue;
        };
        for right in &candidates[left_index + 1..] {
            if !right.conflict_eligible
                || !intervals_overlap(
                    left.valid_from,
                    left.valid_to,
                    right.valid_from,
                    right.valid_to,
                )
            {
                continue;
            }
            let Some(right_value) = right.value.as_ref() else {
                continue;
            };
            if functional_values_are_incompatible(
                left_value,
                left.polarity,
                right_value,
                right.polarity,
            ) {
                pairs.push(ConflictPairAudit {
                    left_claim_id: left.id,
                    right_claim_id: right.id,
                });
            }
        }
    }
    pairs
}

fn pair_endpoints(pairs: &[ConflictPairAudit]) -> BTreeSet<i64> {
    pairs
        .iter()
        .flat_map(|pair| [pair.left_claim_id, pair.right_claim_id])
        .collect()
}

#[allow(clippy::too_many_lines)]
async fn latest_transition_provenance(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &FleetScope,
    legacy_conflict_id: i64,
    claim_ids: &[i64],
) -> Result<BTreeMap<i64, LatestTransitionProvenance>> {
    if claim_ids.is_empty() {
        return Ok(BTreeMap::new());
    }
    if claim_ids.len() > MAX_CURRENT_CLAIMS_PER_KEY
        || claim_ids.iter().any(|claim_id| *claim_id <= 0)
        || claim_ids.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(protocol_error(
            "restoration candidates violate the positive unique bounded ordering contract",
        ));
    }
    let rows = sqlx::query(LATEST_TRANSITION_PROVENANCE_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(claim_ids)
        .fetch_all(&mut **transaction)
        .await?;
    if rows.len() > MAX_TRANSITION_PROVENANCE_ROWS {
        return Err(protocol_error(
            "latest-transition projection exceeded its aggregate row bound",
        ));
    }
    let requested = claim_ids.iter().copied().collect::<BTreeSet<_>>();
    let mut evidence_by_claim = claim_ids
        .iter()
        .copied()
        .map(|claim_id| (claim_id, Vec::<TransitionEvidence>::new()))
        .collect::<BTreeMap<_, _>>();
    let mut projected_row_counts = claim_ids
        .iter()
        .copied()
        .map(|claim_id| (claim_id, 0_usize))
        .collect::<BTreeMap<_, _>>();
    let mut null_placeholders = BTreeSet::new();
    for row in rows {
        let claim_id: i64 = row.try_get("claim_id")?;
        if !requested.contains(&claim_id) {
            return Err(protocol_error(
                "latest-transition projection escaped its requested claim ids",
            ));
        }
        let projected_count = projected_row_counts
            .get_mut(&claim_id)
            .ok_or_else(|| protocol_error("latest-transition claim was not preallocated"))?;
        *projected_count += 1;
        if *projected_count > 2 {
            return Err(protocol_error(
                "latest-transition projection exceeded its per-claim row bound",
            ));
        }
        let event_id: Option<Uuid> = row.try_get("event_id")?;
        let created_at: Option<DateTime<Utc>> = row.try_get("created_at")?;
        let reason: Option<String> = row.try_get("reason")?;
        let from_state: Option<String> = row.try_get("from_state")?;
        let to_state: Option<String> = row.try_get("to_state")?;
        let payload: Option<Value> = row.try_get("payload")?;
        let exact_legacy_conflict = reason.as_deref() == Some("conflict_detected")
            && from_state.as_deref() == Some("active")
            && to_state.as_deref() == Some("disputed")
            && payload
                .as_ref()
                .and_then(|payload| payload.get("conflict_id"))
                .and_then(Value::as_i64)
                == Some(legacy_conflict_id);
        match (event_id, created_at) {
            (Some(event_id), Some(created_at)) => {
                if null_placeholders.contains(&claim_id) || payload.is_none() {
                    return Err(protocol_error(
                        "latest-transition projection returned inconsistent event hydration",
                    ));
                }
                evidence_by_claim
                    .get_mut(&claim_id)
                    .ok_or_else(|| protocol_error("latest-transition claim was not preallocated"))?
                    .push(TransitionEvidence {
                        event_id,
                        created_at,
                        exact_legacy_conflict,
                    });
            }
            (None, None)
                if reason.is_none()
                    && from_state.is_none()
                    && to_state.is_none()
                    && payload.is_none()
                    && null_placeholders.insert(claim_id) => {}
            _ => {
                return Err(protocol_error(
                    "latest-transition projection returned a partial event coordinate",
                ));
            }
        }
    }

    let mut result = BTreeMap::new();
    for (claim_id, evidence) in evidence_by_claim {
        let expected_projected_count = if evidence.is_empty() {
            1
        } else {
            evidence.len()
        };
        if projected_row_counts.get(&claim_id) != Some(&expected_projected_count)
            || (evidence.is_empty() != null_placeholders.contains(&claim_id))
        {
            return Err(protocol_error(
                "latest-transition projection omitted or duplicated a restoration candidate",
            ));
        }
        result.insert(claim_id, classify_latest_transition(evidence)?);
    }
    Ok(result)
}

fn plan_transitions(
    candidates: &[LockedCandidate],
    v2_members: &BTreeSet<i64>,
    provenance: &BTreeMap<i64, LatestTransitionProvenance>,
) -> TransitionPlan {
    let mut plan = TransitionPlan::default();
    for candidate in candidates {
        match candidate.state.as_str() {
            "active" if v2_members.contains(&candidate.id) => {
                plan.newly_disputed.push(candidate.id);
            }
            "disputed" if candidate.legacy_member && !v2_members.contains(&candidate.id) => {
                if provenance
                    .get(&candidate.id)
                    .is_some_and(LatestTransitionProvenance::authorizes_restoration)
                {
                    plan.restored.push(candidate.id);
                } else {
                    plan.retained_disputed.push(candidate.id);
                    plan.provenance_ambiguous.push(candidate.id);
                }
            }
            "disputed" => plan.retained_disputed.push(candidate.id),
            _ => {}
        }
    }
    plan
}

async fn insert_v2_conflict(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &FleetScope,
    claim_key: &str,
    v2_state: &str,
) -> Result<i64> {
    let resolution_kind =
        (v2_state == "dismissed").then_some(NO_V2_INCOMPATIBILITY_RESOLUTION_KIND);
    sqlx::query_scalar::<_, i64>(INSERT_V2_CONFLICT_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(claim_key)
        .bind(v2_state)
        .bind(FUNCTIONAL_VALUE_CONFLICT_DETECTOR_V2)
        .bind(FUNCTIONAL_VALUE_CONFLICT_RATIONALE_V2)
        .bind(resolution_kind)
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or_else(|| {
            FleetError::Memory(
                "legacy conflict already has a v2 reconciliation lineage; replay its original idempotency key"
                    .into(),
            )
        })
}

async fn insert_and_verify_v2_members(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &FleetScope,
    v2_conflict_id: i64,
    member_ids: &[i64],
) -> Result<()> {
    if !member_ids.is_empty() {
        sqlx::query(INSERT_V2_MEMBERS_SQL)
            .bind(scope.tenant_id)
            .bind(&scope.project)
            .bind(v2_conflict_id)
            .bind(member_ids)
            .execute(&mut **transaction)
            .await?;
    }
    let stored_member_ids = sqlx::query_scalar::<_, i64>(
        "SELECT claim_id FROM memory_conflict_members@primary \
         WHERE tenant_id = $1 AND project = $2 AND conflict_id = $3 \
         ORDER BY claim_id",
    )
    .bind(scope.tenant_id)
    .bind(&scope.project)
    .bind(v2_conflict_id)
    .fetch_all(&mut **transaction)
    .await?;
    if stored_member_ids != member_ids {
        return Err(protocol_error(
            "v2 conflict memberships differ from exact pair-graph endpoints",
        ));
    }
    Ok(())
}

fn candidate_audit(candidate: &LockedCandidate) -> Result<CandidateAudit> {
    let value_sha256 = candidate
        .value
        .as_ref()
        .map(|value| {
            serde_json::to_vec(&canonical_json(value))
                .map(|bytes| hex::encode(Sha256::digest(bytes)))
                .map_err(|error| protocol_error(format!("canonicalize claim value: {error}")))
        })
        .transpose()?;
    Ok(CandidateAudit {
        id: candidate.id,
        revision: candidate.revision,
        state: candidate.state.clone(),
        polarity: candidate.polarity,
        valid_from: candidate.valid_from,
        valid_to: candidate.valid_to,
        conflict_eligible: candidate.conflict_eligible,
        legacy_member: candidate.legacy_member,
        value_sha256,
    })
}

fn restoration_provenance_audit(
    provenance: &BTreeMap<i64, LatestTransitionProvenance>,
    transitions: &TransitionPlan,
) -> Result<Vec<RestorationProvenanceAudit>> {
    if transitions
        .restored
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
        || transitions
            .provenance_ambiguous
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    {
        return Err(protocol_error(
            "restoration transition plan is not in positive unique stable order",
        ));
    }
    let restored = transitions
        .restored
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let ambiguous = transitions
        .provenance_ambiguous
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let provenance_claim_ids = provenance.keys().copied().collect::<BTreeSet<_>>();
    if restored.iter().any(|claim_id| *claim_id <= 0)
        || ambiguous.iter().any(|claim_id| *claim_id <= 0)
        || !restored.is_disjoint(&ambiguous)
        || restored.union(&ambiguous).copied().collect::<BTreeSet<_>>() != provenance_claim_ids
    {
        return Err(protocol_error(
            "restoration transition plan does not exactly cover its provenance candidates",
        ));
    }
    let mut audit = Vec::with_capacity(provenance.len());
    for (&claim_id, value) in provenance {
        let authorized = value.authorizes_restoration();
        if authorized != restored.contains(&claim_id)
            || (!authorized && !ambiguous.contains(&claim_id))
            || (authorized != value.authorizing_event.is_some())
        {
            return Err(protocol_error(
                "restoration transition plan differs from its exact provenance evidence",
            ));
        }
        let evidence = value
            .evidence
            .iter()
            .map(|event| TransitionEvidenceAudit {
                event_id: event.event_id,
                created_at: event.created_at,
                classification: if event.exact_legacy_conflict {
                    "exact_legacy_conflict"
                } else {
                    "nonmatching_transition"
                },
            })
            .collect();
        audit.push(RestorationProvenanceAudit {
            claim_id,
            decision: value.decision.audit_name(),
            authorizing_event: value.authorizing_event,
            evidence,
        });
    }
    Ok(audit)
}

#[allow(clippy::too_many_arguments)]
fn reconciliation_audit_payload(
    legacy: &LockedLegacyConflict,
    v2_conflict_id: i64,
    v2_state: &str,
    candidates: &[CandidateAudit],
    pairs: &[ConflictPairAudit],
    v2_member_ids: &[i64],
    transitions: &TransitionPlan,
    legacy_members: &[LegacyMemberAudit],
    provenance: &BTreeMap<i64, LatestTransitionProvenance>,
) -> Result<Value> {
    let restoration_provenance = restoration_provenance_audit(provenance, transitions)?;
    let transition_evidence_count = restoration_provenance
        .iter()
        .map(|entry| entry.evidence.len())
        .sum::<usize>();
    Ok(serde_json::json!({
        "version": RECONCILIATION_AUDIT_VERSION,
        "legacy": {
            "conflict_id": legacy.id,
            "detector": legacy.detector,
            "revision": legacy.revision,
            "state": legacy.state,
            "members": legacy_members,
        },
        "v2": {
            "conflict_id": v2_conflict_id,
            "detector": FUNCTIONAL_VALUE_CONFLICT_DETECTOR_V2,
            "state": v2_state,
        },
        "candidates": candidates,
        "incompatibility_pairs": pairs,
        "v2_member_ids": v2_member_ids,
        "newly_disputed": transitions.newly_disputed,
        "restored": transitions.restored,
        "retained_disputed": transitions.retained_disputed,
        "provenance_ambiguous": transitions.provenance_ambiguous,
        "restoration_provenance": restoration_provenance,
        "bounds": {
            "max_current_claims": MAX_CURRENT_CLAIMS_PER_KEY,
            "candidate_query_limit": CURRENT_CLAIM_SENTINEL_LIMIT,
            "max_legacy_members": MAX_LEGACY_MEMBERS_PER_CONFLICT,
            "legacy_member_query_limit": LEGACY_MEMBER_SENTINEL_LIMIT,
            "legacy_member_count": legacy_members.len(),
            "max_pre_v2_memberships_per_legacy_member": MAX_PRE_V2_MEMBERSHIPS_PER_LEGACY_MEMBER,
            "legacy_member_inverse_query_limit_per_claim": LEGACY_MEMBER_INVERSE_SENTINEL_LIMIT,
            "max_legacy_member_inverse_rows": MAX_LEGACY_MEMBER_INVERSE_ROWS,
            "max_unordered_pairs": MAX_UNORDERED_PAIRS,
            "candidate_count": candidates.len(),
            "pair_count": pairs.len(),
            "max_transition_evidence_per_restoration_candidate": 2,
            "max_transition_provenance_rows": MAX_TRANSITION_PROVENANCE_ROWS,
            "restoration_candidate_count": provenance.len(),
            "transition_evidence_count": transition_evidence_count,
        },
    }))
}

async fn insert_aggregate_event(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &FleetScope,
    event_id: Uuid,
    v2_conflict_id: i64,
    idempotency_key: &str,
    payload: &Value,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO memory_events (\
             tenant_id, project, event_id, agent, session_id, event_kind, \
             entity_kind, entity_id, idempotency_key, payload\
         ) VALUES ($1, $2, $3, $4, $5, 'conflict_detector_reconciled', \
             'conflict', $6, $7, $8)",
    )
    .bind(scope.tenant_id)
    .bind(&scope.project)
    .bind(event_id)
    .bind(&scope.agent)
    .bind(&scope.session_id)
    .bind(v2_conflict_id.to_string())
    .bind(idempotency_key)
    .bind(payload)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn apply_claim_transitions(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &FleetScope,
    plan: &TransitionPlan,
    payload: &Value,
) -> Result<()> {
    update_claim_state(
        transaction,
        scope,
        &plan.newly_disputed,
        UPDATE_CLAIMS_TO_DISPUTED_SQL,
    )
    .await?;
    insert_claim_transition_events(
        transaction,
        scope,
        &plan.newly_disputed,
        "conflict_detector_reconciled_v2",
        "active",
        "disputed",
        payload,
    )
    .await?;

    update_claim_state(
        transaction,
        scope,
        &plan.restored,
        UPDATE_CLAIMS_TO_ACTIVE_SQL,
    )
    .await?;
    insert_claim_transition_events(
        transaction,
        scope,
        &plan.restored,
        "legacy_false_positive_reconciled",
        "disputed",
        "active",
        payload,
    )
    .await?;
    Ok(())
}

async fn update_claim_state(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &FleetScope,
    expected_ids: &[i64],
    sql: &str,
) -> Result<()> {
    if expected_ids.is_empty() {
        return Ok(());
    }
    let mut updated_ids = sqlx::query_scalar::<_, i64>(sql)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(expected_ids)
        .fetch_all(&mut **transaction)
        .await?;
    updated_ids.sort_unstable();
    if updated_ids != expected_ids {
        return Err(protocol_error(
            "locked claim states changed before reconciliation transition",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn insert_claim_transition_events(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &FleetScope,
    claim_ids: &[i64],
    reason: &str,
    from_state: &str,
    to_state: &str,
    payload: &Value,
) -> Result<()> {
    if claim_ids.is_empty() {
        return Ok(());
    }
    let inserted = sqlx::query(INSERT_CLAIM_TRANSITIONS_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(claim_ids)
        .bind(&scope.agent)
        .bind(reason)
        .bind(from_state)
        .bind(to_state)
        .bind(payload)
        .execute(&mut **transaction)
        .await?;
    if inserted.rows_affected()
        != u64::try_from(claim_ids.len())
            .map_err(|_| protocol_error("transition event count exceeds u64"))?
    {
        return Err(protocol_error(
            "claim transition audit count differs from transitioned claims",
        ));
    }
    Ok(())
}

async fn finish_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &FleetScope,
    idempotency_key: &str,
    request: &Value,
    response: &ConflictDetectorReconciliation,
) -> Result<()> {
    let conflict_id = response.conflict_id;
    let response = serde_json::to_value(response)
        .map_err(|error| protocol_error(format!("serialize reconciliation receipt: {error}")))?;
    let updated = sqlx::query(
        "UPDATE memory_mutation_receipts \
         SET conflict_id = $5, response = $6 \
         WHERE tenant_id = $1 \
           AND idempotency_key = $2 \
           AND project = $3 \
           AND request = $4 \
           AND operation = $7 \
           AND response IS NULL",
    )
    .bind(scope.tenant_id)
    .bind(idempotency_key)
    .bind(&scope.project)
    .bind(request)
    .bind(conflict_id)
    .bind(&response)
    .bind(CONFLICT_RECONCILIATION_OPERATION)
    .execute(&mut **transaction)
    .await?;
    if updated.rows_affected() != 1 {
        return Err(protocol_error(
            "idempotency receipt reservation disappeared during reconciliation",
        ));
    }
    Ok(())
}

fn protocol_error(message: impl Into<String>) -> FleetError {
    FleetError::Protocol(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(
        id: i64,
        value: Value,
        polarity: i16,
        state: &str,
        legacy_member: bool,
    ) -> LockedCandidate {
        LockedCandidate {
            id,
            revision: 1,
            state: state.into(),
            polarity,
            valid_from: None,
            valid_to: None,
            conflict_eligible: true,
            value: Some(value),
            legacy_member,
        }
    }

    fn string_candidate(
        id: i64,
        value: &str,
        polarity: i16,
        state: &str,
        legacy_member: bool,
    ) -> LockedCandidate {
        candidate(
            id,
            Value::String(value.into()),
            polarity,
            state,
            legacy_member,
        )
    }

    fn stored_reconciliation_response() -> ConflictDetectorReconciliation {
        ConflictDetectorReconciliation {
            operation: CONFLICT_RECONCILIATION_OPERATION.into(),
            request_version: RECONCILIATION_REQUEST_VERSION,
            legacy_conflict_id: 41,
            legacy_conflict_revision: 7,
            conflict_id: 73,
            reconciliation_event_id: Uuid::now_v7(),
            v2_state: "open".into(),
            candidate_count: 2,
            incompatibility_pair_count: 1,
            v2_member_ids: vec![3, 5],
            newly_disputed_claim_ids: vec![3, 5],
            restored_claim_ids: Vec::new(),
            retained_disputed_claim_ids: Vec::new(),
            provenance_ambiguous_claim_ids: Vec::new(),
            idempotent_replay: false,
        }
    }

    #[test]
    fn authoritative_polarity_vectors_build_only_real_v2_edges() {
        let vectors = [
            (("cockroachdb", 1), ("postgresql", -1), false),
            (("postgresql", -1), ("mysql", -1), false),
            (("cockroachdb", 1), ("cockroachdb", -1), true),
            (("cockroachdb", 1), ("postgresql", 1), true),
        ];
        for ((left_value, left_polarity), (right_value, right_polarity), expected) in vectors {
            let candidates = vec![
                string_candidate(1, left_value, left_polarity, "active", false),
                string_candidate(2, right_value, right_polarity, "active", false),
            ];
            assert_eq!(build_pair_graph(&candidates).len(), usize::from(expected));

            let reversed_values = vec![
                string_candidate(1, right_value, right_polarity, "active", false),
                string_candidate(2, left_value, left_polarity, "active", false),
            ];
            assert_eq!(
                build_pair_graph(&reversed_values).len(),
                usize::from(expected)
            );
        }
    }

    #[test]
    fn complete_polarity_truth_table_matches_jsonb_value_semantics() {
        let cases = [
            ((1, "same"), (1, "same"), false),
            ((1, "left"), (1, "right"), true),
            ((1, "same"), (-1, "same"), true),
            ((1, "left"), (-1, "right"), false),
            ((-1, "same"), (1, "same"), true),
            ((-1, "left"), (1, "right"), false),
            ((-1, "same"), (-1, "same"), false),
            ((-1, "left"), (-1, "right"), false),
        ];
        for ((left_polarity, left), (right_polarity, right), expected) in cases {
            let candidates = vec![
                string_candidate(1, left, left_polarity, "active", false),
                string_candidate(2, right, right_polarity, "active", false),
            ];
            assert_eq!(build_pair_graph(&candidates).len() == 1, expected);
        }

        let equivalent_jsonb = vec![
            candidate(1, serde_json::json!({"b": 2, "a": 1}), 1, "active", false),
            candidate(2, serde_json::json!({"a": 1.0, "b": 2}), 1, "active", false),
        ];
        assert!(build_pair_graph(&equivalent_jsonb).is_empty());

        let ordered_arrays = vec![
            candidate(1, serde_json::json!([1, 2]), 1, "active", false),
            candidate(2, serde_json::json!([2, 1]), 1, "active", false),
        ];
        assert_eq!(build_pair_graph(&ordered_arrays).len(), 1);
    }

    #[test]
    fn pair_graph_respects_half_open_intervals_and_eligibility() {
        let boundary = Utc::now();
        let mut left = string_candidate(1, "cockroachdb", 1, "active", false);
        let mut right = string_candidate(2, "postgresql", 1, "active", false);
        left.valid_to = Some(boundary);
        right.valid_from = Some(boundary);
        assert!(build_pair_graph(&[left.clone(), right.clone()]).is_empty());

        right.valid_from = Some(boundary - chrono::Duration::nanoseconds(1));
        assert_eq!(build_pair_graph(&[left.clone(), right.clone()]).len(), 1);

        right.conflict_eligible = false;
        assert!(build_pair_graph(&[left, right]).is_empty());
    }

    #[test]
    fn maximum_complete_graph_is_exactly_32640_sorted_pairs() {
        let candidates = (1..=MAX_CURRENT_CLAIMS_PER_KEY)
            .map(|id| {
                string_candidate(
                    i64::try_from(id).unwrap(),
                    &format!("value-{id}"),
                    1,
                    "active",
                    false,
                )
            })
            .collect::<Vec<_>>();
        let pairs = build_pair_graph(&candidates);
        assert_eq!(pairs.len(), MAX_UNORDERED_PAIRS);
        assert_eq!(MAX_UNORDERED_PAIRS, 32_640);
        assert_eq!(
            pairs.first(),
            Some(&ConflictPairAudit {
                left_claim_id: 1,
                right_claim_id: 2,
            })
        );
        assert_eq!(
            pairs.last(),
            Some(&ConflictPairAudit {
                left_claim_id: 255,
                right_claim_id: 256,
            })
        );
        assert_eq!(pair_endpoints(&pairs).len(), MAX_CURRENT_CLAIMS_PER_KEY);
    }

    #[test]
    fn legacy_membership_rows_and_claims_fail_closed_without_rejecting_history() {
        let members = vec![
            LockedLegacyMember {
                claim_id: 1,
                role: "claim".into(),
            },
            LockedLegacyMember {
                claim_id: 2,
                role: "claim".into(),
            },
        ];
        let ids = validate_legacy_member_rows(&members).unwrap();
        let claims = vec![
            LockedLegacyMemberClaim {
                id: 1,
                claim_key: Some("fleet-store::database-choice".into()),
                state: "active".into(),
            },
            LockedLegacyMemberClaim {
                id: 2,
                claim_key: Some("fleet-store::database-choice".into()),
                state: "retracted".into(),
            },
        ];
        let audit =
            validate_legacy_member_claims(&members, &ids, &claims, "fleet-store::database-choice")
                .unwrap();
        assert_eq!(
            audit
                .iter()
                .map(|member| (member.claim_id, member.classification))
                .collect::<Vec<_>>(),
            vec![
                (1, LegacyMemberClassification::CurrentCandidate),
                (2, LegacyMemberClassification::Historical),
            ]
        );

        let mut wrong_role = members.clone();
        wrong_role[1].role = "witness".into();
        assert!(validate_legacy_member_rows(&wrong_role).is_err());

        let mut cross_key = claims.clone();
        cross_key[1].claim_key = Some("fleet-store::message-bus".into());
        assert!(
            validate_legacy_member_claims(
                &members,
                &ids,
                &cross_key,
                "fleet-store::database-choice",
            )
            .is_err()
        );
        cross_key[1].claim_key = None;
        assert!(
            validate_legacy_member_claims(
                &members,
                &ids,
                &cross_key,
                "fleet-store::database-choice",
            )
            .is_err()
        );
        assert!(
            validate_legacy_member_claims(
                &members,
                &ids,
                &claims[..1],
                "fleet-store::database-choice",
            )
            .is_err()
        );

        let sentinel = (1..=LEGACY_MEMBER_SENTINEL_LIMIT)
            .map(|claim_id| LockedLegacyMember {
                claim_id: i64::try_from(claim_id).unwrap(),
                role: "claim".into(),
            })
            .collect::<Vec<_>>();
        let error = validate_legacy_member_rows(&sentinel).unwrap_err();
        assert!(error.to_string().contains("bounded limit of 256"));

        let duplicate = vec![members[0].clone(), members[0].clone()];
        assert!(validate_legacy_member_rows(&duplicate).is_err());
        let mut non_positive = members;
        non_positive[0].claim_id = 0;
        assert!(validate_legacy_member_rows(&non_positive).is_err());
    }

    #[test]
    fn inverse_membership_set_must_be_exactly_the_one_legacy_lineage() {
        let legacy = LockedLegacyConflict {
            id: 10,
            claim_key: "fleet-store::database-choice".into(),
            state: "open".into(),
            detector: LEGACY_TYPED_VALUE_CONFLICT_DETECTOR.into(),
            revision: 7,
        };
        let expected = BTreeSet::from([1, 2]);
        let inverse = |claim_id, member_conflict_id| LockedLegacyMemberInverse {
            claim_id,
            member_conflict_id,
            actual_conflict_id: Some(member_conflict_id),
            claim_key: Some(legacy.claim_key.clone()),
            detector: Some(LEGACY_TYPED_VALUE_CONFLICT_DETECTOR.into()),
        };
        let valid = vec![inverse(1, legacy.id), inverse(2, legacy.id)];
        assert!(validate_legacy_member_inverse_memberships(&expected, &legacy, &valid).is_ok());

        let second = vec![
            inverse(1, legacy.id),
            inverse(1, legacy.id + 1),
            inverse(2, legacy.id),
        ];
        assert!(validate_legacy_member_inverse_memberships(&expected, &legacy, &second).is_err());

        let mut dangling = valid.clone();
        dangling[0].actual_conflict_id = None;
        dangling[0].claim_key = None;
        dangling[0].detector = None;
        assert!(validate_legacy_member_inverse_memberships(&expected, &legacy, &dangling).is_err());

        let mut cross_key = valid.clone();
        cross_key[0].claim_key = Some("fleet-store::message-bus".into());
        assert!(
            validate_legacy_member_inverse_memberships(&expected, &legacy, &cross_key).is_err()
        );

        let mut unknown = valid;
        unknown[0].detector = Some("unknown_detector".into());
        assert!(validate_legacy_member_inverse_memberships(&expected, &legacy, &unknown).is_err());

        let escaped = vec![inverse(1, legacy.id), inverse(3, legacy.id)];
        assert!(validate_legacy_member_inverse_memberships(&expected, &legacy, &escaped).is_err());
    }

    #[test]
    fn validated_members_intersect_current_candidates_without_promoting_history() {
        let members = vec![
            LegacyMemberAudit {
                claim_id: 1,
                role: "claim".into(),
                state: "disputed".into(),
                classification: LegacyMemberClassification::CurrentCandidate,
            },
            LegacyMemberAudit {
                claim_id: 2,
                role: "claim".into(),
                state: "retracted".into(),
                classification: LegacyMemberClassification::Historical,
            },
        ];
        let candidates = vec![string_candidate(1, "cockroachdb", 1, "disputed", true)];
        assert!(validate_current_legacy_member_intersection(&members, &candidates).is_ok());
        assert!(validate_current_legacy_member_intersection(&members, &[]).is_err());
        let historical_leak = vec![
            string_candidate(1, "cockroachdb", 1, "disputed", true),
            string_candidate(2, "postgresql", 1, "active", true),
        ];
        assert!(validate_current_legacy_member_intersection(&members, &historical_leak).is_err());
    }

    #[test]
    fn state_restoration_is_conservative_and_provenance_bound() {
        let now = "2026-08-15T12:00:00Z".parse::<DateTime<Utc>>().unwrap();
        let candidates = vec![
            string_candidate(1, "a", 1, "active", false),
            string_candidate(2, "b", 1, "disputed", true),
            string_candidate(3, "c", -1, "disputed", true),
            string_candidate(4, "d", 1, "disputed", true),
            string_candidate(5, "e", -1, "disputed", false),
            string_candidate(6, "f", -1, "active", true),
        ];
        let v2_members = BTreeSet::from([1, 4]);
        let provenance = BTreeMap::from([
            (
                2,
                classify_latest_transition(vec![TransitionEvidence {
                    event_id: Uuid::from_u128(2),
                    created_at: now,
                    exact_legacy_conflict: true,
                }])
                .unwrap(),
            ),
            (
                3,
                classify_latest_transition(vec![TransitionEvidence {
                    event_id: Uuid::from_u128(3),
                    created_at: now,
                    exact_legacy_conflict: false,
                }])
                .unwrap(),
            ),
        ]);
        let plan = plan_transitions(&candidates, &v2_members, &provenance);
        assert_eq!(plan.newly_disputed, vec![1]);
        assert_eq!(plan.restored, vec![2]);
        assert_eq!(plan.retained_disputed, vec![3, 4, 5]);
        assert_eq!(plan.provenance_ambiguous, vec![3]);
    }

    #[test]
    fn open_v2_graph_has_exact_endpoints_and_only_disputes_active_endpoints() {
        let candidates = vec![
            string_candidate(1, "cockroachdb", 1, "active", true),
            string_candidate(2, "postgresql", 1, "active", true),
            string_candidate(3, "mysql", -1, "active", true),
        ];
        let pairs = build_pair_graph(&candidates);
        assert_eq!(
            pairs,
            vec![ConflictPairAudit {
                left_claim_id: 1,
                right_claim_id: 2,
            }]
        );
        let endpoints = pair_endpoints(&pairs);
        assert_eq!(endpoints, BTreeSet::from([1, 2]));
        let plan = plan_transitions(&candidates, &endpoints, &BTreeMap::new());
        assert_eq!(plan.newly_disputed, vec![1, 2]);
        assert!(plan.restored.is_empty());
        assert!(plan.retained_disputed.is_empty());
        assert!(
            !pairs.is_empty(),
            "a non-empty exact graph creates an open v2 row"
        );
    }

    #[test]
    fn top_two_transition_coordinates_authorize_or_deny_deterministically() {
        let now = "2026-08-15T12:00:00Z".parse::<DateTime<Utc>>().unwrap();
        let exact = TransitionEvidence {
            event_id: Uuid::from_u128(1),
            created_at: now,
            exact_legacy_conflict: true,
        };
        let authorized = classify_latest_transition(vec![exact]).unwrap();
        assert_eq!(
            authorized.authorizing_event,
            Some(TransitionCoordinate {
                event_id: Uuid::from_u128(1),
                created_at: now,
            })
        );
        assert_eq!(
            authorized.decision,
            TransitionProvenanceDecision::RestoreExactUniqueLatest
        );

        let tied_independent = TransitionEvidence {
            event_id: Uuid::from_u128(2),
            created_at: now,
            exact_legacy_conflict: false,
        };
        let tied = classify_latest_transition(vec![exact, tied_independent]).unwrap();
        assert!(!tied.authorizes_restoration());
        assert_eq!(
            tied.decision,
            TransitionProvenanceDecision::RetainLatestTimestampTie
        );
        assert_eq!(
            tied.evidence
                .iter()
                .map(|event| event.event_id)
                .collect::<Vec<_>>(),
            vec![Uuid::from_u128(2), Uuid::from_u128(1)]
        );

        let older_independent = TransitionEvidence {
            event_id: Uuid::from_u128(3),
            created_at: now - chrono::Duration::nanoseconds(1),
            exact_legacy_conflict: false,
        };
        assert!(
            classify_latest_transition(vec![older_independent, exact])
                .unwrap()
                .authorizes_restoration()
        );

        let latest_nonmatching = TransitionEvidence {
            event_id: Uuid::from_u128(4),
            created_at: now + chrono::Duration::nanoseconds(1),
            exact_legacy_conflict: false,
        };
        let denied = classify_latest_transition(vec![exact, latest_nonmatching]).unwrap();
        assert_eq!(
            denied.decision,
            TransitionProvenanceDecision::RetainLatestNonmatching
        );
        assert_eq!(
            classify_latest_transition(Vec::new()).unwrap().decision,
            TransitionProvenanceDecision::RetainNoEvidence
        );
        assert!(classify_latest_transition(vec![exact, exact]).is_err());
        assert!(
            classify_latest_transition(vec![exact, older_independent, latest_nonmatching]).is_err()
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn aggregate_audit_is_exact_sorted_and_bound_annotated() {
        let legacy = LockedLegacyConflict {
            id: 10,
            claim_key: "fleet-store::database-choice".into(),
            state: "open".into(),
            detector: LEGACY_TYPED_VALUE_CONFLICT_DETECTOR.into(),
            revision: 7,
        };
        let mut left = string_candidate(1, "cockroachdb", 1, "disputed", true);
        left.revision = 3;
        let right = string_candidate(2, "postgresql", -1, "disputed", true);
        let third = string_candidate(3, "mysql", -1, "disputed", true);
        let fourth = string_candidate(4, "oracle", -1, "disputed", true);
        let candidates = vec![
            candidate_audit(&left).unwrap(),
            candidate_audit(&right).unwrap(),
            candidate_audit(&third).unwrap(),
            candidate_audit(&fourth).unwrap(),
        ];
        let transitions = TransitionPlan {
            newly_disputed: Vec::new(),
            restored: vec![1],
            retained_disputed: vec![2, 3, 4],
            provenance_ambiguous: vec![2, 3, 4],
        };
        let legacy_members = vec![
            LegacyMemberAudit {
                claim_id: 1,
                role: "claim".into(),
                state: "disputed".into(),
                classification: LegacyMemberClassification::CurrentCandidate,
            },
            LegacyMemberAudit {
                claim_id: 2,
                role: "claim".into(),
                state: "disputed".into(),
                classification: LegacyMemberClassification::CurrentCandidate,
            },
            LegacyMemberAudit {
                claim_id: 3,
                role: "claim".into(),
                state: "disputed".into(),
                classification: LegacyMemberClassification::CurrentCandidate,
            },
            LegacyMemberAudit {
                claim_id: 4,
                role: "claim".into(),
                state: "disputed".into(),
                classification: LegacyMemberClassification::CurrentCandidate,
            },
            LegacyMemberAudit {
                claim_id: 9,
                role: "claim".into(),
                state: "retracted".into(),
                classification: LegacyMemberClassification::Historical,
            },
        ];
        let at = |value: &str| value.parse::<DateTime<Utc>>().unwrap();
        let provenance = BTreeMap::from([
            (
                1,
                classify_latest_transition(vec![TransitionEvidence {
                    event_id: Uuid::from_u128(1),
                    created_at: at("2026-08-15T10:00:00Z"),
                    exact_legacy_conflict: true,
                }])
                .unwrap(),
            ),
            (
                2,
                classify_latest_transition(vec![
                    TransitionEvidence {
                        event_id: Uuid::from_u128(2),
                        created_at: at("2026-08-15T11:00:00Z"),
                        exact_legacy_conflict: true,
                    },
                    TransitionEvidence {
                        event_id: Uuid::from_u128(3),
                        created_at: at("2026-08-15T11:00:00Z"),
                        exact_legacy_conflict: false,
                    },
                ])
                .unwrap(),
            ),
            (
                3,
                classify_latest_transition(vec![
                    TransitionEvidence {
                        event_id: Uuid::from_u128(4),
                        created_at: at("2026-08-15T11:30:00Z"),
                        exact_legacy_conflict: true,
                    },
                    TransitionEvidence {
                        event_id: Uuid::from_u128(5),
                        created_at: at("2026-08-15T12:00:00Z"),
                        exact_legacy_conflict: false,
                    },
                ])
                .unwrap(),
            ),
            (4, classify_latest_transition(Vec::new()).unwrap()),
        ]);
        let payload = reconciliation_audit_payload(
            &legacy,
            11,
            "dismissed",
            &candidates,
            &[],
            &[],
            &transitions,
            &legacy_members,
            &provenance,
        )
        .unwrap();
        assert_eq!(payload["version"], RECONCILIATION_AUDIT_VERSION);
        assert_eq!(payload["legacy"]["conflict_id"], 10);
        assert_eq!(payload["legacy"]["revision"], 7);
        assert_eq!(payload["legacy"]["members"][4]["claim_id"], 9);
        assert_eq!(
            payload["legacy"]["members"][4]["classification"],
            "historical"
        );
        assert_eq!(payload["v2"]["conflict_id"], 11);
        assert_eq!(payload["candidates"][0]["id"], 1);
        assert_eq!(
            payload["candidates"][0]["value_sha256"]
                .as_str()
                .unwrap()
                .len(),
            64
        );
        assert_eq!(
            payload["restoration_provenance"],
            serde_json::json!([
                {
                    "claim_id": 1,
                    "decision": "restore_exact_unique_latest",
                    "authorizing_event": {
                        "event_id": "00000000-0000-0000-0000-000000000001",
                        "created_at": "2026-08-15T10:00:00Z",
                    },
                    "evidence": [{
                        "event_id": "00000000-0000-0000-0000-000000000001",
                        "created_at": "2026-08-15T10:00:00Z",
                        "classification": "exact_legacy_conflict",
                    }],
                },
                {
                    "claim_id": 2,
                    "decision": "retain_latest_timestamp_tie",
                    "authorizing_event": null,
                    "evidence": [
                        {
                            "event_id": "00000000-0000-0000-0000-000000000003",
                            "created_at": "2026-08-15T11:00:00Z",
                            "classification": "nonmatching_transition",
                        },
                        {
                            "event_id": "00000000-0000-0000-0000-000000000002",
                            "created_at": "2026-08-15T11:00:00Z",
                            "classification": "exact_legacy_conflict",
                        },
                    ],
                },
                {
                    "claim_id": 3,
                    "decision": "retain_latest_nonmatching",
                    "authorizing_event": null,
                    "evidence": [
                        {
                            "event_id": "00000000-0000-0000-0000-000000000005",
                            "created_at": "2026-08-15T12:00:00Z",
                            "classification": "nonmatching_transition",
                        },
                        {
                            "event_id": "00000000-0000-0000-0000-000000000004",
                            "created_at": "2026-08-15T11:30:00Z",
                            "classification": "exact_legacy_conflict",
                        },
                    ],
                },
                {
                    "claim_id": 4,
                    "decision": "retain_no_evidence",
                    "authorizing_event": null,
                    "evidence": [],
                },
            ])
        );
        let provenance_json = payload["restoration_provenance"].to_string();
        for forbidden in ["payload", "reason", "from_state", "to_state"] {
            assert!(!provenance_json.contains(forbidden));
        }
        assert_eq!(payload["bounds"]["max_current_claims"], 256);
        assert_eq!(payload["bounds"]["candidate_query_limit"], 257);
        assert_eq!(payload["bounds"]["max_legacy_members"], 256);
        assert_eq!(payload["bounds"]["legacy_member_query_limit"], 257);
        assert_eq!(payload["bounds"]["legacy_member_count"], 5);
        assert_eq!(
            payload["bounds"]["legacy_member_inverse_query_limit_per_claim"],
            2
        );
        assert_eq!(payload["bounds"]["transition_evidence_count"], 5);
        assert_eq!(payload["bounds"]["max_unordered_pairs"], 32_640);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn sql_contract_is_serializable_bounded_history_preserving_and_indexed() {
        assert!(REQUIRED_SCHEMA_PREFIX_SQL.contains("FROM _sqlx_migrations"));
        assert!(REQUIRED_SCHEMA_PREFIX_SQL.contains("version BETWEEN 1 AND $1"));
        assert!(REQUIRED_SCHEMA_PREFIX_SQL.contains("count(*) = $1"));
        assert!(REQUIRED_SCHEMA_PREFIX_SQL.contains("bool_and(success)"));
        assert_eq!(REQUIRED_SCHEMA_VERSION, 16);

        assert!(LOCK_LEGACY_CONFLICT_SQL.contains("memory_conflicts@primary"));
        assert!(LOCK_LEGACY_CONFLICT_SQL.contains("id = $3"));
        assert!(LOCK_LEGACY_CONFLICT_SQL.contains("FOR UPDATE"));

        assert!(
            LOCK_CONFLICT_LINEAGES_SQL.contains("memory_conflicts_scope_key_detector_unique_idx")
        );
        assert!(LOCK_CONFLICT_LINEAGES_SQL.contains("ORDER BY detector"));
        assert!(!LOCK_CONFLICT_LINEAGES_SQL.contains("ORDER BY detector, id"));
        assert!(LOCK_CONFLICT_LINEAGES_SQL.contains("LIMIT 3"));
        assert!(LOCK_CONFLICT_LINEAGES_SQL.contains("FOR UPDATE"));

        assert!(LOCK_CURRENT_CLAIMS_SQL.contains("AS MATERIALIZED"));
        assert!(LOCK_CURRENT_CLAIMS_SQL.contains("memory_claims_scope_key_idx"));
        assert!(LOCK_CURRENT_CLAIMS_SQL.contains("state IN ('active', 'disputed')"));
        assert!(LOCK_CURRENT_CLAIMS_SQL.contains("ORDER BY state, id"));
        assert!(LOCK_CURRENT_CLAIMS_SQL.contains("LIMIT $4"));
        assert!(LOCK_CURRENT_CLAIMS_SQL.contains("memory_claims@primary"));
        assert!(LOCK_CURRENT_CLAIMS_SQL.contains("FOR UPDATE"));

        assert!(LOCK_LEGACY_MEMBERS_SQL.contains("memory_conflict_members@primary"));
        assert!(LOCK_LEGACY_MEMBERS_SQL.contains("conflict_id = $3"));
        assert!(LOCK_LEGACY_MEMBERS_SQL.contains("SELECT claim_id, role"));
        assert!(LOCK_LEGACY_MEMBERS_SQL.contains("ORDER BY claim_id"));
        assert!(LOCK_LEGACY_MEMBERS_SQL.contains("LIMIT 257"));
        assert!(!LOCK_LEGACY_MEMBERS_SQL.contains("ANY("));
        assert!(LOCK_LEGACY_MEMBERS_SQL.contains("FOR UPDATE"));

        assert!(LOCK_LEGACY_MEMBER_CLAIMS_SQL.contains("AS MATERIALIZED"));
        assert!(LOCK_LEGACY_MEMBER_CLAIMS_SQL.contains("unnest($3::INT8[])"));
        assert!(LOCK_LEGACY_MEMBER_CLAIMS_SQL.contains("LIMIT 256"));
        assert!(LOCK_LEGACY_MEMBER_CLAIMS_SQL.contains("memory_claims@primary"));
        assert!(LOCK_LEGACY_MEMBER_CLAIMS_SQL.contains("SELECT c.id, c.claim_key, c.state"));
        assert!(!LOCK_LEGACY_MEMBER_CLAIMS_SQL.contains("state IN"));
        assert!(LOCK_LEGACY_MEMBER_CLAIMS_SQL.contains("ORDER BY c.id"));
        assert!(LOCK_LEGACY_MEMBER_CLAIMS_SQL.contains("FOR UPDATE"));

        assert!(LOCK_LEGACY_MEMBER_INVERSE_SQL.contains("AS MATERIALIZED"));
        assert!(LOCK_LEGACY_MEMBER_INVERSE_SQL.contains("unnest($3::INT8[])"));
        assert!(
            LOCK_LEGACY_MEMBER_INVERSE_SQL
                .contains("memory_conflict_members@memory_conflict_members_claim_idx")
        );
        assert!(LOCK_LEGACY_MEMBER_INVERSE_SQL.contains("ORDER BY conflict_id"));
        assert_eq!(
            LOCK_LEGACY_MEMBER_INVERSE_SQL
                .matches("\n    LIMIT 2\n")
                .count(),
            1
        );
        assert!(LOCK_LEGACY_MEMBER_INVERSE_SQL.contains("memory_conflicts@primary"));
        assert!(LOCK_LEGACY_MEMBER_INVERSE_SQL.contains("LEFT JOIN"));
        assert!(
            LOCK_LEGACY_MEMBER_INVERSE_SQL
                .contains("ORDER BY wanted.claim_id, membership.conflict_id")
        );
        assert!(!LOCK_LEGACY_MEMBER_INVERSE_SQL.contains("FOR UPDATE"));
        let substrate = include_str!("../../migrations/0001_fleet_memory.sql");
        assert!(substrate.contains(
            "CREATE INDEX memory_conflict_members_claim_idx\n    ON memory_conflict_members (tenant_id, project, claim_id, conflict_id)"
        ));

        assert!(LATEST_TRANSITION_PROVENANCE_SQL.contains("AS MATERIALIZED"));
        assert!(LATEST_TRANSITION_PROVENANCE_SQL.contains("LIMIT 256"));
        assert!(LATEST_TRANSITION_PROVENANCE_SQL.contains("LEFT JOIN LATERAL"));
        assert!(
            LATEST_TRANSITION_PROVENANCE_SQL
                .contains("FROM memory_claim_events@memory_claim_events_transition_provenance_idx")
        );
        assert!(!LATEST_TRANSITION_PROVENANCE_SQL.contains("memory_claim_events_claim_idx"));
        assert!(
            LATEST_TRANSITION_PROVENANCE_SQL
                .contains("SELECT event_id, reason, from_state, to_state, payload, created_at")
        );
        assert!(!LATEST_TRANSITION_PROVENANCE_SQL.contains("SELECT *"));
        assert!(LATEST_TRANSITION_PROVENANCE_SQL.contains("tenant_id = $1"));
        assert!(LATEST_TRANSITION_PROVENANCE_SQL.contains("project = $2"));
        assert!(LATEST_TRANSITION_PROVENANCE_SQL.contains("claim_id = wanted.claim_id"));
        assert!(LATEST_TRANSITION_PROVENANCE_SQL.contains("event_kind = 'state_transition'"));
        assert!(
            LATEST_TRANSITION_PROVENANCE_SQL.contains("ORDER BY created_at DESC, event_id DESC")
        );
        assert!(
            LATEST_TRANSITION_PROVENANCE_SQL
                .contains("ORDER BY wanted.claim_id, latest.created_at DESC, latest.event_id DESC")
        );
        assert_eq!(
            LATEST_TRANSITION_PROVENANCE_SQL
                .matches("\n    LIMIT 2\n")
                .count(),
            1
        );
        assert!(LATEST_TRANSITION_PROVENANCE_SQL.contains("LIMIT 2"));
        let provenance_index =
            include_str!("../../migrations/0016_claim_transition_provenance_index.sql");
        assert!(provenance_index.contains(
            "CREATE INDEX IF NOT EXISTS memory_claim_events_transition_provenance_idx\n    ON memory_claim_events (\n        tenant_id,\n        project,\n        claim_id,\n        event_kind,\n        created_at DESC,\n        event_id DESC\n    ) STORING (\n        reason,\n        from_state,\n        to_state,\n        payload\n    )"
        ));

        assert!(INSERT_V2_CONFLICT_SQL.contains("claim_key, detector"));
        assert!(INSERT_V2_CONFLICT_SQL.contains("ON CONFLICT"));
        assert!(INSERT_V2_MEMBERS_SQL.contains("unnest($4::INT8[])"));
        assert_eq!(
            CONFLICT_RECONCILIATION_OPERATION,
            "reconcile_conflict_detector_v2"
        );
        assert_eq!(
            NO_V2_INCOMPATIBILITY_RESOLUTION_KIND,
            "no_v2_incompatibility_at_reconciliation"
        );

        let source = include_str!("reconciliation.rs");
        let legacy_update = ["UPDATE", " memory_conflicts SET"].concat();
        let legacy_delete = ["DELETE FROM", " memory_conflicts"].concat();
        let membership_delete = ["DELETE FROM", " memory_conflict_members"].concat();
        assert!(!source.contains(&legacy_update));
        assert!(!source.contains(&legacy_delete));
        assert!(!source.contains(&membership_delete));
        assert!(source.contains("with_serializable_retry"));
        assert!(source.contains("ON CONFLICT (tenant_id, idempotency_key) DO NOTHING"));
        let reconcile_body = source.split_once("async fn reconcile_once(").unwrap().1;
        assert!(
            reconcile_body
                .find("require_schema_prefix(transaction)")
                .unwrap()
                < reconcile_body.find("select_receipt(transaction").unwrap()
        );
        assert!(
            reconcile_body
                .find("lock_and_validate_legacy_members(transaction")
                .unwrap()
                < reconcile_body
                    .find("lock_current_candidates(transaction")
                    .unwrap()
        );
        assert!(
            reconcile_body
                .find("lock_and_validate_legacy_members(transaction")
                .unwrap()
                < reconcile_body
                    .find("insert_v2_conflict(transaction")
                    .unwrap()
        );
    }

    #[test]
    fn receipt_request_is_versioned_and_stable_across_sessions() {
        let request = reconciliation_request(41, 7);
        assert_eq!(
            request,
            serde_json::json!({
                "version": 1,
                "legacy_conflict_id": 41,
                "expected_legacy_revision": 7,
            })
        );
        assert!(request.get("scope").is_none());
        assert!(request.get("session_id").is_none());
        assert!(request.get("agent").is_none());
        assert!(request.get("privacy_tier").is_none());
    }

    #[test]
    fn receipt_response_rejects_every_cross_wired_legacy_coordinate() {
        let request = reconciliation_request(41, 7);
        let response = stored_reconciliation_response();
        assert!(validate_stored_reconciliation_response(&response, &request, Some(73)).is_ok());

        let mut wrong_legacy = response.clone();
        wrong_legacy.legacy_conflict_id = 42;
        assert!(
            validate_stored_reconciliation_response(&wrong_legacy, &request, Some(73)).is_err()
        );

        let mut wrong_revision = response.clone();
        wrong_revision.legacy_conflict_revision = 8;
        assert!(
            validate_stored_reconciliation_response(&wrong_revision, &request, Some(73)).is_err()
        );

        let mut wrong_version = response.clone();
        wrong_version.request_version = RECONCILIATION_REQUEST_VERSION + 1;
        assert!(
            validate_stored_reconciliation_response(&wrong_version, &request, Some(73)).is_err()
        );

        assert!(validate_stored_reconciliation_response(&response, &request, Some(74)).is_err());

        let mut replay_bit_persisted = response.clone();
        replay_bit_persisted.idempotent_replay = true;
        assert!(
            validate_stored_reconciliation_response(&replay_bit_persisted, &request, Some(73))
                .is_err()
        );

        let future_request = serde_json::json!({
            "version": RECONCILIATION_REQUEST_VERSION + 1,
            "legacy_conflict_id": 41,
            "expected_legacy_revision": 7,
        });
        assert!(
            validate_stored_reconciliation_response(&response, &future_request, Some(73)).is_err()
        );
    }

    #[tokio::test]
    async fn live_reconciliation_is_inert_without_its_exact_database_url() {
        let Ok(database_url) = std::env::var("FLEET_RECONCILIATION_TEST_DATABASE_URL") else {
            return;
        };
        run_live_reconciliation_contract(&database_url)
            .await
            .unwrap();
    }

    #[allow(clippy::too_many_lines)]
    async fn run_live_reconciliation_contract(database_url: &str) -> Result<()> {
        use crate::store::cockroach::{CockroachStore, PoolConfig};
        use ostk_recall_core::PrivacyTier;

        let tenant_id = Uuid::now_v7();
        let project = format!("live-conflict-reconciliation-{}", Uuid::now_v7());
        let scope = FleetScope::new(
            tenant_id,
            project,
            "reconciliation-test",
            Some("isolated-official-binary-proof".into()),
            PrivacyTier::T1Project,
        )?;
        let store = CockroachStore::connect(
            database_url,
            scope.clone(),
            PoolConfig {
                max_connections: 4,
                ..PoolConfig::default()
            },
        )
        .await?;
        store.migrate().await?;
        let pool = store.pool().clone();
        let claim_key = "fleet-store::database-choice";
        let left_id = seed_live_claim(
            &pool,
            &scope,
            claim_key,
            Value::String("cockroachdb".into()),
            1,
        )
        .await?;
        let right_id = seed_live_claim(
            &pool,
            &scope,
            claim_key,
            Value::String("postgresql".into()),
            -1,
        )
        .await?;
        let legacy_id = sqlx::query_scalar::<_, i64>(
            "INSERT INTO memory_conflicts (\
                 tenant_id, project, claim_key, state, detector, rationale, revision\
             ) VALUES ($1, $2, $3, 'open', $4, 'legacy fixture', 7) \
             RETURNING id",
        )
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(claim_key)
        .bind(LEGACY_TYPED_VALUE_CONFLICT_DETECTOR)
        .fetch_one(&pool)
        .await?;
        for claim_id in [left_id, right_id] {
            sqlx::query(
                "INSERT INTO memory_conflict_members (\
                     tenant_id, project, conflict_id, claim_id\
                 ) VALUES ($1, $2, $3, $4)",
            )
            .bind(scope.tenant_id)
            .bind(&scope.project)
            .bind(legacy_id)
            .bind(claim_id)
            .execute(&pool)
            .await?;
            sqlx::query(
                "INSERT INTO memory_claim_events (\
                     tenant_id, project, claim_id, event_kind, actor, reason, \
                     from_state, to_state, payload\
                 ) VALUES ($1, $2, $3, 'state_transition', $4, \
                     'conflict_detected', 'active', 'disputed', $5)",
            )
            .bind(scope.tenant_id)
            .bind(&scope.project)
            .bind(claim_id)
            .bind(&scope.agent)
            .bind(serde_json::json!({"conflict_id": legacy_id}))
            .execute(&pool)
            .await?;
        }
        let legacy_receipt_key = format!("legacy-fixture-{legacy_id}");
        sqlx::query(
            "INSERT INTO memory_mutation_receipts (\
                 tenant_id, idempotency_key, project, request, operation, conflict_id, response\
             ) VALUES ($1, $2, $3, $4, 'legacy_fixture', $5, $6)",
        )
        .bind(scope.tenant_id)
        .bind(&legacy_receipt_key)
        .bind(&scope.project)
        .bind(serde_json::json!({"legacy": true}))
        .bind(legacy_id)
        .bind(serde_json::json!({"preserve": true}))
        .execute(&pool)
        .await?;

        let legacy_before = live_legacy_snapshot(&pool, &scope, legacy_id).await?;
        let members_before = live_member_snapshot(&pool, &scope, legacy_id).await?;
        let receipt_before = live_receipt_snapshot(&pool, &scope, &legacy_receipt_key).await?;

        let repository = CockroachConflictReconciliationRepository::new(
            pool.clone(),
            scope.clone(),
            RetryPolicy::default(),
        )?;
        let replay_key = format!("reconcile-{legacy_id}");
        let first = repository
            .reconcile_legacy_conflict(&scope, legacy_id, 7, &replay_key)
            .await?;
        assert!(!first.idempotent_replay);
        assert_eq!(first.request_version, RECONCILIATION_REQUEST_VERSION);
        assert_eq!(first.legacy_conflict_id, legacy_id);
        assert_eq!(first.legacy_conflict_revision, 7);
        assert_eq!(first.v2_state, "dismissed");
        assert_eq!(first.candidate_count, 2);
        assert_eq!(first.incompatibility_pair_count, 0);
        assert!(first.v2_member_ids.is_empty());
        assert_eq!(first.restored_claim_ids, vec![left_id, right_id]);
        assert!(first.retained_disputed_claim_ids.is_empty());

        let mut replacement_session_scope = scope.clone();
        replacement_session_scope.session_id = Some("replacement-session".into());
        let replay = repository
            .reconcile_legacy_conflict(&replacement_session_scope, legacy_id, 7, &replay_key)
            .await?;
        assert!(replay.idempotent_replay);
        let mut normalized_replay = replay.clone();
        normalized_replay.idempotent_replay = false;
        assert_eq!(normalized_replay, first);

        assert_eq!(
            live_legacy_snapshot(&pool, &scope, legacy_id).await?,
            legacy_before
        );
        assert_eq!(
            live_member_snapshot(&pool, &scope, legacy_id).await?,
            members_before
        );
        assert_eq!(
            live_receipt_snapshot(&pool, &scope, &legacy_receipt_key).await?,
            receipt_before
        );

        let v2_row: (String, String, Option<String>, i64) = sqlx::query_as(
            "SELECT state, detector, resolution_kind, revision \
             FROM memory_conflicts \
             WHERE tenant_id = $1 AND project = $2 AND id = $3",
        )
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(first.conflict_id)
        .fetch_one(&pool)
        .await?;
        assert_eq!(v2_row.0, "dismissed");
        assert_eq!(v2_row.1, FUNCTIONAL_VALUE_CONFLICT_DETECTOR_V2);
        assert_eq!(
            v2_row.2.as_deref(),
            Some(NO_V2_INCOMPATIBILITY_RESOLUTION_KIND)
        );
        assert_eq!(v2_row.3, 1);

        let v2_members: i64 = sqlx::query_scalar(
            "SELECT count(*)::INT8 FROM memory_conflict_members \
             WHERE tenant_id = $1 AND project = $2 AND conflict_id = $3",
        )
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(first.conflict_id)
        .fetch_one(&pool)
        .await?;
        assert_eq!(v2_members, 0);
        let states: Vec<(i64, String, i64)> = sqlx::query_as(
            "SELECT id, state, revision FROM memory_claims \
             WHERE tenant_id = $1 AND project = $2 AND id = ANY($3) ORDER BY id",
        )
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind([left_id, right_id])
        .fetch_all(&pool)
        .await?;
        assert_eq!(
            states,
            vec![
                (left_id, "active".into(), 2),
                (right_id, "active".into(), 2)
            ]
        );

        let audit: Value = sqlx::query_scalar(
            "SELECT payload FROM memory_events \
             WHERE tenant_id = $1 AND project = $2 AND event_id = $3 \
               AND event_kind = 'conflict_detector_reconciled'",
        )
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(first.reconciliation_event_id)
        .fetch_one(&pool)
        .await?;
        assert_eq!(audit["legacy"]["conflict_id"], legacy_id);
        assert_eq!(audit["legacy"]["members"].as_array().unwrap().len(), 2);
        assert!(
            audit["legacy"]["members"]
                .as_array()
                .unwrap()
                .iter()
                .all(|member| {
                    member["role"] == "claim" && member["classification"] == "current_candidate"
                })
        );
        assert_eq!(audit["v2"]["conflict_id"], first.conflict_id);
        assert_eq!(audit["bounds"]["candidate_count"], 2);
        assert_eq!(audit["bounds"]["pair_count"], 0);
        assert_eq!(audit["bounds"]["legacy_member_count"], 2);
        assert_eq!(audit["bounds"]["transition_evidence_count"], 2);
        assert_eq!(audit["restored"], serde_json::json!([left_id, right_id]));
        assert!(
            audit["restoration_provenance"]
                .as_array()
                .unwrap()
                .iter()
                .all(|entry| {
                    entry["decision"] == "restore_exact_unique_latest"
                        && !entry["authorizing_event"].is_null()
                        && entry["evidence"].as_array().is_some_and(|events| {
                            events.len() == 1
                                && events[0]["classification"] == "exact_legacy_conflict"
                        })
                })
        );

        cleanup_live_scope(&pool, &scope).await?;
        pool.close().await;
        Ok(())
    }

    async fn seed_live_claim(
        pool: &PgPool,
        scope: &FleetScope,
        claim_key: &str,
        value: Value,
        polarity: i16,
    ) -> Result<i64> {
        Ok(sqlx::query_scalar::<_, i64>(
            "INSERT INTO memory_claims (\
                 tenant_id, project, kind, claim_key, subject, predicate, value, text, \
                 polarity, state, conflict_eligible\
             ) VALUES ($1, $2, 'decision', $3, 'fleet-store', 'database-choice', \
                 $4, $5, $6, 'disputed', true) \
             RETURNING id",
        )
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(claim_key)
        .bind(&value)
        .bind(value.to_string())
        .bind(polarity)
        .fetch_one(pool)
        .await?)
    }

    async fn live_legacy_snapshot(
        pool: &PgPool,
        scope: &FleetScope,
        legacy_id: i64,
    ) -> Result<Value> {
        Ok(sqlx::query_scalar(
            "SELECT jsonb_build_object(\
                 'id', id, 'claim_key', claim_key, 'kind', kind, 'state', state, \
                 'detector', detector, 'rationale', rationale, 'revision', revision, \
                 'detected_at', detected_at, 'last_seen_at', last_seen_at, \
                 'resolved_at', resolved_at, 'resolution_kind', resolution_kind, \
                 'resolution_reason', resolution_reason\
             ) \
             FROM memory_conflicts \
             WHERE tenant_id = $1 AND project = $2 AND id = $3",
        )
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(legacy_id)
        .fetch_one(pool)
        .await?)
    }

    async fn live_member_snapshot(
        pool: &PgPool,
        scope: &FleetScope,
        conflict_id: i64,
    ) -> Result<Vec<(i64, String)>> {
        Ok(sqlx::query_as(
            "SELECT claim_id, role FROM memory_conflict_members \
             WHERE tenant_id = $1 AND project = $2 AND conflict_id = $3 \
             ORDER BY claim_id",
        )
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(conflict_id)
        .fetch_all(pool)
        .await?)
    }

    async fn live_receipt_snapshot(
        pool: &PgPool,
        scope: &FleetScope,
        idempotency_key: &str,
    ) -> Result<(String, Value, String, Option<i64>, Option<Value>)> {
        Ok(sqlx::query_as(
            "SELECT project, request, operation, conflict_id, response \
             FROM memory_mutation_receipts \
             WHERE tenant_id = $1 AND idempotency_key = $2",
        )
        .bind(scope.tenant_id)
        .bind(idempotency_key)
        .fetch_one(pool)
        .await?)
    }

    async fn cleanup_live_scope(pool: &PgPool, scope: &FleetScope) -> Result<()> {
        for table in [
            "memory_mutation_receipts",
            "memory_events",
            "memory_claim_events",
            "memory_conflict_members",
            "memory_conflicts",
            "memory_claims",
        ] {
            let statement = format!("DELETE FROM {table} WHERE tenant_id = $1 AND project = $2");
            sqlx::query(&statement)
                .bind(scope.tenant_id)
                .bind(&scope.project)
                .execute(pool)
                .await?;
        }
        Ok(())
    }
}
