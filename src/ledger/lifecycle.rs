//! Pure planning for the serving claim/conflict lifecycle (ADR 0004).
//!
//! Every decision a lifecycle transaction makes after it has locked its rows
//! lives here, free of I/O: owner authority over a locked claim, the functional
//! incompatibility graph over the locked lifecycle-current claims of one key,
//! and whether the key's v2 conflict may be closed. The store module only
//! reads, locks, and applies what these functions decide.

use std::collections::BTreeMap;
use std::fmt;

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{Value, json};

use crate::ledger::{
    Acknowledgement, ClaimKind, ClaimState, ClosureView, ConflictLifecycleEvent,
    ConflictLifecycleOverlay, RevisionGap, WaiverView, functional_values_are_incompatible,
    intervals_overlap,
};
use crate::memory_contracts::discrepancy::is_blank_rationale;
use crate::{FleetError, FleetScope, Result};

/// Only authored claims may be retired by the serving writer.
pub const OPERATOR_ASSERTED_ORIGIN: &str = "operator_asserted";
/// Upper bound, in Unicode characters, on an optional lifecycle audit note.
/// It counts characters as the advertised JSON Schema `maxLength` does, so a
/// schema-valid note is never refused by the server.
pub const MAX_LIFECYCLE_REASON_CHARS: usize = 1_000;
/// Remaining incompatible pairs echoed in a reevaluation; the count is exact.
pub const MAX_REPORTED_REMAINING_PAIRS: usize = 32;
/// Claims one concession `resolve` may retract.
pub const MAX_CONCESSION_CLAIMS: usize = 32;
/// Durable members a conflict lifecycle mutation may count; the lifecycle
/// log's CHECK admits no more.
pub const MAX_CONFLICT_MEMBER_COUNT: i64 = 4_096;
/// Events one conflict's lifecycle log may hold (its `event_seq` CHECK).
pub const MAX_CONFLICT_LIFECYCLE_EVENTS: i64 = 4_096;
/// Events the overlay reads per episode, newest first; one more is fetched
/// as a sentinel.
pub const MAX_OVERLAY_EPISODE_EVENTS: usize = 32;
/// Acknowledgers the overlay lists; the rest are reported as truncated.
pub const MAX_OVERLAY_ACKNOWLEDGERS: usize = 16;
/// Events `recall(get, kind=conflict)` returns as history; one more is
/// fetched as a sentinel.
pub const MAX_HISTORY_EVENTS: usize = 256;
/// Characters of a waiver rationale the overlay echoes.
const MAX_OVERLAY_RATIONALE_CHARS: usize = 1_000;

const V2_DETECTOR_CLASS: i64 = 2;
const LEGACY_DETECTOR_CLASS: i64 = 1;
const UNKNOWN_DETECTOR_CLASS: i64 = 0;

/// Closed vocabulary for a refused lifecycle mutation.
///
/// A refusal is decided before commit, so the whole transaction (including
/// the idempotency reservation) rolls back and the key stays free.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusalCode {
    NotFound,
    NotOwner,
    NotOperatorAsserted,
    NotCurrent,
    StaleRevision,
    StaleMemberCount,
    NotOpen,
    LegacyLineage,
    SuccessorKindMismatch,
    SuccessorKeyMismatch,
    SuccessorEligibilityMismatch,
    NotMember,
    StillIncompatible,
    VerificationDivergence,
    Implicated,
    UnattributedMember,
    BoundExceeded,
    LifecycleUnavailable,
    AdjudicationDisabled,
}

impl RefusalCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::NotOwner => "not_owner",
            Self::NotOperatorAsserted => "not_operator_asserted",
            Self::NotCurrent => "not_current",
            Self::StaleRevision => "stale_revision",
            Self::StaleMemberCount => "stale_member_count",
            Self::NotOpen => "not_open",
            Self::LegacyLineage => "legacy_lineage",
            Self::SuccessorKindMismatch => "successor_kind_mismatch",
            Self::SuccessorKeyMismatch => "successor_key_mismatch",
            Self::SuccessorEligibilityMismatch => "successor_eligibility_mismatch",
            Self::NotMember => "not_member",
            Self::StillIncompatible => "still_incompatible",
            Self::VerificationDivergence => "verification_divergence",
            Self::Implicated => "implicated",
            Self::UnattributedMember => "unattributed_member",
            Self::BoundExceeded => "bound_exceeded",
            Self::LifecycleUnavailable => "lifecycle_unavailable",
            Self::AdjudicationDisabled => "adjudication_disabled",
        }
    }
}

impl fmt::Display for RefusalCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A typed, caller-correctable refusal. Nothing was committed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LifecycleRefusal {
    pub code: RefusalCode,
    pub message: String,
    pub details: Value,
}

impl LifecycleRefusal {
    #[must_use]
    pub fn new(code: RefusalCode, message: impl Into<String>, details: Value) -> Self {
        Self {
            code,
            message: message.into(),
            details,
        }
    }
}

impl fmt::Display for LifecycleRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl From<LifecycleRefusal> for FleetError {
    fn from(refusal: LifecycleRefusal) -> Self {
        Self::LifecycleRefused(Box::new(refusal))
    }
}

/// One lifecycle-current claim of a key, locked `FOR UPDATE` in id order, or
/// the locked target itself when it is not conflict-eligible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockedKeyClaim {
    pub id: i64,
    pub state: ClaimState,
    pub origin: String,
    pub actor: Option<String>,
    pub revision: i64,
    pub polarity: i16,
    pub valid_from: Option<DateTime<Utc>>,
    pub valid_to: Option<DateTime<Utc>>,
    pub conflict_eligible: bool,
    pub value: Option<Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictRowState {
    Open,
    Resolved,
    Dismissed,
}

impl ConflictRowState {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "open" => Ok(Self::Open),
            "resolved" => Ok(Self::Resolved),
            "dismissed" => Ok(Self::Dismissed),
            _ => Err(FleetError::Memory(
                "database returned an unknown conflict state".into(),
            )),
        }
    }
}

/// The key's `same_key_functional_value_v2` lineage row, as locked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V2Lineage {
    pub id: i64,
    pub state: ConflictRowState,
    pub revision: i64,
}

/// Classify the lineage rows locked for one key, applying the same admission
/// rules as the record path's detector write probe: an unknown detector or a
/// duplicate lineage is corruption, and a key that has only the legacy
/// `same_key_typed_value` lineage must be reconciled before the serving writer
/// changes anything on it.
///
/// Rows are `(conflict_id, detector_class, state, revision)`; the lock query
/// returns at most three so a third row is a sentinel.
pub fn classify_lineages(rows: &[(i64, i64, String, i64)]) -> Result<Option<V2Lineage>> {
    let corrupt = || {
        FleetError::Memory("claim key has an unknown or duplicate conflict detector lineage".into())
    };
    if rows.len() > 2 {
        return Err(corrupt());
    }
    let mut v2 = None;
    let mut legacy = false;
    for (id, detector_class, state, revision) in rows {
        if *id <= 0 || *revision <= 0 {
            return Err(FleetError::Memory(
                "database returned an invalid conflict lineage coordinate".into(),
            ));
        }
        match *detector_class {
            V2_DETECTOR_CLASS => {
                let lineage = V2Lineage {
                    id: *id,
                    state: ConflictRowState::parse(state)?,
                    revision: *revision,
                };
                if v2.replace(lineage).is_some() {
                    return Err(corrupt());
                }
            }
            LEGACY_DETECTOR_CLASS => {
                if legacy {
                    return Err(corrupt());
                }
                legacy = true;
            }
            UNKNOWN_DETECTOR_CLASS => return Err(corrupt()),
            _ => {
                return Err(FleetError::Memory(
                    "database returned an invalid conflict detector classification".into(),
                ));
            }
        }
    }
    if legacy && v2.is_none() {
        return Err(LifecycleRefusal::new(
            RefusalCode::LegacyLineage,
            "the claim key has only an unreconciled legacy conflict lineage; run conflict reconciliation first",
            json!({}),
        )
        .into());
    }
    Ok(v2)
}

/// Owner authority over one locked claim: the caller authored it, it is an
/// operator assertion, it is lifecycle-current, and the caller read its
/// current revision.
pub fn check_owner_transition(
    target: &LockedKeyClaim,
    agent: &str,
    expected_revision: i64,
) -> std::result::Result<(), LifecycleRefusal> {
    if target.actor.as_deref() != Some(agent) {
        return Err(LifecycleRefusal::new(
            RefusalCode::NotOwner,
            format!("claim {} was not authored by this agent", target.id),
            json!({ "claim_id": target.id }),
        ));
    }
    if target.origin != OPERATOR_ASSERTED_ORIGIN {
        return Err(LifecycleRefusal::new(
            RefusalCode::NotOperatorAsserted,
            format!(
                "claim {} has origin {}; only operator_asserted claims can be retired",
                target.id, target.origin
            ),
            json!({ "claim_id": target.id, "origin": target.origin }),
        ));
    }
    let details = json!({
        "claim_id": target.id,
        "current_revision": target.revision,
        "current_state": target.state.as_str(),
    });
    if !target.state.is_current() {
        return Err(LifecycleRefusal::new(
            RefusalCode::NotCurrent,
            format!(
                "claim {} is {}, not active or disputed",
                target.id,
                target.state.as_str()
            ),
            details,
        ));
    }
    if target.revision != expected_revision {
        return Err(LifecycleRefusal::new(
            RefusalCode::StaleRevision,
            format!(
                "claim {} is at revision {} ({})",
                target.id,
                target.revision,
                target.state.as_str()
            ),
            details,
        ));
    }
    Ok(())
}

/// The detector-relevant identity of a claim: its kind, its normalized
/// functional key, and whether the detector compares it at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimShape {
    pub kind: ClaimKind,
    pub claim_key: Option<String>,
    pub conflict_eligible: bool,
}

/// A successor must keep its predecessor's kind, normalized key, and conflict
/// eligibility, so a supersede can change a claim's value or wording but can
/// never move it out of the detector's view or onto another key.
pub fn check_successor(
    predecessor_id: i64,
    predecessor: &ClaimShape,
    successor: &ClaimShape,
) -> std::result::Result<(), LifecycleRefusal> {
    if successor.kind != predecessor.kind {
        return Err(LifecycleRefusal::new(
            RefusalCode::SuccessorKindMismatch,
            format!(
                "claim {predecessor_id} is a {}; its successor must be a {} too, not a {}",
                predecessor.kind.as_str(),
                predecessor.kind.as_str(),
                successor.kind.as_str()
            ),
            json!({
                "claim_id": predecessor_id,
                "kind": predecessor.kind.as_str(),
                "successor_kind": successor.kind.as_str(),
            }),
        ));
    }
    if successor.claim_key != predecessor.claim_key {
        return Err(LifecycleRefusal::new(
            RefusalCode::SuccessorKeyMismatch,
            format!(
                "claim {predecessor_id} has claim_key {}; its successor's subject and predicate normalize to {}",
                display_key(predecessor.claim_key.as_deref()),
                display_key(successor.claim_key.as_deref())
            ),
            json!({
                "claim_id": predecessor_id,
                "claim_key": predecessor.claim_key,
                "successor_claim_key": successor.claim_key,
            }),
        ));
    }
    if successor.conflict_eligible != predecessor.conflict_eligible {
        let message = if predecessor.conflict_eligible {
            format!(
                "claim {predecessor_id} is conflict-eligible; its successor must also carry a value so the detector keeps comparing it"
            )
        } else {
            format!(
                "claim {predecessor_id} is not conflict-eligible; its successor must not carry a value either"
            )
        };
        return Err(LifecycleRefusal::new(
            RefusalCode::SuccessorEligibilityMismatch,
            message,
            json!({
                "claim_id": predecessor_id,
                "conflict_eligible": predecessor.conflict_eligible,
                "successor_conflict_eligible": successor.conflict_eligible,
            }),
        ));
    }
    Ok(())
}

fn display_key(claim_key: Option<&str>) -> String {
    claim_key.map_or_else(|| "none".to_owned(), |key| format!("'{key}'"))
}

/// Every incompatible pair among lifecycle-current, conflict-eligible claims
/// of one functional key, as `(lower id, higher id)` in ascending order.
///
/// This is the record detector's contract (overlapping half-open validity
/// windows; two affirmations of different values, or an affirmation and a
/// negation of the same value) and the reconciliation pair graph's algorithm.
pub fn incompatible_pairs(claims: &[LockedKeyClaim]) -> Vec<(i64, i64)> {
    let mut eligible = claims
        .iter()
        .filter(|claim| claim.conflict_eligible && claim.state.is_current())
        .filter_map(|claim| claim.value.as_ref().map(|value| (claim, value)))
        .collect::<Vec<_>>();
    eligible.sort_by_key(|(claim, _)| claim.id);
    let mut pairs = Vec::new();
    for (index, (left, left_value)) in eligible.iter().enumerate() {
        for (right, right_value) in &eligible[index + 1..] {
            if intervals_overlap(
                left.valid_from,
                left.valid_to,
                right.valid_from,
                right.valid_to,
            ) && functional_values_are_incompatible(
                left_value,
                left.polarity,
                right_value,
                right.polarity,
            ) {
                pairs.push((left.id.min(right.id), left.id.max(right.id)));
            }
        }
    }
    pairs.sort_unstable();
    pairs.dedup();
    pairs
}

/// What a lifecycle change means for the key's v2 conflict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reevaluation {
    NoLineage,
    NotOpen,
    /// Incompatible current pairs remain, so the conflict stays open.
    StillOpen {
        conflict_id: i64,
        revision: i64,
        pairs: Vec<(i64, i64)>,
    },
    /// No incompatible current pair remains: the detector verifies the close.
    /// `restore_candidates` are the remaining disputed claim ids.
    Close {
        conflict_id: i64,
        revision: i64,
        restore_candidates: Vec<i64>,
    },
    /// The Rust and SQL pair sets disagree. Nothing is closed.
    Divergent {
        conflict_id: i64,
        revision: i64,
        rust_pairs: Vec<(i64, i64)>,
        sql_pairs: Vec<(i64, i64)>,
    },
}

/// Decide whether the key's v2 conflict closes, given the locked remaining
/// current claims and the database's own pair computation over the same rows.
/// The two pair sets must agree exactly before anything is closed.
pub fn plan_reevaluation(
    lineage: Option<V2Lineage>,
    remaining: &[LockedKeyClaim],
    sql_pairs: &[(i64, i64)],
) -> Reevaluation {
    let Some(lineage) = lineage else {
        return Reevaluation::NoLineage;
    };
    if lineage.state != ConflictRowState::Open {
        return Reevaluation::NotOpen;
    }
    let rust_pairs = incompatible_pairs(remaining);
    let mut sql_pairs = sql_pairs
        .iter()
        .map(|(left, right)| (*left.min(right), *left.max(right)))
        .collect::<Vec<_>>();
    sql_pairs.sort_unstable();
    sql_pairs.dedup();
    if rust_pairs != sql_pairs {
        return Reevaluation::Divergent {
            conflict_id: lineage.id,
            revision: lineage.revision,
            rust_pairs,
            sql_pairs,
        };
    }
    if rust_pairs.is_empty() {
        let mut restore_candidates = remaining
            .iter()
            .filter(|claim| claim.state == ClaimState::Disputed)
            .map(|claim| claim.id)
            .collect::<Vec<_>>();
        restore_candidates.sort_unstable();
        restore_candidates.dedup();
        return Reevaluation::Close {
            conflict_id: lineage.id,
            revision: lineage.revision,
            restore_candidates,
        };
    }
    Reevaluation::StillOpen {
        conflict_id: lineage.id,
        revision: lineage.revision,
        pairs: rust_pairs,
    }
}

/// A concession's split of the key's locked current claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Concession {
    /// The caller's own member claims to retract, ascending by id.
    pub retracted: Vec<LockedKeyClaim>,
    /// Every other locked current claim of the key, ascending by id.
    pub remaining: Vec<LockedKeyClaim>,
}

/// Check a concession `resolve`: every claim it names must be a member of
/// the conflict, lifecycle-current, and the caller's own operator assertion.
/// It never touches another agent's claim (DISC-03).
///
/// `retract_claim_ids` is sorted and deduplicated. `members` are the named
/// ids that are members of the conflict, with their plain-read state and
/// revision. `current` is the key's lifecycle-current claims, locked in
/// ascending id order.
pub fn plan_concession(
    conflict_id: i64,
    agent: &str,
    retract_claim_ids: &[i64],
    members: &[(i64, ClaimState, i64)],
    current: Vec<LockedKeyClaim>,
) -> Result<Concession> {
    let members = members
        .iter()
        .map(|(id, state, revision)| (*id, (*state, *revision)))
        .collect::<BTreeMap<_, _>>();
    let mut retracted = Vec::with_capacity(retract_claim_ids.len());
    for claim_id in retract_claim_ids {
        let Some((state, revision)) = members.get(claim_id) else {
            return Err(LifecycleRefusal::new(
                RefusalCode::NotMember,
                format!("claim {claim_id} is not a member of conflict {conflict_id}"),
                json!({ "conflict_id": conflict_id, "claim_id": claim_id }),
            )
            .into());
        };
        let Some(locked) = current.iter().find(|claim| claim.id == *claim_id) else {
            if state.is_current() {
                // A current member always carries the conflict's own key.
                return Err(FleetError::Memory(
                    "a current conflict member was missing from its key's locked claims".into(),
                ));
            }
            return Err(LifecycleRefusal::new(
                RefusalCode::NotCurrent,
                format!(
                    "claim {claim_id} is {}, not active or disputed",
                    state.as_str()
                ),
                json!({
                    "claim_id": claim_id,
                    "current_revision": revision,
                    "current_state": state.as_str(),
                }),
            )
            .into());
        };
        // The conflict's revision and member count guard the caller's view,
        // so each claim is checked at its locked revision.
        check_owner_transition(locked, agent, locked.revision)?;
        retracted.push(locked.clone());
    }
    let remaining = current
        .into_iter()
        .filter(|claim| retract_claim_ids.binary_search(&claim.id).is_err())
        .collect();
    Ok(Concession {
        retracted,
        remaining,
    })
}

/// The conflict revision whose lifecycle events describe the row: the current
/// revision of an open conflict, and the episode a close ended otherwise
/// (a close always advances the revision by one).
#[must_use]
pub fn overlay_episode_revision(state: &str, revision: i64) -> i64 {
    if is_closed_state(state) {
        (revision - 1).max(1)
    } else {
        revision
    }
}

fn is_closed_state(state: &str) -> bool {
    matches!(state, "resolved" | "dismissed")
}

/// Derive the lifecycle overlay of one conflict row from its episode's
/// events, evaluated at the database time `evaluated_at`.
///
/// A closed row reads `clear` and names its logged close, if any. An open
/// row reads `waived` only while its latest waiver is unexpired and the
/// conflict still has the members it was waived with; otherwise it reads
/// `acknowledged` when an agent acknowledged this episode, and `open`
/// otherwise. Acknowledgement never changes the read side (ADR 0003).
#[must_use]
pub fn derive_overlay(
    state: &str,
    revision: i64,
    member_count: i64,
    events: &[ConflictLifecycleEvent],
    events_truncated: bool,
    evaluated_at: DateTime<Utc>,
) -> ConflictLifecycleOverlay {
    let episode_revision = overlay_episode_revision(state, revision);
    let mut episode = events
        .iter()
        .filter(|event| event.episode_revision == episode_revision)
        .collect::<Vec<_>>();
    episode.sort_by_key(|event| event.seq);
    let acknowledgements = episode
        .iter()
        .filter(|event| event.kind == "acknowledged")
        .collect::<Vec<_>>();
    let acknowledged_by = acknowledgements
        .iter()
        .take(MAX_OVERLAY_ACKNOWLEDGERS)
        .map(|event| Acknowledgement {
            actor: event.actor.clone(),
            at: event.created_at,
            reason: event.rationale.clone(),
        })
        .collect::<Vec<_>>();
    let acknowledgers_truncated =
        acknowledgements.len() > MAX_OVERLAY_ACKNOWLEDGERS || events_truncated;

    if is_closed_state(state) {
        let closed_by = episode
            .iter()
            .rev()
            .find(|event| is_closed_state(&event.kind) && event.result_revision == revision)
            .map(|event| ClosureView {
                actor_kind: event.actor_kind.clone(),
                actor: event.actor.clone(),
                operation: event.operation.clone(),
                reason_kind: event.reason_kind.clone(),
                at: event.created_at,
            });
        return ConflictLifecycleOverlay {
            state: state.to_owned(),
            read_side: "clear".into(),
            episode_revision,
            acknowledged_by,
            acknowledgers_truncated,
            waiver: None,
            closed_unlogged: closed_by.is_none(),
            closed_by,
            evaluated_at,
        };
    }

    let waiver = episode
        .iter()
        .rev()
        .find(|event| event.kind == "waived")
        .and_then(|event| {
            let expires_at = event.expires_at?;
            let void_reason = if expires_at <= evaluated_at {
                Some("expired")
            } else if event.member_count != member_count {
                Some("membership_changed")
            } else {
                None
            };
            let active = void_reason.is_none();
            Some(WaiverView {
                actor: event.actor.clone(),
                reason_kind: event.reason_kind.clone(),
                rationale: event.rationale.as_deref().map(|rationale| {
                    rationale
                        .chars()
                        .take(MAX_OVERLAY_RATIONALE_CHARS)
                        .collect()
                }),
                expires_at,
                review_by: event.review_by,
                review_due: active && event.review_by.is_some_and(|at| at <= evaluated_at),
                member_count: event.member_count,
                active,
                void_reason: void_reason.map(str::to_owned),
            })
        });
    let waiver_active = waiver.as_ref().is_some_and(|waiver| waiver.active);
    let overlay_state = if waiver_active {
        "waived"
    } else if acknowledged_by.is_empty() {
        "open"
    } else {
        "acknowledged"
    };
    ConflictLifecycleOverlay {
        state: overlay_state.into(),
        read_side: if waiver_active { "waived" } else { "open" }.into(),
        episode_revision,
        acknowledged_by,
        acknowledgers_truncated,
        waiver,
        closed_by: None,
        closed_unlogged: false,
        evaluated_at,
    }
}

/// The revision ranges a conflict passed through without a logged event.
///
/// A conflict is created open at revision 1. Each logged event starts at its
/// `episode_revision` and leaves `result_revision`; a later event, or the
/// current row, at a higher revision means something unlogged moved the
/// conflict in between (a reopen by `record`, or a close from before the
/// lifecycle log). `events` are in `seq` order; `complete` is false when the
/// history was truncated, so no trailing gap can be inferred.
#[must_use]
pub fn unlogged_transitions(
    events: &[ConflictLifecycleEvent],
    current_revision: i64,
    complete: bool,
) -> Vec<RevisionGap> {
    let mut gaps = Vec::new();
    let mut cursor = 1_i64;
    for event in events {
        if event.episode_revision > cursor {
            gaps.push(RevisionGap {
                from_revision: cursor,
                to_revision: event.episode_revision,
            });
        }
        cursor = cursor.max(event.result_revision);
    }
    if complete && current_revision > cursor {
        gaps.push(RevisionGap {
            from_revision: cursor,
            to_revision: current_revision,
        });
    }
    gaps
}

/// Canonical idempotency identity for a lifecycle mutation. It binds the
/// operation, the trusted scope (including the session, as record does), and
/// the canonical typed arguments.
pub fn lifecycle_request_identity(action: &str, scope: &FleetScope, input: &Value) -> Value {
    json!({
        "action": action,
        "scope": {
            "project": scope.project,
            "agent": scope.agent,
            "session_id": scope.session_id,
            "privacy_tier": scope.privacy_tier,
        },
        "input": input,
    })
}

/// A lifecycle audit note is 1..=1000 characters of visible text with no
/// control characters other than newline and tab.
pub fn validate_reason(reason: &str) -> std::result::Result<(), String> {
    if reason.is_empty() || reason.chars().count() > MAX_LIFECYCLE_REASON_CHARS {
        return Err(format!(
            "reason must be between 1 and {MAX_LIFECYCLE_REASON_CHARS} characters"
        ));
    }
    if is_blank_rationale(reason) {
        return Err("reason must contain visible text".into());
    }
    if reason
        .chars()
        .any(|character| character.is_control() && !matches!(character, '\n' | '\t'))
    {
        return Err("reason must not contain control characters other than newline and tab".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use ostk_recall_core::PrivacyTier;
    use uuid::Uuid;

    use super::*;
    use crate::ledger::{Claim, ClaimInput, claims_are_incompatible};

    fn locked(id: i64, value: Value, polarity: i16) -> LockedKeyClaim {
        LockedKeyClaim {
            id,
            state: ClaimState::Active,
            origin: OPERATOR_ASSERTED_ORIGIN.into(),
            actor: Some("agent-a".into()),
            revision: 1,
            polarity,
            valid_from: None,
            valid_to: None,
            conflict_eligible: true,
            value: Some(value),
        }
    }

    fn as_claim(locked: &LockedKeyClaim) -> Claim {
        let now = Utc::now();
        Claim {
            id: locked.id,
            project: "project".into(),
            kind: ClaimKind::Decision,
            claim_key: Some("fleet::database".into()),
            subject: Some("fleet".into()),
            predicate: Some("database".into()),
            value: locked.value.clone(),
            text: "fixture".into(),
            polarity: locked.polarity,
            state: locked.state,
            origin: locked.origin.clone(),
            actor: locked.actor.clone(),
            confidence: 1.0,
            valid_from: locked.valid_from,
            valid_to: locked.valid_to,
            superseded_by: None,
            revision: locked.revision,
            conflict_eligible: locked.conflict_eligible,
            created_at: now,
            updated_at: now,
            support: Vec::new(),
            conflict_ids: Vec::new(),
        }
    }

    fn open_lineage() -> V2Lineage {
        V2Lineage {
            id: 9,
            state: ConflictRowState::Open,
            revision: 3,
        }
    }

    #[test]
    fn owner_transition_refusals_are_typed() {
        let owned = locked(41, json!("x"), 1);
        assert!(check_owner_transition(&owned, "agent-a", 1).is_ok());
        let mut disputed = owned.clone();
        disputed.state = ClaimState::Disputed;
        disputed.revision = 2;
        assert!(check_owner_transition(&disputed, "agent-a", 2).is_ok());

        let mut unattributed = owned.clone();
        unattributed.actor = None;
        for (claim, agent) in [(&unattributed, "agent-a"), (&owned, "agent-b")] {
            let refusal = check_owner_transition(claim, agent, 1).unwrap_err();
            assert_eq!(refusal.code, RefusalCode::NotOwner);
            assert_eq!(refusal.details["claim_id"], 41);
        }

        for origin in ["source_derived", "legacy_unverified"] {
            let mut derived = owned.clone();
            derived.origin = origin.into();
            let refusal = check_owner_transition(&derived, "agent-a", 1).unwrap_err();
            assert_eq!(refusal.code, RefusalCode::NotOperatorAsserted);
            assert_eq!(refusal.details["origin"], origin);
        }

        for state in [
            ClaimState::Unsupported,
            ClaimState::Superseded,
            ClaimState::Retracted,
            ClaimState::Suppressed,
            ClaimState::Expired,
        ] {
            let mut retired = owned.clone();
            retired.state = state;
            // A retired claim is reported as not current even with a matching
            // revision, so a caller never retries a revision it cannot fix.
            let refusal = check_owner_transition(&retired, "agent-a", 1).unwrap_err();
            assert_eq!(refusal.code, RefusalCode::NotCurrent);
            assert_eq!(refusal.details["current_state"], state.as_str());
        }

        let refusal = check_owner_transition(&disputed, "agent-a", 1).unwrap_err();
        assert_eq!(refusal.code, RefusalCode::StaleRevision);
        assert_eq!(refusal.details["current_revision"], 2);
        assert_eq!(refusal.details["current_state"], "disputed");
        assert_eq!(
            refusal.to_string(),
            "stale_revision: claim 41 is at revision 2 (disputed)"
        );
    }

    #[test]
    fn incompatible_pairs_match_claims_are_incompatible() {
        let at = Utc::now();
        let mut fixtures = vec![
            locked(1, json!("x"), 1),
            locked(2, json!("y"), 1),
            locked(3, json!("x"), -1),
            locked(4, json!("y"), -1),
            locked(5, json!(1), 1),
            locked(6, json!(1.0), 1),
            locked(7, json!({"a": 1, "b": [1, [2, 3]]}), 1),
            locked(8, json!({"b": [1, [2, 3]], "a": 1}), 1),
            locked(9, json!([1, [3, 2]]), 1),
        ];
        let mut touching_left = locked(10, json!("early"), 1);
        touching_left.valid_to = Some(at);
        let mut touching_right = locked(11, json!("late"), 1);
        touching_right.valid_from = Some(at);
        let mut ineligible = locked(12, json!("z"), 1);
        ineligible.conflict_eligible = false;
        let mut retired = locked(13, json!("w"), 1);
        retired.state = ClaimState::Retracted;
        fixtures.extend([touching_left, touching_right, ineligible, retired]);

        let pairs = incompatible_pairs(&fixtures)
            .into_iter()
            .collect::<BTreeSet<_>>();
        let mut expected = BTreeSet::new();
        for (index, left) in fixtures.iter().enumerate() {
            for right in &fixtures[index + 1..] {
                if claims_are_incompatible(&as_claim(left), &as_claim(right)) {
                    expected.insert((left.id.min(right.id), left.id.max(right.id)));
                }
            }
        }
        assert_eq!(pairs, expected);

        // Spot-check the polarity matrix and value semantics directly.
        assert!(pairs.contains(&(1, 2)), "+x/+y conflict");
        assert!(pairs.contains(&(1, 3)), "+x/-x conflict");
        assert!(!pairs.contains(&(3, 4)), "-x/-y is compatible");
        assert!(!pairs.contains(&(1, 4)), "+x/-y is compatible");
        assert!(
            !pairs.contains(&(5, 6)),
            "1 and 1.0 are the same JSON number"
        );
        assert!(!pairs.contains(&(7, 8)), "object key order is irrelevant");
        assert!(pairs.contains(&(7, 9)), "nested array order matters");
        assert!(!pairs.contains(&(10, 11)), "half-open windows only touch");
        assert!(
            pairs
                .iter()
                .all(|(left, right)| *left != 12 && *right != 12)
        );
        assert!(
            pairs
                .iter()
                .all(|(left, right)| *left != 13 && *right != 13)
        );
    }

    #[test]
    fn reevaluation_plans() {
        let x = locked(1, json!("x"), 1);
        let mut y = locked(2, json!("y"), 1);
        y.state = ClaimState::Disputed;
        let mut z = locked(3, json!("z"), 1);
        z.state = ClaimState::Disputed;
        let lineage = Some(open_lineage());

        // Two-party x vs y: retracting x leaves only y, which is restorable.
        assert_eq!(
            plan_reevaluation(lineage, std::slice::from_ref(&y), &[]),
            Reevaluation::Close {
                conflict_id: 9,
                revision: 3,
                restore_candidates: vec![2],
            }
        );

        // Three-way x/y/z: retracting x leaves y vs z open.
        assert_eq!(
            plan_reevaluation(lineage, &[y.clone(), z.clone()], &[(3, 2)]),
            Reevaluation::StillOpen {
                conflict_id: 9,
                revision: 3,
                pairs: vec![(2, 3)],
            }
        );

        // +x/-x/+y: retracting +x leaves -x and +y, which are compatible.
        let negative_x = locked(4, json!("x"), -1);
        let positive_y = locked(5, json!("y"), 1);
        assert!(!incompatible_pairs(&[x, negative_x.clone(), positive_y.clone()]).is_empty());
        assert!(matches!(
            plan_reevaluation(lineage, &[negative_x.clone(), positive_y.clone()], &[]),
            Reevaluation::Close { .. }
        ));

        assert_eq!(
            plan_reevaluation(None, std::slice::from_ref(&y), &[]),
            Reevaluation::NoLineage
        );
        for state in [ConflictRowState::Resolved, ConflictRowState::Dismissed] {
            let closed = Some(V2Lineage {
                state,
                ..open_lineage()
            });
            assert_eq!(
                plan_reevaluation(closed, std::slice::from_ref(&y), &[]),
                Reevaluation::NotOpen
            );
        }

        // The database found a pair Rust did not: nothing may close.
        assert_eq!(
            plan_reevaluation(lineage, &[negative_x, positive_y], &[(4, 5)]),
            Reevaluation::Divergent {
                conflict_id: 9,
                revision: 3,
                rust_pairs: Vec::new(),
                sql_pairs: vec![(4, 5)],
            }
        );
        // And Rust found a pair the database did not.
        assert!(matches!(
            plan_reevaluation(lineage, &[y, z], &[]),
            Reevaluation::Divergent { .. }
        ));
    }

    fn claim_input(kind: ClaimKind, subject: Option<&str>, value: Option<Value>) -> ClaimInput {
        ClaimInput {
            kind,
            text: "successor fixture".into(),
            subject: subject.map(str::to_owned),
            predicate: subject.map(|_| "Database".to_owned()),
            value,
            polarity: 1,
            origin: OPERATOR_ASSERTED_ORIGIN.into(),
            actor: None,
            confidence: 1.0,
            valid_from: None,
            valid_to: None,
            support: Vec::new(),
        }
    }

    /// The shape `record` would give this input, as the successor check sees it.
    fn shape_of(input: &ClaimInput) -> ClaimShape {
        let prepared = input.prepare().unwrap();
        ClaimShape {
            kind: input.kind,
            claim_key: prepared.claim_key,
            conflict_eligible: prepared.conflict_eligible,
        }
    }

    #[test]
    fn successor_must_keep_kind_key_and_eligibility() {
        let predecessor = shape_of(&claim_input(
            ClaimKind::Decision,
            Some("fleet-memory"),
            Some(json!("cockroachdb")),
        ));
        assert_eq!(
            predecessor.claim_key.as_deref(),
            Some("fleet-memory::database")
        );

        // A new value, and spelling that normalizes to the same key, are fine.
        let respelled = claim_input(
            ClaimKind::Decision,
            Some("  Fleet   Memory "),
            Some(json!({"engine": "cockroachdb", "version": 26})),
        );
        assert!(check_successor(41, &predecessor, &shape_of(&respelled)).is_ok());
        // A keyless note may be replaced by another keyless note.
        let note = shape_of(&claim_input(ClaimKind::Note, None, None));
        assert!(check_successor(41, &note, &note.clone()).is_ok());
        // A keyed note carries no value, so it stays outside the detector.
        let keyed_note = shape_of(&claim_input(ClaimKind::Note, Some("fleet-memory"), None));
        assert!(!keyed_note.conflict_eligible);
        assert!(check_successor(41, &keyed_note, &keyed_note.clone()).is_ok());

        let refused = |successor: &ClaimInput| {
            check_successor(41, &predecessor, &shape_of(successor)).unwrap_err()
        };
        let kind = refused(&claim_input(
            ClaimKind::Fact,
            Some("fleet-memory"),
            Some(json!("x")),
        ));
        assert_eq!(kind.code, RefusalCode::SuccessorKindMismatch);
        assert_eq!(kind.details["kind"], "decision");
        assert_eq!(kind.details["successor_kind"], "fact");

        let moved = refused(&claim_input(
            ClaimKind::Decision,
            Some("fleet-store"),
            Some(json!("x")),
        ));
        assert_eq!(moved.code, RefusalCode::SuccessorKeyMismatch);
        assert_eq!(moved.details["claim_key"], "fleet-memory::database");
        assert_eq!(
            moved.details["successor_claim_key"],
            "fleet-store::database"
        );
        let unkeyed = refused(&claim_input(ClaimKind::Decision, None, Some(json!("x"))));
        assert_eq!(unkeyed.code, RefusalCode::SuccessorKeyMismatch);
        assert_eq!(unkeyed.details["successor_claim_key"], Value::Null);

        // Dropping the value would take the key out of the detector's view.
        let valueless = refused(&claim_input(
            ClaimKind::Decision,
            Some("fleet-memory"),
            None,
        ));
        assert_eq!(valueless.code, RefusalCode::SuccessorEligibilityMismatch);
        assert_eq!(valueless.details["conflict_eligible"], true);
        assert_eq!(valueless.details["successor_conflict_eligible"], false);
        // And adding one would bring an unchecked key into it.
        let entering = check_successor(
            41,
            &shape_of(&claim_input(
                ClaimKind::Decision,
                Some("fleet-memory"),
                None,
            )),
            &predecessor,
        )
        .unwrap_err();
        assert_eq!(entering.code, RefusalCode::SuccessorEligibilityMismatch);
    }

    #[test]
    fn successor_value_matters_only_where_it_changes_eligibility() {
        let value = || Some(json!("cockroachdb"));
        // Outside the detector a successor may add or drop a value: neither
        // side is conflict-eligible, so nothing leaves or enters its view.
        for kind in [
            ClaimKind::Note,
            ClaimKind::Observation,
            ClaimKind::OpenQuestion,
        ] {
            let with = shape_of(&claim_input(kind, Some("fleet-memory"), value()));
            let without = shape_of(&claim_input(kind, Some("fleet-memory"), None));
            assert!(check_successor(41, &with, &without).is_ok(), "{kind:?}");
            assert!(check_successor(41, &without, &with).is_ok(), "{kind:?}");
        }
        for kind in [
            ClaimKind::Decision,
            ClaimKind::Fact,
            ClaimKind::Constraint,
            ClaimKind::Preference,
            ClaimKind::Procedure,
        ] {
            let keyless_with = shape_of(&claim_input(kind, None, value()));
            let keyless_without = shape_of(&claim_input(kind, None, None));
            assert!(check_successor(41, &keyless_with, &keyless_without).is_ok());
            assert!(check_successor(41, &keyless_without, &keyless_with).is_ok());

            // A keyed claim of a detector kind keeps its value presence.
            let with = shape_of(&claim_input(kind, Some("fleet-memory"), value()));
            let without = shape_of(&claim_input(kind, Some("fleet-memory"), None));
            for (predecessor, successor) in [(&with, &without), (&without, &with)] {
                assert_eq!(
                    check_successor(41, predecessor, successor)
                        .unwrap_err()
                        .code,
                    RefusalCode::SuccessorEligibilityMismatch,
                    "{kind:?}"
                );
            }
        }
    }

    #[test]
    fn classify_lineages_matches_write_probe_rules() {
        let v2 = (9, V2_DETECTOR_CLASS, "open".to_owned(), 3);
        let legacy = (4, LEGACY_DETECTOR_CLASS, "open".to_owned(), 1);

        assert_eq!(classify_lineages(&[]).unwrap(), None);
        assert_eq!(
            classify_lineages(std::slice::from_ref(&v2)).unwrap(),
            Some(open_lineage())
        );
        assert_eq!(
            classify_lineages(&[v2.clone(), legacy.clone()]).unwrap(),
            Some(open_lineage())
        );

        let Err(FleetError::LifecycleRefused(refusal)) =
            classify_lineages(std::slice::from_ref(&legacy))
        else {
            panic!("a legacy-only key must be refused, not failed");
        };
        assert_eq!(refusal.code, RefusalCode::LegacyLineage);

        for corrupt in [
            vec![v2.clone(), v2.clone()],
            vec![legacy.clone(), legacy.clone()],
            vec![(5, UNKNOWN_DETECTOR_CLASS, "open".to_owned(), 1)],
            vec![(5, 7, "open".to_owned(), 1)],
            vec![
                v2,
                legacy,
                (5, UNKNOWN_DETECTOR_CLASS, "open".to_owned(), 1),
            ],
            vec![(9, V2_DETECTOR_CLASS, "archived".to_owned(), 3)],
        ] {
            assert!(
                matches!(classify_lineages(&corrupt), Err(FleetError::Memory(_))),
                "{corrupt:?} must be a protocol error"
            );
        }
    }

    #[test]
    fn request_identity_includes_action_scope_session_input() {
        let scope = FleetScope::new(
            Uuid::from_u128(1),
            "project",
            "agent-a",
            Some("turn-7".into()),
            PrivacyTier::T1Project,
        )
        .unwrap();
        let input = json!({ "claim_id": 41, "expected_revision": 2, "reason": null });
        let identity = lifecycle_request_identity("retract", &scope, &input);
        assert_eq!(identity["action"], "retract");
        assert_eq!(identity["scope"]["project"], "project");
        assert_eq!(identity["scope"]["agent"], "agent-a");
        assert_eq!(identity["scope"]["session_id"], "turn-7");
        assert_eq!(identity["scope"]["privacy_tier"], "t1_project");
        assert_eq!(identity["input"], input);
        assert!(identity.get("tenant_id").is_none());

        let other_session = FleetScope::new(
            scope.tenant_id,
            "project",
            "agent-a",
            Some("turn-8".into()),
            PrivacyTier::T1Project,
        )
        .unwrap();
        assert_ne!(
            lifecycle_request_identity("retract", &other_session, &input),
            identity
        );
        assert_ne!(
            lifecycle_request_identity("supersede", &scope, &input),
            identity
        );
    }

    #[test]
    fn reasons_are_bounded_visible_text() {
        assert!(validate_reason("wrong value; see ticket 12").is_ok());
        assert!(validate_reason("line one\nline two\tindented").is_ok());
        assert!(validate_reason(&"x".repeat(MAX_LIFECYCLE_REASON_CHARS)).is_ok());
        // The bound counts characters, as the tool schema's maxLength does:
        // 1000 three-byte CJK characters are 3000 bytes and still valid.
        assert!(validate_reason(&"\u{7406}".repeat(MAX_LIFECYCLE_REASON_CHARS)).is_ok());
        for rejected in [
            String::new(),
            " \n\t ".into(),
            "\u{200B}\u{FEFF}".into(),
            "x".repeat(MAX_LIFECYCLE_REASON_CHARS + 1),
            "\u{7406}".repeat(MAX_LIFECYCLE_REASON_CHARS + 1),
            "bell\u{7}".into(),
            "carriage\rreturn".into(),
        ] {
            assert!(validate_reason(&rejected).is_err(), "{rejected:?}");
        }
    }

    fn owned(id: i64, actor: &str, value: &str, state: ClaimState) -> LockedKeyClaim {
        LockedKeyClaim {
            actor: Some(actor.into()),
            state,
            revision: 4,
            ..locked(id, json!(value), 1)
        }
    }

    #[test]
    fn plan_concession_refusals() {
        let mine = owned(41, "agent-a", "x", ClaimState::Disputed);
        let theirs = owned(42, "agent-b", "y", ClaimState::Disputed);
        let third = owned(43, "agent-c", "z", ClaimState::Disputed);
        let current = vec![mine.clone(), theirs.clone(), third.clone()];
        let members = [
            (41, ClaimState::Disputed, 4),
            (42, ClaimState::Disputed, 4),
            (44, ClaimState::Retracted, 5),
        ];

        let concession = plan_concession(9, "agent-a", &[41], &members, current.clone()).unwrap();
        assert_eq!(concession.retracted, std::slice::from_ref(&mine));
        assert_eq!(concession.remaining, [theirs.clone(), third.clone()]);
        // Re-verification alone retracts nothing.
        let verify = plan_concession(9, "agent-a", &[], &[], current.clone()).unwrap();
        assert!(verify.retracted.is_empty());
        assert_eq!(verify.remaining.len(), 3);

        let refused = |ids: &[i64], agent: &str| match plan_concession(
            9,
            agent,
            ids,
            &members,
            current.clone(),
        ) {
            Err(FleetError::LifecycleRefused(refusal)) => *refusal,
            other => panic!("expected a refusal, got {other:?}"),
        };
        // Another agent's member is never retracted on its behalf (DISC-03).
        let not_owner = refused(&[41, 42], "agent-a");
        assert_eq!(not_owner.code, RefusalCode::NotOwner);
        assert_eq!(not_owner.details["claim_id"], 42);
        // A current claim on the key that is not in this conflict.
        let not_member = refused(&[43], "agent-c");
        assert_eq!(not_member.code, RefusalCode::NotMember);
        assert_eq!(
            not_member.details,
            json!({ "conflict_id": 9, "claim_id": 43 })
        );
        // A member that is no longer current.
        let not_current = refused(&[44], "agent-a");
        assert_eq!(not_current.code, RefusalCode::NotCurrent);
        assert_eq!(not_current.details["current_state"], "retracted");
        assert_eq!(not_current.details["current_revision"], 5);
        // Ownership also requires an operator assertion.
        let mut derived = mine;
        derived.origin = "source_derived".into();
        let refusal =
            plan_concession(9, "agent-a", &[41], &members, vec![derived, theirs]).unwrap_err();
        assert!(matches!(
            refusal,
            FleetError::LifecycleRefused(refusal) if refusal.code == RefusalCode::NotOperatorAsserted
        ));
        // A current member missing from its key's locked claims is corruption.
        assert!(matches!(
            plan_concession(9, "agent-a", &[41], &members, vec![third]),
            Err(FleetError::Memory(_))
        ));
    }

    #[test]
    fn concession_verification_is_the_detector_verdict() {
        let lineage = Some(open_lineage());
        let x = owned(41, "agent-a", "x", ClaimState::Disputed);
        let y = owned(42, "agent-b", "y", ClaimState::Disputed);
        let z = owned(43, "agent-c", "z", ClaimState::Disputed);
        let members = [
            (41, ClaimState::Disputed, 4),
            (42, ClaimState::Disputed, 4),
            (43, ClaimState::Disputed, 4),
        ];
        // Two-party: conceding x leaves y alone, so the detector closes.
        let two =
            plan_concession(9, "agent-a", &[41], &members, vec![x.clone(), y.clone()]).unwrap();
        assert!(matches!(
            plan_reevaluation(lineage, &two.remaining, &[]),
            Reevaluation::Close { ref restore_candidates, .. } if *restore_candidates == [42]
        ));
        // Three-way: y and z still disagree, so the concession is refused.
        let three = plan_concession(9, "agent-a", &[41], &members, vec![x, y, z]).unwrap();
        let Reevaluation::StillOpen { pairs, .. } =
            plan_reevaluation(lineage, &three.remaining, &[(42, 43)])
        else {
            panic!("y and z keep the conflict open");
        };
        assert_eq!(pairs, [(42, 43)]);
    }

    fn event(seq: i64, kind: &str, episode: i64, actor: &str) -> ConflictLifecycleEvent {
        let at = DateTime::parse_from_rfc3339("2026-09-24T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let closes = matches!(kind, "resolved" | "dismissed");
        ConflictLifecycleEvent {
            seq,
            kind: kind.into(),
            actor_kind: if kind == "resolved" {
                "detector"
            } else {
                "agent"
            }
            .into(),
            actor: actor.into(),
            operation: match kind {
                "acknowledged" => "conflict_acknowledge",
                "waived" => "conflict_waive",
                "dismissed" => "conflict_dismiss",
                _ => "retract",
            }
            .into(),
            episode_revision: episode,
            result_revision: episode + i64::from(closes),
            reason_kind: None,
            rationale: Some(format!("{actor} note")),
            expires_at: None,
            review_by: None,
            member_count: 2,
            created_at: at + chrono::Duration::seconds(seq),
            payload: None,
            payload_elided: false,
        }
    }

    fn waiver(
        seq: i64,
        episode: i64,
        expires_at: DateTime<Utc>,
        members: i64,
    ) -> ConflictLifecycleEvent {
        ConflictLifecycleEvent {
            expires_at: Some(expires_at),
            member_count: members,
            reason_kind: Some("capacity_deferred".into()),
            ..event(seq, "waived", episode, "agent-c")
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)] // one table of overlay rules
    fn derive_overlay_rules() {
        let now = DateTime::parse_from_rfc3339("2026-09-24T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let later = now + chrono::Duration::hours(1);
        let earlier = now - chrono::Duration::hours(1);

        // No events: open, read side open.
        let open = derive_overlay("open", 3, 2, &[], false, now);
        assert_eq!(
            (open.state.as_str(), open.read_side.as_str()),
            ("open", "open")
        );
        assert_eq!(open.episode_revision, 3);
        assert_eq!(open.evaluated_at, now);

        // Acknowledgement is triage only: it never changes the read side.
        let acks = [
            event(1, "acknowledged", 3, "agent-a"),
            event(2, "acknowledged", 3, "agent-b"),
        ];
        let acknowledged = derive_overlay("open", 3, 2, &acks, false, now);
        assert_eq!(acknowledged.state, "acknowledged");
        assert_eq!(acknowledged.read_side, "open");
        assert_eq!(
            acknowledged
                .acknowledged_by
                .iter()
                .map(|ack| (ack.actor.as_str(), ack.reason.as_deref()))
                .collect::<Vec<_>>(),
            [
                ("agent-a", Some("agent-a note")),
                ("agent-b", Some("agent-b note"))
            ]
        );
        assert!(!acknowledged.acknowledgers_truncated);

        // Events of an older episode (before a reopen) are ignored.
        let stale = derive_overlay("open", 5, 2, &acks, false, now);
        assert_eq!(stale.state, "open");
        assert!(stale.acknowledged_by.is_empty());

        // An active waiver reads waived; review becomes due at review_by.
        let mut active = waiver(3, 3, later, 2);
        active.review_by = Some(earlier);
        let mut events = acks.to_vec();
        events.push(active);
        let waived = derive_overlay("open", 3, 2, &events, false, now);
        assert_eq!(
            (waived.state.as_str(), waived.read_side.as_str()),
            ("waived", "waived")
        );
        let view = waived.waiver.unwrap();
        assert!(view.active && view.review_due);
        assert_eq!(view.void_reason, None);

        // An expired waiver reads open again, keeping its context.
        let expired = derive_overlay("open", 3, 2, &[waiver(1, 3, earlier, 2)], false, now);
        assert_eq!(
            (expired.state.as_str(), expired.read_side.as_str()),
            ("open", "open")
        );
        let view = expired.waiver.unwrap();
        assert!(!view.active);
        assert_eq!(view.void_reason.as_deref(), Some("expired"));
        // A waiver ends exactly at its expiry.
        let boundary = derive_overlay("open", 3, 2, &[waiver(1, 3, now, 2)], false, now);
        assert_eq!(
            boundary.waiver.unwrap().void_reason.as_deref(),
            Some("expired")
        );

        // A member joined after the waiver: it no longer covers the conflict.
        let joined = derive_overlay("open", 3, 3, &[waiver(1, 3, later, 2)], false, now);
        assert_eq!(joined.state, "open");
        assert_eq!(
            joined.waiver.unwrap().void_reason.as_deref(),
            Some("membership_changed")
        );
        // Only the latest waiver counts.
        let replaced = derive_overlay(
            "open",
            3,
            2,
            &[waiver(1, 3, later, 2), waiver(2, 3, earlier, 2)],
            false,
            now,
        );
        assert_eq!(replaced.state, "open");

        // Closed rows read clear and name their logged close.
        let mut close = event(3, "resolved", 3, "same_key_functional_value_v2");
        close.reason_kind = Some("no_current_incompatibility".into());
        let mut closed_events = acks.to_vec();
        closed_events.push(close);
        let resolved = derive_overlay("resolved", 4, 2, &closed_events, false, now);
        assert_eq!(
            (resolved.state.as_str(), resolved.read_side.as_str()),
            ("resolved", "clear")
        );
        assert_eq!(resolved.episode_revision, 3);
        let closed_by = resolved.closed_by.unwrap();
        assert_eq!(closed_by.actor_kind, "detector");
        assert_eq!(closed_by.operation, "retract");
        assert_eq!(
            closed_by.reason_kind.as_deref(),
            Some("no_current_incompatibility")
        );
        assert!(!resolved.closed_unlogged);
        assert!(resolved.waiver.is_none());
        assert_eq!(resolved.acknowledged_by.len(), 2);
        // A close before the lifecycle log existed is reported as unlogged.
        let unlogged = derive_overlay("resolved", 2, 2, &[], false, now);
        assert_eq!(unlogged.read_side, "clear");
        assert!(unlogged.closed_unlogged && unlogged.closed_by.is_none());
        let dismissed = derive_overlay("dismissed", 4, 2, &[], false, now);
        assert_eq!(
            (dismissed.state.as_str(), dismissed.read_side.as_str()),
            ("dismissed", "clear")
        );

        // More acknowledgers than the overlay lists are reported, not dropped
        // silently, and so is an episode with more events than were read.
        let many = (1..=17)
            .map(|seq| event(seq, "acknowledged", 3, &format!("agent-{seq}")))
            .collect::<Vec<_>>();
        let crowded = derive_overlay("open", 3, 2, &many, false, now);
        assert_eq!(crowded.acknowledged_by.len(), MAX_OVERLAY_ACKNOWLEDGERS);
        assert_eq!(crowded.acknowledged_by[0].actor, "agent-1");
        assert!(crowded.acknowledgers_truncated);
        assert!(derive_overlay("open", 3, 2, &acks, true, now).acknowledgers_truncated);
    }

    #[test]
    fn unlogged_transition_gaps() {
        let gap = |from_revision, to_revision| RevisionGap {
            from_revision,
            to_revision,
        };
        // Created open at 1, acknowledged and closed by a logged retract.
        let logged = [
            event(1, "acknowledged", 1, "agent-a"),
            event(2, "resolved", 1, "same_key_functional_value_v2"),
        ];
        assert!(unlogged_transitions(&logged, 2, true).is_empty());
        // record reopened it (2 -> 3): an unlogged transition.
        assert_eq!(unlogged_transitions(&logged, 3, true), [gap(2, 3)]);
        // A truncated history cannot see its own tail.
        assert!(unlogged_transitions(&logged, 3, false).is_empty());
        // An unlogged close and reopen before the first logged event.
        let later = [
            event(1, "acknowledged", 3, "agent-a"),
            event(2, "resolved", 3, "same_key_functional_value_v2"),
            event(3, "acknowledged", 5, "agent-b"),
        ];
        assert_eq!(
            unlogged_transitions(&later, 5, true),
            [gap(1, 3), gap(4, 5)]
        );
        // No log at all: every revision after creation is unlogged.
        assert_eq!(unlogged_transitions(&[], 3, true), [gap(1, 3)]);
        assert!(unlogged_transitions(&[], 1, true).is_empty());
    }

    #[test]
    fn refusal_codes_serialize_as_their_wire_names() {
        for code in [
            RefusalCode::NotFound,
            RefusalCode::NotOwner,
            RefusalCode::NotOperatorAsserted,
            RefusalCode::NotCurrent,
            RefusalCode::StaleRevision,
            RefusalCode::StaleMemberCount,
            RefusalCode::NotOpen,
            RefusalCode::LegacyLineage,
            RefusalCode::SuccessorKindMismatch,
            RefusalCode::SuccessorKeyMismatch,
            RefusalCode::SuccessorEligibilityMismatch,
            RefusalCode::NotMember,
            RefusalCode::StillIncompatible,
            RefusalCode::VerificationDivergence,
            RefusalCode::Implicated,
            RefusalCode::UnattributedMember,
            RefusalCode::BoundExceeded,
            RefusalCode::LifecycleUnavailable,
            RefusalCode::AdjudicationDisabled,
        ] {
            assert_eq!(serde_json::to_value(code).unwrap(), json!(code.as_str()));
        }
    }
}
