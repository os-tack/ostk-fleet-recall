//! Pure planning for the serving claim/conflict lifecycle (ADR 0004).
//!
//! Every decision a lifecycle transaction makes after it has locked its rows
//! lives here, free of I/O: owner authority over a locked claim, the functional
//! incompatibility graph over the locked lifecycle-current claims of one key,
//! and whether the key's v2 conflict may be closed. The store module only
//! reads, locks, and applies what these functions decide.

use std::fmt;

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{Value, json};

use crate::ledger::{ClaimState, functional_values_are_incompatible, intervals_overlap};
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
    use crate::ledger::{Claim, ClaimKind, claims_are_incompatible};

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
