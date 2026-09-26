//! Pure planning for the serving claim/conflict lifecycle (ADR 0004).
//!
//! Every decision a lifecycle transaction makes after it has locked its rows
//! lives here, free of I/O: owner authority over a locked claim, the functional
//! incompatibility graph over the locked lifecycle-current claims of one key,
//! and whether the key's v2 conflict may be closed. The store module only
//! reads, locks, and applies what these functions decide.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{Value, json};

use crate::ledger::{
    Acknowledgement, ClaimKind, ClaimState, ClosureView, ConflictHistory, ConflictLifecycleEvent,
    ConflictLifecycleOverlay, RevisionGap, WaiverView, claim_key_from_parts,
    functional_values_are_incompatible, intervals_overlap,
};
use crate::memory_contracts::discrepancy::{
    DismissalReasonKindV1, MAX_RATIONALE_BYTES, WaiverReasonKindV1, is_blank_rationale,
};
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
/// Durable members a lifecycle event can record; the lifecycle log's CHECK
/// admits no more.
pub const MAX_CONFLICT_MEMBER_COUNT: i64 = 4_096;
/// Events one conflict's lifecycle log may hold (its `event_seq` CHECK).
pub const MAX_CONFLICT_LIFECYCLE_EVENTS: i64 = 4_096;
/// Events the overlay reads per episode, newest first; one more is fetched
/// as a sentinel.
pub const MAX_OVERLAY_EPISODE_EVENTS: usize = 32;
/// Acknowledgers the overlay lists; the rest are reported as truncated.
pub const MAX_OVERLAY_ACKNOWLEDGERS: usize = 16;
/// The newest events `recall(get, kind=conflict)` reads as history; one more
/// is fetched as a sentinel.
pub const MAX_HISTORY_EVENTS: usize = 256;
/// Characters of a waiver rationale the overlay echoes.
const MAX_OVERLAY_RATIONALE_CHARS: usize = 1_000;
/// Upper bound, in Unicode characters, on a dismissal or waiver rationale.
///
/// It counts characters as the advertised JSON Schema `maxLength` does, and
/// 1,000 characters of at most four bytes each stay within the contract's
/// 4,096-byte rationale bound and the lifecycle log's CHECK.
pub const MAX_ADJUDICATION_RATIONALE_CHARS: usize = 1_000;
/// Longest waiver, and latest review, in hours (90 days).
pub const MAX_WAIVER_HOURS: u16 = 2_160;
/// Incompatible pairs one dismissal may record.
pub const MAX_DISMISSED_PAIRS: usize = 1_024;
/// The newest dismissals of a conflict whose pairs re-evaluation excludes.
/// Older ones are ignored: fewer exclusions only keep a conflict open.
pub const MAX_EXCLUDED_DISMISSALS: usize = 64;

const V2_DETECTOR_CLASS: i64 = 2;
const LEGACY_DETECTOR_CLASS: i64 = 1;
const UNKNOWN_DETECTOR_CLASS: i64 = 0;

/// Closed vocabulary for a refused lifecycle or assert mutation.
///
/// A refusal is decided before commit, so the whole transaction (including
/// the idempotency reservation) rolls back and the key stays free. The
/// `remember(action="assert")` codes, from `AssertUnavailable` on, refuse
/// before or inside the event-first append transaction, so a refused assert
/// writes neither its accepted event nor its claim projection.
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
    /// This writer does not serve the event-first assert: no writer-authority
    /// pins are configured, or they did not verify at startup.
    AssertUnavailable,
    /// The pinned writer authority did not verify for this request.
    WriterAuthorityUnavailable,
    /// The active remember route did not admit the assertion; `details.reason`
    /// names which check failed.
    AssertionNotAdmitted,
    /// A support evidence event ID names no accepted event in this scope.
    SupportEventUnknown,
    /// The active registry head moved between admission and append.
    RegistryHeadChanged,
    /// This exact accepted statement is already in the ledger, committed
    /// under another idempotency key.
    AlreadyAsserted,
    /// This writer does not serve agent capture, or the active registry
    /// package does not bind `connector.collected.capture` (ADR 0008 D10).
    CaptureUnavailable,
    /// This writer does not let claims cite collected items: the schema
    /// predates migration 35, its grants are absent, or item recall is not
    /// served (ADR 0008 D11).
    ItemSupportUnavailable,
    /// A cited item, version, or provider URL names no admitted item in this
    /// scope, and nothing staged for it is pending.
    SupportItemUnknown,
    /// A cited item or version is staged but not yet admitted; a drain
    /// (the worker's `collect` step) admits it.
    SupportItemPending,
    /// A cited item is hidden from recall: its presented head is a
    /// tombstone, or its container or the item itself was withdrawn.
    SupportItemWithdrawn,
    /// Two support entries cite one version of one collected item.
    SupportItemDuplicate,
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
            Self::AssertUnavailable => "assert_unavailable",
            Self::WriterAuthorityUnavailable => "writer_authority_unavailable",
            Self::AssertionNotAdmitted => "assertion_not_admitted",
            Self::SupportEventUnknown => "support_event_unknown",
            Self::RegistryHeadChanged => "registry_head_changed",
            Self::AlreadyAsserted => "already_asserted",
            Self::CaptureUnavailable => "capture_unavailable",
            Self::ItemSupportUnavailable => "item_support_unavailable",
            Self::SupportItemUnknown => "support_item_unknown",
            Self::SupportItemPending => "support_item_pending",
            Self::SupportItemWithdrawn => "support_item_withdrawn",
            Self::SupportItemDuplicate => "support_item_duplicate",
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
/// functional key with the stored parts it was built from, and whether the
/// detector compares it at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimShape {
    pub kind: ClaimKind,
    pub claim_key: Option<String>,
    pub subject: Option<String>,
    pub predicate: Option<String>,
    pub conflict_eligible: bool,
}

impl ClaimShape {
    /// The key a successor must carry: the predecessor's stored `subject`
    /// and `predicate` re-normalized under the current rule, so a claim
    /// written under the earlier normalizer (which kept `_`) is superseded
    /// onto the key a fresh record of the same words gets. The parts are
    /// used rather than the joined key, because re-normalizing the string
    /// `a_::b` would give `a-::b` while its parts give `a::b`. A key not
    /// built from parts (an `assert`'s `claim-v2:` key, or a row without
    /// them) must be kept verbatim.
    #[must_use]
    pub fn successor_claim_key(&self) -> Option<String> {
        match (&self.subject, &self.predicate) {
            (Some(subject), Some(predicate)) if !self.has_assert_key() => {
                claim_key_from_parts(subject, predicate)
            }
            _ => self.claim_key.clone(),
        }
    }

    fn has_assert_key(&self) -> bool {
        self.claim_key
            .as_deref()
            .is_some_and(|key| key.starts_with(ASSERT_CLAIM_KEY_PREFIX))
    }
}

/// The prefix of every key `remember(assert)` derives; those keys are never
/// re-normalized from a subject and predicate.
const ASSERT_CLAIM_KEY_PREFIX: &str = "claim-v2:";

/// A successor must keep its predecessor's kind, normalized key, and conflict
/// eligibility, so a supersede can change a claim's value or wording but can
/// never move it out of the detector's view or onto another key. The key is
/// compared as [`ClaimShape::successor_claim_key`] derives it from the stored
/// parts, which is how a legacy `_` key is superseded onto its current form.
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
    let expected_key = predecessor.successor_claim_key();
    if successor.claim_key != expected_key {
        return Err(LifecycleRefusal::new(
            RefusalCode::SuccessorKeyMismatch,
            format!(
                "claim {predecessor_id} has claim_key {} (its subject and predicate normalize to {}); its successor's subject and predicate normalize to {}",
                display_key(predecessor.claim_key.as_deref()),
                display_key(expected_key.as_deref()),
                display_key(successor.claim_key.as_deref())
            ),
            json!({
                "claim_id": predecessor_id,
                "claim_key": predecessor.claim_key,
                "normalized_claim_key": expected_key,
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
    /// Incompatible current pairs that no adjudicator dismissed remain, so
    /// the conflict stays open.
    StillOpen {
        conflict_id: i64,
        revision: i64,
        pairs: Vec<(i64, i64)>,
        /// Current incompatible pairs left out because a dismissal of this
        /// conflict already judged them.
        excluded_pairs: usize,
    },
    /// No incompatible current pair remains beyond those an adjudicator
    /// dismissed: the detector verifies the close. `restore_candidates` are
    /// the remaining disputed claim ids.
    Close {
        conflict_id: i64,
        revision: i64,
        restore_candidates: Vec<i64>,
        excluded_pairs: usize,
    },
    /// The Rust and SQL pair sets disagree. Nothing is closed.
    Divergent {
        conflict_id: i64,
        revision: i64,
        rust_pairs: Vec<(i64, i64)>,
        sql_pairs: Vec<(i64, i64)>,
    },
}

/// `(lower id, higher id)` pairs, ascending and deduplicated.
fn normalized_pairs(pairs: &[(i64, i64)]) -> Vec<(i64, i64)> {
    let mut pairs = pairs
        .iter()
        .map(|(left, right)| (*left.min(right), *left.max(right)))
        .collect::<Vec<_>>();
    pairs.sort_unstable();
    pairs.dedup();
    pairs
}

/// The remaining disputed claims a close may return to `active`, ascending.
fn disputed_ids(claims: &[LockedKeyClaim]) -> Vec<i64> {
    let mut ids = claims
        .iter()
        .filter(|claim| claim.state == ClaimState::Disputed)
        .map(|claim| claim.id)
        .collect::<Vec<_>>();
    ids.sort_unstable();
    ids.dedup();
    ids
}

/// Decide whether the key's v2 conflict closes, given the locked remaining
/// current claims and the database's own pair computation over the same rows.
/// The two raw pair sets must agree exactly before anything is decided;
/// only then are the pairs in `excluded` (those a dismissal of this conflict
/// already judged) left out, so a dismissed pair cannot keep a reopened
/// conflict open forever.
pub fn plan_reevaluation(
    lineage: Option<V2Lineage>,
    remaining: &[LockedKeyClaim],
    sql_pairs: &[(i64, i64)],
    excluded: &BTreeSet<(i64, i64)>,
) -> Reevaluation {
    let Some(lineage) = lineage else {
        return Reevaluation::NoLineage;
    };
    if lineage.state != ConflictRowState::Open {
        return Reevaluation::NotOpen;
    }
    let rust_pairs = incompatible_pairs(remaining);
    let sql_pairs = normalized_pairs(sql_pairs);
    if rust_pairs != sql_pairs {
        return Reevaluation::Divergent {
            conflict_id: lineage.id,
            revision: lineage.revision,
            rust_pairs,
            sql_pairs,
        };
    }
    let raw_count = rust_pairs.len();
    let pairs = rust_pairs
        .into_iter()
        .filter(|pair| !excluded.contains(pair))
        .collect::<Vec<_>>();
    let excluded_pairs = raw_count - pairs.len();
    if pairs.is_empty() {
        return Reevaluation::Close {
            conflict_id: lineage.id,
            revision: lineage.revision,
            restore_candidates: disputed_ids(remaining),
            excluded_pairs,
        };
    }
    Reevaluation::StillOpen {
        conflict_id: lineage.id,
        revision: lineage.revision,
        pairs,
        excluded_pairs,
    }
}

/// The `memory_conflicts.resolution_kind` of a detector-verified close that
/// found no incompatible current pair at all.
pub const NO_CURRENT_INCOMPATIBILITY: &str = "no_current_incompatibility";
/// The `memory_conflicts.resolution_kind` of a detector-verified close whose
/// only remaining incompatible current pairs are ones an adjudicator
/// dismissed in that conflict.
pub const NO_UNDISMISSED_INCOMPATIBILITY: &str = "no_undismissed_incompatibility";

/// The `resolution_kind` a detector-verified close writes to the conflict row.
///
/// A close that left out dismissed pairs says so in its own kind, because
/// those pairs are still current and still incompatible to the detector:
/// `no_current_incompatibility` is kept for a key with no incompatible
/// current pair at all. The close's logged `resolved` event keeps
/// `no_current_incompatibility`, the only reason kind the lifecycle log's
/// CHECK admits for it, and reports the excluded count in its payload.
#[must_use]
pub const fn verified_close_resolution_kind(excluded_dismissed_pairs: usize) -> &'static str {
    if excluded_dismissed_pairs == 0 {
        NO_CURRENT_INCOMPATIBILITY
    } else {
        NO_UNDISMISSED_INCOMPATIBILITY
    }
}

/// The wire name of a dismissal reason kind, exactly its contract serde name.
#[must_use]
pub const fn dismissal_reason_kind(kind: DismissalReasonKindV1) -> &'static str {
    match kind {
        DismissalReasonKindV1::FalsePositive => "false_positive",
        DismissalReasonKindV1::DuplicateOfOtherEpisode => "duplicate_of_other_episode",
        DismissalReasonKindV1::OutOfScope => "out_of_scope",
        DismissalReasonKindV1::NotReproducible => "not_reproducible",
    }
}

/// The wire name of a waiver reason kind, exactly its contract serde name.
#[must_use]
pub const fn waiver_reason_kind(kind: WaiverReasonKindV1) -> &'static str {
    match kind {
        WaiverReasonKindV1::CapacityDeferred => "capacity_deferred",
        WaiverReasonKindV1::CostExceedsRisk => "cost_exceeds_risk",
        WaiverReasonKindV1::UpstreamBlocked => "upstream_blocked",
        WaiverReasonKindV1::PolicyException => "policy_exception",
        WaiverReasonKindV1::ScheduledRemediation => "scheduled_remediation",
    }
}

/// The member authorship an adjudication is checked against: every durable
/// member of the conflict, in every episode, joined to its claim's actor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemberAuthorship {
    /// Members read, up to one past the bound an event can record.
    pub members_checked: i64,
    /// Members the adjudicating agent authored.
    pub implicated_members: i64,
    /// Members with no recorded actor.
    pub unattributed_members: i64,
}

/// A dismissal or waiver is decided only by an agent that authored none of
/// the conflict's members, in any episode (AUTH-03). A member with no
/// recorded actor could be the adjudicator's own, so it fails closed.
///
/// `member_count` is the durable member count the caller's view was checked
/// against; every one of those members must have been joined to its claim.
pub fn check_adjudicator(
    conflict_id: i64,
    member_count: i64,
    authorship: MemberAuthorship,
) -> Result<()> {
    if authorship.members_checked > MAX_CONFLICT_MEMBER_COUNT {
        return Err(LifecycleRefusal::new(
            RefusalCode::BoundExceeded,
            format!("conflict {conflict_id} has more than {MAX_CONFLICT_MEMBER_COUNT} members"),
            json!({ "conflict_id": conflict_id, "bound": MAX_CONFLICT_MEMBER_COUNT }),
        )
        .into());
    }
    if authorship.members_checked != member_count
        || authorship.implicated_members < 0
        || authorship.unattributed_members < 0
        || authorship.implicated_members + authorship.unattributed_members
            > authorship.members_checked
    {
        return Err(FleetError::Memory(
            "conflict member authorship did not match its locked member count".into(),
        ));
    }
    if authorship.implicated_members > 0 {
        return Err(LifecycleRefusal::new(
            RefusalCode::Implicated,
            format!(
                "this agent authored {} member claim(s) of conflict {conflict_id}; only an agent that authored none may dismiss or waive it",
                authorship.implicated_members
            ),
            json!({
                "conflict_id": conflict_id,
                "implicated_members": authorship.implicated_members,
            }),
        )
        .into());
    }
    if authorship.unattributed_members > 0 {
        return Err(LifecycleRefusal::new(
            RefusalCode::UnattributedMember,
            format!(
                "conflict {conflict_id} has {} member claim(s) with no recorded author, so no agent can be shown to be uninvolved",
                authorship.unattributed_members
            ),
            json!({
                "conflict_id": conflict_id,
                "unattributed_members": authorship.unattributed_members,
            }),
        )
        .into());
    }
    Ok(())
}

/// What a dismissal records and changes, decided over the key's locked
/// current claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DismissalPlan {
    /// Every current incompatible pair the adjudicator judged, ascending.
    /// Later re-evaluations of this conflict leave them out.
    pub dismissed_pairs: Vec<(i64, i64)>,
    /// The remaining disputed claims the dismissal may return to `active`.
    pub restore_candidates: Vec<i64>,
}

/// Plan a dismissal: the Rust and SQL pair computations must agree, and the
/// judged pairs must fit one lifecycle event.
pub fn plan_dismissal(
    conflict_id: i64,
    current: &[LockedKeyClaim],
    sql_pairs: &[(i64, i64)],
) -> std::result::Result<DismissalPlan, LifecycleRefusal> {
    let rust_pairs = incompatible_pairs(current);
    if rust_pairs != normalized_pairs(sql_pairs) {
        return Err(LifecycleRefusal::new(
            RefusalCode::VerificationDivergence,
            format!(
                "the detector could not verify conflict {conflict_id}'s pairs consistently; nothing was changed"
            ),
            json!({ "conflict_id": conflict_id }),
        ));
    }
    if rust_pairs.len() > MAX_DISMISSED_PAIRS {
        return Err(LifecycleRefusal::new(
            RefusalCode::BoundExceeded,
            format!(
                "conflict {conflict_id} has {} incompatible current pairs; one dismissal records at most {MAX_DISMISSED_PAIRS}",
                rust_pairs.len()
            ),
            json!({
                "conflict_id": conflict_id,
                "pair_count": rust_pairs.len(),
                "bound": MAX_DISMISSED_PAIRS,
            }),
        ));
    }
    Ok(DismissalPlan {
        dismissed_pairs: rust_pairs,
        restore_candidates: disputed_ids(current),
    })
}

/// The union of the pairs recorded by a conflict's newest dismissals, from
/// each `dismissed` event's `payload.dismissed_pairs`. The log is written only
/// by the serving writer, so a malformed entry is corruption, not input.
pub fn dismissed_pairs(payloads: &[Value]) -> Result<BTreeSet<(i64, i64)>> {
    let corrupt =
        || FleetError::Memory("a dismissal event recorded malformed dismissed pairs".into());
    let mut pairs = BTreeSet::new();
    for payload in payloads {
        let entries = payload.as_array().ok_or_else(corrupt)?;
        if entries.len() > MAX_DISMISSED_PAIRS {
            return Err(corrupt());
        }
        for entry in entries {
            let [left, right] = entry.as_array().map(Vec::as_slice).ok_or_else(corrupt)? else {
                return Err(corrupt());
            };
            let (Some(left), Some(right)) = (left.as_i64(), right.as_i64()) else {
                return Err(corrupt());
            };
            if left < 1 || left >= right {
                return Err(corrupt());
            }
            pairs.insert((left, right));
        }
    }
    Ok(pairs)
}

/// A dismissal or waiver rationale: 1..=1000 characters of visible text with
/// no control characters other than newline and tab, within the contract's
/// byte bound.
pub fn validate_rationale(rationale: &str) -> std::result::Result<(), String> {
    validate_note("rationale", rationale, MAX_ADJUDICATION_RATIONALE_CHARS)?;
    if rationale.len() > MAX_RATIONALE_BYTES {
        return Err(format!(
            "rationale must be at most {MAX_RATIONALE_BYTES} bytes"
        ));
    }
    Ok(())
}

/// A waiver lasts 1..=2160 hours, and its optional review falls due no later
/// than it expires.
pub fn validate_waiver_hours(
    expires_in_hours: u16,
    review_in_hours: Option<u16>,
) -> std::result::Result<(), String> {
    if !(1..=MAX_WAIVER_HOURS).contains(&expires_in_hours) {
        return Err(format!(
            "expires_in_hours must be between 1 and {MAX_WAIVER_HOURS}"
        ));
    }
    match review_in_hours {
        Some(review) if !(1..=expires_in_hours).contains(&review) => Err(format!(
            "review_in_hours must be between 1 and expires_in_hours ({expires_in_hours})"
        )),
        _ => Ok(()),
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

/// Whether the lifecycle log can hold an event at `seq` recording
/// `member_count` members: both are bounded by the log's CHECK constraints.
///
/// An `acknowledge`, whose only effect is its event, is refused
/// `bound_exceeded` when this is false. A detector-verified close is never
/// refused for it: the close commits without its event and reads as
/// `closed_unlogged`, so the log's capacity never takes away an owner's
/// retract or supersede.
#[must_use]
pub const fn event_fits_log(seq: i64, member_count: i64) -> bool {
    seq >= 1
        && seq <= MAX_CONFLICT_LIFECYCLE_EVENTS
        && member_count >= 0
        && member_count <= MAX_CONFLICT_MEMBER_COUNT
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
/// conflict in between (a reopen by `record`, a close from before the
/// lifecycle log, or a close the full log could not hold). `events` are the
/// log's newest events in `seq` order; `from_first_event` is false when older
/// events were left out, so no gap before the first returned event can be
/// inferred.
#[must_use]
pub fn unlogged_transitions(
    events: &[ConflictLifecycleEvent],
    current_revision: i64,
    from_first_event: bool,
) -> Vec<RevisionGap> {
    let mut gaps = Vec::new();
    let mut cursor = if from_first_event {
        1_i64
    } else {
        match events.first() {
            Some(first) => first.episode_revision,
            None => return gaps,
        }
    };
    for event in events {
        if event.episode_revision > cursor {
            gaps.push(RevisionGap {
                from_revision: cursor,
                to_revision: event.episode_revision,
            });
        }
        cursor = cursor.max(event.result_revision);
    }
    if current_revision > cursor {
        gaps.push(RevisionGap {
            from_revision: cursor,
            to_revision: current_revision,
        });
    }
    gaps
}

/// Keep the newest events of `history` that fit in `byte_budget`.
///
/// Older events are dropped first and the history is marked truncated, so a
/// long-lived conflict's lookup stays within one bounded response however
/// large its events' notes and payloads are.
#[must_use]
pub fn history_within_bytes(mut history: ConflictHistory, byte_budget: usize) -> ConflictHistory {
    let mut used = 0_usize;
    let mut kept = 0_usize;
    for event in history.events.iter().rev() {
        // One separator byte per array element.
        let size = serde_json::to_vec(event)
            .map_or(usize::MAX, |bytes| bytes.len())
            .saturating_add(1);
        used = used.saturating_add(size);
        if used > byte_budget {
            break;
        }
        kept += 1;
    }
    let dropped = history.events.len() - kept;
    if dropped > 0 {
        history.events.drain(..dropped);
        history.truncated = true;
    }
    history
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
    validate_note("reason", reason, MAX_LIFECYCLE_REASON_CHARS)
}

fn validate_note(label: &str, note: &str, max_chars: usize) -> std::result::Result<(), String> {
    if note.is_empty() || note.chars().count() > max_chars {
        return Err(format!(
            "{label} must be between 1 and {max_chars} characters"
        ));
    }
    if is_blank_rationale(note) {
        return Err(format!("{label} must contain visible text"));
    }
    if note
        .chars()
        .any(|character| character.is_control() && !matches!(character, '\n' | '\t'))
    {
        return Err(format!(
            "{label} must not contain control characters other than newline and tab"
        ));
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
            plan_reevaluation(lineage, std::slice::from_ref(&y), &[], &BTreeSet::new()),
            Reevaluation::Close {
                conflict_id: 9,
                revision: 3,
                restore_candidates: vec![2],
                excluded_pairs: 0,
            }
        );

        // Three-way x/y/z: retracting x leaves y vs z open.
        assert_eq!(
            plan_reevaluation(
                lineage,
                &[y.clone(), z.clone()],
                &[(3, 2)],
                &BTreeSet::new()
            ),
            Reevaluation::StillOpen {
                conflict_id: 9,
                revision: 3,
                pairs: vec![(2, 3)],
                excluded_pairs: 0,
            }
        );

        // +x/-x/+y: retracting +x leaves -x and +y, which are compatible.
        let negative_x = locked(4, json!("x"), -1);
        let positive_y = locked(5, json!("y"), 1);
        assert!(!incompatible_pairs(&[x, negative_x.clone(), positive_y.clone()]).is_empty());
        assert!(matches!(
            plan_reevaluation(
                lineage,
                &[negative_x.clone(), positive_y.clone()],
                &[],
                &BTreeSet::new()
            ),
            Reevaluation::Close { .. }
        ));

        assert_eq!(
            plan_reevaluation(None, std::slice::from_ref(&y), &[], &BTreeSet::new()),
            Reevaluation::NoLineage
        );
        for state in [ConflictRowState::Resolved, ConflictRowState::Dismissed] {
            let closed = Some(V2Lineage {
                state,
                ..open_lineage()
            });
            assert_eq!(
                plan_reevaluation(closed, std::slice::from_ref(&y), &[], &BTreeSet::new()),
                Reevaluation::NotOpen
            );
        }

        // The database found a pair Rust did not: nothing may close.
        assert_eq!(
            plan_reevaluation(
                lineage,
                &[negative_x, positive_y],
                &[(4, 5)],
                &BTreeSet::new()
            ),
            Reevaluation::Divergent {
                conflict_id: 9,
                revision: 3,
                rust_pairs: Vec::new(),
                sql_pairs: vec![(4, 5)],
            }
        );
        // And Rust found a pair the database did not.
        assert!(matches!(
            plan_reevaluation(lineage, &[y, z], &[], &BTreeSet::new()),
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
            subject: prepared.subject,
            predicate: prepared.predicate,
            conflict_eligible: prepared.conflict_eligible,
        }
    }

    /// A stored row as the earlier normalizer left it: lowercase parts with
    /// `_` kept, and the key joined from exactly those parts.
    fn legacy_shape(subject: &str, predicate: &str) -> ClaimShape {
        ClaimShape {
            kind: ClaimKind::Decision,
            claim_key: Some(format!("{subject}::{predicate}")),
            subject: Some(subject.into()),
            predicate: Some(predicate.into()),
            conflict_eligible: true,
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
            moved.details["normalized_claim_key"],
            "fleet-memory::database"
        );
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

    /// A predecessor stored under the earlier normalizer, which kept `_`, is
    /// superseded onto the key its words get today, and nowhere else.
    #[test]
    fn legacy_key_predecessor_is_superseded_onto_its_current_key() {
        let legacy = legacy_shape("include_transcript_default", "x");
        assert_eq!(
            legacy.successor_claim_key().as_deref(),
            Some("include-transcript-default::x")
        );
        let mut bridged = claim_input(
            ClaimKind::Decision,
            Some("include-transcript default"),
            Some(json!(false)),
        );
        bridged.predicate = Some("X".into());
        let bridged = shape_of(&bridged);
        assert_eq!(
            bridged.claim_key.as_deref(),
            Some("include-transcript-default::x")
        );
        assert!(check_successor(41, &legacy, &bridged).is_ok());

        let mut elsewhere = claim_input(
            ClaimKind::Decision,
            Some("include-transcript"),
            Some(json!(false)),
        );
        elsewhere.predicate = Some("x".into());
        let refused = check_successor(41, &legacy, &shape_of(&elsewhere)).unwrap_err();
        assert_eq!(refused.code, RefusalCode::SuccessorKeyMismatch);
        assert_eq!(
            refused.details["claim_key"],
            "include_transcript_default::x"
        );
        assert_eq!(
            refused.details["normalized_claim_key"],
            "include-transcript-default::x"
        );
        assert_eq!(
            refused.details["successor_claim_key"],
            "include-transcript::x"
        );

        // The parts decide, not the joined string: `a_` re-keys to `a::b`.
        let trailing = legacy_shape("a_", "b");
        assert_eq!(trailing.successor_claim_key().as_deref(), Some("a::b"));
        // An assert's derived key is never re-normalized from its parts.
        let asserted = ClaimShape {
            kind: ClaimKind::Decision,
            claim_key: Some("claim-v2:coordinate:attested".into()),
            subject: Some("urn:ostk:entity:v1:repository:sha256:00".into()),
            predicate: Some("mcp.remember.allowed_actions".into()),
            conflict_eligible: true,
        };
        assert_eq!(
            asserted.successor_claim_key().as_deref(),
            Some("claim-v2:coordinate:attested")
        );
        // A row without parts keeps whatever key it has.
        let partless = ClaimShape {
            subject: None,
            predicate: None,
            ..legacy_shape("fleet-memory", "database")
        };
        assert_eq!(
            partless.successor_claim_key().as_deref(),
            Some("fleet-memory::database")
        );
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
            plan_reevaluation(lineage, &two.remaining, &[], &BTreeSet::new()),
            Reevaluation::Close { ref restore_candidates, .. } if *restore_candidates == [42]
        ));
        // Three-way: y and z still disagree, so the concession is refused.
        let three = plan_concession(9, "agent-a", &[41], &members, vec![x, y, z]).unwrap();
        let Reevaluation::StillOpen { pairs, .. } =
            plan_reevaluation(lineage, &three.remaining, &[(42, 43)], &BTreeSet::new())
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
        // A history that left out its oldest events cannot see what came
        // before them, but still sees everything after them.
        assert_eq!(unlogged_transitions(&later, 5, false), [gap(4, 5)]);
        assert_eq!(
            unlogged_transitions(&later[1..], 6, false),
            [gap(4, 5), gap(5, 6)]
        );
        assert!(unlogged_transitions(&[], 3, false).is_empty());
        // No log at all: every revision after creation is unlogged.
        assert_eq!(unlogged_transitions(&[], 3, true), [gap(1, 3)]);
        assert!(unlogged_transitions(&[], 1, true).is_empty());
    }

    #[test]
    fn history_keeps_its_newest_events_within_a_byte_budget() {
        let mut events = (1..=6)
            .map(|seq| event(seq, "acknowledged", 1, &format!("agent-{seq}")))
            .collect::<Vec<_>>();
        // Long notes in a three-byte script, as the reason schema allows.
        for event in &mut events {
            event.rationale = Some("\u{8a3c}".repeat(MAX_LIFECYCLE_REASON_CHARS));
        }
        let size = |events: &[ConflictLifecycleEvent]| serde_json::to_vec(events).unwrap().len();
        let whole = ConflictHistory {
            events: events.clone(),
            truncated: false,
        };
        assert_eq!(history_within_bytes(whole.clone(), size(&events)), whole);

        let budget = size(&events[3..]);
        let bounded = history_within_bytes(whole.clone(), budget);
        assert!(bounded.truncated);
        assert_eq!(bounded.events, events[3..]);
        assert!(size(&bounded.events) <= budget);
        // A history already cut at its event bound stays truncated.
        let cut = ConflictHistory {
            truncated: true,
            ..whole.clone()
        };
        assert!(history_within_bytes(cut, usize::MAX).truncated);
        // Too small a budget keeps nothing rather than overrunning it.
        let empty = history_within_bytes(whole, 10);
        assert!(empty.truncated && empty.events.is_empty());
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
            RefusalCode::AssertUnavailable,
            RefusalCode::WriterAuthorityUnavailable,
            RefusalCode::AssertionNotAdmitted,
            RefusalCode::SupportEventUnknown,
            RefusalCode::RegistryHeadChanged,
            RefusalCode::AlreadyAsserted,
        ] {
            assert_eq!(serde_json::to_value(code).unwrap(), json!(code.as_str()));
        }
    }

    #[test]
    fn dismissed_pairs_excluded_only_when_exact() {
        let lineage = Some(open_lineage());
        let x = owned(41, "agent-a", "x", ClaimState::Disputed);
        let y = owned(42, "agent-b", "y", ClaimState::Disputed);
        let z = owned(43, "agent-d", "z", ClaimState::Disputed);
        let raw = [(41, 42), (41, 43), (42, 43)];

        // A dismissed x/y pair, reopened by z: z's pairs keep it open.
        let dismissed = BTreeSet::from([(41, 42)]);
        let Reevaluation::StillOpen {
            pairs,
            excluded_pairs,
            ..
        } = plan_reevaluation(lineage, &[x.clone(), y.clone(), z], &raw, &dismissed)
        else {
            panic!("z's pairs are not dismissed");
        };
        assert_eq!(pairs, [(41, 43), (42, 43)]);
        assert_eq!(excluded_pairs, 1);

        // Once z is gone, only the dismissed pair is left: the conflict closes
        // and both of its members may return to active.
        assert_eq!(
            plan_reevaluation(lineage, &[x.clone(), y.clone()], &[(42, 41)], &dismissed),
            Reevaluation::Close {
                conflict_id: 9,
                revision: 3,
                restore_candidates: vec![41, 42],
                excluded_pairs: 1,
            }
        );

        // Only the exact pair is excluded: a pair sharing one claim, a pair of
        // the same claims under other ids, or no dismissal at all keeps it open.
        for other in [
            BTreeSet::new(),
            BTreeSet::from([(41, 43)]),
            BTreeSet::from([(40, 42)]),
            BTreeSet::from([(42, 41)]),
        ] {
            assert!(
                matches!(
                    plan_reevaluation(lineage, &[x.clone(), y.clone()], &[(41, 42)], &other),
                    Reevaluation::StillOpen {
                        excluded_pairs: 0,
                        ..
                    }
                ),
                "{other:?}"
            );
        }

        // Exclusion never hides a disagreement between Rust and SQL.
        assert!(matches!(
            plan_reevaluation(lineage, &[x, y], &[], &dismissed),
            Reevaluation::Divergent { .. }
        ));
    }

    #[test]
    fn close_that_left_out_dismissed_pairs_does_not_claim_no_current_incompatibility() {
        let lineage = Some(open_lineage());
        let x = owned(41, "agent-a", "x", ClaimState::Disputed);
        let y = owned(42, "agent-b", "y", ClaimState::Disputed);
        let kind_of = |remaining: &[LockedKeyClaim],
                       sql_pairs: &[(i64, i64)],
                       dismissed: &BTreeSet<(i64, i64)>| {
            match plan_reevaluation(lineage, remaining, sql_pairs, dismissed) {
                Reevaluation::Close { excluded_pairs, .. } => {
                    verified_close_resolution_kind(excluded_pairs)
                }
                other => panic!("expected a close, got {other:?}"),
            }
        };

        // The key still holds the incompatible x/y pair, which the close only
        // leaves out because an adjudicator dismissed it.
        let excluding = kind_of(&[x.clone(), y], &[(41, 42)], &BTreeSet::from([(41, 42)]));
        assert_ne!(excluding, NO_CURRENT_INCOMPATIBILITY);
        assert_eq!(excluding, NO_UNDISMISSED_INCOMPATIBILITY);

        // A key with no incompatible current pair at all keeps the plain kind,
        // whatever was dismissed before.
        for dismissed in [BTreeSet::new(), BTreeSet::from([(41, 42)])] {
            assert_eq!(
                kind_of(std::slice::from_ref(&x), &[], &dismissed),
                NO_CURRENT_INCOMPATIBILITY
            );
        }
    }

    #[test]
    fn dismissed_pairs_parse_strictly_from_dismissal_payloads() {
        let pairs =
            dismissed_pairs(&[json!([[41, 42], [42, 43]]), json!([[41, 42]]), json!([])]).unwrap();
        assert_eq!(pairs, BTreeSet::from([(41, 42), (42, 43)]));
        assert!(dismissed_pairs(&[]).unwrap().is_empty());
        for corrupt in [
            Value::Null,
            json!({"pairs": []}),
            json!([[41]]),
            json!([[41, 42, 43]]),
            json!([[42, 41]]),
            json!([[41, 41]]),
            json!([[0, 41]]),
            json!([["41", 42]]),
            json!([[41.5, 42]]),
        ] {
            assert!(
                matches!(
                    dismissed_pairs(std::slice::from_ref(&corrupt)),
                    Err(FleetError::Memory(_))
                ),
                "{corrupt}"
            );
        }
    }

    #[test]
    fn dismissal_plans_record_verified_bounded_pairs() {
        let x = owned(41, "agent-a", "x", ClaimState::Disputed);
        let y = owned(42, "agent-b", "y", ClaimState::Disputed);
        let active = owned(43, "agent-c", "x", ClaimState::Active);
        let plan =
            plan_dismissal(9, &[x.clone(), y.clone(), active], &[(42, 43), (41, 42)]).unwrap();
        assert_eq!(plan.dismissed_pairs, [(41, 42), (42, 43)]);
        assert_eq!(plan.restore_candidates, [41, 42]);

        let divergent = plan_dismissal(9, &[x, y], &[]).unwrap_err();
        assert_eq!(divergent.code, RefusalCode::VerificationDivergence);

        // 46 distinct values are 1,035 pairs, more than one event records.
        let crowded = (1..=46)
            .map(|id| owned(id, "agent-a", &format!("value-{id}"), ClaimState::Disputed))
            .collect::<Vec<_>>();
        let sql = incompatible_pairs(&crowded);
        assert!(sql.len() > MAX_DISMISSED_PAIRS);
        let bound = plan_dismissal(9, &crowded, &sql).unwrap_err();
        assert_eq!(bound.code, RefusalCode::BoundExceeded);
        assert_eq!(bound.details["pair_count"], sql.len());
        let fitting = &crowded[..45];
        assert_eq!(
            plan_dismissal(9, fitting, &incompatible_pairs(fitting))
                .unwrap()
                .dismissed_pairs
                .len(),
            990
        );
    }

    #[test]
    fn adjudicator_checks() {
        let authorship =
            |members_checked, implicated_members, unattributed_members| MemberAuthorship {
                members_checked,
                implicated_members,
                unattributed_members,
            };
        let refused = |member_count, check| match check_adjudicator(9, member_count, check) {
            Err(FleetError::LifecycleRefused(refusal)) => *refusal,
            other => panic!("expected a refusal, got {other:?}"),
        };
        assert!(check_adjudicator(9, 2, authorship(2, 0, 0)).is_ok());

        let implicated = refused(3, authorship(3, 1, 0));
        assert_eq!(implicated.code, RefusalCode::Implicated);
        assert_eq!(implicated.details["implicated_members"], 1);
        // Implication is reported first: it is about the caller.
        assert_eq!(
            refused(3, authorship(3, 1, 1)).code,
            RefusalCode::Implicated
        );
        let unattributed = refused(3, authorship(3, 0, 1));
        assert_eq!(unattributed.code, RefusalCode::UnattributedMember);
        assert_eq!(unattributed.details["unattributed_members"], 1);

        let bound = MAX_CONFLICT_MEMBER_COUNT + 1;
        assert_eq!(
            refused(bound, authorship(bound, 0, 0)).code,
            RefusalCode::BoundExceeded
        );
        // A member missing from its join, or counts that cannot add up, are
        // corruption rather than a refusal.
        for check in [
            authorship(1, 0, 0),
            authorship(2, 2, 1),
            authorship(2, -1, 0),
        ] {
            assert!(
                matches!(check_adjudicator(9, 2, check), Err(FleetError::Memory(_))),
                "{check:?}"
            );
        }
    }

    #[test]
    fn waiver_bounds() {
        assert!(validate_waiver_hours(1, None).is_ok());
        assert!(validate_waiver_hours(MAX_WAIVER_HOURS, Some(MAX_WAIVER_HOURS)).is_ok());
        assert!(validate_waiver_hours(24, Some(1)).is_ok());
        for (expires, review) in [
            (0, None),
            (MAX_WAIVER_HOURS + 1, None),
            (24, Some(0)),
            (24, Some(25)),
            (MAX_WAIVER_HOURS + 1, Some(1)),
        ] {
            assert!(
                validate_waiver_hours(expires, review).is_err(),
                "{expires}/{review:?}"
            );
        }

        assert!(validate_rationale("the detector compares unrelated deployments").is_ok());
        assert!(validate_rationale(&"x".repeat(MAX_ADJUDICATION_RATIONALE_CHARS)).is_ok());
        // Every rationale the schema admits fits the contract's byte bound.
        let widest = "\u{1F4DD}".repeat(MAX_ADJUDICATION_RATIONALE_CHARS);
        assert!(widest.len() <= MAX_RATIONALE_BYTES);
        assert!(validate_rationale(&widest).is_ok());
        for rejected in [
            String::new(),
            " \t ".into(),
            "\u{2060}\u{200D}".into(),
            "x".repeat(MAX_ADJUDICATION_RATIONALE_CHARS + 1),
            "nul\u{0}".into(),
        ] {
            let error = validate_rationale(&rejected).unwrap_err();
            assert!(error.starts_with("rationale"), "{error}");
        }
    }

    #[test]
    fn reason_kind_enums_match_contract_serde_names() {
        for kind in [
            DismissalReasonKindV1::FalsePositive,
            DismissalReasonKindV1::DuplicateOfOtherEpisode,
            DismissalReasonKindV1::OutOfScope,
            DismissalReasonKindV1::NotReproducible,
        ] {
            assert_eq!(
                serde_json::to_value(kind).unwrap(),
                json!(dismissal_reason_kind(kind))
            );
        }
        for kind in [
            WaiverReasonKindV1::CapacityDeferred,
            WaiverReasonKindV1::CostExceedsRisk,
            WaiverReasonKindV1::UpstreamBlocked,
            WaiverReasonKindV1::PolicyException,
            WaiverReasonKindV1::ScheduledRemediation,
        ] {
            assert_eq!(
                serde_json::to_value(kind).unwrap(),
                json!(waiver_reason_kind(kind))
            );
        }
    }
}
