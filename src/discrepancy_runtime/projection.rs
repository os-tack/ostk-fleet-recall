//! Pure layer of the discrepancy ledger runtime (W3-DISC, Stage 6).
//!
//! Two independent concerns live here, both free of I/O:
//!
//! 1. **Coverage-bounded two-sided comparison.** A discrepancy is a claim
//!    about two sides — "what IS" (the observer plane) versus "what SHOULD
//!    be" (the active normative projection) — and that claim is only
//!    meaningful when BOTH sides were actually measured over the compared
//!    interval. Every comparison input therefore carries its own coverage
//!    bound AS DATA ([`MeasuredComparisonSideV1`]), the provider seam
//!    ([`ComparisonSideProvider`]) has DELIBERATELY NO DEFAULT for the
//!    measurement method, and [`compare_measured_sides`] resolves any
//!    partial, unknown, stale, unmeasured, or short-windowed side to an
//!    explicit [`ComparisonVerdictV1::Indeterminate`] — never to
//!    "no discrepancy" (a verified negative) and never to a confirmed
//!    finding. Absence of evidence of disagreement is not evidence of
//!    agreement.
//!
//! 2. **Deterministic ledger projection.** [`project_ledger_episode`] wraps
//!    the contract's own pure replay
//!    ([`crate::memory_contracts::discrepancy::project_discrepancy_episode`])
//!    with a deterministic evaluation instant derived from the log itself
//!    ([`ledger_evaluation_time`]), so the durable projection the repository
//!    stores is a total function of the durable log — no wall clock
//!    participates — and a rebuild from the database reproduces it byte for
//!    byte (REPLAY-01).
//!
//! The opening transition helper [`seed_episode_fingerprint`] selects the
//! episode-seeding candidate by the total order over
//! `(effective_at, provider_order, source_fact_id)` via the contract's
//! [`select_opening_transition`] — receipt order never participates, so
//! ingesting the same facts in a different sequence cannot move the episode
//! fingerprint.

use serde::{Deserialize, Serialize};

use crate::memory_contracts::common::CanonicalTimestamp;
use crate::memory_contracts::coverage::{
    CoverageCompletenessV1, CoverageWindowV1, FreshnessStateV1,
};
use crate::memory_contracts::digest::Sha256Digest;
use crate::memory_contracts::discrepancy::{
    ApplicabilityDimensionV1, DiscrepancyEnvelopeV1, DiscrepancyEpisodeFingerprintV1,
    DiscrepancyEpisodePreimageV1, DiscrepancyEpisodeProjectionV1, DiscrepancyEpisodeRelationV1,
    DiscrepancyFamilyFingerprintV1, DiscrepancyLifecycleEventV1, OpeningTransitionCandidateV1,
    VerificationState, project_discrepancy_episode, select_opening_transition,
};
use crate::memory_contracts::{ContractError, ContractResult};

/// `schema_version` of the episode preimage this runtime seeds fingerprints
/// with; equals the contract's own `DISCREPANCY_SCHEMA_VERSION`.
pub const DISCREPANCY_RUNTIME_SCHEMA_VERSION: u32 = 1;

/// Upper bound on one episode's ledger log.
///
/// Envelope plus lifecycle events: a rebuild replays every record, so the
/// log is bounded rather than unbounded-and-hoped-for, mirroring the
/// normative runtime's bound.
pub const MAX_EPISODE_LOG_ENTRIES: usize = 4096;

/// Upper bound on one family's stored relation set, for the same reason.
pub const MAX_FAMILY_RELATIONS: usize = 4096;

// ---------------------------------------------------------------------------
// Coverage-bounded comparison (CRITICAL SEMANTICS 4)
// ---------------------------------------------------------------------------

/// Which side of the comparison a measurement claims to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComparisonSideRoleV1 {
    /// "What IS": an observer-plane measurement.
    Observed,
    /// "What SHOULD be": the active normative resolution.
    Normative,
}

/// One side's measurement over a compared interval, carrying its own
/// coverage bound AS DATA.
///
/// There is no constructor that defaults `completeness` to `Complete`,
/// `freshness` to `Current`, or `measured_window` to the compared window:
/// every field must be stated by whoever performed (or failed to perform)
/// the measurement. `value_digest: None` means the side was not measured at
/// all over the interval — which poisons the comparison
/// ([`ComparisonIndeterminacyV1`]), never silently supports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeasuredComparisonSideV1 {
    pub role: ComparisonSideRoleV1,
    /// The interval this side ACTUALLY covers — not the interval the caller
    /// wished it covered.
    pub measured_window: CoverageWindowV1,
    pub completeness: CoverageCompletenessV1,
    pub freshness: FreshnessStateV1,
    /// Canonical digest of the side's resolved value over the interval;
    /// `None` when the side produced no measurement.
    pub value_digest: Option<Sha256Digest>,
}

impl MeasuredComparisonSideV1 {
    pub fn validate(&self) -> ContractResult<()> {
        self.measured_window.validate()
    }
}

/// The provider seam a comparison input must come through.
///
/// `measure` has DELIBERATELY NO DEFAULT implementation, exactly like
/// `CiRunProvider::listing_bound` (W3-CIEV): a defaulted "my coverage is
/// complete" is the unsound assumption that turns an unread interval into a
/// verified negative, and a required method forces every future implementor
/// to answer the coverage question consciously.
pub trait ComparisonSideProvider: Send + Sync {
    /// This side's measurement over `compared`, with its honest coverage
    /// bound. Returning `Complete` here is a claim the implementor makes
    /// about its own read, and it is the implementor's to defend.
    fn measure(&self, compared: &CoverageWindowV1) -> ContractResult<MeasuredComparisonSideV1>;
}

/// Why a comparison could not produce a verdict. Closed set: an unlisted
/// cause cannot be smuggled in as a string.
///
/// The serde form is [`Self::as_str`], so a spec check record carries the
/// same names agents read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComparisonIndeterminacyV1 {
    ObservedUnmeasured,
    NormativeUnmeasured,
    ObservedPartialCoverage,
    NormativePartialCoverage,
    ObservedUnknownCoverage,
    NormativeUnknownCoverage,
    ObservedStale,
    NormativeStale,
    /// The side's measured window does not contain the compared interval.
    ObservedWindowShortfall,
    NormativeWindowShortfall,
}

impl ComparisonIndeterminacyV1 {
    /// Stable `snake_case` wire name, for check records and agent-facing
    /// output. The set is closed, so the name is total.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ObservedUnmeasured => "observed_unmeasured",
            Self::NormativeUnmeasured => "normative_unmeasured",
            Self::ObservedPartialCoverage => "observed_partial_coverage",
            Self::NormativePartialCoverage => "normative_partial_coverage",
            Self::ObservedUnknownCoverage => "observed_unknown_coverage",
            Self::NormativeUnknownCoverage => "normative_unknown_coverage",
            Self::ObservedStale => "observed_stale",
            Self::NormativeStale => "normative_stale",
            Self::ObservedWindowShortfall => "observed_window_shortfall",
            Self::NormativeWindowShortfall => "normative_window_shortfall",
        }
    }
}

/// Outcome of comparing the observed side against the normative side over
/// one interval.
///
/// There are exactly three arms. `Indeterminate` is an explicit first-class
/// verdict, not an error and not a default: a caller cannot pattern-match
/// its way from a poisoned comparison to either `NoDiscrepancy` or
/// `Discrepant` without writing the arm out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComparisonVerdictV1 {
    /// Both sides fully measured; their values disagree.
    Discrepant,
    /// Both sides fully measured; their values agree. This is a VERIFIED
    /// negative and is only reachable when every coverage conjunct holds.
    NoDiscrepancy,
    /// At least one side is partial, unknown, stale, unmeasured, or short of
    /// the compared window. Never collapses to `NoDiscrepancy`.
    Indeterminate {
        reasons: Vec<ComparisonIndeterminacyV1>,
    },
}

impl ComparisonVerdictV1 {
    /// The `initial_verification_state` a detection envelope seeded from this
    /// verdict may carry. `NoDiscrepancy` yields `None`: a verified negative
    /// opens no discrepancy at all, so there is no state to seed.
    #[must_use]
    pub const fn initial_verification_state(&self) -> Option<VerificationState> {
        match self {
            Self::Discrepant => Some(VerificationState::Candidate),
            Self::NoDiscrepancy => None,
            Self::Indeterminate { .. } => Some(VerificationState::Indeterminate),
        }
    }
}

/// True when `measured` contains the whole half-open `compared` interval.
fn covers(measured: &CoverageWindowV1, compared: &CoverageWindowV1) -> bool {
    measured.window_start <= compared.window_start && compared.window_end <= measured.window_end
}

/// Collect every reason `side` cannot support a verdict over `compared`.
fn side_indeterminacy(
    side: &MeasuredComparisonSideV1,
    compared: &CoverageWindowV1,
) -> Vec<ComparisonIndeterminacyV1> {
    use ComparisonIndeterminacyV1 as Reason;
    let observed = side.role == ComparisonSideRoleV1::Observed;
    let pick = |if_observed: Reason, if_normative: Reason| {
        if observed { if_observed } else { if_normative }
    };
    let mut reasons = Vec::new();
    if side.value_digest.is_none() {
        reasons.push(pick(
            Reason::ObservedUnmeasured,
            Reason::NormativeUnmeasured,
        ));
    }
    match side.completeness {
        CoverageCompletenessV1::Complete => {}
        CoverageCompletenessV1::Partial => reasons.push(pick(
            Reason::ObservedPartialCoverage,
            Reason::NormativePartialCoverage,
        )),
        CoverageCompletenessV1::Unknown => reasons.push(pick(
            Reason::ObservedUnknownCoverage,
            Reason::NormativeUnknownCoverage,
        )),
    }
    if side.freshness == FreshnessStateV1::Stale {
        reasons.push(pick(Reason::ObservedStale, Reason::NormativeStale));
    }
    if !covers(&side.measured_window, compared) {
        reasons.push(pick(
            Reason::ObservedWindowShortfall,
            Reason::NormativeWindowShortfall,
        ));
    }
    reasons
}

/// Compare one observed-side measurement against one normative-side
/// measurement over `compared`.
///
/// A real verdict — `Discrepant` or `NoDiscrepancy` — requires, for BOTH
/// sides: a present value, `Complete` coverage, `Current` freshness, and a
/// measured window containing the compared interval. Any failed conjunct on
/// either side resolves to `Indeterminate` carrying every failed conjunct,
/// and there is no code path from a failed conjunct to `NoDiscrepancy`:
/// absence of evidence of disagreement is not evidence of agreement.
///
/// The two inputs must actually be one observed side and one normative side;
/// two same-role inputs are a category error and are rejected closed rather
/// than compared.
pub fn compare_measured_sides(
    compared: &CoverageWindowV1,
    observed: &MeasuredComparisonSideV1,
    normative: &MeasuredComparisonSideV1,
) -> ContractResult<ComparisonVerdictV1> {
    compared.validate()?;
    observed.validate()?;
    normative.validate()?;
    if observed.role != ComparisonSideRoleV1::Observed
        || normative.role != ComparisonSideRoleV1::Normative
    {
        return Err(ContractError::Schema(
            "comparison requires exactly one observed side and one normative side".into(),
        ));
    }

    let mut reasons = side_indeterminacy(observed, compared);
    reasons.extend(side_indeterminacy(normative, compared));
    if !reasons.is_empty() {
        reasons.sort_unstable();
        reasons.dedup();
        return Ok(ComparisonVerdictV1::Indeterminate { reasons });
    }

    // Both sides fully measured over the compared interval; the values are
    // guaranteed present by the empty reason set.
    let observed_value = observed
        .value_digest
        .ok_or_else(|| ContractError::Schema("observed side lost its value".into()))?;
    let normative_value = normative
        .value_digest
        .ok_or_else(|| ContractError::Schema("normative side lost its value".into()))?;
    Ok(if observed_value == normative_value {
        ComparisonVerdictV1::NoDiscrepancy
    } else {
        ComparisonVerdictV1::Discrepant
    })
}

/// Ask both providers for their measurement over `compared` and compare.
///
/// Because [`ComparisonSideProvider::measure`] has no default, every
/// provider reaching this function has consciously stated its coverage.
pub fn compare_sides(
    compared: &CoverageWindowV1,
    observed: &dyn ComparisonSideProvider,
    normative: &dyn ComparisonSideProvider,
) -> ContractResult<ComparisonVerdictV1> {
    compared.validate()?;
    let observed_side = observed.measure(compared)?;
    let normative_side = normative.measure(compared)?;
    compare_measured_sides(compared, &observed_side, &normative_side)
}

// ---------------------------------------------------------------------------
// Opening transition seeding (CRITICAL SEMANTICS 3)
// ---------------------------------------------------------------------------

/// Select the opening transition from `candidates` by the contract's total
/// order and derive the episode fingerprint it seeds.
///
/// The winner is chosen by `(effective_at, provider_order, source_fact_id)`
/// via [`select_opening_transition`] — the order candidates were RECEIVED in
/// never participates, because no receipt-order field exists on the
/// candidate type at all. Ingesting the same facts in a different sequence
/// therefore cannot move the returned fingerprint.
pub fn seed_episode_fingerprint(
    family_fingerprint: DiscrepancyFamilyFingerprintV1,
    continuity_key: &[ApplicabilityDimensionV1],
    episode_policy_version: u32,
    candidates: &[OpeningTransitionCandidateV1],
) -> ContractResult<(
    OpeningTransitionCandidateV1,
    DiscrepancyEpisodeFingerprintV1,
)> {
    let winner = select_opening_transition(candidates)?.clone();
    let fingerprint = DiscrepancyEpisodePreimageV1 {
        schema_version: DISCREPANCY_RUNTIME_SCHEMA_VERSION,
        family_fingerprint,
        continuity_key: continuity_key.to_vec(),
        opening_transition_source_fact_id: winner.source_fact_id,
        episode_policy_version,
    }
    .fingerprint()?;
    Ok((winner, fingerprint))
}

// ---------------------------------------------------------------------------
// Deterministic ledger projection (REPLAY-01)
// ---------------------------------------------------------------------------

/// The evaluation instant the durable projection is computed at: the latest
/// instant the log itself knows about — the envelope's `detected_at` or the
/// newest lifecycle `effective_at`, whichever is later.
///
/// Deliberately NOT a wall clock: a projection stored under this instant is
/// a total function of the durable log, so a rebuild from the database
/// reproduces it byte for byte no matter when the rebuild runs. A caller
/// that wants "as of now" semantics (e.g. to observe a waiver expiring with
/// no intervening event) calls the contract's
/// [`project_discrepancy_episode`] directly with its own evaluation time;
/// the LEDGER's stored state only ever advances when the log advances.
#[must_use]
pub fn ledger_evaluation_time(
    envelope: &DiscrepancyEnvelopeV1,
    events: &[DiscrepancyLifecycleEventV1],
) -> CanonicalTimestamp {
    let mut latest = envelope.detected_at.clone();
    for event in events {
        if event.effective_at > latest {
            latest = event.effective_at.clone();
        }
    }
    latest
}

/// Replay one envelope's lifecycle events and family relations into the
/// deterministic ledger projection, returning it with the evaluation instant
/// it was computed at.
///
/// Order-independent by construction: the underlying contract replay orders
/// events by `(effective_at, canonical bytes)` and the evaluation instant is
/// a maximum over a set, so any permutation of `events` — including a late
/// event whose `effective_at` precedes an already-applied one arriving last
/// — produces the identical projection.
pub fn project_ledger_episode(
    envelope: &DiscrepancyEnvelopeV1,
    events: &[DiscrepancyLifecycleEventV1],
    relations: &[DiscrepancyEpisodeRelationV1],
) -> ContractResult<(DiscrepancyEpisodeProjectionV1, CanonicalTimestamp)> {
    let evaluated_at = ledger_evaluation_time(envelope, events);
    let projection = project_discrepancy_episode(envelope, events, relations, &evaluated_at)?;
    Ok((projection, evaluated_at))
}

#[cfg(test)]
#[path = "projection_tests.rs"]
mod tests;
