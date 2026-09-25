//! The two sides of one spec comparison, each with its own coverage bound
//! (Stage 6).
//!
//! A spec check compares what the active statement requires with what the
//! observer verified, through the discrepancy runtime's
//! [`ComparisonSideProvider`] seam. Both providers here are synchronous over
//! data the check has already loaded, and each states its own coverage
//! honestly, so [`compare_spec_sides`] can reach a verdict only when both
//! sides really were measured over the compared instant:
//!
//! * [`NormativeStatementSide`] is complete only when the family's projection
//!   resolves to exactly this statement at the compared instant. A contested
//!   family, no binding, or another statement leaves it unmeasured with
//!   unknown coverage. Its window is `[effective_from, min(effective_until,
//!   known_through))`: the statement's own interval, cut at the instant the
//!   projection was read, because nothing later is known.
//! * [`ObservedMembershipSide`] is complete only for a verified observation.
//!   An unverified one is unmeasured, with partial coverage when the read was
//!   not exhaustive and unknown coverage when it was (an exhaustive read that
//!   did not find the member still verifies nothing under the
//!   `positive_verified` admission). Its window starts at the observed
//!   commit's own instant and never ends: the content of an immutable commit
//!   does not go stale.
//!
//! Both sides hold [`membership_value_digest`] values: the normative side
//! digests the membership the expectation requires, the observed side the
//! membership the observer verified, so the comparison is by value.
//!
//! The compared interval is one microsecond starting at `t = max(statement
//! effective_from, observed commit instant)` ([`compared_window`]): a commit
//! older than the statement is judged at the instant the statement took
//! effect, which is what lets an old commit be checked against the spec in
//! force now.

use chrono::{DateTime, TimeDelta, Utc};

use crate::discrepancy_runtime::{
    ComparisonIndeterminacyV1, ComparisonSideProvider, ComparisonSideRoleV1, ComparisonVerdictV1,
    MeasuredComparisonSideV1, compare_sides,
};
use crate::memory_contracts::common::CanonicalTimestamp;
use crate::memory_contracts::coverage::{
    CoverageCompletenessV1, CoverageWindowV1, FreshnessStateV1,
};
use crate::memory_contracts::digest::Sha256Digest;
use crate::memory_contracts::normative_v2::NormativeBindingProposalV2;
use crate::memory_contracts::observer::{EvaluatedConditionV1, VerificationOutcomeV1};
use crate::memory_contracts::{ContractError, ContractResult};
use crate::normative_runtime::{NormativeFamilyProjectionV1, NormativePointResolutionV1};
use crate::observer_runtime::ObserverRunRecordV1;

use super::expectation::{RememberActionExpectationV1, membership_value_digest};
use super::record::SpecVerdictV1;

/// The end of an interval that never ends: the last representable instant.
pub const OPEN_ENDED_AT: &str = "9999-12-31T23:59:59.999999999Z";

/// The normative side: what the statement requires, measured through its
/// binding family's projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormativeStatementSide {
    /// The binding family's projection, as read.
    pub projection: NormativeFamilyProjectionV1,
    /// The statement being checked.
    pub statement_id: Sha256Digest,
    /// What the statement requires.
    pub expectation: RememberActionExpectationV1,
    pub effective_from: CanonicalTimestamp,
    pub effective_until: Option<CanonicalTimestamp>,
    /// The instant the projection was read as of: nothing after it is known.
    pub known_through: CanonicalTimestamp,
}

impl NormativeStatementSide {
    /// The side of `statement_id`, whose proposal is `proposal`, as
    /// `projection` stands at `known_through`.
    #[must_use]
    pub fn new(
        projection: NormativeFamilyProjectionV1,
        statement_id: Sha256Digest,
        proposal: &NormativeBindingProposalV2,
        expectation: RememberActionExpectationV1,
        known_through: CanonicalTimestamp,
    ) -> Self {
        Self {
            projection,
            statement_id,
            expectation,
            effective_from: proposal.effective_from.clone(),
            effective_until: proposal.effective_until.clone(),
            known_through,
        }
    }

    /// The interval this side actually covers: the statement's own interval
    /// cut at [`Self::known_through`]. When that leaves nothing (the
    /// projection was read before the statement took effect), the window is
    /// the microsecond before `known_through`, which no compared interval at
    /// or after `effective_from` can fall inside.
    fn measured_window(&self) -> ContractResult<CoverageWindowV1> {
        let known_until = match &self.effective_until {
            Some(until) if until < &self.known_through => until.clone(),
            _ => self.known_through.clone(),
        };
        if known_until > self.effective_from {
            return Ok(CoverageWindowV1 {
                window_start: self.effective_from.clone(),
                window_end: known_until,
            });
        }
        Ok(CoverageWindowV1 {
            window_start: shift_micros(&known_until, -1)?,
            window_end: known_until,
        })
    }
}

impl ComparisonSideProvider for NormativeStatementSide {
    fn measure(&self, compared: &CoverageWindowV1) -> ContractResult<MeasuredComparisonSideV1> {
        let bound = self.projection.resolve_at(&compared.window_start)
            == NormativePointResolutionV1::Bound(self.statement_id);
        Ok(MeasuredComparisonSideV1 {
            role: ComparisonSideRoleV1::Normative,
            measured_window: self.measured_window()?,
            completeness: if bound {
                CoverageCompletenessV1::Complete
            } else {
                CoverageCompletenessV1::Unknown
            },
            freshness: FreshnessStateV1::Current,
            value_digest: bound.then(|| {
                membership_value_digest(
                    &self.expectation.enum_name,
                    &self.expectation.member,
                    self.expectation.expected.is_present(),
                )
            }),
        })
    }
}

/// The observed side: what one observer run verified about the member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedMembershipSide {
    /// The enum the run read, as the expectation names it.
    pub enum_name: String,
    /// The member the run was asked about.
    pub member: String,
    pub evaluated_condition: EvaluatedConditionV1,
    pub verification_outcome: VerificationOutcomeV1,
    /// The observed commit's own instant (the result's `effective_at`).
    pub observed_at: CanonicalTimestamp,
    /// Whether the read enumerated the whole enum.
    pub exhaustive: bool,
}

impl ObservedMembershipSide {
    /// The side one run record measured for `expectation`'s member.
    #[must_use]
    pub fn from_run(
        record: &ObserverRunRecordV1,
        expectation: &RememberActionExpectationV1,
    ) -> Self {
        Self {
            enum_name: expectation.enum_name.clone(),
            member: expectation.member.clone(),
            evaluated_condition: record.result.evaluated_condition,
            verification_outcome: record.result.verification_outcome,
            observed_at: record.result.effective_at.clone(),
            exhaustive: record.exhaustive,
        }
    }

    /// `Some(true)` for a verified presence, `Some(false)` for a verified
    /// absence, `None` when the run verified nothing about the member.
    #[must_use]
    pub const fn verified_presence(&self) -> Option<bool> {
        match (self.verification_outcome, self.evaluated_condition) {
            (VerificationOutcomeV1::VerifiedPositive, EvaluatedConditionV1::Present) => Some(true),
            (VerificationOutcomeV1::VerifiedNegative, EvaluatedConditionV1::Absent) => Some(false),
            _ => None,
        }
    }
}

impl ComparisonSideProvider for ObservedMembershipSide {
    fn measure(&self, _compared: &CoverageWindowV1) -> ContractResult<MeasuredComparisonSideV1> {
        let verified = self.verified_presence();
        let completeness = match (verified, self.exhaustive) {
            (Some(_), _) => CoverageCompletenessV1::Complete,
            (None, false) => CoverageCompletenessV1::Partial,
            (None, true) => CoverageCompletenessV1::Unknown,
        };
        Ok(MeasuredComparisonSideV1 {
            role: ComparisonSideRoleV1::Observed,
            measured_window: CoverageWindowV1 {
                window_start: self.observed_at.clone(),
                window_end: CanonicalTimestamp::parse(OPEN_ENDED_AT)?,
            },
            completeness,
            freshness: FreshnessStateV1::Current,
            value_digest: verified
                .map(|present| membership_value_digest(&self.enum_name, &self.member, present)),
        })
    }
}

/// The interval one check compares over: `[t, t + 1µs)`, where
/// `t = max(effective_from, observed_at)`.
///
/// # Errors
///
/// A contract error when `t` is the last representable instant.
pub fn compared_window(
    effective_from: &CanonicalTimestamp,
    observed_at: &CanonicalTimestamp,
) -> ContractResult<CoverageWindowV1> {
    let at = effective_from.max(observed_at).clone();
    Ok(CoverageWindowV1 {
        window_end: shift_micros(&at, 1)?,
        window_start: at,
    })
}

/// Compare both sides over [`compared_window`], returning the window and the
/// verdict.
///
/// # Errors
///
/// A contract error for a side whose measurement is malformed.
pub fn compare_spec_sides(
    normative: &NormativeStatementSide,
    observed: &ObservedMembershipSide,
) -> ContractResult<(CoverageWindowV1, ComparisonVerdictV1)> {
    let compared = compared_window(&normative.effective_from, &observed.observed_at)?;
    let verdict = compare_sides(&compared, observed, normative)?;
    Ok((compared, verdict))
}

/// The spec verdict a comparison reached, with the reasons an unknown one
/// could not conclude (sorted, and empty for every other verdict).
#[must_use]
pub fn spec_verdict(
    verdict: &ComparisonVerdictV1,
) -> (SpecVerdictV1, Vec<ComparisonIndeterminacyV1>) {
    match verdict {
        ComparisonVerdictV1::Discrepant => (SpecVerdictV1::Nonconforming, Vec::new()),
        ComparisonVerdictV1::NoDiscrepancy => (SpecVerdictV1::Conforming, Vec::new()),
        ComparisonVerdictV1::Indeterminate { reasons } => (SpecVerdictV1::Unknown, reasons.clone()),
    }
}

/// `at` moved by `micros` microseconds.
pub(crate) fn shift_micros(
    at: &CanonicalTimestamp,
    micros: i64,
) -> ContractResult<CanonicalTimestamp> {
    let parsed = DateTime::parse_from_rfc3339(at.as_str())
        .map_err(|_| ContractError::Schema("timestamp is not canonical UTC".into()))?
        .with_timezone(&Utc);
    let moved = parsed
        .checked_add_signed(TimeDelta::microseconds(micros))
        .ok_or_else(|| ContractError::Schema("timestamp moved out of range".into()))?;
    CanonicalTimestamp::from_datetime(&moved)
}

#[cfg(test)]
#[path = "providers_tests.rs"]
mod tests;
