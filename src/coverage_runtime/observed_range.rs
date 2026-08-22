//! Pure coverage-range algebra for the coverage runtime (COVER-01..03).
//!
//! A connector instance observes a source over half-open provider-sequence
//! intervals `[start, end)`. This module keeps the merged union of every
//! interval observed so far for one coverage domain and answers two questions
//! about it against a fixed target interval, with no I/O and no default arm:
//!
//! * [`ObservedRangeV1::completeness_over`] — is the target fully observed
//!   ([`CoverageCompletenessV1::Complete`]), observed with a hole
//!   ([`CoverageCompletenessV1::Partial`]), or not observed at all
//!   ([`CoverageCompletenessV1::Unknown`])? These are exactly the three words
//!   the coverage runtime brief fixes: "a gap in observed range surfaces as
//!   'partial', an unobserved region as 'unknown', a fully-observed contiguous
//!   range as 'complete'."
//! * [`ObservedRangeV1::continuity_over`] — does the observed portion of the
//!   target have a known internal gap ([`SequenceContinuityV1::GapDetected`])
//!   or not ([`SequenceContinuityV1::Contiguous`])? Completeness and continuity
//!   are separate witnesses (COVER-03): a value can be `partial` and yet
//!   contiguous (a clean prefix), or carry a detected gap.
//!
//! The union is always kept sorted, disjoint, and non-adjacent (adjacent
//! intervals are coalesced), so "one interval that equals the target" is the
//! sole shape that means fully covered, and "more than one interval touching
//! the target" is the sole shape that means a hole.

use serde::{Deserialize, Serialize};

use crate::memory_contracts::coverage::{
    CoverageCompletenessV1, CoverageWatermarkV1, SequenceContinuityV1, SequenceGapV1,
};

/// Error returned when an interval or an observed range is not well-formed.
///
/// Every constructor and mutator fails closed on a degenerate interval rather
/// than silently normalizing it: an empty or inverted `[start, end)` is never
/// coverage of anything, and admitting one would let a caller claim coverage
/// it never had.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObservedRangeError {
    /// `end <= start`: the interval covers nothing.
    EmptyInterval { start: u64, end: u64 },
    /// A persisted union violated the sorted/disjoint/non-adjacent invariant.
    MalformedUnion(String),
}

impl std::fmt::Display for ObservedRangeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyInterval { start, end } => write!(
                formatter,
                "observed interval [{start}, {end}) is empty or inverted"
            ),
            Self::MalformedUnion(reason) => {
                write!(formatter, "persisted observed range is malformed: {reason}")
            }
        }
    }
}

impl std::error::Error for ObservedRangeError {}

/// A half-open `[start, end)` interval over provider-sequence space, `start < end`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SequenceIntervalV1 {
    pub start: u64,
    pub end: u64,
}

impl SequenceIntervalV1 {
    /// Construct a non-empty half-open interval, failing closed on `end <= start`.
    pub const fn new(start: u64, end: u64) -> Result<Self, ObservedRangeError> {
        if end <= start {
            return Err(ObservedRangeError::EmptyInterval { start, end });
        }
        Ok(Self { start, end })
    }
}

/// What one [`ObservedRangeV1::insert`] did to the union.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertOutcome {
    /// The interval added coverage the union did not already have.
    Extended,
    /// The interval was already wholly inside the union: nothing changed.
    ///
    /// This is the coverage-runtime idempotency signal: re-observing an
    /// already-covered range must not advance the cursor or mint a receipt.
    Redundant,
}

/// The merged union of every observed interval for one coverage domain.
///
/// Kept sorted, pairwise-disjoint, and non-adjacent by every mutator; the
/// invariant is re-checked by [`Self::validate`] on load so a tampered
/// persisted blob fails closed rather than corrupting a coverage verdict.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedRangeV1 {
    intervals: Vec<SequenceIntervalV1>,
}

impl ObservedRangeV1 {
    /// The empty union: nothing observed yet.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            intervals: Vec::new(),
        }
    }

    /// Borrow the merged intervals (sorted, disjoint, non-adjacent).
    #[must_use]
    pub fn intervals(&self) -> &[SequenceIntervalV1] {
        &self.intervals
    }

    /// Re-check the sorted / disjoint / non-adjacent invariant of a value that
    /// was decoded from persistence. A stored blob that violates it is a
    /// tamper or a bug, never a coverage verdict this module will trust.
    pub fn validate(&self) -> Result<(), ObservedRangeError> {
        let mut previous_end: Option<u64> = None;
        for interval in &self.intervals {
            if interval.end <= interval.start {
                return Err(ObservedRangeError::MalformedUnion(format!(
                    "interval [{}, {}) is empty or inverted",
                    interval.start, interval.end
                )));
            }
            if let Some(previous_end) = previous_end {
                // Strictly greater than the previous end: sorted AND
                // non-adjacent (an adjacent pair should have been coalesced).
                if interval.start <= previous_end {
                    return Err(ObservedRangeError::MalformedUnion(format!(
                        "interval starting at {} is not strictly after the previous end {previous_end}",
                        interval.start
                    )));
                }
            }
            previous_end = Some(interval.end);
        }
        Ok(())
    }

    /// Merge one observed interval into the union.
    ///
    /// Returns [`InsertOutcome::Redundant`] iff the interval was already wholly
    /// covered (so the union is byte-for-byte unchanged), and
    /// [`InsertOutcome::Extended`] otherwise. Fails closed on an empty or
    /// inverted interval.
    pub fn insert(
        &mut self,
        interval: SequenceIntervalV1,
    ) -> Result<InsertOutcome, ObservedRangeError> {
        if interval.end <= interval.start {
            return Err(ObservedRangeError::EmptyInterval {
                start: interval.start,
                end: interval.end,
            });
        }
        if self.covers(interval) {
            return Ok(InsertOutcome::Redundant);
        }
        // Coalesce: absorb every existing interval that overlaps or is adjacent
        // to the growing merged interval, and keep the rest in sorted order.
        let mut merged_start = interval.start;
        let mut merged_end = interval.end;
        let mut result: Vec<SequenceIntervalV1> = Vec::with_capacity(self.intervals.len() + 1);
        let mut inserted = false;
        for existing in &self.intervals {
            if existing.end < merged_start || existing.start > merged_end {
                // Fully disjoint and non-adjacent from the merged interval.
                if existing.start > merged_end && !inserted {
                    result.push(SequenceIntervalV1 {
                        start: merged_start,
                        end: merged_end,
                    });
                    inserted = true;
                }
                result.push(*existing);
            } else {
                // Overlaps or is adjacent: absorb it.
                merged_start = merged_start.min(existing.start);
                merged_end = merged_end.max(existing.end);
            }
        }
        if !inserted {
            result.push(SequenceIntervalV1 {
                start: merged_start,
                end: merged_end,
            });
        }
        self.intervals = result;
        Ok(InsertOutcome::Extended)
    }

    /// Whether the union already wholly covers `interval`.
    fn covers(&self, interval: SequenceIntervalV1) -> bool {
        self.intervals
            .iter()
            .any(|existing| existing.start <= interval.start && existing.end >= interval.end)
    }

    /// The observed sub-intervals restricted to (clipped against) the target.
    fn covered_within(&self, target: SequenceIntervalV1) -> Vec<SequenceIntervalV1> {
        let mut covered = Vec::new();
        for interval in &self.intervals {
            let start = interval.start.max(target.start);
            let end = interval.end.min(target.end);
            if start < end {
                covered.push(SequenceIntervalV1 { start, end });
            }
        }
        covered
    }

    /// Coverage completeness of `target` given everything observed so far.
    ///
    /// * [`CoverageCompletenessV1::Complete`] — the target is wholly observed
    ///   as one contiguous run.
    /// * [`CoverageCompletenessV1::Partial`] — some of the target is observed
    ///   but not all of it.
    /// * [`CoverageCompletenessV1::Unknown`] — none of the target is observed.
    ///
    /// There is deliberately no default arm and no path that upgrades
    /// `partial`/`unknown` to `complete` (PRED-03).
    #[must_use]
    pub fn completeness_over(&self, target: SequenceIntervalV1) -> CoverageCompletenessV1 {
        let covered = self.covered_within(target);
        match covered.as_slice() {
            [] => CoverageCompletenessV1::Unknown,
            [only] if only.start == target.start && only.end == target.end => {
                CoverageCompletenessV1::Complete
            }
            _ => CoverageCompletenessV1::Partial,
        }
    }

    /// Sequence continuity of the observed portion of `target` (COVER-03).
    ///
    /// Reports [`SequenceContinuityV1::GapDetected`] with the first hole's
    /// bounded extent when the observed portion breaks into more than one
    /// interval, and [`SequenceContinuityV1::Contiguous`] otherwise (including
    /// when nothing in the target is observed — there is then no observed
    /// sequence in which to detect a gap).
    #[must_use]
    pub fn continuity_over(&self, target: SequenceIntervalV1) -> SequenceContinuityV1 {
        let covered = self.covered_within(target);
        if covered.len() < 2 {
            return SequenceContinuityV1::Contiguous {};
        }
        // The union is disjoint and non-adjacent, so the first pair already
        // brackets a real, strictly-ordered hole: covered[0].end <
        // covered[1].start. That is exactly SequenceGapV1's provable extent.
        let gap_after = covered[0].end;
        let gap_before = covered[1].start;
        SequenceContinuityV1::GapDetected {
            gap: Some(SequenceGapV1 {
                gap_after: CoverageWatermarkV1::ProviderSequence {
                    sequence: gap_after,
                },
                gap_before: CoverageWatermarkV1::ProviderSequence {
                    sequence: gap_before,
                },
            }),
        }
    }

    /// The highest observed sequence, or `None` if nothing is observed. Used to
    /// stamp a receipt's provider-sequence watermark.
    #[must_use]
    pub fn high_watermark(&self) -> Option<u64> {
        self.intervals.last().map(|interval| interval.end)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn interval(start: u64, end: u64) -> SequenceIntervalV1 {
        SequenceIntervalV1::new(start, end).unwrap()
    }

    fn range(intervals: &[(u64, u64)]) -> ObservedRangeV1 {
        let mut range = ObservedRangeV1::empty();
        for &(start, end) in intervals {
            range.insert(interval(start, end)).unwrap();
        }
        range
    }

    #[test]
    fn empty_or_inverted_interval_is_rejected_closed() {
        assert_eq!(
            SequenceIntervalV1::new(5, 5),
            Err(ObservedRangeError::EmptyInterval { start: 5, end: 5 })
        );
        assert_eq!(
            SequenceIntervalV1::new(9, 3),
            Err(ObservedRangeError::EmptyInterval { start: 9, end: 3 })
        );
        let mut union = ObservedRangeV1::empty();
        assert!(matches!(
            union.insert(SequenceIntervalV1 { start: 5, end: 5 }),
            Err(ObservedRangeError::EmptyInterval { .. })
        ));
    }

    #[test]
    fn disjoint_inserts_stay_sorted_and_separate() {
        let union = range(&[(60, 100), (0, 40)]);
        assert_eq!(union.intervals(), &[interval(0, 40), interval(60, 100)]);
        union.validate().unwrap();
    }

    #[test]
    fn overlapping_and_adjacent_inserts_coalesce() {
        // Adjacent [0,40)+[40,60) coalesce to [0,60); overlapping [50,80)
        // extends it to [0,80).
        let union = range(&[(0, 40), (40, 60), (50, 80)]);
        assert_eq!(union.intervals(), &[interval(0, 80)]);
    }

    #[test]
    fn a_gap_filled_by_a_later_insert_becomes_one_interval() {
        let mut union = range(&[(0, 40), (60, 100)]);
        assert_eq!(
            union.insert(interval(40, 60)).unwrap(),
            InsertOutcome::Extended
        );
        assert_eq!(union.intervals(), &[interval(0, 100)]);
    }

    #[test]
    fn re_inserting_a_covered_range_is_redundant() {
        let mut union = range(&[(0, 100)]);
        assert_eq!(
            union.insert(interval(0, 100)).unwrap(),
            InsertOutcome::Redundant
        );
        assert_eq!(
            union.insert(interval(10, 90)).unwrap(),
            InsertOutcome::Redundant
        );
        // A range extending past the covered end is NOT redundant.
        assert_eq!(
            union.insert(interval(90, 120)).unwrap(),
            InsertOutcome::Extended
        );
    }

    #[test]
    fn completeness_complete_partial_unknown() {
        let target = interval(0, 100);

        // Fully observed contiguous range -> complete.
        assert_eq!(
            range(&[(0, 100)]).completeness_over(target),
            CoverageCompletenessV1::Complete
        );
        // Observed union extends beyond the target but still covers it whole.
        assert_eq!(
            range(&[(0, 200)]).completeness_over(target),
            CoverageCompletenessV1::Complete
        );

        // A hole inside the target -> partial.
        assert_eq!(
            range(&[(0, 40), (60, 100)]).completeness_over(target),
            CoverageCompletenessV1::Partial
        );
        // A clean prefix that never reaches the end -> partial (some observed).
        assert_eq!(
            range(&[(0, 40)]).completeness_over(target),
            CoverageCompletenessV1::Partial
        );

        // Nothing in the target observed -> unknown.
        assert_eq!(
            ObservedRangeV1::empty().completeness_over(target),
            CoverageCompletenessV1::Unknown
        );
        assert_eq!(
            range(&[(200, 300)]).completeness_over(target),
            CoverageCompletenessV1::Unknown
        );
    }

    #[test]
    fn continuity_flags_only_an_internal_hole() {
        let target = interval(0, 100);

        assert_eq!(
            range(&[(0, 100)]).continuity_over(target),
            SequenceContinuityV1::Contiguous {}
        );
        // A clean prefix is contiguous even though it is only partial.
        assert_eq!(
            range(&[(0, 40)]).continuity_over(target),
            SequenceContinuityV1::Contiguous {}
        );
        // Nothing observed -> no sequence to have a gap in.
        assert_eq!(
            ObservedRangeV1::empty().continuity_over(target),
            SequenceContinuityV1::Contiguous {}
        );

        match range(&[(0, 40), (60, 100)]).continuity_over(target) {
            SequenceContinuityV1::GapDetected { gap: Some(gap) } => {
                gap.validate().unwrap();
                assert_eq!(
                    gap.gap_after,
                    CoverageWatermarkV1::ProviderSequence { sequence: 40 }
                );
                assert_eq!(
                    gap.gap_before,
                    CoverageWatermarkV1::ProviderSequence { sequence: 60 }
                );
            }
            other => panic!("expected a detected gap, got {other:?}"),
        }
    }

    #[test]
    fn a_gap_outside_the_target_does_not_flag_continuity() {
        // Observed [0,100) then [200,300); the target is only [0,100), so the
        // gap at [100,200) is outside the target and continuity is contiguous.
        let target = interval(0, 100);
        assert_eq!(
            range(&[(0, 100), (200, 300)]).continuity_over(target),
            SequenceContinuityV1::Contiguous {}
        );
    }

    #[test]
    fn validate_rejects_a_tampered_persisted_union() {
        // Not sorted / overlapping.
        let overlapping = ObservedRangeV1 {
            intervals: vec![interval(0, 50), interval(40, 90)],
        };
        assert!(overlapping.validate().is_err());
        // Adjacent (should have been coalesced).
        let adjacent = ObservedRangeV1 {
            intervals: vec![interval(0, 40), interval(40, 80)],
        };
        assert!(adjacent.validate().is_err());
        // Inverted interval.
        let inverted = ObservedRangeV1 {
            intervals: vec![SequenceIntervalV1 { start: 90, end: 10 }],
        };
        assert!(inverted.validate().is_err());
    }

    #[test]
    fn high_watermark_tracks_the_last_end() {
        assert_eq!(ObservedRangeV1::empty().high_watermark(), None);
        assert_eq!(range(&[(0, 40), (60, 100)]).high_watermark(), Some(100));
    }

    #[test]
    fn json_round_trips_and_revalidates() {
        let union = range(&[(0, 40), (60, 100)]);
        let bytes = serde_json::to_vec(&union).unwrap();
        let decoded: ObservedRangeV1 = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded, union);
        decoded.validate().unwrap();
    }
}
