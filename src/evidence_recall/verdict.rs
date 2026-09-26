//! The pure parts of an evidence answer: what the fused lanes said about a
//! hit, and what an empty answer means.

use std::collections::BTreeSet;

use crate::memory_contracts::coverage::CoverageCompletenessV1;
use crate::memory_contracts::digest::Sha256Digest;
use crate::projectors::FusedHitV1;
use crate::worker::WorkerSourceOutcomeV1;

use super::{
    AbsenceReasonV1, AbsenceV1, AbsenceVerdictV1, EvidenceMatchV1, EvidenceReadinessV1,
    EvidenceSourcesV1,
};

/// A fused hit before hydration: the body, the lanes that matched it after
/// the lexical cutoff and the dense floor (both applied by
/// [`crate::projectors::fuse_lanes`]), their scores, and the fused score.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(super) struct ScoredHitV1 {
    pub(super) id: Sha256Digest,
    pub(super) score: f32,
    pub(super) matched_by: EvidenceMatchV1,
    pub(super) lexical_score: Option<f32>,
    pub(super) dense_similarity: Option<f32>,
}

impl From<FusedHitV1<Sha256Digest>> for ScoredHitV1 {
    fn from(hit: FusedHitV1<Sha256Digest>) -> Self {
        Self {
            id: hit.key,
            score: hit.score,
            matched_by: lane_match(hit.lexical_rank.is_some(), hit.dense_rank.is_some()),
            lexical_score: hit.lexical_score,
            dense_similarity: hit.dense_similarity,
        }
    }
}

/// Which lanes matched a fused hit.
///
/// A fused hit was matched by at least one lane, so `(false, false)` cannot
/// arise from fusion; it is read as a lexical match rather than invented as
/// a variant of its own.
#[must_use]
pub const fn lane_match(lexical: bool, dense: bool) -> EvidenceMatchV1 {
    match (lexical, dense) {
        (true, true) => EvidenceMatchV1::LexicalAndDense,
        (false, true) => EvidenceMatchV1::Dense,
        (_, false) => EvidenceMatchV1::Lexical,
    }
}

/// What an answer with `hit_count` hits means, given what was read before the
/// lanes ran. See the module documentation of `evidence_recall` for the rule.
#[must_use]
pub fn absence_verdict(
    hit_count: usize,
    lexical_terms: bool,
    readiness: &EvidenceReadinessV1,
    sources: &EvidenceSourcesV1,
) -> AbsenceV1 {
    let as_of = sources
        .active
        .iter()
        .filter_map(|source| source.last_checked_at)
        .min();
    if hit_count > 0 {
        return AbsenceV1 {
            verdict: AbsenceVerdictV1::Present,
            reasons: Vec::new(),
            as_of,
        };
    }
    let mut reasons = BTreeSet::new();
    if !lexical_terms {
        reasons.insert(AbsenceReasonV1::QueryHasNoLexicalTerms);
    }
    if readiness.events_awaiting_body_projection > 0 {
        reasons.insert(AbsenceReasonV1::BodyProjectionLag);
    }
    if readiness.transcript_turns_awaiting_admission > 0
        || readiness
            .items_awaiting_admission
            .is_some_and(|pending| pending > 0)
        || readiness
            .hints_awaiting_fetch
            .is_some_and(|pending| pending > 0)
    {
        reasons.insert(AbsenceReasonV1::IngestOutboxPending);
    }
    // An unreadable hint queue is collector state this login cannot read: a
    // signed change may be waiting unseen.
    if readiness.collector_state_unreadable || readiness.hints_unreadable {
        reasons.insert(AbsenceReasonV1::CollectorStateUnreadable);
    }
    if !readiness.lexical_current {
        reasons.insert(AbsenceReasonV1::LexicalProjectionLag);
    }
    if sources.active.is_empty() {
        reasons.insert(AbsenceReasonV1::NoSourcesRegistered);
    }
    for source in &sources.active {
        if source.last_outcome == WorkerSourceOutcomeV1::Failed {
            reasons.insert(AbsenceReasonV1::SourceFailed);
        }
        if source.last_checked_at.is_none() {
            reasons.insert(AbsenceReasonV1::SourceNeverChecked);
        } else if source.stale {
            reasons.insert(AbsenceReasonV1::SourceStale);
        }
        if !source
            .coverage
            .as_ref()
            .is_some_and(|coverage| coverage.completeness == CoverageCompletenessV1::Complete)
        {
            reasons.insert(AbsenceReasonV1::IncompleteCoverage);
        }
    }
    if sources.truncated {
        reasons.insert(AbsenceReasonV1::ListingTruncated);
    }
    AbsenceV1 {
        verdict: if reasons.is_empty() {
            AbsenceVerdictV1::Absent
        } else {
            AbsenceVerdictV1::Unknown
        },
        reasons: reasons.into_iter().collect(),
        as_of,
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};

    use super::super::{
        EvidenceCoverageV1, EvidenceDenseLaneV1, EvidenceSourceKindV1, EvidenceSourceV1,
        EvidenceSourcesV1,
    };
    use super::*;

    fn instant(seconds: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_790_000_000 + seconds, 0).unwrap()
    }

    fn current() -> EvidenceReadinessV1 {
        EvidenceReadinessV1 {
            events_awaiting_body_projection: 0,
            transcript_turns_awaiting_admission: 0,
            items_awaiting_admission: None,
            hints_awaiting_fetch: None,
            hints_unreadable: false,
            collector_state_unreadable: false,
            lexical_current: true,
            dense_current: true,
            dense_lane: EvidenceDenseLaneV1::NoQueryVector,
            as_of: instant(100),
        }
    }

    fn healthy(instance: &str, checked: i64) -> EvidenceSourceV1 {
        EvidenceSourceV1 {
            connector_instance: instance.to_owned(),
            kind: EvidenceSourceKindV1::Git,
            provider: None,
            state: "active".to_owned(),
            last_outcome: WorkerSourceOutcomeV1::Unchanged,
            last_checked_at: Some(instant(checked)),
            last_error: None,
            stale: false,
            coverage: Some(EvidenceCoverageV1 {
                completeness: CoverageCompletenessV1::Complete,
                observed: vec![[1, 2]],
                target: [1, 2],
                as_of: instant(checked - 10),
            }),
        }
    }

    fn listing(active: Vec<EvidenceSourceV1>) -> EvidenceSourcesV1 {
        EvidenceSourcesV1 {
            active,
            truncated: false,
        }
    }

    fn two_healthy() -> EvidenceSourcesV1 {
        listing(vec![
            healthy("connector.git.a", 50),
            healthy("connector.ci.b", 40),
        ])
    }

    fn reasons(
        lexical_terms: bool,
        readiness: &EvidenceReadinessV1,
        sources: &EvidenceSourcesV1,
    ) -> Vec<AbsenceReasonV1> {
        let absence = absence_verdict(0, lexical_terms, readiness, sources);
        assert_eq!(
            absence.verdict == AbsenceVerdictV1::Absent,
            absence.reasons.is_empty(),
            "a verdict is absent exactly when no reason applies"
        );
        absence.reasons
    }

    #[test]
    fn a_hit_is_present_whatever_else_holds() {
        let mut lagging = current();
        lagging.events_awaiting_body_projection = 3;
        lagging.lexical_current = false;
        let absence = absence_verdict(1, false, &lagging, &listing(Vec::new()));
        assert_eq!(absence.verdict, AbsenceVerdictV1::Present);
        assert!(absence.reasons.is_empty());
    }

    #[test]
    fn no_hit_over_a_current_fresh_complete_scope_is_absent() {
        let absence = absence_verdict(0, true, &current(), &two_healthy());
        assert_eq!(absence.verdict, AbsenceVerdictV1::Absent);
        assert_eq!(
            absence.as_of,
            Some(instant(40)),
            "as_of is the oldest check"
        );
    }

    #[test]
    fn dense_lag_alone_still_allows_absent() {
        let mut readiness = current();
        readiness.dense_current = false;
        readiness.dense_lane = EvidenceDenseLaneV1::DisabledForeignModel;
        assert!(reasons(true, &readiness, &two_healthy()).is_empty());
    }

    #[test]
    fn each_readiness_gap_alone_is_its_own_reason() {
        let sources = two_healthy();
        assert_eq!(
            reasons(false, &current(), &sources),
            [AbsenceReasonV1::QueryHasNoLexicalTerms]
        );

        let mut bodies = current();
        bodies.events_awaiting_body_projection = 1;
        assert_eq!(
            reasons(true, &bodies, &sources),
            [AbsenceReasonV1::BodyProjectionLag]
        );

        let mut outbox = current();
        outbox.transcript_turns_awaiting_admission = 2;
        assert_eq!(
            reasons(true, &outbox, &sources),
            [AbsenceReasonV1::IngestOutboxPending]
        );

        let mut lexical = current();
        lexical.lexical_current = false;
        assert_eq!(
            reasons(true, &lexical, &sources),
            [AbsenceReasonV1::LexicalProjectionLag]
        );
    }

    #[test]
    fn a_scope_with_no_active_source_is_unknown() {
        assert_eq!(
            reasons(true, &current(), &listing(Vec::new())),
            [AbsenceReasonV1::NoSourcesRegistered]
        );
    }

    #[test]
    fn a_failed_source_is_unknown_even_after_an_earlier_complete_check() {
        let mut sources = two_healthy();
        sources.active[1].last_outcome = WorkerSourceOutcomeV1::Failed;
        sources.active[1].last_error = Some("gh: not found".to_owned());
        assert_eq!(
            reasons(true, &current(), &sources),
            [AbsenceReasonV1::SourceFailed]
        );
    }

    #[test]
    fn a_stale_source_is_unknown() {
        let mut sources = two_healthy();
        sources.active[0].stale = true;
        assert_eq!(
            reasons(true, &current(), &sources),
            [AbsenceReasonV1::SourceStale]
        );
    }

    #[test]
    fn a_source_that_never_completed_a_check_is_unknown() {
        let mut sources = two_healthy();
        let never = &mut sources.active[0];
        never.last_outcome = WorkerSourceOutcomeV1::Failed;
        never.last_checked_at = None;
        never.coverage = None;
        assert_eq!(
            reasons(true, &current(), &sources),
            [
                AbsenceReasonV1::SourceFailed,
                AbsenceReasonV1::SourceNeverChecked,
                AbsenceReasonV1::IncompleteCoverage,
            ]
        );
        assert_eq!(
            absence_verdict(0, true, &current(), &sources).as_of,
            Some(instant(40)),
            "a source never checked does not set as_of"
        );
    }

    #[test]
    fn a_source_without_a_complete_newest_cursor_is_unknown() {
        let mut missing = two_healthy();
        missing.active[0].coverage = None;
        assert_eq!(
            reasons(true, &current(), &missing),
            [AbsenceReasonV1::IncompleteCoverage]
        );

        for completeness in [
            CoverageCompletenessV1::Partial,
            CoverageCompletenessV1::Unknown,
        ] {
            let mut partial = two_healthy();
            partial.active[1].coverage.as_mut().unwrap().completeness = completeness;
            assert_eq!(
                reasons(true, &current(), &partial),
                [AbsenceReasonV1::IncompleteCoverage]
            );
        }
    }

    #[test]
    fn a_source_of_a_kind_this_build_does_not_know_still_gates_absence() {
        let other = || EvidenceSourceKindV1::Other("collected.slack".to_owned());
        let mut sources = two_healthy();
        sources.active[1].kind = other();
        // Healthy, it is one more fresh, complete source.
        assert!(reasons(true, &current(), &sources).is_empty());

        let mut failed = sources.clone();
        failed.active[1].last_outcome = WorkerSourceOutcomeV1::Failed;
        assert_eq!(
            reasons(true, &current(), &failed),
            [AbsenceReasonV1::SourceFailed]
        );

        let mut stale = sources.clone();
        stale.active[1].stale = true;
        assert_eq!(
            reasons(true, &current(), &stale),
            [AbsenceReasonV1::SourceStale]
        );

        let mut never = sources.clone();
        never.active[1].last_checked_at = None;
        assert_eq!(
            reasons(true, &current(), &never),
            [AbsenceReasonV1::SourceNeverChecked]
        );

        let mut incomplete = sources;
        incomplete.active[1].coverage.as_mut().unwrap().completeness =
            CoverageCompletenessV1::Partial;
        let absence = absence_verdict(0, true, &current(), &incomplete);
        assert_eq!(absence.verdict, AbsenceVerdictV1::Unknown);
        assert_eq!(absence.reasons, [AbsenceReasonV1::IncompleteCoverage]);

        // And alone in the listing it is still a registered source.
        let mut alone = listing(vec![healthy("collected.slack.acme", 50)]);
        alone.active[0].kind = other();
        alone.active[0].stale = true;
        assert_eq!(
            reasons(true, &current(), &alone),
            [AbsenceReasonV1::SourceStale]
        );
    }

    #[test]
    fn pending_collected_items_make_an_empty_answer_unknown() {
        let mut readiness = current();
        readiness.items_awaiting_admission = Some(0);
        assert!(reasons(true, &readiness, &two_healthy()).is_empty());
        readiness.items_awaiting_admission = Some(3);
        assert_eq!(
            reasons(true, &readiness, &two_healthy()),
            [AbsenceReasonV1::IngestOutboxPending]
        );
    }

    #[test]
    fn a_hint_awaiting_its_fetch_makes_an_empty_answer_unknown() {
        let mut readiness = current();
        readiness.hints_awaiting_fetch = Some(0);
        assert!(reasons(true, &readiness, &two_healthy()).is_empty());
        readiness.hints_awaiting_fetch = Some(1);
        assert_eq!(
            reasons(true, &readiness, &two_healthy()),
            [AbsenceReasonV1::IngestOutboxPending]
        );
    }

    #[test]
    fn a_hint_queue_this_login_cannot_read_is_unknown_never_absent() {
        let mut readiness = current();
        readiness.hints_unreadable = true;
        assert_eq!(
            reasons(true, &readiness, &two_healthy()),
            [AbsenceReasonV1::CollectorStateUnreadable]
        );
    }

    #[test]
    fn unreadable_collector_state_is_unknown_never_absent() {
        let mut readiness = current();
        readiness.collector_state_unreadable = true;
        assert_eq!(
            reasons(true, &readiness, &two_healthy()),
            [AbsenceReasonV1::CollectorStateUnreadable]
        );
        // A hit is still present: only the empty answer loses its meaning.
        assert_eq!(
            absence_verdict(1, true, &readiness, &two_healthy()).verdict,
            AbsenceVerdictV1::Present
        );
    }

    #[test]
    fn a_collector_source_gates_absence_like_any_other() {
        let mut sources = two_healthy();
        let mut collector = healthy("docs.specs", 45);
        collector.kind = EvidenceSourceKindV1::Collector;
        collector.provider = Some("docs".to_owned());
        sources.active.push(collector);
        assert!(reasons(true, &current(), &sources).is_empty());
        sources.active[2].coverage = None;
        assert_eq!(
            reasons(true, &current(), &sources),
            [AbsenceReasonV1::IncompleteCoverage]
        );
    }

    #[test]
    fn a_truncated_listing_is_unknown() {
        let mut sources = two_healthy();
        sources.truncated = true;
        assert_eq!(
            reasons(true, &current(), &sources),
            [AbsenceReasonV1::ListingTruncated]
        );
    }

    #[test]
    fn every_gap_is_reported_at_once() {
        let mut readiness = current();
        readiness.events_awaiting_body_projection = 1;
        readiness.lexical_current = false;
        let mut sources = two_healthy();
        sources.active[0].stale = true;
        sources.active[1].last_outcome = WorkerSourceOutcomeV1::Failed;
        let found = reasons(false, &readiness, &sources);
        for expected in [
            AbsenceReasonV1::QueryHasNoLexicalTerms,
            AbsenceReasonV1::BodyProjectionLag,
            AbsenceReasonV1::LexicalProjectionLag,
            AbsenceReasonV1::SourceFailed,
            AbsenceReasonV1::SourceStale,
        ] {
            assert!(found.contains(&expected), "{expected:?} in {found:?}");
        }
    }

    #[test]
    fn a_lane_match_names_the_lanes_that_ranked_the_hit() {
        assert_eq!(lane_match(true, true), EvidenceMatchV1::LexicalAndDense);
        assert_eq!(lane_match(true, false), EvidenceMatchV1::Lexical);
        assert_eq!(lane_match(false, true), EvidenceMatchV1::Dense);
    }

    #[test]
    fn a_fused_hit_carries_its_lanes_scores_and_the_fused_score() {
        let id = Sha256Digest::from_bytes([7; 32]);
        let scored = ScoredHitV1::from(FusedHitV1 {
            key: id,
            score: 0.983,
            lexical_rank: Some(1),
            lexical_score: Some(0.5),
            dense_rank: Some(1),
            dense_similarity: Some(0.8),
        });
        assert_eq!(
            scored,
            ScoredHitV1 {
                id,
                score: 0.983,
                matched_by: EvidenceMatchV1::LexicalAndDense,
                lexical_score: Some(0.5),
                dense_similarity: Some(0.8),
            }
        );
        let dense_only = ScoredHitV1::from(FusedHitV1 {
            key: id,
            score: 0.5,
            lexical_rank: None,
            lexical_score: None,
            dense_rank: Some(0),
            dense_similarity: Some(0.6),
        });
        assert_eq!(dense_only.matched_by, EvidenceMatchV1::Dense);
        assert_eq!(dense_only.lexical_score, None);
    }
}
