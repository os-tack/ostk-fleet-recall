//! The pure parts of an evidence answer: what the fused lanes said about a
//! hit, which hits vote `present`, and what an answer nothing voted for
//! means.

use std::collections::BTreeSet;

use crate::memory_contracts::coverage::CoverageCompletenessV1;
use crate::memory_contracts::digest::Sha256Digest;
use crate::projectors::FusedHitV1;
use crate::projectors::lexical::GIT_FACT_MEDIA_TYPE;
use crate::worker::WorkerSourceOutcomeV1;

use super::{
    AbsenceReasonV1, AbsenceV1, AbsenceVerdictV1, EvidenceMatchV1, EvidenceReadinessV1,
    EvidenceSourcesV1, PresentByV1,
};

/// The cosine similarity a dense-only hit needs before it votes `present`.
///
/// The retrieval floor (0.18, [`crate::store::cockroach::RETRIEVAL_DENSE_MIN_COSINE_SIMILARITY`])
/// decides what is returned; this bound decides what a returned neighbour
/// proves. Measured with `potion-retrieval-32M` over the trial corpus
/// (`docs/TRIAL_RETEST_2026-09-26.md`, issue 8): correct answers to the
/// trial questions scored 0.45 to 0.78, loose in-domain neighbours of
/// never-discussed topics 0.22 to 0.40 (Helm 0.257, Oracle 0.269, GDPR
/// 0.400, tokio 0.403), and raw git facts attract nonsense at about 0.29.
/// Re-measured on 2026-09-26 with this bound in place, on the same stack
/// with more documents collected: the never-discussed neighbours read
/// 0.257, 0.269, 0.430 (GDPR), 0.427 (tokio) and 0.291 (the git fact), all
/// `absent`; the natural phrasings of Q1 and Q3 found their answers
/// dense-only at 0.492 and 0.496 (`present_by: dense`); the natural
/// phrasings of Q5 (0.338, over `source: linear`) and Q10 (0.411) read
/// `absent` with the right answer listed as a weak neighbour, and `present`
/// on their retry wording, which matches lexically. Lowering the bound to
/// 0.42 would rescue neither of those and would call GDPR and tokio
/// `present`, so it stays at 0.45. No single value separates a correct
/// answer's dense neighbourhood from a never-discussed topic's, which is
/// why the verdict is anchored on the lexical lane and this bound only lets
/// a strong dense-only neighbour add to it.
pub const ABSENCE_DENSE_MIN_COSINE_SIMILARITY: f32 = 0.45;

/// The cosine similarity from which a dense-only neighbour that cannot vote
/// `present` still refuses `absent`.
///
/// Measured on the same stack as the bound above (`docs/TRIAL_RETEST_2026-09-26.md`):
/// the correct answers to the trial questions asked in natural wording
/// scored 0.34 to 0.41 dense-only (Q5 0.338 over `source: linear`, Q10
/// 0.411), while in-domain noise for never-discussed topics scored 0.22 to
/// 0.43 (Helm 0.257, Oracle 0.269, GDPR 0.430, tokio 0.427). The band
/// `[0.30, 0.45)` is therefore where memory has a candidate it cannot
/// confirm: the answer may be listed, or the neighbour may be noise, and no
/// similarity separates the two. In the band the verdict is `unknown` with
/// [`super::AbsenceReasonV1::DenseNeighbourBelowBound`] and names the
/// candidate (`strongest_hit`), so an agent reads it rather than recording a
/// negative claim from an `absent` whose first hit was the answer. Below the
/// floor a neighbour is only counted (`weak_neighbours`), and `absent`
/// stands.
pub const ABSENCE_NEIGHBOUR_BAND_FLOOR: f32 = 0.30;

/// Media types whose bodies never vote `present` on a dense-only match.
///
/// A raw git fact (a commit's author, message, and paths as one record) is
/// the neighbour a nonsense query lands on at about 0.29, and on a real
/// question it is rarely the answer a document or a message is; it still
/// votes lexically, and it is still returned as a hit.
pub const DENSE_VOTE_EXCLUDED_MEDIA_TYPES: &[&str] = &[GIT_FACT_MEDIA_TYPE];

/// What one hit contributes to the absence verdict.
///
/// [`super::EvidenceHitV1::vote`] and [`crate::item_recall::ItemHitV1::vote`]
/// derive it from a hit; the verdict never reads a hit's text.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HitVoteV1 {
    /// The lanes that matched the hit after the lexical cutoff and the dense
    /// floor.
    pub matched_by: EvidenceMatchV1,
    /// The dense lane's cosine similarity, when it matched.
    pub dense_similarity: Option<f32>,
    /// Whether the body's media type may vote on a dense-only match
    /// ([`DENSE_VOTE_EXCLUDED_MEDIA_TYPES`]).
    pub dense_may_vote: bool,
}

impl HitVoteV1 {
    /// A hit's vote for a body of `media_type`.
    #[must_use]
    pub fn for_media_type(
        matched_by: EvidenceMatchV1,
        dense_similarity: Option<f32>,
        media_type: &str,
    ) -> Self {
        Self {
            matched_by,
            dense_similarity,
            dense_may_vote: !DENSE_VOTE_EXCLUDED_MEDIA_TYPES.contains(&media_type),
        }
    }

    const fn votes_lexically(self) -> bool {
        matches!(
            self.matched_by,
            EvidenceMatchV1::Lexical | EvidenceMatchV1::LexicalAndDense
        )
    }

    fn votes_densely(self) -> bool {
        self.dense_may_vote
            && self
                .dense_similarity
                .is_some_and(|similarity| similarity >= ABSENCE_DENSE_MIN_COSINE_SIMILARITY)
    }

    /// A dense-only neighbour whose body may vote, too weak to vote and too
    /// close to dismiss: in `[ABSENCE_NEIGHBOUR_BAND_FLOOR,
    /// ABSENCE_DENSE_MIN_COSINE_SIMILARITY)`.
    fn in_neighbour_band(self) -> bool {
        self.dense_may_vote
            && matches!(self.matched_by, EvidenceMatchV1::Dense)
            && self.dense_similarity.is_some_and(|similarity| {
                (ABSENCE_NEIGHBOUR_BAND_FLOOR..ABSENCE_DENSE_MIN_COSINE_SIMILARITY)
                    .contains(&similarity)
            })
    }
}

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

/// The first hit at the highest dense similarity, voting or not, and that
/// similarity: ties keep the fused order.
fn strongest_neighbour(votes: &[HitVoteV1]) -> Option<(usize, f32)> {
    votes
        .iter()
        .enumerate()
        .filter_map(|(index, vote)| Some((index, vote.dense_similarity?)))
        .filter(|(_, similarity)| !similarity.is_nan())
        .fold(
            None,
            |best: Option<(usize, f32)>, (index, similarity)| match best {
                Some((_, strongest)) if strongest >= similarity => best,
                _ => Some((index, similarity)),
            },
        )
}

/// What an answer whose hits cast `votes` means, given what was read before
/// the lanes ran. See the module documentation of `evidence_recall` for the
/// rule.
///
/// The verdict is `present` when any hit matched lexically, or when a
/// dense-only hit whose body may vote reached
/// [`ABSENCE_DENSE_MIN_COSINE_SIMILARITY`]; `present_by` says which. A hit
/// that did neither is a weak neighbour: it is counted, its similarity is
/// reported, and it never makes the answer `present`. A weak neighbour
/// whose body may vote and that reached [`ABSENCE_NEIGHBOUR_BAND_FLOOR`]
/// refuses `absent` (reason `dense_neighbour_below_bound`); one below the
/// floor decides nothing and hides no reason.
///
/// `votes` are in hit order, so `strongest_hit` indexes the caller's hits.
/// The verdict's `scope` is the caller's to set: it depends on the request,
/// not on the votes.
#[must_use]
pub fn absence_verdict(
    votes: &[HitVoteV1],
    lexical_terms: bool,
    readiness: &EvidenceReadinessV1,
    sources: &EvidenceSourcesV1,
) -> AbsenceV1 {
    let as_of = sources
        .active
        .iter()
        .filter_map(|source| source.last_checked_at)
        .min();
    let lexical = votes.iter().any(|vote| vote.votes_lexically());
    let dense = votes.iter().any(|vote| vote.votes_densely());
    let present_by = match (lexical, dense) {
        (true, true) => Some(PresentByV1::Both),
        (true, false) => Some(PresentByV1::Lexical),
        (false, true) => Some(PresentByV1::Dense),
        (false, false) => None,
    };
    let strongest = strongest_neighbour(votes);
    let strongest_hit = strongest.map(|(index, _)| index);
    let strongest_dense_similarity = strongest.map(|(_, similarity)| similarity);
    let weak_neighbours = votes
        .iter()
        .filter(|vote| !(vote.votes_lexically() || vote.votes_densely()))
        .count();
    let weak_neighbours = u32::try_from(weak_neighbours).unwrap_or(u32::MAX);
    if present_by.is_some() {
        return AbsenceV1 {
            verdict: AbsenceVerdictV1::Present,
            reasons: Vec::new(),
            as_of,
            present_by,
            strongest_dense_similarity,
            strongest_hit,
            weak_neighbours,
            scope: None,
        };
    }
    let mut reasons = BTreeSet::new();
    if !lexical_terms {
        reasons.insert(AbsenceReasonV1::QueryHasNoLexicalTerms);
    }
    if votes.iter().any(|vote| vote.in_neighbour_band()) {
        reasons.insert(AbsenceReasonV1::DenseNeighbourBelowBound);
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
        present_by: None,
        strongest_dense_similarity,
        strongest_hit,
        weak_neighbours,
        scope: None,
    }
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};
    use serde_json::json;

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
            lag_by_kind: None,
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
        let absence = absence_verdict(&[], lexical_terms, readiness, sources);
        assert_eq!(
            absence.verdict == AbsenceVerdictV1::Absent,
            absence.reasons.is_empty(),
            "a verdict is absent exactly when no reason applies"
        );
        absence.reasons
    }

    /// A vote of a body that may vote densely.
    const fn vote(matched_by: EvidenceMatchV1, dense_similarity: Option<f32>) -> HitVoteV1 {
        HitVoteV1 {
            matched_by,
            dense_similarity,
            dense_may_vote: true,
        }
    }

    fn lexical() -> HitVoteV1 {
        vote(EvidenceMatchV1::Lexical, None)
    }

    fn dense(similarity: f32) -> HitVoteV1 {
        vote(EvidenceMatchV1::Dense, Some(similarity))
    }

    fn verdict(votes: &[HitVoteV1]) -> AbsenceV1 {
        absence_verdict(votes, true, &current(), &two_healthy())
    }

    #[test]
    fn a_lexical_hit_is_present_whatever_else_holds() {
        let mut lagging = current();
        lagging.events_awaiting_body_projection = 3;
        lagging.lexical_current = false;
        let absence = absence_verdict(&[lexical()], false, &lagging, &listing(Vec::new()));
        assert_eq!(absence.verdict, AbsenceVerdictV1::Present);
        assert_eq!(absence.present_by, Some(PresentByV1::Lexical));
        assert!(absence.reasons.is_empty());
        assert_eq!(absence.strongest_dense_similarity, None);
        assert_eq!(absence.weak_neighbours, 0);
    }

    #[test]
    fn a_dense_only_neighbour_below_the_band_is_a_weak_neighbour() {
        let absence = verdict(&[dense(0.25)]);
        assert_eq!(absence.verdict, AbsenceVerdictV1::Absent);
        assert_eq!(absence.present_by, None);
        assert!(absence.reasons.is_empty());
        assert_eq!(absence.strongest_dense_similarity, Some(0.25));
        assert_eq!(absence.strongest_hit, Some(0));
        assert_eq!(absence.weak_neighbours, 1);
        // Just under the floor it is still only counted.
        let just_under = verdict(&[dense(0.2999)]);
        assert_eq!(just_under.verdict, AbsenceVerdictV1::Absent);
        assert!(just_under.reasons.is_empty());
        assert_eq!(just_under.weak_neighbours, 1);
    }

    #[test]
    fn a_dense_only_neighbour_in_the_band_refuses_absent() {
        for similarity in [ABSENCE_NEIGHBOUR_BAND_FLOOR, 0.35, 0.41, 0.4499] {
            let absence = verdict(&[dense(similarity)]);
            assert_eq!(
                absence.verdict,
                AbsenceVerdictV1::Unknown,
                "{similarity}: {absence:?}"
            );
            assert_eq!(
                absence.reasons,
                [AbsenceReasonV1::DenseNeighbourBelowBound],
                "{similarity}"
            );
            assert_eq!(absence.present_by, None);
            assert_eq!(absence.strongest_dense_similarity, Some(similarity));
            assert_eq!(absence.strongest_hit, Some(0));
            assert_eq!(absence.weak_neighbours, 1, "still a weak neighbour");
        }
        // The candidate is named wherever it ranks.
        let second = verdict(&[dense(0.25), dense(0.41), dense(0.33)]);
        assert_eq!(second.verdict, AbsenceVerdictV1::Unknown);
        assert_eq!(second.strongest_hit, Some(1));
        assert_eq!(second.strongest_dense_similarity, Some(0.41));
        assert_eq!(second.weak_neighbours, 3);
        // A tie names the first, which the fused order ranked higher.
        assert_eq!(verdict(&[dense(0.41), dense(0.41)]).strongest_hit, Some(0));
    }

    #[test]
    fn a_lexical_vote_overrides_the_band() {
        let absence = verdict(&[dense(0.41), lexical()]);
        assert_eq!(absence.verdict, AbsenceVerdictV1::Present);
        assert_eq!(absence.present_by, Some(PresentByV1::Lexical));
        assert!(absence.reasons.is_empty());
        assert_eq!(absence.strongest_hit, Some(0));
        assert_eq!(absence.weak_neighbours, 1);
        // A hit both lanes matched votes lexically whatever its similarity.
        let both = verdict(&[vote(EvidenceMatchV1::LexicalAndDense, Some(0.35))]);
        assert_eq!(both.verdict, AbsenceVerdictV1::Present);
        assert!(both.reasons.is_empty());
    }

    #[test]
    fn a_body_that_may_not_vote_is_never_in_the_band() {
        let fact =
            HitVoteV1::for_media_type(EvidenceMatchV1::Dense, Some(0.41), GIT_FACT_MEDIA_TYPE);
        let absence = verdict(&[fact]);
        assert_eq!(absence.verdict, AbsenceVerdictV1::Absent);
        assert!(absence.reasons.is_empty());
        assert_eq!(absence.strongest_dense_similarity, Some(0.41));
        assert_eq!(absence.strongest_hit, Some(0));
        assert_eq!(absence.weak_neighbours, 1);
    }

    #[test]
    fn a_dense_only_neighbour_at_the_bound_is_present_by_dense() {
        let absence = verdict(&[dense(0.60)]);
        assert_eq!(absence.verdict, AbsenceVerdictV1::Present);
        assert_eq!(absence.present_by, Some(PresentByV1::Dense));
        assert_eq!(absence.strongest_dense_similarity, Some(0.60));
        assert_eq!(absence.strongest_hit, Some(0));
        assert_eq!(absence.weak_neighbours, 0);

        let exactly = verdict(&[dense(ABSENCE_DENSE_MIN_COSINE_SIMILARITY)]);
        assert_eq!(exactly.present_by, Some(PresentByV1::Dense));
        let just_under = verdict(&[dense(0.4499)]);
        assert_eq!(just_under.verdict, AbsenceVerdictV1::Unknown);
        assert_eq!(
            just_under.reasons,
            [AbsenceReasonV1::DenseNeighbourBelowBound]
        );
        assert_eq!(just_under.weak_neighbours, 1);
    }

    #[test]
    fn a_both_lane_hit_is_present_by_both_only_when_its_dense_part_votes() {
        let both = verdict(&[vote(EvidenceMatchV1::LexicalAndDense, Some(0.60))]);
        assert_eq!(both.present_by, Some(PresentByV1::Both));
        assert_eq!(both.weak_neighbours, 0);
        let lexical_only = verdict(&[vote(EvidenceMatchV1::LexicalAndDense, Some(0.30))]);
        assert_eq!(lexical_only.present_by, Some(PresentByV1::Lexical));
        assert_eq!(lexical_only.strongest_dense_similarity, Some(0.30));
        assert_eq!(
            lexical_only.weak_neighbours, 0,
            "a lexical voter is never weak"
        );
        // Voters of each lane in different hits are still both.
        let mixed = verdict(&[lexical(), dense(0.60), dense(0.30)]);
        assert_eq!(mixed.present_by, Some(PresentByV1::Both));
        assert_eq!(mixed.strongest_dense_similarity, Some(0.60));
        assert_eq!(mixed.weak_neighbours, 1);
    }

    #[test]
    fn a_git_fact_never_votes_on_a_dense_match_but_still_votes_lexically() {
        assert!(DENSE_VOTE_EXCLUDED_MEDIA_TYPES.contains(&GIT_FACT_MEDIA_TYPE));
        let fact =
            HitVoteV1::for_media_type(EvidenceMatchV1::Dense, Some(0.60), GIT_FACT_MEDIA_TYPE);
        assert!(!fact.dense_may_vote);
        let absence = verdict(&[fact]);
        assert_eq!(absence.verdict, AbsenceVerdictV1::Absent);
        assert_eq!(absence.present_by, None);
        assert_eq!(absence.strongest_dense_similarity, Some(0.60));
        assert_eq!(absence.weak_neighbours, 1);

        let lexical_fact =
            HitVoteV1::for_media_type(EvidenceMatchV1::Lexical, None, GIT_FACT_MEDIA_TYPE);
        assert_eq!(
            verdict(&[lexical_fact]).present_by,
            Some(PresentByV1::Lexical)
        );
        let document = HitVoteV1::for_media_type(
            EvidenceMatchV1::Dense,
            Some(0.60),
            "application.transcript-turn-v1",
        );
        assert!(document.dense_may_vote);
        assert_eq!(verdict(&[document]).present_by, Some(PresentByV1::Dense));
    }

    #[test]
    fn a_weak_neighbour_never_hides_a_reason() {
        let mut lagging = current();
        lagging.events_awaiting_body_projection = 1;
        let absence = absence_verdict(&[dense(0.25)], true, &lagging, &two_healthy());
        assert_eq!(absence.verdict, AbsenceVerdictV1::Unknown);
        assert_eq!(absence.reasons, [AbsenceReasonV1::BodyProjectionLag]);
        assert_eq!(absence.present_by, None);
        assert_eq!(absence.strongest_dense_similarity, Some(0.25));
        assert_eq!(absence.weak_neighbours, 1);
        // In the band, the candidate is one more reason beside the lag.
        let banded = absence_verdict(&[dense(0.41)], true, &lagging, &two_healthy());
        assert_eq!(
            banded.reasons,
            [
                AbsenceReasonV1::BodyProjectionLag,
                AbsenceReasonV1::DenseNeighbourBelowBound
            ]
        );
    }

    #[test]
    fn an_empty_absent_answer_serializes_as_it_always_did() {
        let absence = verdict(&[]);
        assert_eq!(absence.verdict, AbsenceVerdictV1::Absent);
        let value = serde_json::to_value(&absence).unwrap();
        let mut keys: Vec<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, ["as_of", "reasons", "verdict"]);

        let weak = serde_json::to_value(verdict(&[dense(0.25)])).unwrap();
        assert_eq!(weak["verdict"], "absent");
        assert_eq!(weak["weak_neighbours"], 1);
        assert!((weak["strongest_dense_similarity"].as_f64().unwrap() - 0.25).abs() < 1e-6);
        assert_eq!(weak["strongest_hit"], 0);
        assert!(weak.get("present_by").is_none());
        assert!(weak.get("scope").is_none());
        let present = serde_json::to_value(verdict(&[lexical()])).unwrap();
        assert_eq!(present["present_by"], "lexical");
        assert!(present.get("weak_neighbours").is_none());
        assert!(present.get("strongest_hit").is_none());
        // The band, as an agent reads it.
        let banded = serde_json::to_value(verdict(&[dense(0.41)])).unwrap();
        assert_eq!(banded["verdict"], "unknown");
        assert_eq!(banded["reasons"], json!(["dense_neighbour_below_bound"]));
        assert_eq!(banded["strongest_hit"], 0);
        assert!((banded["strongest_dense_similarity"].as_f64().unwrap() - 0.41).abs() < 1e-6);
        assert_eq!(banded["weak_neighbours"], 1);
        assert!(banded.get("present_by").is_none());
        // A scoped verdict names its source.
        let mut scoped = verdict(&[]);
        scoped.scope = Some(super::super::AbsenceScopeV1 {
            source: super::super::EvidenceSourceFilterV1::Git,
        });
        assert_eq!(
            serde_json::to_value(&scoped).unwrap()["scope"],
            json!({ "source": "git" })
        );
    }

    #[test]
    fn no_hit_over_a_current_fresh_complete_scope_is_absent() {
        let absence = absence_verdict(&[], true, &current(), &two_healthy());
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
            absence_verdict(&[], true, &current(), &sources).as_of,
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
        let absence = absence_verdict(&[], true, &current(), &incomplete);
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
        // A lexical hit is still present: only the empty answer loses its
        // meaning.
        assert_eq!(
            absence_verdict(&[lexical()], true, &readiness, &two_healthy()).verdict,
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
