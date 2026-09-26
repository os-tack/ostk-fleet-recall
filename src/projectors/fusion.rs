//! Score-aware fusion of the lexical and dense recall lanes.
//!
//! Item recall and evidence recall each read two ranked lanes over the
//! projection tiers: the lexical lane orders bodies by `ts_rank`, the dense
//! lane by cosine distance. The two scales are not commensurable (a `ts_rank`
//! of 0.1 says nothing about a cosine similarity of 0.5), so the lanes are
//! fused by reciprocal rank, the scale-free rule chunk recall already uses
//! (`ostk_recall_retrieval::fuse_rrf`, `K_RRF = 60`): each lane contributes
//! `1 / (K + rank)` for a key, the contributions are summed, and the sum is
//! normalized so a key first in both lanes scores `1.0`. A body first in one
//! lane and absent from the other scores `0.5`.
//!
//! Before ranking, each lane drops what is not a match: a lexical row whose
//! `ts_rank` is below [`LEXICAL_MIN_TS_RANK`], and a dense row whose cosine
//! similarity is below the caller's floor (nearest-neighbour padding). The
//! ranks are numbered over the survivors, so a dropped row takes no rank.
//!
//! Each lane is read [`LANE_DEPTH`] rows per hit asked for
//! ([`lane_depth`]), so a body ranked fifth in both lanes can outrank a body
//! ranked first in one; the fused list is then cut to the requested limit.
//! This fusion is internal to item and evidence recall: no evidence or item
//! hit enters chunk recall's own fusion (ADR 0006 D5).

use std::collections::BTreeMap;

use ostk_recall_retrieval::{K_RRF, rrf_score_normalized};

/// The lowest `ts_rank` the lexical lane counts as a match.
///
/// Under `ts_rank` a single-term match scores about 0.1 whatever the
/// document, while a multi-term AND rank below 0.001 means the terms are
/// ten or more words apart: co-occurrence, not a match.
pub const LEXICAL_MIN_TS_RANK: f32 = 1e-3;

/// How many rows each lane is read per hit asked for, so that a body a
/// little down both lanes can outrank a body at the top of one.
pub const LANE_DEPTH: usize = 5;

/// How many rows each lane reads for a search of `limit` hits.
#[must_use]
pub const fn lane_depth(limit: usize) -> usize {
    limit.saturating_mul(LANE_DEPTH)
}

/// One fused hit: the key both lanes name a body by, its fused score, and
/// what each lane said about it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FusedHitV1<K> {
    /// The lanes' key for the body.
    pub key: K,
    /// The normalized reciprocal-rank score, in `[0, 1]`: `1.0` for a key
    /// first in both lanes, `0.5` for a key first in one lane and absent from
    /// the other.
    pub score: f32,
    /// The key's zero-based rank among the lexical rows that cleared the
    /// cutoff, when the lexical lane matched.
    pub lexical_rank: Option<u32>,
    /// `ts_rank` of the lexical lane, when it matched.
    pub lexical_score: Option<f32>,
    /// The key's zero-based rank among the dense rows that cleared the floor,
    /// when the dense lane matched.
    pub dense_rank: Option<u32>,
    /// Cosine similarity of the dense lane, when it matched at or above the
    /// floor.
    pub dense_similarity: Option<f32>,
}

/// Fuse the two lanes by reciprocal rank into at most `limit` hits.
///
/// `lexical` is `(key, ts_rank)` by descending rank; `dense` is `(key, cosine
/// distance)` by ascending distance, as the lane queries return them. A
/// lexical row below [`LEXICAL_MIN_TS_RANK`] and a dense row whose similarity
/// (`1 - distance`) is below `dense_floor` are dropped before ranking, as is
/// any row with a NaN score. Within a lane a key counts once, at its first
/// occurrence. The result is ordered by fused score, highest first, ties by
/// ascending key, so the order is total whatever the lanes' own tie order.
#[must_use]
pub fn fuse_lanes<K: Ord + Clone>(
    lexical: &[(K, f32)],
    dense: &[(K, f32)],
    dense_floor: f32,
    limit: usize,
) -> Vec<FusedHitV1<K>> {
    let mut hits: BTreeMap<K, FusedHitV1<K>> = BTreeMap::new();
    let mut rank: u32 = 0;
    for (key, ts_rank) in lexical {
        if ts_rank.is_nan() || *ts_rank < LEXICAL_MIN_TS_RANK {
            continue;
        }
        let hit = hits
            .entry(key.clone())
            .or_insert_with(|| unranked(key.clone()));
        if hit.lexical_rank.is_none() {
            hit.lexical_rank = Some(rank);
            hit.lexical_score = Some(*ts_rank);
            rank += 1;
        }
    }
    let mut rank: u32 = 0;
    for (key, distance) in dense {
        let similarity = 1.0 - distance;
        if similarity.is_nan() || similarity < dense_floor {
            continue;
        }
        let hit = hits
            .entry(key.clone())
            .or_insert_with(|| unranked(key.clone()));
        if hit.dense_rank.is_none() {
            hit.dense_rank = Some(rank);
            hit.dense_similarity = Some(similarity);
            rank += 1;
        }
    }
    let mut fused: Vec<FusedHitV1<K>> = hits
        .into_values()
        .map(|mut hit| {
            hit.score = rrf_score_normalized(
                hit.lexical_rank.map_or(0.0, contribution)
                    + hit.dense_rank.map_or(0.0, contribution),
            );
            hit
        })
        .collect();
    fused.sort_by(|left, right| {
        right
            .score
            .total_cmp(&left.score)
            .then_with(|| left.key.cmp(&right.key))
    });
    fused.truncate(limit);
    fused
}

/// One lane's reciprocal-rank contribution for a zero-based rank.
#[allow(clippy::cast_precision_loss)]
fn contribution(rank: u32) -> f32 {
    1.0 / (K_RRF + rank as f32)
}

const fn unranked<K>(key: K) -> FusedHitV1<K> {
    FusedHitV1 {
        key,
        score: 0.0,
        lexical_rank: None,
        lexical_score: None,
        dense_rank: None,
        dense_similarity: None,
    }
}

#[cfg(test)]
mod tests {
    use ostk_recall_retrieval::fuse_rrf;

    use super::*;

    const FLOOR: f32 = 0.18;

    fn close(left: f32, right: f32) -> bool {
        (left - right).abs() < 1e-3
    }

    fn keys<K: Copy>(hits: &[FusedHitV1<K>]) -> Vec<K> {
        hits.iter().map(|hit| hit.key).collect()
    }

    fn scores<K>(hits: &[FusedHitV1<K>]) -> Vec<f32> {
        hits.iter().map(|hit| hit.score).collect()
    }

    #[test]
    fn the_lexical_cutoff_drops_degenerate_ranks_and_renumbers_the_survivors() {
        let lexical = [(1, 0.0), (2, 1e-3), (3, 7.7e-5), (4, 0.05)];
        let fused = fuse_lanes(&lexical, &[], FLOOR, 10);
        assert_eq!(keys(&fused), [2, 4]);
        // Key 2 is first among the survivors, whatever its row position.
        assert_eq!(fused[0].lexical_rank, Some(0));
        assert_eq!(fused[1].lexical_rank, Some(1));
        assert!(close(fused[0].score, 0.5), "{:?}", scores(&fused));
        assert!(close(fused[1].score, 0.492), "{:?}", scores(&fused));
        assert_eq!(fused[0].lexical_score, Some(1e-3));
    }

    #[test]
    fn dense_leads_when_every_lexical_row_is_degenerate() {
        // The Q3 shape: three dense neighbours and a lexical lane of
        // co-occurrences only.
        let lexical = [(9, 0.0006), (8, 0.0)];
        let dense = [(1, 0.5), (2, 0.51), (3, 0.52)];
        let fused = fuse_lanes(&lexical, &dense, FLOOR, 10);
        assert_eq!(keys(&fused), [1, 2, 3]);
        let scores = scores(&fused);
        assert!(close(scores[0], 0.500), "{scores:?}");
        assert!(close(scores[1], 0.492), "{scores:?}");
        assert!(close(scores[2], 0.484), "{scores:?}");
        assert!(fused.iter().all(|hit| hit.lexical_rank.is_none()));
    }

    #[test]
    fn a_key_second_in_both_lanes_beats_a_key_first_in_one() {
        let lexical = [(1, 0.9), (2, 0.5)];
        let dense = [(3, 0.1), (2, 0.2)];
        let fused = fuse_lanes(&lexical, &dense, FLOOR, 10);
        assert_eq!(keys(&fused), [2, 1, 3]);
        let scores = scores(&fused);
        assert!(close(scores[0], 0.983), "{scores:?}");
        assert!(close(scores[1], 0.5), "{scores:?}");
        assert!(close(scores[2], 0.5), "{scores:?}");
        assert_eq!(
            (fused[0].lexical_rank, fused[0].dense_rank),
            (Some(1), Some(1))
        );
        assert!(close(fused[0].dense_similarity.unwrap(), 0.8));
        assert_eq!(fused[0].lexical_score, Some(0.5));
    }

    #[test]
    fn a_key_first_in_both_lanes_scores_one() {
        let fused = fuse_lanes(&[(1, 0.4)], &[(1, 0.3)], FLOOR, 10);
        assert_eq!(fused.len(), 1);
        assert!((fused[0].score - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn the_dense_floor_drops_padding_and_takes_no_rank() {
        let dense = [(1, 0.4), (2, 0.95), (3, 0.5)];
        let fused = fuse_lanes(&[], &dense, FLOOR, 10);
        assert_eq!(keys(&fused), [1, 3]);
        // Padding at distance 0.95 takes no rank: key 3 is second, not third.
        assert_eq!(fused[1].dense_rank, Some(1));
        assert!(close(fused[0].dense_similarity.unwrap(), 0.6));
    }

    #[test]
    fn a_similarity_exactly_at_the_floor_is_kept() {
        let fused = fuse_lanes(&[], &[(1, 0.75)], 0.25, 10);
        assert_eq!(keys(&fused), [1]);
        assert_eq!(fused[0].dense_rank, Some(0));
    }

    #[test]
    fn a_both_lane_key_below_the_floor_keeps_only_its_lexical_match() {
        let fused = fuse_lanes(&[(1, 0.3)], &[(1, 0.9)], FLOOR, 10);
        assert_eq!(fused.len(), 1);
        assert_eq!(fused[0].lexical_rank, Some(0));
        assert_eq!(fused[0].dense_rank, None);
        assert_eq!(fused[0].dense_similarity, None);
        assert!(close(fused[0].score, 0.5));
    }

    #[test]
    fn nan_scores_are_dropped_from_either_lane() {
        let fused = fuse_lanes(&[(1, f32::NAN), (2, 0.2)], &[(3, f32::NAN)], FLOOR, 10);
        assert_eq!(keys(&fused), [2]);
    }

    #[test]
    fn the_fused_list_is_cut_to_the_limit_after_ranking() {
        let lexical = [(1, 0.9), (2, 0.5)];
        let dense = [(2, 0.2), (3, 0.3)];
        assert_eq!(keys(&fuse_lanes(&lexical, &dense, FLOOR, 1)), [2]);
        assert_eq!(keys(&fuse_lanes(&lexical, &dense, FLOOR, 2)), [2, 1]);
        assert!(fuse_lanes(&lexical, &dense, FLOOR, 0).is_empty());
    }

    #[test]
    fn an_equal_score_ties_by_key_whatever_the_lane() {
        // Rank 0 in one lane each: same score, key order decides.
        let fused = fuse_lanes(&[(7, 0.9)], &[(3, 0.1)], FLOOR, 10);
        assert_eq!(keys(&fused), [3, 7]);
        let fused = fuse_lanes(&[(3, 0.9)], &[(7, 0.1)], FLOOR, 10);
        assert_eq!(keys(&fused), [3, 7]);
    }

    #[test]
    fn a_key_repeated_within_a_lane_counts_once_at_its_first_occurrence() {
        let lexical = [(1, 0.9), (1, 0.8), (2, 0.5)];
        let dense = [(2, 0.1), (2, 0.2)];
        let fused = fuse_lanes(&lexical, &dense, FLOOR, 10);
        assert_eq!(keys(&fused), [2, 1]);
        assert_eq!(fused[1].lexical_rank, Some(0));
        assert_eq!(fused[1].lexical_score, Some(0.9));
        assert_eq!(fused[0].lexical_rank, Some(1));
        assert_eq!(fused[0].dense_rank, Some(0));
        assert!(close(fused[0].dense_similarity.unwrap(), 0.9));
        assert!(close(
            fused[0].score,
            (1.0 / 61.0 + 1.0 / 60.0) / (2.0 / 60.0)
        ));
    }

    #[test]
    fn fusion_agrees_with_the_chunk_lanes_reciprocal_rank_fusion() {
        let lexical = [("a", 0.9), ("b", 0.5), ("c", 0.2), ("d", 0.1)];
        let dense = [("c", 0.1), ("e", 0.2), ("a", 0.3), ("f", 0.4)];
        let fused = fuse_lanes(&lexical, &dense, FLOOR, 10);

        let entry = |(key, score): &(&str, f32), rank: usize| {
            ((*key).to_owned(), *score, u32::try_from(rank).unwrap())
        };
        let lexical_entries: Vec<_> = lexical
            .iter()
            .enumerate()
            .map(|(rank, row)| entry(row, rank))
            .collect();
        let dense_entries: Vec<_> = dense
            .iter()
            .enumerate()
            .map(|(rank, row)| entry(row, rank))
            .collect();
        let reference = fuse_rrf(&[&lexical_entries, &dense_entries]);

        assert_eq!(fused.len(), reference.len());
        for hit in &fused {
            let expected = rrf_score_normalized(reference[hit.key]);
            assert!(
                (hit.score - expected).abs() < 1e-6,
                "{}: {} vs {expected}",
                hit.key,
                hit.score
            );
        }
        assert_eq!(keys(&fused), ["a", "c", "b", "e", "d", "f"]);
    }

    #[test]
    fn lane_depth_reads_five_rows_per_hit_and_saturates() {
        assert_eq!(lane_depth(1), 5);
        assert_eq!(lane_depth(100), 500);
        assert_eq!(lane_depth(usize::MAX), usize::MAX);
    }
}
