//! Collapsing the superseded versions of a collected item whose recall text
//! is identical to another listed version's.
//!
//! An edit of a collected document is a new version of the whole document,
//! so every part of the presented head is the new version's (ADR 0008), and
//! an unchanged section renders to the same lexical text twice, once per
//! version, each with its own body. A search that matches that section would
//! list both, tied, one of them `current: false`. The fused candidates are
//! read wider than the answer ([`collapse_bound`]), the duplicates are
//! collapsed to the item's presented head when it is among them and to the
//! best-ranked copy otherwise, and only then is the answer cut to its limit.

use std::collections::HashMap;

use crate::memory_contracts::digest::Sha256Digest;
use crate::projectors::lane_depth;

use super::EvidenceHitV1;

/// How many fused candidates are read per hit asked for, so that a duplicate
/// collapsed before the cut leaves the answer full.
pub(super) const DUPLICATE_HEADROOM: usize = 2;

/// How many fused candidates a search of `limit` hits keeps before the
/// duplicates are collapsed: [`DUPLICATE_HEADROOM`] per hit, never more than
/// the lanes were read ([`lane_depth`]).
#[must_use]
pub(super) const fn collapse_bound(limit: usize) -> usize {
    let bound = limit.saturating_mul(DUPLICATE_HEADROOM);
    let depth = lane_depth(limit);
    if bound < depth { bound } else { depth }
}

/// A hydrated hit and the digest of its recall text, which the collapse keys
/// on and the answer never carries.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct HydratedHitV1 {
    pub(super) hit: EvidenceHitV1,
    pub(super) text_digest: Sha256Digest,
}

/// Collapse the versions of one collected item that share a recall text,
/// then cut the answer to `limit`.
///
/// One pass in fused order. Hits of the same item with the same text digest
/// are one group; the group keeps the hit whose version is the item's
/// presented head (`item.current`), or the best-ranked hit when none is,
/// listed at the group's best rank. A body with no item is never collapsed:
/// identical text of different items, or of the project's own evidence, is
/// as many hits as it was. The second value is how many hits were removed.
#[must_use]
pub(super) fn collapse_duplicates(
    hydrated: Vec<HydratedHitV1>,
    limit: usize,
) -> (Vec<EvidenceHitV1>, u32) {
    let mut winners: HashMap<(Sha256Digest, Sha256Digest), usize> =
        HashMap::with_capacity(hydrated.len());
    let mut kept: Vec<EvidenceHitV1> = Vec::with_capacity(hydrated.len());
    let mut collapsed: u32 = 0;
    for HydratedHitV1 { hit, text_digest } in hydrated {
        let Some(item) = &hit.item else {
            kept.push(hit);
            continue;
        };
        match winners.get(&(item.item_id, text_digest)) {
            None => {
                winners.insert((item.item_id, text_digest), kept.len());
                kept.push(hit);
            }
            Some(&index) => {
                let winner_is_current = kept[index]
                    .item
                    .as_ref()
                    .is_some_and(|winner| winner.current);
                if item.current && !winner_is_current {
                    kept[index] = hit;
                }
                collapsed = collapsed.saturating_add(1);
            }
        }
    }
    kept.truncate(limit);
    (kept, collapsed)
}

#[cfg(test)]
mod tests {
    use super::super::{
        COLLECTED_ITEM_MEDIA_TYPE, ContentTrustV1, EvidenceItemV1, EvidenceMatchV1,
        ItemLifecycleV1, TrustTierV1,
    };
    use super::*;

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([byte; 32])
    }

    /// A collected hit of body `body`, of item `item`, at fused `score`.
    fn collected(body: u8, item: u8, current: bool, score: f32) -> EvidenceHitV1 {
        EvidenceHitV1 {
            id: digest(body),
            score,
            matched_by: EvidenceMatchV1::Lexical,
            lexical_score: Some(score),
            dense_similarity: None,
            media_type: COLLECTED_ITEM_MEDIA_TYPE.to_owned(),
            content_trust: ContentTrustV1::of_media_type(COLLECTED_ITEM_MEDIA_TYPE),
            snippet: "Applies to the albatross fleet.".to_owned(),
            snippet_truncated: false,
            first_accepted_event_id: digest(0xe0 | body),
            item: Some(EvidenceItemV1 {
                item_id: digest(item),
                provider: "docs".to_owned(),
                trust: TrustTierV1::Verified,
                current,
                lifecycle: ItemLifecycleV1::Live,
            }),
        }
    }

    fn own(body: u8, score: f32) -> EvidenceHitV1 {
        EvidenceHitV1 {
            media_type: "application.git-commit-v1".to_owned(),
            content_trust: None,
            item: None,
            ..collected(body, 0, false, score)
        }
    }

    fn with_text(hit: EvidenceHitV1, text: u8) -> HydratedHitV1 {
        HydratedHitV1 {
            hit,
            text_digest: digest(text),
        }
    }

    fn ids(hits: &[EvidenceHitV1]) -> Vec<Sha256Digest> {
        hits.iter().map(|hit| hit.id).collect()
    }

    #[test]
    fn a_superseded_copy_of_unchanged_text_yields_to_the_current_version() {
        // The old version ranks first (fusion ties break on the body id).
        let (hits, collapsed) = collapse_duplicates(
            vec![
                with_text(collected(1, 9, false, 0.5), 7),
                with_text(collected(2, 9, true, 0.5), 7),
            ],
            10,
        );
        assert_eq!(ids(&hits), [digest(2)]);
        assert!(hits[0].item.as_ref().unwrap().current);
        assert_eq!(collapsed, 1);
    }

    #[test]
    fn two_superseded_copies_keep_the_best_ranked() {
        let (hits, collapsed) = collapse_duplicates(
            vec![
                with_text(collected(1, 9, false, 0.5), 7),
                with_text(collected(2, 9, false, 0.4), 7),
            ],
            10,
        );
        assert_eq!(ids(&hits), [digest(1)]);
        assert_eq!(collapsed, 1);
        // Three versions, the head last: it wins, at the group's rank.
        let (hits, collapsed) = collapse_duplicates(
            vec![
                with_text(own(5, 0.6), 1),
                with_text(collected(1, 9, false, 0.5), 7),
                with_text(collected(2, 9, false, 0.5), 7),
                with_text(collected(3, 9, true, 0.5), 7),
            ],
            10,
        );
        assert_eq!(ids(&hits), [digest(5), digest(3)]);
        assert_eq!(collapsed, 2);
    }

    #[test]
    fn identical_text_of_different_items_is_two_hits() {
        let (hits, collapsed) = collapse_duplicates(
            vec![
                with_text(collected(1, 8, true, 0.5), 7),
                with_text(collected(2, 9, true, 0.5), 7),
            ],
            10,
        );
        assert_eq!(ids(&hits), [digest(1), digest(2)]);
        assert_eq!(collapsed, 0);
    }

    #[test]
    fn different_text_of_one_item_is_two_hits() {
        let (hits, collapsed) = collapse_duplicates(
            vec![
                with_text(collected(1, 9, false, 0.5), 6),
                with_text(collected(2, 9, true, 0.5), 7),
            ],
            10,
        );
        assert_eq!(ids(&hits), [digest(1), digest(2)]);
        assert_eq!(collapsed, 0);
    }

    #[test]
    fn bodies_without_an_item_are_never_collapsed() {
        let (hits, collapsed) = collapse_duplicates(
            vec![
                with_text(own(1, 0.5), 7),
                with_text(own(2, 0.5), 7),
                with_text(collected(3, 9, true, 0.5), 7),
            ],
            10,
        );
        assert_eq!(ids(&hits), [digest(1), digest(2), digest(3)]);
        assert_eq!(collapsed, 0);
    }

    #[test]
    fn the_cut_runs_after_the_collapse() {
        let (hits, collapsed) = collapse_duplicates(
            vec![
                with_text(collected(1, 9, true, 0.6), 7),
                with_text(collected(2, 9, false, 0.5), 7),
                with_text(collected(3, 9, true, 0.4), 8),
            ],
            2,
        );
        assert_eq!(ids(&hits), [digest(1), digest(3)]);
        assert_eq!(collapsed, 1);
        // The cut itself is not a collapse.
        let (hits, collapsed) = collapse_duplicates(
            vec![
                with_text(collected(1, 9, true, 0.6), 6),
                with_text(collected(2, 9, true, 0.5), 7),
                with_text(collected(3, 9, true, 0.4), 8),
            ],
            2,
        );
        assert_eq!(ids(&hits), [digest(1), digest(2)]);
        assert_eq!(collapsed, 0);
    }

    #[test]
    fn the_collapse_bound_is_twice_the_limit_within_the_lane_depth() {
        assert_eq!(collapse_bound(1), 2);
        assert_eq!(collapse_bound(10), 20);
        assert_eq!(collapse_bound(100), 200);
        assert_eq!(collapse_bound(usize::MAX), usize::MAX);
    }
}
