//! The head move rule, the presentation, and the independence of both from
//! arrival order.

use std::collections::{BTreeMap, BTreeSet};

use super::*;

fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([byte; 32])
}

fn version(key: u8, order: u64, profile: u32) -> CompletedVersionV1 {
    CompletedVersionV1 {
        version_key: digest(key),
        content_digest: digest(key.wrapping_add(100)),
        provider_order: order,
        redaction_profile: profile,
        lifecycle: ItemLifecycleV1::Live,
        part_count: 1,
        container_key: None,
    }
}

fn head(version: CompletedVersionV1) -> TierHeadV1 {
    TierHeadV1 {
        version,
        version_count: 1,
        order_ties: 0,
        revision: 1,
    }
}

#[test]
fn the_first_complete_version_creates_the_head() {
    let (row, change) = advance_tier_head(None, &version(1, 10, 1));
    assert_eq!(change, HeadMoveV1::Created);
    assert_eq!(row, Some(head(version(1, 10, 1))));
    assert!(change.moved());
}

#[test]
fn a_greater_order_moves_the_head() {
    let current = head(version(1, 10, 1));
    let (row, change) = advance_tier_head(Some(&current), &version(2, 11, 1));
    let row = row.unwrap();
    assert_eq!(change, HeadMoveV1::Moved);
    assert_eq!(row.version, version(2, 11, 1));
    assert_eq!((row.version_count, row.order_ties, row.revision), (2, 0, 2));
}

#[test]
fn the_same_order_under_a_newer_redaction_profile_moves_the_head() {
    let current = head(version(1, 10, 1));
    let (row, change) = advance_tier_head(Some(&current), &version(2, 10, 2));
    assert_eq!(change, HeadMoveV1::Moved);
    assert_eq!(row.unwrap().version, version(2, 10, 2));

    // An older profile at the same order is an older rendering.
    let current = head(version(2, 10, 2));
    let (row, change) = advance_tier_head(Some(&current), &version(1, 10, 1));
    assert_eq!(change, HeadMoveV1::Older);
    assert_eq!(row.unwrap().version, version(2, 10, 2));
}

#[test]
fn an_older_version_arriving_late_keeps_the_head_and_is_counted() {
    let current = head(version(5, 20, 1));
    let (row, change) = advance_tier_head(Some(&current), &version(4, 19, 1));
    let row = row.unwrap();
    assert_eq!(change, HeadMoveV1::Older);
    assert!(!change.moved());
    assert_eq!(row.version, version(5, 20, 1));
    assert_eq!((row.version_count, row.revision), (2, 2));
}

#[test]
fn a_tie_is_counted_and_broken_by_the_greater_version_key() {
    let current = head(version(3, 10, 1));
    let (row, change) = advance_tier_head(Some(&current), &version(2, 10, 1));
    let row = row.unwrap();
    assert_eq!(change, HeadMoveV1::Tied { moved: false });
    assert_eq!(row.version, version(3, 10, 1));
    assert_eq!(row.order_ties, 1);

    let (row, change) = advance_tier_head(Some(&current), &version(4, 10, 1));
    let row = row.unwrap();
    assert_eq!(change, HeadMoveV1::Tied { moved: true });
    assert_eq!(row.version, version(4, 10, 1));
    assert_eq!((row.version_count, row.order_ties), (2, 1));
}

#[test]
fn a_tombstone_wins_a_tie_whatever_the_version_keys() {
    let tombstone = |key: u8| CompletedVersionV1 {
        lifecycle: ItemLifecycleV1::Deleted,
        ..version(key, 1_000, 1)
    };
    // The delete's version key is the smaller one: the key alone would keep
    // the live version presented.
    let live = head(version(0xee, 1_000, 1));
    let (row, change) = advance_tier_head(Some(&live), &tombstone(0x11));
    let row = row.unwrap();
    assert_eq!(change, HeadMoveV1::Tied { moved: true });
    assert_eq!(row.version.lifecycle, ItemLifecycleV1::Deleted);
    assert_eq!(row.order_ties, 1);

    // A live version tied with a tombstone head never displaces it.
    let deleted = head(tombstone(0x11));
    let (row, change) = advance_tier_head(Some(&deleted), &version(0xee, 1_000, 1));
    assert_eq!(change, HeadMoveV1::Tied { moved: false });
    assert_eq!(row.unwrap().version.lifecycle, ItemLifecycleV1::Deleted);

    // Between two tombstones the version key still decides.
    let (row, change) = advance_tier_head(Some(&deleted), &tombstone(0x22));
    assert_eq!(change, HeadMoveV1::Tied { moved: true });
    assert_eq!(row.unwrap().version.version_key, digest(0x22));

    // A newer live version (an undelete) still moves past a tombstone.
    let (row, change) = advance_tier_head(Some(&deleted), &version(0x05, 1_001, 1));
    assert_eq!(change, HeadMoveV1::Moved);
    assert_eq!(row.unwrap().version.lifecycle, ItemLifecycleV1::Live);
}

#[test]
fn the_head_version_completing_again_changes_nothing() {
    let current = head(version(3, 10, 1));
    assert_eq!(
        advance_tier_head(Some(&current), &version(3, 10, 1)),
        (None, HeadMoveV1::Unchanged)
    );
}

#[test]
fn only_the_last_missing_part_completes_a_version() {
    // Three parts: the first two admissions do not complete it.
    assert!(!part_completes_version(false, 0, 3));
    assert!(!part_completes_version(false, 1, 3));
    assert!(part_completes_version(false, 2, 3));
    // A second attester's copy of an admitted part completes nothing.
    assert!(!part_completes_version(true, 2, 3));
    assert!(!part_completes_version(true, 3, 3));
    assert!(part_completes_version(false, 0, 1));
}

#[test]
fn a_verified_head_is_presented_over_a_reported_one() {
    let verified = version(1, 10, 1);
    let older_report = version(2, 9, 1);
    let presentation = present(Some(&verified), Some(&older_report)).unwrap();
    assert_eq!(presentation.presented, TrustTierV1::Verified);
    assert!(!presentation.disagreement);

    let only_reported = present(None, Some(&older_report)).unwrap();
    assert_eq!(only_reported.presented, TrustTierV1::Reported);
    assert!(!only_reported.disagreement);
    assert_eq!(present(None, None), None);
}

#[test]
fn a_newer_different_report_disagrees_with_the_verified_head() {
    let verified = version(1, 10, 1);
    let newer_report = version(2, 11, 1);
    let presentation = present(Some(&verified), Some(&newer_report)).unwrap();
    assert_eq!(presentation.presented, TrustTierV1::Verified);
    assert!(presentation.disagreement);

    // The same content reported later is corroboration, not disagreement.
    let mut echo = newer_report;
    echo.content_digest = verified.content_digest;
    assert!(!present(Some(&verified), Some(&echo)).unwrap().disagreement);
}

/// One admitted part: which tier, which version, which ordinal.
#[derive(Debug, Clone, Copy)]
struct Arrival {
    tier: TrustTierV1,
    version: u8,
    ordinal: u32,
}

/// The item's current view after a sequence of admissions, computed exactly
/// as the drain's projection computes it: per tier, count distinct admitted
/// ordinals, and advance the head when a part completes its version.
fn replay(
    arrivals: &[Arrival],
    versions: &BTreeMap<u8, CompletedVersionV1>,
) -> (BTreeMap<&'static str, TierHeadV1>, Option<PresentationV1>) {
    let mut admitted: BTreeMap<(&'static str, u8), BTreeSet<u32>> = BTreeMap::new();
    let mut heads: BTreeMap<&'static str, TierHeadV1> = BTreeMap::new();
    for arrival in arrivals {
        let parts = admitted
            .entry((arrival.tier.as_str(), arrival.version))
            .or_default();
        let already = parts.contains(&arrival.ordinal);
        let before = u32::try_from(parts.len()).unwrap();
        parts.insert(arrival.ordinal);
        let completed = &versions[&arrival.version];
        if part_completes_version(already, before, completed.part_count) {
            let (row, _) = advance_tier_head(heads.get(arrival.tier.as_str()), completed);
            if let Some(row) = row {
                heads.insert(arrival.tier.as_str(), row);
            }
        }
    }
    let presentation = present(
        heads.get("verified").map(|row| &row.version),
        heads.get("reported").map(|row| &row.version),
    );
    (heads, presentation)
}

/// Every permutation of `items`, by Heap's algorithm.
fn permutations<T: Clone>(items: &[T]) -> Vec<Vec<T>> {
    fn heap<T: Clone>(size: usize, items: &mut Vec<T>, out: &mut Vec<Vec<T>>) {
        if size <= 1 {
            out.push(items.clone());
            return;
        }
        for index in 0..size {
            heap(size - 1, items, out);
            if size.is_multiple_of(2) {
                items.swap(index, size - 1);
            } else {
                items.swap(0, size - 1);
            }
        }
    }
    let mut items = items.to_vec();
    let mut out = Vec::new();
    heap(items.len(), &mut items, &mut out);
    out
}

#[test]
fn arrival_order_never_decides_the_current_view() {
    // A two-part verified version, a newer one-part verified edit, a tied
    // verified version, and a newer reported version with other content that
    // arrives twice (two attesters).
    let mut two_part = version(1, 10, 1);
    two_part.part_count = 2;
    let versions = BTreeMap::from([
        (1, two_part),
        (2, version(2, 12, 1)),
        (3, version(3, 12, 1)),
        (4, version(4, 15, 1)),
    ]);
    let verified = TrustTierV1::Verified;
    let reported = TrustTierV1::Reported;
    let arrivals = [
        Arrival {
            tier: verified,
            version: 1,
            ordinal: 0,
        },
        Arrival {
            tier: verified,
            version: 1,
            ordinal: 1,
        },
        Arrival {
            tier: verified,
            version: 2,
            ordinal: 0,
        },
        Arrival {
            tier: verified,
            version: 3,
            ordinal: 0,
        },
        Arrival {
            tier: reported,
            version: 4,
            ordinal: 0,
        },
        Arrival {
            tier: reported,
            version: 4,
            ordinal: 0,
        },
    ];
    let orders = permutations(&arrivals);
    assert_eq!(orders.len(), 720);
    let (expected_heads, expected_presentation) = replay(&orders[0], &versions);
    assert_eq!(expected_heads["verified"].version, versions[&3]);
    assert_eq!(expected_heads["verified"].version_count, 3);
    assert_eq!(expected_heads["reported"].version, versions[&4]);
    assert_eq!(expected_heads["reported"].version_count, 1);
    assert_eq!(
        expected_presentation,
        Some(PresentationV1 {
            presented: TrustTierV1::Verified,
            disagreement: true,
        })
    );
    for order in &orders {
        let (heads, presentation) = replay(order, &versions);
        for tier in ["verified", "reported"] {
            assert_eq!(
                heads[tier].version, expected_heads[tier].version,
                "{tier} head under {order:?}"
            );
            assert_eq!(
                heads[tier].version_count, expected_heads[tier].version_count,
                "{tier} versions under {order:?}"
            );
        }
        assert_eq!(presentation, expected_presentation, "{order:?}");
    }
}

#[test]
fn a_tied_tombstone_heads_the_tier_in_every_arrival_order() {
    let tombstone = CompletedVersionV1 {
        lifecycle: ItemLifecycleV1::Trashed,
        ..version(0x01, 1_000, 1)
    };
    let versions = BTreeMap::from([
        (0x01, tombstone.clone()),
        (0xee, version(0xee, 1_000, 1)),
        (0x77, version(0x77, 1_000, 1)),
    ]);
    let arrivals: Vec<Arrival> = versions
        .keys()
        .map(|key| Arrival {
            tier: TrustTierV1::Verified,
            version: *key,
            ordinal: 0,
        })
        .collect();
    for order in permutations(&arrivals) {
        let (heads, _) = replay(&order, &versions);
        assert_eq!(heads["verified"].version, tombstone, "{order:?}");
        assert_eq!(heads["verified"].order_ties, 2, "{order:?}");
    }
}

#[test]
fn a_version_with_only_some_parts_admitted_never_heads_a_tier() {
    let mut three_parts = version(9, 50, 1);
    three_parts.part_count = 3;
    let versions = BTreeMap::from([(1, version(1, 10, 1)), (9, three_parts)]);
    let arrivals = [
        Arrival {
            tier: TrustTierV1::Verified,
            version: 1,
            ordinal: 0,
        },
        Arrival {
            tier: TrustTierV1::Verified,
            version: 9,
            ordinal: 0,
        },
        Arrival {
            tier: TrustTierV1::Verified,
            version: 9,
            ordinal: 2,
        },
    ];
    for order in permutations(&arrivals) {
        let (heads, _) = replay(&order, &versions);
        assert_eq!(heads["verified"].version, versions[&1], "{order:?}");
        assert_eq!(heads["verified"].version_count, 1);
    }
}
