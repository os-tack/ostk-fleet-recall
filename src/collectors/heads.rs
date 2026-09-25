//! The current view of a collected item (ADR 0008 D5): which complete
//! version heads each trust tier, which tier is presented, and whether a newer
//! report disagrees with the verified head.
//!
//! Everything here is pure. The drain's projection reads the item's two tier
//! rows under `SELECT ... FOR UPDATE`, asks these functions what they become,
//! and writes the answer in the append's own transaction.
//!
//! # The rules
//!
//! * **Only a complete version heads a tier.** A version is complete when
//!   every one of its parts has been admitted through that tier's channels;
//!   [`part_completes_version`] says whether one admission completed it.
//! * **The head moves only forward.** A complete version replaces the tier's
//!   head only when its `(provider_order, redaction_profile)` is strictly
//!   greater ([`advance_tier_head`]). The provider's order, never the arrival
//!   order, says what is newer; a strictly newer redaction profile at the same
//!   order moves the head to the better-redacted rendering.
//! * **A tie is counted, and broken by the version key.** Two different
//!   versions at the same order and profile are a provider anomaly:
//!   `order_ties` counts it, and the greater version key heads the tier, so
//!   the head is a function of the set of complete versions and never of the
//!   order they arrived in.
//! * **A report never displaces a verification.** The verified head (pull,
//!   push) is presented whenever one exists; the reported head (capture,
//!   import) is presented only when none does ([`present`]).
//! * **A newer, different report is a disagreement.** When the reported head
//!   is newer than the verified head and its content differs, the presented
//!   row says so.

use std::cmp::Ordering;

use crate::memory_contracts::collected_item::{ItemLifecycleV1, TrustTierV1};
use crate::memory_contracts::digest::Sha256Digest;

/// One complete version of one item, as one tier sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletedVersionV1 {
    /// The version key.
    pub version_key: Sha256Digest,
    /// The version's content digest.
    pub content_digest: Sha256Digest,
    /// The provider's order for the version.
    pub provider_order: u64,
    /// The collector redaction profile that rendered it.
    pub redaction_profile: u32,
    /// The version's lifecycle state.
    pub lifecycle: ItemLifecycleV1,
    /// How many parts the version has.
    pub part_count: u32,
    /// The container key, when the item has a container.
    pub container_key: Option<Sha256Digest>,
}

impl CompletedVersionV1 {
    /// How the move rule orders two versions: provider order, then redaction
    /// profile. Equal keys of different versions are a tie.
    const fn move_key(&self) -> (u64, u32) {
        (self.provider_order, self.redaction_profile)
    }
}

/// One tier's head row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TierHeadV1 {
    /// The version that heads the tier.
    pub version: CompletedVersionV1,
    /// Complete versions this tier has seen, the head included.
    pub version_count: u64,
    /// Complete versions that arrived tied with the head's order and profile.
    pub order_ties: u64,
    /// The row's revision, bumped by every change.
    pub revision: u64,
}

/// What one complete version did to its tier's head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeadMoveV1 {
    /// The tier had no head; this version is it.
    Created,
    /// The version is newer; it heads the tier now.
    Moved,
    /// The version ties the head's order and profile; `moved` says whether
    /// its greater version key made it the head.
    Tied {
        /// Whether the head changed.
        moved: bool,
    },
    /// The version is older than the head; the head stays.
    Older,
    /// The version already heads the tier; nothing changes.
    Unchanged,
}

impl HeadMoveV1 {
    /// Whether the tier's head version changed.
    #[must_use]
    pub const fn moved(self) -> bool {
        matches!(
            self,
            Self::Created | Self::Moved | Self::Tied { moved: true }
        )
    }
}

/// Whether admitting one part completed its version for a tier.
///
/// `already_admitted` says whether this part's ordinal was already admitted
/// for the version in the tier (another attester's capture of the same part);
/// `distinct_before` is how many distinct ordinals were admitted before this
/// one. Only the admission of the last missing ordinal completes a version, so
/// a version completes exactly once per tier.
#[must_use]
pub const fn part_completes_version(
    already_admitted: bool,
    distinct_before: u32,
    part_count: u32,
) -> bool {
    !already_admitted && distinct_before.saturating_add(1) == part_count
}

/// The tier's head after `completed` completes, and what that did.
///
/// Returns `None` for the row when nothing changes.
#[must_use]
pub fn advance_tier_head(
    current: Option<&TierHeadV1>,
    completed: &CompletedVersionV1,
) -> (Option<TierHeadV1>, HeadMoveV1) {
    let Some(current) = current else {
        return (
            Some(TierHeadV1 {
                version: completed.clone(),
                version_count: 1,
                order_ties: 0,
                revision: 1,
            }),
            HeadMoveV1::Created,
        );
    };
    if current.version.version_key == completed.version_key {
        return (None, HeadMoveV1::Unchanged);
    }
    let mut next = TierHeadV1 {
        version: current.version.clone(),
        version_count: current.version_count.saturating_add(1),
        order_ties: current.order_ties,
        revision: current.revision.saturating_add(1),
    };
    let change = match completed.move_key().cmp(&current.version.move_key()) {
        Ordering::Greater => {
            next.version = completed.clone();
            HeadMoveV1::Moved
        }
        Ordering::Less => HeadMoveV1::Older,
        Ordering::Equal => {
            let moved = completed.version_key > current.version.version_key;
            next.order_ties = next.order_ties.saturating_add(1);
            if moved {
                next.version = completed.clone();
            }
            HeadMoveV1::Tied { moved }
        }
    };
    (Some(next), change)
}

/// Which tier an item presents, and whether the presented head is disputed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PresentationV1 {
    /// The presented tier.
    pub presented: TrustTierV1,
    /// The reported head is newer than the verified head and differs from it.
    pub disagreement: bool,
}

/// The presentation of an item whose tiers are headed by `verified` and
/// `reported`; `None` when neither tier has a head.
#[must_use]
pub fn present(
    verified: Option<&CompletedVersionV1>,
    reported: Option<&CompletedVersionV1>,
) -> Option<PresentationV1> {
    match (verified, reported) {
        (Some(verified), reported) => Some(PresentationV1 {
            presented: TrustTierV1::Verified,
            disagreement: reported.is_some_and(|reported| {
                reported.provider_order > verified.provider_order
                    && reported.content_digest != verified.content_digest
            }),
        }),
        (None, Some(_)) => Some(PresentationV1 {
            presented: TrustTierV1::Reported,
            disagreement: false,
        }),
        (None, None) => None,
    }
}

#[cfg(test)]
#[path = "heads_tests.rs"]
mod tests;
