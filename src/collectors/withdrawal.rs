//! Withdrawals: how a narrowed audience hides what the memory already
//! admitted, and what may lift that (ADR 0008 D5, D6; migration 0034).
//!
//! Everything here is pure. The sink reads the stored rows under
//! `SELECT ... FOR UPDATE` in its staging transaction, asks these functions
//! what they become, and writes the answer in the same transaction.
//!
//! # Containers
//!
//! A container observation (a pull's channel list, an import's export) either
//! admits the container on a basis or refuses it. [`container_write`] decides
//! what that does to the stored row, under one rule: **a withdrawal is lifted
//! only by a channel at least as trusted as the one that made it.**
//!
//! * An admissible observation records a new container, and re-opens or
//!   relabels a recorded one, unless a report (an import) would override a
//!   verification (a pull or a push): a stale export can never re-open a
//!   channel a pull saw go private.
//! * A refusal withdraws a readable container, whatever the channel: narrowing
//!   is always safe. A verified refusal of a container a report withdrew makes
//!   the withdrawal verified, so no report can lift it any more.
//! * A refusal of a container the memory never recorded is recorded as
//!   withdrawn, with no audience basis, when it is a fact about the container
//!   (a direct conversation, a container shared with another organization, a
//!   restricted container the operator did not list): captures into it are
//!   refused, and what a capture scope admitted through it is withheld.
//!   A refusal that is only the instance's own policy (no operator
//!   declaration) records nothing new.
//!
//! # Items
//!
//! An item can narrow on its own, without its container changing: a Linear
//! issue moved into a private team that is not listed arrives in a restricted
//! container, and its earlier versions sit in a public one. When a channel
//! that observes provider audience (a pull, a push, an import) refuses a
//! draft of an item the memory has already admitted or staged, the item is
//! withdrawn for that channel's trust tier ([`after_refusal`]), and evidence
//! recall withholds every body of it. A first sighting is only a dead letter.
//!
//! Each tier's row keeps the provider order of the observation that last
//! decided it. A refusal older than what the row, or an admissible version a
//! lifting channel already staged, says is stale and changes nothing. An
//! admissible observation at an order at least as great, through a channel at
//! least as trusted ([`may_lift`]), lifts the withdrawal ([`after_admission`]);
//! at an equal order the later observation wins, so an operator who lists the
//! private team sees the item on the next read of it. A capture neither
//! withdraws nor lifts: it has no audience facts of its own.

use crate::memory_contracts::collected_item::{AudienceBasisV1, CollectionModeV1, TrustTierV1};

use super::audience::{AudienceDecisionV1, AudienceRefusalV1};

/// Whether a container row is readable or withdrawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerAccessV1 {
    /// Recorded as readable by the project.
    Ok,
    /// Withdrawn: every item in it is withheld.
    Withdrawn,
}

/// The stored state of one container row that decides a write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredContainerV1 {
    /// Its access.
    pub access: ContainerAccessV1,
    /// The tier of the observation that last set it; a row written before
    /// migration 0034 is read as verified.
    pub tier: TrustTierV1,
}

/// What one container observation writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerWriteV1 {
    /// Record the container as readable on this basis: a new row, or a
    /// recorded one re-opened or relabelled.
    Record(AudienceBasisV1),
    /// Record a container the memory never recorded as withdrawn.
    RecordWithdrawn,
    /// Withdraw a readable container.
    Withdraw,
    /// Keep a withdrawal a report made, now on a verified channel's word.
    Confirm,
    /// Change nothing.
    Keep,
}

/// Whether an observation through `observer` may override state `stored`
/// set: a verification overrides anything, a report only a report.
#[must_use]
pub const fn may_lift(observer: TrustTierV1, stored: TrustTierV1) -> bool {
    matches!(observer, TrustTierV1::Verified) || matches!(stored, TrustTierV1::Reported)
}

/// Whether a refusal is a fact about the container itself, as opposed to the
/// instance's own policy or a missing fact.
#[must_use]
pub const fn describes_container(refusal: AudienceRefusalV1) -> bool {
    matches!(
        refusal,
        AudienceRefusalV1::DirectMessage
            | AudienceRefusalV1::ExternallyShared
            | AudienceRefusalV1::RestrictedUnlisted
    )
}

/// What a container observation through a channel of tier `observer`, with
/// audience decision `decision`, does to the row `stored`.
#[must_use]
pub const fn container_write(
    stored: Option<StoredContainerV1>,
    decision: AudienceDecisionV1,
    observer: TrustTierV1,
) -> ContainerWriteV1 {
    match (decision, stored) {
        (AudienceDecisionV1::Admit(basis), None) => ContainerWriteV1::Record(basis),
        (AudienceDecisionV1::Admit(basis), Some(stored)) => {
            if may_lift(observer, stored.tier) {
                ContainerWriteV1::Record(basis)
            } else {
                ContainerWriteV1::Keep
            }
        }
        (AudienceDecisionV1::Refuse(refusal), None) => {
            if describes_container(refusal) {
                ContainerWriteV1::RecordWithdrawn
            } else {
                ContainerWriteV1::Keep
            }
        }
        (
            AudienceDecisionV1::Refuse(_),
            Some(StoredContainerV1 {
                access: ContainerAccessV1::Ok,
                ..
            }),
        ) => ContainerWriteV1::Withdraw,
        (
            AudienceDecisionV1::Refuse(_),
            Some(StoredContainerV1 {
                access: ContainerAccessV1::Withdrawn,
                tier: TrustTierV1::Reported,
            }),
        ) if matches!(observer, TrustTierV1::Verified) => ContainerWriteV1::Confirm,
        (AudienceDecisionV1::Refuse(_), Some(_)) => ContainerWriteV1::Keep,
    }
}

/// Whether a channel observes provider audience, so its refusals withdraw
/// items and its admissions lift item withdrawals. A capture has no audience
/// facts of its own.
#[must_use]
pub const fn observes_item_audience(mode: CollectionModeV1) -> bool {
    matches!(
        mode,
        CollectionModeV1::Pull | CollectionModeV1::Push | CollectionModeV1::Import
    )
}

/// Whether a refusal says an item's own audience narrowed: the provider puts
/// it in a direct, shared, or unlisted restricted container, or the importer
/// marked it private or direct.
///
/// A container already withdrawn is not such a fact: it hides the item's
/// bodies there by itself, and an item withdrawal on top of it would outlive
/// the container's re-opening.
#[must_use]
pub const fn narrows_item(refusal: AudienceRefusalV1) -> bool {
    matches!(
        refusal,
        AudienceRefusalV1::DirectMessage
            | AudienceRefusalV1::ExternallyShared
            | AudienceRefusalV1::RestrictedUnlisted
            | AudienceRefusalV1::HintRefused
    )
}

/// One tier's item-withdrawal row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ItemWithdrawalStateV1 {
    /// Whether the item is withdrawn for this tier.
    pub withdrawn: bool,
    /// The provider order of the observation that last decided it.
    pub order: u64,
}

/// What a narrowing refusal at `order` does to its own tier's row.
///
/// `stored` is that row. Without one, `seen` says whether the memory holds
/// any admitted or staged part of the item (else the refusal is a first
/// sighting, not a narrowing), and `newest_admissible` is the greatest order
/// at which a channel that may lift the row staged the item. Returns the new
/// row, or `None` when nothing changes.
#[must_use]
pub fn after_refusal(
    stored: Option<ItemWithdrawalStateV1>,
    order: u64,
    seen: bool,
    newest_admissible: Option<u64>,
) -> Option<ItemWithdrawalStateV1> {
    let withdrawn = ItemWithdrawalStateV1 {
        withdrawn: true,
        order,
    };
    let changes = stored.map_or_else(
        || seen && newest_admissible.is_none_or(|newest| order >= newest),
        |stored| order >= stored.order && stored != withdrawn,
    );
    changes.then_some(withdrawn)
}

/// What an admissible observation at `order` does to a row its channel
/// [`may_lift`].
///
/// A withdrawal at an order no greater is lifted, and a lifted row remembers
/// the greater order, so a stale refusal arriving later changes nothing.
/// Returns the new row, or `None`.
#[must_use]
pub fn after_admission(stored: ItemWithdrawalStateV1, order: u64) -> Option<ItemWithdrawalStateV1> {
    let lifted = ItemWithdrawalStateV1 {
        withdrawn: false,
        order,
    };
    let changes = if stored.withdrawn {
        order >= stored.order
    } else {
        order > stored.order
    };
    changes.then_some(lifted)
}

#[cfg(test)]
#[path = "withdrawal_tests.rs"]
mod tests;
