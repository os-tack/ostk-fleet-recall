//! Durable claim, conflict, concept, thread, and chain-event operations.

mod cockroach;
mod conflict;
mod lifecycle;
mod reconciliation;
mod repository;
mod types;

pub use cockroach::CockroachClaimLedger;
pub use conflict::{
    FUNCTIONAL_VALUE_CONFLICT_DETECTOR_V2, FUNCTIONAL_VALUE_CONFLICT_RATIONALE_V2, canonical_json,
    claim_key_from_parts, claims_are_incompatible, functional_values_are_incompatible,
    intervals_overlap, normalize_key_part,
};
pub(crate) use lifecycle::validate_reason as validate_lifecycle_reason;
pub use lifecycle::{
    LifecycleRefusal, MAX_ADJUDICATION_RATIONALE_CHARS, MAX_CONCESSION_CLAIMS,
    MAX_CONFLICT_LIFECYCLE_EVENTS, MAX_CONFLICT_MEMBER_COUNT, MAX_DISMISSED_PAIRS,
    MAX_OVERLAY_EPISODE_EVENTS, MAX_WAIVER_HOURS, RefusalCode, derive_overlay,
    dismissal_reason_kind, history_within_bytes, overlay_episode_revision, unlogged_transitions,
    waiver_reason_kind,
};
pub(crate) use lifecycle::{validate_rationale, validate_waiver_hours};
pub use reconciliation::{
    CockroachConflictReconciliationRepository, ConflictDetectorReconciliation,
};
pub(crate) use repository::assert_unavailable;
pub use repository::{ClaimLedger, SupportedClaimCoordinate, SupportedClaimIds};
pub(crate) use types::MAX_CLAIM_VALUE_SERIALIZED_BYTES;
pub use types::{
    AcceptedEventRefV1, Acknowledgement, AssertedClaimMutation, CitedItemV1, Claim, ClaimHistoryV1,
    ClaimInput, ClaimItemSupportV1, ClaimKind, ClaimLifecycleEventV1, ClaimMutation, ClaimState,
    ClaimSupport, ClaimSupportInput, ClaimTarget, ClaimsForKeyV1, ClosureView, Conflict,
    ConflictCoverage, ConflictHistory, ConflictLifecycleEvent, ConflictLifecycleOverlay,
    ConflictLifecycleRows, ConflictMutation, ConflictReevaluation, ConflictTarget, DismissalTerms,
    ITEM_SUPPORT_SOURCE, ITEM_SUPPORT_SOURCE_CONFIG_ID, ItemRefV1, ItemSupportInputV1, KeyClaimV1,
    LegacyClaimKeySampleV1, LegacyClaimKeysV1, LifecycleMutation, LifecycleReplayRequest,
    MAX_BRIEF_CLAIMS, MAX_CLAIM_HISTORY_EVENTS, MAX_CLAIM_HIT_VALUE_BYTES, MAX_KEY_LOOKUP_CLAIMS,
    MAX_KEY_LOOKUP_VALUE_BYTES, MAX_LEGACY_CLAIM_KEY_SAMPLE, MAX_OPEN_CONFLICT_ROWS,
    MAX_SUPPORT_ITEMS, OpenConflictRowV1, OpenConflictsV1, RecentClaimsV1, RevisionGap,
    SemanticClaimHit, SupersededClaim, SupportInputV1, WaiverTerms, WaiverView,
};
