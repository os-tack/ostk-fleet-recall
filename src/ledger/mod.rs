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
    claims_are_incompatible, functional_values_are_incompatible, intervals_overlap,
    normalize_key_part,
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
pub use types::{
    AcceptedEventRefV1, Acknowledgement, AssertedClaimMutation, Claim, ClaimInput, ClaimKind,
    ClaimMutation, ClaimState, ClaimSupport, ClaimSupportInput, ClaimTarget, ClosureView, Conflict,
    ConflictCoverage, ConflictHistory, ConflictLifecycleEvent, ConflictLifecycleOverlay,
    ConflictLifecycleRows, ConflictMutation, ConflictReevaluation, ConflictTarget, DismissalTerms,
    LifecycleMutation, LifecycleReplayRequest, RevisionGap, SemanticClaimHit, SupersededClaim,
    WaiverTerms, WaiverView,
};
