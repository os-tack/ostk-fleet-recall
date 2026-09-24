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
    LifecycleRefusal, MAX_CONCESSION_CLAIMS, MAX_CONFLICT_LIFECYCLE_EVENTS,
    MAX_CONFLICT_MEMBER_COUNT, MAX_OVERLAY_EPISODE_EVENTS, RefusalCode, derive_overlay,
    history_within_bytes, overlay_episode_revision, unlogged_transitions,
};
pub use reconciliation::{
    CockroachConflictReconciliationRepository, ConflictDetectorReconciliation,
};
pub use repository::{ClaimLedger, SupportedClaimCoordinate, SupportedClaimIds};
pub use types::{
    Acknowledgement, Claim, ClaimInput, ClaimKind, ClaimMutation, ClaimState, ClaimSupport,
    ClaimSupportInput, ClaimTarget, ClosureView, Conflict, ConflictCoverage, ConflictHistory,
    ConflictLifecycleEvent, ConflictLifecycleOverlay, ConflictLifecycleRows, ConflictMutation,
    ConflictReevaluation, ConflictTarget, LifecycleMutation, LifecycleReplayRequest, RevisionGap,
    SemanticClaimHit, SupersededClaim, WaiverView,
};
