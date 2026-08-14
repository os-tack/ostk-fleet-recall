//! Durable claim, conflict, concept, thread, and chain-event operations.

mod cockroach;
mod conflict;
mod repository;
mod types;

pub use cockroach::CockroachClaimLedger;
pub use conflict::{
    canonical_json, claims_are_incompatible, intervals_overlap, normalize_key_part,
};
pub use repository::{ClaimLedger, SupportedClaimIds};
pub use types::{
    Claim, ClaimInput, ClaimKind, ClaimMutation, ClaimState, ClaimSupport, ClaimSupportInput,
    Conflict, ConflictCoverage, SemanticClaimHit,
};
