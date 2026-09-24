//! Server-side `remember(action="assert")` (item 1, ADR 0005).
//!
//! [`admission`] is pure. It turns an ergonomic MCP assertion plus the trusted
//! actor, semantic scope, and active registry head into the opaque
//! [`AdmittedRememberStatementV2`](crate::memory_contracts::remember_v2::AdmittedRememberStatementV2)
//! that the event-first append consumes. It reads no database: the append
//! transaction re-verifies the head and re-audits support events before it
//! commits.

pub mod admission;

pub use admission::{
    AdmittedRememberAssertionV1, AssertRouteDescriptionV1, AssertRoutePredicateV1,
    DimensionDerivationV1, RememberAdmissionRefusal, RememberAdmissionRefusalReason,
    RememberAssertInputV1, RememberAssertRouteV1, admit_remember_assertion, claim_kind_for,
    claim_polarity_for, modality_name, resolve_assert_route,
};
