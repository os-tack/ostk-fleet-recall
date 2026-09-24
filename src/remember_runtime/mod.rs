//! Server-side `remember(action="assert")` (item 1, ADR 0005).
//!
//! [`admission`] is pure. It turns an ergonomic MCP assertion plus the trusted
//! actor, semantic scope, and active registry head into the opaque
//! [`AdmittedRememberStatementV2`](crate::memory_contracts::remember_v2::AdmittedRememberStatementV2)
//! that the event-first append consumes. It reads no database: the append
//! transaction re-verifies the head and re-audits support events before it
//! commits.
//!
//! [`event_first`] is what a claim ledger holds to serve that append: a
//! writer-authority runtime and the actor it asserts as. The append itself,
//! and the claim projection committed with it, live in the claim ledger
//! (`CockroachClaimLedger::assert_claim`).

pub mod admission;
pub mod event_first;

pub use admission::{
    AdmittedRememberAssertionV1, AssertRouteDescriptionV1, AssertRoutePredicateV1,
    DimensionDerivationV1, RememberAdmissionRefusal, RememberAdmissionRefusalReason,
    RememberAssertInputV1, RememberAssertRouteV1, admit_remember_assertion, claim_kind_for,
    claim_polarity_for, modality_name, resolve_assert_route,
};
pub use event_first::{EventFirstAssert, actor_for_agent};
