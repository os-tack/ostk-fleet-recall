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
//!
//! [`serve`] is how `serve` starts it: served when the writer-authority pins
//! verify, off (with a reason `recall(status)` reports) when they are
//! configured but unusable, and absent when they are not configured. It never
//! stops `serve` from starting.
//!
//! [`capture`] is `remember(action="capture")` (ADR 0008 D10): an agent
//! relays items it read through its own connectors into the collected-item
//! sink as reported items it attests, served only where
//! `FLEET_RECALL_COLLECTED_CAPTURE` turns it on and its startup checks pass.
//! Like assert, it never stops `serve` from starting.

pub mod admission;
pub mod capture;
pub mod event_first;
pub mod serve;

pub use admission::{
    AdmittedRememberAssertionV1, AssertRouteDescriptionV1, AssertRoutePredicateV1,
    DimensionDerivationV1, RememberAdmissionRefusal, RememberAdmissionRefusalReason,
    RememberAssertInputV1, RememberAssertRouteV1, admit_remember_assertion, claim_kind_for,
    claim_polarity_for, modality_name, resolve_assert_route,
};
pub use capture::{
    CAPTURE_OPERATION, CaptureDispositionV1, CaptureIdentityV1, CaptureOutcomeV1, CaptureRequestV1,
    CaptureResponseV1, CaptureStartup, CaptureStatusV1, CapturedItemV1, CockroachCapture,
    ItemCapture, MAX_CAPTURE_ITEMS, MAX_CAPTURE_TEXT_BYTES, PreparedCaptureV1,
    start_collected_capture, start_collected_capture_with,
};
pub use event_first::{EventFirstAssert, actor_for_agent};
pub use serve::{
    AssertStartup, AssertStatusV1, start_event_first_assert, start_event_first_assert_with,
};
