//! Normative activation runtime (W3-NORM, Stage 6).
//!
//! Makes the `normative_v2` contracts executable against `CockroachDB`: a
//! compare-and-set activation over the doc's composite head, a fail-closed
//! separation-of-duty verdict, the activation / retirement / supersession
//! lifecycle, and an active-normative projection advanced atomically with its
//! cursor.
//!
//! # Layout
//!
//! * [`projection`] — pure fold from an ordered normative log to one binding
//!   family's resolution. No I/O; unit-tested including every rejection path.
//! * [`repository`] — the admission rules (the whole fail-closed boundary, all
//!   pure), the request/outcome shapes, and the
//!   [`repository::NormativeActivationRepository`] trait.
//! * [`cockroach`] — the `CockroachDB` implementation over migration 0024.
//! * [`approvals`] — pure. Verifies Ed25519 approvals against the active
//!   activation policy's keys, under a normative-only signature domain, and
//!   mints the [`crate::memory_contracts::normative_v2::NormativeActivationReceiptV2`]
//!   [`repository::admit_activation`] consumes. The receipt is derived, never
//!   supplied: its principals are keys the live policy lists, its threshold is
//!   the policy's, and its `accepted_at` is the caller's server time.
//!
//! A caller holding a strict writer-authority witness takes the registry
//! binding from it ([`repository::NormativeRegistryBindingV1::from_witness`])
//! and requires the proposal to name exactly the witnessed head
//! ([`repository::require_witnessed_head`]), which adds the exact
//! `activation_id` (ABA safety) to the digest comparison `admit_activation`
//! makes.
//!
//! # Invariants this module enforces
//!
//! * **AUTH-03** — separation of duty is fail-closed and re-derived, never
//!   trusted as a flag. The contract's own
//!   [`crate::memory_contracts::normative_v2::NormativeActivationReceiptV2::validate`]
//!   re-derives the source-author rule from the declared approvals, and
//!   [`repository::admit_activation`] adds the runtime rule the contract layer
//!   cannot know: an approval set consisting *only* of actors implicated in the
//!   change (the source author and the proposer) is refused, so an implicated
//!   actor can never be the one who activates it.
//! * **AUTH-04** — normativity is event-derived. The lifecycle event is
//!   *derived* by the runtime from the proposal and the receipt, never supplied
//!   by the caller, so a caller cannot declare an activation to be a
//!   supersession or hand over a pre-signed event for a statement it did not
//!   propose. Nothing about a path or a filename grants normativity.
//! * **EVENT-03 / REPLAY-02** — the log append, the composite-head advance and
//!   the projection advance are ONE serializable transaction. The projection
//!   rebuilds byte-identically from the durable log
//!   ([`repository::NormativeActivationRepository::rebuild_projection`]), and a
//!   retirement or supersession appends rather than rewriting, so the prior
//!   activation stays queryable exactly as accepted.
//! * **Scope binding** — the proposal's authenticated project scope must be the
//!   scope the repository was constructed for, and every SQL statement is keyed
//!   by the trusted `(tenant_id, project)` pair. A proposal minted for another
//!   tenant or project is refused before a transaction opens.
//! * **Contested ⇒ unknown** — a contested overlap resolves to
//!   [`projection::NormativeResolutionV1::Unknown`]. There is no arm anywhere in
//!   [`projection`] that breaks a tie by recency or insertion order; the fold
//!   reads only order-insensitive sets, so reversing two conflicting records in
//!   the log produces the identical projection.

mod approvals;
mod cockroach;
mod projection;
mod repository;

pub use approvals::{
    NORMATIVE_APPROVAL_SIGNATURE_PREFIX, approval_attestation_id, normative_approval_message,
    verify_normative_approvals,
};
pub use cockroach::{CockroachNormativeActivationRepository, NormativeFaultInjection};
pub use projection::{
    MAX_FAMILY_LOG_ENTRIES, NORMATIVE_PROJECTION_SCHEMA_VERSION, NormativeFamilyProjectionV1,
    NormativeLogEntryV1, NormativeLogRecordV1, NormativePointResolutionV1, NormativeResolutionV1,
    NormativeStatementIntervalV1, apply_entry, project_family,
};
pub use repository::{
    AdmittedNormativeActivationV1, NormativeActivationCandidateV1, NormativeActivationOutcomeV1,
    NormativeActivationRepository, NormativeHeadRowV1, NormativeLifecycleRequestV1,
    NormativeRegistryBindingV1, NormativeTransitionV1, active_binding_set_digest, admit_activation,
    admit_contest, admit_lifecycle, require_non_conflicting_against_live, require_witnessed_head,
};
