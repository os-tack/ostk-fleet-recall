//! Discrepancy ledger runtime (W3-DISC, Stage 6).
//!
//! Makes the `discrepancy` contracts executable against `CockroachDB`: the
//! immutable per-detection envelope admitted as a durable log seed, the
//! append-only lifecycle transitions and episode relations, and the pure,
//! order-independent replay into a durable, byte-reproducible episode
//! projection. This is the runtime that turns "the observed world disagrees
//! with the normative world" from a type into a durable, replayable ledger.
//!
//! # Layout
//!
//! * [`projection`] — pure. The coverage-bounded two-sided comparison (a
//!   finding's two sides each carry their own coverage bound as data, and an
//!   unmeasured or partial side poisons the claim to an explicit
//!   indeterminate verdict), the total-order opening-transition seeding, and
//!   the deterministic ledger projection wrapper. No I/O.
//! * [`repository`] — the admission rules (the whole fail-closed boundary,
//!   all pure), the record/outcome shapes, and the
//!   [`repository::DiscrepancyLedgerRepository`] trait.
//! * [`cockroach`] — the `CockroachDB` implementation over migration 0027.
//!
//! # Invariants this module enforces
//!
//! * **DISC-01 / DISC-02** — lifecycle state never defines identity. The
//!   envelope's digest preimage carries no lifecycle or verification state
//!   (that is the contract's own shape), and this runtime never rewrites an
//!   admitted envelope: family and episode fingerprints are byte-identical
//!   under any acknowledge/waive/resolve/dismiss history.
//! * **REPLAY-01** — replay is pure and order-independent. The stored
//!   projection is a total function of the durable log and relation set,
//!   evaluated at an instant derived from the log itself
//!   ([`projection::ledger_evaluation_time`]) rather than a wall clock, so
//!   [`repository::DiscrepancyLedgerRepository::rebuild_projection`] must
//!   reproduce the stored bytes exactly — including when a late event (an
//!   `effective_at` before an already-applied event) arrives last.
//! * **Total-order opening** — the episode-seeding transition is selected by
//!   the total order over `(effective_at, provider_order, source_fact_id)`
//!   ([`projection::seed_episode_fingerprint`]); receipt order never
//!   participates, so re-ingesting the same facts in a different sequence
//!   cannot move an episode fingerprint.
//! * **An unmeasured side poisons the claim** — every comparison input
//!   carries its own coverage bound as data
//!   ([`projection::MeasuredComparisonSideV1`]), the provider seam's
//!   [`projection::ComparisonSideProvider::measure`] has deliberately no
//!   default implementation, and a partial/unknown/stale/unmeasured side
//!   resolves to [`projection::ComparisonVerdictV1::Indeterminate`] — never
//!   to a verified negative and never to a confirmed finding.
//! * **Scope binds from the runtime, never the payload** — every record's
//!   authenticated scope must equal the scope bound at construction, every
//!   SQL statement is keyed by the trusted `(tenant_id, project)` pair, and
//!   a payload minted for another tenant or project is refused before a
//!   transaction opens.

mod cockroach;
mod projection;
mod repository;

#[cfg(test)]
pub(crate) mod testbed;

pub use cockroach::{CockroachDiscrepancyLedgerRepository, MAX_FAMILY_EPISODES};
pub use projection::{
    ComparisonIndeterminacyV1, ComparisonSideProvider, ComparisonSideRoleV1, ComparisonVerdictV1,
    DISCREPANCY_RUNTIME_SCHEMA_VERSION, MAX_EPISODE_LOG_ENTRIES, MAX_FAMILY_RELATIONS,
    MeasuredComparisonSideV1, compare_measured_sides, compare_sides, ledger_evaluation_time,
    project_ledger_episode, seed_episode_fingerprint,
};
pub use repository::{
    AdmittedDiscrepancyEnvelopeV1, AdmittedDiscrepancyLifecycleEventV1,
    AdmittedDiscrepancyRelationV1, DiscrepancyAppendOutcomeV1, DiscrepancyEnvelopeCandidateV1,
    DiscrepancyLedgerRepository, DiscrepancyLedgerTransitionV1, DiscrepancyLogEntryV1,
    DiscrepancyLogRecordV1, DiscrepancyOpeningOutcomeV1, DiscrepancyRegistryBindingV1,
    STANDING_LIFECYCLE_STATES, StoredDiscrepancyProjectionV1, admit_envelope,
    admit_lifecycle_event, admit_relation, is_standing, lifecycle_state_from_str,
    lifecycle_state_str, verification_state_from_str, verification_state_str,
};
