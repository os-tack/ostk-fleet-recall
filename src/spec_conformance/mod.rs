//! Spec conformance (Stage 6): what an activated spec statement expects of the
//! code, and what each check of a commit concluded.
//!
//! The Stage-6 chain runs normative -> observer -> discrepancy: an operator
//! activates a signed spec statement, the observer reads the repository at a
//! commit, and a verified disagreement opens a `spec_nonconformance`
//! discrepancy episode. This module holds the parts of that chain the existing
//! runtimes do not:
//!
//! * [`expectation`] — [`RememberActionExpectationV1`], the typed meaning of a
//!   statement's single proposition (which enum in which Rust source file must
//!   or must not declare which member), bound to its normative proposal by
//!   fingerprint, and [`membership_value_digest`], the value both sides of a
//!   comparison digest.
//! * [`record`] — [`SpecCheckRecordV1`], one content-addressed record per
//!   comparison, whatever its [`SpecVerdictV1`]. Episodes record verified
//!   nonconformance only, so these records are how `conforming` and `unknown`
//!   stay visible instead of reading as silence.
//! * [`cockroach`] — [`CockroachSpecRepository`], the insert-only store over
//!   migration 0031's `memory_normative_statements_v1` and
//!   `memory_spec_checks_v1`, which re-verifies every row it reads.
//! * [`draft`] — [`draft_statement`], which builds a normative proposal and
//!   its expectation from a fresh witness and a local git reader: the spec
//!   document bound at an exact commit, its cited byte spans digested, the
//!   repository subject derived through the active package's recipe, and the
//!   registry head exactly the witnessed one.
//! * [`activation`] — [`activate_spec_statement`], the only path from a draft
//!   to a normative statement: exact witnessed head, a genesis-checkable
//!   expectation, approvals verified under the ACTIVE policy with a receipt
//!   minted at server time, then the statement row and the normative
//!   compare-and-set. `ostk-spec draft|approve|activate` is a thin shell over
//!   these two and [`crate::normative_runtime::sign_normative_approval`].
//! * [`check`] — [`run_spec_check`], the spec-nonconformance deriver behind
//!   `ostk-spec check`: select the statement in force, observe the commit
//!   through the genesis-admitted observer under the worker's git source
//!   identity, compare both sides with their coverage bounds
//!   ([`providers`]), open a `spec_nonconformance` episode only for a
//!   verified nonconformance ([`envelope`]), and record every comparison.
//! * [`lifecycle`] — [`append_episode_lifecycle`], behind
//!   `ostk-spec episode resolve|dismiss`: an operator closes a spec episode,
//!   since no check ever verifies a fix. A resolution cites evidence, by
//!   default the latest check of the violated statement; a dismissal gives a
//!   reason and a rationale. The event is appended to the episode's log and
//!   checked by the discrepancy contract against the stored envelope.
//! * [`registry`] — the compiled-in comparator lineage and episode policy
//!   spec episodes are judged and grouped under. They are not
//!   package-admitted (a DISC-06 deferral) and never change in place.
//! * [`read`] — [`CockroachSpecConformanceReader`], the SELECT-only read
//!   behind `recall(action="discrepancies")` and `recall(status)`'s
//!   `spec_conformance` block: the standing episodes of live specs (or every
//!   episode), each with the statement it violates and what its opening check
//!   observed, beside every live spec's latest check, so an agent can tell
//!   `unknown` and "never checked" from conforming.
//!
//! Nothing here grants authority. A statement is normative only once the
//! normative runtime has activated it under verified approvals; recording its
//! proposal and expectation here is what lets a later check recover what the
//! statement means, and a stored row that no longer derives its own identity
//! is refused rather than re-interpreted.

pub mod activation;
pub mod check;
pub mod cockroach;
pub mod draft;
pub mod envelope;
pub mod expectation;
pub mod lifecycle;
pub mod providers;
pub mod read;
pub mod record;
pub mod registry;

#[cfg(test)]
pub(crate) mod testkit;

pub use activation::{
    SpecActivationOutcomeV1, SpecActivationV1, activate_spec_statement, database_now,
    normative_repository, require_spec_statement, spec_repository,
};
pub use check::{
    DEFAULT_SPEC_MEMBER_BOUND, SpecCheckOutcomeV1, SpecCheckRequestV1, SpecDiscrepancyActionV1,
    SpecSelectionV1, run_spec_check,
};
pub use cockroach::{
    CockroachSpecRepository, MAX_CANONICAL_PROPOSAL_BYTES, MAX_CANONICAL_SPEC_RECORD_BYTES,
    MAX_LATEST_CHECK_STATEMENTS, RecordedSpecStatementV1, SpecCheckWriteV1, SpecRowWriteV1,
    SpecStatementWriteV1, StoredSpecCheckV1,
};
pub use draft::{
    DraftStatementRequestV1, MAX_SPEC_DOCUMENT_BYTES, REPOSITORY_IDENTITY_RECIPE_ID,
    REPOSITORY_LOCATOR_KEY, SPEC_OBSERVER_ID, SPEC_OBSERVER_VERSION, draft_spec_statement,
    draft_statement, repository_subject, select_spans, spec_applicability_evaluator,
    spec_parser_artifact_id, spec_predicate, spec_span_digest,
};
pub use envelope::{
    SPEC_EXPECTATION_POLICY_VERSION, SPEC_OPENING_PROVIDER_ORDER, SpecDetectionV1,
    build_spec_envelope, observer_source_fact_id, spec_applicability, spec_expectation_policy,
    spec_family_fingerprint,
};
pub use expectation::{
    ExpectedMembershipV1, MAX_RUST_IDENTIFIER_BYTES, MAX_SOURCE_PATH_BYTES,
    REMEMBER_ACTION_EXPECTATION_SCHEMA_VERSION, REPOSITORY_SELECTOR_KEY,
    RememberActionExpectationV1, membership_value_digest, repository_selector,
};
pub use lifecycle::{
    SpecEpisodeLifecycleV1, SpecEpisodeTransitionV1, append_episode_lifecycle,
    default_resolution_evidence, spec_episode_statement, spec_lifecycle_event,
};
pub use providers::{
    NormativeStatementSide, OPEN_ENDED_AT, ObservedMembershipSide, compare_spec_sides,
    compared_window, spec_verdict,
};
pub use read::{
    CockroachSpecConformanceReader, MAX_DISCREPANCY_RESULTS, MAX_EPISODE_HISTORY, MAX_LISTED_SPECS,
    SPEC_CONFORMANCE_NOTE, SpecConformanceAnswerV1, SpecConformanceRead, SpecConformanceStatusV1,
    SpecConformanceWarningV1, SpecCoverageV1, SpecDiscrepancyV1, SpecEpisodeEventV1,
    SpecEvidenceV1, SpecExpectationViewV1, SpecLastCheckV1, SpecObservationV1, SpecStatementViewV1,
    SpecSummaryV1, start_spec_conformance,
};
pub use record::{
    MAX_SPEC_CHECK_REASONS, SPEC_CHECK_RECORD_SCHEMA_VERSION, SpecCheckRecordV1, SpecVerdictV1,
};
pub use registry::{
    SPEC_APPLICABILITY_DIMENSION, SPEC_COMPARATOR_ID, SPEC_COMPARATOR_VERSION,
    SPEC_EPISODE_POLICY_ID, SPEC_EPISODE_POLICY_VERSION, comparator_lineage_entry,
    episode_policy_entry, spec_comparator_lineage, spec_episode_policy,
};
