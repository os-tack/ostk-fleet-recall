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
//!
//! Nothing here grants authority. A statement is normative only once the
//! normative runtime has activated it under verified approvals; recording its
//! proposal and expectation here is what lets a later check recover what the
//! statement means, and a stored row that no longer derives its own identity
//! is refused rather than re-interpreted.

pub mod cockroach;
pub mod expectation;
pub mod record;

#[cfg(test)]
pub(crate) mod testkit;

pub use cockroach::{
    CockroachSpecRepository, MAX_CANONICAL_PROPOSAL_BYTES, MAX_CANONICAL_SPEC_RECORD_BYTES,
    MAX_LATEST_CHECK_STATEMENTS, RecordedSpecStatementV1, SpecCheckWriteV1, SpecRowWriteV1,
    SpecStatementWriteV1, StoredSpecCheckV1,
};
pub use expectation::{
    ExpectedMembershipV1, MAX_RUST_IDENTIFIER_BYTES, MAX_SOURCE_PATH_BYTES,
    REMEMBER_ACTION_EXPECTATION_SCHEMA_VERSION, REPOSITORY_SELECTOR_KEY,
    RememberActionExpectationV1, membership_value_digest, repository_selector,
};
pub use record::{
    MAX_SPEC_CHECK_REASONS, SPEC_CHECK_RECORD_SCHEMA_VERSION, SpecCheckRecordV1, SpecVerdictV1,
};
