//! The exhaustive observer runtime (W3-OBSRT, Stage 6).
//!
//! One private worker, no public route. It evaluates
//! `mcp.remember.allowed_actions` over the `RememberAction` enum
//! ([`crate::service::RememberAction`]) at an EXACT commit and blob, and emits
//! two things that commit together: a run receipt and a typed observer-result
//! accepted event.
//!
//! # The one claim this runtime exists to make honestly
//!
//! Partial coverage can never yield a verified negative. Three independent
//! layers enforce it, and each is a plain test away from being checked:
//!
//! 1. [`enumeration`] returns exhaustiveness and the reasons it might be
//!    wrong as ONE value: [`enumeration::RustEnumEnumerationV1::exhaustive`]
//!    is exactly "no diagnostics were raised", so a caller cannot keep the
//!    claim and drop the caveats.
//! 2. [`receipt`] refuses to evaluate an absence at all under a non-exhaustive
//!    read: the evaluated condition becomes
//!    [`EvaluatedConditionV1::Indeterminate`](crate::memory_contracts::observer::EvaluatedConditionV1::Indeterminate)
//!    rather than `Absent`, and the run receipt's unsupported input tally and
//!    coverage witness both carry the gap.
//! 3. The contract's own
//!    [`derive_verification_outcome`](crate::memory_contracts::observer::derive_verification_outcome)
//!    independently refuses `verified_negative`/`verified_exact_set` without
//!    `closed_world_verified`, zero gap inputs, and complete/current/contiguous
//!    coverage — and [`build_observer_result`](crate::memory_contracts::observer::build_observer_result)
//!    recomputes it, so the runtime cannot label an outcome it did not derive.
//!
//! Layer 3 alone would be enough for the ledger; layers 1 and 2 exist so that
//! the *receipt* is honest about the read even where the outcome would have
//! been indeterminate anyway.
//!
//! # Naming the git object, not "the current source"
//!
//! [`source`] binds a commit id, a path, a blob object id, and a blob content
//! digest, all supplied as pins, and refuses closed on any disagreement. It
//! takes a commit OBJECT ID, never a revision expression, so the repository
//! cannot decide at read time what "the" source is. It re-hashes the bytes it
//! read back to the git object id it asked for, so an object store that
//! answers a request for blob B with different bytes is caught rather than
//! believed. And the run receipt's `source_version` is derived through the
//! ACTIVATED `identity.github.commit` recipe, so the URI naming the observed
//! revision is the one the registry's own identity rules produce.
//!
//! # Admission is governance, not configuration
//!
//! [`admission`] resolves the observer's admission out of the genesis registry
//! package that the deployment-pinned bootstrap receipt names, and refuses
//! unless the runtime's declared executable identity, dependency closure,
//! configuration context, admission mode, and predicate reference all equal
//! what that activated entry decided (AUTH-03: an observer cannot admit
//! itself). That is also why the remember basis cannot move as a side effect
//! of a run: this runtime reads the activated
//! [`RememberAdmissionRuleV2`](crate::memory_contracts::remember_v2::RememberAdmissionRuleV2)
//! and refuses to run at all if the active package would let a
//! `registered_observer` append happen, rather than performing one. Flipping
//! the basis remains a package change.
//!
//! # Atomicity and replay
//!
//! [`drain`] hands the run record to [`crate::evidence_ledger::admit_evidence`]
//! and appends through [`crate::evidence_ledger::AcceptedEventRepository`],
//! with the governed content object carrying the run receipt in the SAME
//! serializable transaction as the accepted event (EVENT-03). Every byte of
//! the record is a function of the admission, the pinned source, and the
//! algorithm's output — no wall clock inside the preimage — so a second run
//! over the same pins reproduces the same source-fact and representation
//! identity and the ledger classifies it as an exact replay (REPLAY-01).

pub mod admission;
pub mod drain;
pub mod enumeration;
pub mod error;
pub mod ingress;
pub mod receipt;
pub mod source;

pub use admission::{
    ADMISSION_ENUMERATION_ALGORITHM, ADVERSARIAL_VECTOR_DIGEST, CLOSED_INPUT_BOUNDARY,
    MUTATION_VECTOR_DIGEST, NEGATIVE_VECTOR_DIGEST, OBSERVER_CONNECTOR_SCHEMA, OBSERVER_KIND,
    ObserverAdmissionBindingV1, ObserverRuntimeDeclarationV1, POSITIVE_VECTOR_DIGEST,
    REQUIRED_APPLICABILITY_DIMENSION, SUPPORTED_RESOURCE_KIND, SUPPORTED_SOURCE_KIND,
    TOOLCHAIN_API_VERSION, TOOLCHAIN_COMPILER_VERSION, TOOLCHAIN_LANGUAGE_VERSION,
    TOOLCHAIN_SCHEMA_VERSION, dependency_closure_digest, observer_input_domain,
    observer_toolchain_versions, remember_basis_is_package_governed,
    require_remember_basis_is_package_governed,
};
pub use drain::{
    ObserverAppendDispositionV1, ObserverDrainContextV1, ObserverRunOutcomeV1, drain_observer_run,
};
pub use enumeration::{
    ALL_DIAGNOSTICS, DIAGNOSTIC_BOUND_EXCEEDED, DIAGNOSTIC_ENUM_ATTRIBUTE, DIAGNOSTIC_ENUM_GENERIC,
    DIAGNOSTIC_MACRO_UNRESOLVED, DIAGNOSTIC_NON_EXHAUSTIVE, DIAGNOSTIC_SOURCE_UNBALANCED,
    DIAGNOSTIC_VARIANT_ATTRIBUTE, DIAGNOSTIC_VARIANT_PAYLOAD, DIAGNOSTIC_VARIANT_UNRECOGNISED,
    ENUMERATION_ALGORITHM_ID, MAX_MEMBER_BOUND, RustEnumEnumerationV1, SET_PRESERVING_ATTRIBUTES,
    enumerate_rust_enum,
};
pub use error::{ObserverRuntimeError, ObserverRuntimeResult};
pub use ingress::{
    OBSERVER_RUN_RECORD_MEDIA_TYPE, ObserverConnectorBindingV1, ObserverIngressClocksV1,
    ObserverIngressV1,
};
pub use receipt::{
    MAX_OBSERVED_SOURCE_BYTES, ObserverQuestionV1, ObserverRunPlanV1, ObserverRunRecordV1,
    build_observer_run,
};
pub use source::{
    ObservedSourceV1, ObserverSourcePinV1, bind_observed_source, source_content_digest,
};
