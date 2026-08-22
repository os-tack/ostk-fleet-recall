//! CI-evidence connector (W3-CIEV): GitHub Actions workflow runs -> accepted
//! events.
//!
//! # The question this exists to make answerable
//!
//! Before this connector, "when did CI first fail?" returned UNKNOWN — and not
//! because coverage was partial. NO connector read CI at all, so there was
//! nothing in the memory that had ever observed a build. This module is the
//! third instance of the established connector pattern (after
//! [`super::git`] and [`super::transcript`]): same module layout, same W1-EVID
//! admission seam, same drain and watermark discipline. What is new is the
//! provider and the epistemics it forces.
//!
//! # What this connector claims
//!
//! Two families of provider fact, and no more:
//!
//! * **Settled workflow runs.** A run that the provider has completed with a
//!   settled conclusion, together with its jobs, their steps, and the failure
//!   annotations attached to the jobs that failed. A settled run is immutable,
//!   so it is Version-form-addressable; an unsettled one is refused.
//! * **Window observations.** The finite range of run numbers one scan read, on
//!   one workflow and one branch, at one instant. A branch's CI history is
//!   unbounded and this connector reads a slice of it, so the durable fact is
//!   the *observation of a slice*, never "the CI history".
//!
//! # What it deliberately cannot claim
//!
//! It cannot claim that a run outside its window did or did not fail, and it
//! cannot claim a window the provider's own answer did not reach: a `gh`
//! listing cut off by its `--limit` narrows the minted window to the oldest run
//! it actually names, or is refused outright, rather than reporting an unread
//! range as measured ([`scan`]).
//! [`answer_first_failure`] checks containment BEFORE it examines any run, so a
//! question reaching outside the measured range resolves to
//! [`CiFirstFailureAnswerV1::Unknown`] rather than to a negative. Absence of a
//! failure inside a bounded window is not evidence of absence outside it, and
//! [`CiFirstFailureAnswerV1::is_verified_negative`] is false for every unknown
//! answer so a caller cannot read one as the other by accident.
//!
//! It also cannot claim a run is immutable when the provider has not settled
//! it. An in-flight, queued, or cancelled run has no immutable revision, so
//! [`CiWorkflowRunFactV1::validate`] refuses it with
//! [`CiFactError::UnsettledRun`] before any identity is derived.
//!
//! # Layout
//!
//! * [`fact`] — the provider-truth model, the identity derivations, and the
//!   bounded-coverage epistemics. Pure; unit-tested including every rejection
//!   path.
//! * [`scan`] — the provider seam ([`CiRunProvider`]) with a real `gh`
//!   implementation and a recorded one, plus the payload parsers. Tests use the
//!   recorded side only and never open a socket.
//! * [`ingress`] — resolving the active package's CI connector and building
//!   [`crate::memory_contracts::evidence_v2::EvidenceIngressCandidateV2`]s whose
//!   scope comes from the witness and whose locator coordinates come from the
//!   activated recipe.
//! * [`drain`] — admitting and appending a batch through the W1-EVID seam, plus
//!   the coverage observation and the run-number resume cursor.
//! * [`cockroach`] — migration 0026's measured-window record.
//!
//! # Invariants this module enforces
//!
//! * **EVID-04 / AUTH-04** — every candidate's scope is
//!   [`crate::evidence_ledger::ActiveStage4Package::scope`], which is the writer
//!   credential's. No CI fact carries a scope field at all, so a payload cannot
//!   declare one, and `#[serde(deny_unknown_fields)]` refuses a payload that
//!   tries.
//! * **EVID-02 / PROV-01** — locator coordinates are filled only from proven
//!   values; a recipe naming a coordinate this connector cannot prove is refused
//!   rather than guessed.
//! * **EVID-03** — `occurred_at` (the provider's settle instant), `observed_at`
//!   (the scan's fetch instant), and `received_at` (the ingress instant) are
//!   three distinct clocks, ordered before admission is called, and a provider
//!   clock ahead of the reader's is refused rather than back-dated.
//! * **EVENT-01 / REPLAY-01** — a re-drain of the same recorded scan reproduces
//!   byte-identical facts and clocks, so the ledger classifies it as an exact
//!   replay; a re-run of a workflow produces a new attempt and therefore a new
//!   immutable revision rather than a mutation of the old one.
//! * **EVID-05** — no private raw artifact is ever emitted, and no provider
//!   credential is read, stored, or transported: the real reader inherits
//!   ambient `gh` authentication from the operator's environment.
//! * **COVER-01..03** — a coverage receipt is only built when the drain produced
//!   a durable window-observation event to bind, and only from facts the ledger
//!   made durable. A quarantined window voids the whole scope's receipt closed
//!   rather than letting an older surviving window stand in for it.

pub mod cockroach;
pub mod drain;
pub mod error;
pub mod fact;
pub mod ingress;
pub mod scan;

pub use cockroach::{
    CiMeasuredWindowRepository, CiMeasuredWindowRowV1, CockroachCiMeasuredWindowRepository,
};
pub use drain::{
    CiCoverageBindingV1, CiDrainContextV1, CiDrainReportV1, ci_coverage_observation,
    ci_fact_canonical_bytes, ci_fact_manifest_keys, ci_resume_run_number, ci_scan_facts,
    ci_scan_manifest_digest, drain_ci_facts,
};
pub use error::{
    CiDrainError, CiDrainResult, CiFactError, CiFactResult, CiIngressError, CiIngressResult,
    CiScanError, CiScanResult,
};
pub use fact::{
    CI_FACT_SCHEMA_VERSION, CiCommitShaV1, CiCoverageWindowV1, CiFactKindV1, CiFactV1,
    CiFailureQuestionV1, CiFirstFailureAnswerV1, CiJobV1, CiOutcomeV1, CiRepositoryIdV1,
    CiRunRangeV1, CiRunStatusV1, CiStepV1, CiTextV1, CiUnknownReasonV1, CiWindowObservationFactV1,
    CiWindowObservationLogV1, CiWorkflowRunFactV1, MAX_CI_JOBS, MAX_CI_STEPS, MAX_CI_TEXT_BYTES,
    MAX_CI_WINDOW_RUNS, answer_first_failure,
};
pub use ingress::{CI_FACT_MEDIA_TYPE, CiConnectorBindingV1, CiIngressClocksV1, CiIngressV1};
pub use scan::{
    CiRunProvider, CiScanRequestV1, CiScanV1, GH_RUN_LIST_FIELDS, GhCliRunProvider,
    MAX_GH_RUN_LIST_LIMIT, RecordedRunProvider, scan_runs,
};
