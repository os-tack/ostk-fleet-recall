//! Turning one enumeration into a run receipt and an observer result (W3-OBSRT).
//!
//! # Where "partial coverage never verifies a negative" is actually decided
//!
//! Twice, in this file, before the contract gets a third say:
//!
//! * [`evaluate_question`] refuses to report `absent` under a non-exhaustive
//!   read. A scan that stopped early, or that met a `#[cfg]` gate it never
//!   evaluated, genuinely does not know whether the action it was asked about
//!   is missing or merely unread, so the honest evaluated condition is
//!   `indeterminate` — not `absent` with a caveat attached somewhere else.
//! * [`input_accounting`] derives the run's tallies from the enumeration, not
//!   from a caller. Every diagnostic becomes an `unsupported` input, and
//!   `unsupported` is one of the four categories the contract requires to be
//!   empty before a verified negative or exact set is reachable. There is no
//!   argument through which a caller can report zero unsupported inputs for a
//!   read that raised diagnostics.
//!
//! [`coverage_witness`] then reports `partial` completeness for the same
//! reads, so the third layer — the contract's own
//! [`derive_verification_outcome`] — refuses independently. Three layers is
//! not redundancy for its own sake: layer three protects the LEDGER, and
//! layers one and two make the RECEIPT honest, which matters because the
//! receipt is what a human reads when they want to know what the observer
//! actually saw.
//!
//! # No clock inside the preimage
//!
//! `observed_at` is the observed commit's own instant, so two runs over the
//! same pins produce byte-identical receipts, results, and accepted-event
//! identities. That is what makes replay an exact replay rather than an
//! integrity collision (REPLAY-01, EVENT-01).

use serde::{Deserialize, Serialize};

use crate::memory_contracts::canonical::encode_canonical;
use crate::memory_contracts::common::{
    AuthenticatedProjectScopeV1, ContractId, ProfileReferenceV1,
};
use crate::memory_contracts::digest::{DigestDomain, Sha256Digest, framed_digest};
use crate::memory_contracts::evidence::AcceptedEventId;
use crate::memory_contracts::identity::ResourceUri;
use crate::memory_contracts::observer::{
    AdmittedObserverResultV1, EvaluatedConditionV1, ObserverClaimShapeV1,
    ObserverCoverageCompletenessV1, ObserverCoverageContinuityV1, ObserverCoverageFreshnessV1,
    ObserverCoverageWitnessV1, ObserverInputAccountingV1, ObserverInputTallyV1,
    ObserverOutcomeKindV1, ObserverResultV1, ObserverRunReceiptV1, ObserverRuntimeIdentityV1,
    VerificationOutcomeV1, build_observer_result,
};
use crate::memory_contracts::relation::ConcreteApplicabilityDimensionV1;

use super::admission::ObserverAdmissionBindingV1;
use super::enumeration::RustEnumEnumerationV1;
use super::error::ObserverRuntimeResult;
use super::source::ObservedSourceV1;

/// Widest source blob this runtime will read.
///
/// A blob over the bound is refused, never truncated: a truncated read of a
/// source file is precisely the partial coverage that must not be able to look
/// complete.
pub const MAX_OBSERVED_SOURCE_BYTES: usize = 4 * 1024 * 1024;

/// Receipt and result schema version.
const OBSERVER_SCHEMA_VERSION: u32 = 1;

/// What one run was asked.
///
/// Both shapes are about the same closed set. `Membership` asks whether one
/// named action is in it; `ExactSet` asks for the set itself. They are
/// separate because the contract's outcome taxonomy treats them differently:
/// an exact-set claim can only ever verify under `closed_world_verified`,
/// while a membership claim that is answered POSITIVELY can verify under
/// `positive_verified` too — finding a thing is not the same kind of act as
/// proving nothing else exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObserverQuestionV1 {
    /// Is `member` one of the enum's variants?
    Membership {
        /// The variant name asked about.
        member: String,
    },
    /// What is the exact variant set?
    ExactSet,
}

/// Everything one run needs beyond its admission and its source.
#[derive(Debug, Clone)]
pub struct ObserverRunPlanV1 {
    /// The enum the predicate is about.
    pub enum_name: String,
    /// The question this run answers.
    pub question: ObserverQuestionV1,
    /// Hard cap on enumerated members. Reaching it makes the read
    /// non-exhaustive rather than shorter.
    pub member_bound: usize,
    /// Concrete applicability the run read, sorted by dimension.
    pub applicability: Vec<ConcreteApplicabilityDimensionV1>,
    /// The accepted-event ids of the evidence this run cites — for this
    /// observer, the git blob-source fact naming the exact object it read.
    pub evidence_event_ids: Vec<AcceptedEventId>,
    /// Digest of the W0-COVER coverage receipt this run's coverage witness
    /// binds. Bound by digest only; this runtime never redefines that shape.
    pub coverage_receipt_digest: Sha256Digest,
    /// Whether the coverage domain has a sequencing dimension at all.
    pub coverage_continuity: ObserverCoverageContinuityV1,
    /// The canonicalization profile the active package pins.
    pub profile: ProfileReferenceV1,
    /// The credential-bound scope every emitted record carries.
    pub scope: AuthenticatedProjectScopeV1,
}

/// The receipt and the result one run produced, as one value.
///
/// They are deliberately not returned separately: the result's
/// `run_receipt_digest` names this exact receipt, and handing a caller two
/// values it could mix and match with another run's is the seam
/// `require_result_matches_admitted_run` exists to close. Keeping them
/// together also makes "written atomically" the natural implementation rather
/// than a discipline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObserverRunRecordV1 {
    /// Record schema version.
    pub schema_version: u32,
    /// The run receipt.
    pub receipt: ObserverRunReceiptV1,
    /// The observer result derived from it.
    pub result: ObserverResultV1,
    /// The enum the predicate is about.
    pub enum_name: ContractId,
    /// The members the run enumerated, in declaration order.
    pub members: Vec<String>,
    /// Every exhaustiveness caveat the read raised.
    pub diagnostics: Vec<ContractId>,
    /// Whether the read enumerated the whole input domain.
    pub exhaustive: bool,
}

impl ObserverRunRecordV1 {
    /// Exact canonical bytes of this record.
    pub fn canonical_bytes(&self) -> ObserverRuntimeResult<Vec<u8>> {
        Ok(encode_canonical(self)?)
    }

    /// Logical event key of this record.
    ///
    /// Frames the admission digest, the run receipt digest, and the result
    /// fingerprint — the three identities that together say WHICH observer,
    /// under WHICH admission, produced WHICH finding. It contains no clock and
    /// no storage coordinate, so a re-run over the same pins mints the same
    /// key and the ledger sees a replay.
    pub fn logical_event_key(&self) -> ObserverRuntimeResult<Sha256Digest> {
        Ok(framed_digest(
            DigestDomain::ObserverRunRecordV1,
            &[
                self.result.admission_digest.as_bytes(),
                self.receipt.digest()?.as_bytes(),
                self.result.result_fingerprint()?.digest().as_bytes(),
            ],
        ))
    }

    /// The verification outcome the ledger will carry.
    #[must_use]
    pub const fn verification_outcome(&self) -> VerificationOutcomeV1 {
        self.result.verification_outcome
    }

    /// Promote this record's result to the opaque append capability.
    ///
    /// Re-derives every binding from `binding`'s activated admission and this
    /// record's OWN receipt: the admission digest, the run-receipt digest, the
    /// predicate reference, the applicability, and the self-reported
    /// verification outcome. A record that was decoded from storage, or edited
    /// between construction and append, therefore cannot reach the ledger with
    /// an outcome its cited receipt does not support — the same check
    /// [`build_observer_result`] performs at construction, applied again at
    /// the second entry point that would otherwise reopen the seam.
    pub fn admitted_result(
        &self,
        binding: &ObserverAdmissionBindingV1,
    ) -> ObserverRuntimeResult<AdmittedObserverResultV1> {
        Ok(AdmittedObserverResultV1::from_derivation(
            binding.admitted(),
            &self.receipt,
            self.result.clone(),
        )?)
    }
}

/// Run the predicate over one observed source and build both records.
///
/// The `admitted` capability, the observed source, and the enumeration all
/// flow in; nothing about the outcome flows in. The verification outcome is
/// whatever [`build_observer_result`] independently derives, so this function
/// cannot label a run.
pub fn build_observer_run(
    binding: &ObserverAdmissionBindingV1,
    source: &ObservedSourceV1,
    enumeration: &RustEnumEnumerationV1,
    plan: &ObserverRunPlanV1,
    source_version: ResourceUri,
) -> ObserverRuntimeResult<ObserverRunRecordV1> {
    let admission = binding.admission();
    let (claim_shape, evaluated_condition) = evaluate_question(&plan.question, enumeration);
    let observed_at = source.fact().committed_at.clone();

    let receipt = ObserverRunReceiptV1 {
        schema_version: OBSERVER_SCHEMA_VERSION,
        admission: binding.entry_reference().clone(),
        executable_identity: ObserverRuntimeIdentityV1 {
            executable_digest: admission.identity.executable_digest,
            dependency_digests: admission.identity.dependency_digests.clone(),
        },
        source_version,
        inputs: input_accounting(enumeration),
        applicability: plan.applicability.clone(),
        configuration_context_digest: admission.configuration_context_digest,
        input_digest: source.input_digest(),
        output_digest: enumeration.output_digest(),
        coverage: coverage_witness(enumeration, plan),
        evidence_event_ids: plan.evidence_event_ids.clone(),
        outcome: run_outcome(enumeration),
        observed_at: observed_at.clone(),
    };
    receipt.validate_shape()?;

    let result = build_observer_result(
        binding.admitted(),
        &receipt,
        plan.profile.clone(),
        plan.scope.clone(),
        admission.predicate.clone(),
        plan.applicability.clone(),
        claim_shape,
        evaluated_condition,
        observed_at,
    )?;

    let record = ObserverRunRecordV1 {
        schema_version: OBSERVER_SCHEMA_VERSION,
        receipt,
        result,
        enum_name: enum_name_id(&plan.enum_name)?,
        members: enumeration.members().to_vec(),
        diagnostics: enumeration.diagnostics().to_vec(),
        exhaustive: enumeration.exhaustive(),
    };
    // Canonicalizable now, so the drain never discovers a record it cannot
    // render after it has already decided to write one; and admissible now,
    // so the record this function hands back is one the append capability
    // will accept rather than one that fails a re-derivation later.
    record.canonical_bytes()?;
    record.admitted_result(binding)?;
    Ok(record)
}

/// The claim shape and evaluated condition one question reaches.
///
/// The single most important line in this module is the `absent` arm: it is
/// reachable only when the read was exhaustive. A non-exhaustive read that did
/// not see the member reports `indeterminate`, because it does not know
/// whether the member is missing or merely unread.
fn evaluate_question(
    question: &ObserverQuestionV1,
    enumeration: &RustEnumEnumerationV1,
) -> (ObserverClaimShapeV1, EvaluatedConditionV1) {
    match question {
        ObserverQuestionV1::Membership { member } => {
            let condition = if enumeration.contains(member) {
                // Finding a member is a positive observation that a partial
                // read can honestly make: it saw the thing.
                EvaluatedConditionV1::Present
            } else if enumeration.exhaustive() {
                EvaluatedConditionV1::Absent
            } else {
                EvaluatedConditionV1::Indeterminate
            };
            (ObserverClaimShapeV1::Presence, condition)
        }
        ObserverQuestionV1::ExactSet => {
            let condition = if enumeration.exhaustive() {
                EvaluatedConditionV1::Present
            } else {
                EvaluatedConditionV1::Indeterminate
            };
            (ObserverClaimShapeV1::ExactSet, condition)
        }
    }
}

/// Exact input accounting, derived from the enumeration and nothing else.
///
/// Each enumerated member is one included input; each diagnostic is one
/// unsupported input. `unsupported` is one of the four tallies the contract
/// requires to be empty before a verified negative or exact set is reachable,
/// so an unproven construct in the source becomes a hard bar downstream rather
/// than a footnote.
fn input_accounting(enumeration: &RustEnumEnumerationV1) -> ObserverInputAccountingV1 {
    ObserverInputAccountingV1 {
        included: tally(enumeration.members().len()),
        excluded: tally(0),
        skipped: tally(0),
        failed: tally(0),
        unsupported: tally(enumeration.diagnostics().len()),
        unknown: tally(0),
    }
}

/// One tally with an exact count and no sample.
///
/// The sample is deliberately empty: it is bounded to 64 resource URIs, and an
/// enum variant is not a resource this deployment has an identity recipe for.
/// A fabricated URI would be indistinguishable from a derived one, so the
/// count carries the accounting alone and the members themselves are carried
/// in the run record beside the receipt.
fn tally(total: usize) -> ObserverInputTallyV1 {
    ObserverInputTallyV1 {
        // Saturating rather than wrapping: an accounting that wrapped to a
        // small number would understate a gap, and understating a gap is the
        // one arithmetic error that could turn an unknown into a verdict.
        total_count: u32::try_from(total).unwrap_or(u32::MAX),
        sample: Vec::new(),
    }
}

/// The coverage witness one enumeration supports.
///
/// Completeness is `complete` only for an exhaustive read. Freshness is
/// `current` unconditionally, and that is honest here for a reason specific to
/// this observer: its input domain is one immutable git blob named by object
/// id, so there is no newer version of the thing it read that it could be
/// stale relative to.
const fn coverage_witness(
    enumeration: &RustEnumEnumerationV1,
    plan: &ObserverRunPlanV1,
) -> ObserverCoverageWitnessV1 {
    ObserverCoverageWitnessV1 {
        coverage_receipt_digest: plan.coverage_receipt_digest,
        completeness: if enumeration.exhaustive() {
            ObserverCoverageCompletenessV1::Complete
        } else {
            ObserverCoverageCompletenessV1::Partial
        },
        freshness: ObserverCoverageFreshnessV1::Current,
        continuity: plan.coverage_continuity,
    }
}

/// The run-receipt outcome kind one enumeration reached.
///
/// `success` only for an exhaustive read; `partial` otherwise. Never
/// `parse_failure`: this runtime refuses a source it cannot read rather than
/// reporting a run over it, so a receipt that exists is a receipt whose source
/// parsed.
const fn run_outcome(enumeration: &RustEnumEnumerationV1) -> ObserverOutcomeKindV1 {
    if enumeration.exhaustive() {
        ObserverOutcomeKindV1::Success
    } else {
        ObserverOutcomeKindV1::Partial
    }
}

/// The enum name as a contract id.
///
/// `ContractId` is lowercase by construction, so the record's `enum_name`
/// field is a case-folded label. The MEMBERS are stored verbatim in
/// [`ObserverRunRecordV1::members`] and framed verbatim into the output
/// digest, so nothing about the actual finding is case-folded — only the label
/// that says which item was read.
fn enum_name_id(enum_name: &str) -> ObserverRuntimeResult<ContractId> {
    Ok(ContractId::new(enum_name.to_ascii_lowercase())?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observer_runtime::enumeration::enumerate_rust_enum;

    fn exhaustive() -> RustEnumEnumerationV1 {
        enumerate_rust_enum("pub enum Action { Record, Assert }", "Action", 8).unwrap()
    }

    fn partial() -> RustEnumEnumerationV1 {
        enumerate_rust_enum("pub enum Action { Record, Assert }", "Action", 1).unwrap()
    }

    #[test]
    fn a_member_that_was_seen_is_present_however_partial_the_read() {
        let (shape, condition) = evaluate_question(
            &ObserverQuestionV1::Membership {
                member: "Record".to_owned(),
            },
            &partial(),
        );
        assert_eq!(shape, ObserverClaimShapeV1::Presence);
        assert_eq!(condition, EvaluatedConditionV1::Present);
    }

    #[test]
    fn a_member_that_was_not_seen_is_absent_only_under_an_exhaustive_read() {
        let question = ObserverQuestionV1::Membership {
            member: "Assert".to_owned(),
        };
        // The bounded read never saw `Assert`, and says so.
        assert_eq!(
            evaluate_question(&question, &partial()).1,
            EvaluatedConditionV1::Indeterminate
        );
        // The full read saw it, so it is present rather than absent.
        assert_eq!(
            evaluate_question(&question, &exhaustive()).1,
            EvaluatedConditionV1::Present
        );
        // A member no read ever finds is absent only when the read was whole.
        let missing = ObserverQuestionV1::Membership {
            member: "Deploy".to_owned(),
        };
        assert_eq!(
            evaluate_question(&missing, &partial()).1,
            EvaluatedConditionV1::Indeterminate
        );
        assert_eq!(
            evaluate_question(&missing, &exhaustive()).1,
            EvaluatedConditionV1::Absent
        );
    }

    #[test]
    fn an_exact_set_question_is_indeterminate_under_a_partial_read() {
        assert_eq!(
            evaluate_question(&ObserverQuestionV1::ExactSet, &partial()).1,
            EvaluatedConditionV1::Indeterminate
        );
        assert_eq!(
            evaluate_question(&ObserverQuestionV1::ExactSet, &exhaustive()).1,
            EvaluatedConditionV1::Present
        );
    }

    #[test]
    fn every_diagnostic_becomes_an_unsupported_input() {
        let whole = input_accounting(&exhaustive());
        assert_eq!(whole.included.total_count, 2);
        assert_eq!(whole.unsupported.total_count, 0);

        let bounded = input_accounting(&partial());
        assert_eq!(bounded.included.total_count, 1);
        assert_eq!(bounded.unsupported.total_count, 1);
        // The four gap categories the contract requires to be empty: this
        // read fills one of them, which is the point.
        assert_eq!(bounded.skipped.total_count, 0);
        assert_eq!(bounded.failed.total_count, 0);
        assert_eq!(bounded.unknown.total_count, 0);
    }

    #[test]
    fn a_partial_read_never_reports_complete_coverage_or_a_success_outcome() {
        let plan = ObserverRunPlanV1 {
            enum_name: "Action".to_owned(),
            question: ObserverQuestionV1::ExactSet,
            member_bound: 8,
            applicability: Vec::new(),
            evidence_event_ids: Vec::new(),
            coverage_receipt_digest: Sha256Digest::from_bytes([0x0c; 32]),
            coverage_continuity: ObserverCoverageContinuityV1::NotApplicable,
            profile: crate::memory_contracts::common::frozen_profile_reference_v1(),
            scope: AuthenticatedProjectScopeV1 {
                tenant_namespace: ContractId::new("tenant.test").unwrap(),
                project_namespace: ContractId::new("project.test").unwrap(),
            },
        };
        assert_eq!(
            coverage_witness(&exhaustive(), &plan).completeness,
            ObserverCoverageCompletenessV1::Complete
        );
        assert_eq!(
            coverage_witness(&partial(), &plan).completeness,
            ObserverCoverageCompletenessV1::Partial
        );
        assert_eq!(run_outcome(&exhaustive()), ObserverOutcomeKindV1::Success);
        assert_eq!(run_outcome(&partial()), ObserverOutcomeKindV1::Partial);
    }
}
