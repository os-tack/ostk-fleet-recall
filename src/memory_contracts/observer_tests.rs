use std::str::FromStr;

use sha2::{Digest as _, Sha256};

use super::*;
use crate::memory_contracts::canonical::require_canonical;
use crate::memory_contracts::common::frozen_profile_reference_v1;

const ADMISSION_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/observer/observer-admission-closed-world-v1.jsonl"
);
const ADMISSION_POSITIVE_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/observer/observer-admission-positive-verified-v1.jsonl"
);
const ADMISSION_CANDIDATE_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/observer/observer-admission-candidate-only-v1.jsonl"
);
const RUN_RECEIPT_SUCCESS_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/observer/observer-run-receipt-success-v1.jsonl"
);
const RESULT_VERIFIED_NEGATIVE_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/observer/observer-result-verified-negative-v1.jsonl"
);
const VECTOR_SUITE_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v3/observer/vector-suite.jsonl");
const NEGATIVE_LLM_CLOSED_WORLD_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v3/observer/negative-llm-closed-world-v1.jsonl");
const NEGATIVE_UNKNOWN_FIELD_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v3/observer/negative-unknown-field-v1.jsonl");
const NEGATIVE_UNSORTED_DEPENDENCY_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/observer/negative-unsorted-dependency-digests-v1.jsonl"
);

const ADMISSION_DIGEST: &str = "6ecf60cd22cdd72f53e59b8c239a4dfd063d6e4c30aeda68a5a8f781b20dd4c4";
const ADMISSION_RAW_SHA256: &str =
    "10742b3198fe59664df6721900ab89c8ca3cb8ecf2d28d207fb9a24de757ffce";
const ADMISSION_POSITIVE_RAW_SHA256: &str =
    "56d3df41e09fae038ea02a7728688f95e95f67f0f5ff14f04e119b25e675d8b9";
const ADMISSION_CANDIDATE_RAW_SHA256: &str =
    "f86bb1dda0cd027cea31ea536db60e48cc31aaa9fd2b69c4da4fae9857417ee2";
const RUN_RECEIPT_SUCCESS_RAW_SHA256: &str =
    "d0e614be910017935d0f2667fc0f2143f8f2d020224a44079b5d9ac2bde7509e";
const RESULT_VERIFIED_NEGATIVE_RAW_SHA256: &str =
    "e60d73b6bd9d0452d10dac19c220c230dfd7e64d1d469afdbe8ff0d971947e37";
const VECTOR_SUITE_RAW_SHA256: &str =
    "f101acd3565e4d0c8425885b821e0c8943ebc560d243764ccd0f40562333296c";
const NEGATIVE_LLM_CLOSED_WORLD_RAW_SHA256: &str =
    "be437394e1c017463c966a8ee39ba3f70ef88a2f72ef834602b317b13303a8cd";
const NEGATIVE_UNKNOWN_FIELD_RAW_SHA256: &str =
    "7dd6033e985916035f15ec9584c2dcc50fe55c23a19947670718ac50a5b2e2f2";
const NEGATIVE_UNSORTED_DEPENDENCY_RAW_SHA256: &str =
    "825bb66f599b1fc9eea04634a070c084bf07dd2aab03faded109bb8e44390716";

fn record(bytes: &[u8]) -> &[u8] {
    let body = bytes
        .strip_suffix(b"\n")
        .expect("contract artifact must have exactly one framing LF");
    assert!(!body.ends_with(b"\n"));
    assert!(!body.contains(&b'\r'));
    body
}

fn raw_sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn digest_from_label(label: &str) -> Sha256Digest {
    domain_separated_digest(DigestDomain::RegistryEntry, label.as_bytes())
}

fn reference(id: &str) -> RegistryReferenceV1 {
    RegistryReferenceV1 {
        entry_id: ContractId::new(id).unwrap(),
        version: 1,
        entry_digest: digest_from_label(id),
    }
}

fn scope() -> AuthenticatedProjectScopeV1 {
    AuthenticatedProjectScopeV1::from_trusted_context(
        ContractId::new("tenant.fleet").unwrap(),
        ContractId::new("project.fleet-recall").unwrap(),
    )
}

fn timestamp(value: &str) -> CanonicalTimestamp {
    CanonicalTimestamp::parse(value).unwrap()
}

fn resource_uri(kind: &str, form: IdentityForm, seed: u8) -> ResourceUri {
    let uri = format!(
        "urn:ostk:{}:v1:{kind}:sha256:{}",
        form.as_str(),
        hex::encode([seed; 32])
    );
    ResourceUri::from_str(&uri).unwrap()
}

fn toolchain() -> ObserverToolchainVersionsV1 {
    ObserverToolchainVersionsV1 {
        language_version: ContractId::new("rust-1.94").unwrap(),
        schema_version: ContractId::new("schema-v1").unwrap(),
        compiler_version: ContractId::new("rustc-1.94.0").unwrap(),
        api_version: ContractId::new("api-v1").unwrap(),
    }
}

fn input_domain() -> ObserverInputDomainV1 {
    ObserverInputDomainV1 {
        closed_input_boundary_id: ContractId::new("boundary.crate-source").unwrap(),
        supported_source_kinds: vec![ContractId::new("git.blob").unwrap()],
        supported_resource_kinds: vec![ContractId::new("rust.enum").unwrap()],
        required_applicability_dimensions: vec![ContractId::new("repository_commit").unwrap()],
    }
}

fn enumeration_algorithm() -> ObserverEnumerationAlgorithmV1 {
    ObserverEnumerationAlgorithmV1 {
        algorithm_id: ContractId::new("algorithm.syn-ast-walk").unwrap(),
        unsupported_feature_diagnostics: vec![ContractId::new("macro.unresolved").unwrap()],
    }
}

fn executable_identity(kind: &str) -> ObserverExecutableIdentityV1 {
    ObserverExecutableIdentityV1 {
        observer_kind: ContractId::new(kind).unwrap(),
        executable_digest: digest_from_label("observer.executable"),
        dependency_digests: vec![
            digest_from_label("dependency.one"),
            digest_from_label("dependency.two"),
        ],
        version: 1,
    }
}

fn admission(kind: &str, mode: ObserverAdmissionModeV1) -> ObserverAdmissionV2 {
    ObserverAdmissionV2 {
        schema_version: OBSERVER_SCHEMA_VERSION,
        admission_id: ContractId::new("observer.ast_schema_enum").unwrap(),
        version: 1,
        identity: executable_identity(kind),
        predicate: reference("predicate.mcp.remember.allowed_actions"),
        input_domain: input_domain(),
        configuration_context_digest: digest_from_label("configuration.default"),
        toolchain_versions: toolchain(),
        mode,
        enumeration_algorithm: enumeration_algorithm(),
        declared_outcome_kinds: vec![
            ObserverOutcomeKindV1::Success,
            ObserverOutcomeKindV1::Partial,
            ObserverOutcomeKindV1::Stale,
            ObserverOutcomeKindV1::ParseFailure,
            ObserverOutcomeKindV1::Timeout,
        ],
        coverage_receipt_recipe: reference("coverage.recipe.default"),
        positive_vector_digest: digest_from_label("vector.positive"),
        negative_vector_digest: digest_from_label("vector.negative"),
        mutation_vector_digest: digest_from_label("vector.mutation"),
        adversarial_vector_digest: digest_from_label("vector.adversarial"),
    }
}

fn full_input_tally() -> ObserverInputTallyV1 {
    ObserverInputTallyV1 {
        total_count: 2,
        sample: vec![
            resource_uri("rust.enum", IdentityForm::Occurrence, 0x01),
            resource_uri("rust.enum", IdentityForm::Occurrence, 0x02),
        ],
    }
}

fn empty_input_tally() -> ObserverInputTallyV1 {
    ObserverInputTallyV1 {
        total_count: 0,
        sample: Vec::new(),
    }
}

fn zero_gap_inputs() -> ObserverInputAccountingV1 {
    ObserverInputAccountingV1 {
        included: full_input_tally(),
        excluded: empty_input_tally(),
        skipped: empty_input_tally(),
        failed: empty_input_tally(),
        unsupported: empty_input_tally(),
        unknown: empty_input_tally(),
    }
}

fn full_coverage_witness() -> ObserverCoverageWitnessV1 {
    ObserverCoverageWitnessV1 {
        coverage_receipt_digest: digest_from_label("coverage.receipt.one"),
        completeness: ObserverCoverageCompletenessV1::Complete,
        freshness: ObserverCoverageFreshnessV1::Current,
        continuity: ObserverCoverageContinuityV1::Contiguous,
    }
}

fn applicability() -> Vec<ConcreteApplicabilityDimensionV1> {
    vec![ConcreteApplicabilityDimensionV1 {
        dimension_id: ContractId::new("repository_commit").unwrap(),
        resource: resource_uri("commit", IdentityForm::Version, 0x10),
    }]
}

fn run_receipt(
    executable_identity: ObserverRuntimeIdentityV1,
    inputs: ObserverInputAccountingV1,
    coverage: ObserverCoverageWitnessV1,
    outcome: ObserverOutcomeKindV1,
) -> ObserverRunReceiptV1 {
    ObserverRunReceiptV1 {
        schema_version: OBSERVER_SCHEMA_VERSION,
        admission: reference("observer.ast_schema_enum"),
        executable_identity,
        source_version: resource_uri("repository", IdentityForm::Version, 0x20),
        inputs,
        applicability: applicability(),
        configuration_context_digest: digest_from_label("configuration.default"),
        input_digest: digest_from_label("input.snapshot"),
        output_digest: digest_from_label("output.snapshot"),
        coverage,
        evidence_event_ids: vec![AcceptedEventId::from_digest(digest_from_label(
            "evidence.one",
        ))],
        outcome,
        observed_at: timestamp("2026-08-14T12:00:00.000000000Z"),
    }
}

/// Admit `admission` under the registry entry reference its own
/// `admission_id`/`version` name, exactly as a genuine registry
/// activation witness would. Reused by every test so a call site cannot
/// accidentally admit under an unrelated reference.
fn admit(admission: ObserverAdmissionV2) -> AdmittedObserverV1 {
    let admission_reference = reference(admission.admission_id.as_str());
    AdmittedObserverV1::from_test_witness(admission, admission_reference).unwrap()
}

fn matching_runtime_identity(admitted: &ObserverExecutableIdentityV1) -> ObserverRuntimeIdentityV1 {
    ObserverRuntimeIdentityV1 {
        executable_digest: admitted.executable_digest,
        dependency_digests: admitted.dependency_digests.clone(),
    }
}

fn drifted_runtime_identity() -> ObserverRuntimeIdentityV1 {
    ObserverRuntimeIdentityV1 {
        executable_digest: digest_from_label("observer.executable.drifted"),
        dependency_digests: vec![digest_from_label("dependency.one")],
    }
}

#[test]
fn closed_world_admission_verifies_a_negative_under_full_coverage() {
    let admission = admission("ast_schema", ObserverAdmissionModeV1::ClosedWorldVerified);
    let admitted = admit(admission.clone());
    let run = run_receipt(
        matching_runtime_identity(&admission.identity),
        zero_gap_inputs(),
        full_coverage_witness(),
        ObserverOutcomeKindV1::Success,
    );
    let outcome = derive_verification_outcome(
        &admitted,
        &run,
        ObserverClaimShapeV1::Presence,
        EvaluatedConditionV1::Absent,
    )
    .unwrap();
    assert_eq!(outcome, VerificationOutcomeV1::VerifiedNegative);
}

#[test]
fn closed_world_admission_never_verifies_a_negative_over_an_empty_included_tally() {
    // A closed input boundary that included nothing proves nothing,
    // however "complete/current/contiguous" the coverage witness reports
    // it: `included.total_count == 0` must fail closed rather than
    // vacuously support a verified negative.
    let admission = admission("ast_schema", ObserverAdmissionModeV1::ClosedWorldVerified);
    let admitted = admit(admission.clone());
    let vacuous_inputs = ObserverInputAccountingV1 {
        included: empty_input_tally(),
        ..zero_gap_inputs()
    };
    let run = run_receipt(
        matching_runtime_identity(&admission.identity),
        vacuous_inputs,
        full_coverage_witness(),
        ObserverOutcomeKindV1::Success,
    );
    let outcome = derive_verification_outcome(
        &admitted,
        &run,
        ObserverClaimShapeV1::Presence,
        EvaluatedConditionV1::Absent,
    )
    .unwrap();
    assert_eq!(outcome, VerificationOutcomeV1::Indeterminate);
}

#[test]
fn closed_world_admission_verifies_an_exact_set_under_full_coverage() {
    let admission = admission("ast_schema", ObserverAdmissionModeV1::ClosedWorldVerified);
    let admitted = admit(admission.clone());
    let run = run_receipt(
        matching_runtime_identity(&admission.identity),
        zero_gap_inputs(),
        full_coverage_witness(),
        ObserverOutcomeKindV1::Success,
    );
    let outcome = derive_verification_outcome(
        &admitted,
        &run,
        ObserverClaimShapeV1::ExactSet,
        EvaluatedConditionV1::Present,
    )
    .unwrap();
    assert_eq!(outcome, VerificationOutcomeV1::VerifiedExactSet);
}

#[test]
fn skipped_input_under_closed_world_is_indeterminate() {
    let admission = admission("ast_schema", ObserverAdmissionModeV1::ClosedWorldVerified);
    let admitted = admit(admission.clone());
    let mut inputs = zero_gap_inputs();
    inputs.skipped = ObserverInputTallyV1 {
        total_count: 1,
        sample: vec![resource_uri("rust.enum", IdentityForm::Occurrence, 0x09)],
    };
    let run = run_receipt(
        matching_runtime_identity(&admission.identity),
        inputs,
        full_coverage_witness(),
        ObserverOutcomeKindV1::Success,
    );
    let outcome = derive_verification_outcome(
        &admitted,
        &run,
        ObserverClaimShapeV1::Presence,
        EvaluatedConditionV1::Absent,
    )
    .unwrap();
    assert_eq!(outcome, VerificationOutcomeV1::Indeterminate);
}

#[test]
fn dependency_drift_is_always_indeterminate() {
    let admission = admission("ast_schema", ObserverAdmissionModeV1::ClosedWorldVerified);
    let admitted = admit(admission);
    let run = run_receipt(
        drifted_runtime_identity(),
        zero_gap_inputs(),
        full_coverage_witness(),
        ObserverOutcomeKindV1::Success,
    );
    let outcome = derive_verification_outcome(
        &admitted,
        &run,
        ObserverClaimShapeV1::Presence,
        EvaluatedConditionV1::Absent,
    )
    .unwrap();
    assert_eq!(outcome, VerificationOutcomeV1::Indeterminate);
}

#[test]
fn configuration_drift_is_always_indeterminate() {
    // A run witnessed under a different configuration context than the
    // one this admission is scoped to must never verify, even though its
    // executable/dependency identity matches the admitted one.
    let admission = admission("ast_schema", ObserverAdmissionModeV1::ClosedWorldVerified);
    let admitted = admit(admission.clone());
    let mut run = run_receipt(
        matching_runtime_identity(&admission.identity),
        zero_gap_inputs(),
        full_coverage_witness(),
        ObserverOutcomeKindV1::Success,
    );
    run.configuration_context_digest = digest_from_label("configuration.drifted");
    let outcome = derive_verification_outcome(
        &admitted,
        &run,
        ObserverClaimShapeV1::Presence,
        EvaluatedConditionV1::Absent,
    )
    .unwrap();
    assert_eq!(outcome, VerificationOutcomeV1::Indeterminate);
}

#[test]
fn run_outcome_undeclared_by_its_own_admission_is_indeterminate() {
    // An admission's `declared_outcome_kinds` is a closed enumeration of
    // what this admitted observer may honestly report, not a decorative
    // hint: a run reporting a kind its own admission never declared must
    // never verify.
    let mut admission = admission("ast_schema", ObserverAdmissionModeV1::ClosedWorldVerified);
    admission.declared_outcome_kinds = vec![ObserverOutcomeKindV1::Success];
    let admitted = admit(admission.clone());
    let run = run_receipt(
        matching_runtime_identity(&admission.identity),
        zero_gap_inputs(),
        full_coverage_witness(),
        ObserverOutcomeKindV1::Partial,
    );
    let outcome = derive_verification_outcome(
        &admitted,
        &run,
        ObserverClaimShapeV1::Presence,
        EvaluatedConditionV1::Present,
    )
    .unwrap();
    assert_eq!(outcome, VerificationOutcomeV1::Indeterminate);
}

#[test]
fn unrelated_admission_reference_is_indeterminate() {
    // A run receipt whose `admission` field names an entirely different
    // registry entry must never verify against this admission merely
    // because its executable/dependency digests happen to match: matching
    // executable identity alone does not prove the run was produced under
    // *this* admission.
    let admission = admission("ast_schema", ObserverAdmissionModeV1::ClosedWorldVerified);
    let admitted = admit(admission.clone());
    let mut run = run_receipt(
        matching_runtime_identity(&admission.identity),
        zero_gap_inputs(),
        full_coverage_witness(),
        ObserverOutcomeKindV1::Success,
    );
    run.admission = reference("observer.some.other.entry.entirely");
    let outcome = derive_verification_outcome(
        &admitted,
        &run,
        ObserverClaimShapeV1::Presence,
        EvaluatedConditionV1::Absent,
    )
    .unwrap();
    assert_eq!(outcome, VerificationOutcomeV1::Indeterminate);
}

#[test]
fn missing_required_applicability_dimension_is_indeterminate() {
    // The admission requires `repository_commit` as a concrete
    // applicability dimension (`input_domain()`); a run that reports no
    // applicability at all must never verify absence. `run.validate_shape`
    // permits an empty applicability list structurally, so this must be
    // enforced by the derivation, not by shape validation.
    let admission = admission("ast_schema", ObserverAdmissionModeV1::ClosedWorldVerified);
    let admitted = admit(admission.clone());
    let mut run = run_receipt(
        matching_runtime_identity(&admission.identity),
        zero_gap_inputs(),
        full_coverage_witness(),
        ObserverOutcomeKindV1::Success,
    );
    run.applicability = Vec::new();
    run.validate_shape().unwrap();
    let outcome = derive_verification_outcome(
        &admitted,
        &run,
        ObserverClaimShapeV1::Presence,
        EvaluatedConditionV1::Absent,
    )
    .unwrap();
    assert_eq!(outcome, VerificationOutcomeV1::Indeterminate);
}

#[test]
fn timeout_is_always_indeterminate_never_a_verified_negative() {
    let admission = admission("ast_schema", ObserverAdmissionModeV1::ClosedWorldVerified);
    let admitted = admit(admission.clone());
    let run = run_receipt(
        matching_runtime_identity(&admission.identity),
        zero_gap_inputs(),
        full_coverage_witness(),
        ObserverOutcomeKindV1::Timeout,
    );
    let outcome = derive_verification_outcome(
        &admitted,
        &run,
        ObserverClaimShapeV1::Presence,
        EvaluatedConditionV1::Absent,
    )
    .unwrap();
    assert_eq!(outcome, VerificationOutcomeV1::Indeterminate);
}

#[test]
fn candidate_only_never_verifies() {
    let admission = admission("ast_schema", ObserverAdmissionModeV1::CandidateOnly);
    let admitted = admit(admission.clone());
    let run = run_receipt(
        matching_runtime_identity(&admission.identity),
        zero_gap_inputs(),
        full_coverage_witness(),
        ObserverOutcomeKindV1::Success,
    );
    for evaluated_condition in [EvaluatedConditionV1::Present, EvaluatedConditionV1::Absent] {
        let outcome = derive_verification_outcome(
            &admitted,
            &run,
            ObserverClaimShapeV1::Presence,
            evaluated_condition,
        )
        .unwrap();
        assert_eq!(outcome, VerificationOutcomeV1::Candidate);
    }
}

#[test]
fn llm_observer_cannot_admit_closed_world() {
    let admission = admission("llm", ObserverAdmissionModeV1::ClosedWorldVerified);
    assert_eq!(
        admission.validate_shape(),
        Err(ContractError::Schema(
            "invalid observer admission v2".into()
        ))
    );
}

#[test]
fn semantic_search_observer_cannot_admit_positive_verified() {
    let admission = admission("semantic_search", ObserverAdmissionModeV1::PositiveVerified);
    assert!(admission.validate_shape().is_err());
}

#[test]
fn llm_observer_candidate_only_admission_is_valid() {
    let admission = admission("llm", ObserverAdmissionModeV1::CandidateOnly);
    admission.validate_shape().unwrap();
}

#[test]
fn partial_coverage_positive_verified_ok_but_candidate_only_stays_candidate() {
    let mut inputs = zero_gap_inputs();
    inputs.skipped = ObserverInputTallyV1 {
        total_count: 1,
        sample: vec![resource_uri("rust.enum", IdentityForm::Occurrence, 0x0a)],
    };
    let mut coverage = full_coverage_witness();
    coverage.completeness = ObserverCoverageCompletenessV1::Partial;

    let positive_admission = admission("ast_schema", ObserverAdmissionModeV1::PositiveVerified);
    let positive_admitted = admit(positive_admission.clone());
    let positive_run = run_receipt(
        matching_runtime_identity(&positive_admission.identity),
        inputs.clone(),
        coverage.clone(),
        ObserverOutcomeKindV1::Partial,
    );
    let positive_outcome = derive_verification_outcome(
        &positive_admitted,
        &positive_run,
        ObserverClaimShapeV1::Presence,
        EvaluatedConditionV1::Present,
    )
    .unwrap();
    assert_eq!(positive_outcome, VerificationOutcomeV1::VerifiedPositive);

    let candidate_admission = admission("llm", ObserverAdmissionModeV1::CandidateOnly);
    let candidate_admitted = admit(candidate_admission.clone());
    let candidate_run = run_receipt(
        matching_runtime_identity(&candidate_admission.identity),
        inputs,
        coverage,
        ObserverOutcomeKindV1::Partial,
    );
    let candidate_outcome = derive_verification_outcome(
        &candidate_admitted,
        &candidate_run,
        ObserverClaimShapeV1::Presence,
        EvaluatedConditionV1::Present,
    )
    .unwrap();
    assert_eq!(candidate_outcome, VerificationOutcomeV1::Candidate);
}

#[test]
fn exact_set_claim_shape_rejects_an_absent_evaluated_condition() {
    let admission = admission("ast_schema", ObserverAdmissionModeV1::ClosedWorldVerified);
    let admitted = admit(admission.clone());
    let run = run_receipt(
        matching_runtime_identity(&admission.identity),
        zero_gap_inputs(),
        full_coverage_witness(),
        ObserverOutcomeKindV1::Success,
    );
    assert!(
        derive_verification_outcome(
            &admitted,
            &run,
            ObserverClaimShapeV1::ExactSet,
            EvaluatedConditionV1::Absent,
        )
        .is_err()
    );
}

#[test]
fn build_observer_result_rejects_a_predicate_that_does_not_match_the_admission() {
    // An admitted-for-P observer must never be able to emit a verified
    // finding about an entirely different predicate Q merely by passing Q
    // as the `predicate` parameter.
    let admission = admission("ast_schema", ObserverAdmissionModeV1::ClosedWorldVerified);
    let admitted = admit(admission.clone());
    let run = run_receipt(
        matching_runtime_identity(&admission.identity),
        zero_gap_inputs(),
        full_coverage_witness(),
        ObserverOutcomeKindV1::Success,
    );
    let unadmitted_predicate = reference("predicate.totally.unadmitted.security_policy");
    let result = build_observer_result(
        &admitted,
        &run,
        frozen_profile_reference_v1(),
        scope(),
        unadmitted_predicate,
        applicability(),
        ObserverClaimShapeV1::Presence,
        EvaluatedConditionV1::Absent,
        timestamp("2026-08-14T12:00:00.000000000Z"),
    );
    assert!(result.is_err());
}

#[test]
fn build_observer_result_rejects_an_applicability_that_does_not_match_the_run() {
    // An admitted observer must never be able to emit a verified finding
    // about a concrete applicability its run receipt never actually read.
    let admission = admission("ast_schema", ObserverAdmissionModeV1::ClosedWorldVerified);
    let admitted = admit(admission.clone());
    let run = run_receipt(
        matching_runtime_identity(&admission.identity),
        zero_gap_inputs(),
        full_coverage_witness(),
        ObserverOutcomeKindV1::Success,
    );
    let unrelated_applicability = vec![ConcreteApplicabilityDimensionV1 {
        dimension_id: ContractId::new("unrelated_dimension").unwrap(),
        resource: resource_uri("commit", IdentityForm::Version, 0x99),
    }];
    let result = build_observer_result(
        &admitted,
        &run,
        frozen_profile_reference_v1(),
        scope(),
        reference("predicate.mcp.remember.allowed_actions"),
        unrelated_applicability,
        ObserverClaimShapeV1::Presence,
        EvaluatedConditionV1::Absent,
        timestamp("2026-08-14T12:00:00.000000000Z"),
    );
    assert!(result.is_err());
}

#[test]
fn deterministic_replay_same_inputs_yield_identical_digest() {
    let admission = admission("ast_schema", ObserverAdmissionModeV1::ClosedWorldVerified);
    let run_a = run_receipt(
        matching_runtime_identity(&admission.identity),
        zero_gap_inputs(),
        full_coverage_witness(),
        ObserverOutcomeKindV1::Success,
    );
    let run_b = run_receipt(
        matching_runtime_identity(&admission.identity),
        zero_gap_inputs(),
        full_coverage_witness(),
        ObserverOutcomeKindV1::Success,
    );
    assert_eq!(run_a.digest().unwrap(), run_b.digest().unwrap());
}

#[test]
fn deterministic_replay_reordered_inputs_are_rejected_fail_closed() {
    // PRED-05 order-independence is enforced by rejecting a genuinely
    // non-canonical input sample order before a digest is ever produced,
    // not by two differently-ordered receipts happening to hash equal.
    // `inputs_b` here is actually descending (0x02 before 0x01) -- unlike
    // the previous vector, which built both samples in the same ascending
    // order and called a no-op `.sort()`, so it only ever exercised the
    // already-canonical path and never observed a real reorder.
    let admission = admission("ast_schema", ObserverAdmissionModeV1::ClosedWorldVerified);
    let mut inputs_b = zero_gap_inputs();
    inputs_b.included.sample = vec![
        resource_uri("rust.enum", IdentityForm::Occurrence, 0x02),
        resource_uri("rust.enum", IdentityForm::Occurrence, 0x01),
    ];
    let run_b = run_receipt(
        matching_runtime_identity(&admission.identity),
        inputs_b,
        full_coverage_witness(),
        ObserverOutcomeKindV1::Success,
    );
    assert_eq!(
        run_b.digest(),
        Err(ContractError::Schema("invalid observer input tally".into()))
    );
}

#[test]
fn unsorted_dependency_digests_are_rejected() {
    let mut identity = executable_identity("ast_schema");
    identity.dependency_digests = vec![
        digest_from_label("dependency.two"),
        digest_from_label("dependency.one"),
    ];
    assert!(identity.validate_shape().is_err());
}

#[test]
fn overlapping_admitted_observers_with_incompatible_outputs_disagree() {
    let closed_admission = admission("ast_schema", ObserverAdmissionModeV1::ClosedWorldVerified);
    let closed_admitted = admit(closed_admission.clone());
    let closed_run = run_receipt(
        matching_runtime_identity(&closed_admission.identity),
        zero_gap_inputs(),
        full_coverage_witness(),
        ObserverOutcomeKindV1::Success,
    );
    let negative_result = build_observer_result(
        &closed_admitted,
        &closed_run,
        frozen_profile_reference_v1(),
        scope(),
        reference("predicate.mcp.remember.allowed_actions"),
        applicability(),
        ObserverClaimShapeV1::Presence,
        EvaluatedConditionV1::Absent,
        timestamp("2026-08-14T12:00:00.000000000Z"),
    )
    .unwrap();

    let mut other_admission = admission("ast_schema", ObserverAdmissionModeV1::PositiveVerified);
    other_admission.admission_id = ContractId::new("observer.ast_schema_enum_v2").unwrap();
    let other_admitted = admit(other_admission.clone());
    let mut other_run = run_receipt(
        matching_runtime_identity(&other_admission.identity),
        zero_gap_inputs(),
        full_coverage_witness(),
        ObserverOutcomeKindV1::Success,
    );
    other_run.admission = reference(other_admission.admission_id.as_str());
    let positive_result = build_observer_result(
        &other_admitted,
        &other_run,
        frozen_profile_reference_v1(),
        scope(),
        reference("predicate.mcp.remember.allowed_actions"),
        applicability(),
        ObserverClaimShapeV1::Presence,
        EvaluatedConditionV1::Present,
        timestamp("2026-08-14T12:00:00.000000000Z"),
    )
    .unwrap();

    let disagreement = detect_disagreement(
        &closed_admitted,
        &closed_run,
        &negative_result,
        &other_admitted,
        &other_run,
        &positive_result,
        timestamp("2026-08-14T13:00:00.000000000Z"),
    )
    .unwrap();
    assert!(disagreement.is_some());
}

#[test]
fn non_overlapping_domains_never_disagree() {
    let closed_admission = admission("ast_schema", ObserverAdmissionModeV1::ClosedWorldVerified);
    let closed_admitted = admit(closed_admission.clone());
    let closed_run = run_receipt(
        matching_runtime_identity(&closed_admission.identity),
        zero_gap_inputs(),
        full_coverage_witness(),
        ObserverOutcomeKindV1::Success,
    );
    let negative_result = build_observer_result(
        &closed_admitted,
        &closed_run,
        frozen_profile_reference_v1(),
        scope(),
        reference("predicate.mcp.remember.allowed_actions"),
        applicability(),
        ObserverClaimShapeV1::Presence,
        EvaluatedConditionV1::Absent,
        timestamp("2026-08-14T12:00:00.000000000Z"),
    )
    .unwrap();

    let mut disjoint_admission = admission("ast_schema", ObserverAdmissionModeV1::PositiveVerified);
    disjoint_admission.admission_id = ContractId::new("observer.other_enum").unwrap();
    disjoint_admission.input_domain.supported_resource_kinds =
        vec![ContractId::new("rust.struct").unwrap()];
    let disjoint_admitted = admit(disjoint_admission.clone());
    let mut disjoint_run = run_receipt(
        matching_runtime_identity(&disjoint_admission.identity),
        zero_gap_inputs(),
        full_coverage_witness(),
        ObserverOutcomeKindV1::Success,
    );
    disjoint_run.admission = reference(disjoint_admission.admission_id.as_str());
    let positive_result = build_observer_result(
        &disjoint_admitted,
        &disjoint_run,
        frozen_profile_reference_v1(),
        scope(),
        reference("predicate.mcp.remember.allowed_actions"),
        applicability(),
        ObserverClaimShapeV1::Presence,
        EvaluatedConditionV1::Present,
        timestamp("2026-08-14T12:00:00.000000000Z"),
    )
    .unwrap();

    let disagreement = detect_disagreement(
        &closed_admitted,
        &closed_run,
        &negative_result,
        &disjoint_admitted,
        &disjoint_run,
        &positive_result,
        timestamp("2026-08-14T13:00:00.000000000Z"),
    )
    .unwrap();
    assert!(disagreement.is_none());
}

#[test]
fn overlapping_domains_with_different_admitted_predicates_never_disagree() {
    // Same admitted input domain (so `domains_overlap` alone would not
    // suppress this), but each side is genuinely admitted for a
    // different predicate. Overlap must be keyed on the *admitted*
    // predicates, not merely on whether the two supported-kind sets
    // intersect.
    let closed_admission = admission("ast_schema", ObserverAdmissionModeV1::ClosedWorldVerified);
    let closed_admitted = admit(closed_admission.clone());
    let closed_run = run_receipt(
        matching_runtime_identity(&closed_admission.identity),
        zero_gap_inputs(),
        full_coverage_witness(),
        ObserverOutcomeKindV1::Success,
    );
    let negative_result = build_observer_result(
        &closed_admitted,
        &closed_run,
        frozen_profile_reference_v1(),
        scope(),
        reference("predicate.mcp.remember.allowed_actions"),
        applicability(),
        ObserverClaimShapeV1::Presence,
        EvaluatedConditionV1::Absent,
        timestamp("2026-08-14T12:00:00.000000000Z"),
    )
    .unwrap();

    let mut other_admission = admission("ast_schema", ObserverAdmissionModeV1::PositiveVerified);
    other_admission.admission_id = ContractId::new("observer.other_predicate").unwrap();
    other_admission.predicate = reference("predicate.totally.unrelated.topic");
    let other_admitted = admit(other_admission.clone());
    let mut other_run = run_receipt(
        matching_runtime_identity(&other_admission.identity),
        zero_gap_inputs(),
        full_coverage_witness(),
        ObserverOutcomeKindV1::Success,
    );
    other_run.admission = reference(other_admission.admission_id.as_str());
    let positive_result = build_observer_result(
        &other_admitted,
        &other_run,
        frozen_profile_reference_v1(),
        scope(),
        reference("predicate.totally.unrelated.topic"),
        applicability(),
        ObserverClaimShapeV1::Presence,
        EvaluatedConditionV1::Present,
        timestamp("2026-08-14T12:00:00.000000000Z"),
    )
    .unwrap();

    let disagreement = detect_disagreement(
        &closed_admitted,
        &closed_run,
        &negative_result,
        &other_admitted,
        &other_run,
        &positive_result,
        timestamp("2026-08-14T13:00:00.000000000Z"),
    )
    .unwrap();
    assert!(disagreement.is_none());
}

#[test]
fn overlapping_domains_with_different_run_applicability_never_disagree() {
    // Same admitted domain and same admitted predicate, but each run
    // actually read a different concrete applicability. Overlap must be
    // keyed on the two *runs*' applicability, not merely on domain and
    // predicate overlap.
    let closed_admission = admission("ast_schema", ObserverAdmissionModeV1::ClosedWorldVerified);
    let closed_admitted = admit(closed_admission.clone());
    let closed_run = run_receipt(
        matching_runtime_identity(&closed_admission.identity),
        zero_gap_inputs(),
        full_coverage_witness(),
        ObserverOutcomeKindV1::Success,
    );
    let negative_result = build_observer_result(
        &closed_admitted,
        &closed_run,
        frozen_profile_reference_v1(),
        scope(),
        reference("predicate.mcp.remember.allowed_actions"),
        applicability(),
        ObserverClaimShapeV1::Presence,
        EvaluatedConditionV1::Absent,
        timestamp("2026-08-14T12:00:00.000000000Z"),
    )
    .unwrap();

    let other_applicability = vec![ConcreteApplicabilityDimensionV1 {
        dimension_id: ContractId::new("repository_commit").unwrap(),
        resource: resource_uri("commit", IdentityForm::Version, 0x99),
    }];
    let mut other_admission = admission("ast_schema", ObserverAdmissionModeV1::PositiveVerified);
    other_admission.admission_id = ContractId::new("observer.other_applicability").unwrap();
    let other_admitted = admit(other_admission.clone());
    let mut other_run = run_receipt(
        matching_runtime_identity(&other_admission.identity),
        zero_gap_inputs(),
        full_coverage_witness(),
        ObserverOutcomeKindV1::Success,
    );
    other_run.admission = reference(other_admission.admission_id.as_str());
    other_run.applicability = other_applicability.clone();
    let positive_result = build_observer_result(
        &other_admitted,
        &other_run,
        frozen_profile_reference_v1(),
        scope(),
        reference("predicate.mcp.remember.allowed_actions"),
        other_applicability,
        ObserverClaimShapeV1::Presence,
        EvaluatedConditionV1::Present,
        timestamp("2026-08-14T12:00:00.000000000Z"),
    )
    .unwrap();

    let disagreement = detect_disagreement(
        &closed_admitted,
        &closed_run,
        &negative_result,
        &other_admitted,
        &other_run,
        &positive_result,
        timestamp("2026-08-14T13:00:00.000000000Z"),
    )
    .unwrap();
    assert!(disagreement.is_none());
}

#[test]
fn candidate_only_opposing_evidence_does_not_invalidate_a_verified_proof() {
    let closed_admission = admission("ast_schema", ObserverAdmissionModeV1::ClosedWorldVerified);
    let closed_admitted = admit(closed_admission.clone());
    let closed_run = run_receipt(
        matching_runtime_identity(&closed_admission.identity),
        zero_gap_inputs(),
        full_coverage_witness(),
        ObserverOutcomeKindV1::Success,
    );
    let negative_result = build_observer_result(
        &closed_admitted,
        &closed_run,
        frozen_profile_reference_v1(),
        scope(),
        reference("predicate.mcp.remember.allowed_actions"),
        applicability(),
        ObserverClaimShapeV1::Presence,
        EvaluatedConditionV1::Absent,
        timestamp("2026-08-14T12:00:00.000000000Z"),
    )
    .unwrap();

    let llm_admission = admission("llm", ObserverAdmissionModeV1::CandidateOnly);
    let llm_admitted = admit(llm_admission.clone());
    let llm_run = run_receipt(
        matching_runtime_identity(&llm_admission.identity),
        zero_gap_inputs(),
        full_coverage_witness(),
        ObserverOutcomeKindV1::Success,
    );
    let candidate_result = build_observer_result(
        &llm_admitted,
        &llm_run,
        frozen_profile_reference_v1(),
        scope(),
        reference("predicate.mcp.remember.allowed_actions"),
        applicability(),
        ObserverClaimShapeV1::Presence,
        EvaluatedConditionV1::Present,
        timestamp("2026-08-14T12:00:00.000000000Z"),
    )
    .unwrap();

    let disagreement = detect_disagreement(
        &closed_admitted,
        &closed_run,
        &negative_result,
        &llm_admitted,
        &llm_run,
        &candidate_result,
        timestamp("2026-08-14T13:00:00.000000000Z"),
    )
    .unwrap();
    assert!(disagreement.is_none());
}

#[test]
fn detect_disagreement_rejects_a_result_bound_to_a_different_admission() {
    // `ObserverResultV1`'s fields are all public, so a caller can pass a
    // result next to an admission it was never actually derived from.
    // `admission_digest` must be checked against the accompanying
    // admission's real digest, not assumed correct because it came out of
    // `build_observer_result` for *some* admission.
    let closed_admission = admission("ast_schema", ObserverAdmissionModeV1::ClosedWorldVerified);
    let closed_admitted = admit(closed_admission.clone());
    let closed_run = run_receipt(
        matching_runtime_identity(&closed_admission.identity),
        zero_gap_inputs(),
        full_coverage_witness(),
        ObserverOutcomeKindV1::Success,
    );
    let mut negative_result = build_observer_result(
        &closed_admitted,
        &closed_run,
        frozen_profile_reference_v1(),
        scope(),
        reference("predicate.mcp.remember.allowed_actions"),
        applicability(),
        ObserverClaimShapeV1::Presence,
        EvaluatedConditionV1::Absent,
        timestamp("2026-08-14T12:00:00.000000000Z"),
    )
    .unwrap();
    negative_result.admission_digest = digest_from_label("forged.unrelated.admission");

    let llm_admission = admission("llm", ObserverAdmissionModeV1::CandidateOnly);
    let llm_admitted = admit(llm_admission.clone());
    let llm_run = run_receipt(
        matching_runtime_identity(&llm_admission.identity),
        zero_gap_inputs(),
        full_coverage_witness(),
        ObserverOutcomeKindV1::Success,
    );
    let candidate_result = build_observer_result(
        &llm_admitted,
        &llm_run,
        frozen_profile_reference_v1(),
        scope(),
        reference("predicate.mcp.remember.allowed_actions"),
        applicability(),
        ObserverClaimShapeV1::Presence,
        EvaluatedConditionV1::Present,
        timestamp("2026-08-14T12:00:00.000000000Z"),
    )
    .unwrap();

    let outcome = detect_disagreement(
        &closed_admitted,
        &closed_run,
        &negative_result,
        &llm_admitted,
        &llm_run,
        &candidate_result,
        timestamp("2026-08-14T13:00:00.000000000Z"),
    );
    assert!(outcome.is_err());
}

#[test]
fn detect_disagreement_rejects_a_result_whose_run_receipt_digest_names_no_supplied_receipt() {
    // `run_receipt_digest` is public and freely settable. Citing a digest
    // that does not equal `ObserverRunReceiptV1::digest()` of the run
    // receipt actually supplied alongside it -- naming a receipt that was
    // never actually produced -- must be rejected outright, not merely
    // left unverified downstream.
    let closed_admission = admission("ast_schema", ObserverAdmissionModeV1::ClosedWorldVerified);
    let closed_admitted = admit(closed_admission.clone());
    let closed_run = run_receipt(
        matching_runtime_identity(&closed_admission.identity),
        zero_gap_inputs(),
        full_coverage_witness(),
        ObserverOutcomeKindV1::Success,
    );
    let mut negative_result = build_observer_result(
        &closed_admitted,
        &closed_run,
        frozen_profile_reference_v1(),
        scope(),
        reference("predicate.mcp.remember.allowed_actions"),
        applicability(),
        ObserverClaimShapeV1::Presence,
        EvaluatedConditionV1::Absent,
        timestamp("2026-08-14T12:00:00.000000000Z"),
    )
    .unwrap();
    negative_result.run_receipt_digest = digest_from_label("attacker.invented.receipt");

    let llm_admission = admission("llm", ObserverAdmissionModeV1::CandidateOnly);
    let llm_admitted = admit(llm_admission.clone());
    let llm_run = run_receipt(
        matching_runtime_identity(&llm_admission.identity),
        zero_gap_inputs(),
        full_coverage_witness(),
        ObserverOutcomeKindV1::Success,
    );
    let candidate_result = build_observer_result(
        &llm_admitted,
        &llm_run,
        frozen_profile_reference_v1(),
        scope(),
        reference("predicate.mcp.remember.allowed_actions"),
        applicability(),
        ObserverClaimShapeV1::Presence,
        EvaluatedConditionV1::Present,
        timestamp("2026-08-14T12:00:00.000000000Z"),
    )
    .unwrap();

    let outcome = detect_disagreement(
        &closed_admitted,
        &closed_run,
        &negative_result,
        &llm_admitted,
        &llm_run,
        &candidate_result,
        timestamp("2026-08-14T13:00:00.000000000Z"),
    );
    assert!(outcome.is_err());
}

#[test]
fn detect_disagreement_rejects_a_verification_outcome_relabelled_away_from_a_timed_out_run() {
    // A genuinely admitted observer whose run receipt reports `timeout`
    // honestly derives `indeterminate` (never a verified negative, never
    // a silent failure). Relabelling only `verification_outcome` on the
    // public result -- while still citing the real admission and the
    // real (timed-out) run receipt by digest -- must be rejected, not
    // silently accepted as a disagreement input. This is the fix for the
    // reviewer's `zz2_public_bytes_only_forgery_invalidates_a_verified_proof`
    // and `zz2_forged_indeterminate_cannot_be_detected_from_the_result_alone`
    // reproductions.
    let closed_admission = admission("ast_schema", ObserverAdmissionModeV1::ClosedWorldVerified);
    let closed_admitted = admit(closed_admission.clone());
    let timed_out_run = run_receipt(
        matching_runtime_identity(&closed_admission.identity),
        zero_gap_inputs(),
        full_coverage_witness(),
        ObserverOutcomeKindV1::Timeout,
    );
    let mut relabelled_result = build_observer_result(
        &closed_admitted,
        &timed_out_run,
        frozen_profile_reference_v1(),
        scope(),
        reference("predicate.mcp.remember.allowed_actions"),
        applicability(),
        ObserverClaimShapeV1::Presence,
        EvaluatedConditionV1::Present,
        timestamp("2026-08-14T12:00:00.000000000Z"),
    )
    .unwrap();
    assert_eq!(
        relabelled_result.verification_outcome,
        VerificationOutcomeV1::Indeterminate
    );
    relabelled_result.verification_outcome = VerificationOutcomeV1::VerifiedPositive;
    // The relabelled shape is still structurally admissible in isolation
    // (`presence`/`present`/`verified_positive` is a valid combination),
    // so only the cross-check against the honest derivation can catch it.
    relabelled_result.validate_shape().unwrap();

    let llm_admission = admission("llm", ObserverAdmissionModeV1::CandidateOnly);
    let llm_admitted = admit(llm_admission.clone());
    let llm_run = run_receipt(
        matching_runtime_identity(&llm_admission.identity),
        zero_gap_inputs(),
        full_coverage_witness(),
        ObserverOutcomeKindV1::Success,
    );
    let candidate_result = build_observer_result(
        &llm_admitted,
        &llm_run,
        frozen_profile_reference_v1(),
        scope(),
        reference("predicate.mcp.remember.allowed_actions"),
        applicability(),
        ObserverClaimShapeV1::Presence,
        EvaluatedConditionV1::Present,
        timestamp("2026-08-14T12:00:00.000000000Z"),
    )
    .unwrap();

    let outcome = detect_disagreement(
        &closed_admitted,
        &timed_out_run,
        &relabelled_result,
        &llm_admitted,
        &llm_run,
        &candidate_result,
        timestamp("2026-08-14T13:00:00.000000000Z"),
    );
    assert!(outcome.is_err());
}

#[test]
fn detect_disagreement_rejects_a_result_whose_predicate_is_relabelled_to_an_unrelated_admission() {
    // A genuine closed_world_verified admission for predicate P produces
    // a real, complete VerifiedNegative. A genuinely admitted (`admit`),
    // honestly-run positive_verified observer under a wholly UNRELATED
    // admission and predicate Q produces its own real VerifiedPositive
    // about Q. The only mutation is relabelling the attacker's public
    // `predicate` field to P after the fact: `predicate` is never
    // consumed by `derive_verification_outcome`, so the attacker's
    // self-reported `verification_outcome` still matches its own honest
    // re-derivation, and `validate_shape` alone cannot catch it. Without
    // binding `result.predicate == admitted.admission().predicate`,
    // this forged pair would be treated as opposing evidence over the
    // victim's predicate and could nullify a complete verified proof
    // about an unrelated P (PRED-05, COVER-01, AUTH-03).
    let closed_admission = admission("ast_schema", ObserverAdmissionModeV1::ClosedWorldVerified);
    let closed_admitted = admit(closed_admission.clone());
    let closed_run = run_receipt(
        matching_runtime_identity(&closed_admission.identity),
        zero_gap_inputs(),
        full_coverage_witness(),
        ObserverOutcomeKindV1::Success,
    );
    let negative_result = build_observer_result(
        &closed_admitted,
        &closed_run,
        frozen_profile_reference_v1(),
        scope(),
        reference("predicate.mcp.remember.allowed_actions"),
        applicability(),
        ObserverClaimShapeV1::Presence,
        EvaluatedConditionV1::Absent,
        timestamp("2026-08-14T12:00:00.000000000Z"),
    )
    .unwrap();
    assert_eq!(
        negative_result.verification_outcome,
        VerificationOutcomeV1::VerifiedNegative
    );

    let mut unrelated_admission =
        admission("ast_schema", ObserverAdmissionModeV1::PositiveVerified);
    unrelated_admission.admission_id = ContractId::new("observer.unrelated_topic").unwrap();
    unrelated_admission.predicate = reference("predicate.totally.unrelated.topic");
    let unrelated_admitted = admit(unrelated_admission.clone());
    let unrelated_run = ObserverRunReceiptV1 {
        admission: reference("observer.unrelated_topic"),
        ..run_receipt(
            matching_runtime_identity(&unrelated_admission.identity),
            zero_gap_inputs(),
            full_coverage_witness(),
            ObserverOutcomeKindV1::Success,
        )
    };
    let mut attacker_result = build_observer_result(
        &unrelated_admitted,
        &unrelated_run,
        frozen_profile_reference_v1(),
        scope(),
        reference("predicate.totally.unrelated.topic"),
        applicability(),
        ObserverClaimShapeV1::Presence,
        EvaluatedConditionV1::Present,
        timestamp("2026-08-14T12:00:00.000000000Z"),
    )
    .unwrap();
    assert_eq!(
        attacker_result.verification_outcome,
        VerificationOutcomeV1::VerifiedPositive
    );
    attacker_result.predicate = reference("predicate.mcp.remember.allowed_actions");
    attacker_result.validate_shape().unwrap();

    let outcome = detect_disagreement(
        &closed_admitted,
        &closed_run,
        &negative_result,
        &unrelated_admitted,
        &unrelated_run,
        &attacker_result,
        timestamp("2026-08-14T13:00:00.000000000Z"),
    );
    assert!(outcome.is_err());
}

#[test]
fn detect_disagreement_rejects_a_result_whose_applicability_was_never_read_by_its_run() {
    // Same shape of attack as the predicate relabel above, but on
    // `applicability`: the result claims a concrete applicability its
    // own cited run receipt never actually read. `applicability` is
    // never consumed by `derive_verification_outcome` either, so the
    // relabelled result's `verification_outcome` still matches its
    // honest re-derivation and `validate_shape` alone cannot catch it.
    let closed_admission = admission("ast_schema", ObserverAdmissionModeV1::ClosedWorldVerified);
    let closed_admitted = admit(closed_admission.clone());
    let closed_run = run_receipt(
        matching_runtime_identity(&closed_admission.identity),
        zero_gap_inputs(),
        full_coverage_witness(),
        ObserverOutcomeKindV1::Success,
    );
    let mut negative_result = build_observer_result(
        &closed_admitted,
        &closed_run,
        frozen_profile_reference_v1(),
        scope(),
        reference("predicate.mcp.remember.allowed_actions"),
        applicability(),
        ObserverClaimShapeV1::Presence,
        EvaluatedConditionV1::Absent,
        timestamp("2026-08-14T12:00:00.000000000Z"),
    )
    .unwrap();
    assert_eq!(
        negative_result.verification_outcome,
        VerificationOutcomeV1::VerifiedNegative
    );
    // The run receipt cited by digest is unchanged, and its
    // `applicability` never included this alternate dimension value --
    // only the public result field is relabelled.
    negative_result.applicability = vec![ConcreteApplicabilityDimensionV1 {
        dimension_id: ContractId::new("repository_commit").unwrap(),
        resource: resource_uri("commit", IdentityForm::Version, 0x99),
    }];
    negative_result.validate_shape().unwrap();

    let llm_admission = admission("llm", ObserverAdmissionModeV1::CandidateOnly);
    let llm_admitted = admit(llm_admission.clone());
    let llm_run = run_receipt(
        matching_runtime_identity(&llm_admission.identity),
        zero_gap_inputs(),
        full_coverage_witness(),
        ObserverOutcomeKindV1::Success,
    );
    let candidate_result = build_observer_result(
        &llm_admitted,
        &llm_run,
        frozen_profile_reference_v1(),
        scope(),
        reference("predicate.mcp.remember.allowed_actions"),
        applicability(),
        ObserverClaimShapeV1::Presence,
        EvaluatedConditionV1::Present,
        timestamp("2026-08-14T12:00:00.000000000Z"),
    )
    .unwrap();

    let outcome = detect_disagreement(
        &closed_admitted,
        &closed_run,
        &negative_result,
        &llm_admitted,
        &llm_run,
        &candidate_result,
        timestamp("2026-08-14T13:00:00.000000000Z"),
    );
    assert!(outcome.is_err());
}

#[test]
fn admitted_observer_result_requires_valid_shape() {
    let admission = admission("ast_schema", ObserverAdmissionModeV1::ClosedWorldVerified);
    let admitted = admit(admission.clone());
    let run = run_receipt(
        matching_runtime_identity(&admission.identity),
        zero_gap_inputs(),
        full_coverage_witness(),
        ObserverOutcomeKindV1::Success,
    );
    let result = build_observer_result(
        &admitted,
        &run,
        frozen_profile_reference_v1(),
        scope(),
        reference("predicate.mcp.remember.allowed_actions"),
        applicability(),
        ObserverClaimShapeV1::Presence,
        EvaluatedConditionV1::Absent,
        timestamp("2026-08-14T12:00:00.000000000Z"),
    )
    .unwrap();
    let admitted_result = AdmittedObserverResultV1::from_test_witness(result).unwrap();
    assert_eq!(
        admitted_result.result().verification_outcome,
        VerificationOutcomeV1::VerifiedNegative
    );
}

#[test]
fn accepted_event_id_and_result_fingerprint_are_domain_separated() {
    let admission = admission("ast_schema", ObserverAdmissionModeV1::ClosedWorldVerified);
    let admitted = admit(admission.clone());
    let run = run_receipt(
        matching_runtime_identity(&admission.identity),
        zero_gap_inputs(),
        full_coverage_witness(),
        ObserverOutcomeKindV1::Success,
    );
    let result = build_observer_result(
        &admitted,
        &run,
        frozen_profile_reference_v1(),
        scope(),
        reference("predicate.mcp.remember.allowed_actions"),
        applicability(),
        ObserverClaimShapeV1::Presence,
        EvaluatedConditionV1::Absent,
        timestamp("2026-08-14T12:00:00.000000000Z"),
    )
    .unwrap();
    let event_id = result.accepted_event_id().unwrap();
    let fingerprint = result.result_fingerprint().unwrap();
    assert_ne!(event_id.digest(), fingerprint.digest());
}

#[test]
fn negative_predicate_public_default_style_shapes_fail_closed() {
    // Wrong claim-shape/condition/outcome combinations must never validate.
    let sanity_admission = admission("ast_schema", ObserverAdmissionModeV1::ClosedWorldVerified);
    sanity_admission.validate_shape().unwrap();
    assert!(!verification_outcome_is_shape_admissible(
        ObserverClaimShapeV1::Presence,
        EvaluatedConditionV1::Absent,
        VerificationOutcomeV1::VerifiedPositive
    ));
    assert!(!verification_outcome_is_shape_admissible(
        ObserverClaimShapeV1::Presence,
        EvaluatedConditionV1::Present,
        VerificationOutcomeV1::VerifiedNegative
    ));
    assert!(!verification_outcome_is_shape_admissible(
        ObserverClaimShapeV1::ExactSet,
        EvaluatedConditionV1::Absent,
        VerificationOutcomeV1::VerifiedExactSet
    ));
}

fn digest(value: &str) -> Sha256Digest {
    Sha256Digest::from_str(value).unwrap()
}

#[test]
fn admission_fixture_is_frozen_and_decodes() {
    let bytes = record(ADMISSION_FIXTURE);
    assert_eq!(raw_sha256(bytes), ADMISSION_RAW_SHA256);
    require_canonical(bytes).unwrap();
    let admission: ObserverAdmissionV2 =
        crate::memory_contracts::canonical::decode_strict(bytes).unwrap();
    admission.validate_shape().unwrap();
    assert_eq!(admission.mode, ObserverAdmissionModeV1::ClosedWorldVerified);
    assert_eq!(admission.digest().unwrap(), digest(ADMISSION_DIGEST));
}

#[test]
fn positive_verified_fixture_decodes() {
    let bytes = record(ADMISSION_POSITIVE_FIXTURE);
    assert_eq!(raw_sha256(bytes), ADMISSION_POSITIVE_RAW_SHA256);
    require_canonical(bytes).unwrap();
    let admission: ObserverAdmissionV2 =
        crate::memory_contracts::canonical::decode_strict(bytes).unwrap();
    admission.validate_shape().unwrap();
    assert_eq!(admission.mode, ObserverAdmissionModeV1::PositiveVerified);
}

#[test]
fn candidate_only_fixture_decodes() {
    let bytes = record(ADMISSION_CANDIDATE_FIXTURE);
    assert_eq!(raw_sha256(bytes), ADMISSION_CANDIDATE_RAW_SHA256);
    require_canonical(bytes).unwrap();
    let admission: ObserverAdmissionV2 =
        crate::memory_contracts::canonical::decode_strict(bytes).unwrap();
    admission.validate_shape().unwrap();
    assert_eq!(admission.mode, ObserverAdmissionModeV1::CandidateOnly);
}

#[test]
fn run_receipt_success_fixture_decodes() {
    let bytes = record(RUN_RECEIPT_SUCCESS_FIXTURE);
    assert_eq!(raw_sha256(bytes), RUN_RECEIPT_SUCCESS_RAW_SHA256);
    require_canonical(bytes).unwrap();
    let run: ObserverRunReceiptV1 =
        crate::memory_contracts::canonical::decode_strict(bytes).unwrap();
    run.validate_shape().unwrap();
    assert_eq!(run.outcome, ObserverOutcomeKindV1::Success);
}

#[test]
fn result_verified_negative_fixture_decodes() {
    let bytes = record(RESULT_VERIFIED_NEGATIVE_FIXTURE);
    assert_eq!(raw_sha256(bytes), RESULT_VERIFIED_NEGATIVE_RAW_SHA256);
    require_canonical(bytes).unwrap();
    let result: ObserverResultV1 =
        crate::memory_contracts::canonical::decode_strict(bytes).unwrap();
    result.validate_shape().unwrap();
    assert_eq!(
        result.verification_outcome,
        VerificationOutcomeV1::VerifiedNegative
    );
}

#[test]
fn vector_suite_fixture_is_present() {
    let bytes = record(VECTOR_SUITE_FIXTURE);
    assert_eq!(raw_sha256(bytes), VECTOR_SUITE_RAW_SHA256);
    require_canonical(bytes).unwrap();
    let _: serde_json::Value = serde_json::from_slice(bytes).unwrap();
}

#[test]
fn negative_llm_closed_world_fixture_is_rejected() {
    let bytes = record(NEGATIVE_LLM_CLOSED_WORLD_FIXTURE);
    assert_eq!(raw_sha256(bytes), NEGATIVE_LLM_CLOSED_WORLD_RAW_SHA256);
    let admission: ObserverAdmissionV2 =
        crate::memory_contracts::canonical::decode_strict(bytes).unwrap();
    assert_eq!(
        admission.validate_shape(),
        Err(ContractError::Schema(
            "invalid observer admission v2".into()
        ))
    );
}

#[test]
fn negative_unknown_field_fixture_is_rejected() {
    let bytes = record(NEGATIVE_UNKNOWN_FIELD_FIXTURE);
    assert_eq!(raw_sha256(bytes), NEGATIVE_UNKNOWN_FIELD_RAW_SHA256);
    let decoded: ContractResult<ObserverAdmissionV2> =
        crate::memory_contracts::canonical::decode_strict(bytes);
    match decoded {
        Err(ContractError::Schema(message)) => {
            assert!(message.contains("unknown field"));
            assert!(message.contains("unexpected_extra_field"));
        }
        other => panic!("expected Schema error for unknown field, got {other:?}"),
    }
}

#[test]
fn negative_unsorted_dependency_digests_fixture_is_rejected() {
    let bytes = record(NEGATIVE_UNSORTED_DEPENDENCY_FIXTURE);
    assert_eq!(raw_sha256(bytes), NEGATIVE_UNSORTED_DEPENDENCY_RAW_SHA256);
    let admission: ObserverAdmissionV2 =
        crate::memory_contracts::canonical::decode_strict(bytes).unwrap();
    assert_eq!(
        admission.validate_shape(),
        Err(ContractError::Schema(
            "invalid observer executable identity".into()
        ))
    );
}

#[test]
fn result_verified_negative_fixture_chains_to_the_frozen_admission_and_run_receipt() {
    // PRED-05: the frozen result vector's admission_digest/run_receipt_digest
    // must be the real digests of the sibling frozen fixtures it claims to
    // cite, not independent labels. Recomputed from the frozen bytes so the
    // chain cannot silently drift again.
    let admission_bytes = record(ADMISSION_FIXTURE);
    let admission: ObserverAdmissionV2 =
        crate::memory_contracts::canonical::decode_strict(admission_bytes).unwrap();
    let run_bytes = record(RUN_RECEIPT_SUCCESS_FIXTURE);
    let run: ObserverRunReceiptV1 =
        crate::memory_contracts::canonical::decode_strict(run_bytes).unwrap();
    let result_bytes = record(RESULT_VERIFIED_NEGATIVE_FIXTURE);
    let result: ObserverResultV1 =
        crate::memory_contracts::canonical::decode_strict(result_bytes).unwrap();
    assert_eq!(result.admission_digest, admission.digest().unwrap());
    assert_eq!(result.run_receipt_digest, run.digest().unwrap());
}
