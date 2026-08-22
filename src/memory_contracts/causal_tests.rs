use std::str::FromStr;

use super::*;
use crate::memory_contracts::{
    canonical::{decode_strict, encode_canonical},
    common::frozen_profile_reference_v1,
    digest::domain_separated_digest,
};

fn scope() -> AuthenticatedProjectScopeV1 {
    AuthenticatedProjectScopeV1::from_trusted_context(
        ContractId::new("tenant.fixture").unwrap(),
        ContractId::new("project.fixture").unwrap(),
    )
}

fn uri(kind: &str, fill: u8) -> ResourceUri {
    ResourceUri::from_str(&format!(
        "urn:ostk:entity:v1:{kind}:sha256:{}",
        hex::encode([fill; 32])
    ))
    .unwrap()
}

fn version_uri(kind: &str, fill: u8) -> ResourceUri {
    ResourceUri::from_str(&format!(
        "urn:ostk:version:v1:{kind}:sha256:{}",
        hex::encode([fill; 32])
    ))
    .unwrap()
}

fn digest(fill: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([fill; 32])
}

fn event(fill: u8) -> AcceptedEventId {
    AcceptedEventId::from_digest(digest(fill))
}

fn source_fact(fill: u8) -> SourceFactId {
    SourceFactId::from_digest(digest(fill))
}

fn ts(value: &str) -> CanonicalTimestamp {
    CanonicalTimestamp::parse(value).unwrap()
}

fn mechanism(recorded_at: &str) -> PreRecordedMechanismV1 {
    PreRecordedMechanismV1 {
        schema_version: CAUSAL_SCHEMA_VERSION,
        mechanism_narrative: MechanismNarrativeTextV1::parse(
            "deploy increased connection pool saturation",
        )
        .unwrap(),
        predicted_outcome_direction: PredictedOutcomeDirectionV1::Degrades,
        recorded_at: ts(recorded_at),
    }
}

fn material_input_deltas() -> Vec<MaterialInputDeltaV1> {
    vec![MaterialInputDeltaV1 {
        component: version_uri("commit", 0x10),
        category: MaterialInputCategoryV1::Code,
        observation: MaterialInputObservationV1::Changed {
            before_digest: digest(0x01),
            after_digest: digest(0x02),
        },
    }]
}

fn hypothesis() -> CausalHypothesisV1 {
    CausalHypothesisV1 {
        schema_version: CAUSAL_SCHEMA_VERSION,
        profile: frozen_profile_reference_v1(),
        scope: scope(),
        cause: uri("deployment", 0x11),
        outcome: uri("slo_breach", 0x22),
        workload: uri("workload", 0x33),
        artifact: uri("artifact", 0x44),
        environment: uri("environment", 0x55),
        mechanism: mechanism("2026-08-15T12:00:00.000000000Z"),
        material_input_deltas: material_input_deltas(),
    }
}

fn base_intervention(hypothesis: &CausalHypothesisV1) -> InterventionSupportV1 {
    InterventionSupportV1 {
        schema_version: CAUSAL_SCHEMA_VERSION,
        profile: frozen_profile_reference_v1(),
        scope: scope(),
        cause: hypothesis.cause.clone(),
        outcome: hypothesis.outcome.clone(),
        workload: hypothesis.workload.clone(),
        artifact: hypothesis.artifact.clone(),
        environment: hypothesis.environment.clone(),
        exposure: VerifiedExposureIntervalV1 {
            cause_exposure_started_at: ts("2026-08-15T12:05:00.000000000Z"),
            cause_exposure_ended_at: None,
            outcome_onset_at: ts("2026-08-15T12:10:00.000000000Z"),
        },
        outcome_measurement: VerifiedOutcomeV1::Measurement {
            receipt: event(0x66),
            observed_at: ts("2026-08-15T12:20:00.000000000Z"),
            matches_predicted_direction: true,
        },
        provenance_to_exposed_cohort: vec![event(0x01), event(0x02)],
        material_input_deltas: hypothesis.material_input_deltas.clone(),
        material_input_separation: MaterialInputSeparationV1::SingleInputChanged {},
        mechanism: hypothesis.mechanism.clone(),
        intervention: AuthorizedInterventionV1 {
            kind: InterventionKindV1::AuthorizedRollback,
            authorization_receipt: event(0x77),
            provider_receipt: event(0x78),
        },
        cohort_comparison: CohortComparisonV1::BeforeAfter {
            before_receipt: event(0x81),
            after_receipt: event(0x82),
        },
        execution_outcome: ExecutionOutcomeV1::Unambiguous,
        coverage: ConfirmationCoverageV1 {
            completeness: CoverageCompletenessV1::Complete,
            freshness: CoverageFreshnessV1::Current,
            confirmation_window_started_at: ts("2026-08-15T12:00:00.000000000Z"),
            confirmation_window_ended_at: ts("2026-08-15T12:30:00.000000000Z"),
        },
        evidence: EvidenceLedgerV1 {
            supporting: vec![event(0x91)],
            opposing: vec![],
            confounding: vec![],
        },
    }
}

fn base_separation_of_duty() -> SeparationOfDutyResultV1 {
    SeparationOfDutyResultV1 {
        ratifier: RatifierIdentityV1::HumanPrincipal {
            principal_id: ContractId::new("principal.ratifier").unwrap(),
        },
        proposer_principal_id: ContractId::new("principal.proposer").unwrap(),
        executor_principal_id: ContractId::new("principal.executor").unwrap(),
        implicated_change_author_principal_ids: vec![
            ContractId::new("principal.author-one").unwrap(),
        ],
        exception: None,
    }
}

fn base_ratification(hypothesis: &CausalHypothesisV1) -> CausalRatificationV1 {
    CausalRatificationV1 {
        schema_version: CAUSAL_SCHEMA_VERSION,
        profile: frozen_profile_reference_v1(),
        scope: scope(),
        hypothesis_fingerprint: hypothesis.fingerprint().unwrap(),
        intervention_support_digest: Some(base_intervention(hypothesis).digest().unwrap()),
        evidence_bundle_digests: vec![digest(0xa1)],
        conclusion: CausalConclusionV1::Ratified,
        causal_role: Some(CausalRoleV1::ContributingCause),
        bounded_scope: hypothesis.environment.clone(),
        achieved_support: SupportLevel::InterventionSupported,
        supporting_evidence: vec![event(0x91)],
        opposing_evidence: vec![],
        unresolved_required_gaps: vec![],
        residual_unknowns: vec![],
        policy_version: 1,
        closure_watermark: ts("2026-08-15T13:00:00.000000000Z"),
        separation_of_duty: base_separation_of_duty(),
        confirmation_lines: vec![],
        supersedes: None,
    }
}

/// `evaluate_ratification` against the exact hypothesis and intervention
/// `base_ratification` bound the record to, for tests that are not
/// themselves exercising the binding checks.
fn evaluate_base_ratification(
    ratification: &CausalRatificationV1,
    hypothesis: &CausalHypothesisV1,
) -> ContractResult<Result<(), Vec<RatificationBlockedReasonV1>>> {
    let intervention = base_intervention(hypothesis);
    evaluate_ratification(ratification, hypothesis, Some(&intervention))
}

// -- SupportLevel / AdjudicationState -----------------------------------

#[test]
fn support_level_orders_from_declaration() {
    assert!(SupportLevel::Possible < SupportLevel::ScopeAssociated);
    assert!(SupportLevel::ScopeAssociated < SupportLevel::MechanisticallyCorroborated);
    assert!(SupportLevel::MechanisticallyCorroborated < SupportLevel::InterventionSupported);
}

#[test]
fn adjudication_transitions_are_append_only_and_terminal_at_superseded() {
    assert!(is_allowed_adjudication_transition(
        AdjudicationState::Open,
        AdjudicationState::Ratified
    ));
    assert!(is_allowed_adjudication_transition(
        AdjudicationState::Ratified,
        AdjudicationState::Superseded
    ));
    assert!(!is_allowed_adjudication_transition(
        AdjudicationState::Ratified,
        AdjudicationState::Refuted
    ));
    assert!(!is_allowed_adjudication_transition(
        AdjudicationState::Superseded,
        AdjudicationState::Ratified
    ));
    assert!(!is_allowed_adjudication_transition(
        AdjudicationState::Open,
        AdjudicationState::Open
    ));
}

#[test]
fn later_refutation_appends_without_erasing_prior_ratification() {
    let hyp = hypothesis();
    let ratified = base_ratification(&hyp);
    let mut refuted = base_ratification(&hyp);
    refuted.conclusion = CausalConclusionV1::Refuted;
    refuted.causal_role = None;
    refuted.achieved_support = SupportLevel::MechanisticallyCorroborated;

    // A single ratified record projects to `ratified`.
    assert_eq!(
        project_adjudication_state(std::slice::from_ref(&ratified)).unwrap(),
        AdjudicationState::Ratified
    );
    // `ratified -> refuted` is not a legal transition: it must append as
    // `superseded`, never reopen as `refuted`.
    assert!(project_adjudication_state(&[ratified.clone(), refuted]).is_err());

    let mut superseded = base_ratification(&hyp);
    superseded.conclusion = CausalConclusionV1::Superseded;
    superseded.supersedes = Some(ratified.digest().unwrap());
    assert_eq!(
        project_adjudication_state(&[ratified, superseded]).unwrap(),
        AdjudicationState::Superseded
    );
}

/// The fingerprint conjunct must be the *sole possible rejection*: the
/// two folded records here differ ONLY in `hypothesis_fingerprint` (via
/// a different `cause` identity), their conclusions form an otherwise
/// legal transition (`open -> refuted -> superseded`), and the second
/// record's `supersedes` correctly cites the immediate predecessor's own
/// digest. Before this test existed, the only committed reproduction
/// used two `Ratified` records, which `is_allowed_adjudication_transition`
/// already rejects on its own (`Ratified -> Ratified` is not a legal
/// transition) — so the fingerprint check at the heart of this function
/// was never actually exercised, and mutating `expected_fingerprint !=
/// event.hypothesis_fingerprint` to `false` left the entire suite green.
#[test]
fn project_adjudication_state_rejects_a_fold_mixing_two_hypotheses() {
    let hyp_a = hypothesis();
    let mut hyp_b = hypothesis();
    hyp_b.cause = uri("deployment", 0xbb);
    assert_ne!(hyp_a.fingerprint().unwrap(), hyp_b.fingerprint().unwrap());

    let mut refuted_a = base_ratification(&hyp_a);
    refuted_a.conclusion = CausalConclusionV1::Refuted;
    refuted_a.causal_role = None;
    refuted_a.achieved_support = SupportLevel::MechanisticallyCorroborated;

    let mut superseded_b = base_ratification(&hyp_b);
    superseded_b.conclusion = CausalConclusionV1::Superseded;
    superseded_b.causal_role = None;
    // Correctly cites the immediate predecessor's real digest — the
    // supersedes-lineage check alone must not be why this is rejected.
    superseded_b.supersedes = Some(refuted_a.digest().unwrap());

    // `Refuted -> Superseded` is a legal transition
    // (`is_allowed_adjudication_transition`), so if this is rejected it
    // can only be the fingerprint mismatch.
    assert!(is_allowed_adjudication_transition(
        AdjudicationState::Refuted,
        AdjudicationState::Superseded
    ));
    assert!(project_adjudication_state(&[refuted_a, superseded_b]).is_err());
}

/// Blocker 4: the fold must also fail closed when two records share one
/// `hypothesis_fingerprint` but were authenticated under different
/// `scope`s. `CausalHypothesisV1::fingerprint` covers `scope`, so a
/// record can never truthfully carry hypothesis A's fingerprint while
/// authenticated under a foreign scope — but that fact only protects the
/// fold if the fold itself checks the record's own `scope` field,
/// because this pure layer never resolves a hypothesis to compare
/// against. The two records below differ ONLY in `scope`: same
/// fingerprint, a legal transition, and a correct supersedes citation,
/// so the scope conjunct is the sole possible rejection.
#[test]
fn project_adjudication_state_rejects_a_fold_mixing_two_scopes() {
    let hyp = hypothesis();
    let mut refuted = base_ratification(&hyp);
    refuted.conclusion = CausalConclusionV1::Refuted;
    refuted.causal_role = None;
    refuted.achieved_support = SupportLevel::MechanisticallyCorroborated;

    let mut superseded_foreign_scope = base_ratification(&hyp);
    superseded_foreign_scope.conclusion = CausalConclusionV1::Superseded;
    superseded_foreign_scope.causal_role = None;
    superseded_foreign_scope.scope = AuthenticatedProjectScopeV1::from_trusted_context(
        ContractId::new("tenant.attacker").unwrap(),
        ContractId::new("project.attacker").unwrap(),
    );
    superseded_foreign_scope.supersedes = Some(refuted.digest().unwrap());

    assert_eq!(
        refuted.hypothesis_fingerprint,
        superseded_foreign_scope.hypothesis_fingerprint
    );
    assert_ne!(refuted.scope, superseded_foreign_scope.scope);
    assert!(project_adjudication_state(&[refuted, superseded_foreign_scope]).is_err());
}

#[test]
fn project_adjudication_state_rejects_supersedes_citing_a_foreign_digest() {
    let hyp = hypothesis();
    let ratified = base_ratification(&hyp);
    let mut superseded = base_ratification(&hyp);
    superseded.conclusion = CausalConclusionV1::Superseded;
    // Cites a real digest, but not the one belonging to the record it
    // was actually folded after.
    superseded.supersedes = Some(digest(0xde));
    assert_ne!(superseded.supersedes, Some(ratified.digest().unwrap()));

    assert!(project_adjudication_state(&[ratified, superseded]).is_err());
}

#[test]
fn project_adjudication_state_rejects_a_superseded_record_with_no_predecessor() {
    // A `superseded` conclusion as the very first folded record can
    // never cite a real predecessor, so it can never be admitted:
    // `supersedes` would have to name the digest of a record that was
    // never folded.
    let hyp = hypothesis();
    let mut superseded = base_ratification(&hyp);
    superseded.conclusion = CausalConclusionV1::Superseded;
    superseded.supersedes = Some(digest(0xde));
    assert!(project_adjudication_state(std::slice::from_ref(&superseded)).is_err());
}

// -- PreRecordedMechanismV1 ----------------------------------------------

#[test]
fn mechanism_commitment_binds_exact_bytes_and_recorded_time() {
    let committed = mechanism("2026-08-15T12:00:00.000000000Z");
    let mut different_direction = committed.clone();
    different_direction.predicted_outcome_direction = PredictedOutcomeDirectionV1::Improves;

    assert_ne!(
        committed.commitment_digest().unwrap(),
        different_direction.commitment_digest().unwrap()
    );
    assert!(committed.recorded_before(&ts("2026-08-15T12:00:00.000000001Z")));
    assert!(!committed.recorded_before(&ts("2026-08-15T12:00:00.000000000Z")));
    assert!(!committed.recorded_before(&ts("2026-08-15T11:59:59.000000000Z")));
}

#[test]
fn mechanism_narrative_rejects_empty_control_and_non_nfc_text() {
    assert!(MechanismNarrativeTextV1::parse("").is_err());
    assert!(MechanismNarrativeTextV1::parse("has\ttab").is_err());
    assert!(MechanismNarrativeTextV1::parse("has\nnewline").is_err());
    // Decomposed ("NFD") "café" is not equal to its own NFC
    // normalization, so it must be rejected even though it has no
    // control characters and is well within the length limit — despite
    // this test's name, nothing here actually exercised non-NFC text
    // before this assertion (a full-file mutation sweep found `||` ->
    // `&&` on this exact clause survived: with no non-NFC assertion,
    // only the length-and-non-NFC conjunction mattered, never the
    // non-NFC check alone).
    assert!(MechanismNarrativeTextV1::parse("cafe\u{0301}").is_err());
    let parsed = MechanismNarrativeTextV1::parse("ok narrative").unwrap();
    assert_eq!(parsed.as_str(), "ok narrative");
}

/// A full-file mutation sweep found `value.len() > MAX_..._BYTES` at
/// `MechanismNarrativeTextV1::parse` had no test exercising its
/// boundary at all (`>` -> `==` and `>` -> `>=` both survived): a
/// narrative of exactly the maximum length must be accepted, and one
/// byte over must be rejected.
#[test]
fn mechanism_narrative_length_boundary_is_inclusive_of_the_maximum() {
    let at_limit = "a".repeat(MAX_MECHANISM_NARRATIVE_BYTES);
    let over_limit = "a".repeat(MAX_MECHANISM_NARRATIVE_BYTES + 1);
    assert!(MechanismNarrativeTextV1::parse(at_limit).is_ok());
    assert!(MechanismNarrativeTextV1::parse(over_limit).is_err());
}

// -- maximum_support_without_intervention --------------------------------

#[test]
fn exemplars_only_never_reaches_mechanistic_corroboration() {
    let exemplar_scope_associated =
        maximum_support_without_intervention(&CorroboratingEvidenceBasisV1::ExemplarsOnly {}, true)
            .unwrap();
    assert_eq!(exemplar_scope_associated, SupportLevel::ScopeAssociated);
    assert!(exemplar_scope_associated < SupportLevel::MechanisticallyCorroborated);

    let exemplar_bare = maximum_support_without_intervention(
        &CorroboratingEvidenceBasisV1::ExemplarsOnly {},
        false,
    )
    .unwrap();
    assert_eq!(exemplar_bare, SupportLevel::Possible);

    let bound = CorroboratingEvidenceBasisV1::MechanisticVerifierBound(Box::new(
        MechanisticVerifierBoundV1 {
            verifier: RegistryReferenceV1 {
                entry_id: ContractId::new("verifier.trace_binder").unwrap(),
                version: 1,
                entry_digest: digest(0xc1),
            },
            bound_trace_digest: digest(0xc2),
            bound_workload: uri("workload", 0x33),
            bound_revision: version_uri("commit", 0x10),
        },
    ));
    assert_eq!(
        maximum_support_without_intervention(&bound, false).unwrap(),
        SupportLevel::MechanisticallyCorroborated
    );
    // Still strictly below intervention_supported (support remains open
    // below intervention evidence).
    assert!(SupportLevel::MechanisticallyCorroborated < SupportLevel::InterventionSupported);
}

// -- derive_intervention_support_level ------------------------------------

#[test]
fn well_formed_intervention_reaches_intervention_supported() {
    let hyp = hypothesis();
    let intervention = base_intervention(&hyp);
    assert_eq!(
        derive_intervention_support_level(&hyp, &intervention).unwrap(),
        Ok(SupportLevel::InterventionSupported)
    );
    assert!(ProvenInterventionSupportV1::from_test_derivation(&hyp, intervention).is_ok());
}

#[test]
fn exposure_after_outcome_onset_blocks_intervention_supported() {
    let hyp = hypothesis();
    let mut intervention = base_intervention(&hyp);
    intervention.exposure = VerifiedExposureIntervalV1 {
        cause_exposure_started_at: ts("2026-08-15T12:15:00.000000000Z"),
        cause_exposure_ended_at: None,
        outcome_onset_at: ts("2026-08-15T12:10:00.000000000Z"),
    };
    let result = derive_intervention_support_level(&hyp, &intervention).unwrap();
    assert_eq!(
        result,
        Err(vec![
            InterventionUnreachableReasonV1::ExposureDoesNotPrecedeAndOverlapOnset
        ])
    );
}

#[test]
fn required_coverage_gap_blocks_intervention_supported() {
    let hyp = hypothesis();
    let mut intervention = base_intervention(&hyp);
    intervention.coverage.completeness = CoverageCompletenessV1::Partial;
    let result = derive_intervention_support_level(&hyp, &intervention).unwrap();
    assert_eq!(
        result,
        Err(vec![
            InterventionUnreachableReasonV1::IncompleteOrStaleCoverage
        ])
    );

    let mut stale = base_intervention(&hyp);
    stale.coverage.freshness = CoverageFreshnessV1::Stale;
    assert_eq!(
        derive_intervention_support_level(&hyp, &stale).unwrap(),
        Err(vec![
            InterventionUnreachableReasonV1::IncompleteOrStaleCoverage
        ])
    );
}

#[test]
fn ambiguous_or_confounded_intervention_blocks_intervention_supported() {
    let hyp = hypothesis();

    let mut ambiguous = base_intervention(&hyp);
    ambiguous.execution_outcome = ExecutionOutcomeV1::Ambiguous;
    assert_eq!(
        derive_intervention_support_level(&hyp, &ambiguous).unwrap(),
        Err(vec![
            InterventionUnreachableReasonV1::AmbiguousExecutionOutcome
        ])
    );

    let mut mixed = base_intervention(&hyp);
    mixed.cohort_comparison = CohortComparisonV1::Mixed {
        receipts: vec![event(0x01), event(0x02)],
    };
    assert_eq!(
        derive_intervention_support_level(&hyp, &mixed).unwrap(),
        Err(vec![InterventionUnreachableReasonV1::MixedCohorts])
    );

    let mut confounded_hypothesis = hyp;
    confounded_hypothesis.material_input_deltas = vec![
        material_input_deltas()[0].clone(),
        MaterialInputDeltaV1 {
            component: version_uri("config", 0x20),
            category: MaterialInputCategoryV1::Configuration,
            observation: MaterialInputObservationV1::Changed {
                before_digest: digest(0x03),
                after_digest: digest(0x04),
            },
        },
    ];
    let mut confounded = base_intervention(&confounded_hypothesis);
    confounded.material_input_separation = MaterialInputSeparationV1::MultipleInputsInseparable {};
    assert_eq!(
        derive_intervention_support_level(&confounded_hypothesis, &confounded).unwrap(),
        Err(vec![
            InterventionUnreachableReasonV1::MaterialInputsChangedInseparably
        ])
    );
}

#[test]
fn prediction_after_observation_blocks_intervention_supported() {
    let mut hyp = hypothesis();
    hyp.mechanism = mechanism("2026-08-15T12:25:00.000000000Z");
    let mut intervention = base_intervention(&hyp);
    intervention.mechanism = hyp.mechanism.clone();
    // outcome observed_at (12:20) is before the mechanism's recorded_at
    // (12:25): the prediction was written after the observation.
    let result = derive_intervention_support_level(&hyp, &intervention).unwrap();
    assert_eq!(
        result,
        Err(vec![
            InterventionUnreachableReasonV1::PredictionRecordedAfterObservation
        ])
    );
}

// -- evaluate_separation_of_duty ------------------------------------------

/// A `closure_watermark` used by tests that do not themselves exercise
/// the activation-ordering check (matches `base_ratification`'s value).
fn closure_watermark() -> CanonicalTimestamp {
    ts("2026-08-15T13:00:00.000000000Z")
}

#[test]
fn separation_of_duty_rejects_author_of_change_as_ratifier() {
    let mut result = base_separation_of_duty();
    result.ratifier = RatifierIdentityV1::HumanPrincipal {
        principal_id: ContractId::new("principal.author-one").unwrap(),
    };
    assert!(!evaluate_separation_of_duty(&result, &closure_watermark()).unwrap());
}

#[test]
fn separation_of_duty_agent_exception_is_always_rejected() {
    let mut result = base_separation_of_duty();
    result.ratifier = RatifierIdentityV1::Agent {
        principal_id: ContractId::new("principal.executor").unwrap(),
    };
    result.exception = Some(SignedSeparationOfDutyExceptionV1 {
        policy_reference: RegistryReferenceV1 {
            entry_id: ContractId::new("policy.sod_exception").unwrap(),
            version: 1,
            entry_digest: digest(0xd1),
        },
        activated_at: ts("2026-08-15T09:00:00.000000000Z"),
    });
    assert!(!evaluate_separation_of_duty(&result, &closure_watermark()).unwrap());
}

#[test]
fn separation_of_duty_human_exception_passes_only_with_activated_policy() {
    let mut result = base_separation_of_duty();
    result.ratifier = RatifierIdentityV1::HumanPrincipal {
        principal_id: ContractId::new("principal.executor").unwrap(),
    };
    assert!(!evaluate_separation_of_duty(&result, &closure_watermark()).unwrap());

    result.exception = Some(SignedSeparationOfDutyExceptionV1 {
        policy_reference: RegistryReferenceV1 {
            entry_id: ContractId::new("policy.sod_exception").unwrap(),
            version: 1,
            entry_digest: digest(0xd1),
        },
        activated_at: ts("2026-08-15T09:00:00.000000000Z"),
    });
    assert!(evaluate_separation_of_duty(&result, &closure_watermark()).unwrap());
}

/// Blocker 5: an exception's `activated_at` must be *provably prior* to
/// the ratification's own `closure_watermark`, not merely present. This
/// is the exact reproduction from the adversarial review: an author of
/// the implicated change citing an exception "activated" a century after
/// the ratification it is meant to excuse — retroactive
/// self-authorization, which AUTH-03's human-only carve-out must never
/// admit.
#[test]
fn separation_of_duty_exception_activated_after_closure_watermark_is_rejected() {
    let mut result = base_separation_of_duty();
    result.ratifier = RatifierIdentityV1::HumanPrincipal {
        principal_id: ContractId::new("principal.author-one").unwrap(),
    };
    result.exception = Some(SignedSeparationOfDutyExceptionV1 {
        policy_reference: RegistryReferenceV1 {
            entry_id: ContractId::new("policy.sod_exception").unwrap(),
            version: 1,
            entry_digest: digest(0xd1),
        },
        activated_at: ts("2126-08-15T09:00:00.000000000Z"),
    });
    assert!(!evaluate_separation_of_duty(&result, &closure_watermark()).unwrap());
}

/// Equal instants do not count as "before" — matching
/// `PreRecordedMechanismV1::recorded_before`'s strict treatment of an
/// equal timestamp.
#[test]
fn separation_of_duty_exception_activated_exactly_at_closure_watermark_is_rejected() {
    let mut result = base_separation_of_duty();
    result.ratifier = RatifierIdentityV1::HumanPrincipal {
        principal_id: ContractId::new("principal.author-one").unwrap(),
    };
    let watermark = closure_watermark();
    result.exception = Some(SignedSeparationOfDutyExceptionV1 {
        policy_reference: RegistryReferenceV1 {
            entry_id: ContractId::new("policy.sod_exception").unwrap(),
            version: 1,
            entry_digest: digest(0xd1),
        },
        activated_at: watermark.clone(),
    });
    assert!(!evaluate_separation_of_duty(&result, &watermark).unwrap());
}

/// End-to-end: the same retroactive-exception attack blocks the whole
/// ratification through `evaluate_ratification`, not merely the isolated
/// `evaluate_separation_of_duty` predicate.
#[test]
fn evaluate_ratification_rejects_retroactively_activated_separation_of_duty_exception() {
    let hyp = hypothesis();
    let mut ratification = base_ratification(&hyp);
    ratification.separation_of_duty.ratifier = RatifierIdentityV1::HumanPrincipal {
        principal_id: ContractId::new("principal.author-one").unwrap(),
    };
    ratification.separation_of_duty.exception = Some(SignedSeparationOfDutyExceptionV1 {
        policy_reference: RegistryReferenceV1 {
            entry_id: ContractId::new("policy.sod_exception").unwrap(),
            version: 1,
            entry_digest: digest(0xd1),
        },
        // A century after `ratification.closure_watermark`.
        activated_at: ts("2126-08-15T09:00:00.000000000Z"),
    });
    assert_eq!(
        evaluate_base_ratification(&ratification, &hyp).unwrap(),
        Err(vec![RatificationBlockedReasonV1::SeparationOfDutyFailed])
    );
}

// -- evaluate_ratification -------------------------------------------------

/// Blocker 2: a `ratified` conclusion with a positive causal role and
/// literally no bound intervention at all (`intervention: None`) must be
/// rejected — before this fix, the `None` arm of `evaluate_ratification`
/// had zero test coverage, and both of its conjuncts (`conclusion ==
/// Ratified`, `causal_role.is_some()`) survived mutation. Every other
/// check passes (bound hypothesis, non-empty supporting evidence, no
/// opposing evidence, separation of duty), so
/// `MissingInterventionBinding` must be the *only* reported reason.
#[test]
fn evaluate_ratification_rejects_ratified_positive_role_with_no_bound_intervention() {
    let hyp = hypothesis();
    let ratification = base_ratification(&hyp);
    assert_eq!(
        evaluate_ratification(&ratification, &hyp, None).unwrap(),
        Err(vec![
            RatificationBlockedReasonV1::MissingInterventionBinding
        ])
    );
}

/// A `ratified` conclusion with a positive causal role but no causal
/// role... i.e. a `refuted`/non-positive-role record must NOT be
/// blocked by `MissingInterventionBinding` even with no intervention
/// supplied: the conjunct is `conclusion == Ratified && causal_role.is_some()`,
/// not `conclusion == Ratified` alone.
#[test]
fn missing_intervention_binding_does_not_fire_for_non_ratified_conclusion() {
    let hyp = hypothesis();
    let mut ratification = base_ratification(&hyp);
    ratification.conclusion = CausalConclusionV1::Refuted;
    ratification.causal_role = None;
    ratification.achieved_support = SupportLevel::MechanisticallyCorroborated;
    let result = evaluate_ratification(&ratification, &hyp, None).unwrap();
    assert!(result.is_ok(), "unexpected block set: {result:?}");
}

/// Mechanical mutation testing found the sibling test above does not
/// discriminate `&&` from `||` in the `None`-arm guard
/// (`conclusion == Ratified && causal_role.is_some()`): with
/// `causal_role: None`, both operators evaluate to `false` since the
/// second conjunct is already `false`. This test instead sets
/// `causal_role: Some(..)` on a NON-ratified conclusion — the first
/// conjunct is `false`, the second is `true`. Under the correct `&&`,
/// `MissingInterventionBinding` must not fire (only
/// `CausalRoleForbiddenForNonRatifiedConclusion`, from the later
/// conclusion-match block, should); under the `||` mutant it would
/// fire in addition, which mechanical mutation testing confirmed this
/// exact test catches (`1495:17: replace && with || in
/// evaluate_ratification` — MISSED before this test, CAUGHT after).
#[test]
fn missing_intervention_binding_guard_requires_ratified_conclusion_not_merely_a_causal_role() {
    let hyp = hypothesis();
    let mut ratification = base_ratification(&hyp);
    ratification.conclusion = CausalConclusionV1::Refuted;
    // causal_role stays `Some(..)` from `base_ratification`.
    assert_eq!(
        evaluate_ratification(&ratification, &hyp, None).unwrap(),
        Err(vec![
            RatificationBlockedReasonV1::CausalRoleForbiddenForNonRatifiedConclusion
        ])
    );
}

/// Blocker 2 (mismatch half): a `ratified`/positive-role record whose
/// cited `intervention_support_digest` does not match the digest of the
/// intervention actually supplied must be rejected with
/// `InterventionBindingMismatch`, not silently pass through to the
/// re-derivation check.
#[test]
fn evaluate_ratification_rejects_intervention_that_does_not_match_the_cited_digest() {
    let hyp = hypothesis();
    let ratification = base_ratification(&hyp);
    let mut foreign_intervention = base_intervention(&hyp);
    foreign_intervention.intervention.provider_receipt = event(0xf0);
    assert_ne!(
        ratification.intervention_support_digest,
        Some(foreign_intervention.digest().unwrap())
    );
    assert_eq!(
        evaluate_ratification(&ratification, &hyp, Some(&foreign_intervention)).unwrap(),
        Err(vec![
            RatificationBlockedReasonV1::InterventionBindingMismatch
        ])
    );
}

#[test]
fn positive_caused_by_cannot_ratify_below_intervention_support() {
    let hyp = hypothesis();
    let mut ratification = base_ratification(&hyp);
    ratification.achieved_support = SupportLevel::MechanisticallyCorroborated;
    let result = evaluate_base_ratification(&ratification, &hyp).unwrap();
    assert_eq!(
        result,
        Err(vec![
            RatificationBlockedReasonV1::PositiveCauseBelowInterventionSupport
        ])
    );
}

#[test]
fn primary_trigger_requires_independent_second_confirmation() {
    let hyp = hypothesis();
    let mut ratification = base_ratification(&hyp);
    ratification.causal_role = Some(CausalRoleV1::PrimaryTrigger);

    // No confirmation lines at all.
    assert_eq!(
        evaluate_base_ratification(&ratification, &hyp).unwrap(),
        Err(vec![
            RatificationBlockedReasonV1::PrimaryTriggerRequiresIndependentSecondConfirmation
        ])
    );

    // Same receipt cited twice under different labels is one line, not
    // an independent second confirmation.
    ratification.confirmation_lines = vec![
        ConfirmationLineV1 {
            source_fact_id: source_fact(0xe1),
            failure_mode: ContractId::new("withdrawal").unwrap(),
        },
        ConfirmationLineV1 {
            source_fact_id: source_fact(0xe1),
            failure_mode: ContractId::new("faithful_reproduction").unwrap(),
        },
    ];
    assert_eq!(
        evaluate_base_ratification(&ratification, &hyp).unwrap(),
        Err(vec![
            RatificationBlockedReasonV1::PrimaryTriggerRequiresIndependentSecondConfirmation
        ])
    );

    // Distinct source facts and distinct failure modes: independent.
    ratification.confirmation_lines = vec![
        ConfirmationLineV1 {
            source_fact_id: source_fact(0xe1),
            failure_mode: ContractId::new("withdrawal").unwrap(),
        },
        ConfirmationLineV1 {
            source_fact_id: source_fact(0xe2),
            failure_mode: ContractId::new("faithful_reproduction").unwrap(),
        },
    ];
    assert_eq!(
        evaluate_base_ratification(&ratification, &hyp).unwrap(),
        Ok(())
    );
    let intervention = base_intervention(&hyp);
    assert!(
        AdmittedCausalRatificationV1::from_test_witness(ratification, &hyp, Some(&intervention))
            .is_ok()
    );
}

#[test]
fn required_gap_blocks_ratification() {
    let hyp = hypothesis();
    let mut ratification = base_ratification(&hyp);
    ratification.unresolved_required_gaps = vec![ContractId::new("gap.coverage").unwrap()];
    assert_eq!(
        evaluate_base_ratification(&ratification, &hyp).unwrap(),
        Err(vec![RatificationBlockedReasonV1::UnresolvedGapsPresent])
    );
}

#[test]
fn refuted_conclusion_rejects_causal_role() {
    let hyp = hypothesis();
    let mut ratification = base_ratification(&hyp);
    ratification.conclusion = CausalConclusionV1::Refuted;
    // causal_role is still Some(...) from the base fixture: forbidden.
    assert_eq!(
        evaluate_base_ratification(&ratification, &hyp).unwrap(),
        Err(vec![
            RatificationBlockedReasonV1::CausalRoleForbiddenForNonRatifiedConclusion
        ])
    );
}

#[test]
fn superseded_conclusion_requires_supersedes_digest() {
    let hyp = hypothesis();
    let mut ratification = base_ratification(&hyp);
    ratification.conclusion = CausalConclusionV1::Superseded;
    ratification.causal_role = None;
    assert!(ratification.validate_shape().is_err());
}

#[test]
fn supersedes_zero_digest_is_rejected_at_shape() {
    // `hypothesis_fingerprint == ZERO`, `intervention_support_digest ==
    // Some(ZERO)`, and any ZERO entry in `evidence_bundle_digests` are
    // all rejected by validate_shape; `supersedes` gets the same
    // treatment for consistency, even though `project_adjudication_state`
    // separately rejects it (ZERO can never equal a real predecessor
    // digest).
    let hyp = hypothesis();
    let mut ratification = base_ratification(&hyp);
    ratification.conclusion = CausalConclusionV1::Superseded;
    ratification.causal_role = None;
    ratification.supersedes = Some(Sha256Digest::ZERO);
    assert!(ratification.validate_shape().is_err());
}

// -- unknown-role / shape negatives ----------------------------------------

#[test]
fn unknown_causal_role_is_rejected_at_decode() {
    let raw = br#""root_cause""#;
    let decoded: ContractResult<CausalRoleV1> = decode_strict(raw);
    assert!(decoded.is_err());
}

#[test]
fn unknown_adjudication_state_is_rejected_at_decode() {
    let raw = br#""pending""#;
    let decoded: ContractResult<AdjudicationState> = decode_strict(raw);
    assert!(decoded.is_err());
}

// -- unit-variant unknown-field smuggling (blocker 3) --------------------
//
// `#[serde(tag = "...", deny_unknown_fields)]` on an internally-tagged
// enum has NO effect on a *unit* variant: serde routes it through a
// tag-only visitor that never inspects residual keys, so
// `Unobserved`/`ExemplarsOnly`/`SingleInputChanged`/
// `MultipleInputsInseparable` used to accept — and silently drop — any
// extra JSON key smuggled alongside their tag. The fix promotes each to
// the empty struct-variant form (`Unobserved {}`, ...), which serializes
// to the identical wire bytes but goes through the field-checked struct
// visitor. These tests decode the mutated bytes directly rather than
// relying on a byte-frozen fixture, matching this module's existing
// `unknown_causal_role_is_rejected_at_decode` /
// `unknown_adjudication_state_is_rejected_at_decode` pattern.

#[test]
fn unobserved_material_input_observation_rejects_unknown_field() {
    let mut value = serde_json::to_value(MaterialInputObservationV1::Unobserved {}).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("smuggled".into(), serde_json::json!("payload"));
    let bytes = serde_json::to_vec(&value).unwrap();
    assert!(decode_strict::<MaterialInputObservationV1>(&bytes).is_err());
}

#[test]
fn exemplars_only_basis_rejects_unknown_field() {
    let mut value = serde_json::to_value(CorroboratingEvidenceBasisV1::ExemplarsOnly {}).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("smuggled".into(), serde_json::json!("payload"));
    let bytes = serde_json::to_vec(&value).unwrap();
    assert!(decode_strict::<CorroboratingEvidenceBasisV1>(&bytes).is_err());
}

#[test]
fn material_input_separation_unit_variants_reject_unknown_field() {
    for variant in [
        MaterialInputSeparationV1::SingleInputChanged {},
        MaterialInputSeparationV1::MultipleInputsInseparable {},
    ] {
        let mut value = serde_json::to_value(&variant).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("isolation_receipt".into(), serde_json::json!("urn:evil"));
        let bytes = serde_json::to_vec(&value).unwrap();
        assert!(
            decode_strict::<MaterialInputSeparationV1>(&bytes).is_err(),
            "variant {variant:?} must reject a smuggled field"
        );
    }
}

/// Closes the exact digest-collision path from the adversarial review:
/// before the unit-variant fix, `{"material_input_separation":
/// {"kind":"single_input_changed"}}` and `{"material_input_separation":
/// {"kind":"single_input_changed","isolation_receipt":"urn:evil"}}` were
/// two different byte strings that decoded to the identical
/// `InterventionSupportV1` and digested to the identical value — a party
/// pinning raw wire bytes and a party pinning the canonical digest would
/// disagree about what was admitted.
#[test]
fn smuggled_field_inside_material_input_separation_is_rejected_at_full_record_decode() {
    let hyp = hypothesis();
    let intervention = base_intervention(&hyp);
    let clean_digest = intervention.digest().unwrap();

    let mut value = serde_json::to_value(&intervention).unwrap();
    value
        .get_mut("material_input_separation")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("isolation_receipt".into(), serde_json::json!("urn:evil"));
    let smuggled_bytes = serde_json::to_vec(&value).unwrap();

    let decoded: ContractResult<InterventionSupportV1> = decode_strict(&smuggled_bytes);
    assert!(
        decoded.is_err(),
        "a smuggled key inside material_input_separation must be rejected at decode, not \
             silently collapsed to the clean record"
    );
    // Sanity: the clean record's own digest is unaffected by this test.
    assert_eq!(intervention.digest().unwrap(), clean_digest);
}

#[test]
fn cause_equal_to_outcome_is_rejected() {
    let mut hyp = hypothesis();
    hyp.outcome = hyp.cause.clone();
    assert!(hyp.validate_shape().is_err());
}

#[test]
fn empty_material_input_inventory_is_rejected() {
    let mut hyp = hypothesis();
    hyp.material_input_deltas = vec![];
    assert!(hyp.validate_shape().is_err());
}

// -- duplicate (not merely misordered) canonical-set entries ------------
//
// PREFLIGHT item 10 / blocker 1(b): `strictly_sorted` and
// `strictly_sorted_by_component` both use `<`, which rejects both a
// misordered pair AND a duplicated (equal) adjacent pair. Before these
// tests, every existing assertion in the crate only ever exercised
// misordering, so a `<` -> `<=` mutation — which still rejects
// misordering but silently *admits* an exact duplicate — left the whole
// suite green on every one of these fields.

#[test]
fn strictly_sorted_rejects_duplicate_adjacent_elements() {
    assert!(strictly_sorted(&[1, 2, 3]));
    assert!(!strictly_sorted(&[1, 2, 2, 3]));
}

#[test]
fn duplicate_material_input_component_is_rejected() {
    let mut hyp = hypothesis();
    let dup = hyp.material_input_deltas[0].clone();
    hyp.material_input_deltas = vec![dup.clone(), dup];
    assert!(hyp.validate_shape().is_err());
}

#[test]
fn duplicate_entries_in_causal_ratification_canonical_sets_are_rejected() {
    let hyp = hypothesis();

    let mut evidence_bundle_dup = base_ratification(&hyp);
    evidence_bundle_dup.evidence_bundle_digests = vec![digest(0xa1), digest(0xa1)];
    assert!(evidence_bundle_dup.validate_shape().is_err());

    let mut supporting_dup = base_ratification(&hyp);
    supporting_dup.supporting_evidence = vec![event(0x91), event(0x91)];
    assert!(supporting_dup.validate_shape().is_err());

    let mut opposing_dup = base_ratification(&hyp);
    let entry = OpposingEvidenceEntryV1 {
        event: event(0x95),
        reconciliation: None,
    };
    opposing_dup.opposing_evidence = vec![entry.clone(), entry];
    assert!(opposing_dup.validate_shape().is_err());

    let mut gaps_dup = base_ratification(&hyp);
    let gap = ContractId::new("gap.coverage").unwrap();
    gaps_dup.unresolved_required_gaps = vec![gap.clone(), gap];
    assert!(gaps_dup.validate_shape().is_err());

    let mut residual_dup = base_ratification(&hyp);
    let unknown = ContractId::new("unknown.residual").unwrap();
    residual_dup.residual_unknowns = vec![unknown.clone(), unknown];
    assert!(residual_dup.validate_shape().is_err());
}

#[test]
fn duplicate_entries_in_intervention_support_canonical_sets_are_rejected() {
    let hyp = hypothesis();

    let mut provenance_dup = base_intervention(&hyp);
    provenance_dup.provenance_to_exposed_cohort = vec![event(0x01), event(0x01)];
    assert!(provenance_dup.validate_shape().is_err());

    let mut mixed_receipts_dup = base_intervention(&hyp);
    mixed_receipts_dup.cohort_comparison = CohortComparisonV1::Mixed {
        receipts: vec![event(0x81), event(0x81)],
    };
    assert!(mixed_receipts_dup.validate_shape().is_err());
}

#[test]
fn duplicate_implicated_change_author_is_rejected() {
    let mut result = base_separation_of_duty();
    let author = ContractId::new("principal.author-one").unwrap();
    result.implicated_change_author_principal_ids = vec![author.clone(), author];
    assert!(result.validate_shape().is_err());
}

#[test]
fn unbound_intervention_fails_the_hypothesis_binding_check() {
    let hyp = hypothesis();
    let mut other_hyp = hyp.clone();
    other_hyp.mechanism = mechanism("2026-08-15T12:01:00.000000000Z");
    let intervention = base_intervention(&other_hyp);
    assert!(!intervention.binds_hypothesis(&hyp).unwrap());
    assert_eq!(
        derive_intervention_support_level(&hyp, &intervention).unwrap(),
        Err(vec![
            InterventionUnreachableReasonV1::HypothesisMechanismMismatch
        ])
    );
}

/// Blocker 4c: an intervention that contradicts the hypothesis's own
/// characterization of a registered material input — the hypothesis says
/// `Unchanged{digest}`, the intervention actually observed `Changed` on
/// that exact component — must not bind, even though the intervention
/// otherwise agrees on every causal identity.
#[test]
fn contradictory_material_input_observation_fails_binding_check() {
    let mut hyp = hypothesis();
    hyp.material_input_deltas = vec![MaterialInputDeltaV1 {
        component: version_uri("commit", 0x10),
        category: MaterialInputCategoryV1::Code,
        observation: MaterialInputObservationV1::Unchanged {
            digest: digest(0x01),
        },
    }];
    let mut intervention = base_intervention(&hyp);
    intervention.material_input_deltas = vec![MaterialInputDeltaV1 {
        component: version_uri("commit", 0x10),
        category: MaterialInputCategoryV1::Code,
        observation: MaterialInputObservationV1::Changed {
            before_digest: digest(0x01),
            after_digest: digest(0x02),
        },
    }];
    assert!(!intervention.binds_hypothesis(&hyp).unwrap());
    assert_eq!(
        derive_intervention_support_level(&hyp, &intervention).unwrap(),
        Err(vec![
            InterventionUnreachableReasonV1::HypothesisMechanismMismatch
        ])
    );
}

/// Blocker 3: a ratification cannot be replayed against a different
/// hypothesis merely because that hypothesis shares the same mechanism
/// narrative, predicted direction, and `recorded_at` — two hypotheses
/// with different cause/outcome/workload/artifact/environment identities
/// collide on `PreRecordedMechanismV1::commitment_digest` (its preimage
/// covers only the narrative, direction, and timestamp) but must never
/// collide on `CausalHypothesisV1::fingerprint`.
#[test]
fn ratification_cannot_be_replayed_against_a_different_hypothesis() {
    let hyp_a = hypothesis();
    let mut hyp_b = hyp_a.clone();
    hyp_b.cause = uri("deployment", 0x99);
    // Same mechanism commitment preimage (narrative, direction,
    // recorded_at are unchanged), but a materially different hypothesis.
    assert_eq!(
        hyp_a.mechanism.commitment_digest().unwrap(),
        hyp_b.mechanism.commitment_digest().unwrap()
    );
    assert_ne!(hyp_a.fingerprint().unwrap(), hyp_b.fingerprint().unwrap());

    let ratification = base_ratification(&hyp_a);
    assert!(ratification.binds_hypothesis(&hyp_a).unwrap());
    assert!(!ratification.binds_hypothesis(&hyp_b).unwrap());
    // Checked against hyp_b, this fails two independent ways: the
    // ratification itself does not bind hyp_b (wrong fingerprint), and
    // the intervention it cites — built for hyp_a — does not re-derive
    // to `intervention_supported` against hyp_b either (it does not
    // bind hyp_b's identities/mechanism). Both are reported; neither
    // masks the other.
    assert_eq!(
        evaluate_ratification(&ratification, &hyp_b, Some(&base_intervention(&hyp_a))).unwrap(),
        Err(vec![
            RatificationBlockedReasonV1::HypothesisBindingMismatch,
            RatificationBlockedReasonV1::BoundInterventionDoesNotReachInterventionSupported,
        ])
    );
}

/// Blocker 2 (ratification half): a ratification whose `scope` differs
/// from the intervention it claims support from must not bind, even when
/// the digest matches (the digest alone cannot prove the record was
/// authenticated under the same tenant/project).
#[test]
fn ratification_cross_scope_intervention_binding_fails() {
    let hyp = hypothesis();
    let intervention = base_intervention(&hyp);
    let mut ratification = base_ratification(&hyp);
    ratification.scope = AuthenticatedProjectScopeV1::from_trusted_context(
        ContractId::new("tenant.attacker").unwrap(),
        ContractId::new("project.attacker").unwrap(),
    );
    assert!(!ratification.binds_intervention(&intervention).unwrap());
}

#[test]
fn hypothesis_and_intervention_digests_are_stable_and_domain_separated() {
    let hyp = hypothesis();
    let fingerprint = hyp.fingerprint().unwrap();
    assert_eq!(fingerprint, hyp.fingerprint().unwrap());
    assert_eq!(
        fingerprint,
        domain_separated_digest(
            DigestDomain::CausalHypothesisV1,
            &encode_canonical(&hyp).unwrap()
        )
    );

    let intervention = base_intervention(&hyp);
    let intervention_digest = intervention.digest().unwrap();
    assert_ne!(fingerprint, intervention_digest);
}

#[test]
fn ratification_digest_is_domain_separated_from_hypothesis_and_intervention() {
    let hyp = hypothesis();
    let ratification = base_ratification(&hyp);
    let ratification_digest = ratification.digest().unwrap();
    assert_eq!(
        ratification_digest,
        domain_separated_digest(
            DigestDomain::CausalRatificationV1,
            &encode_canonical(&ratification).unwrap()
        )
    );
    assert_ne!(ratification_digest, hyp.fingerprint().unwrap());
}

// -- Byte-frozen fixture vectors (contracts/dynamic-memory/v3/causal) ----
//
// Every fixture below is `include_bytes!`'d verbatim, then: (1) its raw
// SHA-256 (trailing LF included) is checked against a pinned constant, so
// an accidental reformat is caught before decoding even runs; (2)
// `canonical::decode_strict` decodes the stripped body and
// `canonical::encode_canonical` round-trips it back to the exact stripped
// bytes, so the file is proven to already be in canonical form; (3) for
// identity-bearing records, the derived digest is checked against a
// second pinned constant; (4) every negative fixture is proven to fail
// exactly the named way.

const CAUSAL_HYPOTHESIS_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v3/causal/causal-hypothesis-v1.jsonl");
const INTERVENTION_SUPPORT_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v3/causal/intervention-support-v1.jsonl");
const RATIFICATION_CONTRIBUTING_CAUSE_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/causal/causal-ratification-contributing-cause-v1.jsonl"
);
const RATIFICATION_PRIMARY_TRIGGER_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/causal/causal-ratification-primary-trigger-v1.jsonl"
);
const NEGATIVE_CAUSE_EQUALS_OUTCOME_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v3/causal/negative-cause-equals-outcome.jsonl");
const NEGATIVE_EMPTY_MATERIAL_INPUT_INVENTORY_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/causal/negative-empty-material-input-inventory.jsonl"
);
const NEGATIVE_EXPOSURE_AFTER_ONSET_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v3/causal/negative-exposure-after-onset.jsonl");
const NEGATIVE_COVERAGE_PARTIAL_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v3/causal/negative-coverage-partial.jsonl");
const NEGATIVE_COHORTS_MIXED_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v3/causal/negative-cohorts-mixed.jsonl");
const NEGATIVE_EXECUTION_AMBIGUOUS_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v3/causal/negative-execution-ambiguous.jsonl");
const NEGATIVE_MATERIAL_INPUTS_INSEPARABLE_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/causal/negative-material-inputs-inseparable.jsonl"
);
const NEGATIVE_PREDICTION_AFTER_OBSERVATION_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/causal/negative-prediction-after-observation.jsonl"
);
const NEGATIVE_RATIFICATION_UNRESOLVED_GAPS_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/causal/negative-ratification-unresolved-gaps.jsonl"
);
const NEGATIVE_RATIFICATION_BELOW_INTERVENTION_SUPPORT_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/causal/negative-ratification-below-intervention-support.jsonl"
);
const NEGATIVE_RATIFICATION_DISQUALIFIED_INTERVENTION_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/causal/negative-ratification-disqualified-intervention.jsonl"
);
const NEGATIVE_PRIMARY_TRIGGER_SAME_RECEIPT_TWICE_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/causal/negative-primary-trigger-same-receipt-twice.jsonl"
);
const NEGATIVE_RATIFICATION_AUTHOR_AS_RATIFIER_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/causal/negative-ratification-author-as-ratifier.jsonl"
);
const NEGATIVE_RATIFICATION_AGENT_EXCEPTION_REJECTED_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/causal/negative-ratification-agent-exception-rejected.jsonl"
);
const NEGATIVE_RATIFICATION_SUPERSEDED_WITHOUT_DIGEST_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/causal/negative-ratification-superseded-without-digest.jsonl"
);
const NEGATIVE_RATIFICATION_SUPERSEDED_CAUSAL_ROLE_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/causal/negative-ratification-superseded-causal-role.jsonl"
);
const NEGATIVE_INTERVENTION_SCOPE_MISMATCH_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/causal/negative-intervention-scope-mismatch.jsonl"
);
const NEGATIVE_INTERVENTION_UNOBSERVED_MATERIAL_INPUT_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/causal/negative-intervention-unobserved-material-input.jsonl"
);
const NEGATIVE_INTERVENTION_SINGLE_INPUT_CHANGED_ZERO_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/causal/negative-intervention-single-input-changed-zero.jsonl"
);
const NEGATIVE_RATIFICATION_UNRECONCILED_OPPOSING_EVIDENCE_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/causal/negative-ratification-unreconciled-opposing-evidence.jsonl"
);
const NEGATIVE_RATIFICATION_EMPTY_SUPPORTING_EVIDENCE_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/causal/negative-ratification-empty-supporting-evidence.jsonl"
);
const NEGATIVE_CAUSAL_ROLE_UNKNOWN_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v3/causal/negative-causal-role-unknown.jsonl");
const NEGATIVE_ADJUDICATION_STATE_UNKNOWN_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/causal/negative-adjudication-state-unknown.jsonl"
);
const VECTOR_SUITE_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v3/causal/vector-suite.jsonl");

const CAUSAL_HYPOTHESIS_V1_RAW_SHA256: &str =
    "37a4d3eb5f37a5a62076abb0a543e2c527aaad8195876d1f4dcb11da230d1c66";
const CAUSAL_RATIFICATION_CONTRIBUTING_CAUSE_V1_RAW_SHA256: &str =
    "6d801166af4772deb58498d833090558561baee7ba9d7d3e1d8c2379d636fffc";
const CAUSAL_RATIFICATION_PRIMARY_TRIGGER_V1_RAW_SHA256: &str =
    "70d67360be1b03048a12eee19525f9fe9de1cf82495bad4b099ec1a00b0a20b8";
const INTERVENTION_SUPPORT_V1_RAW_SHA256: &str =
    "09bd170b5195730c19992d6e0e1fe833dfd0f12dcaf42ed2a87317f1dc6a3893";
const NEGATIVE_ADJUDICATION_STATE_UNKNOWN_RAW_SHA256: &str =
    "6006c8517af64611108324ddb24ea0332b6a2114b53e75acf4bf55ae285d66ca";
const NEGATIVE_CAUSAL_ROLE_UNKNOWN_RAW_SHA256: &str =
    "1104841ac38aae06cb66cbef248f7f3bbdc66b7d31b4426ab3cddc31bca7b0c4";
const NEGATIVE_CAUSE_EQUALS_OUTCOME_RAW_SHA256: &str =
    "ed0d5e213ca31e2b09174bb98530cabe35a97675e146a0b15be370d02799417b";
const NEGATIVE_COHORTS_MIXED_RAW_SHA256: &str =
    "480c27570215e93e8e9d0888383acb015920a0f42dea9fc8b12478da992e6300";
const NEGATIVE_COVERAGE_PARTIAL_RAW_SHA256: &str =
    "3d1b75eb9a6dbfc16cf0c8e5071f331fdc53bdb64228bce2c1cec2a40b0178cd";
const NEGATIVE_EMPTY_MATERIAL_INPUT_INVENTORY_RAW_SHA256: &str =
    "eec04adf03de139a5d3a66241bff196b302ad097b328b836619654a6314ad393";
const NEGATIVE_EXECUTION_AMBIGUOUS_RAW_SHA256: &str =
    "2f53c3e137666b91babba72eb8afa1c4964f51607b0ea149078b0f1cdecbe1b8";
const NEGATIVE_EXPOSURE_AFTER_ONSET_RAW_SHA256: &str =
    "d79aef147f1167be576257d1c059cfbf48084d2e22280a45ea3093327c073295";
const NEGATIVE_MATERIAL_INPUTS_INSEPARABLE_RAW_SHA256: &str =
    "ffe56a7358429ff1e9fce2179b459e747e5fef7fc301ab5de46855c6fe49cdf1";
const NEGATIVE_PREDICTION_AFTER_OBSERVATION_RAW_SHA256: &str =
    "b2ca92a4d637783e9e0fecc2616d54a5d66ecdb350adbe9ddd0185008b27f295";
const NEGATIVE_PRIMARY_TRIGGER_SAME_RECEIPT_TWICE_RAW_SHA256: &str =
    "b6286584e1a9bdfef300679db3007fcac3c3e0c51d7c469c295156891b748faa";
const NEGATIVE_RATIFICATION_AGENT_EXCEPTION_REJECTED_RAW_SHA256: &str =
    "d8c4ac716999d5efb3e568bbd4650bb0d05106343fb3a94353aa087c92a09ae7";
const NEGATIVE_RATIFICATION_AUTHOR_AS_RATIFIER_RAW_SHA256: &str =
    "d2b767d9e5551b860bcdf7629972ccbce49add7fee96c8bfa7cb9c3be2503956";
const NEGATIVE_RATIFICATION_BELOW_INTERVENTION_SUPPORT_RAW_SHA256: &str =
    "d3766a8061fd6853c1723e4d11f14248eef5f6792a79e98d66369257debc075c";
const NEGATIVE_RATIFICATION_DISQUALIFIED_INTERVENTION_RAW_SHA256: &str =
    "d078f992a72d43a731b2e2f1bf12ef04ce53cf402fa07245aa047a385611592e";
const NEGATIVE_RATIFICATION_SUPERSEDED_WITHOUT_DIGEST_RAW_SHA256: &str =
    "84d122708bd1b3df0b0e05d0ae1f0ab1e251f843dbce360f29b598539f591b56";
const NEGATIVE_RATIFICATION_UNRESOLVED_GAPS_RAW_SHA256: &str =
    "de14a2e8abb0539c5747591a1870df8c6a70fe8d96ee44ce47a1031432aacf71";
const NEGATIVE_RATIFICATION_SUPERSEDED_CAUSAL_ROLE_RAW_SHA256: &str =
    "70e7a0f52cf245fb08d756f78ac10033825e78591621d77cfbb6392c49fac5d6";
const NEGATIVE_INTERVENTION_SCOPE_MISMATCH_RAW_SHA256: &str =
    "1691453f7c9b9883211f82fd2b3075743a3d7810e4cb08e2f869c38bb6d2cd5b";
const NEGATIVE_INTERVENTION_UNOBSERVED_MATERIAL_INPUT_RAW_SHA256: &str =
    "c980c4a0c8cdebca5567baa69b851c900a044c0f308604f86577638485d32e99";
const NEGATIVE_INTERVENTION_SINGLE_INPUT_CHANGED_ZERO_RAW_SHA256: &str =
    "8c4927fdff6b07e7140a80865320dfcb31b6a303d3dde8981dbdd783b3d76ab2";
const NEGATIVE_RATIFICATION_UNRECONCILED_OPPOSING_EVIDENCE_RAW_SHA256: &str =
    "30cf8a6a66b5f17b3a71d54b34818b8bb6192cf7829c42bcff5ae1e495b2c4ef";
const NEGATIVE_RATIFICATION_EMPTY_SUPPORTING_EVIDENCE_RAW_SHA256: &str =
    "380517f6442fba898b3e53a72a3131a795faad1c89285895f42e268d2af6d8c4";
const VECTOR_SUITE_RAW_SHA256: &str =
    "3372b58f86fdb8e22bb490730cf03027b8564419f4709b9b07b4a3373eb5991b";

const CAUSAL_HYPOTHESIS_FINGERPRINT: &str =
    "76b41ed32639adbe1291dd3aca9ae24c51f21ae570014b8119cfc0ce719f3dad";
const INTERVENTION_SUPPORT_DIGEST: &str =
    "5fb951d6aa0d41b64812ce2e706012eb71621cd7c30dab644ff3e76e7599afe0";
const RATIFICATION_CONTRIBUTING_CAUSE_DIGEST: &str =
    "71d9e5bde10a790907ccf5db2cb136f542db46c689cabce40598b268c088aabd";
const RATIFICATION_PRIMARY_TRIGGER_DIGEST: &str =
    "cdf4b41bc5884fe1fe05ff7a12adccf38fdf67d250d5208a59b8871f91779cc4";

/// One canonical JSON record plus exactly one trailing LF; the LF is
/// excluded from every pinned digest.
fn record(bytes: &[u8]) -> &[u8] {
    let body = bytes
        .strip_suffix(b"\n")
        .expect("contract artifact must have exactly one framing LF");
    assert!(!body.ends_with(b"\n"), "exactly one trailing LF");
    assert!(!body.contains(&b'\r'), "no CR in a contract artifact");
    body
}

fn raw_sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};
    hex::encode(Sha256::digest(bytes))
}

/// Decode, prove the file is already canonical (round-trips byte for
/// byte), and return the decoded value.
fn decode_and_prove_canonical<T>(raw: &[u8]) -> T
where
    T: serde::de::DeserializeOwned + Serialize,
{
    let body = record(raw);
    let decoded: T = decode_strict(body).expect("fixture must decode under closed schema");
    assert_eq!(
        encode_canonical(&decoded).expect("re-encode must succeed"),
        body,
        "fixture bytes are not already in canonical form"
    );
    decoded
}

#[test]
#[allow(clippy::too_many_lines)] // one pinned (fixture, digest) pair per fixture file
fn raw_fixture_bytes_are_pinned() {
    for (raw, expected) in [
        (CAUSAL_HYPOTHESIS_FIXTURE, CAUSAL_HYPOTHESIS_V1_RAW_SHA256),
        (
            INTERVENTION_SUPPORT_FIXTURE,
            INTERVENTION_SUPPORT_V1_RAW_SHA256,
        ),
        (
            RATIFICATION_CONTRIBUTING_CAUSE_FIXTURE,
            CAUSAL_RATIFICATION_CONTRIBUTING_CAUSE_V1_RAW_SHA256,
        ),
        (
            RATIFICATION_PRIMARY_TRIGGER_FIXTURE,
            CAUSAL_RATIFICATION_PRIMARY_TRIGGER_V1_RAW_SHA256,
        ),
        (
            NEGATIVE_CAUSE_EQUALS_OUTCOME_FIXTURE,
            NEGATIVE_CAUSE_EQUALS_OUTCOME_RAW_SHA256,
        ),
        (
            NEGATIVE_EMPTY_MATERIAL_INPUT_INVENTORY_FIXTURE,
            NEGATIVE_EMPTY_MATERIAL_INPUT_INVENTORY_RAW_SHA256,
        ),
        (
            NEGATIVE_EXPOSURE_AFTER_ONSET_FIXTURE,
            NEGATIVE_EXPOSURE_AFTER_ONSET_RAW_SHA256,
        ),
        (
            NEGATIVE_COVERAGE_PARTIAL_FIXTURE,
            NEGATIVE_COVERAGE_PARTIAL_RAW_SHA256,
        ),
        (
            NEGATIVE_COHORTS_MIXED_FIXTURE,
            NEGATIVE_COHORTS_MIXED_RAW_SHA256,
        ),
        (
            NEGATIVE_EXECUTION_AMBIGUOUS_FIXTURE,
            NEGATIVE_EXECUTION_AMBIGUOUS_RAW_SHA256,
        ),
        (
            NEGATIVE_MATERIAL_INPUTS_INSEPARABLE_FIXTURE,
            NEGATIVE_MATERIAL_INPUTS_INSEPARABLE_RAW_SHA256,
        ),
        (
            NEGATIVE_PREDICTION_AFTER_OBSERVATION_FIXTURE,
            NEGATIVE_PREDICTION_AFTER_OBSERVATION_RAW_SHA256,
        ),
        (
            NEGATIVE_RATIFICATION_UNRESOLVED_GAPS_FIXTURE,
            NEGATIVE_RATIFICATION_UNRESOLVED_GAPS_RAW_SHA256,
        ),
        (
            NEGATIVE_RATIFICATION_BELOW_INTERVENTION_SUPPORT_FIXTURE,
            NEGATIVE_RATIFICATION_BELOW_INTERVENTION_SUPPORT_RAW_SHA256,
        ),
        (
            NEGATIVE_RATIFICATION_DISQUALIFIED_INTERVENTION_FIXTURE,
            NEGATIVE_RATIFICATION_DISQUALIFIED_INTERVENTION_RAW_SHA256,
        ),
        (
            NEGATIVE_PRIMARY_TRIGGER_SAME_RECEIPT_TWICE_FIXTURE,
            NEGATIVE_PRIMARY_TRIGGER_SAME_RECEIPT_TWICE_RAW_SHA256,
        ),
        (
            NEGATIVE_RATIFICATION_AUTHOR_AS_RATIFIER_FIXTURE,
            NEGATIVE_RATIFICATION_AUTHOR_AS_RATIFIER_RAW_SHA256,
        ),
        (
            NEGATIVE_RATIFICATION_AGENT_EXCEPTION_REJECTED_FIXTURE,
            NEGATIVE_RATIFICATION_AGENT_EXCEPTION_REJECTED_RAW_SHA256,
        ),
        (
            NEGATIVE_RATIFICATION_SUPERSEDED_WITHOUT_DIGEST_FIXTURE,
            NEGATIVE_RATIFICATION_SUPERSEDED_WITHOUT_DIGEST_RAW_SHA256,
        ),
        (
            NEGATIVE_RATIFICATION_SUPERSEDED_CAUSAL_ROLE_FIXTURE,
            NEGATIVE_RATIFICATION_SUPERSEDED_CAUSAL_ROLE_RAW_SHA256,
        ),
        (
            NEGATIVE_INTERVENTION_SCOPE_MISMATCH_FIXTURE,
            NEGATIVE_INTERVENTION_SCOPE_MISMATCH_RAW_SHA256,
        ),
        (
            NEGATIVE_INTERVENTION_UNOBSERVED_MATERIAL_INPUT_FIXTURE,
            NEGATIVE_INTERVENTION_UNOBSERVED_MATERIAL_INPUT_RAW_SHA256,
        ),
        (
            NEGATIVE_INTERVENTION_SINGLE_INPUT_CHANGED_ZERO_FIXTURE,
            NEGATIVE_INTERVENTION_SINGLE_INPUT_CHANGED_ZERO_RAW_SHA256,
        ),
        (
            NEGATIVE_RATIFICATION_UNRECONCILED_OPPOSING_EVIDENCE_FIXTURE,
            NEGATIVE_RATIFICATION_UNRECONCILED_OPPOSING_EVIDENCE_RAW_SHA256,
        ),
        (
            NEGATIVE_RATIFICATION_EMPTY_SUPPORTING_EVIDENCE_FIXTURE,
            NEGATIVE_RATIFICATION_EMPTY_SUPPORTING_EVIDENCE_RAW_SHA256,
        ),
        (
            NEGATIVE_CAUSAL_ROLE_UNKNOWN_FIXTURE,
            NEGATIVE_CAUSAL_ROLE_UNKNOWN_RAW_SHA256,
        ),
        (
            NEGATIVE_ADJUDICATION_STATE_UNKNOWN_FIXTURE,
            NEGATIVE_ADJUDICATION_STATE_UNKNOWN_RAW_SHA256,
        ),
        (VECTOR_SUITE_FIXTURE, VECTOR_SUITE_RAW_SHA256),
    ] {
        assert_eq!(raw_sha256_hex(raw), expected);
    }
}

#[test]
fn positive_causal_hypothesis_fixture_decodes_and_pins_fingerprint() {
    let hyp: CausalHypothesisV1 = decode_and_prove_canonical(CAUSAL_HYPOTHESIS_FIXTURE);
    hyp.validate_shape().unwrap();
    assert_eq!(
        hyp.fingerprint().unwrap().to_hex(),
        CAUSAL_HYPOTHESIS_FINGERPRINT
    );
}

#[test]
fn positive_intervention_support_fixture_reaches_intervention_supported() {
    let hyp: CausalHypothesisV1 = decode_and_prove_canonical(CAUSAL_HYPOTHESIS_FIXTURE);
    let intervention: InterventionSupportV1 =
        decode_and_prove_canonical(INTERVENTION_SUPPORT_FIXTURE);
    assert_eq!(
        intervention.digest().unwrap().to_hex(),
        INTERVENTION_SUPPORT_DIGEST
    );
    assert_eq!(
        derive_intervention_support_level(&hyp, &intervention).unwrap(),
        Ok(SupportLevel::InterventionSupported)
    );
    assert!(ProvenInterventionSupportV1::from_test_derivation(&hyp, intervention).is_ok());
}

#[test]
fn positive_ratification_fixtures_are_admitted() {
    let hyp: CausalHypothesisV1 = decode_and_prove_canonical(CAUSAL_HYPOTHESIS_FIXTURE);
    let intervention: InterventionSupportV1 =
        decode_and_prove_canonical(INTERVENTION_SUPPORT_FIXTURE);

    let contributing: CausalRatificationV1 =
        decode_and_prove_canonical(RATIFICATION_CONTRIBUTING_CAUSE_FIXTURE);
    assert_eq!(
        contributing.digest().unwrap().to_hex(),
        RATIFICATION_CONTRIBUTING_CAUSE_DIGEST
    );
    assert_eq!(
        evaluate_ratification(&contributing, &hyp, Some(&intervention)).unwrap(),
        Ok(())
    );
    assert!(
        AdmittedCausalRatificationV1::from_test_witness(contributing, &hyp, Some(&intervention))
            .is_ok()
    );

    let primary: CausalRatificationV1 =
        decode_and_prove_canonical(RATIFICATION_PRIMARY_TRIGGER_FIXTURE);
    assert_eq!(
        primary.digest().unwrap().to_hex(),
        RATIFICATION_PRIMARY_TRIGGER_DIGEST
    );
    assert_eq!(primary.causal_role, Some(CausalRoleV1::PrimaryTrigger));
    assert!(confirmation_lines_contain_independent_pair(
        &primary.confirmation_lines
    ));
    assert_eq!(
        evaluate_ratification(&primary, &hyp, Some(&intervention)).unwrap(),
        Ok(())
    );
    assert!(
        AdmittedCausalRatificationV1::from_test_witness(primary, &hyp, Some(&intervention)).is_ok()
    );
}

#[test]
fn negative_hypothesis_shape_fixtures_fail_validate_shape() {
    let cause_equals_outcome: CausalHypothesisV1 =
        decode_and_prove_canonical(NEGATIVE_CAUSE_EQUALS_OUTCOME_FIXTURE);
    assert!(cause_equals_outcome.validate_shape().is_err());

    let empty_inventory: CausalHypothesisV1 =
        decode_and_prove_canonical(NEGATIVE_EMPTY_MATERIAL_INPUT_INVENTORY_FIXTURE);
    assert!(empty_inventory.validate_shape().is_err());
}

#[test]
fn negative_intervention_fixtures_fail_the_named_reason() {
    let hyp: CausalHypothesisV1 = decode_and_prove_canonical(CAUSAL_HYPOTHESIS_FIXTURE);

    let cases: &[(&[u8], InterventionUnreachableReasonV1)] = &[
        (
            NEGATIVE_EXPOSURE_AFTER_ONSET_FIXTURE,
            InterventionUnreachableReasonV1::ExposureDoesNotPrecedeAndOverlapOnset,
        ),
        (
            NEGATIVE_COVERAGE_PARTIAL_FIXTURE,
            InterventionUnreachableReasonV1::IncompleteOrStaleCoverage,
        ),
        (
            NEGATIVE_COHORTS_MIXED_FIXTURE,
            InterventionUnreachableReasonV1::MixedCohorts,
        ),
        (
            NEGATIVE_EXECUTION_AMBIGUOUS_FIXTURE,
            InterventionUnreachableReasonV1::AmbiguousExecutionOutcome,
        ),
        (
            NEGATIVE_MATERIAL_INPUTS_INSEPARABLE_FIXTURE,
            InterventionUnreachableReasonV1::MaterialInputsChangedInseparably,
        ),
        (
            NEGATIVE_PREDICTION_AFTER_OBSERVATION_FIXTURE,
            InterventionUnreachableReasonV1::PredictionRecordedAfterObservation,
        ),
        (
            NEGATIVE_INTERVENTION_SCOPE_MISMATCH_FIXTURE,
            InterventionUnreachableReasonV1::ScopeMismatch,
        ),
        (
            NEGATIVE_INTERVENTION_UNOBSERVED_MATERIAL_INPUT_FIXTURE,
            InterventionUnreachableReasonV1::UnobservedMaterialInput,
        ),
    ];
    for (raw, expected_reason) in cases {
        let intervention: InterventionSupportV1 = decode_and_prove_canonical(raw);
        assert_eq!(
            derive_intervention_support_level(&hyp, &intervention).unwrap(),
            Err(vec![*expected_reason]),
            "unexpected reason set for one negative intervention fixture"
        );
    }
}

/// Blocker 4b: an intervention that declares `single_input_changed` but
/// whose own inventory shows zero changed inputs is internally
/// inconsistent and must be rejected at the shape level (not merely a
/// `derive_intervention_support_level` reason).
#[test]
fn negative_single_input_changed_zero_fixture_fails_validate_shape() {
    let intervention: InterventionSupportV1 =
        decode_and_prove_canonical(NEGATIVE_INTERVENTION_SINGLE_INPUT_CHANGED_ZERO_FIXTURE);
    assert_eq!(
        intervention.material_input_separation,
        MaterialInputSeparationV1::SingleInputChanged {}
    );
    assert!(intervention.validate_shape().is_err());
}

#[test]
fn negative_ratification_fixtures_fail_the_named_reason() {
    let cases: &[(&[u8], RatificationBlockedReasonV1)] = &[
        (
            NEGATIVE_RATIFICATION_UNRESOLVED_GAPS_FIXTURE,
            RatificationBlockedReasonV1::UnresolvedGapsPresent,
        ),
        (
            NEGATIVE_RATIFICATION_BELOW_INTERVENTION_SUPPORT_FIXTURE,
            RatificationBlockedReasonV1::PositiveCauseBelowInterventionSupport,
        ),
        (
            NEGATIVE_PRIMARY_TRIGGER_SAME_RECEIPT_TWICE_FIXTURE,
            RatificationBlockedReasonV1::PrimaryTriggerRequiresIndependentSecondConfirmation,
        ),
        (
            NEGATIVE_RATIFICATION_AUTHOR_AS_RATIFIER_FIXTURE,
            RatificationBlockedReasonV1::SeparationOfDutyFailed,
        ),
        (
            NEGATIVE_RATIFICATION_AGENT_EXCEPTION_REJECTED_FIXTURE,
            RatificationBlockedReasonV1::SeparationOfDutyFailed,
        ),
        (
            NEGATIVE_RATIFICATION_SUPERSEDED_CAUSAL_ROLE_FIXTURE,
            RatificationBlockedReasonV1::CausalRoleForbiddenForNonRatifiedConclusion,
        ),
        (
            NEGATIVE_RATIFICATION_UNRECONCILED_OPPOSING_EVIDENCE_FIXTURE,
            RatificationBlockedReasonV1::UnreconciledOpposingEvidencePresent,
        ),
        (
            NEGATIVE_RATIFICATION_EMPTY_SUPPORTING_EVIDENCE_FIXTURE,
            RatificationBlockedReasonV1::SupportingEvidenceRequiredForPositiveCausalRole,
        ),
    ];
    let hyp: CausalHypothesisV1 = decode_and_prove_canonical(CAUSAL_HYPOTHESIS_FIXTURE);
    let intervention: InterventionSupportV1 =
        decode_and_prove_canonical(INTERVENTION_SUPPORT_FIXTURE);
    for (raw, expected_reason) in cases {
        let ratification: CausalRatificationV1 = decode_and_prove_canonical(raw);
        assert_eq!(
            evaluate_ratification(&ratification, &hyp, Some(&intervention)).unwrap(),
            Err(vec![*expected_reason]),
            "unexpected reason set for one negative ratification fixture"
        );
    }
}

#[test]
fn negative_superseded_without_digest_fixture_fails_validate_shape() {
    let ratification: CausalRatificationV1 =
        decode_and_prove_canonical(NEGATIVE_RATIFICATION_SUPERSEDED_WITHOUT_DIGEST_FIXTURE);
    assert_eq!(ratification.conclusion, CausalConclusionV1::Superseded);
    assert!(ratification.supersedes.is_none());
    assert!(ratification.validate_shape().is_err());
}

#[test]
fn negative_unknown_variant_fixtures_fail_at_decode() {
    let role_body = record(NEGATIVE_CAUSAL_ROLE_UNKNOWN_FIXTURE);
    let role: ContractResult<CausalRoleV1> = decode_strict(role_body);
    assert!(role.is_err());

    let adjudication_body = record(NEGATIVE_ADJUDICATION_STATE_UNKNOWN_FIXTURE);
    let adjudication: ContractResult<AdjudicationState> = decode_strict(adjudication_body);
    assert!(adjudication.is_err());
}

/// Test-only aggregate manifest: the raw SHA-256 of every fixture file in
/// this directory plus the derived digests of the four positive
/// artifacts, so the manifest and the fixtures it names cannot silently
/// drift apart.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureRawDigestV1 {
    name: ContractId,
    raw_sha256: Sha256Digest,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CausalVectorSuiteV1 {
    schema_version: u32,
    fixture_authority: String,
    causal_hypothesis_fingerprint: Sha256Digest,
    intervention_support_digest: Sha256Digest,
    causal_ratification_contributing_cause_digest: Sha256Digest,
    causal_ratification_primary_trigger_digest: Sha256Digest,
    fixture_raw_sha256: Vec<FixtureRawDigestV1>,
}

#[test]
#[allow(clippy::too_many_lines)] // one (name, digest) pair per fixture file in the manifest
fn vector_suite_manifest_matches_every_pinned_fixture_digest() {
    let suite: CausalVectorSuiteV1 = decode_and_prove_canonical(VECTOR_SUITE_FIXTURE);
    assert_eq!(suite.schema_version, CAUSAL_SCHEMA_VERSION);
    assert_eq!(
        suite.causal_hypothesis_fingerprint.to_hex(),
        CAUSAL_HYPOTHESIS_FINGERPRINT
    );
    assert_eq!(
        suite.intervention_support_digest.to_hex(),
        INTERVENTION_SUPPORT_DIGEST
    );
    assert_eq!(
        suite.causal_ratification_contributing_cause_digest.to_hex(),
        RATIFICATION_CONTRIBUTING_CAUSE_DIGEST
    );
    assert_eq!(
        suite.causal_ratification_primary_trigger_digest.to_hex(),
        RATIFICATION_PRIMARY_TRIGGER_DIGEST
    );

    let expected: &[(&str, &str)] = &[
        ("causal-hypothesis-v1", CAUSAL_HYPOTHESIS_V1_RAW_SHA256),
        (
            "causal-ratification-contributing-cause-v1",
            CAUSAL_RATIFICATION_CONTRIBUTING_CAUSE_V1_RAW_SHA256,
        ),
        (
            "causal-ratification-primary-trigger-v1",
            CAUSAL_RATIFICATION_PRIMARY_TRIGGER_V1_RAW_SHA256,
        ),
        (
            "intervention-support-v1",
            INTERVENTION_SUPPORT_V1_RAW_SHA256,
        ),
        (
            "negative-adjudication-state-unknown",
            NEGATIVE_ADJUDICATION_STATE_UNKNOWN_RAW_SHA256,
        ),
        (
            "negative-causal-role-unknown",
            NEGATIVE_CAUSAL_ROLE_UNKNOWN_RAW_SHA256,
        ),
        (
            "negative-cause-equals-outcome",
            NEGATIVE_CAUSE_EQUALS_OUTCOME_RAW_SHA256,
        ),
        ("negative-cohorts-mixed", NEGATIVE_COHORTS_MIXED_RAW_SHA256),
        (
            "negative-coverage-partial",
            NEGATIVE_COVERAGE_PARTIAL_RAW_SHA256,
        ),
        (
            "negative-empty-material-input-inventory",
            NEGATIVE_EMPTY_MATERIAL_INPUT_INVENTORY_RAW_SHA256,
        ),
        (
            "negative-execution-ambiguous",
            NEGATIVE_EXECUTION_AMBIGUOUS_RAW_SHA256,
        ),
        (
            "negative-exposure-after-onset",
            NEGATIVE_EXPOSURE_AFTER_ONSET_RAW_SHA256,
        ),
        (
            "negative-intervention-scope-mismatch",
            NEGATIVE_INTERVENTION_SCOPE_MISMATCH_RAW_SHA256,
        ),
        (
            "negative-intervention-single-input-changed-zero",
            NEGATIVE_INTERVENTION_SINGLE_INPUT_CHANGED_ZERO_RAW_SHA256,
        ),
        (
            "negative-intervention-unobserved-material-input",
            NEGATIVE_INTERVENTION_UNOBSERVED_MATERIAL_INPUT_RAW_SHA256,
        ),
        (
            "negative-material-inputs-inseparable",
            NEGATIVE_MATERIAL_INPUTS_INSEPARABLE_RAW_SHA256,
        ),
        (
            "negative-prediction-after-observation",
            NEGATIVE_PREDICTION_AFTER_OBSERVATION_RAW_SHA256,
        ),
        (
            "negative-primary-trigger-same-receipt-twice",
            NEGATIVE_PRIMARY_TRIGGER_SAME_RECEIPT_TWICE_RAW_SHA256,
        ),
        (
            "negative-ratification-agent-exception-rejected",
            NEGATIVE_RATIFICATION_AGENT_EXCEPTION_REJECTED_RAW_SHA256,
        ),
        (
            "negative-ratification-author-as-ratifier",
            NEGATIVE_RATIFICATION_AUTHOR_AS_RATIFIER_RAW_SHA256,
        ),
        (
            "negative-ratification-below-intervention-support",
            NEGATIVE_RATIFICATION_BELOW_INTERVENTION_SUPPORT_RAW_SHA256,
        ),
        (
            "negative-ratification-disqualified-intervention",
            NEGATIVE_RATIFICATION_DISQUALIFIED_INTERVENTION_RAW_SHA256,
        ),
        (
            "negative-ratification-empty-supporting-evidence",
            NEGATIVE_RATIFICATION_EMPTY_SUPPORTING_EVIDENCE_RAW_SHA256,
        ),
        (
            "negative-ratification-superseded-causal-role",
            NEGATIVE_RATIFICATION_SUPERSEDED_CAUSAL_ROLE_RAW_SHA256,
        ),
        (
            "negative-ratification-superseded-without-digest",
            NEGATIVE_RATIFICATION_SUPERSEDED_WITHOUT_DIGEST_RAW_SHA256,
        ),
        (
            "negative-ratification-unreconciled-opposing-evidence",
            NEGATIVE_RATIFICATION_UNRECONCILED_OPPOSING_EVIDENCE_RAW_SHA256,
        ),
        (
            "negative-ratification-unresolved-gaps",
            NEGATIVE_RATIFICATION_UNRESOLVED_GAPS_RAW_SHA256,
        ),
    ];
    assert_eq!(suite.fixture_raw_sha256.len(), expected.len());
    for ((name, raw_sha256), entry) in expected.iter().zip(suite.fixture_raw_sha256.iter()) {
        assert_eq!(entry.name.as_str(), *name);
        assert_eq!(entry.raw_sha256.to_hex(), *raw_sha256);
    }
}

/// Blocker 1: `achieved_support` on a `CausalRatificationV1` is
/// self-asserted and must never be trusted on its own. This fixture's
/// record claims `achieved_support: intervention_supported`, but the
/// `InterventionSupportV1` it cites (`negative-coverage-partial.jsonl`,
/// the cheapest disqualifying mutation — `coverage.completeness:
/// partial`) does not itself re-derive to `intervention_supported`.
/// `evaluate_ratification` must catch this even though `binds_intervention`
/// (digest + scope match) is satisfied.
#[test]
fn disqualified_bound_intervention_blocks_ratification_despite_self_asserted_support() {
    let hyp: CausalHypothesisV1 = decode_and_prove_canonical(CAUSAL_HYPOTHESIS_FIXTURE);
    let disqualified_intervention: InterventionSupportV1 = decode_and_prove_canonical(
        include_bytes!("../../contracts/dynamic-memory/v3/causal/negative-coverage-partial.jsonl"),
    );
    let ratification: CausalRatificationV1 =
        decode_and_prove_canonical(NEGATIVE_RATIFICATION_DISQUALIFIED_INTERVENTION_FIXTURE);

    // The record cites exactly this intervention (digest + scope match);
    // the flaw is that the cited intervention does not qualify, not that
    // the citation is wrong.
    assert!(
        ratification
            .binds_intervention(&disqualified_intervention)
            .unwrap()
    );
    assert_eq!(
        ratification.achieved_support,
        SupportLevel::InterventionSupported
    );
    assert!(matches!(
        derive_intervention_support_level(&hyp, &disqualified_intervention).unwrap(),
        Err(reasons) if reasons == vec![InterventionUnreachableReasonV1::IncompleteOrStaleCoverage]
    ));

    assert_eq!(
        evaluate_ratification(&ratification, &hyp, Some(&disqualified_intervention)).unwrap(),
        Err(vec![
            RatificationBlockedReasonV1::BoundInterventionDoesNotReachInterventionSupported
        ])
    );
}

/// Mutation coverage for the `ratification.conclusion ==
/// CausalConclusionV1::Ratified` conjunct guarding the re-derivation
/// branch in `evaluate_ratification`. Same disqualified-but-correctly-
/// bound intervention as the fixture test above (so `binds_intervention`
/// passes and the `else if` branch is actually reachable), but
/// `conclusion` is `superseded` with a (structurally permitted at this
/// point, forbidden by the later conclusion match) leftover positive
/// `causal_role`. The only admissible reason is
/// `CausalRoleForbiddenForNonRatifiedConclusion`; flipping the `==` to
/// `!=` (or deleting the conjunct) would additionally surface
/// `BoundInterventionDoesNotReachInterventionSupported` here, since the
/// disqualified intervention never derives to `intervention_supported`
/// regardless of `conclusion`. This test fails on that mutant.
#[test]
fn superseded_conclusion_skips_the_intervention_rederivation_branch() {
    let hyp = hypothesis();
    let disqualified_intervention: InterventionSupportV1 = decode_and_prove_canonical(
        include_bytes!("../../contracts/dynamic-memory/v3/causal/negative-coverage-partial.jsonl"),
    );
    let mut ratification = base_ratification(&hyp);
    ratification.conclusion = CausalConclusionV1::Superseded;
    ratification.supersedes = Some(digest(0xde));
    ratification.intervention_support_digest = Some(disqualified_intervention.digest().unwrap());
    // causal_role is left `Some(ContributingCause)` from base_ratification:
    // structurally permitted at the point evaluate_ratification checks
    // the intervention binding (that ordering is exactly what this test
    // pins), forbidden only by the later match on `conclusion`.
    assert!(ratification.causal_role.is_some());
    assert!(
        ratification
            .binds_intervention(&disqualified_intervention)
            .unwrap()
    );

    assert_eq!(
        evaluate_ratification(&ratification, &hyp, Some(&disqualified_intervention)).unwrap(),
        Err(vec![
            RatificationBlockedReasonV1::CausalRoleForbiddenForNonRatifiedConclusion
        ])
    );
}

/// Mutation coverage for the `ratification.causal_role.is_some()`
/// conjunct guarding the re-derivation branch in `evaluate_ratification`
/// (and, incidentally, the first committed exercise of
/// `CausalRoleRequiredForRatifiedConclusion`, which no prior test
/// reached). `conclusion` is `ratified` — so the re-derivation branch's
/// other two conjuncts are satisfied — but `causal_role` is `None`, so a
/// `ratified` record with no causal role is rejected on that ground
/// alone; the bound intervention's own disqualification (partial
/// coverage) must never additionally surface here, since a record with
/// no causal role makes no claim for `derive_intervention_support_level`
/// to re-derive against. Deleting `causal_role.is_some()` (or flipping it
/// to a tautology) would surface `BoundInterventionDoesNotReachInterventionSupported`
/// too, which this exact-match assertion catches.
#[test]
fn causal_role_none_on_ratified_conclusion_skips_the_intervention_rederivation_branch() {
    let hyp = hypothesis();
    let mut disqualified_intervention = base_intervention(&hyp);
    disqualified_intervention.coverage.completeness = CoverageCompletenessV1::Partial;
    let mut ratification = base_ratification(&hyp);
    ratification.causal_role = None;
    ratification.intervention_support_digest = Some(disqualified_intervention.digest().unwrap());
    assert!(
        ratification
            .binds_intervention(&disqualified_intervention)
            .unwrap()
    );
    assert!(
        derive_intervention_support_level(&hyp, &disqualified_intervention)
            .unwrap()
            .is_err()
    );

    assert_eq!(
        evaluate_ratification(&ratification, &hyp, Some(&disqualified_intervention)).unwrap(),
        Err(vec![
            RatificationBlockedReasonV1::CausalRoleRequiredForRatifiedConclusion
        ])
    );
}
