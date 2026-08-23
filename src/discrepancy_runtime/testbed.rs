//! Shared in-crate builders for the discrepancy runtime's unit tests.
//!
//! Test-constructed data only (the same convention as the contract's own
//! `discrepancy_tests.rs`): registry entries here prove structural closure,
//! never active-package membership, and nothing in this file is a frozen
//! fixture.

use std::str::FromStr;

use crate::memory_contracts::canonical::{CanonicalValue, decode_strict, encode_canonical};
use crate::memory_contracts::common::{
    AuthenticatedProjectScopeV1, CanonicalTimestamp, ContractId, RegistryReferenceV1,
    frozen_profile_reference_v1,
};
use crate::memory_contracts::digest::Sha256Digest;
use crate::memory_contracts::discrepancy::{
    ApplicabilityDimensionV1, ApplicabilityDimensionValueV1, CardinalityAlgebraV1,
    ComparatorLineageRegistrationV1, ComparatorLineageV1, DiscrepancyActorV1,
    DiscrepancyEnvelopeV1, DiscrepancyEpisodeFingerprintV1, DiscrepancyEpisodePreimageV1,
    DiscrepancyFamilyPreimageV1, DiscrepancyLifecycleEventV1, DiscrepancySeverityV1,
    DismissalReasonKindV1, DismissalReasonV1, EffectiveIntervalRuleV1, EpisodeClosingRuleV1,
    EpisodeOpeningRuleV1, EpisodePolicyV2, EpisodeWindowingV1, FindingType, LateEvidenceBehaviorV1,
    LifecycleTransitionV1, ModalityCompatibilityRuleV1, OpeningTransitionCandidateV1,
    PolarityRuleV1, RuleChangeBehaviorV1, StructurallyResolvedComparatorLineageV1,
    StructurallyResolvedEpisodePolicyV2, VerificationState, WaiverReasonKindV1, WaiverRecordV1,
};
use crate::memory_contracts::evidence::{AcceptedEventId, SourceFactId};
use crate::memory_contracts::evidence_v2::RegistryHeadBindingV1;
use crate::memory_contracts::genesis::PropositionModalityV1;
use crate::memory_contracts::identity::ResourceUri;
use crate::memory_contracts::registry::{RegistryEntryKind, RegistryEntryV1, RegistryHeadV1};

pub const ENVELOPE_EVENT_KIND: &str = "discrepancy.envelope.accepted";
pub const LIFECYCLE_EVENT_KIND: &str = "discrepancy.lifecycle.accepted";
pub const SCHEMA_VERSION: u32 = 1;

pub fn digest(value: &str) -> Sha256Digest {
    Sha256Digest::from_str(value).unwrap()
}

pub fn timestamp(value: &str) -> CanonicalTimestamp {
    CanonicalTimestamp::parse(value).unwrap()
}

pub fn scope() -> AuthenticatedProjectScopeV1 {
    AuthenticatedProjectScopeV1::from_trusted_context(
        ContractId::new("tenant.runtime").unwrap(),
        ContractId::new("project.runtime").unwrap(),
    )
}

pub fn other_scope() -> AuthenticatedProjectScopeV1 {
    AuthenticatedProjectScopeV1::from_trusted_context(
        ContractId::new("tenant.other").unwrap(),
        ContractId::new("project.other").unwrap(),
    )
}

pub fn registry_head_binding() -> RegistryHeadBindingV1 {
    RegistryHeadBindingV1 {
        head: RegistryHeadV1 {
            activation_id: digest(&"1".repeat(64)),
            package_digest: digest(&"2".repeat(64)),
            activation_policy_digest: digest(&"3".repeat(64)),
        },
        effective_from: timestamp("2026-08-15T04:00:00.000000000Z"),
        effective_until: None,
    }
}

pub fn resource(form: &str, kind: &str, digit: char) -> ResourceUri {
    format!(
        "urn:ostk:{form}:v1:{kind}:sha256:{}",
        digit.to_string().repeat(64)
    )
    .parse()
    .unwrap()
}

pub fn source_fact_id(digit: char) -> SourceFactId {
    SourceFactId::from_digest(digest(&digit.to_string().repeat(64)))
}

pub fn evidence_id(digit: char) -> AcceptedEventId {
    AcceptedEventId::from_digest(digest(&digit.to_string().repeat(64)))
}

pub fn reference(id: &str, digest_hex: &str) -> RegistryReferenceV1 {
    RegistryReferenceV1 {
        entry_id: ContractId::new(id).unwrap(),
        version: 1,
        entry_digest: digest(digest_hex),
    }
}

pub fn comparator_lineage() -> ComparatorLineageV1 {
    ComparatorLineageV1 {
        schema_version: 1,
        comparator_id: ContractId::new("comparator.exact_value_v1").unwrap(),
        comparator_version: 1,
        cardinality: CardinalityAlgebraV1::Functional,
        polarity_rule: PolarityRuleV1::AffirmationNegationConflictOnSameValue,
        modality_compatibility: vec![ModalityCompatibilityRuleV1 {
            left: PropositionModalityV1::Attested,
            right: PropositionModalityV1::Normative,
        }],
        concrete_applicability_required: true,
        effective_interval_rule: EffectiveIntervalRuleV1::OverlapRequired,
        coverage_proof_required: false,
    }
}

pub fn episode_policy() -> EpisodePolicyV2 {
    EpisodePolicyV2 {
        schema_version: 1,
        policy_id: ContractId::new("episode.non_windowed_state_v1").unwrap(),
        version: 1,
        continuity_key_dimension_ids: vec![ContractId::new("runtime_environment").unwrap()],
        windowing: EpisodeWindowingV1::NonWindowed,
        opening_rule: EpisodeOpeningRuleV1::FirstVerifiedIncompatibleObservation,
        allowed_observation_gap_seconds: Some(3_600),
        closing_rule: EpisodeClosingRuleV1::VerifiedCompatibleSupersessionOrScopeExit,
        rule_change_behavior: RuleChangeBehaviorV1::NewFamilyLinkedBySupersession,
        late_evidence_behavior: LateEvidenceBehaviorV1::EffectiveIntervalReplayWithSupersession,
    }
}

pub fn episode_policy_entry() -> RegistryEntryV1 {
    let policy = episode_policy();
    let body_bytes = encode_canonical(&policy).unwrap();
    let body: CanonicalValue = decode_strict(&body_bytes).unwrap();
    RegistryEntryV1 {
        schema_version: 1,
        kind: RegistryEntryKind::EpisodePolicy,
        entry_id: policy.policy_id.clone(),
        version: policy.version,
        entry_schema_id: ContractId::new("registry.episode_policy").unwrap(),
        entry_schema_version: 1,
        body,
        positive_vector_digest: digest(&"a".repeat(64)),
        negative_vector_digest: digest(&"b".repeat(64)),
    }
}

pub fn resolved_episode_policy() -> StructurallyResolvedEpisodePolicyV2 {
    StructurallyResolvedEpisodePolicyV2::from_registry_entry(&episode_policy_entry()).unwrap()
}

pub fn comparator_lineage_entry() -> RegistryEntryV1 {
    let registration = ComparatorLineageRegistrationV1 {
        schema_version: 1,
        lineage: comparator_lineage(),
        required_applicability_dimension_ids: vec![ContractId::new("runtime_environment").unwrap()],
    };
    let body_bytes = encode_canonical(&registration).unwrap();
    let body: CanonicalValue = decode_strict(&body_bytes).unwrap();
    RegistryEntryV1 {
        schema_version: 1,
        kind: RegistryEntryKind::ComparatorLineage,
        entry_id: registration.lineage.comparator_id.clone(),
        version: registration.lineage.comparator_version,
        entry_schema_id: ContractId::new("registry.comparator_lineage").unwrap(),
        entry_schema_version: 1,
        body,
        positive_vector_digest: digest(&"c".repeat(64)),
        negative_vector_digest: digest(&"d".repeat(64)),
    }
}

pub fn resolved_comparator_lineage() -> StructurallyResolvedComparatorLineageV1 {
    StructurallyResolvedComparatorLineageV1::from_registry_entry(&comparator_lineage_entry())
        .unwrap()
}

pub fn applicability() -> Vec<ApplicabilityDimensionV1> {
    vec![
        ApplicabilityDimensionV1 {
            dimension_id: ContractId::new("repository_commit").unwrap(),
            value: ApplicabilityDimensionValueV1::Concrete {
                resource: resource("version", "commit", '3'),
            },
        },
        ApplicabilityDimensionV1 {
            dimension_id: ContractId::new("runtime_environment").unwrap(),
            value: ApplicabilityDimensionValueV1::Concrete {
                resource: resource("entity", "environment", '4'),
            },
        },
    ]
}

/// A shape-valid envelope for `envelope_scope`, bound to the exact resolved
/// episode policy and comparator lineage this module registers, with an
/// opening-transition source fact chosen by `opening_digit` so tests can
/// mint distinct episodes in one family.
pub fn envelope_for_scope(
    envelope_scope: &AuthenticatedProjectScopeV1,
    opening_digit: char,
) -> DiscrepancyEnvelopeV1 {
    let lineage = resolved_comparator_lineage();
    let policy = resolved_episode_policy();
    let lineage_fingerprint = lineage.lineage().fingerprint().unwrap();
    let required_applicability_dimension_ids =
        lineage.required_applicability_dimension_ids().to_vec();
    let continuity_key_dimension_ids = policy.policy().continuity_key_dimension_ids.clone();
    let episode_policy_reference = policy.registry_reference().clone();
    let expectation_policy = reference(
        "policy.database_choice_v1",
        "d0b7d4e7b630ce599389e50948541e21b4aa24d4d030860f6cfcaf7508d49df4",
    );
    let predicate = reference(
        "predicate.database_choice_v1",
        "36660875b3d71595ccb4b5dfbc17c4c0fe546eec0fa4b8da6a63b17fec074586",
    );
    let detector = reference(
        "detector.claim_conflict_v1",
        "8a12f99ff35969845f08f9b64cee7d86fa42dc6165ebc617d950be8960b86111",
    );
    let opening_transition = OpeningTransitionCandidateV1 {
        effective_at: timestamp("2026-08-15T04:05:00.000000000Z"),
        provider_order: 0,
        source_fact_id: source_fact_id(opening_digit),
    };
    let family_fingerprint = DiscrepancyFamilyPreimageV1 {
        schema_version: SCHEMA_VERSION,
        profile: frozen_profile_reference_v1(),
        scope: envelope_scope.clone(),
        finding_type: FindingType::ClaimConflict,
        canonical_subject: resource("entity", "repository", '1'),
        predicate: predicate.clone(),
        comparator_lineage_fingerprint: lineage_fingerprint,
        expectation_policy: expectation_policy.clone(),
        required_applicability_dimension_ids: required_applicability_dimension_ids.clone(),
        applicability: applicability(),
        episode_policy_version: episode_policy_reference.version,
    }
    .fingerprint()
    .unwrap();
    let episode_fingerprint = DiscrepancyEpisodePreimageV1 {
        schema_version: SCHEMA_VERSION,
        family_fingerprint,
        continuity_key: vec![applicability()[1].clone()],
        opening_transition_source_fact_id: opening_transition.source_fact_id,
        episode_policy_version: episode_policy_reference.version,
    }
    .fingerprint()
    .unwrap();
    DiscrepancyEnvelopeV1 {
        schema_version: SCHEMA_VERSION,
        event_kind: ContractId::new(ENVELOPE_EVENT_KIND).unwrap(),
        profile: frozen_profile_reference_v1(),
        scope: envelope_scope.clone(),
        finding_type: FindingType::ClaimConflict,
        severity: DiscrepancySeverityV1::Medium,
        canonical_subject: resource("entity", "repository", '1'),
        predicate,
        comparator_lineage_fingerprint: lineage_fingerprint,
        expectation_policy,
        episode_policy: episode_policy_reference,
        required_applicability_dimension_ids,
        applicability: applicability(),
        continuity_key_dimension_ids,
        family_fingerprint,
        opening_transition,
        episode_fingerprint,
        registry: registry_head_binding(),
        detector,
        extractor: None,
        member_evidence_ids: vec![evidence_id('6'), evidence_id('7')],
        supporting_evidence_ids: vec![evidence_id('8')],
        opposing_evidence_ids: vec![],
        coverage_receipt_ids: vec![],
        implicated_actor_ids: vec![
            ContractId::new("principal.author_a").unwrap(),
            ContractId::new("principal.author_b").unwrap(),
        ],
        initial_verification_state: VerificationState::Candidate,
        detected_at: timestamp("2026-08-15T04:06:00.000000000Z"),
        effective_from: timestamp("2026-08-15T04:05:00.000000000Z"),
        effective_until: None,
    }
}

pub fn envelope() -> DiscrepancyEnvelopeV1 {
    envelope_for_scope(&scope(), '5')
}

pub fn lifecycle_event(
    envelope: &DiscrepancyEnvelopeV1,
    effective_at: &str,
    transition: Option<LifecycleTransitionV1>,
    evidence_digit: char,
) -> DiscrepancyLifecycleEventV1 {
    DiscrepancyLifecycleEventV1 {
        schema_version: SCHEMA_VERSION,
        event_kind: ContractId::new(LIFECYCLE_EVENT_KIND).unwrap(),
        profile: envelope.profile.clone(),
        scope: envelope.scope.clone(),
        episode_fingerprint: envelope.episode_fingerprint,
        effective_at: timestamp(effective_at),
        verification_update: None,
        lifecycle_transition: transition,
        evidence_event_ids: vec![evidence_id(evidence_digit)],
    }
}

pub fn acknowledge_event(
    envelope: &DiscrepancyEnvelopeV1,
    effective_at: &str,
) -> DiscrepancyLifecycleEventV1 {
    lifecycle_event(
        envelope,
        effective_at,
        Some(LifecycleTransitionV1::Acknowledge {
            actor: DiscrepancyActorV1 {
                principal_id: ContractId::new("principal.on_call").unwrap(),
            },
        }),
        '9',
    )
}

pub fn waive_event(
    envelope: &DiscrepancyEnvelopeV1,
    effective_at: &str,
    expiry_at: &str,
) -> DiscrepancyLifecycleEventV1 {
    lifecycle_event(
        envelope,
        effective_at,
        Some(LifecycleTransitionV1::Waive {
            waiver: WaiverRecordV1 {
                actor: DiscrepancyActorV1 {
                    principal_id: ContractId::new("principal.on_call").unwrap(),
                },
                reason_kind: WaiverReasonKindV1::CapacityDeferred,
                rationale: "capacity deferred to next sprint".into(),
                applicability_scope: vec![],
                expiry_at: timestamp(expiry_at),
                review_by: None,
            },
        }),
        'a',
    )
}

pub fn resolve_event(
    envelope: &DiscrepancyEnvelopeV1,
    effective_at: &str,
) -> DiscrepancyLifecycleEventV1 {
    lifecycle_event(
        envelope,
        effective_at,
        Some(LifecycleTransitionV1::Resolve {
            actor: DiscrepancyActorV1 {
                principal_id: ContractId::new("principal.on_call").unwrap(),
            },
            resolution_evidence_ids: vec![evidence_id('b')],
        }),
        'b',
    )
}

pub fn dismiss_event(
    envelope: &DiscrepancyEnvelopeV1,
    effective_at: &str,
    actor_id: &str,
) -> DiscrepancyLifecycleEventV1 {
    lifecycle_event(
        envelope,
        effective_at,
        Some(LifecycleTransitionV1::Dismiss {
            actor: DiscrepancyActorV1 {
                principal_id: ContractId::new(actor_id).unwrap(),
            },
            reason: DismissalReasonV1 {
                kind: DismissalReasonKindV1::NotReproducible,
                rationale: "unable to reproduce after three attempts".into(),
            },
        }),
        'c',
    )
}

/// A distinct episode fingerprint that no envelope in these tests seeds.
pub fn unseeded_episode_fingerprint() -> DiscrepancyEpisodeFingerprintV1 {
    DiscrepancyEpisodeFingerprintV1::from_digest(digest(&"9".repeat(64)))
}

/// Recompute both fingerprints from an envelope's current fields through the
/// PUBLIC preimage types, so negative tests can mutate identity-bearing
/// fields and still present a shape-valid envelope.
pub fn refingerprint(target: &mut DiscrepancyEnvelopeV1) {
    let family = DiscrepancyFamilyPreimageV1 {
        schema_version: SCHEMA_VERSION,
        profile: target.profile.clone(),
        scope: target.scope.clone(),
        finding_type: target.finding_type,
        canonical_subject: target.canonical_subject.clone(),
        predicate: target.predicate.clone(),
        comparator_lineage_fingerprint: target.comparator_lineage_fingerprint,
        expectation_policy: target.expectation_policy.clone(),
        required_applicability_dimension_ids: target.required_applicability_dimension_ids.clone(),
        applicability: target.applicability.clone(),
        episode_policy_version: target.episode_policy.version,
    }
    .fingerprint()
    .unwrap();
    let continuity_key = target
        .continuity_key_dimension_ids
        .iter()
        .filter_map(|id| {
            target
                .applicability
                .iter()
                .find(|dimension| &dimension.dimension_id == id)
                .cloned()
        })
        .collect();
    let episode = DiscrepancyEpisodePreimageV1 {
        schema_version: SCHEMA_VERSION,
        family_fingerprint: family,
        continuity_key,
        opening_transition_source_fact_id: target.opening_transition.source_fact_id,
        episode_policy_version: target.episode_policy.version,
    }
    .fingerprint()
    .unwrap();
    target.family_fingerprint = family;
    target.episode_fingerprint = episode;
}
