use std::{fs, path::Path, str::FromStr};

use sha2::{Digest as _, Sha256};

use super::*;
use crate::memory_contracts::{
    canonical::{CanonicalValue, decode_strict, require_canonical},
    common::frozen_profile_reference_v1,
    generation2::ReservedSlotCarriageV1,
    genesis::SemanticallyClosedGenesisPackage,
    identity::IdentityForm,
    registry::{
        ManifestVerifiedRegistryPackage, RegistryHeadV1, RegistryManifestEntryV1, RegistryPackageV1,
    },
    successor_package::SemanticallyClosedSuccessorPackage,
};

const ENVELOPE_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v3/discrepancy/discrepancy-envelope.jsonl");
const COMPARATOR_LINEAGE_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v3/discrepancy/comparator-lineage.jsonl");
const EPISODE_POLICY_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v3/discrepancy/episode-policy.jsonl");
const LIFECYCLE_ACKNOWLEDGE_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/discrepancy/lifecycle-event-acknowledge.jsonl"
);
const LIFECYCLE_WAIVE_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v3/discrepancy/lifecycle-event-waive.jsonl");
const LIFECYCLE_RESOLVE_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v3/discrepancy/lifecycle-event-resolve.jsonl");
const LIFECYCLE_DISMISS_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v3/discrepancy/lifecycle-event-dismiss.jsonl");
const EPISODE_RELATION_SPLIT_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/discrepancy/episode-relation-superseded-split.jsonl"
);
const EPISODE_RELATION_COMBINED_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/discrepancy/episode-relation-combined-from.jsonl"
);
const VECTOR_SUITE_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v3/discrepancy/vector-suite.jsonl");
// Frozen v1/Stage-4 fixtures, reused read-only here (never re-pinned by
// this workstream) only to prove a comparator-lineage entry appended to
// an otherwise-valid package is rejected by every v1/successor closure.
const GENESIS_REGISTRY_PACKAGE_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v1/genesis-registry-package.jsonl");
const STAGE4_SUCCESSOR_PACKAGE_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v2/stage4-successor/registry-package.jsonl");

const FAMILY_FINGERPRINT: &str = "2a0e121fcd2b26621670f810a213e72d91a4a3084c2314ff7811b105cc9c6374";
const EPISODE_FINGERPRINT: &str =
    "41dc523d985324bbb4c268eb7b0f814547caa8250180274703107487d46e246d";
const ENVELOPE_ID: &str = "91d220c7d6e869f8cdd10b5d6c3b50d8546b69cfd33403abadcaf1d6e1be756b";
const COMPARATOR_LINEAGE_FINGERPRINT: &str =
    "11589b382071ef9df593ef7efe4df898f2ad4ed8e1775a011d4ec3912a5116d2";
const VECTOR_SUITE_DIGEST: &str =
    "e1897e015369b91282401e7e9567f1c7dadbb351e67054869b2deb08798809fd";

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DiscrepancyVectorSuiteV1 {
    schema_version: u32,
    fixture_authority: String,
    envelope_path: String,
    envelope_id: DiscrepancyEnvelopeId,
    family_fingerprint: DiscrepancyFamilyFingerprintV1,
    episode_fingerprint: DiscrepancyEpisodeFingerprintV1,
    comparator_lineage_path: String,
    comparator_lineage_fingerprint: ComparatorLineageFingerprint,
    episode_policy_path: String,
    lifecycle_acknowledge_path: String,
    lifecycle_waive_path: String,
    lifecycle_resolve_path: String,
    lifecycle_dismiss_path: String,
    episode_relation_split_path: String,
    episode_relation_combined_path: String,
    negative_cases: Vec<String>,
}

fn record(artifact: &'static [u8]) -> &'static [u8] {
    let body = artifact
        .strip_suffix(b"\n")
        .expect("contract artifact must have one repository-framing LF");
    assert!(!body.ends_with(b"\n"));
    assert!(!body.contains(&b'\r'));
    body
}

fn digest(value: &str) -> Sha256Digest {
    Sha256Digest::from_str(value).unwrap()
}

fn raw_sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn scope() -> AuthenticatedProjectScopeV1 {
    AuthenticatedProjectScopeV1::from_trusted_context(
        ContractId::new("tenant.fixture").unwrap(),
        ContractId::new("project.fixture").unwrap(),
    )
}

fn registry_binding() -> RegistryHeadBindingV1 {
    RegistryHeadBindingV1 {
        head: RegistryHeadV1 {
            activation_id: digest(
                "5a7263f5c98e75b94e82341d2a7729e9578d4691691b5a8401e1c37a83931261",
            ),
            package_digest: digest(
                "5a931fd5551bec47f83adb019f3e794d1b6a759f4501e7ea26a83076d9518177",
            ),
            activation_policy_digest: digest(
                "6f92f99ff35969845f08f9b64cee7d86fa42dc6165ebc617d950be8960b86968",
            ),
        },
        effective_from: CanonicalTimestamp::parse("2026-08-15T04:00:00.000000000Z").unwrap(),
        effective_until: None,
    }
}

fn reference(id: &str, digest_value: &str) -> RegistryReferenceV1 {
    RegistryReferenceV1 {
        entry_id: ContractId::new(id).unwrap(),
        version: 1,
        entry_digest: digest(digest_value),
    }
}

fn resource(identity_form: IdentityForm, kind: &str, digit: char) -> ResourceUri {
    format!(
        "urn:ostk:{}:v1:{kind}:sha256:{}",
        identity_form.as_str(),
        digit.to_string().repeat(64)
    )
    .parse()
    .unwrap()
}

fn source_fact_id(digit: char) -> SourceFactId {
    SourceFactId::from_digest(digest(&digit.to_string().repeat(64)))
}

fn evidence_id(digit: char) -> AcceptedEventId {
    AcceptedEventId::from_digest(digest(&digit.to_string().repeat(64)))
}

fn comparator_lineage() -> ComparatorLineageV1 {
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

fn episode_policy() -> EpisodePolicyV2 {
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

/// The registry entry that structurally resolves to [`episode_policy`],
/// matching the `connector_entry()` pattern in `evidence_v2.rs`'s tests: a
/// registry entry is test-constructed data, never a byte-frozen fixture
/// file, because it only proves structural closure, not active-package
/// membership.
fn episode_policy_entry() -> RegistryEntryV1 {
    let policy = episode_policy();
    let body_bytes = encode_canonical(&policy).unwrap();
    let body: CanonicalValue = decode_strict(&body_bytes).unwrap();
    RegistryEntryV1 {
        schema_version: 1,
        kind: RegistryEntryKind::EpisodePolicy,
        entry_id: policy.policy_id.clone(),
        version: policy.version,
        entry_schema_id: ContractId::new(EPISODE_POLICY_ENTRY_SCHEMA_ID).unwrap(),
        entry_schema_version: EPISODE_POLICY_SCHEMA_VERSION,
        body,
        positive_vector_digest: digest(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        negative_vector_digest: digest(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ),
    }
}

fn resolved_episode_policy() -> StructurallyResolvedEpisodePolicyV2 {
    StructurallyResolvedEpisodePolicyV2::from_registry_entry(&episode_policy_entry()).unwrap()
}

/// An envelope whose `episode_policy` reference names the exact structurally
/// resolved policy entry (unlike the shared `envelope()` fixture, whose
/// `episode_policy.entry_digest` is a placeholder hex literal never meant to
/// be checked against a resolved policy body).
fn envelope_bound_to_resolved_policy() -> DiscrepancyEnvelopeV1 {
    let mut bound = envelope();
    bound.episode_policy = resolved_episode_policy().registry_reference().clone();
    bound
}

/// The registry entry that structurally resolves to [`comparator_lineage`]
/// plus the registry-declared required-applicability-dimension set, using
/// the same test-constructed-data convention as `episode_policy_entry()`.
fn comparator_lineage_registration_entry() -> RegistryEntryV1 {
    let registration = ComparatorLineageRegistrationV1 {
        schema_version: COMPARATOR_LINEAGE_REGISTRATION_SCHEMA_VERSION,
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
        entry_schema_id: ContractId::new(COMPARATOR_LINEAGE_ENTRY_SCHEMA_ID).unwrap(),
        entry_schema_version: COMPARATOR_LINEAGE_REGISTRATION_SCHEMA_VERSION,
        body,
        positive_vector_digest: digest(
            "cc11cc11cc11cc11cc11cc11cc11cc11cc11cc11cc11cc11cc11cc11cc11cc11",
        ),
        negative_vector_digest: digest(
            "dd11dd11dd11dd11dd11dd11dd11dd11dd11dd11dd11dd11dd11dd11dd11dd11",
        ),
    }
}

fn resolved_comparator_lineage() -> StructurallyResolvedComparatorLineageV1 {
    StructurallyResolvedComparatorLineageV1::from_registry_entry(
        &comparator_lineage_registration_entry(),
    )
    .unwrap()
}

/// Re-sort a package's entries and rebuild its manifest to match, after
/// appending an entry by hand -- the same canonicalization
/// `generation2.rs`'s own test helper performs, duplicated here rather
/// than imported since it is private to that module.
fn canonicalize_package_order(package: &mut RegistryPackageV1) {
    package.entries.sort_by(|left, right| {
        (left.kind.as_str(), left.entry_id.as_str(), left.version).cmp(&(
            right.kind.as_str(),
            right.entry_id.as_str(),
            right.version,
        ))
    });
    package.manifest = package
        .entries
        .iter()
        .map(|entry| RegistryManifestEntryV1 {
            kind: entry.kind,
            entry_id: entry.entry_id.clone(),
            version: entry.version,
            entry_digest: entry.digest().unwrap(),
        })
        .collect();
}

/// Blocker 1 (rebind to the real registry kind): a manifest-verified,
/// canonically ordered, digest-checked `RegistryPackageV1` -- the crate's
/// real registry-package path, not a hand-built loose `RegistryEntryV1`
/// -- can carry a comparator-lineage registration entry, and the
/// `ReservedSlotCarriageV1` it reports resolves into the identical
/// canonical body `StructurallyResolvedComparatorLineageV1` resolves
/// directly from the same raw entry.
#[test]
fn comparator_lineage_registration_is_carriable_through_the_real_registry_package_path() {
    let entry = comparator_lineage_registration_entry();
    let package = RegistryPackageV1 {
        schema_version: 1,
        profile: frozen_profile_reference_v1(),
        entries: vec![entry.clone()],
        manifest: vec![RegistryManifestEntryV1 {
            kind: entry.kind,
            entry_id: entry.entry_id.clone(),
            version: entry.version,
            entry_digest: entry.digest().unwrap(),
        }],
        positive_vector_suite_digest: digest(
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        ),
        negative_vector_suite_digest: digest(
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        ),
    };
    let verified = ManifestVerifiedRegistryPackage::new(package, &frozen_profile_reference_v1())
        .expect(
            "a package carrying only a reserved comparator-lineage entry still manifest-verifies",
        );

    let carriage = ReservedSlotCarriageV1::from_package_entry(
        &verified,
        RegistryEntryKind::ComparatorLineage,
        &entry.entry_id,
        entry.version,
    )
    .expect("the reserved-slot carriage path is the crate's real registry membership proof");
    assert_eq!(carriage.entry_reference().entry_id, entry.entry_id);

    let via_carriage: ComparatorLineageRegistrationV1 =
        decode_strict(carriage.body_bytes()).unwrap();
    let resolved_directly = resolved_comparator_lineage();
    assert_eq!(&via_carriage.lineage, resolved_directly.lineage());
    assert_eq!(
        via_carriage.required_applicability_dimension_ids,
        resolved_directly.required_applicability_dimension_ids()
    );
}

/// Blocker 1 (rejection by every v1/successor closure): the same entry
/// appended to an otherwise-valid, frozen genesis (v1) or Stage-4
/// (successor) package is rejected outright -- `ComparatorLineage` is
/// `is_generation2_only()`, so `decode_entry` (`genesis.rs`) and
/// `decode_successor_entry` (`successor_package.rs`) both refuse it
/// before reaching any comparator-specific logic.
/// `SemanticallyClosedStage4Package::from_successor_package` only
/// narrows an already-closed `SemanticallyClosedSuccessorPackage`, so the
/// successor rejection below forecloses every Stage-4 package too.
#[test]
fn comparator_lineage_entry_is_rejected_by_every_v1_and_successor_closure() {
    let entry = comparator_lineage_registration_entry();

    let mut genesis_package: RegistryPackageV1 =
        decode_strict(record(GENESIS_REGISTRY_PACKAGE_FIXTURE)).unwrap();
    genesis_package.entries.push(entry.clone());
    canonicalize_package_order(&mut genesis_package);
    let genesis_verified =
        ManifestVerifiedRegistryPackage::new(genesis_package, &frozen_profile_reference_v1())
            .unwrap();
    let genesis_error =
        SemanticallyClosedGenesisPackage::from_manifest_verified(genesis_verified).unwrap_err();
    assert!(format!("{genesis_error:?}").contains("generation-2-only"));

    let mut successor_package: RegistryPackageV1 =
        decode_strict(record(STAGE4_SUCCESSOR_PACKAGE_FIXTURE)).unwrap();
    successor_package.entries.push(entry);
    canonicalize_package_order(&mut successor_package);
    let successor_verified =
        ManifestVerifiedRegistryPackage::new(successor_package, &frozen_profile_reference_v1())
            .unwrap();
    let successor_error =
        SemanticallyClosedSuccessorPackage::from_manifest_verified(successor_verified).unwrap_err();
    assert!(format!("{successor_error:?}").contains("generation-2-only"));
}

/// Closeout blocker (PRED-02/APPL-01 registry-path admissibility): mirrors
/// `relation_policy_v2.rs::selector_and_body_identity_are_exact` for
/// `StructurallyResolvedComparatorLineageV1::from_registry_entry`. Each
/// registry-binding conjunct -- kind, entry-schema id, entry-schema
/// version, body identity, body version -- is asserted individually so a
/// caller cannot smuggle a wrong-kind, wrong-schema, or
/// identity/version-mismatched entry past structural resolution. Kills
/// the surviving `||`-to-`&&` mutants at the `entry.kind`/
/// `entry.entry_schema_id`/`entry.entry_schema_version` disjunct and the
/// `!identity_matches || !version_matches` disjunct.
#[test]
fn comparator_lineage_registry_binding_conjuncts_are_exact() {
    let valid = comparator_lineage_registration_entry();

    let mut wrong_kind = valid.clone();
    wrong_kind.kind = RegistryEntryKind::AuthorityRule;
    assert!(StructurallyResolvedComparatorLineageV1::from_registry_entry(&wrong_kind).is_err());

    let mut wrong_schema_id = valid.clone();
    wrong_schema_id.entry_schema_id = ContractId::new("registry.authority_rule").unwrap();
    assert!(
        StructurallyResolvedComparatorLineageV1::from_registry_entry(&wrong_schema_id).is_err()
    );

    let mut wrong_schema_version = valid.clone();
    wrong_schema_version.entry_schema_version = COMPARATOR_LINEAGE_REGISTRATION_SCHEMA_VERSION + 1;
    assert!(
        StructurallyResolvedComparatorLineageV1::from_registry_entry(&wrong_schema_version)
            .is_err()
    );

    let mut wrong_body_identity = valid.clone();
    let mut registration = ComparatorLineageRegistrationV1 {
        schema_version: COMPARATOR_LINEAGE_REGISTRATION_SCHEMA_VERSION,
        lineage: comparator_lineage(),
        required_applicability_dimension_ids: vec![ContractId::new("runtime_environment").unwrap()],
    };
    registration.lineage.comparator_id = ContractId::new("comparator.other_v1").unwrap();
    let body_bytes = encode_canonical(&registration).unwrap();
    wrong_body_identity.body = decode_strict(&body_bytes).unwrap();
    assert!(
        StructurallyResolvedComparatorLineageV1::from_registry_entry(&wrong_body_identity).is_err()
    );

    let mut wrong_body_version = valid;
    let mut registration = ComparatorLineageRegistrationV1 {
        schema_version: COMPARATOR_LINEAGE_REGISTRATION_SCHEMA_VERSION,
        lineage: comparator_lineage(),
        required_applicability_dimension_ids: vec![ContractId::new("runtime_environment").unwrap()],
    };
    registration.lineage.comparator_version += 1;
    let body_bytes = encode_canonical(&registration).unwrap();
    wrong_body_version.body = decode_strict(&body_bytes).unwrap();
    assert!(
        StructurallyResolvedComparatorLineageV1::from_registry_entry(&wrong_body_version).is_err()
    );
}

/// Closeout blocker (PRED-02/APPL-01 registry-path admissibility): the
/// identical conjunct-by-conjunct proof as
/// `comparator_lineage_registry_binding_conjuncts_are_exact`, for
/// `StructurallyResolvedEpisodePolicyV2::from_registry_entry`. Kills the
/// analogous surviving mutants at the `entry.kind`/`entry.entry_schema_id`/
/// `entry.entry_schema_version` disjunct and the
/// `!identity_matches || !version_matches` disjunct at lines 566-579.
#[test]
fn episode_policy_registry_binding_conjuncts_are_exact() {
    let valid = episode_policy_entry();

    let mut wrong_kind = valid.clone();
    wrong_kind.kind = RegistryEntryKind::AuthorityRule;
    assert!(StructurallyResolvedEpisodePolicyV2::from_registry_entry(&wrong_kind).is_err());

    let mut wrong_schema_id = valid.clone();
    wrong_schema_id.entry_schema_id = ContractId::new("registry.authority_rule").unwrap();
    assert!(StructurallyResolvedEpisodePolicyV2::from_registry_entry(&wrong_schema_id).is_err());

    let mut wrong_schema_version = valid.clone();
    wrong_schema_version.entry_schema_version = EPISODE_POLICY_SCHEMA_VERSION + 1;
    assert!(
        StructurallyResolvedEpisodePolicyV2::from_registry_entry(&wrong_schema_version).is_err()
    );

    let mut wrong_body_identity = valid.clone();
    let mut policy = episode_policy();
    policy.policy_id = ContractId::new("episode.other_v1").unwrap();
    let body_bytes = encode_canonical(&policy).unwrap();
    wrong_body_identity.body = decode_strict(&body_bytes).unwrap();
    assert!(
        StructurallyResolvedEpisodePolicyV2::from_registry_entry(&wrong_body_identity).is_err()
    );

    let mut wrong_body_version = valid;
    let mut policy = episode_policy();
    policy.version += 1;
    let body_bytes = encode_canonical(&policy).unwrap();
    wrong_body_version.body = decode_strict(&body_bytes).unwrap();
    assert!(StructurallyResolvedEpisodePolicyV2::from_registry_entry(&wrong_body_version).is_err());
}

/// Recompute `family_fingerprint`/`episode_fingerprint` from an envelope's
/// current fields, using the module's own private preimage computation
/// (visible here as a descendant module) rather than re-deriving the
/// preimage by hand at every call site.
fn refingerprint(envelope: &mut DiscrepancyEnvelopeV1) {
    envelope.family_fingerprint = envelope.compute_family_fingerprint().unwrap();
    envelope.episode_fingerprint = envelope.compute_episode_fingerprint().unwrap();
}

fn applicability() -> Vec<ApplicabilityDimensionV1> {
    vec![
        ApplicabilityDimensionV1 {
            dimension_id: ContractId::new("repository_commit").unwrap(),
            value: ApplicabilityDimensionValueV1::Concrete {
                resource: resource(IdentityForm::Version, "commit", '3'),
            },
        },
        ApplicabilityDimensionV1 {
            dimension_id: ContractId::new("runtime_environment").unwrap(),
            value: ApplicabilityDimensionValueV1::Concrete {
                resource: resource(IdentityForm::Entity, "environment", '4'),
            },
        },
    ]
}

fn envelope() -> DiscrepancyEnvelopeV1 {
    let lineage_fingerprint = comparator_lineage().fingerprint().unwrap();
    let opening_transition = OpeningTransitionCandidateV1 {
        effective_at: CanonicalTimestamp::parse("2026-08-15T04:05:00.000000000Z").unwrap(),
        provider_order: 0,
        source_fact_id: source_fact_id('5'),
    };
    let required_applicability_dimension_ids =
        vec![ContractId::new("runtime_environment").unwrap()];
    let continuity_key_dimension_ids = vec![ContractId::new("runtime_environment").unwrap()];
    let episode_policy = reference(
        "episode.non_windowed_state_v1",
        "7a12f99ff35969845f08f9b64cee7d86fa42dc6165ebc617d950be8960b86999",
    );
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
    let family_fingerprint = DiscrepancyFamilyPreimageV1 {
        schema_version: DISCREPANCY_SCHEMA_VERSION,
        profile: frozen_profile_reference_v1(),
        scope: scope(),
        finding_type: FindingType::ClaimConflict,
        canonical_subject: resource(IdentityForm::Entity, "repository", '1'),
        predicate: predicate.clone(),
        comparator_lineage_fingerprint: lineage_fingerprint,
        expectation_policy: expectation_policy.clone(),
        required_applicability_dimension_ids: required_applicability_dimension_ids.clone(),
        applicability: applicability(),
        episode_policy_version: episode_policy.version,
    }
    .fingerprint()
    .unwrap();
    let episode_fingerprint = DiscrepancyEpisodePreimageV1 {
        schema_version: DISCREPANCY_SCHEMA_VERSION,
        family_fingerprint,
        continuity_key: vec![applicability()[1].clone()],
        opening_transition_source_fact_id: opening_transition.source_fact_id,
        episode_policy_version: episode_policy.version,
    }
    .fingerprint()
    .unwrap();
    DiscrepancyEnvelopeV1 {
        schema_version: DISCREPANCY_SCHEMA_VERSION,
        event_kind: ContractId::new(DISCREPANCY_ENVELOPE_EVENT_KIND).unwrap(),
        profile: frozen_profile_reference_v1(),
        scope: scope(),
        finding_type: FindingType::ClaimConflict,
        severity: DiscrepancySeverityV1::Medium,
        canonical_subject: resource(IdentityForm::Entity, "repository", '1'),
        predicate,
        comparator_lineage_fingerprint: lineage_fingerprint,
        expectation_policy,
        episode_policy,
        required_applicability_dimension_ids,
        applicability: applicability(),
        continuity_key_dimension_ids,
        family_fingerprint,
        opening_transition,
        episode_fingerprint,
        registry: registry_binding(),
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
        detected_at: CanonicalTimestamp::parse("2026-08-15T04:06:00.000000000Z").unwrap(),
        effective_from: CanonicalTimestamp::parse("2026-08-15T04:05:00.000000000Z").unwrap(),
        effective_until: None,
    }
}

fn lifecycle_event(
    episode_fingerprint: DiscrepancyEpisodeFingerprintV1,
    effective_at: &str,
    transition: Option<LifecycleTransitionV1>,
    verification_update: Option<VerificationUpdateV1>,
    evidence_digit: char,
) -> DiscrepancyLifecycleEventV1 {
    DiscrepancyLifecycleEventV1 {
        schema_version: DISCREPANCY_SCHEMA_VERSION,
        event_kind: ContractId::new(DISCREPANCY_LIFECYCLE_EVENT_KIND).unwrap(),
        profile: frozen_profile_reference_v1(),
        scope: scope(),
        episode_fingerprint,
        effective_at: CanonicalTimestamp::parse(effective_at).unwrap(),
        verification_update,
        lifecycle_transition: transition,
        evidence_event_ids: vec![evidence_id(evidence_digit)],
    }
}

fn acknowledge_event(
    episode_fingerprint: DiscrepancyEpisodeFingerprintV1,
) -> DiscrepancyLifecycleEventV1 {
    lifecycle_event(
        episode_fingerprint,
        "2026-08-15T05:00:00.000000000Z",
        Some(LifecycleTransitionV1::Acknowledge {
            actor: DiscrepancyActorV1 {
                principal_id: ContractId::new("principal.on_call").unwrap(),
            },
        }),
        None,
        '9',
    )
}

fn waiver_record(actor_id: &str, expiry_at: &str) -> WaiverRecordV1 {
    WaiverRecordV1 {
        actor: DiscrepancyActorV1 {
            principal_id: ContractId::new(actor_id).unwrap(),
        },
        reason_kind: WaiverReasonKindV1::CapacityDeferred,
        rationale: "capacity deferred to next sprint".into(),
        applicability_scope: vec![],
        expiry_at: CanonicalTimestamp::parse(expiry_at).unwrap(),
        review_by: None,
    }
}

fn waive_event(
    episode_fingerprint: DiscrepancyEpisodeFingerprintV1,
    actor_id: &str,
    expiry_at: &str,
) -> DiscrepancyLifecycleEventV1 {
    lifecycle_event(
        episode_fingerprint,
        "2026-08-15T05:10:00.000000000Z",
        Some(LifecycleTransitionV1::Waive {
            waiver: waiver_record(actor_id, expiry_at),
        }),
        None,
        'a',
    )
}

fn resolve_event(
    episode_fingerprint: DiscrepancyEpisodeFingerprintV1,
) -> DiscrepancyLifecycleEventV1 {
    lifecycle_event(
        episode_fingerprint,
        "2026-08-15T06:00:00.000000000Z",
        Some(LifecycleTransitionV1::Resolve {
            actor: DiscrepancyActorV1 {
                principal_id: ContractId::new("principal.on_call").unwrap(),
            },
            resolution_evidence_ids: vec![evidence_id('b')],
        }),
        None,
        'b',
    )
}

fn dismiss_event(
    episode_fingerprint: DiscrepancyEpisodeFingerprintV1,
    actor_id: &str,
) -> DiscrepancyLifecycleEventV1 {
    lifecycle_event(
        episode_fingerprint,
        "2026-08-15T05:30:00.000000000Z",
        Some(LifecycleTransitionV1::Dismiss {
            actor: DiscrepancyActorV1 {
                principal_id: ContractId::new(actor_id).unwrap(),
            },
            reason: DismissalReasonV1 {
                kind: DismissalReasonKindV1::NotReproducible,
                rationale: "unable to reproduce after three attempts".into(),
            },
        }),
        None,
        'c',
    )
}

fn episode_relation_split(
    old_episode: DiscrepancyEpisodeFingerprintV1,
    new_episode: DiscrepancyEpisodeFingerprintV1,
    family_fingerprint: DiscrepancyFamilyFingerprintV1,
) -> DiscrepancyEpisodeRelationV1 {
    DiscrepancyEpisodeRelationV1 {
        schema_version: DISCREPANCY_SCHEMA_VERSION,
        profile: frozen_profile_reference_v1(),
        scope: scope(),
        family_fingerprint,
        kind: EpisodeRelationKindV1::Superseded,
        from_episodes: vec![old_episode],
        to_episode: new_episode,
    }
}

fn episode_relation_combined(
    first: DiscrepancyEpisodeFingerprintV1,
    second: DiscrepancyEpisodeFingerprintV1,
    combined: DiscrepancyEpisodeFingerprintV1,
    family_fingerprint: DiscrepancyFamilyFingerprintV1,
) -> DiscrepancyEpisodeRelationV1 {
    let mut from_episodes = vec![first, second];
    from_episodes.sort();
    DiscrepancyEpisodeRelationV1 {
        schema_version: DISCREPANCY_SCHEMA_VERSION,
        profile: frozen_profile_reference_v1(),
        scope: scope(),
        family_fingerprint,
        kind: EpisodeRelationKindV1::CombinedFrom,
        from_episodes,
        to_episode: combined,
    }
}

fn negative_cases() -> Vec<String> {
    [
        "applicability_duplicate_or_unsorted",
        "comparator_lineage_entry_rejected_by_every_v1_and_successor_closure",
        "comparator_lineage_fingerprint_diverges_from_registry",
        "comparator_lineage_requires_concrete_applicability_for_required_dimensions",
        "comparator_lineage_requires_coverage_receipt_when_coverage_proof_required",
        "comparator_lineage_version_bump_changes_lineage_fingerprint",
        "continuity_key_dimension_missing_from_applicability",
        "dismiss_missing_or_empty_rationale",
        "dismiss_or_waiver_rationale_of_only_zero_width_spaces_is_rejected",
        "envelope_comparator_lineage_required_applicability_dimension_ids_diverge_from_registry",
        "envelope_continuity_key_diverges_from_registered_episode_policy",
        "envelope_episode_fingerprint_mismatch",
        "envelope_episode_policy_reference_diverges_from_registry_entry_digest",
        "envelope_family_fingerprint_mismatch",
        "episode_relation_cross_family_is_rejected",
        "episode_relation_foreign_scope_is_rejected",
        "implicated_actor_cannot_dismiss_own_finding",
        "implicated_actor_cannot_resolve_own_finding",
        "lifecycle_event_scope_or_profile_diverges_from_envelope",
        "lifecycle_event_targets_wrong_episode",
        "lifecycle_event_with_no_transition_or_verification_update",
        "physical_append_fields_absent",
        "possibly_continues_rejected_within_the_allowed_observation_gap",
        "receipt_order_independent_opening_transition",
        "repeated_waiver_drift_is_never_verified",
        "required_applicability_dimension_omitted_is_not_any",
        "resolve_requires_nonempty_evidence",
        "self_implicated_verification_refutation_violates_auth_03",
        "self_implicated_waiver_violates_separation_of_duty",
        "superseded_lifecycle_state_reachable_via_episode_relation",
        "unattributed_verification_update_is_not_representable",
        "unknown_finding_type",
        "verified_promotion_requires_nonempty_evidence",
        "waiver_expiry_at_or_before_the_events_effective_at_is_rejected",
        "waiver_missing_actor_or_expiry",
        "waiver_scope_out_of_scope_or_alien_dimension_is_rejected",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn vector_suite() -> DiscrepancyVectorSuiteV1 {
    let envelope = envelope();
    DiscrepancyVectorSuiteV1 {
        schema_version: 1,
        fixture_authority: "none; structural canonical fixture bytes never prove active registry, actor, or evidence authority".into(),
        envelope_path: "discrepancy-envelope.jsonl".into(),
        envelope_id: envelope.envelope_id().unwrap(),
        family_fingerprint: envelope.family_fingerprint,
        episode_fingerprint: envelope.episode_fingerprint,
        comparator_lineage_path: "comparator-lineage.jsonl".into(),
        comparator_lineage_fingerprint: comparator_lineage().fingerprint().unwrap(),
        episode_policy_path: "episode-policy.jsonl".into(),
        lifecycle_acknowledge_path: "lifecycle-event-acknowledge.jsonl".into(),
        lifecycle_waive_path: "lifecycle-event-waive.jsonl".into(),
        lifecycle_resolve_path: "lifecycle-event-resolve.jsonl".into(),
        lifecycle_dismiss_path: "lifecycle-event-dismiss.jsonl".into(),
        episode_relation_split_path: "episode-relation-superseded-split.jsonl".into(),
        episode_relation_combined_path: "episode-relation-combined-from.jsonl".into(),
        negative_cases: negative_cases(),
    }
}

#[test]
#[allow(clippy::too_many_lines)] // one exhaustive fixture/digest cross-check, not test logic sprawl
fn hard_coded_fixtures_match_canonical_vectors() {
    for bytes in [
        ENVELOPE_FIXTURE,
        COMPARATOR_LINEAGE_FIXTURE,
        EPISODE_POLICY_FIXTURE,
        LIFECYCLE_ACKNOWLEDGE_FIXTURE,
        LIFECYCLE_WAIVE_FIXTURE,
        LIFECYCLE_RESOLVE_FIXTURE,
        LIFECYCLE_DISMISS_FIXTURE,
        EPISODE_RELATION_SPLIT_FIXTURE,
        EPISODE_RELATION_COMBINED_FIXTURE,
        VECTOR_SUITE_FIXTURE,
    ] {
        require_canonical(record(bytes)).unwrap();
    }

    let expected_envelope = envelope();
    assert_eq!(
        encode_canonical(&expected_envelope).unwrap(),
        record(ENVELOPE_FIXTURE)
    );
    let decoded_envelope: DiscrepancyEnvelopeV1 = decode_strict(record(ENVELOPE_FIXTURE)).unwrap();
    decoded_envelope.validate_shape().unwrap();
    assert_eq!(decoded_envelope, expected_envelope);

    let expected_lineage = comparator_lineage();
    assert_eq!(
        encode_canonical(&expected_lineage).unwrap(),
        record(COMPARATOR_LINEAGE_FIXTURE)
    );

    let expected_policy = episode_policy();
    assert_eq!(
        encode_canonical(&expected_policy).unwrap(),
        record(EPISODE_POLICY_FIXTURE)
    );

    let episode_fingerprint = expected_envelope.episode_fingerprint;
    let acknowledge = acknowledge_event(episode_fingerprint);
    assert_eq!(
        encode_canonical(&acknowledge).unwrap(),
        record(LIFECYCLE_ACKNOWLEDGE_FIXTURE)
    );
    let waive = waive_event(
        episode_fingerprint,
        "principal.on_call",
        "2026-09-15T00:00:00.000000000Z",
    );
    assert_eq!(
        encode_canonical(&waive).unwrap(),
        record(LIFECYCLE_WAIVE_FIXTURE)
    );
    let resolve = resolve_event(episode_fingerprint);
    assert_eq!(
        encode_canonical(&resolve).unwrap(),
        record(LIFECYCLE_RESOLVE_FIXTURE)
    );
    let dismiss = dismiss_event(episode_fingerprint, "principal.on_call");
    assert_eq!(
        encode_canonical(&dismiss).unwrap(),
        record(LIFECYCLE_DISMISS_FIXTURE)
    );

    let other_episode = DiscrepancyEpisodeFingerprintV1::from_digest(digest(
        "1111111111111111111111111111111111111111111111111111111111111111",
    ));
    let combined_episode = DiscrepancyEpisodeFingerprintV1::from_digest(digest(
        "2222222222222222222222222222222222222222222222222222222222222222",
    ));
    let split_relation = episode_relation_split(
        episode_fingerprint,
        other_episode,
        expected_envelope.family_fingerprint,
    );
    split_relation.validate_shape().unwrap();
    assert_eq!(
        encode_canonical(&split_relation).unwrap(),
        record(EPISODE_RELATION_SPLIT_FIXTURE)
    );
    let combined_relation = episode_relation_combined(
        episode_fingerprint,
        other_episode,
        combined_episode,
        expected_envelope.family_fingerprint,
    );
    combined_relation.validate_shape().unwrap();
    assert_eq!(
        encode_canonical(&combined_relation).unwrap(),
        record(EPISODE_RELATION_COMBINED_FIXTURE)
    );

    let expected_suite = vector_suite();
    assert_eq!(
        encode_canonical(&expected_suite).unwrap(),
        record(VECTOR_SUITE_FIXTURE)
    );
    let suite: DiscrepancyVectorSuiteV1 = decode_strict(record(VECTOR_SUITE_FIXTURE)).unwrap();
    assert_eq!(suite, expected_suite);
    assert!(strictly_sorted(&suite.negative_cases));
    assert!(suite.fixture_authority.starts_with("none;"));

    assert_eq!(
        expected_envelope.family_fingerprint.digest(),
        digest(FAMILY_FINGERPRINT)
    );
    assert_eq!(
        expected_envelope.episode_fingerprint.digest(),
        digest(EPISODE_FINGERPRINT)
    );
    assert_eq!(
        expected_envelope.envelope_id().unwrap().digest(),
        digest(ENVELOPE_ID)
    );
    assert_eq!(
        expected_lineage.fingerprint().unwrap().digest(),
        digest(COMPARATOR_LINEAGE_FINGERPRINT)
    );
    assert_eq!(
        domain_separated_digest(
            super::super::digest::DigestDomain::TestVectorManifest,
            record(VECTOR_SUITE_FIXTURE)
        ),
        digest(VECTOR_SUITE_DIGEST)
    );
}

#[test]
fn lifecycle_and_verification_never_define_episode_identity() {
    let first = envelope();
    let mut second = envelope();
    second.severity = DiscrepancySeverityV1::Critical;
    second.detected_at = CanonicalTimestamp::parse("2026-08-15T09:00:00.000000000Z").unwrap();
    second.initial_verification_state = VerificationState::Verified;
    assert_eq!(first.family_fingerprint, second.family_fingerprint);
    assert_eq!(first.episode_fingerprint, second.episode_fingerprint);

    let episode_fingerprint = first.episode_fingerprint;
    let acknowledged = project_discrepancy_episode(
        &first,
        &[acknowledge_event(episode_fingerprint)],
        &[],
        &CanonicalTimestamp::parse("2026-08-15T05:01:00.000000000Z").unwrap(),
    )
    .unwrap();
    let untouched = project_discrepancy_episode(
        &first,
        &[],
        &[],
        &CanonicalTimestamp::parse("2026-08-15T05:01:00.000000000Z").unwrap(),
    )
    .unwrap();
    assert_eq!(
        acknowledged.episode_fingerprint,
        untouched.episode_fingerprint
    );
    assert_ne!(acknowledged.lifecycle_state, untouched.lifecycle_state);
}

#[test]
fn late_evidence_that_only_appends_keeps_the_same_episode() {
    let mut later = envelope();
    later.detected_at = CanonicalTimestamp::parse("2026-08-16T00:00:00.000000000Z").unwrap();
    later.supporting_evidence_ids = vec![evidence_id('8'), evidence_id('9')];
    assert_eq!(envelope().episode_fingerprint, later.episode_fingerprint);
    later.validate_shape().unwrap();
}

#[test]
fn late_evidence_that_changes_the_opening_transition_creates_a_replacement_episode() {
    let original = envelope();
    let mut earlier_evidence = envelope();
    earlier_evidence.opening_transition = OpeningTransitionCandidateV1 {
        effective_at: CanonicalTimestamp::parse("2026-08-15T04:00:00.000000000Z").unwrap(),
        provider_order: 0,
        source_fact_id: source_fact_id('1'),
    };
    earlier_evidence.episode_fingerprint = DiscrepancyEpisodePreimageV1 {
        schema_version: DISCREPANCY_SCHEMA_VERSION,
        family_fingerprint: earlier_evidence.family_fingerprint,
        continuity_key: vec![applicability()[1].clone()],
        opening_transition_source_fact_id: earlier_evidence.opening_transition.source_fact_id,
        episode_policy_version: earlier_evidence.episode_policy.version,
    }
    .fingerprint()
    .unwrap();
    earlier_evidence.validate_shape().unwrap();

    assert_eq!(
        original.family_fingerprint,
        earlier_evidence.family_fingerprint
    );
    assert_ne!(
        original.episode_fingerprint,
        earlier_evidence.episode_fingerprint
    );

    // Replay of the union of candidates always selects the earlier one,
    // matching the replacement episode's opening transition.
    let candidates = [
        original.opening_transition.clone(),
        earlier_evidence.opening_transition.clone(),
    ];
    let winner = select_opening_transition(&candidates).unwrap();
    assert_eq!(winner, &earlier_evidence.opening_transition);

    let replacement = episode_relation_split(
        original.episode_fingerprint,
        earlier_evidence.episode_fingerprint,
        original.family_fingerprint,
    );
    replacement.validate_shape().unwrap();

    // "Old marked superseded, retained" (doc lines 1353-1356): the OLD
    // side's projection is `Superseded` once the relation is supplied,
    // and the NEW side's is not -- neither episode's own fingerprint
    // changes because of the relation (retention without erasure; the
    // relation is an append-only sibling record, never a rewrite).
    let eval_time = CanonicalTimestamp::parse("2026-08-16T00:00:00.000000000Z").unwrap();
    let old_side = project_discrepancy_episode(
        &original,
        &[],
        std::slice::from_ref(&replacement),
        &eval_time,
    )
    .unwrap();
    assert_eq!(old_side.lifecycle_state, LifecycleState::Superseded);
    assert_eq!(old_side.episode_fingerprint, original.episode_fingerprint);

    let new_side = project_discrepancy_episode(
        &earlier_evidence,
        &[],
        std::slice::from_ref(&replacement),
        &eval_time,
    )
    .unwrap();
    assert_ne!(new_side.lifecycle_state, LifecycleState::Superseded);
    assert_eq!(
        new_side.episode_fingerprint,
        earlier_evidence.episode_fingerprint
    );

    // An episode with no relation naming it at all is never superseded --
    // `Superseded` is unreachable except through an explicit relation.
    let unrelated = project_discrepancy_episode(&original, &[], &[], &eval_time).unwrap();
    assert_ne!(unrelated.lifecycle_state, LifecycleState::Superseded);
}

#[test]
fn late_evidence_that_combines_two_episodes_records_combined_from() {
    let first = envelope();
    let mut second_source = envelope();
    second_source.opening_transition.source_fact_id = source_fact_id('2');
    second_source.episode_fingerprint = DiscrepancyEpisodePreimageV1 {
        schema_version: DISCREPANCY_SCHEMA_VERSION,
        family_fingerprint: second_source.family_fingerprint,
        continuity_key: vec![applicability()[1].clone()],
        opening_transition_source_fact_id: second_source.opening_transition.source_fact_id,
        episode_policy_version: second_source.episode_policy.version,
    }
    .fingerprint()
    .unwrap();
    assert_ne!(first.episode_fingerprint, second_source.episode_fingerprint);
    assert_eq!(first.family_fingerprint, second_source.family_fingerprint);

    let combined = DiscrepancyEpisodeFingerprintV1::from_digest(digest(
        "3333333333333333333333333333333333333333333333333333333333333333",
    ));
    let relation = episode_relation_combined(
        first.episode_fingerprint,
        second_source.episode_fingerprint,
        combined,
        first.family_fingerprint,
    );
    relation.validate_shape().unwrap();
    assert_eq!(relation.kind, EpisodeRelationKindV1::CombinedFrom);
    assert_eq!(relation.from_episodes.len(), 2);

    // Doc:1353-1356 ("replay ... marks the earlier projections
    // superseded, retaining explicit combined_from ... relations")
    // applies to the combine case exactly as it does to the split case:
    // BOTH sources project `Superseded` once the relation is supplied,
    // retained (not erased) -- the same continuous incompatible interval
    // must not surface three times (once per source, once for the
    // combined episode).
    let eval_time = CanonicalTimestamp::parse("2026-08-16T00:00:00.000000000Z").unwrap();
    let first_projection =
        project_discrepancy_episode(&first, &[], std::slice::from_ref(&relation), &eval_time)
            .unwrap();
    assert_eq!(first_projection.lifecycle_state, LifecycleState::Superseded);
    assert_eq!(
        first_projection.episode_fingerprint,
        first.episode_fingerprint
    );

    let second_projection = project_discrepancy_episode(
        &second_source,
        &[],
        std::slice::from_ref(&relation),
        &eval_time,
    )
    .unwrap();
    assert_eq!(
        second_projection.lifecycle_state,
        LifecycleState::Superseded
    );
    assert_eq!(
        second_projection.episode_fingerprint,
        second_source.episode_fingerprint
    );

    let mut single_source = relation;
    single_source.from_episodes.truncate(1);
    assert!(single_source.validate_shape().is_err());
}

#[test]
fn recurrence_after_resolved_interval_opens_a_new_episode_in_the_same_family() {
    let original = envelope();
    let episode_fingerprint = original.episode_fingerprint;
    let resolved = project_discrepancy_episode(
        &original,
        &[resolve_event(episode_fingerprint)],
        &[],
        &CanonicalTimestamp::parse("2026-08-15T06:01:00.000000000Z").unwrap(),
    )
    .unwrap();
    assert_eq!(resolved.lifecycle_state, LifecycleState::Resolved);

    let mut recurrence = envelope();
    recurrence.opening_transition.source_fact_id = source_fact_id('4');
    recurrence.detected_at = CanonicalTimestamp::parse("2026-09-01T00:00:00.000000000Z").unwrap();
    recurrence.effective_from =
        CanonicalTimestamp::parse("2026-09-01T00:00:00.000000000Z").unwrap();
    recurrence.episode_fingerprint = DiscrepancyEpisodePreimageV1 {
        schema_version: DISCREPANCY_SCHEMA_VERSION,
        family_fingerprint: recurrence.family_fingerprint,
        continuity_key: vec![applicability()[1].clone()],
        opening_transition_source_fact_id: recurrence.opening_transition.source_fact_id,
        episode_policy_version: recurrence.episode_policy.version,
    }
    .fingerprint()
    .unwrap();
    recurrence.validate_shape().unwrap();

    assert_eq!(original.family_fingerprint, recurrence.family_fingerprint);
    assert_ne!(original.episode_fingerprint, recurrence.episode_fingerprint);
}

#[test]
fn observation_gap_within_the_allowed_bound_is_bridged() {
    // `episode_policy()`'s `allowed_observation_gap_seconds` is
    // `Some(3_600)`; a 30-minute gap is within that bound.
    let outcome = classify_observation_gap(
        &episode_policy(),
        &CanonicalTimestamp::parse("2026-08-15T06:00:00.000000000Z").unwrap(),
        &CanonicalTimestamp::parse("2026-08-15T06:30:00.000000000Z").unwrap(),
    )
    .unwrap();
    assert_eq!(outcome, ObservationGapOutcomeV1::Bridged);
}

#[test]
fn observation_gap_with_no_allowed_bound_never_bridges() {
    // Doc lines 1338-1341 / the field's own doc comment: `None` means no
    // observation gap may ever be bridged, no matter how short.
    let mut never_bridges = episode_policy();
    never_bridges.allowed_observation_gap_seconds = None;
    let outcome = classify_observation_gap(
        &never_bridges,
        &CanonicalTimestamp::parse("2026-08-15T06:00:00.000000000Z").unwrap(),
        &CanonicalTimestamp::parse("2026-08-15T06:00:01.000000000Z").unwrap(),
    )
    .unwrap();
    assert_eq!(outcome, ObservationGapOutcomeV1::EpisodeEnded);
}

#[test]
fn observation_gap_exactly_at_the_bound_is_bridged_one_second_over_is_not() {
    // Pins the `<=` (not `<`) boundary: a mutation flipping the operator
    // would change the outcome at exactly the registered bound but agree
    // everywhere else, so only a boundary-exact vector can kill it.
    let policy = episode_policy(); // allowed_observation_gap_seconds = Some(3_600)
    let prior = CanonicalTimestamp::parse("2026-08-15T06:00:00.000000000Z").unwrap();
    let at_bound = CanonicalTimestamp::parse("2026-08-15T07:00:00.000000000Z").unwrap(); // +3600s
    let one_second_over = CanonicalTimestamp::parse("2026-08-15T07:00:01.000000000Z").unwrap(); // +3601s
    assert_eq!(
        classify_observation_gap(&policy, &prior, &at_bound).unwrap(),
        ObservationGapOutcomeV1::Bridged
    );
    assert_eq!(
        classify_observation_gap(&policy, &prior, &one_second_over).unwrap(),
        ObservationGapOutcomeV1::EpisodeEnded
    );
}

#[test]
fn observation_gap_requires_strictly_increasing_timestamps() {
    let policy = episode_policy();
    let earlier = CanonicalTimestamp::parse("2026-08-15T06:00:00.000000000Z").unwrap();
    let same_instant = earlier.clone();
    assert!(classify_observation_gap(&policy, &earlier, &same_instant).is_err());
    let before = CanonicalTimestamp::parse("2026-08-15T05:59:59.000000000Z").unwrap();
    assert!(classify_observation_gap(&policy, &earlier, &before).is_err());
}

#[test]
fn validate_possibly_continues_gap_does_not_reject_other_relation_kinds() {
    // `validate_possibly_continues_gap`'s rejection is specific to
    // `PossiblyContinues`; a `Superseded` (or any other kind) relation
    // must pass regardless of the gap outcome -- otherwise a mutation
    // that dropped the `kind == PossiblyContinues` conjunct (rejecting
    // every kind under a `Bridged` gap) would go undetected.
    let envelope = envelope();
    let new_episode = DiscrepancyEpisodeFingerprintV1::from_digest(digest(
        "9999999999999999999999999999999999999999999999999999999999999999",
    ));
    let relation = episode_relation_split(
        envelope.episode_fingerprint,
        new_episode,
        envelope.family_fingerprint,
    );
    assert_eq!(relation.kind, EpisodeRelationKindV1::Superseded);
    validate_possibly_continues_gap(&relation, ObservationGapOutcomeV1::Bridged).unwrap();
}

#[test]
fn long_gap_ends_the_prior_occurrence_and_links_a_new_episode_by_possibly_continues() {
    let mut stale = envelope();
    stale.effective_until =
        Some(CanonicalTimestamp::parse("2026-08-15T06:00:00.000000000Z").unwrap());
    stale.validate_shape().unwrap();

    let mut resumed = envelope();
    resumed.opening_transition.source_fact_id = source_fact_id('9');
    resumed.effective_from = CanonicalTimestamp::parse("2026-08-20T00:00:00.000000000Z").unwrap();
    resumed.episode_fingerprint = DiscrepancyEpisodePreimageV1 {
        schema_version: DISCREPANCY_SCHEMA_VERSION,
        family_fingerprint: resumed.family_fingerprint,
        continuity_key: vec![applicability()[1].clone()],
        opening_transition_source_fact_id: resumed.opening_transition.source_fact_id,
        episode_policy_version: resumed.episode_policy.version,
    }
    .fingerprint()
    .unwrap();
    resumed.validate_shape().unwrap();

    // Multi-day gap, far beyond the registered one-hour bound.
    let gap_outcome = classify_observation_gap(
        &episode_policy(),
        stale.effective_until.as_ref().unwrap(),
        &resumed.effective_from,
    )
    .unwrap();
    assert_eq!(gap_outcome, ObservationGapOutcomeV1::EpisodeEnded);

    let relation = DiscrepancyEpisodeRelationV1 {
        schema_version: DISCREPANCY_SCHEMA_VERSION,
        profile: frozen_profile_reference_v1(),
        scope: scope(),
        family_fingerprint: stale.family_fingerprint,
        kind: EpisodeRelationKindV1::PossiblyContinues,
        from_episodes: vec![stale.episode_fingerprint],
        to_episode: resumed.episode_fingerprint,
    };
    validate_possibly_continues_gap(&relation, gap_outcome).unwrap();

    // The prior occurrence becomes observation-indeterminate: already
    // representable via `VerificationUpdateV1` (no new type needed),
    // reached through the same replay every other verification-state
    // change goes through.
    let indeterminate_event = lifecycle_event(
        stale.episode_fingerprint,
        "2026-08-16T00:00:00.000000000Z",
        None,
        Some(VerificationUpdateV1 {
            actor: DiscrepancyActorV1 {
                principal_id: ContractId::new("principal.on_call").unwrap(),
            },
            state: VerificationState::Indeterminate,
            evidence_event_ids: vec![],
        }),
        'd',
    );
    let projected = project_discrepancy_episode(
        &stale,
        &[indeterminate_event],
        &[],
        &CanonicalTimestamp::parse("2026-08-16T00:00:01.000000000Z").unwrap(),
    )
    .unwrap();
    assert_eq!(
        projected.verification_state,
        VerificationState::Indeterminate
    );
}

#[test]
fn possibly_continues_is_rejected_within_the_allowed_observation_gap() {
    let bridged = classify_observation_gap(
        &episode_policy(),
        &CanonicalTimestamp::parse("2026-08-15T06:00:00.000000000Z").unwrap(),
        &CanonicalTimestamp::parse("2026-08-15T06:30:00.000000000Z").unwrap(),
    )
    .unwrap();
    assert_eq!(bridged, ObservationGapOutcomeV1::Bridged);

    let stale = envelope();
    let resumed_fingerprint = DiscrepancyEpisodeFingerprintV1::from_digest(digest(
        "6666666666666666666666666666666666666666666666666666666666666666",
    ));
    let relation = DiscrepancyEpisodeRelationV1 {
        schema_version: DISCREPANCY_SCHEMA_VERSION,
        profile: frozen_profile_reference_v1(),
        scope: scope(),
        family_fingerprint: stale.family_fingerprint,
        kind: EpisodeRelationKindV1::PossiblyContinues,
        from_episodes: vec![stale.episode_fingerprint],
        to_episode: resumed_fingerprint,
    };
    relation.validate_shape().unwrap();
    assert!(validate_possibly_continues_gap(&relation, bridged).is_err());
}

#[test]
fn waiver_does_not_split_or_erase_the_interval_and_expiry_reopens_the_same_episode() {
    let original_interval = envelope();
    let envelope = envelope();
    let episode_fingerprint = envelope.episode_fingerprint;
    let events = [waive_event(
        episode_fingerprint,
        "principal.on_call",
        "2026-08-20T00:00:00.000000000Z",
    )];

    let before_expiry = project_discrepancy_episode(
        &envelope,
        &events,
        &[],
        &CanonicalTimestamp::parse("2026-08-16T00:00:00.000000000Z").unwrap(),
    )
    .unwrap();
    assert_eq!(before_expiry.lifecycle_state, LifecycleState::Waived);
    assert!(before_expiry.active_waiver.is_some());

    let after_expiry = project_discrepancy_episode(
        &envelope,
        &events,
        &[],
        &CanonicalTimestamp::parse("2026-08-21T00:00:00.000000000Z").unwrap(),
    )
    .unwrap();
    assert_eq!(after_expiry.lifecycle_state, LifecycleState::Open);
    // Surfacing keeps the waiver context even after expiry reopens the episode.
    assert!(after_expiry.active_waiver.is_some());
    assert_eq!(
        before_expiry.episode_fingerprint,
        after_expiry.episode_fingerprint
    );
    assert_eq!(envelope.effective_from, original_interval.effective_from);
    assert_eq!(envelope.effective_until, original_interval.effective_until);
}

#[test]
fn superseded_dominates_a_waiver_expiry_reopen() {
    // A replaced episode is frozen: supersession must win even when an
    // expired waiver would otherwise have reopened it to `Open`.
    let envelope = envelope();
    let new_episode = DiscrepancyEpisodeFingerprintV1::from_digest(digest(
        "5555555555555555555555555555555555555555555555555555555555555555",
    ));
    let relation = episode_relation_split(
        envelope.episode_fingerprint,
        new_episode,
        envelope.family_fingerprint,
    );
    let events = [waive_event(
        envelope.episode_fingerprint,
        "principal.on_call",
        "2026-08-20T00:00:00.000000000Z",
    )];
    let after_expiry = project_discrepancy_episode(
        &envelope,
        &events,
        &[relation],
        &CanonicalTimestamp::parse("2026-08-21T00:00:00.000000000Z").unwrap(),
    )
    .unwrap();
    assert_eq!(after_expiry.lifecycle_state, LifecycleState::Superseded);
}

#[test]
fn episode_relation_with_foreign_scope_is_rejected() {
    // A relation minted with only the public episode fingerprints must
    // not suppress an envelope in a DIFFERENT tenant/project scope --
    // matching `lifecycle_event_scope_or_profile_diverges_from_envelope`'s
    // identical guarantee for lifecycle events.
    let envelope = envelope();
    let new_episode = DiscrepancyEpisodeFingerprintV1::from_digest(digest(
        "9999999999999999999999999999999999999999999999999999999999999999",
    ));
    let mut relation = episode_relation_split(
        envelope.episode_fingerprint,
        new_episode,
        envelope.family_fingerprint,
    );
    relation.scope = AuthenticatedProjectScopeV1::from_trusted_context(
        ContractId::new("tenant.attacker").unwrap(),
        ContractId::new("project.attacker").unwrap(),
    );
    relation.validate_shape().unwrap();
    let eval_time = CanonicalTimestamp::parse("2026-08-16T00:00:00.000000000Z").unwrap();
    assert!(project_discrepancy_episode(&envelope, &[], &[relation], &eval_time).is_err());
}

#[test]
fn episode_relation_with_foreign_profile_is_rejected() {
    // Same guarantee as the foreign-scope case, isolated to the
    // `profile` conjunct alone (scope and family left matching): the
    // relation-binding check is `scope != .. || profile != .. || family
    // != ..`, and a mutation that dropped only the `profile` disjunct
    // would otherwise go undetected by the foreign-scope/foreign-family
    // tests, which each vary a different field.
    let envelope = envelope();
    let new_episode = DiscrepancyEpisodeFingerprintV1::from_digest(digest(
        "9999999999999999999999999999999999999999999999999999999999999999",
    ));
    let mut relation = episode_relation_split(
        envelope.episode_fingerprint,
        new_episode,
        envelope.family_fingerprint,
    );
    // `ProfileReferenceV1::validate` only checks `profile_id` against the
    // one fixed compiled-in profile, so a divergent `profile_digest`
    // (same `profile_id`) still passes `validate_shape` -- exactly the
    // divergence a real cross-profile relation would carry.
    relation.profile.profile_digest =
        digest("1234123412341234123412341234123412341234123412341234123412341234");
    relation.validate_shape().unwrap();
    assert_ne!(relation.profile, envelope.profile);
    let eval_time = CanonicalTimestamp::parse("2026-08-16T00:00:00.000000000Z").unwrap();
    assert!(project_discrepancy_episode(&envelope, &[], &[relation], &eval_time).is_err());
}

#[test]
fn possibly_continues_naming_this_episode_does_not_supersede_it() {
    // The `is_superseded` producer fires only for `Superseded` and
    // `CombinedFrom` -- a `PossiblyContinues` relation naming this
    // envelope's episode as a source must leave it `Open` (or whatever
    // the events alone project), never `Superseded`. Without this test,
    // a mutation widening the `matches!` to admit every relation kind
    // (or narrowing it to drop `CombinedFrom`) would go undetected by
    // the split/combine positive vectors, which only ever supply the
    // kind they mean to test.
    let stale = envelope();
    let resumed_fingerprint = DiscrepancyEpisodeFingerprintV1::from_digest(digest(
        "9999999999999999999999999999999999999999999999999999999999999999",
    ));
    let relation = DiscrepancyEpisodeRelationV1 {
        schema_version: DISCREPANCY_SCHEMA_VERSION,
        profile: frozen_profile_reference_v1(),
        scope: scope(),
        family_fingerprint: stale.family_fingerprint,
        kind: EpisodeRelationKindV1::PossiblyContinues,
        from_episodes: vec![stale.episode_fingerprint],
        to_episode: resumed_fingerprint,
    };
    relation.validate_shape().unwrap();
    let eval_time = CanonicalTimestamp::parse("2026-08-16T00:00:00.000000000Z").unwrap();
    let projection = project_discrepancy_episode(&stale, &[], &[relation], &eval_time).unwrap();
    assert_ne!(projection.lifecycle_state, LifecycleState::Superseded);
}

#[test]
fn episode_relation_naming_a_different_family_is_rejected() {
    // A `superseded` relation whose declared `family_fingerprint`
    // diverges from the envelope's own real family must not suppress it
    // -- knowledge of the public episode fingerprint alone is not proof
    // the replacement belongs to the same discrepancy family.
    let envelope = envelope();
    let new_episode = DiscrepancyEpisodeFingerprintV1::from_digest(digest(
        "9999999999999999999999999999999999999999999999999999999999999999",
    ));
    let mut relation = episode_relation_split(
        envelope.episode_fingerprint,
        new_episode,
        envelope.family_fingerprint,
    );
    relation.family_fingerprint = DiscrepancyFamilyFingerprintV1::from_digest(digest(
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    ));
    relation.validate_shape().unwrap();
    let eval_time = CanonicalTimestamp::parse("2026-08-16T00:00:00.000000000Z").unwrap();
    assert!(project_discrepancy_episode(&envelope, &[], &[relation], &eval_time).is_err());
}

#[test]
fn unrelated_episode_relation_in_the_pool_is_ignored_without_scope_or_family_checks() {
    // A relations pool naming OTHER episodes entirely (never this
    // envelope's fingerprint, as source or target) must not be rejected
    // merely for existing in the same slice -- only relations that
    // actually name this envelope are scope/profile/family-checked.
    let envelope = envelope();
    let unrelated_a = DiscrepancyEpisodeFingerprintV1::from_digest(digest(
        "9999999999999999999999999999999999999999999999999999999999999999",
    ));
    let unrelated_b = DiscrepancyEpisodeFingerprintV1::from_digest(digest(
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    ));
    let mut unrelated_relation = episode_relation_split(
        unrelated_a,
        unrelated_b,
        DiscrepancyFamilyFingerprintV1::from_digest(digest(
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        )),
    );
    unrelated_relation.scope = AuthenticatedProjectScopeV1::from_trusted_context(
        ContractId::new("tenant.attacker").unwrap(),
        ContractId::new("project.attacker").unwrap(),
    );
    unrelated_relation.validate_shape().unwrap();
    let eval_time = CanonicalTimestamp::parse("2026-08-16T00:00:00.000000000Z").unwrap();
    let projection =
        project_discrepancy_episode(&envelope, &[], &[unrelated_relation], &eval_time).unwrap();
    assert_ne!(projection.lifecycle_state, LifecycleState::Superseded);
}

#[test]
fn a_later_resolution_never_drops_an_earlier_resolutions_cited_evidence() {
    // DISC-03: "prior finding and resolution history remains immutable";
    // "reopening ... does not clear prior resolution evidence."
    let envelope = envelope();
    let first_resolve = resolve_event(envelope.episode_fingerprint); // cites evidence_id('b') at 06:00
    let second_resolve = lifecycle_event(
        envelope.episode_fingerprint,
        "2026-08-15T08:00:00.000000000Z",
        Some(LifecycleTransitionV1::Resolve {
            actor: DiscrepancyActorV1 {
                principal_id: ContractId::new("principal.on_call").unwrap(),
            },
            resolution_evidence_ids: vec![evidence_id('d')],
        }),
        None,
        'd',
    );
    // A third re-resolve that cites one already-seen id plus a new one:
    // proves accumulation dedups rather than blindly appending.
    let third_resolve = lifecycle_event(
        envelope.episode_fingerprint,
        "2026-08-15T10:00:00.000000000Z",
        Some(LifecycleTransitionV1::Resolve {
            actor: DiscrepancyActorV1 {
                principal_id: ContractId::new("principal.on_call").unwrap(),
            },
            resolution_evidence_ids: vec![evidence_id('b'), evidence_id('f')],
        }),
        None,
        'e',
    );
    let expected = vec![evidence_id('b'), evidence_id('d'), evidence_id('f')];

    let forward = project_discrepancy_episode(
        &envelope,
        &[
            first_resolve.clone(),
            second_resolve.clone(),
            third_resolve.clone(),
        ],
        &[],
        &CanonicalTimestamp::parse("2026-08-15T11:00:00.000000000Z").unwrap(),
    )
    .unwrap();
    assert_eq!(forward.lifecycle_state, LifecycleState::Resolved);
    assert_eq!(forward.resolution_evidence_ids, expected);

    // Order-independent: replaying in a different input order yields the
    // identical accumulated, sorted, deduplicated set (REPLAY-01).
    let reordered = project_discrepancy_episode(
        &envelope,
        &[third_resolve, first_resolve, second_resolve],
        &[],
        &CanonicalTimestamp::parse("2026-08-15T11:00:00.000000000Z").unwrap(),
    )
    .unwrap();
    assert_eq!(reordered.resolution_evidence_ids, expected);
}

#[test]
fn rule_change_creates_a_new_family_linked_by_supersession() {
    let original = envelope();
    let mut new_comparator = comparator_lineage();
    new_comparator.comparator_version += 1;
    let mut changed = envelope();
    changed.comparator_lineage_fingerprint = new_comparator.fingerprint().unwrap();
    changed.family_fingerprint = DiscrepancyFamilyPreimageV1 {
        schema_version: DISCREPANCY_SCHEMA_VERSION,
        profile: changed.profile.clone(),
        scope: changed.scope.clone(),
        finding_type: changed.finding_type,
        canonical_subject: changed.canonical_subject.clone(),
        predicate: changed.predicate.clone(),
        comparator_lineage_fingerprint: changed.comparator_lineage_fingerprint,
        expectation_policy: changed.expectation_policy.clone(),
        required_applicability_dimension_ids: changed.required_applicability_dimension_ids.clone(),
        applicability: changed.applicability.clone(),
        episode_policy_version: changed.episode_policy.version,
    }
    .fingerprint()
    .unwrap();
    changed.episode_fingerprint = DiscrepancyEpisodePreimageV1 {
        schema_version: DISCREPANCY_SCHEMA_VERSION,
        family_fingerprint: changed.family_fingerprint,
        continuity_key: vec![applicability()[1].clone()],
        opening_transition_source_fact_id: changed.opening_transition.source_fact_id,
        episode_policy_version: changed.episode_policy.version,
    }
    .fingerprint()
    .unwrap();
    changed.validate_shape().unwrap();

    assert_ne!(original.family_fingerprint, changed.family_fingerprint);
    assert_eq!(
        episode_policy().rule_change_behavior,
        RuleChangeBehaviorV1::NewFamilyLinkedBySupersession
    );
}

#[test]
fn detector_upgrade_under_the_same_contract_appends_a_derivation_to_the_same_family() {
    let original = envelope();
    let mut upgraded = envelope();
    upgraded.detector = reference(
        "detector.claim_conflict_v1",
        "9a12f99ff35969845f08f9b64cee7d86fa42dc6165ebc617d950be8960b86222",
    );
    upgraded.validate_shape().unwrap();
    assert_eq!(original.family_fingerprint, upgraded.family_fingerprint);
    assert_eq!(original.episode_fingerprint, upgraded.episode_fingerprint);
}

#[test]
fn an_unrelated_concurrent_finding_shares_no_family_or_episode_identity_with_an_active_breach() {
    let breach = envelope();
    // A concurrent, unrelated finding shares no family/episode identity with
    // the active breach: it cannot split it merely by effective-time overlap.
    let mut unrelated = envelope();
    unrelated.finding_type = FindingType::RuntimeNonconformance {
        subtype: RuntimeNonconformanceSubtypeV1::SloBreach,
    };
    unrelated.family_fingerprint = DiscrepancyFamilyPreimageV1 {
        schema_version: DISCREPANCY_SCHEMA_VERSION,
        profile: unrelated.profile.clone(),
        scope: unrelated.scope.clone(),
        finding_type: unrelated.finding_type,
        canonical_subject: unrelated.canonical_subject.clone(),
        predicate: unrelated.predicate.clone(),
        comparator_lineage_fingerprint: unrelated.comparator_lineage_fingerprint,
        expectation_policy: unrelated.expectation_policy.clone(),
        required_applicability_dimension_ids: unrelated
            .required_applicability_dimension_ids
            .clone(),
        applicability: unrelated.applicability.clone(),
        episode_policy_version: unrelated.episode_policy.version,
    }
    .fingerprint()
    .unwrap();
    unrelated.episode_fingerprint = DiscrepancyEpisodePreimageV1 {
        schema_version: DISCREPANCY_SCHEMA_VERSION,
        family_fingerprint: unrelated.family_fingerprint,
        continuity_key: vec![applicability()[1].clone()],
        opening_transition_source_fact_id: unrelated.opening_transition.source_fact_id,
        episode_policy_version: unrelated.episode_policy.version,
    }
    .fingerprint()
    .unwrap();
    unrelated.validate_shape().unwrap();
    assert_ne!(breach.family_fingerprint, unrelated.family_fingerprint);
    assert_ne!(breach.episode_fingerprint, unrelated.episode_fingerprint);
}

#[test]
fn deployment_during_active_breach_does_not_split_it() {
    // slo_breach's registered applicability set carries no revision/commit
    // dimension -- only `runtime_environment` -- so a redeploy (which
    // changes the deployed commit, never the runtime environment) cannot
    // appear anywhere in the family/episode preimage: there is no field for
    // it to change. Two independently constructed preimages for the same
    // ongoing breach, one representing pre-deploy and one post-deploy, are
    // identical.
    let slo_breach_predicate = reference(
        "predicate.latency_slo_v1",
        "9a12f99ff35969845f08f9b64cee7d86fa42dc6165ebc617d950be8960b86333",
    );
    let slo_breach_expectation = reference(
        "policy.latency_slo_v1",
        "9a12f99ff35969845f08f9b64cee7d86fa42dc6165ebc617d950be8960b86444",
    );
    let pre_deploy = DiscrepancyFamilyPreimageV1 {
        schema_version: DISCREPANCY_SCHEMA_VERSION,
        profile: frozen_profile_reference_v1(),
        scope: scope(),
        finding_type: FindingType::RuntimeNonconformance {
            subtype: RuntimeNonconformanceSubtypeV1::SloBreach,
        },
        canonical_subject: resource(IdentityForm::Entity, "service", '2'),
        predicate: slo_breach_predicate.clone(),
        comparator_lineage_fingerprint: comparator_lineage().fingerprint().unwrap(),
        expectation_policy: slo_breach_expectation.clone(),
        required_applicability_dimension_ids: vec![ContractId::new("runtime_environment").unwrap()],
        applicability: vec![applicability()[1].clone()],
        episode_policy_version: episode_policy().version,
    }
    .fingerprint()
    .unwrap();
    let post_deploy = DiscrepancyFamilyPreimageV1 {
        schema_version: DISCREPANCY_SCHEMA_VERSION,
        profile: frozen_profile_reference_v1(),
        scope: scope(),
        finding_type: FindingType::RuntimeNonconformance {
            subtype: RuntimeNonconformanceSubtypeV1::SloBreach,
        },
        canonical_subject: resource(IdentityForm::Entity, "service", '2'),
        predicate: slo_breach_predicate,
        comparator_lineage_fingerprint: comparator_lineage().fingerprint().unwrap(),
        expectation_policy: slo_breach_expectation,
        required_applicability_dimension_ids: vec![ContractId::new("runtime_environment").unwrap()],
        applicability: vec![applicability()[1].clone()],
        episode_policy_version: episode_policy().version,
    }
    .fingerprint()
    .unwrap();
    assert_eq!(pre_deploy, post_deploy);

    // Contrast: `claim_conflict`'s applicability legitimately DOES bind
    // `repository_commit`, so changing only that dimension does mint a new
    // family -- proving the invariance above is a real consequence of
    // slo_breach's applicability set, not the fingerprint ignoring
    // applicability altogether.
    let original = envelope();
    let mut revision_bound_applicability = applicability();
    revision_bound_applicability[0] = ApplicabilityDimensionV1 {
        dimension_id: ContractId::new("repository_commit").unwrap(),
        value: ApplicabilityDimensionValueV1::Concrete {
            resource: resource(IdentityForm::Version, "commit", '9'),
        },
    };
    let redeployed_family_fingerprint = DiscrepancyFamilyPreimageV1 {
        schema_version: DISCREPANCY_SCHEMA_VERSION,
        profile: original.profile.clone(),
        scope: original.scope.clone(),
        finding_type: original.finding_type,
        canonical_subject: original.canonical_subject.clone(),
        predicate: original.predicate.clone(),
        comparator_lineage_fingerprint: original.comparator_lineage_fingerprint,
        expectation_policy: original.expectation_policy.clone(),
        required_applicability_dimension_ids: original.required_applicability_dimension_ids.clone(),
        applicability: revision_bound_applicability,
        episode_policy_version: original.episode_policy.version,
    }
    .fingerprint()
    .unwrap();
    assert_ne!(original.family_fingerprint, redeployed_family_fingerprint);
}

#[test]
fn non_windowed_policy_opens_on_first_incompatible_and_closes_only_on_verified_resolution() {
    let policy = episode_policy();
    assert_eq!(policy.windowing, EpisodeWindowingV1::NonWindowed);
    assert_eq!(
        policy.opening_rule,
        EpisodeOpeningRuleV1::FirstVerifiedIncompatibleObservation
    );
    assert_eq!(
        policy.closing_rule,
        EpisodeClosingRuleV1::VerifiedCompatibleSupersessionOrScopeExit
    );
    let envelope = envelope();
    let untouched = project_discrepancy_episode(
        &envelope,
        &[],
        &[],
        &CanonicalTimestamp::parse("2026-08-15T04:06:00.000000000Z").unwrap(),
    )
    .unwrap();
    assert_eq!(untouched.lifecycle_state, LifecycleState::Open);
}

#[test]
fn opening_transition_selection_is_receipt_order_independent() {
    let earliest = OpeningTransitionCandidateV1 {
        effective_at: CanonicalTimestamp::parse("2026-08-15T04:00:00.000000000Z").unwrap(),
        provider_order: 5,
        source_fact_id: source_fact_id('1'),
    };
    let middle = OpeningTransitionCandidateV1 {
        effective_at: CanonicalTimestamp::parse("2026-08-15T04:05:00.000000000Z").unwrap(),
        provider_order: 0,
        source_fact_id: source_fact_id('2'),
    };
    let tie_break_by_provider_order = OpeningTransitionCandidateV1 {
        effective_at: middle.effective_at.clone(),
        provider_order: 1,
        source_fact_id: source_fact_id('3'),
    };
    let candidates = [
        earliest.clone(),
        middle.clone(),
        tie_break_by_provider_order.clone(),
    ];
    let forward = select_opening_transition(&candidates).unwrap().clone();
    let reversed: Vec<_> = candidates.iter().rev().cloned().collect();
    let backward = select_opening_transition(&reversed).unwrap().clone();
    assert_eq!(forward, backward);
    assert_eq!(forward, earliest);

    // With effective_at tied, provider_order breaks the tie -- never receipt
    // position (`middle` is passed after `tie_break_by_provider_order` here).
    let tie_candidates = [tie_break_by_provider_order, middle.clone()];
    assert_eq!(select_opening_transition(&tie_candidates).unwrap(), &middle);

    assert!(select_opening_transition(&[]).is_err());
}

#[test]
fn family_fingerprint_omits_lifecycle_and_receipt_fields() {
    let preimage_bytes = encode_canonical(&DiscrepancyFamilyPreimageV1 {
        schema_version: DISCREPANCY_SCHEMA_VERSION,
        profile: frozen_profile_reference_v1(),
        scope: scope(),
        finding_type: FindingType::ClaimConflict,
        canonical_subject: resource(IdentityForm::Entity, "repository", '1'),
        predicate: reference(
            "predicate.database_choice_v1",
            "36660875b3d71595ccb4b5dfbc17c4c0fe546eec0fa4b8da6a63b17fec074586",
        ),
        comparator_lineage_fingerprint: comparator_lineage().fingerprint().unwrap(),
        expectation_policy: reference(
            "policy.database_choice_v1",
            "d0b7d4e7b630ce599389e50948541e21b4aa24d4d030860f6cfcaf7508d49df4",
        ),
        required_applicability_dimension_ids: vec![ContractId::new("runtime_environment").unwrap()],
        applicability: applicability(),
        episode_policy_version: 1,
    })
    .unwrap();
    let text = std::str::from_utf8(&preimage_bytes).unwrap();
    for forbidden in [
        "\"receipt_order\"",
        "\"lifecycle_state\"",
        "\"verification_state\"",
        "\"append_position\"",
        "\"epoch_id\"",
        "\"shard\"",
    ] {
        assert!(!text.contains(forbidden), "forbidden field {forbidden}");
    }
}

#[test]
fn physical_append_and_lifecycle_fields_are_absent_from_the_lifecycle_event() {
    let acknowledge = acknowledge_event(envelope().episode_fingerprint);
    let canonical = encode_canonical(&acknowledge).unwrap();
    let text = std::str::from_utf8(&canonical).unwrap();
    for forbidden in [
        "\"accepted_at\"",
        "\"append_position\"",
        "\"epoch_id\"",
        "\"shard\"",
        "\"committed_offset\"",
    ] {
        assert!(!text.contains(forbidden), "forbidden field {forbidden}");
    }

    let mut value: serde_json::Value = serde_json::from_slice(&canonical).unwrap();
    value.as_object_mut().unwrap().insert(
        "accepted_at".into(),
        serde_json::Value::String("2026-08-15T05:06:00.000000000Z".into()),
    );
    assert!(
        decode_strict::<DiscrepancyLifecycleEventV1>(&serde_json::to_vec(&value).unwrap()).is_err()
    );
}

#[test]
fn dismiss_requires_nonempty_rationale() {
    let mut dismiss = dismiss_event(envelope().episode_fingerprint, "principal.on_call");
    if let Some(LifecycleTransitionV1::Dismiss { reason, .. }) = &mut dismiss.lifecycle_transition {
        reason.rationale = "   ".into();
    }
    assert!(dismiss.validate_shape().is_err());
}

#[test]
fn dismiss_rationale_of_only_zero_width_spaces_is_rejected() {
    // `str::trim` alone treats U+200B ZERO WIDTH SPACE as non-whitespace,
    // so a rationale of only zero-width characters would otherwise pass
    // the non-empty check in form while carrying no visible content.
    let mut dismiss = dismiss_event(envelope().episode_fingerprint, "principal.on_call");
    if let Some(LifecycleTransitionV1::Dismiss { reason, .. }) = &mut dismiss.lifecycle_transition {
        reason.rationale = "\u{200B}\u{200B}\u{200B}".into();
    }
    assert!(dismiss.validate_shape().is_err());
}

#[test]
fn waiver_rationale_of_only_zero_width_spaces_is_rejected() {
    let mut waiver = waiver_record("principal.on_call", "2026-09-15T00:00:00.000000000Z");
    waiver.rationale = "\u{200B}".into();
    assert!(waiver.validate_shape().is_err());
}

#[test]
fn rationale_mixing_zero_width_and_visible_content_still_passes() {
    // The zero-width filter must not reject ordinary rationale text that
    // merely happens to contain a zero-width character (e.g. copy-pasted
    // from a rich-text source); only rationale that is ENTIRELY
    // invisible once whitespace and zero-width characters are stripped
    // is blank.
    assert!(!is_blank_rationale("capacity\u{200B} deferred"));
}

#[test]
fn waiver_expiry_at_or_before_the_events_effective_at_is_rejected() {
    // DISC-05 ("a waiver is durable policy"): a waiver that expires
    // before or exactly when it takes effect never had effect.
    let envelope = envelope();
    let backdated = waive_event(
        envelope.episode_fingerprint,
        "principal.on_call",
        "2026-08-15T05:10:00.000000000Z", // == the event's own effective_at
    );
    assert!(authorize_lifecycle_transition(&envelope, &backdated).is_err());
}

#[test]
fn duplicate_byte_identical_lifecycle_events_are_applied_once() {
    // REPLAY-01's order-independence guarantee is weaker than it should
    // be if it holds for reordering but not repetition: an
    // at-least-once delivery retry that appends the same event twice
    // must not be double-counted or double-applied.
    let envelope = envelope();
    let acknowledge = acknowledge_event(envelope.episode_fingerprint);
    let eval_time = CanonicalTimestamp::parse("2026-08-15T05:01:00.000000000Z").unwrap();
    let once = project_discrepancy_episode(
        &envelope,
        std::slice::from_ref(&acknowledge),
        &[],
        &eval_time,
    )
    .unwrap();
    let duplicated = project_discrepancy_episode(
        &envelope,
        &[acknowledge.clone(), acknowledge],
        &[],
        &eval_time,
    )
    .unwrap();
    assert_eq!(duplicated.applied_event_count, once.applied_event_count);
    assert_eq!(duplicated.applied_event_count, 1);
}

#[test]
fn resolve_requires_nonempty_evidence() {
    let mut resolve = resolve_event(envelope().episode_fingerprint);
    if let Some(LifecycleTransitionV1::Resolve {
        resolution_evidence_ids,
        ..
    }) = &mut resolve.lifecycle_transition
    {
        resolution_evidence_ids.clear();
    }
    assert!(resolve.validate_shape().is_err());
}

#[test]
fn lifecycle_event_requires_a_transition_or_verification_update() {
    let mut empty = acknowledge_event(envelope().episode_fingerprint);
    empty.lifecycle_transition = None;
    empty.verification_update = None;
    assert!(empty.validate_shape().is_err());

    let mut only_verification = empty;
    only_verification.verification_update = Some(VerificationUpdateV1 {
        actor: DiscrepancyActorV1 {
            principal_id: ContractId::new("principal.on_call").unwrap(),
        },
        state: VerificationState::Verified,
        evidence_event_ids: vec![evidence_id('b')],
    });
    assert!(only_verification.validate_shape().is_ok());
}

#[test]
fn lifecycle_event_must_target_the_envelope_episode() {
    let envelope = envelope();
    let wrong_episode = DiscrepancyEpisodeFingerprintV1::from_digest(digest(
        "4444444444444444444444444444444444444444444444444444444444444444",
    ));
    let event = acknowledge_event(wrong_episode);
    assert!(authorize_lifecycle_transition(&envelope, &event).is_err());
}

#[test]
fn lifecycle_event_scope_must_match_the_envelope_scope() {
    let envelope = envelope();
    let mut foreign_tenant = acknowledge_event(envelope.episode_fingerprint);
    foreign_tenant.scope = AuthenticatedProjectScopeV1::from_trusted_context(
        ContractId::new("tenant.attacker").unwrap(),
        ContractId::new("project.attacker").unwrap(),
    );
    // The episode fingerprint is a public identifier, not a secret:
    // knowing it must not be sufficient to authorize a cross-tenant
    // transition merely because the fingerprint field matches.
    assert!(authorize_lifecycle_transition(&envelope, &foreign_tenant).is_err());

    let mut foreign_profile = acknowledge_event(envelope.episode_fingerprint);
    foreign_profile.profile.profile_digest =
        digest("9999999999999999999999999999999999999999999999999999999999999999");
    assert!(authorize_lifecycle_transition(&envelope, &foreign_profile).is_err());
}

#[test]
fn auth_03_rejects_self_implicated_dismiss() {
    let envelope = envelope();
    let self_implicated = dismiss_event(envelope.episode_fingerprint, "principal.author_a");
    assert!(authorize_lifecycle_transition(&envelope, &self_implicated).is_err());

    let independent = dismiss_event(envelope.episode_fingerprint, "principal.on_call");
    authorize_lifecycle_transition(&envelope, &independent).unwrap();
}

#[test]
fn auth_03_rejects_self_implicated_resolve() {
    let envelope = envelope();
    let self_implicated = lifecycle_event(
        envelope.episode_fingerprint,
        "2026-08-15T06:00:00.000000000Z",
        Some(LifecycleTransitionV1::Resolve {
            actor: DiscrepancyActorV1 {
                principal_id: ContractId::new("principal.author_a").unwrap(),
            },
            resolution_evidence_ids: vec![evidence_id('b')],
        }),
        None,
        'b',
    );
    assert!(authorize_lifecycle_transition(&envelope, &self_implicated).is_err());

    let independent = resolve_event(envelope.episode_fingerprint);
    authorize_lifecycle_transition(&envelope, &independent).unwrap();
}

#[test]
fn auth_03_rejects_self_implicated_waiver_regardless_of_finding_type() {
    let envelope = envelope();
    let conflicted_waiver = waive_event(
        envelope.episode_fingerprint,
        "principal.author_a",
        "2026-09-01T00:00:00.000000000Z",
    );
    assert!(authorize_lifecycle_transition(&envelope, &conflicted_waiver).is_err());

    let independent_waiver = waive_event(
        envelope.episode_fingerprint,
        "principal.on_call",
        "2026-09-01T00:00:00.000000000Z",
    );
    authorize_lifecycle_transition(&envelope, &independent_waiver).unwrap();

    // AUTH-03's "silently resolve its own discrepancy" is not scoped to
    // claim-authorship: a self-implicated waiver on a non-claim_conflict
    // finding type is rejected too, because `implicated_actor_ids` is a
    // generic field any finding type may populate.
    let mut non_conflict = envelope;
    non_conflict.finding_type = FindingType::SpecNonconformance;
    non_conflict.family_fingerprint = DiscrepancyFamilyPreimageV1 {
        schema_version: DISCREPANCY_SCHEMA_VERSION,
        profile: non_conflict.profile.clone(),
        scope: non_conflict.scope.clone(),
        finding_type: non_conflict.finding_type,
        canonical_subject: non_conflict.canonical_subject.clone(),
        predicate: non_conflict.predicate.clone(),
        comparator_lineage_fingerprint: non_conflict.comparator_lineage_fingerprint,
        expectation_policy: non_conflict.expectation_policy.clone(),
        required_applicability_dimension_ids: non_conflict
            .required_applicability_dimension_ids
            .clone(),
        applicability: non_conflict.applicability.clone(),
        episode_policy_version: non_conflict.episode_policy.version,
    }
    .fingerprint()
    .unwrap();
    non_conflict.episode_fingerprint = DiscrepancyEpisodePreimageV1 {
        schema_version: DISCREPANCY_SCHEMA_VERSION,
        family_fingerprint: non_conflict.family_fingerprint,
        continuity_key: vec![applicability()[1].clone()],
        opening_transition_source_fact_id: non_conflict.opening_transition.source_fact_id,
        episode_policy_version: non_conflict.episode_policy.version,
    }
    .fingerprint()
    .unwrap();
    non_conflict.validate_shape().unwrap();
    let spec_nonconformance_self_waiver = waive_event(
        non_conflict.episode_fingerprint,
        "principal.author_a",
        "2026-09-01T00:00:00.000000000Z",
    );
    assert!(
        authorize_lifecycle_transition(&non_conflict, &spec_nonconformance_self_waiver).is_err()
    );
}

fn waiver_with_scope(
    actor_id: &str,
    expiry_at: &str,
    applicability_scope: Vec<ApplicabilityDimensionV1>,
) -> WaiverRecordV1 {
    WaiverRecordV1 {
        applicability_scope,
        ..waiver_record(actor_id, expiry_at)
    }
}

#[test]
fn disc_05_waiver_scope_must_cover_the_envelope_applicability() {
    let envelope = envelope();
    // Positive: a scope entry that exactly matches an applicability
    // dimension the envelope actually carries covers, and authorizes,
    // the waiver.
    let covered = lifecycle_event(
        envelope.episode_fingerprint,
        "2026-08-15T05:10:00.000000000Z",
        Some(LifecycleTransitionV1::Waive {
            waiver: waiver_with_scope(
                "principal.on_call",
                "2026-09-01T00:00:00.000000000Z",
                vec![applicability()[1].clone()],
            ),
        }),
        None,
        'a',
    );
    authorize_lifecycle_transition(&envelope, &covered).unwrap();
    let projection = project_discrepancy_episode(
        &envelope,
        &[covered],
        &[],
        &CanonicalTimestamp::parse("2026-08-15T06:00:00.000000000Z").unwrap(),
    )
    .unwrap();
    assert_eq!(projection.lifecycle_state, LifecycleState::Waived);

    // Negative: a scope entry naming the same dimension_id the envelope
    // carries, but a DIFFERENT concrete value, does not cover -- an
    // "out-of-scope" waiver must not suppress the episode.
    let out_of_scope_value = ApplicabilityDimensionV1 {
        dimension_id: ContractId::new("runtime_environment").unwrap(),
        value: ApplicabilityDimensionValueV1::Concrete {
            resource: resource(IdentityForm::Entity, "environment", '7'),
        },
    };
    let out_of_scope = lifecycle_event(
        envelope.episode_fingerprint,
        "2026-08-15T05:10:00.000000000Z",
        Some(LifecycleTransitionV1::Waive {
            waiver: waiver_with_scope(
                "principal.on_call",
                "2026-09-01T00:00:00.000000000Z",
                vec![out_of_scope_value],
            ),
        }),
        None,
        'a',
    );
    assert!(authorize_lifecycle_transition(&envelope, &out_of_scope).is_err());

    // Negative: a scope entry naming a dimension_id the envelope does not
    // carry at all does not cover either.
    let alien_dimension = ApplicabilityDimensionV1 {
        dimension_id: ContractId::new("totally_unrelated_dimension").unwrap(),
        value: ApplicabilityDimensionValueV1::Any,
    };
    let alien = lifecycle_event(
        envelope.episode_fingerprint,
        "2026-08-15T05:10:00.000000000Z",
        Some(LifecycleTransitionV1::Waive {
            waiver: waiver_with_scope(
                "principal.on_call",
                "2026-09-01T00:00:00.000000000Z",
                vec![alien_dimension],
            ),
        }),
        None,
        'a',
    );
    assert!(authorize_lifecycle_transition(&envelope, &alien).is_err());

    // Empty scope (the default `waiver_record`/`waive_event` fixtures use)
    // always covers: it applies to the full episode applicability.
    let empty_scope = waive_event(
        envelope.episode_fingerprint,
        "principal.on_call",
        "2026-09-01T00:00:00.000000000Z",
    );
    authorize_lifecycle_transition(&envelope, &empty_scope).unwrap();
}

#[test]
fn repeated_waiver_drift_is_always_candidate_only() {
    assert_eq!(nominate_repeated_waiver_drift(0, 3).unwrap(), None);
    assert_eq!(
        nominate_repeated_waiver_drift(3, 3).unwrap(),
        Some(VerificationState::Candidate)
    );
    assert_eq!(
        nominate_repeated_waiver_drift(1_000_000, 3).unwrap(),
        Some(VerificationState::Candidate)
    );
    assert!(nominate_repeated_waiver_drift(5, 0).is_err());
}

#[test]
fn required_applicability_dimension_omitted_is_rejected_not_treated_as_any() {
    let mut missing = DiscrepancyFamilyPreimageV1 {
        schema_version: DISCREPANCY_SCHEMA_VERSION,
        profile: frozen_profile_reference_v1(),
        scope: scope(),
        finding_type: FindingType::ClaimConflict,
        canonical_subject: resource(IdentityForm::Entity, "repository", '1'),
        predicate: reference(
            "predicate.database_choice_v1",
            "36660875b3d71595ccb4b5dfbc17c4c0fe546eec0fa4b8da6a63b17fec074586",
        ),
        comparator_lineage_fingerprint: comparator_lineage().fingerprint().unwrap(),
        expectation_policy: reference(
            "policy.database_choice_v1",
            "d0b7d4e7b630ce599389e50948541e21b4aa24d4d030860f6cfcaf7508d49df4",
        ),
        required_applicability_dimension_ids: vec![ContractId::new("runtime_environment").unwrap()],
        applicability: applicability(),
        episode_policy_version: 1,
    };
    missing
        .applicability
        .retain(|dim| dim.dimension_id.as_str() != "runtime_environment");
    assert!(missing.validate_shape().is_err());

    // Explicitly declaring `any` is the only way to satisfy a required
    // dimension without a concrete resource.
    missing.applicability.push(ApplicabilityDimensionV1 {
        dimension_id: ContractId::new("runtime_environment").unwrap(),
        value: ApplicabilityDimensionValueV1::Any,
    });
    assert!(missing.validate_shape().is_ok());
}

#[test]
fn envelope_fingerprints_fail_closed_on_tampering() {
    let mut tampered_family = envelope();
    tampered_family.severity = DiscrepancySeverityV1::Critical;
    tampered_family.family_fingerprint = DiscrepancyFamilyFingerprintV1::from_digest(digest(
        "5555555555555555555555555555555555555555555555555555555555555555",
    ));
    assert!(tampered_family.validate_shape().is_err());

    let mut tampered_episode = envelope();
    tampered_episode.episode_fingerprint = DiscrepancyEpisodeFingerprintV1::from_digest(digest(
        "6666666666666666666666666666666666666666666666666666666666666666",
    ));
    assert!(tampered_episode.validate_shape().is_err());
}

#[test]
fn envelope_validates_against_its_exact_registered_episode_policy() {
    let bound = envelope_bound_to_resolved_policy();
    bound
        .validate_against_episode_policy(&resolved_episode_policy())
        .unwrap();
}

#[test]
fn envelope_continuity_key_divergent_from_registered_policy_is_rejected() {
    // `validate_shape` alone accepts a continuity key that is any sorted
    // subset of `applicability`, regardless of what the named
    // `episode_policy` actually registers -- that is exactly the gap this
    // seam closes. The registered policy's continuity key is
    // `[runtime_environment]`.
    let mut divergent = envelope_bound_to_resolved_policy();
    divergent.continuity_key_dimension_ids = vec![ContractId::new("repository_commit").unwrap()];
    divergent.episode_fingerprint = DiscrepancyEpisodePreimageV1 {
        schema_version: DISCREPANCY_SCHEMA_VERSION,
        family_fingerprint: divergent.family_fingerprint,
        continuity_key: vec![applicability()[0].clone()],
        opening_transition_source_fact_id: divergent.opening_transition.source_fact_id,
        episode_policy_version: divergent.episode_policy.version,
    }
    .fingerprint()
    .unwrap();
    divergent.validate_shape().unwrap();
    assert!(
        divergent
            .validate_against_episode_policy(&resolved_episode_policy())
            .is_err()
    );

    // The empty continuity key is likewise structurally valid on its own
    // (vacuously a sorted subset of applicability) but still diverges from
    // the registered non-empty continuity key.
    let mut empty_key = envelope_bound_to_resolved_policy();
    empty_key.continuity_key_dimension_ids = vec![];
    empty_key.episode_fingerprint = DiscrepancyEpisodePreimageV1 {
        schema_version: DISCREPANCY_SCHEMA_VERSION,
        family_fingerprint: empty_key.family_fingerprint,
        continuity_key: vec![],
        opening_transition_source_fact_id: empty_key.opening_transition.source_fact_id,
        episode_policy_version: empty_key.episode_policy.version,
    }
    .fingerprint()
    .unwrap();
    empty_key.validate_shape().unwrap();
    assert!(
        empty_key
            .validate_against_episode_policy(&resolved_episode_policy())
            .is_err()
    );
}

#[test]
fn envelope_episode_policy_reference_divergent_from_registry_entry_digest_is_rejected() {
    let mut wrong_digest = envelope_bound_to_resolved_policy();
    wrong_digest.episode_policy.entry_digest =
        digest("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
    wrong_digest.validate_shape().unwrap();
    assert!(
        wrong_digest
            .validate_against_episode_policy(&resolved_episode_policy())
            .is_err()
    );
}

#[test]
fn envelope_validates_against_its_exact_registered_comparator_lineage() {
    // Positive: the shared `envelope()` fixture's comparator lineage
    // fingerprint, required-applicability-dimension set, concrete
    // applicability, and (empty, since `coverage_proof_required` is
    // false) coverage receipts all satisfy the registered lineage.
    envelope()
        .validate_against_comparator_lineage(&resolved_comparator_lineage())
        .unwrap();
}

#[test]
fn envelope_comparator_lineage_fingerprint_divergent_from_registry_is_rejected() {
    // (a): a self-consistent envelope whose comparator lineage fingerprint
    // names a *different* (version-bumped) lineage than the one
    // `resolved_comparator_lineage()` resolves must be rejected -- the
    // envelope alone proves nothing about which lineage is registered.
    let mut bumped_lineage = comparator_lineage();
    bumped_lineage.comparator_version += 1;
    let mut divergent = envelope();
    divergent.comparator_lineage_fingerprint = bumped_lineage.fingerprint().unwrap();
    refingerprint(&mut divergent);
    divergent.validate_shape().unwrap();
    assert!(
        divergent
            .validate_against_comparator_lineage(&resolved_comparator_lineage())
            .is_err()
    );
}

#[test]
fn envelope_required_applicability_dimension_ids_divergent_from_registry_is_rejected() {
    // (d): `validate_shape` alone accepts any producer-declared required
    // set that is a subset of `applicability` -- including the empty
    // set. The registered comparator lineage requires
    // `[runtime_environment]`; a producer that declares no required
    // dimensions at all must still be rejected once checked against the
    // registry.
    let mut no_required = envelope();
    no_required.required_applicability_dimension_ids = vec![];
    refingerprint(&mut no_required);
    no_required.validate_shape().unwrap();
    assert!(
        no_required
            .validate_against_comparator_lineage(&resolved_comparator_lineage())
            .is_err()
    );
}

#[test]
fn envelope_any_applicability_under_concrete_requirement_is_rejected() {
    // (b): the registered lineage has `concrete_applicability_required =
    // true`. `validate_shape` alone accepts a required dimension whose
    // value is `Any` -- `Any` merely has to be *present*, not concrete.
    // The registry-bound check must reject it.
    let mut any_required = envelope();
    any_required.applicability[1].value = ApplicabilityDimensionValueV1::Any;
    refingerprint(&mut any_required);
    any_required.validate_shape().unwrap();
    assert!(
        any_required
            .validate_against_comparator_lineage(&resolved_comparator_lineage())
            .is_err()
    );
}

#[test]
fn envelope_missing_coverage_receipt_under_coverage_requirement_is_rejected() {
    // (c): a lineage registered with `coverage_proof_required = true`
    // rejects an envelope with no coverage receipts, and accepts one with
    // at least one.
    let mut coverage_required_lineage = comparator_lineage();
    coverage_required_lineage.coverage_proof_required = true;
    let registration = ComparatorLineageRegistrationV1 {
        schema_version: COMPARATOR_LINEAGE_REGISTRATION_SCHEMA_VERSION,
        lineage: coverage_required_lineage.clone(),
        required_applicability_dimension_ids: vec![ContractId::new("runtime_environment").unwrap()],
    };
    let body_bytes = encode_canonical(&registration).unwrap();
    let body: CanonicalValue = decode_strict(&body_bytes).unwrap();
    let entry = RegistryEntryV1 {
        schema_version: 1,
        kind: RegistryEntryKind::ComparatorLineage,
        entry_id: coverage_required_lineage.comparator_id.clone(),
        version: coverage_required_lineage.comparator_version,
        entry_schema_id: ContractId::new(COMPARATOR_LINEAGE_ENTRY_SCHEMA_ID).unwrap(),
        entry_schema_version: COMPARATOR_LINEAGE_REGISTRATION_SCHEMA_VERSION,
        body,
        positive_vector_digest: digest(
            "ee22ee22ee22ee22ee22ee22ee22ee22ee22ee22ee22ee22ee22ee22ee22ee22",
        ),
        negative_vector_digest: digest(
            "ff22ff22ff22ff22ff22ff22ff22ff22ff22ff22ff22ff22ff22ff22ff22ff22",
        ),
    };
    let resolved = StructurallyResolvedComparatorLineageV1::from_registry_entry(&entry).unwrap();

    let mut no_coverage = envelope();
    no_coverage.comparator_lineage_fingerprint = coverage_required_lineage.fingerprint().unwrap();
    refingerprint(&mut no_coverage);
    no_coverage.validate_shape().unwrap();
    assert!(no_coverage.coverage_receipt_ids.is_empty());
    assert!(
        no_coverage
            .validate_against_comparator_lineage(&resolved)
            .is_err()
    );

    let mut with_coverage = no_coverage;
    with_coverage.coverage_receipt_ids = vec![evidence_id('9')];
    with_coverage.validate_shape().unwrap();
    with_coverage
        .validate_against_comparator_lineage(&resolved)
        .unwrap();
}

#[test]
fn unknown_finding_type_and_unknown_fields_fail_closed() {
    let canonical = record(ENVELOPE_FIXTURE);
    let mut value: serde_json::Value = serde_json::from_slice(canonical).unwrap();
    value["finding_type"]["kind"] = serde_json::Value::String("root_cause_theory".into());
    assert!(decode_strict::<DiscrepancyEnvelopeV1>(&serde_json::to_vec(&value).unwrap()).is_err());

    let mut extra_field: serde_json::Value = serde_json::from_slice(canonical).unwrap();
    extra_field.as_object_mut().unwrap().insert(
        "lifecycle_state".into(),
        serde_json::Value::String("open".into()),
    );
    assert!(
        decode_strict::<DiscrepancyEnvelopeV1>(&serde_json::to_vec(&extra_field).unwrap()).is_err()
    );
}

#[test]
fn waiver_without_actor_or_expiry_fails_to_deserialize() {
    let waiver = waiver_record("principal.on_call", "2026-09-01T00:00:00.000000000Z");
    let mut value = serde_json::to_value(&waiver).unwrap();
    let mut missing_actor = value.clone();
    missing_actor.as_object_mut().unwrap().remove("actor");
    assert!(decode_strict::<WaiverRecordV1>(&serde_json::to_vec(&missing_actor).unwrap()).is_err());

    value.as_object_mut().unwrap().remove("expiry_at");
    assert!(decode_strict::<WaiverRecordV1>(&serde_json::to_vec(&value).unwrap()).is_err());
}

#[test]
fn unattributed_verification_update_fails_to_deserialize() {
    // AUTH-03: an actor-free verification-state change (the wire shape
    // this closes) cannot even be constructed by a well-typed caller,
    // matching `WaiverRecordV1`'s mandatory-`actor` convention.
    let update = VerificationUpdateV1 {
        actor: DiscrepancyActorV1 {
            principal_id: ContractId::new("principal.on_call").unwrap(),
        },
        state: VerificationState::Refuted,
        evidence_event_ids: vec![],
    };
    let mut value = serde_json::to_value(&update).unwrap();
    value.as_object_mut().unwrap().remove("actor");
    assert!(decode_strict::<VerificationUpdateV1>(&serde_json::to_vec(&value).unwrap()).is_err());
}

#[test]
fn promotion_to_verified_with_empty_evidence_is_rejected() {
    // PRED-01/PRED-05: a verified discrepancy cites evidence -- promotion
    // to `Verified` with no evidence is rejected at shape validation, not
    // left to a caller to remember to check.
    let evidence_free_promotion = VerificationUpdateV1 {
        actor: DiscrepancyActorV1 {
            principal_id: ContractId::new("principal.on_call").unwrap(),
        },
        state: VerificationState::Verified,
        evidence_event_ids: vec![],
    };
    assert!(evidence_free_promotion.validate_shape().is_err());

    let evidenced_promotion = VerificationUpdateV1 {
        evidence_event_ids: vec![evidence_id('b')],
        ..evidence_free_promotion
    };
    assert!(evidenced_promotion.validate_shape().is_ok());

    // Refuted/Candidate/Indeterminate never require evidence.
    let evidence_free_refutation = VerificationUpdateV1 {
        actor: DiscrepancyActorV1 {
            principal_id: ContractId::new("principal.on_call").unwrap(),
        },
        state: VerificationState::Refuted,
        evidence_event_ids: vec![],
    };
    assert!(evidence_free_refutation.validate_shape().is_ok());
}

#[test]
fn auth_03_rejects_self_implicated_verification_refutation() {
    let envelope = envelope();
    let self_implicated_refutation = lifecycle_event(
        envelope.episode_fingerprint,
        "2026-08-15T05:20:00.000000000Z",
        None,
        Some(VerificationUpdateV1 {
            actor: DiscrepancyActorV1 {
                principal_id: ContractId::new("principal.author_a").unwrap(),
            },
            state: VerificationState::Refuted,
            evidence_event_ids: vec![],
        }),
        'f',
    );
    assert!(authorize_lifecycle_transition(&envelope, &self_implicated_refutation).is_err());

    let independent_refutation = lifecycle_event(
        envelope.episode_fingerprint,
        "2026-08-15T05:20:00.000000000Z",
        None,
        Some(VerificationUpdateV1 {
            actor: DiscrepancyActorV1 {
                principal_id: ContractId::new("principal.on_call").unwrap(),
            },
            state: VerificationState::Refuted,
            evidence_event_ids: vec![],
        }),
        'f',
    );
    authorize_lifecycle_transition(&envelope, &independent_refutation).unwrap();
}

#[test]
fn comparator_lineage_version_bump_is_a_new_lineage() {
    let base = comparator_lineage();
    let mut bumped = base.clone();
    bumped.comparator_version += 1;
    assert_ne!(base.fingerprint().unwrap(), bumped.fingerprint().unwrap());

    let mut different_cardinality = base.clone();
    different_cardinality.cardinality = CardinalityAlgebraV1::SetValued;
    assert_ne!(
        base.fingerprint().unwrap(),
        different_cardinality.fingerprint().unwrap()
    );

    let mut different_polarity = base.clone();
    different_polarity.polarity_rule = PolarityRuleV1::NegationsNeverConflict;
    assert_ne!(
        base.fingerprint().unwrap(),
        different_polarity.fingerprint().unwrap()
    );

    let mut reversed_modality = base;
    reversed_modality.modality_compatibility = vec![ModalityCompatibilityRuleV1 {
        left: PropositionModalityV1::Normative,
        right: PropositionModalityV1::Attested,
    }];
    assert!(reversed_modality.validate_shape().is_err());
}

#[test]
fn episode_relation_arity_is_enforced() {
    let a = DiscrepancyEpisodeFingerprintV1::from_digest(digest(
        "7777777777777777777777777777777777777777777777777777777777777777",
    ));
    let b = DiscrepancyEpisodeFingerprintV1::from_digest(digest(
        "8888888888888888888888888888888888888888888888888888888888888888",
    ));

    let family_fingerprint = envelope().family_fingerprint;

    let single_source_combine = DiscrepancyEpisodeRelationV1 {
        schema_version: DISCREPANCY_SCHEMA_VERSION,
        profile: frozen_profile_reference_v1(),
        scope: scope(),
        family_fingerprint,
        kind: EpisodeRelationKindV1::CombinedFrom,
        from_episodes: vec![a],
        to_episode: b,
    };
    assert!(single_source_combine.validate_shape().is_err());

    let self_referential = DiscrepancyEpisodeRelationV1 {
        schema_version: DISCREPANCY_SCHEMA_VERSION,
        profile: frozen_profile_reference_v1(),
        scope: scope(),
        family_fingerprint,
        kind: EpisodeRelationKindV1::Continues,
        from_episodes: vec![a],
        to_episode: a,
    };
    assert!(self_referential.validate_shape().is_err());
}

#[test]
#[ignore = "maintainer-only canonical discrepancy fixture regeneration"]
fn regenerate_discrepancy_contract_artifacts() {
    fn write(output: &Path, name: &str, bytes: &[u8]) {
        let mut framed = bytes.to_vec();
        framed.push(b'\n');
        fs::write(output.join(name), framed).unwrap();
    }

    let output = std::env::var_os("DISCREPANCY_VECTOR_OUTPUT")
        .map(std::path::PathBuf::from)
        .expect("DISCREPANCY_VECTOR_OUTPUT is required");
    fs::create_dir_all(&output).unwrap();

    let envelope = envelope();
    let episode_fingerprint = envelope.episode_fingerprint;
    let lineage = comparator_lineage();
    let policy = episode_policy();
    let acknowledge = acknowledge_event(episode_fingerprint);
    let waive = waive_event(
        episode_fingerprint,
        "principal.on_call",
        "2026-09-15T00:00:00.000000000Z",
    );
    let resolve = resolve_event(episode_fingerprint);
    let dismiss = dismiss_event(episode_fingerprint, "principal.on_call");
    let other_episode = DiscrepancyEpisodeFingerprintV1::from_digest(digest(
        "1111111111111111111111111111111111111111111111111111111111111111",
    ));
    let combined_episode = DiscrepancyEpisodeFingerprintV1::from_digest(digest(
        "2222222222222222222222222222222222222222222222222222222222222222",
    ));
    let split_relation = episode_relation_split(
        episode_fingerprint,
        other_episode,
        envelope.family_fingerprint,
    );
    let combined_relation = episode_relation_combined(
        episode_fingerprint,
        other_episode,
        combined_episode,
        envelope.family_fingerprint,
    );
    let suite = vector_suite();

    for (name, bytes) in [
        (
            "discrepancy-envelope.jsonl",
            encode_canonical(&envelope).unwrap(),
        ),
        (
            "comparator-lineage.jsonl",
            encode_canonical(&lineage).unwrap(),
        ),
        ("episode-policy.jsonl", encode_canonical(&policy).unwrap()),
        (
            "lifecycle-event-acknowledge.jsonl",
            encode_canonical(&acknowledge).unwrap(),
        ),
        (
            "lifecycle-event-waive.jsonl",
            encode_canonical(&waive).unwrap(),
        ),
        (
            "lifecycle-event-resolve.jsonl",
            encode_canonical(&resolve).unwrap(),
        ),
        (
            "lifecycle-event-dismiss.jsonl",
            encode_canonical(&dismiss).unwrap(),
        ),
        (
            "episode-relation-superseded-split.jsonl",
            encode_canonical(&split_relation).unwrap(),
        ),
        (
            "episode-relation-combined-from.jsonl",
            encode_canonical(&combined_relation).unwrap(),
        ),
        ("vector-suite.jsonl", encode_canonical(&suite).unwrap()),
    ] {
        write(&output, name, &bytes);
    }

    println!("FAMILY_FINGERPRINT {}", envelope.family_fingerprint);
    println!("EPISODE_FINGERPRINT {}", envelope.episode_fingerprint);
    println!("ENVELOPE_ID {}", envelope.envelope_id().unwrap());
    println!(
        "COMPARATOR_LINEAGE_FINGERPRINT {}",
        lineage.fingerprint().unwrap()
    );
    println!(
        "VECTOR_SUITE_DIGEST {}",
        domain_separated_digest(
            super::super::digest::DigestDomain::TestVectorManifest,
            &encode_canonical(&suite).unwrap()
        )
    );
    for bytes in [
        ("ENVELOPE_RAW_SHA256", encode_canonical(&envelope).unwrap()),
        ("VECTOR_SUITE_RAW_SHA256", encode_canonical(&suite).unwrap()),
    ] {
        let mut framed = bytes.1.clone();
        framed.push(b'\n');
        println!("{} {}", bytes.0, raw_sha256(&framed));
    }
}
