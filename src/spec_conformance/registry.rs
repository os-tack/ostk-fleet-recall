//! The comparator lineage and episode policy every spec nonconformance is
//! judged under (Stage 6).
//!
//! A discrepancy envelope must name, by exact registry reference, the
//! comparator lineage that decided its two sides disagree and the episode
//! policy that groups its detections; admission then proves the envelope
//! against the resolved bodies of both. No active package registers either
//! kind yet: `comparator_lineage` and `episode_policy` are generation-2-only
//! registry slots that no semantic closure admits (the DISC-06 deferral). So
//! the two entries spec conformance needs are compiled in here, built as
//! ordinary [`RegistryEntryV1`] values and resolved through the contract's
//! own structural resolvers:
//!
//! * [`spec_comparator_lineage`] — `comparator.remember_action_membership`
//!   v1: a functional comparison of one membership value, where two
//!   affirmations of distinct values conflict, between a normative and an
//!   observed side, over overlapping intervals, with a coverage proof
//!   required. Its one required applicability dimension is
//!   `repository_commit`, which a spec envelope declares explicitly as `any`
//!   so that one family spans every commit of one repository under one
//!   statement.
//! * [`spec_episode_policy`] — `episode.spec_nonconformance_v2` v1: no
//!   continuity key and no windowing, so an episode is exactly one family's
//!   run of nonconformance from its first verified detection until an
//!   operator closes it.
//!
//! These entries are NOT package-admitted: nothing proves their membership in
//! the active package, and an envelope that cites them is trusted only as far
//! as the deriver that built it. They are also identity: their digests enter
//! every spec family and episode fingerprint, so they must never be edited in
//! place. A change is a new version (a new lineage or policy, and therefore a
//! new family), never a new body under an old version.

use std::sync::OnceLock;

use crate::memory_contracts::canonical::{decode_strict, encode_canonical};
use crate::memory_contracts::common::ContractId;
use crate::memory_contracts::digest::{DigestDomain, Sha256Digest, framed_digest};
use crate::memory_contracts::discrepancy::{
    CardinalityAlgebraV1, ComparatorLineageRegistrationV1, ComparatorLineageV1,
    EffectiveIntervalRuleV1, EpisodeClosingRuleV1, EpisodeOpeningRuleV1, EpisodePolicyV2,
    EpisodeWindowingV1, LateEvidenceBehaviorV1, ModalityCompatibilityRuleV1, PolarityRuleV1,
    RuleChangeBehaviorV1, StructurallyResolvedComparatorLineageV1,
    StructurallyResolvedEpisodePolicyV2,
};
use crate::memory_contracts::genesis::PropositionModalityV1;
use crate::memory_contracts::registry::{RegistryEntryKind, RegistryEntryV1};
use crate::memory_contracts::{ContractError, ContractResult};
use crate::observer_runtime::REQUIRED_APPLICABILITY_DIMENSION;

/// The comparator every spec nonconformance is decided by.
pub const SPEC_COMPARATOR_ID: &str = "comparator.remember_action_membership";

/// The version of [`SPEC_COMPARATOR_ID`] this build compiles in.
pub const SPEC_COMPARATOR_VERSION: u32 = 1;

/// The episode policy every spec nonconformance episode is grouped under.
pub const SPEC_EPISODE_POLICY_ID: &str = "episode.spec_nonconformance_v2";

/// The version of [`SPEC_EPISODE_POLICY_ID`] this build compiles in.
pub const SPEC_EPISODE_POLICY_VERSION: u32 = 1;

/// The applicability dimension a spec family declares as `any`: the observed
/// commit, which the observer binds concretely on every run.
pub const SPEC_APPLICABILITY_DIMENSION: &str = REQUIRED_APPLICABILITY_DIMENSION;

/// `schema_version` of a registry entry, a lineage registration, a lineage,
/// and an episode policy.
const SCHEMA_VERSION: u32 = 1;
const COMPARATOR_LINEAGE_ENTRY_SCHEMA_ID: &str = "registry.comparator_lineage";
const EPISODE_POLICY_ENTRY_SCHEMA_ID: &str = "registry.episode_policy";

/// The compiled-in spec comparator lineage, structurally resolved.
///
/// # Errors
///
/// A contract error when the compiled-in entry does not resolve, which is a
/// build defect rather than a verdict about any input.
pub fn spec_comparator_lineage() -> ContractResult<&'static StructurallyResolvedComparatorLineageV1>
{
    static LINEAGE: OnceLock<Result<StructurallyResolvedComparatorLineageV1, String>> =
        OnceLock::new();
    memoized(&LINEAGE, "spec comparator lineage", || {
        StructurallyResolvedComparatorLineageV1::from_registry_entry(&comparator_lineage_entry()?)
    })
}

/// The compiled-in spec episode policy, structurally resolved.
///
/// # Errors
///
/// A contract error when the compiled-in entry does not resolve, which is a
/// build defect rather than a verdict about any input.
pub fn spec_episode_policy() -> ContractResult<&'static StructurallyResolvedEpisodePolicyV2> {
    static POLICY: OnceLock<Result<StructurallyResolvedEpisodePolicyV2, String>> = OnceLock::new();
    memoized(&POLICY, "spec episode policy", || {
        StructurallyResolvedEpisodePolicyV2::from_registry_entry(&episode_policy_entry()?)
    })
}

/// The registry entry [`spec_comparator_lineage`] resolves.
///
/// # Errors
///
/// A contract error for a body the canonical profile refuses.
pub fn comparator_lineage_entry() -> ContractResult<RegistryEntryV1> {
    let registration = ComparatorLineageRegistrationV1 {
        schema_version: SCHEMA_VERSION,
        lineage: ComparatorLineageV1 {
            schema_version: SCHEMA_VERSION,
            comparator_id: ContractId::new(SPEC_COMPARATOR_ID)?,
            comparator_version: SPEC_COMPARATOR_VERSION,
            cardinality: CardinalityAlgebraV1::Functional,
            polarity_rule: PolarityRuleV1::AffirmationsConflictOnDistinctValues,
            modality_compatibility: vec![ModalityCompatibilityRuleV1 {
                left: PropositionModalityV1::Normative,
                right: PropositionModalityV1::Observed,
            }],
            // The family declares its commit dimension as `any`, so the
            // lineage cannot require concrete applicability.
            concrete_applicability_required: false,
            effective_interval_rule: EffectiveIntervalRuleV1::OverlapRequired,
            coverage_proof_required: true,
        },
        required_applicability_dimension_ids: vec![ContractId::new(SPEC_APPLICABILITY_DIMENSION)?],
    };
    compiled_entry(
        RegistryEntryKind::ComparatorLineage,
        SPEC_COMPARATOR_ID,
        SPEC_COMPARATOR_VERSION,
        COMPARATOR_LINEAGE_ENTRY_SCHEMA_ID,
        &registration,
    )
}

/// The registry entry [`spec_episode_policy`] resolves.
///
/// # Errors
///
/// A contract error for a body the canonical profile refuses.
pub fn episode_policy_entry() -> ContractResult<RegistryEntryV1> {
    let policy = EpisodePolicyV2 {
        schema_version: SCHEMA_VERSION,
        policy_id: ContractId::new(SPEC_EPISODE_POLICY_ID)?,
        version: SPEC_EPISODE_POLICY_VERSION,
        continuity_key_dimension_ids: Vec::new(),
        windowing: EpisodeWindowingV1::NonWindowed,
        opening_rule: EpisodeOpeningRuleV1::FirstVerifiedIncompatibleObservation,
        allowed_observation_gap_seconds: None,
        closing_rule: EpisodeClosingRuleV1::VerifiedCompatibleSupersessionOrScopeExit,
        rule_change_behavior: RuleChangeBehaviorV1::NewFamilyLinkedBySupersession,
        late_evidence_behavior: LateEvidenceBehaviorV1::EffectiveIntervalReplayWithSupersession,
    };
    compiled_entry(
        RegistryEntryKind::EpisodePolicy,
        SPEC_EPISODE_POLICY_ID,
        SPEC_EPISODE_POLICY_VERSION,
        EPISODE_POLICY_ENTRY_SCHEMA_ID,
        &policy,
    )
}

fn compiled_entry<Body: serde::Serialize>(
    kind: RegistryEntryKind,
    entry_id: &str,
    version: u32,
    entry_schema_id: &str,
    body: &Body,
) -> ContractResult<RegistryEntryV1> {
    let entry = RegistryEntryV1 {
        schema_version: SCHEMA_VERSION,
        kind,
        entry_id: ContractId::new(entry_id)?,
        version,
        entry_schema_id: ContractId::new(entry_schema_id)?,
        entry_schema_version: SCHEMA_VERSION,
        body: decode_strict(&encode_canonical(body)?)?,
        positive_vector_digest: vectors_label(entry_id, version, b"positive"),
        negative_vector_digest: vectors_label(entry_id, version, b"negative"),
    };
    entry.validate()?;
    Ok(entry)
}

fn vectors_label(entry_id: &str, version: u32, polarity: &[u8]) -> Sha256Digest {
    framed_digest(
        DigestDomain::SpecCompiledEntryVectorsV1,
        &[entry_id.as_bytes(), &version.to_be_bytes(), polarity],
    )
}

fn memoized<T>(
    cell: &'static OnceLock<Result<T, String>>,
    label: &str,
    resolve: impl FnOnce() -> ContractResult<T>,
) -> ContractResult<&'static T> {
    cell.get_or_init(|| resolve().map_err(|error| error.to_string()))
        .as_ref()
        .map_err(|reason| {
            ContractError::Schema(format!(
                "the compiled-in {label} does not resolve: {reason}"
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_compiled_entries_resolve_under_their_own_references() {
        let lineage = spec_comparator_lineage().unwrap();
        assert_eq!(
            lineage.registry_reference().entry_id.as_str(),
            SPEC_COMPARATOR_ID
        );
        assert_eq!(
            lineage.registry_reference().entry_digest,
            comparator_lineage_entry().unwrap().digest().unwrap()
        );
        assert_eq!(
            lineage.required_applicability_dimension_ids(),
            [ContractId::new(SPEC_APPLICABILITY_DIMENSION).unwrap()]
        );
        // A spec family declares its commit dimension as `any`, which a
        // lineage requiring concrete applicability would refuse.
        assert!(!lineage.lineage().concrete_applicability_required);

        let policy = spec_episode_policy().unwrap();
        assert_eq!(
            policy.registry_reference().entry_id.as_str(),
            SPEC_EPISODE_POLICY_ID
        );
        assert!(policy.policy().continuity_key_dimension_ids.is_empty());
        assert_eq!(policy.policy().windowing, EpisodeWindowingV1::NonWindowed);
    }
}
