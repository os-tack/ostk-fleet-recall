//! Discrepancy family/episode fingerprints, episode policy, envelope, lifecycle and
//! verification states.
//!
//! Three tiers, mirroring `relation.rs`:
//!
//! 1. [`DiscrepancyEnvelopeV1`] — the immutable per-detection identity. Its digest
//!    preimage never includes lifecycle or verification state, so replaying the same
//!    detection under a different acknowledge/waive/resolve/dismiss history always
//!    yields the same [`DiscrepancyFamilyFingerprintV1`] and
//!    [`DiscrepancyEpisodeFingerprintV1`] (DISC-01, DISC-02; "lifecycle state and
//!    verification state therefore never define episode identity").
//! 2. [`DiscrepancyLifecycleEventV1`] — an append-only transition (acknowledge, waive,
//!    resolve, dismiss, and/or an independent verification update) that names the
//!    exact episode it applies to (DISC-03, DISC-05, AUTH-03).
//! 3. [`project_discrepancy_episode`] — a pure, order-independent replay of one
//!    envelope plus its lifecycle events into a current [`DiscrepancyEpisodeProjectionV1`]
//!    (REPLAY-01).
//!
//! The opening transition that seeds an episode fingerprint is selected by a total
//! order over `(effective_at, provider_order, source_fact_id)`
//! ([`OpeningTransitionCandidateV1`]) — never by receipt order. This is deliberately
//! disjoint from the legacy `same_key_functional_value_v2` conflict identity in
//! `src/ledger/conflict.rs`: that identity is an integer-keyed
//! `(tenant_id, project, claim_key, detector)` database row, never a domain-separated
//! SHA-256 preimage, so no value in either space can collide with or masquerade as a
//! row in the other. See `contracts/dynamic-memory/v3/discrepancy/README.md`.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::{
    ContractError, ContractResult,
    canonical::{decode_strict, encode_canonical},
    common::{
        AuthenticatedProjectScopeV1, CanonicalTimestamp, ContractId, ProfileReferenceV1,
        RegistryReferenceV1,
    },
    digest::{DigestDomain, Sha256Digest, domain_separated_digest},
    evidence::{AcceptedEventId, SourceFactId},
    evidence_v2::RegistryHeadBindingV1,
    genesis::PropositionModalityV1,
    identity::ResourceUri,
    registry::{RegistryEntryKind, RegistryEntryV1},
};

const DISCREPANCY_SCHEMA_VERSION: u32 = 1;
const COMPARATOR_LINEAGE_SCHEMA_VERSION: u32 = 1;
const EPISODE_POLICY_SCHEMA_VERSION: u32 = 1;
const DISCREPANCY_ENVELOPE_EVENT_KIND: &str = "discrepancy.envelope.accepted";
const DISCREPANCY_LIFECYCLE_EVENT_KIND: &str = "discrepancy.lifecycle.accepted";
const EPISODE_POLICY_ENTRY_SCHEMA_ID: &str = "registry.episode_policy";
const COMPARATOR_LINEAGE_REGISTRATION_SCHEMA_VERSION: u32 = 1;
const COMPARATOR_LINEAGE_ENTRY_SCHEMA_ID: &str = "registry.comparator_lineage";
const MAX_APPLICABILITY_DIMENSIONS: usize = 64;
const MAX_CONTINUITY_KEY_DIMENSIONS: usize = 32;
const MAX_EVIDENCE_EVENT_IDS: usize = 256;
const MAX_IMPLICATED_ACTORS: usize = 64;
const MAX_MODALITY_COMPATIBILITY_RULES: usize = 16;
const MAX_RATIONALE_BYTES: usize = 4_096;

macro_rules! fingerprint_newtype {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(Sha256Digest);

        impl $name {
            pub const fn from_digest(digest: Sha256Digest) -> Self {
                Self(digest)
            }

            pub const fn digest(self) -> Sha256Digest {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                self.0.serialize(serializer)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                Sha256Digest::deserialize(deserializer).map(Self)
            }
        }
    };
}

fingerprint_newtype!(DiscrepancyFamilyFingerprintV1);
fingerprint_newtype!(DiscrepancyEpisodeFingerprintV1);
fingerprint_newtype!(ComparatorLineageFingerprint);
fingerprint_newtype!(DiscrepancyEnvelopeId);
fingerprint_newtype!(DiscrepancyLifecycleEventId);

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn strictly_sorted_by_dimension(values: &[ApplicabilityDimensionV1]) -> bool {
    values
        .windows(2)
        .all(|pair| pair[0].dimension_id < pair[1].dimension_id)
}

fn dimension_present(applicability: &[ApplicabilityDimensionV1], id: &ContractId) -> bool {
    applicability
        .binary_search_by(|dimension| dimension.dimension_id.cmp(id))
        .is_ok()
}

// ---------------------------------------------------------------------------
// Finding types (lines 640-652 of the architecture doc)
// ---------------------------------------------------------------------------

/// Closed subtype set for `lifecycle_gap`. New subtypes require a new module
/// release, never a caller-supplied string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleGapSubtypeV1 {
    Validation,
}

/// Closed subtype set for `runtime_nonconformance`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeNonconformanceSubtypeV1 {
    SloBreach,
}

/// Closed discrepancy finding-type taxonomy. Unknown wire values fail closed:
/// there is no catch-all variant, so an unrecognized `kind` is a deserialize
/// error rather than a silently accepted new category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum FindingType {
    ClaimConflict,
    ClaimEvidenceContradiction,
    SpecNonconformance,
    DocumentationDrift,
    ProvenanceGap,
    LifecycleGap {
        subtype: LifecycleGapSubtypeV1,
    },
    RuntimeNonconformance {
        subtype: RuntimeNonconformanceSubtypeV1,
    },
    ConfigurationDrift,
    ReleaseIntegrityConflict,
    RegressionCandidate,
    TelemetryDisagreement,
}

// ---------------------------------------------------------------------------
// Comparator lineage (PRED-01..05; legacy `same_key_functional_value_v2` is
// intentionally narrower and is never generalized silently -- doc lines 360-369)
// ---------------------------------------------------------------------------

/// Closed cardinality algebra a comparator commits to. Legacy
/// `same_key_functional_value_v2` corresponds only to `Functional`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CardinalityAlgebraV1 {
    Functional,
    SetValued,
    ThresholdRatio,
    FiniteDomainExhaustive,
}

/// Closed polarity rule: how affirmation/negation combine under this comparator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolarityRuleV1 {
    AffirmationsConflictOnDistinctValues,
    AffirmationNegationConflictOnSameValue,
    NegationsNeverConflict,
}

/// Closed rule for how the effective interval participates in comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectiveIntervalRuleV1 {
    OverlapRequired,
    ExactMatchRequired,
}

/// One declared-compatible ordered pair of modalities (PRED-04).
///
/// `left <= right` is required so `(Observed, Normative)` and `(Normative,
/// Observed)` cannot both be registered as distinct rules for the same
/// unordered pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModalityCompatibilityRuleV1 {
    pub left: PropositionModalityV1,
    pub right: PropositionModalityV1,
}

/// A comparator's exact incompatibility algorithm.
///
/// Bound together per doc lines 360-369: cardinality, polarity, modality
/// compatibility, concrete-applicability requirement, effective-interval rule,
/// coverage-proof requirement, and version. Changing any field changes the
/// fingerprint, which is exactly "any change => new lineage."
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComparatorLineageV1 {
    pub schema_version: u32,
    pub comparator_id: ContractId,
    pub comparator_version: u32,
    pub cardinality: CardinalityAlgebraV1,
    pub polarity_rule: PolarityRuleV1,
    pub modality_compatibility: Vec<ModalityCompatibilityRuleV1>,
    pub concrete_applicability_required: bool,
    pub effective_interval_rule: EffectiveIntervalRuleV1,
    pub coverage_proof_required: bool,
}

impl ComparatorLineageV1 {
    pub fn validate_shape(&self) -> ContractResult<()> {
        let valid = self.schema_version == COMPARATOR_LINEAGE_SCHEMA_VERSION
            && self.comparator_version > 0
            && self.modality_compatibility.len() <= MAX_MODALITY_COMPATIBILITY_RULES
            && self
                .modality_compatibility
                .iter()
                .all(|rule| rule.left <= rule.right)
            && strictly_sorted(&self.modality_compatibility);
        if !valid {
            return Err(ContractError::Schema("invalid comparator lineage".into()));
        }
        Ok(())
    }

    /// Any field change -- including a bare `comparator_version` bump -- yields a
    /// different digest, which is the contract's entire notion of "new lineage."
    pub fn fingerprint(&self) -> ContractResult<ComparatorLineageFingerprint> {
        self.validate_shape()?;
        Ok(ComparatorLineageFingerprint::from_digest(
            domain_separated_digest(DigestDomain::ComparatorLineageV1, &encode_canonical(self)?),
        ))
    }
}

/// Registry-entry body binding one [`ComparatorLineageV1`] to its required dimensions.
///
/// The required-applicability-dimension set the registry -- never an envelope
/// payload -- actually attaches to it (doc "Predicate schema", PRED-02,
/// APPL-01: required selectors resolve against the registered predicate, not
/// a caller-declared list).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComparatorLineageRegistrationV1 {
    pub schema_version: u32,
    pub lineage: ComparatorLineageV1,
    pub required_applicability_dimension_ids: Vec<ContractId>,
}

impl ComparatorLineageRegistrationV1 {
    fn validate_shape(&self) -> ContractResult<()> {
        self.lineage.validate_shape()?;
        let valid = self.schema_version == COMPARATOR_LINEAGE_REGISTRATION_SCHEMA_VERSION
            && self.required_applicability_dimension_ids.len() <= MAX_APPLICABILITY_DIMENSIONS
            && strictly_sorted(&self.required_applicability_dimension_ids);
        if !valid {
            return Err(ContractError::Schema(
                "invalid comparator lineage registration".into(),
            ));
        }
        Ok(())
    }
}

/// One exact comparator-lineage registry entry whose reference and body agree.
///
/// Named `StructurallyResolved`, matching `StructurallyResolvedEpisodePolicyV2`
/// (this module) and `StructurallyResolvedConnectorSchemaV2`
/// (`evidence_v2.rs`): any caller can construct registry-entry bytes; runtime
/// admission must additionally prove membership in the exact active
/// package/head. Reuses `RegistryEntryKind::PredicateSchema` (the doc's
/// PRED-02 predicate/comparator category) under its own `entry_schema_id`
/// (`registry.comparator_lineage`), disjoint from `genesis.rs`'s
/// `PredicateSchemaEntryV1` body (`registry.predicate_schema`) -- the same
/// kind tag, a distinct body namespace, exactly the reuse-without-collision
/// pattern `StructurallyResolvedEpisodePolicyV2` already established for
/// `RegistryEntryKind::EpisodePolicy`. No digest.rs/registry.rs/genesis.rs
/// change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructurallyResolvedComparatorLineageV1 {
    registry_reference: RegistryReferenceV1,
    registration: ComparatorLineageRegistrationV1,
}

impl StructurallyResolvedComparatorLineageV1 {
    pub fn from_registry_entry(entry: &RegistryEntryV1) -> ContractResult<Self> {
        entry.validate()?;
        if entry.kind != RegistryEntryKind::PredicateSchema
            || entry.entry_schema_id.as_str() != COMPARATOR_LINEAGE_ENTRY_SCHEMA_ID
            || entry.entry_schema_version != COMPARATOR_LINEAGE_REGISTRATION_SCHEMA_VERSION
        {
            return Err(ContractError::Schema(
                "registry entry is not a comparator lineage registration body".into(),
            ));
        }
        let body_bytes = encode_canonical(&entry.body)?;
        let registration: ComparatorLineageRegistrationV1 = decode_strict(&body_bytes)?;
        registration.validate_shape()?;
        let identity_matches = registration.lineage.comparator_id == entry.entry_id;
        let version_matches = registration.lineage.comparator_version == entry.version;
        if !identity_matches || !version_matches {
            return Err(ContractError::ManifestMismatch);
        }
        Ok(Self {
            registry_reference: RegistryReferenceV1 {
                entry_id: entry.entry_id.clone(),
                version: entry.version,
                entry_digest: entry.digest()?,
            },
            registration,
        })
    }

    pub const fn lineage(&self) -> &ComparatorLineageV1 {
        &self.registration.lineage
    }

    pub fn required_applicability_dimension_ids(&self) -> &[ContractId] {
        &self.registration.required_applicability_dimension_ids
    }

    pub const fn registry_reference(&self) -> &RegistryReferenceV1 {
        &self.registry_reference
    }
}

// ---------------------------------------------------------------------------
// Applicability (APPL-01..03 background: an omitted dimension is `unknown`,
// never a silent `any`; `any` must be declared explicitly)
// ---------------------------------------------------------------------------

/// A concrete resource, or an explicitly declared wildcard.
///
/// There is no third, implicit "omitted means any" form: omission is modeled
/// by the dimension's absence from the applicability vector entirely, which
/// fails closed wherever that dimension is required (see
/// [`DiscrepancyEnvelopeV1::validate_shape`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "form", rename_all = "snake_case", deny_unknown_fields)]
pub enum ApplicabilityDimensionValueV1 {
    Concrete { resource: ResourceUri },
    Any,
}

/// One applicability dimension keyed by a registry-controlled dimension ID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicabilityDimensionV1 {
    pub dimension_id: ContractId,
    pub value: ApplicabilityDimensionValueV1,
}

// ---------------------------------------------------------------------------
// Discrepancy family fingerprint (doc lines 1315-1319)
// ---------------------------------------------------------------------------

/// Preimage for [`DiscrepancyFamilyFingerprintV1`].
///
/// Binds tenant/project scope, finding type, canonical subject, predicate +
/// comparator lineage, expectation identity, normalized applicability target,
/// and episode-policy version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscrepancyFamilyPreimageV1 {
    pub schema_version: u32,
    pub profile: ProfileReferenceV1,
    pub scope: AuthenticatedProjectScopeV1,
    pub finding_type: FindingType,
    pub canonical_subject: ResourceUri,
    pub predicate: RegistryReferenceV1,
    pub comparator_lineage_fingerprint: ComparatorLineageFingerprint,
    pub expectation_policy: RegistryReferenceV1,
    pub required_applicability_dimension_ids: Vec<ContractId>,
    pub applicability: Vec<ApplicabilityDimensionV1>,
    pub episode_policy_version: u32,
}

impl DiscrepancyFamilyPreimageV1 {
    /// A required dimension absent from `applicability` fails closed here. It is
    /// never silently treated as `any`: `any` can only ever come from an
    /// explicit [`ApplicabilityDimensionValueV1::Any`] entry actually present in
    /// the vector (APPL-02).
    pub fn validate_shape(&self) -> ContractResult<()> {
        self.profile.validate()?;
        self.predicate.validate()?;
        self.expectation_policy.validate()?;
        let valid = self.schema_version == DISCREPANCY_SCHEMA_VERSION
            && self.required_applicability_dimension_ids.len() <= MAX_APPLICABILITY_DIMENSIONS
            && strictly_sorted(&self.required_applicability_dimension_ids)
            && self.applicability.len() <= MAX_APPLICABILITY_DIMENSIONS
            && strictly_sorted_by_dimension(&self.applicability)
            && self
                .required_applicability_dimension_ids
                .iter()
                .all(|id| dimension_present(&self.applicability, id))
            && self.episode_policy_version > 0;
        if !valid {
            return Err(ContractError::Schema(
                "invalid discrepancy family fingerprint preimage".into(),
            ));
        }
        Ok(())
    }

    pub fn fingerprint(&self) -> ContractResult<DiscrepancyFamilyFingerprintV1> {
        self.validate_shape()?;
        Ok(DiscrepancyFamilyFingerprintV1::from_digest(
            domain_separated_digest(DigestDomain::DiscrepancyFamilyV1, &encode_canonical(self)?),
        ))
    }
}

// ---------------------------------------------------------------------------
// Episode policy V2 (doc lines 1329-1336, 1357-1358)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EpisodeWindowingV1 {
    NonWindowed,
    Windowed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EpisodeOpeningRuleV1 {
    FirstVerifiedIncompatibleObservation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EpisodeClosingRuleV1 {
    VerifiedCompatibleSupersessionOrScopeExit,
}

/// "Material comparator or predicate-schema changes create a new family linked
/// by supersession" (doc line 1357-1358) is the only registered algorithm today.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleChangeBehaviorV1 {
    NewFamilyLinkedBySupersession,
}

/// The only registered late-evidence algorithm.
///
/// Late evidence is inserted by effective interval, and replay creates
/// canonical replacement episodes, marking earlier projections superseded
/// (doc lines 1353-1356).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LateEvidenceBehaviorV1 {
    EffectiveIntervalReplayWithSupersession,
}

/// Every discrepancy type registers these per doc lines 1329-1336.
///
/// Continuity-key dimensions, opening rule, allowed observation gap,
/// closing/confirmation rule, rule-change behavior, late-evidence behavior,
/// and windowed vs non-windowed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpisodePolicyV2 {
    pub schema_version: u32,
    pub policy_id: ContractId,
    pub version: u32,
    pub continuity_key_dimension_ids: Vec<ContractId>,
    pub windowing: EpisodeWindowingV1,
    pub opening_rule: EpisodeOpeningRuleV1,
    /// `None` means no observation gap may be bridged: any missing interval ends
    /// the known observed interval (doc lines 1338-1341).
    pub allowed_observation_gap_seconds: Option<u64>,
    pub closing_rule: EpisodeClosingRuleV1,
    pub rule_change_behavior: RuleChangeBehaviorV1,
    pub late_evidence_behavior: LateEvidenceBehaviorV1,
}

impl EpisodePolicyV2 {
    pub fn validate_shape(&self) -> ContractResult<()> {
        let valid = self.schema_version == EPISODE_POLICY_SCHEMA_VERSION
            && self.version > 0
            && self.continuity_key_dimension_ids.len() <= MAX_CONTINUITY_KEY_DIMENSIONS
            && strictly_sorted(&self.continuity_key_dimension_ids);
        if !valid {
            return Err(ContractError::Schema("invalid episode policy".into()));
        }
        Ok(())
    }
}

/// One exact episode-policy registry entry whose reference and body agree.
///
/// Named `StructurallyResolved`, not `Verified` or `Active`, matching the
/// identical convention in `evidence_v2.rs`'s
/// `StructurallyResolvedConnectorSchemaV2`: any caller can construct
/// registry-entry bytes. Runtime admission must additionally prove membership
/// in the exact active package/head before trusting this as the effective
/// policy. `registry_reference().entry_digest` is `RegistryEntryV1::digest()`
/// -- the same generic, already-existing digest domain every registry entry in
/// this crate is checked against -- so a `DiscrepancyEnvelopeV1.episode_policy`
/// reference can be proven to name this exact policy body, not merely a
/// same-shaped one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructurallyResolvedEpisodePolicyV2 {
    registry_reference: RegistryReferenceV1,
    policy: EpisodePolicyV2,
}

impl StructurallyResolvedEpisodePolicyV2 {
    pub fn from_registry_entry(entry: &RegistryEntryV1) -> ContractResult<Self> {
        entry.validate()?;
        if entry.kind != RegistryEntryKind::EpisodePolicy
            || entry.entry_schema_id.as_str() != EPISODE_POLICY_ENTRY_SCHEMA_ID
            || entry.entry_schema_version != EPISODE_POLICY_SCHEMA_VERSION
        {
            return Err(ContractError::Schema(
                "registry entry is not an episode policy v2 body".into(),
            ));
        }
        let body_bytes = encode_canonical(&entry.body)?;
        let policy: EpisodePolicyV2 = decode_strict(&body_bytes)?;
        policy.validate_shape()?;
        let identity_matches = policy.policy_id == entry.entry_id;
        let version_matches = policy.version == entry.version;
        if !identity_matches || !version_matches {
            return Err(ContractError::ManifestMismatch);
        }
        Ok(Self {
            registry_reference: RegistryReferenceV1 {
                entry_id: entry.entry_id.clone(),
                version: entry.version,
                entry_digest: entry.digest()?,
            },
            policy,
        })
    }

    pub const fn policy(&self) -> &EpisodePolicyV2 {
        &self.policy
    }

    pub const fn registry_reference(&self) -> &RegistryReferenceV1 {
        &self.registry_reference
    }
}

// ---------------------------------------------------------------------------
// Opening transition -- pure total order, never receipt order (doc lines 1321-1327)
// ---------------------------------------------------------------------------

/// One candidate opening observation.
///
/// Field declaration order is the tie-break order: effective time, then
/// registered provider order, then stable source-fact identity as the final
/// tie-break -- receipt order never participates because no receipt-order
/// field exists on this type at all.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpeningTransitionCandidateV1 {
    pub effective_at: CanonicalTimestamp,
    pub provider_order: u32,
    pub source_fact_id: SourceFactId,
}

/// Select the deterministic opening transition from a candidate set.
///
/// The result does not depend on the order candidates are passed in (proven
/// by `opening_transition_selection_is_receipt_order_independent`).
pub fn select_opening_transition(
    candidates: &[OpeningTransitionCandidateV1],
) -> ContractResult<&OpeningTransitionCandidateV1> {
    candidates.iter().min().ok_or_else(|| {
        ContractError::Schema("opening transition selection requires at least one candidate".into())
    })
}

// ---------------------------------------------------------------------------
// Discrepancy episode fingerprint (doc lines 1321-1327)
// ---------------------------------------------------------------------------

/// Preimage for [`DiscrepancyEpisodeFingerprintV1`].
///
/// Binds family fingerprint, normalized continuity-key values, the
/// deterministic opening transition's source-fact identity, and
/// episode-policy version. Effective time and provider order participate
/// only in *selecting* the winning candidate, never in the fingerprint
/// content itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscrepancyEpisodePreimageV1 {
    pub schema_version: u32,
    pub family_fingerprint: DiscrepancyFamilyFingerprintV1,
    pub continuity_key: Vec<ApplicabilityDimensionV1>,
    pub opening_transition_source_fact_id: SourceFactId,
    pub episode_policy_version: u32,
}

impl DiscrepancyEpisodePreimageV1 {
    pub fn validate_shape(&self) -> ContractResult<()> {
        let valid = self.schema_version == DISCREPANCY_SCHEMA_VERSION
            && self.continuity_key.len() <= MAX_CONTINUITY_KEY_DIMENSIONS
            && strictly_sorted_by_dimension(&self.continuity_key)
            && self.episode_policy_version > 0;
        if !valid {
            return Err(ContractError::Schema(
                "invalid discrepancy episode fingerprint preimage".into(),
            ));
        }
        Ok(())
    }

    pub fn fingerprint(&self) -> ContractResult<DiscrepancyEpisodeFingerprintV1> {
        self.validate_shape()?;
        Ok(DiscrepancyEpisodeFingerprintV1::from_digest(
            domain_separated_digest(DigestDomain::DiscrepancyEpisodeV1, &encode_canonical(self)?),
        ))
    }
}

// ---------------------------------------------------------------------------
// Severity, lifecycle state, verification state (doc lines 657-660)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscrepancySeverityV1 {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// "Verification states are `candidate`, `verified`, `refuted`, and
/// `indeterminate`." (doc line 657) Separate axis from [`LifecycleState`]: it
/// changes without erasing lifecycle events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationState {
    Candidate,
    Verified,
    Refuted,
    Indeterminate,
}

/// "Lifecycle states are `open`, `acknowledged`, `resolved`, `waived`,
/// `dismissed`, and `superseded`." (doc lines 658-659)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleState {
    Open,
    Acknowledged,
    Resolved,
    Waived,
    Dismissed,
    Superseded,
}

// ---------------------------------------------------------------------------
// Discrepancy envelope (doc lines 626-638) -- the immutable per-detection identity
// ---------------------------------------------------------------------------

/// The generalized discrepancy envelope's immutable identity content.
///
/// Lifecycle state, verification state, and acknowledge/waive/resolve times
/// are deliberately absent: they are rebuilt by [`project_discrepancy_episode`]
/// over the append-only [`DiscrepancyLifecycleEventV1`] history, so they can
/// never affect `family_fingerprint` or `episode_fingerprint`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscrepancyEnvelopeV1 {
    pub schema_version: u32,
    pub event_kind: ContractId,
    pub profile: ProfileReferenceV1,
    pub scope: AuthenticatedProjectScopeV1,
    pub finding_type: FindingType,
    pub severity: DiscrepancySeverityV1,
    pub canonical_subject: ResourceUri,
    pub predicate: RegistryReferenceV1,
    pub comparator_lineage_fingerprint: ComparatorLineageFingerprint,
    pub expectation_policy: RegistryReferenceV1,
    pub episode_policy: RegistryReferenceV1,
    pub required_applicability_dimension_ids: Vec<ContractId>,
    pub applicability: Vec<ApplicabilityDimensionV1>,
    pub continuity_key_dimension_ids: Vec<ContractId>,
    pub family_fingerprint: DiscrepancyFamilyFingerprintV1,
    pub opening_transition: OpeningTransitionCandidateV1,
    pub episode_fingerprint: DiscrepancyEpisodeFingerprintV1,
    pub registry: RegistryHeadBindingV1,
    pub detector: RegistryReferenceV1,
    pub extractor: Option<RegistryReferenceV1>,
    pub member_evidence_ids: Vec<AcceptedEventId>,
    pub supporting_evidence_ids: Vec<AcceptedEventId>,
    pub opposing_evidence_ids: Vec<AcceptedEventId>,
    pub coverage_receipt_ids: Vec<AcceptedEventId>,
    /// Authors/actors implicated by this finding (e.g. the authors of
    /// conflicting claims). Used to enforce AUTH-03 self-dismissal and DISC-05
    /// waiver separation-of-duty; never used to grant authority.
    pub implicated_actor_ids: Vec<ContractId>,
    pub initial_verification_state: VerificationState,
    pub detected_at: CanonicalTimestamp,
    pub effective_from: CanonicalTimestamp,
    pub effective_until: Option<CanonicalTimestamp>,
}

impl DiscrepancyEnvelopeV1 {
    pub fn validate_shape(&self) -> ContractResult<()> {
        self.profile.validate()?;
        self.registry.validate_shape()?;
        self.predicate.validate()?;
        self.expectation_policy.validate()?;
        self.episode_policy.validate()?;
        self.detector.validate()?;
        if let Some(extractor) = &self.extractor {
            extractor.validate()?;
        }

        let structurally_valid = self.schema_version == DISCREPANCY_SCHEMA_VERSION
            && self.event_kind.as_str() == DISCREPANCY_ENVELOPE_EVENT_KIND
            && self.required_applicability_dimension_ids.len() <= MAX_APPLICABILITY_DIMENSIONS
            && strictly_sorted(&self.required_applicability_dimension_ids)
            && self.applicability.len() <= MAX_APPLICABILITY_DIMENSIONS
            && strictly_sorted_by_dimension(&self.applicability)
            && self
                .required_applicability_dimension_ids
                .iter()
                .all(|id| dimension_present(&self.applicability, id))
            && self.continuity_key_dimension_ids.len() <= MAX_CONTINUITY_KEY_DIMENSIONS
            && strictly_sorted(&self.continuity_key_dimension_ids)
            && self
                .continuity_key_dimension_ids
                .iter()
                .all(|id| dimension_present(&self.applicability, id))
            && !self.member_evidence_ids.is_empty()
            && self.member_evidence_ids.len() <= MAX_EVIDENCE_EVENT_IDS
            && strictly_sorted(&self.member_evidence_ids)
            && !self.supporting_evidence_ids.is_empty()
            && self.supporting_evidence_ids.len() <= MAX_EVIDENCE_EVENT_IDS
            && strictly_sorted(&self.supporting_evidence_ids)
            && self.opposing_evidence_ids.len() <= MAX_EVIDENCE_EVENT_IDS
            && strictly_sorted(&self.opposing_evidence_ids)
            && self.coverage_receipt_ids.len() <= MAX_EVIDENCE_EVENT_IDS
            && strictly_sorted(&self.coverage_receipt_ids)
            && self.implicated_actor_ids.len() <= MAX_IMPLICATED_ACTORS
            && strictly_sorted(&self.implicated_actor_ids)
            && self
                .effective_until
                .as_ref()
                .is_none_or(|until| until > &self.effective_from);
        if !structurally_valid {
            return Err(ContractError::Schema("invalid discrepancy envelope".into()));
        }

        if self.family_fingerprint != self.compute_family_fingerprint()? {
            return Err(ContractError::Schema(
                "envelope family fingerprint does not match its own fields".into(),
            ));
        }
        if self.episode_fingerprint != self.compute_episode_fingerprint()? {
            return Err(ContractError::Schema(
                "envelope episode fingerprint does not match its own fields".into(),
            ));
        }
        Ok(())
    }

    fn compute_family_fingerprint(&self) -> ContractResult<DiscrepancyFamilyFingerprintV1> {
        DiscrepancyFamilyPreimageV1 {
            schema_version: DISCREPANCY_SCHEMA_VERSION,
            profile: self.profile.clone(),
            scope: self.scope.clone(),
            finding_type: self.finding_type,
            canonical_subject: self.canonical_subject.clone(),
            predicate: self.predicate.clone(),
            comparator_lineage_fingerprint: self.comparator_lineage_fingerprint,
            expectation_policy: self.expectation_policy.clone(),
            required_applicability_dimension_ids: self.required_applicability_dimension_ids.clone(),
            applicability: self.applicability.clone(),
            episode_policy_version: self.episode_policy.version,
        }
        .fingerprint()
    }

    fn continuity_key(&self) -> Vec<ApplicabilityDimensionV1> {
        self.continuity_key_dimension_ids
            .iter()
            .filter_map(|id| {
                self.applicability
                    .iter()
                    .find(|dimension| &dimension.dimension_id == id)
                    .cloned()
            })
            .collect()
    }

    fn compute_episode_fingerprint(&self) -> ContractResult<DiscrepancyEpisodeFingerprintV1> {
        DiscrepancyEpisodePreimageV1 {
            schema_version: DISCREPANCY_SCHEMA_VERSION,
            family_fingerprint: self.compute_family_fingerprint()?,
            continuity_key: self.continuity_key(),
            opening_transition_source_fact_id: self.opening_transition.source_fact_id,
            episode_policy_version: self.episode_policy.version,
        }
        .fingerprint()
    }

    pub fn envelope_id(&self) -> ContractResult<DiscrepancyEnvelopeId> {
        self.validate_shape()?;
        Ok(DiscrepancyEnvelopeId::from_digest(domain_separated_digest(
            DigestDomain::DiscrepancyEnvelopeV1,
            &encode_canonical(self)?,
        )))
    }

    /// Bind this envelope's `episode_policy` reference and
    /// `continuity_key_dimension_ids` to the exact registered
    /// [`EpisodePolicyV2`], closing the payload-selected-authority gap left by
    /// `validate_shape` alone: `validate_shape` only proves the declared
    /// continuity key is a subset of `applicability` and sorted, never that it
    /// matches what the named policy actually registers. Without this seam a
    /// producer could cite the same `episode_policy` reference while declaring
    /// any continuity-key subset it likes -- including the empty set -- making
    /// episode identity producer-selected rather than policy-derived. A caller
    /// that skips this check when accepting an envelope re-opens exactly that
    /// gap; it is not folded into `validate_shape` because that method has no
    /// access to the resolved policy body.
    pub fn validate_against_episode_policy(
        &self,
        policy: &StructurallyResolvedEpisodePolicyV2,
    ) -> ContractResult<()> {
        self.validate_shape()?;
        if self.episode_policy != *policy.registry_reference() {
            return Err(ContractError::ManifestMismatch);
        }
        if self.continuity_key_dimension_ids != policy.policy().continuity_key_dimension_ids {
            return Err(ContractError::Schema(
                "envelope continuity-key dimensions diverge from the registered episode policy"
                    .into(),
            ));
        }
        Ok(())
    }

    /// Bind this envelope's `comparator_lineage_fingerprint` and
    /// `required_applicability_dimension_ids` to the exact registered
    /// [`ComparatorLineageV1`], closing the payload-selected-authority gap
    /// left by `validate_shape` alone: `validate_shape` only proves the
    /// envelope's own applicability is internally consistent (sorted, and a
    /// superset of whatever the *producer* declared as required), never that
    /// `comparator_lineage_fingerprint` actually names a registered lineage,
    /// nor that the envelope actually satisfies that lineage's own
    /// `concrete_applicability_required` / `coverage_proof_required` flags.
    /// Proves, in order:
    /// (a) `comparator_lineage_fingerprint` equals `resolved.lineage()`'s own
    ///     fingerprint;
    /// (d) `required_applicability_dimension_ids` equals the registry's set
    ///     for this lineage, not the payload's own declaration;
    /// (b) if `concrete_applicability_required`, every required dimension
    ///     resolves to `Concrete`, never `Any`;
    /// (c) if `coverage_proof_required`, `coverage_receipt_ids` is non-empty.
    /// A runtime admitting an envelope as an accepted event must call this in
    /// addition to `validate_shape`, mirroring
    /// `validate_against_episode_policy`.
    pub fn validate_against_comparator_lineage(
        &self,
        resolved: &StructurallyResolvedComparatorLineageV1,
    ) -> ContractResult<()> {
        self.validate_shape()?;
        let lineage = resolved.lineage();
        if self.comparator_lineage_fingerprint != lineage.fingerprint()? {
            return Err(ContractError::ManifestMismatch);
        }
        if self.required_applicability_dimension_ids
            != resolved.required_applicability_dimension_ids()
        {
            return Err(ContractError::Schema(
                "envelope required_applicability_dimension_ids diverges from the registered comparator lineage"
                    .into(),
            ));
        }
        if lineage.concrete_applicability_required {
            let all_concrete = resolved
                .required_applicability_dimension_ids()
                .iter()
                .all(|id| {
                    self.applicability
                        .iter()
                        .find(|dimension| &dimension.dimension_id == id)
                        .is_some_and(|dimension| {
                            matches!(
                                dimension.value,
                                ApplicabilityDimensionValueV1::Concrete { .. }
                            )
                        })
                });
            if !all_concrete {
                return Err(ContractError::Schema(
                    "comparator lineage requires concrete applicability for every required dimension"
                        .into(),
                ));
            }
        }
        if lineage.coverage_proof_required && self.coverage_receipt_ids.is_empty() {
            return Err(ContractError::Schema(
                "comparator lineage requires at least one coverage receipt".into(),
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Lifecycle events, waivers, dismissals (DISC-03, DISC-05, AUTH-03)
// ---------------------------------------------------------------------------

/// Server-bound actor identity, descriptive until trusted admission proves it
/// from credential context (matches `RememberActorV2`'s convention).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscrepancyActorV1 {
    pub principal_id: ContractId,
}

/// Closed waiver reason taxonomy (DISC-05: "explicit, attributed, scoped").
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WaiverReasonKindV1 {
    CapacityDeferred,
    CostExceedsRisk,
    UpstreamBlocked,
    PolicyException,
    ScheduledRemediation,
}

/// Signed-lifecycle-event shape for a waiver (DISC-05).
///
/// `actor` and `expiry_at` are mandatory fields, not `Option`, so "waiver
/// without actor" and "waiver without expiry" cannot even be constructed by a
/// well-typed caller; wire input omitting either fails to deserialize at all
/// under `deny_unknown_fields`. `review_by` is the softer, optional companion
/// checkpoint distinct from the hard `expiry_at`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WaiverRecordV1 {
    pub actor: DiscrepancyActorV1,
    pub reason_kind: WaiverReasonKindV1,
    pub rationale: String,
    /// Empty means the waiver applies to the full episode applicability; a
    /// non-empty scope narrows it. It never widens or erases the underlying
    /// incompatible interval (DISC-05, DISC-03).
    ///
    /// Chosen semantics (DISC-05 "a waiver is ... scoped"): every entry here
    /// must exactly match (same `dimension_id`, same `value`) an entry
    /// actually present in the target envelope's `applicability`.
    /// `authorize_lifecycle_transition` rejects the transition outright --
    /// full stop, not a partial-suppression projection -- whenever a scope
    /// entry names a dimension the envelope does not carry, or names a
    /// concrete value that disagrees with the envelope's value for that
    /// dimension. A waiver that clears this check suppresses the whole
    /// episode; there is no third, silently-accepted "narrower than the
    /// envelope but still applied" outcome. See
    /// `waiver_scope_covers_envelope`.
    pub applicability_scope: Vec<ApplicabilityDimensionV1>,
    pub expiry_at: CanonicalTimestamp,
    pub review_by: Option<CanonicalTimestamp>,
}

impl WaiverRecordV1 {
    pub fn validate_shape(&self) -> ContractResult<()> {
        let valid = !self.rationale.trim().is_empty()
            && self.rationale.len() <= MAX_RATIONALE_BYTES
            && self.applicability_scope.len() <= MAX_APPLICABILITY_DIMENSIONS
            && strictly_sorted_by_dimension(&self.applicability_scope)
            && self
                .review_by
                .as_ref()
                .is_none_or(|review_by| review_by <= &self.expiry_at);
        if !valid {
            return Err(ContractError::Schema("invalid waiver record".into()));
        }
        Ok(())
    }
}

/// Closed dismissal reason taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DismissalReasonKindV1 {
    FalsePositive,
    DuplicateOfOtherEpisode,
    OutOfScope,
    NotReproducible,
}

/// A structured dismissal reason. `rationale` must be non-empty: "dismiss
/// without justification" fails [`DiscrepancyLifecycleEventV1::validate_shape`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DismissalReasonV1 {
    pub kind: DismissalReasonKindV1,
    pub rationale: String,
}

impl DismissalReasonV1 {
    fn validate_shape(&self) -> ContractResult<()> {
        if self.rationale.trim().is_empty() || self.rationale.len() > MAX_RATIONALE_BYTES {
            return Err(ContractError::Schema(
                "dismissal requires a non-empty, bounded rationale".into(),
            ));
        }
        Ok(())
    }
}

/// Closed lifecycle transition taxonomy. Exactly one may be carried per
/// [`DiscrepancyLifecycleEventV1`] (or none, if the event carries only a
/// verification update).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "transition", rename_all = "snake_case", deny_unknown_fields)]
pub enum LifecycleTransitionV1 {
    Acknowledge {
        actor: DiscrepancyActorV1,
    },
    Waive {
        waiver: WaiverRecordV1,
    },
    /// DISC-03: resolution appends evidence. `resolution_evidence_ids` must be
    /// non-empty -- a resolution with no cited evidence is rejected.
    Resolve {
        actor: DiscrepancyActorV1,
        resolution_evidence_ids: Vec<AcceptedEventId>,
    },
    Dismiss {
        actor: DiscrepancyActorV1,
        reason: DismissalReasonV1,
    },
}

/// Attributed verification-state change (AUTH-03, PRED-01, PRED-05).
///
/// A bare `Option<VerificationState>` on the wire would let any event flip a
/// finding's verification state with no actor at all to authorize or
/// attribute against -- including an unattributed `Refuted` flip reachable by
/// an implicated actor precisely because no actor field exists to check, and
/// an evidence-free promotion straight to `Verified`. `actor` is mandatory
/// (not `Option`), so an unattributed verification change cannot even be
/// constructed by a well-typed caller or deserialized under
/// `deny_unknown_fields`. Promotion to `Verified` additionally requires a
/// non-empty `evidence_event_ids` here, at shape validation, rather than
/// leaving PRED-01/PRED-05's "a verified discrepancy cites evidence"
/// requirement to a caller who might forget to check it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationUpdateV1 {
    pub actor: DiscrepancyActorV1,
    pub state: VerificationState,
    pub evidence_event_ids: Vec<AcceptedEventId>,
}

impl VerificationUpdateV1 {
    fn validate_shape(&self) -> ContractResult<()> {
        let valid = self.evidence_event_ids.len() <= MAX_EVIDENCE_EVENT_IDS
            && strictly_sorted(&self.evidence_event_ids)
            && (self.state != VerificationState::Verified || !self.evidence_event_ids.is_empty());
        if !valid {
            return Err(ContractError::Schema(
                "invalid verification update: promotion to verified requires non-empty evidence"
                    .into(),
            ));
        }
        Ok(())
    }
}

/// Append-only discrepancy lifecycle transition, targeting one exact episode.
///
/// It contains no storage locator, receipt clock, epoch, shard, offset, or
/// append-chain field: physical append order can never affect projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscrepancyLifecycleEventV1 {
    pub schema_version: u32,
    pub event_kind: ContractId,
    pub profile: ProfileReferenceV1,
    pub scope: AuthenticatedProjectScopeV1,
    pub episode_fingerprint: DiscrepancyEpisodeFingerprintV1,
    pub effective_at: CanonicalTimestamp,
    /// Independent of `lifecycle_transition`: verification state "changes
    /// without erasing lifecycle events" (doc line 665). Attributed and, for
    /// promotion to `Verified`, evidenced -- see [`VerificationUpdateV1`].
    pub verification_update: Option<VerificationUpdateV1>,
    pub lifecycle_transition: Option<LifecycleTransitionV1>,
    pub evidence_event_ids: Vec<AcceptedEventId>,
}

impl DiscrepancyLifecycleEventV1 {
    pub fn validate_shape(&self) -> ContractResult<()> {
        self.profile.validate()?;
        if let Some(update) = &self.verification_update {
            update.validate_shape()?;
        }
        if let Some(LifecycleTransitionV1::Waive { waiver }) = &self.lifecycle_transition {
            waiver.validate_shape()?;
        }
        if let Some(LifecycleTransitionV1::Dismiss { reason, .. }) = &self.lifecycle_transition {
            reason.validate_shape()?;
        }

        let resolution_evidence_valid = match &self.lifecycle_transition {
            Some(LifecycleTransitionV1::Resolve {
                resolution_evidence_ids,
                ..
            }) => {
                !resolution_evidence_ids.is_empty()
                    && resolution_evidence_ids.len() <= MAX_EVIDENCE_EVENT_IDS
                    && strictly_sorted(resolution_evidence_ids)
            }
            _ => true,
        };

        let valid = self.schema_version == DISCREPANCY_SCHEMA_VERSION
            && self.event_kind.as_str() == DISCREPANCY_LIFECYCLE_EVENT_KIND
            && self.evidence_event_ids.len() <= MAX_EVIDENCE_EVENT_IDS
            && strictly_sorted(&self.evidence_event_ids)
            && (self.verification_update.is_some() || self.lifecycle_transition.is_some())
            && resolution_evidence_valid;
        if !valid {
            return Err(ContractError::Schema(
                "invalid discrepancy lifecycle event".into(),
            ));
        }
        Ok(())
    }

    pub fn lifecycle_event_id(&self) -> ContractResult<DiscrepancyLifecycleEventId> {
        self.validate_shape()?;
        Ok(DiscrepancyLifecycleEventId::from_digest(
            domain_separated_digest(
                DigestDomain::DiscrepancyLifecycleEventV1,
                &encode_canonical(self)?,
            ),
        ))
    }
}

/// True when `principal_id` is one of the envelope's implicated actors.
///
/// Requires `envelope.implicated_actor_ids` to already be proven sorted
/// (`DiscrepancyEnvelopeV1::validate_shape`) before this `binary_search` can be
/// trusted.
fn is_self_implicated(envelope: &DiscrepancyEnvelopeV1, principal_id: &ContractId) -> bool {
    envelope
        .implicated_actor_ids
        .binary_search(principal_id)
        .is_ok()
}

/// True when every entry in `scope` exactly matches (same `dimension_id`,
/// same `value`) an entry actually present in `applicability`.
///
/// An empty `scope` vacuously covers (DISC-05: "empty means the waiver
/// applies to the full episode applicability"). A non-empty `scope` entry
/// naming a dimension the envelope does not carry at all, or naming a
/// concrete value that disagrees with the envelope's value for that
/// dimension, does not cover -- without this check `applicability_scope` is
/// otherwise decorative: a field no code path reads is worse than no field
/// at all, since it reads as enforcement in review and grants none.
fn waiver_scope_covers_envelope(
    scope: &[ApplicabilityDimensionV1],
    applicability: &[ApplicabilityDimensionV1],
) -> bool {
    scope.iter().all(|scoped| {
        applicability.iter().any(|dimension| {
            dimension.dimension_id == scoped.dimension_id && dimension.value == scoped.value
        })
    })
}

/// Authorize one lifecycle event against its target envelope.
///
/// The event's authenticated `scope`/`profile` must match the envelope's own
/// (a lifecycle event's episode fingerprint is a public identifier, not a
/// secret, so knowledge of it alone must never authorize a cross-tenant
/// transition -- matching the `self.scope != other.scope` convention used by
/// every sibling contract in this crate: relation.rs, `remember_v2.rs`,
/// `evidence_v2.rs`, evidence.rs, control.rs, bootstrap.rs, `genesis_activation.rs`,
/// `successor_activation.rs`, `successor_policy.rs`). The episode must also match.
///
/// AUTH-03 ("an agent ... cannot ... silently resolve its own discrepancy")
/// applies to every transition that clears or suppresses active surfacing of a
/// discrepancy an actor is implicated in: `Dismiss`, `Resolve`, and `Waive`
/// alike. It is enforced uniformly across every [`FindingType`], not narrowed
/// to `claim_conflict` -- the doc's wording is not scoped to claim authorship,
/// and `implicated_actor_ids` is itself a generic field any finding type may
/// populate. `Acknowledge` is deliberately exempt: acknowledging a discrepancy
/// one is implicated in does not resolve or suppress it.
///
/// DISC-05 ("a waiver is explicit, attributed, scoped"): a `Waive` transition
/// is additionally rejected outright when its `waiver.applicability_scope`
/// does not cover the envelope's `applicability`
/// (`waiver_scope_covers_envelope`) -- an out-of-scope or alien-dimension
/// scope can no longer suppress the episode at all.
pub fn authorize_lifecycle_transition(
    envelope: &DiscrepancyEnvelopeV1,
    event: &DiscrepancyLifecycleEventV1,
) -> ContractResult<()> {
    envelope.validate_shape()?;
    event.validate_shape()?;
    if event.scope != envelope.scope || event.profile != envelope.profile {
        return Err(ContractError::Schema(
            "lifecycle event scope/profile does not match its envelope".into(),
        ));
    }
    if event.episode_fingerprint != envelope.episode_fingerprint {
        return Err(ContractError::Schema(
            "lifecycle event targets a different episode than its envelope".into(),
        ));
    }
    if let Some(transition) = &event.lifecycle_transition {
        match transition {
            LifecycleTransitionV1::Dismiss { actor, .. } => {
                if is_self_implicated(envelope, &actor.principal_id) {
                    return Err(ContractError::Schema(
                        "AUTH-03: an implicated actor cannot dismiss their own discrepancy".into(),
                    ));
                }
            }
            LifecycleTransitionV1::Resolve { actor, .. } => {
                if is_self_implicated(envelope, &actor.principal_id) {
                    return Err(ContractError::Schema(
                        "AUTH-03: an implicated actor cannot resolve their own discrepancy".into(),
                    ));
                }
            }
            LifecycleTransitionV1::Waive { waiver } => {
                if is_self_implicated(envelope, &waiver.actor.principal_id) {
                    return Err(ContractError::Schema(
                        "AUTH-03: an implicated actor cannot waive their own discrepancy".into(),
                    ));
                }
                if !waiver_scope_covers_envelope(
                    &waiver.applicability_scope,
                    &envelope.applicability,
                ) {
                    return Err(ContractError::Schema(
                        "DISC-05: waiver applicability_scope does not cover the envelope's applicability"
                            .into(),
                    ));
                }
            }
            LifecycleTransitionV1::Acknowledge { .. } => {}
        }
    }
    // AUTH-03 also covers a bare verification-state change: refuting a
    // finding is the strongest possible suppression a verification update can
    // achieve, so it is gated by the same self-implication check as
    // Dismiss/Resolve/Waive, at minimum. Promotion to `Verified` with no
    // evidence is rejected earlier, structurally, by
    // `VerificationUpdateV1::validate_shape`.
    if let Some(update) = &event.verification_update
        && update.state == VerificationState::Refuted
        && is_self_implicated(envelope, &update.actor.principal_id)
    {
        return Err(ContractError::Schema(
            "AUTH-03: an implicated actor cannot refute their own finding".into(),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Episode relations: combined_from / continues / possibly_continues / superseded
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EpisodeRelationKindV1 {
    CombinedFrom,
    Continues,
    PossiblyContinues,
    Superseded,
}

/// An explicit, non-destructive relation between episodes. `combined_from`
/// requires at least two sources; the other kinds require exactly one. The
/// target may never also appear as one of its own sources.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscrepancyEpisodeRelationV1 {
    pub schema_version: u32,
    pub kind: EpisodeRelationKindV1,
    pub from_episodes: Vec<DiscrepancyEpisodeFingerprintV1>,
    pub to_episode: DiscrepancyEpisodeFingerprintV1,
}

impl DiscrepancyEpisodeRelationV1 {
    pub fn validate_shape(&self) -> ContractResult<()> {
        let arity_valid = match self.kind {
            EpisodeRelationKindV1::CombinedFrom => self.from_episodes.len() >= 2,
            EpisodeRelationKindV1::Continues
            | EpisodeRelationKindV1::PossiblyContinues
            | EpisodeRelationKindV1::Superseded => self.from_episodes.len() == 1,
        };
        let valid = self.schema_version == DISCREPANCY_SCHEMA_VERSION
            && arity_valid
            && strictly_sorted(&self.from_episodes)
            && !self.from_episodes.contains(&self.to_episode);
        if !valid {
            return Err(ContractError::Schema(
                "invalid discrepancy episode relation".into(),
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Pure replay projection (REPLAY-01, DISC-03)
// ---------------------------------------------------------------------------

/// Rebuildable current state of one episode.
///
/// Lifecycle state, verification state, and (if waived, even after expiry)
/// the waiver context. Deliberately `Serialize`-only, like
/// `RelationProjectionV1`: it is a server-derived projection, not
/// authority-bearing wire input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiscrepancyEpisodeProjectionV1 {
    pub episode_fingerprint: DiscrepancyEpisodeFingerprintV1,
    pub lifecycle_state: LifecycleState,
    pub verification_state: VerificationState,
    /// Populated whenever a waiver has ever been applied, including after its
    /// expiry has reopened the episode -- surfacing keeps its waiver context.
    pub active_waiver: Option<WaiverRecordV1>,
    pub acknowledged_at: Option<CanonicalTimestamp>,
    pub waived_at: Option<CanonicalTimestamp>,
    pub resolved_at: Option<CanonicalTimestamp>,
    pub resolution_evidence_ids: Vec<AcceptedEventId>,
    pub applied_event_count: usize,
}

/// Deterministically replay one envelope's lifecycle events into current state.
///
/// Events are ordered by `(effective_at, canonical event bytes)`, never by
/// input `Vec` position, so passing the same events in a different order always
/// yields an identical result (REPLAY-01). `evaluation_time` is a pure input: a
/// waiver whose `expiry_at` has passed returns the lifecycle state to `open`
/// without erasing or splitting the underlying interval and without discarding
/// the waiver context (DISC-05, DISC-03).
///
/// `relations` is the full set of [`DiscrepancyEpisodeRelationV1`] records that
/// may name this envelope's episode. Whenever a `superseded` relation's
/// `from_episodes` contains `envelope.episode_fingerprint` -- i.e. this is the
/// OLD side of a canonical replacement -- the projection is
/// [`LifecycleState::Superseded`], overriding whatever lifecycle transitions
/// replayed above it (a replaced episode is frozen, not reopened by a later
/// waiver expiry). This is the only producer of `Superseded`: the variant is
/// otherwise unreachable, matching the doc's "replay ... marks the earlier
/// projections superseded, retaining explicit `combined_from` or `continues`
/// relations." Pass `&[]` when no relation set applies (an episode with no
/// known supersession is never superseded).
pub fn project_discrepancy_episode(
    envelope: &DiscrepancyEnvelopeV1,
    events: &[DiscrepancyLifecycleEventV1],
    relations: &[DiscrepancyEpisodeRelationV1],
    evaluation_time: &CanonicalTimestamp,
) -> ContractResult<DiscrepancyEpisodeProjectionV1> {
    envelope.validate_shape()?;
    for event in events {
        authorize_lifecycle_transition(envelope, event)?;
    }
    for relation in relations {
        relation.validate_shape()?;
    }

    let mut ordered: Vec<(&DiscrepancyLifecycleEventV1, Vec<u8>)> = events
        .iter()
        .map(|event| Ok((event, encode_canonical(event)?)))
        .collect::<ContractResult<_>>()?;
    ordered.sort_by(|(left_event, left_bytes), (right_event, right_bytes)| {
        left_event
            .effective_at
            .cmp(&right_event.effective_at)
            .then_with(|| left_bytes.cmp(right_bytes))
    });

    let mut state = DiscrepancyEpisodeProjectionV1 {
        episode_fingerprint: envelope.episode_fingerprint,
        lifecycle_state: LifecycleState::Open,
        verification_state: envelope.initial_verification_state,
        active_waiver: None,
        acknowledged_at: None,
        waived_at: None,
        resolved_at: None,
        resolution_evidence_ids: Vec::new(),
        applied_event_count: 0,
    };

    for (event, _) in ordered {
        if let Some(update) = &event.verification_update {
            state.verification_state = update.state;
        }
        match &event.lifecycle_transition {
            Some(LifecycleTransitionV1::Acknowledge { .. }) => {
                if state.lifecycle_state == LifecycleState::Open {
                    state.lifecycle_state = LifecycleState::Acknowledged;
                }
                state
                    .acknowledged_at
                    .get_or_insert_with(|| event.effective_at.clone());
            }
            Some(LifecycleTransitionV1::Waive { waiver }) => {
                state.lifecycle_state = LifecycleState::Waived;
                state.waived_at = Some(event.effective_at.clone());
                state.active_waiver = Some(waiver.clone());
            }
            Some(LifecycleTransitionV1::Resolve {
                resolution_evidence_ids,
                ..
            }) => {
                state.lifecycle_state = LifecycleState::Resolved;
                state.resolved_at = Some(event.effective_at.clone());
                // DISC-03: "prior finding and resolution history remains
                // immutable" -- a later resolution (e.g. after a reopen) must
                // never drop evidence cited by an earlier one. Accumulate,
                // then sort and dedup so the result is order-independent
                // regardless of how many Resolve transitions replay applies.
                state
                    .resolution_evidence_ids
                    .extend(resolution_evidence_ids.iter().copied());
                state.resolution_evidence_ids.sort_unstable();
                state.resolution_evidence_ids.dedup();
            }
            Some(LifecycleTransitionV1::Dismiss { .. }) => {
                state.lifecycle_state = LifecycleState::Dismissed;
            }
            None => {}
        }
        state.applied_event_count += 1;
    }

    // Waiver expiry is a pure function of `evaluation_time`, not a stored event:
    // it never rewrites the interval and never discards the waiver context; it
    // only returns the still-continuing episode to `open`.
    if state.lifecycle_state == LifecycleState::Waived
        && let Some(waiver) = &state.active_waiver
        && &waiver.expiry_at <= evaluation_time
    {
        state.lifecycle_state = LifecycleState::Open;
    }

    // A canonical replacement freezes the old side's projection: this check
    // runs last so supersession dominates every event-driven transition and
    // the waiver-expiry reopen above, retaining the episode's history without
    // erasing it (doc: "marks the earlier projections superseded, retaining
    // explicit ... relations").
    let is_superseded = relations.iter().any(|relation| {
        relation.kind == EpisodeRelationKindV1::Superseded
            && relation
                .from_episodes
                .contains(&envelope.episode_fingerprint)
    });
    if is_superseded {
        state.lifecycle_state = LifecycleState::Superseded;
    }

    Ok(state)
}

/// A family with at least `threshold` waivers is a drift signal, not a
/// verified finding.
///
/// The return type structurally cannot express `Verified` -- nomination is
/// always `candidate_only`, no matter how large `waiver_count` grows (PRED-01:
/// similarity/pattern signals cannot open a verified discrepancy on their
/// own).
pub fn nominate_repeated_waiver_drift(
    waiver_count: usize,
    threshold: usize,
) -> ContractResult<Option<VerificationState>> {
    if threshold == 0 {
        return Err(ContractError::Schema(
            "repeated-waiver drift threshold must be positive".into(),
        ));
    }
    Ok((waiver_count >= threshold).then_some(VerificationState::Candidate))
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path, str::FromStr};

    use sha2::{Digest as _, Sha256};

    use super::*;
    use crate::memory_contracts::{
        canonical::{CanonicalValue, decode_strict, require_canonical},
        common::frozen_profile_reference_v1,
        identity::IdentityForm,
        registry::RegistryHeadV1,
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
    const LIFECYCLE_RESOLVE_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/discrepancy/lifecycle-event-resolve.jsonl"
    );
    const LIFECYCLE_DISMISS_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/discrepancy/lifecycle-event-dismiss.jsonl"
    );
    const EPISODE_RELATION_SPLIT_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/discrepancy/episode-relation-superseded-split.jsonl"
    );
    const EPISODE_RELATION_COMBINED_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/discrepancy/episode-relation-combined-from.jsonl"
    );
    const VECTOR_SUITE_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v3/discrepancy/vector-suite.jsonl");

    const FAMILY_FINGERPRINT: &str =
        "2a0e121fcd2b26621670f810a213e72d91a4a3084c2314ff7811b105cc9c6374";
    const EPISODE_FINGERPRINT: &str =
        "41dc523d985324bbb4c268eb7b0f814547caa8250180274703107487d46e246d";
    const ENVELOPE_ID: &str = "91d220c7d6e869f8cdd10b5d6c3b50d8546b69cfd33403abadcaf1d6e1be756b";
    const COMPARATOR_LINEAGE_FINGERPRINT: &str =
        "11589b382071ef9df593ef7efe4df898f2ad4ed8e1775a011d4ec3912a5116d2";
    const VECTOR_SUITE_DIGEST: &str =
        "49f31ef97bfea3adde890e622e6147c1c251559f081b87259a9a812737fee017";

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
            required_applicability_dimension_ids: vec![
                ContractId::new("runtime_environment").unwrap(),
            ],
        };
        let body_bytes = encode_canonical(&registration).unwrap();
        let body: CanonicalValue = decode_strict(&body_bytes).unwrap();
        RegistryEntryV1 {
            schema_version: 1,
            kind: RegistryEntryKind::PredicateSchema,
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
    ) -> DiscrepancyEpisodeRelationV1 {
        DiscrepancyEpisodeRelationV1 {
            schema_version: DISCREPANCY_SCHEMA_VERSION,
            kind: EpisodeRelationKindV1::Superseded,
            from_episodes: vec![old_episode],
            to_episode: new_episode,
        }
    }

    fn episode_relation_combined(
        first: DiscrepancyEpisodeFingerprintV1,
        second: DiscrepancyEpisodeFingerprintV1,
        combined: DiscrepancyEpisodeFingerprintV1,
    ) -> DiscrepancyEpisodeRelationV1 {
        let mut from_episodes = vec![first, second];
        from_episodes.sort();
        DiscrepancyEpisodeRelationV1 {
            schema_version: DISCREPANCY_SCHEMA_VERSION,
            kind: EpisodeRelationKindV1::CombinedFrom,
            from_episodes,
            to_episode: combined,
        }
    }

    fn negative_cases() -> Vec<String> {
        [
            "applicability_duplicate_or_unsorted",
            "comparator_lineage_fingerprint_diverges_from_registry",
            "comparator_lineage_requires_concrete_applicability_for_required_dimensions",
            "comparator_lineage_requires_coverage_receipt_when_coverage_proof_required",
            "comparator_lineage_version_bump_changes_lineage_fingerprint",
            "continuity_key_dimension_missing_from_applicability",
            "dismiss_missing_or_empty_rationale",
            "envelope_comparator_lineage_required_applicability_dimension_ids_diverge_from_registry",
            "envelope_continuity_key_diverges_from_registered_episode_policy",
            "envelope_episode_fingerprint_mismatch",
            "envelope_episode_policy_reference_diverges_from_registry_entry_digest",
            "envelope_family_fingerprint_mismatch",
            "implicated_actor_cannot_dismiss_own_finding",
            "implicated_actor_cannot_resolve_own_finding",
            "lifecycle_event_scope_or_profile_diverges_from_envelope",
            "lifecycle_event_targets_wrong_episode",
            "lifecycle_event_with_no_transition_or_verification_update",
            "physical_append_fields_absent",
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
        let decoded_envelope: DiscrepancyEnvelopeV1 =
            decode_strict(record(ENVELOPE_FIXTURE)).unwrap();
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
        let split_relation = episode_relation_split(episode_fingerprint, other_episode);
        split_relation.validate_shape().unwrap();
        assert_eq!(
            encode_canonical(&split_relation).unwrap(),
            record(EPISODE_RELATION_SPLIT_FIXTURE)
        );
        let combined_relation =
            episode_relation_combined(episode_fingerprint, other_episode, combined_episode);
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

        let combined = DiscrepancyEpisodeFingerprintV1::from_digest(digest(
            "3333333333333333333333333333333333333333333333333333333333333333",
        ));
        let relation = episode_relation_combined(
            first.episode_fingerprint,
            second_source.episode_fingerprint,
            combined,
        );
        relation.validate_shape().unwrap();
        assert_eq!(relation.kind, EpisodeRelationKindV1::CombinedFrom);
        assert_eq!(relation.from_episodes.len(), 2);

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
        recurrence.detected_at =
            CanonicalTimestamp::parse("2026-09-01T00:00:00.000000000Z").unwrap();
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
    fn long_gap_links_a_new_episode_by_possibly_continues() {
        let stale = envelope();
        let mut resumed = envelope();
        resumed.opening_transition.source_fact_id = source_fact_id('9');
        resumed.episode_fingerprint = DiscrepancyEpisodePreimageV1 {
            schema_version: DISCREPANCY_SCHEMA_VERSION,
            family_fingerprint: resumed.family_fingerprint,
            continuity_key: vec![applicability()[1].clone()],
            opening_transition_source_fact_id: resumed.opening_transition.source_fact_id,
            episode_policy_version: resumed.episode_policy.version,
        }
        .fingerprint()
        .unwrap();

        let relation = DiscrepancyEpisodeRelationV1 {
            schema_version: DISCREPANCY_SCHEMA_VERSION,
            kind: EpisodeRelationKindV1::PossiblyContinues,
            from_episodes: vec![stale.episode_fingerprint],
            to_episode: resumed.episode_fingerprint,
        };
        relation.validate_shape().unwrap();
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
        let relation = episode_relation_split(envelope.episode_fingerprint, new_episode);
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
            required_applicability_dimension_ids: changed
                .required_applicability_dimension_ids
                .clone(),
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
    fn an_unrelated_concurrent_finding_shares_no_family_or_episode_identity_with_an_active_breach()
    {
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
            required_applicability_dimension_ids: vec![
                ContractId::new("runtime_environment").unwrap(),
            ],
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
            required_applicability_dimension_ids: vec![
                ContractId::new("runtime_environment").unwrap(),
            ],
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
            required_applicability_dimension_ids: original
                .required_applicability_dimension_ids
                .clone(),
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
            required_applicability_dimension_ids: vec![
                ContractId::new("runtime_environment").unwrap(),
            ],
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
            decode_strict::<DiscrepancyLifecycleEventV1>(&serde_json::to_vec(&value).unwrap())
                .is_err()
        );
    }

    #[test]
    fn dismiss_requires_nonempty_rationale() {
        let mut dismiss = dismiss_event(envelope().episode_fingerprint, "principal.on_call");
        if let Some(LifecycleTransitionV1::Dismiss { reason, .. }) =
            &mut dismiss.lifecycle_transition
        {
            reason.rationale = "   ".into();
        }
        assert!(dismiss.validate_shape().is_err());
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
            authorize_lifecycle_transition(&non_conflict, &spec_nonconformance_self_waiver)
                .is_err()
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
            required_applicability_dimension_ids: vec![
                ContractId::new("runtime_environment").unwrap(),
            ],
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
        tampered_episode.episode_fingerprint = DiscrepancyEpisodeFingerprintV1::from_digest(
            digest("6666666666666666666666666666666666666666666666666666666666666666"),
        );
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
        divergent.continuity_key_dimension_ids =
            vec![ContractId::new("repository_commit").unwrap()];
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
            required_applicability_dimension_ids: vec![
                ContractId::new("runtime_environment").unwrap(),
            ],
        };
        let body_bytes = encode_canonical(&registration).unwrap();
        let body: CanonicalValue = decode_strict(&body_bytes).unwrap();
        let entry = RegistryEntryV1 {
            schema_version: 1,
            kind: RegistryEntryKind::PredicateSchema,
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
        let resolved =
            StructurallyResolvedComparatorLineageV1::from_registry_entry(&entry).unwrap();

        let mut no_coverage = envelope();
        no_coverage.comparator_lineage_fingerprint =
            coverage_required_lineage.fingerprint().unwrap();
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
        assert!(
            decode_strict::<DiscrepancyEnvelopeV1>(&serde_json::to_vec(&value).unwrap()).is_err()
        );

        let mut extra_field: serde_json::Value = serde_json::from_slice(canonical).unwrap();
        extra_field.as_object_mut().unwrap().insert(
            "lifecycle_state".into(),
            serde_json::Value::String("open".into()),
        );
        assert!(
            decode_strict::<DiscrepancyEnvelopeV1>(&serde_json::to_vec(&extra_field).unwrap())
                .is_err()
        );
    }

    #[test]
    fn waiver_without_actor_or_expiry_fails_to_deserialize() {
        let waiver = waiver_record("principal.on_call", "2026-09-01T00:00:00.000000000Z");
        let mut value = serde_json::to_value(&waiver).unwrap();
        let mut missing_actor = value.clone();
        missing_actor.as_object_mut().unwrap().remove("actor");
        assert!(
            decode_strict::<WaiverRecordV1>(&serde_json::to_vec(&missing_actor).unwrap()).is_err()
        );

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
        assert!(
            decode_strict::<VerificationUpdateV1>(&serde_json::to_vec(&value).unwrap()).is_err()
        );
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

        let single_source_combine = DiscrepancyEpisodeRelationV1 {
            schema_version: DISCREPANCY_SCHEMA_VERSION,
            kind: EpisodeRelationKindV1::CombinedFrom,
            from_episodes: vec![a],
            to_episode: b,
        };
        assert!(single_source_combine.validate_shape().is_err());

        let self_referential = DiscrepancyEpisodeRelationV1 {
            schema_version: DISCREPANCY_SCHEMA_VERSION,
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
        let split_relation = episode_relation_split(episode_fingerprint, other_episode);
        let combined_relation =
            episode_relation_combined(episode_fingerprint, other_episode, combined_episode);
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
}
