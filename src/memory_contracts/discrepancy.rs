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

/// True when `text` has no visible content once ordinary whitespace AND the
/// zero-width Unicode characters `str::trim` does not strip are removed.
///
/// `str::trim` only strips `White_Space`; U+200B ZERO WIDTH SPACE, U+200C/
/// U+200D (ZWNJ/ZWJ), U+FEFF (BOM / ZERO WIDTH NO-BREAK SPACE), and U+2060
/// WORD JOINER are not `White_Space`, so `"\u{200B}".trim().is_empty()` is
/// `false` -- a rationale of only invisible characters would otherwise pass
/// a "dismiss/waive without justification is rejected" check in form while
/// evading it in substance.
fn is_blank_rationale(text: &str) -> bool {
    text.chars()
        .filter(|character| !matches!(character, '\u{200B}'..='\u{200D}' | '\u{FEFF}' | '\u{2060}'))
        .collect::<String>()
        .trim()
        .is_empty()
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
/// package/head.
///
/// Binds to the real `RegistryEntryKind::ComparatorLineage` reserved slot
/// (W0-REG-2, `dd21a2e`) under its own `entry_schema_id`
/// (`registry.comparator_lineage`) -- **not** a squat on
/// `RegistryEntryKind::PredicateSchema` as an earlier revision of this type
/// did. The kind is `is_generation2_only()`, so `decode_successor_entry`
/// (`successor_package.rs`) and `decode_entry` (`genesis.rs`) both reject any
/// package that carries this entry outright: no `SemanticallyClosedGenesisPackage`,
/// `SemanticallyClosedSuccessorPackage`, or (by extension)
/// `SemanticallyClosedStage4Package` can ever admit a comparator-lineage
/// registration today (`comparator_lineage_entry_is_rejected_by_every_v1_and_successor_closure`).
/// The one path that genuinely proves package membership without decoding is
/// `generation2::ReservedSlotCarriageV1::from_package_entry` -- a
/// manifest-verified, canonically ordered, digest-checked
/// `RegistryPackageV1` can carry this entry, and the carriage reports the
/// same canonical body bytes this type resolves from a raw entry directly
/// (`comparator_lineage_registration_is_carriable_through_the_real_registry_package_path`).
/// Carriage is not admission (`generation2.rs`'s own `ReservedSlotCarriageV1`
/// doc): full generation-2 typed-body dispatch for this kind is still W0-REG's
/// to wire (flagged under `requests`), so `from_registry_entry` below remains
/// a structural-only resolution, exactly like
/// `StructurallyResolvedEpisodePolicyV2`, used both directly on test-constructed
/// entries and on the body bytes a `ReservedSlotCarriageV1` reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructurallyResolvedComparatorLineageV1 {
    registry_reference: RegistryReferenceV1,
    registration: ComparatorLineageRegistrationV1,
}

impl StructurallyResolvedComparatorLineageV1 {
    pub fn from_registry_entry(entry: &RegistryEntryV1) -> ContractResult<Self> {
        entry.validate()?;
        if entry.kind != RegistryEntryKind::ComparatorLineage
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
        let valid = !is_blank_rationale(&self.rationale)
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
        if is_blank_rationale(&self.rationale) || self.rationale.len() > MAX_RATIONALE_BYTES {
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
                // DISC-05 ("a waiver is durable policy"): a waiver whose
                // `expiry_at` is already at or before the event's own
                // `effective_at` never had effect -- it would project `Open`
                // the instant it is applied, recording an audit-trail entry
                // for a suppression that never actually suppressed anything.
                if waiver.expiry_at <= event.effective_at {
                    return Err(ContractError::Schema(
                        "DISC-05: waiver expiry_at must be strictly after the event's own effective_at"
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
///
/// Carries `scope`, `profile`, and `family_fingerprint` -- the same
/// authenticated-scope-binding convention every sibling contract in this
/// crate uses -- because a relation can force the strongest possible
/// suppression an episode's projection can reach
/// (`LifecycleState::Superseded`, via [`project_discrepancy_episode`]) purely
/// from its episode fingerprints, which are public identifiers, not secrets.
/// Without this binding, a relation minted with only the public fingerprints
/// of two episodes in different tenants or different discrepancy families
/// could suppress one from the other; `project_discrepancy_episode` rejects
/// any relation naming its envelope whose `scope`/`profile`/`family_fingerprint`
/// diverges from the envelope's own, mirroring
/// `authorize_lifecycle_transition`'s identical check on lifecycle events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscrepancyEpisodeRelationV1 {
    pub schema_version: u32,
    pub profile: ProfileReferenceV1,
    pub scope: AuthenticatedProjectScopeV1,
    pub family_fingerprint: DiscrepancyFamilyFingerprintV1,
    pub kind: EpisodeRelationKindV1,
    pub from_episodes: Vec<DiscrepancyEpisodeFingerprintV1>,
    pub to_episode: DiscrepancyEpisodeFingerprintV1,
}

impl DiscrepancyEpisodeRelationV1 {
    pub fn validate_shape(&self) -> ContractResult<()> {
        self.profile.validate()?;
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

    /// True when this relation names `episode_fingerprint`, either as a
    /// source or as its target.
    fn names(&self, episode_fingerprint: DiscrepancyEpisodeFingerprintV1) -> bool {
        self.to_episode == episode_fingerprint || self.from_episodes.contains(&episode_fingerprint)
    }
}

// ---------------------------------------------------------------------------
// Observation gap (doc lines 1338-1348): the seam `allowed_observation_gap_seconds`
// actually feeds. A declared field no code path reads is worse than no field
// at all (see the waiver-scope docstring above): this is that field's reader.
// ---------------------------------------------------------------------------

/// Outcome of comparing an observation gap against
/// [`EpisodePolicyV2::allowed_observation_gap_seconds`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservationGapOutcomeV1 {
    /// The gap is within the registered bound: the SAME episode continues,
    /// its observed interval recorded incomplete but not ended.
    Bridged,
    /// The gap exceeds the registered bound -- or the policy registers no
    /// bound at all (`allowed_observation_gap_seconds: None`, "no observation
    /// gap may be bridged") -- so the prior occurrence's known observed
    /// interval ends here.
    EpisodeEnded,
}

/// Classify the gap between one episode's last known observed instant and
/// the next candidate occurrence's opening instant, against
/// `policy.allowed_observation_gap_seconds`.
///
/// `EpisodeEnded` is the outcome a caller pairs with a
/// `VerificationState::Indeterminate` verification update on the prior
/// occurrence (already representable: `VerificationUpdateV1 { state:
/// VerificationState::Indeterminate, .. }` needs no new type) and a
/// `PossiblyContinues` relation linking it to the newly opened episode. This
/// function only classifies the gap; recording those two outcomes is the
/// caller's responsibility, matching every other pure decision function in
/// this module (`select_opening_transition`, `nominate_repeated_waiver_drift`).
pub fn classify_observation_gap(
    policy: &EpisodePolicyV2,
    prior_effective_until: &CanonicalTimestamp,
    next_effective_from: &CanonicalTimestamp,
) -> ContractResult<ObservationGapOutcomeV1> {
    if next_effective_from <= prior_effective_until {
        return Err(ContractError::Schema(
            "observation gap requires the next occurrence to begin strictly after the prior one ends"
                .into(),
        ));
    }
    let gap_seconds = seconds_between(prior_effective_until, next_effective_from)?;
    Ok(match policy.allowed_observation_gap_seconds {
        Some(allowed) if gap_seconds <= allowed => ObservationGapOutcomeV1::Bridged,
        _ => ObservationGapOutcomeV1::EpisodeEnded,
    })
}

/// Whole seconds between two canonical UTC timestamps. Both are already
/// proven parseable RFC 3339 by [`CanonicalTimestamp::parse`], so only the
/// ordering precondition (`classify_observation_gap`'s caller) can make this
/// fail in practice.
fn seconds_between(
    earlier: &CanonicalTimestamp,
    later: &CanonicalTimestamp,
) -> ContractResult<u64> {
    let earlier = chrono::DateTime::parse_from_rfc3339(earlier.as_str())
        .map_err(|_| ContractError::Schema("timestamp is not parseable".into()))?;
    let later = chrono::DateTime::parse_from_rfc3339(later.as_str())
        .map_err(|_| ContractError::Schema("timestamp is not parseable".into()))?;
    u64::try_from(later.signed_duration_since(earlier).num_seconds())
        .map_err(|_| ContractError::Schema("observation gap is not positive".into()))
}

/// A `PossiblyContinues` relation is only meaningful once the gap has ended
/// the prior occurrence's observed interval.
///
/// Asserting it while the gap between the two episodes is still within the
/// registered bound (`ObservationGapOutcomeV1::Bridged`) is rejected: the
/// policy itself says those two occurrences bridge into ONE episode, so
/// linking them as merely "possibly" the same occurrence contradicts the
/// very policy that resolved them.
pub fn validate_possibly_continues_gap(
    relation: &DiscrepancyEpisodeRelationV1,
    gap_outcome: ObservationGapOutcomeV1,
) -> ContractResult<()> {
    relation.validate_shape()?;
    if relation.kind == EpisodeRelationKindV1::PossiblyContinues
        && gap_outcome == ObservationGapOutcomeV1::Bridged
    {
        return Err(ContractError::Schema(
            "possibly_continues asserted within the allowed observation gap: the policy bridges these occurrences into one episode"
                .into(),
        ));
    }
    Ok(())
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
/// may name this envelope's episode. Whenever a `superseded` OR
/// `combined_from` relation's `from_episodes` contains
/// `envelope.episode_fingerprint` -- i.e. this is a SOURCE side of a
/// canonical replacement, whether a one-to-one split/rebind or a
/// many-to-one combine -- the projection is [`LifecycleState::Superseded`],
/// overriding whatever lifecycle transitions replayed above it (a replaced
/// episode is frozen, not reopened by a later waiver expiry). This is the
/// only producer of `Superseded`: the variant is otherwise unreachable,
/// matching the doc's "replay ... marks the earlier projections superseded,
/// retaining explicit `combined_from` or `continues` relations." Pass `&[]`
/// when no relation set applies (an episode with no known supersession is
/// never superseded).
///
/// A relation that names this envelope's episode -- as a source or as the
/// target -- but whose `scope`/`profile`/`family_fingerprint` diverges from
/// the envelope's own is rejected with an error, never silently ignored or
/// silently trusted: an episode fingerprint is a public identifier, not a
/// secret, so knowledge of it alone must never authorize a cross-tenant or
/// cross-family transition (mirroring `authorize_lifecycle_transition`'s
/// identical scope/profile check on lifecycle events).
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
        // A relation's episode fingerprints are public identifiers, not
        // secrets (matching `authorize_lifecycle_transition`'s identical
        // reasoning for lifecycle events): a relation that names this
        // envelope's episode at all -- as a source or as the target -- must
        // be bound to the exact same authenticated scope/profile and the
        // exact same discrepancy family, or it is rejected outright rather
        // than silently ignored or silently trusted.
        if relation.names(envelope.episode_fingerprint)
            && (relation.scope != envelope.scope
                || relation.profile != envelope.profile
                || relation.family_fingerprint != envelope.family_fingerprint)
        {
            return Err(ContractError::Schema(
                "episode relation naming this envelope diverges in scope/profile/family from the envelope"
                    .into(),
            ));
        }
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
    // Idempotent replay: a byte-identical event supplied more than once (an
    // at-least-once delivery retry, a duplicate append) is applied once, not
    // once per occurrence -- REPLAY-01's order-independence guarantee is
    // weaker than it should be if it holds for reordering but not repetition.
    // Dedup only after sorting so which physical copy survives is itself
    // deterministic, never input-position-dependent.
    let mut seen_event_bytes: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
    ordered.retain(|(_, bytes)| seen_event_bytes.insert(bytes.clone()));

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
    // explicit `combined_from` or `continues` relations"). Both `superseded`
    // (split) AND `combined_from` (bridge) relations retire their SOURCE
    // episodes this way -- a combine is a supersession of two-or-more
    // episodes into one canonical replacement, not merely a record of the
    // arity rule: the same continuous incompatible interval must not surface
    // three times (once per source, once for the combined episode).
    let is_superseded = relations.iter().any(|relation| {
        matches!(
            relation.kind,
            EpisodeRelationKindV1::Superseded | EpisodeRelationKindV1::CombinedFrom
        ) && relation
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
/// `Option<VerificationState>` could technically carry `Verified` -- the
/// restriction to `Candidate`-only is enforced by this function's body, not
/// by the return type itself. It is *this call site*, not the type, that
/// structurally cannot express `Verified`, no matter how large
/// `waiver_count` grows (PRED-01: similarity/pattern signals cannot open a
/// verified discrepancy on their own); see
/// `repeated_waiver_drift_is_always_candidate_only`.
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
#[path = "discrepancy_tests.rs"]
mod tests;
