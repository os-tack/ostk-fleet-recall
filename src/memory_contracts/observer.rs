//! Observer admission v2, run receipt, and typed observer-result event.
//!
//! Exhaustiveness is granted per observer version, predicate, input domain, and
//! configuration context, never to an observer globally (COVER-01). Registry
//! admission grants exactly one closed mode: `candidate_only` may only nominate
//! propositions or discrepancies; `positive_verified` may prove an individually
//! found value with exact proof but never absence or an exact set;
//! `closed_world_verified` may additionally prove absence or an exact set
//! inside its admitted closed domain. `llm` and `semantic_search` observer
//! kinds are always `candidate_only`: no other mode is admissible for them.
//!
//! [`ObserverAdmissionV2`] is a public registry body: deserializing or
//! structurally validating it grants no governance authority. Only
//! [`AdmittedObserverV1`], produced from a trusted registry-activation witness,
//! may derive a verification outcome (AUTH-03: an observer cannot admit
//! itself; activation is a separate registry governance action, never emitted
//! by the observer's own event). Likewise [`ObserverResultV1`] is a public
//! candidate accepted-event preimage; only [`AdmittedObserverResultV1`],
//! produced from a trusted append witness, is the opaque capability a later
//! repository consumes to append it.
//!
//! [`ObserverRunReceiptV1`] carries exact included/excluded/skipped/failed/
//! unsupported/unknown input accounting, exact applicability and
//! configuration, input/output digests, and a coverage witness that binds
//! W0-COVER's `CoverageReceiptV1` by digest only (this module never imports
//! that contract) together with the completeness/freshness/continuity triple
//! it asserts. [`derive_verification_outcome`] is the pure PRED-05 derivation:
//! `verified_negative`/`verified_exact_set` require `closed_world_verified`,
//! zero skipped/failed/unsupported/unknown inputs, and complete, current,
//! contiguous-when-applicable coverage; `positive_verified` may still prove an
//! individually found positive under partial coverage; `candidate_only` never
//! verifies; dependency drift and timeout/resource exhaustion always resolve
//! to `indeterminate`, never a verified negative and never a silent failure.
//!
//! [`detect_disagreement`] implements `observer_derivation_disagreement`:
//! incompatible outputs from two admitted observers with overlapping admitted
//! domains, predicate references, and concrete applicability make every
//! affected observation indeterminate, while a `candidate_only` output remains
//! only opposing candidate evidence and never by itself invalidates a complete
//! verified proof.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::{
    ContractError, ContractResult,
    canonical::encode_canonical,
    common::{
        AuthenticatedProjectScopeV1, CanonicalTimestamp, ContractId, ProfileReferenceV1,
        RegistryReferenceV1,
    },
    digest::{DigestDomain, Sha256Digest, domain_separated_digest},
    evidence::AcceptedEventId,
    identity::{IdentityForm, ResourceUri},
    relation::ConcreteApplicabilityDimensionV1,
};

const OBSERVER_SCHEMA_VERSION: u32 = 1;
const OBSERVER_RESULT_EVENT_KIND: &str = "observer.result.accepted";
const OBSERVER_KIND_LLM: &str = "llm";
const OBSERVER_KIND_SEMANTIC_SEARCH: &str = "semantic_search";
const MAX_DEPENDENCY_DIGESTS: usize = 64;
const MAX_SUPPORTED_KINDS: usize = 64;
const MAX_APPLICABILITY_DIMENSIONS: usize = 64;
const MAX_UNSUPPORTED_DIAGNOSTICS: usize = 64;
const MAX_OUTCOME_KINDS: usize = 5;
const MAX_INPUT_SAMPLE: usize = 64;
const MAX_EVIDENCE_EVENT_IDS: usize = 256;

macro_rules! digest_newtype {
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

digest_newtype!(ObserverResultFingerprintV1);
digest_newtype!(ObserverDisagreementFingerprintV1);

/// Closed exhaustiveness grant.
///
/// Each mode is a strictly increasing capability: `closed_world_verified`
/// retains everything `positive_verified` may do, and `positive_verified`
/// retains everything `candidate_only` may do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObserverAdmissionModeV1 {
    CandidateOnly,
    PositiveVerified,
    ClosedWorldVerified,
}

/// Closed run-receipt outcome taxonomy (`success`, `partial`, `stale`,
/// `parse_failure`, `timeout`).
///
/// Resource exhaustion is reported as `timeout`: this module deliberately has
/// no separate variant that could be mistaken for a completed read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObserverOutcomeKindV1 {
    Success,
    Partial,
    Stale,
    ParseFailure,
    Timeout,
}

/// Exact executable and dependency identity admitted into the registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObserverExecutableIdentityV1 {
    pub observer_kind: ContractId,
    pub executable_digest: Sha256Digest,
    pub dependency_digests: Vec<Sha256Digest>,
    pub version: u32,
}

impl ObserverExecutableIdentityV1 {
    fn validate_shape(&self) -> ContractResult<()> {
        if self.executable_digest == Sha256Digest::ZERO
            || self.version == 0
            || self.dependency_digests.len() > MAX_DEPENDENCY_DIGESTS
            || !strictly_sorted(&self.dependency_digests)
            || self.dependency_digests.contains(&Sha256Digest::ZERO)
        {
            return Err(ContractError::Schema(
                "invalid observer executable identity".into(),
            ));
        }
        Ok(())
    }

    /// Whether `observer_kind` is one of the always-`candidate_only` kinds.
    fn forces_candidate_only(&self) -> bool {
        matches!(
            self.observer_kind.as_str(),
            OBSERVER_KIND_LLM | OBSERVER_KIND_SEMANTIC_SEARCH
        )
    }
}

/// Exact executable/dependency identity actually witnessed by one run.
///
/// This is deliberately a separate, smaller type from
/// [`ObserverExecutableIdentityV1`]: a run receipt compares its own witnessed
/// digests against the admitted identity to detect dependency drift, and never
/// asserts its own `observer_kind` or `version` as authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObserverRuntimeIdentityV1 {
    pub executable_digest: Sha256Digest,
    pub dependency_digests: Vec<Sha256Digest>,
}

impl ObserverRuntimeIdentityV1 {
    fn validate_shape(&self) -> ContractResult<()> {
        if self.executable_digest == Sha256Digest::ZERO
            || self.dependency_digests.len() > MAX_DEPENDENCY_DIGESTS
            || !strictly_sorted(&self.dependency_digests)
            || self.dependency_digests.contains(&Sha256Digest::ZERO)
        {
            return Err(ContractError::Schema(
                "invalid observer runtime identity".into(),
            ));
        }
        Ok(())
    }

    fn matches_admitted(&self, admitted: &ObserverExecutableIdentityV1) -> bool {
        self.executable_digest == admitted.executable_digest
            && self.dependency_digests == admitted.dependency_digests
    }
}

/// Language/schema/compiler/API version identifiers closed into the
/// exhaustive-proof contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObserverToolchainVersionsV1 {
    pub language_version: ContractId,
    pub schema_version: ContractId,
    pub compiler_version: ContractId,
    pub api_version: ContractId,
}

/// Closed input boundary: supported source/resource kinds plus the
/// applicability dimensions the observer requires to be concrete.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObserverInputDomainV1 {
    pub closed_input_boundary_id: ContractId,
    pub supported_source_kinds: Vec<ContractId>,
    pub supported_resource_kinds: Vec<ContractId>,
    pub required_applicability_dimensions: Vec<ContractId>,
}

impl ObserverInputDomainV1 {
    fn validate_shape(&self) -> ContractResult<()> {
        if self.supported_source_kinds.is_empty()
            || self.supported_source_kinds.len() > MAX_SUPPORTED_KINDS
            || !strictly_sorted(&self.supported_source_kinds)
            || self.supported_resource_kinds.is_empty()
            || self.supported_resource_kinds.len() > MAX_SUPPORTED_KINDS
            || !strictly_sorted(&self.supported_resource_kinds)
            || self.required_applicability_dimensions.len() > MAX_APPLICABILITY_DIMENSIONS
            || !strictly_sorted(&self.required_applicability_dimensions)
        {
            return Err(ContractError::Schema(
                "invalid observer input domain".into(),
            ));
        }
        Ok(())
    }
}

/// Enumeration algorithm identity plus the exact unsupported-feature
/// diagnostics it is registered to emit.
///
/// A search miss, truncated AST, generated code outside this closed
/// boundary, or an unresolved macro/configuration path can never silently
/// become a proof of absence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObserverEnumerationAlgorithmV1 {
    pub algorithm_id: ContractId,
    pub unsupported_feature_diagnostics: Vec<ContractId>,
}

impl ObserverEnumerationAlgorithmV1 {
    fn validate_shape(&self) -> ContractResult<()> {
        if self.unsupported_feature_diagnostics.len() > MAX_UNSUPPORTED_DIAGNOSTICS
            || !strictly_sorted(&self.unsupported_feature_diagnostics)
        {
            return Err(ContractError::Schema(
                "invalid observer enumeration algorithm".into(),
            ));
        }
        Ok(())
    }
}

/// Registry body for one exhaustive-observer admission (`RegistryEntryKind::ObserverAdmission`).
///
/// Deserializing this body grants no runtime authority: a later repository
/// must resolve it from an active registry package and construct
/// [`AdmittedObserverV1`] before any derivation may cite it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObserverAdmissionV2 {
    pub schema_version: u32,
    pub admission_id: ContractId,
    pub version: u32,
    pub identity: ObserverExecutableIdentityV1,
    pub predicate: RegistryReferenceV1,
    pub input_domain: ObserverInputDomainV1,
    pub configuration_context_digest: Sha256Digest,
    pub toolchain_versions: ObserverToolchainVersionsV1,
    pub mode: ObserverAdmissionModeV1,
    pub enumeration_algorithm: ObserverEnumerationAlgorithmV1,
    pub declared_outcome_kinds: Vec<ObserverOutcomeKindV1>,
    pub coverage_receipt_recipe: RegistryReferenceV1,
    pub positive_vector_digest: Sha256Digest,
    pub negative_vector_digest: Sha256Digest,
    pub mutation_vector_digest: Sha256Digest,
    pub adversarial_vector_digest: Sha256Digest,
}

impl ObserverAdmissionV2 {
    /// Validate closed wire shape and the LLM/semantic-search mode rule only.
    /// This does not prove active-registry authority.
    pub fn validate_shape(&self) -> ContractResult<()> {
        validate_registry_reference(&self.predicate)?;
        validate_registry_reference(&self.coverage_receipt_recipe)?;
        self.identity.validate_shape()?;
        self.input_domain.validate_shape()?;
        self.enumeration_algorithm.validate_shape()?;
        let forced_candidate_only_violated = self.identity.forces_candidate_only()
            && self.mode != ObserverAdmissionModeV1::CandidateOnly;
        if self.schema_version != OBSERVER_SCHEMA_VERSION
            || self.version == 0
            || self.configuration_context_digest == Sha256Digest::ZERO
            || self.declared_outcome_kinds.is_empty()
            || self.declared_outcome_kinds.len() > MAX_OUTCOME_KINDS
            || !strictly_sorted(&self.declared_outcome_kinds)
            || !self
                .declared_outcome_kinds
                .contains(&ObserverOutcomeKindV1::Success)
            || self.positive_vector_digest == Sha256Digest::ZERO
            || self.negative_vector_digest == Sha256Digest::ZERO
            || self.mutation_vector_digest == Sha256Digest::ZERO
            || self.adversarial_vector_digest == Sha256Digest::ZERO
            || forced_candidate_only_violated
        {
            return Err(ContractError::Schema(
                "invalid observer admission v2".into(),
            ));
        }
        encode_canonical(self)?;
        Ok(())
    }

    /// Exact body identity under the `ostk-observer-admission-v2` domain.
    pub fn digest(&self) -> ContractResult<Sha256Digest> {
        self.validate_shape()?;
        Ok(domain_separated_digest(
            DigestDomain::ObserverAdmissionV2,
            &encode_canonical(self)?,
        ))
    }
}

/// Opaque governance-activated observer admission capability.
///
/// This contract-only module exposes no production constructor. An observer's
/// own run receipt or result event can never construct this capability merely
/// by asserting a matching admission ID: activation is a separate registry
/// governance action, never emitted by the observer's own event (AUTH-03).
#[derive(Debug)]
pub struct AdmittedObserverV1 {
    admission: ObserverAdmissionV2,
}

impl AdmittedObserverV1 {
    pub const fn admission(&self) -> &ObserverAdmissionV2 {
        &self.admission
    }

    #[cfg(test)]
    fn from_test_witness(admission: ObserverAdmissionV2) -> ContractResult<Self> {
        admission.validate_shape()?;
        Ok(Self { admission })
    }
}

/// One bounded tally of resource inputs: an exact total plus a bounded,
/// strictly sorted sample. `sample.len()` may be smaller than `total_count`
/// but never larger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObserverInputTallyV1 {
    pub total_count: u32,
    pub sample: Vec<ResourceUri>,
}

impl ObserverInputTallyV1 {
    fn validate_shape(&self) -> ContractResult<()> {
        if self.sample.len() > MAX_INPUT_SAMPLE
            || u32::try_from(self.sample.len()).unwrap_or(u32::MAX) > self.total_count
            || !strictly_sorted(&self.sample)
        {
            return Err(ContractError::Schema("invalid observer input tally".into()));
        }
        Ok(())
    }

    const fn is_empty(&self) -> bool {
        self.total_count == 0
    }
}

/// Exact accounting for every input this run touched.
///
/// `skipped`, `failed`, `unsupported`, and `unknown` are the four categories
/// whose totals must all be zero before this run may support a verified
/// negative or exact-set outcome. `excluded` inputs are deliberately outside
/// the admitted domain and never count against completeness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObserverInputAccountingV1 {
    pub included: ObserverInputTallyV1,
    pub excluded: ObserverInputTallyV1,
    pub skipped: ObserverInputTallyV1,
    pub failed: ObserverInputTallyV1,
    pub unsupported: ObserverInputTallyV1,
    pub unknown: ObserverInputTallyV1,
}

impl ObserverInputAccountingV1 {
    fn validate_shape(&self) -> ContractResult<()> {
        self.included.validate_shape()?;
        self.excluded.validate_shape()?;
        self.skipped.validate_shape()?;
        self.failed.validate_shape()?;
        self.unsupported.validate_shape()?;
        self.unknown.validate_shape()?;
        Ok(())
    }

    const fn has_no_gap_inputs(&self) -> bool {
        self.skipped.is_empty()
            && self.failed.is_empty()
            && self.unsupported.is_empty()
            && self.unknown.is_empty()
    }
}

/// Closed coverage completeness taxonomy (COVER-03).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObserverCoverageCompletenessV1 {
    Complete,
    Partial,
    Unknown,
}

/// Closed coverage freshness taxonomy (COVER-03).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObserverCoverageFreshnessV1 {
    Current,
    Stale,
}

/// Closed sequence-continuity taxonomy.
///
/// `NotApplicable` covers predicates with no sequencing dimension at all;
/// only `Contiguous` and `NotApplicable` are compatible with a verified
/// negative or exact-set outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObserverCoverageContinuityV1 {
    Contiguous,
    GapDetected,
    NotApplicable,
}

/// Local coverage witness carried by a run receipt. This binds W0-COVER's
/// `CoverageReceiptV1` by digest only; this module never imports that
/// contract and never redefines its own coverage-receipt shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObserverCoverageWitnessV1 {
    pub coverage_receipt_digest: Sha256Digest,
    pub completeness: ObserverCoverageCompletenessV1,
    pub freshness: ObserverCoverageFreshnessV1,
    pub continuity: ObserverCoverageContinuityV1,
}

impl ObserverCoverageWitnessV1 {
    fn validate_shape(&self) -> ContractResult<()> {
        if self.coverage_receipt_digest == Sha256Digest::ZERO {
            return Err(ContractError::Schema(
                "invalid observer coverage witness".into(),
            ));
        }
        Ok(())
    }

    fn is_complete_current_and_contiguous(&self) -> bool {
        self.completeness == ObserverCoverageCompletenessV1::Complete
            && self.freshness == ObserverCoverageFreshnessV1::Current
            && matches!(
                self.continuity,
                ObserverCoverageContinuityV1::Contiguous
                    | ObserverCoverageContinuityV1::NotApplicable
            )
    }
}

/// Immutable run-receipt preimage for one observer execution.
///
/// The receipt asserts its own witnessed executable/dependency digests
/// separately from the admitted identity so [`derive_verification_outcome`]
/// can detect dependency drift. It contains no storage locator, receipt
/// clock, epoch, shard, offset, or append-chain field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObserverRunReceiptV1 {
    pub schema_version: u32,
    pub admission: RegistryReferenceV1,
    pub executable_identity: ObserverRuntimeIdentityV1,
    pub source_version: ResourceUri,
    pub inputs: ObserverInputAccountingV1,
    pub applicability: Vec<ConcreteApplicabilityDimensionV1>,
    pub configuration_context_digest: Sha256Digest,
    pub input_digest: Sha256Digest,
    pub output_digest: Sha256Digest,
    pub coverage: ObserverCoverageWitnessV1,
    pub evidence_event_ids: Vec<AcceptedEventId>,
    pub outcome: ObserverOutcomeKindV1,
    pub observed_at: CanonicalTimestamp,
}

impl ObserverRunReceiptV1 {
    /// Validate canonical semantic bindings only. Active admission, exact
    /// registry authority, and evidence existence remain runtime admission
    /// checks performed before [`AdmittedObserverV1`] is constructed.
    pub fn validate_shape(&self) -> ContractResult<()> {
        validate_registry_reference(&self.admission)?;
        self.executable_identity.validate_shape()?;
        self.inputs.validate_shape()?;
        self.coverage.validate_shape()?;
        if self.schema_version != OBSERVER_SCHEMA_VERSION
            || self.source_version.identity_form() != IdentityForm::Version
            || self.applicability.len() > MAX_APPLICABILITY_DIMENSIONS
            || !strictly_sorted_by_dimension(&self.applicability)
            || self.configuration_context_digest == Sha256Digest::ZERO
            || self.input_digest == Sha256Digest::ZERO
            || self.output_digest == Sha256Digest::ZERO
            || self.evidence_event_ids.is_empty()
            || self.evidence_event_ids.len() > MAX_EVIDENCE_EVENT_IDS
            || !strictly_sorted(&self.evidence_event_ids)
        {
            return Err(ContractError::Schema("invalid observer run receipt".into()));
        }
        encode_canonical(self)?;
        Ok(())
    }

    /// Exact receipt identity under the `ostk-observer-run-receipt-v1` domain.
    pub fn digest(&self) -> ContractResult<Sha256Digest> {
        self.validate_shape()?;
        Ok(domain_separated_digest(
            DigestDomain::ObserverRunReceiptV1,
            &encode_canonical(self)?,
        ))
    }
}

/// Separate from coverage completeness/continuity (COVER-03): the evaluated
/// condition this run reached for its cited predicate and applicability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluatedConditionV1 {
    Present,
    Absent,
    Indeterminate,
}

/// Whether the cited predicate is a presence/absence claim or an exact-set
/// enumeration claim. `verified_exact_set` is only meaningful for the latter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObserverClaimShapeV1 {
    Presence,
    ExactSet,
}

/// Closed verification-outcome taxonomy an observer result may reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationOutcomeV1 {
    VerifiedPositive,
    VerifiedNegative,
    VerifiedExactSet,
    Candidate,
    Indeterminate,
}

/// Two-variant helper used only where `EvaluatedConditionV1::Indeterminate`
/// has already been resolved to [`VerificationOutcomeV1::Indeterminate`] by
/// the caller, so the remaining match can stay exhaustive without a wildcard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DefiniteConditionV1 {
    Present,
    Absent,
}

/// Structural compatibility between a claimed shape, an evaluated condition,
/// and a verification outcome. This is a shape-level invariant true under
/// every admission mode; it does not by itself prove the outcome was reached
/// under the coverage this specific admission requires.
fn verification_outcome_is_shape_admissible(
    claim_shape: ObserverClaimShapeV1,
    evaluated_condition: EvaluatedConditionV1,
    verification_outcome: VerificationOutcomeV1,
) -> bool {
    match verification_outcome {
        VerificationOutcomeV1::Candidate | VerificationOutcomeV1::Indeterminate => true,
        VerificationOutcomeV1::VerifiedPositive => {
            claim_shape == ObserverClaimShapeV1::Presence
                && evaluated_condition == EvaluatedConditionV1::Present
        }
        VerificationOutcomeV1::VerifiedNegative => {
            claim_shape == ObserverClaimShapeV1::Presence
                && evaluated_condition == EvaluatedConditionV1::Absent
        }
        VerificationOutcomeV1::VerifiedExactSet => {
            claim_shape == ObserverClaimShapeV1::ExactSet
                && evaluated_condition == EvaluatedConditionV1::Present
        }
    }
}

/// Pure PRED-05 derivation from an admitted observer and one of its run
/// receipts to a verification outcome.
///
/// Dependency drift (the run's witnessed executable/dependency digests do not
/// exactly match the admitted identity) and a `timeout` outcome both resolve
/// to `indeterminate` unconditionally: never a verified negative, never a
/// silent failure. A `candidate_only` admission never verifies. Otherwise,
/// `verified_negative`/`verified_exact_set` require `closed_world_verified`,
/// zero skipped/failed/unsupported/unknown inputs, and complete, current,
/// contiguous-when-applicable coverage; a `positive_verified` (or
/// `closed_world_verified`) admission may still emit an individually proven
/// positive under partial coverage, provided the run itself did not fail to
/// parse.
pub fn derive_verification_outcome(
    admitted: &AdmittedObserverV1,
    run: &ObserverRunReceiptV1,
    claim_shape: ObserverClaimShapeV1,
    evaluated_condition: EvaluatedConditionV1,
) -> ContractResult<VerificationOutcomeV1> {
    let admission = admitted.admission();
    admission.validate_shape()?;
    run.validate_shape()?;

    if !run
        .executable_identity
        .matches_admitted(&admission.identity)
    {
        return Ok(VerificationOutcomeV1::Indeterminate);
    }
    if run.outcome == ObserverOutcomeKindV1::Timeout {
        return Ok(VerificationOutcomeV1::Indeterminate);
    }
    if admission.mode == ObserverAdmissionModeV1::CandidateOnly {
        return Ok(VerificationOutcomeV1::Candidate);
    }

    let condition = match evaluated_condition {
        EvaluatedConditionV1::Indeterminate => return Ok(VerificationOutcomeV1::Indeterminate),
        EvaluatedConditionV1::Present => DefiniteConditionV1::Present,
        EvaluatedConditionV1::Absent => DefiniteConditionV1::Absent,
    };

    let full_coverage =
        run.inputs.has_no_gap_inputs() && run.coverage.is_complete_current_and_contiguous();

    let outcome = match (claim_shape, condition) {
        (ObserverClaimShapeV1::Presence, DefiniteConditionV1::Absent) => {
            if admission.mode == ObserverAdmissionModeV1::ClosedWorldVerified
                && full_coverage
                && run.outcome == ObserverOutcomeKindV1::Success
            {
                VerificationOutcomeV1::VerifiedNegative
            } else {
                VerificationOutcomeV1::Indeterminate
            }
        }
        (ObserverClaimShapeV1::ExactSet, DefiniteConditionV1::Present) => {
            if admission.mode == ObserverAdmissionModeV1::ClosedWorldVerified
                && full_coverage
                && run.outcome == ObserverOutcomeKindV1::Success
            {
                VerificationOutcomeV1::VerifiedExactSet
            } else {
                VerificationOutcomeV1::Indeterminate
            }
        }
        (ObserverClaimShapeV1::Presence, DefiniteConditionV1::Present) => {
            let admission_allows_positive = matches!(
                admission.mode,
                ObserverAdmissionModeV1::PositiveVerified
                    | ObserverAdmissionModeV1::ClosedWorldVerified
            );
            let run_supports_a_proof = matches!(
                run.outcome,
                ObserverOutcomeKindV1::Success | ObserverOutcomeKindV1::Partial
            );
            if admission_allows_positive && run_supports_a_proof {
                VerificationOutcomeV1::VerifiedPositive
            } else {
                VerificationOutcomeV1::Indeterminate
            }
        }
        (ObserverClaimShapeV1::ExactSet, DefiniteConditionV1::Absent) => {
            return Err(ContractError::Schema(
                "an exact-set claim shape cannot pair with an absent evaluated condition".into(),
            ));
        }
    };
    debug_assert!(verification_outcome_is_shape_admissible(
        claim_shape,
        evaluated_condition,
        outcome
    ));
    Ok(outcome)
}

/// Public candidate accepted-event preimage for `observer.result.accepted`.
///
/// Constructing this value asserts no authority by itself. Its
/// `verification_outcome` must be structurally admissible for its
/// `claim_shape`/`evaluated_condition` pair; a later repository must still
/// recompute [`derive_verification_outcome`] from a trusted
/// [`AdmittedObserverV1`] and matching run receipt before wrapping it in
/// [`AdmittedObserverResultV1`] for append.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObserverResultV1 {
    pub schema_version: u32,
    pub event_kind: ContractId,
    pub profile: ProfileReferenceV1,
    pub scope: AuthenticatedProjectScopeV1,
    pub predicate: RegistryReferenceV1,
    pub applicability: Vec<ConcreteApplicabilityDimensionV1>,
    pub admission_digest: Sha256Digest,
    pub run_receipt_digest: Sha256Digest,
    pub claim_shape: ObserverClaimShapeV1,
    pub evaluated_condition: EvaluatedConditionV1,
    pub verification_outcome: VerificationOutcomeV1,
    pub effective_at: CanonicalTimestamp,
}

impl ObserverResultV1 {
    /// Validate structural bindings only. This does not admit the result.
    pub fn validate_shape(&self) -> ContractResult<()> {
        self.profile.validate()?;
        validate_registry_reference(&self.predicate)?;
        if self.schema_version != OBSERVER_SCHEMA_VERSION
            || self.event_kind.as_str() != OBSERVER_RESULT_EVENT_KIND
            || self.applicability.len() > MAX_APPLICABILITY_DIMENSIONS
            || !strictly_sorted_by_dimension(&self.applicability)
            || self.admission_digest == Sha256Digest::ZERO
            || self.run_receipt_digest == Sha256Digest::ZERO
            || !verification_outcome_is_shape_admissible(
                self.claim_shape,
                self.evaluated_condition,
                self.verification_outcome,
            )
        {
            return Err(ContractError::Schema("invalid observer result v1".into()));
        }
        encode_canonical(self)?;
        Ok(())
    }

    /// Content identity under the `ostk-observer-result-v1` domain: the
    /// semantic finding this result carries, independent of its append event.
    pub fn result_fingerprint(&self) -> ContractResult<ObserverResultFingerprintV1> {
        self.validate_shape()?;
        Ok(ObserverResultFingerprintV1::from_digest(
            domain_separated_digest(DigestDomain::ObserverResultV1, &encode_canonical(self)?),
        ))
    }

    /// Semantic accepted-event identity under the shared `ostk-accepted-event-v1`
    /// domain (EVENT-03: one immutable write history shares one event-ID space).
    pub fn accepted_event_id(&self) -> ContractResult<AcceptedEventId> {
        self.validate_shape()?;
        Ok(AcceptedEventId::from_digest(domain_separated_digest(
            DigestDomain::AcceptedEvent,
            &encode_canonical(self)?,
        )))
    }
}

/// Build one [`ObserverResultV1`] whose `verification_outcome` is exactly
/// [`derive_verification_outcome`]'s pure result for `admitted` and `run`.
#[allow(clippy::too_many_arguments)]
pub fn build_observer_result(
    admitted: &AdmittedObserverV1,
    run: &ObserverRunReceiptV1,
    profile: ProfileReferenceV1,
    scope: AuthenticatedProjectScopeV1,
    predicate: RegistryReferenceV1,
    applicability: Vec<ConcreteApplicabilityDimensionV1>,
    claim_shape: ObserverClaimShapeV1,
    evaluated_condition: EvaluatedConditionV1,
    effective_at: CanonicalTimestamp,
) -> ContractResult<ObserverResultV1> {
    let verification_outcome =
        derive_verification_outcome(admitted, run, claim_shape, evaluated_condition)?;
    let result = ObserverResultV1 {
        schema_version: OBSERVER_SCHEMA_VERSION,
        event_kind: ContractId::new(OBSERVER_RESULT_EVENT_KIND)?,
        profile,
        scope,
        predicate,
        applicability,
        admission_digest: admitted.admission().digest()?,
        run_receipt_digest: run.digest()?,
        claim_shape,
        evaluated_condition,
        verification_outcome,
        effective_at,
    };
    result.validate_shape()?;
    Ok(result)
}

/// Opaque append capability for one [`ObserverResultV1`] accepted event.
///
/// No production constructor exists in this contract-only stage. A later
/// repository seam must construct it from trusted scope, active-registry, and
/// admission witnesses in the same transaction; a public candidate result
/// cannot promote itself.
#[derive(Debug)]
pub struct AdmittedObserverResultV1 {
    result: ObserverResultV1,
}

impl AdmittedObserverResultV1 {
    pub const fn result(&self) -> &ObserverResultV1 {
        &self.result
    }

    #[cfg(test)]
    fn from_test_witness(result: ObserverResultV1) -> ContractResult<Self> {
        result.validate_shape()?;
        Ok(Self { result })
    }
}

/// Durable finding: two admitted observers with overlapping admitted domains,
/// the same predicate reference, and the same concrete applicability reached
/// incompatible outputs.
///
/// Every affected observation becomes indeterminate until a rule narrows the
/// domains or evidence resolves the disagreement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObserverDerivationDisagreementV1 {
    pub schema_version: u32,
    pub profile: ProfileReferenceV1,
    pub scope: AuthenticatedProjectScopeV1,
    pub predicate: RegistryReferenceV1,
    pub applicability: Vec<ConcreteApplicabilityDimensionV1>,
    pub left_admission_digest: Sha256Digest,
    pub right_admission_digest: Sha256Digest,
    pub left_result_fingerprint: ObserverResultFingerprintV1,
    pub right_result_fingerprint: ObserverResultFingerprintV1,
    pub detected_at: CanonicalTimestamp,
}

impl ObserverDerivationDisagreementV1 {
    fn validate_shape(&self) -> ContractResult<()> {
        self.profile.validate()?;
        validate_registry_reference(&self.predicate)?;
        if self.schema_version != OBSERVER_SCHEMA_VERSION
            || self.applicability.len() > MAX_APPLICABILITY_DIMENSIONS
            || !strictly_sorted_by_dimension(&self.applicability)
            || self.left_admission_digest == Sha256Digest::ZERO
            || self.right_admission_digest == Sha256Digest::ZERO
            || self.left_result_fingerprint == self.right_result_fingerprint
        {
            return Err(ContractError::Schema(
                "invalid observer derivation disagreement".into(),
            ));
        }
        encode_canonical(self)?;
        Ok(())
    }

    /// Exact finding identity under the `ostk-observer-disagreement-v1` domain.
    pub fn disagreement_fingerprint(&self) -> ContractResult<ObserverDisagreementFingerprintV1> {
        self.validate_shape()?;
        Ok(ObserverDisagreementFingerprintV1::from_digest(
            domain_separated_digest(
                DigestDomain::ObserverDisagreementV1,
                &encode_canonical(self)?,
            ),
        ))
    }
}

/// Pure `observer_derivation_disagreement` detector.
///
/// Returns `Ok(None)` when the two admissions' domains do not overlap, when
/// the predicate or concrete applicability differ, or when either result is
/// only `candidate_only` opposing evidence: a `candidate_only` output remains
/// opposing candidate evidence and never by itself invalidates an otherwise
/// complete verified proof. Returns `Ok(None)` when either result is already
/// `indeterminate`, since there is nothing further to disagree about. Returns
/// `Ok(Some(..))` only when both sides reached a real, differing
/// determination over the same overlapping domain.
pub fn detect_disagreement(
    left_admission: &ObserverAdmissionV2,
    left_result: &ObserverResultV1,
    right_admission: &ObserverAdmissionV2,
    right_result: &ObserverResultV1,
    detected_at: CanonicalTimestamp,
) -> ContractResult<Option<ObserverDerivationDisagreementV1>> {
    left_admission.validate_shape()?;
    right_admission.validate_shape()?;
    left_result.validate_shape()?;
    right_result.validate_shape()?;

    let domains_overlap = kinds_overlap(
        &left_admission.input_domain.supported_resource_kinds,
        &right_admission.input_domain.supported_resource_kinds,
    ) && kinds_overlap(
        &left_admission.input_domain.supported_source_kinds,
        &right_admission.input_domain.supported_source_kinds,
    );
    let same_predicate = left_result.predicate == right_result.predicate;
    let same_applicability = left_result.applicability == right_result.applicability;
    let same_scope = left_result.scope == right_result.scope;
    if !(domains_overlap && same_predicate && same_applicability && same_scope) {
        return Ok(None);
    }

    let neither_is_only_candidate_evidence = left_result.verification_outcome
        != VerificationOutcomeV1::Candidate
        && right_result.verification_outcome != VerificationOutcomeV1::Candidate;
    let both_reached_a_determination = left_result.verification_outcome
        != VerificationOutcomeV1::Indeterminate
        && right_result.verification_outcome != VerificationOutcomeV1::Indeterminate;
    if !(neither_is_only_candidate_evidence && both_reached_a_determination) {
        return Ok(None);
    }

    let incompatible = left_result.evaluated_condition != right_result.evaluated_condition
        || left_result.verification_outcome != right_result.verification_outcome;
    if !incompatible {
        return Ok(None);
    }

    let disagreement = ObserverDerivationDisagreementV1 {
        schema_version: OBSERVER_SCHEMA_VERSION,
        profile: left_result.profile.clone(),
        scope: left_result.scope.clone(),
        predicate: left_result.predicate.clone(),
        applicability: left_result.applicability.clone(),
        left_admission_digest: left_admission.digest()?,
        right_admission_digest: right_admission.digest()?,
        left_result_fingerprint: left_result.result_fingerprint()?,
        right_result_fingerprint: right_result.result_fingerprint()?,
        detected_at,
    };
    disagreement.validate_shape()?;
    Ok(Some(disagreement))
}

fn kinds_overlap(left: &[ContractId], right: &[ContractId]) -> bool {
    left.iter().any(|kind| right.contains(kind))
}

fn validate_registry_reference(reference: &RegistryReferenceV1) -> ContractResult<()> {
    reference.validate()?;
    if reference.entry_digest == Sha256Digest::ZERO {
        return Err(ContractError::Schema(
            "registry reference cannot use the zero digest".into(),
        ));
    }
    Ok(())
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn strictly_sorted_by_dimension(values: &[ConcreteApplicabilityDimensionV1]) -> bool {
    values
        .windows(2)
        .all(|pair| pair[0].dimension_id < pair[1].dimension_id)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use sha2::{Digest as _, Sha256};

    use super::*;
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
    const NEGATIVE_LLM_CLOSED_WORLD_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/observer/negative-llm-closed-world-v1.jsonl"
    );
    const NEGATIVE_UNKNOWN_FIELD_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/observer/negative-unknown-field-v1.jsonl"
    );
    const NEGATIVE_UNSORTED_DEPENDENCY_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/observer/negative-unsorted-dependency-digests-v1.jsonl"
    );

    const ADMISSION_DIGEST: &str =
        "6ecf60cd22cdd72f53e59b8c239a4dfd063d6e4c30aeda68a5a8f781b20dd4c4";
    const ADMISSION_RAW_SHA256: &str =
        "555c9d40c1b78e0bd6dc45385658f81f688f1aa8a6190e699f1fdc4ce5046677";
    const ADMISSION_POSITIVE_RAW_SHA256: &str =
        "ad22628f8957055d51e0235f9bda16d49518fd2aadea6719c6f4a3ecb35cfa7b";
    const ADMISSION_CANDIDATE_RAW_SHA256: &str =
        "ba94d2245f8222bc9ec97b1038e714e519c3d1058fb6939c736e13dd344ed4dc";
    const RUN_RECEIPT_SUCCESS_RAW_SHA256: &str =
        "363a5a83d47dfeae6ffe5df229966790d748dd31b40681881396b8c25da49d92";
    const RESULT_VERIFIED_NEGATIVE_RAW_SHA256: &str =
        "a39760ee8635ac221ea29706dde44c56f6255ab241d6d62aafe515435005e703";
    const VECTOR_SUITE_RAW_SHA256: &str =
        "f83d43d588d9b789b2cc50640d549498c06ad78bf9ff94f54525e7e0e273219f";
    const NEGATIVE_LLM_CLOSED_WORLD_RAW_SHA256: &str =
        "7241b069efa722206bc823db510e85b7a0da27e606d6f01b6121fa09c4f72a69";
    const NEGATIVE_UNKNOWN_FIELD_RAW_SHA256: &str =
        "857db4d439006bfce98e0078971ec3d0a55d8784b8ee4602a808f842b8a71bdb";
    const NEGATIVE_UNSORTED_DEPENDENCY_RAW_SHA256: &str =
        "da105377c890d9c5522eb9b1bd2c94c0e0c677e6ca367a3ef068bfcc7e323eaf";

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

    fn matching_runtime_identity(
        admitted: &ObserverExecutableIdentityV1,
    ) -> ObserverRuntimeIdentityV1 {
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
        let admitted = AdmittedObserverV1::from_test_witness(admission.clone()).unwrap();
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
    fn closed_world_admission_verifies_an_exact_set_under_full_coverage() {
        let admission = admission("ast_schema", ObserverAdmissionModeV1::ClosedWorldVerified);
        let admitted = AdmittedObserverV1::from_test_witness(admission.clone()).unwrap();
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
        let admitted = AdmittedObserverV1::from_test_witness(admission.clone()).unwrap();
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
        let admitted = AdmittedObserverV1::from_test_witness(admission).unwrap();
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
    fn timeout_is_always_indeterminate_never_a_verified_negative() {
        let admission = admission("ast_schema", ObserverAdmissionModeV1::ClosedWorldVerified);
        let admitted = AdmittedObserverV1::from_test_witness(admission.clone()).unwrap();
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
        let admitted = AdmittedObserverV1::from_test_witness(admission.clone()).unwrap();
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
        let positive_admitted =
            AdmittedObserverV1::from_test_witness(positive_admission.clone()).unwrap();
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
        let candidate_admitted =
            AdmittedObserverV1::from_test_witness(candidate_admission.clone()).unwrap();
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
        let admitted = AdmittedObserverV1::from_test_witness(admission.clone()).unwrap();
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
    fn deterministic_replay_reordered_but_sorted_inputs_yield_identical_digest() {
        let admission = admission("ast_schema", ObserverAdmissionModeV1::ClosedWorldVerified);
        let mut inputs_a = zero_gap_inputs();
        inputs_a.included.sample = vec![
            resource_uri("rust.enum", IdentityForm::Occurrence, 0x01),
            resource_uri("rust.enum", IdentityForm::Occurrence, 0x02),
        ];
        let mut inputs_b = zero_gap_inputs();
        inputs_b.included.sample = vec![
            resource_uri("rust.enum", IdentityForm::Occurrence, 0x01),
            resource_uri("rust.enum", IdentityForm::Occurrence, 0x02),
        ];
        inputs_b.included.sample.sort();
        let run_a = run_receipt(
            matching_runtime_identity(&admission.identity),
            inputs_a,
            full_coverage_witness(),
            ObserverOutcomeKindV1::Success,
        );
        let run_b = run_receipt(
            matching_runtime_identity(&admission.identity),
            inputs_b,
            full_coverage_witness(),
            ObserverOutcomeKindV1::Success,
        );
        assert_eq!(run_a.digest().unwrap(), run_b.digest().unwrap());
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
        let closed_admission =
            admission("ast_schema", ObserverAdmissionModeV1::ClosedWorldVerified);
        let closed_admitted =
            AdmittedObserverV1::from_test_witness(closed_admission.clone()).unwrap();
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

        let mut other_admission =
            admission("ast_schema", ObserverAdmissionModeV1::PositiveVerified);
        other_admission.admission_id = ContractId::new("observer.ast_schema_enum_v2").unwrap();
        let other_admitted =
            AdmittedObserverV1::from_test_witness(other_admission.clone()).unwrap();
        let other_run = run_receipt(
            matching_runtime_identity(&other_admission.identity),
            zero_gap_inputs(),
            full_coverage_witness(),
            ObserverOutcomeKindV1::Success,
        );
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
            &closed_admission,
            &negative_result,
            &other_admission,
            &positive_result,
            timestamp("2026-08-14T13:00:00.000000000Z"),
        )
        .unwrap();
        assert!(disagreement.is_some());
    }

    #[test]
    fn non_overlapping_domains_never_disagree() {
        let closed_admission =
            admission("ast_schema", ObserverAdmissionModeV1::ClosedWorldVerified);
        let closed_admitted =
            AdmittedObserverV1::from_test_witness(closed_admission.clone()).unwrap();
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

        let mut disjoint_admission =
            admission("ast_schema", ObserverAdmissionModeV1::PositiveVerified);
        disjoint_admission.admission_id = ContractId::new("observer.other_enum").unwrap();
        disjoint_admission.input_domain.supported_resource_kinds =
            vec![ContractId::new("rust.struct").unwrap()];
        let disjoint_admitted =
            AdmittedObserverV1::from_test_witness(disjoint_admission.clone()).unwrap();
        let disjoint_run = run_receipt(
            matching_runtime_identity(&disjoint_admission.identity),
            zero_gap_inputs(),
            full_coverage_witness(),
            ObserverOutcomeKindV1::Success,
        );
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
            &closed_admission,
            &negative_result,
            &disjoint_admission,
            &positive_result,
            timestamp("2026-08-14T13:00:00.000000000Z"),
        )
        .unwrap();
        assert!(disagreement.is_none());
    }

    #[test]
    fn candidate_only_opposing_evidence_does_not_invalidate_a_verified_proof() {
        let closed_admission =
            admission("ast_schema", ObserverAdmissionModeV1::ClosedWorldVerified);
        let closed_admitted =
            AdmittedObserverV1::from_test_witness(closed_admission.clone()).unwrap();
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
        let llm_admitted = AdmittedObserverV1::from_test_witness(llm_admission.clone()).unwrap();
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
            &closed_admission,
            &negative_result,
            &llm_admission,
            &candidate_result,
            timestamp("2026-08-14T13:00:00.000000000Z"),
        )
        .unwrap();
        assert!(disagreement.is_none());
    }

    #[test]
    fn admitted_observer_result_requires_valid_shape() {
        let admission = admission("ast_schema", ObserverAdmissionModeV1::ClosedWorldVerified);
        let admitted = AdmittedObserverV1::from_test_witness(admission.clone()).unwrap();
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
        let admitted = AdmittedObserverV1::from_test_witness(admission.clone()).unwrap();
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
        let sanity_admission =
            admission("ast_schema", ObserverAdmissionModeV1::ClosedWorldVerified);
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
        let admission: ObserverAdmissionV2 =
            crate::memory_contracts::canonical::decode_strict(bytes).unwrap();
        admission.validate_shape().unwrap();
        assert_eq!(admission.mode, ObserverAdmissionModeV1::PositiveVerified);
    }

    #[test]
    fn candidate_only_fixture_decodes() {
        let bytes = record(ADMISSION_CANDIDATE_FIXTURE);
        assert_eq!(raw_sha256(bytes), ADMISSION_CANDIDATE_RAW_SHA256);
        let admission: ObserverAdmissionV2 =
            crate::memory_contracts::canonical::decode_strict(bytes).unwrap();
        admission.validate_shape().unwrap();
        assert_eq!(admission.mode, ObserverAdmissionModeV1::CandidateOnly);
    }

    #[test]
    fn run_receipt_success_fixture_decodes() {
        let bytes = record(RUN_RECEIPT_SUCCESS_FIXTURE);
        assert_eq!(raw_sha256(bytes), RUN_RECEIPT_SUCCESS_RAW_SHA256);
        let run: ObserverRunReceiptV1 =
            crate::memory_contracts::canonical::decode_strict(bytes).unwrap();
        run.validate_shape().unwrap();
        assert_eq!(run.outcome, ObserverOutcomeKindV1::Success);
    }

    #[test]
    fn result_verified_negative_fixture_decodes() {
        let bytes = record(RESULT_VERIFIED_NEGATIVE_FIXTURE);
        assert_eq!(raw_sha256(bytes), RESULT_VERIFIED_NEGATIVE_RAW_SHA256);
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
        let _: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    }

    #[test]
    fn negative_llm_closed_world_fixture_is_rejected() {
        let bytes = record(NEGATIVE_LLM_CLOSED_WORLD_FIXTURE);
        assert_eq!(raw_sha256(bytes), NEGATIVE_LLM_CLOSED_WORLD_RAW_SHA256);
        let admission: ObserverAdmissionV2 =
            crate::memory_contracts::canonical::decode_strict(bytes).unwrap();
        assert!(admission.validate_shape().is_err());
    }

    #[test]
    fn negative_unknown_field_fixture_is_rejected() {
        let bytes = record(NEGATIVE_UNKNOWN_FIELD_FIXTURE);
        assert_eq!(raw_sha256(bytes), NEGATIVE_UNKNOWN_FIELD_RAW_SHA256);
        let decoded: ContractResult<ObserverAdmissionV2> =
            crate::memory_contracts::canonical::decode_strict(bytes);
        assert!(decoded.is_err());
    }

    #[test]
    fn negative_unsorted_dependency_digests_fixture_is_rejected() {
        let bytes = record(NEGATIVE_UNSORTED_DEPENDENCY_FIXTURE);
        assert_eq!(raw_sha256(bytes), NEGATIVE_UNSORTED_DEPENDENCY_RAW_SHA256);
        let admission: ObserverAdmissionV2 =
            crate::memory_contracts::canonical::decode_strict(bytes).unwrap();
        assert!(admission.validate_shape().is_err());
    }
}
