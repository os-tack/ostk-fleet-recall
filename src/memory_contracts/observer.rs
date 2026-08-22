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
//! it first requires the run to bind to *this* admission (the run's own
//! `admission` reference equals [`AdmittedObserverV1::admission_reference`],
//! its witnessed executable/dependency digests match the admitted identity,
//! its configuration-context digest matches the admitted one, and every
//! admission-required applicability dimension is present in the run's
//! concrete applicability) before considering the run's outcome at all,
//! since none of the executable/dependency check alone proves the run was
//! actually produced under this admission's configuration or applicability
//! scope; `verified_negative`/`verified_exact_set` further require
//! `closed_world_verified`, zero skipped/failed/unsupported/unknown inputs,
//! and complete, current, contiguous-when-applicable coverage;
//! `positive_verified` may still prove an individually found positive under
//! partial coverage; `candidate_only` never verifies; dependency drift and
//! timeout/resource exhaustion always resolve to `indeterminate`, never a
//! verified negative and never a silent failure. [`build_observer_result`]
//! similarly rejects unless the caller-supplied predicate and applicability
//! equal the admission's predicate and the run's applicability, so an
//! admitted-for-P observer can never emit a verified finding about an
//! unrelated predicate or an applicability its run never read.
//!
//! [`detect_disagreement`] implements `observer_derivation_disagreement`. Each
//! side must supply its governance-activated [`AdmittedObserverV1`]
//! capability -- never a bare, freely constructible `ObserverAdmissionV2` --
//! together with the exact [`ObserverRunReceiptV1`] it claims to have
//! produced. [`require_result_matches_admitted_run`] then requires the
//! result's `admission_digest` to equal that admission's real digest, its
//! `run_receipt_digest` to equal that run receipt's real digest (naming a
//! receipt that was never actually supplied is rejected, not merely
//! unverified), and its self-reported `verification_outcome` to equal what
//! [`derive_verification_outcome`] independently recomputes from the supplied
//! admission and run receipt -- so a hand-built public [`ObserverResultV1`]
//! can neither borrow a genuine admission's authority nor relabel its outcome
//! away from its honest derivation (for example, forging `verified_positive`
//! over a run that timed out, whose honest derivation is `indeterminate`)
//! merely by being passed next to public bytes that happen to match. Only
//! after both sides pass that check do incompatible outputs from two admitted
//! observers with overlapping admitted domains, predicate references, and
//! concrete applicability make every affected observation indeterminate,
//! while an admission whose `mode` is `candidate_only` on either side never
//! yields a disagreement: its output remains only opposing candidate evidence
//! and never by itself invalidates a complete verified proof. That
//! suppression is keyed on the admission's `mode`, not on the result's
//! `verification_outcome` (which is in any case already proven above to
//! match its honest derivation).

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
    admission_reference: RegistryReferenceV1,
}

impl AdmittedObserverV1 {
    pub const fn admission(&self) -> &ObserverAdmissionV2 {
        &self.admission
    }

    /// The registry entry reference this activation witness bound to
    /// `admission`. A run receipt's own `admission` field must equal this
    /// exact reference (entry ID, version, and entry digest) before any
    /// derivation may cite the run against this admission (COVER-01,
    /// PRED-05): matching only the admitted executable/dependency identity
    /// is not sufficient, since an unrelated admission can share the same
    /// executable.
    pub const fn admission_reference(&self) -> &RegistryReferenceV1 {
        &self.admission_reference
    }

    #[cfg(test)]
    fn from_test_witness(
        admission: ObserverAdmissionV2,
        admission_reference: RegistryReferenceV1,
    ) -> ContractResult<Self> {
        admission.validate_shape()?;
        validate_registry_reference(&admission_reference)?;
        let entry_id_matches = admission_reference.entry_id == admission.admission_id;
        let version_matches = admission_reference.version == admission.version;
        if !(entry_id_matches && version_matches) {
            return Err(ContractError::Schema(
                "admission reference does not identify this admission".into(),
            ));
        }
        Ok(Self {
            admission,
            admission_reference,
        })
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
/// exactly match the admitted identity), a run outcome kind its own
/// admission never declared in `declared_outcome_kinds`, and a `timeout`
/// outcome all resolve to `indeterminate` unconditionally: never a verified
/// negative, never a silent failure. A `candidate_only` admission never
/// verifies. Otherwise,
/// `verified_negative`/`verified_exact_set` require `closed_world_verified`,
/// zero skipped/failed/unsupported/unknown inputs, a non-empty included-input
/// tally (a closed domain that included nothing proves nothing, however
/// "complete" the coverage receipt reports it), and complete, current,
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

    if run.admission != *admitted.admission_reference() {
        return Ok(VerificationOutcomeV1::Indeterminate);
    }
    if !run
        .executable_identity
        .matches_admitted(&admission.identity)
    {
        return Ok(VerificationOutcomeV1::Indeterminate);
    }
    if run.configuration_context_digest != admission.configuration_context_digest {
        return Ok(VerificationOutcomeV1::Indeterminate);
    }
    if !run_covers_every_required_applicability_dimension(admission, run) {
        return Ok(VerificationOutcomeV1::Indeterminate);
    }
    // A run reporting an outcome kind its own admission never declared is
    // contested input, not a silent pass-through: the declared set is a
    // closed enumeration of what this admitted observer may honestly report,
    // not decoration.
    if !admission.declared_outcome_kinds.contains(&run.outcome) {
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

    // A closed input boundary that included nothing (`included.total_count ==
    // 0`) can never itself support a verified negative or exact-set finding:
    // the coverage receipt is the external authority for "complete", but
    // this module stays fail-closed on its own rather than trusting that a
    // vacuously empty domain was ever the domain the admission intended.
    let full_coverage = run.inputs.has_no_gap_inputs()
        && run.coverage.is_complete_current_and_contiguous()
        && !run.inputs.included.is_empty();

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
///
/// Rejects with [`ContractError::Schema`] unless `predicate` is exactly
/// `admitted.admission().predicate` and `applicability` is exactly
/// `run.applicability`: an admitted-for-P observer must never be able to
/// emit a verified finding about an unrelated predicate Q, nor about a
/// concrete applicability its run receipt never actually read (COVER-01,
/// AUTH-03).
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
    if predicate != admitted.admission().predicate {
        return Err(ContractError::Schema(
            "observer result predicate must match the admitted predicate".into(),
        ));
    }
    if applicability != run.applicability {
        return Err(ContractError::Schema(
            "observer result applicability must match the run receipt applicability".into(),
        ));
    }
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

/// Reject unless `result` is exactly the pure derivation `admitted`'s own
/// `run` supports.
///
/// Every field of [`ObserverResultV1`] and [`ObserverRunReceiptV1`] is
/// public, so none of these five bindings may be trusted from the payload
/// alone (AUTH-03): `result.admission_digest` must equal
/// `admitted.admission().digest()`; `result.run_receipt_digest` must equal
/// `run.digest()` (naming a run receipt that was never actually supplied is
/// rejected, not merely unverified); `result.predicate` must equal
/// `admitted.admission().predicate` -- exactly, by `entry_id`, `version`,
/// AND `entry_digest`, i.e. the doc's "predicate versions" (PRED-05) -- so an
/// observer admitted for predicate Q can never emit a verified finding about
/// an unrelated predicate P merely by relabelling the payload field;
/// `result.applicability` must equal `run.applicability`, so a result can
/// never claim a concrete applicability its own cited run receipt never
/// actually read (COVER-01); and `result.verification_outcome` must equal
/// what [`derive_verification_outcome`] independently recomputes from
/// `admitted`, `run`, and the result's own `claim_shape`/
/// `evaluated_condition` -- a self-reported outcome relabelled away from its
/// cited run receipt's honest derivation (for example, forging
/// `verified_positive` over a run whose honest derivation is `indeterminate`
/// because it timed out) is rejected outright, never silently accepted and
/// merely ignored downstream. These are the same bindings
/// [`build_observer_result`] already enforces at construction time; this
/// function re-derives and re-checks all of them from the supplied
/// capabilities so a second entry point (a stored/replayed result) can never
/// reopen the seam that one honest constructor closes.
fn require_result_matches_admitted_run(
    admitted: &AdmittedObserverV1,
    run: &ObserverRunReceiptV1,
    result: &ObserverResultV1,
) -> ContractResult<()> {
    result.validate_shape()?;
    if result.admission_digest != admitted.admission().digest()? {
        return Err(ContractError::Schema(
            "result admission_digest does not match the supplied admission".into(),
        ));
    }
    if result.run_receipt_digest != run.digest()? {
        return Err(ContractError::Schema(
            "result run_receipt_digest does not match the supplied run receipt".into(),
        ));
    }
    if result.predicate != admitted.admission().predicate {
        return Err(ContractError::Schema(
            "result predicate does not match the supplied admission's predicate".into(),
        ));
    }
    if result.applicability != run.applicability {
        return Err(ContractError::Schema(
            "result applicability does not match the supplied run receipt's applicability".into(),
        ));
    }
    let expected_outcome = derive_verification_outcome(
        admitted,
        run,
        result.claim_shape,
        result.evaluated_condition,
    )?;
    if result.verification_outcome != expected_outcome {
        return Err(ContractError::Schema(
            "result verification_outcome does not match its derivation from the supplied \
             admission and run receipt"
                .into(),
        ));
    }
    Ok(())
}

/// Pure `observer_derivation_disagreement` detector.
///
/// Each side supplies its governance-activated [`AdmittedObserverV1`]
/// capability (never a bare, freely constructible `ObserverAdmissionV2`)
/// together with the exact [`ObserverRunReceiptV1`] and [`ObserverResultV1`]
/// it claims to have produced. [`require_result_matches_admitted_run`]
/// rejects with [`ContractError::Schema`] unless the result's
/// `admission_digest`, `run_receipt_digest`, and self-reported
/// `verification_outcome` all independently reproduce from the supplied
/// admission and run receipt: a hand-built `ObserverResultV1` cannot borrow a
/// genuine admission's authority, cite a run receipt that was never actually
/// supplied, or relabel its outcome away from its honest derivation merely by
/// being passed next to public bytes that happen to match.
///
/// Returns `Ok(None)` when the two admissions' domains do not overlap, when
/// the predicate or concrete applicability differ, or when either
/// *admission's* `mode` is `candidate_only`: a `candidate_only` output
/// remains opposing candidate evidence and never by itself invalidates an
/// otherwise complete verified proof. This is keyed on the admission's mode,
/// not on a result's self-reported `verification_outcome` (which is now
/// independently proven above in any case), so a `candidate_only`-admitted
/// side can never claim disagreement authority it was never granted. Returns
/// `Ok(None)` when either result is already `indeterminate`, since there is
/// nothing further to disagree about. Returns `Ok(Some(..))` only when both
/// sides reached a real, differing determination over the same overlapping
/// domain.
pub fn detect_disagreement(
    left_admission: &AdmittedObserverV1,
    left_run: &ObserverRunReceiptV1,
    left_result: &ObserverResultV1,
    right_admission: &AdmittedObserverV1,
    right_run: &ObserverRunReceiptV1,
    right_result: &ObserverResultV1,
    detected_at: CanonicalTimestamp,
) -> ContractResult<Option<ObserverDerivationDisagreementV1>> {
    require_result_matches_admitted_run(left_admission, left_run, left_result)?;
    require_result_matches_admitted_run(right_admission, right_run, right_result)?;

    let left_admission_body = left_admission.admission();
    let right_admission_body = right_admission.admission();

    let domains_overlap = kinds_overlap(
        &left_admission_body.input_domain.supported_resource_kinds,
        &right_admission_body.input_domain.supported_resource_kinds,
    ) && kinds_overlap(
        &left_admission_body.input_domain.supported_source_kinds,
        &right_admission_body.input_domain.supported_source_kinds,
    );
    // Keyed on the *admitted* predicate and the *run's* applicability, not on
    // the two results' self-reported `predicate`/`applicability` fields:
    // `require_result_matches_admitted_run` above has already proven each
    // result's fields equal its own admission's predicate and its own run's
    // applicability, but overlap must be decided on the trusted capabilities
    // directly so no future entry point can reintroduce a payload-to-payload
    // comparison here (PRED-05, COVER-01).
    let same_predicate = left_admission_body.predicate == right_admission_body.predicate;
    let same_applicability = left_run.applicability == right_run.applicability;
    let same_scope = left_result.scope == right_result.scope;
    if !(domains_overlap && same_predicate && same_applicability && same_scope) {
        return Ok(None);
    }

    // The suppression is keyed on the *admission's* mode, not on whatever
    // `verification_outcome` the result payload carries: a `candidate_only`
    // admission can never produce anything but candidate evidence, and no
    // result field may override that governance fact. (The result's outcome
    // is in any case now proven above to equal its honest derivation, so
    // there is no forgery left to key off of either way.)
    let neither_admission_is_candidate_only = left_admission_body.mode
        != ObserverAdmissionModeV1::CandidateOnly
        && right_admission_body.mode != ObserverAdmissionModeV1::CandidateOnly;
    let both_reached_a_determination = left_result.verification_outcome
        != VerificationOutcomeV1::Indeterminate
        && right_result.verification_outcome != VerificationOutcomeV1::Indeterminate;
    if !(neither_admission_is_candidate_only && both_reached_a_determination) {
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
        left_admission_digest: left_admission_body.digest()?,
        right_admission_digest: right_admission_body.digest()?,
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

/// Whether every applicability dimension the admission's closed input domain
/// requires (APPL-01/COVER-01) is present in the run's concrete applicability.
/// `run.applicability` is already validated as strictly sorted by
/// `dimension_id` (no duplicates), so "present" and "present exactly once"
/// coincide; this is checked explicitly rather than assumed so a future
/// relaxation of that sort invariant cannot silently reopen a duplicate-count
/// bypass here.
fn run_covers_every_required_applicability_dimension(
    admission: &ObserverAdmissionV2,
    run: &ObserverRunReceiptV1,
) -> bool {
    admission
        .input_domain
        .required_applicability_dimensions
        .iter()
        .all(|required_dimension| {
            run.applicability
                .iter()
                .filter(|concrete| &concrete.dimension_id == required_dimension)
                .count()
                == 1
        })
}

#[cfg(test)]
#[path = "observer_tests.rs"]
mod tests;
