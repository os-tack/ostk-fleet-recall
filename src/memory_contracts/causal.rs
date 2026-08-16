//! Causal hypothesis support, intervention binding, and ratification contracts.
//!
//! This module is contract-only: it establishes closed shapes and a pure
//! derivation of the *maximum achievable* [`SupportLevel`] and the pure v1
//! [`CausalRatificationV1`] admissibility policy. It does not itself append
//! events, resolve active-registry authority, or verify that a cited
//! [`AcceptedEventId`] exists. Deserializing or shape-validating any type here
//! never proves that cited evidence, receipts, or principals are real; a later
//! runtime seam must resolve those against durable trusted witnesses before
//! any append.
//!
//! Support level and adjudication state are deliberately independent axes
//! (CAUS-01). [`SupportLevel`] answers "how strong is the evidence"; it can
//! rise or fall as evidence arrives. [`AdjudicationState`] answers "what did
//! an authorized principal conclude"; [`project_adjudication_state`] folds an
//! append-only sequence of [`CausalRatificationV1`] conclusions and never lets
//! a later record rewrite an earlier one's supporting or opposing evidence.
//!
//! [`CausalHypothesisV1::mechanism`] binds a narrative and a predicted outcome
//! direction to a `recorded_at` timestamp *before* any outcome is observed
//! (RUN-01: a metric excursion is an anomaly until compared against a
//! pre-registered expectation, not narrated after the fact). Its
//! [`PreRecordedMechanismV1::commitment_digest`] lets a later reveal prove
//! the exact narrative and direction were fixed at that time; recomputing the
//! digest under different bytes proves tampering, and
//! [`PreRecordedMechanismV1::recorded_before`] rejects a prediction written
//! after the outcome it claims to predict.
//!
//! [`derive_intervention_support_level`] is the pure v1 policy that decides
//! whether one [`InterventionSupportV1`] can reach `intervention_supported`
//! for a bound [`CausalHypothesisV1`] (lines 1418-1476 of the architecture
//! doc): it fails closed and names every blocking reason rather than
//! collapsing them into one opaque rejection, so a reviewer can see exactly
//! which requirement was not met.
//!
//! [`evaluate_ratification`] is the pure v1 ratification policy (AUTH-03,
//! ACT-04): no positive `caused_by` conclusion is admissible below
//! `intervention_supported`; `primary_trigger` additionally requires an
//! independent second confirmation; and the ratifier can never be the
//! proposing agent, the executor, or an author of the implicated change,
//! except under a previously activated signed separation-of-duty policy that
//! an agent ratifier can never invoke.

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use unicode_normalization::UnicodeNormalization;

use super::{
    ContractError, ContractResult,
    canonical::encode_canonical,
    common::{
        AuthenticatedProjectScopeV1, CanonicalTimestamp, ContractId, ProfileReferenceV1,
        RegistryReferenceV1,
    },
    digest::{DigestDomain, Sha256Digest, domain_separated_digest},
    evidence::{AcceptedEventId, SourceFactId},
    identity::ResourceUri,
};

const CAUSAL_SCHEMA_VERSION: u32 = 1;
const MAX_MECHANISM_NARRATIVE_BYTES: usize = 4_096;
const MAX_MATERIAL_INPUT_DELTAS: usize = 64;
const MAX_PROVENANCE_EVENT_IDS: usize = 256;
const MAX_EVIDENCE_EVENT_IDS: usize = 256;
const MAX_UNRESOLVED_GAP_IDS: usize = 64;
const MAX_CONFIRMATION_LINES: usize = 16;
const MAX_IMPLICATED_AUTHORS: usize = 64;
const MAX_EVIDENCE_BUNDLE_DIGESTS: usize = 64;

// ---------------------------------------------------------------------------
// Support level and adjudication state (two independent axes; CAUS-01)
// ---------------------------------------------------------------------------

/// Explanatory strength for one causal hypothesis.
///
/// Declaration order is the
/// ordering used by `Ord`: `possible < scope_associated <
/// mechanistically_corroborated < intervention_supported`. These are not
/// opaque confidence scores; each step names a distinct, checkable proof
/// obligation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportLevel {
    Possible,
    ScopeAssociated,
    MechanisticallyCorroborated,
    InterventionSupported,
}

/// Human adjudication of a causal claim.
///
/// Independent of [`SupportLevel`]: a
/// principal may ratify that root cause remains unknown, or leave strong
/// mechanistic evidence `open`, without overstating causality (ACT-04).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdjudicationState {
    Open,
    Ratified,
    Refuted,
    Superseded,
}

/// Whether one exact adjudication transition is permitted.
///
/// `open -> {ratified, refuted, superseded}` and `{ratified, refuted} ->
/// superseded` are the only allowed edges. `superseded` is terminal: it can
/// never be reopened, and `ratified` can never revert to `refuted` or `open`
/// — a later, better hypothesis version supersedes it, but the fact that it
/// was ratified with the evidence then available is never erased.
#[must_use]
pub const fn is_allowed_adjudication_transition(
    from: AdjudicationState,
    to: AdjudicationState,
) -> bool {
    matches!(
        (from, to),
        (
            AdjudicationState::Open,
            AdjudicationState::Ratified
                | AdjudicationState::Refuted
                | AdjudicationState::Superseded
        ) | (
            AdjudicationState::Ratified | AdjudicationState::Refuted,
            AdjudicationState::Superseded
        )
    )
}

/// Fold an append-only sequence of ratification conclusions into the current
/// adjudication state.
///
/// Each record's `conclusion` must be a legal transition
/// from the state the fold has reached so far; an illegal transition (for
/// example `ratified -> refuted`, or reopening `superseded`) fails closed
/// without mutating anything already folded. This never inspects or discards
/// supporting/opposing evidence: it only projects state.
pub fn project_adjudication_state(
    events: &[CausalRatificationV1],
) -> ContractResult<AdjudicationState> {
    let mut current = AdjudicationState::Open;
    for event in events {
        event.validate_shape()?;
        let next = event.conclusion.as_adjudication_state();
        if !is_allowed_adjudication_transition(current, next) {
            return Err(ContractError::Schema(
                "adjudication transition is not permitted from the current projected state".into(),
            ));
        }
        current = next;
    }
    Ok(current)
}

// ---------------------------------------------------------------------------
// Mechanism narrative and pre-recorded commitment
// ---------------------------------------------------------------------------

/// Bounded, control-free, NFC mechanism narrative. Single-line by
/// construction: a mechanism statement is a structured claim, not free-form
/// prose.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MechanismNarrativeTextV1(String);

impl MechanismNarrativeTextV1 {
    pub fn parse(value: impl Into<String>) -> ContractResult<Self> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_MECHANISM_NARRATIVE_BYTES
            || !value.nfc().eq(value.chars())
            || value.chars().any(char::is_control)
        {
            return Err(ContractError::Schema(
                "invalid mechanism narrative text".into(),
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Serialize for MechanismNarrativeTextV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for MechanismNarrativeTextV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(D::Error::custom)
    }
}

/// Predicted direction of the outcome measurement, fixed before observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PredictedOutcomeDirectionV1 {
    Improves,
    Degrades,
    Unchanged,
}

/// A mechanism narrative and predicted outcome direction, bound to the exact
/// time it was recorded.
///
/// [`Self::commitment_digest`] is the exact preimage
/// that must have existed at `recorded_at`; [`Self::recorded_before`] proves
/// that time precedes a claimed observation. Neither check proves the
/// timestamp itself is honest — an external anchor or trusted clock witness
/// is a runtime concern outside this contract-only stage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreRecordedMechanismV1 {
    pub schema_version: u32,
    pub mechanism_narrative: MechanismNarrativeTextV1,
    pub predicted_outcome_direction: PredictedOutcomeDirectionV1,
    pub recorded_at: CanonicalTimestamp,
}

impl PreRecordedMechanismV1 {
    pub fn validate_shape(&self) -> ContractResult<()> {
        if self.schema_version != CAUSAL_SCHEMA_VERSION {
            return Err(ContractError::Schema(
                "unsupported pre-recorded mechanism schema version".into(),
            ));
        }
        Ok(())
    }

    /// Domain-separated commitment over the exact narrative, predicted
    /// direction, and recorded time.
    pub fn commitment_digest(&self) -> ContractResult<Sha256Digest> {
        self.validate_shape()?;
        Ok(domain_separated_digest(
            DigestDomain::CausalMechanismCommitmentV1,
            &encode_canonical(self)?,
        ))
    }

    /// Whether this commitment's recorded time strictly precedes
    /// `observed_at`. Equal timestamps do not count as "before": a prediction
    /// and its observation cannot share one instant.
    pub fn recorded_before(&self, observed_at: &CanonicalTimestamp) -> bool {
        self.recorded_at < *observed_at
    }
}

// ---------------------------------------------------------------------------
// Registered material-runtime-input delta inventory (RUN-03)
// ---------------------------------------------------------------------------

/// Closed taxonomy of material runtime inputs a diagnosis must register
/// (RUN-03).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaterialInputCategoryV1 {
    Code,
    Configuration,
    FeatureFlag,
    Migration,
    Dependency,
    Infrastructure,
    Traffic,
    UpstreamState,
}

/// What was observed for one registered material input across the window
/// under study.
///
/// `Unobserved` is explicit rather than an absent field, so a
/// gap in coverage cannot be silently read as "unchanged" (RUN-03, PRED-03).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum MaterialInputObservationV1 {
    Unobserved,
    Unchanged {
        digest: Sha256Digest,
    },
    Changed {
        before_digest: Sha256Digest,
        after_digest: Sha256Digest,
    },
}

impl MaterialInputObservationV1 {
    fn validate_shape(&self) -> ContractResult<()> {
        if let Self::Changed {
            before_digest,
            after_digest,
        } = self
            && before_digest == after_digest
        {
            return Err(ContractError::Schema(
                "a changed material input observation requires distinct before/after digests"
                    .into(),
            ));
        }
        Ok(())
    }

    const fn is_changed(&self) -> bool {
        matches!(self, Self::Changed { .. })
    }
}

/// One registered material input and what was observed for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaterialInputDeltaV1 {
    pub component: ResourceUri,
    pub category: MaterialInputCategoryV1,
    pub observation: MaterialInputObservationV1,
}

impl MaterialInputDeltaV1 {
    fn validate_shape(&self) -> ContractResult<()> {
        self.observation.validate_shape()
    }
}

fn strictly_sorted_by_component(deltas: &[MaterialInputDeltaV1]) -> bool {
    deltas
        .windows(2)
        .all(|pair| pair[0].component < pair[1].component)
}

fn validate_material_input_deltas(deltas: &[MaterialInputDeltaV1]) -> ContractResult<()> {
    if deltas.is_empty()
        || deltas.len() > MAX_MATERIAL_INPUT_DELTAS
        || !strictly_sorted_by_component(deltas)
    {
        return Err(ContractError::Schema(
            "invalid registered material-input delta inventory".into(),
        ));
    }
    for delta in deltas {
        delta.validate_shape()?;
    }
    Ok(())
}

fn changed_delta_count(deltas: &[MaterialInputDeltaV1]) -> usize {
    deltas
        .iter()
        .filter(|delta| delta.observation.is_changed())
        .count()
}

// ---------------------------------------------------------------------------
// CausalHypothesisV1
// ---------------------------------------------------------------------------

/// An explanation for an outcome, pinned to exact identities before any
/// intervention evidence exists. Temporal proximity alone can produce this
/// record; it never by itself verifies causation (CAUS-01).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CausalHypothesisV1 {
    pub schema_version: u32,
    pub profile: ProfileReferenceV1,
    pub scope: AuthenticatedProjectScopeV1,
    pub cause: ResourceUri,
    pub outcome: ResourceUri,
    pub workload: ResourceUri,
    pub artifact: ResourceUri,
    pub environment: ResourceUri,
    pub mechanism: PreRecordedMechanismV1,
    pub material_input_deltas: Vec<MaterialInputDeltaV1>,
}

impl CausalHypothesisV1 {
    pub fn validate_shape(&self) -> ContractResult<()> {
        self.profile.require_frozen_runtime_profile()?;
        self.mechanism.validate_shape()?;
        validate_material_input_deltas(&self.material_input_deltas)?;
        if self.schema_version != CAUSAL_SCHEMA_VERSION || self.cause == self.outcome {
            return Err(ContractError::Schema("invalid causal hypothesis".into()));
        }
        Ok(())
    }

    /// Stable semantic fingerprint. Adjudication, support evidence, and
    /// append coordinates are deliberately absent from this preimage.
    pub fn fingerprint(&self) -> ContractResult<Sha256Digest> {
        self.validate_shape()?;
        Ok(domain_separated_digest(
            DigestDomain::CausalHypothesisV1,
            &encode_canonical(self)?,
        ))
    }
}

// ---------------------------------------------------------------------------
// Corroborating evidence basis (exemplars cannot reach mechanistic support)
// ---------------------------------------------------------------------------

/// The kind of evidence offered in support of a hypothesis below the
/// intervention tier.
///
/// Bounded telemetry exemplars alone can never justify
/// `mechanistically_corroborated`: causal use requires a separately admitted
/// verifier binding exact trace, workload, and revision identities to the
/// proposed mechanism.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CorroboratingEvidenceBasisV1 {
    ExemplarsOnly,
    MechanisticVerifierBound(Box<MechanisticVerifierBoundV1>),
}

/// The exact mechanistic verifier binding backing
/// [`CorroboratingEvidenceBasisV1::MechanisticVerifierBound`]. Boxed in that
/// variant so `ExemplarsOnly` does not pay for this shape's size.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MechanisticVerifierBoundV1 {
    pub verifier: RegistryReferenceV1,
    pub bound_trace_digest: Sha256Digest,
    pub bound_workload: ResourceUri,
    pub bound_revision: ResourceUri,
}

impl CorroboratingEvidenceBasisV1 {
    fn validate_shape(&self) -> ContractResult<()> {
        if let Self::MechanisticVerifierBound(bound) = self {
            bound.verifier.validate()?;
        }
        Ok(())
    }
}

/// Maximum support reachable without any [`InterventionSupportV1`].
///
/// Exemplar
/// evidence caps out at `scope_associated`; only a bound mechanistic verifier
/// can justify `mechanistically_corroborated`, and even that remains below
/// `intervention_supported` until a qualifying intervention exists.
pub fn maximum_support_without_intervention(
    basis: &CorroboratingEvidenceBasisV1,
    scope_associated: bool,
) -> ContractResult<SupportLevel> {
    basis.validate_shape()?;
    Ok(match (basis, scope_associated) {
        (CorroboratingEvidenceBasisV1::ExemplarsOnly, false) => SupportLevel::Possible,
        (CorroboratingEvidenceBasisV1::ExemplarsOnly, true) => SupportLevel::ScopeAssociated,
        (CorroboratingEvidenceBasisV1::MechanisticVerifierBound(_), _) => {
            SupportLevel::MechanisticallyCorroborated
        }
    })
}

// ---------------------------------------------------------------------------
// InterventionSupportV1
// ---------------------------------------------------------------------------

/// Verified interval during which the cause was exposed, and when the
/// outcome began.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedExposureIntervalV1 {
    pub cause_exposure_started_at: CanonicalTimestamp,
    pub cause_exposure_ended_at: Option<CanonicalTimestamp>,
    pub outcome_onset_at: CanonicalTimestamp,
}

impl VerifiedExposureIntervalV1 {
    fn validate_shape(&self) -> ContractResult<()> {
        if let Some(ended) = &self.cause_exposure_ended_at
            && *ended <= self.cause_exposure_started_at
        {
            return Err(ContractError::Schema(
                "cause exposure interval must end after it starts".into(),
            ));
        }
        Ok(())
    }

    /// Exposure must begin strictly before outcome onset and remain open (or
    /// end strictly after onset) so the exposed interval actually overlaps
    /// the instant the outcome began. Exposure starting at or after onset can
    /// never support intervention evidence, no matter how strong the rest of
    /// the bundle is.
    fn begins_before_and_overlaps_onset(&self) -> bool {
        let begins_before = self.cause_exposure_started_at < self.outcome_onset_at;
        let overlaps_onset = self
            .cause_exposure_ended_at
            .as_ref()
            .is_none_or(|ended| *ended > self.outcome_onset_at);
        begins_before && overlaps_onset
    }
}

/// A verified outcome measurement or a linked discrepancy finding, either of
/// which records the exact time the outcome was observed and whether it
/// matched the pre-recorded predicted direction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum VerifiedOutcomeV1 {
    Measurement {
        receipt: AcceptedEventId,
        observed_at: CanonicalTimestamp,
        matches_predicted_direction: bool,
    },
    DiscrepancyFinding {
        discrepancy_fingerprint: Sha256Digest,
        observed_at: CanonicalTimestamp,
        matches_predicted_direction: bool,
    },
}

impl VerifiedOutcomeV1 {
    const fn observed_at(&self) -> &CanonicalTimestamp {
        match self {
            Self::Measurement { observed_at, .. }
            | Self::DiscrepancyFinding { observed_at, .. } => observed_at,
        }
    }

    const fn matches_predicted_direction(&self) -> bool {
        match self {
            Self::Measurement {
                matches_predicted_direction,
                ..
            }
            | Self::DiscrepancyFinding {
                matches_predicted_direction,
                ..
            } => *matches_predicted_direction,
        }
    }
}

/// Whether multiple changed material inputs were isolated from one another.
///
/// `MultipleInputsInseparable` always blocks `intervention_supported`
/// (lines 1418-1476): recovery correlating with several simultaneous changes
/// never proves which one mattered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MaterialInputSeparationV1 {
    SingleInputChanged,
    MultipleInputsInseparable,
    MultipleInputsIsolated { isolation_receipt: AcceptedEventId },
}

/// Closed set of qualifying intervention/reproduction kinds. Unsafe
/// production reintroduction is never required or modeled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterventionKindV1 {
    AuthorizedRollback,
    AuthorizedRollForward,
    BoundedFeatureFlagIsolation,
    TrafficCohortIsolation,
    ControlledCanaryWithdrawal,
    TargetedCorrectiveChange,
    DeterministicReplay,
    FaithfulIsolatedReproduction,
}

/// The exact authorized intervention or reproduction and its provider
/// receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedInterventionV1 {
    pub kind: InterventionKindV1,
    pub authorization_receipt: AcceptedEventId,
    pub provider_receipt: AcceptedEventId,
}

/// Compatible measurement receipts.
///
/// `Mixed` is not a comparison shape at all:
/// it is the disqualifying case where the receipts do not form one coherent
/// exposed/control or before/after pair (lines 1418-1476: "cohorts are
/// mixed").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CohortComparisonV1 {
    ExposedControl {
        exposed_receipt: AcceptedEventId,
        control_receipt: AcceptedEventId,
    },
    BeforeAfter {
        before_receipt: AcceptedEventId,
        after_receipt: AcceptedEventId,
    },
    Mixed {
        receipts: Vec<AcceptedEventId>,
    },
}

/// Whether the intervention's execution outcome was unambiguous.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionOutcomeV1 {
    Unambiguous,
    Ambiguous,
}

/// Whether coverage of the confirmation window is complete (COVER-03).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageCompletenessV1 {
    Complete,
    Partial,
    Unknown,
}

/// Whether coverage of the confirmation window is current or stale.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageFreshnessV1 {
    Current,
    Stale,
}

/// Coverage and confirmation window bound to the intervention.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfirmationCoverageV1 {
    pub completeness: CoverageCompletenessV1,
    pub freshness: CoverageFreshnessV1,
    pub confirmation_window_started_at: CanonicalTimestamp,
    pub confirmation_window_ended_at: CanonicalTimestamp,
}

impl ConfirmationCoverageV1 {
    fn validate_shape(&self) -> ContractResult<()> {
        if self.confirmation_window_ended_at <= self.confirmation_window_started_at {
            return Err(ContractError::Schema(
                "confirmation window must end after it starts".into(),
            ));
        }
        Ok(())
    }

    const fn is_complete_and_current(&self) -> bool {
        matches!(self.completeness, CoverageCompletenessV1::Complete)
            && matches!(self.freshness, CoverageFreshnessV1::Current)
    }
}

/// Supporting, opposing, and confounding evidence for one intervention.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceLedgerV1 {
    pub supporting: Vec<AcceptedEventId>,
    pub opposing: Vec<AcceptedEventId>,
    pub confounding: Vec<AcceptedEventId>,
}

impl EvidenceLedgerV1 {
    fn validate_shape(&self) -> ContractResult<()> {
        for (field, values) in [
            ("supporting", &self.supporting),
            ("opposing", &self.opposing),
            ("confounding", &self.confounding),
        ] {
            if values.len() > MAX_EVIDENCE_EVENT_IDS || !strictly_sorted(values) {
                return Err(ContractError::NonCanonicalSet { field });
            }
        }
        Ok(())
    }
}

/// Intervention support binding (lines 1418-1476 of the architecture doc).
///
/// Exact identities, verified exposure and outcome, complete provenance,
/// registered material-input deltas, the pre-recorded mechanism it is bound
/// to, the exact authorized intervention, compatible measurement receipts,
/// coverage, and the full evidence ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterventionSupportV1 {
    pub schema_version: u32,
    pub profile: ProfileReferenceV1,
    pub scope: AuthenticatedProjectScopeV1,
    pub cause: ResourceUri,
    pub outcome: ResourceUri,
    pub workload: ResourceUri,
    pub artifact: ResourceUri,
    pub environment: ResourceUri,
    pub exposure: VerifiedExposureIntervalV1,
    pub outcome_measurement: VerifiedOutcomeV1,
    pub provenance_to_exposed_cohort: Vec<AcceptedEventId>,
    pub material_input_deltas: Vec<MaterialInputDeltaV1>,
    pub material_input_separation: MaterialInputSeparationV1,
    pub mechanism: PreRecordedMechanismV1,
    pub intervention: AuthorizedInterventionV1,
    pub cohort_comparison: CohortComparisonV1,
    pub execution_outcome: ExecutionOutcomeV1,
    pub coverage: ConfirmationCoverageV1,
    pub evidence: EvidenceLedgerV1,
}

impl InterventionSupportV1 {
    pub fn validate_shape(&self) -> ContractResult<()> {
        self.profile.require_frozen_runtime_profile()?;
        self.exposure.validate_shape()?;
        self.coverage.validate_shape()?;
        self.evidence.validate_shape()?;
        self.mechanism.validate_shape()?;
        validate_material_input_deltas(&self.material_input_deltas)?;
        let changed = changed_delta_count(&self.material_input_deltas);
        let separation_is_consistent = match &self.material_input_separation {
            MaterialInputSeparationV1::SingleInputChanged => changed <= 1,
            MaterialInputSeparationV1::MultipleInputsInseparable
            | MaterialInputSeparationV1::MultipleInputsIsolated { .. } => changed >= 2,
        };
        if self.schema_version != CAUSAL_SCHEMA_VERSION
            || self.cause == self.outcome
            || !separation_is_consistent
            || self.provenance_to_exposed_cohort.is_empty()
            || self.provenance_to_exposed_cohort.len() > MAX_PROVENANCE_EVENT_IDS
            || !strictly_sorted(&self.provenance_to_exposed_cohort)
        {
            return Err(ContractError::Schema(
                "invalid intervention support binding".into(),
            ));
        }
        if let CohortComparisonV1::Mixed { receipts } = &self.cohort_comparison
            && (receipts.len() > MAX_EVIDENCE_EVENT_IDS || !strictly_sorted(receipts))
        {
            return Err(ContractError::NonCanonicalSet {
                field: "cohort_comparison.receipts",
            });
        }
        Ok(())
    }

    /// Whether this intervention is bound to the exact hypothesis: same
    /// causal identities and the exact same pre-recorded mechanism
    /// commitment (not merely an equal-looking narrative).
    pub fn binds_hypothesis(&self, hypothesis: &CausalHypothesisV1) -> ContractResult<bool> {
        self.validate_shape()?;
        hypothesis.validate_shape()?;
        Ok(self.cause == hypothesis.cause
            && self.outcome == hypothesis.outcome
            && self.workload == hypothesis.workload
            && self.artifact == hypothesis.artifact
            && self.environment == hypothesis.environment
            && self.mechanism.commitment_digest()? == hypothesis.mechanism.commitment_digest()?
            && registered_components_are_covered(
                &hypothesis.material_input_deltas,
                &self.material_input_deltas,
            ))
    }

    pub fn digest(&self) -> ContractResult<Sha256Digest> {
        self.validate_shape()?;
        Ok(domain_separated_digest(
            DigestDomain::InterventionSupportV1,
            &encode_canonical(self)?,
        ))
    }
}

fn registered_components_are_covered(
    registered: &[MaterialInputDeltaV1],
    observed: &[MaterialInputDeltaV1],
) -> bool {
    registered.iter().all(|component| {
        observed
            .iter()
            .any(|candidate| candidate.component == component.component)
    })
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

/// Every named way `intervention_supported` can be unreachable (lines
/// 1418-1476). Distinct, named reasons let a reviewer see exactly which
/// requirement failed rather than one opaque rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterventionUnreachableReasonV1 {
    HypothesisMechanismMismatch,
    ExposureDoesNotPrecedeAndOverlapOnset,
    MaterialInputsChangedInseparably,
    PredictionRecordedAfterObservation,
    AmbiguousExecutionOutcome,
    MixedCohorts,
    IncompleteOrStaleCoverage,
}

/// Pure v1 derivation of the maximum support one [`InterventionSupportV1`]
/// can justify for a bound [`CausalHypothesisV1`].
///
/// Returns `Ok(Ok(level))`
/// with `level == SupportLevel::InterventionSupported` only when every
/// binding requirement holds; otherwise returns every blocking reason. This
/// function proves nothing about whether the cited receipts, digests, or
/// principals are real — only that the claimed shape, taken at face value,
/// would or would not qualify under the v1 policy.
pub fn derive_intervention_support_level(
    hypothesis: &CausalHypothesisV1,
    intervention: &InterventionSupportV1,
) -> ContractResult<Result<SupportLevel, Vec<InterventionUnreachableReasonV1>>> {
    hypothesis.validate_shape()?;
    intervention.validate_shape()?;

    let mut reasons = Vec::new();
    if !intervention.binds_hypothesis(hypothesis)? {
        reasons.push(InterventionUnreachableReasonV1::HypothesisMechanismMismatch);
    }
    if !intervention.exposure.begins_before_and_overlaps_onset() {
        reasons.push(InterventionUnreachableReasonV1::ExposureDoesNotPrecedeAndOverlapOnset);
    }
    if matches!(
        intervention.material_input_separation,
        MaterialInputSeparationV1::MultipleInputsInseparable
    ) {
        reasons.push(InterventionUnreachableReasonV1::MaterialInputsChangedInseparably);
    }
    if !hypothesis
        .mechanism
        .recorded_before(intervention.outcome_measurement.observed_at())
    {
        reasons.push(InterventionUnreachableReasonV1::PredictionRecordedAfterObservation);
    }
    if matches!(
        intervention.execution_outcome,
        ExecutionOutcomeV1::Ambiguous
    ) || !intervention
        .outcome_measurement
        .matches_predicted_direction()
    {
        reasons.push(InterventionUnreachableReasonV1::AmbiguousExecutionOutcome);
    }
    if matches!(
        intervention.cohort_comparison,
        CohortComparisonV1::Mixed { .. }
    ) {
        reasons.push(InterventionUnreachableReasonV1::MixedCohorts);
    }
    if !intervention.coverage.is_complete_and_current() {
        reasons.push(InterventionUnreachableReasonV1::IncompleteOrStaleCoverage);
    }

    if reasons.is_empty() {
        Ok(Ok(SupportLevel::InterventionSupported))
    } else {
        Ok(Err(reasons))
    }
}

/// Opaque proof that one [`InterventionSupportV1`] reaches
/// `intervention_supported` under [`derive_intervention_support_level`].
///
/// No
/// production constructor exists at this contract-only stage: deserializing
/// or shape-validating an [`InterventionSupportV1`] cannot create this type.
#[derive(Debug)]
pub struct ProvenInterventionSupportV1 {
    intervention: InterventionSupportV1,
}

impl ProvenInterventionSupportV1 {
    pub const fn intervention(&self) -> &InterventionSupportV1 {
        &self.intervention
    }

    #[cfg(test)]
    fn from_test_derivation(
        hypothesis: &CausalHypothesisV1,
        intervention: InterventionSupportV1,
    ) -> ContractResult<Self> {
        match derive_intervention_support_level(hypothesis, &intervention)? {
            Ok(SupportLevel::InterventionSupported) => Ok(Self { intervention }),
            Ok(_) | Err(_) => Err(ContractError::Schema(
                "intervention does not achieve intervention_supported".into(),
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// CausalRatificationV1
// ---------------------------------------------------------------------------

/// Closed causal role vocabulary.
///
/// `necessary_cause`, `sufficient_cause`, and
/// unqualified `root cause` are deliberately absent: they remain unsupported
/// until a predicate-specific methodology is registered, so this enum cannot
/// represent them at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CausalRoleV1 {
    ContributingCause,
    PrimaryTrigger,
}

/// One line of a second confirmation: the exact source-fact identity behind
/// it and a label for its evidentiary failure mode.
///
/// For example
/// `"withdrawal"`, `"faithful_reproduction"`, `"cohort_isolation"`,
/// `"mechanistic_trace"`, or `"controlled_reintroduction"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfirmationLineV1 {
    pub source_fact_id: SourceFactId,
    pub failure_mode: ContractId,
}

/// Two confirmation lines are independent only when they cite distinct
/// source-fact identities *and* a materially different failure mode.
/// Re-querying the same measurement, re-rendering one trace, or citing the
/// same receipt under two labels is one evidentiary line, not two.
fn confirmation_lines_are_independent(
    first: &ConfirmationLineV1,
    second: &ConfirmationLineV1,
) -> bool {
    first.source_fact_id != second.source_fact_id && first.failure_mode != second.failure_mode
}

fn confirmation_lines_contain_independent_pair(lines: &[ConfirmationLineV1]) -> bool {
    lines.iter().enumerate().any(|(index, first)| {
        lines
            .iter()
            .skip(index + 1)
            .any(|second| confirmation_lines_are_independent(first, second))
    })
}

/// Ratifier identity.
///
/// An agent can never invoke the human-only
/// separation-of-duty exception (`Self::Agent` pairs only with
/// [`SeparationOfDutyResultV1::exception`] being `None`, checked in
/// [`evaluate_separation_of_duty`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RatifierIdentityV1 {
    Agent { principal_id: ContractId },
    HumanPrincipal { principal_id: ContractId },
}

impl RatifierIdentityV1 {
    const fn principal_id(&self) -> &ContractId {
        match self {
            Self::Agent { principal_id } | Self::HumanPrincipal { principal_id } => principal_id,
        }
    }
}

/// A previously activated, signed separation-of-duty exception policy.
///
/// Its
/// signature and activation are established by registry activation
/// elsewhere; this contract cites the activated reference rather than
/// re-verifying a signature itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedSeparationOfDutyExceptionV1 {
    pub policy_reference: RegistryReferenceV1,
    pub activated_at: CanonicalTimestamp,
}

/// Separation-of-duty inputs and result for one ratification. The ratifier
/// must be distinct from the proposer, the executor, and every author of the
/// implicated change (AUTH-03).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeparationOfDutyResultV1 {
    pub ratifier: RatifierIdentityV1,
    pub proposer_principal_id: ContractId,
    pub executor_principal_id: ContractId,
    pub implicated_change_author_principal_ids: Vec<ContractId>,
    pub exception: Option<SignedSeparationOfDutyExceptionV1>,
}

impl SeparationOfDutyResultV1 {
    fn validate_shape(&self) -> ContractResult<()> {
        if self.implicated_change_author_principal_ids.len() > MAX_IMPLICATED_AUTHORS
            || !strictly_sorted(&self.implicated_change_author_principal_ids)
        {
            return Err(ContractError::NonCanonicalSet {
                field: "implicated_change_author_principal_ids",
            });
        }
        Ok(())
    }
}

/// Pure v1 separation-of-duty check (AUTH-03).
///
/// The ratifier passes outright
/// when distinct from every named role. When not distinct, only a
/// [`RatifierIdentityV1::HumanPrincipal`] citing a previously activated
/// [`SignedSeparationOfDutyExceptionV1`] can still pass; an agent ratifier
/// can never use the exception, and a missing exception never passes.
pub fn evaluate_separation_of_duty(result: &SeparationOfDutyResultV1) -> ContractResult<bool> {
    result.validate_shape()?;
    let ratifier_id = result.ratifier.principal_id();
    let distinct = *ratifier_id != result.proposer_principal_id
        && *ratifier_id != result.executor_principal_id
        && !result
            .implicated_change_author_principal_ids
            .contains(ratifier_id);
    if distinct {
        return Ok(true);
    }
    // An agent ratifier can never invoke the exception, regardless of what
    // is cited. Only a human ratifier with a previously activated exception
    // policy may still pass.
    match &result.ratifier {
        RatifierIdentityV1::Agent { .. } => Ok(false),
        RatifierIdentityV1::HumanPrincipal { .. } => match &result.exception {
            Some(exception) => {
                exception.policy_reference.validate()?;
                Ok(true)
            }
            None => Ok(false),
        },
    }
}

/// What one [`CausalRatificationV1`] concludes. Never `open`: a ratification
/// record is itself an authorized conclusion, and [`project_adjudication_state`]
/// starts every hypothesis at `open` implicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CausalConclusionV1 {
    Ratified,
    Refuted,
    Superseded,
}

impl CausalConclusionV1 {
    /// The [`AdjudicationState`] this conclusion transitions to.
    const fn as_adjudication_state(self) -> AdjudicationState {
        match self {
            Self::Ratified => AdjudicationState::Ratified,
            Self::Refuted => AdjudicationState::Refuted,
            Self::Superseded => AdjudicationState::Superseded,
        }
    }
}

/// The exact ratification record (lines 1418-1476).
///
/// Hypothesis and
/// evidence-bundle digests, causal role and bounded scope, achieved support,
/// supporting/opposing evidence, an explicit empty set of unresolved
/// required gaps, non-blocking residual unknowns, policy version, closure
/// watermark, and the separation-of-duty result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CausalRatificationV1 {
    pub schema_version: u32,
    pub profile: ProfileReferenceV1,
    pub scope: AuthenticatedProjectScopeV1,
    pub hypothesis_commitment_digest: Sha256Digest,
    pub evidence_bundle_digests: Vec<Sha256Digest>,
    pub conclusion: CausalConclusionV1,
    pub causal_role: Option<CausalRoleV1>,
    pub bounded_scope: ResourceUri,
    pub achieved_support: SupportLevel,
    pub supporting_evidence: Vec<AcceptedEventId>,
    pub opposing_evidence: Vec<AcceptedEventId>,
    pub unresolved_required_gaps: Vec<ContractId>,
    pub residual_unknowns: Vec<ContractId>,
    pub policy_version: u32,
    pub closure_watermark: CanonicalTimestamp,
    pub separation_of_duty: SeparationOfDutyResultV1,
    pub confirmation_lines: Vec<ConfirmationLineV1>,
    pub supersedes: Option<Sha256Digest>,
}

impl CausalRatificationV1 {
    /// Structural well-formedness only. This does not decide whether the
    /// record is *admissible* under the v1 policy — see
    /// [`evaluate_ratification`] for that.
    pub fn validate_shape(&self) -> ContractResult<()> {
        self.profile.require_frozen_runtime_profile()?;
        self.separation_of_duty.validate_shape()?;
        if self.schema_version != CAUSAL_SCHEMA_VERSION
            || self.policy_version == 0
            || self.hypothesis_commitment_digest == Sha256Digest::ZERO
            || self.evidence_bundle_digests.is_empty()
            || self.evidence_bundle_digests.len() > MAX_EVIDENCE_BUNDLE_DIGESTS
            || !strictly_sorted(&self.evidence_bundle_digests)
            || self.evidence_bundle_digests.contains(&Sha256Digest::ZERO)
        {
            return Err(ContractError::Schema("invalid causal ratification".into()));
        }
        for (field, values) in [
            ("supporting_evidence", &self.supporting_evidence),
            ("opposing_evidence", &self.opposing_evidence),
        ] {
            if values.len() > MAX_EVIDENCE_EVENT_IDS || !strictly_sorted(values) {
                return Err(ContractError::NonCanonicalSet { field });
            }
        }
        if self.unresolved_required_gaps.len() > MAX_UNRESOLVED_GAP_IDS
            || !strictly_sorted(&self.unresolved_required_gaps)
        {
            return Err(ContractError::NonCanonicalSet {
                field: "unresolved_required_gaps",
            });
        }
        if self.residual_unknowns.len() > MAX_UNRESOLVED_GAP_IDS
            || !strictly_sorted(&self.residual_unknowns)
        {
            return Err(ContractError::NonCanonicalSet {
                field: "residual_unknowns",
            });
        }
        if self.confirmation_lines.len() > MAX_CONFIRMATION_LINES {
            return Err(ContractError::Schema("too many confirmation lines".into()));
        }
        if self.conclusion == CausalConclusionV1::Superseded && self.supersedes.is_none() {
            return Err(ContractError::Schema(
                "a superseded conclusion must cite the exact prior digest it supersedes".into(),
            ));
        }
        Ok(())
    }

    pub fn digest(&self) -> ContractResult<Sha256Digest> {
        self.validate_shape()?;
        Ok(domain_separated_digest(
            DigestDomain::CausalRatificationV1,
            &encode_canonical(self)?,
        ))
    }
}

/// Every named way one [`CausalRatificationV1`] can be blocked under the v1
/// policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RatificationBlockedReasonV1 {
    UnresolvedGapsPresent,
    CausalRoleRequiredForRatifiedConclusion,
    CausalRoleForbiddenForNonRatifiedConclusion,
    PositiveCauseBelowInterventionSupport,
    PrimaryTriggerRequiresIndependentSecondConfirmation,
    SeparationOfDutyFailed,
}

/// Pure v1 ratification admissibility policy (lines 1418-1476, AUTH-03,
/// ACT-04).
///
/// `unresolved_required_gaps` must be empty for every conclusion.
/// A `ratified` conclusion requires a causal role, `achieved_support ==
/// intervention_supported`, and — for `primary_trigger` — an independent
/// second confirmation. A `refuted` conclusion may not carry a causal role.
/// A `superseded` conclusion must cite what it supersedes (checked by
/// [`CausalRatificationV1::validate_shape`]). Every conclusion requires the
/// separation-of-duty result to pass.
pub fn evaluate_ratification(
    ratification: &CausalRatificationV1,
) -> ContractResult<Result<(), Vec<RatificationBlockedReasonV1>>> {
    ratification.validate_shape()?;
    let mut reasons = Vec::new();

    if !ratification.unresolved_required_gaps.is_empty() {
        reasons.push(RatificationBlockedReasonV1::UnresolvedGapsPresent);
    }

    match ratification.conclusion {
        CausalConclusionV1::Ratified => {
            if ratification.causal_role.is_none() {
                reasons.push(RatificationBlockedReasonV1::CausalRoleRequiredForRatifiedConclusion);
            }
            if ratification.achieved_support != SupportLevel::InterventionSupported {
                reasons.push(RatificationBlockedReasonV1::PositiveCauseBelowInterventionSupport);
            }
            if ratification.causal_role == Some(CausalRoleV1::PrimaryTrigger)
                && !confirmation_lines_contain_independent_pair(&ratification.confirmation_lines)
            {
                reasons.push(
                    RatificationBlockedReasonV1::PrimaryTriggerRequiresIndependentSecondConfirmation,
                );
            }
        }
        CausalConclusionV1::Refuted => {
            if ratification.causal_role.is_some() {
                reasons
                    .push(RatificationBlockedReasonV1::CausalRoleForbiddenForNonRatifiedConclusion);
            }
        }
        CausalConclusionV1::Superseded => {}
    }

    if !evaluate_separation_of_duty(&ratification.separation_of_duty)? {
        reasons.push(RatificationBlockedReasonV1::SeparationOfDutyFailed);
    }

    if reasons.is_empty() {
        Ok(Ok(()))
    } else {
        Ok(Err(reasons))
    }
}

/// Opaque proof that one [`CausalRatificationV1`] passed
/// [`evaluate_ratification`].
///
/// No production constructor exists at this
/// contract-only stage: deserializing or shape-validating a
/// [`CausalRatificationV1`] cannot create this type.
#[derive(Debug)]
pub struct AdmittedCausalRatificationV1 {
    ratification: CausalRatificationV1,
}

impl AdmittedCausalRatificationV1 {
    pub const fn ratification(&self) -> &CausalRatificationV1 {
        &self.ratification
    }

    #[cfg(test)]
    fn from_test_witness(ratification: CausalRatificationV1) -> ContractResult<Self> {
        match evaluate_ratification(&ratification)? {
            Ok(()) => Ok(Self { ratification }),
            Err(reasons) => Err(ContractError::Schema(format!(
                "ratification blocked: {reasons:?}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
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
            material_input_separation: MaterialInputSeparationV1::SingleInputChanged,
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
            hypothesis_commitment_digest: hypothesis.mechanism.commitment_digest().unwrap(),
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
        assert!(MechanismNarrativeTextV1::parse("ok narrative").is_ok());
    }

    // -- maximum_support_without_intervention --------------------------------

    #[test]
    fn exemplars_only_never_reaches_mechanistic_corroboration() {
        let exemplar_scope_associated = maximum_support_without_intervention(
            &CorroboratingEvidenceBasisV1::ExemplarsOnly,
            true,
        )
        .unwrap();
        assert_eq!(exemplar_scope_associated, SupportLevel::ScopeAssociated);
        assert!(exemplar_scope_associated < SupportLevel::MechanisticallyCorroborated);

        let exemplar_bare = maximum_support_without_intervention(
            &CorroboratingEvidenceBasisV1::ExemplarsOnly,
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
        confounded.material_input_separation = MaterialInputSeparationV1::MultipleInputsInseparable;
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

    #[test]
    fn separation_of_duty_rejects_author_of_change_as_ratifier() {
        let mut result = base_separation_of_duty();
        result.ratifier = RatifierIdentityV1::HumanPrincipal {
            principal_id: ContractId::new("principal.author-one").unwrap(),
        };
        assert!(!evaluate_separation_of_duty(&result).unwrap());
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
        assert!(!evaluate_separation_of_duty(&result).unwrap());
    }

    #[test]
    fn separation_of_duty_human_exception_passes_only_with_activated_policy() {
        let mut result = base_separation_of_duty();
        result.ratifier = RatifierIdentityV1::HumanPrincipal {
            principal_id: ContractId::new("principal.executor").unwrap(),
        };
        assert!(!evaluate_separation_of_duty(&result).unwrap());

        result.exception = Some(SignedSeparationOfDutyExceptionV1 {
            policy_reference: RegistryReferenceV1 {
                entry_id: ContractId::new("policy.sod_exception").unwrap(),
                version: 1,
                entry_digest: digest(0xd1),
            },
            activated_at: ts("2026-08-15T09:00:00.000000000Z"),
        });
        assert!(evaluate_separation_of_duty(&result).unwrap());
    }

    // -- evaluate_ratification -------------------------------------------------

    #[test]
    fn positive_caused_by_cannot_ratify_below_intervention_support() {
        let hyp = hypothesis();
        let mut ratification = base_ratification(&hyp);
        ratification.achieved_support = SupportLevel::MechanisticallyCorroborated;
        let result = evaluate_ratification(&ratification).unwrap();
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
            evaluate_ratification(&ratification).unwrap(),
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
            evaluate_ratification(&ratification).unwrap(),
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
        assert_eq!(evaluate_ratification(&ratification).unwrap(), Ok(()));
        assert!(AdmittedCausalRatificationV1::from_test_witness(ratification).is_ok());
    }

    #[test]
    fn required_gap_blocks_ratification() {
        let hyp = hypothesis();
        let mut ratification = base_ratification(&hyp);
        ratification.unresolved_required_gaps = vec![ContractId::new("gap.coverage").unwrap()];
        assert_eq!(
            evaluate_ratification(&ratification).unwrap(),
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
            evaluate_ratification(&ratification).unwrap(),
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
    const NEGATIVE_CAUSE_EQUALS_OUTCOME_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/causal/negative-cause-equals-outcome.jsonl"
    );
    const NEGATIVE_EMPTY_MATERIAL_INPUT_INVENTORY_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/causal/negative-empty-material-input-inventory.jsonl"
    );
    const NEGATIVE_EXPOSURE_AFTER_ONSET_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/causal/negative-exposure-after-onset.jsonl"
    );
    const NEGATIVE_COVERAGE_PARTIAL_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v3/causal/negative-coverage-partial.jsonl");
    const NEGATIVE_COHORTS_MIXED_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v3/causal/negative-cohorts-mixed.jsonl");
    const NEGATIVE_EXECUTION_AMBIGUOUS_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/causal/negative-execution-ambiguous.jsonl"
    );
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
    const NEGATIVE_CAUSAL_ROLE_UNKNOWN_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/causal/negative-causal-role-unknown.jsonl"
    );
    const NEGATIVE_ADJUDICATION_STATE_UNKNOWN_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/causal/negative-adjudication-state-unknown.jsonl"
    );
    const VECTOR_SUITE_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v3/causal/vector-suite.jsonl");

    const CAUSAL_HYPOTHESIS_V1_RAW_SHA256: &str =
        "37a4d3eb5f37a5a62076abb0a543e2c527aaad8195876d1f4dcb11da230d1c66";
    const CAUSAL_RATIFICATION_CONTRIBUTING_CAUSE_V1_RAW_SHA256: &str =
        "b40db86931beb4f8ea238bfd0533a9afc7bc7316ae5301d3ef469b50928fd740";
    const CAUSAL_RATIFICATION_PRIMARY_TRIGGER_V1_RAW_SHA256: &str =
        "75ef9d100e17880472d5496a846ffe14003a1792d17f7ad646bbee1fbbb7371c";
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
        "5fe51b61a520505a66950db14d1742bb98a0baf521c1c8dda79082e969346ae7";
    const NEGATIVE_RATIFICATION_AGENT_EXCEPTION_REJECTED_RAW_SHA256: &str =
        "471129d17d2172d34f1d8c7e532b27984187e217ec00f91b4c62a1f03bb6cf75";
    const NEGATIVE_RATIFICATION_AUTHOR_AS_RATIFIER_RAW_SHA256: &str =
        "365aa2de73b102f844c24acf5e218d4b0d71edd6ecd0cdad6a791b86d2280474";
    const NEGATIVE_RATIFICATION_BELOW_INTERVENTION_SUPPORT_RAW_SHA256: &str =
        "396abf5c605b09a381daa0440f5ebd9872adf27699f026ee86de363737287602";
    const NEGATIVE_RATIFICATION_SUPERSEDED_WITHOUT_DIGEST_RAW_SHA256: &str =
        "156e3ea784a331e5f54624742606535042a1d6ae30e1e7af6f8b6ad073b46e75";
    const NEGATIVE_RATIFICATION_UNRESOLVED_GAPS_RAW_SHA256: &str =
        "64699d6832d92b9b084f8d51bcb27568d67fd7a86902c4d5eb51232af045bafa";
    const VECTOR_SUITE_RAW_SHA256: &str =
        "f45b5c5f1f23337eb248578c1a82cd8d81b2042753606e7d98d6e64c4b6613d0";

    const CAUSAL_HYPOTHESIS_FINGERPRINT: &str =
        "76b41ed32639adbe1291dd3aca9ae24c51f21ae570014b8119cfc0ce719f3dad";
    const INTERVENTION_SUPPORT_DIGEST: &str =
        "5fb951d6aa0d41b64812ce2e706012eb71621cd7c30dab644ff3e76e7599afe0";
    const RATIFICATION_CONTRIBUTING_CAUSE_DIGEST: &str =
        "cad9fb5757a30b18204c953333e007e153e58d3f3667f6085d4b81137f1e1b84";
    const RATIFICATION_PRIMARY_TRIGGER_DIGEST: &str =
        "ff9e7b9ac4b5c975143e50b3714ff1162d9c3a52c56845c8dcef5155d0e1450b";

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
        let contributing: CausalRatificationV1 =
            decode_and_prove_canonical(RATIFICATION_CONTRIBUTING_CAUSE_FIXTURE);
        assert_eq!(
            contributing.digest().unwrap().to_hex(),
            RATIFICATION_CONTRIBUTING_CAUSE_DIGEST
        );
        assert_eq!(evaluate_ratification(&contributing).unwrap(), Ok(()));
        assert!(AdmittedCausalRatificationV1::from_test_witness(contributing).is_ok());

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
        assert_eq!(evaluate_ratification(&primary).unwrap(), Ok(()));
        assert!(AdmittedCausalRatificationV1::from_test_witness(primary).is_ok());
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
        ];
        for (raw, expected_reason) in cases {
            let ratification: CausalRatificationV1 = decode_and_prove_canonical(raw);
            assert_eq!(
                evaluate_ratification(&ratification).unwrap(),
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
                "negative-ratification-superseded-without-digest",
                NEGATIVE_RATIFICATION_SUPERSEDED_WITHOUT_DIGEST_RAW_SHA256,
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
}
