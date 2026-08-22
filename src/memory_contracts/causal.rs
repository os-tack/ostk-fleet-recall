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
//! [`evaluate_ratification`] is the pure v1 ratification policy (CAUS-01,
//! AUTH-03, ACT-04): it requires the exact [`CausalHypothesisV1`] (and, when
//! claimed, the exact [`InterventionSupportV1`]) the record binds to, both
//! checked for scope and identity equality; for a `ratified` conclusion with
//! a positive causal role it re-derives the bound intervention's support
//! level with [`derive_intervention_support_level`] rather than trusting the
//! record's own `achieved_support` field, so a disqualified intervention
//! (partial coverage, an ambiguous execution outcome, wrong scope, an
//! unbound hypothesis, ...) can never be cited to reach
//! `intervention_supported`; no positive `caused_by` conclusion is
//! admissible below `intervention_supported`; `primary_trigger` additionally
//! requires an independent second confirmation; a `refuted` or `superseded`
//! conclusion can never carry a causal role; unreconciled opposing evidence
//! blocks a `ratified` conclusion; and the ratifier can never be the
//! proposing agent, the executor, or an author of the implicated change,
//! except under a signed separation-of-duty policy that was *provably*
//! activated before this record's own `closure_watermark` (an agent ratifier
//! can never invoke it at all, and an exception dated at or after the
//! ratification it excuses is retroactive self-authorization, not a prior
//! exception, so it is rejected the same as a missing one); a `ratified`
//! conclusion with a positive causal role and no bound intervention at all
//! is rejected, distinctly from one whose bound intervention does not
//! qualify.

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
///
/// Three identity checks apply per event, all CAUS-01: every folded record
/// must carry the exact same `hypothesis_fingerprint` as the first (a
/// ratification authored for a different hypothesis can never flip this
/// one's adjudication state — `project_adjudication_state` does not resolve
/// a hypothesis from a digest itself, so this is the only identity binding
/// available at this pure layer), every folded record must also carry the
/// exact same authenticated `scope` as the first (a record's
/// `hypothesis_fingerprint` alone can never be produced by a foreign scope —
/// `CausalHypothesisV1::fingerprint` covers `scope` too — but that fact is
/// only useful if the fold checks the record's *own* `scope` field itself,
/// since this pure layer never resolves a hypothesis to compare against),
/// and a `superseded` record's `supersedes` digest must equal exactly the
/// digest of the immediately preceding folded record (never an arbitrary or
/// absent prior digest — `validate_shape` only checks presence, not the
/// value).
pub fn project_adjudication_state(
    events: &[CausalRatificationV1],
) -> ContractResult<AdjudicationState> {
    let mut current = AdjudicationState::Open;
    let mut identity: Option<(Sha256Digest, &AuthenticatedProjectScopeV1)> = None;
    let mut previous: Option<&CausalRatificationV1> = None;
    for event in events {
        event.validate_shape()?;
        match identity {
            None => identity = Some((event.hypothesis_fingerprint, &event.scope)),
            Some((expected_fingerprint, _))
                if expected_fingerprint != event.hypothesis_fingerprint =>
            {
                return Err(ContractError::Schema(
                    "adjudication fold mixes ratification records for different causal hypotheses"
                        .into(),
                ));
            }
            Some((_, expected_scope)) if *expected_scope != event.scope => {
                return Err(ContractError::Schema(
                    "adjudication fold mixes ratification records authenticated under different \
                     tenant/project scopes"
                        .into(),
                ));
            }
            Some(_) => {}
        }
        if event.conclusion == CausalConclusionV1::Superseded {
            let immediate_predecessor_digest =
                previous.map(CausalRatificationV1::digest).transpose()?;
            if event.supersedes != immediate_predecessor_digest {
                return Err(ContractError::Schema(
                    "a superseded conclusion must cite the digest of the immediately preceding \
                     folded ratification record"
                        .into(),
                ));
            }
        }
        let next = event.conclusion.as_adjudication_state();
        if !is_allowed_adjudication_transition(current, next) {
            return Err(ContractError::Schema(
                "adjudication transition is not permitted from the current projected state".into(),
            ));
        }
        current = next;
        previous = Some(event);
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
///
/// Declared as the empty struct-variant form `Unobserved {}`, not the bare
/// unit form `Unobserved`, even though both serialize to the identical wire
/// bytes `{"state":"unobserved"}`: `#[serde(deny_unknown_fields)]` on an
/// internally-tagged enum has no effect on a *unit* variant (serde routes it
/// through a tag-only visitor that never checks for residual keys), so a
/// bare `Unobserved` would silently accept `{"state":"unobserved","x":1}` as
/// the identical decoded value. The empty-struct form goes through the
/// normal field-checked struct visitor instead. See
/// `unobserved_material_input_observation_rejects_unknown_field` and the
/// identical fix already applied to `SequenceContinuityV1::Contiguous {}` in
/// `coverage.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum MaterialInputObservationV1 {
    Unobserved {},
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

    /// Whether this registered component was left unobserved (RUN-03,
    /// PRED-03). An unobserved entry never implies "unchanged" — a caller
    /// checking coverage must inspect this directly rather than treating an
    /// absent `Changed` as a negative result.
    const fn is_unobserved(&self) -> bool {
        matches!(self, Self::Unobserved {})
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

/// Whether any registered material input in this inventory was left
/// unobserved. An intervention record built on an inventory with even one
/// unobserved entry cannot prove the material inputs it did not look at
/// stayed constant, so it can never justify `intervention_supported`
/// (RUN-03: "explicitly reports every unknown or unobserved dimension" is
/// not satisfied by silently reading a gap as "unchanged").
fn has_unobserved_delta(deltas: &[MaterialInputDeltaV1]) -> bool {
    deltas.iter().any(|delta| delta.observation.is_unobserved())
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
///
/// `ExemplarsOnly` is the empty struct-variant form `ExemplarsOnly {}`, not
/// the bare unit form: `#[serde(deny_unknown_fields)]` on an
/// internally-tagged enum does not check unknown keys on a *unit* variant
/// (see [`MaterialInputObservationV1::Unobserved`]'s doc comment for why);
/// the struct-variant form serializes to the identical `{"kind":
/// "exemplars_only"}` bytes but goes through the field-checked visitor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CorroboratingEvidenceBasisV1 {
    ExemplarsOnly {},
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
        (CorroboratingEvidenceBasisV1::ExemplarsOnly {}, false) => SupportLevel::Possible,
        (CorroboratingEvidenceBasisV1::ExemplarsOnly {}, true) => SupportLevel::ScopeAssociated,
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
///
/// `SingleInputChanged` and `MultipleInputsInseparable` are the empty
/// struct-variant form (`SingleInputChanged {}`), not the bare unit form:
/// `#[serde(deny_unknown_fields)]` on an internally-tagged enum does not
/// check unknown keys on a *unit* variant (see
/// [`MaterialInputObservationV1::Unobserved`]'s doc comment for why); the
/// struct-variant form serializes to the identical
/// `{"kind":"single_input_changed"}` / `{"kind":"multiple_inputs_inseparable"}`
/// bytes but goes through the field-checked visitor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MaterialInputSeparationV1 {
    SingleInputChanged {},
    MultipleInputsInseparable {},
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
            // Exactly one changed input, not merely "at most one": a record
            // that declares `single_input_changed` while its own inventory
            // shows zero changed inputs is internally inconsistent and must
            // be rejected at the shape level, not silently accepted.
            MaterialInputSeparationV1::SingleInputChanged {} => changed == 1,
            MaterialInputSeparationV1::MultipleInputsInseparable {}
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
    ///
    /// This deliberately does *not* check `self.scope == hypothesis.scope`
    /// (CAUS-01 scope binding) — that is checked separately by
    /// [`derive_intervention_support_level`] under the distinct
    /// [`InterventionUnreachableReasonV1::ScopeMismatch`] reason, so a
    /// reviewer can tell a cross-tenant/cross-project binding attempt apart
    /// from an identity/mechanism mismatch.
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

/// Whether every component the hypothesis registered is present in what the
/// intervention actually observed, *and* agrees with it.
///
/// A registered component the hypothesis left `Unobserved` may be covered by
/// any observation for that component (the intervention is free to be the
/// first to actually look). A registered component the hypothesis already
/// characterized as `Changed` or `Unchanged` must be covered by the exact
/// same observation: an intervention that reports `Unobserved`, or a
/// different before/after digest, for a component the hypothesis already
/// pinned is a contradiction, not corroboration, and must not bind.
fn registered_components_are_covered(
    registered: &[MaterialInputDeltaV1],
    observed: &[MaterialInputDeltaV1],
) -> bool {
    registered.iter().all(|component| {
        observed.iter().any(|candidate| {
            candidate.component == component.component
                && (component.observation.is_unobserved()
                    || candidate.observation == component.observation)
        })
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
    /// The intervention's authenticated tenant/project scope does not
    /// exactly match the hypothesis's (CAUS-01 scope binding). Distinct from
    /// [`Self::HypothesisMechanismMismatch`] so a cross-tenant or
    /// cross-project binding attempt is never confused with an ordinary
    /// identity mismatch inside one scope.
    ScopeMismatch,
    HypothesisMechanismMismatch,
    ExposureDoesNotPrecedeAndOverlapOnset,
    MaterialInputsChangedInseparably,
    /// At least one registered material input the intervention reports on
    /// was left `Unobserved` (RUN-03). A gap in coverage can never be
    /// silently read as "unchanged" for the purpose of reaching the
    /// strongest support level.
    UnobservedMaterialInput,
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
    // CAUS-01 scope binding: an intervention authenticated under a different
    // tenant or project can never support a hypothesis outside its own
    // scope, regardless of how well every other identity lines up.
    if intervention.scope != hypothesis.scope {
        reasons.push(InterventionUnreachableReasonV1::ScopeMismatch);
    }
    if !intervention.binds_hypothesis(hypothesis)? {
        reasons.push(InterventionUnreachableReasonV1::HypothesisMechanismMismatch);
    }
    if !intervention.exposure.begins_before_and_overlaps_onset() {
        reasons.push(InterventionUnreachableReasonV1::ExposureDoesNotPrecedeAndOverlapOnset);
    }
    if matches!(
        intervention.material_input_separation,
        MaterialInputSeparationV1::MultipleInputsInseparable {}
    ) {
        reasons.push(InterventionUnreachableReasonV1::MaterialInputsChangedInseparably);
    }
    if has_unobserved_delta(&intervention.material_input_deltas) {
        reasons.push(InterventionUnreachableReasonV1::UnobservedMaterialInput);
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
/// [`RatifierIdentityV1::HumanPrincipal`] citing a *previously* activated
/// [`SignedSeparationOfDutyExceptionV1`] can still pass; an agent ratifier
/// can never use the exception, a missing exception never passes, and an
/// exception is honored only when its
/// [`SignedSeparationOfDutyExceptionV1::activated_at`] strictly precedes
/// `closure_watermark` — the exact instant [`CausalRatificationV1`] records
/// as this record's own closure. "Previously activated" is a claim about
/// *when relative to this ratification*, not merely that the field is
/// present: an exception dated after the ratification it excuses would be
/// retroactive self-authorization, which is the one thing AUTH-03's
/// human-only carve-out must never become. Equal instants do not count as
/// "before" (matching [`PreRecordedMechanismV1::recorded_before`]'s
/// treatment of equal instants) — a policy cannot activate at the exact
/// moment it excuses.
pub fn evaluate_separation_of_duty(
    result: &SeparationOfDutyResultV1,
    closure_watermark: &CanonicalTimestamp,
) -> ContractResult<bool> {
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
                Ok(exception.activated_at < *closure_watermark)
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

/// A reconciliation of one item of opposing evidence: who reconciled it,
/// when, and its disposition.
///
/// Its presence is what lets
/// [`evaluate_ratification`] admit a `Ratified` conclusion despite the
/// opposing evidence still being cited (doc line 1467: "All verified
/// opposing evidence must be reconciled or the causal claim remains open").
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpposingEvidenceReconciliationV1 {
    pub reconciled_by_principal_id: ContractId,
    pub reconciled_at: CanonicalTimestamp,
    pub disposition: ContractId,
}

/// One item of opposing evidence cited by a ratification, and — if it no
/// longer blocks that ratification — the exact reconciliation that resolved
/// it.
///
/// `reconciliation: None` means unreconciled:
/// [`evaluate_ratification`] blocks any `Ratified` conclusion that cites an
/// unreconciled item.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpposingEvidenceEntryV1 {
    pub event: AcceptedEventId,
    pub reconciliation: Option<OpposingEvidenceReconciliationV1>,
}

/// The exact ratification record (lines 1418-1476).
///
/// The exact hypothesis
/// fingerprint and, when it rests on one, the exact intervention-support
/// digest, evidence-bundle digests, causal role and bounded scope, achieved
/// support, supporting/opposing evidence, an explicit empty set of
/// unresolved required gaps, non-blocking residual unknowns, policy
/// version, closure watermark, and the separation-of-duty result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CausalRatificationV1 {
    pub schema_version: u32,
    pub profile: ProfileReferenceV1,
    pub scope: AuthenticatedProjectScopeV1,
    /// The exact [`CausalHypothesisV1::fingerprint`] this record ratifies —
    /// not merely the mechanism's own commitment digest, which two
    /// hypotheses with different cause/outcome/workload/artifact/environment
    /// identities can share (they differ only in narrative, direction, and
    /// timestamp). See [`Self::binds_hypothesis`].
    pub hypothesis_fingerprint: Sha256Digest,
    /// The exact [`InterventionSupportV1::digest`] this record's
    /// `achieved_support` rests on, when it rests on one. `None` is only
    /// consistent with a conclusion that does not claim
    /// `intervention_supported` for a positive causal role — see
    /// [`Self::binds_intervention`].
    pub intervention_support_digest: Option<Sha256Digest>,
    pub evidence_bundle_digests: Vec<Sha256Digest>,
    pub conclusion: CausalConclusionV1,
    pub causal_role: Option<CausalRoleV1>,
    pub bounded_scope: ResourceUri,
    pub achieved_support: SupportLevel,
    pub supporting_evidence: Vec<AcceptedEventId>,
    pub opposing_evidence: Vec<OpposingEvidenceEntryV1>,
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
            || self.hypothesis_fingerprint == Sha256Digest::ZERO
            || self
                .intervention_support_digest
                .is_some_and(|digest| digest == Sha256Digest::ZERO)
            || self
                .supersedes
                .is_some_and(|digest| digest == Sha256Digest::ZERO)
            || self.evidence_bundle_digests.is_empty()
            || self.evidence_bundle_digests.len() > MAX_EVIDENCE_BUNDLE_DIGESTS
            || !strictly_sorted(&self.evidence_bundle_digests)
            || self.evidence_bundle_digests.contains(&Sha256Digest::ZERO)
        {
            return Err(ContractError::Schema("invalid causal ratification".into()));
        }
        if self.supporting_evidence.len() > MAX_EVIDENCE_EVENT_IDS
            || !strictly_sorted(&self.supporting_evidence)
        {
            return Err(ContractError::NonCanonicalSet {
                field: "supporting_evidence",
            });
        }
        if self.opposing_evidence.len() > MAX_EVIDENCE_EVENT_IDS
            || !strictly_sorted(&self.opposing_evidence)
        {
            return Err(ContractError::NonCanonicalSet {
                field: "opposing_evidence",
            });
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

    /// Whether this ratification is bound to the exact hypothesis it claims
    /// to ratify: same authenticated tenant/project scope (CAUS-01) and the
    /// exact [`CausalHypothesisV1::fingerprint`] — not merely a mechanism
    /// commitment that a differently-identified hypothesis could share.
    ///
    /// This module never resolves a hypothesis from a digest itself (that is
    /// a later runtime seam's job); this pure check lets that seam prove one
    /// ratification record can never be replayed against a hypothesis other
    /// than the one it names.
    pub fn binds_hypothesis(&self, hypothesis: &CausalHypothesisV1) -> ContractResult<bool> {
        self.validate_shape()?;
        Ok(self.scope == hypothesis.scope
            && self.hypothesis_fingerprint == hypothesis.fingerprint()?)
    }

    /// Whether this ratification is bound to the exact
    /// [`InterventionSupportV1`] it claims `achieved_support` rests on: same
    /// authenticated tenant/project scope (CAUS-01) and the exact
    /// [`InterventionSupportV1::digest`].
    pub fn binds_intervention(&self, intervention: &InterventionSupportV1) -> ContractResult<bool> {
        self.validate_shape()?;
        Ok(self.scope == intervention.scope
            && self.intervention_support_digest == Some(intervention.digest()?))
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
    /// This record does not bind to the hypothesis it was checked against —
    /// wrong scope or a fingerprint that does not match
    /// [`CausalHypothesisV1::fingerprint`] (see
    /// [`CausalRatificationV1::binds_hypothesis`]).
    HypothesisBindingMismatch,
    /// A `Ratified` conclusion with a positive causal role was checked
    /// without an intervention-support record to bind to at all.
    MissingInterventionBinding,
    /// An intervention-support record was supplied but does not bind — wrong
    /// scope or a digest that does not match
    /// [`CausalRatificationV1::binds_intervention`].
    InterventionBindingMismatch,
    /// The bound intervention (see [`CausalRatificationV1::binds_intervention`])
    /// does not itself reach `intervention_supported` under
    /// [`derive_intervention_support_level`] — for example partial coverage,
    /// an ambiguous execution outcome, or an intervention that does not
    /// actually bind the hypothesis's identities/mechanism. `binds_intervention`
    /// only proves the ratification cites the exact record it claims to; it
    /// says nothing about whether that record qualifies. `achieved_support`
    /// on [`CausalRatificationV1`] is a self-asserted field and is never
    /// trusted on its own for this check.
    BoundInterventionDoesNotReachInterventionSupported,
    CausalRoleRequiredForRatifiedConclusion,
    CausalRoleForbiddenForNonRatifiedConclusion,
    PositiveCauseBelowInterventionSupport,
    PrimaryTriggerRequiresIndependentSecondConfirmation,
    /// A `Ratified` conclusion cites at least one item of opposing evidence
    /// with no [`OpposingEvidenceReconciliationV1`] attached (doc line 1467:
    /// "All verified opposing evidence must be reconciled or the causal
    /// claim remains open").
    UnreconciledOpposingEvidencePresent,
    /// A `Ratified` conclusion with a positive causal role cites no
    /// supporting evidence at all.
    SupportingEvidenceRequiredForPositiveCausalRole,
    SeparationOfDutyFailed,
}

/// Pure v1 ratification admissibility policy (lines 1418-1476, AUTH-03,
/// ACT-04).
///
/// `unresolved_required_gaps` must be empty for every conclusion, and the
/// record must bind to the exact `hypothesis` supplied (and, when supplied,
/// the exact `intervention`) — see
/// [`CausalRatificationV1::binds_hypothesis`]/[`CausalRatificationV1::binds_intervention`].
/// A `ratified` conclusion with a positive causal role requires the bound
/// intervention to itself re-derive to
/// `SupportLevel::InterventionSupported` under
/// [`derive_intervention_support_level`] — `achieved_support` on the record
/// is self-asserted and is never trusted on its own; this function proves it
/// rather than believing it. A `ratified` conclusion also requires a causal
/// role, non-empty supporting evidence, every cited opposing-evidence item
/// reconciled, and — for `primary_trigger` — an independent second
/// confirmation. A `refuted` or `superseded` conclusion may not carry a
/// causal role. A `superseded` conclusion must cite what it supersedes
/// (checked by [`CausalRatificationV1::validate_shape`]). Every conclusion
/// requires the separation-of-duty result to pass.
pub fn evaluate_ratification(
    ratification: &CausalRatificationV1,
    hypothesis: &CausalHypothesisV1,
    intervention: Option<&InterventionSupportV1>,
) -> ContractResult<Result<(), Vec<RatificationBlockedReasonV1>>> {
    ratification.validate_shape()?;
    let mut reasons = Vec::new();

    if !ratification.unresolved_required_gaps.is_empty() {
        reasons.push(RatificationBlockedReasonV1::UnresolvedGapsPresent);
    }

    if !ratification.binds_hypothesis(hypothesis)? {
        reasons.push(RatificationBlockedReasonV1::HypothesisBindingMismatch);
    }
    match intervention {
        Some(intervention) => {
            if !ratification.binds_intervention(intervention)? {
                reasons.push(RatificationBlockedReasonV1::InterventionBindingMismatch);
            } else if ratification.conclusion == CausalConclusionV1::Ratified
                && ratification.causal_role.is_some()
                && !matches!(
                    derive_intervention_support_level(hypothesis, intervention)?,
                    Ok(SupportLevel::InterventionSupported)
                )
            {
                // `binds_intervention` only proves this ratification cites
                // the exact InterventionSupportV1 record it claims to (right
                // scope, right digest). It proves nothing about whether that
                // record actually qualifies — `achieved_support` on the
                // ratification is self-asserted and must never be trusted on
                // its own. Re-derive the support level from the bound
                // intervention itself; this call also covers
                // `intervention.binds_hypothesis(hypothesis)` and the CAUS-01
                // scope check (`ScopeMismatch`), so no separate check is
                // needed here.
                reasons.push(
                    RatificationBlockedReasonV1::BoundInterventionDoesNotReachInterventionSupported,
                );
            }
        }
        None => {
            if ratification.conclusion == CausalConclusionV1::Ratified
                && ratification.causal_role.is_some()
            {
                reasons.push(RatificationBlockedReasonV1::MissingInterventionBinding);
            }
        }
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
            if ratification
                .opposing_evidence
                .iter()
                .any(|entry| entry.reconciliation.is_none())
            {
                reasons.push(RatificationBlockedReasonV1::UnreconciledOpposingEvidencePresent);
            }
            if ratification.causal_role.is_some() && ratification.supporting_evidence.is_empty() {
                reasons.push(
                    RatificationBlockedReasonV1::SupportingEvidenceRequiredForPositiveCausalRole,
                );
            }
        }
        // A refuted or superseded conclusion may never carry a causal role:
        // without that, both the achieved-support floor and the
        // independent-second-confirmation requirement above are moot, so
        // neither arm can be used to smuggle a positive causal claim past
        // them at any support level.
        CausalConclusionV1::Refuted | CausalConclusionV1::Superseded => {
            if ratification.causal_role.is_some() {
                reasons
                    .push(RatificationBlockedReasonV1::CausalRoleForbiddenForNonRatifiedConclusion);
            }
        }
    }

    if !evaluate_separation_of_duty(
        &ratification.separation_of_duty,
        &ratification.closure_watermark,
    )? {
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
    fn from_test_witness(
        ratification: CausalRatificationV1,
        hypothesis: &CausalHypothesisV1,
        intervention: Option<&InterventionSupportV1>,
    ) -> ContractResult<Self> {
        match evaluate_ratification(&ratification, hypothesis, intervention)? {
            Ok(()) => Ok(Self { ratification }),
            Err(reasons) => Err(ContractError::Schema(format!(
                "ratification blocked: {reasons:?}"
            ))),
        }
    }
}

#[cfg(test)]
#[path = "causal_tests.rs"]
mod tests;
