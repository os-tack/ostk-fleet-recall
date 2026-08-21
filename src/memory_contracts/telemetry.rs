//! Telemetry measurement receipt and `deterministic_stratified_hash_v1` exemplar selection (RUN-01).
//!
//! Keeps three resources distinct, as the architecture doc requires: a bounded
//! [`MeasurementReceiptV1`], a separate [`SloEvaluationV1`], and an alert
//! lifecycle event, which is a different workstream's resource and is not
//! defined here. A telemetry provider is authoritative for its retained
//! records and query responses, never for completeness, correctness, or
//! causal interpretation (RUN-01). Runtime nonconformance is a rebuildable
//! comparison outcome; nothing in this module can grant it on its own.
//!
//! Exemplars are illustration, never proof: [`ExemplarPolicyV1`] fixes closed,
//! versioned caps; [`ExemplarV1`] is a closed allow-listed field set that
//! structurally cannot carry a header, cookie, credential, body, query
//! string, environment value, user identifier, IP address, database value,
//! stack local, or arbitrary raw log line, because no such field exists on
//! the type (EVID-05). `deterministic_stratified_hash_v1` is the only
//! selector implemented here; it never accepts a rotating secret or
//! process-local seed, and it refuses to run under a policy labelled
//! `biased_extrema` because that describes a different, unimplemented
//! selector family.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use unicode_normalization::UnicodeNormalization;

use super::{
    ContractError, ContractResult,
    canonical::encode_canonical,
    common::{
        AuthenticatedProjectScopeV1, CanonicalDecimal, CanonicalTimestamp, ContractId, FixedHex32,
        HexBytes, ProfileReferenceV1, RegistryReferenceV1,
    },
    digest::{DigestDomain, Sha256Digest, domain_separated_digest, framed_digest},
    identity::ResourceUri,
};

const TELEMETRY_SCHEMA_VERSION: u32 = 1;
const MAX_DIMENSIONS: usize = 32;
const MAX_MISSING_DIMENSIONS: usize = 32;
const MAX_SANITIZED_CODE_FRAMES: usize = 4;
const EXEMPLAR_TEXT_MAX_BYTES: usize = 512;

/// Fixed v1 private exemplar cap: at most 8 exemplars, 1,024 bytes each, 8 KiB
/// total. This cap does not vary by policy content; a policy can only select
/// public visibility and, if separately activated, the smaller public cap.
const PRIVATE_EXEMPLAR_MAX_COUNT: usize = 8;
const PRIVATE_EXEMPLAR_MAX_BYTES_EACH: usize = 1_024;
const PRIVATE_EXEMPLAR_MAX_TOTAL_BYTES: usize = 8 * 1_024;

/// Fixed v1 activated public exemplar cap: at most 3 exemplars, 512 bytes
/// each, 1.5 KiB total. The unactivated public default is zero.
const PUBLIC_ACTIVATED_EXEMPLAR_MAX_COUNT: usize = 3;
const PUBLIC_ACTIVATED_EXEMPLAR_MAX_BYTES_EACH: usize = 512;
const PUBLIC_ACTIVATED_EXEMPLAR_MAX_TOTAL_BYTES: usize = 1_536;

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

digest_newtype!(MeasurementReceiptId);
digest_newtype!(SloEvaluationId);

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

/// Strict order by `key` alone, so two dimensions sharing a key but differing
/// only in `value` are caught as non-canonical instead of slipping through a
/// whole-struct comparison that would tie-break on `value`.
fn strictly_sorted_dimensions(values: &[MeasurementDimensionV1]) -> bool {
    values.windows(2).all(|pair| pair[0].key < pair[1].key)
}

/// Strict order by `stratum_key` alone, for the same reason.
fn strictly_sorted_strata(values: &[StratumSelectionV1]) -> bool {
    values
        .windows(2)
        .all(|pair| pair[0].stratum_key < pair[1].stratum_key)
}

/// NFC UTF-8 scalar filter shared by every bounded exemplar text field. A
/// newline is permitted so a sanitized code frame can retain line breaks;
/// every other control scalar, and every other forbidden Unicode scalar
/// class the canonical profile itself rejects, is disallowed here too so a
/// rejection is visible at the typed-field boundary rather than only inside
/// the generic canonical-JSON parser.
fn is_forbidden_exemplar_scalar(value: char) -> bool {
    let code = u32::from(value);
    (value.is_control() && value != '\n')
        || value == '\u{feff}'
        || (0xfdd0..=0xfdef).contains(&code)
        || code & 0xffff >= 0xfffe
        || (0xe000..=0xf8ff).contains(&code)
        || (0xf0000..=0xffffd).contains(&code)
        || (0x0010_0000..=0x0010_fffd).contains(&code)
}

/// Bounded, control-free NFC text used inside exemplar fields (route
/// templates, sanitized code frames, canonical stratum keys).
///
/// It structurally cannot carry a raw multi-line log body: length is capped
/// well under every exemplar byte cap, and only `\n` survives the
/// control-scalar filter.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExemplarTextV1(String);

impl ExemplarTextV1 {
    pub fn parse(value: impl Into<String>) -> ContractResult<Self> {
        let value = value.into();
        if value.is_empty()
            || value.len() > EXEMPLAR_TEXT_MAX_BYTES
            || !value.nfc().eq(value.chars())
            || value.chars().any(is_forbidden_exemplar_scalar)
        {
            return Err(ContractError::Schema("invalid exemplar text".into()));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub const fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    fn from_utf8_bytes(bytes: &[u8]) -> ContractResult<Self> {
        let text = std::str::from_utf8(bytes)
            .map_err(|_| ContractError::Schema("stratum key is not valid UTF-8".into()))?;
        Self::parse(text)
    }
}

impl Serialize for ExemplarTextV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ExemplarTextV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(D::Error::custom)
    }
}

/// Half-open measurement window: `[start, end)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeasurementWindowV1 {
    pub start: CanonicalTimestamp,
    pub end: CanonicalTimestamp,
}

impl MeasurementWindowV1 {
    pub fn validate(&self) -> ContractResult<()> {
        if self.start >= self.end {
            return Err(ContractError::Schema(
                "measurement window must be half-open with start strictly before end".into(),
            ));
        }
        Ok(())
    }

    /// Whether `timestamp` falls inside `[start, end)`.
    pub fn contains(&self, timestamp: &CanonicalTimestamp) -> bool {
        *timestamp >= self.start && *timestamp < self.end
    }
}

/// A durable provider link, or the expiration metadata that replaces it once
/// the provider can no longer rerun the exact query. Either way the receipt
/// remains evidence of the captured evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProviderQueryLinkV1 {
    Durable {
        locator: ResourceUri,
    },
    Expired {
        expired_at: CanonicalTimestamp,
        last_known_locator_digest: Sha256Digest,
    },
}

/// Closed aggregation family. No selector or receipt may name a free-form
/// aggregation string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AggregationV1 {
    Sum,
    Count,
    Rate,
    Average,
    Minimum,
    Maximum,
    PercentileP50,
    PercentileP90,
    PercentileP95,
    PercentileP99,
}

/// COVER-03 completeness, kept as a small local capture on the telemetry
/// receipt. The general coverage-receipt contract belongs to the W0-COVER
/// workstream; this module does not depend on that stub.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageCompletenessV1 {
    Complete,
    Partial,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageFreshnessV1 {
    Current,
    Stale,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageContinuityV1 {
    Contiguous,
    GapDetected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeasurementCoverageV1 {
    pub completeness: CoverageCompletenessV1,
    pub freshness: CoverageFreshnessV1,
    pub continuity: CoverageContinuityV1,
}

/// Dimensions the receipt could not resolve, and why. PRED-03: absence here
/// means `unknown`, never silent agreement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MissingnessV1 {
    pub missing_dimensions: Vec<ContractId>,
    pub reason: Option<ContractId>,
}

impl MissingnessV1 {
    fn validate(&self) -> ContractResult<()> {
        if self.missing_dimensions.len() > MAX_MISSING_DIMENSIONS
            || !strictly_sorted(&self.missing_dimensions)
        {
            return Err(ContractError::Schema("invalid missingness record".into()));
        }
        Ok(())
    }
}

/// One canonical `key`/`value` measurement dimension.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeasurementDimensionV1 {
    pub key: ContractId,
    pub value: ContractId,
}

fn validate_dimensions(
    dimensions: &[MeasurementDimensionV1],
    missing: &[ContractId],
) -> ContractResult<()> {
    if dimensions.len() > MAX_DIMENSIONS
        || !strictly_sorted_dimensions(dimensions)
        || dimensions
            .iter()
            .any(|dimension| missing.contains(&dimension.key))
    {
        return Err(ContractError::Schema(
            "invalid measurement dimensions".into(),
        ));
    }
    Ok(())
}

/// A bounded telemetry measurement receipt (RUN-01, RUN-02, RUN-03, EVID-05).
///
/// The receipt is evidence of one captured evaluation, not proof that the
/// provider query can still be rerun, that the measured population is
/// complete, or that any one workload revision caused the result (RUN-02).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeasurementReceiptV1 {
    pub schema_version: u32,
    pub profile: ProfileReferenceV1,
    pub scope: AuthenticatedProjectScopeV1,
    pub provider: RegistryReferenceV1,
    pub query: RegistryReferenceV1,
    pub query_digest: Sha256Digest,
    pub provider_link: ProviderQueryLinkV1,
    pub window: MeasurementWindowV1,
    pub evaluation_time: CanonicalTimestamp,
    pub aggregation: AggregationV1,
    pub unit: ContractId,
    pub result: CanonicalDecimal,
    pub sample_count: u64,
    pub dimensions: Vec<MeasurementDimensionV1>,
    pub coverage: MeasurementCoverageV1,
    pub missingness: MissingnessV1,
    pub deployment: Option<ResourceUri>,
    pub workload: Option<ResourceUri>,
    pub artifact: Option<ResourceUri>,
    pub config: Option<ResourceUri>,
    pub exemplars: ExemplarSelectionReceiptV1,
    pub private_raw_artifact: Option<ResourceUri>,
    pub provider_response_digest: Sha256Digest,
}

impl MeasurementReceiptV1 {
    pub fn validate_shape(&self) -> ContractResult<()> {
        self.profile.require_frozen_runtime_profile()?;
        self.provider.validate()?;
        self.query.validate()?;
        self.window.validate()?;
        self.missingness.validate()?;
        validate_dimensions(&self.dimensions, &self.missingness.missing_dimensions)?;
        self.exemplars.validate_shape()?;
        // Non-blocking observation fix: `ExemplarV1::occurred_within` used to
        // be dead production code, so a receipt whose window was e.g.
        // 2026-08-15T12:00..12:05 validated with an exemplar dated
        // 2019-01-01 -- illustration evidence from a different incident
        // could ride inside a receipt it never happened in. Every present
        // (non-tombstoned) exemplar must have occurred inside this receipt's
        // own measurement window.
        for present_exemplar in &self.exemplars.exemplars {
            if !present_exemplar.occurred_within(&self.window) {
                return Err(ContractError::Schema(
                    "exemplar occurred outside the measurement window".into(),
                ));
            }
        }
        if self.schema_version != TELEMETRY_SCHEMA_VERSION || self.evaluation_time < self.window.end
        {
            return Err(ContractError::Schema("invalid measurement receipt".into()));
        }
        Ok(())
    }

    /// Semantic receipt identity. Receipt and append metadata cannot affect it
    /// because those values are not fields in this preimage.
    pub fn receipt_id(&self) -> ContractResult<MeasurementReceiptId> {
        self.validate_shape()?;
        Ok(MeasurementReceiptId::from_digest(domain_separated_digest(
            DigestDomain::MeasurementReceiptV1,
            &encode_canonical(self)?,
        )))
    }
}

/// Opaque authority capability consumed by the future append repository.
///
/// No production constructor exists in this contract-only stage. Deserializing
/// or structurally validating [`MeasurementReceiptV1`] cannot create it.
#[derive(Debug)]
pub struct AdmittedMeasurementReceiptV1 {
    receipt: MeasurementReceiptV1,
}

impl AdmittedMeasurementReceiptV1 {
    pub const fn receipt(&self) -> &MeasurementReceiptV1 {
        &self.receipt
    }

    #[cfg(test)]
    fn from_test_witness(receipt: MeasurementReceiptV1) -> ContractResult<Self> {
        receipt.validate_shape()?;
        Ok(Self { receipt })
    }
}

/// Comparison outcome.
///
/// RUN-01: an elevated metric is only ever a candidate or unknown until an
/// applicable rule, comparator, and required coverage all verify; only then
/// can it become a verified `compliant`/`nonconformant` state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SloOutcomeV1 {
    Unknown,
    Candidate,
    Compliant,
    Nonconformant,
}

impl SloOutcomeV1 {
    /// `0` = no verification support, `1` = candidate, `2` = a verified
    /// state. Exemplars can never move this rank on their own (see
    /// [`exemplars_do_not_upgrade_outcome`]).
    const fn verification_rank(self) -> u8 {
        match self {
            Self::Unknown => 0,
            Self::Candidate => 1,
            Self::Compliant | Self::Nonconformant => 2,
        }
    }
}

/// An SLO/rule evaluation, kept distinct from both its cited measurement
/// receipts and any alert lifecycle event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SloEvaluationV1 {
    pub schema_version: u32,
    pub scope: AuthenticatedProjectScopeV1,
    pub normative_rule: RegistryReferenceV1,
    pub measurement_receipt_ids: Vec<MeasurementReceiptId>,
    pub comparator: RegistryReferenceV1,
    pub applicability_evaluator: RegistryReferenceV1,
    pub concrete_context: Vec<MeasurementDimensionV1>,
    pub coverage_result: CoverageCompletenessV1,
    pub outcome: SloOutcomeV1,
}

impl SloEvaluationV1 {
    pub fn validate_shape(&self) -> ContractResult<()> {
        self.normative_rule.validate()?;
        self.comparator.validate()?;
        self.applicability_evaluator.validate()?;
        if self.schema_version != TELEMETRY_SCHEMA_VERSION
            || self.measurement_receipt_ids.is_empty()
            || !strictly_sorted(&self.measurement_receipt_ids)
            || self.concrete_context.len() > MAX_DIMENSIONS
            || !strictly_sorted_dimensions(&self.concrete_context)
            // RUN-01: ANY verified state (rank 2 -- currently `Compliant`
            // and `Nonconformant`, but written off the rank rather than a
            // single enum arm so a future rank-2 variant cannot slip past
            // this check) requires full coverage. Checking only the
            // `Nonconformant` arm would fail open: a `Compliant` outcome
            // under partial/unknown coverage would sail through.
            || (self.outcome.verification_rank() == 2
                && !matches!(self.coverage_result, CoverageCompletenessV1::Complete))
        {
            return Err(ContractError::Schema("invalid SLO evaluation".into()));
        }
        Ok(())
    }

    pub fn evaluation_id(&self) -> ContractResult<SloEvaluationId> {
        self.validate_shape()?;
        Ok(SloEvaluationId::from_digest(domain_separated_digest(
            DigestDomain::SloEvaluationV1,
            &encode_canonical(self)?,
        )))
    }
}

/// Opaque authority capability consumed by the future append repository.
///
/// No production constructor exists in this contract-only stage. Deserializing
/// or structurally validating [`SloEvaluationV1`] cannot create it.
#[derive(Debug)]
pub struct AdmittedSloEvaluationV1 {
    evaluation: SloEvaluationV1,
}

impl AdmittedSloEvaluationV1 {
    pub const fn evaluation(&self) -> &SloEvaluationV1 {
        &self.evaluation
    }

    #[cfg(test)]
    fn from_test_witness(evaluation: SloEvaluationV1) -> ContractResult<Self> {
        evaluation.validate_shape()?;
        Ok(Self { evaluation })
    }
}

/// Exemplars alone establish neither prevalence nor exhaustive coverage and
/// cannot upgrade a hypothesis (architecture doc, "Telemetry receipts and
/// bounded exemplars").
///
/// This predicate makes that a checkable fact: an outcome computed with
/// exemplars present may never outrank the outcome the aggregate alone
/// supports.
pub const fn exemplars_do_not_upgrade_outcome(
    aggregate_only_outcome: SloOutcomeV1,
    with_exemplars_outcome: SloOutcomeV1,
) -> bool {
    with_exemplars_outcome.verification_rank() <= aggregate_only_outcome.verification_rank()
}

/// Private vs. public exemplar visibility. There is no third state: a
/// private-only exemplar set is never partially public.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExemplarVisibilityV1 {
    Private,
    Public,
}

/// The only selector this module implements. A distinct, separately labelled
/// biased-extrema selector is out of scope for v1 and is never named here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExemplarSelectorV1 {
    DeterministicStratifiedHashV1,
}

/// Records that a public exemplar policy was separately activated and
/// independently approved, after public visibility was already established.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicExemplarActivationV1 {
    pub approval: RegistryReferenceV1,
    pub public_visibility_established_at: CanonicalTimestamp,
    pub activated_at: CanonicalTimestamp,
}

/// A registered exemplar-selection policy.
///
/// Numeric caps are never carried as policy fields:
/// [`ExemplarPolicyV1::effective_caps`] derives them from the fixed v1
/// constants, so a payload cannot grant itself a bigger cap merely by naming
/// one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExemplarPolicyV1 {
    pub schema_version: u32,
    pub policy_id: ContractId,
    pub policy_version: u32,
    pub selector: ExemplarSelectorV1,
    pub biased_extrema: bool,
    pub visibility: ExemplarVisibilityV1,
    pub public_activation: Option<PublicExemplarActivationV1>,
}

/// Fixed effective caps derived from policy visibility and activation state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExemplarCapsV1 {
    pub max_count: usize,
    pub max_bytes_each: usize,
    pub max_total_bytes: usize,
}

impl ExemplarPolicyV1 {
    pub fn validate(&self) -> ContractResult<()> {
        if self.schema_version != TELEMETRY_SCHEMA_VERSION || self.policy_version == 0 {
            return Err(ContractError::Schema(
                "invalid exemplar policy version".into(),
            ));
        }
        // The only selector this module implements never runs under a
        // biased-extrema label (`select_exemplars_deterministic_stratified_hash_v1`
        // refuses at call time). Rejecting the combination here too means a
        // reader can trust a decoded `biased_extrema: true` policy actually
        // came from a selector family that supports it -- written as an
        // exhaustive match so a future biased selector variant forces this
        // decision to be revisited rather than silently staying permissive.
        match self.selector {
            ExemplarSelectorV1::DeterministicStratifiedHashV1 if self.biased_extrema => {
                return Err(ContractError::Schema(
                    "deterministic_stratified_hash_v1 cannot be labelled biased_extrema".into(),
                ));
            }
            ExemplarSelectorV1::DeterministicStratifiedHashV1 => {}
        }
        match (self.visibility, &self.public_activation) {
            (ExemplarVisibilityV1::Private, Some(_)) => Err(ContractError::Schema(
                "a private exemplar policy cannot carry a public activation".into(),
            )),
            (ExemplarVisibilityV1::Private | ExemplarVisibilityV1::Public, None) => Ok(()),
            (ExemplarVisibilityV1::Public, Some(activation)) => {
                activation.approval.validate()?;
                if activation.activated_at < activation.public_visibility_established_at {
                    return Err(ContractError::Schema(
                        "public exemplar activation precedes established public visibility".into(),
                    ));
                }
                Ok(())
            }
        }
    }

    pub const fn effective_caps(&self) -> ExemplarCapsV1 {
        match (self.visibility, self.public_activation.is_some()) {
            (ExemplarVisibilityV1::Private, _) => ExemplarCapsV1 {
                max_count: PRIVATE_EXEMPLAR_MAX_COUNT,
                max_bytes_each: PRIVATE_EXEMPLAR_MAX_BYTES_EACH,
                max_total_bytes: PRIVATE_EXEMPLAR_MAX_TOTAL_BYTES,
            },
            (ExemplarVisibilityV1::Public, false) => ExemplarCapsV1 {
                max_count: 0,
                max_bytes_each: 0,
                max_total_bytes: 0,
            },
            (ExemplarVisibilityV1::Public, true) => ExemplarCapsV1 {
                max_count: PUBLIC_ACTIVATED_EXEMPLAR_MAX_COUNT,
                max_bytes_each: PUBLIC_ACTIVATED_EXEMPLAR_MAX_BYTES_EACH,
                max_total_bytes: PUBLIC_ACTIVATED_EXEMPLAR_MAX_TOTAL_BYTES,
            },
        }
    }
}

/// Content identity of one exact policy. Used as the first ingredient of the
/// deterministic per-record ordering key, so a different policy can never
/// silently reuse another policy's exemplar order.
pub fn exemplar_policy_digest(policy: &ExemplarPolicyV1) -> ContractResult<Sha256Digest> {
    policy.validate()?;
    Ok(domain_separated_digest(
        DigestDomain::ExemplarSelectionV1,
        &encode_canonical(policy)?,
    ))
}

/// Closed status/error-class bucket. Never a free-form string, so an
/// exemplar cannot carry an arbitrary status message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExemplarStatusClassV1 {
    Success,
    ClientError,
    ServerError,
    Timeout,
    Cancelled,
    Unknown,
}

/// Opaque trace coordinates. Deliberately just fixed-width identifiers, never
/// a trace body or attributes bag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExemplarTraceCoordinatesV1 {
    pub trace_id: FixedHex32,
    pub span_id: Option<FixedHex32>,
}

/// One bounded, illustration-only exemplar (EVID-05).
///
/// This is the entire allowed field set: bounded time, service/
/// environment/region, workload/cohort, route template, status/error class,
/// duration, sanitized code frames, and opaque trace coordinates. There is no
/// header, cookie, credential, body, query-string, environment-value, user-
/// identifier, IP-address, database-value, stack-local, or raw-log-line
/// field anywhere on this type: `#[serde(deny_unknown_fields)]` rejects any
/// wire payload that tries to add one, so the deny list is enforced
/// structurally rather than by runtime content inspection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExemplarV1 {
    pub schema_version: u32,
    pub occurred_at: CanonicalTimestamp,
    pub service: ContractId,
    pub environment: ContractId,
    pub region: ContractId,
    pub workload: Option<ContractId>,
    pub cohort: Option<ContractId>,
    pub route_template: ExemplarTextV1,
    pub status_class: ExemplarStatusClassV1,
    pub duration_ms: u64,
    pub sanitized_code_frames: Vec<ExemplarTextV1>,
    pub trace: ExemplarTraceCoordinatesV1,
}

impl ExemplarV1 {
    pub fn validate(&self) -> ContractResult<()> {
        if self.schema_version != TELEMETRY_SCHEMA_VERSION
            || self.sanitized_code_frames.len() > MAX_SANITIZED_CODE_FRAMES
        {
            return Err(ContractError::Schema("invalid exemplar".into()));
        }
        Ok(())
    }

    /// Exact canonical wire length, used to enforce the policy's per-exemplar
    /// byte cap.
    pub fn wire_len(&self) -> ContractResult<usize> {
        self.validate()?;
        Ok(encode_canonical(self)?.len())
    }

    /// Content identity, used only for tombstone cross-reference on erasure.
    pub fn exemplar_digest(&self) -> ContractResult<Sha256Digest> {
        self.validate()?;
        Ok(domain_separated_digest(
            DigestDomain::ExemplarSelectionV1,
            &encode_canonical(self)?,
        ))
    }

    pub fn occurred_within(&self, window: &MeasurementWindowV1) -> bool {
        window.contains(&self.occurred_at)
    }
}

/// Why an adapter could not bind a reproducible population for selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PopulationUnboundReasonV1 {
    SnapshotUnavailable,
    IdentitiesUnavailable,
    Irreproducible,
}

/// The exact provider snapshot/query population selection ran against, or
/// the reason none was bound. When unbound, selection returns none while the
/// aggregate receipt is preserved untouched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum PopulationBoundaryV1 {
    Bound {
        snapshot_digest: Sha256Digest,
        query_population_digest: Sha256Digest,
    },
    Unbound {
        reason: PopulationUnboundReasonV1,
    },
}

/// One classified candidate record. `Withheld` means the deny-list check or
/// classification failed for this record: the aggregate keeps counting it,
/// but no exemplar for it can ever be constructed.
#[derive(Debug, Clone)]
pub enum CandidateOutcomeV1 {
    /// Boxed so a large, potentially long, candidate population does not pad
    /// every `Withheld` record out to the size of a full exemplar.
    Eligible(Box<ExemplarV1>),
    Withheld,
}

/// One provider-record identity plus its already-classified outcome.
///
/// The selection function trusts none of this data's authenticity; it only
/// enforces internal consistency (unique immutable IDs) and computes a
/// deterministic order over it.
#[derive(Debug, Clone)]
pub struct SelectionCandidateV1 {
    pub stratum_key: ExemplarTextV1,
    pub measurement_source_fact_id: Sha256Digest,
    pub provider_record_id: HexBytes,
    pub outcome: CandidateOutcomeV1,
}

/// Population input to the selector. `Unbound` and a `Bound` population with
/// zero candidates are different facts: the first means the adapter could
/// not even define what it would have sampled from.
pub enum PopulationInputV1<'a> {
    Unbound(PopulationUnboundReasonV1),
    Bound {
        snapshot_digest: Sha256Digest,
        query_population_digest: Sha256Digest,
        candidates: &'a [SelectionCandidateV1],
    },
}

/// Per-stratum selection summary in canonical stratum order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StratumSelectionV1 {
    pub stratum_key: ExemplarTextV1,
    pub eligible_count: u32,
    pub selected_count: u32,
}

/// Immutable erasure record for one previously selected exemplar (EVID-08,
/// EVID-09). The receipt's counts are unchanged by erasure; only the exemplar
/// payload is removed and replaced by this tombstone.
///
/// `selection_index` is the erased record's stable 0-based position in the
/// original round-robin selection order (out of `selected_count` slots),
/// not a derivative of `erased_exemplar_digest`. Erasure is total even when
/// two selected exemplars are byte-identical in content: each occupies a
/// distinct `selection_index`, so tombstoning one never blocks tombstoning
/// the other, and canonical order and cap/consistency checks key off this
/// index rather than off content-digest set membership.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErasedExemplarTombstoneV1 {
    pub schema_version: u32,
    pub selection_index: u32,
    pub erased_exemplar_digest: Sha256Digest,
    pub erased_at: CanonicalTimestamp,
    pub erasure_policy: RegistryReferenceV1,
}

/// The full, auditable outcome of one exemplar-selection run: policy,
/// population boundary, every count the doc requires, canonical strata, and
/// the selected exemplars (or their tombstones).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExemplarSelectionReceiptV1 {
    pub schema_version: u32,
    pub policy: ExemplarPolicyV1,
    pub policy_digest: Sha256Digest,
    pub population: PopulationBoundaryV1,
    pub strata: Vec<StratumSelectionV1>,
    pub candidate_count: u32,
    pub eligible_count: u32,
    pub withheld_count: u32,
    pub selected_count: u32,
    pub omitted_count: u32,
    pub truncated: bool,
    pub exemplars: Vec<ExemplarV1>,
    pub tombstones: Vec<ErasedExemplarTombstoneV1>,
}

impl ExemplarSelectionReceiptV1 {
    pub fn validate_shape(&self) -> ContractResult<()> {
        self.policy.validate()?;
        if self.schema_version != TELEMETRY_SCHEMA_VERSION
            || self.policy_digest != exemplar_policy_digest(&self.policy)?
        {
            return Err(ContractError::Schema(
                "invalid exemplar selection receipt".into(),
            ));
        }

        match &self.population {
            PopulationBoundaryV1::Unbound { .. } => {
                if self.candidate_count != 0
                    || self.eligible_count != 0
                    || self.withheld_count != 0
                    || self.selected_count != 0
                    || self.omitted_count != 0
                    || self.truncated
                    || !self.strata.is_empty()
                    || !self.exemplars.is_empty()
                    || !self.tombstones.is_empty()
                {
                    return Err(ContractError::Schema(
                        "an unbound population must select none and keep only the aggregate".into(),
                    ));
                }
                return Ok(());
            }
            PopulationBoundaryV1::Bound { .. } => {}
        }

        self.validate_counts_and_strata()?;
        self.validate_caps_and_tombstones()?;
        Ok(())
    }

    /// Candidate/eligible/withheld/selected/omitted arithmetic, canonical
    /// strata order, per-stratum totals, and the present-plus-tombstoned
    /// identity. Split out of [`Self::validate_shape`] purely to stay under
    /// clippy's line-count lint on production code -- every check here ran
    /// (and still runs) unconditionally as part of one shape validation.
    fn validate_counts_and_strata(&self) -> ContractResult<()> {
        let eligible_from_candidates = self
            .candidate_count
            .checked_sub(self.withheld_count)
            .ok_or_else(|| {
                ContractError::Schema("withheld count exceeds candidate count".into())
            })?;
        let selected_plus_omitted = self
            .selected_count
            .checked_add(self.omitted_count)
            .ok_or_else(|| ContractError::Schema("selected plus omitted count overflows".into()))?;
        if eligible_from_candidates != self.eligible_count
            || selected_plus_omitted != self.eligible_count
            || self.truncated != (self.omitted_count > 0)
        {
            return Err(ContractError::Schema(
                "exemplar selection counts are inconsistent".into(),
            ));
        }

        if !strictly_sorted_strata(&self.strata) {
            return Err(ContractError::Schema(
                "exemplar selection strata are not in canonical order".into(),
            ));
        }
        let mut strata_eligible: u32 = 0;
        let mut strata_selected: u32 = 0;
        for stratum in &self.strata {
            if stratum.selected_count > stratum.eligible_count {
                return Err(ContractError::Schema(
                    "a stratum selected more than its eligible count".into(),
                ));
            }
            strata_eligible = strata_eligible
                .checked_add(stratum.eligible_count)
                .ok_or_else(|| ContractError::Schema("stratum eligible total overflows".into()))?;
            strata_selected = strata_selected
                .checked_add(stratum.selected_count)
                .ok_or_else(|| ContractError::Schema("stratum selected total overflows".into()))?;
        }
        if strata_eligible != self.eligible_count || strata_selected != self.selected_count {
            return Err(ContractError::Schema(
                "strata totals do not match the receipt's eligible/selected counts".into(),
            ));
        }

        let present_and_tombstoned = u32::try_from(self.exemplars.len())
            .ok()
            .and_then(|present| {
                u32::try_from(self.tombstones.len())
                    .ok()
                    .and_then(|tombstoned| present.checked_add(tombstoned))
            })
            .ok_or_else(|| ContractError::Schema("exemplar/tombstone count overflows".into()))?;
        if present_and_tombstoned != self.selected_count {
            return Err(ContractError::Schema(
                "present plus tombstoned exemplars must equal the selected count".into(),
            ));
        }
        Ok(())
    }

    /// Policy-derived count/byte caps and tombstone/present-exemplar
    /// consistency. Split out of [`Self::validate_shape`]; see
    /// [`Self::validate_counts_and_strata`] for why.
    fn validate_caps_and_tombstones(&self) -> ContractResult<()> {
        let caps = self.policy.effective_caps();
        // `selected_count` is the true count the policy cap bounds: present
        // plus tombstoned. Checking only `self.exemplars.len()` (as a prior
        // version of this function did) let a payload fabricate tombstones
        // to carry `selected_count` arbitrarily far past the cap while
        // keeping the *present* exemplar count under it -- a genuine
        // selection can never produce `selected_count > cap` (selection
        // stops at the cap and erasure never raises `selected_count`), so
        // nothing legitimate is rejected by enforcing it here too.
        let max_count = u32::try_from(caps.max_count)
            .map_err(|_| ContractError::Schema("policy cap exceeds u32".into()))?;
        if self.selected_count > max_count {
            return Err(ContractError::Schema(
                "selected exemplar count exceeds the policy cap".into(),
            ));
        }
        if self.exemplars.len() > caps.max_count {
            return Err(ContractError::Schema(
                "present exemplar count exceeds the policy cap".into(),
            ));
        }
        let mut total_bytes: usize = 0;
        for exemplar in &self.exemplars {
            let wire_len = exemplar.wire_len()?;
            if wire_len > caps.max_bytes_each {
                return Err(ContractError::Schema(
                    "one exemplar exceeds the policy's per-exemplar byte cap".into(),
                ));
            }
            total_bytes = total_bytes.checked_add(wire_len).ok_or_else(|| {
                ContractError::Schema("exemplar total byte count overflows".into())
            })?;
        }
        if total_bytes > caps.max_total_bytes {
            return Err(ContractError::Schema(
                "selected exemplars exceed the policy's total byte cap".into(),
            ));
        }

        if !strictly_sorted(&self.tombstones) {
            return Err(ContractError::Schema(
                "exemplar tombstones are not in canonical order".into(),
            ));
        }
        // Every tombstone must itself be a shape this module could have
        // produced: a current schema version, and an
        // `erasure_policy` that passes the same `RegistryReferenceV1`
        // validation every other registry reference on this module's types
        // is subject to (an unknown schema version or a zero-version policy
        // reference must fail closed, not decode successfully as evidence).
        //
        // `selection_index` values must be distinct and each address one of
        // the `selected_count` original selection slots. This -- not
        // content-digest set membership against `self.exemplars` -- is what
        // proves the tombstones are a coherent subset of the original
        // selection: two selected exemplars with byte-identical content
        // occupy different `selection_index` values, so tombstoning one
        // never collides with the other still being present.
        let mut tombstoned_indices: BTreeSet<u32> = BTreeSet::new();
        for tombstone in &self.tombstones {
            if tombstone.schema_version != TELEMETRY_SCHEMA_VERSION {
                return Err(ContractError::Schema(
                    "invalid exemplar tombstone schema version".into(),
                ));
            }
            tombstone.erasure_policy.validate()?;
            if tombstone.selection_index >= self.selected_count {
                return Err(ContractError::Schema(
                    "tombstone selection index is out of range".into(),
                ));
            }
            if !tombstoned_indices.insert(tombstone.selection_index) {
                return Err(ContractError::Schema(
                    "duplicate tombstone selection index".into(),
                ));
            }
        }

        Ok(())
    }

    /// Only a public-visibility policy's exemplars are ever returned here. A
    /// private-only exemplar set can never appear through this accessor,
    /// regardless of what the underlying `exemplars` field happens to hold
    /// (PUBLIC-04, EVID-05).
    ///
    /// Publication is impossible without validation: this always runs
    /// [`Self::validate_shape`] first (which re-derives `policy_digest` from
    /// `policy` and enforces the zero cap for an unactivated public policy)
    /// and returns nothing at all if it fails. A record with a tampered
    /// `visibility` field -- decoded straight from a store without being
    /// validated first -- cannot reach the `Public` branch below with a
    /// mismatched `policy_digest`, and an unactivated public policy caps
    /// `exemplars` at zero regardless of what `visibility` claims.
    pub fn public_exemplars(&self) -> ContractResult<&[ExemplarV1]> {
        self.validate_shape()?;
        if matches!(self.policy.visibility, ExemplarVisibilityV1::Public) {
            Ok(&self.exemplars)
        } else {
            Ok(&[])
        }
    }

    /// Replace one currently present exemplar with an immutable tombstone.
    /// The selected count, strata, and every other receipt field are
    /// unchanged; only that one exemplar's payload is gone (EVID-08, EVID-09).
    ///
    /// `index` addresses `self.exemplars` (the current, already-shrunk
    /// list), exactly as before. Erasure is total even for content-identical
    /// exemplars: the new tombstone's `selection_index` names this record's
    /// stable position in the *original* selection order, computed by
    /// [`Self::selection_index_for_present_exemplar`], so erasing one of
    /// several duplicate-content exemplars never collides with the others
    /// still being present.
    pub fn erase_exemplar_at(
        &self,
        index: usize,
        erased_at: CanonicalTimestamp,
        erasure_policy: RegistryReferenceV1,
    ) -> ContractResult<Self> {
        self.validate_shape()?;
        let exemplar = self
            .exemplars
            .get(index)
            .ok_or_else(|| ContractError::Schema("erasure index out of range".into()))?;
        let selection_index = self.selection_index_for_present_exemplar(index)?;
        let tombstone = ErasedExemplarTombstoneV1 {
            schema_version: TELEMETRY_SCHEMA_VERSION,
            selection_index,
            erased_exemplar_digest: exemplar.exemplar_digest()?,
            erased_at,
            erasure_policy,
        };
        let mut next = self.clone();
        next.exemplars.remove(index);
        next.tombstones.push(tombstone);
        next.tombstones
            .sort_by(|left, right| left.selection_index.cmp(&right.selection_index));
        next.validate_shape()?;
        Ok(next)
    }

    /// Map a position in the current `self.exemplars` list back to its
    /// stable 0-based position in the original round-robin selection order
    /// (out of `self.selected_count` slots). `self.exemplars` always keeps
    /// the relative order the selector produced (erasure only ever removes
    /// entries, never reorders survivors), so the mapping is: walk every
    /// original slot in order, skip the slots already named by an existing
    /// tombstone, and the `local_index`-th slot that is not skipped is the
    /// original position of `self.exemplars[local_index]`.
    fn selection_index_for_present_exemplar(&self, local_index: usize) -> ContractResult<u32> {
        let tombstoned: BTreeSet<u32> = self.tombstones.iter().map(|t| t.selection_index).collect();
        let mut remaining = local_index;
        for original in 0..self.selected_count {
            if tombstoned.contains(&original) {
                continue;
            }
            if remaining == 0 {
                return Ok(original);
            }
            remaining -= 1;
        }
        Err(ContractError::Schema("erasure index out of range".into()))
    }
}

impl PartialOrd for ErasedExemplarTombstoneV1 {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Canonical order is by `selection_index`, not by content digest: two
/// content-identical erased exemplars must still sort deterministically
/// against each other, and `selection_index` (unlike the digest) is unique
/// per tombstone by construction.
impl Ord for ErasedExemplarTombstoneV1 {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.selection_index.cmp(&other.selection_index)
    }
}

/// Deterministic per-record ordering key:
/// `SHA-256(policy_digest || measurement_source_fact_id || provider_record_id)`.
///
/// Domain-separated under [`DigestDomain::ExemplarSelectionV1`]. No rotating
/// secret or process-local seed is ever mixed in, so the same inputs always
/// produce the same order.
pub fn exemplar_ordering_key(
    policy_digest: Sha256Digest,
    measurement_source_fact_id: Sha256Digest,
    provider_record_id: &HexBytes,
) -> Sha256Digest {
    framed_digest(
        DigestDomain::ExemplarSelectionV1,
        &[
            policy_digest.as_bytes(),
            measurement_source_fact_id.as_bytes(),
            provider_record_id.as_bytes(),
        ],
    )
}

/// The default selector.
///
/// Given the exact provider snapshot/query population, with
/// authorization/visibility and redaction/classification already applied by
/// the caller, this sorts canonical normalized stratum keys, then orders
/// each stratum's eligible records by [`exemplar_ordering_key`], then
/// selects round-robin across strata in canonical order until the policy's
/// cap. Candidate order is irrelevant: strata are grouped by exact byte
/// value and each stratum is re-sorted by the deterministic ordering key
/// before any selection happens.
///
/// Refuses to run under a `biased_extrema` policy: that describes a
/// different, unimplemented selector family, and running the unbiased
/// algorithm under a policy labelled biased would misrepresent what was
/// actually sampled.
pub fn select_exemplars_deterministic_stratified_hash_v1(
    policy: &ExemplarPolicyV1,
    input: &PopulationInputV1<'_>,
) -> ContractResult<ExemplarSelectionReceiptV1> {
    policy.validate()?;
    if policy.biased_extrema {
        return Err(ContractError::Schema(
            "deterministic_stratified_hash_v1 cannot run under a biased-extrema policy".into(),
        ));
    }
    let policy_digest = exemplar_policy_digest(policy)?;
    let caps = policy.effective_caps();

    let (population, candidates): (PopulationBoundaryV1, &[SelectionCandidateV1]) = match input {
        PopulationInputV1::Unbound(reason) => {
            (PopulationBoundaryV1::Unbound { reason: *reason }, &[])
        }
        PopulationInputV1::Bound {
            snapshot_digest,
            query_population_digest,
            candidates,
        } => (
            PopulationBoundaryV1::Bound {
                snapshot_digest: *snapshot_digest,
                query_population_digest: *query_population_digest,
            },
            candidates,
        ),
    };

    if matches!(population, PopulationBoundaryV1::Unbound { .. }) {
        let receipt = ExemplarSelectionReceiptV1 {
            schema_version: TELEMETRY_SCHEMA_VERSION,
            policy: policy.clone(),
            policy_digest,
            population,
            strata: Vec::new(),
            candidate_count: 0,
            eligible_count: 0,
            withheld_count: 0,
            selected_count: 0,
            omitted_count: 0,
            truncated: false,
            exemplars: Vec::new(),
            tombstones: Vec::new(),
        };
        receipt.validate_shape()?;
        return Ok(receipt);
    }

    let candidate_count = u32::try_from(candidates.len())
        .map_err(|_| ContractError::Schema("candidate population exceeds u32".into()))?;

    let (withheld_count, strata) = classify_and_bucket_candidates(candidates, policy_digest)?;
    let eligible_count = candidate_count
        .checked_sub(withheld_count)
        .ok_or_else(|| ContractError::Schema("withheld count exceeds candidate count".into()))?;

    let (selected, strata_summary) = round_robin_select(&strata, caps.max_count)?;
    let selected_count = u32::try_from(selected.len())
        .map_err(|_| ContractError::Schema("selected count exceeds u32".into()))?;
    let omitted_count = eligible_count
        .checked_sub(selected_count)
        .ok_or_else(|| ContractError::Schema("selected count exceeds eligible count".into()))?;

    let receipt = ExemplarSelectionReceiptV1 {
        schema_version: TELEMETRY_SCHEMA_VERSION,
        policy: policy.clone(),
        policy_digest,
        population,
        strata: strata_summary,
        candidate_count,
        eligible_count,
        withheld_count,
        selected_count,
        omitted_count,
        truncated: omitted_count > 0,
        exemplars: selected,
        tombstones: Vec::new(),
    };
    receipt.validate_shape()?;
    Ok(receipt)
}

/// One canonical-stratum bucket: eligible `(ordering_key, provider_record_id,
/// exemplar)` triples, already sorted by [`exemplar_ordering_key`].
type StratumBucket = Vec<(Sha256Digest, HexBytes, ExemplarV1)>;

/// Classify every candidate (`Withheld` vs. `Eligible`), validate each
/// eligible exemplar, and group eligible records into canonical-stratum
/// buckets, each already sorted by [`exemplar_ordering_key`]. Also enforces
/// that every provider-record identity in the population is unique.
fn classify_and_bucket_candidates(
    candidates: &[SelectionCandidateV1],
    policy_digest: Sha256Digest,
) -> ContractResult<(u32, BTreeMap<Vec<u8>, StratumBucket>)> {
    let mut seen_ids: BTreeSet<Vec<u8>> = BTreeSet::new();
    for candidate in candidates {
        if !seen_ids.insert(candidate.provider_record_id.as_bytes().to_vec()) {
            return Err(ContractError::Schema(
                "duplicate provider-record identity in selection population".into(),
            ));
        }
    }

    let mut withheld_count: u32 = 0;
    let mut strata: BTreeMap<Vec<u8>, StratumBucket> = BTreeMap::new();
    for candidate in candidates {
        match &candidate.outcome {
            CandidateOutcomeV1::Withheld => {
                withheld_count = withheld_count
                    .checked_add(1)
                    .ok_or_else(|| ContractError::Schema("withheld count overflows".into()))?;
            }
            CandidateOutcomeV1::Eligible(exemplar) => {
                exemplar.validate()?;
                let ordering_key = exemplar_ordering_key(
                    policy_digest,
                    candidate.measurement_source_fact_id,
                    &candidate.provider_record_id,
                );
                strata
                    .entry(candidate.stratum_key.as_bytes().to_vec())
                    .or_default()
                    .push((
                        ordering_key,
                        candidate.provider_record_id.clone(),
                        exemplar.as_ref().clone(),
                    ));
            }
        }
    }

    for bucket in strata.values_mut() {
        bucket.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    }
    Ok((withheld_count, strata))
}

/// Round-robin across strata in canonical (sorted-key) order until `cap`,
/// returning the selected exemplars in selection order plus a per-stratum
/// eligible/selected summary in the same canonical order.
fn round_robin_select(
    strata: &BTreeMap<Vec<u8>, StratumBucket>,
    cap: usize,
) -> ContractResult<(Vec<ExemplarV1>, Vec<StratumSelectionV1>)> {
    let stratum_keys: Vec<&Vec<u8>> = strata.keys().collect();
    let mut cursors = vec![0usize; stratum_keys.len()];
    let mut selected_counts = vec![0u32; stratum_keys.len()];
    let mut selected: Vec<ExemplarV1> = Vec::new();

    'rounds: loop {
        if selected.len() >= cap {
            break;
        }
        let mut advanced = false;
        for (index, key) in stratum_keys.iter().enumerate() {
            if selected.len() >= cap {
                break 'rounds;
            }
            let bucket = &strata[*key];
            if let Some((_, _, exemplar)) = bucket.get(cursors[index]) {
                selected.push(exemplar.clone());
                selected_counts[index] =
                    selected_counts[index].checked_add(1).ok_or_else(|| {
                        ContractError::Schema("stratum selected count overflows".into())
                    })?;
                cursors[index] += 1;
                advanced = true;
            }
        }
        if !advanced {
            break;
        }
    }

    let mut strata_summary = Vec::with_capacity(stratum_keys.len());
    for (index, key) in stratum_keys.iter().enumerate() {
        strata_summary.push(StratumSelectionV1 {
            stratum_key: ExemplarTextV1::from_utf8_bytes(key)?,
            eligible_count: u32::try_from(strata[*key].len())
                .map_err(|_| ContractError::Schema("stratum size exceeds u32".into()))?,
            selected_count: selected_counts[index],
        });
    }
    Ok((selected, strata_summary))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory_contracts::{
        canonical::{decode_strict, require_canonical},
        common::frozen_profile_reference_v1,
        identity::IdentityForm,
    };
    use sha2::{Digest as _, Sha256};

    const EXPECTED_PRIVATE_RECEIPT_RAW_SHA256: &str =
        "a7ad8669ed13129c9ea20edeb1ef7366b1cf7c98a67135c10f73e9a4a215a17d";
    const EXPECTED_UNAVAILABLE_RECEIPT_RAW_SHA256: &str =
        "8b85689c0ea4c22fb2f46256a1836d7dc0bdfc1352507c51a4c3a42840f3dd46";
    const EXPECTED_SLO_COMPLIANT_RAW_SHA256: &str =
        "a14b0aab4a6c23acecbc12a4d9da2fffb9c7a0500a5f6fd07bc3581a0947d3a8";
    const EXPECTED_SLO_NONCONFORMANT_RAW_SHA256: &str =
        "143c004b864f051752f681a45185d09cbea157876f364f7dee1f375093552245";
    const EXPECTED_POLICY_PRIVATE_RAW_SHA256: &str =
        "0e0b2c9844695ba6ad9beb4c745fb89d613fcf5205e7cb853634833fe735b3c9";
    const EXPECTED_POLICY_PUBLIC_ACTIVATED_RAW_SHA256: &str =
        "cfff1bce1aff5dd865538a66e19f89165fe46fd104233a366cd3d397fd82f32a";
    const EXPECTED_EXEMPLAR_RAW_SHA256: &str =
        "0e7a6b613281957e7b2be5f46e759368f376d39f88b3d6f35a89b3c2bc8aa406";
    const EXPECTED_SELECTION_ERASED_RAW_SHA256: &str =
        "52268bfdcbb1f2e77f69239ceb3198006aa70efe486dc86540dcc26ffd9227c7";
    const EXPECTED_SELECTION_CAP_TRUNCATED_RAW_SHA256: &str =
        "514d02715f0e688d12dcb48de8188248fa070e0a0152fd0aa152df21a66532bc";
    const EXPECTED_NEGATIVE_FLOAT_RAW_SHA256: &str =
        "deb7bbba3996c8a8e2169a895ce948ffd4e8af742847d24df88b74e1bee4e66f";
    const EXPECTED_NEGATIVE_CAP_EXCEEDED_RAW_SHA256: &str =
        "7a27836cf61199174ec342777b1470c1c88939cdde79a2dfcf04f0e334722e3e";
    const EXPECTED_NEGATIVE_SECRET_FIELD_RAW_SHA256: &str =
        "9377fe56379612bc143d917d407a832e21b4d9c9563fad49d986aae856b2bdc0";
    const EXPECTED_NEGATIVE_RAW_LOG_LINE_RAW_SHA256: &str =
        "0253f931594d74fb17a6285e42fb8ae92caad2f09c6b18a10867f40dd135e22f";
    const EXPECTED_NEGATIVE_SELECTED_COUNT_EXCEEDS_CAP_RAW_SHA256: &str =
        "234ae09541413f2c7cc8da81bd4d17d32f55ce4b5e49e77e7f786f4f6d71a2da";
    const EXPECTED_NEGATIVE_TOMBSTONE_INVALID_SCHEMA_VERSION_RAW_SHA256: &str =
        "804adcdaff390a07da0e50bdd2ded6a4540abea9830bcc281c9207d081a30577";
    const EXPECTED_NEGATIVE_TOMBSTONE_INVALID_ERASURE_POLICY_RAW_SHA256: &str =
        "59b0465eff2baf9d4caf0a221d79a103c4dc31047c22cbaba94f703d3ea8ee8d";
    const EXPECTED_VECTOR_SUITE_RAW_SHA256: &str =
        "c2c0769b67994f77ebedb2f5c6eaf80e31891cc181f30fb1ab9a71f6b966e897";

    // Semantic identities, recomputed from the decoded fixtures below and
    // asserted against these hard-coded constants -- not merely
    // self-equality. The raw-SHA pins above only prove the checked-in bytes
    // have not changed; they do NOT prove that `receipt_id()`,
    // `evaluation_id()`, `exemplar_digest()`, or `exemplar_policy_digest()`
    // still compute the same value from those bytes. Changing any of the
    // three `DigestDomain` prefixes this workstream owns
    // (`ostk-measurement-receipt-v1`, `ostk-slo-evaluation-v1`,
    // `ostk-exemplar-selection-v1`), or the canonical encoding those
    // functions hash, would silently change every id below while every
    // fixture file, and the raw-SHA loop above, stayed green.
    const EXPECTED_PRIVATE_RECEIPT_ID: &str =
        "795340f7ef91d68f40c472b74b49bc45edc6a291df0b4b085861ab60e95aca6f";
    const EXPECTED_UNAVAILABLE_RECEIPT_ID: &str =
        "2b7badbe900d070622e42020026a38643a2b865b62a814467476346322cd3e64";
    const EXPECTED_SLO_COMPLIANT_EVALUATION_ID: &str =
        "5e7e4a5f6c630017c05a6191989b7717efac72839a9d8cdcef0ebe3ce6e1a878";
    const EXPECTED_SLO_NONCONFORMANT_EVALUATION_ID: &str =
        "6a1b7a6ef2d04b477470de293c265fe44937be650fd9eb84476a6b43afaeff64";
    const EXPECTED_POLICY_PRIVATE_DIGEST: &str =
        "fc8924afba85139d8b93b485d3a11dc39f5b2925f422e3aa3e0de4a0b42e541a";
    const EXPECTED_POLICY_PUBLIC_ACTIVATED_DIGEST: &str =
        "2e3c4248e4e39c3590a73ecd467918a48b400c2822b0adb7e47e492e8212cb55";
    const EXPECTED_EXEMPLAR_DIGEST: &str =
        "8cdd33bb5ecd5ae33f62f967c6bba9d37768ae07e719c0ef79e6b7e5a60ce723";
    const EXPECTED_NEGATIVE_COMPLIANT_PARTIAL_COVERAGE_RAW_SHA256: &str =
        "ae29b4f136b07993e899252366558368993b9a9d303d8b355b378969b9c50fcf";

    fn raw_sha256(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    /// Strip the exact single trailing LF and require the remainder to
    /// already be canonical-JSON bytes.
    fn fixture_record(framed: &'static [u8]) -> &'static [u8] {
        let record = framed
            .strip_suffix(b"\n")
            .expect("fixture must end in exactly one LF");
        assert!(!record.ends_with(b"\n"));
        require_canonical(record).unwrap();
        record
    }

    #[test]
    // One long, flat, linear pinning test over every checked-in fixture is
    // clearer than splitting it across helpers that would each need the same
    // `include_bytes!` plumbing.
    #[allow(clippy::too_many_lines)]
    fn authoritative_fixture_corpus_is_frozen() {
        let private_receipt_framed = include_bytes!(
            "../../contracts/dynamic-memory/v3/telemetry/measurement-receipt-v1-private-with-exemplars.jsonl"
        );
        let unavailable_receipt_framed = include_bytes!(
            "../../contracts/dynamic-memory/v3/telemetry/measurement-receipt-v1-population-unavailable.jsonl"
        );
        let slo_compliant_framed = include_bytes!(
            "../../contracts/dynamic-memory/v3/telemetry/slo-evaluation-v1-compliant.jsonl"
        );
        let slo_nonconformant_framed = include_bytes!(
            "../../contracts/dynamic-memory/v3/telemetry/slo-evaluation-v1-nonconformant.jsonl"
        );
        let policy_private_framed = include_bytes!(
            "../../contracts/dynamic-memory/v3/telemetry/exemplar-policy-v1-private.jsonl"
        );
        let policy_public_activated_framed = include_bytes!(
            "../../contracts/dynamic-memory/v3/telemetry/exemplar-policy-v1-public-activated.jsonl"
        );
        let exemplar_framed =
            include_bytes!("../../contracts/dynamic-memory/v3/telemetry/exemplar-v1.jsonl");
        let selection_erased_framed = include_bytes!(
            "../../contracts/dynamic-memory/v3/telemetry/exemplar-selection-receipt-v1-erased.jsonl"
        );
        let selection_cap_truncated_framed = include_bytes!(
            "../../contracts/dynamic-memory/v3/telemetry/exemplar-selection-receipt-v1-cap-truncated.jsonl"
        );
        let negative_float_framed = include_bytes!(
            "../../contracts/dynamic-memory/v3/telemetry/negative-float-result.jsonl"
        );
        let negative_cap_exceeded_framed = include_bytes!(
            "../../contracts/dynamic-memory/v3/telemetry/negative-cap-exceeded-exemplar.jsonl"
        );
        let negative_secret_field_framed = include_bytes!(
            "../../contracts/dynamic-memory/v3/telemetry/negative-secret-shaped-field.jsonl"
        );
        let negative_raw_log_line_framed = include_bytes!(
            "../../contracts/dynamic-memory/v3/telemetry/negative-raw-log-line-field.jsonl"
        );
        let negative_compliant_partial_coverage_framed = include_bytes!(
            "../../contracts/dynamic-memory/v3/telemetry/negative-compliant-partial-coverage.jsonl"
        );
        let negative_selected_count_exceeds_cap_framed = include_bytes!(
            "../../contracts/dynamic-memory/v3/telemetry/negative-selected-count-exceeds-cap.jsonl"
        );
        let negative_tombstone_invalid_schema_version_framed = include_bytes!(
            "../../contracts/dynamic-memory/v3/telemetry/negative-tombstone-invalid-schema-version.jsonl"
        );
        let negative_tombstone_invalid_erasure_policy_framed = include_bytes!(
            "../../contracts/dynamic-memory/v3/telemetry/negative-tombstone-invalid-erasure-policy.jsonl"
        );
        let vector_suite_framed =
            include_bytes!("../../contracts/dynamic-memory/v3/telemetry/vector-suite.jsonl");

        for (framed, expected) in [
            (
                private_receipt_framed.as_slice(),
                EXPECTED_PRIVATE_RECEIPT_RAW_SHA256,
            ),
            (
                unavailable_receipt_framed.as_slice(),
                EXPECTED_UNAVAILABLE_RECEIPT_RAW_SHA256,
            ),
            (
                slo_compliant_framed.as_slice(),
                EXPECTED_SLO_COMPLIANT_RAW_SHA256,
            ),
            (
                slo_nonconformant_framed.as_slice(),
                EXPECTED_SLO_NONCONFORMANT_RAW_SHA256,
            ),
            (
                policy_private_framed.as_slice(),
                EXPECTED_POLICY_PRIVATE_RAW_SHA256,
            ),
            (
                policy_public_activated_framed.as_slice(),
                EXPECTED_POLICY_PUBLIC_ACTIVATED_RAW_SHA256,
            ),
            (exemplar_framed.as_slice(), EXPECTED_EXEMPLAR_RAW_SHA256),
            (
                selection_erased_framed.as_slice(),
                EXPECTED_SELECTION_ERASED_RAW_SHA256,
            ),
            (
                selection_cap_truncated_framed.as_slice(),
                EXPECTED_SELECTION_CAP_TRUNCATED_RAW_SHA256,
            ),
            (
                negative_float_framed.as_slice(),
                EXPECTED_NEGATIVE_FLOAT_RAW_SHA256,
            ),
            (
                negative_cap_exceeded_framed.as_slice(),
                EXPECTED_NEGATIVE_CAP_EXCEEDED_RAW_SHA256,
            ),
            (
                negative_secret_field_framed.as_slice(),
                EXPECTED_NEGATIVE_SECRET_FIELD_RAW_SHA256,
            ),
            (
                negative_raw_log_line_framed.as_slice(),
                EXPECTED_NEGATIVE_RAW_LOG_LINE_RAW_SHA256,
            ),
            (
                negative_compliant_partial_coverage_framed.as_slice(),
                EXPECTED_NEGATIVE_COMPLIANT_PARTIAL_COVERAGE_RAW_SHA256,
            ),
            (
                negative_selected_count_exceeds_cap_framed.as_slice(),
                EXPECTED_NEGATIVE_SELECTED_COUNT_EXCEEDS_CAP_RAW_SHA256,
            ),
            (
                negative_tombstone_invalid_schema_version_framed.as_slice(),
                EXPECTED_NEGATIVE_TOMBSTONE_INVALID_SCHEMA_VERSION_RAW_SHA256,
            ),
            (
                negative_tombstone_invalid_erasure_policy_framed.as_slice(),
                EXPECTED_NEGATIVE_TOMBSTONE_INVALID_ERASURE_POLICY_RAW_SHA256,
            ),
            (
                vector_suite_framed.as_slice(),
                EXPECTED_VECTOR_SUITE_RAW_SHA256,
            ),
        ] {
            assert_eq!(raw_sha256(framed), expected);
        }

        // Positive fixtures decode into their exact typed contracts, and
        // re-encoding produces byte-identical output (the fixture is the
        // canonical form, not merely "a" valid encoding of it).
        let private_receipt_bytes = fixture_record(private_receipt_framed);
        let private_receipt: MeasurementReceiptV1 = decode_strict(private_receipt_bytes).unwrap();
        private_receipt.validate_shape().unwrap();
        assert_eq!(
            encode_canonical(&private_receipt).unwrap(),
            private_receipt_bytes
        );
        assert_eq!(private_receipt.exemplars.selected_count, 4);
        assert_eq!(private_receipt.exemplars.withheld_count, 1);
        assert_eq!(private_receipt.exemplars.exemplars.len(), 4);
        assert_eq!(
            private_receipt.receipt_id().unwrap().to_string(),
            EXPECTED_PRIVATE_RECEIPT_ID
        );
        // Blocker fix (ordering-rule pinning): re-run the selector over the
        // exact (uncapped) population `write_fixture_corpus` generated this
        // fixture from and require byte-for-byte equality of the embedded
        // selection receipt with the frozen record. Neither the raw fixture
        // SHA-256 above, nor the per-stratum count/permutation-equality
        // checks in `selection_is_deterministic_and_input_order_is_irrelevant`,
        // detect an inverted ordering-key comparator; recomputing and
        // comparing canonical bytes against this exact population does.
        let private_with_exemplars_candidates = two_stratum_candidates();
        let private_with_exemplars_population = PopulationInputV1::Bound {
            snapshot_digest: Sha256Digest::from_bytes([200; 32]),
            query_population_digest: Sha256Digest::from_bytes([201; 32]),
            candidates: &private_with_exemplars_candidates,
        };
        let recomputed_private_selection = select_exemplars_deterministic_stratified_hash_v1(
            &private_policy(),
            &private_with_exemplars_population,
        )
        .unwrap();
        assert_eq!(
            encode_canonical(&recomputed_private_selection).unwrap(),
            encode_canonical(&private_receipt.exemplars).unwrap(),
            "recomputed selection must byte-match the frozen private-with-exemplars fixture"
        );

        let unavailable_receipt_bytes = fixture_record(unavailable_receipt_framed);
        let unavailable_receipt: MeasurementReceiptV1 =
            decode_strict(unavailable_receipt_bytes).unwrap();
        unavailable_receipt.validate_shape().unwrap();
        assert_eq!(
            encode_canonical(&unavailable_receipt).unwrap(),
            unavailable_receipt_bytes
        );
        assert!(matches!(
            unavailable_receipt.exemplars.population,
            PopulationBoundaryV1::Unbound {
                reason: PopulationUnboundReasonV1::SnapshotUnavailable
            }
        ));
        assert_eq!(unavailable_receipt.exemplars.selected_count, 0);
        assert_eq!(
            unavailable_receipt.receipt_id().unwrap().to_string(),
            EXPECTED_UNAVAILABLE_RECEIPT_ID
        );

        let slo_compliant_bytes = fixture_record(slo_compliant_framed);
        let slo_compliant: SloEvaluationV1 = decode_strict(slo_compliant_bytes).unwrap();
        slo_compliant.validate_shape().unwrap();
        assert_eq!(slo_compliant.outcome, SloOutcomeV1::Compliant);
        assert_eq!(
            encode_canonical(&slo_compliant).unwrap(),
            slo_compliant_bytes
        );
        assert_eq!(
            slo_compliant.evaluation_id().unwrap().to_string(),
            EXPECTED_SLO_COMPLIANT_EVALUATION_ID
        );

        let slo_nonconformant_bytes = fixture_record(slo_nonconformant_framed);
        let slo_nonconformant: SloEvaluationV1 = decode_strict(slo_nonconformant_bytes).unwrap();
        slo_nonconformant.validate_shape().unwrap();
        assert_eq!(slo_nonconformant.outcome, SloOutcomeV1::Nonconformant);
        assert_eq!(
            slo_nonconformant.coverage_result,
            CoverageCompletenessV1::Complete
        );
        assert_eq!(
            encode_canonical(&slo_nonconformant).unwrap(),
            slo_nonconformant_bytes
        );
        assert_eq!(
            slo_nonconformant.evaluation_id().unwrap().to_string(),
            EXPECTED_SLO_NONCONFORMANT_EVALUATION_ID
        );

        let policy_private_bytes = fixture_record(policy_private_framed);
        let policy_private: ExemplarPolicyV1 = decode_strict(policy_private_bytes).unwrap();
        policy_private.validate().unwrap();
        assert_eq!(policy_private.effective_caps().max_count, 8);
        assert_eq!(
            encode_canonical(&policy_private).unwrap(),
            policy_private_bytes
        );
        assert_eq!(
            exemplar_policy_digest(&policy_private).unwrap().to_string(),
            EXPECTED_POLICY_PRIVATE_DIGEST
        );

        let policy_public_activated_bytes = fixture_record(policy_public_activated_framed);
        let policy_public_activated: ExemplarPolicyV1 =
            decode_strict(policy_public_activated_bytes).unwrap();
        policy_public_activated.validate().unwrap();
        assert_eq!(policy_public_activated.effective_caps().max_count, 3);
        assert_eq!(
            encode_canonical(&policy_public_activated).unwrap(),
            policy_public_activated_bytes
        );
        assert_eq!(
            exemplar_policy_digest(&policy_public_activated)
                .unwrap()
                .to_string(),
            EXPECTED_POLICY_PUBLIC_ACTIVATED_DIGEST
        );

        let exemplar_bytes = fixture_record(exemplar_framed);
        let exemplar_value: ExemplarV1 = decode_strict(exemplar_bytes).unwrap();
        exemplar_value.validate().unwrap();
        assert_eq!(encode_canonical(&exemplar_value).unwrap(), exemplar_bytes);
        assert_eq!(
            exemplar_value.exemplar_digest().unwrap().to_string(),
            EXPECTED_EXEMPLAR_DIGEST
        );

        let selection_erased_bytes = fixture_record(selection_erased_framed);
        let selection_erased: ExemplarSelectionReceiptV1 =
            decode_strict(selection_erased_bytes).unwrap();
        selection_erased.validate_shape().unwrap();
        assert_eq!(selection_erased.selected_count, 4);
        assert_eq!(selection_erased.exemplars.len(), 3);
        assert_eq!(selection_erased.tombstones.len(), 1);
        assert_eq!(
            encode_canonical(&selection_erased).unwrap(),
            selection_erased_bytes
        );

        let selection_cap_truncated_bytes = fixture_record(selection_cap_truncated_framed);
        let selection_cap_truncated: ExemplarSelectionReceiptV1 =
            decode_strict(selection_cap_truncated_bytes).unwrap();
        selection_cap_truncated.validate_shape().unwrap();
        assert_eq!(selection_cap_truncated.candidate_count, 9);
        assert_eq!(selection_cap_truncated.selected_count, 8);
        assert_eq!(selection_cap_truncated.omitted_count, 1);
        assert!(selection_cap_truncated.truncated);
        assert_eq!(
            encode_canonical(&selection_cap_truncated).unwrap(),
            selection_cap_truncated_bytes
        );
        // Blocker fix (ordering-rule pinning): re-run the selector over the
        // exact population this fixture was generated from and require
        // byte-for-byte equality with the frozen record. Asserting only
        // counts (above) or permutation-equality survives an inverted
        // ordering key or comparator; recomputing and comparing canonical
        // bytes does not.
        let cap_truncated_candidates = cap_truncating_candidates();
        let cap_truncated_population = PopulationInputV1::Bound {
            snapshot_digest: Sha256Digest::from_bytes([210; 32]),
            query_population_digest: Sha256Digest::from_bytes([211; 32]),
            candidates: &cap_truncated_candidates,
        };
        let recomputed_cap_truncated = select_exemplars_deterministic_stratified_hash_v1(
            &private_policy(),
            &cap_truncated_population,
        )
        .unwrap();
        assert_eq!(
            encode_canonical(&recomputed_cap_truncated).unwrap(),
            selection_cap_truncated_bytes,
            "recomputed cap-truncating selection must byte-match the frozen fixture"
        );

        // Negative fixtures are syntactically framed the same way but each
        // fails either canonical-JSON decoding or typed shape validation.
        // `negative-float-result.jsonl` is deliberately NOT canonical (it
        // carries a raw JSON float), so it is stripped of its trailing LF
        // without also requiring canonical form, unlike every other fixture.
        let negative_float_bytes = negative_float_framed
            .strip_suffix(b"\n")
            .expect("fixture must end in exactly one LF");
        assert!(require_canonical(negative_float_bytes).is_err());
        assert!(decode_strict::<MeasurementReceiptV1>(negative_float_bytes).is_err());

        let negative_cap_exceeded_bytes = fixture_record(negative_cap_exceeded_framed);
        let negative_cap_exceeded: ExemplarSelectionReceiptV1 =
            decode_strict(negative_cap_exceeded_bytes).unwrap();
        assert!(negative_cap_exceeded.validate_shape().is_err());

        // Both fixtures splice a deny-listed key into an otherwise-valid
        // exemplar and are re-canonicalized before being written to disk, so
        // `ExemplarV1::deny_unknown_fields` is the only reason decoding
        // fails — not incidental key disorder.
        let negative_secret_field_bytes = fixture_record(negative_secret_field_framed);
        assert!(decode_strict::<ExemplarV1>(negative_secret_field_bytes).is_err());

        let negative_raw_log_line_bytes = fixture_record(negative_raw_log_line_framed);
        assert!(decode_strict::<ExemplarV1>(negative_raw_log_line_bytes).is_err());

        // RUN-01 fail-open guard: `compliant` + `partial` coverage decodes
        // structurally (nothing about the JSON shape is malformed) but
        // `validate_shape` must refuse it, exactly as it already refuses
        // `nonconformant` + `partial`.
        let negative_compliant_partial_coverage_bytes =
            fixture_record(negative_compliant_partial_coverage_framed);
        let negative_compliant_partial_coverage: SloEvaluationV1 =
            decode_strict(negative_compliant_partial_coverage_bytes).unwrap();
        assert_eq!(
            negative_compliant_partial_coverage.outcome,
            SloOutcomeV1::Compliant
        );
        assert!(
            negative_compliant_partial_coverage
                .validate_shape()
                .is_err()
        );

        // Blocker fix (cap-bypass guard): `selected_count = 9` under the
        // private policy's cap of 8, with 1 present exemplar plus 8
        // fabricated tombstones making every other count arithmetically
        // self-consistent. Only the explicit `selected_count > caps.max_count`
        // check in `validate_caps_and_tombstones` rejects it.
        let negative_selected_count_exceeds_cap_bytes =
            fixture_record(negative_selected_count_exceeds_cap_framed);
        let negative_selected_count_exceeds_cap: ExemplarSelectionReceiptV1 =
            decode_strict(negative_selected_count_exceeds_cap_bytes).unwrap();
        assert_eq!(negative_selected_count_exceeds_cap.selected_count, 9);
        assert_eq!(negative_selected_count_exceeds_cap.exemplars.len(), 1);
        assert_eq!(negative_selected_count_exceeds_cap.tombstones.len(), 8);
        assert!(
            negative_selected_count_exceeds_cap
                .validate_shape()
                .is_err()
        );

        // Blocker fix (tombstone-shape guard): the erased fixture with its
        // one tombstone's `schema_version` bumped to an unknown value.
        // Decodes structurally; `validate_shape` must reject it rather than
        // trust a tombstone this module could never have produced.
        let negative_tombstone_invalid_schema_version_bytes =
            fixture_record(negative_tombstone_invalid_schema_version_framed);
        let negative_tombstone_invalid_schema_version: ExemplarSelectionReceiptV1 =
            decode_strict(negative_tombstone_invalid_schema_version_bytes).unwrap();
        assert_eq!(
            negative_tombstone_invalid_schema_version.tombstones[0].schema_version,
            9999
        );
        assert!(
            negative_tombstone_invalid_schema_version
                .validate_shape()
                .is_err()
        );

        // Blocker fix (tombstone-shape guard): the erased fixture with its
        // tombstone's `erasure_policy.version` rewritten to 0.
        // `RegistryReferenceV1::validate` rejects a zero version; this pins
        // that every tombstone's `erasure_policy` is actually validated.
        let negative_tombstone_invalid_erasure_policy_bytes =
            fixture_record(negative_tombstone_invalid_erasure_policy_framed);
        let negative_tombstone_invalid_erasure_policy: ExemplarSelectionReceiptV1 =
            decode_strict(negative_tombstone_invalid_erasure_policy_bytes).unwrap();
        assert_eq!(
            negative_tombstone_invalid_erasure_policy.tombstones[0]
                .erasure_policy
                .version,
            0
        );
        assert!(
            negative_tombstone_invalid_erasure_policy
                .validate_shape()
                .is_err()
        );
    }

    /// Non-blocking observation fix: `vector-suite.jsonl` was previously
    /// pinned only by its raw SHA-256 above, never parsed, so its embedded
    /// `receipt_id`/`evaluation_id`/`*_digest` fields could silently drift
    /// from the values the code actually computes while every gate stayed
    /// green (the Rust `EXPECTED_*` constants happened to carry the same
    /// values independently, not because anything compared them). This test
    /// closes that gap: it parses the manifest as JSON and asserts every
    /// semantic id it restates equals the same `EXPECTED_*` constant the
    /// fixture corpus test above already pins from the decoded records.
    #[test]
    fn vector_suite_restates_only_the_pinned_semantic_ids_and_all_match() {
        let vector_suite_framed =
            include_bytes!("../../contracts/dynamic-memory/v3/telemetry/vector-suite.jsonl");
        let value: serde_json::Value = serde_json::from_slice(vector_suite_framed).unwrap();
        let artifacts = value["artifacts"].as_object().unwrap();
        let field = |file: &str, key: &str| {
            artifacts[file][key]
                .as_str()
                .unwrap_or_else(|| panic!("{file}.{key} missing from vector-suite.jsonl"))
                .to_string()
        };

        assert_eq!(
            field("exemplar-policy-v1-private.jsonl", "policy_digest"),
            EXPECTED_POLICY_PRIVATE_DIGEST
        );
        assert_eq!(
            field("exemplar-policy-v1-public-activated.jsonl", "policy_digest"),
            EXPECTED_POLICY_PUBLIC_ACTIVATED_DIGEST
        );
        assert_eq!(
            field("exemplar-v1.jsonl", "exemplar_digest"),
            EXPECTED_EXEMPLAR_DIGEST
        );
        assert_eq!(
            field(
                "measurement-receipt-v1-population-unavailable.jsonl",
                "receipt_id"
            ),
            EXPECTED_UNAVAILABLE_RECEIPT_ID
        );
        assert_eq!(
            field(
                "measurement-receipt-v1-private-with-exemplars.jsonl",
                "receipt_id"
            ),
            EXPECTED_PRIVATE_RECEIPT_ID
        );
        assert_eq!(
            field("slo-evaluation-v1-compliant.jsonl", "evaluation_id"),
            EXPECTED_SLO_COMPLIANT_EVALUATION_ID
        );
        assert_eq!(
            field("slo-evaluation-v1-nonconformant.jsonl", "evaluation_id"),
            EXPECTED_SLO_NONCONFORMANT_EVALUATION_ID
        );
    }

    fn scope() -> AuthenticatedProjectScopeV1 {
        AuthenticatedProjectScopeV1::from_trusted_context(
            ContractId::new("tenant.default").unwrap(),
            ContractId::new("project.default").unwrap(),
        )
    }

    fn registry_ref(id: &str, digest_seed: u8) -> RegistryReferenceV1 {
        RegistryReferenceV1 {
            entry_id: ContractId::new(id).unwrap(),
            version: 1,
            entry_digest: Sha256Digest::from_bytes([digest_seed; 32]),
        }
    }

    fn window() -> MeasurementWindowV1 {
        MeasurementWindowV1 {
            start: CanonicalTimestamp::parse("2026-08-15T12:00:00.000000000Z").unwrap(),
            end: CanonicalTimestamp::parse("2026-08-15T12:05:00.000000000Z").unwrap(),
        }
    }

    fn resource_uri(kind: &str, seed: u8) -> ResourceUri {
        format!(
            "urn:ostk:entity:v1:{kind}:sha256:{}",
            Sha256Digest::from_bytes([seed; 32]).to_hex()
        )
        .parse()
        .unwrap()
    }

    fn private_policy() -> ExemplarPolicyV1 {
        ExemplarPolicyV1 {
            schema_version: TELEMETRY_SCHEMA_VERSION,
            policy_id: ContractId::new("telemetry.exemplar.default").unwrap(),
            policy_version: 1,
            selector: ExemplarSelectorV1::DeterministicStratifiedHashV1,
            biased_extrema: false,
            visibility: ExemplarVisibilityV1::Private,
            public_activation: None,
        }
    }

    fn public_default_policy() -> ExemplarPolicyV1 {
        ExemplarPolicyV1 {
            visibility: ExemplarVisibilityV1::Public,
            ..private_policy()
        }
    }

    fn public_activated_policy() -> ExemplarPolicyV1 {
        ExemplarPolicyV1 {
            visibility: ExemplarVisibilityV1::Public,
            public_activation: Some(PublicExemplarActivationV1 {
                approval: registry_ref("telemetry.exemplar.public_approval", 9),
                public_visibility_established_at: CanonicalTimestamp::parse(
                    "2026-08-01T00:00:00.000000000Z",
                )
                .unwrap(),
                activated_at: CanonicalTimestamp::parse("2026-08-10T00:00:00.000000000Z").unwrap(),
            }),
            ..private_policy()
        }
    }

    fn exemplar(seed: u8, frame_bytes: usize) -> ExemplarV1 {
        let frame = "x".repeat(frame_bytes.min(EXEMPLAR_TEXT_MAX_BYTES));
        ExemplarV1 {
            schema_version: TELEMETRY_SCHEMA_VERSION,
            occurred_at: CanonicalTimestamp::parse("2026-08-15T12:02:00.000000000Z").unwrap(),
            service: ContractId::new("checkout").unwrap(),
            environment: ContractId::new("prod").unwrap(),
            region: ContractId::new("us-east-1").unwrap(),
            workload: Some(ContractId::new("checkout-api").unwrap()),
            cohort: Some(ContractId::new("stable").unwrap()),
            route_template: ExemplarTextV1::parse("/v1/orders/:id").unwrap(),
            status_class: ExemplarStatusClassV1::ServerError,
            duration_ms: 250,
            sanitized_code_frames: if frame_bytes == 0 {
                Vec::new()
            } else {
                vec![ExemplarTextV1::parse(frame).unwrap()]
            },
            trace: ExemplarTraceCoordinatesV1 {
                trace_id: FixedHex32::from_bytes([seed; 32]),
                span_id: None,
            },
        }
    }

    fn candidate(
        stratum: &str,
        source_seed: u8,
        record_id: u8,
        outcome: CandidateOutcomeV1,
    ) -> SelectionCandidateV1 {
        SelectionCandidateV1 {
            stratum_key: ExemplarTextV1::parse(stratum).unwrap(),
            measurement_source_fact_id: Sha256Digest::from_bytes([source_seed; 32]),
            provider_record_id: HexBytes::new(vec![record_id]).unwrap(),
            outcome,
        }
    }

    fn receipt(exemplars: ExemplarSelectionReceiptV1) -> MeasurementReceiptV1 {
        MeasurementReceiptV1 {
            schema_version: TELEMETRY_SCHEMA_VERSION,
            profile: frozen_profile_reference_v1(),
            scope: scope(),
            provider: registry_ref("telemetry.provider.cloudwatch", 1),
            query: registry_ref("telemetry.query.p99_latency", 2),
            query_digest: Sha256Digest::from_bytes([3; 32]),
            provider_link: ProviderQueryLinkV1::Durable {
                locator: resource_uri("telemetry_query", 4),
            },
            window: window(),
            evaluation_time: CanonicalTimestamp::parse("2026-08-15T12:05:30.000000000Z").unwrap(),
            aggregation: AggregationV1::PercentileP99,
            unit: ContractId::new("ms").unwrap(),
            result: CanonicalDecimal::parse("482.5").unwrap(),
            sample_count: 12_000,
            dimensions: vec![MeasurementDimensionV1 {
                key: ContractId::new("route").unwrap(),
                value: ContractId::new("checkout.submit").unwrap(),
            }],
            coverage: MeasurementCoverageV1 {
                completeness: CoverageCompletenessV1::Complete,
                freshness: CoverageFreshnessV1::Current,
                continuity: CoverageContinuityV1::Contiguous,
            },
            missingness: MissingnessV1 {
                missing_dimensions: Vec::new(),
                reason: None,
            },
            deployment: Some(resource_uri("deployment", 5)),
            workload: Some(resource_uri("workload", 6)),
            artifact: Some(resource_uri("artifact", 7)),
            config: Some(resource_uri("config", 8)),
            exemplars,
            private_raw_artifact: Some(resource_uri("raw_artifact", 10)),
            provider_response_digest: Sha256Digest::from_bytes([11; 32]),
        }
    }

    fn unbound_selection(policy: &ExemplarPolicyV1) -> ExemplarSelectionReceiptV1 {
        select_exemplars_deterministic_stratified_hash_v1(
            policy,
            &PopulationInputV1::Unbound(PopulationUnboundReasonV1::SnapshotUnavailable),
        )
        .unwrap()
    }

    #[test]
    fn measurement_window_is_half_open() {
        let window = window();
        window.validate().unwrap();
        assert!(window.contains(&window.start));
        assert!(!window.contains(&window.end));
        let inverted = MeasurementWindowV1 {
            start: window.end,
            end: window.start,
        };
        assert!(inverted.validate().is_err());
    }

    #[test]
    fn measurement_receipt_round_trips_and_pins_a_stable_identity() {
        let value = receipt(unbound_selection(&private_policy()));
        value.validate_shape().unwrap();
        let bytes = encode_canonical(&value).unwrap();
        let decoded: MeasurementReceiptV1 = decode_strict(&bytes).unwrap();
        assert_eq!(decoded, value);
        let id_a = value.receipt_id().unwrap();
        let id_b = value.receipt_id().unwrap();
        assert_eq!(id_a, id_b);
    }

    #[test]
    fn admitted_receipt_typestate_is_test_only() {
        let value = receipt(unbound_selection(&private_policy()));
        let admitted = AdmittedMeasurementReceiptV1::from_test_witness(value.clone()).unwrap();
        assert_eq!(admitted.receipt(), &value);
    }

    #[test]
    fn evaluation_time_before_window_end_is_rejected() {
        let mut value = receipt(unbound_selection(&private_policy()));
        value.evaluation_time = window().start;
        assert!(value.validate_shape().is_err());
    }

    /// Non-blocking observation fix: previously `ExemplarV1::occurred_within`
    /// was never called by production code, so a receipt whose window was
    /// 2026-08-15T12:00..12:05 validated with an exemplar dated seven years
    /// outside it. Build a receipt with one genuinely selected exemplar
    /// (occurring inside the window, so this passes today), confirm it
    /// validates, then move only that exemplar's `occurred_at` outside the
    /// window and confirm `validate_shape` now refuses it.
    #[test]
    fn exemplar_outside_the_measurement_window_is_rejected() {
        let candidates = vec![candidate(
            "route.only",
            96,
            1,
            CandidateOutcomeV1::Eligible(Box::new(exemplar(1, 0))),
        )];
        let population = PopulationInputV1::Bound {
            snapshot_digest: Sha256Digest::from_bytes([97; 32]),
            query_population_digest: Sha256Digest::from_bytes([98; 32]),
            candidates: &candidates,
        };
        let selection =
            select_exemplars_deterministic_stratified_hash_v1(&private_policy(), &population)
                .unwrap();
        assert_eq!(selection.exemplars.len(), 1);
        assert!(selection.exemplars[0].occurred_within(&window()));

        let value = receipt(selection.clone());
        value.validate_shape().unwrap();

        let mut outside_window = selection;
        outside_window.exemplars[0].occurred_at =
            CanonicalTimestamp::parse("2019-01-01T00:00:00.000000000Z").unwrap();
        assert!(!outside_window.exemplars[0].occurred_within(&window()));
        let tampered = receipt(outside_window);
        assert!(tampered.validate_shape().is_err());
    }

    #[test]
    fn negative_float_result_is_rejected_end_to_end() {
        let value = receipt(unbound_selection(&private_policy()));
        let mut bytes = encode_canonical(&value).unwrap();
        let good = String::from_utf8(bytes.clone()).unwrap();
        let bad = good.replacen("\"482.5\"", "482.5", 1);
        assert_ne!(good, bad);
        bytes = bad.into_bytes();
        let decoded = decode_strict::<MeasurementReceiptV1>(&bytes);
        assert!(decoded.is_err());
    }

    #[test]
    fn slo_evaluation_round_trips_and_pins_a_stable_identity() {
        let value = SloEvaluationV1 {
            schema_version: TELEMETRY_SCHEMA_VERSION,
            scope: scope(),
            normative_rule: registry_ref("normative.slo.checkout_latency", 20),
            measurement_receipt_ids: vec![MeasurementReceiptId::from_digest(
                Sha256Digest::from_bytes([21; 32]),
            )],
            comparator: registry_ref("comparator.less_than_or_equal", 22),
            applicability_evaluator: registry_ref("applicability.default", 23),
            concrete_context: vec![MeasurementDimensionV1 {
                key: ContractId::new("environment").unwrap(),
                value: ContractId::new("prod").unwrap(),
            }],
            coverage_result: CoverageCompletenessV1::Complete,
            outcome: SloOutcomeV1::Compliant,
        };
        value.validate_shape().unwrap();
        let bytes = encode_canonical(&value).unwrap();
        let decoded: SloEvaluationV1 = decode_strict(&bytes).unwrap();
        assert_eq!(decoded, value);
        assert_eq!(
            value.evaluation_id().unwrap(),
            value.evaluation_id().unwrap()
        );
    }

    #[test]
    fn nonconformant_outcome_requires_complete_coverage() {
        let mut value = SloEvaluationV1 {
            schema_version: TELEMETRY_SCHEMA_VERSION,
            scope: scope(),
            normative_rule: registry_ref("normative.slo.checkout_latency", 20),
            measurement_receipt_ids: vec![MeasurementReceiptId::from_digest(
                Sha256Digest::from_bytes([21; 32]),
            )],
            comparator: registry_ref("comparator.less_than_or_equal", 22),
            applicability_evaluator: registry_ref("applicability.default", 23),
            concrete_context: Vec::new(),
            coverage_result: CoverageCompletenessV1::Partial,
            outcome: SloOutcomeV1::Nonconformant,
        };
        assert!(value.validate_shape().is_err());
        value.coverage_result = CoverageCompletenessV1::Complete;
        value.validate_shape().unwrap();
    }

    #[test]
    // RUN-01 fail-open regression: a `compliant` outcome is exactly as
    // "verified" (`verification_rank() == 2`) as `nonconformant` and must be
    // rejected under the same coverage weaker than `complete`, for BOTH
    // `partial` and `unknown`. The guard is written off `verification_rank`
    // precisely so this arm cannot be forgotten the way it originally was.
    fn compliant_outcome_requires_complete_coverage() {
        let mut value = SloEvaluationV1 {
            schema_version: TELEMETRY_SCHEMA_VERSION,
            scope: scope(),
            normative_rule: registry_ref("normative.slo.checkout_latency", 20),
            measurement_receipt_ids: vec![MeasurementReceiptId::from_digest(
                Sha256Digest::from_bytes([21; 32]),
            )],
            comparator: registry_ref("comparator.less_than_or_equal", 22),
            applicability_evaluator: registry_ref("applicability.default", 23),
            concrete_context: Vec::new(),
            coverage_result: CoverageCompletenessV1::Partial,
            outcome: SloOutcomeV1::Compliant,
        };
        assert!(value.validate_shape().is_err());
        value.coverage_result = CoverageCompletenessV1::Unknown;
        assert!(value.validate_shape().is_err());
        value.coverage_result = CoverageCompletenessV1::Complete;
        value.validate_shape().unwrap();
    }

    #[test]
    fn admitted_evaluation_typestate_is_test_only() {
        let value = SloEvaluationV1 {
            schema_version: TELEMETRY_SCHEMA_VERSION,
            scope: scope(),
            normative_rule: registry_ref("normative.slo.checkout_latency", 20),
            measurement_receipt_ids: vec![MeasurementReceiptId::from_digest(
                Sha256Digest::from_bytes([21; 32]),
            )],
            comparator: registry_ref("comparator.less_than_or_equal", 22),
            applicability_evaluator: registry_ref("applicability.default", 23),
            concrete_context: Vec::new(),
            coverage_result: CoverageCompletenessV1::Complete,
            outcome: SloOutcomeV1::Compliant,
        };
        let admitted = AdmittedSloEvaluationV1::from_test_witness(value.clone()).unwrap();
        assert_eq!(admitted.evaluation(), &value);
    }

    #[test]
    fn exemplars_cannot_upgrade_the_aggregate_outcome() {
        assert!(exemplars_do_not_upgrade_outcome(
            SloOutcomeV1::Unknown,
            SloOutcomeV1::Unknown
        ));
        assert!(exemplars_do_not_upgrade_outcome(
            SloOutcomeV1::Candidate,
            SloOutcomeV1::Candidate
        ));
        assert!(!exemplars_do_not_upgrade_outcome(
            SloOutcomeV1::Unknown,
            SloOutcomeV1::Nonconformant
        ));
        assert!(!exemplars_do_not_upgrade_outcome(
            SloOutcomeV1::Candidate,
            SloOutcomeV1::Compliant
        ));
    }

    #[test]
    fn selection_caps_are_fixed_by_visibility_and_activation() {
        assert_eq!(private_policy().effective_caps().max_count, 8);
        assert_eq!(private_policy().effective_caps().max_bytes_each, 1_024);
        assert_eq!(private_policy().effective_caps().max_total_bytes, 8 * 1_024);
        assert_eq!(public_default_policy().effective_caps().max_count, 0);
        assert_eq!(public_activated_policy().effective_caps().max_count, 3);
        assert_eq!(
            public_activated_policy().effective_caps().max_bytes_each,
            512
        );
        assert_eq!(
            public_activated_policy().effective_caps().max_total_bytes,
            1_536
        );
    }

    #[test]
    fn public_activation_cannot_precede_established_visibility() {
        let mut policy = public_activated_policy();
        if let Some(activation) = policy.public_activation.as_mut() {
            activation.activated_at =
                CanonicalTimestamp::parse("2026-07-01T00:00:00.000000000Z").unwrap();
        }
        assert!(policy.validate().is_err());
    }

    #[test]
    fn private_policy_cannot_carry_a_public_activation() {
        let mut policy = private_policy();
        policy.public_activation = Some(PublicExemplarActivationV1 {
            approval: registry_ref("telemetry.exemplar.public_approval", 9),
            public_visibility_established_at: CanonicalTimestamp::parse(
                "2026-08-01T00:00:00.000000000Z",
            )
            .unwrap(),
            activated_at: CanonicalTimestamp::parse("2026-08-10T00:00:00.000000000Z").unwrap(),
        });
        assert!(policy.validate().is_err());
    }

    /// A reader must be able to trust a decoded `biased_extrema: true`
    /// policy: `deterministic_stratified_hash_v1` (the only selector this
    /// module implements) already refuses to *run* under that label
    /// (`biased_extrema_policy_is_refused_by_the_hash_selector`), but
    /// nothing previously stopped such a policy from decoding and passing
    /// `ExemplarPolicyV1::validate` on its own -- a receipt could be
    /// hand-assembled naming the hash selector under a biased label without
    /// ever going through the selector function that refuses it.
    #[test]
    fn biased_extrema_policy_fails_validation_for_the_hash_selector() {
        let mut policy = private_policy();
        policy.biased_extrema = true;
        assert!(policy.validate().is_err());
    }

    fn two_stratum_candidates() -> Vec<SelectionCandidateV1> {
        vec![
            candidate(
                "route.checkout",
                30,
                1,
                CandidateOutcomeV1::Eligible(Box::new(exemplar(1, 0))),
            ),
            candidate(
                "route.checkout",
                31,
                2,
                CandidateOutcomeV1::Eligible(Box::new(exemplar(2, 0))),
            ),
            candidate("route.checkout", 32, 3, CandidateOutcomeV1::Withheld),
            candidate(
                "route.refund",
                33,
                4,
                CandidateOutcomeV1::Eligible(Box::new(exemplar(4, 0))),
            ),
            candidate(
                "route.refund",
                34,
                5,
                CandidateOutcomeV1::Eligible(Box::new(exemplar(5, 0))),
            ),
        ]
    }

    /// Three strata, three eligible candidates each (9 eligible total),
    /// against the private policy's cap of 8: round-robin fills every
    /// stratum's first two slots (6 selected), then has exactly two of the
    /// three cap-remaining slots left, so the third stratum's (canonically
    /// last) third-ranked candidate is omitted while the first two strata's
    /// third-ranked candidates are selected. The cap therefore forces a
    /// real choice between eligible records, unlike [`two_stratum_candidates`]
    /// (4 eligible, cap 8: never truncates). Used to pin
    /// `deterministic_stratified_hash_v1` against a population where an
    /// inverted ordering key or comparator would change which record is
    /// omitted, not merely their order.
    fn cap_truncating_candidates() -> Vec<SelectionCandidateV1> {
        let mut candidates = Vec::with_capacity(9);
        let mut record_id = 1u8;
        for (stratum, base_seed) in [
            ("route.checkout", 60u8),
            ("route.orders", 70u8),
            ("route.refund", 80u8),
        ] {
            for offset in 0..3u8 {
                candidates.push(candidate(
                    stratum,
                    base_seed + offset,
                    record_id,
                    CandidateOutcomeV1::Eligible(Box::new(exemplar(record_id, 0))),
                ));
                record_id += 1;
            }
        }
        candidates
    }

    #[test]
    fn selection_is_deterministic_and_input_order_is_irrelevant() {
        let policy = private_policy();
        let forward = two_stratum_candidates();
        let mut shuffled = forward.clone();
        shuffled.reverse();
        shuffled.swap(0, 2);

        let population_a = PopulationInputV1::Bound {
            snapshot_digest: Sha256Digest::from_bytes([50; 32]),
            query_population_digest: Sha256Digest::from_bytes([51; 32]),
            candidates: &forward,
        };
        let population_b = PopulationInputV1::Bound {
            snapshot_digest: Sha256Digest::from_bytes([50; 32]),
            query_population_digest: Sha256Digest::from_bytes([51; 32]),
            candidates: &shuffled,
        };

        let receipt_a =
            select_exemplars_deterministic_stratified_hash_v1(&policy, &population_a).unwrap();
        let receipt_b =
            select_exemplars_deterministic_stratified_hash_v1(&policy, &population_b).unwrap();

        assert_eq!(
            encode_canonical(&receipt_a).unwrap(),
            encode_canonical(&receipt_b).unwrap()
        );
        assert_eq!(receipt_a.candidate_count, 5);
        assert_eq!(receipt_a.withheld_count, 1);
        assert_eq!(receipt_a.eligible_count, 4);
        assert_eq!(receipt_a.selected_count, 4);
        assert_eq!(receipt_a.omitted_count, 0);
        assert!(!receipt_a.truncated);
        assert_eq!(receipt_a.strata.len(), 2);
        assert!(strictly_sorted_strata(&receipt_a.strata));
    }

    #[test]
    fn round_robin_selects_across_strata_in_canonical_order_until_the_cap() {
        let policy = private_policy();
        let mut candidates = Vec::new();
        for id in 0..5u8 {
            candidates.push(candidate(
                "route.a",
                60 + id,
                id,
                CandidateOutcomeV1::Eligible(Box::new(exemplar(id, 0))),
            ));
        }
        for id in 5..9u8 {
            candidates.push(candidate(
                "route.b",
                60 + id,
                id,
                CandidateOutcomeV1::Eligible(Box::new(exemplar(id, 0))),
            ));
        }
        let population = PopulationInputV1::Bound {
            snapshot_digest: Sha256Digest::from_bytes([70; 32]),
            query_population_digest: Sha256Digest::from_bytes([71; 32]),
            candidates: &candidates,
        };
        let value =
            select_exemplars_deterministic_stratified_hash_v1(&policy, &population).unwrap();
        assert_eq!(value.selected_count, 8);
        assert!(value.truncated);
        assert_eq!(value.omitted_count, 1);
        let by_key: BTreeMap<_, _> = value
            .strata
            .iter()
            .map(|stratum| {
                (
                    stratum.stratum_key.as_str().to_owned(),
                    stratum.selected_count,
                )
            })
            .collect();
        assert_eq!(by_key.get("route.a").copied(), Some(4));
        assert_eq!(by_key.get("route.b").copied(), Some(4));
    }

    #[test]
    fn withheld_candidates_are_never_representable_as_exemplars() {
        let policy = private_policy();
        let candidates = vec![candidate("route.only", 80, 1, CandidateOutcomeV1::Withheld)];
        let population = PopulationInputV1::Bound {
            snapshot_digest: Sha256Digest::from_bytes([81; 32]),
            query_population_digest: Sha256Digest::from_bytes([82; 32]),
            candidates: &candidates,
        };
        let value =
            select_exemplars_deterministic_stratified_hash_v1(&policy, &population).unwrap();
        assert_eq!(value.candidate_count, 1);
        assert_eq!(value.withheld_count, 1);
        assert_eq!(value.eligible_count, 0);
        assert!(value.exemplars.is_empty());
    }

    #[test]
    fn unavailable_snapshot_selects_none_and_keeps_the_aggregate() {
        let policy = private_policy();
        let value = select_exemplars_deterministic_stratified_hash_v1(
            &policy,
            &PopulationInputV1::Unbound(PopulationUnboundReasonV1::SnapshotUnavailable),
        )
        .unwrap();
        assert_eq!(value.selected_count, 0);
        assert!(value.exemplars.is_empty());
        assert!(matches!(
            value.population,
            PopulationBoundaryV1::Unbound {
                reason: PopulationUnboundReasonV1::SnapshotUnavailable
            }
        ));
        let measurement = receipt(value);
        measurement.validate_shape().unwrap();
    }

    #[test]
    fn irreproducible_population_selects_none_and_keeps_the_aggregate() {
        let policy = private_policy();
        let value = select_exemplars_deterministic_stratified_hash_v1(
            &policy,
            &PopulationInputV1::Unbound(PopulationUnboundReasonV1::Irreproducible),
        )
        .unwrap();
        assert_eq!(value.selected_count, 0);
        assert!(matches!(
            value.population,
            PopulationBoundaryV1::Unbound {
                reason: PopulationUnboundReasonV1::Irreproducible
            }
        ));
    }

    #[test]
    fn unbound_population_with_nonzero_counts_is_rejected() {
        let mut value = unbound_selection(&private_policy());
        value.candidate_count = 1;
        assert!(value.validate_shape().is_err());
    }

    #[test]
    fn public_reclassification_never_exposes_a_private_only_selection() {
        let private_selection = unbound_selection(&private_policy());
        assert!(private_selection.public_exemplars().unwrap().is_empty());

        let candidates = vec![candidate(
            "route.only",
            90,
            1,
            CandidateOutcomeV1::Eligible(Box::new(exemplar(1, 0))),
        )];
        let population = PopulationInputV1::Bound {
            snapshot_digest: Sha256Digest::from_bytes([91; 32]),
            query_population_digest: Sha256Digest::from_bytes([92; 32]),
            candidates: &candidates,
        };
        let private_with_exemplar =
            select_exemplars_deterministic_stratified_hash_v1(&private_policy(), &population)
                .unwrap();
        assert_eq!(private_with_exemplar.exemplars.len(), 1);
        assert!(private_with_exemplar.public_exemplars().unwrap().is_empty());

        let public_with_exemplar = select_exemplars_deterministic_stratified_hash_v1(
            &public_activated_policy(),
            &population,
        )
        .unwrap();
        assert_eq!(public_with_exemplar.public_exemplars().unwrap().len(), 1);
    }

    #[test]
    fn public_exemplars_rejects_a_receipt_with_tampered_visibility_instead_of_publishing_it() {
        // Adversarial reproduction of the PUBLIC-04/EVID-05 blocker: take a
        // legitimately Private receipt with real exemplars, decode it from
        // wire bytes the way a store-backed reader would, then flip only
        // the `visibility` token (leaving `policy_digest` bound to the
        // original -- now mismatched -- private policy). The accessor must
        // refuse to publish rather than trust the unvalidated field.
        let candidates = vec![candidate(
            "route.only",
            93,
            1,
            CandidateOutcomeV1::Eligible(Box::new(exemplar(1, 0))),
        )];
        let population = PopulationInputV1::Bound {
            snapshot_digest: Sha256Digest::from_bytes([94; 32]),
            query_population_digest: Sha256Digest::from_bytes([95; 32]),
            candidates: &candidates,
        };
        let private_with_exemplar =
            select_exemplars_deterministic_stratified_hash_v1(&private_policy(), &population)
                .unwrap();
        assert_eq!(private_with_exemplar.exemplars.len(), 1);

        let bytes = encode_canonical(&private_with_exemplar).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        let flipped_text =
            text.replacen("\"visibility\":\"private\"", "\"visibility\":\"public\"", 1);
        assert_ne!(text, flipped_text);
        let flipped_bytes =
            crate::memory_contracts::canonical::parse_strict(flipped_text.as_bytes())
                .unwrap()
                .bytes()
                .to_vec();
        let tampered: ExemplarSelectionReceiptV1 = decode_strict(&flipped_bytes).unwrap();
        assert!(matches!(
            tampered.policy.visibility,
            ExemplarVisibilityV1::Public
        ));
        assert!(tampered.validate_shape().is_err());
        assert!(tampered.public_exemplars().is_err());
    }

    #[test]
    fn biased_extrema_policy_is_refused_by_the_hash_selector() {
        let mut policy = private_policy();
        policy.biased_extrema = true;
        let result = select_exemplars_deterministic_stratified_hash_v1(
            &policy,
            &PopulationInputV1::Unbound(PopulationUnboundReasonV1::SnapshotUnavailable),
        );
        assert!(result.is_err());
    }

    #[test]
    fn erasure_removes_the_payload_and_keeps_the_receipt() {
        let candidates = two_stratum_candidates();
        let population = PopulationInputV1::Bound {
            snapshot_digest: Sha256Digest::from_bytes([100; 32]),
            query_population_digest: Sha256Digest::from_bytes([101; 32]),
            candidates: &candidates,
        };
        let selection =
            select_exemplars_deterministic_stratified_hash_v1(&private_policy(), &population)
                .unwrap();
        assert_eq!(selection.selected_count, 4);
        assert_eq!(selection.exemplars.len(), 4);

        let erased = selection
            .erase_exemplar_at(
                0,
                CanonicalTimestamp::parse("2026-08-16T00:00:00.000000000Z").unwrap(),
                registry_ref("erasure.policy.default", 40),
            )
            .unwrap();
        assert_eq!(erased.selected_count, 4);
        assert_eq!(erased.exemplars.len(), 3);
        assert_eq!(erased.tombstones.len(), 1);
        erased.validate_shape().unwrap();
    }

    /// Blocker fix (erasure-deadlock guard): two selected exemplars whose
    /// content is byte-identical must both be individually erasable. The
    /// prior `validate_caps_and_tombstones` rejected a tombstone whose
    /// digest was still present anywhere in `exemplars`, which permanently
    /// blocked erasing the second of two content-duplicate records; erasure
    /// now keys off each tombstone's stable `selection_index` instead.
    #[test]
    fn erasure_is_total_for_content_identical_selected_exemplars() {
        let duplicate = exemplar(1, 0);
        let candidates = vec![
            candidate(
                "route.only",
                120,
                1,
                CandidateOutcomeV1::Eligible(Box::new(duplicate.clone())),
            ),
            candidate(
                "route.only",
                121,
                2,
                CandidateOutcomeV1::Eligible(Box::new(duplicate)),
            ),
        ];
        let population = PopulationInputV1::Bound {
            snapshot_digest: Sha256Digest::from_bytes([130; 32]),
            query_population_digest: Sha256Digest::from_bytes([131; 32]),
            candidates: &candidates,
        };
        let selection =
            select_exemplars_deterministic_stratified_hash_v1(&private_policy(), &population)
                .unwrap();
        assert_eq!(selection.selected_count, 2);
        assert_eq!(selection.exemplars.len(), 2);
        assert_eq!(
            selection.exemplars[0].exemplar_digest().unwrap(),
            selection.exemplars[1].exemplar_digest().unwrap(),
            "both candidates carry byte-identical exemplar content by construction"
        );

        let erased_at = CanonicalTimestamp::parse("2026-08-16T00:00:00.000000000Z").unwrap();
        let one_erased = selection
            .erase_exemplar_at(
                0,
                erased_at.clone(),
                registry_ref("erasure.policy.default", 40),
            )
            .unwrap();
        assert_eq!(one_erased.exemplars.len(), 1);
        assert_eq!(one_erased.tombstones.len(), 1);
        one_erased.validate_shape().unwrap();

        // The second content-identical exemplar must also be erasable: a
        // digest-set-membership check would deadlock here even though it
        // names a distinct originally-selected record.
        let both_erased = one_erased
            .erase_exemplar_at(0, erased_at, registry_ref("erasure.policy.default", 40))
            .unwrap();
        assert_eq!(both_erased.exemplars.len(), 0);
        assert_eq!(both_erased.tombstones.len(), 2);
        assert_eq!(both_erased.selected_count, 2);
        both_erased.validate_shape().unwrap();
    }

    /// Mechanical mutation check (PREFLIGHT item 1): each conjunct inside
    /// `validate_caps_and_tombstones`'s tombstone-shape loop -- canonical
    /// order, in-range `selection_index`, and no duplicate `selection_index`
    /// -- had no dedicated killing test; deleting any one of the three left
    /// every other committed test green (confirmed by hand before writing
    /// this test: `if false && <conjunct> { .. }` on each, one at a time,
    /// left `cargo test --lib memory_contracts::telemetry` fully green).
    /// Starting from a receipt with two genuinely erased, content-identical
    /// exemplars -- `present + tombstoned == selected_count` stays satisfied
    /// throughout, so the count-consistency check never fires first and each
    /// mutation below isolates exactly one conjunct.
    #[test]
    fn tombstone_shape_conjuncts_are_each_independently_enforced() {
        let duplicate = exemplar(1, 0);
        let candidates = vec![
            candidate(
                "route.only",
                140,
                1,
                CandidateOutcomeV1::Eligible(Box::new(duplicate.clone())),
            ),
            candidate(
                "route.only",
                141,
                2,
                CandidateOutcomeV1::Eligible(Box::new(duplicate)),
            ),
        ];
        let population = PopulationInputV1::Bound {
            snapshot_digest: Sha256Digest::from_bytes([142; 32]),
            query_population_digest: Sha256Digest::from_bytes([143; 32]),
            candidates: &candidates,
        };
        let selection =
            select_exemplars_deterministic_stratified_hash_v1(&private_policy(), &population)
                .unwrap();
        let erased_at = CanonicalTimestamp::parse("2026-08-16T00:00:00.000000000Z").unwrap();
        let one_erased = selection
            .erase_exemplar_at(
                0,
                erased_at.clone(),
                registry_ref("erasure.policy.default", 40),
            )
            .unwrap();
        let both_erased = one_erased
            .erase_exemplar_at(0, erased_at, registry_ref("erasure.policy.default", 40))
            .unwrap();
        assert_eq!(both_erased.exemplars.len(), 0);
        assert_eq!(both_erased.tombstones.len(), 2);
        assert_eq!(both_erased.tombstones[0].selection_index, 0);
        assert_eq!(both_erased.tombstones[1].selection_index, 1);
        both_erased.validate_shape().unwrap();

        // Kills `!tombstoned_indices.insert(tombstone.selection_index)`:
        // present(0) + tombstoned(2) == selected_count(2) is unaffected, so
        // only the duplicate-index conjunct can reject this.
        let mut duplicate_index = both_erased.clone();
        duplicate_index.tombstones[1].selection_index = 0;
        assert!(duplicate_index.validate_shape().is_err());

        // Kills `tombstone.selection_index >= self.selected_count`.
        let mut out_of_range = both_erased.clone();
        out_of_range.tombstones[1].selection_index = 99;
        assert!(out_of_range.validate_shape().is_err());

        // Kills `!strictly_sorted(&self.tombstones)`: indices stay 0 and 1
        // (both valid, both unique) but out of canonical order.
        let mut unsorted = both_erased;
        unsorted.tombstones.swap(0, 1);
        assert!(unsorted.validate_shape().is_err());
    }

    #[test]
    fn cap_exceeded_exemplar_is_rejected() {
        let candidates = vec![candidate(
            "route.only",
            110,
            1,
            CandidateOutcomeV1::Eligible(Box::new(exemplar(1, 0))),
        )];
        let population = PopulationInputV1::Bound {
            snapshot_digest: Sha256Digest::from_bytes([111; 32]),
            query_population_digest: Sha256Digest::from_bytes([112; 32]),
            candidates: &candidates,
        };
        let mut value = select_exemplars_deterministic_stratified_hash_v1(
            &public_activated_policy(),
            &population,
        )
        .unwrap();
        // Public activated per-exemplar cap is 512 bytes; swap in an exemplar
        // whose sanitized code frame alone pushes it well past that cap.
        value.exemplars[0] = exemplar(1, 480);
        assert!(value.validate_shape().is_err());
    }

    #[test]
    fn secret_shaped_field_is_rejected_structurally() {
        let value = exemplar(1, 0);
        let mut bytes = encode_canonical(&value).unwrap();
        let mut text = String::from_utf8(bytes.clone()).unwrap();
        text = text.replacen(
            "\"schema_version\":1",
            "\"schema_version\":1,\"headers\":{\"authorization\":\"Bearer secret\"}",
            1,
        );
        bytes = text.into_bytes();
        assert!(decode_strict::<ExemplarV1>(&bytes).is_err());
    }

    #[test]
    fn raw_log_line_field_is_rejected_structurally() {
        let value = exemplar(1, 0);
        let mut bytes = encode_canonical(&value).unwrap();
        let mut text = String::from_utf8(bytes.clone()).unwrap();
        text = text.replacen(
            "\"schema_version\":1",
            "\"schema_version\":1,\"raw_log_line\":\"2026-08-15 500 error at checkout.rs:42\"",
            1,
        );
        bytes = text.into_bytes();
        assert!(decode_strict::<ExemplarV1>(&bytes).is_err());
    }

    #[test]
    fn exemplar_text_rejects_control_scalars_and_oversize() {
        assert!(ExemplarTextV1::parse("clean text").is_ok());
        assert!(ExemplarTextV1::parse("line one\nline two").is_ok());
        assert!(ExemplarTextV1::parse("tab\tnot allowed").is_err());
        assert!(ExemplarTextV1::parse("x".repeat(EXEMPLAR_TEXT_MAX_BYTES + 1)).is_err());
        assert!(ExemplarTextV1::parse(String::new()).is_err());
    }

    #[test]
    fn identity_form_import_is_exercised_by_resource_uri_round_trip() {
        let uri = resource_uri("workload", 200);
        assert_eq!(uri.identity_form(), IdentityForm::Entity);
    }

    fn slo_evaluation_fixture(
        outcome: SloOutcomeV1,
        coverage: CoverageCompletenessV1,
    ) -> SloEvaluationV1 {
        SloEvaluationV1 {
            schema_version: TELEMETRY_SCHEMA_VERSION,
            scope: scope(),
            normative_rule: registry_ref("normative.slo.checkout_latency", 20),
            measurement_receipt_ids: vec![MeasurementReceiptId::from_digest(
                Sha256Digest::from_bytes([21; 32]),
            )],
            comparator: registry_ref("comparator.less_than_or_equal", 22),
            applicability_evaluator: registry_ref("applicability.default", 23),
            concrete_context: vec![MeasurementDimensionV1 {
                key: ContractId::new("environment").unwrap(),
                value: ContractId::new("prod").unwrap(),
            }],
            coverage_result: coverage,
            outcome,
        }
    }

    #[test]
    #[ignore = "one-shot fixture generator; run explicitly with --ignored"]
    // A linear generator that writes every fixture in one place is easier to
    // audit for byte-exactness than one split across helper functions.
    #[allow(clippy::too_many_lines)]
    fn write_fixture_corpus() {
        let dir = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/contracts/dynamic-memory/v3/telemetry/"
        );
        let mut manifest: BTreeMap<String, serde_json::Value> = BTreeMap::new();
        // Writes one fixture to disk and returns its raw SHA-256 hex digest.
        // Deliberately does not touch `manifest` itself (a closure borrowing
        // it mutably would hold that borrow for its entire lifetime and
        // conflict with every direct `manifest.get_mut(...)` call below);
        // callers record the manifest entry themselves right after writing.
        let write = |name: &str, bytes: Vec<u8>| -> String {
            let mut framed = bytes;
            framed.push(b'\n');
            // Hash the exact checked-in (framed, LF-terminated) bytes, matching
            // what `include_bytes!` sees and what `shasum -a 256` reports.
            let raw_sha256 = hex::encode(Sha256::digest(&framed));
            std::fs::write(format!("{dir}{name}"), &framed).unwrap();
            println!("{name} bytes={}", framed.len());
            raw_sha256
        };
        let record =
            |manifest: &mut BTreeMap<String, serde_json::Value>, name: &str, raw_sha256: String| {
                manifest.insert(
                    name.to_owned(),
                    serde_json::json!({"path": name, "raw_sha256": raw_sha256}),
                );
            };

        let private_with_exemplars = {
            let candidates = two_stratum_candidates();
            let population = PopulationInputV1::Bound {
                snapshot_digest: Sha256Digest::from_bytes([200; 32]),
                query_population_digest: Sha256Digest::from_bytes([201; 32]),
                candidates: &candidates,
            };
            select_exemplars_deterministic_stratified_hash_v1(&private_policy(), &population)
                .unwrap()
        };
        let receipt_with_exemplars = receipt(private_with_exemplars.clone());
        let private_receipt_id = receipt_with_exemplars.receipt_id().unwrap();
        println!(
            "measurement-receipt-v1-private-with-exemplars.jsonl receipt_id={private_receipt_id}"
        );
        let sha = write(
            "measurement-receipt-v1-private-with-exemplars.jsonl",
            encode_canonical(&receipt_with_exemplars).unwrap(),
        );
        record(
            &mut manifest,
            "measurement-receipt-v1-private-with-exemplars.jsonl",
            sha,
        );
        manifest
            .get_mut("measurement-receipt-v1-private-with-exemplars.jsonl")
            .unwrap()["receipt_id"] = serde_json::Value::String(private_receipt_id.to_string());

        let unavailable_receipt = receipt(unbound_selection(&private_policy()));
        let unavailable_receipt_id = unavailable_receipt.receipt_id().unwrap();
        println!(
            "measurement-receipt-v1-population-unavailable.jsonl receipt_id={unavailable_receipt_id}"
        );
        let sha = write(
            "measurement-receipt-v1-population-unavailable.jsonl",
            encode_canonical(&unavailable_receipt).unwrap(),
        );
        record(
            &mut manifest,
            "measurement-receipt-v1-population-unavailable.jsonl",
            sha,
        );
        manifest
            .get_mut("measurement-receipt-v1-population-unavailable.jsonl")
            .unwrap()["receipt_id"] = serde_json::Value::String(unavailable_receipt_id.to_string());

        let compliant =
            slo_evaluation_fixture(SloOutcomeV1::Compliant, CoverageCompletenessV1::Complete);
        let compliant_id = compliant.evaluation_id().unwrap();
        println!("slo-evaluation-v1-compliant.jsonl evaluation_id={compliant_id}");
        let sha = write(
            "slo-evaluation-v1-compliant.jsonl",
            encode_canonical(&compliant).unwrap(),
        );
        record(&mut manifest, "slo-evaluation-v1-compliant.jsonl", sha);
        manifest
            .get_mut("slo-evaluation-v1-compliant.jsonl")
            .unwrap()["evaluation_id"] = serde_json::Value::String(compliant_id.to_string());

        let nonconformant = slo_evaluation_fixture(
            SloOutcomeV1::Nonconformant,
            CoverageCompletenessV1::Complete,
        );
        let nonconformant_id = nonconformant.evaluation_id().unwrap();
        println!("slo-evaluation-v1-nonconformant.jsonl evaluation_id={nonconformant_id}");
        let sha = write(
            "slo-evaluation-v1-nonconformant.jsonl",
            encode_canonical(&nonconformant).unwrap(),
        );
        record(&mut manifest, "slo-evaluation-v1-nonconformant.jsonl", sha);
        manifest
            .get_mut("slo-evaluation-v1-nonconformant.jsonl")
            .unwrap()["evaluation_id"] = serde_json::Value::String(nonconformant_id.to_string());

        let private_policy_digest = exemplar_policy_digest(&private_policy()).unwrap();
        println!("exemplar-policy-v1-private.jsonl policy_digest={private_policy_digest}");
        let sha = write(
            "exemplar-policy-v1-private.jsonl",
            encode_canonical(&private_policy()).unwrap(),
        );
        record(&mut manifest, "exemplar-policy-v1-private.jsonl", sha);
        manifest
            .get_mut("exemplar-policy-v1-private.jsonl")
            .unwrap()["policy_digest"] =
            serde_json::Value::String(private_policy_digest.to_string());

        let public_activated_policy_digest =
            exemplar_policy_digest(&public_activated_policy()).unwrap();
        println!(
            "exemplar-policy-v1-public-activated.jsonl policy_digest={public_activated_policy_digest}"
        );
        let sha = write(
            "exemplar-policy-v1-public-activated.jsonl",
            encode_canonical(&public_activated_policy()).unwrap(),
        );
        record(
            &mut manifest,
            "exemplar-policy-v1-public-activated.jsonl",
            sha,
        );
        manifest
            .get_mut("exemplar-policy-v1-public-activated.jsonl")
            .unwrap()["policy_digest"] =
            serde_json::Value::String(public_activated_policy_digest.to_string());

        let single_exemplar = exemplar(1, 0);
        let single_exemplar_digest = single_exemplar.exemplar_digest().unwrap();
        println!("exemplar-v1.jsonl exemplar_digest={single_exemplar_digest}");
        let sha = write(
            "exemplar-v1.jsonl",
            encode_canonical(&single_exemplar).unwrap(),
        );
        record(&mut manifest, "exemplar-v1.jsonl", sha);
        manifest.get_mut("exemplar-v1.jsonl").unwrap()["exemplar_digest"] =
            serde_json::Value::String(single_exemplar_digest.to_string());

        let erased = private_with_exemplars
            .erase_exemplar_at(
                0,
                CanonicalTimestamp::parse("2026-08-16T00:00:00.000000000Z").unwrap(),
                registry_ref("erasure.policy.default", 40),
            )
            .unwrap();
        let sha = write(
            "exemplar-selection-receipt-v1-erased.jsonl",
            encode_canonical(&erased).unwrap(),
        );
        record(
            &mut manifest,
            "exemplar-selection-receipt-v1-erased.jsonl",
            sha,
        );

        // A cap-truncating selection: 9 eligible candidates across 3 strata
        // against the private policy's cap of 8, so `omitted_count == 1` and
        // exactly which candidate is left out depends on the ordering key
        // and comparator, not just on per-stratum counts. Pinned separately
        // from `measurement-receipt-v1-private-with-exemplars.jsonl` (whose
        // 4-candidate population never reaches the cap) so the replay test
        // below actually exercises the cap-forces-a-choice path.
        let cap_truncating_candidates = cap_truncating_candidates();
        let cap_truncated_population = PopulationInputV1::Bound {
            snapshot_digest: Sha256Digest::from_bytes([210; 32]),
            query_population_digest: Sha256Digest::from_bytes([211; 32]),
            candidates: &cap_truncating_candidates,
        };
        let cap_truncated = select_exemplars_deterministic_stratified_hash_v1(
            &private_policy(),
            &cap_truncated_population,
        )
        .unwrap();
        assert_eq!(cap_truncated.candidate_count, 9);
        assert_eq!(cap_truncated.selected_count, 8);
        assert_eq!(cap_truncated.omitted_count, 1);
        assert!(cap_truncated.truncated);
        let sha = write(
            "exemplar-selection-receipt-v1-cap-truncated.jsonl",
            encode_canonical(&cap_truncated).unwrap(),
        );
        record(
            &mut manifest,
            "exemplar-selection-receipt-v1-cap-truncated.jsonl",
            sha,
        );

        // Negative (cap-bypass guard): a hand-fabricated receipt naming
        // `selected_count = 9` under the private policy's cap of 8 --
        // 1 present exemplar plus 8 tombstones, arithmetically self-
        // consistent everywhere else (`validate_counts_and_strata` alone
        // would accept it). Only `validate_caps_and_tombstones`'s explicit
        // `selected_count > caps.max_count` check rejects it; a genuine
        // selection can never produce this shape because selection stops at
        // the cap and erasure never raises `selected_count`.
        let cap_bypass_tombstones: Vec<ErasedExemplarTombstoneV1> = (0..8u8)
            .map(|seed| ErasedExemplarTombstoneV1 {
                schema_version: TELEMETRY_SCHEMA_VERSION,
                selection_index: u32::from(seed),
                erased_exemplar_digest: exemplar(seed + 1, 0).exemplar_digest().unwrap(),
                erased_at: CanonicalTimestamp::parse("2026-08-16T00:00:00.000000000Z").unwrap(),
                erasure_policy: registry_ref("erasure.policy.default", 40),
            })
            .collect();
        let cap_bypass = ExemplarSelectionReceiptV1 {
            schema_version: TELEMETRY_SCHEMA_VERSION,
            policy: private_policy(),
            policy_digest: private_policy_digest,
            population: PopulationBoundaryV1::Bound {
                snapshot_digest: Sha256Digest::from_bytes([220; 32]),
                query_population_digest: Sha256Digest::from_bytes([221; 32]),
            },
            strata: vec![StratumSelectionV1 {
                stratum_key: ExemplarTextV1::parse("route.only").unwrap(),
                eligible_count: 9,
                selected_count: 9,
            }],
            candidate_count: 9,
            eligible_count: 9,
            withheld_count: 0,
            selected_count: 9,
            omitted_count: 0,
            truncated: false,
            exemplars: vec![exemplar(9, 0)],
            tombstones: cap_bypass_tombstones,
        };
        assert!(cap_bypass.validate_shape().is_err());
        let sha = write(
            "negative-selected-count-exceeds-cap.jsonl",
            encode_canonical(&cap_bypass).unwrap(),
        );
        record(
            &mut manifest,
            "negative-selected-count-exceeds-cap.jsonl",
            sha,
        );

        // Negative (tombstone-shape guard): the erased fixture with its one
        // tombstone's `schema_version` bumped to an unknown value. Decodes
        // structurally (schema_version is just a u32 field); `validate_shape`
        // must reject it rather than trust a tombstone this module could
        // never have produced.
        let erased_bytes = encode_canonical(&erased).unwrap();
        let erased_text = String::from_utf8(erased_bytes).unwrap();
        let bad_tombstone_schema_text = erased_text.replacen(
            "\"schema_version\":1,\"selection_index\"",
            "\"schema_version\":9999,\"selection_index\"",
            1,
        );
        assert_ne!(erased_text, bad_tombstone_schema_text);
        let bad_tombstone_schema_bytes =
            crate::memory_contracts::canonical::parse_strict(bad_tombstone_schema_text.as_bytes())
                .unwrap()
                .bytes()
                .to_vec();
        let bad_tombstone_schema: ExemplarSelectionReceiptV1 =
            decode_strict(&bad_tombstone_schema_bytes).unwrap();
        assert!(bad_tombstone_schema.validate_shape().is_err());
        let sha = write(
            "negative-tombstone-invalid-schema-version.jsonl",
            bad_tombstone_schema_bytes,
        );
        record(
            &mut manifest,
            "negative-tombstone-invalid-schema-version.jsonl",
            sha,
        );

        // Negative (tombstone-shape guard): the erased fixture with its
        // tombstone's `erasure_policy.version` rewritten to 0.
        // `RegistryReferenceV1::validate` rejects a zero version; this pins
        // that `validate_caps_and_tombstones` actually calls it for every
        // tombstone rather than trusting the nested record's shape.
        let bad_erasure_policy_text = erased_text.replacen(
            "\"erasure.policy.default\",\"version\":1",
            "\"erasure.policy.default\",\"version\":0",
            1,
        );
        assert_ne!(erased_text, bad_erasure_policy_text);
        let bad_erasure_policy_bytes =
            crate::memory_contracts::canonical::parse_strict(bad_erasure_policy_text.as_bytes())
                .unwrap()
                .bytes()
                .to_vec();
        let bad_erasure_policy: ExemplarSelectionReceiptV1 =
            decode_strict(&bad_erasure_policy_bytes).unwrap();
        assert!(bad_erasure_policy.validate_shape().is_err());
        let sha = write(
            "negative-tombstone-invalid-erasure-policy.jsonl",
            bad_erasure_policy_bytes,
        );
        record(
            &mut manifest,
            "negative-tombstone-invalid-erasure-policy.jsonl",
            sha,
        );

        // Negative: a syntactically well-formed receipt with a raw JSON float
        // result instead of a canonical decimal string. Deliberately NOT run
        // through `parse_strict`/`require_canonical`: the whole point is
        // that the canonical-JSON layer itself forbids the bare float.
        let good_receipt_bytes = encode_canonical(&unavailable_receipt).unwrap();
        let good_receipt_text = String::from_utf8(good_receipt_bytes).unwrap();
        let float_text = good_receipt_text.replacen("\"482.5\"", "482.5", 1);
        assert_ne!(good_receipt_text, float_text);
        assert!(require_canonical(float_text.as_bytes()).is_err());
        let sha = write("negative-float-result.jsonl", float_text.into_bytes());
        record(&mut manifest, "negative-float-result.jsonl", sha);

        // Negative: an exemplar-selection receipt whose one exemplar exceeds
        // the public activated per-exemplar byte cap (512 B). A single
        // candidate keeps the selected count within the count cap (3), so
        // the byte-size check is what actually fails.
        let single_candidate = vec![candidate(
            "route.only",
            110,
            1,
            CandidateOutcomeV1::Eligible(Box::new(exemplar(1, 0))),
        )];
        let single_population = PopulationInputV1::Bound {
            snapshot_digest: Sha256Digest::from_bytes([111; 32]),
            query_population_digest: Sha256Digest::from_bytes([112; 32]),
            candidates: &single_candidate,
        };
        let mut oversized = select_exemplars_deterministic_stratified_hash_v1(
            &public_activated_policy(),
            &single_population,
        )
        .unwrap();
        oversized.exemplars[0] = exemplar(1, 480);
        assert!(oversized.validate_shape().is_err());
        let sha = write(
            "negative-cap-exceeded-exemplar.jsonl",
            encode_canonical(&oversized).unwrap(),
        );
        record(&mut manifest, "negative-cap-exceeded-exemplar.jsonl", sha);

        // Negative: an exemplar payload carrying a deny-listed field name.
        // The extra key is spliced in at an arbitrary position, then the
        // whole document is re-canonicalized (`parse_strict` sorts keys
        // independently of any typed schema) so the checked-in fixture is
        // still one canonical JSON record: `ExemplarV1::deny_unknown_fields`
        // is what rejects it, not incidental key disorder.
        let exemplar_bytes = encode_canonical(&single_exemplar).unwrap();
        let exemplar_text = String::from_utf8(exemplar_bytes).unwrap();
        let secret_spliced = exemplar_text.replacen(
            "\"schema_version\":1",
            "\"schema_version\":1,\"headers\":{\"authorization\":\"Bearer secret\"}",
            1,
        );
        assert_ne!(exemplar_text, secret_spliced);
        let secret_bytes =
            crate::memory_contracts::canonical::parse_strict(secret_spliced.as_bytes())
                .unwrap()
                .bytes()
                .to_vec();
        assert!(decode_strict::<ExemplarV1>(&secret_bytes).is_err());
        let sha = write("negative-secret-shaped-field.jsonl", secret_bytes);
        record(&mut manifest, "negative-secret-shaped-field.jsonl", sha);

        let raw_log_spliced = exemplar_text.replacen(
            "\"schema_version\":1",
            "\"schema_version\":1,\"raw_log_line\":\"2026-08-15 500 error at checkout.rs:42\"",
            1,
        );
        assert_ne!(exemplar_text, raw_log_spliced);
        let raw_log_bytes =
            crate::memory_contracts::canonical::parse_strict(raw_log_spliced.as_bytes())
                .unwrap()
                .bytes()
                .to_vec();
        assert!(decode_strict::<ExemplarV1>(&raw_log_bytes).is_err());
        let sha = write("negative-raw-log-line-field.jsonl", raw_log_bytes);
        record(&mut manifest, "negative-raw-log-line-field.jsonl", sha);

        // Negative (RUN-01 fail-open guard): a `compliant` outcome under
        // `partial` coverage. Both `Compliant` and `Nonconformant` are
        // rank-2 "verified" outcomes (`SloOutcomeV1::verification_rank`);
        // this pins that the rank-2 coverage requirement is enforced for
        // BOTH arms, not only the `Nonconformant` one the earlier
        // `nonconformant_outcome_requires_complete_coverage` unit test
        // already covered. Decodes structurally; `validate_shape` rejects it.
        let compliant_partial_coverage =
            slo_evaluation_fixture(SloOutcomeV1::Compliant, CoverageCompletenessV1::Partial);
        assert!(compliant_partial_coverage.validate_shape().is_err());
        let sha = write(
            "negative-compliant-partial-coverage.jsonl",
            encode_canonical(&compliant_partial_coverage).unwrap(),
        );
        record(
            &mut manifest,
            "negative-compliant-partial-coverage.jsonl",
            sha,
        );

        // The manifest itself: raw SHA-256 of every fixture's exact bytes,
        // plus the semantic identity each positive fixture decodes to. Built
        // from the in-memory bytes just written, then re-canonicalized like
        // every other checked-in record.
        let suite = serde_json::json!({
            "schema_version": TELEMETRY_SCHEMA_VERSION,
            "suite_id": "ostk.telemetry-v1.vectors",
            "fixture_authority": "none; structural fixtures are assertions, not active-policy, active-registry, or provider witnesses",
            "profile": {
                "profile_id": frozen_profile_reference_v1().profile_id.as_str(),
                "profile_digest": frozen_profile_reference_v1().profile_digest.to_string(),
                "vector_manifest_digest": frozen_profile_reference_v1()
                    .vector_manifest_digest
                    .to_string(),
            },
            "digest_domains": {
                "MeasurementReceiptV1": DigestDomain::MeasurementReceiptV1.prefix(),
                "SloEvaluationV1": DigestDomain::SloEvaluationV1.prefix(),
                "ExemplarSelectionV1": DigestDomain::ExemplarSelectionV1.prefix(),
            },
            "positive_fixtures": manifest
                .keys()
                .filter(|name| !name.starts_with("negative-"))
                .collect::<Vec<_>>(),
            "negative_cases": {
                "float_result": "negative-float-result.jsonl",
                "cap_exceeded_exemplar": "negative-cap-exceeded-exemplar.jsonl",
                "secret_shaped_field": "negative-secret-shaped-field.jsonl",
                "raw_log_line_field": "negative-raw-log-line-field.jsonl",
                "compliant_partial_coverage": "negative-compliant-partial-coverage.jsonl",
                "selected_count_exceeds_cap": "negative-selected-count-exceeds-cap.jsonl",
                "tombstone_invalid_schema_version": "negative-tombstone-invalid-schema-version.jsonl",
                "tombstone_invalid_erasure_policy": "negative-tombstone-invalid-erasure-policy.jsonl",
            },
            "artifacts": manifest,
        });
        let suite_bytes = crate::memory_contracts::canonical::parse_strict(
            serde_json::to_vec(&suite).unwrap().as_slice(),
        )
        .unwrap()
        .bytes()
        .to_vec();
        let mut framed_suite = suite_bytes;
        framed_suite.push(b'\n');
        // Hash the framed (LF-terminated) bytes, matching every other
        // fixture and what `include_bytes!`/`shasum -a 256` see on disk.
        println!(
            "vector-suite.jsonl raw_sha256={}",
            hex::encode(Sha256::digest(&framed_suite))
        );
        std::fs::write(format!("{dir}vector-suite.jsonl"), &framed_suite).unwrap();
    }
}
