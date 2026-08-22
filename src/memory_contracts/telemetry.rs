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
#[path = "telemetry_tests.rs"]
mod tests;
