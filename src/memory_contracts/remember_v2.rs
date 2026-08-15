//! Canonical claim assertions for the deliberate `remember` boundary.
//!
//! The public values in this module establish byte shape and semantic identity
//! only. In particular, an ingress payload cannot select its authenticated
//! scope, active registry head, actor, accepted-event ID, or physical append
//! location. Registry references, subject URIs, requested admission bases, and
//! support IDs in [`RememberIngressCandidateV2`] are assertions that a later
//! repository must rederive and re-audit against one active-registry witness.
//! That re-audit covers the subject and every applicability resource URI, not
//! merely their canonical string shape.
//!
//! [`RememberAcceptedStatementV2`] remains a public wire contract, not an
//! authority capability. A later repository seam may append only an opaque
//! [`AdmittedRememberStatementV2`] constructed from trusted scope, identity,
//! actor, active-registry, support-event, and admission-rule witnesses in the
//! same transaction. Resource-valued claims require the same exact body
//! resolution and rederivation as subjects and applicability resources. This
//! contract-only module intentionally exposes no
//! production constructor for that typestate.
//!
//! This first seam records immutable assertions only. Correction, supersession,
//! and retraction are deliberately separate future event kinds: each must name
//! an exact prior [`AcceptedEventId`] and prove retirement authority without
//! letting a public record candidate acquire that authority merely by carrying
//! a predecessor field.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use unicode_normalization::UnicodeNormalization;

use super::{
    ContractError, ContractResult,
    bootstrap::ConsistencyPartitionKeyV1,
    canonical::{decode_strict, encode_canonical},
    common::{
        AuthenticatedProjectScopeV1, CanonicalDecimal, CanonicalTimestamp, ContractId,
        ProfileReferenceV1, RegistryReferenceV1,
    },
    digest::{DigestDomain, Sha256Digest, domain_separated_digest},
    evidence::AcceptedEventId,
    evidence_v2::RegistryHeadBindingV1,
    genesis::{
        AbsenceSemanticsV1, PredicateComparatorV1, PropositionModalityV1, PublicationDefaultV1,
        SensitivityDefaultV1,
    },
    identity::ResourceUri,
    registry::{RegistryEntryKind, RegistryEntryV1},
    relation::ConcreteApplicabilityDimensionV1,
};

const REMEMBER_SCHEMA_VERSION: u32 = 2;
const SEMANTIC_CLAIM_SCHEMA_VERSION: u32 = 2;
const REMEMBER_ACCEPTED_EVENT_KIND: &str = "memory.claim.accepted";
const CLAIM_CONSISTENCY_FAMILY: &str = "claim";
const MAX_APPLICABILITY_DIMENSIONS: usize = 64;
const MAX_SUPPORT_EVENT_IDS: usize = 256;
const MAX_STRING_SET_VALUES: usize = 256;
const MAX_CLAIM_TEXT_BYTES: usize = 65_536;
const MAX_ASSERTION_TEXT_BYTES: usize = 100_000;
const ASSERTION_TEXT_CHUNK_BYTES: usize = 32_768;
const MAX_ASSERTION_TEXT_CHUNKS: usize =
    MAX_ASSERTION_TEXT_BYTES.div_ceil(ASSERTION_TEXT_CHUNK_BYTES);
const MAX_ADMISSION_BASIS_RULES: usize = 3;
const PREDICATE_ENTRY_SCHEMA_ID: &str = "registry.predicate_schema";
const ADMISSION_ENTRY_SCHEMA_ID: &str = "registry.remember_admission_rule";

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

digest_newtype!(ClaimCoordinateIdV2);
digest_newtype!(SemanticClaimFingerprintV2);

/// A non-empty, canonical Unicode scalar used only by explicitly string-typed
/// predicates. It cannot carry arbitrary JSON or a second interpretation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CanonicalClaimTextV2(String);

impl CanonicalClaimTextV2 {
    pub fn parse(value: impl Into<String>) -> ContractResult<Self> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_CLAIM_TEXT_BYTES
            || value.trim() != value
            || value.chars().any(char::is_control)
            || encode_canonical(&value).is_err()
        {
            return Err(ContractError::Schema("invalid canonical claim text".into()));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Serialize for CanonicalClaimTextV2 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for CanonicalClaimTextV2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(D::Error::custom)
    }
}

/// Exact authored narrative encoded as deterministic lowercase UTF-8 hex chunks.
///
/// The frozen canonical JSON profile rejects every control scalar in a JSON
/// string after unescaping, and caps one JSON string at 65,536 bytes. Fixed
/// 32,768-byte raw chunks preserve the existing 100,000-byte remember limit,
/// authored LF/TAB bytes, and one wire form without weakening the profile or
/// normalizing platform newlines. Decoded CR, NUL, and all other controls remain
/// forbidden.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CanonicalAssertionTextV2(String);

impl CanonicalAssertionTextV2 {
    pub fn parse(value: impl Into<String>) -> ContractResult<Self> {
        let value = value.into();
        if value.is_empty()
            || value.chars().all(char::is_whitespace)
            || value.len() > MAX_ASSERTION_TEXT_BYTES
            || !value.nfc().eq(value.chars())
            || value.chars().any(is_forbidden_assertion_scalar)
        {
            return Err(ContractError::Schema(
                "invalid exact authored assertion text".into(),
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub const fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl Serialize for CanonicalAssertionTextV2 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.as_bytes()
            .chunks(ASSERTION_TEXT_CHUNK_BYTES)
            .map(hex::encode)
            .collect::<Vec<_>>()
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CanonicalAssertionTextV2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded_chunks = Vec::<String>::deserialize(deserializer)?;
        if encoded_chunks.is_empty() || encoded_chunks.len() > MAX_ASSERTION_TEXT_CHUNKS {
            return Err(D::Error::custom(
                "authored assertion text has an invalid hex chunk count",
            ));
        }
        let mut bytes = Vec::with_capacity(MAX_ASSERTION_TEXT_BYTES);
        for (index, encoded) in encoded_chunks.iter().enumerate() {
            if encoded.is_empty()
                || encoded.len() > ASSERTION_TEXT_CHUNK_BYTES * 2
                || encoded.len() % 2 != 0
                || !encoded
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(D::Error::custom(
                    "authored assertion text requires lowercase UTF-8 hex chunks",
                ));
            }
            let chunk = hex::decode(encoded).map_err(D::Error::custom)?;
            let is_final = index + 1 == encoded_chunks.len();
            if (!is_final && chunk.len() != ASSERTION_TEXT_CHUNK_BYTES)
                || (is_final && chunk.len() > ASSERTION_TEXT_CHUNK_BYTES)
                || bytes.len().saturating_add(chunk.len()) > MAX_ASSERTION_TEXT_BYTES
            {
                return Err(D::Error::custom(
                    "authored assertion text is not canonically chunked",
                ));
            }
            bytes.extend_from_slice(&chunk);
        }
        let value = String::from_utf8(bytes).map_err(D::Error::custom)?;
        Self::parse(value).map_err(D::Error::custom)
    }
}

/// Closed, explicitly tagged claim values.
///
/// There is deliberately no `null`, floating-point, untagged number, array,
/// object, or generic JSON variant. Predicate closure in the active registry
/// must additionally prove that this tag matches the exact predicate schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CanonicalClaimValueV2 {
    Boolean { value: bool },
    CanonicalDecimal { value: CanonicalDecimal },
    ContractId { value: ContractId },
    ResourceUri { value: ResourceUri },
    Sha256Digest { value: Sha256Digest },
    String { value: CanonicalClaimTextV2 },
    StringSet { values: Vec<CanonicalClaimTextV2> },
}

impl CanonicalClaimValueV2 {
    fn validate(&self) -> ContractResult<()> {
        if let Self::ResourceUri { value } = self
            && value.digest() == Sha256Digest::ZERO
        {
            return Err(ContractError::Schema(
                "claim resource value cannot use the zero digest".into(),
            ));
        }
        if let Self::StringSet { values } = self
            && (values.is_empty()
                || values.len() > MAX_STRING_SET_VALUES
                || !strictly_sorted_claim_text(values))
        {
            return Err(ContractError::NonCanonicalSet {
                field: "claim.value.string_set",
            });
        }
        // This rechecks the canonical string scalar rules and total output
        // bound even for values constructed directly rather than deserialized.
        encode_canonical(self)?;
        Ok(())
    }
}

/// Exact truth direction; the old `-1`/`1` scalar is not accepted here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimPolarityV2 {
    Affirms,
    Negates,
}

/// Closed projection kinds supported by the canonical v2 assertion seam.
///
/// Legacy `observation` belongs in evidence v2; free-form `note` and
/// `open_question` need distinct non-proposition contracts. They are therefore
/// rejected by deserialization rather than being silently coerced here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RememberAssertionKindV2 {
    Decision,
    Fact,
    Constraint,
    Preference,
    Procedure,
}

/// Exact active-registry identity closure for one resource-valued coordinate.
///
/// Both references must be resolved from the same active package. The active
/// resolver must additionally prove that the identity recipe embeds this exact
/// resource-kind-schema reference before rederiving a URI.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceIdentityConstraintV2 {
    pub resource_kind_schema: RegistryReferenceV1,
    pub identity_recipe: RegistryReferenceV1,
}

impl ResourceIdentityConstraintV2 {
    pub fn validate_shape(&self) -> ContractResult<()> {
        validate_registry_reference(&self.resource_kind_schema)?;
        validate_registry_reference(&self.identity_recipe)
    }

    /// Preliminary entry-ID agreement only, never identity proof.
    ///
    /// Active closure must resolve the exact resource-kind and identity-recipe
    /// bodies, prove the recipe embeds this kind/form, obtain a trusted locator
    /// witness, and rederive the URI.
    fn accepts_uri_shape(&self, resource: &ResourceUri) -> bool {
        resource.digest() != Sha256Digest::ZERO
            && resource.resource_kind() == &self.resource_kind_schema.entry_id
    }
}

/// Registry-defined identity closure for one applicability dimension.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicabilityDimensionRuleV2 {
    pub dimension_id: ContractId,
    pub resource_identity: ResourceIdentityConstraintV2,
    pub required: bool,
}

impl ApplicabilityDimensionRuleV2 {
    fn validate_shape(&self) -> ContractResult<()> {
        self.resource_identity.validate_shape()
    }
}

/// Closed value schema for one remember predicate.
///
/// Resource-valued predicates carry the exact kind/recipe closure needed to
/// rederive their value URI. Other variants admit no alternate JSON shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RememberValueConstraintV2 {
    Boolean {
        unit_id: ContractId,
    },
    CanonicalDecimal {
        unit_id: ContractId,
    },
    ContractId,
    ResourceUri {
        resource_identity: ResourceIdentityConstraintV2,
    },
    Sha256Digest,
    String {
        maximum_utf8_bytes: u32,
    },
    StringSet {
        maximum_values: u16,
        maximum_each_utf8_bytes: u32,
    },
}

impl RememberValueConstraintV2 {
    fn validate_shape(&self) -> ContractResult<()> {
        match self {
            Self::ResourceUri { resource_identity } => resource_identity.validate_shape()?,
            Self::String { maximum_utf8_bytes } => {
                if *maximum_utf8_bytes == 0
                    || usize::try_from(*maximum_utf8_bytes).unwrap_or(usize::MAX)
                        > MAX_CLAIM_TEXT_BYTES
                {
                    return Err(ContractError::Schema(
                        "invalid remember string value limit".into(),
                    ));
                }
            }
            Self::StringSet {
                maximum_values,
                maximum_each_utf8_bytes,
            } => {
                if *maximum_values == 0
                    || usize::from(*maximum_values) > MAX_STRING_SET_VALUES
                    || *maximum_each_utf8_bytes == 0
                    || usize::try_from(*maximum_each_utf8_bytes).unwrap_or(usize::MAX)
                        > MAX_CLAIM_TEXT_BYTES
                {
                    return Err(ContractError::Schema(
                        "invalid remember string-set value limits".into(),
                    ));
                }
            }
            Self::Boolean { .. }
            | Self::CanonicalDecimal { .. }
            | Self::ContractId
            | Self::Sha256Digest => {}
        }
        Ok(())
    }

    fn accepts_value_shape(&self, value: &CanonicalClaimValueV2) -> bool {
        match (self, value) {
            (Self::Boolean { .. }, CanonicalClaimValueV2::Boolean { .. })
            | (Self::CanonicalDecimal { .. }, CanonicalClaimValueV2::CanonicalDecimal { .. })
            | (Self::ContractId, CanonicalClaimValueV2::ContractId { .. })
            | (Self::Sha256Digest, CanonicalClaimValueV2::Sha256Digest { .. }) => true,
            (
                Self::ResourceUri { resource_identity },
                CanonicalClaimValueV2::ResourceUri { value },
            ) => resource_identity.accepts_uri_shape(value),
            (Self::String { maximum_utf8_bytes }, CanonicalClaimValueV2::String { value }) => {
                value.as_str().len() <= usize::try_from(*maximum_utf8_bytes).unwrap_or(0)
            }
            (
                Self::StringSet {
                    maximum_values,
                    maximum_each_utf8_bytes,
                },
                CanonicalClaimValueV2::StringSet { values },
            ) => {
                values.len() <= usize::from(*maximum_values)
                    && values.iter().all(|value| {
                        value.as_str().len()
                            <= usize::try_from(*maximum_each_utf8_bytes).unwrap_or(0)
                    })
            }
            _ => false,
        }
    }
}

/// Predicate body required by the active remember admission resolver.
///
/// This is package-dependency scaffolding, not activation authority. Until a
/// successor package verifier accepts this exact schema version and constructs
/// an active typestate, public bodies and references remain assertions only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RememberPredicateSchemaV2 {
    pub schema_version: u32,
    pub predicate_id: ContractId,
    pub version: u32,
    pub subject_identity: ResourceIdentityConstraintV2,
    pub value_constraint: RememberValueConstraintV2,
    pub comparator: PredicateComparatorV1,
    pub allowed_modalities: Vec<PropositionModalityV1>,
    pub applicability_evaluator: RegistryReferenceV1,
    pub applicability_dimensions: Vec<ApplicabilityDimensionRuleV2>,
    pub absence_semantics: AbsenceSemanticsV1,
    pub coverage_proof: Option<RegistryReferenceV1>,
    pub publication_default: PublicationDefaultV1,
    pub sensitivity_default: SensitivityDefaultV1,
}

impl RememberPredicateSchemaV2 {
    pub fn validate_shape(&self) -> ContractResult<()> {
        self.subject_identity.validate_shape()?;
        self.value_constraint.validate_shape()?;
        validate_registry_reference(&self.applicability_evaluator)?;
        let absence_is_closed = matches!(
            self.absence_semantics,
            AbsenceSemanticsV1::ClosedWorldWithCoverage
        );
        if let Some(coverage_proof) = &self.coverage_proof {
            validate_registry_reference(coverage_proof)?;
        }
        let comparator_matches = match self.comparator {
            PredicateComparatorV1::NumericThreshold => {
                matches!(
                    self.value_constraint,
                    RememberValueConstraintV2::CanonicalDecimal { .. }
                )
            }
            PredicateComparatorV1::SetEquality => {
                matches!(
                    self.value_constraint,
                    RememberValueConstraintV2::StringSet { .. }
                )
            }
            PredicateComparatorV1::ExactEquality => true,
        };
        if self.schema_version != REMEMBER_SCHEMA_VERSION
            || self.version == 0
            || self.allowed_modalities.is_empty()
            || !strictly_sorted(&self.allowed_modalities)
            || self.applicability_dimensions.is_empty()
            || self.applicability_dimensions.len() > MAX_APPLICABILITY_DIMENSIONS
            || !strictly_sorted_by_dimension_rule(&self.applicability_dimensions)
            || !self
                .applicability_dimensions
                .iter()
                .any(|dimension| dimension.required)
            || absence_is_closed != self.coverage_proof.is_some()
            || !comparator_matches
        {
            return Err(ContractError::Schema(
                "invalid remember predicate schema v2".into(),
            ));
        }
        for dimension in &self.applicability_dimensions {
            dimension.validate_shape()?;
        }
        encode_canonical(self)?;
        Ok(())
    }
}

/// Exact interval admission semantics resolved from the active rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct RememberEffectiveIntervalRuleV2 {
    pub payload_may_select_effective_from: bool,
    pub past_effective_from_allowed: bool,
    pub future_effective_from_allowed: bool,
    pub open_ended_interval_allowed: bool,
    pub bounded_interval_allowed: bool,
    pub microsecond_alignment_required: bool,
}

impl RememberEffectiveIntervalRuleV2 {
    fn validate_shape(&self) -> ContractResult<()> {
        if !self.payload_may_select_effective_from
            || !self.microsecond_alignment_required
            || (!self.open_ended_interval_allowed && !self.bounded_interval_allowed)
        {
            return Err(ContractError::Schema(
                "invalid remember effective-interval rule".into(),
            ));
        }
        Ok(())
    }
}

/// Closed admission requirements for each supported basis.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RememberAdmissionBasisRuleV2 {
    AuthenticatedActor {
        allowed_modalities: Vec<PropositionModalityV1>,
        maximum_support_events: u16,
    },
    RegisteredObserver {
        observer_admission: RegistryReferenceV1,
        observer_result_event_schema: RegistryReferenceV1,
        allowed_modalities: Vec<PropositionModalityV1>,
        minimum_support_events: u16,
        maximum_support_events: u16,
        same_scope_required: bool,
        same_registry_head_required: bool,
        exact_observer_reference_required: bool,
        exact_claim_output_required: bool,
        coverage_reaudit_required: bool,
    },
    ActivatedNormativeBinding {
        binding_schema: RegistryReferenceV1,
        allowed_modalities: Vec<PropositionModalityV1>,
        maximum_support_events: u16,
        exact_statement_required: bool,
        same_scope_required: bool,
        same_registry_head_required: bool,
    },
}

impl RememberAdmissionBasisRuleV2 {
    fn allowed_modalities(&self) -> &[PropositionModalityV1] {
        match self {
            Self::AuthenticatedActor {
                allowed_modalities, ..
            }
            | Self::RegisteredObserver {
                allowed_modalities, ..
            }
            | Self::ActivatedNormativeBinding {
                allowed_modalities, ..
            } => allowed_modalities,
        }
    }

    fn validate_shape(&self) -> ContractResult<()> {
        let (modalities, minimum_support, maximum_support, fail_closed) = match self {
            Self::AuthenticatedActor {
                allowed_modalities,
                maximum_support_events,
            } => (allowed_modalities, 0, *maximum_support_events, true),
            Self::RegisteredObserver {
                observer_admission,
                observer_result_event_schema,
                allowed_modalities,
                minimum_support_events,
                maximum_support_events,
                same_scope_required,
                same_registry_head_required,
                exact_observer_reference_required,
                exact_claim_output_required,
                coverage_reaudit_required,
            } => {
                validate_registry_reference(observer_admission)?;
                validate_registry_reference(observer_result_event_schema)?;
                (
                    allowed_modalities,
                    *minimum_support_events,
                    *maximum_support_events,
                    *same_scope_required
                        && *same_registry_head_required
                        && *exact_observer_reference_required
                        && *exact_claim_output_required
                        && *coverage_reaudit_required,
                )
            }
            Self::ActivatedNormativeBinding {
                binding_schema,
                allowed_modalities,
                maximum_support_events,
                exact_statement_required,
                same_scope_required,
                same_registry_head_required,
            } => {
                validate_registry_reference(binding_schema)?;
                (
                    allowed_modalities,
                    0,
                    *maximum_support_events,
                    *exact_statement_required
                        && *same_scope_required
                        && *same_registry_head_required,
                )
            }
        };
        let modalities_match_basis = match self {
            Self::AuthenticatedActor { .. } => modalities.iter().all(|modality| {
                matches!(
                    modality,
                    PropositionModalityV1::Attested | PropositionModalityV1::Intended
                )
            }),
            Self::RegisteredObserver { .. } => modalities
                .iter()
                .all(|modality| *modality == PropositionModalityV1::Observed),
            Self::ActivatedNormativeBinding { .. } => modalities
                .iter()
                .all(|modality| *modality == PropositionModalityV1::Normative),
        };
        if modalities.is_empty()
            || !strictly_sorted(modalities)
            || !modalities_match_basis
            || usize::from(maximum_support) > MAX_SUPPORT_EVENT_IDS
            || minimum_support > maximum_support
            || matches!(self, Self::RegisteredObserver { .. }) && minimum_support == 0
            || !fail_closed
        {
            return Err(ContractError::Schema(
                "invalid remember admission basis rule".into(),
            ));
        }
        Ok(())
    }

    fn matches_basis(
        &self,
        basis: &RememberAdmissionBasisV2,
        modality: PropositionModalityV1,
        support_count: usize,
    ) -> bool {
        let (modalities, minimum_support, maximum_support, reference_matches) = match (self, basis)
        {
            (
                Self::AuthenticatedActor {
                    allowed_modalities,
                    maximum_support_events,
                },
                RememberAdmissionBasisV2::AuthenticatedActor,
            ) => (allowed_modalities, 0, *maximum_support_events, true),
            (
                Self::RegisteredObserver {
                    observer_admission: expected,
                    allowed_modalities,
                    minimum_support_events,
                    maximum_support_events,
                    ..
                },
                RememberAdmissionBasisV2::RegisteredObserver { observer_admission },
            ) => (
                allowed_modalities,
                *minimum_support_events,
                *maximum_support_events,
                expected == observer_admission,
            ),
            (
                Self::ActivatedNormativeBinding {
                    binding_schema: expected,
                    allowed_modalities,
                    maximum_support_events,
                    ..
                },
                RememberAdmissionBasisV2::ActivatedNormativeBinding { binding_schema, .. },
            ) => (
                allowed_modalities,
                0,
                *maximum_support_events,
                expected == binding_schema,
            ),
            _ => return false,
        };
        reference_matches
            && modalities.contains(&modality)
            && support_count >= usize::from(minimum_support)
            && support_count <= usize::from(maximum_support)
    }
}

/// Active-package body that closes remember admission and governance.
///
/// Deserializing this body grants no authority. A successor package verifier
/// must resolve every reference, verify this exact schema, and construct the
/// repository's active admission typestate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct RememberAdmissionRuleV2 {
    pub schema_version: u32,
    pub rule_id: ContractId,
    pub version: u32,
    pub predicate_schema: RegistryReferenceV1,
    pub applicability_evaluator: RegistryReferenceV1,
    pub allowed_assertion_kinds: Vec<RememberAssertionKindV2>,
    pub basis_rules: Vec<RememberAdmissionBasisRuleV2>,
    pub effective_interval_rule: RememberEffectiveIntervalRuleV2,
    pub classifier_policy: RegistryReferenceV1,
    pub redaction_policy: RegistryReferenceV1,
    pub retention_policy: RegistryReferenceV1,
    pub publication_rule: RegistryReferenceV1,
    pub maximum_assertion_text_utf8_bytes: u32,
    pub authenticated_scope_required: bool,
    pub resource_rederivation_required: bool,
    pub support_event_reaudit_required: bool,
    pub server_derived_governance_required: bool,
    pub registered_observer_append_enabled: bool,
    pub normative_binding_append_enabled: bool,
    pub payload_may_select_actor: bool,
    pub payload_may_select_scope: bool,
    pub payload_may_select_registry_head: bool,
    pub payload_may_select_admission_rule: bool,
    pub payload_may_select_admission_outcome: bool,
}

impl RememberAdmissionRuleV2 {
    pub fn validate_shape(&self) -> ContractResult<()> {
        validate_registry_reference(&self.predicate_schema)?;
        validate_registry_reference(&self.applicability_evaluator)?;
        validate_registry_reference(&self.classifier_policy)?;
        validate_registry_reference(&self.redaction_policy)?;
        validate_registry_reference(&self.retention_policy)?;
        validate_registry_reference(&self.publication_rule)?;
        self.effective_interval_rule.validate_shape()?;
        if self.schema_version != REMEMBER_SCHEMA_VERSION
            || self.version == 0
            || self.allowed_assertion_kinds.is_empty()
            || !strictly_sorted(&self.allowed_assertion_kinds)
            || self.basis_rules.is_empty()
            || self.basis_rules.len() > MAX_ADMISSION_BASIS_RULES
            || !strictly_sorted(&self.basis_rules)
            || !basis_rule_keys_are_unique(&self.basis_rules)
            || self.maximum_assertion_text_utf8_bytes == 0
            || usize::try_from(self.maximum_assertion_text_utf8_bytes).unwrap_or(usize::MAX)
                > MAX_ASSERTION_TEXT_BYTES
            || !self.authenticated_scope_required
            || !self.resource_rederivation_required
            || !self.support_event_reaudit_required
            || !self.server_derived_governance_required
            || self.registered_observer_append_enabled
            || self.normative_binding_append_enabled
            || self.payload_may_select_actor
            || self.payload_may_select_scope
            || self.payload_may_select_registry_head
            || self.payload_may_select_admission_rule
            || self.payload_may_select_admission_outcome
        {
            return Err(ContractError::Schema(
                "invalid remember admission rule v2".into(),
            ));
        }
        for basis_rule in &self.basis_rules {
            basis_rule.validate_shape()?;
        }
        encode_canonical(self)?;
        Ok(())
    }
}

/// Exact semantic time interval. Receipt and append clocks are separate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimEffectiveIntervalV2 {
    pub effective_from: CanonicalTimestamp,
    pub effective_until: Option<CanonicalTimestamp>,
}

impl ClaimEffectiveIntervalV2 {
    fn validate(&self) -> ContractResult<()> {
        if !self.effective_from.is_microsecond_aligned()
            || self.effective_until.as_ref().is_some_and(|until| {
                !until.is_microsecond_aligned() || until <= &self.effective_from
            })
        {
            return Err(ContractError::Schema(
                "invalid claim effective interval".into(),
            ));
        }
        Ok(())
    }
}

/// Requested or admitted semantic source of a remember assertion.
///
/// In an ingress candidate each variant is only a request. In an accepted
/// statement a later repository must prove the exact active reference or
/// normative statement before creating the opaque admitted typestate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RememberAdmissionBasisV2 {
    AuthenticatedActor,
    RegisteredObserver {
        observer_admission: RegistryReferenceV1,
    },
    ActivatedNormativeBinding {
        binding_schema: RegistryReferenceV1,
        binding_statement_id: Sha256Digest,
    },
}

impl RememberAdmissionBasisV2 {
    fn validate_for_modality(&self, modality: PropositionModalityV1) -> ContractResult<()> {
        let valid = match self {
            Self::AuthenticatedActor => matches!(
                modality,
                PropositionModalityV1::Attested | PropositionModalityV1::Intended
            ),
            Self::RegisteredObserver { observer_admission } => {
                validate_registry_reference(observer_admission)?;
                modality == PropositionModalityV1::Observed
            }
            Self::ActivatedNormativeBinding {
                binding_schema,
                binding_statement_id,
            } => {
                validate_registry_reference(binding_schema)?;
                *binding_statement_id != Sha256Digest::ZERO
                    && modality == PropositionModalityV1::Normative
            }
        };
        if !valid {
            return Err(ContractError::Schema(
                "claim admission basis does not match modality".into(),
            ));
        }
        Ok(())
    }
}

/// Public, authority-free input to the deliberate remember boundary.
///
/// The subject URI, references, basis, and support IDs are assertions only.
/// Trusted runtime code must rederive the subject from an activated identity
/// witness, resolve every reference from the exact active package, and re-audit
/// every applicability/value identity and support event before materializing
/// an accepted statement. Its admission-rule reference is compare-only after
/// the server routes to one unique active rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RememberIngressCandidateV2 {
    pub schema_version: u32,
    pub asserted_subject: ResourceUri,
    pub subject_identity_recipe: RegistryReferenceV1,
    pub predicate_schema: RegistryReferenceV1,
    pub applicability_evaluator: RegistryReferenceV1,
    pub admission_rule: RegistryReferenceV1,
    pub assertion_kind: RememberAssertionKindV2,
    pub assertion_text_utf8_hex_chunks: CanonicalAssertionTextV2,
    pub modality: PropositionModalityV1,
    pub polarity: ClaimPolarityV2,
    pub value: CanonicalClaimValueV2,
    pub applicability: Vec<ConcreteApplicabilityDimensionV1>,
    pub effective_interval: ClaimEffectiveIntervalV2,
    pub requested_basis: RememberAdmissionBasisV2,
    pub support_evidence_event_ids: Vec<AcceptedEventId>,
}

impl RememberIngressCandidateV2 {
    /// Validate canonical public shape only; this grants no admission authority.
    pub fn validate_shape(&self) -> ContractResult<()> {
        validate_registry_reference(&self.subject_identity_recipe)?;
        validate_registry_reference(&self.predicate_schema)?;
        validate_registry_reference(&self.applicability_evaluator)?;
        validate_registry_reference(&self.admission_rule)?;
        self.value.validate()?;
        self.effective_interval.validate()?;
        self.requested_basis.validate_for_modality(self.modality)?;
        if self.schema_version != REMEMBER_SCHEMA_VERSION
            || self.asserted_subject.digest() == Sha256Digest::ZERO
            || self.applicability.is_empty()
            || self.applicability.len() > MAX_APPLICABILITY_DIMENSIONS
            || !strictly_sorted_by_dimension(&self.applicability)
            || self
                .applicability
                .iter()
                .any(|dimension| dimension.resource.digest() == Sha256Digest::ZERO)
            || self.support_evidence_event_ids.len() > MAX_SUPPORT_EVENT_IDS
            || !strictly_sorted(&self.support_evidence_event_ids)
            || self
                .support_evidence_event_ids
                .iter()
                .any(|event_id| event_id.digest() == Sha256Digest::ZERO)
            || basis_requires_support(&self.requested_basis)
                && self.support_evidence_event_ids.is_empty()
        {
            return Err(ContractError::Schema(
                "invalid remember ingress candidate".into(),
            ));
        }
        encode_canonical(self)?;
        Ok(())
    }
}

/// Structurally closed remember package dependencies.
///
/// This is not an active-registry witness. Any caller can construct registry
/// entries. A successor package verifier must additionally prove that both
/// exact entries are members of the same active package and that the admission
/// entry is the unique server-routed rule for the trusted scope, predicate,
/// and basis. The candidate's admission reference is compare-only.
#[derive(Debug)]
pub struct StructurallyResolvedRememberContractsV2 {
    predicate_reference: RegistryReferenceV1,
    predicate: RememberPredicateSchemaV2,
    admission_reference: RegistryReferenceV1,
    admission: RememberAdmissionRuleV2,
}

impl StructurallyResolvedRememberContractsV2 {
    /// Resolve two exact registry-entry preimages without granting authority.
    pub fn from_registry_entries(
        predicate_entry: &RegistryEntryV1,
        admission_entry: &RegistryEntryV1,
    ) -> ContractResult<Self> {
        predicate_entry.validate()?;
        admission_entry.validate()?;
        if predicate_entry.kind != RegistryEntryKind::PredicateSchema
            || predicate_entry.entry_schema_id.as_str() != PREDICATE_ENTRY_SCHEMA_ID
            || predicate_entry.entry_schema_version != REMEMBER_SCHEMA_VERSION
            || admission_entry.kind != RegistryEntryKind::AuthorityRule
            || admission_entry.entry_schema_id.as_str() != ADMISSION_ENTRY_SCHEMA_ID
            || admission_entry.entry_schema_version != REMEMBER_SCHEMA_VERSION
        {
            return Err(ContractError::Schema(
                "registry entries are not remember v2 dependency bodies".into(),
            ));
        }
        let predicate: RememberPredicateSchemaV2 =
            decode_strict(&encode_canonical(&predicate_entry.body)?)?;
        let admission: RememberAdmissionRuleV2 =
            decode_strict(&encode_canonical(&admission_entry.body)?)?;
        predicate.validate_shape()?;
        admission.validate_shape()?;
        let predicate_reference = registry_reference_for_entry(predicate_entry)?;
        let admission_reference = registry_reference_for_entry(admission_entry)?;
        let basis_modalities_fit_predicate = admission.basis_rules.iter().all(|basis_rule| {
            basis_rule
                .allowed_modalities()
                .iter()
                .all(|modality| predicate.allowed_modalities.contains(modality))
        });
        let predicate_id_matches = predicate.predicate_id == predicate_entry.entry_id;
        let predicate_version_matches = predicate.version == predicate_entry.version;
        let admission_id_matches = admission.rule_id == admission_entry.entry_id;
        let admission_version_matches = admission.version == admission_entry.version;
        if !predicate_id_matches
            || !predicate_version_matches
            || !admission_id_matches
            || !admission_version_matches
            || admission.predicate_schema != predicate_reference
            || admission.applicability_evaluator != predicate.applicability_evaluator
            || !basis_modalities_fit_predicate
        {
            return Err(ContractError::ManifestMismatch);
        }
        Ok(Self {
            predicate_reference,
            predicate,
            admission_reference,
            admission,
        })
    }

    pub const fn predicate_reference(&self) -> &RegistryReferenceV1 {
        &self.predicate_reference
    }

    pub const fn admission_reference(&self) -> &RegistryReferenceV1 {
        &self.admission_reference
    }

    pub const fn predicate(&self) -> &RememberPredicateSchemaV2 {
        &self.predicate
    }

    pub const fn admission(&self) -> &RememberAdmissionRuleV2 {
        &self.admission
    }

    /// Validate candidate fields against already-resolved body semantics.
    ///
    /// This still does not rederive resource URIs or re-audit support events;
    /// the active repository must do both before constructing append authority.
    pub fn validate_candidate_shape(
        &self,
        candidate: &RememberIngressCandidateV2,
    ) -> ContractResult<()> {
        candidate.validate_shape()?;
        let references_match = candidate.predicate_schema == self.predicate_reference
            && candidate.admission_rule == self.admission_reference
            && candidate.applicability_evaluator == self.predicate.applicability_evaluator
            && candidate.applicability_evaluator == self.admission.applicability_evaluator
            && self.admission.predicate_schema == self.predicate_reference
            && candidate.subject_identity_recipe == self.predicate.subject_identity.identity_recipe;
        let interval_allowed = if candidate.effective_interval.effective_until.is_some() {
            self.admission
                .effective_interval_rule
                .bounded_interval_allowed
        } else {
            self.admission
                .effective_interval_rule
                .open_ended_interval_allowed
        };
        let basis_path_enabled = match &candidate.requested_basis {
            RememberAdmissionBasisV2::AuthenticatedActor => true,
            RememberAdmissionBasisV2::RegisteredObserver { .. } => {
                self.admission.registered_observer_append_enabled
            }
            RememberAdmissionBasisV2::ActivatedNormativeBinding { .. } => {
                self.admission.normative_binding_append_enabled
            }
        };
        let basis_allowed = basis_path_enabled
            && self.admission.basis_rules.iter().any(|rule| {
                rule.matches_basis(
                    &candidate.requested_basis,
                    candidate.modality,
                    candidate.support_evidence_event_ids.len(),
                )
            });
        if !references_match
            || !self
                .predicate
                .subject_identity
                .accepts_uri_shape(&candidate.asserted_subject)
            || !self
                .predicate
                .value_constraint
                .accepts_value_shape(&candidate.value)
            || !self
                .predicate
                .allowed_modalities
                .contains(&candidate.modality)
            || !self
                .admission
                .allowed_assertion_kinds
                .contains(&candidate.assertion_kind)
            || candidate.assertion_text_utf8_hex_chunks.as_bytes().len()
                > usize::try_from(self.admission.maximum_assertion_text_utf8_bytes).unwrap_or(0)
            || !interval_allowed
            || !basis_allowed
            || !applicability_matches_rules(
                &candidate.applicability,
                &self.predicate.applicability_dimensions,
            )
        {
            return Err(ContractError::Schema(
                "remember candidate does not match structurally resolved active bodies".into(),
            ));
        }
        Ok(())
    }
}

/// The exact proposition shared by independent actors and evidence paths.
///
/// The active-head binding is deliberately identity-bearing and ABA-safe. The
/// actor, admission rule/basis, and supporting events are attestation semantics
/// and therefore live in [`RememberAcceptedStatementV2`] instead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticClaimV2 {
    pub schema_version: u32,
    pub profile: ProfileReferenceV1,
    pub scope: AuthenticatedProjectScopeV1,
    pub registry: RegistryHeadBindingV1,
    pub subject: ResourceUri,
    pub subject_identity_recipe: RegistryReferenceV1,
    pub predicate_schema: RegistryReferenceV1,
    pub applicability_evaluator: RegistryReferenceV1,
    pub assertion_kind: RememberAssertionKindV2,
    pub modality: PropositionModalityV1,
    pub polarity: ClaimPolarityV2,
    pub value: CanonicalClaimValueV2,
    pub applicability: Vec<ConcreteApplicabilityDimensionV1>,
    pub effective_interval: ClaimEffectiveIntervalV2,
}

impl SemanticClaimV2 {
    /// Validate byte shape and exact frozen-profile binding only.
    ///
    /// This cannot prove that `registry` is active or that `subject` was
    /// derived by the named recipe. Those are repository admission witnesses.
    pub fn validate_shape(&self) -> ContractResult<()> {
        self.profile.require_frozen_runtime_profile()?;
        self.registry.validate_shape()?;
        validate_registry_reference(&self.subject_identity_recipe)?;
        validate_registry_reference(&self.predicate_schema)?;
        validate_registry_reference(&self.applicability_evaluator)?;
        self.value.validate()?;
        self.effective_interval.validate()?;
        if self.schema_version != SEMANTIC_CLAIM_SCHEMA_VERSION
            || self.subject.digest() == Sha256Digest::ZERO
            || self.applicability.is_empty()
            || self.applicability.len() > MAX_APPLICABILITY_DIMENSIONS
            || !strictly_sorted_by_dimension(&self.applicability)
            || self
                .applicability
                .iter()
                .any(|dimension| dimension.resource.digest() == Sha256Digest::ZERO)
        {
            return Err(ContractError::Schema("invalid semantic claim".into()));
        }
        encode_canonical(self)?;
        Ok(())
    }

    /// Exact semantic proposition identity under the shared v2 claim domain.
    pub fn fingerprint(&self) -> ContractResult<SemanticClaimFingerprintV2> {
        self.validate_shape()?;
        Ok(SemanticClaimFingerprintV2::from_digest(
            domain_separated_digest(
                DigestDomain::RememberSemanticClaimV2,
                &encode_canonical(self)?,
            ),
        ))
    }

    /// Conflict/replay serialization coordinate.
    ///
    /// Value, polarity, modality, effective interval, actor, support, and the
    /// entire active-head binding are intentionally absent, so competing and
    /// overlapping assertions cannot escape to different logical streams.
    /// Exact profile, scope, subject/recipe, predicate, evaluator, and
    /// applicability remain.
    pub fn coordinate(&self) -> ClaimCoordinateV2 {
        ClaimCoordinateV2 {
            schema_version: SEMANTIC_CLAIM_SCHEMA_VERSION,
            profile: self.profile.clone(),
            scope: self.scope.clone(),
            subject: self.subject.clone(),
            subject_identity_recipe: self.subject_identity_recipe.clone(),
            predicate_schema: self.predicate_schema.clone(),
            applicability_evaluator: self.applicability_evaluator.clone(),
            applicability: self.applicability.clone(),
        }
    }

    pub fn consistency_partition_key(&self) -> ContractResult<ConsistencyPartitionKeyV1> {
        Ok(ConsistencyPartitionKeyV1 {
            family: ContractId::new(CLAIM_CONSISTENCY_FAMILY)?,
            key_digest: self.coordinate().coordinate_id()?.digest(),
        })
    }
}

/// Exact logical conflict coordinate, derived from a semantic claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimCoordinateV2 {
    pub schema_version: u32,
    pub profile: ProfileReferenceV1,
    pub scope: AuthenticatedProjectScopeV1,
    pub subject: ResourceUri,
    pub subject_identity_recipe: RegistryReferenceV1,
    pub predicate_schema: RegistryReferenceV1,
    pub applicability_evaluator: RegistryReferenceV1,
    pub applicability: Vec<ConcreteApplicabilityDimensionV1>,
}

impl ClaimCoordinateV2 {
    pub fn validate_shape(&self) -> ContractResult<()> {
        self.profile.require_frozen_runtime_profile()?;
        validate_registry_reference(&self.subject_identity_recipe)?;
        validate_registry_reference(&self.predicate_schema)?;
        validate_registry_reference(&self.applicability_evaluator)?;
        if self.schema_version != SEMANTIC_CLAIM_SCHEMA_VERSION
            || self.subject.digest() == Sha256Digest::ZERO
            || self.applicability.is_empty()
            || self.applicability.len() > MAX_APPLICABILITY_DIMENSIONS
            || !strictly_sorted_by_dimension(&self.applicability)
            || self
                .applicability
                .iter()
                .any(|dimension| dimension.resource.digest() == Sha256Digest::ZERO)
        {
            return Err(ContractError::Schema(
                "invalid claim consistency coordinate".into(),
            ));
        }
        encode_canonical(self)?;
        Ok(())
    }

    pub fn coordinate_id(&self) -> ContractResult<ClaimCoordinateIdV2> {
        self.validate_shape()?;
        Ok(ClaimCoordinateIdV2::from_digest(domain_separated_digest(
            DigestDomain::RememberClaimCoordinateV2,
            &encode_canonical(self)?,
        )))
    }
}

/// Server-bound actor identity. This value is descriptive until trusted
/// admission proves it from credential context; ingress has no actor field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RememberActorV2 {
    pub principal_id: ContractId,
}

/// Immutable accepted-event preimage for one admitted remember assertion.
///
/// It contains no claim row ID, support row ID, idempotency key, receipt clock,
/// storage locator, epoch, shard, offset, or append-chain field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RememberAcceptedStatementV2 {
    pub schema_version: u32,
    pub event_kind: ContractId,
    pub profile: ProfileReferenceV1,
    pub scope: AuthenticatedProjectScopeV1,
    pub registry: RegistryHeadBindingV1,
    pub claim: SemanticClaimV2,
    pub claim_fingerprint: SemanticClaimFingerprintV2,
    pub assertion_text_utf8_hex_chunks: CanonicalAssertionTextV2,
    pub actor: RememberActorV2,
    pub admission_rule: RegistryReferenceV1,
    pub admission_basis: RememberAdmissionBasisV2,
    pub support_evidence_event_ids: Vec<AcceptedEventId>,
}

impl RememberAcceptedStatementV2 {
    /// Validate structural bindings only. This does not admit the statement.
    pub fn validate_shape(&self) -> ContractResult<()> {
        self.profile.require_frozen_runtime_profile()?;
        self.registry.validate_shape()?;
        self.claim.validate_shape()?;
        validate_registry_reference(&self.admission_rule)?;
        self.admission_basis
            .validate_for_modality(self.claim.modality)?;
        if self.schema_version != REMEMBER_SCHEMA_VERSION
            || self.event_kind.as_str() != REMEMBER_ACCEPTED_EVENT_KIND
            || self.profile != self.claim.profile
            || self.scope != self.claim.scope
            || self.registry != self.claim.registry
            || self.claim_fingerprint != self.claim.fingerprint()?
            || self.support_evidence_event_ids.len() > MAX_SUPPORT_EVENT_IDS
            || !strictly_sorted(&self.support_evidence_event_ids)
            || self
                .support_evidence_event_ids
                .iter()
                .any(|event_id| event_id.digest() == Sha256Digest::ZERO)
            || basis_requires_support(&self.admission_basis)
                && self.support_evidence_event_ids.is_empty()
        {
            return Err(ContractError::Schema(
                "invalid accepted remember statement".into(),
            ));
        }
        encode_canonical(self)?;
        Ok(())
    }

    /// Semantic accepted-event identity. Receipt and append metadata cannot
    /// affect it because those values are not fields in this preimage.
    pub fn accepted_event_id(&self) -> ContractResult<AcceptedEventId> {
        self.validate_shape()?;
        Ok(AcceptedEventId::from_digest(domain_separated_digest(
            DigestDomain::AcceptedEvent,
            &encode_canonical(self)?,
        )))
    }

    pub fn consistency_partition_key(&self) -> ContractResult<ConsistencyPartitionKeyV1> {
        self.claim.consistency_partition_key()
    }
}

/// Opaque authority capability consumed by the future append repository.
///
/// No production constructor exists in this contract-only stage. Deserializing
/// or structurally validating [`RememberAcceptedStatementV2`] cannot create it.
#[derive(Debug)]
pub struct AdmittedRememberStatementV2 {
    statement: RememberAcceptedStatementV2,
}

impl AdmittedRememberStatementV2 {
    pub const fn statement(&self) -> &RememberAcceptedStatementV2 {
        &self.statement
    }

    #[cfg(test)]
    fn from_test_witness(statement: RememberAcceptedStatementV2) -> ContractResult<Self> {
        statement.validate_shape()?;
        Ok(Self { statement })
    }
}

fn is_forbidden_assertion_scalar(value: char) -> bool {
    let code = u32::from(value);
    (value.is_control() && !matches!(value, '\n' | '\t'))
        || value == '\u{feff}'
        || (0xfdd0..=0xfdef).contains(&code)
        || code & 0xffff >= 0xfffe
        || (0xe000..=0xf8ff).contains(&code)
        || (0xf0000..=0xffffd).contains(&code)
        || (0x0010_0000..=0x0010_fffd).contains(&code)
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn strictly_sorted_claim_text(values: &[CanonicalClaimTextV2]) -> bool {
    values
        .windows(2)
        .all(|pair| pair[0].as_str().as_bytes() < pair[1].as_str().as_bytes())
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

fn registry_reference_for_entry(entry: &RegistryEntryV1) -> ContractResult<RegistryReferenceV1> {
    Ok(RegistryReferenceV1 {
        entry_id: entry.entry_id.clone(),
        version: entry.version,
        entry_digest: entry.digest()?,
    })
}

#[derive(PartialEq, Eq)]
enum RememberAdmissionBasisRuleKey<'a> {
    AuthenticatedActor,
    RegisteredObserver(&'a RegistryReferenceV1),
    ActivatedNormativeBinding(&'a RegistryReferenceV1),
}

const fn basis_rule_key(rule: &RememberAdmissionBasisRuleV2) -> RememberAdmissionBasisRuleKey<'_> {
    match rule {
        RememberAdmissionBasisRuleV2::AuthenticatedActor { .. } => {
            RememberAdmissionBasisRuleKey::AuthenticatedActor
        }
        RememberAdmissionBasisRuleV2::RegisteredObserver {
            observer_admission, ..
        } => RememberAdmissionBasisRuleKey::RegisteredObserver(observer_admission),
        RememberAdmissionBasisRuleV2::ActivatedNormativeBinding { binding_schema, .. } => {
            RememberAdmissionBasisRuleKey::ActivatedNormativeBinding(binding_schema)
        }
    }
}

fn basis_rule_keys_are_unique(rules: &[RememberAdmissionBasisRuleV2]) -> bool {
    rules.iter().enumerate().all(|(index, left)| {
        rules
            .iter()
            .skip(index + 1)
            .all(|right| basis_rule_key(left) != basis_rule_key(right))
    })
}

fn strictly_sorted_by_dimension(values: &[ConcreteApplicabilityDimensionV1]) -> bool {
    values
        .windows(2)
        .all(|pair| pair[0].dimension_id < pair[1].dimension_id)
}

fn strictly_sorted_by_dimension_rule(values: &[ApplicabilityDimensionRuleV2]) -> bool {
    values
        .windows(2)
        .all(|pair| pair[0].dimension_id < pair[1].dimension_id)
}

fn applicability_matches_rules(
    values: &[ConcreteApplicabilityDimensionV1],
    rules: &[ApplicabilityDimensionRuleV2],
) -> bool {
    let every_value_is_constrained = values.iter().all(|value| {
        rules.iter().any(|rule| {
            rule.dimension_id == value.dimension_id
                && rule.resource_identity.accepts_uri_shape(&value.resource)
        })
    });
    let every_required_rule_is_present = rules.iter().all(|rule| {
        !rule.required
            || values
                .iter()
                .any(|value| value.dimension_id == rule.dimension_id)
    });
    every_value_is_constrained && every_required_rule_is_present
}

const fn basis_requires_support(basis: &RememberAdmissionBasisV2) -> bool {
    matches!(basis, RememberAdmissionBasisV2::RegisteredObserver { .. })
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use serde::{Deserialize, Serialize};
    use sha2::{Digest as _, Sha256};

    use super::*;
    use crate::memory_contracts::{
        canonical::{CanonicalValue, decode_strict, encode_canonical, require_canonical},
        common::frozen_profile_reference_v1,
        digest::{DigestDomain, domain_separated_digest},
        identity::IdentityForm,
        registry::RegistryHeadV1,
    };

    const INGRESS_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v2/remember/remember-ingress-candidate-v2.jsonl"
    );
    const CLAIM_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v2/remember/semantic-claim-v2.jsonl");
    const STATEMENT_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v2/remember/remember-accepted-statement-v2.jsonl"
    );
    const PREDICATE_ENTRY_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v2/remember/remember-predicate-schema-v2-entry.jsonl"
    );
    const ADMISSION_ENTRY_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v2/remember/remember-admission-rule-v2-entry.jsonl"
    );
    const PREDICATE_POSITIVE_CASES_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v2/remember/predicate-positive-cases-v2.jsonl"
    );
    const PREDICATE_NEGATIVE_CASES_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v2/remember/predicate-negative-cases-v2.jsonl"
    );
    const ADMISSION_POSITIVE_CASES_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v2/remember/admission-positive-cases-v2.jsonl"
    );
    const ADMISSION_NEGATIVE_CASES_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v2/remember/admission-negative-cases-v2.jsonl"
    );
    const NEGATIVE_FLOAT_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v2/remember/negative-floating-value.jsonl");
    const NEGATIVE_JSON_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v2/remember/negative-arbitrary-json-value.jsonl"
    );
    const NEGATIVE_AUTHORITY_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v2/remember/negative-ingress-authority-fields.jsonl"
    );
    const NEGATIVE_NUMERIC_SUPPORT_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v2/remember/negative-numeric-support-id.jsonl"
    );
    const NEGATIVE_PHYSICAL_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v2/remember/negative-statement-physical-fields.jsonl"
    );
    const NEGATIVE_SUBJECT_IDENTITY_FORM_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v2/remember/negative-subject-identity-form.jsonl"
    );
    const NEGATIVE_ENVIRONMENT_IDENTITY_FORM_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v2/remember/negative-environment-identity-form.jsonl"
    );
    const NEGATIVE_PREDICATE_DIMENSION_IDENTITY_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v2/remember/negative-predicate-dimension-identity-entry.jsonl"
    );
    const NEGATIVE_PREDICATE_RESOURCE_VALUE_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v2/remember/negative-predicate-resource-value-entry.jsonl"
    );
    const NEGATIVE_PREDICATE_PUBLIC_DEFAULT_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v2/remember/negative-predicate-public-default-entry.jsonl"
    );
    const NEGATIVE_ADMISSION_OBSERVER_OPEN_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v2/remember/negative-admission-observer-open-entry.jsonl"
    );
    const NEGATIVE_ADMISSION_PAYLOAD_AUTHORITY_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v2/remember/negative-admission-payload-authority-entry.jsonl"
    );
    const NEGATIVE_ADMISSION_DUPLICATE_BASIS_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v2/remember/negative-admission-duplicate-basis-entry.jsonl"
    );
    const NEGATIVE_ADMISSION_BASIS_MODALITY_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v2/remember/negative-admission-basis-modality-entry.jsonl"
    );
    const VECTOR_SUITE_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v2/remember/vector-suite.jsonl");

    const CLAIM_COORDINATE_ID: &str =
        "c964975c9d734cbf6e8d0c300f97b1b2374d0107565b3be8835bbda9b8b5cded";
    const CLAIM_FINGERPRINT: &str =
        "6911f6090f66d4601651df777ad6e4bd765f595c97e795cd07b72095f9ebe0ee";
    const ACCEPTED_EVENT_ID: &str =
        "884c9becc53a6f2dc444df3728972c196cc52fd10184c600e8fbcb639a22e491";
    const VECTOR_SUITE_DIGEST: &str =
        "21bd8d133554af1e144e4e13798b5a521545aed407fe6980db6d0132629aa6a6";
    const INGRESS_RAW_SHA256: &str =
        "98f70e8075f82fdd9243215e63a4d49fc7fd2bcf3ac9defe3edc13d39ae09a1b";
    const CLAIM_RAW_SHA256: &str =
        "46046d108489b9736e8caa757bf2d4d1be24897d0e8917c4b8376579f865966c";
    const STATEMENT_RAW_SHA256: &str =
        "203e72429a2a0f0d60af96b62af79415adcdff6a381e32c81568ea93267f38a6";
    const VECTOR_SUITE_RAW_SHA256: &str =
        "4b31addb79455c408e413803469f57b75c4769780373469c3ad54ae4b3db05dd";
    const NEGATIVE_ARBITRARY_JSON_RAW_SHA256: &str =
        "2d1046da15c7a8b9860a5d1170506ab93b77683ea792550b280ee54ca09f79c8";
    const NEGATIVE_FLOAT_RAW_SHA256: &str =
        "77b2d05d1a647dc037fdbe8d98e372df23f65ccdaf8483c0834f4c755cccafbd";
    const NEGATIVE_AUTHORITY_RAW_SHA256: &str =
        "65c35b284ba9674eca366b740922ae583b9935c0841f99f5f503618c6a43d8f4";
    const NEGATIVE_NUMERIC_SUPPORT_RAW_SHA256: &str =
        "b7a1ba95b54d27a5189eb5a1a8f6e5012bd38d18ce4e1cc5d0790208deb53a41";
    const NEGATIVE_PHYSICAL_RAW_SHA256: &str =
        "c5cc7337dde9e022f3981197d38f312d56d62127f3eb96f89f33262a431c9e74";
    const NEGATIVE_SUBJECT_IDENTITY_FORM_RAW_SHA256: &str =
        "e0870231e6241de9aba60bef799b652294ea79d4475d2b22e8438b120d8bd595";
    const NEGATIVE_ENVIRONMENT_IDENTITY_FORM_RAW_SHA256: &str =
        "cdd41ca80a7a0b061a2330adbba39b10588573a171dc92e22fd7f6d30e963992";
    const PREDICATE_ENTRY_RAW_SHA256: &str =
        "a74f9da62be272a6b99f539f691a413560f712daebd5c7cf1716dfe3d1a1ff0f";
    const ADMISSION_ENTRY_RAW_SHA256: &str =
        "ca10f7c3591f739fb0535275b4abbf9d0e8206db411dcf2d4b1bb71d3ea25ab4";
    const PREDICATE_POSITIVE_CASES_RAW_SHA256: &str =
        "0dc6dac2dc81f4fe2d52ccd713ec632843b546328894e5f6c3d5ffc761306230";
    const PREDICATE_NEGATIVE_CASES_RAW_SHA256: &str =
        "53e2cd51d19bb5506a08c3b90d3618a13703a46f2faba3033c27223d72020007";
    const ADMISSION_POSITIVE_CASES_RAW_SHA256: &str =
        "9acfbea8471b1d7179e87ec6cb97deadbce2ce522bf1cf7ff0189b2fdfebe9cc";
    const ADMISSION_NEGATIVE_CASES_RAW_SHA256: &str =
        "07473341caf159cc325c5f2a31b0744fd0024162311791c629d1da7f64f10d55";
    const NEGATIVE_PREDICATE_DIMENSION_IDENTITY_RAW_SHA256: &str =
        "028bafe8f27804fd0e1774141e34473c04a7e7d32411759bc9e794f951437cb4";
    const NEGATIVE_PREDICATE_RESOURCE_VALUE_RAW_SHA256: &str =
        "510785d789c55bf86d18ba9d04e7ac2af3a85a77f3177d6eee76530d78035beb";
    const NEGATIVE_PREDICATE_PUBLIC_DEFAULT_RAW_SHA256: &str =
        "e0ca4059e80671d322e26e8d327bd85851c6c1464487c875b96a171af395f4e1";
    const NEGATIVE_ADMISSION_OBSERVER_OPEN_RAW_SHA256: &str =
        "7343de2ef67b7330950acdaed5b03dbb3dced6c9dda77d8081d04ee725051991";
    const NEGATIVE_ADMISSION_PAYLOAD_AUTHORITY_RAW_SHA256: &str =
        "b0e5fbd804a5570e24c574ecf1e053e755f9a59a5c599eba2335c5f522c96214";
    const NEGATIVE_ADMISSION_DUPLICATE_BASIS_RAW_SHA256: &str =
        "dc0abb9aa178145cc45bb6f3ec9d935fa380b71e410b7aac92a47740173486c4";
    const NEGATIVE_ADMISSION_BASIS_MODALITY_RAW_SHA256: &str =
        "5ede144d4bba7e0ed08a46ee717655a6dec8c1a3d511f708980aa694d98d4e79";

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RememberVectorSuiteV2 {
        schema_version: u32,
        fixture_authority: String,
        claim_coordinate_id: ClaimCoordinateIdV2,
        semantic_claim_fingerprint: SemanticClaimFingerprintV2,
        accepted_event_id: AcceptedEventId,
        predicate_registry_entry_digest: Sha256Digest,
        admission_registry_entry_digest: Sha256Digest,
        predicate_positive_cases_digest: Sha256Digest,
        predicate_negative_cases_digest: Sha256Digest,
        admission_positive_cases_digest: Sha256Digest,
        admission_negative_cases_digest: Sha256Digest,
        consistency_key_family: ContractId,
        consistency_key_digest: Sha256Digest,
        negative_cases: Vec<ContractId>,
    }

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RememberRegistryCaseManifestV2 {
        schema_version: u32,
        case_set_id: ContractId,
        entry_schema_id: ContractId,
        expected_outcome: ContractId,
        cases: Vec<ContractId>,
    }

    impl RememberRegistryCaseManifestV2 {
        fn validate(&self) -> ContractResult<()> {
            if self.schema_version != 2
                || !matches!(self.expected_outcome.as_str(), "accept" | "reject")
                || self.cases.is_empty()
                || !strictly_sorted(&self.cases)
            {
                return Err(ContractError::Schema(
                    "invalid remember registry case manifest".into(),
                ));
            }
            encode_canonical(self)?;
            Ok(())
        }
    }

    fn record(bytes: &[u8]) -> &[u8] {
        let body = bytes
            .strip_suffix(b"\n")
            .expect("contract artifact must have exactly one framing LF");
        assert!(!body.ends_with(b"\n"));
        assert!(!body.contains(&b'\r'));
        body
    }

    fn digest(value: &str) -> Sha256Digest {
        Sha256Digest::from_str(value).unwrap()
    }

    fn labelled_digest(label: &str) -> Sha256Digest {
        domain_separated_digest(DigestDomain::RegistryEntry, label.as_bytes())
    }

    fn raw_sha256(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    fn reference(id: &str) -> RegistryReferenceV1 {
        RegistryReferenceV1 {
            entry_id: ContractId::new(id).unwrap(),
            version: 2,
            entry_digest: labelled_digest(id),
        }
    }

    fn canonical_value<T: Serialize>(value: &T) -> CanonicalValue {
        decode_strict(&encode_canonical(value).unwrap()).unwrap()
    }

    fn resource_identity(kind: &str, recipe: &str) -> ResourceIdentityConstraintV2 {
        ResourceIdentityConstraintV2 {
            resource_kind_schema: reference(kind),
            identity_recipe: reference(recipe),
        }
    }

    fn predicate_schema() -> RememberPredicateSchemaV2 {
        RememberPredicateSchemaV2 {
            schema_version: 2,
            predicate_id: ContractId::new("mcp.remember.allowed_actions").unwrap(),
            version: 2,
            subject_identity: resource_identity("repository", "identity.github.repository"),
            value_constraint: RememberValueConstraintV2::Boolean {
                unit_id: ContractId::new("unit.none").unwrap(),
            },
            comparator: PredicateComparatorV1::ExactEquality,
            allowed_modalities: vec![
                PropositionModalityV1::Attested,
                PropositionModalityV1::Intended,
            ],
            applicability_evaluator: reference("applicability.default"),
            applicability_dimensions: vec![
                ApplicabilityDimensionRuleV2 {
                    dimension_id: ContractId::new("repository_commit").unwrap(),
                    resource_identity: resource_identity("commit", "identity.github.commit"),
                    required: true,
                },
                ApplicabilityDimensionRuleV2 {
                    dimension_id: ContractId::new("runtime_environment").unwrap(),
                    resource_identity: resource_identity(
                        "environment",
                        "identity.runtime.environment",
                    ),
                    required: true,
                },
            ],
            absence_semantics: AbsenceSemanticsV1::OpenWorld,
            coverage_proof: None,
            publication_default: PublicationDefaultV1::Denied,
            sensitivity_default: SensitivityDefaultV1::Project,
        }
    }

    fn case_ids(values: &[&str]) -> Vec<ContractId> {
        values
            .iter()
            .map(|value| ContractId::new(*value).unwrap())
            .collect()
    }

    fn predicate_positive_cases() -> RememberRegistryCaseManifestV2 {
        RememberRegistryCaseManifestV2 {
            schema_version: 2,
            case_set_id: ContractId::new("remember.predicate.v2.positive").unwrap(),
            entry_schema_id: ContractId::new(PREDICATE_ENTRY_SCHEMA_ID).unwrap(),
            expected_outcome: ContractId::new("accept").unwrap(),
            cases: case_ids(&[
                "closed_value_constraint",
                "exact_resource_identity_closure",
                "publication_sensitivity_defaults",
                "required_applicability_dimensions",
            ]),
        }
    }

    fn predicate_negative_cases() -> RememberRegistryCaseManifestV2 {
        RememberRegistryCaseManifestV2 {
            schema_version: 2,
            case_set_id: ContractId::new("remember.predicate.v2.negative").unwrap(),
            entry_schema_id: ContractId::new(PREDICATE_ENTRY_SCHEMA_ID).unwrap(),
            expected_outcome: ContractId::new("reject").unwrap(),
            cases: case_ids(&[
                "dimension_identity_recipe_zero",
                "public_default_unknown",
                "resource_value_recipe_zero",
            ]),
        }
    }

    fn admission_positive_cases() -> RememberRegistryCaseManifestV2 {
        RememberRegistryCaseManifestV2 {
            schema_version: 2,
            case_set_id: ContractId::new("remember.admission.v2.positive").unwrap(),
            entry_schema_id: ContractId::new(ADMISSION_ENTRY_SCHEMA_ID).unwrap(),
            expected_outcome: ContractId::new("accept").unwrap(),
            cases: case_ids(&[
                "actor_attested_or_intended",
                "governance_server_derived",
                "payload_authority_denied",
                "text_limit_bounded",
            ]),
        }
    }

    fn admission_negative_cases() -> RememberRegistryCaseManifestV2 {
        RememberRegistryCaseManifestV2 {
            schema_version: 2,
            case_set_id: ContractId::new("remember.admission.v2.negative").unwrap(),
            entry_schema_id: ContractId::new(ADMISSION_ENTRY_SCHEMA_ID).unwrap(),
            expected_outcome: ContractId::new("reject").unwrap(),
            cases: case_ids(&[
                "actor_observed_modality",
                "duplicate_actor_basis",
                "observer_coverage_open",
                "payload_selects_admission_rule",
            ]),
        }
    }

    fn case_manifest_digest(manifest: &RememberRegistryCaseManifestV2) -> Sha256Digest {
        manifest.validate().unwrap();
        domain_separated_digest(
            DigestDomain::TestVectorManifest,
            &encode_canonical(manifest).unwrap(),
        )
    }

    fn predicate_entry() -> RegistryEntryV1 {
        RegistryEntryV1 {
            schema_version: 1,
            kind: RegistryEntryKind::PredicateSchema,
            entry_id: ContractId::new("mcp.remember.allowed_actions").unwrap(),
            version: 2,
            entry_schema_id: ContractId::new(PREDICATE_ENTRY_SCHEMA_ID).unwrap(),
            entry_schema_version: 2,
            body: canonical_value(&predicate_schema()),
            positive_vector_digest: case_manifest_digest(&predicate_positive_cases()),
            negative_vector_digest: case_manifest_digest(&predicate_negative_cases()),
        }
    }

    fn predicate_reference() -> RegistryReferenceV1 {
        registry_reference_for_entry(&predicate_entry()).unwrap()
    }

    fn admission_rule() -> RememberAdmissionRuleV2 {
        RememberAdmissionRuleV2 {
            schema_version: 2,
            rule_id: ContractId::new("remember.actor_assertion").unwrap(),
            version: 2,
            predicate_schema: predicate_reference(),
            applicability_evaluator: reference("applicability.default"),
            allowed_assertion_kinds: vec![
                RememberAssertionKindV2::Decision,
                RememberAssertionKindV2::Fact,
                RememberAssertionKindV2::Constraint,
                RememberAssertionKindV2::Preference,
                RememberAssertionKindV2::Procedure,
            ],
            basis_rules: vec![RememberAdmissionBasisRuleV2::AuthenticatedActor {
                allowed_modalities: vec![
                    PropositionModalityV1::Attested,
                    PropositionModalityV1::Intended,
                ],
                maximum_support_events: 256,
            }],
            effective_interval_rule: RememberEffectiveIntervalRuleV2 {
                payload_may_select_effective_from: true,
                past_effective_from_allowed: true,
                future_effective_from_allowed: false,
                open_ended_interval_allowed: true,
                bounded_interval_allowed: true,
                microsecond_alignment_required: true,
            },
            classifier_policy: reference("classifier.default"),
            redaction_policy: reference("redaction.default"),
            retention_policy: reference("retention.default"),
            publication_rule: reference("publication.default"),
            maximum_assertion_text_utf8_bytes: 100_000,
            authenticated_scope_required: true,
            resource_rederivation_required: true,
            support_event_reaudit_required: true,
            server_derived_governance_required: true,
            registered_observer_append_enabled: false,
            normative_binding_append_enabled: false,
            payload_may_select_actor: false,
            payload_may_select_scope: false,
            payload_may_select_registry_head: false,
            payload_may_select_admission_rule: false,
            payload_may_select_admission_outcome: false,
        }
    }

    fn admission_entry() -> RegistryEntryV1 {
        RegistryEntryV1 {
            schema_version: 1,
            kind: RegistryEntryKind::AuthorityRule,
            entry_id: ContractId::new("remember.actor_assertion").unwrap(),
            version: 2,
            entry_schema_id: ContractId::new(ADMISSION_ENTRY_SCHEMA_ID).unwrap(),
            entry_schema_version: 2,
            body: canonical_value(&admission_rule()),
            positive_vector_digest: case_manifest_digest(&admission_positive_cases()),
            negative_vector_digest: case_manifest_digest(&admission_negative_cases()),
        }
    }

    fn admission_reference() -> RegistryReferenceV1 {
        registry_reference_for_entry(&admission_entry()).unwrap()
    }

    fn predicate_entry_with(schema: &RememberPredicateSchemaV2) -> RegistryEntryV1 {
        let mut entry = predicate_entry();
        entry.body = canonical_value(schema);
        entry
    }

    fn admission_entry_with(rule: &RememberAdmissionRuleV2) -> RegistryEntryV1 {
        let mut entry = admission_entry();
        entry.body = canonical_value(rule);
        entry
    }

    fn negative_predicate_dimension_identity_entry() -> RegistryEntryV1 {
        let mut schema = predicate_schema();
        schema.applicability_dimensions[0]
            .resource_identity
            .identity_recipe
            .entry_digest = Sha256Digest::ZERO;
        predicate_entry_with(&schema)
    }

    fn negative_predicate_resource_value_entry() -> RegistryEntryV1 {
        let mut schema = predicate_schema();
        let mut resource_identity = resource_identity("repository", "identity.github.repository");
        resource_identity.identity_recipe.entry_digest = Sha256Digest::ZERO;
        schema.value_constraint = RememberValueConstraintV2::ResourceUri { resource_identity };
        predicate_entry_with(&schema)
    }

    fn registered_observer_basis(coverage_reaudit_required: bool) -> RememberAdmissionBasisRuleV2 {
        RememberAdmissionBasisRuleV2::RegisteredObserver {
            observer_admission: reference("observer.rust_enum"),
            observer_result_event_schema: reference("observer_result.remember.v2"),
            allowed_modalities: vec![PropositionModalityV1::Observed],
            minimum_support_events: 1,
            maximum_support_events: 256,
            same_scope_required: true,
            same_registry_head_required: true,
            exact_observer_reference_required: true,
            exact_claim_output_required: true,
            coverage_reaudit_required,
        }
    }

    fn negative_admission_observer_open_entry() -> RegistryEntryV1 {
        let mut rule = admission_rule();
        rule.basis_rules = vec![registered_observer_basis(false)];
        admission_entry_with(&rule)
    }

    fn negative_admission_payload_authority_entry() -> RegistryEntryV1 {
        let mut rule = admission_rule();
        rule.payload_may_select_admission_rule = true;
        admission_entry_with(&rule)
    }

    fn negative_admission_duplicate_basis_entry() -> RegistryEntryV1 {
        let mut rule = admission_rule();
        rule.basis_rules = vec![
            RememberAdmissionBasisRuleV2::AuthenticatedActor {
                allowed_modalities: vec![PropositionModalityV1::Attested],
                maximum_support_events: 1,
            },
            RememberAdmissionBasisRuleV2::AuthenticatedActor {
                allowed_modalities: vec![
                    PropositionModalityV1::Attested,
                    PropositionModalityV1::Intended,
                ],
                maximum_support_events: 256,
            },
        ];
        admission_entry_with(&rule)
    }

    fn negative_admission_basis_modality_entry() -> RegistryEntryV1 {
        let mut rule = admission_rule();
        rule.basis_rules = vec![RememberAdmissionBasisRuleV2::AuthenticatedActor {
            allowed_modalities: vec![PropositionModalityV1::Observed],
            maximum_support_events: 256,
        }];
        admission_entry_with(&rule)
    }

    fn scope() -> AuthenticatedProjectScopeV1 {
        AuthenticatedProjectScopeV1::from_trusted_context(
            ContractId::new("tenant.fixture").unwrap(),
            ContractId::new("project.fixture").unwrap(),
        )
    }

    fn registry() -> RegistryHeadBindingV1 {
        RegistryHeadBindingV1 {
            head: RegistryHeadV1 {
                activation_id: labelled_digest("activation.remember.v2"),
                package_digest: labelled_digest("package.remember.v2"),
                activation_policy_digest: labelled_digest("activation.policy.v2"),
            },
            effective_from: CanonicalTimestamp::parse("2026-08-15T12:00:00.000000000Z").unwrap(),
            effective_until: None,
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

    fn first_stage4_resource_forms_match(candidate: &RememberIngressCandidateV2) -> bool {
        let dimension_matches = |dimension_id: &str, kind: &str, form: IdentityForm| {
            candidate.applicability.iter().any(|dimension| {
                dimension.dimension_id.as_str() == dimension_id
                    && dimension.resource.resource_kind().as_str() == kind
                    && dimension.resource.identity_form() == form
            })
        };
        candidate.asserted_subject.resource_kind().as_str() == "repository"
            && candidate.asserted_subject.identity_form() == IdentityForm::Entity
            && dimension_matches("repository_commit", "commit", IdentityForm::Version)
            && dimension_matches("runtime_environment", "environment", IdentityForm::Entity)
    }

    fn applicability() -> Vec<ConcreteApplicabilityDimensionV1> {
        vec![
            ConcreteApplicabilityDimensionV1 {
                dimension_id: ContractId::new("repository_commit").unwrap(),
                resource: resource(IdentityForm::Version, "commit", '3'),
            },
            ConcreteApplicabilityDimensionV1 {
                dimension_id: ContractId::new("runtime_environment").unwrap(),
                resource: resource(IdentityForm::Entity, "environment", '4'),
            },
        ]
    }

    fn interval() -> ClaimEffectiveIntervalV2 {
        ClaimEffectiveIntervalV2 {
            effective_from: CanonicalTimestamp::parse("2026-08-15T12:30:00.000000000Z").unwrap(),
            effective_until: None,
        }
    }

    fn support(digit: char) -> AcceptedEventId {
        AcceptedEventId::from_digest(digest(&digit.to_string().repeat(64)))
    }

    fn candidate() -> RememberIngressCandidateV2 {
        RememberIngressCandidateV2 {
            schema_version: 2,
            asserted_subject: resource(IdentityForm::Entity, "repository", '1'),
            subject_identity_recipe: reference("identity.github.repository"),
            predicate_schema: predicate_reference(),
            applicability_evaluator: reference("applicability.default"),
            admission_rule: admission_reference(),
            assertion_kind: RememberAssertionKindV2::Fact,
            assertion_text_utf8_hex_chunks: CanonicalAssertionTextV2::parse(
                "MCP remember allows deliberate record assertions.\nIt preserves authored narrative.",
            )
            .unwrap(),
            modality: PropositionModalityV1::Attested,
            polarity: ClaimPolarityV2::Affirms,
            value: CanonicalClaimValueV2::Boolean { value: true },
            applicability: applicability(),
            effective_interval: interval(),
            requested_basis: RememberAdmissionBasisV2::AuthenticatedActor,
            support_evidence_event_ids: vec![support('5'), support('6')],
        }
    }

    fn claim() -> SemanticClaimV2 {
        let candidate = candidate();
        SemanticClaimV2 {
            schema_version: 2,
            profile: frozen_profile_reference_v1(),
            scope: scope(),
            registry: registry(),
            subject: candidate.asserted_subject,
            subject_identity_recipe: candidate.subject_identity_recipe,
            predicate_schema: candidate.predicate_schema,
            applicability_evaluator: candidate.applicability_evaluator,
            assertion_kind: candidate.assertion_kind,
            modality: candidate.modality,
            polarity: candidate.polarity,
            value: candidate.value,
            applicability: candidate.applicability,
            effective_interval: candidate.effective_interval,
        }
    }

    fn statement() -> RememberAcceptedStatementV2 {
        let claim = claim();
        RememberAcceptedStatementV2 {
            schema_version: 2,
            event_kind: ContractId::new(REMEMBER_ACCEPTED_EVENT_KIND).unwrap(),
            profile: frozen_profile_reference_v1(),
            scope: scope(),
            registry: registry(),
            claim_fingerprint: claim.fingerprint().unwrap(),
            claim,
            assertion_text_utf8_hex_chunks: CanonicalAssertionTextV2::parse(
                "MCP remember allows deliberate record assertions.\nIt preserves authored narrative.",
            )
            .unwrap(),
            actor: RememberActorV2 {
                principal_id: ContractId::new("principal.operator").unwrap(),
            },
            admission_rule: admission_reference(),
            admission_basis: RememberAdmissionBasisV2::AuthenticatedActor,
            support_evidence_event_ids: vec![support('5'), support('6')],
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn hard_coded_contract_vectors_match_independent_ids() {
        for (bytes, expected_raw_sha256) in [
            (INGRESS_FIXTURE, INGRESS_RAW_SHA256),
            (CLAIM_FIXTURE, CLAIM_RAW_SHA256),
            (STATEMENT_FIXTURE, STATEMENT_RAW_SHA256),
            (PREDICATE_ENTRY_FIXTURE, PREDICATE_ENTRY_RAW_SHA256),
            (ADMISSION_ENTRY_FIXTURE, ADMISSION_ENTRY_RAW_SHA256),
            (
                PREDICATE_POSITIVE_CASES_FIXTURE,
                PREDICATE_POSITIVE_CASES_RAW_SHA256,
            ),
            (
                PREDICATE_NEGATIVE_CASES_FIXTURE,
                PREDICATE_NEGATIVE_CASES_RAW_SHA256,
            ),
            (
                ADMISSION_POSITIVE_CASES_FIXTURE,
                ADMISSION_POSITIVE_CASES_RAW_SHA256,
            ),
            (
                ADMISSION_NEGATIVE_CASES_FIXTURE,
                ADMISSION_NEGATIVE_CASES_RAW_SHA256,
            ),
            (VECTOR_SUITE_FIXTURE, VECTOR_SUITE_RAW_SHA256),
            (NEGATIVE_JSON_FIXTURE, NEGATIVE_ARBITRARY_JSON_RAW_SHA256),
            (NEGATIVE_FLOAT_FIXTURE, NEGATIVE_FLOAT_RAW_SHA256),
            (NEGATIVE_AUTHORITY_FIXTURE, NEGATIVE_AUTHORITY_RAW_SHA256),
            (
                NEGATIVE_NUMERIC_SUPPORT_FIXTURE,
                NEGATIVE_NUMERIC_SUPPORT_RAW_SHA256,
            ),
            (NEGATIVE_PHYSICAL_FIXTURE, NEGATIVE_PHYSICAL_RAW_SHA256),
            (
                NEGATIVE_SUBJECT_IDENTITY_FORM_FIXTURE,
                NEGATIVE_SUBJECT_IDENTITY_FORM_RAW_SHA256,
            ),
            (
                NEGATIVE_ENVIRONMENT_IDENTITY_FORM_FIXTURE,
                NEGATIVE_ENVIRONMENT_IDENTITY_FORM_RAW_SHA256,
            ),
            (
                NEGATIVE_PREDICATE_DIMENSION_IDENTITY_FIXTURE,
                NEGATIVE_PREDICATE_DIMENSION_IDENTITY_RAW_SHA256,
            ),
            (
                NEGATIVE_PREDICATE_RESOURCE_VALUE_FIXTURE,
                NEGATIVE_PREDICATE_RESOURCE_VALUE_RAW_SHA256,
            ),
            (
                NEGATIVE_PREDICATE_PUBLIC_DEFAULT_FIXTURE,
                NEGATIVE_PREDICATE_PUBLIC_DEFAULT_RAW_SHA256,
            ),
            (
                NEGATIVE_ADMISSION_OBSERVER_OPEN_FIXTURE,
                NEGATIVE_ADMISSION_OBSERVER_OPEN_RAW_SHA256,
            ),
            (
                NEGATIVE_ADMISSION_PAYLOAD_AUTHORITY_FIXTURE,
                NEGATIVE_ADMISSION_PAYLOAD_AUTHORITY_RAW_SHA256,
            ),
            (
                NEGATIVE_ADMISSION_DUPLICATE_BASIS_FIXTURE,
                NEGATIVE_ADMISSION_DUPLICATE_BASIS_RAW_SHA256,
            ),
            (
                NEGATIVE_ADMISSION_BASIS_MODALITY_FIXTURE,
                NEGATIVE_ADMISSION_BASIS_MODALITY_RAW_SHA256,
            ),
        ] {
            assert_eq!(raw_sha256(bytes), expected_raw_sha256);
        }
        for bytes in [
            INGRESS_FIXTURE,
            CLAIM_FIXTURE,
            STATEMENT_FIXTURE,
            PREDICATE_ENTRY_FIXTURE,
            ADMISSION_ENTRY_FIXTURE,
            PREDICATE_POSITIVE_CASES_FIXTURE,
            PREDICATE_NEGATIVE_CASES_FIXTURE,
            ADMISSION_POSITIVE_CASES_FIXTURE,
            ADMISSION_NEGATIVE_CASES_FIXTURE,
            VECTOR_SUITE_FIXTURE,
        ] {
            require_canonical(record(bytes)).unwrap();
        }
        assert_eq!(
            encode_canonical(&candidate()).unwrap(),
            record(INGRESS_FIXTURE)
        );
        assert_eq!(encode_canonical(&claim()).unwrap(), record(CLAIM_FIXTURE));
        assert_eq!(
            encode_canonical(&statement()).unwrap(),
            record(STATEMENT_FIXTURE)
        );
        assert_eq!(
            encode_canonical(&predicate_entry()).unwrap(),
            record(PREDICATE_ENTRY_FIXTURE)
        );
        assert_eq!(
            encode_canonical(&admission_entry()).unwrap(),
            record(ADMISSION_ENTRY_FIXTURE)
        );
        for (bytes, expected) in [
            (PREDICATE_POSITIVE_CASES_FIXTURE, predicate_positive_cases()),
            (PREDICATE_NEGATIVE_CASES_FIXTURE, predicate_negative_cases()),
            (ADMISSION_POSITIVE_CASES_FIXTURE, admission_positive_cases()),
            (ADMISSION_NEGATIVE_CASES_FIXTURE, admission_negative_cases()),
        ] {
            let decoded: RememberRegistryCaseManifestV2 = decode_strict(record(bytes)).unwrap();
            decoded.validate().unwrap();
            assert_eq!(decoded, expected);
        }

        let coordinate_id = claim().coordinate().coordinate_id().unwrap();
        let fingerprint = claim().fingerprint().unwrap();
        let event_id = statement().accepted_event_id().unwrap();
        assert_eq!(coordinate_id.digest(), digest(CLAIM_COORDINATE_ID));
        assert_eq!(fingerprint.digest(), digest(CLAIM_FINGERPRINT));
        assert_eq!(event_id.digest(), digest(ACCEPTED_EVENT_ID));

        let suite: RememberVectorSuiteV2 = decode_strict(record(VECTOR_SUITE_FIXTURE)).unwrap();
        assert_eq!(suite.schema_version, 2);
        assert!(suite.fixture_authority.starts_with("none;"));
        assert_eq!(suite.claim_coordinate_id, coordinate_id);
        assert_eq!(suite.semantic_claim_fingerprint, fingerprint);
        assert_eq!(suite.accepted_event_id, event_id);
        assert_eq!(
            suite.predicate_registry_entry_digest,
            predicate_entry().digest().unwrap()
        );
        assert_eq!(
            suite.admission_registry_entry_digest,
            admission_entry().digest().unwrap()
        );
        assert_eq!(
            suite.predicate_positive_cases_digest,
            predicate_entry().positive_vector_digest
        );
        assert_eq!(
            suite.predicate_negative_cases_digest,
            predicate_entry().negative_vector_digest
        );
        assert_eq!(
            suite.admission_positive_cases_digest,
            admission_entry().positive_vector_digest
        );
        assert_eq!(
            suite.admission_negative_cases_digest,
            admission_entry().negative_vector_digest
        );
        assert_eq!(
            suite.consistency_key_family.as_str(),
            CLAIM_CONSISTENCY_FAMILY
        );
        assert_eq!(suite.consistency_key_digest, coordinate_id.digest());
        assert!(strictly_sorted(&suite.negative_cases));
        assert_eq!(
            domain_separated_digest(
                DigestDomain::TestVectorManifest,
                record(VECTOR_SUITE_FIXTURE)
            ),
            digest(VECTOR_SUITE_DIGEST)
        );
    }

    #[test]
    fn full_registry_entry_preimages_close_structural_policy_without_authority() {
        let decoded_predicate: RegistryEntryV1 =
            decode_strict(record(PREDICATE_ENTRY_FIXTURE)).unwrap();
        let decoded_admission: RegistryEntryV1 =
            decode_strict(record(ADMISSION_ENTRY_FIXTURE)).unwrap();
        assert_eq!(decoded_predicate, predicate_entry());
        assert_eq!(decoded_admission, admission_entry());

        let resolved = StructurallyResolvedRememberContractsV2::from_registry_entries(
            &decoded_predicate,
            &decoded_admission,
        )
        .unwrap();
        assert_eq!(resolved.predicate_reference(), &predicate_reference());
        assert_eq!(resolved.admission_reference(), &admission_reference());
        resolved.validate_candidate_shape(&candidate()).unwrap();

        let mut changed_predicate = predicate_entry();
        let mut changed_body = predicate_schema();
        changed_body.sensitivity_default = SensitivityDefaultV1::Private;
        changed_predicate.body = canonical_value(&changed_body);
        assert!(
            StructurallyResolvedRememberContractsV2::from_registry_entries(
                &changed_predicate,
                &admission_entry(),
            )
            .is_err()
        );

        let mut wrong_kind = admission_entry();
        wrong_kind.kind = RegistryEntryKind::PredicateSchema;
        assert!(
            StructurallyResolvedRememberContractsV2::from_registry_entries(
                &predicate_entry(),
                &wrong_kind,
            )
            .is_err()
        );
    }

    #[test]
    fn typed_policy_negatives_are_canonical_raw_pinned_and_fail_closed() {
        for bytes in [
            NEGATIVE_PREDICATE_DIMENSION_IDENTITY_FIXTURE,
            NEGATIVE_PREDICATE_RESOURCE_VALUE_FIXTURE,
            NEGATIVE_PREDICATE_PUBLIC_DEFAULT_FIXTURE,
            NEGATIVE_ADMISSION_OBSERVER_OPEN_FIXTURE,
            NEGATIVE_ADMISSION_PAYLOAD_AUTHORITY_FIXTURE,
            NEGATIVE_ADMISSION_DUPLICATE_BASIS_FIXTURE,
            NEGATIVE_ADMISSION_BASIS_MODALITY_FIXTURE,
        ] {
            require_canonical(record(bytes)).unwrap();
        }

        for bytes in [
            NEGATIVE_PREDICATE_DIMENSION_IDENTITY_FIXTURE,
            NEGATIVE_PREDICATE_RESOURCE_VALUE_FIXTURE,
            NEGATIVE_PREDICATE_PUBLIC_DEFAULT_FIXTURE,
        ] {
            let entry: RegistryEntryV1 = decode_strict(record(bytes)).unwrap();
            assert!(
                StructurallyResolvedRememberContractsV2::from_registry_entries(
                    &entry,
                    &admission_entry(),
                )
                .is_err()
            );
        }
        for bytes in [
            NEGATIVE_ADMISSION_OBSERVER_OPEN_FIXTURE,
            NEGATIVE_ADMISSION_PAYLOAD_AUTHORITY_FIXTURE,
            NEGATIVE_ADMISSION_DUPLICATE_BASIS_FIXTURE,
            NEGATIVE_ADMISSION_BASIS_MODALITY_FIXTURE,
        ] {
            let entry: RegistryEntryV1 = decode_strict(record(bytes)).unwrap();
            assert!(
                StructurallyResolvedRememberContractsV2::from_registry_entries(
                    &predicate_entry(),
                    &entry,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn basis_routes_and_resource_identity_checks_remain_fail_closed() {
        let mut observer_predicate = predicate_schema();
        observer_predicate.allowed_modalities = vec![PropositionModalityV1::Observed];
        let observer_predicate_entry = predicate_entry_with(&observer_predicate);
        let observer_predicate_reference =
            registry_reference_for_entry(&observer_predicate_entry).unwrap();
        let mut observer_rule = admission_rule();
        observer_rule.basis_rules = vec![registered_observer_basis(true)];
        observer_rule.predicate_schema = observer_predicate_reference.clone();
        let observer_entry = admission_entry_with(&observer_rule);
        let observer_resolved = StructurallyResolvedRememberContractsV2::from_registry_entries(
            &observer_predicate_entry,
            &observer_entry,
        )
        .unwrap();
        let mut observer = candidate();
        observer.modality = PropositionModalityV1::Observed;
        observer.predicate_schema = observer_predicate_reference;
        observer.requested_basis = RememberAdmissionBasisV2::RegisteredObserver {
            observer_admission: reference("observer.rust_enum"),
        };
        observer.admission_rule = registry_reference_for_entry(&observer_entry).unwrap();
        observer.validate_shape().unwrap();
        assert!(
            observer_resolved
                .validate_candidate_shape(&observer)
                .is_err()
        );

        let mut duplicate = admission_rule();
        duplicate.basis_rules = vec![
            RememberAdmissionBasisRuleV2::AuthenticatedActor {
                allowed_modalities: vec![PropositionModalityV1::Attested],
                maximum_support_events: 1,
            },
            RememberAdmissionBasisRuleV2::AuthenticatedActor {
                allowed_modalities: vec![PropositionModalityV1::Intended],
                maximum_support_events: 2,
            },
        ];
        assert!(duplicate.validate_shape().is_err());

        let mut observer_enabled = admission_rule();
        observer_enabled.registered_observer_append_enabled = true;
        assert!(observer_enabled.validate_shape().is_err());
        let mut normative_enabled = admission_rule();
        normative_enabled.normative_binding_append_enabled = true;
        assert!(normative_enabled.validate_shape().is_err());

        let constraint = resource_identity("repository", "identity.github.repository");
        assert!(constraint.accepts_uri_shape(&resource(IdentityForm::Entity, "repository", 'a')));
        assert!(!constraint.accepts_uri_shape(&resource(IdentityForm::Version, "commit", 'a')));

        let mut strict_rule = admission_rule();
        strict_rule.maximum_assertion_text_utf8_bytes = 1;
        let strict_entry = admission_entry_with(&strict_rule);
        let strict_resolved = StructurallyResolvedRememberContractsV2::from_registry_entries(
            &predicate_entry(),
            &strict_entry,
        )
        .unwrap();
        let mut too_long = candidate();
        too_long.admission_rule = registry_reference_for_entry(&strict_entry).unwrap();
        assert!(strict_resolved.validate_candidate_shape(&too_long).is_err());
    }

    #[test]
    fn first_stage4_resource_forms_are_explicit_and_mismatches_fail_closed() {
        let positive = candidate();
        assert!(first_stage4_resource_forms_match(&positive));
        assert_eq!(
            positive.asserted_subject.identity_form(),
            IdentityForm::Entity
        );
        assert_eq!(
            positive.applicability[0].resource.identity_form(),
            IdentityForm::Version
        );
        assert_eq!(
            positive.applicability[1].resource.identity_form(),
            IdentityForm::Entity
        );
        assert!(matches!(
            &positive.value,
            CanonicalClaimValueV2::Boolean { value: true }
        ));
        assert!(matches!(
            predicate_schema().value_constraint,
            RememberValueConstraintV2::Boolean { unit_id }
                if unit_id.as_str() == "unit.none"
        ));

        for bytes in [
            NEGATIVE_SUBJECT_IDENTITY_FORM_FIXTURE,
            NEGATIVE_ENVIRONMENT_IDENTITY_FORM_FIXTURE,
        ] {
            require_canonical(record(bytes)).unwrap();
            let negative: RememberIngressCandidateV2 = decode_strict(record(bytes)).unwrap();
            // Public shape remains authority-free; exact active recipe
            // rederivation is what rejects the incompatible URI form.
            negative.validate_shape().unwrap();
            assert!(!first_stage4_resource_forms_match(&negative));
        }
    }

    #[test]
    fn ingress_cannot_select_server_authority_or_physical_state() {
        candidate().validate_shape().unwrap();
        let encoded = encode_canonical(&candidate()).unwrap();
        let text = std::str::from_utf8(&encoded).unwrap();
        for forbidden in [
            "\"profile\"",
            "\"scope\"",
            "\"registry\"",
            "\"actor\"",
            "\"event_kind\"",
            "\"claim_fingerprint\"",
            "\"accepted_event_id\"",
            "\"accepted_at\"",
            "\"epoch_id\"",
            "\"shard\"",
            "\"committed_offset\"",
        ] {
            assert!(
                !text.contains(forbidden),
                "forbidden ingress field {forbidden}"
            );
        }

        for bytes in [
            NEGATIVE_AUTHORITY_FIXTURE,
            NEGATIVE_NUMERIC_SUPPORT_FIXTURE,
            NEGATIVE_PHYSICAL_FIXTURE,
        ] {
            require_canonical(record(bytes)).unwrap();
        }
        assert!(
            decode_strict::<RememberIngressCandidateV2>(record(NEGATIVE_AUTHORITY_FIXTURE))
                .is_err()
        );
        assert!(
            decode_strict::<RememberAcceptedStatementV2>(record(NEGATIVE_PHYSICAL_FIXTURE))
                .is_err()
        );
        assert!(
            decode_strict::<RememberIngressCandidateV2>(record(NEGATIVE_NUMERIC_SUPPORT_FIXTURE))
                .is_err()
        );
    }

    #[test]
    fn values_are_closed_typed_and_never_floating_or_arbitrary_json() {
        require_canonical(record(NEGATIVE_JSON_FIXTURE)).unwrap();
        assert!(
            decode_strict::<RememberIngressCandidateV2>(record(NEGATIVE_FLOAT_FIXTURE)).is_err()
        );
        assert!(
            decode_strict::<RememberIngressCandidateV2>(record(NEGATIVE_JSON_FIXTURE)).is_err()
        );

        assert!(CanonicalClaimTextV2::parse(" canonical ").is_err());
        assert!(CanonicalClaimTextV2::parse("line\nbreak").is_err());
        assert!(CanonicalClaimTextV2::parse("e\u{301}").is_err());
        let mut duplicate = candidate();
        duplicate.value = CanonicalClaimValueV2::StringSet {
            values: vec![
                CanonicalClaimTextV2::parse("alpha").unwrap(),
                CanonicalClaimTextV2::parse("alpha").unwrap(),
            ],
        };
        assert!(duplicate.validate_shape().is_err());
        let mut reversed = candidate();
        reversed.value = CanonicalClaimValueV2::StringSet {
            values: vec![
                CanonicalClaimTextV2::parse("zeta").unwrap(),
                CanonicalClaimTextV2::parse("alpha").unwrap(),
            ],
        };
        assert!(reversed.validate_shape().is_err());
    }

    #[test]
    fn authored_text_preserves_lf_and_tab_as_exact_utf8_bytes() {
        for exact in [
            "first line\n\tindented second line",
            "  leading authored spaces",
            "authored trailing spaces  ",
            "authored trailing LF\n",
            "authored trailing TAB\t",
        ] {
            let text = CanonicalAssertionTextV2::parse(exact).unwrap();
            assert_eq!(text.as_str(), exact);
            assert_eq!(text.as_bytes(), exact.as_bytes());
            let encoded = encode_canonical(&text).unwrap();
            assert_eq!(
                encoded,
                format!("[\"{}\"]", hex::encode(exact.as_bytes())).as_bytes()
            );
            let decoded: CanonicalAssertionTextV2 = decode_strict(&encoded).unwrap();
            assert_eq!(decoded, text);
        }

        let exact = "first line\n\tindented second line";

        let noncanonical_split = format!(
            "[\"{}\",\"{}\"]",
            hex::encode(&exact.as_bytes()[..2]),
            hex::encode(&exact.as_bytes()[2..])
        );
        assert!(decode_strict::<CanonicalAssertionTextV2>(noncanonical_split.as_bytes()).is_err());

        for invalid in [
            "   \n\t",
            "carriage\rreturn",
            "nul\0byte",
            "form\u{000c}feed",
            "private\u{e000}use",
            "noncharacter\u{fdd0}",
            "byte\u{feff}order",
        ] {
            assert!(CanonicalAssertionTextV2::parse(invalid).is_err());
        }
        let largest = CanonicalAssertionTextV2::parse("a".repeat(MAX_ASSERTION_TEXT_BYTES))
            .expect("maximum assertion text must remain encodable");
        encode_canonical(&largest).unwrap();
        let mut maximum_candidate = candidate();
        maximum_candidate.assertion_text_utf8_hex_chunks = largest;
        maximum_candidate.validate_shape().unwrap();
        assert!(CanonicalAssertionTextV2::parse("a".repeat(MAX_ASSERTION_TEXT_BYTES + 1)).is_err());
    }

    #[test]
    fn claim_meaning_and_attestation_identity_are_separate() {
        let base_claim = claim();
        let fingerprint = base_claim.fingerprint().unwrap();
        let key = base_claim.consistency_partition_key().unwrap();
        assert_eq!(key.family.as_str(), CLAIM_CONSISTENCY_FAMILY);

        let first = statement();
        let mut second = first.clone();
        second.actor.principal_id = ContractId::new("principal.second_operator").unwrap();
        second.support_evidence_event_ids = vec![support('7')];
        assert_eq!(first.claim_fingerprint, second.claim_fingerprint);
        assert_eq!(
            first.consistency_partition_key().unwrap(),
            second.consistency_partition_key().unwrap()
        );
        assert_ne!(
            first.accepted_event_id().unwrap(),
            second.accepted_event_id().unwrap()
        );

        let mut reworded = first.clone();
        reworded.assertion_text_utf8_hex_chunks =
            CanonicalAssertionTextV2::parse("Same proposition, independently authored wording.")
                .unwrap();
        assert_eq!(first.claim_fingerprint, reworded.claim_fingerprint);
        assert_ne!(
            first.accepted_event_id().unwrap(),
            reworded.accepted_event_id().unwrap()
        );

        let mut changed_value = base_claim.clone();
        changed_value.value = CanonicalClaimValueV2::Boolean { value: false };
        assert_ne!(fingerprint, changed_value.fingerprint().unwrap());
        assert_eq!(key, changed_value.consistency_partition_key().unwrap());

        let mut changed_head = base_claim.clone();
        changed_head.registry.head.activation_id = labelled_digest("activation.aba");
        assert_ne!(fingerprint, changed_head.fingerprint().unwrap());
        assert_eq!(key, changed_head.consistency_partition_key().unwrap());

        let mut changed_interval = base_claim;
        changed_interval.effective_interval.effective_from =
            CanonicalTimestamp::parse("2026-08-15T13:00:00.000000000Z").unwrap();
        assert_ne!(fingerprint, changed_interval.fingerprint().unwrap());
        assert_eq!(key, changed_interval.consistency_partition_key().unwrap());
    }

    #[test]
    fn semantic_coordinate_changes_only_for_comparison_dimensions() {
        let base = claim();
        let key = base.consistency_partition_key().unwrap();

        let mut subject = base.clone();
        subject.subject = resource(IdentityForm::Entity, "repository", '2');
        assert_ne!(key, subject.consistency_partition_key().unwrap());

        let mut predicate = base.clone();
        predicate.predicate_schema = reference("repository.default_branch");
        assert_ne!(key, predicate.consistency_partition_key().unwrap());

        let mut context = base;
        context.applicability[1].resource = resource(IdentityForm::Entity, "environment", '9');
        assert_ne!(key, context.consistency_partition_key().unwrap());
    }

    #[test]
    fn basis_modality_and_sets_fail_closed() {
        let mut invalid_basis = candidate();
        invalid_basis.requested_basis = RememberAdmissionBasisV2::RegisteredObserver {
            observer_admission: reference("observer.rust_enum"),
        };
        assert!(invalid_basis.validate_shape().is_err());

        let mut actor_without_citations = candidate();
        actor_without_citations.support_evidence_event_ids.clear();
        actor_without_citations.validate_shape().unwrap();

        let mut accepted_actor_without_citations = statement();
        accepted_actor_without_citations
            .support_evidence_event_ids
            .clear();
        accepted_actor_without_citations.validate_shape().unwrap();

        let mut observer_without_support = actor_without_citations;
        observer_without_support.modality = PropositionModalityV1::Observed;
        observer_without_support.requested_basis = RememberAdmissionBasisV2::RegisteredObserver {
            observer_admission: reference("observer.rust_enum"),
        };
        assert!(observer_without_support.validate_shape().is_err());

        let mut accepted_observer = statement();
        accepted_observer.claim.modality = PropositionModalityV1::Observed;
        accepted_observer.claim_fingerprint = accepted_observer.claim.fingerprint().unwrap();
        accepted_observer.admission_basis = RememberAdmissionBasisV2::RegisteredObserver {
            observer_admission: reference("observer.rust_enum"),
        };
        accepted_observer.validate_shape().unwrap();
        accepted_observer.support_evidence_event_ids.clear();
        assert!(accepted_observer.validate_shape().is_err());

        let mut accepted_normative = statement();
        accepted_normative.claim.modality = PropositionModalityV1::Normative;
        accepted_normative.claim_fingerprint = accepted_normative.claim.fingerprint().unwrap();
        accepted_normative.admission_basis = RememberAdmissionBasisV2::ActivatedNormativeBinding {
            binding_schema: reference("normative.binding.default"),
            binding_statement_id: labelled_digest("normative.statement"),
        };
        accepted_normative.support_evidence_event_ids.clear();
        accepted_normative.validate_shape().unwrap();

        let mut duplicate_support = candidate();
        duplicate_support.support_evidence_event_ids = vec![support('5'), support('5')];
        assert!(duplicate_support.validate_shape().is_err());

        let mut duplicate_dimension = candidate();
        duplicate_dimension.applicability[1].dimension_id =
            duplicate_dimension.applicability[0].dimension_id.clone();
        assert!(duplicate_dimension.validate_shape().is_err());

        let mut zero_support = candidate();
        zero_support.support_evidence_event_ids =
            vec![AcceptedEventId::from_digest(Sha256Digest::ZERO)];
        assert!(zero_support.validate_shape().is_err());

        let mut zero_reference = candidate();
        zero_reference.predicate_schema.entry_digest = Sha256Digest::ZERO;
        assert!(zero_reference.validate_shape().is_err());
    }

    #[test]
    fn fixed_profile_head_event_kind_and_fingerprint_bindings_fail_closed() {
        let mut wrong_kind = statement();
        wrong_kind.event_kind = ContractId::new("memory.claim.proposed").unwrap();
        assert!(wrong_kind.validate_shape().is_err());

        let mut wrong_profile = statement();
        wrong_profile.profile.profile_digest = labelled_digest("attacker.profile");
        wrong_profile.claim.profile = wrong_profile.profile.clone();
        assert!(wrong_profile.validate_shape().is_err());

        let mut mismatched_head = statement();
        mismatched_head.registry.head.activation_id = labelled_digest("other.activation");
        assert!(mismatched_head.validate_shape().is_err());

        let mut wrong_fingerprint = statement();
        wrong_fingerprint.claim_fingerprint =
            SemanticClaimFingerprintV2::from_digest(Sha256Digest::ZERO);
        assert!(wrong_fingerprint.validate_shape().is_err());

        let mut sub_microsecond = statement();
        sub_microsecond.claim.effective_interval.effective_from =
            CanonicalTimestamp::parse("2026-08-15T12:30:00.000000001Z").unwrap();
        assert!(sub_microsecond.validate_shape().is_err());
    }

    #[test]
    fn accepted_statement_excludes_all_receipt_and_append_coordinates() {
        let accepted = statement();
        accepted.validate_shape().unwrap();
        let encoded = encode_canonical(&accepted).unwrap();
        let text = std::str::from_utf8(&encoded).unwrap();
        for forbidden in [
            "\"id\"",
            "\"claim_id\"",
            "\"support_id\"",
            "\"idempotency_key\"",
            "\"accepted_at\"",
            "\"received_at\"",
            "\"created_at\"",
            "\"consistency_partition_key\"",
            "\"epoch_id\"",
            "\"shard\"",
            "\"committed_offset\"",
            "\"previous_chain_digest\"",
            "\"append_chain_digest\"",
        ] {
            assert!(
                !text.contains(forbidden),
                "forbidden event field {forbidden}"
            );
        }
    }

    #[test]
    fn structural_bytes_cannot_enter_the_append_typestate() {
        let decoded: RememberAcceptedStatementV2 =
            decode_strict(record(STATEMENT_FIXTURE)).unwrap();
        decoded.validate_shape().unwrap();
        let admitted = AdmittedRememberStatementV2::from_test_witness(decoded).unwrap();
        assert_eq!(
            admitted.statement().accepted_event_id().unwrap(),
            statement().accepted_event_id().unwrap()
        );
    }

    #[test]
    #[ignore = "maintainer-only canonical fixture regeneration"]
    #[allow(clippy::too_many_lines)]
    fn regenerate_remember_v2_contract_artifacts() {
        use std::{fs, path::Path};

        fn mutate_json<T: Serialize>(
            value: &T,
            mutate: impl FnOnce(&mut serde_json::Map<String, serde_json::Value>),
        ) -> Vec<u8> {
            let mut value = serde_json::to_value(value).unwrap();
            let object = value.as_object_mut().unwrap();
            mutate(object);
            serde_json::to_vec(&value).unwrap()
        }

        fn framed(bytes: &[u8]) -> Vec<u8> {
            let mut framed = bytes.to_vec();
            framed.push(b'\n');
            framed
        }

        fn write(output: &Path, name: &str, bytes: &[u8]) {
            fs::write(output.join(name), framed(bytes)).unwrap();
        }

        let output = std::env::var_os("REMEMBER_VECTOR_OUTPUT")
            .map(std::path::PathBuf::from)
            .expect("REMEMBER_VECTOR_OUTPUT is required");
        fs::create_dir_all(&output).unwrap();

        let candidate = candidate();
        let claim = claim();
        let statement = statement();
        let predicate_entry = predicate_entry();
        let admission_entry = admission_entry();
        write(
            &output,
            "remember-ingress-candidate-v2.jsonl",
            &encode_canonical(&candidate).unwrap(),
        );
        write(
            &output,
            "semantic-claim-v2.jsonl",
            &encode_canonical(&claim).unwrap(),
        );
        write(
            &output,
            "remember-accepted-statement-v2.jsonl",
            &encode_canonical(&statement).unwrap(),
        );
        write(
            &output,
            "remember-predicate-schema-v2-entry.jsonl",
            &encode_canonical(&predicate_entry).unwrap(),
        );
        write(
            &output,
            "remember-admission-rule-v2-entry.jsonl",
            &encode_canonical(&admission_entry).unwrap(),
        );
        for (name, manifest) in [
            (
                "predicate-positive-cases-v2.jsonl",
                predicate_positive_cases(),
            ),
            (
                "predicate-negative-cases-v2.jsonl",
                predicate_negative_cases(),
            ),
            (
                "admission-positive-cases-v2.jsonl",
                admission_positive_cases(),
            ),
            (
                "admission-negative-cases-v2.jsonl",
                admission_negative_cases(),
            ),
        ] {
            write(&output, name, &encode_canonical(&manifest).unwrap());
        }

        let floating = mutate_json(&candidate, |object| {
            object.insert(
                "value".into(),
                serde_json::from_str(r#"{"kind":"canonical_decimal","value":0.5}"#).unwrap(),
            );
        });
        let arbitrary_json = mutate_json(&candidate, |object| {
            object.insert(
                "value".into(),
                serde_json::from_str(r#"{"kind":"json","value":{"nested":true}}"#).unwrap(),
            );
        });
        let ingress_authority = mutate_json(&candidate, |object| {
            object.insert("actor".into(), serde_json::Value::from(42));
        });
        let numeric_support = mutate_json(&candidate, |object| {
            object.insert(
                "support_evidence_event_ids".into(),
                serde_json::Value::Array(vec![serde_json::Value::from(7)]),
            );
        });
        let physical_statement = mutate_json(&statement, |object| {
            object.insert(
                "accepted_at".into(),
                serde_json::Value::String("2026-08-15T12:31:00.000000000Z".into()),
            );
            object.insert("claim_id".into(), serde_json::Value::from(99));
            object.insert("shard".into(), serde_json::Value::from(3));
        });
        let mut wrong_subject_form = candidate.clone();
        wrong_subject_form.asserted_subject = resource(IdentityForm::Version, "repository", '1');
        let mut wrong_environment_form = candidate;
        wrong_environment_form.applicability[1].resource =
            resource(IdentityForm::Version, "environment", '4');
        for bytes in [
            arbitrary_json.as_slice(),
            ingress_authority.as_slice(),
            numeric_support.as_slice(),
            physical_statement.as_slice(),
        ] {
            require_canonical(bytes).unwrap();
        }
        write(&output, "negative-floating-value.jsonl", &floating);
        write(
            &output,
            "negative-arbitrary-json-value.jsonl",
            &arbitrary_json,
        );
        write(
            &output,
            "negative-ingress-authority-fields.jsonl",
            &ingress_authority,
        );
        write(
            &output,
            "negative-numeric-support-id.jsonl",
            &numeric_support,
        );
        write(
            &output,
            "negative-statement-physical-fields.jsonl",
            &physical_statement,
        );
        write(
            &output,
            "negative-subject-identity-form.jsonl",
            &encode_canonical(&wrong_subject_form).unwrap(),
        );
        write(
            &output,
            "negative-environment-identity-form.jsonl",
            &encode_canonical(&wrong_environment_form).unwrap(),
        );

        write(
            &output,
            "negative-predicate-dimension-identity-entry.jsonl",
            &encode_canonical(&negative_predicate_dimension_identity_entry()).unwrap(),
        );
        write(
            &output,
            "negative-predicate-resource-value-entry.jsonl",
            &encode_canonical(&negative_predicate_resource_value_entry()).unwrap(),
        );
        let predicate_public = mutate_json(&predicate_entry, |object| {
            object
                .get_mut("body")
                .and_then(serde_json::Value::as_object_mut)
                .unwrap()
                .insert(
                    "publication_default".into(),
                    serde_json::Value::String("public".into()),
                );
        });
        require_canonical(&predicate_public).unwrap();
        write(
            &output,
            "negative-predicate-public-default-entry.jsonl",
            &predicate_public,
        );
        write(
            &output,
            "negative-admission-observer-open-entry.jsonl",
            &encode_canonical(&negative_admission_observer_open_entry()).unwrap(),
        );
        write(
            &output,
            "negative-admission-payload-authority-entry.jsonl",
            &encode_canonical(&negative_admission_payload_authority_entry()).unwrap(),
        );
        write(
            &output,
            "negative-admission-duplicate-basis-entry.jsonl",
            &encode_canonical(&negative_admission_duplicate_basis_entry()).unwrap(),
        );
        write(
            &output,
            "negative-admission-basis-modality-entry.jsonl",
            &encode_canonical(&negative_admission_basis_modality_entry()).unwrap(),
        );

        let coordinate_id = claim.coordinate().coordinate_id().unwrap();
        let claim_fingerprint = claim.fingerprint().unwrap();
        let accepted_event_id = statement.accepted_event_id().unwrap();
        let suite = RememberVectorSuiteV2 {
            schema_version: 2,
            fixture_authority: "none; structural fixtures are assertions, not active-package or admission witnesses".into(),
            claim_coordinate_id: coordinate_id,
            semantic_claim_fingerprint: claim_fingerprint,
            accepted_event_id,
            predicate_registry_entry_digest: predicate_entry.digest().unwrap(),
            admission_registry_entry_digest: admission_entry.digest().unwrap(),
            predicate_positive_cases_digest: predicate_entry.positive_vector_digest,
            predicate_negative_cases_digest: predicate_entry.negative_vector_digest,
            admission_positive_cases_digest: admission_entry.positive_vector_digest,
            admission_negative_cases_digest: admission_entry.negative_vector_digest,
            consistency_key_family: ContractId::new(CLAIM_CONSISTENCY_FAMILY).unwrap(),
            consistency_key_digest: coordinate_id.digest(),
            negative_cases: [
                "admission_basis_modality",
                "admission_duplicate_basis_key",
                "admission_observer_open",
                "admission_payload_authority",
                "arbitrary_json_value",
                "floating_value",
                "ingress_authority_fields",
                "numeric_support_id",
                "predicate_dimension_identity",
                "predicate_public_default",
                "predicate_resource_value",
                "runtime_environment_identity_form",
                "statement_physical_fields",
                "subject_identity_form",
            ]
            .into_iter()
            .map(|value| ContractId::new(value).unwrap())
            .collect(),
        };
        let suite_bytes = encode_canonical(&suite).unwrap();
        write(&output, "vector-suite.jsonl", &suite_bytes);

        println!("claim_coordinate_id={coordinate_id}");
        println!("semantic_claim_fingerprint={claim_fingerprint}");
        println!("accepted_event_id={accepted_event_id}");
        println!(
            "vector_suite_digest={}",
            domain_separated_digest(DigestDomain::TestVectorManifest, &suite_bytes)
        );
    }
}
