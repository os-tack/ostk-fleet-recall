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
#[path = "remember_v2_tests.rs"]
mod tests;
