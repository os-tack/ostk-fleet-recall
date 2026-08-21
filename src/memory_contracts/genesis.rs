//! Semantic closure for one offline genesis registry package.
//!
//! [`ManifestVerifiedRegistryPackage`] proves byte, ordering, and digest
//! closure. This module adds the next offline-only typestate: every entry body
//! must decode through one closed kind-specific schema, all defaults must be
//! present explicitly in those bytes, and every declared dependency must
//! resolve to the exact kind, ID, version, and digest in the same package.
//!
//! Semantic closure is deliberately not activation. It establishes neither a
//! trusted bootstrap receipt nor a current registry head, and it performs no
//! database, network, clock, signature, or runtime work.

use serde::{Deserialize, Serialize, de::DeserializeOwned};

use super::{
    ContractError, ContractResult,
    canonical::{CanonicalValue, decode_strict, encode_canonical},
    common::{ContractId, RegistryReferenceV1},
    digest::Sha256Digest,
    evidence::{PublicationClass, RetentionClass, VisibilityClass},
    identity::{
        AuthorityNamespaceV1, IdentityForm, IdentityRecipeV1, MAX_LOCATOR_COMPONENTS,
        ResourceKindSchemaV1, ValidatedIdentityRecipe,
    },
    registry::{
        ManifestVerifiedRegistryPackage, RegistryEntryKind, RegistryEntryV1, RegistryPackageV1,
    },
};

const GENESIS_ENTRY_SCHEMA_VERSION: u32 = 1;
const MAX_SMALL_SET: usize = 256;
const MAX_NORMATIVE_SOURCE_SPANS: u16 = 256;
const MAX_NORMATIVE_PROPOSITIONS: u16 = 256;

/// Every kind is required in the v1 genesis package so later stages cannot
/// silently invent a missing contract from source-code defaults.
pub const REQUIRED_GENESIS_KINDS: [RegistryEntryKind; 20] = [
    RegistryEntryKind::ActivationPolicy,
    RegistryEntryKind::ApplicabilityEvaluator,
    RegistryEntryKind::AuthorityRule,
    RegistryEntryKind::CausalRatificationPolicy,
    RegistryEntryKind::ClassifierPolicy,
    RegistryEntryKind::ConnectorSchema,
    RegistryEntryKind::CoverageProof,
    RegistryEntryKind::EpisodePolicy,
    RegistryEntryKind::EvidenceSchema,
    RegistryEntryKind::ExemplarPolicy,
    RegistryEntryKind::IdentityRecipe,
    RegistryEntryKind::NamespaceDefinition,
    RegistryEntryKind::NormativeBindingSchema,
    RegistryEntryKind::ObserverAdmission,
    RegistryEntryKind::PredicateSchema,
    RegistryEntryKind::PublicationRule,
    RegistryEntryKind::RedactionPolicy,
    RegistryEntryKind::RelationProof,
    RegistryEntryKind::ResourceKindSchema,
    RegistryEntryKind::RetentionPolicy,
];

/// These are package-wide v1 roots. Genesis contains exactly one of each;
/// later package versions may replace this rule with an explicit root map.
///
/// This is an explicit Stage-1 assumption, not a claim that every policy kind
/// is globally singleton: authority, coverage, episode, exemplar, observer,
/// predicate, relation, namespace, resource-kind, and identity entries may all
/// have multiple instances.
pub const REQUIRED_SINGLETON_KINDS: [RegistryEntryKind; 4] = [
    RegistryEntryKind::ActivationPolicy,
    RegistryEntryKind::ApplicabilityEvaluator,
    RegistryEntryKind::NormativeBindingSchema,
    RegistryEntryKind::PublicationRule,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownOutcomeV1 {
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityOutcomeV1 {
    Provisional,
    Verified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CausalSupportLevelV1 {
    InterventionSupported,
    MechanisticallyCorroborated,
    Possible,
    ScopeAssociated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageMethodV1 {
    ClosedCursorInterval,
    EnumeratedSnapshot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EpisodeWindowModeV1 {
    NonWindowed,
    Windowed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExemplarSelectorV1 {
    DeterministicStratifiedHashV1,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObserverAdmissionModeV1 {
    CandidateOnly,
    ClosedWorldVerified,
    PositiveVerified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PropositionModalityV1 {
    Attested,
    Intended,
    Normative,
    Observed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PredicateValueKindV1 {
    Boolean,
    CanonicalDecimal,
    ContractId,
    ResourceUri,
    Sha256Digest,
    String,
    StringSet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PredicateComparatorV1 {
    ExactEquality,
    NumericThreshold,
    SetEquality,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AbsenceSemanticsV1 {
    ClosedWorldWithCoverage,
    OpenWorld,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicationDefaultV1 {
    Denied,
    PrivateOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensitivityDefaultV1 {
    Private,
    Project,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationMultiplicityV1 {
    ManyToMany,
    ManyToOne,
    OneToMany,
    OneToOne,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationProofMethodV1 {
    ExactProviderIdentifiers,
    RegisteredVerifier,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyFailureOutcomeV1 {
    Withhold,
}

/// `None` is encoded explicitly rather than materialized from a missing field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum RatificationRequirementV1 {
    None,
    Required { policy: RegistryReferenceV1 },
}

/// Candidate-only observers explicitly encode that exhaustive coverage is not
/// required; verified modes bind one exact proof entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum CoverageRequirementV1 {
    NotRequired,
    Required { proof: RegistryReferenceV1 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationPolicyEntryV1 {
    schema_version: u32,
    policy_id: ContractId,
    version: u32,
    eligible_principal_ids: Vec<ContractId>,
    approval_threshold: u16,
    separation_of_duty_required: bool,
    self_authorization_allowed: bool,
    break_glass_enabled: bool,
}

impl ActivationPolicyEntryV1 {
    pub const fn approval_threshold(&self) -> u16 {
        self.approval_threshold
    }

    pub fn eligible_principal_ids(&self) -> &[ContractId] {
        &self.eligible_principal_ids
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicabilityEvaluatorEntryV1 {
    schema_version: u32,
    evaluator_id: ContractId,
    version: u32,
    missing_dimension_outcome: UnknownOutcomeV1,
    null_dimension_outcome: UnknownOutcomeV1,
    explicit_any_enabled: bool,
    same_concrete_context_required: bool,
    receipt_order_tiebreaker_allowed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityRuleEntryV1 {
    schema_version: u32,
    rule_id: ContractId,
    version: u32,
    predicate_schema: RegistryReferenceV1,
    applicability_evaluator: RegistryReferenceV1,
    admissible_evidence_kind: ContractId,
    admissible_modality: PropositionModalityV1,
    provider_namespace: RegistryReferenceV1,
    evidence_schema: RegistryReferenceV1,
    observer_admission: RegistryReferenceV1,
    maximum_outcome: AuthorityOutcomeV1,
    ratification: RatificationRequirementV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CausalRatificationPolicyEntryV1 {
    schema_version: u32,
    policy_id: ContractId,
    version: u32,
    approval_policy: RegistryReferenceV1,
    minimum_positive_support: CausalSupportLevelV1,
    approval_threshold: u16,
    separation_of_duty_required: bool,
    agent_exception_allowed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClassifierPolicyEntryV1 {
    schema_version: u32,
    policy_id: ContractId,
    version: u32,
    server_derived: bool,
    classify_before_projection: bool,
    default_visibility: VisibilityClass,
    default_publication: PublicationClass,
    failure_outcome: PolicyFailureOutcomeV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorSchemaEntryV1 {
    schema_version: u32,
    connector_schema_id: ContractId,
    version: u32,
    provider_namespace: RegistryReferenceV1,
    evidence_schema: RegistryReferenceV1,
    identity_recipe: RegistryReferenceV1,
    authenticated_scope_required: bool,
    delivery_id_in_semantic_identity: bool,
    immutable_revision_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)] // each proof property is independently identity-bearing
pub struct CoverageProofEntryV1 {
    schema_version: u32,
    proof_id: ContractId,
    version: u32,
    method: CoverageMethodV1,
    complete_required_for_absence: bool,
    current_required_for_absence: bool,
    contiguous_required_when_sequenced: bool,
    receipt_order_establishes_provider_order: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpisodePolicyEntryV1 {
    schema_version: u32,
    policy_id: ContractId,
    version: u32,
    predicate_schema: RegistryReferenceV1,
    applicability_evaluator: RegistryReferenceV1,
    window_mode: EpisodeWindowModeV1,
    allowed_missing_windows: u16,
    missing_window_proves_recovery: bool,
    alert_closure_resolves_episode: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceSchemaEntryV1 {
    schema_version: u32,
    evidence_schema_id: ContractId,
    version: u32,
    evidence_kind: ContractId,
    identity_recipe: RegistryReferenceV1,
    redaction_policy: RegistryReferenceV1,
    classifier_policy: RegistryReferenceV1,
    retention_policy: RegistryReferenceV1,
    publication_rule: RegistryReferenceV1,
    canonical_payload_required: bool,
    private_raw_default_enabled: bool,
}

impl EvidenceSchemaEntryV1 {
    pub(crate) const fn identity_recipe(&self) -> &RegistryReferenceV1 {
        &self.identity_recipe
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExemplarPolicyEntryV1 {
    schema_version: u32,
    policy_id: ContractId,
    version: u32,
    selector: ExemplarSelectorV1,
    private_max_count: u16,
    private_max_each_bytes: u16,
    private_max_total_bytes: u16,
    public_enabled: bool,
    public_max_count: u16,
    public_max_each_bytes: u16,
    public_max_total_bytes: u16,
    raw_lines_allowed: bool,
    headers_allowed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormativeBindingSchemaEntryV1 {
    schema_version: u32,
    binding_schema_id: ContractId,
    version: u32,
    activation_policy: RegistryReferenceV1,
    applicability_evaluator: RegistryReferenceV1,
    exact_source_binding_required: bool,
    separation_of_duty_required: bool,
    retroactive_correction_allowed_by_default: bool,
    maximum_source_spans: u16,
    maximum_propositions: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObserverAdmissionEntryV1 {
    schema_version: u32,
    observer_id: ContractId,
    version: u32,
    predicate_schema: RegistryReferenceV1,
    evidence_schema: RegistryReferenceV1,
    provider_namespace: RegistryReferenceV1,
    admission_mode: ObserverAdmissionModeV1,
    coverage: CoverageRequirementV1,
    executable_artifact_digest: Sha256Digest,
    dependency_closure_digest: Sha256Digest,
    configuration_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PredicateSchemaEntryV1 {
    schema_version: u32,
    predicate_id: ContractId,
    version: u32,
    value_kind: PredicateValueKindV1,
    unit_id: ContractId,
    allowed_modalities: Vec<PropositionModalityV1>,
    comparator: PredicateComparatorV1,
    applicability_evaluator: RegistryReferenceV1,
    required_dimensions: Vec<ContractId>,
    absence_semantics: AbsenceSemanticsV1,
    coverage_proof: Option<RegistryReferenceV1>,
    publication_default: PublicationDefaultV1,
    sensitivity_default: SensitivityDefaultV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationRuleEntryV1 {
    schema_version: u32,
    rule_id: ContractId,
    version: u32,
    exemplar_policy: RegistryReferenceV1,
    default_publication: PublicationDefaultV1,
    classification_before_projection_required: bool,
    private_material_allowed: bool,
    raw_content_references_allowed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactionPolicyEntryV1 {
    schema_version: u32,
    policy_id: ContractId,
    version: u32,
    redact_before_durable_outbox: bool,
    secrets_allowed_in_recall: bool,
    failure_outcome: PolicyFailureOutcomeV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelationProofEntryV1 {
    schema_version: u32,
    relation_id: ContractId,
    version: u32,
    from_resource_kind: RegistryReferenceV1,
    to_resource_kind: RegistryReferenceV1,
    authority_rule: RegistryReferenceV1,
    predicate_schema: RegistryReferenceV1,
    admissible_modality: PropositionModalityV1,
    observer_admission: RegistryReferenceV1,
    proof_method: RelationProofMethodV1,
    multiplicity: RelationMultiplicityV1,
    temporal_overlap_required: bool,
    payload_may_select_verified_state: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionPolicyEntryV1 {
    schema_version: u32,
    policy_id: ContractId,
    version: u32,
    default_retention: RetentionClass,
    erasure_index_required: bool,
    tombstones_before_restore: bool,
    private_raw_separate_key: bool,
    failure_outcome: PolicyFailureOutcomeV1,
}

/// One body decoded through the schema selected by its manifest kind. Variant
/// fields remain immutable behind a shared reference once the package closes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SemanticallyDecodedGenesisEntryV1 {
    ActivationPolicy(ActivationPolicyEntryV1),
    ApplicabilityEvaluator(ApplicabilityEvaluatorEntryV1),
    AuthorityRule(AuthorityRuleEntryV1),
    CausalRatificationPolicy(CausalRatificationPolicyEntryV1),
    ClassifierPolicy(ClassifierPolicyEntryV1),
    ConnectorSchema(ConnectorSchemaEntryV1),
    CoverageProof(CoverageProofEntryV1),
    EpisodePolicy(EpisodePolicyEntryV1),
    EvidenceSchema(EvidenceSchemaEntryV1),
    ExemplarPolicy(ExemplarPolicyEntryV1),
    IdentityRecipe(IdentityRecipeV1),
    NamespaceDefinition(AuthorityNamespaceV1),
    NormativeBindingSchema(NormativeBindingSchemaEntryV1),
    ObserverAdmission(ObserverAdmissionEntryV1),
    PredicateSchema(PredicateSchemaEntryV1),
    PublicationRule(PublicationRuleEntryV1),
    RedactionPolicy(RedactionPolicyEntryV1),
    RelationProof(RelationProofEntryV1),
    ResourceKindSchema(ResourceKindSchemaV1),
    RetentionPolicy(RetentionPolicyEntryV1),
}

impl SemanticallyDecodedGenesisEntryV1 {
    pub const fn kind(&self) -> RegistryEntryKind {
        match self {
            Self::ActivationPolicy(_) => RegistryEntryKind::ActivationPolicy,
            Self::ApplicabilityEvaluator(_) => RegistryEntryKind::ApplicabilityEvaluator,
            Self::AuthorityRule(_) => RegistryEntryKind::AuthorityRule,
            Self::CausalRatificationPolicy(_) => RegistryEntryKind::CausalRatificationPolicy,
            Self::ClassifierPolicy(_) => RegistryEntryKind::ClassifierPolicy,
            Self::ConnectorSchema(_) => RegistryEntryKind::ConnectorSchema,
            Self::CoverageProof(_) => RegistryEntryKind::CoverageProof,
            Self::EpisodePolicy(_) => RegistryEntryKind::EpisodePolicy,
            Self::EvidenceSchema(_) => RegistryEntryKind::EvidenceSchema,
            Self::ExemplarPolicy(_) => RegistryEntryKind::ExemplarPolicy,
            Self::IdentityRecipe(_) => RegistryEntryKind::IdentityRecipe,
            Self::NamespaceDefinition(_) => RegistryEntryKind::NamespaceDefinition,
            Self::NormativeBindingSchema(_) => RegistryEntryKind::NormativeBindingSchema,
            Self::ObserverAdmission(_) => RegistryEntryKind::ObserverAdmission,
            Self::PredicateSchema(_) => RegistryEntryKind::PredicateSchema,
            Self::PublicationRule(_) => RegistryEntryKind::PublicationRule,
            Self::RedactionPolicy(_) => RegistryEntryKind::RedactionPolicy,
            Self::RelationProof(_) => RegistryEntryKind::RelationProof,
            Self::ResourceKindSchema(_) => RegistryEntryKind::ResourceKindSchema,
            Self::RetentionPolicy(_) => RegistryEntryKind::RetentionPolicy,
        }
    }

    pub const fn entry_id(&self) -> &ContractId {
        match self {
            Self::ActivationPolicy(value) => &value.policy_id,
            Self::ApplicabilityEvaluator(value) => &value.evaluator_id,
            Self::AuthorityRule(value) => &value.rule_id,
            Self::CausalRatificationPolicy(value) => &value.policy_id,
            Self::ClassifierPolicy(value) => &value.policy_id,
            Self::ConnectorSchema(value) => &value.connector_schema_id,
            Self::CoverageProof(value) => &value.proof_id,
            Self::EpisodePolicy(value) => &value.policy_id,
            Self::EvidenceSchema(value) => &value.evidence_schema_id,
            Self::ExemplarPolicy(value) => &value.policy_id,
            Self::IdentityRecipe(value) => &value.recipe_id,
            Self::NamespaceDefinition(value) => &value.namespace_id,
            Self::NormativeBindingSchema(value) => &value.binding_schema_id,
            Self::ObserverAdmission(value) => &value.observer_id,
            Self::PredicateSchema(value) => &value.predicate_id,
            Self::PublicationRule(value) => &value.rule_id,
            Self::RedactionPolicy(value) => &value.policy_id,
            Self::RelationProof(value) => &value.relation_id,
            Self::ResourceKindSchema(value) => &value.resource_kind,
            Self::RetentionPolicy(value) => &value.policy_id,
        }
    }

    pub const fn body_version(&self) -> Option<u32> {
        match self {
            Self::ActivationPolicy(value) => Some(value.version),
            Self::ApplicabilityEvaluator(value) => Some(value.version),
            Self::AuthorityRule(value) => Some(value.version),
            Self::CausalRatificationPolicy(value) => Some(value.version),
            Self::ClassifierPolicy(value) => Some(value.version),
            Self::ConnectorSchema(value) => Some(value.version),
            Self::CoverageProof(value) => Some(value.version),
            Self::EpisodePolicy(value) => Some(value.version),
            Self::EvidenceSchema(value) => Some(value.version),
            Self::ExemplarPolicy(value) => Some(value.version),
            Self::IdentityRecipe(value) => Some(value.version),
            Self::NamespaceDefinition(value) => Some(value.version),
            Self::NormativeBindingSchema(value) => Some(value.version),
            Self::ObserverAdmission(value) => Some(value.version),
            Self::PredicateSchema(value) => Some(value.version),
            Self::PublicationRule(value) => Some(value.version),
            Self::RedactionPolicy(value) => Some(value.version),
            Self::RelationProof(value) => Some(value.version),
            Self::ResourceKindSchema(value) => Some(value.version),
            Self::RetentionPolicy(value) => Some(value.version),
        }
    }
}

/// Offline package with a verified manifest and semantic dependency graph.
///
/// This typestate does not imply bootstrap acceptance, activation, uncontested
/// history, or runtime authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticallyClosedGenesisPackage {
    manifest_verified: ManifestVerifiedRegistryPackage,
    entries: Vec<SemanticallyDecodedGenesisEntryV1>,
    activation_policy_index: usize,
    applicability_evaluator_index: usize,
    normative_binding_schema_index: usize,
    publication_rule_index: usize,
}

impl SemanticallyClosedGenesisPackage {
    /// Consume a manifest-verified package and close its semantic graph.
    pub fn from_manifest_verified(
        manifest_verified: ManifestVerifiedRegistryPackage,
    ) -> ContractResult<Self> {
        validate_kind_cardinality(manifest_verified.package())?;

        let mut entries = Vec::with_capacity(manifest_verified.package().entries.len());
        for entry in &manifest_verified.package().entries {
            entries.push(decode_entry(entry)?);
        }

        for (registry_entry, decoded) in manifest_verified.package().entries.iter().zip(&entries) {
            validate_entry_identity(registry_entry, decoded)?;
            validate_entry_semantics(&manifest_verified, registry_entry, decoded)?;
        }

        let activation_policy_index =
            singleton_index(&entries, RegistryEntryKind::ActivationPolicy)?;
        let applicability_evaluator_index =
            singleton_index(&entries, RegistryEntryKind::ApplicabilityEvaluator)?;
        let normative_binding_schema_index =
            singleton_index(&entries, RegistryEntryKind::NormativeBindingSchema)?;
        let publication_rule_index = singleton_index(&entries, RegistryEntryKind::PublicationRule)?;

        Ok(Self {
            manifest_verified,
            entries,
            activation_policy_index,
            applicability_evaluator_index,
            normative_binding_schema_index,
            publication_rule_index,
        })
    }

    pub const fn manifest_verified_package(&self) -> &ManifestVerifiedRegistryPackage {
        &self.manifest_verified
    }

    pub const fn package_digest(&self) -> Sha256Digest {
        self.manifest_verified.package_digest()
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        self.manifest_verified.canonical_bytes()
    }

    pub fn entries(&self) -> &[SemanticallyDecodedGenesisEntryV1] {
        &self.entries
    }

    pub fn entry(
        &self,
        kind: RegistryEntryKind,
        entry_id: &ContractId,
        version: u32,
    ) -> Option<&SemanticallyDecodedGenesisEntryV1> {
        self.manifest_verified
            .package()
            .entries
            .iter()
            .zip(&self.entries)
            .find(|(raw, decoded)| {
                raw.kind == kind
                    && raw.entry_id == *entry_id
                    && raw.version == version
                    && decoded.kind() == kind
            })
            .map(|(_, decoded)| decoded)
    }

    pub fn activation_policy(&self) -> &ActivationPolicyEntryV1 {
        match &self.entries[self.activation_policy_index] {
            SemanticallyDecodedGenesisEntryV1::ActivationPolicy(value) => value,
            _ => unreachable!("singleton index is established during semantic closure"),
        }
    }

    pub fn applicability_evaluator(&self) -> &ApplicabilityEvaluatorEntryV1 {
        match &self.entries[self.applicability_evaluator_index] {
            SemanticallyDecodedGenesisEntryV1::ApplicabilityEvaluator(value) => value,
            _ => unreachable!("singleton index is established during semantic closure"),
        }
    }

    pub fn normative_binding_schema(&self) -> &NormativeBindingSchemaEntryV1 {
        match &self.entries[self.normative_binding_schema_index] {
            SemanticallyDecodedGenesisEntryV1::NormativeBindingSchema(value) => value,
            _ => unreachable!("singleton index is established during semantic closure"),
        }
    }

    pub fn publication_rule(&self) -> &PublicationRuleEntryV1 {
        match &self.entries[self.publication_rule_index] {
            SemanticallyDecodedGenesisEntryV1::PublicationRule(value) => value,
            _ => unreachable!("singleton index is established during semantic closure"),
        }
    }
}

impl TryFrom<ManifestVerifiedRegistryPackage> for SemanticallyClosedGenesisPackage {
    type Error = ContractError;

    fn try_from(value: ManifestVerifiedRegistryPackage) -> Result<Self, Self::Error> {
        Self::from_manifest_verified(value)
    }
}

#[allow(clippy::too_many_lines)] // exhaustive closed-schema dispatch is intentional and auditable
/// Decode one exact legacy registry body through the closed v1 selector.
///
/// This crate-private seam is reusable by later offline package typestates. It
/// proves body shape only; callers must also invoke the identity and semantic
/// validators below against the same manifest-verified package.
pub(crate) fn decode_entry(
    entry: &RegistryEntryV1,
) -> ContractResult<SemanticallyDecodedGenesisEntryV1> {
    if entry.kind.is_generation2_only() {
        return Err(generation2_only_kind_error(entry));
    }
    validate_entry_schema_selector(entry)?;
    reject_dynamic_policy_constructs(&entry.body)?;

    Ok(match entry.kind {
        RegistryEntryKind::ActivationPolicy => {
            require_exact_fields(
                &entry.body,
                &[
                    "approval_threshold",
                    "break_glass_enabled",
                    "eligible_principal_ids",
                    "policy_id",
                    "schema_version",
                    "self_authorization_allowed",
                    "separation_of_duty_required",
                    "version",
                ],
            )?;
            SemanticallyDecodedGenesisEntryV1::ActivationPolicy(decode_body(&entry.body)?)
        }
        RegistryEntryKind::ApplicabilityEvaluator => {
            require_exact_fields(
                &entry.body,
                &[
                    "evaluator_id",
                    "explicit_any_enabled",
                    "missing_dimension_outcome",
                    "null_dimension_outcome",
                    "receipt_order_tiebreaker_allowed",
                    "same_concrete_context_required",
                    "schema_version",
                    "version",
                ],
            )?;
            SemanticallyDecodedGenesisEntryV1::ApplicabilityEvaluator(decode_body(&entry.body)?)
        }
        RegistryEntryKind::AuthorityRule => {
            require_exact_fields(
                &entry.body,
                &[
                    "admissible_evidence_kind",
                    "admissible_modality",
                    "applicability_evaluator",
                    "evidence_schema",
                    "maximum_outcome",
                    "observer_admission",
                    "predicate_schema",
                    "provider_namespace",
                    "ratification",
                    "rule_id",
                    "schema_version",
                    "version",
                ],
            )?;
            SemanticallyDecodedGenesisEntryV1::AuthorityRule(decode_body(&entry.body)?)
        }
        RegistryEntryKind::CausalRatificationPolicy => {
            require_exact_fields(
                &entry.body,
                &[
                    "agent_exception_allowed",
                    "approval_policy",
                    "approval_threshold",
                    "minimum_positive_support",
                    "policy_id",
                    "schema_version",
                    "separation_of_duty_required",
                    "version",
                ],
            )?;
            SemanticallyDecodedGenesisEntryV1::CausalRatificationPolicy(decode_body(&entry.body)?)
        }
        RegistryEntryKind::ClassifierPolicy => {
            require_exact_fields(
                &entry.body,
                &[
                    "classify_before_projection",
                    "default_publication",
                    "default_visibility",
                    "failure_outcome",
                    "policy_id",
                    "schema_version",
                    "server_derived",
                    "version",
                ],
            )?;
            SemanticallyDecodedGenesisEntryV1::ClassifierPolicy(decode_body(&entry.body)?)
        }
        RegistryEntryKind::ConnectorSchema => {
            require_exact_fields(
                &entry.body,
                &[
                    "authenticated_scope_required",
                    "connector_schema_id",
                    "delivery_id_in_semantic_identity",
                    "evidence_schema",
                    "identity_recipe",
                    "immutable_revision_required",
                    "provider_namespace",
                    "schema_version",
                    "version",
                ],
            )?;
            SemanticallyDecodedGenesisEntryV1::ConnectorSchema(decode_body(&entry.body)?)
        }
        RegistryEntryKind::CoverageProof => {
            require_exact_fields(
                &entry.body,
                &[
                    "complete_required_for_absence",
                    "contiguous_required_when_sequenced",
                    "current_required_for_absence",
                    "method",
                    "proof_id",
                    "receipt_order_establishes_provider_order",
                    "schema_version",
                    "version",
                ],
            )?;
            SemanticallyDecodedGenesisEntryV1::CoverageProof(decode_body(&entry.body)?)
        }
        RegistryEntryKind::EpisodePolicy => {
            require_exact_fields(
                &entry.body,
                &[
                    "alert_closure_resolves_episode",
                    "allowed_missing_windows",
                    "applicability_evaluator",
                    "missing_window_proves_recovery",
                    "policy_id",
                    "predicate_schema",
                    "schema_version",
                    "version",
                    "window_mode",
                ],
            )?;
            SemanticallyDecodedGenesisEntryV1::EpisodePolicy(decode_body(&entry.body)?)
        }
        RegistryEntryKind::EvidenceSchema => {
            require_exact_fields(
                &entry.body,
                &[
                    "canonical_payload_required",
                    "classifier_policy",
                    "evidence_kind",
                    "evidence_schema_id",
                    "identity_recipe",
                    "private_raw_default_enabled",
                    "publication_rule",
                    "redaction_policy",
                    "retention_policy",
                    "schema_version",
                    "version",
                ],
            )?;
            SemanticallyDecodedGenesisEntryV1::EvidenceSchema(decode_body(&entry.body)?)
        }
        RegistryEntryKind::ExemplarPolicy => {
            require_exact_fields(
                &entry.body,
                &[
                    "headers_allowed",
                    "policy_id",
                    "private_max_count",
                    "private_max_each_bytes",
                    "private_max_total_bytes",
                    "public_enabled",
                    "public_max_count",
                    "public_max_each_bytes",
                    "public_max_total_bytes",
                    "raw_lines_allowed",
                    "schema_version",
                    "selector",
                    "version",
                ],
            )?;
            SemanticallyDecodedGenesisEntryV1::ExemplarPolicy(decode_body(&entry.body)?)
        }
        RegistryEntryKind::IdentityRecipe => {
            require_exact_fields(
                &entry.body,
                &[
                    "authority_namespace",
                    "component_rules",
                    "identity_form",
                    "recipe_id",
                    "resource_kind",
                    "resource_kind_schema",
                    "schema_version",
                    "version",
                ],
            )?;
            SemanticallyDecodedGenesisEntryV1::IdentityRecipe(decode_body(&entry.body)?)
        }
        RegistryEntryKind::NamespaceDefinition => {
            require_exact_fields(
                &entry.body,
                &[
                    "immutable_coordinate_keys",
                    "namespace_id",
                    "schema_version",
                    "version",
                ],
            )?;
            SemanticallyDecodedGenesisEntryV1::NamespaceDefinition(decode_body(&entry.body)?)
        }
        RegistryEntryKind::NormativeBindingSchema => {
            require_exact_fields(
                &entry.body,
                &[
                    "activation_policy",
                    "applicability_evaluator",
                    "binding_schema_id",
                    "exact_source_binding_required",
                    "maximum_propositions",
                    "maximum_source_spans",
                    "retroactive_correction_allowed_by_default",
                    "schema_version",
                    "separation_of_duty_required",
                    "version",
                ],
            )?;
            SemanticallyDecodedGenesisEntryV1::NormativeBindingSchema(decode_body(&entry.body)?)
        }
        RegistryEntryKind::ObserverAdmission => {
            require_exact_fields(
                &entry.body,
                &[
                    "admission_mode",
                    "configuration_digest",
                    "coverage",
                    "dependency_closure_digest",
                    "evidence_schema",
                    "executable_artifact_digest",
                    "observer_id",
                    "predicate_schema",
                    "provider_namespace",
                    "schema_version",
                    "version",
                ],
            )?;
            SemanticallyDecodedGenesisEntryV1::ObserverAdmission(decode_body(&entry.body)?)
        }
        RegistryEntryKind::PredicateSchema => {
            require_exact_fields(
                &entry.body,
                &[
                    "absence_semantics",
                    "allowed_modalities",
                    "applicability_evaluator",
                    "comparator",
                    "coverage_proof",
                    "predicate_id",
                    "publication_default",
                    "required_dimensions",
                    "schema_version",
                    "sensitivity_default",
                    "unit_id",
                    "value_kind",
                    "version",
                ],
            )?;
            SemanticallyDecodedGenesisEntryV1::PredicateSchema(decode_body(&entry.body)?)
        }
        RegistryEntryKind::PublicationRule => {
            require_exact_fields(
                &entry.body,
                &[
                    "classification_before_projection_required",
                    "default_publication",
                    "exemplar_policy",
                    "private_material_allowed",
                    "raw_content_references_allowed",
                    "rule_id",
                    "schema_version",
                    "version",
                ],
            )?;
            SemanticallyDecodedGenesisEntryV1::PublicationRule(decode_body(&entry.body)?)
        }
        RegistryEntryKind::RedactionPolicy => {
            require_exact_fields(
                &entry.body,
                &[
                    "failure_outcome",
                    "policy_id",
                    "redact_before_durable_outbox",
                    "schema_version",
                    "secrets_allowed_in_recall",
                    "version",
                ],
            )?;
            SemanticallyDecodedGenesisEntryV1::RedactionPolicy(decode_body(&entry.body)?)
        }
        RegistryEntryKind::RelationProof => {
            require_exact_fields(
                &entry.body,
                &[
                    "admissible_modality",
                    "authority_rule",
                    "from_resource_kind",
                    "multiplicity",
                    "observer_admission",
                    "payload_may_select_verified_state",
                    "predicate_schema",
                    "proof_method",
                    "relation_id",
                    "schema_version",
                    "temporal_overlap_required",
                    "to_resource_kind",
                    "version",
                ],
            )?;
            SemanticallyDecodedGenesisEntryV1::RelationProof(decode_body(&entry.body)?)
        }
        RegistryEntryKind::ResourceKindSchema => {
            require_exact_fields(
                &entry.body,
                &[
                    "component_rules",
                    "identity_form",
                    "parent_entity_kind",
                    "resource_kind",
                    "schema_version",
                    "version",
                ],
            )?;
            SemanticallyDecodedGenesisEntryV1::ResourceKindSchema(decode_body(&entry.body)?)
        }
        RegistryEntryKind::RetentionPolicy => {
            require_exact_fields(
                &entry.body,
                &[
                    "default_retention",
                    "erasure_index_required",
                    "failure_outcome",
                    "policy_id",
                    "private_raw_separate_key",
                    "schema_version",
                    "tombstones_before_restore",
                    "version",
                ],
            )?;
            SemanticallyDecodedGenesisEntryV1::RetentionPolicy(decode_body(&entry.body)?)
        }
        // Generation-2-only kinds have no v1 body schema. The closed dispatch
        // keeps them visible here so a later typed body cannot be added by
        // widening a wildcard arm.
        RegistryEntryKind::ArrowBatchSchema
        | RegistryEntryKind::ComparatorLineage // W0-REG-2
        | RegistryEntryKind::ConsolidationPolicy // W0-REG-2
        | RegistryEntryKind::LogEpochRecipe
        | RegistryEntryKind::ParserContract => return Err(generation2_only_kind_error(entry)),
    })
}

/// Explicit fail-closed rejection for a kind that no generation-1 body schema
/// covers.
///
/// Both the genesis closure and the generic successor closure return this exact
/// error, so a package that names a generation-2-only kind is rejected with the
/// same reason wherever it is offered.
pub(crate) fn generation2_only_kind_error(entry: &RegistryEntryV1) -> ContractError {
    ContractError::Schema(format!(
        "registry entry {} names generation-2-only kind {}, which has no wired body schema",
        entry.entry_id,
        entry.kind.as_str()
    ))
}

fn validate_entry_schema_selector(entry: &RegistryEntryV1) -> ContractResult<()> {
    let expected = format!("registry.{}", entry.kind.as_str());
    if entry.entry_schema_version != GENESIS_ENTRY_SCHEMA_VERSION
        || entry.entry_schema_id.as_str() != expected
    {
        return Err(ContractError::Schema(format!(
            "registry entry {} selects the wrong closed body schema",
            entry.entry_id
        )));
    }
    Ok(())
}

fn require_exact_fields(value: &CanonicalValue, expected: &[&str]) -> ContractResult<()> {
    let object = value
        .as_object()
        .ok_or_else(|| ContractError::Schema("registry entry body must be an object".into()))?;
    if object.len() != expected.len()
        || !object
            .keys()
            .map(String::as_str)
            .eq(expected.iter().copied())
    {
        return Err(ContractError::Schema(
            "registry entry omits an explicit default or contains an unknown field".into(),
        ));
    }
    Ok(())
}

fn decode_body<T: DeserializeOwned>(body: &CanonicalValue) -> ContractResult<T> {
    decode_strict(&encode_canonical(body)?)
}

fn validate_kind_cardinality(package: &RegistryPackageV1) -> ContractResult<()> {
    for kind in REQUIRED_GENESIS_KINDS {
        let count = package
            .entries
            .iter()
            .filter(|entry| entry.kind == kind)
            .count();
        if count == 0 {
            return Err(ContractError::Schema(format!(
                "genesis package is missing required {} entry",
                kind.as_str()
            )));
        }
    }
    for kind in REQUIRED_SINGLETON_KINDS {
        let count = package
            .entries
            .iter()
            .filter(|entry| entry.kind == kind)
            .count();
        if count != 1 {
            return Err(ContractError::Schema(format!(
                "genesis package requires exactly one {} entry",
                kind.as_str()
            )));
        }
    }
    Ok(())
}

fn singleton_index(
    entries: &[SemanticallyDecodedGenesisEntryV1],
    kind: RegistryEntryKind,
) -> ContractResult<usize> {
    let mut matches = entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| entry.kind() == kind)
        .map(|(index, _)| index);
    let first = matches
        .next()
        .ok_or_else(|| ContractError::Schema(format!("missing {} singleton", kind.as_str())))?;
    if matches.next().is_some() {
        return Err(ContractError::Schema(format!(
            "duplicate {} singleton",
            kind.as_str()
        )));
    }
    Ok(first)
}

/// Require a decoded legacy v1 body's identity to match its full entry envelope.
pub(crate) fn validate_entry_identity(
    raw: &RegistryEntryV1,
    decoded: &SemanticallyDecodedGenesisEntryV1,
) -> ContractResult<()> {
    if decoded.kind() != raw.kind
        || decoded.entry_id() != &raw.entry_id
        || decoded
            .body_version()
            .is_some_and(|version| version != raw.version)
    {
        return Err(ContractError::Schema(format!(
            "registry entry {} body identity does not match its envelope",
            raw.entry_id
        )));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // one exhaustive validator keeps kind coverage reviewable
/// Close one legacy v1 body over exact full-entry dependencies in `package`.
pub(crate) fn validate_entry_semantics(
    package: &ManifestVerifiedRegistryPackage,
    raw: &RegistryEntryV1,
    decoded: &SemanticallyDecodedGenesisEntryV1,
) -> ContractResult<()> {
    match decoded {
        SemanticallyDecodedGenesisEntryV1::ActivationPolicy(value) => {
            require_schema_version(value.schema_version)?;
            if value.version == 0
                || value.eligible_principal_ids.is_empty()
                || value.eligible_principal_ids.len() > MAX_SMALL_SET
                || !strictly_sorted(&value.eligible_principal_ids)
                || value.approval_threshold == 0
                || usize::from(value.approval_threshold) > value.eligible_principal_ids.len()
                || !value.separation_of_duty_required
                || value.self_authorization_allowed
                || value.break_glass_enabled
            {
                return semantic_error(raw, "invalid or fail-open activation policy");
            }
        }
        SemanticallyDecodedGenesisEntryV1::ApplicabilityEvaluator(value) => {
            require_schema_version(value.schema_version)?;
            if value.version == 0
                || value.missing_dimension_outcome != UnknownOutcomeV1::Unknown
                || value.null_dimension_outcome != UnknownOutcomeV1::Unknown
                || !value.explicit_any_enabled
                || !value.same_concrete_context_required
                || value.receipt_order_tiebreaker_allowed
            {
                return semantic_error(raw, "invalid or fail-open applicability evaluator");
            }
        }
        SemanticallyDecodedGenesisEntryV1::AuthorityRule(value) => {
            require_schema_version(value.schema_version)?;
            require_positive_version(value.version, raw)?;
            let predicate_entry = resolve_reference(
                package.package(),
                RegistryEntryKind::PredicateSchema,
                &value.predicate_schema,
            )?;
            let predicate: PredicateSchemaEntryV1 = decode_body(&predicate_entry.body)?;
            resolve_reference(
                package.package(),
                RegistryEntryKind::ApplicabilityEvaluator,
                &value.applicability_evaluator,
            )?;
            resolve_reference(
                package.package(),
                RegistryEntryKind::NamespaceDefinition,
                &value.provider_namespace,
            )?;
            let evidence_entry = resolve_reference(
                package.package(),
                RegistryEntryKind::EvidenceSchema,
                &value.evidence_schema,
            )?;
            let evidence: EvidenceSchemaEntryV1 = decode_body(&evidence_entry.body)?;
            let observer_entry = resolve_reference(
                package.package(),
                RegistryEntryKind::ObserverAdmission,
                &value.observer_admission,
            )?;
            let observer: ObserverAdmissionEntryV1 = decode_body(&observer_entry.body)?;
            if let RatificationRequirementV1::Required { policy } = &value.ratification {
                resolve_reference(
                    package.package(),
                    RegistryEntryKind::CausalRatificationPolicy,
                    policy,
                )?;
            }
            let evidence_kind_matches = evidence.evidence_kind == value.admissible_evidence_kind;
            let observer_binding_matches = observer.predicate_schema == value.predicate_schema
                && observer.provider_namespace == value.provider_namespace
                && observer.evidence_schema == value.evidence_schema;
            if value.admissible_evidence_kind.as_str().is_empty()
                || predicate.applicability_evaluator != value.applicability_evaluator
                || !predicate
                    .allowed_modalities
                    .contains(&value.admissible_modality)
                || !evidence_kind_matches
                || !observer_binding_matches
                || (value.maximum_outcome == AuthorityOutcomeV1::Verified
                    && observer.admission_mode == ObserverAdmissionModeV1::CandidateOnly)
                || !matches!(
                    value.maximum_outcome,
                    AuthorityOutcomeV1::Provisional | AuthorityOutcomeV1::Verified
                )
            {
                return semantic_error(raw, "invalid authority rule");
            }
        }
        SemanticallyDecodedGenesisEntryV1::CausalRatificationPolicy(value) => {
            require_schema_version(value.schema_version)?;
            require_positive_version(value.version, raw)?;
            let approval_entry = resolve_reference(
                package.package(),
                RegistryEntryKind::ActivationPolicy,
                &value.approval_policy,
            )?;
            let approval: ActivationPolicyEntryV1 = decode_body(&approval_entry.body)?;
            if value.minimum_positive_support != CausalSupportLevelV1::InterventionSupported
                || value.approval_threshold == 0
                || value.approval_threshold < approval.approval_threshold
                || usize::from(value.approval_threshold) > approval.eligible_principal_ids.len()
                || !value.separation_of_duty_required
                || value.agent_exception_allowed
            {
                return semantic_error(raw, "invalid or fail-open causal ratification policy");
            }
        }
        SemanticallyDecodedGenesisEntryV1::ClassifierPolicy(value) => {
            require_schema_version(value.schema_version)?;
            require_positive_version(value.version, raw)?;
            if !value.server_derived
                || !value.classify_before_projection
                || value.default_visibility != VisibilityClass::Private
                || value.default_publication != PublicationClass::Denied
                || value.failure_outcome != PolicyFailureOutcomeV1::Withhold
            {
                return semantic_error(raw, "classifier policy is fail-open");
            }
        }
        SemanticallyDecodedGenesisEntryV1::ConnectorSchema(value) => {
            require_schema_version(value.schema_version)?;
            require_positive_version(value.version, raw)?;
            resolve_reference(
                package.package(),
                RegistryEntryKind::NamespaceDefinition,
                &value.provider_namespace,
            )?;
            let evidence_entry = resolve_reference(
                package.package(),
                RegistryEntryKind::EvidenceSchema,
                &value.evidence_schema,
            )?;
            let evidence: EvidenceSchemaEntryV1 = decode_body(&evidence_entry.body)?;
            let recipe_entry = resolve_reference(
                package.package(),
                RegistryEntryKind::IdentityRecipe,
                &value.identity_recipe,
            )?;
            let recipe: IdentityRecipeV1 = decode_body(&recipe_entry.body)?;
            let evidence_recipe_matches = evidence.identity_recipe == value.identity_recipe;
            let provider_namespace_matches = recipe.authority_namespace == value.provider_namespace;
            if !evidence_recipe_matches
                || !provider_namespace_matches
                || !value.authenticated_scope_required
                || value.delivery_id_in_semantic_identity
                || !value.immutable_revision_required
            {
                return semantic_error(raw, "connector schema weakens identity or scope binding");
            }
        }
        SemanticallyDecodedGenesisEntryV1::CoverageProof(value) => {
            require_schema_version(value.schema_version)?;
            require_positive_version(value.version, raw)?;
            if !value.complete_required_for_absence
                || !value.current_required_for_absence
                || !value.contiguous_required_when_sequenced
                || value.receipt_order_establishes_provider_order
            {
                return semantic_error(raw, "coverage proof weakens absence semantics");
            }
        }
        SemanticallyDecodedGenesisEntryV1::EpisodePolicy(value) => {
            require_schema_version(value.schema_version)?;
            require_positive_version(value.version, raw)?;
            let predicate_entry = resolve_reference(
                package.package(),
                RegistryEntryKind::PredicateSchema,
                &value.predicate_schema,
            )?;
            let predicate: PredicateSchemaEntryV1 = decode_body(&predicate_entry.body)?;
            resolve_reference(
                package.package(),
                RegistryEntryKind::ApplicabilityEvaluator,
                &value.applicability_evaluator,
            )?;
            if predicate.applicability_evaluator != value.applicability_evaluator
                || (value.window_mode == EpisodeWindowModeV1::NonWindowed
                    && value.allowed_missing_windows != 0)
            {
                return semantic_error(raw, "episode predicate or window contract is inconsistent");
            }
            if value.missing_window_proves_recovery || value.alert_closure_resolves_episode {
                return semantic_error(raw, "episode closure is fail-open");
            }
        }
        SemanticallyDecodedGenesisEntryV1::EvidenceSchema(value) => {
            require_schema_version(value.schema_version)?;
            require_positive_version(value.version, raw)?;
            resolve_reference(
                package.package(),
                RegistryEntryKind::IdentityRecipe,
                &value.identity_recipe,
            )?;
            resolve_reference(
                package.package(),
                RegistryEntryKind::RedactionPolicy,
                &value.redaction_policy,
            )?;
            resolve_reference(
                package.package(),
                RegistryEntryKind::ClassifierPolicy,
                &value.classifier_policy,
            )?;
            resolve_reference(
                package.package(),
                RegistryEntryKind::RetentionPolicy,
                &value.retention_policy,
            )?;
            resolve_reference(
                package.package(),
                RegistryEntryKind::PublicationRule,
                &value.publication_rule,
            )?;
            if !value.canonical_payload_required || value.private_raw_default_enabled {
                return semantic_error(raw, "evidence schema permits an unsafe payload default");
            }
        }
        SemanticallyDecodedGenesisEntryV1::ExemplarPolicy(value) => {
            require_schema_version(value.schema_version)?;
            require_positive_version(value.version, raw)?;
            if value.private_max_count > 8
                || value.private_max_each_bytes > 1_024
                || value.private_max_total_bytes > 8_192
                || value.public_max_count > 3
                || value.public_max_each_bytes > 512
                || value.public_max_total_bytes > 1_536
                || !exemplar_cap_is_coherent(
                    value.private_max_count,
                    value.private_max_each_bytes,
                    value.private_max_total_bytes,
                )
                || !exemplar_cap_is_coherent(
                    value.public_max_count,
                    value.public_max_each_bytes,
                    value.public_max_total_bytes,
                )
                || value.public_enabled != (value.public_max_count > 0)
                || value.raw_lines_allowed
                || value.headers_allowed
                || ((value.selector == ExemplarSelectorV1::None)
                    != (value.private_max_count == 0 && value.public_max_count == 0))
            {
                return semantic_error(raw, "exemplar bounds or denied fields are invalid");
            }
        }
        SemanticallyDecodedGenesisEntryV1::IdentityRecipe(value) => {
            value.validate()?;
            ValidatedIdentityRecipe::from_package(package, &value.recipe_id, value.version)?;
        }
        SemanticallyDecodedGenesisEntryV1::NamespaceDefinition(value) => {
            require_schema_version(value.schema_version)?;
            require_positive_version(value.version, raw)?;
            if value.immutable_coordinate_keys.is_empty()
                || value.immutable_coordinate_keys.len() > MAX_LOCATOR_COMPONENTS
                || !strictly_sorted(&value.immutable_coordinate_keys)
            {
                return semantic_error(raw, "invalid authority namespace definition");
            }
        }
        SemanticallyDecodedGenesisEntryV1::NormativeBindingSchema(value) => {
            require_schema_version(value.schema_version)?;
            require_positive_version(value.version, raw)?;
            resolve_reference(
                package.package(),
                RegistryEntryKind::ActivationPolicy,
                &value.activation_policy,
            )?;
            resolve_reference(
                package.package(),
                RegistryEntryKind::ApplicabilityEvaluator,
                &value.applicability_evaluator,
            )?;
            if !value.exact_source_binding_required
                || !value.separation_of_duty_required
                || value.retroactive_correction_allowed_by_default
                || value.maximum_source_spans == 0
                || value.maximum_source_spans > MAX_NORMATIVE_SOURCE_SPANS
                || value.maximum_propositions == 0
                || value.maximum_propositions > MAX_NORMATIVE_PROPOSITIONS
            {
                return semantic_error(raw, "normative binding schema is fail-open or unbounded");
            }
        }
        SemanticallyDecodedGenesisEntryV1::ObserverAdmission(value) => {
            require_schema_version(value.schema_version)?;
            require_positive_version(value.version, raw)?;
            let predicate_entry = resolve_reference(
                package.package(),
                RegistryEntryKind::PredicateSchema,
                &value.predicate_schema,
            )?;
            let predicate: PredicateSchemaEntryV1 = decode_body(&predicate_entry.body)?;
            let evidence_entry = resolve_reference(
                package.package(),
                RegistryEntryKind::EvidenceSchema,
                &value.evidence_schema,
            )?;
            let evidence: EvidenceSchemaEntryV1 = decode_body(&evidence_entry.body)?;
            resolve_reference(
                package.package(),
                RegistryEntryKind::NamespaceDefinition,
                &value.provider_namespace,
            )?;
            let recipe_entry = resolve_reference(
                package.package(),
                RegistryEntryKind::IdentityRecipe,
                &evidence.identity_recipe,
            )?;
            let recipe: IdentityRecipeV1 = decode_body(&recipe_entry.body)?;
            if recipe.authority_namespace != value.provider_namespace {
                return semantic_error(raw, "observer provider namespace is not evidence-bound");
            }
            if value.admission_mode == ObserverAdmissionModeV1::ClosedWorldVerified {
                return semantic_error(
                    raw,
                    "closed-world observer admission requires a typed closed-domain contract",
                );
            }
            match (&value.admission_mode, &value.coverage) {
                (ObserverAdmissionModeV1::CandidateOnly, CoverageRequirementV1::NotRequired) => {}
                (
                    ObserverAdmissionModeV1::PositiveVerified,
                    CoverageRequirementV1::Required { proof },
                ) => {
                    resolve_reference(package.package(), RegistryEntryKind::CoverageProof, proof)?;
                    if predicate.comparator == PredicateComparatorV1::SetEquality
                        || predicate.absence_semantics
                            == AbsenceSemanticsV1::ClosedWorldWithCoverage
                    {
                        return semantic_error(
                            raw,
                            "positive observer cannot verify set equality or closed-world absence",
                        );
                    }
                }
                _ => return semantic_error(raw, "observer admission and coverage disagree"),
            }
        }
        SemanticallyDecodedGenesisEntryV1::PredicateSchema(value) => {
            require_schema_version(value.schema_version)?;
            require_positive_version(value.version, raw)?;
            resolve_reference(
                package.package(),
                RegistryEntryKind::ApplicabilityEvaluator,
                &value.applicability_evaluator,
            )?;
            match (&value.absence_semantics, &value.coverage_proof) {
                (AbsenceSemanticsV1::ClosedWorldWithCoverage, Some(proof)) => {
                    resolve_reference(package.package(), RegistryEntryKind::CoverageProof, proof)?;
                    let predicate_reference = registry_reference(raw)?;
                    let has_exact_closed_world_observer =
                        package.package().entries.iter().any(|entry| {
                            if entry.kind != RegistryEntryKind::ObserverAdmission {
                                return false;
                            }
                            decode_body::<ObserverAdmissionEntryV1>(&entry.body).is_ok_and(
                                |observer| {
                                    observer.predicate_schema == predicate_reference
                                        && observer.admission_mode
                                            == ObserverAdmissionModeV1::ClosedWorldVerified
                                        && observer.coverage
                                            == CoverageRequirementV1::Required {
                                                proof: proof.clone(),
                                            }
                                },
                            )
                        });
                    if !has_exact_closed_world_observer {
                        return semantic_error(
                            raw,
                            "closed-world predicate lacks an exact admitted observer and proof",
                        );
                    }
                }
                (AbsenceSemanticsV1::OpenWorld, None) => {}
                _ => {
                    return semantic_error(
                        raw,
                        "predicate absence semantics and coverage proof disagree",
                    );
                }
            }
            if value.allowed_modalities.is_empty()
                || value.allowed_modalities.len() > 4
                || !strictly_sorted(&value.allowed_modalities)
                || value.required_dimensions.is_empty()
                || value.required_dimensions.len() > MAX_SMALL_SET
                || !strictly_sorted(&value.required_dimensions)
                || value.unit_id.as_str().is_empty()
                || !matches!(
                    value.value_kind,
                    PredicateValueKindV1::Boolean
                        | PredicateValueKindV1::CanonicalDecimal
                        | PredicateValueKindV1::ContractId
                        | PredicateValueKindV1::ResourceUri
                        | PredicateValueKindV1::Sha256Digest
                        | PredicateValueKindV1::String
                        | PredicateValueKindV1::StringSet
                )
                || !matches!(
                    value.comparator,
                    PredicateComparatorV1::ExactEquality
                        | PredicateComparatorV1::NumericThreshold
                        | PredicateComparatorV1::SetEquality
                )
                || !matches!(
                    value.publication_default,
                    PublicationDefaultV1::Denied | PublicationDefaultV1::PrivateOnly
                )
                || !matches!(
                    value.sensitivity_default,
                    SensitivityDefaultV1::Private | SensitivityDefaultV1::Project
                )
                || !predicate_comparator_matches_value(value.value_kind, value.comparator)
            {
                return semantic_error(raw, "invalid predicate schema");
            }
        }
        SemanticallyDecodedGenesisEntryV1::PublicationRule(value) => {
            require_schema_version(value.schema_version)?;
            require_positive_version(value.version, raw)?;
            resolve_reference(
                package.package(),
                RegistryEntryKind::ExemplarPolicy,
                &value.exemplar_policy,
            )?;
            if value.default_publication != PublicationDefaultV1::Denied
                || !value.classification_before_projection_required
                || value.private_material_allowed
                || value.raw_content_references_allowed
            {
                return semantic_error(raw, "publication rule is fail-open");
            }
        }
        SemanticallyDecodedGenesisEntryV1::RedactionPolicy(value) => {
            require_schema_version(value.schema_version)?;
            require_positive_version(value.version, raw)?;
            if !value.redact_before_durable_outbox
                || value.secrets_allowed_in_recall
                || value.failure_outcome != PolicyFailureOutcomeV1::Withhold
            {
                return semantic_error(raw, "redaction policy is fail-open");
            }
        }
        SemanticallyDecodedGenesisEntryV1::RelationProof(value) => {
            require_schema_version(value.schema_version)?;
            require_positive_version(value.version, raw)?;
            resolve_reference(
                package.package(),
                RegistryEntryKind::ResourceKindSchema,
                &value.from_resource_kind,
            )?;
            resolve_reference(
                package.package(),
                RegistryEntryKind::ResourceKindSchema,
                &value.to_resource_kind,
            )?;
            let authority_entry = resolve_reference(
                package.package(),
                RegistryEntryKind::AuthorityRule,
                &value.authority_rule,
            )?;
            let authority: AuthorityRuleEntryV1 = decode_body(&authority_entry.body)?;
            let predicate_entry = resolve_reference(
                package.package(),
                RegistryEntryKind::PredicateSchema,
                &value.predicate_schema,
            )?;
            let predicate: PredicateSchemaEntryV1 = decode_body(&predicate_entry.body)?;
            let observer_entry = resolve_reference(
                package.package(),
                RegistryEntryKind::ObserverAdmission,
                &value.observer_admission,
            )?;
            let observer: ObserverAdmissionEntryV1 = decode_body(&observer_entry.body)?;
            if value.payload_may_select_verified_state
                || authority.maximum_outcome != AuthorityOutcomeV1::Verified
                || authority.predicate_schema != value.predicate_schema
                || authority.observer_admission != value.observer_admission
                || authority.admissible_modality != value.admissible_modality
                || observer.predicate_schema != value.predicate_schema
                || observer.admission_mode == ObserverAdmissionModeV1::CandidateOnly
                || !predicate
                    .allowed_modalities
                    .contains(&value.admissible_modality)
                || !matches!(
                    value.proof_method,
                    RelationProofMethodV1::ExactProviderIdentifiers
                        | RelationProofMethodV1::RegisteredVerifier
                )
                || !matches!(
                    value.multiplicity,
                    RelationMultiplicityV1::ManyToMany
                        | RelationMultiplicityV1::ManyToOne
                        | RelationMultiplicityV1::OneToMany
                        | RelationMultiplicityV1::OneToOne
                )
            {
                return semantic_error(raw, "invalid or payload-authorized relation proof");
            }
            let _ = value.temporal_overlap_required;
        }
        SemanticallyDecodedGenesisEntryV1::ResourceKindSchema(value) => {
            require_schema_version(value.schema_version)?;
            require_positive_version(value.version, raw)?;
            if let Some(parent) = &value.parent_entity_kind {
                let parent_entry = resolve_reference(
                    package.package(),
                    RegistryEntryKind::ResourceKindSchema,
                    parent,
                )?;
                let parent_schema: ResourceKindSchemaV1 = decode_body(&parent_entry.body)?;
                if parent_schema.identity_form != IdentityForm::Entity
                    || (&parent_schema.resource_kind, parent_schema.version)
                        != (&parent_entry.entry_id, parent_entry.version)
                {
                    return semantic_error(raw, "parent kind is not an exact entity schema");
                }
            }
            let parent_shape_is_valid = matches!(
                (value.identity_form, value.parent_entity_kind.as_ref()),
                (IdentityForm::Version, Some(_))
                    | (IdentityForm::Entity | IdentityForm::Occurrence, None)
            );
            if !parent_shape_is_valid
                || value.component_rules.is_empty()
                || value.component_rules.len() > MAX_LOCATOR_COMPONENTS
                || !value
                    .component_rules
                    .windows(2)
                    .all(|pair| pair[0].key < pair[1].key)
            {
                return semantic_error(raw, "invalid resource-kind schema");
            }
        }
        SemanticallyDecodedGenesisEntryV1::RetentionPolicy(value) => {
            require_schema_version(value.schema_version)?;
            require_positive_version(value.version, raw)?;
            if value.default_retention != RetentionClass::Governed
                || !value.erasure_index_required
                || !value.tombstones_before_restore
                || !value.private_raw_separate_key
                || value.failure_outcome != PolicyFailureOutcomeV1::Withhold
            {
                return semantic_error(raw, "retention policy is fail-open");
            }
        }
    }
    Ok(())
}

fn require_schema_version(version: u32) -> ContractResult<()> {
    if version != GENESIS_ENTRY_SCHEMA_VERSION {
        return Err(ContractError::Schema(
            "unsupported genesis entry body schema version".into(),
        ));
    }
    Ok(())
}

const fn predicate_comparator_matches_value(
    value_kind: PredicateValueKindV1,
    comparator: PredicateComparatorV1,
) -> bool {
    matches!(
        (value_kind, comparator),
        (
            PredicateValueKindV1::Boolean
                | PredicateValueKindV1::ContractId
                | PredicateValueKindV1::ResourceUri
                | PredicateValueKindV1::Sha256Digest
                | PredicateValueKindV1::String,
            PredicateComparatorV1::ExactEquality
        ) | (
            PredicateValueKindV1::CanonicalDecimal,
            PredicateComparatorV1::ExactEquality | PredicateComparatorV1::NumericThreshold
        ) | (
            PredicateValueKindV1::StringSet,
            PredicateComparatorV1::SetEquality
        )
    )
}

fn require_positive_version(version: u32, raw: &RegistryEntryV1) -> ContractResult<()> {
    if version == 0 {
        return semantic_error(raw, "entry body version must be positive");
    }
    Ok(())
}

fn exemplar_cap_is_coherent(count: u16, each_bytes: u16, total_bytes: u16) -> bool {
    if count == 0 {
        return each_bytes == 0 && total_bytes == 0;
    }
    if each_bytes == 0 || total_bytes < each_bytes {
        return false;
    }
    u32::from(total_bytes) <= u32::from(count) * u32::from(each_bytes)
}

fn registry_reference(entry: &RegistryEntryV1) -> ContractResult<RegistryReferenceV1> {
    Ok(RegistryReferenceV1 {
        entry_id: entry.entry_id.clone(),
        version: entry.version,
        entry_digest: entry.digest()?,
    })
}

/// Resolve one exact full-entry dependency by kind, ID, revision, and digest.
pub(crate) fn resolve_reference<'a>(
    package: &'a RegistryPackageV1,
    expected_kind: RegistryEntryKind,
    reference: &RegistryReferenceV1,
) -> ContractResult<&'a RegistryEntryV1> {
    reference.validate()?;
    let mut matches = package.entries.iter().filter(|entry| {
        entry.kind == expected_kind
            && entry.entry_id == reference.entry_id
            && entry.version == reference.version
    });
    let entry = matches.next().ok_or_else(|| {
        ContractError::Schema(format!(
            "missing exact {} dependency {}@{}",
            expected_kind.as_str(),
            reference.entry_id,
            reference.version
        ))
    })?;
    if matches.next().is_some() || entry.digest()? != reference.entry_digest {
        return Err(ContractError::Schema(format!(
            "{} dependency {}@{} has an identity or digest mismatch",
            expected_kind.as_str(),
            reference.entry_id,
            reference.version
        )));
    }
    Ok(entry)
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn semantic_error<T>(raw: &RegistryEntryV1, detail: &str) -> ContractResult<T> {
    Err(ContractError::Schema(format!(
        "registry entry {} is not semantically closed: {detail}",
        raw.entry_id
    )))
}

fn reject_dynamic_policy_constructs(value: &CanonicalValue) -> ContractResult<()> {
    match value {
        CanonicalValue::Array(values) => {
            for value in values {
                reject_dynamic_policy_constructs(value)?;
            }
        }
        CanonicalValue::Object(values) => {
            for (key, value) in values {
                if matches!(
                    key.as_str(),
                    "$ref"
                        | "command"
                        | "environment_substitution"
                        | "environment_variable"
                        | "executable"
                        | "expression"
                        | "include"
                        | "includes"
                        | "remote_include"
                        | "remote_includes"
                        | "script"
                ) {
                    return Err(ContractError::Schema(
                        "registry entries cannot include remote, environment-derived, or executable policy"
                            .into(),
                    ));
                }
                reject_dynamic_policy_constructs(value)?;
            }
        }
        CanonicalValue::String(value)
            if value.contains("${")
                || value.contains("$(")
                || value.starts_with("env:")
                || value.starts_with("exec:")
                || value.starts_with("file://")
                || value.starts_with("http://")
                || value.starts_with("https://")
                || value.starts_with("javascript:")
                || value.starts_with("wasm:") =>
        {
            return Err(ContractError::Schema(
                "registry entries cannot include remote, environment-derived, or executable policy"
                    .into(),
            ));
        }
        CanonicalValue::Null
        | CanonicalValue::Bool(_)
        | CanonicalValue::Integer(_)
        | CanonicalValue::String(_) => {}
    }
    Ok(())
}

/// Canonical, semantically closed genesis fixture shared by sibling contract
/// tests. Production code cannot access or mistake these test keys and policy
/// identities for an activated registry.
#[cfg(test)]
pub(crate) fn fixture_closed_package() -> SemanticallyClosedGenesisPackage {
    tests::close(tests::complete_package()).expect("shared genesis fixture must remain valid")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::memory_contracts::{
        canonical::{encode_canonical, parse_strict},
        common::ProfileReferenceV1,
        digest::{DigestDomain, domain_separated_digest},
        identity::{IdentityComponentRuleV1, LocatorEncoding},
        registry::{RegistryManifestEntryV1, RegistryPackageV1},
    };

    fn digest(domain: DigestDomain, label: &str) -> Sha256Digest {
        domain_separated_digest(domain, label.as_bytes())
    }

    fn profile() -> ProfileReferenceV1 {
        let profile_bytes =
            include_bytes!("../../contracts/dynamic-memory/v1/canonical-profile.jsonl")
                .strip_suffix(b"\n")
                .expect("profile fixture has one repository-framing LF");
        let vector_bytes =
            include_bytes!("../../contracts/dynamic-memory/v1/conformance-manifest.jsonl")
                .strip_suffix(b"\n")
                .expect("vector fixture has one repository-framing LF");
        ProfileReferenceV1 {
            profile_id: ContractId::new("ostk-canonical-json-v1").unwrap(),
            profile_digest: domain_separated_digest(DigestDomain::CanonicalProfile, profile_bytes),
            vector_manifest_digest: domain_separated_digest(
                DigestDomain::TestVectorManifest,
                vector_bytes,
            ),
        }
    }

    fn body<T: Serialize>(value: &T) -> CanonicalValue {
        parse_strict(&encode_canonical(value).unwrap())
            .unwrap()
            .value()
            .clone()
    }

    fn entry<T: Serialize>(kind: RegistryEntryKind, entry_id: &str, value: &T) -> RegistryEntryV1 {
        RegistryEntryV1 {
            schema_version: 1,
            kind,
            entry_id: ContractId::new(entry_id).unwrap(),
            version: 1,
            entry_schema_id: ContractId::new(format!("registry.{}", kind.as_str())).unwrap(),
            entry_schema_version: 1,
            body: body(value),
            positive_vector_digest: digest(DigestDomain::TestVectorManifest, "positive"),
            negative_vector_digest: digest(DigestDomain::TestVectorManifest, "negative"),
        }
    }

    fn reference(entry: &RegistryEntryV1) -> RegistryReferenceV1 {
        RegistryReferenceV1 {
            entry_id: entry.entry_id.clone(),
            version: entry.version,
            entry_digest: entry.digest().unwrap(),
        }
    }

    fn rebuild_manifest(package: &mut RegistryPackageV1) {
        package.entries.sort_by(|left, right| {
            (left.kind.as_str(), left.entry_id.as_str(), left.version).cmp(&(
                right.kind.as_str(),
                right.entry_id.as_str(),
                right.version,
            ))
        });
        package.manifest = package
            .entries
            .iter()
            .map(|entry| RegistryManifestEntryV1 {
                kind: entry.kind,
                entry_id: entry.entry_id.clone(),
                version: entry.version,
                entry_digest: entry.digest().unwrap(),
            })
            .collect();
    }

    #[allow(clippy::too_many_lines)]
    pub(super) fn complete_package() -> RegistryPackageV1 {
        let activation = entry(
            RegistryEntryKind::ActivationPolicy,
            "activation.default",
            &ActivationPolicyEntryV1 {
                schema_version: 1,
                policy_id: ContractId::new("activation.default").unwrap(),
                version: 1,
                eligible_principal_ids: vec![
                    ContractId::new("principal.alice").unwrap(),
                    ContractId::new("principal.bob").unwrap(),
                ],
                approval_threshold: 2,
                separation_of_duty_required: true,
                self_authorization_allowed: false,
                break_glass_enabled: false,
            },
        );
        let applicability = entry(
            RegistryEntryKind::ApplicabilityEvaluator,
            "applicability.default",
            &ApplicabilityEvaluatorEntryV1 {
                schema_version: 1,
                evaluator_id: ContractId::new("applicability.default").unwrap(),
                version: 1,
                missing_dimension_outcome: UnknownOutcomeV1::Unknown,
                null_dimension_outcome: UnknownOutcomeV1::Unknown,
                explicit_any_enabled: true,
                same_concrete_context_required: true,
                receipt_order_tiebreaker_allowed: false,
            },
        );
        let causal = entry(
            RegistryEntryKind::CausalRatificationPolicy,
            "causal.default",
            &CausalRatificationPolicyEntryV1 {
                schema_version: 1,
                policy_id: ContractId::new("causal.default").unwrap(),
                version: 1,
                approval_policy: reference(&activation),
                minimum_positive_support: CausalSupportLevelV1::InterventionSupported,
                approval_threshold: 2,
                separation_of_duty_required: true,
                agent_exception_allowed: false,
            },
        );
        let coverage = entry(
            RegistryEntryKind::CoverageProof,
            "coverage.enumerated",
            &CoverageProofEntryV1 {
                schema_version: 1,
                proof_id: ContractId::new("coverage.enumerated").unwrap(),
                version: 1,
                method: CoverageMethodV1::EnumeratedSnapshot,
                complete_required_for_absence: true,
                current_required_for_absence: true,
                contiguous_required_when_sequenced: true,
                receipt_order_establishes_provider_order: false,
            },
        );
        let exemplar = entry(
            RegistryEntryKind::ExemplarPolicy,
            "exemplar.private",
            &ExemplarPolicyEntryV1 {
                schema_version: 1,
                policy_id: ContractId::new("exemplar.private").unwrap(),
                version: 1,
                selector: ExemplarSelectorV1::DeterministicStratifiedHashV1,
                private_max_count: 8,
                private_max_each_bytes: 1_024,
                private_max_total_bytes: 8_192,
                public_enabled: false,
                public_max_count: 0,
                public_max_each_bytes: 0,
                public_max_total_bytes: 0,
                raw_lines_allowed: false,
                headers_allowed: false,
            },
        );
        let namespace = entry(
            RegistryEntryKind::NamespaceDefinition,
            "github.namespace",
            &AuthorityNamespaceV1 {
                schema_version: 1,
                namespace_id: ContractId::new("github.namespace").unwrap(),
                version: 1,
                immutable_coordinate_keys: vec![ContractId::new("provider_repository_id").unwrap()],
            },
        );
        let resource_kind = entry(
            RegistryEntryKind::ResourceKindSchema,
            "repository",
            &ResourceKindSchemaV1 {
                schema_version: 1,
                resource_kind: ContractId::new("repository").unwrap(),
                version: 1,
                identity_form: IdentityForm::Entity,
                parent_entity_kind: None,
                component_rules: vec![IdentityComponentRuleV1 {
                    key: ContractId::new("provider_repository_id").unwrap(),
                    encoding: LocatorEncoding::Decimal,
                }],
            },
        );
        let identity = entry(
            RegistryEntryKind::IdentityRecipe,
            "github.repository",
            &IdentityRecipeV1 {
                schema_version: 1,
                recipe_id: ContractId::new("github.repository").unwrap(),
                version: 1,
                resource_kind: ContractId::new("repository").unwrap(),
                identity_form: IdentityForm::Entity,
                authority_namespace: reference(&namespace),
                resource_kind_schema: reference(&resource_kind),
                component_rules: vec![IdentityComponentRuleV1 {
                    key: ContractId::new("provider_repository_id").unwrap(),
                    encoding: LocatorEncoding::Decimal,
                }],
            },
        );
        let redaction = entry(
            RegistryEntryKind::RedactionPolicy,
            "redaction.default",
            &RedactionPolicyEntryV1 {
                schema_version: 1,
                policy_id: ContractId::new("redaction.default").unwrap(),
                version: 1,
                redact_before_durable_outbox: true,
                secrets_allowed_in_recall: false,
                failure_outcome: PolicyFailureOutcomeV1::Withhold,
            },
        );
        let classifier = entry(
            RegistryEntryKind::ClassifierPolicy,
            "classifier.default",
            &ClassifierPolicyEntryV1 {
                schema_version: 1,
                policy_id: ContractId::new("classifier.default").unwrap(),
                version: 1,
                server_derived: true,
                classify_before_projection: true,
                default_visibility: VisibilityClass::Private,
                default_publication: PublicationClass::Denied,
                failure_outcome: PolicyFailureOutcomeV1::Withhold,
            },
        );
        let retention = entry(
            RegistryEntryKind::RetentionPolicy,
            "retention.default",
            &RetentionPolicyEntryV1 {
                schema_version: 1,
                policy_id: ContractId::new("retention.default").unwrap(),
                version: 1,
                default_retention: RetentionClass::Governed,
                erasure_index_required: true,
                tombstones_before_restore: true,
                private_raw_separate_key: true,
                failure_outcome: PolicyFailureOutcomeV1::Withhold,
            },
        );
        let publication = entry(
            RegistryEntryKind::PublicationRule,
            "publication.default",
            &PublicationRuleEntryV1 {
                schema_version: 1,
                rule_id: ContractId::new("publication.default").unwrap(),
                version: 1,
                exemplar_policy: reference(&exemplar),
                default_publication: PublicationDefaultV1::Denied,
                classification_before_projection_required: true,
                private_material_allowed: false,
                raw_content_references_allowed: false,
            },
        );
        let evidence = entry(
            RegistryEntryKind::EvidenceSchema,
            "evidence.git_blob",
            &EvidenceSchemaEntryV1 {
                schema_version: 1,
                evidence_schema_id: ContractId::new("evidence.git_blob").unwrap(),
                version: 1,
                evidence_kind: ContractId::new("git.blob").unwrap(),
                identity_recipe: reference(&identity),
                redaction_policy: reference(&redaction),
                classifier_policy: reference(&classifier),
                retention_policy: reference(&retention),
                publication_rule: reference(&publication),
                canonical_payload_required: true,
                private_raw_default_enabled: false,
            },
        );
        let connector = entry(
            RegistryEntryKind::ConnectorSchema,
            "connector.github_git",
            &ConnectorSchemaEntryV1 {
                schema_version: 1,
                connector_schema_id: ContractId::new("connector.github_git").unwrap(),
                version: 1,
                provider_namespace: reference(&namespace),
                evidence_schema: reference(&evidence),
                identity_recipe: reference(&identity),
                authenticated_scope_required: true,
                delivery_id_in_semantic_identity: false,
                immutable_revision_required: true,
            },
        );
        let predicate = entry(
            RegistryEntryKind::PredicateSchema,
            "mcp.remember.allowed_actions",
            &PredicateSchemaEntryV1 {
                schema_version: 1,
                predicate_id: ContractId::new("mcp.remember.allowed_actions").unwrap(),
                version: 1,
                value_kind: PredicateValueKindV1::Boolean,
                unit_id: ContractId::new("unit.none").unwrap(),
                allowed_modalities: vec![
                    PropositionModalityV1::Normative,
                    PropositionModalityV1::Observed,
                ],
                comparator: PredicateComparatorV1::ExactEquality,
                applicability_evaluator: reference(&applicability),
                required_dimensions: vec![ContractId::new("repository_commit").unwrap()],
                absence_semantics: AbsenceSemanticsV1::OpenWorld,
                coverage_proof: None,
                publication_default: PublicationDefaultV1::Denied,
                sensitivity_default: SensitivityDefaultV1::Project,
            },
        );
        let episode = entry(
            RegistryEntryKind::EpisodePolicy,
            "episode.spec_nonconformance",
            &EpisodePolicyEntryV1 {
                schema_version: 1,
                policy_id: ContractId::new("episode.spec_nonconformance").unwrap(),
                version: 1,
                predicate_schema: reference(&predicate),
                applicability_evaluator: reference(&applicability),
                window_mode: EpisodeWindowModeV1::NonWindowed,
                allowed_missing_windows: 0,
                missing_window_proves_recovery: false,
                alert_closure_resolves_episode: false,
            },
        );
        let normative = entry(
            RegistryEntryKind::NormativeBindingSchema,
            "normative.binding.default",
            &NormativeBindingSchemaEntryV1 {
                schema_version: 1,
                binding_schema_id: ContractId::new("normative.binding.default").unwrap(),
                version: 1,
                activation_policy: reference(&activation),
                applicability_evaluator: reference(&applicability),
                exact_source_binding_required: true,
                separation_of_duty_required: true,
                retroactive_correction_allowed_by_default: false,
                maximum_source_spans: 256,
                maximum_propositions: 256,
            },
        );
        let observer = entry(
            RegistryEntryKind::ObserverAdmission,
            "observer.rust_enum",
            &ObserverAdmissionEntryV1 {
                schema_version: 1,
                observer_id: ContractId::new("observer.rust_enum").unwrap(),
                version: 1,
                predicate_schema: reference(&predicate),
                evidence_schema: reference(&evidence),
                provider_namespace: reference(&namespace),
                admission_mode: ObserverAdmissionModeV1::PositiveVerified,
                coverage: CoverageRequirementV1::Required {
                    proof: reference(&coverage),
                },
                executable_artifact_digest: digest(DigestDomain::RegistryEntry, "observer"),
                dependency_closure_digest: digest(DigestDomain::RegistryEntry, "dependencies"),
                configuration_digest: digest(DigestDomain::RegistryEntry, "configuration"),
            },
        );
        let authority = entry(
            RegistryEntryKind::AuthorityRule,
            "authority.git_schema",
            &AuthorityRuleEntryV1 {
                schema_version: 1,
                rule_id: ContractId::new("authority.git_schema").unwrap(),
                version: 1,
                predicate_schema: reference(&predicate),
                applicability_evaluator: reference(&applicability),
                admissible_evidence_kind: ContractId::new("git.blob").unwrap(),
                admissible_modality: PropositionModalityV1::Observed,
                provider_namespace: reference(&namespace),
                evidence_schema: reference(&evidence),
                observer_admission: reference(&observer),
                maximum_outcome: AuthorityOutcomeV1::Verified,
                ratification: RatificationRequirementV1::Required {
                    policy: reference(&causal),
                },
            },
        );
        let relation = entry(
            RegistryEntryKind::RelationProof,
            "relation.repository_parent",
            &RelationProofEntryV1 {
                schema_version: 1,
                relation_id: ContractId::new("relation.repository_parent").unwrap(),
                version: 1,
                from_resource_kind: reference(&resource_kind),
                to_resource_kind: reference(&resource_kind),
                authority_rule: reference(&authority),
                predicate_schema: reference(&predicate),
                admissible_modality: PropositionModalityV1::Observed,
                observer_admission: reference(&observer),
                proof_method: RelationProofMethodV1::ExactProviderIdentifiers,
                multiplicity: RelationMultiplicityV1::ManyToMany,
                temporal_overlap_required: false,
                payload_may_select_verified_state: false,
            },
        );

        let mut package = RegistryPackageV1 {
            schema_version: 1,
            profile: profile(),
            entries: vec![
                activation,
                applicability,
                authority,
                causal,
                classifier,
                connector,
                coverage,
                episode,
                evidence,
                exemplar,
                identity,
                namespace,
                normative,
                observer,
                predicate,
                publication,
                redaction,
                relation,
                resource_kind,
                retention,
            ],
            manifest: Vec::new(),
            positive_vector_suite_digest: digest(
                DigestDomain::TestVectorManifest,
                "positive-suite",
            ),
            negative_vector_suite_digest: digest(
                DigestDomain::TestVectorManifest,
                "negative-suite",
            ),
        };
        rebuild_manifest(&mut package);
        package
    }

    pub(super) fn close(
        package: RegistryPackageV1,
    ) -> ContractResult<SemanticallyClosedGenesisPackage> {
        let verified = ManifestVerifiedRegistryPackage::new(package, &profile())?;
        SemanticallyClosedGenesisPackage::from_manifest_verified(verified)
    }

    #[test]
    fn complete_package_closes_without_implying_activation() {
        let package = fixture_closed_package();
        assert_eq!(package.entries().len(), REQUIRED_GENESIS_KINDS.len());
        assert_eq!(package.activation_policy().approval_threshold(), 2);
        assert_eq!(
            package.activation_policy().eligible_principal_ids().len(),
            2
        );
        assert!(
            package
                .entry(
                    RegistryEntryKind::IdentityRecipe,
                    &ContractId::new("github.repository").unwrap(),
                    1,
                )
                .is_some()
        );
    }

    #[test]
    fn missing_required_kind_fails_after_manifest_verification() {
        let mut package = complete_package();
        package
            .entries
            .retain(|entry| entry.kind != RegistryEntryKind::RelationProof);
        rebuild_manifest(&mut package);
        let error = close(package).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("missing required relation_proof")
        );
    }

    #[test]
    fn duplicated_singleton_fails_after_manifest_verification() {
        let mut package = complete_package();
        let mut duplicate = package
            .entries
            .iter()
            .find(|entry| entry.kind == RegistryEntryKind::PublicationRule)
            .unwrap()
            .clone();
        duplicate.entry_id = ContractId::new("publication.second").unwrap();
        if let CanonicalValue::Object(body) = &mut duplicate.body {
            body.insert(
                "rule_id".into(),
                CanonicalValue::String("publication.second".into()),
            );
        }
        package.entries.push(duplicate);
        rebuild_manifest(&mut package);
        let error = close(package).unwrap_err();
        assert!(error.to_string().contains("exactly one publication_rule"));
    }

    #[test]
    fn missing_explicit_default_is_rejected() {
        let mut package = complete_package();
        let activation = package
            .entries
            .iter_mut()
            .find(|entry| entry.kind == RegistryEntryKind::ActivationPolicy)
            .unwrap();
        if let CanonicalValue::Object(body) = &mut activation.body {
            body.remove("break_glass_enabled");
        }
        rebuild_manifest(&mut package);
        let error = close(package).unwrap_err();
        assert!(error.to_string().contains("explicit default"));
    }

    #[test]
    fn dynamic_policy_constructs_are_rejected() {
        for (field, value) in [
            ("include", "https://example.invalid/policy.json"),
            ("environment_substitution", "${POLICY}"),
            ("script", "exec:policy"),
        ] {
            let mut package = complete_package();
            let activation = package
                .entries
                .iter_mut()
                .find(|entry| entry.kind == RegistryEntryKind::ActivationPolicy)
                .unwrap();
            if let CanonicalValue::Object(body) = &mut activation.body {
                body.insert(field.into(), CanonicalValue::String(value.into()));
            }
            rebuild_manifest(&mut package);
            let error = close(package).unwrap_err();
            assert!(error.to_string().contains("cannot include remote"));
        }
    }

    #[test]
    fn exact_dependency_digest_is_required() {
        let mut package = complete_package();
        let predicate = package
            .entries
            .iter_mut()
            .find(|entry| entry.kind == RegistryEntryKind::PredicateSchema)
            .unwrap();
        let CanonicalValue::Object(body) = &mut predicate.body else {
            panic!("predicate body must be an object");
        };
        let CanonicalValue::Object(reference) = body
            .get_mut("applicability_evaluator")
            .expect("applicability reference")
        else {
            panic!("reference must be an object");
        };
        reference.insert(
            "entry_digest".into(),
            CanonicalValue::String(Sha256Digest::ZERO.to_string()),
        );
        rebuild_manifest(&mut package);
        let error = close(package).unwrap_err();
        assert!(error.to_string().contains("digest mismatch"));
    }

    #[test]
    fn body_schema_selector_is_closed_by_kind() {
        let mut package = complete_package();
        let predicate = package
            .entries
            .iter_mut()
            .find(|entry| entry.kind == RegistryEntryKind::PredicateSchema)
            .unwrap();
        predicate.entry_schema_id = ContractId::new("registry.authority_rule").unwrap();
        rebuild_manifest(&mut package);
        let error = close(package).unwrap_err();
        assert!(error.to_string().contains("wrong closed body schema"));
    }

    #[test]
    fn parent_default_must_be_present_even_when_null() {
        let mut package = complete_package();
        let resource = package
            .entries
            .iter_mut()
            .find(|entry| entry.kind == RegistryEntryKind::ResourceKindSchema)
            .unwrap();
        if let CanonicalValue::Object(body) = &mut resource.body {
            assert_eq!(
                body.remove("parent_entity_kind"),
                Some(CanonicalValue::Null)
            );
        }
        rebuild_manifest(&mut package);
        let error = close(package).unwrap_err();
        assert!(error.to_string().contains("explicit default"));
    }

    #[test]
    fn exact_field_check_uses_canonical_key_order() {
        let value = CanonicalValue::Object(BTreeMap::from([
            ("a".into(), CanonicalValue::Bool(false)),
            ("b".into(), CanonicalValue::Bool(true)),
        ]));
        assert!(require_exact_fields(&value, &["a", "b"]).is_ok());
        assert!(require_exact_fields(&value, &["b", "a"]).is_err());
    }

    #[test]
    fn generation2_only_kinds_have_no_v1_body_schema() {
        // The selector these entries carry is exactly the one a v1 entry of
        // this kind would carry, so only the kind itself can reject them.
        let body = BTreeMap::from([("schema_version".to_owned(), 1_u32)]);
        for kind in [
            RegistryEntryKind::ArrowBatchSchema,
            RegistryEntryKind::LogEpochRecipe,
            RegistryEntryKind::ParserContract,
        ] {
            assert!(kind.is_generation2_only());
            let candidate = entry(kind, "generation2.reserved", &body);
            assert_eq!(
                candidate.entry_schema_id.as_str(),
                format!("registry.{}", kind.as_str())
            );
            let error = decode_entry(&candidate).unwrap_err();
            assert!(
                matches!(&error, ContractError::Schema(message)
                    if message.contains("generation-2-only kind")),
                "{error:?}"
            );
        }
    }
}
