//! Remember admission against the active registry package.
//!
//! # What the caller chooses, and what the server derives
//!
//! An agent sends a [`RememberAssertInputV1`]: the assertion kind, text,
//! modality, polarity, value, optional effective interval and support event
//! IDs, and the locator COMPONENTS of the subject and of each applicability
//! dimension (for example `provider_repository_id` or `commit_oid`). It never
//! sends a resource URI, a registry reference, an actor, a scope, a head, or
//! an admission rule. The server:
//!
//! 1. routes the one authenticated-actor remember rule of the active package
//!    ([`resolve_assert_route`]). A package with zero or several such rules
//!    fails closed;
//! 2. checks the text first, against both the legacy claim projection's rules
//!    and the canonical assertion-text contract. A text the projection would
//!    reject is a typed `text_invalid` refusal, not an internal error after
//!    embedding;
//! 3. REDERIVES the subject and every applicability URI from the supplied
//!    components under the recipes the predicate names, keyed and encoded by
//!    each recipe's component rules;
//! 4. fills every registry reference from the route. The optional `predicate`
//!    is compare-only;
//! 5. defaults `effective_from` to the server clock truncated to microseconds
//!    and enforces the whole active effective-interval rule, including "no
//!    future `effective_from`";
//! 6. runs the contract's candidate shape check and mints the admitted
//!    statement through its crate-private constructor.
//!
//! # The commit dimension (owner decision D1)
//!
//! The only active route, `remember.actor_assertion` over
//! `mcp.remember.allowed_actions`, requires a `repository_commit` dimension.
//! Its recipe, `identity.github.commit`, is version-form with parent kind
//! `repository`, but it lives in `namespace.github.commit`, which has no
//! repository entity recipe, so the generic same-namespace parent rule can
//! never derive it. The route plans such a dimension as
//! [`DimensionDerivationV1::VersionUnderSubject`] exactly when that generic
//! parent is unresolvable AND the recipe's parent kind is the predicate
//! subject's own resource kind. The commit URI is then derived with the
//! already-rederived subject repository as its parent, so every agent that
//! names the same repository and commit gets the same URI. Any other
//! underivable dimension, and any resource-valued predicate, fails closed.
//!
//! # Claim key
//!
//! `claim-v2:<coordinate id>:<modality>`. The coordinate excludes the value,
//! polarity, interval, actor, and head, so two agents asserting about the same
//! subject, predicate, and applicability share a key and the conflict detector
//! compares them. The modality suffix keeps an intention from conflicting with
//! an attestation. The coordinate does not bind the head either, and every
//! recipe is carried byte for byte from generation 1 into generation 2, so a
//! key survives that upgrade.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::FleetError;
use crate::ledger::{ClaimInput, ClaimKind, MAX_CLAIM_VALUE_SERIALIZED_BYTES, canonical_json};
use crate::memory_contracts::common::{
    AuthenticatedProjectScopeV1, CanonicalTimestamp, ContractId, RegistryReferenceV1,
};
use crate::memory_contracts::digest::Sha256Digest;
use crate::memory_contracts::evidence::AcceptedEventId;
use crate::memory_contracts::evidence_v2::RegistryHeadBindingV1;
use crate::memory_contracts::genesis::{PropositionModalityV1, PublicationDefaultV1};
use crate::memory_contracts::identity::{
    IdentityForm, LocatorEncoding, ResourceUri, ValidatedIdentityRecipe, derive_entity_with_recipe,
    derive_version_under_entity_parent, locator_from_components, resolve_parent_entity_recipe,
};
use crate::memory_contracts::registry::{ManifestVerifiedRegistryPackage, RegistryEntryKind};
use crate::memory_contracts::relation::ConcreteApplicabilityDimensionV1;
use crate::memory_contracts::remember_v2::{
    AdmittedRememberStatementV2, CanonicalAssertionTextV2, CanonicalClaimValueV2,
    ClaimEffectiveIntervalV2, ClaimPolarityV2, RederivedRememberIdentitiesV2, RememberActorV2,
    RememberAdmissionBasisRuleV2, RememberAdmissionBasisV2, RememberAssertionKindV2,
    RememberEffectiveIntervalRuleV2, RememberIngressCandidateV2, RememberValueConstraintV2,
    ResourceIdentityConstraintV2, StructurallyResolvedRememberContractsV2,
    admit_authenticated_actor_statement,
};
use crate::memory_contracts::successor_package::SemanticallyClosedSuccessorPackage;
use crate::memory_contracts::{ContractError, ContractResult};

const REMEMBER_SCHEMA_VERSION: u32 = 2;
const CLAIM_KEY_PREFIX: &str = "claim-v2";
const OPERATOR_ASSERTED_ORIGIN: &str = "operator_asserted";

/// Ergonomic MCP input for `remember(action="assert")`.
///
/// Everything identity-bearing is a locator COMPONENT, never a URI or a
/// registry reference: the server rederives every URI and fills every
/// reference from the one active route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RememberAssertInputV1 {
    /// Optional predicate ID. Compare-only: the server routes the one active
    /// rule and refuses a different predicate rather than selecting by it.
    #[serde(default)]
    pub predicate: Option<ContractId>,
    pub kind: RememberAssertionKindV2,
    /// Exact authored text, at most 100,000 UTF-8 bytes.
    pub text: String,
    pub modality: PropositionModalityV1,
    #[serde(default = "affirms")]
    pub polarity: ClaimPolarityV2,
    pub value: CanonicalClaimValueV2,
    /// Subject locator components, `component key -> value`.
    pub subject: BTreeMap<String, String>,
    /// Applicability locator components, `dimension ID -> component key ->
    /// value`.
    pub applicability: BTreeMap<String, BTreeMap<String, String>>,
    /// Defaults to the server clock, truncated to microseconds.
    #[serde(default)]
    pub effective_from: Option<DateTime<Utc>>,
    #[serde(default)]
    pub effective_until: Option<DateTime<Utc>>,
    #[serde(default)]
    pub support_evidence_event_ids: Vec<AcceptedEventId>,
}

const fn affirms() -> ClaimPolarityV2 {
    ClaimPolarityV2::Affirms
}

/// How the server derives one applicability dimension's URI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DimensionDerivationV1 {
    /// An entity-form recipe, derived from the dimension's own components.
    Entity,
    /// A version-form recipe whose parent kind is the predicate subject's
    /// kind and which has no same-namespace parent recipe. It is derived with
    /// the rederived subject as its parent (owner decision D1).
    VersionUnderSubject,
}

#[derive(Debug, Clone)]
struct DimensionRouteV1 {
    dimension_id: ContractId,
    required: bool,
    recipe: ValidatedIdentityRecipe,
    derivation: DimensionDerivationV1,
}

/// The one authenticated-actor remember route of an active package.
///
/// It is resolved from a package, never from a request, and it remembers
/// which package, so admission refuses to use it under a head that activates
/// a different one.
#[derive(Debug, Clone)]
pub struct RememberAssertRouteV1 {
    package_digest: Sha256Digest,
    contracts: StructurallyResolvedRememberContractsV2,
    modalities: Vec<PropositionModalityV1>,
    maximum_support_events: u16,
    subject_recipe: ValidatedIdentityRecipe,
    dimensions: Vec<DimensionRouteV1>,
}

impl RememberAssertRouteV1 {
    /// Digest of the package this route was resolved from.
    #[must_use]
    pub const fn package_digest(&self) -> Sha256Digest {
        self.package_digest
    }

    /// Exact predicate-schema entry the route admits.
    #[must_use]
    pub const fn predicate_reference(&self) -> &RegistryReferenceV1 {
        self.contracts.predicate_reference()
    }

    /// Exact admission-rule entry the route runs.
    #[must_use]
    pub const fn admission_reference(&self) -> &RegistryReferenceV1 {
        self.contracts.admission_reference()
    }

    /// Modalities both the predicate and the authenticated-actor basis allow.
    #[must_use]
    pub fn modalities(&self) -> &[PropositionModalityV1] {
        &self.modalities
    }

    /// How one applicability dimension is derived, when the route has it.
    #[must_use]
    pub fn dimension_derivation(&self, dimension_id: &str) -> Option<DimensionDerivationV1> {
        self.dimensions
            .iter()
            .find(|dimension| dimension.dimension_id.as_str() == dimension_id)
            .map(|dimension| dimension.derivation)
    }

    /// What an agent may assert through this route, for `recall(status)`.
    #[must_use]
    pub fn describe(&self) -> AssertRouteDescriptionV1 {
        let predicate = self.contracts.predicate();
        AssertRouteDescriptionV1 {
            predicate: AssertRoutePredicateV1 {
                id: predicate.predicate_id.clone(),
                version: predicate.version,
            },
            value_kind: value_kind_name(&predicate.value_constraint),
            modalities: self.modalities.clone(),
            subject_keys: component_keys(&self.subject_recipe),
            applicability_keys: self
                .dimensions
                .iter()
                .map(|dimension| {
                    (
                        dimension.dimension_id.clone(),
                        component_keys(&dimension.recipe),
                    )
                })
                .collect(),
        }
    }
}

/// Minimal public description of an assert route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AssertRouteDescriptionV1 {
    pub predicate: AssertRoutePredicateV1,
    pub value_kind: &'static str,
    pub modalities: Vec<PropositionModalityV1>,
    /// Locator component keys of the subject.
    pub subject_keys: Vec<ContractId>,
    /// Locator component keys of each applicability dimension.
    pub applicability_keys: BTreeMap<ContractId, Vec<ContractId>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AssertRoutePredicateV1 {
    pub id: ContractId,
    pub version: u32,
}

/// Resolve the one authenticated-actor remember route of `package`.
///
/// The successor closure already guarantees at most one authenticated-actor
/// rule per predicate. This additionally requires exactly one across the
/// whole package, because an assert names no rule and must not be routed by
/// guesswork. It then closes the route over the package:
///
/// * the predicate and rule bodies resolve through
///   [`StructurallyResolvedRememberContractsV2::from_registry_entries`];
/// * the subject recipe resolves out of the package, matches the predicate's
///   exact recipe and resource-kind references, and is entity-form;
/// * each applicability dimension is planned as [`DimensionDerivationV1`].
///
/// A resource-valued predicate, a non-entity subject, and any dimension that
/// cannot be derived from its components fail closed.
pub fn resolve_assert_route(
    package: &SemanticallyClosedSuccessorPackage,
) -> ContractResult<RememberAssertRouteV1> {
    let manifest = package.manifest_verified_package();
    let mut routes = Vec::new();
    for entry in &manifest.package().entries {
        if entry.kind != RegistryEntryKind::AuthorityRule {
            continue;
        }
        let reference = RegistryReferenceV1 {
            entry_id: entry.entry_id.clone(),
            version: entry.version,
            entry_digest: entry.digest()?,
        };
        if let Some(rule) = package.remember_admission(&reference)
            && let Some(basis) = rule.basis_rules.iter().find_map(authenticated_actor_basis)
        {
            routes.push((reference, rule, basis));
        }
    }
    let [(admission_reference, rule, (basis_modalities, maximum_support_events))] =
        routes.as_slice()
    else {
        return Err(ContractError::Schema(format!(
            "the active package must have exactly one authenticated-actor remember route, not {}",
            routes.len()
        )));
    };
    let predicate_entry =
        package.exact_entry(RegistryEntryKind::PredicateSchema, &rule.predicate_schema)?;
    let admission_entry =
        package.exact_entry(RegistryEntryKind::AuthorityRule, admission_reference)?;
    let contracts = StructurallyResolvedRememberContractsV2::from_registry_entries(
        predicate_entry,
        admission_entry,
    )?;
    let predicate = contracts.predicate();
    if matches!(
        predicate.value_constraint,
        RememberValueConstraintV2::ResourceUri { .. }
    ) {
        return Err(ContractError::Schema(
            "resource-valued remember predicates are not served by assert".into(),
        ));
    }
    let subject_recipe = constrained_recipe(manifest, &predicate.subject_identity)?;
    if subject_recipe.recipe().identity_form != IdentityForm::Entity {
        return Err(ContractError::Schema(
            "the remember subject must be entity-form to derive from components".into(),
        ));
    }
    let mut dimensions = Vec::with_capacity(predicate.applicability_dimensions.len());
    for dimension in &predicate.applicability_dimensions {
        let recipe = constrained_recipe(manifest, &dimension.resource_identity)?;
        let derivation = match recipe.recipe().identity_form {
            IdentityForm::Entity => DimensionDerivationV1::Entity,
            IdentityForm::Version
                if resolve_parent_entity_recipe(manifest, &recipe).is_err()
                    && recipe.parent_entity_kind()
                        == Some(&predicate.subject_identity.resource_kind_schema) =>
            {
                DimensionDerivationV1::VersionUnderSubject
            }
            IdentityForm::Version | IdentityForm::Occurrence => {
                return Err(ContractError::Schema(format!(
                    "applicability dimension `{}` cannot be derived from locator components",
                    dimension.dimension_id
                )));
            }
        };
        dimensions.push(DimensionRouteV1 {
            dimension_id: dimension.dimension_id.clone(),
            required: dimension.required,
            recipe,
            derivation,
        });
    }
    let modalities = predicate
        .allowed_modalities
        .iter()
        .copied()
        .filter(|modality| basis_modalities.contains(modality))
        .collect::<Vec<_>>();
    if modalities.is_empty() {
        return Err(ContractError::Schema(
            "the assert route admits no modality".into(),
        ));
    }
    Ok(RememberAssertRouteV1 {
        package_digest: package.package_digest(),
        modalities,
        maximum_support_events: *maximum_support_events,
        subject_recipe,
        dimensions,
        contracts,
    })
}

/// Why an assertion was not admitted. Nothing was written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RememberAdmissionRefusalReason {
    /// The text breaks the canonical assertion-text or claim-projection rules.
    TextInvalid,
    /// The compare-only `predicate` names a different predicate.
    PredicateMismatch,
    /// A subject or applicability locator is missing, unknown, or not in its
    /// component encoding.
    LocatorInvalid,
    /// The value does not have the predicate's value kind or bounds.
    ValueInvalid,
    /// The modality is not one the route admits.
    ModalityNotAllowed,
    /// Too many, or zero-digest, support evidence event IDs.
    SupportInvalid,
    /// The effective interval breaks the active interval rule.
    EffectiveIntervalInvalid,
    /// Any other failure of the active contract's admission checks.
    AssertionNotAdmitted,
    /// The route was resolved from a package the head does not activate.
    RegistryHeadMismatch,
}

impl RememberAdmissionRefusalReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TextInvalid => "text_invalid",
            Self::PredicateMismatch => "predicate_mismatch",
            Self::LocatorInvalid => "locator_invalid",
            Self::ValueInvalid => "value_invalid",
            Self::ModalityNotAllowed => "modality_not_allowed",
            Self::SupportInvalid => "support_invalid",
            Self::EffectiveIntervalInvalid => "effective_interval_invalid",
            Self::AssertionNotAdmitted => "assertion_not_admitted",
            Self::RegistryHeadMismatch => "registry_head_mismatch",
        }
    }
}

impl fmt::Display for RememberAdmissionRefusalReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A typed, caller-correctable admission refusal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, thiserror::Error)]
#[error("{reason}: {message}")]
pub struct RememberAdmissionRefusal {
    pub reason: RememberAdmissionRefusalReason,
    pub message: String,
}

impl RememberAdmissionRefusal {
    fn new(reason: RememberAdmissionRefusalReason, message: impl Into<String>) -> Self {
        Self {
            reason,
            message: message.into(),
        }
    }

    fn not_admitted(error: &ContractError) -> Self {
        Self::new(
            RememberAdmissionRefusalReason::AssertionNotAdmitted,
            error.to_string(),
        )
    }
}

/// One admitted assertion: the opaque statement plus what its legacy claim
/// projection needs.
#[derive(Debug)]
pub struct AdmittedRememberAssertionV1 {
    admitted: AdmittedRememberStatementV2,
    accepted_event_id: AcceptedEventId,
    subject: ResourceUri,
    applicability: Vec<ConcreteApplicabilityDimensionV1>,
    claim_key: String,
    predicate: RegistryReferenceV1,
    modality: PropositionModalityV1,
    publication_default: PublicationDefaultV1,
}

impl AdmittedRememberAssertionV1 {
    /// The append capability.
    #[must_use]
    pub const fn admitted(&self) -> &AdmittedRememberStatementV2 {
        &self.admitted
    }

    #[must_use]
    pub fn into_admitted(self) -> AdmittedRememberStatementV2 {
        self.admitted
    }

    /// Semantic accepted-event identity of the admitted statement.
    #[must_use]
    pub const fn accepted_event_id(&self) -> AcceptedEventId {
        self.accepted_event_id
    }

    /// Server-rederived subject URI.
    #[must_use]
    pub const fn subject(&self) -> &ResourceUri {
        &self.subject
    }

    /// Server-rederived applicability, strictly by dimension ID.
    #[must_use]
    pub fn applicability(&self) -> &[ConcreteApplicabilityDimensionV1] {
        &self.applicability
    }

    /// `claim-v2:<coordinate id>:<modality>`.
    #[must_use]
    pub fn claim_key(&self) -> &str {
        &self.claim_key
    }

    /// Exact predicate-schema entry the assertion was admitted under.
    #[must_use]
    pub const fn predicate(&self) -> &RegistryReferenceV1 {
        &self.predicate
    }

    #[must_use]
    pub const fn modality(&self) -> PropositionModalityV1 {
        self.modality
    }

    /// The predicate's publication default. Admission does not publish.
    #[must_use]
    pub const fn publication_default(&self) -> PublicationDefaultV1 {
        self.publication_default
    }
}

/// Admit one assertion through `route` under the trusted `head`, `scope`,
/// and `actor`, with `now` as the server clock.
///
/// `package` must be the package `head` activates and `route` was resolved
/// from; a mismatch is refused as [`RememberAdmissionRefusalReason::RegistryHeadMismatch`].
/// The result is deterministic in its inputs: the same input, actor, head,
/// scope, and clock always yield the same accepted-event ID.
pub fn admit_remember_assertion(
    route: &RememberAssertRouteV1,
    package: &SemanticallyClosedSuccessorPackage,
    head: &RegistryHeadBindingV1,
    scope: &AuthenticatedProjectScopeV1,
    actor: &ContractId,
    input: &RememberAssertInputV1,
    now: DateTime<Utc>,
) -> Result<AdmittedRememberAssertionV1, RememberAdmissionRefusal> {
    if route.package_digest != package.package_digest()
        || head.head.package_digest != route.package_digest
    {
        return Err(RememberAdmissionRefusal::new(
            RememberAdmissionRefusalReason::RegistryHeadMismatch,
            "the assert route was not resolved from the package the active head activates",
        ));
    }
    let predicate = route.contracts.predicate();
    let admission = route.contracts.admission();

    let text = admit_text(input, admission.maximum_assertion_text_utf8_bytes)?;
    if let Some(requested) = &input.predicate
        && requested != &predicate.predicate_id
    {
        return Err(RememberAdmissionRefusal::new(
            RememberAdmissionRefusalReason::PredicateMismatch,
            format!(
                "predicate `{requested}` is not the active assert predicate `{}`",
                predicate.predicate_id
            ),
        ));
    }
    let rederived = rederive(route, scope, input)?;
    check_claim_shape(route, input)?;
    let support_evidence_event_ids = admit_support(route, &input.support_evidence_event_ids)?;
    let now = truncate_to_microseconds(now)?;
    let effective_interval = admit_interval(&admission.effective_interval_rule, input, &now)?;

    let candidate = RememberIngressCandidateV2 {
        schema_version: REMEMBER_SCHEMA_VERSION,
        asserted_subject: rederived.subject.uri().clone(),
        subject_identity_recipe: predicate.subject_identity.identity_recipe.clone(),
        predicate_schema: route.contracts.predicate_reference().clone(),
        applicability_evaluator: predicate.applicability_evaluator.clone(),
        admission_rule: route.contracts.admission_reference().clone(),
        assertion_kind: input.kind,
        assertion_text_utf8_hex_chunks: text,
        modality: input.modality,
        polarity: input.polarity,
        value: input.value.clone(),
        applicability: rederived
            .applicability
            .iter()
            .map(|(dimension_id, derived)| ConcreteApplicabilityDimensionV1 {
                dimension_id: dimension_id.clone(),
                resource: derived.uri().clone(),
            })
            .collect(),
        effective_interval,
        requested_basis: RememberAdmissionBasisV2::AuthenticatedActor,
        support_evidence_event_ids,
    };
    route
        .contracts
        .validate_candidate_shape(&candidate)
        .map_err(|error| RememberAdmissionRefusal::not_admitted(&error))?;

    let admitted = admit_authenticated_actor_statement(
        &route.contracts,
        &candidate,
        &rederived,
        &package.manifest_verified_package().package().profile,
        scope,
        head,
        RememberActorV2 {
            principal_id: actor.clone(),
        },
        &now,
    )
    .map_err(|error| RememberAdmissionRefusal::not_admitted(&error))?;
    let statement = admitted.statement();
    let coordinate_id = statement
        .claim
        .coordinate()
        .coordinate_id()
        .map_err(|error| RememberAdmissionRefusal::not_admitted(&error))?;
    let accepted_event_id = statement
        .accepted_event_id()
        .map_err(|error| RememberAdmissionRefusal::not_admitted(&error))?;
    Ok(AdmittedRememberAssertionV1 {
        accepted_event_id,
        subject: statement.claim.subject.clone(),
        applicability: statement.claim.applicability.clone(),
        claim_key: format!(
            "{CLAIM_KEY_PREFIX}:{coordinate_id}:{}",
            modality_name(input.modality)
        ),
        predicate: route.contracts.predicate_reference().clone(),
        modality: input.modality,
        publication_default: predicate.publication_default,
        admitted,
    })
}

/// The legacy claim kind an assertion kind projects to.
#[must_use]
pub const fn claim_kind_for(kind: RememberAssertionKindV2) -> ClaimKind {
    match kind {
        RememberAssertionKindV2::Decision => ClaimKind::Decision,
        RememberAssertionKindV2::Fact => ClaimKind::Fact,
        RememberAssertionKindV2::Constraint => ClaimKind::Constraint,
        RememberAssertionKindV2::Preference => ClaimKind::Preference,
        RememberAssertionKindV2::Procedure => ClaimKind::Procedure,
    }
}

/// The legacy `-1`/`1` polarity a truth direction projects to.
#[must_use]
pub const fn claim_polarity_for(polarity: ClaimPolarityV2) -> i16 {
    match polarity {
        ClaimPolarityV2::Affirms => 1,
        ClaimPolarityV2::Negates => -1,
    }
}

/// The wire name of a modality.
#[must_use]
pub const fn modality_name(modality: PropositionModalityV1) -> &'static str {
    match modality {
        PropositionModalityV1::Attested => "attested",
        PropositionModalityV1::Intended => "intended",
        PropositionModalityV1::Normative => "normative",
        PropositionModalityV1::Observed => "observed",
    }
}

const fn authenticated_actor_basis(
    basis: &RememberAdmissionBasisRuleV2,
) -> Option<(&[PropositionModalityV1], u16)> {
    match basis {
        RememberAdmissionBasisRuleV2::AuthenticatedActor {
            allowed_modalities,
            maximum_support_events,
        } => Some((allowed_modalities.as_slice(), *maximum_support_events)),
        RememberAdmissionBasisRuleV2::RegisteredObserver { .. }
        | RememberAdmissionBasisRuleV2::ActivatedNormativeBinding { .. } => None,
    }
}

/// Resolve the exact recipe a resource-identity constraint names, and
/// require it to derive the constraint's exact resource kind.
fn constrained_recipe(
    package: &ManifestVerifiedRegistryPackage,
    constraint: &ResourceIdentityConstraintV2,
) -> ContractResult<ValidatedIdentityRecipe> {
    let reference = &constraint.identity_recipe;
    let recipe =
        ValidatedIdentityRecipe::from_package(package, &reference.entry_id, reference.version)?;
    if recipe.registry_reference() != reference
        || recipe.recipe().resource_kind_schema != constraint.resource_kind_schema
    {
        return Err(ContractError::ManifestMismatch);
    }
    Ok(recipe)
}

/// Check the text against the legacy claim projection's rules and the
/// canonical assertion-text contract, before anything is derived or embedded.
fn admit_text(
    input: &RememberAssertInputV1,
    maximum_utf8_bytes: u32,
) -> Result<CanonicalAssertionTextV2, RememberAdmissionRefusal> {
    let projection = ClaimInput {
        kind: claim_kind_for(input.kind),
        text: input.text.clone(),
        subject: None,
        predicate: None,
        value: None,
        polarity: claim_polarity_for(input.polarity),
        origin: OPERATOR_ASSERTED_ORIGIN.to_owned(),
        actor: None,
        confidence: 1.0,
        valid_from: None,
        valid_to: None,
        support: Vec::new(),
    };
    projection.validate().map_err(|error| {
        let message = match error {
            FleetError::Memory(message) => message,
            other => other.to_string(),
        };
        RememberAdmissionRefusal::new(RememberAdmissionRefusalReason::TextInvalid, message)
    })?;
    if input.text.len() > usize::try_from(maximum_utf8_bytes).unwrap_or(0) {
        return Err(RememberAdmissionRefusal::new(
            RememberAdmissionRefusalReason::TextInvalid,
            format!("text must not exceed {maximum_utf8_bytes} UTF-8 bytes"),
        ));
    }
    CanonicalAssertionTextV2::parse(input.text.clone()).map_err(|_| {
        RememberAdmissionRefusal::new(
            RememberAdmissionRefusalReason::TextInvalid,
            "text must be Unicode NFC with no control characters other than LF and TAB, \
             and no byte-order mark, noncharacter, or private-use scalar",
        )
    })
}

/// Check the modality, assertion kind, and value against the route, so each
/// failure carries its own reason rather than a generic contract error.
fn check_claim_shape(
    route: &RememberAssertRouteV1,
    input: &RememberAssertInputV1,
) -> Result<(), RememberAdmissionRefusal> {
    if !route.modalities.contains(&input.modality) {
        return Err(RememberAdmissionRefusal::new(
            RememberAdmissionRefusalReason::ModalityNotAllowed,
            format!(
                "modality `{}` is not admitted; use one of {}",
                modality_name(input.modality),
                route
                    .modalities
                    .iter()
                    .map(|modality| modality_name(*modality))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ));
    }
    if !route
        .contracts
        .admission()
        .allowed_assertion_kinds
        .contains(&input.kind)
    {
        return Err(RememberAdmissionRefusal::new(
            RememberAdmissionRefusalReason::AssertionNotAdmitted,
            "the active rule does not admit this assertion kind",
        ));
    }
    let constraint = &route.contracts.predicate().value_constraint;
    if !constraint.accepts_value_shape(&input.value) {
        return Err(RememberAdmissionRefusal::new(
            RememberAdmissionRefusalReason::ValueInvalid,
            format!(
                "value must be a `{}` value within the predicate's bounds",
                value_kind_name(constraint)
            ),
        ));
    }
    check_projected_value(&input.value)
}

/// Refuse a value the legacy claim row cannot store. A string or string-set
/// predicate's own bounds admit values whose canonical JSON exceeds the row's
/// [`MAX_CLAIM_VALUE_SERIALIZED_BYTES`], so this is checked here, as a typed
/// `value_invalid`, rather than after embedding.
pub(super) fn check_projected_value(
    value: &CanonicalClaimValueV2,
) -> Result<(), RememberAdmissionRefusal> {
    let fits = serde_json::to_value(value).is_ok_and(|value| {
        canonical_json(&value).to_string().len() <= MAX_CLAIM_VALUE_SERIALIZED_BYTES
    });
    if fits {
        return Ok(());
    }
    Err(RememberAdmissionRefusal::new(
        RememberAdmissionRefusalReason::ValueInvalid,
        format!("value must not exceed {MAX_CLAIM_VALUE_SERIALIZED_BYTES} serialized JSON bytes"),
    ))
}

/// Rederive the subject and every applicability URI from their components.
fn rederive(
    route: &RememberAssertRouteV1,
    scope: &AuthenticatedProjectScopeV1,
    input: &RememberAssertInputV1,
) -> Result<RederivedRememberIdentitiesV2, RememberAdmissionRefusal> {
    let subject = derive_entity_with_recipe(&route.subject_recipe, scope, &input.subject)
        .map_err(|error| locator_refusal("subject", &route.subject_recipe, &error))?;
    if let Some(unknown) = input.applicability.keys().find(|key| {
        !route
            .dimensions
            .iter()
            .any(|dimension| dimension.dimension_id.as_str() == key.as_str())
    }) {
        return Err(RememberAdmissionRefusal::new(
            RememberAdmissionRefusalReason::LocatorInvalid,
            format!("unknown applicability dimension `{unknown}`"),
        ));
    }
    let mut applicability = Vec::with_capacity(route.dimensions.len());
    for dimension in &route.dimensions {
        let Some(components) = input.applicability.get(dimension.dimension_id.as_str()) else {
            if dimension.required {
                return Err(RememberAdmissionRefusal::new(
                    RememberAdmissionRefusalReason::LocatorInvalid,
                    format!(
                        "missing required applicability dimension `{}`",
                        dimension.dimension_id
                    ),
                ));
            }
            continue;
        };
        let derived = match dimension.derivation {
            DimensionDerivationV1::Entity => {
                derive_entity_with_recipe(&dimension.recipe, scope, components)
            }
            DimensionDerivationV1::VersionUnderSubject => {
                locator_from_components(&dimension.recipe, scope, Some(subject.uri()), components)
                    .and_then(|locator| {
                        derive_version_under_entity_parent(
                            &dimension.recipe.derivation_context(scope),
                            &locator,
                            &dimension.recipe,
                            &subject,
                        )
                    })
            }
        }
        .map_err(|error| {
            locator_refusal(
                &format!("applicability.{}", dimension.dimension_id),
                &dimension.recipe,
                &error,
            )
        })?;
        applicability.push((dimension.dimension_id.clone(), derived));
    }
    Ok(RederivedRememberIdentitiesV2 {
        subject,
        applicability,
    })
}

fn locator_refusal(
    field: &str,
    recipe: &ValidatedIdentityRecipe,
    error: &ContractError,
) -> RememberAdmissionRefusal {
    let expected = recipe
        .recipe()
        .component_rules
        .iter()
        .map(|rule| format!("`{}` ({})", rule.key, encoding_name(rule.encoding)))
        .collect::<Vec<_>>()
        .join(", ");
    RememberAdmissionRefusal::new(
        RememberAdmissionRefusalReason::LocatorInvalid,
        format!("{field}: {error}; expected components: {expected}"),
    )
}

const fn encoding_name(encoding: LocatorEncoding) -> &'static str {
    match encoding {
        LocatorEncoding::Decimal => "canonical decimal",
        LocatorEncoding::HexBytes => "lowercase even-length hex",
        LocatorEncoding::NfcUtf8 => "NFC UTF-8 text",
    }
}

fn admit_support(
    route: &RememberAssertRouteV1,
    requested: &[AcceptedEventId],
) -> Result<Vec<AcceptedEventId>, RememberAdmissionRefusal> {
    let maximum = usize::from(route.maximum_support_events);
    if requested.len() > maximum {
        return Err(RememberAdmissionRefusal::new(
            RememberAdmissionRefusalReason::SupportInvalid,
            format!("at most {maximum} support evidence event IDs are admitted"),
        ));
    }
    if requested
        .iter()
        .any(|event_id| event_id.digest() == Sha256Digest::ZERO)
    {
        return Err(RememberAdmissionRefusal::new(
            RememberAdmissionRefusalReason::SupportInvalid,
            "a support evidence event ID cannot be the zero digest",
        ));
    }
    Ok(requested
        .iter()
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect())
}

fn truncate_to_microseconds(
    now: DateTime<Utc>,
) -> Result<CanonicalTimestamp, RememberAdmissionRefusal> {
    DateTime::<Utc>::from_timestamp_micros(now.timestamp_micros())
        .and_then(|now| CanonicalTimestamp::from_datetime(&now).ok())
        .ok_or_else(|| {
            RememberAdmissionRefusal::new(
                RememberAdmissionRefusalReason::EffectiveIntervalInvalid,
                "the server clock is outside the canonical timestamp range",
            )
        })
}

fn canonical_time(
    value: &DateTime<Utc>,
    field: &str,
) -> Result<CanonicalTimestamp, RememberAdmissionRefusal> {
    CanonicalTimestamp::from_datetime(value).map_err(|_| {
        RememberAdmissionRefusal::new(
            RememberAdmissionRefusalReason::EffectiveIntervalInvalid,
            format!("{field} is outside the canonical timestamp range"),
        )
    })
}

/// Build the effective interval, defaulting `effective_from` to `now`, and
/// require the whole active interval rule.
fn admit_interval(
    rule: &RememberEffectiveIntervalRuleV2,
    input: &RememberAssertInputV1,
    now: &CanonicalTimestamp,
) -> Result<ClaimEffectiveIntervalV2, RememberAdmissionRefusal> {
    let effective_from = match &input.effective_from {
        Some(from) => canonical_time(from, "effective_from")?,
        None => now.clone(),
    };
    let effective_until = input
        .effective_until
        .as_ref()
        .map(|until| canonical_time(until, "effective_until"))
        .transpose()?;
    let interval = ClaimEffectiveIntervalV2 {
        effective_from,
        effective_until,
    };
    if rule.admits(&interval, now) {
        return Ok(interval);
    }
    let from = &interval.effective_from;
    let until = interval.effective_until.as_ref();
    let message = if !from.is_microsecond_aligned()
        || until.is_some_and(|until| !until.is_microsecond_aligned())
    {
        "effective_from and effective_until must be whole microseconds"
    } else if from > now && !rule.future_effective_from_allowed {
        "effective_from is later than the server clock; the active rule admits no \
         future-effective assertion"
    } else if from < now && !rule.past_effective_from_allowed {
        "effective_from is earlier than the server clock; the active rule admits no \
         past-effective assertion"
    } else if from != now && !rule.payload_may_select_effective_from {
        "the active rule does not let an assertion choose its effective_from"
    } else if until.is_some_and(|until| until <= from) {
        "effective_until must be later than effective_from"
    } else if until.is_some() {
        "the active rule admits no bounded effective interval"
    } else {
        "the active rule admits no open-ended effective interval"
    };
    Err(RememberAdmissionRefusal::new(
        RememberAdmissionRefusalReason::EffectiveIntervalInvalid,
        message,
    ))
}

const fn value_kind_name(constraint: &RememberValueConstraintV2) -> &'static str {
    match constraint {
        RememberValueConstraintV2::Boolean { .. } => "boolean",
        RememberValueConstraintV2::CanonicalDecimal { .. } => "canonical_decimal",
        RememberValueConstraintV2::ContractId => "contract_id",
        RememberValueConstraintV2::ResourceUri { .. } => "resource_uri",
        RememberValueConstraintV2::Sha256Digest => "sha256_digest",
        RememberValueConstraintV2::String { .. } => "string",
        RememberValueConstraintV2::StringSet { .. } => "string_set",
    }
}

fn component_keys(recipe: &ValidatedIdentityRecipe) -> Vec<ContractId> {
    recipe
        .recipe()
        .component_rules
        .iter()
        .map(|rule| rule.key.clone())
        .collect()
}

#[cfg(test)]
#[path = "admission_tests.rs"]
mod tests;
