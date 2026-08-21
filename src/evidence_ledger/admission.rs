//! Evidence v2 admission: from an ingress candidate to an appendable accepted
//! event (Stage 4 general accepted-evidence events).
//!
//! # The pipeline, and why each stage exists
//!
//! ```text
//! EvidenceIngressCandidateV2            (asserted + transport-bearing)
//!   -> ActiveStage4Package              (package digest == the witnessed head's)
//!   -> connector + identity recipes     (resolved FROM that package, never from payload)
//!   -> URI / source-fact rederivation   (derived, then compared with what was declared)
//!   -> server-derived governance        (read from the activated policy bodies)
//!   -> EvidenceStatementV2              (validate_against_structural_connector)
//!   -> AppendableAcceptedEvent          (bound to the head witness)
//!   -> AcceptedEventRepository::append  (+ GovernedContentProjection, one transaction)
//! ```
//!
//! Every stage exists because the previous one cannot prove the next fact:
//!
//! * A candidate can *name* a connector. Only [`ActiveStage4Package`] can prove
//!   the named connector is the one in the package the active head activated
//!   (AUTH-04, EVID-04). The binding is the package digest: the writer-authority
//!   view reports the active head's `package_digest`, the offline package
//!   recomputes its own, and admission refuses to start unless they are equal.
//! * A candidate can *assert* resource URIs. Only rederivation through the
//!   activated identity recipes proves those URIs are the ones the registry's
//!   own recipe produces from the published provider coordinates (PROV-01,
//!   EVID-02). A mismatch is a closed rejection, never a "trust the caller"
//!   fallback.
//! * A candidate carries no governance classification at all. Visibility,
//!   retention, and publication classes are read out of the activated
//!   classifier / retention / publication bodies, so a payload cannot select a
//!   protection domain, a retention class, or publication approval (EVID-04,
//!   EVID-05, PUBLIC-04).
//! * Integrity state is derived, never supplied. See
//!   [`derive_integrity_state`].
//!
//! # Scope comes from the credential, never the payload
//!
//! [`EvidenceIngressCandidateV2`] does carry a `scope` field, because the wire
//! form has to round-trip. Admission never *uses* it: the produced statement's
//! scope is [`WriterAuthorityWitness::semantic_scope`], and a candidate whose
//! declared scope differs is rejected with
//! [`EvidenceAdmissionError::PayloadSelectedScope`] before any derivation, any
//! encryption, and any database work (EVID-04).
//!
//! # What this stage deliberately does not admit yet
//!
//! * A private raw artifact. EVID-05 requires a separate key, policy, and
//!   retention boundary for the private raw archive; that boundary does not
//!   exist, so a candidate carrying one is refused rather than quietly stored
//!   under the governed key.
//! * A `version`-form resource whose locator names a parent entity. The parent
//!   derivation seam is not built, and guessing a parent would be exactly the
//!   self-asserted identity this module exists to prevent.
//! * `provider_verified` / `signature_verified` integrity. See
//!   [`derive_integrity_state`].

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::memory_contracts::canonical::{decode_strict, encode_canonical};
use crate::memory_contracts::chunk_identity::StorageIdentityPreimageV1;
use crate::memory_contracts::common::{
    AuthenticatedProjectScopeV1, CanonicalDecimal, CanonicalTimestamp, ContractId,
    ProfileReferenceV1, RegistryReferenceV1,
};
use crate::memory_contracts::digest::Sha256Digest;
use crate::memory_contracts::evidence::{
    ErasureScopeKind, ErasureScopeReferenceV1, GovernedContentIdentityV1, IntegrityState,
    PublicationClass, RetentionClass, VisibilityClass,
};
use crate::memory_contracts::evidence_v2::{
    EvidenceIngressCandidateV2, EvidenceStatementV2, RegistryHeadBindingV1,
    RepresentationIdentityV2, RepresentationLineageV2, SourceFactIdV2,
    StructurallyResolvedConnectorSchemaV2, derive_representation_key_v2, derive_source_fact_id_v2,
};
use crate::memory_contracts::identity::{
    CanonicalLocatorV1, IdentityDerivationContextV1, LocatorEncoding, ValidatedIdentityRecipe,
    derive_resource_uri,
};
use crate::memory_contracts::registry::{RegistryEntryKind, RegistryEntryV1};
use crate::memory_contracts::stage4_target_package::SemanticallyClosedStage4Package;
use crate::memory_contracts::{ContractError, ContractResult};

use super::appendable::{AppendableAcceptedEvent, EvidenceDeliveryContextV1};
use super::content_store::{GovernedContentObjectV1, MAX_GOVERNED_CONTENT_BYTES};
use super::error::{EvidenceAppendError, EvidenceAppendResult};
use super::witness::WriterAuthorityWitness;

const EVIDENCE_SCHEMA_VERSION: u32 = 2;
const POLICY_BODY_SCHEMA_VERSION: u32 = 1;
const STORAGE_IDENTITY_SCHEMA_VERSION: u32 = 1;
const IMMUTABLE_REVISION_KEY: &str = "immutable_revision";
const PROVIDER_OBJECT_ID_KEY: &str = "provider_object_id";

/// Which resource identity failed rederivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceIdentityKind {
    /// `source_fact.provider_instance_id`.
    ProviderInstance,
    /// `source_fact.canonical_resource_id`.
    CanonicalResource,
}

impl ResourceIdentityKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProviderInstance => "provider_instance_id",
            Self::CanonicalResource => "canonical_resource_id",
        }
    }
}

/// Which EVID-03 clock ordering was violated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockOrderKind {
    /// A timestamp is not microsecond-aligned, so its identity bytes could not
    /// survive a `TIMESTAMPTZ` round trip.
    NotMicrosecondAligned,
    /// The provider observed the fact before it occurred.
    ObservedBeforeOccurred,
    /// The ingress received the delivery before the provider observed it.
    ReceivedBeforeObserved,
}

impl ClockOrderKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotMicrosecondAligned => "timestamp is not microsecond aligned",
            Self::ObservedBeforeOccurred => "observed_at precedes occurred_at",
            Self::ReceivedBeforeObserved => "received_at precedes observed_at",
        }
    }
}

/// Closed rejection taxonomy of evidence admission.
///
/// Every variant is a refusal: nothing is written, nothing is encrypted, and no
/// weaker statement is synthesized in place of the rejected one.
#[derive(Debug, thiserror::Error)]
pub enum EvidenceAdmissionError {
    /// A memory contract refused an input or a derived value.
    #[error("evidence admission contract failure: {0}")]
    Contract(#[from] ContractError),
    /// The candidate's declared scope is not the credential-bound scope of the
    /// active head (EVID-04).
    #[error("evidence candidate declares a scope the credential did not authorize")]
    PayloadSelectedScope,
    /// The offline package is not the one the active head activated.
    #[error("the supplied registry package is not the activated package")]
    PackageNotActive,
    /// The candidate names a connector entry that is not the active package's.
    #[error("evidence candidate names a connector outside the active package")]
    ConnectorNotInActivePackage,
    /// A registry reference the connector body names does not resolve to the
    /// exact entry in the active package.
    #[error("active package does not close over the exact {0} entry the connector names")]
    RegistryReferenceNotInActivePackage(&'static str),
    /// The active package does not contain exactly one entry of a policy kind.
    #[error("active package does not contain exactly one {0} entry")]
    AmbiguousActivePolicy(&'static str),
    /// An activated policy body is missing a guarantee this stage requires.
    #[error("activated policy body is not admissible: {0}")]
    PolicyBodyRefused(String),
    /// Rederiving a resource URI through its activated recipe did not reproduce
    /// the candidate's declared identity.
    #[error("rederived {} does not equal the declared identity", .0.as_str())]
    ResourceIdentityMismatch(ResourceIdentityKind),
    /// A locator coordinate does not equal the published provider fact the
    /// candidate declares under the same name.
    #[error("locator component {0} does not equal the declared provider coordinate")]
    LocatorCoordinateMismatch(&'static str),
    /// A locator names a parent entity, which this stage cannot derive.
    #[error("locators naming a parent entity are not admitted yet")]
    ParentEntityUnsupported,
    /// EVID-03 clock ordering failed.
    #[error("evidence clocks are inconsistent: {}", .0.as_str())]
    ClockOrder(ClockOrderKind),
    /// The supplied canonical bytes do not hash to the declared digest.
    #[error("canonical payload bytes do not reproduce the declared content digest")]
    ContentDigestMismatch,
    /// The supplied canonical bytes are not the declared length.
    #[error("canonical payload bytes are not the declared byte length")]
    ContentLengthMismatch,
    /// The payload exceeds what the governed content store can hold.
    #[error(
        "canonical payload exceeds the governed content bound of {MAX_GOVERNED_CONTENT_BYTES} bytes"
    )]
    ContentTooLarge,
    /// The declared storage identity is not the one the protection domain and
    /// content digest derive.
    #[error("declared storage identity is not the derived protection-domain-keyed identity")]
    StorageIdentityMismatch,
    /// A private raw artifact was offered; its separate key/policy/retention
    /// boundary does not exist yet (EVID-05).
    #[error("private raw artifacts are not admitted by this stage")]
    PrivateRawArtifactUnsupported,
    /// The appendable could not be built from the admitted statement.
    #[error("admitted statement could not be bound to the head witness: {0}")]
    Append(#[from] EvidenceAppendError),
}

/// One offline Stage-4 package proven to be the package the active head
/// activated.
///
/// This is the type that turns "a package" into "the active package". It is not
/// registry authority on its own: the authority is the writer-authority view
/// the [`WriterAuthorityWitness`] was read from, and the append transaction
/// re-reads that view under serializable isolation. What binding adds is the
/// link from that head to a concrete, manifest-verified set of entries, so
/// connector and recipe resolution can be *from the active package* rather than
/// from whatever bytes a caller happened to pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveStage4Package {
    package: SemanticallyClosedStage4Package,
    head: RegistryHeadBindingV1,
    scope: AuthenticatedProjectScopeV1,
    profile: ProfileReferenceV1,
}

impl ActiveStage4Package {
    /// Prove `package` is the activated package for `witness`'s head.
    ///
    /// The head binding is the caller's; every field of its head triple must
    /// equal the witness's, and the package's own recomputed digest must equal
    /// the activated `package_digest`. Scope and profile are then taken from
    /// the witness and the package respectively — never from a request.
    pub fn bind(
        package: SemanticallyClosedStage4Package,
        head: RegistryHeadBindingV1,
        witness: &WriterAuthorityWitness,
    ) -> Result<Self, EvidenceAdmissionError> {
        head.validate_shape()?;
        if head.head != *witness.head() {
            return Err(EvidenceAdmissionError::PackageNotActive);
        }
        if package.package_digest() != witness.head().package_digest {
            return Err(EvidenceAdmissionError::PackageNotActive);
        }
        let profile = package
            .successor_package()
            .manifest_verified_package()
            .package()
            .profile
            .clone();
        Ok(Self {
            package,
            head,
            scope: witness.semantic_scope().clone(),
            profile,
        })
    }

    /// The activated connector schema, resolved from the package itself.
    #[must_use]
    pub fn connector(&self) -> &StructurallyResolvedConnectorSchemaV2 {
        self.package.connector_schema()
    }

    /// The exact active-head binding every admitted statement carries.
    #[must_use]
    pub const fn head(&self) -> &RegistryHeadBindingV1 {
        &self.head
    }

    /// The credential-bound semantic scope of every admitted statement.
    #[must_use]
    pub const fn scope(&self) -> &AuthenticatedProjectScopeV1 {
        &self.scope
    }

    /// The canonicalization profile the activated package pins.
    #[must_use]
    pub const fn profile(&self) -> &ProfileReferenceV1 {
        &self.profile
    }

    fn entries(&self) -> &[RegistryEntryV1] {
        &self
            .package
            .successor_package()
            .manifest_verified_package()
            .package()
            .entries
    }

    fn unique_entry(
        &self,
        kind: RegistryEntryKind,
        label: &'static str,
    ) -> Result<&RegistryEntryV1, EvidenceAdmissionError> {
        let mut matching = self.entries().iter().filter(|entry| entry.kind == kind);
        let first = matching
            .next()
            .ok_or(EvidenceAdmissionError::AmbiguousActivePolicy(label))?;
        if matching.next().is_some() {
            return Err(EvidenceAdmissionError::AmbiguousActivePolicy(label));
        }
        Ok(first)
    }

    fn recipe(
        &self,
        reference: &RegistryReferenceV1,
        label: &'static str,
    ) -> Result<ValidatedIdentityRecipe, EvidenceAdmissionError> {
        let manifest = self.package.successor_package().manifest_verified_package();
        let recipe =
            ValidatedIdentityRecipe::from_package(manifest, &reference.entry_id, reference.version)
                .map_err(|_| EvidenceAdmissionError::RegistryReferenceNotInActivePackage(label))?;
        if recipe.registry_reference() != reference {
            return Err(EvidenceAdmissionError::RegistryReferenceNotInActivePackage(
                label,
            ));
        }
        Ok(recipe)
    }
}

/// Trusted locator inputs for the two resource identities a source fact names.
///
/// These are ingress-side coordinates, not payload authority: every field is
/// re-checked against the activated recipe, the trusted scope, and the
/// candidate's own published provider coordinates before any URI is accepted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceIngressLocatorsV1 {
    pub provider_instance: CanonicalLocatorV1,
    pub canonical_resource: CanonicalLocatorV1,
}

/// One complete admission request.
///
/// Bundled rather than passed as loose arguments so adding an input is a
/// visible, reviewable change to a named contract.
#[derive(Debug, Clone)]
pub struct EvidenceAdmissionRequestV1<'request> {
    /// The asserted, transport-bearing candidate.
    pub candidate: &'request EvidenceIngressCandidateV2,
    /// Trusted locator coordinates for URI rederivation.
    pub locators: &'request EvidenceIngressLocatorsV1,
    /// Exact canonical redacted payload bytes.
    pub canonical_payload: &'request [u8],
    /// Authenticated connector delivery metadata.
    pub delivery: EvidenceDeliveryContextV1,
    /// Representation ancestry. `Origin` for a first rendering; a
    /// reinterpretation must name the exact predecessor key (EVENT-01).
    pub lineage: RepresentationLineageV2,
}

/// One evidence statement that passed the whole admission pipeline, with the
/// governed content object it commits alongside.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedEvidenceStatementV2 {
    statement: EvidenceStatementV2,
    connector: StructurallyResolvedConnectorSchemaV2,
    delivery: EvidenceDeliveryContextV1,
    content: GovernedContentObjectV1,
}

impl AdmittedEvidenceStatementV2 {
    /// The production accepted-evidence statement.
    #[must_use]
    pub const fn statement(&self) -> &EvidenceStatementV2 {
        &self.statement
    }

    /// The governed content object that must commit in the same transaction.
    #[must_use]
    pub const fn content(&self) -> &GovernedContentObjectV1 {
        &self.content
    }

    /// The connector entry the statement was admitted against.
    #[must_use]
    pub const fn connector(&self) -> &StructurallyResolvedConnectorSchemaV2 {
        &self.connector
    }

    /// Bind this statement to the head witness the append will re-check.
    pub fn appendable(
        &self,
        witness: &WriterAuthorityWitness,
    ) -> EvidenceAppendResult<AppendableAcceptedEvent> {
        AppendableAcceptedEvent::evidence(
            &self.statement,
            &self.connector,
            self.delivery.clone(),
            witness,
        )
    }
}

/// Server-derived governance classification read from the activated policies.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ServerDerivedGovernance {
    redaction_policy: RegistryReferenceV1,
    classifier_policy: RegistryReferenceV1,
    retention_policy: RegistryReferenceV1,
    publication_policy: RegistryReferenceV1,
    visibility_class: VisibilityClass,
    retention_class: RetentionClass,
    publication_class: PublicationClass,
}

/// The strongest integrity state this stage can itself prove.
///
/// AUTH-02/AUTH-03: `provider_verified` and `signature_verified` are claims
/// about a provider signature or a provider-side verification this stage does
/// not perform, and EVID-04 forbids taking them from a payload — so no input
/// can raise the result. What admission does prove is that an authenticated
/// connector principal delivered bytes that reproduce the declared canonical
/// digest, which is exactly `transport_authenticated`. A later verification
/// stage that actually checks provider signatures may raise it; until then the
/// conservative value is the only reachable one.
#[must_use]
pub const fn derive_integrity_state() -> IntegrityState {
    IntegrityState::TransportAuthenticated
}

/// Admit one evidence ingress candidate against the active package.
///
/// Returns the production [`EvidenceStatementV2`] plus its governed content
/// object, or a closed [`EvidenceAdmissionError`].
pub fn admit_evidence(
    active: &ActiveStage4Package,
    request: EvidenceAdmissionRequestV1<'_>,
) -> Result<AdmittedEvidenceStatementV2, EvidenceAdmissionError> {
    let candidate = request.candidate;

    // (1) Scope, before anything else. The statement's scope is the witnessed
    // one; a candidate that declares a different one is refused rather than
    // silently rescoped (EVID-04).
    if candidate.scope != *active.scope() || candidate.source_fact.scope != *active.scope() {
        return Err(EvidenceAdmissionError::PayloadSelectedScope);
    }

    // (2) The connector must be the active package's, compared on the exact
    // entry digest, not merely on id and version.
    let connector = active.connector();
    if candidate.connector_schema != *connector.registry_reference() {
        return Err(EvidenceAdmissionError::ConnectorNotInActivePackage);
    }
    // Pins the candidate's schema version, its declared provider namespace, and
    // the scope agreement between candidate and source fact.
    candidate.validate_against_structural_connector(connector)?;
    if candidate.private_raw_artifact.is_some() {
        return Err(EvidenceAdmissionError::PrivateRawArtifactUnsupported);
    }

    // (3) EVID-03: three distinct clocks, ordered the only way they can be.
    require_clock_order(candidate)?;

    // (4) Rederive both resource identities through the activated recipes.
    require_derived_resource_identities(active, connector, candidate, request.locators)?;

    // (5) Identity preimages over published facts only.
    let source_fact_id = derive_source_fact_id_v2(&candidate.source_fact)?;

    // (6) Governance read out of the activated policy bodies.
    let governance = derive_server_governance(active)?;

    // (7) The erasure index EVID-08's fence is evaluated against, derived from
    // the identities this admission just proved.
    let erasure_scopes = derive_erasure_scopes(source_fact_id.digest(), candidate);

    let representation = build_representation(
        active,
        connector,
        source_fact_id,
        &governance,
        erasure_scopes.clone(),
        request.lineage,
    );
    let representation_key = derive_representation_key_v2(&representation)?;

    // (8) Governed content: verify the bytes, then derive the storage identity
    // rather than believing the declared one.
    let content = require_governed_content(active, candidate, request.canonical_payload)?;

    let statement = EvidenceStatementV2 {
        schema_version: EVIDENCE_SCHEMA_VERSION,
        event_kind: ContractId::new("evidence.accepted")?,
        profile: active.profile().clone(),
        scope: active.scope().clone(),
        registry_head: active.head().clone(),
        source_fact: candidate.source_fact.clone(),
        source_fact_id,
        representation,
        representation_key,
        provider_actor_id: candidate.provider_actor_id.clone(),
        occurred_at: candidate.occurred_at.clone(),
        observed_at: candidate.observed_at.clone(),
        canonical_content: content.clone(),
        integrity_state: derive_integrity_state(),
        visibility_class: governance.visibility_class,
        classifier_policy: governance.classifier_policy,
        retention_class: governance.retention_class,
        retention_policy: governance.retention_policy.clone(),
        erasure_scopes,
        publication_class: governance.publication_class,
        publication_policy: governance.publication_policy,
    };
    statement.validate_against_structural_connector(connector)?;

    let object = GovernedContentObjectV1::from_admitted(
        active.scope().clone(),
        content,
        candidate.canonical_payload.storage_identity,
        governance.retention_class,
        governance.retention_policy,
        request.canonical_payload.to_vec(),
    );

    Ok(AdmittedEvidenceStatementV2 {
        statement,
        connector: connector.clone(),
        delivery: request.delivery,
        content: object,
    })
}

/// Assemble the representation identity from the active package and the
/// server-derived governance. Every field is copied from a proven source; the
/// function takes no caller-supplied value except the lineage.
fn build_representation(
    active: &ActiveStage4Package,
    connector: &StructurallyResolvedConnectorSchemaV2,
    source_fact_id: SourceFactIdV2,
    governance: &ServerDerivedGovernance,
    erasure_scopes: Vec<ErasureScopeReferenceV1>,
    lineage: RepresentationLineageV2,
) -> RepresentationIdentityV2 {
    RepresentationIdentityV2 {
        schema_version: EVIDENCE_SCHEMA_VERSION,
        source_fact_id,
        registry_head: active.head().clone(),
        connector_schema: connector.registry_reference().clone(),
        evidence_schema: connector.schema().evidence_schema.clone(),
        canonicalization_profile: active.profile().clone(),
        provider_instance_identity_recipe: connector
            .schema()
            .provider_instance_identity_recipe
            .clone(),
        canonical_resource_identity_recipe: connector
            .schema()
            .canonical_resource_identity_recipe
            .clone(),
        redaction_policy: governance.redaction_policy.clone(),
        classifier_policy: governance.classifier_policy.clone(),
        retention_policy: governance.retention_policy.clone(),
        publication_policy: governance.publication_policy.clone(),
        integrity_state: derive_integrity_state(),
        visibility_class: governance.visibility_class,
        retention_class: governance.retention_class,
        publication_class: governance.publication_class,
        erasure_scopes,
        lineage,
    }
}

fn require_clock_order(
    candidate: &EvidenceIngressCandidateV2,
) -> Result<(), EvidenceAdmissionError> {
    let clocks: [&CanonicalTimestamp; 3] = [
        &candidate.occurred_at,
        &candidate.observed_at,
        &candidate.received_at,
    ];
    if !clocks.iter().all(|clock| clock.is_microsecond_aligned()) {
        return Err(EvidenceAdmissionError::ClockOrder(
            ClockOrderKind::NotMicrosecondAligned,
        ));
    }
    if candidate.observed_at < candidate.occurred_at {
        return Err(EvidenceAdmissionError::ClockOrder(
            ClockOrderKind::ObservedBeforeOccurred,
        ));
    }
    if candidate.received_at < candidate.observed_at {
        return Err(EvidenceAdmissionError::ClockOrder(
            ClockOrderKind::ReceivedBeforeObserved,
        ));
    }
    Ok(())
}

/// Rederive the provider-instance and canonical-resource URIs and compare them
/// with what the candidate declared.
fn require_derived_resource_identities(
    active: &ActiveStage4Package,
    connector: &StructurallyResolvedConnectorSchemaV2,
    candidate: &EvidenceIngressCandidateV2,
    locators: &EvidenceIngressLocatorsV1,
) -> Result<(), EvidenceAdmissionError> {
    if locators.provider_instance.parent_entity.is_some()
        || locators.canonical_resource.parent_entity.is_some()
    {
        return Err(EvidenceAdmissionError::ParentEntityUnsupported);
    }

    let instance_recipe = active.recipe(
        &connector.schema().provider_instance_identity_recipe,
        "provider instance identity recipe",
    )?;
    let instance_context = IdentityDerivationContextV1::from_trusted_context(
        active.profile().clone(),
        active.scope().clone(),
        instance_recipe
            .recipe()
            .authority_namespace
            .entry_id
            .clone(),
    );
    let instance = derive_resource_uri(
        &instance_context,
        &locators.provider_instance,
        &instance_recipe,
        None,
    )?;
    if *instance.uri() != candidate.source_fact.provider_instance_id {
        return Err(EvidenceAdmissionError::ResourceIdentityMismatch(
            ResourceIdentityKind::ProviderInstance,
        ));
    }

    let resource_recipe = active.recipe(
        &connector.schema().canonical_resource_identity_recipe,
        "canonical resource identity recipe",
    )?;
    let resource_context = IdentityDerivationContextV1::from_trusted_context(
        active.profile().clone(),
        active.scope().clone(),
        resource_recipe
            .recipe()
            .authority_namespace
            .entry_id
            .clone(),
    );
    let resource = derive_resource_uri(
        &resource_context,
        &locators.canonical_resource,
        &resource_recipe,
        None,
    )?;
    if *resource.uri() != candidate.source_fact.canonical_resource_id {
        return Err(EvidenceAdmissionError::ResourceIdentityMismatch(
            ResourceIdentityKind::CanonicalResource,
        ));
    }

    // The URI is only as trustworthy as its preimage: every locator coordinate
    // that names a published provider fact must equal the fact the candidate
    // declares under that name (PROV-01, EVID-02). Without this a caller could
    // hash one revision into the URI while the envelope claims another.
    require_locator_coordinates(candidate, &locators.canonical_resource)?;
    require_locator_coordinates(candidate, &locators.provider_instance)?;
    Ok(())
}

fn require_locator_coordinates(
    candidate: &EvidenceIngressCandidateV2,
    locator: &CanonicalLocatorV1,
) -> Result<(), EvidenceAdmissionError> {
    for component in &locator.components {
        let (label, declared) = match component.key.as_str() {
            IMMUTABLE_REVISION_KEY => (
                IMMUTABLE_REVISION_KEY,
                candidate.source_fact.immutable_revision.as_bytes(),
            ),
            PROVIDER_OBJECT_ID_KEY => (
                PROVIDER_OBJECT_ID_KEY,
                candidate.source_fact.provider_object_id.as_bytes(),
            ),
            _ => continue,
        };
        if component.encoding != LocatorEncoding::HexBytes
            || component.value != hex::encode(declared)
        {
            return Err(EvidenceAdmissionError::LocatorCoordinateMismatch(label));
        }
    }
    Ok(())
}

/// Read visibility, retention, and publication out of the activated policies.
fn derive_server_governance(
    active: &ActiveStage4Package,
) -> Result<ServerDerivedGovernance, EvidenceAdmissionError> {
    let redaction_entry = active.unique_entry(RegistryEntryKind::RedactionPolicy, "redaction")?;
    let classifier_entry =
        active.unique_entry(RegistryEntryKind::ClassifierPolicy, "classifier")?;
    let retention_entry = active.unique_entry(RegistryEntryKind::RetentionPolicy, "retention")?;
    let publication_entry =
        active.unique_entry(RegistryEntryKind::PublicationRule, "publication")?;

    let redaction: RedactionPolicyBodyV1 = decode_body(redaction_entry)?;
    let classifier: ClassifierPolicyBodyV1 = decode_body(classifier_entry)?;
    let retention: RetentionPolicyBodyV1 = decode_body(retention_entry)?;
    let publication: PublicationRuleBodyV1 = decode_body(publication_entry)?;

    redaction.require_admissible(redaction_entry)?;
    classifier.require_admissible(classifier_entry)?;
    retention.require_admissible(retention_entry)?;
    publication.require_admissible(publication_entry)?;

    reconcile_publication(
        classifier.default_publication,
        classifier.default_visibility,
        publication.default_publication,
    )?;

    Ok(ServerDerivedGovernance {
        redaction_policy: reference_for(redaction_entry)?,
        classifier_policy: reference_for(classifier_entry)?,
        retention_policy: reference_for(retention_entry)?,
        publication_policy: reference_for(publication_entry)?,
        visibility_class: classifier.default_visibility,
        retention_class: retention.default_retention,
        publication_class: classifier.default_publication,
    })
}

/// Reconcile the two policies that both name a default publication class.
///
/// They are separate registry entries, so they can disagree. PRED-03 says an
/// ambiguous input is never silently resolved: admission fails closed rather
/// than choosing one. PUBLIC-04 additionally forbids approving publication
/// without publication-approved visibility.
fn reconcile_publication(
    classifier_publication: PublicationClass,
    classifier_visibility: VisibilityClass,
    rule_publication: PublicationClass,
) -> Result<(), EvidenceAdmissionError> {
    if classifier_publication != rule_publication {
        return Err(EvidenceAdmissionError::PolicyBodyRefused(
            "classifier and publication policies disagree on the default publication class".into(),
        ));
    }
    if classifier_publication == PublicationClass::PublicationApproved
        && classifier_visibility != VisibilityClass::PublicationApproved
    {
        return Err(EvidenceAdmissionError::PolicyBodyRefused(
            "classifier approves publication without publication-approved visibility".into(),
        ));
    }
    Ok(())
}

/// Derive the erasure fence targets from the identities admission proved.
///
/// The representation axis is deliberately absent: the representation key is
/// derived FROM this list, so naming it here would be a self-referential
/// preimage. The governed content row indexes the representation separately,
/// where no such cycle exists.
fn derive_erasure_scopes(
    source_fact_id: Sha256Digest,
    candidate: &EvidenceIngressCandidateV2,
) -> Vec<ErasureScopeReferenceV1> {
    let targets = BTreeSet::from([
        ErasureScopeReferenceV1 {
            kind: ErasureScopeKind::SourceFact,
            target_digest: source_fact_id,
        },
        ErasureScopeReferenceV1 {
            kind: ErasureScopeKind::Resource,
            target_digest: candidate.source_fact.canonical_resource_id.digest(),
        },
    ]);
    targets.into_iter().collect()
}

/// Verify the canonical bytes and derive the governed content identity.
fn require_governed_content(
    active: &ActiveStage4Package,
    candidate: &EvidenceIngressCandidateV2,
    payload: &[u8],
) -> Result<GovernedContentIdentityV1, EvidenceAdmissionError> {
    candidate.canonical_payload.validate()?;
    let declared_length: u64 = candidate
        .canonical_payload
        .byte_length
        .as_str()
        .parse()
        .map_err(|_| {
            EvidenceAdmissionError::Contract(ContractError::Schema(
                "ingress content length is not a positive integer".into(),
            ))
        })?;
    let actual_length = u64::try_from(payload.len()).unwrap_or(u64::MAX);
    if actual_length != declared_length {
        return Err(EvidenceAdmissionError::ContentLengthMismatch);
    }
    if declared_length > MAX_GOVERNED_CONTENT_BYTES {
        return Err(EvidenceAdmissionError::ContentTooLarge);
    }
    let content_digest = Sha256Digest::from_bytes(Sha256::digest(payload).into());
    if content_digest != candidate.canonical_payload.content_digest {
        return Err(EvidenceAdmissionError::ContentDigestMismatch);
    }

    // The protection domain is the credential-bound project namespace, never a
    // payload field (EVID-04, EVID-07).
    let protection_domain_id = active.scope().project_namespace.clone();
    let derived_storage_identity = StorageIdentityPreimageV1 {
        schema_version: STORAGE_IDENTITY_SCHEMA_VERSION,
        protection_domain_id: protection_domain_id.clone(),
        body_content_id: content_digest,
    }
    .storage_identity()?;
    if derived_storage_identity.digest() != candidate.canonical_payload.storage_identity {
        return Err(EvidenceAdmissionError::StorageIdentityMismatch);
    }

    Ok(GovernedContentIdentityV1 {
        protection_domain_id,
        media_type: candidate.canonical_payload.asserted_media_type.clone(),
        byte_length: CanonicalDecimal::parse(declared_length.to_string())?,
        content_digest,
    })
}

fn decode_body<T: serde::de::DeserializeOwned>(entry: &RegistryEntryV1) -> ContractResult<T> {
    decode_strict(&encode_canonical(&entry.body)?)
}

fn reference_for(entry: &RegistryEntryV1) -> ContractResult<RegistryReferenceV1> {
    Ok(RegistryReferenceV1 {
        entry_id: entry.entry_id.clone(),
        version: entry.version,
        entry_digest: entry.digest()?,
    })
}

/// Closed failure disposition every Stage-4 policy body declares.
///
/// A single-variant enum is the point: a policy body that says anything other
/// than `withhold` fails to deserialize, so "fail open" is not expressible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PolicyFailureOutcomeV1 {
    Withhold,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RedactionPolicyBodyV1 {
    schema_version: u32,
    policy_id: ContractId,
    version: u32,
    failure_outcome: PolicyFailureOutcomeV1,
    redact_before_durable_outbox: bool,
    secrets_allowed_in_recall: bool,
}

impl RedactionPolicyBodyV1 {
    fn require_admissible(&self, entry: &RegistryEntryV1) -> Result<(), EvidenceAdmissionError> {
        if self.schema_version != POLICY_BODY_SCHEMA_VERSION
            || self.policy_id != entry.entry_id
            || self.version != entry.version
            || self.failure_outcome != PolicyFailureOutcomeV1::Withhold
            || !self.redact_before_durable_outbox
            || self.secrets_allowed_in_recall
        {
            return Err(EvidenceAdmissionError::PolicyBodyRefused(
                "activated redaction policy does not redact before the durable outbox (EVID-05)"
                    .into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClassifierPolicyBodyV1 {
    schema_version: u32,
    policy_id: ContractId,
    version: u32,
    classify_before_projection: bool,
    default_publication: PublicationClass,
    default_visibility: VisibilityClass,
    failure_outcome: PolicyFailureOutcomeV1,
    server_derived: bool,
}

impl ClassifierPolicyBodyV1 {
    fn require_admissible(&self, entry: &RegistryEntryV1) -> Result<(), EvidenceAdmissionError> {
        if self.schema_version != POLICY_BODY_SCHEMA_VERSION
            || self.policy_id != entry.entry_id
            || self.version != entry.version
            || !self.classify_before_projection
            || !self.server_derived
            || self.failure_outcome != PolicyFailureOutcomeV1::Withhold
        {
            return Err(EvidenceAdmissionError::PolicyBodyRefused(
                "activated classifier policy is not a server-derived classify-before-projection policy (EVID-04)"
                    .into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetentionPolicyBodyV1 {
    schema_version: u32,
    policy_id: ContractId,
    version: u32,
    default_retention: RetentionClass,
    erasure_index_required: bool,
    failure_outcome: PolicyFailureOutcomeV1,
    private_raw_separate_key: bool,
    tombstones_before_restore: bool,
}

impl RetentionPolicyBodyV1 {
    fn require_admissible(&self, entry: &RegistryEntryV1) -> Result<(), EvidenceAdmissionError> {
        if self.schema_version != POLICY_BODY_SCHEMA_VERSION
            || self.policy_id != entry.entry_id
            || self.version != entry.version
            || !self.erasure_index_required
            || !self.private_raw_separate_key
            || !self.tombstones_before_restore
            || self.failure_outcome != PolicyFailureOutcomeV1::Withhold
            || self.default_retention == RetentionClass::Ephemeral
        {
            return Err(EvidenceAdmissionError::PolicyBodyRefused(
                "activated retention policy does not guarantee an erasure-indexed governed class (EVID-08)"
                    .into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicationRuleBodyV1 {
    schema_version: u32,
    rule_id: ContractId,
    version: u32,
    classification_before_projection_required: bool,
    default_publication: PublicationClass,
    exemplar_policy: RegistryReferenceV1,
    private_material_allowed: bool,
    raw_content_references_allowed: bool,
}

impl PublicationRuleBodyV1 {
    fn require_admissible(&self, entry: &RegistryEntryV1) -> Result<(), EvidenceAdmissionError> {
        if self.schema_version != POLICY_BODY_SCHEMA_VERSION
            || self.rule_id != entry.entry_id
            || self.version != entry.version
            || !self.classification_before_projection_required
            || self.private_material_allowed
            || self.raw_content_references_allowed
            || self.exemplar_policy.validate().is_err()
            || self.exemplar_policy.entry_digest == Sha256Digest::ZERO
        {
            return Err(EvidenceAdmissionError::PolicyBodyRefused(
                "activated publication rule admits private or raw material (PUBLIC-04)".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::error::WitnessMismatchKind;
    use super::super::witness::{WriterAuthoritySnapshot, partition_algorithm_label};
    use super::*;
    use crate::memory_contracts::bootstrap::BootstrapReceiptV1;
    use crate::memory_contracts::canonical::require_canonical;
    use crate::memory_contracts::common::{HexBytes, frozen_profile_reference_v1};
    use crate::memory_contracts::digest::{DigestDomain, domain_separated_digest};
    use crate::memory_contracts::evidence_v2::{IngressContentReferenceV1, SourceFactIdentityV2};
    use crate::memory_contracts::identity::{IdentityForm, LocatorComponentV1, ResourceUri};
    use crate::memory_contracts::registry::{ManifestVerifiedRegistryPackage, RegistryHeadV1};
    use crate::memory_contracts::successor_package::SemanticallyClosedSuccessorPackage;

    const BOOTSTRAP_RECEIPT: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v1/bootstrap-receipt.jsonl");
    const TARGET_PACKAGE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v2/stage4-successor/registry-package.jsonl");

    const INGRESS_CANDIDATE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/evidence-admission/ingress-candidate.jsonl"
    );
    const INGRESS_LOCATORS: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/evidence-admission/ingress-locators.jsonl"
    );
    const ADMITTED_STATEMENT: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/evidence-admission/admitted-statement.jsonl"
    );
    const NEGATIVE_PAYLOAD_SCOPE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/evidence-admission/negative-payload-scope.jsonl"
    );
    const NEGATIVE_FOREIGN_CONNECTOR: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/evidence-admission/negative-foreign-connector.jsonl"
    );
    const NEGATIVE_RESOURCE_IDENTITY: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/evidence-admission/negative-resource-identity.jsonl"
    );
    const NEGATIVE_STORAGE_IDENTITY: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/evidence-admission/negative-storage-identity.jsonl"
    );
    const NEGATIVE_CLOCK_INVERSION: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/evidence-admission/negative-clock-inversion.jsonl"
    );
    const NEGATIVE_PRIVATE_RAW: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/evidence-admission/negative-private-raw.jsonl"
    );
    const VECTOR_SUITE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v3/evidence-admission/vector-suite.jsonl");

    /// Exact canonical redacted bytes every vector in this suite refers to.
    const CANONICAL_PAYLOAD: &[u8] = br#"{"provider_event":"push","revision":"sha256:abc"}"#;

    const EXPECTED_CANDIDATE_RAW_SHA256: &str =
        "3993c4ef269c25c82e8f8da840f9bb10e9f1af701502bfdbb9d7f0b3e6ef3d8d";
    const EXPECTED_LOCATORS_RAW_SHA256: &str =
        "243f8a6d465932aa9d4aef517dddaaaa2330525f84906647b93a10a0ae82eff2";
    const EXPECTED_STATEMENT_RAW_SHA256: &str =
        "1306a29f3ff3a5f82224d73343a2ab18db4f81f7aa8bd4fc806168ed63c225d8";
    const EXPECTED_NEGATIVE_SCOPE_RAW_SHA256: &str =
        "62f9b93b6031d38fd760442616c7628d9fd7167601306b752acf29302717c315";
    const EXPECTED_NEGATIVE_CONNECTOR_RAW_SHA256: &str =
        "141358f379b04a2cc3d08d2c2d1c6bd6dce6a855136bcbba6a1a79208486ca2c";
    const EXPECTED_NEGATIVE_RESOURCE_RAW_SHA256: &str =
        "fe4039fea1c23d00e02960e575286302569a4fdbc85b63135512347bab593feb";
    const EXPECTED_NEGATIVE_STORAGE_RAW_SHA256: &str =
        "14cf85256fa89ca907bf237dccdb8b39613cd671ee467cedda2527ad1a6c1a55";
    const EXPECTED_NEGATIVE_CLOCK_RAW_SHA256: &str =
        "3692a95e2ffa55125927e7d36cb97cb69418fa2ac24fb9bbcf83b6689923edea";
    const EXPECTED_NEGATIVE_PRIVATE_RAW_SHA256: &str =
        "25b79ca655d9b2768aec7c4f149f0cf9a48d9e4ff7d03c3149f6f2f58ff18bbe";
    const EXPECTED_VECTOR_SUITE_RAW_SHA256: &str =
        "041dc592fc3ce73c786fff2a3b11b71b50cd17c916a1e430839108c6adf242a8";

    const EXPECTED_SOURCE_FACT_ID: &str =
        "22fa8ce6eb7eeaf3cd0514d91ef1b0a47acd89668587f44b82ff5683b1936cab";
    const EXPECTED_REPRESENTATION_KEY: &str =
        "28ad5297b083df5d8925dd26ffd8a8990199b983a741359ffb7b0f8501be53d5";
    const EXPECTED_ACCEPTED_EVENT_ID: &str =
        "c41322f64746684fd8b1a2d8b8a2d7ba32ae565134becac853366bee1cce5e5c";
    const EXPECTED_STORAGE_IDENTITY: &str =
        "c9d799387e0a326e134f8224b6a119e95ac4fa86359644f0b11096d690d61fa9";
    const EXPECTED_CONTENT_DIGEST: &str =
        "b8b66661476337d4023c7bbad7cd1af791317e15c310e982a5649b60a4603fbd";

    fn record(artifact: &'static [u8]) -> &'static [u8] {
        let body = artifact
            .strip_suffix(b"\n")
            .expect("contract JSONL must have exactly one framing LF");
        assert!(!body.ends_with(b"\n"));
        assert!(!body.contains(&b'\r'));
        require_canonical(body).expect("fixture must be one canonical JSON record");
        body
    }

    fn raw_sha256(artifact: &[u8]) -> String {
        hex::encode(Sha256::digest(artifact))
    }

    fn target_package() -> SemanticallyClosedStage4Package {
        let manifest = ManifestVerifiedRegistryPackage::decode(
            record(TARGET_PACKAGE),
            &frozen_profile_reference_v1(),
        )
        .expect("frozen Stage-4 package must decode");
        SemanticallyClosedStage4Package::from_successor_package(
            SemanticallyClosedSuccessorPackage::from_manifest_verified(manifest)
                .expect("frozen Stage-4 package must close"),
        )
        .expect("frozen Stage-4 package must narrow to the Stage-4 target")
    }

    fn synthetic_head(package_digest: Sha256Digest) -> RegistryHeadBindingV1 {
        RegistryHeadBindingV1 {
            head: RegistryHeadV1 {
                activation_id: domain_separated_digest(
                    DigestDomain::RegistryActivationReceipt,
                    b"w1-evid-activation",
                ),
                package_digest,
                activation_policy_digest: domain_separated_digest(
                    DigestDomain::RegistryActivationStatement,
                    b"w1-evid-activation-policy",
                ),
            },
            effective_from: CanonicalTimestamp::parse("2026-08-15T12:00:00.000000000Z").unwrap(),
            effective_until: None,
        }
    }

    fn witness_for(head: &RegistryHeadBindingV1) -> WriterAuthorityWitness {
        let receipt: BootstrapReceiptV1 = decode_strict(record(BOOTSTRAP_RECEIPT)).unwrap();
        let genesis_epoch = receipt.statement.genesis_epoch.clone();
        let scope = receipt.statement.scope;
        let recipe = genesis_epoch.partition_recipe.clone();
        WriterAuthorityWitness::from_authority_snapshot(WriterAuthoritySnapshot {
            head_state: "active".to_owned(),
            generation: 1,
            activation_id: head.head.activation_id,
            package_digest: head.head.package_digest,
            activation_policy_digest: head.head.activation_policy_digest,
            log_epoch_id: genesis_epoch.epoch_id().unwrap(),
            partition_recipe_id: recipe.recipe_id.as_str().to_owned(),
            partition_recipe_version: recipe.recipe_version,
            partition_algorithm: partition_algorithm_label(recipe.algorithm).to_owned(),
            partition_seed: recipe.seed,
            log_shard_count: recipe.shard_count,
            head_scope: scope.clone(),
            bootstrap_scope: scope,
            genesis_epoch,
        })
        .expect("the frozen bootstrap receipt must yield a consistent witness")
    }

    fn active_package() -> ActiveStage4Package {
        let package = target_package();
        let head = synthetic_head(package.package_digest());
        let witness = witness_for(&head);
        ActiveStage4Package::bind(package, head, &witness)
            .expect("the frozen package must bind to a head that activated it")
    }

    fn built_locators(active: &ActiveStage4Package) -> EvidenceIngressLocatorsV1 {
        let connector = active.connector();
        EvidenceIngressLocatorsV1 {
            provider_instance: CanonicalLocatorV1 {
                schema_version: 1,
                profile: active.profile().clone(),
                scope: active.scope().clone(),
                identity_form: IdentityForm::Entity,
                resource_kind: ContractId::new("provider_instance").unwrap(),
                recipe: connector.schema().provider_instance_identity_recipe.clone(),
                provider_instance_namespace: ContractId::new("namespace.github.provider_instance")
                    .unwrap(),
                parent_entity: None,
                components: vec![LocatorComponentV1 {
                    key: ContractId::new("provider_installation_id").unwrap(),
                    encoding: LocatorEncoding::Decimal,
                    value: "4242".to_owned(),
                }],
            },
            canonical_resource: CanonicalLocatorV1 {
                schema_version: 1,
                profile: active.profile().clone(),
                scope: active.scope().clone(),
                identity_form: IdentityForm::Occurrence,
                resource_kind: ContractId::new("provider_event").unwrap(),
                recipe: connector
                    .schema()
                    .canonical_resource_identity_recipe
                    .clone(),
                provider_instance_namespace: ContractId::new("namespace.github.push").unwrap(),
                parent_entity: None,
                components: vec![
                    LocatorComponentV1 {
                        key: ContractId::new(IMMUTABLE_REVISION_KEY).unwrap(),
                        encoding: LocatorEncoding::HexBytes,
                        value: hex::encode(b"sha256:abc"),
                    },
                    LocatorComponentV1 {
                        key: ContractId::new(PROVIDER_OBJECT_ID_KEY).unwrap(),
                        encoding: LocatorEncoding::HexBytes,
                        value: hex::encode(b"123"),
                    },
                ],
            },
        }
    }

    fn derived_uri(
        active: &ActiveStage4Package,
        locator: &CanonicalLocatorV1,
        reference: &RegistryReferenceV1,
        namespace: &str,
        label: &'static str,
    ) -> ResourceUri {
        let recipe = active.recipe(reference, label).unwrap();
        let context = IdentityDerivationContextV1::from_trusted_context(
            active.profile().clone(),
            active.scope().clone(),
            ContractId::new(namespace).unwrap(),
        );
        derive_resource_uri(&context, locator, &recipe, None)
            .unwrap()
            .into_uri()
    }

    fn built_candidate(active: &ActiveStage4Package) -> EvidenceIngressCandidateV2 {
        let locators = built_locators(active);
        let connector = active.connector();
        let provider_instance_id = derived_uri(
            active,
            &locators.provider_instance,
            &connector.schema().provider_instance_identity_recipe,
            "namespace.github.provider_instance",
            "provider instance identity recipe",
        );
        let canonical_resource_id = derived_uri(
            active,
            &locators.canonical_resource,
            &connector.schema().canonical_resource_identity_recipe,
            "namespace.github.push",
            "canonical resource identity recipe",
        );
        let content_digest = Sha256Digest::from_bytes(Sha256::digest(CANONICAL_PAYLOAD).into());
        let storage_identity = StorageIdentityPreimageV1 {
            schema_version: STORAGE_IDENTITY_SCHEMA_VERSION,
            protection_domain_id: active.scope().project_namespace.clone(),
            body_content_id: content_digest,
        }
        .storage_identity()
        .unwrap()
        .digest();
        EvidenceIngressCandidateV2 {
            schema_version: EVIDENCE_SCHEMA_VERSION,
            scope: active.scope().clone(),
            connector_schema: connector.registry_reference().clone(),
            source_fact: SourceFactIdentityV2 {
                schema_version: EVIDENCE_SCHEMA_VERSION,
                scope: active.scope().clone(),
                provider_namespace: connector.schema().provider_namespace.clone(),
                provider_instance_id,
                logical_event_key: HexBytes::new(b"push:123".to_vec()).unwrap(),
                provider_object_id: HexBytes::new(b"123".to_vec()).unwrap(),
                immutable_revision: HexBytes::new(b"sha256:abc".to_vec()).unwrap(),
                canonical_resource_id,
            },
            provider_actor_id: None,
            occurred_at: CanonicalTimestamp::parse("2026-08-15T12:30:00.000000000Z").unwrap(),
            observed_at: CanonicalTimestamp::parse("2026-08-15T12:30:01.000000000Z").unwrap(),
            authenticated_ingress_principal_id: ContractId::new("connector.github").unwrap(),
            connector_instance_id: ContractId::new("connector.github.instance-1").unwrap(),
            provider_delivery_id: HexBytes::new(b"delivery-1".to_vec()).unwrap(),
            received_at: CanonicalTimestamp::parse("2026-08-15T12:30:02.000000000Z").unwrap(),
            canonical_payload: IngressContentReferenceV1 {
                asserted_media_type: ContractId::new("application.json").unwrap(),
                byte_length: CanonicalDecimal::parse(CANONICAL_PAYLOAD.len().to_string()).unwrap(),
                content_digest,
                storage_identity,
            },
            private_raw_artifact: None,
        }
    }

    fn delivery() -> EvidenceDeliveryContextV1 {
        EvidenceDeliveryContextV1 {
            connector_principal_id: ContractId::new("connector.github").unwrap(),
            connector_instance_id: ContractId::new("connector.github.instance-1").unwrap(),
            transport_delivery_id: HexBytes::new(b"delivery-1".to_vec()).unwrap(),
            attempt_count: 1,
        }
    }

    fn admit_with<'a>(
        active: &ActiveStage4Package,
        candidate: &'a EvidenceIngressCandidateV2,
        locators: &'a EvidenceIngressLocatorsV1,
    ) -> Result<AdmittedEvidenceStatementV2, EvidenceAdmissionError> {
        admit_evidence(
            active,
            EvidenceAdmissionRequestV1 {
                candidate,
                locators,
                canonical_payload: CANONICAL_PAYLOAD,
                delivery: delivery(),
                lineage: RepresentationLineageV2::Origin,
            },
        )
    }

    fn admit(
        active: &ActiveStage4Package,
        candidate: &EvidenceIngressCandidateV2,
    ) -> Result<AdmittedEvidenceStatementV2, EvidenceAdmissionError> {
        let locators = built_locators(active);
        admit_with(active, candidate, &locators)
    }

    fn frozen_candidate(artifact: &'static [u8]) -> EvidenceIngressCandidateV2 {
        decode_strict(record(artifact)).expect("frozen candidate vector must decode")
    }

    // -----------------------------------------------------------------------
    // Positive path
    // -----------------------------------------------------------------------

    #[test]
    fn the_admitted_statement_is_bound_to_the_active_head_and_package() {
        let active = active_package();
        let candidate = built_candidate(&active);
        let admitted = admit(&active, &candidate).unwrap();
        let statement = admitted.statement();
        assert_eq!(statement.scope, *active.scope());
        assert_eq!(statement.registry_head, *active.head());
        assert_eq!(statement.representation.registry_head, *active.head());
        assert_eq!(
            statement.representation.connector_schema,
            *active.connector().registry_reference()
        );
        statement
            .validate_against_structural_connector(active.connector())
            .unwrap();
        admitted.appendable(&witness_for(active.head())).unwrap();
    }

    #[test]
    fn the_frozen_vectors_admit_to_the_frozen_statement() {
        let active = active_package();
        let candidate = frozen_candidate(INGRESS_CANDIDATE);
        let locators: EvidenceIngressLocatorsV1 = decode_strict(record(INGRESS_LOCATORS)).unwrap();
        assert_eq!(candidate, built_candidate(&active));
        assert_eq!(locators, built_locators(&active));
        let admitted = admit_with(&active, &candidate, &locators).unwrap();
        assert_eq!(
            encode_canonical(admitted.statement()).unwrap(),
            record(ADMITTED_STATEMENT)
        );
        assert_eq!(
            admitted.statement().source_fact_id.digest().to_hex(),
            EXPECTED_SOURCE_FACT_ID
        );
        assert_eq!(
            admitted.statement().representation_key.digest().to_hex(),
            EXPECTED_REPRESENTATION_KEY
        );
        assert_eq!(
            admitted
                .statement()
                .accepted_event_id()
                .unwrap()
                .digest()
                .to_hex(),
            EXPECTED_ACCEPTED_EVENT_ID
        );
        assert_eq!(
            admitted.content().storage_identity().to_hex(),
            EXPECTED_STORAGE_IDENTITY
        );
        assert_eq!(
            admitted.content().content().content_digest.to_hex(),
            EXPECTED_CONTENT_DIGEST
        );
    }

    #[test]
    fn every_vector_file_is_byte_frozen() {
        for (artifact, expected) in [
            (INGRESS_CANDIDATE, EXPECTED_CANDIDATE_RAW_SHA256),
            (INGRESS_LOCATORS, EXPECTED_LOCATORS_RAW_SHA256),
            (ADMITTED_STATEMENT, EXPECTED_STATEMENT_RAW_SHA256),
            (NEGATIVE_PAYLOAD_SCOPE, EXPECTED_NEGATIVE_SCOPE_RAW_SHA256),
            (
                NEGATIVE_FOREIGN_CONNECTOR,
                EXPECTED_NEGATIVE_CONNECTOR_RAW_SHA256,
            ),
            (
                NEGATIVE_RESOURCE_IDENTITY,
                EXPECTED_NEGATIVE_RESOURCE_RAW_SHA256,
            ),
            (
                NEGATIVE_STORAGE_IDENTITY,
                EXPECTED_NEGATIVE_STORAGE_RAW_SHA256,
            ),
            (NEGATIVE_CLOCK_INVERSION, EXPECTED_NEGATIVE_CLOCK_RAW_SHA256),
            (NEGATIVE_PRIVATE_RAW, EXPECTED_NEGATIVE_PRIVATE_RAW_SHA256),
            (VECTOR_SUITE, EXPECTED_VECTOR_SUITE_RAW_SHA256),
        ] {
            assert_eq!(raw_sha256(artifact), expected);
            // One canonical record and exactly one framing LF.
            let _ = record(artifact);
        }
    }

    #[test]
    fn governance_is_read_from_the_activated_policy_bodies() {
        let active = active_package();
        let admitted = admit(&active, &built_candidate(&active)).unwrap();
        let statement = admitted.statement();
        assert_eq!(statement.visibility_class, VisibilityClass::Private);
        assert_eq!(statement.publication_class, PublicationClass::Denied);
        assert_eq!(statement.retention_class, RetentionClass::Governed);
        assert_eq!(
            statement.classifier_policy.entry_id.as_str(),
            "classifier.default"
        );
        assert_eq!(
            statement.retention_policy.entry_id.as_str(),
            "retention.default"
        );
        assert_eq!(
            statement.publication_policy.entry_id.as_str(),
            "publication.default"
        );
        assert_eq!(
            statement.representation.redaction_policy.entry_id.as_str(),
            "redaction.default"
        );
    }

    #[test]
    fn no_input_can_raise_the_integrity_state() {
        assert_eq!(
            derive_integrity_state(),
            IntegrityState::TransportAuthenticated
        );
        let active = active_package();
        let admitted = admit(&active, &built_candidate(&active)).unwrap();
        assert_eq!(
            admitted.statement().integrity_state,
            IntegrityState::TransportAuthenticated
        );
        assert_eq!(
            admitted.statement().representation.integrity_state,
            IntegrityState::TransportAuthenticated
        );
    }

    #[test]
    fn the_erasure_scopes_are_derived_from_the_proven_identities() {
        let active = active_package();
        let candidate = built_candidate(&active);
        let admitted = admit(&active, &candidate).unwrap();
        let statement = admitted.statement();
        assert_eq!(statement.erasure_scopes.len(), 2);
        assert!(statement.erasure_scopes.iter().any(|scope| {
            scope.kind == ErasureScopeKind::SourceFact
                && scope.target_digest == statement.source_fact_id.digest()
        }));
        assert!(statement.erasure_scopes.iter().any(|scope| {
            scope.kind == ErasureScopeKind::Resource
                && scope.target_digest == candidate.source_fact.canonical_resource_id.digest()
        }));
        // The representation axis is absent: the representation key is derived
        // FROM this list, so naming it would be a self-referential preimage.
        assert!(
            !statement
                .erasure_scopes
                .iter()
                .any(|scope| scope.kind == ErasureScopeKind::Representation)
        );
    }

    #[test]
    fn the_protection_domain_is_the_credential_bound_project_namespace() {
        let active = active_package();
        let admitted = admit(&active, &built_candidate(&active)).unwrap();
        assert_eq!(
            admitted.statement().canonical_content.protection_domain_id,
            active.scope().project_namespace
        );
    }

    #[test]
    fn late_arrival_preserves_the_provider_clocks() {
        let active = active_package();
        let mut candidate = built_candidate(&active);
        candidate.received_at =
            CanonicalTimestamp::parse("2027-01-01T00:00:00.000000000Z").unwrap();
        let admitted = admit(&active, &candidate).unwrap();
        // EVID-03: receipt time is transport metadata and never enters the
        // accepted preimage, so a late delivery of the same fact is byte-equal.
        let punctual = admit(&active, &built_candidate(&active)).unwrap();
        assert_eq!(
            encode_canonical(admitted.statement()).unwrap(),
            encode_canonical(punctual.statement()).unwrap()
        );
        assert_eq!(
            admitted.statement().occurred_at.as_str(),
            "2026-08-15T12:30:00.000000000Z"
        );
        assert_eq!(
            admitted.statement().observed_at.as_str(),
            "2026-08-15T12:30:01.000000000Z"
        );
    }

    #[test]
    fn a_new_representation_must_name_its_predecessor() {
        let active = active_package();
        let candidate = built_candidate(&active);
        let locators = built_locators(&active);
        let origin = admit_with(&active, &candidate, &locators).unwrap();
        let successor = admit_evidence(
            &active,
            EvidenceAdmissionRequestV1 {
                candidate: &candidate,
                locators: &locators,
                canonical_payload: CANONICAL_PAYLOAD,
                delivery: delivery(),
                lineage: RepresentationLineageV2::Supersedes {
                    predecessor_representation_key: origin.statement().representation_key,
                },
            },
        )
        .unwrap();
        assert_ne!(
            origin.statement().representation_key,
            successor.statement().representation_key
        );
        assert_eq!(
            origin.statement().source_fact_id,
            successor.statement().source_fact_id
        );
    }

    // -----------------------------------------------------------------------
    // Rejection classes
    // -----------------------------------------------------------------------

    #[test]
    fn a_package_that_is_not_the_activated_one_cannot_bind() {
        let package = target_package();
        let mut head = synthetic_head(package.package_digest());
        head.head.package_digest = Sha256Digest::from_bytes([0x11; 32]);
        let witness = witness_for(&head);
        assert!(matches!(
            ActiveStage4Package::bind(package.clone(), head, &witness),
            Err(EvidenceAdmissionError::PackageNotActive)
        ));

        // Same package digest, different activation ID: ABA safety.
        let good = synthetic_head(package.package_digest());
        let mut other = good.clone();
        other.head.activation_id = Sha256Digest::from_bytes([0x22; 32]);
        assert!(matches!(
            ActiveStage4Package::bind(package, good, &witness_for(&other)),
            Err(EvidenceAdmissionError::PackageNotActive)
        ));
    }

    #[test]
    fn a_payload_selected_scope_is_rejected_before_any_derivation() {
        let active = active_package();
        let candidate = frozen_candidate(NEGATIVE_PAYLOAD_SCOPE);
        assert!(matches!(
            admit(&active, &candidate),
            Err(EvidenceAdmissionError::PayloadSelectedScope)
        ));
        // ...and the source-fact scope alone is enough to reject.
        let mut inner = built_candidate(&active);
        inner.source_fact.scope = AuthenticatedProjectScopeV1::from_trusted_context(
            ContractId::new("tenant.attacker").unwrap(),
            ContractId::new("project.attacker").unwrap(),
        );
        assert!(matches!(
            admit(&active, &inner),
            Err(EvidenceAdmissionError::PayloadSelectedScope)
        ));
    }

    #[test]
    fn a_connector_outside_the_active_package_is_rejected() {
        let active = active_package();
        assert!(matches!(
            admit(&active, &frozen_candidate(NEGATIVE_FOREIGN_CONNECTOR)),
            Err(EvidenceAdmissionError::ConnectorNotInActivePackage)
        ));
        // Right id and version, wrong entry digest: still refused.
        let mut forged = built_candidate(&active);
        forged.connector_schema.entry_digest = Sha256Digest::from_bytes([0x33; 32]);
        assert!(matches!(
            admit(&active, &forged),
            Err(EvidenceAdmissionError::ConnectorNotInActivePackage)
        ));
    }

    #[test]
    fn a_rederived_resource_identity_must_equal_the_declared_one() {
        let active = active_package();
        assert!(matches!(
            admit(&active, &frozen_candidate(NEGATIVE_RESOURCE_IDENTITY)),
            Err(EvidenceAdmissionError::ResourceIdentityMismatch(
                ResourceIdentityKind::CanonicalResource
            ))
        ));
        let mut instance = built_candidate(&active);
        instance.source_fact.provider_instance_id =
            instance.source_fact.canonical_resource_id.clone();
        assert!(matches!(
            admit(&active, &instance),
            Err(EvidenceAdmissionError::Contract(_)
                | EvidenceAdmissionError::ResourceIdentityMismatch(
                    ResourceIdentityKind::ProviderInstance
                ))
        ));
    }

    #[test]
    fn a_locator_coordinate_must_equal_the_declared_provider_fact() {
        let active = active_package();
        let candidate = built_candidate(&active);
        let mut locators = built_locators(&active);
        // Rewrite BOTH the locator coordinate and the candidate's declared
        // revision so the URI still rederives; only the coordinate binding can
        // catch this.
        locators.canonical_resource.components[0].value = hex::encode(b"sha256:zzz");
        let mut mismatched = candidate;
        mismatched.source_fact.canonical_resource_id = derived_uri(
            &active,
            &locators.canonical_resource,
            &active
                .connector()
                .schema()
                .canonical_resource_identity_recipe,
            "namespace.github.push",
            "canonical resource identity recipe",
        );
        assert!(matches!(
            admit_with(&active, &mismatched, &locators),
            Err(EvidenceAdmissionError::LocatorCoordinateMismatch(
                IMMUTABLE_REVISION_KEY
            ))
        ));
    }

    #[test]
    fn a_locator_naming_a_parent_entity_is_refused() {
        let active = active_package();
        let candidate = built_candidate(&active);
        let mut locators = built_locators(&active);
        locators.canonical_resource.parent_entity =
            Some(candidate.source_fact.provider_instance_id.clone());
        assert!(matches!(
            admit_with(&active, &candidate, &locators),
            Err(EvidenceAdmissionError::ParentEntityUnsupported)
        ));
    }

    #[test]
    fn the_three_clocks_must_point_the_right_way() {
        let active = active_package();
        assert!(matches!(
            admit(&active, &frozen_candidate(NEGATIVE_CLOCK_INVERSION)),
            Err(EvidenceAdmissionError::ClockOrder(
                ClockOrderKind::ObservedBeforeOccurred
            ))
        ));
        let mut received = built_candidate(&active);
        received.received_at = CanonicalTimestamp::parse("2026-08-15T12:30:00.500000000Z").unwrap();
        assert!(matches!(
            admit(&active, &received),
            Err(EvidenceAdmissionError::ClockOrder(
                ClockOrderKind::ReceivedBeforeObserved
            ))
        ));
        let mut unaligned = built_candidate(&active);
        unaligned.observed_at =
            CanonicalTimestamp::parse("2026-08-15T12:30:01.000000001Z").unwrap();
        assert!(matches!(
            admit(&active, &unaligned),
            Err(EvidenceAdmissionError::ClockOrder(
                ClockOrderKind::NotMicrosecondAligned
            ))
        ));
        // Equal clocks are lawful: a synchronous local collector may observe at
        // the instant of occurrence.
        let mut equal = built_candidate(&active);
        equal.observed_at = equal.occurred_at.clone();
        equal.received_at = equal.occurred_at.clone();
        assert!(admit(&active, &equal).is_ok());
    }

    #[test]
    fn the_declared_storage_identity_must_be_the_derived_one() {
        let active = active_package();
        assert!(matches!(
            admit(&active, &frozen_candidate(NEGATIVE_STORAGE_IDENTITY)),
            Err(EvidenceAdmissionError::StorageIdentityMismatch)
        ));
    }

    #[test]
    fn payload_bytes_must_reproduce_the_declared_digest_and_length() {
        let active = active_package();
        let candidate = built_candidate(&active);
        let locators = built_locators(&active);
        let other = br#"{"provider_event":"push","revision":"sha256:xyz"}"#;
        assert_eq!(other.len(), CANONICAL_PAYLOAD.len());
        assert!(matches!(
            admit_evidence(
                &active,
                EvidenceAdmissionRequestV1 {
                    candidate: &candidate,
                    locators: &locators,
                    canonical_payload: other,
                    delivery: delivery(),
                    lineage: RepresentationLineageV2::Origin,
                },
            ),
            Err(EvidenceAdmissionError::ContentDigestMismatch)
        ));
        assert!(matches!(
            admit_evidence(
                &active,
                EvidenceAdmissionRequestV1 {
                    candidate: &candidate,
                    locators: &locators,
                    canonical_payload: b"short",
                    delivery: delivery(),
                    lineage: RepresentationLineageV2::Origin,
                },
            ),
            Err(EvidenceAdmissionError::ContentLengthMismatch)
        ));
    }

    #[test]
    fn a_private_raw_artifact_is_refused() {
        let active = active_package();
        assert!(matches!(
            admit(&active, &frozen_candidate(NEGATIVE_PRIVATE_RAW)),
            Err(EvidenceAdmissionError::PrivateRawArtifactUnsupported)
        ));
    }

    #[test]
    fn a_delivery_outside_the_quarantine_bound_cannot_be_bound() {
        let active = active_package();
        let candidate = built_candidate(&active);
        let locators = built_locators(&active);
        let mut zero = delivery();
        zero.attempt_count = 0;
        let admitted = admit_evidence(
            &active,
            EvidenceAdmissionRequestV1 {
                candidate: &candidate,
                locators: &locators,
                canonical_payload: CANONICAL_PAYLOAD,
                delivery: zero,
                lineage: RepresentationLineageV2::Origin,
            },
        )
        .unwrap();
        assert!(admitted.appendable(&witness_for(active.head())).is_err());
    }

    #[test]
    fn a_statement_admitted_under_one_head_cannot_be_appended_under_another() {
        let active = active_package();
        let admitted = admit(&active, &built_candidate(&active)).unwrap();
        let mut other = active.head().clone();
        other.head.activation_id = Sha256Digest::from_bytes([0x44; 32]);
        assert!(matches!(
            admitted.appendable(&witness_for(&other)),
            Err(EvidenceAppendError::StatementAuthority(
                WitnessMismatchKind::ActivationId
            ))
        ));
    }

    // -----------------------------------------------------------------------
    // Activated policy bodies
    // -----------------------------------------------------------------------

    #[test]
    fn a_policy_body_that_could_fail_open_is_refused() {
        let reference = policy_entry(RegistryEntryKind::RedactionPolicy, "redaction.default", 3);
        let admissible = RedactionPolicyBodyV1 {
            schema_version: 1,
            policy_id: ContractId::new("redaction.default").unwrap(),
            version: 3,
            failure_outcome: PolicyFailureOutcomeV1::Withhold,
            redact_before_durable_outbox: true,
            secrets_allowed_in_recall: false,
        };
        admissible.require_admissible(&reference).unwrap();

        let mut secrets = RedactionPolicyBodyV1 {
            secrets_allowed_in_recall: true,
            ..admissible
        };
        assert!(secrets.require_admissible(&reference).is_err());
        secrets.secrets_allowed_in_recall = false;
        secrets.redact_before_durable_outbox = false;
        assert!(secrets.require_admissible(&reference).is_err());
        secrets.redact_before_durable_outbox = true;
        secrets.version = 4;
        assert!(secrets.require_admissible(&reference).is_err());
        secrets.version = 3;
        secrets.schema_version = 2;
        assert!(secrets.require_admissible(&reference).is_err());
        secrets.schema_version = 1;
        secrets.policy_id = ContractId::new("redaction.other").unwrap();
        assert!(secrets.require_admissible(&reference).is_err());
    }

    #[test]
    fn a_fail_open_disposition_cannot_even_deserialize() {
        let withhold: PolicyFailureOutcomeV1 = decode_strict(b"\"withhold\"").unwrap();
        assert_eq!(withhold, PolicyFailureOutcomeV1::Withhold);
        assert!(decode_strict::<PolicyFailureOutcomeV1>(b"\"admit\"").is_err());
        assert!(decode_strict::<PolicyFailureOutcomeV1>(b"\"fail_open\"").is_err());
    }

    #[test]
    fn an_unknown_field_in_a_policy_body_fails_closed() {
        let body = br#"{"failure_outcome":"withhold","policy_id":"redaction.default","redact_before_durable_outbox":true,"schema_version":1,"secrets_allowed_in_recall":false,"unexpected":1,"version":3}"#;
        assert!(decode_strict::<RedactionPolicyBodyV1>(body).is_err());
    }

    #[test]
    #[ignore = "fixture generator; authoritative bytes are checked by non-ignored tests"]
    fn print_fixture_records() {
        let active = active_package();
        let candidate = built_candidate(&active);
        let locators = built_locators(&active);
        let admitted = admit_with(&active, &candidate, &locators).unwrap();

        let mut scope_negative = candidate.clone();
        scope_negative.scope = AuthenticatedProjectScopeV1::from_trusted_context(
            ContractId::new("tenant.attacker").unwrap(),
            ContractId::new("project.attacker").unwrap(),
        );
        let mut connector_negative = candidate.clone();
        connector_negative.connector_schema = active.connector().schema().evidence_schema.clone();
        let mut resource_negative = candidate.clone();
        resource_negative.source_fact.canonical_resource_id =
            candidate.source_fact.provider_instance_id.clone();
        let mut storage_negative = candidate.clone();
        storage_negative.canonical_payload.storage_identity = Sha256Digest::from_bytes([0x5A; 32]);
        let mut clock_negative = candidate.clone();
        clock_negative.observed_at =
            CanonicalTimestamp::parse("2026-08-15T12:29:59.000000000Z").unwrap();
        let mut private_negative = candidate.clone();
        private_negative.private_raw_artifact = Some(IngressContentReferenceV1 {
            asserted_media_type: ContractId::new("application.octet-stream").unwrap(),
            byte_length: CanonicalDecimal::parse("64").unwrap(),
            content_digest: Sha256Digest::from_bytes([0x6B; 32]),
            storage_identity: Sha256Digest::from_bytes([0x6C; 32]),
        });

        for (name, bytes) in [
            (
                "ingress-candidate.jsonl",
                encode_canonical(&candidate).unwrap(),
            ),
            (
                "ingress-locators.jsonl",
                encode_canonical(&locators).unwrap(),
            ),
            (
                "admitted-statement.jsonl",
                encode_canonical(admitted.statement()).unwrap(),
            ),
            (
                "negative-payload-scope.jsonl",
                encode_canonical(&scope_negative).unwrap(),
            ),
            (
                "negative-foreign-connector.jsonl",
                encode_canonical(&connector_negative).unwrap(),
            ),
            (
                "negative-resource-identity.jsonl",
                encode_canonical(&resource_negative).unwrap(),
            ),
            (
                "negative-storage-identity.jsonl",
                encode_canonical(&storage_negative).unwrap(),
            ),
            (
                "negative-clock-inversion.jsonl",
                encode_canonical(&clock_negative).unwrap(),
            ),
            (
                "negative-private-raw.jsonl",
                encode_canonical(&private_negative).unwrap(),
            ),
        ] {
            println!("FIXTURE {name} {}", String::from_utf8(bytes).unwrap());
        }
        println!(
            "DIGEST source_fact_id {}",
            admitted.statement().source_fact_id.digest().to_hex()
        );
        println!(
            "DIGEST representation_key {}",
            admitted.statement().representation_key.digest().to_hex()
        );
        println!(
            "DIGEST accepted_event_id {}",
            admitted
                .statement()
                .accepted_event_id()
                .unwrap()
                .digest()
                .to_hex()
        );
        println!(
            "DIGEST storage_identity {}",
            admitted.content().storage_identity().to_hex()
        );
        println!(
            "DIGEST content_digest {}",
            admitted.content().content().content_digest.to_hex()
        );
        println!(
            "DIGEST package_digest {}",
            active.head().head.package_digest.to_hex()
        );
        println!(
            "DIGEST activation_id {}",
            active.head().head.activation_id.to_hex()
        );
    }

    #[test]
    fn the_locator_binding_ignores_keys_it_does_not_own() {
        let active = active_package();
        let candidate = built_candidate(&active);
        let mut locator = built_locators(&active).provider_instance;
        // `provider_installation_id` is not a declared provider coordinate of
        // the source fact, so the binding must not invent a comparison for it.
        require_locator_coordinates(&candidate, &locator).unwrap();
        locator.components[0].key = ContractId::new(PROVIDER_OBJECT_ID_KEY).unwrap();
        assert!(matches!(
            require_locator_coordinates(&candidate, &locator),
            Err(EvidenceAdmissionError::LocatorCoordinateMismatch(
                PROVIDER_OBJECT_ID_KEY
            ))
        ));
        // The right bytes under the wrong encoding are still a mismatch: the
        // comparison is against the exact hex wire form the recipe declares.
        locator.components[0].value = hex::encode(b"123");
        require_locator_coordinates(&candidate, &locator).unwrap_err();
        locator.components[0].encoding = LocatorEncoding::HexBytes;
        require_locator_coordinates(&candidate, &locator).unwrap();
        locator.components[0].encoding = LocatorEncoding::Decimal;
        assert!(matches!(
            require_locator_coordinates(&candidate, &locator),
            Err(EvidenceAdmissionError::LocatorCoordinateMismatch(
                PROVIDER_OBJECT_ID_KEY
            ))
        ));
    }

    #[test]
    fn a_policy_kind_must_resolve_to_exactly_one_entry() {
        let active = active_package();
        for kind in [
            RegistryEntryKind::RedactionPolicy,
            RegistryEntryKind::ClassifierPolicy,
            RegistryEntryKind::RetentionPolicy,
            RegistryEntryKind::PublicationRule,
        ] {
            active.unique_entry(kind, "policy").unwrap();
        }
        // Five identity recipes: more than one is as fatal as none.
        assert!(matches!(
            active.unique_entry(RegistryEntryKind::IdentityRecipe, "identity"),
            Err(EvidenceAdmissionError::AmbiguousActivePolicy("identity"))
        ));
        // The Stage-4 package carries no observer admission entry.
        assert!(matches!(
            active.unique_entry(RegistryEntryKind::ObserverAdmission, "observer"),
            Err(EvidenceAdmissionError::AmbiguousActivePolicy("observer"))
        ));
    }

    #[test]
    fn two_policies_naming_a_publication_class_must_agree() {
        reconcile_publication(
            PublicationClass::Denied,
            VisibilityClass::Private,
            PublicationClass::Denied,
        )
        .unwrap();
        // Disagreement is unknown, and unknown is never resolved silently.
        assert!(matches!(
            reconcile_publication(
                PublicationClass::PrivateOnly,
                VisibilityClass::Private,
                PublicationClass::Denied,
            ),
            Err(EvidenceAdmissionError::PolicyBodyRefused(_))
        ));
        // Publication approval without publication-approved visibility.
        assert!(matches!(
            reconcile_publication(
                PublicationClass::PublicationApproved,
                VisibilityClass::Project,
                PublicationClass::PublicationApproved,
            ),
            Err(EvidenceAdmissionError::PolicyBodyRefused(_))
        ));
        reconcile_publication(
            PublicationClass::PublicationApproved,
            VisibilityClass::PublicationApproved,
            PublicationClass::PublicationApproved,
        )
        .unwrap();
    }

    fn policy_entry(kind: RegistryEntryKind, id: &str, version: u32) -> RegistryEntryV1 {
        RegistryEntryV1 {
            schema_version: 1,
            kind,
            entry_id: ContractId::new(id).unwrap(),
            version,
            entry_schema_id: ContractId::new("registry.redaction_policy").unwrap(),
            entry_schema_version: 1,
            body: crate::memory_contracts::canonical::CanonicalValue::Object(
                std::collections::BTreeMap::new(),
            ),
            positive_vector_digest: Sha256Digest::from_bytes([1; 32]),
            negative_vector_digest: Sha256Digest::from_bytes([2; 32]),
        }
    }

    #[test]
    fn a_classifier_policy_that_could_classify_after_projection_is_refused() {
        let entry = policy_entry(RegistryEntryKind::ClassifierPolicy, "classifier.default", 3);
        let admissible = ClassifierPolicyBodyV1 {
            schema_version: 1,
            policy_id: ContractId::new("classifier.default").unwrap(),
            version: 3,
            classify_before_projection: true,
            default_publication: PublicationClass::Denied,
            default_visibility: VisibilityClass::Private,
            failure_outcome: PolicyFailureOutcomeV1::Withhold,
            server_derived: true,
        };
        admissible.require_admissible(&entry).unwrap();
        let mut broken = ClassifierPolicyBodyV1 {
            classify_before_projection: false,
            ..admissible
        };
        assert!(broken.require_admissible(&entry).is_err());
        broken.classify_before_projection = true;
        broken.server_derived = false;
        assert!(broken.require_admissible(&entry).is_err());
        broken.server_derived = true;
        broken.version = 4;
        assert!(broken.require_admissible(&entry).is_err());
        broken.version = 3;
        broken.schema_version = 2;
        assert!(broken.require_admissible(&entry).is_err());
        broken.schema_version = 1;
        broken.policy_id = ContractId::new("classifier.other").unwrap();
        assert!(broken.require_admissible(&entry).is_err());
    }

    #[test]
    fn a_retention_policy_without_an_erasure_index_is_refused() {
        let entry = policy_entry(RegistryEntryKind::RetentionPolicy, "retention.default", 3);
        let admissible = RetentionPolicyBodyV1 {
            schema_version: 1,
            policy_id: ContractId::new("retention.default").unwrap(),
            version: 3,
            default_retention: RetentionClass::Governed,
            erasure_index_required: true,
            failure_outcome: PolicyFailureOutcomeV1::Withhold,
            private_raw_separate_key: true,
            tombstones_before_restore: true,
        };
        admissible.require_admissible(&entry).unwrap();
        let mut broken = RetentionPolicyBodyV1 {
            erasure_index_required: false,
            ..admissible
        };
        assert!(broken.require_admissible(&entry).is_err());
        broken.erasure_index_required = true;
        broken.private_raw_separate_key = false;
        assert!(broken.require_admissible(&entry).is_err());
        broken.private_raw_separate_key = true;
        broken.tombstones_before_restore = false;
        assert!(broken.require_admissible(&entry).is_err());
        broken.tombstones_before_restore = true;
        // Ephemeral governed evidence is a contradiction: EVID-01 keeps the
        // accepted envelope, and an ephemeral payload class would let the bytes
        // vanish outside the erasure ceremony.
        broken.default_retention = RetentionClass::Ephemeral;
        assert!(broken.require_admissible(&entry).is_err());
        broken.default_retention = RetentionClass::Immutable;
        broken.require_admissible(&entry).unwrap();
        broken.version = 4;
        assert!(broken.require_admissible(&entry).is_err());
        broken.version = 3;
        broken.schema_version = 2;
        assert!(broken.require_admissible(&entry).is_err());
        broken.schema_version = 1;
        broken.policy_id = ContractId::new("retention.other").unwrap();
        assert!(broken.require_admissible(&entry).is_err());
    }

    #[test]
    fn a_publication_rule_that_admits_private_or_raw_material_is_refused() {
        let entry = policy_entry(RegistryEntryKind::PublicationRule, "publication.default", 3);
        let admissible = PublicationRuleBodyV1 {
            schema_version: 1,
            rule_id: ContractId::new("publication.default").unwrap(),
            version: 3,
            classification_before_projection_required: true,
            default_publication: PublicationClass::Denied,
            exemplar_policy: RegistryReferenceV1 {
                entry_id: ContractId::new("exemplar.private").unwrap(),
                version: 3,
                entry_digest: Sha256Digest::from_bytes([5; 32]),
            },
            private_material_allowed: false,
            raw_content_references_allowed: false,
        };
        admissible.require_admissible(&entry).unwrap();
        let mut broken = PublicationRuleBodyV1 {
            private_material_allowed: true,
            ..admissible
        };
        assert!(broken.require_admissible(&entry).is_err());
        broken.private_material_allowed = false;
        broken.raw_content_references_allowed = true;
        assert!(broken.require_admissible(&entry).is_err());
        broken.raw_content_references_allowed = false;
        broken.classification_before_projection_required = false;
        assert!(broken.require_admissible(&entry).is_err());
        broken.classification_before_projection_required = true;
        // A zero digest names no entry, and a zero version names no revision.
        broken.exemplar_policy.entry_digest = Sha256Digest::ZERO;
        assert!(broken.require_admissible(&entry).is_err());
        broken.exemplar_policy.entry_digest = Sha256Digest::from_bytes([5; 32]);
        broken.exemplar_policy.version = 0;
        assert!(broken.require_admissible(&entry).is_err());
        broken.exemplar_policy.version = 3;
        broken.version = 4;
        assert!(broken.require_admissible(&entry).is_err());
        broken.version = 3;
        broken.schema_version = 2;
        assert!(broken.require_admissible(&entry).is_err());
        broken.schema_version = 1;
        broken.rule_id = ContractId::new("publication.other").unwrap();
        assert!(broken.require_admissible(&entry).is_err());
    }

    #[test]
    fn a_payload_larger_than_the_governed_bound_is_refused() {
        let active = active_package();
        let locators = built_locators(&active);
        let oversized = vec![b'x'; usize::try_from(MAX_GOVERNED_CONTENT_BYTES).unwrap() + 1];
        let content_digest = Sha256Digest::from_bytes(Sha256::digest(&oversized).into());
        let mut candidate = built_candidate(&active);
        candidate.canonical_payload.content_digest = content_digest;
        candidate.canonical_payload.byte_length =
            CanonicalDecimal::parse(oversized.len().to_string()).unwrap();
        candidate.canonical_payload.storage_identity = StorageIdentityPreimageV1 {
            schema_version: STORAGE_IDENTITY_SCHEMA_VERSION,
            protection_domain_id: active.scope().project_namespace.clone(),
            body_content_id: content_digest,
        }
        .storage_identity()
        .unwrap()
        .digest();
        assert!(matches!(
            admit_evidence(
                &active,
                EvidenceAdmissionRequestV1 {
                    candidate: &candidate,
                    locators: &locators,
                    canonical_payload: &oversized,
                    delivery: delivery(),
                    lineage: RepresentationLineageV2::Origin,
                },
            ),
            Err(EvidenceAdmissionError::ContentTooLarge)
        ));
    }
}
