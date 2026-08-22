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
//! * A *caller-supplied* parent entity. A `version`-form resource does name a
//!   parent, but the parent is derived here from the child's own already-proven
//!   coordinates and the active package's unique entity recipe for the declared
//!   parent kind (see [`derive_version_parent`]). A locator that names a parent
//!   the package does not derive to is refused
//!   ([`EvidenceAdmissionError::ParentEntityUnsupported`]), which is what keeps
//!   a parent from being the self-asserted identity this module exists to
//!   prevent.
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
    CanonicalLocatorV1, IdentityDerivationContextV1, IdentityForm, LocatorEncoding,
    ValidatedIdentityRecipe, derive_resource_uri, derive_version_parent,
};
use crate::memory_contracts::registry::{RegistryEntryKind, RegistryEntryV1};
use crate::memory_contracts::stage4_target_package::SemanticallyClosedStage4Package;
use crate::memory_contracts::successor_package::SemanticallyClosedSuccessorPackage;
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
    /// A locator's parent entity is not the one the active package derives:
    /// a provider-instance locator naming any parent, an entity/occurrence
    /// resource naming one, a version resource naming none, or a version
    /// resource naming a parent other than the derived one.
    #[error("locator parent entity is not the one the active package derives")]
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

/// One offline package proven to be the package the active head activated,
/// narrowed to the one connector schema a caller runs as.
///
/// This is the type that turns "a package" into "the active package". It is not
/// registry authority on its own: the authority is the writer-authority view
/// the [`WriterAuthorityWitness`] was read from, and the append transaction
/// re-reads that view under serializable isolation. What binding adds is the
/// link from that head to a concrete, manifest-verified set of entries, so
/// connector and recipe resolution can be *from the active package* rather than
/// from whatever bytes a caller happened to pass.
///
/// Generation 1 carries exactly one connector schema, so [`Self::bind`] resolves
/// it with no choice to make. Generation 2 carries one connector schema per
/// installed connector, so [`Self::bind_connector`] takes the schema id the
/// caller runs as and proves *that* entry is a member of the activated package.
/// Naming a connector the active package does not carry is refused
/// ([`EvidenceAdmissionError::ConnectorNotInActivePackage`]); naming one it does
/// carry selects an entry, never authority — every recipe, policy, and digest
/// still comes from the activated bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveStage4Package {
    package: SemanticallyClosedSuccessorPackage,
    connector: StructurallyResolvedConnectorSchemaV2,
    head: RegistryHeadBindingV1,
    scope: AuthenticatedProjectScopeV1,
    profile: ProfileReferenceV1,
}

impl ActiveStage4Package {
    /// Prove the frozen generation-1 Stage-4 `package` is the activated package
    /// for `witness`'s head.
    ///
    /// The head binding is the caller's; every field of its head triple must
    /// equal the witness's, and the package's own recomputed digest must equal
    /// the activated `package_digest`. Scope and profile are then taken from
    /// the witness and the package respectively — never from a request.
    pub fn bind(
        package: &SemanticallyClosedStage4Package,
        head: RegistryHeadBindingV1,
        witness: &WriterAuthorityWitness,
    ) -> Result<Self, EvidenceAdmissionError> {
        let connector = package.connector_schema().clone();
        Self::bound(
            package.successor_package().clone(),
            connector,
            head,
            witness,
        )
    }

    /// Prove `package` is the activated package for `witness`'s head, and
    /// narrow it to the connector schema entry `connector_schema_id` names.
    ///
    /// This is the generation-2 path. The schema id selects which of the
    /// activated package's connector entries this binding delivers as; it can
    /// never introduce one, because the entry is resolved out of the already
    /// digest-checked package closure.
    pub fn bind_connector(
        package: SemanticallyClosedSuccessorPackage,
        connector_schema_id: &ContractId,
        head: RegistryHeadBindingV1,
        witness: &WriterAuthorityWitness,
    ) -> Result<Self, EvidenceAdmissionError> {
        let entry = package
            .manifest_verified_package()
            .package()
            .entries
            .iter()
            .find(|entry| {
                entry.kind == RegistryEntryKind::ConnectorSchema
                    && entry.entry_id == *connector_schema_id
            })
            .ok_or(EvidenceAdmissionError::ConnectorNotInActivePackage)?;
        let reference = RegistryReferenceV1 {
            entry_id: entry.entry_id.clone(),
            version: entry.version,
            entry_digest: entry
                .digest()
                .map_err(|_| EvidenceAdmissionError::ConnectorNotInActivePackage)?,
        };
        let connector = package
            .connector_schema(&reference)
            .ok_or(EvidenceAdmissionError::ConnectorNotInActivePackage)?
            .clone();
        Self::bound(package, connector, head, witness)
    }

    fn bound(
        package: SemanticallyClosedSuccessorPackage,
        connector: StructurallyResolvedConnectorSchemaV2,
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
            .manifest_verified_package()
            .package()
            .profile
            .clone();
        Ok(Self {
            package,
            connector,
            head,
            scope: witness.semantic_scope().clone(),
            profile,
        })
    }

    /// The activated connector schema this binding delivers as.
    #[must_use]
    pub const fn connector(&self) -> &StructurallyResolvedConnectorSchemaV2 {
        &self.connector
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

    /// The manifest-verified package the active head activated.
    ///
    /// Exposed so a connector can resolve an activated identity recipe through
    /// [`ValidatedIdentityRecipe::from_package`] and build a locator from the
    /// recipe's own component rules — the same closure this module rederives
    /// against. Read-only: nothing here can select or alter the active package.
    #[must_use]
    pub const fn manifest_verified_package(
        &self,
    ) -> &crate::memory_contracts::registry::ManifestVerifiedRegistryPackage {
        self.package.manifest_verified_package()
    }

    /// Every registry entry the active package closes over.
    ///
    /// Exposed so a connector can read an ACTIVATED policy body (for instance,
    /// to prove the redaction policy promises redaction before the durable
    /// outbox) instead of carrying its own copy of a governance decision.
    #[must_use]
    pub fn registry_entries(&self) -> &[RegistryEntryV1] {
        self.entries()
    }

    fn entries(&self) -> &[RegistryEntryV1] {
        &self.package.manifest_verified_package().package().entries
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

    /// Prove one registry reference names an entry the active package itself
    /// closes over, at that exact kind, version, and entry digest.
    ///
    /// Used for references that arrive inside an activated policy *body* rather
    /// than as a top-level entry: the body is package bytes, but the reference
    /// it carries is still just a triple until it is resolved here.
    fn require_entry(
        &self,
        kind: RegistryEntryKind,
        reference: &RegistryReferenceV1,
        label: &'static str,
    ) -> Result<(), EvidenceAdmissionError> {
        let entry = self
            .entries()
            .iter()
            .find(|entry| entry.kind == kind && entry.entry_id == reference.entry_id)
            .ok_or(EvidenceAdmissionError::RegistryReferenceNotInActivePackage(
                label,
            ))?;
        if entry.version != reference.version || entry.digest()? != reference.entry_digest {
            return Err(EvidenceAdmissionError::RegistryReferenceNotInActivePackage(
                label,
            ));
        }
        Ok(())
    }

    fn recipe(
        &self,
        reference: &RegistryReferenceV1,
        label: &'static str,
    ) -> Result<ValidatedIdentityRecipe, EvidenceAdmissionError> {
        let manifest = self.package.manifest_verified_package();
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
///
/// The lineage is not checked against stored ledger state, and it does not need
/// to be at this stage: every other field here is a function of the active
/// package and the proven source fact, so for a fixed package and a fixed source
/// fact, `Origin` lineage always reproduces the SAME representation key — hence
/// the same accepted-event ID, which the append transaction classifies as a
/// replay or an integrity collision, never as a new representation. `Supersedes`
/// is therefore structurally the only way to mint a distinct representation of
/// one source fact, and it must name its immediate predecessor. The property
/// holds by construction rather than by an explicit refusal;
/// `a_new_representation_must_name_its_predecessor` pins the key inequality that
/// makes it so, and the ledger-side replay/quarantine classification is what
/// enforces the consequence.
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
    // A provider instance is an entity: it is a root, so a parent on its
    // locator is nonsense whatever the package says.
    if locators.provider_instance.parent_entity.is_some() {
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
    // The parent of a version-form resource is DERIVED, never accepted: it is
    // rebuilt from this locator's own components under the active package's
    // unique entity recipe for the parent kind the child recipe declares. A
    // locator that names any other parent — including one the caller minted
    // itself — cannot match and is refused.
    let parent = derive_version_parent(
        active.manifest_verified_package(),
        active.profile(),
        active.scope(),
        &resource_recipe,
        &locators.canonical_resource,
    )?;
    match (
        resource_recipe.recipe().identity_form,
        &locators.canonical_resource.parent_entity,
        parent.as_ref(),
    ) {
        (IdentityForm::Version, Some(named), Some(derived)) if named == derived.uri() => {}
        (IdentityForm::Entity | IdentityForm::Occurrence, None, None) => {}
        _ => return Err(EvidenceAdmissionError::ParentEntityUnsupported),
    }
    let resource = derive_resource_uri(
        &resource_context,
        &locators.canonical_resource,
        &resource_recipe,
        parent.as_ref(),
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

/// Compare every locator coordinate that names a published source-fact field
/// against the field the candidate declares under that name.
///
/// Residual, recorded rather than hidden: `SourceFactIdentityV2` publishes only
/// `immutable_revision` and `provider_object_id` as coordinate-shaped fields, so
/// a locator whose components name neither is not bound to any published fact.
/// Under the frozen recipe the provider-instance locator is exactly that case —
/// its single component is `provider_installation_id`, which the source fact
/// does not declare — so for that one URI EVID-02's rederivation proves the
/// caller's inputs are internally consistent, not that they match a published
/// provider fact. Closing it requires an installation-id field on the source
/// fact, which is a contract change this stage may not make;
/// `the_locator_binding_ignores_keys_it_does_not_own` pins today's behaviour so
/// the gap cannot close or widen silently.
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

    // The publication rule names an exemplar policy inside its own body. Every
    // other registry reference this module consumes — the connector, both
    // identity recipes, all four policy entries — is resolved against the active
    // package, and this one must be too: an activated rule that pointed at an
    // exemplar policy the package does not close over would be an unresolved
    // governance reference admitted as if it were proven (AUTH-04).
    active.require_entry(
        RegistryEntryKind::ExemplarPolicy,
        &publication.exemplar_policy,
        "exemplar policy",
    )?;

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
#[path = "admission_tests.rs"]
mod tests;
