//! Turning CI provider facts into evidence ingress candidates (W3-CIEV).
//!
//! # Version-form, or nothing is built
//!
//! [`CiConnectorBindingV1::resolve`] refuses an active connector whose
//! canonical-resource recipe is not `version`-form. That check is the whole
//! reason this connector can be retrieved at all. The body plane chunks a
//! source object by its VERSION uri
//! ([`crate::memory_contracts::chunk_identity::ChunkOccurrencePreimageV1`]), so
//! an occurrence-form canonical resource yields an accepted event that can
//! never become a body, a chunk, or a lexical row. That is not hypothetical: it
//! is exactly what left 980 accepted events with 0 bodies and 0 lexical rows
//! before W3-CHAIN. A settled CI run IS an immutable object, so refusing to
//! build the candidate is strictly better than minting evidence nothing can
//! read.
//!
//! # What this stage may decide, and what it may not
//!
//! It may decide what the *provider fact* is. It may not decide anything about
//! authority. Scope, canonicalization profile, the connector schema, and both
//! identity recipes are read out of
//! [`crate::evidence_ledger::ActiveStage4Package`] — the type whose
//! construction already proved the offline package is the one the active head
//! activated — so a candidate this module builds asserts the credential-bound
//! scope or it is not built at all (EVID-04, AUTH-04). No CI fact carries a
//! scope field, so there is nothing for a payload to declare and nothing for
//! this stage to prefer over the witness's.
//!
//! # Three clocks, ordered, never rewritten
//!
//! `occurred_at` is the provider's own settle instant, `observed_at` is when
//! this connector fetched the window, and `received_at` is when the ingress
//! accepted the reading. [`require_clock_order`] refuses `occurred_at >
//! observed_at` rather than back-dating either: a provider that reports a run
//! settling after the fetch that saw it is reporting something this connector
//! cannot reconcile, and making the ordering true by rewriting a clock would
//! make it true by fabrication (EVID-03).

use crate::evidence_ledger::{
    ActiveStage4Package, EvidenceDeliveryContextV1, EvidenceIngressLocatorsV1,
};
use crate::memory_contracts::chunk_identity::StorageIdentityPreimageV1;
use crate::memory_contracts::common::{
    AuthenticatedProjectScopeV1, CanonicalDecimal, CanonicalTimestamp, ContractId,
    ProfileReferenceV1, RegistryReferenceV1,
};
use crate::memory_contracts::digest::Sha256Digest;
use crate::memory_contracts::evidence_v2::{
    EvidenceIngressCandidateV2, IngressContentReferenceV1, SourceFactIdentityV2,
    StructurallyResolvedConnectorSchemaV2,
};
use crate::memory_contracts::identity::{
    CanonicalLocatorV1, IdentityDerivationContextV1, IdentityForm, LocatorComponentV1,
    LocatorEncoding, ResourceUri, ValidatedIdentityRecipe, derive_resource_uri,
    derive_version_parent,
};
use crate::memory_contracts::registry::ManifestVerifiedRegistryPackage;
use sha2::{Digest as _, Sha256};

use super::error::{CiIngressError, CiIngressResult};
use super::fact::CiFactV1;

/// Evidence schema version every candidate carries.
const EVIDENCE_SCHEMA_VERSION: u32 = 2;
/// Storage-identity preimage schema version.
const STORAGE_IDENTITY_SCHEMA_VERSION: u32 = 1;
/// Canonical-locator schema version.
const IDENTITY_SCHEMA_VERSION: u32 = 1;

/// Media type asserted for a rendered CI fact.
///
/// Plain canonical JSON, and declared as such so the lexical projector renders
/// the body's scalar leaves rather than indexing JSON scaffolding. Every text
/// field in a CI fact is already a canonical string, so there is nothing for a
/// media-type-specific decoder to undo — which is exactly why a job name is
/// searchable as a word here and a commit message was not before W3-CHAIN.
pub const CI_FACT_MEDIA_TYPE: &str = "application.json";

/// Locator coordinate naming the fact's immutable revision.
const IMMUTABLE_REVISION_KEY: &str = "immutable_revision";
/// Locator coordinate naming the fact's provider object.
const PROVIDER_OBJECT_ID_KEY: &str = "provider_object_id";
/// Locator coordinate naming the deployment's installation.
const PROVIDER_INSTALLATION_ID_KEY: &str = "provider_installation_id";

/// The two clocks this connector supplies from its own trusted context.
///
/// `occurred_at` is deliberately absent: it belongs to the provider fact, and
/// taking it from ingress would let the connector restate when a run settled
/// (EVID-03).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiIngressClocksV1 {
    /// When this connector fetched the window the fact came from.
    ///
    /// It is the scan's `fetched_at`, not a fresh wall clock: `observed_at` is
    /// inside the accepted-event preimage, so a value that changed on every
    /// call would make two drains of one recorded scan two different events for
    /// one source fact. Deriving it from the scan makes a re-drain of that scan
    /// an exact replay, and makes a genuinely new observation a genuinely new
    /// reading (EVENT-01).
    pub observed_at: CanonicalTimestamp,
    /// When the ingress accepted the reading.
    pub received_at: CanonicalTimestamp,
}

/// One built ingress: everything [`crate::evidence_ledger::admit_evidence`]
/// needs, and nothing it does not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiIngressV1 {
    /// The asserted, transport-bearing candidate.
    pub candidate: EvidenceIngressCandidateV2,
    /// Trusted locator coordinates for URI rederivation.
    pub locators: EvidenceIngressLocatorsV1,
    /// Exact canonical bytes the candidate's content digest commits to.
    pub canonical_payload: Vec<u8>,
    /// Authenticated connector delivery metadata.
    pub delivery: EvidenceDeliveryContextV1,
}

/// The active package's CI connector, resolved once per drain.
#[derive(Debug, Clone)]
pub struct CiConnectorBindingV1 {
    connector: StructurallyResolvedConnectorSchemaV2,
    package: ManifestVerifiedRegistryPackage,
    provider_instance_recipe: ValidatedIdentityRecipe,
    canonical_resource_recipe: ValidatedIdentityRecipe,
    scope: AuthenticatedProjectScopeV1,
    profile: ProfileReferenceV1,
    principal_id: ContractId,
    connector_instance_id: ContractId,
    installation_id: CanonicalDecimal,
}

impl CiConnectorBindingV1 {
    /// Resolve the CI connector and both identity recipes from the package the
    /// active head activated.
    ///
    /// Every input comes from `active`, which is itself only constructible by
    /// proving a package digest against a writer-authority witness. The
    /// canonical-resource recipe is additionally required to be Version-form,
    /// so a head that activated an occurrence-form connector cannot be bound at
    /// all rather than producing unretrievable evidence.
    pub fn resolve(
        active: &ActiveStage4Package,
        principal_id: ContractId,
        connector_instance_id: ContractId,
        installation_id: u64,
    ) -> CiIngressResult<Self> {
        let manifest = active.manifest_verified_package();
        let connector = active.connector().clone();
        let provider_instance_recipe = resolve_recipe(
            manifest,
            &connector.schema().provider_instance_identity_recipe,
            "provider instance",
        )?;
        let canonical_resource_recipe = resolve_recipe(
            manifest,
            &connector.schema().canonical_resource_identity_recipe,
            "canonical resource",
        )?;
        let form = canonical_resource_recipe.recipe().identity_form;
        if form != IdentityForm::Version {
            return Err(CiIngressError::CanonicalResourceNotVersionForm {
                recipe: canonical_resource_recipe
                    .recipe()
                    .recipe_id
                    .as_str()
                    .to_owned(),
                form,
            });
        }
        Ok(Self {
            connector,
            package: manifest.clone(),
            provider_instance_recipe,
            canonical_resource_recipe,
            scope: active.scope().clone(),
            profile: active.profile().clone(),
            principal_id,
            connector_instance_id,
            installation_id: CanonicalDecimal::parse(installation_id.to_string())?,
        })
    }

    /// The credential-bound scope every candidate this binding builds carries.
    #[must_use]
    pub const fn scope(&self) -> &AuthenticatedProjectScopeV1 {
        &self.scope
    }

    /// The connector instance this binding delivers as.
    #[must_use]
    pub const fn connector_instance_id(&self) -> &ContractId {
        &self.connector_instance_id
    }

    /// The provider-instance resource URI for this deployment.
    pub fn provider_instance_uri(&self) -> CiIngressResult<ResourceUri> {
        let locator = self.locator(&self.provider_instance_recipe, None)?;
        self.derive(&self.provider_instance_recipe, &locator)
    }

    /// The canonical-resource URI one fact addresses.
    ///
    /// Version-form by construction, because [`Self::resolve`] refused any
    /// other form. Exposed so a caller — a coverage receipt, say — can name the
    /// exact resource the ledger will carry without rebuilding a whole ingress.
    pub fn canonical_resource_uri(&self, fact: &CiFactV1) -> CiIngressResult<ResourceUri> {
        let locator = self.locator(&self.canonical_resource_recipe, Some(fact))?;
        self.derive(&self.canonical_resource_recipe, &locator)
    }

    /// Build one ingress from one CI fact.
    pub fn build_ingress(
        &self,
        fact: &CiFactV1,
        clocks: &CiIngressClocksV1,
        attempt_count: u32,
    ) -> CiIngressResult<CiIngressV1> {
        // Validation FIRST: an unsettled run is refused here, before any
        // identity is derived and long before admission would see it.
        fact.validate()?;
        let occurred_at = fact.occurred_at().clone();
        require_clock_order(&occurred_at, clocks)?;

        let instance_locator = self.locator(&self.provider_instance_recipe, None)?;
        let provider_instance_id =
            self.derive(&self.provider_instance_recipe, &instance_locator)?;
        let resource_locator = self.locator(&self.canonical_resource_recipe, Some(fact))?;
        let canonical_resource_id =
            self.derive(&self.canonical_resource_recipe, &resource_locator)?;

        let canonical_payload = fact.canonical_payload()?;
        let content_digest = Sha256Digest::from_bytes(Sha256::digest(&canonical_payload).into());
        let storage_identity = StorageIdentityPreimageV1 {
            schema_version: STORAGE_IDENTITY_SCHEMA_VERSION,
            protection_domain_id: self.scope.project_namespace.clone(),
            body_content_id: content_digest,
        }
        .storage_identity()?
        .digest();

        let logical_event_key = fact.logical_event_key()?;
        let candidate = EvidenceIngressCandidateV2 {
            schema_version: EVIDENCE_SCHEMA_VERSION,
            scope: self.scope.clone(),
            connector_schema: self.connector.registry_reference().clone(),
            source_fact: SourceFactIdentityV2 {
                schema_version: EVIDENCE_SCHEMA_VERSION,
                scope: self.scope.clone(),
                provider_namespace: self.connector.schema().provider_namespace.clone(),
                provider_instance_id,
                logical_event_key: logical_event_key.clone(),
                provider_object_id: fact.provider_object_id()?,
                immutable_revision: fact.immutable_revision()?,
                canonical_resource_id,
            },
            // A workflow run names an actor that triggered it, but this
            // connector cannot prove that string denotes an authenticated
            // provider actor, so it asserts none (AUTH-02).
            provider_actor_id: None,
            occurred_at,
            observed_at: clocks.observed_at.clone(),
            authenticated_ingress_principal_id: self.principal_id.clone(),
            connector_instance_id: self.connector_instance_id.clone(),
            provider_delivery_id: logical_event_key.clone(),
            received_at: clocks.received_at.clone(),
            canonical_payload: IngressContentReferenceV1 {
                asserted_media_type: ContractId::new(CI_FACT_MEDIA_TYPE)?,
                byte_length: CanonicalDecimal::parse(canonical_payload.len().to_string())?,
                content_digest,
                storage_identity,
            },
            // The public plane carries the governed rendering only. A raw
            // provider archive would need its own key, retention, and
            // publication boundary (EVID-05), which this connector does not
            // have, so it never emits one.
            private_raw_artifact: None,
        };

        Ok(CiIngressV1 {
            candidate,
            locators: EvidenceIngressLocatorsV1 {
                provider_instance: instance_locator,
                canonical_resource: resource_locator,
            },
            canonical_payload,
            delivery: EvidenceDeliveryContextV1 {
                connector_principal_id: self.principal_id.clone(),
                connector_instance_id: self.connector_instance_id.clone(),
                transport_delivery_id: logical_event_key,
                attempt_count,
            },
        })
    }

    fn derive(
        &self,
        recipe: &ValidatedIdentityRecipe,
        locator: &CanonicalLocatorV1,
    ) -> CiIngressResult<ResourceUri> {
        let context = IdentityDerivationContextV1::from_trusted_context(
            self.profile.clone(),
            self.scope.clone(),
            recipe.recipe().authority_namespace.entry_id.clone(),
        );
        // Re-derived rather than carried: `locator` already names the parent,
        // but a URI must never be minted against a parent nobody re-derived.
        let parent =
            derive_version_parent(&self.package, &self.profile, &self.scope, recipe, locator)?;
        Ok(derive_resource_uri(&context, locator, recipe, parent.as_ref())?.into_uri())
    }

    /// Fill the recipe's component rules, and only those, from proven values.
    fn locator(
        &self,
        recipe: &ValidatedIdentityRecipe,
        fact: Option<&CiFactV1>,
    ) -> CiIngressResult<CanonicalLocatorV1> {
        let rules = &recipe.recipe().component_rules;
        let mut components = Vec::with_capacity(rules.len());
        for rule in rules {
            let (value, encoding) =
                proven_locator_component(rule.key.as_str(), &self.installation_id, fact)?;
            require_component_encoding(rule.key.as_str(), rule.encoding, encoding)?;
            components.push(LocatorComponentV1 {
                key: rule.key.clone(),
                encoding,
                value,
            });
        }
        let locator = CanonicalLocatorV1 {
            schema_version: IDENTITY_SCHEMA_VERSION,
            profile: self.profile.clone(),
            scope: self.scope.clone(),
            identity_form: recipe.recipe().identity_form,
            resource_kind: recipe.recipe().resource_kind.clone(),
            recipe: recipe.registry_reference().clone(),
            provider_instance_namespace: recipe.recipe().authority_namespace.entry_id.clone(),
            parent_entity: None,
            components,
        };
        // A version-form recipe names a parent entity, and the parent is
        // derived from this locator's own proven coordinates through the ACTIVE
        // package — the same function admission rederives with, so a locator
        // this connector builds and one admission accepts cannot disagree.
        let parent =
            derive_version_parent(&self.package, &self.profile, &self.scope, recipe, &locator)?;
        Ok(CanonicalLocatorV1 {
            parent_entity: parent.map(|derived| derived.uri().clone()),
            ..locator
        })
    }
}

/// The one place a locator coordinate is filled, and the only three values it
/// may be filled from.
///
/// A recipe naming a coordinate this connector cannot prove is refused rather
/// than guessed (PROV-01, EVID-02): a fabricated coordinate hashes into the
/// resource URI exactly like a proven one, so the two would be
/// indistinguishable downstream.
fn proven_locator_component(
    key: &str,
    installation_id: &CanonicalDecimal,
    fact: Option<&CiFactV1>,
) -> CiIngressResult<(String, LocatorEncoding)> {
    match (key, fact) {
        (IMMUTABLE_REVISION_KEY, Some(fact)) => Ok((
            hex::encode(fact.immutable_revision()?.as_bytes()),
            LocatorEncoding::HexBytes,
        )),
        (PROVIDER_OBJECT_ID_KEY, Some(fact)) => Ok((
            hex::encode(fact.provider_object_id()?.as_bytes()),
            LocatorEncoding::HexBytes,
        )),
        (PROVIDER_INSTALLATION_ID_KEY, _) => Ok((
            installation_id.as_str().to_owned(),
            LocatorEncoding::Decimal,
        )),
        _ => Err(CiIngressError::UnsupportedLocatorComponent(key.to_owned())),
    }
}

/// The encoding the recipe demands must be the encoding the proven value
/// actually has.
fn require_component_encoding(
    key: &str,
    demanded: LocatorEncoding,
    supplied: LocatorEncoding,
) -> CiIngressResult<()> {
    if demanded == supplied {
        return Ok(());
    }
    Err(CiIngressError::LocatorEncodingMismatch {
        key: key.to_owned(),
        demanded,
        supplied,
    })
}

fn resolve_recipe(
    manifest: &ManifestVerifiedRegistryPackage,
    reference: &RegistryReferenceV1,
    label: &'static str,
) -> CiIngressResult<ValidatedIdentityRecipe> {
    let recipe =
        ValidatedIdentityRecipe::from_package(manifest, &reference.entry_id, reference.version)
            .map_err(|_| CiIngressError::RecipeNotInActivePackage(label))?;
    if recipe.registry_reference() != reference {
        return Err(CiIngressError::RecipeNotInActivePackage(label));
    }
    Ok(recipe)
}

/// EVID-03, checked here so a bad reading never reaches admission.
///
/// The full ordering is `occurred <= observed <= received`. A run whose
/// recorded settle instant is AFTER the fetch that observed it is refused
/// rather than back-dated: the connector cannot have observed a fact that had
/// not yet happened, and rewriting either clock would make the ordering true by
/// fabrication.
fn require_clock_order(
    occurred_at: &CanonicalTimestamp,
    clocks: &CiIngressClocksV1,
) -> CiIngressResult<()> {
    if !occurred_at.is_microsecond_aligned()
        || !clocks.observed_at.is_microsecond_aligned()
        || !clocks.received_at.is_microsecond_aligned()
    {
        return Err(CiIngressError::ClockOrder(
            "a clock is not microsecond aligned",
        ));
    }
    if clocks.observed_at < *occurred_at {
        return Err(CiIngressError::ClockOrder(
            "observed_at precedes the provider clock",
        ));
    }
    if clocks.received_at < clocks.observed_at {
        return Err(CiIngressError::ClockOrder(
            "received_at precedes observed_at",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "ingress_tests.rs"]
mod tests;
