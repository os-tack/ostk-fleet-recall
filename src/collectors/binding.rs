//! Turning a staged collected-item envelope into an evidence ingress
//! candidate, under the active package's `connector.collected.<mode>` schema.
//!
//! # One connector per channel, resolved from the active package
//!
//! [`CollectedConnectorBindingV1::resolve`] binds the connector schema the
//! channel admits under, and nothing else: an active package narrowed to any
//! other connector is refused, so a pulled item can never be admitted as a
//! capture or the reverse. Scope, profile, and both identity recipes come from
//! the [`ActiveStage4Package`], whose construction proved the package is the
//! one the active head activated (EVID-04, AUTH-04).
//!
//! # Version-form, or nothing is built
//!
//! The body plane chunks a source object by its version URI, so a canonical
//! resource recipe that is not `version`-form would mint evidence no body,
//! chunk, or lexical row can ever read. The binding refuses such a recipe, as
//! the CI connector does.
//!
//! # The scope and instance check
//!
//! A binding is pinned to one collector instance: its connector instance id,
//! provider, and provider scope. [`CollectedConnectorBindingV1::build`] derives
//! the provider-instance locator and the item key from the same envelope and
//! refuses an envelope whose provider or scope is not the pinned one, or whose
//! channel or instance is not this binding's. The provider-scope coordinates
//! are an unbound residual of admission (the source fact publishes no field
//! for them, exactly like the generation-1 installation id), so this check is
//! what ties them to the instance the operator configured.
//!
//! # Clocks
//!
//! The sink fixes `observed_at` and `received_at` when it stages a row, and
//! `occurred_at` is the envelope's own provider clock, else the observation.
//! Re-draining a row therefore rebuilds a byte-identical candidate.

use sha2::{Digest as _, Sha256};

use crate::evidence_ledger::{
    ActiveStage4Package, EvidenceDeliveryContextV1, EvidenceIngressLocatorsV1,
};
use crate::memory_contracts::ContractError;
use crate::memory_contracts::chunk_identity::StorageIdentityPreimageV1;
use crate::memory_contracts::collected_item::{
    BoundedTextV1, COLLECTED_ITEM_MEDIA_TYPE, CollectedItemEnvelopeV1, CollectionModeV1,
    MAX_SCOPE_ID_BYTES, ProviderKindV1,
};
use crate::memory_contracts::common::{
    AuthenticatedProjectScopeV1, CanonicalDecimal, CanonicalTimestamp, ContractId, HexBytes,
    ProfileReferenceV1, RegistryReferenceV1,
};
use crate::memory_contracts::digest::Sha256Digest;
use crate::memory_contracts::evidence_v2::{
    EvidenceIngressCandidateV2, IngressContentReferenceV1, SourceFactIdentityV2,
    StructurallyResolvedConnectorSchemaV2,
};
use crate::memory_contracts::generation3_registry::{
    PROVIDER_KIND_COORDINATE, PROVIDER_SCOPE_ID_COORDINATE,
};
use crate::memory_contracts::identity::{
    CanonicalLocatorV1, IdentityDerivationContextV1, IdentityForm, LocatorComponentV1,
    LocatorEncoding, ResourceUri, ValidatedIdentityRecipe, derive_resource_uri,
    derive_version_parent,
};
use crate::memory_contracts::registry::ManifestVerifiedRegistryPackage;

/// Evidence schema version every candidate carries.
const EVIDENCE_SCHEMA_VERSION: u32 = 2;
/// Storage-identity preimage schema version.
const STORAGE_IDENTITY_SCHEMA_VERSION: u32 = 1;
/// Canonical-locator schema version.
const IDENTITY_SCHEMA_VERSION: u32 = 1;
/// Locator coordinate naming the item revision.
const IMMUTABLE_REVISION_KEY: &str = "immutable_revision";
/// Largest transport delivery id (a page digest, a hint key, a request digest,
/// a file digest plus a line number).
pub const MAX_DELIVERY_ID_BYTES: usize = 64;

/// Why a collected-item candidate could not be built.
#[derive(Debug, thiserror::Error)]
pub enum CollectedBindingError {
    /// The active package is narrowed to another connector than the channel's.
    #[error("the active connector is {active}, not {expected}")]
    ConnectorMismatch {
        /// The connector the channel admits under.
        expected: &'static str,
        /// The connector the active package was narrowed to.
        active: String,
    },
    /// An identity recipe the connector names is not in the active package.
    #[error("the {0} identity recipe is not in the active package")]
    RecipeNotInActivePackage(&'static str),
    /// The canonical-resource recipe is not version-form.
    #[error("canonical resource recipe {recipe} is {form:?}-form, not version-form")]
    CanonicalResourceNotVersionForm {
        /// The recipe id.
        recipe: String,
        /// Its form.
        form: IdentityForm,
    },
    /// A recipe names a locator coordinate the binding cannot prove.
    #[error("unsupported locator component {0}")]
    UnsupportedLocatorComponent(String),
    /// A recipe demands another encoding than the proven value has.
    #[error("locator component {key} demands {demanded:?}, the binding has {supplied:?}")]
    LocatorEncodingMismatch {
        /// The coordinate.
        key: String,
        /// What the recipe demands.
        demanded: LocatorEncoding,
        /// What the binding has.
        supplied: LocatorEncoding,
    },
    /// The envelope is not an exact canonical, valid collected-item envelope.
    #[error("the staged envelope is not a valid collected item: {0}")]
    Envelope(ContractError),
    /// The envelope's provider or scope is not the pinned instance's.
    #[error("the envelope's provider scope is not this collector instance's")]
    ScopeMismatch,
    /// The envelope's channel is not this binding's.
    #[error("the envelope was collected through {envelope}, not {binding}")]
    ModeMismatch {
        /// The envelope's channel.
        envelope: &'static str,
        /// The binding's channel.
        binding: &'static str,
    },
    /// The envelope names another collector instance.
    #[error("the envelope was staged by another collector instance")]
    InstanceMismatch,
    /// The clocks are misaligned, out of order, or disagree with the envelope.
    #[error("collected item clocks are inconsistent: {0}")]
    ClockOrder(&'static str),
    /// The delivery id is empty or longer than 64 bytes.
    #[error("a delivery id is 1 to {MAX_DELIVERY_ID_BYTES} bytes")]
    DeliveryId,
    /// A contract refused a derived value.
    #[error("collected item contract failure: {0}")]
    Contract(#[from] ContractError),
}

/// Result alias for the binding.
pub type CollectedBindingResult<T> = Result<T, CollectedBindingError>;

/// The collector instance a binding is pinned to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectorInstanceV1 {
    /// The connector instance id, as configured.
    pub connector_instance_id: ContractId,
    /// The provider kind.
    pub provider: ProviderKindV1,
    /// The operator-pinned provider scope id.
    pub provider_scope_id: BoundedTextV1<MAX_SCOPE_ID_BYTES>,
}

/// The three clocks of one staged row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectedRowClocksV1 {
    /// The provider clock the sink recorded: the envelope's, else the
    /// observation.
    pub occurred_at: CanonicalTimestamp,
    /// When the staging transaction observed the item.
    pub observed_at: CanonicalTimestamp,
    /// When the staging transaction received it.
    pub received_at: CanonicalTimestamp,
}

/// One built ingress: everything admission needs, and nothing it does not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectedIngressV1 {
    /// The asserted candidate.
    pub candidate: EvidenceIngressCandidateV2,
    /// Trusted locator coordinates for URI rederivation.
    pub locators: EvidenceIngressLocatorsV1,
    /// The exact envelope bytes: the governed payload.
    pub canonical_payload: Vec<u8>,
    /// Authenticated delivery metadata.
    pub delivery: EvidenceDeliveryContextV1,
    /// The decoded envelope, for the drain's own projection rows.
    pub envelope: CollectedItemEnvelopeV1,
    /// The staging id: the item revision.
    pub stage_id: Sha256Digest,
}

/// The active package's collected connector for one channel and instance.
#[derive(Debug, Clone)]
pub struct CollectedConnectorBindingV1 {
    mode: CollectionModeV1,
    connector: StructurallyResolvedConnectorSchemaV2,
    package: ManifestVerifiedRegistryPackage,
    provider_instance_recipe: ValidatedIdentityRecipe,
    canonical_resource_recipe: ValidatedIdentityRecipe,
    scope: AuthenticatedProjectScopeV1,
    profile: ProfileReferenceV1,
    principal_id: ContractId,
    instance: CollectorInstanceV1,
}

impl CollectedConnectorBindingV1 {
    /// Bind `connector.collected.<mode>` from the package the active head
    /// activated, pinned to one collector instance.
    pub fn resolve(
        active: &ActiveStage4Package,
        mode: CollectionModeV1,
        principal_id: ContractId,
        instance: CollectorInstanceV1,
    ) -> CollectedBindingResult<Self> {
        let connector = active.connector().clone();
        let expected = mode.connector_schema_id();
        if connector.registry_reference().entry_id.as_str() != expected {
            return Err(CollectedBindingError::ConnectorMismatch {
                expected,
                active: connector.registry_reference().entry_id.to_string(),
            });
        }
        let manifest = active.manifest_verified_package();
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
        require_version_form(&canonical_resource_recipe)?;
        Ok(Self {
            mode,
            connector,
            package: manifest.clone(),
            provider_instance_recipe,
            canonical_resource_recipe,
            scope: active.scope().clone(),
            profile: active.profile().clone(),
            principal_id,
            instance,
        })
    }

    /// The channel this binding admits under.
    #[must_use]
    pub const fn mode(&self) -> CollectionModeV1 {
        self.mode
    }

    /// The pinned instance.
    #[must_use]
    pub const fn instance(&self) -> &CollectorInstanceV1 {
        &self.instance
    }

    /// The credential-bound scope every candidate carries.
    #[must_use]
    pub const fn scope(&self) -> &AuthenticatedProjectScopeV1 {
        &self.scope
    }

    /// The provider-scope entity URI of the pinned instance.
    pub fn provider_instance_uri(&self) -> CollectedBindingResult<ResourceUri> {
        let locator = self.locator(&self.provider_instance_recipe, None)?;
        self.derive(&self.provider_instance_recipe, &locator)
    }

    /// The version URI one staging id addresses.
    pub fn canonical_resource_uri(
        &self,
        stage_id: &Sha256Digest,
    ) -> CollectedBindingResult<ResourceUri> {
        let locator = self.locator(&self.canonical_resource_recipe, Some(stage_id))?;
        self.derive(&self.canonical_resource_recipe, &locator)
    }

    /// Build one ingress from one staged row: its exact envelope bytes, its
    /// clocks, and its transport delivery id.
    pub fn build(
        &self,
        envelope_bytes: &[u8],
        clocks: &CollectedRowClocksV1,
        delivery_id: &[u8],
        attempt_count: u32,
    ) -> CollectedBindingResult<CollectedIngressV1> {
        let envelope = CollectedItemEnvelopeV1::decode(envelope_bytes)
            .map_err(CollectedBindingError::Envelope)?;
        if envelope.provider != self.instance.provider
            || envelope.provider_scope_id != self.instance.provider_scope_id
        {
            return Err(CollectedBindingError::ScopeMismatch);
        }
        if envelope.collection.mode != self.mode {
            return Err(CollectedBindingError::ModeMismatch {
                envelope: envelope.collection.mode.as_str(),
                binding: self.mode.as_str(),
            });
        }
        if envelope.collection.collector_instance != self.instance.connector_instance_id {
            return Err(CollectedBindingError::InstanceMismatch);
        }
        require_clock_order(&envelope, clocks)?;
        if delivery_id.is_empty() || delivery_id.len() > MAX_DELIVERY_ID_BYTES {
            return Err(CollectedBindingError::DeliveryId);
        }
        let delivery_id = HexBytes::new(delivery_id.to_vec())?;

        let stage_id = envelope.immutable_revision();
        let instance_locator = self.locator(&self.provider_instance_recipe, None)?;
        let provider_instance_id =
            self.derive(&self.provider_instance_recipe, &instance_locator)?;
        let resource_locator = self.locator(&self.canonical_resource_recipe, Some(&stage_id))?;
        let canonical_resource_id =
            self.derive(&self.canonical_resource_recipe, &resource_locator)?;

        let canonical_payload = envelope_bytes.to_vec();
        let content_digest = Sha256Digest::from_bytes(Sha256::digest(&canonical_payload).into());
        let storage_identity = StorageIdentityPreimageV1 {
            schema_version: STORAGE_IDENTITY_SCHEMA_VERSION,
            protection_domain_id: self.scope.project_namespace.clone(),
            body_content_id: content_digest,
        }
        .storage_identity()?
        .digest();

        // AUTH-02/AUTH-03: a verified channel read the author from the
        // provider under the collector's own credential, so the provider's
        // author id is a bounded provider fact. A reported channel only
        // relays what an agent or a file says, which is never provider proof.
        let provider_actor_id = match self.mode.trust_tier() {
            crate::memory_contracts::collected_item::TrustTierV1::Verified => envelope
                .author
                .as_ref()
                .map(|author| HexBytes::new(author.id.as_str().as_bytes().to_vec()))
                .transpose()?,
            crate::memory_contracts::collected_item::TrustTierV1::Reported => None,
        };

        let candidate = EvidenceIngressCandidateV2 {
            schema_version: EVIDENCE_SCHEMA_VERSION,
            scope: self.scope.clone(),
            connector_schema: self.connector.registry_reference().clone(),
            source_fact: SourceFactIdentityV2 {
                schema_version: EVIDENCE_SCHEMA_VERSION,
                scope: self.scope.clone(),
                provider_namespace: self.connector.schema().provider_namespace.clone(),
                provider_instance_id,
                logical_event_key: HexBytes::new(envelope.logical_event_key().into_bytes())?,
                provider_object_id: HexBytes::new(envelope.item_key().as_bytes().to_vec())?,
                immutable_revision: HexBytes::new(stage_id.as_bytes().to_vec())?,
                canonical_resource_id,
            },
            provider_actor_id,
            occurred_at: clocks.occurred_at.clone(),
            observed_at: clocks.observed_at.clone(),
            authenticated_ingress_principal_id: self.principal_id.clone(),
            connector_instance_id: self.instance.connector_instance_id.clone(),
            provider_delivery_id: delivery_id.clone(),
            received_at: clocks.received_at.clone(),
            canonical_payload: IngressContentReferenceV1 {
                asserted_media_type: ContractId::new(COLLECTED_ITEM_MEDIA_TYPE)?,
                byte_length: CanonicalDecimal::parse(canonical_payload.len().to_string())?,
                content_digest,
                storage_identity,
            },
            // The envelope is the governed rendering; no raw provider archive
            // crosses to the private plane (EVID-05).
            private_raw_artifact: None,
        };
        Ok(CollectedIngressV1 {
            candidate,
            locators: EvidenceIngressLocatorsV1 {
                provider_instance: instance_locator,
                canonical_resource: resource_locator,
            },
            canonical_payload,
            delivery: EvidenceDeliveryContextV1 {
                connector_principal_id: self.principal_id.clone(),
                connector_instance_id: self.instance.connector_instance_id.clone(),
                transport_delivery_id: delivery_id,
                attempt_count,
            },
            envelope,
            stage_id,
        })
    }

    fn derive(
        &self,
        recipe: &ValidatedIdentityRecipe,
        locator: &CanonicalLocatorV1,
    ) -> CollectedBindingResult<ResourceUri> {
        let context = IdentityDerivationContextV1::from_trusted_context(
            self.profile.clone(),
            self.scope.clone(),
            recipe.recipe().authority_namespace.entry_id.clone(),
        );
        let parent =
            derive_version_parent(&self.package, &self.profile, &self.scope, recipe, locator)?;
        Ok(derive_resource_uri(&context, locator, recipe, parent.as_ref())?.into_uri())
    }

    /// Fill the recipe's component rules, and only those, from proven values:
    /// the pinned instance's provider and scope, and the staging id.
    fn locator(
        &self,
        recipe: &ValidatedIdentityRecipe,
        stage_id: Option<&Sha256Digest>,
    ) -> CollectedBindingResult<CanonicalLocatorV1> {
        let rules = &recipe.recipe().component_rules;
        let mut components = Vec::with_capacity(rules.len());
        for rule in rules {
            let (value, encoding) = match (rule.key.as_str(), stage_id) {
                (IMMUTABLE_REVISION_KEY, Some(stage_id)) => {
                    (stage_id.to_hex(), LocatorEncoding::HexBytes)
                }
                (PROVIDER_KIND_COORDINATE, _) => (
                    self.instance.provider.as_str().to_owned(),
                    LocatorEncoding::NfcUtf8,
                ),
                (PROVIDER_SCOPE_ID_COORDINATE, _) => (
                    self.instance.provider_scope_id.as_str().to_owned(),
                    LocatorEncoding::NfcUtf8,
                ),
                (key, _) => {
                    return Err(CollectedBindingError::UnsupportedLocatorComponent(
                        key.to_owned(),
                    ));
                }
            };
            if rule.encoding != encoding {
                return Err(CollectedBindingError::LocatorEncodingMismatch {
                    key: rule.key.to_string(),
                    demanded: rule.encoding,
                    supplied: encoding,
                });
            }
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
        let parent =
            derive_version_parent(&self.package, &self.profile, &self.scope, recipe, &locator)?;
        Ok(CanonicalLocatorV1 {
            parent_entity: parent.map(|derived| derived.uri().clone()),
            ..locator
        })
    }
}

/// The body plane reads only a version-form canonical resource, so any other
/// form is refused before a candidate exists (the CI precedent).
fn require_version_form(recipe: &ValidatedIdentityRecipe) -> CollectedBindingResult<()> {
    let form = recipe.recipe().identity_form;
    if form != IdentityForm::Version {
        return Err(CollectedBindingError::CanonicalResourceNotVersionForm {
            recipe: recipe.recipe().recipe_id.to_string(),
            form,
        });
    }
    Ok(())
}

fn resolve_recipe(
    manifest: &ManifestVerifiedRegistryPackage,
    reference: &RegistryReferenceV1,
    label: &'static str,
) -> CollectedBindingResult<ValidatedIdentityRecipe> {
    let recipe =
        ValidatedIdentityRecipe::from_package(manifest, &reference.entry_id, reference.version)
            .map_err(|_| CollectedBindingError::RecipeNotInActivePackage(label))?;
    if recipe.registry_reference() != reference {
        return Err(CollectedBindingError::RecipeNotInActivePackage(label));
    }
    Ok(recipe)
}

/// EVID-03, checked before admission: aligned, ordered, and `occurred_at` is
/// the envelope's own clock (else the observation) rather than anything a row
/// could restate.
fn require_clock_order(
    envelope: &CollectedItemEnvelopeV1,
    clocks: &CollectedRowClocksV1,
) -> CollectedBindingResult<()> {
    if !clocks.occurred_at.is_microsecond_aligned()
        || !clocks.observed_at.is_microsecond_aligned()
        || !clocks.received_at.is_microsecond_aligned()
    {
        return Err(CollectedBindingError::ClockOrder(
            "a clock is not microsecond aligned",
        ));
    }
    if clocks.occurred_at != envelope.occurred_at(&clocks.observed_at) {
        return Err(CollectedBindingError::ClockOrder(
            "occurred_at is not the envelope's provider clock",
        ));
    }
    if clocks.observed_at < clocks.occurred_at {
        return Err(CollectedBindingError::ClockOrder(
            "the provider clock is ahead of the observation",
        ));
    }
    if clocks.received_at < clocks.observed_at {
        return Err(CollectedBindingError::ClockOrder(
            "received_at precedes observed_at",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "binding_tests.rs"]
mod tests;
