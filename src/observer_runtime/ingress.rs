//! Delivering an observer run record through the W1-EVID seam (W3-OBSRT).
//!
//! # Why the result is evidence, not a new event kind
//!
//! [`AcceptedEventKindV1`](crate::evidence_ledger::AcceptedEventKindV1) is a
//! closed set of four, mirrored by migration 0018's governance-exclusion CHECK
//! and by the `fleet_runtime` grants. Minting a fifth kind for observer
//! results would mean a migration, a grant change, and a new consistency
//! family — governance work this workstream does not own. The observer result
//! is instead delivered as what it actually is: a provider fact from a
//! connector instance, whose governed content is the canonical
//! [`ObserverRunRecordV1`](super::receipt::ObserverRunRecordV1) carrying BOTH
//! the run receipt and the typed result. It goes through
//! [`admit_evidence`](crate::evidence_ledger::admit_evidence) like every other
//! producer, which is exactly what EVENT-03 asks for.
//!
//! # Locator coordinates come from proven values only
//!
//! The activated identity recipe decides which coordinates a resource URI is
//! hashed from. This binding fills only three, each of which it can prove:
//!
//! * `immutable_revision` — the result fingerprint. A result IS a function of
//!   its admission, its run receipt and its finding, so its fingerprint is
//!   genuinely immutable for that triple.
//! * `provider_object_id` — the run receipt digest, which names the exact run.
//! * `provider_installation_id` — the deployment's own installation
//!   coordinate.
//!
//! A recipe naming any other coordinate is refused with
//! [`GitIngressError::UnsupportedLocatorComponent`] rather than filled with a
//! plausible value, because a guessed coordinate hashes into the URI exactly
//! like a proven one (PROV-01, EVID-02).
//!
//! # The three clocks
//!
//! `occurred_at` and `observed_at` are both the observed commit's own instant,
//! for the reason W2-GIT gives for the same choice: a wall clock inside the
//! accepted-event preimage would make a re-run a different event and the
//! ledger would quarantine it as an integrity collision instead of
//! recognising a replay. `received_at` is the free clock and is deliberately
//! not part of the preimage (EVID-03, REPLAY-01).

use crate::connectors::git::{GitIngressError, GitIngressResult};
use crate::evidence_ledger::{
    ActiveStage4Package, EvidenceDeliveryContextV1, EvidenceIngressLocatorsV1,
};
use crate::memory_contracts::chunk_identity::StorageIdentityPreimageV1;
use crate::memory_contracts::common::{
    AuthenticatedProjectScopeV1, CanonicalDecimal, CanonicalTimestamp, ContractId, HexBytes,
    ProfileReferenceV1, RegistryReferenceV1,
};
use crate::memory_contracts::digest::Sha256Digest;
use crate::memory_contracts::evidence_v2::{
    EvidenceIngressCandidateV2, IngressContentReferenceV1, SourceFactIdentityV2,
    StructurallyResolvedConnectorSchemaV2,
};
use crate::memory_contracts::identity::{
    CanonicalLocatorV1, IdentityDerivationContextV1, LocatorComponentV1, LocatorEncoding,
    ResourceUri, ValidatedIdentityRecipe, derive_resource_uri, derive_version_parent,
};
use crate::memory_contracts::registry::ManifestVerifiedRegistryPackage;
use sha2::{Digest as _, Sha256};

use super::error::ObserverRuntimeResult;
use super::receipt::ObserverRunRecordV1;

/// Evidence schema version every candidate carries.
const EVIDENCE_SCHEMA_VERSION: u32 = 2;
/// Storage-identity preimage schema version.
const STORAGE_IDENTITY_SCHEMA_VERSION: u32 = 1;
/// Canonical-locator schema version.
const IDENTITY_SCHEMA_VERSION: u32 = 1;

/// Media type asserted for a rendered observer run record.
pub const OBSERVER_RUN_RECORD_MEDIA_TYPE: &str = "application.ostk-observer-run-record-v1";

/// Locator coordinate naming the record's immutable revision.
const IMMUTABLE_REVISION_KEY: &str = "immutable_revision";
/// Locator coordinate naming the record's provider object.
const PROVIDER_OBJECT_ID_KEY: &str = "provider_object_id";
/// Locator coordinate naming the deployment's installation.
const PROVIDER_INSTALLATION_ID_KEY: &str = "provider_installation_id";

/// The one ingress clock this runtime reads from its own trusted context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObserverIngressClocksV1 {
    /// When the ingress accepted the record.
    pub received_at: CanonicalTimestamp,
}

/// One built ingress: everything admission needs, and nothing it does not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObserverIngressV1 {
    /// The asserted, transport-bearing candidate.
    pub candidate: EvidenceIngressCandidateV2,
    /// Trusted locator coordinates for URI rederivation.
    pub locators: EvidenceIngressLocatorsV1,
    /// Exact canonical bytes the candidate's content digest commits to.
    pub canonical_payload: Vec<u8>,
    /// Authenticated connector delivery metadata.
    pub delivery: EvidenceDeliveryContextV1,
}

/// The active package's connector and identity recipes, resolved once per run.
///
/// Every input comes from [`ActiveStage4Package`], which is only constructible
/// by proving a package digest against a writer-authority witness, so there is
/// no second package a caller could resolve a recipe out of by mistake
/// (EVID-04, AUTH-04).
#[derive(Debug, Clone)]
pub struct ObserverConnectorBindingV1 {
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

impl ObserverConnectorBindingV1 {
    /// Resolve the connector and both of its identity recipes out of the
    /// package the active head activated.
    pub fn resolve(
        active: &ActiveStage4Package,
        principal_id: ContractId,
        connector_instance_id: ContractId,
        installation_id: u64,
    ) -> GitIngressResult<Self> {
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

    /// The canonicalization profile the activated package pins.
    #[must_use]
    pub const fn profile(&self) -> &ProfileReferenceV1 {
        &self.profile
    }

    /// The connector instance this binding delivers as.
    #[must_use]
    pub const fn connector_instance_id(&self) -> &ContractId {
        &self.connector_instance_id
    }

    /// Build one ingress from one observer run record.
    pub fn build_ingress(
        &self,
        record: &ObserverRunRecordV1,
        clocks: &ObserverIngressClocksV1,
        attempt_count: u32,
    ) -> ObserverRuntimeResult<ObserverIngressV1> {
        let fingerprint = record.result.result_fingerprint()?.digest();
        let receipt_digest = record.receipt.digest()?;
        let logical_event_key = HexBytes::new(record.logical_event_key()?.as_bytes().to_vec())?;
        let immutable_revision = HexBytes::new(fingerprint.as_bytes().to_vec())?;
        let provider_object_id = HexBytes::new(receipt_digest.as_bytes().to_vec())?;

        let coordinates = ProvenCoordinates {
            immutable_revision: immutable_revision.as_bytes(),
            provider_object_id: provider_object_id.as_bytes(),
        };
        let instance_locator = self.locator(&self.provider_instance_recipe, &coordinates)?;
        let provider_instance_id =
            self.derive(&self.provider_instance_recipe, &instance_locator)?;
        let resource_locator = self.locator(&self.canonical_resource_recipe, &coordinates)?;
        let canonical_resource_id =
            self.derive(&self.canonical_resource_recipe, &resource_locator)?;

        let canonical_payload = record.canonical_bytes()?;
        let content_digest = Sha256Digest::from_bytes(Sha256::digest(&canonical_payload).into());
        let storage_identity = StorageIdentityPreimageV1 {
            schema_version: STORAGE_IDENTITY_SCHEMA_VERSION,
            protection_domain_id: self.scope.project_namespace.clone(),
            body_content_id: content_digest,
        }
        .storage_identity()?
        .digest();

        // Both provider clocks are the observed commit's own instant, which is
        // also the result's `effective_at`, so the whole preimage is a
        // function of the pins.
        let occurred_at = record.result.effective_at.clone();
        require_clock_order(&occurred_at, clocks)?;

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
                provider_object_id,
                immutable_revision,
                canonical_resource_id,
            },
            // The observer is a worker, not an authenticated provider actor:
            // it has no provider-side principal to assert (AUTH-02).
            provider_actor_id: None,
            occurred_at: occurred_at.clone(),
            observed_at: occurred_at,
            authenticated_ingress_principal_id: self.principal_id.clone(),
            connector_instance_id: self.connector_instance_id.clone(),
            provider_delivery_id: logical_event_key.clone(),
            received_at: clocks.received_at.clone(),
            canonical_payload: IngressContentReferenceV1 {
                asserted_media_type: ContractId::new(OBSERVER_RUN_RECORD_MEDIA_TYPE)?,
                byte_length: CanonicalDecimal::parse(canonical_payload.len().to_string())?,
                content_digest,
                storage_identity,
            },
            // The public plane carries the governed rendering only. A private
            // raw artifact would need its own key, retention, and publication
            // boundary (EVID-05), which this runtime does not have.
            private_raw_artifact: None,
        };

        Ok(ObserverIngressV1 {
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
    ) -> GitIngressResult<ResourceUri> {
        let context = IdentityDerivationContextV1::from_trusted_context(
            self.profile.clone(),
            self.scope.clone(),
            recipe.recipe().authority_namespace.entry_id.clone(),
        );
        let parent =
            derive_version_parent(&self.package, &self.profile, &self.scope, recipe, locator)?;
        Ok(derive_resource_uri(&context, locator, recipe, parent.as_ref())?.into_uri())
    }

    /// Fill the recipe's component rules, and only those, from proven values.
    fn locator(
        &self,
        recipe: &ValidatedIdentityRecipe,
        coordinates: &ProvenCoordinates<'_>,
    ) -> GitIngressResult<CanonicalLocatorV1> {
        let rules = &recipe.recipe().component_rules;
        let mut components = Vec::with_capacity(rules.len());
        for rule in rules {
            let (value, encoding) =
                proven_locator_component(rule.key.as_str(), &self.installation_id, coordinates)?;
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
        let parent =
            derive_version_parent(&self.package, &self.profile, &self.scope, recipe, &locator)?;
        Ok(CanonicalLocatorV1 {
            parent_entity: parent.map(|derived| derived.uri().clone()),
            ..locator
        })
    }
}

/// The only values a locator coordinate may be filled from.
#[derive(Debug, Clone, Copy)]
struct ProvenCoordinates<'run> {
    immutable_revision: &'run [u8],
    provider_object_id: &'run [u8],
}

/// The one place a locator coordinate is filled.
///
/// A recipe naming a coordinate this runtime cannot prove is refused rather
/// than guessed: a fabricated coordinate hashes into the resource URI exactly
/// like a proven one, so the two would be indistinguishable downstream
/// (PROV-01, EVID-02). `commit_oid` is `None` for the record's own locators —
/// the record is about a run, not about a commit — and asking for it there is
/// a refusal, not a fallback.
fn proven_locator_component(
    key: &str,
    installation_id: &CanonicalDecimal,
    coordinates: &ProvenCoordinates<'_>,
) -> GitIngressResult<(String, LocatorEncoding)> {
    match key {
        IMMUTABLE_REVISION_KEY => Ok((
            hex::encode(coordinates.immutable_revision),
            LocatorEncoding::HexBytes,
        )),
        PROVIDER_OBJECT_ID_KEY => Ok((
            hex::encode(coordinates.provider_object_id),
            LocatorEncoding::HexBytes,
        )),
        PROVIDER_INSTALLATION_ID_KEY => Ok((
            installation_id.as_str().to_owned(),
            LocatorEncoding::Decimal,
        )),
        _ => Err(GitIngressError::UnsupportedLocatorComponent(key.to_owned())),
    }
}

/// The encoding the recipe demands must be the encoding the proven value has.
fn require_component_encoding(
    key: &str,
    demanded: LocatorEncoding,
    supplied: LocatorEncoding,
) -> GitIngressResult<()> {
    if demanded == supplied {
        return Ok(());
    }
    Err(GitIngressError::LocatorEncodingMismatch {
        key: key.to_owned(),
        demanded,
        supplied,
    })
}

fn resolve_recipe(
    manifest: &ManifestVerifiedRegistryPackage,
    reference: &RegistryReferenceV1,
    label: &'static str,
) -> GitIngressResult<ValidatedIdentityRecipe> {
    let recipe =
        ValidatedIdentityRecipe::from_package(manifest, &reference.entry_id, reference.version)
            .map_err(|_| GitIngressError::RecipeNotInActivePackage(label))?;
    if recipe.registry_reference() != reference {
        return Err(GitIngressError::RecipeNotInActivePackage(label));
    }
    Ok(recipe)
}

/// EVID-03, checked here so a bad reading never reaches admission.
fn require_clock_order(
    occurred_at: &CanonicalTimestamp,
    clocks: &ObserverIngressClocksV1,
) -> GitIngressResult<()> {
    if !occurred_at.is_microsecond_aligned() || !clocks.received_at.is_microsecond_aligned() {
        return Err(GitIngressError::ClockOrder(
            "a clock is not microsecond aligned",
        ));
    }
    if clocks.received_at < *occurred_at {
        return Err(GitIngressError::ClockOrder(
            "received_at precedes the observed clock",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn coordinates() -> ProvenCoordinates<'static> {
        ProvenCoordinates {
            immutable_revision: b"\x01\x02",
            provider_object_id: b"\x03\x04",
        }
    }

    fn installation() -> CanonicalDecimal {
        CanonicalDecimal::parse("4242".to_owned()).unwrap()
    }

    #[test]
    fn only_proven_coordinates_are_fillable() {
        assert_eq!(
            proven_locator_component(IMMUTABLE_REVISION_KEY, &installation(), &coordinates())
                .unwrap(),
            ("0102".to_owned(), LocatorEncoding::HexBytes)
        );
        assert_eq!(
            proven_locator_component(PROVIDER_OBJECT_ID_KEY, &installation(), &coordinates())
                .unwrap(),
            ("0304".to_owned(), LocatorEncoding::HexBytes)
        );
        assert_eq!(
            proven_locator_component(
                PROVIDER_INSTALLATION_ID_KEY,
                &installation(),
                &coordinates()
            )
            .unwrap(),
            ("4242".to_owned(), LocatorEncoding::Decimal)
        );
    }

    #[test]
    fn a_coordinate_this_runtime_cannot_prove_is_refused_not_guessed() {
        for key in ["provider_repository_id", "commit_oid", "anything_else"] {
            let error = proven_locator_component(key, &installation(), &coordinates()).unwrap_err();
            assert!(
                matches!(error, GitIngressError::UnsupportedLocatorComponent(named) if named == key),
                "{key}"
            );
        }
    }

    #[test]
    fn a_re_encoded_coordinate_is_refused() {
        require_component_encoding("k", LocatorEncoding::HexBytes, LocatorEncoding::HexBytes)
            .unwrap();
        let error =
            require_component_encoding("k", LocatorEncoding::Decimal, LocatorEncoding::HexBytes)
                .unwrap_err();
        assert!(matches!(
            error,
            GitIngressError::LocatorEncodingMismatch { .. }
        ));
    }

    #[test]
    fn a_received_clock_that_precedes_the_observation_is_refused() {
        let observed = CanonicalTimestamp::parse("2026-08-15T12:00:00.000000000Z").unwrap();
        let ordered = ObserverIngressClocksV1 {
            received_at: CanonicalTimestamp::parse("2026-08-15T12:00:01.000000000Z").unwrap(),
        };
        require_clock_order(&observed, &ordered).unwrap();
        let backwards = ObserverIngressClocksV1 {
            received_at: CanonicalTimestamp::parse("2026-08-15T11:59:59.000000000Z").unwrap(),
        };
        assert!(matches!(
            require_clock_order(&observed, &backwards).unwrap_err(),
            GitIngressError::ClockOrder(_)
        ));
    }
}
