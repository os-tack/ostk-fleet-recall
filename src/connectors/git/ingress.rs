//! Turning git provider facts into evidence ingress candidates (W2-GIT).
//!
//! # What this stage may decide, and what it may not
//!
//! It may decide what the *provider fact* is: which commit, which tree entry,
//! which ref observation, and the exact canonical bytes that render it. It may
//! not decide anything about authority. Scope, canonicalization profile, the
//! connector schema, and both identity recipes are read out of
//! [`ActiveStage4Package`] — the type whose construction already proved the
//! offline package is the one the active head activated — so a candidate this
//! module builds asserts the credential-bound scope or it is not built at all
//! (EVID-04, AUTH-04).
//!
//! # Locator coordinates fail closed
//!
//! The activated identity recipe, not this connector, decides which coordinates
//! a resource URI is hashed from. [`GitConnectorBindingV1`] therefore reads the
//! recipe's component rules and fills only coordinates it can *prove* from the
//! fact it was handed: the immutable revision, the provider object id, and the
//! deployment's installation coordinate. A recipe naming any other coordinate
//! is refused with
//! [`GitIngressError::UnsupportedLocatorComponent`] rather than filled with a
//! plausible-looking value — a guessed coordinate would hash into the resource
//! URI and become indistinguishable from a proven one (PROV-01, EVID-02).

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
    CanonicalLocatorV1, IdentityDerivationContextV1, LocatorComponentV1, LocatorEncoding,
    ResourceUri, ValidatedIdentityRecipe, derive_resource_uri,
};
use crate::memory_contracts::registry::ManifestVerifiedRegistryPackage;
use crate::memory_contracts::stage4_target_package::SemanticallyClosedStage4Package;
use sha2::{Digest as _, Sha256};

use super::error::{GitIngressError, GitIngressResult};
use super::fact::GitFactV1;

/// Evidence schema version every candidate carries.
const EVIDENCE_SCHEMA_VERSION: u32 = 2;
/// Storage-identity preimage schema version.
const STORAGE_IDENTITY_SCHEMA_VERSION: u32 = 1;
/// Canonical-locator schema version.
const IDENTITY_SCHEMA_VERSION: u32 = 1;
/// Media type asserted for a rendered git fact.
pub const GIT_FACT_MEDIA_TYPE: &str = "application.ostk-git-fact-v1";

/// Locator coordinate naming the fact's immutable revision.
const IMMUTABLE_REVISION_KEY: &str = "immutable_revision";
/// Locator coordinate naming the fact's provider object.
const PROVIDER_OBJECT_ID_KEY: &str = "provider_object_id";
/// Locator coordinate naming the deployment's installation.
const PROVIDER_INSTALLATION_ID_KEY: &str = "provider_installation_id";

/// The two ingress clocks the connector reads from its own trusted context.
///
/// `occurred_at` is not here on purpose: it belongs to the provider fact, and
/// taking it from ingress would let the connector restate when a commit
/// happened (EVID-03).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitIngressClocksV1 {
    /// When this connector read the fact out of the object store.
    pub observed_at: CanonicalTimestamp,
    /// When the ingress accepted the reading.
    pub received_at: CanonicalTimestamp,
}

/// One built ingress: everything [`crate::evidence_ledger::admit_evidence`]
/// needs, and nothing it does not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitIngressV1 {
    /// The asserted, transport-bearing candidate.
    pub candidate: EvidenceIngressCandidateV2,
    /// Trusted locator coordinates for URI rederivation.
    pub locators: EvidenceIngressLocatorsV1,
    /// Exact canonical bytes the candidate's content digest commits to.
    pub canonical_payload: Vec<u8>,
    /// Authenticated connector delivery metadata.
    pub delivery: EvidenceDeliveryContextV1,
}

/// The active package's git connector, resolved once per drain.
#[derive(Debug, Clone)]
pub struct GitConnectorBindingV1 {
    connector: StructurallyResolvedConnectorSchemaV2,
    provider_instance_recipe: ValidatedIdentityRecipe,
    canonical_resource_recipe: ValidatedIdentityRecipe,
    scope: AuthenticatedProjectScopeV1,
    profile: ProfileReferenceV1,
    principal_id: ContractId,
    connector_instance_id: ContractId,
    installation_id: CanonicalDecimal,
}

impl GitConnectorBindingV1 {
    /// Resolve the git connector and both identity recipes from the package the
    /// active head activated.
    ///
    /// `package` must be the same package `active` was bound to. Comparing the
    /// package digest is what makes that a proof rather than an assumption: a
    /// caller holding two packages cannot resolve recipes out of the one that is
    /// not active.
    pub fn resolve(
        package: &SemanticallyClosedStage4Package,
        active: &ActiveStage4Package,
        principal_id: ContractId,
        connector_instance_id: ContractId,
        installation_id: u64,
    ) -> GitIngressResult<Self> {
        if package.package_digest() != active.head().head.package_digest {
            return Err(GitIngressError::PackageNotActive);
        }
        let manifest = package.successor_package().manifest_verified_package();
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
    ///
    /// Stable across facts: it names the installation, not the object.
    pub fn provider_instance_uri(&self) -> GitIngressResult<ResourceUri> {
        let locator = self.locator(&self.provider_instance_recipe, None)?;
        self.derive(&self.provider_instance_recipe, &locator)
    }

    /// Build one ingress from one git fact.
    pub fn build_ingress(
        &self,
        fact: &GitFactV1,
        clocks: &GitIngressClocksV1,
        attempt_count: u32,
    ) -> GitIngressResult<GitIngressV1> {
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
            // A git object records an author and a committer, but this
            // connector cannot prove either string denotes an authenticated
            // provider actor, so it asserts none (AUTH-02).
            provider_actor_id: None,
            occurred_at,
            observed_at: clocks.observed_at.clone(),
            authenticated_ingress_principal_id: self.principal_id.clone(),
            connector_instance_id: self.connector_instance_id.clone(),
            provider_delivery_id: logical_event_key.clone(),
            received_at: clocks.received_at.clone(),
            canonical_payload: IngressContentReferenceV1 {
                asserted_media_type: ContractId::new(GIT_FACT_MEDIA_TYPE)?,
                byte_length: CanonicalDecimal::parse(canonical_payload.len().to_string())?,
                content_digest,
                storage_identity,
            },
            // The public plane carries the governed rendering only. A raw
            // archive would need its own key, retention, and publication
            // boundary (EVID-05), which this connector does not have, so it
            // never emits one.
            private_raw_artifact: None,
        };

        Ok(GitIngressV1 {
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
        Ok(derive_resource_uri(&context, locator, recipe, None)?.into_uri())
    }

    /// Fill the recipe's component rules, and only those, from proven values.
    fn locator(
        &self,
        recipe: &ValidatedIdentityRecipe,
        fact: Option<&GitFactV1>,
    ) -> GitIngressResult<CanonicalLocatorV1> {
        let rules = &recipe.recipe().component_rules;
        let mut components = Vec::with_capacity(rules.len());
        for rule in rules {
            let (value, encoding) = match (rule.key.as_str(), fact) {
                (IMMUTABLE_REVISION_KEY, Some(fact)) => (
                    hex::encode(fact.immutable_revision()?.as_bytes()),
                    LocatorEncoding::HexBytes,
                ),
                (PROVIDER_OBJECT_ID_KEY, Some(fact)) => (
                    hex::encode(fact.provider_object_id()?.as_bytes()),
                    LocatorEncoding::HexBytes,
                ),
                (PROVIDER_INSTALLATION_ID_KEY, _) => (
                    self.installation_id.as_str().to_owned(),
                    LocatorEncoding::Decimal,
                ),
                _ => {
                    return Err(GitIngressError::UnsupportedLocatorComponent(
                        rule.key.as_str().to_owned(),
                    ));
                }
            };
            if rule.encoding != encoding {
                return Err(GitIngressError::LocatorEncodingMismatch {
                    key: rule.key.as_str().to_owned(),
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
        Ok(CanonicalLocatorV1 {
            schema_version: IDENTITY_SCHEMA_VERSION,
            profile: self.profile.clone(),
            scope: self.scope.clone(),
            identity_form: recipe.recipe().identity_form,
            resource_kind: recipe.recipe().resource_kind.clone(),
            recipe: recipe.registry_reference().clone(),
            provider_instance_namespace: recipe.recipe().authority_namespace.entry_id.clone(),
            // Deriving a parent entity is a seam admission itself refuses, so
            // this connector never names one.
            parent_entity: None,
            components,
        })
    }
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
///
/// A commit whose committer clock runs ahead of this host's is refused rather
/// than back-dated: rewriting either clock would make the ordering true by
/// fabrication.
fn require_clock_order(
    occurred_at: &CanonicalTimestamp,
    clocks: &GitIngressClocksV1,
) -> GitIngressResult<()> {
    if !occurred_at.is_microsecond_aligned()
        || !clocks.observed_at.is_microsecond_aligned()
        || !clocks.received_at.is_microsecond_aligned()
    {
        return Err(GitIngressError::ClockOrder(
            "a clock is not microsecond aligned",
        ));
    }
    if clocks.observed_at < *occurred_at {
        return Err(GitIngressError::ClockOrder(
            "observed_at precedes occurred_at",
        ));
    }
    if clocks.received_at < clocks.observed_at {
        return Err(GitIngressError::ClockOrder(
            "received_at precedes observed_at",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clocks(observed: &str, received: &str) -> GitIngressClocksV1 {
        GitIngressClocksV1 {
            observed_at: CanonicalTimestamp::parse(observed).unwrap(),
            received_at: CanonicalTimestamp::parse(received).unwrap(),
        }
    }

    fn stamp(value: &str) -> CanonicalTimestamp {
        CanonicalTimestamp::parse(value).unwrap()
    }

    #[test]
    fn ordered_clocks_are_admitted() {
        assert!(
            require_clock_order(
                &stamp("2026-08-15T12:00:00.000000000Z"),
                &clocks(
                    "2026-08-15T12:00:01.000000000Z",
                    "2026-08-15T12:00:02.000000000Z"
                ),
            )
            .is_ok()
        );
    }

    #[test]
    fn equal_clocks_are_admitted() {
        assert!(
            require_clock_order(
                &stamp("2026-08-15T12:00:00.000000000Z"),
                &clocks(
                    "2026-08-15T12:00:00.000000000Z",
                    "2026-08-15T12:00:00.000000000Z"
                ),
            )
            .is_ok()
        );
    }

    #[test]
    fn a_commit_clock_ahead_of_the_reader_is_refused() {
        let refused = require_clock_order(
            &stamp("2026-08-15T12:00:05.000000000Z"),
            &clocks(
                "2026-08-15T12:00:01.000000000Z",
                "2026-08-15T12:00:02.000000000Z",
            ),
        );
        assert!(matches!(refused, Err(GitIngressError::ClockOrder(_))));
    }

    #[test]
    fn a_receipt_before_the_reading_is_refused() {
        let refused = require_clock_order(
            &stamp("2026-08-15T12:00:00.000000000Z"),
            &clocks(
                "2026-08-15T12:00:02.000000000Z",
                "2026-08-15T12:00:01.000000000Z",
            ),
        );
        assert!(matches!(refused, Err(GitIngressError::ClockOrder(_))));
    }

    #[test]
    fn a_sub_microsecond_clock_is_refused() {
        let refused = require_clock_order(
            &stamp("2026-08-15T12:00:00.000000001Z"),
            &clocks(
                "2026-08-15T12:00:01.000000000Z",
                "2026-08-15T12:00:02.000000000Z",
            ),
        );
        assert!(matches!(refused, Err(GitIngressError::ClockOrder(_))));
    }
}
