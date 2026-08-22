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
    ResourceUri, ValidatedIdentityRecipe, derive_resource_uri, derive_version_parent,
};
use crate::memory_contracts::registry::ManifestVerifiedRegistryPackage;
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

/// The one ingress clock the connector reads from its own trusted context.
///
/// `occurred_at` is not here on purpose: it belongs to the provider fact, and
/// taking it from ingress would let the connector restate when a commit
/// happened (EVID-03).
///
/// Neither is `observed_at`, and that is the subtler point. `observed_at` is
/// inside the accepted-event preimage, so if it were a wall clock, two scans of
/// an unchanged repository would produce two different events for one source
/// fact — the ledger would see the same representation with different bytes and
/// quarantine the second as an integrity collision instead of recognising a
/// replay. For git the honest value is the fact's own instant anyway: a commit
/// object is immutable and self-dating, and a ref *observation* carries its
/// observation instant inside its own identity. So the connector observes what
/// git recorded, and `received_at` — which is deliberately NOT part of the
/// accepted-event preimage — is the only free clock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitIngressClocksV1 {
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
    package: ManifestVerifiedRegistryPackage,
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
    /// Every input comes from `active`, which is itself only constructible by
    /// proving a package digest against a writer-authority witness. There is no
    /// second package a caller could resolve a recipe out of by mistake.
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
        // See `GitIngressClocksV1`: the observation instant is the fact's own.
        let observed_at = occurred_at.clone();

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
            observed_at,
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
        // Re-derived rather than carried: `locator` already names the parent,
        // but a URI must never be minted against a parent nobody re-derived.
        // `None` for an entity or occurrence recipe, which have no parent.
        let parent =
            derive_version_parent(&self.package, &self.profile, &self.scope, recipe, locator)?;
        Ok(derive_resource_uri(&context, locator, recipe, parent.as_ref())?.into_uri())
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
        // this connector builds and one admission accepts cannot disagree. A
        // non-version recipe derives no parent and keeps `None`.
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
/// indistinguishable downstream. A fact-derived coordinate is likewise refused
/// when there is no fact in hand — the provider-instance recipe names the
/// installation, never an object — instead of falling back to a placeholder.
fn proven_locator_component(
    key: &str,
    installation_id: &CanonicalDecimal,
    fact: Option<&GitFactV1>,
) -> GitIngressResult<(String, LocatorEncoding)> {
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
        _ => Err(GitIngressError::UnsupportedLocatorComponent(key.to_owned())),
    }
}

/// The encoding the recipe demands must be the encoding the proven value
/// actually has.
///
/// Re-encoding the value to satisfy the recipe would change the bytes the
/// resource URI is hashed from while leaving the recipe reference intact, so a
/// mismatch fails closed.
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
///
/// A commit whose recorded clock runs ahead of this host's is refused rather
/// than back-dated: rewriting either clock would make the ordering true by
/// fabrication.
fn require_clock_order(
    occurred_at: &CanonicalTimestamp,
    clocks: &GitIngressClocksV1,
) -> GitIngressResult<()> {
    if !occurred_at.is_microsecond_aligned() || !clocks.received_at.is_microsecond_aligned() {
        return Err(GitIngressError::ClockOrder(
            "a clock is not microsecond aligned",
        ));
    }
    if clocks.received_at < *occurred_at {
        return Err(GitIngressError::ClockOrder(
            "received_at precedes the provider clock",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clocks(received: &str) -> GitIngressClocksV1 {
        GitIngressClocksV1 {
            received_at: CanonicalTimestamp::parse(received).unwrap(),
        }
    }

    fn stamp(value: &str) -> CanonicalTimestamp {
        CanonicalTimestamp::parse(value).unwrap()
    }

    fn installation() -> CanonicalDecimal {
        CanonicalDecimal::parse("4242".to_owned()).unwrap()
    }

    fn commit_fact() -> GitFactV1 {
        use crate::connectors::git::fact::{
            GIT_FACT_SCHEMA_VERSION, GitAncestryClaimV1, GitCommitFactV1, GitIdentityV1,
            GitObjectId, GitRepositoryIdV1,
        };
        use crate::memory_contracts::common::HexBytes;

        let identity = GitIdentityV1 {
            name: HexBytes::new(b"Ada".to_vec()).unwrap(),
            email: HexBytes::new(b"ada@example.test".to_vec()).unwrap(),
            at: stamp("2026-08-15T12:00:00.000000000Z"),
            utc_offset_minutes: 0,
        };
        GitFactV1::Commit(GitCommitFactV1 {
            schema_version: GIT_FACT_SCHEMA_VERSION,
            repository: GitRepositoryIdV1::from_trusted_config(
                ContractId::new("git.repo.fixture").unwrap(),
                4242,
            )
            .unwrap(),
            commit_id: GitObjectId::parse_hex(&hex::encode([0x11_u8; 20])).unwrap(),
            tree_id: GitObjectId::parse_hex(&hex::encode([0x22_u8; 20])).unwrap(),
            parents: Vec::new(),
            author: identity.clone(),
            committer: identity,
            message: HexBytes::new(b"first".to_vec()).unwrap(),
            ancestry: GitAncestryClaimV1::RecordedParents,
            declared_links: Vec::new(),
        })
    }

    #[test]
    fn the_three_proven_coordinates_fill_from_the_values_they_name() {
        let fact = commit_fact();
        let (revision, encoding) =
            proven_locator_component(IMMUTABLE_REVISION_KEY, &installation(), Some(&fact)).unwrap();
        assert_eq!(encoding, LocatorEncoding::HexBytes);
        assert_eq!(revision, hex::encode([0x11_u8; 20]));

        let (object, encoding) =
            proven_locator_component(PROVIDER_OBJECT_ID_KEY, &installation(), Some(&fact)).unwrap();
        assert_eq!(encoding, LocatorEncoding::HexBytes);
        assert_eq!(object, hex::encode([0x11_u8; 20]));

        let (installation_value, encoding) =
            proven_locator_component(PROVIDER_INSTALLATION_ID_KEY, &installation(), None).unwrap();
        assert_eq!(encoding, LocatorEncoding::Decimal);
        assert_eq!(installation_value, "4242");
    }

    #[test]
    fn a_coordinate_this_connector_cannot_prove_is_refused_not_guessed() {
        let fact = commit_fact();
        let refused =
            proven_locator_component("provider_repository_url", &installation(), Some(&fact));
        assert!(matches!(
            refused,
            Err(GitIngressError::UnsupportedLocatorComponent(key)) if key == "provider_repository_url"
        ));
    }

    #[test]
    fn a_fact_derived_coordinate_is_refused_when_there_is_no_fact() {
        // The provider-instance recipe names the installation, not an object;
        // asking it for a revision must fail closed rather than fall back to a
        // placeholder that would still hash into the URI.
        for key in [IMMUTABLE_REVISION_KEY, PROVIDER_OBJECT_ID_KEY] {
            let refused = proven_locator_component(key, &installation(), None);
            assert!(matches!(
                refused,
                Err(GitIngressError::UnsupportedLocatorComponent(refused_key)) if refused_key == key
            ));
        }
    }

    #[test]
    fn a_recipe_demanding_another_encoding_of_a_proven_value_is_refused() {
        let refused = require_component_encoding(
            IMMUTABLE_REVISION_KEY,
            LocatorEncoding::Decimal,
            LocatorEncoding::HexBytes,
        );
        assert!(matches!(
            refused,
            Err(GitIngressError::LocatorEncodingMismatch {
                key,
                demanded: LocatorEncoding::Decimal,
                supplied: LocatorEncoding::HexBytes,
            }) if key == IMMUTABLE_REVISION_KEY
        ));
        assert!(
            require_component_encoding(
                IMMUTABLE_REVISION_KEY,
                LocatorEncoding::HexBytes,
                LocatorEncoding::HexBytes,
            )
            .is_ok()
        );
    }

    #[test]
    fn ordered_clocks_are_admitted() {
        assert!(
            require_clock_order(
                &stamp("2026-08-15T12:00:00.000000000Z"),
                &clocks("2026-08-15T12:00:02.000000000Z"),
            )
            .is_ok()
        );
    }

    #[test]
    fn equal_clocks_are_admitted() {
        assert!(
            require_clock_order(
                &stamp("2026-08-15T12:00:00.000000000Z"),
                &clocks("2026-08-15T12:00:00.000000000Z"),
            )
            .is_ok()
        );
    }

    #[test]
    fn a_provider_clock_ahead_of_the_reader_is_refused() {
        let refused = require_clock_order(
            &stamp("2026-08-15T12:00:05.000000000Z"),
            &clocks("2026-08-15T12:00:01.000000000Z"),
        );
        assert!(matches!(refused, Err(GitIngressError::ClockOrder(_))));
    }

    #[test]
    fn a_sub_microsecond_provider_clock_is_refused() {
        let refused = require_clock_order(
            &stamp("2026-08-15T12:00:00.000000001Z"),
            &clocks("2026-08-15T12:00:02.000000000Z"),
        );
        assert!(matches!(refused, Err(GitIngressError::ClockOrder(_))));
    }

    #[test]
    fn a_sub_microsecond_receipt_clock_is_refused() {
        let refused = require_clock_order(
            &stamp("2026-08-15T12:00:00.000000000Z"),
            &clocks("2026-08-15T12:00:02.000000001Z"),
        );
        assert!(matches!(refused, Err(GitIngressError::ClockOrder(_))));
    }
}
