//! Turn a redacted transcript turn into an [`EvidenceIngressCandidateV2`].
//!
//! # Everything identity-bearing comes from the ACTIVE package
//!
//! The canonicalizer holds no hard-coded connector id, no hard-coded namespace,
//! and no hard-coded locator shape. It reads the connector schema and both
//! identity recipes out of the [`ActiveStage4Package`], and builds each
//! [`CanonicalLocatorV1`] from that recipe's own `component_rules`. A coordinate
//! key the recipe requires and the binding does not supply is a closed
//! [`TranscriptConnectorError::MissingLocatorCoordinate`], never a guessed
//! value. The consequence is that this module works unchanged against whichever
//! generation's transcript connector schema is active: a new package with a
//! different recipe changes which coordinates are demanded, not this code.
//!
//! # Where the parser identity enters representation identity
//!
//! [`TranscriptTurnRevisionPreimageV1`] binds the parser key digest, the source
//! span, the turn's position, and the digest of the exact redacted body. Its
//! digest becomes the turn's `immutable_revision`, which is a component of the
//! canonical-resource locator, so it flows into the canonical-resource URI, into
//! `source_fact_id`, and therefore into the representation key the ledger keys
//! on. Re-parsing under a different [`ParserKeyV1`] therefore yields a different
//! representation rather than colliding with the first one — the property
//! `a_different_parser_key_is_a_different_representation` pins.
//!
//! # Scope is the credential's, never the payload's
//!
//! Every candidate is built with `active.scope()`. There is no parameter a
//! caller could use to select a different tenant or project, which is the
//! connector-side half of the admission seam's own
//! `PayloadSelectedScope` refusal (EVID-04).

use std::collections::BTreeMap;

use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::evidence_ledger::ActiveStage4Package;
use crate::memory_contracts::canonical::encode_canonical;
use crate::memory_contracts::chunk_identity::{ParserKeyId, ParserKeyV1, SourceSpanV1};
use crate::memory_contracts::common::{CanonicalDecimal, CanonicalTimestamp, ContractId, HexBytes};
use crate::memory_contracts::digest::{DigestDomain, Sha256Digest, domain_separated_digest};
use crate::memory_contracts::evidence_v2::{
    EvidenceIngressCandidateV2, IngressContentReferenceV1, SourceFactIdentityV2,
    StructurallyResolvedConnectorSchemaV2,
};
use crate::memory_contracts::identity::{
    CanonicalLocatorV1, IdentityDerivationContextV1, LocatorComponentV1, LocatorEncoding,
    ValidatedIdentityRecipe, derive_resource_uri, derive_version_parent,
};

use super::error::{TranscriptConnectorError, TranscriptConnectorResult};
use super::parser::{ParsedTurnV1, TranscriptRoleV1};

/// `schema_version` every value this module mints carries.
pub const TRANSCRIPT_SCHEMA_VERSION: u32 = 1;
const EVIDENCE_SCHEMA_VERSION: u32 = 2;
const STORAGE_IDENTITY_SCHEMA_VERSION: u32 = 1;

/// Locator key naming the turn's content-and-parser revision.
const IMMUTABLE_REVISION_KEY: &str = "immutable_revision";
/// Locator key naming the provider-side object the turn belongs to.
const PROVIDER_OBJECT_ID_KEY: &str = "provider_object_id";

/// The media type every canonical transcript body asserts.
const TRANSCRIPT_MEDIA_TYPE: &str = "application.json";

/// The canonical body of one transcript turn: exactly what is digested,
/// encrypted, and stored as the governed content object.
///
/// It carries the REDACTED text and nothing else that could reintroduce raw
/// material: no file path, no raw line, no untouched original.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TranscriptTurnBodyV1 {
    /// Schema version of this body.
    pub schema_version: u32,
    /// Session the turn belongs to.
    pub session_id: String,
    /// Provider-side unique identifier of the turn.
    pub turn_uid: String,
    /// Position of the turn within its source.
    pub ordinal: u32,
    /// Which side authored the turn.
    pub role: String,
    /// The redacted turn text.
    pub text: String,
}

/// Preimage of a transcript turn's `immutable_revision`.
///
/// This is what makes the parser's identity and configuration part of the
/// turn's representation identity, exactly as the chunk-identity contract
/// requires: the revision is a function of the parser key, the source span, the
/// turn's position, and the redacted body — change any one and the turn is a
/// different immutable revision, hence a different canonical resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TranscriptTurnRevisionPreimageV1 {
    /// Schema version of this preimage.
    pub schema_version: u32,
    /// Identity of the parser that produced the turn.
    pub parser_key_id: ParserKeyId,
    /// Session the turn belongs to.
    pub session_id: String,
    /// Provider-side unique identifier of the turn.
    pub turn_uid: String,
    /// Position of the turn within its source.
    pub ordinal: u32,
    /// Exact raw-source byte span the turn was parsed from.
    pub span: SourceSpanV1,
    /// Digest of the exact canonical redacted body bytes.
    pub body_digest: Sha256Digest,
}

impl TranscriptTurnRevisionPreimageV1 {
    /// The domain-separated revision digest.
    pub fn revision_digest(&self) -> TranscriptConnectorResult<Sha256Digest> {
        self.span.validate()?;
        Ok(domain_separated_digest(
            DigestDomain::TranscriptTurnRevisionV1,
            &encode_canonical(self)?,
        ))
    }
}

/// Trusted, ingress-side connector binding.
///
/// `instance_coordinates` supplies the locator coordinates the ACTIVE package's
/// provider-instance recipe demands but the transcript itself does not publish
/// (for the frozen gen-1 recipe that is `provider_installation_id`). They are
/// deployment configuration, not payload: nothing a transcript file contains can
/// change them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranscriptConnectorBindingV1 {
    /// Authenticated ingress principal of this connector.
    pub ingress_principal_id: ContractId,
    /// The exact connector instance staging and draining these turns.
    pub connector_instance_id: ContractId,
    /// Values for locator coordinates the transcript does not itself publish.
    pub instance_coordinates: BTreeMap<ContractId, String>,
}

/// One canonicalized turn, ready to be staged in the outbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalizedTurnV1 {
    /// The ingress candidate, exactly as the admission seam will receive it.
    pub candidate: EvidenceIngressCandidateV2,
    /// Trusted locator coordinates the admission seam rederives both URIs from.
    pub locators: crate::evidence_ledger::EvidenceIngressLocatorsV1,
    /// The exact canonical redacted payload bytes.
    pub canonical_payload: Vec<u8>,
    /// The turn's derived immutable revision.
    pub revision: Sha256Digest,
    /// Position of the turn within its source.
    pub ordinal: u32,
    /// Session the turn belongs to.
    pub session_id: String,
}

/// Resolve one activated identity recipe out of the active package.
fn recipe(
    active: &ActiveStage4Package,
    reference: &crate::memory_contracts::common::RegistryReferenceV1,
) -> TranscriptConnectorResult<ValidatedIdentityRecipe> {
    let manifest = active.manifest_verified_package();
    let validated =
        ValidatedIdentityRecipe::from_package(manifest, &reference.entry_id, reference.version)?;
    if validated.registry_reference() != reference {
        return Err(TranscriptConnectorError::MissingLocatorCoordinate {
            key: reference.entry_id.to_string(),
        });
    }
    Ok(validated)
}

/// Build one locator from the recipe's own component rules.
///
/// `published` holds the coordinates the source fact itself publishes; those
/// MUST be carried at `hex_bytes` so the locator preimage and the published
/// field are the same bytes (the binding the admission seam re-checks). Every
/// other rule key is filled from the connector binding, and an unfilled key is a
/// closed refusal.
fn build_locator(
    active: &ActiveStage4Package,
    validated: &ValidatedIdentityRecipe,
    binding: &TranscriptConnectorBindingV1,
    published: &BTreeMap<&str, Vec<u8>>,
) -> TranscriptConnectorResult<CanonicalLocatorV1> {
    let recipe_body = validated.recipe();
    let mut components = Vec::with_capacity(recipe_body.component_rules.len());
    for rule in &recipe_body.component_rules {
        let key = rule.key.as_str();
        let value = if let Some(bytes) = published.get(key) {
            if rule.encoding != LocatorEncoding::HexBytes {
                return Err(TranscriptConnectorError::UnsupportedCoordinateEncoding {
                    key: key.to_owned(),
                });
            }
            hex::encode(bytes)
        } else {
            binding
                .instance_coordinates
                .get(&rule.key)
                .cloned()
                .ok_or_else(|| TranscriptConnectorError::MissingLocatorCoordinate {
                    key: key.to_owned(),
                })?
        };
        components.push(LocatorComponentV1 {
            key: rule.key.clone(),
            encoding: rule.encoding,
            value,
        });
    }
    let locator = CanonicalLocatorV1 {
        schema_version: 1,
        profile: active.profile().clone(),
        scope: active.scope().clone(),
        identity_form: recipe_body.identity_form,
        resource_kind: recipe_body.resource_kind.clone(),
        recipe: validated.registry_reference().clone(),
        provider_instance_namespace: recipe_body.authority_namespace.entry_id.clone(),
        parent_entity: None,
        components,
    };
    // A version-form recipe names a parent entity. It is derived from this
    // locator's own proven coordinates through the ACTIVE package, by the same
    // function the admission seam rederives with, so the ingress-side locator
    // and the admitted one cannot disagree. A non-version recipe keeps `None`.
    let parent = derive_version_parent(
        active.manifest_verified_package(),
        active.profile(),
        active.scope(),
        validated,
        &locator,
    )?;
    Ok(CanonicalLocatorV1 {
        parent_entity: parent.map(|derived| derived.uri().clone()),
        ..locator
    })
}

/// Both locators and the two URIs derived from them.
struct DerivedIdentitiesV1 {
    instance_locator: CanonicalLocatorV1,
    resource_locator: CanonicalLocatorV1,
    provider_instance_id: crate::memory_contracts::identity::ResourceUri,
    canonical_resource_id: crate::memory_contracts::identity::ResourceUri,
}

/// Build both locators from the ACTIVE package's recipes and derive both URIs
/// exactly as [`crate::evidence_ledger::admit_evidence`] will rederive them.
fn derive_identities(
    active: &ActiveStage4Package,
    connector: &StructurallyResolvedConnectorSchemaV2,
    binding: &TranscriptConnectorBindingV1,
    published: &BTreeMap<&str, Vec<u8>>,
) -> TranscriptConnectorResult<DerivedIdentitiesV1> {
    let instance_recipe = recipe(
        active,
        &connector.schema().provider_instance_identity_recipe,
    )?;
    let resource_recipe = recipe(
        active,
        &connector.schema().canonical_resource_identity_recipe,
    )?;
    // The provider-instance locator names an installation, not this turn, so it
    // is built from the binding alone: passing the turn's published coordinates
    // here would let a transcript's own bytes steer the instance URI.
    let instance_locator = build_locator(active, &instance_recipe, binding, &BTreeMap::new())?;
    let resource_locator = build_locator(active, &resource_recipe, binding, published)?;

    let instance_context = IdentityDerivationContextV1::from_trusted_context(
        active.profile().clone(),
        active.scope().clone(),
        instance_recipe
            .recipe()
            .authority_namespace
            .entry_id
            .clone(),
    );
    let provider_instance_id =
        derive_resource_uri(&instance_context, &instance_locator, &instance_recipe, None)?
            .into_uri();
    let resource_context = IdentityDerivationContextV1::from_trusted_context(
        active.profile().clone(),
        active.scope().clone(),
        resource_recipe
            .recipe()
            .authority_namespace
            .entry_id
            .clone(),
    );
    // Re-derived rather than carried: `resource_locator` already names the
    // parent, but a URI must never be minted against a parent nobody
    // re-derived. `None` for an entity or occurrence recipe.
    let resource_parent = derive_version_parent(
        active.manifest_verified_package(),
        active.profile(),
        active.scope(),
        &resource_recipe,
        &resource_locator,
    )?;
    let canonical_resource_id = derive_resource_uri(
        &resource_context,
        &resource_locator,
        &resource_recipe,
        resource_parent.as_ref(),
    )?
    .into_uri();
    Ok(DerivedIdentitiesV1 {
        instance_locator,
        resource_locator,
        provider_instance_id,
        canonical_resource_id,
    })
}

/// Canonicalize one redacted turn into an ingress candidate under the active
/// package's connector schema.
///
/// `redacted_text` must already have passed
/// [`super::redactor::RedactionGuaranteeV1::apply`]; this function has no access
/// to a turn's raw text, which is why nothing unredacted can reach the outbox
/// through it.
pub fn canonicalize_turn(
    active: &ActiveStage4Package,
    binding: &TranscriptConnectorBindingV1,
    parser_key: &ParserKeyV1,
    turn: &ParsedTurnV1,
    redacted_text: &str,
    observed_at: &CanonicalTimestamp,
    received_at: &CanonicalTimestamp,
) -> TranscriptConnectorResult<CanonicalizedTurnV1> {
    let connector: &StructurallyResolvedConnectorSchemaV2 = active.connector();

    // (1) The canonical body: redacted text only.
    let body = TranscriptTurnBodyV1 {
        schema_version: TRANSCRIPT_SCHEMA_VERSION,
        session_id: turn.session_id.clone(),
        turn_uid: turn.turn_uid.clone(),
        ordinal: turn.ordinal,
        role: turn.role.as_str().to_owned(),
        text: redacted_text.to_owned(),
    };
    let canonical_payload = encode_canonical(&body)?;
    let body_digest = Sha256Digest::from_bytes(Sha256::digest(&canonical_payload).into());

    // (2) The revision, which is where the parser identity enters the chain.
    let revision = TranscriptTurnRevisionPreimageV1 {
        schema_version: TRANSCRIPT_SCHEMA_VERSION,
        parser_key_id: parser_key.key_digest()?,
        session_id: turn.session_id.clone(),
        turn_uid: turn.turn_uid.clone(),
        ordinal: turn.ordinal,
        span: turn.span.clone(),
        body_digest,
    }
    .revision_digest()?;

    // (3) Published provider coordinates. Both are byte fields, and both appear
    // verbatim in the canonical-resource locator preimage.
    let provider_object_id = format!("{}:{}", turn.session_id, turn.turn_uid).into_bytes();
    let logical_event_key = format!("{}:{}", turn.session_id, turn.ordinal).into_bytes();
    let mut published: BTreeMap<&str, Vec<u8>> = BTreeMap::new();
    published.insert(IMMUTABLE_REVISION_KEY, revision.as_bytes().to_vec());
    published.insert(PROVIDER_OBJECT_ID_KEY, provider_object_id.clone());

    // (4) Both locators and both URIs, from the ACTIVE package's own recipes.
    let DerivedIdentitiesV1 {
        instance_locator,
        resource_locator,
        provider_instance_id,
        canonical_resource_id,
    } = derive_identities(active, connector, binding, &published)?;

    // (5) EVID-03 clock ordering, refused here rather than at the outbox.
    if !turn.occurred_at.is_microsecond_aligned()
        || !observed_at.is_microsecond_aligned()
        || !received_at.is_microsecond_aligned()
        || *observed_at < turn.occurred_at
        || *received_at < *observed_at
    {
        return Err(TranscriptConnectorError::ClockOrder);
    }

    // (6) The storage identity is derived from the credential-bound protection
    // domain and the body digest — the same function the admission seam
    // recomputes, so a mismatch here fails closed there too (EVID-04, EVID-07).
    let storage_identity = crate::memory_contracts::chunk_identity::StorageIdentityPreimageV1 {
        schema_version: STORAGE_IDENTITY_SCHEMA_VERSION,
        protection_domain_id: active.scope().project_namespace.clone(),
        body_content_id: body_digest,
    }
    .storage_identity()?
    .digest();

    let candidate = EvidenceIngressCandidateV2 {
        schema_version: EVIDENCE_SCHEMA_VERSION,
        scope: active.scope().clone(),
        connector_schema: connector.registry_reference().clone(),
        source_fact: SourceFactIdentityV2 {
            schema_version: EVIDENCE_SCHEMA_VERSION,
            scope: active.scope().clone(),
            provider_namespace: connector.schema().provider_namespace.clone(),
            provider_instance_id,
            logical_event_key: HexBytes::new(logical_event_key)?,
            provider_object_id: HexBytes::new(provider_object_id)?,
            immutable_revision: HexBytes::new(revision.as_bytes().to_vec())?,
            canonical_resource_id,
        },
        provider_actor_id: None,
        occurred_at: turn.occurred_at.clone(),
        observed_at: observed_at.clone(),
        authenticated_ingress_principal_id: binding.ingress_principal_id.clone(),
        connector_instance_id: binding.connector_instance_id.clone(),
        provider_delivery_id: HexBytes::new(revision.as_bytes().to_vec())?,
        received_at: received_at.clone(),
        canonical_payload: IngressContentReferenceV1 {
            asserted_media_type: ContractId::new(TRANSCRIPT_MEDIA_TYPE)?,
            byte_length: CanonicalDecimal::parse(canonical_payload.len().to_string())?,
            content_digest: body_digest,
            storage_identity,
        },
        private_raw_artifact: None,
    };
    candidate.validate_against_structural_connector(connector)?;

    Ok(CanonicalizedTurnV1 {
        candidate,
        locators: crate::evidence_ledger::EvidenceIngressLocatorsV1 {
            provider_instance: instance_locator,
            canonical_resource: resource_locator,
        },
        canonical_payload,
        revision,
        ordinal: turn.ordinal,
        session_id: turn.session_id.clone(),
    })
}

/// Wire label of a role, exposed so the outbox row and the body agree.
#[must_use]
pub const fn role_label(role: TranscriptRoleV1) -> &'static str {
    role.as_str()
}

#[cfg(test)]
#[path = "canonicalizer_tests.rs"]
mod tests;
