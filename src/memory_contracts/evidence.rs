//! Accepted evidence identities and governed content references.
//!
//! Source-fact identity models provider truth. Representation identity models
//! one schema/canonicalization/redaction rendering of that fact. Delivery and
//! receipt clocks are deliberately outside both identities.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::{
    ContractError, ContractResult,
    canonical::encode_canonical,
    common::{
        AuthenticatedProjectScopeV1, CanonicalDecimal, CanonicalTimestamp, ContractId, HexBytes,
        ProfileReferenceV1, RegistryReferenceV1,
    },
    digest::{DigestDomain, Sha256Digest, domain_separated_digest},
    identity::ResourceUri,
};

const EVIDENCE_SCHEMA_VERSION: u32 = 1;
const MAX_ERASURE_SCOPES: usize = 16;

macro_rules! digest_newtype {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(Sha256Digest);

        impl $name {
            pub const fn from_digest(digest: Sha256Digest) -> Self {
                Self(digest)
            }

            pub const fn digest(self) -> Sha256Digest {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                self.0.serialize(serializer)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                Sha256Digest::deserialize(deserializer).map(Self)
            }
        }
    };
}

digest_newtype!(SourceFactId);
digest_newtype!(RepresentationKey);
digest_newtype!(EvidenceEnvelopeId);
digest_newtype!(AcceptedEventId);

/// Exact semantic provider fact preimage. The connector schema is an exact
/// content-addressed registry reference; transport retry identifiers and
/// collector clocks are intentionally absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceFactIdentityV1 {
    pub schema_version: u32,
    pub scope: AuthenticatedProjectScopeV1,
    pub connector_schema: RegistryReferenceV1,
    pub provider_instance_id: ResourceUri,
    pub logical_event_key: HexBytes,
    pub provider_object_id: HexBytes,
    pub immutable_revision: HexBytes,
    pub canonical_resource_id: ResourceUri,
}

impl SourceFactIdentityV1 {
    pub fn validate(&self) -> ContractResult<()> {
        self.connector_schema.validate()?;
        if self.schema_version != EVIDENCE_SCHEMA_VERSION {
            return Err(ContractError::Schema("invalid source-fact identity".into()));
        }
        Ok(())
    }
}

/// Representation preimage.
///
/// Every interpretation and governance policy is an exact registry reference.
/// The payload digest is deliberately separate so a same-key/different-bytes
/// collision can be detected rather than hidden.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepresentationIdentityV1 {
    pub schema_version: u32,
    pub source_fact_id: SourceFactId,
    pub evidence_schema: RegistryReferenceV1,
    pub canonicalization_profile: ProfileReferenceV1,
    pub identity_recipe: RegistryReferenceV1,
    pub redaction_policy: RegistryReferenceV1,
    pub classifier_policy: RegistryReferenceV1,
    pub retention_policy: RegistryReferenceV1,
    pub publication_policy: RegistryReferenceV1,
    pub visibility_class: VisibilityClass,
    pub retention_class: RetentionClass,
    pub publication_class: PublicationClass,
    pub erasure_scopes: Vec<ErasureScopeReferenceV1>,
}

impl RepresentationIdentityV1 {
    pub fn validate(&self) -> ContractResult<()> {
        self.canonicalization_profile.validate()?;
        self.evidence_schema.validate()?;
        self.identity_recipe.validate()?;
        self.redaction_policy.validate()?;
        self.classifier_policy.validate()?;
        self.retention_policy.validate()?;
        self.publication_policy.validate()?;
        if self.schema_version != EVIDENCE_SCHEMA_VERSION
            || self.erasure_scopes.is_empty()
            || self.erasure_scopes.len() > MAX_ERASURE_SCOPES
            || !strictly_sorted(&self.erasure_scopes)
            || (self.publication_class == PublicationClass::PublicationApproved
                && self.visibility_class != VisibilityClass::PublicationApproved)
        {
            return Err(ContractError::Schema(
                "invalid representation identity".into(),
            ));
        }
        Ok(())
    }
}

/// Stable governed content semantics. Storage location is deliberately absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedContentIdentityV1 {
    pub protection_domain_id: ContractId,
    pub media_type: ContractId,
    pub byte_length: CanonicalDecimal,
    pub content_digest: Sha256Digest,
}

impl GovernedContentIdentityV1 {
    pub fn validate(&self) -> ContractResult<()> {
        let byte_length = self
            .byte_length
            .as_str()
            .parse::<u64>()
            .ok()
            .filter(|value| *value > 0 && i64::try_from(*value).is_ok());
        if byte_length.is_none() {
            return Err(ContractError::Schema(
                "governed content length must be a positive INT8 decimal".into(),
            ));
        }
        Ok(())
    }
}

/// Separately addressable governed bytes. The envelope stores no storage URL or
/// credential-bearing locator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentReferenceV1 {
    pub content: GovernedContentIdentityV1,
    pub storage_identity: Sha256Digest,
}

impl ContentReferenceV1 {
    pub fn validate(&self) -> ContractResult<()> {
        self.content.validate()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrityState {
    ProviderVerified,
    SignatureVerified,
    TransportAuthenticated,
    Unverified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VisibilityClass {
    Private,
    Project,
    PublicationApproved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionClass {
    Ephemeral,
    Governed,
    Immutable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicationClass {
    Denied,
    PrivateOnly,
    PublicationApproved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErasureScopeKind {
    PrivacySubject,
    Representation,
    Resource,
    SourceFact,
}

/// One target included in the composite erasure fence.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErasureScopeReferenceV1 {
    pub kind: ErasureScopeKind,
    pub target_digest: Sha256Digest,
}

/// Transport-neutral accepted-evidence envelope. Ingress and provider actors
/// remain distinct, and all policy classifications are server-derived.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceEnvelopeV1 {
    pub schema_version: u32,
    pub profile: ProfileReferenceV1,
    pub scope: AuthenticatedProjectScopeV1,
    pub source_fact: SourceFactIdentityV1,
    pub source_fact_id: SourceFactId,
    pub representation: RepresentationIdentityV1,
    pub representation_key: RepresentationKey,
    pub authenticated_ingress_principal_id: ContractId,
    pub connector_instance_id: ContractId,
    pub provider_actor_id: Option<HexBytes>,
    pub provider_delivery_id: HexBytes,
    pub occurred_at: CanonicalTimestamp,
    pub observed_at: CanonicalTimestamp,
    pub received_at: CanonicalTimestamp,
    pub canonical_payload_digest: Sha256Digest,
    pub canonical_payload: ContentReferenceV1,
    pub private_raw_artifact: Option<ContentReferenceV1>,
    pub integrity_state: IntegrityState,
    pub visibility_class: VisibilityClass,
    pub classifier_policy: RegistryReferenceV1,
    pub retention_class: RetentionClass,
    pub retention_policy: RegistryReferenceV1,
    pub erasure_scopes: Vec<ErasureScopeReferenceV1>,
    pub publication_class: PublicationClass,
    pub publication_policy: RegistryReferenceV1,
}

/// Stable semantic statement preimage proposed to the append ledger.
///
/// Transport IDs, authenticated attempt principal, connector instance,
/// received time, content storage identity, epoch, shard, offset, and projector
/// metadata are absent. Constructing or hashing this public wire type grants no
/// authority; Stage 2 admission must bind trusted scope/profile and activated
/// registry witnesses before appending it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceStatementV1 {
    pub schema_version: u32,
    pub profile: ProfileReferenceV1,
    pub scope: AuthenticatedProjectScopeV1,
    pub source_fact: SourceFactIdentityV1,
    pub source_fact_id: SourceFactId,
    pub representation: RepresentationIdentityV1,
    pub representation_key: RepresentationKey,
    pub provider_actor_id: Option<HexBytes>,
    pub occurred_at: CanonicalTimestamp,
    pub observed_at: CanonicalTimestamp,
    pub canonical_content: GovernedContentIdentityV1,
    pub integrity_state: IntegrityState,
    pub visibility_class: VisibilityClass,
    pub classifier_policy: RegistryReferenceV1,
    pub retention_class: RetentionClass,
    pub retention_policy: RegistryReferenceV1,
    pub erasure_scopes: Vec<ErasureScopeReferenceV1>,
    pub publication_class: PublicationClass,
    pub publication_policy: RegistryReferenceV1,
}

impl EvidenceStatementV1 {
    pub fn from_envelope(envelope: &EvidenceEnvelopeV1) -> ContractResult<Self> {
        validate_envelope(envelope)?;
        Ok(Self {
            schema_version: envelope.schema_version,
            profile: envelope.profile.clone(),
            scope: envelope.scope.clone(),
            source_fact: envelope.source_fact.clone(),
            source_fact_id: envelope.source_fact_id,
            representation: envelope.representation.clone(),
            representation_key: envelope.representation_key,
            provider_actor_id: envelope.provider_actor_id.clone(),
            occurred_at: envelope.occurred_at.clone(),
            observed_at: envelope.observed_at.clone(),
            canonical_content: envelope.canonical_payload.content.clone(),
            integrity_state: envelope.integrity_state,
            visibility_class: envelope.visibility_class,
            classifier_policy: envelope.classifier_policy.clone(),
            retention_class: envelope.retention_class,
            retention_policy: envelope.retention_policy.clone(),
            erasure_scopes: envelope.erasure_scopes.clone(),
            publication_class: envelope.publication_class,
            publication_policy: envelope.publication_policy.clone(),
        })
    }

    pub fn event_id(&self) -> ContractResult<AcceptedEventId> {
        validate_statement(self)?;
        Ok(AcceptedEventId::from_digest(domain_separated_digest(
            DigestDomain::AcceptedEvent,
            &encode_canonical(self)?,
        )))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayDisposition {
    DistinctSourceFact,
    ExactReplay,
    NewRepresentation,
}

/// Decide idempotency without using delivery or append coordinates.
pub fn replay_disposition(
    existing: &EvidenceStatementV1,
    candidate: &EvidenceStatementV1,
) -> ContractResult<ReplayDisposition> {
    validate_statement(existing)?;
    validate_statement(candidate)?;
    if existing.source_fact_id != candidate.source_fact_id {
        return Ok(ReplayDisposition::DistinctSourceFact);
    }
    if existing.representation_key != candidate.representation_key {
        return Ok(ReplayDisposition::NewRepresentation);
    }
    // A representation key reserves one exact stable accepted statement.
    // Policy or classification changes must mint a new representation rather
    // than creating two event IDs behind one representation reservation.
    if existing.event_id()? != candidate.event_id()? {
        return Err(ContractError::RepresentationCollision);
    }
    Ok(ReplayDisposition::ExactReplay)
}

/// Derive one semantic provider fact ID. Delivery and all three envelope clocks
/// cannot affect this formula because they are absent from the preimage type.
pub fn derive_source_fact_id(identity: &SourceFactIdentityV1) -> ContractResult<SourceFactId> {
    identity.validate()?;
    Ok(SourceFactId::from_digest(domain_separated_digest(
        DigestDomain::EvidenceSourceFact,
        &encode_canonical(identity)?,
    )))
}

/// Derive one representation key without hashing its payload bytes.
pub fn derive_representation_key(
    identity: &RepresentationIdentityV1,
) -> ContractResult<RepresentationKey> {
    identity.validate()?;
    Ok(RepresentationKey::from_digest(domain_separated_digest(
        DigestDomain::EvidenceRepresentation,
        &encode_canonical(identity)?,
    )))
}

pub fn validate_envelope(envelope: &EvidenceEnvelopeV1) -> ContractResult<()> {
    envelope.profile.validate()?;
    envelope.source_fact.validate()?;
    envelope.representation.validate()?;
    envelope.canonical_payload.validate()?;
    envelope.classifier_policy.validate()?;
    envelope.retention_policy.validate()?;
    envelope.publication_policy.validate()?;
    if envelope.schema_version != EVIDENCE_SCHEMA_VERSION
        || envelope.scope != envelope.source_fact.scope
        || envelope.source_fact_id != derive_source_fact_id(&envelope.source_fact)?
        || envelope.representation.source_fact_id != envelope.source_fact_id
        || envelope.representation.canonicalization_profile != envelope.profile
        || envelope.representation_key != derive_representation_key(&envelope.representation)?
        || envelope.canonical_payload_digest != envelope.canonical_payload.content.content_digest
        || envelope.representation.classifier_policy != envelope.classifier_policy
        || envelope.representation.retention_policy != envelope.retention_policy
        || envelope.representation.publication_policy != envelope.publication_policy
        || envelope.representation.visibility_class != envelope.visibility_class
        || envelope.representation.retention_class != envelope.retention_class
        || envelope.representation.publication_class != envelope.publication_class
        || envelope.representation.erasure_scopes != envelope.erasure_scopes
        || envelope.erasure_scopes.is_empty()
        || envelope.erasure_scopes.len() > MAX_ERASURE_SCOPES
        || !strictly_sorted(&envelope.erasure_scopes)
        || (envelope.publication_class == PublicationClass::PublicationApproved
            && envelope.visibility_class != VisibilityClass::PublicationApproved)
        || (envelope.retention_class != RetentionClass::Immutable
            && envelope.private_raw_artifact.is_some()
            && envelope.erasure_scopes.is_empty())
    {
        return Err(ContractError::Schema("invalid evidence envelope".into()));
    }
    if let Some(raw) = &envelope.private_raw_artifact {
        raw.validate()?;
    }
    Ok(())
}

pub fn evidence_envelope_id(envelope: &EvidenceEnvelopeV1) -> ContractResult<EvidenceEnvelopeId> {
    validate_envelope(envelope)?;
    Ok(EvidenceEnvelopeId::from_digest(domain_separated_digest(
        DigestDomain::EvidenceEnvelope,
        &encode_canonical(envelope)?,
    )))
}

fn validate_statement(statement: &EvidenceStatementV1) -> ContractResult<()> {
    statement.profile.validate()?;
    statement.source_fact.validate()?;
    statement.representation.validate()?;
    statement.classifier_policy.validate()?;
    statement.retention_policy.validate()?;
    statement.publication_policy.validate()?;
    statement.canonical_content.validate()?;
    if statement.schema_version != EVIDENCE_SCHEMA_VERSION
        || statement.scope != statement.source_fact.scope
        || statement.source_fact_id != derive_source_fact_id(&statement.source_fact)?
        || statement.representation.source_fact_id != statement.source_fact_id
        || statement.representation.canonicalization_profile != statement.profile
        || statement.representation_key != derive_representation_key(&statement.representation)?
        || statement.representation.classifier_policy != statement.classifier_policy
        || statement.representation.retention_policy != statement.retention_policy
        || statement.representation.publication_policy != statement.publication_policy
        || statement.representation.visibility_class != statement.visibility_class
        || statement.representation.retention_class != statement.retention_class
        || statement.representation.publication_class != statement.publication_class
        || statement.representation.erasure_scopes != statement.erasure_scopes
        || statement.erasure_scopes.is_empty()
        || statement.erasure_scopes.len() > MAX_ERASURE_SCOPES
        || !strictly_sorted(&statement.erasure_scopes)
        || (statement.publication_class == PublicationClass::PublicationApproved
            && statement.visibility_class != VisibilityClass::PublicationApproved)
    {
        return Err(ContractError::Schema(
            "invalid accepted evidence statement".into(),
        ));
    }
    Ok(())
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory_contracts::{
        common::ContractId,
        digest::{DigestDomain, domain_separated_digest},
        identity::ResourceUri,
    };

    fn digest(domain: DigestDomain, label: &str) -> Sha256Digest {
        domain_separated_digest(domain, label.as_bytes())
    }

    fn resource(label: &str) -> ResourceUri {
        format!(
            "urn:ostk:occurrence:v1:provider_event:sha256:{}",
            digest(DigestDomain::ResourceLocator, label)
        )
        .parse()
        .unwrap()
    }

    fn source_fact() -> SourceFactIdentityV1 {
        SourceFactIdentityV1 {
            schema_version: 1,
            scope: AuthenticatedProjectScopeV1::from_trusted_context(
                ContractId::new("tenant.fixture").unwrap(),
                ContractId::new("project.fixture").unwrap(),
            ),
            connector_schema: reference("connector.github.push", 1),
            provider_instance_id: resource("provider"),
            logical_event_key: HexBytes::new(b"push:123".to_vec()).unwrap(),
            provider_object_id: HexBytes::new(b"123".to_vec()).unwrap(),
            immutable_revision: HexBytes::new(b"sha256:abc".to_vec()).unwrap(),
            canonical_resource_id: resource("event"),
        }
    }

    fn profile() -> ProfileReferenceV1 {
        ProfileReferenceV1 {
            profile_id: ContractId::new("ostk-canonical-json-v1").unwrap(),
            profile_digest: digest(DigestDomain::CanonicalProfile, "profile"),
            vector_manifest_digest: digest(DigestDomain::TestVectorManifest, "vectors"),
        }
    }

    fn reference(id: &str, version: u32) -> RegistryReferenceV1 {
        RegistryReferenceV1 {
            entry_id: ContractId::new(id).unwrap(),
            version,
            entry_digest: digest(DigestDomain::RegistryEntry, &format!("{id}-{version}")),
        }
    }

    fn representation() -> RepresentationIdentityV1 {
        let source_fact_id = derive_source_fact_id(&source_fact()).unwrap();
        RepresentationIdentityV1 {
            schema_version: 1,
            source_fact_id,
            evidence_schema: reference("evidence.github.push", 1),
            canonicalization_profile: profile(),
            identity_recipe: reference("github.push", 1),
            redaction_policy: reference("redaction.default", 1),
            classifier_policy: reference("classifier.default", 1),
            retention_policy: reference("retention.default", 1),
            publication_policy: reference("publication.default", 1),
            visibility_class: VisibilityClass::Project,
            retention_class: RetentionClass::Governed,
            publication_class: PublicationClass::PrivateOnly,
            erasure_scopes: vec![ErasureScopeReferenceV1 {
                kind: ErasureScopeKind::SourceFact,
                target_digest: source_fact_id.digest(),
            }],
        }
    }

    fn envelope() -> EvidenceEnvelopeV1 {
        let source_fact = source_fact();
        let source_fact_id = derive_source_fact_id(&source_fact).unwrap();
        let representation = representation();
        let representation_key = derive_representation_key(&representation).unwrap();
        let payload_digest = digest(DigestDomain::Body, "payload");
        EvidenceEnvelopeV1 {
            schema_version: 1,
            profile: profile(),
            scope: source_fact.scope.clone(),
            source_fact,
            source_fact_id,
            representation,
            representation_key,
            authenticated_ingress_principal_id: ContractId::new("principal.collector").unwrap(),
            connector_instance_id: ContractId::new("connector.installation").unwrap(),
            provider_actor_id: Some(HexBytes::new(b"actor-1".to_vec()).unwrap()),
            provider_delivery_id: HexBytes::new(b"delivery-1".to_vec()).unwrap(),
            occurred_at: CanonicalTimestamp::parse("2026-08-14T12:00:00.000000000Z").unwrap(),
            observed_at: CanonicalTimestamp::parse("2026-08-14T12:00:01.000000000Z").unwrap(),
            received_at: CanonicalTimestamp::parse("2026-08-14T12:00:02.000000000Z").unwrap(),
            canonical_payload_digest: payload_digest,
            canonical_payload: ContentReferenceV1 {
                content: GovernedContentIdentityV1 {
                    protection_domain_id: ContractId::new("project.fixture").unwrap(),
                    media_type: ContractId::new("application.json").unwrap(),
                    byte_length: CanonicalDecimal::parse("128").unwrap(),
                    content_digest: payload_digest,
                },
                storage_identity: digest(DigestDomain::Body, "storage-1"),
            },
            private_raw_artifact: None,
            integrity_state: IntegrityState::ProviderVerified,
            visibility_class: VisibilityClass::Project,
            classifier_policy: reference("classifier.default", 1),
            retention_class: RetentionClass::Governed,
            retention_policy: reference("retention.default", 1),
            erasure_scopes: vec![ErasureScopeReferenceV1 {
                kind: ErasureScopeKind::SourceFact,
                target_digest: source_fact_id.digest(),
            }],
            publication_class: PublicationClass::PrivateOnly,
            publication_policy: reference("publication.default", 1),
        }
    }

    #[test]
    fn delivery_and_receipt_clocks_do_not_change_semantic_identity() {
        let identity = source_fact();
        let first = derive_source_fact_id(&identity).unwrap();
        let mut transport_only = identity;
        assert_eq!(first, derive_source_fact_id(&transport_only).unwrap());
        transport_only.logical_event_key = HexBytes::new(b"push:124".to_vec()).unwrap();
        assert_ne!(first, derive_source_fact_id(&transport_only).unwrap());

        let mut reinterpreted = source_fact();
        reinterpreted.connector_schema = reference("connector.github.push", 2);
        assert_ne!(first, derive_source_fact_id(&reinterpreted).unwrap());
    }

    #[test]
    fn representation_versions_do_not_duplicate_provider_facts() {
        let source_fact_id = derive_source_fact_id(&source_fact()).unwrap();
        let first = RepresentationIdentityV1 {
            schema_version: 1,
            source_fact_id,
            evidence_schema: reference("evidence.github.push", 1),
            canonicalization_profile: profile(),
            identity_recipe: reference("github.push", 1),
            redaction_policy: reference("redaction.default", 1),
            classifier_policy: reference("classifier.default", 1),
            retention_policy: reference("retention.default", 1),
            publication_policy: reference("publication.default", 1),
            visibility_class: VisibilityClass::Project,
            retention_class: RetentionClass::Governed,
            publication_class: PublicationClass::PrivateOnly,
            erasure_scopes: vec![ErasureScopeReferenceV1 {
                kind: ErasureScopeKind::SourceFact,
                target_digest: source_fact_id.digest(),
            }],
        };
        let mut second = first.clone();
        second.redaction_policy = reference("redaction.default", 2);
        assert_ne!(
            derive_representation_key(&first).unwrap(),
            derive_representation_key(&second).unwrap()
        );
        assert_eq!(first.source_fact_id, second.source_fact_id);
    }

    #[test]
    fn accepted_event_identity_excludes_transport_position_and_storage() {
        let first = envelope();
        let first_statement = EvidenceStatementV1::from_envelope(&first).unwrap();
        let first_id = first_statement.event_id().unwrap();

        let mut retry = first;
        retry.authenticated_ingress_principal_id = ContractId::new("principal.rotated").unwrap();
        retry.connector_instance_id = ContractId::new("connector.reinstalled").unwrap();
        retry.provider_delivery_id = HexBytes::new(b"delivery-2".to_vec()).unwrap();
        retry.received_at = CanonicalTimestamp::parse("2026-08-14T12:10:00.000000000Z").unwrap();
        retry.canonical_payload.storage_identity = digest(DigestDomain::Body, "storage-2");
        let retry_statement = EvidenceStatementV1::from_envelope(&retry).unwrap();
        assert_eq!(first_id, retry_statement.event_id().unwrap());
        assert_eq!(
            replay_disposition(&first_statement, &retry_statement).unwrap(),
            ReplayDisposition::ExactReplay
        );
    }

    #[test]
    fn same_representation_with_different_payload_is_a_collision() {
        let first = EvidenceStatementV1::from_envelope(&envelope()).unwrap();
        let mut collision = first.clone();
        collision.canonical_content.content_digest = digest(DigestDomain::Body, "different");
        assert_eq!(
            replay_disposition(&first, &collision),
            Err(ContractError::RepresentationCollision)
        );

        let mut reclassified = first.clone();
        reclassified.publication_class = PublicationClass::Denied;
        reclassified.representation.publication_class = PublicationClass::Denied;
        reclassified.representation_key =
            derive_representation_key(&reclassified.representation).unwrap();
        assert_eq!(
            replay_disposition(&first, &reclassified).unwrap(),
            ReplayDisposition::NewRepresentation
        );

        let mut conflicting_actor = first.clone();
        conflicting_actor.provider_actor_id = Some(HexBytes::new(b"actor-2".to_vec()).unwrap());
        assert_eq!(
            replay_disposition(&first, &conflicting_actor),
            Err(ContractError::RepresentationCollision)
        );
    }

    #[test]
    fn governed_content_length_is_a_positive_bounded_integer() {
        for invalid in ["0", "-1", "0.5", "9223372036854775808"] {
            let content = GovernedContentIdentityV1 {
                protection_domain_id: ContractId::new("project.fixture").unwrap(),
                media_type: ContractId::new("application.json").unwrap(),
                byte_length: CanonicalDecimal::parse(invalid).unwrap(),
                content_digest: digest(DigestDomain::Body, "payload"),
            };
            assert!(content.validate().is_err(), "accepted {invalid}");
        }
    }
}
