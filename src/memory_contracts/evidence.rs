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

/// Exact semantic provider fact preimage. Transport retry identifiers and
/// collector clocks are intentionally absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceFactIdentityV1 {
    pub schema_version: u32,
    pub scope: AuthenticatedProjectScopeV1,
    pub connector_schema_id: ContractId,
    pub connector_schema_version: u32,
    pub provider_instance_id: ResourceUri,
    pub logical_event_key: HexBytes,
    pub provider_object_id: HexBytes,
    pub immutable_revision: HexBytes,
    pub canonical_resource_id: ResourceUri,
}

impl SourceFactIdentityV1 {
    pub fn validate(&self) -> ContractResult<()> {
        if self.schema_version != EVIDENCE_SCHEMA_VERSION || self.connector_schema_version == 0 {
            return Err(ContractError::Schema("invalid source-fact identity".into()));
        }
        Ok(())
    }
}

/// Representation preimage. The payload digest is deliberately separate so a
/// same-key/different-bytes collision can be detected rather than hidden.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepresentationIdentityV1 {
    pub schema_version: u32,
    pub source_fact_id: SourceFactId,
    pub evidence_schema_id: ContractId,
    pub evidence_schema_version: u32,
    pub canonicalization_profile: ProfileReferenceV1,
    pub identity_recipe: RegistryReferenceV1,
    pub redaction_policy: RegistryReferenceV1,
    pub redaction_policy_version: u32,
}

impl RepresentationIdentityV1 {
    pub fn validate(&self) -> ContractResult<()> {
        self.canonicalization_profile.validate()?;
        self.identity_recipe.validate()?;
        self.redaction_policy.validate()?;
        if self.schema_version != EVIDENCE_SCHEMA_VERSION
            || self.evidence_schema_version == 0
            || self.redaction_policy_version == 0
        {
            return Err(ContractError::Schema(
                "invalid representation identity".into(),
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
    pub protection_domain_id: ContractId,
    pub media_type: ContractId,
    pub byte_length: CanonicalDecimal,
    pub content_digest: Sha256Digest,
    pub storage_identity: Sha256Digest,
}

impl ContentReferenceV1 {
    pub fn validate(&self) -> ContractResult<()> {
        if self.byte_length.as_str() == "0" {
            return Err(ContractError::Schema(
                "content reference cannot be empty".into(),
            ));
        }
        Ok(())
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
        || envelope.canonical_payload_digest != envelope.canonical_payload.content_digest
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
            connector_schema_id: ContractId::new("github.push").unwrap(),
            connector_schema_version: 1,
            provider_instance_id: resource("provider"),
            logical_event_key: HexBytes::new(b"push:123".to_vec()).unwrap(),
            provider_object_id: HexBytes::new(b"123".to_vec()).unwrap(),
            immutable_revision: HexBytes::new(b"sha256:abc".to_vec()).unwrap(),
            canonical_resource_id: resource("event"),
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
    }

    #[test]
    fn representation_versions_do_not_duplicate_provider_facts() {
        let source_fact_id = derive_source_fact_id(&source_fact()).unwrap();
        let profile = ProfileReferenceV1 {
            profile_id: ContractId::new("ostk-canonical-json-v1").unwrap(),
            profile_digest: digest(DigestDomain::CanonicalProfile, "profile"),
            vector_manifest_digest: digest(DigestDomain::TestVectorManifest, "vectors"),
        };
        let reference = |id: &str, version| RegistryReferenceV1 {
            entry_id: ContractId::new(id).unwrap(),
            version,
            entry_digest: digest(DigestDomain::RegistryEntry, &format!("{id}-{version}")),
        };
        let first = RepresentationIdentityV1 {
            schema_version: 1,
            source_fact_id,
            evidence_schema_id: ContractId::new("github.push").unwrap(),
            evidence_schema_version: 1,
            canonicalization_profile: profile,
            identity_recipe: reference("github.push", 1),
            redaction_policy: reference("redaction.default", 1),
            redaction_policy_version: 1,
        };
        let mut second = first.clone();
        second.redaction_policy_version = 2;
        assert_ne!(
            derive_representation_key(&first).unwrap(),
            derive_representation_key(&second).unwrap()
        );
        assert_eq!(first.source_fact_id, second.source_fact_id);
    }
}
