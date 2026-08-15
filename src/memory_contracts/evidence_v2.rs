//! Registry-bound evidence candidates and connector-owned consistency recipes.
//!
//! This module is contract-only. [`RegistryHeadBindingV1`] is identity-bearing
//! data, not proof that the named head is active. Likewise,
//! [`StructurallyResolvedConnectorSchemaV2`] proves that one exact registry
//! entry closes over a valid connector body, but not that the entry belongs to
//! the active package. A later repository seam must supply both facts from one
//! transaction before it may append an event.
//!
//! Source-fact identity is deliberately independent of registry activation.
//! Head, connector, evidence-schema, policy, profile, or governance changes
//! that preserve the exact resource identities instead mint an explicitly
//! linked representation. An identity-recipe revision is different: the exact
//! recipe reference participates in its resource-locator digest, so runtime
//! admission must rederive the affected URI and therefore a distinct source
//! fact. Delivery IDs, receipt clocks, storage locations, and physical
//! partition coordinates stay outside the accepted-event preimage.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::{
    ContractError, ContractResult,
    bootstrap::ConsistencyPartitionKeyV1,
    canonical::{decode_strict, encode_canonical},
    common::{
        AuthenticatedProjectScopeV1, CanonicalDecimal, CanonicalTimestamp, ContractId, HexBytes,
        ProfileReferenceV1, RegistryReferenceV1,
    },
    digest::{DigestDomain, Sha256Digest, domain_separated_digest},
    evidence::{
        AcceptedEventId, ErasureScopeReferenceV1, GovernedContentIdentityV1, IntegrityState,
        PublicationClass, RetentionClass, VisibilityClass,
    },
    identity::{IdentityForm, ResourceUri},
    registry::{RegistryEntryKind, RegistryEntryV1, RegistryHeadV1},
};

const EVIDENCE_SCHEMA_VERSION: u32 = 2;
const CONNECTOR_SCHEMA_VERSION: u32 = 2;
const CONSISTENCY_RECIPE_SCHEMA_VERSION: u32 = 1;
const MAX_ERASURE_SCOPES: usize = 16;
const CONSISTENCY_RECIPE_ID: &str = "ostk.consistency.source_fact_id";
const CONNECTOR_ENTRY_SCHEMA_ID: &str = "registry.connector_schema";
const EVIDENCE_ACCEPTED_EVENT_KIND: &str = "evidence.accepted";

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

digest_newtype!(SourceFactIdV2);
digest_newtype!(RepresentationKeyV2);

/// Exact active-head coordinates copied into an identity preimage.
///
/// Shape validation cannot establish that this head is active. In particular,
/// callers cannot gain registry authority by constructing this public value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryHeadBindingV1 {
    pub head: RegistryHeadV1,
    pub effective_from: CanonicalTimestamp,
    pub effective_until: Option<CanonicalTimestamp>,
}

impl RegistryHeadBindingV1 {
    pub fn validate_shape(&self) -> ContractResult<()> {
        if self.head.activation_id == Sha256Digest::ZERO
            || self.head.package_digest == Sha256Digest::ZERO
            || self.head.activation_policy_digest == Sha256Digest::ZERO
            || !self.effective_from.is_microsecond_aligned()
            || self.effective_until.as_ref().is_some_and(|until| {
                !until.is_microsecond_aligned() || until <= &self.effective_from
            })
        {
            return Err(ContractError::Schema(
                "invalid structural registry head binding".into(),
            ));
        }
        Ok(())
    }
}

/// Closed consistency family for evidence v2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsistencyPartitionFamilyV1 {
    SourceFact,
}

impl ConsistencyPartitionFamilyV1 {
    const fn as_str(self) -> &'static str {
        match self {
            Self::SourceFact => "source_fact",
        }
    }
}

/// Closed logical-key derivation for evidence v2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsistencyKeyDerivationV1 {
    SourceFactId,
}

/// Exact connector-owned logical consistency recipe.
///
/// The recipe contains no epoch, shard count, seed, or append coordinate. The
/// bootstrap epoch maps its logical result to a physical shard independently.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsistencyPartitionRecipeV1 {
    pub schema_version: u32,
    pub recipe_id: ContractId,
    pub recipe_version: u32,
    pub family: ConsistencyPartitionFamilyV1,
    pub key_derivation: ConsistencyKeyDerivationV1,
}

impl ConsistencyPartitionRecipeV1 {
    pub fn validate(&self) -> ContractResult<()> {
        if self.schema_version != CONSISTENCY_RECIPE_SCHEMA_VERSION
            || self.recipe_id.as_str() != CONSISTENCY_RECIPE_ID
            || self.recipe_version != 1
            || self.family != ConsistencyPartitionFamilyV1::SourceFact
            || self.key_derivation != ConsistencyKeyDerivationV1::SourceFactId
        {
            return Err(ContractError::Schema(
                "invalid evidence consistency partition recipe".into(),
            ));
        }
        Ok(())
    }

    fn derive(&self, source_fact_id: SourceFactIdV2) -> ContractResult<ConsistencyPartitionKeyV1> {
        self.validate()?;
        Ok(ConsistencyPartitionKeyV1 {
            family: ContractId::new(self.family.as_str())?,
            key_digest: source_fact_id.digest(),
        })
    }
}

/// Registry body contract for evidence-producing connectors.
///
/// A semantic package verifier will require this exact body for connector
/// schema v2. The consistency recipe is therefore registry-controlled rather
/// than selected by an ingress payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct ConnectorSchemaV2 {
    pub schema_version: u32,
    pub connector_schema_id: ContractId,
    pub version: u32,
    pub provider_namespace: RegistryReferenceV1,
    pub evidence_schema: RegistryReferenceV1,
    pub provider_instance_identity_recipe: RegistryReferenceV1,
    pub canonical_resource_identity_recipe: RegistryReferenceV1,
    pub consistency_partition_recipe: ConsistencyPartitionRecipeV1,
    pub authenticated_scope_required: bool,
    pub delivery_id_in_semantic_identity: bool,
    pub immutable_revision_required: bool,
}

impl ConnectorSchemaV2 {
    pub fn validate(&self) -> ContractResult<()> {
        self.provider_namespace.validate()?;
        self.evidence_schema.validate()?;
        self.provider_instance_identity_recipe.validate()?;
        self.canonical_resource_identity_recipe.validate()?;
        self.consistency_partition_recipe.validate()?;
        if self.schema_version != CONNECTOR_SCHEMA_VERSION
            || self.version == 0
            || !self.authenticated_scope_required
            || self.delivery_id_in_semantic_identity
            || !self.immutable_revision_required
        {
            return Err(ContractError::Schema(
                "invalid evidence connector schema v2".into(),
            ));
        }
        Ok(())
    }
}

/// One exact connector registry entry whose body and reference agree.
///
/// This is intentionally named `StructurallyResolved`, not `Verified` or
/// `Active`: any caller can construct registry-entry bytes. Runtime admission
/// must additionally prove membership in the exact active package/head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructurallyResolvedConnectorSchemaV2 {
    registry_reference: RegistryReferenceV1,
    schema: ConnectorSchemaV2,
}

impl StructurallyResolvedConnectorSchemaV2 {
    pub fn from_registry_entry(entry: &RegistryEntryV1) -> ContractResult<Self> {
        entry.validate()?;
        if entry.kind != RegistryEntryKind::ConnectorSchema
            || entry.entry_schema_id.as_str() != CONNECTOR_ENTRY_SCHEMA_ID
            || entry.entry_schema_version != CONNECTOR_SCHEMA_VERSION
        {
            return Err(ContractError::Schema(
                "registry entry is not a connector schema v2 body".into(),
            ));
        }
        let body_bytes = encode_canonical(&entry.body)?;
        let schema: ConnectorSchemaV2 = decode_strict(&body_bytes)?;
        schema.validate()?;
        if schema.connector_schema_id != entry.entry_id {
            return Err(ContractError::ManifestMismatch);
        }
        if schema.version != entry.version {
            return Err(ContractError::ManifestMismatch);
        }
        Ok(Self {
            registry_reference: RegistryReferenceV1 {
                entry_id: entry.entry_id.clone(),
                version: entry.version,
                entry_digest: entry.digest()?,
            },
            schema,
        })
    }

    pub const fn schema(&self) -> &ConnectorSchemaV2 {
        &self.schema
    }

    pub const fn registry_reference(&self) -> &RegistryReferenceV1 {
        &self.registry_reference
    }
}

/// Provider-truth preimage, stable across registry-head activations.
///
/// Connector schema is absent on purpose. Provider namespace and immutable
/// provider coordinates identify the fact; interpretation belongs to a
/// representation. Structural validation does not authenticate caller-supplied
/// resource URIs: runtime admission must rederive each URI through its exact
/// activated identity-recipe witness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceFactIdentityV2 {
    pub schema_version: u32,
    pub scope: AuthenticatedProjectScopeV1,
    pub provider_namespace: RegistryReferenceV1,
    pub provider_instance_id: ResourceUri,
    pub logical_event_key: HexBytes,
    pub provider_object_id: HexBytes,
    pub immutable_revision: HexBytes,
    pub canonical_resource_id: ResourceUri,
}

impl SourceFactIdentityV2 {
    pub fn validate(&self) -> ContractResult<()> {
        self.provider_namespace.validate()?;
        if self.schema_version != EVIDENCE_SCHEMA_VERSION
            || self.provider_instance_id.identity_form() != IdentityForm::Entity
        {
            return Err(ContractError::Schema(
                "invalid source-fact identity v2".into(),
            ));
        }
        Ok(())
    }
}

/// Explicit representation ancestry. A first rendering is `Origin`; every
/// reinterpretation of the same source fact names the exact predecessor key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RepresentationLineageV2 {
    Origin,
    Supersedes {
        predecessor_representation_key: RepresentationKeyV2,
    },
}

/// Interpretation and governance preimage for one provider fact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepresentationIdentityV2 {
    pub schema_version: u32,
    pub source_fact_id: SourceFactIdV2,
    pub registry_head: RegistryHeadBindingV1,
    pub connector_schema: RegistryReferenceV1,
    pub evidence_schema: RegistryReferenceV1,
    pub canonicalization_profile: ProfileReferenceV1,
    pub provider_instance_identity_recipe: RegistryReferenceV1,
    pub canonical_resource_identity_recipe: RegistryReferenceV1,
    pub redaction_policy: RegistryReferenceV1,
    pub classifier_policy: RegistryReferenceV1,
    pub retention_policy: RegistryReferenceV1,
    pub publication_policy: RegistryReferenceV1,
    pub integrity_state: IntegrityState,
    pub visibility_class: VisibilityClass,
    pub retention_class: RetentionClass,
    pub publication_class: PublicationClass,
    pub erasure_scopes: Vec<ErasureScopeReferenceV1>,
    pub lineage: RepresentationLineageV2,
}

impl RepresentationIdentityV2 {
    pub fn validate(&self) -> ContractResult<()> {
        self.registry_head.validate_shape()?;
        self.connector_schema.validate()?;
        self.evidence_schema.validate()?;
        self.canonicalization_profile.validate()?;
        self.provider_instance_identity_recipe.validate()?;
        self.canonical_resource_identity_recipe.validate()?;
        self.redaction_policy.validate()?;
        self.classifier_policy.validate()?;
        self.retention_policy.validate()?;
        self.publication_policy.validate()?;
        if self.schema_version != EVIDENCE_SCHEMA_VERSION
            || self.erasure_scopes.is_empty()
            || self.erasure_scopes.len() > MAX_ERASURE_SCOPES
            || !strictly_sorted(&self.erasure_scopes)
            || matches!(
                self.lineage,
                RepresentationLineageV2::Supersedes {
                    predecessor_representation_key
                } if predecessor_representation_key.digest() == Sha256Digest::ZERO
            )
            || (self.publication_class == PublicationClass::PublicationApproved
                && self.visibility_class != VisibilityClass::PublicationApproved)
        {
            return Err(ContractError::Schema(
                "invalid representation identity v2".into(),
            ));
        }
        Ok(())
    }
}

/// Stable accepted-evidence semantic preimage proposed to the append ledger.
///
/// Public construction and hashing do not admit the event. A repository must
/// compare `registry_head` to a same-transaction active-head witness, resolve
/// every registry reference from that package, rederive resource identities,
/// and use opaque integrity-verification and policy-derivation results to
/// select every integrity/classification field. It then derives the logical
/// consistency key separately before append. Only that later seam may persist
/// this ID as an accepted event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceStatementV2 {
    pub schema_version: u32,
    pub event_kind: ContractId,
    pub profile: ProfileReferenceV1,
    pub scope: AuthenticatedProjectScopeV1,
    pub registry_head: RegistryHeadBindingV1,
    pub source_fact: SourceFactIdentityV2,
    pub source_fact_id: SourceFactIdV2,
    pub representation: RepresentationIdentityV2,
    pub representation_key: RepresentationKeyV2,
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

impl EvidenceStatementV2 {
    pub fn validate_shape(&self) -> ContractResult<()> {
        self.profile.validate()?;
        self.registry_head.validate_shape()?;
        self.source_fact.validate()?;
        self.representation.validate()?;
        self.canonical_content.validate()?;
        self.classifier_policy.validate()?;
        self.retention_policy.validate()?;
        self.publication_policy.validate()?;
        if self.schema_version != EVIDENCE_SCHEMA_VERSION
            || self.event_kind.as_str() != EVIDENCE_ACCEPTED_EVENT_KIND
            || self.scope != self.source_fact.scope
            || self.registry_head != self.representation.registry_head
            || self.source_fact_id != derive_source_fact_id_v2(&self.source_fact)?
            || self.representation.source_fact_id != self.source_fact_id
            || self.representation.canonicalization_profile != self.profile
            || self.representation_key != derive_representation_key_v2(&self.representation)?
            || self.representation.classifier_policy != self.classifier_policy
            || self.representation.retention_policy != self.retention_policy
            || self.representation.publication_policy != self.publication_policy
            || self.representation.integrity_state != self.integrity_state
            || self.representation.visibility_class != self.visibility_class
            || self.representation.retention_class != self.retention_class
            || self.representation.publication_class != self.publication_class
            || self.representation.erasure_scopes != self.erasure_scopes
            || self.erasure_scopes.is_empty()
            || self.erasure_scopes.len() > MAX_ERASURE_SCOPES
            || !strictly_sorted(&self.erasure_scopes)
            || (self.publication_class == PublicationClass::PublicationApproved
                && self.visibility_class != VisibilityClass::PublicationApproved)
        {
            return Err(ContractError::Schema(
                "invalid accepted evidence statement v2 candidate".into(),
            ));
        }
        Ok(())
    }

    /// Prove exact connector-entry closure and all copied references, but not
    /// active-package membership or active-head authority.
    pub fn validate_against_structural_connector(
        &self,
        connector: &StructurallyResolvedConnectorSchemaV2,
    ) -> ContractResult<()> {
        self.validate_shape()?;
        if self.representation.connector_schema != *connector.registry_reference()
            || self.source_fact.provider_namespace != connector.schema().provider_namespace
            || self.representation.evidence_schema != connector.schema().evidence_schema
            || self.representation.provider_instance_identity_recipe
                != connector.schema().provider_instance_identity_recipe
            || self.representation.canonical_resource_identity_recipe
                != connector.schema().canonical_resource_identity_recipe
        {
            return Err(ContractError::ManifestMismatch);
        }
        Ok(())
    }

    /// Derive the logical append key from the exact connector body. The result
    /// is not part of [`Self::accepted_event_id`].
    pub fn consistency_partition_key(
        &self,
        connector: &StructurallyResolvedConnectorSchemaV2,
    ) -> ContractResult<ConsistencyPartitionKeyV1> {
        self.validate_against_structural_connector(connector)?;
        connector
            .schema()
            .consistency_partition_recipe
            .derive(self.source_fact_id)
    }

    pub fn accepted_event_id(&self) -> ContractResult<AcceptedEventId> {
        self.validate_shape()?;
        Ok(AcceptedEventId::from_digest(domain_separated_digest(
            DigestDomain::AcceptedEvent,
            &encode_canonical(self)?,
        )))
    }
}

/// Ungoverned content reference accepted only as ingress input.
///
/// Media type is explicitly asserted. Protection domain and every governance
/// classification are absent and must be derived during repository admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngressContentReferenceV1 {
    pub asserted_media_type: ContractId,
    pub byte_length: CanonicalDecimal,
    pub content_digest: Sha256Digest,
    pub storage_identity: Sha256Digest,
}

impl IngressContentReferenceV1 {
    pub fn validate(&self) -> ContractResult<()> {
        let byte_length = self
            .byte_length
            .as_str()
            .parse::<u64>()
            .ok()
            .filter(|value| *value > 0 && i64::try_from(*value).is_ok());
        if byte_length.is_none() {
            return Err(ContractError::Schema(
                "ingress content length must be a positive INT8 decimal".into(),
            ));
        }
        Ok(())
    }
}

/// Asserted and transport-bearing ingress candidate.
///
/// It deliberately cannot contain a registry head, representation, integrity
/// state, governance classifications, or an accepted-event ID. Scope,
/// principal, connector-instance, and receipt time must be populated from
/// trusted ingress context. A later opaque repository admission capability
/// materializes [`EvidenceStatementV2`] after active-registry, identity,
/// integrity, and policy checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceIngressCandidateV2 {
    pub schema_version: u32,
    pub scope: AuthenticatedProjectScopeV1,
    pub connector_schema: RegistryReferenceV1,
    pub source_fact: SourceFactIdentityV2,
    pub provider_actor_id: Option<HexBytes>,
    pub occurred_at: CanonicalTimestamp,
    pub observed_at: CanonicalTimestamp,
    pub authenticated_ingress_principal_id: ContractId,
    pub connector_instance_id: ContractId,
    pub provider_delivery_id: HexBytes,
    pub received_at: CanonicalTimestamp,
    pub canonical_payload: IngressContentReferenceV1,
    pub private_raw_artifact: Option<IngressContentReferenceV1>,
}

impl EvidenceIngressCandidateV2 {
    pub fn validate_against_structural_connector(
        &self,
        connector: &StructurallyResolvedConnectorSchemaV2,
    ) -> ContractResult<()> {
        self.source_fact.validate()?;
        self.canonical_payload.validate()?;
        if self.schema_version != EVIDENCE_SCHEMA_VERSION
            || self.scope != self.source_fact.scope
            || self.connector_schema != *connector.registry_reference()
            || self.source_fact.provider_namespace != connector.schema().provider_namespace
        {
            return Err(ContractError::Schema(
                "invalid evidence ingress candidate v2".into(),
            ));
        }
        if let Some(raw) = &self.private_raw_artifact {
            raw.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayDispositionV2 {
    DistinctSourceFact,
    ExactReplay,
    NewRepresentation,
}

/// Decide semantic replay and require explicit same-fact predecessor lineage.
pub fn replay_disposition_v2(
    existing: &EvidenceStatementV2,
    candidate: &EvidenceStatementV2,
) -> ContractResult<ReplayDispositionV2> {
    existing.validate_shape()?;
    candidate.validate_shape()?;
    if existing.source_fact_id != candidate.source_fact_id {
        return Ok(ReplayDispositionV2::DistinctSourceFact);
    }
    if existing.representation_key == candidate.representation_key {
        if existing.accepted_event_id()? != candidate.accepted_event_id()? {
            return Err(ContractError::RepresentationCollision);
        }
        return Ok(ReplayDispositionV2::ExactReplay);
    }
    if candidate.representation.lineage
        != (RepresentationLineageV2::Supersedes {
            predecessor_representation_key: existing.representation_key,
        })
    {
        return Err(ContractError::Schema(
            "new representation does not name the exact predecessor".into(),
        ));
    }
    Ok(ReplayDispositionV2::NewRepresentation)
}

pub fn derive_source_fact_id_v2(identity: &SourceFactIdentityV2) -> ContractResult<SourceFactIdV2> {
    identity.validate()?;
    Ok(SourceFactIdV2::from_digest(domain_separated_digest(
        DigestDomain::EvidenceSourceFactV2,
        &encode_canonical(identity)?,
    )))
}

pub fn derive_representation_key_v2(
    identity: &RepresentationIdentityV2,
) -> ContractResult<RepresentationKeyV2> {
    identity.validate()?;
    let key = RepresentationKeyV2::from_digest(domain_separated_digest(
        DigestDomain::EvidenceRepresentationV2,
        &encode_canonical(identity)?,
    ));
    if matches!(
        identity.lineage,
        RepresentationLineageV2::Supersedes {
            predecessor_representation_key
        } if predecessor_representation_key == key
    ) {
        return Err(ContractError::Schema(
            "representation cannot supersede itself".into(),
        ));
    }
    Ok(key)
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory_contracts::{
        canonical::{CanonicalValue, require_canonical},
        common::frozen_profile_reference_v1,
    };
    use sha2::{Digest as _, Sha256};

    const EXPECTED_SOURCE_FACT_ID: &str =
        "1b85e827dbdb36627ba53dd336ac1ca42a811bfdbd0395631d1e60062ee3610c";
    const EXPECTED_REPRESENTATION_KEY: &str =
        "43524ede361ff9a5b797c45c301175bc4f20a33a1b2686675b9558f44703c239";
    const EXPECTED_EVENT_ID: &str =
        "7eec4cae23bee151e5e12bd966f01b9bb3e0b3bc45e72de9214ba5fd2a284aa2";
    const EXPECTED_CONNECTOR_ENTRY_DIGEST: &str =
        "65adedae08d6f23fea387ad91e2bdf1de16ad9f2662fa392192b2d28693c03f6";
    const EXPECTED_SUCCESSOR_KEY: &str =
        "62405e1dfeb3d286aa043272d63a0d53e74e638271334a101761b99c24cfc9a2";
    const EXPECTED_SUCCESSOR_EVENT_ID: &str =
        "fa8a78763eca031b420b2b3602aaa5fe983087a072c40cd5f9f9827d4270a616";
    const EXPECTED_VECTOR_SUITE_DIGEST: &str =
        "d0c485a45d9ba15eb5512c0ab8f40a7e5ce4c3bd774e39b8168424b9fafe9141";
    const EXPECTED_POLICY_KEY: &str =
        "fb2e1566070e794b144a66e31de91f9fcdb462ee1b6b13e6edf6915235e6f808";
    const EXPECTED_POLICY_EVENT_ID: &str =
        "632b73e45afefd57e8296ef52635ae95f64c8818e896ac91a86261139fb0ebd1";
    const EXPECTED_PROFILE_KEY: &str =
        "f1ce4d4fc0d332a2ce94e506972d3bcf3a44d4320a75112b441a764db08043ca";
    const EXPECTED_PROFILE_EVENT_ID: &str =
        "f84677e70fde5ae5a0b3583e038179d3cd0e756ca2bc24a91692bc42cdc90637";
    const EXPECTED_INTEGRITY_KEY: &str =
        "422f0ae9d0f996661269f2c4ce4dedf6ac37edc8c650de67f076adfc176ec538";
    const EXPECTED_INTEGRITY_EVENT_ID: &str =
        "d6aebb962c0fc25811d0e4a870cbb3afb2376285dbdfb460da763a1bd69a389c";
    const EXPECTED_CONNECTOR_RAW_SHA256: &str =
        "2c7eed9d0a5b9107415b9f11551b6db5923aeb11e991e2b56c091038756f34f7";
    const EXPECTED_SOURCE_RAW_SHA256: &str =
        "7771c8ede425cce12528ceca81d69662d05b4ba19811e1a2b90da89c18b46225";
    const EXPECTED_REPRESENTATION_RAW_SHA256: &str =
        "abadfb76594e8001700c4b61ea2ae4dbfe26d1234129419ebb2f311ff14bb660";
    const EXPECTED_SUCCESSOR_RAW_SHA256: &str =
        "05053b36f4e3e7fda74c9b102a96bd23a3d0fd9deeb2f66888a4a39737cf0e7b";
    const EXPECTED_STATEMENT_RAW_SHA256: &str =
        "7c64432cc11c7f85c721ee3789343f4c22804fbe2ef34a946f7f8d652bfc199a";
    const EXPECTED_BAD_FAMILY_RAW_SHA256: &str =
        "6c9470b0760a3789d267d5416b9900cf0787c3b47ebda6a165eefab1176f9022";
    const EXPECTED_BAD_DERIVATION_RAW_SHA256: &str =
        "587d239629963b92274382fcb4609c6d39515a2bee6e4e6288286c47511824a1";
    const EXPECTED_VECTOR_SUITE_RAW_SHA256: &str =
        "3bdd2c2112023772b33fe9e5479f823d6293350339686c250a431a034b2d9628";

    fn digest(domain: DigestDomain, label: &str) -> Sha256Digest {
        domain_separated_digest(domain, label.as_bytes())
    }

    fn reference(id: &str, version: u32) -> RegistryReferenceV1 {
        RegistryReferenceV1 {
            entry_id: ContractId::new(id).unwrap(),
            version,
            entry_digest: digest(DigestDomain::RegistryEntry, &format!("{id}-{version}")),
        }
    }

    fn resource(identity_form: IdentityForm, resource_kind: &str, label: &str) -> ResourceUri {
        format!(
            "urn:ostk:{}:v1:{resource_kind}:sha256:{}",
            identity_form.as_str(),
            digest(DigestDomain::ResourceLocator, label)
        )
        .parse()
        .unwrap()
    }

    fn registry_head(label: &str) -> RegistryHeadBindingV1 {
        RegistryHeadBindingV1 {
            head: RegistryHeadV1 {
                activation_id: digest(DigestDomain::RegistryActivationReceipt, label),
                package_digest: digest(DigestDomain::RegistryPackage, "package-a"),
                activation_policy_digest: digest(
                    DigestDomain::RegistryEntry,
                    "activation-policy-a",
                ),
            },
            effective_from: CanonicalTimestamp::parse("2026-08-15T12:00:00.000000000Z").unwrap(),
            effective_until: None,
        }
    }

    fn connector_schema() -> ConnectorSchemaV2 {
        ConnectorSchemaV2 {
            schema_version: 2,
            connector_schema_id: ContractId::new("connector.github.push-v2").unwrap(),
            version: 2,
            provider_namespace: reference("namespace.github", 1),
            evidence_schema: reference("evidence.github.push", 2),
            provider_instance_identity_recipe: reference("identity.github.provider_instance", 1),
            canonical_resource_identity_recipe: reference("identity.github.push", 2),
            consistency_partition_recipe: ConsistencyPartitionRecipeV1 {
                schema_version: 1,
                recipe_id: ContractId::new(CONSISTENCY_RECIPE_ID).unwrap(),
                recipe_version: 1,
                family: ConsistencyPartitionFamilyV1::SourceFact,
                key_derivation: ConsistencyKeyDerivationV1::SourceFactId,
            },
            authenticated_scope_required: true,
            delivery_id_in_semantic_identity: false,
            immutable_revision_required: true,
        }
    }

    fn connector_entry() -> RegistryEntryV1 {
        let body_bytes = encode_canonical(&connector_schema()).unwrap();
        let body: CanonicalValue = decode_strict(&body_bytes).unwrap();
        RegistryEntryV1 {
            schema_version: 1,
            kind: RegistryEntryKind::ConnectorSchema,
            entry_id: ContractId::new("connector.github.push-v2").unwrap(),
            version: 2,
            entry_schema_id: ContractId::new(CONNECTOR_ENTRY_SCHEMA_ID).unwrap(),
            entry_schema_version: 2,
            body,
            positive_vector_digest: digest(DigestDomain::TestVectorManifest, "connector-v2-ok"),
            negative_vector_digest: digest(DigestDomain::TestVectorManifest, "connector-v2-bad"),
        }
    }

    fn resolved_connector() -> StructurallyResolvedConnectorSchemaV2 {
        StructurallyResolvedConnectorSchemaV2::from_registry_entry(&connector_entry()).unwrap()
    }

    fn source_fact() -> SourceFactIdentityV2 {
        SourceFactIdentityV2 {
            schema_version: 2,
            scope: AuthenticatedProjectScopeV1::from_trusted_context(
                ContractId::new("tenant.fixture").unwrap(),
                ContractId::new("project.fixture").unwrap(),
            ),
            provider_namespace: reference("namespace.github", 1),
            provider_instance_id: resource(
                IdentityForm::Entity,
                "provider_instance",
                "provider-instance",
            ),
            logical_event_key: HexBytes::new(b"push:123".to_vec()).unwrap(),
            provider_object_id: HexBytes::new(b"123".to_vec()).unwrap(),
            immutable_revision: HexBytes::new(b"sha256:abc".to_vec()).unwrap(),
            canonical_resource_id: resource(
                IdentityForm::Occurrence,
                "provider_event",
                "provider-event",
            ),
        }
    }

    fn origin_representation() -> RepresentationIdentityV2 {
        let source_fact_id = derive_source_fact_id_v2(&source_fact()).unwrap();
        RepresentationIdentityV2 {
            schema_version: 2,
            source_fact_id,
            registry_head: registry_head("activation-a"),
            connector_schema: resolved_connector().registry_reference().clone(),
            evidence_schema: reference("evidence.github.push", 2),
            canonicalization_profile: frozen_profile_reference_v1(),
            provider_instance_identity_recipe: reference("identity.github.provider_instance", 1),
            canonical_resource_identity_recipe: reference("identity.github.push", 2),
            redaction_policy: reference("redaction.default", 2),
            classifier_policy: reference("classifier.default", 2),
            retention_policy: reference("retention.default", 2),
            publication_policy: reference("publication.default", 2),
            integrity_state: IntegrityState::ProviderVerified,
            visibility_class: VisibilityClass::Private,
            retention_class: RetentionClass::Governed,
            publication_class: PublicationClass::Denied,
            erasure_scopes: vec![ErasureScopeReferenceV1 {
                kind: super::super::evidence::ErasureScopeKind::SourceFact,
                target_digest: source_fact_id.digest(),
            }],
            lineage: RepresentationLineageV2::Origin,
        }
    }

    fn statement_for(representation: &RepresentationIdentityV2) -> EvidenceStatementV2 {
        let source_fact = source_fact();
        let source_fact_id = derive_source_fact_id_v2(&source_fact).unwrap();
        let representation_key = derive_representation_key_v2(representation).unwrap();
        EvidenceStatementV2 {
            schema_version: 2,
            event_kind: ContractId::new(EVIDENCE_ACCEPTED_EVENT_KIND).unwrap(),
            profile: representation.canonicalization_profile.clone(),
            scope: source_fact.scope.clone(),
            registry_head: representation.registry_head.clone(),
            source_fact,
            source_fact_id,
            representation: representation.clone(),
            representation_key,
            provider_actor_id: None,
            occurred_at: CanonicalTimestamp::parse("2026-08-15T12:30:00.000000000Z").unwrap(),
            observed_at: CanonicalTimestamp::parse("2026-08-15T12:30:01.000000000Z").unwrap(),
            canonical_content: GovernedContentIdentityV1 {
                protection_domain_id: ContractId::new("project.fixture").unwrap(),
                media_type: ContractId::new("application.json").unwrap(),
                byte_length: CanonicalDecimal::parse("128").unwrap(),
                content_digest: digest(DigestDomain::Body, "payload-v2"),
            },
            integrity_state: representation.integrity_state,
            visibility_class: representation.visibility_class,
            classifier_policy: representation.classifier_policy.clone(),
            retention_class: representation.retention_class,
            retention_policy: representation.retention_policy.clone(),
            erasure_scopes: representation.erasure_scopes.clone(),
            publication_class: representation.publication_class,
            publication_policy: representation.publication_policy.clone(),
        }
    }

    fn origin_statement() -> EvidenceStatementV2 {
        statement_for(&origin_representation())
    }

    fn ingress_candidate(
        delivery: &[u8],
        received_at: &str,
        storage: &str,
    ) -> EvidenceIngressCandidateV2 {
        let source_fact = source_fact();
        EvidenceIngressCandidateV2 {
            schema_version: 2,
            scope: source_fact.scope.clone(),
            connector_schema: resolved_connector().registry_reference().clone(),
            source_fact,
            provider_actor_id: None,
            occurred_at: CanonicalTimestamp::parse("2026-08-15T12:30:00.000000000Z").unwrap(),
            observed_at: CanonicalTimestamp::parse("2026-08-15T12:30:01.000000000Z").unwrap(),
            authenticated_ingress_principal_id: ContractId::new("principal.collector").unwrap(),
            connector_instance_id: ContractId::new("connector.installation").unwrap(),
            provider_delivery_id: HexBytes::new(delivery.to_vec()).unwrap(),
            received_at: CanonicalTimestamp::parse(received_at).unwrap(),
            canonical_payload: IngressContentReferenceV1 {
                asserted_media_type: ContractId::new("application.json").unwrap(),
                byte_length: CanonicalDecimal::parse("128").unwrap(),
                content_digest: digest(DigestDomain::Body, "payload-v2"),
                storage_identity: digest(DigestDomain::Body, storage),
            },
            private_raw_artifact: None,
        }
    }

    fn head_successor_statement() -> EvidenceStatementV2 {
        let origin = origin_representation();
        let predecessor_representation_key = derive_representation_key_v2(&origin).unwrap();
        let mut successor = origin;
        // Package and policy return to the same values; the fresh activation ID
        // still changes identity and prevents A -> B -> A ambiguity.
        successor.registry_head = registry_head("activation-a-returned");
        successor.lineage = RepresentationLineageV2::Supersedes {
            predecessor_representation_key,
        };
        statement_for(&successor)
    }

    fn fixture_record(framed: &'static [u8]) -> &'static [u8] {
        let record = framed
            .strip_suffix(b"\n")
            .expect("fixture must end in exactly one LF");
        assert!(!record.ends_with(b"\n"));
        require_canonical(record).unwrap();
        record
    }

    fn raw_sha256(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    #[test]
    fn authoritative_artifacts_and_hard_coded_digests_are_frozen() {
        let connector_framed = include_bytes!(
            "../../contracts/dynamic-memory/v2/evidence/connector-schema-v2-entry.jsonl"
        );
        let source_framed =
            include_bytes!("../../contracts/dynamic-memory/v2/evidence/source-fact-v2.jsonl");
        let representation_framed = include_bytes!(
            "../../contracts/dynamic-memory/v2/evidence/representation-origin-v2.jsonl"
        );
        let successor_framed = include_bytes!(
            "../../contracts/dynamic-memory/v2/evidence/representation-supersedes-v2.jsonl"
        );
        let statement_framed = include_bytes!(
            "../../contracts/dynamic-memory/v2/evidence/evidence-statement-v2.jsonl"
        );
        let vector_suite_framed =
            include_bytes!("../../contracts/dynamic-memory/v2/evidence/vector-suite.jsonl");
        for (framed, expected) in [
            (connector_framed.as_slice(), EXPECTED_CONNECTOR_RAW_SHA256),
            (source_framed.as_slice(), EXPECTED_SOURCE_RAW_SHA256),
            (
                representation_framed.as_slice(),
                EXPECTED_REPRESENTATION_RAW_SHA256,
            ),
            (successor_framed.as_slice(), EXPECTED_SUCCESSOR_RAW_SHA256),
            (statement_framed.as_slice(), EXPECTED_STATEMENT_RAW_SHA256),
            (
                vector_suite_framed.as_slice(),
                EXPECTED_VECTOR_SUITE_RAW_SHA256,
            ),
        ] {
            assert_eq!(raw_sha256(framed), expected);
        }
        let connector_bytes = fixture_record(connector_framed);
        let source_bytes = fixture_record(source_framed);
        let representation_bytes = fixture_record(representation_framed);
        let successor_bytes = fixture_record(successor_framed);
        let statement_bytes = fixture_record(statement_framed);
        let vector_suite_bytes = fixture_record(vector_suite_framed);

        assert_eq!(
            encode_canonical(&connector_entry()).unwrap(),
            connector_bytes
        );
        assert_eq!(encode_canonical(&source_fact()).unwrap(), source_bytes);
        assert_eq!(
            encode_canonical(&origin_representation()).unwrap(),
            representation_bytes
        );
        assert_eq!(
            encode_canonical(&head_successor_statement().representation).unwrap(),
            successor_bytes
        );
        assert_eq!(
            encode_canonical(&origin_statement()).unwrap(),
            statement_bytes
        );

        let source = derive_source_fact_id_v2(&source_fact()).unwrap();
        let representation = derive_representation_key_v2(&origin_representation()).unwrap();
        let event = origin_statement().accepted_event_id().unwrap();
        let partition = origin_statement()
            .consistency_partition_key(&resolved_connector())
            .unwrap();
        let successor = head_successor_statement();
        assert_eq!(source.to_string(), EXPECTED_SOURCE_FACT_ID);
        assert_eq!(representation.to_string(), EXPECTED_REPRESENTATION_KEY);
        assert_eq!(event.to_string(), EXPECTED_EVENT_ID);
        assert_eq!(partition.family.as_str(), "source_fact");
        assert_eq!(partition.key_digest.to_string(), EXPECTED_SOURCE_FACT_ID);
        assert_eq!(
            connector_entry().digest().unwrap().to_string(),
            EXPECTED_CONNECTOR_ENTRY_DIGEST
        );
        assert_eq!(
            successor.representation_key.to_string(),
            EXPECTED_SUCCESSOR_KEY
        );
        assert_eq!(
            successor.accepted_event_id().unwrap().to_string(),
            EXPECTED_SUCCESSOR_EVENT_ID
        );
        assert_eq!(
            domain_separated_digest(DigestDomain::TestVectorManifest, vector_suite_bytes)
                .to_string(),
            EXPECTED_VECTOR_SUITE_DIGEST
        );
    }

    #[test]
    fn authoritative_negative_connector_records_fail_closed() {
        for (framed, expected_raw_sha256) in [
            (
                include_bytes!(
                    "../../contracts/dynamic-memory/v2/evidence/negative-connector-family.jsonl"
                )
                .as_slice(),
                EXPECTED_BAD_FAMILY_RAW_SHA256,
            ),
            (
                include_bytes!(
                    "../../contracts/dynamic-memory/v2/evidence/negative-connector-derivation.jsonl"
                )
                .as_slice(),
                EXPECTED_BAD_DERIVATION_RAW_SHA256,
            ),
        ] {
            assert_eq!(raw_sha256(framed), expected_raw_sha256);
            let record = fixture_record(framed);
            assert!(decode_strict::<ConnectorSchemaV2>(record).is_err());
        }
    }

    #[test]
    fn connector_entry_closes_over_frozen_source_fact_recipe() {
        let resolved = resolved_connector();
        assert_eq!(resolved.schema(), &connector_schema());
        assert_ne!(
            resolved.schema().provider_instance_identity_recipe,
            resolved.schema().canonical_resource_identity_recipe,
            "the Git push fixture uses distinct recipes for its two resource kinds"
        );
        let statement = origin_statement();
        statement
            .validate_against_structural_connector(&resolved)
            .unwrap();
        let key = statement.consistency_partition_key(&resolved).unwrap();
        assert_eq!(key.family.as_str(), "source_fact");
        assert_eq!(key.key_digest, statement.source_fact_id.digest());
        let statement_bytes = encode_canonical(&statement).unwrap();
        for forbidden_field in [
            b"\"family\":".as_slice(),
            b"\"key_digest\":".as_slice(),
            b"\"epoch_id\":".as_slice(),
            b"\"shard\":".as_slice(),
            b"\"committed_offset\":".as_slice(),
        ] {
            assert!(
                !statement_bytes
                    .windows(forbidden_field.len())
                    .any(|window| window == forbidden_field),
                "physical/logical append field entered the semantic preimage"
            );
        }
    }

    #[test]
    fn source_fact_requires_an_entity_provider_instance_without_freezing_its_kind() {
        let source = source_fact();
        source.validate().unwrap();
        assert_eq!(
            source.provider_instance_id.identity_form(),
            IdentityForm::Entity
        );
        assert_eq!(
            source.provider_instance_id.resource_kind().as_str(),
            "provider_instance"
        );

        let mut occurrence = source.clone();
        occurrence.provider_instance_id = resource(
            IdentityForm::Occurrence,
            "provider_instance",
            "provider-instance",
        );
        assert!(occurrence.validate().is_err());

        let mut provider_specific_kind = source;
        provider_specific_kind.provider_instance_id = resource(
            IdentityForm::Entity,
            "installation",
            "provider-installation",
        );
        provider_specific_kind.validate().unwrap();
    }

    #[test]
    fn statement_copies_both_exact_connector_identity_recipes() {
        let connector = resolved_connector();
        let origin = origin_statement();
        origin
            .validate_against_structural_connector(&connector)
            .unwrap();

        for role in ["provider_instance", "canonical_resource"] {
            let mut mismatched = origin.clone();
            match role {
                "provider_instance" => {
                    mismatched.representation.provider_instance_identity_recipe =
                        reference("identity.github.provider_instance", 2);
                }
                "canonical_resource" => {
                    mismatched.representation.canonical_resource_identity_recipe =
                        reference("identity.github.push", 3);
                }
                _ => unreachable!(),
            }
            mismatched.representation_key =
                derive_representation_key_v2(&mismatched.representation).unwrap();
            assert_eq!(mismatched.source_fact_id, origin.source_fact_id);
            assert_ne!(mismatched.representation_key, origin.representation_key);
            assert_ne!(
                mismatched.accepted_event_id().unwrap(),
                origin.accepted_event_id().unwrap()
            );
            assert_eq!(
                mismatched.validate_against_structural_connector(&connector),
                Err(ContractError::ManifestMismatch),
                "accepted a mismatched {role} identity recipe"
            );
        }
    }

    #[test]
    fn one_recipe_may_fill_both_explicit_roles_for_the_same_resource() {
        let shared_recipe = reference("identity.github.provider_instance", 1);
        let mut connector = connector_schema();
        connector.provider_instance_identity_recipe = shared_recipe.clone();
        connector.canonical_resource_identity_recipe = shared_recipe.clone();
        connector.validate().unwrap();

        let mut source = source_fact();
        source.canonical_resource_id = source.provider_instance_id.clone();
        let source_fact_id = derive_source_fact_id_v2(&source).unwrap();

        let mut representation = origin_representation();
        representation.source_fact_id = source_fact_id;
        representation.provider_instance_identity_recipe = shared_recipe.clone();
        representation.canonical_resource_identity_recipe = shared_recipe;
        representation.erasure_scopes = vec![ErasureScopeReferenceV1 {
            kind: super::super::evidence::ErasureScopeKind::SourceFact,
            target_digest: source_fact_id.digest(),
        }];
        representation.validate().unwrap();
    }

    #[test]
    fn delivery_only_retry_has_one_semantic_event() {
        let first = ingress_candidate(b"delivery-1", "2026-08-15T12:30:02.000000000Z", "storage-a");
        let second =
            ingress_candidate(b"delivery-2", "2026-08-15T12:30:03.000000000Z", "storage-b");
        first
            .validate_against_structural_connector(&resolved_connector())
            .unwrap();
        second
            .validate_against_structural_connector(&resolved_connector())
            .unwrap();
        assert_ne!(
            encode_canonical(&first).unwrap(),
            encode_canonical(&second).unwrap()
        );
        assert_eq!(first.source_fact, second.source_fact);
        assert_eq!(
            first.canonical_payload.content_digest,
            second.canonical_payload.content_digest
        );
        let first_statement = origin_statement();
        let second_statement = origin_statement();
        assert_eq!(
            first_statement.accepted_event_id().unwrap(),
            second_statement.accepted_event_id().unwrap()
        );
        assert_eq!(
            replay_disposition_v2(&first_statement, &second_statement).unwrap(),
            ReplayDispositionV2::ExactReplay
        );
    }

    #[test]
    fn registry_aba_and_non_recipe_representation_changes_mint_successors() {
        let origin = origin_statement();
        let aba = head_successor_statement();
        assert_ne!(origin.representation_key, aba.representation_key);
        assert_ne!(
            origin.accepted_event_id().unwrap(),
            aba.accepted_event_id().unwrap()
        );
        assert_eq!(
            replay_disposition_v2(&origin, &aba).unwrap(),
            ReplayDispositionV2::NewRepresentation
        );

        let mut policy = origin.representation.clone();
        policy.retention_policy = reference("retention.default", 3);
        let mut profile = origin.representation.clone();
        profile.canonicalization_profile.profile_digest =
            digest(DigestDomain::CanonicalProfile, "profile-v2-successor");
        let mut integrity = origin.representation.clone();
        integrity.integrity_state = IntegrityState::SignatureVerified;
        let cases = [
            (
                "policy",
                policy,
                EXPECTED_POLICY_KEY,
                EXPECTED_POLICY_EVENT_ID,
            ),
            (
                "profile",
                profile,
                EXPECTED_PROFILE_KEY,
                EXPECTED_PROFILE_EVENT_ID,
            ),
            (
                "integrity",
                integrity,
                EXPECTED_INTEGRITY_KEY,
                EXPECTED_INTEGRITY_EVENT_ID,
            ),
        ];
        for (label, mut representation, expected_key, expected_event) in cases {
            representation.lineage = RepresentationLineageV2::Supersedes {
                predecessor_representation_key: origin.representation_key,
            };
            let successor = statement_for(&representation);
            assert_eq!(origin.source_fact_id, successor.source_fact_id, "{label}");
            assert_ne!(
                origin.representation_key, successor.representation_key,
                "{label}"
            );
            assert_ne!(
                origin.accepted_event_id().unwrap(),
                successor.accepted_event_id().unwrap(),
                "{label}"
            );
            assert_eq!(
                replay_disposition_v2(&origin, &successor).unwrap(),
                ReplayDispositionV2::NewRepresentation,
                "{label}"
            );
            assert_eq!(
                successor.representation_key.to_string(),
                expected_key,
                "{label}"
            );
            assert_eq!(
                successor.accepted_event_id().unwrap().to_string(),
                expected_event,
                "{label}"
            );
        }
    }

    #[test]
    fn structural_head_and_lineage_mismatches_fail_closed() {
        let mut mismatched = origin_statement();
        mismatched.registry_head = registry_head("different-statement-head");
        assert!(mismatched.validate_shape().is_err());

        for zero_field in ["activation", "package", "policy"] {
            let mut zero = registry_head("nonzero-head");
            match zero_field {
                "activation" => zero.head.activation_id = Sha256Digest::ZERO,
                "package" => zero.head.package_digest = Sha256Digest::ZERO,
                "policy" => zero.head.activation_policy_digest = Sha256Digest::ZERO,
                _ => unreachable!(),
            }
            assert!(zero.validate_shape().is_err(), "accepted zero {zero_field}");
        }

        let mut unlinked = origin_representation();
        unlinked.retention_policy = reference("retention.default", 3);
        let unlinked = statement_for(&unlinked);
        assert!(replay_disposition_v2(&origin_statement(), &unlinked).is_err());

        let mut wrong_predecessor = origin_representation();
        wrong_predecessor.retention_policy = reference("retention.default", 3);
        wrong_predecessor.lineage = RepresentationLineageV2::Supersedes {
            predecessor_representation_key: RepresentationKeyV2::from_digest(Sha256Digest::ZERO),
        };
        assert!(derive_representation_key_v2(&wrong_predecessor).is_err());
    }

    #[test]
    fn representation_reservation_collides_but_source_coordinates_partition_identity() {
        let origin = origin_statement();

        for semantic_change in ["content", "actor", "clock"] {
            let mut collision = origin.clone();
            match semantic_change {
                "content" => {
                    collision.canonical_content.content_digest =
                        digest(DigestDomain::Body, "different-content");
                }
                "actor" => {
                    collision.provider_actor_id =
                        Some(HexBytes::new(b"different-actor".to_vec()).unwrap());
                }
                "clock" => {
                    collision.occurred_at =
                        CanonicalTimestamp::parse("2026-08-15T12:29:59.000000000Z").unwrap();
                }
                _ => unreachable!(),
            }
            collision.validate_shape().unwrap();
            assert_eq!(collision.representation_key, origin.representation_key);
            assert_eq!(
                replay_disposition_v2(&origin, &collision),
                Err(ContractError::RepresentationCollision),
                "{semantic_change}"
            );
        }

        let mut distinct = origin.clone();
        distinct.source_fact.logical_event_key = HexBytes::new(b"push:124".to_vec()).unwrap();
        distinct.source_fact_id = derive_source_fact_id_v2(&distinct.source_fact).unwrap();
        distinct.representation.source_fact_id = distinct.source_fact_id;
        let distinct_erasure = vec![ErasureScopeReferenceV1 {
            kind: super::super::evidence::ErasureScopeKind::SourceFact,
            target_digest: distinct.source_fact_id.digest(),
        }];
        distinct.representation.erasure_scopes = distinct_erasure.clone();
        distinct.representation.lineage = RepresentationLineageV2::Origin;
        distinct.representation_key =
            derive_representation_key_v2(&distinct.representation).unwrap();
        distinct.erasure_scopes = distinct_erasure;
        distinct.validate_shape().unwrap();
        assert_ne!(origin.source_fact_id, distinct.source_fact_id);
        assert_eq!(
            replay_disposition_v2(&origin, &distinct).unwrap(),
            ReplayDispositionV2::DistinctSourceFact
        );
    }

    #[test]
    fn bad_consistency_family_and_derivation_are_closed() {
        let canonical = encode_canonical(&connector_schema()).unwrap();
        let bad_family = String::from_utf8(canonical.clone())
            .unwrap()
            .replace("\"family\":\"source_fact\"", "\"family\":\"request\"");
        let bad_derivation = String::from_utf8(canonical).unwrap().replace(
            "\"key_derivation\":\"source_fact_id\"",
            "\"key_derivation\":\"delivery_id\"",
        );
        require_canonical(bad_family.as_bytes()).unwrap();
        require_canonical(bad_derivation.as_bytes()).unwrap();
        assert!(decode_strict::<ConnectorSchemaV2>(bad_family.as_bytes()).is_err());
        assert!(decode_strict::<ConnectorSchemaV2>(bad_derivation.as_bytes()).is_err());
    }

    #[test]
    fn inactive_structural_bytes_never_create_an_authority_typestate() {
        // This is the strongest claim available in this pure module: exact
        // entry/body closure plus internal candidate consistency.
        let structural = resolved_connector();
        let candidate =
            ingress_candidate(b"delivery-1", "2026-08-15T12:30:02.000000000Z", "storage-a");
        candidate
            .validate_against_structural_connector(&structural)
            .unwrap();
        // There is deliberately no `Verified`/`Active`/`Accepted` constructor
        // or return value here; repository authority remains a later seam.
    }

    #[test]
    #[ignore = "fixture generator; authoritative bytes are checked by non-ignored tests"]
    fn print_fixture_records() {
        let records = [
            (
                "connector-schema-v2-entry.jsonl",
                encode_canonical(&connector_entry()).unwrap(),
            ),
            (
                "source-fact-v2.jsonl",
                encode_canonical(&source_fact()).unwrap(),
            ),
            (
                "representation-origin-v2.jsonl",
                encode_canonical(&origin_representation()).unwrap(),
            ),
            (
                "evidence-statement-v2.jsonl",
                encode_canonical(&origin_statement()).unwrap(),
            ),
            (
                "representation-supersedes-v2.jsonl",
                encode_canonical(&head_successor_statement().representation).unwrap(),
            ),
            (
                "evidence-statement-supersedes-v2.jsonl",
                encode_canonical(&head_successor_statement()).unwrap(),
            ),
        ];
        for (name, bytes) in records {
            println!("FIXTURE {name} {}", String::from_utf8(bytes).unwrap());
        }
        let connector_bytes = encode_canonical(&connector_schema()).unwrap();
        let connector_json = String::from_utf8(connector_bytes).unwrap();
        println!(
            "FIXTURE negative-connector-family.jsonl {}",
            connector_json.replace("\"family\":\"source_fact\"", "\"family\":\"request\"")
        );
        println!(
            "FIXTURE negative-connector-derivation.jsonl {}",
            connector_json.replace(
                "\"key_derivation\":\"source_fact_id\"",
                "\"key_derivation\":\"delivery_id\""
            )
        );
        let origin = origin_statement();
        let successor = head_successor_statement();
        println!("SOURCE_FACT_ID {}", origin.source_fact_id);
        println!("REPRESENTATION_KEY {}", origin.representation_key);
        println!("EVENT_ID {}", origin.accepted_event_id().unwrap());
        println!(
            "CONNECTOR_ENTRY_DIGEST {}",
            connector_entry().digest().unwrap()
        );
        println!("SUCCESSOR_KEY {}", successor.representation_key);
        println!(
            "SUCCESSOR_EVENT_ID {}",
            successor.accepted_event_id().unwrap()
        );
        for (label, mut representation) in [
            ("policy", origin.representation.clone()),
            ("profile", origin.representation.clone()),
            ("integrity", origin.representation.clone()),
        ] {
            match label {
                "policy" => {
                    representation.retention_policy = reference("retention.default", 3);
                }
                "profile" => {
                    representation.canonicalization_profile.profile_digest =
                        digest(DigestDomain::CanonicalProfile, "profile-v2-successor");
                }
                "integrity" => {
                    representation.integrity_state = IntegrityState::SignatureVerified;
                }
                _ => unreachable!(),
            }
            representation.lineage = RepresentationLineageV2::Supersedes {
                predecessor_representation_key: origin.representation_key,
            };
            let changed = statement_for(&representation);
            println!(
                "CHANGE {label} {} {}",
                changed.representation_key,
                changed.accepted_event_id().unwrap()
            );
        }
    }
}
