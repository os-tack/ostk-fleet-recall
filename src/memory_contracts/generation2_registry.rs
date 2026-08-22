//! The generation-2 registry package: the one a running memory can actually
//! ingest under (W3-CHAIN).
//!
//! # Why this module exists
//!
//! The frozen generation-1 target package
//! ([`stage4_target_package`](super::stage4_target_package)) carries exactly one
//! connector schema, `connector.github.push`, and it names
//! `identity.github.push` as its canonical-resource identity recipe. That
//! recipe's identity form is `occurrence`. Every fact any connector admits under
//! generation 1 therefore names an *occurrence*-form canonical resource, and the
//! body plane refuses to chunk one, because an occurrence URI names no immutable
//! source-object version
//! ([`ChunkOccurrencePreimageV1`](super::chunk_identity::ChunkOccurrencePreimageV1)).
//! The dogfood run recorded the consequence exactly: 980 accepted events, 980
//! unprojectable, 0 bodies, 0 lexical rows, no recall.
//!
//! Generation 1 cannot be edited — its bytes and its digest *are* the contract
//! version. So the fix is a generation-2 package: this module carries every
//! generation-1 entry forward verbatim (same bytes, same entry digests) and
//! appends one closed identity chain per Wave-2 connector, ending in a
//! `version`-form canonical resource the body plane accepts.
//!
//! # Why generation 1's `identity.github.commit` could not simply be pointed at
//!
//! Generation 1 does contain a `version`-form recipe, `identity.github.commit`.
//! It is not derivable. A `version`-form locator must name a parent entity
//! ([`validate_locator`](super::identity::validate_locator)), the parent must be
//! derived under the *same* authority namespace as the child, and
//! [`ValidatedIdentityRecipe::from_package`](super::identity::ValidatedIdentityRecipe::from_package)
//! requires a namespace's `immutable_coordinate_keys` to equal its recipe's
//! component keys. So a version recipe and its entity parent must share a
//! namespace, and therefore must share their coordinate keys.
//! `identity.github.commit` lives in `namespace.github.commit` (key
//! `commit_oid`) and declares its parent kind as `repository`, whose only
//! generation-1 recipe lives in `namespace.github.repository` (key
//! `provider_repository_id`). No parent can be derived for it under any locator.
//! `generation_one_commit_recipe_has_no_derivable_parent` pins that finding.
//!
//! # The shape this module adds, and why it is honest
//!
//! For each connector, four entries form a closed pair of coordinates:
//!
//! * an `entity` resource kind + recipe keyed on `immutable_revision`;
//! * a `version` resource kind + recipe keyed on the same `immutable_revision`,
//!   whose parent kind is that entity.
//!
//! Entity and version share their single coordinate. That is not a shortcut, it
//! is what a content-addressed provider *is*: a git object id and a transcript
//! turn revision each name one immutable object, so "the object" and "that
//! object's immutable version" are the same coordinate seen at two identity
//! forms. The coordinate itself is not self-asserted — it is the source fact's
//! own `immutable_revision`, which the admission seam re-checks against the
//! candidate's published field before any URI is accepted (EVID-02).
//!
//! Nothing here activates anything. A package composed here is public bytes with
//! no authority: a repository must still run the full generation-1 to
//! generation-2 activation ceremony, and the resulting head must still be proven
//! by a witness before any connector may resolve a recipe out of it.

use super::{
    ContractError, ContractResult,
    canonical::{decode_strict, encode_canonical},
    common::{ContractId, RegistryReferenceV1},
    digest::Sha256Digest,
    evidence_v2::{ConnectorSchemaV2, StructurallyResolvedConnectorSchemaV2},
    identity::{
        AuthorityNamespaceV1, IdentityComponentRuleV1, IdentityForm, IdentityRecipeV1,
        LocatorEncoding, ResourceKindSchemaV1,
    },
    registry::{
        ManifestVerifiedRegistryPackage, RegistryEntryKind, RegistryEntryV1,
        RegistryManifestEntryV1, RegistryPackageV1,
    },
};

/// Entry-body schema version every v1 registry body uses.
const ENTRY_BODY_SCHEMA_VERSION: u32 = 1;
/// Registry-entry envelope schema version.
const ENTRY_SCHEMA_VERSION: u32 = 1;
/// Version every generation-2-only entry this module mints declares.
const GENERATION_TWO_ENTRY_VERSION: u32 = 1;
/// Connector schema v2 entry-body schema version.
const CONNECTOR_ENTRY_SCHEMA_VERSION: u32 = 2;

/// The one coordinate every generation-2 source-object recipe hashes.
///
/// It is the source fact's own immutable revision — the field admission binds
/// against the candidate's published value.
pub const SOURCE_OBJECT_COORDINATE: &str = "immutable_revision";

/// Generation-1 entry ids this composition carries forward and depends on.
const GEN1_PROVIDER_INSTANCE_RECIPE: &str = "identity.github.provider_instance";
const GEN1_PROVIDER_NAMESPACE: &str = "namespace.github.provider_instance";
const GEN1_CONNECTOR_SCHEMA: &str = "connector.github.push";
const GEN1_REDACTION_POLICY: &str = "redaction.default";
const GEN1_CLASSIFIER_POLICY: &str = "classifier.default";
const GEN1_RETENTION_POLICY: &str = "retention.default";
const GEN1_PUBLICATION_RULE: &str = "publication.default";
/// Generation-1's underivable version recipe, named only as the negative case.
pub const GEN1_COMMIT_RECIPE: &str = "identity.github.commit";

/// One connector's generation-2 identity chain, named so a caller resolves
/// exactly the connector it runs rather than "the" connector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Generation2ConnectorIds {
    /// Authority namespace both recipes live in.
    pub namespace: &'static str,
    /// `entity`-form resource kind schema.
    pub entity_kind: &'static str,
    /// `version`-form resource kind schema, parented by `entity_kind`.
    pub version_kind: &'static str,
    /// `entity`-form identity recipe.
    pub entity_recipe: &'static str,
    /// `version`-form identity recipe — the canonical-resource recipe.
    pub version_recipe: &'static str,
    /// Evidence schema naming `version_recipe`.
    pub evidence_schema: &'static str,
    /// Connector schema naming `version_recipe` as its canonical resource.
    pub connector_schema: &'static str,
    /// Evidence kind label the evidence schema declares.
    pub evidence_kind: &'static str,
}

/// The version-history (git) connector's generation-2 identity chain.
pub const GIT_CONNECTOR: Generation2ConnectorIds = Generation2ConnectorIds {
    namespace: "namespace.git.source_object",
    entity_kind: "git_source_object",
    version_kind: "git_source_object_version",
    entity_recipe: "identity.git.source_object",
    version_recipe: "identity.git.source_object_version",
    evidence_schema: "evidence.git.source_object",
    connector_schema: "connector.git.history",
    evidence_kind: "git.source_object",
};

/// The transcript connector's generation-2 identity chain.
pub const TRANSCRIPT_CONNECTOR: Generation2ConnectorIds = Generation2ConnectorIds {
    namespace: "namespace.transcript.turn",
    entity_kind: "transcript_turn",
    version_kind: "transcript_turn_version",
    entity_recipe: "identity.transcript.turn",
    version_recipe: "identity.transcript.turn_version",
    evidence_schema: "evidence.transcript.turn",
    connector_schema: "connector.transcript.session",
    evidence_kind: "transcript.turn",
};

/// Both connector chains, in the order they are appended.
pub const GENERATION_TWO_CONNECTORS: [Generation2ConnectorIds; 2] =
    [GIT_CONNECTOR, TRANSCRIPT_CONNECTOR];

fn missing(entry_id: &str) -> ContractError {
    ContractError::Schema(format!(
        "generation-1 package does not carry the entry {entry_id}"
    ))
}

fn find_entry<'package>(
    package: &'package RegistryPackageV1,
    entry_id: &str,
) -> ContractResult<&'package RegistryEntryV1> {
    package
        .entries
        .iter()
        .find(|entry| entry.entry_id.as_str() == entry_id)
        .ok_or_else(|| missing(entry_id))
}

/// Exact reference (id, version, digest) of one carried-forward entry.
fn reference_to(
    package: &RegistryPackageV1,
    entry_id: &str,
) -> ContractResult<RegistryReferenceV1> {
    reference_for(find_entry(package, entry_id)?)
}

fn reference_for(entry: &RegistryEntryV1) -> ContractResult<RegistryReferenceV1> {
    Ok(RegistryReferenceV1 {
        entry_id: entry.entry_id.clone(),
        version: entry.version,
        entry_digest: entry.digest()?,
    })
}

/// Build one registry entry from a typed body, reusing the vector digests of a
/// carried-forward sibling.
fn mint_entry<Body: serde::Serialize>(
    kind: RegistryEntryKind,
    entry_id: &str,
    entry_schema_id: &str,
    entry_schema_version: u32,
    body: &Body,
    vectors: (Sha256Digest, Sha256Digest),
) -> ContractResult<RegistryEntryV1> {
    let entry = RegistryEntryV1 {
        schema_version: ENTRY_SCHEMA_VERSION,
        kind,
        entry_id: ContractId::new(entry_id)?,
        version: GENERATION_TWO_ENTRY_VERSION,
        entry_schema_id: ContractId::new(entry_schema_id)?,
        entry_schema_version,
        body: decode_strict(&encode_canonical(body)?)?,
        positive_vector_digest: vectors.0,
        negative_vector_digest: vectors.1,
    };
    entry.validate()?;
    Ok(entry)
}

/// The carried-forward references one generation-2 connector chain binds.
struct CarryForward {
    provider_instance_recipe: RegistryReferenceV1,
    provider_namespace: RegistryReferenceV1,
    redaction_policy: RegistryReferenceV1,
    classifier_policy: RegistryReferenceV1,
    retention_policy: RegistryReferenceV1,
    publication_rule: RegistryReferenceV1,
    consistency_partition_recipe: super::evidence_v2::ConsistencyPartitionRecipeV1,
    vectors: (Sha256Digest, Sha256Digest),
}

impl CarryForward {
    fn resolve(source: &RegistryPackageV1) -> ContractResult<Self> {
        let sibling = source
            .entries
            .iter()
            .find(|entry| entry.kind == RegistryEntryKind::IdentityRecipe)
            .ok_or(ContractError::ManifestMismatch)?;
        // The consistency partition recipe is registry-controlled, never
        // selected by an ingress payload, so generation 2 keeps generation 1's
        // exactly rather than minting a second one.
        let connector: ConnectorSchemaV2 = decode_strict(&encode_canonical(
            &find_entry(source, GEN1_CONNECTOR_SCHEMA)?.body,
        )?)?;
        Ok(Self {
            provider_instance_recipe: reference_to(source, GEN1_PROVIDER_INSTANCE_RECIPE)?,
            provider_namespace: reference_to(source, GEN1_PROVIDER_NAMESPACE)?,
            redaction_policy: reference_to(source, GEN1_REDACTION_POLICY)?,
            classifier_policy: reference_to(source, GEN1_CLASSIFIER_POLICY)?,
            retention_policy: reference_to(source, GEN1_RETENTION_POLICY)?,
            publication_rule: reference_to(source, GEN1_PUBLICATION_RULE)?,
            consistency_partition_recipe: connector.consistency_partition_recipe,
            vectors: (
                sibling.positive_vector_digest,
                sibling.negative_vector_digest,
            ),
        })
    }
}

/// Mint the seven entries that close one connector's generation-2 identity
/// chain.
// One linear composition of seven registry entries; the length is the entry
// count, not branching.
#[allow(clippy::too_many_lines)]
fn connector_chain(
    connector: Generation2ConnectorIds,
    carry: &CarryForward,
) -> ContractResult<Vec<RegistryEntryV1>> {
    let component_rules = vec![IdentityComponentRuleV1 {
        key: ContractId::new(SOURCE_OBJECT_COORDINATE)?,
        encoding: LocatorEncoding::HexBytes,
    }];
    let vectors = carry.vectors;

    let namespace_entry = mint_entry(
        RegistryEntryKind::NamespaceDefinition,
        connector.namespace,
        "registry.namespace_definition",
        ENTRY_BODY_SCHEMA_VERSION,
        &AuthorityNamespaceV1 {
            schema_version: ENTRY_BODY_SCHEMA_VERSION,
            namespace_id: ContractId::new(connector.namespace)?,
            version: GENERATION_TWO_ENTRY_VERSION,
            immutable_coordinate_keys: vec![ContractId::new(SOURCE_OBJECT_COORDINATE)?],
        },
        vectors,
    )?;
    let namespace_reference = reference_for(&namespace_entry)?;

    let entity_kind_entry = mint_entry(
        RegistryEntryKind::ResourceKindSchema,
        connector.entity_kind,
        "registry.resource_kind_schema",
        ENTRY_BODY_SCHEMA_VERSION,
        &ResourceKindSchemaV1 {
            schema_version: ENTRY_BODY_SCHEMA_VERSION,
            resource_kind: ContractId::new(connector.entity_kind)?,
            version: GENERATION_TWO_ENTRY_VERSION,
            identity_form: IdentityForm::Entity,
            parent_entity_kind: None,
            component_rules: component_rules.clone(),
        },
        vectors,
    )?;
    let entity_kind_reference = reference_for(&entity_kind_entry)?;

    let version_kind_entry = mint_entry(
        RegistryEntryKind::ResourceKindSchema,
        connector.version_kind,
        "registry.resource_kind_schema",
        ENTRY_BODY_SCHEMA_VERSION,
        &ResourceKindSchemaV1 {
            schema_version: ENTRY_BODY_SCHEMA_VERSION,
            resource_kind: ContractId::new(connector.version_kind)?,
            version: GENERATION_TWO_ENTRY_VERSION,
            identity_form: IdentityForm::Version,
            parent_entity_kind: Some(entity_kind_reference.clone()),
            component_rules: component_rules.clone(),
        },
        vectors,
    )?;
    let version_kind_reference = reference_for(&version_kind_entry)?;

    let entity_recipe_entry = mint_entry(
        RegistryEntryKind::IdentityRecipe,
        connector.entity_recipe,
        "registry.identity_recipe",
        ENTRY_BODY_SCHEMA_VERSION,
        &IdentityRecipeV1 {
            schema_version: ENTRY_BODY_SCHEMA_VERSION,
            recipe_id: ContractId::new(connector.entity_recipe)?,
            version: GENERATION_TWO_ENTRY_VERSION,
            resource_kind: ContractId::new(connector.entity_kind)?,
            identity_form: IdentityForm::Entity,
            authority_namespace: namespace_reference.clone(),
            resource_kind_schema: entity_kind_reference,
            component_rules: component_rules.clone(),
        },
        vectors,
    )?;

    let version_recipe_entry = mint_entry(
        RegistryEntryKind::IdentityRecipe,
        connector.version_recipe,
        "registry.identity_recipe",
        ENTRY_BODY_SCHEMA_VERSION,
        &IdentityRecipeV1 {
            schema_version: ENTRY_BODY_SCHEMA_VERSION,
            recipe_id: ContractId::new(connector.version_recipe)?,
            version: GENERATION_TWO_ENTRY_VERSION,
            resource_kind: ContractId::new(connector.version_kind)?,
            identity_form: IdentityForm::Version,
            authority_namespace: namespace_reference,
            resource_kind_schema: version_kind_reference,
            component_rules,
        },
        vectors,
    )?;
    let version_recipe_reference = reference_for(&version_recipe_entry)?;

    let evidence_entry = mint_entry(
        RegistryEntryKind::EvidenceSchema,
        connector.evidence_schema,
        "registry.evidence_schema",
        ENTRY_BODY_SCHEMA_VERSION,
        &EvidenceSchemaBodyV1 {
            schema_version: ENTRY_BODY_SCHEMA_VERSION,
            evidence_schema_id: ContractId::new(connector.evidence_schema)?,
            version: GENERATION_TWO_ENTRY_VERSION,
            evidence_kind: ContractId::new(connector.evidence_kind)?,
            identity_recipe: version_recipe_reference.clone(),
            redaction_policy: carry.redaction_policy.clone(),
            classifier_policy: carry.classifier_policy.clone(),
            retention_policy: carry.retention_policy.clone(),
            publication_rule: carry.publication_rule.clone(),
            canonical_payload_required: true,
            private_raw_default_enabled: false,
        },
        vectors,
    )?;
    let evidence_reference = reference_for(&evidence_entry)?;

    let connector_entry = mint_entry(
        RegistryEntryKind::ConnectorSchema,
        connector.connector_schema,
        "registry.connector_schema",
        CONNECTOR_ENTRY_SCHEMA_VERSION,
        &ConnectorSchemaV2 {
            schema_version: CONNECTOR_ENTRY_SCHEMA_VERSION,
            connector_schema_id: ContractId::new(connector.connector_schema)?,
            version: GENERATION_TWO_ENTRY_VERSION,
            provider_namespace: carry.provider_namespace.clone(),
            evidence_schema: evidence_reference,
            provider_instance_identity_recipe: carry.provider_instance_recipe.clone(),
            canonical_resource_identity_recipe: version_recipe_reference,
            consistency_partition_recipe: carry.consistency_partition_recipe.clone(),
            authenticated_scope_required: true,
            delivery_id_in_semantic_identity: false,
            immutable_revision_required: true,
        },
        vectors,
    )?;

    Ok(vec![
        namespace_entry,
        entity_kind_entry,
        version_kind_entry,
        entity_recipe_entry,
        version_recipe_entry,
        evidence_entry,
        connector_entry,
    ])
}

/// Compose the generation-2 registry package from the generation-1 package.
///
/// Every generation-1 entry is carried forward byte for byte, so every
/// generation-1 entry digest — and therefore every reference already frozen in
/// the wild — still resolves. The package digest necessarily differs, which is
/// exactly what makes this a new generation rather than an edit.
///
/// Fails closed when generation 1 does not carry an entry this composition
/// depends on, or when the composed package does not pass full package
/// validation.
pub fn generation_two_registry_package(
    generation_one: &ManifestVerifiedRegistryPackage,
) -> ContractResult<ManifestVerifiedRegistryPackage> {
    let source = generation_one.package();
    let carry = CarryForward::resolve(source)?;

    let mut entries = source.entries.clone();
    for connector in GENERATION_TWO_CONNECTORS {
        entries.extend(connector_chain(connector, &carry)?);
    }

    entries.sort_by(|left, right| {
        (left.kind.as_str(), left.entry_id.as_str(), left.version).cmp(&(
            right.kind.as_str(),
            right.entry_id.as_str(),
            right.version,
        ))
    });
    let mut manifest = Vec::with_capacity(entries.len());
    for entry in &entries {
        manifest.push(RegistryManifestEntryV1 {
            kind: entry.kind,
            entry_id: entry.entry_id.clone(),
            version: entry.version,
            entry_digest: entry.digest()?,
        });
    }

    let package = RegistryPackageV1 {
        schema_version: source.schema_version,
        profile: source.profile.clone(),
        entries,
        manifest,
        positive_vector_suite_digest: source.positive_vector_suite_digest,
        negative_vector_suite_digest: source.negative_vector_suite_digest,
    };
    let profile = package.profile.clone();
    ManifestVerifiedRegistryPackage::new(package, &profile)
}

/// Resolve one generation-2 connector schema out of a composed package.
///
/// Structural resolution only: membership in *this* package, not authority. A
/// runtime must still prove the package is the activated head's package.
pub fn resolve_connector_schema(
    package: &ManifestVerifiedRegistryPackage,
    connector_schema_id: &str,
) -> ContractResult<StructurallyResolvedConnectorSchemaV2> {
    let entry = package
        .package()
        .entries
        .iter()
        .find(|entry| {
            entry.kind == RegistryEntryKind::ConnectorSchema
                && entry.entry_id.as_str() == connector_schema_id
        })
        .ok_or_else(|| {
            ContractError::Schema(format!(
                "package does not carry the connector schema {connector_schema_id}"
            ))
        })?;
    StructurallyResolvedConnectorSchemaV2::from_registry_entry(entry)
}

/// Local mirror of the registry's evidence-schema body.
///
/// [`EvidenceSchemaEntryV1`](super::genesis::EvidenceSchemaEntryV1) has private
/// fields — it is a decode target, never a producer — so composition declares
/// the same canonical shape here. The `deny_unknown_fields` decode inside
/// package closure is what proves the two agree: drift in either direction fails
/// closure rather than producing an entry the runtime silently misreads.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceSchemaBodyV1 {
    schema_version: u32,
    evidence_schema_id: ContractId,
    version: u32,
    evidence_kind: ContractId,
    identity_recipe: RegistryReferenceV1,
    redaction_policy: RegistryReferenceV1,
    classifier_policy: RegistryReferenceV1,
    retention_policy: RegistryReferenceV1,
    publication_rule: RegistryReferenceV1,
    canonical_payload_required: bool,
    private_raw_default_enabled: bool,
}

#[cfg(test)]
#[path = "generation2_registry_tests.rs"]
mod tests;
