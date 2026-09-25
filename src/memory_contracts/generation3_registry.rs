//! The generation-3 registry package: generation 2 carried forward byte for
//! byte, plus one generic, provider-parameterized collected-item family
//! (ADR 0008 D1).
//!
//! # Why a generation, and why only one
//!
//! Generation 2 admits exactly three connectors (git history, transcript
//! sessions, CI runs), and its digest is frozen: installed heads name it, so it
//! can never gain a fourth. A collected item — a Slack message, a Linear issue,
//! a Granola note, a document from a directory, anything a collector turns into
//! the generic envelope — needs connector schemas the active package carries,
//! so it needs a new package.
//!
//! This family is deliberately generic. The provider (`slack`, `linear`,
//! `docs`, ...) and the provider's own scope (a Slack team, a Linear
//! organization, a documents root) are *locator components* of one
//! provider-scope entity, not registry entries. Adding a provider later is a
//! collector module and configuration, never a generation 4. What the registry
//! does distinguish is the trust channel an item arrived through, because that
//! is a governance fact rather than data: one connector schema per channel,
//! `connector.collected.{pull,push,capture,import}`.
//!
//! # The shape
//!
//! * A **provider-scope chain** in its own namespace, keyed on
//!   `[provider_kind, provider_scope_id]` (both NFC UTF-8): the entity every
//!   collected connector names as its provider instance.
//! * An **item chain** in the generation-2 pattern: an `entity` kind and recipe
//!   plus a `version` kind and recipe, both keyed on the single hex coordinate
//!   `immutable_revision`. The entity is honestly named
//!   `collected_item_revision`: a mutable item has one immutable revision per
//!   (version, part, channel), and continuity across revisions comes from the
//!   item key the envelope carries, not from a continuing-entity URI.
//! * One evidence schema, `evidence.collected.item`, naming the version recipe
//!   and the four carried-forward governance policies.
//! * Four connector schemas that differ only in their id.
//!
//! Every generation-2 entry is carried forward verbatim, so every entry digest
//! already frozen in the wild — the git, transcript, and CI chains, the
//! remember route, the governance policies — still resolves. The package digest
//! necessarily differs, which is what makes this a generation rather than an
//! edit. Nothing here activates anything: a scope must still run the `2 -> 3`
//! activation ceremony (`ostk-authority-install apply --target generation-3`).
//!
//! The authoritative bytes are checked in at
//! `contracts/dynamic-memory/v3/collected-items/registry-package.jsonl`; the
//! registry witness compiles those bytes in, and a test proves this
//! composition reproduces them.

use super::{
    ContractResult,
    canonical::{decode_strict, encode_canonical},
    common::{ContractId, RegistryReferenceV1},
    digest::Sha256Digest,
    evidence_v2::{ConnectorSchemaV2, ConsistencyPartitionRecipeV1},
    generation2_registry::{
        CONNECTOR_ENTRY_SCHEMA_VERSION, ENTRY_BODY_SCHEMA_VERSION, EvidenceSchemaBodyV1,
        GEN1_CLASSIFIER_POLICY, GEN1_CONNECTOR_SCHEMA, GEN1_PUBLICATION_RULE,
        GEN1_REDACTION_POLICY, GEN1_RETENTION_POLICY, GENERATION_TWO_ENTRY_VERSION, GIT_CONNECTOR,
        SOURCE_OBJECT_COORDINATE, assemble_package, find_entry, mint_entry, reference_for,
        reference_to,
    },
    identity::{
        AuthorityNamespaceV1, IdentityComponentRuleV1, IdentityForm, IdentityRecipeV1,
        LocatorEncoding, ResourceKindSchemaV1,
    },
    registry::{ManifestVerifiedRegistryPackage, RegistryEntryKind, RegistryEntryV1},
};

/// Provider-scope coordinate: the provider kind (`slack`, `linear`, `docs`,
/// ...), lowercase ASCII.
pub const PROVIDER_KIND_COORDINATE: &str = "provider_kind";

/// Provider-scope coordinate: the operator-pinned scope inside the provider (a
/// Slack `team_id`, a Linear organization UUID, a documents `root_id`).
pub const PROVIDER_SCOPE_ID_COORDINATE: &str = "provider_scope_id";

/// The collected-item family's registry ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CollectedItemFamilyIds {
    /// Namespace of the provider-scope entity, keyed on
    /// `[provider_kind, provider_scope_id]`.
    pub provider_scope_namespace: &'static str,
    /// `entity`-form resource kind of a provider scope.
    pub provider_scope_kind: &'static str,
    /// `entity`-form recipe every collected connector names as its provider
    /// instance recipe.
    pub provider_scope_recipe: &'static str,
    /// Namespace both item recipes live in, keyed on `immutable_revision`.
    pub item_namespace: &'static str,
    /// `entity`-form resource kind of one immutable item revision.
    pub item_revision_kind: &'static str,
    /// `version`-form resource kind, parented by `item_revision_kind`.
    pub item_version_kind: &'static str,
    /// `entity`-form item recipe.
    pub item_revision_recipe: &'static str,
    /// `version`-form item recipe — the canonical-resource recipe.
    pub item_version_recipe: &'static str,
    /// Evidence schema naming `item_version_recipe`.
    pub evidence_schema: &'static str,
    /// Evidence kind label the evidence schema declares.
    pub evidence_kind: &'static str,
    /// Items a worker pulled from the provider's API (verified).
    pub pull_connector: &'static str,
    /// Items a signed provider notification caused (verified).
    pub push_connector: &'static str,
    /// Items an agent relayed from its own connectors (reported).
    pub capture_connector: &'static str,
    /// Items an operator imported from an export or a file (reported).
    pub import_connector: &'static str,
}

impl CollectedItemFamilyIds {
    /// The four connector schemas, one per trust channel, in the order they
    /// are minted.
    #[must_use]
    pub const fn connectors(&self) -> [&'static str; 4] {
        [
            self.pull_connector,
            self.push_connector,
            self.capture_connector,
            self.import_connector,
        ]
    }
}

/// The one collected-item family generation 3 adds.
pub const COLLECTED_ITEM_FAMILY: CollectedItemFamilyIds = CollectedItemFamilyIds {
    provider_scope_namespace: "namespace.collected.provider_scope",
    provider_scope_kind: "collected_provider_scope",
    provider_scope_recipe: "identity.collected.provider_scope",
    item_namespace: "namespace.collected.item",
    item_revision_kind: "collected_item_revision",
    item_version_kind: "collected_item_version",
    item_revision_recipe: "identity.collected.item_revision",
    item_version_recipe: "identity.collected.item_version",
    evidence_schema: "evidence.collected.item",
    evidence_kind: "collected.item",
    pull_connector: "connector.collected.pull",
    push_connector: "connector.collected.push",
    capture_connector: "connector.collected.capture",
    import_connector: "connector.collected.import",
};

/// The generation-2 references the collected-item family binds, resolved by
/// id out of the generation-2 package.
struct CarriedForGenerationThree {
    redaction_policy: RegistryReferenceV1,
    classifier_policy: RegistryReferenceV1,
    retention_policy: RegistryReferenceV1,
    publication_rule: RegistryReferenceV1,
    consistency_partition_recipe: ConsistencyPartitionRecipeV1,
    vectors: (Sha256Digest, Sha256Digest),
}

impl CarriedForGenerationThree {
    fn resolve(generation_two: &super::registry::RegistryPackageV1) -> ContractResult<Self> {
        // The consistency partition recipe is registry-controlled and has only
        // ever had one value: generation 1's, which generation 2 already reused
        // for its own connectors. The collected connectors reuse it too rather
        // than minting a second partition rule.
        let generation_one_connector: ConnectorSchemaV2 = decode_strict(&encode_canonical(
            &find_entry(generation_two, GEN1_CONNECTOR_SCHEMA)?.body,
        )?)?;
        // Every entry generation 2 minted carries one vector pair, taken from
        // a generation-1 sibling; the family's entries reuse the same pair.
        let sibling = find_entry(generation_two, GIT_CONNECTOR.version_recipe)?;
        Ok(Self {
            redaction_policy: reference_to(generation_two, GEN1_REDACTION_POLICY)?,
            classifier_policy: reference_to(generation_two, GEN1_CLASSIFIER_POLICY)?,
            retention_policy: reference_to(generation_two, GEN1_RETENTION_POLICY)?,
            publication_rule: reference_to(generation_two, GEN1_PUBLICATION_RULE)?,
            consistency_partition_recipe: generation_one_connector.consistency_partition_recipe,
            vectors: (
                sibling.positive_vector_digest,
                sibling.negative_vector_digest,
            ),
        })
    }
}

fn component_rules(
    keys: &[&str],
    encoding: LocatorEncoding,
) -> ContractResult<Vec<IdentityComponentRuleV1>> {
    keys.iter()
        .map(|key| {
            Ok(IdentityComponentRuleV1 {
                key: ContractId::new(*key)?,
                encoding,
            })
        })
        .collect()
}

fn namespace_entry(
    namespace_id: &str,
    keys: &[&str],
    vectors: (Sha256Digest, Sha256Digest),
) -> ContractResult<RegistryEntryV1> {
    mint_entry(
        RegistryEntryKind::NamespaceDefinition,
        namespace_id,
        "registry.namespace_definition",
        ENTRY_BODY_SCHEMA_VERSION,
        &AuthorityNamespaceV1 {
            schema_version: ENTRY_BODY_SCHEMA_VERSION,
            namespace_id: ContractId::new(namespace_id)?,
            version: GENERATION_TWO_ENTRY_VERSION,
            immutable_coordinate_keys: keys
                .iter()
                .map(|key| ContractId::new(*key))
                .collect::<ContractResult<_>>()?,
        },
        vectors,
    )
}

fn kind_entry(
    resource_kind: &str,
    identity_form: IdentityForm,
    parent_entity_kind: Option<RegistryReferenceV1>,
    component_rules: Vec<IdentityComponentRuleV1>,
    vectors: (Sha256Digest, Sha256Digest),
) -> ContractResult<RegistryEntryV1> {
    mint_entry(
        RegistryEntryKind::ResourceKindSchema,
        resource_kind,
        "registry.resource_kind_schema",
        ENTRY_BODY_SCHEMA_VERSION,
        &ResourceKindSchemaV1 {
            schema_version: ENTRY_BODY_SCHEMA_VERSION,
            resource_kind: ContractId::new(resource_kind)?,
            version: GENERATION_TWO_ENTRY_VERSION,
            identity_form,
            parent_entity_kind,
            component_rules,
        },
        vectors,
    )
}

fn recipe_entry(
    recipe_id: &str,
    kind: &RegistryEntryV1,
    identity_form: IdentityForm,
    namespace: &RegistryEntryV1,
    component_rules: Vec<IdentityComponentRuleV1>,
    vectors: (Sha256Digest, Sha256Digest),
) -> ContractResult<RegistryEntryV1> {
    mint_entry(
        RegistryEntryKind::IdentityRecipe,
        recipe_id,
        "registry.identity_recipe",
        ENTRY_BODY_SCHEMA_VERSION,
        &IdentityRecipeV1 {
            schema_version: ENTRY_BODY_SCHEMA_VERSION,
            recipe_id: ContractId::new(recipe_id)?,
            version: GENERATION_TWO_ENTRY_VERSION,
            resource_kind: kind.entry_id.clone(),
            identity_form,
            authority_namespace: reference_for(namespace)?,
            resource_kind_schema: reference_for(kind)?,
            component_rules,
        },
        vectors,
    )
}

/// Mint the provider-scope chain: namespace, entity kind, and entity recipe
/// over the two NFC UTF-8 coordinates.
fn provider_scope_chain(
    family: CollectedItemFamilyIds,
    vectors: (Sha256Digest, Sha256Digest),
) -> ContractResult<[RegistryEntryV1; 3]> {
    let keys = [PROVIDER_KIND_COORDINATE, PROVIDER_SCOPE_ID_COORDINATE];
    let rules = component_rules(&keys, LocatorEncoding::NfcUtf8)?;
    let namespace = namespace_entry(family.provider_scope_namespace, &keys, vectors)?;
    let kind = kind_entry(
        family.provider_scope_kind,
        IdentityForm::Entity,
        None,
        rules.clone(),
        vectors,
    )?;
    let recipe = recipe_entry(
        family.provider_scope_recipe,
        &kind,
        IdentityForm::Entity,
        &namespace,
        rules,
        vectors,
    )?;
    Ok([namespace, kind, recipe])
}

/// Mint the item chain — the generation-2 entity/version pair over one
/// immutable revision coordinate — and the evidence schema naming its version
/// recipe: namespace, revision kind, version kind, revision recipe, version
/// recipe, evidence schema.
fn item_chain(
    family: CollectedItemFamilyIds,
    carry: &CarriedForGenerationThree,
) -> ContractResult<[RegistryEntryV1; 6]> {
    let vectors = carry.vectors;
    let rules = component_rules(&[SOURCE_OBJECT_COORDINATE], LocatorEncoding::HexBytes)?;
    let namespace = namespace_entry(family.item_namespace, &[SOURCE_OBJECT_COORDINATE], vectors)?;
    let revision_kind = kind_entry(
        family.item_revision_kind,
        IdentityForm::Entity,
        None,
        rules.clone(),
        vectors,
    )?;
    let version_kind = kind_entry(
        family.item_version_kind,
        IdentityForm::Version,
        Some(reference_for(&revision_kind)?),
        rules.clone(),
        vectors,
    )?;
    let revision_recipe = recipe_entry(
        family.item_revision_recipe,
        &revision_kind,
        IdentityForm::Entity,
        &namespace,
        rules.clone(),
        vectors,
    )?;
    let version_recipe = recipe_entry(
        family.item_version_recipe,
        &version_kind,
        IdentityForm::Version,
        &namespace,
        rules,
        vectors,
    )?;
    let evidence = mint_entry(
        RegistryEntryKind::EvidenceSchema,
        family.evidence_schema,
        "registry.evidence_schema",
        ENTRY_BODY_SCHEMA_VERSION,
        &EvidenceSchemaBodyV1 {
            schema_version: ENTRY_BODY_SCHEMA_VERSION,
            evidence_schema_id: ContractId::new(family.evidence_schema)?,
            version: GENERATION_TWO_ENTRY_VERSION,
            evidence_kind: ContractId::new(family.evidence_kind)?,
            identity_recipe: reference_for(&version_recipe)?,
            redaction_policy: carry.redaction_policy.clone(),
            classifier_policy: carry.classifier_policy.clone(),
            retention_policy: carry.retention_policy.clone(),
            publication_rule: carry.publication_rule.clone(),
            canonical_payload_required: true,
            private_raw_default_enabled: false,
        },
        vectors,
    )?;
    Ok([
        namespace,
        revision_kind,
        version_kind,
        revision_recipe,
        version_recipe,
        evidence,
    ])
}

/// Mint the thirteen entries of the collected-item family: the two chains,
/// then one connector schema per trust channel binding both.
fn collected_item_family(
    family: CollectedItemFamilyIds,
    carry: &CarriedForGenerationThree,
) -> ContractResult<Vec<RegistryEntryV1>> {
    let [scope_namespace, scope_kind, scope_recipe] = provider_scope_chain(family, carry.vectors)?;
    let item = item_chain(family, carry)?;
    let [_, _, _, _, version_recipe, evidence] = &item;
    let connector = ConnectorSchemaV2 {
        schema_version: CONNECTOR_ENTRY_SCHEMA_VERSION,
        connector_schema_id: ContractId::new(family.pull_connector)?,
        version: GENERATION_TWO_ENTRY_VERSION,
        provider_namespace: reference_for(&scope_namespace)?,
        evidence_schema: reference_for(evidence)?,
        provider_instance_identity_recipe: reference_for(&scope_recipe)?,
        canonical_resource_identity_recipe: reference_for(version_recipe)?,
        consistency_partition_recipe: carry.consistency_partition_recipe.clone(),
        authenticated_scope_required: true,
        delivery_id_in_semantic_identity: false,
        immutable_revision_required: true,
    };

    let mut entries = vec![scope_namespace, scope_kind, scope_recipe];
    entries.extend(item);
    for connector_schema_id in family.connectors() {
        // The four channels differ only in their id.
        entries.push(mint_entry(
            RegistryEntryKind::ConnectorSchema,
            connector_schema_id,
            "registry.connector_schema",
            CONNECTOR_ENTRY_SCHEMA_VERSION,
            &ConnectorSchemaV2 {
                connector_schema_id: ContractId::new(connector_schema_id)?,
                ..connector.clone()
            },
            carry.vectors,
        )?);
    }
    Ok(entries)
}

/// Compose the generation-3 registry package from the generation-2 package.
///
/// Every generation-2 entry is carried forward byte for byte and the
/// collected-item family is appended; the result is sorted and its manifest
/// rebuilt exactly as generation 2's was. Fails closed when generation 2 does
/// not carry an entry the family binds, or when the composed package does not
/// pass full package validation.
pub fn generation_three_registry_package(
    generation_two: &ManifestVerifiedRegistryPackage,
) -> ContractResult<ManifestVerifiedRegistryPackage> {
    let source = generation_two.package();
    let carry = CarriedForGenerationThree::resolve(source)?;
    let mut entries = source.entries.clone();
    entries.extend(collected_item_family(COLLECTED_ITEM_FAMILY, &carry)?);
    assemble_package(source, entries)
}

#[cfg(test)]
#[path = "generation3_registry_tests.rs"]
mod tests;
