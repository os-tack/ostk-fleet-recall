//! Typed canonical locators and content-addressed OSTK resource URIs.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use unicode_normalization::UnicodeNormalization;

use super::{
    ContractError, ContractResult,
    canonical::encode_canonical,
    common::{
        AuthenticatedProjectScopeV1, CanonicalDecimal, ContractId, HexBytes, ProfileReferenceV1,
        RegistryReferenceV1,
    },
    digest::{DigestDomain, Sha256Digest, domain_separated_digest},
    registry::{RegistryEntryKind, RegistryPackageV1, ValidatedRegistryPackage},
};

const IDENTITY_SCHEMA_VERSION: u32 = 1;
const MAX_LOCATOR_COMPONENTS: usize = 64;
const MAX_COMPONENT_VALUE_BYTES: usize = 4_096;

/// Resource identity form selected by an activated kind recipe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityForm {
    Entity,
    Occurrence,
    Version,
}

impl IdentityForm {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Entity => "entity",
            Self::Occurrence => "occurrence",
            Self::Version => "version",
        }
    }
}

/// Wire encoding required for one immutable locator coordinate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocatorEncoding {
    Decimal,
    HexBytes,
    NfcUtf8,
}

/// Ordered component rule included in an identity recipe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityComponentRuleV1 {
    pub key: ContractId,
    pub encoding: LocatorEncoding,
}

/// Registry-controlled namespace definition. Credentials and connector install
/// IDs are deliberately absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityNamespaceV1 {
    pub schema_version: u32,
    pub namespace_id: ContractId,
    pub immutable_coordinate_keys: Vec<ContractId>,
}

/// Closed resource-kind schema referenced by an identity recipe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceKindSchemaV1 {
    pub schema_version: u32,
    pub resource_kind: ContractId,
    pub identity_form: IdentityForm,
    pub parent_entity_kind: Option<ContractId>,
    pub component_rules: Vec<IdentityComponentRuleV1>,
}

/// Recipe whose digest closes over its exact namespace and kind-schema refs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityRecipeV1 {
    pub schema_version: u32,
    pub recipe_id: ContractId,
    pub version: u32,
    pub resource_kind: ContractId,
    pub identity_form: IdentityForm,
    pub authority_namespace: RegistryReferenceV1,
    pub resource_kind_schema: RegistryReferenceV1,
    pub component_rules: Vec<IdentityComponentRuleV1>,
}

impl IdentityRecipeV1 {
    pub fn validate(&self) -> ContractResult<()> {
        self.authority_namespace.validate()?;
        self.resource_kind_schema.validate()?;
        if self.schema_version != IDENTITY_SCHEMA_VERSION
            || self.version == 0
            || self.component_rules.is_empty()
            || self.component_rules.len() > MAX_LOCATOR_COMPONENTS
            || !strictly_sorted_by_key(&self.component_rules)
        {
            return Err(ContractError::InvalidIdentityRecipe(
                "invalid version or component rule set".into(),
            ));
        }
        Ok(())
    }
}

/// Identity recipe whose registry entry and exact namespace/kind dependencies
/// were resolved from one verified package closure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedIdentityRecipe {
    recipe: IdentityRecipeV1,
    registry_reference: RegistryReferenceV1,
}

impl ValidatedIdentityRecipe {
    pub fn from_package(
        package: &ValidatedRegistryPackage,
        recipe_id: &ContractId,
        version: u32,
    ) -> ContractResult<Self> {
        let package = package.package();
        let recipe_entry = exact_entry(
            package,
            RegistryEntryKind::IdentityRecipe,
            recipe_id,
            version,
        )?;
        let recipe: IdentityRecipeV1 = super::canonical::decode_strict(
            &super::canonical::encode_canonical(&recipe_entry.body)?,
        )?;
        recipe.validate()?;
        if recipe.recipe_id != *recipe_id || recipe.version != version {
            return Err(ContractError::InvalidIdentityRecipe(
                "recipe body metadata does not match its registry entry".into(),
            ));
        }

        let namespace_entry = exact_referenced_entry(
            package,
            RegistryEntryKind::NamespaceDefinition,
            &recipe.authority_namespace,
        )?;
        let namespace: AuthorityNamespaceV1 = super::canonical::decode_strict(
            &super::canonical::encode_canonical(&namespace_entry.body)?,
        )?;
        validate_namespace(&namespace)?;

        let kind_entry = exact_referenced_entry(
            package,
            RegistryEntryKind::ResourceKindSchema,
            &recipe.resource_kind_schema,
        )?;
        let kind: ResourceKindSchemaV1 = super::canonical::decode_strict(
            &super::canonical::encode_canonical(&kind_entry.body)?,
        )?;
        validate_kind_schema(&kind)?;

        if kind.resource_kind != recipe.resource_kind
            || kind.identity_form != recipe.identity_form
            || kind.component_rules != recipe.component_rules
            || namespace.immutable_coordinate_keys
                != recipe
                    .component_rules
                    .iter()
                    .map(|rule| rule.key.clone())
                    .collect::<Vec<_>>()
        {
            return Err(ContractError::InvalidIdentityRecipe(
                "recipe dependency closure is inconsistent".into(),
            ));
        }

        Ok(Self {
            recipe,
            registry_reference: RegistryReferenceV1 {
                entry_id: recipe_entry.entry_id.clone(),
                version: recipe_entry.version,
                entry_digest: recipe_entry.digest()?,
            },
        })
    }

    pub const fn recipe(&self) -> &IdentityRecipeV1 {
        &self.recipe
    }

    pub const fn registry_reference(&self) -> &RegistryReferenceV1 {
        &self.registry_reference
    }
}

/// One already normalized immutable locator coordinate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocatorComponentV1 {
    pub key: ContractId,
    pub encoding: LocatorEncoding,
    pub value: String,
}

impl LocatorComponentV1 {
    fn validate(&self) -> ContractResult<()> {
        if self.value.is_empty() || self.value.len() > MAX_COMPONENT_VALUE_BYTES {
            return Err(ContractError::InvalidResourceLocator(
                "component length is invalid".into(),
            ));
        }
        match self.encoding {
            LocatorEncoding::Decimal => {
                CanonicalDecimal::parse(self.value.clone())?;
            }
            LocatorEncoding::HexBytes => {
                let encoded = format!("\"{}\"", self.value);
                let _: HexBytes = super::canonical::decode_strict(encoded.as_bytes())?;
            }
            LocatorEncoding::NfcUtf8 => {
                if !self.value.nfc().eq(self.value.chars())
                    || self.value.chars().any(char::is_control)
                {
                    return Err(ContractError::InvalidResourceLocator(
                        "UTF-8 component is not canonical NFC".into(),
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Full locator preimage. Scope and provider namespace are trusted ingress
/// values; visible URN form/kind are also inside these hashed bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalLocatorV1 {
    pub schema_version: u32,
    pub profile: ProfileReferenceV1,
    pub scope: AuthenticatedProjectScopeV1,
    pub identity_form: IdentityForm,
    pub resource_kind: ContractId,
    pub recipe: RegistryReferenceV1,
    pub provider_instance_namespace: ContractId,
    pub parent_entity: Option<ResourceUri>,
    pub components: Vec<LocatorComponentV1>,
}

/// Parsed, canonical OSTK URI. It contains no user-facing provider name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResourceUri {
    identity_form: IdentityForm,
    resource_kind: ContractId,
    digest: Sha256Digest,
}

impl ResourceUri {
    pub const fn identity_form(&self) -> IdentityForm {
        self.identity_form
    }

    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    pub const fn resource_kind(&self) -> &ContractId {
        &self.resource_kind
    }
}

impl fmt::Display for ResourceUri {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "urn:ostk:{}:v1:{}:sha256:{}",
            self.identity_form.as_str(),
            self.resource_kind,
            self.digest
        )
    }
}

impl FromStr for ResourceUri {
    type Err = ContractError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let parts = value.split(':').collect::<Vec<_>>();
        if parts.len() != 7
            || parts[0] != "urn"
            || parts[1] != "ostk"
            || parts[3] != "v1"
            || parts[5] != "sha256"
        {
            return Err(ContractError::InvalidResourceUri);
        }
        let identity_form = match parts[2] {
            "entity" => IdentityForm::Entity,
            "occurrence" => IdentityForm::Occurrence,
            "version" => IdentityForm::Version,
            _ => return Err(ContractError::InvalidResourceUri),
        };
        let resource_kind =
            ContractId::new(parts[4]).map_err(|_| ContractError::InvalidResourceUri)?;
        let digest = parts[6]
            .parse()
            .map_err(|_| ContractError::InvalidResourceUri)?;
        Ok(Self {
            identity_form,
            resource_kind,
            digest,
        })
    }
}

impl Serialize for ResourceUri {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ResourceUri {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(D::Error::custom)
    }
}

/// Validate a locator against the exact activated recipe, then derive its URN.
pub fn derive_resource_uri(
    locator: &CanonicalLocatorV1,
    recipe: &ValidatedIdentityRecipe,
) -> ContractResult<ResourceUri> {
    validate_locator(locator, recipe)?;
    let bytes = encode_canonical(locator)?;
    let digest = domain_separated_digest(DigestDomain::ResourceLocator, &bytes);
    Ok(ResourceUri {
        identity_form: locator.identity_form,
        resource_kind: locator.resource_kind.clone(),
        digest,
    })
}

pub fn validate_locator(
    locator: &CanonicalLocatorV1,
    validated_recipe: &ValidatedIdentityRecipe,
) -> ContractResult<()> {
    let recipe = validated_recipe.recipe();
    locator.profile.validate()?;
    locator.recipe.validate()?;
    recipe.validate()?;
    if locator.schema_version != IDENTITY_SCHEMA_VERSION
        || locator.identity_form != recipe.identity_form
        || locator.resource_kind != recipe.resource_kind
        || locator.recipe != *validated_recipe.registry_reference()
    {
        return Err(ContractError::InvalidResourceLocator(
            "locator does not match recipe identity".into(),
        ));
    }
    match (locator.identity_form, locator.parent_entity.as_ref()) {
        (IdentityForm::Version, Some(parent)) if parent.identity_form() == IdentityForm::Entity => {
        }
        (IdentityForm::Entity | IdentityForm::Occurrence, None) => {}
        _ => {
            return Err(ContractError::InvalidResourceLocator(
                "identity form has invalid parent".into(),
            ));
        }
    }
    if locator.components.len() != recipe.component_rules.len()
        || locator.components.len() > MAX_LOCATOR_COMPONENTS
    {
        return Err(ContractError::InvalidResourceLocator(
            "component set does not match recipe".into(),
        ));
    }
    for (component, rule) in locator.components.iter().zip(&recipe.component_rules) {
        component.validate()?;
        if component.key != rule.key || component.encoding != rule.encoding {
            return Err(ContractError::InvalidResourceLocator(
                "component set does not match recipe".into(),
            ));
        }
    }
    Ok(())
}

fn exact_entry<'a>(
    package: &'a RegistryPackageV1,
    kind: RegistryEntryKind,
    entry_id: &ContractId,
    version: u32,
) -> ContractResult<&'a super::registry::RegistryEntryV1> {
    let mut matches = package.entries.iter().filter(|entry| {
        entry.kind == kind && entry.entry_id == *entry_id && entry.version == version
    });
    let entry = matches.next().ok_or_else(|| {
        ContractError::InvalidIdentityRecipe("missing registry dependency".into())
    })?;
    if matches.next().is_some() {
        return Err(ContractError::InvalidIdentityRecipe(
            "duplicate registry dependency".into(),
        ));
    }
    Ok(entry)
}

fn exact_referenced_entry<'a>(
    package: &'a RegistryPackageV1,
    kind: RegistryEntryKind,
    reference: &RegistryReferenceV1,
) -> ContractResult<&'a super::registry::RegistryEntryV1> {
    let entry = exact_entry(package, kind, &reference.entry_id, reference.version)?;
    if entry.digest()? != reference.entry_digest {
        return Err(ContractError::InvalidIdentityRecipe(
            "registry dependency digest mismatch".into(),
        ));
    }
    Ok(entry)
}

fn validate_namespace(namespace: &AuthorityNamespaceV1) -> ContractResult<()> {
    if namespace.schema_version != IDENTITY_SCHEMA_VERSION
        || namespace.immutable_coordinate_keys.is_empty()
        || namespace.immutable_coordinate_keys.len() > MAX_LOCATOR_COMPONENTS
        || !strictly_sorted(&namespace.immutable_coordinate_keys)
    {
        return Err(ContractError::InvalidIdentityRecipe(
            "invalid authority namespace".into(),
        ));
    }
    Ok(())
}

fn validate_kind_schema(kind: &ResourceKindSchemaV1) -> ContractResult<()> {
    let parent_is_valid = matches!(
        (kind.identity_form, kind.parent_entity_kind.as_ref()),
        (IdentityForm::Version, Some(_)) | (IdentityForm::Entity | IdentityForm::Occurrence, None)
    );
    if kind.schema_version != IDENTITY_SCHEMA_VERSION
        || !parent_is_valid
        || kind.component_rules.is_empty()
        || !strictly_sorted_by_key(&kind.component_rules)
    {
        return Err(ContractError::InvalidIdentityRecipe(
            "invalid resource-kind schema".into(),
        ));
    }
    Ok(())
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn strictly_sorted_by_key(values: &[IdentityComponentRuleV1]) -> bool {
    values.windows(2).all(|pair| pair[0].key < pair[1].key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory_contracts::digest::{DigestDomain, domain_separated_digest};

    fn digest(label: &str) -> Sha256Digest {
        domain_separated_digest(DigestDomain::RegistryEntry, label.as_bytes())
    }

    fn profile() -> ProfileReferenceV1 {
        ProfileReferenceV1 {
            profile_id: ContractId::new("ostk-canonical-json-v1").unwrap(),
            profile_digest: domain_separated_digest(DigestDomain::CanonicalProfile, b"profile"),
            vector_manifest_digest: domain_separated_digest(
                DigestDomain::TestVectorManifest,
                b"vectors",
            ),
        }
    }

    fn reference(id: &str, version: u32, label: &str) -> RegistryReferenceV1 {
        RegistryReferenceV1 {
            entry_id: ContractId::new(id).unwrap(),
            version,
            entry_digest: digest(label),
        }
    }

    fn recipe(version: u32) -> IdentityRecipeV1 {
        IdentityRecipeV1 {
            schema_version: 1,
            recipe_id: ContractId::new("github.repository").unwrap(),
            version,
            resource_kind: ContractId::new("repository").unwrap(),
            identity_form: IdentityForm::Entity,
            authority_namespace: reference("github.namespace", 1, "namespace"),
            resource_kind_schema: reference("github.repository", 1, "kind"),
            component_rules: vec![IdentityComponentRuleV1 {
                key: ContractId::new("provider_repository_id").unwrap(),
                encoding: LocatorEncoding::Decimal,
            }],
        }
    }

    fn validated(recipe: IdentityRecipeV1) -> ValidatedIdentityRecipe {
        let registry_reference = RegistryReferenceV1 {
            entry_id: recipe.recipe_id.clone(),
            version: recipe.version,
            entry_digest: digest(&format!("recipe-{}", recipe.version)),
        };
        ValidatedIdentityRecipe {
            recipe,
            registry_reference,
        }
    }

    fn locator(recipe: &ValidatedIdentityRecipe, provider_id: &str) -> CanonicalLocatorV1 {
        CanonicalLocatorV1 {
            schema_version: 1,
            profile: profile(),
            scope: AuthenticatedProjectScopeV1::from_trusted_context(
                ContractId::new("tenant.test").unwrap(),
                ContractId::new("project.test").unwrap(),
            ),
            identity_form: recipe.recipe.identity_form,
            resource_kind: recipe.recipe.resource_kind.clone(),
            recipe: recipe.registry_reference.clone(),
            provider_instance_namespace: ContractId::new("github.public").unwrap(),
            parent_entity: None,
            components: vec![LocatorComponentV1 {
                key: ContractId::new("provider_repository_id").unwrap(),
                encoding: LocatorEncoding::Decimal,
                value: provider_id.to_owned(),
            }],
        }
    }

    #[test]
    fn rename_is_not_an_identity_component_but_scope_is() {
        let recipe = validated(recipe(1));
        let first = locator(&recipe, "12345");
        let first_uri = derive_resource_uri(&first, &recipe).unwrap();
        assert_eq!(first_uri, derive_resource_uri(&first, &recipe).unwrap());

        let mut other_scope = first;
        other_scope.scope.project_namespace = ContractId::new("project.other").unwrap();
        assert_ne!(
            first_uri,
            derive_resource_uri(&other_scope, &recipe).unwrap()
        );
    }

    #[test]
    fn recipe_upgrade_always_mints_a_new_uri() {
        let first_recipe = validated(recipe(1));
        let second_recipe = validated(recipe(2));
        let first = derive_resource_uri(&locator(&first_recipe, "12345"), &first_recipe).unwrap();
        let second =
            derive_resource_uri(&locator(&second_recipe, "12345"), &second_recipe).unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn version_requires_exact_entity_parent() {
        let mut recipe = recipe(1);
        recipe.identity_form = IdentityForm::Version;
        let recipe = validated(recipe);
        let mut locator = locator(&recipe, "12345");
        assert!(derive_resource_uri(&locator, &recipe).is_err());

        let entity_recipe = validated(self::recipe(1));
        locator.parent_entity = Some(
            derive_resource_uri(&self::locator(&entity_recipe, "12345"), &entity_recipe).unwrap(),
        );
        assert!(derive_resource_uri(&locator, &recipe).is_ok());
    }

    #[test]
    fn exact_bytes_round_trip_without_path_normalization() {
        let bytes = HexBytes::new(vec![0xff, b'/', b'.', b'.', b'/', b'A']).unwrap();
        let encoded = super::super::canonical::encode_canonical(&bytes).unwrap();
        let decoded: HexBytes = super::super::canonical::decode_strict(&encoded).unwrap();
        assert_eq!(decoded, bytes);
    }
}
