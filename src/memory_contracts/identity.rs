//! Typed canonical locators and content-addressed OSTK resource URIs.

use std::{collections::BTreeMap, fmt, str::FromStr};

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
    registry::{ManifestVerifiedRegistryPackage, RegistryEntryKind, RegistryPackageV1},
};

const IDENTITY_SCHEMA_VERSION: u32 = 1;
pub(crate) const MAX_LOCATOR_COMPONENTS: usize = 64;
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
    pub version: u32,
    pub immutable_coordinate_keys: Vec<ContractId>,
}

/// Closed resource-kind schema referenced by an identity recipe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceKindSchemaV1 {
    pub schema_version: u32,
    pub resource_kind: ContractId,
    pub version: u32,
    pub identity_form: IdentityForm,
    pub parent_entity_kind: Option<RegistryReferenceV1>,
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
/// were resolved from one manifest-verified offline package closure.
///
/// Runtime acceptance will additionally require an uncontested active-head
/// witness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedIdentityRecipe {
    recipe: IdentityRecipeV1,
    registry_reference: RegistryReferenceV1,
    profile: ProfileReferenceV1,
    authority_namespace_id: ContractId,
    parent_entity_kind: Option<RegistryReferenceV1>,
}

impl ValidatedIdentityRecipe {
    pub fn from_package(
        package: &ManifestVerifiedRegistryPackage,
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
        if (&namespace.namespace_id, namespace.version)
            != (&namespace_entry.entry_id, namespace_entry.version)
        {
            return Err(ContractError::InvalidIdentityRecipe(
                "namespace body ID does not match its registry entry".into(),
            ));
        }

        let kind_entry = exact_referenced_entry(
            package,
            RegistryEntryKind::ResourceKindSchema,
            &recipe.resource_kind_schema,
        )?;
        let kind: ResourceKindSchemaV1 = super::canonical::decode_strict(
            &super::canonical::encode_canonical(&kind_entry.body)?,
        )?;
        validate_kind_schema(&kind)?;
        if (&kind.resource_kind, kind.version) != (&kind_entry.entry_id, kind_entry.version) {
            return Err(ContractError::InvalidIdentityRecipe(
                "resource-kind body ID does not match its registry entry".into(),
            ));
        }
        if let Some(parent_reference) = &kind.parent_entity_kind {
            let parent_entry = exact_referenced_entry(
                package,
                RegistryEntryKind::ResourceKindSchema,
                parent_reference,
            )?;
            let parent: ResourceKindSchemaV1 = super::canonical::decode_strict(
                &super::canonical::encode_canonical(&parent_entry.body)?,
            )?;
            validate_kind_schema(&parent)?;
            if parent.identity_form != IdentityForm::Entity
                || (&parent.resource_kind, parent.version)
                    != (&parent_entry.entry_id, parent_entry.version)
            {
                return Err(ContractError::InvalidIdentityRecipe(
                    "version parent must resolve to an exact entity-kind schema".into(),
                ));
            }
        }

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
            profile: package.profile.clone(),
            authority_namespace_id: namespace.namespace_id,
            parent_entity_kind: kind.parent_entity_kind,
        })
    }

    pub const fn recipe(&self) -> &IdentityRecipeV1 {
        &self.recipe
    }

    pub const fn registry_reference(&self) -> &RegistryReferenceV1 {
        &self.registry_reference
    }

    /// The resource-kind schema this recipe's parent entity must resolve to.
    ///
    /// `Some` exactly when the recipe's identity form is `version`: the recipe
    /// closure already rejects a version recipe with no parent kind and an
    /// entity/occurrence recipe that names one.
    #[must_use]
    pub const fn parent_entity_kind(&self) -> Option<&RegistryReferenceV1> {
        self.parent_entity_kind.as_ref()
    }

    /// The authority namespace this recipe hashes under.
    #[must_use]
    pub const fn authority_namespace_id(&self) -> &ContractId {
        &self.authority_namespace_id
    }

    /// The trusted derivation context for this recipe inside one
    /// authenticated scope: the package's profile, the caller's trusted
    /// scope, and the recipe's own authority namespace. Nothing in it comes
    /// from the resource assertion being derived.
    pub(crate) fn derivation_context(
        &self,
        scope: &AuthenticatedProjectScopeV1,
    ) -> IdentityDerivationContextV1 {
        IdentityDerivationContextV1::from_trusted_context(
            self.profile.clone(),
            scope.clone(),
            self.authority_namespace_id.clone(),
        )
    }
}

/// Build the canonical locator a recipe's component rules define from
/// caller-supplied `key -> value` components.
///
/// Keys are matched exactly against the recipe's component rules and encoded
/// as those rules say. A key the recipe does not name, or a rule with no
/// supplied value, is refused rather than ignored or defaulted. Profile,
/// scope, form, kind, recipe reference, and namespace all come from the
/// recipe and the trusted scope, never from the components. Component values
/// are checked against their encodings when the locator is derived.
pub(crate) fn locator_from_components(
    recipe: &ValidatedIdentityRecipe,
    scope: &AuthenticatedProjectScopeV1,
    parent_entity: Option<&ResourceUri>,
    components: &BTreeMap<String, String>,
) -> ContractResult<CanonicalLocatorV1> {
    let rules = &recipe.recipe().component_rules;
    if let Some(unknown) = components
        .keys()
        .find(|key| !rules.iter().any(|rule| rule.key.as_str() == key.as_str()))
    {
        return Err(ContractError::InvalidResourceLocator(format!(
            "unknown locator component `{unknown}`"
        )));
    }
    let components = rules
        .iter()
        .map(|rule| {
            components
                .get(rule.key.as_str())
                .map(|value| LocatorComponentV1 {
                    key: rule.key.clone(),
                    encoding: rule.encoding,
                    value: value.clone(),
                })
                .ok_or_else(|| {
                    ContractError::InvalidResourceLocator(format!(
                        "missing locator component `{}`",
                        rule.key
                    ))
                })
        })
        .collect::<ContractResult<Vec<_>>>()?;
    Ok(CanonicalLocatorV1 {
        schema_version: IDENTITY_SCHEMA_VERSION,
        profile: recipe.profile.clone(),
        scope: scope.clone(),
        identity_form: recipe.recipe().identity_form,
        resource_kind: recipe.recipe().resource_kind.clone(),
        recipe: recipe.registry_reference().clone(),
        provider_instance_namespace: recipe.authority_namespace_id().clone(),
        parent_entity: parent_entity.cloned(),
        components,
    })
}

/// Derive one entity-form identity from `key -> value` components under an
/// already package-resolved recipe.
pub(crate) fn derive_entity_with_recipe(
    recipe: &ValidatedIdentityRecipe,
    scope: &AuthenticatedProjectScopeV1,
    components: &BTreeMap<String, String>,
) -> ContractResult<DerivedResourceIdentityV1> {
    if recipe.recipe().identity_form != IdentityForm::Entity {
        return Err(ContractError::InvalidIdentityRecipe(
            "component derivation requires an entity-form recipe".into(),
        ));
    }
    let locator = locator_from_components(recipe, scope, None, components)?;
    derive_resource_uri(&recipe.derivation_context(scope), &locator, recipe, None)
}

/// Derive one entity-form resource identity from `key -> value` locator
/// components, under the exact recipe `recipe` names inside `package`.
///
/// The recipe is resolved out of the package and must match the reference's
/// entry digest, not only its ID and version. Components are keyed and
/// encoded by the recipe's component rules: a missing or unknown key, or a
/// value that is not in its rule's canonical encoding, is refused. The
/// derivation context is the package profile, the trusted `scope`, and the
/// recipe's own authority namespace, so a caller supplies coordinates and
/// nothing else.
pub fn derive_entity_from_components(
    package: &ManifestVerifiedRegistryPackage,
    recipe: &RegistryReferenceV1,
    scope: &AuthenticatedProjectScopeV1,
    components: &BTreeMap<String, String>,
) -> ContractResult<DerivedResourceIdentityV1> {
    let validated =
        ValidatedIdentityRecipe::from_package(package, &recipe.entry_id, recipe.version)?;
    if validated.registry_reference() != recipe {
        return Err(ContractError::InvalidIdentityRecipe(
            "recipe reference does not match the package entry".into(),
        ));
    }
    derive_entity_with_recipe(&validated, scope, components)
}

/// Derive a `version`-form identity under an explicitly supplied, already
/// derived entity parent whose recipe may live in a different authority
/// namespace (owner decision D1, recorded in ADR 0005).
///
/// [`validate_locator`] requires a version parent derived under the child's
/// own authority namespace. The frozen `identity.github.commit` recipe lives
/// in `namespace.github.commit`, while its declared parent kind (`repository`)
/// has an entity recipe only in `namespace.github.repository`, so no locator
/// can satisfy that rule and a commit URI is underivable through it. This
/// function applies every other [`validate_locator`] check unchanged, and in
/// place of the same-namespace rule requires that:
///
/// * the locator is version-form and names exactly `parent` as its parent;
/// * `parent` is entity-form and was derived under the exact resource-kind
///   schema reference (entry ID, version, AND digest) the recipe declares as
///   its parent kind;
/// * `parent` was derived in the same trusted scope as the context.
///
/// The parent is a value a caller already rederived, never a URI it asserted,
/// and it is part of the hashed locator, so the same commit under two
/// different repositories yields two different URIs.
pub(crate) fn derive_version_under_entity_parent(
    context: &IdentityDerivationContextV1,
    locator: &CanonicalLocatorV1,
    recipe: &ValidatedIdentityRecipe,
    parent: &DerivedResourceIdentityV1,
) -> ContractResult<DerivedResourceIdentityV1> {
    validate_locator_identity(context, locator, recipe)?;
    let parent_matches = locator.identity_form == IdentityForm::Version
        && locator.parent_entity.as_ref() == Some(parent.uri())
        && parent.uri().identity_form() == IdentityForm::Entity
        && recipe.parent_entity_kind().is_some_and(|kind| {
            kind == &parent.resource_kind_schema && kind.entry_id == *parent.uri().resource_kind()
        })
        && parent.scope == context.scope;
    if !parent_matches {
        return Err(ContractError::InvalidResourceLocator(
            "version locator does not name a valid entity parent".into(),
        ));
    }
    validate_locator_components(locator, recipe)?;
    mint_derived_identity(context, locator, recipe)
}

/// Resolve the entity recipe a `version`-form recipe's parent must be derived
/// under, out of the same offline package closure.
///
/// The parent is *derived, never supplied*. A caller hands a version-form
/// locator and nothing else; this function finds the one recipe in the package
/// that can produce a parent [`validate_locator`] will accept:
///
/// * `entity` identity form,
/// * `resource_kind_schema` equal to the child's declared `parent_entity_kind`,
/// * the same authority namespace as the child (which
///   [`ValidatedIdentityRecipe::from_package`] in turn forces to the same
///   coordinate keys).
///
/// Zero matches or more than one is a closed refusal, not a guess: a package in
/// which the parent is ambiguous must not be allowed to mint version identities
/// under whichever recipe happened to sort first.
///
/// Returns `Ok(None)` when `child` is not a version recipe — such a recipe has
/// no parent, and asking for one is not an error.
pub fn resolve_parent_entity_recipe(
    package: &ManifestVerifiedRegistryPackage,
    child: &ValidatedIdentityRecipe,
) -> ContractResult<Option<ValidatedIdentityRecipe>> {
    let Some(parent_kind) = child.parent_entity_kind() else {
        return Ok(None);
    };
    let mut matches = package
        .package()
        .entries
        .iter()
        .filter(|entry| entry.kind == RegistryEntryKind::IdentityRecipe)
        .filter_map(|entry| {
            let bytes = encode_canonical(&entry.body).ok()?;
            let recipe: IdentityRecipeV1 = super::canonical::decode_strict(&bytes).ok()?;
            (recipe.identity_form == IdentityForm::Entity
                && recipe.resource_kind_schema == *parent_kind
                && recipe.authority_namespace.entry_id == *child.authority_namespace_id())
            .then_some((recipe.recipe_id, recipe.version))
        });
    let Some((recipe_id, version)) = matches.next() else {
        return Err(ContractError::InvalidIdentityRecipe(
            "version recipe has no entity-parent recipe in this package".into(),
        ));
    };
    if matches.next().is_some() {
        return Err(ContractError::InvalidIdentityRecipe(
            "version recipe has an ambiguous entity-parent recipe".into(),
        ));
    }
    Ok(Some(ValidatedIdentityRecipe::from_package(
        package, &recipe_id, version,
    )?))
}

/// Derive the parent-entity identity one `version`-form locator must name.
///
/// The parent locator is *reconstructed* from the child's own already-proven
/// coordinates — same profile, same scope, same components — under the parent
/// recipe resolved by [`resolve_parent_entity_recipe`]. Nothing about the parent
/// comes from a request: a caller cannot name a parent, choose the recipe that
/// derives it, or vary a coordinate between child and parent.
///
/// Returns `Ok(None)` when `child_recipe` is not a version recipe.
pub fn derive_version_parent(
    package: &ManifestVerifiedRegistryPackage,
    profile: &ProfileReferenceV1,
    scope: &AuthenticatedProjectScopeV1,
    child_recipe: &ValidatedIdentityRecipe,
    child_locator: &CanonicalLocatorV1,
) -> ContractResult<Option<DerivedResourceIdentityV1>> {
    let Some(parent_recipe) = resolve_parent_entity_recipe(package, child_recipe)? else {
        return Ok(None);
    };
    let parent_locator = CanonicalLocatorV1 {
        schema_version: IDENTITY_SCHEMA_VERSION,
        profile: profile.clone(),
        scope: scope.clone(),
        identity_form: parent_recipe.recipe().identity_form,
        resource_kind: parent_recipe.recipe().resource_kind.clone(),
        recipe: parent_recipe.registry_reference().clone(),
        provider_instance_namespace: parent_recipe.authority_namespace_id().clone(),
        // An entity is a root: nothing above it to name.
        parent_entity: None,
        components: child_locator.components.clone(),
    };
    let parent_context = IdentityDerivationContextV1::from_trusted_context(
        profile.clone(),
        scope.clone(),
        parent_recipe.authority_namespace_id().clone(),
    );
    Ok(Some(derive_resource_uri(
        &parent_context,
        &parent_locator,
        &parent_recipe,
        None,
    )?))
}

/// Trusted identity inputs supplied by authenticated ingress, never by the
/// resource assertion being checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityDerivationContextV1 {
    profile: ProfileReferenceV1,
    scope: AuthenticatedProjectScopeV1,
    provider_instance_namespace: ContractId,
}

impl IdentityDerivationContextV1 {
    pub const fn from_trusted_context(
        profile: ProfileReferenceV1,
        scope: AuthenticatedProjectScopeV1,
        provider_instance_namespace: ContractId,
    ) -> Self {
        Self {
            profile,
            scope,
            provider_instance_namespace,
        }
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

/// URI returned only after recipe, trusted scope, provider namespace, and parent
/// assertions have all been checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedResourceIdentityV1 {
    uri: ResourceUri,
    scope: AuthenticatedProjectScopeV1,
    provider_instance_namespace: ContractId,
    resource_kind_schema: RegistryReferenceV1,
}

impl DerivedResourceIdentityV1 {
    pub const fn uri(&self) -> &ResourceUri {
        &self.uri
    }

    pub fn into_uri(self) -> ResourceUri {
        self.uri
    }

    /// Trusted scope this identity was derived in.
    pub(crate) const fn scope(&self) -> &AuthenticatedProjectScopeV1 {
        &self.scope
    }

    /// Exact resource-kind schema reference of the recipe that derived it.
    pub(crate) const fn resource_kind_schema(&self) -> &RegistryReferenceV1 {
        &self.resource_kind_schema
    }
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
        if value.len() > 256 {
            return Err(ContractError::InvalidResourceUri);
        }
        let mut parts = value.split(':');
        let urn = parts.next();
        let ostk = parts.next();
        let form = parts.next();
        let version = parts.next();
        let kind = parts.next();
        let algorithm = parts.next();
        let digest_value = parts.next();
        if parts.next().is_some()
            || urn != Some("urn")
            || ostk != Some("ostk")
            || version != Some("v1")
            || algorithm != Some("sha256")
        {
            return Err(ContractError::InvalidResourceUri);
        }
        let identity_form = match form {
            Some("entity") => IdentityForm::Entity,
            Some("occurrence") => IdentityForm::Occurrence,
            Some("version") => IdentityForm::Version,
            _ => return Err(ContractError::InvalidResourceUri),
        };
        let resource_kind = ContractId::new(kind.ok_or(ContractError::InvalidResourceUri)?)
            .map_err(|_| ContractError::InvalidResourceUri)?;
        let digest = digest_value
            .ok_or(ContractError::InvalidResourceUri)?
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

/// Validate a locator against one manifest-verified offline recipe, then derive
/// its URN. Runtime admission additionally requires an uncontested active-head
/// witness and a distinct activated typestate.
pub fn derive_resource_uri(
    context: &IdentityDerivationContextV1,
    locator: &CanonicalLocatorV1,
    recipe: &ValidatedIdentityRecipe,
    parent: Option<&DerivedResourceIdentityV1>,
) -> ContractResult<DerivedResourceIdentityV1> {
    validate_locator(context, locator, recipe, parent)?;
    mint_derived_identity(context, locator, recipe)
}

/// Hash an already validated locator into its derived identity.
fn mint_derived_identity(
    context: &IdentityDerivationContextV1,
    locator: &CanonicalLocatorV1,
    recipe: &ValidatedIdentityRecipe,
) -> ContractResult<DerivedResourceIdentityV1> {
    let bytes = encode_canonical(locator)?;
    let digest = domain_separated_digest(DigestDomain::ResourceLocator, &bytes);
    Ok(DerivedResourceIdentityV1 {
        uri: ResourceUri {
            identity_form: locator.identity_form,
            resource_kind: locator.resource_kind.clone(),
            digest,
        },
        scope: context.scope.clone(),
        provider_instance_namespace: context.provider_instance_namespace.clone(),
        resource_kind_schema: recipe.recipe.resource_kind_schema.clone(),
    })
}

pub fn validate_locator(
    context: &IdentityDerivationContextV1,
    locator: &CanonicalLocatorV1,
    validated_recipe: &ValidatedIdentityRecipe,
    validated_parent: Option<&DerivedResourceIdentityV1>,
) -> ContractResult<()> {
    validate_locator_identity(context, locator, validated_recipe)?;
    match (
        locator.identity_form,
        locator.parent_entity.as_ref(),
        validated_parent,
    ) {
        (IdentityForm::Version, Some(parent), Some(validated_parent))
            if parent == validated_parent.uri()
                && parent.identity_form() == IdentityForm::Entity
                && validated_recipe
                    .parent_entity_kind
                    .as_ref()
                    .is_some_and(|kind| kind.entry_id == *parent.resource_kind())
                && validated_recipe
                    .parent_entity_kind
                    .as_ref()
                    .is_some_and(|kind| kind == &validated_parent.resource_kind_schema)
                && validated_parent.scope == context.scope
                && validated_parent.provider_instance_namespace
                    == context.provider_instance_namespace => {}
        (IdentityForm::Entity | IdentityForm::Occurrence, None, None) => {}
        _ => {
            return Err(ContractError::InvalidResourceLocator(
                "identity form has invalid parent".into(),
            ));
        }
    }
    validate_locator_components(locator, validated_recipe)
}

/// Every [`validate_locator`] check that precedes the parent rule: profile,
/// recipe, form, kind, scope, and namespace identity.
fn validate_locator_identity(
    context: &IdentityDerivationContextV1,
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
        || locator.profile != context.profile
        || locator.profile != validated_recipe.profile
        || locator.scope != context.scope
        || locator.provider_instance_namespace != context.provider_instance_namespace
        || locator.provider_instance_namespace != validated_recipe.authority_namespace_id
    {
        return Err(ContractError::InvalidResourceLocator(
            "locator does not match recipe identity".into(),
        ));
    }
    Ok(())
}

/// Every [`validate_locator`] check that follows the parent rule: the exact
/// component set, keys, encodings, and canonical values.
fn validate_locator_components(
    locator: &CanonicalLocatorV1,
    validated_recipe: &ValidatedIdentityRecipe,
) -> ContractResult<()> {
    let recipe = validated_recipe.recipe();
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
        || namespace.version == 0
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
    if let Some(parent) = &kind.parent_entity_kind {
        parent.validate()?;
    }
    let parent_is_valid = matches!(
        (kind.identity_form, kind.parent_entity_kind.as_ref()),
        (IdentityForm::Version, Some(_)) | (IdentityForm::Entity | IdentityForm::Occurrence, None)
    );
    if kind.schema_version != IDENTITY_SCHEMA_VERSION
        || kind.version == 0
        || !parent_is_valid
        || kind.component_rules.is_empty()
        || kind.component_rules.len() > MAX_LOCATOR_COMPONENTS
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
            resource_kind_schema: reference("repository", 1, "kind"),
            component_rules: vec![IdentityComponentRuleV1 {
                key: ContractId::new("provider_repository_id").unwrap(),
                encoding: LocatorEncoding::Decimal,
            }],
        }
    }

    fn validated(recipe: IdentityRecipeV1) -> ValidatedIdentityRecipe {
        let parent_entity_kind = (recipe.identity_form == IdentityForm::Version)
            .then(|| recipe.resource_kind_schema.clone());
        let registry_reference = RegistryReferenceV1 {
            entry_id: recipe.recipe_id.clone(),
            version: recipe.version,
            entry_digest: digest(&format!("recipe-{}", recipe.version)),
        };
        ValidatedIdentityRecipe {
            profile: profile(),
            authority_namespace_id: ContractId::new("github.namespace").unwrap(),
            parent_entity_kind,
            recipe,
            registry_reference,
        }
    }

    fn context() -> IdentityDerivationContextV1 {
        IdentityDerivationContextV1::from_trusted_context(
            profile(),
            AuthenticatedProjectScopeV1::from_trusted_context(
                ContractId::new("tenant.test").unwrap(),
                ContractId::new("project.test").unwrap(),
            ),
            ContractId::new("github.namespace").unwrap(),
        )
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
            provider_instance_namespace: ContractId::new("github.namespace").unwrap(),
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
        let first_uri = derive_resource_uri(&context(), &first, &recipe, None).unwrap();
        assert_eq!(
            first_uri,
            derive_resource_uri(&context(), &first, &recipe, None).unwrap()
        );

        let mut other_scope = first;
        other_scope.scope.project_namespace = ContractId::new("project.other").unwrap();
        assert!(derive_resource_uri(&context(), &other_scope, &recipe, None).is_err());
        let other_context = IdentityDerivationContextV1::from_trusted_context(
            profile(),
            other_scope.scope.clone(),
            ContractId::new("github.namespace").unwrap(),
        );
        assert_ne!(
            first_uri,
            derive_resource_uri(&other_context, &other_scope, &recipe, None).unwrap()
        );
    }

    #[test]
    fn recipe_upgrade_always_mints_a_new_uri() {
        let first_recipe = validated(recipe(1));
        let second_recipe = validated(recipe(2));
        let first = derive_resource_uri(
            &context(),
            &locator(&first_recipe, "12345"),
            &first_recipe,
            None,
        )
        .unwrap();
        let second = derive_resource_uri(
            &context(),
            &locator(&second_recipe, "12345"),
            &second_recipe,
            None,
        )
        .unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn version_requires_exact_entity_parent() {
        let entity_recipe = validated(self::recipe(1));
        let parent = derive_resource_uri(
            &context(),
            &self::locator(&entity_recipe, "12345"),
            &entity_recipe,
            None,
        )
        .unwrap();

        let mut version_recipe = self::recipe(1);
        version_recipe.identity_form = IdentityForm::Version;
        version_recipe.resource_kind = ContractId::new("repository_revision").unwrap();
        version_recipe.resource_kind_schema = reference("repository_revision", 1, "version-kind");
        let mut recipe = validated(version_recipe);
        recipe.parent_entity_kind = Some(entity_recipe.recipe.resource_kind_schema);
        let mut locator = locator(&recipe, "12345");
        assert!(derive_resource_uri(&context(), &locator, &recipe, None).is_err());

        locator.parent_entity = Some(parent.uri().clone());
        assert!(derive_resource_uri(&context(), &locator, &recipe, Some(&parent)).is_ok());

        let mut wrong_parent_recipe = self::recipe(2);
        wrong_parent_recipe.resource_kind_schema = reference("repository", 2, "other-kind");
        let wrong_parent_recipe = validated(wrong_parent_recipe);
        let wrong_parent = derive_resource_uri(
            &context(),
            &self::locator(&wrong_parent_recipe, "12345"),
            &wrong_parent_recipe,
            None,
        )
        .unwrap();
        locator.parent_entity = Some(wrong_parent.uri().clone());
        assert!(derive_resource_uri(&context(), &locator, &recipe, Some(&wrong_parent)).is_err());
    }

    #[test]
    fn exact_bytes_round_trip_without_path_normalization() {
        let bytes = HexBytes::new(vec![0xff, b'/', b'.', b'.', b'/', b'A']).unwrap();
        let encoded = super::super::canonical::encode_canonical(&bytes).unwrap();
        let decoded: HexBytes = super::super::canonical::decode_strict(&encoded).unwrap();
        assert_eq!(decoded, bytes);
    }
}
