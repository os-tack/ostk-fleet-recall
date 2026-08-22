//! Generation-2 semantically-closed target package (W2-PKG).
//!
//! [`SemanticallyClosedStage4Package`](super::stage4_target_package) narrows a
//! generic offline successor closure to the one frozen generation-1 target.
//! This module is its generation-2 mirror: a *content-addressed composition*
//! of the gen-2 semantic components, proven closed offline and never granted
//! runtime authority.
//!
//! Unlike the gen-1 wrapper, this composition does not embed a full registry
//! package. It binds each gen-2 component by its exact content digest, computes
//! one package identity over that manifest, and proves closure: every referenced
//! component digest is present and non-zero, the two connector *instances* are
//! distinct, the coverage proof covers both of them, and no connector admits a
//! payload-selected scope. Composition proves offline closure only — it does
//! not prove the package is the active registry head and exposes no constructor
//! for runtime authority.
//!
//! The gen-2 components are:
//! 1. a transcript connector instance and a version-history connector instance
//!    ([`ConnectorInstanceBindingV2`]);
//! 2. a connector-instance-cursor-aware coverage proof ([`CoverageProofV2`]);
//! 3. a parser contract ([`ParserContractV2`], over
//!    [`ParserKeyV1`](super::chunk_identity::ParserKeyV1) +
//!    [`NormalizationRuleV1`](super::chunk_identity::NormalizationRuleV1));
//! 4. the remember predicate and admission rule, carried forward from gen-1;
//! 5. the activation policy, relation proof, observer admission, episode
//!    policy, and normative binding, each bound by content digest.

use serde::{Deserialize, Serialize};

use super::{
    ContractError, ContractResult,
    canonical::{decode_strict, encode_canonical, require_canonical},
    chunk_identity::ParserKeyV1,
    common::{ContractId, RegistryReferenceV1},
    coverage::CoverageProofV2,
    digest::{DigestDomain, Sha256Digest, domain_separated_digest},
    evidence_v2::ConnectorInstanceBindingV2,
};

const STAGE5_MANIFEST_SCHEMA_VERSION: u32 = 1;
const STAGE5_GENERATION: u32 = 2;
const PARSER_CONTRACT_SCHEMA_VERSION: u32 = 2;
const STAGE5_COMPONENT_COUNT: usize = 11;

/// Typed, fail-closed rejection reasons for generation-2 package closure.
///
/// Every rejection class the offline unit tests exercise maps to one exact
/// variant so a reviewer can assert the precise failure, never a stringly-typed
/// message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stage5PackageError {
    /// The transcript and version-history connectors named the same instance id.
    DuplicateConnectorInstance,
    /// The two connector instances resolved to the same connector schema id.
    ConnectorSchemaCollision,
    /// A connector schema admits a payload-selected scope, a payload-selected
    /// consistency recipe, or a mutable revision — none may bind evidence
    /// identity, so the package is rejected before it could ever be activated.
    PayloadSelectedConnectorScope,
    /// The coverage proof does not carry a cursor witness for one of the two
    /// named connector instances.
    CoverageDoesNotCoverConnectors,
    /// A bound component digest is the zero digest, or a required role is
    /// missing from a decoded manifest.
    DanglingComponentReference,
    /// Two manifest components claimed the same role, or the component set is
    /// not strictly ordered by role.
    NonCanonicalComponentSet,
    /// A decoded manifest's claimed component digest disagrees with the digest
    /// recomputed from the resolved component.
    ComponentDigestMismatch,
    /// Manifest bytes were not already in canonical form, or decoded to the
    /// wrong shape.
    NonCanonicalManifest,
    /// A component failed its own structural validation.
    InvalidComponent(ContractError),
}

impl From<ContractError> for Stage5PackageError {
    fn from(error: ContractError) -> Self {
        Self::InvalidComponent(error)
    }
}

/// Closed set of the roles a generation-2 package binds, one component each.
///
/// The declaration order is the canonical manifest order; the derived `Ord`
/// follows it, so a strictly-sorted manifest is one whose components appear in
/// this order with no repeats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage5ComponentRole {
    TranscriptConnector,
    VersionHistoryConnector,
    CoverageProof,
    ParserContract,
    RememberPredicate,
    RememberAdmission,
    ActivationPolicy,
    RelationProof,
    ObserverAdmission,
    EpisodePolicy,
    NormativeBinding,
}

/// Parser contract: the parser key plus its declared normalization
/// configuration, digested as one identity that becomes part of representation
/// identity (W2-PKG).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParserContractV2 {
    pub schema_version: u32,
    pub parser_contract_id: ContractId,
    pub version: u32,
    pub parser_key: ParserKeyV1,
}

impl ParserContractV2 {
    /// Validate the contract: schema version, a non-empty id, a positive
    /// version, and a well-formed parser key.
    pub fn validate(&self) -> ContractResult<()> {
        self.parser_key.validate()?;
        if self.schema_version != PARSER_CONTRACT_SCHEMA_VERSION
            || self.version == 0
            || self.parser_contract_id.as_str().is_empty()
        {
            return Err(ContractError::Schema("invalid parser contract v2".into()));
        }
        encode_canonical(self)?;
        Ok(())
    }

    /// `SHA-256("ostk-parser-contract-v2" || 0x00 || canonical_contract_bytes)`.
    pub fn contract_id(&self) -> ContractResult<Sha256Digest> {
        self.validate()?;
        Ok(domain_separated_digest(
            DigestDomain::ParserContractV2,
            &encode_canonical(self)?,
        ))
    }
}

/// One content-addressed entry in a generation-2 package manifest.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage5ComponentV1 {
    pub role: Stage5ComponentRole,
    pub component_id: ContractId,
    pub version: u32,
    pub component_digest: Sha256Digest,
}

/// The canonical, content-addressed manifest that is the package preimage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage5PackageManifestV1 {
    pub schema_version: u32,
    pub generation: u32,
    pub components: Vec<Stage5ComponentV1>,
}

impl Stage5PackageManifestV1 {
    /// Structural closure over the manifest alone: exactly the expected number
    /// of components, strictly ordered by role with no repeats, and no zero
    /// (dangling) component digest.
    fn validate_structure(&self) -> Result<(), Stage5PackageError> {
        if self.schema_version != STAGE5_MANIFEST_SCHEMA_VERSION
            || self.generation != STAGE5_GENERATION
            || self.components.len() != STAGE5_COMPONENT_COUNT
        {
            return Err(Stage5PackageError::NonCanonicalManifest);
        }
        for component in &self.components {
            if component.component_digest == Sha256Digest::ZERO || component.version == 0 {
                return Err(Stage5PackageError::DanglingComponentReference);
            }
        }
        if !self
            .components
            .windows(2)
            .all(|pair| pair[0].role < pair[1].role)
        {
            return Err(Stage5PackageError::NonCanonicalComponentSet);
        }
        Ok(())
    }
}

/// The resolved generation-2 components a producer composes into a package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stage5PackageComponents {
    pub transcript_connector: ConnectorInstanceBindingV2,
    pub version_history_connector: ConnectorInstanceBindingV2,
    pub coverage: CoverageProofV2,
    pub parser: ParserContractV2,
    pub remember_predicate: RegistryReferenceV1,
    pub remember_admission: RegistryReferenceV1,
    pub activation_policy: RegistryReferenceV1,
    pub relation_proof: RegistryReferenceV1,
    pub observer_admission: RegistryReferenceV1,
    pub episode_policy: RegistryReferenceV1,
    pub normative_binding: RegistryReferenceV1,
}

/// A generation-2 package, semantically closed but never active.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticallyClosedStage5Package {
    components: Stage5PackageComponents,
    manifest: Stage5PackageManifestV1,
    canonical_bytes: Vec<u8>,
    package_digest: Sha256Digest,
}

impl SemanticallyClosedStage5Package {
    /// Compose resolved gen-2 components into a closed package.
    ///
    /// Fails closed with an exact [`Stage5PackageError`] on any closure
    /// violation: a payload-selected connector, duplicate connector instances,
    /// a colliding connector schema, a coverage proof that misses a connector,
    /// or a dangling component reference.
    pub fn from_components(
        components: Stage5PackageComponents,
    ) -> Result<Self, Stage5PackageError> {
        Self::require_connector_binding(&components.transcript_connector)?;
        Self::require_connector_binding(&components.version_history_connector)?;

        let transcript_instance = components
            .transcript_connector
            .connector_instance_id()
            .clone();
        let version_history_instance = components
            .version_history_connector
            .connector_instance_id()
            .clone();
        if transcript_instance == version_history_instance {
            return Err(Stage5PackageError::DuplicateConnectorInstance);
        }
        if components
            .transcript_connector
            .schema()
            .schema()
            .connector_schema_id
            == components
                .version_history_connector
                .schema()
                .schema()
                .connector_schema_id
        {
            return Err(Stage5PackageError::ConnectorSchemaCollision);
        }

        components
            .coverage
            .validate()
            .map_err(Stage5PackageError::InvalidComponent)?;
        if !components.coverage.covers_instance(&transcript_instance)
            || !components
                .coverage
                .covers_instance(&version_history_instance)
        {
            return Err(Stage5PackageError::CoverageDoesNotCoverConnectors);
        }

        components
            .parser
            .validate()
            .map_err(Stage5PackageError::InvalidComponent)?;
        for reference in [
            &components.remember_predicate,
            &components.remember_admission,
            &components.activation_policy,
            &components.relation_proof,
            &components.observer_admission,
            &components.episode_policy,
            &components.normative_binding,
        ] {
            reference
                .validate()
                .map_err(Stage5PackageError::InvalidComponent)?;
            if reference.entry_digest == Sha256Digest::ZERO {
                return Err(Stage5PackageError::DanglingComponentReference);
            }
        }

        let manifest = Self::build_manifest(&components)?;
        manifest.validate_structure()?;
        let canonical_bytes =
            encode_canonical(&manifest).map_err(Stage5PackageError::InvalidComponent)?;
        let package_digest =
            domain_separated_digest(DigestDomain::Stage5TargetPackageV1, &canonical_bytes);
        Ok(Self {
            components,
            manifest,
            canonical_bytes,
            package_digest,
        })
    }

    /// Resolve external canonical package bytes against the resolved components
    /// they claim to name, failing closed on any digest disagreement.
    ///
    /// This is the activation-time gate: a package is handed as canonical bytes
    /// and must be re-derived from the components a repository actually resolves.
    /// If any claimed component digest differs from the recomputed digest, the
    /// package is rejected with [`Stage5PackageError::ComponentDigestMismatch`].
    pub fn from_canonical_bytes_and_components(
        canonical_manifest: &[u8],
        components: Stage5PackageComponents,
    ) -> Result<Self, Stage5PackageError> {
        require_canonical(canonical_manifest)
            .map_err(|_| Stage5PackageError::NonCanonicalManifest)?;
        let decoded: Stage5PackageManifestV1 = decode_strict(canonical_manifest)
            .map_err(|_| Stage5PackageError::NonCanonicalManifest)?;
        decoded.validate_structure()?;
        let recomposed = Self::from_components(components)?;
        if decoded != recomposed.manifest {
            // A same-shaped manifest that decodes and validates but does not
            // equal the recomputed one differs in a component digest; a
            // different shape was already rejected by validate_structure.
            return Err(Stage5PackageError::ComponentDigestMismatch);
        }
        Ok(recomposed)
    }

    /// Verify external canonical package bytes structurally and return the
    /// package identity they commit to. Proves round-trip and no dangling
    /// reference without needing the resolved components.
    pub fn verify_canonical_bytes(
        canonical_manifest: &[u8],
    ) -> Result<Sha256Digest, Stage5PackageError> {
        require_canonical(canonical_manifest)
            .map_err(|_| Stage5PackageError::NonCanonicalManifest)?;
        let decoded: Stage5PackageManifestV1 = decode_strict(canonical_manifest)
            .map_err(|_| Stage5PackageError::NonCanonicalManifest)?;
        decoded.validate_structure()?;
        Ok(domain_separated_digest(
            DigestDomain::Stage5TargetPackageV1,
            canonical_manifest,
        ))
    }

    /// Content-addressed package identity over the canonical manifest.
    pub const fn package_digest(&self) -> Sha256Digest {
        self.package_digest
    }

    /// The exact canonical manifest bytes the package identity commits to.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub const fn manifest(&self) -> &Stage5PackageManifestV1 {
        &self.manifest
    }

    pub const fn transcript_connector(&self) -> &ConnectorInstanceBindingV2 {
        &self.components.transcript_connector
    }

    pub const fn version_history_connector(&self) -> &ConnectorInstanceBindingV2 {
        &self.components.version_history_connector
    }

    pub const fn coverage_proof(&self) -> &CoverageProofV2 {
        &self.components.coverage
    }

    pub const fn parser_contract(&self) -> &ParserContractV2 {
        &self.components.parser
    }

    pub const fn remember_predicate(&self) -> &RegistryReferenceV1 {
        &self.components.remember_predicate
    }

    pub const fn remember_admission(&self) -> &RegistryReferenceV1 {
        &self.components.remember_admission
    }

    pub const fn activation_policy(&self) -> &RegistryReferenceV1 {
        &self.components.activation_policy
    }

    pub const fn relation_proof(&self) -> &RegistryReferenceV1 {
        &self.components.relation_proof
    }

    pub const fn observer_admission(&self) -> &RegistryReferenceV1 {
        &self.components.observer_admission
    }

    pub const fn episode_policy(&self) -> &RegistryReferenceV1 {
        &self.components.episode_policy
    }

    pub const fn normative_binding(&self) -> &RegistryReferenceV1 {
        &self.components.normative_binding
    }

    const fn require_connector_binding(
        binding: &ConnectorInstanceBindingV2,
    ) -> Result<(), Stage5PackageError> {
        let schema = binding.schema().schema();
        // A connector that admits a payload-selected scope, folds a delivery id
        // into semantic identity, or tolerates a mutable revision can never bind
        // evidence identity closed. `from_registry_entry` already rejects these,
        // but re-checking here keeps the package fail-closed independently.
        if !schema.authenticated_scope_required
            || schema.delivery_id_in_semantic_identity
            || !schema.immutable_revision_required
        {
            return Err(Stage5PackageError::PayloadSelectedConnectorScope);
        }
        Ok(())
    }

    fn build_manifest(
        components: &Stage5PackageComponents,
    ) -> Result<Stage5PackageManifestV1, Stage5PackageError> {
        let transcript = &components.transcript_connector;
        let version_history = &components.version_history_connector;
        let coverage_digest = components
            .coverage
            .proof_id()
            .map_err(Stage5PackageError::InvalidComponent)?
            .digest();
        let parser_digest = components
            .parser
            .contract_id()
            .map_err(Stage5PackageError::InvalidComponent)?;
        let coverage_component_id = ContractId::new("coverage.connector_instances")
            .map_err(Stage5PackageError::InvalidComponent)?;

        let mut entries = vec![
            Stage5ComponentV1 {
                role: Stage5ComponentRole::TranscriptConnector,
                component_id: transcript.schema().schema().connector_schema_id.clone(),
                version: transcript.schema().schema().version,
                component_digest: transcript.schema().registry_reference().entry_digest,
            },
            Stage5ComponentV1 {
                role: Stage5ComponentRole::VersionHistoryConnector,
                component_id: version_history
                    .schema()
                    .schema()
                    .connector_schema_id
                    .clone(),
                version: version_history.schema().schema().version,
                component_digest: version_history.schema().registry_reference().entry_digest,
            },
            Stage5ComponentV1 {
                role: Stage5ComponentRole::CoverageProof,
                component_id: coverage_component_id,
                version: STAGE5_GENERATION,
                component_digest: coverage_digest,
            },
            Stage5ComponentV1 {
                role: Stage5ComponentRole::ParserContract,
                component_id: components.parser.parser_contract_id.clone(),
                version: components.parser.version,
                component_digest: parser_digest,
            },
            Self::reference_component(
                Stage5ComponentRole::RememberPredicate,
                &components.remember_predicate,
            ),
            Self::reference_component(
                Stage5ComponentRole::RememberAdmission,
                &components.remember_admission,
            ),
            Self::reference_component(
                Stage5ComponentRole::ActivationPolicy,
                &components.activation_policy,
            ),
            Self::reference_component(
                Stage5ComponentRole::RelationProof,
                &components.relation_proof,
            ),
            Self::reference_component(
                Stage5ComponentRole::ObserverAdmission,
                &components.observer_admission,
            ),
            Self::reference_component(
                Stage5ComponentRole::EpisodePolicy,
                &components.episode_policy,
            ),
            Self::reference_component(
                Stage5ComponentRole::NormativeBinding,
                &components.normative_binding,
            ),
        ];
        entries.sort();
        Ok(Stage5PackageManifestV1 {
            schema_version: STAGE5_MANIFEST_SCHEMA_VERSION,
            generation: STAGE5_GENERATION,
            components: entries,
        })
    }

    fn reference_component(
        role: Stage5ComponentRole,
        reference: &RegistryReferenceV1,
    ) -> Stage5ComponentV1 {
        Stage5ComponentV1 {
            role,
            component_id: reference.entry_id.clone(),
            version: reference.version,
            component_digest: reference.entry_digest,
        }
    }
}

#[cfg(test)]
#[path = "stage5_target_package_tests.rs"]
mod tests;
