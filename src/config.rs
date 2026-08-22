use std::env;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use ostk_recall_core::PrivacyTier;
use sha2::{Digest, Sha256};
use sqlx::postgres::PgConnectOptions;
use url::{Host, Url};
use uuid::Uuid;

use crate::control_log::TrustedControlScope;
use crate::evidence_ledger::{CONTENT_KEY_ENCRYPTION_KEY_ENV, ContentKeyEncryptionKey};
use crate::memory_contracts::bootstrap::{BootstrapPin, BootstrapReceiptDigest};
use crate::memory_contracts::common::{AuthenticatedProjectScopeV1, ContractId};
use crate::memory_contracts::digest::Sha256Digest;
use crate::memory_contracts::genesis_activation::{
    GenesisActivationPrincipalBinding, RegistryTestResultDigest, RegistryTestRunnerPin,
};
use crate::memory_contracts::successor_activation::{
    SuccessorActivationPrincipalBinding, SuccessorRegistryTestRunnerPin,
};
use crate::memory_contracts::successor_generic::{
    GenericSuccessorPrincipalBinding, GenericSuccessorTestRunnerPin,
};
use crate::memory_contracts::successor_policy::{
    GenesisSuccessorKeyBridgeDigest, GenesisSuccessorKeyBridgePin,
};
use crate::private_postgres::{
    MIGRATOR_POSTGRES_USER, PRIVATE_RUNTIME_POSTGRES_DATABASE, PUBLICATION_POSTGRES_USER,
    PrivatePostgresSslPolicy, WRITER_POSTGRES_USER,
};
use crate::{FleetError, FleetScope, Result};

/// Deployment-only authority needed by the private control-ledger bootstrap.
///
/// These values are deliberately absent from normal request and serving
/// configuration. The `CloudFront` demo and MCP tools cannot select or override
/// either scope representation or the out-of-band receipt pin.
#[derive(Clone)]
pub struct ControlBootstrapConfig {
    trusted_scope: TrustedControlScope,
    receipt_digest: BootstrapReceiptDigest,
}

impl std::fmt::Debug for ControlBootstrapConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ControlBootstrapConfig")
            .field("trusted_scope", &self.trusted_scope)
            .field("receipt_digest", &"<redacted>")
            .finish()
    }
}

impl ControlBootstrapConfig {
    #[must_use]
    pub const fn trusted_scope(&self) -> &TrustedControlScope {
        &self.trusted_scope
    }

    /// Reconstitute the authority token only at the bootstrap call boundary.
    #[must_use]
    pub const fn receipt_pin(&self) -> BootstrapPin {
        BootstrapPin::from_trusted_config(self.receipt_digest)
    }

    #[must_use]
    pub const fn receipt_digest(&self) -> BootstrapReceiptDigest {
        self.receipt_digest
    }
}

/// Minimal process configuration for the private one-shot bootstrap binary.
///
/// Bootstrap neither loads nor identifies an embedding model. Keeping this
/// separate from [`FleetConfig`] prevents unrelated serving and corpus
/// variables from becoming accidental control-plane prerequisites.
#[derive(Clone)]
pub struct ControlBootstrapRuntimeConfig {
    database_url: String,
    database_ssl_policy: PrivatePostgresSslPolicy,
    authority: ControlBootstrapConfig,
}

impl std::fmt::Debug for ControlBootstrapRuntimeConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ControlBootstrapRuntimeConfig")
            .field("database_url", &"<redacted>")
            .field("database_ssl_policy", &self.database_ssl_policy)
            .field("authority", &self.authority)
            .finish()
    }
}

impl ControlBootstrapRuntimeConfig {
    /// Read only the database, physical scope, semantic scope, and receipt pin
    /// needed by the private control bootstrap process.
    pub fn from_env() -> Result<Self> {
        control_bootstrap_runtime_config(
            &required("FLEET_RECALL_CONTROL_DATABASE_URL")?,
            &required("FLEET_RECALL_TENANT_ID")?,
            &required("FLEET_RECALL_PROJECT")?,
            &required("FLEET_RECALL_CONTROL_TENANT_NAMESPACE")?,
            &required("FLEET_RECALL_CONTROL_PROJECT_NAMESPACE")?,
            &required("FLEET_RECALL_BOOTSTRAP_RECEIPT_DIGEST")?,
        )
    }

    #[must_use]
    pub fn database_url(&self) -> &str {
        &self.database_url
    }

    #[must_use]
    pub const fn database_ssl_policy(&self) -> PrivatePostgresSslPolicy {
        self.database_ssl_policy
    }

    #[must_use]
    pub const fn authority(&self) -> &ControlBootstrapConfig {
        &self.authority
    }
}

/// Deployment-only authority for the private genesis-registry activation.
///
/// The activation ceremony binds the same physical and semantic scope as its
/// durable Stage-2 predecessor. Its bootstrap, conformance-runner, result, and
/// principal identities all come from trusted process configuration rather
/// than from CLI routing fields or the artifacts being verified.
#[derive(Clone)]
pub struct RegistryActivationConfig {
    trusted_scope: TrustedControlScope,
    bootstrap_receipt_digest: BootstrapReceiptDigest,
    test_result_digest: RegistryTestResultDigest,
    test_runner_artifact_digest: Sha256Digest,
    test_runner_configuration_digest: Sha256Digest,
    proposer_principal_id: ContractId,
    package_author_principal_id: ContractId,
}

impl std::fmt::Debug for RegistryActivationConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RegistryActivationConfig")
            .field("trusted_scope", &self.trusted_scope)
            .field("bootstrap_receipt_digest", &"<redacted>")
            .field("test_result_digest", &"<redacted>")
            .field("test_runner_artifact_digest", &"<redacted>")
            .field("test_runner_configuration_digest", &"<redacted>")
            .field("proposer_principal_id", &"<bound>")
            .field("package_author_principal_id", &"<bound>")
            .finish()
    }
}

impl RegistryActivationConfig {
    #[must_use]
    pub const fn trusted_scope(&self) -> &TrustedControlScope {
        &self.trusted_scope
    }

    #[must_use]
    pub const fn bootstrap_receipt_digest(&self) -> BootstrapReceiptDigest {
        self.bootstrap_receipt_digest
    }

    /// Reconstitute the bootstrap authority token only at verification.
    #[must_use]
    pub const fn bootstrap_pin(&self) -> BootstrapPin {
        BootstrapPin::from_trusted_config(self.bootstrap_receipt_digest)
    }

    /// Reconstitute the exact conformance-runner authority at verification.
    #[must_use]
    pub const fn test_runner_pin(&self) -> RegistryTestRunnerPin {
        RegistryTestRunnerPin::from_trusted_config(
            self.test_runner_artifact_digest,
            self.test_runner_configuration_digest,
            self.test_result_digest,
        )
    }

    /// Reconstitute the principal binding only at activation verification.
    #[must_use]
    pub fn principal_binding(&self) -> GenesisActivationPrincipalBinding {
        GenesisActivationPrincipalBinding::from_trusted_config(
            self.proposer_principal_id.clone(),
            self.package_author_principal_id.clone(),
        )
    }
}

/// Minimal process configuration for the workstation-only activation binary.
///
/// This surface intentionally has its own database URL and no serving,
/// bootstrap-database, embedding-model, HTTP, MCP, container, or cloud inputs.
#[derive(Clone)]
pub struct RegistryActivationRuntimeConfig {
    database_url: String,
    authority: RegistryActivationConfig,
}

impl std::fmt::Debug for RegistryActivationRuntimeConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RegistryActivationRuntimeConfig")
            .field("database_url", &"<redacted>")
            .field("authority", &self.authority)
            .finish()
    }
}

impl RegistryActivationRuntimeConfig {
    /// Read only the dedicated database URL and exact activation authority.
    pub fn from_env() -> Result<Self> {
        Self::from_lookup(|name| env::var(name).ok())
    }

    fn from_lookup(mut lookup: impl FnMut(&str) -> Option<String>) -> Result<Self> {
        registry_activation_runtime_config(
            &required_from(&mut lookup, "FLEET_RECALL_REGISTRY_DATABASE_URL")?,
            &required_from(&mut lookup, "FLEET_RECALL_REGISTRY_TENANT_ID")?,
            &required_from(&mut lookup, "FLEET_RECALL_REGISTRY_PROJECT")?,
            &required_from(&mut lookup, "FLEET_RECALL_REGISTRY_TENANT_NAMESPACE")?,
            &required_from(&mut lookup, "FLEET_RECALL_REGISTRY_PROJECT_NAMESPACE")?,
            &required_from(
                &mut lookup,
                "FLEET_RECALL_REGISTRY_BOOTSTRAP_RECEIPT_DIGEST",
            )?,
            &required_from(&mut lookup, "FLEET_RECALL_REGISTRY_TEST_RESULT_DIGEST")?,
            &required_from(
                &mut lookup,
                "FLEET_RECALL_REGISTRY_TEST_RUNNER_ARTIFACT_DIGEST",
            )?,
            &required_from(
                &mut lookup,
                "FLEET_RECALL_REGISTRY_TEST_RUNNER_CONFIGURATION_DIGEST",
            )?,
            &required_from(&mut lookup, "FLEET_RECALL_REGISTRY_PROPOSER_PRINCIPAL_ID")?,
            &required_from(
                &mut lookup,
                "FLEET_RECALL_REGISTRY_PACKAGE_AUTHOR_PRINCIPAL_ID",
            )?,
        )
    }

    #[must_use]
    pub fn database_url(&self) -> &str {
        &self.database_url
    }

    #[must_use]
    pub const fn authority(&self) -> &RegistryActivationConfig {
        &self.authority
    }
}

/// Deployment-only authority for the private generation `0 -> 1` activation.
///
/// Every value is bound by the dedicated successor process namespace. Neither
/// serving, bootstrap, nor genesis-activation configuration can supply a
/// fallback authority for this one-time transition.
#[derive(Clone)]
pub struct SuccessorActivationConfig {
    trusted_scope: TrustedControlScope,
    bootstrap_receipt_digest: BootstrapReceiptDigest,
    genesis_test_result_digest: RegistryTestResultDigest,
    genesis_test_runner_artifact_digest: Sha256Digest,
    genesis_test_runner_configuration_digest: Sha256Digest,
    target_test_result_digest: RegistryTestResultDigest,
    target_test_runner_artifact_digest: Sha256Digest,
    target_test_runner_configuration_digest: Sha256Digest,
    genesis_key_bridge_digest: GenesisSuccessorKeyBridgeDigest,
    genesis_proposer_principal_id: ContractId,
    genesis_package_author_principal_id: ContractId,
    proposer_principal_id: ContractId,
    package_author_principal_id: ContractId,
}

impl std::fmt::Debug for SuccessorActivationConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SuccessorActivationConfig")
            .field("trusted_scope", &self.trusted_scope)
            .field("bootstrap_receipt_digest", &"<redacted>")
            .field("genesis_test_result_digest", &"<redacted>")
            .field("genesis_test_runner_artifact_digest", &"<redacted>")
            .field("genesis_test_runner_configuration_digest", &"<redacted>")
            .field("target_test_result_digest", &"<redacted>")
            .field("target_test_runner_artifact_digest", &"<redacted>")
            .field("target_test_runner_configuration_digest", &"<redacted>")
            .field("genesis_key_bridge_digest", &"<redacted>")
            .field("genesis_proposer_principal_id", &"<bound>")
            .field("genesis_package_author_principal_id", &"<bound>")
            .field("proposer_principal_id", &"<bound>")
            .field("package_author_principal_id", &"<bound>")
            .finish()
    }
}

impl SuccessorActivationConfig {
    #[must_use]
    pub const fn trusted_scope(&self) -> &TrustedControlScope {
        &self.trusted_scope
    }

    #[must_use]
    pub const fn bootstrap_receipt_digest(&self) -> BootstrapReceiptDigest {
        self.bootstrap_receipt_digest
    }

    #[must_use]
    pub const fn bootstrap_pin(&self) -> BootstrapPin {
        BootstrapPin::from_trusted_config(self.bootstrap_receipt_digest)
    }

    #[must_use]
    pub const fn genesis_test_runner_pin(&self) -> RegistryTestRunnerPin {
        RegistryTestRunnerPin::from_trusted_config(
            self.genesis_test_runner_artifact_digest,
            self.genesis_test_runner_configuration_digest,
            self.genesis_test_result_digest,
        )
    }

    #[must_use]
    pub const fn target_test_runner_pin(&self) -> SuccessorRegistryTestRunnerPin {
        SuccessorRegistryTestRunnerPin::from_trusted_config(
            self.target_test_runner_artifact_digest,
            self.target_test_runner_configuration_digest,
            self.target_test_result_digest,
        )
    }

    #[must_use]
    pub const fn genesis_key_bridge_digest(&self) -> GenesisSuccessorKeyBridgeDigest {
        self.genesis_key_bridge_digest
    }

    #[must_use]
    pub const fn genesis_key_bridge_pin(&self) -> GenesisSuccessorKeyBridgePin {
        GenesisSuccessorKeyBridgePin::from_trusted_config(self.genesis_key_bridge_digest)
    }

    #[must_use]
    pub fn genesis_principal_binding(&self) -> GenesisActivationPrincipalBinding {
        GenesisActivationPrincipalBinding::from_trusted_config(
            self.genesis_proposer_principal_id.clone(),
            self.genesis_package_author_principal_id.clone(),
        )
    }

    #[must_use]
    pub fn successor_principal_binding(&self) -> SuccessorActivationPrincipalBinding {
        SuccessorActivationPrincipalBinding::from_trusted_config(
            self.proposer_principal_id.clone(),
            self.package_author_principal_id.clone(),
        )
    }

    /// The same trusted target-runner pin, typed for the repeatable generic
    /// `N -> N+1` ceremony.
    ///
    /// The generic ceremony reuses this closed process namespace rather than
    /// opening a second one: the target runner artifact/configuration/result
    /// pins name whichever successor package that invocation activates, and no
    /// new environment variable can widen the authority.
    #[must_use]
    pub const fn generic_target_test_runner_pin(&self) -> GenericSuccessorTestRunnerPin {
        GenericSuccessorTestRunnerPin::from_trusted_config(
            self.target_test_runner_artifact_digest,
            self.target_test_runner_configuration_digest,
            self.target_test_result_digest,
        )
    }

    /// The same trusted proposer/author identities, typed for the generic
    /// `N -> N+1` ceremony.
    #[must_use]
    pub fn generic_principal_binding(&self) -> GenericSuccessorPrincipalBinding {
        GenericSuccessorPrincipalBinding::from_trusted_config(
            self.proposer_principal_id.clone(),
            self.package_author_principal_id.clone(),
        )
    }
}

/// Minimal runtime configuration for the private first-successor process.
///
/// This process has a dedicated credential and receives no insecure-local
/// database escape or unrelated serving configuration.
#[derive(Clone)]
pub struct SuccessorActivationRuntimeConfig {
    database_url: String,
    authority: SuccessorActivationConfig,
}

impl std::fmt::Debug for SuccessorActivationRuntimeConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SuccessorActivationRuntimeConfig")
            .field("database_url", &"<redacted>")
            .field("authority", &self.authority)
            .finish()
    }
}

impl SuccessorActivationRuntimeConfig {
    pub fn from_env() -> Result<Self> {
        Self::from_lookup(|name| env::var(name).ok())
    }

    fn from_lookup(mut lookup: impl FnMut(&str) -> Option<String>) -> Result<Self> {
        successor_activation_runtime_config(
            &required_from(&mut lookup, "FLEET_RECALL_SUCCESSOR_DATABASE_URL")?,
            &required_from(&mut lookup, "FLEET_RECALL_SUCCESSOR_TENANT_ID")?,
            &required_from(&mut lookup, "FLEET_RECALL_SUCCESSOR_PROJECT")?,
            &required_from(&mut lookup, "FLEET_RECALL_SUCCESSOR_TENANT_NAMESPACE")?,
            &required_from(&mut lookup, "FLEET_RECALL_SUCCESSOR_PROJECT_NAMESPACE")?,
            &required_from(
                &mut lookup,
                "FLEET_RECALL_SUCCESSOR_BOOTSTRAP_RECEIPT_DIGEST",
            )?,
            &required_from(
                &mut lookup,
                "FLEET_RECALL_SUCCESSOR_GENESIS_TEST_RESULT_DIGEST",
            )?,
            &required_from(
                &mut lookup,
                "FLEET_RECALL_SUCCESSOR_GENESIS_TEST_RUNNER_ARTIFACT_DIGEST",
            )?,
            &required_from(
                &mut lookup,
                "FLEET_RECALL_SUCCESSOR_GENESIS_TEST_RUNNER_CONFIGURATION_DIGEST",
            )?,
            &required_from(
                &mut lookup,
                "FLEET_RECALL_SUCCESSOR_TARGET_TEST_RESULT_DIGEST",
            )?,
            &required_from(
                &mut lookup,
                "FLEET_RECALL_SUCCESSOR_TARGET_TEST_RUNNER_ARTIFACT_DIGEST",
            )?,
            &required_from(
                &mut lookup,
                "FLEET_RECALL_SUCCESSOR_TARGET_TEST_RUNNER_CONFIGURATION_DIGEST",
            )?,
            &required_from(
                &mut lookup,
                "FLEET_RECALL_SUCCESSOR_GENESIS_KEY_BRIDGE_DIGEST",
            )?,
            &required_from(
                &mut lookup,
                "FLEET_RECALL_SUCCESSOR_GENESIS_PROPOSER_PRINCIPAL_ID",
            )?,
            &required_from(
                &mut lookup,
                "FLEET_RECALL_SUCCESSOR_GENESIS_PACKAGE_AUTHOR_PRINCIPAL_ID",
            )?,
            &required_from(&mut lookup, "FLEET_RECALL_SUCCESSOR_PROPOSER_PRINCIPAL_ID")?,
            &required_from(
                &mut lookup,
                "FLEET_RECALL_SUCCESSOR_PACKAGE_AUTHOR_PRINCIPAL_ID",
            )?,
        )
    }

    #[must_use]
    pub fn database_url(&self) -> &str {
        &self.database_url
    }

    #[must_use]
    pub const fn authority(&self) -> &SuccessorActivationConfig {
        &self.authority
    }
}

/// Minimal runtime configuration for the private conflict-reconciliation
/// ceremony.
///
/// The process has its own database credential and physical fleet identity.
/// It never consults serving, control-bootstrap, registry, or successor
/// configuration and exposes no insecure-local database escape.
#[derive(Clone)]
pub struct ConflictReconciliationRuntimeConfig {
    database_url: String,
    trusted_scope: FleetScope,
}

impl std::fmt::Debug for ConflictReconciliationRuntimeConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConflictReconciliationRuntimeConfig")
            .field("database_url", &"<redacted>")
            .field("trusted_scope", &"<bound>")
            .finish()
    }
}

impl ConflictReconciliationRuntimeConfig {
    /// Read only the dedicated database URL and physical scope needed by this
    /// one-shot writer.
    pub fn from_env() -> Result<Self> {
        Self::from_lookup(|name| env::var(name).ok())
    }

    fn from_lookup(mut lookup: impl FnMut(&str) -> Option<String>) -> Result<Self> {
        conflict_reconciliation_runtime_config(
            &required_from(&mut lookup, "FLEET_RECALL_RECONCILIATION_DATABASE_URL")?,
            &required_from(&mut lookup, "FLEET_RECALL_RECONCILIATION_TENANT_ID")?,
            &required_from(&mut lookup, "FLEET_RECALL_RECONCILIATION_PROJECT")?,
        )
    }

    #[must_use]
    pub fn database_url(&self) -> &str {
        &self.database_url
    }

    #[must_use]
    pub const fn trusted_scope(&self) -> &FleetScope {
        &self.trusted_scope
    }
}

/// Deployment-only pins that enable the event-first writer path (ADR 0002 D4).
///
/// The three primary pins are optional as one group. Either all three are
/// present, and the per-transaction head witness plus the `assert` route are
/// enabled, or all three are absent, the event-first path stays disabled, and
/// every legacy behaviour remains byte-stable. A partial set is a
/// configuration error rather than a silently disabled authority path, so a
/// half-applied task definition can never downgrade a deployment that was
/// meant to run event-first.
///
/// These values are deployment authority, never request or payload fields:
/// the semantic namespaces come from process configuration and the receipt pin
/// arrives out of band, exactly as they do for the control bootstrap (AUTH-04,
/// EVID-04).
#[derive(Clone)]
pub struct WriterAuthorityConfig {
    semantic_scope: AuthenticatedProjectScopeV1,
    bootstrap_receipt_digest: BootstrapReceiptDigest,
    expected_activation_id: Option<Sha256Digest>,
}

impl std::fmt::Debug for WriterAuthorityConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WriterAuthorityConfig")
            .field("semantic_scope", &self.semantic_scope)
            .field("bootstrap_receipt_digest", &"<redacted>")
            .field(
                "expected_activation_id",
                &self.expected_activation_id.map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// Exact variables that enable the event-first writer path, as one group.
const WRITER_AUTHORITY_PIN_ENV_NAMES: [&str; 3] = [
    "FLEET_RECALL_CONTRACT_TENANT_NAMESPACE",
    "FLEET_RECALL_CONTRACT_PROJECT_NAMESPACE",
    "FLEET_RECALL_BOOTSTRAP_RECEIPT_DIGEST",
];

/// Optional break-glass pin, meaningless without the group above.
const WRITER_AUTHORITY_ACTIVATION_ID_ENV_NAME: &str = "FLEET_RECALL_EXPECTED_ACTIVATION_ID";

impl WriterAuthorityConfig {
    /// Read the optional writer-authority pin group from the process
    /// environment. `Ok(None)` means the event-first path stays disabled.
    pub fn from_env() -> Result<Option<Self>> {
        Self::from_lookup(|name| env::var(name).ok())
    }

    fn from_lookup(mut lookup: impl FnMut(&str) -> Option<String>) -> Result<Option<Self>> {
        let tenant_namespace = lookup(WRITER_AUTHORITY_PIN_ENV_NAMES[0]);
        let project_namespace = lookup(WRITER_AUTHORITY_PIN_ENV_NAMES[1]);
        let receipt_digest = lookup(WRITER_AUTHORITY_PIN_ENV_NAMES[2]);
        let expected_activation_id = lookup(WRITER_AUTHORITY_ACTIVATION_ID_ENV_NAME);
        match (tenant_namespace, project_namespace, receipt_digest) {
            (None, None, None) => {
                if expected_activation_id.is_some() {
                    return Err(FleetError::Configuration(format!(
                        "{WRITER_AUTHORITY_ACTIVATION_ID_ENV_NAME} has no effect without the complete writer authority pin set {}",
                        WRITER_AUTHORITY_PIN_ENV_NAMES.join(", ")
                    )));
                }
                Ok(None)
            }
            (Some(tenant_namespace), Some(project_namespace), Some(receipt_digest)) => {
                Ok(Some(Self {
                    semantic_scope: AuthenticatedProjectScopeV1::from_trusted_context(
                        parse_contract_id(&tenant_namespace, WRITER_AUTHORITY_PIN_ENV_NAMES[0])?,
                        parse_contract_id(&project_namespace, WRITER_AUTHORITY_PIN_ENV_NAMES[1])?,
                    ),
                    bootstrap_receipt_digest: BootstrapReceiptDigest::from_digest(parse_digest(
                        &receipt_digest,
                        WRITER_AUTHORITY_PIN_ENV_NAMES[2],
                    )?),
                    expected_activation_id: expected_activation_id
                        .map(|value| parse_digest(&value, WRITER_AUTHORITY_ACTIVATION_ID_ENV_NAME))
                        .transpose()?,
                }))
            }
            (tenant_namespace, project_namespace, receipt_digest) => {
                let missing = [
                    (
                        WRITER_AUTHORITY_PIN_ENV_NAMES[0],
                        tenant_namespace.is_none(),
                    ),
                    (
                        WRITER_AUTHORITY_PIN_ENV_NAMES[1],
                        project_namespace.is_none(),
                    ),
                    (WRITER_AUTHORITY_PIN_ENV_NAMES[2], receipt_digest.is_none()),
                ]
                .into_iter()
                .filter_map(|(name, absent)| absent.then_some(name))
                .collect::<Vec<_>>()
                .join(", ");
                Err(FleetError::Configuration(format!(
                    "the event-first writer path requires all of {} or none of them; missing {missing}",
                    WRITER_AUTHORITY_PIN_ENV_NAMES.join(", ")
                )))
            }
        }
    }

    /// Assemble the pin group from already trusted process context.
    ///
    /// Deployment code that resolves these values somewhere other than the
    /// process environment uses this; nothing here is caller-selectable at a
    /// protocol boundary (EVID-04).
    #[must_use]
    pub const fn from_trusted_context(
        semantic_scope: AuthenticatedProjectScopeV1,
        bootstrap_receipt_digest: BootstrapReceiptDigest,
        expected_activation_id: Option<Sha256Digest>,
    ) -> Self {
        Self {
            semantic_scope,
            bootstrap_receipt_digest,
            expected_activation_id,
        }
    }

    /// Pinned contract tenant/project namespaces the active head must carry.
    #[must_use]
    pub const fn semantic_scope(&self) -> &AuthenticatedProjectScopeV1 {
        &self.semantic_scope
    }

    /// Reconstitute the bootstrap authority token only at the verification
    /// boundary, exactly as the control bootstrap does.
    #[must_use]
    pub const fn receipt_pin(&self) -> BootstrapPin {
        BootstrapPin::from_trusted_config(self.bootstrap_receipt_digest)
    }

    #[must_use]
    pub const fn bootstrap_receipt_digest(&self) -> BootstrapReceiptDigest {
        self.bootstrap_receipt_digest
    }

    /// Break-glass exact activation ID, compared with equality when present.
    #[must_use]
    pub const fn expected_activation_id(&self) -> Option<Sha256Digest> {
        self.expected_activation_id
    }
}

#[derive(Clone)]
pub struct FleetConfig {
    pub database_url: String,
    pub database_ssl_policy: PrivatePostgresSslPolicy,
    pub default_scope: FleetScope,
    pub max_connections: u32,
    /// Stable logical model name used in the embedding registry.
    pub embedding_model: String,
    /// Baked, local model2vec bundle. Runtime code never resolves the logical
    /// model name through a remote registry.
    pub embedding_model_path: PathBuf,
    pub embedding_model_sha256: String,
    /// Deployment pins that enable the event-first writer path (ADR 0002 D4).
    ///
    /// `None` means the pins are absent and the event-first path is disabled;
    /// a partial set never reaches this field because
    /// [`WriterAuthorityConfig::from_lookup`] refuses it while this
    /// configuration is being built. That refusal is the whole point of
    /// carrying the group here: a half-applied task definition fails process
    /// startup instead of silently downgrading a deployment that was meant to
    /// run event-first.
    pub writer_authority: Option<WriterAuthorityConfig>,
}

impl std::fmt::Debug for FleetConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FleetConfig")
            .field("database_url", &"<redacted>")
            .field("database_ssl_policy", &self.database_ssl_policy)
            .field("default_scope", &self.default_scope)
            .field("max_connections", &self.max_connections)
            .field("embedding_model", &self.embedding_model)
            .field("embedding_model_path", &self.embedding_model_path)
            .field("embedding_model_sha256", &self.embedding_model_sha256)
            .field("writer_authority", &self.writer_authority)
            .finish()
    }
}

const MODEL_BUNDLE_DIGEST_DOMAIN: &[u8] = b"ostk-fleet-recall-model-bundle-v1\0";
const MODEL_BUNDLE_FILES: [&str; 3] = ["config.json", "model.safetensors", "tokenizer.json"];
const PUBLICATION_FORBIDDEN_DATABASE_URL_ENV_NAMES: [&str; 8] = [
    "FLEET_RECALL_DATABASE_URL",
    "FLEET_RECALL_CONTROL_DATABASE_URL",
    "FLEET_RECALL_REGISTRY_DATABASE_URL",
    "FLEET_RECALL_SUCCESSOR_DATABASE_URL",
    "FLEET_RECALL_RECONCILIATION_DATABASE_URL",
    "FLEET_RECALL_TEST_DATABASE_URL",
    "FLEET_RECONCILIATION_TEST_DATABASE_URL",
    "FLEET_RECALL_PUBLICATION_TEST_ADMIN_DATABASE_URL",
];

/// Runtime configuration admitted only for the bounded public recall process.
///
/// The publication process has a dedicated database identity. It fails closed
/// if the private writer URL is present, so a task definition cannot silently
/// cross-wire the existing DML-capable credential into the public process.
#[derive(Clone)]
pub struct PublicationConfig {
    database_url: String,
    database_ssl_policy: PrivatePostgresSslPolicy,
    runtime: FleetConfig,
}

impl std::fmt::Debug for PublicationConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PublicationConfig")
            .field("database_url", &"<redacted>")
            .field("database_ssl_policy", &self.database_ssl_policy)
            .field("runtime", &self.runtime)
            .finish()
    }
}

impl PublicationConfig {
    /// Load only the dedicated publication database identity plus the common
    /// immutable scope/model inputs required to execute recall.
    pub fn from_env() -> Result<Self> {
        reject_publication_private_database_urls(|name| env::var_os(name).is_some())?;
        Self::from_lookup(|name| env::var(name).ok())
    }

    fn from_lookup(mut lookup: impl FnMut(&str) -> Option<String>) -> Result<Self> {
        reject_publication_private_database_urls(|name| lookup(name).is_some())?;
        let database_url = required_from(&mut lookup, "FLEET_RECALL_PUBLICATION_DATABASE_URL")?;
        let allow_insecure_local =
            lookup("FLEET_RECALL_ALLOW_INSECURE_LOCAL_DATABASE").is_some_and(|value| value == "1");
        let database_ssl_policy =
            validate_publication_database_url(&database_url, allow_insecure_local)?;
        let runtime =
            fleet_config_from_lookup(database_url.clone(), database_ssl_policy, &mut lookup)?;

        Ok(Self {
            database_url,
            database_ssl_policy,
            runtime,
        })
    }

    #[must_use]
    pub fn database_url(&self) -> &str {
        &self.database_url
    }

    #[must_use]
    pub const fn database_ssl_policy(&self) -> PrivatePostgresSslPolicy {
        self.database_ssl_policy
    }

    #[must_use]
    pub const fn default_scope(&self) -> &FleetScope {
        &self.runtime.default_scope
    }

    #[must_use]
    pub const fn max_connections(&self) -> u32 {
        self.runtime.max_connections
    }

    #[must_use]
    pub fn embedding_model_identity(&self) -> String {
        self.runtime.embedding_model_identity()
    }

    pub fn verify_embedding_model_bundle(&self) -> Result<PathBuf> {
        self.runtime.verify_embedding_model_bundle()
    }
}

fn reject_publication_private_database_urls(
    mut is_present: impl FnMut(&str) -> bool,
) -> Result<()> {
    if let Some(name) = PUBLICATION_FORBIDDEN_DATABASE_URL_ENV_NAMES
        .iter()
        .copied()
        .find(|name| is_present(name))
    {
        return Err(FleetError::Configuration(format!(
            "the public demo forbids private database variable {name}; configure only FLEET_RECALL_PUBLICATION_DATABASE_URL; value is redacted"
        )));
    }
    Ok(())
}

impl FleetConfig {
    /// Load the long-lived private runtime writer configuration.
    pub fn from_env() -> Result<Self> {
        Self::from_writer_env()
    }

    /// Load the long-lived private runtime writer configuration.
    pub fn from_writer_env() -> Result<Self> {
        Self::from_lookup(|name| env::var(name).ok())
    }

    /// Load the one-shot schema migrator configuration.
    pub fn from_migrator_env() -> Result<Self> {
        Self::from_migrator_lookup(|name| env::var(name).ok())
    }

    fn from_lookup(mut lookup: impl FnMut(&str) -> Option<String>) -> Result<Self> {
        Self::from_lookup_for_database_user(&mut lookup, WRITER_POSTGRES_USER)
    }

    fn from_migrator_lookup(mut lookup: impl FnMut(&str) -> Option<String>) -> Result<Self> {
        Self::from_lookup_for_database_user(&mut lookup, MIGRATOR_POSTGRES_USER)
    }

    fn from_lookup_for_database_user(
        mut lookup: impl FnMut(&str) -> Option<String>,
        expected_user: &str,
    ) -> Result<Self> {
        let database_url = required_from(&mut lookup, "FLEET_RECALL_DATABASE_URL")?;
        let allow_insecure_local =
            lookup("FLEET_RECALL_ALLOW_INSECURE_LOCAL_DATABASE").is_some_and(|value| value == "1");
        let database_ssl_policy = validate_private_runtime_database_url(
            &database_url,
            allow_insecure_local,
            expected_user,
        )?;
        fleet_config_from_lookup(database_url, database_ssl_policy, &mut lookup)
    }

    /// Stable registry identity, independent of where the baked bundle is
    /// mounted on a particular deployment.
    #[must_use]
    pub fn embedding_model_identity(&self) -> String {
        format!(
            "{}@sha256:{}",
            self.embedding_model, self.embedding_model_sha256
        )
    }

    /// Verify the configured local bundle and return its canonical directory.
    pub fn verify_embedding_model_bundle(&self) -> Result<PathBuf> {
        let canonical = canonical_model_bundle_path(&self.embedding_model_path)?;
        let actual = model_bundle_sha256_at(&canonical)?;
        if actual != self.embedding_model_sha256 {
            return Err(FleetError::Configuration(format!(
                "embedding model bundle digest mismatch: expected {}, got {actual}",
                self.embedding_model_sha256
            )));
        }
        Ok(canonical)
    }
}

fn fleet_config_from_lookup(
    database_url: String,
    database_ssl_policy: PrivatePostgresSslPolicy,
    mut lookup: impl FnMut(&str) -> Option<String>,
) -> Result<FleetConfig> {
    let tenant_id = required_from(&mut lookup, "FLEET_RECALL_TENANT_ID")?
        .parse::<Uuid>()
        .map_err(|error| {
            FleetError::Configuration(format!("FLEET_RECALL_TENANT_ID must be a UUID: {error}"))
        })?;
    let project = required_from(&mut lookup, "FLEET_RECALL_PROJECT")?;
    let agent = required_from(&mut lookup, "FLEET_RECALL_AGENT")?;
    let max_connections = lookup("FLEET_RECALL_MAX_CONNECTIONS")
        .unwrap_or_else(|| "16".into())
        .parse::<u32>()
        .map_err(|error| {
            FleetError::Configuration(format!(
                "FLEET_RECALL_MAX_CONNECTIONS must be an integer: {error}"
            ))
        })?;
    let embedding_model = lookup("FLEET_RECALL_EMBEDDING_MODEL")
        .unwrap_or_else(|| "minishlab/potion-retrieval-32M".into());
    let embedding_model_path = PathBuf::from(required_from(
        &mut lookup,
        "FLEET_RECALL_EMBEDDING_MODEL_PATH",
    )?);
    let embedding_model_sha256 = required_from(&mut lookup, "FLEET_RECALL_EMBEDDING_MODEL_SHA256")?;
    // ADR 0002 D4: the writer-authority pin group is read by the same process
    // configuration every runtime entry point loads, so a partial set fails
    // startup here rather than leaving the event-first path silently disabled.
    let writer_authority = WriterAuthorityConfig::from_lookup(&mut lookup)?;

    if max_connections == 0 {
        return Err(FleetError::Configuration(
            "FLEET_RECALL_MAX_CONNECTIONS must be greater than zero".into(),
        ));
    }
    let embedding_model = embedding_model.trim();
    if embedding_model.is_empty() {
        return Err(FleetError::Configuration(
            "FLEET_RECALL_EMBEDDING_MODEL must not be empty".into(),
        ));
    }
    if embedding_model.len() > 256 || embedding_model.chars().any(char::is_control) {
        return Err(FleetError::Configuration(
                "FLEET_RECALL_EMBEDDING_MODEL must be at most 256 characters and contain no control characters"
                    .into(),
            ));
    }
    if embedding_model_sha256.len() != 64
        || !embedding_model_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(FleetError::Configuration(
            "FLEET_RECALL_EMBEDDING_MODEL_SHA256 must be a 64-character hex digest".into(),
        ));
    }

    Ok(FleetConfig {
        database_url,
        database_ssl_policy,
        default_scope: FleetScope::new(tenant_id, project, agent, None, PrivacyTier::T1Project)?,
        max_connections,
        embedding_model: embedding_model.to_owned(),
        embedding_model_path,
        embedding_model_sha256: embedding_model_sha256.to_ascii_lowercase(),
        writer_authority,
    })
}

fn control_bootstrap_config(
    deployment_scope: &FleetScope,
    tenant_namespace: &str,
    project_namespace: &str,
    receipt_digest: &str,
) -> Result<ControlBootstrapConfig> {
    let semantic_scope = AuthenticatedProjectScopeV1::from_trusted_context(
        ContractId::new(tenant_namespace).map_err(|error| {
            FleetError::Configuration(format!(
                "FLEET_RECALL_CONTROL_TENANT_NAMESPACE is invalid: {error}"
            ))
        })?,
        ContractId::new(project_namespace).map_err(|error| {
            FleetError::Configuration(format!(
                "FLEET_RECALL_CONTROL_PROJECT_NAMESPACE is invalid: {error}"
            ))
        })?,
    );
    let receipt_digest = Sha256Digest::from_str(receipt_digest)
        .map(BootstrapReceiptDigest::from_digest)
        .map_err(|error| {
            FleetError::Configuration(format!(
                "FLEET_RECALL_BOOTSTRAP_RECEIPT_DIGEST must be lowercase SHA-256: {error}"
            ))
        })?;
    Ok(ControlBootstrapConfig {
        trusted_scope: TrustedControlScope::from_trusted_context(deployment_scope, semantic_scope)?,
        receipt_digest,
    })
}

fn control_bootstrap_runtime_config(
    database_url: &str,
    tenant_id: &str,
    project: &str,
    tenant_namespace: &str,
    project_namespace: &str,
    receipt_digest: &str,
) -> Result<ControlBootstrapRuntimeConfig> {
    const DATABASE_VARIABLE: &str = "FLEET_RECALL_CONTROL_DATABASE_URL";
    validate_database_url(database_url, DATABASE_VARIABLE)?;
    validate_explicit_private_database_identity(database_url, DATABASE_VARIABLE)?;
    let database_ssl_policy =
        explicit_private_database_ssl_policy(database_url, DATABASE_VARIABLE)?;
    let tenant_id = tenant_id.parse::<Uuid>().map_err(|error| {
        FleetError::Configuration(format!("FLEET_RECALL_TENANT_ID must be a UUID: {error}"))
    })?;
    let deployment_scope = FleetScope::new(
        tenant_id,
        project,
        "private-control-bootstrap",
        None,
        PrivacyTier::T1Project,
    )?;
    Ok(ControlBootstrapRuntimeConfig {
        database_url: database_url.to_owned(),
        database_ssl_policy,
        authority: control_bootstrap_config(
            &deployment_scope,
            tenant_namespace,
            project_namespace,
            receipt_digest,
        )?,
    })
}

#[allow(clippy::too_many_arguments)]
fn registry_activation_runtime_config(
    database_url: &str,
    tenant_id: &str,
    project: &str,
    tenant_namespace: &str,
    project_namespace: &str,
    bootstrap_receipt_digest: &str,
    test_result_digest: &str,
    test_runner_artifact_digest: &str,
    test_runner_configuration_digest: &str,
    proposer_principal_id: &str,
    package_author_principal_id: &str,
) -> Result<RegistryActivationRuntimeConfig> {
    const DATABASE_VARIABLE: &str = "FLEET_RECALL_REGISTRY_DATABASE_URL";
    validate_database_url_with_local_escape(database_url, DATABASE_VARIABLE, false, false)?;
    validate_explicit_private_database_identity(database_url, DATABASE_VARIABLE)?;
    let tenant_id = tenant_id.parse::<Uuid>().map_err(|error| {
        FleetError::Configuration(format!(
            "FLEET_RECALL_REGISTRY_TENANT_ID must be a UUID: {error}"
        ))
    })?;
    let deployment_scope = FleetScope::new(
        tenant_id,
        project,
        "private-registry-activation",
        None,
        PrivacyTier::T1Project,
    )?;
    let semantic_scope = AuthenticatedProjectScopeV1::from_trusted_context(
        parse_contract_id(tenant_namespace, "FLEET_RECALL_REGISTRY_TENANT_NAMESPACE")?,
        parse_contract_id(project_namespace, "FLEET_RECALL_REGISTRY_PROJECT_NAMESPACE")?,
    );
    let trusted_scope =
        TrustedControlScope::from_trusted_context(&deployment_scope, semantic_scope)?;
    let bootstrap_receipt_digest = BootstrapReceiptDigest::from_digest(parse_digest(
        bootstrap_receipt_digest,
        "FLEET_RECALL_REGISTRY_BOOTSTRAP_RECEIPT_DIGEST",
    )?);
    let test_result_digest = parse_digest(
        test_result_digest,
        "FLEET_RECALL_REGISTRY_TEST_RESULT_DIGEST",
    )?;
    let test_runner_artifact_digest = parse_digest(
        test_runner_artifact_digest,
        "FLEET_RECALL_REGISTRY_TEST_RUNNER_ARTIFACT_DIGEST",
    )?;
    let test_runner_configuration_digest = parse_digest(
        test_runner_configuration_digest,
        "FLEET_RECALL_REGISTRY_TEST_RUNNER_CONFIGURATION_DIGEST",
    )?;
    let proposer_principal_id = parse_contract_id(
        proposer_principal_id,
        "FLEET_RECALL_REGISTRY_PROPOSER_PRINCIPAL_ID",
    )?;
    let package_author_principal_id = parse_contract_id(
        package_author_principal_id,
        "FLEET_RECALL_REGISTRY_PACKAGE_AUTHOR_PRINCIPAL_ID",
    )?;
    Ok(RegistryActivationRuntimeConfig {
        database_url: database_url.to_owned(),
        authority: RegistryActivationConfig {
            trusted_scope,
            bootstrap_receipt_digest,
            test_result_digest: RegistryTestResultDigest::from_digest(test_result_digest),
            test_runner_artifact_digest,
            test_runner_configuration_digest,
            proposer_principal_id,
            package_author_principal_id,
        },
    })
}

#[allow(clippy::too_many_arguments)]
fn successor_activation_runtime_config(
    database_url: &str,
    tenant_id: &str,
    project: &str,
    tenant_namespace: &str,
    project_namespace: &str,
    bootstrap_receipt_digest: &str,
    genesis_test_result_digest: &str,
    genesis_test_runner_artifact_digest: &str,
    genesis_test_runner_configuration_digest: &str,
    target_test_result_digest: &str,
    target_test_runner_artifact_digest: &str,
    target_test_runner_configuration_digest: &str,
    genesis_key_bridge_digest: &str,
    genesis_proposer_principal_id: &str,
    genesis_package_author_principal_id: &str,
    proposer_principal_id: &str,
    package_author_principal_id: &str,
) -> Result<SuccessorActivationRuntimeConfig> {
    validate_successor_database_url(database_url)?;
    let trusted_scope =
        successor_trusted_scope(tenant_id, project, tenant_namespace, project_namespace)?;
    let bootstrap_receipt_digest = BootstrapReceiptDigest::from_digest(parse_digest(
        bootstrap_receipt_digest,
        "FLEET_RECALL_SUCCESSOR_BOOTSTRAP_RECEIPT_DIGEST",
    )?);
    let genesis_test_result_digest = RegistryTestResultDigest::from_digest(parse_digest(
        genesis_test_result_digest,
        "FLEET_RECALL_SUCCESSOR_GENESIS_TEST_RESULT_DIGEST",
    )?);
    let genesis_test_runner_artifact_digest = parse_digest(
        genesis_test_runner_artifact_digest,
        "FLEET_RECALL_SUCCESSOR_GENESIS_TEST_RUNNER_ARTIFACT_DIGEST",
    )?;
    let genesis_test_runner_configuration_digest = parse_digest(
        genesis_test_runner_configuration_digest,
        "FLEET_RECALL_SUCCESSOR_GENESIS_TEST_RUNNER_CONFIGURATION_DIGEST",
    )?;
    let target_test_result_digest = RegistryTestResultDigest::from_digest(parse_digest(
        target_test_result_digest,
        "FLEET_RECALL_SUCCESSOR_TARGET_TEST_RESULT_DIGEST",
    )?);
    let target_test_runner_artifact_digest = parse_digest(
        target_test_runner_artifact_digest,
        "FLEET_RECALL_SUCCESSOR_TARGET_TEST_RUNNER_ARTIFACT_DIGEST",
    )?;
    let target_test_runner_configuration_digest = parse_digest(
        target_test_runner_configuration_digest,
        "FLEET_RECALL_SUCCESSOR_TARGET_TEST_RUNNER_CONFIGURATION_DIGEST",
    )?;
    let genesis_key_bridge_digest = GenesisSuccessorKeyBridgeDigest::from_digest(parse_digest(
        genesis_key_bridge_digest,
        "FLEET_RECALL_SUCCESSOR_GENESIS_KEY_BRIDGE_DIGEST",
    )?);
    let genesis_proposer_principal_id = parse_contract_id(
        genesis_proposer_principal_id,
        "FLEET_RECALL_SUCCESSOR_GENESIS_PROPOSER_PRINCIPAL_ID",
    )?;
    let genesis_package_author_principal_id = parse_contract_id(
        genesis_package_author_principal_id,
        "FLEET_RECALL_SUCCESSOR_GENESIS_PACKAGE_AUTHOR_PRINCIPAL_ID",
    )?;
    let proposer_principal_id = parse_contract_id(
        proposer_principal_id,
        "FLEET_RECALL_SUCCESSOR_PROPOSER_PRINCIPAL_ID",
    )?;
    let package_author_principal_id = parse_contract_id(
        package_author_principal_id,
        "FLEET_RECALL_SUCCESSOR_PACKAGE_AUTHOR_PRINCIPAL_ID",
    )?;
    Ok(SuccessorActivationRuntimeConfig {
        database_url: database_url.to_owned(),
        authority: SuccessorActivationConfig {
            trusted_scope,
            bootstrap_receipt_digest,
            genesis_test_result_digest,
            genesis_test_runner_artifact_digest,
            genesis_test_runner_configuration_digest,
            target_test_result_digest,
            target_test_runner_artifact_digest,
            target_test_runner_configuration_digest,
            genesis_key_bridge_digest,
            genesis_proposer_principal_id,
            genesis_package_author_principal_id,
            proposer_principal_id,
            package_author_principal_id,
        },
    })
}

fn successor_trusted_scope(
    tenant_id: &str,
    project: &str,
    tenant_namespace: &str,
    project_namespace: &str,
) -> Result<TrustedControlScope> {
    let tenant_id = tenant_id.parse::<Uuid>().map_err(|error| {
        FleetError::Configuration(format!(
            "FLEET_RECALL_SUCCESSOR_TENANT_ID must be a UUID: {error}"
        ))
    })?;
    if tenant_id.is_nil() {
        return Err(FleetError::Configuration(
            "FLEET_RECALL_SUCCESSOR_TENANT_ID must not be the nil UUID".into(),
        ));
    }
    let deployment_scope = FleetScope::new(
        tenant_id,
        project,
        "private-successor-activation",
        None,
        PrivacyTier::T1Project,
    )
    .map_err(|error| {
        FleetError::Configuration(format!(
            "FLEET_RECALL_SUCCESSOR_PROJECT is invalid: {error}"
        ))
    })?;
    let semantic_scope = AuthenticatedProjectScopeV1::from_trusted_context(
        parse_contract_id(tenant_namespace, "FLEET_RECALL_SUCCESSOR_TENANT_NAMESPACE")?,
        parse_contract_id(
            project_namespace,
            "FLEET_RECALL_SUCCESSOR_PROJECT_NAMESPACE",
        )?,
    );
    TrustedControlScope::from_trusted_context(&deployment_scope, semantic_scope).map_err(|error| {
        FleetError::Configuration(format!(
            "FLEET_RECALL_SUCCESSOR physical scope is invalid: {error}"
        ))
    })
}

fn conflict_reconciliation_runtime_config(
    database_url: &str,
    tenant_id: &str,
    project: &str,
) -> Result<ConflictReconciliationRuntimeConfig> {
    validate_reconciliation_database_url(database_url)?;

    let tenant_id = tenant_id.parse::<Uuid>().map_err(|error| {
        FleetError::Configuration(format!(
            "FLEET_RECALL_RECONCILIATION_TENANT_ID must be a UUID: {error}"
        ))
    })?;
    if tenant_id.is_nil() {
        return Err(FleetError::Configuration(
            "FLEET_RECALL_RECONCILIATION_TENANT_ID must not be the nil UUID".into(),
        ));
    }
    let trusted_scope = FleetScope::new(
        tenant_id,
        project,
        "private-conflict-reconciliation",
        None,
        PrivacyTier::T1Project,
    )
    .map_err(|error| {
        FleetError::Configuration(format!(
            "FLEET_RECALL_RECONCILIATION_PROJECT is invalid: {error}"
        ))
    })?;

    Ok(ConflictReconciliationRuntimeConfig {
        database_url: database_url.to_owned(),
        trusted_scope,
    })
}

fn validate_reconciliation_database_url(database_url: &str) -> Result<()> {
    const VARIABLE_NAME: &str = "FLEET_RECALL_RECONCILIATION_DATABASE_URL";
    validate_database_url_with_local_escape(database_url, VARIABLE_NAME, false, false)?;
    validate_explicit_private_database_identity(database_url, VARIABLE_NAME)?;

    let parsed = Url::parse(database_url).map_err(|error| {
        FleetError::Configuration(format!(
            "{VARIABLE_NAME} must be a valid PostgreSQL URL: {error}"
        ))
    })?;
    let host = parsed.host_str().ok_or_else(|| {
        FleetError::Configuration(format!("{VARIABLE_NAME} must include a hostname"))
    })?;
    let ordinary_network_host = match parsed.host() {
        Some(Host::Ipv4(_) | Host::Ipv6(_)) => !host.contains('%'),
        Some(Host::Domain(domain)) => is_ordinary_dns_host(domain),
        None => false,
    };
    if !ordinary_network_host || host.starts_with(['/', '\\']) {
        return Err(FleetError::Configuration(format!(
            "{VARIABLE_NAME} must use an ordinary DNS or IP hostname, not an encoded or Unix-socket host"
        )));
    }
    Ok(())
}

fn parse_digest(value: &str, variable_name: &str) -> Result<Sha256Digest> {
    Sha256Digest::from_str(value).map_err(|error| {
        FleetError::Configuration(format!(
            "{variable_name} must be lowercase SHA-256: {error}"
        ))
    })
}

fn parse_contract_id(value: &str, variable_name: &str) -> Result<ContractId> {
    ContractId::new(value)
        .map_err(|error| FleetError::Configuration(format!("{variable_name} is invalid: {error}")))
}

/// Compute the versioned digest for the three files consumed by model2vec.
///
/// The path itself and unrelated directory entries are intentionally excluded,
/// so the same baked bundle has the same identity at every mount point.
pub fn model_bundle_sha256(bundle: &Path) -> Result<String> {
    let canonical = canonical_model_bundle_path(bundle)?;
    model_bundle_sha256_at(&canonical)
}

fn canonical_model_bundle_path(bundle: &Path) -> Result<PathBuf> {
    let canonical = bundle.canonicalize().map_err(|error| {
        FleetError::Configuration(format!(
            "cannot resolve embedding model bundle {}: {error}",
            bundle.display()
        ))
    })?;
    if !canonical.is_dir() {
        return Err(FleetError::Configuration(format!(
            "embedding model bundle {} is not a directory",
            canonical.display()
        )));
    }
    Ok(canonical)
}

fn model_bundle_sha256_at(canonical: &Path) -> Result<String> {
    let mut digest = Sha256::new();
    digest.update(MODEL_BUNDLE_DIGEST_DOMAIN);

    for name in MODEL_BUNDLE_FILES {
        let path = canonical.join(name);
        let link_metadata = path.symlink_metadata().map_err(|error| {
            FleetError::Configuration(format!(
                "embedding model bundle is missing required file {name}: {error}"
            ))
        })?;
        if link_metadata.file_type().is_symlink() || !link_metadata.is_file() {
            return Err(FleetError::Configuration(format!(
                "embedding model bundle entry {name} must be a regular, non-symlink file"
            )));
        }

        let mut file = File::open(&path).map_err(|error| {
            FleetError::Configuration(format!(
                "cannot open embedding model bundle entry {name}: {error}"
            ))
        })?;
        digest.update(name.as_bytes());
        digest.update([0]);
        digest.update(link_metadata.len().to_be_bytes());

        let mut read_len = 0_u64;
        let mut buffer = [0_u8; 16 * 1024];
        loop {
            let count = file.read(&mut buffer).map_err(|error| {
                FleetError::Configuration(format!(
                    "cannot read embedding model bundle entry {name}: {error}"
                ))
            })?;
            if count == 0 {
                break;
            }
            read_len = read_len.saturating_add(count as u64);
            digest.update(&buffer[..count]);
        }
        if read_len != link_metadata.len() {
            return Err(FleetError::Configuration(format!(
                "embedding model bundle entry {name} changed while it was being verified"
            )));
        }
    }

    Ok(hex::encode(digest.finalize()))
}

/// Load the governed-content key-encryption key (ADR 0002 D5).
///
/// Deliberately a standalone accessor rather than a [`FleetConfig`] field.
/// [`PublicationConfig`] embeds a `FleetConfig`, and the publication process
/// must never hold the key that unwraps governed content DEKs — a field would
/// hand it one. Every caller that needs the key asks for it explicitly, so the
/// set of processes holding it is the set of call sites (PUBLIC-03, EVID-05).
///
/// The variable is required when called: a deployment that enables governed
/// evidence admission without a key fails closed at startup instead of storing
/// unencrypted bytes.
pub fn content_key_encryption_key() -> Result<ContentKeyEncryptionKey> {
    ContentKeyEncryptionKey::from_hex(&required(CONTENT_KEY_ENCRYPTION_KEY_ENV)?)
}

fn required(name: &str) -> Result<String> {
    env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| FleetError::Configuration(format!("{name} is required")))
}

fn required_from(lookup: &mut impl FnMut(&str) -> Option<String>, name: &str) -> Result<String> {
    lookup(name)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| FleetError::Configuration(format!("{name} is required")))
}

fn validate_database_url(database_url: &str, variable_name: &str) -> Result<()> {
    let allow_insecure_local =
        env::var("FLEET_RECALL_ALLOW_INSECURE_LOCAL_DATABASE").is_ok_and(|value| value == "1");
    validate_database_url_with_local_escape(database_url, variable_name, allow_insecure_local, true)
}

fn validate_database_url_with_local_escape(
    database_url: &str,
    variable_name: &str,
    allow_insecure_local: bool,
    local_escape_supported: bool,
) -> Result<()> {
    let parsed = Url::parse(database_url).map_err(|error| {
        FleetError::Configuration(format!(
            "{variable_name} must be a valid PostgreSQL URL: {error}"
        ))
    })?;
    if !matches!(parsed.scheme(), "postgres" | "postgresql") {
        return Err(FleetError::Configuration(format!(
            "{variable_name} must use the postgres or postgresql scheme"
        )));
    }
    let host = parsed.host_str().ok_or_else(|| {
        FleetError::Configuration(format!("{variable_name} must include a hostname"))
    })?;
    if host.contains('%') || host.starts_with(['/', '\\']) {
        return Err(FleetError::Configuration(format!(
            "{variable_name} must use a network hostname, not an encoded or Unix-socket host"
        )));
    }

    if parsed.fragment().is_some() {
        return Err(FleetError::Configuration(format!(
            "{variable_name} must not contain a URL fragment"
        )));
    }

    let mut ssl_mode = None;
    let mut ssl_root_cert = None;
    for (name, value) in parsed.query_pairs() {
        match name.as_ref() {
            "sslmode" if ssl_mode.is_none() => ssl_mode = Some(value.into_owned()),
            "sslrootcert" if ssl_root_cert.is_none() => {
                let value = value.into_owned();
                if value.len() > 4_096
                    || value.chars().any(char::is_control)
                    || !Path::new(&value).is_absolute()
                {
                    return Err(FleetError::Configuration(format!(
                        "{variable_name} sslrootcert must be a bounded absolute path"
                    )));
                }
                ssl_root_cert = Some(value);
            }
            "sslmode" | "sslrootcert" => {
                return Err(FleetError::Configuration(format!(
                    "{variable_name} must not repeat connection parameter {name}"
                )));
            }
            _ => {
                return Err(FleetError::Configuration(format!(
                    "{variable_name} contains an unsupported connection parameter; name and value are redacted"
                )));
            }
        }
    }

    if ssl_mode.as_deref() == Some("verify-full") {
        return Ok(());
    }

    let local_host = matches!(host, "localhost" | "127.0.0.1" | "::1" | "cockroach");
    if allow_insecure_local
        && local_host
        && ssl_root_cert.is_none()
        && matches!(ssl_mode.as_deref(), None | Some("disable"))
    {
        return Ok(());
    }
    let local_hint = if local_escape_supported {
        "; local development may set FLEET_RECALL_ALLOW_INSECURE_LOCAL_DATABASE=1 only for a loopback or `cockroach` host"
    } else {
        ""
    };
    Err(FleetError::Configuration(format!(
        "{variable_name} must set exactly sslmode=verify-full{local_hint}"
    )))
}

/// Require every identity field consumed by a private `PostgreSQL` writer to be
/// present in its dedicated URL. In particular, a nonempty explicit password
/// prevents `sqlx-postgres` from consulting `pgpass` after URL parsing.
fn validate_explicit_private_database_identity(
    database_url: &str,
    variable_name: &str,
) -> Result<()> {
    let parsed = Url::parse(database_url).map_err(|error| {
        FleetError::Configuration(format!(
            "{variable_name} must be a valid PostgreSQL URL: {error}"
        ))
    })?;
    if parsed.username().is_empty() {
        return Err(FleetError::Configuration(format!(
            "{variable_name} must include an explicit username"
        )));
    }
    if parsed.password().is_none_or(str::is_empty) {
        return Err(FleetError::Configuration(format!(
            "{variable_name} must include a nonempty explicit password"
        )));
    }
    if parsed.port().is_none_or(|port| port == 0) {
        return Err(FleetError::Configuration(format!(
            "{variable_name} must include an explicit nonzero numeric port"
        )));
    }
    if parsed.path().trim_start_matches('/').is_empty() {
        return Err(FleetError::Configuration(format!(
            "{variable_name} must include a nonempty database path"
        )));
    }
    Ok(())
}

fn explicit_private_database_ssl_policy(
    database_url: &str,
    variable_name: &str,
) -> Result<PrivatePostgresSslPolicy> {
    let parsed = Url::parse(database_url).map_err(|error| {
        FleetError::Configuration(format!(
            "{variable_name} must be a valid PostgreSQL URL: {error}"
        ))
    })?;
    match parsed
        .query_pairs()
        .find_map(|(name, value)| (name == "sslmode").then_some(value))
        .as_deref()
    {
        Some("verify-full") => Ok(PrivatePostgresSslPolicy::VerifyFull),
        Some("disable") => Ok(PrivatePostgresSslPolicy::Disable),
        _ => Err(FleetError::Configuration(format!(
            "{variable_name} must include an explicit supported sslmode"
        ))),
    }
}

/// Apply the closed endpoint policy for the private runtime or schema migrator.
///
/// The URL variable remains shared by deployment convention, but each command
/// class supplies one fixed expected principal. Comparing decoded driver
/// options prevents percent encoding from bypassing the identity boundary.
fn validate_private_runtime_database_url(
    database_url: &str,
    allow_insecure_local: bool,
    expected_user: &str,
) -> Result<PrivatePostgresSslPolicy> {
    const VARIABLE_NAME: &str = "FLEET_RECALL_DATABASE_URL";

    Url::parse(database_url).map_err(|_| {
        FleetError::Configuration(format!(
            "{VARIABLE_NAME} must be a valid PostgreSQL URL; value is redacted"
        ))
    })?;
    validate_database_url_with_local_escape(
        database_url,
        VARIABLE_NAME,
        allow_insecure_local,
        true,
    )?;
    validate_explicit_private_database_identity(database_url, VARIABLE_NAME)?;
    let decoded_options = database_url.parse::<PgConnectOptions>().map_err(|_| {
        FleetError::Configuration(format!(
            "{VARIABLE_NAME} must be a valid PostgreSQL URL; value is redacted"
        ))
    })?;
    if decoded_options.get_username() != expected_user {
        return Err(FleetError::Configuration(format!(
            "{VARIABLE_NAME} must authenticate exactly as {expected_user}; value is redacted"
        )));
    }
    if decoded_options.get_database() != Some(PRIVATE_RUNTIME_POSTGRES_DATABASE) {
        return Err(FleetError::Configuration(format!(
            "{VARIABLE_NAME} must select exactly the {PRIVATE_RUNTIME_POSTGRES_DATABASE} database; value is redacted"
        )));
    }

    explicit_private_database_ssl_policy(database_url, VARIABLE_NAME)
}

/// Apply the closed endpoint policy for the one-shot successor writer.
///
/// `sqlx-postgres` supports libpq-compatible environment and Unix-socket
/// defaults. Requiring every routing and credential field in the URL keeps a
/// later connection builder from filling those fields from ambient process
/// state. Percent-encoded opaque hosts are rejected because the `PostgreSQL`
/// parser decodes a leading slash as a Unix-socket directory, where TLS mode
/// is not applied.
fn validate_successor_database_url(database_url: &str) -> Result<()> {
    const VARIABLE_NAME: &str = "FLEET_RECALL_SUCCESSOR_DATABASE_URL";

    validate_database_url_with_local_escape(database_url, VARIABLE_NAME, false, false)?;
    let parsed = Url::parse(database_url).map_err(|error| {
        FleetError::Configuration(format!(
            "{VARIABLE_NAME} must be a valid PostgreSQL URL: {error}"
        ))
    })?;

    let host = parsed.host_str().ok_or_else(|| {
        FleetError::Configuration(format!("{VARIABLE_NAME} must include a hostname"))
    })?;
    let ordinary_network_host = match parsed.host() {
        Some(Host::Ipv4(_) | Host::Ipv6(_)) => !host.contains('%'),
        Some(Host::Domain(domain)) => is_ordinary_dns_host(domain),
        None => false,
    };
    if !ordinary_network_host || host.starts_with(['/', '\\']) {
        return Err(FleetError::Configuration(format!(
            "{VARIABLE_NAME} must use an ordinary DNS or IP hostname, not an encoded or Unix-socket host"
        )));
    }
    if parsed.username().is_empty() {
        return Err(FleetError::Configuration(format!(
            "{VARIABLE_NAME} must include an explicit username"
        )));
    }
    if parsed.password().is_none_or(str::is_empty) {
        return Err(FleetError::Configuration(format!(
            "{VARIABLE_NAME} must include a nonempty explicit password"
        )));
    }
    if parsed.port().is_none_or(|port| port == 0) {
        return Err(FleetError::Configuration(format!(
            "{VARIABLE_NAME} must include an explicit nonzero numeric port"
        )));
    }
    if parsed.path() != "/fleet_recall" {
        return Err(FleetError::Configuration(format!(
            "{VARIABLE_NAME} must select exactly the fleet_recall database"
        )));
    }

    Ok(())
}

/// Apply the closed endpoint policy for the public recall reader.
///
/// Unlike the general private runtime URL, publication is bound to the one
/// canonical application database and requires an explicit credential and TLS
/// mode. The sole exception is the existing opt-in loopback development escape,
/// which still requires the URL to say `sslmode=disable` explicitly.
fn validate_publication_database_url(
    database_url: &str,
    allow_insecure_local: bool,
) -> Result<PrivatePostgresSslPolicy> {
    const VARIABLE_NAME: &str = "FLEET_RECALL_PUBLICATION_DATABASE_URL";

    validate_database_url_with_local_escape(
        database_url,
        VARIABLE_NAME,
        allow_insecure_local,
        true,
    )?;
    validate_explicit_private_database_identity(database_url, VARIABLE_NAME)?;
    let parsed = Url::parse(database_url).map_err(|_| {
        FleetError::Configuration(format!(
            "{VARIABLE_NAME} must be a valid PostgreSQL URL; value is redacted"
        ))
    })?;
    let decoded_options = database_url.parse::<PgConnectOptions>().map_err(|_| {
        FleetError::Configuration(format!(
            "{VARIABLE_NAME} must be a valid PostgreSQL URL; value is redacted"
        ))
    })?;
    if decoded_options.get_username() != PUBLICATION_POSTGRES_USER {
        return Err(FleetError::Configuration(format!(
            "{VARIABLE_NAME} must authenticate exactly as {PUBLICATION_POSTGRES_USER}; value is redacted"
        )));
    }
    let host = parsed.host_str().ok_or_else(|| {
        FleetError::Configuration(format!("{VARIABLE_NAME} must include a hostname"))
    })?;
    let ordinary_network_host = match parsed.host() {
        Some(Host::Ipv4(_) | Host::Ipv6(_)) => !host.contains('%'),
        Some(Host::Domain(domain)) => is_ordinary_dns_host(domain),
        None => false,
    };
    if !ordinary_network_host || host.starts_with(['/', '\\']) {
        return Err(FleetError::Configuration(format!(
            "{VARIABLE_NAME} must use an ordinary DNS or IP hostname, not an encoded or Unix-socket host"
        )));
    }
    if parsed.path() != "/fleet_recall" {
        return Err(FleetError::Configuration(format!(
            "{VARIABLE_NAME} must select exactly the fleet_recall database"
        )));
    }

    explicit_private_database_ssl_policy(database_url, VARIABLE_NAME)
}

fn is_ordinary_dns_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 || host.contains('%') || !host.is_ascii() {
        return false;
    }
    let host = host.strip_suffix('.').unwrap_or(host);
    !host.is_empty()
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod tests;
