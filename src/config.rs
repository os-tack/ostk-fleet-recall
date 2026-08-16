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
use crate::memory_contracts::bootstrap::{BootstrapPin, BootstrapReceiptDigest};
use crate::memory_contracts::common::{AuthenticatedProjectScopeV1, ContractId};
use crate::memory_contracts::digest::Sha256Digest;
use crate::memory_contracts::genesis_activation::{
    GenesisActivationPrincipalBinding, RegistryTestResultDigest, RegistryTestRunnerPin,
};
use crate::memory_contracts::successor_activation::{
    SuccessorActivationPrincipalBinding, SuccessorRegistryTestRunnerPin,
};
use crate::memory_contracts::successor_policy::{
    GenesisSuccessorKeyBridgeDigest, GenesisSuccessorKeyBridgePin,
};
use crate::private_postgres::{PUBLICATION_POSTGRES_USER, PrivatePostgresSslPolicy};
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

#[derive(Clone)]
pub struct FleetConfig {
    pub database_url: String,
    pub default_scope: FleetScope,
    pub max_connections: u32,
    /// Stable logical model name used in the embedding registry.
    pub embedding_model: String,
    /// Baked, local model2vec bundle. Runtime code never resolves the logical
    /// model name through a remote registry.
    pub embedding_model_path: PathBuf,
    pub embedding_model_sha256: String,
}

impl std::fmt::Debug for FleetConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FleetConfig")
            .field("database_url", &"<redacted>")
            .field("default_scope", &self.default_scope)
            .field("max_connections", &self.max_connections)
            .field("embedding_model", &self.embedding_model)
            .field("embedding_model_path", &self.embedding_model_path)
            .field("embedding_model_sha256", &self.embedding_model_sha256)
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
        let runtime = fleet_config_from_lookup(database_url.clone(), &mut lookup)?;

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
    pub fn from_env() -> Result<Self> {
        Self::from_lookup(|name| env::var(name).ok())
    }

    fn from_lookup(mut lookup: impl FnMut(&str) -> Option<String>) -> Result<Self> {
        let database_url = required_from(&mut lookup, "FLEET_RECALL_DATABASE_URL")?;
        let allow_insecure_local =
            lookup("FLEET_RECALL_ALLOW_INSECURE_LOCAL_DATABASE").is_some_and(|value| value == "1");
        validate_database_url_with_local_escape(
            &database_url,
            "FLEET_RECALL_DATABASE_URL",
            allow_insecure_local,
            true,
        )?;
        fleet_config_from_lookup(database_url, &mut lookup)
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
        default_scope: FleetScope::new(tenant_id, project, agent, None, PrivacyTier::T1Project)?,
        max_connections,
        embedding_model: embedding_model.to_owned(),
        embedding_model_path,
        embedding_model_sha256: embedding_model_sha256.to_ascii_lowercase(),
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
mod tests {
    use std::collections::BTreeMap;
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    const FIXTURE_RECEIPT_DIGEST: &str =
        "084ee06ea7ebf3b1d592d6e5843584485144c0ee5720fcc2124a61a7fcde48f0";
    const FIXTURE_TEST_RESULT_DIGEST: &str =
        "e91e08070250a722446195b76ee685a9697298b9fdce9809027f120c829b679d";
    const FIXTURE_RUNNER_ARTIFACT_DIGEST: &str =
        "c2e5b0653471d35e54600a8d3fbe5613aff4c04e911787c09a25e2b327d4bbbd";
    const FIXTURE_RUNNER_CONFIGURATION_DIGEST: &str =
        "1d12aabe349fd0013389f93bf1917b0de6bbd5d2bd7156c85faff0b97360686d";
    const FIXTURE_TARGET_TEST_RESULT_DIGEST: &str =
        "e6783b2a018957a5861fe4e0670f55613d1ace35e381a6a9f5190ea9d7fbff8d";
    const FIXTURE_TARGET_RUNNER_ARTIFACT_DIGEST: &str =
        "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
    const FIXTURE_TARGET_RUNNER_CONFIGURATION_DIGEST: &str =
        "a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2";
    const FIXTURE_GENESIS_KEY_BRIDGE_DIGEST: &str =
        "e15309eba5118e21996a7cee6b3780c1a237982bdf4f22460bca4da189ef6592";

    fn deployment_scope() -> FleetScope {
        FleetScope::new(
            Uuid::from_u128(1),
            "physical-project",
            "deployment-agent",
            None,
            PrivacyTier::T1Project,
        )
        .expect("scope")
    }

    fn model_bundle() -> TempDir {
        let directory = tempfile::tempdir().expect("tempdir");
        fs::write(directory.path().join("config.json"), b"config").expect("config");
        fs::write(directory.path().join("model.safetensors"), b"weights").expect("weights");
        fs::write(directory.path().join("tokenizer.json"), b"tokenizer").expect("tokenizer");
        directory
    }

    #[test]
    fn model_bundle_digest_is_stable_and_content_addressed() {
        let first = model_bundle();
        let second = model_bundle();
        let digest = model_bundle_sha256(first.path()).expect("digest");

        assert_eq!(digest, model_bundle_sha256(first.path()).expect("digest"));
        assert_eq!(digest, model_bundle_sha256(second.path()).expect("digest"));

        fs::write(second.path().join("config.json"), b"different").expect("mutate");
        assert_ne!(digest, model_bundle_sha256(second.path()).expect("digest"));
    }

    #[test]
    fn configured_digest_and_registry_identity_are_verified() {
        let bundle = model_bundle();
        let digest = model_bundle_sha256(bundle.path()).expect("digest");
        let config = FleetConfig {
            database_url: "postgresql://example.invalid/defaultdb".into(),
            default_scope: FleetScope::new(
                Uuid::from_u128(1),
                "project",
                "agent",
                None,
                PrivacyTier::T1Project,
            )
            .expect("scope"),
            max_connections: 1,
            embedding_model: "logical/model".into(),
            embedding_model_path: bundle.path().into(),
            embedding_model_sha256: digest.clone(),
        };

        assert!(config.verify_embedding_model_bundle().is_ok());
        assert_eq!(
            config.embedding_model_identity(),
            format!("logical/model@sha256:{digest}")
        );

        let mut mismatched = config;
        mismatched.embedding_model_sha256 = "0".repeat(64);
        assert!(mismatched.verify_embedding_model_bundle().is_err());
    }

    #[test]
    fn model_bundle_requires_every_runtime_file() {
        let bundle = model_bundle();
        fs::remove_file(bundle.path().join("tokenizer.json")).expect("remove");

        let error = model_bundle_sha256(bundle.path()).expect_err("missing file must fail");
        assert!(error.to_string().contains("tokenizer.json"));
    }

    #[test]
    fn debug_never_exposes_database_credentials() {
        let bundle = model_bundle();
        let config = FleetConfig {
            database_url:
                "postgresql://operator:super-secret@example.invalid/defaultdb?sslmode=verify-full"
                    .into(),
            default_scope: FleetScope::new(
                Uuid::from_u128(1),
                "project",
                "agent",
                None,
                PrivacyTier::T1Project,
            )
            .expect("scope"),
            max_connections: 1,
            embedding_model: "logical/model".into(),
            embedding_model_path: bundle.path().into(),
            embedding_model_sha256: "0".repeat(64),
        };
        let debug = format!("{config:?}");
        assert!(!debug.contains("super-secret"));
        assert!(!debug.contains("operator:"));
        assert!(debug.contains("<redacted>"));
    }

    fn serving_values() -> BTreeMap<&'static str, String> {
        BTreeMap::from([
            (
                "FLEET_RECALL_TENANT_ID",
                "0198a849-f6ae-7d61-9800-000000000001".into(),
            ),
            ("FLEET_RECALL_PROJECT", "physical-project".into()),
            ("FLEET_RECALL_AGENT", "deployment-agent".into()),
            ("FLEET_RECALL_MAX_CONNECTIONS", "4".into()),
            (
                "FLEET_RECALL_EMBEDDING_MODEL",
                "logical/publication-model".into(),
            ),
            (
                "FLEET_RECALL_EMBEDDING_MODEL_PATH",
                "/opt/fleet-recall/model".into(),
            ),
            ("FLEET_RECALL_EMBEDDING_MODEL_SHA256", "a".repeat(64)),
        ])
    }

    #[test]
    fn publication_config_uses_only_its_dedicated_database_identity() {
        let mut values = serving_values();
        values.insert(
            "FLEET_RECALL_PUBLICATION_DATABASE_URL",
            "postgresql://fleet_publication:reader-secret@cluster.example:26257/fleet_recall?sslmode=verify-full"
                .into(),
        );

        let config = PublicationConfig::from_lookup(|name| values.get(name).cloned())
            .expect("publication config");

        assert_eq!(
            config.database_url(),
            "postgresql://fleet_publication:reader-secret@cluster.example:26257/fleet_recall?sslmode=verify-full"
        );
        assert_eq!(
            config.database_ssl_policy(),
            PrivatePostgresSslPolicy::VerifyFull
        );
        assert_eq!(config.runtime.database_url, config.database_url);
        let debug = format!("{config:?}");
        assert!(!debug.contains("reader-secret"));
        assert!(!debug.contains("fleet_publication:"));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn publication_config_rejects_writer_cross_wiring_without_reflection() {
        for forbidden_name in PUBLICATION_FORBIDDEN_DATABASE_URL_ENV_NAMES {
            let mut values = serving_values();
            values.insert(
                "FLEET_RECALL_PUBLICATION_DATABASE_URL",
                "postgresql://fleet_publication:reader-secret@cluster.example:26257/fleet_recall?sslmode=verify-full"
                    .into(),
            );
            values.insert(
                forbidden_name,
                "postgresql://private:private-secret@cluster.example:26257/fleet_recall?sslmode=verify-full"
                    .into(),
            );

            let error = PublicationConfig::from_lookup(|name| values.get(name).cloned())
                .expect_err("private URL presence must fail closed")
                .to_string();

            assert!(error.contains(forbidden_name));
            assert!(error.contains("value is redacted"));
            for secret in ["private-secret", "reader-secret"] {
                assert!(!error.contains(secret));
            }
        }
    }

    #[test]
    fn writer_config_never_falls_back_to_publication_url() {
        let mut values = serving_values();
        values.insert(
            "FLEET_RECALL_PUBLICATION_DATABASE_URL",
            "postgresql://fleet_publication:reader-secret@cluster.example:26257/fleet_recall?sslmode=verify-full"
                .into(),
        );

        let error = FleetConfig::from_lookup(|name| values.get(name).cloned())
            .expect_err("private runtime must require the writer URL")
            .to_string();
        assert_eq!(
            error,
            "configuration error: FLEET_RECALL_DATABASE_URL is required"
        );

        values.insert(
            "FLEET_RECALL_DATABASE_URL",
            "postgresql://writer:writer-secret@cluster.example:26257/fleet_recall?sslmode=verify-full"
                .into(),
        );
        let config =
            FleetConfig::from_lookup(|name| values.get(name).cloned()).expect("writer config");
        assert!(config.database_url.contains("writer:writer-secret"));
        assert!(!config.database_url.contains("reader-secret"));
    }

    #[test]
    fn publication_url_is_canonical_explicit_and_redacted() {
        let accepted = "postgresql://fleet_publication:secret@cluster.example:26257/fleet_recall?sslmode=verify-full";
        assert_eq!(
            validate_publication_database_url(accepted, false).expect("cloud publication URL"),
            PrivatePostgresSslPolicy::VerifyFull
        );
        assert_eq!(
            validate_publication_database_url(
                "postgresql://%66leet_publication:secret@cluster.example:26257/fleet_recall?sslmode=verify-full",
                false,
            )
            .expect("decoded canonical publication user"),
            PrivatePostgresSslPolicy::VerifyFull
        );

        for rejected in [
            "postgresql://fleet_publication:secret@cluster.example:26257/other?sslmode=verify-full",
            "postgresql://fleet_publication:secret@cluster.example:26257/fleet_recall",
            "postgresql://fleet_publication:secret@cluster.example:26257/fleet_recall?sslmode=require",
            "postgresql://fleet_publication:secret@cluster.example:26257/fleet_recall?sslmode=verify-full&options=-csearch_path%3Dattacker",
            "postgresql://fleet_publication:secret@%2Fvar%2Frun%2Fpostgres:26257/fleet_recall?sslmode=verify-full",
        ] {
            let error = validate_publication_database_url(rejected, false)
                .expect_err("closed publication URL must reject alternate authority")
                .to_string();
            assert!(!error.contains("fleet_publication:secret"));
        }

        let local =
            "postgresql://fleet_publication:secret@127.0.0.1:26257/fleet_recall?sslmode=disable";
        assert!(validate_publication_database_url(local, false).is_err());
        assert_eq!(
            validate_publication_database_url(local, true).expect("explicit local escape"),
            PrivatePostgresSslPolicy::Disable
        );
        assert!(
            validate_publication_database_url(
                "postgresql://fleet_publication:secret@127.0.0.1:26257/fleet_recall",
                true,
            )
            .is_err(),
            "even the local escape must state sslmode explicitly"
        );
    }

    #[test]
    fn publication_url_rejects_wrong_decoded_user_without_reflection() {
        for (database_url, supplied_user, supplied_password) in [
            (
                "postgresql://writer_identity_42:wrong-user-secret-42@cluster.example:26257/fleet_recall?sslmode=verify-full",
                "writer_identity_42",
                "wrong-user-secret-42",
            ),
            (
                "postgresql://%66leet_writer_43:encoded-wrong-secret-43@cluster.example:26257/fleet_recall?sslmode=verify-full",
                "fleet_writer_43",
                "encoded-wrong-secret-43",
            ),
        ] {
            let error = validate_publication_database_url(database_url, false)
                .expect_err("wrong decoded publication user must fail closed")
                .to_string();

            assert!(error.contains(PUBLICATION_POSTGRES_USER));
            assert!(error.contains("value is redacted"));
            assert!(!error.contains(database_url));
            assert!(!error.contains(supplied_user));
            assert!(!error.contains(supplied_password));
        }
    }

    #[test]
    fn cloud_database_urls_require_full_tls_verification() {
        assert!(
            validate_database_url(
                "postgresql://user:secret@cluster.example:26257/defaultdb?sslmode=verify-full",
                "TEST_DATABASE_URL",
            )
            .is_ok()
        );
        assert!(
            validate_database_url(
                "postgresql://user:secret@cluster.example:26257/defaultdb?sslmode=require",
                "TEST_DATABASE_URL",
            )
            .is_err()
        );
        assert!(
            validate_database_url(
                "postgresql://user:secret@cluster.example:26257/defaultdb?sslmode=disable",
                "TEST_DATABASE_URL",
            )
            .is_err()
        );
    }

    #[test]
    fn database_url_query_parameters_are_closed() {
        assert!(
            validate_database_url(
                "postgresql://user:secret@cluster.example:26257/defaultdb?sslmode=verify-full&sslrootcert=%2Fetc%2Fssl%2Fcerts%2Fca.pem",
                "TEST_DATABASE_URL",
            )
            .is_ok()
        );

        for parameter in [
            "ssl-mode=disable",
            "ssl-mode=verify-full",
            "ssl-root-cert=/tmp/ca.pem",
            "ssl-ca=/tmp/ca.pem",
            "host=attacker.example",
            "hostaddr=127.0.0.1",
            "port=5432",
            "dbname=other",
            "user=other",
            "password=other",
            "options=-csearch_path%3Dattacker",
            "options[search_path]=attacker",
            "application_name=other",
            "statement-cache-capacity=0",
            "unknown=value",
        ] {
            let url = format!(
                "postgresql://user:secret@cluster.example:26257/defaultdb?sslmode=verify-full&{parameter}"
            );
            assert!(
                validate_database_url(&url, "TEST_DATABASE_URL").is_err(),
                "accepted {parameter}"
            );
        }

        let error = validate_database_url(
            "postgresql://user:secret@cluster.example:26257/defaultdb?sslmode=verify-full&forged%0Alog-line=secret-value",
            "TEST_DATABASE_URL",
        )
        .expect_err("decoded control characters in query names must fail closed")
        .to_string();
        assert!(error.contains("name and value are redacted"));
        for reflected in ["forged", "log-line", "secret-value", "\n"] {
            assert!(!error.contains(reflected), "error reflected {reflected:?}");
        }

        for query in [
            "sslmode=verify-full&sslmode=disable",
            "sslrootcert=/tmp/one.pem&sslrootcert=/tmp/two.pem&sslmode=verify-full",
            "sslmode=verify-full&sslrootcert=relative.pem",
        ] {
            let url = format!("postgresql://user:secret@cluster.example:26257/defaultdb?{query}");
            assert!(
                validate_database_url(&url, "TEST_DATABASE_URL").is_err(),
                "accepted {query}"
            );
        }

        assert!(
            validate_database_url(
                "postgresql://user:secret@cluster.example:26257/defaultdb?sslmode=verify-full#ignored",
                "TEST_DATABASE_URL",
            )
            .is_err()
        );
    }

    #[test]
    fn control_bootstrap_authority_is_explicit_and_scope_bound() {
        let config = control_bootstrap_config(
            &deployment_scope(),
            "tenant.authority",
            "project.authority",
            FIXTURE_RECEIPT_DIGEST,
        )
        .expect("control config");

        assert_eq!(config.trusted_scope().project(), "physical-project");
        assert_eq!(
            config
                .trusted_scope()
                .semantic_scope()
                .tenant_namespace
                .as_str(),
            "tenant.authority"
        );
        assert_eq!(
            config
                .trusted_scope()
                .semantic_scope()
                .project_namespace
                .as_str(),
            "project.authority"
        );
        assert_eq!(
            config.receipt_digest().digest().to_string(),
            FIXTURE_RECEIPT_DIGEST
        );
        let debug = format!("{config:?}");
        assert!(!debug.contains(FIXTURE_RECEIPT_DIGEST));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn control_bootstrap_authority_rejects_noncanonical_values() {
        assert!(
            control_bootstrap_config(
                &deployment_scope(),
                "Tenant.Invalid",
                "project.authority",
                FIXTURE_RECEIPT_DIGEST,
            )
            .is_err()
        );
        assert!(
            control_bootstrap_config(
                &deployment_scope(),
                "tenant.authority",
                "project.authority",
                &FIXTURE_RECEIPT_DIGEST.to_ascii_uppercase(),
            )
            .is_err()
        );

        let mut invalid_physical = deployment_scope();
        invalid_physical.project = " project ".into();
        assert!(
            control_bootstrap_config(
                &invalid_physical,
                "tenant.authority",
                "project.authority",
                FIXTURE_RECEIPT_DIGEST,
            )
            .is_err()
        );
    }

    #[test]
    fn private_bootstrap_runtime_config_has_no_model_or_agent_dependency() {
        let config = control_bootstrap_runtime_config(
            "postgresql://bootstrap:secret@cluster.example:26257/fleet_recall?sslmode=verify-full",
            "0198a849-f6ae-7d61-9800-000000000001",
            "physical-project",
            "tenant.authority",
            "project.authority",
            FIXTURE_RECEIPT_DIGEST,
        )
        .expect("private bootstrap runtime config");

        assert_eq!(
            config.authority().trusted_scope().project(),
            "physical-project"
        );
        assert_eq!(
            config
                .authority()
                .trusted_scope()
                .semantic_scope()
                .project_namespace
                .as_str(),
            "project.authority"
        );
        assert_eq!(
            config.database_ssl_policy(),
            PrivatePostgresSslPolicy::VerifyFull
        );
        let debug = format!("{config:?}");
        assert!(!debug.contains("bootstrap:secret"));
        assert!(!debug.contains(FIXTURE_RECEIPT_DIGEST));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn private_control_database_requires_explicit_connection_identity() {
        for database_url in [
            "postgresql://:secret@cluster.example:26257/fleet_recall?sslmode=verify-full",
            "postgresql://bootstrap@cluster.example:26257/fleet_recall?sslmode=verify-full",
            "postgresql://bootstrap:@cluster.example:26257/fleet_recall?sslmode=verify-full",
            "postgresql://bootstrap:secret@cluster.example/fleet_recall?sslmode=verify-full",
            "postgresql://bootstrap:secret@cluster.example:0/fleet_recall?sslmode=verify-full",
            "postgresql://bootstrap:secret@cluster.example:26257?sslmode=verify-full",
            "postgresql://bootstrap:secret@cluster.example:26257///?sslmode=verify-full",
        ] {
            assert!(
                control_bootstrap_runtime_config(
                    database_url,
                    "0198a849-f6ae-7d61-9800-000000000001",
                    "physical-project",
                    "tenant.authority",
                    "project.authority",
                    FIXTURE_RECEIPT_DIGEST,
                )
                .is_err(),
                "accepted incomplete control database identity"
            );
        }
    }

    fn registry_activation_values() -> BTreeMap<&'static str, String> {
        BTreeMap::from([
            (
                "FLEET_RECALL_REGISTRY_DATABASE_URL",
                "postgresql://activation:registry-secret@cluster.example:26257/fleet_recall?sslmode=verify-full"
                    .into(),
            ),
            (
                "FLEET_RECALL_REGISTRY_TENANT_ID",
                "0198a849-f6ae-7d61-9800-000000000001".into(),
            ),
            ("FLEET_RECALL_REGISTRY_PROJECT", "physical-project".into()),
            (
                "FLEET_RECALL_REGISTRY_TENANT_NAMESPACE",
                "tenant.authority".into(),
            ),
            (
                "FLEET_RECALL_REGISTRY_PROJECT_NAMESPACE",
                "project.authority".into(),
            ),
            (
                "FLEET_RECALL_REGISTRY_BOOTSTRAP_RECEIPT_DIGEST",
                FIXTURE_RECEIPT_DIGEST.into(),
            ),
            (
                "FLEET_RECALL_REGISTRY_TEST_RESULT_DIGEST",
                FIXTURE_TEST_RESULT_DIGEST.into(),
            ),
            (
                "FLEET_RECALL_REGISTRY_TEST_RUNNER_ARTIFACT_DIGEST",
                FIXTURE_RUNNER_ARTIFACT_DIGEST.into(),
            ),
            (
                "FLEET_RECALL_REGISTRY_TEST_RUNNER_CONFIGURATION_DIGEST",
                FIXTURE_RUNNER_CONFIGURATION_DIGEST.into(),
            ),
            (
                "FLEET_RECALL_REGISTRY_PROPOSER_PRINCIPAL_ID",
                "principal.operator".into(),
            ),
            (
                "FLEET_RECALL_REGISTRY_PACKAGE_AUTHOR_PRINCIPAL_ID",
                "principal.author".into(),
            ),
        ])
    }

    #[test]
    fn private_registry_activation_config_is_fully_bound_and_redacted() {
        let values = registry_activation_values();
        let config = RegistryActivationRuntimeConfig::from_lookup(|name| values.get(name).cloned())
            .expect("private registry activation config");

        assert_eq!(
            config.authority().trusted_scope().tenant_id(),
            Uuid::parse_str("0198a849-f6ae-7d61-9800-000000000001").unwrap()
        );
        assert_eq!(
            config.authority().trusted_scope().project(),
            "physical-project"
        );
        assert_eq!(
            config
                .authority()
                .trusted_scope()
                .semantic_scope()
                .tenant_namespace
                .as_str(),
            "tenant.authority"
        );
        assert_eq!(
            config.authority().bootstrap_receipt_digest().to_string(),
            FIXTURE_RECEIPT_DIGEST
        );

        let debug = format!("{config:?}");
        for secret in [
            "registry-secret",
            FIXTURE_RECEIPT_DIGEST,
            FIXTURE_TEST_RESULT_DIGEST,
            FIXTURE_RUNNER_ARTIFACT_DIGEST,
            FIXTURE_RUNNER_CONFIGURATION_DIGEST,
            "principal.operator",
            "principal.author",
        ] {
            assert!(!debug.contains(secret));
        }
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn registry_activation_database_has_no_serving_or_bootstrap_fallback() {
        let mut values = registry_activation_values();
        values.remove("FLEET_RECALL_REGISTRY_DATABASE_URL");
        values.insert(
            "FLEET_RECALL_DATABASE_URL",
            "postgresql://serving:wrong@cluster.example/fleet?sslmode=verify-full".into(),
        );
        values.insert(
            "FLEET_RECALL_CONTROL_DATABASE_URL",
            "postgresql://bootstrap:wrong@cluster.example/fleet?sslmode=verify-full".into(),
        );

        let error = RegistryActivationRuntimeConfig::from_lookup(|name| values.get(name).cloned())
            .expect_err("dedicated registry database URL must be required");
        assert!(
            error
                .to_string()
                .contains("FLEET_RECALL_REGISTRY_DATABASE_URL is required")
        );
    }

    #[test]
    fn registry_activation_database_never_inherits_the_serving_tls_escape() {
        let mut values = registry_activation_values();
        values.insert(
            "FLEET_RECALL_REGISTRY_DATABASE_URL",
            "postgresql://activation:secret@127.0.0.1:26257/fleet_recall?sslmode=disable".into(),
        );

        let error = RegistryActivationRuntimeConfig::from_lookup(|name| values.get(name).cloned())
            .expect_err("private activation must require full TLS even on loopback");
        assert!(
            error.to_string().contains(
                "FLEET_RECALL_REGISTRY_DATABASE_URL must set exactly sslmode=verify-full"
            )
        );
    }

    #[test]
    fn private_registry_database_requires_explicit_connection_identity() {
        for database_url in [
            "postgresql://:secret@cluster.example:26257/fleet_recall?sslmode=verify-full",
            "postgresql://activation@cluster.example:26257/fleet_recall?sslmode=verify-full",
            "postgresql://activation:@cluster.example:26257/fleet_recall?sslmode=verify-full",
            "postgresql://activation:secret@cluster.example/fleet_recall?sslmode=verify-full",
            "postgresql://activation:secret@cluster.example:0/fleet_recall?sslmode=verify-full",
            "postgresql://activation:secret@cluster.example:26257?sslmode=verify-full",
            "postgresql://activation:secret@cluster.example:26257///?sslmode=verify-full",
        ] {
            let mut values = registry_activation_values();
            values.insert("FLEET_RECALL_REGISTRY_DATABASE_URL", database_url.into());
            assert!(
                RegistryActivationRuntimeConfig::from_lookup(|name| values.get(name).cloned())
                    .is_err(),
                "accepted incomplete registry database identity"
            );
        }
    }

    #[test]
    fn registry_activation_rejects_encoded_unix_socket_host_before_tls_acceptance() {
        let mut values = registry_activation_values();
        values.insert(
            "FLEET_RECALL_REGISTRY_DATABASE_URL",
            "postgresql://activation:secret@%2Fvar%2Frun%2Fpostgres/fleet_recall?sslmode=verify-full"
                .into(),
        );

        let error = RegistryActivationRuntimeConfig::from_lookup(|name| values.get(name).cloned())
            .expect_err("encoded Unix-socket routing must not satisfy strict TLS policy");
        assert!(matches!(&error, FleetError::Configuration(_)));
        assert!(
            error.to_string().contains("encoded or Unix-socket host"),
            "wrong encoded-host error: {error}"
        );
    }

    #[test]
    fn registry_activation_authority_rejects_noncanonical_pins_and_ids() {
        let mut values = registry_activation_values();
        values.insert(
            "FLEET_RECALL_REGISTRY_TEST_RESULT_DIGEST",
            FIXTURE_TEST_RESULT_DIGEST.to_ascii_uppercase(),
        );
        assert!(
            RegistryActivationRuntimeConfig::from_lookup(|name| values.get(name).cloned()).is_err()
        );

        let mut values = registry_activation_values();
        values.insert(
            "FLEET_RECALL_REGISTRY_PROPOSER_PRINCIPAL_ID",
            "Principal.Invalid".into(),
        );
        assert!(
            RegistryActivationRuntimeConfig::from_lookup(|name| values.get(name).cloned()).is_err()
        );
    }

    const SUCCESSOR_VARIABLES: [&str; 17] = [
        "FLEET_RECALL_SUCCESSOR_DATABASE_URL",
        "FLEET_RECALL_SUCCESSOR_TENANT_ID",
        "FLEET_RECALL_SUCCESSOR_PROJECT",
        "FLEET_RECALL_SUCCESSOR_TENANT_NAMESPACE",
        "FLEET_RECALL_SUCCESSOR_PROJECT_NAMESPACE",
        "FLEET_RECALL_SUCCESSOR_BOOTSTRAP_RECEIPT_DIGEST",
        "FLEET_RECALL_SUCCESSOR_GENESIS_TEST_RESULT_DIGEST",
        "FLEET_RECALL_SUCCESSOR_GENESIS_TEST_RUNNER_ARTIFACT_DIGEST",
        "FLEET_RECALL_SUCCESSOR_GENESIS_TEST_RUNNER_CONFIGURATION_DIGEST",
        "FLEET_RECALL_SUCCESSOR_TARGET_TEST_RESULT_DIGEST",
        "FLEET_RECALL_SUCCESSOR_TARGET_TEST_RUNNER_ARTIFACT_DIGEST",
        "FLEET_RECALL_SUCCESSOR_TARGET_TEST_RUNNER_CONFIGURATION_DIGEST",
        "FLEET_RECALL_SUCCESSOR_GENESIS_KEY_BRIDGE_DIGEST",
        "FLEET_RECALL_SUCCESSOR_GENESIS_PROPOSER_PRINCIPAL_ID",
        "FLEET_RECALL_SUCCESSOR_GENESIS_PACKAGE_AUTHOR_PRINCIPAL_ID",
        "FLEET_RECALL_SUCCESSOR_PROPOSER_PRINCIPAL_ID",
        "FLEET_RECALL_SUCCESSOR_PACKAGE_AUTHOR_PRINCIPAL_ID",
    ];

    fn successor_activation_values() -> BTreeMap<&'static str, String> {
        BTreeMap::from([
            (
                "FLEET_RECALL_SUCCESSOR_DATABASE_URL",
                "postgresql://successor:successor-secret@cluster.example:26257/fleet_recall?sslmode=verify-full"
                    .into(),
            ),
            (
                "FLEET_RECALL_SUCCESSOR_TENANT_ID",
                "0198a849-f6ae-7d61-9800-000000000001".into(),
            ),
            (
                "FLEET_RECALL_SUCCESSOR_PROJECT",
                "physical-project".into(),
            ),
            (
                "FLEET_RECALL_SUCCESSOR_TENANT_NAMESPACE",
                "tenant.authority".into(),
            ),
            (
                "FLEET_RECALL_SUCCESSOR_PROJECT_NAMESPACE",
                "project.authority".into(),
            ),
            (
                "FLEET_RECALL_SUCCESSOR_BOOTSTRAP_RECEIPT_DIGEST",
                FIXTURE_RECEIPT_DIGEST.into(),
            ),
            (
                "FLEET_RECALL_SUCCESSOR_GENESIS_TEST_RESULT_DIGEST",
                FIXTURE_TEST_RESULT_DIGEST.into(),
            ),
            (
                "FLEET_RECALL_SUCCESSOR_GENESIS_TEST_RUNNER_ARTIFACT_DIGEST",
                FIXTURE_RUNNER_ARTIFACT_DIGEST.into(),
            ),
            (
                "FLEET_RECALL_SUCCESSOR_GENESIS_TEST_RUNNER_CONFIGURATION_DIGEST",
                FIXTURE_RUNNER_CONFIGURATION_DIGEST.into(),
            ),
            (
                "FLEET_RECALL_SUCCESSOR_TARGET_TEST_RESULT_DIGEST",
                FIXTURE_TARGET_TEST_RESULT_DIGEST.into(),
            ),
            (
                "FLEET_RECALL_SUCCESSOR_TARGET_TEST_RUNNER_ARTIFACT_DIGEST",
                FIXTURE_TARGET_RUNNER_ARTIFACT_DIGEST.into(),
            ),
            (
                "FLEET_RECALL_SUCCESSOR_TARGET_TEST_RUNNER_CONFIGURATION_DIGEST",
                FIXTURE_TARGET_RUNNER_CONFIGURATION_DIGEST.into(),
            ),
            (
                "FLEET_RECALL_SUCCESSOR_GENESIS_KEY_BRIDGE_DIGEST",
                FIXTURE_GENESIS_KEY_BRIDGE_DIGEST.into(),
            ),
            (
                "FLEET_RECALL_SUCCESSOR_GENESIS_PROPOSER_PRINCIPAL_ID",
                "principal.genesis_operator".into(),
            ),
            (
                "FLEET_RECALL_SUCCESSOR_GENESIS_PACKAGE_AUTHOR_PRINCIPAL_ID",
                "principal.genesis_author".into(),
            ),
            (
                "FLEET_RECALL_SUCCESSOR_PROPOSER_PRINCIPAL_ID",
                "principal.successor_operator".into(),
            ),
            (
                "FLEET_RECALL_SUCCESSOR_PACKAGE_AUTHOR_PRINCIPAL_ID",
                "principal.successor_author".into(),
            ),
        ])
    }

    fn successor_configuration_error(
        values: &BTreeMap<&'static str, String>,
        context: &str,
    ) -> FleetError {
        let error = SuccessorActivationRuntimeConfig::from_lookup(|name| values.get(name).cloned())
            .expect_err(context);
        assert!(
            matches!(&error, FleetError::Configuration(_)),
            "successor environment ingestion returned a non-configuration error: {error:?}"
        );
        error
    }

    #[test]
    fn private_successor_activation_config_is_fully_bound() {
        let values = successor_activation_values();
        let config =
            SuccessorActivationRuntimeConfig::from_lookup(|name| values.get(name).cloned())
                .expect("private successor activation config");
        let authority = config.authority();

        assert_eq!(
            authority.trusted_scope().tenant_id(),
            Uuid::parse_str("0198a849-f6ae-7d61-9800-000000000001").unwrap()
        );
        assert_eq!(authority.trusted_scope().project(), "physical-project");
        assert_eq!(
            authority
                .trusted_scope()
                .semantic_scope()
                .tenant_namespace
                .as_str(),
            "tenant.authority"
        );
        assert_eq!(
            authority
                .trusted_scope()
                .semantic_scope()
                .project_namespace
                .as_str(),
            "project.authority"
        );
        assert_eq!(
            authority.bootstrap_receipt_digest().to_string(),
            FIXTURE_RECEIPT_DIGEST
        );
        assert_eq!(
            authority.bootstrap_pin(),
            BootstrapPin::from_trusted_config(BootstrapReceiptDigest::from_digest(
                parse_digest(FIXTURE_RECEIPT_DIGEST, "fixture").unwrap(),
            ))
        );
        assert_eq!(
            authority.genesis_test_runner_pin(),
            RegistryTestRunnerPin::from_trusted_config(
                parse_digest(FIXTURE_RUNNER_ARTIFACT_DIGEST, "fixture").unwrap(),
                parse_digest(FIXTURE_RUNNER_CONFIGURATION_DIGEST, "fixture").unwrap(),
                RegistryTestResultDigest::from_digest(
                    parse_digest(FIXTURE_TEST_RESULT_DIGEST, "fixture").unwrap(),
                ),
            )
        );
        assert_eq!(
            authority.target_test_runner_pin(),
            SuccessorRegistryTestRunnerPin::from_trusted_config(
                parse_digest(FIXTURE_TARGET_RUNNER_ARTIFACT_DIGEST, "fixture").unwrap(),
                parse_digest(FIXTURE_TARGET_RUNNER_CONFIGURATION_DIGEST, "fixture",).unwrap(),
                RegistryTestResultDigest::from_digest(
                    parse_digest(FIXTURE_TARGET_TEST_RESULT_DIGEST, "fixture").unwrap(),
                ),
            )
        );
        assert_eq!(
            authority.genesis_key_bridge_digest().to_string(),
            FIXTURE_GENESIS_KEY_BRIDGE_DIGEST
        );
        assert_eq!(
            authority.genesis_key_bridge_pin(),
            GenesisSuccessorKeyBridgePin::from_trusted_config(
                GenesisSuccessorKeyBridgeDigest::from_digest(
                    parse_digest(FIXTURE_GENESIS_KEY_BRIDGE_DIGEST, "fixture").unwrap(),
                ),
            )
        );
        assert_eq!(
            authority.genesis_principal_binding(),
            GenesisActivationPrincipalBinding::from_trusted_config(
                ContractId::new("principal.genesis_operator").unwrap(),
                ContractId::new("principal.genesis_author").unwrap(),
            )
        );
        assert_eq!(
            authority.successor_principal_binding(),
            SuccessorActivationPrincipalBinding::from_trusted_config(
                ContractId::new("principal.successor_operator").unwrap(),
                ContractId::new("principal.successor_author").unwrap(),
            )
        );
        assert!(config.database_url().contains("successor-secret"));
    }

    #[test]
    fn successor_activation_debug_redacts_credentials_pins_and_principals() {
        let values = successor_activation_values();
        let config =
            SuccessorActivationRuntimeConfig::from_lookup(|name| values.get(name).cloned())
                .unwrap();
        let debug = format!("{config:?}");
        for secret in [
            config.database_url(),
            "successor",
            "successor-secret",
            "cluster.example",
            "fleet_recall",
            FIXTURE_RECEIPT_DIGEST,
            FIXTURE_TEST_RESULT_DIGEST,
            FIXTURE_RUNNER_ARTIFACT_DIGEST,
            FIXTURE_RUNNER_CONFIGURATION_DIGEST,
            FIXTURE_TARGET_TEST_RESULT_DIGEST,
            FIXTURE_TARGET_RUNNER_ARTIFACT_DIGEST,
            FIXTURE_TARGET_RUNNER_CONFIGURATION_DIGEST,
            FIXTURE_GENESIS_KEY_BRIDGE_DIGEST,
            "principal.genesis_operator",
            "principal.genesis_author",
            "principal.successor_operator",
            "principal.successor_author",
        ] {
            assert!(!debug.contains(secret), "debug exposed {secret}");
        }
        assert!(debug.contains("<redacted>"));
        assert!(debug.contains("<bound>"));
    }

    #[test]
    fn successor_activation_requires_every_exact_namespaced_variable() {
        for missing in SUCCESSOR_VARIABLES {
            let mut values = successor_activation_values();
            values.remove(missing);
            let error = successor_configuration_error(
                &values,
                "every exact successor variable must be required",
            );
            assert!(
                error
                    .to_string()
                    .contains(&format!("{missing} is required")),
                "wrong error for {missing}: {error}"
            );
        }

        let values = successor_activation_values();
        let mut requested = Vec::new();
        SuccessorActivationRuntimeConfig::from_lookup(|name| {
            assert!(
                SUCCESSOR_VARIABLES.contains(&name),
                "looked up an unrelated or fallback variable {name}"
            );
            requested.push(name.to_owned());
            values.get(name).cloned()
        })
        .unwrap();
        assert_eq!(requested, SUCCESSOR_VARIABLES);
        assert!(
            requested
                .iter()
                .all(|name| name.starts_with("FLEET_RECALL_SUCCESSOR_"))
        );
    }

    #[test]
    fn successor_activation_has_no_legacy_or_generic_fallbacks() {
        let mut values = successor_activation_values();
        values.remove("FLEET_RECALL_SUCCESSOR_DATABASE_URL");
        values.insert(
            "FLEET_RECALL_DATABASE_URL",
            "postgresql://serving:wrong@cluster.example/fleet?sslmode=verify-full".into(),
        );
        values.insert(
            "FLEET_RECALL_CONTROL_DATABASE_URL",
            "postgresql://bootstrap:wrong@cluster.example/fleet?sslmode=verify-full".into(),
        );
        values.insert(
            "FLEET_RECALL_REGISTRY_DATABASE_URL",
            "postgresql://genesis:wrong@cluster.example/fleet?sslmode=verify-full".into(),
        );
        let error =
            successor_configuration_error(&values, "successor database must never fall back");
        assert!(
            error
                .to_string()
                .contains("FLEET_RECALL_SUCCESSOR_DATABASE_URL is required")
        );

        let mut values = successor_activation_values();
        values.remove("FLEET_RECALL_SUCCESSOR_GENESIS_KEY_BRIDGE_DIGEST");
        values.insert(
            "FLEET_RECALL_SUCCESSOR_BRIDGE_DIGEST",
            FIXTURE_GENESIS_KEY_BRIDGE_DIGEST.into(),
        );
        let error = successor_configuration_error(
            &values,
            "generic bridge alias must not supply authority",
        );
        assert!(
            error
                .to_string()
                .contains("FLEET_RECALL_SUCCESSOR_GENESIS_KEY_BRIDGE_DIGEST is required")
        );
    }

    #[test]
    fn successor_activation_rejects_noncanonical_digests_ids_and_scope() {
        for name in [
            "FLEET_RECALL_SUCCESSOR_BOOTSTRAP_RECEIPT_DIGEST",
            "FLEET_RECALL_SUCCESSOR_GENESIS_TEST_RESULT_DIGEST",
            "FLEET_RECALL_SUCCESSOR_GENESIS_TEST_RUNNER_ARTIFACT_DIGEST",
            "FLEET_RECALL_SUCCESSOR_GENESIS_TEST_RUNNER_CONFIGURATION_DIGEST",
            "FLEET_RECALL_SUCCESSOR_TARGET_TEST_RESULT_DIGEST",
            "FLEET_RECALL_SUCCESSOR_TARGET_TEST_RUNNER_ARTIFACT_DIGEST",
            "FLEET_RECALL_SUCCESSOR_TARGET_TEST_RUNNER_CONFIGURATION_DIGEST",
            "FLEET_RECALL_SUCCESSOR_GENESIS_KEY_BRIDGE_DIGEST",
        ] {
            let mut values = successor_activation_values();
            let noncanonical = values.get(name).unwrap().to_ascii_uppercase();
            values.insert(name, noncanonical);
            successor_configuration_error(&values, &format!("accepted noncanonical {name}"));
        }

        for name in [
            "FLEET_RECALL_SUCCESSOR_TENANT_NAMESPACE",
            "FLEET_RECALL_SUCCESSOR_PROJECT_NAMESPACE",
            "FLEET_RECALL_SUCCESSOR_GENESIS_PROPOSER_PRINCIPAL_ID",
            "FLEET_RECALL_SUCCESSOR_GENESIS_PACKAGE_AUTHOR_PRINCIPAL_ID",
            "FLEET_RECALL_SUCCESSOR_PROPOSER_PRINCIPAL_ID",
            "FLEET_RECALL_SUCCESSOR_PACKAGE_AUTHOR_PRINCIPAL_ID",
        ] {
            let mut values = successor_activation_values();
            values.insert(name, "Principal.Invalid".into());
            successor_configuration_error(&values, &format!("accepted noncanonical {name}"));
        }

        for (name, value) in [
            ("FLEET_RECALL_SUCCESSOR_TENANT_ID", "not-a-uuid"),
            (
                "FLEET_RECALL_SUCCESSOR_TENANT_ID",
                "00000000-0000-0000-0000-000000000000",
            ),
            ("FLEET_RECALL_SUCCESSOR_PROJECT", " physical-project "),
        ] {
            let mut values = successor_activation_values();
            values.insert(name, value.into());
            successor_configuration_error(
                &values,
                &format!("accepted invalid physical scope {name}"),
            );
        }
    }

    #[test]
    fn successor_activation_database_url_accepts_only_strict_tls_parameters() {
        let mut values = successor_activation_values();
        values.insert(
            "FLEET_RECALL_SUCCESSOR_DATABASE_URL",
            "postgresql://successor:secret@cluster.example:26257/fleet_recall?sslmode=verify-full&sslrootcert=%2Fetc%2Fssl%2Fcerts%2Fca.pem".into(),
        );
        assert!(
            SuccessorActivationRuntimeConfig::from_lookup(|name| values.get(name).cloned()).is_ok()
        );

        for url in [
            "https://successor:secret@cluster.example:26257/fleet_recall?sslmode=verify-full",
            "cockroachdb://successor:secret@cluster.example:26257/fleet_recall?sslmode=verify-full",
            "postgresql:///fleet_recall?sslmode=verify-full",
            "postgresql://successor:secret@cluster.example:26257/fleet_recall",
            "postgresql://successor:secret@cluster.example:26257/fleet_recall?sslmode=require",
            "postgresql://successor:secret@127.0.0.1:26257/fleet_recall?sslmode=disable",
            "postgresql://successor:secret@cluster.example:26257/fleet_recall?ssl-mode=verify-full",
            "postgresql://successor:secret@cluster.example:26257/fleet_recall?sslmode=verify-full&ssl-root-cert=/tmp/ca.pem",
            "postgresql://successor:secret@cluster.example:26257/fleet_recall?sslmode=verify-full&sslmode=disable",
            "postgresql://successor:secret@cluster.example:26257/fleet_recall?sslmode=verify-full&sslrootcert=/tmp/one.pem&sslrootcert=/tmp/two.pem",
            "postgresql://successor:secret@cluster.example:26257/fleet_recall?sslmode=verify-full&sslrootcert=relative.pem",
            "postgresql://successor:secret@cluster.example:26257/fleet_recall?sslmode=verify-full&host=attacker.example",
            "postgresql://successor:secret@cluster.example:26257/fleet_recall?sslmode=verify-full&hostaddr=127.0.0.1",
            "postgresql://successor:secret@cluster.example:26257/fleet_recall?sslmode=verify-full&options=-csearch_path%3Dattacker",
            "postgresql://successor:secret@cluster.example:26257/fleet_recall?sslmode=verify-full&user=other",
            "postgresql://successor:secret@cluster.example:26257/fleet_recall?sslmode=verify-full&port=5432",
            "postgresql://successor:secret@cluster.example:26257/fleet_recall?sslmode=verify-full&application_name=other",
            "postgresql://successor:secret@cluster.example:26257/fleet_recall?sslmode=verify-full&unknown=value",
            "postgresql://successor:secret@cluster.example:26257/fleet_recall?sslmode=verify-full#ignored",
        ] {
            let mut values = successor_activation_values();
            values.insert("FLEET_RECALL_SUCCESSOR_DATABASE_URL", url.into());
            successor_configuration_error(&values, &format!("accepted unsafe successor URL {url}"));
        }
    }

    #[test]
    fn successor_activation_database_url_requires_explicit_connection_identity() {
        for url in [
            "postgresql://:secret@cluster.example:26257/fleet_recall?sslmode=verify-full",
            "postgresql://successor@cluster.example:26257/fleet_recall?sslmode=verify-full",
            "postgresql://successor:@cluster.example:26257/fleet_recall?sslmode=verify-full",
            "postgresql://successor:secret@cluster.example/fleet_recall?sslmode=verify-full",
            "postgresql://successor:secret@cluster.example:0/fleet_recall?sslmode=verify-full",
            "postgresql://successor:secret@cluster.example:26257?sslmode=verify-full",
            "postgresql://successor:secret@cluster.example:26257/?sslmode=verify-full",
            "postgresql://successor:secret@cluster.example:26257//?sslmode=verify-full",
            "postgresql://successor:secret@cluster.example:26257///?sslmode=verify-full",
        ] {
            let mut values = successor_activation_values();
            values.insert("FLEET_RECALL_SUCCESSOR_DATABASE_URL", url.into());
            successor_configuration_error(
                &values,
                &format!("accepted URL with implicit connection identity {url}"),
            );
        }
    }

    #[test]
    fn successor_activation_database_name_is_exact_and_canonical() {
        for database_path in [
            "fleet",
            "defaultdb",
            "fleet_recall/",
            "fleet_recall/other",
            "%66leet_recall",
            "fleet%5Frecall",
        ] {
            let mut values = successor_activation_values();
            values.insert(
                "FLEET_RECALL_SUCCESSOR_DATABASE_URL",
                format!(
                    "postgresql://successor:secret@cluster.example:26257/{database_path}?sslmode=verify-full"
                ),
            );
            let error = successor_configuration_error(
                &values,
                &format!("accepted noncanonical successor database path {database_path}"),
            );
            assert!(
                error
                    .to_string()
                    .contains("must select exactly the fleet_recall database"),
                "wrong database-name error for {database_path}: {error}"
            );
        }
    }

    #[test]
    fn successor_activation_rejects_encoded_unix_socket_and_non_dns_hosts() {
        for url in [
            "postgresql://successor:secret@%2Fvar%2Frun%2Fpostgres/fleet_recall?sslmode=verify-full",
            "postgresql://successor:secret@%2Fvar%2Frun%2Fpostgres:26257/fleet_recall?sslmode=verify-full",
            "postgresql://successor:secret@%2fvar%2frun%2fpostgres:26257/fleet_recall?sslmode=verify-full",
            "postgresql://successor:secret@%252Fvar%252Frun%252Fpostgres:26257/fleet_recall?sslmode=verify-full",
            "postgresql://successor:secret@%5C%5Cserver%5Csocket:26257/fleet_recall?sslmode=verify-full",
            "postgresql://successor:secret@bad_host.example:26257/fleet_recall?sslmode=verify-full",
            "postgresql://successor:secret@-bad.example:26257/fleet_recall?sslmode=verify-full",
            "postgresql://successor:secret@bad..example:26257/fleet_recall?sslmode=verify-full",
        ] {
            let mut values = successor_activation_values();
            values.insert("FLEET_RECALL_SUCCESSOR_DATABASE_URL", url.into());
            let error = successor_configuration_error(
                &values,
                &format!("accepted encoded, socket, or non-DNS host {url}"),
            );
            assert!(
                error.to_string().contains("ordinary DNS or IP hostname")
                    || error.to_string().contains("encoded or Unix-socket host"),
                "wrong closed-host error for {url}: {error}"
            );
        }
    }

    #[test]
    fn successor_activation_allows_network_ips_only_with_verify_full() {
        for url in [
            "postgresql://successor:secret@127.0.0.1:26257/fleet_recall?sslmode=verify-full",
            "postgresql://successor:secret@[::1]:26257/fleet_recall?sslmode=verify-full",
        ] {
            let mut values = successor_activation_values();
            values.insert("FLEET_RECALL_SUCCESSOR_DATABASE_URL", url.into());
            SuccessorActivationRuntimeConfig::from_lookup(|name| values.get(name).cloned())
                .unwrap_or_else(|error| panic!("rejected strict-TLS network IP {url}: {error}"));
        }
    }

    const RECONCILIATION_VARIABLES: [&str; 3] = [
        "FLEET_RECALL_RECONCILIATION_DATABASE_URL",
        "FLEET_RECALL_RECONCILIATION_TENANT_ID",
        "FLEET_RECALL_RECONCILIATION_PROJECT",
    ];

    fn reconciliation_values() -> BTreeMap<&'static str, String> {
        BTreeMap::from([
            (
                "FLEET_RECALL_RECONCILIATION_DATABASE_URL",
                "postgresql://reconciler:reconciliation-secret@cluster.example:26257/fleet_recall?sslmode=verify-full".into(),
            ),
            (
                "FLEET_RECALL_RECONCILIATION_TENANT_ID",
                "0198a849-f6ae-7d61-9800-000000000001".into(),
            ),
            (
                "FLEET_RECALL_RECONCILIATION_PROJECT",
                "physical-project".into(),
            ),
        ])
    }

    #[test]
    fn reconciliation_runtime_config_is_scope_bound_and_redacted() {
        let values = reconciliation_values();
        let config =
            ConflictReconciliationRuntimeConfig::from_lookup(|name| values.get(name).cloned())
                .expect("private conflict-reconciliation config");

        assert_eq!(
            config.trusted_scope().tenant_id,
            Uuid::parse_str("0198a849-f6ae-7d61-9800-000000000001").unwrap()
        );
        assert_eq!(config.trusted_scope().project, "physical-project");
        assert_eq!(
            config.trusted_scope().agent,
            "private-conflict-reconciliation"
        );
        assert_eq!(config.trusted_scope().session_id, None);
        assert_eq!(config.trusted_scope().privacy_tier, PrivacyTier::T1Project);

        let debug = format!("{config:?}");
        for secret in [
            config.database_url(),
            "reconciler",
            "reconciliation-secret",
            "cluster.example",
            "physical-project",
            "0198a849-f6ae-7d61-9800-000000000001",
        ] {
            assert!(!debug.contains(secret), "debug exposed {secret}");
        }
        assert!(debug.contains("<redacted>"));
        assert!(debug.contains("<bound>"));
    }

    #[test]
    fn reconciliation_uses_only_its_exact_dedicated_variables() {
        let values = reconciliation_values();
        let mut requested = Vec::new();
        ConflictReconciliationRuntimeConfig::from_lookup(|name| {
            assert!(
                RECONCILIATION_VARIABLES.contains(&name),
                "looked up unrelated or fallback variable {name}"
            );
            requested.push(name.to_owned());
            values.get(name).cloned()
        })
        .expect("dedicated reconciliation variables");
        assert_eq!(requested, RECONCILIATION_VARIABLES);

        for missing in RECONCILIATION_VARIABLES {
            let mut values = reconciliation_values();
            values.remove(missing);
            values.insert(
                "FLEET_RECALL_DATABASE_URL",
                "postgresql://serving:wrong@cluster.example:26257/fleet?sslmode=verify-full".into(),
            );
            values.insert("FLEET_RECALL_TENANT_ID", Uuid::now_v7().to_string());
            values.insert("FLEET_RECALL_PROJECT", "serving-project".into());
            let error =
                ConflictReconciliationRuntimeConfig::from_lookup(|name| values.get(name).cloned())
                    .expect_err(
                        "generic serving variables must not supply reconciliation authority",
                    );
            assert!(
                error
                    .to_string()
                    .contains(&format!("{missing} is required")),
                "wrong error for {missing}: {error}"
            );
        }
    }

    #[test]
    fn reconciliation_database_requires_strict_tls_and_explicit_identity() {
        for url in [
            "postgresql://reconciler:secret@cluster.example:26257/fleet?sslmode=verify-full",
            "postgresql://reconciler:secret@127.0.0.1:26257/fleet?sslmode=verify-full",
            "postgresql://reconciler:secret@[::1]:26257/fleet?sslmode=verify-full&sslrootcert=%2Fetc%2Fssl%2Fcerts%2Fca.pem",
        ] {
            let mut values = reconciliation_values();
            values.insert("FLEET_RECALL_RECONCILIATION_DATABASE_URL", url.into());
            ConflictReconciliationRuntimeConfig::from_lookup(|name| values.get(name).cloned())
                .unwrap_or_else(|error| {
                    panic!("rejected closed reconciliation URL {url}: {error}")
                });
        }

        for url in [
            "https://reconciler:secret@cluster.example:26257/fleet?sslmode=verify-full",
            "postgresql://reconciler:secret@cluster.example:26257/fleet",
            "postgresql://reconciler:secret@cluster.example:26257/fleet?sslmode=disable",
            "postgresql://reconciler:secret@cluster.example:26257/fleet?sslmode=require",
            "postgresql://reconciler:secret@cluster.example:26257/fleet?sslmode=verify-full&options=-csearch_path%3Dattacker",
            "postgresql://reconciler:secret@cluster.example:26257/fleet?sslmode=verify-full&sslmode=disable",
            "postgresql://:secret@cluster.example:26257/fleet?sslmode=verify-full",
            "postgresql://reconciler@cluster.example:26257/fleet?sslmode=verify-full",
            "postgresql://reconciler:@cluster.example:26257/fleet?sslmode=verify-full",
            "postgresql://reconciler:secret@cluster.example/fleet?sslmode=verify-full",
            "postgresql://reconciler:secret@cluster.example:0/fleet?sslmode=verify-full",
            "postgresql://reconciler:secret@cluster.example:26257/?sslmode=verify-full",
            "postgresql://reconciler:secret@%2Fvar%2Frun%2Fpostgres:26257/fleet?sslmode=verify-full",
            "postgresql://reconciler:secret@bad_host.example:26257/fleet?sslmode=verify-full",
            "postgresql://reconciler:secret@-bad.example:26257/fleet?sslmode=verify-full",
        ] {
            let mut values = reconciliation_values();
            values.insert("FLEET_RECALL_RECONCILIATION_DATABASE_URL", url.into());
            assert!(
                ConflictReconciliationRuntimeConfig::from_lookup(|name| values.get(name).cloned())
                    .is_err(),
                "accepted unsafe reconciliation URL {url}"
            );
        }
    }

    #[test]
    fn reconciliation_rejects_invalid_physical_scope() {
        for (name, value) in [
            ("FLEET_RECALL_RECONCILIATION_TENANT_ID", "not-a-uuid"),
            (
                "FLEET_RECALL_RECONCILIATION_TENANT_ID",
                "00000000-0000-0000-0000-000000000000",
            ),
            ("FLEET_RECALL_RECONCILIATION_PROJECT", " physical-project "),
        ] {
            let mut values = reconciliation_values();
            values.insert(name, value.into());
            assert!(
                ConflictReconciliationRuntimeConfig::from_lookup(|name| values.get(name).cloned())
                    .is_err(),
                "accepted invalid reconciliation scope {name}"
            );
        }
    }
}
