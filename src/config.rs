use std::env;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use ostk_recall_core::PrivacyTier;
use sha2::{Digest, Sha256};
use url::Url;
use uuid::Uuid;

use crate::control_log::TrustedControlScope;
use crate::memory_contracts::bootstrap::{BootstrapPin, BootstrapReceiptDigest};
use crate::memory_contracts::common::{AuthenticatedProjectScopeV1, ContractId};
use crate::memory_contracts::digest::Sha256Digest;
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
    authority: ControlBootstrapConfig,
}

impl std::fmt::Debug for ControlBootstrapRuntimeConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ControlBootstrapRuntimeConfig")
            .field("database_url", &"<redacted>")
            .field("authority", &self.authority)
            .finish()
    }
}

impl ControlBootstrapRuntimeConfig {
    /// Read only the database, physical scope, semantic scope, and receipt pin
    /// needed by the private control bootstrap process.
    pub fn from_env() -> Result<Self> {
        control_bootstrap_runtime_config(
            &required("FLEET_RECALL_DATABASE_URL")?,
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
    pub const fn authority(&self) -> &ControlBootstrapConfig {
        &self.authority
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

impl FleetConfig {
    pub fn from_env() -> Result<Self> {
        let database_url = required("FLEET_RECALL_DATABASE_URL")?;
        validate_database_url(&database_url)?;
        let tenant_id = required("FLEET_RECALL_TENANT_ID")?
            .parse::<Uuid>()
            .map_err(|error| {
                FleetError::Configuration(format!("FLEET_RECALL_TENANT_ID must be a UUID: {error}"))
            })?;
        let project = required("FLEET_RECALL_PROJECT")?;
        let agent = required("FLEET_RECALL_AGENT")?;
        let max_connections = env::var("FLEET_RECALL_MAX_CONNECTIONS")
            .unwrap_or_else(|_| "16".into())
            .parse::<u32>()
            .map_err(|error| {
                FleetError::Configuration(format!(
                    "FLEET_RECALL_MAX_CONNECTIONS must be an integer: {error}"
                ))
            })?;
        let embedding_model = env::var("FLEET_RECALL_EMBEDDING_MODEL")
            .unwrap_or_else(|_| "minishlab/potion-retrieval-32M".into());
        let embedding_model_path = PathBuf::from(required("FLEET_RECALL_EMBEDDING_MODEL_PATH")?);
        let embedding_model_sha256 = required("FLEET_RECALL_EMBEDDING_MODEL_SHA256")?;

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

        Ok(Self {
            database_url,
            default_scope: FleetScope::new(
                tenant_id,
                project,
                agent,
                None,
                PrivacyTier::T1Project,
            )?,
            max_connections,
            embedding_model: embedding_model.to_owned(),
            embedding_model_path,
            embedding_model_sha256: embedding_model_sha256.to_ascii_lowercase(),
        })
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
    validate_database_url(database_url)?;
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
        authority: control_bootstrap_config(
            &deployment_scope,
            tenant_namespace,
            project_namespace,
            receipt_digest,
        )?,
    })
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

fn validate_database_url(database_url: &str) -> Result<()> {
    let parsed = Url::parse(database_url).map_err(|error| {
        FleetError::Configuration(format!(
            "FLEET_RECALL_DATABASE_URL must be a valid PostgreSQL URL: {error}"
        ))
    })?;
    if !matches!(parsed.scheme(), "postgres" | "postgresql") {
        return Err(FleetError::Configuration(
            "FLEET_RECALL_DATABASE_URL must use the postgres or postgresql scheme".into(),
        ));
    }
    let host = parsed.host_str().ok_or_else(|| {
        FleetError::Configuration("FLEET_RECALL_DATABASE_URL must include a hostname".into())
    })?;
    let ssl_modes = parsed
        .query_pairs()
        .filter(|(name, _)| name == "sslmode")
        .map(|(_, value)| value.into_owned())
        .collect::<Vec<_>>();
    if ssl_modes.as_slice() == ["verify-full"] {
        return Ok(());
    }

    let local_escape =
        env::var("FLEET_RECALL_ALLOW_INSECURE_LOCAL_DATABASE").is_ok_and(|value| value == "1");
    let local_host = matches!(host, "localhost" | "127.0.0.1" | "::1" | "cockroach");
    if local_escape && local_host {
        return Ok(());
    }
    Err(FleetError::Configuration(
        "FLEET_RECALL_DATABASE_URL must set sslmode=verify-full; local development may set FLEET_RECALL_ALLOW_INSECURE_LOCAL_DATABASE=1 only for a loopback or `cockroach` host"
            .into(),
    ))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    const FIXTURE_RECEIPT_DIGEST: &str =
        "084ee06ea7ebf3b1d592d6e5843584485144c0ee5720fcc2124a61a7fcde48f0";

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

    #[test]
    fn cloud_database_urls_require_full_tls_verification() {
        assert!(
            validate_database_url(
                "postgresql://user:secret@cluster.example:26257/defaultdb?sslmode=verify-full"
            )
            .is_ok()
        );
        assert!(
            validate_database_url(
                "postgresql://user:secret@cluster.example:26257/defaultdb?sslmode=require"
            )
            .is_err()
        );
        assert!(
            validate_database_url(
                "postgresql://user:secret@cluster.example:26257/defaultdb?sslmode=disable"
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
        let debug = format!("{config:?}");
        assert!(!debug.contains("bootstrap:secret"));
        assert!(!debug.contains(FIXTURE_RECEIPT_DIGEST));
        assert!(debug.contains("<redacted>"));
    }
}
