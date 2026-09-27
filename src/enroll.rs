//! Enrollment command helpers. The caller supplies the dedicated enrollment pool.
use crate::auth::registry::{
    ApplyReport, DeclarationFile, PrincipalRegistry, RegistryError, declared_scopes,
    validate_declarations,
};
use crate::store::cockroach::CockroachStore;
use serde::Serialize;
use sqlx::PgPool;
use std::path::Path;

pub const MAX_ENROLLMENT_FILE_BYTES: u64 = 1024 * 1024;

pub fn read_declarations(path: &Path) -> Result<DeclarationFile, RegistryError> {
    use std::io::Read as _;
    let file = std::fs::File::open(path)
        .map_err(|e| RegistryError::Invalid(format!("cannot read enrollment file: {e}")))?;
    let mut bytes = Vec::new();
    file.take(MAX_ENROLLMENT_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| RegistryError::Invalid(format!("cannot read enrollment file: {e}")))?;
    if bytes.len() as u64 > MAX_ENROLLMENT_FILE_BYTES {
        return Err(RegistryError::Invalid(
            "enrollment file exceeds 1 MiB".into(),
        ));
    }
    let declarations = serde_json::from_slice(&bytes)
        .map_err(|e| RegistryError::Invalid(format!("invalid enrollment JSON: {e}")))?;
    validate_declarations(&declarations)?;
    Ok(declarations)
}
#[derive(Debug, Serialize)]
pub struct EnrollmentReport {
    pub apply: ApplyReport,
    pub bootstrapped_scopes: usize,
}
/// Bootstrapping is optional and idempotent, using only the model registry's
/// SELECT/INSERT surface. Validate every declaration before any side effects.
pub async fn apply(
    pool: PgPool,
    declarations: &DeclarationFile,
    prune: bool,
    bootstrap_model: Option<&str>,
) -> Result<EnrollmentReport, crate::FleetError> {
    validate_declarations(declarations)
        .map_err(|e| crate::FleetError::Configuration(e.to_string()))?;
    let mut bootstrapped_scopes = 0;
    if let Some(model) = bootstrap_model {
        for (tenant, project) in declared_scopes(declarations) {
            let scope = crate::FleetScope::new(
                tenant,
                project,
                "enrollment",
                None,
                ostk_recall_core::PrivacyTier::T1Project,
            )?;
            CockroachStore::from_pool(pool.clone(), scope)?
                .initialize_embedding_model(model)
                .await?;
            bootstrapped_scopes += 1;
        }
    }
    let apply = PrincipalRegistry::new(pool)
        .apply(declarations, prune)
        .await
        .map_err(|e| crate::FleetError::Configuration(e.to_string()))?;
    Ok(EnrollmentReport {
        apply,
        bootstrapped_scopes,
    })
}
