//! Enrollment-owned identity bindings. The runtime has read access only.
use std::collections::{BTreeSet, HashSet};
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("identity is not enrolled")]
    Unknown,
    #[error("identity binding is revoked")]
    Revoked,
    #[error("identity binding is ambiguous")]
    Ambiguous,
    #[error("invalid enrollment: {0}")]
    Invalid(String),
    #[error("registry database unavailable")]
    Database(#[from] sqlx::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalRole {
    Operator,
    Launcher,
    Shipper,
}
impl PrincipalRole {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Operator => "operator",
            Self::Launcher => "launcher",
            Self::Shipper => "shipper",
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ceiling {
    Private,
    Project,
    Trusted,
    Public,
}
impl Ceiling {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Private => "private",
            Self::Project => "project",
            Self::Trusted => "trusted",
            Self::Public => "public",
        }
    }
    pub const fn is_served(self) -> bool {
        matches!(self, Self::Project | Self::Public)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalDeclaration {
    pub principal_id: Uuid,
    pub anchor_id: String,
    pub subject_pattern: String,
    pub role: PrincipalRole,
    pub tenant_id: Uuid,
    pub project: String,
    pub ceiling: Ceiling,
    pub agent_pattern: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeclarationFile {
    pub principals: Vec<PrincipalDeclaration>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Principal {
    pub principal_id: Uuid,
    pub anchor_id: String,
    pub subject_pattern: String,
    pub role: PrincipalRole,
    pub tenant_id: Uuid,
    pub project: String,
    pub ceiling: Ceiling,
    pub agent_pattern: String,
    pub enrolled_at: DateTime<Utc>,
    pub revised_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub source_digest: Vec<u8>,
    pub revision: i64,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ApplyReport {
    pub changed: u64,
    pub unchanged: u64,
    pub revoked: u64,
}

pub(crate) const PRINCIPAL_COLUMNS: &str = "principal_id, anchor_id, subject_pattern, role, tenant_id, project, ceiling, agent_pattern, enrolled_at, revised_at, revoked_at, source_digest, revision";

#[derive(Debug, Clone)]
pub struct PrincipalRegistry {
    pool: PgPool,
}
impl PrincipalRegistry {
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }
    /// Deliberately includes revoked rows while choosing specificity. Otherwise
    /// revoking an exact binding could reactivate a broader wildcard binding.
    pub async fn resolve(
        &self,
        anchor_id: &str,
        subject: &str,
    ) -> Result<Principal, RegistryError> {
        let rows = sqlx::query(&format!("SELECT {PRINCIPAL_COLUMNS} FROM public.memory_principals_v1 WHERE anchor_id = $1 AND (subject_pattern = $2 OR (right(subject_pattern, 1) = '*' AND left($2, length(subject_pattern) - 1) = left(subject_pattern, length(subject_pattern) - 1)))"))
            .bind(anchor_id).bind(subject).fetch_all(&self.pool).await?;
        let principals = rows
            .into_iter()
            .map(|row| principal_from_row(&row))
            .collect::<Result<Vec<_>, _>>()?;
        resolve_candidates(principals, subject)
    }
    pub async fn get(&self, id: Uuid) -> Result<Principal, RegistryError> {
        let row = sqlx::query(&format!(
            "SELECT {PRINCIPAL_COLUMNS} FROM public.memory_principals_v1 WHERE principal_id = $1"
        ))
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(RegistryError::Unknown)?;
        let principal = principal_from_row(&row)?;
        if principal.revoked_at.is_some() {
            return Err(RegistryError::Revoked);
        }
        Ok(principal)
    }
    pub async fn list(&self) -> Result<Vec<Principal>, RegistryError> {
        sqlx::query(&format!(
            "SELECT {PRINCIPAL_COLUMNS} FROM public.memory_principals_v1 ORDER BY principal_id"
        ))
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(|row| principal_from_row(&row))
        .collect()
    }
    pub async fn revoke(&self, id: Uuid) -> Result<bool, RegistryError> {
        Ok(sqlx::query("UPDATE public.memory_principals_v1 SET revoked_at = now(), revised_at = now(), revision = revision + 1 WHERE principal_id = $1 AND revoked_at IS NULL")
            .bind(id).execute(&self.pool).await?.rows_affected() != 0)
    }
    /// Apply one complete desired-state document atomically. Prune makes the
    /// supplied document authoritative for the whole registry; omission revokes.
    pub async fn apply(
        &self,
        declarations: &DeclarationFile,
        prune: bool,
    ) -> Result<ApplyReport, RegistryError> {
        validate_declarations(declarations)?;
        for attempt in 0..5_u32 {
            let result = self.apply_once(declarations, prune).await;
            if result.as_ref().err().is_some_and(retryable) && attempt < 4 {
                tokio::time::sleep(Duration::from_millis(
                    (10 << attempt) + u64::from(Uuid::now_v7().as_bytes()[15] % 11),
                ))
                .await;
            } else {
                return result;
            }
        }
        unreachable!("bounded retry returns on the final attempt")
    }
    async fn apply_once(
        &self,
        declarations: &DeclarationFile,
        prune: bool,
    ) -> Result<ApplyReport, RegistryError> {
        let mut tx = self.pool.begin().await?;
        let changed = apply_principals(&mut tx, &declarations.principals).await?;
        let mut report = ApplyReport {
            changed,
            unchanged: declarations.principals.len() as u64 - changed,
            revoked: 0,
        };
        if prune {
            let ids: Vec<Uuid> = declarations
                .principals
                .iter()
                .map(|p| p.principal_id)
                .collect();
            report.revoked = sqlx::query("UPDATE public.memory_principals_v1 SET revoked_at = now(), revised_at = now(), revision = revision + 1 WHERE revoked_at IS NULL AND NOT (principal_id = ANY($1))")
                .bind(ids).execute(&mut *tx).await?.rows_affected();
        }
        tx.commit().await?;
        Ok(report)
    }
}

pub fn validate_declarations(file: &DeclarationFile) -> Result<(), RegistryError> {
    if file.principals.len() > 1000 {
        return Err(RegistryError::Invalid(
            "at most 1000 principals per apply".into(),
        ));
    }
    let mut ids = HashSet::new();
    let mut bindings = HashSet::new();
    for p in &file.principals {
        if p.principal_id.is_nil() || p.tenant_id.is_nil() || !ids.insert(p.principal_id) {
            return Err(RegistryError::Invalid(
                "principal and tenant IDs must be non-nil; principal IDs must be unique".into(),
            ));
        }
        if !bindings.insert((&p.anchor_id, &p.subject_pattern)) {
            return Err(RegistryError::Invalid(
                "duplicate anchor/subject binding".into(),
            ));
        }
        validate_text(&p.anchor_id, 128)?;
        validate_text(&p.project, 256)?;
        validate_pattern(&p.subject_pattern, 1024)?;
        validate_agent_pattern(&p.agent_pattern)?;
        if p.role == PrincipalRole::Shipper && p.ceiling != Ceiling::Project {
            return Err(RegistryError::Invalid(
                "shipper principals require the project ceiling".into(),
            ));
        }
        if p.role != PrincipalRole::Launcher
            && p.agent_pattern
                .strip_suffix('*')
                .is_some_and(|prefix| prefix.len() > 96)
        {
            return Err(RegistryError::Invalid("direct principal wildcard must leave room for a stable 32-character identity suffix".into()));
        }
        if !p.ceiling.is_served() {
            return Err(RegistryError::Invalid("private/trusted ceilings are unavailable until durable owner/tier visibility exists".into()));
        }
        // Match the exact scope validation used by the serving layer.
        crate::FleetScope::new(
            p.tenant_id,
            &p.project,
            "enrollment-probe",
            None,
            ostk_recall_core::PrivacyTier::T1Project,
        )
        .map_err(|e| RegistryError::Invalid(e.to_string()))?;
    }
    Ok(())
}
fn validate_text(value: &str, max: usize) -> Result<(), RegistryError> {
    if value.is_empty()
        || value.len() > max
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(RegistryError::Invalid(
            "empty, oversized, padded, or control-bearing identity component".into(),
        ));
    }
    Ok(())
}
pub fn validate_pattern(pattern: &str, max: usize) -> Result<(), RegistryError> {
    validate_text(pattern, max)?;
    if pattern.strip_suffix('*').unwrap_or(pattern).contains('*') {
        return Err(RegistryError::Invalid(
            "only a single trailing wildcard is supported".into(),
        ));
    }
    Ok(())
}
pub fn validate_agent_pattern(pattern: &str) -> Result<(), RegistryError> {
    validate_pattern(pattern, 129)?;
    if pattern == "*" {
        return Ok(());
    }
    let prefix = pattern.strip_suffix('*').unwrap_or(pattern);
    crate::memory_contracts::common::ContractId::new(prefix).map_err(|_| {
        RegistryError::Invalid(
            "agent pattern must be a contract identifier with an optional trailing wildcard".into(),
        )
    })?;
    Ok(())
}
pub fn pattern_matches(pattern: &str, value: &str) -> bool {
    pattern
        .strip_suffix('*')
        .map_or_else(|| pattern == value, |prefix| value.starts_with(prefix))
}
fn resolve_candidates(
    principals: Vec<Principal>,
    subject: &str,
) -> Result<Principal, RegistryError> {
    let mut matches: Vec<_> = principals
        .into_iter()
        .filter(|p| pattern_matches(&p.subject_pattern, subject))
        .collect();
    matches.sort_by_key(|p| (p.subject_pattern == subject, p.subject_pattern.len()));
    let chosen = matches.pop().ok_or(RegistryError::Unknown)?;
    if matches.last().is_some_and(|p| {
        (p.subject_pattern == subject, p.subject_pattern.len())
            == (
                chosen.subject_pattern == subject,
                chosen.subject_pattern.len(),
            )
    }) {
        return Err(RegistryError::Ambiguous);
    }
    if chosen.revoked_at.is_some() {
        return Err(RegistryError::Revoked);
    }
    if !chosen.ceiling.is_served() {
        return Err(RegistryError::Invalid(
            "principal ceiling is not served".into(),
        ));
    }
    Ok(chosen)
}
pub fn declared_scopes(file: &DeclarationFile) -> BTreeSet<(Uuid, String)> {
    file.principals
        .iter()
        .map(|p| (p.tenant_id, p.project.clone()))
        .collect()
}
async fn apply_principals(
    tx: &mut Transaction<'_, Postgres>,
    principals: &[PrincipalDeclaration],
) -> Result<u64, RegistryError> {
    if principals.is_empty() {
        return Ok(0);
    }
    let digests = principals
        .iter()
        .map(|p| {
            serde_json::to_vec(p)
                .map(|bytes| Sha256::digest(bytes).to_vec())
                .map_err(|e| RegistryError::Invalid(e.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(sqlx::query("INSERT INTO public.memory_principals_v1 (principal_id, anchor_id, subject_pattern, role, tenant_id, project, ceiling, agent_pattern, enrolled_at, revised_at, source_digest, revision) SELECT input.principal_id,input.anchor_id,input.subject_pattern,input.role,input.tenant_id,input.project,input.ceiling,input.agent_pattern,now(),now(),input.source_digest,1 FROM UNNEST($1::UUID[],$2::STRING[],$3::STRING[],$4::STRING[],$5::UUID[],$6::STRING[],$7::STRING[],$8::STRING[],$9::BYTES[]) AS input(principal_id,anchor_id,subject_pattern,role,tenant_id,project,ceiling,agent_pattern,source_digest) ON CONFLICT (principal_id) DO UPDATE SET anchor_id = excluded.anchor_id, subject_pattern = excluded.subject_pattern, role = excluded.role, tenant_id = excluded.tenant_id, project = excluded.project, ceiling = excluded.ceiling, agent_pattern = excluded.agent_pattern, revised_at = now(), revoked_at = NULL, source_digest = excluded.source_digest, revision = memory_principals_v1.revision + 1 WHERE memory_principals_v1.source_digest <> excluded.source_digest OR memory_principals_v1.revoked_at IS NOT NULL")
        .bind(principals.iter().map(|p|p.principal_id).collect::<Vec<_>>())
        .bind(principals.iter().map(|p|p.anchor_id.as_str()).collect::<Vec<_>>())
        .bind(principals.iter().map(|p|p.subject_pattern.as_str()).collect::<Vec<_>>())
        .bind(principals.iter().map(|p|p.role.as_str()).collect::<Vec<_>>())
        .bind(principals.iter().map(|p|p.tenant_id).collect::<Vec<_>>())
        .bind(principals.iter().map(|p|p.project.as_str()).collect::<Vec<_>>())
        .bind(principals.iter().map(|p|p.ceiling.as_str()).collect::<Vec<_>>())
        .bind(principals.iter().map(|p|p.agent_pattern.as_str()).collect::<Vec<_>>())
        .bind(digests).execute(&mut **tx).await?.rows_affected())
}

fn retryable(error: &RegistryError) -> bool {
    matches!(error,RegistryError::Database(sqlx::Error::Database(e)) if e.code().as_deref()==Some("40001"))
}
pub(crate) fn principal_from_row(row: &sqlx::postgres::PgRow) -> Result<Principal, RegistryError> {
    let role: String = row.try_get("role")?;
    let ceiling: String = row.try_get("ceiling")?;
    Ok(Principal {
        principal_id: row.try_get("principal_id")?,
        anchor_id: row.try_get("anchor_id")?,
        subject_pattern: row.try_get("subject_pattern")?,
        role: serde_json::from_value(serde_json::Value::String(role))
            .map_err(|_| RegistryError::Invalid("stored role".into()))?,
        tenant_id: row.try_get("tenant_id")?,
        project: row.try_get("project")?,
        ceiling: serde_json::from_value(serde_json::Value::String(ceiling))
            .map_err(|_| RegistryError::Invalid("stored ceiling".into()))?,
        agent_pattern: row.try_get("agent_pattern")?,
        enrolled_at: row.try_get("enrolled_at")?,
        revised_at: row.try_get("revised_at")?,
        revoked_at: row.try_get("revoked_at")?,
        source_digest: row.try_get("source_digest")?,
        revision: row.try_get("revision")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn principal(pattern: &str) -> Principal {
        Principal {
            principal_id: Uuid::now_v7(),
            anchor_id: "test".into(),
            subject_pattern: pattern.into(),
            role: PrincipalRole::Operator,
            tenant_id: Uuid::now_v7(),
            project: "test".into(),
            ceiling: Ceiling::Project,
            agent_pattern: "*".into(),
            enrolled_at: Utc::now(),
            revised_at: Utc::now(),
            revoked_at: None,
            source_digest: vec![0; 32],
            revision: 1,
        }
    }
    #[test]
    fn exact_then_longest_prefix_and_ties_fail_closed() {
        let p = resolve_candidates(
            vec![principal("user*"), principal("*"), principal("user42")],
            "user42",
        )
        .unwrap();
        assert_eq!(p.subject_pattern, "user42");
        assert_eq!(
            resolve_candidates(vec![principal("user*"), principal("*")], "user42")
                .unwrap()
                .subject_pattern,
            "user*"
        );
        assert!(matches!(
            resolve_candidates(vec![principal("user*"), principal("user*")], "user42"),
            Err(RegistryError::Ambiguous)
        ));
    }
    #[test]
    fn revoked_exact_cannot_fall_back_to_wildcard() {
        let mut revoked = principal("user42");
        revoked.revoked_at = Some(Utc::now());
        assert!(matches!(
            resolve_candidates(vec![principal("*"), revoked], "user42"),
            Err(RegistryError::Revoked)
        ));
    }
    #[test]
    fn patterns_are_literal_except_one_trailing_star() {
        assert!(validate_pattern("a*b*", 64).is_err());
        assert!(pattern_matches("a._%*", "a._%value"));
        assert!(!pattern_matches("a._%*", "a_abc"));
    }
    #[test]
    fn unknown_declaration_fields_are_rejected() {
        assert!(
            serde_json::from_str::<DeclarationFile>(r#"{"principals":[],"admin":true}"#).is_err()
        );
    }
    #[test]
    fn direct_agent_wildcards_reserve_a_collision_resistant_suffix() {
        let mut declaration = PrincipalDeclaration {
            principal_id: Uuid::now_v7(),
            anchor_id: "test".into(),
            subject_pattern: "user".into(),
            role: PrincipalRole::Operator,
            tenant_id: Uuid::now_v7(),
            project: "test".into(),
            ceiling: Ceiling::Project,
            agent_pattern: format!("{}*", "a".repeat(96)),
        };
        assert!(
            validate_declarations(&DeclarationFile {
                principals: vec![declaration.clone()]
            })
            .is_ok()
        );
        declaration.agent_pattern = format!("{}*", "a".repeat(97));
        assert!(
            validate_declarations(&DeclarationFile {
                principals: vec![declaration.clone()]
            })
            .is_err()
        );
        declaration.role = PrincipalRole::Launcher;
        assert!(
            validate_declarations(&DeclarationFile {
                principals: vec![declaration]
            })
            .is_ok()
        );
    }
}
