//! Durable, revocable delegation. Commit the authorization row before signing.
use super::jose::Ed25519Signer;
use super::registry::{Ceiling, Principal, PrincipalRole, pattern_matches};
use chrono::{DateTime, Utc};
use ring::rand::SecureRandom as _;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum GrantError {
    #[error("grant is expired, revoked, or unknown")]
    Invalid,
    #[error("principal cannot perform this grant operation")]
    Forbidden,
    #[error("invalid grant request: {0}")]
    Request(&'static str),
    #[error("grant database unavailable")]
    Database(#[from] sqlx::Error),
    #[error("grant signing failed")]
    Signing,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantKind {
    Agent,
    Shipper,
}
impl GrantKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::Shipper => "shipper",
        }
    }
}
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantRequest {
    pub kind: GrantKind,
    pub agent: String,
    #[serde(default)]
    pub sandbox_id: Option<String>,
    #[serde(default)]
    pub ttl_seconds: Option<u64>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionGrant {
    pub jti: Uuid,
    pub kind: GrantKind,
    pub principal_id: Uuid,
    pub principal_revision: i64,
    pub tenant_id: Uuid,
    pub project: String,
    pub agent: String,
    pub ceiling: Ceiling,
    pub sandbox_id: Option<String>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}
#[derive(Debug, Clone, Serialize)]
pub struct IssuedGrant {
    pub token: String,
    pub grant: SessionGrant,
}

#[derive(Clone)]
pub struct GrantIssuer {
    pool: PgPool,
    signer: Arc<Ed25519Signer>,
    resource: String,
    ttl_seconds: u64,
    cache_seconds: u64,
    cache: Arc<Mutex<HashMap<Uuid, (Instant, SessionGrant)>>>,
}
impl GrantIssuer {
    pub fn new(
        pool: PgPool,
        signer: Arc<Ed25519Signer>,
        resource: String,
        ttl_seconds: u64,
        cache_seconds: u64,
    ) -> Result<Self, GrantError> {
        if ttl_seconds == 0 || ttl_seconds > 86400 {
            return Err(GrantError::Request("grant TTL must be 1..86400 seconds"));
        }
        if cache_seconds > 5 {
            return Err(GrantError::Request(
                "grant check cache must be 0..5 seconds",
            ));
        }
        Ok(Self {
            pool,
            signer,
            resource,
            ttl_seconds,
            cache_seconds,
            cache: Arc::new(Mutex::new(HashMap::new())),
        })
    }
    pub async fn issue(
        &self,
        principal: &Principal,
        kind: GrantKind,
        agent: &str,
        sandbox_id: Option<&str>,
        ttl: Option<u64>,
    ) -> Result<IssuedGrant, GrantError> {
        if principal.role != PrincipalRole::Launcher
            || (kind == GrantKind::Shipper && principal.ceiling != Ceiling::Project)
            || principal.revoked_at.is_some()
            || !principal.ceiling.is_served()
            || !pattern_matches(&principal.agent_pattern, agent)
        {
            return Err(GrantError::Forbidden);
        }
        crate::FleetScope::new(
            principal.tenant_id,
            &principal.project,
            agent,
            sandbox_id.map(str::to_owned),
            ostk_recall_core::PrivacyTier::T1Project,
        )
        .map_err(|_| GrantError::Request("invalid agent or sandbox ID"))?;
        crate::memory_contracts::common::ContractId::new(agent)
            .map_err(|_| GrantError::Request("agent must be a contract identifier"))?;
        let ttl = ttl.unwrap_or(self.ttl_seconds);
        if ttl == 0 || ttl > self.ttl_seconds || ttl > 86400 {
            return Err(GrantError::Request(
                "requested TTL exceeds the configured grant lifetime",
            ));
        }
        let issued_at = Utc::now();
        let seconds = i64::try_from(ttl).map_err(|_| GrantError::Request("invalid TTL"))?;
        let expires_at = issued_at + chrono::Duration::seconds(seconds);
        let grant = SessionGrant {
            jti: new_grant_id()?,
            kind,
            principal_id: principal.principal_id,
            principal_revision: principal.revision,
            tenant_id: principal.tenant_id,
            project: principal.project.clone(),
            agent: agent.into(),
            ceiling: principal.ceiling,
            sandbox_id: sandbox_id.map(str::to_owned),
            issued_at,
            expires_at,
        };
        // The INSERT's principal read and write share one serializable statement.
        // Revocation or revision after authentication cannot mint a stale grant.
        let inserted=sqlx::query("INSERT INTO public.memory_session_grants_v1 (jti,kind,principal_id,principal_revision,tenant_id,project,agent,ceiling,sandbox_id,issued_at,expires_at) SELECT $1,$2,p.principal_id,p.revision,p.tenant_id,p.project,$3,p.ceiling,$4,$5,$6 FROM public.memory_principals_v1 AS p WHERE p.principal_id=$7 AND p.revision=$8 AND p.revoked_at IS NULL AND p.role='launcher' AND p.tenant_id=$9 AND p.project=$10 AND p.ceiling=$11 AND (p.agent_pattern=$3 OR (right(p.agent_pattern,1)='*' AND left($3,length(p.agent_pattern)-1)=left(p.agent_pattern,length(p.agent_pattern)-1)))")
            .bind(grant.jti).bind(kind.as_str()).bind(agent).bind(sandbox_id).bind(issued_at).bind(expires_at).bind(principal.principal_id).bind(principal.revision).bind(principal.tenant_id).bind(&principal.project).bind(principal.ceiling.as_str()).execute(&self.pool).await?.rows_affected();
        if inserted != 1 {
            return Err(GrantError::Forbidden);
        }
        let claims = serde_json::json!({"iss":self.resource,"aud":self.resource,"sub":principal.principal_id.to_string(),"jti":grant.jti.to_string(),"iat":issued_at.timestamp(),"exp":expires_at.timestamp(),"token_kind":"session_grant","kind":kind,"tenant_id":grant.tenant_id,"project":grant.project,"agent":grant.agent,"ceiling":grant.ceiling,"principal_revision":grant.principal_revision});
        // A signer failure leaves an unreturned, harmless audit row.
        let token = self.signer.sign(&claims).map_err(|_| GrantError::Signing)?;
        Ok(IssuedGrant { token, grant })
    }
    pub async fn check(&self, jti: Uuid) -> Result<SessionGrant, GrantError> {
        self.check_at(jti, Utc::now()).await
    }
    pub async fn check_at(
        &self,
        jti: Uuid,
        now: DateTime<Utc>,
    ) -> Result<SessionGrant, GrantError> {
        if self.cache_seconds > 0 {
            let cache = self.cache.lock().await;
            if let Some((checked, grant)) = cache.get(&jti)
                && checked.elapsed() < Duration::from_secs(self.cache_seconds)
                && grant.expires_at > now
                && grant.issued_at <= now
            {
                return Ok(grant.clone());
            }
        }
        let row=sqlx::query("SELECT g.jti,g.kind,g.principal_id,g.principal_revision,g.tenant_id,g.project,g.agent,g.ceiling,g.sandbox_id,g.issued_at,g.expires_at FROM public.memory_session_grants_v1 AS g JOIN public.memory_principals_v1 AS p ON p.principal_id=g.principal_id WHERE g.jti=$1 AND g.revoked_at IS NULL AND g.expires_at>$2 AND g.issued_at<=$2 AND p.revoked_at IS NULL AND p.revision=g.principal_revision AND p.role='launcher' AND p.tenant_id=g.tenant_id AND p.project=g.project AND p.ceiling=g.ceiling AND (p.agent_pattern=g.agent OR (right(p.agent_pattern,1)='*' AND left(g.agent,length(p.agent_pattern)-1)=left(p.agent_pattern,length(p.agent_pattern)-1)))")
            .bind(jti).bind(now).fetch_optional(&self.pool).await?.ok_or(GrantError::Invalid)?;
        let kind: String = row.try_get("kind")?;
        let ceiling: String = row.try_get("ceiling")?;
        let grant = SessionGrant {
            jti: row.try_get("jti")?,
            kind: serde_json::from_value(serde_json::Value::String(kind))
                .map_err(|_| GrantError::Invalid)?,
            principal_id: row.try_get("principal_id")?,
            principal_revision: row.try_get("principal_revision")?,
            tenant_id: row.try_get("tenant_id")?,
            project: row.try_get("project")?,
            agent: row.try_get("agent")?,
            ceiling: serde_json::from_value(serde_json::Value::String(ceiling))
                .map_err(|_| GrantError::Invalid)?,
            sandbox_id: row.try_get("sandbox_id")?,
            issued_at: row.try_get("issued_at")?,
            expires_at: row.try_get("expires_at")?,
        };
        if !grant.ceiling.is_served() {
            return Err(GrantError::Invalid);
        }
        if self.cache_seconds > 0 {
            let mut cache = self.cache.lock().await;
            // Bound attacker-driven cardinality without retaining failed checks.
            if cache.len() >= 4096 {
                cache.retain(|_, (time, _)| {
                    time.elapsed() < Duration::from_secs(self.cache_seconds)
                });
            }
            if cache.len() < 4096 {
                cache.insert(jti, (Instant::now(), grant.clone()));
            }
        }
        Ok(grant)
    }
    pub async fn revoke(&self, jti: Uuid, by: &Principal) -> Result<bool, GrantError> {
        if by.revoked_at.is_some() {
            return Err(GrantError::Forbidden);
        }
        // Re-check the revoker in the same statement; an old Principal value is
        // never itself authority. Operators may revoke within their own scope.
        let result=sqlx::query("UPDATE public.memory_session_grants_v1 AS g SET revoked_at=COALESCE(g.revoked_at,now()),revoked_by=COALESCE(g.revoked_by,$2) WHERE g.jti=$1 AND EXISTS (SELECT 1 FROM public.memory_principals_v1 AS p WHERE p.principal_id=$2 AND p.revision=$3 AND p.revoked_at IS NULL AND (p.principal_id=g.principal_id OR (p.role='operator' AND p.tenant_id=g.tenant_id AND p.project=g.project)))")
            .bind(jti).bind(by.principal_id).bind(by.revision).execute(&self.pool).await?;
        self.cache.lock().await.remove(&jti);
        if result.rows_affected() == 0 {
            return Err(GrantError::Forbidden);
        }
        Ok(true)
    }
}

fn new_grant_id() -> Result<Uuid, GrantError> {
    let mut bytes = [0_u8; 16];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| GrantError::Signing)?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(Uuid::from_bytes(bytes))
}

/// Check the complete remote-plane schema prefix and least-privilege runtime
/// surface before opening the HTTP listener. No principal or grant is changed.
pub async fn probe_remote_plane(pool: &PgPool) -> Result<(), GrantError> {
    let ready: bool = sqlx::query_scalar("SELECT count(*) = 38 AND min(version) = 1 AND max(version) = 39 AND bool_and(version <> 25) AND COALESCE(bool_and(success),false) FROM public._sqlx_migrations WHERE version BETWEEN 1 AND 39")
        .fetch_one(pool).await?;
    if !ready {
        return Err(GrantError::Request(
            "remote plane requires successful migrations through 39",
        ));
    }
    for statement in [
        "SELECT principal_id FROM public.memory_principals_v1 WHERE false",
        "INSERT INTO public.memory_session_grants_v1 SELECT * FROM public.memory_session_grants_v1 WHERE false",
        "UPDATE public.memory_session_grants_v1 SET revoked_at=revoked_at WHERE false",
    ] {
        sqlx::query(statement).execute(pool).await?;
    }
    Ok(())
}
