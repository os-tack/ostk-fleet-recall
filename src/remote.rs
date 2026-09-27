//! Remote-plane authentication and process integration.

use crate::auth::anchors::{
    IdentityAnchor,
    local_key::LocalKeyAnchor,
    oidc::{OidcAnchor, OidcConfig},
};
use crate::auth::grant::{GrantError, GrantIssuer, GrantKind, GrantRequest};
use crate::auth::jose::{self, AudiencePolicy, ClaimsPolicy, Ed25519Signer};
use crate::auth::registry::{
    Ceiling, Principal, PrincipalRegistry, PrincipalRole, RegistryError, pattern_matches,
};
use crate::auth::{AuthError, Authenticator, VerifiedIdentity};
use crate::mcp::{
    McpServer,
    http::{HttpBackend, HttpConfig, HttpError},
    scopes::{Access, ScopeServices},
};
use crate::{FleetError, FleetScope, Result};
use async_trait::async_trait;
use chrono::Utc;
use ostk_recall_core::PrivacyTier;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use sqlx::PgPool;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read as _,
    path::Path,
    sync::Arc,
    time::Duration,
};
use uuid::Uuid;

/// Configuration is deliberately not Debug: it contains the grant signing key.
pub struct RemoteConfig {
    pub http: HttpConfig,
    pub scope_cache_max: usize,
    pub agent_cache_max: usize,
    pub grant_ttl_seconds: u64,
    pub grant_cache_seconds: u64,
    signing_key: String,
    oidc: BTreeMap<String, String>,
    scope_substitutes: BTreeMap<String, String>,
    oidc_ca_path: Option<String>,
    local_key_path: Option<String>,
    aws_endpoint: Option<String>,
    aws_server_id: Option<String>,
    aws_accounts: BTreeSet<String>,
}

fn configuration(message: &str) -> FleetError {
    FleetError::Configuration(message.into())
}
fn pairs(value: &str) -> Result<BTreeMap<String, String>> {
    let mut pairs = BTreeMap::new();
    if value.is_empty() {
        return Ok(pairs);
    }
    for pair in value.split(',') {
        let (name, value) = pair
            .split_once('=')
            .ok_or_else(|| configuration("identity mapping must contain name=value pairs"))?;
        if name.is_empty()
            || value.is_empty()
            || name.trim() != name
            || value.trim() != value
            || pairs.insert(name.into(), value.into()).is_some()
        {
            return Err(configuration(
                "identity mapping names must be nonempty and unique",
            ));
        }
    }
    Ok(pairs)
}

impl RemoteConfig {
    pub fn from_env() -> Result<Self> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }
    pub fn from_lookup(mut lookup: impl FnMut(&str) -> Option<String>) -> Result<Self> {
        let resource = lookup("FLEET_RECALL_RESOURCE_URL").ok_or_else(|| {
            configuration("FLEET_RECALL_RESOURCE_URL is required for HTTP serving")
        })?;
        let oidc = pairs(&lookup("FLEET_RECALL_OIDC_ISSUERS").unwrap_or_default())?;
        let scope_substitutes =
            pairs(&lookup("FLEET_RECALL_OIDC_SCOPE_SUBSTITUTES").unwrap_or_default())?;
        if scope_substitutes.keys().any(|key| !oidc.contains_key(key))
            || oidc.contains_key("local-key")
            || oidc.contains_key("aws-iam")
            || oidc
                .values()
                .any(|value| value == &resource || value == "fleet-recall-local-key")
        {
            return Err(configuration(
                "issuer and audience-policy mappings conflict with configured trust roots",
            ));
        }
        let mut http = HttpConfig::new(resource, oidc.values().cloned().collect());
        http.allowed_origins = lookup("FLEET_RECALL_HTTP_ALLOWED_ORIGINS")
            .unwrap_or_default()
            .split(',')
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
        http.max_inflight = number(&mut lookup, "FLEET_RECALL_HTTP_MAX_INFLIGHT", 64, 1, 1024)?;
        http.request_deadline = Duration::from_secs(30);
        let scope_cache_max = number(&mut lookup, "FLEET_RECALL_SCOPE_CACHE_MAX", 64, 1, 4096)?;
        let agent_cache_max = number(&mut lookup, "FLEET_RECALL_AGENT_CACHE_MAX", 256, 1, 16384)?;
        let grant_ttl_seconds = number(
            &mut lookup,
            "FLEET_RECALL_GRANT_TTL_SECONDS",
            3600,
            1,
            86400,
        )? as u64;
        let grant_cache_seconds = number(
            &mut lookup,
            "FLEET_RECALL_GRANT_CHECK_CACHE_SECONDS",
            5,
            0,
            5,
        )? as u64;
        let signing_key = lookup("FLEET_RECALL_GRANT_SIGNING_KEY_HEX")
            .ok_or_else(|| configuration("FLEET_RECALL_GRANT_SIGNING_KEY_HEX is required"))?;
        let local_key_path = lookup("FLEET_RECALL_LOCAL_KEY_ANCHOR_PATH");
        let aws_endpoint = lookup("FLEET_RECALL_AWS_STS_ENDPOINT");
        let aws_server_id = lookup("FLEET_RECALL_AWS_IAM_SERVER_ID");
        let aws_accounts = lookup("FLEET_RECALL_AWS_ALLOWED_ACCOUNTS")
            .unwrap_or_default()
            .split(',')
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        let any_aws = aws_endpoint.is_some() || aws_server_id.is_some() || !aws_accounts.is_empty();
        if any_aws
            && !(aws_endpoint.is_some() && aws_server_id.is_some() && !aws_accounts.is_empty())
        {
            return Err(configuration(
                "AWS authentication requires endpoint, server ID and allowed accounts together",
            ));
        }
        if oidc.is_empty() && local_key_path.is_none() && aws_endpoint.is_none() {
            return Err(configuration(
                "HTTP serving requires at least one identity anchor",
            ));
        }
        Ok(Self {
            http,
            scope_cache_max,
            agent_cache_max,
            grant_ttl_seconds,
            grant_cache_seconds,
            signing_key,
            oidc,
            scope_substitutes,
            oidc_ca_path: lookup("FLEET_RECALL_OIDC_CA_PATH"),
            local_key_path,
            aws_endpoint,
            aws_server_id,
            aws_accounts,
        })
    }
}

fn number(
    lookup: &mut impl FnMut(&str) -> Option<String>,
    name: &str,
    default: usize,
    min: usize,
    max: usize,
) -> Result<usize> {
    lookup(name).map_or(Ok(default), |value| {
        value
            .parse::<usize>()
            .ok()
            .filter(|value| (min..=max).contains(value))
            .ok_or_else(|| configuration(&format!("{name} must be in {min}..={max}")))
    })
}
fn read_bounded(path: &str) -> Result<Vec<u8>> {
    let file = std::fs::File::open(Path::new(path))
        .map_err(|_| configuration("cannot read identity anchor configuration file"))?;
    let mut bytes = Vec::new();
    file.take(262_145)
        .read_to_end(&mut bytes)
        .map_err(|_| configuration("cannot read identity anchor configuration file"))?;
    if bytes.len() > 262_144 {
        return Err(configuration(
            "identity anchor configuration exceeds 256 KiB",
        ));
    }
    Ok(bytes)
}

pub struct RemoteBackend {
    authenticator: Authenticator,
    registry: PrincipalRegistry,
    grants: GrantIssuer,
    signer: Arc<Ed25519Signer>,
    resource: String,
    services: Arc<ScopeServices>,
    // Filled by the AWS anchor integration; the service never forwards an
    // arbitrary client-selected endpoint.
    aws: Option<crate::auth::anchors::aws_iam::AwsIamAnchor>,
}

impl RemoteBackend {
    pub fn new(config: &RemoteConfig, pool: PgPool, services: Arc<ScopeServices>) -> Result<Self> {
        let resource = config.http.resource_url.clone();
        let signer = Arc::new(
            Ed25519Signer::from_seed_hex("fleet-grants", &config.signing_key)
                .map_err(|_| configuration("invalid remote grant signing key"))?,
        );
        let ca_pem = config
            .oidc_ca_path
            .as_deref()
            .map(read_bounded)
            .transpose()?;
        let mut anchors: Vec<Arc<dyn IdentityAnchor>> = Vec::new();
        for (id, issuer) in &config.oidc {
            anchors.push(Arc::new(
                OidcAnchor::new(OidcConfig {
                    anchor_id: id.clone(),
                    issuer: issuer.clone(),
                    resource: resource.clone(),
                    audience_policy: config
                        .scope_substitutes
                        .get(id)
                        .map_or(AudiencePolicy::Required, |scope| {
                            AudiencePolicy::ScopeSubstitute(scope.clone())
                        }),
                    ca_pem: ca_pem.clone(),
                    allow_http: true,
                })
                .map_err(|_| configuration("invalid OIDC anchor configuration"))?,
            ));
        }
        if let Some(path) = &config.local_key_path {
            anchors.push(Arc::new(
                LocalKeyAnchor::from_json("local-key", &resource, &read_bounded(path)?)
                    .map_err(|_| configuration("invalid local key anchor configuration"))?,
            ));
        }
        let aws = config
            .aws_endpoint
            .as_ref()
            .map(|endpoint| {
                crate::auth::anchors::aws_iam::AwsIamAnchor::new(
                    crate::auth::anchors::aws_iam::AwsIamConfig {
                        anchor_id: "aws-iam".into(),
                        sts_endpoint: endpoint.clone(),
                        server_id: config.aws_server_id.clone().unwrap_or_default(),
                        allowed_accounts: config.aws_accounts.clone(),
                        allow_http: true,
                    },
                )
            })
            .transpose()
            .map_err(|_| configuration("invalid AWS IAM anchor configuration"))?;
        let grants = GrantIssuer::new(
            pool.clone(),
            signer.clone(),
            resource.clone(),
            config.grant_ttl_seconds,
            config.grant_cache_seconds,
        )
        .map_err(|_| configuration("invalid grant configuration"))?;
        Ok(Self {
            authenticator: Authenticator::new(anchors)
                .map_err(|_| configuration("ambiguous authentication configuration"))?,
            registry: PrincipalRegistry::new(pool),
            grants,
            signer,
            resource,
            services,
            aws,
        })
    }

    fn self_claims(&self, token: &str) -> std::result::Result<jose::Claims, HttpError> {
        let mut policy = ClaimsPolicy::new(&self.resource, &self.resource);
        policy.require_jti = true;
        policy.leeway_seconds = 0;
        jose::verify(
            token,
            &[self.signer.public_jwk()],
            &policy,
            Utc::now().timestamp(),
        )
        .map_err(auth_error)
    }

    async fn principal(
        &self,
        bearer: &str,
    ) -> std::result::Result<(Principal, VerifiedIdentity), HttpError> {
        let identity = if jose::unverified_issuer(bearer).map_err(auth_error)? == self.resource {
            let claims = self.self_claims(bearer)?;
            if self.aws.is_none()
                || claims.extra.get("token_kind").and_then(Value::as_str) != Some("aws_identity")
                || claims.extra.get("anchor").and_then(Value::as_str) != Some("aws-iam")
            {
                return Err(HttpError::Unauthorized);
            }
            VerifiedIdentity {
                anchor_id: "aws-iam".into(),
                subject: claims.sub,
            }
        } else {
            self.authenticator
                .authenticate(bearer, Utc::now().timestamp())
                .await
                .map_err(auth_error)?
        };
        let principal = self
            .registry
            .resolve(&identity.anchor_id, &identity.subject)
            .await
            .map_err(registry_error)?;
        Ok((principal, identity))
    }
}

#[async_trait]
impl HttpBackend for RemoteBackend {
    async fn authenticate(&self, bearer: &str) -> std::result::Result<Arc<McpServer>, HttpError> {
        let issuer = jose::unverified_issuer(bearer).map_err(auth_error)?;
        let (scope, access) = if issuer == self.resource {
            let claims = self.self_claims(bearer)?;
            if claims.extra.get("token_kind").and_then(Value::as_str) == Some("session_grant") {
                let id = claims
                    .jti
                    .as_deref()
                    .ok_or(HttpError::Unauthorized)?
                    .parse::<Uuid>()
                    .map_err(|_| HttpError::Unauthorized)?;
                let grant = self.grants.check(id).await.map_err(grant_error)?;
                if claims.sub != grant.principal_id.to_string() {
                    return Err(HttpError::Unauthorized);
                }
                let access = access_for(grant.ceiling, grant.kind == GrantKind::Shipper)?;
                (
                    trusted_scope(grant.tenant_id, grant.project, grant.agent)?,
                    access,
                )
            } else {
                let (principal, identity) = self.principal(bearer).await?;
                direct_scope(&principal, &identity)?
            }
        } else {
            let (principal, identity) = self.principal(bearer).await?;
            direct_scope(&principal, &identity)?
        };
        self.services
            .server(scope, access)
            .await
            .map_err(|_| HttpError::Unavailable("scope_not_bootstrapped"))
    }

    async fn issue_grant(
        &self,
        bearer: &str,
        request: Value,
    ) -> std::result::Result<Value, HttpError> {
        let (principal, _) = self.principal(bearer).await?;
        let request: GrantRequest = serde_json::from_value(request)
            .map_err(|_| HttpError::BadRequest("invalid_grant_request"))?;
        let issued = self
            .grants
            .issue(
                &principal,
                request.kind,
                &request.agent,
                request.sandbox_id.as_deref(),
                request.ttl_seconds,
            )
            .await
            .map_err(grant_error)?;
        serde_json::to_value(issued).map_err(|_| HttpError::Unavailable("grant_encoding_failed"))
    }
    async fn revoke_grant(&self, bearer: &str, jti: &str) -> std::result::Result<(), HttpError> {
        let (principal, _) = self.principal(bearer).await?;
        let jti = jti
            .parse::<Uuid>()
            .map_err(|_| HttpError::BadRequest("invalid_grant_id"))?;
        self.grants
            .revoke(jti, &principal)
            .await
            .map_err(grant_error)?;
        Ok(())
    }
    async fn exchange_aws(&self, request: Value) -> std::result::Result<Value, HttpError> {
        let aws = self
            .aws
            .as_ref()
            .ok_or(HttpError::NotFound("aws_auth_not_configured"))?;
        let request = serde_json::from_value(request)
            .map_err(|_| HttpError::BadRequest("invalid_aws_request"))?;
        let identity = aws
            .verify_request(&request, Utc::now().timestamp())
            .await
            .map_err(auth_error)?;
        // An unenrolled AWS identity cannot obtain even an identity token.
        self.registry
            .resolve(&identity.anchor_id, &identity.subject)
            .await
            .map_err(registry_error)?;
        let now = Utc::now().timestamp();
        let token = self.signer.sign(&json!({"iss":self.resource,"aud":self.resource,"sub":identity.subject,"iat":now,"exp":now+900,"jti":Uuid::now_v7(),"token_kind":"aws_identity","anchor":identity.anchor_id})).map_err(auth_error)?;
        Ok(json!({"access_token":token,"token_type":"Bearer","expires_in":900}))
    }
}

fn trusted_scope(
    tenant: Uuid,
    project: String,
    agent: String,
) -> std::result::Result<FleetScope, HttpError> {
    FleetScope::new(tenant, project, agent, None, PrivacyTier::T1Project)
        .map_err(|_| HttpError::Forbidden)
}
const fn access_for(ceiling: Ceiling, shipper: bool) -> std::result::Result<Access, HttpError> {
    match (ceiling, shipper) {
        (Ceiling::Project, false) => Ok(Access::Writer),
        (Ceiling::Project, true) => Ok(Access::Shipper),
        (Ceiling::Public, false) => Ok(Access::Publication),
        _ => Err(HttpError::Forbidden),
    }
}
fn direct_scope(
    principal: &Principal,
    identity: &VerifiedIdentity,
) -> std::result::Result<(FleetScope, Access), HttpError> {
    if principal.role == PrincipalRole::Launcher {
        return Err(HttpError::Forbidden);
    }
    let access = access_for(principal.ceiling, principal.role == PrincipalRole::Shipper)?;
    let agent = if let Some(prefix) = principal.agent_pattern.strip_suffix('*') {
        if prefix.len() > 96 {
            return Err(HttpError::Forbidden);
        }
        let digest = hex::encode(Sha256::digest(
            format!("{}\0{}", identity.anchor_id, identity.subject).as_bytes(),
        ));
        let prefix = if prefix.is_empty() {
            "identity-"
        } else {
            prefix
        };
        format!(
            "{prefix}{}",
            &digest[..(128_usize.saturating_sub(prefix.len())).min(32)]
        )
    } else {
        principal.agent_pattern.clone()
    };
    if !pattern_matches(&principal.agent_pattern, &agent) {
        return Err(HttpError::Forbidden);
    }
    Ok((
        trusted_scope(principal.tenant_id, principal.project.clone(), agent)?,
        access,
    ))
}
const fn auth_error(error: AuthError) -> HttpError {
    if matches!(error, AuthError::ProviderUnavailable) {
        HttpError::Unavailable("identity_provider_unavailable")
    } else {
        HttpError::Unauthorized
    }
}
#[allow(clippy::needless_pass_by_value)] // Consumes the underlying error at the HTTP redaction boundary.
fn registry_error(error: RegistryError) -> HttpError {
    match error {
        RegistryError::Database(_) => HttpError::Unavailable("registry_unavailable"),
        RegistryError::Revoked => HttpError::Unauthorized,
        _ => HttpError::Forbidden,
    }
}
#[allow(clippy::needless_pass_by_value)] // Consumes the underlying error at the HTTP redaction boundary.
fn grant_error(error: GrantError) -> HttpError {
    match error {
        GrantError::Invalid => HttpError::Unauthorized,
        GrantError::Forbidden => HttpError::Forbidden,
        GrantError::Request(_) => HttpError::BadRequest("invalid_grant_request"),
        GrantError::Database(_) | GrantError::Signing => {
            HttpError::Unavailable("grant_service_unavailable")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> BTreeMap<String, String> {
        BTreeMap::from([
            (
                "FLEET_RECALL_RESOURCE_URL".into(),
                "https://recall.example/mcp".into(),
            ),
            ("FLEET_RECALL_GRANT_SIGNING_KEY_HEX".into(), "11".repeat(32)),
            (
                "FLEET_RECALL_OIDC_ISSUERS".into(),
                "human=https://id.example/".into(),
            ),
        ])
    }

    #[test]
    fn trust_roots_and_bounds_fail_closed() {
        let base = settings();
        assert!(RemoteConfig::from_lookup(|name| base.get(name).cloned()).is_ok());
        for (name, value) in [
            ("FLEET_RECALL_OIDC_ISSUERS", "local-key=https://id.example/"),
            (
                "FLEET_RECALL_OIDC_ISSUERS",
                "human=https://recall.example/mcp",
            ),
            (
                "FLEET_RECALL_OIDC_ISSUERS",
                "human=https://a/,human=https://b/",
            ),
            (
                "FLEET_RECALL_OIDC_SCOPE_SUBSTITUTES",
                "unknown=fleet-recall",
            ),
            ("FLEET_RECALL_GRANT_CHECK_CACHE_SECONDS", "6"),
            ("FLEET_RECALL_SCOPE_CACHE_MAX", "0"),
            ("FLEET_RECALL_AWS_IAM_SERVER_ID", "partial"),
            ("FLEET_RECALL_AWS_ALLOWED_ACCOUNTS", "123456789012"),
        ] {
            let mut values = base.clone();
            values.insert(name.into(), value.into());
            assert!(
                RemoteConfig::from_lookup(|name| values.get(name).cloned()).is_err(),
                "{name}"
            );
        }
    }

    #[test]
    fn ceilings_and_roles_map_to_served_surfaces_only() {
        assert_eq!(access_for(Ceiling::Project, false).unwrap(), Access::Writer);
        assert_eq!(access_for(Ceiling::Project, true).unwrap(), Access::Shipper);
        assert_eq!(
            access_for(Ceiling::Public, false).unwrap(),
            Access::Publication
        );
        for ceiling in [Ceiling::Private, Ceiling::Trusted] {
            assert!(matches!(
                access_for(ceiling, false),
                Err(HttpError::Forbidden)
            ));
        }
        assert!(access_for(Ceiling::Public, true).is_err());
    }
}
