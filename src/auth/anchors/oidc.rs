//! OIDC discovery and bounded JWKS caching. Provider requests are never
//! redirected, and unknown key IDs share a one-minute refresh cooldown.

use async_trait::async_trait;
use serde::Deserialize;
use std::collections::BTreeSet;
use tokio::sync::Mutex;

use super::super::{
    AuthError, VerifiedIdentity,
    jose::{self, AudiencePolicy, ClaimsPolicy, Jwk},
};
use super::{IdentityAnchor, bounded_body, discovery_endpoint, endpoint, http_client};

const BODY_LIMIT: usize = 262_144;
const CACHE_SECONDS: i64 = 600;
const REFRESH_COOLDOWN_SECONDS: i64 = 60;

pub struct OidcConfig {
    pub anchor_id: String,
    pub issuer: String,
    pub resource: String,
    pub audience_policy: AudiencePolicy,
    pub ca_pem: Option<Vec<u8>>,
    /// Development only; restricted to literal loopback hosts/addresses.
    pub allow_http: bool,
}

pub struct OidcAnchor {
    anchor_id: String,
    policy: ClaimsPolicy,
    discovery_url: String,
    allow_http: bool,
    client: reqwest::Client,
    cache: Mutex<KeyCache>,
}

#[derive(Default)]
struct KeyCache {
    keys: Vec<Jwk>,
    fetched_at: Option<i64>,
    last_attempt: Option<i64>,
}

#[derive(Deserialize)]
struct Discovery {
    issuer: String,
    jwks_uri: String,
}
#[derive(Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

impl OidcAnchor {
    pub fn new(config: OidcConfig) -> Result<Self, AuthError> {
        endpoint(&config.issuer, config.allow_http)?;
        if !jose::valid_identifier(&config.anchor_id, 128)
            || config.resource.is_empty()
            || matches!(&config.audience_policy, AudiencePolicy::ScopeSubstitute(scope) if scope.is_empty() || scope.split_ascii_whitespace().count()!=1)
        {
            return Err(AuthError::Configuration);
        }
        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            config.issuer.trim_end_matches('/')
        );
        let mut policy = ClaimsPolicy::new(config.issuer, config.resource);
        policy.audience_policy = config.audience_policy;
        Ok(Self {
            anchor_id: config.anchor_id,
            policy,
            discovery_url,
            allow_http: config.allow_http,
            client: http_client(config.ca_pem.as_deref())?,
            cache: Mutex::new(KeyCache::default()),
        })
    }

    async fn fetch_keys(&self) -> Result<Vec<Jwk>, AuthError> {
        let response = self
            .client
            .get(&self.discovery_url)
            .send()
            .await
            .map_err(|_| AuthError::ProviderUnavailable)?;
        let discovery: Discovery = jose::strict_json(&bounded_body(response, BODY_LIMIT).await?)
            .map_err(|_| AuthError::ProviderUnavailable)?;
        if discovery.issuer != self.policy.issuer {
            return Err(AuthError::ProviderUnavailable);
        }
        let jwks_url = discovery_endpoint(&discovery.jwks_uri, self.allow_http)
            .map_err(|_| AuthError::ProviderUnavailable)?;
        let response = self
            .client
            .get(jwks_url)
            .send()
            .await
            .map_err(|_| AuthError::ProviderUnavailable)?;
        let jwks: Jwks = jose::strict_json(&bounded_body(response, BODY_LIMIT).await?)
            .map_err(|_| AuthError::ProviderUnavailable)?;
        let mut kids = BTreeSet::new();
        if jwks.keys.is_empty()
            || jwks.keys.len() > jose::MAX_JWKS_KEYS
            || jwks.keys.iter().any(|key| {
                key.kid
                    .as_deref()
                    .is_some_and(|kid| !jose::valid_identifier(kid, 256) || !kids.insert(kid))
            })
        {
            return Err(AuthError::ProviderUnavailable);
        }
        Ok(jwks.keys)
    }

    async fn keys(&self, kid: Option<&str>, now: i64) -> Result<Vec<Jwk>, AuthError> {
        // Keep the guard across refresh so concurrent misses cannot amplify
        // requests; requests against fresh known keys do no network I/O.
        let mut cache = self.cache.lock().await;
        let fresh = cache
            .fetched_at
            .is_some_and(|at| (0..CACHE_SECONDS).contains(&now.saturating_sub(at)));
        let known =
            kid.is_none_or(|kid| cache.keys.iter().any(|key| key.kid.as_deref() == Some(kid)));
        if fresh && known {
            return Ok(cache.keys.clone());
        }
        if cache
            .last_attempt
            .is_some_and(|at| now.saturating_sub(at) < REFRESH_COOLDOWN_SECONDS)
        {
            return Err(if fresh {
                AuthError::UnknownKey
            } else {
                AuthError::ProviderUnavailable
            });
        }
        cache.last_attempt = Some(now);
        let keys = self.fetch_keys().await?;
        cache.keys = keys;
        cache.fetched_at = Some(now);
        Ok(cache.keys.clone())
    }
}

#[async_trait]
impl IdentityAnchor for OidcAnchor {
    fn anchor_id(&self) -> &str {
        &self.anchor_id
    }
    fn issuer(&self) -> &str {
        &self.policy.issuer
    }
    async fn verify(&self, jws: &str, now: i64) -> Result<VerifiedIdentity, AuthError> {
        if jose::unverified_issuer(jws)? != self.policy.issuer {
            return Err(AuthError::UnknownIssuer);
        }
        let kid = jose::unverified_kid(jws)?;
        let keys = self.keys(kid.as_deref(), now).await?;
        let claims = jose::verify(jws, &keys, &self.policy, now)?;
        Ok(VerifiedIdentity {
            anchor_id: self.anchor_id.clone(),
            subject: claims.sub,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::jose::Ed25519Signer;
    use axum::{Router, routing::get};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::sync::RwLock;

    #[tokio::test]
    async fn discovery_rotation_and_miss_cooldown_are_bounded() {
        let old = Ed25519Signer::from_seed_hex("old", &"01".repeat(32)).unwrap();
        let new = Ed25519Signer::from_seed_hex("new", &"02".repeat(32)).unwrap();
        let keys = Arc::new(RwLock::new(serde_json::json!({"keys":[old.public_jwk()]})));
        let discovery_calls = Arc::new(AtomicUsize::new(0));
        let key_calls = Arc::new(AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}/", listener.local_addr().unwrap());
        let metadata = serde_json::json!({"issuer":issuer,"jwks_uri":format!("{issuer}keys")});
        let dc = discovery_calls.clone();
        let kc = key_calls.clone();
        let document = keys.clone();
        let app = Router::new()
            .route(
                "/.well-known/openid-configuration",
                get(move || {
                    dc.fetch_add(1, Ordering::SeqCst);
                    let metadata = metadata.clone();
                    async { axum::Json(metadata) }
                }),
            )
            .route(
                "/keys",
                get(move || {
                    let keys = document.clone();
                    kc.fetch_add(1, Ordering::SeqCst);
                    async move { axum::Json(keys.read().await.clone()) }
                }),
            );
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let anchor = OidcAnchor::new(OidcConfig {
            anchor_id: "test".into(),
            issuer: issuer.clone(),
            resource: "https://recall/mcp".into(),
            audience_policy: AudiencePolicy::Required,
            ca_pem: None,
            allow_http: true,
        })
        .unwrap();
        let claims =
            serde_json::json!({"iss":issuer,"sub":"human","aud":"https://recall/mcp","exp":5000});
        let token = old.sign(&claims).unwrap();
        assert_eq!(anchor.verify(&token, 1000).await.unwrap().subject, "human");
        assert!(anchor.verify(&token, 1001).await.is_ok());
        *keys.write().await = serde_json::json!({"keys":[new.public_jwk()]});
        let rotated = new.sign(&claims).unwrap();
        for _ in 0..10 {
            assert_eq!(
                anchor.verify(&rotated, 1001).await.unwrap_err(),
                AuthError::UnknownKey
            );
        }
        assert_eq!(discovery_calls.load(Ordering::SeqCst), 1);
        assert_eq!(key_calls.load(Ordering::SeqCst), 1);
        assert!(anchor.verify(&rotated, 1060).await.is_ok());
        assert_eq!(key_calls.load(Ordering::SeqCst), 2);
        assert!(anchor.verify(&token, 1061).await.is_err());
        assert_eq!(key_calls.load(Ordering::SeqCst), 2);
        task.abort();
        assert!(anchor.verify(&rotated, 1100).await.is_ok());
        assert_eq!(
            anchor.verify(&rotated, 1700).await.unwrap_err(),
            AuthError::ProviderUnavailable
        );
    }

    #[tokio::test]
    async fn discovery_must_match_issuer_and_redirects_are_not_followed() {
        for redirect in [false, true] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let issuer = format!("http://{}/", listener.local_addr().unwrap());
            let app=Router::new().route("/.well-known/openid-configuration",get(move ||async move {
                use axum::response::IntoResponse;
                if redirect { axum::response::Redirect::temporary("http://169.254.169.254/secret").into_response() }
                else {axum::Json(serde_json::json!({"issuer":"https://different/","jwks_uri":"https://different/keys"})).into_response()}
            }));
            let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let anchor = OidcAnchor::new(OidcConfig {
                anchor_id: "test".into(),
                issuer,
                resource: "https://recall/mcp".into(),
                audience_policy: AudiencePolicy::Required,
                ca_pem: None,
                allow_http: true,
            })
            .unwrap();
            assert_eq!(
                anchor.fetch_keys().await.unwrap_err(),
                AuthError::ProviderUnavailable
            );
            task.abort();
        }
    }

    #[test]
    fn insecure_and_credential_bearing_endpoints_are_rejected() {
        for url in [
            "http://issuer.example/",
            "https://user:secret@issuer.example/",
            "https://issuer.example/#keys",
            "https://issuer.example/?keys=1",
        ] {
            assert!(endpoint(url, true).is_err());
        }
        assert!(endpoint("http://localhost:4444/", false).is_err());
        assert!(endpoint("http://127.0.0.1:4444/", true).is_ok());
    }
}
