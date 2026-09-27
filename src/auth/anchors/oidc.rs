//! OIDC discovery and bounded JWKS caching. Provider requests are never
//! redirected, and unknown key IDs share a one-minute refresh cooldown.

use async_trait::async_trait;
use serde::Deserialize;
use std::{
    collections::BTreeSet,
    io::Read as _,
    path::{Path, PathBuf},
};
use tokio::sync::Mutex;

use super::super::{
    AuthError, VerifiedIdentity,
    jose::{self, AudiencePolicy, ClaimsPolicy, Jwk},
};
use super::{IdentityAnchor, bounded_body, discovery_endpoint, endpoint, http_client};

const BODY_LIMIT: usize = 262_144;
const CACHE_SECONDS: i64 = 600;
const REFRESH_COOLDOWN_SECONDS: i64 = 60;
const DISCOVERY_TOKEN_LIMIT: usize = 16_384;

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
    transport_origin: Option<url::Url>,
    discovery_token_path: Option<PathBuf>,
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
            transport_origin: None,
            discovery_token_path: None,
            cache: Mutex::new(KeyCache::default()),
        })
    }

    /// Explicit operator routing for a loopback development issuer published
    /// through a different origin inside the cluster. This never changes JWT
    /// issuer verification or accepts an origin supplied by a token/client.
    /// Only same-issuer-origin discovery and JWKS URLs may use this route.
    pub fn with_local_transport(mut self, origin: Option<&str>) -> Result<Self, AuthError> {
        if let Some(origin) = origin {
            if self.discovery_token_path.is_some() {
                return Err(AuthError::Configuration);
            }
            let issuer = endpoint(&self.policy.issuer, self.allow_http)?;
            let local = match issuer.host() {
                Some(url::Host::Domain(host)) => host == "localhost",
                Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
                Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
                None => false,
            };
            let target = url::Url::parse(origin).map_err(|_| AuthError::Configuration)?;
            if !local
                || !self.allow_http
                || !target.has_host()
                || !matches!(target.scheme(), "http" | "https")
                || !target.username().is_empty()
                || target.password().is_some()
                || target.query().is_some()
                || target.fragment().is_some()
                || target.path() != "/"
            {
                return Err(AuthError::Configuration);
            }
            self.transport_origin = Some(target);
        }
        Ok(self)
    }

    /// Operator-configured projected token for authenticated issuer metadata.
    /// The token is reloaded for every request, including JWKS, so Kubernetes
    /// volume rotation does not require a restart. Authenticated requests may
    /// only use the issuer's exact origin, without a transport override.
    pub fn with_discovery_token_path(mut self, path: Option<&Path>) -> Result<Self, AuthError> {
        if let Some(path) = path {
            if !path.is_absolute() || self.transport_origin.is_some() {
                return Err(AuthError::Configuration);
            }
            self.discovery_token_path = Some(path.to_owned());
        }
        Ok(self)
    }

    fn routed_url(&self, original: &str) -> Result<url::Url, AuthError> {
        let source = discovery_endpoint(original, self.allow_http)?;
        let issuer = endpoint(&self.policy.issuer, self.allow_http)?;
        if (self.discovery_token_path.is_some() || self.transport_origin.is_some())
            && source.origin() != issuer.origin()
        {
            return Err(AuthError::Configuration);
        }
        let Some(target) = &self.transport_origin else {
            return Ok(source);
        };
        let mut routed = target.clone();
        routed.set_path(source.path());
        routed.set_query(source.query());
        Ok(routed)
    }

    async fn request(&self, original: &str) -> Result<reqwest::RequestBuilder, AuthError> {
        // Check origin before reading the token or constructing its header.
        let url = self
            .routed_url(original)
            .map_err(|_| AuthError::ProviderUnavailable)?;
        let mut request = self.client.get(url);
        if let Some(path) = &self.discovery_token_path {
            let path = path.clone();
            let value = tokio::task::spawn_blocking(move || discovery_token(&path))
                .await
                .map_err(|_| AuthError::ProviderUnavailable)??;
            request = request.header(reqwest::header::AUTHORIZATION, value);
        }
        Ok(request)
    }

    async fn fetch_keys(&self) -> Result<Vec<Jwk>, AuthError> {
        let response = self
            .request(&self.discovery_url)
            .await?
            .send()
            .await
            .map_err(|_| AuthError::ProviderUnavailable)?;
        let discovery: Discovery = jose::strict_json(&bounded_body(response, BODY_LIMIT).await?)
            .map_err(|_| AuthError::ProviderUnavailable)?;
        if discovery.issuer != self.policy.issuer {
            return Err(AuthError::ProviderUnavailable);
        }
        let response = self
            .request(&discovery.jwks_uri)
            .await?
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

fn discovery_token(path: &Path) -> Result<reqwest::header::HeaderValue, AuthError> {
    // Projected volumes deliberately use symlinks for atomic rotation. Follow
    // the operator-controlled path, then validate and bound the opened file.
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| AuthError::ProviderUnavailable)?;
    let source = std::fs::File::from(descriptor);
    let metadata = source
        .metadata()
        .map_err(|_| AuthError::ProviderUnavailable)?;
    if !metadata.is_file() || metadata.len() > DISCOVERY_TOKEN_LIMIT as u64 {
        return Err(AuthError::ProviderUnavailable);
    }
    let mut bytes = Vec::new();
    source
        .take(DISCOVERY_TOKEN_LIMIT as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| AuthError::ProviderUnavailable)?;
    if bytes.len() > DISCOVERY_TOKEN_LIMIT {
        return Err(AuthError::ProviderUnavailable);
    }
    let token = std::str::from_utf8(&bytes)
        .map_err(|_| AuthError::ProviderUnavailable)?
        .trim_ascii();
    if token.is_empty() || !token.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(AuthError::ProviderUnavailable);
    }
    let mut value = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))
        .map_err(|_| AuthError::ProviderUnavailable)?;
    value.set_sensitive(true);
    Ok(value)
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

    fn authenticated_anchor(issuer: &str, path: &Path) -> OidcAnchor {
        OidcAnchor::new(OidcConfig {
            anchor_id: "k8s".into(),
            issuer: issuer.into(),
            resource: "https://recall/mcp".into(),
            audience_policy: AudiencePolicy::Required,
            ca_pem: None,
            allow_http: true,
        })
        .unwrap()
        .with_discovery_token_path(Some(path))
        .unwrap()
    }

    #[tokio::test]
    async fn discovery_token_files_are_bounded_sensitive_and_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("token");
        let anchor = authenticated_anchor("http://localhost:4444/", &path);
        assert!(anchor.request(&anchor.discovery_url).await.is_err());
        for invalid in [
            Vec::new(),
            vec![b'x'; DISCOVERY_TOKEN_LIMIT + 1],
            b"first\r\nAuthorization: second".to_vec(),
            b"contains space".to_vec(),
            vec![0xff],
        ] {
            std::fs::write(&path, invalid).unwrap();
            assert!(anchor.request(&anchor.discovery_url).await.is_err());
        }
        std::fs::write(&path, b"header.payload.signature\n").unwrap();
        let request = anchor
            .request(&anchor.discovery_url)
            .await
            .unwrap()
            .build()
            .unwrap();
        let header = &request.headers()[reqwest::header::AUTHORIZATION];
        assert_eq!(header, "Bearer header.payload.signature");
        assert!(header.is_sensitive());
        assert!(!format!("{request:?}").contains("header.payload.signature"));
        assert!(
            authenticated_anchor("http://localhost:4444/", directory.path())
                .request("http://localhost:4444/keys")
                .await
                .is_err()
        );
        assert!(
            anchor
                .with_local_transport(Some("http://internal/"))
                .is_err()
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn discovery_token_follows_projected_symlink_but_refuses_fifo() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("generation-token");
        std::fs::write(&target, b"projected-token").unwrap();
        let link = directory.path().join("token");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let anchor = authenticated_anchor("http://localhost/", &link);
        assert_eq!(
            anchor
                .request(&anchor.discovery_url)
                .await
                .unwrap()
                .build()
                .unwrap()
                .headers()[reqwest::header::AUTHORIZATION],
            "Bearer projected-token"
        );
        let fifo = directory.path().join("fifo");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        let anchor = authenticated_anchor("http://localhost/", &fifo);
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            anchor.request(&anchor.discovery_url),
        )
        .await
        .expect("nonregular token paths must not block");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn authenticated_discovery_reloads_token_for_each_request() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("token");
        std::fs::write(&path, b"first-token").unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}/", listener.local_addr().unwrap());
        let metadata = serde_json::json!({"issuer":issuer,"jwks_uri":format!("{issuer}keys")});
        let signer = Ed25519Signer::from_seed_hex("k8s", &"01".repeat(32)).unwrap();
        let jwks = serde_json::json!({"keys":[signer.public_jwk()]});
        let observed = Arc::new(Mutex::new(Vec::new()));
        let discovery_observed = observed.clone();
        let keys_observed = observed.clone();
        let rotated_path = path.clone();
        let app = Router::new()
            .route(
                "/.well-known/openid-configuration",
                get(move |headers: axum::http::HeaderMap| {
                    let observed = discovery_observed.clone();
                    let metadata = metadata.clone();
                    let path = rotated_path.clone();
                    async move {
                        observed
                            .lock()
                            .await
                            .push(headers[reqwest::header::AUTHORIZATION].clone());
                        // Rotation occurs between discovery and its JWKS request.
                        std::fs::write(path, b"rotated-token").unwrap();
                        axum::Json(metadata)
                    }
                }),
            )
            .route(
                "/keys",
                get(move |headers: axum::http::HeaderMap| {
                    let observed = keys_observed.clone();
                    let jwks = jwks.clone();
                    async move {
                        observed
                            .lock()
                            .await
                            .push(headers[reqwest::header::AUTHORIZATION].clone());
                        axum::Json(jwks)
                    }
                }),
            );
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let anchor = authenticated_anchor(&issuer, &path);
        assert_eq!(anchor.fetch_keys().await.unwrap().len(), 1);
        assert_eq!(anchor.fetch_keys().await.unwrap().len(), 1);
        assert_eq!(
            observed.lock().await.as_slice(),
            [
                "Bearer first-token",
                "Bearer rotated-token",
                "Bearer rotated-token",
                "Bearer rotated-token"
            ]
        );
        task.abort();
    }

    #[tokio::test]
    async fn authenticated_metadata_cannot_send_token_to_another_origin() {
        use axum::response::IntoResponse as _;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("token");
        std::fs::write(&path, b"private-discovery-token").unwrap();
        let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_url = format!("http://{}/keys", target.local_addr().unwrap());
        let leaks = Arc::new(AtomicUsize::new(0));
        let observed = leaks.clone();
        let target_app = Router::new().fallback(move || {
            observed.fetch_add(1, Ordering::SeqCst);
            async { "unexpected" }
        });
        let target_task =
            tokio::spawn(async move { axum::serve(target, target_app).await.unwrap() });
        for redirect in [false, true] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let issuer = format!("http://{}/", listener.local_addr().unwrap());
            let metadata = serde_json::json!({"issuer":issuer,"jwks_uri":target_url});
            let destination = target_url.clone();
            let app = Router::new().route(
                "/.well-known/openid-configuration",
                get(move |headers: axum::http::HeaderMap| {
                    assert_eq!(
                        headers[reqwest::header::AUTHORIZATION],
                        "Bearer private-discovery-token"
                    );
                    let metadata = metadata.clone();
                    let destination = destination.clone();
                    async move {
                        if redirect {
                            axum::response::Redirect::temporary(&destination).into_response()
                        } else {
                            axum::Json(metadata).into_response()
                        }
                    }
                }),
            );
            let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let anchor = authenticated_anchor(&issuer, &path);
            assert_eq!(
                anchor.fetch_keys().await.unwrap_err(),
                AuthError::ProviderUnavailable
            );
            assert_eq!(leaks.load(Ordering::SeqCst), 0);
            task.abort();
        }
        target_task.abort();
    }

    #[test]
    fn local_transport_preserves_issuer_paths_and_rejects_origin_escape() {
        let make = |issuer: &str| {
            OidcAnchor::new(OidcConfig {
                anchor_id: "hydra".into(),
                issuer: issuer.into(),
                resource: "https://recall/mcp".into(),
                audience_policy: AudiencePolicy::Required,
                ca_pem: None,
                allow_http: true,
            })
            .unwrap()
        };
        let anchor = make("http://localhost:4444/")
            .with_local_transport(Some("http://hydra-public.ory.svc.cluster.local:4444/"))
            .unwrap();
        assert_eq!(anchor.issuer(), "http://localhost:4444/");
        assert_eq!(
            anchor
                .routed_url("http://localhost:4444/.well-known/jwks.json?v=1")
                .unwrap()
                .as_str(),
            "http://hydra-public.ory.svc.cluster.local:4444/.well-known/jwks.json?v=1"
        );
        assert!(anchor.routed_url("https://evil.example/keys").is_err());
        assert!(anchor.routed_url("http://localhost:5555/keys").is_err());
        assert!(
            make("https://issuer.example")
                .with_local_transport(Some("http://internal/"))
                .is_err()
        );
        for target in [
            "http://user:pass@internal/",
            "http://internal/prefix",
            "http://internal/?q=1",
            "http://internal/#x",
            "file:///tmp/key",
        ] {
            assert!(
                make("http://localhost:4444/")
                    .with_local_transport(Some(target))
                    .is_err()
            );
        }
    }

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
