//! Configured identity trust roots. Identity verification is separate from
//! principal resolution and grant revocation.

pub mod aws_iam;
pub mod local_key;
pub mod oidc;

use async_trait::async_trait;
use url::Url;

use super::{AuthError, VerifiedIdentity};

#[async_trait]
pub trait IdentityAnchor: Send + Sync {
    fn anchor_id(&self) -> &str;
    fn issuer(&self) -> &str;
    fn accepts_issuer(&self, issuer: &str) -> bool {
        self.issuer() == issuer
    }
    async fn verify(&self, jws: &str, now: i64) -> Result<VerifiedIdentity, AuthError>;
}

pub(super) fn endpoint(value: &str, allow_http: bool) -> Result<Url, AuthError> {
    let url = discovery_endpoint(value, allow_http)?;
    if url.query().is_some() {
        return Err(AuthError::Configuration);
    }
    Ok(url)
}

/// An issuer-provided JWKS URI may contain a query string. It still cannot
/// redirect, carry credentials, downgrade TLS, or name non-loopback HTTP.
pub(super) fn discovery_endpoint(value: &str, allow_http: bool) -> Result<Url, AuthError> {
    let url = Url::parse(value).map_err(|_| AuthError::Configuration)?;
    let loopback = match url.host() {
        Some(url::Host::Domain(host)) => host == "localhost",
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    };
    if !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || !(url.scheme() == "https" || allow_http && loopback && url.scheme() == "http")
    {
        return Err(AuthError::Configuration);
    }
    Ok(url)
}

pub(super) fn http_client(ca_pem: Option<&[u8]>) -> Result<reqwest::Client, AuthError> {
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(5))
        .connect_timeout(std::time::Duration::from_secs(2))
        .no_proxy();
    if let Some(pem) = ca_pem {
        let certs =
            reqwest::Certificate::from_pem_bundle(pem).map_err(|_| AuthError::Configuration)?;
        if certs.is_empty() {
            return Err(AuthError::Configuration);
        }
        for cert in certs {
            builder = builder.add_root_certificate(cert);
        }
    }
    builder.build().map_err(|_| AuthError::Configuration)
}

pub(super) async fn bounded_body(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, AuthError> {
    if !response.status().is_success()
        || response
            .content_length()
            .is_some_and(|length| length > limit as u64)
    {
        return Err(AuthError::ProviderUnavailable);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| AuthError::ProviderUnavailable)?
    {
        if body.len().saturating_add(chunk.len()) > limit {
            return Err(AuthError::ProviderUnavailable);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}
