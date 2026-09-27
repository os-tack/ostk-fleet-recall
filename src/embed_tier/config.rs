//! Secret-redacting embedding tier client and server configuration.

use super::TierError;
use std::time::Duration;
use url::Url;

pub const TIER_URL_ENV: &str = "FLEET_RECALL_EMBEDDING_TIER_URL";
pub const TIER_TOKEN_ENV: &str = "FLEET_RECALL_EMBEDDING_TIER_TOKEN";

#[derive(Clone)]
pub struct RemoteConfig {
    pub endpoint: Url,
    pub timeout: Duration,
    token: Option<String>,
}

impl RemoteConfig {
    pub fn new(
        endpoint: &str,
        timeout: Duration,
        token: Option<String>,
    ) -> Result<Self, TierError> {
        let endpoint = Url::parse(endpoint).map_err(|_| TierError::Configuration)?;
        if !matches!(endpoint.scheme(), "http" | "https")
            || endpoint.host().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || timeout < Duration::from_millis(1)
            || timeout > Duration::from_secs(30)
        {
            return Err(TierError::Configuration);
        }
        validate_token(token.as_deref())?;
        Ok(Self {
            endpoint,
            timeout,
            token,
        })
    }
    pub fn from_env() -> Result<Option<Self>, TierError> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Option<Self>, TierError> {
        let Some(endpoint) = lookup(TIER_URL_ENV) else {
            return Ok(None);
        };
        let milliseconds = lookup("FLEET_RECALL_EMBEDDING_TIER_TIMEOUT_MS")
            .map_or(Ok(2000), |value| {
                value.parse::<u64>().map_err(|_| TierError::Configuration)
            })?;
        Self::new(
            &endpoint,
            Duration::from_millis(milliseconds),
            lookup(TIER_TOKEN_ENV),
        )
        .map(Some)
    }
    pub(super) fn token(&self) -> Option<&str> {
        self.token.as_deref()
    }
}

pub(super) fn validate_token(token: Option<&str>) -> Result<(), TierError> {
    if token.is_some_and(|token| {
        token.is_empty() || token.len() > 4096 || token.bytes().any(|byte| !byte.is_ascii_graphic())
    }) {
        return Err(TierError::Configuration);
    }
    Ok(())
}
