//! Remote identity verification. Anchors establish identity; the principal
//! registry and logged grants alone establish authority.

pub mod anchors;
pub mod grant;
pub mod jose;
pub mod registry;

use std::sync::Arc;

use anchors::IdentityAnchor;

/// Deliberately static errors: no token, provider response, or key material
/// can enter an HTTP response or log through this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthError {
    #[error("invalid authentication token")]
    InvalidToken,
    #[error("authentication token has expired or is not yet valid")]
    InvalidTime,
    #[error("authentication issuer is not configured")]
    UnknownIssuer,
    #[error("authentication key is not available")]
    UnknownKey,
    #[error("authentication provider is unavailable")]
    ProviderUnavailable,
    #[error("invalid authentication configuration")]
    Configuration,
}

/// The complete output of an identity anchor. Scope and role are never
/// accepted from provider claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedIdentity {
    pub anchor_id: String,
    pub subject: String,
}

/// A closed, configured issuer registry. Unverified `iss` only selects a
/// verifier; it cannot trigger discovery of an unconfigured issuer.
pub struct Authenticator {
    anchors: Vec<Arc<dyn IdentityAnchor>>,
}

impl Authenticator {
    pub fn new(anchors: Vec<Arc<dyn IdentityAnchor>>) -> Result<Self, AuthError> {
        if anchors.len() > 64
            || anchors.iter().enumerate().any(|(i, anchor)| {
                anchor.anchor_id().is_empty()
                    || anchors[..i].iter().any(|other| {
                        other.anchor_id() == anchor.anchor_id()
                            || other.accepts_issuer(anchor.issuer())
                    })
            })
        {
            return Err(AuthError::Configuration);
        }
        Ok(Self { anchors })
    }

    pub async fn authenticate(
        &self,
        bearer: &str,
        now: i64,
    ) -> Result<VerifiedIdentity, AuthError> {
        let issuer = jose::unverified_issuer(bearer)?;
        let anchor = self
            .anchors
            .iter()
            .find(|anchor| anchor.accepts_issuer(&issuer))
            .ok_or(AuthError::UnknownIssuer)?;
        anchor.verify(bearer, now).await
    }
}
