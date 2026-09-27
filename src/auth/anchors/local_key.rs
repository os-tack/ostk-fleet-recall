//! Laptop/break-glass assertions. An assertion's subject is its enrolled
//! key identifier, so one valid local key cannot impersonate another key.

use super::{
    super::{
        AuthError, VerifiedIdentity,
        jose::{self, ClaimsPolicy, Jwk},
    },
    IdentityAnchor,
};
use crate::encoding::base64::encode_url;
use async_trait::async_trait;
use std::collections::BTreeMap;

pub const LOCAL_KEY_ISSUER: &str = "fleet-recall-local-key";

pub struct LocalKeyAnchor {
    anchor_id: String,
    keys: Vec<Jwk>,
    policy: ClaimsPolicy,
}

impl LocalKeyAnchor {
    /// JSON object mapping key identifiers to 32-byte public keys as hex.
    pub fn from_json(anchor_id: &str, resource: &str, bytes: &[u8]) -> Result<Self, AuthError> {
        if !jose::valid_identifier(anchor_id, 128) || resource.is_empty() || bytes.len() > 65_536 {
            return Err(AuthError::Configuration);
        }
        let source: BTreeMap<String, String> =
            jose::strict_json(bytes).map_err(|_| AuthError::Configuration)?;
        if source.is_empty() || source.len() > jose::MAX_JWKS_KEYS {
            return Err(AuthError::Configuration);
        }
        let mut keys = Vec::new();
        for (kid, public) in source {
            if !jose::valid_identifier(&kid, 256) || public.len() != 64 {
                return Err(AuthError::Configuration);
            }
            let public = hex::decode(public).map_err(|_| AuthError::Configuration)?;
            keys.push(Jwk {
                kty: "OKP".into(),
                kid: Some(kid),
                alg: Some("EdDSA".into()),
                usage: Some("sig".into()),
                key_ops: Some(vec!["verify".into()]),
                crv: Some("Ed25519".into()),
                x: Some(encode_url(&public)),
                y: None,
                n: None,
                e: None,
            });
        }
        let mut policy = ClaimsPolicy::new(LOCAL_KEY_ISSUER, resource);
        policy.require_jti = true;
        policy.max_remaining_seconds = Some(300);
        Ok(Self {
            anchor_id: anchor_id.into(),
            keys,
            policy,
        })
    }
}

#[async_trait]
impl IdentityAnchor for LocalKeyAnchor {
    fn anchor_id(&self) -> &str {
        &self.anchor_id
    }
    fn issuer(&self) -> &str {
        LOCAL_KEY_ISSUER
    }
    async fn verify(&self, jws: &str, now: i64) -> Result<VerifiedIdentity, AuthError> {
        let claims = jose::verify(jws, &self.keys, &self.policy, now)?;
        if jose::unverified_kid(jws)?.as_deref() != Some(claims.sub.as_str()) {
            return Err(AuthError::InvalidToken);
        }
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
    use crate::encoding::base64::decode_url;

    #[tokio::test]
    async fn local_keys_cannot_impersonate_other_subjects() {
        let signer = Ed25519Signer::from_seed_hex("laptop", &"12".repeat(32)).unwrap();
        let public = hex::encode(decode_url(signer.public_jwk().x.as_ref().unwrap()).unwrap());
        let anchor = LocalKeyAnchor::from_json(
            "local",
            "https://recall/mcp",
            &serde_json::to_vec(&serde_json::json!({"laptop":public})).unwrap(),
        )
        .unwrap();
        let claims = serde_json::json!({"iss":LOCAL_KEY_ISSUER,"aud":"https://recall/mcp","sub":"laptop","exp":1200,"jti":"unique"});
        let token = signer.sign(&claims).unwrap();
        assert_eq!(anchor.verify(&token, 1000).await.unwrap().subject, "laptop");
        for (field, value) in [
            ("sub", serde_json::json!("other-laptop")),
            ("exp", serde_json::json!(1301)),
            ("jti", serde_json::json!(null)),
            ("aud", serde_json::json!("https://other")),
        ] {
            let mut bad = claims.clone();
            bad[field] = value;
            assert!(
                anchor
                    .verify(&signer.sign(&bad).unwrap(), 1000)
                    .await
                    .is_err()
            );
        }
    }
}
