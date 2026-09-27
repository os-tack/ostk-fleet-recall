//! Narrow JOSE implementation: canonical compact JWS with RS256, ES256,
//! or EdDSA/Ed25519 only.
//!
//! No algorithm-selected secrets, remote header keys,
//! unencoded payloads, detached payloads, or critical extensions.

use std::{collections::BTreeSet, fmt};

use ring::signature::{self, KeyPair};
use serde::{
    Deserialize, Serialize,
    de::{self, DeserializeOwned, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Value};

use super::AuthError;
use crate::encoding::base64::{decode_url, encode_url};

pub const MAX_TOKEN_BYTES: usize = 16_384;
pub const MAX_JWKS_KEYS: usize = 64;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Jwk {
    pub kty: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    pub usage: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_ops: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(untagged)]
pub enum Audience {
    One(String),
    Many(Vec<String>),
    #[default]
    Missing,
}

impl Audience {
    pub fn contains(&self, expected: &str) -> bool {
        match self {
            Self::One(value) => value == expected,
            Self::Many(values) => values.iter().any(|value| value == expected),
            Self::Missing => false,
        }
    }

    pub const fn is_empty(&self) -> bool {
        match self {
            Self::One(value) => value.is_empty(),
            Self::Many(values) => values.is_empty(),
            Self::Missing => true,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub exp: i64,
    #[serde(default)]
    pub aud: Audience,
    pub iat: Option<i64>,
    pub nbf: Option<i64>,
    pub jti: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum AudiencePolicy {
    #[default]
    Required,
    /// Explicit per-issuer workaround. Never permits a nonempty audience
    /// naming some different resource, even with a matching scope.
    ScopeSubstitute(String),
}

#[derive(Debug, Clone)]
pub struct ClaimsPolicy {
    pub issuer: String,
    pub audience: String,
    pub audience_policy: AudiencePolicy,
    pub require_jti: bool,
    pub max_remaining_seconds: Option<i64>,
    pub leeway_seconds: i64,
}

impl ClaimsPolicy {
    pub fn new(issuer: impl Into<String>, audience: impl Into<String>) -> Self {
        Self {
            issuer: issuer.into(),
            audience: audience.into(),
            audience_policy: AudiencePolicy::Required,
            require_jti: false,
            max_remaining_seconds: None,
            leeway_seconds: 60,
        }
    }

    pub fn validate(&self, claims: &Claims, now: i64) -> Result<(), AuthError> {
        if self.issuer.is_empty()
            || self.audience.is_empty()
            || !(0..=300).contains(&self.leeway_seconds)
        {
            return Err(AuthError::Configuration);
        }
        if claims.iss != self.issuer || !valid_identifier(&claims.sub, 2048) {
            return Err(AuthError::InvalidToken);
        }
        if now.saturating_sub(self.leeway_seconds) >= claims.exp
            || claims
                .nbf
                .is_some_and(|nbf| nbf > now.saturating_add(self.leeway_seconds))
            || claims.iat.is_some_and(|iat| {
                iat > now.saturating_add(self.leeway_seconds) || iat >= claims.exp
            })
            || self
                .max_remaining_seconds
                .is_some_and(|max| max <= 0 || claims.exp > now.saturating_add(max))
        {
            return Err(AuthError::InvalidTime);
        }
        if self.require_jti
            && !claims
                .jti
                .as_deref()
                .is_some_and(|jti| valid_identifier(jti, 256))
        {
            return Err(AuthError::InvalidToken);
        }
        if !claims.aud.contains(&self.audience) {
            let substitute = match &self.audience_policy {
                AudiencePolicy::Required => false,
                AudiencePolicy::ScopeSubstitute(scope) => {
                    !scope.is_empty() && claims.aud.is_empty() && has_scope(claims, scope)
                }
            };
            if !substitute {
                return Err(AuthError::InvalidToken);
            }
        }
        Ok(())
    }
}

fn has_scope(claims: &Claims, expected: &str) -> bool {
    ["scp", "scope"]
        .iter()
        .any(|name| match claims.extra.get(*name) {
            Some(Value::String(value)) => value
                .split_ascii_whitespace()
                .any(|scope| scope == expected),
            Some(Value::Array(values)) => {
                values.iter().all(Value::is_string)
                    && values.iter().any(|scope| scope.as_str() == Some(expected))
            }
            _ => false,
        })
}

pub(super) fn valid_identifier(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}

#[derive(Deserialize)]
struct Header {
    alg: String,
    kid: Option<String>,
    crit: Option<Vec<String>>,
    b64: Option<bool>,
}

struct Parsed<'a> {
    header: Header,
    claims: Claims,
    signing_input: &'a [u8],
    signature: Vec<u8>,
}

fn parse(token: &str) -> Result<Parsed<'_>, AuthError> {
    if token.len() > MAX_TOKEN_BYTES {
        return Err(AuthError::InvalidToken);
    }
    let mut parts = token.split('.');
    let header = parts.next().ok_or(AuthError::InvalidToken)?;
    let payload = parts.next().ok_or(AuthError::InvalidToken)?;
    let signature = parts.next().ok_or(AuthError::InvalidToken)?;
    if parts.next().is_some()
        || header.is_empty()
        || header.len() > 4096
        || payload.is_empty()
        || signature.is_empty()
        || signature.len() > 1400
    {
        return Err(AuthError::InvalidToken);
    }
    let header: Header = strict_json(&decode_url(header).ok_or(AuthError::InvalidToken)?)?;
    if !matches!(header.alg.as_str(), "RS256" | "ES256" | "EdDSA")
        || header.crit.is_some()
        || header.b64 == Some(false)
        || header
            .kid
            .as_deref()
            .is_some_and(|kid| !valid_identifier(kid, 256))
    {
        return Err(AuthError::InvalidToken);
    }
    Ok(Parsed {
        header,
        claims: strict_json(&decode_url(payload).ok_or(AuthError::InvalidToken)?)?,
        signing_input: &token.as_bytes()[..token.len() - signature.len() - 1],
        signature: decode_url(signature).ok_or(AuthError::InvalidToken)?,
    })
}

/// Only for dispatch into configured anchors, never an authenticated result.
pub fn unverified_issuer(token: &str) -> Result<String, AuthError> {
    Ok(parse(token)?.claims.iss)
}

/// The key identifier used for bounded JWKS refresh decisions.
pub fn unverified_kid(token: &str) -> Result<Option<String>, AuthError> {
    Ok(parse(token)?.header.kid)
}

pub fn verify(
    token: &str,
    keys: &[Jwk],
    policy: &ClaimsPolicy,
    now: i64,
) -> Result<Claims, AuthError> {
    let parsed = parse(token)?;
    if keys.is_empty() || keys.len() > MAX_JWKS_KEYS {
        return Err(AuthError::UnknownKey);
    }
    let mut eligible = keys.iter().filter(|key| {
        parsed
            .header
            .kid
            .as_ref()
            .is_none_or(|kid| key.kid.as_ref() == Some(kid))
            && key.alg.as_ref().is_none_or(|alg| alg == &parsed.header.alg)
            && key.usage.as_deref().is_none_or(|usage| usage == "sig")
            && key.key_ops.as_ref().is_none_or(|ops| {
                ops.iter().any(|op| op == "verify") && !ops.iter().any(|op| op != "verify")
            })
            && matches!(
                (
                    parsed.header.alg.as_str(),
                    key.kty.as_str(),
                    key.crv.as_deref()
                ),
                ("RS256", "RSA", _)
                    | ("ES256", "EC", Some("P-256"))
                    | ("EdDSA", "OKP", Some("Ed25519"))
            )
    });
    let key = eligible.next().ok_or(AuthError::UnknownKey)?;
    if eligible.next().is_some() {
        return Err(AuthError::UnknownKey);
    }
    verify_signature(&parsed, key)?;
    policy.validate(&parsed.claims, now)?;
    Ok(parsed.claims)
}

fn component(value: Option<&str>) -> Result<Vec<u8>, AuthError> {
    decode_url(value.ok_or(AuthError::InvalidToken)?).ok_or(AuthError::InvalidToken)
}

fn verify_signature(parsed: &Parsed<'_>, key: &Jwk) -> Result<(), AuthError> {
    let result = match parsed.header.alg.as_str() {
        "RS256" => {
            let n = component(key.n.as_deref())?;
            let e = component(key.e.as_deref())?;
            if !(256..=1024).contains(&n.len())
                || n[0] == 0
                || e.is_empty()
                || e.len() > 8
                || e[0] == 0
            {
                return Err(AuthError::InvalidToken);
            }
            signature::RsaPublicKeyComponents { n: &n, e: &e }.verify(
                &signature::RSA_PKCS1_2048_8192_SHA256,
                parsed.signing_input,
                &parsed.signature,
            )
        }
        "ES256" => {
            let x = component(key.x.as_deref())?;
            let y = component(key.y.as_deref())?;
            if x.len() != 32 || y.len() != 32 {
                return Err(AuthError::InvalidToken);
            }
            let mut point = Vec::with_capacity(65);
            point.push(4);
            point.extend(x);
            point.extend(y);
            signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, point)
                .verify(parsed.signing_input, &parsed.signature)
        }
        "EdDSA" => {
            let x = component(key.x.as_deref())?;
            if x.len() != 32 {
                return Err(AuthError::InvalidToken);
            }
            signature::UnparsedPublicKey::new(&signature::ED25519, x)
                .verify(parsed.signing_input, &parsed.signature)
        }
        _ => return Err(AuthError::InvalidToken),
    };
    result.map_err(|_| AuthError::InvalidToken)
}

/// Signing keys never implement Debug, Serialize, or expose seed bytes.
pub struct Ed25519Signer {
    kid: String,
    key: signature::Ed25519KeyPair,
}

impl Ed25519Signer {
    pub fn from_seed_hex(kid: &str, seed_hex: &str) -> Result<Self, AuthError> {
        if !valid_identifier(kid, 256) || seed_hex.len() != 64 {
            return Err(AuthError::Configuration);
        }
        let mut seed = [0_u8; 32];
        hex::decode_to_slice(seed_hex, &mut seed).map_err(|_| AuthError::Configuration)?;
        let key = signature::Ed25519KeyPair::from_seed_unchecked(&seed)
            .map_err(|_| AuthError::Configuration)?;
        seed.fill(0);
        Ok(Self {
            kid: kid.to_owned(),
            key,
        })
    }

    pub fn public_jwk(&self) -> Jwk {
        Jwk {
            kty: "OKP".into(),
            kid: Some(self.kid.clone()),
            alg: Some("EdDSA".into()),
            usage: Some("sig".into()),
            key_ops: Some(vec!["verify".into()]),
            crv: Some("Ed25519".into()),
            x: Some(encode_url(self.key.public_key().as_ref())),
            y: None,
            n: None,
            e: None,
        }
    }

    pub fn sign(&self, claims: &Value) -> Result<String, AuthError> {
        if !claims.is_object() {
            return Err(AuthError::InvalidToken);
        }
        let header = serde_json::json!({"alg":"EdDSA", "kid":self.kid, "typ":"JWT"});
        let mut input = format!(
            "{}.{}",
            encode_url(&serde_json::to_vec(&header).map_err(|_| AuthError::InvalidToken)?),
            encode_url(&serde_json::to_vec(claims).map_err(|_| AuthError::InvalidToken)?)
        );
        let signature = self.key.sign(input.as_bytes());
        input.push('.');
        input.push_str(&encode_url(signature.as_ref()));
        if input.len() > MAX_TOKEN_BYTES {
            return Err(AuthError::InvalidToken);
        }
        Ok(input)
    }
}

/// Reject duplicate JSON members, including nested objects, before typed
/// deserialization. A verifier and a consumer must not disagree on claims.
pub(super) fn strict_json<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, AuthError> {
    let value: UniqueValue = serde_json::from_slice(bytes).map_err(|_| AuthError::InvalidToken)?;
    serde_json::from_value(value.0).map_err(|_| AuthError::InvalidToken)
}

struct UniqueValue(Value);
impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D: de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct UniqueVisitor;
        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = UniqueValue;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("JSON without duplicate members")
            }
            fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
                serde_json::Number::from_f64(value)
                    .map(|n| UniqueValue(Value::Number(n)))
                    .ok_or_else(|| E::custom("invalid number"))
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(UniqueValue(value.into()))
            }
            fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Null))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(UniqueValue(value)) = seq.next_element()? {
                    values.push(value);
                }
                Ok(UniqueValue(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut values = Map::new();
                let mut seen = BTreeSet::new();
                while let Some(key) = map.next_key::<String>()? {
                    if !seen.insert(key.clone()) {
                        return Err(de::Error::custom("duplicate JSON member"));
                    }
                    let UniqueValue(value) = map.next_value()?;
                    values.insert(key, value);
                }
                Ok(UniqueValue(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(UniqueVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use serde_json::json;

    fn claims() -> Value {
        json!({"iss":"https://issuer/","sub":"human","aud":"https://recall/mcp","exp":1300,"iat":900,"jti":"unique"})
    }
    fn policy() -> ClaimsPolicy {
        ClaimsPolicy::new("https://issuer/", "https://recall/mcp")
    }
    fn raw_token(
        alg: &str,
        kid: &str,
        value: &Value,
        sign: impl FnOnce(&[u8]) -> Vec<u8>,
    ) -> String {
        let input = format!(
            "{}.{}",
            encode_url(&serde_json::to_vec(&json!({"alg":alg,"kid":kid})).unwrap()),
            encode_url(&serde_json::to_vec(value).unwrap())
        );
        format!("{input}.{}", encode_url(&sign(input.as_bytes())))
    }

    #[test]
    fn ed25519_claims_signature_and_key_binding() {
        let signer = Ed25519Signer::from_seed_hex("ed", &"11".repeat(32)).unwrap();
        let key = signer.public_jwk();
        let token = signer.sign(&claims()).unwrap();
        assert_eq!(
            verify(&token, std::slice::from_ref(&key), &policy(), 1000)
                .unwrap()
                .sub,
            "human"
        );
        for (field, value) in [
            ("aud", json!("https://elsewhere/")),
            ("iss", json!("https://attacker/")),
            ("sub", json!("")),
            ("exp", json!(940)),
            ("nbf", json!(1061)),
            ("iat", json!(1061)),
        ] {
            let mut bad = claims();
            bad[field] = value;
            assert!(
                verify(
                    &signer.sign(&bad).unwrap(),
                    std::slice::from_ref(&key),
                    &policy(),
                    1000
                )
                .is_err(),
                "{field}"
            );
        }
        let mut altered = token.clone().into_bytes();
        let last = altered.len() - 4;
        altered[last] = if altered[last] == b'A' { b'B' } else { b'A' };
        assert!(
            verify(
                std::str::from_utf8(&altered).unwrap(),
                std::slice::from_ref(&key),
                &policy(),
                1000
            )
            .is_err()
        );
        assert_eq!(
            verify(&token, &[key.clone(), key.clone()], &policy(), 1000).unwrap_err(),
            AuthError::UnknownKey
        );
        let mut wrong_usage = key.clone();
        wrong_usage.usage = Some("enc".into());
        assert!(verify(&token, &[wrong_usage], &policy(), 1000).is_err());
        let mut wrong_alg = key;
        wrong_alg.alg = Some("HS256".into());
        assert!(verify(&token, &[wrong_alg], &policy(), 1000).is_err());
    }

    #[test]
    fn es256_fixed_width_signature_verifies() {
        let rng = SystemRandom::new();
        let document = signature::EcdsaKeyPair::generate_pkcs8(
            &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &rng,
        )
        .unwrap();
        let pair = signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            document.as_ref(),
            &rng,
        )
        .unwrap();
        let point = pair.public_key().as_ref();
        let key: Jwk=serde_json::from_value(json!({"kty":"EC","kid":"ec","alg":"ES256","crv":"P-256","x":encode_url(&point[1..33]),"y":encode_url(&point[33..])})).unwrap();
        let token = raw_token("ES256", "ec", &claims(), |input| {
            pair.sign(&rng, input).unwrap().as_ref().to_vec()
        });
        assert!(verify(&token, &[key], &policy(), 1000).is_ok());
    }

    #[test]
    fn rsa_pkcs1_signature_verifies() {
        let pair = signature::RsaKeyPair::from_der(include_bytes!(
            "../../tests/fixtures/auth/rsa-private.der"
        ))
        .unwrap();
        let key: Jwk =
            serde_json::from_slice(include_bytes!("../../tests/fixtures/auth/rsa-public.json"))
                .unwrap();
        let token = raw_token("RS256", "test-rsa", &claims(), |input| {
            let mut signed = vec![0; pair.public().modulus_len()];
            pair.sign(
                &signature::RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                input,
                &mut signed,
            )
            .unwrap();
            signed
        });
        assert!(verify(&token, &[key], &policy(), 1000).is_ok());
    }

    #[test]
    fn scope_substitute_is_explicit_and_only_for_empty_audience() {
        let signer = Ed25519Signer::from_seed_hex("ed", &"11".repeat(32)).unwrap();
        let key = signer.public_jwk();
        let mut local = policy();
        local.audience_policy = AudiencePolicy::ScopeSubstitute("fleet-recall".into());
        let mut value = claims();
        value["aud"] = json!([]);
        value["scp"] = json!(["openid", "fleet-recall"]);
        let token = signer.sign(&value).unwrap();
        assert!(verify(&token, std::slice::from_ref(&key), &policy(), 1000).is_err());
        assert!(verify(&token, std::slice::from_ref(&key), &local, 1000).is_ok());
        value["aud"] = json!("https://another-resource");
        assert!(
            verify(
                &signer.sign(&value).unwrap(),
                std::slice::from_ref(&key),
                &local,
                1000
            )
            .is_err()
        );
        value["aud"] = json!([]);
        value["scp"] = json!(["fleet-recall-admin"]);
        assert!(verify(&signer.sign(&value).unwrap(), &[key], &local, 1000).is_err());
    }

    #[test]
    fn malformed_duplicate_and_unsupported_headers_fail_closed() {
        let good_payload = encode_url(&serde_json::to_vec(&claims()).unwrap());
        for header in [
            r#"{"alg":"none"}"#,
            r#"{"alg":"HS256"}"#,
            r#"{"alg":"EdDSA","alg":"RS256"}"#,
            r#"{"alg":"EdDSA","crit":["unknown"]}"#,
            r#"{"alg":"EdDSA","b64":false}"#,
        ] {
            let token = format!("{}.{good_payload}.AA", encode_url(header.as_bytes()));
            assert!(unverified_issuer(&token).is_err());
        }
        for json in [r#"{"a":1,"a":2}"#, r#"{"a":{"b":1,"b":2}}"#] {
            assert!(strict_json::<Value>(json.as_bytes()).is_err());
        }
        assert!(unverified_issuer(&"x".repeat(MAX_TOKEN_BYTES + 1)).is_err());
    }
}
