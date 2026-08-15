//! Shared scalar contracts used by registry, identity, and evidence artifacts.

use std::{fmt, str::FromStr, sync::LazyLock};

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use unicode_normalization::UnicodeNormalization;

use super::{ContractError, ContractResult, canonical::PROFILE_ID, digest::Sha256Digest};

/// Digest of the only canonicalization profile implemented by this binary.
pub const FROZEN_PROFILE_DIGEST: Sha256Digest = Sha256Digest::from_bytes([
    0xcf, 0x22, 0x99, 0x1a, 0x86, 0xbf, 0xc5, 0x60, 0x55, 0x6c, 0x7d, 0x04, 0xef, 0xa4, 0xee, 0x6b,
    0x7b, 0x1e, 0xe0, 0xf4, 0x9c, 0x91, 0x9b, 0x25, 0x7e, 0xa7, 0xb4, 0xf3, 0x0f, 0x8e, 0x4a, 0x29,
]);
/// Digest of the authoritative positive/negative vectors for that profile.
pub const FROZEN_VECTOR_MANIFEST_DIGEST: Sha256Digest = Sha256Digest::from_bytes([
    0xf9, 0x84, 0xf6, 0x28, 0x66, 0xfc, 0x76, 0x9d, 0xf3, 0xa5, 0x61, 0x7a, 0x22, 0x47, 0xe3, 0xad,
    0xe6, 0x94, 0x82, 0x7c, 0x1d, 0xe6, 0x9e, 0x61, 0x5a, 0x7b, 0xda, 0x68, 0x85, 0x8b, 0x41, 0x74,
]);

/// Exact canonicalization profile reference implemented by this binary.
pub static FROZEN_PROFILE_REFERENCE_V1: LazyLock<ProfileReferenceV1> =
    LazyLock::new(|| ProfileReferenceV1 {
        profile_id: ContractId::new(PROFILE_ID)
            .expect("the compile-time canonical profile ID must remain valid"),
        profile_digest: FROZEN_PROFILE_DIGEST,
        vector_manifest_digest: FROZEN_VECTOR_MANIFEST_DIGEST,
    });

/// Stable ASCII identifier used for registry-controlled names.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContractId(String);

impl ContractId {
    pub fn new(value: impl Into<String>) -> ContractResult<Self> {
        let value = value.into();
        validate_contract_id(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ContractId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for ContractId {
    type Err = ContractError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl Serialize for ContractId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ContractId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(D::Error::custom)
    }
}

/// Profile ID and digests that every identity-bearing v1 artifact binds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileReferenceV1 {
    pub profile_id: ContractId,
    pub profile_digest: Sha256Digest,
    pub vector_manifest_digest: Sha256Digest,
}

impl ProfileReferenceV1 {
    pub fn validate(&self) -> ContractResult<()> {
        if self.profile_id.as_str() != PROFILE_ID {
            return Err(ContractError::ProfileMismatch);
        }
        Ok(())
    }

    /// Require the exact profile and vector suite compiled into this binary.
    ///
    /// A signed or pinned artifact authenticates its bytes; it cannot select a
    /// different canonicalizer implementation merely by naming new digests.
    pub fn require_frozen_runtime_profile(&self) -> ContractResult<()> {
        self.validate()?;
        if self.profile_digest != FROZEN_PROFILE_DIGEST
            || self.vector_manifest_digest != FROZEN_VECTOR_MANIFEST_DIGEST
        {
            return Err(ContractError::ProfileMismatch);
        }
        Ok(())
    }
}

/// Return the exact profile reference implemented by this binary.
pub fn frozen_profile_reference_v1() -> ProfileReferenceV1 {
    FROZEN_PROFILE_REFERENCE_V1.clone()
}

/// Immutable reference to one entry in an activated registry package.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryReferenceV1 {
    pub entry_id: ContractId,
    pub version: u32,
    pub entry_digest: Sha256Digest,
}

impl RegistryReferenceV1 {
    pub fn validate(&self) -> ContractResult<()> {
        if self.version == 0 {
            return Err(ContractError::Schema(
                "registry entry version must be positive".into(),
            ));
        }
        Ok(())
    }
}

/// Credential-bound opaque authority scope inserted by trusted ingress.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedProjectScopeV1 {
    pub tenant_namespace: ContractId,
    pub project_namespace: ContractId,
}

impl AuthenticatedProjectScopeV1 {
    /// Construct only from authenticated server context, never payload fields.
    pub const fn from_trusted_context(
        tenant_namespace: ContractId,
        project_namespace: ContractId,
    ) -> Self {
        Self {
            tenant_namespace,
            project_namespace,
        }
    }
}

/// Exact uppercase-UTC timestamp form: `YYYY-MM-DDTHH:MM:SS.nnnnnnnnnZ`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CanonicalTimestamp(String);

impl CanonicalTimestamp {
    pub fn parse(value: impl Into<String>) -> ContractResult<Self> {
        let value = value.into();
        let bytes = value.as_bytes();
        let separators_are_exact = bytes.len() == 30
            && bytes.get(4) == Some(&b'-')
            && bytes.get(7) == Some(&b'-')
            && bytes.get(10) == Some(&b'T')
            && bytes.get(13) == Some(&b':')
            && bytes.get(16) == Some(&b':')
            && bytes.get(19) == Some(&b'.')
            && bytes.get(29) == Some(&b'Z');
        let digits_are_exact = bytes.iter().enumerate().all(|(index, byte)| {
            matches!(index, 4 | 7 | 10 | 13 | 16 | 19 | 29) || byte.is_ascii_digit()
        });
        if !separators_are_exact
            || !digits_are_exact
            || &value[0..4] == "0000"
            || &value[17..19] == "60"
        {
            return Err(ContractError::Schema(
                "timestamp is not canonical UTC".into(),
            ));
        }
        let parsed = DateTime::parse_from_rfc3339(&value)
            .map_err(|_| ContractError::Schema("timestamp is not canonical UTC".into()))?
            .with_timezone(&Utc);
        let canonical = parsed.to_rfc3339_opts(SecondsFormat::Nanos, true);
        if value != canonical || value.len() != 30 {
            return Err(ContractError::Schema(
                "timestamp is not canonical UTC".into(),
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether the exact nanosecond form can round-trip through `CockroachDB`'s
    /// microsecond-precision `TIMESTAMPTZ` without changing identity bytes.
    pub fn is_microsecond_aligned(&self) -> bool {
        self.0.as_bytes()[26..29] == *b"000"
    }

    /// Convert one trusted database UTC timestamp into the exact contract wire
    /// form. Callers must still choose and read the database time only once.
    pub fn from_datetime(value: &DateTime<Utc>) -> ContractResult<Self> {
        Self::parse(value.to_rfc3339_opts(SecondsFormat::Nanos, true))
    }
}

impl fmt::Display for CanonicalTimestamp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for CanonicalTimestamp {
    type Err = ContractError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl Serialize for CanonicalTimestamp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for CanonicalTimestamp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(D::Error::custom)
    }
}

/// Canonical arbitrary-precision decimal string for values outside JSON's safe
/// integer range and for registry-controlled decimal quantities.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CanonicalDecimal(String);

impl CanonicalDecimal {
    pub fn parse(value: impl Into<String>) -> ContractResult<Self> {
        let value = value.into();
        if !is_canonical_decimal(&value) {
            return Err(ContractError::Schema(
                "invalid canonical decimal string".into(),
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Serialize for CanonicalDecimal {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for CanonicalDecimal {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(D::Error::custom)
    }
}

/// Lowercase hexadecimal bytes with no alternate wire encoding.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HexBytes(Vec<u8>);

impl HexBytes {
    pub fn new(bytes: Vec<u8>) -> ContractResult<Self> {
        if bytes.is_empty() || bytes.len() > 4_096 {
            return Err(ContractError::Schema(
                "hex byte string length is invalid".into(),
            ));
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

macro_rules! fixed_hex_type {
    ($name:ident, $length:expr) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; $length]);

        impl $name {
            pub const fn from_bytes(bytes: [u8; $length]) -> Self {
                Self(bytes)
            }

            pub const fn as_bytes(&self) -> &[u8; $length] {
                &self.0
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&hex::encode(self.0))
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                if value.len() != $length * 2
                    || !value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                {
                    return Err(D::Error::custom(
                        "fixed bytes require lowercase exact-length hex",
                    ));
                }
                let decoded = hex::decode(value).map_err(D::Error::custom)?;
                let bytes = decoded
                    .try_into()
                    .map_err(|_| D::Error::custom("fixed bytes have the wrong length"))?;
                Ok(Self(bytes))
            }
        }
    };
}

fixed_hex_type!(FixedHex32, 32);
fixed_hex_type!(FixedHex64, 64);

impl Serialize for HexBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for HexBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if value.len() % 2 != 0
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(D::Error::custom(
                "hex bytes must use lowercase even-length hex",
            ));
        }
        let bytes = hex::decode(value).map_err(D::Error::custom)?;
        Self::new(bytes).map_err(D::Error::custom)
    }
}

fn validate_contract_id(value: &str) -> ContractResult<()> {
    if value.is_empty() || value.len() > 128 || !value.nfc().eq(value.chars()) {
        return Err(ContractError::InvalidIdentifier(value.to_owned()));
    }
    let mut bytes = value.bytes();
    let valid_first = bytes.next().is_some_and(|byte| byte.is_ascii_lowercase());
    let valid_rest = bytes.all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-' | b'.')
    });
    if !valid_first || !valid_rest {
        return Err(ContractError::InvalidIdentifier(value.to_owned()));
    }
    Ok(())
}

fn is_canonical_decimal(value: &str) -> bool {
    if value.is_empty() || value.len() > 128 || value.starts_with('+') || value.contains(['e', 'E'])
    {
        return false;
    }
    let unsigned = value.strip_prefix('-').unwrap_or(value);
    if unsigned == "0" {
        return value == "0";
    }
    let (integer, fraction) = unsigned
        .split_once('.')
        .map_or((unsigned, None), |(left, right)| (left, Some(right)));
    if integer.is_empty()
        || (integer.starts_with('0') && integer != "0")
        || !integer.bytes().all(|byte| byte.is_ascii_digit())
    {
        return false;
    }
    fraction.is_none_or(|fraction| {
        !fraction.is_empty()
            && !fraction.ends_with('0')
            && fraction.bytes().all(|byte| byte.is_ascii_digit())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_are_closed_ascii_names() {
        assert!(ContractId::new("git.commit-v1").is_ok());
        for invalid in ["", "Upper", "two words", "é"] {
            assert!(ContractId::new(invalid).is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn runtime_profile_is_exactly_frozen() {
        let frozen = frozen_profile_reference_v1();
        assert_eq!(frozen.profile_id.as_str(), PROFILE_ID);
        assert_eq!(
            frozen.profile_digest.to_hex(),
            "cf22991a86bfc560556c7d04efa4ee6b7b1ee0f49c919b257ea7b4f30f8e4a29"
        );
        assert_eq!(
            frozen.vector_manifest_digest.to_hex(),
            "f984f62866fc769df3a5617a2247e3ade694827c1de69e615a7bda68858b4174"
        );
        frozen.require_frozen_runtime_profile().unwrap();

        let mut wrong_profile = frozen.clone();
        wrong_profile.profile_digest = Sha256Digest::ZERO;
        assert_eq!(
            wrong_profile.require_frozen_runtime_profile(),
            Err(ContractError::ProfileMismatch)
        );

        let mut wrong_vectors = frozen;
        wrong_vectors.vector_manifest_digest = Sha256Digest::ZERO;
        assert_eq!(
            wrong_vectors.require_frozen_runtime_profile(),
            Err(ContractError::ProfileMismatch)
        );
    }

    #[test]
    fn timestamps_have_one_wire_form() {
        let canonical = "2026-08-14T12:34:56.000000000Z";
        assert!(CanonicalTimestamp::parse(canonical).is_ok());
        let database_time = DateTime::parse_from_rfc3339("2026-08-14T12:34:56Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(
            CanonicalTimestamp::from_datetime(&database_time)
                .unwrap()
                .as_str(),
            canonical
        );
        assert!(
            CanonicalTimestamp::parse(canonical)
                .unwrap()
                .is_microsecond_aligned()
        );
        assert!(
            !CanonicalTimestamp::parse("2026-08-14T12:34:56.000000001Z")
                .unwrap()
                .is_microsecond_aligned()
        );
        for invalid in [
            "2026-08-14T12:34:56Z",
            "2026-08-14T12:34:56.000Z",
            "2026-08-14T12:34:56.000000000+00:00",
            "2026-08-14t12:34:56.000000000z",
            "2026-08-14T12:34:60.000000000Z",
            "0000-08-14T12:34:56.000000000Z",
        ] {
            assert!(
                CanonicalTimestamp::parse(invalid).is_err(),
                "accepted {invalid}"
            );
        }
    }

    #[test]
    fn decimals_have_one_wire_form() {
        for valid in ["0", "1", "-1", "12.34", "-0.5"] {
            assert!(CanonicalDecimal::parse(valid).is_ok(), "rejected {valid}");
        }
        for invalid in ["-0", "+1", "01", "1.0", ".5", "1e2"] {
            assert!(
                CanonicalDecimal::parse(invalid).is_err(),
                "accepted {invalid}"
            );
        }
    }
}
