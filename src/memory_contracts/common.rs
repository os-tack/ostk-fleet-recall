//! Shared scalar contracts used by registry, identity, and evidence artifacts.

use std::{fmt, str::FromStr};

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use unicode_normalization::UnicodeNormalization;

use super::{ContractError, ContractResult, canonical::PROFILE_ID, digest::Sha256Digest};

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
    fn timestamps_have_one_wire_form() {
        assert!(CanonicalTimestamp::parse("2026-08-14T12:34:56.000000000Z").is_ok());
        for invalid in [
            "2026-08-14T12:34:56Z",
            "2026-08-14T12:34:56.000Z",
            "2026-08-14T12:34:56.000000000+00:00",
            "2026-08-14t12:34:56.000000000z",
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
