//! `ostk-canonical-json-v1`: a strict, bounded RFC 8785/JCS subset.
//!
//! Inputs are decoded without first constructing `serde_json::Value`, so
//! duplicate keys cannot be collapsed. The profile admits only NFC strings and
//! safe-range integers; floats, exponent forms, negative zero, private-use
//! scalars, noncharacters, controls, BOMs, and trailing bytes are rejected.

use std::{cmp::Ordering, collections::BTreeMap, fmt, marker::PhantomData};

use serde::{
    Deserialize, Serialize,
    de::{DeserializeOwned, DeserializeSeed, MapAccess, SeqAccess, Visitor},
};
use unicode_normalization::UnicodeNormalization;

use super::{ContractError, ContractResult};

/// Stable identifier for the only canonical JSON profile supported by v1.
pub const PROFILE_ID: &str = "ostk-canonical-json-v1";
/// Largest accepted encoded JSON document.
pub const MAX_INPUT_BYTES: usize = 1_048_576;
/// Largest emitted canonical JSON document.
pub const MAX_OUTPUT_BYTES: usize = 1_048_576;
/// Maximum recursive container depth.
pub const MAX_DEPTH: usize = 64;
/// Maximum number of values and object members in one document.
pub const MAX_NODES: usize = 100_000;
/// Maximum members in one array or object.
pub const MAX_COLLECTION_ELEMENTS: usize = 4_096;
/// Maximum UTF-8 bytes in one decoded string.
pub const MAX_STRING_BYTES: usize = 65_536;
/// Largest integer admitted directly as a JSON number (I-JSON/JCS safe range).
pub const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

/// A JSON value admitted by the strict canonical profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalValue {
    Null,
    Bool(bool),
    Integer(i64),
    String(String),
    Array(Vec<Self>),
    Object(BTreeMap<String, Self>),
}

impl CanonicalValue {
    /// Return the value as an object when its schema requires an object root.
    pub const fn as_object(&self) -> Option<&BTreeMap<String, Self>> {
        match self {
            Self::Object(value) => Some(value),
            _ => None,
        }
    }
}

/// Parsed value together with its deterministic canonical bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalDocument {
    value: CanonicalValue,
    bytes: Vec<u8>,
}

impl CanonicalDocument {
    pub const fn value(&self) -> &CanonicalValue {
        &self.value
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_parts(self) -> (CanonicalValue, Vec<u8>) {
        (self.value, self.bytes)
    }
}

#[derive(Debug, Default)]
struct ParseState {
    nodes: usize,
}

impl ParseState {
    const fn add_node(&mut self) -> ContractResult<()> {
        self.nodes = self.nodes.saturating_add(1);
        if self.nodes > MAX_NODES {
            return Err(ContractError::NodeLimit { limit: MAX_NODES });
        }
        Ok(())
    }
}

struct StrictSeed<'a> {
    state: &'a mut ParseState,
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for StrictSeed<'_> {
    type Value = CanonicalValue;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        self.state.add_node().map_err(serde::de::Error::custom)?;
        deserializer.deserialize_any(StrictVisitor {
            state: self.state,
            depth: self.depth,
        })
    }
}

struct StrictVisitor<'a> {
    state: &'a mut ParseState,
    depth: usize,
}

impl<'de> Visitor<'de> for StrictVisitor<'_> {
    type Value = CanonicalValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a value admitted by ostk-canonical-json-v1")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(CanonicalValue::Null)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(CanonicalValue::Null)
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(CanonicalValue::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if !(-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&value) {
            return Err(E::custom(ContractError::IntegerOutOfRange));
        }
        Ok(CanonicalValue::Integer(value))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let value = i64::try_from(value)
            .ok()
            .filter(|value| *value <= MAX_SAFE_INTEGER)
            .ok_or_else(|| E::custom(ContractError::IntegerOutOfRange))?;
        Ok(CanonicalValue::Integer(value))
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Err(E::custom(ContractError::FloatingPointForbidden))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        validate_string(value).map_err(E::custom)?;
        Ok(CanonicalValue::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        validate_string(&value).map_err(E::custom)?;
        Ok(CanonicalValue::String(value))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let child_depth = checked_child_depth(self.depth).map_err(serde::de::Error::custom)?;
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(StrictSeed {
            state: self.state,
            depth: child_depth,
        })? {
            if values.len() >= MAX_COLLECTION_ELEMENTS {
                return Err(serde::de::Error::custom(ContractError::CollectionLimit {
                    limit: MAX_COLLECTION_ELEMENTS,
                }));
            }
            values.push(value);
        }
        Ok(CanonicalValue::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let child_depth = checked_child_depth(self.depth).map_err(serde::de::Error::custom)?;
        let mut values = BTreeMap::new();
        while let Some(key) = map.next_key::<String>()? {
            validate_string(&key).map_err(serde::de::Error::custom)?;
            if values.len() >= MAX_COLLECTION_ELEMENTS {
                return Err(serde::de::Error::custom(ContractError::CollectionLimit {
                    limit: MAX_COLLECTION_ELEMENTS,
                }));
            }
            if values.contains_key(&key) {
                return Err(serde::de::Error::custom(ContractError::DuplicateKey(key)));
            }
            let value = map.next_value_seed(StrictSeed {
                state: self.state,
                depth: child_depth,
            })?;
            values.insert(key, value);
        }
        Ok(CanonicalValue::Object(values))
    }
}

const fn checked_child_depth(depth: usize) -> ContractResult<usize> {
    let child = depth.saturating_add(1);
    if child > MAX_DEPTH {
        return Err(ContractError::DepthLimit { limit: MAX_DEPTH });
    }
    Ok(child)
}

/// Parse strict JSON and produce its canonical bytes.
pub fn parse_strict(input: &[u8]) -> ContractResult<CanonicalDocument> {
    if input.len() > MAX_INPUT_BYTES {
        return Err(ContractError::InputTooLarge {
            limit: MAX_INPUT_BYTES,
        });
    }
    if input.starts_with(&[0xef, 0xbb, 0xbf]) {
        return Err(ContractError::InvalidJson("UTF-8 BOM is forbidden".into()));
    }
    validate_number_lexemes(input)?;

    let mut state = ParseState::default();
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    let value = StrictSeed {
        state: &mut state,
        depth: 0,
    }
    .deserialize(&mut deserializer)
    .map_err(|error| ContractError::InvalidJson(error.to_string()))?;
    deserializer
        .end()
        .map_err(|error| ContractError::InvalidJson(error.to_string()))?;
    let bytes = canonical_bytes(&value)?;
    Ok(CanonicalDocument { value, bytes })
}

/// Require the input itself—not merely its decoded meaning—to be canonical.
pub fn require_canonical(input: &[u8]) -> ContractResult<CanonicalDocument> {
    let document = parse_strict(input)?;
    if document.bytes() != input {
        return Err(ContractError::NotCanonical);
    }
    Ok(document)
}

/// Decode a closed typed schema only after duplicate-safe strict parsing.
pub fn decode_strict<T>(input: &[u8]) -> ContractResult<T>
where
    T: DeserializeOwned,
{
    let document = parse_strict(input)?;
    serde_json::from_slice(document.bytes())
        .map_err(|error| ContractError::Schema(error.to_string()))
}

/// Serialize a typed value, then validate and emit it through the strict profile.
pub fn encode_canonical<T>(value: &T) -> ContractResult<Vec<u8>>
where
    T: Serialize,
{
    let encoded =
        serde_json::to_vec(value).map_err(|error| ContractError::Schema(error.to_string()))?;
    Ok(parse_strict(&encoded)?.bytes)
}

/// Emit deterministic RFC 8785/JCS bytes for an admitted value.
pub fn canonical_bytes(value: &CanonicalValue) -> ContractResult<Vec<u8>> {
    let mut output = Vec::new();
    write_value(value, &mut output)?;
    if output.len() > MAX_OUTPUT_BYTES {
        return Err(ContractError::OutputTooLarge {
            limit: MAX_OUTPUT_BYTES,
        });
    }
    Ok(output)
}

fn write_value(value: &CanonicalValue, output: &mut Vec<u8>) -> ContractResult<()> {
    match value {
        CanonicalValue::Null => output.extend_from_slice(b"null"),
        CanonicalValue::Bool(true) => output.extend_from_slice(b"true"),
        CanonicalValue::Bool(false) => output.extend_from_slice(b"false"),
        CanonicalValue::Integer(value) => output.extend_from_slice(value.to_string().as_bytes()),
        CanonicalValue::String(value) => write_string(value, output),
        CanonicalValue::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_value(value, output)?;
            }
            output.push(b']');
        }
        CanonicalValue::Object(values) => {
            output.push(b'{');
            let mut entries = values.iter().collect::<Vec<_>>();
            entries.sort_by(|(left, _), (right, _)| utf16_cmp(left, right));
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_string(key, output);
                output.push(b':');
                write_value(value, output)?;
            }
            output.push(b'}');
        }
    }
    if output.len() > MAX_OUTPUT_BYTES {
        return Err(ContractError::OutputTooLarge {
            limit: MAX_OUTPUT_BYTES,
        });
    }
    Ok(())
}

fn write_string(value: &str, output: &mut Vec<u8>) {
    output.push(b'"');
    for character in value.chars() {
        match character {
            '"' => output.extend_from_slice(br#"\""#),
            '\\' => output.extend_from_slice(br"\\"),
            '\u{0008}' => output.extend_from_slice(br"\b"),
            '\u{0009}' => output.extend_from_slice(br"\t"),
            '\u{000a}' => output.extend_from_slice(br"\n"),
            '\u{000c}' => output.extend_from_slice(br"\f"),
            '\u{000d}' => output.extend_from_slice(br"\r"),
            character if character <= '\u{001f}' => {
                let code = u32::from(character);
                output.extend_from_slice(format!("\\u{code:04x}").as_bytes());
            }
            character => {
                let mut encoded = [0_u8; 4];
                output.extend_from_slice(character.encode_utf8(&mut encoded).as_bytes());
            }
        }
    }
    output.push(b'"');
}

fn utf16_cmp(left: &str, right: &str) -> Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

fn validate_string(value: &str) -> ContractResult<()> {
    if value.len() > MAX_STRING_BYTES {
        return Err(ContractError::StringTooLong {
            limit: MAX_STRING_BYTES,
        });
    }
    if !value.nfc().eq(value.chars()) {
        return Err(ContractError::NonNfcString);
    }
    if value.chars().any(is_forbidden_scalar) {
        return Err(ContractError::ForbiddenUnicode);
    }
    Ok(())
}

fn is_forbidden_scalar(value: char) -> bool {
    let code = u32::from(value);
    value.is_control()
        || (0xfdd0..=0xfdef).contains(&code)
        || code & 0xffff >= 0xfffe
        || (0xe000..=0xf8ff).contains(&code)
        || (0xf0000..=0xffffd).contains(&code)
        || (0x0010_0000..=0x0010_fffd).contains(&code)
}

fn validate_number_lexemes(input: &[u8]) -> ContractResult<()> {
    let mut index = 0;
    let mut in_string = false;
    let mut escaped = false;
    while index < input.len() {
        let byte = input[index];
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            index += 1;
            continue;
        }
        if byte == b'"' {
            in_string = true;
            index += 1;
            continue;
        }
        if byte == b'-' || byte.is_ascii_digit() {
            let start = index;
            if byte == b'-' {
                index += 1;
                if input.get(index).is_none_or(|next| !next.is_ascii_digit()) {
                    return Err(ContractError::InvalidJson("invalid number".into()));
                }
            }
            let digit_start = index;
            while input.get(index).is_some_and(u8::is_ascii_digit) {
                index += 1;
            }
            let digits = &input[digit_start..index];
            if digits.len() > 1 && digits[0] == b'0' {
                return Err(ContractError::InvalidJson(
                    "leading zero is forbidden".into(),
                ));
            }
            if input
                .get(index)
                .is_some_and(|next| matches!(next, b'.' | b'e' | b'E'))
            {
                return Err(ContractError::FloatingPointForbidden);
            }
            let token = std::str::from_utf8(&input[start..index])
                .map_err(|error| ContractError::InvalidJson(error.to_string()))?;
            if token == "-0" {
                return Err(ContractError::NegativeZero);
            }
            let value = token
                .parse::<i64>()
                .map_err(|_| ContractError::IntegerOutOfRange)?;
            if !(-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&value) {
                return Err(ContractError::IntegerOutOfRange);
            }
            continue;
        }
        index += 1;
    }
    Ok(())
}

/// Decode a typed value while retaining its strict canonical preimage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalTyped<T> {
    value: T,
    bytes: Vec<u8>,
    marker: PhantomData<T>,
}

/// Extraction-friendly name for a typed value and its verified canonical bytes.
pub type CanonicalBytes<T> = CanonicalTyped<T>;

impl<T> CanonicalTyped<T>
where
    T: DeserializeOwned,
{
    pub fn decode(input: &[u8]) -> ContractResult<Self> {
        let document = parse_strict(input)?;
        let value = serde_json::from_slice(document.bytes())
            .map_err(|error| ContractError::Schema(error.to_string()))?;
        Ok(Self {
            value,
            bytes: document.bytes,
            marker: PhantomData,
        })
    }

    pub const fn value(&self) -> &T {
        &self.value
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_value(self) -> T {
        self.value
    }
}

impl Serialize for CanonicalValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Null => serializer.serialize_none(),
            Self::Bool(value) => serializer.serialize_bool(*value),
            Self::Integer(value) => serializer.serialize_i64(*value),
            Self::String(value) => serializer.serialize_str(value),
            Self::Array(values) => values.serialize(serializer),
            Self::Object(values) => values.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for CanonicalValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let mut state = ParseState::default();
        StrictSeed {
            state: &mut state,
            depth: 0,
        }
        .deserialize(deserializer)
    }
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;

    #[test]
    fn canonicalizes_without_collapsing_duplicate_keys() {
        let document = parse_strict(br#" { "b": 2, "a": [true, null] } "#).unwrap();
        assert_eq!(document.bytes(), br#"{"a":[true,null],"b":2}"#);

        assert!(matches!(
            parse_strict(br#"{"a":1,"\u0061":2}"#),
            Err(ContractError::InvalidJson(message)) if message.contains("duplicate decoded object key")
        ));
    }

    #[test]
    fn uses_utf16_key_order_from_jcs() {
        let document =
            parse_strict("{\"\\u20ac\":1,\"\\ud83d\\ude00\":2,\"\\uff21\":3}".as_bytes()).unwrap();
        assert_eq!(
            std::str::from_utf8(document.bytes()).unwrap(),
            "{\"€\":1,\"😀\":2,\"Ａ\":3}"
        );
    }

    #[test]
    fn rejects_ambiguous_numbers_and_unicode() {
        for invalid in ["-0", "1.0", "1e0", "9007199254740992"] {
            assert!(
                parse_strict(invalid.as_bytes()).is_err(),
                "accepted {invalid}"
            );
        }
        assert!(matches!(
            parse_strict("\"e\u{0301}\"".as_bytes()),
            Err(ContractError::InvalidJson(message)) if message.contains("not Unicode NFC")
        ));
        assert!(parse_strict("\"\u{fdd0}\"".as_bytes()).is_err());
        assert!(parse_strict("\"\u{e000}\"".as_bytes()).is_err());
    }

    #[test]
    fn rejects_bom_trailing_data_and_noncanonical_bytes() {
        assert!(parse_strict(b"\xef\xbb\xbf{}").is_err());
        assert!(parse_strict(b"{} {}").is_err());
        assert!(require_canonical(b"{ }").is_err());
        assert!(require_canonical(b"{}").is_ok());
    }

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    struct ClosedSchema {
        enabled: bool,
    }

    #[test]
    fn typed_decode_rejects_unknown_fields_after_strict_parse() {
        assert_eq!(
            decode_strict::<ClosedSchema>(br#"{"enabled":true}"#).unwrap(),
            ClosedSchema { enabled: true }
        );
        assert!(decode_strict::<ClosedSchema>(br#"{"enabled":true,"other":false}"#).is_err());
    }
}
