//! The six shared secret matchers every redaction in this crate runs
//! (EVID-05, PRED-03): a PEM private-key block, an AWS access key id, a bearer
//! token, a key/token/secret assignment, a password assignment, and a URL
//! authority carrying a credential.
//!
//! The replacement discipline (withhold an unredactable class whole; replace
//! every other range; re-scan and withhold on any residual) lives in
//! [`super::redact`], where these shapes and the provider shapes of
//! [`super::provider_shapes`] are scanned together. This module only knows how
//! to find its six shapes.
//!
//! # Why hand-written matchers
//!
//! The crate takes no regex dependency, and a regex engine would make the
//! matcher set data rather than reviewable code. Each detector below is a small
//! explicit scan with a stated shape, and each has a positive and a negative
//! unit test.

use serde::Serialize;

/// The exact text every redacted range is replaced with.
///
/// Deliberately carries no class name: a placeholder that spelled out
/// `api_key`/`password` would risk re-triggering the detectors it stands in for,
/// and the class belongs in the finding metadata, not in the stored body.
pub const REDACTION_PLACEHOLDER: &str = "[REDACTED]";

/// Minimum length of a secret-shaped value before an assignment counts.
const MIN_ASSIGNED_SECRET_LEN: usize = 12;
/// Minimum length of a bearer-style token before it counts.
const MIN_BEARER_TOKEN_LEN: usize = 16;
/// Minimum length of a password value before it counts.
const MIN_PASSWORD_LEN: usize = 6;
/// Length of the alphanumeric tail of an AWS access key ID.
const AWS_KEY_TAIL_LEN: usize = 16;

/// Closed set of secret shapes no redacting caller persists.
///
/// Closed on purpose: an unclassifiable shape is not a new enum arm invented at
/// runtime, it is simply not detected, and the residual re-scan is what keeps a
/// partially-neutralized detection from being staged anyway.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretClassV1 {
    /// A PEM private-key block.
    PrivateKeyBlock,
    /// An AWS access key ID (`AKIA` + 16 uppercase alphanumerics).
    AwsAccessKeyId,
    /// An `Authorization:`/`Bearer` header value.
    BearerToken,
    /// A `…key`/`…token`/`…secret` assignment with a long value.
    ApiKeyAssignment,
    /// A password assignment.
    PasswordAssignment,
    /// Credentials embedded in a URL authority (`scheme://user:pass@host`).
    UrlEmbeddedCredential,
}

impl SecretClassV1 {
    /// Whether a text carrying this class can be salvaged by replacing the
    /// matched range, or must be withheld whole.
    ///
    /// [`Self::PrivateKeyBlock`] is the one unredactable class. A PEM block's
    /// extent is only as reliable as its footer, and a truncated or
    /// re-wrapped block has no dependable end marker — so a "redaction" of it
    /// is a guess about where the key material stops. A text that contains one
    /// is key material rather than prose that mentions a key, and EVID-05's
    /// fail-closed disposition says the answer to an ambiguous secret is to
    /// withhold, not to publish a body that might still carry half a key.
    #[must_use]
    pub const fn is_redactable(self) -> bool {
        !matches!(self, Self::PrivateKeyBlock)
    }

    /// Stable label used in errors and metrics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PrivateKeyBlock => "private_key_block",
            Self::AwsAccessKeyId => "aws_access_key_id",
            Self::BearerToken => "bearer_token",
            Self::ApiKeyAssignment => "api_key_assignment",
            Self::PasswordAssignment => "password_assignment",
            Self::UrlEmbeddedCredential => "url_embedded_credential",
        }
    }
}

/// One detected secret-shaped byte range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecretFindingV1 {
    /// Which shape matched.
    pub class: SecretClassV1,
    /// Inclusive start byte offset into the scanned text.
    pub byte_start: usize,
    /// Exclusive end byte offset into the scanned text.
    pub byte_end: usize,
}

const fn is_secret_value_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'+' | b'/' | b'=' | b'~')
}

fn ascii_lower(bytes: &[u8]) -> Vec<u8> {
    bytes.to_ascii_lowercase()
}

/// `-----BEGIN … PRIVATE KEY-----` through the matching `-----END …-----`, or to
/// the end of the text when the block is truncated.
fn scan_private_key_blocks(bytes: &[u8], findings: &mut Vec<SecretFindingV1>) {
    const BEGIN: &[u8] = b"-----BEGIN ";
    const KEY: &[u8] = b"PRIVATE KEY-----";
    const END: &[u8] = b"-----END ";
    let mut index = 0_usize;
    while index + BEGIN.len() <= bytes.len() {
        if !bytes[index..].starts_with(BEGIN) {
            index += 1;
            continue;
        }
        // The header must actually name a private key.
        let header_end = bytes[index..]
            .windows(KEY.len())
            .position(|window| window == KEY)
            .map(|offset| index + offset + KEY.len());
        let Some(header_end) = header_end.filter(|end| end - index <= 64) else {
            index += BEGIN.len();
            continue;
        };
        let end = bytes[header_end..]
            .windows(END.len())
            .position(|window| window == END)
            .map_or(bytes.len(), |offset| {
                let footer = header_end + offset;
                bytes[footer..]
                    .iter()
                    .position(|byte| *byte == b'\n')
                    .map_or(bytes.len(), |newline| footer + newline)
            });
        findings.push(SecretFindingV1 {
            class: SecretClassV1::PrivateKeyBlock,
            byte_start: index,
            byte_end: end,
        });
        index = end;
    }
}

/// `AKIA` followed by exactly 16 uppercase alphanumerics.
fn scan_aws_access_key_ids(bytes: &[u8], findings: &mut Vec<SecretFindingV1>) {
    const PREFIX: &[u8] = b"AKIA";
    let total = PREFIX.len() + AWS_KEY_TAIL_LEN;
    let mut index = 0_usize;
    while index + total <= bytes.len() {
        if bytes[index..].starts_with(PREFIX)
            && bytes[index + PREFIX.len()..index + total]
                .iter()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
            && bytes
                .get(index + total)
                .is_none_or(|byte| !byte.is_ascii_alphanumeric())
        {
            findings.push(SecretFindingV1 {
                class: SecretClassV1::AwsAccessKeyId,
                byte_start: index,
                byte_end: index + total,
            });
            index += total;
            continue;
        }
        index += 1;
    }
}

/// `bearer <token>` (case-insensitive), token at least [`MIN_BEARER_TOKEN_LEN`].
fn scan_bearer_tokens(bytes: &[u8], lower: &[u8], findings: &mut Vec<SecretFindingV1>) {
    const MARK: &[u8] = b"bearer ";
    let mut index = 0_usize;
    while index + MARK.len() < lower.len() {
        if !lower[index..].starts_with(MARK) {
            index += 1;
            continue;
        }
        let mut cursor = index + MARK.len();
        while bytes.get(cursor).is_some_and(|byte| *byte == b' ') {
            cursor += 1;
        }
        let start = cursor;
        while bytes
            .get(cursor)
            .is_some_and(|byte| is_secret_value_byte(*byte))
        {
            cursor += 1;
        }
        if cursor - start >= MIN_BEARER_TOKEN_LEN {
            findings.push(SecretFindingV1 {
                class: SecretClassV1::BearerToken,
                byte_start: start,
                byte_end: cursor,
            });
            index = cursor;
            continue;
        }
        index += MARK.len();
    }
}

/// An assignment whose key ends in a secret-ish word and whose value is long
/// enough to be a real credential. Handles `k=v`, `k: v`, and `"k": "v"`.
fn scan_assignments(
    bytes: &[u8],
    lower: &[u8],
    keys: &[&[u8]],
    class: SecretClassV1,
    min_value: usize,
    findings: &mut Vec<SecretFindingV1>,
) {
    for key in keys {
        let mut index = 0_usize;
        while index + key.len() <= lower.len() {
            let Some(offset) = lower[index..]
                .windows(key.len())
                .position(|window| window == *key)
            else {
                break;
            };
            let key_start = index + offset;
            let mut cursor = key_start + key.len();
            // Optional closing quote, then whitespace, then a separator.
            while bytes
                .get(cursor)
                .is_some_and(|byte| matches!(byte, b'"' | b'\'' | b' '))
            {
                cursor += 1;
            }
            if !bytes
                .get(cursor)
                .is_some_and(|byte| matches!(byte, b'=' | b':'))
            {
                index = key_start + key.len();
                continue;
            }
            cursor += 1;
            while bytes
                .get(cursor)
                .is_some_and(|byte| matches!(byte, b' ' | b'"' | b'\''))
            {
                cursor += 1;
            }
            let value_start = cursor;
            while bytes
                .get(cursor)
                .is_some_and(|byte| is_secret_value_byte(*byte))
            {
                cursor += 1;
            }
            if cursor - value_start >= min_value {
                findings.push(SecretFindingV1 {
                    class,
                    byte_start: value_start,
                    byte_end: cursor,
                });
                index = cursor;
                continue;
            }
            index = key_start + key.len();
        }
    }
}

/// `scheme://user:password@host` — the credential runs from after `//` to `@`.
fn scan_url_credentials(bytes: &[u8], findings: &mut Vec<SecretFindingV1>) {
    const MARK: &[u8] = b"://";
    let mut index = 0_usize;
    while index + MARK.len() < bytes.len() {
        if !bytes[index..].starts_with(MARK) {
            index += 1;
            continue;
        }
        let start = index + MARK.len();
        let mut cursor = start;
        let mut colon = None;
        while let Some(byte) = bytes.get(cursor) {
            match byte {
                b'@' => break,
                b'/' | b' ' | b'\n' | b'\t' => {
                    cursor = start;
                    break;
                }
                b':' if colon.is_none() => {
                    colon = Some(cursor);
                    cursor += 1;
                }
                _ => cursor += 1,
            }
        }
        if cursor > start
            && bytes.get(cursor) == Some(&b'@')
            && colon.is_some_and(|position| cursor - position > 1)
        {
            findings.push(SecretFindingV1 {
                class: SecretClassV1::UrlEmbeddedCredential,
                byte_start: start,
                byte_end: cursor,
            });
            index = cursor;
            continue;
        }
        index = start;
    }
}

/// Every range of the six shared shapes in `text`, as each matcher reported
/// it: unsorted and possibly overlapping. [`super::scan_secrets`] merges them
/// with the provider findings so one replacement neutralizes every class that
/// matched there.
pub fn scan_shared_secrets(text: &str) -> Vec<SecretFindingV1> {
    let bytes = text.as_bytes();
    let lower = ascii_lower(bytes);
    let mut findings = Vec::new();
    scan_private_key_blocks(bytes, &mut findings);
    scan_aws_access_key_ids(bytes, &mut findings);
    scan_bearer_tokens(bytes, &lower, &mut findings);
    scan_assignments(
        bytes,
        &lower,
        &[b"api_key", b"apikey", b"api-key", b"secret", b"token"],
        SecretClassV1::ApiKeyAssignment,
        MIN_ASSIGNED_SECRET_LEN,
        &mut findings,
    );
    scan_assignments(
        bytes,
        &lower,
        &[b"password", b"passwd", b"pwd"],
        SecretClassV1::PasswordAssignment,
        MIN_PASSWORD_LEN,
        &mut findings,
    );
    scan_url_credentials(bytes, &mut findings);
    findings
}

#[cfg(test)]
#[path = "credential_shapes_tests.rs"]
mod tests;
