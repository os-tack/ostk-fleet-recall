//! Redaction and secret classification, applied BEFORE anything durable.
//!
//! This module is the security boundary of the transcript connector. Every turn
//! passes through [`redact`] before it is canonicalized, so secret-shaped
//! content can never reach an outbox row, an accepted event, the governed
//! content store, or any downstream projection: the connector has no code path
//! that stages a turn's raw text.
//!
//! # Fail closed, twice
//!
//! 1. [`scan_secrets`] finds every match of the closed [`SecretClassV1`] set. If
//!    any match is an UNREDACTABLE class ([`SecretClassV1::is_redactable`]), the
//!    turn is withheld whole and no body is built for it at all. Otherwise
//!    [`redact`] replaces those byte ranges with [`REDACTION_PLACEHOLDER`].
//! 2. The redacted text is then RE-SCANNED. A residual finding means the
//!    redactor did not fully neutralize what it detected, and the turn is
//!    withheld entirely ([`RedactionDispositionV1::Withhold`]) rather than
//!    staged with a partial redaction. There is no path that stages a turn the
//!    re-scan still flags.
//!
//! The disposition is not a connector-side choice: it is derived from the
//! ACTIVATED redaction policy body through
//! [`RedactionGuaranteeV1::from_active_package`], which refuses to run at all
//! unless the active package's policy declares `redact_before_durable_outbox`
//! and forbids secrets in recall. A package that does not make that promise
//! produces no redaction guarantee, and with no guarantee the collector cannot
//! build a batch (EVID-05, PRED-03).
//!
//! # Why hand-written matchers
//!
//! The crate takes no regex dependency, and a regex engine would make the
//! matcher set data rather than reviewable code. Each detector below is a small
//! explicit scan with a stated shape, and each has a positive and a negative
//! unit test.

use serde::Serialize;

use crate::evidence_ledger::ActiveStage4Package;
use crate::memory_contracts::canonical::{decode_strict, encode_canonical};
use crate::memory_contracts::common::ContractId;
use crate::memory_contracts::registry::{RegistryEntryKind, RegistryEntryV1};

use super::error::{TranscriptConnectorError, TranscriptConnectorResult};

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

/// Closed set of secret shapes this connector refuses to persist.
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
    /// Whether a turn carrying this class can be salvaged by replacing the
    /// matched range, or must be withheld whole.
    ///
    /// [`Self::PrivateKeyBlock`] is the one unredactable class. A PEM block's
    /// extent is only as reliable as its footer, and a truncated or
    /// re-wrapped block has no dependable end marker — so a "redaction" of it
    /// is a guess about where the key material stops. A turn that contains one
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

/// What the redactor decided about one turn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedactionDispositionV1 {
    /// The turn is clean or was fully redacted; `text` is safe to stage.
    Stage {
        /// The redacted body. Equal to the input when nothing matched.
        text: String,
    },
    /// The turn must not be staged at all: the post-redaction re-scan still
    /// found a secret shape, so no partially-redacted body is durable.
    Withhold {
        /// The residual class that forced the refusal.
        class: SecretClassV1,
    },
}

/// The outcome of running the redactor over one turn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionOutcomeV1 {
    /// What to do with the turn.
    pub disposition: RedactionDispositionV1,
    /// Classes detected in the ORIGINAL text, sorted and deduplicated. Metadata
    /// only: it never carries matched bytes.
    pub classes: Vec<SecretClassV1>,
    /// Number of ranges replaced.
    pub redacted_ranges: u32,
}

impl RedactionOutcomeV1 {
    /// The body to stage, or `None` when the turn is withheld.
    #[must_use]
    pub fn staged_text(&self) -> Option<&str> {
        match &self.disposition {
            RedactionDispositionV1::Stage { text } => Some(text),
            RedactionDispositionV1::Withhold { .. } => None,
        }
    }
}

/// Proof that the ACTIVE package's redaction policy promises redaction before
/// the durable outbox and forbids secrets in recall.
///
/// The collector cannot build a batch without one, so "redact before outbox" is
/// enforced by construction rather than by remembering to call the redactor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionGuaranteeV1 {
    policy_id: ContractId,
    policy_version: u32,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivatedRedactionPolicyBodyV1 {
    schema_version: u32,
    policy_id: ContractId,
    version: u32,
    failure_outcome: ActivatedFailureOutcomeV1,
    redact_before_durable_outbox: bool,
    secrets_allowed_in_recall: bool,
}

/// Single-variant on purpose: a policy that says anything but `withhold` fails
/// to deserialize, so "fail open" is not expressible in the wire form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum ActivatedFailureOutcomeV1 {
    Withhold,
}

impl RedactionGuaranteeV1 {
    /// Read the activated redaction policy out of the active package and prove
    /// it makes the guarantee this connector depends on (EVID-05).
    pub fn from_active_package(active: &ActiveStage4Package) -> TranscriptConnectorResult<Self> {
        let entries = active.registry_entries();
        let mut matching = entries
            .iter()
            .filter(|entry| entry.kind == RegistryEntryKind::RedactionPolicy);
        let entry: &RegistryEntryV1 = matching
            .next()
            .ok_or(TranscriptConnectorError::RedactionPolicyNotGuaranteed)?;
        if matching.next().is_some() {
            return Err(TranscriptConnectorError::RedactionPolicyNotGuaranteed);
        }
        let body: ActivatedRedactionPolicyBodyV1 = decode_strict(&encode_canonical(&entry.body)?)?;
        if body.schema_version != 1
            || body.policy_id != entry.entry_id
            || body.version != entry.version
            || body.failure_outcome != ActivatedFailureOutcomeV1::Withhold
            || !body.redact_before_durable_outbox
            || body.secrets_allowed_in_recall
        {
            return Err(TranscriptConnectorError::RedactionPolicyNotGuaranteed);
        }
        Ok(Self {
            policy_id: body.policy_id,
            policy_version: body.version,
        })
    }

    /// The activated policy this guarantee was read from.
    #[must_use]
    pub const fn policy_id(&self) -> &ContractId {
        &self.policy_id
    }

    /// The activated policy's version.
    #[must_use]
    pub const fn policy_version(&self) -> u32 {
        self.policy_version
    }

    /// Redact one turn under this guarantee.
    ///
    /// Taking `&self` is the point: there is no free function the collector can
    /// call without first having proven the active package makes the promise.
    #[must_use]
    pub fn apply(&self, text: &str) -> RedactionOutcomeV1 {
        redact(text)
    }
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

/// Every secret-shaped range in `text`, sorted by start and non-overlapping.
///
/// Overlapping detections are merged into the widest range so a single
/// replacement always neutralizes every class that matched there.
#[must_use]
pub fn scan_secrets(text: &str) -> Vec<SecretFindingV1> {
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
    merge(findings)
}

fn merge(mut findings: Vec<SecretFindingV1>) -> Vec<SecretFindingV1> {
    findings.sort_by_key(|finding| (finding.byte_start, std::cmp::Reverse(finding.byte_end)));
    let mut merged: Vec<SecretFindingV1> = Vec::with_capacity(findings.len());
    for finding in findings {
        match merged.last_mut() {
            Some(previous) if finding.byte_start < previous.byte_end => {
                previous.byte_end = previous.byte_end.max(finding.byte_end);
            }
            _ => merged.push(finding),
        }
    }
    merged
}

/// Redact every detected range, then prove the result is clean.
#[must_use]
pub fn redact(text: &str) -> RedactionOutcomeV1 {
    let findings = scan_secrets(text);
    let mut classes: Vec<SecretClassV1> = findings.iter().map(|finding| finding.class).collect();
    classes.sort_unstable();
    classes.dedup();
    let redacted_ranges = u32::try_from(findings.len()).unwrap_or(u32::MAX);

    // The first fence: an unredactable class withholds the whole turn before a
    // partially-redacted body is even built, so there is no intermediate value
    // a later stage could accidentally stage (EVID-05).
    if let Some(unredactable) = findings
        .iter()
        .find(|finding| !finding.class.is_redactable())
    {
        return RedactionOutcomeV1 {
            disposition: RedactionDispositionV1::Withhold {
                class: unredactable.class,
            },
            classes,
            redacted_ranges,
        };
    }

    let mut redacted = String::with_capacity(text.len());
    let mut cursor = 0_usize;
    for finding in &findings {
        // Byte offsets come from this same &str and every matcher only ever
        // stops on ASCII bytes, so the ranges are always char boundaries;
        // get() rather than indexing keeps that a refusal, not a panic.
        let Some(prefix) = text.get(cursor..finding.byte_start) else {
            return RedactionOutcomeV1 {
                disposition: RedactionDispositionV1::Withhold {
                    class: finding.class,
                },
                classes,
                redacted_ranges,
            };
        };
        redacted.push_str(prefix);
        redacted.push_str(REDACTION_PLACEHOLDER);
        cursor = finding.byte_end;
    }
    let Some(tail) = text.get(cursor..) else {
        return RedactionOutcomeV1 {
            disposition: RedactionDispositionV1::Withhold {
                class: findings
                    .last()
                    .map_or(SecretClassV1::ApiKeyAssignment, |finding| finding.class),
            },
            classes,
            redacted_ranges,
        };
    };
    redacted.push_str(tail);

    // The second fence: if anything still matches after redaction, refuse the
    // turn outright rather than stage a partial redaction (EVID-05, PRED-03).
    if let Some(residual) = scan_secrets(&redacted).first() {
        return RedactionOutcomeV1 {
            disposition: RedactionDispositionV1::Withhold {
                class: residual.class,
            },
            classes,
            redacted_ranges,
        };
    }
    RedactionOutcomeV1 {
        disposition: RedactionDispositionV1::Stage { text: redacted },
        classes,
        redacted_ranges,
    }
}

#[cfg(test)]
#[path = "redactor_tests.rs"]
mod tests;
