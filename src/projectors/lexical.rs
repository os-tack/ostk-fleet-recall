//! Pure derivation of the lexical projection of one content-addressed body
//! (W2-PROJ).
//!
//! No database access lives here. Given a body's content address and its exact
//! stored bytes, [`derive_lexical_projection`] verifies the bytes against the
//! address and normalizes them into the text the lexical tier indexes.
//!
//! # Invariants enforced here
//!
//! * **Identity before projection.** The bytes must reproduce the body's
//!   content address ([`body_digest`]) or the derivation fails closed with
//!   [`RecallProjectionError::BodyIntegrityMismatch`]. A projection is never
//!   derived from bytes the body plane did not commit to.
//! * **Determinism.** The normalizer is a pure function of `(bytes,
//!   LEXICAL_NORMALIZATION_VERSION)`. Replaying the same body tables rebuilds
//!   byte-identical lexical rows.
//! * **No silent skip.** A body that yields no indexable text is still
//!   projected, as an `Unindexable` row naming its reason, so the cursor can
//!   advance past it without losing the fact that it was consumed.
//! * **Text is not the body.** The normalized text is lossy, so it is
//!   addressed under its own digest domain
//!   ([`DigestDomain::LexicalProjectionTextV1`]) and never under the body's
//!   content address.

use unicode_normalization::UnicodeNormalization as _;

use crate::memory_contracts::digest::{DigestDomain, Sha256Digest, body_digest, framed_digest};

use super::error::{RecallProjectionError, RecallProjectionResult};

/// Version of the normalization pipeline in this module.
///
/// It is part of the lexical text's digest preimage: changing the pipeline
/// without changing this constant would let two different normalizers claim the
/// same identity.
pub const LEXICAL_NORMALIZATION_VERSION: u32 = 1;

/// Upper bound on the normalized text stored per body.
///
/// Migration 0019 caps a body at 1 MiB; the lexical tier keeps a smaller,
/// bounded slice so one pathological body cannot dominate the inverted index.
/// Truncation happens on a `char` boundary and is deterministic, so it does not
/// weaken replay stability.
pub const MAX_LEXICAL_TEXT_BYTES: usize = 262_144;

/// Closed set of reasons a body carries no indexable lexical text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LexicalUnindexableReasonV1 {
    /// The body bytes are not valid UTF-8, so no text can be decoded.
    NonUtf8,
    /// The body decoded, but normalization left no non-whitespace character.
    EmptyAfterNormalization,
}

impl LexicalUnindexableReasonV1 {
    /// Exact stored `unindexable_reason` value. Part of the schema contract.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NonUtf8 => "non_utf8",
            Self::EmptyAfterNormalization => "empty_after_normalization",
        }
    }

    /// Parse a stored `unindexable_reason` value. Unknown values fail closed.
    pub fn parse(value: &str) -> RecallProjectionResult<Self> {
        match value {
            "non_utf8" => Ok(Self::NonUtf8),
            "empty_after_normalization" => Ok(Self::EmptyAfterNormalization),
            other => Err(RecallProjectionError::ProjectionIntegrity(format!(
                "stored lexical row names an unknown unindexable reason: {other}"
            ))),
        }
    }
}

/// Whether a body's lexical projection carries searchable text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LexicalStateV1 {
    /// The row carries normalized, searchable text.
    Indexed,
    /// The row records that the body was consumed but yields no text.
    Unindexable(LexicalUnindexableReasonV1),
}

impl LexicalStateV1 {
    /// Exact stored `lexical_state` value. Part of the schema contract.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Indexed => "indexed",
            Self::Unindexable(_) => "unindexable",
        }
    }

    /// Exact stored `unindexable_reason` value (empty when indexed).
    #[must_use]
    pub const fn reason_str(self) -> &'static str {
        match self {
            Self::Indexed => "",
            Self::Unindexable(reason) => reason.as_str(),
        }
    }

    /// Rebuild the state from a stored `(lexical_state, unindexable_reason)`
    /// pair. Any combination the schema CHECK forbids fails closed.
    pub fn parse(state: &str, reason: &str) -> RecallProjectionResult<Self> {
        match (state, reason) {
            ("indexed", "") => Ok(Self::Indexed),
            ("unindexable", reason) => Ok(Self::Unindexable(LexicalUnindexableReasonV1::parse(
                reason,
            )?)),
            (state, reason) => Err(RecallProjectionError::ProjectionIntegrity(format!(
                "stored lexical row pairs state {state:?} with reason {reason:?}"
            ))),
        }
    }

    /// True when this row participates in lexical search.
    #[must_use]
    pub const fn is_indexed(self) -> bool {
        matches!(self, Self::Indexed)
    }
}

/// One body's derived lexical projection row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LexicalProjectionV1 {
    /// Content address of the body this row projects.
    pub body_content_id: Sha256Digest,
    /// Normalization pipeline version the text was produced under.
    pub normalization_version: u32,
    /// Indexed, or unindexable with a reason.
    pub state: LexicalStateV1,
    /// The exact normalized text stored in `lexical_text` (empty when
    /// unindexable).
    pub text: String,
    /// `framed_digest` over `(version, state, text)`.
    pub text_digest: Sha256Digest,
}

/// Digest of one normalized lexical text under its own domain.
///
/// The state label is framed alongside the text so the two unindexable reasons
/// — which both store empty text — cannot collapse to the same identity.
#[must_use]
pub fn lexical_text_digest(
    normalization_version: u32,
    state: LexicalStateV1,
    text: &str,
) -> Sha256Digest {
    framed_digest(
        DigestDomain::LexicalProjectionTextV1,
        &[
            &normalization_version.to_be_bytes(),
            state.as_str().as_bytes(),
            state.reason_str().as_bytes(),
            text.as_bytes(),
        ],
    )
}

/// Normalize body bytes into the exact text the lexical tier indexes.
///
/// The pipeline, in order:
///
/// 1. strict UTF-8 decode (a non-UTF-8 body is `Unindexable(NonUtf8)`);
/// 2. Unicode NFC composition, so two byte spellings of the same text produce
///    the same tokens;
/// 3. every Unicode whitespace scalar becomes a single ASCII space and every
///    other control scalar is dropped, which folds CR/LF, tabs, and stray
///    control bytes without depending on the platform's line endings;
/// 4. runs of spaces collapse and the ends are trimmed;
/// 5. the result is truncated to [`MAX_LEXICAL_TEXT_BYTES`] on a `char`
///    boundary and re-trimmed.
///
/// An empty result is `Unindexable(EmptyAfterNormalization)`.
fn normalize(body_bytes: &[u8]) -> (LexicalStateV1, String) {
    let Ok(decoded) = std::str::from_utf8(body_bytes) else {
        return (
            LexicalStateV1::Unindexable(LexicalUnindexableReasonV1::NonUtf8),
            String::new(),
        );
    };

    let mut normalized = String::with_capacity(decoded.len());
    let mut pending_space = false;
    for character in decoded.nfc() {
        if character.is_whitespace() {
            pending_space = !normalized.is_empty();
            continue;
        }
        if character.is_control() {
            continue;
        }
        if pending_space {
            normalized.push(' ');
            pending_space = false;
        }
        normalized.push(character);
    }

    if normalized.len() > MAX_LEXICAL_TEXT_BYTES {
        let mut boundary = MAX_LEXICAL_TEXT_BYTES;
        while boundary > 0 && !normalized.is_char_boundary(boundary) {
            boundary -= 1;
        }
        normalized.truncate(boundary);
        let trimmed = normalized.trim_end().len();
        normalized.truncate(trimmed);
    }

    if normalized.is_empty() {
        return (
            LexicalStateV1::Unindexable(LexicalUnindexableReasonV1::EmptyAfterNormalization),
            String::new(),
        );
    }
    (LexicalStateV1::Indexed, normalized)
}

/// Derive one body's lexical projection, failing closed if the supplied bytes
/// do not reproduce the body's content address.
pub fn derive_lexical_projection(
    body_content_id: Sha256Digest,
    body_bytes: &[u8],
) -> RecallProjectionResult<LexicalProjectionV1> {
    if body_digest(body_bytes) != body_content_id {
        return Err(RecallProjectionError::BodyIntegrityMismatch);
    }
    let (state, text) = normalize(body_bytes);
    let text_digest = lexical_text_digest(LEXICAL_NORMALIZATION_VERSION, state, &text);
    Ok(LexicalProjectionV1 {
        body_content_id,
        normalization_version: LEXICAL_NORMALIZATION_VERSION,
        state,
        text,
        text_digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn projection(bytes: &[u8]) -> LexicalProjectionV1 {
        derive_lexical_projection(body_digest(bytes), bytes).unwrap()
    }

    #[test]
    fn derivation_fails_closed_when_bytes_do_not_match_the_content_address() {
        // The one attack this seam must refuse: projecting text that is not the
        // body the content address names.
        let honest = b"alpha beta";
        let swapped = b"gamma delta";
        assert!(matches!(
            derive_lexical_projection(body_digest(honest), swapped),
            Err(RecallProjectionError::BodyIntegrityMismatch)
        ));
    }

    #[test]
    fn a_plain_body_is_indexed_with_collapsed_whitespace() {
        let derived = projection(b"  alpha\r\n\tbeta   gamma \n");
        assert_eq!(derived.state, LexicalStateV1::Indexed);
        assert_eq!(derived.text, "alpha beta gamma");
        assert_eq!(derived.normalization_version, LEXICAL_NORMALIZATION_VERSION);
    }

    #[test]
    fn normalization_is_deterministic() {
        let bytes = b"alpha\n\nbeta";
        assert_eq!(projection(bytes), projection(bytes));
    }

    #[test]
    fn nfc_composition_makes_two_spellings_of_one_word_identical() {
        // U+0065 U+0301 (decomposed) and U+00E9 (composed) must tokenize the
        // same, or the same source text would be unfindable depending on how it
        // was encoded upstream.
        let decomposed = "cafe\u{301}".as_bytes();
        let composed = "caf\u{e9}".as_bytes();
        assert_eq!(projection(decomposed).text, projection(composed).text);
        // The digests agree because the text does; the body addresses do not.
        assert_eq!(
            projection(decomposed).text_digest,
            projection(composed).text_digest
        );
        assert_ne!(body_digest(decomposed), body_digest(composed));
    }

    #[test]
    fn a_non_utf8_body_is_recorded_as_unindexable_rather_than_skipped() {
        // 0xFF is not a valid UTF-8 lead byte. The body must still produce a
        // row so the projector cursor can pass it without losing it.
        let derived = projection(&[0xff, 0xfe, 0xfd]);
        assert_eq!(
            derived.state,
            LexicalStateV1::Unindexable(LexicalUnindexableReasonV1::NonUtf8)
        );
        assert!(derived.text.is_empty());
    }

    #[test]
    fn a_whitespace_only_body_is_recorded_as_empty_after_normalization() {
        let derived = projection(b" \t\r\n \x0b\x0c");
        assert_eq!(
            derived.state,
            LexicalStateV1::Unindexable(LexicalUnindexableReasonV1::EmptyAfterNormalization)
        );
        assert!(derived.text.is_empty());
    }

    #[test]
    fn the_two_unindexable_reasons_do_not_share_a_digest() {
        // Both store empty text; framing the state label is what keeps them
        // distinguishable as identities.
        let non_utf8 = projection(&[0xff]);
        let empty = projection(b"   ");
        assert_ne!(non_utf8.text_digest, empty.text_digest);
    }

    #[test]
    fn text_is_truncated_on_a_char_boundary_and_stays_deterministic() {
        // A multi-byte character straddling the cap must not be cut in half.
        let mut source = "\u{e9}".repeat(MAX_LEXICAL_TEXT_BYTES);
        source.push_str(" tail");
        let derived = projection(source.as_bytes());
        assert_eq!(derived.state, LexicalStateV1::Indexed);
        assert!(derived.text.len() <= MAX_LEXICAL_TEXT_BYTES);
        assert!(std::str::from_utf8(derived.text.as_bytes()).is_ok());
        assert_eq!(derived, projection(source.as_bytes()));
    }

    #[test]
    fn stored_state_round_trips_and_rejects_impossible_pairs() {
        for state in [
            LexicalStateV1::Indexed,
            LexicalStateV1::Unindexable(LexicalUnindexableReasonV1::NonUtf8),
            LexicalStateV1::Unindexable(LexicalUnindexableReasonV1::EmptyAfterNormalization),
        ] {
            assert_eq!(
                LexicalStateV1::parse(state.as_str(), state.reason_str()).unwrap(),
                state
            );
        }
        // An indexed row that also names a reason, an unknown reason, and an
        // unknown state are all tamper signals.
        assert!(LexicalStateV1::parse("indexed", "non_utf8").is_err());
        assert!(LexicalStateV1::parse("unindexable", "").is_err());
        assert!(LexicalStateV1::parse("unindexable", "made_up").is_err());
        assert!(LexicalStateV1::parse("shredded", "").is_err());
    }

    #[test]
    fn the_lexical_digest_domain_is_not_the_body_digest_domain() {
        // A lexical projection must never be addressable as if it were the body
        // it was derived from.
        let text = "alpha";
        assert_ne!(
            lexical_text_digest(LEXICAL_NORMALIZATION_VERSION, LexicalStateV1::Indexed, text),
            body_digest(text.as_bytes())
        );
    }

    #[test]
    fn the_normalization_version_is_part_of_the_identity() {
        let text = "alpha";
        assert_ne!(
            lexical_text_digest(1, LexicalStateV1::Indexed, text),
            lexical_text_digest(2, LexicalStateV1::Indexed, text)
        );
    }
}
