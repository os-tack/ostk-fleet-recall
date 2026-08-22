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
//! * **No secret is retrievable.** The activated redaction policy says
//!   `secrets_allowed_in_recall: false`, and the lexical tier is the recall
//!   index, so every secret-shaped range is replaced before a row is written
//!   ([`redact_for_recall`]). The body keeps the provider's exact bytes; the
//!   searchable copy does not.
//!
//! # Why the pipeline knows about media types
//!
//! A body is a connector's canonical JSON rendering of one provider fact, not
//! prose. Two consequences made the first version of this module unable to
//! answer a word query:
//!
//! * a canonical body is JSON, so its punctuation and key names outweigh its
//!   content in an inverted index; and
//! * the git connector carries verbatim provider byte strings as `HexBytes`,
//!   because the canonical-JSON profile admits only NFC strings with no control
//!   scalars and a real commit message has newlines. A body therefore holds
//!   `"message":"<hex>"`, and indexing it verbatim indexes a hex string. The
//!   dogfood report had to hex-decode every commit message it quoted.
//!
//! The rule chosen, and the trade-off it takes: **the body stays byte-exact and
//! the lexical text learns to read it.** For a media type this module declares,
//! [`derive_lexical_projection`] renders the body's scalar leaves in canonical
//! order and hex-decodes the byte-string fields that media type declares as
//! text, then normalizes the result. The alternative — rendering provider text
//! as canonical strings in the *body* — was rejected because it would either
//! reject ordinary commits or rewrite provider bytes, and either way would move
//! the body's content address and with it every chunk-occurrence identity
//! derived from it.
//!
//! Nothing about identity is weakened by this. The body's content address, the
//! occurrence ids, and the parse manifest are all unchanged; only the *lossy*
//! search text differs, it is still addressed under its own digest domain, and
//! [`LEXICAL_NORMALIZATION_VERSION`] rises so the old and new texts can never
//! claim the same identity. A media type this module does not declare is
//! normalized from its raw bytes exactly as before.

use std::borrow::Cow;

use unicode_normalization::UnicodeNormalization as _;

// The secret scanner and its replacement discipline live beside the transcript
// connector, which is where they were first needed. They are not
// transcript-specific: the shapes they match are credentials wherever they
// appear, and the recall plane needs exactly the same refusal.
use crate::connectors::transcript::{REDACTION_PLACEHOLDER, RedactionDispositionV1, redact};
use crate::memory_contracts::digest::{DigestDomain, Sha256Digest, body_digest, framed_digest};

use super::error::{RecallProjectionError, RecallProjectionResult};

/// Version of the normalization pipeline in this module.
///
/// It is part of the lexical text's digest preimage: changing the pipeline
/// without changing this constant would let two different normalizers claim the
/// same identity. Version 2 added the media-type-aware rendering described
/// above; version 1 normalized raw body bytes for every media type.
pub const LEXICAL_NORMALIZATION_VERSION: u32 = 2;

/// Media type of a canonical git provider fact.
pub const GIT_FACT_MEDIA_TYPE: &str = "application.ostk-git-fact-v1";
/// Media type of a canonical JSON body with no byte-string fields (the
/// transcript connector's turn body).
pub const CANONICAL_JSON_MEDIA_TYPE: &str = "application.json";

/// Deepest canonical-JSON nesting this renderer will walk.
///
/// Well below the canonical profile's own depth bound, so a body that reaches
/// it is not a body this pipeline produced; it falls back to raw-byte
/// normalization rather than recursing.
const MAX_RENDER_DEPTH: u32 = 32;

/// Keys whose JSON string value is lowercase hex of verbatim provider bytes,
/// per media type, sorted so lookup is a binary search.
///
/// This is a *declaration about a body format*, not a decoding heuristic: a key
/// not listed here is indexed exactly as it is stored, so an object id stays an
/// object id and is never mangled into bytes it does not mean.
fn declared_text_fields(media_type: &str) -> Option<&'static [&'static str]> {
    match media_type {
        // GitCommitFactV1::message, GitIdentityV1::{name,email},
        // GitBlobSourceFactV1::path.
        GIT_FACT_MEDIA_TYPE => Some(&["email", "message", "name", "path"]),
        // Canonical JSON with no byte-string fields: rendering still strips the
        // JSON scaffolding so the turn text dominates its own index entry.
        CANONICAL_JSON_MEDIA_TYPE => Some(&[]),
        _ => None,
    }
}

fn push_word(out: &mut String, value: &str) {
    if value.is_empty() {
        return;
    }
    if !out.is_empty() {
        out.push(' ');
    }
    out.push_str(value);
}

/// Append one JSON value's scalar leaves, decoding declared byte-string fields.
///
/// `key` is the object key the value was reached under, carried through arrays
/// so a list of byte strings decodes element by element.
fn render_value(
    value: &serde_json::Value,
    fields: &[&str],
    key: Option<&str>,
    depth: u32,
    out: &mut String,
) -> bool {
    if depth > MAX_RENDER_DEPTH {
        return false;
    }
    match value {
        serde_json::Value::Null => {}
        serde_json::Value::Bool(flag) => push_word(out, if *flag { "true" } else { "false" }),
        serde_json::Value::Number(number) => push_word(out, &number.to_string()),
        serde_json::Value::String(text) => {
            let decoded = key
                .filter(|name| fields.binary_search(name).is_ok())
                .and_then(|_| hex::decode(text).ok())
                .map(|bytes| String::from_utf8_lossy(&bytes).into_owned());
            match decoded {
                // Lossy on purpose: provider bytes with no declared encoding
                // still have to produce SOME deterministic text, and the body
                // itself keeps the exact bytes.
                Some(text) => push_word(out, &text),
                None => push_word(out, text),
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                if !render_value(item, fields, key, depth + 1, out) {
                    return false;
                }
            }
        }
        serde_json::Value::Object(entries) => {
            for (name, item) in entries {
                if !render_value(item, fields, Some(name), depth + 1, out) {
                    return false;
                }
            }
        }
    }
    true
}

/// The bytes the normalizer runs over for one body.
///
/// A declared media type whose body parses as JSON is rendered; anything else —
/// an undeclared media type, a body that is not JSON, a body deeper than
/// [`MAX_RENDER_DEPTH`] — falls back to the raw body bytes, which is the
/// version-1 behaviour and never loses a body.
fn searchable_source<'body>(media_type: &str, body_bytes: &'body [u8]) -> Cow<'body, [u8]> {
    let Some(fields) = declared_text_fields(media_type) else {
        return Cow::Borrowed(body_bytes);
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body_bytes) else {
        return Cow::Borrowed(body_bytes);
    };
    let mut rendered = String::new();
    if render_value(&value, fields, None, 0, &mut rendered) {
        Cow::Owned(rendered.into_bytes())
    } else {
        Cow::Borrowed(body_bytes)
    }
}

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

/// Strip every secret-shaped range out of the text the recall plane will index.
///
/// The activated redaction policy this memory runs under says
/// `secrets_allowed_in_recall: false`. The lexical tier IS the recall index, so
/// this is that activated promise enforced at exactly the plane it names.
///
/// It matters here and not before because of what rendering does: the git
/// connector carries verbatim provider bytes as `HexBytes`, so a
/// credential-shaped commit message is invisible to a scanner reading the body
/// and visible the moment the text is decoded for search. The dogfood run found
/// exactly one such commit in this repository's own history — a message quoting
/// a `postgresql://user:pass@host` fixture string — and it is that decoding, not
/// this projector, that made it readable.
///
/// Residual, recorded rather than hidden: the BODY still holds those bytes, and
/// deliberately so — a body is evidence and must reproduce the provider fact
/// exactly. What this removes is the *retrievable* copy. Closing the gap at
/// ingress needs a redactor on the git connector, which is a connector change,
/// not a projector one.
///
/// A text redaction cannot neutralize (an unredactable class, or a residual
/// match after replacement) collapses to the placeholder alone: the recall
/// plane's answer to "this could not be made safe" is to carry no searchable
/// text from it, never a partial redaction.
fn redact_for_recall(text: &str) -> String {
    match redact(text).disposition {
        RedactionDispositionV1::Stage { text } => text,
        RedactionDispositionV1::Withhold { .. } => REDACTION_PLACEHOLDER.to_owned(),
    }
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
/// 5. every secret-shaped range is replaced ([`redact_for_recall`]);
/// 6. the result is truncated to [`MAX_LEXICAL_TEXT_BYTES`] on a `char`
///    boundary and re-trimmed.
///
/// Redaction runs BEFORE truncation because a replacement can be longer than
/// what it replaces; truncating first could push a redacted row past the
/// column bound.
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

    let mut normalized = redact_for_recall(&normalized);

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
///
/// `media_type` is the body row's own stored media type. It selects the
/// rendering described in the module docs and nothing else: it cannot change
/// the integrity check, and an unrecognized value is normalized from raw bytes.
pub fn derive_lexical_projection(
    body_content_id: Sha256Digest,
    body_bytes: &[u8],
    media_type: &str,
) -> RecallProjectionResult<LexicalProjectionV1> {
    // Identity BEFORE any rendering: the media type steers what gets indexed,
    // so it must never be able to steer what gets accepted.
    if body_digest(body_bytes) != body_content_id {
        return Err(RecallProjectionError::BodyIntegrityMismatch);
    }
    let source = searchable_source(media_type, body_bytes);
    let (state, text) = normalize(&source);
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
    use crate::connectors::transcript::scan_secrets;

    /// An undeclared media type: raw-byte normalization, the version-1 path.
    const OPAQUE: &str = "application.octet-stream";

    fn projection(bytes: &[u8]) -> LexicalProjectionV1 {
        derive_lexical_projection(body_digest(bytes), bytes, OPAQUE).unwrap()
    }

    fn projection_of(media_type: &str, bytes: &[u8]) -> LexicalProjectionV1 {
        derive_lexical_projection(body_digest(bytes), bytes, media_type).unwrap()
    }

    #[test]
    fn derivation_fails_closed_when_bytes_do_not_match_the_content_address() {
        // The one attack this seam must refuse: projecting text that is not the
        // body the content address names.
        let honest = b"alpha beta";
        let swapped = b"gamma delta";
        assert!(matches!(
            derive_lexical_projection(body_digest(honest), swapped, OPAQUE),
            Err(RecallProjectionError::BodyIntegrityMismatch)
        ));
    }

    #[test]
    fn the_media_type_cannot_talk_a_mismatched_body_past_the_integrity_check() {
        // Rendering happens AFTER the content address is proven, so no media
        // type — declared or not — can make foreign bytes projectable.
        let honest = b"{\"message\":\"6869\"}";
        let swapped = b"{\"message\":\"6a6b\"}";
        assert!(matches!(
            derive_lexical_projection(body_digest(honest), swapped, GIT_FACT_MEDIA_TYPE),
            Err(RecallProjectionError::BodyIntegrityMismatch)
        ));
    }

    #[test]
    fn a_git_fact_body_indexes_its_commit_message_as_words() {
        // The defect the dogfood report found: a commit message carried as
        // HexBytes indexed as a hex string, so `record-count` could not hit the
        // commit that deleted the record-count pin.
        let message = "ci: delete the brittle record-count pins";
        let body = format!(
            "{{\"commit_id\":\"abc123\",\"kind\":\"commit\",\"message\":\"{}\"}}",
            hex::encode(message)
        );
        let derived = projection_of(GIT_FACT_MEDIA_TYPE, body.as_bytes());
        assert_eq!(derived.state, LexicalStateV1::Indexed);
        assert!(derived.text.contains("record-count"));
        assert!(derived.text.contains("brittle"));
        // The object id is not a declared text field, so it stays exactly as
        // the body records it rather than being decoded into noise.
        assert!(derived.text.contains("abc123"));
        // And the hex spelling of the message is gone from the index.
        assert!(!derived.text.contains(&hex::encode(message)));
    }

    #[test]
    fn an_undeclared_media_type_still_indexes_the_raw_body() {
        // Fallback, not failure: an unknown body format loses the rendering,
        // never the row.
        let body = br#"{"message":"6869"}"#;
        let derived = projection_of(OPAQUE, body);
        assert_eq!(derived.state, LexicalStateV1::Indexed);
        assert!(derived.text.contains("6869"));
    }

    #[test]
    fn a_canonical_json_body_indexes_its_text_without_the_json_scaffolding() {
        let body = br#"{"ordinal":415,"role":"assistant","text":"the record-count pin"}"#;
        let derived = projection_of(CANONICAL_JSON_MEDIA_TYPE, body);
        assert_eq!(derived.text, "415 assistant the record-count pin");
    }

    #[test]
    fn a_declared_field_that_is_not_hex_is_indexed_verbatim() {
        // A body whose declared text field holds an ordinary string must not be
        // dropped or mangled; decoding is best-effort, indexing is not.
        let body = br#"{"message":"not hex at all"}"#;
        let derived = projection_of(GIT_FACT_MEDIA_TYPE, body);
        assert_eq!(derived.text, "not hex at all");
    }

    #[test]
    fn a_body_that_is_not_json_falls_back_to_its_raw_bytes() {
        let body = b"this is not json";
        let derived = projection_of(GIT_FACT_MEDIA_TYPE, body);
        assert_eq!(derived.text, "this is not json");
    }

    #[test]
    fn rendering_is_deterministic_and_independent_of_the_body_address() {
        let body = br#"{"message":"6869","name":"6a6b"}"#;
        assert_eq!(
            projection_of(GIT_FACT_MEDIA_TYPE, body),
            projection_of(GIT_FACT_MEDIA_TYPE, body)
        );
        // Two media types over the same bytes produce different SEARCH text and
        // different text digests, and the body address is untouched by either.
        assert_ne!(
            projection_of(GIT_FACT_MEDIA_TYPE, body).text_digest,
            projection_of(OPAQUE, body).text_digest
        );
        assert_eq!(
            projection_of(GIT_FACT_MEDIA_TYPE, body).body_content_id,
            projection_of(OPAQUE, body).body_content_id
        );
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
    fn a_credential_shaped_commit_message_never_reaches_the_search_index() {
        // The leak the dogfood run found, as a unit test. This repository's own
        // history contains a commit whose message quotes a
        // `postgresql://user:pass@host` fixture string. Carried as HexBytes it
        // was invisible to a scanner reading the body; decoded for search it is
        // a credential shape, and the activated redaction policy says secrets
        // are not allowed in recall.
        let message = "corpus fixture: EXPLICIT_URL = \"postgresql://generic:explicit-secret@cluster.example\"";
        let body = format!(
            "{{\"kind\":\"commit\",\"message\":\"{}\"}}",
            hex::encode(message)
        );
        let derived = projection_of(GIT_FACT_MEDIA_TYPE, body.as_bytes());
        assert_eq!(derived.state, LexicalStateV1::Indexed);
        assert!(!derived.text.contains("explicit-secret"));
        assert!(derived.text.contains(REDACTION_PLACEHOLDER));
        // The surrounding prose survives: this is a redaction, not a drop.
        assert!(derived.text.contains("corpus fixture"));
        // And the check is not fooled by its own output.
        assert!(scan_secrets(&derived.text).is_empty());
    }

    #[test]
    fn an_unredactable_secret_leaves_no_searchable_text_at_all() {
        // A private-key block has no dependable end marker, so the redactor
        // refuses to guess where it stops. The recall plane's answer is to
        // carry nothing from that body rather than a partial redaction.
        let body = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK\n";
        let derived = projection_of(OPAQUE, body.as_bytes());
        assert_eq!(derived.text, REDACTION_PLACEHOLDER);
        assert!(scan_secrets(&derived.text).is_empty());
    }

    #[test]
    fn redaction_happens_before_truncation_so_a_row_stays_inside_its_bound() {
        // A replacement is longer than a one-character match, so truncating
        // first could push a redacted row past the stored column bound.
        let mut source = "a".repeat(MAX_LEXICAL_TEXT_BYTES - 8);
        source.push_str(" https://u:p@h ");
        source.push_str(&"b".repeat(64));
        let derived = projection_of(OPAQUE, source.as_bytes());
        assert!(derived.text.len() <= MAX_LEXICAL_TEXT_BYTES);
        assert!(!derived.text.contains("u:p@h"));
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
