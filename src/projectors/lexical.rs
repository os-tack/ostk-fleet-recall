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

use crate::memory_contracts::collected_item::{COLLECTED_ITEM_MEDIA_TYPE, ItemLifecycleV1};
use crate::memory_contracts::digest::{DigestDomain, Sha256Digest, body_digest, framed_digest};
// The crate's one secret scanner and its replacement discipline: the shapes it
// matches are credentials wherever they appear, and the recall plane needs
// exactly the same refusal as every collector.
use crate::redaction::{REDACTION_PLACEHOLDER, RedactionDispositionV1, RedactionOutcomeV1, redact};

use super::error::{RecallProjectionError, RecallProjectionResult};

/// Version of the normalization pipeline in this module.
///
/// It is part of the lexical text's digest preimage: changing the pipeline
/// without changing this constant would let two different normalizers claim the
/// same identity. Version 1 normalized raw body bytes for every media type;
/// version 2 added the media-type-aware rendering described above; version 3
/// redacts with redaction profile 3 (`crate::redaction`), which adds the
/// provider credential shapes and Stripe keys to the six shared shapes the
/// recall text was scanned with before. A row stored at an older version is
/// re-derived by the worker's lexical step (`rows_reprojected`), which is what
/// redacts the served copy of a body admitted before profile 3.
pub const LEXICAL_NORMALIZATION_VERSION: u32 = 3;

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

/// A collected-item envelope ([`COLLECTED_ITEM_MEDIA_TYPE`]) is rendered by
/// its own branch, [`render_collected_item`]: text first, identity skipped.
///
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

/// One hex-encoded collected text field, decoded; lossy on purpose, as the
/// declared git fields are, so a body this build did not write still yields
/// deterministic text.
fn collected_text(value: Option<&serde_json::Value>) -> Option<String> {
    let bytes = hex::decode(value?.as_str()?).ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// The searchable text of one collected-item envelope, text first.
///
/// A collected body is an envelope, and most of an envelope is identity:
/// digests, ids, a marker, the audience basis, the collector instance.
/// Indexing those would let a digest outweigh a word, so the render keeps only
/// what a reader would type: the title and the text (both hex-decoded), then
/// the author's display name, the container label, and the link labels. Ids,
/// digests, kinds, and link targets are skipped.
///
/// `None` when the body is not a JSON object, which falls back to raw-byte
/// normalization like any undeclared body.
fn render_collected_item(body_bytes: &[u8]) -> Option<String> {
    let value = serde_json::from_slice::<serde_json::Value>(body_bytes).ok()?;
    let envelope = value.as_object()?;
    let mut rendered = String::new();
    // A tombstone is metadata only; it contributes no searchable text, so a
    // deleted item's author and container never answer a query as if they
    // were its content.
    if envelope
        .get("lifecycle")
        .and_then(serde_json::Value::as_str)
        .and_then(|lifecycle| ItemLifecycleV1::parse(lifecycle).ok())
        .is_some_and(ItemLifecycleV1::is_tombstone)
    {
        return Some(rendered);
    }
    for field in ["title", "text"] {
        if let Some(text) = collected_text(envelope.get(field)) {
            push_word(&mut rendered, &text);
        }
    }
    let display = envelope
        .get("author")
        .and_then(|author| author.get("display"))
        .and_then(serde_json::Value::as_str);
    let label = envelope
        .get("container")
        .and_then(|container| container.get("label"))
        .and_then(serde_json::Value::as_str);
    for word in [display, label].into_iter().flatten() {
        push_word(&mut rendered, word);
    }
    let links = envelope
        .get("links")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten();
    for link in links {
        if let Some(label) = link.get("label").and_then(serde_json::Value::as_str) {
            push_word(&mut rendered, label);
        }
    }
    Some(rendered)
}

/// The bytes the normalizer runs over for one body.
///
/// A declared media type whose body parses as JSON is rendered; anything else —
/// an undeclared media type, a body that is not JSON, a body deeper than
/// [`MAX_RENDER_DEPTH`] — falls back to the raw body bytes, which is the
/// version-1 behaviour and never loses a body.
fn searchable_source<'body>(media_type: &str, body_bytes: &'body [u8]) -> Cow<'body, [u8]> {
    if media_type == COLLECTED_ITEM_MEDIA_TYPE {
        return render_collected_item(body_bytes).map_or(Cow::Borrowed(body_bytes), |rendered| {
            Cow::Owned(rendered.into_bytes())
        });
    }
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
/// a connection-string fixture with an embedded `user:password` authority — and it is that decoding, not
/// this projector, that made it readable.
///
/// Residual, recorded rather than hidden: the BODY still holds those bytes, and
/// deliberately so — a body is evidence and must reproduce the provider fact
/// exactly. What this removes is the *retrievable* copy. Since redaction
/// profile 3 the git connector redacts a commit's text fields at ingress too
/// (`crate::connectors::git::redaction`), so a fact admitted after it carries
/// the placeholder in its body as well; a fact admitted before it keeps its
/// raw bytes at rest, and only this recall copy is redacted, once the worker
/// re-projects rows stored under an older `LEXICAL_NORMALIZATION_VERSION`.
///
/// A text redaction cannot neutralize (an unredactable class, or a residual
/// match after replacement) collapses to the placeholder alone: the recall
/// plane's answer to "this could not be made safe" is to carry no searchable
/// text from it, never a partial redaction.
///
/// Item recall (`src/item_recall`) passes every collected title and text it
/// returns through this again, after decoding it from the body envelope.
#[must_use]
pub fn redact_for_recall(text: &str) -> String {
    redact_for_recall_marked(text).0
}

/// What the recall plane's read-time redaction ([`redact_for_recall`])
/// removed from one text.
///
/// The residual `docs/SECURITY.md` records (a body admitted before the
/// ingress redactors stays raw at rest) made visible per body, and the
/// worklist of the future at-rest supersession pass. Absent from an answer
/// when the pass removed nothing.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RecallRedactionV1 {
    /// The secret classes detected in the stored text, sorted and
    /// deduplicated: labels only, never the matched bytes.
    pub classes: Vec<&'static str>,
    /// Ranges replaced with the placeholder.
    pub ranges: u32,
    /// The text could not be made safe (an unredactable class, or a residual
    /// match after replacement), so the answer carries the placeholder alone.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub withheld: bool,
}

impl RecallRedactionV1 {
    /// The marker of one redaction outcome, or `None` when nothing was
    /// detected and nothing replaced.
    #[must_use]
    pub fn of(outcome: &RedactionOutcomeV1) -> Option<Self> {
        let withheld = matches!(outcome.disposition, RedactionDispositionV1::Withhold { .. });
        if outcome.classes.is_empty() && outcome.redacted_ranges == 0 && !withheld {
            return None;
        }
        Some(Self {
            classes: outcome.classes.iter().map(|class| class.as_str()).collect(),
            ranges: outcome.redacted_ranges,
            withheld,
        })
    }
}

/// [`redact_for_recall`], with what it removed: the text an answer may
/// carry, and a marker when the pass detected or replaced anything.
#[must_use]
pub fn redact_for_recall_marked(text: &str) -> (String, Option<RecallRedactionV1>) {
    let outcome = redact(text);
    let marker = RecallRedactionV1::of(&outcome);
    let text = match outcome.disposition {
        RedactionDispositionV1::Stage { text } => text,
        RedactionDispositionV1::Withhold { .. } => REDACTION_PLACEHOLDER.to_owned(),
    };
    (text, marker)
}

/// Steps 2 to 4 of the lexical normalization pipeline (see [`normalize`]).
///
/// That is Unicode NFC composition, every whitespace scalar folded into one
/// ASCII space with the ends trimmed, and every other control scalar dropped.
/// The lexical tier indexes text folded this way, so a query must be folded
/// the same way before it is matched against it: a decomposed (NFD) query
/// word, or one split by a control scalar, would otherwise never match the
/// indexed spelling of the same word.
#[must_use]
pub fn fold_lexical_characters(text: &str) -> String {
    let mut folded = String::with_capacity(text.len());
    let mut pending_space = false;
    for character in text.nfc() {
        if character.is_whitespace() {
            pending_space = !folded.is_empty();
            continue;
        }
        if character.is_control() {
            continue;
        }
        if pending_space {
            folded.push(' ');
            pending_space = false;
        }
        folded.push(character);
    }
    folded
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
///
///    (steps 2 to 4 are [`fold_lexical_characters`], which evidence recall
///    also applies to a query);
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

    let mut normalized = redact_for_recall(&fold_lexical_characters(decoded));

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
#[path = "lexical_tests.rs"]
mod tests;
