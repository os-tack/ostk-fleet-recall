//! Unit tests for the lexical projection.
//!
//! Extracted into its own file for one reason: these tests carry
//! DELIBERATE secret-shaped strings — a `postgresql://user:pass@host`
//! fixture and a private-key header — because that is how you test a
//! redaction boundary. They therefore match the publication corpus's
//! sensitive-pattern gate, exactly like `src/config_tests.rs` and
//! `src/connectors/transcript/redactor_tests.rs`, and are excluded from the
//! corpus for the same reason. Keeping them here leaves the production
//! module itself publication-safe.

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
    let message =
        "corpus fixture: EXPLICIT_URL = \"postgresql://generic:explicit-secret@cluster.example\"";
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
