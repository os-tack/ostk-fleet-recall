//! Unit tests for the bespoke transcript JSONL parser.

use super::*;

const SESSION: &str = "01931f2c-0000-7000-8000-000000000001";

fn line(kind: &str, uid: &str, timestamp: &str, text: &str) -> String {
    format!(
        r#"{{"type":"{kind}","sessionId":"{SESSION}","uuid":"{uid}","timestamp":"{timestamp}","message":{{"role":"{kind}","content":[{{"type":"text","text":{}}}]}}}}"#,
        serde_json::to_string(text).unwrap()
    )
}

fn transcript() -> String {
    format!(
        "{}\n{}\n",
        line("user", "turn-1", "2026-08-15T12:30:00.000Z", "hello"),
        line(
            "assistant",
            "turn-2",
            "2026-08-15T12:30:01.500Z",
            "hi there"
        )
    )
}

#[test]
fn a_well_formed_transcript_parses_into_ordered_turns() {
    let bytes = transcript();
    let parsed = parse_transcript("s", bytes.as_bytes(), 0, 0).unwrap();

    assert_eq!(parsed.turns.len(), 2);
    assert_eq!(parsed.turns[0].role, TranscriptRoleV1::User);
    assert_eq!(parsed.turns[0].ordinal, 0);
    assert_eq!(parsed.turns[0].text, "hello");
    assert_eq!(parsed.turns[1].role, TranscriptRoleV1::Assistant);
    assert_eq!(parsed.turns[1].ordinal, 1);
    assert_eq!(parsed.turns[1].text, "hi there");
    assert_eq!(parsed.consumed_bytes, bytes.len() as u64);
    assert_eq!(parsed.consumed_lines, 2);
    assert_eq!(parsed.skipped_records, 0);
}

#[test]
fn every_span_names_the_exact_source_line_bytes() {
    let bytes = transcript();
    let parsed = parse_transcript("s", bytes.as_bytes(), 0, 0).unwrap();
    for turn in &parsed.turns {
        let start = usize::try_from(turn.span.byte_start).unwrap();
        let end = usize::try_from(turn.span.byte_end).unwrap();
        let slice = &bytes.as_bytes()[start..end];
        assert_eq!(turn.span.span_digest, source_span_digest(slice));
        assert!(slice.starts_with(b"{\"type\":"));
        assert!(!slice.contains(&b'\n'));
    }
}

#[test]
fn timestamps_are_truncated_to_microseconds_so_they_survive_a_timestamptz() {
    let raw = line("user", "turn-1", "2026-08-15T12:30:00.123456789Z", "x");
    let parsed = parse_transcript("s", format!("{raw}\n").as_bytes(), 0, 0).unwrap();
    let occurred = &parsed.turns[0].occurred_at;
    assert!(occurred.is_microsecond_aligned());
    assert_eq!(occurred.as_str(), "2026-08-15T12:30:00.123456000Z");
}

#[test]
fn system_and_summary_records_are_counted_not_silently_dropped() {
    let bytes = format!(
        "{}\n{}\n{}\n",
        r#"{"type":"summary","summary":"a"}"#,
        line("user", "turn-1", "2026-08-15T12:30:00.000Z", "hello"),
        r#"{"type":"system","content":"boot"}"#
    );
    let parsed = parse_transcript("s", bytes.as_bytes(), 0, 0).unwrap();
    assert_eq!(parsed.turns.len(), 1);
    assert_eq!(parsed.skipped_records, 2);
    // Ordinals number turns, not lines: the skipped records take no ordinal.
    assert_eq!(parsed.turns[0].ordinal, 0);
}

#[test]
fn an_unparseable_line_fails_the_whole_batch_closed() {
    let bytes = format!(
        "{}\nnot json at all\n",
        line("user", "turn-1", "2026-08-15T12:30:00.000Z", "hello")
    );
    let error = parse_transcript("s", bytes.as_bytes(), 0, 0).unwrap_err();
    assert!(matches!(
        error,
        TranscriptConnectorError::MalformedTranscript {
            line_ordinal: 2,
            reason: "line is not a transcript record",
            ..
        }
    ));
}

#[test]
fn an_unknown_record_type_is_refused_rather_than_skipped() {
    let bytes = r#"{"type":"telemetry","sessionId":"s","uuid":"u"}"#.to_owned() + "\n";
    let error = parse_transcript("s", bytes.as_bytes(), 0, 0).unwrap_err();
    assert!(matches!(
        error,
        TranscriptConnectorError::MalformedTranscript { .. }
    ));
}

#[test]
fn a_record_without_a_session_id_is_refused() {
    let bytes = r#"{"type":"user","uuid":"u","timestamp":"2026-08-15T12:30:00Z","message":{"content":"hi"}}"#
        .to_owned()
        + "\n";
    let error = parse_transcript("s", bytes.as_bytes(), 0, 0).unwrap_err();
    assert!(matches!(
        error,
        TranscriptConnectorError::MalformedTranscript {
            reason: "record has no session id",
            ..
        }
    ));
}

#[test]
fn a_record_with_an_uncanonical_timestamp_is_refused() {
    let bytes = format!(
        "{}\n",
        r#"{"type":"user","sessionId":"s","uuid":"u","timestamp":"yesterday","message":{"content":"hi"}}"#
    );
    let error = parse_transcript("s", bytes.as_bytes(), 0, 0).unwrap_err();
    assert!(matches!(
        error,
        TranscriptConnectorError::MalformedTranscript {
            reason: "record has no canonical timestamp",
            ..
        }
    ));
}

#[test]
fn a_turn_record_with_no_text_block_is_counted_not_refused() {
    // Generation 2: a tool call, a tool result, or a thinking-only reply is a
    // real record that carries no conversational turn. It is counted like a
    // `system` record, takes no ordinal, and does not fail the batch.
    let bytes = format!(
        "{}\n{}\n{}\n",
        r#"{"type":"assistant","sessionId":"s","uuid":"u1","timestamp":"2026-08-15T12:30:00Z","message":{"content":[{"type":"tool_use","id":"t"}]}}"#,
        line("user", "turn-1", "2026-08-15T12:30:01.000Z", "hello"),
        r#"{"type":"user","sessionId":"s","uuid":"u2","timestamp":"2026-08-15T12:30:02Z","message":{"content":[{"type":"tool_result","tool_use_id":"t"}]}}"#
    );
    let parsed = parse_transcript("s", bytes.as_bytes(), 0, 0).unwrap();
    assert_eq!(parsed.turns.len(), 1);
    assert_eq!(parsed.turns[0].text, "hello");
    assert_eq!(parsed.turns[0].ordinal, 0, "skips take no turn ordinal");
    assert_eq!(parsed.skipped_records, 2);
}

#[test]
fn a_turn_record_missing_an_identity_field_is_still_refused() {
    // The text allowance is narrow: a record missing a field the IDENTITY needs
    // still fails the batch closed rather than being counted as a skip.
    for (reason, raw) in [
        (
            "record has no turn uid",
            r#"{"type":"assistant","sessionId":"s","timestamp":"2026-08-15T12:30:00Z","message":{"content":[{"type":"tool_use","id":"t"}]}}"#,
        ),
        (
            "record has no canonical timestamp",
            r#"{"type":"assistant","sessionId":"s","uuid":"u","message":{"content":[{"type":"tool_use","id":"t"}]}}"#,
        ),
    ] {
        let bytes = format!("{raw}\n");
        let error = parse_transcript("s", bytes.as_bytes(), 0, 0).unwrap_err();
        match error {
            TranscriptConnectorError::MalformedTranscript { reason: got, .. } => {
                assert_eq!(got, reason);
            }
            other => panic!("expected a malformed-transcript refusal, got {other:?}"),
        }
    }
}

#[test]
fn every_session_runtime_record_kind_is_counted_and_none_is_a_turn() {
    // The exact non-turn kinds a live Claude session file carries. Each must be
    // a counted skip; an unrecognized kind must still abort (covered by
    // `an_unknown_record_type_is_refused_rather_than_skipped`).
    let kinds = [
        "mode",
        "permission-mode",
        "atis-latch",
        "bridge-session",
        "ai-title",
        "last-prompt",
        "queue-operation",
        "attachment",
        "file-history-snapshot",
        "file-history-delta",
        "system",
        "summary",
    ];
    let mut source = String::new();
    for kind in kinds {
        use std::fmt::Write as _;
        let _ = writeln!(source, r#"{{"type":"{kind}","sessionId":"s"}}"#);
    }
    source.push_str(&line("user", "turn-1", "2026-08-15T12:30:00.000Z", "hello"));
    source.push('\n');
    let parsed = parse_transcript("s", source.as_bytes(), 0, 0).unwrap();
    assert_eq!(parsed.turns.len(), 1);
    assert_eq!(
        parsed.skipped_records,
        u32::try_from(kinds.len()).unwrap(),
        "every non-turn kind is counted, never silently dropped"
    );
}

#[test]
fn a_partial_final_line_is_left_for_the_next_batch() {
    let complete = line("user", "turn-1", "2026-08-15T12:30:00.000Z", "hello");
    let bytes = format!("{complete}\n{{\"type\":\"user\",\"session");
    let parsed = parse_transcript("s", bytes.as_bytes(), 0, 0).unwrap();
    assert_eq!(parsed.turns.len(), 1);
    // The cursor stops at the end of the last COMPLETE line, so the partial
    // write is re-read whole next time rather than parsed half-formed.
    assert_eq!(parsed.consumed_bytes, (complete.len() + 1) as u64);
}

#[test]
fn resuming_from_a_cursor_emits_only_the_new_turns_and_continues_numbering() {
    let first = line("user", "turn-1", "2026-08-15T12:30:00.000Z", "hello");
    let second = line("assistant", "turn-2", "2026-08-15T12:30:01.000Z", "world");
    let bytes = format!("{first}\n{second}\n");
    let resume = (first.len() + 1) as u64;

    let parsed = parse_transcript("s", bytes.as_bytes(), resume, 1).unwrap();
    assert_eq!(parsed.turns.len(), 1);
    assert_eq!(parsed.turns[0].text, "world");
    assert_eq!(parsed.turns[0].ordinal, 1);
    assert_eq!(parsed.consumed_bytes, bytes.len() as u64);
}

#[test]
fn a_source_shorter_than_its_cursor_is_refused() {
    let bytes = b"{}\n";
    let error = parse_transcript("s", bytes, 4_096, 0).unwrap_err();
    assert!(matches!(
        error,
        TranscriptConnectorError::MalformedTranscript {
            reason: "transcript is shorter than the durable cursor",
            ..
        }
    ));
}

#[test]
fn a_cursor_that_does_not_land_on_a_line_boundary_is_refused() {
    let first = line("user", "turn-1", "2026-08-15T12:30:00.000Z", "hello");
    let bytes = format!("{first}\n");
    let error = parse_transcript("s", bytes.as_bytes(), 4, 0).unwrap_err();
    assert!(matches!(
        error,
        TranscriptConnectorError::MalformedTranscript {
            reason: "durable cursor does not land on a line boundary",
            ..
        }
    ));
}

#[test]
fn an_oversized_batch_is_refused_rather_than_partially_parsed() {
    let bytes = vec![b'x'; MAX_TRANSCRIPT_BYTES + 1];
    let error = parse_transcript("s", &bytes, 0, 0).unwrap_err();
    assert!(matches!(
        error,
        TranscriptConnectorError::MalformedTranscript {
            reason: "transcript batch exceeds the batch bound",
            ..
        }
    ));
}

#[test]
fn a_file_past_the_bound_is_still_readable_once_its_cursor_has_advanced() {
    // The bound is on the UNCONSUMED remainder. A session file that has grown
    // past the bound must stay readable: bounding the whole file made a live
    // source permanently unreadable the moment it crossed 8 MiB, however small
    // the batch left to read.
    let turn = line("user", "turn-1", "2026-08-15T12:30:00.000Z", "hello");
    let mut bytes = vec![b'\n'; MAX_TRANSCRIPT_BYTES + 1];
    bytes.extend_from_slice(turn.as_bytes());
    bytes.push(b'\n');
    let resume = u64::try_from(MAX_TRANSCRIPT_BYTES + 1).unwrap();

    assert!(
        parse_transcript("s", &bytes, 0, 0).is_err(),
        "reading the whole file in one batch is still refused"
    );
    let parsed = parse_transcript("s", &bytes, resume, 7).unwrap();
    assert_eq!(parsed.turns.len(), 1);
    assert_eq!(parsed.turns[0].ordinal, 7, "numbering continues");
    assert_eq!(parsed.consumed_bytes, u64::try_from(bytes.len()).unwrap());
}

#[test]
fn normalization_applies_exactly_the_declared_rules() {
    // Every whitespace scalar folds to one space; runs collapse; both ends trim.
    assert_eq!(normalize("a  \r\nb\t\n\n\n"), "a b");
    assert_eq!(normalize("a\n\nb"), "a b");
    assert_eq!(normalize("  a  "), "a");
    // Control scalars that are not whitespace are dropped outright.
    assert_eq!(normalize("a\u{0}\u{7}b"), "ab");
    // NFC composition, so two byte spellings of one word normalize alike.
    assert_eq!(normalize("cafe\u{301}"), normalize("caf\u{e9}"));
}

#[test]
fn a_normalized_turn_is_canonically_encodable() {
    // The property generation 2 exists for: generation 1 preserved interior
    // newlines, and the canonical encoder refuses ANY control scalar in a
    // string, so a real multi-line turn could not be encoded at all.
    let raw = "first line\n\nsecond line\twith a tab\r\nand a CRLF";
    let normalized = normalize(raw);
    assert!(!normalized.chars().any(char::is_control));
    ostk_fleet_recall_canonical_probe(&normalized);
}

/// Encode the normalized text through the exact canonical encoder the
/// connector's candidate goes through, so this test fails if the encoder ever
/// stops accepting what the parser emits.
fn ostk_fleet_recall_canonical_probe(text: &str) {
    crate::memory_contracts::canonical::encode_canonical(&text.to_owned())
        .expect("a normalized turn must be canonically encodable");
}

#[test]
fn both_parser_keys_validate_and_are_distinct_identities() {
    let first = transcript_parser_key_v1();
    let second = transcript_parser_key_v2();
    first.validate().unwrap();
    second.validate().unwrap();
    assert_ne!(first, second);
    assert_ne!(
        first.key_digest().unwrap().digest(),
        second.key_digest().unwrap().digest()
    );
    assert_eq!(first.declared_normalization_rules.len(), 2);
    // The retired generation-1 key keeps its own version; the production key is
    // the parser's current one, so a behaviour change is visible as an identity
    // change rather than happening underneath the old identity.
    assert_eq!(first.parser_version, 1);
    assert_eq!(second.parser_version, TRANSCRIPT_PARSER_VERSION);
    assert_ne!(first.configuration_digest, second.configuration_digest);
}

#[test]
fn a_record_carrying_both_session_id_spellings_parses_and_camel_case_wins() {
    // Real records carry BOTH spellings. A serde alias would make the second
    // one a duplicate-field error and refuse the line; two fields with a stated
    // precedence accept either or both.
    let both = format!(
        "{}\n",
        r#"{"type":"user","sessionId":"camel","session_id":"snake","uuid":"u","timestamp":"2026-08-15T12:30:00Z","message":{"content":"hi"}}"#
    );
    assert_eq!(
        parse_transcript("s", both.as_bytes(), 0, 0).unwrap().turns[0].session_id,
        "camel"
    );

    let snake_only = format!(
        "{}\n",
        r#"{"type":"user","session_id":"snake","uuid":"u","timestamp":"2026-08-15T12:30:00Z","message":{"content":"hi"}}"#
    );
    assert_eq!(
        parse_transcript("s", snake_only.as_bytes(), 0, 0)
            .unwrap()
            .turns[0]
            .session_id,
        "snake"
    );
}

#[test]
fn a_string_content_body_parses_the_same_as_a_single_text_block() {
    let string_form = format!(
        "{}\n",
        r#"{"type":"user","sessionId":"s","uuid":"u","timestamp":"2026-08-15T12:30:00Z","message":{"content":"plain"}}"#
    );
    let parsed = parse_transcript("s", string_form.as_bytes(), 0, 0).unwrap();
    assert_eq!(parsed.turns[0].text, "plain");
}
