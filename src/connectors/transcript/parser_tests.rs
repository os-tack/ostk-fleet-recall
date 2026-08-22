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
fn a_record_with_no_extractable_text_is_refused() {
    let bytes = format!(
        "{}\n",
        r#"{"type":"assistant","sessionId":"s","uuid":"u","timestamp":"2026-08-15T12:30:00Z","message":{"content":[{"type":"tool_use","id":"t"}]}}"#
    );
    let error = parse_transcript("s", bytes.as_bytes(), 0, 0).unwrap_err();
    assert!(matches!(
        error,
        TranscriptConnectorError::MalformedTranscript {
            reason: "record carries no extractable text",
            ..
        }
    ));
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
fn an_oversized_transcript_is_refused_rather_than_partially_parsed() {
    let bytes = vec![b'x'; MAX_TRANSCRIPT_BYTES + 1];
    let error = parse_transcript("s", &bytes, 0, 0).unwrap_err();
    assert!(matches!(
        error,
        TranscriptConnectorError::MalformedTranscript {
            reason: "transcript exceeds the batch bound",
            ..
        }
    ));
}

#[test]
fn normalization_applies_exactly_the_declared_rules() {
    // CRLF collapses to LF, trailing spaces/tabs go, trailing blank lines go.
    assert_eq!(normalize("a  \r\nb\t\n\n\n"), "a\nb");
    // Interior blank lines are preserved: whitespace collapse is NOT declared.
    assert_eq!(normalize("a\n\nb"), "a\n\nb");
    // Leading whitespace is preserved: only TRAILING trim is declared.
    assert_eq!(normalize("  a"), "  a");
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
