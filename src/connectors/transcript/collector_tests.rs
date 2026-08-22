//! Unit tests for the collection pipeline — above all, the security boundary:
//! secret-shaped content never becomes an outbox row.

use super::super::parser::transcript_parser_key_v1;
use super::super::redactor::{RedactionGuaranteeV1, SecretClassV1};
use super::super::test_fixture::{
    PLANTED_KEY_MATERIAL, PLANTED_REDACTABLE_SECRET, active_package, binding, clean_transcript,
    clocks, line, secret_transcript,
};
use super::*;
use crate::connectors::transcript::{
    TranscriptConnectorError, TranscriptCursorRowV1, TranscriptOutboxStateV1,
};

const SESSION: &str = "01931f2c-0000-7000-8000-000000000002";

fn guarantee() -> RedactionGuaranteeV1 {
    RedactionGuaranteeV1::from_active_package(&active_package())
        .expect("the frozen Stage-4 package promises redaction before the durable outbox")
}

fn collect(
    transcript: &str,
    cursor: Option<&TranscriptCursorRowV1>,
) -> (TranscriptBatchV1, TranscriptCollectionStatsV1) {
    let active = active_package();
    collect_batch(&TranscriptCollectionRequestV1 {
        active: &active,
        binding: &binding(),
        guarantee: &guarantee(),
        parser_key: &transcript_parser_key_v1(),
        source_id: "session.jsonl",
        bytes: transcript.as_bytes(),
        cursor,
        clocks: &clocks(),
    })
    .unwrap()
}

#[test]
fn the_active_package_supplies_the_redaction_guarantee() {
    let guarantee = guarantee();
    assert_eq!(guarantee.policy_id().as_str(), "redaction.default");
    assert_eq!(guarantee.policy_version(), 3);
}

#[test]
fn a_clean_transcript_stages_one_row_per_turn() {
    let (batch, stats) = collect(&clean_transcript(SESSION), None);
    assert_eq!(batch.rows.len(), 2);
    assert_eq!(stats.turns_parsed, 2);
    assert_eq!(stats.turns_staged, 2);
    assert_eq!(stats.turns_withheld, 0);
    assert_eq!(stats.turns_redacted, 0);
    assert_eq!(batch.cursor.next_ordinal, 2);
    assert_eq!(batch.cursor.batch_seq, 1);
    assert!(stats.classes_detected.is_empty());
    for (index, row) in batch.rows.iter().enumerate() {
        assert_eq!(row.turn_ordinal, u32::try_from(index).unwrap());
        assert_eq!(row.state, TranscriptOutboxStateV1::Pending);
        assert_eq!(row.source_id, "session.jsonl");
    }
}

/// THE KILLER PROPERTY (pure half). No byte of either planted secret appears in
/// any field of any staged row: the unredactable turn is withheld whole and the
/// redactable one is staged with the secret replaced.
#[test]
fn a_planted_secret_never_reaches_a_staged_row() {
    let (batch, stats) = collect(&secret_transcript(SESSION), None);

    assert_eq!(stats.turns_parsed, 4);
    assert_eq!(
        stats.turns_staged, 3,
        "only the key-material turn is dropped"
    );
    assert_eq!(stats.turns_withheld, 1);
    assert_eq!(stats.turns_redacted, 1);
    assert_eq!(batch.withheld, 1);
    assert_eq!(batch.rows.len(), 3);
    assert!(
        stats
            .classes_detected
            .contains(&SecretClassV1::PrivateKeyBlock)
    );
    assert!(
        stats
            .classes_detected
            .contains(&SecretClassV1::AwsAccessKeyId)
    );

    for planted in [PLANTED_KEY_MATERIAL, PLANTED_REDACTABLE_SECRET] {
        let needle = planted.as_bytes();
        for row in &batch.rows {
            for field in [
                &row.canonical_candidate,
                &row.canonical_locators,
                &row.canonical_payload,
            ] {
                assert!(
                    !field.windows(needle.len()).any(|window| window == needle),
                    "a staged row field contains the planted secret {planted}"
                );
            }
            assert!(!row.session_id.contains(planted));
            assert!(!row.source_id.contains(planted));
        }
    }
    // The whole PEM envelope is gone too, not merely its base64 payload.
    for row in &batch.rows {
        let payload = String::from_utf8(row.canonical_payload.clone()).unwrap();
        assert!(!payload.contains("PRIVATE KEY"));
    }
}

#[test]
fn a_withheld_turn_leaves_a_hole_in_the_ordinals_rather_than_renumbering() {
    // Renumbering around a withheld turn would make the next collection of the
    // same source mint different identities for the same turns.
    let (batch, _) = collect(&secret_transcript(SESSION), None);
    let ordinals: Vec<u32> = batch.rows.iter().map(|row| row.turn_ordinal).collect();
    assert_eq!(ordinals, vec![0, 2, 3]);
    assert_eq!(batch.cursor.next_ordinal, 4);
}

#[test]
fn a_turn_whose_secret_can_be_redacted_is_staged_with_the_placeholder() {
    // A redactable secret in the middle of otherwise useful prose: the turn is
    // kept, the secret is not.
    let transcript = format!(
        "{}\n",
        line(
            "user",
            SESSION,
            "turn-1",
            "2026-08-15T12:30:00.000Z",
            "set PGPASSWORD=hunter22 before running the migration"
        )
    );
    let (batch, stats) = collect(&transcript, None);
    assert_eq!(stats.turns_staged, 1);
    assert_eq!(stats.turns_withheld, 0);
    assert_eq!(stats.turns_redacted, 1);
    assert_eq!(
        stats.classes_detected,
        vec![SecretClassV1::PasswordAssignment]
    );
    let payload = String::from_utf8(batch.rows[0].canonical_payload.clone()).unwrap();
    assert!(!payload.contains("hunter22"));
    assert!(payload.contains("[REDACTED]"));
    assert!(payload.contains("before running the migration"));
}

#[test]
fn the_row_identity_is_the_digest_of_the_candidate_bytes() {
    let (batch, _) = collect(&clean_transcript(SESSION), None);
    for row in &batch.rows {
        assert_eq!(
            row.outbox_id,
            super::super::test_fixture::sha256(&row.canonical_candidate)
        );
    }
}

#[test]
fn re_collecting_the_same_bytes_produces_byte_identical_rows() {
    // The idempotency the outbox primary key depends on.
    let (first, _) = collect(&clean_transcript(SESSION), None);
    let (second, _) = collect(&clean_transcript(SESSION), None);
    assert_eq!(first.rows, second.rows);
    assert_eq!(first.cursor, second.cursor);
}

#[test]
fn resuming_from_a_cursor_stages_only_the_new_turns() {
    let first_line = line(
        "user",
        SESSION,
        "turn-1",
        "2026-08-15T12:30:00.000Z",
        "the first turn",
    );
    let second_line = line(
        "assistant",
        SESSION,
        "turn-2",
        "2026-08-15T12:30:01.000Z",
        "the second turn",
    );
    let head = format!("{first_line}\n");
    let full = format!("{first_line}\n{second_line}\n");

    let (first_batch, _) = collect(&head, None);
    assert_eq!(first_batch.rows.len(), 1);

    let (second_batch, stats) = collect(&full, Some(&first_batch.cursor));
    assert_eq!(second_batch.rows.len(), 1);
    assert_eq!(stats.turns_parsed, 1);
    assert_eq!(second_batch.rows[0].turn_ordinal, 1);
    assert_eq!(second_batch.cursor.batch_seq, 2);
    assert_eq!(second_batch.cursor.byte_offset, full.len() as u64);
    // The already-collected turn keeps its identity across the resume.
    let (whole, _) = collect(&full, None);
    assert_eq!(whole.rows[0].outbox_id, first_batch.rows[0].outbox_id);
    assert_eq!(whole.rows[1].outbox_id, second_batch.rows[0].outbox_id);
}

#[test]
fn a_malformed_line_stages_nothing_and_advances_nothing() {
    let transcript = format!(
        "{}\nnot json\n",
        line(
            "user",
            SESSION,
            "turn-1",
            "2026-08-15T12:30:00.000Z",
            "the first turn"
        )
    );
    let active = active_package();
    let error = collect_batch(&TranscriptCollectionRequestV1 {
        active: &active,
        binding: &binding(),
        guarantee: &guarantee(),
        parser_key: &transcript_parser_key_v1(),
        source_id: "session.jsonl",
        bytes: transcript.as_bytes(),
        cursor: None,
        clocks: &clocks(),
    })
    .unwrap_err();
    assert!(matches!(
        error,
        TranscriptConnectorError::MalformedTranscript { .. }
    ));
}

#[test]
fn an_empty_transcript_produces_an_empty_batch_at_the_zero_cursor() {
    let (batch, stats) = collect("", None);
    assert!(batch.rows.is_empty());
    assert_eq!(batch.cursor.byte_offset, 0);
    assert_eq!(batch.cursor.next_ordinal, 0);
    assert_eq!(stats.turns_parsed, 0);
}

#[test]
fn the_cursor_source_digest_covers_exactly_the_consumed_bytes() {
    let transcript = clean_transcript(SESSION);
    let (batch, _) = collect(&transcript, None);
    let consumed = usize::try_from(batch.cursor.byte_offset).unwrap();
    assert_eq!(
        batch.cursor.source_digest,
        super::super::test_fixture::sha256(&transcript.as_bytes()[..consumed])
    );
}
