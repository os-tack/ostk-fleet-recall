//! Pure unit tests for the `CockroachDB` adapter's decode and fold helpers.
//! Connected behavior is proven in `tests/discrepancy_ledger_live.rs`.

use super::super::testbed::{acknowledge_event, digest, envelope, resolve_event};
use super::*;
use crate::memory_contracts::canonical::encode_canonical;
use crate::memory_contracts::discrepancy::LifecycleState;

fn entry(seq: u64, record: DiscrepancyLogRecordV1) -> DiscrepancyLogEntryV1 {
    DiscrepancyLogEntryV1 {
        seq,
        record_id: digest(&"1".repeat(64)),
        record,
    }
}

#[test]
fn split_log_requires_an_envelope_seed() {
    assert!(split_log(&[]).is_err());

    let sample = envelope();
    let event = acknowledge_event(&sample, "2026-08-15T05:00:00.000000000Z");
    // Sequence 1 is a lifecycle record: corruption, fails closed.
    let malformed = [entry(1, DiscrepancyLogRecordV1::Lifecycle { event })];
    assert!(split_log(&malformed).is_err());
}

#[test]
fn split_log_rejects_a_second_envelope_record() {
    let sample = envelope();
    let log = [
        entry(
            1,
            DiscrepancyLogRecordV1::Envelope {
                envelope: sample.clone(),
            },
        ),
        entry(2, DiscrepancyLogRecordV1::Envelope { envelope: sample }),
    ];
    assert!(split_log(&log).is_err());
}

#[test]
fn split_log_returns_the_envelope_and_events_in_order() {
    let sample = envelope();
    let ack = acknowledge_event(&sample, "2026-08-15T05:00:00.000000000Z");
    let resolve = resolve_event(&sample, "2026-08-15T06:00:00.000000000Z");
    let log = [
        entry(
            1,
            DiscrepancyLogRecordV1::Envelope {
                envelope: sample.clone(),
            },
        ),
        entry(2, DiscrepancyLogRecordV1::Lifecycle { event: ack.clone() }),
        entry(
            3,
            DiscrepancyLogRecordV1::Lifecycle {
                event: resolve.clone(),
            },
        ),
    ];
    let (decoded_envelope, events) = split_log(&log).unwrap();
    assert_eq!(decoded_envelope, sample);
    assert_eq!(events, vec![ack, resolve]);
}

#[test]
fn derive_stored_projection_denormalises_the_fold() {
    let sample = envelope();
    let resolve = resolve_event(&sample, "2026-08-15T06:00:00.000000000Z");
    let stored = derive_stored_projection(&sample, &[resolve], &[], 2).unwrap();
    assert_eq!(stored.episode_fingerprint, sample.episode_fingerprint);
    assert_eq!(stored.cursor_seq, 2);
    assert_eq!(stored.lifecycle_state, LifecycleState::Resolved);
    assert_eq!(
        stored.evaluated_at.as_str(),
        "2026-08-15T06:00:00.000000000Z"
    );
    assert!(!stored.canonical_projection.is_empty());
    // Deterministic: the same log folds to the same bytes.
    let again = derive_stored_projection(&sample, &[resolve_event(&sample, "2026-08-15T06:00:00.000000000Z")], &[], 2)
        .unwrap();
    assert_eq!(again.canonical_projection, stored.canonical_projection);
}

#[test]
fn decode_relation_rows_fails_closed_on_non_canonical_bytes() {
    assert!(decode_relation_rows(&[b"{not json".to_vec()]).is_err());
}

#[test]
fn encode_log_record_matches_encode_canonical() {
    let sample = envelope();
    let record = DiscrepancyLogRecordV1::Envelope { envelope: sample };
    assert_eq!(
        encode_log_record(&record).unwrap(),
        encode_canonical(&record).unwrap()
    );
}

#[test]
fn stored_digest_and_sequence_decoding_fail_closed() {
    assert!(digest_from(&[0_u8; 16]).is_err());
    assert!(digest_from(&[0_u8; 33]).is_err());
    assert!(digest_from(&[0_u8; 32]).is_ok());
    assert!(seq_from_i64(-1).is_err());
    assert_eq!(seq_from_i64(7).unwrap(), 7);
    assert_eq!(seq_as_i64(7).unwrap(), 7);
    assert!(seq_as_i64(u64::MAX).is_err());
}

#[test]
fn family_from_bytes_round_trips() {
    let sample = envelope();
    let bytes = sample.family_fingerprint.digest().as_bytes().to_vec();
    assert_eq!(
        family_from_bytes(&bytes).unwrap(),
        sample.family_fingerprint
    );
}
