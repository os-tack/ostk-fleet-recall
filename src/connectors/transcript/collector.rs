//! The batch pipeline: bytes on disk to a staged, redacted outbox batch.
//!
//! ```text
//! transcript bytes
//!   -> parse            (bespoke JSONL; fail closed on any malformed line)
//!   -> REDACT + classify (before ANY durable value exists)
//!   -> canonicalize     (identity from the ACTIVE package only)
//!   -> TranscriptBatchV1 (outbox rows + the cursor that must advance with them)
//! ```
//!
//! [`collect_batch`] is pure: it touches no database and no clock of its own, so
//! the whole redact-before-outbox property is provable as ordinary unit tests.
//! Its output is the ONLY thing [`super::outbox::TranscriptOutboxRepository`]
//! will accept, and the only way to build one is through this function, which
//! requires a [`RedactionGuaranteeV1`]. There is therefore no code path from raw
//! transcript bytes to a durable row that skips redaction.

use sha2::{Digest as _, Sha256};

use crate::evidence_ledger::ActiveStage4Package;
use crate::memory_contracts::canonical::encode_canonical;
use crate::memory_contracts::chunk_identity::ParserKeyV1;
use crate::memory_contracts::common::CanonicalTimestamp;
use crate::memory_contracts::digest::Sha256Digest;

use super::canonicalizer::{TranscriptConnectorBindingV1, canonicalize_turn};
use super::error::TranscriptConnectorResult;
use super::outbox::{
    TranscriptBatchV1, TranscriptCursorRowV1, TranscriptOutboxRowV1, TranscriptOutboxStateV1,
};
use super::parser::parse_transcript;
use super::redactor::{RedactionGuaranteeV1, SecretClassV1};

/// The ingress clocks one batch is stamped with.
///
/// Both are read once, from the caller's trusted clock (in production, the
/// database's `statement_timestamp()`), never from the transcript.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranscriptIngressClocksV1 {
    /// When the collector observed the source.
    pub observed_at: CanonicalTimestamp,
    /// When ingress received the batch.
    pub received_at: CanonicalTimestamp,
}

/// What one collection pass produced, alongside the batch.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TranscriptCollectionStatsV1 {
    /// Turns parsed from the source.
    pub turns_parsed: u32,
    /// Turns staged into the batch.
    pub turns_staged: u32,
    /// Turns withheld because secret-shaped content survived redaction.
    pub turns_withheld: u32,
    /// Turns whose body was redacted before staging.
    pub turns_redacted: u32,
    /// Records that carried no turn.
    pub records_skipped: u32,
    /// Distinct secret classes detected in this pass (metadata only; never the
    /// matched bytes).
    pub classes_detected: Vec<SecretClassV1>,
}

/// Everything one collection pass needs.
///
/// Bundled rather than passed as loose arguments so adding an input is a
/// visible, reviewable change to a named contract — and so the
/// [`RedactionGuaranteeV1`] is a *required field*, not an argument a future
/// caller could forget.
pub struct TranscriptCollectionRequestV1<'request> {
    /// The active package every identity is derived from.
    pub active: &'request ActiveStage4Package,
    /// Trusted, ingress-side connector binding.
    pub binding: &'request TranscriptConnectorBindingV1,
    /// Proof the active package promises redaction before the durable outbox.
    pub guarantee: &'request RedactionGuaranteeV1,
    /// The parser whose identity becomes part of every turn's revision.
    pub parser_key: &'request ParserKeyV1,
    /// Stable identifier of the transcript source.
    pub source_id: &'request str,
    /// The source bytes read this pass.
    pub bytes: &'request [u8],
    /// The durable cursor for this source, or `None` for a first read.
    pub cursor: Option<&'request TranscriptCursorRowV1>,
    /// The ingress clocks this batch is stamped with.
    pub clocks: &'request TranscriptIngressClocksV1,
}

/// Parse, redact, classify, and canonicalize one transcript source into a batch.
///
/// The returned batch carries the NEW cursor: the repository writes the rows and
/// that cursor in one transaction, so a crash leaves both unadvanced.
pub fn collect_batch(
    request: &TranscriptCollectionRequestV1<'_>,
) -> TranscriptConnectorResult<(TranscriptBatchV1, TranscriptCollectionStatsV1)> {
    let TranscriptCollectionRequestV1 {
        active,
        binding,
        guarantee,
        parser_key,
        source_id,
        bytes,
        cursor,
        clocks,
    } = request;
    let resume_from = cursor.map_or(0, |row| row.byte_offset);
    let first_ordinal = cursor.map_or(0, |row| row.next_ordinal);
    let batch_seq = cursor.map_or(0, |row| row.batch_seq).saturating_add(1);

    let parsed = parse_transcript(source_id, bytes, resume_from, first_ordinal)?;
    let mut stats = TranscriptCollectionStatsV1 {
        turns_parsed: u32::try_from(parsed.turns.len()).unwrap_or(u32::MAX),
        records_skipped: parsed.skipped_records,
        ..TranscriptCollectionStatsV1::default()
    };

    let mut rows = Vec::with_capacity(parsed.turns.len());
    let mut next_ordinal = first_ordinal;
    for turn in &parsed.turns {
        next_ordinal = turn.ordinal.saturating_add(1);
        let outcome = guarantee.apply(&turn.text);
        for class in &outcome.classes {
            if !stats.classes_detected.contains(class) {
                stats.classes_detected.push(*class);
            }
        }
        let Some(redacted) = outcome.staged_text() else {
            // Withheld: no row, no payload, no digest of the raw text — the
            // secret-shaped turn simply does not become durable anywhere.
            stats.turns_withheld = stats.turns_withheld.saturating_add(1);
            continue;
        };
        if outcome.redacted_ranges > 0 {
            stats.turns_redacted = stats.turns_redacted.saturating_add(1);
        }

        let canonicalized = canonicalize_turn(
            active,
            binding,
            parser_key,
            turn,
            redacted,
            &clocks.observed_at,
            &clocks.received_at,
        )?;
        let canonical_candidate = encode_canonical(&canonicalized.candidate)?;
        let canonical_locators = encode_canonical(&canonicalized.locators)?;
        // The outbox row's identity is the digest of the exact candidate bytes,
        // so re-staging the same turn is an idempotent primary-key conflict
        // rather than a duplicate row.
        let outbox_id = Sha256Digest::from_bytes(Sha256::digest(&canonical_candidate).into());
        rows.push(TranscriptOutboxRowV1 {
            outbox_id,
            source_id: (*source_id).to_owned(),
            session_id: canonicalized.session_id,
            turn_ordinal: canonicalized.ordinal,
            canonical_candidate,
            canonical_locators,
            canonical_payload: canonicalized.canonical_payload,
            state: TranscriptOutboxStateV1::Pending,
            batch_seq,
        });
        stats.turns_staged = stats.turns_staged.saturating_add(1);
    }

    stats.classes_detected.sort_unstable();
    stats.classes_detected.dedup();

    let batch = TranscriptBatchV1 {
        rows,
        cursor: TranscriptCursorRowV1 {
            source_id: (*source_id).to_owned(),
            byte_offset: parsed.consumed_bytes,
            line_ordinal: parsed.consumed_lines,
            next_ordinal,
            batch_seq,
            source_digest: parsed.source_digest,
        },
        withheld: stats.turns_withheld,
    };
    Ok((batch, stats))
}

#[cfg(test)]
#[path = "collector_tests.rs"]
mod tests;
