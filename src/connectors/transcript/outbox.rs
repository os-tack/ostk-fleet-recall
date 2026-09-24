//! Durable outbox and per-source cursor for the transcript connector.
//!
//! The outbox exists so the two halves of ingestion can fail independently
//! without losing or duplicating a turn: collection stages canonical candidates
//! and advances the source cursor in ONE serializable transaction, and the drain
//! loop turns those staged candidates into accepted events later, at its own
//! pace, through the W1-EVID admission seam.
//!
//! # The atomic pair
//!
//! [`TranscriptOutboxRepository::enqueue_batch`] writes every row of a
//! [`TranscriptBatchV1`] AND the batch's [`TranscriptCursorRowV1`] in one
//! transaction. A crash anywhere in that transaction leaves BOTH unadvanced, so
//! re-collecting the same source re-reads the same bytes and re-derives the same
//! rows — which the row identity then absorbs as an idempotent conflict. This is
//! the same discipline the coverage runtime uses for its cursor and receipt
//! (EVENT-03, REPLAY-02).
//!
//! # Row identity
//!
//! `outbox_id` is the SHA-256 of the exact canonical candidate bytes. Two
//! collections of the same turn under the same parser and the same active
//! package produce the same id, so `ON CONFLICT DO NOTHING` makes re-staging a
//! no-op instead of a duplicate. A different parser key changes the candidate's
//! `immutable_revision`, hence the id, hence the row — a new representation
//! rather than an overwrite.

use async_trait::async_trait;

use crate::memory_contracts::digest::Sha256Digest;

use super::error::TranscriptConnectorResult;

/// Whether a staged row has been drained into the ledger yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TranscriptOutboxStateV1 {
    /// Staged, not yet admitted and appended.
    Pending,
    /// Admitted and appended; the accepted event is durable.
    Drained,
}

impl TranscriptOutboxStateV1 {
    /// Stable column value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Drained => "drained",
        }
    }

    /// Parse one stored column value, failing closed on anything else.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "drained" => Some(Self::Drained),
            _ => None,
        }
    }
}

/// One staged transcript turn, ready to be admitted.
///
/// `canonical_payload` is the REDACTED body and nothing else. There is no field
/// on this row that could carry raw transcript text: the collector never
/// constructs one from unredacted input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranscriptOutboxRowV1 {
    /// Digest of the exact canonical candidate bytes; the row's identity.
    pub outbox_id: Sha256Digest,
    /// Transcript source this turn came from.
    pub source_id: String,
    /// Session the turn belongs to.
    pub session_id: String,
    /// Position of the turn within its source.
    pub turn_ordinal: u32,
    /// Canonical bytes of the `EvidenceIngressCandidateV2`.
    pub canonical_candidate: Vec<u8>,
    /// Canonical bytes of the `EvidenceIngressLocatorsV1`.
    pub canonical_locators: Vec<u8>,
    /// Exact canonical redacted payload bytes.
    pub canonical_payload: Vec<u8>,
    /// Whether this row has been drained.
    pub state: TranscriptOutboxStateV1,
    /// Collection batch that staged this row.
    pub batch_seq: u64,
}

/// The durable per-source collection cursor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranscriptCursorRowV1 {
    /// Transcript source this cursor tracks.
    pub source_id: String,
    /// Byte offset one past the last complete line consumed.
    pub byte_offset: u64,
    /// Number of newline-delimited lines consumed.
    pub line_ordinal: u32,
    /// Ordinal the next collected turn of this source will take.
    pub next_ordinal: u32,
    /// How many batches have advanced this cursor.
    pub batch_seq: u64,
    /// Digest of exactly the bytes consumed so far.
    pub source_digest: Sha256Digest,
}

/// Rows plus the cursor that must advance with them, atomically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TranscriptBatchV1 {
    /// The staged rows, in source order.
    pub rows: Vec<TranscriptOutboxRowV1>,
    /// The cursor this batch advances the source to.
    pub cursor: TranscriptCursorRowV1,
    /// How many turns this batch withheld for secret-shaped content. Counted so
    /// a withheld turn is visible in coverage rather than an invisible gap.
    pub withheld: u32,
}

/// What one [`TranscriptOutboxRepository::enqueue_batch`] call did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TranscriptEnqueueOutcome {
    /// The batch advanced the cursor; `rows_written` new rows were inserted.
    Enqueued {
        /// Rows this call actually inserted (re-staged rows do not count).
        rows_written: u64,
        /// The cursor's batch counter after the advance.
        batch_seq: u64,
    },
    /// The cursor already covers this batch's byte range: nothing was written
    /// and the cursor did not move (idempotent re-collection).
    AlreadyCovered {
        /// The cursor's unchanged batch counter.
        batch_seq: u64,
    },
}

/// Where, if anywhere, a batch enqueue is forced to fail.
///
/// Used only by the connected atomicity proof: it makes "a crash between the row
/// insert and the cursor advance leaves both unadvanced" an observable fact
/// rather than a claim about the transaction boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TranscriptFaultInjection {
    /// Run normally.
    None,
    /// Fail AFTER the rows are inserted and the cursor is advanced, but BEFORE
    /// the transaction commits.
    AbortAfterWrites,
}

/// Durable outbox and cursor surface, bound once to physical and semantic scope
/// exactly like [`crate::evidence_ledger::AcceptedEventRepository`].
#[async_trait]
pub trait TranscriptOutboxRepository: Send + Sync {
    /// Stage one batch: every row and the batch's cursor, in ONE serializable
    /// transaction (EVENT-03).
    async fn enqueue_batch(
        &self,
        batch: &TranscriptBatchV1,
    ) -> TranscriptConnectorResult<TranscriptEnqueueOutcome>;

    /// Read the durable cursor for one source, if it exists.
    async fn read_cursor(
        &self,
        source_id: &str,
    ) -> TranscriptConnectorResult<Option<TranscriptCursorRowV1>>;

    /// Read staged rows in `(batch_seq, turn_ordinal, outbox_id)` order.
    ///
    /// `pending_only` selects the production drain; the replay drain reads every
    /// row so a re-drain can be proven idempotent against the ledger itself.
    async fn staged_rows(
        &self,
        pending_only: bool,
        limit: u32,
    ) -> TranscriptConnectorResult<Vec<TranscriptOutboxRowV1>>;

    /// Read ONE source's staged rows, in the same order as
    /// [`Self::staged_rows`].
    ///
    /// A scheduled runner drains each source under its own coverage binding, so
    /// it must never see another source's rows. The default reads every staged
    /// row and filters, which is correct for any implementation but reads the
    /// whole outbox; the `CockroachDB` repository overrides it with a
    /// source-bound statement.
    async fn staged_rows_for_source(
        &self,
        source_id: &str,
        pending_only: bool,
        limit: u32,
    ) -> TranscriptConnectorResult<Vec<TranscriptOutboxRowV1>> {
        let mut rows = self.staged_rows(pending_only, u32::MAX).await?;
        rows.retain(|row| row.source_id == source_id);
        rows.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
        Ok(rows)
    }

    /// The lowest turn ordinal of one source that is still pending, or `None`
    /// when nothing of that source awaits the drain.
    ///
    /// This is where a runner's coverage target for the source starts: every
    /// ordinal below it was drained by an earlier pass.
    async fn pending_ordinal_floor(
        &self,
        source_id: &str,
    ) -> TranscriptConnectorResult<Option<u32>> {
        Ok(self
            .staged_rows_for_source(source_id, true, u32::MAX)
            .await?
            .iter()
            .map(|row| row.turn_ordinal)
            .min())
    }

    /// Mark one row drained. Idempotent, and used only on the replay path: the
    /// production path marks the row inside the append transaction.
    async fn mark_drained(&self, outbox_id: Sha256Digest) -> TranscriptConnectorResult<()>;

    /// Count outbox rows for one source, at any state.
    async fn count_rows(&self, source_id: &str) -> TranscriptConnectorResult<u64>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An in-memory outbox that implements only the required methods, so the
    /// trait defaults are what the assertions exercise.
    struct MemoryOutbox {
        rows: Vec<TranscriptOutboxRowV1>,
    }

    #[async_trait]
    impl TranscriptOutboxRepository for MemoryOutbox {
        async fn enqueue_batch(
            &self,
            batch: &TranscriptBatchV1,
        ) -> TranscriptConnectorResult<TranscriptEnqueueOutcome> {
            Ok(TranscriptEnqueueOutcome::AlreadyCovered {
                batch_seq: batch.cursor.batch_seq,
            })
        }

        async fn read_cursor(
            &self,
            _source_id: &str,
        ) -> TranscriptConnectorResult<Option<TranscriptCursorRowV1>> {
            Ok(None)
        }

        async fn staged_rows(
            &self,
            pending_only: bool,
            limit: u32,
        ) -> TranscriptConnectorResult<Vec<TranscriptOutboxRowV1>> {
            let mut rows: Vec<TranscriptOutboxRowV1> = self
                .rows
                .iter()
                .filter(|row| !pending_only || row.state == TranscriptOutboxStateV1::Pending)
                .cloned()
                .collect();
            rows.sort_by_key(|row| (row.batch_seq, row.turn_ordinal, row.outbox_id));
            rows.truncate(usize::try_from(limit).unwrap());
            Ok(rows)
        }

        async fn mark_drained(&self, _outbox_id: Sha256Digest) -> TranscriptConnectorResult<()> {
            Ok(())
        }

        async fn count_rows(&self, source_id: &str) -> TranscriptConnectorResult<u64> {
            Ok(self
                .rows
                .iter()
                .filter(|row| row.source_id == source_id)
                .count() as u64)
        }
    }

    fn row(
        source_id: &str,
        turn_ordinal: u32,
        batch_seq: u64,
        state: TranscriptOutboxStateV1,
    ) -> TranscriptOutboxRowV1 {
        let id = format!("{source_id}:{turn_ordinal}");
        TranscriptOutboxRowV1 {
            outbox_id: Sha256Digest::from_bytes(
                <sha2::Sha256 as sha2::Digest>::digest(id.as_bytes()).into(),
            ),
            source_id: source_id.to_owned(),
            session_id: "session".to_owned(),
            turn_ordinal,
            canonical_candidate: Vec::new(),
            canonical_locators: Vec::new(),
            canonical_payload: Vec::new(),
            state,
            batch_seq,
        }
    }

    /// Two sources interleaved across batches, with one drained row each.
    fn outbox() -> MemoryOutbox {
        use TranscriptOutboxStateV1::{Drained, Pending};
        MemoryOutbox {
            rows: vec![
                row("a.jsonl", 0, 1, Drained),
                row("b.jsonl", 0, 1, Drained),
                row("a.jsonl", 1, 1, Pending),
                row("b.jsonl", 1, 2, Pending),
                row("a.jsonl", 2, 2, Pending),
                row("b.jsonl", 2, 3, Pending),
            ],
        }
    }

    fn ordinals(rows: &[TranscriptOutboxRowV1]) -> Vec<(String, u32)> {
        rows.iter()
            .map(|row| (row.source_id.clone(), row.turn_ordinal))
            .collect()
    }

    #[tokio::test]
    async fn the_default_source_read_returns_only_that_source_in_drain_order() {
        let outbox = outbox();
        let pending = outbox
            .staged_rows_for_source("a.jsonl", true, 256)
            .await
            .unwrap();
        assert_eq!(
            ordinals(&pending),
            vec![("a.jsonl".to_owned(), 1), ("a.jsonl".to_owned(), 2)]
        );
        let every = outbox
            .staged_rows_for_source("b.jsonl", false, 256)
            .await
            .unwrap();
        assert_eq!(
            ordinals(&every),
            vec![
                ("b.jsonl".to_owned(), 0),
                ("b.jsonl".to_owned(), 1),
                ("b.jsonl".to_owned(), 2)
            ]
        );
        assert!(
            outbox
                .staged_rows_for_source("c.jsonl", false, 256)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn the_default_source_read_applies_its_limit_after_filtering() {
        // Another source's rows sort first, so a limit applied before the filter
        // would return nothing of this source.
        let outbox = outbox();
        let first = outbox
            .staged_rows_for_source("b.jsonl", true, 1)
            .await
            .unwrap();
        assert_eq!(ordinals(&first), vec![("b.jsonl".to_owned(), 1)]);
    }

    #[tokio::test]
    async fn the_default_pending_floor_is_the_lowest_pending_ordinal_of_the_source() {
        let outbox = outbox();
        assert_eq!(
            outbox.pending_ordinal_floor("a.jsonl").await.unwrap(),
            Some(1)
        );
        assert_eq!(
            outbox.pending_ordinal_floor("b.jsonl").await.unwrap(),
            Some(1)
        );
        assert_eq!(outbox.pending_ordinal_floor("c.jsonl").await.unwrap(), None);
        let drained = MemoryOutbox {
            rows: vec![row("a.jsonl", 0, 1, TranscriptOutboxStateV1::Drained)],
        };
        assert_eq!(
            drained.pending_ordinal_floor("a.jsonl").await.unwrap(),
            None
        );
    }
}
