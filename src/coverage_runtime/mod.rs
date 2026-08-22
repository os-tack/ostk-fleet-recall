//! Coverage runtime: per-connector-instance cursors and coverage receipts
//! (W2-COVER-RT, COVER-01..03).
//!
//! This module persists, per connector instance and coverage domain, a durable
//! cursor — the merged [`observed_range::ObservedRangeV1`] of everything the
//! connector has observed — and, each time an observation extends that range, a
//! coverage receipt row built on the coverage contract
//! ([`crate::memory_contracts::coverage`]). The cursor advance and its receipt
//! row are written in ONE serializable transaction, the same atomic-cursor
//! discipline [`crate::relation_projection`] uses for its projection and
//! watermark (EVENT-03, REPLAY-02): a crash leaves neither. Re-observing an
//! already-covered range is idempotent — no duplicate receipt, no cursor
//! regression.
//!
//! # Layout
//!
//! * [`observed_range`] — pure interval algebra: the merged union of observed
//!   intervals, and the completeness (`complete`/`partial`/`unknown`) and
//!   sequence-continuity verdicts derived from it against a target range. No
//!   I/O; exhaustively unit-tested, including every fail-closed path.
//! * [`repository`] — the [`repository::CoverageRuntimeRepository`] trait, the
//!   observation input, the outcome enum, and the persisted row shapes, plus
//!   the pure receipt builder.
//! * [`cockroach`] — the `CockroachDB` implementation over migration 0020's
//!   `memory_coverage_cursors_v1` and `memory_coverage_receipts_v1`.
//!
//! # Invariants this module enforces
//!
//! * **COVER-01/02** — a coverage receipt records `complete` only when the
//!   target range is wholly observed as one contiguous run; a hole surfaces as
//!   `partial`, an unobserved region as `unknown`. Completeness is derived from
//!   the observed range, never from a caller-supplied field, and the coverage
//!   contract's own [`crate::memory_contracts::coverage::CoverageReceiptV1::validate`]
//!   runs before any row is written.
//! * **COVER-03 / PRED-03** — completeness and sequence continuity are separate
//!   witnesses; there is no default arm and no path that upgrades
//!   `partial`/`unknown` to `complete`. A zero `source_digest` or `evidence_id`
//!   is rejected closed.
//! * **EVENT-03** — the receipt row and the cursor advance commit in one
//!   serializable transaction; a failure of either rolls the whole observation
//!   back (nothing written).

mod cockroach;
mod observed_range;
mod repository;

pub use cockroach::{CockroachCoverageRuntimeRepository, CoverageFaultInjection};
pub use observed_range::{InsertOutcome, ObservedRangeError, ObservedRangeV1, SequenceIntervalV1};
pub use repository::{
    COVERAGE_RECEIPT_SCHEMA_VERSION, CoverageCursorRowV1, CoverageObservationOutcome,
    CoverageObservationV1, CoverageReceiptRowV1, CoverageRuntimeRepository,
};
