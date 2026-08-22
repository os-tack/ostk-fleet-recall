//! Local transcript collector — the first real connector (W2-TRANS).
//!
//! It reads local agent-transcript JSONL (Claude session files: one JSON object
//! per line), turns each conversational turn into an
//! [`crate::memory_contracts::evidence_v2::EvidenceIngressCandidateV2`] under the
//! ACTIVE package's connector schema, stages it in a durable outbox, and drains
//! that outbox into accepted evidence events through the W1-EVID admission seam.
//!
//! ```text
//! transcript JSONL
//!   -> parser        bespoke line parser; the parser key is part of identity
//!   -> redactor      REDACT + classify, BEFORE anything durable exists
//!   -> canonicalizer candidate + locators, derived from the ACTIVE package
//!   -> outbox        rows + per-source cursor, advanced in ONE transaction
//!   -> drain         admit_evidence -> AcceptedEventRepository::append
//!                    (+ governed content, + outbox state, same transaction)
//!   -> coverage      a COVER-01 receipt per drained turn
//! ```
//!
//! # The security boundary: redact before the outbox
//!
//! This is the property the whole module is arranged around. Secret-shaped
//! content must never reach an outbox row, an accepted event, the governed
//! content store, or any projection built from them. Three structural facts make
//! that so, rather than one remembered call:
//!
//! 1. [`collector::collect_batch`] is the ONLY way to build a
//!    [`outbox::TranscriptBatchV1`], and it requires a
//!    [`redactor::RedactionGuaranteeV1`], which exists only if the ACTIVE
//!    package's redaction policy declares `redact_before_durable_outbox` and
//!    forbids secrets in recall (EVID-05).
//! 2. [`canonicalizer::canonicalize_turn`] takes the redacted text as a separate
//!    argument and never reads [`parser::ParsedTurnV1::text`], so no candidate
//!    can be built from raw material.
//! 3. A turn whose post-redaction re-scan still matches a secret shape is
//!    WITHHELD: no row is constructed for it at all, so there is nothing for a
//!    later stage to leak (PRED-03).
//!
//! # Invariants enforced
//!
//! * **EVID-05 / PRED-03** — redaction runs before the durable outbox, the
//!   activated policy is what authorizes staging, and a residual detection is a
//!   closed refusal rather than a partial write.
//! * **EVID-04** — every candidate's scope is `active.scope()`, taken from the
//!   credential-bound witness; no argument can select a different one, and the
//!   admission seam rejects a mismatch before any work.
//! * **AUTH-04 / EVID-02** — the connector schema, both identity recipes, and
//!   every locator shape come from the ACTIVE package. A connector that is not
//!   in the active package is refused by
//!   [`crate::evidence_ledger::admit_evidence`] with nothing written.
//! * **EVENT-03 / REPLAY-02** — outbox rows commit with their source cursor in
//!   one serializable transaction, and an accepted event commits with its
//!   governed content object and its outbox state change in one more. A crash in
//!   either leaves nothing partial.
//! * **EVENT-01** — a re-drain re-derives byte-identical accepted events, so the
//!   ledger classifies them `Replayed` and no projection runs twice.
//! * **COVER-01..03** — every drained turn emits a coverage receipt through the
//!   W2-COVER-RT cursor/receipt tables, bound to the accepted event the append
//!   just made durable.

mod canonicalizer;
mod cockroach;
mod collector;
mod drain;
mod error;
mod outbox;
mod parser;
mod redactor;
#[cfg(test)]
mod test_fixture;

pub use canonicalizer::{
    CanonicalizedTurnV1, TRANSCRIPT_SCHEMA_VERSION, TranscriptConnectorBindingV1,
    TranscriptTurnBodyV1, TranscriptTurnRevisionPreimageV1, canonicalize_turn, role_label,
};
pub use cockroach::CockroachTranscriptOutboxRepository;
pub use collector::{
    TranscriptCollectionRequestV1, TranscriptCollectionStatsV1, TranscriptIngressClocksV1,
    collect_batch,
};
pub use drain::{
    TranscriptCoverageBindingV1, TranscriptDrainModeV1, TranscriptDrainRequest,
    TranscriptDrainSummaryV1, drain_outbox,
};
pub use error::{TranscriptConnectorError, TranscriptConnectorResult};
pub use outbox::{
    TranscriptBatchV1, TranscriptCursorRowV1, TranscriptEnqueueOutcome, TranscriptFaultInjection,
    TranscriptOutboxRepository, TranscriptOutboxRowV1, TranscriptOutboxStateV1,
};
pub use parser::{
    MAX_TRANSCRIPT_BYTES, MAX_TURNS_PER_BATCH, ParsedTranscriptV1, ParsedTurnV1,
    TRANSCRIPT_PARSER_VERSION, TranscriptRoleV1, parse_transcript, transcript_parser_key_v1,
    transcript_parser_key_v2,
};
pub use redactor::{
    REDACTION_PLACEHOLDER, RedactionDispositionV1, RedactionGuaranteeV1, RedactionOutcomeV1,
    SecretClassV1, SecretFindingV1, redact, scan_secrets,
};
