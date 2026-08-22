//! Closed failure taxonomy of the transcript connector (W2-TRANS).
//!
//! Every variant is a refusal, never a downgrade: a batch that fails to parse,
//! to redact, or to canonicalize stages NOTHING and advances NO cursor, and a
//! drain that fails admission or append leaves its outbox row pending for a
//! later retry. There is no "best effort" path anywhere in this module.

use crate::FleetError;
use crate::evidence_ledger::{EvidenceAdmissionError, EvidenceAppendError};
use crate::memory_contracts::ContractError;

use super::redactor::SecretClassV1;

/// Closed rejection taxonomy of the transcript connector.
#[derive(Debug, thiserror::Error)]
pub enum TranscriptConnectorError {
    /// A memory contract refused an input or a derived value.
    #[error("transcript connector contract failure: {0}")]
    Contract(#[from] ContractError),
    /// A transcript line could not be parsed as a transcript record, or the
    /// source disagrees with the durable cursor. The whole batch is refused.
    #[error("transcript {source_id} line {line_ordinal} is malformed: {reason}")]
    MalformedTranscript {
        /// The transcript source that failed.
        source_id: String,
        /// One-based line ordinal within that source.
        line_ordinal: u32,
        /// Why the line was refused.
        reason: &'static str,
    },
    /// The active package's redaction policy does not promise redaction before
    /// the durable outbox, so no batch may be staged at all (EVID-05).
    #[error("the active package does not guarantee redaction before the durable outbox")]
    RedactionPolicyNotGuaranteed,
    /// A turn was withheld because secret-shaped content survived redaction.
    /// Recorded so a withheld turn is a visible, counted outcome rather than a
    /// silent drop.
    #[error("turn withheld: residual {} content survived redaction", .class.as_str())]
    SecretWithheld {
        /// The residual class that forced the refusal.
        class: SecretClassV1,
    },
    /// An identity recipe in the active package names a locator coordinate the
    /// connector binding does not supply. Fail closed rather than invent one.
    #[error("connector binding supplies no value for locator coordinate {key}")]
    MissingLocatorCoordinate {
        /// The coordinate key the activated recipe requires.
        key: String,
    },
    /// A published source-fact byte field is required at an encoding other than
    /// `hex_bytes`, which would make the URI preimage disagree with the
    /// published fact.
    #[error("locator coordinate {key} is required at a non-byte encoding")]
    UnsupportedCoordinateEncoding {
        /// The coordinate key whose declared encoding is unusable.
        key: String,
    },
    /// The three ingress clocks are not ordered occurred <= observed <= received
    /// (EVID-03). Refused before anything is staged.
    #[error("transcript ingress clocks are not ordered occurred <= observed <= received")]
    ClockOrder,
    /// A durable cursor moved backwards, or a batch was built against a stale
    /// cursor. Fail closed: a regressed cursor would re-mint turn ordinals.
    #[error("transcript cursor for {source_id} regressed or was stale")]
    CursorRegression {
        /// The transcript source whose cursor disagreed.
        source_id: String,
    },
    /// Evidence admission refused the candidate (the connector is not in the
    /// active package, scope does not match, an identity did not rederive, …).
    #[error("transcript evidence admission refused the candidate: {0}")]
    Admission(#[from] EvidenceAdmissionError),
    /// The accepted-event append refused the admitted statement.
    #[error("transcript accepted-event append failed: {0}")]
    Append(#[from] EvidenceAppendError),
    /// The ledger dead-lettered a staged candidate. No event row, no head
    /// advance, no projection — so the outbox row stays pending and no coverage
    /// receipt is emitted. Surfaced rather than counted so a quarantined turn
    /// can never look like covered ground.
    #[error("staged transcript candidate was quarantined by the ledger: {reason:?}")]
    Quarantined {
        /// The staged row the ledger refused.
        outbox_id: crate::memory_contracts::digest::Sha256Digest,
        /// Deterministic identity of the quarantine record.
        quarantine_id: crate::memory_contracts::quarantine::QuarantineRecordId,
        /// Closed rejection cause.
        reason: crate::memory_contracts::quarantine::QuarantineReasonV1,
    },
    /// A stored row contradicts the schema contract this connector relies on.
    /// A tamper or corruption signal, never a caller error.
    #[error("transcript connector integrity failure: {0}")]
    LedgerIntegrity(String),
    /// Underlying storage, pool, or transaction failure.
    #[error("transcript connector storage failure: {0}")]
    Storage(#[from] FleetError),
}

impl From<sqlx::Error> for TranscriptConnectorError {
    fn from(error: sqlx::Error) -> Self {
        Self::Storage(FleetError::Database(error))
    }
}

impl From<TranscriptConnectorError> for FleetError {
    /// Collapse into the application error type at the service boundary.
    ///
    /// `Storage` keeps its original variant so retry classification upstream is
    /// unchanged; every other variant becomes a closed `Memory` failure.
    fn from(error: TranscriptConnectorError) -> Self {
        match error {
            TranscriptConnectorError::Storage(inner) => inner,
            other => Self::Memory(other.to_string()),
        }
    }
}

/// Result alias for the transcript connector.
pub type TranscriptConnectorResult<T> = std::result::Result<T, TranscriptConnectorError>;
