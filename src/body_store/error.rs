//! Typed failure taxonomy for the content-addressed body projection (W2-BODY).
//!
//! Every variant is a *closed* rejection: the per-event projection transaction
//! writes nothing (or is rolled back) before the error is returned, and the
//! projector cursor is never advanced for a rejected event. A rejection is
//! never downgraded into a silently skipped row or a best-effort partial write.

use crate::FleetError;
use crate::memory_contracts::ContractError;
use crate::memory_contracts::chunk_identity::ChunkIntegrityCollisionV1;

/// Closed failure taxonomy of the body-projection seam.
#[derive(Debug, thiserror::Error)]
pub enum BodyProjectionError {
    /// A memory contract refused the accepted statement, a derived preimage, or
    /// a generation-pointer switch.
    #[error("body projection contract rejected the event: {0}")]
    Contract(#[from] ContractError),
    /// The accepted evidence event's canonical resource identity is not a
    /// version-form URI, so it names no immutable source-object version to
    /// chunk. Fail closed rather than mint occurrences against an entity or
    /// occurrence URI.
    #[error("accepted evidence names a non-versioned source resource: {0}")]
    NonVersionedSource(String),
    /// The bytes the source-content resolver returned do not reproduce the
    /// governed content digest the accepted evidence attests. Fail closed: a
    /// body must never be derived from bytes the evidence did not commit to.
    #[error("resolved source bytes do not match the attested content digest")]
    SourceIntegrityMismatch,
    /// No source bytes are available for an accepted evidence event. The
    /// projector cannot fabricate content, so it fails closed and leaves the
    /// cursor unadvanced for retry once the content plane catches up.
    #[error("no source content available for the accepted evidence event")]
    MissingSourceContent,
    /// The parser produced no chunk for a source, so no parse-run manifest can
    /// be minted (a manifest must cite at least one occurrence). Fail closed.
    #[error("parser produced no chunk occurrences for the source")]
    EmptyParse,
    /// A content-addressed identity was presented over bytes that do not match
    /// the bytes already durably stored under that identity: a genuine
    /// integrity collision ([`ChunkIntegrityCollisionV1`]). Fail closed, write
    /// no row.
    #[error("content-addressed integrity collision: {0:?}")]
    IntegrityCollision(ChunkIntegrityCollisionV1),
    /// A stored occurrence or manifest row carries a different canonical
    /// preimage than the one just derived for the same content-addressed id.
    #[error("stored {kind} preimage collides with the derived preimage")]
    PreimageCollision {
        /// Which content-addressed record collided ("occurrence" / "manifest").
        kind: &'static str,
    },
    /// The generation-pointer compare-and-swap observed a current pointer other
    /// than the one the shadow-generation switch was proposed against
    /// (a concurrent projector already advanced it). Fail closed, retryable.
    #[error("generation pointer moved under the projection compare-and-swap")]
    StaleGenerationPointer,
    /// A stored row contradicts the schema contract this projector relies on.
    /// A tamper or corruption signal, never a caller error.
    #[error("body projection integrity failure: {0}")]
    LedgerIntegrity(String),
    /// Underlying storage, pool, or transaction failure.
    #[error("body projection storage failure: {0}")]
    Storage(#[from] FleetError),
}

impl From<sqlx::Error> for BodyProjectionError {
    fn from(error: sqlx::Error) -> Self {
        Self::Storage(FleetError::Database(error))
    }
}

impl From<BodyProjectionError> for FleetError {
    /// Collapse into the application error type at the service boundary.
    ///
    /// `Storage` keeps its original variant so retry classification upstream is
    /// unchanged; every other variant becomes a closed `Memory` failure.
    fn from(error: BodyProjectionError) -> Self {
        match error {
            BodyProjectionError::Storage(inner) => inner,
            other => Self::Memory(other.to_string()),
        }
    }
}

/// Result alias for the body-projection seam.
pub type BodyProjectionResult<T> = std::result::Result<T, BodyProjectionError>;
