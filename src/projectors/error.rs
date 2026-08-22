//! Typed failure taxonomy for the recall projectors (W2-PROJ).
//!
//! Every variant is a *closed* rejection: the batch transaction that hit it
//! writes nothing (it is rolled back) and the projector's own cursor is never
//! advanced past the body that caused it. A rejection is never downgraded into
//! a silently skipped body or a best-effort partial write.
//!
//! The two tiers have SEPARATE errors for a reason. A dense failure — a model
//! that returns the wrong dimension, a non-finite component, a degenerate
//! zero vector, a provider outage — is raised by the dense worker alone. It
//! cannot reach the lexical tier's rows, its cursor, or its availability,
//! because the two tiers write disjoint tables and disjoint cursor rows.

use crate::FleetError;
use crate::memory_contracts::ContractError;

/// Closed failure taxonomy of the recall-projection seam.
#[derive(Debug, thiserror::Error)]
pub enum RecallProjectionError {
    /// A memory contract refused a derived preimage (for example an embedding
    /// identity whose model digest is zero or whose dimension is out of range).
    #[error("recall projection contract rejected the derivation: {0}")]
    Contract(#[from] ContractError),
    /// The bytes stored under a body's content address do not reproduce that
    /// address. Fail closed: a projection must never be derived from bytes the
    /// body plane did not commit to.
    #[error("stored body bytes do not match their content address")]
    BodyIntegrityMismatch,
    /// A stored lexical row carries a different normalized text digest than the
    /// one just re-derived for the same body content address. Either the stored
    /// row or the normalizer changed under a fixed normalization version; fail
    /// closed rather than overwrite.
    #[error("stored lexical projection digest collides with the derived digest")]
    LexicalDigestCollision,
    /// A stored dense row carries a different embedding identity than the one
    /// just derived for the same body under the same model descriptor.
    #[error("stored dense projection identity collides with the derived identity")]
    EmbeddingIdentityCollision,
    /// The embedding provider returned a vector whose length is not the
    /// descriptor's declared dimension.
    #[error("embedding provider returned {actual} components, expected {expected}")]
    EmbeddingDimensionMismatch {
        /// Dimension the model descriptor declares.
        expected: u32,
        /// Dimension the provider actually returned.
        actual: usize,
    },
    /// The embedding provider returned a `NaN` or infinite component. Such a
    /// vector poisons every distance comparison it participates in, so it is
    /// refused before it can reach the ANN index.
    #[error("embedding provider returned a non-finite component at index {index}")]
    NonFiniteEmbedding {
        /// Position of the first offending component.
        index: usize,
    },
    /// The embedding provider returned the zero vector under a cosine metric,
    /// for which cosine distance is undefined. Fail closed.
    #[error("embedding provider returned a degenerate zero vector under cosine distance")]
    DegenerateEmbedding,
    /// The embedding provider itself failed (outage, timeout, refusal). This is
    /// the ordinary "dense is behind" condition: the dense cursor stays where
    /// the last committed batch left it and the lexical tier is untouched.
    #[error("embedding provider failed: {0}")]
    EmbeddingProvider(String),
    /// A stored row contradicts the schema contract this projector relies on.
    /// A tamper or corruption signal, never a caller error.
    #[error("recall projection integrity failure: {0}")]
    ProjectionIntegrity(String),
    /// A recall request carried an out-of-range limit or a query vector whose
    /// dimension does not match the projection's.
    #[error("invalid recall request: {0}")]
    InvalidRequest(String),
    /// Underlying storage, pool, or transaction failure.
    #[error("recall projection storage failure: {0}")]
    Storage(#[from] FleetError),
}

impl From<sqlx::Error> for RecallProjectionError {
    fn from(error: sqlx::Error) -> Self {
        Self::Storage(FleetError::Database(error))
    }
}

impl From<RecallProjectionError> for FleetError {
    /// Collapse into the application error type at the service boundary.
    ///
    /// `Storage` keeps its original variant so retry classification upstream is
    /// unchanged; every other variant becomes a closed `Memory` failure.
    fn from(error: RecallProjectionError) -> Self {
        match error {
            RecallProjectionError::Storage(inner) => inner,
            other => Self::Memory(other.to_string()),
        }
    }
}

/// Result alias for the recall-projection seam.
pub type RecallProjectionResult<T> = std::result::Result<T, RecallProjectionError>;
