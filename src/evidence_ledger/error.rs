//! Typed failure taxonomy for the general accepted-event append seam.
//!
//! Every variant here is a *closed* rejection: the append transaction writes
//! nothing, or is rolled back, before it is returned. A rejection is never
//! downgraded into a synthesized event, a "last known head" fallback, or a
//! silently skipped projection (ADR 0002 D4, EVENT-03).

use crate::FleetError;
use crate::memory_contracts::ContractError;

/// Exactly which authority field the in-transaction head read disagreed with.
///
/// The witness carries the values the admission stage read; the append
/// transaction re-reads `memory_writer_authority_v1` and compares. Serializable
/// isolation is the fence, so a disagreement means the head genuinely moved (or
/// the witness was never derived from this scope's authority at all).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WitnessMismatchKind {
    /// The exact ABA-safe activation ID differs. Never compared by package
    /// digest: two generations may share a package (ADR 0002 D4).
    ActivationId,
    /// The registry generation differs.
    Generation,
    /// The activated package digest differs.
    PackageDigest,
    /// The activation policy digest differs.
    ActivationPolicyDigest,
    /// The genesis log-epoch ID differs.
    LogEpochId,
    /// The partition recipe ID, version, algorithm, seed, or shard count
    /// differs, so the shard mapping itself is not the one that was witnessed.
    PartitionRecipe,
    /// The contract tenant/project namespaces differ from the witnessed scope.
    ContractNamespaces,
}

impl WitnessMismatchKind {
    /// Stable diagnostic label. Exhaustive over the closed enum.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ActivationId => "activation_id",
            Self::Generation => "generation",
            Self::PackageDigest => "package_digest",
            Self::ActivationPolicyDigest => "activation_policy_digest",
            Self::LogEpochId => "log_epoch_id",
            Self::PartitionRecipe => "partition_recipe",
            Self::ContractNamespaces => "contract_namespaces",
        }
    }
}

impl std::fmt::Display for WitnessMismatchKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Why `memory_writer_authority_v1` could not supply a usable head.
///
/// D4 admits no fallback: zero rows, more than one row, and a non-active head
/// all fail the append closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityUnavailableKind {
    /// The scope has no bootstrap/epoch/head triple yet.
    NoRow,
    /// More than one row, which can only happen if a documented uniqueness key
    /// on bootstraps, epochs, or current heads was violated.
    AmbiguousRow,
    /// A row exists but its `head_state` is not `active`.
    NotActive,
    /// A stored authority column could not be decoded into its contract type.
    UndecodableRow,
}

impl AuthorityUnavailableKind {
    /// Stable diagnostic label. Exhaustive over the closed enum.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoRow => "no active writer authority row",
            Self::AmbiguousRow => "more than one writer authority row",
            Self::NotActive => "writer authority head is not active",
            Self::UndecodableRow => "writer authority row could not be decoded",
        }
    }
}

impl std::fmt::Display for AuthorityUnavailableKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Closed failure taxonomy of the accepted-event append seam.
#[derive(Debug, thiserror::Error)]
pub enum EvidenceAppendError {
    /// A memory contract refused the statement, the derived key, or the chain.
    #[error("accepted-event contract rejected the append: {0}")]
    Contract(#[from] ContractError),
    /// The statement's own head binding is not the witnessed active head, or
    /// its scope is not the witnessed scope (ADR 0002 D4, EVID-04).
    #[error("accepted-event statement is not bound to the witnessed authority: {0}")]
    StatementAuthority(WitnessMismatchKind),
    /// The in-transaction head read disagreed with the witness token.
    #[error("writer authority witness does not match the in-transaction head: {0}")]
    WitnessMismatch(WitnessMismatchKind),
    /// The authority view could not supply exactly one active head.
    #[error("writer authority is unavailable: {0}")]
    AuthorityUnavailable(AuthorityUnavailableKind),
    /// A stored ledger row contradicts the append chain or the schema contract.
    /// This is a tamper or corruption signal, never a caller error.
    #[error("evidence ledger integrity failure: {0}")]
    LedgerIntegrity(String),
    /// Underlying storage, pool, or transaction failure.
    #[error("evidence ledger storage failure: {0}")]
    Storage(#[from] FleetError),
}

impl From<sqlx::Error> for EvidenceAppendError {
    fn from(error: sqlx::Error) -> Self {
        Self::Storage(FleetError::Database(error))
    }
}

impl From<EvidenceAppendError> for FleetError {
    /// Collapse into the application error type at the service boundary.
    ///
    /// `Storage` keeps its original variant so retry classification upstream is
    /// unchanged; every other variant becomes a closed `Memory` failure.
    fn from(error: EvidenceAppendError) -> Self {
        match error {
            EvidenceAppendError::Storage(inner) => inner,
            other => Self::Memory(other.to_string()),
        }
    }
}

pub fn integrity(message: impl Into<String>) -> EvidenceAppendError {
    EvidenceAppendError::LedgerIntegrity(message.into())
}

/// Result alias for the accepted-event append seam.
pub type EvidenceAppendResult<T> = std::result::Result<T, EvidenceAppendError>;
