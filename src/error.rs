use crate::memory_contracts::ContractError;

/// Closed semantic reasons a valid genesis activation cannot replace state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GenesisActivationConflictKind {
    #[error("the durable bootstrap anchor differs from the repository authority")]
    BootstrapAnchor,
    #[error("the same activation statement already has a different approval ceremony")]
    ApprovalSet,
    #[error("the request was verified against different construction-bound authority")]
    BoundAuthority,
}

/// Closed timing failures for a verified activation statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GenesisActivationTimingKind {
    #[error("effective_from precedes durable bootstrap acceptance")]
    BeforeBootstrap,
    #[error("effective_from is later than the one server acceptance timestamp")]
    FutureEffective,
}

#[derive(Debug, thiserror::Error)]
pub enum FleetError {
    #[error("configuration error: {0}")]
    Configuration(String),
    #[error("invalid fleet scope: {0}")]
    InvalidScope(String),
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("migration error: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("idempotency conflict: {0}")]
    IdempotencyConflict(String),
    #[error("control contract validation failed: {0}")]
    ControlContract(#[from] ContractError),
    #[error("genesis bootstrap conflicts with the existing control authority: {0}")]
    GenesisBootstrapConflict(String),
    #[error("control log is corrupt or incomplete: {0}")]
    ControlLogCorrupt(String),
    #[error("genesis registry activation requires a complete durable bootstrap")]
    GenesisActivationNotReady,
    #[error("genesis registry activation requires the complete successful schema prefix through 9")]
    GenesisActivationSchemaUnavailable,
    #[error("genesis registry activation conflict: {0}")]
    GenesisActivationConflict(GenesisActivationConflictKind),
    #[error("genesis registry activation is stale because another statement already won")]
    GenesisActivationStale,
    #[error("genesis registry activation timing failed: {0}")]
    GenesisActivationTiming(GenesisActivationTimingKind),
    #[error("registry activation state is corrupt or incomplete: {0}")]
    RegistryActivationCorrupt(String),
    #[error("memory operation failed: {0}")]
    Memory(String),
}

pub type Result<T> = std::result::Result<T, FleetError>;
