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
    #[error("memory operation failed: {0}")]
    Memory(String),
}

pub type Result<T> = std::result::Result<T, FleetError>;
