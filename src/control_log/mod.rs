//! Trusted scope and persistence boundaries for the append-only control log.
//!
//! This module is intentionally separate from the legacy claim/event ledger.
//! Control-log repositories bind their SQL coordinates and semantic authority
//! scope once at construction rather than accepting routing fields per call.

mod cockroach;
mod repository;
mod types;

pub use cockroach::CockroachGenesisRepository;
pub(crate) use cockroach::{DurableGenesisWitness, load_durable_genesis_witness};
pub use repository::{
    GenesisBootstrapInspection, GenesisBootstrapOutcome, GenesisInspection, GenesisRepository,
};
pub use types::TrustedControlScope;
