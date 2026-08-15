//! Distributed semantic memory for agent fleets, with optional OSTK integration.
//!
//! The crate implements the same agent-facing `recall`/`remember` contract as
//! `ostk-recall`, while keeping durable corpus and epistemic state in
//! `CockroachDB`. The local-first project remains the source of shared semantic
//! types, embedding behavior, and—once its backend API lands—ranking logic.

#![recursion_limit = "256"]

pub mod application;
pub mod config;
pub mod context;
pub mod error;
pub mod ledger;
pub mod mcp;
pub mod memory_contracts;
pub mod reference_agent;
pub mod service;
pub mod store;

pub use application::CockroachMemoryService;
pub use config::FleetConfig;
pub use context::FleetScope;
pub use error::{FleetError, Result};
