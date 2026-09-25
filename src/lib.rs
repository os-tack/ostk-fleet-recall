//! Distributed semantic memory for agent fleets, with optional OSTK integration.
//!
//! The crate implements the same agent-facing `recall`/`remember` contract as
//! `ostk-recall`, while keeping durable corpus and epistemic state in
//! `CockroachDB`. The local-first project remains the source of shared semantic
//! types, embedding behavior, and—once its backend API lands—ranking logic.

#![recursion_limit = "256"]

pub mod application;
pub mod body_store;
pub mod collectors;
pub mod config;
pub mod connectors;
pub mod context;
pub mod control_log;
pub mod coverage_runtime;
pub mod discrepancy_runtime;
pub mod error;
pub mod evidence_ledger;
pub mod evidence_recall;
pub mod ledger;
pub mod mcp;
pub mod memory_contracts;
pub mod normative_runtime;
pub mod observer_runtime;
pub mod private_postgres;
pub mod projectors;
pub mod redaction;
pub mod registry_activation;
pub mod registry_witness;
pub mod relation_projection;
pub mod remember_runtime;
pub mod service;
pub mod spec_conformance;
pub mod store;
pub mod worker;

pub use application::CockroachMemoryService;
pub use config::{ControlBootstrapConfig, FleetConfig};
pub use context::FleetScope;
pub use control_log::TrustedControlScope;
pub use error::{FleetError, Result};
