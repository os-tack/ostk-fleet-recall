//! Pure, transport-neutral contracts for dynamic causal memory.
//!
//! This module is deliberately a leaf: it does not depend on the application,
//! database, HTTP, or retrieval layers. Runtime acceptance and projection are
//! later stages built on these byte-exact contracts.

pub mod action;
pub mod bootstrap;
pub mod bootstrap_manifest;
pub mod canonical;
pub mod causal;
pub mod chunk_identity;
pub mod common;
pub mod consolidation;
pub mod control;
pub mod coverage;
pub mod digest;
pub mod discrepancy;
pub mod erasure;
pub mod error;
pub mod evidence;
pub mod evidence_v2;
pub mod generation2;
pub mod generation2_registry;
pub mod genesis;
pub mod genesis_activation;
pub mod identity;
pub mod ledger_epoch;
pub mod normative;
pub mod normative_v2;
pub mod observer;
pub mod quarantine;
pub mod registry;
pub mod relation;
pub mod relation_admission_v2;
pub mod relation_policy_v2;
pub mod remember_v2;
pub mod stage4_target_package;
pub mod stage5_target_package;
pub mod successor_activation;
pub mod successor_generic;
pub mod successor_package;
pub mod successor_policy;
pub mod telemetry;

#[cfg(test)]
mod vectors;

pub use error::{ContractError, ContractResult};
