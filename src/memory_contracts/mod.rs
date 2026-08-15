//! Pure, transport-neutral contracts for dynamic causal memory.
//!
//! This module is deliberately a leaf: it does not depend on the application,
//! database, HTTP, or retrieval layers. Runtime acceptance and projection are
//! later stages built on these byte-exact contracts.

pub mod bootstrap;
pub mod canonical;
pub mod common;
pub mod control;
pub mod digest;
pub mod error;
pub mod evidence;
pub mod evidence_v2;
pub mod genesis;
pub mod genesis_activation;
pub mod identity;
pub mod normative;
pub mod registry;
pub mod relation;
pub mod relation_policy_v2;
pub mod remember_v2;
pub mod stage4_target_package;
pub mod successor_package;
pub mod successor_policy;

#[cfg(test)]
mod vectors;

pub use error::{ContractError, ContractResult};
