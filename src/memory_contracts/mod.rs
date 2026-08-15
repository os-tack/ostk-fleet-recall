//! Pure, transport-neutral contracts for dynamic causal memory.
//!
//! This module is deliberately a leaf: it does not depend on the application,
//! database, HTTP, or retrieval layers. Runtime acceptance and projection are
//! later stages built on these byte-exact contracts.

pub mod bootstrap;
pub mod canonical;
pub mod common;
pub mod digest;
pub mod error;
pub mod evidence;
pub mod genesis;
pub mod identity;
pub mod normative;
pub mod registry;

pub use error::{ContractError, ContractResult};
