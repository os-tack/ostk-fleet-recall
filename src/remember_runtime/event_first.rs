//! What a claim ledger needs to serve the event-first assert.
//!
//! [`EventFirstAssert`] pairs a started [`WriterAuthorityRuntime`] with the
//! actor every assertion through it is attributed to. It caches exactly one
//! thing: the assert route resolved from a package, keyed by that package's
//! digest. The route is a pure function of the package bytes, so reusing it
//! for the same digest trusts nothing new. Authority itself is never cached:
//! each assert re-verifies the head ([`WriterAuthorityRuntime::verify`]) and
//! the append re-reads it inside its own transaction.

use std::sync::{Mutex, PoisonError};

use crate::memory_contracts::ContractResult;
use crate::memory_contracts::common::ContractId;
use crate::memory_contracts::digest::Sha256Digest;
use crate::memory_contracts::successor_package::SemanticallyClosedSuccessorPackage;
use crate::registry_witness::WriterAuthorityRuntime;

use super::admission::{RememberAssertRouteV1, resolve_assert_route};

/// Prefix of the contract ID an authenticated agent asserts as.
const AGENT_ACTOR_PREFIX: &str = "agent.";

/// The actor an authenticated fleet agent asserts as: `agent.<agent>`.
///
/// # Errors
///
/// When `agent.<agent>` is not a contract ID (lowercase ASCII letters,
/// digits, `_`, `-`, and `.`, at most 128 bytes).
pub fn actor_for_agent(agent: &str) -> ContractResult<ContractId> {
    ContractId::new(format!("{AGENT_ACTOR_PREFIX}{agent}"))
}

/// A writer-authority runtime, the actor it asserts as, and the assert route
/// of the last package it served.
#[derive(Debug)]
pub struct EventFirstAssert {
    authority: WriterAuthorityRuntime,
    actor: ContractId,
    route_cache: Mutex<Option<(Sha256Digest, RememberAssertRouteV1)>>,
}

impl EventFirstAssert {
    #[must_use]
    pub const fn new(authority: WriterAuthorityRuntime, actor: ContractId) -> Self {
        Self {
            authority,
            actor,
            route_cache: Mutex::new(None),
        }
    }

    /// Serve asserts for the fleet agent `agent`, as [`actor_for_agent`].
    ///
    /// # Errors
    ///
    /// As [`actor_for_agent`].
    pub fn for_agent(authority: WriterAuthorityRuntime, agent: &str) -> ContractResult<Self> {
        Ok(Self::new(authority, actor_for_agent(agent)?))
    }

    #[must_use]
    pub const fn authority(&self) -> &WriterAuthorityRuntime {
        &self.authority
    }

    #[must_use]
    pub const fn actor(&self) -> &ContractId {
        &self.actor
    }

    /// The assert route of `package`, resolved once per package digest.
    ///
    /// # Errors
    ///
    /// As [`resolve_assert_route`]: the package has no single
    /// authenticated-actor remember route this server can derive.
    pub fn route(
        &self,
        package: &SemanticallyClosedSuccessorPackage,
    ) -> ContractResult<RememberAssertRouteV1> {
        let digest = package.package_digest();
        if let Some((cached, route)) = self
            .route_cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            && *cached == digest
        {
            return Ok(route.clone());
        }
        let route = resolve_assert_route(package)?;
        *self
            .route_cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some((digest, route.clone()));
        Ok(route)
    }
}
