//! How `serve` starts the event-first assert (ADR 0005, owner decision D5).
//!
//! `remember(action="assert")` is additive. `recall` and `remember(record)`
//! need no registry authority, so the writer-authority pins only ever decide
//! whether assert is served, never whether `serve` starts:
//!
//! - no pin group: assert is [`AssertStartup::NotConfigured`]. It is neither
//!   advertised nor described, and every surface stays byte for byte what it
//!   was;
//! - a pin group that is partial or malformed, a head that does not verify
//!   under it, an agent that cannot be a contract actor, or an active package
//!   with no assert route: assert is [`AssertStartup::Off`]. The reason is
//!   logged at error level and reported in `recall(status).remember_assert`;
//! - otherwise assert is [`AssertStartup::Served`], and the claim ledger
//!   serves it through [`EventFirstAssert`].
//!
//! What startup verified is a snapshot for the status block and the startup
//! log only. Nothing here authorizes an append: every assert re-verifies the
//! head, and the append re-reads it inside its own transaction.

use std::sync::Arc;

use serde::Serialize;
use sqlx::PgPool;

use crate::FleetScope;
use crate::config::WriterAuthorityConfig;
use crate::ledger::CockroachClaimLedger;
use crate::registry_witness::{
    WriterAuthorityError, WriterAuthorityRuntime, WriterAuthorityStartError,
    WriterAuthorityStartupV1,
};
use crate::store::cockroach::RetryPolicy;

use super::admission::AssertRouteDescriptionV1;
use super::event_first::{EventFirstAssert, actor_for_agent};

/// Whether this writer serves `remember(action="assert")`, and against what,
/// as `recall(status).remember_assert` reports it.
///
/// Present only when the writer-authority pin group is configured, even
/// partially; a writer with no pins reports nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AssertStatusV1 {
    pub served: bool,
    /// Why assert is off. Absent when it is served.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The active head startup verified, when it verified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry: Option<WriterAuthorityStartupV1>,
    /// What an agent may assert: the predicate, its value kind and
    /// modalities, and the locator component keys of the subject and of each
    /// applicability dimension.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route: Option<AssertRouteDescriptionV1>,
}

impl AssertStatusV1 {
    fn off(reason: String, registry: Option<WriterAuthorityStartupV1>) -> Self {
        tracing::error!(
            reason = %reason,
            "remember(assert) is off: the writer-authority pins are configured but unusable; serving recall and remember without it"
        );
        Self {
            served: false,
            reason: Some(reason),
            registry,
            route: None,
        }
    }
}

/// What `serve` does about `remember(action="assert")`.
#[derive(Debug)]
pub enum AssertStartup {
    /// The pins verified and the active package routes an assertion.
    Served(Arc<EventFirstAssert>, AssertStatusV1),
    /// The pin group is configured but unusable. `serve` starts with assert
    /// off and reports why.
    Off(AssertStatusV1),
    /// No pin group: the event-first path is not configured.
    NotConfigured,
}

impl AssertStartup {
    /// Serve the assert this startup resolved through `ledger`.
    ///
    /// Returns the ledger to serve with and the status to report. The status
    /// says `served` exactly when the returned ledger serves assert; a ledger
    /// that refuses the binding (an authority for another scope or agent)
    /// turns a served startup off rather than failing `serve`.
    #[must_use]
    pub fn bind_ledger(
        self,
        ledger: CockroachClaimLedger,
    ) -> (CockroachClaimLedger, Option<AssertStatusV1>) {
        match self {
            Self::NotConfigured => (ledger, None),
            Self::Off(status) => (ledger, Some(status)),
            Self::Served(assert, status) => match ledger.clone().with_event_first_assert(assert) {
                Ok(serving) => (serving, Some(status)),
                Err(error) => {
                    let status = AssertStatusV1::off(
                        format!("the claim ledger cannot serve the writer authority: {error}"),
                        status.registry,
                    );
                    (ledger, Some(status))
                }
            },
        }
    }
}

/// Start the event-first assert for `default_scope` under the writer-authority
/// pins in the process environment. See the module documentation.
///
/// Never fails: every problem is [`AssertStartup::Off`] with its reason.
pub async fn start_event_first_assert(
    pool: PgPool,
    default_scope: &FleetScope,
    retry: RetryPolicy,
) -> AssertStartup {
    start_event_first_assert_with(pool, default_scope, retry, |name| std::env::var(name).ok()).await
}

/// [`start_event_first_assert`] over an injected variable lookup.
///
/// The actor is `agent.<default_scope.agent>` (`FLEET_RECALL_AGENT`). Nothing
/// is read from the database unless the pin group parses and the agent is a
/// contract actor.
pub async fn start_event_first_assert_with(
    pool: PgPool,
    default_scope: &FleetScope,
    retry: RetryPolicy,
    lookup: impl FnMut(&str) -> Option<String>,
) -> AssertStartup {
    let config = match WriterAuthorityConfig::from_lookup(lookup) {
        Ok(Some(config)) => config,
        Ok(None) => return AssertStartup::NotConfigured,
        Err(error) => {
            return AssertStartup::Off(AssertStatusV1::off(
                format!("the writer-authority pins are invalid: {error}"),
                None,
            ));
        }
    };
    let actor = match actor_for_agent(&default_scope.agent) {
        Ok(actor) => actor,
        Err(error) => {
            return AssertStartup::Off(AssertStatusV1::off(
                format!(
                    "FLEET_RECALL_AGENT `{}` cannot assert as the contract actor `agent.{}`: {error}",
                    default_scope.agent, default_scope.agent
                ),
                None,
            ));
        }
    };
    let runtime =
        match WriterAuthorityRuntime::start(pool, default_scope.clone(), config, retry).await {
            Ok((runtime, _)) => runtime,
            Err(error) => {
                return AssertStartup::Off(AssertStatusV1::off(start_reason(&error), None));
            }
        };
    let assert = EventFirstAssert::new(runtime, actor);
    // One more read, so the route and the reported head come from one witness.
    let verified = match assert.authority().verify().await {
        Ok(verified) => verified,
        Err(error) => {
            return AssertStartup::Off(AssertStatusV1::off(verify_reason(&error), None));
        }
    };
    let witness = verified.witness();
    let registry = WriterAuthorityStartupV1 {
        generation: witness.generation(),
        activation_id: witness.activation_id(),
        package: witness.active_package().known(),
    };
    let route = match assert.route(witness.package()) {
        Ok(route) => route,
        Err(error) => {
            return AssertStartup::Off(AssertStatusV1::off(
                format!("the active registry package serves no assert route: {error}"),
                Some(registry),
            ));
        }
    };
    tracing::info!(
        generation = registry.generation,
        package = ?registry.package,
        actor = %assert.actor(),
        "serving remember(assert) under the verified writer authority"
    );
    let status = AssertStatusV1 {
        served: true,
        reason: None,
        registry: Some(registry),
        route: Some(route.describe()),
    };
    AssertStartup::Served(Arc::new(assert), status)
}

pub(super) fn start_reason(error: &WriterAuthorityStartError) -> String {
    match error {
        WriterAuthorityStartError::Config(error) => {
            format!("the writer-authority pins are invalid: {error}")
        }
        WriterAuthorityStartError::Rejected(rejection) => {
            format!("the writer authority did not verify: {rejection}")
        }
        WriterAuthorityStartError::Contract(error) => {
            format!("a writer-authority contract did not verify: {error}")
        }
        WriterAuthorityStartError::Database(error) => database_reason(error),
    }
}

pub(super) fn verify_reason(error: &WriterAuthorityError) -> String {
    match error {
        WriterAuthorityError::Rejected(rejection) => {
            format!("the writer authority did not verify: {rejection}")
        }
        WriterAuthorityError::Contract(error) => {
            format!("a writer-authority contract did not verify: {error}")
        }
        WriterAuthorityError::Database(error) => database_reason(error),
    }
}

/// A database failure is reported without its detail, which is logged.
fn database_reason(error: &sqlx::Error) -> String {
    tracing::error!(error = %error, "the writer-authority view could not be read");
    "the writer-authority view could not be read by this login".into()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use ostk_recall_core::PrivacyTier;
    use sqlx::postgres::PgPoolOptions;
    use uuid::Uuid;

    use super::*;

    const TENANT_NAMESPACE: &str = "FLEET_RECALL_CONTRACT_TENANT_NAMESPACE";
    const PROJECT_NAMESPACE: &str = "FLEET_RECALL_CONTRACT_PROJECT_NAMESPACE";
    const RECEIPT_DIGEST: &str = "FLEET_RECALL_BOOTSTRAP_RECEIPT_DIGEST";

    /// A pool that fails any use: every case here must decide before I/O.
    fn unreachable_pool() -> PgPool {
        PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_millis(200))
            .connect_lazy("postgresql://root@127.0.0.1:1/unreachable")
            .unwrap()
    }

    fn scope(agent: &str) -> FleetScope {
        FleetScope::new(
            Uuid::now_v7(),
            "project",
            agent,
            None,
            PrivacyTier::T1Project,
        )
        .unwrap()
    }

    async fn start(agent: &str, pins: &[(&str, &str)]) -> AssertStartup {
        let pins = pins
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect::<HashMap<_, _>>();
        start_event_first_assert_with(
            unreachable_pool(),
            &scope(agent),
            RetryPolicy::default(),
            |name| pins.get(name).cloned(),
        )
        .await
    }

    fn off_reason(startup: AssertStartup) -> String {
        let AssertStartup::Off(status) = startup else {
            panic!("expected assert off, got {startup:?}");
        };
        assert!(!status.served);
        assert!(status.route.is_none());
        status.reason.expect("an off status says why")
    }

    #[tokio::test]
    async fn no_pins_is_not_configured() {
        assert!(matches!(
            start("agent-a", &[]).await,
            AssertStartup::NotConfigured
        ));
    }

    #[tokio::test]
    async fn a_partial_pin_group_turns_assert_off_before_io() {
        let reason = off_reason(
            start(
                "agent-a",
                &[
                    (TENANT_NAMESPACE, "tenant.acme"),
                    (PROJECT_NAMESPACE, "project.recall"),
                ],
            )
            .await,
        );
        assert!(reason.contains(RECEIPT_DIGEST), "{reason}");
    }

    #[tokio::test]
    async fn an_agent_that_is_no_contract_actor_turns_assert_off_before_io() {
        let digest = "ab".repeat(32);
        let reason = off_reason(
            start(
                "Agent A",
                &[
                    (TENANT_NAMESPACE, "tenant.acme"),
                    (PROJECT_NAMESPACE, "project.recall"),
                    (RECEIPT_DIGEST, &digest),
                ],
            )
            .await,
        );
        assert!(reason.contains("FLEET_RECALL_AGENT"), "{reason}");
    }

    #[test]
    fn a_status_names_only_what_it_knows() {
        let status = AssertStatusV1 {
            served: false,
            reason: Some("why".into()),
            registry: None,
            route: None,
        };
        assert_eq!(
            serde_json::to_value(&status).unwrap(),
            serde_json::json!({ "served": false, "reason": "why" })
        );
    }
}
