//! One composition from the writer-authority pins to an appendable ledger.
//!
//! Every process that appends accepted events under the active registry head
//! — `serve` for `remember(action="assert")`, the memory worker, `ostk-spec`,
//! and `ostk-observer-run` — needs the same four things bound to one physical
//! scope: the deployment pins ([`WriterAuthorityConfig`]), the strict witness
//! ([`load_and_verify`]), the [`TrustedControlScope`] the witness certifies,
//! and a [`CockroachAcceptedEventRepository`] bound to that scope.
//! [`WriterAuthorityRuntime`] is that composition, written once.
//!
//! It holds configuration and a pool, never authority (D4). [`start`] runs
//! the strict witness once so a process refuses to start under pins the
//! database does not honor, and every later [`verify`] re-reads
//! `memory_writer_authority_v1` from scratch: a caller that wants a head for a
//! request or a tick asks for a fresh [`VerifiedWriterAuthority`] and drops it
//! when the work is done. The append itself re-reads the same view inside its
//! own serializable transaction, so a head that moves between [`verify`] and
//! the append aborts the append rather than being trusted.
//!
//! There is deliberately no startup grant probe. A runtime login missing an
//! evidence-plane grant fails the first append with SQLSTATE 42501 inside the
//! append transaction, which writes nothing; a separate probe would only
//! duplicate that verdict earlier.
//!
//! [`start`]: WriterAuthorityRuntime::start
//! [`verify`]: WriterAuthorityRuntime::verify

use std::env;
use std::sync::Arc;

use serde::Serialize;
use sqlx::PgPool;

use crate::config::WriterAuthorityConfig;
use crate::context::FleetScope;
use crate::control_log::TrustedControlScope;
use crate::error::FleetError;
use crate::evidence_ledger::{
    ActiveStage4Package, CockroachAcceptedEventRepository, EvidenceAdmissionError,
    EvidenceAppendError, WriterAuthorityWitness as AppendWitness,
};
use crate::memory_contracts::ContractError;
use crate::memory_contracts::common::{AuthenticatedProjectScopeV1, ContractId};
use crate::memory_contracts::digest::Sha256Digest;
use crate::memory_contracts::evidence_v2::RegistryHeadBindingV1;
use crate::store::cockroach::RetryPolicy;

use super::{
    KnownRegistryPackage, WitnessResult, WriterAuthorityError, WriterAuthorityRejection,
    WriterAuthorityWitness, load_and_verify,
};

/// Why a writer-authority runtime could not start.
#[derive(Debug, thiserror::Error)]
pub enum WriterAuthorityStartError {
    /// The pin group is partial or malformed, or the physical scope is
    /// invalid. Nothing was read from the database.
    #[error("writer authority configuration is invalid: {0}")]
    Config(#[source] FleetError),
    /// The durable head does not verify under the pins (a fail-closed
    /// witness verdict).
    #[error("writer authority is unusable: {0}")]
    Rejected(WriterAuthorityRejection),
    /// A durable authority artifact, or a compiled-in package, does not
    /// verify as a memory contract.
    #[error("writer authority contract validation failed: {0}")]
    Contract(#[source] ContractError),
    /// The authority view could not be read, including SQLSTATE 42501 when
    /// the login lacks SELECT on `memory_writer_authority_v1`.
    #[error("database error: {0}")]
    Database(#[source] sqlx::Error),
}

impl From<WriterAuthorityError> for WriterAuthorityStartError {
    fn from(error: WriterAuthorityError) -> Self {
        match error {
            WriterAuthorityError::Rejected(rejection) => Self::Rejected(rejection),
            WriterAuthorityError::Database(error) => Self::Database(error),
            WriterAuthorityError::Contract(error) => Self::Contract(error),
        }
    }
}

impl From<WriterAuthorityStartError> for FleetError {
    fn from(error: WriterAuthorityStartError) -> Self {
        match error {
            WriterAuthorityStartError::Config(error) => error,
            WriterAuthorityStartError::Rejected(rejection) => {
                WriterAuthorityError::Rejected(rejection).into()
            }
            WriterAuthorityStartError::Contract(error) => Self::ControlContract(error),
            WriterAuthorityStartError::Database(error) => Self::Database(error),
        }
    }
}

/// What a started runtime verified, for a startup log line or a status block.
///
/// A snapshot of the one startup read, not a cache: nothing consults it to
/// authorize an append.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct WriterAuthorityStartupV1 {
    pub generation: u64,
    pub activation_id: Sha256Digest,
    pub package: KnownRegistryPackage,
}

impl WriterAuthorityStartupV1 {
    const fn of(witness: &WriterAuthorityWitness) -> Self {
        Self {
            generation: witness.generation(),
            activation_id: witness.activation_id(),
            package: witness.active_package().known(),
        }
    }
}

/// The deployment pins, the physical scope they are verified for, and the
/// evidence ledger bound to that scope.
///
/// Holds no witness. See the module documentation for why authority is never
/// cached here.
#[derive(Clone)]
pub struct WriterAuthorityRuntime {
    pool: PgPool,
    physical_scope: FleetScope,
    config: WriterAuthorityConfig,
    control_scope: TrustedControlScope,
    ledger: Arc<CockroachAcceptedEventRepository>,
    retry: RetryPolicy,
}

impl std::fmt::Debug for WriterAuthorityRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WriterAuthorityRuntime")
            .field("physical_scope", &self.physical_scope)
            .field("config", &self.config)
            .field("control_scope", &self.control_scope)
            .finish_non_exhaustive()
    }
}

impl WriterAuthorityRuntime {
    /// Bind the pins to `physical_scope` and verify the active head once.
    ///
    /// The control scope pairs the physical scope with the pinned semantic
    /// namespaces; the strict witness has just proved the durable head carries
    /// exactly those namespaces for exactly this physical scope. `retry`
    /// governs the ledger's serializable appends (retried only on 40001).
    ///
    /// # Errors
    ///
    /// [`WriterAuthorityStartError::Config`] for an invalid physical scope,
    /// before any read; otherwise whatever the strict witness refuses.
    pub async fn start(
        pool: PgPool,
        physical_scope: FleetScope,
        config: WriterAuthorityConfig,
        retry: RetryPolicy,
    ) -> Result<(Self, WriterAuthorityStartupV1), WriterAuthorityStartError> {
        let control_scope = TrustedControlScope::from_trusted_context(
            &physical_scope,
            config.semantic_scope().clone(),
        )
        .map_err(WriterAuthorityStartError::Config)?;
        let ledger = Arc::new(CockroachAcceptedEventRepository::new(
            pool.clone(),
            control_scope.clone(),
            retry,
        ));
        let runtime = Self {
            pool,
            physical_scope,
            config,
            control_scope,
            ledger,
            retry,
        };
        let verified = runtime.verify().await?;
        let startup = WriterAuthorityStartupV1::of(verified.witness());
        Ok((runtime, startup))
    }

    /// [`Self::start`] under the pin group in the process environment
    /// ([`WriterAuthorityConfig::from_env`]).
    ///
    /// `Ok(None)` means the group is absent: the event-first path is not
    /// configured for this process, and nothing was read from the database.
    /// Whether that is acceptable is the caller's policy, not this function's.
    ///
    /// # Errors
    ///
    /// [`WriterAuthorityStartError::Config`] for a partial or malformed group,
    /// before any read; otherwise as [`Self::start`].
    pub async fn from_env(
        pool: PgPool,
        physical_scope: FleetScope,
        retry: RetryPolicy,
    ) -> Result<Option<(Self, WriterAuthorityStartupV1)>, WriterAuthorityStartError> {
        Self::from_lookup(pool, physical_scope, retry, |name| env::var(name).ok()).await
    }

    /// [`Self::from_env`] over an injected variable lookup.
    pub(crate) async fn from_lookup(
        pool: PgPool,
        physical_scope: FleetScope,
        retry: RetryPolicy,
        lookup: impl FnMut(&str) -> Option<String>,
    ) -> Result<Option<(Self, WriterAuthorityStartupV1)>, WriterAuthorityStartError> {
        let Some(config) = WriterAuthorityConfig::from_lookup(lookup)
            .map_err(WriterAuthorityStartError::Config)?
        else {
            return Ok(None);
        };
        Self::start(pool, physical_scope, config, retry)
            .await
            .map(Some)
    }

    /// Re-read and re-verify the active head now.
    ///
    /// Every call reads `memory_writer_authority_v1` again under the pins;
    /// nothing from [`Self::start`] or an earlier call is reused (D4).
    ///
    /// # Errors
    ///
    /// Whatever the strict witness refuses, exactly as [`load_and_verify`].
    pub async fn verify(&self) -> WitnessResult<VerifiedWriterAuthority> {
        let witness = load_and_verify(&self.pool, &self.physical_scope, &self.config).await?;
        let append_witness = witness.to_append_witness().map_err(append_witness_error)?;
        Ok(VerifiedWriterAuthority {
            witness,
            append_witness,
        })
    }

    #[must_use]
    pub const fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// The physical `(tenant_id, project)` every read and append binds.
    #[must_use]
    pub const fn physical_scope(&self) -> &FleetScope {
        &self.physical_scope
    }

    #[must_use]
    pub const fn config(&self) -> &WriterAuthorityConfig {
        &self.config
    }

    #[must_use]
    pub const fn control_scope(&self) -> &TrustedControlScope {
        &self.control_scope
    }

    /// The pinned contract namespaces the head was verified to carry.
    #[must_use]
    pub const fn semantic_scope(&self) -> &AuthenticatedProjectScopeV1 {
        self.control_scope.semantic_scope()
    }

    /// The evidence ledger bound to [`Self::control_scope`].
    #[must_use]
    pub const fn ledger(&self) -> &Arc<CockroachAcceptedEventRepository> {
        &self.ledger
    }

    /// The serializable retry policy this runtime was started with (retried
    /// only on 40001), for the other repositories a caller binds to the same
    /// scope.
    #[must_use]
    pub const fn retry_policy(&self) -> RetryPolicy {
        self.retry
    }
}

/// One fresh verification of the active head: the strict witness and the
/// append witness adapted from it.
///
/// Scoped to one request or tick. Holding it longer is safe but pointless,
/// because every append re-reads the head inside its own transaction and
/// refuses one that has moved.
#[derive(Debug, Clone)]
pub struct VerifiedWriterAuthority {
    witness: WriterAuthorityWitness,
    append_witness: AppendWitness,
}

impl VerifiedWriterAuthority {
    #[must_use]
    pub const fn witness(&self) -> &WriterAuthorityWitness {
        &self.witness
    }

    /// The value the append transaction compares its own head read against.
    #[must_use]
    pub const fn append_witness(&self) -> &AppendWitness {
        &self.append_witness
    }

    #[must_use]
    pub fn head_binding(&self) -> &RegistryHeadBindingV1 {
        self.witness.head_binding()
    }

    /// Narrow the active package to the connector schema `connector_schema_id`
    /// names, for admission under this head.
    ///
    /// # Errors
    ///
    /// [`EvidenceAdmissionError::ConnectorNotInActivePackage`] when the active
    /// package does not carry that connector schema.
    pub fn bind_connector(
        &self,
        connector_schema_id: &ContractId,
    ) -> Result<ActiveStage4Package, EvidenceAdmissionError> {
        ActiveStage4Package::bind_connector(
            self.witness.package().clone(),
            connector_schema_id,
            self.witness.head_binding().clone(),
            &self.append_witness,
        )
    }
}

/// The strict witness already proved every field it hands the adapter, so a
/// refusal here is a contradiction between the two witness types, never a
/// verdict about the database; it still fails closed.
fn append_witness_error(error: EvidenceAppendError) -> WriterAuthorityError {
    match error {
        EvidenceAppendError::Contract(error) => WriterAuthorityError::Contract(error),
        _ => WriterAuthorityRejection::Unrepresentable.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use ostk_recall_core::PrivacyTier;
    use sqlx::postgres::PgPoolOptions;
    use uuid::Uuid;

    use super::*;

    /// Any canonical digest: nothing here reaches the database, so no value
    /// is ever compared against a durable receipt.
    const ANY_DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    const PIN_GROUP: [&str; 3] = [
        "FLEET_RECALL_CONTRACT_TENANT_NAMESPACE",
        "FLEET_RECALL_CONTRACT_PROJECT_NAMESPACE",
        "FLEET_RECALL_BOOTSTRAP_RECEIPT_DIGEST",
    ];

    /// A pool that never connects: every test here must decide before any
    /// read, so an attempted connection would fail the test.
    fn unreachable_pool() -> PgPool {
        PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_millis(1))
            .connect_lazy("postgresql://fleet_writer@127.0.0.1:1/fleet_recall")
            .expect("a lazy pool never connects at construction")
    }

    fn physical_scope() -> FleetScope {
        FleetScope::new(
            Uuid::now_v7(),
            "runtime-unit",
            "writer-authority-runtime",
            None,
            PrivacyTier::T1Project,
        )
        .unwrap()
    }

    fn pins() -> HashMap<&'static str, String> {
        HashMap::from([
            (PIN_GROUP[0], "tenant.acme".into()),
            (PIN_GROUP[1], "project.recall".into()),
            (PIN_GROUP[2], ANY_DIGEST.into()),
        ])
    }

    async fn from_values(
        values: &HashMap<&'static str, String>,
    ) -> Result<Option<(WriterAuthorityRuntime, WriterAuthorityStartupV1)>, WriterAuthorityStartError>
    {
        WriterAuthorityRuntime::from_lookup(
            unreachable_pool(),
            physical_scope(),
            RetryPolicy::default(),
            |name| values.get(name).cloned(),
        )
        .await
    }

    #[tokio::test]
    async fn an_absent_pin_group_starts_nothing() {
        let started = from_values(&HashMap::new())
            .await
            .expect("an absent pin group is not an error");
        assert!(started.is_none());
    }

    #[tokio::test]
    async fn a_partial_pin_group_is_a_configuration_error_before_any_read() {
        for missing in PIN_GROUP {
            let mut values = pins();
            values.remove(missing);
            let error = from_values(&values)
                .await
                .expect_err("a partial pin group must not start");
            match error {
                WriterAuthorityStartError::Config(FleetError::Configuration(message)) => {
                    assert!(
                        message.contains(missing),
                        "{message} does not name {missing}"
                    );
                }
                other => panic!("a partial pin group must be a configuration error: {other}"),
            }
        }
    }
}
