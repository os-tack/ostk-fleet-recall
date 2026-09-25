//! Collector status: one row per collector instance in
//! `memory_collector_sources_v1` (migration 0033).
//!
//! The table is kept apart from the worker's own `memory_worker_sources_v1`,
//! so the worker's retirement of unconfigured git, transcript, and CI sources
//! and every older binary never see a collector row. Each row names its
//! `owner` (the worker, an import, or agent capture), and only that owner
//! updates it: an import can never overwrite the row of a worker collector
//! that happens to share its instance name.
//!
//! Only a reconciliation pass sets `last_checked_at`; incremental ticks
//! record their attempt and outcome and leave it where the last
//! reconciliation put it. Evidence recall lists `live` and `snapshot` rows
//! beside the worker's sources and judges them by the same rules.

use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::error::{FleetError, Result};
use crate::memory_contracts::collected_item::{
    BoundedTextV1, CollectionModeV1, MAX_SCOPE_ID_BYTES, ProviderKindV1,
};
use crate::memory_contracts::common::ContractId;

use super::cockroach::bounded;

/// Longest `last_error` a collector status row keeps.
pub const MAX_COLLECTOR_STATUS_ERROR_BYTES: usize = 2_048;

/// Bounds migration 0033 puts on `stale_after_seconds`: one minute to one
/// year.
pub const MIN_COLLECTOR_STALE_AFTER_SECONDS: u64 = 60;
pub const MAX_COLLECTOR_STALE_AFTER_SECONDS: u64 = 31_536_000;

const UPSERT_COLLECTOR_SOURCE_SQL: &str = "INSERT INTO public.memory_collector_sources_v1 (\
     tenant_id, project, collector_instance_id, provider, provider_scope_id, collection_mode, \
     coverage_role, owner, state, stale_after_seconds, last_outcome, last_attempt_at, \
     last_checked_at, last_error, updated_at\
     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'active', $9, $10, \
     pg_catalog.statement_timestamp(), \
     CASE WHEN $11 THEN pg_catalog.statement_timestamp() END, $12, \
     pg_catalog.statement_timestamp()) \
     ON CONFLICT (tenant_id, project, collector_instance_id) DO UPDATE SET \
     provider = excluded.provider, provider_scope_id = excluded.provider_scope_id, \
     collection_mode = excluded.collection_mode, coverage_role = excluded.coverage_role, \
     state = 'active', stale_after_seconds = excluded.stale_after_seconds, \
     last_outcome = excluded.last_outcome, last_attempt_at = excluded.last_attempt_at, \
     last_checked_at = COALESCE(excluded.last_checked_at, \
         public.memory_collector_sources_v1.last_checked_at), \
     last_error = excluded.last_error, updated_at = excluded.updated_at \
     WHERE public.memory_collector_sources_v1.owner = excluded.owner";

/// Retire every worker-owned collector row whose instance is not in `$3`.
/// Rows an import or a capture owns are never touched.
const RETIRE_WORKER_COLLECTORS_SQL: &str = "UPDATE public.memory_collector_sources_v1 SET \
     state = 'retired', updated_at = pg_catalog.statement_timestamp() \
     WHERE tenant_id = $1 AND project = $2 AND owner = 'worker' AND state = 'active' \
       AND collector_instance_id <> ALL($3::STRING[])";

/// What a collector's source is to the absence verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverageRoleV1 {
    /// A worker collector that reconciles against the provider: its coverage
    /// can make an absence sound.
    Live,
    /// An import of an export: complete as of the snapshot.
    Snapshot,
    /// Agent capture: never coverage.
    None,
}

impl CoverageRoleV1 {
    /// The stored `coverage_role`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Snapshot => "snapshot",
            Self::None => "none",
        }
    }
}

/// Which process maintains a collector status row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollectorOwnerV1 {
    /// `ostk-fleet-recall worker`.
    Worker,
    /// `ostk-fleet-recall collect import`.
    Import,
    /// `remember(action=capture)`.
    Capture,
}

impl CollectorOwnerV1 {
    /// The stored `owner`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Worker => "worker",
            Self::Import => "import",
            Self::Capture => "capture",
        }
    }
}

/// What one attempt at a collector source did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollectorOutcomeV1 {
    /// New material was staged or admitted.
    Ok,
    /// The source was read and had nothing new.
    Unchanged,
    /// The source could not be read.
    Failed,
}

impl CollectorOutcomeV1 {
    /// The stored `last_outcome`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Unchanged => "unchanged",
            Self::Failed => "failed",
        }
    }
}

/// One status update for one collector instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectorSourceStatusV1 {
    /// The collector instance.
    pub instance: ContractId,
    /// The provider kind.
    pub provider: ProviderKindV1,
    /// The provider scope id.
    pub provider_scope_id: BoundedTextV1<MAX_SCOPE_ID_BYTES>,
    /// The channel: pull, import, or capture. A push has no source of its own:
    /// it is a hint to its pull collector.
    pub mode: CollectionModeV1,
    /// What the source is to the absence verdict.
    pub coverage_role: CoverageRoleV1,
    /// Who maintains the row.
    pub owner: CollectorOwnerV1,
    /// How long a completed check stays current.
    pub stale_after_seconds: u64,
    /// What this attempt did.
    pub outcome: CollectorOutcomeV1,
    /// Whether this attempt was a complete reconciliation: only then is
    /// `last_checked_at` set.
    pub reconciled: bool,
    /// Why the attempt failed; bounded to
    /// [`MAX_COLLECTOR_STATUS_ERROR_BYTES`] and scrubbed by the caller.
    pub error: Option<String>,
}

impl CollectorSourceStatusV1 {
    /// Refuse a status the table cannot hold.
    ///
    /// # Errors
    ///
    /// [`FleetError::Configuration`] for a push-mode row, a staleness bound
    /// outside migration 0033's, or a reconciliation that failed.
    pub fn validate(&self) -> Result<()> {
        if self.mode == CollectionModeV1::Push {
            return Err(FleetError::Configuration(
                "a push collector has no status row of its own; its pull collector reports"
                    .to_owned(),
            ));
        }
        if !(MIN_COLLECTOR_STALE_AFTER_SECONDS..=MAX_COLLECTOR_STALE_AFTER_SECONDS)
            .contains(&self.stale_after_seconds)
        {
            return Err(FleetError::Configuration(format!(
                "collector {} stale_after_seconds must be between \
                 {MIN_COLLECTOR_STALE_AFTER_SECONDS} and {MAX_COLLECTOR_STALE_AFTER_SECONDS}",
                self.instance
            )));
        }
        if self.reconciled && self.outcome == CollectorOutcomeV1::Failed {
            return Err(FleetError::Configuration(
                "a failed attempt is not a completed reconciliation".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Upsert one collector status row inside `transaction`.
///
/// # Errors
///
/// [`FleetError::Configuration`] when [`CollectorSourceStatusV1::validate`]
/// refuses the status, or when the instance's row belongs to another owner;
/// any database failure as itself.
pub async fn upsert_collector_source(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    project: &str,
    status: &CollectorSourceStatusV1,
) -> Result<()> {
    status.validate()?;
    let stale_after = i64::try_from(status.stale_after_seconds)
        .map_err(|_| FleetError::Configuration("stale_after_seconds exceeds INT8".to_owned()))?;
    let written = sqlx::query(UPSERT_COLLECTOR_SOURCE_SQL)
        .bind(tenant_id)
        .bind(project)
        .bind(status.instance.as_str())
        .bind(status.provider.as_str())
        .bind(status.provider_scope_id.as_str())
        .bind(status.mode.as_str())
        .bind(status.coverage_role.as_str())
        .bind(status.owner.as_str())
        .bind(stale_after)
        .bind(status.outcome.as_str())
        .bind(status.reconciled)
        .bind(
            status
                .error
                .as_deref()
                .map(|error| bounded(error, MAX_COLLECTOR_STATUS_ERROR_BYTES)),
        )
        .execute(&mut **transaction)
        .await?
        .rows_affected();
    if written == 0 {
        return Err(FleetError::Configuration(format!(
            "collector instance {} already reports under another owner than {}",
            status.instance,
            status.owner.as_str()
        )));
    }
    Ok(())
}

/// Mark `retired` every active collector row the worker owns whose instance
/// is not in `configured`, inside `transaction`; the number retired.
///
/// # Errors
///
/// Any database failure.
pub async fn retire_worker_collectors(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    project: &str,
    configured: &[String],
) -> Result<u64> {
    Ok(sqlx::query(RETIRE_WORKER_COLLECTORS_SQL)
        .bind(tenant_id)
        .bind(project)
        .bind(configured)
        .execute(&mut **transaction)
        .await?
        .rows_affected())
}
