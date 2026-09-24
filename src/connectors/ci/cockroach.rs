//! The durable record of what this connector actually measured (W3-CIEV).
//!
//! Migration 0026's `memory_ci_measured_windows_v1` is an index into the
//! ledger, not a second copy of it: each row names one finite run-number range,
//! the accepted event carrying that range's window observation, and the digest
//! of the fact set the scan admitted. Nothing here grants authority and nothing
//! here stores provider text.
//!
//! It exists so that a reader can answer "what did you measure?" without
//! replaying the ledger, and so that
//! [`super::fact::answer_first_failure`] can be handed a window that came from
//! durable state rather than from whatever the caller happened to have in
//! memory. A question about a run outside every recorded window resolves to
//! UNKNOWN, and this table is what makes that resolution checkable.

use async_trait::async_trait;
use sqlx::{PgPool, Row as _};

use crate::FleetError;
use crate::memory_contracts::common::{CanonicalTimestamp, ContractId};
use crate::memory_contracts::digest::Sha256Digest;
use crate::memory_contracts::evidence::AcceptedEventId;

use super::error::{CiDrainError, CiDrainResult};
use super::fact::{CI_FACT_SCHEMA_VERSION, CiCoverageWindowV1, CiRepositoryIdV1, CiTextV1};

const INSERT_WINDOW_SQL: &str = "INSERT INTO public.memory_ci_measured_windows_v1 (\
     tenant_id, project, connector_instance, repository_id, installation_id, workflow, branch, \
     window_id, first_run_number, last_run_number, fetched_at, admitted_run_count, \
     failed_run_count, source_digest, evidence_id, recorded_at) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, \
     pg_catalog.statement_timestamp()) \
     ON CONFLICT (tenant_id, project, connector_instance, window_id) DO NOTHING";

const SELECT_WINDOWS_SQL: &str = "SELECT repository_id, installation_id, workflow, branch, \
     window_id, \
     first_run_number, last_run_number, fetched_at, admitted_run_count, failed_run_count, \
     source_digest, evidence_id \
     FROM public.memory_ci_measured_windows_v1 \
     WHERE tenant_id = $1 AND project = $2 AND connector_instance = $3 \
     ORDER BY repository_id, workflow, branch, first_run_number, last_run_number, window_id";

const SELECT_HIGH_WATERMARK_SQL: &str = "SELECT coalesce(max(last_run_number), 0)::INT8 \
     FROM public.memory_ci_measured_windows_v1 \
     WHERE tenant_id = $1 AND project = $2 AND connector_instance = $3 \
     AND repository_id = $4 AND workflow = $5 AND branch = $6";

/// One durably recorded measured window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiMeasuredWindowRowV1 {
    /// Connector instance that took the reading.
    pub connector_instance: ContractId,
    /// The window itself, exactly as the observation recorded it.
    pub window: CiCoverageWindowV1,
    /// Content address of the window preimage.
    pub window_id: Sha256Digest,
    /// Settled runs the scan admitted inside the window.
    pub admitted_run_count: u32,
    /// Runs inside the window that reported a failure.
    pub failed_run_count: u32,
    /// Digest of the exact fact set the ledger made durable for this scan.
    pub source_digest: Sha256Digest,
    /// Accepted event carrying the window observation.
    pub evidence_id: AcceptedEventId,
}

/// Read and write side of the measured-window record.
#[async_trait]
pub trait CiMeasuredWindowRepository: Send + Sync {
    /// Record one measured window. Idempotent: the same window recorded twice
    /// is a primary-key conflict that changes nothing.
    async fn record_window(&self, row: &CiMeasuredWindowRowV1) -> CiDrainResult<()>;

    /// Every window this connector instance has recorded, in a deterministic
    /// order.
    async fn measured_windows(
        &self,
        connector_instance: &ContractId,
    ) -> CiDrainResult<Vec<CiMeasuredWindowRowV1>>;

    /// The next unread run number for one coverage domain.
    ///
    /// One past the highest run number any recorded window reached, or one when
    /// nothing has been measured — because a domain with no window has covered
    /// nothing, and "covered nothing" must read as UNKNOWN rather than as a
    /// negative.
    async fn resume_run_number(
        &self,
        connector_instance: &ContractId,
        repository_id: &ContractId,
        workflow: &CiTextV1,
        branch: &CiTextV1,
    ) -> CiDrainResult<u64>;
}

/// `CockroachDB`-backed measured-window record, bound once to physical scope.
#[derive(Debug, Clone)]
pub struct CockroachCiMeasuredWindowRepository {
    pool: PgPool,
    tenant_id: uuid::Uuid,
    project: String,
}

impl CockroachCiMeasuredWindowRepository {
    /// Bind the record to one physical scope.
    #[must_use]
    pub const fn new(pool: PgPool, tenant_id: uuid::Uuid, project: String) -> Self {
        Self {
            pool,
            tenant_id,
            project,
        }
    }
}

fn bounded_count(value: i64) -> CiDrainResult<u32> {
    u32::try_from(value).map_err(|_| {
        CiDrainError::Storage(FleetError::Protocol(
            "ci measured-window count is out of range".to_owned(),
        ))
    })
}

fn bounded_run_number(value: i64) -> CiDrainResult<u64> {
    u64::try_from(value).map_err(|_| {
        CiDrainError::Storage(FleetError::Protocol(
            "ci measured-window run number is out of range".to_owned(),
        ))
    })
}

fn digest_from_row(bytes: &[u8], field: &'static str) -> CiDrainResult<Sha256Digest> {
    let exact: [u8; 32] = bytes.try_into().map_err(|_| {
        CiDrainError::Storage(FleetError::Protocol(format!(
            "ci measured-window {field} is not a 32-byte digest"
        )))
    })?;
    Ok(Sha256Digest::from_bytes(exact))
}

#[async_trait]
impl CiMeasuredWindowRepository for CockroachCiMeasuredWindowRepository {
    async fn record_window(&self, row: &CiMeasuredWindowRowV1) -> CiDrainResult<()> {
        row.window.validate()?;
        // Recomputed rather than trusted: a caller that handed us a window id
        // belonging to a different window would otherwise index the ledger
        // under an address nothing derives.
        let recomputed = row.window.window_id()?;
        if recomputed != row.window_id {
            return Err(CiDrainError::Storage(FleetError::Protocol(
                "ci measured-window id does not match its window".to_owned(),
            )));
        }
        let installation_id = row
            .window
            .repository
            .installation_id
            .as_str()
            .parse::<i64>()
            .map_err(|_| {
                CiDrainError::Storage(FleetError::Protocol(
                    "ci measured-window installation coordinate is out of range".to_owned(),
                ))
            })?;
        let fetched_at: chrono::DateTime<chrono::Utc> =
            row.window.fetched_at.as_str().parse().map_err(|_| {
                CiDrainError::Storage(FleetError::Protocol(
                    "ci measured-window fetch instant is not a timestamp".to_owned(),
                ))
            })?;
        sqlx::query(INSERT_WINDOW_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(row.connector_instance.as_str())
            .bind(row.window.repository.repository_id.as_str())
            .bind(installation_id)
            .bind(row.window.workflow.as_str())
            .bind(row.window.branch.as_str())
            .bind(row.window_id.as_bytes().to_vec())
            .bind(i64::try_from(row.window.first_run_number).unwrap_or(i64::MAX))
            .bind(i64::try_from(row.window.last_run_number).unwrap_or(i64::MAX))
            .bind(fetched_at)
            .bind(i64::from(row.admitted_run_count))
            .bind(i64::from(row.failed_run_count))
            .bind(row.source_digest.as_bytes().to_vec())
            .bind(row.evidence_id.digest().as_bytes().to_vec())
            .execute(&self.pool)
            .await
            .map_err(|error| CiDrainError::Storage(FleetError::Database(error)))?;
        Ok(())
    }

    async fn measured_windows(
        &self,
        connector_instance: &ContractId,
    ) -> CiDrainResult<Vec<CiMeasuredWindowRowV1>> {
        let rows = sqlx::query(SELECT_WINDOWS_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(connector_instance.as_str())
            .fetch_all(&self.pool)
            .await
            .map_err(|error| CiDrainError::Storage(FleetError::Database(error)))?;
        let mut windows = Vec::with_capacity(rows.len());
        for row in rows {
            let repository_id: String = row
                .try_get("repository_id")
                .map_err(|error| CiDrainError::Storage(FleetError::Database(error)))?;
            let installation_id: i64 = row
                .try_get("installation_id")
                .map_err(|error| CiDrainError::Storage(FleetError::Database(error)))?;
            let workflow: String = row
                .try_get("workflow")
                .map_err(|error| CiDrainError::Storage(FleetError::Database(error)))?;
            let branch: String = row
                .try_get("branch")
                .map_err(|error| CiDrainError::Storage(FleetError::Database(error)))?;
            let window_id: Vec<u8> = row
                .try_get("window_id")
                .map_err(|error| CiDrainError::Storage(FleetError::Database(error)))?;
            let first: i64 = row
                .try_get("first_run_number")
                .map_err(|error| CiDrainError::Storage(FleetError::Database(error)))?;
            let last: i64 = row
                .try_get("last_run_number")
                .map_err(|error| CiDrainError::Storage(FleetError::Database(error)))?;
            let fetched_at: chrono::DateTime<chrono::Utc> = row
                .try_get("fetched_at")
                .map_err(|error| CiDrainError::Storage(FleetError::Database(error)))?;
            let admitted: i64 = row
                .try_get("admitted_run_count")
                .map_err(|error| CiDrainError::Storage(FleetError::Database(error)))?;
            let failed: i64 = row
                .try_get("failed_run_count")
                .map_err(|error| CiDrainError::Storage(FleetError::Database(error)))?;
            let source_digest: Vec<u8> = row
                .try_get("source_digest")
                .map_err(|error| CiDrainError::Storage(FleetError::Database(error)))?;
            let evidence_id: Vec<u8> = row
                .try_get("evidence_id")
                .map_err(|error| CiDrainError::Storage(FleetError::Database(error)))?;
            // The installation coordinate is stored so a read reconstructs the
            // EXACT window that was observed. It is a pointer into deployment
            // configuration, never authority: admission still hashes the
            // coordinate it is configured with, and a row that disagreed would
            // simply fail to reproduce its own window id.
            let window = CiCoverageWindowV1 {
                schema_version: CI_FACT_SCHEMA_VERSION,
                repository: CiRepositoryIdV1::from_trusted_config(
                    ContractId::new(repository_id)?,
                    bounded_run_number(installation_id)?,
                )?,
                workflow: CiTextV1::parse(&workflow)?,
                branch: CiTextV1::parse(&branch)?,
                first_run_number: bounded_run_number(first)?,
                last_run_number: bounded_run_number(last)?,
                fetched_at: CanonicalTimestamp::from_datetime(&fetched_at)?,
            };
            windows.push(CiMeasuredWindowRowV1 {
                connector_instance: connector_instance.clone(),
                window,
                window_id: digest_from_row(&window_id, "window_id")?,
                admitted_run_count: bounded_count(admitted)?,
                failed_run_count: bounded_count(failed)?,
                source_digest: digest_from_row(&source_digest, "source_digest")?,
                evidence_id: AcceptedEventId::from_digest(digest_from_row(
                    &evidence_id,
                    "evidence_id",
                )?),
            });
        }
        Ok(windows)
    }

    async fn resume_run_number(
        &self,
        connector_instance: &ContractId,
        repository_id: &ContractId,
        workflow: &CiTextV1,
        branch: &CiTextV1,
    ) -> CiDrainResult<u64> {
        let highest: i64 = sqlx::query_scalar(SELECT_HIGH_WATERMARK_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(connector_instance.as_str())
            .bind(repository_id.as_str())
            .bind(workflow.as_str())
            .bind(branch.as_str())
            .fetch_one(&self.pool)
            .await
            .map_err(|error| CiDrainError::Storage(FleetError::Database(error)))?;
        Ok(bounded_run_number(highest)? + 1)
    }
}
