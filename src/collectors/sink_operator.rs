//! What an operator import and the `collect` command read and write around
//! the sink (ADR 0008 D9): the database clock, a cursor written on its own,
//! the cursors of one domain across instances, adopting a pass's pending rows,
//! a pass's unsettled rows, a collector's status row, completing or retiring
//! an import, and the status and dead-letter listings `collect status` and
//! `collect dead-letters` print.
//!
//! Every statement binds the sink's `(tenant_id, project)` first. Nothing here
//! reads an envelope or a dead letter's payload: the listings carry
//! identities, digests, counts, reasons, and the static diagnostics the sink
//! writes, never provider text.

use std::collections::BTreeMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::Row as _;
use sqlx::postgres::PgRow;

use crate::error::{FleetError, Result};
use crate::memory_contracts::common::{CanonicalTimestamp, ContractId};
use crate::memory_contracts::digest::Sha256Digest;
use crate::store::cockroach::with_serializable_retry;

use super::{
    CollectedItemSink, CollectorCursorV1, CursorAdvanceV1, MAX_CURSOR_DOMAIN_BYTES,
    MAX_CURSOR_STATE_BYTES, order_i64,
};
use crate::collectors::cockroach::{
    MAX_DEAD_LETTER_DIAGNOSTIC_BYTES, UPSERT_CURSOR_SQL, bounded, digest_column,
    optional_digest_column, statement_time,
};
use crate::collectors::status::MAX_COLLECTOR_STATUS_ERROR_BYTES;

/// Adopt this instance's pending rows into pass `$3`.
const ADOPT_ROWS_SQL: &str = "UPDATE public.memory_collector_outbox_v1 SET pass_seq = $3 \
     WHERE tenant_id = $1 AND project = $2 AND state = 'pending' \
       AND collector_instance_id = $4 AND stage_id = ANY($5::BYTES[])";

/// The state, instance, and pass of each named row.
const ROW_OWNERS_SQL: &str = "SELECT stage_id, state, collector_instance_id, pass_seq \
     FROM public.memory_collector_outbox_v1 \
     WHERE tenant_id = $1 AND project = $2 AND stage_id = ANY($3::BYTES[])";

/// One pass's rows that are not admitted, read through the state index.
const PASS_UNSETTLED_SQL: &str = "SELECT \
     count(CASE WHEN state = 'pending' THEN 1 END)::INT8 AS pending, \
     count(CASE WHEN state <> 'pending' THEN 1 END)::INT8 AS not_admitted \
     FROM public.memory_collector_outbox_v1 \
     WHERE tenant_id = $1 AND project = $2 \
       AND state IN ('pending', 'quarantined', 'dead_lettered') \
       AND collector_instance_id = $3 AND pass_seq = $4";

/// Every instance's cursor in one domain, a page at a time by instance.
const DOMAIN_CURSORS_SQL: &str = "SELECT collector_instance_id, cursor_state, \
     high_water_order, pass_seq, updated_at FROM public.memory_collector_cursors_v1 \
     WHERE tenant_id = $1 AND project = $2 AND domain_key = $3 \
       AND collector_instance_id > $4 \
     ORDER BY collector_instance_id LIMIT $5";

const SOURCE_COLUMNS: &str = "collector_instance_id, provider, provider_scope_id, \
     collection_mode, coverage_role, owner, state, stale_after_seconds, last_outcome, \
     last_attempt_at, last_checked_at, last_error";

/// Whether the worker's own status table names an instance.
const WORKER_SOURCE_EXISTS_SQL: &str = "SELECT EXISTS (SELECT 1 \
     FROM public.memory_worker_sources_v1 \
     WHERE tenant_id = $1 AND project = $2 AND connector_instance_id = $3)";

/// Record an import attempt on its own row, only while an import owns it and
/// it is active: a retired import is never re-activated by its worker-side
/// completion.
const COMPLETE_IMPORT_SQL: &str = "UPDATE public.memory_collector_sources_v1 SET \
     last_outcome = $4, last_attempt_at = pg_catalog.statement_timestamp(), \
     last_checked_at = CASE WHEN $5 THEN pg_catalog.statement_timestamp() \
         ELSE last_checked_at END, \
     last_error = $6, updated_at = pg_catalog.statement_timestamp() \
     WHERE tenant_id = $1 AND project = $2 AND collector_instance_id = $3 \
       AND owner = 'import' AND state = 'active'";

/// Retire one import's row; rows the worker or a capture owns are never
/// touched.
const RETIRE_IMPORT_SQL: &str = "UPDATE public.memory_collector_sources_v1 SET \
     state = 'retired', updated_at = pg_catalog.statement_timestamp() \
     WHERE tenant_id = $1 AND project = $2 AND collector_instance_id = $3 \
       AND owner = 'import' AND state = 'active'";

const OUTBOX_COUNTS_SQL: &str = "SELECT collector_instance_id, state, count(*)::INT8 AS rows \
     FROM public.memory_collector_outbox_v1 WHERE tenant_id = $1 AND project = $2 \
     GROUP BY collector_instance_id, state";

const DEAD_LETTER_COUNTS_SQL: &str = "SELECT collector_instance_id, reason, \
     count(*)::INT8 AS letters \
     FROM public.memory_collector_dead_letters_v1 WHERE tenant_id = $1 AND project = $2 \
     GROUP BY collector_instance_id, reason";

const CURSOR_ROWS_SQL: &str = "SELECT collector_instance_id, domain_key, pass_seq, \
     high_water_order, updated_at FROM public.memory_collector_cursors_v1 \
     WHERE tenant_id = $1 AND project = $2 \
     ORDER BY collector_instance_id, domain_key LIMIT $3";

const DEAD_LETTERS_SQL: &str = "SELECT dead_letter_id, collector_instance_id, collection_mode, \
     provider, reason, stage_id, delivery_id, payload_digest, diagnostic, created_at \
     FROM public.memory_collector_dead_letters_v1 \
     WHERE tenant_id = $1 AND project = $2 AND created_at >= $3 \
       AND ($4::STRING IS NULL OR collector_instance_id = $4) \
     ORDER BY created_at, dead_letter_id LIMIT $5";

/// Cursor rows `collect status` lists at most.
pub const MAX_STATUS_CURSORS: usize = 4_096;

/// Dead letters `collect dead-letters` lists at most.
pub const MAX_LISTED_DEAD_LETTERS: usize = 1_000;

/// Where one named row stood after [`CollectedItemSink::adopt_rows`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdoptedRowV1 {
    /// Pending in the adopting instance's pass.
    Pending,
    /// Admitted.
    Admitted,
    /// Pending, staged by another instance: it settles when that row drains.
    Borrowed,
    /// Quarantined or dead-lettered, or missing.
    NotAdmitted,
}

/// One pass's rows that are not admitted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PassUnsettledV1 {
    /// Still pending.
    pub pending: u64,
    /// Quarantined or dead-lettered.
    pub not_admitted: u64,
}

/// One collector status row, as `collect status` prints it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CollectorSourceRowV1 {
    /// The provider kind.
    pub provider: String,
    /// The provider scope id.
    pub provider_scope_id: String,
    /// `pull`, `import`, or `capture`.
    pub collection_mode: String,
    /// `live`, `snapshot`, or `none`.
    pub coverage_role: String,
    /// `worker`, `import`, or `capture`.
    pub owner: String,
    /// `active` or `retired`.
    pub state: String,
    /// How long a completed check stays current.
    pub stale_after_seconds: u64,
    /// `ok`, `unchanged`, or `failed`.
    pub last_outcome: String,
    /// When the owner last attempted the source.
    pub last_attempt_at: DateTime<Utc>,
    /// When a complete check last finished; `None` before the first.
    pub last_checked_at: Option<DateTime<Utc>>,
    /// Why the last attempt failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// One cursor, as `collect status` prints it: never its state bytes, which
/// may hold provider paging tokens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CollectorCursorRowV1 {
    /// The cursor's domain.
    pub domain_key: String,
    /// The pass it was last advanced in.
    pub pass_seq: u64,
    /// The highest provider order it passed.
    pub high_water_order: Option<u64>,
    /// When it was advanced.
    pub updated_at: DateTime<Utc>,
}

/// Everything one collector instance holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CollectorInstanceStatusV1 {
    /// The collector instance.
    pub instance: String,
    /// Its status row, when it has one.
    pub source: Option<CollectorSourceRowV1>,
    /// Outbox rows by state.
    pub outbox: BTreeMap<String, u64>,
    /// Its cursors.
    pub cursors: Vec<CollectorCursorRowV1>,
    /// Dead letters by reason.
    pub dead_letters: BTreeMap<String, u64>,
}

/// `collect status`: every collector instance of the scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CollectorStatusReportV1 {
    /// The database's clock when the listing was read.
    pub as_of: DateTime<Utc>,
    /// Every instance with a status row, a staged row, a cursor, or a dead
    /// letter, by instance.
    pub instances: Vec<CollectorInstanceStatusV1>,
    /// Whether the cursor listing stopped at [`MAX_STATUS_CURSORS`].
    pub cursors_truncated: bool,
}

/// One dead letter: its identity, digests, reason, and static diagnostic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeadLetterRowV1 {
    /// The dead letter's key.
    pub dead_letter_id: Sha256Digest,
    /// The collector instance.
    pub instance: String,
    /// The channel.
    pub collection_mode: String,
    /// The provider kind.
    pub provider: String,
    /// The closed reason.
    pub reason: String,
    /// The staged row it settled, when there was one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stage_id: Option<Sha256Digest>,
    /// The transport delivery, as lowercase hex.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivery_id: Option<String>,
    /// The digest of the refused material: all that is kept of it.
    pub payload_digest: Sha256Digest,
    /// The sink's static diagnostic; never provider text.
    pub diagnostic: String,
    /// When it was recorded.
    pub created_at: DateTime<Utc>,
}

/// `collect dead-letters`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeadLetterListingV1 {
    /// The dead letters, oldest first.
    pub dead_letters: Vec<DeadLetterRowV1>,
    /// Whether the listing stopped at [`MAX_LISTED_DEAD_LETTERS`].
    pub truncated: bool,
}

/// What `collect retire` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetireImportV1 {
    /// The import's active row is now retired.
    Retired,
    /// The instance's row is already retired.
    AlreadyRetired,
    /// Another owner reports under the instance.
    OwnedBy(String),
    /// No collector reports under the instance.
    Unknown,
}

/// How [`CollectedItemSink::complete_import`] records an import's attempt.
#[derive(Debug, Clone)]
pub struct ImportCompletionV1<'a> {
    /// `ok`, `unchanged`, or `failed`.
    pub outcome: &'a str,
    /// Whether a snapshot receipt was recorded: only then is
    /// `last_checked_at` set.
    pub checked: bool,
    /// Why it failed.
    pub error: Option<&'a str>,
    /// The import's plan cursor, written in the same transaction.
    pub plan: &'a CursorAdvanceV1,
}

fn unsigned(row: &PgRow, column: &str) -> Result<u64> {
    let value: i64 = row.try_get(column)?;
    u64::try_from(value).map_err(|_| FleetError::Memory(format!("a stored {column} is negative")))
}

fn optional_unsigned(row: &PgRow, column: &str) -> Result<Option<u64>> {
    let value: Option<i64> = row.try_get(column)?;
    value
        .map(|value| {
            u64::try_from(value)
                .map_err(|_| FleetError::Memory(format!("a stored {column} is negative")))
        })
        .transpose()
}

fn decode_source_row(row: &PgRow) -> Result<CollectorSourceRowV1> {
    Ok(CollectorSourceRowV1 {
        provider: row.try_get("provider")?,
        provider_scope_id: row.try_get("provider_scope_id")?,
        collection_mode: row.try_get("collection_mode")?,
        coverage_role: row.try_get("coverage_role")?,
        owner: row.try_get("owner")?,
        state: row.try_get("state")?,
        stale_after_seconds: unsigned(row, "stale_after_seconds")?,
        last_outcome: row.try_get("last_outcome")?,
        last_attempt_at: row.try_get("last_attempt_at")?,
        last_checked_at: row.try_get("last_checked_at")?,
        last_error: row.try_get("last_error")?,
    })
}

/// The listing entry of one instance, created empty on first sight.
fn instance_status(
    instances: &mut BTreeMap<String, CollectorInstanceStatusV1>,
    instance: String,
) -> &mut CollectorInstanceStatusV1 {
    instances
        .entry(instance.clone())
        .or_insert_with(|| CollectorInstanceStatusV1 {
            instance,
            source: None,
            outbox: BTreeMap::new(),
            cursors: Vec::new(),
            dead_letters: BTreeMap::new(),
        })
}

fn validate_advance(advance: &CursorAdvanceV1) -> Result<()> {
    if advance.domain_key.is_empty()
        || advance.domain_key.len() > MAX_CURSOR_DOMAIN_BYTES
        || advance.cursor_state.is_empty()
        || advance.cursor_state.len() > MAX_CURSOR_STATE_BYTES
        || i64::try_from(advance.pass_seq).is_err()
        || advance
            .high_water_order
            .is_some_and(|order| i64::try_from(order).is_err())
    {
        return Err(FleetError::Configuration(
            "a cursor advance is outside migration 0033's bounds".to_owned(),
        ));
    }
    Ok(())
}

impl CollectedItemSink {
    /// The database's clock.
    ///
    /// # Errors
    ///
    /// A database failure.
    pub async fn server_instant(&self) -> Result<CanonicalTimestamp> {
        let now: DateTime<Utc> = sqlx::query_scalar("SELECT pg_catalog.statement_timestamp()")
            .fetch_one(&self.pool)
            .await?;
        CanonicalTimestamp::from_datetime(&now)
            .map_err(|error| FleetError::Memory(format!("the database clock: {error}")))
    }

    /// Write one cursor of `instance` in its own transaction.
    ///
    /// # Errors
    ///
    /// [`FleetError::Configuration`] for an advance outside migration 0033's
    /// bounds; a database failure.
    pub async fn write_cursor(
        &self,
        instance: &ContractId,
        advance: &CursorAdvanceV1,
    ) -> Result<()> {
        validate_advance(advance)?;
        let (tenant_id, project) = (self.tenant_id, self.project.clone());
        let instance = instance.as_str().to_owned();
        let advance = Arc::new(advance.clone());
        with_serializable_retry(&self.pool, self.retry, move |transaction| {
            let (project, instance, advance) =
                (project.clone(), instance.clone(), Arc::clone(&advance));
            Box::pin(async move {
                let now = statement_time(transaction).await?;
                sqlx::query(UPSERT_CURSOR_SQL)
                    .bind(tenant_id)
                    .bind(&project)
                    .bind(&instance)
                    .bind(&advance.domain_key)
                    .bind(advance.cursor_state.as_slice())
                    .bind(advance.high_water_order.map(order_i64))
                    .bind(order_i64(advance.pass_seq))
                    .bind(now)
                    .execute(&mut **transaction)
                    .await?;
                Ok(())
            })
        })
        .await
    }

    /// The cursors in `domain_key` of the instances after `after` (from the
    /// first when `None`), by instance, at most `limit`: one page.
    ///
    /// # Errors
    ///
    /// A database failure, or a stored cursor outside its bounds.
    pub async fn domain_cursors(
        &self,
        domain_key: &str,
        after: Option<&str>,
        limit: u32,
    ) -> Result<Vec<(String, CollectorCursorV1)>> {
        let rows: Vec<PgRow> = sqlx::query(DOMAIN_CURSORS_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(domain_key)
            .bind(after.unwrap_or_default())
            .bind(i64::from(limit))
            .fetch_all(&self.pool)
            .await?;
        rows.iter()
            .map(|row| {
                Ok((
                    row.try_get("collector_instance_id")?,
                    CollectorCursorV1 {
                        cursor_state: row.try_get("cursor_state")?,
                        high_water_order: optional_unsigned(row, "high_water_order")?,
                        pass_seq: unsigned(row, "pass_seq")?,
                        updated_at: row.try_get("updated_at")?,
                    },
                ))
            })
            .collect()
    }

    /// Bring the named rows into `instance`'s pass `pass_seq` and say where
    /// each stands, in one serializable transaction.
    ///
    /// A row this instance staged earlier and that is still pending is
    /// re-tagged with the pass, so the pass's own rows are exactly the rows
    /// it must see admitted; a pending row another instance staged is
    /// `Borrowed`; a settled row keeps its state for good.
    ///
    /// # Errors
    ///
    /// A pass sequence past INT8; a database failure.
    pub async fn adopt_rows(
        &self,
        instance: &ContractId,
        pass_seq: u64,
        stage_ids: &[Sha256Digest],
    ) -> Result<BTreeMap<Sha256Digest, AdoptedRowV1>> {
        let pass = i64::try_from(pass_seq)
            .map_err(|_| FleetError::Configuration("a pass sequence exceeds INT8".to_owned()))?;
        let mut adopted = BTreeMap::new();
        for chunk in stage_ids.chunks(1_024) {
            let (tenant_id, project) = (self.tenant_id, self.project.clone());
            let owner = instance.as_str().to_owned();
            let ids: Arc<Vec<Vec<u8>>> =
                Arc::new(chunk.iter().map(|id| id.as_bytes().to_vec()).collect());
            let rows = with_serializable_retry(&self.pool, self.retry, move |transaction| {
                let (project, owner, ids) = (project.clone(), owner.clone(), Arc::clone(&ids));
                Box::pin(async move {
                    sqlx::query(ADOPT_ROWS_SQL)
                        .bind(tenant_id)
                        .bind(&project)
                        .bind(pass)
                        .bind(&owner)
                        .bind(ids.as_slice())
                        .execute(&mut **transaction)
                        .await?;
                    let rows: Vec<PgRow> = sqlx::query(ROW_OWNERS_SQL)
                        .bind(tenant_id)
                        .bind(&project)
                        .bind(ids.as_slice())
                        .fetch_all(&mut **transaction)
                        .await?;
                    let mut states = Vec::with_capacity(rows.len());
                    for row in &rows {
                        let state: String = row.try_get("state")?;
                        let staged_by: String = row.try_get("collector_instance_id")?;
                        let row_pass: Option<i64> = row.try_get("pass_seq")?;
                        let stood = match state.as_str() {
                            "admitted" => AdoptedRowV1::Admitted,
                            "pending" if staged_by == owner && row_pass == Some(pass) => {
                                AdoptedRowV1::Pending
                            }
                            "pending" => AdoptedRowV1::Borrowed,
                            _ => AdoptedRowV1::NotAdmitted,
                        };
                        states.push((digest_column(row, "stage_id")?, stood));
                    }
                    Ok(states)
                })
            })
            .await?;
            adopted.extend(rows);
        }
        for id in stage_ids {
            adopted.entry(*id).or_insert(AdoptedRowV1::NotAdmitted);
        }
        Ok(adopted)
    }

    /// The rows `instance` staged in pass `pass_seq` that are not admitted.
    ///
    /// # Errors
    ///
    /// A pass sequence past INT8; a database failure.
    pub async fn pass_unsettled(
        &self,
        instance: &ContractId,
        pass_seq: u64,
    ) -> Result<PassUnsettledV1> {
        let pass = i64::try_from(pass_seq)
            .map_err(|_| FleetError::Configuration("a pass sequence exceeds INT8".to_owned()))?;
        let row: PgRow = sqlx::query(PASS_UNSETTLED_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(instance.as_str())
            .bind(pass)
            .fetch_one(&self.pool)
            .await?;
        Ok(PassUnsettledV1 {
            pending: unsigned(&row, "pending")?,
            not_admitted: unsigned(&row, "not_admitted")?,
        })
    }

    /// One collector instance's status row.
    ///
    /// # Errors
    ///
    /// A database failure.
    pub async fn collector_source(
        &self,
        instance: &ContractId,
    ) -> Result<Option<CollectorSourceRowV1>> {
        let row: Option<PgRow> = sqlx::query(&format!(
            "SELECT {SOURCE_COLUMNS} FROM public.memory_collector_sources_v1 \
             WHERE tenant_id = $1 AND project = $2 AND collector_instance_id = $3"
        ))
        .bind(self.tenant_id)
        .bind(&self.project)
        .bind(instance.as_str())
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(decode_source_row).transpose()
    }

    /// Whether the worker's own status table (git, transcripts, CI) names
    /// `instance`.
    ///
    /// # Errors
    ///
    /// A database failure.
    pub async fn worker_source_exists(&self, instance: &ContractId) -> Result<bool> {
        Ok(sqlx::query_scalar(WORKER_SOURCE_EXISTS_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(instance.as_str())
            .fetch_one(&self.pool)
            .await?)
    }

    /// Record an import's attempt on its status row and write its plan
    /// cursor, in one transaction. Returns whether the row was updated: an
    /// import retired meanwhile is left retired.
    ///
    /// # Errors
    ///
    /// [`FleetError::Configuration`] for a plan outside the cursor bounds; a
    /// database failure.
    pub async fn complete_import(
        &self,
        instance: &ContractId,
        completion: &ImportCompletionV1<'_>,
    ) -> Result<bool> {
        validate_advance(completion.plan)?;
        let (tenant_id, project) = (self.tenant_id, self.project.clone());
        let instance = instance.as_str().to_owned();
        let outcome = completion.outcome.to_owned();
        let checked = completion.checked;
        let error = completion
            .error
            .map(|error| bounded(error, MAX_COLLECTOR_STATUS_ERROR_BYTES));
        let plan = Arc::new(completion.plan.clone());
        with_serializable_retry(&self.pool, self.retry, move |transaction| {
            let (project, instance, outcome, error, plan) = (
                project.clone(),
                instance.clone(),
                outcome.clone(),
                error.clone(),
                Arc::clone(&plan),
            );
            Box::pin(async move {
                let updated = sqlx::query(COMPLETE_IMPORT_SQL)
                    .bind(tenant_id)
                    .bind(&project)
                    .bind(&instance)
                    .bind(&outcome)
                    .bind(checked)
                    .bind(error.as_deref())
                    .execute(&mut **transaction)
                    .await?
                    .rows_affected();
                let now = statement_time(transaction).await?;
                sqlx::query(UPSERT_CURSOR_SQL)
                    .bind(tenant_id)
                    .bind(&project)
                    .bind(&instance)
                    .bind(&plan.domain_key)
                    .bind(plan.cursor_state.as_slice())
                    .bind(plan.high_water_order.map(order_i64))
                    .bind(order_i64(plan.pass_seq))
                    .bind(now)
                    .execute(&mut **transaction)
                    .await?;
                Ok(updated == 1)
            })
        })
        .await
    }

    /// Retire one import's status row (`collect retire`).
    ///
    /// # Errors
    ///
    /// A database failure.
    pub async fn retire_import(&self, instance: &ContractId) -> Result<RetireImportV1> {
        let (tenant_id, project) = (self.tenant_id, self.project.clone());
        let name = instance.as_str().to_owned();
        let retired = with_serializable_retry(&self.pool, self.retry, move |transaction| {
            let (project, name) = (project.clone(), name.clone());
            Box::pin(async move {
                Ok(sqlx::query(RETIRE_IMPORT_SQL)
                    .bind(tenant_id)
                    .bind(&project)
                    .bind(&name)
                    .execute(&mut **transaction)
                    .await?
                    .rows_affected())
            })
        })
        .await?;
        if retired == 1 {
            return Ok(RetireImportV1::Retired);
        }
        Ok(match self.collector_source(instance).await? {
            None => RetireImportV1::Unknown,
            Some(row) if row.owner != "import" => RetireImportV1::OwnedBy(row.owner),
            Some(_) => RetireImportV1::AlreadyRetired,
        })
    }

    /// `collect status`: every collector instance's status row, outbox rows
    /// by state, cursors, and dead letters by reason.
    ///
    /// # Errors
    ///
    /// A database failure, or a stored count or order outside its bounds.
    pub async fn collector_status(&self) -> Result<CollectorStatusReportV1> {
        let as_of = self.server_instant().await?;
        let as_of = DateTime::parse_from_rfc3339(as_of.as_str())
            .map_err(|error| FleetError::Memory(format!("the database clock: {error}")))?
            .with_timezone(&Utc);
        let mut instances: BTreeMap<String, CollectorInstanceStatusV1> = BTreeMap::new();
        let sources: Vec<PgRow> = sqlx::query(&format!(
            "SELECT {SOURCE_COLUMNS} FROM public.memory_collector_sources_v1 \
             WHERE tenant_id = $1 AND project = $2"
        ))
        .bind(self.tenant_id)
        .bind(&self.project)
        .fetch_all(&self.pool)
        .await?;
        for row in &sources {
            instance_status(&mut instances, row.try_get("collector_instance_id")?).source =
                Some(decode_source_row(row)?);
        }
        let outbox: Vec<PgRow> = sqlx::query(OUTBOX_COUNTS_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .fetch_all(&self.pool)
            .await?;
        for row in &outbox {
            let count = unsigned(row, "rows")?;
            instance_status(&mut instances, row.try_get("collector_instance_id")?)
                .outbox
                .insert(row.try_get("state")?, count);
        }
        let letters: Vec<PgRow> = sqlx::query(DEAD_LETTER_COUNTS_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .fetch_all(&self.pool)
            .await?;
        for row in &letters {
            let count = unsigned(row, "letters")?;
            instance_status(&mut instances, row.try_get("collector_instance_id")?)
                .dead_letters
                .insert(row.try_get("reason")?, count);
        }
        let cursors: Vec<PgRow> = sqlx::query(CURSOR_ROWS_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(i64::try_from(MAX_STATUS_CURSORS + 1).unwrap_or(i64::MAX))
            .fetch_all(&self.pool)
            .await?;
        let cursors_truncated = cursors.len() > MAX_STATUS_CURSORS;
        for row in cursors.iter().take(MAX_STATUS_CURSORS) {
            let cursor = CollectorCursorRowV1 {
                domain_key: row.try_get("domain_key")?,
                pass_seq: unsigned(row, "pass_seq")?,
                high_water_order: optional_unsigned(row, "high_water_order")?,
                updated_at: row.try_get("updated_at")?,
            };
            instance_status(&mut instances, row.try_get("collector_instance_id")?)
                .cursors
                .push(cursor);
        }
        Ok(CollectorStatusReportV1 {
            as_of,
            instances: instances.into_values().collect(),
            cursors_truncated,
        })
    }

    /// `collect dead-letters`: dead letters recorded at or after `since`, of
    /// one instance or all, oldest first.
    ///
    /// # Errors
    ///
    /// A database failure, or a stored digest outside its shape.
    pub async fn dead_letters(
        &self,
        since: Option<DateTime<Utc>>,
        instance: Option<&ContractId>,
    ) -> Result<DeadLetterListingV1> {
        let rows: Vec<PgRow> = sqlx::query(DEAD_LETTERS_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(since.unwrap_or(DateTime::<Utc>::UNIX_EPOCH))
            .bind(instance.map(ContractId::as_str))
            .bind(i64::try_from(MAX_LISTED_DEAD_LETTERS + 1).unwrap_or(i64::MAX))
            .fetch_all(&self.pool)
            .await?;
        let truncated = rows.len() > MAX_LISTED_DEAD_LETTERS;
        let dead_letters = rows
            .iter()
            .take(MAX_LISTED_DEAD_LETTERS)
            .map(|row| {
                let delivery: Option<Vec<u8>> = row.try_get("delivery_id")?;
                let diagnostic: String = row.try_get("diagnostic")?;
                Ok(DeadLetterRowV1 {
                    dead_letter_id: digest_column(row, "dead_letter_id")?,
                    instance: row.try_get("collector_instance_id")?,
                    collection_mode: row.try_get("collection_mode")?,
                    provider: row.try_get("provider")?,
                    reason: row.try_get("reason")?,
                    stage_id: optional_digest_column(row, "stage_id")?,
                    delivery_id: delivery.map(hex::encode),
                    payload_digest: digest_column(row, "payload_digest")?,
                    diagnostic: bounded(&diagnostic, MAX_DEAD_LETTER_DIAGNOSTIC_BYTES),
                    created_at: row.try_get("created_at")?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(DeadLetterListingV1 {
            dead_letters,
            truncated,
        })
    }
}
