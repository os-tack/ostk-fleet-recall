//! The ingress hint queue, as the worker's `collect` step reads and settles
//! it (ADR 0008 D12, migration 0036).
//!
//! The receiver inserts hints; everything here is the worker's, under the
//! runtime role's `SELECT` and `UPDATE` on `memory_ingress_deliveries_v1`:
//!
//! * [`CollectedItemSink::pending_hints`] reads one instance's due hints,
//!   oldest first;
//! * a hint settles in the staging transaction of what it caused
//!   ([`CollectedItemSink::stage_settling`]), or on its own when it caused
//!   nothing ([`CollectedItemSink::settle_hint`]);
//! * a failed fetch backs off, `60 s * 2^n` after the `n+1`-th failure, and
//!   the eighth failure makes the hint `dead` with a `retry_exhausted` dead
//!   letter ([`CollectedItemSink::hint_failed`]);
//! * `collect retry --delivery` reopens a dead hint
//!   ([`CollectedItemSink::reopen_hint`]).
//!
//! Every statement binds `tenant_id = $1` and `project = $2` first.

use std::collections::BTreeMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use sqlx::postgres::PgRow;
use sqlx::{Postgres, Row as _, Transaction};
use uuid::Uuid;

use crate::collectors::cockroach::{
    INSERT_DEAD_LETTER_SQL, MAX_DEAD_LETTER_DIAGNOSTIC_BYTES, bounded, digest_column,
    statement_time,
};
use crate::collectors::ingress::HintKindV1;
use crate::error::{FleetError, Result};
use crate::memory_contracts::collected_item::{
    ItemLifecycleV1, ObjectKindV1, ProviderKindV1, TrustTierV1, derive_item_key,
};
use crate::memory_contracts::common::ContractId;
use crate::memory_contracts::digest::Sha256Digest;
use crate::store::cockroach::with_serializable_retry;

use super::{CollectedItemSink, DeadLetterReasonV1, dead_letter_id};

/// Failed fetches after which a hint is dead.
pub const MAX_HINT_ATTEMPTS: u32 = 8;

/// The backoff after a hint's first failed fetch; each later failure doubles
/// it.
const HINT_BACKOFF_SECONDS: i64 = 60;

/// Longest `last_error` a hint keeps.
const MAX_HINT_ERROR_BYTES: usize = 512;

const PENDING_HINTS_SQL: &str = "SELECT delivery_key, hint_kind, object_kind, external_id, \
     container_id, provider_event_at, attempts, raw_body_sha256 \
     FROM public.memory_ingress_deliveries_v1 \
     WHERE tenant_id = $1 AND project = $2 AND state = 'pending' \
       AND collector_instance_id = $3 \
       AND (next_attempt_at IS NULL OR next_attempt_at <= pg_catalog.statement_timestamp()) \
     ORDER BY received_at, delivery_key LIMIT $4";

const LOCK_HINT_SQL: &str = "SELECT state, attempts, provider, raw_body_sha256 \
     FROM public.memory_ingress_deliveries_v1 \
     WHERE tenant_id = $1 AND project = $2 AND collector_instance_id = $3 \
       AND delivery_key = $4 FOR UPDATE";

const SETTLE_HINT_SQL: &str = "UPDATE public.memory_ingress_deliveries_v1 \
     SET state = 'settled', settled_at = $5, next_attempt_at = NULL, last_error = NULL \
     WHERE tenant_id = $1 AND project = $2 AND collector_instance_id = $3 \
       AND delivery_key = $4 AND state = 'pending'";

const RETRY_HINT_SQL: &str = "UPDATE public.memory_ingress_deliveries_v1 \
     SET attempts = $5, next_attempt_at = $6, last_error = $7 \
     WHERE tenant_id = $1 AND project = $2 AND collector_instance_id = $3 \
       AND delivery_key = $4 AND state = 'pending'";

const KILL_HINT_SQL: &str = "UPDATE public.memory_ingress_deliveries_v1 \
     SET state = 'dead', attempts = $5, next_attempt_at = NULL, settled_at = $6, \
     last_error = $7 \
     WHERE tenant_id = $1 AND project = $2 AND collector_instance_id = $3 \
       AND delivery_key = $4 AND state = 'pending'";

const REOPEN_HINT_SQL: &str = "UPDATE public.memory_ingress_deliveries_v1 \
     SET state = 'pending', attempts = 0, next_attempt_at = NULL, settled_at = NULL, \
     last_error = NULL \
     WHERE tenant_id = $1 AND project = $2 AND delivery_key = $3 AND state = 'dead' \
     RETURNING collector_instance_id";

const HINT_STATE_SQL: &str = "SELECT state FROM public.memory_ingress_deliveries_v1 \
     WHERE tenant_id = $1 AND project = $2 AND delivery_key = $3 LIMIT 1";

/// The presented head of one item, with its container and thread: what a
/// deletion's tombstone is built from.
const HINT_TARGET_SQL: &str = "SELECT head.lifecycle, head.provider_order, head.trust_tier, \
     container.container_kind, container.container_id, item.thread_root_external_id, \
     EXISTS (SELECT 1 FROM public.memory_collected_item_withdrawals_v1 AS withdrawal \
        WHERE withdrawal.tenant_id = head.tenant_id AND withdrawal.project = head.project \
          AND withdrawal.item_key_digest = head.item_key_digest AND withdrawal.withdrawn) \
       AS withdrawn \
     FROM public.memory_collected_item_heads_v1 AS head \
     LEFT JOIN public.memory_collector_containers_v1 AS container \
       ON container.tenant_id = head.tenant_id AND container.project = head.project \
      AND container.container_key = head.container_key \
     LEFT JOIN public.memory_collected_items_v1 AS item \
       ON item.tenant_id = head.tenant_id AND item.project = head.project \
      AND item.accepted_event_id = head.last_accepted_event_id \
     WHERE head.tenant_id = $1 AND head.project = $2 AND head.item_key_digest = $3 \
     ORDER BY head.presented DESC, head.trust_tier DESC LIMIT 1";

const HINT_COUNTS_SQL: &str = "SELECT collector_instance_id, state, count(*)::INT8 AS hints \
     FROM public.memory_ingress_deliveries_v1 \
     WHERE tenant_id = $1 AND project = $2 AND disposition = 'hint' \
     GROUP BY collector_instance_id, state";

const UNDEFINED_TABLE_SQLSTATE: &str = "42P01";

/// One hint due for the worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingHintV1 {
    /// The delivery's dedupe key: the hint's identity, and the transport
    /// delivery id of what it stages.
    pub delivery_key: Sha256Digest,
    /// Upsert or delete.
    pub kind: HintKindV1,
    /// The object kind it names.
    pub object_kind: String,
    /// The external id it names.
    pub external_id: String,
    /// The container it names, when the delivery named one.
    pub container_id: Option<String>,
    /// When the provider says the change happened.
    pub provider_event_at: Option<DateTime<Utc>>,
    /// Failed fetches so far.
    pub attempts: u32,
    /// The digest of the delivery's raw body.
    pub raw_body_sha256: Sha256Digest,
}

/// One hint to settle with what a staging call stages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HintSettlementV1 {
    /// The instance the hint was delivered to: the staging call's own.
    pub instance: ContractId,
    /// The hint's key.
    pub delivery_key: Sha256Digest,
}

/// What recording a failed fetch did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HintFailureV1 {
    /// Counted; the hint is due again at `next_attempt_at`.
    Retried {
        /// Failed fetches so far.
        attempts: u32,
        /// When it is due again.
        next_attempt_at: DateTime<Utc>,
    },
    /// The eighth failure: dead, with a `retry_exhausted` dead letter.
    Dead,
    /// No longer pending: another worker settled it.
    Gone,
}

/// The presented head of the item a deletion names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HintTargetV1 {
    /// Its tier.
    pub trust_tier: TrustTierV1,
    /// Its lifecycle.
    pub lifecycle: ItemLifecycleV1,
    /// Its provider order.
    pub provider_order: u64,
    /// Its container's kind and id, when it has a recorded container.
    pub container: Option<(String, String)>,
    /// Its thread root's external id, when it is a reply.
    pub thread_root: Option<String>,
    /// Whether the item is withdrawn for either tier.
    pub withdrawn: bool,
}

/// What `collect retry --delivery` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReopenedHintV1 {
    /// The dead hint is pending again, for this instance.
    Reopened {
        /// Its collector instance.
        instance: String,
    },
    /// The delivery is not a dead hint; it is in this state.
    NotDead {
        /// Its state.
        state: String,
    },
    /// No delivery has the key.
    Unknown,
}

/// Lock one hint's row in a staging transaction.
pub(super) async fn lock_hint(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    project: &str,
    settlement: &HintSettlementV1,
) -> Result<()> {
    sqlx::query(LOCK_HINT_SQL)
        .bind(tenant_id)
        .bind(project)
        .bind(settlement.instance.as_str())
        .bind(settlement.delivery_key.as_bytes().as_slice())
        .fetch_optional(&mut **transaction)
        .await?;
    Ok(())
}

/// Settle one hint if it is still pending; how many rows it settled.
pub(super) async fn settle_hint(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    project: &str,
    settlement: &HintSettlementV1,
    now: DateTime<Utc>,
) -> Result<u64> {
    Ok(sqlx::query(SETTLE_HINT_SQL)
        .bind(tenant_id)
        .bind(project)
        .bind(settlement.instance.as_str())
        .bind(settlement.delivery_key.as_bytes().as_slice())
        .bind(now)
        .execute(&mut **transaction)
        .await?
        .rows_affected())
}

/// The backoff after `attempts` failed fetches: `60 s * 2^(attempts - 1)`.
#[must_use]
pub fn hint_backoff(attempts: u32) -> chrono::Duration {
    let doublings = attempts.saturating_sub(1).min(MAX_HINT_ATTEMPTS);
    chrono::Duration::seconds(HINT_BACKOFF_SECONDS.saturating_mul(1_i64 << doublings))
}

fn decode_hint(row: &PgRow) -> Result<PendingHintV1> {
    let kind: String = row.try_get("hint_kind")?;
    let attempts: i64 = row.try_get("attempts")?;
    Ok(PendingHintV1 {
        delivery_key: digest_column(row, "delivery_key")?,
        kind: HintKindV1::parse(&kind)
            .ok_or_else(|| FleetError::Memory(format!("a hint has an unknown kind {kind:?}")))?,
        object_kind: row.try_get("object_kind")?,
        external_id: row.try_get("external_id")?,
        container_id: row.try_get("container_id")?,
        provider_event_at: row.try_get("provider_event_at")?,
        attempts: u32::try_from(attempts)
            .map_err(|_| FleetError::Memory("a hint's attempts are negative".to_owned()))?,
        raw_body_sha256: digest_column(row, "raw_body_sha256")?,
    })
}

impl CollectedItemSink {
    /// At most `limit` of `instance`'s pending hints that are due, oldest
    /// first.
    ///
    /// # Errors
    ///
    /// A database failure, or a stored hint outside its shape.
    pub async fn pending_hints(
        &self,
        instance: &ContractId,
        limit: u32,
    ) -> Result<Vec<PendingHintV1>> {
        let rows: Vec<PgRow> = sqlx::query(PENDING_HINTS_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(instance.as_str())
            .bind(i64::from(limit))
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(decode_hint).collect()
    }

    /// Settle a hint that caused nothing to stage (its object is gone, or
    /// outside what the instance admits); `true` when it was still pending.
    ///
    /// # Errors
    ///
    /// A database failure.
    pub async fn settle_hint(&self, settlement: &HintSettlementV1) -> Result<bool> {
        let (tenant_id, project, settlement) = (
            self.tenant_id,
            self.project.clone(),
            Arc::new(settlement.clone()),
        );
        let settled = with_serializable_retry(&self.pool, self.retry, move |transaction| {
            let (project, settlement) = (project.clone(), Arc::clone(&settlement));
            Box::pin(async move {
                let now = statement_time(transaction).await?;
                settle_hint(transaction, tenant_id, &project, &settlement, now).await
            })
        })
        .await?;
        Ok(settled == 1)
    }

    /// Record one failed fetch of `hint`: count it and back off, or, at the
    /// eighth, make the hint dead with a `retry_exhausted` dead letter.
    ///
    /// # Errors
    ///
    /// A database failure.
    pub async fn hint_failed(
        &self,
        instance: &ContractId,
        hint: &PendingHintV1,
        error: &str,
    ) -> Result<HintFailureV1> {
        let (tenant_id, project, instance, key, error) = (
            self.tenant_id,
            self.project.clone(),
            instance.clone(),
            hint.delivery_key,
            Arc::new(bounded(error, MAX_HINT_ERROR_BYTES)),
        );
        with_serializable_retry(&self.pool, self.retry, move |transaction| {
            let (project, instance, error) =
                (project.clone(), instance.clone(), Arc::clone(&error));
            Box::pin(async move {
                let Some(row) = sqlx::query(LOCK_HINT_SQL)
                    .bind(tenant_id)
                    .bind(&project)
                    .bind(instance.as_str())
                    .bind(key.as_bytes().as_slice())
                    .fetch_optional(&mut **transaction)
                    .await?
                else {
                    return Ok(HintFailureV1::Gone);
                };
                if row.try_get::<String, _>("state")? != "pending" {
                    return Ok(HintFailureV1::Gone);
                }
                let now = statement_time(transaction).await?;
                let attempts = u32::try_from(row.try_get::<i64, _>("attempts")?)
                    .unwrap_or(0)
                    .saturating_add(1);
                if attempts >= MAX_HINT_ATTEMPTS {
                    sqlx::query(KILL_HINT_SQL)
                        .bind(tenant_id)
                        .bind(&project)
                        .bind(instance.as_str())
                        .bind(key.as_bytes().as_slice())
                        .bind(i64::from(MAX_HINT_ATTEMPTS))
                        .bind(now)
                        .bind(error.as_str())
                        .execute(&mut **transaction)
                        .await?;
                    let payload = digest_column(&row, "raw_body_sha256")?;
                    let provider: String = row.try_get("provider")?;
                    let id = dead_letter_id(
                        instance.as_str(),
                        DeadLetterReasonV1::RetryExhausted,
                        &payload,
                        None,
                    );
                    sqlx::query(INSERT_DEAD_LETTER_SQL)
                        .bind(tenant_id)
                        .bind(&project)
                        .bind(id.as_bytes().as_slice())
                        .bind(instance.as_str())
                        .bind("push")
                        .bind(&provider)
                        .bind(DeadLetterReasonV1::RetryExhausted.as_str())
                        .bind(None::<Vec<u8>>)
                        .bind(key.as_bytes().as_slice())
                        .bind(payload.as_bytes().as_slice())
                        .bind(bounded(
                            &format!("a hinted fetch failed {MAX_HINT_ATTEMPTS} times: {error}"),
                            MAX_DEAD_LETTER_DIAGNOSTIC_BYTES,
                        ))
                        .bind(now)
                        .execute(&mut **transaction)
                        .await?;
                    return Ok(HintFailureV1::Dead);
                }
                let next_attempt_at = now + hint_backoff(attempts);
                sqlx::query(RETRY_HINT_SQL)
                    .bind(tenant_id)
                    .bind(&project)
                    .bind(instance.as_str())
                    .bind(key.as_bytes().as_slice())
                    .bind(i64::from(attempts))
                    .bind(next_attempt_at)
                    .bind(error.as_str())
                    .execute(&mut **transaction)
                    .await?;
                Ok(HintFailureV1::Retried {
                    attempts,
                    next_attempt_at,
                })
            })
        })
        .await
    }

    /// The presented head of the item `(provider, scope, object kind,
    /// external id)`, with its recorded container and thread; `None` when the
    /// memory holds no head of it.
    ///
    /// # Errors
    ///
    /// A database failure, or a stored head outside its shape.
    pub async fn hint_target(
        &self,
        provider: &ProviderKindV1,
        provider_scope_id: &str,
        object_kind: &ObjectKindV1,
        external_id: &str,
    ) -> Result<Option<HintTargetV1>> {
        let key = derive_item_key(provider, provider_scope_id, object_kind, external_id);
        let row: Option<PgRow> = sqlx::query(HINT_TARGET_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(key.as_bytes().as_slice())
            .fetch_optional(&self.pool)
            .await?;
        row.map(|row| {
            let order: i64 = row.try_get("provider_order")?;
            let kind: Option<String> = row.try_get("container_kind")?;
            let id: Option<String> = row.try_get("container_id")?;
            Ok(HintTargetV1 {
                trust_tier: TrustTierV1::parse(&row.try_get::<String, _>("trust_tier")?)?,
                lifecycle: ItemLifecycleV1::parse(&row.try_get::<String, _>("lifecycle")?)?,
                provider_order: u64::try_from(order).map_err(|_| {
                    FleetError::Memory("a stored head order is negative".to_owned())
                })?,
                container: kind.zip(id),
                thread_root: row.try_get("thread_root_external_id")?,
                withdrawn: row.try_get("withdrawn")?,
            })
        })
        .transpose()
    }

    /// `collect retry --delivery`: make a dead hint pending again, due at
    /// once, with its attempts reset.
    ///
    /// # Errors
    ///
    /// A database failure.
    pub async fn reopen_hint(&self, delivery_key: &Sha256Digest) -> Result<ReopenedHintV1> {
        let (tenant_id, project, key) = (self.tenant_id, self.project.clone(), *delivery_key);
        with_serializable_retry(&self.pool, self.retry, move |transaction| {
            let project = project.clone();
            Box::pin(async move {
                let reopened: Option<String> = sqlx::query_scalar(REOPEN_HINT_SQL)
                    .bind(tenant_id)
                    .bind(&project)
                    .bind(key.as_bytes().as_slice())
                    .fetch_optional(&mut **transaction)
                    .await?;
                if let Some(instance) = reopened {
                    return Ok(ReopenedHintV1::Reopened { instance });
                }
                let state: Option<String> = sqlx::query_scalar(HINT_STATE_SQL)
                    .bind(tenant_id)
                    .bind(&project)
                    .bind(key.as_bytes().as_slice())
                    .fetch_optional(&mut **transaction)
                    .await?;
                Ok(
                    state.map_or(ReopenedHintV1::Unknown, |state| ReopenedHintV1::NotDead {
                        state,
                    }),
                )
            })
        })
        .await
    }

    /// Every instance's hints by state, for `collect status`; empty before
    /// migration 36.
    ///
    /// # Errors
    ///
    /// Any other database failure, or a stored count outside its bounds.
    pub async fn hint_counts(&self) -> Result<BTreeMap<String, BTreeMap<String, u64>>> {
        let rows: Vec<PgRow> = match sqlx::query(HINT_COUNTS_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .fetch_all(&self.pool)
            .await
        {
            Ok(rows) => rows,
            Err(sqlx::Error::Database(error))
                if error.code().as_deref() == Some(UNDEFINED_TABLE_SQLSTATE) =>
            {
                return Ok(BTreeMap::new());
            }
            Err(error) => return Err(error.into()),
        };
        let mut counts: BTreeMap<String, BTreeMap<String, u64>> = BTreeMap::new();
        for row in &rows {
            let count: i64 = row.try_get("hints")?;
            counts
                .entry(row.try_get("collector_instance_id")?)
                .or_default()
                .insert(
                    row.try_get("state")?,
                    u64::try_from(count).map_err(|_| {
                        FleetError::Memory("a stored hint count is negative".to_owned())
                    })?,
                );
        }
        Ok(counts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failed_hint_backs_off_by_doubling_from_a_minute() {
        let seconds: Vec<i64> = (1..MAX_HINT_ATTEMPTS)
            .map(|attempts| hint_backoff(attempts).num_seconds())
            .collect();
        assert_eq!(seconds, [60, 120, 240, 480, 960, 1_920, 3_840]);
    }
}
