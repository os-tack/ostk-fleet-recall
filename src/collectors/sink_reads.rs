//! What a pull collector reads back from the sink, and the writes it makes
//! around a pass (ADR 0008 D8): the newest version the memory knows of each
//! item of a provider scope, the state of staged rows after a drain, a dead
//! letter for provider material that never became a draft, the collector's
//! status row, and retiring the worker's unconfigured collectors.
//!
//! Every statement binds the sink's `(tenant_id, project)` first.

use std::collections::BTreeMap;
use std::sync::Arc;

use sqlx::Row as _;
use sqlx::postgres::PgRow;

use crate::error::{FleetError, Result};
use crate::memory_contracts::collected_item::{
    CollectedItemEnvelopeV1, CollectionModeV1, ItemLifecycleV1, ObjectKindV1, ProviderKindV1,
    TrustTierV1,
};
use crate::memory_contracts::digest::Sha256Digest;
use crate::store::cockroach::with_serializable_retry;

use super::{CollectedItemSink, DeadLetterReasonV1, MAX_DELIVERY_ID_BYTES, dead_letter_id};
use crate::collectors::cockroach::{
    INSERT_DEAD_LETTER_SQL, MAX_DEAD_LETTER_DIAGNOSTIC_BYTES, ROW_STATES_SQL, SCOPE_HEADS_SQL,
    SCOPE_PENDING_SQL, bounded, digest_column, optional_digest_column, statement_time,
};
use crate::collectors::status::{
    CollectorSourceStatusV1, retire_worker_collectors, upsert_collector_source,
};

/// The newest version the memory knows of one item: its tier's head, or a
/// newer version still pending in the outbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownVersionV1 {
    /// The item key.
    pub item_key: Sha256Digest,
    /// The version key.
    pub version_key: Sha256Digest,
    /// The version's content digest.
    pub content_digest: Sha256Digest,
    /// The version's lifecycle.
    pub lifecycle: ItemLifecycleV1,
    /// The version's provider order.
    pub provider_order: u64,
    /// The stage ids of the version's parts that are still pending; empty
    /// when the version heads its tier, which only a complete version does.
    pub pending: Vec<Sha256Digest>,
}

/// Where one staged row stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboxRowStateV1 {
    /// Waiting for a drain.
    Pending,
    /// Admitted as this accepted event.
    Admitted(Sha256Digest),
    /// Quarantined by the ledger.
    Quarantined,
    /// Refused and dead-lettered.
    DeadLettered,
}

/// A dead letter for provider material that never became a draft: a file
/// that is not UTF-8, a page that could not be parsed. Digest only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectorDeadLetterV1 {
    /// The channel it arrived through.
    pub mode: CollectionModeV1,
    /// Why.
    pub reason: DeadLetterReasonV1,
    /// A digest of the refused material; the only trace of it that is kept.
    pub payload_digest: Sha256Digest,
    /// The transport delivery, when there was one (1 to 64 bytes).
    pub delivery_id: Option<Vec<u8>>,
    /// A static diagnostic; never provider content.
    pub diagnostic: String,
}

/// One version seen in the outbox, while reading pending rows.
struct PendingVersionV1 {
    external_id: String,
    object_kind: String,
    known: KnownVersionV1,
}

impl CollectedItemSink {
    /// The newest version the memory knows of every item of one provider
    /// scope and object kind, through the channels of `tier`, keyed by
    /// external id: the tier's head, or a newer version whose parts are still
    /// pending (a version staged by a tick that did not get to drain it).
    ///
    /// # Errors
    ///
    /// A database failure, or a stored row outside its bounds.
    pub async fn known_versions(
        &self,
        provider: &ProviderKindV1,
        provider_scope_id: &str,
        object_kind: &ObjectKindV1,
        tier: TrustTierV1,
    ) -> Result<BTreeMap<String, KnownVersionV1>> {
        let heads: Vec<PgRow> = sqlx::query(SCOPE_HEADS_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(provider.as_str())
            .bind(provider_scope_id)
            .bind(object_kind.as_str())
            .bind(tier.as_str())
            .fetch_all(&self.pool)
            .await?;
        let mut known = BTreeMap::new();
        for row in &heads {
            let order: i64 = row.try_get("provider_order")?;
            known.insert(
                row.try_get::<String, _>("external_id")?,
                KnownVersionV1 {
                    item_key: digest_column(row, "item_key_digest")?,
                    version_key: digest_column(row, "version_key_digest")?,
                    content_digest: digest_column(row, "content_digest")?,
                    lifecycle: ItemLifecycleV1::parse(&row.try_get::<String, _>("lifecycle")?)?,
                    provider_order: u64::try_from(order).map_err(|_| {
                        FleetError::Memory("a stored head order is negative".to_owned())
                    })?,
                    pending: Vec::new(),
                },
            );
        }
        let modes: Vec<&str> = CollectionModeV1::ALL
            .iter()
            .filter(|mode| mode.trust_tier() == tier)
            .map(|mode| mode.as_str())
            .collect();
        let pending: Vec<PgRow> = sqlx::query(SCOPE_PENDING_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(provider.as_str())
            .bind(provider_scope_id)
            .bind(&modes)
            .fetch_all(&self.pool)
            .await?;
        let mut versions: BTreeMap<Sha256Digest, PendingVersionV1> = BTreeMap::new();
        for row in &pending {
            let stage_id = digest_column(row, "stage_id")?;
            let version_key = digest_column(row, "version_key_digest")?;
            if let Some(version) = versions.get_mut(&version_key) {
                version.known.pending.push(stage_id);
                continue;
            }
            // Every part's envelope names its item; the first one read is
            // enough for the version.
            let envelope: Option<Vec<u8>> = row.try_get("canonical_envelope")?;
            let envelope = CollectedItemEnvelopeV1::decode(&envelope.ok_or_else(|| {
                FleetError::Memory("a pending collector row has no envelope".to_owned())
            })?)?;
            let order: i64 = row.try_get("provider_order")?;
            versions.insert(
                version_key,
                PendingVersionV1 {
                    external_id: envelope.external_id.as_str().to_owned(),
                    object_kind: envelope.object_kind.as_str().to_owned(),
                    known: KnownVersionV1 {
                        item_key: envelope.item_key(),
                        version_key,
                        content_digest: envelope.content_digest,
                        lifecycle: envelope.lifecycle,
                        provider_order: u64::try_from(order).map_err(|_| {
                            FleetError::Memory("a staged order is negative".to_owned())
                        })?,
                        pending: vec![stage_id],
                    },
                },
            );
        }
        for version in versions.into_values() {
            if version.object_kind != object_kind.as_str() {
                continue;
            }
            // A pending version at least as new as the head is what the
            // memory will present once it is drained.
            match known.get(&version.external_id) {
                Some(current) if current.provider_order > version.known.provider_order => {}
                Some(current)
                    if current.provider_order == version.known.provider_order
                        && !current.pending.is_empty() => {}
                _ => {
                    known.insert(version.external_id, version.known);
                }
            }
        }
        Ok(known)
    }

    /// The state of each named row that exists, by stage id.
    ///
    /// # Errors
    ///
    /// A database failure, or a stored state this build does not know.
    pub async fn row_states(
        &self,
        stage_ids: &[Sha256Digest],
    ) -> Result<BTreeMap<Sha256Digest, OutboxRowStateV1>> {
        let mut states = BTreeMap::new();
        for chunk in stage_ids.chunks(1_024) {
            let ids: Vec<Vec<u8>> = chunk.iter().map(|id| id.as_bytes().to_vec()).collect();
            let rows: Vec<PgRow> = sqlx::query(ROW_STATES_SQL)
                .bind(self.tenant_id)
                .bind(&self.project)
                .bind(&ids)
                .fetch_all(&self.pool)
                .await?;
            for row in &rows {
                let state: String = row.try_get("state")?;
                let state = match state.as_str() {
                    "pending" => OutboxRowStateV1::Pending,
                    "admitted" => OutboxRowStateV1::Admitted(
                        optional_digest_column(row, "accepted_event_id")?.ok_or_else(|| {
                            FleetError::Memory(
                                "an admitted collector row names no accepted event".to_owned(),
                            )
                        })?,
                    ),
                    "quarantined" => OutboxRowStateV1::Quarantined,
                    "dead_lettered" => OutboxRowStateV1::DeadLettered,
                    other => {
                        return Err(FleetError::Memory(format!(
                            "a collector row is in an unknown state {other:?}"
                        )));
                    }
                };
                states.insert(digest_column(row, "stage_id")?, state);
            }
        }
        Ok(states)
    }

    /// Record a digest-only dead letter for `instance` that no draft carries.
    /// Recording the same one again is a no-op.
    ///
    /// # Errors
    ///
    /// [`FleetError::Configuration`] for a delivery id outside its bounds; a
    /// database failure.
    pub async fn record_dead_letter(
        &self,
        instance: &crate::memory_contracts::common::ContractId,
        provider: &ProviderKindV1,
        letter: &CollectorDeadLetterV1,
    ) -> Result<()> {
        if letter
            .delivery_id
            .as_ref()
            .is_some_and(|id| id.is_empty() || id.len() > MAX_DELIVERY_ID_BYTES)
        {
            return Err(FleetError::Configuration(
                "a delivery id is 1 to 64 bytes".to_owned(),
            ));
        }
        let (tenant_id, project) = (self.tenant_id, self.project.clone());
        let instance = instance.as_str().to_owned();
        let provider = provider.as_str().to_owned();
        let letter = Arc::new(letter.clone());
        with_serializable_retry(&self.pool, self.retry, move |transaction| {
            let (project, instance, provider, letter) = (
                project.clone(),
                instance.clone(),
                provider.clone(),
                Arc::clone(&letter),
            );
            Box::pin(async move {
                let now = statement_time(transaction).await?;
                let id = dead_letter_id(&instance, letter.reason, &letter.payload_digest, None);
                sqlx::query(INSERT_DEAD_LETTER_SQL)
                    .bind(tenant_id)
                    .bind(&project)
                    .bind(id.as_bytes().as_slice())
                    .bind(&instance)
                    .bind(letter.mode.as_str())
                    .bind(&provider)
                    .bind(letter.reason.as_str())
                    .bind(None::<Vec<u8>>)
                    .bind(letter.delivery_id.as_deref())
                    .bind(letter.payload_digest.as_bytes().as_slice())
                    .bind(bounded(
                        &letter.diagnostic,
                        MAX_DEAD_LETTER_DIAGNOSTIC_BYTES,
                    ))
                    .bind(now)
                    .execute(&mut **transaction)
                    .await?;
                Ok(())
            })
        })
        .await
    }

    /// Upsert one collector's status row in its own transaction.
    ///
    /// # Errors
    ///
    /// As [`upsert_collector_source`].
    pub async fn record_status(&self, status: &CollectorSourceStatusV1) -> Result<()> {
        status.validate()?;
        let (tenant_id, project) = (self.tenant_id, self.project.clone());
        let status = Arc::new(status.clone());
        with_serializable_retry(&self.pool, self.retry, move |transaction| {
            let (project, status) = (project.clone(), Arc::clone(&status));
            Box::pin(async move {
                upsert_collector_source(transaction, tenant_id, &project, &status).await
            })
        })
        .await
    }

    /// Retire every active collector row the worker owns whose instance is
    /// not in `configured`; the number retired.
    ///
    /// # Errors
    ///
    /// A database failure.
    pub async fn retire_worker_collectors(&self, configured: &[String]) -> Result<u64> {
        let (tenant_id, project) = (self.tenant_id, self.project.clone());
        let configured = Arc::new(configured.to_vec());
        with_serializable_retry(&self.pool, self.retry, move |transaction| {
            let (project, configured) = (project.clone(), Arc::clone(&configured));
            Box::pin(async move {
                retire_worker_collectors(transaction, tenant_id, &project, &configured).await
            })
        })
        .await
    }
}
