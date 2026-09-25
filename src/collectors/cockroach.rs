//! `CockroachDB` statements of the collected-item sink (migrations 0033 and
//! 0034).
//!
//! Every statement binds `tenant_id = $1` and `project = $2` first, so no
//! stored value and no request field can move a read or a write into another
//! scope. The outbox, the heads, the collector status, the cursors, the
//! containers, and the item withdrawals take locking reads and
//! compare-and-set upserts; the item history, its links, and the dead letters
//! are only ever inserted. Nothing here deletes: a lifted withdrawal is
//! updated. None of these tables is a publication table.
//!
//! The helpers run inside a caller's transaction: the sink's staging
//! transaction, or the append transaction of the drain's projection.

use chrono::{DateTime, Utc};
use sha2::{Digest as _, Sha256};
use sqlx::postgres::PgRow;
use sqlx::{Postgres, Row as _, Transaction};
use uuid::Uuid;

use crate::memory_contracts::collected_item::AudienceBasisV1;
use crate::memory_contracts::digest::Sha256Digest;

use crate::memory_contracts::collected_item::TrustTierV1;

use super::audience::KnownContainerV1;
use super::withdrawal::{ContainerAccessV1, ItemWithdrawalStateV1, StoredContainerV1};

/// Longest `last_error` an outbox row keeps.
pub const MAX_OUTBOX_ERROR_BYTES: usize = 512;

/// Longest diagnostic a dead letter keeps.
pub const MAX_DEAD_LETTER_DIAGNOSTIC_BYTES: usize = 512;

/// Attempts after which a row that keeps failing to append is dead-lettered.
pub const MAX_DRAIN_ATTEMPTS: i64 = 8;

pub(super) const STATEMENT_TIME_SQL: &str = "SELECT pg_catalog.statement_timestamp()";

pub(super) const SELECT_CONTAINER_SQL: &str = "SELECT audience_basis, access \
     FROM public.memory_collector_containers_v1 \
     WHERE tenant_id = $1 AND project = $2 AND container_key = $3";

/// One container row, locked for [`super::withdrawal::container_write`].
pub(super) const LOCK_CONTAINER_SQL: &str = "SELECT access, observed_tier \
     FROM public.memory_collector_containers_v1 \
     WHERE tenant_id = $1 AND project = $2 AND container_key = $3 FOR UPDATE";

/// Record a container as readable: a new row, or a recorded one re-opened or
/// relabelled by a channel that may.
pub(super) const RECORD_CONTAINER_SQL: &str = "INSERT INTO public.memory_collector_containers_v1 (\
     tenant_id, project, container_key, provider, provider_scope_id, container_kind, \
     container_id, label, audience_basis, access, observed_by_instance, observed_at, updated_at, \
     observed_tier\
     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'ok', $10, $11, $11, $12) \
     ON CONFLICT (tenant_id, project, container_key) DO UPDATE SET \
     label = excluded.label, audience_basis = excluded.audience_basis, access = 'ok', \
     observed_by_instance = excluded.observed_by_instance, \
     observed_at = excluded.observed_at, updated_at = excluded.updated_at, \
     observed_tier = excluded.observed_tier";

/// Record a container nothing was admitted through as withdrawn: no label,
/// no audience basis.
pub(super) const RECORD_WITHDRAWN_CONTAINER_SQL: &str = "INSERT INTO \
     public.memory_collector_containers_v1 (\
     tenant_id, project, container_key, provider, provider_scope_id, container_kind, \
     container_id, label, audience_basis, access, observed_by_instance, observed_at, updated_at, \
     observed_tier\
     ) VALUES ($1, $2, $3, $4, $5, $6, $7, NULL, 'none', 'withdrawn', $8, $9, $9, $10) \
     ON CONFLICT (tenant_id, project, container_key) DO NOTHING";

/// A container whose audience is no longer admissible is withdrawn, never
/// deleted: every item in it is then withheld at read time. The same
/// statement makes a report's withdrawal a verified one.
pub(super) const WITHDRAW_CONTAINER_SQL: &str = "UPDATE public.memory_collector_containers_v1 \
     SET access = 'withdrawn', observed_tier = $4, observed_by_instance = $5, \
     observed_at = $6, updated_at = $6 \
     WHERE tenant_id = $1 AND project = $2 AND container_key = $3";

/// The item-withdrawal rows of a batch of items, locked.
pub(super) const LOCK_ITEM_WITHDRAWALS_SQL: &str = "SELECT item_key_digest, observed_tier, \
     withdrawn, observed_order \
     FROM public.memory_collected_item_withdrawals_v1 \
     WHERE tenant_id = $1 AND project = $2 AND item_key_digest = ANY($3::BYTES[]) FOR UPDATE";

/// Whether the memory holds any admitted or staged part of an item, and the
/// greatest provider order at which one of the channels in `$4` staged it.
pub(super) const ITEM_SEEN_SQL: &str = "SELECT \
     (EXISTS (SELECT 1 FROM public.memory_collected_items_v1 \
        WHERE tenant_id = $1 AND project = $2 AND item_key_digest = $3) \
      OR EXISTS (SELECT 1 FROM public.memory_collector_outbox_v1 \
        WHERE tenant_id = $1 AND project = $2 AND item_key_digest = $3 \
          AND state = 'pending')) AS seen, \
     GREATEST(\
       (SELECT max(provider_order) FROM public.memory_collected_items_v1 \
          WHERE tenant_id = $1 AND project = $2 AND item_key_digest = $3 \
            AND collection_mode = ANY($4::STRING[])), \
       (SELECT max(provider_order) FROM public.memory_collector_outbox_v1 \
          WHERE tenant_id = $1 AND project = $2 AND item_key_digest = $3 \
            AND state = 'pending' AND collection_mode = ANY($4::STRING[]))\
     ) AS newest_admissible";

/// Withdraw an item for one tier.
pub(super) const WITHDRAW_ITEM_SQL: &str = "INSERT INTO \
     public.memory_collected_item_withdrawals_v1 (\
     tenant_id, project, item_key_digest, observed_tier, withdrawn, observed_order, reason, \
     collection_mode, observed_by_instance, observed_at, updated_at\
     ) VALUES ($1, $2, $3, $4, true, $5, $6, $7, $8, $9, $9) \
     ON CONFLICT (tenant_id, project, item_key_digest, observed_tier) DO UPDATE SET \
     withdrawn = true, observed_order = excluded.observed_order, reason = excluded.reason, \
     collection_mode = excluded.collection_mode, \
     observed_by_instance = excluded.observed_by_instance, \
     observed_at = excluded.observed_at, updated_at = excluded.updated_at";

/// Lift one tier's item withdrawal, or move a lifted row's order forward.
/// The reason of the last withdrawal stays.
pub(super) const LIFT_ITEM_SQL: &str = "UPDATE public.memory_collected_item_withdrawals_v1 \
     SET withdrawn = false, observed_order = $5, collection_mode = $6, \
     observed_by_instance = $7, observed_at = $8, updated_at = $8 \
     WHERE tenant_id = $1 AND project = $2 AND item_key_digest = $3 AND observed_tier = $4";

pub(super) const INSERT_OUTBOX_SQL: &str = "INSERT INTO public.memory_collector_outbox_v1 (\
     tenant_id, project, stage_id, collector_instance_id, principal_id, collection_mode, \
     attester_principal_id, provider, provider_scope_id, item_key_digest, version_key_digest, \
     container_key, part_ordinal, part_count, provider_order, pass_seq, canonical_envelope, \
     envelope_sha256, delivery_id, occurred_at, observed_at, received_at, state, \
     accepted_event_id, quarantine_id, attempts, last_error, created_at, settled_at\
     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, \
     $18, $19, $20, $21, $21, 'pending', NULL, NULL, 0, NULL, $21, NULL) \
     ON CONFLICT (tenant_id, project, stage_id) DO NOTHING";

pub(super) const INSERT_DEAD_LETTER_SQL: &str = "INSERT INTO public.memory_collector_dead_letters_v1 (\
     tenant_id, project, dead_letter_id, collector_instance_id, collection_mode, provider, \
     reason, stage_id, delivery_id, payload_digest, diagnostic, created_at\
     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
     ON CONFLICT (tenant_id, project, dead_letter_id) DO NOTHING";

pub(super) const UPSERT_CURSOR_SQL: &str = "INSERT INTO public.memory_collector_cursors_v1 (\
     tenant_id, project, collector_instance_id, domain_key, cursor_state, high_water_order, \
     pass_seq, updated_at\
     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
     ON CONFLICT (tenant_id, project, collector_instance_id, domain_key) DO UPDATE SET \
     cursor_state = excluded.cursor_state, high_water_order = excluded.high_water_order, \
     pass_seq = excluded.pass_seq, updated_at = excluded.updated_at";

pub(super) const SELECT_CURSOR_SQL: &str = "SELECT cursor_state, high_water_order, pass_seq, \
     updated_at FROM public.memory_collector_cursors_v1 \
     WHERE tenant_id = $1 AND project = $2 AND collector_instance_id = $3 AND domain_key = $4";

const PENDING_COLUMNS: &str = "stage_id, collector_instance_id, principal_id, collection_mode, \
     provider, provider_scope_id, canonical_envelope, envelope_sha256, delivery_id, \
     occurred_at, observed_at, received_at, attempts";

/// The oldest pending rows, in staging order.
pub(super) fn select_pending_sql() -> String {
    format!(
        "SELECT {PENDING_COLUMNS} FROM public.memory_collector_outbox_v1 \
         WHERE tenant_id = $1 AND project = $2 AND state = 'pending' \
         ORDER BY created_at, stage_id LIMIT $3"
    )
}

/// The named rows that are still pending, in staging order.
pub(super) fn select_pending_by_id_sql() -> String {
    format!(
        "SELECT {PENDING_COLUMNS} FROM public.memory_collector_outbox_v1 \
         WHERE tenant_id = $1 AND project = $2 AND state = 'pending' \
           AND stage_id = ANY($3::BYTES[]) \
         ORDER BY created_at, stage_id"
    )
}

pub(super) const SELECT_ROW_STATE_SQL: &str = "SELECT state, accepted_event_id, attempts \
     FROM public.memory_collector_outbox_v1 \
     WHERE tenant_id = $1 AND project = $2 AND stage_id = $3";

pub(super) const LOCK_PENDING_ROW_SQL: &str = "SELECT attempts \
     FROM public.memory_collector_outbox_v1 \
     WHERE tenant_id = $1 AND project = $2 AND stage_id = $3 AND state = 'pending' FOR UPDATE";

/// Settle a row as admitted, in the append's own transaction. The envelope's
/// redacted text leaves the outbox here; its digest stays.
pub(super) const MARK_ADMITTED_SQL: &str = "UPDATE public.memory_collector_outbox_v1 \
     SET state = 'admitted', accepted_event_id = $4, canonical_envelope = NULL, \
     settled_at = $5, last_error = NULL \
     WHERE tenant_id = $1 AND project = $2 AND stage_id = $3 AND state = 'pending'";

pub(super) const MARK_QUARANTINED_SQL: &str = "UPDATE public.memory_collector_outbox_v1 \
     SET state = 'quarantined', quarantine_id = $4, canonical_envelope = NULL, \
     settled_at = pg_catalog.statement_timestamp(), last_error = $5 \
     WHERE tenant_id = $1 AND project = $2 AND stage_id = $3 AND state = 'pending'";

pub(super) const MARK_DEAD_LETTERED_SQL: &str = "UPDATE public.memory_collector_outbox_v1 \
     SET state = 'dead_lettered', canonical_envelope = NULL, settled_at = $4, \
     last_error = $5, attempts = $6 \
     WHERE tenant_id = $1 AND project = $2 AND stage_id = $3 AND state = 'pending'";

pub(super) const BUMP_ATTEMPTS_SQL: &str = "UPDATE public.memory_collector_outbox_v1 \
     SET attempts = $4, last_error = $5 \
     WHERE tenant_id = $1 AND project = $2 AND stage_id = $3 AND state = 'pending'";

/// Before an admitted part's history row is written: whether its ordinal was
/// already admitted for the version in the tier, and how many distinct
/// ordinals were.
pub(super) const PART_STATE_SQL: &str = "SELECT \
     count(DISTINCT part_ordinal)::INT8 AS distinct_parts, \
     COALESCE(bool_or(part_ordinal = $6), false) AS has_part \
     FROM public.memory_collected_items_v1 \
     WHERE tenant_id = $1 AND project = $2 AND item_key_digest = $3 \
       AND version_key_digest = $4 AND trust_tier = $5";

pub(super) const INSERT_ITEM_SQL: &str = "INSERT INTO public.memory_collected_items_v1 (\
     tenant_id, project, accepted_event_id, stage_id, item_key_digest, version_key_digest, \
     part_ordinal, part_count, provider, provider_scope_id, object_kind, external_id, \
     collection_mode, trust_tier, collector_instance_id, attester_principal_id, lifecycle, \
     version_marker, provider_order, redaction_profile, container_key, \
     thread_root_external_id, author_id, author_kind, provider_created_at, \
     provider_updated_at, provider_url, canonical_resource_id, body_content_id, \
     content_digest, audience_basis, admitted_at\
     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, \
     $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32)";

pub(super) const INSERT_LINK_SQL: &str = "INSERT INTO public.memory_collected_item_links_v1 (\
     tenant_id, project, accepted_event_id, link_ordinal, rel, target\
     ) VALUES ($1, $2, $3, $4, $5, $6)";

/// Both tier rows of one item, locked for the move rule.
pub(super) const LOCK_HEADS_SQL: &str = "SELECT trust_tier, presented, version_key_digest, \
     content_digest, provider_order, redaction_profile, lifecycle, part_count, container_key, \
     version_count, order_ties, disagreement, revision \
     FROM public.memory_collected_item_heads_v1 \
     WHERE tenant_id = $1 AND project = $2 AND item_key_digest = $3 \
     ORDER BY trust_tier FOR UPDATE";

pub(super) const UPSERT_HEAD_SQL: &str = "INSERT INTO public.memory_collected_item_heads_v1 (\
     tenant_id, project, item_key_digest, trust_tier, presented, provider, provider_scope_id, \
     object_kind, external_id, container_key, version_key_digest, content_digest, \
     provider_order, redaction_profile, lifecycle, part_count, version_count, order_ties, \
     disagreement, last_accepted_event_id, revision, updated_at\
     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, \
     $18, $19, $20, $21, $22) \
     ON CONFLICT (tenant_id, project, item_key_digest, trust_tier) DO UPDATE SET \
     presented = excluded.presented, container_key = excluded.container_key, \
     version_key_digest = excluded.version_key_digest, content_digest = excluded.content_digest, \
     provider_order = excluded.provider_order, redaction_profile = excluded.redaction_profile, \
     lifecycle = excluded.lifecycle, part_count = excluded.part_count, \
     version_count = excluded.version_count, order_ties = excluded.order_ties, \
     disagreement = excluded.disagreement, \
     last_accepted_event_id = excluded.last_accepted_event_id, \
     revision = excluded.revision, updated_at = excluded.updated_at";

pub(super) const UPDATE_HEAD_PRESENTATION_SQL: &str = "UPDATE public.memory_collected_item_heads_v1 \
     SET presented = $5, disagreement = $6, revision = revision + 1, updated_at = $7 \
     WHERE tenant_id = $1 AND project = $2 AND item_key_digest = $3 AND trust_tier = $4";

/// The heads of one provider scope's items of one object kind, in one tier:
/// what a pull collector compares a fresh read with.
pub(super) const SCOPE_HEADS_SQL: &str = "SELECT item_key_digest, external_id, \
     version_key_digest, content_digest, lifecycle, provider_order \
     FROM public.memory_collected_item_heads_v1 \
     WHERE tenant_id = $1 AND project = $2 AND provider = $3 AND provider_scope_id = $4 \
       AND object_kind = $5 AND trust_tier = $6";

/// The pending rows of one provider scope staged through the channels in
/// `$5`, with their envelopes, which name each row's item.
pub(super) const SCOPE_PENDING_SQL: &str = "SELECT stage_id, version_key_digest, \
     provider_order, canonical_envelope \
     FROM public.memory_collector_outbox_v1 \
     WHERE tenant_id = $1 AND project = $2 AND state = 'pending' AND provider = $3 \
       AND provider_scope_id = $4 AND collection_mode = ANY($5::STRING[]) \
     ORDER BY created_at, stage_id";

/// The state of each named row.
pub(super) const ROW_STATES_SQL: &str = "SELECT stage_id, state, accepted_event_id \
     FROM public.memory_collector_outbox_v1 \
     WHERE tenant_id = $1 AND project = $2 AND stage_id = ANY($3::BYTES[])";

/// Pending staged parts in one scope: what readiness reports as awaiting
/// admission.
pub const COUNT_PENDING_SQL: &str = "SELECT count(*)::INT8 \
     FROM public.memory_collector_outbox_v1 \
     WHERE tenant_id = $1 AND project = $2 AND state = 'pending'";

/// Whether a collected body is withheld from recall.
///
/// It is when its item's presented head is a tombstone, its container was
/// withdrawn, or the item itself was withdrawn for either tier.
/// `body_column` names the outer row's body id column, `$1`/`$2` its scope.
#[must_use]
pub fn suppressed_body_predicate(body_column: &str) -> String {
    format!(
        "EXISTS (SELECT 1 FROM public.memory_collected_items_v1 AS item \
         LEFT JOIN public.memory_collected_item_heads_v1 AS head \
           ON head.tenant_id = item.tenant_id AND head.project = item.project \
          AND head.item_key_digest = item.item_key_digest AND head.presented \
         LEFT JOIN public.memory_collector_containers_v1 AS container \
           ON container.tenant_id = item.tenant_id AND container.project = item.project \
          AND container.container_key = item.container_key \
         WHERE item.tenant_id = $1 AND item.project = $2 \
           AND item.body_content_id = {body_column} \
           AND (head.lifecycle IN ('deleted', 'trashed', 'revoked') \
                OR container.access = 'withdrawn' \
                OR EXISTS (SELECT 1 FROM public.memory_collected_item_withdrawals_v1 AS withdrawal \
                    WHERE withdrawal.tenant_id = $1 AND withdrawal.project = $2 \
                      AND withdrawal.item_key_digest = item.item_key_digest \
                      AND withdrawal.withdrawn)))"
    )
}

/// One container row as the withdrawal rules read it, locked; `None` when
/// the memory never recorded it.
pub(super) async fn lock_container(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    project: &str,
    container_key: &Sha256Digest,
) -> sqlx::Result<Option<StoredContainerV1>> {
    let row: Option<PgRow> = sqlx::query(LOCK_CONTAINER_SQL)
        .bind(tenant_id)
        .bind(project)
        .bind(container_key.as_bytes().as_slice())
        .fetch_optional(&mut **transaction)
        .await?;
    row.map(|row| {
        let access: String = row.try_get("access")?;
        let tier: Option<String> = row.try_get("observed_tier")?;
        Ok(StoredContainerV1 {
            access: if access == "ok" {
                ContainerAccessV1::Ok
            } else {
                ContainerAccessV1::Withdrawn
            },
            // A row from before migration 0034 is read as verified, so no
            // report can override it.
            tier: match tier.as_deref() {
                Some("reported") => TrustTierV1::Reported,
                _ => TrustTierV1::Verified,
            },
        })
    })
    .transpose()
}

/// The locked item-withdrawal rows of `item_keys`, by item and tier.
pub(super) async fn lock_item_withdrawals(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    project: &str,
    item_keys: &[Sha256Digest],
) -> sqlx::Result<std::collections::BTreeMap<(Sha256Digest, TrustTierV1), ItemWithdrawalStateV1>> {
    let keys: Vec<Vec<u8>> = item_keys
        .iter()
        .map(|key| key.as_bytes().to_vec())
        .collect();
    let rows: Vec<PgRow> = sqlx::query(LOCK_ITEM_WITHDRAWALS_SQL)
        .bind(tenant_id)
        .bind(project)
        .bind(&keys)
        .fetch_all(&mut **transaction)
        .await?;
    let mut stored = std::collections::BTreeMap::new();
    for row in &rows {
        let tier: String = row.try_get("observed_tier")?;
        let tier = TrustTierV1::parse(&tier).map_err(|_| sqlx::Error::ColumnDecode {
            index: "observed_tier".to_owned(),
            source: "a stored withdrawal tier is not known".into(),
        })?;
        let order: i64 = row.try_get("observed_order")?;
        stored.insert(
            (digest_column(row, "item_key_digest")?, tier),
            ItemWithdrawalStateV1 {
                withdrawn: row.try_get("withdrawn")?,
                order: u64::try_from(order).map_err(|_| sqlx::Error::ColumnDecode {
                    index: "observed_order".to_owned(),
                    source: "a stored withdrawal order is negative".into(),
                })?,
            },
        );
    }
    Ok(stored)
}

/// What the memory recorded about one container.
pub(super) async fn known_container(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    project: &str,
    container_key: &Sha256Digest,
) -> sqlx::Result<KnownContainerV1> {
    let row: Option<PgRow> = sqlx::query(SELECT_CONTAINER_SQL)
        .bind(tenant_id)
        .bind(project)
        .bind(container_key.as_bytes().as_slice())
        .fetch_optional(&mut **transaction)
        .await?;
    let Some(row) = row else {
        return Ok(KnownContainerV1::Unknown);
    };
    let access: String = row.try_get("access")?;
    if access != "ok" {
        return Ok(KnownContainerV1::Withdrawn);
    }
    let basis: String = row.try_get("audience_basis")?;
    // A basis this build does not know cannot vouch for anything.
    Ok(
        AudienceBasisV1::parse(&basis)
            .map_or(KnownContainerV1::Unknown, KnownContainerV1::Readable),
    )
}

/// The database's clock inside `transaction`.
pub(super) async fn statement_time(
    transaction: &mut Transaction<'_, Postgres>,
) -> sqlx::Result<DateTime<Utc>> {
    sqlx::query_scalar(STATEMENT_TIME_SQL)
        .fetch_one(&mut **transaction)
        .await
}

/// A 32-byte digest column.
pub(super) fn digest_column(row: &PgRow, column: &str) -> sqlx::Result<Sha256Digest> {
    let bytes: Vec<u8> = row.try_get(column)?;
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| sqlx::Error::ColumnDecode {
        index: column.to_owned(),
        source: format!("stored {column} is not 32 bytes").into(),
    })?;
    Ok(Sha256Digest::from_bytes(bytes))
}

/// An optional 32-byte digest column.
pub(super) fn optional_digest_column(
    row: &PgRow,
    column: &str,
) -> sqlx::Result<Option<Sha256Digest>> {
    let bytes: Option<Vec<u8>> = row.try_get(column)?;
    bytes
        .map(|bytes| {
            let bytes: [u8; 32] = bytes.try_into().map_err(|_| sqlx::Error::ColumnDecode {
                index: column.to_owned(),
                source: format!("stored {column} is not 32 bytes").into(),
            })?;
            Ok(Sha256Digest::from_bytes(bytes))
        })
        .transpose()
}

/// `text` cut to at most `limit` bytes on a character boundary.
#[must_use]
pub fn bounded(text: &str, limit: usize) -> String {
    if text.len() <= limit {
        return text.to_owned();
    }
    let mut end = limit;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

/// SHA-256 over a label and length-framed parts: the digest dead letters and
/// draft fingerprints are keyed by.
#[must_use]
pub fn framed_sha256(label: &str, parts: &[&[u8]]) -> Sha256Digest {
    let mut hash = Sha256::new();
    hash.update(u64::try_from(label.len()).unwrap_or(u64::MAX).to_be_bytes());
    hash.update(label.as_bytes());
    for part in parts {
        hash.update(u64::try_from(part.len()).unwrap_or(u64::MAX).to_be_bytes());
        hash.update(part);
    }
    Sha256Digest::from_bytes(hash.finalize().into())
}
