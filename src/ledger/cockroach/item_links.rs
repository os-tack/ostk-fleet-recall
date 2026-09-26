//! Claims that cite collected items (ADR 0008 D11, migration 0035).
//!
//! A claim cites an item with `remember(assert)`'s `assertion.support_items`
//! or a `record` (or `supersede` successor) support entry `{item: ...}`. The
//! reference names the item (`item_id`, or its provider `url`), whose
//! presented version is cited, or one exact version (`version_id`). This
//! module resolves it in the claim's own `(tenant_id, project)`, to one
//! admitted part per ordinal of that version, each an accepted evidence
//! event:
//!
//! * a reference that names nothing admitted, and nothing pending, is
//!   refused as `support_item_unknown`;
//! * one whose item (or version) is staged but not yet admitted (a
//!   `stage_only` capture, a drain still to run) as `support_item_pending`;
//! * one whose item is hidden from recall (its presented head a tombstone,
//!   its container or the item withdrawn), or that names a tombstone
//!   version or one admitted in a container since withdrawn, as
//!   `support_item_withdrawn`.
//!
//! A URL names the item a verified channel admitted under it before any a
//! capture or an import reported, so an agent's capture cannot take over a
//! collected item's permalink. An assertion that lists a collected item's
//! accepted event directly in `support_evidence_event_ids` is audited by the
//! same rule in its append transaction, and linked like a citation.
//!
//! Each cited part gets one row in the private `memory_claim_item_links_v1`,
//! keyed by the claim and the part's event: `via = 'assert'` rows name the
//! claim's own accepted event, `via = 'record'` rows share a random link id
//! that the claim's opaque `memory_claim_support` row (`fleet.item`,
//! `item-link`, the link id in hex) names. The publication reader can read
//! that support row, never which item it cites.
//!
//! Every statement binds `tenant_id = $1` and `project = $2` first, and none
//! writes anything but the links and the opaque support row.

use std::collections::{BTreeMap, BTreeSet};

use ring::rand::{SecureRandom as _, SystemRandom};
use serde_json::{Value, json};
use sqlx::postgres::{PgPool, PgRow};
use sqlx::{PgConnection, Row as _};

use super::protocol_error;
use crate::evidence_recall::ContentTrustV1;
use crate::item_recall::ItemSuppressionV1;
use crate::ledger::lifecycle::{LifecycleRefusal, RefusalCode};
use crate::ledger::{
    CitedItemV1, ClaimItemSupportV1, ClaimSupport, ITEM_SUPPORT_SOURCE,
    ITEM_SUPPORT_SOURCE_CONFIG_ID, ItemRefV1, MAX_SUPPORT_ITEMS,
};
use crate::memory_contracts::collected_item::{ItemLifecycleV1, TrustTierV1};
use crate::memory_contracts::digest::Sha256Digest;
use crate::memory_contracts::evidence::AcceptedEventId;
use crate::{FleetError, FleetScope, Result};

/// The `via` of a link an assert wrote.
pub(super) const VIA_ASSERT: &str = "assert";
/// The `via` of a link a record (or supersede successor) wrote.
pub(super) const VIA_RECORD: &str = "record";
/// The relation an assert's citations carry: an assertion's support has no
/// relation of its own.
const ASSERT_RELATION: &str = "supports";

/// Link rows one claim expansion reads: [`MAX_SUPPORT_ITEMS`] citations of
/// at most 64 parts each, plus one row to tell a cut read.
const MAX_CLAIM_LINK_ROWS: i64 = 32 * 64 + 1;

/// The item a provider URL names (`memory_collected_items_url_idx`), as
/// `recall(get, kind=item)` resolves it: an item a verified channel admitted
/// under that URL first, then the greatest provider order. A capture's URL is
/// the agent's word, so it can never take a verified item's permalink over.
const ITEM_BY_URL_SQL: &str = "SELECT item_key_digest FROM public.memory_collected_items_v1 \
     WHERE tenant_id = $1 AND project = $2 AND provider_url = $3 \
     ORDER BY (trust_tier = 'verified') DESC, provider_order DESC, item_key_digest LIMIT 1";

/// The item a version id belongs to. A version key has no index of its own,
/// so this reads the scope's item history, as a get by version URI does.
const ITEM_BY_VERSION_SQL: &str = "SELECT item_key_digest FROM public.memory_collected_items_v1 \
     WHERE tenant_id = $1 AND project = $2 AND version_key_digest = $3 LIMIT 1";

/// Whether a version no admitted part names yet is staged and pending.
const VERSION_PENDING_SQL: &str = "SELECT EXISTS (\
       SELECT 1 FROM public.memory_collector_outbox_v1 \
       WHERE tenant_id = $1 AND project = $2 AND version_key_digest = $3 AND state = 'pending')";

/// Whether a part of an item (of version `$4`, or of any) is staged and
/// pending (`memory_collector_outbox_item_idx`).
const ITEM_PENDING_SQL: &str = "SELECT EXISTS (\
       SELECT 1 FROM public.memory_collector_outbox_v1 \
       WHERE tenant_id = $1 AND project = $2 AND item_key_digest = $3 AND state = 'pending' \
         AND ($4::BYTES IS NULL OR version_key_digest = $4))";

/// The presented head of an item, with what hides it: the rule
/// `recall(kind=item)` applies.
const PRESENTED_HEAD_SQL: &str = "SELECT head.version_key_digest, head.trust_tier, \
     head.lifecycle, head.object_kind, container.access AS container_access, \
     EXISTS (SELECT 1 FROM public.memory_collected_item_withdrawals_v1 AS withdrawal \
        WHERE withdrawal.tenant_id = $1 AND withdrawal.project = $2 \
          AND withdrawal.item_key_digest = $3 AND withdrawal.withdrawn) AS item_withdrawn \
     FROM public.memory_collected_item_heads_v1 AS head \
     LEFT JOIN public.memory_collector_containers_v1 AS container \
       ON container.tenant_id = head.tenant_id AND container.project = head.project \
      AND container.container_key = head.container_key \
     WHERE head.tenant_id = $1 AND head.project = $2 AND head.item_key_digest = $3 \
       AND head.presented";

/// One admitted part per ordinal of a version (`memory_collected_items_version_idx`):
/// the tier `$5`'s copy first, then the earliest admitted; with whether the
/// container that part was admitted in is withdrawn now.
const VERSION_PARTS_SQL: &str = "SELECT DISTINCT ON (item.part_ordinal) item.part_ordinal, \
     item.part_count, item.accepted_event_id, item.lifecycle, \
     COALESCE(container.access <> 'ok', false) AS container_withdrawn \
     FROM public.memory_collected_items_v1 AS item \
     LEFT JOIN public.memory_collector_containers_v1 AS container \
       ON container.tenant_id = item.tenant_id AND container.project = item.project \
      AND container.container_key = item.container_key \
     WHERE item.tenant_id = $1 AND item.project = $2 AND item.item_key_digest = $3 \
       AND item.version_key_digest = $4 \
     ORDER BY item.part_ordinal, (item.trust_tier = $5) DESC, item.admitted_at, \
              item.accepted_event_id";

/// The collected-item rows of a set of accepted events (the primary key),
/// each with what hides it now: its item's presented head a tombstone, the
/// head's container or its own withdrawn, or the item withdrawn. Rows of an
/// item with no presented head carry a NULL head lifecycle.
const CITED_EVENTS_SQL: &str = "SELECT item.accepted_event_id, item.item_key_digest, \
     item.version_key_digest, item.part_ordinal, item.object_kind, \
     head.lifecycle AS head_lifecycle, head_container.access AS head_container_access, \
     COALESCE(own_container.access <> 'ok', false) AS own_container_withdrawn, \
     EXISTS (SELECT 1 FROM public.memory_collected_item_withdrawals_v1 AS withdrawal \
        WHERE withdrawal.tenant_id = $1 AND withdrawal.project = $2 \
          AND withdrawal.item_key_digest = item.item_key_digest AND withdrawal.withdrawn) \
        AS item_withdrawn \
     FROM public.memory_collected_items_v1 AS item \
     LEFT JOIN public.memory_collected_item_heads_v1 AS head \
       ON head.tenant_id = item.tenant_id AND head.project = item.project \
      AND head.item_key_digest = item.item_key_digest AND head.presented \
     LEFT JOIN public.memory_collector_containers_v1 AS head_container \
       ON head_container.tenant_id = head.tenant_id AND head_container.project = head.project \
      AND head_container.container_key = head.container_key \
     LEFT JOIN public.memory_collector_containers_v1 AS own_container \
       ON own_container.tenant_id = item.tenant_id AND own_container.project = item.project \
      AND own_container.container_key = item.container_key \
     WHERE item.tenant_id = $1 AND item.project = $2 \
       AND item.accepted_event_id = ANY($3::BYTES[]) \
     ORDER BY item.item_key_digest, item.version_key_digest, item.part_ordinal";

/// One citation's link rows: every cited part, in one statement.
const INSERT_LINKS_SQL: &str = "INSERT INTO public.memory_claim_item_links_v1 (\
         tenant_id, project, claim_id, support_event_id, link_id, via, claim_event_id, \
         item_key_digest, version_key_digest, part_ordinal, relation, created_at\
     ) SELECT $1, $2, $3, part.event_id, $4, $5, $6, $7, $8, part.ordinal, $9, now() \
     FROM unnest($10::BYTES[], $11::INT8[]) AS part (event_id, ordinal)";

/// A record citation's opaque support row: the link id, never the item.
const INSERT_OPAQUE_SUPPORT_SQL: &str = "INSERT INTO memory_claim_support (\
         tenant_id, project, claim_id, source_config_id, source, source_id, chunk_id, \
         content_sha256, excerpt, relation\
     ) VALUES ($1, $2, $3, $4, $5, $6, NULL, NULL, NULL, $7) \
     RETURNING id, source_config_id, source, source_id, chunk_id, content_sha256, \
               excerpt, relation, state, observed_at, invalidated_at";

/// A claim's links, each part with its item row and what hides its item now.
const CLAIM_LINKS_SQL: &str = "SELECT link.link_id, link.via, link.relation, \
     link.item_key_digest, link.version_key_digest, link.part_ordinal, link.support_event_id, \
     item.trust_tier, item.content_digest, item.provider, item.object_kind, item.external_id, \
     item.provider_url, item.lifecycle, \
     head.version_key_digest AS head_version_key, head.lifecycle AS head_lifecycle, \
     container.access AS container_access, \
     COALESCE(own_container.access <> 'ok', false) AS own_container_withdrawn, \
     EXISTS (SELECT 1 FROM public.memory_collected_item_withdrawals_v1 AS withdrawal \
        WHERE withdrawal.tenant_id = $1 AND withdrawal.project = $2 \
          AND withdrawal.item_key_digest = link.item_key_digest AND withdrawal.withdrawn) \
        AS item_withdrawn \
     FROM public.memory_claim_item_links_v1 AS link \
     JOIN public.memory_collected_items_v1 AS item \
       ON item.tenant_id = link.tenant_id AND item.project = link.project \
      AND item.accepted_event_id = link.support_event_id \
     LEFT JOIN public.memory_collected_item_heads_v1 AS head \
       ON head.tenant_id = link.tenant_id AND head.project = link.project \
      AND head.item_key_digest = link.item_key_digest AND head.presented \
     LEFT JOIN public.memory_collector_containers_v1 AS container \
       ON container.tenant_id = head.tenant_id AND container.project = head.project \
      AND container.container_key = head.container_key \
     LEFT JOIN public.memory_collector_containers_v1 AS own_container \
       ON own_container.tenant_id = item.tenant_id AND own_container.project = item.project \
      AND own_container.container_key = item.container_key \
     WHERE link.tenant_id = $1 AND link.project = $2 AND link.claim_id = $3 \
     ORDER BY link.created_at, link.link_id, link.part_ordinal \
     LIMIT $4";

/// One cited item resolved in the claim's scope: the version cited, and one
/// admitted part per ordinal of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ResolvedItemV1 {
    pub(super) item_key: Sha256Digest,
    pub(super) version_key: Sha256Digest,
    /// `(part ordinal, accepted event)`, in part order.
    pub(super) parts: Vec<(i64, Sha256Digest)>,
}

impl ResolvedItemV1 {
    /// The cited parts' accepted events, in part order.
    pub(super) fn event_ids(&self) -> impl Iterator<Item = AcceptedEventId> + '_ {
        self.parts
            .iter()
            .map(|(_, event)| AcceptedEventId::from_digest(*event))
    }
}

/// One citation to resolve: where the request names it, and the reference.
#[derive(Debug, Clone, Copy)]
pub(super) struct CitationV1<'a> {
    /// The request field, for the refusal (`support_items[1]`, `support[3]`).
    pub(super) field: &'a str,
    pub(super) reference: &'a ItemRefV1,
}

/// What one reference resolved to.
enum ResolutionV1 {
    Resolved(ResolvedItemV1),
    Unknown,
    Pending,
    Hidden(ItemSuppressionV1),
}

/// The presented head of an item, as resolution reads it.
struct HeadV1 {
    version_key: Sha256Digest,
    tier: String,
    object_kind: String,
    suppressed: Option<ItemSuppressionV1>,
}

fn digest_of(row: &PgRow, column: &str) -> Result<Sha256Digest> {
    let bytes: Vec<u8> = row.try_get(column)?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| protocol_error(format!("stored {column} is not 32 bytes")))?;
    Ok(Sha256Digest::from_bytes(bytes))
}

fn optional_digest(row: &PgRow, column: &str) -> Result<Option<Sha256Digest>> {
    let bytes: Option<Vec<u8>> = row.try_get(column)?;
    bytes
        .map(|bytes| {
            <[u8; 32]>::try_from(bytes)
                .map(Sha256Digest::from_bytes)
                .map_err(|_| protocol_error(format!("stored {column} is not 32 bytes")))
        })
        .transpose()
}

fn bytes(digest: Sha256Digest) -> Vec<u8> {
    digest.as_bytes().to_vec()
}

/// Why an item is hidden, from its presented head's lifecycle, its
/// container's access, and its withdrawal: `recall(kind=item)`'s rule.
fn suppression(
    lifecycle: ItemLifecycleV1,
    container_access: Option<&str>,
    item_withdrawn: bool,
) -> Option<ItemSuppressionV1> {
    if lifecycle.is_tombstone() {
        Some(ItemSuppressionV1::Deleted)
    } else if container_access.is_some_and(|access| access != "ok") {
        Some(ItemSuppressionV1::ContainerWithdrawn)
    } else if item_withdrawn {
        Some(ItemSuppressionV1::ItemWithdrawn)
    } else {
        None
    }
}

const fn suppression_label(suppressed: ItemSuppressionV1) -> &'static str {
    match suppressed {
        ItemSuppressionV1::Deleted => "deleted",
        ItemSuppressionV1::ContainerWithdrawn => "container_withdrawn",
        ItemSuppressionV1::ItemWithdrawn => "item_withdrawn",
    }
}

async fn presented_head(
    connection: &mut PgConnection,
    scope: &FleetScope,
    item_key: Sha256Digest,
) -> Result<Option<HeadV1>> {
    let Some(row) = sqlx::query(PRESENTED_HEAD_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(bytes(item_key))
        .fetch_optional(&mut *connection)
        .await?
    else {
        return Ok(None);
    };
    let lifecycle: String = row.try_get("lifecycle")?;
    let access: Option<String> = row.try_get("container_access")?;
    Ok(Some(HeadV1 {
        version_key: digest_of(&row, "version_key_digest")?,
        tier: row.try_get("trust_tier")?,
        object_kind: row.try_get("object_kind")?,
        suppressed: suppression(
            ItemLifecycleV1::parse(&lifecycle)?,
            access.as_deref(),
            row.try_get("item_withdrawn")?,
        ),
    }))
}

async fn item_pending(
    connection: &mut PgConnection,
    scope: &FleetScope,
    item_key: Sha256Digest,
    version_key: Option<Sha256Digest>,
) -> Result<bool> {
    Ok(sqlx::query_scalar(ITEM_PENDING_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(bytes(item_key))
        .bind(version_key.map(bytes))
        .fetch_one(&mut *connection)
        .await?)
}

/// The item key a reference names, and the version it pins, when any; or
/// what the reference resolves to without an item.
async fn named_item(
    connection: &mut PgConnection,
    scope: &FleetScope,
    reference: &ItemRefV1,
) -> Result<std::result::Result<(Sha256Digest, Option<Sha256Digest>), ResolutionV1>> {
    let (row, version) = match reference {
        ItemRefV1::ItemId(item) => return Ok(Ok((*item, None))),
        ItemRefV1::VersionId(version) => (
            sqlx::query(ITEM_BY_VERSION_SQL)
                .bind(scope.tenant_id)
                .bind(&scope.project)
                .bind(bytes(*version))
                .fetch_optional(&mut *connection)
                .await?,
            Some(*version),
        ),
        ItemRefV1::Url(url) => (
            sqlx::query(ITEM_BY_URL_SQL)
                .bind(scope.tenant_id)
                .bind(&scope.project)
                .bind(url.as_str())
                .fetch_optional(&mut *connection)
                .await?,
            None,
        ),
    };
    if let Some(row) = row {
        return Ok(Ok((digest_of(&row, "item_key_digest")?, version)));
    }
    // A version no admitted part names may still be staged. The outbox does
    // not record provider URLs, so an unknown URL is only unknown.
    let pending = match version {
        Some(version) => {
            sqlx::query_scalar(VERSION_PENDING_SQL)
                .bind(scope.tenant_id)
                .bind(&scope.project)
                .bind(bytes(version))
                .fetch_one(&mut *connection)
                .await?
        }
        None => false,
    };
    Ok(Err(if pending {
        ResolutionV1::Pending
    } else {
        ResolutionV1::Unknown
    }))
}

async fn resolve_one(
    connection: &mut PgConnection,
    scope: &FleetScope,
    reference: &ItemRefV1,
) -> Result<ResolutionV1> {
    let (item_key, pinned) = match named_item(connection, scope, reference).await? {
        Ok(named) => named,
        Err(resolution) => return Ok(resolution),
    };
    let Some(head) = presented_head(connection, scope, item_key).await? else {
        // No complete version heads the item yet.
        return Ok(
            if item_pending(connection, scope, item_key, pinned).await? {
                ResolutionV1::Pending
            } else {
                ResolutionV1::Unknown
            },
        );
    };
    // A collector's own coverage observation is never recalled as an item,
    // so it is never cited as one either.
    if head.object_kind == "collector_observation" {
        return Ok(ResolutionV1::Unknown);
    }
    if let Some(suppressed) = head.suppressed {
        return Ok(ResolutionV1::Hidden(suppressed));
    }
    let version_key = pinned.unwrap_or(head.version_key);
    let rows: Vec<PgRow> = sqlx::query(VERSION_PARTS_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(bytes(item_key))
        .bind(bytes(version_key))
        .bind(&head.tier)
        .fetch_all(&mut *connection)
        .await?;
    let mut parts = Vec::with_capacity(rows.len());
    let mut part_count = None;
    let mut tombstone = false;
    let mut container_withdrawn = false;
    for row in &rows {
        let lifecycle: String = row.try_get("lifecycle")?;
        tombstone |= ItemLifecycleV1::parse(&lifecycle)?.is_tombstone();
        container_withdrawn |= row.try_get::<bool, _>("container_withdrawn")?;
        part_count = Some(row.try_get::<i64, _>("part_count")?);
        parts.push((
            row.try_get::<i64, _>("part_ordinal")?,
            digest_of(row, "accepted_event_id")?,
        ));
    }
    // A version is cited only whole: every ordinal admitted.
    let complete = part_count.is_some_and(|count| {
        usize::try_from(count).is_ok_and(|count| count == parts.len())
            && parts
                .iter()
                .zip(0_i64..)
                .all(|((ordinal, _), expected)| *ordinal == expected)
    });
    if !complete {
        return Ok(
            if item_pending(connection, scope, item_key, Some(version_key)).await? {
                ResolutionV1::Pending
            } else {
                ResolutionV1::Unknown
            },
        );
    }
    if tombstone {
        return Ok(ResolutionV1::Hidden(ItemSuppressionV1::Deleted));
    }
    // A version admitted in a container since withdrawn is withheld from
    // every recall lane, even when the item moved to a readable one.
    if container_withdrawn {
        return Ok(ResolutionV1::Hidden(ItemSuppressionV1::ContainerWithdrawn));
    }
    Ok(ResolutionV1::Resolved(ResolvedItemV1 {
        item_key,
        version_key,
        parts,
    }))
}

fn cited_refusal(code: RefusalCode, message: String, citation: CitationV1<'_>) -> FleetError {
    LifecycleRefusal::new(
        code,
        message,
        json!({ "field": citation.field, "item": citation.reference }),
    )
    .into()
}

/// Resolve every citation, in order, in `scope`: the first that does not
/// resolve refuses the whole claim, naming its field.
///
/// # Errors
///
/// `support_item_unknown`, `support_item_pending`, or
/// `support_item_withdrawn` (with `details.suppressed`) as a typed refusal;
/// a request with more than [`MAX_SUPPORT_ITEMS`] citations as
/// `FleetError::Memory`; a database failure as itself.
pub(super) async fn resolve_citations(
    connection: &mut PgConnection,
    scope: &FleetScope,
    citations: &[CitationV1<'_>],
) -> Result<Vec<ResolvedItemV1>> {
    if citations.len() > MAX_SUPPORT_ITEMS {
        return Err(FleetError::Memory(format!(
            "a claim may cite at most {MAX_SUPPORT_ITEMS} collected items"
        )));
    }
    let mut resolved = Vec::with_capacity(citations.len());
    for citation in citations {
        citation.reference.validate()?;
        match resolve_one(connection, scope, citation.reference).await? {
            ResolutionV1::Resolved(item) => resolved.push(item),
            ResolutionV1::Unknown => {
                return Err(cited_refusal(
                    RefusalCode::SupportItemUnknown,
                    format!(
                        "{} names no admitted collected item in this project",
                        citation.field
                    ),
                    *citation,
                ));
            }
            ResolutionV1::Pending => {
                return Err(cited_refusal(
                    RefusalCode::SupportItemPending,
                    format!(
                        "{} names a collected item that is staged but not yet admitted; cite it \
                         once the worker's collect step has admitted it",
                        citation.field
                    ),
                    *citation,
                ));
            }
            ResolutionV1::Hidden(suppressed) => {
                return Err(LifecycleRefusal::new(
                    RefusalCode::SupportItemWithdrawn,
                    format!(
                        "{} names a collected item withheld from recall ({})",
                        citation.field,
                        suppression_label(suppressed)
                    ),
                    json!({
                        "field": citation.field,
                        "item": citation.reference,
                        "suppressed": suppressed,
                    }),
                )
                .into());
            }
        }
    }
    Ok(resolved)
}

/// Audit, in the append transaction, every support event of an assertion
/// that a collected item admitted: whether it cites the item through
/// `support_items` or lists the event in `support_evidence_event_ids`
/// directly. An event whose item is hidden from recall now (its presented
/// head a tombstone, the head's container or the event's own container
/// withdrawn, the item withdrawn) refuses the claim as
/// `support_item_withdrawn`, so nothing deletion or a withdrawal hides can
/// become a claim's support by any route.
///
/// Returns the directly listed events that no `cited` version covers, one
/// entry per item version, so they are linked like a citation and the item
/// lists the claim. A collector's own observation is audited but not linked.
///
/// # Errors
///
/// That refusal, or a database failure.
pub(super) async fn audit_cited_events(
    connection: &mut PgConnection,
    scope: &FleetScope,
    events: &[AcceptedEventId],
    cited: &[ResolvedItemV1],
) -> Result<Vec<ResolvedItemV1>> {
    if events.is_empty() {
        return Ok(Vec::new());
    }
    let wanted: Vec<Vec<u8>> = events.iter().map(|event| bytes(event.digest())).collect();
    let rows: Vec<PgRow> = sqlx::query(CITED_EVENTS_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(&wanted)
        .fetch_all(&mut *connection)
        .await?;
    let cited_versions: BTreeSet<Sha256Digest> =
        cited.iter().map(|item| item.version_key).collect();
    let mut direct: Vec<ResolvedItemV1> = Vec::new();
    for row in &rows {
        let event = digest_of(row, "accepted_event_id")?;
        let item_key = digest_of(row, "item_key_digest")?;
        let item_withdrawn: bool = row.try_get("item_withdrawn")?;
        let head_lifecycle: Option<String> = row.try_get("head_lifecycle")?;
        let head_access: Option<String> = row.try_get("head_container_access")?;
        // A part of a version not yet whole may have no presented head; its
        // own container and the item's withdrawal still hide it.
        let by_head = match head_lifecycle {
            Some(lifecycle) => suppression(
                ItemLifecycleV1::parse(&lifecycle)?,
                head_access.as_deref(),
                item_withdrawn,
            ),
            None => item_withdrawn.then_some(ItemSuppressionV1::ItemWithdrawn),
        };
        let own_withdrawn: bool = row.try_get("own_container_withdrawn")?;
        let suppressed =
            by_head.or_else(|| own_withdrawn.then_some(ItemSuppressionV1::ContainerWithdrawn));
        if let Some(suppressed) = suppressed {
            return Err(LifecycleRefusal::new(
                RefusalCode::SupportItemWithdrawn,
                format!(
                    "a support event is a collected item withheld from recall ({}); nothing was \
                     written",
                    suppression_label(suppressed)
                ),
                json!({ "item_id": item_key, "event_id": event, "suppressed": suppressed }),
            )
            .into());
        }
        let version_key = digest_of(row, "version_key_digest")?;
        let object_kind: String = row.try_get("object_kind")?;
        if cited_versions.contains(&version_key) || object_kind == "collector_observation" {
            continue;
        }
        let part = (row.try_get::<i64, _>("part_ordinal")?, event);
        match direct.last_mut() {
            // Rows are sorted by item and version, so a version's rows are
            // contiguous.
            Some(last) if last.item_key == item_key && last.version_key == version_key => {
                last.parts.push(part);
            }
            _ => direct.push(ResolvedItemV1 {
                item_key,
                version_key,
                parts: vec![part],
            }),
        }
    }
    Ok(direct)
}

/// A fresh random link id.
pub(super) fn new_link_id() -> Result<[u8; 16]> {
    let mut link_id = [0_u8; 16];
    SystemRandom::new()
        .fill(&mut link_id)
        .map_err(|_| protocol_error("the system random source failed"))?;
    Ok(link_id)
}

/// The link rows of one citation.
pub(super) struct LinkWriteV1<'a> {
    pub(super) claim_id: i64,
    pub(super) link_id: [u8; 16],
    pub(super) via: &'static str,
    /// The claim's accepted event, for an assert.
    pub(super) claim_event: Option<Sha256Digest>,
    pub(super) relation: &'a str,
    pub(super) item: &'a ResolvedItemV1,
}

/// Insert one citation's link rows.
pub(super) async fn insert_links(
    connection: &mut PgConnection,
    scope: &FleetScope,
    link: &LinkWriteV1<'_>,
) -> Result<()> {
    let (ordinals, events): (Vec<i64>, Vec<Vec<u8>>) = link
        .item
        .parts
        .iter()
        .map(|(ordinal, event)| (*ordinal, bytes(*event)))
        .unzip();
    sqlx::query(INSERT_LINKS_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(link.claim_id)
        .bind(link.link_id.as_slice())
        .bind(link.via)
        .bind(link.claim_event.map(bytes))
        .bind(bytes(link.item.item_key))
        .bind(bytes(link.item.version_key))
        .bind(link.relation)
        .bind(&events)
        .bind(&ordinals)
        .execute(&mut *connection)
        .await?;
    Ok(())
}

/// The links of an assert's citations. Citations of one version are one
/// citation: the events are the same, and an assertion's support carries no
/// relation of its own.
pub(super) async fn insert_assert_links(
    connection: &mut PgConnection,
    scope: &FleetScope,
    claim_id: i64,
    claim_event: Sha256Digest,
    items: &[ResolvedItemV1],
) -> Result<()> {
    let mut linked = BTreeSet::new();
    for item in items {
        if !linked.insert(item.version_key) {
            continue;
        }
        insert_links(
            connection,
            scope,
            &LinkWriteV1 {
                claim_id,
                link_id: new_link_id()?,
                via: VIA_ASSERT,
                claim_event: Some(claim_event),
                relation: ASSERT_RELATION,
                item,
            },
        )
        .await?;
    }
    Ok(())
}

/// A record citation: its opaque support row, then its links, sharing one
/// random link id. The support row names the link id only.
pub(super) async fn insert_record_citation(
    connection: &mut PgConnection,
    scope: &FleetScope,
    claim_id: i64,
    relation: &str,
    item: &ResolvedItemV1,
) -> Result<ClaimSupport> {
    let link_id = new_link_id()?;
    let row = sqlx::query(INSERT_OPAQUE_SUPPORT_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(claim_id)
        .bind(ITEM_SUPPORT_SOURCE_CONFIG_ID)
        .bind(ITEM_SUPPORT_SOURCE)
        .bind(hex::encode(link_id))
        .bind(relation)
        .fetch_one(&mut *connection)
        .await?;
    insert_links(
        connection,
        scope,
        &LinkWriteV1 {
            claim_id,
            link_id,
            via: VIA_RECORD,
            claim_event: None,
            relation,
            item,
        },
    )
    .await?;
    super::decode_support(&row)
}

/// One citation being expanded.
struct CitationRowsV1 {
    cited: CitedItemV1,
    content_digest: Sha256Digest,
}

/// Every citation of `claim_id`, oldest first, with its item's current state
/// and the count of distinct contents among the visible ones.
///
/// # Errors
///
/// A database failure, or a stored row of the wrong shape.
pub(super) async fn claim_item_support(
    pool: &PgPool,
    scope: &FleetScope,
    claim_id: i64,
) -> Result<ClaimItemSupportV1> {
    let rows: Vec<PgRow> = sqlx::query(CLAIM_LINKS_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(claim_id)
        .bind(MAX_CLAIM_LINK_ROWS)
        .fetch_all(pool)
        .await?;
    let cut = usize::try_from(MAX_CLAIM_LINK_ROWS - 1).unwrap_or(usize::MAX);
    let truncated = rows.len() > cut;
    let mut order: Vec<Vec<u8>> = Vec::new();
    let mut citations: BTreeMap<Vec<u8>, CitationRowsV1> = BTreeMap::new();
    for row in rows.iter().take(cut) {
        let link_id: Vec<u8> = row.try_get("link_id")?;
        let event = digest_of(row, "support_event_id")?;
        let tier = TrustTierV1::parse(&row.try_get::<String, _>("trust_tier")?)?;
        if let Some(citation) = citations.get_mut(&link_id) {
            citation.cited.accepted_event_ids.push(event);
            if tier == TrustTierV1::Reported {
                citation.cited.trust = TrustTierV1::Reported;
            }
            continue;
        }
        let version_key = digest_of(row, "version_key_digest")?;
        let head_version = optional_digest(row, "head_version_key")?;
        let head_lifecycle: Option<String> = row.try_get("head_lifecycle")?;
        let access: Option<String> = row.try_get("container_access")?;
        let by_head = match head_lifecycle {
            Some(lifecycle) => suppression(
                ItemLifecycleV1::parse(&lifecycle)?,
                access.as_deref(),
                row.try_get("item_withdrawn")?,
            ),
            None => None,
        };
        // The cited version's own container, as evidence recall judges its
        // bodies: a version admitted where the audience has since narrowed
        // is withheld even when the item now lives somewhere readable.
        let own_withdrawn: bool = row.try_get("own_container_withdrawn")?;
        let suppressed =
            by_head.or_else(|| own_withdrawn.then_some(ItemSuppressionV1::ContainerWithdrawn));
        let cited = CitedItemV1 {
            link_id: hex::encode(&link_id),
            via: row.try_get("via")?,
            relation: row.try_get("relation")?,
            item_id: digest_of(row, "item_key_digest")?,
            version_id: version_key,
            provider: row.try_get("provider")?,
            object_kind: row.try_get("object_kind")?,
            external_id: row.try_get("external_id")?,
            provider_url: row.try_get("provider_url")?,
            trust: tier,
            current: head_version == Some(version_key),
            suppressed,
            accepted_event_ids: vec![event],
            content_trust: ContentTrustV1::UntrustedThirdParty,
        };
        order.push(link_id.clone());
        citations.insert(
            link_id,
            CitationRowsV1 {
                cited,
                content_digest: digest_of(row, "content_digest")?,
            },
        );
    }
    // One source per item: two versions of one message are one source, its
    // current version's content when that is cited. Then identical content
    // across items (an echo, a cross-post) counts once.
    let mut per_item: BTreeMap<Sha256Digest, (bool, Sha256Digest)> = BTreeMap::new();
    for link_id in &order {
        let Some(citation) = citations.get(link_id) else {
            continue;
        };
        if citation.cited.suppressed.is_some() {
            continue;
        }
        let candidate = (citation.cited.current, citation.content_digest);
        per_item
            .entry(citation.cited.item_id)
            .and_modify(|chosen| {
                if candidate.0 && !chosen.0 {
                    *chosen = candidate;
                }
            })
            .or_insert(candidate);
    }
    let independent: BTreeSet<Sha256Digest> =
        per_item.values().map(|(_, digest)| *digest).collect();
    let items = order
        .iter()
        .filter_map(|link_id| citations.remove(link_id))
        .map(|citation| citation.cited)
        .collect();
    Ok(ClaimItemSupportV1 {
        items,
        independent_sources: u64::try_from(independent.len()).unwrap_or(u64::MAX),
        truncated,
    })
}

/// The refusal of an item citation by a ledger that does not serve claim
/// item links.
pub(super) fn item_support_unavailable() -> FleetError {
    LifecycleRefusal::new(
        RefusalCode::ItemSupportUnavailable,
        "this deployment does not let claims cite collected items: the schema predates \
         migration 35, its runtime grants are absent, or recall(kind=item) is not served",
        Value::Null,
    )
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suppression_follows_the_item_recall_rule() {
        assert_eq!(
            suppression(ItemLifecycleV1::Deleted, Some("ok"), false),
            Some(ItemSuppressionV1::Deleted)
        );
        assert_eq!(
            suppression(ItemLifecycleV1::Live, Some("withdrawn"), true),
            Some(ItemSuppressionV1::ContainerWithdrawn)
        );
        assert_eq!(
            suppression(ItemLifecycleV1::Edited, None, true),
            Some(ItemSuppressionV1::ItemWithdrawn)
        );
        assert_eq!(
            suppression(ItemLifecycleV1::Archived, Some("ok"), false),
            None
        );
        for suppressed in [
            ItemSuppressionV1::Deleted,
            ItemSuppressionV1::ContainerWithdrawn,
            ItemSuppressionV1::ItemWithdrawn,
        ] {
            assert_eq!(
                serde_json::to_value(suppressed).unwrap(),
                json!(suppression_label(suppressed))
            );
        }
    }

    #[test]
    fn link_ids_are_random() {
        assert_ne!(new_link_id().unwrap(), new_link_id().unwrap());
    }
}
