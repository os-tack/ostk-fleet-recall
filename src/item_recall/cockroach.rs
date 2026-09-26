//! `CockroachDB` item recall over the collected-item tables (migrations 0033
//! and 0034) and the Stage-5 body and projection tiers.
//!
//! Every statement binds `tenant_id = $1` and `project = $2` first and reads
//! private-plane base tables only; nothing here writes. The visibility rule
//! of every item read is one predicate ([`VISIBLE_ITEM_FILTER`]): an item
//! whose presented head is a tombstone, whose container was withdrawn, or
//! which was itself withdrawn is excluded inside the `WHERE`, before ranking
//! and before any `LIMIT`.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::LazyLock;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::Row as _;
use sqlx::postgres::{PgPool, PgRow};
use uuid::Uuid;

use crate::collectors::ingress::deliveries::count_pending_hints;
use crate::context::FleetScope;
use crate::error::{FleetError, Result};
use crate::evidence_recall::{
    ContentTrustV1, EVENTS_AWAITING_BODIES_SQL, EvidenceDenseLaneV1, EvidenceMatchV1,
    EvidenceSourcesV1, FOREIGN_DENSE_MODEL_SQL, MAX_EVIDENCE_SOURCES, absence_verdict,
    attach_coverage, count, decode_collector_source_row, dense_lane, digest, has_lexical_terms,
    lane_match, lexical_query_text, listing_limit, may_read,
};
use crate::memory_contracts::collected_item::{
    CollectedItemEnvelopeV1, CollectionModeV1, ItemLifecycleV1, ObjectKindV1, ProviderKindV1,
    TrustTierV1,
};
use crate::memory_contracts::digest::Sha256Digest;
use crate::projectors::{
    CockroachRecallReader, EMBEDDING_DIMENSIONS, RecallRedactionV1, fuse_lanes, lane_depth,
    redact_for_recall, redact_for_recall_marked,
};
use crate::store::cockroach::{
    ClaimItemLinksCapability, DatabaseCapabilities, RETRIEVAL_DENSE_MIN_COSINE_SIMILARITY,
    serialize_vector,
};

use super::signals::{InjectionSignalV1, defang_markdown_images, injection_signals};
use super::{
    ITEM_RECALL_SCHEMA_VERSION, ITEM_SNIPPET_CHARS, ItemAuthorRefV1, ItemCitationV1, ItemCitedByV1,
    ItemContainerRefV1, ItemGetV1, ItemHitV1, ItemLinkInV1, ItemLinkOutV1, ItemPartRefV1,
    ItemPartTextV1, ItemProvenanceV1, ItemReadinessV1, ItemRecall, ItemReferenceV1,
    ItemSearchRequestV1, ItemSearchV1, ItemSummaryV1, ItemSuppressionV1, ItemThreadRootV1,
    ItemThreadV1, ItemVersionRecordV1, ItemVersionRefV1, MAX_HIT_CITATION_IDS, MAX_ITEM_CITATIONS,
    MAX_ITEM_GET_ROWS, MAX_ITEM_GET_TEXT_BYTES, MAX_ITEM_LINKS_IN, MAX_ITEM_SEARCH_LIMIT,
    thread_root_item_key,
};

/// Every table item recall reads. The startup probe checks SELECT on each.
pub const ITEM_RECALL_TABLES: [&str; 14] = [
    "memory_collected_items_v1",
    "memory_collected_item_heads_v1",
    "memory_collector_containers_v1",
    "memory_collected_item_withdrawals_v1",
    "memory_collected_item_links_v1",
    "memory_collector_outbox_v1",
    "memory_collector_sources_v1",
    "memory_coverage_cursors_v1",
    "memory_evidence_shard_heads",
    "memory_evidence_events",
    "memory_body_projection_watermarks_v1",
    "memory_body_objects_v1",
    "memory_body_lexical_projection_v1",
    "memory_body_dense_projection_v1",
];

/// The presented head of `item`, and its container, for [`VISIBLE_ITEM_FILTER`].
const VISIBLE_ITEM_JOINS: &str = "JOIN public.memory_collected_item_heads_v1 AS head \
       ON head.tenant_id = item.tenant_id AND head.project = item.project \
      AND head.item_key_digest = item.item_key_digest AND head.presented \
     LEFT JOIN public.memory_collector_containers_v1 AS container \
       ON container.tenant_id = item.tenant_id AND container.project = item.project \
      AND container.container_key = item.container_key";

/// Whether an item row may be recalled: not a collector's own observation,
/// its item's presented head not a tombstone, its container not withdrawn,
/// the item not withdrawn for either tier. Suppresses every version of a
/// hidden item, the earlier ones included.
const VISIBLE_ITEM_FILTER: &str = "item.object_kind <> 'collector_observation' \
     AND head.lifecycle NOT IN ('deleted', 'trashed', 'revoked') \
     AND (container.access IS NULL OR container.access = 'ok') \
     AND NOT EXISTS (SELECT 1 FROM public.memory_collected_item_withdrawals_v1 AS withdrawal \
           WHERE withdrawal.tenant_id = $1 AND withdrawal.project = $2 \
             AND withdrawal.item_key_digest = item.item_key_digest AND withdrawal.withdrawn)";

/// The search filters: `$4` the provider (NULL for every provider), `$5`
/// whether versions other than the presented head's are admitted.
const SEARCH_FILTER: &str = "($4::STRING IS NULL OR item.provider = $4) \
     AND ($5 OR item.version_key_digest = head.version_key_digest)";

/// The lexical lane: each matching item version's best-ranked part, then the
/// versions by rank. `$3` is the query text, `$6` the lane depth (five rows
/// per hit asked for, [`lane_depth`]); the fusion applies the `ts_rank`
/// cutoff and cuts the fused list to the limit.
static LEXICAL_ITEMS_SQL: LazyLock<String> = LazyLock::new(|| {
    format!(
        "SELECT best.item_key_digest, best.version_key_digest, best.body_content_id, best.score \
         FROM (SELECT DISTINCT ON (item.item_key_digest, item.version_key_digest) \
                 item.item_key_digest, item.version_key_digest, item.body_content_id, \
                 ts_rank(lex.search_document, plainto_tsquery('english', $3))::FLOAT4 AS score \
               FROM public.memory_body_lexical_projection_v1 AS lex \
               JOIN public.memory_collected_items_v1 AS item \
                 ON item.tenant_id = lex.tenant_id AND item.project = lex.project \
                AND item.body_content_id = lex.body_content_id \
               {VISIBLE_ITEM_JOINS} \
               WHERE lex.tenant_id = $1 AND lex.project = $2 \
                 AND lex.search_document @@ plainto_tsquery('english', $3) \
                 AND {VISIBLE_ITEM_FILTER} AND {SEARCH_FILTER} \
               ORDER BY item.item_key_digest, item.version_key_digest, score DESC, \
                        (item.trust_tier = head.trust_tier) DESC, item.body_content_id) AS best \
         ORDER BY best.score DESC, best.body_content_id LIMIT $6"
    )
});

/// The dense lane, in the pattern of the evidence reader's model-restricted
/// lane: an approximate nearest-neighbour subquery the C-SPANN index serves
/// (`$6` candidates, the same lane depth as the lexical lane), then the join
/// to the item tables, the model filter (`$7`), and the visibility and
/// search filters outside it; each version's nearest part, then the versions
/// by distance. The fusion applies the dense floor.
static DENSE_ITEMS_SQL: LazyLock<String> = LazyLock::new(|| {
    format!(
        "SELECT best.item_key_digest, best.version_key_digest, best.body_content_id, \
                best.distance \
         FROM (SELECT DISTINCT ON (item.item_key_digest, item.version_key_digest) \
                 item.item_key_digest, item.version_key_digest, item.body_content_id, \
                 nearest.distance \
               FROM (SELECT body_content_id, model_digest, \
                       (embedding <=> $3::VECTOR(512))::FLOAT4 AS distance \
                     FROM public.memory_body_dense_projection_v1 \
                     WHERE tenant_id = $1 AND project = $2 \
                     ORDER BY embedding <=> $3::VECTOR(512) LIMIT $6) AS nearest \
               JOIN public.memory_collected_items_v1 AS item \
                 ON item.tenant_id = $1 AND item.project = $2 \
                AND item.body_content_id = nearest.body_content_id \
               {VISIBLE_ITEM_JOINS} \
               WHERE nearest.model_digest = $7 \
                 AND {VISIBLE_ITEM_FILTER} AND {SEARCH_FILTER} \
               ORDER BY item.item_key_digest, item.version_key_digest, nearest.distance, \
                        (item.trust_tier = head.trust_tier) DESC, item.body_content_id) AS best \
         ORDER BY best.distance, best.body_content_id"
    )
});

/// Everything a hit shows about its part, its item's presented head, and its
/// container, with the part's body envelope.
const HYDRATE_SQL: &str = "SELECT item.accepted_event_id, item.item_key_digest, \
     item.version_key_digest, item.part_ordinal, item.part_count, item.provider, \
     item.provider_scope_id, item.object_kind, item.external_id, item.trust_tier, \
     item.lifecycle, item.version_marker, item.provider_order, item.redaction_profile, \
     item.thread_root_external_id, item.provider_created_at, \
     item.provider_updated_at, item.provider_url, item.canonical_resource_id, \
     item.body_content_id, body.body_bytes, \
     head.version_key_digest AS head_version_key, head.disagreement, \
     container.label AS container_label \
     FROM public.memory_collected_items_v1 AS item \
     JOIN public.memory_body_objects_v1 AS body \
       ON body.tenant_id = item.tenant_id AND body.project = item.project \
      AND body.content_sha256 = item.body_content_id \
     LEFT JOIN public.memory_collected_item_heads_v1 AS head \
       ON head.tenant_id = item.tenant_id AND head.project = item.project \
      AND head.item_key_digest = item.item_key_digest AND head.presented \
     LEFT JOIN public.memory_collector_containers_v1 AS container \
       ON container.tenant_id = item.tenant_id AND container.project = item.project \
      AND container.container_key = item.container_key \
     WHERE item.tenant_id = $1 AND item.project = $2 \
       AND item.body_content_id = ANY($3::BYTES[])";

/// Every (item, version, channel) of a set of items.
const VERSION_MODES_SQL: &str = "SELECT item_key_digest, version_key_digest, collection_mode \
     FROM public.memory_collected_items_v1 \
     WHERE tenant_id = $1 AND project = $2 AND item_key_digest = ANY($3::BYTES[]) \
     GROUP BY item_key_digest, version_key_digest, collection_mode";

/// Collected parts staged and not yet admitted (of provider `$3`, or all),
/// events awaiting the body projector, and the read's clock.
static READINESS_SQL: LazyLock<String> = LazyLock::new(|| {
    format!(
        "SELECT (SELECT count(*) FROM public.memory_collector_outbox_v1 \
                   WHERE tenant_id = $1 AND project = $2 AND state = 'pending' \
                     AND ($3::STRING IS NULL OR provider = $3)) AS items_pending, \
                {EVENTS_AWAITING_BODIES_SQL} AS events_awaiting_bodies, \
                pg_catalog.statement_timestamp() AS as_of"
    )
});

/// The live and snapshot collectors (of provider `$3`, or all), one row past
/// the listing bound, shaped as evidence recall's collector listing.
const SOURCES_SQL: &str = "SELECT collector_instance_id, provider, state, last_outcome, \
     last_checked_at, last_error, \
     (pg_catalog.statement_timestamp() - last_checked_at) \
        > (stale_after_seconds * INTERVAL '1 second') AS stale \
     FROM public.memory_collector_sources_v1 \
     WHERE tenant_id = $1 AND project = $2 AND state = 'active' \
       AND coverage_role IN ('live', 'snapshot') \
       AND ($3::STRING IS NULL OR provider = $3) \
     ORDER BY collector_instance_id LIMIT $4";

/// The item and version a part's version URI names. `canonical_resource_id`
/// has no index of its own, so this reads the scope's item history.
const RESOLVE_URI_SQL: &str = "SELECT item_key_digest, version_key_digest \
     FROM public.memory_collected_items_v1 \
     WHERE tenant_id = $1 AND project = $2 AND canonical_resource_id = $3 \
     ORDER BY accepted_event_id LIMIT 1";

/// The item and version a provider URL names (`memory_collected_items_url_idx`):
/// one a verified channel admitted under that URL first, then the greatest
/// provider order. A capture's URL is the agent's word, so it never takes a
/// collected item's permalink over (claim citations resolve URLs the same).
const RESOLVE_URL_SQL: &str = "SELECT item_key_digest, version_key_digest \
     FROM public.memory_collected_items_v1 \
     WHERE tenant_id = $1 AND project = $2 AND provider_url = $3 \
     ORDER BY (trust_tier = 'verified') DESC, provider_order DESC, item_key_digest, \
              version_key_digest LIMIT 1";

/// The presented head of one item, with its container's access and whether
/// the item is withdrawn for either tier.
const PRESENTED_HEAD_SQL: &str = "SELECT head.trust_tier, head.version_key_digest, \
     head.lifecycle, head.disagreement, head.provider, head.provider_scope_id, \
     head.object_kind, head.external_id, head.container_key, \
     container.access AS container_access, container.label AS container_label, \
     EXISTS (SELECT 1 FROM public.memory_collected_item_withdrawals_v1 AS withdrawal \
        WHERE withdrawal.tenant_id = $1 AND withdrawal.project = $2 \
          AND withdrawal.item_key_digest = $3 AND withdrawal.withdrawn) AS item_withdrawn \
     FROM public.memory_collected_item_heads_v1 AS head \
     LEFT JOIN public.memory_collector_containers_v1 AS container \
       ON container.tenant_id = head.tenant_id AND container.project = head.project \
      AND container.container_key = head.container_key \
     WHERE head.tenant_id = $1 AND head.project = $2 AND head.item_key_digest = $3 \
       AND head.presented";

/// One item's admitted parts (`memory_collected_items_version_idx`): the
/// presented version `$5` first, so a cut at the bound only ever drops older
/// history, then the greatest provider order; one row past the bound. Each
/// version's rows are contiguous. Each row says whether its own container
/// (the one that version was admitted in, not the head's) is withdrawn, the
/// rule evidence recall applies to every body.
const HISTORY_SQL: &str = "SELECT item.accepted_event_id, item.version_key_digest, \
     item.part_ordinal, item.part_count, item.collection_mode, item.trust_tier, \
     item.collector_instance_id, item.attester_principal_id, item.lifecycle, \
     item.version_marker, item.provider_order, item.redaction_profile, \
     item.thread_root_external_id, \
     item.provider_url, item.provider_created_at, item.provider_updated_at, \
     item.canonical_resource_id, item.body_content_id, item.admitted_at, \
     COALESCE(container.access <> 'ok', false) AS container_withdrawn \
     FROM public.memory_collected_items_v1 AS item \
     LEFT JOIN public.memory_collector_containers_v1 AS container \
       ON container.tenant_id = item.tenant_id AND container.project = item.project \
      AND container.container_key = item.container_key \
     WHERE item.tenant_id = $1 AND item.project = $2 AND item.item_key_digest = $3 \
     ORDER BY (item.version_key_digest = $5) DESC, item.provider_order DESC, \
              item.version_key_digest, item.part_ordinal, item.admitted_at, \
              item.accepted_event_id \
     LIMIT $4";

/// Bodies one `get` reads per statement while its text budget lasts.
const ENVELOPE_BATCH: usize = 8;

/// Body envelopes by content address.
const BODIES_SQL: &str = "SELECT content_sha256, body_bytes FROM public.memory_body_objects_v1 \
     WHERE tenant_id = $1 AND project = $2 AND content_sha256 = ANY($3::BYTES[])";

/// The outbound links of a set of admitted parts.
const LINKS_OUT_SQL: &str = "SELECT accepted_event_id, link_ordinal, rel, target \
     FROM public.memory_collected_item_links_v1 \
     WHERE tenant_id = $1 AND project = $2 AND accepted_event_id = ANY($3::BYTES[]) \
     ORDER BY accepted_event_id, link_ordinal";

/// Visible items whose presented version links to one of `$3`
/// (`memory_collected_item_links_target_idx`), other than item `$4`.
static LINKS_IN_SQL: LazyLock<String> = LazyLock::new(|| {
    format!(
        "SELECT DISTINCT item.item_key_digest, item.provider, item.object_kind, \
                item.external_id, link.rel \
         FROM public.memory_collected_item_links_v1 AS link \
         JOIN public.memory_collected_items_v1 AS item \
           ON item.tenant_id = link.tenant_id AND item.project = link.project \
          AND item.accepted_event_id = link.accepted_event_id \
         {VISIBLE_ITEM_JOINS} \
         WHERE link.tenant_id = $1 AND link.project = $2 AND link.target = ANY($3::STRING[]) \
           AND item.item_key_digest <> $4 \
           AND item.version_key_digest = head.version_key_digest \
           AND {VISIBLE_ITEM_FILTER} \
         ORDER BY item.item_key_digest, link.rel LIMIT $5"
    )
});

/// The claims that cite item `$3` (`memory_claim_item_links_item_idx`): one
/// row per citation, oldest first, one row past the bound (`$4`).
const CITATIONS_SQL: &str = "SELECT link.claim_id, link.via, link.relation, \
     link.version_key_digest, min(link.created_at) AS cited_at, claim.state AS claim_state \
     FROM public.memory_claim_item_links_v1 AS link \
     JOIN public.memory_claims AS claim \
       ON claim.tenant_id = link.tenant_id AND claim.project = link.project \
      AND claim.id = link.claim_id \
     WHERE link.tenant_id = $1 AND link.project = $2 AND link.item_key_digest = $3 \
     GROUP BY link.claim_id, link.link_id, link.via, link.relation, link.version_key_digest, \
              claim.state \
     ORDER BY cited_at, link.claim_id, link.link_id \
     LIMIT $4";

/// The citation marker of every item of a page of hits
/// (`memory_claim_item_links_item_idx`): per item, how many claims cite it,
/// how many of those a conflict holds `disputed` now, and the citing claims
/// oldest citation first. A claim that cites an item through several links
/// counts once.
const HIT_CITATIONS_SQL: &str = "SELECT cited.item_key_digest, count(*) AS claims, \
     count(*) FILTER (WHERE cited.claim_state = 'disputed') AS disputed, \
     array_agg(cited.claim_id ORDER BY cited.cited_at, cited.claim_id) AS claim_ids \
     FROM (SELECT link.item_key_digest, link.claim_id, claim.state AS claim_state, \
             min(link.created_at) AS cited_at \
           FROM public.memory_claim_item_links_v1 AS link \
           JOIN public.memory_claims AS claim \
             ON claim.tenant_id = link.tenant_id AND claim.project = link.project \
            AND claim.id = link.claim_id \
           WHERE link.tenant_id = $1 AND link.project = $2 \
             AND link.item_key_digest = ANY($3::BYTES[]) \
           GROUP BY link.item_key_digest, link.claim_id, claim.state) AS cited \
     GROUP BY cited.item_key_digest";

/// Proof that this login may read every item-recall table in one scope, and
/// whether the dense lane is served there.
///
/// Only [`probe_item_recall`] mints it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemRecallCapability {
    tenant_id: Uuid,
    project: String,
    /// The model this process embeds queries with.
    model_digest: Sha256Digest,
    dense_served: bool,
}

impl ItemRecallCapability {
    /// The dense lane's state for a read with no query.
    #[must_use]
    pub const fn dense_lane(&self) -> EvidenceDenseLaneV1 {
        dense_lane(self.dense_served, None)
    }
}

/// Whether this deployment may serve item recall for `scope`.
///
/// It may when the schema has reached migration 34
/// ([`ITEM_RECALL_SCHEMA_VERSION`]) and the login may SELECT every table in
/// [`ITEM_RECALL_TABLES`]. `None` means item recall is not served. As for
/// evidence recall, every dense query is restricted to the vectors
/// `model_digest` embedded, and the lane is off for the process when the
/// scope's dense tier already holds another model's vectors at startup.
///
/// # Errors
///
/// An invalid scope, or a database failure other than a missing privilege.
pub async fn probe_item_recall(
    pool: &PgPool,
    capabilities: &DatabaseCapabilities,
    scope: &FleetScope,
    model_digest: Sha256Digest,
) -> Result<Option<ItemRecallCapability>> {
    scope.validate()?;
    if !capabilities.supports_schema_version(ITEM_RECALL_SCHEMA_VERSION) {
        return Ok(None);
    }
    if !may_read(pool, &ITEM_RECALL_TABLES).await? {
        return Ok(None);
    }
    let foreign: Option<i64> = sqlx::query_scalar(FOREIGN_DENSE_MODEL_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(model_digest.as_bytes().as_slice())
        .fetch_optional(pool)
        .await?;
    Ok(Some(ItemRecallCapability {
        tenant_id: scope.tenant_id,
        project: scope.project.clone(),
        model_digest,
        dense_served: foreign.is_none(),
    }))
}

/// [`ItemRecall`] over one scope's private plane.
#[derive(Clone)]
pub struct CockroachItemRecall {
    pool: PgPool,
    tenant_id: Uuid,
    project: String,
    model_digest: Sha256Digest,
    dense_served: bool,
    /// Whether `get` lists the claims that cite an item: set only from the
    /// claim item links probe (migration 35, ADR 0008 D11).
    claim_citations: bool,
    /// The projection readiness counts.
    reader: CockroachRecallReader,
}

impl std::fmt::Debug for CockroachItemRecall {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CockroachItemRecall")
            .field("tenant_id", &self.tenant_id)
            .field("project", &self.project)
            .field("dense_served", &self.dense_served)
            .field("claim_citations", &self.claim_citations)
            .finish_non_exhaustive()
    }
}

/// One lane's best part of one item version.
#[derive(Debug, Clone, Copy, PartialEq)]
struct LaneRowV1 {
    item_key: Sha256Digest,
    version_key: Sha256Digest,
    body: Sha256Digest,
    /// `ts_rank` for the lexical lane, cosine distance for the dense one.
    score: f32,
}

/// One fused hit before hydration.
#[derive(Debug, Clone, Copy, PartialEq)]
struct FusedHitV1 {
    body: Sha256Digest,
    score: f32,
    matched_by: EvidenceMatchV1,
    lexical_score: Option<f32>,
    dense_similarity: Option<f32>,
}

/// The lanes' versions fused by reciprocal rank
/// ([`crate::projectors::fuse_lanes`]), keyed by `(item, version)`, with the
/// lexical `ts_rank` cutoff and the dense floor applied inside the fusion;
/// at most `limit`, highest fused score first. A version both lanes found
/// keeps its lexical part and gains its dense similarity; a version only
/// the dense lane ranked carries its nearest part.
fn fuse(lexical: &[LaneRowV1], dense: &[LaneRowV1], limit: usize) -> Vec<FusedHitV1> {
    type VersionKey = (Sha256Digest, Sha256Digest);
    let version = |row: &LaneRowV1| (row.item_key, row.version_key);
    let parts = |rows: &[LaneRowV1]| -> HashMap<VersionKey, Sha256Digest> {
        let mut parts = HashMap::with_capacity(rows.len());
        for row in rows {
            parts.entry(version(row)).or_insert(row.body);
        }
        parts
    };
    let lexical_parts = parts(lexical);
    let dense_parts = parts(dense);
    let lexical: Vec<(VersionKey, f32)> = lexical
        .iter()
        .map(|row| (version(row), row.score))
        .collect();
    let dense: Vec<(VersionKey, f32)> = dense.iter().map(|row| (version(row), row.score)).collect();
    fuse_lanes(
        &lexical,
        &dense,
        RETRIEVAL_DENSE_MIN_COSINE_SIMILARITY,
        limit,
    )
    .into_iter()
    .map(|hit| {
        let lexical = hit.lexical_rank.is_some();
        let body = if lexical {
            lexical_parts[&hit.key]
        } else {
            dense_parts[&hit.key]
        };
        FusedHitV1 {
            body,
            score: hit.score,
            matched_by: lane_match(lexical, hit.dense_rank.is_some()),
            lexical_score: hit.lexical_score,
            dense_similarity: hit.dense_similarity,
        }
    })
    .collect()
}

/// Text an answer may carry: the recall plane's redaction again, then
/// markdown images defanged.
fn recall_text(text: &str) -> String {
    recall_text_marked(text).0
}

/// [`recall_text`], with what the read-time redaction removed.
fn recall_text_marked(text: &str) -> (String, Option<RecallRedactionV1>) {
    let (redacted, marker) = redact_for_recall_marked(text);
    (defang_markdown_images(&redacted), marker)
}

/// The root of the thread a reply is in, under the root's own object kind
/// ([`thread_root_item_key`]); `None` for a channel-level item, and for a
/// root that names itself.
fn thread_root_of(
    provider: &str,
    provider_scope_id: &str,
    object_kind: &str,
    external_id: &str,
    thread_root: Option<&str>,
) -> Result<Option<ItemThreadRootV1>> {
    thread_root
        .filter(|root| *root != external_id)
        .map(|root| {
            Ok(ItemThreadRootV1 {
                item_id: thread_root_item_key(
                    &ProviderKindV1::new(provider)?,
                    provider_scope_id,
                    &ObjectKindV1::new(object_kind)?,
                    root,
                ),
                external_id: root.to_owned(),
            })
        })
        .transpose()
}

/// One hit's citation marker from its grouped row: the counts whole, the
/// claim ids cut at [`MAX_HIT_CITATION_IDS`].
fn citation_marker(claims: i64, disputed: i64, mut claim_ids: Vec<i64>) -> Result<ItemCitedByV1> {
    let count = |value: i64, what: &str| {
        u32::try_from(value)
            .map_err(|_| FleetError::Memory(format!("a citation {what} count is out of range")))
    };
    claim_ids.truncate(MAX_HIT_CITATION_IDS);
    Ok(ItemCitedByV1 {
        claims: count(claims, "claim")?,
        disputed: count(disputed, "dispute")?,
        claim_ids,
    })
}

/// The first `limit` characters of `text`, and whether it was cut.
fn snippet(text: &str, limit: usize) -> (String, bool) {
    match text.char_indices().nth(limit) {
        Some((end, _)) => (text[..end].to_owned(), true),
        None => (text.to_owned(), false),
    }
}

/// A title an answer may carry, and the text the signals read.
fn recalled_title(envelope: &CollectedItemEnvelopeV1) -> Option<String> {
    envelope
        .title
        .as_ref()
        .map(|title| recall_text(title.as_str()))
}

/// The attested author a version names, its display name redacted.
fn author_of(envelope: &CollectedItemEnvelopeV1) -> Option<ItemAuthorRefV1> {
    envelope.author.as_ref().map(|author| ItemAuthorRefV1 {
        id: author.id.as_str().to_owned(),
        display: author
            .display
            .as_ref()
            .map(|display| redact_for_recall(display.as_str())),
        kind: author.kind.as_str().to_owned(),
        attested: true,
    })
}

/// The container a version names, with the label its collector recorded
/// last in place of the version's own when there is one.
fn container_of(
    envelope: &CollectedItemEnvelopeV1,
    recorded_label: Option<String>,
) -> Option<ItemContainerRefV1> {
    envelope
        .container
        .as_ref()
        .map(|container| ItemContainerRefV1 {
            kind: container.kind.as_str().to_owned(),
            id: container.id.as_str().to_owned(),
            label: recorded_label.or_else(|| {
                container
                    .label
                    .as_ref()
                    .map(|label| label.as_str().to_owned())
            }),
        })
}

/// The signals of one part: its title and text, as recalled before
/// defanging, and what the sanitizer stripped from the item.
fn part_signals(envelope: &CollectedItemEnvelopeV1) -> Vec<InjectionSignalV1> {
    let title = envelope
        .title
        .as_ref()
        .map(|title| redact_for_recall(title.as_str()));
    let text = redact_for_recall(envelope.text.as_str());
    injection_signals(
        title.iter().map(String::as_str).chain([text.as_str()]),
        envelope.redaction.hidden_scalars_removed,
    )
}

fn decode_envelope(bytes: &[u8]) -> Result<CollectedItemEnvelopeV1> {
    Ok(CollectedItemEnvelopeV1::decode(bytes)?)
}

fn order_of(row: &PgRow) -> Result<u64> {
    let order: i64 = row.try_get("provider_order")?;
    u64::try_from(order)
        .map_err(|_| FleetError::Memory("a stored provider order is negative".to_owned()))
}

fn small(row: &PgRow, column: &str) -> Result<u32> {
    let value: i64 = row.try_get(column)?;
    u32::try_from(value).map_err(|_| FleetError::Memory(format!("stored {column} is out of range")))
}

fn optional_digest(row: &PgRow, column: &str) -> Result<Option<Sha256Digest>> {
    let bytes: Option<Vec<u8>> = row.try_get(column)?;
    bytes
        .map(|bytes| {
            let bytes: [u8; 32] = bytes
                .try_into()
                .map_err(|_| FleetError::Memory(format!("stored {column} is not 32 bytes")))?;
            Ok(Sha256Digest::from_bytes(bytes))
        })
        .transpose()
}

fn digest_list(digests: impl IntoIterator<Item = Sha256Digest>) -> Vec<Vec<u8>> {
    digests
        .into_iter()
        .map(|digest| digest.as_bytes().to_vec())
        .collect()
}

/// One admitted part of the item `get` reads.
#[derive(Debug, Clone)]
struct HistoryRowV1 {
    accepted_event_id: Sha256Digest,
    version_key: Sha256Digest,
    part_ordinal: u32,
    part_count: u32,
    mode: CollectionModeV1,
    tier: TrustTierV1,
    instance: String,
    attester: Option<String>,
    lifecycle: ItemLifecycleV1,
    marker: String,
    order: u64,
    redaction_profile: u32,
    thread_root: Option<String>,
    provider_url: Option<String>,
    created_at: Option<DateTime<Utc>>,
    updated_at: Option<DateTime<Utc>>,
    uri: String,
    body: Sha256Digest,
    admitted_at: DateTime<Utc>,
    /// The container this row was admitted in is withdrawn now.
    container_withdrawn: bool,
}

impl HistoryRowV1 {
    fn decode(row: &PgRow) -> Result<Self> {
        let mode: String = row.try_get("collection_mode")?;
        let tier: String = row.try_get("trust_tier")?;
        let lifecycle: String = row.try_get("lifecycle")?;
        Ok(Self {
            accepted_event_id: digest(row, "accepted_event_id")?,
            version_key: digest(row, "version_key_digest")?,
            part_ordinal: small(row, "part_ordinal")?,
            part_count: small(row, "part_count")?,
            mode: CollectionModeV1::parse(&mode)?,
            tier: TrustTierV1::parse(&tier)?,
            instance: row.try_get("collector_instance_id")?,
            attester: row.try_get("attester_principal_id")?,
            lifecycle: ItemLifecycleV1::parse(&lifecycle)?,
            marker: row.try_get("version_marker")?,
            order: order_of(row)?,
            redaction_profile: small(row, "redaction_profile")?,
            thread_root: row.try_get("thread_root_external_id")?,
            provider_url: row.try_get("provider_url")?,
            created_at: row.try_get("provider_created_at")?,
            updated_at: row.try_get("provider_updated_at")?,
            uri: row.try_get("canonical_resource_id")?,
            body: digest(row, "body_content_id")?,
            admitted_at: row.try_get("admitted_at")?,
            container_withdrawn: row.try_get("container_withdrawn")?,
        })
    }
}

/// The presented head of the item `get` reads.
#[derive(Debug, Clone)]
struct PresentedHeadV1 {
    tier: TrustTierV1,
    version_key: Sha256Digest,
    lifecycle: ItemLifecycleV1,
    disagreement: bool,
    provider: String,
    provider_scope_id: String,
    object_kind: String,
    external_id: String,
    container_label: Option<String>,
    suppressed: Option<ItemSuppressionV1>,
}

/// One version of the item `get` reads: its rows, in part order.
#[derive(Debug)]
struct VersionRowsV1 {
    version_key: Sha256Digest,
    rows: Vec<HistoryRowV1>,
}

impl VersionRowsV1 {
    /// One row per ordinal: the presented tier's copy first, then the
    /// earliest admitted.
    fn representatives(&self, presented: TrustTierV1) -> Vec<&HistoryRowV1> {
        let mut chosen: BTreeMap<u32, &HistoryRowV1> = BTreeMap::new();
        for row in &self.rows {
            chosen
                .entry(row.part_ordinal)
                .and_modify(|current| {
                    if current.tier != presented && row.tier == presented {
                        *current = row;
                    }
                })
                .or_insert(row);
        }
        chosen.into_values().collect()
    }
}

impl CockroachItemRecall {
    /// Item recall over the scope `capability` was probed for.
    #[must_use]
    pub fn new(capability: ItemRecallCapability, pool: PgPool) -> Self {
        let ItemRecallCapability {
            tenant_id,
            project,
            model_digest,
            dense_served,
        } = capability;
        Self {
            reader: CockroachRecallReader::new(pool.clone(), tenant_id, project.clone()),
            pool,
            tenant_id,
            project,
            model_digest,
            dense_served,
            claim_citations: false,
        }
    }

    /// List, in each `get`, the claims that cite the item (ADR 0008 D11), as
    /// the claim item links probe found this login may read them.
    #[must_use]
    pub const fn with_claim_citations(mut self, _capability: ClaimItemLinksCapability) -> Self {
        self.claim_citations = true;
        self
    }

    /// The claims that cite `item`, when this reader lists them; and
    /// whether more cite it than one answer lists.
    async fn citations(&self, item: Sha256Digest) -> Result<(Option<Vec<ItemCitationV1>>, bool)> {
        if !self.claim_citations {
            return Ok((None, false));
        }
        let rows: Vec<PgRow> = sqlx::query(CITATIONS_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(item.as_bytes().as_slice())
            .bind(listing_limit(MAX_ITEM_CITATIONS + 1))
            .fetch_all(&self.pool)
            .await?;
        let truncated = rows.len() > MAX_ITEM_CITATIONS;
        let citations = rows
            .iter()
            .take(MAX_ITEM_CITATIONS)
            .map(|row| {
                Ok(ItemCitationV1 {
                    claim_id: row.try_get("claim_id")?,
                    via: row.try_get("via")?,
                    relation: row.try_get("relation")?,
                    version_id: digest(row, "version_key_digest")?,
                    claim_state: row.try_get("claim_state")?,
                    cited_at: row.try_get("cited_at")?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok((Some(citations), truncated))
    }

    /// The citation marker of each hit's item, when this reader lists
    /// citations: one grouped read over the page's items, an item no claim
    /// cites marked as such rather than left unmarked.
    async fn attach_citations(&self, hits: &mut [ItemHitV1]) -> Result<()> {
        if !self.claim_citations || hits.is_empty() {
            return Ok(());
        }
        let items: BTreeSet<Sha256Digest> = hits.iter().map(|hit| hit.item_id).collect();
        let rows: Vec<PgRow> = sqlx::query(HIT_CITATIONS_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(digest_list(items.iter().copied()))
            .fetch_all(&self.pool)
            .await?;
        let mut markers: HashMap<Sha256Digest, ItemCitedByV1> = HashMap::with_capacity(rows.len());
        for row in &rows {
            let claim_ids: Vec<i64> = row.try_get("claim_ids")?;
            markers.insert(
                digest(row, "item_key_digest")?,
                citation_marker(row.try_get("claims")?, row.try_get("disputed")?, claim_ids)?,
            );
        }
        for hit in hits {
            hit.cited_by = Some(
                markers
                    .get(&hit.item_id)
                    .cloned()
                    .unwrap_or_else(ItemCitedByV1::none),
            );
        }
        Ok(())
    }

    /// The live and snapshot collectors of `provider`, or of every provider,
    /// and each one's newest coverage cursor.
    async fn read_sources(&self, provider: Option<&str>) -> Result<EvidenceSourcesV1> {
        let rows: Vec<PgRow> = sqlx::query(SOURCES_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(provider)
            .bind(listing_limit(MAX_EVIDENCE_SOURCES + 1))
            .fetch_all(&self.pool)
            .await?;
        let mut active = rows
            .iter()
            .map(decode_collector_source_row)
            .collect::<Result<Vec<_>>>()?;
        let truncated = active.len() > MAX_EVIDENCE_SOURCES;
        active.truncate(MAX_EVIDENCE_SOURCES);
        attach_coverage(&self.pool, self.tenant_id, &self.project, &mut active).await?;
        Ok(EvidenceSourcesV1 { active, truncated })
    }

    /// Collection and projection lag. Read after the sources and before the
    /// lanes, and upstream first, as evidence recall reads it: hints, then
    /// the outbox and the evidence awaiting projection (one statement), then
    /// the lexical tier.
    async fn read_readiness(
        &self,
        dense_lane: EvidenceDenseLaneV1,
        provider: Option<&str>,
    ) -> Result<ItemReadinessV1> {
        let hints =
            count_pending_hints(&self.pool, self.tenant_id, &self.project, provider).await?;
        let row: PgRow = sqlx::query(READINESS_SQL.as_str())
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(provider)
            .fetch_one(&self.pool)
            .await?;
        let completeness = self.reader.completeness().await?;
        Ok(ItemReadinessV1 {
            items_awaiting_admission: count(&row, "items_pending")?,
            hints_awaiting_fetch: hints.count(),
            hints_unreadable: hints.unreadable(),
            events_awaiting_body_projection: count(&row, "events_awaiting_bodies")?,
            lexical_current: completeness.lexical_complete(),
            dense_current: completeness.dense_complete(),
            dense_lane,
            as_of: row.try_get("as_of")?,
        })
    }

    async fn lexical_lane(
        &self,
        lexical_text: &str,
        request: &ItemSearchRequestV1,
    ) -> Result<Vec<LaneRowV1>> {
        let rows: Vec<PgRow> = sqlx::query(LEXICAL_ITEMS_SQL.as_str())
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(lexical_text)
            .bind(request.provider.as_ref().map(ProviderKindV1::as_str))
            .bind(request.include_history)
            .bind(listing_limit(lane_depth(request.limit)))
            .fetch_all(&self.pool)
            .await?;
        rows.iter()
            .map(|row| lane_row(row, "score"))
            .collect::<Result<Vec<_>>>()
    }

    async fn dense_lane(
        &self,
        vector: &[f32],
        request: &ItemSearchRequestV1,
    ) -> Result<Vec<LaneRowV1>> {
        if vector.len() != EMBEDDING_DIMENSIONS as usize {
            return Err(FleetError::Memory(format!(
                "item query vector must have {EMBEDDING_DIMENSIONS} components"
            )));
        }
        let rows: Vec<PgRow> = sqlx::query(DENSE_ITEMS_SQL.as_str())
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(serialize_vector(vector)?)
            .bind(request.provider.as_ref().map(ProviderKindV1::as_str))
            .bind(request.include_history)
            .bind(listing_limit(lane_depth(request.limit)))
            .bind(self.model_digest.as_bytes().as_slice())
            .fetch_all(&self.pool)
            .await?;
        rows.iter()
            .map(|row| lane_row(row, "distance"))
            .collect::<Result<Vec<_>>>()
    }

    /// Attach each fused hit's part, item, and envelope, keeping the order.
    async fn hydrate(&self, fused: Vec<FusedHitV1>) -> Result<Vec<ItemHitV1>> {
        if fused.is_empty() {
            return Ok(Vec::new());
        }
        let rows: Vec<PgRow> = sqlx::query(HYDRATE_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(digest_list(fused.iter().map(|hit| hit.body)))
            .fetch_all(&self.pool)
            .await?;
        let mut parts = HashMap::with_capacity(rows.len());
        for row in rows {
            parts.entry(digest(&row, "body_content_id")?).or_insert(row);
        }
        let items: BTreeSet<Sha256Digest> = parts
            .values()
            .map(|row| digest(row, "item_key_digest"))
            .collect::<Result<_>>()?;
        let modes = self.version_modes(&items).await?;
        let mut hits = fused
            .into_iter()
            .map(|hit| {
                let row = parts.remove(&hit.body).ok_or_else(|| {
                    FleetError::Memory(format!(
                        "recalled item body {} has no item row and body row in this scope",
                        hit.body
                    ))
                })?;
                hit_from_row(&hit, &row, &modes)
            })
            .collect::<Result<Vec<_>>>()?;
        self.attach_citations(&mut hits).await?;
        Ok(hits)
    }

    /// Per item, each version's admitting channels.
    async fn version_modes(&self, items: &BTreeSet<Sha256Digest>) -> Result<VersionModes> {
        let rows: Vec<PgRow> = sqlx::query(VERSION_MODES_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(digest_list(items.iter().copied()))
            .fetch_all(&self.pool)
            .await?;
        let mut modes: VersionModes = BTreeMap::new();
        for row in &rows {
            let mode: String = row.try_get("collection_mode")?;
            modes
                .entry(digest(row, "item_key_digest")?)
                .or_default()
                .entry(digest(row, "version_key_digest")?)
                .or_default()
                .insert(CollectionModeV1::parse(&mode)?);
        }
        Ok(modes)
    }

    /// The item key (and version) a reference names.
    async fn resolve(
        &self,
        reference: &ItemReferenceV1,
    ) -> Result<Option<(Sha256Digest, Option<Sha256Digest>)>> {
        let (statement, value) = match reference {
            ItemReferenceV1::Item(item) => return Ok(Some((*item, None))),
            ItemReferenceV1::VersionUri(uri) => (RESOLVE_URI_SQL, uri),
            ItemReferenceV1::ProviderUrl(url) => (RESOLVE_URL_SQL, url),
        };
        let row: Option<PgRow> = sqlx::query(statement)
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(value)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|row| {
            Ok((
                digest(&row, "item_key_digest")?,
                Some(digest(&row, "version_key_digest")?),
            ))
        })
        .transpose()
    }

    async fn presented_head(&self, item: Sha256Digest) -> Result<Option<PresentedHeadV1>> {
        let row: Option<PgRow> = sqlx::query(PRESENTED_HEAD_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(item.as_bytes().as_slice())
            .fetch_optional(&self.pool)
            .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let tier: String = row.try_get("trust_tier")?;
        let lifecycle: String = row.try_get("lifecycle")?;
        let lifecycle = ItemLifecycleV1::parse(&lifecycle)?;
        let access: Option<String> = row.try_get("container_access")?;
        let item_withdrawn: bool = row.try_get("item_withdrawn")?;
        let suppressed = if lifecycle.is_tombstone() {
            Some(ItemSuppressionV1::Deleted)
        } else if access.as_deref().is_some_and(|access| access != "ok") {
            Some(ItemSuppressionV1::ContainerWithdrawn)
        } else if item_withdrawn {
            Some(ItemSuppressionV1::ItemWithdrawn)
        } else {
            None
        };
        Ok(Some(PresentedHeadV1 {
            tier: TrustTierV1::parse(&tier)?,
            version_key: digest(&row, "version_key_digest")?,
            lifecycle,
            disagreement: row.try_get("disagreement")?,
            provider: row.try_get("provider")?,
            provider_scope_id: row.try_get("provider_scope_id")?,
            object_kind: row.try_get("object_kind")?,
            external_id: row.try_get("external_id")?,
            container_label: row.try_get("container_label")?,
            suppressed,
        }))
    }

    /// The item's admitted parts grouped by version, the presented version
    /// first and then the greatest provider order; and whether the read was
    /// cut at [`MAX_ITEM_GET_ROWS`].
    async fn history(
        &self,
        item: Sha256Digest,
        presented: Sha256Digest,
    ) -> Result<(Vec<VersionRowsV1>, bool)> {
        let rows: Vec<PgRow> = sqlx::query(HISTORY_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(item.as_bytes().as_slice())
            .bind(listing_limit(MAX_ITEM_GET_ROWS + 1))
            .bind(presented.as_bytes().as_slice())
            .fetch_all(&self.pool)
            .await?;
        let truncated = rows.len() > MAX_ITEM_GET_ROWS;
        let mut versions: Vec<VersionRowsV1> = Vec::new();
        for row in rows.iter().take(MAX_ITEM_GET_ROWS) {
            let row = HistoryRowV1::decode(row)?;
            match versions.last_mut() {
                Some(version) if version.version_key == row.version_key => version.rows.push(row),
                _ => versions.push(VersionRowsV1 {
                    version_key: row.version_key,
                    rows: vec![row],
                }),
            }
        }
        Ok((versions, truncated))
    }

    /// The envelopes of `bodies`, read in order a batch at a time until
    /// their text alone would exceed [`MAX_ITEM_GET_TEXT_BYTES`]: a long
    /// history never loads bodies whose text the answer could not carry.
    async fn envelopes_within_budget(
        &self,
        bodies: &[Sha256Digest],
    ) -> Result<HashMap<Sha256Digest, CollectedItemEnvelopeV1>> {
        let mut envelopes = HashMap::new();
        let mut text_bytes = 0_usize;
        for batch in bodies.chunks(ENVELOPE_BATCH) {
            if text_bytes > MAX_ITEM_GET_TEXT_BYTES {
                break;
            }
            let read = self.envelopes(batch).await?;
            text_bytes = read.values().fold(text_bytes, |total, envelope| {
                total.saturating_add(envelope.text.as_str().len())
            });
            envelopes.extend(read);
        }
        Ok(envelopes)
    }

    /// Body envelopes by content address.
    async fn envelopes(
        &self,
        bodies: &[Sha256Digest],
    ) -> Result<HashMap<Sha256Digest, CollectedItemEnvelopeV1>> {
        if bodies.is_empty() {
            return Ok(HashMap::new());
        }
        let rows: Vec<PgRow> = sqlx::query(BODIES_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(digest_list(bodies.iter().copied()))
            .fetch_all(&self.pool)
            .await?;
        let mut envelopes = HashMap::with_capacity(rows.len());
        for row in &rows {
            let bytes: Vec<u8> = row.try_get("body_bytes")?;
            envelopes.insert(digest(row, "content_sha256")?, decode_envelope(&bytes)?);
        }
        Ok(envelopes)
    }

    async fn links_out(&self, parts: &[&HistoryRowV1]) -> Result<Vec<ItemLinkOutV1>> {
        if parts.is_empty() {
            return Ok(Vec::new());
        }
        let rows: Vec<PgRow> = sqlx::query(LINKS_OUT_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(digest_list(parts.iter().map(|part| part.accepted_event_id)))
            .fetch_all(&self.pool)
            .await?;
        let mut by_event: HashMap<Sha256Digest, Vec<ItemLinkOutV1>> = HashMap::new();
        for row in &rows {
            by_event
                .entry(digest(row, "accepted_event_id")?)
                .or_default()
                .push(ItemLinkOutV1 {
                    rel: row.try_get("rel")?,
                    target: row.try_get("target")?,
                });
        }
        let mut links: Vec<ItemLinkOutV1> = Vec::new();
        for part in parts {
            for link in by_event.remove(&part.accepted_event_id).unwrap_or_default() {
                if !links.contains(&link) {
                    links.push(link);
                }
            }
        }
        Ok(links)
    }

    async fn links_in(
        &self,
        item: Sha256Digest,
        targets: &BTreeSet<String>,
    ) -> Result<Vec<ItemLinkInV1>> {
        if targets.is_empty() {
            return Ok(Vec::new());
        }
        let targets: Vec<&str> = targets.iter().map(String::as_str).collect();
        let rows: Vec<PgRow> = sqlx::query(LINKS_IN_SQL.as_str())
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(&targets)
            .bind(item.as_bytes().as_slice())
            .bind(listing_limit(MAX_ITEM_LINKS_IN))
            .fetch_all(&self.pool)
            .await?;
        rows.iter()
            .map(|row| {
                Ok(ItemLinkInV1 {
                    item_id: digest(row, "item_key_digest")?,
                    provider: row.try_get("provider")?,
                    object_kind: row.try_get("object_kind")?,
                    external_id: row.try_get("external_id")?,
                    rel: row.try_get("rel")?,
                })
            })
            .collect()
    }
}

/// Per item, per version, the channels that admitted it.
type VersionModes = BTreeMap<Sha256Digest, BTreeMap<Sha256Digest, BTreeSet<CollectionModeV1>>>;

fn lane_row(row: &PgRow, score: &str) -> Result<LaneRowV1> {
    Ok(LaneRowV1 {
        item_key: digest(row, "item_key_digest")?,
        version_key: digest(row, "version_key_digest")?,
        body: digest(row, "body_content_id")?,
        score: row.try_get(score)?,
    })
}

/// One hydrated hit.
fn hit_from_row(hit: &FusedHitV1, row: &PgRow, modes: &VersionModes) -> Result<ItemHitV1> {
    let bytes: Vec<u8> = row.try_get("body_bytes")?;
    let envelope = decode_envelope(&bytes)?;
    let item_id = digest(row, "item_key_digest")?;
    let version_id = digest(row, "version_key_digest")?;
    let head_version = optional_digest(row, "head_version_key")?;
    let item_versions = modes.get(&item_id);
    let versions = item_versions.map_or(1, BTreeMap::len);
    let tier: String = row.try_get("trust_tier")?;
    let lifecycle: String = row.try_get("lifecycle")?;
    let (text, redacted_at_read) = recall_text_marked(envelope.text.as_str());
    let (snippet, snippet_truncated) = snippet(&text, ITEM_SNIPPET_CHARS);
    let provider: String = row.try_get("provider")?;
    let object_kind: String = row.try_get("object_kind")?;
    let external_id: String = row.try_get("external_id")?;
    let thread_root: Option<String> = row.try_get("thread_root_external_id")?;
    let provider_scope_id: String = row.try_get("provider_scope_id")?;
    let thread_root = thread_root_of(
        &provider,
        &provider_scope_id,
        &object_kind,
        &external_id,
        thread_root.as_deref(),
    )?;
    Ok(ItemHitV1 {
        item_id,
        version_id,
        uri: row.try_get("canonical_resource_id")?,
        provider,
        object_kind,
        external_id,
        title: recalled_title(&envelope),
        snippet,
        snippet_truncated,
        container: container_of(&envelope, row.try_get("container_label")?),
        author: author_of(&envelope),
        created_at: row.try_get("provider_created_at")?,
        updated_at: row.try_get("provider_updated_at")?,
        version: ItemVersionRefV1 {
            marker: row.try_get("version_marker")?,
            order: order_of(row)?,
            lifecycle: ItemLifecycleV1::parse(&lifecycle)?,
        },
        part: ItemPartRefV1 {
            ordinal: small(row, "part_ordinal")?,
            count: small(row, "part_count")?,
            anchor: envelope
                .part
                .anchor
                .as_ref()
                .map(|anchor| anchor.as_str().to_owned()),
        },
        provider_url: row.try_get("provider_url")?,
        trust: TrustTierV1::parse(&tier)?,
        collection_modes: item_versions
            .and_then(|versions| versions.get(&version_id))
            .map(|modes| modes.iter().copied().collect())
            .unwrap_or_default(),
        current: head_version == Some(version_id),
        accepted_event_id: digest(row, "accepted_event_id")?,
        body_id: hit.body,
        score: hit.score,
        matched_by: hit.matched_by,
        lexical_score: hit.lexical_score,
        dense_similarity: hit.dense_similarity,
        superseded_versions: u64::try_from(versions.saturating_sub(1)).unwrap_or(u64::MAX),
        disagreement: row
            .try_get::<Option<bool>, _>("disagreement")?
            .unwrap_or(false),
        content_trust: ContentTrustV1::UntrustedThirdParty,
        injection_signals: part_signals(&envelope),
        // Attached after hydration, where citations are served.
        cited_by: None,
        thread_root_external_id: thread_root.as_ref().map(|root| root.external_id.clone()),
        thread_root_item_id: thread_root.map(|root| root.item_id),
        redaction_profile: small(row, "redaction_profile")?,
        redacted_at_read,
    })
}

/// What `get` may still spend on text.
struct TextBudgetV1 {
    remaining: usize,
    exhausted: bool,
}

impl TextBudgetV1 {
    /// `text` when it fits, else nothing, and the budget marked cut.
    fn take(&mut self, text: String) -> Option<String> {
        if text.len() <= self.remaining {
            self.remaining -= text.len();
            Some(text)
        } else {
            self.cut()
        }
    }

    /// Nothing, and the budget marked cut.
    const fn cut(&mut self) -> Option<String> {
        self.exhausted = true;
        None
    }
}

/// One version's record: its parts in order, with text only when `with_text`
/// and the budget allows, and every admission.
fn version_record(
    version: &VersionRowsV1,
    presented: &PresentedHeadV1,
    envelopes: &HashMap<Sha256Digest, CollectedItemEnvelopeV1>,
    with_text: bool,
    budget: &mut TextBudgetV1,
) -> ItemVersionRecordV1 {
    let representatives = version.representatives(presented.tier);
    let first = representatives[0];
    let lead = representatives
        .iter()
        .find_map(|part| envelopes.get(&part.body));
    // A version admitted in a container since withdrawn is withheld as
    // evidence recall withholds its bodies, even when the item moved to a
    // container that is still readable.
    let withdrawn = representatives.iter().any(|part| part.container_withdrawn);
    let show = with_text && !first.lifecycle.is_tombstone() && !withdrawn;
    let parts = representatives
        .iter()
        .map(|part| {
            let envelope = envelopes.get(&part.body);
            let (text, redacted_at_read) = match (show, envelope) {
                (true, Some(envelope)) => {
                    let (text, marker) = recall_text_marked(envelope.text.as_str());
                    let text = budget.take(text);
                    // The marker describes text the answer carries.
                    let marker = marker.filter(|_| text.is_some());
                    (text, marker)
                }
                // A body left unread is past the budget.
                (true, None) => (budget.cut(), None),
                (false, _) => (None, None),
            };
            ItemPartTextV1 {
                ordinal: part.part_ordinal,
                count: part.part_count,
                anchor: envelope
                    .and_then(|envelope| envelope.part.anchor.as_ref())
                    .map(|anchor| anchor.as_str().to_owned()),
                uri: part.uri.clone(),
                accepted_event_id: part.accepted_event_id,
                body_id: part.body,
                text,
                redacted_at_read,
                injection_signals: envelope
                    .filter(|_| show)
                    .map(part_signals)
                    .unwrap_or_default(),
            }
        })
        .collect();
    ItemVersionRecordV1 {
        version_id: version.version_key,
        marker: first.marker.clone(),
        order: first.order,
        lifecycle: first.lifecycle,
        current: version.version_key == presented.version_key,
        suppressed: withdrawn.then_some(ItemSuppressionV1::ContainerWithdrawn),
        title: lead.filter(|_| show).and_then(recalled_title),
        author: lead.filter(|_| show).and_then(author_of),
        created_at: first.created_at,
        updated_at: first.updated_at,
        parts,
        provenance: version
            .rows
            .iter()
            .map(|row| ItemProvenanceV1 {
                part_ordinal: row.part_ordinal,
                mode: row.mode,
                collector_instance: row.instance.clone(),
                attester: row.attester.clone(),
                trust: row.tier,
                admitted_at: row.admitted_at,
                accepted_event_id: row.accepted_event_id,
                redaction_profile: row.redaction_profile,
            })
            .collect(),
    }
}

#[async_trait]
impl ItemRecall for CockroachItemRecall {
    async fn search(
        &self,
        request: &ItemSearchRequestV1,
        query_vector: Option<Vec<f32>>,
    ) -> Result<ItemSearchV1> {
        if request.limit == 0 || request.limit > MAX_ITEM_SEARCH_LIMIT {
            return Err(FleetError::Memory(format!(
                "item search limit must be between 1 and {MAX_ITEM_SEARCH_LIMIT}"
            )));
        }
        let provider = request.provider.as_ref().map(ProviderKindV1::as_str);
        let lexical_text = lexical_query_text(&request.query);
        let lane = dense_lane(self.dense_served, Some(query_vector.is_some()));
        // Sources, then readiness, then the lanes: the order that makes an
        // absent verdict sound (see evidence recall).
        let sources = self.read_sources(provider).await?;
        let readiness = self.read_readiness(lane, provider).await?;
        let lexical_terms = has_lexical_terms(&self.pool, &lexical_text).await?;
        let lexical = if lexical_terms {
            self.lexical_lane(&lexical_text, request).await?
        } else {
            Vec::new()
        };
        let dense = match query_vector.filter(|_| lane == EvidenceDenseLaneV1::Used) {
            Some(vector) => self.dense_lane(&vector, request).await?,
            None => Vec::new(),
        };
        let hits = self.hydrate(fuse(&lexical, &dense, request.limit)).await?;
        let votes: Vec<_> = hits.iter().map(ItemHitV1::vote).collect();
        let absence = absence_verdict(&votes, lexical_terms, &readiness.as_evidence(), &sources);
        Ok(ItemSearchV1 {
            hits,
            readiness,
            sources,
            absence,
        })
    }

    async fn get(&self, reference: &ItemReferenceV1) -> Result<Option<ItemGetV1>> {
        let Some((item, requested_version_id)) = self.resolve(reference).await? else {
            return Ok(None);
        };
        let Some(head) = self.presented_head(item).await? else {
            return Ok(None);
        };
        let (versions, history_truncated) = self.history(item, head.version_key).await?;
        // The presented version is sorted first; a history cut before it
        // leaves nothing to present.
        let Some(current) = versions
            .first()
            .filter(|version| version.version_key == head.version_key)
        else {
            return Ok(None);
        };
        let hidden = head.suppressed.is_some();
        // The presented version's first part always, for the container; the
        // rest only where text may be shown, in answer order, while the text
        // budget lasts. A hidden item's answer reads no other body.
        let lead_body = current.representatives(head.tier)[0].body;
        let mut bodies = vec![lead_body];
        if !hidden {
            bodies.extend(
                versions
                    .iter()
                    .map(|version| version.representatives(head.tier))
                    // A version whose own container is withdrawn shows no
                    // text, so none of its bodies is read.
                    .filter(|parts| !parts.iter().any(|part| part.container_withdrawn))
                    .flatten()
                    .filter(|part| !part.lifecycle.is_tombstone() && part.body != lead_body)
                    .map(|part| part.body),
            );
        }
        let envelopes = self.envelopes_within_budget(&bodies).await?;
        let mut budget = TextBudgetV1 {
            remaining: MAX_ITEM_GET_TEXT_BYTES,
            exhausted: false,
        };
        let records: Vec<ItemVersionRecordV1> = versions
            .iter()
            .map(|version| version_record(version, &head, &envelopes, !hidden, &mut budget))
            .collect();
        let current_parts = current.representatives(head.tier);
        let lead = current_parts
            .iter()
            .find_map(|part| envelopes.get(&part.body));
        let provider_urls: BTreeSet<String> = versions
            .iter()
            .flat_map(|version| &version.rows)
            .filter_map(|row| row.provider_url.clone())
            .collect();
        let links_out = if hidden {
            Vec::new()
        } else {
            self.links_out(&current_parts).await?
        };
        let links_in = self.links_in(item, &provider_urls).await?;
        let (cited_by, cited_by_truncated) = self.citations(item).await?;
        let first = current_parts[0];
        let mut records = records.into_iter();
        let current_record = records
            .next()
            .ok_or_else(|| FleetError::Memory("an item get lost its presented version".into()))?;
        // A reply's thread: its root, reachable in one more `get`.
        let thread = thread_root_of(
            &head.provider,
            &head.provider_scope_id,
            &head.object_kind,
            &head.external_id,
            first.thread_root.as_deref(),
        )?
        .map(|root| ItemThreadV1 { root });
        Ok(Some(ItemGetV1 {
            item: ItemSummaryV1 {
                item_id: item,
                provider: head.provider,
                provider_scope_id: head.provider_scope_id,
                object_kind: head.object_kind,
                external_id: head.external_id,
                container: lead.and_then(|envelope| container_of(envelope, head.container_label)),
                thread_root_external_id: first.thread_root.clone(),
                provider_url: first.provider_url.clone(),
                trust: head.tier,
                lifecycle: head.lifecycle,
                disagreement: head.disagreement,
                versions: u64::try_from(versions.len()).unwrap_or(u64::MAX),
            },
            thread,
            content_trust: ContentTrustV1::UntrustedThirdParty,
            suppressed: head.suppressed,
            requested_version_id,
            current: current_record,
            history: records.collect(),
            history_truncated,
            text_truncated: budget.exhausted,
            links_out,
            links_in,
            cited_by,
            cited_by_truncated,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([byte; 32])
    }

    fn row(item: u8, version: u8, body: u8, score: f32) -> LaneRowV1 {
        LaneRowV1 {
            item_key: key(item),
            version_key: key(version),
            body: key(body),
            score,
        }
    }

    #[test]
    fn fusion_ranks_versions_by_reciprocal_rank_over_both_lanes_and_applies_the_floor() {
        let lexical = [row(1, 10, 100, 0.9), row(2, 20, 200, 0.5)];
        let dense = [
            // The second lexical version's nearest part: similarity 0.8.
            row(2, 20, 201, 0.2),
            // A version only the dense lane found, above the floor.
            row(3, 30, 230, 0.4),
            // Below the floor: nearest-neighbour padding, dropped.
            row(4, 40, 240, 0.95),
        ];
        let fused = fuse(&lexical, &dense, 10);
        // Second in both lanes beats first in one; the both-lane version
        // keeps its lexical part (200), not its nearest dense part (201).
        assert_eq!(
            fused.iter().map(|hit| hit.body).collect::<Vec<_>>(),
            [key(200), key(100), key(230)]
        );
        assert_eq!(
            fused.iter().map(|hit| hit.matched_by).collect::<Vec<_>>(),
            [
                EvidenceMatchV1::LexicalAndDense,
                EvidenceMatchV1::Lexical,
                EvidenceMatchV1::Dense
            ]
        );
        assert!((fused[0].dense_similarity.unwrap() - 0.8).abs() < 1e-6);
        assert_eq!(fused[0].lexical_score, Some(0.5));
        assert!((fused[0].score - (1.0 / 61.0 + 1.0 / 60.0) / (2.0 / 60.0)).abs() < 1e-6);
        assert!((fused[1].score - 0.5).abs() < 1e-6);
        assert!((fused[2].score - 30.0 / 61.0).abs() < 1e-6);
        assert_eq!(fused[2].lexical_score, None);
        assert_eq!(
            fuse(&lexical, &dense, 1)
                .iter()
                .map(|hit| hit.body)
                .collect::<Vec<_>>(),
            [key(200)]
        );
    }

    #[test]
    fn a_lexical_row_below_the_cutoff_leaves_its_version_to_the_dense_lane() {
        // The version's lexical row is a co-occurrence, not a match: the hit
        // is dense-only and carries the dense lane's nearest part.
        let lexical = [row(1, 10, 100, 0.0006)];
        let dense = [row(1, 10, 101, 0.3)];
        let fused = fuse(&lexical, &dense, 10);
        assert_eq!(fused.len(), 1);
        assert_eq!(fused[0].body, key(101));
        assert_eq!(fused[0].matched_by, EvidenceMatchV1::Dense);
        assert_eq!(fused[0].lexical_score, None);
        assert!(fuse(&lexical, &[], 10).is_empty());
    }

    #[test]
    fn a_snippet_is_cut_on_a_character_boundary() {
        assert_eq!(snippet("héllo", 2), ("hé".to_owned(), true));
        assert_eq!(snippet("hé", 2), ("hé".to_owned(), false));
        assert_eq!(snippet("", 2), (String::new(), false));
    }

    #[test]
    fn recalled_text_is_redacted_and_defanged() {
        // The collector redactor scrubbed the text at staging; the recall
        // plane's own redaction runs again over what an answer carries.
        let text = recall_text("creds AKIAIOSFODNN7EXAMPLE and ![p](https://evil.example/x.png)");
        assert!(!text.contains("AKIAIOSFODNN7EXAMPLE"), "{text}");
        assert!(
            text.contains("[image: p](hxxps://evil.example/x.png)"),
            "{text}"
        );
    }

    #[test]
    fn a_hit_citation_marker_keeps_its_counts_whole_and_cuts_its_ids() {
        let ids: Vec<i64> = (1..=12).collect();
        let marker = citation_marker(12, 3, ids).unwrap();
        assert_eq!(marker.claims, 12);
        assert_eq!(marker.disputed, 3);
        assert_eq!(marker.claim_ids, (1..=8).collect::<Vec<i64>>());
        assert_eq!(
            citation_marker(0, 0, Vec::new()).unwrap(),
            ItemCitedByV1::none()
        );
        assert!(citation_marker(-1, 0, Vec::new()).is_err());
    }

    #[test]
    fn a_part_carrying_redacted_text_says_what_the_read_pass_removed() {
        let presented = PresentedHeadV1 {
            tier: TrustTierV1::Verified,
            version_key: key(1),
            lifecycle: ItemLifecycleV1::Live,
            disagreement: false,
            provider: "docs".into(),
            provider_scope_id: "docs.acme.specs".into(),
            object_kind: "document".into(),
            external_id: "creds.md".into(),
            container_label: None,
            suppressed: None,
        };
        let version = VersionRowsV1 {
            version_key: key(1),
            rows: vec![history_row(0, TrustTierV1::Verified, 30)],
        };
        // A sealed envelope is clean; a body admitted before the ingress
        // redactors could still hold a secret at rest, which the read pass
        // removes and marks.
        let mut envelope = sealed_envelope("the pelican limit is ten");
        assert!(RecallRedactionV1::of(&crate::redaction::redact(envelope.text.as_str())).is_none());
        envelope.text = crate::memory_contracts::collected_item::CollectedTextV1::new(
            "creds are AKIAIOSFODNN7EXAMPLE for the bucket",
        )
        .unwrap();
        let envelopes: HashMap<Sha256Digest, CollectedItemEnvelopeV1> =
            std::iter::once((key(30), envelope)).collect();
        let mut budget = TextBudgetV1 {
            remaining: MAX_ITEM_GET_TEXT_BYTES,
            exhausted: false,
        };
        let record = version_record(&version, &presented, &envelopes, true, &mut budget);
        let part = &record.parts[0];
        let text = part.text.as_deref().unwrap();
        assert!(!text.contains("AKIAIOSFODNN7EXAMPLE"), "{text}");
        let marker = part
            .redacted_at_read
            .as_ref()
            .expect("the read pass marks what it removed");
        assert_eq!(marker.classes, ["aws_access_key_id"]);
        assert_eq!(marker.ranges, 1);
        assert_eq!(
            record.provenance[0].redaction_profile,
            crate::redaction::REDACTION_PROFILE_VERSION
        );

        // Past the text budget the part carries no text, so no marker either.
        let mut exhausted = TextBudgetV1 {
            remaining: 0,
            exhausted: false,
        };
        let cut = version_record(&version, &presented, &envelopes, true, &mut exhausted);
        assert_eq!(cut.parts[0].text, None);
        assert_eq!(cut.parts[0].redacted_at_read, None);
        assert!(exhausted.exhausted);
    }

    /// One sealed, clean document envelope carrying `text`.
    fn sealed_envelope(text: &str) -> CollectedItemEnvelopeV1 {
        use crate::collectors::draft::{
            CollectedItemDraftV1, DraftSectionV1, SealContextV1, collection_record, seal,
        };
        use crate::memory_contracts::collected_item::{
            AudienceBasisV1, ObjectKindV1, TextFormatV1,
        };
        use crate::memory_contracts::common::ContractId;

        let draft = CollectedItemDraftV1 {
            provider: ProviderKindV1::new("docs").unwrap(),
            provider_scope_id: "docs.acme.specs".into(),
            object_kind: ObjectKindV1::new("document").unwrap(),
            external_id: "creds.md".into(),
            marker: Some("m".into()),
            order_micros: 1,
            lifecycle: ItemLifecycleV1::Live,
            container: None,
            thread: None,
            author: None,
            created_at: None,
            updated_at: None,
            title: None,
            sections: vec![DraftSectionV1::whole(text.to_owned())],
            text_format: TextFormatV1::Markdown,
            links: Vec::new(),
            provider_url: None,
            visibility: None,
        };
        let collection = collection_record(
            CollectionModeV1::Pull,
            ContractId::new("docs.specs").unwrap(),
            None,
            None,
        )
        .unwrap();
        seal(
            &draft,
            &SealContextV1 {
                redactor: &crate::collectors::test_support::redactor(),
                audience: AudienceBasisV1::TeamPublic,
                collection: &collection,
            },
        )
        .unwrap()
        .parts
        .remove(0)
        .envelope
    }

    #[test]
    fn the_text_budget_cuts_whole_parts_and_says_so() {
        let mut budget = TextBudgetV1 {
            remaining: 5,
            exhausted: false,
        };
        assert_eq!(budget.take("abc".into()), Some("abc".into()));
        assert_eq!(budget.take("abc".into()), None);
        assert!(budget.exhausted);
        assert_eq!(budget.take("ab".into()), Some("ab".into()));
    }

    fn history_row(ordinal: u32, tier: TrustTierV1, event: u8) -> HistoryRowV1 {
        HistoryRowV1 {
            accepted_event_id: key(event),
            version_key: key(1),
            part_ordinal: ordinal,
            part_count: 2,
            mode: if tier == TrustTierV1::Verified {
                CollectionModeV1::Pull
            } else {
                CollectionModeV1::Import
            },
            tier,
            instance: "docs.specs".into(),
            attester: None,
            lifecycle: ItemLifecycleV1::Live,
            marker: "m".into(),
            order: 1,
            redaction_profile: crate::redaction::REDACTION_PROFILE_VERSION,
            thread_root: None,
            provider_url: None,
            created_at: None,
            updated_at: None,
            uri: format!("urn:part:{event}"),
            body: key(event),
            admitted_at: DateTime::from_timestamp(1_790_000_000, 0).unwrap(),
            container_withdrawn: false,
        }
    }

    #[test]
    fn a_version_admitted_in_a_withdrawn_container_shows_no_text() {
        let presented = PresentedHeadV1 {
            tier: TrustTierV1::Verified,
            version_key: key(2),
            lifecycle: ItemLifecycleV1::Live,
            disagreement: false,
            provider: "slack".into(),
            provider_scope_id: "T07ACME0001".into(),
            object_kind: "message".into(),
            external_id: "C07BBBBBBB2:1790006860.001100".into(),
            container_label: None,
            suppressed: None,
        };
        let mut withdrawn = history_row(0, TrustTierV1::Verified, 20);
        withdrawn.container_withdrawn = true;
        let version = VersionRowsV1 {
            version_key: key(1),
            rows: vec![withdrawn],
        };
        let mut budget = TextBudgetV1 {
            remaining: MAX_ITEM_GET_TEXT_BYTES,
            exhausted: false,
        };
        let record = version_record(&version, &presented, &HashMap::new(), true, &mut budget);
        assert_eq!(
            record.suppressed,
            Some(ItemSuppressionV1::ContainerWithdrawn)
        );
        assert!(record.parts.iter().all(|part| part.text.is_none()));
        assert!(record.title.is_none() && record.author.is_none());
        // Withheld, not cut: the answer says why, and the budget is untouched.
        assert!(!budget.exhausted);

        let readable = VersionRowsV1 {
            version_key: key(1),
            rows: vec![history_row(0, TrustTierV1::Verified, 21)],
        };
        let record = version_record(&readable, &presented, &HashMap::new(), true, &mut budget);
        assert_eq!(record.suppressed, None);
    }

    #[test]
    fn a_version_shows_one_part_per_ordinal_preferring_the_presented_tier() {
        let version = VersionRowsV1 {
            version_key: key(1),
            rows: vec![
                history_row(0, TrustTierV1::Reported, 10),
                history_row(0, TrustTierV1::Verified, 11),
                history_row(1, TrustTierV1::Reported, 12),
            ],
        };
        let chosen: Vec<u8> = version
            .representatives(TrustTierV1::Verified)
            .iter()
            .map(|row| row.accepted_event_id.as_bytes()[0])
            .collect();
        assert_eq!(chosen, [11, 12]);
        let chosen: Vec<u8> = version
            .representatives(TrustTierV1::Reported)
            .iter()
            .map(|row| row.accepted_event_id.as_bytes()[0])
            .collect();
        assert_eq!(chosen, [10, 12]);
    }
}
