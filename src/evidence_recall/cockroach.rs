//! `CockroachDB` evidence recall over the Stage-5 projection tables.
//!
//! Every statement binds `tenant_id = $1` and `project = $2` first and reads
//! private-plane base tables only; nothing here writes. The recall lanes are
//! [`CockroachRecallReader`]'s, on the private plane.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, LazyLock};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::Row as _;
use sqlx::postgres::{PgPool, PgRow};
use uuid::Uuid;

use crate::collectors::cockroach::{COUNT_PENDING_SQL, suppressed_body_predicate};
use crate::collectors::ingress::deliveries::{PendingHintsV1, count_pending_hints};
use crate::context::FleetScope;
use crate::coverage_runtime::decode_cursor_row;
use crate::error::{FleetError, Result};
use crate::memory_contracts::collected_item::{
    COLLECTED_ITEM_MEDIA_TYPE, ItemLifecycleV1, TrustTierV1,
};
use crate::memory_contracts::digest::Sha256Digest;
use crate::projectors::{CockroachRecallReader, RowVisibilityClassV1, fuse_lanes, lane_depth};
use crate::store::cockroach::{
    COLLECTED_ITEMS_SCHEMA_VERSION, DatabaseCapabilities, RETRIEVAL_DENSE_MIN_COSINE_SIMILARITY,
};
use crate::worker::WorkerSourceOutcomeV1;

use super::verdict::{ScoredHitV1, absence_verdict};
use super::{
    ContentTrustV1, EVIDENCE_RECALL_SCHEMA_VERSION, EVIDENCE_SNIPPET_CHARS, EvidenceBodyV1,
    EvidenceCollectorsV1, EvidenceCoverageV1, EvidenceDenseLaneV1, EvidenceHitV1, EvidenceItemV1,
    EvidenceReadinessV1, EvidenceRecall, EvidenceSearchV1, EvidenceSourceKindV1, EvidenceSourceV1,
    EvidenceSourcesV1, EvidenceStatusV1, MAX_EVIDENCE_SEARCH_LIMIT,
    MAX_EVIDENCE_SOURCE_ERROR_BYTES, MAX_EVIDENCE_SOURCES, lexical_query_text,
};

const INSUFFICIENT_PRIVILEGE_SQLSTATE: &str = "42501";

/// A relation the statement names does not exist.
const UNDEFINED_TABLE_SQLSTATE: &str = "42P01";

/// `plainto_tsquery` raises this for a query with no lexeme, such as one made
/// only of stopwords.
const NO_LEXEMES_SQLSTATE: &str = "42601";

/// Every table evidence recall reads. The startup probe checks SELECT on each.
pub const EVIDENCE_RECALL_TABLES: [&str; 9] = [
    "memory_worker_sources_v1",
    "memory_coverage_cursors_v1",
    "memory_evidence_shard_heads",
    "memory_evidence_events",
    "memory_body_projection_watermarks_v1",
    "memory_transcript_outbox_v1",
    "memory_body_objects_v1",
    "memory_body_lexical_projection_v1",
    "memory_body_dense_projection_v1",
];

/// The collector tables evidence recall reads from migration 34 on.
///
/// Pending parts, which items a body belongs to, their heads, their
/// containers, item withdrawals, and the collector sources. Probed
/// separately: a login without them still serves evidence recall,
/// fail-closed (see the module documentation).
pub const COLLECTOR_RECALL_TABLES: [&str; 6] = [
    "memory_collector_outbox_v1",
    "memory_collected_items_v1",
    "memory_collected_item_heads_v1",
    "memory_collector_containers_v1",
    "memory_collected_item_withdrawals_v1",
    "memory_collector_sources_v1",
];

/// Live and snapshot collectors, one row past the listing bound, shaped like
/// [`SOURCES_SQL`]. A capture's row has no coverage role and is not listed.
const COLLECTOR_SOURCES_SQL: &str = "SELECT collector_instance_id, provider, state, \
     last_outcome, last_checked_at, last_error, \
     (pg_catalog.statement_timestamp() - last_checked_at) \
        > (stale_after_seconds * INTERVAL '1 second') AS stale \
     FROM public.memory_collector_sources_v1 \
     WHERE tenant_id = $1 AND project = $2 AND state = 'active' \
       AND coverage_role IN ('live', 'snapshot') \
     ORDER BY collector_instance_id LIMIT $3";

/// Whether the scope's dense tier holds a vector from any other model.
pub const FOREIGN_DENSE_MODEL_SQL: &str = "SELECT 1 FROM public.memory_body_dense_projection_v1 \
     WHERE tenant_id = $1 AND project = $2 AND model_digest <> $3 LIMIT 1";

/// Active sources, one row past the listing bound so truncation shows.
/// `stale` is NULL when the source has never completed a check.
const SOURCES_SQL: &str = "SELECT connector_instance_id, source_kind, state, last_outcome, \
     last_checked_at, last_error, \
     (pg_catalog.statement_timestamp() - last_checked_at) \
        > (stale_after_seconds * INTERVAL '1 second') AS stale \
     FROM public.memory_worker_sources_v1 \
     WHERE tenant_id = $1 AND project = $2 AND state = 'active' \
     ORDER BY connector_instance_id LIMIT $3";

/// Each listed instance's newest coverage cursor, with every column
/// `decode_cursor_row` reads. The instance filter keeps cursors of sources
/// that are retired or not the worker's out of the listing.
const COVERAGE_SQL: &str = "SELECT DISTINCT ON (connector_instance_id) connector_instance_id, \
     observed_ranges, target_start, target_end, observation_seq, last_completeness, \
     last_receipt_id, updated_at \
     FROM public.memory_coverage_cursors_v1 \
     WHERE tenant_id = $1 AND project = $2 AND connector_instance_id = ANY($3::STRING[]) \
     ORDER BY connector_instance_id, updated_at DESC, coverage_key_digest LIMIT $4";

/// Accepted evidence events the body projector has not consumed, as a scalar
/// subquery over the scope `$1`/`$2`.
///
/// The body projector keeps one watermark per shard (across epochs) and
/// consumes `evidence.accepted` events past it. Each shard head drives a
/// lookup into the events' primary key past that watermark, so the count
/// reads only pending events, not every event in the scope. Item recall
/// (`src/item_recall`) reads the same count.
pub const EVENTS_AWAITING_BODIES_SQL: &str = "(SELECT count(*) \
        FROM public.memory_evidence_shard_heads AS head \
        LEFT JOIN public.memory_body_projection_watermarks_v1 AS watermark \
          ON watermark.tenant_id = head.tenant_id AND watermark.project = head.project \
         AND watermark.ledger_family = 'evidence' AND watermark.shard = head.shard \
        INNER LOOKUP JOIN public.memory_evidence_events AS event \
          ON event.tenant_id = head.tenant_id AND event.project = head.project \
         AND event.epoch_id = head.epoch_id AND event.shard = head.shard \
         AND event.committed_offset > COALESCE(watermark.last_committed_offset, 0) \
        WHERE head.tenant_id = $1 AND head.project = $2 \
          AND event.event_kind = 'evidence.accepted')";

/// Events the body projector has not consumed, and turns still in the outbox.
static READINESS_SQL: LazyLock<String> = LazyLock::new(|| {
    format!(
        "SELECT {EVENTS_AWAITING_BODIES_SQL} AS events_awaiting_bodies, \
         (SELECT count(*) FROM public.memory_transcript_outbox_v1 \
            WHERE tenant_id = $1 AND project = $2 AND state = 'pending') \
            AS turns_awaiting_admission, \
         pg_catalog.statement_timestamp() AS as_of"
    )
});

/// Whether a query has any lexeme. `$1` is already [`lexical_query_text`].
const LEXICAL_TERMS_SQL: &str = "SELECT plainto_tsquery('english', $1)::STRING";

/// The hits' bodies: media type, first event, and a snippet of recall text.
const HYDRATE_SQL: &str = "SELECT body.content_sha256, body.media_type, \
     body.first_accepted_event_id, \
     substring(lexical.lexical_text FROM 1 FOR $4) AS snippet, \
     octet_length(lexical.lexical_text) AS text_bytes \
     FROM public.memory_body_objects_v1 AS body \
     JOIN public.memory_body_lexical_projection_v1 AS lexical \
       ON lexical.tenant_id = body.tenant_id AND lexical.project = body.project \
      AND lexical.body_content_id = body.content_sha256 \
     WHERE body.tenant_id = $1 AND body.project = $2 \
       AND body.content_sha256 = ANY($3::BYTES[])";

/// The collected item each of a set of bodies belongs to, and whether the
/// body's version is the item's presented head. Reads
/// `memory_collected_items_body_idx`.
const HIT_ITEMS_SQL: &str = "SELECT item.body_content_id, item.item_key_digest, item.provider, \
     item.trust_tier, item.lifecycle, \
     COALESCE(head.version_key_digest = item.version_key_digest, false) AS current \
     FROM public.memory_collected_items_v1 AS item \
     LEFT JOIN public.memory_collected_item_heads_v1 AS head \
       ON head.tenant_id = item.tenant_id AND head.project = item.project \
      AND head.item_key_digest = item.item_key_digest AND head.presented \
     WHERE item.tenant_id = $1 AND item.project = $2 \
       AND item.body_content_id = ANY($3::BYTES[])";

/// The collectors of one scope at a glance: active instances, pending parts,
/// and the dead letters of the last day (`memory_collector_dead_letters_time_idx`).
const COLLECTORS_STATUS_SQL: &str = "SELECT \
     (SELECT count(*) FROM public.memory_collector_sources_v1 \
        WHERE tenant_id = $1 AND project = $2 AND state = 'active') AS sources, \
     (SELECT count(*) FROM public.memory_collector_outbox_v1 \
        WHERE tenant_id = $1 AND project = $2 AND state = 'pending') AS outbox_pending, \
     (SELECT count(*) FROM public.memory_collector_dead_letters_v1 \
        WHERE tenant_id = $1 AND project = $2 \
          AND created_at > pg_catalog.statement_timestamp() - INTERVAL '24 hours') \
        AS dead_letters_24h";

/// [`GET_SQL`] for a reader that can read the collector state: a collected
/// body whose item was deleted or withdrawn, or whose container was
/// withdrawn, is not returned.
static GET_COLLECTED_SQL: LazyLock<String> = LazyLock::new(|| {
    format!(
        "{GET_SQL} AND NOT {}",
        suppressed_body_predicate("body.content_sha256")
    )
});

/// One body's full recall text.
const GET_SQL: &str = "SELECT body.media_type, body.first_accepted_event_id, \
     lexical.lexical_text, octet_length(lexical.lexical_text) AS text_bytes, \
     lexical.visibility_class \
     FROM public.memory_body_objects_v1 AS body \
     JOIN public.memory_body_lexical_projection_v1 AS lexical \
       ON lexical.tenant_id = body.tenant_id AND lexical.project = body.project \
      AND lexical.body_content_id = body.content_sha256 \
     WHERE body.tenant_id = $1 AND body.project = $2 AND body.content_sha256 = $3";

/// What evidence recall can know about collected items in one scope.
///
/// Only [`Self::Readable`] is settled for the life of the process. The other
/// two are checked again on every read ([`CockroachEvidenceRecall`]), so a
/// `serve` started before migration 34 or before the collector grants were
/// applied reads the collector state as soon as it can, with no restart. In
/// either of them every collected body is withheld (fail closed): a body that
/// exists while this process believed there were none is one it cannot tell
/// deleted from current.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum CollectorStateV1 {
    /// The collector tables do not exist (the schema predates migration 34).
    Absent = 0,
    /// The login may read every collector table recall needs.
    Readable = 1,
    /// The schema has them and the login may not read them: collected bodies
    /// are dropped and absence cannot be shown.
    Unreadable = 2,
}

impl CollectorStateV1 {
    const fn from_stored(value: u8) -> Self {
        match value {
            1 => Self::Readable,
            2 => Self::Unreadable,
            _ => Self::Absent,
        }
    }

    /// Whether suppression can be applied, so collected bodies may be
    /// recalled at all.
    const fn readable(self) -> bool {
        matches!(self, Self::Readable)
    }
}

/// Proof that this login may read every evidence-recall table in one scope,
/// and whether the dense lane is served there.
///
/// Only [`probe_evidence_recall`] mints it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceRecallCapability {
    tenant_id: Uuid,
    project: String,
    /// The model this process embeds queries with; the dense lane compares
    /// query vectors only with vectors it embedded.
    model_digest: Sha256Digest,
    dense_served: bool,
    collectors: CollectorStateV1,
}

impl EvidenceRecallCapability {
    /// The dense lane's state for a read with no query.
    #[must_use]
    pub const fn dense_lane(&self) -> EvidenceDenseLaneV1 {
        dense_lane(self.dense_served, None)
    }

    /// Whether the schema has collector state this login cannot read, so
    /// every collected body is withheld and absence is `unknown`.
    #[must_use]
    pub const fn collector_state_unreadable(&self) -> bool {
        matches!(self.collectors, CollectorStateV1::Unreadable)
    }
}

fn privilege_probe_sql(tables: &[&str]) -> String {
    tables
        .iter()
        .map(|table| format!("SELECT 1 FROM public.{table} WHERE false"))
        .collect::<Vec<_>>()
        .join(" UNION ALL ")
}

fn sqlstate(error: &sqlx::Error) -> Option<String> {
    match error {
        sqlx::Error::Database(database) => database.code().map(std::borrow::Cow::into_owned),
        _ => None,
    }
}

/// Whether this deployment may serve evidence recall for `scope`.
///
/// It may when the schema has reached migration 30
/// ([`EVIDENCE_RECALL_SCHEMA_VERSION`]) and the login may SELECT every table in
/// [`EVIDENCE_RECALL_TABLES`]. `None` means evidence recall is not served;
/// any other failure is an error. The privilege check plans one statement over
/// every table in a transaction that is rolled back, so it reads nothing.
///
/// `model_digest` is the model this process embeds queries with. Every dense
/// query of the recall this capability builds is restricted to vectors that
/// model embedded ([`CockroachRecallReader::with_dense_model`]), so a vector
/// another model writes later, while this process runs, is never compared
/// with a query vector. The probe also reads, once, whether the scope's dense
/// tier already holds a vector of another model; if it does, the capability
/// turns the dense lane off for the process and every answer says so, since
/// such a tier is only partly searchable by this model. That read runs once
/// at startup, so a Stage-5 grant or model change needs a restart. The
/// collector state it records is only a starting point: a recall built from
/// it checks again on every read until the state is readable.
///
/// # Errors
///
/// An invalid scope, or a database failure other than a missing privilege.
pub async fn probe_evidence_recall(
    pool: &PgPool,
    capabilities: &DatabaseCapabilities,
    scope: &FleetScope,
    model_digest: Sha256Digest,
) -> Result<Option<EvidenceRecallCapability>> {
    scope.validate()?;
    if !capabilities.supports_schema_version(EVIDENCE_RECALL_SCHEMA_VERSION) {
        return Ok(None);
    }
    if !may_read(pool, &EVIDENCE_RECALL_TABLES).await? {
        return Ok(None);
    }
    let collectors = if capabilities.supports_schema_version(COLLECTED_ITEMS_SCHEMA_VERSION) {
        if may_read(pool, &COLLECTOR_RECALL_TABLES).await? {
            CollectorStateV1::Readable
        } else {
            CollectorStateV1::Unreadable
        }
    } else {
        CollectorStateV1::Absent
    };
    let foreign: Option<i64> = sqlx::query_scalar(FOREIGN_DENSE_MODEL_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(model_digest.as_bytes().as_slice())
        .fetch_optional(pool)
        .await?;
    Ok(Some(EvidenceRecallCapability {
        tenant_id: scope.tenant_id,
        project: scope.project.clone(),
        model_digest,
        dense_served: foreign.is_none(),
        collectors,
    }))
}

/// Whether this login may SELECT every table in `tables`. The check plans one
/// statement over them in a transaction that is rolled back, so it reads
/// nothing.
pub async fn may_read(pool: &PgPool, tables: &[&str]) -> Result<bool> {
    let mut transaction = pool.begin().await?;
    let probe = sqlx::query(&privilege_probe_sql(tables))
        .execute(&mut *transaction)
        .await;
    let readable = match probe {
        Ok(_) => Ok(true),
        Err(error) if sqlstate(&error).as_deref() == Some(INSUFFICIENT_PRIVILEGE_SQLSTATE) => {
            Ok(false)
        }
        Err(error) => Err(FleetError::from(error)),
    };
    // The probe read nothing; roll back regardless of its outcome.
    transaction.rollback().await?;
    readable
}

/// The collector state as it stands now, for a process that last saw it
/// absent or unreadable: one statement that plans a read of every collector
/// table recall needs, outside any transaction, so it reads nothing.
async fn current_collector_state(pool: &PgPool) -> Result<CollectorStateV1> {
    match sqlx::query(&privilege_probe_sql(&COLLECTOR_RECALL_TABLES))
        .execute(pool)
        .await
    {
        Ok(_) => Ok(CollectorStateV1::Readable),
        Err(error) => match sqlstate(&error).as_deref() {
            Some(INSUFFICIENT_PRIVILEGE_SQLSTATE) => Ok(CollectorStateV1::Unreadable),
            Some(UNDEFINED_TABLE_SQLSTATE) => Ok(CollectorStateV1::Absent),
            _ => Err(FleetError::from(error)),
        },
    }
}

/// [`EvidenceRecall`] over one scope's private plane.
#[derive(Clone)]
pub struct CockroachEvidenceRecall {
    pool: PgPool,
    tenant_id: Uuid,
    project: String,
    dense_served: bool,
    /// The last [`CollectorStateV1`] seen, shared by every clone.
    collectors: Arc<AtomicU8>,
    /// The lanes with no collected-item suppression, for a read that cannot
    /// read the collector state and drops every collected body instead.
    reader: CockroachRecallReader,
    /// The same lanes withholding deleted and withdrawn collected bodies.
    suppressed_reader: CockroachRecallReader,
}

impl std::fmt::Debug for CockroachEvidenceRecall {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CockroachEvidenceRecall")
            .field("tenant_id", &self.tenant_id)
            .field("project", &self.project)
            .field("dense_served", &self.dense_served)
            .field(
                "collectors",
                &CollectorStateV1::from_stored(self.collectors.load(Ordering::Acquire)),
            )
            .finish_non_exhaustive()
    }
}

impl CockroachEvidenceRecall {
    /// Evidence recall over the scope `capability` was probed for.
    #[must_use]
    pub fn new(capability: EvidenceRecallCapability, pool: PgPool) -> Self {
        let EvidenceRecallCapability {
            tenant_id,
            project,
            model_digest,
            dense_served,
            collectors,
        } = capability;
        let reader = CockroachRecallReader::new(pool.clone(), tenant_id, project.clone())
            .with_dense_model(model_digest);
        Self {
            suppressed_reader: reader.clone().with_collected_suppression(),
            reader,
            pool,
            tenant_id,
            project,
            dense_served,
            collectors: Arc::new(AtomicU8::new(collectors as u8)),
        }
    }

    /// The collector state for one read. Once readable it stays so; until
    /// then it is checked again, so migration 34 and the collector grants
    /// take effect in a running process, and every read before they do
    /// withholds collected bodies.
    async fn collector_state(&self) -> Result<CollectorStateV1> {
        let known = CollectorStateV1::from_stored(self.collectors.load(Ordering::Acquire));
        if known.readable() {
            return Ok(known);
        }
        let current = current_collector_state(&self.pool).await?;
        if current != known {
            self.collectors.store(current as u8, Ordering::Release);
        }
        Ok(current)
    }

    /// The lanes for a read under `state`.
    const fn reader(&self, state: CollectorStateV1) -> &CockroachRecallReader {
        if state.readable() {
            &self.suppressed_reader
        } else {
            &self.reader
        }
    }

    /// The active sources and each one's newest coverage cursor: the
    /// worker's, and, when the collector state is readable, the live and
    /// snapshot collectors', in instance order and capped together.
    async fn read_sources(&self, state: CollectorStateV1) -> Result<EvidenceSourcesV1> {
        let rows: Vec<PgRow> = sqlx::query(SOURCES_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(listing_limit(MAX_EVIDENCE_SOURCES + 1))
            .fetch_all(&self.pool)
            .await?;
        let mut listed = rows
            .iter()
            .map(decode_source_row)
            .collect::<Result<Vec<_>>>()?;
        if state.readable() {
            let rows: Vec<PgRow> = sqlx::query(COLLECTOR_SOURCES_SQL)
                .bind(self.tenant_id)
                .bind(&self.project)
                .bind(listing_limit(MAX_EVIDENCE_SOURCES + 1))
                .fetch_all(&self.pool)
                .await?;
            for row in &rows {
                listed.push(decode_collector_source_row(row)?);
            }
            // Instance ids are unique across both tables (the sources file
            // refuses a collision), so the order is total.
            listed.sort_by(|left, right| left.connector_instance.cmp(&right.connector_instance));
        }
        let truncated = listed.len() > MAX_EVIDENCE_SOURCES;
        listed.truncate(MAX_EVIDENCE_SOURCES);
        let mut active = listed;
        if active.is_empty() {
            return Ok(EvidenceSourcesV1 { active, truncated });
        }

        attach_coverage(&self.pool, self.tenant_id, &self.project, &mut active).await?;
        Ok(EvidenceSourcesV1 { active, truncated })
    }

    /// Ingestion and projection lag. Read after the sources and before the
    /// lanes, and upstream first: hints, the collector outbox, the evidence
    /// awaiting projection, then the lexical tier (see the module
    /// documentation).
    async fn read_readiness(
        &self,
        dense_lane: EvidenceDenseLaneV1,
        state: CollectorStateV1,
    ) -> Result<EvidenceReadinessV1> {
        let hints = match state {
            CollectorStateV1::Readable => {
                count_pending_hints(&self.pool, self.tenant_id, &self.project, None).await?
            }
            CollectorStateV1::Absent | CollectorStateV1::Unreadable => PendingHintsV1::Absent,
        };
        let items_awaiting_admission = match state {
            CollectorStateV1::Readable => {
                let pending: i64 = sqlx::query_scalar(COUNT_PENDING_SQL)
                    .bind(self.tenant_id)
                    .bind(&self.project)
                    .fetch_one(&self.pool)
                    .await?;
                Some(u64::try_from(pending).map_err(|_| {
                    FleetError::Memory("the collector outbox count is negative".to_owned())
                })?)
            }
            CollectorStateV1::Absent | CollectorStateV1::Unreadable => None,
        };
        let row: PgRow = sqlx::query(READINESS_SQL.as_str())
            .bind(self.tenant_id)
            .bind(&self.project)
            .fetch_one(&self.pool)
            .await?;
        let completeness = self.reader(state).completeness().await?;
        Ok(EvidenceReadinessV1 {
            events_awaiting_body_projection: count(&row, "events_awaiting_bodies")?,
            transcript_turns_awaiting_admission: count(&row, "turns_awaiting_admission")?,
            items_awaiting_admission,
            hints_awaiting_fetch: hints.count(),
            hints_unreadable: hints.unreadable(),
            collector_state_unreadable: state == CollectorStateV1::Unreadable,
            lexical_current: completeness.lexical_complete(),
            dense_current: completeness.dense_complete(),
            dense_lane,
            as_of: row.try_get::<DateTime<Utc>, _>("as_of")?,
        })
    }

    /// Attach each scored hit's body, keeping the fused order.
    async fn hydrate(
        &self,
        scored: Vec<ScoredHitV1>,
        state: CollectorStateV1,
    ) -> Result<Vec<EvidenceHitV1>> {
        if scored.is_empty() {
            return Ok(Vec::new());
        }
        let ids: Vec<Vec<u8>> = scored
            .iter()
            .map(|hit| hit.id.as_bytes().to_vec())
            .collect();
        let rows: Vec<PgRow> = sqlx::query(HYDRATE_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(&ids)
            .bind(listing_limit(EVIDENCE_SNIPPET_CHARS))
            .fetch_all(&self.pool)
            .await?;
        let mut bodies = HashMap::with_capacity(rows.len());
        for row in &rows {
            let id = digest(row, "content_sha256")?;
            let snippet: String = row.try_get("snippet")?;
            let text_bytes = count(row, "text_bytes")?;
            bodies.insert(
                id,
                (
                    row.try_get::<String, _>("media_type")?,
                    digest(row, "first_accepted_event_id")?,
                    snippet_truncated(&snippet, text_bytes),
                    snippet,
                ),
            );
        }
        let hits = scored
            .into_iter()
            .map(|hit| {
                let (media_type, first_accepted_event_id, snippet_truncated, snippet) =
                    bodies.remove(&hit.id).ok_or_else(|| {
                        FleetError::Memory(format!(
                            "recalled body {} has no body row and lexical row in this scope",
                            hit.id
                        ))
                    })?;
                Ok(EvidenceHitV1 {
                    id: hit.id,
                    score: hit.score,
                    matched_by: hit.matched_by,
                    lexical_score: hit.lexical_score,
                    dense_similarity: hit.dense_similarity,
                    content_trust: ContentTrustV1::of_media_type(&media_type),
                    media_type,
                    snippet,
                    snippet_truncated,
                    first_accepted_event_id,
                    item: None,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        // Fail closed: without the collector state a deleted item's text is
        // indistinguishable from a current one's, so no collected body is
        // recalled.
        if !state.readable() {
            return Ok(hits
                .into_iter()
                .filter(|hit| hit.media_type != COLLECTED_ITEM_MEDIA_TYPE)
                .collect());
        }
        self.annotate_items(hits).await
    }

    /// Attach to each collected hit the item it belongs to.
    async fn annotate_items(&self, mut hits: Vec<EvidenceHitV1>) -> Result<Vec<EvidenceHitV1>> {
        let collected: Vec<Vec<u8>> = hits
            .iter()
            .filter(|hit| hit.media_type == COLLECTED_ITEM_MEDIA_TYPE)
            .map(|hit| hit.id.as_bytes().to_vec())
            .collect();
        if collected.is_empty() {
            return Ok(hits);
        }
        let rows: Vec<PgRow> = sqlx::query(HIT_ITEMS_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(&collected)
            .fetch_all(&self.pool)
            .await?;
        let mut items = HashMap::with_capacity(rows.len());
        for row in &rows {
            let trust: String = row.try_get("trust_tier")?;
            let lifecycle: String = row.try_get("lifecycle")?;
            items.insert(
                digest(row, "body_content_id")?,
                EvidenceItemV1 {
                    item_id: digest(row, "item_key_digest")?,
                    provider: row.try_get("provider")?,
                    trust: TrustTierV1::parse(&trust)?,
                    current: row.try_get("current")?,
                    lifecycle: ItemLifecycleV1::parse(&lifecycle)?,
                },
            );
        }
        for hit in &mut hits {
            hit.item = items.remove(&hit.id);
        }
        Ok(hits)
    }

    /// The collectors block of a status read; `None` when this login may not
    /// read every table it counts.
    async fn read_collectors(&self) -> Result<Option<EvidenceCollectorsV1>> {
        let row = match sqlx::query(COLLECTORS_STATUS_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .fetch_one(&self.pool)
            .await
        {
            Ok(row) => row,
            Err(error) if sqlstate(&error).as_deref() == Some(INSUFFICIENT_PRIVILEGE_SQLSTATE) => {
                return Ok(None);
            }
            Err(error) => return Err(error.into()),
        };
        Ok(Some(EvidenceCollectorsV1 {
            sources: count(&row, "sources")?,
            outbox_pending: count(&row, "outbox_pending")?,
            dead_letters_24h: count(&row, "dead_letters_24h")?,
        }))
    }
}

/// Whether `lexical_text` (already [`lexical_query_text`]) has a lexeme.
pub async fn has_lexical_terms(pool: &PgPool, lexical_text: &str) -> Result<bool> {
    if lexical_text.is_empty() {
        return Ok(false);
    }
    match sqlx::query_scalar::<_, String>(LEXICAL_TERMS_SQL)
        .bind(lexical_text)
        .fetch_one(pool)
        .await
    {
        Ok(terms) => Ok(!terms.is_empty()),
        Err(error) if sqlstate(&error).as_deref() == Some(NO_LEXEMES_SQLSTATE) => Ok(false),
        Err(error) => Err(error.into()),
    }
}

/// Attach each listed source's newest coverage cursor, read in one statement.
pub async fn attach_coverage(
    pool: &PgPool,
    tenant_id: Uuid,
    project: &str,
    active: &mut [EvidenceSourceV1],
) -> Result<()> {
    if active.is_empty() {
        return Ok(());
    }
    let instances: Vec<String> = active
        .iter()
        .map(|source| source.connector_instance.clone())
        .collect();
    let rows: Vec<PgRow> = sqlx::query(COVERAGE_SQL)
        .bind(tenant_id)
        .bind(project)
        .bind(&instances)
        .bind(listing_limit(MAX_EVIDENCE_SOURCES))
        .fetch_all(pool)
        .await?;
    let mut coverage = HashMap::with_capacity(rows.len());
    for row in &rows {
        let instance: String = row.try_get("connector_instance_id")?;
        let cursor = decode_cursor_row(row)?;
        coverage.insert(
            instance,
            EvidenceCoverageV1 {
                completeness: cursor.last_completeness,
                observed: cursor
                    .observed
                    .intervals()
                    .iter()
                    .map(|interval| [interval.start, interval.end])
                    .collect(),
                target: [cursor.target.start, cursor.target.end],
                as_of: cursor.updated_at,
            },
        );
    }
    for source in active {
        source.coverage = coverage.remove(&source.connector_instance);
    }
    Ok(())
}

/// The dense lane's state for one read. `query_vector` is `None` for a read
/// that runs no query, otherwise whether the search carried a vector.
pub const fn dense_lane(served: bool, query_vector: Option<bool>) -> EvidenceDenseLaneV1 {
    match (served, query_vector) {
        (false, _) => EvidenceDenseLaneV1::DisabledForeignModel,
        (true, None) => EvidenceDenseLaneV1::Available,
        (true, Some(true)) => EvidenceDenseLaneV1::Used,
        (true, Some(false)) => EvidenceDenseLaneV1::NoQueryVector,
    }
}

#[async_trait]
impl EvidenceRecall for CockroachEvidenceRecall {
    async fn search(
        &self,
        query: &str,
        query_vector: Option<Vec<f32>>,
        limit: usize,
    ) -> Result<EvidenceSearchV1> {
        if limit == 0 || limit > MAX_EVIDENCE_SEARCH_LIMIT {
            return Err(FleetError::Memory(format!(
                "evidence search limit must be between 1 and {MAX_EVIDENCE_SEARCH_LIMIT}"
            )));
        }
        let lexical_text = lexical_query_text(query);
        let lane = dense_lane(self.dense_served, Some(query_vector.is_some()));
        let state = self.collector_state().await?;
        // Sources, then readiness, then the lanes: the order that makes an
        // absent verdict sound (module documentation).
        let sources = self.read_sources(state).await?;
        let readiness = self.read_readiness(lane, state).await?;
        let lexical_terms = has_lexical_terms(&self.pool, &lexical_text).await?;
        let vector = query_vector.filter(|_| lane == EvidenceDenseLaneV1::Used);
        // Each lane is read deeper than the answer, then the two are fused by
        // reciprocal rank (the lexical cutoff and the dense floor applied
        // inside the fusion) and cut to `limit`.
        let lanes = self
            .reader(state)
            .recall_lanes(
                if lexical_terms { &lexical_text } else { "" },
                vector.as_deref(),
                lane_depth(limit),
            )
            .await?;
        let fused = fuse_lanes(
            &lanes.lexical,
            &lanes.dense,
            RETRIEVAL_DENSE_MIN_COSINE_SIMILARITY,
            limit,
        );
        let hits = self
            .hydrate(fused.into_iter().map(ScoredHitV1::from).collect(), state)
            .await?;
        let votes: Vec<_> = hits.iter().map(EvidenceHitV1::vote).collect();
        let absence = absence_verdict(&votes, lexical_terms, &readiness, &sources);
        Ok(EvidenceSearchV1 {
            hits,
            readiness,
            sources,
            absence,
        })
    }

    async fn get(&self, id: Sha256Digest) -> Result<Option<EvidenceBodyV1>> {
        let state = self.collector_state().await?;
        let statement = if state.readable() {
            GET_COLLECTED_SQL.as_str()
        } else {
            GET_SQL
        };
        let row: Option<PgRow> = sqlx::query(statement)
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(id.as_bytes().as_slice())
            .fetch_optional(&self.pool)
            .await?;
        let row = row.filter(|row| {
            state.readable()
                || row
                    .try_get::<String, _>("media_type")
                    .is_ok_and(|media_type| media_type != COLLECTED_ITEM_MEDIA_TYPE)
        });
        row.map(|row| {
            let media_type: String = row.try_get("media_type")?;
            // The lexical row was redacted when it was projected; the pass
            // runs again at read so a row projected before the current
            // redaction carries no secret out, and says what it removed.
            let stored: String = row.try_get("lexical_text")?;
            let (text, redacted_at_read) = crate::projectors::redact_for_recall_marked(&stored);
            let text_bytes = if redacted_at_read.is_some() {
                u64::try_from(text.len()).unwrap_or(u64::MAX)
            } else {
                count(&row, "text_bytes")?
            };
            Ok(EvidenceBodyV1 {
                id,
                content_trust: ContentTrustV1::of_media_type(&media_type),
                media_type,
                text,
                text_bytes,
                redacted_at_read,
                visibility_class: RowVisibilityClassV1::parse(
                    &row.try_get::<String, _>("visibility_class")?,
                )?,
                first_accepted_event_id: digest(&row, "first_accepted_event_id")?,
            })
        })
        .transpose()
    }

    async fn status(&self) -> Result<EvidenceStatusV1> {
        let state = self.collector_state().await?;
        let sources = self.read_sources(state).await?;
        let readiness = self
            .read_readiness(dense_lane(self.dense_served, None), state)
            .await?;
        let collectors = if state.readable() {
            self.read_collectors().await?
        } else {
            None
        };
        Ok(EvidenceStatusV1 {
            readiness,
            sources,
            collectors,
        })
    }
}

fn decode_source_row(row: &PgRow) -> Result<EvidenceSourceV1> {
    let kind: String = row.try_get("source_kind")?;
    decode_status(
        row,
        row.try_get("connector_instance_id")?,
        EvidenceSourceKindV1::from_stored(&kind),
        None,
    )
}

pub fn decode_collector_source_row(row: &PgRow) -> Result<EvidenceSourceV1> {
    decode_status(
        row,
        row.try_get("collector_instance_id")?,
        EvidenceSourceKindV1::Collector,
        Some(row.try_get("provider")?),
    )
}

/// The status columns worker and collector source rows share.
fn decode_status(
    row: &PgRow,
    connector_instance: String,
    kind: EvidenceSourceKindV1,
    provider: Option<String>,
) -> Result<EvidenceSourceV1> {
    let outcome: String = row.try_get("last_outcome")?;
    let last_error: Option<String> = row.try_get("last_error")?;
    Ok(EvidenceSourceV1 {
        connector_instance,
        kind,
        provider,
        state: row.try_get("state")?,
        last_outcome: match outcome.as_str() {
            "ok" => WorkerSourceOutcomeV1::Ok,
            "unchanged" => WorkerSourceOutcomeV1::Unchanged,
            "failed" => WorkerSourceOutcomeV1::Failed,
            other => {
                return Err(FleetError::Memory(format!(
                    "stored worker source outcome {other:?} is not a known outcome"
                )));
            }
        },
        last_checked_at: row.try_get("last_checked_at")?,
        last_error: last_error.map(|error| cut(&error, MAX_EVIDENCE_SOURCE_ERROR_BYTES)),
        stale: row.try_get::<Option<bool>, _>("stale")?.unwrap_or(false),
        coverage: None,
    })
}

/// A snippet is cut when it holds fewer bytes than the whole text.
fn snippet_truncated(snippet: &str, text_bytes: u64) -> bool {
    u64::try_from(snippet.len()).unwrap_or(u64::MAX) < text_bytes
}

/// `text` cut to at most `limit` bytes on a character boundary.
fn cut(text: &str, limit: usize) -> String {
    if text.len() <= limit {
        return text.to_owned();
    }
    let mut end = limit;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

pub fn listing_limit(limit: usize) -> i64 {
    i64::try_from(limit).unwrap_or(i64::MAX)
}

pub fn count(row: &PgRow, column: &str) -> Result<u64> {
    let value: i64 = row.try_get(column)?;
    u64::try_from(value)
        .map_err(|_| FleetError::Memory(format!("{column} returned a negative count")))
}

pub fn digest(row: &PgRow, column: &str) -> Result<Sha256Digest> {
    let bytes: Vec<u8> = row.try_get(column)?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| FleetError::Memory(format!("stored {column} is not 32 bytes")))?;
    Ok(Sha256Digest::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_long_error_is_cut_on_a_character_boundary() {
        let error = format!("{}é tail", "x".repeat(255));
        let cut = cut(&error, 256);
        assert!(cut.len() <= 256);
        assert_eq!(cut, "x".repeat(255));
        assert_eq!(super::cut("short", 256), "short");
    }

    #[test]
    fn a_snippet_is_truncated_only_when_the_text_is_longer() {
        assert!(!snippet_truncated("abc", 3));
        assert!(snippet_truncated("abc", 4));
        assert!(!snippet_truncated("", 0));
    }
}
