//! `CockroachDB` evidence recall over the Stage-5 projection tables.
//!
//! Every statement binds `tenant_id = $1` and `project = $2` first and reads
//! private-plane base tables only; nothing here writes. The recall lanes are
//! [`CockroachRecallReader`]'s, on the private plane.

use std::collections::HashMap;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::Row as _;
use sqlx::postgres::{PgPool, PgRow};
use uuid::Uuid;

use crate::context::FleetScope;
use crate::coverage_runtime::decode_cursor_row;
use crate::error::{FleetError, Result};
use crate::memory_contracts::digest::Sha256Digest;
use crate::projectors::{CockroachRecallReader, RowVisibilityClassV1};
use crate::store::cockroach::{DatabaseCapabilities, RETRIEVAL_DENSE_MIN_COSINE_SIMILARITY};
use crate::worker::WorkerSourceOutcomeV1;

use super::verdict::{ScoredHitV1, absence_verdict, apply_dense_floor};
use super::{
    EVIDENCE_RECALL_SCHEMA_VERSION, EVIDENCE_SNIPPET_CHARS, EvidenceBodyV1, EvidenceCoverageV1,
    EvidenceDenseLaneV1, EvidenceHitV1, EvidenceReadinessV1, EvidenceRecall, EvidenceSearchV1,
    EvidenceSourceKindV1, EvidenceSourceV1, EvidenceSourcesV1, EvidenceStatusV1,
    MAX_EVIDENCE_SEARCH_LIMIT, MAX_EVIDENCE_SOURCE_ERROR_BYTES, MAX_EVIDENCE_SOURCES,
    lexical_query_text,
};

const INSUFFICIENT_PRIVILEGE_SQLSTATE: &str = "42501";

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

/// Whether the scope's dense tier holds a vector from any other model.
const FOREIGN_DENSE_MODEL_SQL: &str = "SELECT 1 FROM public.memory_body_dense_projection_v1 \
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

/// Events the body projector has not consumed, and turns still in the outbox.
///
/// The body projector keeps one watermark per shard (across epochs) and
/// consumes `evidence.accepted` events past it. Each shard head drives a
/// lookup into the events' primary key past that watermark, so the count
/// reads only pending events, not every event in the scope.
const READINESS_SQL: &str = "SELECT \
     (SELECT count(*) FROM public.memory_evidence_shard_heads AS head \
        LEFT JOIN public.memory_body_projection_watermarks_v1 AS watermark \
          ON watermark.tenant_id = head.tenant_id AND watermark.project = head.project \
         AND watermark.ledger_family = 'evidence' AND watermark.shard = head.shard \
        INNER LOOKUP JOIN public.memory_evidence_events AS event \
          ON event.tenant_id = head.tenant_id AND event.project = head.project \
         AND event.epoch_id = head.epoch_id AND event.shard = head.shard \
         AND event.committed_offset > COALESCE(watermark.last_committed_offset, 0) \
        WHERE head.tenant_id = $1 AND head.project = $2 \
          AND event.event_kind = 'evidence.accepted') AS events_awaiting_bodies, \
     (SELECT count(*) FROM public.memory_transcript_outbox_v1 \
        WHERE tenant_id = $1 AND project = $2 AND state = 'pending') AS turns_awaiting_admission, \
     pg_catalog.statement_timestamp() AS as_of";

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

/// One body's full recall text.
const GET_SQL: &str = "SELECT body.media_type, body.first_accepted_event_id, \
     lexical.lexical_text, octet_length(lexical.lexical_text) AS text_bytes, \
     lexical.visibility_class \
     FROM public.memory_body_objects_v1 AS body \
     JOIN public.memory_body_lexical_projection_v1 AS lexical \
       ON lexical.tenant_id = body.tenant_id AND lexical.project = body.project \
      AND lexical.body_content_id = body.content_sha256 \
     WHERE body.tenant_id = $1 AND body.project = $2 AND body.content_sha256 = $3";

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
}

impl EvidenceRecallCapability {
    /// The dense lane's state for a read with no query.
    #[must_use]
    pub const fn dense_lane(&self) -> EvidenceDenseLaneV1 {
        dense_lane(self.dense_served, None)
    }
}

fn privilege_probe_sql() -> String {
    EVIDENCE_RECALL_TABLES
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
/// at startup, so a grant or model change needs a restart.
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
    let mut transaction = pool.begin().await?;
    let probe = sqlx::query(&privilege_probe_sql())
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
    if !readable? {
        return Ok(None);
    }
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
    }))
}

/// [`EvidenceRecall`] over one scope's private plane.
#[derive(Clone)]
pub struct CockroachEvidenceRecall {
    pool: PgPool,
    tenant_id: Uuid,
    project: String,
    dense_served: bool,
    reader: CockroachRecallReader,
}

impl std::fmt::Debug for CockroachEvidenceRecall {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CockroachEvidenceRecall")
            .field("tenant_id", &self.tenant_id)
            .field("project", &self.project)
            .field("dense_served", &self.dense_served)
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
        } = capability;
        Self {
            reader: CockroachRecallReader::new(pool.clone(), tenant_id, project.clone())
                .with_dense_model(model_digest),
            pool,
            tenant_id,
            project,
            dense_served,
        }
    }

    /// The active sources and each one's newest coverage cursor.
    async fn read_sources(&self) -> Result<EvidenceSourcesV1> {
        let rows: Vec<PgRow> = sqlx::query(SOURCES_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(listing_limit(MAX_EVIDENCE_SOURCES + 1))
            .fetch_all(&self.pool)
            .await?;
        let truncated = rows.len() > MAX_EVIDENCE_SOURCES;
        let mut active = rows
            .iter()
            .take(MAX_EVIDENCE_SOURCES)
            .map(decode_source_row)
            .collect::<Result<Vec<_>>>()?;
        if active.is_empty() {
            return Ok(EvidenceSourcesV1 { active, truncated });
        }

        let instances: Vec<String> = active
            .iter()
            .map(|source| source.connector_instance.clone())
            .collect();
        let rows: Vec<PgRow> = sqlx::query(COVERAGE_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(&instances)
            .bind(listing_limit(MAX_EVIDENCE_SOURCES))
            .fetch_all(&self.pool)
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
        for source in &mut active {
            source.coverage = coverage.remove(&source.connector_instance);
        }
        Ok(EvidenceSourcesV1 { active, truncated })
    }

    /// Ingestion and projection lag. Read after the sources and before the
    /// lanes; see the module documentation.
    async fn read_readiness(&self, dense_lane: EvidenceDenseLaneV1) -> Result<EvidenceReadinessV1> {
        let row: PgRow = sqlx::query(READINESS_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .fetch_one(&self.pool)
            .await?;
        let completeness = self.reader.completeness().await?;
        Ok(EvidenceReadinessV1 {
            events_awaiting_body_projection: count(&row, "events_awaiting_bodies")?,
            transcript_turns_awaiting_admission: count(&row, "turns_awaiting_admission")?,
            lexical_current: completeness.lexical_complete(),
            dense_current: completeness.dense_complete(),
            dense_lane,
            as_of: row.try_get::<DateTime<Utc>, _>("as_of")?,
        })
    }

    /// Whether `lexical_text` has a lexeme.
    async fn has_lexical_terms(&self, lexical_text: &str) -> Result<bool> {
        if lexical_text.is_empty() {
            return Ok(false);
        }
        match sqlx::query_scalar::<_, String>(LEXICAL_TERMS_SQL)
            .bind(lexical_text)
            .fetch_one(&self.pool)
            .await
        {
            Ok(terms) => Ok(!terms.is_empty()),
            Err(error) if sqlstate(&error).as_deref() == Some(NO_LEXEMES_SQLSTATE) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    /// Attach each scored hit's body, keeping the lanes' order.
    async fn hydrate(&self, scored: Vec<ScoredHitV1>) -> Result<Vec<EvidenceHitV1>> {
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
        scored
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
                    matched_by: hit.matched_by,
                    lexical_score: hit.lexical_score,
                    dense_similarity: hit.dense_similarity,
                    media_type,
                    snippet,
                    snippet_truncated,
                    first_accepted_event_id,
                })
            })
            .collect()
    }
}

/// The dense lane's state for one read. `query_vector` is `None` for a read
/// that runs no query, otherwise whether the search carried a vector.
const fn dense_lane(served: bool, query_vector: Option<bool>) -> EvidenceDenseLaneV1 {
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
        // Sources, then readiness, then the lanes: the order that makes an
        // absent verdict sound (module documentation).
        let sources = self.read_sources().await?;
        let readiness = self.read_readiness(lane).await?;
        let lexical_terms = self.has_lexical_terms(&lexical_text).await?;
        let vector = query_vector.filter(|_| lane == EvidenceDenseLaneV1::Used);
        let (hits, _tier) = self
            .reader
            .recall_hits(
                if lexical_terms { &lexical_text } else { "" },
                vector.as_deref(),
                limit,
            )
            .await?;
        let hits = self
            .hydrate(apply_dense_floor(
                &hits,
                RETRIEVAL_DENSE_MIN_COSINE_SIMILARITY,
            ))
            .await?;
        let absence = absence_verdict(hits.len(), lexical_terms, &readiness, &sources);
        Ok(EvidenceSearchV1 {
            hits,
            readiness,
            sources,
            absence,
        })
    }

    async fn get(&self, id: Sha256Digest) -> Result<Option<EvidenceBodyV1>> {
        let row: Option<PgRow> = sqlx::query(GET_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(id.as_bytes().as_slice())
            .fetch_optional(&self.pool)
            .await?;
        row.map(|row| {
            Ok(EvidenceBodyV1 {
                id,
                media_type: row.try_get("media_type")?,
                text: row.try_get("lexical_text")?,
                text_bytes: count(&row, "text_bytes")?,
                visibility_class: RowVisibilityClassV1::parse(
                    &row.try_get::<String, _>("visibility_class")?,
                )?,
                first_accepted_event_id: digest(&row, "first_accepted_event_id")?,
            })
        })
        .transpose()
    }

    async fn status(&self) -> Result<EvidenceStatusV1> {
        let sources = self.read_sources().await?;
        let readiness = self
            .read_readiness(dense_lane(self.dense_served, None))
            .await?;
        Ok(EvidenceStatusV1 { readiness, sources })
    }
}

fn decode_source_row(row: &PgRow) -> Result<EvidenceSourceV1> {
    let kind: String = row.try_get("source_kind")?;
    let outcome: String = row.try_get("last_outcome")?;
    let last_error: Option<String> = row.try_get("last_error")?;
    Ok(EvidenceSourceV1 {
        connector_instance: row.try_get("connector_instance_id")?,
        kind: EvidenceSourceKindV1::from_stored(&kind),
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

fn listing_limit(limit: usize) -> i64 {
    i64::try_from(limit).unwrap_or(i64::MAX)
}

fn count(row: &PgRow, column: &str) -> Result<u64> {
    let value: i64 = row.try_get(column)?;
    u64::try_from(value)
        .map_err(|_| FleetError::Memory(format!("{column} returned a negative count")))
}

fn digest(row: &PgRow, column: &str) -> Result<Sha256Digest> {
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
