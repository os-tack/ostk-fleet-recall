//! `CockroachDB` implementation of the body projection (W2-BODY).
//!
//! This projector consumes the accepted evidence-event stream
//! (`memory_evidence_events`, `event_kind = 'evidence.accepted'`, read-only) and
//! materializes migration 0019's private-plane tables:
//! `memory_body_objects_v1`, `memory_chunk_occurrences_v1`,
//! `memory_chunk_occurrence_spans_v1`, `memory_parse_run_manifests_v1`,
//! `memory_source_commit_membership_v1`, `memory_generation_pointers_v1`, and
//! the cursor `memory_body_projection_watermarks_v1`. It also writes migration
//! 0023's `memory_body_visibility_v1`, one read-plane decision per body, in the
//! same transaction as the body row (W2-VIS).
//!
//! # Invariants enforced here
//!
//! * **REPLAY-02 / cursor atomicity.** Each accepted event's derived rows AND
//!   the cursor advance to that event's offset are written in ONE serializable
//!   transaction. A crash (or rollback) between the row writes and the cursor
//!   advance leaves BOTH unwritten, because they are the same transaction; the
//!   cursor never advances past a row it did not durably write.
//! * **REPLAY-01.** Rows are content-addressed and their canonical preimage
//!   bytes are stored verbatim, so re-deriving from the same accepted-event log
//!   reproduces byte-identical rows.
//! * **Fail closed on collision.** A body content address presented over
//!   different bytes, or an occurrence/manifest id presented over a different
//!   canonical preimage, aborts the whole event transaction with a typed error
//!   and writes no row ([`ChunkIntegrityCollisionV1`]).
//! * **Shadow generations.** A parser-key upgrade advances the per-source
//!   generation pointer by exactly one through a compare-and-swap and writes new
//!   (content-addressed) rows; it never updates or deletes the prior
//!   generation's occurrence/manifest rows.
//! * **Scope binding.** The repository binds `(tenant_id, project)` once at
//!   construction; every read and write is filtered by that exact pair, so no
//!   accepted-event payload can redirect a write to another tenant or project.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::postgres::{PgPool, PgRow};
use sqlx::{Postgres, Row as _, Transaction};
use uuid::Uuid;

use crate::FleetError;
use crate::memory_contracts::canonical::decode_strict;
use crate::memory_contracts::chunk_identity::{
    ChunkIntegrityCollisionV1, GenerationPointerV1, ParseManifestId, ParserKeyId, ParserKeyV1,
    classify_body_reuse,
};
use crate::memory_contracts::digest::Sha256Digest;
use crate::memory_contracts::evidence_v2::EvidenceStatementV2;
use crate::projectors::RowVisibilityClassV1;
use crate::store::cockroach::{RetryPolicy, is_retryable, is_retryable_fleet_error};

use super::error::{BodyProjectionError, BodyProjectionResult};
use super::projector::{
    DerivedParseRunV1, check_shadow_generation_switch, derive_parse_run, generation_pointer,
};
use super::repository::{
    BodyProjectionRepository, BodyProjectionSnapshotV1, BodyProjectionWatermarkV1,
    GenerationPointerRowV1, ProjectionRunSummaryV1, SourceContentResolver, WATERMARK_LEDGER_FAMILY,
};

const EVIDENCE_ACCEPTED_EVENT_KIND: &str = "evidence.accepted";

const SELECT_SHARDS_SQL: &str = "SELECT DISTINCT shard FROM public.memory_evidence_events \
     WHERE tenant_id = $1 AND project = $2 AND event_kind = $3 ORDER BY shard";

const SELECT_PENDING_EVENTS_SQL: &str = "SELECT committed_offset, canonical_event FROM public.memory_evidence_events \
     WHERE tenant_id = $1 AND project = $2 AND event_kind = $3 AND shard = $4 \
       AND committed_offset > $5 ORDER BY committed_offset";

const SELECT_ALL_EVENTS_SQL: &str = "SELECT committed_offset, canonical_event FROM public.memory_evidence_events \
     WHERE tenant_id = $1 AND project = $2 AND event_kind = $3 AND shard = $4 \
     ORDER BY committed_offset";

const SELECT_WATERMARK_SQL: &str = "SELECT last_committed_offset FROM \
     public.memory_body_projection_watermarks_v1 \
     WHERE tenant_id = $1 AND project = $2 AND ledger_family = $3 AND shard = $4";

const INSERT_BODY_SQL: &str = "INSERT INTO public.memory_body_objects_v1 (\
     tenant_id, project, content_sha256, byte_length, body_bytes, media_type, \
     protection_domain_id, first_accepted_event_id, created_at\
     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
     ON CONFLICT (tenant_id, project, content_sha256) DO NOTHING";

const SELECT_BODY_BYTES_SQL: &str = "SELECT body_bytes FROM public.memory_body_objects_v1 \
     WHERE tenant_id = $1 AND project = $2 AND content_sha256 = $3";

// W2-VIS. One visibility decision per content-addressed body, written in the
// SAME transaction as the body row it describes.
//
// Bodies are content-addressed and therefore SHARED: two events with different
// governance envelopes can produce byte-identical bodies. The conflict arm
// resolves that the only safe way — any disagreement collapses the stored class
// to 'private'. Publication safety therefore requires UNANIMITY across every
// event that ever produced the body, and a later private event demotes a body
// the publication plane could previously see. The reverse can never happen: the
// arm has no path that writes 'publication_safe' over an existing row.
const INSERT_BODY_VISIBILITY_SQL: &str = "INSERT INTO public.memory_body_visibility_v1 (\
     tenant_id, project, body_content_id, visibility_class, protection_domain_id, \
     source_visibility_class, source_publication_class, first_accepted_event_id, updated_at\
     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
     ON CONFLICT (tenant_id, project, body_content_id) DO UPDATE SET \
     visibility_class = 'private', \
     updated_at = excluded.updated_at \
     WHERE public.memory_body_visibility_v1.visibility_class \
         IS DISTINCT FROM excluded.visibility_class";

const SELECT_BODY_VISIBILITY_SQL: &str = "SELECT visibility_class \
     FROM public.memory_body_visibility_v1 \
     WHERE tenant_id = $1 AND project = $2 AND body_content_id = $3";

const INSERT_OCCURRENCE_SQL: &str = "INSERT INTO public.memory_chunk_occurrences_v1 (\
     tenant_id, project, occurrence_id, source_object_version_uri, parser_key_id, \
     body_content_id, occurrence_ordinal, redaction_policy_version, \
     publication_classifier_version, generation_sequence, canonical_preimage, \
     accepted_event_id, created_at\
     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) \
     ON CONFLICT (tenant_id, project, occurrence_id) DO NOTHING";

const SELECT_OCCURRENCE_PREIMAGE_SQL: &str = "SELECT canonical_preimage FROM public.memory_chunk_occurrences_v1 \
     WHERE tenant_id = $1 AND project = $2 AND occurrence_id = $3";

const INSERT_SPAN_SQL: &str = "INSERT INTO public.memory_chunk_occurrence_spans_v1 (\
     tenant_id, project, occurrence_id, span_ordinal, byte_start, byte_end, span_digest\
     ) VALUES ($1, $2, $3, $4, $5, $6, $7) \
     ON CONFLICT (tenant_id, project, occurrence_id, span_ordinal) DO NOTHING";

const INSERT_MANIFEST_SQL: &str = "INSERT INTO public.memory_parse_run_manifests_v1 (\
     tenant_id, project, manifest_id, source_representation_uri, parser_key_id, \
     coverage_receipt_digest, generation_sequence, canonical_preimage, accepted_event_id, \
     created_at\
     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
     ON CONFLICT (tenant_id, project, manifest_id) DO NOTHING";

const SELECT_MANIFEST_PREIMAGE_SQL: &str = "SELECT canonical_preimage FROM public.memory_parse_run_manifests_v1 \
     WHERE tenant_id = $1 AND project = $2 AND manifest_id = $3";

const INSERT_MEMBERSHIP_SQL: &str = "INSERT INTO public.memory_source_commit_membership_v1 (\
     tenant_id, project, source_object_version_uri, commit_revision, ref_key, \
     accepted_event_id, observed_at\
     ) VALUES ($1, $2, $3, $4, $5, $6, $7) \
     ON CONFLICT (tenant_id, project, source_object_version_uri, commit_revision) DO NOTHING";

const SELECT_POINTER_FOR_UPDATE_SQL: &str = "SELECT active_parser_key_id, active_manifest_id, generation_sequence \
     FROM public.memory_generation_pointers_v1 \
     WHERE tenant_id = $1 AND project = $2 AND source_representation_uri = $3 FOR UPDATE";

const INSERT_POINTER_SQL: &str = "INSERT INTO public.memory_generation_pointers_v1 (\
     tenant_id, project, source_representation_uri, pointer_id, active_parser_key_id, \
     active_manifest_id, generation_sequence, updated_at\
     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
     ON CONFLICT (tenant_id, project, source_representation_uri) DO NOTHING";

const CAS_POINTER_SQL: &str = "UPDATE public.memory_generation_pointers_v1 SET \
     pointer_id = $4, active_parser_key_id = $5, active_manifest_id = $6, \
     generation_sequence = $7, updated_at = $8 \
     WHERE tenant_id = $1 AND project = $2 AND source_representation_uri = $3 \
       AND generation_sequence = $9";

const UPSERT_WATERMARK_SQL: &str = "INSERT INTO public.memory_body_projection_watermarks_v1 (\
     tenant_id, project, ledger_family, shard, last_committed_offset, updated_at\
     ) VALUES ($1, $2, $3, $4, $5, $6) \
     ON CONFLICT (tenant_id, project, ledger_family, shard) DO UPDATE SET \
     last_committed_offset = excluded.last_committed_offset, updated_at = excluded.updated_at \
     WHERE public.memory_body_projection_watermarks_v1.last_committed_offset \
       < excluded.last_committed_offset";

/// Outcome of applying one accepted evidence event.
#[derive(Debug, Clone, Copy, Default)]
struct EventOutcome {
    occurrences_derived: u64,
    shadow_opened: bool,
}

/// Private body-projection repository bound once to physical scope and one
/// active parser key.
#[derive(Clone)]
pub struct CockroachBodyProjectionRepository {
    pool: PgPool,
    tenant_id: Uuid,
    project: String,
    parser_key: ParserKeyV1,
    resolver: Arc<dyn SourceContentResolver>,
    retry_policy: RetryPolicy,
}

impl std::fmt::Debug for CockroachBodyProjectionRepository {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CockroachBodyProjectionRepository")
            .field("tenant_id", &self.tenant_id)
            .field("project", &self.project)
            .finish_non_exhaustive()
    }
}

impl CockroachBodyProjectionRepository {
    /// Bind one pool, one physical scope, one active parser key, and the source
    /// content resolver.
    #[must_use]
    pub fn new(
        pool: PgPool,
        tenant_id: Uuid,
        project: String,
        parser_key: ParserKeyV1,
        resolver: Arc<dyn SourceContentResolver>,
        retry_policy: RetryPolicy,
    ) -> Self {
        Self {
            pool,
            tenant_id,
            project,
            parser_key,
            resolver,
            retry_policy,
        }
    }

    async fn shards_with_evidence(&self) -> BodyProjectionResult<Vec<i32>> {
        let rows: Vec<PgRow> = sqlx::query(SELECT_SHARDS_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(EVIDENCE_ACCEPTED_EVENT_KIND)
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(|row| Ok(row.try_get("shard")?)).collect()
    }

    async fn read_watermark_offset(&self, shard: i32) -> BodyProjectionResult<i64> {
        let row: Option<PgRow> = sqlx::query(SELECT_WATERMARK_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(WATERMARK_LEDGER_FAMILY)
            .bind(shard)
            .fetch_optional(&self.pool)
            .await?;
        match row {
            Some(row) => Ok(row.try_get("last_committed_offset")?),
            None => Ok(0),
        }
    }

    async fn events_for_shard(
        &self,
        shard: i32,
        after_offset: Option<i64>,
    ) -> BodyProjectionResult<Vec<(i64, Vec<u8>)>> {
        let rows: Vec<PgRow> = match after_offset {
            Some(offset) => {
                sqlx::query(SELECT_PENDING_EVENTS_SQL)
                    .bind(self.tenant_id)
                    .bind(&self.project)
                    .bind(EVIDENCE_ACCEPTED_EVENT_KIND)
                    .bind(shard)
                    .bind(offset)
                    .fetch_all(&self.pool)
                    .await?
            }
            None => {
                sqlx::query(SELECT_ALL_EVENTS_SQL)
                    .bind(self.tenant_id)
                    .bind(&self.project)
                    .bind(EVIDENCE_ACCEPTED_EVENT_KIND)
                    .bind(shard)
                    .fetch_all(&self.pool)
                    .await?
            }
        };
        rows.iter()
            .map(|row| {
                Ok((
                    row.try_get::<i64, _>("committed_offset")?,
                    row.try_get::<Vec<u8>, _>("canonical_event")?,
                ))
            })
            .collect()
    }

    async fn run_pass(&self, incremental: bool) -> BodyProjectionResult<ProjectionRunSummaryV1> {
        let mut summary = ProjectionRunSummaryV1::default();
        for shard in self.shards_with_evidence().await? {
            let after = if incremental {
                Some(self.read_watermark_offset(shard).await?)
            } else {
                None
            };
            for (offset, canonical) in self.events_for_shard(shard, after).await? {
                let outcome = self.project_one_event(shard, offset, canonical).await?;
                summary.events_projected += 1;
                summary.occurrences_derived += outcome.occurrences_derived;
                if outcome.shadow_opened {
                    summary.shadow_generations_opened += 1;
                }
            }
        }
        Ok(summary)
    }

    /// One accepted event, one bounded serializable transaction, retried only on
    /// a `CockroachDB` serialization failure. `apply_event` is idempotent, so a
    /// retry re-runs it against a fresh transaction safely.
    async fn project_one_event(
        &self,
        shard: i32,
        offset: i64,
        canonical: Vec<u8>,
    ) -> BodyProjectionResult<EventOutcome> {
        let mut attempt = 0_u32;
        loop {
            attempt += 1;
            let mut transaction = self.pool.begin().await.map_err(FleetError::from)?;
            sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
                .execute(&mut *transaction)
                .await?;
            match self
                .apply_event(&mut transaction, shard, offset, &canonical)
                .await
            {
                Ok(outcome) => match transaction.commit().await {
                    Ok(()) => return Ok(outcome),
                    Err(error)
                        if is_retryable(&error) && attempt < self.retry_policy.max_attempts =>
                    {
                        tokio::time::sleep(self.retry_policy.delay_for_retry(attempt - 1)).await;
                    }
                    Err(error) => return Err(BodyProjectionError::from(error)),
                },
                Err(BodyProjectionError::Storage(error))
                    if is_retryable_fleet_error(&error)
                        && attempt < self.retry_policy.max_attempts =>
                {
                    drop(transaction);
                    tokio::time::sleep(self.retry_policy.delay_for_retry(attempt - 1)).await;
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// Derive and write one accepted evidence event's whole body-plane
    /// projection, plus the cursor advance, inside `transaction`.
    async fn apply_event(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        shard: i32,
        offset: i64,
        canonical: &[u8],
    ) -> BodyProjectionResult<EventOutcome> {
        let statement: EvidenceStatementV2 = decode_strict(canonical)?;
        let source_bytes = self.resolver.resolve(&statement).await?;
        let derived = derive_parse_run(&statement, &source_bytes, &self.parser_key)?;
        let accepted_event_id = statement.accepted_event_id()?;
        let accepted_event_bytes = bytes(accepted_event_id.digest());
        let source_uri = derived.source_object_version_uri.to_string();

        let now: DateTime<Utc> = sqlx::query_scalar("SELECT pg_catalog.statement_timestamp()")
            .fetch_one(&mut **transaction)
            .await?;

        let generation = self
            .resolve_generation(transaction, &derived, &source_uri, now)
            .await?;

        self.write_bodies(transaction, &derived, &accepted_event_bytes, now)
            .await?;
        let occurrences_derived = self
            .write_occurrences(
                transaction,
                &derived,
                generation.sequence,
                &accepted_event_bytes,
                now,
            )
            .await?;
        self.write_manifest(
            transaction,
            &derived,
            generation.sequence,
            &accepted_event_bytes,
            now,
        )
        .await?;
        self.write_commit_membership(
            transaction,
            &derived,
            &source_uri,
            &accepted_event_bytes,
            now,
        )
        .await?;

        self.advance_watermark(transaction, shard, offset, now)
            .await?;

        Ok(EventOutcome {
            occurrences_derived,
            shadow_opened: generation.shadow_opened,
        })
    }

    /// Read the current generation pointer FOR UPDATE and decide this event's
    /// generation, opening a shadow generation via compare-and-swap on a
    /// parser-key upgrade. The pointer row is written here so its transition is
    /// part of the same transaction as the rows it governs.
    async fn resolve_generation(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        derived: &DerivedParseRunV1,
        source_uri: &str,
        now: DateTime<Utc>,
    ) -> BodyProjectionResult<GenerationDecision> {
        let derived_parser_key = derived.parser_key_id;
        let derived_manifest = derived.manifest.manifest_id;

        let existing: Option<PgRow> = sqlx::query(SELECT_POINTER_FOR_UPDATE_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(source_uri)
            .fetch_optional(&mut **transaction)
            .await?;

        let Some(row) = existing else {
            // First generation for this source.
            let pointer = generation_pointer(derived_parser_key, derived_manifest, 1)?;
            self.insert_pointer(transaction, source_uri, &pointer, now)
                .await?;
            return Ok(GenerationDecision {
                sequence: 1,
                shadow_opened: false,
            });
        };

        let current_parser_key =
            ParserKeyId::from_digest(digest32(row.try_get("active_parser_key_id")?)?);
        let current_manifest =
            ParseManifestId::from_digest(digest32(row.try_get("active_manifest_id")?)?);
        let current_sequence = u64::try_from(row.try_get::<i64, _>("generation_sequence")?)
            .map_err(|_| {
                BodyProjectionError::LedgerIntegrity("negative generation sequence".into())
            })?;

        if current_parser_key == derived_parser_key {
            // Same parser generation: a deterministic re-projection must produce
            // the same manifest for the same source. A different manifest under
            // the same parser key and source is an integrity collision.
            if current_manifest != derived_manifest {
                return Err(BodyProjectionError::IntegrityCollision(
                    ChunkIntegrityCollisionV1::ManifestOccurrenceSetCollision,
                ));
            }
            return Ok(GenerationDecision {
                sequence: current_sequence,
                shadow_opened: false,
            });
        }

        // Parser-key upgrade: open a shadow generation via compare-and-swap. The
        // prior generation's occurrence/manifest rows are never touched.
        let next_sequence = current_sequence.checked_add(1).ok_or_else(|| {
            BodyProjectionError::LedgerIntegrity("generation sequence overflow".into())
        })?;
        let current_pointer = GenerationPointerV1 {
            schema_version: 1,
            active_parser_key: current_parser_key,
            active_manifest_id: current_manifest,
            generation_sequence: current_sequence,
        };
        let proposed_pointer =
            generation_pointer(derived_parser_key, derived_manifest, next_sequence)?;
        check_shadow_generation_switch(
            &current_pointer,
            &proposed_pointer,
            derived.manifest.coverage_receipt_digest,
        )?;

        let pointer_id = bytes(proposed_pointer.pointer_id()?.digest());
        let current_sequence_i64 = i64::try_from(current_sequence).map_err(|_| {
            BodyProjectionError::LedgerIntegrity("generation sequence exceeds INT8".into())
        })?;
        let next_sequence_i64 = i64::try_from(next_sequence).map_err(|_| {
            BodyProjectionError::LedgerIntegrity("generation sequence exceeds INT8".into())
        })?;
        let affected = sqlx::query(CAS_POINTER_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(source_uri)
            .bind(pointer_id)
            .bind(bytes(derived_parser_key.digest()))
            .bind(bytes(derived_manifest.digest()))
            .bind(next_sequence_i64)
            .bind(now)
            .bind(current_sequence_i64)
            .execute(&mut **transaction)
            .await?
            .rows_affected();
        if affected == 0 {
            return Err(BodyProjectionError::StaleGenerationPointer);
        }
        Ok(GenerationDecision {
            sequence: next_sequence,
            shadow_opened: true,
        })
    }

    async fn insert_pointer(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        source_uri: &str,
        pointer: &GenerationPointerV1,
        now: DateTime<Utc>,
    ) -> BodyProjectionResult<()> {
        let sequence = i64::try_from(pointer.generation_sequence).map_err(|_| {
            BodyProjectionError::LedgerIntegrity("generation sequence exceeds INT8".into())
        })?;
        sqlx::query(INSERT_POINTER_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(source_uri)
            .bind(bytes(pointer.pointer_id()?.digest()))
            .bind(bytes(pointer.active_parser_key.digest()))
            .bind(bytes(pointer.active_manifest_id.digest()))
            .bind(sequence)
            .bind(now)
            .execute(&mut **transaction)
            .await?;
        Ok(())
    }

    async fn write_bodies(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        derived: &DerivedParseRunV1,
        accepted_event_bytes: &[u8],
        now: DateTime<Utc>,
    ) -> BodyProjectionResult<()> {
        for body in &derived.bodies {
            let byte_length = i64::try_from(body.byte_length()).map_err(|_| {
                BodyProjectionError::LedgerIntegrity("body length exceeds INT8".into())
            })?;
            sqlx::query(INSERT_BODY_SQL)
                .bind(self.tenant_id)
                .bind(&self.project)
                .bind(bytes(body.content_sha256))
                .bind(byte_length)
                .bind(&body.body_bytes)
                .bind(derived.media_type.as_str())
                .bind(derived.protection_domain_id.as_str())
                .bind(accepted_event_bytes)
                .bind(now)
                .execute(&mut **transaction)
                .await?;

            // Verify the durably stored bytes against this content address. This
            // is the fail-closed BodyDigestBytesCollision check: the frozen
            // classifier proves the stored bytes reproduce the digest AND that a
            // candidate under the same digest is byte-identical.
            let stored: Vec<u8> = sqlx::query_scalar(SELECT_BODY_BYTES_SQL)
                .bind(self.tenant_id)
                .bind(&self.project)
                .bind(bytes(body.content_sha256))
                .fetch_one(&mut **transaction)
                .await?;
            match classify_body_reuse(body.content_sha256, &stored, &body.body_bytes) {
                Ok(ChunkIntegrityCollisionV1::None) => {}
                Ok(collision) => return Err(BodyProjectionError::IntegrityCollision(collision)),
                Err(_) => {
                    return Err(BodyProjectionError::LedgerIntegrity(
                        "stored body bytes are inconsistent with their content address".into(),
                    ));
                }
            }

            self.write_body_visibility(
                transaction,
                derived,
                body.content_sha256,
                accepted_event_bytes,
                now,
            )
            .await?;
        }
        Ok(())
    }

    /// Record this event's read-plane decision for one body (W2-VIS), then read
    /// the durable row back and refuse anything stronger than the decision just
    /// derived.
    ///
    /// The read-back is the fail-closed half: the database's own
    /// `memory_body_visibility_publication_requires_approval` constraint already
    /// refuses a publication-safe row over unapproved evidence, and this check
    /// refuses the remaining case — a stored row that is publication-safe while
    /// the event being applied classified the body private.
    async fn write_body_visibility(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        derived: &DerivedParseRunV1,
        content_sha256: Sha256Digest,
        accepted_event_bytes: &[u8],
        now: DateTime<Utc>,
    ) -> BodyProjectionResult<()> {
        let visibility = &derived.visibility;
        sqlx::query(INSERT_BODY_VISIBILITY_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(bytes(content_sha256))
            .bind(visibility.class.as_str())
            .bind(visibility.protection_domain_id.as_str())
            .bind(visibility.source_visibility_label())
            .bind(visibility.source_publication_label())
            .bind(accepted_event_bytes)
            .bind(now)
            .execute(&mut **transaction)
            .await?;

        let stored: String = sqlx::query_scalar(SELECT_BODY_VISIBILITY_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(bytes(content_sha256))
            .fetch_one(&mut **transaction)
            .await?;
        let stored = RowVisibilityClassV1::parse(&stored).map_err(|error| {
            BodyProjectionError::LedgerIntegrity(format!("stored body visibility: {error}"))
        })?;
        if stored.is_publication_safe() && !visibility.class.is_publication_safe() {
            return Err(BodyProjectionError::LedgerIntegrity(
                "stored body visibility is publication-safe but this event classifies the body private"
                    .into(),
            ));
        }
        Ok(())
    }

    async fn write_occurrences(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        derived: &DerivedParseRunV1,
        generation_sequence: u64,
        accepted_event_bytes: &[u8],
        now: DateTime<Utc>,
    ) -> BodyProjectionResult<u64> {
        let generation = i64::try_from(generation_sequence).map_err(|_| {
            BodyProjectionError::LedgerIntegrity("generation sequence exceeds INT8".into())
        })?;
        let source_uri = derived.source_object_version_uri.to_string();
        for occurrence in &derived.occurrences {
            let ordinal = i64::from(occurrence.ordinal);
            sqlx::query(INSERT_OCCURRENCE_SQL)
                .bind(self.tenant_id)
                .bind(&self.project)
                .bind(bytes(occurrence.occurrence_id.digest()))
                .bind(&source_uri)
                .bind(bytes(derived.parser_key_id.digest()))
                .bind(bytes(occurrence.body_content_id))
                .bind(ordinal)
                .bind(i64::from(occurrence.preimage.redaction_policy_version))
                .bind(i64::from(
                    occurrence.preimage.publication_classifier_version,
                ))
                .bind(generation)
                .bind(&occurrence.canonical_preimage)
                .bind(accepted_event_bytes)
                .bind(now)
                .execute(&mut **transaction)
                .await?;

            let stored: Vec<u8> = sqlx::query_scalar(SELECT_OCCURRENCE_PREIMAGE_SQL)
                .bind(self.tenant_id)
                .bind(&self.project)
                .bind(bytes(occurrence.occurrence_id.digest()))
                .fetch_one(&mut **transaction)
                .await?;
            if stored != occurrence.canonical_preimage {
                return Err(BodyProjectionError::PreimageCollision { kind: "occurrence" });
            }

            for span in &occurrence.spans {
                let byte_start = i64::try_from(span.byte_start).map_err(|_| {
                    BodyProjectionError::LedgerIntegrity("span start exceeds INT8".into())
                })?;
                let byte_end = i64::try_from(span.byte_end).map_err(|_| {
                    BodyProjectionError::LedgerIntegrity("span end exceeds INT8".into())
                })?;
                sqlx::query(INSERT_SPAN_SQL)
                    .bind(self.tenant_id)
                    .bind(&self.project)
                    .bind(bytes(occurrence.occurrence_id.digest()))
                    .bind(i64::from(span.ordinal))
                    .bind(byte_start)
                    .bind(byte_end)
                    .bind(bytes(span.span_digest))
                    .execute(&mut **transaction)
                    .await?;
            }
        }
        Ok(derived.occurrences.len() as u64)
    }

    async fn write_manifest(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        derived: &DerivedParseRunV1,
        generation_sequence: u64,
        accepted_event_bytes: &[u8],
        now: DateTime<Utc>,
    ) -> BodyProjectionResult<()> {
        let generation = i64::try_from(generation_sequence).map_err(|_| {
            BodyProjectionError::LedgerIntegrity("generation sequence exceeds INT8".into())
        })?;
        sqlx::query(INSERT_MANIFEST_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(bytes(derived.manifest.manifest_id.digest()))
            .bind(derived.source_object_version_uri.to_string())
            .bind(bytes(derived.parser_key_id.digest()))
            .bind(bytes(derived.manifest.coverage_receipt_digest))
            .bind(generation)
            .bind(&derived.manifest.canonical_preimage)
            .bind(accepted_event_bytes)
            .bind(now)
            .execute(&mut **transaction)
            .await?;

        let stored: Vec<u8> = sqlx::query_scalar(SELECT_MANIFEST_PREIMAGE_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(bytes(derived.manifest.manifest_id.digest()))
            .fetch_one(&mut **transaction)
            .await?;
        if stored != derived.manifest.canonical_preimage {
            return Err(BodyProjectionError::PreimageCollision { kind: "manifest" });
        }
        Ok(())
    }

    async fn write_commit_membership(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        derived: &DerivedParseRunV1,
        source_uri: &str,
        accepted_event_bytes: &[u8],
        now: DateTime<Utc>,
    ) -> BodyProjectionResult<()> {
        sqlx::query(INSERT_MEMBERSHIP_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(source_uri)
            .bind(&derived.commit_membership.commit_revision)
            .bind(&derived.commit_membership.ref_key)
            .bind(accepted_event_bytes)
            .bind(now)
            .execute(&mut **transaction)
            .await?;
        Ok(())
    }

    async fn advance_watermark(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        shard: i32,
        offset: i64,
        now: DateTime<Utc>,
    ) -> BodyProjectionResult<()> {
        sqlx::query(UPSERT_WATERMARK_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(WATERMARK_LEDGER_FAMILY)
            .bind(shard)
            .bind(offset)
            .bind(now)
            .execute(&mut **transaction)
            .await?;
        Ok(())
    }

    /// Test/inspection helper: apply the first pending accepted event within one
    /// serializable transaction and then ROLL BACK without committing.
    ///
    /// This proves the cursor-atomicity invariant directly: `apply_event` writes
    /// the derived rows AND advances the cursor in one transaction, so a rollback
    /// (the model of a crash between output and cursor commit) leaves BOTH
    /// unwritten. Returns whether a pending event was found to apply.
    pub async fn probe_apply_first_pending_then_rollback(&self) -> BodyProjectionResult<bool> {
        for shard in self.shards_with_evidence().await? {
            let after = self.read_watermark_offset(shard).await?;
            if let Some((offset, canonical)) = self
                .events_for_shard(shard, Some(after))
                .await?
                .into_iter()
                .next()
            {
                let mut transaction = self.pool.begin().await.map_err(FleetError::from)?;
                sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
                    .execute(&mut *transaction)
                    .await?;
                self.apply_event(&mut transaction, shard, offset, &canonical)
                    .await?;
                // Deliberately drop without commit: rolls the whole transaction
                // back (rows AND cursor advance together).
                drop(transaction);
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Read one shard's persisted cursor.
    pub async fn read_watermark(
        &self,
        shard: u16,
    ) -> BodyProjectionResult<Option<BodyProjectionWatermarkV1>> {
        let row: Option<PgRow> = sqlx::query(SELECT_WATERMARK_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(WATERMARK_LEDGER_FAMILY)
            .bind(i32::from(shard))
            .fetch_optional(&self.pool)
            .await?;
        row.map(|row| {
            let offset: i64 = row.try_get("last_committed_offset")?;
            Ok(BodyProjectionWatermarkV1 {
                shard,
                last_committed_offset: u64::try_from(offset).map_err(|_| {
                    BodyProjectionError::LedgerIntegrity(
                        "stored watermark offset is negative".into(),
                    )
                })?,
            })
        })
        .transpose()
    }

    /// Read one source's current generation pointer.
    pub async fn read_generation_pointer(
        &self,
        source_representation_uri: &str,
    ) -> BodyProjectionResult<Option<GenerationPointerRowV1>> {
        let row: Option<PgRow> = sqlx::query(SELECT_POINTER_FOR_UPDATE_SQL)
            .bind(self.tenant_id)
            .bind(&self.project)
            .bind(source_representation_uri)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|row| {
            let sequence =
                u64::try_from(row.try_get::<i64, _>("generation_sequence")?).map_err(|_| {
                    BodyProjectionError::LedgerIntegrity("negative generation sequence".into())
                })?;
            Ok(GenerationPointerRowV1 {
                source_representation_uri: source_representation_uri.to_string(),
                generation_sequence: sequence,
            })
        })
        .transpose()
    }

    /// Read the full, deterministically ordered body-plane snapshot for this
    /// scope. Two snapshots compare equal iff the projector rebuilt
    /// byte-identical rows (REPLAY-01).
    // One straight-line SELECT-and-map block per table (six tables); the length
    // is the table count, not branching complexity.
    #[allow(clippy::too_many_lines)]
    pub async fn snapshot(&self) -> BodyProjectionResult<BodyProjectionSnapshotV1> {
        let mut snapshot = BodyProjectionSnapshotV1::default();

        let body_rows: Vec<PgRow> = sqlx::query(
            "SELECT content_sha256, body_bytes FROM public.memory_body_objects_v1 \
             WHERE tenant_id = $1 AND project = $2 ORDER BY content_sha256",
        )
        .bind(self.tenant_id)
        .bind(&self.project)
        .fetch_all(&self.pool)
        .await?;
        for row in &body_rows {
            snapshot
                .bodies
                .push((row.try_get("content_sha256")?, row.try_get("body_bytes")?));
        }

        let occurrence_rows: Vec<PgRow> = sqlx::query(
            "SELECT occurrence_id, canonical_preimage, generation_sequence \
             FROM public.memory_chunk_occurrences_v1 \
             WHERE tenant_id = $1 AND project = $2 ORDER BY occurrence_id",
        )
        .bind(self.tenant_id)
        .bind(&self.project)
        .fetch_all(&self.pool)
        .await?;
        for row in &occurrence_rows {
            snapshot.occurrences.push((
                row.try_get("occurrence_id")?,
                row.try_get("canonical_preimage")?,
                row.try_get("generation_sequence")?,
            ));
        }

        let span_rows: Vec<PgRow> = sqlx::query(
            "SELECT occurrence_id, span_ordinal, byte_start, byte_end, span_digest \
             FROM public.memory_chunk_occurrence_spans_v1 \
             WHERE tenant_id = $1 AND project = $2 ORDER BY occurrence_id, span_ordinal",
        )
        .bind(self.tenant_id)
        .bind(&self.project)
        .fetch_all(&self.pool)
        .await?;
        for row in &span_rows {
            snapshot.spans.push((
                row.try_get("occurrence_id")?,
                row.try_get("span_ordinal")?,
                row.try_get("byte_start")?,
                row.try_get("byte_end")?,
                row.try_get("span_digest")?,
            ));
        }

        let manifest_rows: Vec<PgRow> = sqlx::query(
            "SELECT manifest_id, canonical_preimage, generation_sequence \
             FROM public.memory_parse_run_manifests_v1 \
             WHERE tenant_id = $1 AND project = $2 ORDER BY manifest_id",
        )
        .bind(self.tenant_id)
        .bind(&self.project)
        .fetch_all(&self.pool)
        .await?;
        for row in &manifest_rows {
            snapshot.manifests.push((
                row.try_get("manifest_id")?,
                row.try_get("canonical_preimage")?,
                row.try_get("generation_sequence")?,
            ));
        }

        let membership_rows: Vec<PgRow> = sqlx::query(
            "SELECT source_object_version_uri, commit_revision, ref_key \
             FROM public.memory_source_commit_membership_v1 \
             WHERE tenant_id = $1 AND project = $2 \
             ORDER BY source_object_version_uri, commit_revision",
        )
        .bind(self.tenant_id)
        .bind(&self.project)
        .fetch_all(&self.pool)
        .await?;
        for row in &membership_rows {
            snapshot.commit_membership.push((
                row.try_get("source_object_version_uri")?,
                row.try_get("commit_revision")?,
                row.try_get("ref_key")?,
            ));
        }

        let pointer_rows: Vec<PgRow> = sqlx::query(
            "SELECT source_representation_uri, active_parser_key_id, active_manifest_id, \
                    generation_sequence FROM public.memory_generation_pointers_v1 \
             WHERE tenant_id = $1 AND project = $2 ORDER BY source_representation_uri",
        )
        .bind(self.tenant_id)
        .bind(&self.project)
        .fetch_all(&self.pool)
        .await?;
        for row in &pointer_rows {
            snapshot.generation_pointers.push((
                row.try_get("source_representation_uri")?,
                row.try_get("active_parser_key_id")?,
                row.try_get("active_manifest_id")?,
                row.try_get("generation_sequence")?,
            ));
        }

        Ok(snapshot)
    }
}

/// The generation this event writes at, and whether it opened a shadow one.
#[derive(Debug, Clone, Copy)]
struct GenerationDecision {
    sequence: u64,
    shadow_opened: bool,
}

#[async_trait]
impl BodyProjectionRepository for CockroachBodyProjectionRepository {
    async fn project_pending(&self) -> BodyProjectionResult<ProjectionRunSummaryV1> {
        self.run_pass(true).await
    }

    async fn reproject_all(&self) -> BodyProjectionResult<ProjectionRunSummaryV1> {
        self.run_pass(false).await
    }
}

fn bytes(digest: Sha256Digest) -> Vec<u8> {
    digest.as_bytes().to_vec()
}

fn digest32(value: Vec<u8>) -> BodyProjectionResult<Sha256Digest> {
    let bytes: [u8; 32] = value.try_into().map_err(|_| {
        BodyProjectionError::LedgerIntegrity("stored digest column is not 32 bytes".into())
    })?;
    Ok(Sha256Digest::from_bytes(bytes))
}
