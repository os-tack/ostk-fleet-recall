//! `CockroachDB` implementation of the discrepancy ledger runtime (W3-DISC).
//!
//! Every statement here touches only migration 0027's four tables —
//! `memory_discrepancy_heads_v1`, `memory_discrepancy_log_v1`,
//! `memory_discrepancy_relations_v1`, and
//! `memory_discrepancy_projections_v1` — all keyed by the trusted
//! `(tenant_id, project)` pair bound at construction. None is a publication
//! reader table (PUBLIC-03/04): all four are private-plane rows.
//!
//! # Append discipline
//!
//! Every write path runs its whole lock → check → append → project sequence
//! inside ONE serializable transaction via [`with_serializable_retry`], the
//! same discipline [`crate::normative_runtime`] uses. The log append (or
//! relation insert) and the projection refresh commit together or not at
//! all, so the stored projection can never sit ahead of or behind the log it
//! was folded from.
//!
//! # Nothing is ever rewritten
//!
//! There is no `UPDATE` or `DELETE` against `memory_discrepancy_log_v1` or
//! `memory_discrepancy_relations_v1` anywhere in this file: an acknowledge,
//! waiver, resolution, dismissal, or supersession APPENDS, and the envelope
//! that opened an episode stays exactly as admitted — which is what makes
//! [`CockroachDiscrepancyLedgerRepository::rebuild_projection`] a real
//! replay rather than a re-read.
//!
//! # Idempotent replay
//!
//! A byte-identical envelope, lifecycle event, or relation delivered twice
//! returns [`DiscrepancyAppendOutcomeV1::AlreadyRecorded`] with nothing
//! written (backed by the per-scope unique record-id index), so an
//! at-least-once delivery cannot double-apply.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::postgres::{PgPool, PgRow};
use sqlx::{Postgres, Row as _, Transaction};

use crate::Result;
use crate::control_log::TrustedControlScope;
use crate::error::FleetError;
use crate::memory_contracts::canonical::decode_strict;
use crate::memory_contracts::common::CanonicalTimestamp;
use crate::memory_contracts::digest::Sha256Digest;
use crate::memory_contracts::discrepancy::{
    DiscrepancyEnvelopeV1, DiscrepancyEpisodeFingerprintV1, DiscrepancyEpisodeRelationV1,
    DiscrepancyFamilyFingerprintV1, DiscrepancyLifecycleEventV1,
};
use crate::store::cockroach::{RetryPolicy, with_serializable_retry};

use super::projection::{MAX_EPISODE_LOG_ENTRIES, MAX_FAMILY_RELATIONS, project_ledger_episode};
use super::repository::{
    AdmittedDiscrepancyEnvelopeV1, AdmittedDiscrepancyLifecycleEventV1,
    AdmittedDiscrepancyRelationV1, DiscrepancyAppendOutcomeV1, DiscrepancyEnvelopeCandidateV1,
    DiscrepancyLedgerRepository, DiscrepancyLedgerTransitionV1, DiscrepancyLogEntryV1,
    DiscrepancyLogRecordV1, DiscrepancyRegistryBindingV1, StoredDiscrepancyProjectionV1,
    admit_envelope, admit_lifecycle_event, admit_relation, lifecycle_state_from_str,
    lifecycle_state_str, verification_state_from_str, verification_state_str,
};

const LOCK_HEAD_SQL: &str = "SELECT family_fingerprint, envelope_id, log_seq \
     FROM public.memory_discrepancy_heads_v1 \
     WHERE tenant_id = $1 AND project = $2 AND episode_fingerprint = $3 FOR UPDATE";

const INSERT_HEAD_SQL: &str = "INSERT INTO public.memory_discrepancy_heads_v1 (\
     tenant_id, project, episode_fingerprint, family_fingerprint, envelope_id, log_seq, updated_at\
     ) VALUES ($1, $2, $3, $4, $5, $6, $7)";

const ADVANCE_HEAD_SQL: &str = "UPDATE public.memory_discrepancy_heads_v1 SET \
     log_seq = $4, updated_at = $5 \
     WHERE tenant_id = $1 AND project = $2 AND episode_fingerprint = $3 AND log_seq = $6 \
     RETURNING log_seq";

const APPEND_LOG_SQL: &str = "INSERT INTO public.memory_discrepancy_log_v1 (\
     tenant_id, project, episode_fingerprint, seq, record_kind, record_id, \
     canonical_record, created_at\
     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)";

const SELECT_LOG_SQL: &str = "SELECT seq, record_id, canonical_record \
     FROM public.memory_discrepancy_log_v1 \
     WHERE tenant_id = $1 AND project = $2 AND episode_fingerprint = $3 ORDER BY seq";

const RECORD_EXISTS_SQL: &str = "SELECT 1 FROM public.memory_discrepancy_log_v1 \
     WHERE tenant_id = $1 AND project = $2 AND record_id = $3";

const INSERT_RELATION_SQL: &str = "INSERT INTO public.memory_discrepancy_relations_v1 (\
     tenant_id, project, family_fingerprint, relation_id, canonical_relation, created_at\
     ) VALUES ($1, $2, $3, $4, $5, $6)";

const SELECT_RELATIONS_SQL: &str = "SELECT canonical_relation \
     FROM public.memory_discrepancy_relations_v1 \
     WHERE tenant_id = $1 AND project = $2 AND family_fingerprint = $3 ORDER BY relation_id";

const RELATION_EXISTS_SQL: &str = "SELECT 1 FROM public.memory_discrepancy_relations_v1 \
     WHERE tenant_id = $1 AND project = $2 AND family_fingerprint = $3 AND relation_id = $4";

const UPSERT_PROJECTION_SQL: &str = "INSERT INTO public.memory_discrepancy_projections_v1 (\
     tenant_id, project, episode_fingerprint, cursor_seq, lifecycle_state, \
     verification_state, evaluated_at, canonical_projection, updated_at\
     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
     ON CONFLICT (tenant_id, project, episode_fingerprint) DO UPDATE SET \
     cursor_seq = excluded.cursor_seq, lifecycle_state = excluded.lifecycle_state, \
     verification_state = excluded.verification_state, evaluated_at = excluded.evaluated_at, \
     canonical_projection = excluded.canonical_projection, updated_at = excluded.updated_at \
     WHERE public.memory_discrepancy_projections_v1.cursor_seq <= excluded.cursor_seq \
     RETURNING cursor_seq";

const SELECT_PROJECTION_SQL: &str = "SELECT cursor_seq, lifecycle_state, verification_state, \
     evaluated_at, canonical_projection \
     FROM public.memory_discrepancy_projections_v1 \
     WHERE tenant_id = $1 AND project = $2 AND episode_fingerprint = $3";

/// Discrepancy ledger runtime bound once to physical scope, semantic scope,
/// and the active registry head.
#[derive(Clone)]
pub struct CockroachDiscrepancyLedgerRepository {
    pool: PgPool,
    trusted_scope: TrustedControlScope,
    registry_binding: DiscrepancyRegistryBindingV1,
    retry_policy: RetryPolicy,
}

impl std::fmt::Debug for CockroachDiscrepancyLedgerRepository {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CockroachDiscrepancyLedgerRepository")
            .field("trusted_scope", &self.trusted_scope)
            .field("registry_binding", &self.registry_binding)
            .finish_non_exhaustive()
    }
}

impl CockroachDiscrepancyLedgerRepository {
    /// Bind one pool, one physical/semantic scope, the active registry head,
    /// and one retry policy. The registry binding is rejected closed if it
    /// names a zero package or policy digest.
    pub fn new(
        pool: PgPool,
        trusted_scope: TrustedControlScope,
        registry_binding: DiscrepancyRegistryBindingV1,
        retry_policy: RetryPolicy,
    ) -> Result<Self> {
        registry_binding.validate()?;
        Ok(Self {
            pool,
            trusted_scope,
            registry_binding,
            retry_policy,
        })
    }

    /// The active registry head this runtime judges every envelope against.
    #[must_use]
    pub const fn registry_binding(&self) -> DiscrepancyRegistryBindingV1 {
        self.registry_binding
    }
}

#[async_trait]
impl DiscrepancyLedgerRepository for CockroachDiscrepancyLedgerRepository {
    async fn admit_envelope(
        &self,
        candidate: &DiscrepancyEnvelopeCandidateV1,
    ) -> Result<DiscrepancyAppendOutcomeV1> {
        // Every fail-closed check runs here, BEFORE a transaction opens: a
        // rejected envelope never reaches the database at all.
        let admitted = admit_envelope(
            candidate,
            &self.registry_binding,
            self.trusted_scope.semantic_scope(),
        )?;
        let envelope = candidate.envelope.clone();
        let scope = self.trusted_scope.clone();
        with_serializable_retry(&self.pool, self.retry_policy, move |transaction| {
            let scope = scope.clone();
            let envelope = envelope.clone();
            let admitted = admitted.clone();
            Box::pin(async move {
                admit_envelope_in_transaction(transaction, &scope, &envelope, &admitted).await
            })
        })
        .await
    }

    async fn append_lifecycle_event(
        &self,
        event: &DiscrepancyLifecycleEventV1,
    ) -> Result<DiscrepancyAppendOutcomeV1> {
        let scope = self.trusted_scope.clone();
        let event = event.clone();
        with_serializable_retry(&self.pool, self.retry_policy, move |transaction| {
            let scope = scope.clone();
            let event = event.clone();
            Box::pin(
                async move { append_lifecycle_in_transaction(transaction, &scope, &event).await },
            )
        })
        .await
    }

    async fn append_relation(
        &self,
        relation: &DiscrepancyEpisodeRelationV1,
    ) -> Result<DiscrepancyAppendOutcomeV1> {
        let admitted = admit_relation(relation, self.trusted_scope.semantic_scope())?;
        let scope = self.trusted_scope.clone();
        let relation = relation.clone();
        with_serializable_retry(&self.pool, self.retry_policy, move |transaction| {
            let scope = scope.clone();
            let relation = relation.clone();
            let admitted = admitted.clone();
            Box::pin(async move {
                append_relation_in_transaction(transaction, &scope, &relation, &admitted).await
            })
        })
        .await
    }

    async fn read_envelope(
        &self,
        episode_fingerprint: DiscrepancyEpisodeFingerprintV1,
    ) -> Result<Option<DiscrepancyEnvelopeV1>> {
        let entries = self.read_log(episode_fingerprint).await?;
        let Some(first) = entries.first() else {
            return Ok(None);
        };
        match &first.record {
            DiscrepancyLogRecordV1::Envelope { envelope } => Ok(Some(envelope.clone())),
            DiscrepancyLogRecordV1::Lifecycle { .. } => Err(FleetError::Memory(
                "discrepancy log sequence 1 is not an envelope record".into(),
            )),
        }
    }

    async fn read_log(
        &self,
        episode_fingerprint: DiscrepancyEpisodeFingerprintV1,
    ) -> Result<Vec<DiscrepancyLogEntryV1>> {
        let rows: Vec<PgRow> = sqlx::query(SELECT_LOG_SQL)
            .bind(self.trusted_scope.tenant_id())
            .bind(self.trusted_scope.project())
            .bind(episode_fingerprint.digest().as_bytes().to_vec())
            .fetch_all(&self.pool)
            .await?;
        decode_log_rows(&rows)
    }

    async fn read_relations(
        &self,
        family_fingerprint: DiscrepancyFamilyFingerprintV1,
    ) -> Result<Vec<DiscrepancyEpisodeRelationV1>> {
        let rows: Vec<Vec<u8>> = sqlx::query_scalar(SELECT_RELATIONS_SQL)
            .bind(self.trusted_scope.tenant_id())
            .bind(self.trusted_scope.project())
            .bind(family_fingerprint.digest().as_bytes().to_vec())
            .fetch_all(&self.pool)
            .await?;
        decode_relation_rows(&rows)
    }

    async fn read_projection(
        &self,
        episode_fingerprint: DiscrepancyEpisodeFingerprintV1,
    ) -> Result<Option<StoredDiscrepancyProjectionV1>> {
        let row: Option<PgRow> = sqlx::query(SELECT_PROJECTION_SQL)
            .bind(self.trusted_scope.tenant_id())
            .bind(self.trusted_scope.project())
            .bind(episode_fingerprint.digest().as_bytes().to_vec())
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref()
            .map(|row| decode_projection_row(episode_fingerprint, row))
            .transpose()
    }

    async fn rebuild_projection(
        &self,
        episode_fingerprint: DiscrepancyEpisodeFingerprintV1,
    ) -> Result<StoredDiscrepancyProjectionV1> {
        let entries = self.read_log(episode_fingerprint).await?;
        let (envelope, events) = split_log(&entries)?;
        let relations = self.read_relations(envelope.family_fingerprint).await?;
        derive_stored_projection(&envelope, &events, &relations, entries.len() as u64)
    }
}

/// Seed one episode: head row, log sequence 1, and the initial projection.
async fn admit_envelope_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    envelope: &DiscrepancyEnvelopeV1,
    admitted: &AdmittedDiscrepancyEnvelopeV1,
) -> Result<DiscrepancyAppendOutcomeV1> {
    let now = statement_timestamp(transaction).await?;
    let episode_bytes = admitted.episode_fingerprint.digest().as_bytes().to_vec();

    let head: Option<PgRow> = sqlx::query(LOCK_HEAD_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(episode_bytes.clone())
        .fetch_optional(&mut **transaction)
        .await?;
    if let Some(head) = head {
        let stored_envelope_id: Vec<u8> = head.try_get("envelope_id")?;
        if stored_envelope_id == admitted.envelope_id.digest().as_bytes() {
            // A byte-identical envelope replayed: idempotent, nothing written.
            return Ok(DiscrepancyAppendOutcomeV1::AlreadyRecorded {
                record_id: admitted.envelope_id.digest(),
            });
        }
        // Per-detection identity is immutable: a DIFFERENT envelope may not
        // re-seed an episode another detection already opened.
        return Err(FleetError::Memory(
            "a different detection envelope is already seeded for this episode".into(),
        ));
    }

    sqlx::query(INSERT_HEAD_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(episode_bytes.clone())
        .bind(admitted.family_fingerprint.digest().as_bytes().to_vec())
        .bind(admitted.envelope_id.digest().as_bytes().to_vec())
        .bind(1_i64)
        .bind(now)
        .execute(&mut **transaction)
        .await?;

    sqlx::query(APPEND_LOG_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(episode_bytes)
        .bind(1_i64)
        .bind("envelope")
        .bind(admitted.envelope_id.digest().as_bytes().to_vec())
        .bind(encode_log_record(&DiscrepancyLogRecordV1::Envelope {
            envelope: envelope.clone(),
        })?)
        .bind(now)
        .execute(&mut **transaction)
        .await?;

    let relations =
        load_relations(transaction, scope, admitted.family_fingerprint).await?;
    let stored = derive_stored_projection(envelope, &[], &relations, 1)?;
    upsert_projection(transaction, scope, &stored, now).await?;

    Ok(DiscrepancyAppendOutcomeV1::Appended(
        DiscrepancyLedgerTransitionV1 {
            record_id: admitted.envelope_id.digest(),
            log_seq: Some(1),
            refreshed_episodes: vec![admitted.episode_fingerprint],
        },
    ))
}

/// Append one lifecycle event and advance its episode's projection.
async fn append_lifecycle_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    event: &DiscrepancyLifecycleEventV1,
) -> Result<DiscrepancyAppendOutcomeV1> {
    let now = statement_timestamp(transaction).await?;
    let episode_bytes = event.episode_fingerprint.digest().as_bytes().to_vec();

    let head: Option<PgRow> = sqlx::query(LOCK_HEAD_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(episode_bytes.clone())
        .fetch_optional(&mut **transaction)
        .await?;
    let Some(head) = head else {
        // Fail closed: a lifecycle transition for an episode this ledger
        // never admitted has no envelope to be authorized against.
        return Err(FleetError::Memory(
            "discrepancy lifecycle event targets an episode with no admitted envelope".into(),
        ));
    };
    let head_seq = seq_from_i64(head.try_get("log_seq")?)?;
    let family = family_from_bytes(&head.try_get::<Vec<u8>, _>("family_fingerprint")?)?;

    let entries = load_log(transaction, scope, &episode_bytes).await?;
    let (envelope, mut events) = split_log(&entries)?;
    if entries.len() as u64 != head_seq {
        return Err(FleetError::Memory(
            "discrepancy head log sequence disagrees with its log".into(),
        ));
    }

    // The whole pure fail-closed boundary, against the STORED envelope.
    let admitted: AdmittedDiscrepancyLifecycleEventV1 =
        admit_lifecycle_event(&envelope, event, scope.semantic_scope())?;

    let exists: Option<i64> = sqlx::query_scalar(RECORD_EXISTS_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(admitted.event_id.digest().as_bytes().to_vec())
        .fetch_optional(&mut **transaction)
        .await?;
    if exists.is_some() {
        return Ok(DiscrepancyAppendOutcomeV1::AlreadyRecorded {
            record_id: admitted.event_id.digest(),
        });
    }

    let next_seq = head_seq
        .checked_add(1)
        .ok_or_else(|| FleetError::Memory("discrepancy log sequence overflow".into()))?;
    if usize::try_from(next_seq).unwrap_or(usize::MAX) > MAX_EPISODE_LOG_ENTRIES {
        return Err(FleetError::Memory(
            "discrepancy episode log exceeds its bound".into(),
        ));
    }

    sqlx::query(APPEND_LOG_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(episode_bytes.clone())
        .bind(seq_as_i64(next_seq)?)
        .bind("lifecycle")
        .bind(admitted.event_id.digest().as_bytes().to_vec())
        .bind(encode_log_record(&DiscrepancyLogRecordV1::Lifecycle {
            event: event.clone(),
        })?)
        .bind(now)
        .execute(&mut **transaction)
        .await?;

    let advanced: Option<i64> = sqlx::query(ADVANCE_HEAD_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(episode_bytes)
        .bind(seq_as_i64(next_seq)?)
        .bind(now)
        .bind(seq_as_i64(head_seq)?)
        .fetch_optional(&mut **transaction)
        .await?
        .map(|row| row.try_get("log_seq"))
        .transpose()?;
    if advanced != Some(seq_as_i64(next_seq)?) {
        return Err(FleetError::Memory(
            "discrepancy head advance lost its compare-and-set".into(),
        ));
    }

    events.push(event.clone());
    let relations = load_relations(transaction, scope, family).await?;
    let stored = derive_stored_projection(&envelope, &events, &relations, next_seq)?;
    upsert_projection(transaction, scope, &stored, now).await?;

    Ok(DiscrepancyAppendOutcomeV1::Appended(
        DiscrepancyLedgerTransitionV1 {
            record_id: admitted.event_id.digest(),
            log_seq: Some(next_seq),
            refreshed_episodes: vec![event.episode_fingerprint],
        },
    ))
}

/// Append one relation to its family store and refresh every in-scope
/// episode it names.
async fn append_relation_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    relation: &DiscrepancyEpisodeRelationV1,
    admitted: &AdmittedDiscrepancyRelationV1,
) -> Result<DiscrepancyAppendOutcomeV1> {
    let now = statement_timestamp(transaction).await?;
    let family_bytes = admitted.family_fingerprint.digest().as_bytes().to_vec();

    let exists: Option<i64> = sqlx::query_scalar(RELATION_EXISTS_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(family_bytes.clone())
        .bind(admitted.relation_id.as_bytes().to_vec())
        .fetch_optional(&mut **transaction)
        .await?;
    if exists.is_some() {
        return Ok(DiscrepancyAppendOutcomeV1::AlreadyRecorded {
            record_id: admitted.relation_id,
        });
    }

    let existing = load_relations(transaction, scope, admitted.family_fingerprint).await?;
    if existing.len() >= MAX_FAMILY_RELATIONS {
        return Err(FleetError::Memory(
            "discrepancy family relation store exceeds its bound".into(),
        ));
    }
    let mut relations = existing;
    relations.push(relation.clone());

    // Every episode the relation names, deterministically ordered.
    let mut named: Vec<DiscrepancyEpisodeFingerprintV1> = relation.from_episodes.clone();
    named.push(relation.to_episode);
    named.sort_unstable();
    named.dedup();

    // Refresh — and thereby fail-closed validate — the projection of every
    // named episode this scope has admitted. `project_ledger_episode`
    // rejects a relation whose scope/profile/family diverges from a named
    // envelope's own, rolling the whole append back: a stored relation can
    // therefore never make a stored episode unprojectable.
    let mut refreshed = Vec::new();
    for episode in &named {
        let episode_bytes = episode.digest().as_bytes().to_vec();
        let head: Option<PgRow> = sqlx::query(LOCK_HEAD_SQL)
            .bind(scope.tenant_id())
            .bind(scope.project())
            .bind(episode_bytes.clone())
            .fetch_optional(&mut **transaction)
            .await?;
        let Some(head) = head else {
            continue;
        };
        let head_family = family_from_bytes(&head.try_get::<Vec<u8>, _>("family_fingerprint")?)?;
        if head_family != relation.family_fingerprint {
            return Err(FleetError::Memory(
                "discrepancy relation names an in-scope episode of a different family".into(),
            ));
        }
        let head_seq = seq_from_i64(head.try_get("log_seq")?)?;
        let entries = load_log(transaction, scope, &episode_bytes).await?;
        let (envelope, events) = split_log(&entries)?;
        let stored = derive_stored_projection(&envelope, &events, &relations, head_seq)?;
        upsert_projection(transaction, scope, &stored, now).await?;
        refreshed.push(*episode);
    }

    sqlx::query(INSERT_RELATION_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(family_bytes)
        .bind(admitted.relation_id.as_bytes().to_vec())
        .bind(admitted.canonical_relation.clone())
        .bind(now)
        .execute(&mut **transaction)
        .await?;

    Ok(DiscrepancyAppendOutcomeV1::Appended(
        DiscrepancyLedgerTransitionV1 {
            record_id: admitted.relation_id,
            log_seq: None,
            refreshed_episodes: refreshed,
        },
    ))
}

/// Fold the log and relation set into the stored projection row.
fn derive_stored_projection(
    envelope: &DiscrepancyEnvelopeV1,
    events: &[DiscrepancyLifecycleEventV1],
    relations: &[DiscrepancyEpisodeRelationV1],
    cursor_seq: u64,
) -> Result<StoredDiscrepancyProjectionV1> {
    let (projection, evaluated_at) = project_ledger_episode(envelope, events, relations)?;
    let canonical_projection =
        crate::memory_contracts::canonical::encode_canonical(&projection)
            .map_err(FleetError::from)?;
    Ok(StoredDiscrepancyProjectionV1 {
        episode_fingerprint: envelope.episode_fingerprint,
        cursor_seq,
        evaluated_at,
        lifecycle_state: projection.lifecycle_state,
        verification_state: projection.verification_state,
        canonical_projection,
    })
}

async fn upsert_projection(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    stored: &StoredDiscrepancyProjectionV1,
    now: DateTime<Utc>,
) -> Result<()> {
    let cursor: Option<i64> = sqlx::query_scalar(UPSERT_PROJECTION_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(stored.episode_fingerprint.digest().as_bytes().to_vec())
        .bind(seq_as_i64(stored.cursor_seq)?)
        .bind(lifecycle_state_str(stored.lifecycle_state))
        .bind(verification_state_str(stored.verification_state))
        .bind(stored.evaluated_at.as_str())
        .bind(stored.canonical_projection.clone())
        .bind(now)
        .fetch_optional(&mut **transaction)
        .await?;
    if cursor != Some(seq_as_i64(stored.cursor_seq)?) {
        return Err(FleetError::Memory(
            "discrepancy projection cursor did not advance with its append".into(),
        ));
    }
    Ok(())
}

async fn load_log(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    episode_bytes: &[u8],
) -> Result<Vec<DiscrepancyLogEntryV1>> {
    let rows: Vec<PgRow> = sqlx::query(SELECT_LOG_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(episode_bytes.to_vec())
        .fetch_all(&mut **transaction)
        .await?;
    decode_log_rows(&rows)
}

async fn load_relations(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    family: DiscrepancyFamilyFingerprintV1,
) -> Result<Vec<DiscrepancyEpisodeRelationV1>> {
    let rows: Vec<Vec<u8>> = sqlx::query_scalar(SELECT_RELATIONS_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(family.digest().as_bytes().to_vec())
        .fetch_all(&mut **transaction)
        .await?;
    decode_relation_rows(&rows)
}

/// Split one episode log into its seeding envelope and lifecycle events,
/// failing closed on an empty or malformed log.
fn split_log(
    entries: &[DiscrepancyLogEntryV1],
) -> Result<(DiscrepancyEnvelopeV1, Vec<DiscrepancyLifecycleEventV1>)> {
    let Some((first, rest)) = entries.split_first() else {
        return Err(FleetError::Memory(
            "discrepancy episode has no admitted envelope".into(),
        ));
    };
    let DiscrepancyLogRecordV1::Envelope { envelope } = &first.record else {
        return Err(FleetError::Memory(
            "discrepancy log sequence 1 is not an envelope record".into(),
        ));
    };
    let mut events = Vec::with_capacity(rest.len());
    for entry in rest {
        let DiscrepancyLogRecordV1::Lifecycle { event } = &entry.record else {
            return Err(FleetError::Memory(
                "discrepancy log carries a second envelope record".into(),
            ));
        };
        events.push(event.clone());
    }
    Ok((envelope.clone(), events))
}

fn encode_log_record(record: &DiscrepancyLogRecordV1) -> Result<Vec<u8>> {
    crate::memory_contracts::canonical::encode_canonical(record).map_err(FleetError::from)
}

fn decode_log_rows(rows: &[PgRow]) -> Result<Vec<DiscrepancyLogEntryV1>> {
    if rows.len() > MAX_EPISODE_LOG_ENTRIES {
        return Err(FleetError::Memory(
            "discrepancy episode log exceeds its bound".into(),
        ));
    }
    let mut entries = Vec::with_capacity(rows.len());
    for row in rows {
        let seq: i64 = row.try_get("seq")?;
        let record_id: Vec<u8> = row.try_get("record_id")?;
        let canonical: Vec<u8> = row.try_get("canonical_record")?;
        // decode_strict, not a lenient parse: a stored record whose bytes are
        // not already canonical is corruption and fails closed.
        let record: DiscrepancyLogRecordV1 = decode_strict(&canonical)?;
        entries.push(DiscrepancyLogEntryV1 {
            seq: seq_from_i64(seq)?,
            record_id: digest_from(&record_id)?,
            record,
        });
    }
    Ok(entries)
}

fn decode_relation_rows(rows: &[Vec<u8>]) -> Result<Vec<DiscrepancyEpisodeRelationV1>> {
    if rows.len() > MAX_FAMILY_RELATIONS {
        return Err(FleetError::Memory(
            "discrepancy family relation store exceeds its bound".into(),
        ));
    }
    let mut relations = Vec::with_capacity(rows.len());
    for bytes in rows {
        let relation: DiscrepancyEpisodeRelationV1 = decode_strict(bytes)?;
        relations.push(relation);
    }
    Ok(relations)
}

fn decode_projection_row(
    episode_fingerprint: DiscrepancyEpisodeFingerprintV1,
    row: &PgRow,
) -> Result<StoredDiscrepancyProjectionV1> {
    let cursor_seq: i64 = row.try_get("cursor_seq")?;
    let lifecycle_state: String = row.try_get("lifecycle_state")?;
    let verification_state: String = row.try_get("verification_state")?;
    let evaluated_at: String = row.try_get("evaluated_at")?;
    let canonical_projection: Vec<u8> = row.try_get("canonical_projection")?;
    Ok(StoredDiscrepancyProjectionV1 {
        episode_fingerprint,
        cursor_seq: seq_from_i64(cursor_seq)?,
        evaluated_at: CanonicalTimestamp::parse(&evaluated_at)
            .map_err(|_| FleetError::Memory("stored evaluation time is not canonical".into()))?,
        lifecycle_state: lifecycle_state_from_str(&lifecycle_state)?,
        verification_state: verification_state_from_str(&verification_state)?,
        canonical_projection,
    })
}

async fn statement_timestamp(transaction: &mut Transaction<'_, Postgres>) -> Result<DateTime<Utc>> {
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT pg_catalog.statement_timestamp()")
        .fetch_one(&mut **transaction)
        .await?;
    Ok(now)
}

fn family_from_bytes(bytes: &[u8]) -> Result<DiscrepancyFamilyFingerprintV1> {
    Ok(DiscrepancyFamilyFingerprintV1::from_digest(digest_from(
        bytes,
    )?))
}

fn digest_from(bytes: &[u8]) -> Result<Sha256Digest> {
    let exact: [u8; 32] = bytes
        .try_into()
        .map_err(|_| FleetError::Memory("stored discrepancy digest is not 32 bytes".into()))?;
    Ok(Sha256Digest::from_bytes(exact))
}

fn seq_as_i64(value: u64) -> Result<i64> {
    i64::try_from(value)
        .map_err(|_| FleetError::Memory("discrepancy sequence exceeds the INT8 column".into()))
}

fn seq_from_i64(value: i64) -> Result<u64> {
    u64::try_from(value)
        .map_err(|_| FleetError::Memory("stored discrepancy sequence is negative".into()))
}

#[cfg(test)]
#[path = "cockroach_tests.rs"]
mod tests;
