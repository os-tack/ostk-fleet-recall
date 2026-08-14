//! `CockroachDB` implementation of the durable claim and conflict ledger.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use ostk_recall_core::{Chunk, ChunkEmbedder};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::postgres::{PgPool, PgRow};
use sqlx::{Row, Transaction};

use crate::ledger::{
    Claim, ClaimInput, ClaimKind, ClaimLedger, ClaimMutation, ClaimState, ClaimSupport, Conflict,
    SemanticClaimHit, SupportedClaimIds,
};
use crate::store::cockroach::{
    EMBEDDING_DIMENSION, RetryPolicy, serialize_vector, with_serializable_retry,
};
use crate::{FleetError, FleetScope, Result};

const MAX_IDEMPOTENCY_KEY_BYTES: usize = 256;
const MAX_LEDGER_RESULTS: usize = 100;
const CLAIM_CANDIDATE_MULTIPLIER: usize = 8;
const MAX_CLAIM_CANDIDATES: usize = 1_000;
const MAX_CLAIM_SEARCH_TEXT_CHARS: usize = 2_000;
const MAX_CLAIM_SEARCH_PASSAGE_CHARS: usize = 2_000;
/// Maximum number of existing, incompatible current claims one record
/// mutation may attach to a same-key conflict. The query reads one sentinel
/// row beyond this bound and aborts the entire serializable transaction rather
/// than performing an open-ended membership/event fan-out.
const MAX_INCOMPATIBLE_CLAIMS_PER_MUTATION: usize = 256;
const MAX_MEMBERS_PER_CONFLICT: usize = 32;
const MAX_CONFLICT_MEMBER_TEXT_CHARS: usize = 1_000;
const MAX_CONFLICT_MEMBER_VALUE_BYTES: usize = 2_000;
const CONFLICT_RATIONALE: &str =
    "overlapping current typed claims have incompatible values or polarity";

// These projections intentionally omit fields that their public list/search
// responses discard. Keeping them as constants also lets tests guard against a
// future refactor accidentally restoring full-row/support amplification.
const CLAIM_ANN_SEARCH_SQL: &str = "SELECT claim_id, passage_index, left(passage_text, $6) AS passage_text, \
            (1.0 - (vector <=> $4::VECTOR(512)))::FLOAT8 AS similarity \
     FROM memory_claim_embeddings \
     WHERE tenant_id = $1 AND project = $2 AND model = $3 \
     ORDER BY vector <=> $4::VECTOR(512) LIMIT $5";
const SEARCH_CLAIM_PROJECTION_SQL: &str = "SELECT id, project, kind, claim_key, subject, predicate, NULL::JSONB AS value, \
            left(text, $4) AS text, polarity, state, origin, actor, confidence, valid_from, \
            valid_to, superseded_by, revision, conflict_eligible, created_at, updated_at \
     FROM memory_claims@{NO_FULL_SCAN} \
     WHERE tenant_id = $1 AND project = $2 AND id = ANY($3)";
const CONFLICT_CLAIM_PROJECTION_SQL: &str = "SELECT id, project, kind, claim_key, subject, predicate, \
            CASE WHEN value IS NULL OR octet_length(value::STRING) > $5 \
                 THEN NULL ELSE value END AS value, \
            left(text, $4) AS text, polarity, state, origin, actor, confidence, valid_from, \
            valid_to, superseded_by, revision, conflict_eligible, created_at, updated_at, \
            (value IS NOT NULL AND octet_length(value::STRING) > $5) AS value_elided \
     FROM memory_claims@{NO_FULL_SCAN} \
     WHERE tenant_id = $1 AND project = $2 AND id = ANY($3)";
const CLAIM_CONFLICT_IDS_SQL: &str = "SELECT claim_id, conflict_id FROM memory_conflict_members@{NO_FULL_SCAN} \
     WHERE tenant_id = $1 AND project = $2 AND claim_id = ANY($3) \
     ORDER BY claim_id, conflict_id";
const SUPPORTED_CLAIM_IDS_SQL: &str = "SELECT DISTINCT claim_id \
     FROM memory_claim_support@{NO_FULL_SCAN} \
     WHERE tenant_id = $1 AND project = $2 AND chunk_id = ANY($3) AND state = 'current' \
     ORDER BY claim_id LIMIT $4";
const SUPPORT_CHUNK_MATCH_SQL: &str = "SELECT EXISTS(\
         SELECT 1 FROM memory_chunks@{NO_FULL_SCAN} \
         WHERE tenant_id = $1 AND project = $2 AND chunk_id = $3 \
           AND source_config_id = $4 AND source = $5 AND source_id = $6 \
           AND ($7::STRING IS NULL OR content_sha256 = $7)\
     )";

/// Claim repository bound to one trusted tenant/project and embedding space.
///
/// Agent/session attribution comes from each resolved operation scope, but it
/// can never redirect a repository to another corpus.
#[derive(Clone)]
pub struct CockroachClaimLedger {
    pool: PgPool,
    trusted_scope: FleetScope,
    embedder: Arc<dyn ChunkEmbedder>,
    claim_model: String,
    retry_policy: RetryPolicy,
}

impl std::fmt::Debug for CockroachClaimLedger {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CockroachClaimLedger")
            .field("trusted_scope", &self.trusted_scope)
            .field("embedding_model", &self.claim_model)
            .field("embedding_dim", &self.embedder.dim())
            .field("retry_policy", &self.retry_policy)
            .finish_non_exhaustive()
    }
}

impl CockroachClaimLedger {
    pub fn new(
        pool: PgPool,
        trusted_scope: FleetScope,
        embedder: Arc<dyn ChunkEmbedder>,
        retry_policy: RetryPolicy,
    ) -> Result<Self> {
        trusted_scope.validate()?;
        if embedder.dim() != EMBEDDING_DIMENSION {
            return Err(FleetError::Configuration(format!(
                "claim embedder dimension mismatch: expected {EMBEDDING_DIMENSION}, got {}",
                embedder.dim()
            )));
        }
        if embedder.model_id().trim().is_empty() {
            return Err(FleetError::Configuration(
                "claim embedder model_id must not be empty".into(),
            ));
        }
        Ok(Self {
            pool,
            trusted_scope,
            claim_model: embedder.model_id().to_string(),
            embedder,
            retry_policy,
        })
    }

    fn ensure_scope(&self, scope: &FleetScope) -> Result<()> {
        scope.validate()?;
        if scope.tenant_id != self.trusted_scope.tenant_id
            || scope.project != self.trusted_scope.project
            || scope.agent != self.trusted_scope.agent
            || scope.privacy_tier != self.trusted_scope.privacy_tier
        {
            return Err(FleetError::InvalidScope(
                "claim operation is outside this repository's trusted fleet identity".into(),
            ));
        }
        Ok(())
    }
}

#[async_trait]
#[allow(clippy::too_many_lines)] // atomic record orchestration is kept visibly in one backend impl
impl ClaimLedger for CockroachClaimLedger {
    async fn record_claim(
        &self,
        scope: &FleetScope,
        input: &ClaimInput,
        idempotency_key: &str,
    ) -> Result<ClaimMutation> {
        self.ensure_scope(scope)?;
        let key = idempotency_key.trim();
        if key.is_empty() || key.len() > MAX_IDEMPOTENCY_KEY_BYTES {
            return Err(FleetError::Memory(format!(
                "idempotency_key must be between 1 and {MAX_IDEMPOTENCY_KEY_BYTES} bytes"
            )));
        }
        if input
            .actor
            .as_deref()
            .is_some_and(|actor| actor != scope.agent)
        {
            return Err(FleetError::InvalidScope(
                "claim actor must match the authenticated fleet agent".into(),
            ));
        }
        let prepared = input.prepare()?;
        let request = serde_json::json!({
            "scope": {
                "project": scope.project,
                "agent": scope.agent,
                "session_id": scope.session_id,
                "privacy_tier": scope.privacy_tier,
            },
            "input": input,
        });
        // A non-transactional fast path avoids embedding a known replay. The
        // transaction performs the same check again, so a concurrent first
        // mutation remains at-most-once despite response loss and retries.
        if let Some(mutation) = replayed_record(&self.pool, scope, key, &request).await? {
            return Ok(mutation);
        }
        // Embedding is intentionally outside the transaction. A model load or
        // expensive encode cannot hold SQL locks, and deterministic passages
        // can be safely reused if Cockroach asks us to replay the transaction.
        let now = Utc::now();
        let provisional = Claim {
            id: 0,
            project: scope.project.clone(),
            kind: input.kind,
            claim_key: prepared.claim_key.clone(),
            subject: prepared.subject.clone(),
            predicate: prepared.predicate.clone(),
            value: prepared.value.clone(),
            text: input.text.trim().to_string(),
            polarity: input.polarity,
            state: ClaimState::Active,
            origin: input.origin.trim().to_string(),
            actor: Some(scope.agent.clone()),
            confidence: input.confidence,
            valid_from: input.valid_from,
            valid_to: input.valid_to,
            superseded_by: None,
            revision: 1,
            conflict_eligible: prepared.conflict_eligible,
            created_at: now,
            updated_at: now,
            support: Vec::new(),
            conflict_ids: Vec::new(),
        };
        let passage_texts = provisional.embedding_passages();
        let passage_refs = passage_texts.iter().map(String::as_str).collect::<Vec<_>>();
        let vectors = self.embedder.encode_batch(&passage_refs);
        if vectors.len() != passage_texts.len() {
            return Err(FleetError::Memory(format!(
                "claim embedder returned {} vectors for {} passages",
                vectors.len(),
                passage_texts.len()
            )));
        }
        let mut passages = Vec::with_capacity(passage_texts.len());
        for (index, (text, vector)) in passage_texts.into_iter().zip(vectors).enumerate() {
            let passage_index = i32::try_from(index)
                .map_err(|_| FleetError::Memory("too many claim passages".into()))?;
            passages.push((passage_index, text, serialize_vector(&vector)?));
        }

        let scope = scope.clone();
        let input = input.clone();
        let prepared = prepared.clone();
        let key = key.to_string();
        let model = self.claim_model.clone();
        let policy = self.retry_policy;
        let pool = self.pool.clone();

        with_serializable_retry(&pool, policy, |transaction| {
            let scope = scope.clone();
            let input = input.clone();
            let prepared = prepared.clone();
            let request = request.clone();
            let key = key.clone();
            let model = model.clone();
            let passages = passages.clone();
            Box::pin(async move {
                if let Some(row) = sqlx::query(
                    "SELECT project, operation, request, response \
                     FROM memory_mutation_receipts \
                     WHERE tenant_id = $1 AND idempotency_key = $2",
                )
                .bind(scope.tenant_id)
                .bind(&key)
                .fetch_optional(&mut **transaction)
                .await?
                {
                    return decode_record_receipt(&row, &scope, &request);
                }

                let reservation = sqlx::query_scalar::<_, String>(
                    "INSERT INTO memory_mutation_receipts (\
                         tenant_id, idempotency_key, project, request, operation\
                     ) VALUES ($1, $2, $3, $4, 'record') \
                     ON CONFLICT (tenant_id, idempotency_key) DO NOTHING \
                     RETURNING idempotency_key",
                )
                .bind(scope.tenant_id)
                .bind(&key)
                .bind(&scope.project)
                .bind(&request)
                .fetch_optional(&mut **transaction)
                .await?;
                if reservation.is_none() {
                    let row = sqlx::query(
                        "SELECT project, operation, request, response \
                         FROM memory_mutation_receipts \
                         WHERE tenant_id = $1 AND idempotency_key = $2",
                    )
                    .bind(scope.tenant_id)
                    .bind(&key)
                    .fetch_one(&mut **transaction)
                    .await?;
                    return decode_record_receipt(&row, &scope, &request);
                }

                // Deployment bootstrap owns model registration. Steady-state
                // fleet mutations only read and compare this immutable project
                // coordinate, avoiding a shared-row INSERT/ON CONFLICT write on
                // every remember call.
                let active_model: Option<String> = sqlx::query_scalar(
                    "SELECT embedding_model FROM memory_corpus_models \
                     WHERE tenant_id = $1 AND project = $2",
                )
                .bind(scope.tenant_id)
                .bind(&scope.project)
                .fetch_optional(&mut **transaction)
                .await?;
                let active_model = active_model.ok_or_else(|| {
                    FleetError::Configuration(
                        "active embedding generation is not initialized; run deployment bootstrap"
                            .into(),
                    )
                })?;
                if active_model != model {
                    return Err(protocol_error(format!(
                        "claim embedding model '{model}' does not match active corpus model '{active_model}'"
                    )));
                }

                let mut claim = insert_claim(transaction, &scope, &input, &prepared).await?;
                claim.support = insert_support(transaction, &scope, claim.id, &input).await?;

                for (passage_index, passage_text, vector) in &passages {
                    sqlx::query(
                        "INSERT INTO memory_claim_embeddings (\
                             tenant_id, project, claim_id, passage_index, passage_text, model, vector\
                         ) VALUES ($1, $2, $3, $4, $5, $6, $7::VECTOR(512))",
                    )
                    .bind(scope.tenant_id)
                    .bind(&scope.project)
                    .bind(claim.id)
                    .bind(passage_index)
                    .bind(passage_text)
                    .bind(&model)
                    .bind(vector)
                    .execute(&mut **transaction)
                    .await?;
                }

                // Project the authoritative claim into the active corpus in
                // the same transaction. Default recall(search) can therefore
                // find deliberate memory through both lexical and vector
                // lanes without a claim-specific caller hint.
                let (_, primary_passage, primary_vector) = passages
                    .first()
                    .ok_or_else(|| protocol_error("claim produced no embedding passages"))?;
                let chunk_id = format!("claim:{}", claim.id);
                let source_id = format!("claim/{}", claim.id);
                let content_hash = hex::encode(Sha256::digest(claim.text.as_bytes()));
                let embedding_hash = Chunk::embedding_input_hash(&model, "", primary_passage);
                sqlx::query(
                    "INSERT INTO memory_chunks (\
                         tenant_id, project, chunk_id, source, source_id, source_config_id, \
                         chunk_index, source_timestamp, text, content_sha256, \
                         embedding_input_sha256, embedding_model, embedding, facets, links, extra\
                     ) VALUES (\
                         $1, $2, $3, 'ostk_memory', $4, 'synthetic:claim', 0, now(), $5, $6, \
                         $7, $8, $9::VECTOR(512), $10, '{}'::JSONB, $11\
                     ) ON CONFLICT (tenant_id, project, chunk_id) DO UPDATE SET \
                         text = excluded.text, content_sha256 = excluded.content_sha256, \
                         embedding_input_sha256 = excluded.embedding_input_sha256, \
                         embedding_model = excluded.embedding_model, embedding = excluded.embedding, \
                         facets = excluded.facets, extra = excluded.extra, updated_at = now()",
                )
                .bind(scope.tenant_id)
                .bind(&scope.project)
                .bind(&chunk_id)
                .bind(&source_id)
                .bind(&claim.text)
                .bind(content_hash)
                .bind(embedding_hash)
                .bind(&model)
                .bind(primary_vector)
                .bind(serde_json::json!({
                    "project": [scope.project.clone()],
                    "record_kind": [claim.kind.as_str()],
                }))
                .bind(serde_json::json!({ "claim_id": claim.id, "claim_key": claim.claim_key }))
                .execute(&mut **transaction)
                .await?;

                // The claim is born active. If conflict detection below
                // changes it to disputed, a separate transition event records
                // that lifecycle edge rather than folding it into creation.
                sqlx::query(
                    "INSERT INTO memory_claim_events (\
                         tenant_id, project, claim_id, event_kind, actor, to_state, payload\
                     ) VALUES ($1, $2, $3, 'recorded', $4, 'active', $5)",
                )
                .bind(scope.tenant_id)
                .bind(&scope.project)
                .bind(claim.id)
                .bind(&scope.agent)
                .bind(serde_json::json!({ "idempotency_key": key }))
                .execute(&mut **transaction)
                .await?;

                let mut conflicts_opened = Vec::new();
                if let (true, Some(claim_key), Some(value)) = (
                    prepared.conflict_eligible,
                    prepared.claim_key.as_deref(),
                    prepared.value.as_ref(),
                ) {
                    let incompatible_ids = sqlx::query_scalar::<_, i64>(
                        "SELECT id FROM memory_claims \
                         WHERE tenant_id = $1 AND project = $2 AND id <> $3 \
                           AND claim_key = $4 AND conflict_eligible \
                           AND state IN ('active', 'disputed') \
                           AND (value IS DISTINCT FROM $5 OR polarity <> $6) \
                           AND (valid_to IS NULL OR $7::TIMESTAMPTZ IS NULL OR $7 < valid_to) \
                           AND ($8::TIMESTAMPTZ IS NULL OR valid_from IS NULL OR valid_from < $8) \
                         ORDER BY id LIMIT $9",
                    )
                    .bind(scope.tenant_id)
                    .bind(&scope.project)
                    .bind(claim.id)
                    .bind(claim_key)
                    .bind(value)
                    .bind(input.polarity)
                    .bind(input.valid_from)
                    .bind(input.valid_to)
                    .bind(i64::try_from(
                        MAX_INCOMPATIBLE_CLAIMS_PER_MUTATION.saturating_add(1),
                    )
                    .map_err(|_| protocol_error("conflict mutation bound is outside INT8 range"))?)
                    .fetch_all(&mut **transaction)
                    .await?;

                    if incompatible_ids.len() > MAX_INCOMPATIBLE_CLAIMS_PER_MUTATION {
                        return Err(FleetError::Memory(format!(
                            "same-key conflict exceeds the bounded mutation limit of {MAX_INCOMPATIBLE_CLAIMS_PER_MUTATION} existing claims"
                        )));
                    }

                    if !incompatible_ids.is_empty() {
                        let observation =
                            observe_conflict(transaction, &scope, claim_key).await?;
                        let conflict_id = observation.id;

                        let mut member_ids = incompatible_ids;
                        member_ids.push(claim.id);
                        member_ids.sort_unstable();
                        member_ids.dedup();
                        for member_id in &member_ids {
                            sqlx::query(
                                "INSERT INTO memory_conflict_members (\
                                     tenant_id, project, conflict_id, claim_id\
                                 ) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
                            )
                            .bind(scope.tenant_id)
                            .bind(&scope.project)
                            .bind(conflict_id)
                            .bind(member_id)
                            .execute(&mut **transaction)
                            .await?;
                        }
                        let transitioned_ids = sqlx::query_scalar::<_, i64>(
                            "UPDATE memory_claims SET state = 'disputed', revision = revision + 1, \
                                 updated_at = now() \
                             WHERE tenant_id = $1 AND project = $2 AND id = ANY($3) \
                               AND state = 'active' \
                             RETURNING id",
                        )
                        .bind(scope.tenant_id)
                        .bind(&scope.project)
                        .bind(&member_ids)
                        .fetch_all(&mut **transaction)
                        .await?;

                        for transitioned_id in &transitioned_ids {
                            insert_disputed_transition_event(
                                transaction,
                                &scope,
                                *transitioned_id,
                                conflict_id,
                            )
                            .await?;
                        }
                        if transitioned_ids.contains(&claim.id) {
                            claim.state = ClaimState::Disputed;
                            claim.revision += 1;
                        }
                        claim.conflict_ids.push(conflict_id);
                        if observation.opened {
                            conflicts_opened.push(conflict_id);
                        }
                    }
                }

                sqlx::query(
                    "INSERT INTO memory_events (\
                         tenant_id, project, agent, session_id, event_kind, entity_kind, \
                         entity_id, idempotency_key, payload\
                     ) VALUES ($1, $2, $3, $4, 'claim_recorded', 'claim', $5, $6, $7)",
                )
                .bind(scope.tenant_id)
                .bind(&scope.project)
                .bind(&scope.agent)
                .bind(&scope.session_id)
                .bind(claim.id.to_string())
                .bind(&key)
                .bind(serde_json::json!({ "claim_key": claim.claim_key }))
                .execute(&mut **transaction)
                .await?;

                let mutation = ClaimMutation {
                    operation: "record".into(),
                    claim,
                    idempotent_replay: false,
                    conflicts_opened,
                    conflicts_resolved: Vec::new(),
                };
                let response = serde_json::to_value(&mutation).map_err(|error| {
                    protocol_error(format!("serialize idempotency response: {error}"))
                })?;
                let receipt = sqlx::query(
                    "UPDATE memory_mutation_receipts \
                     SET claim_id = $5, response = $6 \
                     WHERE tenant_id = $1 AND idempotency_key = $2 \
                       AND project = $3 AND request = $4 AND operation = 'record'",
                )
                .bind(scope.tenant_id)
                .bind(&key)
                .bind(&scope.project)
                .bind(&request)
                .bind(mutation.claim.id)
                .bind(response)
                .execute(&mut **transaction)
                .await?;
                if receipt.rows_affected() != 1 {
                    return Err(protocol_error(
                        "idempotency receipt reservation disappeared during mutation",
                    ));
                }
                Ok(mutation)
            })
        })
        .await
    }

    async fn get_claim(&self, scope: &FleetScope, id: i64) -> Result<Option<Claim>> {
        self.ensure_scope(scope)?;
        if id <= 0 {
            return Ok(None);
        }
        fetch_claim(&self.pool, scope, id).await
    }

    async fn search_claims(
        &self,
        scope: &FleetScope,
        query: &str,
        include_history: bool,
        limit: usize,
    ) -> Result<Vec<SemanticClaimHit>> {
        self.ensure_scope(scope)?;
        validate_result_limit(limit)?;
        if query.trim().is_empty() {
            return Err(FleetError::Memory(
                "claim search query must not be empty".into(),
            ));
        }
        let query_vector = self
            .embedder
            .encode_batch(&[query.trim()])
            .into_iter()
            .next()
            .ok_or_else(|| FleetError::Memory("claim embedder returned no query vector".into()))?;
        let vector = serialize_vector(&query_vector)?;
        let candidate_limit = limit
            .saturating_mul(CLAIM_CANDIDATE_MULTIPLIER)
            .clamp(limit, MAX_CLAIM_CANDIDATES);
        // Keep the ANN statement prefix-only so Cockroach can use the vector
        // index. Lifecycle filtering and claim hydration happen after this
        // bounded candidate phase rather than silently forcing a table scan.
        let rows = sqlx::query(CLAIM_ANN_SEARCH_SQL)
            .bind(scope.tenant_id)
            .bind(&scope.project)
            .bind(&self.claim_model)
            .bind(vector)
            .bind(
                i64::try_from(candidate_limit)
                    .map_err(|_| FleetError::Memory("claim candidate limit exceeds INT8".into()))?,
            )
            // Read one extra character so `compact_text` can preserve the public
            // ellipsis contract without transferring an unbounded passage.
            .bind(
                i64::try_from(MAX_CLAIM_SEARCH_PASSAGE_CHARS + 1)
                    .map_err(|_| protocol_error("claim passage projection limit exceeds INT8"))?,
            )
            .fetch_all(&self.pool)
            .await?;

        let candidates = rows
            .into_iter()
            .map(|row| {
                Ok(ClaimCandidate {
                    claim_id: row.try_get("claim_id")?,
                    similarity: row.try_get("similarity")?,
                    passage_index: row.try_get("passage_index")?,
                    matched_passage: compact_text(
                        &row.try_get::<String, _>("passage_text")?,
                        MAX_CLAIM_SEARCH_PASSAGE_CHARS,
                    ),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let candidates = deduplicate_claim_candidates(candidates);
        let candidate_ids = candidates
            .iter()
            .map(|candidate| candidate.claim_id)
            .collect::<Vec<_>>();
        let claims_by_id = fetch_search_claims(&self.pool, scope, &candidate_ids).await?;
        let mut hits = Vec::with_capacity(limit);
        for candidate in candidates {
            let Some(claim) = claims_by_id.get(&candidate.claim_id).cloned() else {
                continue;
            };
            if !include_history && !claim.state.is_current() {
                continue;
            }
            hits.push(SemanticClaimHit {
                claim,
                similarity: candidate.similarity,
                passage_index: candidate.passage_index,
                matched_passage: candidate.matched_passage,
            });
            if hits.len() == limit {
                break;
            }
        }
        Ok(hits)
    }

    async fn list_conflicts(
        &self,
        scope: &FleetScope,
        include_resolved: bool,
        limit: usize,
    ) -> Result<Vec<Conflict>> {
        self.ensure_scope(scope)?;
        validate_result_limit(limit)?;
        let rows = sqlx::query(
            "SELECT id, project, claim_key, kind, state, detector, rationale, revision, \
                    detected_at, last_seen_at, resolved_at, resolution_kind, resolution_reason \
             FROM memory_conflicts \
             WHERE tenant_id = $1 AND project = $2 \
               AND ($3 OR state = 'open') \
             ORDER BY last_seen_at DESC, id LIMIT $4",
        )
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(include_resolved)
        .bind(
            i64::try_from(limit)
                .map_err(|_| FleetError::Memory("conflict limit exceeds INT8".into()))?,
        )
        .fetch_all(&self.pool)
        .await?;

        hydrate_conflicts(&self.pool, scope, rows).await
    }

    async fn conflicts_for_claim_ids(
        &self,
        scope: &FleetScope,
        claim_ids: &[i64],
        limit: usize,
    ) -> Result<Vec<Conflict>> {
        self.ensure_scope(scope)?;
        validate_result_limit(limit)?;
        if claim_ids.is_empty() {
            return Ok(Vec::new());
        }
        if claim_ids.len() > MAX_LEDGER_RESULTS {
            return Err(FleetError::Memory(format!(
                "claim id filter accepts at most {MAX_LEDGER_RESULTS} ids"
            )));
        }
        let rows = sqlx::query(
            "SELECT DISTINCT c.id, c.project, c.claim_key, c.kind, c.state, c.detector, \
                    c.rationale, c.revision, c.detected_at, c.last_seen_at, c.resolved_at, \
                    c.resolution_kind, c.resolution_reason \
             FROM memory_conflicts AS c \
             JOIN memory_conflict_members AS wanted \
               ON wanted.tenant_id = c.tenant_id AND wanted.project = c.project \
              AND wanted.conflict_id = c.id \
             WHERE c.tenant_id = $1 AND c.project = $2 AND c.state = 'open' \
               AND wanted.claim_id = ANY($3) \
             ORDER BY c.last_seen_at DESC, c.id LIMIT $4",
        )
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(claim_ids)
        .bind(
            i64::try_from(limit)
                .map_err(|_| FleetError::Memory("conflict limit exceeds INT8".into()))?,
        )
        .fetch_all(&self.pool)
        .await?;
        hydrate_conflicts(&self.pool, scope, rows).await
    }

    async fn supported_claim_ids_for_chunk_ids(
        &self,
        scope: &FleetScope,
        chunk_ids: &[String],
        limit: usize,
    ) -> Result<SupportedClaimIds> {
        self.ensure_scope(scope)?;
        validate_result_limit(limit)?;
        if chunk_ids.is_empty() {
            return Ok(SupportedClaimIds {
                claim_ids: Vec::new(),
                truncated: false,
            });
        }
        if chunk_ids.len() > MAX_LEDGER_RESULTS {
            return Err(FleetError::Memory(format!(
                "support chunk filter accepts at most {MAX_LEDGER_RESULTS} ids"
            )));
        }
        if chunk_ids
            .iter()
            .any(|id| id.trim().is_empty() || id.len() > 256)
        {
            return Err(FleetError::Memory(
                "support chunk ids must be between 1 and 256 bytes".into(),
            ));
        }

        let sentinel_limit = limit
            .checked_add(1)
            .ok_or_else(|| FleetError::Memory("support claim limit overflow".into()))?;
        let mut claim_ids = sqlx::query_scalar::<_, i64>(SUPPORTED_CLAIM_IDS_SQL)
            .bind(scope.tenant_id)
            .bind(&scope.project)
            .bind(chunk_ids)
            .bind(
                i64::try_from(sentinel_limit)
                    .map_err(|_| FleetError::Memory("support claim limit exceeds INT8".into()))?,
            )
            .fetch_all(&self.pool)
            .await?;
        let truncated = claim_ids.len() > limit;
        claim_ids.truncate(limit);
        Ok(SupportedClaimIds {
            claim_ids,
            truncated,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ConflictObservation {
    id: i64,
    opened: bool,
}

#[derive(Debug, Clone, PartialEq)]
struct ClaimCandidate {
    claim_id: i64,
    similarity: f64,
    passage_index: i32,
    matched_passage: String,
}

fn deduplicate_claim_candidates(candidates: Vec<ClaimCandidate>) -> Vec<ClaimCandidate> {
    let mut seen = HashSet::with_capacity(candidates.len());
    candidates
        .into_iter()
        .filter(|candidate| seen.insert(candidate.claim_id))
        .collect()
}

async fn observe_conflict(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    scope: &FleetScope,
    claim_key: &str,
) -> Result<ConflictObservation> {
    let inserted = sqlx::query_scalar::<_, i64>(
        "INSERT INTO memory_conflicts (tenant_id, project, claim_key, rationale) \
         VALUES ($1, $2, $3, $4) \
         ON CONFLICT (tenant_id, project, claim_key) DO NOTHING \
         RETURNING id",
    )
    .bind(scope.tenant_id)
    .bind(&scope.project)
    .bind(claim_key)
    .bind(CONFLICT_RATIONALE)
    .fetch_optional(&mut **transaction)
    .await?;
    if let Some(id) = inserted {
        return Ok(ConflictObservation { id, opened: true });
    }

    let row = sqlx::query(
        "SELECT id, state FROM memory_conflicts \
         WHERE tenant_id = $1 AND project = $2 AND claim_key = $3",
    )
    .bind(scope.tenant_id)
    .bind(&scope.project)
    .bind(claim_key)
    .fetch_one(&mut **transaction)
    .await?;
    let id: i64 = row.try_get("id")?;
    let state: String = row.try_get("state")?;
    match state.as_str() {
        "open" => {
            let update = sqlx::query(
                "UPDATE memory_conflicts SET last_seen_at = now() \
                 WHERE tenant_id = $1 AND project = $2 AND id = $3 AND state = 'open'",
            )
            .bind(scope.tenant_id)
            .bind(&scope.project)
            .bind(id)
            .execute(&mut **transaction)
            .await?;
            if update.rows_affected() != 1 {
                return Err(protocol_error(
                    "open conflict changed state during serializable observation",
                ));
            }
            Ok(ConflictObservation { id, opened: false })
        }
        "resolved" | "dismissed" => {
            let reopened = sqlx::query_scalar::<_, i64>(
                "UPDATE memory_conflicts SET \
                     state = 'open', rationale = $4, last_seen_at = now(), \
                     resolved_at = NULL, resolution_kind = NULL, resolution_reason = NULL, \
                     revision = revision + 1 \
                 WHERE tenant_id = $1 AND project = $2 AND id = $3 AND state = $5 \
                 RETURNING id",
            )
            .bind(scope.tenant_id)
            .bind(&scope.project)
            .bind(id)
            .bind(CONFLICT_RATIONALE)
            .bind(&state)
            .fetch_optional(&mut **transaction)
            .await?;
            let id = reopened.ok_or_else(|| {
                protocol_error("conflict changed state during serializable reopen")
            })?;
            Ok(ConflictObservation { id, opened: true })
        }
        other => Err(protocol_error(format!(
            "database returned unknown conflict state {other:?}"
        ))),
    }
}

async fn insert_disputed_transition_event(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    scope: &FleetScope,
    claim_id: i64,
    conflict_id: i64,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO memory_claim_events (\
             tenant_id, project, claim_id, event_kind, actor, reason, \
             from_state, to_state, payload\
         ) VALUES ($1, $2, $3, 'state_transition', $4, 'conflict_detected', \
             'active', 'disputed', $5)",
    )
    .bind(scope.tenant_id)
    .bind(&scope.project)
    .bind(claim_id)
    .bind(&scope.agent)
    .bind(serde_json::json!({ "conflict_id": conflict_id }))
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn hydrate_conflicts(
    pool: &PgPool,
    scope: &FleetScope,
    rows: Vec<PgRow>,
) -> Result<Vec<Conflict>> {
    if rows.is_empty() {
        return Ok(Vec::new());
    }

    let conflict_ids = rows
        .iter()
        .map(|row| row.try_get::<i64, _>("id"))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let member_rows = sqlx::query(
        "SELECT conflict_id, claim_id, member_count FROM (\
             SELECT conflict_id, claim_id, \
                    count(*) OVER (PARTITION BY conflict_id)::INT8 AS member_count, \
                    row_number() OVER (PARTITION BY conflict_id ORDER BY claim_id) AS member_rank \
             FROM memory_conflict_members@{NO_FULL_SCAN} \
             WHERE tenant_id = $1 AND project = $2 AND conflict_id = ANY($3)\
         ) AS ranked \
         WHERE member_rank <= $4 \
         ORDER BY conflict_id, claim_id",
    )
    .bind(scope.tenant_id)
    .bind(&scope.project)
    .bind(&conflict_ids)
    .bind(
        i64::try_from(MAX_MEMBERS_PER_CONFLICT)
            .map_err(|_| protocol_error("conflict member response limit is outside INT8 range"))?,
    )
    .fetch_all(pool)
    .await?;

    let mut member_counts = HashMap::with_capacity(conflict_ids.len());
    let mut member_ids_by_conflict: HashMap<i64, Vec<i64>> =
        HashMap::with_capacity(conflict_ids.len());
    let mut selected_claim_ids = HashSet::new();
    for row in member_rows {
        let conflict_id: i64 = row.try_get("conflict_id")?;
        let claim_id: i64 = row.try_get("claim_id")?;
        let member_count: i64 = row.try_get("member_count")?;
        let member_count = usize::try_from(member_count)
            .map_err(|_| protocol_error("conflict member count is outside usize range"))?;
        member_counts.insert(conflict_id, member_count);
        member_ids_by_conflict
            .entry(conflict_id)
            .or_default()
            .push(claim_id);
        selected_claim_ids.insert(claim_id);
    }

    let selected_claim_ids = selected_claim_ids.into_iter().collect::<Vec<_>>();
    let claim_summaries = fetch_conflict_claim_summaries(pool, scope, &selected_claim_ids).await?;
    let mut conflicts = Vec::with_capacity(rows.len());
    for row in rows {
        let id: i64 = row.try_get("id")?;
        let member_count = member_counts.get(&id).copied().unwrap_or_default();
        let member_ids = member_ids_by_conflict.remove(&id).unwrap_or_default();
        let mut members = Vec::with_capacity(member_ids.len());
        let mut member_values_elided = false;
        for claim_id in member_ids {
            if let Some(claim) = claim_summaries.claims.get(&claim_id).cloned() {
                member_values_elided |= claim_summaries.values_elided.contains(&claim_id);
                members.push(claim);
            }
        }
        let members_truncated = members.len() < member_count;
        conflicts.push(decode_conflict(
            &row,
            members,
            member_count,
            members_truncated,
            member_values_elided,
        )?);
    }
    Ok(conflicts)
}

/// Hydrate the bounded semantic-search projection. Values and support are not
/// read because the public search projection always removes both fields.
async fn fetch_search_claims(
    pool: &PgPool,
    scope: &FleetScope,
    claim_ids: &[i64],
) -> Result<HashMap<i64, Claim>> {
    if claim_ids.is_empty() {
        return Ok(HashMap::new());
    }

    let claim_rows = sqlx::query(SEARCH_CLAIM_PROJECTION_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(claim_ids)
        .bind(
            i64::try_from(MAX_CLAIM_SEARCH_TEXT_CHARS + 1)
                .map_err(|_| protocol_error("claim search projection limit exceeds INT8"))?,
        )
        .fetch_all(pool)
        .await?;
    let mut claims = claim_rows
        .iter()
        .map(decode_claim)
        .map(|result| {
            result.map(|mut claim| {
                claim.text = compact_text(&claim.text, MAX_CLAIM_SEARCH_TEXT_CHARS);
                claim
            })
        })
        .map(|result| result.map(|claim| (claim.id, claim)))
        .collect::<Result<HashMap<_, _>>>()?;

    hydrate_claim_conflict_ids(pool, scope, claim_ids, &mut claims).await?;
    Ok(claims)
}

struct ConflictClaimSummaries {
    claims: HashMap<i64, Claim>,
    values_elided: HashSet<i64>,
}

/// Hydrate only the fields exposed by conflict summaries. SQL truncates text
/// and conditionally projects JSON before either can cross the network; support
/// evidence remains available through the explicit claim lookup only.
async fn fetch_conflict_claim_summaries(
    pool: &PgPool,
    scope: &FleetScope,
    claim_ids: &[i64],
) -> Result<ConflictClaimSummaries> {
    if claim_ids.is_empty() {
        return Ok(ConflictClaimSummaries {
            claims: HashMap::new(),
            values_elided: HashSet::new(),
        });
    }

    let claim_rows = sqlx::query(CONFLICT_CLAIM_PROJECTION_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(claim_ids)
        .bind(
            i64::try_from(MAX_CONFLICT_MEMBER_TEXT_CHARS + 1)
                .map_err(|_| protocol_error("conflict text projection limit exceeds INT8"))?,
        )
        .bind(
            i64::try_from(MAX_CONFLICT_MEMBER_VALUE_BYTES)
                .map_err(|_| protocol_error("conflict value projection limit exceeds INT8"))?,
        )
        .fetch_all(pool)
        .await?;
    let mut values_elided = HashSet::new();
    let mut claims = HashMap::with_capacity(claim_rows.len());
    for row in &claim_rows {
        let mut claim = decode_claim(row)?;
        claim.text = compact_text(&claim.text, MAX_CONFLICT_MEMBER_TEXT_CHARS);
        if row.try_get::<bool, _>("value_elided")? {
            values_elided.insert(claim.id);
        }
        claims.insert(claim.id, claim);
    }

    hydrate_claim_conflict_ids(pool, scope, claim_ids, &mut claims).await?;
    Ok(ConflictClaimSummaries {
        claims,
        values_elided,
    })
}

async fn hydrate_claim_conflict_ids(
    pool: &PgPool,
    scope: &FleetScope,
    claim_ids: &[i64],
    claims: &mut HashMap<i64, Claim>,
) -> Result<()> {
    let conflict_rows = sqlx::query(CLAIM_CONFLICT_IDS_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(claim_ids)
        .fetch_all(pool)
        .await?;
    for row in conflict_rows {
        let claim_id: i64 = row.try_get("claim_id")?;
        if let Some(claim) = claims.get_mut(&claim_id) {
            claim.conflict_ids.push(row.try_get("conflict_id")?);
        }
    }
    Ok(())
}

fn compact_text(text: &str, max_chars: usize) -> String {
    let mut chars = text.chars();
    let compact = chars.by_ref().take(max_chars).collect::<String>();
    if chars.next().is_some() {
        format!("{compact}…")
    } else {
        compact
    }
}

async fn replayed_record(
    pool: &PgPool,
    scope: &FleetScope,
    idempotency_key: &str,
    request: &Value,
) -> Result<Option<ClaimMutation>> {
    let row = sqlx::query(
        "SELECT project, operation, request, response \
         FROM memory_mutation_receipts \
         WHERE tenant_id = $1 AND idempotency_key = $2",
    )
    .bind(scope.tenant_id)
    .bind(idempotency_key)
    .fetch_optional(pool)
    .await?;
    row.as_ref()
        .map(|row| decode_record_receipt(row, scope, request))
        .transpose()
}

fn decode_record_receipt(
    row: &PgRow,
    scope: &FleetScope,
    request: &Value,
) -> Result<ClaimMutation> {
    let receipt_project: String = row.try_get("project")?;
    let operation: String = row.try_get("operation")?;
    let original_request: Value = row.try_get("request")?;
    if receipt_project != scope.project || operation != "record" || original_request != *request {
        return Err(FleetError::IdempotencyConflict(
            "idempotency key was already used for a different mutation".into(),
        ));
    }
    let response: Option<Value> = row.try_get("response")?;
    let mut mutation: ClaimMutation = serde_json::from_value(response.ok_or_else(|| {
        FleetError::Memory("committed idempotency receipt has no response".into())
    })?)
    .map_err(|error| FleetError::Memory(format!("decode idempotency receipt: {error}")))?;
    mutation.idempotent_replay = true;
    Ok(mutation)
}

async fn insert_claim(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    scope: &FleetScope,
    input: &ClaimInput,
    prepared: &crate::ledger::types::PreparedClaim,
) -> Result<Claim> {
    let row = sqlx::query(
        "INSERT INTO memory_claims (\
             tenant_id, project, kind, claim_key, subject, predicate, value, text, polarity, \
             state, origin, actor, confidence, valid_from, valid_to, conflict_eligible\
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'active', $10, $11, $12, $13, $14, $15) \
         RETURNING id, project, kind, claim_key, subject, predicate, value, text, polarity, \
                   state, origin, actor, confidence, valid_from, valid_to, superseded_by, \
                   revision, conflict_eligible, created_at, updated_at",
    )
    .bind(scope.tenant_id)
    .bind(&scope.project)
    .bind(input.kind.as_str())
    .bind(&prepared.claim_key)
    .bind(&prepared.subject)
    .bind(&prepared.predicate)
    .bind(&prepared.value)
    .bind(input.text.trim())
    .bind(input.polarity)
    .bind(input.origin.trim())
    .bind(&scope.agent)
    .bind(input.confidence)
    .bind(input.valid_from)
    .bind(input.valid_to)
    .bind(prepared.conflict_eligible)
    .fetch_one(&mut **transaction)
    .await?;
    decode_claim(&row)
}

async fn insert_support(
    transaction: &mut Transaction<'_, sqlx::Postgres>,
    scope: &FleetScope,
    claim_id: i64,
    input: &ClaimInput,
) -> Result<Vec<ClaimSupport>> {
    let mut support_rows = Vec::with_capacity(input.support.len());
    for support in &input.support {
        if support.source.trim().is_empty() || support.source_id.trim().is_empty() {
            return Err(protocol_error(
                "claim support source and source_id must not be empty",
            ));
        }
        if let Some(chunk_id) = support.chunk_id.as_deref() {
            let exact_match: bool = sqlx::query_scalar(SUPPORT_CHUNK_MATCH_SQL)
                .bind(scope.tenant_id)
                .bind(&scope.project)
                .bind(chunk_id)
                .bind(&support.source_config_id)
                .bind(&support.source)
                .bind(&support.source_id)
                .bind(&support.content_sha256)
                .fetch_one(&mut **transaction)
                .await?;
            if !exact_match {
                return Err(protocol_error(
                    "claim support chunk does not match an active tenant/project corpus coordinate",
                ));
            }
        }
        let row = sqlx::query(
            "INSERT INTO memory_claim_support (\
                 tenant_id, project, claim_id, source_config_id, source, source_id, chunk_id, \
                 content_sha256, excerpt, relation\
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
             RETURNING id, source_config_id, source, source_id, chunk_id, content_sha256, \
                       excerpt, relation, state, observed_at, invalidated_at",
        )
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(claim_id)
        .bind(&support.source_config_id)
        .bind(&support.source)
        .bind(&support.source_id)
        .bind(&support.chunk_id)
        .bind(&support.content_sha256)
        .bind(&support.excerpt)
        .bind(&support.relation)
        .fetch_one(&mut **transaction)
        .await?;
        support_rows.push(decode_support(&row)?);
    }
    Ok(support_rows)
}

async fn fetch_claim(pool: &PgPool, scope: &FleetScope, id: i64) -> Result<Option<Claim>> {
    let Some(row) = sqlx::query(
        "SELECT id, project, kind, claim_key, subject, predicate, value, text, polarity, state, \
                origin, actor, confidence, valid_from, valid_to, superseded_by, revision, \
                conflict_eligible, created_at, updated_at \
         FROM memory_claims WHERE tenant_id = $1 AND project = $2 AND id = $3",
    )
    .bind(scope.tenant_id)
    .bind(&scope.project)
    .bind(id)
    .fetch_optional(pool)
    .await?
    else {
        return Ok(None);
    };
    let mut claim = decode_claim(&row)?;
    claim.support = sqlx::query(
        "SELECT id, source_config_id, source, source_id, chunk_id, content_sha256, excerpt, \
                relation, state, observed_at, invalidated_at \
         FROM memory_claim_support \
         WHERE tenant_id = $1 AND project = $2 AND claim_id = $3 \
         ORDER BY observed_at, id",
    )
    .bind(scope.tenant_id)
    .bind(&scope.project)
    .bind(id)
    .fetch_all(pool)
    .await?
    .iter()
    .map(decode_support)
    .collect::<std::result::Result<Vec<_>, _>>()?;
    claim.conflict_ids = sqlx::query_scalar(
        "SELECT conflict_id FROM memory_conflict_members@{NO_FULL_SCAN} \
         WHERE tenant_id = $1 AND project = $2 AND claim_id = $3 ORDER BY conflict_id",
    )
    .bind(scope.tenant_id)
    .bind(&scope.project)
    .bind(id)
    .fetch_all(pool)
    .await?;
    Ok(Some(claim))
}

fn decode_claim(row: &PgRow) -> Result<Claim> {
    let kind: String = row.try_get("kind")?;
    let state: String = row.try_get("state")?;
    Ok(Claim {
        id: row.try_get("id")?,
        project: row.try_get("project")?,
        kind: parse_claim_kind(&kind)?,
        claim_key: row.try_get("claim_key")?,
        subject: row.try_get("subject")?,
        predicate: row.try_get("predicate")?,
        value: row.try_get("value")?,
        text: row.try_get("text")?,
        polarity: row.try_get("polarity")?,
        state: parse_claim_state(&state)?,
        origin: row.try_get("origin")?,
        actor: row.try_get("actor")?,
        confidence: row.try_get("confidence")?,
        valid_from: row.try_get("valid_from")?,
        valid_to: row.try_get("valid_to")?,
        superseded_by: row.try_get("superseded_by")?,
        revision: row.try_get("revision")?,
        conflict_eligible: row.try_get("conflict_eligible")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        support: Vec::new(),
        conflict_ids: Vec::new(),
    })
}

fn decode_support(row: &PgRow) -> Result<ClaimSupport> {
    Ok(ClaimSupport {
        id: row.try_get("id")?,
        source_config_id: row.try_get("source_config_id")?,
        source: row.try_get("source")?,
        source_id: row.try_get("source_id")?,
        chunk_id: row.try_get("chunk_id")?,
        content_sha256: row.try_get("content_sha256")?,
        excerpt: row.try_get("excerpt")?,
        relation: row.try_get("relation")?,
        state: row.try_get("state")?,
        observed_at: row.try_get("observed_at")?,
        invalidated_at: row.try_get("invalidated_at")?,
    })
}

fn decode_conflict(
    row: &PgRow,
    members: Vec<Claim>,
    member_count: usize,
    members_truncated: bool,
    member_values_elided: bool,
) -> Result<Conflict> {
    Ok(Conflict {
        id: row.try_get("id")?,
        project: row.try_get("project")?,
        claim_key: row.try_get("claim_key")?,
        kind: row.try_get("kind")?,
        state: row.try_get("state")?,
        detector: row.try_get("detector")?,
        rationale: row.try_get("rationale")?,
        revision: row.try_get("revision")?,
        detected_at: row.try_get("detected_at")?,
        last_seen_at: row.try_get("last_seen_at")?,
        resolved_at: row.try_get("resolved_at")?,
        resolution_kind: row.try_get("resolution_kind")?,
        resolution_reason: row.try_get("resolution_reason")?,
        member_count,
        members_truncated,
        member_values_elided,
        members,
    })
}

fn parse_claim_kind(value: &str) -> Result<ClaimKind> {
    match value {
        "observation" => Ok(ClaimKind::Observation),
        "note" => Ok(ClaimKind::Note),
        "decision" => Ok(ClaimKind::Decision),
        "fact" => Ok(ClaimKind::Fact),
        "constraint" => Ok(ClaimKind::Constraint),
        "preference" => Ok(ClaimKind::Preference),
        "procedure" => Ok(ClaimKind::Procedure),
        "open_question" => Ok(ClaimKind::OpenQuestion),
        other => Err(protocol_error(format!(
            "database returned unknown claim kind {other:?}"
        ))),
    }
}

fn parse_claim_state(value: &str) -> Result<ClaimState> {
    match value {
        "active" => Ok(ClaimState::Active),
        "disputed" => Ok(ClaimState::Disputed),
        "unsupported" => Ok(ClaimState::Unsupported),
        "superseded" => Ok(ClaimState::Superseded),
        "retracted" => Ok(ClaimState::Retracted),
        "suppressed" => Ok(ClaimState::Suppressed),
        "expired" => Ok(ClaimState::Expired),
        other => Err(protocol_error(format!(
            "database returned unknown claim state {other:?}"
        ))),
    }
}

fn protocol_error(message: impl Into<String>) -> FleetError {
    FleetError::Memory(message.into())
}

fn validate_result_limit(limit: usize) -> Result<()> {
    if limit == 0 || limit > MAX_LEDGER_RESULTS {
        return Err(FleetError::Memory(format!(
            "ledger result limit must be between 1 and {MAX_LEDGER_RESULTS}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ostk_recall_core::{FacetSet, Links, PrivacyTier, Source};
    use uuid::Uuid;

    use crate::store::cockroach::ScopedChunk;

    struct TestEmbedder;

    impl ChunkEmbedder for TestEmbedder {
        fn dim(&self) -> usize {
            EMBEDDING_DIMENSION
        }

        fn model_id(&self) -> &'static str {
            "fleet-test-512"
        }

        fn encode_batch(&self, texts: &[&str]) -> Vec<Vec<f32>> {
            texts
                .iter()
                .map(|text| {
                    let mut vector = vec![0.0; EMBEDDING_DIMENSION];
                    vector[text.len() % EMBEDDING_DIMENSION] = 1.0;
                    vector
                })
                .collect()
        }
    }

    fn scope(project: &str) -> FleetScope {
        FleetScope::new(
            Uuid::parse_str("0198a849-f6ae-7d61-9800-000000000001").unwrap(),
            project,
            "agent",
            None,
            PrivacyTier::T1Project,
        )
        .unwrap()
    }

    async fn transition_event_count(pool: &PgPool, scope: &FleetScope, claim_id: i64) -> i64 {
        sqlx::query_scalar(
            "SELECT count(*)::INT8 FROM memory_claim_events \
             WHERE tenant_id = $1 AND project = $2 AND claim_id = $3 \
               AND event_kind = 'state_transition' \
               AND from_state = 'active' AND to_state = 'disputed'",
        )
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(claim_id)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn constructor_rejects_wrong_embedding_dimension() {
        struct WrongDimension;
        impl ChunkEmbedder for WrongDimension {
            fn dim(&self) -> usize {
                3
            }

            fn encode_batch(&self, texts: &[&str]) -> Vec<Vec<f32>> {
                texts.iter().map(|_| vec![0.0; 3]).collect()
            }
        }

        let pool = PgPool::connect_lazy("postgresql://root@localhost:26257/defaultdb").unwrap();
        let result = CockroachClaimLedger::new(
            pool,
            scope("fleet"),
            Arc::new(WrongDimension),
            RetryPolicy::default(),
        );
        assert!(matches!(result, Err(FleetError::Configuration(_))));
    }

    #[tokio::test]
    async fn repository_scope_is_tenant_project_bound() {
        let pool = PgPool::connect_lazy("postgresql://root@localhost:26257/defaultdb").unwrap();
        let trusted = scope("fleet");
        let ledger = CockroachClaimLedger::new(
            pool,
            trusted.clone(),
            Arc::new(TestEmbedder),
            RetryPolicy::default(),
        )
        .unwrap();
        assert!(ledger.ensure_scope(&trusted).is_ok());
        assert!(matches!(
            ledger.ensure_scope(&scope("other")),
            Err(FleetError::InvalidScope(_))
        ));

        let alternate_session = FleetScope::new(
            trusted.tenant_id,
            trusted.project.clone(),
            trusted.agent.clone(),
            Some("turn-17".into()),
            trusted.privacy_tier,
        )
        .unwrap();
        assert!(ledger.ensure_scope(&alternate_session).is_ok());

        let different_agent = FleetScope::new(
            trusted.tenant_id,
            trusted.project.clone(),
            "untrusted-agent",
            None,
            trusted.privacy_tier,
        )
        .unwrap();
        assert!(matches!(
            ledger.ensure_scope(&different_agent),
            Err(FleetError::InvalidScope(_))
        ));

        let different_privacy = FleetScope::new(
            trusted.tenant_id,
            trusted.project,
            trusted.agent,
            None,
            PrivacyTier::T2Trusted,
        )
        .unwrap();
        assert!(matches!(
            ledger.ensure_scope(&different_privacy),
            Err(FleetError::InvalidScope(_))
        ));
    }

    #[test]
    fn result_limits_are_bounded() {
        assert!(validate_result_limit(1).is_ok());
        assert!(validate_result_limit(MAX_LEDGER_RESULTS).is_ok());
        assert!(validate_result_limit(0).is_err());
        assert!(validate_result_limit(MAX_LEDGER_RESULTS + 1).is_err());
    }

    #[test]
    fn claim_candidates_keep_first_ann_passage_and_order() {
        let candidate = |claim_id, passage_index, matched_passage: &str| ClaimCandidate {
            claim_id,
            similarity: 1.0 - f64::from(passage_index) / 10.0,
            passage_index,
            matched_passage: matched_passage.into(),
        };
        let candidates = deduplicate_claim_candidates(vec![
            candidate(7, 2, "nearest passage for seven"),
            candidate(3, 0, "nearest passage for three"),
            candidate(7, 5, "later passage for seven"),
            candidate(11, 1, "nearest passage for eleven"),
        ]);

        assert_eq!(
            candidates
                .iter()
                .map(|candidate| candidate.claim_id)
                .collect::<Vec<_>>(),
            [7, 3, 11]
        );
        assert_eq!(candidates[0].passage_index, 2);
        assert_eq!(candidates[0].matched_passage, "nearest passage for seven");
    }

    #[test]
    fn list_and_search_queries_bound_discarded_fields_before_transfer() {
        assert!(CLAIM_ANN_SEARCH_SQL.contains("left(passage_text, $6)"));
        assert!(CLAIM_ANN_SEARCH_SQL.contains("LIMIT $5"));

        assert!(SEARCH_CLAIM_PROJECTION_SQL.contains("NULL::JSONB AS value"));
        assert!(SEARCH_CLAIM_PROJECTION_SQL.contains("left(text, $4)"));
        assert!(!SEARCH_CLAIM_PROJECTION_SQL.contains("memory_claim_support"));
        assert!(!SEARCH_CLAIM_PROJECTION_SQL.contains("SELECT *"));

        assert!(CONFLICT_CLAIM_PROJECTION_SQL.contains("left(text, $4)"));
        assert!(CONFLICT_CLAIM_PROJECTION_SQL.contains("octet_length(value::STRING) > $5"));
        assert!(!CONFLICT_CLAIM_PROJECTION_SQL.contains("memory_claim_support"));
        assert!(!CONFLICT_CLAIM_PROJECTION_SQL.contains("SELECT *"));

        assert!(CLAIM_CONFLICT_IDS_SQL.contains("@{NO_FULL_SCAN}"));
        assert!(SUPPORTED_CLAIM_IDS_SQL.contains("memory_claim_support@{NO_FULL_SCAN}"));
        assert!(SUPPORTED_CLAIM_IDS_SQL.contains("chunk_id = ANY($3)"));
        assert!(SUPPORTED_CLAIM_IDS_SQL.contains("state = 'current'"));
        assert!(SUPPORTED_CLAIM_IDS_SQL.contains("LIMIT $4"));
        assert!(SUPPORT_CHUNK_MATCH_SQL.contains("memory_chunks@{NO_FULL_SCAN}"));
        assert!(SUPPORT_CHUNK_MATCH_SQL.contains("content_sha256 = $7"));
    }

    #[test]
    fn bounded_projection_compaction_is_unicode_safe_and_signals_elision() {
        let text = "🦀".repeat(MAX_CONFLICT_MEMBER_TEXT_CHARS + 1);
        let compact = compact_text(&text, MAX_CONFLICT_MEMBER_TEXT_CHARS);
        assert_eq!(compact.chars().count(), MAX_CONFLICT_MEMBER_TEXT_CHARS + 1);
        assert!(compact.ends_with('…'));
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)] // one live scenario proves the complete transaction lifecycle
    async fn live_claim_conflict_and_replay_when_configured() {
        let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
            return;
        };
        let scope = scope("live-ledger-test");
        let store = crate::store::cockroach::CockroachStore::connect(
            &database_url,
            scope.clone(),
            crate::store::cockroach::PoolConfig::default(),
        )
        .await
        .unwrap();
        store.migrate().await.unwrap();

        let uninitialized_project = format!("live-uninitialized-model-{}", Uuid::now_v7());
        let uninitialized_scope = FleetScope::new(
            scope.tenant_id,
            uninitialized_project,
            scope.agent.clone(),
            None,
            scope.privacy_tier,
        )
        .unwrap();
        let uninitialized_ledger = CockroachClaimLedger::new(
            store.pool().clone(),
            uninitialized_scope.clone(),
            Arc::new(TestEmbedder),
            RetryPolicy::default(),
        )
        .unwrap();
        let uninitialized_input = ClaimInput {
            kind: ClaimKind::Note,
            text: "Model registration belongs to deployment bootstrap".into(),
            subject: None,
            predicate: None,
            value: None,
            polarity: 1,
            origin: "operator_asserted".into(),
            actor: None,
            confidence: 1.0,
            valid_from: None,
            valid_to: None,
            support: Vec::new(),
        };
        let uninitialized_key = format!("live-ledger/uninitialized-model/{}", Uuid::now_v7());
        let uninitialized_error = uninitialized_ledger
            .record_claim(
                &uninitialized_scope,
                &uninitialized_input,
                &uninitialized_key,
            )
            .await
            .expect_err("remember must not initialize the project model registry");
        assert!(
            uninitialized_error
                .to_string()
                .contains("active embedding generation is not initialized")
        );
        assert!(
            crate::store::cockroach::active_embedding_model(store.pool(), &uninitialized_scope)
                .await
                .unwrap()
                .is_none()
        );
        let uninitialized_receipts: i64 = sqlx::query_scalar(
            "SELECT count(*)::INT8 FROM memory_mutation_receipts \
             WHERE tenant_id = $1 AND idempotency_key = $2",
        )
        .bind(uninitialized_scope.tenant_id)
        .bind(&uninitialized_key)
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(uninitialized_receipts, 0);

        store
            .initialize_embedding_model(TestEmbedder.model_id())
            .await
            .unwrap();
        let reverse_membership_index: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM [SHOW INDEXES FROM memory_conflict_members] \
             WHERE index_name = 'memory_conflict_members_claim_idx')",
        )
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert!(reverse_membership_index);
        sqlx::query("DELETE FROM memory_mutation_receipts WHERE tenant_id = $1")
            .bind(scope.tenant_id)
            .execute(store.pool())
            .await
            .unwrap();
        sqlx::query("DELETE FROM memory_events WHERE tenant_id = $1 AND project = $2")
            .bind(scope.tenant_id)
            .bind(&scope.project)
            .execute(store.pool())
            .await
            .unwrap();
        sqlx::query("DELETE FROM memory_conflicts WHERE tenant_id = $1 AND project = $2")
            .bind(scope.tenant_id)
            .bind(&scope.project)
            .execute(store.pool())
            .await
            .unwrap();
        sqlx::query("DELETE FROM memory_claims WHERE tenant_id = $1 AND project = $2")
            .bind(scope.tenant_id)
            .bind(&scope.project)
            .execute(store.pool())
            .await
            .unwrap();

        let ledger = CockroachClaimLedger::new(
            store.pool().clone(),
            scope.clone(),
            Arc::new(TestEmbedder),
            RetryPolicy::default(),
        )
        .unwrap();
        let support_text = "The implementation requires one migration owner before workers start.";
        let support_chunk_id = format!("live-support-{}", Uuid::now_v7());
        let support_sha256 = Chunk::content_hash(support_text);
        let support_chunk = Chunk {
            chunk_id: support_chunk_id.clone(),
            source: Source::Markdown,
            project: Some(scope.project.clone()),
            source_id: "docs/live-migration.md".into(),
            source_config_id: "live-docs-v1".into(),
            chunk_index: 0,
            ts: None,
            role: Some("primary".into()),
            text: support_text.into(),
            sha256: support_sha256.clone(),
            links: Links::default(),
            facets: FacetSet::new(),
            embedding_input_sha256: "live-support-embedding".into(),
            extra: Value::Null,
        };
        store
            .upsert_chunk(&ScopedChunk {
                scope: scope.clone(),
                chunk: support_chunk,
                embedding_model: TestEmbedder.model_id().into(),
                embedding: TestEmbedder
                    .encode_batch(&[support_text])
                    .into_iter()
                    .next()
                    .unwrap(),
                stale: false,
            })
            .await
            .unwrap();
        let first = ClaimInput {
            kind: ClaimKind::Decision,
            text: "Use CockroachDB for shared fleet memory".into(),
            subject: Some("fleet-store".into()),
            predicate: Some("database-choice".into()),
            value: Some(Value::String("cockroachdb".into())),
            polarity: 1,
            origin: "operator_asserted".into(),
            actor: None,
            confidence: 1.0,
            valid_from: None,
            valid_to: None,
            support: vec![crate::ledger::ClaimSupportInput {
                source_config_id: "live-docs-v1".into(),
                source: "markdown".into(),
                source_id: "docs/live-migration.md".into(),
                chunk_id: Some(support_chunk_id.clone()),
                content_sha256: Some(support_sha256.clone()),
                excerpt: Some(support_text.into()),
                relation: "supports".into(),
            }],
        };
        let mut mismatched_support = first.clone();
        mismatched_support.support[0].content_sha256 = Some("0".repeat(64));
        let mismatch_key = format!("live-ledger/mismatched-support/{}", Uuid::now_v7());
        let mismatch_error = ledger
            .record_claim(&scope, &mismatched_support, &mismatch_key)
            .await
            .expect_err("a dangling or stale local support coordinate must fail closed");
        assert!(
            mismatch_error
                .to_string()
                .contains("does not match an active tenant/project corpus coordinate")
        );
        let mismatch_receipts: i64 = sqlx::query_scalar(
            "SELECT count(*)::INT8 FROM memory_mutation_receipts \
             WHERE tenant_id = $1 AND idempotency_key = $2",
        )
        .bind(scope.tenant_id)
        .bind(&mismatch_key)
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(mismatch_receipts, 0);
        let recorded = ledger
            .record_claim(&scope, &first, "live-ledger/first")
            .await
            .unwrap();
        assert!(!recorded.idempotent_replay);
        assert!(recorded.conflicts_opened.is_empty());
        let primary_passage = recorded
            .claim
            .embedding_passages()
            .into_iter()
            .next()
            .unwrap();
        let expected_embedding_hash =
            Chunk::embedding_input_hash(&ledger.claim_model, "", &primary_passage);
        let projected_embedding_hash: String = sqlx::query_scalar(
            "SELECT embedding_input_sha256 FROM memory_chunks \
             WHERE tenant_id = $1 AND project = $2 AND chunk_id = $3",
        )
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(format!("claim:{}", recorded.claim.id))
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(projected_embedding_hash, expected_embedding_hash);
        let replay = ledger
            .record_claim(&scope, &first, "live-ledger/first")
            .await
            .unwrap();
        assert!(replay.idempotent_replay);
        assert_eq!(replay.claim.id, recorded.claim.id);

        let second = ClaimInput {
            text: "Use a single-node database for shared fleet memory".into(),
            value: Some(Value::String("sqlite".into())),
            ..first
        };
        let disputed = ledger
            .record_claim(&scope, &second, "live-ledger/second")
            .await
            .unwrap();
        assert_eq!(disputed.claim.state, ClaimState::Disputed);
        assert_eq!(disputed.conflicts_opened.len(), 1);
        let original = ledger
            .get_claim(&scope, recorded.claim.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(original.state, ClaimState::Disputed);
        let conflicts = ledger.list_conflicts(&scope, false, 10).await.unwrap();
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].members.len(), 2);
        assert_eq!(conflicts[0].member_count, 2);
        assert!(!conflicts[0].members_truncated);
        assert!(!conflicts[0].member_values_elided);
        let supported = ledger
            .supported_claim_ids_for_chunk_ids(&scope, std::slice::from_ref(&support_chunk_id), 10)
            .await
            .unwrap();
        assert!(!supported.truncated);
        assert_eq!(
            supported.claim_ids.iter().copied().collect::<HashSet<_>>(),
            [recorded.claim.id, disputed.claim.id]
                .into_iter()
                .collect::<HashSet<_>>()
        );
        let support_conflicts = ledger
            .conflicts_for_claim_ids(&scope, &supported.claim_ids, 10)
            .await
            .unwrap();
        assert_eq!(support_conflicts.len(), 1);
        assert_eq!(support_conflicts[0].id, conflicts[0].id);
        let bounded_supported = ledger
            .supported_claim_ids_for_chunk_ids(&scope, &[support_chunk_id], 1)
            .await
            .unwrap();
        assert_eq!(bounded_supported.claim_ids.len(), 1);
        assert!(bounded_supported.truncated);
        let semantic_hits = ledger
            .search_claims(&scope, &primary_passage, false, 10)
            .await
            .unwrap();
        assert!(
            semantic_hits
                .iter()
                .any(|hit| hit.claim.id == recorded.claim.id),
            "bulk ANN hydration must retain the nearest claim"
        );
        assert_eq!(
            semantic_hits
                .iter()
                .map(|hit| hit.claim.id)
                .collect::<HashSet<_>>()
                .len(),
            semantic_hits.len(),
            "one claim with multiple passages must appear only at its nearest ANN rank"
        );
        let conflict_id = conflicts[0].id;
        let conflict_revision = conflicts[0].revision;
        let original_revision = original.revision;
        let second_revision = disputed.claim.revision;
        assert_eq!(
            transition_event_count(store.pool(), &scope, original.id).await,
            1
        );
        assert_eq!(
            transition_event_count(store.pool(), &scope, disputed.claim.id).await,
            1
        );

        // Observing an already-open conflict adds the new member, but it does
        // not reopen the conflict or revise claims already disputed.
        let third = ClaimInput {
            text: "Use PostgreSQL for shared fleet memory".into(),
            value: Some(Value::String("postgresql".into())),
            ..second.clone()
        };
        let observed = ledger
            .record_claim(&scope, &third, "live-ledger/third")
            .await
            .unwrap();
        assert!(observed.conflicts_opened.is_empty());
        assert_eq!(observed.claim.state, ClaimState::Disputed);
        assert_eq!(observed.claim.revision, 2);
        let original_after_observation = ledger
            .get_claim(&scope, original.id)
            .await
            .unwrap()
            .unwrap();
        let second_after_observation = ledger
            .get_claim(&scope, disputed.claim.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(original_after_observation.revision, original_revision);
        assert_eq!(second_after_observation.revision, second_revision);
        let observed_conflict = ledger.list_conflicts(&scope, false, 10).await.unwrap();
        assert_eq!(observed_conflict[0].revision, conflict_revision);
        assert_eq!(observed_conflict[0].member_count, 3);
        assert_eq!(
            transition_event_count(store.pool(), &scope, original.id).await,
            1
        );
        assert_eq!(
            transition_event_count(store.pool(), &scope, observed.claim.id).await,
            1
        );

        // A resolved conflict is genuinely reopened by a later incompatible
        // claim, which advances only the conflict and the new active claim.
        sqlx::query(
            "UPDATE memory_conflicts SET state = 'resolved', revision = revision + 1, \
                 resolved_at = now(), resolution_kind = 'test_resolution', \
                 resolution_reason = 'exercise reopen semantics' \
             WHERE tenant_id = $1 AND project = $2 AND id = $3",
        )
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(conflict_id)
        .execute(store.pool())
        .await
        .unwrap();
        let fourth = ClaimInput {
            text: "Use FoundationDB for shared fleet memory".into(),
            value: Some(Value::String("foundationdb".into())),
            ..second.clone()
        };
        let reopened = ledger
            .record_claim(&scope, &fourth, "live-ledger/fourth")
            .await
            .unwrap();
        assert_eq!(reopened.conflicts_opened, vec![conflict_id]);
        assert_eq!(reopened.claim.revision, 2);
        let reopened_conflict = ledger.list_conflicts(&scope, false, 10).await.unwrap();
        assert_eq!(reopened_conflict[0].revision, conflict_revision + 2);
        assert_eq!(reopened_conflict[0].member_count, 4);
        assert_eq!(
            ledger
                .get_claim(&scope, original.id)
                .await
                .unwrap()
                .unwrap()
                .revision,
            original_revision
        );
        assert_eq!(
            transition_event_count(store.pool(), &scope, reopened.claim.id).await,
            1
        );

        // Conflict hydration advertises bounded membership honestly and
        // elides oversized canonical values from its summary projection.
        let large_value = serde_json::json!({ "payload": "x".repeat(3_000) });
        let extra_member_ids = sqlx::query_scalar::<_, i64>(
            "INSERT INTO memory_claims (\
                 tenant_id, project, kind, claim_key, value, text, state, origin, actor, \
                 conflict_eligible\
             ) SELECT $1, $2, 'fact', $3, $4, 'bulk conflict member ' || g::STRING, \
                      'disputed', 'operator_asserted', $5, true \
               FROM generate_series(1, 30) AS g \
             RETURNING id",
        )
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind("fleet-store::database-choice")
        .bind(&large_value)
        .bind(&scope.agent)
        .fetch_all(store.pool())
        .await
        .unwrap();
        for member_id in extra_member_ids {
            sqlx::query(
                "INSERT INTO memory_conflict_members (\
                     tenant_id, project, conflict_id, claim_id\
                 ) VALUES ($1, $2, $3, $4)",
            )
            .bind(scope.tenant_id)
            .bind(&scope.project)
            .bind(conflict_id)
            .bind(member_id)
            .execute(store.pool())
            .await
            .unwrap();
        }

        // Persist the largest legal claim/support payload shape (and an
        // intentionally oversized imported passage) to prove list/search SQL
        // projects before transfer. Explicit lookup remains the lossless path.
        let pathological_text = "t".repeat(100_000);
        let pathological_value = serde_json::json!("v".repeat(95_000));
        sqlx::query(
            "UPDATE memory_claims SET text = $4, value = $5 \
             WHERE tenant_id = $1 AND project = $2 AND id = $3",
        )
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(recorded.claim.id)
        .bind(&pathological_text)
        .bind(&pathological_value)
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query(
            "UPDATE memory_claim_embeddings SET passage_text = $4 \
             WHERE tenant_id = $1 AND project = $2 AND claim_id = $3",
        )
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(recorded.claim.id)
        .bind("p".repeat(100_000))
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO memory_claim_support (\
                 tenant_id, project, claim_id, source_config_id, source, source_id, chunk_id, \
                 excerpt, relation, state\
             ) SELECT $1, $2, $3, '', 'pathological-test', g::STRING, \
                      'pathological-' || g::STRING, $4, 'supports', 'current' \
               FROM generate_series(1, 32) AS g",
        )
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(recorded.claim.id)
        .bind("e".repeat(8_000))
        .execute(store.pool())
        .await
        .unwrap();

        let full_pathological_claim = ledger
            .get_claim(&scope, recorded.claim.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(full_pathological_claim.text, pathological_text);
        assert_eq!(full_pathological_claim.value, Some(pathological_value));
        assert_eq!(full_pathological_claim.support.len(), 32);

        let projected_hits = ledger
            .search_claims(&scope, &primary_passage, false, 10)
            .await
            .unwrap();
        let projected_hit = projected_hits
            .iter()
            .find(|hit| hit.claim.id == recorded.claim.id)
            .expect("the exact-vector pathological claim must remain in ANN order");
        assert_eq!(
            projected_hit.claim.text.chars().count(),
            MAX_CLAIM_SEARCH_TEXT_CHARS + 1
        );
        assert!(projected_hit.claim.text.ends_with('…'));
        assert!(projected_hit.claim.value.is_none());
        assert!(projected_hit.claim.support.is_empty());
        assert!(projected_hit.claim.conflict_ids.contains(&conflict_id));
        assert_eq!(
            projected_hit.matched_passage.chars().count(),
            MAX_CLAIM_SEARCH_PASSAGE_CHARS + 1
        );
        assert!(projected_hit.matched_passage.ends_with('…'));

        let bounded_conflicts = ledger.list_conflicts(&scope, false, 10).await.unwrap();
        assert_eq!(bounded_conflicts[0].member_count, 34);
        assert_eq!(bounded_conflicts[0].members.len(), MAX_MEMBERS_PER_CONFLICT);
        assert!(bounded_conflicts[0].members_truncated);
        assert!(bounded_conflicts[0].member_values_elided);
        assert!(
            bounded_conflicts[0]
                .members
                .windows(2)
                .all(|pair| pair[0].id < pair[1].id),
            "bulk hydration must preserve deterministic claim-id ordering"
        );
        assert!(
            bounded_conflicts[0]
                .members
                .iter()
                .all(|claim| claim.conflict_ids.contains(&conflict_id)),
            "bulk hydration must retain each member's conflict coordinates"
        );
        assert!(
            bounded_conflicts[0]
                .members
                .iter()
                .any(|claim| claim.value.is_none())
        );
        let projected_member = bounded_conflicts[0]
            .members
            .iter()
            .find(|claim| claim.id == recorded.claim.id)
            .expect("the first claim must remain in the bounded member window");
        assert_eq!(
            projected_member.text.chars().count(),
            MAX_CONFLICT_MEMBER_TEXT_CHARS + 1
        );
        assert!(projected_member.text.ends_with('…'));
        assert!(projected_member.value.is_none());
        assert!(projected_member.support.is_empty());
        assert!(projected_member.conflict_ids.contains(&conflict_id));

        // A caller-controlled hot key cannot turn one remember call into an
        // unbounded membership/event fan-out. The sentinel row causes the
        // complete serializable mutation (including its receipt and new claim)
        // to roll back.
        let bounded_claim_key = "bounded-conflict::choice";
        sqlx::query(
            "INSERT INTO memory_claims (\
                 tenant_id, project, kind, claim_key, value, text, state, origin, actor, \
                 conflict_eligible\
             ) SELECT $1, $2, 'fact', $3, $4, 'bounded existing claim ' || g::STRING, \
                      'active', 'operator_asserted', $5, true \
               FROM generate_series(1, $6) AS g",
        )
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(bounded_claim_key)
        .bind(serde_json::json!("existing"))
        .bind(&scope.agent)
        .bind(
            i64::try_from(MAX_INCOMPATIBLE_CLAIMS_PER_MUTATION + 1).expect("test bound fits INT8"),
        )
        .execute(store.pool())
        .await
        .unwrap();
        let bounded_count_before: i64 = sqlx::query_scalar(
            "SELECT count(*)::INT8 FROM memory_claims \
             WHERE tenant_id = $1 AND project = $2 AND claim_key = $3",
        )
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(bounded_claim_key)
        .fetch_one(store.pool())
        .await
        .unwrap();
        let bounded_input = ClaimInput {
            kind: ClaimKind::Fact,
            text: "A bounded conflict mutation must roll back".into(),
            subject: Some("bounded-conflict".into()),
            predicate: Some("choice".into()),
            value: Some(serde_json::json!("new")),
            polarity: 1,
            origin: "operator_asserted".into(),
            actor: None,
            confidence: 1.0,
            valid_from: None,
            valid_to: None,
            support: Vec::new(),
        };
        let bounded_error = ledger
            .record_claim(&scope, &bounded_input, "live-ledger/bounded-conflict")
            .await
            .expect_err("sentinel conflict member must abort the mutation");
        assert!(bounded_error.to_string().contains("bounded mutation limit"));
        let bounded_count_after: i64 = sqlx::query_scalar(
            "SELECT count(*)::INT8 FROM memory_claims \
             WHERE tenant_id = $1 AND project = $2 AND claim_key = $3",
        )
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(bounded_claim_key)
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(bounded_count_after, bounded_count_before);
        let bounded_receipts: i64 = sqlx::query_scalar(
            "SELECT count(*)::INT8 FROM memory_mutation_receipts \
             WHERE tenant_id = $1 AND idempotency_key = $2",
        )
        .bind(scope.tenant_id)
        .bind("live-ledger/bounded-conflict")
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(bounded_receipts, 0);
        let bounded_conflicts: i64 = sqlx::query_scalar(
            "SELECT count(*)::INT8 FROM memory_conflicts \
             WHERE tenant_id = $1 AND project = $2 AND claim_key = $3",
        )
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .bind(bounded_claim_key)
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(bounded_conflicts, 0);

        let concurrent_input = ClaimInput {
            kind: ClaimKind::Fact,
            text: "A concurrent replay creates one durable claim".into(),
            subject: Some("concurrent-replay".into()),
            predicate: Some("cardinality".into()),
            value: Some(serde_json::json!(1)),
            polarity: 1,
            origin: "operator_asserted".into(),
            actor: None,
            confidence: 1.0,
            valid_from: None,
            valid_to: None,
            support: Vec::new(),
        };
        let (left, right) = tokio::join!(
            ledger.record_claim(&scope, &concurrent_input, "live-ledger/concurrent-replay"),
            ledger.record_claim(&scope, &concurrent_input, "live-ledger/concurrent-replay")
        );
        let left = left.unwrap();
        let right = right.unwrap();
        assert_eq!(left.claim.id, right.claim.id);
        assert_ne!(left.idempotent_replay, right.idempotent_replay);

        let conflicting_left = ClaimInput {
            kind: ClaimKind::Decision,
            text: "Concurrent writer A chooses option A".into(),
            subject: Some("concurrent-writers".into()),
            predicate: Some("choice".into()),
            value: Some(serde_json::json!("a")),
            polarity: 1,
            origin: "operator_asserted".into(),
            actor: None,
            confidence: 1.0,
            valid_from: None,
            valid_to: None,
            support: Vec::new(),
        };
        let conflicting_right = ClaimInput {
            text: "Concurrent writer B chooses option B".into(),
            value: Some(serde_json::json!("b")),
            ..conflicting_left.clone()
        };
        let (left, right) = tokio::join!(
            ledger.record_claim(&scope, &conflicting_left, "live-ledger/concurrent-a"),
            ledger.record_claim(&scope, &conflicting_right, "live-ledger/concurrent-b")
        );
        let left = left.unwrap();
        let right = right.unwrap();
        let opened = left
            .conflicts_opened
            .iter()
            .chain(&right.conflicts_opened)
            .copied()
            .collect::<HashSet<_>>();
        assert_eq!(opened.len(), 1);
        let left = ledger
            .get_claim(&scope, left.claim.id)
            .await
            .unwrap()
            .unwrap();
        let right = ledger
            .get_claim(&scope, right.claim.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(left.state, ClaimState::Disputed);
        assert_eq!(right.state, ClaimState::Disputed);
    }
}
