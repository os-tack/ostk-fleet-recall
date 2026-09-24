//! Cockroach-backed implementation of the backend-neutral memory service.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use async_trait::async_trait;
use ostk_recall_core::{
    ChunkEmbedder, CorpusFilter, RankingOverrides, RecallHit, RecallIntent, RecallParams,
};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::ledger::{
    ClaimInput, ClaimLedger, ClaimMutation, ClaimState, ClaimTarget, Conflict, ConflictMutation,
    ConflictTarget, FUNCTIONAL_VALUE_CONFLICT_DETECTOR_V2, LifecycleMutation,
    LifecycleReplayRequest, MAX_CONCESSION_CLAIMS, MAX_CONFLICT_MEMBER_COUNT,
    MAX_OVERLAY_EPISODE_EVENTS, SemanticClaimHit, SupportedClaimCoordinate, derive_overlay,
    overlay_episode_revision, unlogged_transitions, validate_lifecycle_reason,
};
use crate::service::{
    ConflictCoverage, FleetMemoryService, RecallAction, RecallRequest, RecallResult, Refusal,
    RememberAction, RememberRequest, RememberResult, RememberSurface, ServiceError, ServiceResult,
    authorize_surface,
};
use crate::store::cockroach::{
    CockroachStore, RETRIEVAL_DENSE_MIN_COSINE_SIMILARITY, RetrievalHitMetadata,
    active_embedding_model,
};
use crate::{FleetError, FleetScope};

const MAX_TOOL_RESULTS: usize = 100;
const DEFAULT_TOOL_RESULTS: usize = 10;
// Chunk search passes this query to CockroachDB's `plainto_tsquery`; keep every
// token below the same conservative bound enforced for indexed corpus text.
const MAX_TSVECTOR_QUERY_LEXEME_BYTES: usize = 16_000;
const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
/// Source of the corpus projection record writes for every claim.
const SYNTHETIC_CLAIM_SOURCE: &str = "ostk_memory";

/// Which lifecycle behaviour a service instance serves. The default is the
/// historical record-only surface with unfiltered search, which the public
/// recall process always keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LifecycleServing {
    /// The `remember` actions served and advertised in `tools/list`.
    pub surface: RememberSurface,
    /// Drop synthetic `claim:{id}` chunk hits whose claim is no longer
    /// lifecycle-current from `recall(search, kind=chunk)`.
    pub hide_non_current_claim_chunks: bool,
    /// Attach the conflict lifecycle overlay (and, for `recall(get,
    /// kind=conflict)`, the lifecycle history) through a separate read after
    /// each main read. It needs the ledger's conflict lifecycle capability.
    pub lifecycle_overlay: bool,
}

/// Whether a response's conflicts carry the lifecycle overlay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OverlayOutcome {
    Evaluated,
    /// The overlay read failed; the main result is returned without it.
    Unavailable,
}

/// The executable service composition: shared hybrid corpus reads plus the
/// durable epistemic claim ledger, both bound to one deployment identity.
pub struct CockroachMemoryService {
    trusted_scope: FleetScope,
    corpus: Arc<CockroachStore>,
    ledger: Arc<dyn ClaimLedger>,
    embedder: Arc<dyn ChunkEmbedder>,
    lifecycle: LifecycleServing,
}

struct ChunkConflictProjection {
    conflicts: Vec<Conflict>,
    support_claim_count: usize,
    supporting_chunk_ids: Vec<String>,
    support_coordinates: Vec<SupportedClaimCoordinate>,
    support_claims_truncated: bool,
    support_coordinates_truncated: bool,
}

fn merge_supported_claim_ids(direct: &mut Vec<i64>, supported: Vec<i64>) -> bool {
    let mut truncated = false;
    for claim_id in supported {
        if direct.binary_search(&claim_id).is_ok() {
            continue;
        }
        if direct.len() == MAX_TOOL_RESULTS {
            truncated = true;
            break;
        }
        let insertion = direct.binary_search(&claim_id).unwrap_err();
        direct.insert(insertion, claim_id);
    }
    truncated
}

fn fleet_ranking_overrides() -> RankingOverrides {
    RankingOverrides {
        stratified_code_prefetch: Some(0),
        ..RankingOverrides::default()
    }
}

impl std::fmt::Debug for CockroachMemoryService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CockroachMemoryService")
            .field("trusted_scope", &self.trusted_scope)
            .field("embedding_model", &self.embedder.model_id())
            .field("lifecycle", &self.lifecycle)
            .finish_non_exhaustive()
    }
}

impl CockroachMemoryService {
    pub fn new(
        trusted_scope: FleetScope,
        corpus: Arc<CockroachStore>,
        ledger: Arc<dyn ClaimLedger>,
        embedder: Arc<dyn ChunkEmbedder>,
    ) -> crate::Result<Self> {
        trusted_scope.validate()?;
        if corpus.scope().tenant_id != trusted_scope.tenant_id
            || corpus.scope().project != trusted_scope.project
        {
            return Err(FleetError::InvalidScope(
                "service and corpus scopes do not match".into(),
            ));
        }
        Ok(Self {
            trusted_scope,
            corpus,
            ledger,
            embedder,
            lifecycle: LifecycleServing::default(),
        })
    }

    /// Serve the given lifecycle surface. Only the private writer composition
    /// calls this; the publication reader keeps the record-only default.
    #[must_use]
    pub const fn with_lifecycle(mut self, lifecycle: LifecycleServing) -> Self {
        self.lifecycle = lifecycle;
        self
    }

    /// Verify the process embedder shares the corpus's registered vector
    /// generation. Serving requires deployment to initialize the immutable
    /// model coordinate before any fleet process accepts traffic.
    pub async fn verify_embedding_generation(&self) -> crate::Result<()> {
        let active = active_embedding_model(self.corpus.pool(), &self.trusted_scope)
            .await?
            .ok_or_else(|| {
                FleetError::Configuration(
                    "active embedding generation is not initialized; run deployment bootstrap"
                        .into(),
                )
            })?;
        if active != self.embedder.model_id() {
            return Err(FleetError::Configuration(format!(
                "configured embedding model '{}' does not match active corpus model '{active}'",
                self.embedder.model_id()
            )));
        }
        Ok(())
    }

    fn ensure_scope(&self, scope: &FleetScope) -> ServiceResult<()> {
        scope.validate().map_err(service_error)?;
        if scope.tenant_id != self.trusted_scope.tenant_id
            || scope.project != self.trusted_scope.project
            || scope.agent != self.trusted_scope.agent
            || scope.privacy_tier != self.trusted_scope.privacy_tier
        {
            return Err(ServiceError::InvalidRequest(
                "operation scope is outside the deployment identity".into(),
            ));
        }
        Ok(())
    }

    async fn hydrate_retrieval_metadata(&self, hits: &mut [RecallHit]) -> ServiceResult<usize> {
        let hit_ids = hits
            .iter()
            .map(|hit| hit.chunk_id.clone())
            .collect::<Vec<_>>();
        let metadata = self
            .corpus
            .fetch_retrieval_hit_metadata(&hit_ids)
            .await
            .map_err(service_error)?;
        Ok(apply_retrieval_metadata(hits, metadata))
    }

    async fn project_chunk_conflicts(
        &self,
        scope: &FleetScope,
        hits: &[RecallHit],
    ) -> ServiceResult<ChunkConflictProjection> {
        let mut claim_ids = hits
            .iter()
            .filter_map(|hit| {
                hit.extra
                    .get("claim_id")
                    .and_then(Value::as_i64)
                    .filter(|id| *id > 0)
            })
            .collect::<Vec<_>>();
        claim_ids.sort_unstable();
        claim_ids.dedup();
        let mut evidence_chunk_ids = hits
            .iter()
            .filter(|hit| hit.extra.get("claim_id").and_then(Value::as_i64).is_none())
            .map(|hit| hit.chunk_id.clone())
            .collect::<Vec<_>>();
        evidence_chunk_ids.sort_unstable();
        evidence_chunk_ids.dedup();
        let support_matches = if evidence_chunk_ids.is_empty() {
            crate::ledger::SupportedClaimIds {
                claim_ids: Vec::new(),
                supporting_chunk_ids: Vec::new(),
                coordinates: Vec::new(),
                truncated: false,
                coordinates_truncated: false,
            }
        } else {
            self.ledger
                .supported_claim_ids_for_chunk_ids(scope, &evidence_chunk_ids, MAX_TOOL_RESULTS)
                .await
                .map_err(service_error)?
        };
        let crate::ledger::SupportedClaimIds {
            claim_ids: supported_claim_ids,
            supporting_chunk_ids,
            coordinates: support_coordinates,
            truncated,
            coordinates_truncated: support_coordinates_truncated,
        } = support_matches;
        let support_claim_count = supported_claim_ids.len();
        let support_claims_truncated =
            truncated || merge_supported_claim_ids(&mut claim_ids, supported_claim_ids);
        let conflicts = if claim_ids.is_empty() {
            Vec::new()
        } else {
            self.ledger
                .conflicts_for_claim_ids(scope, &claim_ids, MAX_TOOL_RESULTS)
                .await
                .map_err(service_error)?
        };
        Ok(ChunkConflictProjection {
            conflicts,
            support_claim_count,
            supporting_chunk_ids,
            support_coordinates,
            support_claims_truncated,
            support_coordinates_truncated,
        })
    }

    /// One hybrid retrieval pass over the corpus.
    async fn retrieve_chunks(&self, params: &RecallParams) -> ServiceResult<Vec<RecallHit>> {
        let retrieval_corpus = self.corpus.retrieval_reader();
        ostk_recall_retrieval::recall(&retrieval_corpus, self.embedder.as_ref(), None, params)
            .await
            .map_err(|error| ServiceError::Internal(format!("hybrid recall: {error}")))
    }

    /// Retired claims keep their synthetic chunk row. On the private writer,
    /// such hits are dropped before the conflict projection so a retracted
    /// claim can neither surface nor select a conflict through chunk search.
    /// Dropping them after retrieval's cut would short the page, so the
    /// retrieval window grows until `limit` current hits fill it, retrieval
    /// runs out of hits, or the window reaches the tool's hit bound.
    async fn retrieve_lifecycle_current_chunks(
        &self,
        scope: &FleetScope,
        params: &mut RecallParams,
        limit: usize,
    ) -> ServiceResult<LifecyclePage> {
        let mut window = limit;
        loop {
            params.limit = Some(window);
            let hits = self.retrieve_chunks(params).await?;
            let returned = hits.len();
            let claim_ids = synthetic_claim_ids(&hits);
            let states = if claim_ids.is_empty() {
                Vec::new()
            } else {
                self.ledger
                    .claim_states(scope, &claim_ids)
                    .await
                    .map_err(service_error)?
            };
            let (hits, hidden_claim_ids) = page_lifecycle_hits(hits, &states, limit);
            match next_lifecycle_window(window, returned, hits.len(), limit) {
                LifecycleRefill::Grow(next) => window = next,
                outcome => {
                    return Ok(LifecyclePage {
                        hits,
                        hidden_claim_ids,
                        underfilled: outcome == LifecycleRefill::Underfilled,
                    });
                }
            }
        }
    }

    /// Hybrid chunk search with its conflict projection and diagnostics.
    async fn search_chunks(
        &self,
        scope: &FleetScope,
        args: SearchArgs,
        limit: usize,
    ) -> ServiceResult<RecallResult> {
        let mut params = RecallParams {
            query: args.query,
            project: Some(scope.project.clone()),
            source: args.source,
            since: None,
            before: None,
            limit: Some(limit),
            max_per_source_id: args.max_per_source_id,
            min_score: args.min_score,
            intent: args.intent.unwrap_or_default(),
            attention_bias: None,
            // The portable default's extra code-only dense lane is
            // useful for local symbol search, but in a small public
            // demo it grants weak code neighbours a fresh rank-zero
            // contribution. Fleet recall disables that prefetch; code
            // still participates in both primary lexical and dense
            // lanes under the same relevance contract as every source.
            ranking_overrides: Some(fleet_ranking_overrides()),
        };
        let (mut hits, hiding) = if self.lifecycle.hide_non_current_claim_chunks {
            let page = self
                .retrieve_lifecycle_current_chunks(scope, &mut params, limit)
                .await?;
            (page.hits, Some((page.hidden_claim_ids, page.underfilled)))
        } else {
            (self.retrieve_chunks(&params).await?, None)
        };
        let metadata_elided = self.hydrate_retrieval_metadata(&mut hits).await?;
        let mut projection = self.project_chunk_conflicts(scope, &hits).await?;
        let conflict_matches = conflict_match_diagnostics(
            &projection.conflicts,
            &hits,
            &projection.support_coordinates,
        )?;
        let overlay = self
            .overlay_conflicts(scope, &mut projection.conflicts)
            .await;
        let mut result = RecallResult::new(json!({ "hits": hits }));
        result.conflicts = serialize_conflicts(&projection.conflicts)?;
        result.conflict_coverage = conflict_coverage(false, &projection.conflicts);
        mark_lifecycle_overlay(&mut result.conflict_coverage, &mut result.warnings, overlay);
        if projection.support_claims_truncated {
            result.warnings.push(json!({
                "code": "support_claim_projection_truncated",
                "message": "more typed claims cite the surfaced evidence than fit in the bounded conflict projection"
            }));
        }
        if projection.support_coordinates_truncated {
            result.warnings.push(json!({
                "code": "support_coordinate_projection_truncated",
                "message": "additional exact source-support associations exist beyond the bounded conflict-trigger diagnostic"
            }));
        }
        if hiding.as_ref().is_some_and(|(_, underfilled)| *underfilled) {
            result.warnings.push(json!({
                "code": "lifecycle_hidden_hits_underfilled",
                "message": "chunks of claims that are no longer current filled the bounded retrieval window, so fewer hits than the limit are returned and current memory may rank below it; narrow the query or filter by source"
            }));
        }
        let mut retrieval = json!({
            "lanes": ["lexical", "dense"],
            "fusion": "rrf",
            "metadata_elided": metadata_elided,
            "support_claims_matched": projection.support_claim_count,
            "supporting_chunk_ids": projection.supporting_chunk_ids,
            "support_claims_truncated": projection.support_claims_truncated,
            "support_coordinates_truncated": projection.support_coordinates_truncated,
            "conflict_matches": conflict_matches,
            "dense_min_cosine_similarity": RETRIEVAL_DENSE_MIN_COSINE_SIMILARITY,
            "stratified_code_prefetch": 0,
        });
        if let Some((hidden, _)) = hiding {
            retrieval["lifecycle_hidden_claim_ids"] = json!(hidden);
        }
        result.diagnostics.insert("retrieval".into(), retrieval);
        Ok(result)
    }

    async fn recall_search(
        &self,
        scope: &FleetScope,
        arguments: Map<String, Value>,
    ) -> ServiceResult<RecallResult> {
        self.verify_embedding_generation()
            .await
            .map_err(service_error)?;
        let args: SearchArgs = from_arguments(arguments, "recall search")?;
        validate_search_args(&args)?;
        let limit = bounded_limit(args.limit)?;
        match args.kind.as_deref().unwrap_or("chunk") {
            "chunk" => self.search_chunks(scope, args, limit).await,
            "claim" | "assertion" => {
                reject_claim_only_unsupported_filters(&args)?;
                let hits = self
                    .ledger
                    .search_claims(scope, &args.query, args.include_history, limit)
                    .await
                    .map_err(service_error)?;
                let claim_ids = hits.iter().map(|hit| hit.claim.id).collect::<Vec<_>>();
                let mut conflicts = self
                    .ledger
                    .conflicts_for_claim_ids(scope, &claim_ids, MAX_TOOL_RESULTS)
                    .await
                    .map_err(service_error)?;
                let coverage_complete = conflicts.len() < MAX_TOOL_RESULTS
                    && conflicts.iter().all(conflict_projection_complete);
                let overlay = self.overlay_conflicts(scope, &mut conflicts).await;
                let hits = compact_claim_hits(hits);
                let mut result = RecallResult::new(json!({ "hits": hits }));
                result.conflicts = serialize_conflicts(&conflicts)?;
                result.conflict_coverage = conflict_coverage(coverage_complete, &conflicts);
                mark_lifecycle_overlay(
                    &mut result.conflict_coverage,
                    &mut result.warnings,
                    overlay,
                );
                result.diagnostics.insert(
                    "retrieval".into(),
                    json!({ "lane": "claim_passage_dense", "model": self.embedder.model_id() }),
                );
                Ok(result)
            }
            other => Err(ServiceError::InvalidRequest(format!(
                "recall search kind {other:?} is not supported; use chunk or claim"
            ))),
        }
    }

    async fn recall_get(
        &self,
        scope: &FleetScope,
        arguments: Map<String, Value>,
    ) -> ServiceResult<RecallResult> {
        let args: GetArgs = from_arguments(arguments, "recall get")?;
        match args.kind.as_deref().unwrap_or("chunk") {
            "claim" | "assertion" => {
                let id = parse_safe_id(&args.id)?;
                let claim = self
                    .ledger
                    .get_claim(scope, id)
                    .await
                    .map_err(service_error)?;
                let mut result = RecallResult::new(json!({ "claim": claim }));
                let mut conflicts = self
                    .ledger
                    .conflicts_for_claim_ids(scope, &[id], MAX_TOOL_RESULTS)
                    .await
                    .map_err(service_error)?;
                let coverage_complete = conflicts.len() < MAX_TOOL_RESULTS
                    && conflicts.iter().all(conflict_projection_complete);
                let overlay = self.overlay_conflicts(scope, &mut conflicts).await;
                result.conflicts = serialize_conflicts(&conflicts)?;
                result.conflict_coverage = conflict_coverage(coverage_complete, &conflicts);
                mark_lifecycle_overlay(
                    &mut result.conflict_coverage,
                    &mut result.warnings,
                    overlay,
                );
                Ok(result)
            }
            "chunk" => {
                let id = args.id.as_str().ok_or_else(|| {
                    ServiceError::InvalidRequest("chunk id must be a string".into())
                })?;
                if id.trim().is_empty() || id.len() > 256 {
                    return Err(ServiceError::InvalidRequest(
                        "chunk id must be between 1 and 256 bytes".into(),
                    ));
                }
                let filter = CorpusFilter {
                    projects: Some(vec![scope.project.clone()]),
                    ..CorpusFilter::default()
                };
                let chunks = self
                    .corpus
                    .fetch_chunks_scoped(&[id.to_string()], &filter)
                    .await
                    .map_err(|error| ServiceError::Internal(error.to_string()))?;
                let chunk = chunks.into_iter().next().map(|hydrated| hydrated.chunk);
                let mut result = RecallResult::new(json!({ "chunk": chunk }));
                result.conflict_coverage = ConflictCoverage::not_evaluated();
                Ok(result)
            }
            // Conflict lookup by id is part of the lifecycle surface; the
            // record-only (publication) surface keeps its historical kinds.
            "conflict" if self.lifecycle.surface != RememberSurface::RECORD_ONLY => {
                self.recall_conflict(scope, &args.id).await
            }
            other => Err(ServiceError::InvalidRequest(format!(
                "recall get kind {other:?} is not supported"
            ))),
        }
    }

    /// `recall(get, kind=conflict)`: one conflict in any state, with its
    /// members and, where the overlay is served, its lifecycle overlay and
    /// its lifecycle history.
    async fn recall_conflict(&self, scope: &FleetScope, id: &Value) -> ServiceResult<RecallResult> {
        let id = parse_safe_id(id)?;
        let mut conflicts = self
            .ledger
            .get_conflicts(scope, &[id])
            .await
            .map_err(service_error)?;
        let overlay = self.overlay_conflicts(scope, &mut conflicts).await;
        let serialized = serialize_conflicts(&conflicts)?;
        let mut result = RecallResult::new(json!({ "conflict": serialized.first().cloned() }));
        // History is a second read of the same log, after the overlay's.
        if let (Some(_), Some(conflict)) = (overlay, conflicts.first()) {
            match self.ledger.conflict_lifecycle_history(scope, id).await {
                Ok(history) => {
                    let gaps = unlogged_transitions(
                        &history.events,
                        conflict.revision,
                        !history.truncated,
                    );
                    result.data["history"] = json!(history.events);
                    result.data["history_truncated"] = json!(history.truncated);
                    result.data["unlogged_transitions"] = json!(gaps);
                }
                Err(error) => {
                    tracing::warn!(error = %error, conflict_id = id, "conflict lifecycle history read failed");
                    result.data["history"] = Value::Null;
                    result.warnings.push(json!({
                        "code": "lifecycle_history_unavailable",
                        "message": "the conflict's lifecycle history could not be read; the conflict itself is current"
                    }));
                }
            }
        }
        result.conflict_coverage =
            conflict_coverage(lifecycle_coverage_complete(&[id], &conflicts), &conflicts);
        result.conflicts = serialized;
        mark_lifecycle_overlay(&mut result.conflict_coverage, &mut result.warnings, overlay);
        Ok(result)
    }

    async fn recall_conflicts(
        &self,
        scope: &FleetScope,
        arguments: Map<String, Value>,
    ) -> ServiceResult<RecallResult> {
        let args: ConflictArgs = from_arguments(arguments, "recall conflicts")?;
        let limit = bounded_limit(args.limit)?;
        let mut conflicts = self
            .ledger
            .list_conflicts(scope, args.include_resolved, limit)
            .await
            .map_err(service_error)?;
        let coverage_complete =
            conflicts.len() < limit && conflicts.iter().all(conflict_projection_complete);
        let overlay = self.overlay_conflicts(scope, &mut conflicts).await;
        let serialized = serialize_conflicts(&conflicts)?;
        let mut result = RecallResult::new(json!({ "conflicts": serialized }));
        result.conflicts = serialized;
        result.conflict_coverage = conflict_coverage(coverage_complete, &conflicts);
        mark_lifecycle_overlay(&mut result.conflict_coverage, &mut result.warnings, overlay);
        Ok(result)
    }

    /// Attach the lifecycle overlay to `conflicts` with one autocommit read
    /// after the main read, which has already committed. `None` when the
    /// overlay is not served. A failed read leaves the conflicts as they are
    /// and reports `Unavailable`; it never fails the response.
    async fn overlay_conflicts(
        &self,
        scope: &FleetScope,
        conflicts: &mut [Conflict],
    ) -> Option<OverlayOutcome> {
        if !self.lifecycle.lifecycle_overlay {
            return None;
        }
        let mut episodes = conflicts
            .iter()
            .map(|conflict| {
                (
                    conflict.id,
                    overlay_episode_revision(&conflict.state, conflict.revision),
                )
            })
            .collect::<Vec<_>>();
        episodes.sort_unstable();
        episodes.dedup();
        if episodes.is_empty() {
            return Some(OverlayOutcome::Evaluated);
        }
        match self.ledger.conflict_lifecycle_rows(scope, &episodes).await {
            Ok(rows) => {
                for conflict in conflicts.iter_mut() {
                    let events = rows.events.get(&conflict.id).map_or(&[][..], Vec::as_slice);
                    let truncated = events.len() > MAX_OVERLAY_EPISODE_EVENTS;
                    let shown = &events[..events.len().min(MAX_OVERLAY_EPISODE_EVENTS)];
                    let member_count = i64::try_from(conflict.member_count).unwrap_or(i64::MAX);
                    conflict.lifecycle = Some(derive_overlay(
                        &conflict.state,
                        conflict.revision,
                        member_count,
                        shown,
                        truncated,
                        rows.evaluated_at,
                    ));
                }
                Some(OverlayOutcome::Evaluated)
            }
            Err(error) => {
                tracing::warn!(error = %error, "conflict lifecycle overlay read failed");
                Some(OverlayOutcome::Unavailable)
            }
        }
    }

    /// The overlay for a committed mutation's conflict projection. A
    /// projection that already failed carries no overlay.
    async fn overlay_projection(
        &self,
        scope: &FleetScope,
        conflicts: crate::Result<Vec<Conflict>>,
    ) -> (crate::Result<Vec<Conflict>>, Option<OverlayOutcome>) {
        match conflicts {
            Ok(mut conflicts) => {
                let overlay = self.overlay_conflicts(scope, &mut conflicts).await;
                (Ok(conflicts), overlay)
            }
            Err(error) => {
                let overlay = self
                    .lifecycle
                    .lifecycle_overlay
                    .then_some(OverlayOutcome::Unavailable);
                (Err(error), overlay)
            }
        }
    }

    async fn recall_status(&self, arguments: Map<String, Value>) -> ServiceResult<RecallResult> {
        let _: EmptyArgs = from_arguments(arguments, "recall status")?;
        let capabilities = self.corpus.capabilities().await.map_err(service_error)?;
        let mut result = RecallResult::new(json!({
            "status": "ready",
            "database": capabilities,
            "embedding_model": self.embedder.model_id(),
            "embedding_dimension": self.embedder.dim(),
        }));
        if self.lifecycle.surface != RememberSurface::RECORD_ONLY {
            result.data["remember_surface"] = json!(self.lifecycle.surface);
        }
        result.conflict_coverage = ConflictCoverage::not_evaluated();
        Ok(result)
    }

    async fn remember_record(
        &self,
        scope: &FleetScope,
        request: RememberRequest,
    ) -> ServiceResult<RememberResult> {
        self.verify_embedding_generation()
            .await
            .map_err(service_error)?;
        let idempotency_key = required_idempotency_key(request.action, request.idempotency_key)?;
        let input: ClaimInput = from_arguments(request.arguments, "remember record")?;
        validate_operator_claim_input(RememberAction::Record, scope, &input)?;
        let mutation = self
            .ledger
            .record_claim(scope, &input, &idempotency_key)
            .await
            .map_err(service_error)?;
        // `conflicts_opened` is a transition delta, not the claim's current
        // conflict set. A third value can join an already-open conflict
        // without opening it again, so always project this claim's durable
        // conflicts in the mutation response.
        let conflicts = self
            .ledger
            .conflicts_for_claim_ids(scope, &[mutation.claim.id], MAX_TOOL_RESULTS)
            .await;
        let (conflicts, overlay) = self.overlay_projection(scope, conflicts).await;
        let mut result = committed_remember_result(&mutation, conflicts);
        mark_lifecycle_overlay(&mut result.conflict_coverage, &mut result.warnings, overlay);
        Ok(result)
    }

    async fn remember_retract(
        &self,
        scope: &FleetScope,
        request: RememberRequest,
    ) -> ServiceResult<RememberResult> {
        let idempotency_key = required_idempotency_key(request.action, request.idempotency_key)?;
        let (target, reason) = parse_retract_arguments(request.arguments)?;
        let mutation = self
            .ledger
            .retract_claim(scope, target, reason.as_deref(), &idempotency_key)
            .await
            .map_err(service_error)?;
        Ok(self.lifecycle_result(scope, &mutation).await)
    }

    async fn remember_supersede(
        &self,
        scope: &FleetScope,
        request: RememberRequest,
    ) -> ServiceResult<RememberResult> {
        let idempotency_key = required_idempotency_key(request.action, request.idempotency_key)?;
        let (target, reason, successor) = split_supersede_arguments(request.arguments)?;
        validate_operator_claim_input(RememberAction::Supersede, scope, &successor)?;
        // The successor is embedded like a recorded claim, so the process
        // embedder must share the corpus's registered vector generation.
        self.verify_embedding_generation()
            .await
            .map_err(service_error)?;
        let mutation = self
            .ledger
            .supersede_claim(
                scope,
                target,
                reason.as_deref(),
                &successor,
                &idempotency_key,
            )
            .await
            .map_err(service_error)?;
        Ok(self.lifecycle_result(scope, &mutation).await)
    }

    async fn remember_acknowledge(
        &self,
        scope: &FleetScope,
        request: RememberRequest,
    ) -> ServiceResult<RememberResult> {
        let idempotency_key = required_idempotency_key(request.action, request.idempotency_key)?;
        let (target, reason) = parse_acknowledge_arguments(request.arguments)?;
        let mutation = self
            .ledger
            .acknowledge_conflict(scope, target, reason.as_deref(), &idempotency_key)
            .await
            .map_err(service_error)?;
        Ok(self.conflict_result(scope, &mutation).await)
    }

    async fn remember_resolve(
        &self,
        scope: &FleetScope,
        request: RememberRequest,
    ) -> ServiceResult<RememberResult> {
        let idempotency_key = required_idempotency_key(request.action, request.idempotency_key)?;
        let (target, retract_claim_ids, reason) = parse_resolve_arguments(request.arguments)?;
        let mutation = self
            .ledger
            .resolve_conflict(
                scope,
                target,
                &retract_claim_ids,
                reason.as_deref(),
                &idempotency_key,
            )
            .await
            .map_err(service_error)?;
        Ok(self.conflict_result(scope, &mutation).await)
    }

    /// Project a committed (or replayed) lifecycle mutation: every conflict it
    /// touched, in any state, from the claim's lineage membership plus
    /// whatever the detector re-evaluated.
    async fn lifecycle_result(
        &self,
        scope: &FleetScope,
        mutation: &ClaimMutation,
    ) -> RememberResult {
        let requested = affected_conflict_ids(mutation);
        let conflicts = if requested.is_empty() {
            Ok(Vec::new())
        } else {
            self.ledger.get_conflicts(scope, &requested).await
        };
        let (conflicts, overlay) = self.overlay_projection(scope, conflicts).await;
        let mut result = committed_lifecycle_result(mutation, &requested, conflicts);
        mark_lifecycle_overlay(&mut result.conflict_coverage, &mut result.warnings, overlay);
        result
    }

    /// Project a committed (or replayed) conflict mutation with the conflict
    /// it acted on, in its current state.
    async fn conflict_result(
        &self,
        scope: &FleetScope,
        mutation: &ConflictMutation,
    ) -> RememberResult {
        let mut requested = mutation
            .conflicts_resolved
            .iter()
            .copied()
            .chain([mutation.conflict_id])
            .collect::<Vec<_>>();
        requested.sort_unstable();
        requested.dedup();
        let conflicts = self.ledger.get_conflicts(scope, &requested).await;
        let (conflicts, overlay) = self.overlay_projection(scope, conflicts).await;
        let mut result = committed_conflict_result(mutation, &requested, conflicts);
        mark_lifecycle_overlay(&mut result.conflict_coverage, &mut result.warnings, overlay);
        result
    }

    async fn replayed_result(
        &self,
        scope: &FleetScope,
        mutation: &LifecycleMutation,
    ) -> RememberResult {
        match mutation {
            LifecycleMutation::Claim(mutation) => self.lifecycle_result(scope, mutation).await,
            LifecycleMutation::Conflict(mutation) => self.conflict_result(scope, mutation).await,
        }
    }

    /// A committed request replays before any precondition, the surface
    /// included: a writer that no longer serves an action (for example after
    /// `FLEET_RECALL_REMEMBER_LIFECYCLE=disabled`) still returns the stored
    /// result of a request committed under the key. Any other use of the key
    /// is an idempotency conflict, so `refusal`, which promises the key was
    /// not consumed, is returned only for a key that no receipt holds.
    async fn replay_unserved_or_refuse(
        &self,
        scope: &FleetScope,
        request: RememberRequest,
        refusal: ServiceError,
    ) -> ServiceResult<RememberResult> {
        let Some(idempotency_key) = request.idempotency_key else {
            return Err(refusal);
        };
        let parsed = match request.action {
            RememberAction::Retract => parse_retract_arguments(request.arguments)
                .ok()
                .map(|(target, reason)| UnservedLifecycle::Retract { target, reason }),
            RememberAction::Supersede => split_supersede_arguments(request.arguments).ok().map(
                |(target, reason, successor)| UnservedLifecycle::Supersede {
                    target,
                    reason,
                    successor: Box::new(successor),
                },
            ),
            RememberAction::Acknowledge => parse_acknowledge_arguments(request.arguments)
                .ok()
                .map(|(target, reason)| UnservedLifecycle::Acknowledge { target, reason }),
            RememberAction::Resolve => parse_resolve_arguments(request.arguments).ok().map(
                |(target, retract_claim_ids, reason)| UnservedLifecycle::Resolve {
                    target,
                    retract_claim_ids,
                    reason,
                },
            ),
            _ => None,
        };
        let replay = self
            .ledger
            .replay_unserved_lifecycle(
                scope,
                &idempotency_key,
                parsed.as_ref().map(UnservedLifecycle::as_replay),
            )
            .await
            .map_err(service_error)?;
        match replay {
            Some(mutation) => Ok(self.replayed_result(scope, &mutation).await),
            None => Err(refusal),
        }
    }

    /// Fail the event-first `assert` route closed (ADR 0002 D3/D4).
    ///
    /// An enabled `assert` would build a `RememberIngressCandidateV2` from the
    /// trusted server scope (never from payload — EVID-04), route it to the
    /// unique active `RememberAdmissionRuleV2` resolved from the witnessed
    /// active package, rederive the subject from the activated identity recipe,
    /// re-audit applicability and support event IDs, and append
    /// `memory.claim.accepted` through
    /// `AppendableAcceptedEvent::admitted_memory_claim` with an
    /// `AppendProjection` that writes the legacy `memory_claims` /
    /// `memory_events` / receipt rows carrying `accepted_event_id` in the SAME
    /// serializable transaction (EVENT-03).
    ///
    /// That path is deliberately fenced off. ADR 0002 D4 requires three
    /// writer-authority pins
    /// (`FLEET_RECALL_CONTRACT_TENANT_NAMESPACE`,
    /// `FLEET_RECALL_CONTRACT_PROJECT_NAMESPACE`,
    /// `FLEET_RECALL_BOOTSTRAP_RECEIPT_DIGEST`) and an in-transaction
    /// writer-authority witness before an accepted event may be minted; "when
    /// absent the `assert` route is disabled and every legacy behaviour is
    /// byte-stable". The serving runtime loads neither the pins
    /// (`WriterAuthorityConfig`, `src/config.rs`) nor a non-stub witness loader
    /// (`src/registry_witness`), so the route fails closed before any argument
    /// is inspected: no admission rule is consulted, no head is read, no
    /// synthesized canonical event is produced, and nothing is written
    /// (APPL-01/02, PRED-03, AUTH-03).
    fn assert_route_disabled() -> ServiceError {
        ServiceError::Unavailable(
            "remember(assert) is disabled: this deployment carries neither the ADR 0002 D4 \
             writer-authority configuration pins nor an active-head witness, so the event-first \
             path cannot mint an accepted event; use remember(record)"
                .into(),
        )
    }
}

/// Build the response only after the serializable mutation has committed.
///
/// Conflict hydration is a post-commit convenience projection. Its failure
/// must never obscure the durable mutation receipt or invite a caller to treat
/// a committed write as failed.
fn committed_remember_result(
    mutation: &ClaimMutation,
    conflicts: crate::Result<Vec<Conflict>>,
) -> RememberResult {
    let expected_conflict_ids = &mutation.claim.conflict_ids;
    let replay = mutation.idempotent_replay;
    project_committed_conflicts(claim_mutation_data(mutation), conflicts, |conflicts| {
        // A fresh record's projected open conflicts are exactly its lineage
        // memberships. A replayed receipt carries the claim as it was then;
        // a membership it lists may have closed since, so only an open
        // conflict it does not list makes the projection incomplete.
        let memberships_covered = if replay {
            conflicts
                .iter()
                .all(|conflict| expected_conflict_ids.contains(&conflict.id))
        } else {
            conflicts.len() == expected_conflict_ids.len()
        };
        memberships_covered && conflicts.iter().all(conflict_projection_complete)
    })
}

/// Build a lifecycle response after commit. Its conflicts are every affected
/// conflict in any state, and coverage is complete only when each requested
/// conflict was found and fully projected.
fn committed_lifecycle_result(
    mutation: &ClaimMutation,
    requested: &[i64],
    conflicts: crate::Result<Vec<Conflict>>,
) -> RememberResult {
    project_committed_conflicts(claim_mutation_data(mutation), conflicts, |conflicts| {
        lifecycle_coverage_complete(requested, conflicts)
    })
}

/// Build a conflict mutation's response after commit, with the same coverage
/// rule as a claim lifecycle mutation.
fn committed_conflict_result(
    mutation: &ConflictMutation,
    requested: &[i64],
    conflicts: crate::Result<Vec<Conflict>>,
) -> RememberResult {
    let data = serde_json::to_value(mutation).unwrap_or_else(|error| {
        tracing::error!(
            error = %error,
            conflict_id = mutation.conflict_id,
            "committed conflict mutation could not be fully serialized"
        );
        json!({
            "operation": mutation.operation.as_str(),
            "conflict_id": mutation.conflict_id,
            "conflict_state": mutation.conflict_state.as_str(),
            "conflict_revision": mutation.conflict_revision,
            "applied": mutation.applied,
            "idempotent_replay": mutation.idempotent_replay,
        })
    });
    project_committed_conflicts(data, conflicts, |conflicts| {
        lifecycle_coverage_complete(requested, conflicts)
    })
}

/// Record the overlay outcome on a response's conflict coverage. An
/// unavailable overlay adds a warning but never fails the response.
fn mark_lifecycle_overlay(
    coverage: &mut ConflictCoverage,
    warnings: &mut Vec<Value>,
    outcome: Option<OverlayOutcome>,
) {
    let Some(outcome) = outcome else {
        return;
    };
    let status = match outcome {
        OverlayOutcome::Evaluated => "evaluated",
        OverlayOutcome::Unavailable => "unavailable",
    };
    coverage
        .details
        .insert("lifecycle_overlay".into(), Value::String(status.into()));
    if outcome == OverlayOutcome::Unavailable {
        warnings.push(json!({
            "code": "lifecycle_overlay_unavailable",
            "message": "conflict lifecycle state (acknowledgements, closes, and history) could not be read; the conflicts themselves are current"
        }));
    }
}

fn lifecycle_coverage_complete(requested: &[i64], conflicts: &[Conflict]) -> bool {
    requested
        .iter()
        .all(|id| conflicts.iter().any(|conflict| conflict.id == *id))
        && conflicts.iter().all(|conflict| {
            conflict_projection_complete(conflict)
                && conflict.detector == FUNCTIONAL_VALUE_CONFLICT_DETECTOR_V2
        })
}

fn affected_conflict_ids(mutation: &ClaimMutation) -> Vec<i64> {
    let mut ids = mutation
        .claim
        .conflict_ids
        .iter()
        .chain(&mutation.conflicts_resolved)
        .copied()
        .chain(
            mutation
                .reevaluation
                .as_ref()
                .map(|reevaluation| reevaluation.conflict_id),
        )
        .collect::<Vec<_>>();
    ids.sort_unstable();
    ids.dedup();
    ids
}

fn claim_mutation_data(mutation: &ClaimMutation) -> Value {
    serde_json::to_value(mutation).unwrap_or_else(|error| {
        tracing::error!(
            error = %error,
            claim_id = mutation.claim.id,
            "committed remember mutation could not be fully serialized"
        );
        json!({
            "operation": mutation.operation.as_str(),
            "claim": {
                "id": mutation.claim.id,
                "state": &mutation.claim.state,
                "revision": mutation.claim.revision,
            },
            "idempotent_replay": mutation.idempotent_replay,
            "conflicts_opened": &mutation.conflicts_opened,
            "conflicts_resolved": &mutation.conflicts_resolved,
        })
    })
}

fn project_committed_conflicts(
    data: Value,
    conflicts: crate::Result<Vec<Conflict>>,
    coverage_complete: impl FnOnce(&[Conflict]) -> bool,
) -> RememberResult {
    let mut result = RememberResult::new(data);
    result
        .diagnostics
        .insert("transaction".into(), Value::String("serializable".into()));

    match conflicts {
        Ok(conflicts) => match serialize_conflicts(&conflicts) {
            Ok(serialized) => {
                result.conflicts = serialized;
                result.conflict_coverage =
                    conflict_coverage(coverage_complete(&conflicts), &conflicts);
            }
            Err(error) => mark_post_commit_projection_unavailable(&mut result, &error),
        },
        Err(error) => {
            tracing::error!(
                error = %error,
                "committed remember conflict projection failed"
            );
            mark_post_commit_projection_unavailable_without_error(&mut result);
        }
    }
    result
}

fn mark_post_commit_projection_unavailable(result: &mut RememberResult, error: &ServiceError) {
    tracing::error!(
        error = %error,
        "committed remember conflict projection serialization failed"
    );
    mark_post_commit_projection_unavailable_without_error(result);
}

fn mark_post_commit_projection_unavailable_without_error(result: &mut RememberResult) {
    result.conflicts.clear();
    result.conflict_coverage = conflict_coverage(false, &[]);
    result.conflict_coverage.details.insert(
        "reason".into(),
        Value::String("post_commit_projection_unavailable".into()),
    );
    result.warnings.push(json!({
        "code": "post_commit_projection_unavailable",
        "message": "the mutation committed, but its conflict projection is temporarily unavailable; replay the identical full remember request with the same idempotency_key to confirm the same receipt and retry the projection"
    }));
    result.diagnostics.insert(
        "conflict_projection".into(),
        json!({
            "status": "unavailable",
            "mutation_committed": true,
        }),
    );
}

fn apply_retrieval_metadata(hits: &mut [RecallHit], metadata: Vec<RetrievalHitMetadata>) -> usize {
    let elided = metadata
        .iter()
        .filter(|row| row.links_elided || row.extra_elided)
        .count();
    let mut metadata = metadata
        .into_iter()
        .map(|row| (row.chunk_id.clone(), row))
        .collect::<HashMap<_, _>>();
    for hit in hits {
        if let Some(row) = metadata.remove(&hit.chunk_id) {
            hit.links = row.links;
            hit.extra = row.extra;
        }
    }
    elided
}

fn ranked_source_support(
    trigger_claim_ids: &HashSet<i64>,
    support_coordinates: &[SupportedClaimCoordinate],
    chunk_ranks: &HashMap<&str, usize>,
) -> ServiceResult<Vec<(i64, String, usize)>> {
    let mut source_support = support_coordinates
        .iter()
        .filter(|coordinate| trigger_claim_ids.contains(&coordinate.claim_id))
        .map(|coordinate| {
            let fused_hit_rank =
                chunk_ranks
                    .get(coordinate.chunk_id.as_str())
                    .ok_or_else(|| {
                        ServiceError::Internal(
                            "exact source-support coordinate was not present in fused hits".into(),
                        )
                    })?;
            Ok((
                coordinate.claim_id,
                coordinate.chunk_id.clone(),
                *fused_hit_rank,
            ))
        })
        .collect::<ServiceResult<Vec<_>>>()?;
    source_support.sort_unstable_by(|left, right| {
        left.0
            .cmp(&right.0)
            .then_with(|| left.1.cmp(&right.1))
            .then_with(|| left.2.cmp(&right.2))
    });
    source_support.dedup();
    Ok(source_support)
}

fn conflict_match_diagnostics(
    conflicts: &[Conflict],
    hits: &[RecallHit],
    support_coordinates: &[SupportedClaimCoordinate],
) -> ServiceResult<Vec<Value>> {
    let chunk_ranks = hits
        .iter()
        .enumerate()
        .map(|(rank, hit)| (hit.chunk_id.as_str(), rank + 1))
        .collect::<HashMap<_, _>>();
    let mut direct_claim_ranks = HashMap::new();
    for (rank, hit) in hits.iter().enumerate() {
        if let Some(claim_id) = hit
            .extra
            .get("claim_id")
            .and_then(Value::as_i64)
            .filter(|id| *id > 0)
        {
            direct_claim_ranks
                .entry(claim_id)
                .and_modify(|current: &mut usize| *current = (*current).min(rank + 1))
                .or_insert(rank + 1);
        }
    }
    let mut trigger_owner = HashMap::new();
    let mut output = Vec::with_capacity(conflicts.len());
    for conflict in conflicts {
        if conflict.trigger_claim_ids.is_empty() {
            return Err(ServiceError::Internal(
                "returned conflict omitted its exact retrieval trigger".into(),
            ));
        }
        for claim_id in &conflict.trigger_claim_ids {
            if trigger_owner
                .insert(*claim_id, conflict.id)
                .is_some_and(|owner| owner != conflict.id)
            {
                return Err(ServiceError::Internal(
                    "one retrieval claim selected multiple open conflicts".into(),
                ));
            }
        }
        let trigger_claim_ids = conflict
            .trigger_claim_ids
            .iter()
            .copied()
            .collect::<HashSet<_>>();
        let mut direct_claim_ids = trigger_claim_ids
            .iter()
            .filter(|claim_id| direct_claim_ranks.contains_key(claim_id))
            .copied()
            .collect::<Vec<_>>();
        direct_claim_ids.sort_unstable();
        let source_support =
            ranked_source_support(&trigger_claim_ids, support_coordinates, &chunk_ranks)?;

        let represented_claim_ids = direct_claim_ids
            .iter()
            .copied()
            .chain(source_support.iter().map(|(claim_id, _, _)| *claim_id))
            .collect::<HashSet<_>>();
        if represented_claim_ids != trigger_claim_ids {
            return Err(ServiceError::Internal(
                "returned conflict could not be bound to an exact fused hit".into(),
            ));
        }
        let best_fused_hit_rank = direct_claim_ids
            .iter()
            .filter_map(|claim_id| direct_claim_ranks.get(claim_id).copied())
            .chain(source_support.iter().map(|(_, _, rank)| *rank))
            .min()
            .ok_or_else(|| {
                ServiceError::Internal("returned conflict had no ranked trigger".into())
            })?;
        output.push(json!({
            "conflict_id": conflict.id,
            "best_fused_hit_rank": best_fused_hit_rank,
            "direct_claim_ids": direct_claim_ids,
            "source_support": source_support.into_iter().map(|(claim_id, chunk_id, fused_hit_rank)| {
                json!({
                    "claim_id": claim_id,
                    "chunk_id": chunk_id,
                    "fused_hit_rank": fused_hit_rank,
                })
            }).collect::<Vec<_>>(),
        }));
    }
    Ok(output)
}

#[async_trait]
impl FleetMemoryService for CockroachMemoryService {
    async fn recall(
        &self,
        scope: FleetScope,
        request: RecallRequest,
    ) -> ServiceResult<RecallResult> {
        self.ensure_scope(&scope)?;
        match request.action {
            RecallAction::Search => self.recall_search(&scope, request.arguments).await,
            RecallAction::Get => self.recall_get(&scope, request.arguments).await,
            RecallAction::Conflicts => self.recall_conflicts(&scope, request.arguments).await,
            RecallAction::Status => self.recall_status(request.arguments).await,
            action => Err(ServiceError::InvalidRequest(format!(
                "recall({}) is not implemented yet",
                action.as_str()
            ))),
        }
    }

    async fn remember(
        &self,
        scope: FleetScope,
        request: RememberRequest,
    ) -> ServiceResult<RememberResult> {
        self.ensure_scope(&scope)?;
        if let Err(refusal) = authorize_surface(self.lifecycle.surface, request.action) {
            return self
                .replay_unserved_or_refuse(&scope, request, refusal)
                .await;
        }
        match request.action {
            RememberAction::Record => self.remember_record(&scope, request).await,
            RememberAction::Assert => Err(Self::assert_route_disabled()),
            RememberAction::Retract => self.remember_retract(&scope, request).await,
            RememberAction::Supersede => self.remember_supersede(&scope, request).await,
            RememberAction::Acknowledge => self.remember_acknowledge(&scope, request).await,
            RememberAction::Resolve => self.remember_resolve(&scope, request).await,
            action => Err(ServiceError::InvalidRequest(format!(
                "remember({}) is not implemented yet",
                action.as_str()
            ))),
        }
    }

    fn remember_surface(&self) -> RememberSurface {
        self.lifecycle.surface
    }
}

/// Validate a claim an agent writes through `record` or as a `supersede`
/// successor: the domain limits, the trusted actor, and operator origin.
fn validate_operator_claim_input(
    action: RememberAction,
    scope: &FleetScope,
    input: &ClaimInput,
) -> ServiceResult<()> {
    input.validate().map_err(|error| match error {
        FleetError::Memory(message) => ServiceError::InvalidRequest(message),
        other => service_error(other),
    })?;
    if input
        .actor
        .as_deref()
        .is_some_and(|actor| actor != scope.agent)
    {
        return Err(ServiceError::InvalidRequest(
            "claim actor must match the authenticated fleet agent".into(),
        ));
    }
    if input.origin == "source_derived" || input.origin == "legacy_unverified" {
        return Err(ServiceError::InvalidRequest(format!(
            "remember({}) only accepts operator_asserted origin; projection imports use a trusted ingestion path",
            action.as_str()
        )));
    }
    Ok(())
}

/// A lifecycle request parsed by a writer that does not serve its action.
enum UnservedLifecycle {
    Retract {
        target: ClaimTarget,
        reason: Option<String>,
    },
    Supersede {
        target: ClaimTarget,
        reason: Option<String>,
        successor: Box<ClaimInput>,
    },
    Acknowledge {
        target: ConflictTarget,
        reason: Option<String>,
    },
    Resolve {
        target: ConflictTarget,
        retract_claim_ids: Vec<i64>,
        reason: Option<String>,
    },
}

impl UnservedLifecycle {
    fn as_replay(&self) -> LifecycleReplayRequest<'_> {
        match self {
            Self::Retract { target, reason } => LifecycleReplayRequest::Retract {
                target: *target,
                reason: reason.as_deref(),
            },
            Self::Supersede {
                target,
                reason,
                successor,
            } => LifecycleReplayRequest::Supersede {
                target: *target,
                reason: reason.as_deref(),
                successor,
            },
            Self::Acknowledge { target, reason } => LifecycleReplayRequest::Acknowledge {
                target: *target,
                reason: reason.as_deref(),
            },
            Self::Resolve {
                target,
                retract_claim_ids,
                reason,
            } => LifecycleReplayRequest::Resolve {
                target: *target,
                retract_claim_ids,
                reason: reason.as_deref(),
            },
        }
    }
}

/// The owner-lifecycle target fields shared by `retract` and `supersede`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimTargetArgs {
    claim_id: Value,
    expected_revision: i64,
    #[serde(default)]
    reason: Option<String>,
}

fn parse_retract_arguments(
    arguments: Map<String, Value>,
) -> ServiceResult<(ClaimTarget, Option<String>)> {
    parse_claim_target_arguments(arguments, "remember retract")
}

/// Split `supersede` arguments into the predecessor target, the optional
/// audit note, and the successor claim. Every other field must be a
/// `record` claim field.
fn split_supersede_arguments(
    mut arguments: Map<String, Value>,
) -> ServiceResult<(ClaimTarget, Option<String>, ClaimInput)> {
    let mut target_arguments = Map::new();
    for field in ["claim_id", "expected_revision", "reason"] {
        if let Some(value) = arguments.remove(field) {
            target_arguments.insert(field.into(), value);
        }
    }
    let (target, reason) = parse_claim_target_arguments(target_arguments, "remember supersede")?;
    let successor: ClaimInput = from_arguments(arguments, "remember supersede")?;
    Ok((target, reason, successor))
}

fn parse_claim_target_arguments(
    arguments: Map<String, Value>,
    operation: &str,
) -> ServiceResult<(ClaimTarget, Option<String>)> {
    let args: ClaimTargetArgs = from_arguments(arguments, operation)?;
    let claim_id = parse_safe_id(&args.claim_id).map_err(|_| {
        ServiceError::InvalidRequest(format!(
            "claim_id must be an integer between 1 and {MAX_SAFE_INTEGER}"
        ))
    })?;
    if !(1..=MAX_SAFE_INTEGER).contains(&args.expected_revision) {
        return Err(ServiceError::InvalidRequest(format!(
            "expected_revision must be between 1 and {MAX_SAFE_INTEGER}"
        )));
    }
    if let Some(reason) = args.reason.as_deref() {
        validate_lifecycle_reason(reason).map_err(ServiceError::InvalidRequest)?;
    }
    Ok((
        ClaimTarget {
            claim_id,
            expected_revision: args.expected_revision,
        },
        args.reason,
    ))
}

/// `remember(acknowledge)` arguments.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AcknowledgeArgs {
    conflict_id: Value,
    expected_revision: i64,
    #[serde(default)]
    reason: Option<String>,
}

/// `remember(resolve)` arguments: a concession of the caller's own claims.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolveArgs {
    conflict_id: Value,
    expected_revision: i64,
    expected_member_count: i64,
    #[serde(default)]
    retract_claim_ids: Vec<Value>,
    #[serde(default)]
    reason: Option<String>,
}

fn parse_acknowledge_arguments(
    arguments: Map<String, Value>,
) -> ServiceResult<(ConflictTarget, Option<String>)> {
    let args: AcknowledgeArgs = from_arguments(arguments, "remember acknowledge")?;
    let target = conflict_target(&args.conflict_id, args.expected_revision, None)?;
    validate_optional_reason(args.reason.as_deref())?;
    Ok((target, args.reason))
}

fn parse_resolve_arguments(
    arguments: Map<String, Value>,
) -> ServiceResult<(ConflictTarget, Vec<i64>, Option<String>)> {
    let args: ResolveArgs = from_arguments(arguments, "remember resolve")?;
    let target = conflict_target(
        &args.conflict_id,
        args.expected_revision,
        Some(args.expected_member_count),
    )?;
    if args.retract_claim_ids.len() > MAX_CONCESSION_CLAIMS {
        return Err(ServiceError::InvalidRequest(format!(
            "retract_claim_ids accepts at most {MAX_CONCESSION_CLAIMS} claims"
        )));
    }
    let mut retract_claim_ids = Vec::with_capacity(args.retract_claim_ids.len());
    for value in &args.retract_claim_ids {
        let id = parse_safe_id(value).map_err(|_| {
            ServiceError::InvalidRequest(format!(
                "retract_claim_ids must be integers between 1 and {MAX_SAFE_INTEGER}"
            ))
        })?;
        if retract_claim_ids.contains(&id) {
            return Err(ServiceError::InvalidRequest(
                "retract_claim_ids must not repeat a claim".into(),
            ));
        }
        retract_claim_ids.push(id);
    }
    retract_claim_ids.sort_unstable();
    validate_optional_reason(args.reason.as_deref())?;
    Ok((target, retract_claim_ids, args.reason))
}

fn conflict_target(
    conflict_id: &Value,
    expected_revision: i64,
    expected_member_count: Option<i64>,
) -> ServiceResult<ConflictTarget> {
    let conflict_id = parse_safe_id(conflict_id).map_err(|_| {
        ServiceError::InvalidRequest(format!(
            "conflict_id must be an integer between 1 and {MAX_SAFE_INTEGER}"
        ))
    })?;
    if !(1..=MAX_SAFE_INTEGER).contains(&expected_revision) {
        return Err(ServiceError::InvalidRequest(format!(
            "expected_revision must be between 1 and {MAX_SAFE_INTEGER}"
        )));
    }
    if expected_member_count.is_some_and(|count| !(1..=MAX_CONFLICT_MEMBER_COUNT).contains(&count))
    {
        return Err(ServiceError::InvalidRequest(format!(
            "expected_member_count must be between 1 and {MAX_CONFLICT_MEMBER_COUNT}"
        )));
    }
    Ok(ConflictTarget {
        conflict_id,
        expected_revision,
        expected_member_count,
    })
}

fn validate_optional_reason(reason: Option<&str>) -> ServiceResult<()> {
    if let Some(reason) = reason {
        validate_lifecycle_reason(reason).map_err(ServiceError::InvalidRequest)?;
    }
    Ok(())
}

fn required_idempotency_key(action: RememberAction, key: Option<String>) -> ServiceResult<String> {
    key.ok_or_else(|| {
        ServiceError::InvalidRequest(format!(
            "remember({}) requires idempotency_key",
            action.as_str()
        ))
    })
}

/// The claim id of a synthetic `claim:{id}` chunk written by record.
///
/// The coordinate is the reserved chunk id and source, not the bounded
/// `extra` metadata, which retrieval elides above its byte limit.
fn synthetic_claim_id(hit: &RecallHit) -> Option<i64> {
    if hit.source != SYNTHETIC_CLAIM_SOURCE {
        return None;
    }
    hit.chunk_id
        .strip_prefix("claim:")
        .and_then(|id| id.parse::<i64>().ok())
        .filter(|id| (1..=MAX_SAFE_INTEGER).contains(id) && hit.chunk_id == format!("claim:{id}"))
}

fn synthetic_claim_ids(hits: &[RecallHit]) -> Vec<i64> {
    let mut ids = hits
        .iter()
        .filter_map(synthetic_claim_id)
        .collect::<Vec<_>>();
    ids.sort_unstable();
    ids.dedup();
    ids
}

/// A chunk page after lifecycle hiding.
struct LifecyclePage {
    hits: Vec<RecallHit>,
    /// Claims whose synthetic hits ranked within the page but were hidden.
    hidden_claim_ids: Vec<i64>,
    /// The page is short only because hidden hits filled the largest window.
    underfilled: bool,
}

/// Fill a page of at most `limit` hits in rank order: ordinary hits and
/// synthetic claim hits whose claim is still lifecycle-current. A synthetic
/// hit whose claim is not current, or no longer exists, is skipped, and its
/// claim id is reported when it ranked ahead of the page's last kept hit.
fn page_lifecycle_hits(
    window: Vec<RecallHit>,
    states: &[(i64, ClaimState)],
    limit: usize,
) -> (Vec<RecallHit>, Vec<i64>) {
    let states = states.iter().copied().collect::<HashMap<_, _>>();
    let mut kept = Vec::with_capacity(limit.min(window.len()));
    let mut hidden = Vec::new();
    for hit in window {
        if kept.len() >= limit {
            break;
        }
        match synthetic_claim_id(&hit) {
            Some(claim_id)
                if !states
                    .get(&claim_id)
                    .is_some_and(|state| state.is_current()) =>
            {
                hidden.push(claim_id);
            }
            _ => kept.push(hit),
        }
    }
    hidden.sort_unstable();
    hidden.dedup();
    (kept, hidden)
}

/// Largest retrieval window a lifecycle-filtered chunk page refills to: the
/// tool's own hit bound, which also bounds the claim-state lookup.
const MAX_LIFECYCLE_SEARCH_WINDOW: usize = MAX_TOOL_RESULTS;
const LIFECYCLE_SEARCH_WINDOW_GROWTH: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LifecycleRefill {
    /// The page is full, or retrieval returned everything it had.
    Done,
    /// Hidden hits shorted the page; retrieve again with this window.
    Grow(usize),
    /// Hidden hits shorted the page at the largest window.
    Underfilled,
}

/// Decide whether a page shorted by hidden hits is refilled. `returned` is
/// the number of hits the last retrieval window of size `window` yielded.
fn next_lifecycle_window(
    window: usize,
    returned: usize,
    kept: usize,
    limit: usize,
) -> LifecycleRefill {
    if kept >= limit || returned < window {
        LifecycleRefill::Done
    } else if window >= MAX_LIFECYCLE_SEARCH_WINDOW {
        LifecycleRefill::Underfilled
    } else {
        LifecycleRefill::Grow(
            window
                .saturating_mul(LIFECYCLE_SEARCH_WINDOW_GROWTH)
                .min(MAX_LIFECYCLE_SEARCH_WINDOW),
        )
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchArgs {
    query: String,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    max_per_source_id: Option<usize>,
    #[serde(default)]
    min_score: Option<f32>,
    #[serde(default)]
    intent: Option<RecallIntent>,
    #[serde(default)]
    include_history: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GetArgs {
    #[serde(default)]
    kind: Option<String>,
    id: Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConflictArgs {
    #[serde(default)]
    include_resolved: bool,
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyArgs {}

fn from_arguments<T: for<'de> Deserialize<'de>>(
    arguments: Map<String, Value>,
    operation: &str,
) -> ServiceResult<T> {
    serde_json::from_value(Value::Object(arguments))
        .map_err(|error| ServiceError::InvalidRequest(format!("{operation}: {error}")))
}

fn bounded_limit(limit: Option<usize>) -> ServiceResult<usize> {
    let limit = limit.unwrap_or(DEFAULT_TOOL_RESULTS);
    if !(1..=MAX_TOOL_RESULTS).contains(&limit) {
        return Err(ServiceError::InvalidRequest(format!(
            "limit must be between 1 and {MAX_TOOL_RESULTS}"
        )));
    }
    Ok(limit)
}

fn validate_search_args(args: &SearchArgs) -> ServiceResult<()> {
    if args.query.trim().is_empty() || args.query.len() > 100_000 {
        return Err(ServiceError::InvalidRequest(
            "query must be between 1 and 100,000 bytes".into(),
        ));
    }
    if let Some(lexeme) = args
        .query
        .split_whitespace()
        .find(|lexeme| lexeme.len() > MAX_TSVECTOR_QUERY_LEXEME_BYTES)
    {
        return Err(ServiceError::InvalidRequest(format!(
            "query contains a whitespace-delimited lexeme of {} UTF-8 bytes; the limit is {MAX_TSVECTOR_QUERY_LEXEME_BYTES} bytes",
            lexeme.len()
        )));
    }
    if args
        .source
        .as_ref()
        .is_some_and(|source| source.trim().is_empty() || source.len() > 256)
    {
        return Err(ServiceError::InvalidRequest(
            "source must be between 1 and 256 bytes when present".into(),
        ));
    }
    if args.include_history && !matches!(args.kind.as_deref(), Some("claim" | "assertion")) {
        return Err(ServiceError::InvalidRequest(
            "include_history is supported only for kind=claim or kind=assertion".into(),
        ));
    }
    Ok(())
}

fn reject_claim_only_unsupported_filters(args: &SearchArgs) -> ServiceResult<()> {
    if args.source.is_some()
        || args.max_per_source_id.is_some()
        || args.min_score.is_some()
        || args.intent.is_some()
    {
        return Err(ServiceError::InvalidRequest(
            "claim search does not support source, max_per_source_id, min_score, or intent; use kind=chunk for those filters"
                .into(),
        ));
    }
    Ok(())
}

fn parse_safe_id(value: &Value) -> ServiceResult<i64> {
    let id = value
        .as_i64()
        .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
        .ok_or_else(|| ServiceError::InvalidRequest("id must be a positive integer".into()))?;
    if !(1..=MAX_SAFE_INTEGER).contains(&id) {
        return Err(ServiceError::InvalidRequest(format!(
            "id must be between 1 and {MAX_SAFE_INTEGER}"
        )));
    }
    Ok(id)
}

fn serialize_conflicts(conflicts: &[Conflict]) -> ServiceResult<Vec<Value>> {
    conflicts
        .iter()
        .map(|conflict| {
            serde_json::to_value(conflict)
                .map_err(|error| ServiceError::Internal(format!("serialize conflict: {error}")))
        })
        .collect()
}

fn compact_claim_hits(mut hits: Vec<SemanticClaimHit>) -> Vec<SemanticClaimHit> {
    const MAX_PASSAGE_CHARS: usize = 2_000;
    for hit in &mut hits {
        hit.claim.text = truncate_chars(&hit.claim.text, MAX_PASSAGE_CHARS);
        hit.claim.support.clear();
        hit.claim.value = None;
        hit.matched_passage = truncate_chars(&hit.matched_passage, MAX_PASSAGE_CHARS);
    }
    hits
}

fn truncate_chars(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        text.to_owned()
    } else {
        format!("{}…", text.chars().take(max_chars).collect::<String>())
    }
}

const fn conflict_projection_complete(conflict: &Conflict) -> bool {
    !conflict.members_truncated && !conflict.member_values_elided
}

fn conflict_coverage(complete: bool, conflicts: &[Conflict]) -> ConflictCoverage {
    let has_unreconciled_detector = conflicts
        .iter()
        .any(|conflict| conflict.detector != FUNCTIONAL_VALUE_CONFLICT_DETECTOR_V2);
    let mut coverage = ConflictCoverage::new(if complete && !has_unreconciled_detector {
        "complete"
    } else {
        "partial"
    });
    coverage.details.insert(
        "detector".into(),
        Value::String(FUNCTIONAL_VALUE_CONFLICT_DETECTOR_V2.into()),
    );
    coverage
        .details
        .insert("scope".into(), Value::String("tenant_project".into()));
    coverage.details.insert(
        "contract".into(),
        Value::String(
            "functional typed same-key lifecycle-current interval contradictions only: different affirmed values or affirmation and negation of the same exact value; no corpus-wide NLI".into(),
        ),
    );
    coverage.details.insert(
        "complete".into(),
        Value::Bool(complete && !has_unreconciled_detector),
    );
    if has_unreconciled_detector {
        coverage.details.insert(
            "reason".into(),
            Value::String("legacy_conflict_detector_unreconciled".into()),
        );
    }
    coverage
}

fn service_error(error: FleetError) -> ServiceError {
    match error {
        FleetError::InvalidScope(message) | FleetError::IdempotencyConflict(message) => {
            ServiceError::InvalidRequest(message)
        }
        FleetError::LifecycleRefused(refusal) => {
            let refusal = *refusal;
            ServiceError::Refused(Refusal {
                code: refusal.code.as_str(),
                message: refusal.message,
                details: refusal.details,
            })
        }
        FleetError::Database(error) => {
            tracing::error!(error = %error, "fleet database operation failed");
            ServiceError::Unavailable("database operation failed".into())
        }
        other => {
            tracing::error!(error = %other, "fleet memory operation failed");
            ServiceError::Internal("memory operation failed".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use ostk_recall_core::{Links, PrivacyTier};
    use uuid::Uuid;

    use crate::ledger::{
        Claim, ClaimKind, ClaimState, CockroachClaimLedger, ConflictReevaluation, LifecycleRefusal,
        RefusalCode,
    };
    use crate::store::cockroach::{EMBEDDING_DIMENSION, RetryPolicy};

    use super::*;

    #[test]
    fn accepts_numeric_or_decimal_string_safe_ids() {
        assert_eq!(parse_safe_id(&json!(42)).unwrap(), 42);
        assert_eq!(parse_safe_id(&json!("42")).unwrap(), 42);
        assert!(parse_safe_id(&json!(9_007_199_254_740_992_i64)).is_err());
    }

    #[test]
    fn assert_route_is_disabled_and_fails_closed() {
        // ADR 0002 D4: with no writer-authority pins and a stub witness loader,
        // `remember(assert)` must fail closed with a typed error and never
        // reach a write path. This pins the enforced half of the enum-variant
        // doc claim without needing a database-backed service.
        let error = CockroachMemoryService::assert_route_disabled();
        assert!(matches!(error, ServiceError::Unavailable(_)));
        let message = error.to_string();
        assert!(message.contains("remember(assert) is disabled"));
        assert!(message.contains("use remember(record)"));
    }

    #[test]
    fn action_argument_parsers_reject_smuggled_fields() {
        let error = from_arguments::<SearchArgs>(
            Map::from_iter([
                ("query".into(), json!("memory")),
                ("agent".into(), json!("impersonated")),
            ]),
            "recall search",
        )
        .unwrap_err();
        assert!(matches!(error, ServiceError::InvalidRequest(_)));
    }

    #[test]
    fn limits_match_public_tool_bound() {
        assert_eq!(bounded_limit(None).unwrap(), DEFAULT_TOOL_RESULTS);
        assert_eq!(
            bounded_limit(Some(MAX_TOOL_RESULTS)).unwrap(),
            MAX_TOOL_RESULTS
        );
        assert!(bounded_limit(Some(0)).is_err());
        assert!(bounded_limit(Some(MAX_TOOL_RESULTS + 1)).is_err());
    }

    #[test]
    fn conflict_coverage_versions_the_active_detector_and_flags_legacy_rows() {
        let current = conflict_coverage(true, &[]);
        assert_eq!(current.status, "complete");
        assert_eq!(
            current.details["detector"],
            FUNCTIONAL_VALUE_CONFLICT_DETECTOR_V2
        );

        let legacy = serde_json::from_value::<Conflict>(json!({
            "id": 3,
            "project": "project",
            "claim_key": "feature::enabled",
            "kind": "contradiction",
            "state": "open",
            "detector": "same_key_typed_value",
            "rationale": "legacy values or polarity differ",
            "revision": 1,
            "detected_at": "2026-08-14T00:00:00Z",
            "last_seen_at": "2026-08-14T00:00:00Z",
            "resolved_at": null,
            "resolution_kind": null,
            "resolution_reason": null,
            "members": [],
        }))
        .unwrap();
        let coverage = conflict_coverage(true, &[legacy]);
        assert_eq!(coverage.status, "partial");
        assert_eq!(coverage.details["complete"], false);
        assert_eq!(
            coverage.details["reason"],
            "legacy_conflict_detector_unreconciled"
        );
    }

    #[test]
    fn fleet_ranking_disables_unscoped_code_prefetch() {
        let overrides = fleet_ranking_overrides();
        assert_eq!(overrides.stratified_code_prefetch, Some(0));
        assert!(overrides.identifier_code_boost.is_none());
        assert!(overrides.weights.is_none());
    }

    #[test]
    fn conflict_match_diagnostics_distinguish_direct_and_source_triggers() {
        let hits = [
            ("claim-seven", Some(7)),
            ("source-eight", None),
            ("unrelated", None),
        ]
        .into_iter()
        .map(|(chunk_id, claim_id)| {
            serde_json::from_value::<RecallHit>(json!({
                "chunk_id": chunk_id,
                "source": "markdown",
                "source_id": format!("docs/{chunk_id}.md"),
                "snippet": chunk_id,
                "score": 1.0,
                "links": {},
                "extra": claim_id.map_or_else(|| json!({}), |id| json!({ "claim_id": id })),
            }))
            .unwrap()
        })
        .collect::<Vec<_>>();
        let mut conflict = serde_json::from_value::<Conflict>(json!({
            "id": 3,
            "project": "project",
            "claim_key": "feature::enabled",
            "kind": "contradiction",
            "state": "open",
            "detector": "same_key_typed_value",
            "rationale": "typed values disagree",
            "revision": 1,
            "detected_at": "2026-08-14T00:00:00Z",
            "last_seen_at": "2026-08-14T00:00:00Z",
            "resolved_at": null,
            "resolution_kind": null,
            "resolution_reason": null,
            "members": [],
        }))
        .unwrap();
        conflict.trigger_claim_ids = vec![7, 8];
        let matches = conflict_match_diagnostics(
            &[conflict],
            &hits,
            &[SupportedClaimCoordinate {
                claim_id: 8,
                chunk_id: "source-eight".into(),
            }],
        )
        .unwrap();

        assert_eq!(matches[0]["conflict_id"], 3);
        assert_eq!(matches[0]["best_fused_hit_rank"], 1);
        assert_eq!(matches[0]["direct_claim_ids"], json!([7]));
        assert_eq!(
            matches[0]["source_support"],
            json!([{
                "claim_id": 8,
                "chunk_id": "source-eight",
                "fused_hit_rank": 2,
            }])
        );
    }

    #[test]
    fn conflict_match_diagnostics_fail_closed_without_exact_trigger() {
        let mut conflict = serde_json::from_value::<Conflict>(json!({
            "id": 3,
            "project": "project",
            "claim_key": "feature::enabled",
            "kind": "contradiction",
            "state": "open",
            "detector": "same_key_typed_value",
            "rationale": "typed values disagree",
            "revision": 1,
            "detected_at": "2026-08-14T00:00:00Z",
            "last_seen_at": "2026-08-14T00:00:00Z",
            "resolved_at": null,
            "resolution_kind": null,
            "resolution_reason": null,
            "members": [],
        }))
        .unwrap();
        conflict.trigger_claim_ids = vec![9];

        assert!(conflict_match_diagnostics(&[conflict], &[], &[]).is_err());
    }

    #[test]
    fn support_claim_merge_deduplicates_before_enforcing_the_bound() {
        let mut direct = (1..i64::try_from(MAX_TOOL_RESULTS).unwrap()).collect::<Vec<_>>();
        let supported = (1..=i64::try_from(MAX_TOOL_RESULTS + 1).unwrap()).collect::<Vec<_>>();
        assert!(merge_supported_claim_ids(&mut direct, supported));
        assert_eq!(direct.len(), MAX_TOOL_RESULTS);
        assert_eq!(
            direct.last(),
            Some(&i64::try_from(MAX_TOOL_RESULTS).unwrap())
        );
    }

    #[test]
    fn final_hit_metadata_is_joined_by_id_and_reports_elision() {
        let mut hits = ["first", "second"]
            .into_iter()
            .map(|id| {
                serde_json::from_value::<RecallHit>(json!({
                    "chunk_id": id,
                    "source": "markdown",
                    "source_id": format!("docs/{id}.md"),
                    "snippet": id,
                    "score": 1.0,
                    "links": {},
                }))
                .unwrap()
            })
            .collect::<Vec<_>>();
        let metadata = vec![
            RetrievalHitMetadata {
                chunk_id: "second".into(),
                links: Links::default(),
                extra: json!({ "claim_id": 7 }),
                links_elided: false,
                extra_elided: false,
            },
            RetrievalHitMetadata {
                chunk_id: "first".into(),
                links: Links::default(),
                extra: json!({}),
                links_elided: true,
                extra_elided: false,
            },
        ];

        assert_eq!(apply_retrieval_metadata(&mut hits, metadata), 1);
        assert_eq!(hits[0].chunk_id, "first");
        assert_eq!(hits[0].extra, json!({}));
        assert_eq!(hits[1].chunk_id, "second");
        assert_eq!(hits[1].extra.get("claim_id"), Some(&json!(7)));
    }

    #[test]
    fn validates_query_size_and_rejects_unadvertised_time_filters() {
        let mut args = SearchArgs {
            query: "memory".into(),
            kind: None,
            source: None,
            limit: None,
            max_per_source_id: None,
            min_score: None,
            intent: None,
            include_history: false,
        };
        assert!(validate_search_args(&args).is_ok());
        args.include_history = true;
        assert!(validate_search_args(&args).is_err());
        args.kind = Some("claim".into());
        assert!(validate_search_args(&args).is_ok());
        args.kind = Some("assertion".into());
        assert!(validate_search_args(&args).is_ok());
        args.kind = Some("chunk".into());
        assert!(validate_search_args(&args).is_err());
        args.include_history = false;
        args.kind = None;
        args.query = "x".repeat(100_001);
        assert!(validate_search_args(&args).is_err());
        args.query = "é".repeat(MAX_TSVECTOR_QUERY_LEXEME_BYTES / 2);
        assert!(validate_search_args(&args).is_ok());
        args.query.push('é');
        assert!(validate_search_args(&args).is_err());

        let error = from_arguments::<SearchArgs>(
            Map::from_iter([
                ("query".into(), json!("memory")),
                ("since".into(), json!("2026-08-13T00:00:00Z")),
            ]),
            "recall search",
        )
        .unwrap_err();
        assert!(matches!(error, ServiceError::InvalidRequest(_)));
    }

    #[test]
    fn claim_search_rejects_filters_it_cannot_enforce() {
        let args = SearchArgs {
            query: "memory".into(),
            kind: Some("claim".into()),
            source: Some("markdown".into()),
            limit: None,
            max_per_source_id: None,
            min_score: None,
            intent: None,
            include_history: false,
        };
        assert!(reject_claim_only_unsupported_filters(&args).is_err());
    }

    #[test]
    fn public_document_and_code_categories_are_valid_exact_source_filters() {
        for source in ["markdown", "code"] {
            let args = from_arguments::<SearchArgs>(
                Map::from_iter([
                    ("query".into(), json!("where is this configured?")),
                    ("kind".into(), json!("chunk")),
                    ("source".into(), json!(source)),
                    ("limit".into(), json!(8)),
                    ("max_per_source_id".into(), json!(1)),
                ]),
                "recall search",
            )
            .unwrap();

            validate_search_args(&args).unwrap();
            assert_eq!(args.kind.as_deref(), Some("chunk"));
            assert_eq!(args.source.as_deref(), Some(source));
            assert_eq!(args.max_per_source_id, Some(1));
        }
    }

    #[test]
    fn public_claim_category_is_valid_only_without_chunk_filters() {
        let args = from_arguments::<SearchArgs>(
            Map::from_iter([
                ("query".into(), json!("what did the agents decide?")),
                ("kind".into(), json!("claim")),
                ("limit".into(), json!(8)),
            ]),
            "recall search",
        )
        .unwrap();

        validate_search_args(&args).unwrap();
        reject_claim_only_unsupported_filters(&args).unwrap();
        assert_eq!(args.kind.as_deref(), Some("claim"));
        assert!(args.source.is_none());
        assert!(args.max_per_source_id.is_none());
    }

    #[test]
    fn remember_domain_validation_errors_are_client_errors() {
        let input = ClaimInput {
            kind: crate::ledger::ClaimKind::Note,
            text: "x".repeat(16_001),
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
        let error = input.validate().unwrap_err();
        let classified = match error {
            FleetError::Memory(message) => ServiceError::InvalidRequest(message),
            other => service_error(other),
        };
        assert!(
            matches!(classified, ServiceError::InvalidRequest(message) if message.contains("whitespace-delimited lexeme"))
        );
    }

    #[test]
    fn idempotency_conflicts_are_client_errors() {
        let classified = service_error(FleetError::IdempotencyConflict(
            "idempotency key was already used for a different mutation".into(),
        ));
        assert!(matches!(
            classified,
            ServiceError::InvalidRequest(message)
                if message.contains("idempotency key was already used")
        ));
    }

    #[test]
    fn committed_remember_degrades_when_conflict_projection_fails() {
        let now = Utc::now();
        let mutation = ClaimMutation {
            operation: "record".into(),
            claim: Claim {
                id: 41,
                project: "project".into(),
                kind: ClaimKind::Fact,
                claim_key: Some("fleet::database".into()),
                subject: Some("fleet".into()),
                predicate: Some("database".into()),
                value: Some(json!("cockroachdb")),
                text: "The fleet database is CockroachDB.".into(),
                polarity: 1,
                state: ClaimState::Disputed,
                origin: "operator_asserted".into(),
                actor: Some("architect".into()),
                confidence: 1.0,
                valid_from: None,
                valid_to: None,
                superseded_by: None,
                revision: 1,
                conflict_eligible: true,
                created_at: now,
                updated_at: now,
                support: Vec::new(),
                conflict_ids: vec![9],
            },
            superseded: None,
            idempotent_replay: false,
            conflicts_opened: vec![9],
            conflicts_resolved: Vec::new(),
            claims_restored: Vec::new(),
            reevaluation: None,
        };

        let result = committed_remember_result(
            &mutation,
            Err(FleetError::Memory("sensitive backend detail".into())),
        );

        assert_eq!(result.data["claim"]["id"], 41);
        assert!(result.conflicts.is_empty());
        assert_eq!(result.conflict_coverage.status, "partial");
        assert_eq!(
            result.conflict_coverage.details["reason"],
            "post_commit_projection_unavailable"
        );
        assert_eq!(
            result.warnings[0]["code"],
            "post_commit_projection_unavailable"
        );
        assert_eq!(
            result.diagnostics["conflict_projection"]["mutation_committed"],
            true
        );
        assert_eq!(result.diagnostics["transaction"], "serializable");
        assert!(
            !serde_json::to_string(&result)
                .unwrap()
                .contains("sensitive")
        );
    }

    #[test]
    fn claim_search_projection_preserves_authored_text() {
        let now = Utc::now();
        let hit = SemanticClaimHit {
            claim: Claim {
                id: 7,
                project: "project".into(),
                kind: ClaimKind::Decision,
                claim_key: Some("fleet::database".into()),
                subject: Some("fleet".into()),
                predicate: Some("database".into()),
                value: Some(json!("cockroachdb")),
                text: "Use CockroachDB for shared fleet memory.".into(),
                polarity: 1,
                state: ClaimState::Active,
                origin: "operator_asserted".into(),
                actor: Some("architect".into()),
                confidence: 1.0,
                valid_from: None,
                valid_to: None,
                superseded_by: None,
                revision: 1,
                conflict_eligible: true,
                created_at: now,
                updated_at: now,
                support: Vec::new(),
                conflict_ids: Vec::new(),
            },
            similarity: 0.9,
            passage_index: 0,
            matched_passage: "Use CockroachDB for shared fleet memory.\nkind: decision\nsubject: fleet\npredicate: database".into(),
        };

        let projected = compact_claim_hits(vec![hit]);
        assert_eq!(
            projected[0].claim.text,
            "Use CockroachDB for shared fleet memory."
        );
        assert!(projected[0].matched_passage.contains("kind: decision"));
        assert!(projected[0].claim.value.is_none());
    }

    struct OfflineEmbedder;

    impl ChunkEmbedder for OfflineEmbedder {
        fn dim(&self) -> usize {
            EMBEDDING_DIMENSION
        }

        fn model_id(&self) -> &'static str {
            "offline-test"
        }

        fn encode_batch(&self, texts: &[&str]) -> Vec<Vec<f32>> {
            texts
                .iter()
                .map(|_| vec![0.0; EMBEDDING_DIMENSION])
                .collect()
        }
    }

    fn offline_scope() -> FleetScope {
        FleetScope::new(
            Uuid::from_u128(1),
            "project",
            "agent-a",
            None,
            PrivacyTier::T1Project,
        )
        .unwrap()
    }

    /// A service whose pool never connects: anything that reaches I/O fails,
    /// so a passing assertion proves the decision was made before I/O.
    fn offline_service(surface: RememberSurface) -> CockroachMemoryService {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_millis(200))
            .connect_lazy("postgresql://root@127.0.0.1:1/offline")
            .unwrap();
        let scope = offline_scope();
        let embedder: Arc<dyn ChunkEmbedder> = Arc::new(OfflineEmbedder);
        let ledger = Arc::new(
            CockroachClaimLedger::new(
                pool.clone(),
                scope.clone(),
                embedder.clone(),
                RetryPolicy::default(),
            )
            .unwrap(),
        );
        let store = Arc::new(CockroachStore::from_pool(pool, scope.clone()).unwrap());
        CockroachMemoryService::new(scope, store, ledger, embedder)
            .unwrap()
            .with_lifecycle(LifecycleServing {
                surface,
                hide_non_current_claim_chunks: surface.claim_lifecycle,
                lifecycle_overlay: surface.conflict_lifecycle,
            })
    }

    const CLAIM_LIFECYCLE: RememberSurface = RememberSurface {
        claim_lifecycle: true,
        conflict_lifecycle: false,
    };

    const CONFLICT_LIFECYCLE: RememberSurface = RememberSurface {
        claim_lifecycle: true,
        conflict_lifecycle: true,
    };

    fn retract_arguments(value: &Value) -> Map<String, Value> {
        value.as_object().unwrap().clone()
    }

    fn fixture_mutation(conflict_ids: Vec<i64>, idempotent_replay: bool) -> ClaimMutation {
        let now = Utc::now();
        ClaimMutation {
            operation: "record".into(),
            claim: Claim {
                id: 41,
                project: "project".into(),
                kind: ClaimKind::Fact,
                claim_key: Some("fleet::database".into()),
                subject: Some("fleet".into()),
                predicate: Some("database".into()),
                value: Some(json!("cockroachdb")),
                text: "The fleet database is CockroachDB.".into(),
                polarity: 1,
                state: ClaimState::Disputed,
                origin: "operator_asserted".into(),
                actor: Some("agent-a".into()),
                confidence: 1.0,
                valid_from: None,
                valid_to: None,
                superseded_by: None,
                revision: 2,
                conflict_eligible: true,
                created_at: now,
                updated_at: now,
                support: Vec::new(),
                conflict_ids,
            },
            superseded: None,
            idempotent_replay,
            conflicts_opened: Vec::new(),
            conflicts_resolved: Vec::new(),
            claims_restored: Vec::new(),
            reevaluation: None,
        }
    }

    fn fixture_conflict(id: i64, detector: &str) -> Conflict {
        serde_json::from_value(json!({
            "id": id,
            "project": "project",
            "claim_key": "fleet::database",
            "kind": "contradiction",
            "state": "resolved",
            "detector": detector,
            "rationale": "fixture",
            "revision": 2,
            "detected_at": "2026-09-01T00:00:00Z",
            "last_seen_at": "2026-09-01T00:00:00Z",
            "resolved_at": "2026-09-02T00:00:00Z",
            "resolution_kind": "no_current_incompatibility",
            "resolution_reason": "fixture",
            "members": [],
        }))
        .unwrap()
    }

    fn fixture_hit(chunk_id: &str, extra: &Value) -> RecallHit {
        let source = if chunk_id.starts_with("claim:") {
            SYNTHETIC_CLAIM_SOURCE
        } else {
            "markdown"
        };
        serde_json::from_value(json!({
            "chunk_id": chunk_id,
            "source": source,
            "source_id": chunk_id,
            "snippet": chunk_id,
            "score": 1.0,
            "links": {},
            "extra": extra,
        }))
        .unwrap()
    }

    #[test]
    fn lifecycle_refusal_maps_to_refused_not_internal() {
        let refusal = LifecycleRefusal::new(
            RefusalCode::StaleRevision,
            "claim 41 is at revision 3 (disputed)",
            json!({ "claim_id": 41, "current_revision": 3, "current_state": "disputed" }),
        );
        let ServiceError::Refused(mapped) = service_error(refusal.into()) else {
            panic!("a lifecycle refusal must stay a typed refusal");
        };
        assert_eq!(mapped.code, "stale_revision");
        assert_eq!(mapped.message, "claim 41 is at revision 3 (disputed)");
        assert_eq!(mapped.details["current_revision"], 3);
    }

    #[test]
    fn retract_args_reject_unknown_fields_unsafe_ids_and_blank_reason() {
        let (target, reason) = parse_retract_arguments(retract_arguments(
            &json!({ "claim_id": 41, "expected_revision": 2 }),
        ))
        .unwrap();
        assert_eq!(
            target,
            ClaimTarget {
                claim_id: 41,
                expected_revision: 2
            }
        );
        assert!(reason.is_none());
        let (target, reason) = parse_retract_arguments(retract_arguments(
            &json!({ "claim_id": "41", "expected_revision": 2, "reason": "wrong value" }),
        ))
        .unwrap();
        assert_eq!(target.claim_id, 41);
        assert_eq!(reason.as_deref(), Some("wrong value"));

        for rejected in [
            json!({ "claim_id": 41, "expected_revision": 2, "text": "smuggled" }),
            json!({ "claim_id": 41, "expected_revision": 2, "agent": "other" }),
            json!({ "claim_id": 0, "expected_revision": 2 }),
            json!({ "claim_id": -1, "expected_revision": 2 }),
            json!({ "claim_id": 9_007_199_254_740_992_i64, "expected_revision": 2 }),
            json!({ "claim_id": "forty-one", "expected_revision": 2 }),
            json!({ "claim_id": 41 }),
            json!({ "claim_id": 41, "expected_revision": 0 }),
            json!({ "claim_id": 41, "expected_revision": "2" }),
            json!({ "claim_id": 41, "expected_revision": 2, "reason": " \u{200B} " }),
            json!({ "claim_id": 41, "expected_revision": 2, "reason": "" }),
        ] {
            assert!(
                matches!(
                    parse_retract_arguments(retract_arguments(&rejected)),
                    Err(ServiceError::InvalidRequest(_))
                ),
                "{rejected} must be a client error"
            );
        }
    }

    #[test]
    fn every_reason_the_lifecycle_schema_admits_is_accepted() {
        // JSON Schema maxLength counts characters; so must the server, or a
        // schema-valid multi-byte note would be refused.
        let tool = crate::mcp::remember_tool_for(CLAIM_LIFECYCLE);
        let reason = &tool["inputSchema"]["properties"]["reason"];
        let max = usize::try_from(reason["maxLength"].as_u64().unwrap()).unwrap();
        let min = usize::try_from(reason["minLength"].as_u64().unwrap()).unwrap();
        let retract = |reason: String| {
            parse_retract_arguments(retract_arguments(
                &json!({ "claim_id": 41, "expected_revision": 2, "reason": reason }),
            ))
        };
        for admitted in [
            "\u{7406}".repeat(max),
            "\u{1F4DD}".repeat(max),
            "x".repeat(max),
            "x".repeat(min),
        ] {
            assert!(retract(admitted).is_ok());
        }
        assert!(retract("\u{7406}".repeat(max + 1)).is_err());
    }

    fn successor_arguments(extra: &Value) -> Map<String, Value> {
        let mut arguments = retract_arguments(&json!({
            "claim_id": 41,
            "expected_revision": 3,
            "kind": "decision",
            "text": "Use CockroachDB 26 for fleet memory",
            "subject": "fleet",
            "predicate": "database",
            "value": "cockroachdb-26",
        }));
        arguments.extend(retract_arguments(extra));
        arguments
    }

    #[test]
    fn supersede_arguments_split_and_reject_unknown() {
        let (target, reason, successor) = split_supersede_arguments(successor_arguments(
            &json!({ "claim_id": "41", "reason": "storage review" }),
        ))
        .unwrap();
        assert_eq!(
            target,
            ClaimTarget {
                claim_id: 41,
                expected_revision: 3
            }
        );
        assert_eq!(reason.as_deref(), Some("storage review"));
        // Everything else is the successor, with record's defaults.
        assert_eq!(successor.kind, ClaimKind::Decision);
        assert_eq!(successor.text, "Use CockroachDB 26 for fleet memory");
        assert_eq!(successor.value, Some(json!("cockroachdb-26")));
        assert_eq!(successor.origin, "operator_asserted");
        assert_eq!(successor.polarity, 1);

        let mut without_target = successor_arguments(&json!({}));
        without_target.remove("claim_id");
        let mut without_revision = successor_arguments(&json!({}));
        without_revision.remove("expected_revision");
        let mut without_text = successor_arguments(&json!({}));
        without_text.remove("text");
        for rejected in [
            without_target,
            without_revision,
            without_text,
            retract_arguments(&json!({ "claim_id": 41, "expected_revision": 3 })),
            successor_arguments(&json!({ "conflict_id": 9 })),
            successor_arguments(&json!({ "agent": "other" })),
            successor_arguments(&json!({ "tenant_id": "other" })),
            successor_arguments(&json!({ "claim_id": 0 })),
            successor_arguments(&json!({ "claim_id": 9_007_199_254_740_992_i64 })),
            successor_arguments(&json!({ "expected_revision": 0 })),
            successor_arguments(&json!({ "reason": " " })),
            successor_arguments(&json!({ "kind": "memo" })),
        ] {
            let rendered = Value::Object(rejected.clone());
            assert!(
                matches!(
                    split_supersede_arguments(rejected),
                    Err(ServiceError::InvalidRequest(_))
                ),
                "{rendered} must be a client error"
            );
        }
    }

    #[tokio::test]
    async fn lifecycle_actions_require_idempotency_key() {
        let service = offline_service(CLAIM_LIFECYCLE);
        for (action, arguments) in [
            (
                RememberAction::Retract,
                retract_arguments(&json!({ "claim_id": 41, "expected_revision": 2 })),
            ),
            (RememberAction::Supersede, successor_arguments(&json!({}))),
        ] {
            let error = FleetMemoryService::remember(
                &service,
                offline_scope(),
                RememberRequest::new(action, None, arguments),
            )
            .await
            .unwrap_err();
            assert!(
                matches!(&error, ServiceError::InvalidRequest(message)
                    if *message == format!("remember({}) requires idempotency_key", action.as_str())),
                "{error}"
            );
        }
    }

    #[tokio::test]
    async fn supersede_successor_is_validated_before_io() {
        let service = offline_service(CLAIM_LIFECYCLE);
        for (extra, expected) in [
            (
                json!({ "origin": "source_derived" }),
                "remember(supersede) only accepts operator_asserted origin",
            ),
            (
                json!({ "actor": "agent-b" }),
                "claim actor must match the authenticated fleet agent",
            ),
            (json!({ "polarity": 0 }), "claim polarity must be -1 or 1"),
            (
                json!({ "text": " padded " }),
                "claim text must not have leading or trailing whitespace",
            ),
        ] {
            let error = FleetMemoryService::remember(
                &service,
                offline_scope(),
                RememberRequest::new(
                    RememberAction::Supersede,
                    Some("supersede/41".into()),
                    successor_arguments(&extra),
                ),
            )
            .await
            .unwrap_err();
            assert!(
                matches!(&error, ServiceError::InvalidRequest(message) if message.starts_with(expected)),
                "{extra}: {error}"
            );
        }
    }

    #[tokio::test]
    async fn surfaces_gate_lifecycle_actions_and_conflict_lookup_before_io() {
        let record_only = offline_service(RememberSurface::RECORD_ONLY);
        assert_eq!(
            FleetMemoryService::remember_surface(&record_only),
            RememberSurface::RECORD_ONLY
        );
        // With no key there is no receipt to replay, so the refusal needs no I/O.
        let error = FleetMemoryService::remember(
            &record_only,
            offline_scope(),
            RememberRequest::new(
                RememberAction::Retract,
                None,
                retract_arguments(&json!({ "claim_id": 41, "expected_revision": 2 })),
            ),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(&error, ServiceError::Refused(refusal) if refusal.code == "lifecycle_unavailable"),
            "{error}"
        );
        let error = FleetMemoryService::remember(
            &record_only,
            offline_scope(),
            RememberRequest::new(
                RememberAction::Supersede,
                None,
                successor_arguments(&json!({})),
            ),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(&error, ServiceError::Refused(refusal) if refusal.code == "lifecycle_unavailable"),
            "{error}"
        );
        // A keyed request may already have committed on a writer that served
        // it. Its refusal promises the key is unused, so when the receipt
        // cannot be checked the outcome is unknown rather than not_applied.
        let error = FleetMemoryService::remember(
            &record_only,
            offline_scope(),
            RememberRequest::new(
                RememberAction::Retract,
                Some("retract/41".into()),
                retract_arguments(&json!({ "claim_id": 41, "expected_revision": 2 })),
            ),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, ServiceError::Unavailable(_)), "{error}");
        let error = FleetMemoryService::recall(
            &record_only,
            offline_scope(),
            RecallRequest::new(
                RecallAction::Get,
                retract_arguments(&json!({ "kind": "conflict", "id": 9 })),
            ),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(&error, ServiceError::InvalidRequest(message) if message.contains("not supported")),
            "{error}"
        );

        let lifecycle = offline_service(CLAIM_LIFECYCLE);
        assert_eq!(
            FleetMemoryService::remember_surface(&lifecycle),
            CLAIM_LIFECYCLE
        );
        let error = FleetMemoryService::recall(
            &lifecycle,
            offline_scope(),
            RecallRequest::new(
                RecallAction::Get,
                retract_arguments(&json!({ "kind": "conflict", "id": 0 })),
            ),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, ServiceError::InvalidRequest(_)), "{error}");
    }

    fn conflict_arguments(extra: &Value) -> Map<String, Value> {
        let mut arguments = retract_arguments(&json!({
            "conflict_id": 9,
            "expected_revision": 3,
        }));
        arguments.extend(retract_arguments(extra));
        arguments
    }

    #[test]
    fn acknowledge_resolve_args_reject_unknown_and_bounds() {
        let (target, reason) =
            parse_acknowledge_arguments(conflict_arguments(&json!({ "reason": "on it" }))).unwrap();
        assert_eq!(
            target,
            ConflictTarget {
                conflict_id: 9,
                expected_revision: 3,
                expected_member_count: None,
            }
        );
        assert_eq!(reason.as_deref(), Some("on it"));

        let (target, ids, reason) = parse_resolve_arguments(conflict_arguments(&json!({
            "conflict_id": "9",
            "expected_member_count": 2,
            "retract_claim_ids": [43, "41"],
        })))
        .unwrap();
        assert_eq!(target.conflict_id, 9);
        assert_eq!(target.expected_member_count, Some(2));
        assert_eq!(ids, [41, 43], "ids are sorted");
        assert!(reason.is_none());
        // With no claims named, resolve only re-verifies the conflict.
        let (_, ids, _) =
            parse_resolve_arguments(conflict_arguments(&json!({ "expected_member_count": 2 })))
                .unwrap();
        assert!(ids.is_empty());

        let too_many = (1..=33).collect::<Vec<i64>>();
        for rejected in [
            json!({ "claim_id": 41 }),
            json!({ "expected_member_count": 2 }),
            json!({ "retract_claim_ids": [41] }),
            json!({ "text": "smuggled" }),
            json!({ "conflict_id": 0 }),
            json!({ "conflict_id": 9_007_199_254_740_992_i64 }),
            json!({ "expected_revision": 0 }),
            json!({ "reason": " " }),
        ] {
            assert!(
                matches!(
                    parse_acknowledge_arguments(conflict_arguments(&rejected)),
                    Err(ServiceError::InvalidRequest(_))
                ),
                "acknowledge {rejected}"
            );
        }
        for rejected in [
            json!({}),
            json!({ "expected_member_count": 0 }),
            json!({ "expected_member_count": 4_097 }),
            json!({ "expected_member_count": 2, "retract_claim_ids": [41, 41] }),
            json!({ "expected_member_count": 2, "retract_claim_ids": [0] }),
            json!({ "expected_member_count": 2, "retract_claim_ids": too_many }),
            json!({ "expected_member_count": 2, "claim_id": 41 }),
            json!({ "expected_member_count": 2, "winner": 41 }),
            json!({ "expected_member_count": 2, "reason": "" }),
        ] {
            assert!(
                matches!(
                    parse_resolve_arguments(conflict_arguments(&rejected)),
                    Err(ServiceError::InvalidRequest(_))
                ),
                "resolve {rejected}"
            );
        }
    }

    #[tokio::test]
    async fn conflict_actions_are_gated_before_io() {
        let resolve = || conflict_arguments(&json!({ "expected_member_count": 2 }));
        // Without the conflict surface there is no key to replay, so the
        // refusal needs no I/O.
        for (action, arguments) in [
            (RememberAction::Acknowledge, conflict_arguments(&json!({}))),
            (RememberAction::Resolve, resolve()),
        ] {
            let error = FleetMemoryService::remember(
                &offline_service(CLAIM_LIFECYCLE),
                offline_scope(),
                RememberRequest::new(action, None, arguments),
            )
            .await
            .unwrap_err();
            assert!(
                matches!(&error, ServiceError::Refused(refusal) if refusal.code == "lifecycle_unavailable"),
                "{error}"
            );
        }

        let served = offline_service(CONFLICT_LIFECYCLE);
        for (action, arguments) in [
            (RememberAction::Acknowledge, conflict_arguments(&json!({}))),
            (RememberAction::Resolve, resolve()),
        ] {
            let error = FleetMemoryService::remember(
                &served,
                offline_scope(),
                RememberRequest::new(action, None, arguments.clone()),
            )
            .await
            .unwrap_err();
            assert!(
                matches!(&error, ServiceError::InvalidRequest(message)
                    if *message == format!("remember({}) requires idempotency_key", action.as_str())),
                "{error}"
            );
            // A ledger that never passed the startup probe refuses before it
            // touches the database, whatever the surface says.
            let error = FleetMemoryService::remember(
                &served,
                offline_scope(),
                RememberRequest::new(action, Some("conflict/9".into()), arguments),
            )
            .await
            .unwrap_err();
            assert!(
                matches!(&error, ServiceError::Refused(refusal) if refusal.code == "lifecycle_unavailable"),
                "{error}"
            );
        }
    }

    #[test]
    fn lifecycle_overlay_outcome_marks_coverage_without_failing() {
        let mut coverage = conflict_coverage(true, &[]);
        let mut warnings = Vec::new();
        mark_lifecycle_overlay(&mut coverage, &mut warnings, None);
        assert!(coverage.details.get("lifecycle_overlay").is_none());
        assert!(warnings.is_empty());

        mark_lifecycle_overlay(
            &mut coverage,
            &mut warnings,
            Some(OverlayOutcome::Evaluated),
        );
        assert_eq!(coverage.details["lifecycle_overlay"], "evaluated");
        assert!(warnings.is_empty());

        mark_lifecycle_overlay(
            &mut coverage,
            &mut warnings,
            Some(OverlayOutcome::Unavailable),
        );
        assert_eq!(coverage.details["lifecycle_overlay"], "unavailable");
        assert_eq!(
            coverage.status, "complete",
            "the conflicts are still complete"
        );
        assert_eq!(warnings[0]["code"], "lifecycle_overlay_unavailable");
    }

    #[test]
    fn conflict_mutation_response_projects_its_conflict() {
        let mutation = ConflictMutation {
            operation: "acknowledge".into(),
            conflict_id: 9,
            conflict_state: "open".into(),
            conflict_revision: 2,
            member_count: 2,
            applied: false,
            status: Some("already_acknowledged".into()),
            lifecycle_event: None,
            claims_retracted: Vec::new(),
            claims_restored: Vec::new(),
            conflicts_resolved: Vec::new(),
            reevaluation: None,
            idempotent_replay: true,
        };
        let v2 = fixture_conflict(9, FUNCTIONAL_VALUE_CONFLICT_DETECTOR_V2);
        let result = committed_conflict_result(&mutation, &[9], Ok(vec![v2]));
        assert_eq!(result.data["conflict_id"], 9);
        assert_eq!(result.data["applied"], false);
        assert_eq!(result.data["status"], "already_acknowledged");
        assert_eq!(result.conflict_coverage.status, "complete");
        assert_eq!(result.conflicts[0]["id"], 9);
        let missing = committed_conflict_result(&mutation, &[9], Ok(Vec::new()));
        assert_eq!(missing.conflict_coverage.status, "partial");
        let degraded = committed_conflict_result(
            &mutation,
            &[9],
            Err(FleetError::Memory("sensitive backend detail".into())),
        );
        assert_eq!(
            degraded.conflict_coverage.details["reason"],
            "post_commit_projection_unavailable"
        );
        assert_eq!(degraded.data["conflict_id"], 9);
    }

    #[test]
    fn replayed_record_coverage_uses_subset_rule_fresh_record_stays_strict() {
        let open_nine = || {
            Ok(vec![fixture_conflict(
                9,
                FUNCTIONAL_VALUE_CONFLICT_DETECTOR_V2,
            )])
        };
        let open_ten = || {
            Ok(vec![fixture_conflict(
                10,
                FUNCTIONAL_VALUE_CONFLICT_DETECTOR_V2,
            )])
        };

        // Fresh records keep strict equality with their lineage memberships.
        let fresh = fixture_mutation(vec![9], false);
        assert_eq!(
            committed_remember_result(&fresh, open_nine())
                .conflict_coverage
                .status,
            "complete"
        );
        assert_eq!(
            committed_remember_result(&fresh, Ok(Vec::new()))
                .conflict_coverage
                .status,
            "partial"
        );

        // A replay's stored membership may have closed since it committed.
        let replay = fixture_mutation(vec![9], true);
        assert_eq!(
            committed_remember_result(&replay, Ok(Vec::new()))
                .conflict_coverage
                .status,
            "complete"
        );
        assert_eq!(
            committed_remember_result(&replay, open_nine())
                .conflict_coverage
                .status,
            "complete"
        );
        // An open conflict the stored claim does not list is still partial.
        assert_eq!(
            committed_remember_result(&replay, open_ten())
                .conflict_coverage
                .status,
            "partial"
        );
    }

    #[test]
    fn lifecycle_coverage_complete_only_when_all_requested_found() {
        let v2 = fixture_conflict(9, FUNCTIONAL_VALUE_CONFLICT_DETECTOR_V2);
        assert!(lifecycle_coverage_complete(&[], &[]));
        assert!(lifecycle_coverage_complete(&[9], std::slice::from_ref(&v2)));
        assert!(!lifecycle_coverage_complete(
            &[9, 10],
            std::slice::from_ref(&v2)
        ));
        assert!(!lifecycle_coverage_complete(&[9], &[]));
        assert!(!lifecycle_coverage_complete(
            &[9],
            &[fixture_conflict(9, "same_key_typed_value")]
        ));
        let mut truncated = v2.clone();
        truncated.members_truncated = true;
        assert!(!lifecycle_coverage_complete(&[9], &[truncated]));

        let mut retract = fixture_mutation(vec![9], false);
        retract.operation = "retract".into();
        retract.conflicts_resolved = vec![9];
        retract.reevaluation = Some(ConflictReevaluation {
            conflict_id: 9,
            outcome: "closed".into(),
            conflict_revision: 2,
            remaining_pair_count: 0,
            remaining_pairs: Vec::new(),
        });
        assert_eq!(affected_conflict_ids(&retract), [9]);
        let result = committed_lifecycle_result(&retract, &[9], Ok(vec![v2]));
        assert_eq!(result.conflict_coverage.status, "complete");
        assert_eq!(result.conflicts[0]["state"], "resolved");
        assert_eq!(result.data["reevaluation"]["outcome"], "closed");
        let degraded = committed_lifecycle_result(
            &retract,
            &[9],
            Err(FleetError::Memory("sensitive backend detail".into())),
        );
        assert_eq!(
            degraded.conflict_coverage.details["reason"],
            "post_commit_projection_unavailable"
        );
        assert_eq!(degraded.data["claim"]["id"], 41);
    }

    #[test]
    fn page_lifecycle_hits_hides_only_non_current_synthetic_claims() {
        let mut spoofed_source = fixture_hit("claim:2", &json!({ "claim_id": 2 }));
        spoofed_source.source = "markdown".into();
        let hits = vec![
            fixture_hit("claim:1", &json!({ "claim_id": 1 })),
            // Retrieval elides oversized metadata; the chunk id still binds it.
            fixture_hit("claim:2", &json!({})),
            fixture_hit("docs/design.md#0", &json!({})),
            fixture_hit("claim:3", &json!({ "claim_id": 3 })),
            // Ordinary chunks are never hidden, whatever metadata they carry.
            fixture_hit("docs/notes.md#1", &json!({ "claim_id": 2 })),
            spoofed_source,
            fixture_hit("claim:04", &json!({})),
            fixture_hit("claim:4", &json!({ "claim_id": 4 })),
        ];
        assert_eq!(synthetic_claim_ids(&hits), [1, 2, 3, 4]);
        let states = [
            (1, ClaimState::Active),
            (2, ClaimState::Retracted),
            (4, ClaimState::Disputed),
        ];
        let (kept, hidden) = page_lifecycle_hits(hits.clone(), &states, MAX_TOOL_RESULTS);
        assert_eq!(
            kept.iter()
                .map(|hit| (hit.chunk_id.as_str(), hit.source.as_str()))
                .collect::<Vec<_>>(),
            [
                ("claim:1", SYNTHETIC_CLAIM_SOURCE),
                ("docs/design.md#0", "markdown"),
                ("docs/notes.md#1", "markdown"),
                ("claim:2", "markdown"),
                ("claim:04", SYNTHETIC_CLAIM_SOURCE),
                ("claim:4", SYNTHETIC_CLAIM_SOURCE),
            ]
        );
        // Claim 3 no longer exists, so its orphaned chunk is hidden too.
        assert_eq!(hidden, [2, 3]);

        // A page keeps rank order and reports only the hidden hits that
        // ranked ahead of its end.
        let (kept, hidden) = page_lifecycle_hits(hits, &states, 2);
        assert_eq!(
            kept.iter()
                .map(|hit| hit.chunk_id.as_str())
                .collect::<Vec<_>>(),
            ["claim:1", "docs/design.md#0"]
        );
        assert_eq!(hidden, [2]);
    }

    #[test]
    fn lifecycle_search_refills_short_pages_up_to_the_hit_bound() {
        // A full page, or a retrieval that returned everything it had, is final.
        assert_eq!(next_lifecycle_window(3, 3, 3, 3), LifecycleRefill::Done);
        assert_eq!(next_lifecycle_window(12, 9, 1, 3), LifecycleRefill::Done);
        // Hidden hits shorted a full window: retrieve a larger one.
        assert_eq!(next_lifecycle_window(3, 3, 0, 3), LifecycleRefill::Grow(12));
        assert_eq!(
            next_lifecycle_window(48, 48, 2, 3),
            LifecycleRefill::Grow(100)
        );
        // The window never exceeds the tool's hit bound; a page still short
        // there is reported, not silently returned.
        assert_eq!(
            next_lifecycle_window(MAX_TOOL_RESULTS, MAX_TOOL_RESULTS, 2, 3),
            LifecycleRefill::Underfilled
        );
        assert_eq!(
            next_lifecycle_window(MAX_TOOL_RESULTS, MAX_TOOL_RESULTS, 99, MAX_TOOL_RESULTS),
            LifecycleRefill::Underfilled
        );
        // Every window sequence from any limit reaches the bound and stops.
        for limit in 1..=MAX_TOOL_RESULTS {
            let mut window = limit;
            let mut passes = 1;
            while let LifecycleRefill::Grow(next) = next_lifecycle_window(window, window, 0, limit)
            {
                assert!(next > window && next <= MAX_TOOL_RESULTS);
                window = next;
                passes += 1;
            }
            assert!(passes <= 5, "limit {limit} took {passes} passes");
        }
    }
}
