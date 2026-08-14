//! Cockroach-backed implementation of the backend-neutral memory service.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use ostk_recall_core::{ChunkEmbedder, CorpusFilter, RecallHit, RecallIntent, RecallParams};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::ledger::{ClaimInput, ClaimLedger, ClaimMutation, Conflict, SemanticClaimHit};
use crate::service::{
    ConflictCoverage, FleetMemoryService, RecallAction, RecallRequest, RecallResult,
    RememberAction, RememberRequest, RememberResult, ServiceError, ServiceResult,
};
use crate::store::cockroach::{CockroachStore, RetrievalHitMetadata, active_embedding_model};
use crate::{FleetError, FleetScope};

const MAX_TOOL_RESULTS: usize = 100;
const DEFAULT_TOOL_RESULTS: usize = 10;
// Chunk search passes this query to CockroachDB's `plainto_tsquery`; keep every
// token below the same conservative bound enforced for indexed corpus text.
const MAX_TSVECTOR_QUERY_LEXEME_BYTES: usize = 16_000;

/// The executable service composition: shared hybrid corpus reads plus the
/// durable epistemic claim ledger, both bound to one deployment identity.
pub struct CockroachMemoryService {
    trusted_scope: FleetScope,
    corpus: Arc<CockroachStore>,
    ledger: Arc<dyn ClaimLedger>,
    embedder: Arc<dyn ChunkEmbedder>,
}

struct ChunkConflictProjection {
    conflicts: Vec<Conflict>,
    support_claim_count: usize,
    supporting_chunk_ids: Vec<String>,
    support_claims_truncated: bool,
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

impl std::fmt::Debug for CockroachMemoryService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CockroachMemoryService")
            .field("trusted_scope", &self.trusted_scope)
            .field("embedding_model", &self.embedder.model_id())
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
        })
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
                truncated: false,
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
            truncated,
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
            support_claims_truncated,
        })
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
            "chunk" => {
                let params = RecallParams {
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
                    ranking_overrides: None,
                };
                let retrieval_corpus = self.corpus.retrieval_reader();
                let mut hits = ostk_recall_retrieval::recall(
                    &retrieval_corpus,
                    self.embedder.as_ref(),
                    None,
                    &params,
                )
                .await
                .map_err(|error| ServiceError::Internal(format!("hybrid recall: {error}")))?;
                let metadata_elided = self.hydrate_retrieval_metadata(&mut hits).await?;
                let projection = self.project_chunk_conflicts(scope, &hits).await?;
                let mut result = RecallResult::new(json!({ "hits": hits }));
                result.conflicts = serialize_conflicts(&projection.conflicts)?;
                // Ordinary corpus rows are not NLI-checked. Typed conflict
                // coverage applies only to synthetic claim projections, so
                // the aggregate response is deliberately never "complete".
                result.conflict_coverage = structured_conflict_coverage(false);
                if projection.support_claims_truncated {
                    result.warnings.push(json!({
                        "code": "support_claim_projection_truncated",
                        "message": "more typed claims cite the surfaced evidence than fit in the bounded conflict projection"
                    }));
                }
                result.diagnostics.insert(
                    "retrieval".into(),
                    json!({
                        "lanes": ["lexical", "dense"],
                        "fusion": "rrf",
                        "metadata_elided": metadata_elided,
                        "support_claims_matched": projection.support_claim_count,
                        "supporting_chunk_ids": projection.supporting_chunk_ids,
                        "support_claims_truncated": projection.support_claims_truncated,
                    }),
                );
                Ok(result)
            }
            "claim" | "assertion" => {
                reject_claim_only_unsupported_filters(&args)?;
                let hits = self
                    .ledger
                    .search_claims(scope, &args.query, args.include_history, limit)
                    .await
                    .map_err(service_error)?;
                let claim_ids = hits.iter().map(|hit| hit.claim.id).collect::<Vec<_>>();
                let conflicts = self
                    .ledger
                    .conflicts_for_claim_ids(scope, &claim_ids, MAX_TOOL_RESULTS)
                    .await
                    .map_err(service_error)?;
                let coverage_complete = conflicts.len() < MAX_TOOL_RESULTS
                    && conflicts.iter().all(conflict_projection_complete);
                let hits = compact_claim_hits(hits);
                let mut result = RecallResult::new(json!({ "hits": hits }));
                result.conflicts = serialize_conflicts(&conflicts)?;
                result.conflict_coverage = structured_conflict_coverage(coverage_complete);
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
                let conflicts = self
                    .ledger
                    .conflicts_for_claim_ids(scope, &[id], MAX_TOOL_RESULTS)
                    .await
                    .map_err(service_error)?;
                let coverage_complete = conflicts.len() < MAX_TOOL_RESULTS
                    && conflicts.iter().all(conflict_projection_complete);
                result.conflicts = serialize_conflicts(&conflicts)?;
                result.conflict_coverage = structured_conflict_coverage(coverage_complete);
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
            other => Err(ServiceError::InvalidRequest(format!(
                "recall get kind {other:?} is not supported"
            ))),
        }
    }

    async fn recall_conflicts(
        &self,
        scope: &FleetScope,
        arguments: Map<String, Value>,
    ) -> ServiceResult<RecallResult> {
        let args: ConflictArgs = from_arguments(arguments, "recall conflicts")?;
        let limit = bounded_limit(args.limit)?;
        let conflicts = self
            .ledger
            .list_conflicts(scope, args.include_resolved, limit)
            .await
            .map_err(service_error)?;
        let coverage_complete =
            conflicts.len() < limit && conflicts.iter().all(conflict_projection_complete);
        let serialized = serialize_conflicts(&conflicts)?;
        let mut result = RecallResult::new(json!({ "conflicts": serialized }));
        result.conflicts = serialized;
        result.conflict_coverage = structured_conflict_coverage(coverage_complete);
        Ok(result)
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
        let idempotency_key = request.idempotency_key.ok_or_else(|| {
            ServiceError::InvalidRequest("remember(record) requires idempotency_key".into())
        })?;
        let input: ClaimInput = from_arguments(request.arguments, "remember record")?;
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
            return Err(ServiceError::InvalidRequest(
                "remember(record) only accepts operator_asserted origin; projection imports use a trusted ingestion path"
                    .into(),
            ));
        }
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
        Ok(committed_remember_result(&mutation, conflicts))
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
    let claim_id = mutation.claim.id;
    let expected_conflicts = mutation.claim.conflict_ids.len();
    let data = serde_json::to_value(mutation).unwrap_or_else(|error| {
        tracing::error!(
            error = %error,
            claim_id,
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
    });
    let mut result = RememberResult::new(data);
    result
        .diagnostics
        .insert("transaction".into(), Value::String("serializable".into()));

    match conflicts {
        Ok(conflicts) => match serialize_conflicts(&conflicts) {
            Ok(serialized) => {
                result.conflicts = serialized;
                result.conflict_coverage = structured_conflict_coverage(
                    conflicts.len() == expected_conflicts
                        && conflicts.iter().all(conflict_projection_complete),
                );
            }
            Err(error) => mark_post_commit_projection_unavailable(&mut result, claim_id, &error),
        },
        Err(error) => {
            tracing::error!(
                error = %error,
                claim_id,
                "committed remember conflict projection failed"
            );
            mark_post_commit_projection_unavailable_without_error(&mut result);
        }
    }
    result
}

fn mark_post_commit_projection_unavailable(
    result: &mut RememberResult,
    claim_id: i64,
    error: &ServiceError,
) {
    tracing::error!(
        error = %error,
        claim_id,
        "committed remember conflict projection serialization failed"
    );
    mark_post_commit_projection_unavailable_without_error(result);
}

fn mark_post_commit_projection_unavailable_without_error(result: &mut RememberResult) {
    result.conflicts.clear();
    result.conflict_coverage = structured_conflict_coverage(false);
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
                "recall({}) is outside the hackathon vertical slice",
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
        match request.action {
            RememberAction::Record => self.remember_record(&scope, request).await,
            action => Err(ServiceError::InvalidRequest(format!(
                "remember({}) is outside the hackathon vertical slice",
                action.as_str()
            ))),
        }
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
    const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
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

fn structured_conflict_coverage(complete: bool) -> ConflictCoverage {
    let mut coverage = ConflictCoverage::new(if complete { "complete" } else { "partial" });
    coverage.details.insert(
        "detector".into(),
        Value::String("same_key_typed_value".into()),
    );
    coverage
        .details
        .insert("scope".into(), Value::String("tenant_project".into()));
    coverage.details.insert(
        "contract".into(),
        Value::String(
            "typed same-key current-interval contradictions only; no corpus-wide NLI".into(),
        ),
    );
    coverage
        .details
        .insert("complete".into(), Value::Bool(complete));
    coverage
}

fn service_error(error: FleetError) -> ServiceError {
    match error {
        FleetError::InvalidScope(message) | FleetError::IdempotencyConflict(message) => {
            ServiceError::InvalidRequest(message)
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
    use ostk_recall_core::Links;

    use crate::ledger::{Claim, ClaimKind, ClaimState};

    use super::*;

    #[test]
    fn accepts_numeric_or_decimal_string_safe_ids() {
        assert_eq!(parse_safe_id(&json!(42)).unwrap(), 42);
        assert_eq!(parse_safe_id(&json!("42")).unwrap(), 42);
        assert!(parse_safe_id(&json!(9_007_199_254_740_992_i64)).is_err());
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
            idempotent_replay: false,
            conflicts_opened: vec![9],
            conflicts_resolved: Vec::new(),
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
}
