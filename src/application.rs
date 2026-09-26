//! Cockroach-backed implementation of the backend-neutral memory service.

use std::collections::{HashMap, HashSet};
use std::str::FromStr as _;
use std::sync::Arc;

use async_trait::async_trait;
use ostk_recall_core::{
    ChunkEmbedder, CorpusFilter, RankingOverrides, RecallHit, RecallIntent, RecallParams,
};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::evidence_recall::{
    ABSENCE_DENSE_MIN_COSINE_SIMILARITY, ABSENCE_NEIGHBOUR_BAND_FLOOR, EvidenceDenseLaneV1,
    EvidenceReadinessV1, EvidenceRecall, EvidenceSearchV1, EvidenceSourceFilterV1,
    EvidenceSourceV1, EvidenceSourcesV1, MAX_EVIDENCE_SEARCH_LIMIT, MAX_EVIDENCE_SOURCES,
};
use crate::item_recall::{
    ItemRecall, ItemReferenceV1, ItemSearchRequestV1, ItemSearchV1, MAX_ITEM_SEARCH_LIMIT,
};
use crate::ledger::{
    Claim, ClaimHistoryV1, ClaimInput, ClaimLedger, ClaimMutation, ClaimState, ClaimTarget,
    Conflict, ConflictMutation, ConflictTarget, DismissalTerms,
    FUNCTIONAL_VALUE_CONFLICT_DETECTOR_V2, ITEM_SUPPORT_SOURCE_CONFIG_ID, KeyClaimV1,
    LegacyClaimKeysV1, LifecycleMutation, LifecycleReplayRequest, MAX_CLAIM_HIT_VALUE_BYTES,
    MAX_CONCESSION_CLAIMS, MAX_CONFLICT_MEMBER_COUNT, SemanticClaimHit, SupportedClaimCoordinate,
    WaiverTerms, claim_key_from_parts, derive_overlay, history_within_bytes,
    overlay_episode_revision, unlogged_transitions, validate_lifecycle_reason, validate_rationale,
    validate_waiver_hours,
};
use crate::memory_contracts::collected_item::ProviderKindV1;
use crate::memory_contracts::digest::Sha256Digest;
use crate::memory_contracts::discrepancy::{
    DiscrepancyEpisodeFingerprintV1, DismissalReasonKindV1, WaiverReasonKindV1,
};
use crate::projectors::EMBEDDING_DIMENSIONS;
use crate::remember_runtime::{
    AssertStatusV1, CaptureRequestV1, CaptureStatusV1, ItemCapture, PreparedCaptureV1,
    RememberAssertInputV1,
};
use crate::service::{
    ConflictCoverage, FleetMemoryService, RecallAction, RecallRequest, RecallResult, RecallSurface,
    Refusal, RememberAction, RememberRequest, RememberResult, RememberSurface, ServiceError,
    ServiceResult, authorize_surface, capture_unavailable,
};
use crate::spec_conformance::{SpecConformanceAnswerV1, SpecConformanceRead};
use crate::store::cockroach::{
    CockroachStore, RETRIEVAL_DENSE_MIN_COSINE_SIMILARITY, RetrievalHitMetadata,
    active_embedding_model,
};
use crate::worker::WorkerSourceOutcomeV1;
use crate::{FleetError, FleetScope};

const MAX_TOOL_RESULTS: usize = 100;
const DEFAULT_TOOL_RESULTS: usize = 10;
// `recall(kind=evidence)` and `recall(kind=item)` share the tool's limit bound.
const _: () = assert!(MAX_TOOL_RESULTS == MAX_EVIDENCE_SEARCH_LIMIT);
const _: () = assert!(MAX_TOOL_RESULTS == MAX_ITEM_SEARCH_LIMIT);
// Chunk search passes this query to CockroachDB's `plainto_tsquery`; keep every
// token below the same conservative bound enforced for indexed corpus text.
const MAX_TSVECTOR_QUERY_LEXEME_BYTES: usize = 16_000;
const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
/// Source of the corpus projection record writes for every claim.
const SYNTHETIC_CLAIM_SOURCE: &str = "ostk_memory";
/// Serialized bytes `recall(get, kind=conflict)` spends on the conflict, which
/// it returns twice (`data.conflict` and `conflicts`), and its lifecycle
/// history together. History gets what the conflict leaves, so the lookup
/// stays well inside the MCP edge's 768 KiB tool-result budget however long
/// the conflict's log grows.
const MAX_CONFLICT_LOOKUP_BYTES: usize = 576 * 1024;

/// Which lifecycle behaviour a service instance serves.
///
/// The default is the historical record-only surface with no lifecycle
/// filtering. The public recall process keeps that surface but hides
/// non-current claim chunks and withholds asserted claims
/// ([`CockroachMemoryService::publication`]).
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
    /// What startup decided about `remember(assert)`, reported by
    /// `recall(status)`; `None` when no writer-authority pins are configured.
    assert_status: Option<AssertStatusV1>,
    /// Withhold every asserted claim from every read. Only the publication
    /// composition ([`Self::publication`]) sets it.
    withhold_asserted_claims: bool,
    /// `recall(kind=evidence)` over the Stage-5 tiers (ADR 0006); `None` when
    /// this instance does not serve it.
    evidence: Option<Arc<dyn EvidenceRecall>>,
    /// `recall(action=discrepancies)` over the Stage-6 spec conformance
    /// chain (ADR 0007); `None` when this instance does not serve it.
    spec_conformance: Option<Arc<dyn SpecConformanceRead>>,
    /// `recall(kind=item)` over collected items (ADR 0008 D7); `None` when
    /// this instance does not serve it.
    items: Option<Arc<dyn ItemRecall>>,
    /// `remember(action=capture)` into the collected-item sink (ADR 0008
    /// D10); `None` when this instance does not serve it.
    capture: Option<Arc<dyn ItemCapture>>,
    /// What startup decided about `remember(capture)`, reported by
    /// `recall(status)`; `None` when capture is not configured.
    capture_status: Option<CaptureStatusV1>,
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
            .field("assert_status", &self.assert_status)
            .field("withhold_asserted_claims", &self.withhold_asserted_claims)
            .field("evidence_recall", &self.evidence.is_some())
            .field("spec_conformance", &self.spec_conformance.is_some())
            .field("item_recall", &self.items.is_some())
            .field("capture", &self.capture.is_some())
            .field("capture_status", &self.capture_status)
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
            assert_status: None,
            withhold_asserted_claims: false,
            evidence: None,
            spec_conformance: None,
            items: None,
            capture: None,
            capture_status: None,
        })
    }

    /// The public recall composition: [`Self::new`], serving the record-only
    /// default, with every asserted claim withheld from every read (ADR 0005
    /// D8).
    ///
    /// An asserted claim's predicate carries `publication_default: denied`,
    /// and the publication reader holds table-level `SELECT` on
    /// `memory_claims` and `memory_chunks`, so this reader itself withholds
    /// each claim that projects an accepted event: it is absent from claim
    /// search and `get`, its synthetic `claim:{id}` chunk is absent from
    /// chunk search and `get`, and no conflict with it as a member is
    /// returned. Withheld items look exactly like absent ones.
    ///
    /// # Errors
    ///
    /// As [`Self::new`].
    pub fn publication(
        trusted_scope: FleetScope,
        corpus: Arc<CockroachStore>,
        ledger: Arc<dyn ClaimLedger>,
        embedder: Arc<dyn ChunkEmbedder>,
    ) -> crate::Result<Self> {
        let mut service = Self::new(trusted_scope, corpus, ledger, embedder)?;
        service.withhold_asserted_claims = true;
        // The public demo serves what is current: a retracted or superseded
        // claim's synthetic chunk is dropped from chunk search (and the page
        // refilled), as the private writer drops it, and
        // `lifecycle_hidden_claim_ids` names what was hidden. The lifecycle
        // surface itself stays record-only.
        service.lifecycle.hide_non_current_claim_chunks = true;
        Ok(service)
    }

    /// Serve the given lifecycle surface. Only the private writer composition
    /// calls this; the publication reader keeps the record-only default.
    #[must_use]
    pub const fn with_lifecycle(mut self, lifecycle: LifecycleServing) -> Self {
        self.lifecycle = lifecycle;
        self
    }

    /// Report what startup decided about `remember(assert)` in
    /// `recall(status)` as `remember_assert`. `None`, the default, reports
    /// nothing. Whether assert is served is the surface's
    /// [`RememberSurface::assert`], set with [`Self::with_lifecycle`].
    #[must_use]
    pub fn with_assert_status(mut self, status: Option<AssertStatusV1>) -> Self {
        self.assert_status = status;
        self
    }

    /// Serve `recall(kind=evidence)` (ADR 0006) through `evidence`: `search`
    /// and `get` with `kind=evidence`, and an `evidence` block in
    /// `recall(status)`, all advertised in `tools/list`. Only the private
    /// writer composition calls this, and only where
    /// [`crate::evidence_recall::start_evidence_recall`] found the scope's
    /// Stage-5 tables readable; the publication reader never serves it.
    #[must_use]
    pub fn with_evidence_recall(mut self, evidence: Arc<dyn EvidenceRecall>) -> Self {
        self.evidence = Some(evidence);
        self
    }

    /// Serve `recall(action=discrepancies)` (ADR 0007) through `reader`, with
    /// a `spec_conformance` block in `recall(status)`, both advertised in
    /// `tools/list`. Only the private writer composition calls this, and only
    /// where [`crate::spec_conformance::start_spec_conformance`] found the
    /// scope's spec conformance tables readable; the publication reader never
    /// serves it.
    #[must_use]
    pub fn with_spec_conformance(mut self, reader: Arc<dyn SpecConformanceRead>) -> Self {
        self.spec_conformance = Some(reader);
        self
    }

    /// Serve `recall(kind=item)` (ADR 0008 D7) through `items`: `search` and
    /// `get` with `kind=item`, advertised in `tools/list`. Only the private
    /// writer composition calls this, and only where
    /// [`crate::item_recall::start_item_recall`] found the scope's collector
    /// and Stage-5 tables readable; the publication reader never serves it.
    #[must_use]
    pub fn with_item_recall(mut self, items: Arc<dyn ItemRecall>) -> Self {
        self.items = Some(items);
        self
    }

    /// Serve `remember(action=capture)` (ADR 0008 D10) through `capture`, and
    /// report `status` in `recall(status)` as `remember_capture`. Whether
    /// capture is advertised is the surface's [`RememberSurface::capture`],
    /// set with [`Self::with_lifecycle`]; a surface that names it without a
    /// runtime refuses it as `capture_unavailable`. Only the private writer
    /// composition calls this, with what
    /// [`crate::remember_runtime::start_collected_capture`] decided; the
    /// publication reader never serves it.
    #[must_use]
    pub fn with_capture(
        mut self,
        capture: Option<Arc<dyn ItemCapture>>,
        status: Option<CaptureStatusV1>,
    ) -> Self {
        self.capture = capture;
        self.capture_status = status;
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
    /// The publication reader likewise drops the synthetic chunk of every
    /// asserted claim, and reports nothing about it. Dropping hits after
    /// retrieval's cut would short the page, so the retrieval window grows
    /// until `limit` kept hits fill it, retrieval runs out of hits, or the
    /// window reaches the tool's hit bound.
    async fn retrieve_visible_chunks(
        &self,
        scope: &FleetScope,
        params: &mut RecallParams,
        limit: usize,
    ) -> ServiceResult<LifecyclePage> {
        let mut window = limit;
        loop {
            params.limit = Some(window);
            let mut hits = self.retrieve_chunks(params).await?;
            let returned = hits.len();
            let withheld = self
                .withheld_claim_ids(scope, &synthetic_claim_ids(&hits))
                .await?;
            if !withheld.is_empty() {
                hits.retain(|hit| {
                    synthetic_claim_id(hit).is_none_or(|claim_id| !withheld.contains(&claim_id))
                });
            }
            let (hits, hidden_claim_ids) = if self.lifecycle.hide_non_current_claim_chunks {
                let claim_ids = synthetic_claim_ids(&hits);
                let states = if claim_ids.is_empty() {
                    Vec::new()
                } else {
                    self.ledger
                        .claim_states(scope, &claim_ids)
                        .await
                        .map_err(service_error)?
                };
                page_lifecycle_hits(hits, &states, limit)
            } else {
                hits.truncate(limit);
                (hits, Vec::new())
            };
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

    /// Claim search. The publication reader drops asserted claims and, as
    /// chunk search does, grows the window to refill the page.
    async fn search_visible_claims(
        &self,
        scope: &FleetScope,
        query: &str,
        include_history: bool,
        limit: usize,
    ) -> ServiceResult<Vec<SemanticClaimHit>> {
        let mut window = limit;
        loop {
            let mut hits = self
                .ledger
                .search_claims(scope, query, include_history, window)
                .await
                .map_err(service_error)?;
            if !self.withhold_asserted_claims {
                return Ok(hits);
            }
            let returned = hits.len();
            let claim_ids = hits.iter().map(|hit| hit.claim.id).collect::<Vec<_>>();
            let withheld = self.withheld_claim_ids(scope, &claim_ids).await?;
            hits.retain(|hit| !withheld.contains(&hit.claim.id));
            hits.truncate(limit);
            match next_lifecycle_window(window, returned, hits.len(), limit) {
                LifecycleRefill::Grow(next) => window = next,
                LifecycleRefill::Done | LifecycleRefill::Underfilled => return Ok(hits),
            }
        }
    }

    /// The asserted claims among `claim_ids`, which the publication reader
    /// withholds. Always empty, with no read, on every other service.
    async fn withheld_claim_ids(
        &self,
        scope: &FleetScope,
        claim_ids: &[i64],
    ) -> ServiceResult<HashSet<i64>> {
        let mut withheld = HashSet::new();
        if !self.withhold_asserted_claims || claim_ids.is_empty() {
            return Ok(withheld);
        }
        let mut ids = claim_ids.to_vec();
        ids.sort_unstable();
        ids.dedup();
        for batch in ids.chunks(MAX_TOOL_RESULTS) {
            withheld.extend(
                self.ledger
                    .asserted_claim_ids(scope, batch)
                    .await
                    .map_err(service_error)?,
            );
        }
        Ok(withheld)
    }

    /// Drop every conflict with an asserted member on the publication
    /// reader. An asserted claim's `claim-v2:` key never equals a recorded
    /// claim's `subject::predicate` key, so such a conflict has only asserted
    /// members, and one returned member decides it even when the member list
    /// is truncated.
    async fn withhold_asserted_conflicts(
        &self,
        scope: &FleetScope,
        conflicts: &mut Vec<Conflict>,
    ) -> ServiceResult<()> {
        let member_ids = conflicts
            .iter()
            .flat_map(|conflict| conflict.members.iter().map(|member| member.id))
            .collect::<Vec<_>>();
        let withheld = self.withheld_claim_ids(scope, &member_ids).await?;
        if !withheld.is_empty() {
            conflicts.retain(|conflict| {
                !conflict
                    .members
                    .iter()
                    .any(|member| withheld.contains(&member.id))
            });
        }
        Ok(())
    }

    /// Hybrid chunk search with its conflict projection and diagnostics.
    async fn search_chunks(
        &self,
        scope: &FleetScope,
        args: SearchArgs,
        limit: usize,
    ) -> ServiceResult<RecallResult> {
        let unembedded = self.query_has_no_embedding(&args.query);
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
        let (mut hits, hiding) =
            if self.lifecycle.hide_non_current_claim_chunks || self.withhold_asserted_claims {
                let page = self
                    .retrieve_visible_chunks(scope, &mut params, limit)
                    .await?;
                // Only lifecycle hiding is reported; a withheld claim is not.
                let hiding = self
                    .lifecycle
                    .hide_non_current_claim_chunks
                    .then_some((page.hidden_claim_ids, page.underfilled));
                (page.hits, hiding)
            } else {
                (self.retrieve_chunks(&params).await?, None)
            };
        let metadata_elided = self.hydrate_retrieval_metadata(&mut hits).await?;
        let mut projection = self.project_chunk_conflicts(scope, &hits).await?;
        self.withhold_asserted_conflicts(scope, &mut projection.conflicts)
            .await?;
        let conflict_matches = conflict_match_diagnostics(
            &projection.conflicts,
            &hits,
            &projection.support_coordinates,
        )?;
        let overlay = self
            .overlay_conflicts(scope, &mut projection.conflicts)
            .await;
        let no_hits = hits.is_empty();
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
        if unembedded {
            result.warnings.push(json!({
                "code": "query_not_embedded",
                "message": "the query has no usable embedding under the pinned model, so only the lexical lane ran"
            }));
        }
        if no_hits
            && let Some(hint) = other_kinds_hint(self.items.is_some(), self.evidence.is_some())
        {
            result.warnings.push(hint);
        }
        let mut retrieval = json!({
            "lanes": if unembedded { json!(["lexical"]) } else { json!(["lexical", "dense"]) },
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
        // Evidence recall reads the Stage-5 tiers, never the chunk corpus, so
        // the corpus's vector generation does not gate it: its dense lane was
        // matched to this process's model when it was probed (ADR 0006).
        if let Some(evidence) = self.evidence.as_deref()
            && arguments.get("kind").and_then(Value::as_str) == Some("evidence")
        {
            return self.search_evidence(evidence, arguments).await;
        }
        // Item recall reads the same tiers, through the collector tables.
        if let Some(items) = self.items.as_deref()
            && arguments.get("kind").and_then(Value::as_str) == Some("item")
        {
            return self.search_items(items, arguments).await;
        }
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
                let unembedded = self.query_has_no_embedding(&args.query);
                let hits = self
                    .search_visible_claims(scope, &args.query, args.include_history, limit)
                    .await?;
                let claim_ids = hits.iter().map(|hit| hit.claim.id).collect::<Vec<_>>();
                let mut conflicts = self
                    .ledger
                    .conflicts_for_claim_ids(scope, &claim_ids, MAX_TOOL_RESULTS)
                    .await
                    .map_err(service_error)?;
                let coverage_complete = conflicts.len() < MAX_TOOL_RESULTS
                    && conflicts.iter().all(conflict_projection_complete);
                self.withhold_asserted_conflicts(scope, &mut conflicts)
                    .await?;
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
                if unembedded {
                    result.warnings.push(json!({
                        "code": "query_not_embedded",
                        "message": "the query has no usable embedding under the pinned model, and claim search has only a dense lane, so no claim could match"
                    }));
                }
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

    /// `recall(search, kind=evidence)`: one evidence search with the query's
    /// embedding for the dense lane, and every readiness, source, and absence
    /// fact the answer depends on.
    async fn search_evidence(
        &self,
        evidence: &dyn EvidenceRecall,
        arguments: Map<String, Value>,
    ) -> ServiceResult<RecallResult> {
        let args: SearchArgs = from_arguments(arguments, "recall search")?;
        validate_search_args(&args)?;
        reject_evidence_unsupported_filters(&args)?;
        let source = evidence_source_filter(args.source.as_deref())?;
        let limit = bounded_limit(args.limit)?;
        let vector = self.embed_evidence_query(&args.query).await;
        let search = evidence
            .search_from(&args.query, vector, limit, source)
            .await
            .map_err(service_error)?;
        Ok(evidence_search_result(search))
    }

    /// `recall(search, kind=item)`: one item search, with the query's
    /// embedding for the dense lane, an optional provider (`source`), and
    /// `include_history`.
    async fn search_items(
        &self,
        items: &dyn ItemRecall,
        arguments: Map<String, Value>,
    ) -> ServiceResult<RecallResult> {
        let args: SearchArgs = from_arguments(arguments, "recall search")?;
        validate_query_and_source(&args)?;
        if args.max_per_source_id.is_some() || args.min_score.is_some() || args.intent.is_some() {
            return Err(ServiceError::InvalidRequest(
                "item search does not support max_per_source_id, min_score, or intent; source \
                 filters by provider"
                    .into(),
            ));
        }
        let provider = args
            .source
            .as_deref()
            .map(ProviderKindV1::new)
            .transpose()
            .map_err(|_| {
                ServiceError::InvalidRequest(
                    "item search source must be a provider kind such as slack, linear, granola, \
                     or docs"
                        .into(),
                )
            })?;
        let limit = bounded_limit(args.limit)?;
        let vector = self.embed_evidence_query(&args.query).await;
        let search = items
            .search(
                &ItemSearchRequestV1 {
                    query: args.query,
                    provider,
                    include_history: args.include_history,
                    limit,
                },
                vector,
            )
            .await
            .map_err(service_error)?;
        Ok(item_search_result(search))
    }

    /// Whether the process embedder gives `query` no direction at all: the
    /// zero vector a query made only of tokens the model does not know
    /// encodes to (model2vec drops unknown tokens). Chunk and claim search
    /// then have no dense lane to run, and say so. The encode is a static
    /// lookup, like the one retrieval makes for the same query.
    fn query_has_no_embedding(&self, query: &str) -> bool {
        self.embedder
            .encode_batch(&[query.trim()])
            .into_iter()
            .next()
            .is_some_and(|vector| vector.iter().all(|component| *component == 0.0))
    }

    /// The query's vector for the evidence dense lane, from the process
    /// embedder on the blocking pool. `None` when the encode panics or yields
    /// a vector no cosine index can compare (wrong width, non-finite, or the
    /// zero vector); the search then runs its lexical lane alone and says so.
    async fn embed_evidence_query(&self, query: &str) -> Option<Vec<f32>> {
        let embedder = Arc::clone(&self.embedder);
        let query = query.to_owned();
        match tokio::task::spawn_blocking(move || embedder.encode_batch(&[query.as_str()])).await {
            Ok(vectors) => vectors
                .into_iter()
                .next()
                .filter(|vector| dense_query_vector_usable(vector)),
            Err(error) => {
                tracing::warn!(error = %error, "evidence query embedding failed");
                None
            }
        }
    }

    async fn recall_get(
        &self,
        scope: &FleetScope,
        arguments: Map<String, Value>,
    ) -> ServiceResult<RecallResult> {
        let args: GetArgs = from_arguments(arguments, "recall get")?;
        let (kind, target, include_history) = args.target()?;
        let kind = kind.as_deref().unwrap_or("chunk");
        let id = match target {
            GetTarget::Id(id) => id,
            GetTarget::ClaimKey(claim_key) => {
                return if matches!(kind, "claim" | "assertion") {
                    self.recall_claims_for_key(scope, &claim_key, include_history)
                        .await
                } else {
                    Err(ServiceError::InvalidRequest(format!(
                        "recall get by key is served for kind=claim, not kind={kind:?}"
                    )))
                };
            }
        };
        if let Some(evidence) = self.evidence.as_deref()
            && kind == "evidence"
        {
            return get_evidence(evidence, &id).await;
        }
        if let Some(items) = self.items.as_deref()
            && kind == "item"
        {
            return get_item(items, &id).await;
        }
        match kind {
            "claim" | "assertion" => self.recall_claim(scope, &id).await,
            "chunk" => {
                let id = id.as_str().ok_or_else(|| {
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
                let mut chunk = chunks.into_iter().next().map(|hydrated| hydrated.chunk);
                // A withheld claim's synthetic chunk reads as an absent chunk.
                let claim_ids = chunk
                    .as_ref()
                    .and_then(|chunk| {
                        synthetic_claim_coordinate(chunk.source.as_str(), &chunk.chunk_id)
                    })
                    .into_iter()
                    .collect::<Vec<_>>();
                if !self.withheld_claim_ids(scope, &claim_ids).await?.is_empty() {
                    chunk = None;
                }
                let mut result = RecallResult::new(json!({ "chunk": chunk }));
                result.conflict_coverage = ConflictCoverage::not_evaluated();
                Ok(result)
            }
            // Conflict lookup by id is part of the lifecycle surface; the
            // record-only (publication) surface keeps its historical kinds.
            "conflict" if self.lifecycle.surface.lifecycle_served() => {
                self.recall_conflict(scope, &id).await
            }
            other => Err(ServiceError::InvalidRequest(format!(
                "recall get kind {other:?} is not supported"
            ))),
        }
    }

    /// `recall(get, kind=claim)` by id: the claim with its support, item
    /// citations, current conflicts, and (on a private composition) its
    /// lifecycle history. A withheld claim reads exactly as an absent one.
    async fn recall_claim(&self, scope: &FleetScope, id: &Value) -> ServiceResult<RecallResult> {
        let id = parse_safe_id(id)?;
        let withheld = !self.withheld_claim_ids(scope, &[id]).await?.is_empty();
        let mut claim = if withheld {
            None
        } else {
            self.ledger
                .get_claim(scope, id)
                .await
                .map_err(service_error)?
        };
        let mut data = self.claim_citations(scope, id, claim.as_mut()).await?;
        data.insert("claim".into(), json!(claim));
        let mut result = RecallResult::new(Value::Object(data));
        // An asserted claim names the accepted event it projects; a
        // recorded one carries no such field.
        if claim.is_some()
            && let Some(event_id) = self
                .ledger
                .claim_accepted_event_id(scope, id)
                .await
                .map_err(service_error)?
        {
            result.data["accepted_event_id"] = json!(event_id);
        }
        // The claim's own audit trail: every logged transition with who and
        // why, and the predecessor it superseded. A private read only; the
        // publication reader has no grant on the log and keeps its shape. A
        // failed read is a warning, never a failed get.
        if claim.is_some() && !self.withhold_asserted_claims {
            match self.ledger.claim_lifecycle_history(scope, id).await {
                Ok(history) => {
                    let claim_bytes = json_bytes(&result.data);
                    let history = claim_history_within_bytes(
                        history,
                        MAX_CONFLICT_LOOKUP_BYTES.saturating_sub(claim_bytes),
                    );
                    if let Some(predecessor) = history.supersedes {
                        result.data["claim"]["supersedes"] = json!(predecessor);
                    }
                    result.data["history"] = json!(history.events);
                    result.data["history_truncated"] = json!(history.truncated);
                }
                Err(error) => {
                    tracing::warn!(error = %error, claim_id = id, "claim lifecycle history read failed");
                    result.data["history"] = Value::Null;
                    result.warnings.push(json!({
                        "code": "lifecycle_history_unavailable",
                        "message": "the claim's lifecycle history could not be read; the claim itself is current"
                    }));
                }
            }
        }
        let mut conflicts = if withheld {
            Vec::new()
        } else {
            self.ledger
                .conflicts_for_claim_ids(scope, &[id], MAX_TOOL_RESULTS)
                .await
                .map_err(service_error)?
        };
        let coverage_complete = conflicts.len() < MAX_TOOL_RESULTS
            && conflicts.iter().all(conflict_projection_complete);
        self.withhold_asserted_conflicts(scope, &mut conflicts)
            .await?;
        let overlay = self.overlay_conflicts(scope, &mut conflicts).await;
        result.conflicts = serialize_conflicts(&conflicts)?;
        result.conflict_coverage = conflict_coverage(coverage_complete, &conflicts);
        mark_lifecycle_overlay(&mut result.conflict_coverage, &mut result.warnings, overlay);
        Ok(result)
    }

    /// `recall(get, kind=claim, key=…)`: every claim carrying exactly that
    /// stored key, oldest first, each as `get` returns it (support, current
    /// conflicts, value up to the lookup bound), with the conflicts detected
    /// on the key and the open one named. A withheld claim reads as absent,
    /// and the publication reader drops opaque item support as it does on
    /// `get` by id.
    async fn recall_claims_for_key(
        &self,
        scope: &FleetScope,
        claim_key: &str,
        include_history: bool,
    ) -> ServiceResult<RecallResult> {
        let lookup = self
            .ledger
            .claims_for_key(scope, claim_key, include_history)
            .await
            .map_err(service_error)?;
        let claim_ids = lookup
            .claims
            .iter()
            .map(|entry| entry.claim.id)
            .collect::<Vec<_>>();
        let withheld = self.withheld_claim_ids(scope, &claim_ids).await?;
        let mut claims = lookup
            .claims
            .into_iter()
            .filter(|entry| !withheld.contains(&entry.claim.id))
            .collect::<Vec<_>>();
        if self.withhold_asserted_claims {
            for entry in &mut claims {
                withhold_item_support(&mut entry.claim);
            }
        }
        let (claims, cut) = key_claims_within_bytes(claims, MAX_CONFLICT_LOOKUP_BYTES);
        let claims_truncated = lookup.truncated || cut;

        let conflict_ids = self
            .ledger
            .conflict_ids_for_key(scope, claim_key)
            .await
            .map_err(service_error)?;
        let mut conflicts = if conflict_ids.is_empty() {
            Vec::new()
        } else {
            self.ledger
                .get_conflicts(scope, &conflict_ids)
                .await
                .map_err(service_error)?
        };
        self.withhold_asserted_conflicts(scope, &mut conflicts)
            .await?;
        let overlay = self.overlay_conflicts(scope, &mut conflicts).await;
        let serialized = serialize_conflicts(&conflicts)?;
        let open_conflict = conflicts
            .iter()
            .position(|conflict| conflict.state == "open")
            .and_then(|index| serialized.get(index).cloned());
        let mut result = RecallResult::new(json!({
            "claim_key": claim_key,
            "claims": claims,
            "claims_truncated": claims_truncated,
            "include_history": include_history,
            "open_conflict": open_conflict,
        }));
        result.conflict_coverage = conflict_coverage(
            lifecycle_coverage_complete(&conflict_ids, &conflicts),
            &conflicts,
        );
        result.conflicts = serialized;
        mark_lifecycle_overlay(&mut result.conflict_coverage, &mut result.warnings, overlay);
        Ok(result)
    }

    /// A claim get's item citations (ADR 0008 D11). The publication reader
    /// drops the claim's opaque `fleet.item` support rows and never reads the
    /// links; the private writer expands the items it cites into
    /// `support_items` and `independent_sources`. Empty for a claim that
    /// cites none, which reads as before.
    async fn claim_citations(
        &self,
        scope: &FleetScope,
        id: i64,
        claim: Option<&mut Claim>,
    ) -> ServiceResult<Map<String, Value>> {
        let mut citations = Map::new();
        let Some(claim) = claim else {
            return Ok(citations);
        };
        if self.withhold_asserted_claims {
            withhold_item_support(claim);
            return Ok(citations);
        }
        let support = self
            .ledger
            .claim_item_support(scope, id)
            .await
            .map_err(service_error)?;
        if let Some(support) = support.filter(|support| !support.items.is_empty()) {
            citations.insert("support_items".into(), json!(support.items));
            citations.insert(
                "independent_sources".into(),
                json!(support.independent_sources),
            );
            if support.truncated {
                citations.insert("support_items_truncated".into(), json!(true));
            }
        }
        Ok(citations)
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
                    let conflict_bytes = serialized
                        .first()
                        .map_or(0, |conflict| json_bytes(conflict).saturating_mul(2));
                    let history = history_within_bytes(
                        history,
                        MAX_CONFLICT_LOOKUP_BYTES.saturating_sub(conflict_bytes),
                    );
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
        let claim_key = args
            .claim_key
            .as_deref()
            .map(str::trim)
            .filter(|key| !key.is_empty());
        if args.claim_key.is_some() && claim_key.is_none() {
            return Err(ServiceError::InvalidRequest(
                "claim_key must not be empty".into(),
            ));
        }
        let (mut conflicts, coverage_complete) = if let Some(claim_key) = claim_key {
            // One conflict per detector on a key, in any state; the caller's
            // include_resolved keeps or drops the closed ones.
            let ids = self
                .ledger
                .conflict_ids_for_key(scope, claim_key)
                .await
                .map_err(service_error)?;
            let conflicts = if ids.is_empty() {
                Vec::new()
            } else {
                self.ledger
                    .get_conflicts(scope, &ids)
                    .await
                    .map_err(service_error)?
            };
            let conflicts = conflicts
                .into_iter()
                .filter(|conflict| args.include_resolved || conflict.state == "open")
                .take(limit)
                .collect::<Vec<_>>();
            let complete = conflicts.iter().all(conflict_projection_complete);
            (conflicts, complete)
        } else {
            let conflicts = self
                .ledger
                .list_conflicts(scope, args.include_resolved, limit)
                .await
                .map_err(service_error)?;
            let complete =
                conflicts.len() < limit && conflicts.iter().all(conflict_projection_complete);
            (conflicts, complete)
        };
        self.withhold_asserted_conflicts(scope, &mut conflicts)
            .await?;
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
                    let member_count = i64::try_from(conflict.member_count).unwrap_or(i64::MAX);
                    conflict.lifecycle = Some(derive_overlay(
                        &conflict.state,
                        conflict.revision,
                        member_count,
                        events,
                        rows.truncated.contains(&conflict.id),
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

    async fn recall_status(
        &self,
        scope: &FleetScope,
        arguments: Map<String, Value>,
    ) -> ServiceResult<RecallResult> {
        let _: EmptyArgs = from_arguments(arguments, "recall status")?;
        let capabilities = self.corpus.capabilities().await.map_err(service_error)?;
        let mut result = RecallResult::new(json!({
            "status": "ready",
            "database": capabilities,
            "embedding_model": self.embedder.model_id(),
            "embedding_dimension": self.embedder.dim(),
        }));
        if self.lifecycle.surface.lifecycle_served() {
            result.data["remember_surface"] = json!(self.lifecycle.surface);
        }
        if let Some(status) = &self.assert_status {
            result.data["remember_assert"] = json!(status);
        }
        if let Some(status) = &self.capture_status {
            result.data["remember_capture"] = json!(status);
        }
        // The evidence quarantine is a private read: the publication role
        // has no grant on it, and the demo's status keeps its shape.
        let quarantine = async {
            if self.withhold_asserted_claims {
                None
            } else {
                Some(
                    quarantine_status_within(self.corpus.pool(), scope, OPTIONAL_STATUS_DEADLINE)
                        .await,
                )
            }
        };
        let (
            (evidence, spec_conformance),
            (legacy_claim_keys, legacy_warnings),
            (conflicts, conflict_warnings),
            quarantine,
        ) = tokio::join!(
            optional_status_blocks(
                self.evidence.as_deref(),
                self.spec_conformance.as_deref(),
                OPTIONAL_STATUS_DEADLINE,
            ),
            legacy_claim_keys_within(self.ledger.as_ref(), scope, OPTIONAL_STATUS_DEADLINE),
            conflicts_status_within(
                self.ledger.as_ref(),
                scope,
                self.lifecycle.lifecycle_overlay,
                OPTIONAL_STATUS_DEADLINE,
            ),
            quarantine,
        );
        for (name, block) in [
            ("evidence", evidence),
            ("spec_conformance", spec_conformance),
            ("quarantine", quarantine),
        ] {
            if let Some((block, warnings)) = block {
                result.data[name] = block;
                result.warnings.extend(warnings);
            }
        }
        result.data["legacy_claim_keys"] = legacy_claim_keys;
        result.warnings.extend(legacy_warnings);
        result.data["conflicts"] = conflicts;
        result.warnings.extend(conflict_warnings);
        // What the absence verdict means, wherever a verdict is served.
        if self.evidence.is_some() || self.items.is_some() {
            result.data["absence_contract"] = absence_contract();
        }
        result.conflict_coverage = ConflictCoverage::not_evaluated();
        Ok(result)
    }

    /// `recall(action=discrepancies)`: the standing spec-nonconformance
    /// episodes (or, with `include_resolved`, every episode), or one episode
    /// by `id` with its lifecycle history, beside every live spec's latest
    /// check. Refused before any I/O where it is not served.
    async fn recall_discrepancies(
        &self,
        arguments: Map<String, Value>,
    ) -> ServiceResult<RecallResult> {
        let Some(reader) = self.spec_conformance.as_deref() else {
            return Err(ServiceError::InvalidRequest(
                "recall(discrepancies) is not served by this deployment: migration 31 or its \
                 runtime read grants are absent"
                    .into(),
            ));
        };
        let args: DiscrepanciesArgs = from_arguments(arguments, "recall discrepancies")?;
        let answer = if let Some(id) = args.id {
            let episode = parse_episode_id(&id)?;
            reader.get(episode).await
        } else {
            let limit = bounded_limit(args.limit)?;
            reader.list(args.include_resolved, limit).await
        }
        .map_err(service_error)?;
        discrepancies_result(&answer)
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

    /// `remember(assert)`: the event-first append through the active
    /// registry route (ADR 0005), then the same post-commit conflict
    /// projection `record` returns, with the accepted event it appended.
    async fn remember_assert(
        &self,
        scope: &FleetScope,
        request: RememberRequest,
    ) -> ServiceResult<RememberResult> {
        self.verify_embedding_generation()
            .await
            .map_err(service_error)?;
        let idempotency_key = required_idempotency_key(request.action, request.idempotency_key)?;
        let args: AssertArgs = from_arguments(request.arguments, "remember assert")?;
        let asserted = self
            .ledger
            .assert_claim(scope, &args.assertion, &idempotency_key)
            .await
            .map_err(service_error)?;
        let conflicts = self
            .ledger
            .conflicts_for_claim_ids(scope, &[asserted.mutation.claim.id], MAX_TOOL_RESULTS)
            .await;
        let (conflicts, overlay) = self.overlay_projection(scope, conflicts).await;
        let mut result = committed_remember_result(&asserted.mutation, conflicts);
        result.data["accepted_event"] = json!(asserted.accepted_event);
        mark_lifecycle_overlay(&mut result.conflict_coverage, &mut result.warnings, overlay);
        Ok(result)
    }

    /// `remember(capture)`: relay items the agent read through its own
    /// connectors into the collected-item sink (ADR 0008 D10). The request is
    /// checked before any I/O; the answer is the capture receipt's response,
    /// and a capture evaluates no conflict.
    async fn remember_capture(
        &self,
        scope: &FleetScope,
        request: RememberRequest,
    ) -> ServiceResult<RememberResult> {
        let Some(capture) = self.capture.as_deref() else {
            return Err(capture_unavailable());
        };
        let idempotency_key = required_idempotency_key(request.action, request.idempotency_key)?;
        let input: CaptureRequestV1 = from_arguments(request.arguments, "remember capture")?;
        let prepared = PreparedCaptureV1::prepare(&input).map_err(|message| {
            ServiceError::InvalidRequest(format!("remember capture: {message}"))
        })?;
        let outcome = capture
            .capture(scope, &prepared, &idempotency_key)
            .await
            .map_err(service_error)?;
        Ok(RememberResult::new(outcome.response))
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

    async fn remember_dismiss(
        &self,
        scope: &FleetScope,
        request: RememberRequest,
    ) -> ServiceResult<RememberResult> {
        let idempotency_key = required_idempotency_key(request.action, request.idempotency_key)?;
        let (target, dismissal) = parse_dismiss_arguments(request.arguments)?;
        let mutation = self
            .ledger
            .dismiss_conflict(scope, target, dismissal.terms(), &idempotency_key)
            .await
            .map_err(service_error)?;
        Ok(self.conflict_result(scope, &mutation).await)
    }

    async fn remember_waive(
        &self,
        scope: &FleetScope,
        request: RememberRequest,
    ) -> ServiceResult<RememberResult> {
        let idempotency_key = required_idempotency_key(request.action, request.idempotency_key)?;
        let (target, waiver) = parse_waive_arguments(request.arguments)?;
        let mutation = self
            .ledger
            .waive_conflict(scope, target, waiver.terms(), &idempotency_key)
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
            RememberAction::Dismiss => parse_dismiss_arguments(request.arguments)
                .ok()
                .map(|(target, dismissal)| UnservedLifecycle::Dismiss { target, dismissal }),
            RememberAction::Waive => parse_waive_arguments(request.arguments)
                .ok()
                .map(|(target, waiver)| UnservedLifecycle::Waive { target, waiver }),
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
            RecallAction::Status => self.recall_status(&scope, request.arguments).await,
            RecallAction::Discrepancies => self.recall_discrepancies(request.arguments).await,
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
            // An unserved assert or capture is refused before any I/O.
            // Replaying a committed assert or capture receipt once it is
            // turned off is deferred (ADR 0005, ADR 0008 D10); only the
            // lifecycle actions replay here.
            if matches!(
                request.action,
                RememberAction::Assert | RememberAction::Capture
            ) {
                return Err(refusal);
            }
            return self
                .replay_unserved_or_refuse(&scope, request, refusal)
                .await;
        }
        match request.action {
            RememberAction::Record => self.remember_record(&scope, request).await,
            RememberAction::Assert => self.remember_assert(&scope, request).await,
            RememberAction::Retract => self.remember_retract(&scope, request).await,
            RememberAction::Supersede => self.remember_supersede(&scope, request).await,
            RememberAction::Acknowledge => self.remember_acknowledge(&scope, request).await,
            RememberAction::Resolve => self.remember_resolve(&scope, request).await,
            RememberAction::Dismiss => self.remember_dismiss(&scope, request).await,
            RememberAction::Waive => self.remember_waive(&scope, request).await,
            RememberAction::Capture => self.remember_capture(&scope, request).await,
            action => Err(ServiceError::InvalidRequest(format!(
                "remember({}) is not implemented yet",
                action.as_str()
            ))),
        }
    }

    fn remember_surface(&self) -> RememberSurface {
        self.lifecycle.surface
    }

    fn recall_surface(&self) -> RecallSurface {
        RecallSurface {
            evidence: self.evidence.is_some(),
            discrepancies: self.spec_conformance.is_some(),
            items: self.items.is_some(),
        }
    }
}

/// Drop a claim's opaque item-citation support rows (`fleet.item`, ADR 0008
/// D11) on the publication reader. Which item a row cites lives only in the
/// private links, but the public reader does not even say that the claim
/// cites one, as it says nothing about an asserted claim (ADR 0005 D8).
fn withhold_item_support(claim: &mut Claim) {
    claim
        .support
        .retain(|support| support.source_config_id != ITEM_SUPPORT_SOURCE_CONFIG_ID);
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
    Dismiss {
        target: ConflictTarget,
        dismissal: Dismissal,
    },
    Waive {
        target: ConflictTarget,
        waiver: Waiver,
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
            Self::Dismiss { target, dismissal } => LifecycleReplayRequest::Dismiss {
                target: *target,
                terms: dismissal.terms(),
            },
            Self::Waive { target, waiver } => LifecycleReplayRequest::Waive {
                target: *target,
                terms: waiver.terms(),
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

/// `remember(dismiss)` arguments: an adjudicator's judgement that a conflict
/// is not a real disagreement.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DismissArgs {
    conflict_id: Value,
    expected_revision: i64,
    expected_member_count: i64,
    reason_kind: DismissalReasonKindV1,
    rationale: String,
}

/// `remember(waive)` arguments: an adjudicator's time-boxed acceptance of a
/// conflict's current episode.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WaiveArgs {
    conflict_id: Value,
    expected_revision: i64,
    expected_member_count: i64,
    reason_kind: WaiverReasonKindV1,
    rationale: String,
    expires_in_hours: i64,
    #[serde(default)]
    review_in_hours: Option<i64>,
}

/// A parsed, validated dismissal.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Dismissal {
    reason_kind: DismissalReasonKindV1,
    rationale: String,
}

impl Dismissal {
    fn terms(&self) -> DismissalTerms<'_> {
        DismissalTerms {
            reason_kind: self.reason_kind,
            rationale: &self.rationale,
        }
    }
}

/// A parsed, validated waiver.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Waiver {
    reason_kind: WaiverReasonKindV1,
    rationale: String,
    expires_in_hours: u16,
    review_in_hours: Option<u16>,
}

impl Waiver {
    fn terms(&self) -> WaiverTerms<'_> {
        WaiverTerms {
            reason_kind: self.reason_kind,
            rationale: &self.rationale,
            expires_in_hours: self.expires_in_hours,
            review_in_hours: self.review_in_hours,
        }
    }
}

fn parse_dismiss_arguments(
    arguments: Map<String, Value>,
) -> ServiceResult<(ConflictTarget, Dismissal)> {
    let args: DismissArgs = from_arguments(arguments, "remember dismiss")?;
    let target = conflict_target(
        &args.conflict_id,
        args.expected_revision,
        Some(args.expected_member_count),
    )?;
    validate_rationale(&args.rationale).map_err(ServiceError::InvalidRequest)?;
    Ok((
        target,
        Dismissal {
            reason_kind: args.reason_kind,
            rationale: args.rationale,
        },
    ))
}

fn parse_waive_arguments(arguments: Map<String, Value>) -> ServiceResult<(ConflictTarget, Waiver)> {
    let args: WaiveArgs = from_arguments(arguments, "remember waive")?;
    let target = conflict_target(
        &args.conflict_id,
        args.expected_revision,
        Some(args.expected_member_count),
    )?;
    validate_rationale(&args.rationale).map_err(ServiceError::InvalidRequest)?;
    let hours = |value: i64, field: &str| {
        u16::try_from(value).map_err(|_| {
            ServiceError::InvalidRequest(format!(
                "{field} must be between 1 and {}",
                crate::ledger::MAX_WAIVER_HOURS
            ))
        })
    };
    let expires_in_hours = hours(args.expires_in_hours, "expires_in_hours")?;
    let review_in_hours = args
        .review_in_hours
        .map(|review| hours(review, "review_in_hours"))
        .transpose()?;
    validate_waiver_hours(expires_in_hours, review_in_hours)
        .map_err(ServiceError::InvalidRequest)?;
    Ok((
        target,
        Waiver {
            reason_kind: args.reason_kind,
            rationale: args.rationale,
            expires_in_hours,
            review_in_hours,
        },
    ))
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
    synthetic_claim_coordinate(&hit.source, &hit.chunk_id)
}

/// The claim id a `(source, chunk_id)` coordinate names when it is a
/// synthetic `claim:{id}` chunk.
fn synthetic_claim_coordinate(source: &str, chunk_id: &str) -> Option<i64> {
    if source != SYNTHETIC_CLAIM_SOURCE {
        return None;
    }
    chunk_id
        .strip_prefix("claim:")
        .and_then(|id| id.parse::<i64>().ok())
        .filter(|id| (1..=MAX_SAFE_INTEGER).contains(id) && chunk_id == format!("claim:{id}"))
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

/// `remember(assert)` arguments: the assertion and nothing else. The scope,
/// actor, and key travel beside it, never inside it.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AssertArgs {
    assertion: RememberAssertInputV1,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GetArgs {
    #[serde(default)]
    kind: Option<String>,
    /// Absent when the request left it out; an explicit `null` is present
    /// and refused by the kind's own id check, as before key lookups.
    #[serde(default, deserialize_with = "present_value")]
    id: Option<Value>,
    /// `kind=claim` only: the exact stored key to look up.
    #[serde(default)]
    key: Option<String>,
    /// `kind=claim` only: with `predicate`, the key's parts, normalized as
    /// `record` normalizes them.
    #[serde(default)]
    subject: Option<String>,
    #[serde(default)]
    predicate: Option<String>,
    /// Key lookups only: superseded and retracted claims too.
    #[serde(default)]
    include_history: bool,
}

/// Any present JSON value, `null` included, as `Some`.
fn present_value<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Value>, D::Error> {
    Value::deserialize(deserializer).map(Some)
}

/// What a `get` names: one entity by id, or every claim on a key.
#[derive(Debug)]
enum GetTarget {
    Id(Value),
    ClaimKey(String),
}

impl GetArgs {
    /// The id or the key, refusing a request that names both or neither.
    fn target(self) -> ServiceResult<(Option<String>, GetTarget, bool)> {
        let key = match (self.key, self.subject, self.predicate) {
            (Some(_), Some(_), _) | (Some(_), _, Some(_)) => {
                return Err(ServiceError::InvalidRequest(
                    "send key, or subject and predicate, not both".into(),
                ));
            }
            (Some(key), None, None) => {
                let key = key.trim().to_owned();
                if key.is_empty() {
                    return Err(ServiceError::InvalidRequest("key must not be empty".into()));
                }
                Some(key)
            }
            (None, Some(subject), Some(predicate)) => {
                Some(claim_key_from_parts(&subject, &predicate).ok_or_else(|| {
                    ServiceError::InvalidRequest(
                        "subject and predicate normalize to an empty key".into(),
                    )
                })?)
            }
            (None, Some(_), None) | (None, None, Some(_)) => {
                return Err(ServiceError::InvalidRequest(
                    "a key lookup needs both subject and predicate".into(),
                ));
            }
            (None, None, None) => None,
        };
        match (self.id, key) {
            (Some(_), Some(_)) => Err(ServiceError::InvalidRequest(
                "send id, or a key, not both".into(),
            )),
            (Some(id), None) => {
                if self.include_history {
                    return Err(ServiceError::InvalidRequest(
                        "include_history on get applies to a key lookup; a claim's own \
                         lifecycle history is returned with its id"
                            .into(),
                    ));
                }
                Ok((self.kind, GetTarget::Id(id), false))
            }
            (None, Some(key)) => Ok((self.kind, GetTarget::ClaimKey(key), self.include_history)),
            (None, None) => Err(ServiceError::InvalidRequest(
                "recall get requires id, or, for kind=claim, key or subject and predicate".into(),
            )),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConflictArgs {
    #[serde(default)]
    include_resolved: bool,
    #[serde(default)]
    limit: Option<usize>,
    /// Only the conflicts detected on this exact stored key.
    #[serde(default)]
    claim_key: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyArgs {}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DiscrepanciesArgs {
    #[serde(default)]
    include_resolved: bool,
    #[serde(default)]
    limit: Option<usize>,
    /// One episode, in any state, with its lifecycle history.
    #[serde(default)]
    id: Option<String>,
}

fn parse_episode_id(id: &str) -> ServiceResult<DiscrepancyEpisodeFingerprintV1> {
    Sha256Digest::from_str(id)
        .map(DiscrepancyEpisodeFingerprintV1::from_digest)
        .map_err(|_| {
            ServiceError::InvalidRequest(
                "recall discrepancies: id must be a 64-character lowercase hex episode id".into(),
            )
        })
}

/// The `recall(discrepancies)` result: `data.discrepancies`, `data.specs`,
/// and `data.coverage`, with the read's warnings. Discrepancies are not
/// conflicts, so the conflict fields stay empty and not evaluated.
fn discrepancies_result(answer: &SpecConformanceAnswerV1) -> ServiceResult<RecallResult> {
    let serialized = |value: serde_json::Result<Value>| {
        value.map_err(|error| {
            ServiceError::Internal(format!("failed to serialize recall discrepancies: {error}"))
        })
    };
    let mut result = RecallResult::new(json!({
        "discrepancies": serialized(serde_json::to_value(&answer.discrepancies))?,
        "specs": serialized(serde_json::to_value(&answer.specs))?,
        "coverage": serialized(serde_json::to_value(&answer.coverage))?,
    }));
    result.warnings = answer
        .warnings
        .iter()
        .map(|warning| json!(warning))
        .collect();
    result.conflict_coverage = ConflictCoverage::not_evaluated();
    Ok(result)
}

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
    validate_query_and_source(args)?;
    if args.include_history && !matches!(args.kind.as_deref(), Some("claim" | "assertion")) {
        return Err(ServiceError::InvalidRequest(
            "include_history is supported only for kind=claim or kind=assertion".into(),
        ));
    }
    Ok(())
}

/// The query and `source` bounds every search kind shares.
fn validate_query_and_source(args: &SearchArgs) -> ServiceResult<()> {
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

fn reject_evidence_unsupported_filters(args: &SearchArgs) -> ServiceResult<()> {
    if args.max_per_source_id.is_some()
        || args.min_score.is_some()
        || args.intent.is_some()
        || args.include_history
    {
        return Err(ServiceError::InvalidRequest(
            "evidence search does not support max_per_source_id, min_score, intent, or include_history; use kind=chunk for those filters"
                .into(),
        ));
    }
    Ok(())
}

/// The evidence source an argument names: one of the closed set
/// [`EvidenceSourceFilterV1::ALL`], or none.
fn evidence_source_filter(source: Option<&str>) -> ServiceResult<Option<EvidenceSourceFilterV1>> {
    source
        .map(|source| {
            EvidenceSourceFilterV1::parse(source).ok_or_else(|| {
                ServiceError::InvalidRequest(format!(
                    "evidence search source must be one of {}; {source:?} is not (kind=item takes a provider such as slack)",
                    EvidenceSourceFilterV1::ALL
                        .map(EvidenceSourceFilterV1::as_str)
                        .join(", ")
                ))
            })
        })
        .transpose()
}

/// A hit's id: the lowercase hex content address `search` returned.
fn parse_evidence_id(value: &Value) -> ServiceResult<Sha256Digest> {
    value
        .as_str()
        .and_then(|id| Sha256Digest::from_str(id).ok())
        .ok_or_else(|| {
            ServiceError::InvalidRequest(
                "evidence id must be a hit's id: 64 lowercase hex characters".into(),
            )
        })
}

/// Whether a query vector can be compared with the dense tier's: its width,
/// finite components, and not the zero vector, whose cosine is undefined.
fn dense_query_vector_usable(vector: &[f32]) -> bool {
    vector.len() == EMBEDDING_DIMENSIONS as usize
        && vector.iter().all(|component| component.is_finite())
        && vector.iter().any(|component| *component != 0.0)
}

/// The recall result of one evidence search.
fn evidence_search_result(search: EvidenceSearchV1) -> RecallResult {
    let EvidenceSearchV1 {
        hits,
        readiness,
        sources,
        absence,
    } = search;
    let mut warnings = evidence_warnings(&readiness, &sources);
    // The lane is served but this search carried no vector: the process
    // embedder gave none the lane could use.
    if readiness.dense_lane == EvidenceDenseLaneV1::NoQueryVector {
        warnings.push(json!({
            "code": "evidence_query_not_embedded",
            "message": "the query has no usable embedding under the pinned model, so only the lexical lane ran"
        }));
    }
    let lanes = if readiness.dense_lane == EvidenceDenseLaneV1::Used {
        json!(["lexical", "dense"])
    } else {
        json!(["lexical"])
    };
    let dense_lane = readiness.dense_lane;
    let mut result = RecallResult::new(json!({
        "hits": hits,
        "readiness": readiness,
        "sources": sources,
        "absence": absence,
    }));
    result.conflict_coverage = ConflictCoverage::not_evaluated();
    result.warnings = warnings;
    result.diagnostics.insert(
        "retrieval".into(),
        json!({
            "tier": "evidence",
            "lanes": lanes,
            "fusion": "rrf",
            "dense_lane": dense_lane,
            "dense_min_cosine_similarity": RETRIEVAL_DENSE_MIN_COSINE_SIMILARITY,
            "absence_dense_min_cosine_similarity": ABSENCE_DENSE_MIN_COSINE_SIMILARITY,
            "absence_neighbour_band_floor": ABSENCE_NEIGHBOUR_BAND_FLOOR,
        }),
    );
    result
}

/// `recall(get, kind=evidence)`: one body's recall text by a hit's id.
async fn get_evidence(evidence: &dyn EvidenceRecall, id: &Value) -> ServiceResult<RecallResult> {
    let id = parse_evidence_id(id)?;
    let body = evidence.get(id).await.map_err(service_error)?;
    let mut result = RecallResult::new(json!({ "evidence": body }));
    result.conflict_coverage = ConflictCoverage::not_evaluated();
    Ok(result)
}

/// `recall(get, kind=item)`: one item by its id, a version URI, or its
/// provider URL. An item no presented head matches is `null`.
async fn get_item(items: &dyn ItemRecall, id: &Value) -> ServiceResult<RecallResult> {
    let reference = id
        .as_str()
        .ok_or("an item id must be a string")
        .and_then(ItemReferenceV1::parse)
        .map_err(|message| ServiceError::InvalidRequest(message.into()))?;
    let item = items.get(&reference).await.map_err(service_error)?;
    let mut result = RecallResult::new(json!({ "item": item }));
    result.conflict_coverage = ConflictCoverage::not_evaluated();
    Ok(result)
}

/// The recall result of one item search: the evidence answer's shape, with
/// the evidence warnings over the collectors' readiness and sources.
fn item_search_result(search: ItemSearchV1) -> RecallResult {
    let ItemSearchV1 {
        hits,
        readiness,
        sources,
        absence,
    } = search;
    let mut warnings = evidence_warnings(&readiness.as_evidence(), &sources);
    if readiness.dense_lane == EvidenceDenseLaneV1::NoQueryVector {
        warnings.push(json!({
            "code": "item_query_not_embedded",
            "message": "the query has no usable embedding under the pinned model, so only the lexical lane ran"
        }));
    }
    let lanes = if readiness.dense_lane == EvidenceDenseLaneV1::Used {
        json!(["lexical", "dense"])
    } else {
        json!(["lexical"])
    };
    let dense_lane = readiness.dense_lane;
    let mut result = RecallResult::new(json!({
        "hits": hits,
        "readiness": readiness,
        "sources": sources,
        "absence": absence,
    }));
    result.conflict_coverage = ConflictCoverage::not_evaluated();
    result.warnings = warnings;
    result.diagnostics.insert(
        "retrieval".into(),
        json!({
            "tier": "item",
            "lanes": lanes,
            "fusion": "rrf",
            "dense_lane": dense_lane,
            "dense_min_cosine_similarity": RETRIEVAL_DENSE_MIN_COSINE_SIMILARITY,
            "absence_dense_min_cosine_similarity": ABSENCE_DENSE_MIN_COSINE_SIMILARITY,
            "absence_neighbour_band_floor": ABSENCE_NEIGHBOUR_BAND_FLOOR,
        }),
    );
    result
}

/// How long `recall(status)` waits for its optional blocks (evidence and
/// spec conformance).
///
/// The evidence read counts the scope's projection tiers, which grows with the
/// evidence, while `status` is the cheap health check clients poll. Bounded
/// well inside the MCP server's 30-second request deadline, a slow block read
/// degrades to its `*_status_unavailable` warning instead of failing the
/// whole status call. The blocks are read concurrently
/// ([`optional_status_blocks`]), so together they cost at most one deadline
/// however many are served.
const OPTIONAL_STATUS_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

/// A block of `recall(status)` and the warnings it adds.
type StatusBlock = (Value, Vec<Value>);

/// The evidence and spec conformance blocks of `recall(status)`, each read
/// only where it is served and each bounded by `deadline`. The two reads run
/// concurrently, so a slow pair costs one deadline, not two.
async fn optional_status_blocks(
    evidence: Option<&dyn EvidenceRecall>,
    spec_conformance: Option<&dyn SpecConformanceRead>,
    deadline: std::time::Duration,
) -> (Option<StatusBlock>, Option<StatusBlock>) {
    let evidence = async {
        match evidence {
            Some(evidence) => Some(evidence_status_within(evidence, deadline).await),
            None => None,
        }
    };
    let spec_conformance = async {
        match spec_conformance {
            Some(reader) => Some(spec_conformance_status_within(reader, deadline).await),
            None => None,
        }
    };
    tokio::join!(evidence, spec_conformance)
}

/// `recall(status).legacy_claim_keys` and the warnings it adds: how many of
/// the project's lifecycle-current claims still carry a key written before
/// `_` became a key separator, so the conflicts the old keys hide are visible
/// rather than silent. The count is a lower bound once the bounded scan
/// fills up, and a failed or slow read is `null` with a warning, never a
/// failed status.
async fn legacy_claim_keys_within(
    ledger: &dyn ClaimLedger,
    scope: &FleetScope,
    deadline: std::time::Duration,
) -> (Value, Vec<Value>) {
    let legacy = tokio::time::timeout(deadline, ledger.legacy_claim_keys(scope))
        .await
        .unwrap_or_else(|_| {
            Err(FleetError::Memory(format!(
                "the legacy claim key read did not finish within {}s",
                deadline.as_secs_f32()
            )))
        });
    legacy_claim_keys_block(legacy)
}

/// The status field and warnings for one legacy claim key read.
fn legacy_claim_keys_block(legacy: crate::Result<LegacyClaimKeysV1>) -> (Value, Vec<Value>) {
    match legacy {
        Ok(legacy) => {
            let mut warnings = Vec::new();
            if legacy.count > 0 {
                let bound = if legacy.bound_exceeded {
                    "at least "
                } else {
                    ""
                };
                warnings.push(json!({
                    "code": "legacy_claim_keys",
                    "message": format!(
                        "{bound}{} lifecycle-current claims carry a key written before `_` became a key separator, so a claim recorded since under the same words takes another key and no conflict between them is detected; supersede each with the same subject and predicate to move it onto its current key",
                        legacy.count
                    ),
                }));
            }
            (
                json!({
                    "count": legacy.count,
                    "bound_exceeded": legacy.bound_exceeded,
                    "sample": legacy.sample,
                }),
                warnings,
            )
        }
        Err(error) => {
            tracing::warn!(error = %error, "legacy claim key read failed");
            (
                Value::Null,
                vec![json!({
                    "code": "legacy_claim_keys_unavailable",
                    "message": "the count of claims keyed under the earlier normalizer could not be read; remember and recall are still served",
                })],
            )
        }
    }
}

/// The lower edge of the dense neighbour band the absence verdict refuses to
/// call `absent` in: a dense-only neighbour at or above it (and below the
/// dense bound) makes the verdict `unknown`. The verdict's own copy lives in
/// `evidence_recall::verdict` as `ABSENCE_NEIGHBOUR_BAND_FLOOR`; this mirror
/// only publishes the contract in `recall(status)`.
const ABSENCE_NEIGHBOUR_BAND_FLOOR: f32 = 0.30;

/// The cosine bounds of the absence verdict, and what it is anchored on, as
/// `recall(status).absence_contract`: what `absent` and `unknown` mean.
fn absence_contract() -> Value {
    json!({
        "dense_bound": cosine_bound(crate::evidence_recall::ABSENCE_DENSE_MIN_COSINE_SIMILARITY),
        "neighbour_band_floor": cosine_bound(ABSENCE_NEIGHBOUR_BAND_FLOOR),
        "dense_vote_excluded": crate::evidence_recall::DENSE_VOTE_EXCLUDED_MEDIA_TYPES,
        "anchored_on": "lexical",
    })
}

/// A cosine bound as the decimal it was written as, not the nearest binary
/// `f32` widened (`0.45`, not `0.44999998807907104`).
fn cosine_bound(value: f32) -> f64 {
    value
        .to_string()
        .parse()
        .unwrap_or_else(|_| f64::from(value))
}

/// Open conflicts one overlay read covers: the ledger's episode bound.
const STATUS_OVERLAY_EPISODES: usize = 100;

/// `recall(status).conflicts` and the warnings it adds: the open conflicts
/// (bounded, oldest first), how many of them read `acknowledged` or `waived`
/// under the lifecycle overlay where it is served, and the oldest open
/// one's detection time. A failed or slow read is `null` with a warning,
/// never a failed status.
async fn conflicts_status_within(
    ledger: &dyn ClaimLedger,
    scope: &FleetScope,
    overlay_served: bool,
    deadline: std::time::Duration,
) -> (Value, Vec<Value>) {
    let read = async {
        let open = ledger.open_conflicts(scope).await?;
        let overlay_states = if overlay_served && !open.rows.is_empty() {
            let mut states = HashMap::with_capacity(open.rows.len());
            for chunk in open.rows.chunks(STATUS_OVERLAY_EPISODES) {
                let episodes = chunk
                    .iter()
                    .map(|row| (row.id, overlay_episode_revision("open", row.revision)))
                    .collect::<Vec<_>>();
                let rows = ledger.conflict_lifecycle_rows(scope, &episodes).await?;
                for row in chunk {
                    let events = rows.events.get(&row.id).map_or(&[][..], Vec::as_slice);
                    let overlay = derive_overlay(
                        "open",
                        row.revision,
                        row.member_count,
                        events,
                        rows.truncated.contains(&row.id),
                        rows.evaluated_at,
                    );
                    states.insert(row.id, overlay.state);
                }
            }
            Some(states)
        } else {
            None
        };
        Ok::<_, FleetError>((open, overlay_states))
    };
    let outcome = tokio::time::timeout(deadline, read)
        .await
        .unwrap_or_else(|_| {
            Err(FleetError::Memory(format!(
                "the open conflict read did not finish within {}s",
                deadline.as_secs_f32()
            )))
        });
    conflicts_status_block(outcome)
}

/// The status field and warnings for one open-conflict read; `overlay
/// states` is `None` where the lifecycle overlay is not served, and then so
/// are the `acknowledged` and `waived` counts.
fn conflicts_status_block(
    outcome: crate::Result<(crate::ledger::OpenConflictsV1, Option<HashMap<i64, String>>)>,
) -> (Value, Vec<Value>) {
    match outcome {
        Ok((open, overlay_states)) => {
            let counted = |state: &str| {
                overlay_states
                    .as_ref()
                    .map(|states| states.values().filter(|value| *value == state).count())
            };
            let mut warnings = Vec::new();
            if open.bound_exceeded {
                warnings.push(json!({
                    "code": "open_conflicts_bound_exceeded",
                    "message": format!(
                        "more than {} conflicts are open; the counts are lower bounds over the oldest ones",
                        crate::ledger::MAX_OPEN_CONFLICT_ROWS
                    ),
                }));
            }
            (
                json!({
                    "open": open.rows.len(),
                    "acknowledged": counted("acknowledged"),
                    "waived": counted("waived"),
                    "oldest_open_at": open.rows.first().map(|row| row.detected_at),
                    "bound_exceeded": open.bound_exceeded,
                }),
                warnings,
            )
        }
        Err(error) => {
            tracing::warn!(error = %error, "open conflict status read failed");
            (
                Value::Null,
                vec![json!({
                    "code": "conflicts_status_unavailable",
                    "message": "the open conflict counts could not be read; remember and recall are still served",
                })],
            )
        }
    }
}

/// `recall(status).quarantine` and the warnings it adds: the scope's
/// evidence quarantine by reason and its newest preimage disagreements,
/// read through the runtime role's grant. A failed or slow read is `null`
/// with a warning, never a failed status.
async fn quarantine_status_within(
    pool: &sqlx::PgPool,
    scope: &FleetScope,
    deadline: std::time::Duration,
) -> (Value, Vec<Value>) {
    let summary = tokio::time::timeout(
        deadline,
        crate::evidence_ledger::quarantine_summary(pool, scope.tenant_id, &scope.project),
    )
    .await
    .unwrap_or_else(|_| {
        Err(FleetError::Memory(format!(
            "the quarantine read did not finish within {}s",
            deadline.as_secs_f32()
        )))
    });
    quarantine_status_block(summary)
}

/// The status field and warnings for one quarantine read.
fn quarantine_status_block(
    summary: crate::Result<crate::evidence_ledger::QuarantineSummaryV1>,
) -> (Value, Vec<Value>) {
    match summary {
        Ok(summary) => {
            let mut warnings = Vec::new();
            let disagreements = summary
                .by_reason
                .get("preimage_disagreement")
                .copied()
                .unwrap_or_default();
            if disagreements > 0 {
                let bound = if summary.bound_exceeded {
                    "at least "
                } else {
                    ""
                };
                warnings.push(json!({
                    "code": "quarantine_preimage_disagreement",
                    "message": format!(
                        "{bound}{disagreements} evidence deliveries were quarantined because two reports disagreed on one source fact's bytes; quarantine.preimage_disagreement_sample names the newest, and an operator reconciles them (a retry cannot)"
                    ),
                }));
            }
            (
                json!({
                    "by_reason": summary.by_reason,
                    "bound_exceeded": summary.bound_exceeded,
                    "preimage_disagreement_sample": summary.preimage_disagreement_sample,
                }),
                warnings,
            )
        }
        Err(error) => {
            tracing::warn!(error = %error, "quarantine status read failed");
            (
                Value::Null,
                vec![json!({
                    "code": "quarantine_unavailable",
                    "message": "the evidence quarantine could not be read; remember and recall are still served",
                })],
            )
        }
    }
}

/// `recall(status).spec_conformance` and the warnings it adds. A failed or
/// slow read is a warning, never a failed status.
async fn spec_conformance_status_within(
    reader: &dyn SpecConformanceRead,
    deadline: std::time::Duration,
) -> (Value, Vec<Value>) {
    let status = tokio::time::timeout(deadline, reader.status())
        .await
        .unwrap_or_else(|_| {
            Err(FleetError::Memory(format!(
                "the spec conformance status read did not finish within {}s",
                deadline.as_secs_f32()
            )))
        });
    match status {
        Ok(status) => (
            json!({
                "served": true,
                "active_specs": status.active_specs,
                "scheduled_specs": status.scheduled_specs,
                "expired_specs": status.expired_specs,
                "open_discrepancies": status.open_discrepancies,
                "unknown_specs": status.unknown_specs,
                "never_checked_specs": status.never_checked_specs,
            }),
            status
                .warnings
                .iter()
                .map(|warning| json!(warning))
                .collect(),
        ),
        Err(error) => {
            tracing::warn!(error = %error, "spec conformance status read failed");
            (
                json!({
                    "served": true,
                    "active_specs": null,
                    "scheduled_specs": null,
                    "expired_specs": null,
                    "open_discrepancies": null,
                    "unknown_specs": null,
                    "never_checked_specs": null,
                }),
                vec![json!({
                    "code": "spec_conformance_status_unavailable",
                    "message": "the spec conformance counts could not be read; recall(discrepancies) is still served"
                })],
            )
        }
    }
}

/// `recall(status).evidence` and the warnings it adds. A failed or slow read
/// is a warning, never a failed status.
async fn evidence_status_within(
    evidence: &dyn EvidenceRecall,
    deadline: std::time::Duration,
) -> (Value, Vec<Value>) {
    let status = tokio::time::timeout(deadline, evidence.status())
        .await
        .unwrap_or_else(|_| {
            Err(FleetError::Memory(format!(
                "the evidence status read did not finish within {}s",
                deadline.as_secs_f32()
            )))
        });
    match status {
        Ok(status) => {
            let mut warnings = evidence_warnings(&status.readiness, &status.sources);
            let mut block = json!({
                "served": true,
                "readiness": status.readiness,
                "sources": status.sources,
            });
            if let Some(collectors) = status.collectors {
                block["collectors"] = json!(collectors);
                if collectors.dead_letters_24h > 0 {
                    warnings.push(json!({
                        "code": "evidence_collector_dead_letters",
                        "message": format!(
                            "{} collected items or staged parts were dead-lettered in the last 24 hours; memory_collector_dead_letters_v1 holds each one's reason and digests, never its content",
                            collectors.dead_letters_24h
                        ),
                    }));
                }
            }
            (block, warnings)
        }
        Err(error) => {
            tracing::warn!(error = %error, "evidence recall status read failed");
            (
                json!({ "served": true, "readiness": null, "sources": null }),
                vec![json!({
                    "code": "evidence_status_unavailable",
                    "message": "evidence readiness and sources could not be read; recall(kind=evidence) is still served"
                })],
            )
        }
    }
}

/// The collected-item and ingress-hint warnings of one readiness read, in
/// pipeline order: staged parts, pending hints, then what this login cannot
/// read.
fn collector_warnings(readiness: &EvidenceReadinessV1, warnings: &mut Vec<Value>) {
    if let Some(pending) = readiness
        .items_awaiting_admission
        .filter(|pending| *pending > 0)
    {
        warnings.push(json!({
            "code": "evidence_items_pending",
            "message": format!(
                "{pending} collected item parts are staged and not yet admitted as evidence; the worker's collect step admits them"
            ),
        }));
    }
    if let Some(pending) = readiness
        .hints_awaiting_fetch
        .filter(|pending| *pending > 0)
    {
        warnings.push(json!({
            "code": "evidence_hints_pending",
            "message": format!(
                "{pending} signed provider webhooks name objects not yet re-read; the worker's collect step reads them"
            ),
        }));
    }
    if readiness.hints_unreadable {
        warnings.push(json!({
            "code": "evidence_hints_unreadable",
            "message": "this login cannot read the ingress hint queue, so a signed provider change may be waiting unseen and an empty answer is unknown; re-apply the runtime grants"
        }));
    }
    if readiness.collector_state_unreadable {
        warnings.push(json!({
            "code": "evidence_collector_state_unreadable",
            "message": "this login cannot read the collector tables, so no collected item is recalled and an empty answer is unknown; re-apply the runtime grants"
        }));
    }
}

/// What `kind` covers, as `recall`'s schema says it; the `kind` property's
/// description and the empty-answer hint carry the same text.
const KIND_COVERAGE: &str = "chunk (default): the seed corpus and recorded claims. item: Slack, Linear, Granola, documents. evidence: git history, agent transcripts, CI, and items. claim: recorded claims by meaning";

/// The warning an empty chunk answer carries when other kinds are served:
/// an agent that omitted `kind` searched only the seed corpus and the claim
/// chunks, and what it asked for may be an item or evidence.
fn other_kinds_hint(items: bool, evidence: bool) -> Option<Value> {
    let kinds: Vec<&str> = [(items, "item"), (evidence, "evidence")]
        .into_iter()
        .filter_map(|(served, kind)| served.then_some(kind))
        .collect();
    (!kinds.is_empty()).then(|| {
        json!({
            "code": "other_kinds_available",
            "message": format!("no chunk matched; {KIND_COVERAGE}"),
            "kinds": kinds,
        })
    })
}

/// What an evidence answer's readiness and sources warn about: projection
/// lag, pending ingest, a disabled dense lane, failed or stale sources, and a
/// cut listing. The absence verdict carries the same facts as reasons; these
/// say them whether or not anything matched.
fn evidence_warnings(readiness: &EvidenceReadinessV1, sources: &EvidenceSourcesV1) -> Vec<Value> {
    let mut warnings = Vec::new();
    if readiness.events_awaiting_body_projection > 0 {
        let by_kind = readiness.lag_by_kind.map_or_else(String::new, |lag| {
            format!(" ({} collected item parts, {} other)", lag.items, lag.other)
        });
        warnings.push(json!({
            "code": "evidence_body_projection_lag",
            "message": format!(
                "{} accepted evidence events are waiting for the body projector{by_kind}; the newest evidence is not searchable until the worker's project step runs",
                readiness.events_awaiting_body_projection
            ),
            "lag_by_kind": readiness.lag_by_kind,
        }));
    }
    if readiness.transcript_turns_awaiting_admission > 0 {
        warnings.push(json!({
            "code": "evidence_ingest_pending",
            "message": format!(
                "{} transcript turns are staged and not yet admitted as evidence",
                readiness.transcript_turns_awaiting_admission
            ),
        }));
    }
    collector_warnings(readiness, &mut warnings);
    if !readiness.lexical_current {
        warnings.push(json!({
            "code": "evidence_lexical_projection_lag",
            "message": "some evidence bodies have not been through the lexical projector yet"
        }));
    }
    if readiness.dense_lane == EvidenceDenseLaneV1::DisabledForeignModel {
        warnings.push(json!({
            "code": "evidence_dense_lane_disabled",
            "message": "the dense lane is off: the scope's dense tier holds vectors of another embedding model; only the lexical lane runs"
        }));
    } else if !readiness.dense_current {
        warnings.push(json!({
            "code": "evidence_dense_projection_lag",
            "message": "some lexically searchable bodies have no embedding yet; the dense lane cannot find them"
        }));
    }
    let instances = |matches: fn(&EvidenceSourceV1) -> bool| {
        sources
            .active
            .iter()
            .filter(|source| matches(source))
            .map(|source| source.connector_instance.clone())
            .collect::<Vec<_>>()
    };
    let failed = instances(|source| source.last_outcome == WorkerSourceOutcomeV1::Failed);
    if !failed.is_empty() {
        warnings.push(json!({
            "code": "evidence_source_failed",
            "message": "the worker's last attempt at these sources failed; see each source's last_error",
            "connector_instances": failed,
        }));
    }
    let stale = instances(|source| source.stale);
    if !stale.is_empty() {
        warnings.push(json!({
            "code": "evidence_source_stale",
            "message": "these sources' last completed check is older than their staleness bound",
            "connector_instances": stale,
        }));
    }
    if sources.truncated {
        warnings.push(json!({
            "code": "evidence_sources_truncated",
            "message": format!(
                "more than {MAX_EVIDENCE_SOURCES} sources are active; only the first are listed"
            ),
        }));
    }
    warnings
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

/// The oldest key-lookup claims that fit `byte_budget` serialized, and
/// whether any newer one was cut.
fn key_claims_within_bytes(claims: Vec<KeyClaimV1>, byte_budget: usize) -> (Vec<KeyClaimV1>, bool) {
    let mut used = 0_usize;
    let mut kept = Vec::with_capacity(claims.len());
    let total = claims.len();
    for entry in claims {
        // One separator byte per array element.
        let size = serde_json::to_vec(&entry)
            .map_or(usize::MAX, |bytes| bytes.len())
            .saturating_add(1);
        used = used.saturating_add(size);
        if used > byte_budget {
            break;
        }
        kept.push(entry);
    }
    let cut = kept.len() < total;
    (kept, cut)
}

/// The newest claim lifecycle events that fit `byte_budget` serialized,
/// oldest first; a cut marks the history truncated.
fn claim_history_within_bytes(mut history: ClaimHistoryV1, byte_budget: usize) -> ClaimHistoryV1 {
    let mut used = 0_usize;
    let mut kept = 0_usize;
    for event in history.events.iter().rev() {
        // One separator byte per array element.
        let size = serde_json::to_vec(event)
            .map_or(usize::MAX, |bytes| bytes.len())
            .saturating_add(1);
        used = used.saturating_add(size);
        if used > byte_budget {
            break;
        }
        kept += 1;
    }
    let dropped = history.events.len() - kept;
    if dropped > 0 {
        history.events.drain(..dropped);
        history.truncated = true;
    }
    history
}

/// A value's serialized size; one that cannot be serialized counts as
/// unbounded.
fn json_bytes(value: &Value) -> usize {
    serde_json::to_vec(value).map_or(usize::MAX, |bytes| bytes.len())
}

/// The claim search projection: text and passage cut to a page-sized bound,
/// support left to `get`, and the value carried up to
/// [`MAX_CLAIM_HIT_VALUE_BYTES`]. Whatever is left out is flagged on the hit
/// (`support_elided`, `value_elided`) rather than dropped silently, and the
/// claim's `revision` and `actor` are repeated beside it.
fn compact_claim_hits(mut hits: Vec<SemanticClaimHit>) -> Vec<SemanticClaimHit> {
    const MAX_PASSAGE_CHARS: usize = 2_000;
    for hit in &mut hits {
        hit.claim.text = truncate_chars(&hit.claim.text, MAX_PASSAGE_CHARS);
        if !hit.claim.support.is_empty() {
            hit.claim.support.clear();
            hit.support_elided = true;
        }
        if hit
            .claim
            .value
            .as_ref()
            .is_some_and(|value| json_bytes(value) > MAX_CLAIM_HIT_VALUE_BYTES)
        {
            hit.claim.value = None;
            hit.value_elided = true;
        }
        hit.revision = hit.claim.revision;
        hit.actor.clone_from(&hit.claim.actor);
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
    fn get_arguments_name_an_id_or_exactly_one_claim_key() {
        let parse = |value: Value| {
            from_arguments::<GetArgs>(value.as_object().cloned().unwrap(), "recall get")
                .and_then(GetArgs::target)
        };
        let (kind, target, history) = parse(json!({ "kind": "claim", "id": 7 })).unwrap();
        assert_eq!(kind.as_deref(), Some("claim"));
        assert!(matches!(target, GetTarget::Id(Value::Number(_))));
        assert!(!history);

        // A key is looked up exactly as sent, so a legacy key stays findable.
        let (_, target, history) =
            parse(json!({ "kind": "claim", "key": " include_transcript_default::enabled " }))
                .unwrap();
        assert!(matches!(
            target,
            GetTarget::ClaimKey(ref key) if key == "include_transcript_default::enabled"
        ));
        assert!(!history);

        // Parts are normalized as record normalizes them.
        let (_, target, history) = parse(json!({
            "kind": "claim",
            "subject": "Merged_Build",
            "predicate": " rollout mode",
            "include_history": true
        }))
        .unwrap();
        assert!(matches!(
            target,
            GetTarget::ClaimKey(ref key) if key == "merged-build::rollout-mode"
        ));
        assert!(history);

        for (refused, expected) in [
            (json!({ "kind": "claim" }), "requires id"),
            (
                json!({ "kind": "claim", "id": 7, "key": "a::b" }),
                "not both",
            ),
            (
                json!({ "kind": "claim", "key": "a::b", "subject": "a" }),
                "not both",
            ),
            (
                json!({ "kind": "claim", "subject": "a" }),
                "both subject and predicate",
            ),
            (json!({ "kind": "claim", "key": "  " }), "must not be empty"),
            (
                json!({ "kind": "claim", "subject": "_", "predicate": "-" }),
                "empty key",
            ),
            (
                json!({ "kind": "claim", "id": 7, "include_history": true }),
                "applies to a key lookup",
            ),
        ] {
            let error = parse(refused.clone()).unwrap_err();
            assert!(
                matches!(&error, ServiceError::InvalidRequest(message) if message.contains(expected)),
                "{refused}: {error}"
            );
        }
        // An explicit null id is present, for the kind's own check to refuse.
        let (_, target, _) = parse(json!({ "kind": "chunk", "id": null })).unwrap();
        assert!(matches!(target, GetTarget::Id(Value::Null)));
    }

    #[test]
    fn claim_history_keeps_the_newest_events_within_the_byte_budget() {
        use crate::ledger::ClaimLifecycleEventV1;
        let now = Utc::now();
        let event = |seq: i64, reason: &str| ClaimLifecycleEventV1 {
            event_id: format!("0198a849-f6ae-7d61-9800-{seq:012}"),
            kind: "state_transition".into(),
            actor: Some("agent-a".into()),
            reason: Some(reason.into()),
            from_state: Some("active".into()),
            to_state: Some("superseded".into()),
            revision_before: Some(seq),
            successor_claim_id: (reason == "superseded_by_author").then_some(99),
            conflict_id: None,
            supersedes: None,
            note: Some("after review".into()),
            created_at: now,
            payload_elided: false,
        };
        let size = |event: &ClaimLifecycleEventV1| serde_json::to_vec(event).unwrap().len() + 1;
        let history = ClaimHistoryV1 {
            events: vec![
                event(1, "conflict_detected"),
                event(2, "conflict_detected"),
                event(3, "superseded_by_author"),
            ],
            truncated: false,
            supersedes: Some(7),
        };
        // Room for the newest two, not the oldest.
        let budget = size(&history.events[1]) + size(&history.events[2]);
        let cut = claim_history_within_bytes(history.clone(), budget);
        assert_eq!(
            cut.events
                .iter()
                .map(|event| event.revision_before)
                .collect::<Vec<_>>(),
            [Some(2), Some(3)]
        );
        assert!(cut.truncated);
        assert_eq!(cut.supersedes, Some(7));
        let whole = claim_history_within_bytes(history, usize::MAX);
        assert_eq!(whole.events.len(), 3);
        assert!(!whole.truncated);

        // The wire shape carries only what the transition named.
        let wire = serde_json::to_value(event(3, "superseded_by_author")).unwrap();
        assert_eq!(wire["kind"], "state_transition");
        assert_eq!(wire["actor"], "agent-a");
        assert_eq!(wire["reason"], "superseded_by_author");
        assert_eq!(wire["from_state"], "active");
        assert_eq!(wire["to_state"], "superseded");
        assert_eq!(wire["revision_before"], 3);
        assert_eq!(wire["successor_claim_id"], 99);
        assert_eq!(wire["note"], "after review");
        assert!(wire.get("conflict_id").is_none(), "{wire}");
        assert!(wire.get("supersedes").is_none(), "{wire}");
        assert!(wire.get("payload_elided").is_none(), "{wire}");
        let detected = serde_json::to_value(event(1, "conflict_detected")).unwrap();
        assert!(detected.get("successor_claim_id").is_none(), "{detected}");
    }

    #[test]
    fn key_lookup_claims_are_cut_oldest_first_within_the_byte_budget() {
        let now = Utc::now();
        let entry = |id: i64| KeyClaimV1 {
            claim: Claim {
                id,
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
            value_elided: false,
        };
        let one = serde_json::to_vec(&entry(1)).unwrap().len() + 1;
        let (kept, cut) = key_claims_within_bytes(vec![entry(1), entry(2), entry(3)], one * 2);
        assert_eq!(
            kept.iter().map(|entry| entry.claim.id).collect::<Vec<_>>(),
            [1, 2]
        );
        assert!(cut);
        let (kept, cut) = key_claims_within_bytes(vec![entry(1), entry(2)], one * 2);
        assert_eq!(kept.len(), 2);
        assert!(!cut);
        // The key entry serializes as the claim itself plus its elision flag.
        let wire = serde_json::to_value(KeyClaimV1 {
            value_elided: true,
            ..entry(4)
        })
        .unwrap();
        assert_eq!(wire["id"], 4);
        assert_eq!(wire["claim_key"], "fleet::database");
        assert_eq!(wire["value_elided"], true);
        assert!(wire.get("claim").is_none());
        assert!(
            serde_json::to_value(entry(5))
                .unwrap()
                .get("value_elided")
                .is_none()
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
            revision: 0,
            actor: None,
            value_elided: false,
            support_elided: false,
        };

        let projected = compact_claim_hits(vec![hit.clone()]);
        assert_eq!(
            projected[0].claim.text,
            "Use CockroachDB for shared fleet memory."
        );
        assert!(projected[0].matched_passage.contains("kind: decision"));
        // The value rides on the hit, with the claim's revision and author
        // repeated beside it, so an agent can act on what it found.
        assert_eq!(projected[0].claim.value, Some(json!("cockroachdb")));
        assert!(!projected[0].value_elided);
        assert!(!projected[0].support_elided);
        assert_eq!(projected[0].revision, 1);
        assert_eq!(projected[0].actor.as_deref(), Some("architect"));
        let wire = serde_json::to_value(&projected[0]).unwrap();
        assert_eq!(wire["revision"], 1);
        assert_eq!(wire["actor"], "architect");
        assert!(wire.get("value_elided").is_none(), "{wire}");
        assert!(wire.get("support_elided").is_none(), "{wire}");

        // What the projection leaves out is flagged, never dropped silently.
        let mut oversized = hit;
        oversized.claim.value = Some(json!("x".repeat(MAX_CLAIM_HIT_VALUE_BYTES + 1)));
        oversized.claim.support.push(crate::ledger::ClaimSupport {
            id: 1,
            source_config_id: "docs".into(),
            source: "spec".into(),
            source_id: "adr-1".into(),
            chunk_id: None,
            content_sha256: None,
            excerpt: None,
            relation: "supports".into(),
            state: "current".into(),
            observed_at: now,
            invalidated_at: None,
        });
        let projected = compact_claim_hits(vec![oversized]);
        assert!(projected[0].claim.value.is_none());
        assert!(projected[0].value_elided);
        assert!(projected[0].claim.support.is_empty());
        assert!(projected[0].support_elided);
        let wire = serde_json::to_value(&projected[0]).unwrap();
        assert_eq!(wire["value_elided"], true);
        assert_eq!(wire["support_elided"], true);
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
        offline_service_with(surface, Arc::new(OfflineEmbedder))
    }

    /// [`offline_service`] with its own process embedder.
    fn offline_service_with(
        surface: RememberSurface,
        embedder: Arc<dyn ChunkEmbedder>,
    ) -> CockroachMemoryService {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_millis(200))
            .connect_lazy("postgresql://root@127.0.0.1:1/offline")
            .unwrap();
        let scope = offline_scope();
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
        adjudication: false,
        assert: false,
        capture: false,
        item_support: false,
    };

    const CONFLICT_LIFECYCLE: RememberSurface = RememberSurface {
        claim_lifecycle: true,
        conflict_lifecycle: true,
        adjudication: false,
        assert: false,
        capture: false,
        item_support: false,
    };

    const ADJUDICATING: RememberSurface = RememberSurface {
        adjudication: true,
        ..CONFLICT_LIFECYCLE
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
    async fn unserved_assert_is_refused_before_io() {
        let assertion = retract_arguments(&json!({ "assertion": { "kind": "decision" } }));
        // The offline pool fails any read, so a refusal proves no I/O ran,
        // even for a keyed request.
        for surface in [RememberSurface::RECORD_ONLY, CLAIM_LIFECYCLE, ADJUDICATING] {
            let error = FleetMemoryService::remember(
                &offline_service(surface),
                offline_scope(),
                RememberRequest::new(
                    RememberAction::Assert,
                    Some("assert/1".into()),
                    assertion.clone(),
                ),
            )
            .await
            .unwrap_err();
            let ServiceError::Refused(refusal) = &error else {
                panic!("{surface:?}: {error}");
            };
            assert_eq!(refusal.code, "assert_unavailable");
            assert_eq!(refusal.details["action"], "assert");
        }
        // A writer that serves assert takes it past the surface, to the
        // corpus generation check, which needs the database.
        let serving = offline_service(RememberSurface {
            assert: true,
            ..RememberSurface::RECORD_ONLY
        });
        let error = FleetMemoryService::remember(
            &serving,
            offline_scope(),
            RememberRequest::new(RememberAction::Assert, Some("assert/2".into()), assertion),
        )
        .await
        .unwrap_err();
        assert!(!matches!(error, ServiceError::Refused(_)), "{error}");
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

    fn dismiss_arguments(extra: &Value) -> Map<String, Value> {
        conflict_arguments(&json!({
            "expected_member_count": 2,
            "reason_kind": "false_positive",
            "rationale": "the two values name different deployments",
        }))
        .into_iter()
        .chain(retract_arguments(extra))
        .collect()
    }

    fn waive_arguments(extra: &Value) -> Map<String, Value> {
        conflict_arguments(&json!({
            "expected_member_count": 2,
            "reason_kind": "capacity_deferred",
            "rationale": "the migration review is scheduled for next sprint",
            "expires_in_hours": 72,
        }))
        .into_iter()
        .chain(retract_arguments(extra))
        .collect()
    }

    #[test]
    fn dismiss_waive_args_reject_unknown_and_bounds() {
        let (target, dismissal) =
            parse_dismiss_arguments(dismiss_arguments(&json!({ "conflict_id": "9" }))).unwrap();
        assert_eq!(
            target,
            ConflictTarget {
                conflict_id: 9,
                expected_revision: 3,
                expected_member_count: Some(2),
            }
        );
        assert_eq!(dismissal.reason_kind, DismissalReasonKindV1::FalsePositive);
        assert_eq!(
            dismissal.terms().rationale,
            "the two values name different deployments"
        );
        let (_, waiver) =
            parse_waive_arguments(waive_arguments(&json!({ "review_in_hours": 24 }))).unwrap();
        assert_eq!(waiver.reason_kind, WaiverReasonKindV1::CapacityDeferred);
        assert_eq!(
            (waiver.expires_in_hours, waiver.review_in_hours),
            (72, Some(24))
        );
        assert_eq!(
            parse_waive_arguments(waive_arguments(&json!({})))
                .unwrap()
                .1
                .review_in_hours,
            None
        );

        let mut without_rationale = dismiss_arguments(&json!({}));
        without_rationale.remove("rationale");
        let mut without_count = dismiss_arguments(&json!({}));
        without_count.remove("expected_member_count");
        let mut without_kind = dismiss_arguments(&json!({}));
        without_kind.remove("reason_kind");
        for rejected in [
            without_rationale,
            without_count,
            without_kind,
            // A waiver's reason is not a dismissal's, and the vocabulary is closed.
            dismiss_arguments(&json!({ "reason_kind": "capacity_deferred" })),
            dismiss_arguments(&json!({ "reason_kind": "wrong" })),
            dismiss_arguments(&json!({ "rationale": " \u{200B} " })),
            dismiss_arguments(&json!({ "rationale": "x".repeat(1_001) })),
            dismiss_arguments(&json!({ "reason": "a note is not a rationale" })),
            dismiss_arguments(&json!({ "expires_in_hours": 1 })),
            dismiss_arguments(&json!({ "retract_claim_ids": [41] })),
            dismiss_arguments(&json!({ "winner": 41 })),
            dismiss_arguments(&json!({ "expected_member_count": 0 })),
            dismiss_arguments(&json!({ "conflict_id": 0 })),
        ] {
            let rendered = Value::Object(rejected.clone());
            assert!(
                matches!(
                    parse_dismiss_arguments(rejected),
                    Err(ServiceError::InvalidRequest(_))
                ),
                "dismiss {rendered}"
            );
        }

        let mut without_expiry = waive_arguments(&json!({}));
        without_expiry.remove("expires_in_hours");
        for rejected in [
            without_expiry,
            waive_arguments(&json!({ "reason_kind": "false_positive" })),
            waive_arguments(&json!({ "expires_in_hours": 0 })),
            waive_arguments(&json!({ "expires_in_hours": 2_161 })),
            waive_arguments(&json!({ "expires_in_hours": 70_000 })),
            waive_arguments(&json!({ "expires_in_hours": -1 })),
            waive_arguments(&json!({ "review_in_hours": 73 })),
            waive_arguments(&json!({ "review_in_hours": 0 })),
            waive_arguments(&json!({ "rationale": "" })),
            waive_arguments(&json!({ "reason": "note" })),
            waive_arguments(&json!({ "claim_id": 41 })),
        ] {
            let rendered = Value::Object(rejected.clone());
            assert!(
                matches!(
                    parse_waive_arguments(rejected),
                    Err(ServiceError::InvalidRequest(_))
                ),
                "waive {rendered}"
            );
        }
    }

    #[test]
    fn every_rationale_the_adjudication_schema_admits_is_accepted() {
        let tool = crate::mcp::remember_tool_for(ADJUDICATING);
        let rationale = &tool["inputSchema"]["properties"]["rationale"];
        let max = usize::try_from(rationale["maxLength"].as_u64().unwrap()).unwrap();
        let dismiss = |rationale: String| {
            parse_dismiss_arguments(dismiss_arguments(&json!({ "rationale": rationale })))
        };
        for admitted in ["\u{1F4DD}".repeat(max), "\u{7406}".repeat(max), "x".into()] {
            assert!(dismiss(admitted).is_ok());
        }
        assert!(dismiss("\u{7406}".repeat(max + 1)).is_err());
        let expires = &tool["inputSchema"]["properties"]["expires_in_hours"];
        let longest = expires["maximum"].as_i64().unwrap();
        assert!(
            parse_waive_arguments(waive_arguments(
                &json!({ "expires_in_hours": longest, "review_in_hours": longest })
            ))
            .is_ok()
        );
    }

    #[tokio::test]
    async fn adjudication_is_gated_before_io() {
        let remember = |service: CockroachMemoryService,
                        action,
                        key: Option<&'static str>,
                        arguments| async move {
            FleetMemoryService::remember(
                &service,
                offline_scope(),
                RememberRequest::new(action, key.map(str::to_owned), arguments),
            )
            .await
            .unwrap_err()
        };
        for (action, arguments) in [
            (RememberAction::Dismiss, dismiss_arguments(&json!({}))),
            (RememberAction::Waive, waive_arguments(&json!({}))),
        ] {
            // Off by default: the conflict-lifecycle writer refuses before
            // any I/O (with no key there is no receipt to replay).
            let error = remember(
                offline_service(CONFLICT_LIFECYCLE),
                action,
                None,
                arguments.clone(),
            )
            .await;
            assert!(
                matches!(&error, ServiceError::Refused(refusal) if refusal.code == "adjudication_disabled"),
                "{error}"
            );
            // Without the conflict lifecycle there is nothing to adjudicate.
            let error = remember(
                offline_service(CLAIM_LIFECYCLE),
                action,
                None,
                arguments.clone(),
            )
            .await;
            assert!(
                matches!(&error, ServiceError::Refused(refusal) if refusal.code == "lifecycle_unavailable"),
                "{error}"
            );
            // Served: the key is required, then a ledger that never passed
            // the startup probe refuses before it touches the database.
            let error = remember(
                offline_service(ADJUDICATING),
                action,
                None,
                arguments.clone(),
            )
            .await;
            assert!(
                matches!(&error, ServiceError::InvalidRequest(message)
                    if *message == format!("remember({}) requires idempotency_key", action.as_str())),
                "{error}"
            );
            let error = remember(
                offline_service(ADJUDICATING),
                action,
                Some("adjudicate/9"),
                arguments,
            )
            .await;
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
            excluded_dismissed_pairs: 0,
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

    /// A 512-wide embedder whose every vector the dense lane can use.
    struct UnitEmbedder;

    impl ChunkEmbedder for UnitEmbedder {
        fn dim(&self) -> usize {
            EMBEDDING_DIMENSION
        }

        fn model_id(&self) -> &'static str {
            "offline-test"
        }

        fn encode_batch(&self, texts: &[&str]) -> Vec<Vec<f32>> {
            texts
                .iter()
                .map(|_| {
                    let mut vector = vec![0.0; EMBEDDING_DIMENSION];
                    vector[0] = 1.0;
                    vector
                })
                .collect()
        }
    }

    const KNOWN_BODY: [u8; 32] = [0xab; 32];
    const GIT_SOURCE: &str = "connector.git.fixture";
    const TRANSCRIPT_SOURCE: &str = "connector.transcript.fixture";

    fn evidence_readiness(dense_lane: EvidenceDenseLaneV1) -> EvidenceReadinessV1 {
        EvidenceReadinessV1 {
            events_awaiting_body_projection: 2,
            lag_by_kind: None,
            transcript_turns_awaiting_admission: 0,
            items_awaiting_admission: None,
            hints_awaiting_fetch: None,
            hints_unreadable: false,
            collector_state_unreadable: false,
            lexical_current: true,
            dense_current: true,
            dense_lane,
            as_of: Utc::now(),
        }
    }

    /// A git source whose last attempt failed and a transcript source whose
    /// last check is stale.
    fn evidence_sources() -> EvidenceSourcesV1 {
        use crate::evidence_recall::{EvidenceCoverageV1, EvidenceSourceKindV1};
        use crate::memory_contracts::coverage::CoverageCompletenessV1;
        let coverage = Some(EvidenceCoverageV1 {
            completeness: CoverageCompletenessV1::Complete,
            observed: vec![[1, 2]],
            target: [1, 2],
            as_of: Utc::now(),
        });
        EvidenceSourcesV1 {
            active: vec![
                EvidenceSourceV1 {
                    connector_instance: GIT_SOURCE.into(),
                    kind: EvidenceSourceKindV1::Git,
                    provider: None,
                    state: "active".into(),
                    last_outcome: WorkerSourceOutcomeV1::Failed,
                    last_checked_at: Some(Utc::now()),
                    last_error: Some("ref not found".into()),
                    stale: false,
                    coverage: coverage.clone(),
                },
                EvidenceSourceV1 {
                    connector_instance: TRANSCRIPT_SOURCE.into(),
                    kind: EvidenceSourceKindV1::Transcript,
                    provider: None,
                    state: "active".into(),
                    last_outcome: WorkerSourceOutcomeV1::Ok,
                    last_checked_at: Some(Utc::now()),
                    last_error: None,
                    stale: true,
                    coverage,
                },
            ],
            truncated: false,
        }
    }

    /// An [`EvidenceRecall`] that answers from fixtures and records every
    /// call, or fails every call.
    #[derive(Default)]
    struct FakeEvidence {
        fail: bool,
        /// How long `status` takes before it answers.
        status_delay: Option<std::time::Duration>,
        /// Each search's query, whether it carried a vector, and its limit.
        searches: std::sync::Mutex<Vec<(String, bool, usize)>>,
        /// Each search's source filter.
        sources: std::sync::Mutex<Vec<Option<EvidenceSourceFilterV1>>>,
        gets: std::sync::Mutex<Vec<Sha256Digest>>,
        statuses: std::sync::atomic::AtomicUsize,
    }

    impl FakeEvidence {
        fn failing() -> Self {
            Self {
                fail: true,
                ..Self::default()
            }
        }

        fn calls(&self) -> usize {
            self.searches.lock().unwrap().len()
                + self.gets.lock().unwrap().len()
                + self.statuses.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn outcome<T>(&self, value: T) -> crate::Result<T> {
            if self.fail {
                Err(FleetError::Memory("evidence tables unreadable".into()))
            } else {
                Ok(value)
            }
        }
    }

    #[async_trait]
    impl EvidenceRecall for FakeEvidence {
        async fn search_from(
            &self,
            query: &str,
            query_vector: Option<Vec<f32>>,
            limit: usize,
            source: Option<EvidenceSourceFilterV1>,
        ) -> crate::Result<EvidenceSearchV1> {
            use crate::evidence_recall::{
                AbsenceScopeV1, AbsenceV1, AbsenceVerdictV1, EvidenceHitV1, EvidenceMatchV1,
                PresentByV1,
            };
            self.searches
                .lock()
                .unwrap()
                .push((query.to_owned(), query_vector.is_some(), limit));
            self.sources.lock().unwrap().push(source);
            let dense_lane = if query_vector.is_some() {
                EvidenceDenseLaneV1::Used
            } else {
                EvidenceDenseLaneV1::NoQueryVector
            };
            self.outcome(EvidenceSearchV1 {
                hits: vec![EvidenceHitV1 {
                    id: Sha256Digest::from_bytes(KNOWN_BODY),
                    score: 0.5,
                    matched_by: EvidenceMatchV1::Lexical,
                    lexical_score: Some(0.5),
                    dense_similarity: None,
                    content_trust: None,
                    media_type: "application.git-commit-v1".into(),
                    snippet: "document the zephyrine cache eviction".into(),
                    snippet_truncated: false,
                    first_accepted_event_id: Sha256Digest::from_bytes([0xcd; 32]),
                    item: None,
                }],
                readiness: evidence_readiness(dense_lane),
                sources: evidence_sources(),
                absence: AbsenceV1 {
                    verdict: AbsenceVerdictV1::Present,
                    reasons: Vec::new(),
                    as_of: Some(Utc::now()),
                    present_by: Some(PresentByV1::Lexical),
                    strongest_dense_similarity: None,
                    strongest_hit: None,
                    weak_neighbours: 0,
                    scope: source.map(|source| AbsenceScopeV1 { source }),
                },
            })
        }

        async fn get(
            &self,
            id: Sha256Digest,
        ) -> crate::Result<Option<crate::evidence_recall::EvidenceBodyV1>> {
            self.gets.lock().unwrap().push(id);
            self.outcome((id == Sha256Digest::from_bytes(KNOWN_BODY)).then(|| {
                crate::evidence_recall::EvidenceBodyV1 {
                    id,
                    media_type: "application.git-commit-v1".into(),
                    content_trust: None,
                    text: "document the zephyrine cache eviction".into(),
                    text_bytes: 37,
                    redacted_at_read: None,
                    visibility_class: crate::projectors::RowVisibilityClassV1::Private,
                    first_accepted_event_id: Sha256Digest::from_bytes([0xcd; 32]),
                }
            }))
        }

        async fn status(&self) -> crate::Result<crate::evidence_recall::EvidenceStatusV1> {
            self.statuses
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if let Some(delay) = self.status_delay {
                tokio::time::sleep(delay).await;
            }
            self.outcome(crate::evidence_recall::EvidenceStatusV1 {
                readiness: evidence_readiness(EvidenceDenseLaneV1::Available),
                sources: evidence_sources(),
                collectors: None,
            })
        }
    }

    fn evidence_service(
        embedder: Arc<dyn ChunkEmbedder>,
        evidence: &Arc<FakeEvidence>,
    ) -> CockroachMemoryService {
        let evidence: Arc<dyn EvidenceRecall> = evidence.clone();
        offline_service_with(RememberSurface::RECORD_ONLY, embedder).with_evidence_recall(evidence)
    }

    fn recall_request(action: RecallAction, arguments: &Value) -> RecallRequest {
        RecallRequest::new(action, arguments.as_object().unwrap().clone())
    }

    fn warning_codes(warnings: &[Value]) -> Vec<&str> {
        warnings
            .iter()
            .map(|warning| warning["code"].as_str().unwrap())
            .collect()
    }

    #[tokio::test]
    async fn evidence_search_answers_without_the_corpus() {
        let evidence = Arc::new(FakeEvidence::default());
        let service = evidence_service(Arc::new(UnitEmbedder), &evidence);
        assert_eq!(
            FleetMemoryService::recall_surface(&service),
            RecallSurface {
                evidence: true,
                ..RecallSurface::NONE
            }
        );
        // The offline pool fails every read, so an answer proves the search
        // never touched the corpus.
        let result = FleetMemoryService::recall(
            &service,
            offline_scope(),
            recall_request(
                RecallAction::Search,
                &json!({ "kind": "evidence", "query": "zephyrine cache", "limit": 5 }),
            ),
        )
        .await
        .unwrap();
        assert_eq!(
            *evidence.searches.lock().unwrap(),
            [("zephyrine cache".to_owned(), true, 5)]
        );
        let data = result.data.as_object().unwrap();
        let mut keys = data.keys().map(String::as_str).collect::<Vec<_>>();
        keys.sort_unstable();
        assert_eq!(keys, ["absence", "hits", "readiness", "sources"]);
        assert_eq!(result.data["hits"][0]["id"], "ab".repeat(32));
        assert_eq!(result.data["hits"][0]["matched_by"], "lexical");
        assert_eq!(result.data["absence"]["verdict"], "present");
        assert_eq!(result.data["absence"]["present_by"], "lexical");
        assert!(
            result.data["absence"].get("weak_neighbours").is_none(),
            "no weak neighbour, no field"
        );
        assert_eq!(result.data["readiness"]["dense_lane"], "used");
        assert_eq!(
            result.data["sources"]["active"][0]["last_outcome"],
            "failed"
        );
        assert!(result.conflicts.is_empty());
        assert_eq!(result.conflict_coverage, ConflictCoverage::not_evaluated());
        let retrieval = &result.diagnostics["retrieval"];
        assert_eq!(retrieval["tier"], "evidence");
        assert_eq!(retrieval["lanes"], json!(["lexical", "dense"]));
        assert_eq!(
            retrieval["dense_min_cosine_similarity"],
            json!(RETRIEVAL_DENSE_MIN_COSINE_SIMILARITY)
        );
        assert_eq!(
            retrieval["absence_dense_min_cosine_similarity"],
            json!(ABSENCE_DENSE_MIN_COSINE_SIMILARITY)
        );
        assert_eq!(
            warning_codes(&result.warnings),
            [
                "evidence_body_projection_lag",
                "evidence_source_failed",
                "evidence_source_stale"
            ]
        );
        assert_eq!(
            result.warnings[1]["connector_instances"],
            json!([GIT_SOURCE])
        );
        assert_eq!(
            result.warnings[2]["connector_instances"],
            json!([TRANSCRIPT_SOURCE])
        );

        // A query the process model cannot embed searches lexically, and
        // says so; the default limit applies.
        let evidence = Arc::new(FakeEvidence::default());
        let service = evidence_service(Arc::new(OfflineEmbedder), &evidence);
        let result = FleetMemoryService::recall(
            &service,
            offline_scope(),
            recall_request(
                RecallAction::Search,
                &json!({ "kind": "evidence", "query": "zephyrine" }),
            ),
        )
        .await
        .unwrap();
        assert_eq!(
            *evidence.searches.lock().unwrap(),
            [("zephyrine".to_owned(), false, DEFAULT_TOOL_RESULTS)]
        );
        assert_eq!(result.diagnostics["retrieval"]["lanes"], json!(["lexical"]));
        assert!(warning_codes(&result.warnings).contains(&"evidence_query_not_embedded"));
    }

    #[tokio::test]
    async fn evidence_search_refuses_what_it_cannot_honor_before_searching() {
        let evidence = Arc::new(FakeEvidence::default());
        let service = evidence_service(Arc::new(UnitEmbedder), &evidence);
        for arguments in [
            json!({ "kind": "evidence", "query": "q", "source": "slack" }),
            json!({ "kind": "evidence", "query": "q", "source": "Git" }),
            json!({ "kind": "evidence", "query": "q", "max_per_source_id": 3 }),
            json!({ "kind": "evidence", "query": "q", "min_score": 0.0 }),
            json!({ "kind": "evidence", "query": "q", "intent": "general" }),
            json!({ "kind": "evidence", "query": "q", "include_history": true }),
            json!({ "kind": "evidence", "query": "q", "limit": 0 }),
            json!({ "kind": "evidence", "query": "q", "limit": 101 }),
            json!({ "kind": "evidence", "query": " " }),
            json!({ "kind": "evidence", "query": "q", "since": "2026-01-01" }),
            json!({ "kind": "evidence" }),
        ] {
            let error = FleetMemoryService::recall(
                &service,
                offline_scope(),
                recall_request(RecallAction::Search, &arguments),
            )
            .await
            .unwrap_err();
            assert!(
                matches!(error, ServiceError::InvalidRequest(_)),
                "{arguments}: {error}"
            );
        }
        assert_eq!(evidence.calls(), 0);

        // A search the evidence tables cannot answer is a failed read, not a
        // client error.
        let failing = Arc::new(FakeEvidence::failing());
        let error = FleetMemoryService::recall(
            &evidence_service(Arc::new(UnitEmbedder), &failing),
            offline_scope(),
            recall_request(
                RecallAction::Search,
                &json!({ "kind": "evidence", "query": "zephyrine" }),
            ),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, ServiceError::Internal(_)), "{error}");
    }

    #[tokio::test]
    async fn evidence_get_returns_the_body_or_null() {
        let evidence = Arc::new(FakeEvidence::default());
        let service = evidence_service(Arc::new(UnitEmbedder), &evidence);
        let get = |id: Value| {
            FleetMemoryService::recall(
                &service,
                offline_scope(),
                recall_request(RecallAction::Get, &json!({ "kind": "evidence", "id": id })),
            )
        };
        let found = get(json!("ab".repeat(32))).await.unwrap();
        assert_eq!(found.data["evidence"]["id"], "ab".repeat(32));
        assert_eq!(
            found.data["evidence"]["text"],
            "document the zephyrine cache eviction"
        );
        assert_eq!(found.data["evidence"]["visibility_class"], "private");
        assert_eq!(found.conflict_coverage, ConflictCoverage::not_evaluated());
        let missing = get(json!("42".repeat(32))).await.unwrap();
        assert!(missing.data["evidence"].is_null());
        assert_eq!(evidence.gets.lock().unwrap().len(), 2);

        for id in [
            json!("AB".repeat(32)),
            json!("ab".repeat(31)),
            json!(format!("{}g", "a".repeat(63))),
            json!(42),
            json!(null),
        ] {
            let error = get(id.clone()).await.unwrap_err();
            assert!(
                matches!(&error, ServiceError::InvalidRequest(message) if message.contains("64 lowercase hex")),
                "{id}: {error}"
            );
        }
        assert_eq!(evidence.gets.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn unserved_evidence_keeps_the_historical_errors() {
        let service = offline_service(RememberSurface::RECORD_ONLY);
        assert_eq!(
            FleetMemoryService::recall_surface(&service),
            RecallSurface::NONE
        );
        let error = FleetMemoryService::recall(
            &service,
            offline_scope(),
            recall_request(
                RecallAction::Get,
                &json!({ "kind": "evidence", "id": "ab".repeat(32) }),
            ),
        )
        .await
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid memory request: recall get kind \"evidence\" is not supported"
        );
        // An unserved evidence search takes the chunk and claim path, exactly
        // as any other unsupported kind does.
        let mut errors = Vec::new();
        for kind in ["evidence", "unknown"] {
            let error = FleetMemoryService::recall(
                &service,
                offline_scope(),
                recall_request(
                    RecallAction::Search,
                    &json!({ "kind": kind, "query": "zephyrine" }),
                ),
            )
            .await
            .unwrap_err();
            errors.push(error.to_string());
        }
        assert_eq!(errors[0], errors[1]);
    }

    #[tokio::test]
    async fn attaching_evidence_leaves_every_other_request_as_it_was() {
        let evidence = Arc::new(FakeEvidence::default());
        let plain = offline_service(CONFLICT_LIFECYCLE);
        let attached = offline_service(CONFLICT_LIFECYCLE)
            .with_evidence_recall(evidence.clone() as Arc<dyn EvidenceRecall>);
        assert_eq!(
            FleetMemoryService::remember_surface(&attached),
            CONFLICT_LIFECYCLE
        );
        let reads = [
            (
                RecallAction::Search,
                json!({ "kind": "chunk", "query": "zephyrine" }),
            ),
            (RecallAction::Search, json!({ "query": "zephyrine" })),
            (
                RecallAction::Search,
                json!({ "kind": "claim", "query": "zephyrine" }),
            ),
            (RecallAction::Get, json!({ "kind": "chunk", "id": "c1" })),
            (RecallAction::Get, json!({ "kind": "claim", "id": 41 })),
            (RecallAction::Get, json!({ "kind": "conflict", "id": 9 })),
            (RecallAction::Conflicts, json!({})),
            (RecallAction::Status, json!({})),
        ];
        for (action, arguments) in reads {
            let mut outcomes = Vec::new();
            for service in [&plain, &attached] {
                let outcome = FleetMemoryService::recall(
                    service,
                    offline_scope(),
                    recall_request(action, &arguments),
                )
                .await;
                outcomes.push(format!("{outcome:?}"));
            }
            assert_eq!(outcomes[0], outcomes[1], "{arguments}");
        }
        let mut outcomes = Vec::new();
        for service in [&plain, &attached] {
            let outcome = FleetMemoryService::remember(
                service,
                offline_scope(),
                RememberRequest::new(
                    RememberAction::Record,
                    Some("record/1".into()),
                    retract_arguments(&json!({ "kind": "decision", "text": "t" })),
                ),
            )
            .await;
            outcomes.push(format!("{outcome:?}"));
        }
        assert_eq!(outcomes[0], outcomes[1]);
        assert_eq!(evidence.calls(), 0);
    }

    #[tokio::test]
    async fn evidence_status_reports_or_warns_but_never_fails() {
        let (block, warnings) =
            evidence_status_within(&FakeEvidence::default(), OPTIONAL_STATUS_DEADLINE).await;
        assert_eq!(block["served"], true);
        assert_eq!(block["readiness"]["dense_lane"], "available");
        assert_eq!(
            block["sources"]["active"][1]["connector_instance"],
            TRANSCRIPT_SOURCE
        );
        assert_eq!(
            warning_codes(&warnings),
            [
                "evidence_body_projection_lag",
                "evidence_source_failed",
                "evidence_source_stale"
            ]
        );

        let (block, warnings) =
            evidence_status_within(&FakeEvidence::failing(), OPTIONAL_STATUS_DEADLINE).await;
        assert_eq!(
            block,
            json!({ "served": true, "readiness": null, "sources": null })
        );
        assert_eq!(warning_codes(&warnings), ["evidence_status_unavailable"]);

        // A read slower than the status deadline is a warning too, so a large
        // evidence tier can never fail the cheap health check.
        let slow = FakeEvidence {
            status_delay: Some(std::time::Duration::from_secs(600)),
            ..FakeEvidence::default()
        };
        let (block, warnings) =
            evidence_status_within(&slow, std::time::Duration::from_millis(20)).await;
        assert_eq!(
            block,
            json!({ "served": true, "readiness": null, "sources": null })
        );
        assert_eq!(warning_codes(&warnings), ["evidence_status_unavailable"]);
    }

    #[test]
    fn evidence_warnings_name_each_condition_once() {
        let current = EvidenceReadinessV1 {
            events_awaiting_body_projection: 0,
            ..evidence_readiness(EvidenceDenseLaneV1::Available)
        };
        let healthy = EvidenceSourcesV1 {
            active: Vec::new(),
            truncated: false,
        };
        assert!(evidence_warnings(&current, &healthy).is_empty());

        let lagging = EvidenceReadinessV1 {
            transcript_turns_awaiting_admission: 3,
            lexical_current: false,
            dense_current: false,
            ..current
        };
        let truncated = EvidenceSourcesV1 {
            active: Vec::new(),
            truncated: true,
        };
        assert_eq!(
            warning_codes(&evidence_warnings(&lagging, &truncated)),
            [
                "evidence_ingest_pending",
                "evidence_lexical_projection_lag",
                "evidence_dense_projection_lag",
                "evidence_sources_truncated"
            ]
        );
        // A disabled lane is reported as disabled, not as lagging.
        let foreign = EvidenceReadinessV1 {
            dense_current: false,
            dense_lane: EvidenceDenseLaneV1::DisabledForeignModel,
            ..current
        };
        assert_eq!(
            warning_codes(&evidence_warnings(&foreign, &healthy)),
            ["evidence_dense_lane_disabled"]
        );
    }

    #[test]
    fn the_projection_lag_warning_says_which_kind_is_waiting() {
        use crate::evidence_recall::LagByKindV1;
        let healthy = EvidenceSourcesV1 {
            active: Vec::new(),
            truncated: false,
        };
        let unsplit = evidence_readiness(EvidenceDenseLaneV1::Available);
        let warnings = evidence_warnings(&unsplit, &healthy);
        assert_eq!(warning_codes(&warnings), ["evidence_body_projection_lag"]);
        assert!(
            warnings[0]["message"]
                .as_str()
                .unwrap()
                .starts_with("2 accepted evidence events are waiting for the body projector;"),
            "{}",
            warnings[0]
        );
        assert_eq!(warnings[0]["lag_by_kind"], Value::Null);
        let split = EvidenceReadinessV1 {
            events_awaiting_body_projection: 3,
            lag_by_kind: Some(LagByKindV1 { items: 1, other: 2 }),
            ..unsplit
        };
        let warnings = evidence_warnings(&split, &healthy);
        assert!(
            warnings[0]["message"].as_str().unwrap().starts_with(
                "3 accepted evidence events are waiting for the body projector (1 collected item \
                 parts, 2 other);"
            ),
            "{}",
            warnings[0]
        );
        assert_eq!(
            warnings[0]["lag_by_kind"],
            json!({ "items": 1, "other": 2 })
        );
    }

    #[test]
    fn an_empty_chunk_answer_hints_at_the_kinds_that_are_served() {
        assert_eq!(other_kinds_hint(false, false), None);
        let both = other_kinds_hint(true, true).unwrap();
        assert_eq!(both["code"], "other_kinds_available");
        assert_eq!(both["kinds"], json!(["item", "evidence"]));
        assert!(
            both["message"]
                .as_str()
                .unwrap()
                .contains("evidence: git history, agent transcripts, CI, and items"),
            "{both}"
        );
        assert_eq!(
            other_kinds_hint(false, true).unwrap()["kinds"],
            json!(["evidence"])
        );
        assert_eq!(
            other_kinds_hint(true, false).unwrap()["kinds"],
            json!(["item"])
        );
    }

    #[tokio::test]
    async fn evidence_search_passes_its_source_through_and_the_verdict_is_scoped() {
        let evidence = Arc::new(FakeEvidence::default());
        let service = evidence_service(Arc::new(UnitEmbedder), &evidence);
        let result = FleetMemoryService::recall(
            &service,
            offline_scope(),
            recall_request(
                RecallAction::Search,
                &json!({ "kind": "evidence", "query": "webhook ingress", "source": "git" }),
            ),
        )
        .await
        .unwrap();
        assert_eq!(
            *evidence.sources.lock().unwrap(),
            [Some(EvidenceSourceFilterV1::Git)]
        );
        assert_eq!(result.data["absence"]["scope"], json!({ "source": "git" }));
        assert_eq!(
            result.diagnostics["retrieval"]["absence_neighbour_band_floor"],
            json!(ABSENCE_NEIGHBOUR_BAND_FLOOR)
        );
        // Unfiltered, the verdict carries no scope.
        let unscoped = FleetMemoryService::recall(
            &service,
            offline_scope(),
            recall_request(
                RecallAction::Search,
                &json!({ "kind": "evidence", "query": "webhook ingress" }),
            ),
        )
        .await
        .unwrap();
        assert_eq!(*evidence.sources.lock().unwrap().last().unwrap(), None);
        assert!(unscoped.data["absence"].get("scope").is_none());
        // A source that is not in the closed set is refused before the read,
        // naming the set.
        let error = FleetMemoryService::recall(
            &service,
            offline_scope(),
            recall_request(
                RecallAction::Search,
                &json!({ "kind": "evidence", "query": "q", "source": "slack" }),
            ),
        )
        .await
        .unwrap_err();
        assert!(
            error.to_string().contains("git, items, sessions"),
            "{error}"
        );
        assert_eq!(evidence.sources.lock().unwrap().len(), 2);
    }

    #[test]
    fn evidence_warnings_name_pending_and_unreadable_collected_items() {
        let healthy = EvidenceSourcesV1 {
            active: Vec::new(),
            truncated: false,
        };
        let current = EvidenceReadinessV1 {
            events_awaiting_body_projection: 0,
            items_awaiting_admission: Some(0),
            ..evidence_readiness(EvidenceDenseLaneV1::Available)
        };
        assert!(evidence_warnings(&current, &healthy).is_empty());
        let pending = EvidenceReadinessV1 {
            items_awaiting_admission: Some(4),
            ..current
        };
        assert_eq!(
            warning_codes(&evidence_warnings(&pending, &healthy)),
            ["evidence_items_pending"]
        );
        let hinted = EvidenceReadinessV1 {
            hints_awaiting_fetch: Some(2),
            ..current
        };
        assert_eq!(
            warning_codes(&evidence_warnings(&hinted, &healthy)),
            ["evidence_hints_pending"]
        );
        let unreadable = EvidenceReadinessV1 {
            items_awaiting_admission: None,
            collector_state_unreadable: true,
            ..current
        };
        assert_eq!(
            warning_codes(&evidence_warnings(&unreadable, &healthy)),
            ["evidence_collector_state_unreadable"]
        );
        let queue = EvidenceReadinessV1 {
            hints_unreadable: true,
            ..current
        };
        assert_eq!(
            warning_codes(&evidence_warnings(&queue, &healthy)),
            ["evidence_hints_unreadable"]
        );
    }

    #[test]
    fn only_a_comparable_query_vector_reaches_the_dense_lane() {
        let mut unit = vec![0.0; EMBEDDING_DIMENSION];
        unit[0] = 1.0;
        assert!(dense_query_vector_usable(&unit));
        assert!(!dense_query_vector_usable(&vec![0.0; EMBEDDING_DIMENSION]));
        assert!(!dense_query_vector_usable(&unit[1..]));
        assert!(!dense_query_vector_usable(&[]));
        let mut nan = unit.clone();
        nan[3] = f32::NAN;
        assert!(!dense_query_vector_usable(&nan));
        let mut infinite = unit;
        infinite[3] = f32::INFINITY;
        assert!(!dense_query_vector_usable(&infinite));
    }

    /// A [`SpecConformanceRead`] that answers from a fixture and records
    /// every call, or fails every call.
    #[derive(Default)]
    struct FakeSpecConformance {
        fail: bool,
        /// How long `status` takes before it answers.
        status_delay: Option<std::time::Duration>,
        /// Each listing's `include_resolved` and limit.
        lists: std::sync::Mutex<Vec<(bool, usize)>>,
        gets: std::sync::Mutex<Vec<DiscrepancyEpisodeFingerprintV1>>,
    }

    impl FakeSpecConformance {
        fn failing() -> Self {
            Self {
                fail: true,
                ..Self::default()
            }
        }

        fn outcome<T>(&self, value: T) -> crate::Result<T> {
            if self.fail {
                Err(FleetError::Memory("spec tables unreadable".into()))
            } else {
                Ok(value)
            }
        }

        fn contested() -> Vec<crate::spec_conformance::SpecConformanceWarningV1> {
            vec![crate::spec_conformance::SpecConformanceWarningV1 {
                code: "spec_family_contested",
                message: "binding family spec.remember.forget is contested".into(),
            }]
        }
    }

    #[async_trait]
    impl SpecConformanceRead for FakeSpecConformance {
        async fn list(
            &self,
            include_resolved: bool,
            limit: usize,
        ) -> crate::Result<SpecConformanceAnswerV1> {
            self.lists.lock().unwrap().push((include_resolved, limit));
            self.outcome(SpecConformanceAnswerV1 {
                discrepancies: Vec::new(),
                specs: Vec::new(),
                coverage: crate::spec_conformance::SpecCoverageV1 {
                    episodes_returned: 0,
                    episodes_truncated: false,
                    active_specs: 1,
                    scheduled_specs: 0,
                    expired_specs: 0,
                    never_checked_specs: 1,
                    unknown_specs: 0,
                    specs_truncated: false,
                    note: crate::spec_conformance::SPEC_CONFORMANCE_NOTE,
                },
                warnings: Self::contested(),
            })
        }

        async fn get(
            &self,
            episode: DiscrepancyEpisodeFingerprintV1,
        ) -> crate::Result<SpecConformanceAnswerV1> {
            self.gets.lock().unwrap().push(episode);
            self.list(true, 1).await
        }

        async fn status(&self) -> crate::Result<crate::spec_conformance::SpecConformanceStatusV1> {
            if let Some(delay) = self.status_delay {
                tokio::time::sleep(delay).await;
            }
            self.outcome(crate::spec_conformance::SpecConformanceStatusV1 {
                active_specs: 2,
                scheduled_specs: 1,
                expired_specs: 0,
                open_discrepancies: 1,
                unknown_specs: 1,
                never_checked_specs: 0,
                warnings: Self::contested(),
            })
        }
    }

    #[tokio::test]
    async fn unserved_discrepancies_are_refused_before_io() {
        for surface in [RememberSurface::RECORD_ONLY, CONFLICT_LIFECYCLE] {
            let service = offline_service(surface);
            assert!(!FleetMemoryService::recall_surface(&service).discrepancies);
            // The offline pool fails every read, so an invalid request, even
            // for arguments the action would refuse, proves nothing was read.
            for arguments in [json!({}), json!({ "query": "forget" })] {
                let error = FleetMemoryService::recall(
                    &service,
                    offline_scope(),
                    recall_request(RecallAction::Discrepancies, &arguments),
                )
                .await
                .unwrap_err();
                assert!(
                    matches!(&error, ServiceError::InvalidRequest(message) if message.contains("not served")),
                    "{error}"
                );
            }
        }
    }

    #[tokio::test]
    async fn discrepancies_answer_from_the_reader_alone() {
        let reader = Arc::new(FakeSpecConformance::default());
        let service = offline_service(CONFLICT_LIFECYCLE)
            .with_spec_conformance(reader.clone() as Arc<dyn SpecConformanceRead>);
        assert_eq!(
            FleetMemoryService::recall_surface(&service),
            RecallSurface {
                discrepancies: true,
                ..RecallSurface::NONE
            }
        );
        let recall = |arguments: Value| {
            FleetMemoryService::recall(
                &service,
                offline_scope(),
                recall_request(RecallAction::Discrepancies, &arguments),
            )
        };

        // The offline pool fails every read, so an answer proves the action
        // read nothing but the reader.
        let listed = recall(json!({})).await.unwrap();
        assert_eq!(listed.data["discrepancies"], json!([]));
        assert_eq!(listed.data["specs"], json!([]));
        assert_eq!(listed.data["coverage"]["never_checked_specs"], 1);
        assert!(
            listed.data["coverage"]["note"]
                .as_str()
                .unwrap()
                .contains("No episode does not mean the code conforms")
        );
        assert_eq!(warning_codes(&listed.warnings), ["spec_family_contested"]);
        assert!(listed.conflicts.is_empty());
        assert_eq!(listed.conflict_coverage, ConflictCoverage::not_evaluated());
        recall(json!({ "include_resolved": true, "limit": 100 }))
            .await
            .unwrap();
        assert_eq!(*reader.lists.lock().unwrap(), [(false, 10), (true, 100)]);

        let episode = "ab".repeat(32);
        recall(json!({ "id": episode, "include_resolved": true }))
            .await
            .unwrap();
        assert_eq!(
            *reader.gets.lock().unwrap(),
            [DiscrepancyEpisodeFingerprintV1::from_digest(
                Sha256Digest::from_bytes([0xab; 32])
            )]
        );

        for arguments in [
            json!({ "id": "AB".repeat(32) }),
            json!({ "id": "ab".repeat(31) }),
            json!({ "id": 42 }),
            json!({ "limit": 0 }),
            json!({ "limit": 101 }),
            json!({ "query": "forget" }),
            json!({ "kind": "claim" }),
        ] {
            let error = recall(arguments.clone()).await.unwrap_err();
            assert!(
                matches!(error, ServiceError::InvalidRequest(_)),
                "{arguments}: {error}"
            );
        }
        assert_eq!(reader.lists.lock().unwrap().len(), 3);

        let failing =
            offline_service(RememberSurface::RECORD_ONLY)
                .with_spec_conformance(
                    Arc::new(FakeSpecConformance::failing()) as Arc<dyn SpecConformanceRead>
                );
        let error = FleetMemoryService::recall(
            &failing,
            offline_scope(),
            recall_request(RecallAction::Discrepancies, &json!({})),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, ServiceError::Internal(_)), "{error}");
    }

    #[test]
    fn conflicts_status_counts_open_acknowledged_and_waived_or_reports_unavailable() {
        use crate::ledger::{OpenConflictRowV1, OpenConflictsV1};
        let at = |seconds: i64| chrono::DateTime::<Utc>::from_timestamp(seconds, 0).unwrap();
        let row = |id: i64, seconds: i64| OpenConflictRowV1 {
            id,
            revision: 1,
            member_count: 2,
            detected_at: at(seconds),
        };

        // Nothing open: zero counts, no oldest, no warning.
        let (block, warnings) =
            conflicts_status_block(Ok((OpenConflictsV1::default(), Some(HashMap::new()))));
        assert_eq!(
            block,
            json!({
                "open": 0,
                "acknowledged": 0,
                "waived": 0,
                "oldest_open_at": null,
                "bound_exceeded": false,
            })
        );
        assert!(warnings.is_empty());

        // Open conflicts under the overlay: counted by their overlay state,
        // the oldest named.
        let open = OpenConflictsV1 {
            rows: vec![
                row(7, 1_700_000_000),
                row(9, 1_700_000_100),
                row(11, 1_700_000_200),
            ],
            bound_exceeded: false,
        };
        let states = HashMap::from([
            (7, "acknowledged".to_owned()),
            (9, "waived".to_owned()),
            (11, "open".to_owned()),
        ]);
        let (block, warnings) = conflicts_status_block(Ok((open.clone(), Some(states))));
        assert_eq!(block["open"], 3);
        assert_eq!(block["acknowledged"], 1);
        assert_eq!(block["waived"], 1);
        assert_eq!(block["oldest_open_at"], json!(at(1_700_000_000)));
        assert_eq!(block["bound_exceeded"], false);
        assert!(warnings.is_empty());

        // Without the overlay the lifecycle counts are unknown, not zero.
        let (block, _) = conflicts_status_block(Ok((open, None)));
        assert_eq!(block["open"], 3);
        assert_eq!(block["acknowledged"], Value::Null);
        assert_eq!(block["waived"], Value::Null);

        // A full scan reports lower bounds and says so.
        let (block, warnings) = conflicts_status_block(Ok((
            OpenConflictsV1 {
                rows: vec![row(1, 1_700_000_000)],
                bound_exceeded: true,
            },
            None,
        )));
        assert_eq!(block["bound_exceeded"], true);
        assert_eq!(warning_codes(&warnings), ["open_conflicts_bound_exceeded"]);

        // A failed read is null with a warning, never a failed status.
        let (block, warnings) =
            conflicts_status_block(Err(FleetError::Memory("database unreachable".into())));
        assert_eq!(block, Value::Null);
        assert_eq!(warning_codes(&warnings), ["conflicts_status_unavailable"]);
    }

    #[test]
    fn quarantine_status_reports_reasons_and_names_preimage_disagreements() {
        use crate::evidence_ledger::{QuarantineSummaryV1, QuarantinedFactV1};
        let (block, warnings) = quarantine_status_block(Ok(QuarantineSummaryV1::default()));
        assert_eq!(
            block,
            json!({
                "by_reason": {},
                "bound_exceeded": false,
                "preimage_disagreement_sample": [],
            })
        );
        assert!(warnings.is_empty());

        let received_at = chrono::DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap();
        let (block, warnings) = quarantine_status_block(Ok(QuarantineSummaryV1 {
            by_reason: [
                ("oversize".to_owned(), 3),
                ("preimage_disagreement".to_owned(), 2),
            ]
            .into_iter()
            .collect(),
            bound_exceeded: false,
            preimage_disagreement_sample: vec![QuarantinedFactV1 {
                source_fact_id: Some(Sha256Digest::from_bytes([7; 32])),
                received_at,
            }],
        }));
        assert_eq!(block["by_reason"]["oversize"], 3);
        assert_eq!(block["by_reason"]["preimage_disagreement"], 2);
        assert_eq!(
            block["preimage_disagreement_sample"][0]["source_fact_id"],
            json!(Sha256Digest::from_bytes([7; 32]))
        );
        assert_eq!(
            block["preimage_disagreement_sample"][0]["received_at"],
            json!(received_at)
        );
        assert_eq!(
            warning_codes(&warnings),
            ["quarantine_preimage_disagreement"]
        );
        assert!(
            warnings[0]["message"]
                .as_str()
                .unwrap()
                .starts_with("2 evidence deliveries were quarantined")
        );

        let (block, warnings) =
            quarantine_status_block(Err(FleetError::Memory("permission denied".into())));
        assert_eq!(block, Value::Null);
        assert_eq!(warning_codes(&warnings), ["quarantine_unavailable"]);
    }

    #[test]
    fn absence_contract_publishes_the_verdict_bounds_as_written() {
        assert_eq!(
            absence_contract(),
            json!({
                "dense_bound": 0.45,
                "neighbour_band_floor": 0.30,
                "dense_vote_excluded": ["application.ostk-git-fact-v1"],
                "anchored_on": "lexical",
            })
        );
        assert_eq!(
            serde_json::to_string(&absence_contract()["dense_bound"]).unwrap(),
            "0.45"
        );
        assert_eq!(cosine_bound(0.3).to_string(), "0.3");
    }

    #[tokio::test]
    async fn legacy_claim_keys_status_counts_warns_or_reports_unavailable() {
        // No legacy rows: the count alone, no warning.
        let (value, warnings) = legacy_claim_keys_block(Ok(LegacyClaimKeysV1::default()));
        assert_eq!(
            value,
            json!({ "count": 0, "bound_exceeded": false, "sample": [] })
        );
        assert!(warnings.is_empty());

        // Legacy rows are visible as a count, a sample naming what to
        // supersede, and a warning naming the exit.
        let (value, warnings) = legacy_claim_keys_block(Ok(LegacyClaimKeysV1 {
            count: 3,
            bound_exceeded: false,
            sample: vec![crate::ledger::LegacyClaimKeySampleV1 {
                claim_id: 41,
                claim_key: "include_transcript_default::enabled".into(),
                actor: Some("agent-a".into()),
            }],
        }));
        assert_eq!(value["count"], 3);
        assert_eq!(value["bound_exceeded"], false);
        assert_eq!(
            value["sample"],
            json!([{
                "claim_id": 41,
                "claim_key": "include_transcript_default::enabled",
                "actor": "agent-a"
            }])
        );
        assert_eq!(warning_codes(&warnings), ["legacy_claim_keys"]);
        let message = warnings[0]["message"].as_str().unwrap();
        assert!(
            message.starts_with("3 lifecycle-current claims"),
            "{message}"
        );
        assert!(message.contains("supersede"), "{message}");

        // A full scan reports a lower bound.
        let (value, warnings) = legacy_claim_keys_block(Ok(LegacyClaimKeysV1 {
            count: 256,
            bound_exceeded: true,
            sample: Vec::new(),
        }));
        assert_eq!(value["count"], 256);
        assert_eq!(value["bound_exceeded"], true);
        assert_eq!(warning_codes(&warnings), ["legacy_claim_keys"]);
        assert!(
            warnings[0]["message"]
                .as_str()
                .unwrap()
                .starts_with("at least 256 lifecycle-current claims")
        );

        // A failed read is null with a warning, never a failed status.
        let (value, warnings) =
            legacy_claim_keys_block(Err(FleetError::Memory("database unreachable".into())));
        assert_eq!(value, Value::Null);
        assert_eq!(warning_codes(&warnings), ["legacy_claim_keys_unavailable"]);

        // And so is one against an unreachable database, inside the deadline.
        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_millis(200))
            .connect_lazy("postgresql://root@127.0.0.1:1/offline")
            .unwrap();
        let ledger = CockroachClaimLedger::new(
            pool,
            offline_scope(),
            Arc::new(UnitEmbedder),
            RetryPolicy::default(),
        )
        .unwrap();
        let started = std::time::Instant::now();
        let (value, warnings) =
            legacy_claim_keys_within(&ledger, &offline_scope(), OPTIONAL_STATUS_DEADLINE).await;
        assert!(started.elapsed() < OPTIONAL_STATUS_DEADLINE);
        assert_eq!(value, Value::Null);
        assert_eq!(warning_codes(&warnings), ["legacy_claim_keys_unavailable"]);
    }

    #[tokio::test]
    async fn spec_conformance_status_reports_or_warns_but_never_fails() {
        let (block, warnings) = spec_conformance_status_within(
            &FakeSpecConformance::default(),
            OPTIONAL_STATUS_DEADLINE,
        )
        .await;
        assert_eq!(
            block,
            json!({
                "served": true,
                "active_specs": 2,
                "scheduled_specs": 1,
                "expired_specs": 0,
                "open_discrepancies": 1,
                "unknown_specs": 1,
                "never_checked_specs": 0,
            })
        );
        assert_eq!(warning_codes(&warnings), ["spec_family_contested"]);

        let unavailable = json!({
            "served": true,
            "active_specs": null,
            "scheduled_specs": null,
            "expired_specs": null,
            "open_discrepancies": null,
            "unknown_specs": null,
            "never_checked_specs": null,
        });
        let (block, warnings) = spec_conformance_status_within(
            &FakeSpecConformance::failing(),
            OPTIONAL_STATUS_DEADLINE,
        )
        .await;
        assert_eq!(block, unavailable);
        assert_eq!(
            warning_codes(&warnings),
            ["spec_conformance_status_unavailable"]
        );

        let slow = FakeSpecConformance {
            status_delay: Some(std::time::Duration::from_secs(600)),
            ..FakeSpecConformance::default()
        };
        let (block, warnings) =
            spec_conformance_status_within(&slow, std::time::Duration::from_millis(20)).await;
        assert_eq!(block, unavailable);
        assert_eq!(
            warning_codes(&warnings),
            ["spec_conformance_status_unavailable"]
        );
    }

    #[tokio::test]
    async fn optional_status_blocks_are_read_concurrently_under_one_deadline() {
        // Nothing served, nothing read.
        let deadline = std::time::Duration::from_millis(500);
        assert_eq!(
            optional_status_blocks(None, None, deadline).await,
            (None, None)
        );

        // Both reads hang: each degrades to its warning, and together they
        // cost one deadline, so recall(status) stays inside the MCP request
        // deadline however many optional blocks are served.
        let slow_evidence = FakeEvidence {
            status_delay: Some(std::time::Duration::from_secs(600)),
            ..FakeEvidence::default()
        };
        let slow_spec = FakeSpecConformance {
            status_delay: Some(std::time::Duration::from_secs(600)),
            ..FakeSpecConformance::default()
        };
        let started = std::time::Instant::now();
        let (evidence, spec_conformance) =
            optional_status_blocks(Some(&slow_evidence), Some(&slow_spec), deadline).await;
        let elapsed = started.elapsed();
        assert!(elapsed < deadline * 2, "two slow blocks took {elapsed:?}");
        let (_, evidence_warnings) = evidence.expect("evidence is served");
        assert_eq!(
            warning_codes(&evidence_warnings),
            ["evidence_status_unavailable"]
        );
        let (_, spec_warnings) = spec_conformance.expect("spec conformance is served");
        assert_eq!(
            warning_codes(&spec_warnings),
            ["spec_conformance_status_unavailable"]
        );
    }
}
