use async_trait::async_trait;

use crate::ledger::{Claim, ClaimInput, ClaimMutation, Conflict, SemanticClaimHit};
use crate::{FleetScope, Result};

/// Bounded claim coordinates resolved from exact source-chunk support rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportedClaimCoordinate {
    pub claim_id: i64,
    pub chunk_id: String,
}

/// Bounded claim coordinates resolved from exact source-chunk support rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportedClaimIds {
    pub claim_ids: Vec<i64>,
    /// Surfaced corpus chunks that exactly support at least one projected
    /// claim. These are current, hash-bound coordinates rather than every
    /// chunk ever cited by the selected claims.
    pub supporting_chunk_ids: Vec<String>,
    /// Exact current, content-hash-verified claim/chunk associations. At least
    /// one coordinate is retained for every selected claim.
    pub coordinates: Vec<SupportedClaimCoordinate>,
    /// True when more matching claims existed than the requested projection.
    pub truncated: bool,
    /// True when additional exact claim/chunk associations existed beyond the
    /// bounded diagnostic projection.
    pub coordinates_truncated: bool,
}

/// Semantic claim operations implemented atomically by each durable backend.
///
/// The API intentionally does not expose SQL transaction handles. Recording a
/// claim, writing its receipt/event, and updating deterministic conflicts are
/// one backend-owned operation.
#[async_trait]
pub trait ClaimLedger: Send + Sync {
    async fn record_claim(
        &self,
        scope: &FleetScope,
        input: &ClaimInput,
        idempotency_key: &str,
    ) -> Result<ClaimMutation>;

    async fn get_claim(&self, scope: &FleetScope, id: i64) -> Result<Option<Claim>>;

    async fn search_claims(
        &self,
        scope: &FleetScope,
        query: &str,
        include_history: bool,
        limit: usize,
    ) -> Result<Vec<SemanticClaimHit>>;

    async fn list_conflicts(
        &self,
        scope: &FleetScope,
        include_resolved: bool,
        limit: usize,
    ) -> Result<Vec<Conflict>>;

    async fn conflicts_for_claim_ids(
        &self,
        scope: &FleetScope,
        claim_ids: &[i64],
        limit: usize,
    ) -> Result<Vec<Conflict>>;

    /// Resolve current typed claims that cite any exact surfaced corpus chunk.
    ///
    /// This is the provenance seam between semantic passage retrieval and the
    /// conflict ledger: an ordinary spec/code hit can carry a known typed
    /// disagreement without requiring its synthetic claim projection to rank
    /// on the same page.
    async fn supported_claim_ids_for_chunk_ids(
        &self,
        scope: &FleetScope,
        chunk_ids: &[String],
        limit: usize,
    ) -> Result<SupportedClaimIds>;
}
