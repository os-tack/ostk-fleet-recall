use async_trait::async_trait;

use crate::ledger::{
    Claim, ClaimInput, ClaimMutation, ClaimState, ClaimTarget, Conflict, SemanticClaimHit,
};
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

    /// Retract a lifecycle-current operator assertion the caller authored.
    ///
    /// Owner authority, the expected revision, and the key's lineage are
    /// checked under row locks; a violation is a typed
    /// [`crate::FleetError::LifecycleRefused`] that rolls the whole
    /// transaction back. When the key's open v2 conflict has no incompatible
    /// lifecycle-current pair left, the detector closes it and restores its
    /// disputed members that no other open conflict still holds.
    async fn retract_claim(
        &self,
        scope: &FleetScope,
        target: ClaimTarget,
        reason: Option<&str>,
        idempotency_key: &str,
    ) -> Result<ClaimMutation>;

    /// Replay a committed lifecycle request whose action this deployment does
    /// not serve, reading its receipt without taking a lock or writing.
    ///
    /// `retract` names the request when its arguments parsed as a retract; the
    /// stored result replays only for exactly that request. Any other receipt
    /// under the key is an idempotency conflict. `Ok(None)` means no receipt
    /// holds the key in this tenant.
    async fn replay_unserved_lifecycle(
        &self,
        scope: &FleetScope,
        idempotency_key: &str,
        retract: Option<(ClaimTarget, Option<&str>)>,
    ) -> Result<Option<ClaimMutation>>;

    async fn get_claim(&self, scope: &FleetScope, id: i64) -> Result<Option<Claim>>;

    /// Hydrate conflicts by id in any state (at most 100 ids). Unknown ids are
    /// simply absent from the result.
    async fn get_conflicts(
        &self,
        scope: &FleetScope,
        conflict_ids: &[i64],
    ) -> Result<Vec<Conflict>>;

    /// Current lifecycle state of up to 100 claims. Unknown ids are absent.
    async fn claim_states(
        &self,
        scope: &FleetScope,
        claim_ids: &[i64],
    ) -> Result<Vec<(i64, ClaimState)>>;

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
