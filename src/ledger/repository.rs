use async_trait::async_trait;

use crate::ledger::{Claim, ClaimInput, ClaimMutation, Conflict, SemanticClaimHit};
use crate::{FleetScope, Result};

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
}
