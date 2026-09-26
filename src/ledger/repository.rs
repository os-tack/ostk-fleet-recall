use async_trait::async_trait;
use serde_json::json;

use crate::ledger::{
    AssertedClaimMutation, Claim, ClaimInput, ClaimItemSupportV1, ClaimMutation, ClaimState,
    ClaimTarget, Conflict, ConflictHistory, ConflictLifecycleRows, ConflictMutation,
    ConflictTarget, DismissalTerms, LegacyClaimKeysV1, LifecycleMutation, LifecycleRefusal,
    LifecycleReplayRequest, RefusalCode, SemanticClaimHit, WaiverTerms,
};
use crate::memory_contracts::evidence::AcceptedEventId;
use crate::remember_runtime::RememberAssertInputV1;
use crate::{FleetError, FleetScope, Result};

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

    /// Assert through the active registry's remember route, event first.
    ///
    /// One serializable transaction appends the admitted
    /// `memory.claim.accepted` event and commits, with it, the claim
    /// projection `record` would write (plus the event's ID), the conflict
    /// detector, the audit events, and the idempotency receipt. Every refusal
    /// (`assert_unavailable`, `writer_authority_unavailable`,
    /// `assertion_not_admitted`, `support_event_unknown`,
    /// `registry_head_changed`, `already_asserted`) is a typed
    /// [`FleetError::LifecycleRefused`] that writes nothing and leaves the
    /// key free. A ledger that does not serve the event-first path refuses
    /// every assert as `assert_unavailable`, which is this default.
    async fn assert_claim(
        &self,
        _scope: &FleetScope,
        _input: &RememberAssertInputV1,
        _idempotency_key: &str,
    ) -> Result<AssertedClaimMutation> {
        Err(assert_unavailable())
    }

    /// The accepted event a claim was projected from, or `None` when the
    /// claim does not exist or was written by `record`, `supersede`, or an
    /// import that predates the event-first path.
    async fn claim_accepted_event_id(
        &self,
        _scope: &FleetScope,
        _claim_id: i64,
    ) -> Result<Option<AcceptedEventId>> {
        Ok(None)
    }

    /// Which of up to 100 `claim_ids` project an accepted event, that is,
    /// were written by `remember(assert)`. Unknown ids are absent. The
    /// publication reader withholds these claims (ADR 0005 D8). The default
    /// asks [`Self::claim_accepted_event_id`] for each id.
    async fn asserted_claim_ids(&self, scope: &FleetScope, claim_ids: &[i64]) -> Result<Vec<i64>> {
        let mut asserted = Vec::new();
        for &claim_id in claim_ids {
            if self
                .claim_accepted_event_id(scope, claim_id)
                .await?
                .is_some()
            {
                asserted.push(claim_id);
            }
        }
        Ok(asserted)
    }

    /// The collected items `claim_id` cites (ADR 0008 D11), expanded through
    /// the private claim item links: what `assert`'s `support_items` and
    /// `record`'s item support entries linked. `None` when this ledger does
    /// not serve claim item links, which is this default; an unknown claim
    /// or one that cites no item has no items.
    async fn claim_item_support(
        &self,
        _scope: &FleetScope,
        _claim_id: i64,
    ) -> Result<Option<ClaimItemSupportV1>> {
        Ok(None)
    }

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

    /// Supersede a lifecycle-current operator assertion the caller authored
    /// with a successor claim of the same kind, normalized key, and conflict
    /// eligibility.
    ///
    /// The predecessor becomes `superseded` with `superseded_by` naming the
    /// successor, which is written and run through the detector exactly as
    /// `record` writes a claim. The key's open v2 conflict is then
    /// re-evaluated over what is current: a compatible successor lets it
    /// close, and an incompatible one replaces its predecessor as a member.
    /// Authority and refusals are those of [`Self::retract_claim`], plus the
    /// `successor_*_mismatch` refusals.
    async fn supersede_claim(
        &self,
        scope: &FleetScope,
        target: ClaimTarget,
        reason: Option<&str>,
        successor: &ClaimInput,
        idempotency_key: &str,
    ) -> Result<ClaimMutation>;

    /// Replay a committed lifecycle request whose action this deployment does
    /// not serve, reading its receipt without taking a lock or writing.
    ///
    /// `request` names the request when its arguments parsed as that action;
    /// the stored result replays only for exactly that request. Any other
    /// receipt under the key is an idempotency conflict. `Ok(None)` means no
    /// receipt holds the key in this tenant.
    async fn replay_unserved_lifecycle(
        &self,
        scope: &FleetScope,
        idempotency_key: &str,
        request: Option<LifecycleReplayRequest<'_>>,
    ) -> Result<Option<LifecycleMutation>>;

    /// Acknowledge the current episode of an open v2 conflict, at the
    /// revision the caller read. Any agent in scope may acknowledge,
    /// implicated ones included. It appends an `acknowledged` lifecycle event
    /// and never changes `memory_conflicts`; an agent's second
    /// acknowledgement of the same episode commits with `applied = false`.
    /// Refused as `lifecycle_unavailable` without the lifecycle capability.
    async fn acknowledge_conflict(
        &self,
        scope: &FleetScope,
        target: ConflictTarget,
        reason: Option<&str>,
        idempotency_key: &str,
    ) -> Result<ConflictMutation>;

    /// Concede an open v2 conflict: retract the caller's own current member
    /// claims named in `retract_claim_ids` (possibly none), then close the
    /// conflict only if the detector verifies no incompatible current pair
    /// remains. Otherwise the whole request is refused (`still_incompatible`
    /// or `verification_divergence`) and nothing changes. Another agent's
    /// claim is never touched (DISC-03). The conflict revision and member
    /// count the caller read are both checked.
    async fn resolve_conflict(
        &self,
        scope: &FleetScope,
        target: ConflictTarget,
        retract_claim_ids: &[i64],
        reason: Option<&str>,
        idempotency_key: &str,
    ) -> Result<ConflictMutation>;

    /// Dismiss an open v2 conflict as not a real disagreement. Served only
    /// with the lifecycle capability and the deployment's adjudication switch
    /// (`adjudication_disabled` otherwise), and only to an agent that authored
    /// none of the conflict's members in any episode (`implicated`); a member
    /// with no recorded author refuses it (`unattributed_member`). The
    /// conflict revision and member count the caller read are both checked.
    /// The conflict moves to `dismissed`, its disputed members that no other
    /// open conflict holds return to `active`, and a `dismissed` lifecycle
    /// event records the reason, rationale, and every incompatible current
    /// pair judged, which later re-evaluations of the conflict leave out. No
    /// claim changes applicability (DISC-03).
    async fn dismiss_conflict(
        &self,
        scope: &FleetScope,
        target: ConflictTarget,
        terms: DismissalTerms<'_>,
        idempotency_key: &str,
    ) -> Result<ConflictMutation>;

    /// Waive an open v2 conflict's current episode until an expiry the
    /// database clock computes. The same gates and checks as
    /// [`Self::dismiss_conflict`] apply, but nothing but the `waived`
    /// lifecycle event is written: the conflict stays open, reads `waived`
    /// while the waiver is unexpired and its member count unchanged, and
    /// reads `open` again, with the waiver's context, afterwards.
    async fn waive_conflict(
        &self,
        scope: &FleetScope,
        target: ConflictTarget,
        terms: WaiverTerms<'_>,
        idempotency_key: &str,
    ) -> Result<ConflictMutation>;

    /// The newest lifecycle events of each `(conflict_id, episode_revision)`
    /// (at most 100), read in one autocommit statement for the overlay.
    async fn conflict_lifecycle_rows(
        &self,
        scope: &FleetScope,
        episodes: &[(i64, i64)],
    ) -> Result<ConflictLifecycleRows>;

    /// One conflict's newest lifecycle events, at most 256, in event order.
    async fn conflict_lifecycle_history(
        &self,
        scope: &FleetScope,
        conflict_id: i64,
    ) -> Result<ConflictHistory>;

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

    /// How many of the project's lifecycle-current claims still carry a key
    /// the earlier normalizer wrote (see [`LegacyClaimKeysV1`]); a bounded
    /// read for `recall(status)`.
    async fn legacy_claim_keys(&self, scope: &FleetScope) -> Result<LegacyClaimKeysV1>;

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

/// The refusal of an assert this writer does not serve.
pub fn assert_unavailable() -> FleetError {
    LifecycleRefusal::new(
        RefusalCode::AssertUnavailable,
        "this writer does not serve remember(action=\"assert\"): its writer-authority pins are \
         not configured or did not verify at startup",
        json!({}),
    )
    .into()
}
