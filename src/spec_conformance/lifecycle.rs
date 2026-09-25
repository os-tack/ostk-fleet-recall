//! An operator closing a spec nonconformance episode (Stage 6): the library
//! behind `ostk-spec episode resolve|dismiss`.
//!
//! Under the genesis `positive_verified` observer admission only presence is
//! ever verified, so a commit that fixes a "must be absent" violation checks
//! as `unknown`, never as `conforming`, and no check ever closes an episode
//! ([`super::check`]). An operator does, with [`append_episode_lifecycle`]:
//!
//! * **resolve**: the nonconformance is fixed. A resolution must cite
//!   evidence (DISC-03). By default it cites the observer event of the latest
//!   check of the statement the episode violates, typically the `unknown`
//!   check of the fixing commit, but only when that check can stand for a
//!   fix ([`default_resolution_evidence`]): it is not nonconforming, it read
//!   the whole enum, its commit was never judged nonconforming under the
//!   statement, and it follows the check that opened the episode. Otherwise
//!   the operator must cite evidence explicitly.
//! * **dismiss**: the episode should not stand, for one reason of the
//!   contract's closed taxonomy, with a non-blank rationale.
//!
//! Each appends one [`DiscrepancyLifecycleEventV1`] to the episode's log in
//! migration 0027 through the discrepancy ledger runtime, which advances the
//! stored projection in the same transaction. The event's scope is the
//! runtime's semantic scope and its profile the active package's, never the
//! caller's; its `effective_at` is the database clock. The whole contract
//! check (scope, profile, episode, AUTH-03 self-implication, rationale and
//! evidence shape) runs against the stored envelope before anything is
//! written, and again inside the append transaction. Nothing is rewritten:
//! the envelope and every earlier event stay as they were, so the
//! episode's history shows the closure and who made it.
//!
//! An episode is closed once
//! ([`CockroachDiscrepancyLedgerRepository::close_episode`]). Closing an
//! episode that is already resolved, dismissed, or superseded appends
//! nothing: the same transition (actor, and evidence or reason) is answered
//! with the event that already made it, so a retry after an outcome-unknown
//! commit is safe, and any other closure is refused.
//!
//! Only `spec_nonconformance` episodes are closed here; the statement an
//! episode violates is read from its envelope's expectation policy. As for
//! the deriver's opening write, each call verifies the strict witness and
//! builds the ledger from its registry binding; the append transaction does
//! not re-read the registry head. A closed episode is never re-opened: the
//! opening rule is keyed on (statement, commit), so re-checking a commit
//! already judged nonconforming joins the closed episode as already judged,
//! and only a commit newly found nonconforming opens another episode.
//! Acknowledging and waiving are not offered here.

use serde::Serialize;

use crate::Result;
use crate::discrepancy_runtime::{
    CockroachDiscrepancyLedgerRepository, ComparisonIndeterminacyV1,
    DISCREPANCY_RUNTIME_SCHEMA_VERSION, DiscrepancyAppendOutcomeV1,
    DiscrepancyLedgerRepository as _, DiscrepancyLogRecordV1, DiscrepancyRegistryBindingV1,
    admit_lifecycle_event,
};
use crate::error::FleetError;
use crate::memory_contracts::common::{
    AuthenticatedProjectScopeV1, CanonicalTimestamp, ContractId, ProfileReferenceV1,
};
use crate::memory_contracts::digest::Sha256Digest;
use crate::memory_contracts::discrepancy::{
    DiscrepancyActorV1, DiscrepancyEnvelopeV1, DiscrepancyEpisodeFingerprintV1,
    DiscrepancyLifecycleEventV1, DismissalReasonKindV1, DismissalReasonV1, FindingType,
    LifecycleState, LifecycleTransitionV1,
};
use crate::memory_contracts::evidence::AcceptedEventId;
use crate::memory_contracts::{ContractError, ContractResult};
use crate::registry_witness::WriterAuthorityRuntime;

use super::activation::{database_now, spec_repository};
use super::cockroach::StoredSpecCheckV1;
use super::envelope::SPEC_EXPECTATION_POLICY_VERSION;
use super::record::SpecVerdictV1;

/// The event kind of every discrepancy lifecycle event.
const LIFECYCLE_EVENT_KIND: &str = "discrepancy.lifecycle.accepted";

/// What an operator does to one spec episode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpecEpisodeTransitionV1 {
    /// The nonconformance is fixed. `evidence` is the accepted events that
    /// show it; empty cites the observer event of the latest check of the
    /// episode's statement, when that check can stand for a fix
    /// ([`default_resolution_evidence`]).
    Resolve { evidence: Vec<AcceptedEventId> },
    /// The episode should not stand. The rationale must not be blank.
    Dismiss {
        reason: DismissalReasonKindV1,
        rationale: String,
    },
}

/// The report of one [`append_episode_lifecycle`] call; what
/// `ostk-spec episode` prints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SpecEpisodeLifecycleV1 {
    pub episode_id: DiscrepancyEpisodeFingerprintV1,
    /// The binding family and statement the episode's envelope names.
    pub binding_family_id: ContractId,
    pub statement_id: Sha256Digest,
    /// The lifecycle event's identity.
    pub event_id: Sha256Digest,
    /// The log sequence the event sits at.
    pub log_seq: u64,
    /// Whether this call appended the event; false when the episode was
    /// already closed by exactly this transition, whose recorded event is
    /// reported instead.
    pub appended: bool,
    /// The database time the event takes effect at.
    pub effective_at: CanonicalTimestamp,
    /// The transition, its actor, and its evidence or reason.
    #[serde(flatten)]
    pub transition: LifecycleTransitionV1,
    /// The episode's stored lifecycle state before and after the append.
    pub previous_state: LifecycleState,
    pub lifecycle_state: LifecycleState,
}

/// Append one operator transition to a spec episode's log.
///
/// It re-reads the strict witness for the call, loads the stored envelope,
/// refuses an episode that is not a `spec_nonconformance` one, resolves a
/// resolution's default evidence, and builds the event at the database's
/// time under the runtime's scope and the active package's profile
/// ([`spec_lifecycle_event`]); only then does it append.
///
/// # Errors
///
/// [`FleetError::Memory`] for an episode this project does not have, an
/// episode already closed by another transition, or a resolution without
/// evidence whose statement's latest check cannot stand for a fix
/// ([`default_resolution_evidence`]); a contract error for an episode that
/// is not
/// a spec nonconformance or an event the contract refuses (a blank dismissal
/// rationale, an implicated actor); whatever the strict witness or the
/// ledger refuses.
pub async fn append_episode_lifecycle(
    runtime: &WriterAuthorityRuntime,
    episode: DiscrepancyEpisodeFingerprintV1,
    actor: &ContractId,
    transition: &SpecEpisodeTransitionV1,
) -> Result<SpecEpisodeLifecycleV1> {
    let verified = runtime.verify().await?;
    let witness = verified.witness();
    let ledger = CockroachDiscrepancyLedgerRepository::new(
        runtime.pool().clone(),
        runtime.control_scope().clone(),
        DiscrepancyRegistryBindingV1::from_witness(witness),
        runtime.retry_policy(),
    )?;
    let envelope = ledger.read_envelope(episode).await?.ok_or_else(|| {
        FleetError::Memory(format!("this project has no discrepancy episode {episode}"))
    })?;
    let (binding_family_id, statement_id) = spec_episode_statement(&envelope)?;
    let previous_state = stored_state(&ledger, episode).await?;

    let actor = DiscrepancyActorV1 {
        principal_id: actor.clone(),
    };
    let lifecycle_transition = match transition {
        SpecEpisodeTransitionV1::Resolve { evidence } => {
            let resolution_evidence_ids = if evidence.is_empty() {
                vec![default_evidence(runtime, &envelope, statement_id).await?]
            } else {
                evidence.clone()
            };
            LifecycleTransitionV1::Resolve {
                actor,
                resolution_evidence_ids,
            }
        }
        SpecEpisodeTransitionV1::Dismiss { reason, rationale } => LifecycleTransitionV1::Dismiss {
            actor,
            reason: DismissalReasonV1 {
                kind: *reason,
                rationale: rationale.clone(),
            },
        },
    };
    let effective_at = CanonicalTimestamp::from_datetime(&database_now(runtime.pool()).await?)?;
    let event = spec_lifecycle_event(
        &envelope,
        &witness
            .package()
            .manifest_verified_package()
            .package()
            .profile,
        runtime.semantic_scope(),
        lifecycle_transition,
        effective_at,
    )?;

    let (event_id, appended) = match ledger.close_episode(&event).await? {
        DiscrepancyAppendOutcomeV1::Appended(transition) => (transition.record_id, true),
        DiscrepancyAppendOutcomeV1::AlreadyRecorded { record_id } => (record_id, false),
    };
    let (log_seq, recorded) = recorded_event(&ledger, episode, event_id).await?;
    let lifecycle_state = stored_state(&ledger, episode).await?;
    Ok(SpecEpisodeLifecycleV1 {
        episode_id: episode,
        binding_family_id,
        statement_id,
        event_id,
        log_seq,
        appended,
        effective_at: recorded.effective_at,
        transition: recorded.lifecycle_transition.ok_or_else(|| {
            FleetError::Memory("a spec lifecycle event carries its transition".into())
        })?,
        previous_state,
        lifecycle_state,
    })
}

/// The log sequence and the event `event_id` names in `episode`'s log: the
/// event just appended, or the one that already made the transition.
async fn recorded_event(
    ledger: &CockroachDiscrepancyLedgerRepository,
    episode: DiscrepancyEpisodeFingerprintV1,
    event_id: Sha256Digest,
) -> Result<(u64, DiscrepancyLifecycleEventV1)> {
    ledger
        .read_log(episode)
        .await?
        .into_iter()
        .find(|entry| entry.record_id == event_id)
        .and_then(|entry| match entry.record {
            DiscrepancyLogRecordV1::Lifecycle { event } => Some((entry.seq, event)),
            DiscrepancyLogRecordV1::Envelope { .. } => None,
        })
        .ok_or_else(|| {
            FleetError::Memory(format!(
                "lifecycle event {event_id} is not in episode {episode}'s log"
            ))
        })
}

/// The binding family and statement a spec episode's envelope names.
///
/// A spec envelope's expectation policy is `{binding_family_id, 1,
/// statement_id}` ([`super::envelope::spec_expectation_policy`]).
///
/// # Errors
///
/// [`ContractError::Schema`] for an envelope that is not a
/// `spec_nonconformance` one under that policy version.
pub fn spec_episode_statement(
    envelope: &DiscrepancyEnvelopeV1,
) -> ContractResult<(ContractId, Sha256Digest)> {
    if envelope.finding_type != FindingType::SpecNonconformance
        || envelope.expectation_policy.version != SPEC_EXPECTATION_POLICY_VERSION
    {
        return Err(ContractError::Schema(
            "the episode is not a spec nonconformance; ostk-spec closes only spec episodes".into(),
        ));
    }
    Ok((
        envelope.expectation_policy.entry_id.clone(),
        envelope.expectation_policy.entry_digest,
    ))
}

/// What a resolution of `envelope`'s episode cites by default, read from
/// the statement's check history ([`default_resolution_evidence`]).
async fn default_evidence(
    runtime: &WriterAuthorityRuntime,
    envelope: &DiscrepancyEnvelopeV1,
    statement_id: Sha256Digest,
) -> Result<AcceptedEventId> {
    let specs = spec_repository(runtime);
    let latest = specs
        .latest_checks(&[statement_id])
        .await?
        .into_iter()
        .find(|check| check.record.statement_id == statement_id);
    let opening = specs
        .opening_check_for(envelope.episode_fingerprint, &envelope.member_evidence_ids)
        .await?;
    let latest_commit_judged_nonconforming = match &latest {
        Some(check) => specs
            .nonconforming_check_for(statement_id, &check.record.commit_oid)
            .await?
            .is_some(),
        None => false,
    };
    default_resolution_evidence(
        statement_id,
        latest.as_ref(),
        opening.as_ref(),
        latest_commit_judged_nonconforming,
    )
}

/// The evidence a resolution cites by default: the observer event of
/// `latest`, the latest check of `statement_id`, when that check can stand
/// for a fix of the episode `opening` opened.
///
/// `latest_commit_judged_nonconforming` says whether `latest`'s commit was
/// ever judged nonconforming under the statement. Under the observer's
/// `positive_verified` admission no check verifies a fix, so this only keeps
/// the default from citing a check that plainly is not one; an operator who
/// knows better cites evidence explicitly.
///
/// # Errors
///
/// [`FleetError::Memory`] when:
///
/// * the statement was never checked;
/// * `latest` is nonconforming: it shows the violation standing;
/// * `latest`'s commit was judged nonconforming under the statement: a
///   re-read of the violating commit is not a fix, whatever it found;
/// * `latest` did not read the whole enum (`observed_partial_coverage`): a
///   truncated read shows nothing;
/// * the check that opened the episode is not recorded, so nothing shows
///   that `latest` follows it;
/// * `latest` was recorded no later than that check, or compared at an
///   earlier instant (its commit predates the violating one).
pub fn default_resolution_evidence(
    statement_id: Sha256Digest,
    latest: Option<&StoredSpecCheckV1>,
    opening: Option<&StoredSpecCheckV1>,
    latest_commit_judged_nonconforming: bool,
) -> Result<AcceptedEventId> {
    let refuse = |why: String| {
        Err(FleetError::Memory(format!(
            "{why}, so it cannot evidence a resolution by default; check the fixing commit \
             first or cite evidence explicitly"
        )))
    };
    let Some(stored) = latest else {
        return refuse(format!(
            "statement {statement_id} was never checked, so a resolution has nothing to cite"
        ));
    };
    let check = &stored.record;
    let commit = check.commit_oid.to_hex();
    if check.verdict == SpecVerdictV1::Nonconforming {
        return refuse(format!(
            "the latest check of statement {statement_id} (commit {commit}) is nonconforming"
        ));
    }
    if latest_commit_judged_nonconforming {
        return refuse(format!(
            "the latest check of statement {statement_id} re-read commit {commit}, which was \
             already judged nonconforming under it"
        ));
    }
    if check
        .reasons
        .contains(&ComparisonIndeterminacyV1::ObservedPartialCoverage)
    {
        return refuse(format!(
            "the latest check of statement {statement_id} (commit {commit}) did not read the \
             whole enum"
        ));
    }
    let Some(opening) = opening else {
        return refuse(
            "the check that opened the episode is not recorded, so no check can be shown to \
             follow it"
                .into(),
        );
    };
    if stored.recorded_at <= opening.recorded_at || check.compared_at < opening.record.compared_at {
        return refuse(format!(
            "the latest check of statement {statement_id} (commit {commit}) does not follow the \
             check that opened the episode (commit {})",
            opening.record.commit_oid.to_hex()
        ));
    }
    Ok(check.observer_event_id)
}

/// The lifecycle event one operator transition appends to `envelope`'s
/// episode, checked against `envelope` exactly as the ledger will check it.
///
/// A resolution's evidence is sorted and de-duplicated, and it is also the
/// event's own evidence; a dismissal cites none.
///
/// # Errors
///
/// A contract error for an event the contract refuses against `envelope`: a
/// scope or profile other than the envelope's, a blank or oversized
/// rationale, a resolution with no or too much evidence, or an implicated
/// actor closing their own finding (AUTH-03).
pub fn spec_lifecycle_event(
    envelope: &DiscrepancyEnvelopeV1,
    profile: &ProfileReferenceV1,
    scope: &AuthenticatedProjectScopeV1,
    transition: LifecycleTransitionV1,
    effective_at: CanonicalTimestamp,
) -> ContractResult<DiscrepancyLifecycleEventV1> {
    let (transition, evidence_event_ids) = match transition {
        LifecycleTransitionV1::Resolve {
            actor,
            mut resolution_evidence_ids,
        } => {
            resolution_evidence_ids.sort_unstable();
            resolution_evidence_ids.dedup();
            let evidence = resolution_evidence_ids.clone();
            (
                LifecycleTransitionV1::Resolve {
                    actor,
                    resolution_evidence_ids,
                },
                evidence,
            )
        }
        other => (other, Vec::new()),
    };
    let event = DiscrepancyLifecycleEventV1 {
        schema_version: DISCREPANCY_RUNTIME_SCHEMA_VERSION,
        event_kind: ContractId::new(LIFECYCLE_EVENT_KIND)?,
        profile: profile.clone(),
        scope: scope.clone(),
        episode_fingerprint: envelope.episode_fingerprint,
        effective_at,
        verification_update: None,
        lifecycle_transition: Some(transition),
        evidence_event_ids,
    };
    admit_lifecycle_event(envelope, &event, scope)?;
    Ok(event)
}

/// The stored lifecycle state of `episode`.
async fn stored_state(
    ledger: &CockroachDiscrepancyLedgerRepository,
    episode: DiscrepancyEpisodeFingerprintV1,
) -> Result<LifecycleState> {
    Ok(ledger
        .read_projection(episode)
        .await?
        .ok_or_else(|| {
            FleetError::Memory(format!(
                "discrepancy episode {episode} has an envelope but no stored projection"
            ))
        })?
        .lifecycle_state)
}

#[cfg(test)]
#[path = "lifecycle_tests.rs"]
mod tests;
