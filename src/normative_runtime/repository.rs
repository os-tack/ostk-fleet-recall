//! Admission rules, request/outcome shapes, and the repository trait for the
//! normative activation runtime (W3-NORM, Stage 6).
//!
//! [`admit_activation`] is the whole fail-closed boundary, and it is pure: it
//! runs before any transaction opens, so a rejected activation never touches the
//! database. Every check below is an ordinary negative test in
//! `repository_tests.rs`.

use async_trait::async_trait;

use crate::Result;
use crate::memory_contracts::common::{
    AuthenticatedProjectScopeV1, CanonicalTimestamp, ContractId,
};
use crate::memory_contracts::digest::{DigestDomain, Sha256Digest, framed_digest};
use crate::memory_contracts::evidence_v2::RegistryHeadBindingV1;
use crate::memory_contracts::normative_v2::{
    ContestedBindingV1, NormativeActivationReceiptV2, NormativeBindingProposalV2,
    NormativeCompositeHeadV2, NormativeLifecycleEventV1, NormativeLifecycleKindV1,
    RetroactiveCorrectionV1, require_effective_not_before_accepted,
};
use crate::memory_contracts::{ContractError, ContractResult};

use super::projection::{
    NormativeFamilyProjectionV1, NormativeLogEntryV1, NormativeLogRecordV1,
    NormativeStatementIntervalV1,
};

/// The active registry head this runtime is bound to at construction.
///
/// The caller reads it from the registry activation head and hands it over once;
/// every proposal must name exactly this package and activation policy or its
/// compare-and-set is stale. Binding it at construction is what stops a proposal
/// from choosing which registry it is judged against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NormativeRegistryBindingV1 {
    pub registry_package_digest: Sha256Digest,
    pub activation_policy_digest: Sha256Digest,
}

impl NormativeRegistryBindingV1 {
    /// Reject a zero digest closed: an unbound runtime must not exist.
    pub fn validate(&self) -> ContractResult<()> {
        if self.registry_package_digest == Sha256Digest::ZERO
            || self.activation_policy_digest == Sha256Digest::ZERO
        {
            return Err(ContractError::Schema(
                "normative runtime registry binding must name a non-zero package and policy".into(),
            ));
        }
        Ok(())
    }

    /// The composite head that a proposal expecting `active_binding_set_digest`
    /// must match exactly.
    #[must_use]
    pub const fn composite_head(
        &self,
        active_binding_set_digest: Option<Sha256Digest>,
    ) -> NormativeCompositeHeadV2 {
        NormativeCompositeHeadV2 {
            active_binding_set_digest,
            registry_package_digest: self.registry_package_digest,
            activation_policy_digest: self.activation_policy_digest,
        }
    }
}

/// One activation attempt.
///
/// The unsigned proposal, the activation receipt that ratifies it, and — only
/// for a retroactive correction — the separately authorized record that permits
/// an effective time before the accepted time.
#[derive(Debug, Clone)]
pub struct NormativeActivationCandidateV1 {
    pub proposal: NormativeBindingProposalV2,
    pub receipt: NormativeActivationReceiptV2,
    pub retroactive_correction: Option<RetroactiveCorrectionV1>,
}

/// A retirement, retraction, or expiry of one live statement.
#[derive(Debug, Clone)]
pub struct NormativeLifecycleRequestV1 {
    pub binding_family_id: ContractId,
    /// Must be [`NormativeLifecycleKindV1::Retirement`],
    /// [`NormativeLifecycleKindV1::Retraction`], or
    /// [`NormativeLifecycleKindV1::Expiry`]: activation and supersession are
    /// reached only through [`NormativeActivationRepository::activate`], which
    /// requires a receipt.
    pub kind: NormativeLifecycleKindV1,
    pub statement_id: Sha256Digest,
    pub registry_head: RegistryHeadBindingV1,
    pub effective_at: CanonicalTimestamp,
    /// The binding-set digest this request expects to be current: the same
    /// compare-and-set discipline an activation uses.
    pub expected_active_binding_set_digest: Option<Sha256Digest>,
    pub waiver_reference_digest: Option<Sha256Digest>,
}

/// What one accepted transition did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormativeTransitionV1 {
    /// The lifecycle event's own identity, as appended.
    pub event_id: Sha256Digest,
    /// The statement the event names; `None` for a contest record, which names
    /// a set of statements rather than one.
    pub statement_id: Option<Sha256Digest>,
    /// Head revision after the transition (strictly monotone).
    pub head_revision: u64,
    /// Normative-log sequence the projection cursor now sits at.
    pub log_seq: u64,
    /// The binding-set digest now current, `None` when nothing is live.
    pub active_binding_set_digest: Option<Sha256Digest>,
}

/// Outcome of one compare-and-set activation or lifecycle transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NormativeActivationOutcomeV1 {
    /// The compare-and-set won: the log row, the head advance, and the
    /// projection advance all committed together.
    Installed(NormativeTransitionV1),
    /// The compare-and-set lost to a concurrent transition. Nothing was written.
    /// This is an outcome, not an error: the caller re-reads the head and
    /// re-proposes against it.
    Lost {
        /// The binding-set digest actually current when this attempt ran.
        observed_binding_set_digest: Option<Sha256Digest>,
        /// The head revision actually current when this attempt ran.
        observed_head_revision: u64,
    },
}

/// The durable compare-and-set head for one binding family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormativeHeadRowV1 {
    pub binding_family_id: ContractId,
    pub active_binding_set_digest: Option<Sha256Digest>,
    pub registry_package_digest: Sha256Digest,
    pub activation_policy_digest: Sha256Digest,
    pub head_revision: u64,
    pub log_seq: u64,
}

impl NormativeHeadRowV1 {
    /// The exact composite a proposal's `require_current_composite` is checked
    /// against.
    #[must_use]
    pub const fn composite_head(&self) -> NormativeCompositeHeadV2 {
        NormativeCompositeHeadV2 {
            active_binding_set_digest: self.active_binding_set_digest,
            registry_package_digest: self.registry_package_digest,
            activation_policy_digest: self.activation_policy_digest,
        }
    }
}

/// An activation that passed every pure check.
///
/// It carries the lifecycle event the runtime *derived* from the candidate. The
/// event is never supplied by the caller, so a caller cannot declare an
/// activation to be a supersession, or vice versa.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedNormativeActivationV1 {
    pub statement_id: Sha256Digest,
    pub event_id: Sha256Digest,
    pub record: NormativeLogRecordV1,
    pub interval: NormativeStatementIntervalV1,
    pub expected_head: NormativeCompositeHeadV2,
}

/// Digest of the set of statements currently live for one binding family.
///
/// `None` for an empty set: the composite head an inaugural activation must
/// expect. Length-framed under its own domain, so no two families and no two
/// live sets can collide, and the digest is a function of the *set* — sorted,
/// order-insensitive — not of the order statements were activated in.
#[must_use]
pub fn active_binding_set_digest(
    binding_family_id: &ContractId,
    live_statement_ids: &[Sha256Digest],
) -> Option<Sha256Digest> {
    if live_statement_ids.is_empty() {
        return None;
    }
    let mut sorted = live_statement_ids.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let mut parts: Vec<&[u8]> = Vec::with_capacity(sorted.len() + 1);
    parts.push(binding_family_id.as_str().as_bytes());
    for statement_id in &sorted {
        parts.push(statement_id.as_bytes());
    }
    Some(framed_digest(
        DigestDomain::NormativeActiveBindingSetV1,
        &parts,
    ))
}

/// Every pure fail-closed check an activation must pass, in one place.
///
/// Ordered so the cheapest structural rejections run first, but every check is
/// independent: none of them is reachable only because an earlier one passed.
pub fn admit_activation(
    candidate: &NormativeActivationCandidateV1,
    binding: &NormativeRegistryBindingV1,
    bound_scope: &AuthenticatedProjectScopeV1,
) -> ContractResult<AdmittedNormativeActivationV1> {
    binding.validate()?;
    let proposal = &candidate.proposal;
    let statement_id = proposal.statement_id()?;

    // SCOPE binding: the proposal's authenticated project scope must be the
    // scope this repository was constructed for. Without this a proposal minted
    // for another tenant/project would activate here under our credentials.
    if &proposal.scope != bound_scope {
        return Err(ContractError::Schema(
            "normative proposal scope is not the runtime's bound project scope".into(),
        ));
    }

    // Registry/policy binding: a proposal judged against a registry package or
    // activation policy other than the live one is stale, not merely different.
    if proposal.registry_head.head.package_digest != binding.registry_package_digest
        || proposal.registry_head.head.activation_policy_digest != binding.activation_policy_digest
    {
        return Err(ContractError::StaleRegistryHead);
    }

    // The receipt must ratify THIS statement and name THIS source author.
    if candidate.receipt.statement_id != statement_id {
        return Err(ContractError::Schema(
            "normative activation receipt ratifies a different statement".into(),
        ));
    }
    if candidate.receipt.source_author_principal_id != proposal.source_author_principal_id {
        return Err(ContractError::Schema(
            "normative activation receipt names a different source author".into(),
        ));
    }
    // Threshold, unique principal/key bindings, and the contract's own
    // separation-of-duty re-derivation (AUTH-03).
    candidate.receipt.validate()?;

    // Runtime separation of duty, stronger than the contract's: every actor
    // implicated in the change — the source author AND the proposer — is
    // excluded from being the only ratifier. An approval set consisting solely
    // of implicated principals is refused closed.
    let independent = candidate.receipt.eligible_approvals.iter().any(|approval| {
        approval.principal_id != proposal.source_author_principal_id
            && approval.principal_id != proposal.proposer_principal_id
    });
    if !independent {
        return Err(ContractError::Schema(
            "normative activation has no ratifier independent of the actors implicated in the change"
                .into(),
        ));
    }

    // Bitemporal rule: an ordinary activation may not be effective before it was
    // accepted. Only a separately authorized retroactive correction may be, and
    // it must be about exactly this statement at exactly these two times.
    match &candidate.retroactive_correction {
        None => require_effective_not_before_accepted(
            &proposal.effective_from,
            &candidate.receipt.accepted_at,
        )?,
        Some(correction) => {
            correction.validate()?;
            if correction.statement_id != statement_id
                || correction.effective_from != proposal.effective_from
                || correction.accepted_at != candidate.receipt.accepted_at
            {
                return Err(ContractError::Schema(
                    "retroactive correction does not describe this activation".into(),
                ));
            }
            // A correction preserves the prior as-known conclusion; it may not
            // name the statement it introduces as the thing it corrects.
            if correction.superseded_as_known_statement_id == statement_id {
                return Err(ContractError::Schema(
                    "retroactive correction cannot supersede its own statement".into(),
                ));
            }
        }
    }

    // The lifecycle event is DERIVED, never supplied: a proposal that names a
    // supersession target becomes a Supersession event, everything else an
    // Activation. Its own validate() then rejects a self-supersession.
    let kind = if proposal.explicitly_supersedes_statement_id.is_some() {
        NormativeLifecycleKindV1::Supersession
    } else {
        NormativeLifecycleKindV1::Activation
    };
    let event = NormativeLifecycleEventV1 {
        schema_version: 1,
        kind,
        binding_family_id: proposal.binding_family_id.clone(),
        statement_id,
        registry_head: proposal.registry_head.clone(),
        effective_at: candidate.receipt.accepted_at.clone(),
        supersedes_statement_id: proposal.explicitly_supersedes_statement_id,
        waiver_reference_digest: None,
    };
    let event_id = event.event_id()?;
    let interval = NormativeStatementIntervalV1 {
        statement_id,
        effective_from: proposal.effective_from.clone(),
        effective_until: proposal.effective_until.clone(),
    };
    let record = NormativeLogRecordV1::Lifecycle {
        event,
        interval: interval.clone(),
    };
    record.validate()?;

    Ok(AdmittedNormativeActivationV1 {
        statement_id,
        event_id,
        record,
        interval,
        expected_head: proposal.expected_composite_head(),
    })
}

/// Refuse an activation that overlaps any live statement it does not explicitly
/// supersede (the contract's own conflict rule, applied to the durable live set).
pub fn require_non_conflicting_against_live(
    proposal: &NormativeBindingProposalV2,
    projection: &NormativeFamilyProjectionV1,
) -> ContractResult<()> {
    for live in &projection.live {
        proposal.require_non_conflicting_activation(
            &projection.binding_family_id,
            live.statement_id,
            &live.effective_from,
            live.effective_until.as_ref(),
        )?;
    }
    Ok(())
}

/// Derive the lifecycle record for a retirement, retraction, or expiry.
///
/// The statement's interval is taken from the durable projection, not from the
/// caller, so a retirement cannot restate a statement's effective span.
pub fn admit_lifecycle(
    request: &NormativeLifecycleRequestV1,
    binding: &NormativeRegistryBindingV1,
    projection: &NormativeFamilyProjectionV1,
) -> ContractResult<(Sha256Digest, NormativeLogRecordV1)> {
    binding.validate()?;
    match request.kind {
        NormativeLifecycleKindV1::Retirement
        | NormativeLifecycleKindV1::Retraction
        | NormativeLifecycleKindV1::Expiry => {}
        NormativeLifecycleKindV1::Activation | NormativeLifecycleKindV1::Supersession => {
            return Err(ContractError::Schema(
                "activation and supersession require a ratified activation candidate".into(),
            ));
        }
    }
    if request.registry_head.head.package_digest != binding.registry_package_digest
        || request.registry_head.head.activation_policy_digest != binding.activation_policy_digest
    {
        return Err(ContractError::StaleRegistryHead);
    }
    if request.binding_family_id != projection.binding_family_id {
        return Err(ContractError::Schema(
            "normative lifecycle request names a different binding family".into(),
        ));
    }
    let Some(interval) = projection
        .live
        .iter()
        .find(|interval| interval.statement_id == request.statement_id)
    else {
        return Err(ContractError::Schema(
            "normative lifecycle request names a statement that is not live".into(),
        ));
    };
    let event = NormativeLifecycleEventV1 {
        schema_version: 1,
        kind: request.kind,
        binding_family_id: request.binding_family_id.clone(),
        statement_id: request.statement_id,
        registry_head: request.registry_head.clone(),
        effective_at: request.effective_at.clone(),
        supersedes_statement_id: None,
        waiver_reference_digest: request.waiver_reference_digest,
    };
    let event_id = event.event_id()?;
    let record = NormativeLogRecordV1::Lifecycle {
        event,
        interval: interval.clone(),
    };
    record.validate()?;
    Ok((event_id, record))
}

/// Refuse a contest record that does not describe this family's live set.
///
/// A contest is only meaningful while at least two of the statements it names
/// are live; recording one against a single live statement (or none) would flip
/// the family to `unknown` on no evidence.
pub fn admit_contest(
    contest: &ContestedBindingV1,
    projection: &NormativeFamilyProjectionV1,
) -> ContractResult<(Sha256Digest, NormativeLogRecordV1)> {
    contest.validate()?;
    if contest.binding_family_id != projection.binding_family_id {
        return Err(ContractError::Schema(
            "contested binding names a different binding family".into(),
        ));
    }
    let live = projection.live_statement_ids();
    let named_and_live = contest
        .contested_statement_ids
        .iter()
        .filter(|statement_id| live.contains(statement_id))
        .count();
    if named_and_live < 2 {
        return Err(ContractError::Schema(
            "contested binding must name at least two live statements".into(),
        ));
    }
    let contested_id = contest.contested_id()?;
    let record = NormativeLogRecordV1::Contest {
        contest: contest.clone(),
    };
    record.validate()?;
    Ok((contested_id, record))
}

/// Append and read surface for the normative activation runtime, bound once to
/// physical scope, semantic scope, and the active registry head.
#[async_trait]
pub trait NormativeActivationRepository: Send + Sync {
    /// Compare-and-set one activation (or supersession) into place. The log
    /// append, the head advance, and the projection advance commit together or
    /// not at all; a concurrent winner makes this return
    /// [`NormativeActivationOutcomeV1::Lost`] with nothing written.
    async fn activate(
        &self,
        candidate: &NormativeActivationCandidateV1,
    ) -> Result<NormativeActivationOutcomeV1>;

    /// Append a retirement, retraction, or expiry under the same
    /// compare-and-set. History is never erased: the prior activation row stays.
    async fn retire(
        &self,
        request: &NormativeLifecycleRequestV1,
    ) -> Result<NormativeActivationOutcomeV1>;

    /// Record that two or more live statements cannot be ordered, flipping the
    /// family's projection to `unknown`.
    async fn record_contest(&self, contest: &ContestedBindingV1) -> Result<NormativeTransitionV1>;

    /// Read the durable compare-and-set head, if the family has one.
    async fn read_head(&self, binding_family_id: &ContractId)
    -> Result<Option<NormativeHeadRowV1>>;

    /// Read the stored projection exactly as persisted, with its cursor.
    async fn read_projection(
        &self,
        binding_family_id: &ContractId,
    ) -> Result<Option<NormativeFamilyProjectionV1>>;

    /// Read the whole normative log for one family, in sequence order.
    async fn read_log(&self, binding_family_id: &ContractId) -> Result<Vec<NormativeLogEntryV1>>;

    /// Re-derive the projection from the durable log alone. Must equal the
    /// stored projection byte for byte.
    async fn rebuild_projection(
        &self,
        binding_family_id: &ContractId,
    ) -> Result<NormativeFamilyProjectionV1>;
}

#[cfg(test)]
#[path = "repository_tests.rs"]
mod tests;
