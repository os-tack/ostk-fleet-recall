//! The discrepancy envelope a verified spec nonconformance opens (Stage 6).
//!
//! [`build_spec_envelope`] is pure: every field is a function of the inputs,
//! so the same detection always builds the same envelope and a replay is an
//! exact replay. The mapping:
//!
//! * `finding_type` is `spec_nonconformance`; `severity` is the
//!   expectation's; `canonical_subject` is the proposal's repository entity;
//!   `predicate` is the expectation's (a check has already required it to be
//!   the one the genesis package admits the observer for).
//! * `expectation_policy` is `{binding_family_id, version 1, statement_id}`:
//!   the statement itself is the expectation, so the family is one statement
//!   about one repository. Its applicability is `repository_commit: any`,
//!   declared explicitly, so every commit of the repository falls in the same
//!   family ([`spec_family_fingerprint`]).
//! * The comparator lineage and episode policy are the compiled-in ones
//!   ([`super::registry`]); the lineage is also the `detector`, and the
//!   genesis observer admission that read the commit is the `extractor`.
//! * The observer event is the member and the coverage evidence; the observer
//!   event and the git blob event naming the exact source object are the
//!   supporting evidence. No actor is implicated.
//! * `detected_at`, `effective_from`, and the opening transition's
//!   `effective_at` are all the compared instant. The opening transition's
//!   source fact is the observer event's own source-fact identity
//!   ([`observer_source_fact_id`]), so each observed commit seeds its own
//!   episode, while the family stays the same.
//! * `registry` is the witnessed head binding. The initial verification
//!   state is the one the discrepancy runtime gives a discrepant comparison
//!   (`candidate`).

use crate::discrepancy_runtime::{
    ComparisonVerdictV1, DISCREPANCY_RUNTIME_SCHEMA_VERSION, DiscrepancyEnvelopeCandidateV1,
    seed_episode_fingerprint,
};
use crate::memory_contracts::common::{
    AuthenticatedProjectScopeV1, CanonicalTimestamp, ContractId, RegistryReferenceV1,
};
use crate::memory_contracts::digest::Sha256Digest;
use crate::memory_contracts::discrepancy::{
    ApplicabilityDimensionV1, ApplicabilityDimensionValueV1, DiscrepancyEnvelopeV1,
    DiscrepancyFamilyFingerprintV1, DiscrepancyFamilyPreimageV1, FindingType,
    OpeningTransitionCandidateV1,
};
use crate::memory_contracts::evidence::{AcceptedEventId, SourceFactId};
use crate::memory_contracts::evidence_v2::{
    EvidenceIngressCandidateV2, RegistryHeadBindingV1, derive_source_fact_id_v2,
};
use crate::memory_contracts::normative_v2::NormativeBindingProposalV2;
use crate::memory_contracts::{ContractError, ContractResult};

use super::expectation::RememberActionExpectationV1;
use super::registry::{SPEC_APPLICABILITY_DIMENSION, spec_comparator_lineage, spec_episode_policy};

/// The version of the expectation-policy reference a spec family names.
pub const SPEC_EXPECTATION_POLICY_VERSION: u32 = 1;

/// The provider order of a spec detection's opening transition.
///
/// A spec episode opens from exactly one detection, so the order never
/// decides anything; it is fixed so the transition is a function of the
/// detection.
pub const SPEC_OPENING_PROVIDER_ORDER: u32 = 0;

/// The event kind of every discrepancy envelope.
const ENVELOPE_EVENT_KIND: &str = "discrepancy.envelope.accepted";

/// Everything one spec detection's envelope is built from.
#[derive(Debug, Clone, Copy)]
pub struct SpecDetectionV1<'a> {
    /// The witnessed registry head the detection was made under.
    pub registry: &'a RegistryHeadBindingV1,
    /// The statement the commit was judged against, and what it expects.
    pub statement_id: Sha256Digest,
    pub proposal: &'a NormativeBindingProposalV2,
    pub expectation: &'a RememberActionExpectationV1,
    /// The activated observer admission that read the commit.
    pub extractor: &'a RegistryReferenceV1,
    /// The observer result event that measured the commit.
    pub observer_event: AcceptedEventId,
    /// The git blob event naming the exact source object the observer read.
    pub blob_event: AcceptedEventId,
    /// The observer event's source-fact identity.
    pub source_fact_id: SourceFactId,
    /// The compared instant.
    pub compared_at: &'a CanonicalTimestamp,
    /// What the comparison concluded. Only a discrepant one opens anything.
    pub verdict: &'a ComparisonVerdictV1,
}

/// The expectation-policy reference a spec family names:
/// `{binding_family_id, version 1, statement_id}`.
#[must_use]
pub fn spec_expectation_policy(
    proposal: &NormativeBindingProposalV2,
    statement_id: Sha256Digest,
) -> RegistryReferenceV1 {
    RegistryReferenceV1 {
        entry_id: proposal.binding_family_id.clone(),
        version: SPEC_EXPECTATION_POLICY_VERSION,
        entry_digest: statement_id,
    }
}

/// The applicability every spec family declares: `repository_commit` as an
/// explicit `any`.
///
/// # Errors
///
/// None in practice; the dimension id is a valid contract id.
pub fn spec_applicability() -> ContractResult<Vec<ApplicabilityDimensionV1>> {
    Ok(vec![ApplicabilityDimensionV1 {
        dimension_id: ContractId::new(SPEC_APPLICABILITY_DIMENSION)?,
        value: ApplicabilityDimensionValueV1::Any,
    }])
}

/// The discrepancy family every nonconformance of `statement_id` in the
/// proposal's repository belongs to, whichever commit shows it.
///
/// # Errors
///
/// A contract error for a proposal whose scope is not `scope`, or a preimage
/// the contract refuses.
pub fn spec_family_fingerprint(
    scope: &AuthenticatedProjectScopeV1,
    statement_id: Sha256Digest,
    proposal: &NormativeBindingProposalV2,
    expectation: &RememberActionExpectationV1,
) -> ContractResult<DiscrepancyFamilyFingerprintV1> {
    family_preimage(scope, statement_id, proposal, expectation)?.fingerprint()
}

/// The source-fact identity of one observer ingress candidate, as the
/// discrepancy contract's opening transition names it.
///
/// The evidence ledger derives it under the v2 source-fact domain; the
/// discrepancy contract carries it in the v1-named [`SourceFactId`]. Both are
/// the same 32-byte digest, re-typed, never re-hashed.
///
/// # Errors
///
/// A contract error for a source-fact identity the evidence contract refuses.
pub fn observer_source_fact_id(
    candidate: &EvidenceIngressCandidateV2,
) -> ContractResult<SourceFactId> {
    Ok(SourceFactId::from_digest(
        derive_source_fact_id_v2(&candidate.source_fact)?.digest(),
    ))
}

/// The envelope one verified spec nonconformance opens, with the exact
/// resolved policy and lineage it must be admitted against.
///
/// # Errors
///
/// [`ContractError::Schema`] for a detection whose comparison was not
/// discrepant; a contract error for inputs the envelope contract refuses.
pub fn build_spec_envelope(
    detection: &SpecDetectionV1<'_>,
) -> ContractResult<DiscrepancyEnvelopeCandidateV1> {
    if detection.verdict != &ComparisonVerdictV1::Discrepant {
        return Err(ContractError::Schema(
            "only a discrepant comparison opens a spec nonconformance".into(),
        ));
    }
    let lineage = spec_comparator_lineage()?;
    let policy = spec_episode_policy()?;
    let proposal = detection.proposal;
    let preimage = family_preimage(
        &proposal.scope,
        detection.statement_id,
        proposal,
        detection.expectation,
    )?;
    let family_fingerprint = preimage.fingerprint()?;
    let opening = OpeningTransitionCandidateV1 {
        effective_at: detection.compared_at.clone(),
        provider_order: SPEC_OPENING_PROVIDER_ORDER,
        source_fact_id: detection.source_fact_id,
    };
    let (opening_transition, episode_fingerprint) = seed_episode_fingerprint(
        family_fingerprint,
        &[],
        policy.registry_reference().version,
        std::slice::from_ref(&opening),
    )?;
    let mut supporting = vec![detection.observer_event, detection.blob_event];
    supporting.sort_unstable();
    supporting.dedup();
    let envelope = DiscrepancyEnvelopeV1 {
        schema_version: DISCREPANCY_RUNTIME_SCHEMA_VERSION,
        event_kind: ContractId::new(ENVELOPE_EVENT_KIND)?,
        profile: preimage.profile,
        scope: preimage.scope,
        finding_type: preimage.finding_type,
        severity: detection.expectation.severity,
        canonical_subject: preimage.canonical_subject,
        predicate: preimage.predicate,
        comparator_lineage_fingerprint: preimage.comparator_lineage_fingerprint,
        expectation_policy: preimage.expectation_policy,
        episode_policy: policy.registry_reference().clone(),
        required_applicability_dimension_ids: preimage.required_applicability_dimension_ids,
        applicability: preimage.applicability,
        continuity_key_dimension_ids: policy.policy().continuity_key_dimension_ids.clone(),
        family_fingerprint,
        opening_transition,
        episode_fingerprint,
        registry: detection.registry.clone(),
        detector: lineage.registry_reference().clone(),
        extractor: Some(detection.extractor.clone()),
        member_evidence_ids: vec![detection.observer_event],
        supporting_evidence_ids: supporting,
        opposing_evidence_ids: Vec::new(),
        coverage_receipt_ids: vec![detection.observer_event],
        implicated_actor_ids: Vec::new(),
        initial_verification_state: detection.verdict.initial_verification_state().ok_or_else(
            || ContractError::Schema("a discrepant comparison seeds a verification state".into()),
        )?,
        detected_at: detection.compared_at.clone(),
        effective_from: detection.compared_at.clone(),
        effective_until: None,
    };
    envelope.validate_shape()?;
    Ok(DiscrepancyEnvelopeCandidateV1 {
        envelope,
        resolved_episode_policy: policy.clone(),
        resolved_comparator_lineage: lineage.clone(),
    })
}

fn family_preimage(
    scope: &AuthenticatedProjectScopeV1,
    statement_id: Sha256Digest,
    proposal: &NormativeBindingProposalV2,
    expectation: &RememberActionExpectationV1,
) -> ContractResult<DiscrepancyFamilyPreimageV1> {
    if &proposal.scope != scope {
        return Err(ContractError::Schema(
            "the spec statement belongs to another project scope".into(),
        ));
    }
    let lineage = spec_comparator_lineage()?;
    let policy = spec_episode_policy()?;
    Ok(DiscrepancyFamilyPreimageV1 {
        schema_version: DISCREPANCY_RUNTIME_SCHEMA_VERSION,
        profile: proposal.profile.clone(),
        scope: scope.clone(),
        finding_type: FindingType::SpecNonconformance,
        canonical_subject: proposal.repository_entity_id.clone(),
        predicate: expectation.predicate.clone(),
        comparator_lineage_fingerprint: lineage.lineage().fingerprint()?,
        expectation_policy: spec_expectation_policy(proposal, statement_id),
        required_applicability_dimension_ids: lineage
            .required_applicability_dimension_ids()
            .to_vec(),
        applicability: spec_applicability()?,
        episode_policy_version: policy.registry_reference().version,
    })
}

#[cfg(test)]
#[path = "envelope_tests.rs"]
mod tests;
