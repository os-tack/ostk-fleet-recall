//! Normative binding v2: registry-head-bound activation, lifecycle,
//! separation of duty, contested evidence, and retroactive correction.
//!
//! This module implements the "Normative source activation" design (see
//! `docs/DYNAMIC_MEMORY_ARCHITECTURE.md`) on top of the already-frozen v1
//! source-binding shape in [`super::normative`]. It reuses
//! [`super::normative::SourceByteSpanV1`], [`super::normative::NormativePropositionV1`],
//! and [`super::normative::ApprovalAttestationV1`] unchanged; v1's statement
//! and receipt domains are *not* reused here (see `digest.rs`) because the v2
//! composite CAS, lifecycle, contested, and retroactive-correction semantics
//! are new preimages.
//!
//! Every type here is structural data only. It proves shape, not authority:
//! - [`NormativeBindingProposalV2`] is an unsigned candidate binding. Its
//!   `statement_id` is a canonical digest, not activation.
//! - [`NormativeActivationReceiptV2`] proves only that its own bytes are
//!   internally consistent (unique eligible approvals, threshold met, the
//!   declared separation-of-duty rule actually holds against its declared
//!   approvals). It does not prove signature verification, that the named
//!   principals are the server's currently active eligible set, or that its
//!   `statement_id` was ever proposed. A later runtime seam must derive this
//!   receipt only from verified attestations and the live active policy.
//! - [`NormativeLifecycleEventV1`] is a signed-later lifecycle preimage
//!   (activation, retirement, retraction, expiry, supersession); this module
//!   only proves shape and kind/target consistency.
//! - [`ContestedBindingV1`] records that two or more independently accepted
//!   statements for one binding family cannot be ordered; it never resolves
//!   which one is authoritative.
//! - [`RetroactiveCorrectionV1`] is the sole permitted way to accept an
//!   effective time before an accepted time: it is a bitemporal *append*
//!   that must name a distinct prior as-known conclusion and a separately
//!   named higher-threshold authorizing policy. It never rewrites the prior
//!   conclusion's bytes.
//!
//! Invariants enforced: **AUTH-04** (normativity is event-derived, never a
//! path convention — activation is a separate signed event from the source
//! binding proposal), **AUTH-03** (the document author or affected agent
//! cannot be the sole ratifier — [`NormativeActivationSeparationOfDutyV2`] is
//! re-derived from the declared approvals rather than trusted as an opaque
//! flag), and **APPL-01** (the applicability selector must resolve against
//! one concrete, canonically encoded context; a missing or non-object
//! selector fails closed rather than defaulting to `any`).

use serde::{Deserialize, Serialize};

use super::{
    ContractError, ContractResult,
    canonical::{CanonicalValue, MAX_SAFE_INTEGER, canonical_bytes, encode_canonical},
    common::{
        AuthenticatedProjectScopeV1, CanonicalTimestamp, ContractId, HexBytes, ProfileReferenceV1,
        RegistryReferenceV1,
    },
    digest::{DigestDomain, Sha256Digest, domain_separated_digest},
    evidence_v2::RegistryHeadBindingV1,
    identity::{IdentityForm, ResourceUri},
    normative::{NormativePropositionV1, SourceByteSpanV1},
    registry::EligibleApprovalV1,
};

/// Re-exported for v2 callers: the unsigned approval-attestation wire shape
/// is unchanged from v1 (see module docs). What differs in v2 is how the
/// receipt derives its separation-of-duty verdict from the attestations'
/// declared principals, not the attestation shape itself.
pub use super::normative::ApprovalAttestationV1;

const BINDING_SCHEMA_VERSION_V2: u32 = 2;
const LIFECYCLE_SCHEMA_VERSION: u32 = 1;
const CONTESTED_SCHEMA_VERSION: u32 = 1;
const RETROACTIVE_SCHEMA_VERSION: u32 = 1;
const MAX_PROPOSITIONS: usize = 256;
const MAX_SPANS: usize = 256;
const MAX_APPROVALS: usize = 64;
const MAX_CONTESTED_STATEMENTS: usize = 16;

/// Exact current state a normative activation compare-and-swap must match.
///
/// Mirrors the doc's atomic composite: "(expected binding-family
/// revision/set, active registry digest, active activation-policy digest)".
/// A policy or key change (which changes `activation_policy_digest`) makes an
/// outstanding proposal stale even if the binding-family revision and
/// registry package digest are unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NormativeCompositeHeadV2 {
    pub active_binding_set_digest: Option<Sha256Digest>,
    pub registry_package_digest: Sha256Digest,
    pub activation_policy_digest: Sha256Digest,
}

/// Unsigned statement proposed for independent approval under the currently
/// active registry and activation policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormativeBindingProposalV2 {
    pub schema_version: u32,
    pub profile: ProfileReferenceV1,
    pub scope: AuthenticatedProjectScopeV1,
    pub binding_family_id: ContractId,
    pub expected_active_binding_set_digest: Option<Sha256Digest>,
    pub repository_entity_id: ResourceUri,
    pub repository_version_id: ResourceUri,
    pub blob_id: ResourceUri,
    pub exact_path_bytes: HexBytes,
    pub source_spans: Vec<SourceByteSpanV1>,
    pub parser_artifact_id: ResourceUri,
    pub parser_configuration_digest: Sha256Digest,
    pub propositions: Vec<NormativePropositionV1>,
    pub applicability_evaluator: RegistryReferenceV1,
    pub applicability_selector: CanonicalValue,
    pub effective_from: CanonicalTimestamp,
    pub effective_until: Option<CanonicalTimestamp>,
    pub registry_head: RegistryHeadBindingV1,
    pub explicitly_supersedes_statement_id: Option<Sha256Digest>,
    pub proposer_principal_id: ContractId,
    pub source_author_principal_id: ContractId,
}

impl NormativeBindingProposalV2 {
    pub fn validate(&self) -> ContractResult<()> {
        self.profile.validate()?;
        self.applicability_evaluator.validate()?;
        canonical_bytes(&self.applicability_selector)?;
        self.registry_head.validate_shape()?;
        if self.schema_version != BINDING_SCHEMA_VERSION_V2
            || self.source_spans.is_empty()
            || self.source_spans.len() > MAX_SPANS
            || self.propositions.is_empty()
            || self.propositions.len() > MAX_PROPOSITIONS
            || self
                .applicability_selector
                .as_object()
                .is_none_or(std::collections::BTreeMap::is_empty)
            || !strictly_sorted(&self.source_spans)
            || !strictly_sorted(&self.propositions)
            || self
                .source_spans
                .iter()
                .any(|span| span.start >= span.end || span.end > MAX_SAFE_INTEGER as u64)
            || self
                .source_spans
                .windows(2)
                .any(|pair| pair[0].end > pair[1].start)
            || self.repository_entity_id.identity_form() != IdentityForm::Entity
            || self.repository_version_id.identity_form() != IdentityForm::Version
            || self.blob_id.identity_form() != IdentityForm::Occurrence
            || self.parser_artifact_id.identity_form() != IdentityForm::Occurrence
            || self
                .effective_until
                .as_ref()
                .is_some_and(|until| until <= &self.effective_from)
            || self.explicitly_supersedes_statement_id == Some(Sha256Digest::ZERO)
        {
            return Err(ContractError::Schema(
                "invalid normative binding proposal v2".into(),
            ));
        }
        for proposition in &self.propositions {
            proposition.predicate_schema.validate()?;
        }
        Ok(())
    }

    pub fn statement_id(&self) -> ContractResult<Sha256Digest> {
        self.validate()?;
        Ok(domain_separated_digest(
            DigestDomain::NormativeBindingStatementV2,
            &encode_canonical(self)?,
        ))
    }

    /// The exact composite head this proposal expects to be current.
    pub const fn expected_composite_head(&self) -> NormativeCompositeHeadV2 {
        NormativeCompositeHeadV2 {
            active_binding_set_digest: self.expected_active_binding_set_digest,
            registry_package_digest: self.registry_head.head.package_digest,
            activation_policy_digest: self.registry_head.head.activation_policy_digest,
        }
    }

    /// Reject a stale proposal: any drift in the active binding-family
    /// revision/set, active registry package, or active activation policy
    /// invalidates this proposal's compare-and-swap.
    pub fn require_current_composite(
        &self,
        current: &NormativeCompositeHeadV2,
    ) -> ContractResult<()> {
        self.validate()?;
        if &self.expected_composite_head() != current {
            return Err(ContractError::StaleRegistryHead);
        }
        Ok(())
    }

    /// A known incompatible overlap with the active binding for the same
    /// family fails closed unless this proposal explicitly names it as the
    /// supersession target. A different family, or a non-overlapping
    /// interval, is never a conflict.
    pub fn require_non_conflicting_activation(
        &self,
        active_binding_family_id: &ContractId,
        active_statement_id: Sha256Digest,
        active_effective_from: &CanonicalTimestamp,
        active_effective_until: Option<&CanonicalTimestamp>,
    ) -> ContractResult<()> {
        self.validate()?;
        if active_binding_family_id != &self.binding_family_id {
            return Ok(());
        }
        let overlaps = intervals_overlap(
            &self.effective_from,
            self.effective_until.as_ref(),
            active_effective_from,
            active_effective_until,
        );
        if overlaps && self.explicitly_supersedes_statement_id != Some(active_statement_id) {
            return Err(ContractError::Schema(
                "incompatible overlapping normative binding without explicit supersession".into(),
            ));
        }
        Ok(())
    }
}

/// Closed source-author separation-of-duty rule for normative activation v2.
///
/// The document author or affected agent may still approve — the rule only
/// forbids being the *sole* ratifier (doc: "The document author or affected
/// agent cannot be the sole ratifier").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NormativeActivationSeparationOfDutyV2 {
    IndependentApprovalFromSourceAuthor,
}

impl NormativeActivationSeparationOfDutyV2 {
    fn is_satisfied_by(
        self,
        source_author_principal_id: &ContractId,
        approving_principal_ids: &[ContractId],
    ) -> bool {
        match self {
            Self::IndependentApprovalFromSourceAuthor => approving_principal_ids
                .iter()
                .any(|principal| principal != source_author_principal_id),
        }
    }
}

/// Canonical normative-activation receipt preimage.
///
/// Structural validation grants no authority. It proves that the declared
/// eligible approvals are unique per principal and per key, that the
/// threshold is met by their count, and that the declared separation-of-duty
/// verdict is actually re-derivable from `source_author_principal_id` and the
/// declared approving principals — not merely asserted. A later runtime seam
/// must still supply verified signatures and the server's live active
/// eligible-signer set before this receipt carries any authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormativeActivationReceiptV2 {
    pub schema_version: u32,
    pub statement_id: Sha256Digest,
    pub source_author_principal_id: ContractId,
    pub eligible_approvals: Vec<EligibleApprovalV1>,
    pub required_threshold: u16,
    pub separation_of_duty: NormativeActivationSeparationOfDutyV2,
    pub separation_of_duty_satisfied: bool,
    pub accepted_at: CanonicalTimestamp,
}

impl NormativeActivationReceiptV2 {
    pub fn validate(&self) -> ContractResult<()> {
        if self.schema_version != BINDING_SCHEMA_VERSION_V2
            || self.required_threshold == 0
            || usize::from(self.required_threshold) > self.eligible_approvals.len()
            || self.eligible_approvals.len() > MAX_APPROVALS
            || !strictly_sorted(&self.eligible_approvals)
            || !approval_bindings_are_unique(&self.eligible_approvals)
        {
            return Err(ContractError::Schema(
                "invalid normative activation receipt v2".into(),
            ));
        }
        let approving_principal_ids: Vec<ContractId> = self
            .eligible_approvals
            .iter()
            .map(|approval| approval.principal_id.clone())
            .collect();
        let derived_verdict = self
            .separation_of_duty
            .is_satisfied_by(&self.source_author_principal_id, &approving_principal_ids);
        if derived_verdict != self.separation_of_duty_satisfied
            || !self.separation_of_duty_satisfied
        {
            return Err(ContractError::Schema(
                "declared separation-of-duty verdict does not match its declared approvals".into(),
            ));
        }
        Ok(())
    }

    pub fn receipt_id(&self) -> ContractResult<Sha256Digest> {
        self.validate()?;
        Ok(domain_separated_digest(
            DigestDomain::NormativeBindingReceiptV2,
            &encode_canonical(self)?,
        ))
    }
}

/// Closed set of lifecycle transitions a normative binding statement may
/// undergo, each governed by the active policy at the time of the event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NormativeLifecycleKindV1 {
    Activation,
    Retirement,
    Retraction,
    Expiry,
    Supersession,
}

/// Signed-later lifecycle preimage governing one binding statement.
///
/// `supersedes_statement_id` is required exactly when `kind` is
/// [`NormativeLifecycleKindV1::Supersession`] and forbidden otherwise: a
/// supersession without an explicit target, or a non-supersession event that
/// names one, is invalid shape. A supersession event may never name itself
/// as its own supersession target (`supersedes_statement_id ==
/// Some(statement_id)` is rejected), mirroring the identical self-reference
/// guard on [`RetroactiveCorrectionV1`]. `waiver_reference_digest` is a
/// reference-only pointer into the separate, durable waiver system
/// (`DISC-05`); a waiver scopes and expires policy exceptions but never
/// deactivates the underlying expectation, so this module does not model
/// waiver semantics itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormativeLifecycleEventV1 {
    pub schema_version: u32,
    pub kind: NormativeLifecycleKindV1,
    pub binding_family_id: ContractId,
    pub statement_id: Sha256Digest,
    pub registry_head: RegistryHeadBindingV1,
    pub effective_at: CanonicalTimestamp,
    pub supersedes_statement_id: Option<Sha256Digest>,
    pub waiver_reference_digest: Option<Sha256Digest>,
}

impl NormativeLifecycleEventV1 {
    pub fn validate(&self) -> ContractResult<()> {
        self.registry_head.validate_shape()?;
        let supersession_target_consistent = match self.kind {
            NormativeLifecycleKindV1::Supersession => self.supersedes_statement_id.is_some(),
            NormativeLifecycleKindV1::Activation
            | NormativeLifecycleKindV1::Retirement
            | NormativeLifecycleKindV1::Retraction
            | NormativeLifecycleKindV1::Expiry => self.supersedes_statement_id.is_none(),
        };
        if self.schema_version != LIFECYCLE_SCHEMA_VERSION
            || self.statement_id == Sha256Digest::ZERO
            || !supersession_target_consistent
            || self.supersedes_statement_id == Some(Sha256Digest::ZERO)
            || self.supersedes_statement_id == Some(self.statement_id)
        {
            return Err(ContractError::Schema(
                "invalid normative lifecycle event v1".into(),
            ));
        }
        Ok(())
    }

    pub fn event_id(&self) -> ContractResult<Sha256Digest> {
        self.validate()?;
        Ok(domain_separated_digest(
            DigestDomain::NormativeLifecycleEventV1,
            &encode_canonical(self)?,
        ))
    }
}

/// Closed reason a binding family's independently accepted statements cannot
/// be ordered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NormativeContestReasonV1 {
    LateOrCorrectiveEvidence,
    IndependentlyAcceptedUnestablishableOrdering,
}

/// Two or more independently accepted statements for one binding family whose
/// precedence cannot be established.
///
/// Per the doc, `Contested` never resolves which statement is authoritative;
/// it only records that dependent comparisons naming this family become
/// `unknown` until an authorized resolution event supersedes the ambiguity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContestedBindingV1 {
    pub schema_version: u32,
    pub binding_family_id: ContractId,
    pub contested_statement_ids: Vec<Sha256Digest>,
    pub reason: NormativeContestReasonV1,
    pub detected_at: CanonicalTimestamp,
    pub waiver_reference_digest: Option<Sha256Digest>,
}

impl ContestedBindingV1 {
    pub fn validate(&self) -> ContractResult<()> {
        if self.schema_version != CONTESTED_SCHEMA_VERSION
            || self.contested_statement_ids.len() < 2
            || self.contested_statement_ids.len() > MAX_CONTESTED_STATEMENTS
            || !strictly_sorted(&self.contested_statement_ids)
            || self.contested_statement_ids.contains(&Sha256Digest::ZERO)
        {
            return Err(ContractError::Schema(
                "invalid contested normative binding v1".into(),
            ));
        }
        Ok(())
    }

    pub fn contested_id(&self) -> ContractResult<Sha256Digest> {
        self.validate()?;
        Ok(domain_separated_digest(
            DigestDomain::NormativeContestedV1,
            &encode_canonical(self)?,
        ))
    }

    /// Whether a dependent comparison naming one of these contested
    /// statements as authoritative must report `unknown` rather than a
    /// derived verdict. Always `true` while a `ContestedBindingV1` for the
    /// relevant statements remains unresolved.
    pub const fn dependent_comparison_is_unknown(&self) -> bool {
        true
    }
}

/// Reject a normal-policy activation whose effective time precedes its accepted time.
///
/// Only [`RetroactiveCorrectionV1`], authorized under a separately named
/// higher-threshold policy, may accept that ordering.
pub fn require_effective_not_before_accepted(
    effective_from: &CanonicalTimestamp,
    accepted_at: &CanonicalTimestamp,
) -> ContractResult<()> {
    if effective_from < accepted_at {
        return Err(ContractError::Schema(
            "normal activation policy forbids an effective time before the accepted time".into(),
        ));
    }
    Ok(())
}

/// Exceptional, separately authorized bitemporal append.
///
/// This does not rewrite `superseded_as_known_statement_id`: that prior
/// as-known conclusion remains immutable and queryable exactly as it was
/// before this correction. `statement_id` is a new, distinct normative
/// binding statement whose `effective_from` may legitimately precede
/// `accepted_at`, authorized only by `authorizing_policy` — a policy
/// reference `validate()` requires to be distinct from, and to declare a
/// strictly higher threshold than, `normal_activation_policy` (the ordinary
/// policy this correction is exceptional relative to). Like
/// [`NormativeActivationReceiptV2::required_threshold`], the two threshold
/// fields here are declared, structural data: this contract layer proves
/// only that the record is internally self-consistent (separately named,
/// strictly higher), never that either policy reference names the server's
/// actually-active policy or its actually-active threshold — a later
/// runtime seam must still compare both references against the live
/// registry before granting authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetroactiveCorrectionV1 {
    pub schema_version: u32,
    pub statement_id: Sha256Digest,
    pub superseded_as_known_statement_id: Sha256Digest,
    pub effective_from: CanonicalTimestamp,
    pub accepted_at: CanonicalTimestamp,
    pub authorizing_policy: RegistryReferenceV1,
    pub authorizing_policy_required_threshold: u16,
    pub normal_activation_policy: RegistryReferenceV1,
    pub normal_activation_policy_required_threshold: u16,
}

impl RetroactiveCorrectionV1 {
    pub fn validate(&self) -> ContractResult<()> {
        self.authorizing_policy.validate()?;
        self.normal_activation_policy.validate()?;
        if self.schema_version != RETROACTIVE_SCHEMA_VERSION
            || self.statement_id == Sha256Digest::ZERO
            || self.superseded_as_known_statement_id == Sha256Digest::ZERO
            || self.statement_id == self.superseded_as_known_statement_id
            || self.effective_from >= self.accepted_at
            || self.authorizing_policy.entry_id == self.normal_activation_policy.entry_id
            || self.authorizing_policy_required_threshold == 0
            || self.normal_activation_policy_required_threshold == 0
            || self.authorizing_policy_required_threshold
                <= self.normal_activation_policy_required_threshold
        {
            return Err(ContractError::Schema(
                "invalid retroactive correction v1".into(),
            ));
        }
        Ok(())
    }
}

fn intervals_overlap(
    from_a: &CanonicalTimestamp,
    until_a: Option<&CanonicalTimestamp>,
    from_b: &CanonicalTimestamp,
    until_b: Option<&CanonicalTimestamp>,
) -> bool {
    let a_before_b_end = until_b.is_none_or(|until| from_a < until);
    let b_before_a_end = until_a.is_none_or(|until| from_b < until);
    a_before_b_end && b_before_a_end
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn approval_bindings_are_unique(values: &[EligibleApprovalV1]) -> bool {
    use std::collections::BTreeSet;

    let principals = values
        .iter()
        .map(|approval| &approval.principal_id)
        .collect::<BTreeSet<_>>();
    let keys = values
        .iter()
        .map(|approval| &approval.signer_key_id)
        .collect::<BTreeSet<_>>();
    principals.len() == values.len() && keys.len() == values.len()
}

#[cfg(test)]
#[path = "normative_v2_tests.rs"]
mod tests;
