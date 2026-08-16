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
            || self.applicability_selector.as_object().is_none()
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
/// names one, is invalid shape. `waiver_reference_digest` is a reference-only
/// pointer into the separate, durable waiver system (`DISC-05`); a waiver
/// scopes and expires policy exceptions but never deactivates the underlying
/// expectation, so this module does not model waiver semantics itself.
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
            || !supersession_target_consistent
            || self.supersedes_statement_id == Some(Sha256Digest::ZERO)
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
/// reference distinct from, and with a stricter threshold than, the normal
/// activation policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetroactiveCorrectionV1 {
    pub schema_version: u32,
    pub statement_id: Sha256Digest,
    pub superseded_as_known_statement_id: Sha256Digest,
    pub effective_from: CanonicalTimestamp,
    pub accepted_at: CanonicalTimestamp,
    pub authorizing_policy: RegistryReferenceV1,
}

impl RetroactiveCorrectionV1 {
    pub fn validate(&self) -> ContractResult<()> {
        self.authorizing_policy.validate()?;
        if self.schema_version != RETROACTIVE_SCHEMA_VERSION
            || self.statement_id == self.superseded_as_known_statement_id
            || self.effective_from >= self.accepted_at
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
mod tests {
    use std::{collections::BTreeMap, str::FromStr};

    use super::*;
    use crate::memory_contracts::{canonical::decode_strict, registry::RegistryHeadV1};

    const PROPOSAL_POSITIVE_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v3/normative/proposal-positive.jsonl");
    const PROPOSAL_NEGATIVE_UNSORTED_PROPOSITIONS_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/normative/proposal-negative-unsorted-propositions.jsonl"
    );
    const PROPOSAL_NEGATIVE_OVERLAPPING_SPANS_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/normative/proposal-negative-overlapping-spans.jsonl"
    );
    const PROPOSAL_NEGATIVE_WRONG_RESOURCE_FORM_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/normative/proposal-negative-wrong-resource-form.jsonl"
    );
    const RECEIPT_POSITIVE_AUTHOR_PLUS_INDEPENDENT_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/normative/receipt-positive-author-plus-independent.jsonl"
    );
    const RECEIPT_NEGATIVE_AUTHOR_ONLY_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/normative/receipt-negative-author-only.jsonl"
    );
    const LIFECYCLE_ACTIVATION_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v3/normative/lifecycle-activation.jsonl");
    const LIFECYCLE_SUPERSESSION_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v3/normative/lifecycle-supersession.jsonl");
    const LIFECYCLE_NEGATIVE_MISSING_SUPERSEDES_TARGET_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/normative/lifecycle-negative-missing-supersedes-target.jsonl"
    );
    const CONTESTED_POSITIVE_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v3/normative/contested-positive.jsonl");
    const CONTESTED_NEGATIVE_SINGLE_STATEMENT_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/normative/contested-negative-single-statement.jsonl"
    );
    const RETROACTIVE_POSITIVE_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/normative/retroactive-correction-positive.jsonl"
    );
    const RETROACTIVE_NEGATIVE_NOT_RETROACTIVE_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/normative/retroactive-correction-negative-not-retroactive.jsonl"
    );
    const VECTOR_SUITE_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v3/normative/vector-suite.jsonl");

    const EXPECTED_PROPOSAL_STATEMENT_ID: &str =
        "7bee4127c05077b62beab8c7bb1d0e2ae46b6db0e6045b6aeca45fedf2cc59b4";
    const EXPECTED_RECEIPT_ID: &str =
        "d8ac4e408e6b707f144d08b8001d099e68459e227a0bb1b44dcec4ba6c29cf07";
    const EXPECTED_LIFECYCLE_ACTIVATION_EVENT_ID: &str =
        "221748a0b211d49f11f1ce2e9a64214e214a8f401b9479975ec4b01e441402cc";
    const EXPECTED_LIFECYCLE_SUPERSESSION_EVENT_ID: &str =
        "4a2b35d9bb149e8edae89ea8d9cc61c8d96075d56ba6299a882e602114c58ec7";
    const EXPECTED_CONTESTED_ID: &str =
        "103d1d2b73e0a6f29b60ae47247aa473c6faaee60b4d952d785bcaf60c245f57";

    fn record(artifact: &'static [u8]) -> &'static [u8] {
        let record = artifact
            .strip_suffix(b"\n")
            .expect("fixture must end in exactly one LF");
        assert!(!record.ends_with(b"\n"));
        record
    }

    fn digest(value: &str) -> Sha256Digest {
        Sha256Digest::from_str(value).unwrap()
    }

    fn label_digest(label: &str) -> Sha256Digest {
        domain_separated_digest(DigestDomain::RegistryEntry, label.as_bytes())
    }

    /// Digests are pseudo-random relative to their labels, so callers that
    /// need a strictly sorted set (as `ContestedBindingV1` requires) must
    /// sort the derived digests explicitly rather than relying on label
    /// order to happen to match digest order.
    fn sorted_label_digests(labels: &[&str]) -> Vec<Sha256Digest> {
        let mut digests: Vec<Sha256Digest> = labels.iter().copied().map(label_digest).collect();
        digests.sort();
        digests
    }

    fn resource(form: &str, kind: &str, label: &str) -> ResourceUri {
        format!("urn:ostk:{form}:v1:{kind}:sha256:{}", label_digest(label))
            .parse()
            .unwrap()
    }

    fn reference(id: &str) -> RegistryReferenceV1 {
        RegistryReferenceV1 {
            entry_id: ContractId::new(id).unwrap(),
            version: 1,
            entry_digest: label_digest(id),
        }
    }

    fn profile() -> ProfileReferenceV1 {
        crate::memory_contracts::common::frozen_profile_reference_v1()
    }

    fn scope() -> AuthenticatedProjectScopeV1 {
        AuthenticatedProjectScopeV1::from_trusted_context(
            ContractId::new("tenant.fixture").unwrap(),
            ContractId::new("project.fixture").unwrap(),
        )
    }

    fn registry_head(from: &str) -> RegistryHeadBindingV1 {
        RegistryHeadBindingV1 {
            head: RegistryHeadV1 {
                activation_id: label_digest("activation"),
                package_digest: label_digest("registry-package"),
                activation_policy_digest: label_digest("activation-policy"),
            },
            effective_from: CanonicalTimestamp::parse(from).unwrap(),
            effective_until: None,
        }
    }

    fn proposal() -> NormativeBindingProposalV2 {
        NormativeBindingProposalV2 {
            schema_version: 2,
            profile: profile(),
            scope: scope(),
            binding_family_id: ContractId::new("slo.home.errors").unwrap(),
            expected_active_binding_set_digest: None,
            repository_entity_id: resource("entity", "repository", "repo"),
            repository_version_id: resource("version", "repository_version", "commit"),
            blob_id: resource("occurrence", "git_blob", "blob"),
            exact_path_bytes: HexBytes::new(b"docs/SLO.md".to_vec()).unwrap(),
            source_spans: vec![SourceByteSpanV1 {
                start: 10,
                end: 80,
                selected_bytes_digest: label_digest("span"),
            }],
            parser_artifact_id: resource("occurrence", "artifact", "parser"),
            parser_configuration_digest: label_digest("parser-config"),
            propositions: vec![NormativePropositionV1 {
                predicate_schema: reference("slo.error_rate"),
                proposition_fingerprint: label_digest("proposition"),
            }],
            applicability_evaluator: reference("environment.selector"),
            applicability_selector: CanonicalValue::Object(BTreeMap::from([(
                "environment".into(),
                CanonicalValue::String("production".into()),
            )])),
            effective_from: CanonicalTimestamp::parse("2026-08-14T12:00:00.000000000Z").unwrap(),
            effective_until: None,
            registry_head: registry_head("2026-01-01T00:00:00.000000000Z"),
            explicitly_supersedes_statement_id: None,
            proposer_principal_id: ContractId::new("principal.agent").unwrap(),
            source_author_principal_id: ContractId::new("principal.author").unwrap(),
        }
    }

    fn receipt(
        statement_id: Sha256Digest,
        source_author: &str,
        approving_principals: &[&str],
        satisfied: bool,
    ) -> NormativeActivationReceiptV2 {
        let mut approvals: Vec<EligibleApprovalV1> = approving_principals
            .iter()
            .map(|principal| EligibleApprovalV1 {
                attestation_id: label_digest(&format!("attestation.{principal}")),
                principal_id: ContractId::new(*principal).unwrap(),
                signer_key_id: ContractId::new(format!("key.{principal}")).unwrap(),
            })
            .collect();
        approvals.sort();
        NormativeActivationReceiptV2 {
            schema_version: 2,
            statement_id,
            source_author_principal_id: ContractId::new(source_author).unwrap(),
            eligible_approvals: approvals,
            required_threshold: 2,
            separation_of_duty:
                NormativeActivationSeparationOfDutyV2::IndependentApprovalFromSourceAuthor,
            separation_of_duty_satisfied: satisfied,
            accepted_at: CanonicalTimestamp::parse("2026-08-15T09:00:00.000000000Z").unwrap(),
        }
    }

    // --- statement identity and shape ---

    #[test]
    fn statement_identity_changes_with_exact_source_span() {
        let first = proposal();
        let first_id = first.statement_id().unwrap();
        let mut shifted = first;
        shifted.source_spans[0].start += 1;
        assert_ne!(first_id, shifted.statement_id().unwrap());
    }

    #[test]
    fn statement_identity_does_not_reuse_v1_domain() {
        let a = proposal();
        let v2_id = a.statement_id().unwrap();
        // The v1 preimage uses a different domain prefix even for identical
        // logical content; v2 must not collide with it.
        let v1_domain_id = domain_separated_digest(
            DigestDomain::NormativeBindingStatement,
            &encode_canonical(&a).unwrap(),
        );
        assert_ne!(v2_id, v1_domain_id);
    }

    #[test]
    fn a_document_edit_produces_new_evidence_but_does_not_disturb_the_prior_binding() {
        // Two proposals over the same binding family with different exact
        // source spans (as after a document edit) mint distinct statement
        // IDs. Nothing in this contract layer retires the earlier one:
        // retirement/supersession is a separate signed lifecycle event.
        let original = proposal();
        let mut edited = proposal();
        edited.source_spans = vec![SourceByteSpanV1 {
            start: 12,
            end: 90,
            selected_bytes_digest: label_digest("span-after-edit"),
        }];
        assert_ne!(
            original.statement_id().unwrap(),
            edited.statement_id().unwrap()
        );
    }

    #[test]
    fn set_fields_are_rejected_instead_of_silently_sorted() {
        let mut invalid = proposal();
        invalid.propositions = vec![
            NormativePropositionV1 {
                predicate_schema: reference("z"),
                proposition_fingerprint: label_digest("z"),
            },
            NormativePropositionV1 {
                predicate_schema: reference("a"),
                proposition_fingerprint: label_digest("a"),
            },
        ];
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn source_coordinates_and_resource_forms_fail_closed() {
        let mut overlapping = proposal();
        overlapping.source_spans.push(SourceByteSpanV1 {
            start: 79,
            end: 90,
            selected_bytes_digest: label_digest("overlap"),
        });
        assert!(overlapping.validate().is_err());

        let mut wrong_form = proposal();
        wrong_form.repository_version_id = resource("entity", "repository", "not-a-version");
        assert!(wrong_form.validate().is_err());

        let mut zero_supersession = proposal();
        zero_supersession.explicitly_supersedes_statement_id = Some(Sha256Digest::ZERO);
        assert!(zero_supersession.validate().is_err());
    }

    #[test]
    fn applicability_selector_must_be_an_object() {
        let mut invalid = proposal();
        invalid.applicability_selector = CanonicalValue::String("production".into());
        assert!(invalid.validate().is_err());
    }

    // --- stale composite CAS ---

    #[test]
    fn stale_composite_head_after_activation_policy_change_is_rejected() {
        let statement = proposal();
        let current = statement.expected_composite_head();
        assert!(statement.require_current_composite(&current).is_ok());

        let mut policy_changed = current;
        policy_changed.activation_policy_digest = label_digest("new-activation-policy");
        assert_eq!(
            statement.require_current_composite(&policy_changed),
            Err(ContractError::StaleRegistryHead)
        );

        let mut registry_changed = current;
        registry_changed.registry_package_digest = label_digest("new-registry-package");
        assert_eq!(
            statement.require_current_composite(&registry_changed),
            Err(ContractError::StaleRegistryHead)
        );

        let mut binding_set_changed = current;
        binding_set_changed.active_binding_set_digest = Some(label_digest("new-binding-set"));
        assert_eq!(
            statement.require_current_composite(&binding_set_changed),
            Err(ContractError::StaleRegistryHead)
        );
    }

    // --- supersession vs. incompatible overlap ---

    #[test]
    fn explicit_supersession_of_an_overlapping_active_binding_is_accepted() {
        let active_statement_id = label_digest("active-statement");
        let mut successor = proposal();
        successor.explicitly_supersedes_statement_id = Some(active_statement_id);
        assert!(
            successor
                .require_non_conflicting_activation(
                    &successor.binding_family_id,
                    active_statement_id,
                    &CanonicalTimestamp::parse("2026-01-01T00:00:00.000000000Z").unwrap(),
                    None,
                )
                .is_ok()
        );
    }

    #[test]
    fn implicit_overlap_without_explicit_supersession_is_rejected() {
        let active_statement_id = label_digest("active-statement");
        let successor = proposal();
        assert!(
            successor
                .require_non_conflicting_activation(
                    &successor.binding_family_id,
                    active_statement_id,
                    &CanonicalTimestamp::parse("2026-01-01T00:00:00.000000000Z").unwrap(),
                    None,
                )
                .is_err()
        );
    }

    #[test]
    fn non_overlapping_interval_never_conflicts() {
        let active_statement_id = label_digest("active-statement");
        let successor = proposal();
        assert!(
            successor
                .require_non_conflicting_activation(
                    &successor.binding_family_id,
                    active_statement_id,
                    &CanonicalTimestamp::parse("2020-01-01T00:00:00.000000000Z").unwrap(),
                    Some(&CanonicalTimestamp::parse("2021-01-01T00:00:00.000000000Z").unwrap()),
                )
                .is_ok()
        );
    }

    #[test]
    fn a_different_binding_family_never_conflicts() {
        let active_statement_id = label_digest("active-statement");
        let successor = proposal();
        let other_family = ContractId::new("slo.other.errors").unwrap();
        assert!(
            successor
                .require_non_conflicting_activation(
                    &other_family,
                    active_statement_id,
                    &CanonicalTimestamp::parse("2026-01-01T00:00:00.000000000Z").unwrap(),
                    None,
                )
                .is_ok()
        );
    }

    // --- separation of duty ---

    #[test]
    fn author_only_approval_is_rejected() {
        let statement_id = label_digest("statement");
        let author_only = receipt(
            statement_id,
            "principal.author",
            &["principal.author"],
            true,
        );
        assert!(author_only.validate().is_err());
    }

    #[test]
    fn declared_satisfied_flag_disagreeing_with_approvals_is_rejected() {
        let statement_id = label_digest("statement");
        // Two eligible approvals meet the threshold, but the declared flag
        // falsely claims SoD was NOT satisfied even though an independent
        // approver is present; the receipt must re-derive, not trust, so a
        // disagreeing flag is itself invalid.
        let mismatched = receipt(
            statement_id,
            "principal.author",
            &["principal.author", "principal.independent"],
            false,
        );
        assert!(mismatched.validate().is_err());
    }

    #[test]
    fn author_plus_independent_approval_meeting_threshold_is_accepted() {
        let statement_id = label_digest("statement");
        let ok = receipt(
            statement_id,
            "principal.author",
            &["principal.author", "principal.independent"],
            true,
        );
        assert!(ok.validate().is_ok());
    }

    #[test]
    fn threshold_not_met_is_rejected_even_with_independent_approval() {
        let statement_id = label_digest("statement");
        let mut under_threshold = receipt(
            statement_id,
            "principal.author",
            &["principal.independent"],
            true,
        );
        under_threshold.required_threshold = 2;
        assert!(under_threshold.validate().is_err());
    }

    #[test]
    fn duplicate_principal_or_key_is_rejected() {
        let statement_id = label_digest("statement");
        let mut duplicated = receipt(
            statement_id,
            "principal.author",
            &["principal.author", "principal.independent"],
            true,
        );
        duplicated.eligible_approvals[0].principal_id =
            duplicated.eligible_approvals[1].principal_id.clone();
        duplicated.eligible_approvals.sort();
        assert!(duplicated.validate().is_err());
    }

    // --- lifecycle events ---

    #[test]
    fn supersession_without_explicit_target_is_rejected() {
        let event = NormativeLifecycleEventV1 {
            schema_version: 1,
            kind: NormativeLifecycleKindV1::Supersession,
            binding_family_id: ContractId::new("slo.home.errors").unwrap(),
            statement_id: label_digest("statement"),
            registry_head: registry_head("2026-01-01T00:00:00.000000000Z"),
            effective_at: CanonicalTimestamp::parse("2026-08-15T09:00:00.000000000Z").unwrap(),
            supersedes_statement_id: None,
            waiver_reference_digest: None,
        };
        assert!(event.validate().is_err());
    }

    #[test]
    fn activation_naming_a_supersession_target_is_rejected() {
        let event = NormativeLifecycleEventV1 {
            schema_version: 1,
            kind: NormativeLifecycleKindV1::Activation,
            binding_family_id: ContractId::new("slo.home.errors").unwrap(),
            statement_id: label_digest("statement"),
            registry_head: registry_head("2026-01-01T00:00:00.000000000Z"),
            effective_at: CanonicalTimestamp::parse("2026-08-15T09:00:00.000000000Z").unwrap(),
            supersedes_statement_id: Some(label_digest("prior-statement")),
            waiver_reference_digest: None,
        };
        assert!(event.validate().is_err());
    }

    #[test]
    fn every_lifecycle_kind_produces_a_distinct_event_id() {
        let base = |kind: NormativeLifecycleKindV1, target: Option<Sha256Digest>| {
            NormativeLifecycleEventV1 {
                schema_version: 1,
                kind,
                binding_family_id: ContractId::new("slo.home.errors").unwrap(),
                statement_id: label_digest("statement"),
                registry_head: registry_head("2026-01-01T00:00:00.000000000Z"),
                effective_at: CanonicalTimestamp::parse("2026-08-15T09:00:00.000000000Z").unwrap(),
                supersedes_statement_id: target,
                waiver_reference_digest: None,
            }
        };
        let ids = [
            base(NormativeLifecycleKindV1::Activation, None)
                .event_id()
                .unwrap(),
            base(NormativeLifecycleKindV1::Retirement, None)
                .event_id()
                .unwrap(),
            base(NormativeLifecycleKindV1::Retraction, None)
                .event_id()
                .unwrap(),
            base(NormativeLifecycleKindV1::Expiry, None)
                .event_id()
                .unwrap(),
            base(
                NormativeLifecycleKindV1::Supersession,
                Some(label_digest("prior-statement")),
            )
            .event_id()
            .unwrap(),
        ];
        for (index, left) in ids.iter().enumerate() {
            for right in &ids[index + 1..] {
                assert_ne!(left, right);
            }
        }
    }

    // --- contested ---

    #[test]
    fn two_independently_accepted_statements_with_unestablishable_ordering_are_contested() {
        let contested = ContestedBindingV1 {
            schema_version: 1,
            binding_family_id: ContractId::new("slo.home.errors").unwrap(),
            contested_statement_ids: sorted_label_digests(&["statement-a", "statement-b"]),
            reason: NormativeContestReasonV1::IndependentlyAcceptedUnestablishableOrdering,
            detected_at: CanonicalTimestamp::parse("2026-08-15T09:00:00.000000000Z").unwrap(),
            waiver_reference_digest: None,
        };
        assert!(contested.validate().is_ok());
        assert!(contested.dependent_comparison_is_unknown());
    }

    #[test]
    fn a_single_statement_cannot_be_contested() {
        let mut single = ContestedBindingV1 {
            schema_version: 1,
            binding_family_id: ContractId::new("slo.home.errors").unwrap(),
            contested_statement_ids: vec![label_digest("statement-a")],
            reason: NormativeContestReasonV1::LateOrCorrectiveEvidence,
            detected_at: CanonicalTimestamp::parse("2026-08-15T09:00:00.000000000Z").unwrap(),
            waiver_reference_digest: None,
        };
        assert!(single.validate().is_err());
        single
            .contested_statement_ids
            .push(label_digest("statement-a"));
        assert!(
            single.validate().is_err(),
            "duplicate IDs are not two distinct statements"
        );
    }

    // --- retroactive correction ---

    #[test]
    fn normal_policy_rejects_effective_time_before_accepted_time() {
        let effective_from = CanonicalTimestamp::parse("2026-01-01T00:00:00.000000000Z").unwrap();
        let accepted_at = CanonicalTimestamp::parse("2026-08-15T09:00:00.000000000Z").unwrap();
        assert_eq!(
            require_effective_not_before_accepted(&effective_from, &accepted_at),
            Err(ContractError::Schema(
                "normal activation policy forbids an effective time before the accepted time"
                    .into()
            ))
        );
    }

    #[test]
    fn higher_threshold_retroactive_correction_appends_a_bitemporal_pair() {
        let correction = RetroactiveCorrectionV1 {
            schema_version: 1,
            statement_id: label_digest("corrected-statement"),
            superseded_as_known_statement_id: label_digest("prior-as-known-statement"),
            effective_from: CanonicalTimestamp::parse("2026-01-01T00:00:00.000000000Z").unwrap(),
            accepted_at: CanonicalTimestamp::parse("2026-08-15T09:00:00.000000000Z").unwrap(),
            authorizing_policy: reference("normative.retroactive_correction_policy"),
        };
        assert!(correction.validate().is_ok());
        // The prior as-known conclusion's identity is untouched: this is an
        // append naming it, not a rewrite of it.
        assert_ne!(
            correction.statement_id,
            correction.superseded_as_known_statement_id
        );
    }

    #[test]
    fn a_correction_whose_effective_time_is_not_actually_retroactive_is_rejected() {
        let not_retroactive = RetroactiveCorrectionV1 {
            schema_version: 1,
            statement_id: label_digest("corrected-statement"),
            superseded_as_known_statement_id: label_digest("prior-as-known-statement"),
            effective_from: CanonicalTimestamp::parse("2026-08-15T09:00:00.000000000Z").unwrap(),
            accepted_at: CanonicalTimestamp::parse("2026-01-01T00:00:00.000000000Z").unwrap(),
            authorizing_policy: reference("normative.retroactive_correction_policy"),
        };
        assert!(not_retroactive.validate().is_err());
    }

    #[test]
    fn a_correction_naming_itself_as_the_superseded_conclusion_is_rejected() {
        let same_id = label_digest("same-statement");
        let self_referential = RetroactiveCorrectionV1 {
            schema_version: 1,
            statement_id: same_id,
            superseded_as_known_statement_id: same_id,
            effective_from: CanonicalTimestamp::parse("2026-01-01T00:00:00.000000000Z").unwrap(),
            accepted_at: CanonicalTimestamp::parse("2026-08-15T09:00:00.000000000Z").unwrap(),
            authorizing_policy: reference("normative.retroactive_correction_policy"),
        };
        assert!(self_referential.validate().is_err());
    }

    // --- fixtures: byte-frozen positive and negative vectors ---

    #[test]
    fn fixture_proposal_positive_matches_expected_statement_id() {
        let fixture: NormativeBindingProposalV2 =
            decode_strict(record(PROPOSAL_POSITIVE_FIXTURE)).unwrap();
        assert_eq!(
            encode_canonical(&fixture).unwrap(),
            record(PROPOSAL_POSITIVE_FIXTURE)
        );
        assert_eq!(
            fixture.statement_id().unwrap(),
            digest(EXPECTED_PROPOSAL_STATEMENT_ID)
        );
    }

    #[test]
    fn fixture_proposal_negatives_fail_closed() {
        let unsorted: NormativeBindingProposalV2 =
            decode_strict(record(PROPOSAL_NEGATIVE_UNSORTED_PROPOSITIONS_FIXTURE)).unwrap();
        assert!(unsorted.validate().is_err());

        let overlapping: NormativeBindingProposalV2 =
            decode_strict(record(PROPOSAL_NEGATIVE_OVERLAPPING_SPANS_FIXTURE)).unwrap();
        assert!(overlapping.validate().is_err());

        let wrong_form: NormativeBindingProposalV2 =
            decode_strict(record(PROPOSAL_NEGATIVE_WRONG_RESOURCE_FORM_FIXTURE)).unwrap();
        assert!(wrong_form.validate().is_err());
    }

    #[test]
    fn fixture_receipt_positive_matches_expected_receipt_id() {
        let fixture: NormativeActivationReceiptV2 =
            decode_strict(record(RECEIPT_POSITIVE_AUTHOR_PLUS_INDEPENDENT_FIXTURE)).unwrap();
        assert!(fixture.validate().is_ok());
        assert_eq!(
            encode_canonical(&fixture).unwrap(),
            record(RECEIPT_POSITIVE_AUTHOR_PLUS_INDEPENDENT_FIXTURE)
        );
        assert_eq!(fixture.receipt_id().unwrap(), digest(EXPECTED_RECEIPT_ID));
    }

    #[test]
    fn fixture_receipt_negative_author_only_fails_closed() {
        let fixture: NormativeActivationReceiptV2 =
            decode_strict(record(RECEIPT_NEGATIVE_AUTHOR_ONLY_FIXTURE)).unwrap();
        assert!(fixture.validate().is_err());
    }

    #[test]
    fn fixture_lifecycle_events_match_expected_ids() {
        let activation: NormativeLifecycleEventV1 =
            decode_strict(record(LIFECYCLE_ACTIVATION_FIXTURE)).unwrap();
        assert_eq!(
            encode_canonical(&activation).unwrap(),
            record(LIFECYCLE_ACTIVATION_FIXTURE)
        );
        assert_eq!(
            activation.event_id().unwrap(),
            digest(EXPECTED_LIFECYCLE_ACTIVATION_EVENT_ID)
        );

        let supersession: NormativeLifecycleEventV1 =
            decode_strict(record(LIFECYCLE_SUPERSESSION_FIXTURE)).unwrap();
        assert_eq!(
            supersession.event_id().unwrap(),
            digest(EXPECTED_LIFECYCLE_SUPERSESSION_EVENT_ID)
        );

        let negative: NormativeLifecycleEventV1 =
            decode_strict(record(LIFECYCLE_NEGATIVE_MISSING_SUPERSEDES_TARGET_FIXTURE)).unwrap();
        assert!(negative.validate().is_err());
    }

    #[test]
    fn fixture_contested_positive_matches_expected_id_and_negative_fails_closed() {
        let positive: ContestedBindingV1 =
            decode_strict(record(CONTESTED_POSITIVE_FIXTURE)).unwrap();
        assert_eq!(
            encode_canonical(&positive).unwrap(),
            record(CONTESTED_POSITIVE_FIXTURE)
        );
        assert_eq!(
            positive.contested_id().unwrap(),
            digest(EXPECTED_CONTESTED_ID)
        );

        let negative: ContestedBindingV1 =
            decode_strict(record(CONTESTED_NEGATIVE_SINGLE_STATEMENT_FIXTURE)).unwrap();
        assert!(negative.validate().is_err());
    }

    #[test]
    fn fixture_retroactive_correction_positive_and_negative() {
        let positive: RetroactiveCorrectionV1 =
            decode_strict(record(RETROACTIVE_POSITIVE_FIXTURE)).unwrap();
        assert!(positive.validate().is_ok());
        assert_eq!(
            encode_canonical(&positive).unwrap(),
            record(RETROACTIVE_POSITIVE_FIXTURE)
        );

        let negative: RetroactiveCorrectionV1 =
            decode_strict(record(RETROACTIVE_NEGATIVE_NOT_RETROACTIVE_FIXTURE)).unwrap();
        assert!(negative.validate().is_err());
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct VectorSuiteEntryV1 {
        vector_id: ContractId,
        fixture_path: String,
        polarity: String,
        invariant_ids: Vec<String>,
        description: String,
    }

    #[test]
    fn vector_suite_manifest_is_canonical_and_lists_every_fixture() {
        let suite_text = std::str::from_utf8(record(VECTOR_SUITE_FIXTURE)).unwrap();
        let entries: Vec<VectorSuiteEntryV1> = suite_text
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(entries.len(), 18);
        for entry in &entries {
            assert!(!entry.invariant_ids.is_empty());
            assert!(
                entry.polarity == "positive" || entry.polarity == "negative",
                "unexpected polarity {}",
                entry.polarity
            );
            assert!(!entry.description.is_empty());
            assert!(
                entry.fixture_path == "inline"
                    || entry
                        .fixture_path
                        .starts_with("contracts/dynamic-memory/v3/normative/")
            );
        }
        let unique_vector_ids: std::collections::BTreeSet<&ContractId> =
            entries.iter().map(|entry| &entry.vector_id).collect();
        assert_eq!(
            unique_vector_ids.len(),
            entries.len(),
            "vector_suite.jsonl must not repeat a vector_id"
        );
    }

    #[test]
    #[ignore = "maintainer-only canonical fixture regeneration"]
    #[allow(clippy::too_many_lines)] // constructs every fixture vector inline for clarity
    fn regenerate_normative_v2_contract_artifacts() {
        use std::{fs, path::Path};

        fn framed(bytes: &[u8]) -> Vec<u8> {
            let mut framed = bytes.to_vec();
            framed.push(b'\n');
            framed
        }

        fn write(output: &Path, name: &str, bytes: &[u8]) {
            fs::write(output.join(name), framed(bytes)).unwrap();
        }

        let output = std::env::var_os("NORMATIVE_V2_VECTOR_OUTPUT")
            .map(std::path::PathBuf::from)
            .expect("NORMATIVE_V2_VECTOR_OUTPUT is required");
        fs::create_dir_all(&output).unwrap();

        let base_proposal = proposal();
        write(
            &output,
            "proposal-positive.jsonl",
            &encode_canonical(&base_proposal).unwrap(),
        );

        let mut unsorted_propositions = proposal();
        unsorted_propositions.propositions = vec![
            NormativePropositionV1 {
                predicate_schema: reference("z"),
                proposition_fingerprint: label_digest("z"),
            },
            NormativePropositionV1 {
                predicate_schema: reference("a"),
                proposition_fingerprint: label_digest("a"),
            },
        ];
        write(
            &output,
            "proposal-negative-unsorted-propositions.jsonl",
            &encode_canonical(&unsorted_propositions).unwrap(),
        );

        let mut overlapping_spans = proposal();
        overlapping_spans.source_spans.push(SourceByteSpanV1 {
            start: 79,
            end: 90,
            selected_bytes_digest: label_digest("overlap"),
        });
        write(
            &output,
            "proposal-negative-overlapping-spans.jsonl",
            &encode_canonical(&overlapping_spans).unwrap(),
        );

        let mut wrong_resource_form = proposal();
        wrong_resource_form.repository_version_id =
            resource("entity", "repository", "not-a-version");
        write(
            &output,
            "proposal-negative-wrong-resource-form.jsonl",
            &encode_canonical(&wrong_resource_form).unwrap(),
        );

        let statement_id = base_proposal.statement_id().unwrap();

        let receipt_positive = receipt(
            statement_id,
            "principal.author",
            &["principal.author", "principal.independent"],
            true,
        );
        write(
            &output,
            "receipt-positive-author-plus-independent.jsonl",
            &encode_canonical(&receipt_positive).unwrap(),
        );

        let receipt_negative = receipt(
            statement_id,
            "principal.author",
            &["principal.author"],
            true,
        );
        write(
            &output,
            "receipt-negative-author-only.jsonl",
            &encode_canonical(&receipt_negative).unwrap(),
        );

        let activation_event = NormativeLifecycleEventV1 {
            schema_version: 1,
            kind: NormativeLifecycleKindV1::Activation,
            binding_family_id: ContractId::new("slo.home.errors").unwrap(),
            statement_id,
            registry_head: registry_head("2026-01-01T00:00:00.000000000Z"),
            effective_at: CanonicalTimestamp::parse("2026-08-15T09:00:00.000000000Z").unwrap(),
            supersedes_statement_id: None,
            waiver_reference_digest: None,
        };
        write(
            &output,
            "lifecycle-activation.jsonl",
            &encode_canonical(&activation_event).unwrap(),
        );

        let supersession_event = NormativeLifecycleEventV1 {
            schema_version: 1,
            kind: NormativeLifecycleKindV1::Supersession,
            binding_family_id: ContractId::new("slo.home.errors").unwrap(),
            statement_id: label_digest("successor-statement"),
            registry_head: registry_head("2026-01-01T00:00:00.000000000Z"),
            effective_at: CanonicalTimestamp::parse("2026-08-15T09:00:00.000000000Z").unwrap(),
            supersedes_statement_id: Some(statement_id),
            waiver_reference_digest: None,
        };
        write(
            &output,
            "lifecycle-supersession.jsonl",
            &encode_canonical(&supersession_event).unwrap(),
        );

        let lifecycle_negative = NormativeLifecycleEventV1 {
            schema_version: 1,
            kind: NormativeLifecycleKindV1::Supersession,
            binding_family_id: ContractId::new("slo.home.errors").unwrap(),
            statement_id,
            registry_head: registry_head("2026-01-01T00:00:00.000000000Z"),
            effective_at: CanonicalTimestamp::parse("2026-08-15T09:00:00.000000000Z").unwrap(),
            supersedes_statement_id: None,
            waiver_reference_digest: None,
        };
        write(
            &output,
            "lifecycle-negative-missing-supersedes-target.jsonl",
            &encode_canonical(&lifecycle_negative).unwrap(),
        );

        let contested_positive = ContestedBindingV1 {
            schema_version: 1,
            binding_family_id: ContractId::new("slo.home.errors").unwrap(),
            contested_statement_ids: sorted_label_digests(&[
                "independently-accepted-a",
                "independently-accepted-b",
            ]),
            reason: NormativeContestReasonV1::IndependentlyAcceptedUnestablishableOrdering,
            detected_at: CanonicalTimestamp::parse("2026-08-15T09:00:00.000000000Z").unwrap(),
            waiver_reference_digest: None,
        };
        write(
            &output,
            "contested-positive.jsonl",
            &encode_canonical(&contested_positive).unwrap(),
        );

        let contested_negative = ContestedBindingV1 {
            schema_version: 1,
            binding_family_id: ContractId::new("slo.home.errors").unwrap(),
            contested_statement_ids: vec![label_digest("only-one-statement")],
            reason: NormativeContestReasonV1::LateOrCorrectiveEvidence,
            detected_at: CanonicalTimestamp::parse("2026-08-15T09:00:00.000000000Z").unwrap(),
            waiver_reference_digest: None,
        };
        write(
            &output,
            "contested-negative-single-statement.jsonl",
            &encode_canonical(&contested_negative).unwrap(),
        );

        let retroactive_positive = RetroactiveCorrectionV1 {
            schema_version: 1,
            statement_id: label_digest("corrected-statement"),
            superseded_as_known_statement_id: label_digest("prior-as-known-statement"),
            effective_from: CanonicalTimestamp::parse("2026-01-01T00:00:00.000000000Z").unwrap(),
            accepted_at: CanonicalTimestamp::parse("2026-08-15T09:00:00.000000000Z").unwrap(),
            authorizing_policy: reference("normative.retroactive_correction_policy"),
        };
        write(
            &output,
            "retroactive-correction-positive.jsonl",
            &encode_canonical(&retroactive_positive).unwrap(),
        );

        let retroactive_negative = RetroactiveCorrectionV1 {
            schema_version: 1,
            statement_id: label_digest("corrected-statement"),
            superseded_as_known_statement_id: label_digest("prior-as-known-statement"),
            effective_from: CanonicalTimestamp::parse("2026-08-15T09:00:00.000000000Z").unwrap(),
            accepted_at: CanonicalTimestamp::parse("2026-01-01T00:00:00.000000000Z").unwrap(),
            authorizing_policy: reference("normative.retroactive_correction_policy"),
        };
        write(
            &output,
            "retroactive-correction-negative-not-retroactive.jsonl",
            &encode_canonical(&retroactive_negative).unwrap(),
        );

        eprintln!("proposal_statement_id={statement_id}");
        eprintln!("receipt_id={}", receipt_positive.receipt_id().unwrap());
        eprintln!(
            "lifecycle_activation_event_id={}",
            activation_event.event_id().unwrap()
        );
        eprintln!(
            "lifecycle_supersession_event_id={}",
            supersession_event.event_id().unwrap()
        );
        eprintln!(
            "contested_id={}",
            contested_positive.contested_id().unwrap()
        );
    }
}
