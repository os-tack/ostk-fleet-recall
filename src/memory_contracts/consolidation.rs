//! Consolidation derivation contracts (ADR 0003, CONS-01..10).
//!
//! Consolidation derives one durable claim from an explicit set of source
//! claims. It is derivation, never mutation: sources are superseded or left
//! untouched by separate lifecycle events, and no field of a source is
//! rewritten by a consolidation statement (CONS-01).
//!
//! The public values in this module establish byte shape and semantic identity
//! only. A consolidation request cannot select its authenticated scope, the
//! live conflict state of a source, a source's kind, modality, depth, or
//! revision, the active policy, or the derivation outcome. Those enter only
//! through a later repository seam that loads live claims, re-audits every
//! asserted coordinate against the conflict and lineage projections, resolves
//! the active policy from the registry, and commits claim, links, support,
//! events, and receipt in one transaction (CONS-02). This contract-only module
//! intentionally exposes no production constructor for that admitted seam.
//!
//! Statement identity is deterministic (CONS-05): it is a domain-separated
//! digest over the canonical statement bytes, which bind the exact sorted
//! set of distinct source claim fingerprints and revisions, consolidator
//! identity and version, policy reference and digest, output kind and
//! modality, output depth, computed effective interval, and disposition. The
//! authored summary text is versioned enrichment carried by the request and
//! bound server-side by the receipt; it never enters statement identity,
//! exactly like an embedding vector under REPLAY-01. The receipt's
//! `summary_enrichment_digest` commits to the exact authored bytes under the
//! dedicated `ostk-consolidation-summary-enrichment-v1` domain
//! (`.fleet-recall/coordination/requests/
//! 2026-08-16-kimi-reg-summary-enrichment-domain.md`). The statement, policy,
//! receipt, and summary-enrichment digest constructors use the consolidation
//! `DigestDomain` variants accepted by the REG lane (`.fleet-recall/
//! coordination/requests/2026-08-16-fable-re-consolidation-digest-domains.md`)
//! and landed with W0-REG. `validate_derivation` recomputes the policy body
//! digest through `domain_separated_digest`, and the frozen fixtures carry
//! the exact values computed under the frozen formula.
//!
//! Scope containment (CONS-06) is a repository seam duty in the same pattern
//! as `remember_v2`: the statement's single `scope` is server-derived, and
//! the seam must additionally prove every source claim belongs to that scope
//! and that no private or more-visible source content crosses into a wider
//! output. Per-source visibility attributes are deliberately not modeled in
//! v1; adding them is a statement v2 change.
//!
//! Cycle rejection (CONS-09) is split. The one self-cycle decidable from a
//! single statement — the same claim fingerprint appearing twice at any
//! revisions — is rejected here by the distinct-fingerprint source rule.
//! General cycles through previously accepted derivatives require the
//! lineage-graph witness at the repository seam. What this contract
//! additionally enforces is a strictly sorted source set, a bounded
//! derivation depth, and an output depth exactly one greater than the
//! deepest source, so lineage chains are finite and replay-deterministic.
//! Sources may mix modalities; the output is conservatively capped at the
//! weakest source modality (CONS-03), and v1 accepts that a derivative may
//! therefore summarize stronger evidence in weaker terms rather than
//! rejecting the mix (kind stays uniform under the only admitted rule).

use std::fmt;

use serde::{Deserialize, Serialize};

use super::{
    ContractError, ContractResult,
    canonical::encode_canonical,
    common::{AuthenticatedProjectScopeV1, ContractId, ProfileReferenceV1, RegistryReferenceV1},
    digest::{DigestDomain, Sha256Digest, domain_separated_digest},
    evidence::AcceptedEventId,
    genesis::PropositionModalityV1,
    remember_v2::{
        CanonicalAssertionTextV2, ClaimEffectiveIntervalV2, RememberAssertionKindV2,
        SemanticClaimFingerprintV2,
    },
};

const CONSOLIDATION_SCHEMA_VERSION: u32 = 1;
const MIN_CONSOLIDATION_SOURCES: u32 = 2;
const MAX_CONSOLIDATION_SOURCES: u32 = 64;
const MAX_CONFLICT_REFERENCES: usize = 64;
const MAX_CONSOLIDATION_DEPTH: u32 = 8;
const MAX_ACCEPTED_EVENT_IDS: usize = 256;

macro_rules! digest_newtype {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(Sha256Digest);

        impl $name {
            pub const fn from_digest(digest: Sha256Digest) -> Self {
                Self(digest)
            }

            pub const fn digest(self) -> Sha256Digest {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                self.0.serialize(serializer)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                Sha256Digest::deserialize(deserializer).map(Self)
            }
        }
    };
}

digest_newtype!(ConsolidationStatementIdV1);

/// Epistemic strength order used by the no-authority-promotion rule (CONS-03).
///
/// Consolidation output may not exceed the weakest source. Normative is
/// strongest and is additionally excluded from every output by policy shape:
/// derivation can never designate normativity (AUTH-04).
const fn modality_strength(modality: PropositionModalityV1) -> u8 {
    match modality {
        PropositionModalityV1::Intended => 0,
        PropositionModalityV1::Attested => 1,
        PropositionModalityV1::Observed => 2,
        PropositionModalityV1::Normative => 3,
    }
}

/// Declared conflict state of one source claim at derivation time.
///
/// In a statement this is a server-derived record. The repository seam must
/// re-audit it against the live conflict projection; a stale declared state
/// makes the whole statement stale (CONS-04, ACT-03). The fingerprint is the
/// discrepancy-family fingerprint contract owned by the episode workstream;
/// it remains an opaque digest here so this module does not depend on that
/// unlanded contract.
///
/// The seam's mapping from the six-state conflict lifecycle is total and
/// conservative: `open` and `acknowledged` map to `Open` (an unresolved
/// incompatibility is never launderable), `waived` maps to `Waived`, and
/// `resolved`, `dismissed`, and `superseded` map to `Clear` (no live
/// incompatibility remains).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ConsolidationSourceConflictStateV1 {
    Clear,
    Open { conflict_fingerprint: Sha256Digest },
    Waived { conflict_fingerprint: Sha256Digest },
}

impl ConsolidationSourceConflictStateV1 {
    fn validate(&self) -> ContractResult<()> {
        let fingerprint = match self {
            Self::Clear => return Ok(()),
            Self::Open {
                conflict_fingerprint,
            }
            | Self::Waived {
                conflict_fingerprint,
            } => conflict_fingerprint,
        };
        if *fingerprint == Sha256Digest::ZERO {
            return Err(ContractError::Schema(
                "conflict reference cannot use the zero digest".into(),
            ));
        }
        Ok(())
    }

    const fn conflict_fingerprint(&self) -> Option<&Sha256Digest> {
        match self {
            Self::Clear => None,
            Self::Open {
                conflict_fingerprint,
            }
            | Self::Waived {
                conflict_fingerprint,
            } => Some(conflict_fingerprint),
        }
    }
}

/// One exact source claim bound into a consolidation derivation.
///
/// Every field is server-derived in a statement: the repository seam loads
/// the live claim and records what it found. A request may assert only the
/// fingerprint and revision coordinate; see [`ConsolidationRequestV1`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsolidationSourceClaimV1 {
    pub claim_fingerprint: SemanticClaimFingerprintV2,
    pub claim_revision: u64,
    pub assertion_kind: RememberAssertionKindV2,
    pub modality: PropositionModalityV1,
    pub consolidation_depth: u32,
    pub conflict_state: ConsolidationSourceConflictStateV1,
    pub effective_interval: ClaimEffectiveIntervalV2,
}

impl ConsolidationSourceClaimV1 {
    fn validate(&self) -> ContractResult<()> {
        self.conflict_state.validate()?;
        validate_interval(&self.effective_interval)?;
        if self.claim_revision == 0
            || self.claim_fingerprint.digest() == Sha256Digest::ZERO
            || self.consolidation_depth > MAX_CONSOLIDATION_DEPTH
        {
            return Err(ContractError::Schema(
                "invalid consolidation source claim".into(),
            ));
        }
        encode_canonical(self)?;
        Ok(())
    }
}

/// Closed v1 rule for how source assertion kinds constrain the output kind.
///
/// The only admitted v1 rule requires every source to share one assertion
/// kind and keeps that kind for the output. Mixed-kind consolidation is
/// rejected rather than coerced (PRED-03); a mixing rule is a later policy
/// version with its own comparator lineage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ConsolidationKindRuleV1 {
    RequireUniform,
}

/// Policy behavior when any source is a member of an open or waived conflict.
///
/// A waived conflict is still an open incompatibility for this rule
/// (CONS-04): only the lifecycle state differs, and both states take the same
/// branch here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsolidationConflictBehaviorV1 {
    /// Refuse the derivation outright.
    FailClosed,
    /// Derive a disputed output that references every involved conflict.
    DeriveDisputed,
}

/// Versioned consolidation policy body (CONS-03, CONS-04, CONS-09).
///
/// This is registry-controlled configuration, not activation authority. The
/// fail-closed shape rules mean a policy cannot permit normative output,
/// unbounded source sets, or unbounded derivation depth no matter who authors
/// it; changing any field creates a new policy version and therefore a new
/// statement identity lineage (CONS-05).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsolidationPolicyV1 {
    pub schema_version: u32,
    pub policy_id: ContractId,
    pub version: u32,
    pub allowed_output_modalities: Vec<PropositionModalityV1>,
    pub max_sources: u32,
    pub max_consolidation_depth: u32,
    pub kind_rule: ConsolidationKindRuleV1,
    pub conflict_behavior: ConsolidationConflictBehaviorV1,
    pub supersede_sources: bool,
}

impl ConsolidationPolicyV1 {
    /// Validate canonical shape; this grants no activation authority.
    pub fn validate_shape(&self) -> ContractResult<()> {
        if self.schema_version != CONSOLIDATION_SCHEMA_VERSION
            || self.version == 0
            || self.allowed_output_modalities.is_empty()
            || !strictly_sorted(&self.allowed_output_modalities)
            || self
                .allowed_output_modalities
                .contains(&PropositionModalityV1::Normative)
            || self.max_sources < MIN_CONSOLIDATION_SOURCES
            || self.max_sources > MAX_CONSOLIDATION_SOURCES
            || self.max_consolidation_depth == 0
            || self.max_consolidation_depth > MAX_CONSOLIDATION_DEPTH
        {
            return Err(ContractError::Schema(
                "invalid consolidation policy v1".into(),
            ));
        }
        encode_canonical(self)?;
        Ok(())
    }
}

/// What the derivation emitted with respect to involved conflicts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ConsolidationOutputDispositionV1 {
    /// No source was a member of an open or waived conflict.
    DerivedActive,
    /// At least one source was conflicted; the output preserves the
    /// disagreement and references every involved conflict (CONS-04).
    DerivedDisputed {
        conflict_fingerprints: Vec<Sha256Digest>,
    },
}

impl ConsolidationOutputDispositionV1 {
    fn validate(&self) -> ContractResult<()> {
        if let Self::DerivedDisputed {
            conflict_fingerprints,
        } = self
            && (conflict_fingerprints.is_empty()
                || conflict_fingerprints.len() > MAX_CONFLICT_REFERENCES
                || !strictly_sorted(conflict_fingerprints)
                || conflict_fingerprints.contains(&Sha256Digest::ZERO))
        {
            return Err(ContractError::Schema(
                "invalid disputed-output conflict references".into(),
            ));
        }
        Ok(())
    }
}

/// Canonical consolidation derivation statement (CONS-02, CONS-05).
///
/// Every field is server-derived. The scope comes from the authenticated
/// context; the source records come from live claims at exact revisions; the
/// policy reference and digest come from the active registry; the output
/// fields are computed by the deterministic rules in
/// [`ConsolidationStatementV1::validate_derivation`]. The statement carries no
/// summary text and no summary digest: authored narrative is enrichment and
/// never enters derivation identity (CONS-05).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsolidationStatementV1 {
    pub schema_version: u32,
    pub profile: ProfileReferenceV1,
    pub scope: AuthenticatedProjectScopeV1,
    pub sources: Vec<ConsolidationSourceClaimV1>,
    pub consolidator_id: ContractId,
    pub consolidator_version: u32,
    pub policy: RegistryReferenceV1,
    pub policy_digest: Sha256Digest,
    pub output_kind: RememberAssertionKindV2,
    pub output_modality: PropositionModalityV1,
    pub output_depth: u32,
    pub effective_interval: ClaimEffectiveIntervalV2,
    pub disposition: ConsolidationOutputDispositionV1,
}

impl ConsolidationStatementV1 {
    /// Canonical statement bytes, the exact preimage of statement identity.
    ///
    /// Statement identity is `SHA-256("ostk-consolidation-statement-v1" ||
    /// 0x00 || canonical_bytes)`. The digest domain is accepted by the REG
    /// lane and lands with W0-REG; until it merges, no production identity
    /// constructor exists and these bytes are the complete semantic content.
    pub fn canonical_bytes(&self) -> ContractResult<Vec<u8>> {
        encode_canonical(self)
    }

    /// Validate canonical public shape only; this grants no derivation
    /// authority and does not evaluate the policy.
    pub fn validate_shape(&self) -> ContractResult<()> {
        // The statement identity preimage pins the exact frozen
        // canonicalization profile compiled into this binary; a statement
        // cannot mint a second identity by naming other profile digests
        // (CONS-05, REPLAY-01).
        self.profile.require_frozen_runtime_profile()?;
        self.policy.validate()?;
        validate_interval(&self.effective_interval)?;
        self.disposition.validate()?;
        if self.schema_version != CONSOLIDATION_SCHEMA_VERSION
            || self.policy_digest == Sha256Digest::ZERO
            || self.consolidator_version == 0
            || self.output_depth == 0
            || self.output_depth > MAX_CONSOLIDATION_DEPTH + 1
            || self.sources.len() < usize::try_from(MIN_CONSOLIDATION_SOURCES).unwrap_or(usize::MAX)
            || self.sources.len() > usize::try_from(MAX_CONSOLIDATION_SOURCES).unwrap_or(0)
            || !strictly_sorted_sources(&self.sources)
        {
            return Err(ContractError::Schema(
                "invalid consolidation statement v1".into(),
            ));
        }
        for source in &self.sources {
            source.validate()?;
        }
        encode_canonical(self)?;
        Ok(())
    }

    /// Evaluate the deterministic derivation rules against the exact policy
    /// body (CONS-02..05, CONS-09).
    ///
    /// This is still not admission authority: the repository seam must
    /// additionally prove that the policy is the active registry body for the
    /// scope, that every source record matches a live claim at the stated
    /// revision, that declared conflict states match the live conflict
    /// projection, and that the lineage graph stays acyclic when the new claim
    /// is linked.
    pub fn validate_derivation(&self, policy: &ConsolidationPolicyV1) -> ContractResult<()> {
        self.validate_shape()?;
        self.validate_policy_binding(policy)?;
        if self.sources.len() > usize::try_from(policy.max_sources).unwrap_or(0) {
            return Err(ContractError::Schema(
                "consolidation source set exceeds the policy bound".into(),
            ));
        }

        // CONS-03: uniform kind under the only admitted v1 rule, and no
        // authority promotion beyond the weakest source modality.
        let ConsolidationKindRuleV1::RequireUniform = policy.kind_rule;
        let uniform_kind = self.sources[0].assertion_kind;
        if self
            .sources
            .iter()
            .any(|source| source.assertion_kind != uniform_kind)
        {
            return Err(ContractError::Schema(
                "consolidation sources do not share one assertion kind".into(),
            ));
        }
        if self.output_kind != uniform_kind {
            return Err(ContractError::Schema(
                "consolidation output kind differs from the uniform source kind".into(),
            ));
        }
        if !policy
            .allowed_output_modalities
            .contains(&self.output_modality)
        {
            return Err(ContractError::Schema(
                "consolidation output modality is not policy-admitted".into(),
            ));
        }
        let weakest_source_strength = self
            .sources
            .iter()
            .map(|source| modality_strength(source.modality))
            .min()
            .unwrap_or(0);
        if modality_strength(self.output_modality) > weakest_source_strength {
            return Err(ContractError::Schema(
                "consolidation output modality exceeds the weakest source".into(),
            ));
        }

        // CONS-09: output depth is exactly deepest source plus one and stays
        // inside the policy bound, so derivation chains are finite.
        let deepest_source = self
            .sources
            .iter()
            .map(|source| source.consolidation_depth)
            .max()
            .unwrap_or(0);
        if deepest_source >= policy.max_consolidation_depth
            || self.output_depth != deepest_source.saturating_add(1)
        {
            return Err(ContractError::Schema(
                "invalid consolidation output depth".into(),
            ));
        }

        // The output interval is exactly the intersection of source
        // intervals; an empty intersection means the sources were never
        // co-valid and fails closed (PRED-03).
        let intersection = intersect_source_intervals(&self.sources)?;
        if intersection != self.effective_interval {
            return Err(ContractError::Schema(
                "consolidation interval is not the exact source intersection".into(),
            ));
        }

        // CONS-04: conflicted sources either fail closed or produce a
        // disputed output referencing exactly the involved conflicts.
        let mut involved: Vec<Sha256Digest> = self
            .sources
            .iter()
            .filter_map(|source| source.conflict_state.conflict_fingerprint().copied())
            .collect();
        involved.sort_unstable();
        involved.dedup();
        match (
            involved.is_empty(),
            policy.conflict_behavior,
            &self.disposition,
        ) {
            (true, _, ConsolidationOutputDispositionV1::DerivedActive) => {}
            (false, ConsolidationConflictBehaviorV1::FailClosed, _) => {
                return Err(ContractError::Schema(
                    "consolidation over conflicted sources fails closed".into(),
                ));
            }
            (
                false,
                ConsolidationConflictBehaviorV1::DeriveDisputed,
                ConsolidationOutputDispositionV1::DerivedDisputed {
                    conflict_fingerprints,
                },
            ) if *conflict_fingerprints == involved => {}
            _ => {
                return Err(ContractError::Schema(
                    "consolidation disposition does not preserve the involved conflicts".into(),
                ));
            }
        }
        Ok(())
    }

    /// Bind the statement to the exact supplied policy body: the reference
    /// must name the same entry and version, and `policy_digest` must
    /// recompute from the canonical policy bytes (CONS-02). The seam
    /// separately proves the reference is the active registry entry.
    fn validate_policy_binding(&self, policy: &ConsolidationPolicyV1) -> ContractResult<()> {
        policy.validate_shape()?;
        if policy.policy_id != self.policy.entry_id || policy.version != self.policy.version {
            return Err(ContractError::Schema(
                "consolidation policy does not match its registry reference".into(),
            ));
        }
        let recomputed_policy_digest = domain_separated_digest(
            DigestDomain::ConsolidationPolicyV1,
            &encode_canonical(policy)?,
        );
        if recomputed_policy_digest != self.policy_digest {
            return Err(ContractError::Schema(
                "consolidation policy digest does not commit to the supplied policy body".into(),
            ));
        }
        Ok(())
    }
}

/// Public, authority-free coordinate for one requested source claim.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsolidationSourceCoordinateV1 {
    pub claim_fingerprint: SemanticClaimFingerprintV2,
    pub claim_revision: u64,
}

/// Public, authority-free input to the deliberate consolidate boundary.
///
/// The source coordinates, policy reference, and requested output are
/// assertions only. Trusted runtime code must load the live claims, re-audit
/// every coordinate, resolve the active policy, compute the derivation, and
/// construct the statement from trusted state in one transaction. The summary
/// text is authored enrichment: it is bound server-side by the receipt and
/// never enters statement identity (CONS-05).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsolidationRequestV1 {
    pub schema_version: u32,
    pub asserted_sources: Vec<ConsolidationSourceCoordinateV1>,
    pub requested_policy: RegistryReferenceV1,
    pub requested_output_kind: RememberAssertionKindV2,
    pub requested_output_modality: PropositionModalityV1,
    pub summary_text: CanonicalAssertionTextV2,
}

impl ConsolidationRequestV1 {
    /// Validate canonical public shape only; this grants no authority.
    pub fn validate_shape(&self) -> ContractResult<()> {
        self.requested_policy.validate()?;
        if self.schema_version != CONSOLIDATION_SCHEMA_VERSION
            || self.asserted_sources.len()
                < usize::try_from(MIN_CONSOLIDATION_SOURCES).unwrap_or(usize::MAX)
            || self.asserted_sources.len() > usize::try_from(MAX_CONSOLIDATION_SOURCES).unwrap_or(0)
            || !strictly_sorted(
                &self
                    .asserted_sources
                    .iter()
                    .map(|source| source.claim_fingerprint)
                    .collect::<Vec<_>>(),
            )
            || self.asserted_sources.iter().any(|source| {
                source.claim_revision == 0
                    || source.claim_fingerprint.digest() == Sha256Digest::ZERO
            })
            || self.requested_output_modality == PropositionModalityV1::Normative
        {
            return Err(ContractError::Schema(
                "invalid consolidation request v1".into(),
            ));
        }
        encode_canonical(self)?;
        Ok(())
    }
}

/// Server derivation outcome recorded by the receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsolidationOutcomeV1 {
    /// A new derivative claim was emitted.
    Derived,
    /// The same sources under a new consolidator version produced an
    /// explicitly superseding derivation (CONS-05).
    Superseding,
    /// An exact replay of a previously accepted statement; no semantic
    /// effect (EVENT-01).
    NoOpReplay,
}

/// Server record binding one statement identity to its outcome.
///
/// The receipt is not identity authority: the statement identity it carries
/// is verified against the accepted event, and the summary enrichment digest
/// is bound here, server-side, precisely so that narrative bytes stay out of
/// derivation identity (CONS-05). The enrichment digest commits to the exact
/// authored summary bytes under the dedicated
/// `ostk-consolidation-summary-enrichment-v1` domain; see the module docs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsolidationReceiptV1 {
    pub schema_version: u32,
    pub statement_id: ConsolidationStatementIdV1,
    pub outcome: ConsolidationOutcomeV1,
    pub emitted_claim_fingerprint: SemanticClaimFingerprintV2,
    pub summary_enrichment_digest: Sha256Digest,
    pub accepted_event_ids: Vec<AcceptedEventId>,
}

impl ConsolidationReceiptV1 {
    /// Validate canonical shape only; the receipt proves nothing by itself.
    pub fn validate_shape(&self) -> ContractResult<()> {
        if self.schema_version != CONSOLIDATION_SCHEMA_VERSION
            || self.statement_id.digest() == Sha256Digest::ZERO
            || self.emitted_claim_fingerprint.digest() == Sha256Digest::ZERO
            || self.summary_enrichment_digest == Sha256Digest::ZERO
            || self.accepted_event_ids.is_empty()
            || self.accepted_event_ids.len() > MAX_ACCEPTED_EVENT_IDS
            || !strictly_sorted(&self.accepted_event_ids)
            || self
                .accepted_event_ids
                .iter()
                .any(|event_id| event_id.digest() == Sha256Digest::ZERO)
        {
            return Err(ContractError::Schema(
                "invalid consolidation receipt v1".into(),
            ));
        }
        encode_canonical(self)?;
        Ok(())
    }
}

fn validate_interval(interval: &ClaimEffectiveIntervalV2) -> ContractResult<()> {
    if !interval.effective_from.is_microsecond_aligned()
        || interval.effective_until.as_ref().is_some_and(|until| {
            !until.is_microsecond_aligned() || until <= &interval.effective_from
        })
    {
        return Err(ContractError::Schema(
            "invalid consolidation effective interval".into(),
        ));
    }
    Ok(())
}

/// The output interval is exactly the intersection of the source intervals:
/// the latest start, and the earliest end among bounded sources; the result
/// is open-ended only when every source is open-ended. An empty intersection
/// fails closed (PRED-03).
fn intersect_source_intervals(
    sources: &[ConsolidationSourceClaimV1],
) -> ContractResult<ClaimEffectiveIntervalV2> {
    let Some((first, rest)) = sources.split_first() else {
        return Err(ContractError::Schema(
            "consolidation requires at least one source".into(),
        ));
    };
    let mut effective_from = first.effective_interval.effective_from.clone();
    let mut earliest_until = first.effective_interval.effective_until.clone();
    for source in rest {
        if source.effective_interval.effective_from > effective_from {
            effective_from = source.effective_interval.effective_from.clone();
        }
        // An open-ended source does not constrain the intersection end; the
        // result is open-ended only when every source is open-ended.
        if let Some(candidate) = &source.effective_interval.effective_until {
            earliest_until = Some(match &earliest_until {
                Some(current) if current <= candidate => current.clone(),
                _ => candidate.clone(),
            });
        }
    }
    let intersection = ClaimEffectiveIntervalV2 {
        effective_from,
        effective_until: earliest_until,
    };
    validate_interval(&intersection)?;
    Ok(intersection)
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values
        .iter()
        .zip(values.iter().skip(1))
        .all(|(left, right)| left < right)
}

/// Source claims are strictly ordered and unique by fingerprint alone: one
/// claim at two revisions can never satisfy the two-source minimum, which
/// would be self-consolidation (CONS-01/02/09).
fn strictly_sorted_sources(sources: &[ConsolidationSourceClaimV1]) -> bool {
    strictly_sorted(
        &sources
            .iter()
            .map(|source| source.claim_fingerprint)
            .collect::<Vec<_>>(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory_contracts::{
        canonical::{decode_strict, require_canonical},
        common::{CanonicalTimestamp, frozen_profile_reference_v1},
    };
    use sha2::{Digest as _, Sha256};

    const POLICY_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/consolidation/consolidation-policy-v1.jsonl"
    );
    const STATEMENT_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/consolidation/consolidation-statement-v1.jsonl"
    );
    const REQUEST_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/consolidation/consolidation-request-v1.jsonl"
    );
    const RECEIPT_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/consolidation/consolidation-receipt-v1.jsonl"
    );
    const DISPUTED_STATEMENT_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/consolidation/consolidation-disputed-statement-v1.jsonl"
    );
    const NEGATIVE_SINGLE_SOURCE_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/consolidation/negative-single-source.jsonl"
    );
    const NEGATIVE_UNSORTED_SOURCES_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/consolidation/negative-unsorted-sources.jsonl"
    );
    const NEGATIVE_KIND_MIXING_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/consolidation/negative-kind-mixing.jsonl"
    );
    const NEGATIVE_MODALITY_PROMOTION_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/consolidation/negative-modality-promotion.jsonl"
    );
    const NEGATIVE_NORMATIVE_OUTPUT_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/consolidation/negative-normative-output.jsonl"
    );
    const NEGATIVE_DEPTH_EXCEEDED_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/consolidation/negative-depth-exceeded.jsonl"
    );
    const NEGATIVE_CONFLICT_LAUNDERING_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/consolidation/negative-conflict-laundering.jsonl"
    );
    const NEGATIVE_DISPUTED_WITHOUT_REFS_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/consolidation/negative-disputed-without-refs.jsonl"
    );
    const NEGATIVE_EMPTY_INTERVAL_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/consolidation/negative-empty-interval.jsonl"
    );
    const NEGATIVE_REQUEST_AUTHORITY_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/consolidation/negative-request-authority-fields.jsonl"
    );
    const NEGATIVE_PROFILE_DIGEST_SPOOF_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/consolidation/negative-profile-digest-spoof.jsonl"
    );
    const NEGATIVE_DUPLICATE_SOURCE_CLAIM_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/consolidation/negative-duplicate-source-claim.jsonl"
    );
    const NEGATIVE_DISPUTED_REF_MISMATCH_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/consolidation/negative-disputed-ref-mismatch.jsonl"
    );
    const NEGATIVE_DISPUTED_REFS_UNSORTED_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/consolidation/negative-disputed-refs-unsorted.jsonl"
    );
    const NEGATIVE_MODALITY_NOT_POLICY_ADMITTED_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/consolidation/negative-modality-not-policy-admitted.jsonl"
    );
    const NEGATIVE_POLICY_DIGEST_MISMATCH_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/consolidation/negative-policy-digest-mismatch.jsonl"
    );
    const VECTOR_SUITE_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v3/consolidation/vector-suite.jsonl");

    // SHA-256 of the exact fixture file bytes, including the trailing LF.
    // These pins make every fixture byte-for-byte immutable: any edit that is
    // not reflected here, in the suite manifest, and in the digest-bearing
    // fixtures fails the suite test.
    const POLICY_RAW_SHA256: &str =
        "2da697c8fadba3735f42ff6b0d0154afff9dfb2fc7e1f338d4c300c3af0e29c3";
    const STATEMENT_RAW_SHA256: &str =
        "dc9eff9ed0df8561e73d5735eea674b11f478b83806fe708edcd13fe90e78971";
    const DISPUTED_STATEMENT_RAW_SHA256: &str =
        "5e291f7790006a24c6e2feed7cd061fc74e0d5fda3535d907679f40c0dca5068";
    const REQUEST_RAW_SHA256: &str =
        "34d58029deab8d1d63699c9e407ed4df33fa43df0e5305a9c0b57d3a43c5820f";
    const RECEIPT_RAW_SHA256: &str =
        "77d6ca1e45c52ba5dc24ebd0f0e3ee485e0922b8b01ebe56c6acabf86840f5f7";
    const NEGATIVE_SINGLE_SOURCE_RAW_SHA256: &str =
        "c191dee52bc2a7af0c537097d463f68c00876cdece48ddf07a37b2327cc7691b";
    const NEGATIVE_UNSORTED_SOURCES_RAW_SHA256: &str =
        "8bd0ec489baf574890aa952fad9cd0391fde36562d4931a932f4beff719a6917";
    const NEGATIVE_KIND_MIXING_RAW_SHA256: &str =
        "817c73db6ad64ba98253e2922fd262567480a057c804266e49bd612f57a48fe3";
    const NEGATIVE_MODALITY_PROMOTION_RAW_SHA256: &str =
        "3d7c75550138d7a8aa4cd0b67cd575add718f9d0cdff9b50ab1ba3120f427e5c";
    const NEGATIVE_NORMATIVE_OUTPUT_RAW_SHA256: &str =
        "a2f9b11924fdad905b5095914c4671aa44d0ded9280603ff688cb586cbe8f280";
    const NEGATIVE_DEPTH_EXCEEDED_RAW_SHA256: &str =
        "ca9190d9d954ab0479dd4c4d0d443dfc2bf9e159b90958a835ee862a6972cea7";
    const NEGATIVE_CONFLICT_LAUNDERING_RAW_SHA256: &str =
        "80f25d58073f3f1aafd4138b20b8f878ad82a3891f2efb994d75fbfcf9db0012";
    const NEGATIVE_DISPUTED_WITHOUT_REFS_RAW_SHA256: &str =
        "01c7b223d18aebe4cc438f99cba603a145171ad93776db3d8d4457a61f67afdf";
    const NEGATIVE_EMPTY_INTERVAL_RAW_SHA256: &str =
        "7b23b2fe7a1a91fa27f7d35a6c5ed8c6c79fe3cf7bbd658b91cfadeaebccfbf0";
    const NEGATIVE_REQUEST_AUTHORITY_RAW_SHA256: &str =
        "68923c17059f163cdc0af30a9fe97da5af25ed55f6afcc6cdd606e6d3b44675a";
    const NEGATIVE_PROFILE_DIGEST_SPOOF_RAW_SHA256: &str =
        "fb43deb5f6bc85e419d1d7ada7872dd0fb0d45f81d37561684a041b924f7f697";
    const NEGATIVE_DUPLICATE_SOURCE_CLAIM_RAW_SHA256: &str =
        "84737fe473ce230f8ecef54bbb8139ba7b5e9e98eec430940ca170196b38b36e";
    const NEGATIVE_DISPUTED_REF_MISMATCH_RAW_SHA256: &str =
        "a18fea1caf6e81393e2687e941dd13ec44c78bd287e6179969d06abc84d7318d";
    const NEGATIVE_DISPUTED_REFS_UNSORTED_RAW_SHA256: &str =
        "9e82096d8ba0b226c61f692e30b7e7b43b9491b7ba674fa21da2e10aab8b8731";
    const NEGATIVE_MODALITY_NOT_POLICY_ADMITTED_RAW_SHA256: &str =
        "fd2d8820692ad41816949040c1d9dbc0bdea9765de173009ee4d3a2fc2be0d80";
    const NEGATIVE_POLICY_DIGEST_MISMATCH_RAW_SHA256: &str =
        "7138f4ace88e25750277b762b22630d7c56b4894441a8d85fcf3394c15e6b366";
    const VECTOR_SUITE_RAW_SHA256: &str =
        "b1a33cdb6c1e3c8543ebd077e0cce0abe536357f35cee7c84be337a67f427773";

    /// Statement identity minted over the canonical statement bytes under the
    /// accepted W0-REG `ostk-consolidation-statement-v1` domain prefix. The
    /// recompute lands with the W0-REG merge; until then the value is pinned
    /// here and threaded through the receipt fixture.
    const STATEMENT_IDENTITY_V1: &str = "42cecb6a5bc67d24f8984121951327548ab3d48327d9ba0bbca2245f81b0dc6b; ostk-consolidation-statement-v1 over the canonical statement bytes";

    /// Typed decode of `vector-suite.jsonl`; `deny_unknown_fields` makes the
    /// manifest itself part of the pinned surface.
    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ConsolidationVectorSuiteV1 {
        schema_version: u32,
        digest_convention: String,
        fixture_authority: String,
        statement_identity: String,
        policy_digest: String,
        statement_digest: String,
        disputed_statement_digest: String,
        request_digest: String,
        receipt_digest: String,
        negative_case_digests: NegativeCaseDigestsV1,
        negative_cases: Vec<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct NegativeCaseDigestsV1 {
        conflict_laundering: String,
        depth_exceeded: String,
        disputed_ref_mismatch: String,
        disputed_refs_unsorted: String,
        disputed_without_refs: String,
        duplicate_source_claim: String,
        empty_interval: String,
        kind_mixing: String,
        modality_not_policy_admitted: String,
        modality_promotion: String,
        normative_output: String,
        policy_digest_mismatch: String,
        profile_digest_spoof: String,
        request_authority_fields: String,
        single_source: String,
        unsorted_sources: String,
    }

    fn raw_sha256(bytes: &[u8]) -> String {
        let mut hash = Sha256::new();
        hash.update(bytes);
        Sha256Digest::from_bytes(hash.finalize().into()).to_hex()
    }

    fn fixture_bytes(fixture: &[u8]) -> &[u8] {
        fixture
            .strip_suffix(b"\n")
            .expect("fixture files end with exactly one LF")
    }

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([byte; 32])
    }

    fn timestamp(text: &str) -> CanonicalTimestamp {
        CanonicalTimestamp::parse(text).expect("valid canonical timestamp")
    }

    fn interval(from: &str, until: Option<&str>) -> ClaimEffectiveIntervalV2 {
        ClaimEffectiveIntervalV2 {
            effective_from: timestamp(from),
            effective_until: until.map(timestamp),
        }
    }

    fn source(
        byte: u8,
        revision: u64,
        kind: RememberAssertionKindV2,
        modality: PropositionModalityV1,
        depth: u32,
        conflict_state: ConsolidationSourceConflictStateV1,
        effective_interval: ClaimEffectiveIntervalV2,
    ) -> ConsolidationSourceClaimV1 {
        ConsolidationSourceClaimV1 {
            claim_fingerprint: SemanticClaimFingerprintV2::from_digest(digest(byte)),
            claim_revision: revision,
            assertion_kind: kind,
            modality,
            consolidation_depth: depth,
            conflict_state,
            effective_interval,
        }
    }

    fn clear_source(
        byte: u8,
        depth: u32,
        effective_interval: ClaimEffectiveIntervalV2,
    ) -> ConsolidationSourceClaimV1 {
        source(
            byte,
            1,
            RememberAssertionKindV2::Fact,
            PropositionModalityV1::Observed,
            depth,
            ConsolidationSourceConflictStateV1::Clear,
            effective_interval,
        )
    }

    fn policy(conflict_behavior: ConsolidationConflictBehaviorV1) -> ConsolidationPolicyV1 {
        ConsolidationPolicyV1 {
            schema_version: CONSOLIDATION_SCHEMA_VERSION,
            policy_id: ContractId::new("consolidation.default").expect("valid policy id"),
            version: 1,
            allowed_output_modalities: vec![
                PropositionModalityV1::Attested,
                PropositionModalityV1::Intended,
                PropositionModalityV1::Observed,
            ],
            max_sources: 16,
            max_consolidation_depth: 4,
            kind_rule: ConsolidationKindRuleV1::RequireUniform,
            conflict_behavior,
            supersede_sources: true,
        }
    }

    fn policy_reference() -> RegistryReferenceV1 {
        RegistryReferenceV1 {
            entry_id: ContractId::new("consolidation.default").expect("valid policy id"),
            version: 1,
            entry_digest: digest(0x0a),
        }
    }

    /// Bind a helper-built statement to the exact policy body the test will
    /// validate against, mirroring the real policy digest commitment.
    fn bind_policy_digest(
        statement: &mut ConsolidationStatementV1,
        policy: &ConsolidationPolicyV1,
    ) {
        statement.policy_digest = domain_separated_digest(
            DigestDomain::ConsolidationPolicyV1,
            &encode_canonical(policy).expect("encode policy"),
        );
    }

    fn scope() -> AuthenticatedProjectScopeV1 {
        AuthenticatedProjectScopeV1::from_trusted_context(
            ContractId::new("tenant.fixture").expect("valid tenant"),
            ContractId::new("project.fixture").expect("valid project"),
        )
    }

    fn statement(
        sources: Vec<ConsolidationSourceClaimV1>,
        output_modality: PropositionModalityV1,
        output_depth: u32,
        effective_interval: ClaimEffectiveIntervalV2,
        disposition: ConsolidationOutputDispositionV1,
    ) -> ConsolidationStatementV1 {
        ConsolidationStatementV1 {
            schema_version: CONSOLIDATION_SCHEMA_VERSION,
            profile: frozen_profile_reference_v1(),
            scope: scope(),
            sources,
            consolidator_id: ContractId::new("consolidator.reference")
                .expect("valid consolidator id"),
            consolidator_version: 1,
            policy: policy_reference(),
            policy_digest: digest(0x0b),
            output_kind: RememberAssertionKindV2::Fact,
            output_modality,
            output_depth,
            effective_interval,
            disposition,
        }
    }

    fn valid_statement() -> ConsolidationStatementV1 {
        statement(
            vec![
                clear_source(0x11, 0, interval("2026-08-01T00:00:00.000000000Z", None)),
                clear_source(
                    0x12,
                    1,
                    interval(
                        "2026-08-05T00:00:00.000000000Z",
                        Some("2026-08-10T00:00:00.000000000Z"),
                    ),
                ),
            ],
            PropositionModalityV1::Observed,
            2,
            interval(
                "2026-08-05T00:00:00.000000000Z",
                Some("2026-08-10T00:00:00.000000000Z"),
            ),
            ConsolidationOutputDispositionV1::DerivedActive,
        )
    }

    #[test]
    fn valid_statement_passes_shape_and_derivation() {
        let mut statement = valid_statement();
        statement.validate_shape().expect("shape");
        let policy = policy(ConsolidationConflictBehaviorV1::FailClosed);
        bind_policy_digest(&mut statement, &policy);
        statement.validate_derivation(&policy).expect("derivation");
        let bytes = statement.canonical_bytes().expect("canonical bytes");
        let decoded: ConsolidationStatementV1 = decode_strict(&bytes).expect("round trip");
        assert_eq!(decoded, statement);
    }

    #[test]
    fn source_set_requires_two_or_more_and_strict_order() {
        let mut statement = valid_statement();
        statement.sources.truncate(1);
        assert!(statement.validate_shape().is_err());

        let mut statement = valid_statement();
        statement.sources.reverse();
        assert!(statement.validate_shape().is_err());

        let mut statement = valid_statement();
        statement.sources.push(statement.sources[1].clone());
        assert!(statement.validate_shape().is_err());
    }

    #[test]
    fn output_kind_must_match_the_uniform_source_kind() {
        let policy = policy(ConsolidationConflictBehaviorV1::FailClosed);

        let mut statement = valid_statement();
        statement.sources[1].assertion_kind = RememberAssertionKindV2::Decision;
        bind_policy_digest(&mut statement, &policy);
        assert!(statement.validate_derivation(&policy).is_err());

        let mut statement = valid_statement();
        statement.output_kind = RememberAssertionKindV2::Decision;
        bind_policy_digest(&mut statement, &policy);
        assert!(statement.validate_derivation(&policy).is_err());
    }

    #[test]
    fn output_modality_never_exceeds_the_weakest_source() {
        let policy = policy(ConsolidationConflictBehaviorV1::FailClosed);

        let mut statement = valid_statement();
        statement.sources[1].modality = PropositionModalityV1::Attested;
        bind_policy_digest(&mut statement, &policy);
        assert!(statement.validate_derivation(&policy).is_err());

        let mut demoted = valid_statement();
        demoted.sources[1].modality = PropositionModalityV1::Attested;
        demoted.output_modality = PropositionModalityV1::Attested;
        bind_policy_digest(&mut demoted, &policy);
        demoted
            .validate_derivation(&policy)
            .expect("weakened output is admitted");
    }

    #[test]
    fn policy_never_admits_normative_output() {
        let mut policy = policy(ConsolidationConflictBehaviorV1::FailClosed);
        policy
            .allowed_output_modalities
            .push(PropositionModalityV1::Normative);
        assert!(policy.validate_shape().is_err());
    }

    #[test]
    fn derivation_depth_is_bounded_and_exact() {
        let policy = policy(ConsolidationConflictBehaviorV1::FailClosed);

        let mut statement = valid_statement();
        statement.output_depth = 1;
        bind_policy_digest(&mut statement, &policy);
        assert!(statement.validate_derivation(&policy).is_err());

        let mut statement = valid_statement();
        statement.sources[1].consolidation_depth = 4;
        statement.output_depth = 5;
        bind_policy_digest(&mut statement, &policy);
        assert!(statement.validate_derivation(&policy).is_err());
    }

    #[test]
    fn interval_is_the_exact_intersection_and_empty_fails_closed() {
        let policy = policy(ConsolidationConflictBehaviorV1::FailClosed);

        let mut statement = valid_statement();
        statement.effective_interval = interval("2026-08-05T00:00:00.000000000Z", None);
        bind_policy_digest(&mut statement, &policy);
        assert!(statement.validate_derivation(&policy).is_err());

        let mut statement = valid_statement();
        statement.sources[0].effective_interval = interval(
            "2026-08-01T00:00:00.000000000Z",
            Some("2026-08-10T00:00:00.000000000Z"),
        );
        statement.sources[1].effective_interval = interval(
            "2026-08-20T00:00:00.000000000Z",
            Some("2026-08-21T00:00:00.000000000Z"),
        );
        statement.effective_interval = interval(
            "2026-08-20T00:00:00.000000000Z",
            Some("2026-08-21T00:00:00.000000000Z"),
        );
        bind_policy_digest(&mut statement, &policy);
        assert!(statement.validate_derivation(&policy).is_err());
    }

    #[test]
    fn conflicted_sources_fail_closed_or_derive_disputed() {
        let conflicted = || {
            source(
                0x13,
                1,
                RememberAssertionKindV2::Fact,
                PropositionModalityV1::Observed,
                0,
                ConsolidationSourceConflictStateV1::Waived {
                    conflict_fingerprint: digest(0xcc),
                },
                interval("2026-08-05T00:00:00.000000000Z", None),
            )
        };

        let mut laundering = statement(
            vec![
                clear_source(0x11, 0, interval("2026-08-01T00:00:00.000000000Z", None)),
                conflicted(),
            ],
            PropositionModalityV1::Observed,
            1,
            interval("2026-08-05T00:00:00.000000000Z", None),
            ConsolidationOutputDispositionV1::DerivedActive,
        );
        let fail_closed = policy(ConsolidationConflictBehaviorV1::FailClosed);
        bind_policy_digest(&mut laundering, &fail_closed);
        assert!(laundering.validate_derivation(&fail_closed).is_err());
        let derive_disputed = policy(ConsolidationConflictBehaviorV1::DeriveDisputed);
        bind_policy_digest(&mut laundering, &derive_disputed);
        assert!(laundering.validate_derivation(&derive_disputed).is_err());

        let mut disputed = statement(
            vec![
                clear_source(0x11, 0, interval("2026-08-01T00:00:00.000000000Z", None)),
                conflicted(),
            ],
            PropositionModalityV1::Observed,
            1,
            interval("2026-08-05T00:00:00.000000000Z", None),
            ConsolidationOutputDispositionV1::DerivedDisputed {
                conflict_fingerprints: vec![digest(0xcc)],
            },
        );
        bind_policy_digest(&mut disputed, &derive_disputed);
        disputed
            .validate_derivation(&derive_disputed)
            .expect("disputed output preserves the waived conflict");
    }

    #[test]
    fn request_is_authority_free_and_never_normative() {
        let request = ConsolidationRequestV1 {
            schema_version: CONSOLIDATION_SCHEMA_VERSION,
            asserted_sources: vec![
                ConsolidationSourceCoordinateV1 {
                    claim_fingerprint: SemanticClaimFingerprintV2::from_digest(digest(0x11)),
                    claim_revision: 1,
                },
                ConsolidationSourceCoordinateV1 {
                    claim_fingerprint: SemanticClaimFingerprintV2::from_digest(digest(0x12)),
                    claim_revision: 3,
                },
            ],
            requested_policy: policy_reference(),
            requested_output_kind: RememberAssertionKindV2::Fact,
            requested_output_modality: PropositionModalityV1::Observed,
            summary_text: CanonicalAssertionTextV2::parse("condensed narrative")
                .expect("valid summary text"),
        };
        request.validate_shape().expect("valid request");

        let mut normative = request;
        normative.requested_output_modality = PropositionModalityV1::Normative;
        assert!(normative.validate_shape().is_err());
    }

    #[test]
    fn positive_fixtures_are_canonical_and_valid() {
        let policy_bytes = fixture_bytes(POLICY_FIXTURE);
        require_canonical(policy_bytes).expect("policy fixture is canonical");
        let policy: ConsolidationPolicyV1 = decode_strict(policy_bytes).expect("decode policy");
        policy.validate_shape().expect("policy validates");

        let statement_bytes = fixture_bytes(STATEMENT_FIXTURE);
        require_canonical(statement_bytes).expect("statement fixture is canonical");
        let statement: ConsolidationStatementV1 =
            decode_strict(statement_bytes).expect("decode statement");
        statement
            .validate_derivation(&policy)
            .expect("statement derives under the fixture policy");

        let disputed_bytes = fixture_bytes(DISPUTED_STATEMENT_FIXTURE);
        require_canonical(disputed_bytes).expect("disputed fixture is canonical");
        let disputed: ConsolidationStatementV1 =
            decode_strict(disputed_bytes).expect("decode disputed statement");
        disputed
            .validate_derivation(&policy)
            .expect("disputed statement derives under the fixture policy");

        let request_bytes = fixture_bytes(REQUEST_FIXTURE);
        require_canonical(request_bytes).expect("request fixture is canonical");
        let request: ConsolidationRequestV1 = decode_strict(request_bytes).expect("decode request");
        request.validate_shape().expect("request validates");

        let receipt_bytes = fixture_bytes(RECEIPT_FIXTURE);
        require_canonical(receipt_bytes).expect("receipt fixture is canonical");
        let receipt: ConsolidationReceiptV1 = decode_strict(receipt_bytes).expect("decode receipt");
        receipt.validate_shape().expect("receipt validates");
    }

    #[test]
    fn negative_fixtures_fail_closed() {
        let negative_statements: [(&[u8], &str); 15] = [
            (NEGATIVE_SINGLE_SOURCE_FIXTURE, "single source"),
            (NEGATIVE_UNSORTED_SOURCES_FIXTURE, "unsorted sources"),
            (NEGATIVE_KIND_MIXING_FIXTURE, "kind mixing"),
            (NEGATIVE_MODALITY_PROMOTION_FIXTURE, "modality promotion"),
            (NEGATIVE_DEPTH_EXCEEDED_FIXTURE, "depth exceeded"),
            (NEGATIVE_CONFLICT_LAUNDERING_FIXTURE, "conflict laundering"),
            (
                NEGATIVE_DISPUTED_WITHOUT_REFS_FIXTURE,
                "disputed without refs",
            ),
            (NEGATIVE_EMPTY_INTERVAL_FIXTURE, "empty interval"),
            (NEGATIVE_NORMATIVE_OUTPUT_FIXTURE, "normative output"),
            (
                NEGATIVE_PROFILE_DIGEST_SPOOF_FIXTURE,
                "profile digest spoof",
            ),
            (
                NEGATIVE_DUPLICATE_SOURCE_CLAIM_FIXTURE,
                "duplicate source claim",
            ),
            (
                NEGATIVE_DISPUTED_REF_MISMATCH_FIXTURE,
                "disputed ref mismatch",
            ),
            (
                NEGATIVE_DISPUTED_REFS_UNSORTED_FIXTURE,
                "disputed refs unsorted",
            ),
            (
                NEGATIVE_MODALITY_NOT_POLICY_ADMITTED_FIXTURE,
                "modality not policy-admitted",
            ),
            (
                NEGATIVE_POLICY_DIGEST_MISMATCH_FIXTURE,
                "policy digest mismatch",
            ),
        ];
        let policy_bytes = fixture_bytes(POLICY_FIXTURE);
        let policy: ConsolidationPolicyV1 = decode_strict(policy_bytes).expect("decode policy");
        for (fixture, case) in negative_statements {
            let bytes = fixture_bytes(fixture);
            if case == "normative output" {
                let decoded: ConsolidationPolicyV1 =
                    decode_strict(bytes).expect("decode normative policy");
                assert!(
                    decoded.validate_shape().is_err(),
                    "negative case {case} must fail shape validation"
                );
                continue;
            }
            let decoded: ConsolidationStatementV1 =
                decode_strict(bytes).expect("decode negative statement");
            assert!(
                decoded.validate_derivation(&policy).is_err(),
                "negative case {case} must fail derivation"
            );
        }

        let request_bytes = fixture_bytes(NEGATIVE_REQUEST_AUTHORITY_FIXTURE);
        assert!(
            decode_strict::<ConsolidationRequestV1>(request_bytes).is_err(),
            "a request carrying authority fields must fail closed"
        );
    }

    #[test]
    fn vector_suite_manifest_is_canonical() {
        require_canonical(fixture_bytes(VECTOR_SUITE_FIXTURE))
            .expect("vector suite manifest is canonical");
    }

    #[test]
    #[allow(clippy::too_many_lines)] // one pin table freezes every fixture byte hash
    fn vector_suite_manifest_pins_every_fixture_digest() {
        let suite: ConsolidationVectorSuiteV1 =
            serde_json::from_slice(fixture_bytes(VECTOR_SUITE_FIXTURE))
                .expect("typed suite decode");
        assert_eq!(suite.schema_version, 1);
        assert_eq!(
            suite.digest_convention,
            "sha256 of the exact fixture file bytes including the trailing LF"
        );
        assert_eq!(
            suite.fixture_authority,
            "none; structural fixtures are assertions, not active-policy or derivation witnesses"
        );
        assert_eq!(suite.statement_identity, STATEMENT_IDENTITY_V1);

        let positives: [(&str, &[u8], &str, &str); 5] = [
            (
                "consolidation-policy-v1.jsonl",
                POLICY_FIXTURE,
                POLICY_RAW_SHA256,
                suite.policy_digest.as_str(),
            ),
            (
                "consolidation-statement-v1.jsonl",
                STATEMENT_FIXTURE,
                STATEMENT_RAW_SHA256,
                suite.statement_digest.as_str(),
            ),
            (
                "consolidation-disputed-statement-v1.jsonl",
                DISPUTED_STATEMENT_FIXTURE,
                DISPUTED_STATEMENT_RAW_SHA256,
                suite.disputed_statement_digest.as_str(),
            ),
            (
                "consolidation-request-v1.jsonl",
                REQUEST_FIXTURE,
                REQUEST_RAW_SHA256,
                suite.request_digest.as_str(),
            ),
            (
                "consolidation-receipt-v1.jsonl",
                RECEIPT_FIXTURE,
                RECEIPT_RAW_SHA256,
                suite.receipt_digest.as_str(),
            ),
        ];
        let negatives: [(&str, &[u8], &str, &str); 16] = [
            (
                "negative-conflict-laundering.jsonl",
                NEGATIVE_CONFLICT_LAUNDERING_FIXTURE,
                NEGATIVE_CONFLICT_LAUNDERING_RAW_SHA256,
                suite.negative_case_digests.conflict_laundering.as_str(),
            ),
            (
                "negative-depth-exceeded.jsonl",
                NEGATIVE_DEPTH_EXCEEDED_FIXTURE,
                NEGATIVE_DEPTH_EXCEEDED_RAW_SHA256,
                suite.negative_case_digests.depth_exceeded.as_str(),
            ),
            (
                "negative-disputed-ref-mismatch.jsonl",
                NEGATIVE_DISPUTED_REF_MISMATCH_FIXTURE,
                NEGATIVE_DISPUTED_REF_MISMATCH_RAW_SHA256,
                suite.negative_case_digests.disputed_ref_mismatch.as_str(),
            ),
            (
                "negative-disputed-refs-unsorted.jsonl",
                NEGATIVE_DISPUTED_REFS_UNSORTED_FIXTURE,
                NEGATIVE_DISPUTED_REFS_UNSORTED_RAW_SHA256,
                suite.negative_case_digests.disputed_refs_unsorted.as_str(),
            ),
            (
                "negative-disputed-without-refs.jsonl",
                NEGATIVE_DISPUTED_WITHOUT_REFS_FIXTURE,
                NEGATIVE_DISPUTED_WITHOUT_REFS_RAW_SHA256,
                suite.negative_case_digests.disputed_without_refs.as_str(),
            ),
            (
                "negative-duplicate-source-claim.jsonl",
                NEGATIVE_DUPLICATE_SOURCE_CLAIM_FIXTURE,
                NEGATIVE_DUPLICATE_SOURCE_CLAIM_RAW_SHA256,
                suite.negative_case_digests.duplicate_source_claim.as_str(),
            ),
            (
                "negative-empty-interval.jsonl",
                NEGATIVE_EMPTY_INTERVAL_FIXTURE,
                NEGATIVE_EMPTY_INTERVAL_RAW_SHA256,
                suite.negative_case_digests.empty_interval.as_str(),
            ),
            (
                "negative-kind-mixing.jsonl",
                NEGATIVE_KIND_MIXING_FIXTURE,
                NEGATIVE_KIND_MIXING_RAW_SHA256,
                suite.negative_case_digests.kind_mixing.as_str(),
            ),
            (
                "negative-modality-not-policy-admitted.jsonl",
                NEGATIVE_MODALITY_NOT_POLICY_ADMITTED_FIXTURE,
                NEGATIVE_MODALITY_NOT_POLICY_ADMITTED_RAW_SHA256,
                suite
                    .negative_case_digests
                    .modality_not_policy_admitted
                    .as_str(),
            ),
            (
                "negative-modality-promotion.jsonl",
                NEGATIVE_MODALITY_PROMOTION_FIXTURE,
                NEGATIVE_MODALITY_PROMOTION_RAW_SHA256,
                suite.negative_case_digests.modality_promotion.as_str(),
            ),
            (
                "negative-normative-output.jsonl",
                NEGATIVE_NORMATIVE_OUTPUT_FIXTURE,
                NEGATIVE_NORMATIVE_OUTPUT_RAW_SHA256,
                suite.negative_case_digests.normative_output.as_str(),
            ),
            (
                "negative-policy-digest-mismatch.jsonl",
                NEGATIVE_POLICY_DIGEST_MISMATCH_FIXTURE,
                NEGATIVE_POLICY_DIGEST_MISMATCH_RAW_SHA256,
                suite.negative_case_digests.policy_digest_mismatch.as_str(),
            ),
            (
                "negative-profile-digest-spoof.jsonl",
                NEGATIVE_PROFILE_DIGEST_SPOOF_FIXTURE,
                NEGATIVE_PROFILE_DIGEST_SPOOF_RAW_SHA256,
                suite.negative_case_digests.profile_digest_spoof.as_str(),
            ),
            (
                "negative-request-authority-fields.jsonl",
                NEGATIVE_REQUEST_AUTHORITY_FIXTURE,
                NEGATIVE_REQUEST_AUTHORITY_RAW_SHA256,
                suite
                    .negative_case_digests
                    .request_authority_fields
                    .as_str(),
            ),
            (
                "negative-single-source.jsonl",
                NEGATIVE_SINGLE_SOURCE_FIXTURE,
                NEGATIVE_SINGLE_SOURCE_RAW_SHA256,
                suite.negative_case_digests.single_source.as_str(),
            ),
            (
                "negative-unsorted-sources.jsonl",
                NEGATIVE_UNSORTED_SOURCES_FIXTURE,
                NEGATIVE_UNSORTED_SOURCES_RAW_SHA256,
                suite.negative_case_digests.unsorted_sources.as_str(),
            ),
        ];
        for (name, bytes, pinned, manifest) in positives.into_iter().chain(negatives) {
            let recomputed = raw_sha256(bytes);
            assert_eq!(
                recomputed, pinned,
                "{name}: rust pin drifted from the fixture bytes"
            );
            assert_eq!(
                recomputed, manifest,
                "{name}: suite manifest digest drifted from the fixture bytes"
            );
        }
        assert_eq!(
            raw_sha256(VECTOR_SUITE_FIXTURE),
            VECTOR_SUITE_RAW_SHA256,
            "suite manifest self-pin drifted"
        );
        assert_eq!(
            suite.negative_cases,
            [
                "conflict_laundering",
                "depth_exceeded",
                "disputed_ref_mismatch",
                "disputed_refs_unsorted",
                "disputed_without_refs",
                "duplicate_source_claim",
                "empty_interval",
                "kind_mixing",
                "modality_not_policy_admitted",
                "modality_promotion",
                "normative_output",
                "policy_digest_mismatch",
                "profile_digest_spoof",
                "request_authority_fields",
                "single_source",
                "unsorted_sources",
            ]
            .map(String::from),
            "negative case list must stay sorted and complete"
        );
    }

    #[test]
    fn positive_fixtures_reencode_to_their_exact_bytes() {
        let policy: ConsolidationPolicyV1 =
            decode_strict(fixture_bytes(POLICY_FIXTURE)).expect("decode policy");
        assert_eq!(
            encode_canonical(&policy).expect("encode policy"),
            fixture_bytes(POLICY_FIXTURE)
        );
        let statement: ConsolidationStatementV1 =
            decode_strict(fixture_bytes(STATEMENT_FIXTURE)).expect("decode statement");
        assert_eq!(
            encode_canonical(&statement).expect("encode statement"),
            fixture_bytes(STATEMENT_FIXTURE)
        );
        let disputed: ConsolidationStatementV1 =
            decode_strict(fixture_bytes(DISPUTED_STATEMENT_FIXTURE)).expect("decode disputed");
        assert_eq!(
            encode_canonical(&disputed).expect("encode disputed"),
            fixture_bytes(DISPUTED_STATEMENT_FIXTURE)
        );
        let request: ConsolidationRequestV1 =
            decode_strict(fixture_bytes(REQUEST_FIXTURE)).expect("decode request");
        assert_eq!(
            encode_canonical(&request).expect("encode request"),
            fixture_bytes(REQUEST_FIXTURE)
        );
        let receipt: ConsolidationReceiptV1 =
            decode_strict(fixture_bytes(RECEIPT_FIXTURE)).expect("decode receipt");
        assert_eq!(
            encode_canonical(&receipt).expect("encode receipt"),
            fixture_bytes(RECEIPT_FIXTURE)
        );

        // The receipt names the statement identity minted over the canonical
        // statement bytes under the accepted W0-REG domain prefix; the value
        // recomputes locally with byte-identical framing.
        let expected_identity: Sha256Digest =
            "42cecb6a5bc67d24f8984121951327548ab3d48327d9ba0bbca2245f81b0dc6b"
                .parse()
                .expect("statement identity hex");
        assert_eq!(receipt.statement_id.digest(), expected_identity);
        let recomputed_identity = domain_separated_digest(
            DigestDomain::ConsolidationStatementV1,
            &encode_canonical(&statement).expect("encode statement"),
        );
        assert_eq!(recomputed_identity, expected_identity);

        // The receipt's summary enrichment digest commits to the exact
        // authored summary bytes carried by the request fixture under the
        // dedicated summary-enrichment prefix.
        let recomputed_summary = domain_separated_digest(
            DigestDomain::ConsolidationSummaryEnrichmentV1,
            request.summary_text.as_str().as_bytes(),
        );
        assert_eq!(receipt.summary_enrichment_digest, recomputed_summary);
    }

    #[test]
    fn new_negative_fixtures_fail_at_the_documented_stage() {
        let policy: ConsolidationPolicyV1 =
            decode_strict(fixture_bytes(POLICY_FIXTURE)).expect("decode policy");

        let shape_failures: [(&[u8], &str); 3] = [
            (
                NEGATIVE_PROFILE_DIGEST_SPOOF_FIXTURE,
                "profile digest spoof",
            ),
            (
                NEGATIVE_DUPLICATE_SOURCE_CLAIM_FIXTURE,
                "duplicate source claim",
            ),
            (
                NEGATIVE_DISPUTED_REFS_UNSORTED_FIXTURE,
                "disputed refs unsorted",
            ),
        ];
        for (fixture, case) in shape_failures {
            let decoded: ConsolidationStatementV1 =
                decode_strict(fixture_bytes(fixture)).expect("decode negative statement");
            assert!(
                decoded.validate_shape().is_err(),
                "{case} must fail at the shape stage"
            );
        }

        let derivation_failures: [(&[u8], &str); 3] = [
            (
                NEGATIVE_DISPUTED_REF_MISMATCH_FIXTURE,
                "disputed ref mismatch",
            ),
            (
                NEGATIVE_MODALITY_NOT_POLICY_ADMITTED_FIXTURE,
                "modality not policy-admitted",
            ),
            (
                NEGATIVE_POLICY_DIGEST_MISMATCH_FIXTURE,
                "policy digest mismatch",
            ),
        ];
        for (fixture, case) in derivation_failures {
            let decoded: ConsolidationStatementV1 =
                decode_strict(fixture_bytes(fixture)).expect("decode negative statement");
            assert!(
                decoded.validate_shape().is_ok(),
                "{case} must pass the shape stage so the derivation rule is what falsifies it"
            );
            assert!(
                decoded.validate_derivation(&policy).is_err(),
                "{case} must fail at the derivation stage"
            );
        }
    }
}
