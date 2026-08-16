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
//! source claim fingerprint+revision set, consolidator identity and version,
//! policy reference and digest, output kind and modality, output depth,
//! computed effective interval, and disposition. The authored summary text is
//! versioned enrichment carried by the request and bound server-side by the
//! receipt; it never enters statement identity, exactly like an embedding
//! vector under REPLAY-01. The production digest constructor additionally
//! requires the `ostk-consolidation-statement-v1` digest domain, which is a
//! REG-lane allocation pending in `.fleet-recall/coordination/requests/
//! 2026-08-16-kimi-reg-consolidation-digest-domains.md`; this revision
//! deliberately ships canonical bytes and validation without that constructor.
//!
//! Cycle rejection (CONS-09) cannot be decided from one statement alone: it
//! requires the lineage-graph witness at the repository seam. What this
//! contract enforces is a strictly sorted, unique source set, a bounded
//! derivation depth, and an output depth exactly one greater than the deepest
//! source, so lineage chains are finite and replay-deterministic.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::{
    ContractError, ContractResult,
    canonical::encode_canonical,
    common::{AuthenticatedProjectScopeV1, ContractId, ProfileReferenceV1, RegistryReferenceV1},
    digest::Sha256Digest,
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
    /// 0x00 || canonical_bytes)`. The digest domain is a REG-lane allocation
    /// pending in the coordination request dated 2026-08-16; until it lands in
    /// `digest.rs`, no production identity constructor exists and these bytes
    /// are the complete semantic content.
    pub fn canonical_bytes(&self) -> ContractResult<Vec<u8>> {
        encode_canonical(self)
    }

    /// Validate canonical public shape only; this grants no derivation
    /// authority and does not evaluate the policy.
    pub fn validate_shape(&self) -> ContractResult<()> {
        self.profile.validate()?;
        self.policy.validate()?;
        validate_interval(&self.effective_interval)?;
        self.disposition.validate()?;
        if self.schema_version != CONSOLIDATION_SCHEMA_VERSION
            || self.policy_digest == Sha256Digest::ZERO
            || self.consolidator_version == 0
            || self.sources.len() < usize::try_from(MIN_CONSOLIDATION_SOURCES).unwrap_or(0)
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
        policy.validate_shape()?;
        if policy.policy_id != self.policy.entry_id || policy.version != self.policy.version {
            return Err(ContractError::Schema(
                "consolidation policy does not match its registry reference".into(),
            ));
        }
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
            || self.asserted_sources.len() < usize::try_from(MIN_CONSOLIDATION_SOURCES).unwrap_or(0)
            || self.asserted_sources.len() > usize::try_from(MAX_CONSOLIDATION_SOURCES).unwrap_or(0)
            || !strictly_sorted(&self.asserted_sources)
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
/// The receipt is not identity authority: the statement digest it carries is
/// verified against the accepted event, and the summary enrichment digest is
/// bound here, server-side, precisely so that narrative bytes stay out of
/// derivation identity (CONS-05).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsolidationReceiptV1 {
    pub schema_version: u32,
    pub statement_digest: Sha256Digest,
    pub outcome: ConsolidationOutcomeV1,
    pub emitted_claim_fingerprint: SemanticClaimFingerprintV2,
    pub summary_enrichment_digest: Sha256Digest,
    pub accepted_event_ids: Vec<AcceptedEventId>,
}

impl ConsolidationReceiptV1 {
    /// Validate canonical shape only; the receipt proves nothing by itself.
    pub fn validate_shape(&self) -> ContractResult<()> {
        if self.schema_version != CONSOLIDATION_SCHEMA_VERSION
            || self.statement_digest == Sha256Digest::ZERO
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
/// the latest start, and the earliest end unless any source is open-ended.
/// An empty intersection fails closed (PRED-03).
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

fn strictly_sorted_sources(sources: &[ConsolidationSourceClaimV1]) -> bool {
    strictly_sorted(
        &sources
            .iter()
            .map(|source| (source.claim_fingerprint, source.claim_revision))
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
    const VECTOR_SUITE_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v3/consolidation/vector-suite.jsonl");

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
        let statement = valid_statement();
        statement.validate_shape().expect("shape");
        statement
            .validate_derivation(&policy(ConsolidationConflictBehaviorV1::FailClosed))
            .expect("derivation");
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
        let mut statement = valid_statement();
        statement.sources[1].assertion_kind = RememberAssertionKindV2::Decision;
        assert!(
            statement
                .validate_derivation(&policy(ConsolidationConflictBehaviorV1::FailClosed))
                .is_err()
        );

        let mut statement = valid_statement();
        statement.output_kind = RememberAssertionKindV2::Decision;
        assert!(
            statement
                .validate_derivation(&policy(ConsolidationConflictBehaviorV1::FailClosed))
                .is_err()
        );
    }

    #[test]
    fn output_modality_never_exceeds_the_weakest_source() {
        let mut statement = valid_statement();
        statement.sources[1].modality = PropositionModalityV1::Attested;
        assert!(
            statement
                .validate_derivation(&policy(ConsolidationConflictBehaviorV1::FailClosed))
                .is_err()
        );

        let mut demoted = valid_statement();
        demoted.sources[1].modality = PropositionModalityV1::Attested;
        demoted.output_modality = PropositionModalityV1::Attested;
        demoted
            .validate_derivation(&policy(ConsolidationConflictBehaviorV1::FailClosed))
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
        let mut statement = valid_statement();
        statement.output_depth = 1;
        assert!(
            statement
                .validate_derivation(&policy(ConsolidationConflictBehaviorV1::FailClosed))
                .is_err()
        );

        let mut statement = valid_statement();
        statement.sources[1].consolidation_depth = 4;
        statement.output_depth = 5;
        assert!(
            statement
                .validate_derivation(&policy(ConsolidationConflictBehaviorV1::FailClosed))
                .is_err()
        );
    }

    #[test]
    fn interval_is_the_exact_intersection_and_empty_fails_closed() {
        let mut statement = valid_statement();
        statement.effective_interval = interval("2026-08-05T00:00:00.000000000Z", None);
        assert!(
            statement
                .validate_derivation(&policy(ConsolidationConflictBehaviorV1::FailClosed))
                .is_err()
        );

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
        assert!(
            statement
                .validate_derivation(&policy(ConsolidationConflictBehaviorV1::FailClosed))
                .is_err()
        );
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

        let laundering = statement(
            vec![
                clear_source(0x11, 0, interval("2026-08-01T00:00:00.000000000Z", None)),
                conflicted(),
            ],
            PropositionModalityV1::Observed,
            1,
            interval("2026-08-05T00:00:00.000000000Z", None),
            ConsolidationOutputDispositionV1::DerivedActive,
        );
        assert!(
            laundering
                .validate_derivation(&policy(ConsolidationConflictBehaviorV1::FailClosed))
                .is_err()
        );
        assert!(
            laundering
                .validate_derivation(&policy(ConsolidationConflictBehaviorV1::DeriveDisputed))
                .is_err()
        );

        let disputed = statement(
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
        disputed
            .validate_derivation(&policy(ConsolidationConflictBehaviorV1::DeriveDisputed))
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
        let negative_statements: [(&[u8], &str); 9] = [
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
}
