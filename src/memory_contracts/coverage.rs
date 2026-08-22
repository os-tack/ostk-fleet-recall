//! Coverage receipt contract shared by connectors and observers (COVER-01..03).
//!
//! A coverage receipt is the sole evidence that lets a later stage treat an
//! absence as meaningful. It separates three independent bits — completeness,
//! freshness, and sequence continuity — from the evaluated condition itself,
//! and it is the only place [`negative_support_admissible`] may consult to
//! decide whether that receipt may back a negative proposition or a verified
//! provenance gap (COVER-03). Every branch of that function is a closed,
//! explicit comparison: there is no default arm and no field that upgrades a
//! `partial` or `unknown` receipt to `complete`, nor a `stale` receipt to
//! `current` (PRED-03). `gap_detected` continuity always fails admission for
//! negative support even when completeness independently claims `complete`,
//! because completeness and continuity are recorded, and evaluated, as
//! separate witnesses (COVER-03).
//!
//! This module models the receipt itself and the separate evaluated
//! condition (COVER-01, COVER-02). It does not model exhaustive-observer
//! admission, registry entry bodies, or connector/observer run mechanics;
//! those are other workstreams' contracts. A "registered" rule or proof
//! method here is a structural, non-zero [`RegistryReferenceV1`] only —
//! proving that the reference names an *active* registry entry of the
//! expected kind is a runtime concern outside this offline contract layer.
//!
//! # Decode strictness (COVER-03) and the required ingress gate
//!
//! [`CoverageReceiptV1`] identity is defined over the **typed canonical
//! form**, and [`crate::memory_contracts::canonical::decode_typed_canonical`] is the only decode
//! function this module treats as an admissible ingress gate for wire bytes
//! a caller intends to bind by [`CoverageReceiptV1::receipt_id`]. Every
//! plain struct in this module — and [`RegistryReferenceV1`] from
//! `common.rs` that it embeds — derives `Deserialize`, and a derived
//! `Deserialize` on a plain struct accepts a well-typed *positional* JSON
//! array in a field's place exactly as readily as an object, while an
//! `Option` field may be accepted whether its wire key is present-as-`null`
//! or omitted entirely. Under [`crate::memory_contracts::canonical::decode_strict`] alone — which
//! only proves duplicate-safe strict JSON, not that the input is the *sole*
//! accepted encoding of the value it decodes to — two distinct byte strings
//! can therefore decode to one `==` [`CoverageReceiptV1`] and so bind the
//! identical `receipt_id()`, defeating the one property `negative_support_admissible`
//! callers are told to trust. `decode_typed_canonical` closes this for the
//! whole receipt, root and every nested struct at once, without any
//! type-specific `Deserialize` override: it decodes with `decode_strict`,
//! re-encodes the decoded value with [`encode_canonical`], and
//! rejects the input unless the two byte strings are identical, so at most
//! one accepted byte string exists per receipt value. See "Digests and
//! decode strictness" in this crate's
//! `contracts/dynamic-memory/v3/coverage/README.md`, and
//! `negative-nested-positional-producer.jsonl` /
//! `negative-gap-omitted-key.jsonl` for the committed vectors that prove it.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::{
    ContractError, ContractResult,
    canonical::encode_canonical,
    common::{CanonicalTimestamp, ContractId, HexBytes, RegistryReferenceV1},
    digest::{DigestDomain, Sha256Digest, domain_separated_digest},
    evidence::AcceptedEventId,
    identity::ResourceUri,
};

const COVERAGE_SCHEMA_VERSION: u32 = 1;

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
                S: Serializer,
            {
                self.0.serialize(serializer)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                Sha256Digest::deserialize(deserializer).map(Self)
            }
        }
    };
}

digest_newtype!(CoverageReceiptId);
digest_newtype!(CoverageProofV2Id); // W2-PKG

/// Closed kind of the artifact that produced a coverage receipt.
///
/// A connector observes provider events; an observer reads source bytes
/// directly (an AST/schema walker, for example). Exhaustive-observer
/// admission (COVER-01) is a separate, later contract — this enum only names
/// which kind of producer is asserting coverage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProducerKindV1 {
    Connector,
    Observer,
}

/// Exact producer identity and version. Coverage is granted per exact
/// executable/version, never to a producer kind or name globally.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProducerIdentityV1 {
    pub schema_version: u32,
    pub kind: ProducerKindV1,
    pub producer_id: ContractId,
    pub version: u32,
}

impl ProducerIdentityV1 {
    pub fn validate(&self) -> ContractResult<()> {
        if self.schema_version != COVERAGE_SCHEMA_VERSION || self.version == 0 {
            return Err(ContractError::Schema("invalid producer identity".into()));
        }
        Ok(())
    }
}

/// Half-open `[window_start, window_end)` interval in canonical UTC timestamps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageWindowV1 {
    pub window_start: CanonicalTimestamp,
    pub window_end: CanonicalTimestamp,
}

impl CoverageWindowV1 {
    pub fn validate(&self) -> ContractResult<()> {
        if self.window_end <= self.window_start {
            return Err(ContractError::Schema(
                "coverage window end must be strictly after its start".into(),
            ));
        }
        Ok(())
    }
}

/// Exact scope, immutable revision coordinate, and interval a receipt covers.
///
/// `revision` is an immutable coordinate (a commit, snapshot, or provider
/// object version), never a mutable label such as a branch name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageScopeV1 {
    pub scope: ResourceUri,
    pub revision: HexBytes,
    pub window: CoverageWindowV1,
}

impl CoverageScopeV1 {
    pub fn validate(&self) -> ContractResult<()> {
        self.window.validate()
    }
}

/// Typed union: a coverage watermark is a cursor or a provider sequence, never
/// both and never neither.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CoverageWatermarkV1 {
    Cursor { cursor: HexBytes },
    ProviderSequence { sequence: u64 },
}

/// Coverage completeness. There is deliberately no default variant and no
/// conversion that treats `partial` or `unknown` as `complete` (PRED-03).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageCompletenessV1 {
    Complete,
    Partial,
    Unknown,
}

/// Freshness state evaluated under a named, registered rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FreshnessStateV1 {
    Current,
    Stale,
}

/// Freshness is never a bare boolean: it is always stated under one exact
/// registered rule reference so a reviewer can look the rule up.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageFreshnessV1 {
    pub state: FreshnessStateV1,
    pub freshness_rule: RegistryReferenceV1,
}

impl CoverageFreshnessV1 {
    pub fn validate(&self) -> ContractResult<()> {
        validate_registered_reference(&self.freshness_rule, "freshness rule")
    }
}

/// Bounded description of a known sequence gap.
///
/// The last watermark observed before the gap and, if resumption was itself
/// observed, the watermark coverage resumed at. Both endpoints must share the
/// same watermark kind and have a provable, non-empty extent: for a
/// `provider_sequence` watermark, an integer, that means `gap_after` is
/// *strictly ordered* before `gap_before`; for a `cursor` watermark, opaque
/// provider-specific bytes with no crate-defined byte order, it means merely
/// that the two are *distinct* — this module cannot impose an ordering on
/// bytes it does not interpret, only require that the endpoints are not the
/// same watermark.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SequenceGapV1 {
    pub gap_after: CoverageWatermarkV1,
    pub gap_before: CoverageWatermarkV1,
}

impl SequenceGapV1 {
    pub fn validate(&self) -> ContractResult<()> {
        let has_provable_extent = match (&self.gap_after, &self.gap_before) {
            (
                CoverageWatermarkV1::Cursor { cursor: after },
                CoverageWatermarkV1::Cursor { cursor: before },
            ) => after != before,
            (
                CoverageWatermarkV1::ProviderSequence { sequence: after },
                CoverageWatermarkV1::ProviderSequence { sequence: before },
            ) => after < before,
            (CoverageWatermarkV1::Cursor { .. }, CoverageWatermarkV1::ProviderSequence { .. })
            | (CoverageWatermarkV1::ProviderSequence { .. }, CoverageWatermarkV1::Cursor { .. }) => {
                false
            }
        };
        if !has_provable_extent {
            return Err(ContractError::Schema(
                "sequence gap endpoints must share one watermark kind and have a provable, non-empty extent (distinct cursor bytes, or a strictly ordered provider sequence)"
                    .into(),
            ));
        }
        Ok(())
    }
}

/// Sequence continuity (COVER-03).
///
/// `gap_detected` always means the observed provider sequence has a known
/// acquisition or ordering gap; the bounded description is optional because a
/// gap can be known to exist without its exact extent being provable. Under
/// plain `#[derive(Deserialize)]`, `gap: Option<SequenceGapV1>` accepts the
/// `gap` wire key whether present-as-`null` or omitted entirely — that is,
/// `{"state":"gap_detected"}` and `{"gap":null,"state":"gap_detected"}` both
/// decode to the identical value under [`crate::memory_contracts::canonical::decode_strict`] alone.
/// This module does not close that gap with a field-level
/// `deserialize_with` override; it is closed once, generically, for this
/// field and every other same-shaped one in the receipt by requiring
/// [`crate::memory_contracts::canonical::decode_typed_canonical`] as the ingress gate (see the
/// module-level doc comment): the omitted-key form re-encodes with an
/// explicit `"gap":null`, which differs from the omitted-key input bytes, so
/// `decode_typed_canonical` rejects it even though `decode_strict` alone
/// would accept it. `negative-gap-omitted-key.jsonl` is the vector that
/// proves this.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum SequenceContinuityV1 {
    Contiguous {},
    GapDetected { gap: Option<SequenceGapV1> },
}

impl SequenceContinuityV1 {
    pub fn validate(&self) -> ContractResult<()> {
        if let Self::GapDetected { gap: Some(gap) } = self {
            gap.validate()?;
        }
        Ok(())
    }

    const fn is_contiguous(&self) -> bool {
        matches!(self, Self::Contiguous {})
    }
}

/// Closed set of coverage-proof bases named by the architecture doc.
///
/// This set is closed by design: a new proof method is a new variant, never a
/// free string, so `negative_support_admissible` can never be fooled by an
/// unrecognized label silently passing structural validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageProofMethodV1 {
    EnumeratedSnapshot,
    ClosedCursorInterval,
    ExhaustiveAstWalk,
    ClosedProviderQuery,
}

/// Coverage proof basis: the closed method plus the exact registered
/// proof-method entry it was admitted under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageProofBasisV1 {
    pub method: CoverageProofMethodV1,
    pub proof_method_registration: RegistryReferenceV1,
}

impl CoverageProofBasisV1 {
    pub fn validate(&self) -> ContractResult<()> {
        validate_registered_reference(&self.proof_method_registration, "proof method")
    }
}

/// A coverage receipt establishes when absence is meaningful (COVER-01..03).
///
/// Completeness, freshness, and sequence continuity are recorded as three
/// independent witnesses. Nothing in this type collapses them into one
/// another; only [`negative_support_admissible`] combines them into an
/// admission decision, and it does so without any default.
///
/// `Deserialize` is a plain derive: it accepts more wire shapes than the one
/// canonical shape (an object root, and a positional-array root with the
/// fields below in declaration order — the same is true of every nested
/// struct this type embeds). That is by design, not an oversight — this
/// type's decode strictness comes from the ingress *gate*, not from a
/// type-specific `Deserialize` override. Any caller intending to bind a
/// decoded value by [`CoverageReceiptV1::receipt_id`] MUST decode through
/// [`crate::memory_contracts::canonical::decode_typed_canonical`], never `decode_strict` alone or a
/// bare `serde_json` call; see the module-level doc comment for why, and
/// `contracts/dynamic-memory/v3/coverage/README.md`'s "Digests and decode
/// strictness" section for the review finding this closes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageReceiptV1 {
    pub schema_version: u32,
    pub producer: ProducerIdentityV1,
    pub scope: CoverageScopeV1,
    pub watermark: CoverageWatermarkV1,
    pub completeness: CoverageCompletenessV1,
    pub freshness: CoverageFreshnessV1,
    pub continuity: SequenceContinuityV1,
    pub observed_through: CanonicalTimestamp,
    pub proof_basis: CoverageProofBasisV1,
    pub source_digest: Sha256Digest,
    pub source_count: u32,
    pub evidence_id: AcceptedEventId,
}

impl CoverageReceiptV1 {
    pub fn validate(&self) -> ContractResult<()> {
        self.producer.validate()?;
        self.scope.validate()?;
        self.freshness.validate()?;
        self.continuity.validate()?;
        self.proof_basis.validate()?;
        if self.schema_version != COVERAGE_SCHEMA_VERSION {
            return Err(ContractError::Schema("invalid coverage receipt".into()));
        }
        // COVER-02: a receipt may claim coverage of its scope's window only
        // if reading actually reached the end of that half-open interval.
        // `observed_through` short of `window_end` means the receipt asserts
        // completeness over ground it never read.
        if self.observed_through < self.scope.window.window_end {
            return Err(ContractError::Schema(
                "observed_through must reach the end of the covered window".into(),
            ));
        }
        // Consistent with `validate_registered_reference` rejecting the
        // zero digest for a registry reference, and the crate-wide
        // convention (see e.g. `successor_activation.rs`, `evidence_v2.rs`)
        // of rejecting the zero digest for every identity-bearing digest: an
        // all-zero `source_digest` or `evidence_id` can never be the real
        // digest of source material or an accepted event, so accepting it
        // here would silently admit a receipt that names no actual source.
        if self.source_digest == Sha256Digest::ZERO {
            return Err(ContractError::Schema(
                "source digest cannot use the zero digest".into(),
            ));
        }
        if self.evidence_id.digest() == Sha256Digest::ZERO {
            return Err(ContractError::Schema(
                "evidence id cannot use the zero digest".into(),
            ));
        }
        // Reject a programmatically constructed value that the strict
        // canonical profile itself would refuse to emit (for example an
        // out-of-range integer reached without going through JSON at all).
        encode_canonical(self)?;
        Ok(())
    }

    /// `SHA-256("ostk-coverage-receipt-v1" || 0x00 || canonical_receipt_bytes)`.
    ///
    /// W0-OBS and connector call sites bind a coverage receipt by this exact
    /// digest; the preimage is the full canonical receipt, so any field
    /// change — including a field this module does not itself interpret —
    /// changes the bound identity.
    pub fn receipt_id(&self) -> ContractResult<CoverageReceiptId> {
        self.validate()?;
        Ok(CoverageReceiptId::from_digest(domain_separated_digest(
            DigestDomain::CoverageReceipt,
            &encode_canonical(self)?,
        )))
    }
}

/// The evaluated condition a coverage receipt is being asked to support.
///
/// Deliberately separate from [`CoverageReceiptV1`]: coverage completeness
/// and sequence continuity describe how thoroughly the domain was read,
/// never what was found in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluatedConditionV1 {
    Present,
    Absent,
    Indeterminate,
}

/// Whether `receipt` may support a negative proposition or verified
/// provenance gap for `condition` (COVER-01..03, PRED-03).
///
/// `true` only when every one of the following holds:
/// - `condition` is [`EvaluatedConditionV1::Absent`] — a negative finding is
///   the only thing this function ever admits; `present` and `indeterminate`
///   are never "negatively supported" regardless of receipt quality;
/// - `receipt` is well-formed (`validate` succeeds), including a registered,
///   non-zero freshness rule and proof-method reference;
/// - coverage completeness is exactly [`CoverageCompletenessV1::Complete`] —
///   `partial` and `unknown` never qualify, and there is no default that
///   upgrades either into `complete`;
/// - freshness is exactly [`FreshnessStateV1::Current`] — `stale` never
///   qualifies;
/// - sequence continuity is exactly [`SequenceContinuityV1::Contiguous`] —
///   `gap_detected` never qualifies, even when `completeness` independently
///   claims `complete` and even when the gap's bounded description is
///   absent. A known acquisition or sequence gap makes coverage incomplete
///   for this purpose regardless of what the completeness field separately
///   asserts (COVER-03).
///
/// This function is pure: it performs no I/O and mutates nothing, so calling
/// it twice with the same inputs always returns the same answer.
pub fn negative_support_admissible(
    receipt: &CoverageReceiptV1,
    condition: EvaluatedConditionV1,
) -> bool {
    condition == EvaluatedConditionV1::Absent
        && receipt.validate().is_ok()
        && matches!(receipt.completeness, CoverageCompletenessV1::Complete)
        && matches!(receipt.freshness.state, FreshnessStateV1::Current)
        && receipt.continuity.is_contiguous()
}

/// A "registered" rule or proof method is, at this offline contract layer, a
/// structurally valid non-zero reference. Proving the reference names an
/// entry that is actually active in the current registry head is a runtime
/// concern outside this module.
fn validate_registered_reference(
    reference: &RegistryReferenceV1,
    field: &'static str,
) -> ContractResult<()> {
    reference.validate()?;
    if reference.entry_digest == Sha256Digest::ZERO {
        return Err(ContractError::Schema(format!(
            "{field} reference cannot use the zero digest"
        )));
    }
    Ok(())
}

/// Generation-2 coverage constants (W2-PKG).
const COVERAGE_PROOF_V2_SCHEMA_VERSION: u32 = 2;
const MAX_COVERAGE_PROOF_INSTANCES: usize = 64;

/// One connector instance's cursor watermark inside a generation-2 coverage
/// proof.
///
/// The watermark is deliberately restricted to the opaque-cursor form: a
/// generation-2 package's connectors (transcript, version-history) advance by
/// an opaque resumable cursor, not a monotone provider sequence, so a
/// provider-sequence watermark here is a category error and is rejected. Each
/// binding also carries the completeness and continuity witnesses for exactly
/// that instance, so the proof records per-instance coverage rather than one
/// blended claim across instances.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorInstanceCursorV2 {
    pub connector_instance_id: ContractId,
    pub cursor: HexBytes,
    pub completeness: CoverageCompletenessV1,
    pub continuity: SequenceContinuityV1,
}

impl ConnectorInstanceCursorV2 {
    /// Validate one instance cursor: a non-empty instance id, a non-empty
    /// opaque cursor, and a well-formed continuity witness.
    pub fn validate(&self) -> ContractResult<()> {
        self.continuity.validate()?;
        if self.connector_instance_id.as_str().is_empty() || self.cursor.as_bytes().is_empty() {
            return Err(ContractError::Schema(
                "connector instance cursor must name a non-empty instance and cursor".into(),
            ));
        }
        Ok(())
    }

    /// The watermark restated in the shared `CoverageWatermarkV1` cursor form,
    /// so downstream watermark logic sees one representation.
    #[must_use]
    pub fn watermark(&self) -> CoverageWatermarkV1 {
        CoverageWatermarkV1::Cursor {
            cursor: self.cursor.clone(),
        }
    }
}

/// Connector-instance-cursor-aware coverage proof (COVER-01..03, W2-PKG).
///
/// A generation-2 package ingests from more than one connector instance. This
/// proof binds one cursor watermark, completeness, and continuity witness *per
/// connector instance* under one shared scope, freshness, and proof basis, so
/// the package can prove it read every named instance to a resumable cursor.
/// Distinct from [`CoverageReceiptV1`], which records a single producer's
/// coverage; this proof carries the whole instance set and is content-addressed
/// under [`DigestDomain::CoverageProofV2`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageProofV2 {
    pub schema_version: u32,
    pub scope: CoverageScopeV1,
    pub freshness: CoverageFreshnessV1,
    pub proof_basis: CoverageProofBasisV1,
    pub observed_through: CanonicalTimestamp,
    pub instances: Vec<ConnectorInstanceCursorV2>,
}

impl CoverageProofV2 {
    /// Validate the proof: schema version, scope/freshness/basis, a bounded,
    /// non-empty, strictly-ordered-and-unique instance set, and that reading
    /// reached the end of the covered window.
    pub fn validate(&self) -> ContractResult<()> {
        self.scope.validate()?;
        self.freshness.validate()?;
        self.proof_basis.validate()?;
        if self.schema_version != COVERAGE_PROOF_V2_SCHEMA_VERSION
            || self.instances.is_empty()
            || self.instances.len() > MAX_COVERAGE_PROOF_INSTANCES
        {
            return Err(ContractError::Schema("invalid coverage proof v2".into()));
        }
        if self.observed_through < self.scope.window.window_end {
            return Err(ContractError::Schema(
                "observed_through must reach the end of the covered window".into(),
            ));
        }
        for instance in &self.instances {
            instance.validate()?;
        }
        if !self
            .instances
            .windows(2)
            .all(|pair| pair[0].connector_instance_id < pair[1].connector_instance_id)
        {
            return Err(ContractError::NonCanonicalSet { field: "instances" });
        }
        encode_canonical(self)?;
        Ok(())
    }

    /// `SHA-256("ostk-coverage-proof-v2" || 0x00 || canonical_proof_bytes)`.
    pub fn proof_id(&self) -> ContractResult<CoverageProofV2Id> {
        self.validate()?;
        Ok(CoverageProofV2Id::from_digest(domain_separated_digest(
            DigestDomain::CoverageProofV2,
            &encode_canonical(self)?,
        )))
    }

    /// True when this proof carries a cursor witness for `connector_instance_id`.
    #[must_use]
    pub fn covers_instance(&self, connector_instance_id: &ContractId) -> bool {
        self.instances
            .iter()
            .any(|instance| &instance.connector_instance_id == connector_instance_id)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::memory_contracts::{
        canonical::{decode_strict, decode_typed_canonical, require_canonical},
        digest::domain_separated_digest,
    };

    const PRODUCER_IDENTITY_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v3/coverage/producer-identity.jsonl");
    const COVERAGE_SCOPE_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v3/coverage/coverage-scope.jsonl");
    const WATERMARK_CURSOR_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/coverage/coverage-watermark-cursor.jsonl"
    );
    const WATERMARK_SEQUENCE_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/coverage/coverage-watermark-provider-sequence.jsonl"
    );
    const COVERAGE_FRESHNESS_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v3/coverage/coverage-freshness.jsonl");
    const SEQUENCE_GAP_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v3/coverage/sequence-gap.jsonl");
    const COVERAGE_PROOF_BASIS_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v3/coverage/coverage-proof-basis.jsonl");
    const MATRIX_COMPLETE_CURRENT_CONTIGUOUS: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/coverage/matrix-complete-current-contiguous.jsonl"
    );
    const MATRIX_COMPLETE_CURRENT_GAP_DETECTED: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/coverage/matrix-complete-current-gap_detected.jsonl"
    );
    const MATRIX_COMPLETE_STALE_CONTIGUOUS: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/coverage/matrix-complete-stale-contiguous.jsonl"
    );
    const MATRIX_COMPLETE_STALE_GAP_DETECTED: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/coverage/matrix-complete-stale-gap_detected.jsonl"
    );
    const MATRIX_PARTIAL_CURRENT_CONTIGUOUS: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/coverage/matrix-partial-current-contiguous.jsonl"
    );
    const MATRIX_PARTIAL_CURRENT_GAP_DETECTED: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/coverage/matrix-partial-current-gap_detected.jsonl"
    );
    const MATRIX_PARTIAL_STALE_CONTIGUOUS: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/coverage/matrix-partial-stale-contiguous.jsonl"
    );
    const MATRIX_PARTIAL_STALE_GAP_DETECTED: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/coverage/matrix-partial-stale-gap_detected.jsonl"
    );
    const MATRIX_UNKNOWN_CURRENT_CONTIGUOUS: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/coverage/matrix-unknown-current-contiguous.jsonl"
    );
    const MATRIX_UNKNOWN_CURRENT_GAP_DETECTED: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/coverage/matrix-unknown-current-gap_detected.jsonl"
    );
    const MATRIX_UNKNOWN_STALE_CONTIGUOUS: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/coverage/matrix-unknown-stale-contiguous.jsonl"
    );
    const MATRIX_UNKNOWN_STALE_GAP_DETECTED: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/coverage/matrix-unknown-stale-gap_detected.jsonl"
    );
    const NEGATIVE_MISSING_OBSERVED_THROUGH: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/coverage/negative-missing-observed-through.jsonl"
    );
    const NEGATIVE_WINDOW_END_BEFORE_START: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/coverage/negative-window-end-before-start.jsonl"
    );
    const NEGATIVE_UNREGISTERED_PROOF_METHOD: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/coverage/negative-unregistered-proof-method.jsonl"
    );
    const NEGATIVE_UNREGISTERED_FRESHNESS_RULE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/coverage/negative-unregistered-freshness-rule.jsonl"
    );
    const NEGATIVE_FLOATING_VALUE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v3/coverage/negative-floating-value.jsonl");
    const NEGATIVE_UNKNOWN_FIELD: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v3/coverage/negative-unknown-field.jsonl");
    const NEGATIVE_ZERO_SCHEMA_VERSION: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/coverage/negative-zero-schema-version.jsonl"
    );
    const NEGATIVE_GAP_MISMATCHED_WATERMARK_KINDS: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/coverage/negative-gap-mismatched-watermark-kinds.jsonl"
    );
    const NEGATIVE_GAP_UNORDERED_SEQUENCE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/coverage/negative-gap-unordered-sequence.jsonl"
    );
    const NEGATIVE_ARBITRARY_JSON_VALUE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/coverage/negative-arbitrary-json-value.jsonl"
    );
    const NEGATIVE_NESTED_UNKNOWN_FIELD_CONTINUITY: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/coverage/negative-nested-unknown-field-continuity.jsonl"
    );
    const NEGATIVE_OBSERVED_THROUGH_BEFORE_WINDOW_END: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/coverage/negative-observed-through-before-window-end.jsonl"
    );
    const NEGATIVE_GAP_OMITTED_KEY: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v3/coverage/negative-gap-omitted-key.jsonl");
    const NEGATIVE_WELL_TYPED_POSITIONAL_ARRAY: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/coverage/negative-well-typed-positional-array.jsonl"
    );
    const NEGATIVE_NESTED_POSITIONAL_PRODUCER: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/coverage/negative-nested-positional-producer.jsonl"
    );
    const EVALUATED_CONDITION_PRESENT: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/coverage/evaluated-condition-present.jsonl"
    );
    const EVALUATED_CONDITION_ABSENT: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/coverage/evaluated-condition-absent.jsonl"
    );
    const EVALUATED_CONDITION_INDETERMINATE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/coverage/evaluated-condition-indeterminate.jsonl"
    );
    const VECTOR_SUITE_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v3/coverage/vector-suite.jsonl");

    const PRODUCER_IDENTITY_RAW_SHA256: &str =
        "7dc248271eee5cfbb7f3ddcd0bc6b7ee3b859ca9b4d9bb2eb51ecb237113ade8";
    const COVERAGE_SCOPE_RAW_SHA256: &str =
        "a1ba43d465e8f3bb0b80df77439bff57834711d150cd0ea5db1d4a4e8a8d21cc";
    const WATERMARK_CURSOR_RAW_SHA256: &str =
        "684c30eb3921ac7d5de7d3761fe1abf06b0f1150ab1beedcee572278d820e566";
    const WATERMARK_SEQUENCE_RAW_SHA256: &str =
        "f4b2d0ce2e2dd2d82fc9e9a708a657d992936f5fa251f68b75d27b11d490cc02";
    const COVERAGE_FRESHNESS_RAW_SHA256: &str =
        "81acce3937276afb69095f5cc77b8591c0eb105580e136304b5996e35679f919";
    const SEQUENCE_GAP_RAW_SHA256: &str =
        "052d09214405350645c7e3c9e18fb3939604cff61f4c7a041feb99bcad63a89d";
    const COVERAGE_PROOF_BASIS_RAW_SHA256: &str =
        "9d13455c42304260e89dada8cdcf35bec6d8ab693eb7907143c7bb1146167cf9";
    const MATRIX_COMPLETE_CURRENT_CONTIGUOUS_RAW_SHA256: &str =
        "3858a1149980afad0fe4a0fea67c2b4c2ceb78f9bb6d2a4de12b470695ac8571";
    const MATRIX_COMPLETE_CURRENT_GAP_DETECTED_RAW_SHA256: &str =
        "ffe5f795af3714ffc24d369b4cace6c9d3dec311e83d381fbeb13d5e5da59a97";
    const MATRIX_COMPLETE_STALE_CONTIGUOUS_RAW_SHA256: &str =
        "085a8371b9760303dba65ea5aa9c77d104ab901e63679c7701a2bc381800ae14";
    const MATRIX_COMPLETE_STALE_GAP_DETECTED_RAW_SHA256: &str =
        "1bddfe6c072cea526a6e5ad839d1e9dd0852f5272b5e30a5abdcc7e7ff5c7746";
    const MATRIX_PARTIAL_CURRENT_CONTIGUOUS_RAW_SHA256: &str =
        "499eb46383d8fbb4b4b4832de4492e15d73d49e2994af2e774d41c6b6de0ec8a";
    const MATRIX_PARTIAL_CURRENT_GAP_DETECTED_RAW_SHA256: &str =
        "4429e83252697d54c4a1cd05958e7a80b6f25e481650aa63a88a79385e2c54d9";
    const MATRIX_PARTIAL_STALE_CONTIGUOUS_RAW_SHA256: &str =
        "2a6faf7de93c445be07954969490dc551d807d4d5843225b5ebb0f7277a71ba4";
    const MATRIX_PARTIAL_STALE_GAP_DETECTED_RAW_SHA256: &str =
        "eca02dbef8422872a48a39bc7e646d6e0145a5c63569e81784bba9edbe13889b";
    const MATRIX_UNKNOWN_CURRENT_CONTIGUOUS_RAW_SHA256: &str =
        "621f7e1188a1b2b500d9d2ae2ef418500ff9822eae1da089013bb5724109ffa3";
    const MATRIX_UNKNOWN_CURRENT_GAP_DETECTED_RAW_SHA256: &str =
        "d3e1a44189855f70a2869cdfa96b766cc096ab7e3d9a82c5239e0dacea73de17";
    const MATRIX_UNKNOWN_STALE_CONTIGUOUS_RAW_SHA256: &str =
        "2e8f23784bba48c487c500d162a5402a3fe2a0d79c8949dfbcad660a455ed6c9";
    const MATRIX_UNKNOWN_STALE_GAP_DETECTED_RAW_SHA256: &str =
        "8d97f0ad381f6d0e817e1dab56b58a89c22c4f3de71bc54a045c78e33e2d5f3c";
    const NEGATIVE_MISSING_OBSERVED_THROUGH_RAW_SHA256: &str =
        "75323b88745514815ba3f78f2d2394f39e4ddf7b076ab803957feb69a7f3c56c";
    const NEGATIVE_WINDOW_END_BEFORE_START_RAW_SHA256: &str =
        "8ab4b3fd0237331e52a15644c61f77a6177579c8eba0f4aa5df4349eb2b7b63f";
    const NEGATIVE_UNREGISTERED_PROOF_METHOD_RAW_SHA256: &str =
        "5f4df9986f48002887f27b73634119d93d5b3f42904ecec4927378cdc06e1daf";
    const NEGATIVE_UNREGISTERED_FRESHNESS_RULE_RAW_SHA256: &str =
        "8fd4f08614299585ffc734577ebfde2a4784a7c95a7ba57f511a9832d8437e1c";
    const NEGATIVE_FLOATING_VALUE_RAW_SHA256: &str =
        "233152f6e63eb170d86d4c828ebf3937ec74d75cc03227af0977d22b4ab872c3";
    const NEGATIVE_UNKNOWN_FIELD_RAW_SHA256: &str =
        "43f94d95b6bc1681081072535684f82b4a1b7971561b51ca727e08689c700c5a";
    const NEGATIVE_ZERO_SCHEMA_VERSION_RAW_SHA256: &str =
        "00106a1d795abef56edf749f5b6b75d9d3023b7e8bf25189b8a127913a3390e2";
    const NEGATIVE_GAP_MISMATCHED_WATERMARK_KINDS_RAW_SHA256: &str =
        "c8f7cedb3386e6d444ff36379663cabb08bef0721d3b0d212d08b05fa83c2f87";
    const NEGATIVE_GAP_UNORDERED_SEQUENCE_RAW_SHA256: &str =
        "6ed51a9e6b6b32cc9329d59476d00fc866290e98834cc16d0f5d09c639868f8c";
    const NEGATIVE_ARBITRARY_JSON_VALUE_RAW_SHA256: &str =
        "9c6bc7ac937d2daffe5ecdbe7eb3a59aba4f43e96a58a99f08838d4ce48c92ba";
    const NEGATIVE_NESTED_UNKNOWN_FIELD_CONTINUITY_RAW_SHA256: &str =
        "25e2adf454aa5a063e78fecdb1bb5acc78dbae7879ad630b4a6733a08db7987c";
    const NEGATIVE_OBSERVED_THROUGH_BEFORE_WINDOW_END_RAW_SHA256: &str =
        "29373cfecb2d06f94888d6d5ae8e59416d57b9d39190d3f30f85d85ee5483c5b";
    const NEGATIVE_GAP_OMITTED_KEY_RAW_SHA256: &str =
        "68c1edcfd74f5e885302388e123c251ec7eae94351d209b61e13a463e1962410";
    const NEGATIVE_WELL_TYPED_POSITIONAL_ARRAY_RAW_SHA256: &str =
        "3519ccc8b9e7cd1dd69e3df5d5c531ea08a41af3da15aa10813a1ab11e105080";
    const NEGATIVE_NESTED_POSITIONAL_PRODUCER_RAW_SHA256: &str =
        "426e39a8e467f4e1077fc630bf56137b4d01018c99bd008cf6ce8f3a46ada6ad";
    const EVALUATED_CONDITION_PRESENT_RAW_SHA256: &str =
        "87f7439876e4033adb5735dd9e8a4031ef2be2239574b1a83398efca11784151";
    const EVALUATED_CONDITION_ABSENT_RAW_SHA256: &str =
        "70056b5ee93a7f08f583971157cf1ea50b8f27cbb89371e308a2a7b984b43590";
    const EVALUATED_CONDITION_INDETERMINATE_RAW_SHA256: &str =
        "e2a4db258cdc6e923416ddf6f071c079c1ad524c35ff11ce24facbad55cd1859";
    const VECTOR_SUITE_RAW_SHA256: &str =
        "453f1c10f746253ec34e772316a47d022bf1ea1b78b66ba5b9f6fb42fcd7cfe1";

    const SCOPE_URI: &str = "urn:ostk:entity:v1:repository:sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const REVISION_HEX: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const FRESHNESS_RULE_DIGEST: &str =
        "3333333333333333333333333333333333333333333333333333333333333333";
    const PROOF_METHOD_DIGEST: &str =
        "4444444444444444444444444444444444444444444444444444444444444444";
    const SOURCE_DIGEST: &str = "5555555555555555555555555555555555555555555555555555555555555555";
    const EVIDENCE_ID_DIGEST: &str =
        "6666666666666666666666666666666666666666666666666666666666666666";
    const CURSOR_HEX: &str = "a1b2c3d4e5f6";

    const MATRIX_COMPLETE_CURRENT_CONTIGUOUS_RECEIPT_ID: &str =
        "af2991aaafc38234bb455c77d7d525508286ecf637b90506d4a5f5e979743ed7";
    const MATRIX_COMPLETE_CURRENT_GAP_DETECTED_RECEIPT_ID: &str =
        "0c114fb6502460214b91527fe61d3b4311ee24810895eab61d0896ad8b920ee2";
    const MATRIX_COMPLETE_STALE_CONTIGUOUS_RECEIPT_ID: &str =
        "3b83b95eda3b682a6fe0712b635b5cf99e7f6c4e99d840196e3d4cd9401263bf";
    const MATRIX_COMPLETE_STALE_GAP_DETECTED_RECEIPT_ID: &str =
        "188152e1af46747236236f78f83db33bf333daf820ceeca1c1353fa7df7f2aaa";
    const MATRIX_PARTIAL_CURRENT_CONTIGUOUS_RECEIPT_ID: &str =
        "ef85be3fb9163e2b867959a49542285ed2206cea251bfd70d750805e1f2f0206";
    const MATRIX_PARTIAL_CURRENT_GAP_DETECTED_RECEIPT_ID: &str =
        "53c8e8a9f133c2106f0a00318893b9204b3a8e7f9162b36abc5b0e1d7228fd7e";
    const MATRIX_PARTIAL_STALE_CONTIGUOUS_RECEIPT_ID: &str =
        "b1d0eb070c73c58bcf9599401dcdeee3ddda894896ef3833c3ab56cedabdc1ff";
    const MATRIX_PARTIAL_STALE_GAP_DETECTED_RECEIPT_ID: &str =
        "b879c3220e48db5b7ccb01128e6ec200318a14b92521428029b5abf83ee6bc0f";
    const MATRIX_UNKNOWN_CURRENT_CONTIGUOUS_RECEIPT_ID: &str =
        "97d6e681f418ede5b842e9537fcea3200e5b6e208c5d50fd87d879eb7bfa8cef";
    const MATRIX_UNKNOWN_CURRENT_GAP_DETECTED_RECEIPT_ID: &str =
        "9abfddfa9f4e12f964438961e4b091c66acf5af3fb6735e28db6b72cb4a884ef";
    const MATRIX_UNKNOWN_STALE_CONTIGUOUS_RECEIPT_ID: &str =
        "c3441c48b1f9d31b7865ac74dab22b36eb7e03a6be66242258b20d6f3d529ca9";
    const MATRIX_UNKNOWN_STALE_GAP_DETECTED_RECEIPT_ID: &str =
        "3cee8a812644b227eff1da851263f4729a60a572f2e41bcf50587dba06609353";

    const VECTOR_SUITE_DIGEST: &str =
        "9c25f16aa8df684db51ac75b4d5f5e0bcfd1817bc9069e3993038f45667f5bc1";

    fn digest(value: &str) -> Sha256Digest {
        Sha256Digest::from_str(value).expect("hard-coded digest must be lowercase SHA-256")
    }

    fn record(bytes: &'static [u8]) -> &'static [u8] {
        let body = bytes
            .strip_suffix(b"\n")
            .expect("contract artifact must have exactly one framing LF");
        assert!(!body.ends_with(b"\n"));
        assert!(!body.contains(&b'\r'));
        body
    }

    fn raw_sha256(bytes: &[u8]) -> String {
        use sha2::{Digest as _, Sha256};
        hex::encode(Sha256::digest(bytes))
    }

    fn reg_ref(id: &str, version: u32, digest_hex: &str) -> RegistryReferenceV1 {
        RegistryReferenceV1 {
            entry_id: ContractId::new(id).unwrap(),
            version,
            entry_digest: digest(digest_hex),
        }
    }

    fn cursor_watermark(hex_value: &str) -> CoverageWatermarkV1 {
        CoverageWatermarkV1::Cursor {
            cursor: HexBytes::new(hex::decode(hex_value).unwrap()).unwrap(),
        }
    }

    fn sequence_watermark(sequence: u64) -> CoverageWatermarkV1 {
        CoverageWatermarkV1::ProviderSequence { sequence }
    }

    fn producer() -> ProducerIdentityV1 {
        ProducerIdentityV1 {
            schema_version: 1,
            kind: ProducerKindV1::Observer,
            producer_id: ContractId::new("observer.ast_walker_rust").unwrap(),
            version: 3,
        }
    }

    fn scope() -> CoverageScopeV1 {
        CoverageScopeV1 {
            scope: ResourceUri::from_str(SCOPE_URI).unwrap(),
            revision: HexBytes::new(hex::decode(REVISION_HEX).unwrap()).unwrap(),
            window: CoverageWindowV1 {
                window_start: CanonicalTimestamp::parse("2026-08-14T00:00:00.000000000Z").unwrap(),
                window_end: CanonicalTimestamp::parse("2026-08-15T00:00:00.000000000Z").unwrap(),
            },
        }
    }

    fn freshness_current() -> CoverageFreshnessV1 {
        CoverageFreshnessV1 {
            state: FreshnessStateV1::Current,
            freshness_rule: reg_ref("coverage.freshness.default_rule", 1, FRESHNESS_RULE_DIGEST),
        }
    }

    fn freshness_stale() -> CoverageFreshnessV1 {
        CoverageFreshnessV1 {
            state: FreshnessStateV1::Stale,
            freshness_rule: reg_ref("coverage.freshness.default_rule", 1, FRESHNESS_RULE_DIGEST),
        }
    }

    fn proof_basis() -> CoverageProofBasisV1 {
        CoverageProofBasisV1 {
            method: CoverageProofMethodV1::ExhaustiveAstWalk,
            proof_method_registration: reg_ref(
                "coverage.proof.exhaustive_ast_walk",
                1,
                PROOF_METHOD_DIGEST,
            ),
        }
    }

    fn base_receipt(
        completeness: CoverageCompletenessV1,
        freshness: CoverageFreshnessV1,
        continuity: SequenceContinuityV1,
    ) -> CoverageReceiptV1 {
        CoverageReceiptV1 {
            schema_version: 1,
            producer: producer(),
            scope: scope(),
            watermark: sequence_watermark(42),
            completeness,
            freshness,
            continuity,
            observed_through: CanonicalTimestamp::parse("2026-08-15T00:00:00.000000000Z").unwrap(),
            proof_basis: proof_basis(),
            source_digest: digest(SOURCE_DIGEST),
            source_count: 128,
            evidence_id: AcceptedEventId::from_digest(digest(EVIDENCE_ID_DIGEST)),
        }
    }

    #[test]
    fn window_requires_strictly_ordered_bounds() {
        let mut window = CoverageWindowV1 {
            window_start: CanonicalTimestamp::parse("2026-08-14T00:00:00.000000000Z").unwrap(),
            window_end: CanonicalTimestamp::parse("2026-08-15T00:00:00.000000000Z").unwrap(),
        };
        assert!(window.validate().is_ok());

        window.window_end = window.window_start.clone();
        assert!(window.validate().is_err());

        window.window_end = CanonicalTimestamp::parse("2026-08-13T00:00:00.000000000Z").unwrap();
        assert!(window.validate().is_err());
    }

    #[test]
    fn sequence_gap_requires_matching_kind_and_strict_order() {
        assert!(
            SequenceGapV1 {
                gap_after: sequence_watermark(5),
                gap_before: sequence_watermark(9),
            }
            .validate()
            .is_ok()
        );
        assert!(
            SequenceGapV1 {
                gap_after: sequence_watermark(9),
                gap_before: sequence_watermark(9),
            }
            .validate()
            .is_err()
        );
        assert!(
            SequenceGapV1 {
                gap_after: sequence_watermark(9),
                gap_before: sequence_watermark(5),
            }
            .validate()
            .is_err()
        );
        assert!(
            SequenceGapV1 {
                gap_after: cursor_watermark("aa"),
                gap_before: sequence_watermark(5),
            }
            .validate()
            .is_err()
        );
        assert!(
            SequenceGapV1 {
                gap_after: cursor_watermark("aa"),
                gap_before: cursor_watermark("bb"),
            }
            .validate()
            .is_ok()
        );
        assert!(
            SequenceGapV1 {
                gap_after: cursor_watermark("aa"),
                gap_before: cursor_watermark("aa"),
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn zero_digest_registry_references_are_never_registered() {
        let mut freshness = freshness_current();
        freshness.freshness_rule.entry_digest = Sha256Digest::ZERO;
        assert!(freshness.validate().is_err());

        let mut basis = proof_basis();
        basis.proof_method_registration.entry_digest = Sha256Digest::ZERO;
        assert!(basis.validate().is_err());
    }

    /// Consistency: `validate_registered_reference` rejects the zero digest
    /// for a `RegistryReferenceV1`, so the receipt's own identity-bearing
    /// digests reject it too, rather than silently admitting a receipt that
    /// names no actual source material or accepted event.
    #[test]
    fn zero_digest_source_and_evidence_identity_are_rejected() {
        let mut zero_source = base_receipt(
            CoverageCompletenessV1::Complete,
            freshness_current(),
            SequenceContinuityV1::Contiguous {},
        );
        zero_source.source_digest = Sha256Digest::ZERO;
        assert!(zero_source.validate().is_err());

        let mut zero_evidence = base_receipt(
            CoverageCompletenessV1::Complete,
            freshness_current(),
            SequenceContinuityV1::Contiguous {},
        );
        zero_evidence.evidence_id = AcceptedEventId::from_digest(Sha256Digest::ZERO);
        assert!(zero_evidence.validate().is_err());
    }

    /// Full complete/partial/unknown x current/stale x `contiguous/gap_detected`
    /// matrix. Only the complete+current+contiguous cell may ever admit
    /// negative support, and only when the condition is `absent`.
    #[test]
    fn full_admissibility_matrix() {
        let completeness_values = [
            CoverageCompletenessV1::Complete,
            CoverageCompletenessV1::Partial,
            CoverageCompletenessV1::Unknown,
        ];
        let freshness_values = [freshness_current(), freshness_stale()];
        let continuity_values = [
            SequenceContinuityV1::Contiguous {},
            SequenceContinuityV1::GapDetected { gap: None },
            SequenceContinuityV1::GapDetected {
                gap: Some(SequenceGapV1 {
                    gap_after: sequence_watermark(5),
                    gap_before: sequence_watermark(9),
                }),
            },
        ];
        let conditions = [
            EvaluatedConditionV1::Present,
            EvaluatedConditionV1::Absent,
            EvaluatedConditionV1::Indeterminate,
        ];

        for completeness in completeness_values {
            for freshness in &freshness_values {
                for continuity in &continuity_values {
                    let receipt = base_receipt(completeness, freshness.clone(), continuity.clone());
                    assert!(receipt.validate().is_ok(), "well-formed cell must validate");
                    for condition in conditions {
                        let admissible = negative_support_admissible(&receipt, condition);
                        let expected = condition == EvaluatedConditionV1::Absent
                            && completeness == CoverageCompletenessV1::Complete
                            && freshness.state == FreshnessStateV1::Current
                            && matches!(continuity, SequenceContinuityV1::Contiguous {});
                        assert_eq!(
                            admissible, expected,
                            "completeness={completeness:?} freshness={:?} continuity={continuity:?} condition={condition:?}",
                            freshness.state
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn complete_with_gap_detected_never_admits_a_negative() {
        let receipt = base_receipt(
            CoverageCompletenessV1::Complete,
            freshness_current(),
            SequenceContinuityV1::GapDetected { gap: None },
        );
        assert!(receipt.validate().is_ok());
        assert!(!negative_support_admissible(
            &receipt,
            EvaluatedConditionV1::Absent
        ));
    }

    #[test]
    fn present_and_indeterminate_conditions_never_admit_regardless_of_receipt_quality() {
        let receipt = base_receipt(
            CoverageCompletenessV1::Complete,
            freshness_current(),
            SequenceContinuityV1::Contiguous {},
        );
        assert!(negative_support_admissible(
            &receipt,
            EvaluatedConditionV1::Absent
        ));
        assert!(!negative_support_admissible(
            &receipt,
            EvaluatedConditionV1::Present
        ));
        assert!(!negative_support_admissible(
            &receipt,
            EvaluatedConditionV1::Indeterminate
        ));
    }

    #[test]
    fn malformed_receipt_never_admits_even_if_flags_look_admissible() {
        let mut receipt = base_receipt(
            CoverageCompletenessV1::Complete,
            freshness_current(),
            SequenceContinuityV1::Contiguous {},
        );
        receipt.scope.window.window_end = receipt.scope.window.window_start.clone();
        assert!(receipt.validate().is_err());
        assert!(!negative_support_admissible(
            &receipt,
            EvaluatedConditionV1::Absent
        ));

        let mut unregistered = base_receipt(
            CoverageCompletenessV1::Complete,
            freshness_current(),
            SequenceContinuityV1::Contiguous {},
        );
        unregistered
            .proof_basis
            .proof_method_registration
            .entry_digest = Sha256Digest::ZERO;
        assert!(!negative_support_admissible(
            &unregistered,
            EvaluatedConditionV1::Absent
        ));
    }

    #[test]
    fn receipt_id_is_stable_and_domain_separated_from_other_digests() {
        let receipt = base_receipt(
            CoverageCompletenessV1::Complete,
            freshness_current(),
            SequenceContinuityV1::Contiguous {},
        );
        let id_once = receipt.receipt_id().unwrap();
        let id_again = receipt.receipt_id().unwrap();
        assert_eq!(id_once, id_again);

        let bytes = encode_canonical(&receipt).unwrap();
        let generic_domain_digest = domain_separated_digest(DigestDomain::Body, &bytes);
        assert_ne!(id_once.digest(), generic_domain_digest);

        let mut mutated = receipt;
        mutated.source_count += 1;
        assert_ne!(mutated.receipt_id().unwrap(), id_once);
    }

    #[test]
    fn evaluated_condition_round_trips_through_canonical_json() {
        for (bytes, expected) in [
            (EVALUATED_CONDITION_PRESENT, EvaluatedConditionV1::Present),
            (EVALUATED_CONDITION_ABSENT, EvaluatedConditionV1::Absent),
            (
                EVALUATED_CONDITION_INDETERMINATE,
                EvaluatedConditionV1::Indeterminate,
            ),
        ] {
            let decoded: EvaluatedConditionV1 = decode_strict(record(bytes)).unwrap();
            assert_eq!(decoded, expected);
            assert_eq!(encode_canonical(&decoded).unwrap(), record(bytes));
        }
    }

    #[test]
    fn standalone_component_fixtures_round_trip() {
        let decoded_producer: ProducerIdentityV1 =
            decode_strict(record(PRODUCER_IDENTITY_FIXTURE)).unwrap();
        assert_eq!(decoded_producer, producer());

        let decoded_scope: CoverageScopeV1 = decode_strict(record(COVERAGE_SCOPE_FIXTURE)).unwrap();
        assert_eq!(decoded_scope, scope());
        decoded_scope.validate().unwrap();

        let decoded_cursor: CoverageWatermarkV1 =
            decode_strict(record(WATERMARK_CURSOR_FIXTURE)).unwrap();
        assert_eq!(decoded_cursor, cursor_watermark(CURSOR_HEX));

        let decoded_sequence: CoverageWatermarkV1 =
            decode_strict(record(WATERMARK_SEQUENCE_FIXTURE)).unwrap();
        assert_eq!(decoded_sequence, sequence_watermark(7));

        let decoded_freshness: CoverageFreshnessV1 =
            decode_strict(record(COVERAGE_FRESHNESS_FIXTURE)).unwrap();
        assert_eq!(decoded_freshness, freshness_current());
        decoded_freshness.validate().unwrap();

        let decoded_gap: SequenceGapV1 = decode_strict(record(SEQUENCE_GAP_FIXTURE)).unwrap();
        decoded_gap.validate().unwrap();
        assert_eq!(
            decoded_gap,
            SequenceGapV1 {
                gap_after: sequence_watermark(5),
                gap_before: sequence_watermark(9),
            }
        );

        let decoded_basis: CoverageProofBasisV1 =
            decode_strict(record(COVERAGE_PROOF_BASIS_FIXTURE)).unwrap();
        assert_eq!(decoded_basis, proof_basis());
        decoded_basis.validate().unwrap();
    }

    #[test]
    #[allow(clippy::too_many_lines)] // exhaustively enumerates the 3x2x2 coverage matrix by design
    fn matrix_fixtures_match_expected_admissibility_and_pinned_digests() {
        let cases: &[(
            &'static [u8],
            CoverageCompletenessV1,
            CoverageFreshnessV1,
            SequenceContinuityV1,
            &str,
        )] = &[
            (
                MATRIX_COMPLETE_CURRENT_CONTIGUOUS,
                CoverageCompletenessV1::Complete,
                freshness_current(),
                SequenceContinuityV1::Contiguous {},
                MATRIX_COMPLETE_CURRENT_CONTIGUOUS_RECEIPT_ID,
            ),
            (
                MATRIX_COMPLETE_CURRENT_GAP_DETECTED,
                CoverageCompletenessV1::Complete,
                freshness_current(),
                SequenceContinuityV1::GapDetected {
                    gap: Some(SequenceGapV1 {
                        gap_after: cursor_watermark("aa11"),
                        gap_before: cursor_watermark("bb22"),
                    }),
                },
                MATRIX_COMPLETE_CURRENT_GAP_DETECTED_RECEIPT_ID,
            ),
            (
                MATRIX_COMPLETE_STALE_CONTIGUOUS,
                CoverageCompletenessV1::Complete,
                freshness_stale(),
                SequenceContinuityV1::Contiguous {},
                MATRIX_COMPLETE_STALE_CONTIGUOUS_RECEIPT_ID,
            ),
            (
                MATRIX_COMPLETE_STALE_GAP_DETECTED,
                CoverageCompletenessV1::Complete,
                freshness_stale(),
                SequenceContinuityV1::GapDetected {
                    gap: Some(SequenceGapV1 {
                        gap_after: sequence_watermark(10),
                        gap_before: sequence_watermark(20),
                    }),
                },
                MATRIX_COMPLETE_STALE_GAP_DETECTED_RECEIPT_ID,
            ),
            (
                MATRIX_PARTIAL_CURRENT_CONTIGUOUS,
                CoverageCompletenessV1::Partial,
                freshness_current(),
                SequenceContinuityV1::Contiguous {},
                MATRIX_PARTIAL_CURRENT_CONTIGUOUS_RECEIPT_ID,
            ),
            (
                MATRIX_PARTIAL_CURRENT_GAP_DETECTED,
                CoverageCompletenessV1::Partial,
                freshness_current(),
                SequenceContinuityV1::GapDetected { gap: None },
                MATRIX_PARTIAL_CURRENT_GAP_DETECTED_RECEIPT_ID,
            ),
            (
                MATRIX_PARTIAL_STALE_CONTIGUOUS,
                CoverageCompletenessV1::Partial,
                freshness_stale(),
                SequenceContinuityV1::Contiguous {},
                MATRIX_PARTIAL_STALE_CONTIGUOUS_RECEIPT_ID,
            ),
            (
                MATRIX_PARTIAL_STALE_GAP_DETECTED,
                CoverageCompletenessV1::Partial,
                freshness_stale(),
                SequenceContinuityV1::GapDetected { gap: None },
                MATRIX_PARTIAL_STALE_GAP_DETECTED_RECEIPT_ID,
            ),
            (
                MATRIX_UNKNOWN_CURRENT_CONTIGUOUS,
                CoverageCompletenessV1::Unknown,
                freshness_current(),
                SequenceContinuityV1::Contiguous {},
                MATRIX_UNKNOWN_CURRENT_CONTIGUOUS_RECEIPT_ID,
            ),
            (
                MATRIX_UNKNOWN_CURRENT_GAP_DETECTED,
                CoverageCompletenessV1::Unknown,
                freshness_current(),
                SequenceContinuityV1::GapDetected { gap: None },
                MATRIX_UNKNOWN_CURRENT_GAP_DETECTED_RECEIPT_ID,
            ),
            (
                MATRIX_UNKNOWN_STALE_CONTIGUOUS,
                CoverageCompletenessV1::Unknown,
                freshness_stale(),
                SequenceContinuityV1::Contiguous {},
                MATRIX_UNKNOWN_STALE_CONTIGUOUS_RECEIPT_ID,
            ),
            (
                MATRIX_UNKNOWN_STALE_GAP_DETECTED,
                CoverageCompletenessV1::Unknown,
                freshness_stale(),
                SequenceContinuityV1::GapDetected {
                    gap: Some(SequenceGapV1 {
                        gap_after: cursor_watermark("cc33"),
                        gap_before: cursor_watermark("dd44"),
                    }),
                },
                MATRIX_UNKNOWN_STALE_GAP_DETECTED_RECEIPT_ID,
            ),
        ];
        assert_eq!(cases.len(), 12, "matrix must cover all 3x2x2 cells");

        for (fixture, completeness, freshness, continuity, expected_receipt_id) in cases {
            require_canonical(record(fixture)).unwrap();
            let decoded: CoverageReceiptV1 = decode_strict(record(fixture)).unwrap();
            let expected = base_receipt(*completeness, freshness.clone(), continuity.clone());
            assert_eq!(&decoded, &expected);
            assert_eq!(encode_canonical(&decoded).unwrap(), record(fixture));
            assert_eq!(
                decoded.receipt_id().unwrap().digest(),
                digest(expected_receipt_id)
            );
            let expected_admissible = *completeness == CoverageCompletenessV1::Complete
                && freshness.state == FreshnessStateV1::Current
                && matches!(continuity, SequenceContinuityV1::Contiguous {});
            assert_eq!(
                negative_support_admissible(&decoded, EvaluatedConditionV1::Absent),
                expected_admissible
            );
        }

        // Exactly the complete+current+contiguous cell is admissible.
        let admissible_count = cases
            .iter()
            .filter(|(fixture, _, _, _, _)| {
                let decoded: CoverageReceiptV1 = decode_strict(record(fixture)).unwrap();
                negative_support_admissible(&decoded, EvaluatedConditionV1::Absent)
            })
            .count();
        assert_eq!(admissible_count, 1);
    }

    #[test]
    fn negative_vectors_fail_closed() {
        // These fixtures fail at `decode_strict` + `validate()` already: a
        // required field is entirely absent, a value is out of range, an
        // enum tag is unregistered, or a structural rule (window ordering,
        // gap ordering, `observed_through`) is violated. None of them is a
        // same-ID-different-bytes case; those are proved separately by
        // `same_id_different_bytes_forms_decode_under_decode_strict_but_are_rejected_by_decode_typed_canonical`
        // below, because (by construction) they succeed under
        // `decode_strict` + `validate()` and are caught only by the typed
        // canonical round-trip.
        for bytes in [
            NEGATIVE_MISSING_OBSERVED_THROUGH,
            NEGATIVE_WINDOW_END_BEFORE_START,
            NEGATIVE_UNREGISTERED_PROOF_METHOD,
            NEGATIVE_UNREGISTERED_FRESHNESS_RULE,
            NEGATIVE_FLOATING_VALUE,
            NEGATIVE_UNKNOWN_FIELD,
            NEGATIVE_ZERO_SCHEMA_VERSION,
            NEGATIVE_GAP_MISMATCHED_WATERMARK_KINDS,
            NEGATIVE_GAP_UNORDERED_SEQUENCE,
            NEGATIVE_ARBITRARY_JSON_VALUE,
            NEGATIVE_NESTED_UNKNOWN_FIELD_CONTINUITY,
            NEGATIVE_OBSERVED_THROUGH_BEFORE_WINDOW_END,
        ] {
            let outcome = decode_strict::<CoverageReceiptV1>(record(bytes))
                .and_then(|receipt| receipt.validate());
            assert!(outcome.is_err(), "fixture unexpectedly accepted");
        }
    }

    /// COVER-03: same-ID-different-bytes forms. Each of these fixtures
    /// decodes to a `CoverageReceiptV1` `==` the canonical positive fixture
    /// (`matrix-complete-current-contiguous.jsonl`) — same `receipt_id()` —
    /// under plain `decode_strict`, because a derived `Deserialize` on a
    /// plain struct accepts a positional-array form of any nested struct
    /// exactly as readily as an object, and an `Option` field accepts its
    /// wire key either omitted or present-as-`null`. This module does not
    /// close that with type-specific `Deserialize` overrides; it is closed
    /// once, generically, by requiring every caller to decode through
    /// [`decode_typed_canonical`] instead: it decodes, then re-encodes the
    /// decoded value and requires the result to equal the input, so an
    /// alternate encoding of an already-representable value is rejected
    /// even though the value itself is well-formed and would validate.
    #[test]
    fn same_id_different_bytes_forms_decode_under_decode_strict_but_are_rejected_by_decode_typed_canonical()
     {
        let canonical: CoverageReceiptV1 =
            decode_strict(record(MATRIX_COMPLETE_CURRENT_CONTIGUOUS)).unwrap();
        // The one wire form `negative-gap-omitted-key.jsonl` collides with
        // under `decode_strict` is not one of the 12 pinned matrix
        // fixtures (no matrix cell pairs `complete`+`current`+`gap_detected`
        // with an explicit `gap: null`); construct it directly instead.
        let complete_current_gap_none = base_receipt(
            CoverageCompletenessV1::Complete,
            freshness_current(),
            SequenceContinuityV1::GapDetected { gap: None },
        );

        for (name, bytes, expected) in [
            (
                "well_typed_positional_array (root)",
                NEGATIVE_WELL_TYPED_POSITIONAL_ARRAY,
                &canonical,
            ),
            (
                "nested_positional_producer (nested struct)",
                NEGATIVE_NESTED_POSITIONAL_PRODUCER,
                &canonical,
            ),
            (
                "gap_omitted_key (omitted optional key)",
                NEGATIVE_GAP_OMITTED_KEY,
                &complete_current_gap_none,
            ),
        ] {
            // `require_canonical` accepts the document: these are, byte for
            // byte, alternate canonical *documents*.
            require_canonical(record(bytes)).unwrap_or_else(|error| {
                panic!("{name}: expected a canonical document, got {error:?}")
            });
            // `decode_strict` decodes it to the identical value as its
            // clean-object-form counterpart, and that value validates and
            // binds the identical `receipt_id()` — this is the exact
            // same-ID-different-bytes collision COVER-03 forbids, if this
            // were the accepted ingress path.
            let decoded: CoverageReceiptV1 = decode_strict(record(bytes)).unwrap_or_else(|error| {
                panic!("{name}: expected decode_strict to accept, got {error:?}")
            });
            assert_eq!(&decoded, expected, "{name}: must decode to the clean value");
            assert!(decoded.validate().is_ok(), "{name}: must validate");
            assert_eq!(
                decoded.receipt_id().unwrap(),
                expected.receipt_id().unwrap(),
                "{name}: must bind the identical receipt_id under decode_strict alone"
            );
            // `decode_typed_canonical` is the required gate and rejects it:
            // re-encoding the decoded value never reproduces this alternate
            // input byte string.
            let gated = decode_typed_canonical::<CoverageReceiptV1>(record(bytes));
            assert!(
                matches!(gated, Err(ContractError::NotCanonical)),
                "{name}: decode_typed_canonical must reject with NotCanonical, got {gated:?}"
            );
        }

        // And the canonical positive fixture itself must decode through the
        // required gate cleanly, matching the plain `decode_strict` value.
        let gated: CoverageReceiptV1 =
            decode_typed_canonical(record(MATRIX_COMPLETE_CURRENT_CONTIGUOUS)).unwrap();
        assert_eq!(gated, canonical);
    }

    /// Every positive fixture — every full-receipt matrix cell and the
    /// explicit `gap:null` form — decodes through the required
    /// [`decode_typed_canonical`] ingress gate and reproduces the exact
    /// `receipt_id()` pinned for it.
    #[test]
    fn positive_matrix_fixtures_decode_through_the_typed_canonical_gate() {
        for (fixture, expected_receipt_id) in [
            (
                MATRIX_COMPLETE_CURRENT_CONTIGUOUS,
                MATRIX_COMPLETE_CURRENT_CONTIGUOUS_RECEIPT_ID,
            ),
            (
                MATRIX_COMPLETE_CURRENT_GAP_DETECTED,
                MATRIX_COMPLETE_CURRENT_GAP_DETECTED_RECEIPT_ID,
            ),
            (
                MATRIX_PARTIAL_CURRENT_GAP_DETECTED,
                MATRIX_PARTIAL_CURRENT_GAP_DETECTED_RECEIPT_ID,
            ),
        ] {
            let decoded: CoverageReceiptV1 = decode_typed_canonical(record(fixture)).unwrap();
            assert_eq!(
                decoded.receipt_id().unwrap().digest(),
                digest(expected_receipt_id)
            );
        }
    }

    /// A `Contiguous` continuity value with a smuggled `gap` key must be
    /// rejected at DECODE (not merely at validate), because
    /// `#[serde(deny_unknown_fields)]` on an internally-tagged enum does not
    /// by itself reject extra keys on a fieldless variant — see the
    /// `Contiguous {}` fix. Two distinct canonical byte strings must never
    /// decode to the same `CoverageReceiptV1`.
    #[test]
    fn contiguous_with_smuggled_gap_key_is_rejected_at_decode() {
        let outcome =
            decode_strict::<CoverageReceiptV1>(record(NEGATIVE_NESTED_UNKNOWN_FIELD_CONTINUITY));
        assert!(
            outcome.is_err(),
            "a gap key nested under a contiguous continuity value must not decode"
        );
    }

    /// COVER-02: a receipt cannot claim coverage of a window it never read
    /// through to the end.
    #[test]
    fn observed_through_short_of_window_end_is_rejected_at_validate() {
        let decoded: CoverageReceiptV1 =
            decode_strict(record(NEGATIVE_OBSERVED_THROUGH_BEFORE_WINDOW_END)).unwrap();
        assert!(decoded.validate().is_err());
        assert!(!negative_support_admissible(
            &decoded,
            EvaluatedConditionV1::Absent
        ));
    }

    #[test]
    #[allow(clippy::too_many_lines)] // pins every fixture's raw bytes by an independent SHA-256
    fn raw_fixture_bytes_are_pinned() {
        for (bytes, expected) in [
            (PRODUCER_IDENTITY_FIXTURE, PRODUCER_IDENTITY_RAW_SHA256),
            (COVERAGE_SCOPE_FIXTURE, COVERAGE_SCOPE_RAW_SHA256),
            (WATERMARK_CURSOR_FIXTURE, WATERMARK_CURSOR_RAW_SHA256),
            (WATERMARK_SEQUENCE_FIXTURE, WATERMARK_SEQUENCE_RAW_SHA256),
            (COVERAGE_FRESHNESS_FIXTURE, COVERAGE_FRESHNESS_RAW_SHA256),
            (SEQUENCE_GAP_FIXTURE, SEQUENCE_GAP_RAW_SHA256),
            (
                COVERAGE_PROOF_BASIS_FIXTURE,
                COVERAGE_PROOF_BASIS_RAW_SHA256,
            ),
            (
                EVALUATED_CONDITION_PRESENT,
                EVALUATED_CONDITION_PRESENT_RAW_SHA256,
            ),
            (
                EVALUATED_CONDITION_ABSENT,
                EVALUATED_CONDITION_ABSENT_RAW_SHA256,
            ),
            (
                EVALUATED_CONDITION_INDETERMINATE,
                EVALUATED_CONDITION_INDETERMINATE_RAW_SHA256,
            ),
            (
                MATRIX_COMPLETE_CURRENT_CONTIGUOUS,
                MATRIX_COMPLETE_CURRENT_CONTIGUOUS_RAW_SHA256,
            ),
            (
                MATRIX_COMPLETE_CURRENT_GAP_DETECTED,
                MATRIX_COMPLETE_CURRENT_GAP_DETECTED_RAW_SHA256,
            ),
            (
                MATRIX_COMPLETE_STALE_CONTIGUOUS,
                MATRIX_COMPLETE_STALE_CONTIGUOUS_RAW_SHA256,
            ),
            (
                MATRIX_COMPLETE_STALE_GAP_DETECTED,
                MATRIX_COMPLETE_STALE_GAP_DETECTED_RAW_SHA256,
            ),
            (
                MATRIX_PARTIAL_CURRENT_CONTIGUOUS,
                MATRIX_PARTIAL_CURRENT_CONTIGUOUS_RAW_SHA256,
            ),
            (
                MATRIX_PARTIAL_CURRENT_GAP_DETECTED,
                MATRIX_PARTIAL_CURRENT_GAP_DETECTED_RAW_SHA256,
            ),
            (
                MATRIX_PARTIAL_STALE_CONTIGUOUS,
                MATRIX_PARTIAL_STALE_CONTIGUOUS_RAW_SHA256,
            ),
            (
                MATRIX_PARTIAL_STALE_GAP_DETECTED,
                MATRIX_PARTIAL_STALE_GAP_DETECTED_RAW_SHA256,
            ),
            (
                MATRIX_UNKNOWN_CURRENT_CONTIGUOUS,
                MATRIX_UNKNOWN_CURRENT_CONTIGUOUS_RAW_SHA256,
            ),
            (
                MATRIX_UNKNOWN_CURRENT_GAP_DETECTED,
                MATRIX_UNKNOWN_CURRENT_GAP_DETECTED_RAW_SHA256,
            ),
            (
                MATRIX_UNKNOWN_STALE_CONTIGUOUS,
                MATRIX_UNKNOWN_STALE_CONTIGUOUS_RAW_SHA256,
            ),
            (
                MATRIX_UNKNOWN_STALE_GAP_DETECTED,
                MATRIX_UNKNOWN_STALE_GAP_DETECTED_RAW_SHA256,
            ),
            (
                NEGATIVE_MISSING_OBSERVED_THROUGH,
                NEGATIVE_MISSING_OBSERVED_THROUGH_RAW_SHA256,
            ),
            (
                NEGATIVE_WINDOW_END_BEFORE_START,
                NEGATIVE_WINDOW_END_BEFORE_START_RAW_SHA256,
            ),
            (
                NEGATIVE_UNREGISTERED_PROOF_METHOD,
                NEGATIVE_UNREGISTERED_PROOF_METHOD_RAW_SHA256,
            ),
            (
                NEGATIVE_UNREGISTERED_FRESHNESS_RULE,
                NEGATIVE_UNREGISTERED_FRESHNESS_RULE_RAW_SHA256,
            ),
            (NEGATIVE_FLOATING_VALUE, NEGATIVE_FLOATING_VALUE_RAW_SHA256),
            (NEGATIVE_UNKNOWN_FIELD, NEGATIVE_UNKNOWN_FIELD_RAW_SHA256),
            (
                NEGATIVE_ZERO_SCHEMA_VERSION,
                NEGATIVE_ZERO_SCHEMA_VERSION_RAW_SHA256,
            ),
            (
                NEGATIVE_GAP_MISMATCHED_WATERMARK_KINDS,
                NEGATIVE_GAP_MISMATCHED_WATERMARK_KINDS_RAW_SHA256,
            ),
            (
                NEGATIVE_GAP_UNORDERED_SEQUENCE,
                NEGATIVE_GAP_UNORDERED_SEQUENCE_RAW_SHA256,
            ),
            (
                NEGATIVE_ARBITRARY_JSON_VALUE,
                NEGATIVE_ARBITRARY_JSON_VALUE_RAW_SHA256,
            ),
            (
                NEGATIVE_NESTED_UNKNOWN_FIELD_CONTINUITY,
                NEGATIVE_NESTED_UNKNOWN_FIELD_CONTINUITY_RAW_SHA256,
            ),
            (
                NEGATIVE_OBSERVED_THROUGH_BEFORE_WINDOW_END,
                NEGATIVE_OBSERVED_THROUGH_BEFORE_WINDOW_END_RAW_SHA256,
            ),
            (
                NEGATIVE_GAP_OMITTED_KEY,
                NEGATIVE_GAP_OMITTED_KEY_RAW_SHA256,
            ),
            (
                NEGATIVE_WELL_TYPED_POSITIONAL_ARRAY,
                NEGATIVE_WELL_TYPED_POSITIONAL_ARRAY_RAW_SHA256,
            ),
            (
                NEGATIVE_NESTED_POSITIONAL_PRODUCER,
                NEGATIVE_NESTED_POSITIONAL_PRODUCER_RAW_SHA256,
            ),
            (VECTOR_SUITE_FIXTURE, VECTOR_SUITE_RAW_SHA256),
        ] {
            assert_eq!(raw_sha256(bytes), expected);
        }
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct CoverageVectorSuiteV1 {
        schema_version: u32,
        fixture_authority: String,
        canonical_receipt_id: CoverageReceiptId,
        matrix_case_count: u32,
        negative_case_count: u32,
        negative_cases: Vec<ContractId>,
    }

    #[test]
    fn vector_suite_manifest_matches_independent_ids() {
        let suite: CoverageVectorSuiteV1 = decode_strict(record(VECTOR_SUITE_FIXTURE)).unwrap();
        assert_eq!(suite.schema_version, 1);
        assert!(suite.fixture_authority.starts_with("none;"));
        let canonical_receipt: CoverageReceiptV1 =
            decode_strict(record(MATRIX_COMPLETE_CURRENT_CONTIGUOUS)).unwrap();
        assert_eq!(
            suite.canonical_receipt_id,
            canonical_receipt.receipt_id().unwrap()
        );
        assert_eq!(suite.matrix_case_count, 12);
        assert_eq!(suite.negative_case_count, 15);
        assert_eq!(suite.negative_cases.len(), 15);
        let mut sorted = suite.negative_cases.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), suite.negative_cases.len());
        assert_eq!(
            domain_separated_digest(
                DigestDomain::TestVectorManifest,
                record(VECTOR_SUITE_FIXTURE)
            ),
            digest(VECTOR_SUITE_DIGEST)
        );
    }
}
