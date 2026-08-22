//! Chunk occurrence, parse-run manifest, current-generation pointer, embedding
//! and domain-keyed storage identity across parser versions.
//!
//! This module implements the identities described in
//! `docs/DYNAMIC_MEMORY_ARCHITECTURE.md`, "Chunk and embedding identity across
//! parser versions" and "Canonical resource identity". It reuses
//! [`super::digest::body_digest`] for the reusable body-content ID and
//! [`super::identity::ResourceUri`] for the immutable source-object version
//! URI; it does not redefine either.
//!
//! Three identities are deliberately kept separate:
//!
//! - a [`SourceSpanV1`] digest, over the exact raw source bytes a span
//!   covers (EVID-02: exact byte-range coordinates, not line numbers);
//! - a body-content ID (`body_digest`), over the exact canonical bytes a
//!   parser extracted, excluding any parser-added header;
//! - a [`ChunkOccurrenceId`], over the source URI, parser key, ordered
//!   spans, occurrence ordinal, body-content ID, and redaction/publication
//!   classifier versions. It deliberately excludes any parse-manifest ID:
//!   [`ChunkOccurrencePreimageV1`] has no such field, so an occurrence's
//!   identity cannot depend on the manifest that later cites it.
//!
//! A [`ParseRunManifestPreimageV1`] is the reverse dependency: its
//! `occurrence_ids` field is filled in only after every occurrence ID in the
//! run is already known, and its own [`ParseManifestId`] is a pure digest of
//! that already-complete preimage (REPLAY-01: replaying the same parser key
//! over the same source representation and canonical inputs reproduces the
//! same manifest, because the manifest ID is nothing but a domain-separated
//! digest of deterministic canonical bytes).
//!
//! [`GenerationPointerSwitchProposalV1`] models the current-generation
//! pointer as a compare-and-swap preimage: `expected_prior_pointer` names the
//! exact prior pointer the switch was proposed against, so a late proposal
//! computed against a since-superseded pointer fails
//! [`GenerationPointerSwitchProposalV1::checked_against`] rather than
//! silently reclaiming the pointer. [`AdmittedGenerationSwitchV1`] has no
//! production constructor in this contract-only stage: runtime admission
//! must additionally verify the coverage and determinism receipts, and must
//! supply the current pointer from trusted registry storage, never from the
//! proposal's own payload.
//!
//! [`BodyReferenceStateV1::may_reclaim_shared_storage`] and
//! [`apply_occurrence_erasure`] model EVID-08's reference-counted erasure
//! rule as a validated predicate and a pure state transition: erasure
//! removes an occurrence from the lawful-reference set immediately, and
//! shared body or embedding storage may be reclaimed only once that set is
//! empty. `may_reclaim_shared_storage` validates its receiver first, so an
//! unknown-schema or otherwise-invalid state can never answer `Ok(true)`.
//!
//! [`StorageIdentityPreimageV1::storage_identity`] hashes the
//! protection-domain identifier into the same preimage as the body-content
//! ID, so the emitted [`StorageIdentityId`] does not let an unkeyed digest
//! equality leak physical deduplication across protection domains.

use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};

use super::{
    ContractError, ContractResult,
    canonical::encode_canonical,
    common::{CanonicalTimestamp, ContractId},
    digest::{DigestDomain, Sha256Digest, body_digest, domain_separated_digest},
    identity::{IdentityForm, ResourceUri},
};

const CHUNK_IDENTITY_SCHEMA_VERSION: u32 = 1;
const MAX_NORMALIZATION_RULES: usize = 8;
const MAX_SPANS_PER_OCCURRENCE: usize = 64;
const MAX_OCCURRENCES_PER_MANIFEST: usize = 4_096;
const MAX_BODY_DIGESTS_PER_MANIFEST: usize = 4_096;
const MAX_LAWFUL_REFERENCES: usize = 4_096;
const MAX_SPAN_BYTE_OFFSET: u64 = 1 << 40;
const MAX_EMBEDDING_DIMENSIONS: u32 = 65_536;

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

digest_newtype!(ParserKeyId);
digest_newtype!(ChunkOccurrenceId);
digest_newtype!(ParseManifestId);
digest_newtype!(ManifestSupersessionId);
digest_newtype!(GenerationPointerId);
digest_newtype!(EmbeddingIdentityId);
digest_newtype!(StorageIdentityId);

/// Closed set of normalization behaviors a parser configuration may declare.
///
/// This set is closed deliberately: an unrecognized flag must fail to
/// deserialize rather than silently normalize under an unknown rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NormalizationRuleV1 {
    NewlineLf,
    UnicodeNfc,
    WhitespaceCollapse,
    TrailingWhitespaceTrim,
    ControlCharacterStrip,
}

/// Parser/extractor identity: artifact digest, version, exact configuration
/// digest, and the closed set of normalization rules that configuration
/// declares.
///
/// Two parser keys that differ in any field are different parsers for
/// identity purposes, even if they happen to emit identical bytes on one
/// input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParserKeyV1 {
    pub schema_version: u32,
    pub parser_artifact_digest: Sha256Digest,
    pub parser_version: u32,
    pub configuration_digest: Sha256Digest,
    pub declared_normalization_rules: Vec<NormalizationRuleV1>,
}

impl ParserKeyV1 {
    pub fn validate(&self) -> ContractResult<()> {
        if self.schema_version != CHUNK_IDENTITY_SCHEMA_VERSION
            || self.parser_version == 0
            || self.parser_artifact_digest == Sha256Digest::ZERO
            || self.configuration_digest == Sha256Digest::ZERO
            || self.declared_normalization_rules.len() > MAX_NORMALIZATION_RULES
        {
            return Err(ContractError::Schema("invalid parser key".into()));
        }
        if !strictly_sorted(&self.declared_normalization_rules) {
            return Err(ContractError::NonCanonicalSet {
                field: "declared_normalization_rules",
            });
        }
        Ok(())
    }

    pub fn key_digest(&self) -> ContractResult<ParserKeyId> {
        self.validate()?;
        Ok(ParserKeyId::from_digest(domain_separated_digest(
            DigestDomain::ParserKeyV1,
            &encode_canonical(self)?,
        )))
    }
}

/// One half-open `[byte_start, byte_end)` coordinate into an immutable
/// source-object version.
///
/// Also carries the digest of exactly those raw source bytes and this
/// span's position among its occurrence's ordered span list. Line numbers
/// are deliberately absent: they are display metadata only, per "Canonical
/// resource identity" and "Chunk and embedding identity across parser
/// versions".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceSpanV1 {
    pub schema_version: u32,
    pub byte_start: u64,
    pub byte_end: u64,
    pub span_digest: Sha256Digest,
    pub ordinal: u32,
}

impl SourceSpanV1 {
    pub fn validate(&self) -> ContractResult<()> {
        if self.schema_version != CHUNK_IDENTITY_SCHEMA_VERSION
            || self.byte_start >= self.byte_end
            || self.byte_end > MAX_SPAN_BYTE_OFFSET
            || self.span_digest == Sha256Digest::ZERO
        {
            return Err(ContractError::Schema("invalid source span".into()));
        }
        Ok(())
    }

    /// Total: `None` on any decoded-but-unvalidated span whose `byte_end`
    /// does not exceed `byte_start` (the exact condition
    /// [`Self::validate`] rejects). `decode_strict` alone does not call
    /// `validate`, so this must never assume a decoded span is already
    /// well-formed; a bare subtraction here would panic in a debug build
    /// and silently wrap to a near-`u64::MAX` length in release.
    pub const fn byte_len(&self) -> Option<u64> {
        self.byte_end.checked_sub(self.byte_start)
    }
}

/// Digest of the exact raw source bytes one span covers.
///
/// Distinct from [`body_digest`]: a span digest commits to pre-extraction
/// source bytes (which may include parser-added headers or surrounding
/// context the parser later excludes from the body), while `body_digest`
/// commits to the exact canonical bytes a parser extracted.
pub fn source_span_digest(source_bytes_at_span: &[u8]) -> Sha256Digest {
    let mut hash = Sha256::new();
    hash.update(DigestDomain::SourceSpanV1.prefix().as_bytes());
    hash.update(
        u64::try_from(source_bytes_at_span.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    hash.update(source_bytes_at_span);
    Sha256Digest::from_bytes(hash.finalize().into())
}

/// Validate one occurrence's ordered span list: non-empty, individually
/// valid, positioned by `ordinal` matching list order, and strictly ordered
/// with no overlap. Gaps between spans are permitted (non-contiguous derived
/// passages), and adjacent (touching) spans are permitted; only overlap and
/// misordering are rejected.
fn validate_span_list(spans: &[SourceSpanV1]) -> ContractResult<()> {
    if spans.is_empty() || spans.len() > MAX_SPANS_PER_OCCURRENCE {
        return Err(ContractError::Schema(
            "occurrence must cite between 1 and the maximum number of source spans".into(),
        ));
    }
    for (index, span) in spans.iter().enumerate() {
        span.validate()?;
        let expected_ordinal =
            u32::try_from(index).map_err(|_| ContractError::Schema("span list too long".into()))?;
        if span.ordinal != expected_ordinal {
            return Err(ContractError::Schema(
                "span ordinals must equal their position in the ordered span list".into(),
            ));
        }
    }
    if !spans
        .windows(2)
        .all(|pair| pair[0].byte_end <= pair[1].byte_start)
    {
        return Err(ContractError::Schema(
            "source spans must be strictly ordered and non-overlapping".into(),
        ));
    }
    Ok(())
}

/// Preimage of one chunk occurrence's identity.
///
/// Deliberately has no manifest-ID field: occurrence identity never depends
/// on the manifest that later cites it (a manifest depends on already-known
/// occurrence IDs, never the reverse). A JSON payload that adds a
/// `manifest_id` key is rejected by `#[serde(deny_unknown_fields)]`, not
/// merely ignored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChunkOccurrencePreimageV1 {
    pub schema_version: u32,
    pub source_object_version_uri: ResourceUri,
    pub parser_key: ParserKeyV1,
    pub spans: Vec<SourceSpanV1>,
    pub ordinal: u32,
    pub body_content_id: Sha256Digest,
    pub redaction_policy_version: u32,
    pub publication_classifier_version: u32,
}

impl ChunkOccurrencePreimageV1 {
    pub fn validate(&self) -> ContractResult<()> {
        if self.schema_version != CHUNK_IDENTITY_SCHEMA_VERSION
            || self.source_object_version_uri.identity_form() != IdentityForm::Version
            || self.body_content_id == Sha256Digest::ZERO
            || self.redaction_policy_version == 0
            || self.publication_classifier_version == 0
        {
            return Err(ContractError::Schema(
                "invalid chunk occurrence preimage".into(),
            ));
        }
        self.parser_key.validate()?;
        validate_span_list(&self.spans)?;
        Ok(())
    }

    pub fn occurrence_id(&self) -> ContractResult<ChunkOccurrenceId> {
        self.validate()?;
        Ok(ChunkOccurrenceId::from_digest(domain_separated_digest(
            DigestDomain::ChunkOccurrenceV1,
            &encode_canonical(self)?,
        )))
    }
}

/// Preimage of one parse run's manifest.
///
/// `occurrence_ids` is filled in only after every cited occurrence's own ID
/// has already been computed, so [`Self::manifest_id`] is necessarily a
/// function of already-complete occurrence identities, never the other way
/// around.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParseRunManifestPreimageV1 {
    pub schema_version: u32,
    pub source_representation_uri: ResourceUri,
    pub parser_key: ParserKeyV1,
    pub occurrence_ids: Vec<ChunkOccurrenceId>,
    pub body_digests: Vec<Sha256Digest>,
    pub coverage_receipt_digest: Sha256Digest,
}

impl ParseRunManifestPreimageV1 {
    /// Structural-only binding, not a defect: this validates each
    /// `occurrence_ids` element as a well-formed, non-`ZERO`
    /// [`ChunkOccurrenceId`] digest, but a `ChunkOccurrenceId` is one-way —
    /// this preimage cannot recover the `parser_key`/
    /// `source_object_version_uri` an occurrence ID was actually computed
    /// under, so it cannot itself detect an occurrence ID cited here that
    /// was computed under a different parser key or source-object version
    /// than this manifest declares. A runtime built on this contract must
    /// bind that cross-check separately: load each cited occurrence's own
    /// stored [`ChunkOccurrencePreimageV1`], recompute its
    /// [`ChunkOccurrencePreimageV1::occurrence_id`] to confirm it matches
    /// the ID cited here, and additionally assert its `parser_key` and
    /// `source_object_version_uri` equal this manifest's own `parser_key`
    /// and `source_representation_uri` — before trusting `occurrence_ids`
    /// as evidence of what this parser key actually parsed from this
    /// source.
    ///
    /// Rejects a `Sha256Digest::ZERO` element inside `occurrence_ids` or
    /// `body_digests`, in addition to the already-checked `ZERO` coverage
    /// receipt: `ZERO` is this module's sentinel for missing/uninitialised,
    /// never a real occurrence or body identity, so admitting it here would
    /// mint a real, addressable `ParseManifestId` that cites a reference to
    /// nothing (REPLAY-01, fail-closed on missing).
    pub fn validate(&self) -> ContractResult<()> {
        if self.schema_version != CHUNK_IDENTITY_SCHEMA_VERSION
            || self.source_representation_uri.identity_form() != IdentityForm::Version
            || self.coverage_receipt_digest == Sha256Digest::ZERO
            || self.occurrence_ids.is_empty()
            || self.occurrence_ids.len() > MAX_OCCURRENCES_PER_MANIFEST
            || self.body_digests.is_empty()
            || self.body_digests.len() > MAX_BODY_DIGESTS_PER_MANIFEST
            || self
                .occurrence_ids
                .iter()
                .any(|id| id.digest() == Sha256Digest::ZERO)
            || self.body_digests.contains(&Sha256Digest::ZERO)
        {
            return Err(ContractError::Schema(
                "invalid parse-run manifest preimage".into(),
            ));
        }
        self.parser_key.validate()?;
        if has_duplicates(&self.occurrence_ids) {
            return Err(ContractError::NonCanonicalSet {
                field: "occurrence_ids",
            });
        }
        if !strictly_sorted(&self.body_digests) {
            return Err(ContractError::NonCanonicalSet {
                field: "body_digests",
            });
        }
        Ok(())
    }

    /// Computed only after every field is already known: this is the
    /// "afterward" step the architecture document describes. Occurrence
    /// identity, in contrast, never includes this ID.
    pub fn manifest_id(&self) -> ContractResult<ParseManifestId> {
        self.validate()?;
        Ok(ParseManifestId::from_digest(domain_separated_digest(
            DigestDomain::ParseManifestV1,
            &encode_canonical(self)?,
        )))
    }
}

/// Classification of an apparent chunk/parse-manifest identity collision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkIntegrityCollisionV1 {
    /// No collision: either a legitimately different parser key/source, or
    /// exactly reproduced canonical output (determinism, not collision).
    None,
    /// Same parser key and same source representation reproduced a
    /// different occurrence set, body-digest set, or coverage receipt.
    ManifestOccurrenceSetCollision,
    /// The same body-content digest was retained over two different exact
    /// byte sequences.
    BodyDigestBytesCollision,
}

/// Classify whether re-running a parser key against a source representation
/// produced a legitimate reproduction, an unrelated manifest, or an
/// integrity collision.
///
/// Per "Chunk and embedding identity across parser versions": re-running the
/// same parser key on the same source representation and canonical inputs
/// must reproduce the same manifest; a different manifest or occurrence set
/// under that same key and source is an integrity collision, not a new
/// generation.
pub fn classify_manifest_reissue(
    prior: &ParseRunManifestPreimageV1,
    candidate: &ParseRunManifestPreimageV1,
) -> ContractResult<ChunkIntegrityCollisionV1> {
    prior.validate()?;
    candidate.validate()?;
    let same_key_and_source = prior.parser_key == candidate.parser_key
        && prior.source_representation_uri == candidate.source_representation_uri;
    if !same_key_and_source {
        return Ok(ChunkIntegrityCollisionV1::None);
    }
    let same_canonical_output = prior.occurrence_ids == candidate.occurrence_ids
        && prior.body_digests == candidate.body_digests
        && prior.coverage_receipt_digest == candidate.coverage_receipt_digest;
    Ok(if same_canonical_output {
        ChunkIntegrityCollisionV1::None
    } else {
        ChunkIntegrityCollisionV1::ManifestOccurrenceSetCollision
    })
}

/// Classify whether a candidate byte sequence retained under an existing
/// body-content digest is a legitimate match or a digest/bytes collision.
///
/// Mirrors the doc comment already pinned on [`body_digest`]: "same digest
/// with different retained bytes is an integrity collision." That doc names
/// exactly one more shape of the same collision: a *retained* pair that is
/// already inconsistent (`retained_digest` does not actually reproduce from
/// `retained_bytes`). This function verifies that precondition itself,
/// before comparing anything against `candidate_bytes` — a caller-supplied
/// `retained_digest` is trusted input, not a value this function computed,
/// so an unverifiable retained pair must return `Err`, never a silent
/// `Ok(ChunkIntegrityCollisionV1::None)` that reads as "no collision found".
pub fn classify_body_reuse(
    retained_digest: Sha256Digest,
    retained_bytes: &[u8],
    candidate_bytes: &[u8],
) -> ContractResult<ChunkIntegrityCollisionV1> {
    if body_digest(retained_bytes) != retained_digest {
        return Err(ContractError::Schema(
            "retained body bytes do not reproduce the retained digest".into(),
        ));
    }
    Ok(
        if body_digest(candidate_bytes) == retained_digest && candidate_bytes != retained_bytes {
            ChunkIntegrityCollisionV1::BodyDigestBytesCollision
        } else {
            ChunkIntegrityCollisionV1::None
        },
    )
}

/// Automatic historical-citation equivalence requires the same immutable
/// source object plus identical ordered byte spans and span digests.
///
/// Body similarity, shifted text (even if the shifted bytes are identical),
/// or semantic overlap is new support requiring fresh verification, never
/// automatic equivalence.
///
/// Both span lists are validated with the same [`validate_span_list`] rule
/// an admitted [`ChunkOccurrencePreimageV1`] must pass (non-empty,
/// individually valid, strictly ordered, non-overlapping) before any
/// comparison happens. An empty, backwards, zero-digest, or
/// unknown-schema-version span list can therefore never be reported
/// equivalent to anything, including itself: this returns `Err`, not
/// `false`, on invalid input, because a bare `false` would be
/// indistinguishable from "verified different" when it actually means
/// "unverifiable".
pub fn citations_are_automatically_equivalent(
    left_source: &ResourceUri,
    left_spans: &[SourceSpanV1],
    right_source: &ResourceUri,
    right_spans: &[SourceSpanV1],
) -> ContractResult<bool> {
    validate_span_list(left_spans)?;
    validate_span_list(right_spans)?;
    Ok(left_source == right_source && left_spans == right_spans)
}

/// Closed set of reasons one parse manifest may supersede another.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupersessionReasonV1 {
    ParserConfigurationUpgrade,
    SourceRepresentationChange,
    CoverageOrDeterminismCorrection,
}

/// Explicit supersession link between one predecessor and successor
/// manifest.
///
/// A parser/configuration change never silently reuses old occurrence
/// identities; it must be recorded through a link like this one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestSupersessionV1 {
    pub schema_version: u32,
    pub predecessor_manifest_id: ParseManifestId,
    pub successor_manifest_id: ParseManifestId,
    pub reason: SupersessionReasonV1,
    pub effective_at: CanonicalTimestamp,
}

impl ManifestSupersessionV1 {
    /// Rejects a `Sha256Digest::ZERO` predecessor or successor: unlike a
    /// genuine `ParseManifestId`, `ZERO` names no manifest that was ever
    /// minted, so a supersession link naming it would either retire a real,
    /// live manifest into nothing, or mint a link superseding nothing with
    /// something — both are missing/uninitialised references, not
    /// legitimate supersession, and REPLAY-01 (and the fail-closed-on-missing
    /// discipline `GenerationPointerV1::validate` already applies) require
    /// this to fail closed rather than mint an addressable
    /// `ManifestSupersessionId` for a link to nothing.
    pub fn validate(&self) -> ContractResult<()> {
        if self.schema_version != CHUNK_IDENTITY_SCHEMA_VERSION
            || self.predecessor_manifest_id == self.successor_manifest_id
            || self.predecessor_manifest_id.digest() == Sha256Digest::ZERO
            || self.successor_manifest_id.digest() == Sha256Digest::ZERO
        {
            return Err(ContractError::Schema(
                "invalid manifest supersession link".into(),
            ));
        }
        Ok(())
    }

    pub fn supersession_id(&self) -> ContractResult<ManifestSupersessionId> {
        self.validate()?;
        Ok(ManifestSupersessionId::from_digest(
            domain_separated_digest(
                DigestDomain::ManifestSupersessionV1,
                &encode_canonical(self)?,
            ),
        ))
    }
}

/// The registry-declared active parser generation: which parser key produced
/// the current-view manifest, and a monotonic generation sequence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationPointerV1 {
    pub schema_version: u32,
    pub active_parser_key: ParserKeyId,
    pub active_manifest_id: ParseManifestId,
    pub generation_sequence: u64,
}

impl GenerationPointerV1 {
    /// Rejects the all-zero, sequence-0 degenerate pointer: unlike every
    /// other preimage in this module (`ParserKeyV1`,
    /// `ChunkOccurrencePreimageV1`, `ParseRunManifestPreimageV1`,
    /// `EmbeddingIdentityPreimageV1`, `StorageIdentityPreimageV1`,
    /// `BodyReferenceStateV1`), this is the CAS anchor for the
    /// registry-declared active parser generation, so an uninitialised
    /// pointer must never be admissible as either the expected-prior or
    /// proposed pointer of a generation switch.
    pub fn validate(&self) -> ContractResult<()> {
        if self.schema_version != CHUNK_IDENTITY_SCHEMA_VERSION
            || self.active_parser_key.digest() == Sha256Digest::ZERO
            || self.active_manifest_id.digest() == Sha256Digest::ZERO
            || self.generation_sequence == 0
        {
            return Err(ContractError::Schema("invalid generation pointer".into()));
        }
        Ok(())
    }

    pub fn pointer_id(&self) -> ContractResult<GenerationPointerId> {
        self.validate()?;
        Ok(GenerationPointerId::from_digest(domain_separated_digest(
            DigestDomain::GenerationPointerV1,
            &encode_canonical(self)?,
        )))
    }
}

/// Compare-and-swap preimage for a shadow-generation activation.
///
/// It names the exact prior pointer it was proposed against, so a late
/// proposal computed against a since-superseded pointer cannot reclaim the
/// active pointer merely by naming the same parser key again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationPointerSwitchProposalV1 {
    pub schema_version: u32,
    pub expected_prior_pointer: GenerationPointerV1,
    pub proposed_pointer: GenerationPointerV1,
    pub coverage_verification_digest: Sha256Digest,
    pub determinism_verification_digest: Sha256Digest,
}

impl GenerationPointerSwitchProposalV1 {
    pub fn validate(&self) -> ContractResult<()> {
        self.expected_prior_pointer.validate()?;
        self.proposed_pointer.validate()?;
        let expected_next_sequence = self
            .expected_prior_pointer
            .generation_sequence
            .checked_add(1);
        if self.schema_version != CHUNK_IDENTITY_SCHEMA_VERSION
            || self.coverage_verification_digest == Sha256Digest::ZERO
            || self.determinism_verification_digest == Sha256Digest::ZERO
            || Some(self.proposed_pointer.generation_sequence) != expected_next_sequence
            || self.proposed_pointer == self.expected_prior_pointer
        {
            return Err(ContractError::Schema(
                "invalid generation-pointer switch proposal".into(),
            ));
        }
        Ok(())
    }

    /// Structural compare-and-swap check only. `current` must come from a
    /// trusted registry witness, never from this proposal's own payload:
    /// this method proves the proposal names the exact current pointer and
    /// advances exactly one generation, nothing more.
    ///
    /// By design, not a gap: a `proposed_pointer` may legitimately name an
    /// *older* parser key or manifest than `current.active_parser_key` /
    /// `current.active_manifest_id` (an authorized rollback), and this still
    /// passes as long as `expected_prior_pointer == current` and
    /// `generation_sequence` advances by exactly one — the CAS anchor is the
    /// generation sequence and the exact prior-pointer witness, never a
    /// monotonicity claim about which parser key is "newer". Whether a given
    /// rollback proposal is *authorized* is a policy decision outside this
    /// structural check, exactly like the coverage/determinism receipts
    /// noted above.
    pub fn checked_against(&self, current: &GenerationPointerV1) -> ContractResult<()> {
        self.validate()?;
        current.validate()?;
        if &self.expected_prior_pointer != current {
            return Err(ContractError::StaleRegistryHead);
        }
        Ok(())
    }
}

/// Opaque witness that a proposed generation-pointer switch passed its
/// structural compare-and-swap check against one real current-pointer
/// witness.
///
/// No production constructor exists in this contract-only stage. Runtime
/// admission must additionally verify the coverage and determinism receipts
/// against real evidence, and must read the current pointer from trusted
/// registry storage, before treating a switch as authoritative.
#[derive(Debug)]
pub struct AdmittedGenerationSwitchV1 {
    proposal: GenerationPointerSwitchProposalV1,
}

impl AdmittedGenerationSwitchV1 {
    pub const fn new_pointer(&self) -> &GenerationPointerV1 {
        &self.proposal.proposed_pointer
    }

    #[cfg(test)]
    fn from_test_witness(
        proposal: GenerationPointerSwitchProposalV1,
        current: &GenerationPointerV1,
    ) -> ContractResult<Self> {
        proposal.checked_against(current)?;
        Ok(Self { proposal })
    }
}

/// Which content an embedding was computed over, selected by policy.
///
/// Using a tagged union rather than a separate selector-plus-digest pair,
/// combined with `deny_unknown_fields`, makes a selector/digest mismatch
/// structurally impossible: without `deny_unknown_fields` an
/// internally-tagged enum only requires the *selected* arm's own fields to
/// be present, but does not reject an unrelated key such as a stray
/// `occurrence_id` riding alongside a `body` arm — `deny_unknown_fields`
/// closes exactly that gap by rejecting any field the chosen arm does not
/// declare.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EmbeddingInputV1 {
    Body { body_content_id: Sha256Digest },
    Occurrence { occurrence_id: ChunkOccurrenceId },
}

/// Closed set of supported embedding distance metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DistanceMetricV1 {
    Cosine,
    DotProduct,
    EuclideanL2,
}

/// Embedding identity preimage.
///
/// Embedding nondeterminism (a remote model returning slightly different
/// vectors on retry) cannot alter this identity, because none of its bytes
/// are a field here; identity is fixed entirely by the input selection and
/// the declared model/tokenization/preprocessing/metric/dimension
/// configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmbeddingIdentityPreimageV1 {
    pub schema_version: u32,
    pub input: EmbeddingInputV1,
    pub model_digest: Sha256Digest,
    pub tokenization_version: u32,
    pub preprocessing_version: u32,
    pub distance_metric: DistanceMetricV1,
    pub dimensions: u32,
}

impl EmbeddingIdentityPreimageV1 {
    pub fn validate(&self) -> ContractResult<()> {
        let input_digest_is_zero = match &self.input {
            EmbeddingInputV1::Body { body_content_id } => *body_content_id == Sha256Digest::ZERO,
            EmbeddingInputV1::Occurrence { occurrence_id } => {
                occurrence_id.digest() == Sha256Digest::ZERO
            }
        };
        if self.schema_version != CHUNK_IDENTITY_SCHEMA_VERSION
            || input_digest_is_zero
            || self.model_digest == Sha256Digest::ZERO
            || self.tokenization_version == 0
            || self.preprocessing_version == 0
            || self.dimensions == 0
            || self.dimensions > MAX_EMBEDDING_DIMENSIONS
        {
            return Err(ContractError::Schema(
                "invalid embedding identity preimage".into(),
            ));
        }
        Ok(())
    }

    pub fn embedding_identity_id(&self) -> ContractResult<EmbeddingIdentityId> {
        self.validate()?;
        Ok(EmbeddingIdentityId::from_digest(domain_separated_digest(
            DigestDomain::EmbeddingIdentityV1,
            &encode_canonical(self)?,
        )))
    }
}

/// Preimage for a protection-domain-keyed external storage identity.
///
/// Hashing the protection-domain identifier into the same preimage as the
/// body-content digest (rather than using the unkeyed body digest as a
/// storage key directly) is what prevents digest equality from leaking
/// physical deduplication across protection domains.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageIdentityPreimageV1 {
    pub schema_version: u32,
    pub protection_domain_id: ContractId,
    pub body_content_id: Sha256Digest,
}

impl StorageIdentityPreimageV1 {
    pub fn validate(&self) -> ContractResult<()> {
        if self.schema_version != CHUNK_IDENTITY_SCHEMA_VERSION
            || self.body_content_id == Sha256Digest::ZERO
        {
            return Err(ContractError::Schema(
                "invalid storage identity preimage".into(),
            ));
        }
        Ok(())
    }

    pub fn storage_identity(&self) -> ContractResult<StorageIdentityId> {
        self.validate()?;
        Ok(StorageIdentityId::from_digest(domain_separated_digest(
            DigestDomain::StorageIdentityV1,
            &encode_canonical(self)?,
        )))
    }
}

/// Which lawful (non-erased) occurrences currently reference one shared
/// body-content ID. This is the state EVID-08's reference-count rule is
/// checked against.
///
/// Model gap, not a defect: unlike [`StorageIdentityPreimageV1`], this state
/// has no `protection_domain_id`. It is keyed only by `body_content_id`, so
/// a runtime that shares one `BodyReferenceStateV1` table across protection
/// domains would let a reference in domain A hold open storage that domain
/// B's identity also maps to. Any runtime built on this contract must key
/// its reference-state table by `(protection_domain_id, body_content_id)`,
/// exactly as [`StorageIdentityPreimageV1::storage_identity`] does; this
/// contract-only stage does not enforce that keying itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BodyReferenceStateV1 {
    pub schema_version: u32,
    pub body_content_id: Sha256Digest,
    pub lawful_referencing_occurrences: Vec<ChunkOccurrenceId>,
}

impl BodyReferenceStateV1 {
    pub fn validate(&self) -> ContractResult<()> {
        if self.schema_version != CHUNK_IDENTITY_SCHEMA_VERSION
            || self.body_content_id == Sha256Digest::ZERO
            || self.lawful_referencing_occurrences.len() > MAX_LAWFUL_REFERENCES
        {
            return Err(ContractError::Schema("invalid body reference state".into()));
        }
        if !strictly_sorted(&self.lawful_referencing_occurrences) {
            return Err(ContractError::NonCanonicalSet {
                field: "lawful_referencing_occurrences",
            });
        }
        Ok(())
    }

    /// EVID-08: shared body/embedding storage may be reclaimed only once no
    /// lawful occurrence references it. A checkpoint cannot pin bytes that
    /// policy requires erased, so this predicate is the fact a runtime
    /// reclamation decision must be gated on.
    ///
    /// Validates `self` first, so a state with an unknown/future
    /// `schema_version`, a zero `body_content_id`, an oversized or
    /// non-canonically-sorted reference set — anything [`Self::validate`]
    /// rejects — can never yield a reclaim-permitted answer. In particular a
    /// record written under a schema this contract cannot interpret always
    /// answers `Err`, never `Ok(true)`: fail-closed on unknown input, per
    /// the fleet criterion, rather than granting the exact permission
    /// EVID-08 gates on a state this code does not understand.
    pub fn may_reclaim_shared_storage(&self) -> ContractResult<bool> {
        self.validate()?;
        Ok(self.lawful_referencing_occurrences.is_empty())
    }
}

/// Erasure removes the named occurrence from the lawful-reference set
/// immediately (EVID-08: "erasure removes an occurrence immediately").
///
/// The returned state's `may_reclaim_shared_storage` becomes true exactly
/// when the erased occurrence was the last lawful reference.
pub fn apply_occurrence_erasure(
    state: &BodyReferenceStateV1,
    erased_occurrence: ChunkOccurrenceId,
) -> ContractResult<BodyReferenceStateV1> {
    state.validate()?;
    Ok(BodyReferenceStateV1 {
        schema_version: state.schema_version,
        body_content_id: state.body_content_id,
        lawful_referencing_occurrences: state
            .lawful_referencing_occurrences
            .iter()
            .copied()
            .filter(|occurrence_id| *occurrence_id != erased_occurrence)
            .collect(),
    })
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn has_duplicates<T: Ord>(values: &[T]) -> bool {
    let mut seen: BTreeSet<&T> = BTreeSet::new();
    !values.iter().all(|value| seen.insert(value))
}

#[cfg(test)]
#[path = "chunk_identity_tests.rs"]
mod tests;
