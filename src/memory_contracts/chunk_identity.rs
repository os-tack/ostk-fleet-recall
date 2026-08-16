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
    pub fn validate(&self) -> ContractResult<()> {
        if self.schema_version != CHUNK_IDENTITY_SCHEMA_VERSION
            || self.source_representation_uri.identity_form() != IdentityForm::Version
            || self.coverage_receipt_digest == Sha256Digest::ZERO
            || self.occurrence_ids.is_empty()
            || self.occurrence_ids.len() > MAX_OCCURRENCES_PER_MANIFEST
            || self.body_digests.is_empty()
            || self.body_digests.len() > MAX_BODY_DIGESTS_PER_MANIFEST
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
/// with different retained bytes is an integrity collision."
pub fn classify_body_reuse(
    retained_digest: Sha256Digest,
    retained_bytes: &[u8],
    candidate_bytes: &[u8],
) -> ChunkIntegrityCollisionV1 {
    if body_digest(candidate_bytes) == retained_digest && candidate_bytes != retained_bytes {
        ChunkIntegrityCollisionV1::BodyDigestBytesCollision
    } else {
        ChunkIntegrityCollisionV1::None
    }
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
    pub fn validate(&self) -> ContractResult<()> {
        if self.schema_version != CHUNK_IDENTITY_SCHEMA_VERSION
            || self.predecessor_manifest_id == self.successor_manifest_id
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
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::memory_contracts::canonical::decode_strict;

    fn source_uri(seed: u8) -> ResourceUri {
        ResourceUri::from_str(&format!(
            "urn:ostk:version:v1:git.blob:sha256:{}",
            hex::encode([seed; 32])
        ))
        .unwrap()
    }

    fn digest_of(seed: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([seed; 32])
    }

    fn parser_key(configuration_seed: u8) -> ParserKeyV1 {
        ParserKeyV1 {
            schema_version: CHUNK_IDENTITY_SCHEMA_VERSION,
            parser_artifact_digest: digest_of(0x11),
            parser_version: 1,
            configuration_digest: digest_of(configuration_seed),
            declared_normalization_rules: vec![
                NormalizationRuleV1::NewlineLf,
                NormalizationRuleV1::UnicodeNfc,
            ],
        }
    }

    fn span(ordinal: u32, start: u64, end: u64, seed: u8) -> SourceSpanV1 {
        SourceSpanV1 {
            schema_version: CHUNK_IDENTITY_SCHEMA_VERSION,
            byte_start: start,
            byte_end: end,
            span_digest: source_span_digest(&vec![seed; usize::try_from(end - start).unwrap()]),
            ordinal,
        }
    }

    fn occurrence(ordinal: u32, configuration_seed: u8) -> ChunkOccurrencePreimageV1 {
        ChunkOccurrencePreimageV1 {
            schema_version: CHUNK_IDENTITY_SCHEMA_VERSION,
            source_object_version_uri: source_uri(0x01),
            parser_key: parser_key(configuration_seed),
            spans: vec![span(0, 0, 10, 0xaa)],
            ordinal,
            body_content_id: body_digest(b"extracted body text"),
            redaction_policy_version: 1,
            publication_classifier_version: 1,
        }
    }

    fn manifest(configuration_seed: u8) -> ParseRunManifestPreimageV1 {
        let occurrence_id = occurrence(0, configuration_seed).occurrence_id().unwrap();
        ParseRunManifestPreimageV1 {
            schema_version: CHUNK_IDENTITY_SCHEMA_VERSION,
            source_representation_uri: source_uri(0x02),
            parser_key: parser_key(configuration_seed),
            occurrence_ids: vec![occurrence_id],
            body_digests: vec![body_digest(b"extracted body text")],
            coverage_receipt_digest: digest_of(0x33),
        }
    }

    #[test]
    fn parser_key_digest_is_deterministic_and_domain_separated() {
        let key = parser_key(0x22);
        assert_eq!(
            key.key_digest().unwrap(),
            parser_key(0x22).key_digest().unwrap()
        );
        assert_ne!(
            key.key_digest().unwrap(),
            parser_key(0x23).key_digest().unwrap()
        );
    }

    #[test]
    fn parser_key_rejects_unsorted_normalization_rules() {
        let mut key = parser_key(0x22);
        key.declared_normalization_rules = vec![
            NormalizationRuleV1::UnicodeNfc,
            NormalizationRuleV1::NewlineLf,
        ];
        assert_eq!(
            key.validate(),
            Err(ContractError::NonCanonicalSet {
                field: "declared_normalization_rules"
            })
        );
    }

    #[test]
    fn parser_key_rejects_unknown_normalization_flag() {
        let raw = br#"{"configuration_digest":"2222222222222222222222222222222222222222222222222222222222222222","declared_normalization_rules":["not_a_real_rule"],"parser_artifact_digest":"1111111111111111111111111111111111111111111111111111111111111111","parser_version":1,"schema_version":1}"#;
        assert!(decode_strict::<ParserKeyV1>(raw).is_err());
    }

    #[test]
    fn occurrence_id_is_deterministic() {
        let a = occurrence(0, 0x22).occurrence_id().unwrap();
        let b = occurrence(0, 0x22).occurrence_id().unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn occurrence_id_changes_with_parser_configuration() {
        let a = occurrence(0, 0x22).occurrence_id().unwrap();
        let b = occurrence(0, 0x23).occurrence_id().unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn occurrence_preimage_excludes_manifest_id_structurally() {
        let mut value = serde_json::to_value(occurrence(0, 0x22)).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("manifest_id".into(), serde_json::json!("deadbeef"));
        let bytes = serde_json::to_vec(&value).unwrap();
        assert!(decode_strict::<ChunkOccurrencePreimageV1>(&bytes).is_err());
    }

    #[test]
    fn span_byte_len_is_total_even_on_an_invalid_start_after_end_span() {
        // `byte_len` must never panic (debug) or wrap (release) on a value
        // `decode_strict` alone would accept: `decode_strict` does not call
        // `validate`, so a `byte_start > byte_end` span can reach `byte_len`
        // unvalidated. It must report `None`, not abort or return a
        // near-`u64::MAX` nonsense length.
        let backwards = SourceSpanV1 {
            schema_version: CHUNK_IDENTITY_SCHEMA_VERSION,
            byte_start: 100,
            byte_end: 5,
            span_digest: digest_of(0xaa),
            ordinal: 0,
        };
        assert_eq!(backwards.byte_len(), None);
        assert!(backwards.validate().is_err());

        // `byte_start == byte_end` is itself a validation error (an empty
        // span), but `checked_sub` alone cannot distinguish "empty" from
        // "well-formed": it reports the correctly-computed zero length,
        // exactly like any other total unsigned subtraction, and
        // `validate` remains the sole authority on emptiness.
        let equal = span(0, 5, 5, 0xaa);
        assert_eq!(equal.byte_len(), Some(0));
        assert!(equal.validate().is_err());

        let forward = span(0, 5, 100, 0xaa);
        assert_eq!(forward.byte_len(), Some(95));
    }

    #[test]
    fn occurrence_rejects_empty_span() {
        let mut occ = occurrence(0, 0x22);
        occ.spans = vec![span(0, 5, 5, 0xaa)];
        assert!(occ.validate().is_err());
    }

    #[test]
    fn occurrence_rejects_overlapping_spans() {
        let mut occ = occurrence(0, 0x22);
        occ.spans = vec![span(0, 0, 10, 0xaa), span(1, 5, 20, 0xbb)];
        assert!(occ.validate().is_err());
    }

    #[test]
    fn occurrence_rejects_unsorted_spans() {
        let mut occ = occurrence(0, 0x22);
        occ.spans = vec![span(0, 10, 20, 0xaa), span(1, 0, 5, 0xbb)];
        assert!(occ.validate().is_err());
    }

    #[test]
    fn occurrence_accepts_non_contiguous_spans() {
        let mut occ = occurrence(0, 0x22);
        occ.spans = vec![span(0, 0, 5, 0xaa), span(1, 100, 120, 0xbb)];
        assert!(occ.occurrence_id().is_ok());
    }

    #[test]
    fn occurrence_rejects_line_number_field() {
        let raw = br#"{"body_content_id":"1111111111111111111111111111111111111111111111111111111111111111","line":5,"ordinal":0,"parser_key":{"configuration_digest":"2222222222222222222222222222222222222222222222222222222222222222","declared_normalization_rules":[],"parser_artifact_digest":"1111111111111111111111111111111111111111111111111111111111111111","parser_version":1,"schema_version":1},"publication_classifier_version":1,"redaction_policy_version":1,"schema_version":1,"source_object_version_uri":"urn:ostk:version:v1:git.blob:sha256:0101010101010101010101010101010101010101010101010101010101010101","spans":[]}"#;
        assert!(decode_strict::<ChunkOccurrencePreimageV1>(raw).is_err());
    }

    #[test]
    fn manifest_id_is_deterministic() {
        let a = manifest(0x22).manifest_id().unwrap();
        let b = manifest(0x22).manifest_id().unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn same_parser_key_yields_a_different_manifest_for_a_different_source_representation() {
        // "The same parser may legitimately produce a different manifest for
        // a different source representation."
        let mut on_second_source = manifest(0x22);
        on_second_source.source_representation_uri = source_uri(0x09);
        assert_ne!(
            manifest(0x22).manifest_id().unwrap(),
            on_second_source.manifest_id().unwrap()
        );
        assert_eq!(
            classify_manifest_reissue(&manifest(0x22), &on_second_source).unwrap(),
            ChunkIntegrityCollisionV1::None,
            "a different source representation is a new manifest, never a collision"
        );
    }

    #[test]
    fn rechunking_with_new_parser_config_yields_new_manifest_and_occurrences() {
        let old_manifest = manifest(0x22);
        let new_manifest = manifest(0x23);
        assert_ne!(
            old_manifest.manifest_id().unwrap(),
            new_manifest.manifest_id().unwrap()
        );
        assert_ne!(old_manifest.occurrence_ids, new_manifest.occurrence_ids);

        let supersession = ManifestSupersessionV1 {
            schema_version: CHUNK_IDENTITY_SCHEMA_VERSION,
            predecessor_manifest_id: old_manifest.manifest_id().unwrap(),
            successor_manifest_id: new_manifest.manifest_id().unwrap(),
            reason: SupersessionReasonV1::ParserConfigurationUpgrade,
            effective_at: CanonicalTimestamp::parse("2026-08-16T00:00:00.000000000Z").unwrap(),
        };
        assert!(supersession.supersession_id().is_ok());
        // The predecessor manifest remains a valid, independently addressable
        // historical value: superseding it does not mutate or invalidate it.
        assert!(old_manifest.validate().is_ok());
    }

    #[test]
    fn supersession_rejects_self_link() {
        let id = manifest(0x22).manifest_id().unwrap();
        let supersession = ManifestSupersessionV1 {
            schema_version: CHUNK_IDENTITY_SCHEMA_VERSION,
            predecessor_manifest_id: id,
            successor_manifest_id: id,
            reason: SupersessionReasonV1::ParserConfigurationUpgrade,
            effective_at: CanonicalTimestamp::parse("2026-08-16T00:00:00.000000000Z").unwrap(),
        };
        assert!(supersession.validate().is_err());
    }

    #[test]
    fn manifest_reissue_with_same_key_and_source_but_different_occurrences_is_a_collision() {
        let prior = manifest(0x22);
        let mut candidate = manifest(0x22);
        candidate.coverage_receipt_digest = digest_of(0x99);
        assert_eq!(
            classify_manifest_reissue(&prior, &candidate).unwrap(),
            ChunkIntegrityCollisionV1::ManifestOccurrenceSetCollision
        );
    }

    #[test]
    fn manifest_reissue_with_identical_inputs_is_not_a_collision() {
        let prior = manifest(0x22);
        let candidate = manifest(0x22);
        assert_eq!(
            classify_manifest_reissue(&prior, &candidate).unwrap(),
            ChunkIntegrityCollisionV1::None
        );
    }

    #[test]
    fn manifest_reissue_with_different_parser_key_is_a_new_generation_not_a_collision() {
        let prior = manifest(0x22);
        let candidate = manifest(0x23);
        assert_eq!(
            classify_manifest_reissue(&prior, &candidate).unwrap(),
            ChunkIntegrityCollisionV1::None
        );
    }

    #[test]
    fn body_reuse_with_different_bytes_under_same_digest_is_a_collision() {
        // Two byte strings colliding under SHA-256 cannot be constructed, so
        // this proves the predicate's logic by directly forging a retained
        // digest that does not match the retained bytes' real digest.
        let retained_bytes = b"first body";
        let retained_digest = body_digest(b"a different body entirely");
        assert_eq!(
            classify_body_reuse(
                retained_digest,
                retained_bytes,
                b"a different body entirely"
            ),
            ChunkIntegrityCollisionV1::BodyDigestBytesCollision
        );
    }

    #[test]
    fn body_reuse_with_matching_bytes_is_not_a_collision() {
        let bytes = b"same body";
        let digest = body_digest(bytes);
        assert_eq!(
            classify_body_reuse(digest, bytes, bytes),
            ChunkIntegrityCollisionV1::None
        );
    }

    #[test]
    fn parser_added_headers_are_excluded_from_body_identity() {
        // Two occurrences whose raw source spans differ (one covers a
        // parser-added header, one does not) but whose extracted body text
        // is identical must share the same body-content ID and therefore the
        // same protection-domain-keyed storage identity, while remaining
        // distinct occurrences (their evidence coordinates still differ).
        let with_header = ChunkOccurrencePreimageV1 {
            spans: vec![span(0, 0, 40, 0xaa)],
            ordinal: 0,
            ..occurrence(0, 0x22)
        };
        let without_header = ChunkOccurrencePreimageV1 {
            spans: vec![span(0, 12, 40, 0xbb)],
            ordinal: 1,
            ..occurrence(0, 0x22)
        };
        assert_eq!(with_header.body_content_id, without_header.body_content_id);
        assert_ne!(
            with_header.occurrence_id().unwrap(),
            without_header.occurrence_id().unwrap()
        );

        let domain = ContractId::new("domain.tenant-a").unwrap();
        let storage_a = StorageIdentityPreimageV1 {
            schema_version: CHUNK_IDENTITY_SCHEMA_VERSION,
            protection_domain_id: domain.clone(),
            body_content_id: with_header.body_content_id,
        }
        .storage_identity()
        .unwrap();
        let storage_b = StorageIdentityPreimageV1 {
            schema_version: CHUNK_IDENTITY_SCHEMA_VERSION,
            protection_domain_id: domain,
            body_content_id: without_header.body_content_id,
        }
        .storage_identity()
        .unwrap();
        assert_eq!(storage_a, storage_b);
    }

    #[test]
    fn stable_source_span_citations_require_identical_spans_and_digests() {
        let uri = source_uri(0x01);
        let spans_a = vec![span(0, 100, 140, 0xaa)];
        let spans_b = vec![span(0, 100, 140, 0xaa)];
        assert!(citations_are_automatically_equivalent(&uri, &spans_a, &uri, &spans_b).unwrap());

        // Shifted text: same-length span at a different offset is not
        // automatically equivalent, even if the underlying bytes are the
        // same content that moved.
        let shifted = vec![span(0, 105, 145, 0xaa)];
        assert!(!citations_are_automatically_equivalent(&uri, &spans_a, &uri, &shifted).unwrap());
    }

    /// Reviewer ATTACK1: an empty span list is exactly what
    /// `validate_span_list` rejects, and is the case
    /// `negative-empty-span.jsonl` exhibits as a negative vector. Two
    /// citations with no spans and no span digests must never be reported
    /// automatically equivalent — that would vacuously satisfy a
    /// requirement meant to be a positive, exhibited proof of identical
    /// evidence coordinates.
    #[test]
    fn empty_span_lists_are_never_automatically_equivalent() {
        let uri = source_uri(0x01);
        let empty: Vec<SourceSpanV1> = vec![];
        assert!(citations_are_automatically_equivalent(&uri, &empty, &uri, &empty).is_err());
    }

    /// Reviewer ATTACK2: a span that fails `SourceSpanV1::validate` (here:
    /// unknown `schema_version`, a backwards byte range, and a zero span
    /// digest, all three at once) must never be reported automatically
    /// equivalent to an identical copy of itself. `decode_strict` alone
    /// does not call `validate`, so an unvalidated span list hydrated from
    /// a historical citation record must not be able to reach a `true`
    /// answer through this predicate.
    #[test]
    fn invalid_spans_are_never_automatically_equivalent_even_to_themselves() {
        let uri = source_uri(0x01);
        let invalid = vec![SourceSpanV1 {
            schema_version: 99,
            byte_start: 100,
            byte_end: 5,
            span_digest: Sha256Digest::ZERO,
            ordinal: 7,
        }];
        assert!(invalid[0].validate().is_err());
        assert!(
            citations_are_automatically_equivalent(&uri, &invalid, &uri, &invalid.clone()).is_err()
        );
    }

    #[test]
    fn embedding_identity_selector_and_digest_cannot_disagree_by_construction() {
        let body_input = EmbeddingIdentityPreimageV1 {
            schema_version: CHUNK_IDENTITY_SCHEMA_VERSION,
            input: EmbeddingInputV1::Body {
                body_content_id: body_digest(b"body text"),
            },
            model_digest: digest_of(0x44),
            tokenization_version: 1,
            preprocessing_version: 1,
            distance_metric: DistanceMetricV1::Cosine,
            dimensions: 768,
        };
        let occurrence_input = EmbeddingIdentityPreimageV1 {
            input: EmbeddingInputV1::Occurrence {
                occurrence_id: occurrence(0, 0x22).occurrence_id().unwrap(),
            },
            ..body_input
        };
        assert_ne!(
            body_input.embedding_identity_id().unwrap(),
            occurrence_input.embedding_identity_id().unwrap()
        );
        assert_eq!(
            body_input.embedding_identity_id().unwrap(),
            body_input.embedding_identity_id().unwrap()
        );
    }

    #[test]
    fn storage_identity_dedups_within_one_protection_domain() {
        let domain = ContractId::new("domain.tenant-a").unwrap();
        let body = body_digest(b"shared body");
        let first = StorageIdentityPreimageV1 {
            schema_version: CHUNK_IDENTITY_SCHEMA_VERSION,
            protection_domain_id: domain.clone(),
            body_content_id: body,
        }
        .storage_identity()
        .unwrap();
        let second = StorageIdentityPreimageV1 {
            schema_version: CHUNK_IDENTITY_SCHEMA_VERSION,
            protection_domain_id: domain,
            body_content_id: body,
        }
        .storage_identity()
        .unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn storage_identity_does_not_leak_equality_across_protection_domains() {
        let body = body_digest(b"shared body");
        let tenant_a = StorageIdentityPreimageV1 {
            schema_version: CHUNK_IDENTITY_SCHEMA_VERSION,
            protection_domain_id: ContractId::new("domain.tenant-a").unwrap(),
            body_content_id: body,
        }
        .storage_identity()
        .unwrap();
        let tenant_b = StorageIdentityPreimageV1 {
            schema_version: CHUNK_IDENTITY_SCHEMA_VERSION,
            protection_domain_id: ContractId::new("domain.tenant-b").unwrap(),
            body_content_id: body,
        }
        .storage_identity()
        .unwrap();
        assert_ne!(tenant_a, tenant_b);
    }

    fn generation_pointer(sequence: u64, manifest_seed: u8) -> GenerationPointerV1 {
        GenerationPointerV1 {
            schema_version: CHUNK_IDENTITY_SCHEMA_VERSION,
            active_parser_key: ParserKeyId::from_digest(digest_of(0x55)),
            active_manifest_id: ParseManifestId::from_digest(digest_of(manifest_seed)),
            generation_sequence: sequence,
        }
    }

    #[test]
    fn generation_switch_succeeds_against_its_exact_expected_prior_pointer() {
        let generation_1 = generation_pointer(1, 0x01);
        let proposal = GenerationPointerSwitchProposalV1 {
            schema_version: CHUNK_IDENTITY_SCHEMA_VERSION,
            expected_prior_pointer: generation_1.clone(),
            proposed_pointer: generation_pointer(2, 0x02),
            coverage_verification_digest: digest_of(0x77),
            determinism_verification_digest: digest_of(0x88),
        };
        let admitted =
            AdmittedGenerationSwitchV1::from_test_witness(proposal, &generation_1).unwrap();
        assert_eq!(admitted.new_pointer().generation_sequence, 2);
    }

    #[test]
    fn late_old_parser_work_cannot_reclaim_a_since_advanced_pointer() {
        let generation_1 = generation_pointer(1, 0x01);
        let generation_2 = generation_pointer(2, 0x02);

        // Legitimate first switch: 1 -> 2.
        let first_switch = GenerationPointerSwitchProposalV1 {
            schema_version: CHUNK_IDENTITY_SCHEMA_VERSION,
            expected_prior_pointer: generation_1.clone(),
            proposed_pointer: generation_2.clone(),
            coverage_verification_digest: digest_of(0x77),
            determinism_verification_digest: digest_of(0x88),
        };
        assert!(AdmittedGenerationSwitchV1::from_test_witness(first_switch, &generation_1).is_ok());

        // Late old-generation work still proposes a switch expecting
        // generation 1 as prior, but the real current pointer has already
        // advanced to generation 2: it must fail, not reclaim the pointer.
        let late_stale_proposal = GenerationPointerSwitchProposalV1 {
            schema_version: CHUNK_IDENTITY_SCHEMA_VERSION,
            expected_prior_pointer: generation_1,
            proposed_pointer: generation_pointer(2, 0x03),
            coverage_verification_digest: digest_of(0x77),
            determinism_verification_digest: digest_of(0x88),
        };
        assert_eq!(
            AdmittedGenerationSwitchV1::from_test_witness(late_stale_proposal, &generation_2)
                .unwrap_err(),
            ContractError::StaleRegistryHead
        );
    }

    #[test]
    fn generation_switch_rejects_a_non_advancing_sequence() {
        let generation_1 = generation_pointer(1, 0x01);
        let proposal = GenerationPointerSwitchProposalV1 {
            schema_version: CHUNK_IDENTITY_SCHEMA_VERSION,
            expected_prior_pointer: generation_1,
            proposed_pointer: generation_pointer(1, 0x02),
            coverage_verification_digest: digest_of(0x77),
            determinism_verification_digest: digest_of(0x88),
        };
        assert!(proposal.validate().is_err());
    }

    #[test]
    fn generation_switch_rejects_a_sequence_that_would_overflow_to_the_advancing_value() {
        // `expected_prior_pointer.generation_sequence` is `pub u64` and can
        // be hydrated from storage at `u64::MAX` (not reachable through
        // `decode_strict`'s canonical-integer cap, but reachable once a
        // pointer has been round-tripped through a runtime store). An
        // unchecked `+ 1` would wrap to 0 and a proposal advancing to
        // sequence 0 would then satisfy a same-value check, admitting a
        // generation rollback; `checked_add` must reject it instead.
        let rollback_proposal = GenerationPointerSwitchProposalV1 {
            schema_version: CHUNK_IDENTITY_SCHEMA_VERSION,
            expected_prior_pointer: generation_pointer(u64::MAX, 0x01),
            proposed_pointer: generation_pointer(0, 0x02),
            coverage_verification_digest: digest_of(0x77),
            determinism_verification_digest: digest_of(0x88),
        };
        assert!(rollback_proposal.validate().is_err());
    }

    #[test]
    fn erasure_removes_occurrence_immediately_and_predicate_flips_when_last_reference_gone() {
        let occurrence_a = occurrence(0, 0x22).occurrence_id().unwrap();
        let occurrence_b = occurrence(1, 0x22).occurrence_id().unwrap();
        let mut references = vec![occurrence_a, occurrence_b];
        references.sort();
        let state = BodyReferenceStateV1 {
            schema_version: CHUNK_IDENTITY_SCHEMA_VERSION,
            body_content_id: body_digest(b"extracted body text"),
            lawful_referencing_occurrences: references,
        };
        assert!(!state.may_reclaim_shared_storage().unwrap());

        let after_first_erasure = apply_occurrence_erasure(&state, occurrence_a).unwrap();
        assert_eq!(
            after_first_erasure.lawful_referencing_occurrences,
            vec![occurrence_b]
        );
        assert!(!after_first_erasure.may_reclaim_shared_storage().unwrap());

        let after_second_erasure =
            apply_occurrence_erasure(&after_first_erasure, occurrence_b).unwrap();
        assert!(
            after_second_erasure
                .lawful_referencing_occurrences
                .is_empty()
        );
        assert!(after_second_erasure.may_reclaim_shared_storage().unwrap());
    }

    /// Reviewer ATTACK6: a state with an unknown/future `schema_version`
    /// fails `validate`, but before this fix `may_reclaim_shared_storage`
    /// ignored that and answered purely from `lawful_referencing_occurrences
    /// .is_empty()`. A record written under a schema this contract cannot
    /// interpret (e.g. a future version with a second reference class this
    /// v1 struct does not deserialize) must never be able to grant
    /// reclamation permission through this predicate: `true` is the unsafe
    /// direction, since reclaiming shared body/embedding bytes while a
    /// lawful reference this code failed to parse still exists destroys
    /// evidence irrecoverably.
    #[test]
    fn unknown_schema_version_body_reference_state_cannot_yield_a_reclaim_permitted_answer() {
        let future_schema_state = BodyReferenceStateV1 {
            schema_version: 99,
            body_content_id: Sha256Digest::ZERO,
            lawful_referencing_occurrences: vec![],
        };
        assert!(future_schema_state.validate().is_err());
        assert!(future_schema_state.may_reclaim_shared_storage().is_err());
    }

    #[test]
    fn body_reference_state_rejects_unsorted_occurrence_set() {
        let occurrence_a = occurrence(0, 0x22).occurrence_id().unwrap();
        let occurrence_b = occurrence(1, 0x22).occurrence_id().unwrap();
        let mut unsorted = vec![occurrence_a, occurrence_b];
        if unsorted[0] < unsorted[1] {
            unsorted.reverse();
        }
        let state = BodyReferenceStateV1 {
            schema_version: CHUNK_IDENTITY_SCHEMA_VERSION,
            body_content_id: body_digest(b"extracted body text"),
            lawful_referencing_occurrences: unsorted,
        };
        assert!(state.validate().is_err());
    }

    /// Freezes every `contracts/dynamic-memory/v3/chunk-identity/` fixture:
    /// raw file bytes, canonical-form self-check, and recomputed identity
    /// digest are all pinned against hardcoded constants. See that
    /// directory's README.md for what each vector proves.
    mod fixture_pinning {
        use super::*;
        use crate::memory_contracts::canonical::{decode_strict, require_canonical};

        const PARSER_KEY_FIXTURE: &[u8] =
            include_bytes!("../../contracts/dynamic-memory/v3/chunk-identity/parser-key-v1.jsonl");
        const OCCURRENCE_FIXTURE: &[u8] = include_bytes!(
            "../../contracts/dynamic-memory/v3/chunk-identity/chunk-occurrence-v1.jsonl"
        );
        const MANIFEST_FIXTURE: &[u8] = include_bytes!(
            "../../contracts/dynamic-memory/v3/chunk-identity/parse-run-manifest-v1.jsonl"
        );
        const SUPERSESSION_FIXTURE: &[u8] = include_bytes!(
            "../../contracts/dynamic-memory/v3/chunk-identity/manifest-supersession-v1.jsonl"
        );
        const GENERATION_POINTER_FIXTURE: &[u8] = include_bytes!(
            "../../contracts/dynamic-memory/v3/chunk-identity/generation-pointer-v1.jsonl"
        );
        const SWITCH_PROPOSAL_FIXTURE: &[u8] = include_bytes!(
            "../../contracts/dynamic-memory/v3/chunk-identity/generation-pointer-switch-proposal-v1.jsonl"
        );
        const EMBEDDING_BODY_FIXTURE: &[u8] = include_bytes!(
            "../../contracts/dynamic-memory/v3/chunk-identity/embedding-identity-body-v1.jsonl"
        );
        const EMBEDDING_OCCURRENCE_FIXTURE: &[u8] = include_bytes!(
            "../../contracts/dynamic-memory/v3/chunk-identity/embedding-identity-occurrence-v1.jsonl"
        );
        const STORAGE_IDENTITY_FIXTURE: &[u8] = include_bytes!(
            "../../contracts/dynamic-memory/v3/chunk-identity/storage-identity-v1.jsonl"
        );
        const BODY_REFERENCE_STATE_FIXTURE: &[u8] = include_bytes!(
            "../../contracts/dynamic-memory/v3/chunk-identity/body-reference-state-v1.jsonl"
        );
        const NEGATIVE_MANIFEST_ID_FIXTURE: &[u8] = include_bytes!(
            "../../contracts/dynamic-memory/v3/chunk-identity/negative-manifest-id-inside-occurrence.jsonl"
        );
        const NEGATIVE_LINE_FIXTURE: &[u8] = include_bytes!(
            "../../contracts/dynamic-memory/v3/chunk-identity/negative-line-number-field.jsonl"
        );
        const NEGATIVE_EMPTY_SPAN_FIXTURE: &[u8] = include_bytes!(
            "../../contracts/dynamic-memory/v3/chunk-identity/negative-empty-span.jsonl"
        );
        const NEGATIVE_OVERLAP_FIXTURE: &[u8] = include_bytes!(
            "../../contracts/dynamic-memory/v3/chunk-identity/negative-overlapping-spans.jsonl"
        );
        const NEGATIVE_UNSORTED_FIXTURE: &[u8] = include_bytes!(
            "../../contracts/dynamic-memory/v3/chunk-identity/negative-unsorted-spans.jsonl"
        );
        const NEGATIVE_UNKNOWN_FLAG_FIXTURE: &[u8] = include_bytes!(
            "../../contracts/dynamic-memory/v3/chunk-identity/negative-unknown-normalization-flag.jsonl"
        );
        const NEGATIVE_EMBEDDING_EXTRA_FIELD_FIXTURE: &[u8] = include_bytes!(
            "../../contracts/dynamic-memory/v3/chunk-identity/negative-embedding-input-extra-field.jsonl"
        );
        const NEGATIVE_DEGENERATE_POINTER_FIXTURE: &[u8] = include_bytes!(
            "../../contracts/dynamic-memory/v3/chunk-identity/negative-degenerate-generation-pointer.jsonl"
        );
        const VECTOR_SUITE_FIXTURE: &[u8] =
            include_bytes!("../../contracts/dynamic-memory/v3/chunk-identity/vector-suite.jsonl");

        const PARSER_KEY_RAW_SHA256: &str =
            "825ba35ceb22ba74bbe77140c037c84c0f58dcdc9d4f2456f2f5fc3d83c9e8b6";
        const OCCURRENCE_RAW_SHA256: &str =
            "b7dde66c3d2fd1723b8b5378a1e77a176a50ed0590a777112f5c5796c887784c";
        const MANIFEST_RAW_SHA256: &str =
            "4cbde9c0f3a287c163c50fdd713da070697328b8ec6985c38205311b03f14eaf";
        const SUPERSESSION_RAW_SHA256: &str =
            "918f4bfc5259b1d288387cdc6887a0d46fa67e4dadfc2a40e1f07d713e8d801c";
        const GENERATION_POINTER_RAW_SHA256: &str =
            "b812cb9ec9bfbae5d691b8ac6cfd272f676a7a562ab1339c37325d355273d2a8";
        const SWITCH_PROPOSAL_RAW_SHA256: &str =
            "9ca92966eeef6c1f6ee16d365b9ab51e25bc19e0ae043d511af762df1cb84f94";
        const EMBEDDING_BODY_RAW_SHA256: &str =
            "ddfe5ee574b260fa6710977bf7455fa0a19020b07505f5997e4ab2e1bf28a6de";
        const EMBEDDING_OCCURRENCE_RAW_SHA256: &str =
            "260ed5292c12e90a4602444b9e04951fc1d26c09feb6b8cad4871a882bce6b70";
        const STORAGE_IDENTITY_RAW_SHA256: &str =
            "1b8b5351790723a5a76c6662b0010a6dc7b69a50811932799f7835b3816fbb6c";
        const BODY_REFERENCE_STATE_RAW_SHA256: &str =
            "f2eb6243224df1250c533846c80e7122a03a801e1ee3727ae5953c7361d4daa1";
        const NEGATIVE_MANIFEST_ID_RAW_SHA256: &str =
            "95c625f3300e74e1218c7e9790e4a29b11d26596c96f150c91f43e2df26f4f10";
        const NEGATIVE_LINE_RAW_SHA256: &str =
            "f3f2fabefa0ddd702f58d380b6a29e735a9abf96607059483da3cc2e311f3da6";
        const NEGATIVE_EMPTY_SPAN_RAW_SHA256: &str =
            "331ab92aeff614002ef6a22dc58cf75c1e0d6b92f482532b329fae836f2edfe4";
        const NEGATIVE_OVERLAP_RAW_SHA256: &str =
            "39d92486f39b2dfc5b4254151bc93d6620fb6d19c92add84fcd9208af549c83b";
        const NEGATIVE_UNSORTED_RAW_SHA256: &str =
            "e0233a8818df79a1b7a806e0eed5102ca2984954eebf1c5a96e1cee04d6af182";
        const NEGATIVE_UNKNOWN_FLAG_RAW_SHA256: &str =
            "f7d6b4107427cd9e52d0ebb5631d4484ee9241033644c7bb2451721c50275ef5";
        const NEGATIVE_EMBEDDING_EXTRA_FIELD_RAW_SHA256: &str =
            "88a031718b3daa83dc3993966e4e86f2b3616a81f2baa9736427f2574a0e3daa";
        const NEGATIVE_DEGENERATE_POINTER_RAW_SHA256: &str =
            "05da6417540a485eebd6ff2503ee2b8c2bfb78802b2e66a12ca01cdba8bde9ee";
        const VECTOR_SUITE_RAW_SHA256: &str =
            "b6b0c341b74f1648c6583b812b637220f497a4c26292ae0ae24af624a0d67d53";

        const PARSER_KEY_ID: &str =
            "dabca33866e026b582a8e58a7721b5e5ae222bbef2ba7f72b77f8621df79ffd1";
        const OCCURRENCE_ID: &str =
            "eef3a0739aeee8057cd0aeaa417946f8358c75d769fdea9438ee147d85b63c83";
        const MANIFEST_ID: &str =
            "33bd2ea3f050020ca616593be82bb70c85d0177cde1d507cb6866565b361b9e4";
        const SUPERSESSION_ID: &str =
            "ac3114392112930133c5b8ed105e0ea120e38f0156345488b8543190ffb5e66e";
        const GENERATION_1_ID: &str =
            "17a2c60b8e5191e6e93459825f13f7a7ad3a76c7b439a26c2aadef74241fc5c1";
        const GENERATION_2_ID: &str =
            "f68101c36dfae0d4a18d4593daa03f12700be98d5786e031690028c4ccfa39ab";
        const EMBEDDING_BODY_ID: &str =
            "9feff2ba8eafe9f35367b320432b86ecdf09936b2aebc1c3dd7a064b1681b0e4";
        const EMBEDDING_OCCURRENCE_ID: &str =
            "2e7b60ecc5a23cbafd2b325ee1074e2a461abbc1ade7dc5de9d6fa92c962c235";
        const STORAGE_IDENTITY_ID: &str =
            "c54fc20fee5a7ae9ba300700f52136f664bdf8491269e00f5da66acb725f6295";

        fn record(bytes: &[u8]) -> &[u8] {
            let body = bytes
                .strip_suffix(b"\n")
                .expect("every checked-in fixture must have exactly one framing LF");
            assert!(!body.ends_with(b"\n"));
            body
        }

        fn raw_sha256(bytes: &[u8]) -> String {
            let mut hasher = Sha256::new();
            hasher.update(bytes);
            hex::encode(hasher.finalize())
        }

        #[test]
        fn every_fixture_raw_byte_pin_is_frozen() {
            for (bytes, expected) in [
                (PARSER_KEY_FIXTURE, PARSER_KEY_RAW_SHA256),
                (OCCURRENCE_FIXTURE, OCCURRENCE_RAW_SHA256),
                (MANIFEST_FIXTURE, MANIFEST_RAW_SHA256),
                (SUPERSESSION_FIXTURE, SUPERSESSION_RAW_SHA256),
                (GENERATION_POINTER_FIXTURE, GENERATION_POINTER_RAW_SHA256),
                (SWITCH_PROPOSAL_FIXTURE, SWITCH_PROPOSAL_RAW_SHA256),
                (EMBEDDING_BODY_FIXTURE, EMBEDDING_BODY_RAW_SHA256),
                (
                    EMBEDDING_OCCURRENCE_FIXTURE,
                    EMBEDDING_OCCURRENCE_RAW_SHA256,
                ),
                (STORAGE_IDENTITY_FIXTURE, STORAGE_IDENTITY_RAW_SHA256),
                (
                    BODY_REFERENCE_STATE_FIXTURE,
                    BODY_REFERENCE_STATE_RAW_SHA256,
                ),
                (
                    NEGATIVE_MANIFEST_ID_FIXTURE,
                    NEGATIVE_MANIFEST_ID_RAW_SHA256,
                ),
                (NEGATIVE_LINE_FIXTURE, NEGATIVE_LINE_RAW_SHA256),
                (NEGATIVE_EMPTY_SPAN_FIXTURE, NEGATIVE_EMPTY_SPAN_RAW_SHA256),
                (NEGATIVE_OVERLAP_FIXTURE, NEGATIVE_OVERLAP_RAW_SHA256),
                (NEGATIVE_UNSORTED_FIXTURE, NEGATIVE_UNSORTED_RAW_SHA256),
                (
                    NEGATIVE_UNKNOWN_FLAG_FIXTURE,
                    NEGATIVE_UNKNOWN_FLAG_RAW_SHA256,
                ),
                (
                    NEGATIVE_EMBEDDING_EXTRA_FIELD_FIXTURE,
                    NEGATIVE_EMBEDDING_EXTRA_FIELD_RAW_SHA256,
                ),
                (
                    NEGATIVE_DEGENERATE_POINTER_FIXTURE,
                    NEGATIVE_DEGENERATE_POINTER_RAW_SHA256,
                ),
                (VECTOR_SUITE_FIXTURE, VECTOR_SUITE_RAW_SHA256),
            ] {
                assert_eq!(raw_sha256(bytes), expected);
            }
        }

        #[test]
        fn every_positive_fixture_is_already_canonical_bytes() {
            for bytes in [
                PARSER_KEY_FIXTURE,
                OCCURRENCE_FIXTURE,
                MANIFEST_FIXTURE,
                SUPERSESSION_FIXTURE,
                GENERATION_POINTER_FIXTURE,
                SWITCH_PROPOSAL_FIXTURE,
                EMBEDDING_BODY_FIXTURE,
                EMBEDDING_OCCURRENCE_FIXTURE,
                STORAGE_IDENTITY_FIXTURE,
                BODY_REFERENCE_STATE_FIXTURE,
                VECTOR_SUITE_FIXTURE,
            ] {
                require_canonical(record(bytes)).unwrap();
            }
        }

        #[test]
        fn parser_key_fixture_identity_is_pinned() {
            let decoded: ParserKeyV1 = decode_strict(record(PARSER_KEY_FIXTURE)).unwrap();
            assert_eq!(decoded.key_digest().unwrap().to_string(), PARSER_KEY_ID);
        }

        #[test]
        fn occurrence_fixture_identity_is_pinned() {
            let decoded: ChunkOccurrencePreimageV1 =
                decode_strict(record(OCCURRENCE_FIXTURE)).unwrap();
            assert_eq!(decoded.occurrence_id().unwrap().to_string(), OCCURRENCE_ID);
        }

        #[test]
        fn manifest_fixture_identity_is_pinned() {
            let decoded: ParseRunManifestPreimageV1 =
                decode_strict(record(MANIFEST_FIXTURE)).unwrap();
            assert_eq!(decoded.manifest_id().unwrap().to_string(), MANIFEST_ID);
            assert_eq!(
                decoded.occurrence_ids[0].to_string(),
                OCCURRENCE_ID,
                "the manifest must cite the already-computed occurrence ID"
            );
        }

        #[test]
        fn supersession_fixture_identity_is_pinned() {
            let decoded: ManifestSupersessionV1 =
                decode_strict(record(SUPERSESSION_FIXTURE)).unwrap();
            assert_eq!(
                decoded.supersession_id().unwrap().to_string(),
                SUPERSESSION_ID
            );
            assert_eq!(decoded.predecessor_manifest_id.to_string(), MANIFEST_ID);
        }

        #[test]
        fn generation_pointer_fixture_identity_is_pinned() {
            let decoded: GenerationPointerV1 =
                decode_strict(record(GENERATION_POINTER_FIXTURE)).unwrap();
            assert_eq!(decoded.pointer_id().unwrap().to_string(), GENERATION_1_ID);
        }

        #[test]
        fn switch_proposal_fixture_is_internally_consistent_with_the_pointer_fixture() {
            let current: GenerationPointerV1 =
                decode_strict(record(GENERATION_POINTER_FIXTURE)).unwrap();
            let proposal: GenerationPointerSwitchProposalV1 =
                decode_strict(record(SWITCH_PROPOSAL_FIXTURE)).unwrap();
            proposal.checked_against(&current).unwrap();
        }

        #[test]
        fn embedding_identity_fixtures_are_pinned_and_selector_distinct() {
            let body: EmbeddingIdentityPreimageV1 =
                decode_strict(record(EMBEDDING_BODY_FIXTURE)).unwrap();
            let occurrence: EmbeddingIdentityPreimageV1 =
                decode_strict(record(EMBEDDING_OCCURRENCE_FIXTURE)).unwrap();
            assert_eq!(
                body.embedding_identity_id().unwrap().to_string(),
                EMBEDDING_BODY_ID
            );
            assert_eq!(
                occurrence.embedding_identity_id().unwrap().to_string(),
                EMBEDDING_OCCURRENCE_ID
            );
            assert_ne!(EMBEDDING_BODY_ID, EMBEDDING_OCCURRENCE_ID);
        }

        #[test]
        fn storage_identity_fixture_is_pinned() {
            let decoded: StorageIdentityPreimageV1 =
                decode_strict(record(STORAGE_IDENTITY_FIXTURE)).unwrap();
            assert_eq!(
                decoded.storage_identity().unwrap().to_string(),
                STORAGE_IDENTITY_ID
            );
        }

        #[test]
        fn body_reference_state_fixture_has_two_lawful_references() {
            let decoded: BodyReferenceStateV1 =
                decode_strict(record(BODY_REFERENCE_STATE_FIXTURE)).unwrap();
            decoded.validate().unwrap();
            assert_eq!(decoded.lawful_referencing_occurrences.len(), 2);
            assert!(!decoded.may_reclaim_shared_storage().unwrap());
        }

        /// `vector-suite.jsonl` is a restatement, not an independent source
        /// of truth: every field it carries must be recomputable from a
        /// checked-in preimage fixture (or a value already pinned above) and
        /// this test is that recomputation. A digest with no preimage
        /// anywhere in the repository cannot be falsified by any test, so it
        /// must not appear here at all — see README.md, "How digests are
        /// pinned".
        #[test]
        fn vector_suite_fixture_restates_only_recomputable_digests_and_all_match() {
            let value: serde_json::Value =
                serde_json::from_slice(record(VECTOR_SUITE_FIXTURE)).unwrap();
            let obj = value.as_object().unwrap();
            let get = |key: &str| obj.get(key).unwrap().as_str().unwrap();

            assert_eq!(get("parser_key_id"), PARSER_KEY_ID);
            assert_eq!(get("occurrence_id"), OCCURRENCE_ID);
            assert_eq!(get("manifest_id"), MANIFEST_ID);
            assert_eq!(get("supersession_id"), SUPERSESSION_ID);
            assert_eq!(get("generation_1_id"), GENERATION_1_ID);
            assert_eq!(get("embedding_body_id"), EMBEDDING_BODY_ID);
            assert_eq!(get("embedding_occurrence_id"), EMBEDDING_OCCURRENCE_ID);
            assert_eq!(get("storage_identity_id"), STORAGE_IDENTITY_ID);

            // body_content_id is recomputable: it is the occurrence
            // fixture's own field, independently decoded here rather than
            // trusted from vector-suite.jsonl alone.
            let occurrence: ChunkOccurrencePreimageV1 =
                decode_strict(record(OCCURRENCE_FIXTURE)).unwrap();
            assert_eq!(
                get("body_content_id"),
                occurrence.body_content_id.to_string()
            );

            // generation_2_id is recomputable: it is pointer_id() of the
            // switch-proposal fixture's own proposed_pointer.
            let proposal: GenerationPointerSwitchProposalV1 =
                decode_strict(record(SWITCH_PROPOSAL_FIXTURE)).unwrap();
            let recomputed_generation_2_id =
                proposal.proposed_pointer.pointer_id().unwrap().to_string();
            assert_eq!(recomputed_generation_2_id, GENERATION_2_ID);
            assert_eq!(get("generation_2_id"), recomputed_generation_2_id);

            // The closed list of this directory's negative fixture stems.
            let negative_cases: Vec<&str> = obj["negative_cases"]
                .as_array()
                .unwrap()
                .iter()
                .map(|entry| entry.as_str().unwrap())
                .collect();
            assert_eq!(
                negative_cases,
                vec![
                    "degenerate_generation_pointer",
                    "embedding_input_extra_field",
                    "empty_span",
                    "line_number_field",
                    "manifest_id_inside_occurrence",
                    "overlapping_spans",
                    "unknown_normalization_flag",
                    "unsorted_spans",
                ]
            );

            // parser_key_v2_id / occurrence_v2_id / manifest_v2_id were
            // removed: no checked-in v3 fixture computes a "generation 2"
            // ParserKeyV1/ChunkOccurrencePreimageV1/ParseRunManifestPreimageV1,
            // so restating hardcoded digests for them here would be an
            // unfalsifiable claim no test could ever catch drifting stale.
            assert!(!obj.contains_key("parser_key_v2_id"));
            assert!(!obj.contains_key("occurrence_v2_id"));
            assert!(!obj.contains_key("manifest_v2_id"));
        }

        #[test]
        fn negative_fixtures_reject_an_unrecognized_field_at_decode_time() {
            // `manifest_id` and `line` are not fields of
            // `ChunkOccurrencePreimageV1`: `#[serde(deny_unknown_fields)]`
            // rejects them before any semantic validation runs.
            assert!(
                decode_strict::<ChunkOccurrencePreimageV1>(record(NEGATIVE_MANIFEST_ID_FIXTURE))
                    .is_err()
            );
            assert!(
                decode_strict::<ChunkOccurrencePreimageV1>(record(NEGATIVE_LINE_FIXTURE)).is_err()
            );
        }

        /// `EmbeddingInputV1` is internally tagged (`kind` selects the
        /// arm), and before `deny_unknown_fields` was added, a JSON payload
        /// could carry the `body` arm's own `body_content_id` *and* a stray
        /// `occurrence_id` that no `EmbeddingInputV1::Body` field names: the
        /// second digest was silently dropped at decode instead of being
        /// rejected, so a selector/digest mismatch was constructible. This
        /// fixture pins that it is now rejected at decode time, before
        /// `EmbeddingIdentityPreimageV1::validate` ever runs.
        #[test]
        fn negative_fixture_rejects_a_stray_digest_alongside_the_selected_embedding_input_arm() {
            assert!(
                decode_strict::<EmbeddingIdentityPreimageV1>(record(
                    NEGATIVE_EMBEDDING_EXTRA_FIELD_FIXTURE
                ))
                .is_err()
            );
        }

        /// This fixture is a structurally well-formed `GenerationPointerV1`
        /// (no unrecognized field), so `decode_strict` succeeds; it is the
        /// all-zero, sequence-0 degenerate pointer that
        /// `GenerationPointerV1::validate` must reject, unlike a decode-only
        /// check. A degenerate pointer must never be admissible as either
        /// the `expected_prior_pointer` or the `proposed_pointer` of a CAS
        /// switch.
        #[test]
        fn negative_fixture_rejects_the_degenerate_all_zero_generation_pointer() {
            let decoded: GenerationPointerV1 =
                decode_strict(record(NEGATIVE_DEGENERATE_POINTER_FIXTURE)).unwrap();
            assert!(decoded.validate().is_err());
            assert!(decoded.pointer_id().is_err());
        }

        #[test]
        fn negative_fixtures_reject_an_unrecognized_enum_variant_at_decode_time() {
            // The closed `NormalizationRuleV1` set has no `not_a_real_rule`
            // variant: this fails during `serde` struct decode, before
            // `ParserKeyV1::validate` ever runs.
            assert!(decode_strict::<ParserKeyV1>(record(NEGATIVE_UNKNOWN_FLAG_FIXTURE)).is_err());
        }

        #[test]
        fn negative_fixtures_decode_structurally_but_fail_span_validation() {
            // These three fixtures are structurally well-formed
            // `ChunkOccurrencePreimageV1` records (no unrecognized field, no
            // unrecognized enum variant), so `decode_strict` succeeds; the
            // defect is semantic and is caught only by
            // `validate_span_list` inside `ChunkOccurrencePreimageV1::validate`.
            for bytes in [
                NEGATIVE_EMPTY_SPAN_FIXTURE,
                NEGATIVE_OVERLAP_FIXTURE,
                NEGATIVE_UNSORTED_FIXTURE,
            ] {
                let decoded: ChunkOccurrencePreimageV1 = decode_strict(record(bytes)).unwrap();
                assert!(decoded.validate().is_err());
                assert!(decoded.occurrence_id().is_err());
            }
        }
    }
}
