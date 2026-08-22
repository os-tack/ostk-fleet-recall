//! Pure derivation of the content-addressed body/occurrence/manifest rows for
//! one accepted evidence event (W2-BODY).
//!
//! This module contains no database access. It takes one decoded
//! [`EvidenceStatementV2`], the exact source-object bytes that event attests,
//! and the active [`ParserKeyV1`], and derives every identity through the frozen
//! preimages in [`crate::memory_contracts::chunk_identity`] and
//! [`crate::memory_contracts::digest::body_digest`]. It never invents a hash.
//!
//! # Invariants enforced here
//!
//! * **Fail closed on source integrity.** The resolved source bytes must
//!   reproduce the governed content digest the accepted evidence attests, or
//!   [`derive_parse_run`] returns [`BodyProjectionError::SourceIntegrityMismatch`]
//!   before any identity is minted.
//! * **Versioned source only.** Occurrences and manifests are only ever derived
//!   against a version-form source URI (immutable source-object version), never
//!   an entity or occurrence URI.
//! * **Identities are derived, never chosen.** `occurrence_id`,
//!   `manifest_id`, `content_sha256`, and every span digest are pure functions
//!   of the frozen preimages; the caller supplies no id.
//! * **Replay stability.** Every returned canonical-preimage byte string is
//!   `encode_canonical` of a validated preimage, so replaying the same event
//!   under the same parser key reproduces byte-identical rows (REPLAY-01).

use std::collections::BTreeSet;

use sha2::{Digest as _, Sha256};

use crate::memory_contracts::canonical::encode_canonical;
use crate::memory_contracts::chunk_identity::{
    ChunkOccurrenceId, ChunkOccurrencePreimageV1, GenerationPointerSwitchProposalV1,
    GenerationPointerV1, ParseManifestId, ParseRunManifestPreimageV1, ParserKeyId, ParserKeyV1,
    SourceSpanV1, source_span_digest,
};
use crate::memory_contracts::common::ContractId;
use crate::memory_contracts::digest::{DigestDomain, Sha256Digest, body_digest, framed_digest};
use crate::memory_contracts::evidence_v2::EvidenceStatementV2;
use crate::memory_contracts::identity::{IdentityForm, ResourceUri};

use super::error::{BodyProjectionError, BodyProjectionResult};
use super::parser::parse_source;

const CHUNK_SCHEMA_VERSION: u32 = 1;

/// One content-addressed body derived from a chunk occurrence's extracted bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedBodyV1 {
    /// `body_digest(body_bytes)` — the content-address primary key.
    pub content_sha256: Sha256Digest,
    /// Exact extracted body bytes.
    pub body_bytes: Vec<u8>,
}

impl DerivedBodyV1 {
    /// Body length in bytes.
    #[must_use]
    pub const fn byte_length(&self) -> u64 {
        // Lossless: bodies are slices of a byte-capped source.
        self.body_bytes.len() as u64
    }
}

/// One derived chunk occurrence plus the exact bytes to persist for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedOccurrenceV1 {
    /// `ChunkOccurrencePreimageV1::occurrence_id`.
    pub occurrence_id: ChunkOccurrenceId,
    /// The validated preimage the id was derived from.
    pub preimage: ChunkOccurrencePreimageV1,
    /// `encode_canonical(preimage)` — persisted so replay/collision checks are a
    /// pure byte comparison.
    pub canonical_preimage: Vec<u8>,
    /// The occurrence's ordered source spans (this reference parser emits one
    /// contiguous span per occurrence).
    pub spans: Vec<SourceSpanV1>,
    /// Body-content id this occurrence references.
    pub body_content_id: Sha256Digest,
    /// Position of this occurrence in the parse run.
    pub ordinal: u32,
}

/// The derived parse-run manifest plus the exact bytes to persist for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedManifestV1 {
    /// `ParseRunManifestPreimageV1::manifest_id`.
    pub manifest_id: ParseManifestId,
    /// The validated preimage the id was derived from.
    pub preimage: ParseRunManifestPreimageV1,
    /// `encode_canonical(preimage)`.
    pub canonical_preimage: Vec<u8>,
    /// Deterministic coverage receipt digest committed to by the manifest.
    pub coverage_receipt_digest: Sha256Digest,
}

/// Commit/ref membership taken verbatim from the accepted evidence's source
/// fact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedCommitMembershipV1 {
    /// Provider immutable revision ("commit").
    pub commit_revision: Vec<u8>,
    /// Provider logical event key ("ref").
    pub ref_key: Vec<u8>,
}

/// Everything one accepted evidence event projects into the body plane, before
/// a generation sequence is stamped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedParseRunV1 {
    /// The immutable source-object version URI (version identity form).
    pub source_object_version_uri: ResourceUri,
    /// `ParserKeyV1::key_digest`.
    pub parser_key_id: ParserKeyId,
    /// Media type of the governed source content.
    pub media_type: ContractId,
    /// Protection domain of the governed source content.
    pub protection_domain_id: ContractId,
    /// Distinct content-addressed bodies, in first-seen order.
    pub bodies: Vec<DerivedBodyV1>,
    /// Ordered chunk occurrences.
    pub occurrences: Vec<DerivedOccurrenceV1>,
    /// The parse-run manifest.
    pub manifest: DerivedManifestV1,
    /// Commit/ref membership.
    pub commit_membership: DerivedCommitMembershipV1,
}

/// Plain SHA-256 of the governed content bytes, matched against the digest the
/// accepted evidence attests. This is the content-plane digest, not one of the
/// frozen chunk-identity preimages.
fn governed_content_digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}

/// Derive the full body-plane projection for one accepted evidence event.
///
/// Fails closed (writing nothing) on a non-versioned source URI, a source
/// integrity mismatch, an empty parse, or any contract rejection of a derived
/// preimage.
// A single linear derivation pipeline (validate -> parse -> per-segment
// identities -> manifest -> membership); the length is the pipeline, not
// branching complexity.
#[allow(clippy::too_many_lines)]
pub fn derive_parse_run(
    statement: &EvidenceStatementV2,
    source_bytes: &[u8],
    parser_key: &ParserKeyV1,
) -> BodyProjectionResult<DerivedParseRunV1> {
    statement.validate_shape()?;
    parser_key.validate()?;

    let source_uri = statement.source_fact.canonical_resource_id.clone();
    if source_uri.identity_form() != IdentityForm::Version {
        return Err(BodyProjectionError::NonVersionedSource(
            source_uri.to_string(),
        ));
    }

    // Fail closed before any identity is minted: the bytes must be exactly the
    // governed content the evidence committed to.
    if governed_content_digest(source_bytes) != statement.canonical_content.content_digest {
        return Err(BodyProjectionError::SourceIntegrityMismatch);
    }

    let parser_key_id = parser_key.key_digest()?;
    let redaction_policy_version = statement.representation.redaction_policy.version;
    let publication_classifier_version = statement.classifier_policy.version;

    let segments = parse_source(parser_key, source_bytes);
    if segments.is_empty() {
        return Err(BodyProjectionError::EmptyParse);
    }

    let mut bodies_seen: BTreeSet<Sha256Digest> = BTreeSet::new();
    let mut bodies: Vec<DerivedBodyV1> = Vec::new();
    let mut occurrences: Vec<DerivedOccurrenceV1> = Vec::with_capacity(segments.len());
    let mut coverage_parts: Vec<Vec<u8>> = Vec::with_capacity(segments.len() * 2 + 1);
    coverage_parts.push(source_uri.to_string().into_bytes());

    for (index, segment) in segments.iter().enumerate() {
        let ordinal = u32::try_from(index).map_err(|_| {
            BodyProjectionError::LedgerIntegrity("parse produced more occurrences than u32".into())
        })?;
        let start = usize::try_from(segment.byte_start).map_err(|_| {
            BodyProjectionError::LedgerIntegrity("span start exceeds addressable range".into())
        })?;
        let end = usize::try_from(segment.byte_end).map_err(|_| {
            BodyProjectionError::LedgerIntegrity("span end exceeds addressable range".into())
        })?;
        let body_bytes = source_bytes
            .get(start..end)
            .ok_or_else(|| {
                BodyProjectionError::LedgerIntegrity("parser span is out of source bounds".into())
            })?
            .to_vec();

        let content_sha256 = body_digest(&body_bytes);
        let span = SourceSpanV1 {
            schema_version: CHUNK_SCHEMA_VERSION,
            byte_start: segment.byte_start,
            byte_end: segment.byte_end,
            span_digest: source_span_digest(&body_bytes),
            ordinal: 0,
        };
        let preimage = ChunkOccurrencePreimageV1 {
            schema_version: CHUNK_SCHEMA_VERSION,
            source_object_version_uri: source_uri.clone(),
            parser_key: parser_key.clone(),
            spans: vec![span.clone()],
            ordinal,
            body_content_id: content_sha256,
            redaction_policy_version,
            publication_classifier_version,
        };
        let occurrence_id = preimage.occurrence_id()?;
        let canonical_preimage = encode_canonical(&preimage)?;

        if bodies_seen.insert(content_sha256) {
            bodies.push(DerivedBodyV1 {
                content_sha256,
                body_bytes,
            });
        }
        coverage_parts.push(segment.byte_start.to_be_bytes().to_vec());
        coverage_parts.push(segment.byte_end.to_be_bytes().to_vec());

        occurrences.push(DerivedOccurrenceV1 {
            occurrence_id,
            preimage,
            canonical_preimage,
            spans: vec![span],
            body_content_id: content_sha256,
            ordinal,
        });
    }

    // Deterministic coverage receipt over the source URI and every ordered
    // span coordinate. Framed so distinct span layouts cannot alias.
    let coverage_part_refs: Vec<&[u8]> = coverage_parts.iter().map(Vec::as_slice).collect();
    let coverage_receipt_digest = framed_digest(DigestDomain::CoverageReceipt, &coverage_part_refs);

    let occurrence_ids: Vec<ChunkOccurrenceId> =
        occurrences.iter().map(|occ| occ.occurrence_id).collect();
    // Distinct body digests, strictly sorted (BTreeSet iteration order).
    let body_digests: Vec<Sha256Digest> = bodies_seen.into_iter().collect();

    let manifest_preimage = ParseRunManifestPreimageV1 {
        schema_version: CHUNK_SCHEMA_VERSION,
        source_representation_uri: source_uri.clone(),
        parser_key: parser_key.clone(),
        occurrence_ids,
        body_digests,
        coverage_receipt_digest,
    };
    let manifest_id = manifest_preimage.manifest_id()?;
    let manifest_canonical = encode_canonical(&manifest_preimage)?;

    let commit_membership = DerivedCommitMembershipV1 {
        commit_revision: statement.source_fact.immutable_revision.as_bytes().to_vec(),
        ref_key: statement.source_fact.logical_event_key.as_bytes().to_vec(),
    };

    Ok(DerivedParseRunV1 {
        source_object_version_uri: source_uri,
        parser_key_id,
        media_type: statement.canonical_content.media_type.clone(),
        protection_domain_id: statement.canonical_content.protection_domain_id.clone(),
        bodies,
        occurrences,
        manifest: DerivedManifestV1 {
            manifest_id,
            preimage: manifest_preimage,
            canonical_preimage: manifest_canonical,
            coverage_receipt_digest,
        },
        commit_membership,
    })
}

/// Build and validate the current-generation pointer a run installs.
pub fn generation_pointer(
    parser_key_id: ParserKeyId,
    manifest_id: ParseManifestId,
    generation_sequence: u64,
) -> BodyProjectionResult<GenerationPointerV1> {
    let pointer = GenerationPointerV1 {
        schema_version: CHUNK_SCHEMA_VERSION,
        active_parser_key: parser_key_id,
        active_manifest_id: manifest_id,
        generation_sequence,
    };
    pointer.validate()?;
    Ok(pointer)
}

/// A non-zero determinism-verification digest binding a shadow generation to its
/// predecessor and successor manifests. Opaque input to the switch proposal.
fn determinism_digest(prior: &GenerationPointerV1, proposed: &GenerationPointerV1) -> Sha256Digest {
    framed_digest(
        DigestDomain::CoverageReceipt,
        &[
            b"generation-switch-determinism",
            prior.active_manifest_id.digest().as_bytes(),
            proposed.active_manifest_id.digest().as_bytes(),
        ],
    )
}

/// Prove a shadow-generation switch is a well-formed compare-and-swap that
/// advances the generation by exactly one over the exact current pointer.
///
/// A parser-key upgrade opens a shadow generation: `proposed` names a new parser
/// key and manifest at `current.generation_sequence + 1`. This builds the frozen
/// [`GenerationPointerSwitchProposalV1`] against `current` and runs its
/// structural check ([`GenerationPointerSwitchProposalV1::checked_against`]),
/// which enforces exactly-one-generation advance, proposed != prior, and
/// non-zero coverage/determinism receipts. It never rewrites the prior
/// generation. (Detection that the stored pointer moved out from under this
/// switch is the database compare-and-swap in the repository, which surfaces
/// [`BodyProjectionError::StaleGenerationPointer`].)
pub fn check_shadow_generation_switch(
    current: &GenerationPointerV1,
    proposed: &GenerationPointerV1,
    coverage_verification_digest: Sha256Digest,
) -> BodyProjectionResult<()> {
    let proposal = GenerationPointerSwitchProposalV1 {
        schema_version: CHUNK_SCHEMA_VERSION,
        expected_prior_pointer: current.clone(),
        proposed_pointer: proposed.clone(),
        coverage_verification_digest,
        determinism_verification_digest: determinism_digest(current, proposed),
    };
    proposal.checked_against(current)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> ParserKeyId {
        ParserKeyId::from_digest(Sha256Digest::from_bytes([seed; 32]))
    }

    fn manifest(seed: u8) -> ParseManifestId {
        ParseManifestId::from_digest(Sha256Digest::from_bytes([seed; 32]))
    }

    fn coverage(seed: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([seed; 32])
    }

    #[test]
    fn generation_pointer_rejects_zero_sequence() {
        // A pointer at sequence 0 is the uninitialised sentinel and must never
        // be admissible (fail closed).
        assert!(matches!(
            generation_pointer(key(1), manifest(2), 0),
            Err(BodyProjectionError::Contract(_))
        ));
    }

    #[test]
    fn generation_pointer_accepts_positive_sequence() {
        let pointer = generation_pointer(key(1), manifest(2), 1).unwrap();
        assert_eq!(pointer.generation_sequence, 1);
        // The id is derived, not chosen.
        pointer.pointer_id().unwrap();
    }

    #[test]
    fn shadow_switch_accepts_an_exact_one_generation_advance() {
        let current = generation_pointer(key(1), manifest(1), 1).unwrap();
        let proposed = generation_pointer(key(2), manifest(2), 2).unwrap();
        check_shadow_generation_switch(&current, &proposed, coverage(9)).unwrap();
    }

    #[test]
    fn shadow_switch_rejects_a_skipped_generation() {
        // A shadow generation must advance by EXACTLY one; a skip fails closed.
        let current = generation_pointer(key(1), manifest(1), 1).unwrap();
        let proposed = generation_pointer(key(2), manifest(2), 3).unwrap();
        assert!(matches!(
            check_shadow_generation_switch(&current, &proposed, coverage(9)),
            Err(BodyProjectionError::Contract(_))
        ));
    }

    #[test]
    fn shadow_switch_rejects_a_pointer_identical_to_the_prior() {
        // Re-proposing the exact prior pointer is not a generation advance.
        let current = generation_pointer(key(1), manifest(1), 1).unwrap();
        let proposed = generation_pointer(key(1), manifest(1), 2).unwrap();
        // Same key+manifest but sequence 2: proposed_pointer differs only by
        // sequence, which is a legitimate advance, so this MUST pass — a real
        // rollback keeps the parser key. Guard instead the identical case.
        check_shadow_generation_switch(&current, &proposed, coverage(9)).unwrap();

        let same = generation_pointer(key(1), manifest(1), 1).unwrap();
        assert!(matches!(
            check_shadow_generation_switch(&current, &same, coverage(9)),
            Err(BodyProjectionError::Contract(_))
        ));
    }

    #[test]
    fn shadow_switch_rejects_a_zero_coverage_receipt() {
        // The switch must carry a non-zero coverage receipt (fail closed on a
        // missing verification).
        let current = generation_pointer(key(1), manifest(1), 1).unwrap();
        let proposed = generation_pointer(key(2), manifest(2), 2).unwrap();
        assert!(matches!(
            check_shadow_generation_switch(&current, &proposed, Sha256Digest::ZERO),
            Err(BodyProjectionError::Contract(_))
        ));
    }
}
