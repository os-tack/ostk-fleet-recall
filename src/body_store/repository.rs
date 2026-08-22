//! Repository contract and persisted row shapes for the body projection.

use async_trait::async_trait;

use crate::memory_contracts::evidence_v2::EvidenceStatementV2;

use super::error::BodyProjectionResult;

/// The `ledger_family` value every body-projection watermark carries.
///
/// Evidence events are appended only through the general accepted-event
/// (evidence) ledger, so this is the only value this module ever writes; the
/// watermark column's CHECK also admits `'control'` for a lane this module does
/// not use.
pub const WATERMARK_LEDGER_FAMILY: &str = "evidence";

/// Resolves the exact source-object bytes an accepted evidence event attests.
///
/// This is the one seam between the body projector and the content plane. In
/// production it is backed by the governed content store
/// ([`crate::evidence_ledger::fetch_governed_content`]), which decrypts the
/// per-object bytes under the configured key-encryption key; the projector then
/// verifies those bytes reproduce the digest the accepted evidence committed to
/// before deriving any identity. Isolating it behind this trait keeps the
/// projector — its identities, idempotency, fail-closed collision handling, and
/// cursor atomicity — testable as ordinary software without standing up the
/// encrypted content store.
#[async_trait]
pub trait SourceContentResolver: Send + Sync {
    /// Return the exact canonical source bytes for `statement`.
    ///
    /// Implementations return [`crate::body_store::BodyProjectionError::MissingSourceContent`]
    /// when no bytes are available; the projector then fails the event closed
    /// and leaves the cursor unadvanced for retry.
    async fn resolve(&self, statement: &EvidenceStatementV2) -> BodyProjectionResult<Vec<u8>>;
}

/// One persisted `memory_body_projection_watermarks_v1` row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BodyProjectionWatermarkV1 {
    /// Evidence shard this cursor tracks.
    pub shard: u16,
    /// Highest committed offset durably projected on this shard.
    pub last_committed_offset: u64,
}

/// One persisted `memory_generation_pointers_v1` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerationPointerRowV1 {
    /// The source representation this pointer governs.
    pub source_representation_uri: String,
    /// Active parser generation sequence.
    pub generation_sequence: u64,
}

/// `(content_sha256, body_bytes)` snapshot tuple.
pub type SnapshotBodyRowV1 = (Vec<u8>, Vec<u8>);
/// `(occurrence_id, canonical_preimage, generation_sequence)` snapshot tuple.
pub type SnapshotOccurrenceRowV1 = (Vec<u8>, Vec<u8>, i64);
/// `(occurrence_id, span_ordinal, byte_start, byte_end, span_digest)` snapshot
/// tuple.
pub type SnapshotSpanRowV1 = (Vec<u8>, i64, i64, i64, Vec<u8>);
/// `(manifest_id, canonical_preimage, generation_sequence)` snapshot tuple.
pub type SnapshotManifestRowV1 = (Vec<u8>, Vec<u8>, i64);
/// `(source_object_version_uri, commit_revision, ref_key)` snapshot tuple.
pub type SnapshotMembershipRowV1 = (String, Vec<u8>, Vec<u8>);
/// `(source_representation_uri, active_parser_key_id, active_manifest_id,
/// generation_sequence)` snapshot tuple.
pub type SnapshotPointerRowV1 = (String, Vec<u8>, Vec<u8>, i64);

/// A deterministic, sorted snapshot of the whole body plane for one scope.
///
/// Every field is the exact byte content of the corresponding rows, sorted by
/// primary key, so two snapshots taken after two independent replays of the same
/// accepted-event log compare equal iff the projector rebuilt byte-identical
/// rows (REPLAY-01).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BodyProjectionSnapshotV1 {
    /// One row per content-addressed body, sorted by `content_sha256`.
    pub bodies: Vec<SnapshotBodyRowV1>,
    /// One row per occurrence, sorted by `occurrence_id`.
    pub occurrences: Vec<SnapshotOccurrenceRowV1>,
    /// One row per span, sorted by `(occurrence_id, span_ordinal)`.
    pub spans: Vec<SnapshotSpanRowV1>,
    /// One row per manifest, sorted by `manifest_id`.
    pub manifests: Vec<SnapshotManifestRowV1>,
    /// One row per commit-membership entry, sorted lexicographically.
    pub commit_membership: Vec<SnapshotMembershipRowV1>,
    /// One row per generation pointer, sorted by source representation URI.
    pub generation_pointers: Vec<SnapshotPointerRowV1>,
}

/// What one projection pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProjectionRunSummaryV1 {
    /// Accepted evidence events consumed in this pass.
    pub events_projected: u64,
    /// Occurrence rows the pass derived (including idempotent re-derivations).
    pub occurrences_derived: u64,
    /// Shadow generations opened in this pass (a parser upgrade per source).
    pub shadow_generations_opened: u64,
}

/// Append-side surface of the body projection, bound once to physical scope.
#[async_trait]
pub trait BodyProjectionRepository: Send + Sync {
    /// Consume every accepted evidence event past the per-shard cursor under the
    /// repository's active parser key, writing content-addressed body,
    /// occurrence, span, manifest, and commit-membership rows and advancing the
    /// cursor — each event in ONE serializable transaction (REPLAY-02).
    async fn project_pending(&self) -> BodyProjectionResult<ProjectionRunSummaryV1>;

    /// Re-derive from the entire accepted evidence log regardless of the cursor,
    /// under the repository's active parser key. Used both to rebuild from empty
    /// (REPLAY-01) and to open a shadow generation after a parser upgrade
    /// (the prior generation's rows are never mutated).
    async fn reproject_all(&self) -> BodyProjectionResult<ProjectionRunSummaryV1>;
}
