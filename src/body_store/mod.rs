//! Content-addressed body/occurrence/parse-manifest projection (W2-BODY).
//!
//! This module is the runtime that turns the accepted evidence-event stream
//! (`W1-EVID`, `memory_evidence_events`) into migration 0019's private-plane
//! body tables. It consumes each admitted `evidence.accepted` event, resolves
//! the exact source-object bytes that event attests, runs a deterministic
//! parser over them, and writes:
//!
//! * content-addressed bodies (`memory_body_objects_v1`, keyed by
//!   `body_digest`),
//! * chunk occurrences and their raw-source spans
//!   (`memory_chunk_occurrences_v1`, `memory_chunk_occurrence_spans_v1`),
//! * one parse-run manifest per source representation
//!   (`memory_parse_run_manifests_v1`),
//! * commit/ref membership (`memory_source_commit_membership_v1`),
//! * and the current parser generation pointer
//!   (`memory_generation_pointers_v1`),
//!
//! advancing a per-shard projector cursor
//! (`memory_body_projection_watermarks_v1`) ATOMICALLY with each event's rows.
//!
//! # Identity discipline
//!
//! Every identity is DERIVED through the frozen preimages in
//! [`crate::memory_contracts::chunk_identity`] and
//! [`crate::memory_contracts::digest::body_digest`]; this module never invents a
//! hash. A parser-key upgrade produces a SHADOW generation
//! ([`crate::memory_contracts::chunk_identity::GenerationPointerSwitchProposalV1`]
//! compare-and-swap), never an in-place rewrite of the prior generation.
//!
//! # Layout
//!
//! * [`parser`] — the deterministic reference parser and its frozen parser keys.
//! * [`projector`] — pure derivation of one event's body/occurrence/manifest
//!   rows from the frozen preimages (no database access).
//! * [`repository`] — the [`repository::BodyProjectionRepository`] trait, the
//!   [`repository::SourceContentResolver`] seam, and the persisted row shapes.
//! * [`cockroach`] — the `CockroachDB` implementation: cursor-driven,
//!   idempotent, fail-closed on integrity collisions, one serializable
//!   transaction per event.

mod cockroach;
mod error;
mod governed_resolver;
mod parser;
mod projector;
mod repository;

pub use cockroach::CockroachBodyProjectionRepository;
pub use error::{BodyProjectionError, BodyProjectionResult};
pub use governed_resolver::GovernedContentResolver;
pub use parser::{
    LINE_PARSER_VERSION, PARAGRAPH_PARSER_VERSION, ParsedSegmentV1, parse_source,
    reference_parser_key_v1, reference_parser_key_v2,
};
pub use projector::{
    DerivedBodyV1, DerivedCommitMembershipV1, DerivedManifestV1, DerivedOccurrenceV1,
    DerivedParseRunV1, check_shadow_generation_switch, derive_parse_run, generation_pointer,
};
pub use repository::{
    BodyProjectionRepository, BodyProjectionSnapshotV1, BodyProjectionWatermarkV1,
    GenerationPointerRowV1, ProjectionRunSummaryV1, SourceContentResolver, WATERMARK_LEDGER_FAMILY,
};
