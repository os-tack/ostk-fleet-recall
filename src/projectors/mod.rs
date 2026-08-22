//! Lexical-first / dense-later recall projection (W2-PROJ).
//!
//! This module is the runtime that turns W2-BODY's content-addressed bodies
//! (`memory_body_objects_v1`, migration 0019) into the two searchable tiers of
//! migration 0021.
//!
//! # Why two tiers, and why in this order
//!
//! A body becomes *findable* the moment it lands, without waiting on any model.
//! The lexical projector reads a body row, normalizes its bytes into
//! deterministic text, and writes one row into
//! `memory_body_lexical_projection_v1`, whose generated `TSVECTOR` column is
//! backed by an inverted index. That path has no network dependency and no
//! failure mode beyond the database itself.
//!
//! The dense projector is a SEPARATE background worker on the private plane. It
//! reads the lexical rows (so both tiers see the same normalized input), calls
//! an [`EmbeddingProvider`], and writes `memory_body_dense_projection_v1`. It
//! can be arbitrarily far behind, or entirely absent, without changing what the
//! lexical tier answers.
//!
//! # What makes "dense never blocks lexical" structural rather than aspirational
//!
//! * The tiers occupy DIFFERENT TABLES. There is no nullable embedding column
//!   on the lexical row that a dense failure could leave half-written, and no
//!   statement in [`cockroach`] writes both tables.
//! * The tiers keep INDEPENDENT CURSORS — two rows in
//!   `memory_recall_projection_cursors_v1`, one per projector. The dense worker
//!   cannot move the lexical cursor.
//! * Each batch's rows and its own cursor advance are ONE serializable
//!   transaction, so killing the dense worker mid-batch leaves the dense tier
//!   at its last committed batch and the lexical tier untouched.
//! * The dense table's absence of a row IS the "not embedded yet" state, which
//!   is also what lets its vector index keep the equality-prefixed,
//!   NOT-NULL shape `CockroachDB`'s C-SPANN requires (migration 0001).
//!
//! # Readiness
//!
//! [`CockroachRecallReader::recall`] returns [`RecallTierV1`] (which lanes
//! answered) alongside [`RecallCompletenessV1`] (how far each tier has caught
//! up), so a caller can tell "the dense tier found nothing" from "the dense
//! tier has not run yet".
//!
//! # Layout
//!
//! * [`lexical`] — pure normalization and lexical identity, no database.
//! * [`dense`] — pure embedding identity, vector admission, and the
//!   [`EmbeddingProvider`] seam.
//! * [`repository`] — projector traits, cursor shapes, and readiness types.
//! * [`cockroach`] — the `CockroachDB` runtimes and the read side.

mod cockroach;
pub mod dense;
mod error;
pub mod lexical;
mod repository;

pub use cockroach::{
    CockroachDenseProjector, CockroachLexicalProjector, CockroachRecallReader,
    DEFAULT_PROJECTION_BATCH,
};
pub use dense::{
    DerivedEmbeddingV1, EMBEDDING_DIMENSIONS, EmbeddingModelDescriptorV1, EmbeddingProvider,
    admit_embedding, distance_metric_label, embedding_identity, embedding_identity_preimage,
    parse_distance_metric,
};
pub use error::{RecallProjectionError, RecallProjectionResult};
pub use lexical::{
    LEXICAL_NORMALIZATION_VERSION, LexicalProjectionV1, LexicalStateV1, LexicalUnindexableReasonV1,
    MAX_LEXICAL_TEXT_BYTES, derive_lexical_projection, lexical_text_digest,
};
pub use repository::{
    BodyPositionV1, DenseProjector, LexicalProjector, ProjectionCursorV1, ProjectionPassSummaryV1,
    ProjectorKindV1, RecallCompletenessV1, RecallHitV1, RecallProjectionSnapshotV1, RecallResultV1,
    RecallTierV1,
};
