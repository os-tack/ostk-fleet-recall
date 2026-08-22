//! Repository contracts, cursor shapes, and recall readiness types (W2-PROJ).

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::memory_contracts::digest::Sha256Digest;

use super::error::{RecallProjectionError, RecallProjectionResult};

/// Which projector a cursor row belongs to.
///
/// The two projectors keep INDEPENDENT cursors: one row each in
/// `memory_recall_projection_cursors_v1`. Nothing the dense worker does can
/// move the lexical cursor, and vice versa.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectorKindV1 {
    /// The synchronous, always-first lexical projector.
    Lexical,
    /// The background dense (embedding) worker.
    Dense,
}

impl ProjectorKindV1 {
    /// Exact stored `projector` value. Part of the schema contract.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Lexical => "lexical",
            Self::Dense => "dense",
        }
    }

    /// Parse a stored `projector` value. Unknown values fail closed.
    pub fn parse(value: &str) -> RecallProjectionResult<Self> {
        match value {
            "lexical" => Ok(Self::Lexical),
            "dense" => Ok(Self::Dense),
            other => Err(RecallProjectionError::ProjectionIntegrity(format!(
                "stored cursor names an unknown projector: {other}"
            ))),
        }
    }
}

/// The position both projectors scan `memory_body_objects_v1` in.
///
/// `(created_at, content_sha256)` is a total order over the body plane, so a
/// cursor at one of these pairs names exactly one resumption point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BodyPositionV1 {
    /// `memory_body_objects_v1.created_at` of the last consumed body.
    pub created_at: DateTime<Utc>,
    /// `memory_body_objects_v1.content_sha256` of the last consumed body.
    pub content_id: Sha256Digest,
}

/// One persisted `memory_recall_projection_cursors_v1` row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProjectionCursorV1 {
    /// Which projector this cursor belongs to.
    pub projector: ProjectorKindV1,
    /// Last body position a committed batch consumed.
    pub position: BodyPositionV1,
    /// How many bodies this cursor has advanced past.
    ///
    /// Advisory progress telemetry, not an invariant: a full reprojection that
    /// re-walks bodies already behind the cursor leaves the cursor (and this
    /// count) untouched, because the cursor only ever moves forward.
    pub bodies_projected: u64,
}

/// What one projection pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProjectionPassSummaryV1 {
    /// Bodies (lexical) or lexical rows (dense) the pass consumed.
    pub bodies_consumed: u64,
    /// Rows the pass made searchable in its own tier.
    pub rows_indexed: u64,
    /// Bodies the pass consumed but could not make searchable: for the lexical
    /// tier, bodies with no derivable text; for the dense tier, bodies the
    /// lexical tier already marked unindexable.
    pub rows_unindexable: u64,
}

impl ProjectionPassSummaryV1 {
    /// Fold one batch's counters into the running pass total.
    pub(super) const fn absorb(&mut self, other: Self) {
        self.bodies_consumed += other.bodies_consumed;
        self.rows_indexed += other.rows_indexed;
        self.rows_unindexable += other.rows_unindexable;
    }
}

/// How far each tier has caught up with the body plane.
///
/// This is what lets a caller know which tier answered its recall: a result
/// whose `dense_complete()` is false was answered by a dense index that does
/// not yet cover every body, whatever hits came back.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RecallCompletenessV1 {
    /// Bodies in `memory_body_objects_v1` for this scope.
    pub bodies_total: u64,
    /// Bodies with a searchable lexical row.
    pub lexically_indexed: u64,
    /// Bodies recorded as carrying no derivable lexical text.
    pub lexically_unindexable: u64,
    /// Bodies with a stored embedding.
    pub densely_embedded: u64,
}

impl RecallCompletenessV1 {
    /// Bodies the lexical projector has consumed, searchable or not.
    #[must_use]
    pub const fn lexically_projected(&self) -> u64 {
        self.lexically_indexed + self.lexically_unindexable
    }

    /// True when every body has been through the lexical projector.
    #[must_use]
    pub const fn lexical_complete(&self) -> bool {
        self.lexically_projected() >= self.bodies_total
    }

    /// True when every lexically searchable body also has an embedding.
    ///
    /// Bodies with no derivable text are deliberately excluded: they are never
    /// embedded, so counting them would make dense completeness unreachable.
    #[must_use]
    pub const fn dense_complete(&self) -> bool {
        self.lexical_complete() && self.densely_embedded >= self.lexically_indexed
    }
}

/// Which tier actually produced the hits in a recall result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecallTierV1 {
    /// Neither lane returned a hit.
    None,
    /// Lexical only — either no query vector was supplied or the dense tier has
    /// nothing for this scope yet.
    Lexical,
    /// Dense only.
    Dense,
    /// Both lanes contributed.
    Hybrid,
}

/// One recalled body, carrying whichever lane scores produced it.
#[derive(Debug, Clone, PartialEq)]
pub struct RecallHitV1 {
    /// Content address of the recalled body.
    pub body_content_id: Sha256Digest,
    /// `ts_rank` of the lexical lane, when the lexical lane matched.
    pub lexical_score: Option<f32>,
    /// Cosine distance from the dense lane, when the dense lane matched.
    pub dense_distance: Option<f32>,
}

/// A recall answer plus the readiness that produced it.
#[derive(Debug, Clone, PartialEq)]
pub struct RecallResultV1 {
    /// Hits, lexical-matched first (highest `ts_rank` first), then dense-only
    /// hits by ascending distance; ties broken by content address so the order
    /// is total and deterministic.
    pub hits: Vec<RecallHitV1>,
    /// Which lanes contributed.
    pub tier: RecallTierV1,
    /// How complete each tier was at the time of the read.
    pub completeness: RecallCompletenessV1,
}

/// `(body_content_id, lexical_state, unindexable_reason, normalization_version,
/// lexical_text, lexical_text_digest)` snapshot tuple.
pub type SnapshotLexicalRowV1 = (Vec<u8>, String, String, i64, String, Vec<u8>);
/// `(body_content_id, embedding_identity_id, model_digest, distance_metric,
/// dimensions, embedding text)` snapshot tuple.
pub type SnapshotDenseRowV1 = (Vec<u8>, Vec<u8>, Vec<u8>, String, i64, String);

/// A deterministic, sorted snapshot of both projection tiers for one scope.
///
/// Wall-clock columns are deliberately excluded: two replays of the same body
/// tables compare equal iff the projectors rebuilt byte-identical content
/// (REPLAY-01).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecallProjectionSnapshotV1 {
    /// One row per lexical projection, sorted by `body_content_id`.
    pub lexical: Vec<SnapshotLexicalRowV1>,
    /// One row per stored embedding, sorted by `body_content_id`.
    pub dense: Vec<SnapshotDenseRowV1>,
}

/// The lexical tier: runs as soon as body rows land, needs no model.
#[async_trait]
pub trait LexicalProjector: Send + Sync {
    /// Consume every body past the lexical cursor, writing lexical rows and
    /// advancing the lexical cursor — each batch in ONE serializable
    /// transaction (REPLAY-02).
    async fn project_pending(&self) -> RecallProjectionResult<ProjectionPassSummaryV1>;

    /// Re-derive from every body regardless of the cursor. Idempotent: rows are
    /// content-addressed and the derivation is pure, so a replay rebuilds
    /// byte-identical rows (REPLAY-01).
    async fn reproject_all(&self) -> RecallProjectionResult<ProjectionPassSummaryV1>;
}

/// The dense tier: a background worker on the private plane only.
#[async_trait]
pub trait DenseProjector: Send + Sync {
    /// Embed every lexically indexed body past the dense cursor, writing dense
    /// rows and advancing the dense cursor — each batch in ONE serializable
    /// transaction. A provider failure aborts the batch and leaves the dense
    /// cursor where the last committed batch left it; it never touches the
    /// lexical tier.
    async fn embed_pending(&self) -> RecallProjectionResult<ProjectionPassSummaryV1>;

    /// Re-embed from the beginning regardless of the dense cursor.
    async fn reembed_all(&self) -> RecallProjectionResult<ProjectionPassSummaryV1>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_projector_names_round_trip_and_reject_unknown_values() {
        for kind in [ProjectorKindV1::Lexical, ProjectorKindV1::Dense] {
            assert_eq!(ProjectorKindV1::parse(kind.as_str()).unwrap(), kind);
        }
        assert!(ProjectorKindV1::parse("sparse").is_err());
    }

    #[test]
    fn lexical_completeness_ignores_the_dense_tier_entirely() {
        // The load-bearing readiness claim: lexical availability never depends
        // on an embedding existing.
        let completeness = RecallCompletenessV1 {
            bodies_total: 3,
            lexically_indexed: 3,
            lexically_unindexable: 0,
            densely_embedded: 0,
        };
        assert!(completeness.lexical_complete());
        assert!(!completeness.dense_complete());
    }

    #[test]
    fn an_unindexable_body_still_counts_as_lexically_projected() {
        let completeness = RecallCompletenessV1 {
            bodies_total: 2,
            lexically_indexed: 1,
            lexically_unindexable: 1,
            densely_embedded: 1,
        };
        assert!(completeness.lexical_complete());
        // Dense completeness compares against the INDEXED count, so a body with
        // no text does not hold the dense tier permanently incomplete.
        assert!(completeness.dense_complete());
    }

    #[test]
    fn a_lagging_lexical_tier_is_incomplete_in_both_tiers() {
        let completeness = RecallCompletenessV1 {
            bodies_total: 5,
            lexically_indexed: 2,
            lexically_unindexable: 0,
            densely_embedded: 2,
        };
        assert!(!completeness.lexical_complete());
        // Dense cannot be complete while bodies have not even been read.
        assert!(!completeness.dense_complete());
    }

    #[test]
    fn summaries_fold_batch_counters() {
        let mut total = ProjectionPassSummaryV1::default();
        total.absorb(ProjectionPassSummaryV1 {
            bodies_consumed: 2,
            rows_indexed: 1,
            rows_unindexable: 1,
        });
        total.absorb(ProjectionPassSummaryV1 {
            bodies_consumed: 3,
            rows_indexed: 3,
            rows_unindexable: 0,
        });
        assert_eq!(
            total,
            ProjectionPassSummaryV1 {
                bodies_consumed: 5,
                rows_indexed: 4,
                rows_unindexable: 1,
            }
        );
    }
}
