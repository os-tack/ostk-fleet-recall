//! Relation attestation append plus durable projection (W1-REL).
//!
//! This module appends `RelationAttestationEventV1` (REL-01) through the
//! general accepted-event ledger's own doc-hidden production seam,
//! [`crate::evidence_ledger::AppendableAcceptedEvent::relation_attestation`],
//! and — in the SAME serializable transaction, via
//! [`crate::evidence_ledger::AppendProjection`] — materializes migration
//! 0018's `memory_relation_projection_v1` and advances
//! `memory_relation_projection_watermarks_v1` (EVENT-03, REPLAY-02).
//!
//! # Layout
//!
//! * [`projector`] — pure logic: [`projector::project_relation_events`] is a
//!   line-for-line port of
//!   `memory_contracts::relation::project_relation`'s algorithm (see that
//!   module's documentation for exactly why this crate cannot call the
//!   original from production code today, and what would let it).
//! * [`repository`] — the [`RelationProjectionRepository`] trait plus the
//!   persisted row/watermark shapes.
//! * [`cockroach`] — the `CockroachDB` implementation and the
//!   [`crate::evidence_ledger::AppendProjection`] adapter that plugs into
//!   [`crate::evidence_ledger::AcceptedEventRepository::append`].
//!
//! # Invariants this module enforces
//!
//! * **REL-01** — `projection_state` is exactly
//!   [`crate::memory_contracts::relation::project_relation`]'s (ported)
//!   algorithm's output; no payload field selects it directly. Declared vs.
//!   verified attestations are distinguished by `last_basis`, and
//!   supersession requires the SAME attestor and basis on the predecessor
//!   (checked inside [`projector::project_relation_events`]).
//! * **EVENT-03 / REPLAY-02** — the projection and its watermark commit in
//!   the same transaction as the accepted-event insert; a failure of either
//!   rolls the whole append back (nothing written), and the watermark
//!   advances exactly with the projection row.
//! * **REPLAY-01** — every append re-derives the projection from the
//!   COMPLETE admitted history read back from `memory_evidence_events`
//!   inside the same transaction, rather than folding one event into the
//!   prior persisted row; [`repository::RelationProjectionRepository::rebuild_projection`]
//!   exposes the identical rebuild outside any append, for exactly the
//!   equality tests `tests/relation_projection_live.rs` runs.

mod cockroach;
mod projector;
mod repository;

pub use cockroach::CockroachRelationProjectionRepository;
pub use projector::{basis_is_verified, project_relation_events};
pub use repository::{
    RelationProjectionRepository, RelationProjectionRowV1, RelationProjectionWatermarkV1,
    WATERMARK_LEDGER_FAMILY,
};
