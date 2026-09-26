//! The projection steps: accepted evidence to bodies, then the lexical tier,
//! then the dense tier.
//!
//! Each step is one pass of its projector from its own durable cursor, so a
//! step that fails leaves its cursor where it was and the next tick resumes
//! there. The tiers keep independent cursors and share no statement: a dense
//! failure (for example an input the model cannot embed) never holds the
//! lexical tier back.
//!
//! # Re-projection after a normalization version bump
//!
//! The lexical cursor only ever moves forward, so a change to the recall text
//! a body projects to (a stricter redaction profile, for one) would leave
//! every row already stored as it was. Each tick therefore counts the lexical
//! rows stored under an older [`LEXICAL_NORMALIZATION_VERSION`]; when there
//! are any, the lexical step re-derives every body regardless of its cursor
//! (`reproject_all`, upsert in place) and the dense step of the same tick
//! re-embeds every row (`reembed_all`). Both report the pass as
//! `rows_reprojected`, which is non-zero on the first tick after a deploy that
//! moved the version and zero afterwards. This is what redacts the served copy
//! of a transcript turn or a git fact admitted before redaction profile 3.
//!
//! The dense tier follows the lexical tier's re-projection within one tick:
//! a `project`-only tick followed by an `embed`-only tick would re-derive the
//! lexical rows and then embed nothing new, so a version bump is applied by a
//! tick that selects both (`all`, or `project,embed`).

use std::sync::Arc;

use crate::body_store::BodyProjectionRepository as _;
use crate::error::Result;
use crate::projectors::{
    CockroachDenseProjector, CockroachLexicalProjector, DenseProjector as _,
    LEXICAL_NORMALIZATION_VERSION, LexicalProjector as _, ProjectionPassSummaryV1,
};

use super::{DENSE_BATCH, LEXICAL_BATCH, MemoryWorker, WorkerCountersV1, WorkerStepReportV1};

const STALE_LEXICAL_ROWS_SQL: &str = "SELECT count(*) \
     FROM public.memory_body_lexical_projection_v1 \
     WHERE tenant_id = $1 AND project = $2 AND normalization_version < $3";

/// Lexical rows of this scope derived under an older normalization version
/// than this build's: the rows a full re-projection will rewrite.
pub(super) async fn stale_lexical_rows(worker: &MemoryWorker) -> Result<u64> {
    let deps = &worker.deps;
    let stale: i64 = sqlx::query_scalar(STALE_LEXICAL_ROWS_SQL)
        .bind(deps.scope.tenant_id)
        .bind(&deps.scope.project)
        .bind(i64::from(LEXICAL_NORMALIZATION_VERSION))
        .fetch_one(&deps.pool)
        .await?;
    Ok(u64::try_from(stale).unwrap_or(0))
}

pub(super) async fn run_bodies(worker: &MemoryWorker) -> WorkerStepReportV1 {
    let Some(bodies) = &worker.bodies else {
        return WorkerStepReportV1::failed("the body projector is not configured".to_owned());
    };
    match bodies.project_pending().await {
        Ok(summary) => WorkerStepReportV1::ok(WorkerCountersV1::from([
            ("events_projected", summary.events_projected),
            ("events_unprojectable", summary.events_unprojectable),
            ("occurrences_derived", summary.occurrences_derived),
            (
                "shadow_generations_opened",
                summary.shadow_generations_opened,
            ),
        ])),
        Err(error) => WorkerStepReportV1::failed(error.to_string()),
    }
}

/// The lexical step: a pass from the cursor, or, when `stale` rows are stored
/// under an older normalization version, a full re-projection.
pub(super) async fn run_lexical(worker: &MemoryWorker, stale: u64) -> WorkerStepReportV1 {
    let deps = &worker.deps;
    let projector = CockroachLexicalProjector::new(
        deps.pool.clone(),
        deps.scope.tenant_id,
        deps.scope.project.clone(),
        LEXICAL_BATCH,
        deps.retry,
    );
    if stale > 0 {
        pass_report(projector.reproject_all().await, true)
    } else {
        pass_report(projector.project_pending().await, false)
    }
}

/// The dense step: a pass from the cursor, or, when `reembed` (the lexical
/// tier re-projected in this tick), a full re-embed.
pub(super) async fn run_dense(worker: &MemoryWorker, reembed: bool) -> WorkerStepReportV1 {
    let deps = &worker.deps;
    let Some(provider) = &deps.embedding else {
        return WorkerStepReportV1::failed("no embedding provider is configured".to_owned());
    };
    let projector = CockroachDenseProjector::new(
        deps.pool.clone(),
        deps.scope.tenant_id,
        deps.scope.project.clone(),
        Arc::clone(provider),
        DENSE_BATCH,
        deps.retry,
    );
    if reembed {
        pass_report(projector.reembed_all().await, true)
    } else {
        pass_report(projector.embed_pending().await, false)
    }
}

fn pass_report(
    pass: crate::projectors::RecallProjectionResult<ProjectionPassSummaryV1>,
    reprojected: bool,
) -> WorkerStepReportV1 {
    match pass {
        Ok(summary) => WorkerStepReportV1::ok(WorkerCountersV1::from([
            ("bodies_consumed", summary.bodies_consumed),
            ("rows_indexed", summary.rows_indexed),
            ("rows_unindexable", summary.rows_unindexable),
            (
                "rows_reprojected",
                if reprojected {
                    summary.bodies_consumed
                } else {
                    0
                },
            ),
        ])),
        Err(error) => WorkerStepReportV1::failed(error.to_string()),
    }
}
