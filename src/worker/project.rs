//! The projection steps: accepted evidence to bodies, then the lexical tier,
//! then the dense tier.
//!
//! Each step is one pass of its projector from its own durable cursor, so a
//! step that fails leaves its cursor where it was and the next tick resumes
//! there. The tiers keep independent cursors and share no statement: a dense
//! failure (for example an input the model cannot embed) never holds the
//! lexical tier back.

use std::sync::Arc;

use crate::body_store::BodyProjectionRepository as _;
use crate::projectors::{
    CockroachDenseProjector, CockroachLexicalProjector, DenseProjector as _, LexicalProjector as _,
    ProjectionPassSummaryV1,
};

use super::{DENSE_BATCH, LEXICAL_BATCH, MemoryWorker, WorkerCountersV1, WorkerStepReportV1};

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

pub(super) async fn run_lexical(worker: &MemoryWorker) -> WorkerStepReportV1 {
    let deps = &worker.deps;
    let projector = CockroachLexicalProjector::new(
        deps.pool.clone(),
        deps.scope.tenant_id,
        deps.scope.project.clone(),
        LEXICAL_BATCH,
        deps.retry,
    );
    pass_report(projector.project_pending().await)
}

pub(super) async fn run_dense(worker: &MemoryWorker) -> WorkerStepReportV1 {
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
    pass_report(projector.embed_pending().await)
}

fn pass_report(
    pass: crate::projectors::RecallProjectionResult<ProjectionPassSummaryV1>,
) -> WorkerStepReportV1 {
    match pass {
        Ok(summary) => WorkerStepReportV1::ok(WorkerCountersV1::from([
            ("bodies_consumed", summary.bodies_consumed),
            ("rows_indexed", summary.rows_indexed),
            ("rows_unindexable", summary.rows_unindexable),
        ])),
        Err(error) => WorkerStepReportV1::failed(error.to_string()),
    }
}
