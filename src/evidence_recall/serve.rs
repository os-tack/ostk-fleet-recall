//! How `serve` starts evidence recall (ADR 0006).
//!
//! `recall(kind=evidence)` is additive, like `remember(assert)`: whether it is
//! served never decides whether `serve` starts. It is served wherever the
//! schema has reached migration 30 and the writer login may read every
//! Stage-5 table evidence recall reads ([`probe_evidence_recall`]). There is
//! no switch: a deployment that has not applied the Stage-5 grants keeps
//! every tool schema byte for byte what it was. The publication process never
//! calls this; evidence recall reads private base tables only.

use std::str::FromStr as _;
use std::sync::Arc;

use sqlx::PgPool;

use crate::context::FleetScope;
use crate::memory_contracts::digest::Sha256Digest;
use crate::store::cockroach::DatabaseCapabilities;

use super::{CockroachEvidenceRecall, EvidenceDenseLaneV1, EvidenceRecall, probe_evidence_recall};

/// Evidence recall for `scope`, or `None` when this deployment does not serve
/// it.
///
/// `embedding_model_sha256` is the pinned model's digest
/// (`FLEET_RECALL_EMBEDDING_MODEL_SHA256`), the one the worker's dense rows
/// record. Every dense query compares the query vector only with rows that
/// model embedded, so rows another model writes after startup are skipped,
/// never compared. The dense lane is off for the process when, at startup,
/// the scope's dense tier already holds rows of another model. The probe runs
/// once, so a later grant, migration, or model change needs a restart.
///
/// A missing migration or grant is logged at info level. A digest that does
/// not parse or a probe that fails is logged at error level. Either way
/// evidence recall is off and `serve` goes on without it.
pub async fn start_evidence_recall(
    pool: &PgPool,
    capabilities: &DatabaseCapabilities,
    scope: &FleetScope,
    embedding_model_sha256: &str,
) -> Option<Arc<dyn EvidenceRecall>> {
    let Ok(model_digest) = Sha256Digest::from_str(embedding_model_sha256) else {
        tracing::error!(
            "evidence recall is off: the embedding model digest is not a lowercase 64-character hex digest"
        );
        return None;
    };
    match probe_evidence_recall(pool, capabilities, scope, model_digest).await {
        Ok(Some(capability)) => {
            if capability.dense_lane() == EvidenceDenseLaneV1::DisabledForeignModel {
                tracing::warn!(
                    "evidence recall serves its lexical lane only: the scope's dense tier holds vectors of another embedding model than FLEET_RECALL_EMBEDDING_MODEL_SHA256; the worker's embed step does not re-embed them, so the dense lane stays off until serve and the worker run the model those rows were embedded with"
                );
            }
            if capability.collector_state_unreadable() {
                tracing::warn!(
                    "evidence recall withholds every collected item: the schema has the collector tables (migration 33) and this login cannot read them; re-apply deploy/cockroach/runtime-role-grants.sql and restart, and until then an empty answer is unknown (collector_state_unreadable)"
                );
            }
            tracing::info!("serving recall(kind=evidence)");
            Some(Arc::new(CockroachEvidenceRecall::new(
                capability,
                pool.clone(),
            )))
        }
        Ok(None) => {
            tracing::info!(
                "evidence recall not served: migration 30 or the Stage-5 runtime grants are absent"
            );
            None
        }
        Err(error) => {
            tracing::error!(
                error = %error,
                "evidence recall is off: its startup probe failed; serving recall and remember without it"
            );
            None
        }
    }
}
