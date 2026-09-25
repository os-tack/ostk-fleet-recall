//! How `serve` starts item recall (ADR 0008 D7).
//!
//! `recall(kind=item)` is additive, like `recall(kind=evidence)`: whether it
//! is served never decides whether `serve` starts. It is served wherever the
//! schema has reached migration 34 and the writer login may read every table
//! item recall reads ([`probe_item_recall`]). There is no switch: a
//! deployment without the collector grants keeps every tool schema byte for
//! byte what it was. The publication process never calls this; item recall
//! reads private base tables only.

use std::str::FromStr as _;
use std::sync::Arc;

use sqlx::PgPool;

use crate::context::FleetScope;
use crate::evidence_recall::EvidenceDenseLaneV1;
use crate::memory_contracts::digest::Sha256Digest;
use crate::store::cockroach::DatabaseCapabilities;

use super::{CockroachItemRecall, ItemRecall, probe_item_recall};

/// Item recall for `scope`, or `None` when this deployment does not serve it.
///
/// `embedding_model_sha256` is the pinned model's digest, as for evidence
/// recall: every dense query compares the query vector only with vectors that
/// model embedded, and the dense lane is off for the process when, at
/// startup, the scope's dense tier already holds another model's vectors.
/// The probe runs once, so migration 34 or the collector grants applied after
/// startup take effect at the next restart; until then `kind=item` is neither
/// served nor advertised.
///
/// A missing migration or grant is logged at info level. A digest that does
/// not parse or a probe that fails is logged at error level. Either way item
/// recall is off and `serve` goes on without it.
pub async fn start_item_recall(
    pool: &PgPool,
    capabilities: &DatabaseCapabilities,
    scope: &FleetScope,
    embedding_model_sha256: &str,
) -> Option<Arc<dyn ItemRecall>> {
    let Ok(model_digest) = Sha256Digest::from_str(embedding_model_sha256) else {
        tracing::error!(
            "item recall is off: the embedding model digest is not a lowercase 64-character hex digest"
        );
        return None;
    };
    match probe_item_recall(pool, capabilities, scope, model_digest).await {
        Ok(Some(capability)) => {
            if capability.dense_lane() == EvidenceDenseLaneV1::DisabledForeignModel {
                tracing::warn!(
                    "item recall serves its lexical lane only: the scope's dense tier holds vectors of another embedding model than FLEET_RECALL_EMBEDDING_MODEL_SHA256"
                );
            }
            tracing::info!("serving recall(kind=item)");
            Some(Arc::new(CockroachItemRecall::new(capability, pool.clone())))
        }
        Ok(None) => {
            tracing::info!(
                "item recall not served: migration 34 or the collector runtime grants are absent"
            );
            None
        }
        Err(error) => {
            tracing::error!(
                error = %error,
                "item recall is off: its startup probe failed; serving recall and remember without it"
            );
            None
        }
    }
}
