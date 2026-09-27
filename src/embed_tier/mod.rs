//! Pinned embedding service and its asynchronous and synchronous clients.

pub mod config;
pub mod remote;
pub mod server;

#[cfg(test)]
mod tests;

use crate::memory_contracts::{chunk_identity::DistanceMetricV1, digest::Sha256Digest};
use crate::projectors::{EmbeddingModelDescriptorV1, LEXICAL_NORMALIZATION_VERSION};
use serde::{Deserialize, Serialize};

pub const MAX_BATCH: usize = 64;
pub const MAX_TEXT_BYTES: usize = 256 * 1024;
pub const MAX_REQUEST_BYTES: usize = MAX_BATCH * MAX_TEXT_BYTES + 4096;
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
pub const DIMENSIONS: usize = 512;

/// Every error is static: input texts, bearer tokens, and provider replies
/// never enter diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TierError {
    #[error("invalid embedding tier configuration")]
    Configuration,
    #[error("embedding tier is unavailable")]
    Unavailable,
    #[error("embedding tier descriptor differs from the deployment pin")]
    DescriptorMismatch,
    #[error("embedding tier returned invalid vectors")]
    InvalidVectors,
    #[error("embedding request exceeds the tier limits")]
    InvalidRequest,
    #[error("remote synchronous embedding requires a multithread Tokio runtime")]
    UnsupportedRuntime,
}

/// Versioned wire representation; all fields are pinned on every reply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Descriptor {
    pub model_digest: Sha256Digest,
    pub dimensions: u32,
    pub distance_metric: DistanceMetricV1,
    pub tokenization_version: u32,
    pub preprocessing_version: u32,
}
impl Descriptor {
    pub const fn pinned(model_digest: Sha256Digest) -> Self {
        Self {
            model_digest,
            dimensions: 512,
            distance_metric: DistanceMetricV1::Cosine,
            tokenization_version: 1,
            preprocessing_version: LEXICAL_NORMALIZATION_VERSION,
        }
    }
    pub fn validate(&self) -> Result<(), TierError> {
        if self.model_digest == Sha256Digest::ZERO || self != &Self::pinned(self.model_digest) {
            return Err(TierError::DescriptorMismatch);
        }
        Ok(())
    }
    pub const fn projection(&self) -> EmbeddingModelDescriptorV1 {
        EmbeddingModelDescriptorV1 {
            model_digest: self.model_digest,
            dimensions: self.dimensions,
            distance_metric: self.distance_metric,
            tokenization_version: self.tokenization_version,
            preprocessing_version: self.preprocessing_version,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmbedRequest {
    pub texts: Vec<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmbedResponse {
    pub descriptor: Descriptor,
    pub vectors: Vec<Vec<f32>>,
}

fn validate_texts(texts: &[impl AsRef<str>]) -> Result<(), TierError> {
    if texts.is_empty()
        || texts.len() > MAX_BATCH
        || texts
            .iter()
            .any(|text| text.as_ref().len() > MAX_TEXT_BYTES)
    {
        return Err(TierError::InvalidRequest);
    }
    Ok(())
}

fn validate_vectors(vectors: &[Vec<f32>], count: usize) -> Result<(), TierError> {
    if vectors.len() != count
        || vectors
            .iter()
            .any(|vector| vector.len() != DIMENSIONS || vector.iter().any(|x| !x.is_finite()))
    {
        return Err(TierError::InvalidVectors);
    }
    // Zero vectors are a valid model response for unknown words. Reads omit
    // that dense lane; write adapters explicitly refuse to persist them.
    Ok(())
}
