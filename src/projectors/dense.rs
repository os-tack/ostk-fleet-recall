//! Pure derivation and validation of the dense (embedding) tier (W2-PROJ).
//!
//! No database access lives here. This module owns the embedding *identity*
//! — which is a function of the input selection and the declared model
//! configuration only, never of the returned floats — and the fail-closed
//! admission checks a provider-returned vector must pass before it can reach
//! the ANN index.
//!
//! # Invariants enforced here
//!
//! * **Identity is configuration, not output.** The identity comes from the
//!   frozen [`EmbeddingIdentityPreimageV1`], so a model that returns slightly
//!   different floats on retry cannot change which row it belongs to. That is
//!   what makes a dense backfill idempotent and a re-embed detectable.
//! * **The dense tier is derived from the LEXICAL text, not the raw body.**
//!   Both tiers therefore see the same normalized input, and a body that is
//!   lexically unindexable is never embedded.
//! * **Fail closed on a degenerate vector.** Wrong dimension, a non-finite
//!   component, or (under cosine) the zero vector is refused with a typed error
//!   instead of being written; every one of those poisons distance comparisons
//!   for every other row in the index.
//! * **Private plane only.** The [`EmbeddingProvider`] seam is called by the
//!   background dense worker. Nothing in this module is reachable from the
//!   read-only public plane, and migration 0021 grants the dense table to no
//!   publication role.

use async_trait::async_trait;

use crate::memory_contracts::chunk_identity::{
    DistanceMetricV1, EmbeddingIdentityId, EmbeddingIdentityPreimageV1, EmbeddingInputV1,
};
use crate::memory_contracts::digest::Sha256Digest;

use super::error::{RecallProjectionError, RecallProjectionResult};

/// Schema version of the frozen chunk-identity preimages this module builds.
const CHUNK_SCHEMA_VERSION: u32 = 1;

/// The fleet's single embedding width, matching migration 0001's
/// `VECTOR(512)` corpus and migration 0021's dense table.
pub const EMBEDDING_DIMENSIONS: u32 = 512;

/// The declared configuration an embedding's identity is derived from.
///
/// Every field here enters [`EmbeddingIdentityPreimageV1`]; none of the
/// returned vector's bytes do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmbeddingModelDescriptorV1 {
    /// Digest of the exact model artifact/version.
    pub model_digest: Sha256Digest,
    /// Tokenizer version the model was invoked under.
    pub tokenization_version: u32,
    /// Preprocessing version the model was invoked under.
    pub preprocessing_version: u32,
    /// Distance metric the stored vectors are compared under.
    pub distance_metric: DistanceMetricV1,
    /// Declared vector width.
    pub dimensions: u32,
}

/// Exact stored `distance_metric` value. Part of the schema contract.
#[must_use]
pub const fn distance_metric_label(metric: DistanceMetricV1) -> &'static str {
    match metric {
        DistanceMetricV1::Cosine => "cosine",
        DistanceMetricV1::DotProduct => "dot_product",
        DistanceMetricV1::EuclideanL2 => "euclidean_l2",
    }
}

/// Parse a stored `distance_metric` value. Unknown values fail closed.
pub fn parse_distance_metric(value: &str) -> RecallProjectionResult<DistanceMetricV1> {
    match value {
        "cosine" => Ok(DistanceMetricV1::Cosine),
        "dot_product" => Ok(DistanceMetricV1::DotProduct),
        "euclidean_l2" => Ok(DistanceMetricV1::EuclideanL2),
        other => Err(RecallProjectionError::ProjectionIntegrity(format!(
            "stored dense row names an unknown distance metric: {other}"
        ))),
    }
}

/// One admitted embedding, ready to persist.
#[derive(Debug, Clone, PartialEq)]
pub struct DerivedEmbeddingV1 {
    /// Content address of the body the vector represents.
    pub body_content_id: Sha256Digest,
    /// `EmbeddingIdentityPreimageV1::embedding_identity_id`.
    pub identity: EmbeddingIdentityId,
    /// The provider-returned vector, admitted by [`admit_embedding`].
    pub vector: Vec<f32>,
}

/// Build the frozen identity preimage for one body under one descriptor.
pub const fn embedding_identity_preimage(
    descriptor: &EmbeddingModelDescriptorV1,
    body_content_id: Sha256Digest,
) -> EmbeddingIdentityPreimageV1 {
    EmbeddingIdentityPreimageV1 {
        schema_version: CHUNK_SCHEMA_VERSION,
        input: EmbeddingInputV1::Body { body_content_id },
        model_digest: descriptor.model_digest,
        tokenization_version: descriptor.tokenization_version,
        preprocessing_version: descriptor.preprocessing_version,
        distance_metric: descriptor.distance_metric,
        dimensions: descriptor.dimensions,
    }
}

/// Derive one body's embedding identity.
///
/// Fails closed if the descriptor is not admissible — zero model digest, zero
/// policy version, zero or oversized dimension — all rejected by the frozen
/// preimage's own validator.
pub fn embedding_identity(
    descriptor: &EmbeddingModelDescriptorV1,
    body_content_id: Sha256Digest,
) -> RecallProjectionResult<EmbeddingIdentityId> {
    Ok(embedding_identity_preimage(descriptor, body_content_id).embedding_identity_id()?)
}

/// Admit one provider-returned vector for one body, or fail closed.
///
/// The vector never influences the identity; it is checked only for the
/// properties that would corrupt the index if stored.
pub fn admit_embedding(
    descriptor: &EmbeddingModelDescriptorV1,
    body_content_id: Sha256Digest,
    vector: Vec<f32>,
) -> RecallProjectionResult<DerivedEmbeddingV1> {
    let identity = embedding_identity(descriptor, body_content_id)?;
    if vector.len() != descriptor.dimensions as usize {
        return Err(RecallProjectionError::EmbeddingDimensionMismatch {
            expected: descriptor.dimensions,
            actual: vector.len(),
        });
    }
    if let Some(index) = vector.iter().position(|component| !component.is_finite()) {
        return Err(RecallProjectionError::NonFiniteEmbedding { index });
    }
    if descriptor.distance_metric == DistanceMetricV1::Cosine {
        let norm_squared: f64 = vector
            .iter()
            .map(|component| f64::from(*component) * f64::from(*component))
            .sum();
        if norm_squared == 0.0 {
            return Err(RecallProjectionError::DegenerateEmbedding);
        }
    }
    Ok(DerivedEmbeddingV1 {
        body_content_id,
        identity,
        vector,
    })
}

/// The one seam between the dense worker and an embedding model.
///
/// Production wires this to the fleet's embedding service; tests wire it to a
/// deterministic in-process model. It is deliberately the ONLY asynchronous,
/// failure-prone dependency of the dense tier, so "the model is down" is a
/// single, typed, contained condition
/// ([`RecallProjectionError::EmbeddingProvider`]) that cannot reach the lexical
/// tier.
#[async_trait]
pub trait EmbeddingProvider: Send + Sync {
    /// The declared configuration every vector from this provider is derived
    /// under. Identity comes from here, never from the returned floats.
    fn descriptor(&self) -> &EmbeddingModelDescriptorV1;

    /// Embed one body's normalized lexical text.
    async fn embed(&self, lexical_text: &str) -> RecallProjectionResult<Vec<f32>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(seed: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([seed; 32])
    }

    fn descriptor() -> EmbeddingModelDescriptorV1 {
        EmbeddingModelDescriptorV1 {
            model_digest: digest(7),
            tokenization_version: 1,
            preprocessing_version: 1,
            distance_metric: DistanceMetricV1::Cosine,
            dimensions: EMBEDDING_DIMENSIONS,
        }
    }

    fn unit_vector() -> Vec<f32> {
        let mut vector = vec![0.0_f32; EMBEDDING_DIMENSIONS as usize];
        vector[0] = 1.0;
        vector
    }

    #[test]
    fn identity_ignores_the_returned_vector() {
        // Two retries of the same model returning different floats must land on
        // the same row, or a backfill would never converge.
        let descriptor = descriptor();
        let body = digest(3);
        let first = admit_embedding(&descriptor, body, unit_vector()).unwrap();
        let mut jittered = unit_vector();
        jittered[1] = 0.000_1;
        let second = admit_embedding(&descriptor, body, jittered).unwrap();
        assert_eq!(first.identity, second.identity);
        assert_ne!(first.vector, second.vector);
    }

    #[test]
    fn identity_changes_with_every_declared_configuration_field() {
        let body = digest(3);
        let base = embedding_identity(&descriptor(), body).unwrap();
        for mutate in [
            (|d: &mut EmbeddingModelDescriptorV1| d.model_digest = digest(8))
                as fn(&mut EmbeddingModelDescriptorV1),
            |d: &mut EmbeddingModelDescriptorV1| d.tokenization_version = 2,
            |d: &mut EmbeddingModelDescriptorV1| d.preprocessing_version = 2,
            |d: &mut EmbeddingModelDescriptorV1| d.distance_metric = DistanceMetricV1::DotProduct,
            |d: &mut EmbeddingModelDescriptorV1| d.dimensions = 256,
        ] {
            let mut mutated = descriptor();
            mutate(&mut mutated);
            assert_ne!(embedding_identity(&mutated, body).unwrap(), base);
        }
        // The body selection is part of the identity too.
        assert_ne!(embedding_identity(&descriptor(), digest(4)).unwrap(), base);
    }

    #[test]
    fn a_wrong_width_vector_is_refused() {
        assert!(matches!(
            admit_embedding(&descriptor(), digest(3), vec![1.0_f32; 8]),
            Err(RecallProjectionError::EmbeddingDimensionMismatch {
                expected: EMBEDDING_DIMENSIONS,
                actual: 8
            })
        ));
    }

    #[test]
    fn a_non_finite_component_is_refused() {
        for poison in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            let mut vector = unit_vector();
            vector[5] = poison;
            assert!(matches!(
                admit_embedding(&descriptor(), digest(3), vector),
                Err(RecallProjectionError::NonFiniteEmbedding { index: 5 })
            ));
        }
    }

    #[test]
    fn the_zero_vector_is_refused_under_cosine() {
        // Cosine distance is undefined for a zero-norm vector.
        let zero = vec![0.0_f32; EMBEDDING_DIMENSIONS as usize];
        assert!(matches!(
            admit_embedding(&descriptor(), digest(3), zero.clone()),
            Err(RecallProjectionError::DegenerateEmbedding)
        ));
        // Under a metric where it is defined, the same vector is admissible.
        let mut euclidean = descriptor();
        euclidean.distance_metric = DistanceMetricV1::EuclideanL2;
        admit_embedding(&euclidean, digest(3), zero).unwrap();
    }

    #[test]
    fn an_inadmissible_descriptor_is_refused_before_any_vector_check() {
        // A zero model digest cannot bind a vector to a model, so the frozen
        // preimage refuses it; the wrong-width vector never gets that far.
        let mut broken = descriptor();
        broken.model_digest = Sha256Digest::ZERO;
        assert!(matches!(
            admit_embedding(&broken, digest(3), vec![1.0_f32; 3]),
            Err(RecallProjectionError::Contract(_))
        ));
    }

    #[test]
    fn stored_metric_labels_round_trip_and_reject_unknown_values() {
        for metric in [
            DistanceMetricV1::Cosine,
            DistanceMetricV1::DotProduct,
            DistanceMetricV1::EuclideanL2,
        ] {
            assert_eq!(
                parse_distance_metric(distance_metric_label(metric)).unwrap(),
                metric
            );
        }
        assert!(parse_distance_metric("manhattan").is_err());
    }
}
