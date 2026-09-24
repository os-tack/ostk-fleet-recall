//! The production [`EmbeddingProvider`]: the fleet's pinned model2vec embedder
//! behind the dense projector's seam (W2-PROJ, Stage 5).
//!
//! `serve` and `ingest` already load one verified model bundle as an
//! [`ostk_recall_core::ChunkEmbedder`]. [`ChunkEmbedderProvider`] wraps that
//! same embedder so the dense tier and the chunk corpus are embedded by one
//! model, and declares the configuration its vectors are derived under.
//!
//! # What the adapter adds to the embedder
//!
//! * **A declared identity.** The descriptor binds the caller's model digest
//!   (the operator's `FLEET_RECALL_EMBEDDING_MODEL_SHA256`, the digest the
//!   bundle was verified against), the 512-component width of migration 0021,
//!   the cosine metric, and [`LEXICAL_NORMALIZATION_VERSION`] as the
//!   preprocessing version, because the dense tier embeds the lexical tier's
//!   normalized text. A normalizer change therefore changes every dense row's
//!   identity instead of mixing two input spaces in one index.
//! * **No blocking on the async runtime.** A model2vec encode is CPU work, so
//!   it runs on the blocking pool.
//! * **Named refusals.** A vector no index may store — empty, non-finite, or
//!   the zero vector under cosine — and an encode that panics are all
//!   [`RecallProjectionError::EmbeddingProvider`] with a message that says
//!   which. The dense projector refuses the whole batch and keeps its cursor
//!   behind that body, so an input the model cannot embed stalls the dense
//!   tier at that body (never the lexical tier), and the message is what
//!   explains the stall. The message never carries the text itself.
//!
//! [`crate::projectors::admit_embedding`] still runs on every vector this
//! provider returns; the checks here only make the provider's own failures
//! name themselves.

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use ostk_recall_core::ChunkEmbedder;

use crate::memory_contracts::chunk_identity::DistanceMetricV1;
use crate::memory_contracts::digest::Sha256Digest;

use super::dense::{EMBEDDING_DIMENSIONS, EmbeddingModelDescriptorV1, EmbeddingProvider};
use super::error::{RecallProjectionError, RecallProjectionResult};
use super::lexical::LEXICAL_NORMALIZATION_VERSION;

/// Tokenization version the adapter declares.
///
/// The model2vec tokenizer ships inside the pinned bundle, so the model digest
/// already fixes it; this is the first and only way the adapter has invoked
/// that tokenizer (one text per call, no truncation of its own).
const TOKENIZATION_VERSION: u32 = 1;

/// [`EmbeddingProvider`] over a pinned [`ChunkEmbedder`].
pub struct ChunkEmbedderProvider {
    embedder: Arc<dyn ChunkEmbedder>,
    descriptor: EmbeddingModelDescriptorV1,
}

impl ChunkEmbedderProvider {
    /// Wrap `embedder`, declaring `model_digest` as the model its vectors come
    /// from.
    ///
    /// Refuses, as [`RecallProjectionError::EmbeddingProvider`], an embedder
    /// whose width is not [`EMBEDDING_DIMENSIONS`] (the dense table's
    /// `VECTOR(512)`), and a zero digest, which cannot bind a vector to any
    /// model.
    pub fn new(
        embedder: Arc<dyn ChunkEmbedder>,
        model_digest: Sha256Digest,
    ) -> RecallProjectionResult<Self> {
        let width = embedder.dim();
        if width != EMBEDDING_DIMENSIONS as usize {
            return Err(RecallProjectionError::EmbeddingProvider(format!(
                "model {} embeds {width} components, but the dense tier stores \
                 {EMBEDDING_DIMENSIONS}",
                embedder.model_id()
            )));
        }
        if model_digest == Sha256Digest::ZERO {
            return Err(RecallProjectionError::EmbeddingProvider(
                "the embedding model digest is zero, so no dense row could name its model".into(),
            ));
        }
        Ok(Self {
            embedder,
            descriptor: EmbeddingModelDescriptorV1 {
                model_digest,
                tokenization_version: TOKENIZATION_VERSION,
                preprocessing_version: LEXICAL_NORMALIZATION_VERSION,
                distance_metric: DistanceMetricV1::Cosine,
                dimensions: EMBEDDING_DIMENSIONS,
            },
        })
    }

    /// Refuse a returned vector that no cosine index may store, naming why.
    ///
    /// A non-empty vector of the wrong width passes through to
    /// [`crate::projectors::admit_embedding`], whose
    /// [`RecallProjectionError::EmbeddingDimensionMismatch`] already names it.
    fn check_vector(&self, vector: &[f32], text_bytes: usize) -> RecallProjectionResult<()> {
        let model = self.embedder.model_id();
        if vector.is_empty() {
            return Err(RecallProjectionError::EmbeddingProvider(format!(
                "model {model} returned an empty vector for a {text_bytes}-byte text"
            )));
        }
        if let Some(index) = vector.iter().position(|component| !component.is_finite()) {
            return Err(RecallProjectionError::EmbeddingProvider(format!(
                "model {model} returned a non-finite component at index {index} for a \
                 {text_bytes}-byte text"
            )));
        }
        if vector.iter().all(|component| *component == 0.0) {
            return Err(RecallProjectionError::EmbeddingProvider(format!(
                "model {model} returned the zero vector for a {text_bytes}-byte text; cosine \
                 distance is undefined for it, so the dense tier cannot pass this body"
            )));
        }
        Ok(())
    }
}

impl fmt::Debug for ChunkEmbedderProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChunkEmbedderProvider")
            .field("model_id", &self.embedder.model_id())
            .field("descriptor", &self.descriptor)
            .finish()
    }
}

#[async_trait]
impl EmbeddingProvider for ChunkEmbedderProvider {
    fn descriptor(&self) -> &EmbeddingModelDescriptorV1 {
        &self.descriptor
    }

    async fn embed(&self, lexical_text: &str) -> RecallProjectionResult<Vec<f32>> {
        let embedder = Arc::clone(&self.embedder);
        let text = lexical_text.to_owned();
        let text_bytes = text.len();
        let vectors = tokio::task::spawn_blocking(move || embedder.encode_batch(&[text.as_str()]))
            .await
            .map_err(|error| {
                // The panic payload is left out: it is the model's own text and
                // could quote the input.
                let outcome = if error.is_panic() {
                    "panicked"
                } else {
                    "was cancelled"
                };
                RecallProjectionError::EmbeddingProvider(format!(
                    "model {} {outcome} while encoding a {text_bytes}-byte text",
                    self.embedder.model_id()
                ))
            })?;
        let returned = vectors.len();
        let Ok([vector]) = <[Vec<f32>; 1]>::try_from(vectors) else {
            return Err(RecallProjectionError::EmbeddingProvider(format!(
                "model {} returned {returned} vectors for one text",
                self.embedder.model_id()
            )));
        };
        self.check_vector(&vector, text_bytes)?;
        Ok(vector)
    }
}

#[cfg(test)]
mod tests {
    use sha2::{Digest as _, Sha256};

    use super::*;
    use crate::projectors::{admit_embedding, embedding_identity};

    fn digest(seed: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([seed; 32])
    }

    /// What the stub model does with every text it is asked to encode.
    #[derive(Clone, Copy)]
    enum Behaviour {
        /// A deterministic, non-zero 512-component vector per text.
        Healthy,
        /// The zero vector.
        Zero,
        /// A `NaN` in one component.
        NotANumber,
        /// No vector at all.
        Nothing,
        /// A vector with no components.
        Empty,
        /// Two vectors for the one text.
        TwoVectors,
        /// A panic inside the encode.
        Panic,
    }

    struct StubEmbedder {
        width: usize,
        behaviour: Behaviour,
    }

    /// A deterministic vector with no zero component (127.5 is never a byte).
    fn hashed_vector(text: &str, width: usize) -> Vec<f32> {
        let seed = Sha256::digest(text.as_bytes());
        (0..width)
            .map(|index| f32::from(seed[index % seed.len()]) - 127.5)
            .collect()
    }

    impl ChunkEmbedder for StubEmbedder {
        fn dim(&self) -> usize {
            self.width
        }

        fn model_id(&self) -> &'static str {
            "stub-model2vec-512"
        }

        fn encode_batch(&self, texts: &[&str]) -> Vec<Vec<f32>> {
            let healthy = |text: &&str| hashed_vector(text, self.width);
            match self.behaviour {
                Behaviour::Healthy => texts.iter().map(healthy).collect(),
                Behaviour::TwoVectors => texts
                    .iter()
                    .flat_map(|text| [healthy(text), healthy(text)])
                    .collect(),
                Behaviour::Zero => texts.iter().map(|_| vec![0.0; self.width]).collect(),
                Behaviour::NotANumber => texts
                    .iter()
                    .map(|text| {
                        let mut vector = healthy(text);
                        vector[7] = f32::NAN;
                        vector
                    })
                    .collect(),
                Behaviour::Empty => texts.iter().map(|_| Vec::new()).collect(),
                Behaviour::Nothing => Vec::new(),
                Behaviour::Panic => panic!("stub encode panicked"),
            }
        }
    }

    fn provider(behaviour: Behaviour) -> ChunkEmbedderProvider {
        ChunkEmbedderProvider::new(
            Arc::new(StubEmbedder {
                width: EMBEDDING_DIMENSIONS as usize,
                behaviour,
            }),
            digest(9),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn admit_embedding_accepts_what_a_healthy_model_returns() {
        let provider = provider(Behaviour::Healthy);
        let vector = provider.embed("merge the retry fix").await.unwrap();
        let admitted = admit_embedding(provider.descriptor(), digest(3), vector.clone()).unwrap();
        assert_eq!(admitted.vector, vector);
    }

    #[tokio::test]
    async fn identity_is_stable_across_calls_and_follows_the_declared_model() {
        // The same body embedded twice, or by two providers over the same
        // pinned model, lands on one dense row; a different model digest does
        // not.
        let first = provider(Behaviour::Healthy);
        let second = provider(Behaviour::Healthy);
        let body = digest(3);
        let one =
            admit_embedding(first.descriptor(), body, first.embed("text").await.unwrap()).unwrap();
        let again =
            admit_embedding(first.descriptor(), body, first.embed("text").await.unwrap()).unwrap();
        let other_instance = admit_embedding(
            second.descriptor(),
            body,
            second.embed("text").await.unwrap(),
        )
        .unwrap();
        assert_eq!(one.identity, again.identity);
        assert_eq!(one.identity, other_instance.identity);
        assert_eq!(one.vector, other_instance.vector);

        let other_model = ChunkEmbedderProvider::new(
            Arc::new(StubEmbedder {
                width: EMBEDDING_DIMENSIONS as usize,
                behaviour: Behaviour::Healthy,
            }),
            digest(10),
        )
        .unwrap();
        assert_ne!(
            embedding_identity(other_model.descriptor(), body).unwrap(),
            one.identity
        );
    }

    #[test]
    fn the_descriptor_declares_the_pinned_model_over_lexical_text() {
        let descriptor = provider(Behaviour::Healthy).descriptor().clone();
        assert_eq!(descriptor.model_digest, digest(9));
        assert_eq!(descriptor.tokenization_version, 1);
        // The dense tier embeds the lexical tier's normalized text, so a
        // normalizer change must change every dense identity.
        assert_eq!(
            descriptor.preprocessing_version,
            LEXICAL_NORMALIZATION_VERSION
        );
        assert_eq!(descriptor.distance_metric, DistanceMetricV1::Cosine);
        assert_eq!(descriptor.dimensions, EMBEDDING_DIMENSIONS);
    }

    #[test]
    fn a_model_of_the_wrong_width_is_refused() {
        let refused = ChunkEmbedderProvider::new(
            Arc::new(StubEmbedder {
                width: 256,
                behaviour: Behaviour::Healthy,
            }),
            digest(9),
        );
        assert!(matches!(
            refused,
            Err(RecallProjectionError::EmbeddingProvider(message))
                if message.contains("embeds 256 components")
        ));
    }

    #[test]
    fn a_zero_model_digest_is_refused() {
        let refused = ChunkEmbedderProvider::new(
            Arc::new(StubEmbedder {
                width: EMBEDDING_DIMENSIONS as usize,
                behaviour: Behaviour::Healthy,
            }),
            Sha256Digest::ZERO,
        );
        assert!(matches!(
            refused,
            Err(RecallProjectionError::EmbeddingProvider(message)) if message.contains("zero")
        ));
    }

    #[tokio::test]
    async fn a_vector_no_index_may_store_is_a_named_provider_error() {
        for (behaviour, names) in [
            (Behaviour::Zero, "zero vector"),
            (Behaviour::NotANumber, "non-finite component at index 7"),
            (Behaviour::Empty, "empty vector"),
            (Behaviour::Nothing, "returned 0 vectors"),
            (Behaviour::TwoVectors, "returned 2 vectors"),
            (Behaviour::Panic, "panicked"),
        ] {
            let failure = provider(behaviour)
                .embed("a private turn")
                .await
                .unwrap_err();
            let RecallProjectionError::EmbeddingProvider(message) = &failure else {
                panic!("expected a provider error naming {names:?}, got {failure:?}");
            };
            assert!(message.contains(names), "{message:?} should name {names:?}");
            assert!(message.contains("stub-model2vec-512"), "{message:?}");
            assert!(
                !message.contains("a private turn") && !message.contains("stub encode"),
                "neither the text nor a panic payload may reach the error: {message:?}"
            );
        }
    }
}
