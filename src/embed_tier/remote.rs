//! Fail-closed remote embedding clients. Reply bodies and deadlines are bounded;
//! provider text and credentials never enter errors.

use super::{
    DIMENSIONS, Descriptor, EmbedRequest, EmbedResponse, MAX_BATCH, MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES, TierError, config::RemoteConfig, validate_texts, validate_vectors,
};
use crate::projectors::{
    EmbeddingModelDescriptorV1, EmbeddingProvider, RecallProjectionError, RecallProjectionResult,
};
use async_trait::async_trait;
use ostk_recall_core::ChunkEmbedder;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use std::{
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

pub struct RemoteClient {
    client: reqwest::Client,
    config: RemoteConfig,
    descriptor: Descriptor,
    projection: EmbeddingModelDescriptorV1,
    model_identity: String,
    degraded: AtomicBool,
}

impl RemoteClient {
    pub async fn connect(
        config: RemoteConfig,
        descriptor: Descriptor,
        model_identity: String,
    ) -> Result<Arc<Self>, TierError> {
        descriptor.validate()?;
        let client = reqwest::Client::builder()
            .timeout(config.timeout)
            .connect_timeout(config.timeout)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .map_err(|_| TierError::Configuration)?;
        let result = Arc::new(Self {
            client,
            config,
            projection: descriptor.projection(),
            descriptor,
            model_identity,
            degraded: AtomicBool::new(true),
        });
        result.check_health().await?;
        Ok(result)
    }

    pub fn connect_sync(
        config: RemoteConfig,
        descriptor: Descriptor,
        model_identity: String,
    ) -> Result<Arc<Self>, TierError> {
        bridge(Self::connect(config, descriptor, model_identity))
    }

    pub async fn check_health(&self) -> Result<(), TierError> {
        let result = async {
            let actual: Descriptor = self.request("/v1/descriptor", None).await?;
            if actual != self.descriptor {
                return Err(TierError::DescriptorMismatch);
            }
            Ok(())
        }
        .await;
        self.degraded.store(result.is_err(), Ordering::Release);
        result
    }

    pub async fn status(&self) -> Value {
        let _ = self.check_health().await;
        json!({"status": if self.degraded.load(Ordering::Acquire) {"degraded"} else {"ready"},
            "descriptor": self.descriptor})
    }

    pub fn is_degraded(&self) -> bool {
        self.degraded.load(Ordering::Acquire)
    }

    pub async fn embed(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, TierError> {
        let result = self.embed_inner(texts).await;
        self.degraded.store(result.is_err(), Ordering::Release);
        result
    }

    async fn embed_inner(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, TierError> {
        validate_texts(texts)?;
        let request = EmbedRequest {
            texts: texts.iter().map(|text| (*text).to_owned()).collect(),
        };
        let body = serde_json::to_vec(&request).map_err(|_| TierError::InvalidRequest)?;
        if body.len() > MAX_REQUEST_BYTES {
            return Err(TierError::InvalidRequest);
        }
        let response: EmbedResponse = self.request("/v1/embed", Some(body)).await?;
        if response.descriptor != self.descriptor {
            return Err(TierError::DescriptorMismatch);
        }
        validate_vectors(&response.vectors, texts.len())?;
        Ok(response.vectors)
    }

    async fn request<T: DeserializeOwned>(
        &self,
        route: &str,
        body: Option<Vec<u8>>,
    ) -> Result<T, TierError> {
        // One budget covers both attempts and body reads. Only a connect error
        // can retry: an HTTP response or an ambiguous read failure never can.
        tokio::time::timeout(self.config.timeout, async {
            let url = format!(
                "{}{route}",
                self.config.endpoint.as_str().trim_end_matches('/')
            );
            for attempt in 0..2 {
                let mut request = body.as_ref().map_or_else(
                    || self.client.get(&url),
                    |body| {
                        self.client
                            .post(&url)
                            .header(reqwest::header::CONTENT_TYPE, "application/json")
                            .body(body.clone())
                    },
                );
                if let Some(token) = self.config.token() {
                    request = request.bearer_auth(token);
                }
                let mut response = match request.send().await {
                    Err(error) if attempt == 0 && error.is_connect() => continue,
                    Err(_) => return Err(TierError::Unavailable),
                    Ok(response) => response,
                };
                if !response.status().is_success()
                    || response
                        .content_length()
                        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
                {
                    return Err(TierError::Unavailable);
                }
                let mut bytes = Vec::new();
                while let Some(chunk) =
                    response.chunk().await.map_err(|_| TierError::Unavailable)?
                {
                    if chunk.len() > MAX_RESPONSE_BYTES.saturating_sub(bytes.len()) {
                        return Err(TierError::Unavailable);
                    }
                    bytes.extend_from_slice(&chunk);
                }
                return serde_json::from_slice(&bytes).map_err(|_| TierError::Unavailable);
            }
            Err(TierError::Unavailable)
        })
        .await
        .map_err(|_| TierError::Unavailable)?
    }
}

fn bridge<T>(future: impl Future<Output = Result<T, TierError>>) -> Result<T, TierError> {
    let handle =
        tokio::runtime::Handle::try_current().map_err(|_| TierError::UnsupportedRuntime)?;
    if handle.runtime_flavor() != tokio::runtime::RuntimeFlavor::MultiThread {
        return Err(TierError::UnsupportedRuntime);
    }
    tokio::task::block_in_place(|| handle.block_on(future))
}

pub struct RemoteEmbedder {
    client: Arc<RemoteClient>,
}
impl RemoteEmbedder {
    pub const fn new(client: Arc<RemoteClient>) -> Self {
        Self { client }
    }
}
impl ChunkEmbedder for RemoteEmbedder {
    fn dim(&self) -> usize {
        DIMENSIONS
    }
    fn model_id(&self) -> &str {
        &self.client.model_identity
    }
    fn encode_batch(&self, texts: &[&str]) -> Vec<Vec<f32>> {
        if texts.is_empty() {
            return Vec::new();
        }
        let result = bridge(async {
            let mut vectors = Vec::with_capacity(texts.len());
            for batch in texts.chunks(MAX_BATCH) {
                vectors.extend(self.client.embed(batch).await?);
            }
            Ok(vectors)
        });
        result.unwrap_or_else(|_| {
            self.client.degraded.store(true, Ordering::Release);
            vec![vec![0.0; DIMENSIONS]; texts.len()]
        })
    }
}

pub struct RemoteEmbeddingProvider {
    client: Arc<RemoteClient>,
}
impl RemoteEmbeddingProvider {
    pub const fn new(client: Arc<RemoteClient>) -> Self {
        Self { client }
    }
}
#[async_trait]
impl EmbeddingProvider for RemoteEmbeddingProvider {
    fn descriptor(&self) -> &EmbeddingModelDescriptorV1 {
        &self.client.projection
    }
    async fn embed(&self, text: &str) -> RecallProjectionResult<Vec<f32>> {
        let mut vectors = self
            .client
            .embed(&[text])
            .await
            .map_err(|error| RecallProjectionError::EmbeddingProvider(error.to_string()))?;
        let vector = vectors.pop().ok_or_else(|| {
            RecallProjectionError::EmbeddingProvider(TierError::InvalidVectors.to_string())
        })?;
        if vector.iter().all(|value| *value == 0.0) {
            return Err(RecallProjectionError::EmbeddingProvider(
                TierError::InvalidVectors.to_string(),
            ));
        }
        Ok(vector)
    }
}
