//! Bounded embedding HTTP service. Inference runs on the blocking pool;
//! permits remain held until inference finishes even if a client disconnects.

use super::{
    Descriptor, EmbedRequest, EmbedResponse, MAX_REQUEST_BYTES, TierError, validate_texts,
    validate_vectors,
};
use axum::{
    Json, Router,
    body::to_bytes,
    extract::{Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use ostk_recall_core::ChunkEmbedder;
use ring::hmac;
use serde_json::json;
use std::sync::Arc;
use tokio::sync::Semaphore;

#[derive(Clone)]
struct ServerState {
    embedder: Arc<dyn ChunkEmbedder>,
    descriptor: Descriptor,
    bearer: Option<Arc<hmac::Key>>,
    capacity: Arc<Semaphore>,
}

pub fn router(
    embedder: Arc<dyn ChunkEmbedder>,
    descriptor: Descriptor,
    token: Option<String>,
) -> Result<Router, TierError> {
    descriptor.validate()?;
    super::config::validate_token(token.as_deref())?;
    if embedder.dim() != super::DIMENSIONS {
        return Err(TierError::DescriptorMismatch);
    }
    let state = ServerState {
        embedder,
        descriptor,
        bearer: token.map(|token| Arc::new(hmac::Key::new(hmac::HMAC_SHA256, token.as_bytes()))),
        capacity: Arc::new(Semaphore::new(4)),
    };
    Ok(Router::new()
        .route("/v1/descriptor", get(describe))
        .route("/v1/embed", post(embed))
        .layer(middleware::from_fn_with_state(state.clone(), guard))
        .with_state(state))
}

async fn guard(State(state): State<ServerState>, request: Request, next: Next) -> Response {
    let mut response = if authorized(request.headers(), state.bearer.as_deref()) {
        next.run(request).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"invalid_token"})),
        )
            .into_response()
    };
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        header::HeaderValue::from_static("nosniff"),
    );
    response
}

fn authorized(headers: &HeaderMap, key: Option<&hmac::Key>) -> bool {
    let Some(key) = key else { return true };
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let Some(token) = values
        .next()
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
    else {
        return false;
    };
    if values.next().is_some() || super::config::validate_token(Some(token)).is_err() {
        return false;
    }
    let supplied = hmac::Key::new(hmac::HMAC_SHA256, token.as_bytes());
    let tag = hmac::sign(&supplied, b"fleet-embedding-tier-bearer-v1");
    hmac::verify(key, b"fleet-embedding-tier-bearer-v1", tag.as_ref()).is_ok()
}

async fn describe(State(state): State<ServerState>) -> Json<Descriptor> {
    Json(state.descriptor)
}

async fn embed(State(state): State<ServerState>, request: Request) -> Response {
    if request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_none_or(|v| v.split(';').next() != Some("application/json"))
    {
        return failure(StatusCode::UNSUPPORTED_MEDIA_TYPE, "json_required");
    }
    let Ok(permit) = state.capacity.clone().try_acquire_owned() else {
        return failure(StatusCode::SERVICE_UNAVAILABLE, "embedding_busy");
    };
    let Ok(bytes) = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        to_bytes(request.into_body(), MAX_REQUEST_BYTES),
    )
    .await
    else {
        return failure(StatusCode::REQUEST_TIMEOUT, "request_timeout");
    };
    let Ok(bytes) = bytes else {
        return failure(StatusCode::PAYLOAD_TOO_LARGE, "request_too_large");
    };
    let Ok(request) = serde_json::from_slice::<EmbedRequest>(&bytes) else {
        return failure(StatusCode::BAD_REQUEST, "invalid_request");
    };
    if validate_texts(&request.texts).is_err() {
        return failure(StatusCode::BAD_REQUEST, "invalid_request");
    }
    let count = request.texts.len();
    let vectors = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let texts = request.texts.iter().map(String::as_str).collect::<Vec<_>>();
        state.embedder.encode_batch(&texts)
    })
    .await;
    let Ok(vectors) = vectors else {
        return failure(StatusCode::SERVICE_UNAVAILABLE, "embedding_failed");
    };
    if validate_vectors(&vectors, count).is_err() {
        return failure(StatusCode::SERVICE_UNAVAILABLE, "embedding_failed");
    }
    Json(EmbedResponse {
        descriptor: state.descriptor,
        vectors,
    })
    .into_response()
}
fn failure(status: StatusCode, code: &'static str) -> Response {
    (status, Json(json!({"error":code}))).into_response()
}
