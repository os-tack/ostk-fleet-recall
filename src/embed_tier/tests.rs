use super::{
    config::RemoteConfig,
    remote::{RemoteClient, RemoteEmbedder, RemoteEmbeddingProvider},
    *,
};
use crate::projectors::EmbeddingProvider as _;
use axum::{
    Json, Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
    routing::{get, post},
};
use ostk_recall_core::ChunkEmbedder;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tower::ServiceExt as _;

struct TestEmbedder;
impl ChunkEmbedder for TestEmbedder {
    fn dim(&self) -> usize {
        DIMENSIONS
    }
    fn model_id(&self) -> &'static str {
        "fixture"
    }
    fn encode_batch(&self, texts: &[&str]) -> Vec<Vec<f32>> {
        texts
            .iter()
            .map(|text| {
                let mut vector = vec![0.0; DIMENSIONS];
                if !text.is_empty() {
                    vector[0] = 1.0;
                }
                vector
            })
            .collect()
    }
}

fn descriptor() -> Descriptor {
    Descriptor::pinned(Sha256Digest::from_bytes([7; 32]))
}

#[tokio::test]
async fn measurements_cover_remote_failure_without_identity_or_content_labels() {
    let secret = "telemetry-private-tier-token";
    let model = "telemetry-private-model-identity";
    let text = "telemetry-private-query-text";
    let (url, task) =
        host(server::router(Arc::new(TestEmbedder), descriptor(), Some(secret.into())).unwrap())
            .await;
    let config = RemoteConfig::new(&url, Duration::from_millis(200), Some(secret.into())).unwrap();
    let client = RemoteClient::connect(config, descriptor(), model.into())
        .await
        .unwrap();
    let provider = RemoteEmbeddingProvider::new(client.clone());
    provider.embed(text).await.unwrap();
    assert!(provider.embed("").await.is_err());
    assert!(client.embed(&[text; 65]).await.is_err());
    // Current-thread callers cannot run the synchronous bridge; this is the
    // same bounded fallback counter that an unavailable tier increments.
    RemoteEmbedder::new(client.clone()).encode_batch(&[text]);
    task.abort();
    let _ = task.await;
    assert!(client.embed(&[text]).await.is_err());
    let metrics = crate::telemetry::render().unwrap();
    for (operation, outcome) in [
        ("remote_descriptor", "success"),
        ("remote_batch", "success"),
        ("remote_batch", "error"),
        ("remote_batch", "invalid"),
        ("embed", "invalid"),
    ] {
        let prefix = format!(
            "fleet_recall_operations_total{{component=\"embedding\",operation=\"{operation}\",outcome=\"{outcome}\"}} "
        );
        let value = metrics
            .lines()
            .find_map(|line| line.strip_prefix(&prefix))
            .unwrap();
        assert!(value.parse::<u64>().unwrap() > 0);
    }
    assert!(metrics.contains("fleet_recall_units_total{component=\"embedding\",operation=\"remote_batch\",unit=\"zero_fallbacks\"}"));
    for private in [
        secret,
        model,
        text,
        url.as_str(),
        &descriptor().model_digest.to_hex(),
    ] {
        assert!(!metrics.contains(private));
    }
}

async fn host(router: Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    (format!("http://{address}"), task)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::float_cmp)] // The fixture returns the exact wire-representable sentinel 1.0.
async fn authenticated_roundtrip_sync_async_zero_refusal_and_restart() {
    let router = server::router(
        Arc::new(TestEmbedder),
        descriptor(),
        Some("fixture-secret".into()),
    )
    .unwrap();
    let (url, task) = host(router).await;
    let config = RemoteConfig::new(
        &url,
        Duration::from_millis(200),
        Some("fixture-secret".into()),
    )
    .unwrap();
    let client = RemoteClient::connect(config.clone(), descriptor(), "fixture@sha256:pin".into())
        .await
        .unwrap();
    assert!(matches!(
        RemoteClient::connect(
            config.clone(),
            Descriptor::pinned(Sha256Digest::from_bytes([8; 32])),
            "fixture".into()
        )
        .await,
        Err(TierError::DescriptorMismatch)
    ));
    let provider = RemoteEmbeddingProvider::new(client.clone());
    assert_eq!(provider.embed("hello").await.unwrap()[0], 1.0);
    assert!(provider.embed("").await.is_err());
    let sync = RemoteEmbedder::new(client.clone());
    assert_eq!(sync.encode_batch(&["hello"; 65]).len(), 65);
    assert_eq!(sync.encode_batch(&["hello"])[0][0], 1.0);
    let wrong = RemoteConfig::new(&url, Duration::from_millis(200), Some("wrong".into())).unwrap();
    assert!(matches!(
        RemoteClient::connect(wrong, descriptor(), "fixture".into()).await,
        Err(TierError::Unavailable)
    ));
    task.abort();
    let _ = task.await;
    assert_eq!(sync.encode_batch(&["hello"]), vec![vec![0.0; DIMENSIONS]]);
    assert!(client.is_degraded());
    assert_eq!(client.status().await["status"], "degraded");
    // Bind the same endpoint again: health and subsequent requests recover
    // without changing the immutable descriptor or rebuilding consumers.
    let listener = tokio::net::TcpListener::bind(config.endpoint.authority())
        .await
        .unwrap();
    let router = server::router(
        Arc::new(TestEmbedder),
        descriptor(),
        Some("fixture-secret".into()),
    )
    .unwrap();
    let restarted = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    assert_eq!(client.status().await["status"], "ready");
    assert_eq!(provider.embed("hello").await.unwrap()[0], 1.0);
    restarted.abort();
}

#[tokio::test]
async fn current_thread_sync_bridge_fails_closed_without_panicking() {
    let (url, task) =
        host(server::router(Arc::new(TestEmbedder), descriptor(), None).unwrap()).await;
    let config = RemoteConfig::new(&url, Duration::from_millis(200), None).unwrap();
    let client = RemoteClient::connect(config, descriptor(), "fixture".into())
        .await
        .unwrap();
    assert_eq!(
        RemoteEmbedder::new(client.clone()).encode_batch(&["hello"]),
        vec![vec![0.0; DIMENSIONS]]
    );
    assert!(client.is_degraded());
    task.abort();
}

#[tokio::test]
async fn every_reply_checks_all_descriptor_fields_and_dimensions() {
    for alter in 0..6 {
        let router = Router::new()
            .route("/v1/descriptor", get(|| async { Json(descriptor()) }))
            .route(
                "/v1/embed",
                post(move || async move {
                    let mut descriptor = descriptor();
                    let mut vectors = vec![vec![1.0; DIMENSIONS]];
                    match alter {
                        0 => descriptor.model_digest = Sha256Digest::from_bytes([9; 32]),
                        1 => descriptor.tokenization_version += 1,
                        2 => descriptor.preprocessing_version += 1,
                        3 => descriptor.dimensions = 256,
                        4 => descriptor.distance_metric = DistanceMetricV1::DotProduct,
                        _ => {
                            vectors[0].pop();
                        }
                    }
                    Json(EmbedResponse {
                        descriptor,
                        vectors,
                    })
                }),
            );
        let (url, task) = host(router).await;
        let config = RemoteConfig::new(&url, Duration::from_millis(200), None).unwrap();
        let client = RemoteClient::connect(config, descriptor(), "fixture".into())
            .await
            .unwrap();
        let expected = if alter == 5 {
            TierError::InvalidVectors
        } else {
            TierError::DescriptorMismatch
        };
        assert_eq!(client.embed(&["private text"]).await, Err(expected));
        assert!(client.is_degraded());
        task.abort();
    }
}

#[tokio::test]
async fn descriptor_timeout_oversize_and_redirects_fail_closed() {
    let slow = Arc::new(AtomicBool::new(false));
    let state = slow.clone();
    let router = Router::new()
        .route(
            "/v1/descriptor",
            get(move || {
                let state = state.clone();
                async move {
                    if state.load(Ordering::Acquire) {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                    Json(descriptor())
                }
            }),
        )
        .route(
            "/v1/embed",
            post(|| async { "x".repeat(MAX_RESPONSE_BYTES + 1) }),
        );
    let (url, task) = host(router).await;
    let config = RemoteConfig::new(&url, Duration::from_millis(25), None).unwrap();
    let client = RemoteClient::connect(config, descriptor(), "fixture".into())
        .await
        .unwrap();
    assert_eq!(client.embed(&["secret"]).await, Err(TierError::Unavailable));
    slow.store(true, Ordering::Release);
    assert_eq!(client.check_health().await, Err(TierError::Unavailable));
    task.abort();
    let router = Router::new().route(
        "/v1/descriptor",
        get(|| async {
            (
                StatusCode::FOUND,
                [("location", "http://127.0.0.1:1/credential-sink")],
            )
        }),
    );
    let (url, task) = host(router).await;
    let config =
        RemoteConfig::new(&url, Duration::from_millis(200), Some("secret".into())).unwrap();
    assert!(matches!(
        RemoteClient::connect(config, descriptor(), "fixture".into()).await,
        Err(TierError::Unavailable)
    ));
    task.abort();
}

#[tokio::test]
async fn server_rejects_duplicate_auth_and_bounded_invalid_requests() {
    let router =
        server::router(Arc::new(TestEmbedder), descriptor(), Some("secret".into())).unwrap();
    let request = Request::builder()
        .uri("/v1/descriptor")
        .header("authorization", "Bearer secret")
        .header("authorization", "Bearer secret")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        router.clone().oneshot(request).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    for texts in [
        vec![],
        vec!["ok".to_owned(); 65],
        vec!["x".repeat(MAX_TEXT_BYTES + 1)],
    ] {
        let request = Request::builder()
            .method("POST")
            .uri("/v1/embed")
            .header("authorization", "Bearer secret")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&EmbedRequest { texts }).unwrap(),
            ))
            .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        assert!(!String::from_utf8_lossy(&body).contains("secret"));
    }
}

#[test]
fn configuration_and_wire_are_strict() {
    for endpoint in [
        "file:///tmp/model",
        "http://user:pass@example.com",
        "http://example.com/?token=x",
        "http://example.com/#x",
        "",
    ] {
        assert!(RemoteConfig::new(endpoint, Duration::from_secs(2), None).is_err());
    }
    for token in ["", "secret\nvalue", "has space"] {
        assert!(
            RemoteConfig::new(
                "http://embedding:8090",
                Duration::from_secs(2),
                Some(token.into())
            )
            .is_err()
        );
    }
    assert!(Descriptor::pinned(Sha256Digest::ZERO).validate().is_err());
    assert!(
        serde_json::from_str::<EmbedRequest>(r#"{"texts":["hello"],"texts":["other"]}"#).is_err()
    );
    assert!(validate_vectors(&[vec![f32::NAN; DIMENSIONS]], 1).is_err());
    assert!(validate_vectors(&[vec![f32::INFINITY; DIMENSIONS]], 1).is_err());
    assert!(validate_vectors(&[], 1).is_err());
}
