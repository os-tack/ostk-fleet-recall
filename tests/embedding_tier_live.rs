//! A real `CockroachDB` service preserves sparse reads through an embedding outage.
mod common;

use common::{runtime_role::RuntimeProbeRole, worker::StubEmbedder};
use ostk_fleet_recall::{
    FleetScope,
    application::CockroachMemoryService,
    embed_tier::{
        Descriptor,
        config::RemoteConfig,
        remote::{RemoteClient, RemoteEmbedder},
        server,
    },
    ledger::CockroachClaimLedger,
    memory_contracts::digest::Sha256Digest,
    service::{
        FleetMemoryService, RecallAction, RecallRequest, RememberAction, RememberRequest,
        ServiceError,
    },
    store::cockroach::{CockroachStore, RetryPolicy},
};
use ostk_recall_core::PrivacyTier;
use serde_json::{Map, Value, json};
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

fn arguments(value: Value) -> Map<String, Value> {
    let Value::Object(arguments) = value else {
        panic!("test arguments must be an object");
    };
    arguments
}
fn record(key: &str) -> RememberRequest {
    RememberRequest::new(
        RememberAction::Record,
        Some(key.into()),
        arguments(json!({
            "kind":"note", "text":"saffron kestrel resilience through embedding outages"
        })),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)] // One outage/restart lifecycle shares its endpoint and durable scope.
async fn outage_keeps_sparse_reads_and_refuses_writes_until_recovery() {
    let Some(url) = common::test_database_url() else {
        return;
    };
    let owner = common::migrated_pool(&url).await;
    let role = RuntimeProbeRole::create_serve_writer(&owner, &url).await;
    let scope = FleetScope::new(
        Uuid::now_v7(),
        "embedding-outage",
        "agent",
        None,
        PrivacyTier::T1Project,
    )
    .unwrap();
    let descriptor = Descriptor::pinned(Sha256Digest::from_bytes([0x5a; 32]));
    let identity = format!("stub-model2vec-512@sha256:{}", descriptor.model_digest);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let router = server::router(Arc::new(StubEmbedder), descriptor.clone(), None).unwrap();
    let tier = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let config = RemoteConfig::new(
        &format!("http://{address}"),
        Duration::from_millis(100),
        None,
    )
    .unwrap();
    let client = RemoteClient::connect(config, descriptor.clone(), identity.clone())
        .await
        .unwrap();
    let embedder = Arc::new(RemoteEmbedder::new(client.clone()));
    let owner_store = CockroachStore::from_pool(owner.clone(), scope.clone()).unwrap();
    owner_store
        .initialize_embedding_model(&identity)
        .await
        .unwrap();
    let store = Arc::new(CockroachStore::from_pool(role.pool.clone(), scope.clone()).unwrap());
    let ledger = Arc::new(
        CockroachClaimLedger::new(
            role.pool.clone(),
            scope.clone(),
            embedder.clone(),
            RetryPolicy::default(),
        )
        .unwrap(),
    );
    let service = CockroachMemoryService::new(scope.clone(), store, ledger, embedder)
        .unwrap()
        .with_embedding_tier(Some(client));
    let first = service
        .remember(scope.clone(), record("before-outage"))
        .await
        .unwrap();
    let claim_id = first.data["claim"]["id"].clone();
    assert!(!claim_id.is_null());
    tier.abort();
    let _ = tier.await;
    let status = service
        .recall(
            scope.clone(),
            RecallRequest::new(RecallAction::Status, Map::new()),
        )
        .await
        .unwrap();
    assert_eq!(status.data["embedding_tier"]["status"], "degraded");
    let get = service
        .recall(
            scope.clone(),
            RecallRequest::new(
                RecallAction::Get,
                arguments(json!({"kind":"claim","id":claim_id})),
            ),
        )
        .await
        .unwrap();
    assert_eq!(get.data["claim"]["id"], claim_id);
    let search = service
        .recall(
            scope.clone(),
            RecallRequest::new(
                RecallAction::Search,
                arguments(json!({"query":"saffron kestrel","kind":"chunk"})),
            ),
        )
        .await
        .unwrap();
    assert_eq!(search.diagnostics["retrieval"]["lanes"], json!(["lexical"]));
    assert!(
        !search.data["hits"].as_array().unwrap().is_empty(),
        "{search:?}"
    );
    let refused = service
        .remember(scope.clone(), record("during-outage"))
        .await;
    assert!(matches!(refused, Err(ServiceError::Unavailable(_))));
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM memory_claims WHERE tenant_id=$1 AND project=$2")
            .bind(scope.tenant_id)
            .bind(&scope.project)
            .fetch_one(&owner)
            .await
            .unwrap();
    assert_eq!(count, 1, "outage write must leave no durable claim");
    let listener = tokio::net::TcpListener::bind(address).await.unwrap();
    let router = server::router(Arc::new(StubEmbedder), descriptor, None).unwrap();
    let restarted = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let status = service
        .recall(
            scope.clone(),
            RecallRequest::new(RecallAction::Status, Map::new()),
        )
        .await
        .unwrap();
    assert_eq!(status.data["embedding_tier"]["status"], "ready");
    service
        .remember(scope, record("during-outage"))
        .await
        .unwrap();
    restarted.abort();
    drop(service);
    role.drop_role(&owner).await;
    owner.close().await;
}
