//! The authenticated HTTP path against real `CockroachDB`, with local fake
//! identity providers and exactly the runtime/enrollment table privileges.
mod common;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use chrono::Utc;
use common::{
    fake_provider::{FakeProvider, FakeReply},
    runtime_role::RuntimeProbeRole,
    worker::{STUB_MODEL_DIGEST, StubEmbedder},
};
use ostk_fleet_recall::auth::{
    grant::probe_remote_plane,
    jose::Ed25519Signer,
    registry::{Ceiling, DeclarationFile, PrincipalDeclaration, PrincipalRegistry, PrincipalRole},
};
use ostk_fleet_recall::config::LifecycleConfig;
use ostk_fleet_recall::encoding::base64::decode_url;
use ostk_fleet_recall::mcp::{
    MODERN_PROTOCOL_VERSION,
    http::{self, HttpBackend},
    scopes::ScopeServices,
};
use ostk_fleet_recall::private_postgres::PrivatePostgresSslPolicy;
use ostk_fleet_recall::remote::{RemoteBackend, RemoteConfig};
use ostk_fleet_recall::store::cockroach::CockroachStore;
use ostk_fleet_recall::{FleetConfig, FleetScope};
use ostk_recall_core::ChunkEmbedder;
use serde_json::{Value, json};
use sqlx::PgPool;
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};
use tower::ServiceExt;
use uuid::Uuid;

const RESOURCE: &str = "http://localhost:8080/mcp";
const MODEL_ID: &str = concat!(
    "stub-model2vec-512@sha256:",
    "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"
);
struct RemoteEmbedder;
impl ChunkEmbedder for RemoteEmbedder {
    fn dim(&self) -> usize {
        512
    }
    fn model_id(&self) -> &'static str {
        MODEL_ID
    }
    fn encode_batch(&self, texts: &[&str]) -> Vec<Vec<f32>> {
        StubEmbedder.encode_batch(texts)
    }
}

struct Fixture {
    owner: PgPool,
    enrollment: RuntimeProbeRole,
    runtime: RuntimeProbeRole,
    registry: PrincipalRegistry,
    app: Router,
    backend: Arc<RemoteBackend>,
    services: Arc<ScopeServices>,
    provider: FakeProvider,
    signer: Ed25519Signer,
    local_signer: Ed25519Signer,
    _local_keys: tempfile::NamedTempFile,
    _transcript_spool: tempfile::TempDir,
    principals: Vec<PrincipalDeclaration>,
}

impl Fixture {
    // Keep the complete isolated trust roots, role grants and scope setup together.
    #[allow(clippy::too_many_lines)]
    async fn new(url: &str) -> Self {
        let owner = common::migrated_pool(url).await;
        let enrollment = RuntimeProbeRole::create_enrollment(&owner, url).await;
        let runtime = RuntimeProbeRole::create_serve_writer(&owner, url).await;
        probe_remote_plane(&runtime.pool).await.unwrap();
        assert!(probe_remote_plane(&enrollment.pool).await.is_err());
        let registry = PrincipalRegistry::new(enrollment.pool.clone());
        let signer = Ed25519Signer::from_seed_hex("oidc-test", &"61".repeat(32)).unwrap();
        let jwk = signer.public_jwk();
        let issuer_slot = Arc::new(Mutex::new(String::new()));
        let slot = issuer_slot.clone();
        let provider = FakeProvider::start(move |request| match request.path.as_str() {
            "/.well-known/openid-configuration" => {
                let issuer = slot.lock().unwrap().clone();
                FakeReply::json(&json!({"issuer":issuer,"jwks_uri":format!("{issuer}keys")}))
            }
            "/keys" => FakeReply::json(&json!({"keys":[jwk]})),
            _ => FakeReply::status(404, "not found"),
        })
        .await;
        let issuer = format!("{}/", provider.base);
        issuer_slot.lock().unwrap().clone_from(&issuer);
        let local_id = format!("laptop-{}", Uuid::now_v7().simple());
        let local_signer = Ed25519Signer::from_seed_hex(&local_id, &"62".repeat(32)).unwrap();
        let local_public =
            hex::encode(decode_url(local_signer.public_jwk().x.as_deref().unwrap()).unwrap());
        let local_keys = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            local_keys.path(),
            serde_json::to_vec(&BTreeMap::from([(local_id.clone(), local_public)])).unwrap(),
        )
        .unwrap();
        let scope_a = common::fresh_scope("remote-http");
        let scope_b = common::fresh_scope("remote-http");
        let declaration =
            |subject: &str, role, scope: &FleetScope, ceiling, agent: &str| PrincipalDeclaration {
                principal_id: Uuid::now_v7(),
                anchor_id: "test-oidc".into(),
                subject_pattern: format!("{}-{subject}", scope.tenant_id),
                role,
                tenant_id: scope.tenant_id,
                project: scope.project.clone(),
                ceiling,
                agent_pattern: agent.into(),
            };
        let mut principals = vec![
            declaration(
                "operator",
                PrincipalRole::Operator,
                &scope_a,
                Ceiling::Project,
                "operator-one",
            ),
            declaration(
                "other",
                PrincipalRole::Operator,
                &scope_b,
                Ceiling::Project,
                "operator-two",
            ),
            declaration(
                "launcher",
                PrincipalRole::Launcher,
                &scope_a,
                Ceiling::Project,
                "sandbox-*",
            ),
            declaration(
                "reader",
                PrincipalRole::Operator,
                &scope_a,
                Ceiling::Public,
                "public-reader",
            ),
            declaration(
                "shipper",
                PrincipalRole::Shipper,
                &scope_a,
                Ceiling::Project,
                "host-shipper",
            ),
            declaration(
                "local",
                PrincipalRole::Operator,
                &scope_a,
                Ceiling::Project,
                "local-human",
            ),
        ];
        principals[5].anchor_id = "local-key".into();
        principals[5].subject_pattern = local_id;
        registry
            .apply(
                &DeclarationFile {
                    principals: principals.clone(),
                },
                false,
            )
            .await
            .unwrap();
        let fleet = FleetConfig {
            database_url: url.into(),
            database_ssl_policy: PrivatePostgresSslPolicy::Disable,
            default_scope: common::fresh_scope("unused-pinned-scope"),
            max_connections: 4,
            embedding_model: "stub-model2vec-512".into(),
            embedding_model_path: PathBuf::new(),
            embedding_model_sha256: hex::encode(STUB_MODEL_DIGEST),
            lifecycle: LifecycleConfig {
                remember_lifecycle: false,
                conflict_adjudication: false,
            },
        };
        assert_eq!(fleet.embedding_model_identity(), MODEL_ID);
        for scope in [&scope_a, &scope_b] {
            CockroachStore::from_pool(owner.clone(), scope.clone())
                .unwrap()
                .initialize_embedding_model(MODEL_ID)
                .await
                .unwrap();
        }
        let variables = BTreeMap::from([
            ("FLEET_RECALL_RESOURCE_URL", RESOURCE.to_owned()),
            ("FLEET_RECALL_GRANT_SIGNING_KEY_HEX", "63".repeat(32)),
            ("FLEET_RECALL_OIDC_ISSUERS", format!("test-oidc={issuer}")),
            (
                "FLEET_RECALL_LOCAL_KEY_ANCHOR_PATH",
                local_keys.path().to_str().unwrap().into(),
            ),
            ("FLEET_RECALL_GRANT_CHECK_CACHE_SECONDS", "1".into()),
        ]);
        let config = RemoteConfig::from_lookup(|name| variables.get(name).cloned()).unwrap();
        let services = Arc::new(
            ScopeServices::new(fleet, runtime.pool.clone(), Arc::new(RemoteEmbedder), 4, 16)
                .unwrap(),
        );
        let transcript_spool = tempfile::tempdir().unwrap();
        let receiver = ostk_fleet_recall::transcripts::TranscriptReceiver::new(
            ostk_fleet_recall::transcripts::TranscriptReceiverConfig::new(
                transcript_spool.path().into(),
            ),
        )
        .unwrap();
        let backend = Arc::new(
            RemoteBackend::new(&config, runtime.pool.clone(), services.clone())
                .unwrap()
                .with_transcript_receiver(Arc::new(receiver)),
        );
        let app = http::router(config.http, backend.clone()).unwrap();
        Self {
            owner,
            enrollment,
            runtime,
            registry,
            app,
            backend,
            services,
            provider,
            signer,
            local_signer,
            _local_keys: local_keys,
            _transcript_spool: transcript_spool,
            principals,
        }
    }

    fn token(&self, index: usize) -> String {
        let principal = &self.principals[index];
        let now = Utc::now().timestamp();
        let mut claims = json!({"iss":format!("{}/",self.provider.base),"aud":RESOURCE,"sub":principal.subject_pattern,"iat":now,"exp":now+300,"jti":Uuid::now_v7().to_string()});
        if principal.anchor_id == "local-key" {
            claims["iss"] = json!("fleet-recall-local-key");
            self.local_signer.sign(&claims).unwrap()
        } else {
            self.signer.sign(&claims).unwrap()
        }
    }

    async fn request(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        value: Value,
        headers: &[(&str, &str)],
    ) -> (StatusCode, Value) {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json");
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let response = self
            .app
            .clone()
            .oneshot(
                request
                    .body(Body::from(serde_json::to_vec(&value).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 2_097_152).await.unwrap();
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        };
        (status, value)
    }

    async fn tool(&self, token: &str, name: &str, arguments: Value) -> (StatusCode, Value) {
        self.request("POST","/mcp",Some(token),json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":name,"arguments":arguments}}),&[]).await
    }

    async fn cleanup(self) {
        let Self {
            owner,
            enrollment,
            runtime,
            app,
            backend,
            services,
            registry,
            ..
        } = self;
        drop(app);
        drop(backend);
        drop(services);
        drop(registry);
        runtime.drop_role(&owner).await;
        enrollment.drop_role(&owner).await;
        owner.close().await;
    }
}

fn successful(mut response: (StatusCode, Value)) -> Value {
    assert_eq!(response.0, StatusCode::OK, "{}", response.1);
    assert_eq!(response.1["result"]["isError"], false, "{}", response.1);
    response.1["result"]["structuredContent"].take()
}

async fn identity_and_isolation(f: &Fixture) {
    let operator = f.token(0);
    let other = f.token(1);
    let local = f.token(5);
    let recorded=successful(f.tool(&operator,"remember",json!({"action":"record","idempotency_key":"remote-record-one","kind":"note","text":"amethyst aircraft remembered by operator one"})).await);
    let claim_id = recorded["data"]["claim"]["id"].clone();
    assert!(!claim_id.is_null(), "{recorded}");
    let own = successful(
        f.tool(
            &operator,
            "recall",
            json!({"action":"get","kind":"claim","id":claim_id}),
        )
        .await,
    );
    assert_eq!(own["data"]["claim"]["id"], claim_id);
    let cross = successful(
        f.tool(
            &other,
            "recall",
            json!({"action":"get","kind":"claim","id":claim_id}),
        )
        .await,
    );
    assert!(cross["data"]["claim"].is_null(), "{cross}");
    let same_project = successful(
        f.tool(
            &local,
            "recall",
            json!({"action":"get","kind":"claim","id":claim_id}),
        )
        .await,
    );
    assert_eq!(same_project["data"]["claim"]["id"], claim_id);
    for scope in [
        json!({"project":"different-project"}),
        json!({"agent":"other-agent"}),
        json!({"tenant_id":Uuid::now_v7()}),
    ] {
        let response = f
            .tool(
                &operator,
                "recall",
                json!({"action":"status","scope":scope}),
            )
            .await;
        assert_eq!(response.0, StatusCode::FORBIDDEN, "{}", response.1);
    }
    let now = Utc::now().timestamp();
    let unenrolled=f.signer.sign(&json!({"iss":format!("{}/",f.provider.base),"aud":RESOURCE,"sub":"no-registry-entry","exp":now+60})).unwrap();
    assert_eq!(
        f.tool(&unenrolled, "recall", json!({"action":"status"}))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    for principal in [3, 4] {
        let token = f.token(principal);
        let denied=f.tool(&token,"remember",json!({"action":"record","idempotency_key":"must-not-write","kind":"note","text":"must never be persisted"})).await;
        assert_eq!(denied.0, StatusCode::FORBIDDEN, "{}", denied.1);
        assert_eq!(denied.1["error"]["data"]["code"], "role_forbids_action");
    }
    let shipper = f.token(4);
    assert_eq!(
        f.tool(
            &shipper,
            "recall",
            json!({"action":"search","query":"amethyst"})
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    successful(f.tool(&shipper, "recall", json!({"action":"status"})).await);
    let capture = f
        .tool(
            &shipper,
            "remember",
            json!({"action":"capture","idempotency_key":"shipper-capture"}),
        )
        .await;
    assert_eq!(capture.1["error"]["data"]["code"], "capture_unavailable");
    let first = f.backend.authenticate(&operator).await.unwrap();
    let second = f.backend.authenticate(&operator).await.unwrap();
    assert!(
        Arc::ptr_eq(&first, &second),
        "an authenticated agent reuses its scoped MCP edge"
    );
    let other_agent = f.backend.authenticate(&local).await.unwrap();
    assert!(!Arc::ptr_eq(&first, &other_agent));
}

async fn invalid_bearers(f: &Fixture) {
    let now = Utc::now().timestamp();
    let claims = json!({"iss":format!("{}/",f.provider.base),"aud":RESOURCE,"sub":f.principals[0].subject_pattern,"exp":now+60});
    let rogue = Ed25519Signer::from_seed_hex("oidc-test", &"77".repeat(32)).unwrap();
    let mut invalid = vec![rogue.sign(&claims).unwrap()];
    for (field, value) in [
        ("exp", json!(now - 61)),
        ("aud", json!("https://other-resource/mcp")),
        ("iss", json!("https://unconfigured-issuer/")),
    ] {
        let mut altered = claims.clone();
        altered[field] = value;
        invalid.push(f.signer.sign(&altered).unwrap());
    }
    for token in invalid {
        assert_eq!(
            f.tool(&token, "recall", json!({"action":"status"})).await.0,
            StatusCode::UNAUTHORIZED
        );
    }
}

async fn transcript_grant_binding(f: &Fixture) {
    let sandbox = Uuid::now_v7().to_string();
    for index in [0, 2, 4] {
        assert!(
            f.backend
                .transcript_receiver(&f.token(index), &sandbox)
                .await
                .is_err(),
            "operator, launcher and direct shipper identities are not delegated shipper grants"
        );
    }
    let launcher = f.token(2);
    for (kind, bound, allowed) in [
        ("agent", Some(sandbox.as_str()), false),
        ("shipper", None, false),
        ("shipper", Some(sandbox.as_str()), true),
    ] {
        let (status, issued) = f
            .request(
                "POST",
                "/v1/grants",
                Some(&launcher),
                json!({"kind":kind,"agent":"sandbox-transcript","sandbox_id":bound}),
                &[],
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{issued}");
        let token = issued["token"].as_str().unwrap();
        assert_eq!(
            f.backend.transcript_receiver(token, &sandbox).await.is_ok(),
            allowed
        );
        assert!(
            f.backend
                .transcript_receiver(token, &Uuid::now_v7().to_string())
                .await
                .is_err()
        );
        if allowed {
            let (_, auth) = f
                .backend
                .transcript_receiver(token, &sandbox)
                .await
                .unwrap();
            assert_eq!(auth.tenant_id, f.principals[2].tenant_id);
            assert_eq!(auth.project, f.principals[2].project);
            assert_eq!(auth.agent, "sandbox-transcript");
            let jti = issued["grant"]["jti"].as_str().unwrap();
            assert_eq!(
                f.request(
                    "DELETE",
                    &format!("/v1/grants/{jti}"),
                    Some(&launcher),
                    Value::Null,
                    &[]
                )
                .await
                .0,
                StatusCode::NO_CONTENT
            );
            assert!(
                f.backend
                    .transcript_receiver(token, &sandbox)
                    .await
                    .is_err()
            );
        }
    }
}

// One delegation lifecycle proves issue, denied operations, revoke and revision checks.
#[allow(clippy::too_many_lines)]
async fn grants_and_revocations(f: &Fixture) {
    let launcher = f.token(2);
    let operator = f.token(0);
    assert_eq!(
        f.request(
            "POST",
            "/v1/grants",
            Some(&operator),
            json!({"kind":"agent","agent":"sandbox-one"}),
            &[]
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        f.request(
            "POST",
            "/v1/grants",
            Some(&launcher),
            json!({"kind":"agent","agent":"unrelated"}),
            &[]
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let (status, issued) = f
        .request(
            "POST",
            "/v1/grants",
            Some(&launcher),
            json!({"kind":"agent","agent":"sandbox-one","sandbox_id":"box-one"}),
            &[],
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{issued}");
    let grant = issued["token"].as_str().unwrap();
    successful(f.tool(grant,"remember",json!({"action":"record","idempotency_key":"sandbox-record-one","kind":"note","text":"sandbox one writes in its enrolled project"})).await);
    assert_eq!(
        f.tool(
            grant,
            "recall",
            json!({"action":"status","scope":{"agent":"sandbox-two"}})
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        f.request(
            "POST",
            "/v1/grants",
            Some(grant),
            json!({"kind":"agent","agent":"sandbox-nested"}),
            &[]
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    let jti = issued["grant"]["jti"].as_str().unwrap();
    assert_eq!(
        f.request(
            "DELETE",
            &format!("/v1/grants/{jti}"),
            Some(&f.token(1)),
            Value::Null,
            &[]
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    successful(f.tool(grant, "recall", json!({"action":"status"})).await);
    assert_eq!(
        f.request(
            "DELETE",
            &format!("/v1/grants/{jti}"),
            Some(&launcher),
            Value::Null,
            &[]
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        f.tool(grant, "recall", json!({"action":"status"})).await.0,
        StatusCode::UNAUTHORIZED
    );
    let (status, shipper) = f
        .request(
            "POST",
            "/v1/grants",
            Some(&launcher),
            json!({"kind":"shipper","agent":"sandbox-two"}),
            &[],
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{shipper}");
    let token = shipper["token"].as_str().unwrap();
    successful(f.tool(token, "recall", json!({"action":"status"})).await);
    assert_eq!(f.tool(token,"remember",json!({"action":"record","idempotency_key":"shipper-forbidden","kind":"note","text":"shipper cannot author"})).await.0,StatusCode::FORBIDDEN);
    let mut revised = f.principals[2].clone();
    revised.agent_pattern = "replacement-*".into();
    f.registry
        .apply(
            &DeclarationFile {
                principals: vec![revised],
            },
            false,
        )
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(
        f.tool(token, "recall", json!({"action":"status"})).await.0,
        StatusCode::UNAUTHORIZED
    );
    f.registry
        .revoke(f.principals[0].principal_id)
        .await
        .unwrap();
    assert_eq!(
        f.tool(&operator, "recall", json!({"action":"status"}))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
}

// These cases share one authenticated edge and exercise independent HTTP boundaries.
#[allow(clippy::too_many_lines)]
async fn protocol_and_bootstrap(f: &Fixture) {
    let token = f.token(0);
    let modern = json!({"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"recall","arguments":{"action":"status"},"_meta":{"io.modelcontextprotocol/protocolVersion":MODERN_PROTOCOL_VERSION,"io.modelcontextprotocol/clientCapabilities":{}}}});
    let (status, response) = f
        .request(
            "POST",
            "/mcp",
            Some(&token),
            modern.clone(),
            &[
                ("mcp-protocol-version", MODERN_PROTOCOL_VERSION),
                ("mcp-method", "tools/call"),
                ("mcp-name", "recall"),
            ],
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["result"]["resultType"], "complete");
    let mismatch = f
        .request(
            "POST",
            "/mcp",
            Some(&token),
            modern,
            &[
                ("mcp-protocol-version", MODERN_PROTOCOL_VERSION),
                ("mcp-method", "tools/list"),
                ("mcp-name", "recall"),
            ],
        )
        .await;
    assert_eq!(mismatch.0, StatusCode::BAD_REQUEST);
    assert_eq!(mismatch.1["error"]["code"], -32020);
    assert_eq!(
        f.request(
            "POST",
            "/mcp",
            Some(&token),
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),
            &[]
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        f.request(
            "POST",
            "/mcp",
            Some(&token),
            json!({"jsonrpc":"2.0","id":2,"method":"unknown/method"}),
            &[]
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        f.request(
            "POST",
            "/mcp",
            Some(&token),
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            &[]
        )
        .await
        .0,
        StatusCode::ACCEPTED
    );
    assert_eq!(
        f.request(
            "POST",
            "/mcp",
            Some(&token),
            json!({"jsonrpc":"2.0","id":1,"method":"ping"}),
            &[("origin", "https://attacker.example")]
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        f.request("GET", "/mcp", None, Value::Null, &[]).await.0,
        StatusCode::UNAUTHORIZED
    );
    let metadata = f
        .request(
            "GET",
            "/.well-known/oauth-protected-resource/mcp",
            None,
            Value::Null,
            &[],
        )
        .await;
    assert_eq!(metadata.0, StatusCode::OK);
    assert_eq!(metadata.1["resource"], RESOURCE);
    let mut missing = f.principals[0].clone();
    missing.principal_id = Uuid::now_v7();
    missing.subject_pattern = format!("scope-not-bootstrapped-{}", Uuid::now_v7());
    missing.tenant_id = Uuid::now_v7();
    f.registry
        .apply(
            &DeclarationFile {
                principals: vec![missing.clone()],
            },
            false,
        )
        .await
        .unwrap();
    let now = Utc::now().timestamp();
    let unbootstrapped=f.signer.sign(&json!({"iss":format!("{}/",f.provider.base),"aud":RESOURCE,"sub":missing.subject_pattern,"exp":now+60})).unwrap();
    assert_eq!(
        f.tool(&unbootstrapped, "recall", json!({"action":"status"}))
            .await
            .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_remote_plane_enforces_identity_scope_roles_and_revocation() {
    let Some(url) = common::test_database_url() else {
        return;
    };
    let fixture = Fixture::new(&url).await;
    identity_and_isolation(&fixture).await;
    invalid_bearers(&fixture).await;
    protocol_and_bootstrap(&fixture).await;
    transcript_grant_binding(&fixture).await;
    grants_and_revocations(&fixture).await;
    fixture.cleanup().await;
}
