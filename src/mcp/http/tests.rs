use std::sync::atomic::{AtomicUsize, Ordering};

use axum::http::Request as HttpRequest;
use ostk_recall_core::PrivacyTier;
use tower::ServiceExt as _;
use tracing::instrument::WithSubscriber as _;
use uuid::Uuid;

use crate::FleetScope;
use crate::service::{
    FleetMemoryService, RecallRequest, RecallResult, RememberRequest, RememberResult, ServiceResult,
};

use super::*;

#[derive(Default)]
struct Memory {
    writes: AtomicUsize,
    delay: Duration,
    forbid_writes: bool,
}

#[async_trait]
impl FleetMemoryService for Memory {
    async fn recall(
        &self,
        _scope: FleetScope,
        _request: RecallRequest,
    ) -> ServiceResult<RecallResult> {
        Ok(RecallResult::new(json!({"status":"ok"})))
    }

    async fn remember(
        &self,
        _scope: FleetScope,
        _request: RememberRequest,
    ) -> ServiceResult<RememberResult> {
        if self.forbid_writes {
            return Err(crate::service::ServiceError::Refused(
                crate::service::Refusal {
                    code: "role_forbids_action",
                    message: "this role cannot write".into(),
                    details: json!({}),
                },
            ));
        }
        if !self.delay.is_zero() {
            tokio::time::sleep(self.delay).await;
        }
        self.writes.fetch_add(1, Ordering::SeqCst);
        Ok(RememberResult::new(json!({"applied":true})))
    }
}

struct Backend {
    server: Arc<McpServer>,
    authentications: AtomicUsize,
    issued: AtomicUsize,
    revoked: AtomicUsize,
    exchanges: AtomicUsize,
}

impl Backend {
    fn new(memory: Arc<Memory>) -> Arc<Self> {
        let scope = FleetScope::new(
            Uuid::now_v7(),
            "project",
            "agent",
            None,
            PrivacyTier::T1Project,
        )
        .unwrap();
        Arc::new(Self {
            server: Arc::new(McpServer::new(memory, scope).unwrap()),
            authentications: AtomicUsize::new(0),
            issued: AtomicUsize::new(0),
            revoked: AtomicUsize::new(0),
            exchanges: AtomicUsize::new(0),
        })
    }
}

#[async_trait]
impl HttpBackend for Backend {
    async fn authenticate(&self, token: &str) -> std::result::Result<Arc<McpServer>, HttpError> {
        self.authentications.fetch_add(1, Ordering::SeqCst);
        match token {
            "valid" => Ok(self.server.clone()),
            "forbidden" => Err(HttpError::Forbidden),
            "unavailable" => Err(HttpError::Unavailable("scope_not_bootstrapped")),
            _ => Err(HttpError::Unauthorized),
        }
    }

    async fn issue_grant(
        &self,
        token: &str,
        request: Value,
    ) -> std::result::Result<Value, HttpError> {
        self.authenticate(token).await?;
        self.issued.fetch_add(1, Ordering::SeqCst);
        Ok(json!({"token":"grant", "kind":request["kind"]}))
    }

    async fn revoke_grant(&self, token: &str, jti: &str) -> std::result::Result<(), HttpError> {
        self.authenticate(token).await?;
        assert_eq!(jti, "grant-1");
        self.revoked.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn exchange_aws(&self, request: Value) -> std::result::Result<Value, HttpError> {
        if request["proof"] != "valid" {
            return Err(HttpError::Unauthorized);
        }
        self.exchanges.fetch_add(1, Ordering::SeqCst);
        Ok(json!({"token":"identity"}))
    }
}

fn config() -> HttpConfig {
    HttpConfig::new(
        "https://recall.example/mcp".into(),
        vec!["https://id.example/".into()],
    )
}

fn request(path: &str, body: &Value) -> HttpRequest<Body> {
    HttpRequest::post(path)
        .header("authorization", "Bearer valid")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap()
}

fn modern(method: &str) -> Value {
    json!({"jsonrpc":"2.0", "id":1, "method":method, "params": {
        "_meta": {
            PROTOCOL_VERSION_META: MODERN_PROTOCOL_VERSION,
            CLIENT_CAPABILITIES_META: {}
        }
    }})
}

fn modern_request(body: &Value) -> HttpRequest<Body> {
    let mut req = request("/mcp", body);
    req.headers_mut().insert(
        "mcp-protocol-version",
        HeaderValue::from_str(
            body["params"]["_meta"][PROTOCOL_VERSION_META]
                .as_str()
                .unwrap(),
        )
        .unwrap(),
    );
    req.headers_mut().insert(
        "mcp-method",
        HeaderValue::from_str(body["method"].as_str().unwrap()).unwrap(),
    );
    if let Some(name) = body["params"]["name"].as_str() {
        req.headers_mut()
            .insert("mcp-name", HeaderValue::from_str(name).unwrap());
    }
    req
}

async fn json_body(response: Response) -> Value {
    serde_json::from_slice(
        &to_bytes(response.into_body(), MAX_MCP_FRAME_BYTES)
            .await
            .unwrap(),
    )
    .unwrap()
}

#[derive(Clone, Default)]
struct TelemetryLog(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for TelemetryLog {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test(flavor = "current_thread")]
async fn telemetry_covers_remote_rejections_and_correlates_dispatch_without_payloads() {
    crate::telemetry::prepare_test_capture();
    let log = TelemetryLog::default();
    let writer = log.clone();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    exercise_remote_telemetry()
        .with_subscriber(subscriber)
        .await;
    assert_remote_telemetry(&log);
}

async fn exercise_remote_telemetry() {
    let app = router(config(), Backend::new(Arc::new(Memory::default()))).unwrap();
    let mut untrusted_origin = modern_request(&modern("ping"));
    untrusted_origin.headers_mut().insert(
        "origin",
        HeaderValue::from_static("https://private-origin.example"),
    );
    let private_bearer = HttpRequest::get("/mcp")
        .header("authorization", "Bearer private-token")
        .body(Body::empty())
        .unwrap();
    let unknown_route = HttpRequest::get("/private-path?token=private-query")
        .body(Body::empty())
        .unwrap();
    let invalid_json = HttpRequest::post("/mcp")
        .header("authorization", "Bearer valid")
        .header("content-type", "application/json")
        .body(Body::from("private-invalid-json"))
        .unwrap();
    for (request, expected) in [
        (untrusted_origin, StatusCode::FORBIDDEN),
        (private_bearer, StatusCode::UNAUTHORIZED),
        (unknown_route, StatusCode::NOT_FOUND),
        (invalid_json, StatusCode::BAD_REQUEST),
    ] {
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            expected
        );
    }
    let mut discover = modern("server/discover");
    discover["id"] = json!("private-request-id");
    assert_eq!(
        app.oneshot(modern_request(&discover))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );

    let remember = json!({"jsonrpc":"2.0","id":"private-request-id","method":"tools/call",
        "params":{"name":"remember","arguments":{"action":"record",
            "idempotency_key":"private-key","text":"private-document"}}});
    for (memory, expected) in [
        (
            Memory {
                forbid_writes: true,
                ..Memory::default()
            },
            StatusCode::FORBIDDEN,
        ),
        (
            Memory {
                delay: Duration::from_secs(1),
                ..Memory::default()
            },
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
    ] {
        let mut settings = config();
        settings.request_deadline = Duration::from_millis(1);
        let app = router(settings, Backend::new(Arc::new(memory))).unwrap();
        assert_eq!(
            app.oneshot(request("/mcp", &remember))
                .await
                .unwrap()
                .status(),
            expected
        );
    }
}

fn assert_remote_telemetry(log: &TelemetryLog) {
    let encoded = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
    for private in [
        "private-",
        "recall.example",
        "id.example",
        "\"project\"",
        "\"agent\"",
    ] {
        assert!(!encoded.contains(private), "telemetry leaked {private}");
    }
    let events: Vec<Value> = encoded
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .filter(|event: &Value| event["fields"]["event"] == "operation.completed")
        .collect();
    let actual: Vec<_> = events
        .iter()
        .map(|event| {
            let fields = &event["fields"];
            (
                fields["component"].as_str().unwrap(),
                fields["operation"].as_str().unwrap(),
                fields["outcome"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        actual,
        [
            ("http_mcp", "mcp", "refused"),
            ("http_mcp", "mcp", "refused"),
            ("http_mcp", "other", "invalid"),
            ("http_mcp", "mcp", "invalid"),
            ("mcp", "server.discover", "success"),
            ("http_mcp", "mcp", "success"),
            ("mcp", "remember.record", "refused"),
            ("http_mcp", "mcp", "refused"),
            ("mcp", "remember.record", "timeout"),
            ("http_mcp", "mcp", "error"),
        ],
        "{encoded}"
    );
    // Nested boundaries count different work; their generated IDs correlate
    // through spans without retaining bearer, caller ID, scope, or payload.
    for dispatch in [4, 6, 8] {
        let http_span = &events[dispatch + 1]["span"];
        let parents = events[dispatch]["spans"].as_array().unwrap();
        assert!(parents.iter().any(|span| span["component"] == "http_mcp"
            && span["operation_id"] == http_span["operation_id"]));
        assert_ne!(
            events[dispatch]["span"]["operation_id"],
            http_span["operation_id"]
        );
    }
}

#[tokio::test]
async fn configured_human_discovery_and_refresh_scopes_are_served_without_authentication() {
    let settings = [
        ("FLEET_RECALL_RESOURCE_URL", "https://recall.example/mcp"),
        (
            "FLEET_RECALL_GRANT_SIGNING_KEY_HEX",
            "unused-in-router-test",
        ),
        (
            "FLEET_RECALL_OIDC_ISSUERS",
            "human=https://id.example/,k8s=https://kubernetes.default.svc",
        ),
        ("FLEET_RECALL_OAUTH_ADVERTISED_ANCHORS", "human"),
        (
            "FLEET_RECALL_OAUTH_SCOPES",
            "openid,offline_access,fleet-recall",
        ),
    ];
    let configured = crate::remote::RemoteConfig::from_lookup(|name| {
        settings
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| (*value).into())
    })
    .unwrap();
    let backend = Backend::new(Arc::new(Memory::default()));
    let app = router(configured.http, backend.clone()).unwrap();
    for path in [
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource/mcp",
    ] {
        let response = app
            .clone()
            .oneshot(
                HttpRequest::get(path)
                    .header("host", "attacker.example")
                    .header("x-forwarded-host", "attacker.example")
                    .header("x-forwarded-proto", "http")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "no-store");
        let body = json_body(response).await;
        assert_eq!(body["resource"], "https://recall.example/mcp");
        assert_eq!(
            body["authorization_servers"],
            json!(["https://id.example/"])
        );
        assert_eq!(
            body["scopes_supported"],
            json!(["openid", "offline_access", "fleet-recall"])
        );
        assert!(!body.to_string().contains("kubernetes"));
    }
    assert_eq!(backend.authentications.load(Ordering::SeqCst), 0);
    let response = app.oneshot(modern_request(&modern("ping"))).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(backend.authentications.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn machine_only_metadata_has_no_advertised_authorization_servers() {
    let mut settings = config();
    settings.authorization_servers.clear();
    settings.scopes_supported.clear();
    let app = router(settings, Backend::new(Arc::new(Memory::default()))).unwrap();
    let response = app
        .oneshot(
            HttpRequest::get("/.well-known/oauth-protected-resource/mcp")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["authorization_servers"], json!([]));
    assert_eq!(body["scopes_supported"], json!([]));
}

#[tokio::test]
async fn metadata_authentication_and_origin_protection() {
    let backend = Backend::new(Arc::new(Memory::default()));
    let app = router(config(), backend.clone()).unwrap();
    for path in [
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource/mcp",
    ] {
        let response = app
            .clone()
            .oneshot(HttpRequest::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
        let body = json_body(response).await;
        assert_eq!(body["resource"], "https://recall.example/mcp");
        assert_eq!(
            body["authorization_servers"],
            json!(["https://id.example/"])
        );
        assert_eq!(body["scopes_supported"], json!(["fleet-recall"]));
        assert_eq!(body["bearer_methods_supported"], json!(["header"]));
    }
    let response = app
        .clone()
        .oneshot(HttpRequest::get("/mcp").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers()["www-authenticate"],
        "Bearer resource_metadata=\"https://recall.example/.well-known/oauth-protected-resource/mcp\", error=\"invalid_token\""
    );
    for origin in [
        "https://attacker.example",
        "null",
        "https://recall.example.attacker.test",
    ] {
        let mut req = request("/mcp", &modern("ping"));
        req.headers_mut()
            .insert("origin", HeaderValue::from_str(origin).unwrap());
        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(response.headers()["cache-control"], "no-store");
    }
    assert_eq!(backend.authentications.load(Ordering::SeqCst), 0);
    let mut req = modern_request(&modern("ping"));
    req.headers_mut()
        .insert("origin", HeaderValue::from_static("https://recall.example"));
    assert_eq!(app.oneshot(req).await.unwrap().status(), StatusCode::OK);
}

#[tokio::test]
async fn legacy_initialization_and_notifications_keep_their_wire_shape() {
    let memory = Arc::new(Memory::default());
    let app = router(config(), Backend::new(memory.clone())).unwrap();
    let response = app
        .clone()
        .oneshot(request(
            "/mcp",
            &json!({"jsonrpc":"2.0","id":1,"method":"initialize"}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().get("mcp-session-id").is_none());
    let body = json_body(response).await;
    assert_eq!(body["result"]["protocolVersion"], PROTOCOL_VERSION);
    assert!(body["result"].get("resultType").is_none());
    let response = app.clone().oneshot(request("/mcp", &json!({"jsonrpc":"2.0","method":"tools/call","params":{"name":"remember","arguments":{"action":"record"}}}))).await.unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert!(
        to_bytes(response.into_body(), 1024)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(memory.writes.load(Ordering::SeqCst), 0);
    for method in ["GET", "DELETE"] {
        let req = HttpRequest::builder()
            .method(method)
            .uri("/mcp")
            .header("authorization", "Bearer valid")
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(response.headers()["allow"], "POST");
    }
}

#[tokio::test]
async fn modern_discovery_unknown_methods_and_header_consistency() {
    let app = router(config(), Backend::new(Arc::new(Memory::default()))).unwrap();
    let response = app
        .clone()
        .oneshot(modern_request(&modern("server/discover")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["result"]["resultType"], "complete");
    assert_eq!(body["result"]["ttlMs"].as_u64(), Some(0));
    assert_eq!(body["result"]["cacheScope"], "private");
    assert_eq!(
        body["result"]["supportedVersions"],
        json!([MODERN_PROTOCOL_VERSION, PROTOCOL_VERSION])
    );
    assert_eq!(
        body["result"]["_meta"]["io.modelcontextprotocol/serverInfo"]["name"],
        "ostk-fleet-recall"
    );
    let response = app
        .clone()
        .oneshot(modern_request(&modern("missing/method")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        json_body(response).await["error"]["code"],
        codes::METHOD_NOT_FOUND
    );

    for header in ["mcp-protocol-version", "mcp-method"] {
        let mut req = modern_request(&modern("ping"));
        req.headers_mut().remove(header);
        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            json_body(response).await["error"]["code"],
            codes::HEADER_MISMATCH
        );
        let mut req = modern_request(&modern("ping"));
        req.headers_mut()
            .append(header, HeaderValue::from_static("conflicting"));
        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            json_body(response).await["error"]["code"],
            codes::HEADER_MISMATCH
        );
    }
    let mut body = modern("tools/call");
    body["params"]["name"] = json!("recall");
    body["params"]["arguments"] = json!({"action":"status"});
    let mut req = modern_request(&body);
    req.headers_mut()
        .insert("mcp-name", HeaderValue::from_static("remember"));
    let response = app.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        json_body(response).await["error"]["code"],
        codes::HEADER_MISMATCH
    );
    let mut req = modern_request(&body);
    req.headers_mut().remove("mcp-name");
    assert_eq!(
        json_body(app.oneshot(req).await.unwrap()).await["error"]["code"],
        codes::HEADER_MISMATCH
    );
}

#[tokio::test]
async fn modern_tool_list_carries_private_cache_hints_without_changing_legacy_tools() {
    let app = router(config(), Backend::new(Arc::new(Memory::default()))).unwrap();
    let response = app
        .clone()
        .oneshot(modern_request(&modern("tools/list")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut modern = json_body(response).await["result"].clone();
    assert_eq!(modern["ttlMs"].as_u64(), Some(0));
    assert_eq!(modern["cacheScope"], "private");
    assert_eq!(modern["resultType"], "complete");
    assert_eq!(modern["tools"].as_array().unwrap().len(), 2);

    let legacy = json_body(
        app.oneshot(request(
            "/mcp",
            &json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
        ))
        .await
        .unwrap(),
    )
    .await;
    for key in ["ttlMs", "cacheScope", "resultType", "_meta"] {
        assert!(legacy["result"].get(key).is_none(), "legacy field {key}");
        modern.as_object_mut().unwrap().remove(key);
    }
    assert_eq!(modern, legacy["result"]);
}

#[tokio::test]
async fn modern_metadata_failures_do_not_downgrade_to_legacy() {
    let app = router(config(), Backend::new(Arc::new(Memory::default()))).unwrap();
    let mut body = modern("ping");
    body["params"]["_meta"][PROTOCOL_VERSION_META] = json!("2099-01-01");
    let response = app.clone().oneshot(modern_request(&body)).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let failure = json_body(response).await;
    assert_eq!(
        failure["error"]["code"],
        codes::UNSUPPORTED_PROTOCOL_VERSION
    );
    assert_eq!(failure["error"]["data"]["requested"], "2099-01-01");
    assert_eq!(
        failure["error"]["data"]["supported"][0],
        MODERN_PROTOCOL_VERSION
    );
    for malformed in [json!(null), json!([]), json!("capabilities")] {
        let mut body = modern("ping");
        body["params"]["_meta"][CLIENT_CAPABILITIES_META] = malformed;
        let response = app.clone().oneshot(modern_request(&body)).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            json_body(response).await["error"]["code"],
            codes::INVALID_PARAMS
        );
    }
    let mut body = modern("ping");
    body["params"]["_meta"]
        .as_object_mut()
        .unwrap()
        .remove(PROTOCOL_VERSION_META);
    let response = app.clone().oneshot(request("/mcp", &body)).await.unwrap();
    assert_eq!(
        json_body(response).await["error"]["code"],
        codes::INVALID_PARAMS
    );
    for id in [json!(null), json!(1.5)] {
        let mut body = modern("ping");
        body["id"] = id;
        let response = app.clone().oneshot(modern_request(&body)).await.unwrap();
        assert_eq!(
            json_body(response).await["error"]["code"],
            codes::INVALID_REQUEST
        );
    }
}

#[test]
fn name_header_decodes_utf8_and_sentinel_literals_strictly() {
    for name in [
        "recall",
        "mémoire",
        " padded ",
        "line\nbreak",
        "=?base64?literal?=",
    ] {
        let mut body = modern("tools/call");
        body["params"]["name"] = json!(name);
        let parsed = JsonRpcRequest::from_value(&body).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            "mcp-protocol-version",
            HeaderValue::from_static(MODERN_PROTOCOL_VERSION),
        );
        headers.insert("mcp-method", HeaderValue::from_static("tools/call"));
        headers.insert(
            "mcp-name",
            HeaderValue::from_str(&format!("=?base64?{}?=", base64::encode(name.as_bytes())))
                .unwrap(),
        );
        assert!(validate_headers(&headers, &parsed).is_ok(), "{name:?}");
    }
    for invalid in [
        "=?base64?a?=",
        "=?base64?Zh==?=",
        "=?base64?/w==?=",
        " padded ",
    ] {
        assert_eq!(
            decode_name(invalid).unwrap_err().code,
            codes::HEADER_MISMATCH
        );
    }
}

#[tokio::test]
async fn authorization_body_limits_and_scope_refinements_fail_closed() {
    let memory = Arc::new(Memory::default());
    let backend = Backend::new(memory.clone());
    let app = router(config(), backend.clone()).unwrap();
    for (token, status) in [
        ("invalid", StatusCode::UNAUTHORIZED),
        ("forbidden", StatusCode::FORBIDDEN),
        ("unavailable", StatusCode::SERVICE_UNAVAILABLE),
    ] {
        let mut req = request("/mcp", &json!({"jsonrpc":"2.0","id":1,"method":"ping"}));
        req.headers_mut().insert(
            "authorization",
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        assert_eq!(app.clone().oneshot(req).await.unwrap().status(), status);
    }
    let mut req = request("/mcp", &modern("ping"));
    req.headers_mut()
        .append("authorization", HeaderValue::from_static("Bearer valid"));
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    let req = HttpRequest::post("/mcp")
        .header("authorization", "Bearer valid")
        .header("content-type", "application/json")
        .body(Body::from(vec![b' '; MAX_MCP_FRAME_BYTES + 1]))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    for scope in [
        json!({"tenant_id": Uuid::now_v7()}),
        json!({"project":"foreign"}),
        json!({"agent":"foreign"}),
        json!({"privacy_tier":"t3_public"}),
    ] {
        let req = request(
            "/mcp",
            &json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"remember","arguments":{"action":"record","idempotency_key":"fixed","scope":scope}}}),
        );
        assert_eq!(
            app.clone().oneshot(req).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
    }
    assert_eq!(memory.writes.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn grant_routes_dispatch_to_authorization_backend() {
    let backend = Backend::new(Arc::new(Memory::default()));
    let app = router(config(), backend.clone()).unwrap();
    let response = app
        .clone()
        .oneshot(request("/v1/grants", &json!({"kind":"agent"})))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(json_body(response).await["kind"], "agent");
    let req = HttpRequest::delete("/v1/grants/grant-1")
        .header("authorization", "Bearer valid")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::NO_CONTENT
    );
    let response = app
        .clone()
        .oneshot(request("/v1/auth/aws", &json!({"proof":"invalid"})))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = app
        .oneshot(request("/v1/auth/aws", &json!({"proof":"valid"})))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response).await["token"], "identity");
    assert_eq!(backend.issued.load(Ordering::SeqCst), 1);
    assert_eq!(backend.revoked.load(Ordering::SeqCst), 1);
    assert_eq!(backend.exchanges.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn http_response_budget_includes_an_untrusted_request_id() {
    let app = router(config(), Backend::new(Arc::new(Memory::default()))).unwrap();
    let body =
        json!({"jsonrpc":"2.0", "id":"x".repeat(MAX_MCP_FRAME_BYTES - 80), "method":"tools/list"});
    assert!(serde_json::to_vec(&body).unwrap().len() <= MAX_MCP_FRAME_BYTES);
    let response = app.oneshot(request("/mcp", &body)).await.unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = json_body(response).await;
    assert_eq!(body["error"]["code"], codes::INTERNAL_ERROR);
    assert_eq!(body["id"], Value::Null);
}

#[tokio::test]
async fn role_refusals_preserve_rpc_receipt_and_http_forbidden_status() {
    let memory = Arc::new(Memory {
        forbid_writes: true,
        ..Memory::default()
    });
    let app = router(config(), Backend::new(memory)).unwrap();
    let body = json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"remember","arguments":{"action":"record","idempotency_key":"fixed"}}});
    let response = app.oneshot(request("/mcp", &body)).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(
        response.headers()["www-authenticate"]
            .to_str()
            .unwrap()
            .contains("insufficient_scope")
    );
    let body = json_body(response).await;
    assert_eq!(body["id"], 4);
    assert_eq!(body["error"]["data"]["code"], "role_forbids_action");
    assert_eq!(body["error"]["data"]["outcome"], "not_applied");
}

#[tokio::test(start_paused = true)]
async fn deadlines_preserve_unknown_mutation_outcome_and_limit_inflight_work() {
    let memory = Arc::new(Memory {
        writes: AtomicUsize::new(0),
        delay: Duration::from_secs(1),
        forbid_writes: false,
    });
    let backend = Backend::new(memory.clone());
    let mut settings = config();
    settings.max_inflight = 1;
    settings.request_deadline = Duration::from_millis(20);
    let app = router(settings, backend.clone()).unwrap();
    let body = json!({"jsonrpc":"2.0","id":17,"method":"tools/call","params":{"name":"remember","arguments":{"action":"record","idempotency_key":"fixed"}}});
    let first = tokio::spawn(app.clone().oneshot(request("/mcp", &body)));
    while backend.authentications.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
    }
    let overloaded = app.clone().oneshot(request("/mcp", &body)).await.unwrap();
    assert_eq!(overloaded.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(json_body(overloaded).await["error"], "server_busy");
    for (path, status) in [
        ("/healthz", StatusCode::OK),
        ("/readyz", StatusCode::SERVICE_UNAVAILABLE),
    ] {
        let probe = app
            .clone()
            .oneshot(HttpRequest::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(probe.status(), status);
        assert_eq!(probe.headers()["cache-control"], "no-store");
        assert_ne!(json_body(probe).await["error"], "server_busy");
    }
    let response = first.await.unwrap().unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let response = json_body(response).await;
    assert_eq!(response["id"], 17);
    assert_eq!(response["error"]["data"]["outcome"], "unknown");
    assert_eq!(memory.writes.load(Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn readiness_tracks_background_failures_without_affecting_liveness() {
    use std::sync::atomic::AtomicBool;

    let available = Arc::new(AtomicBool::new(true));
    let state = available.clone();
    let (readiness, task) = crate::readiness::Readiness::start(move || {
        let ready = state.load(Ordering::SeqCst);
        async move { ready }
    });
    let mut settings = config();
    settings.readiness = readiness;
    let backend = Backend::new(Arc::new(Memory::default()));
    let app = router(settings, backend.clone()).unwrap();
    let probe = |path| {
        app.clone()
            .oneshot(HttpRequest::get(path).body(Body::empty()).unwrap())
    };
    let initial = probe("/readyz").await.unwrap();
    assert_eq!(initial.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        json_body(initial).await,
        json!({"error":"runtime_not_ready"})
    );
    tokio::task::yield_now().await;
    let ready = probe("/readyz").await.unwrap();
    assert_eq!(ready.status(), StatusCode::OK);
    assert_eq!(json_body(ready).await, json!({"status":"ready"}));
    available.store(false, Ordering::SeqCst);
    tokio::time::advance(Duration::from_secs(5)).await;
    tokio::task::yield_now().await;
    assert_eq!(
        probe("/readyz").await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(probe("/healthz").await.unwrap().status(), StatusCode::OK);
    assert_eq!(backend.authentications.load(Ordering::SeqCst), 0);
    drop(task);
    assert_eq!(
        probe("/readyz").await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[test]
fn invalid_configuration_fails_before_listening() {
    let backend = Backend::new(Arc::new(Memory::default()));
    for resource in [
        "file:///mcp",
        "https://user:pass@recall.example/mcp",
        "https://recall.example/mcp?token=x",
        "https://recall.example/wrong",
    ] {
        let mut settings = config();
        settings.resource_url = resource.into();
        assert!(router(settings, backend.clone()).is_err());
    }
    let mut settings = config();
    settings.allowed_origins.push("*".into());
    assert!(router(settings, backend.clone()).is_err());
    let mut settings = config();
    settings.max_inflight = 0;
    assert!(router(settings, backend).is_err());
}

#[test]
fn invalid_oauth_metadata_fails_before_listening() {
    let backend = Backend::new(Arc::new(Memory::default()));
    for issuer in [
        "file:///issuer",
        "https://user:pass@id.example/",
        "https://id.example/?tenant=x",
        "https://id.example/#fragment",
        " https://id.example/",
        "https://id.example/\n",
        "https://id.example/\0",
    ] {
        let mut settings = config();
        settings.authorization_servers = vec![issuer.into()];
        assert!(router(settings, backend.clone()).is_err(), "{issuer:?}");
    }
    let mut settings = config();
    settings
        .authorization_servers
        .push("https://id.example/".into());
    assert!(router(settings, backend.clone()).is_err());
    for scopes in [
        vec![""],
        vec!["read write"],
        vec!["read\n"],
        vec!["read\\write"],
        vec!["read\"write"],
        vec!["read", "read"],
        vec!["mémoire"],
    ] {
        let mut settings = config();
        settings.scopes_supported = scopes.into_iter().map(str::to_owned).collect();
        assert!(router(settings, backend.clone()).is_err());
    }
    let mut settings = config();
    settings.scopes_supported = [
        "openid",
        "offline_access",
        "fleet-recall",
        "urn:example:scope",
        "!#[]~",
    ]
    .map(str::to_owned)
    .into();
    assert!(router(settings, backend).is_ok());
}
