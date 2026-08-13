use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use ostk_recall_core::PrivacyTier;
use serde_json::{Map, Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use uuid::Uuid;

use crate::FleetScope;
use crate::service::{
    ConflictCoverage, FleetMemoryService, RecallRequest, RecallResult, RememberRequest,
    RememberResult, ServiceResult,
};

use super::protocol::codes;
use super::{McpServer, PROTOCOL_VERSION};

#[derive(Debug, Clone)]
enum ObservedCall {
    Recall {
        scope: FleetScope,
        action: String,
        arguments: Map<String, Value>,
    },
    Remember {
        scope: FleetScope,
        action: String,
        idempotency_key: Option<String>,
        arguments: Map<String, Value>,
    },
}

#[derive(Default)]
struct FakeService {
    calls: Mutex<Vec<ObservedCall>>,
    delay: Duration,
    remember_failure: Option<RememberFailure>,
}

#[derive(Debug, Clone, Copy)]
enum RememberFailure {
    Unavailable,
    Internal,
}

impl FakeService {
    fn calls(&self) -> Vec<ObservedCall> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl FleetMemoryService for FakeService {
    async fn recall(
        &self,
        scope: FleetScope,
        request: RecallRequest,
    ) -> ServiceResult<RecallResult> {
        if !self.delay.is_zero() {
            tokio::time::sleep(self.delay).await;
        }
        let action = request.action.as_str().to_owned();
        self.calls.lock().unwrap().push(ObservedCall::Recall {
            scope,
            action,
            arguments: request.arguments,
        });
        let mut result = RecallResult::new(json!({
            "hits": [{
                "chunk_id": "chunk-7",
                "text": "fleet memory",
                "score": 0.91
            }]
        }));
        result.conflict_coverage = ConflictCoverage::new("complete");
        Ok(result)
    }

    async fn remember(
        &self,
        scope: FleetScope,
        request: RememberRequest,
    ) -> ServiceResult<RememberResult> {
        if !self.delay.is_zero() {
            tokio::time::sleep(self.delay).await;
        }
        let idempotency_key = request.idempotency_key.clone();
        let action = request.action.as_str().to_owned();
        self.calls.lock().unwrap().push(ObservedCall::Remember {
            scope,
            action,
            idempotency_key: idempotency_key.clone(),
            arguments: request.arguments,
        });
        if let Some(failure) = self.remember_failure {
            return Err(match failure {
                RememberFailure::Unavailable => {
                    crate::service::ServiceError::Unavailable("sensitive database detail".into())
                }
                RememberFailure::Internal => {
                    crate::service::ServiceError::Internal("sensitive internal detail".into())
                }
            });
        }
        let mut result = RememberResult::new(json!({
            "applied": true,
            "receipt": {
                "idempotency_key": idempotency_key,
                "replayed": false
            }
        }));
        result.conflict_coverage = ConflictCoverage::new("complete");
        Ok(result)
    }
}

fn tenant_id() -> Uuid {
    Uuid::parse_str("0198a849-f6ae-7d61-9800-000000000001").unwrap()
}

fn server(fake: &Arc<FakeService>) -> Arc<McpServer> {
    let scope = FleetScope::new(
        tenant_id(),
        "default-project",
        "default-agent",
        Some("default-session".into()),
        PrivacyTier::T1Project,
    )
    .unwrap();
    let service: Arc<dyn FleetMemoryService> = fake.clone();
    Arc::new(McpServer::new(service, scope).unwrap())
}

/// Exercise the real newline framing against in-memory duplex streams.
async fn duplex_exchange(server: Arc<McpServer>, input: &str) -> Vec<Value> {
    duplex_exchange_with_deadline(server, input, Duration::from_secs(30)).await
}

async fn duplex_exchange_with_deadline(
    server: Arc<McpServer>,
    input: &str,
    deadline: Duration,
) -> Vec<Value> {
    duplex_exchange_bytes_with_deadline(server, input.as_bytes(), deadline).await
}

async fn duplex_exchange_bytes_with_deadline(
    server: Arc<McpServer>,
    input: &[u8],
    deadline: Duration,
) -> Vec<Value> {
    let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
    let (server_reader, server_writer) = tokio::io::split(server_stream);
    let serve_task = tokio::spawn(async move {
        server
            .serve_with_deadline(server_reader, server_writer, deadline)
            .await
    });

    let (client_reader, mut client_writer) = tokio::io::split(client_stream);
    client_writer.write_all(input).await.unwrap();
    client_writer.shutdown().await.unwrap();

    let mut responses = Vec::new();
    let mut lines = BufReader::new(client_reader).lines();
    while let Some(line) = lines.next_line().await.unwrap() {
        responses.push(serde_json::from_str(&line).unwrap());
    }
    serve_task.await.unwrap().unwrap();
    responses
}

#[tokio::test]
async fn malformed_utf8_returns_parse_error_and_keeps_session_open() {
    let fake = Arc::new(FakeService::default());
    let mut input = vec![0xff, b'\n'];
    input.extend_from_slice(br#"{"jsonrpc":"2.0","id":92,"method":"ping"}"#);
    input.push(b'\n');

    let responses =
        duplex_exchange_bytes_with_deadline(server(&fake), &input, Duration::from_secs(30)).await;
    assert_eq!(responses.len(), 2);
    assert_eq!(responses[0]["error"]["code"], codes::PARSE_ERROR);
    assert_eq!(responses[1]["id"], 92);
    assert_eq!(responses[1]["result"], json!({}));
}

#[tokio::test]
async fn huge_unknown_method_returns_a_small_bounded_error() {
    let fake = Arc::new(FakeService::default());
    let request = json!({
        "jsonrpc": "2.0",
        "id": 93,
        "method": "x".repeat(900_000),
    });
    let input = format!("{request}\n");
    let responses = duplex_exchange(server(&fake), &input).await;
    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0]["id"], 93);
    assert_eq!(responses[0]["error"]["code"], codes::METHOD_NOT_FOUND);
    assert!(serde_json::to_vec(&responses[0]).unwrap().len() < 1_024);
}

#[tokio::test]
async fn deadline_keeps_request_id_and_marks_remember_outcome_unknown() {
    let fake = Arc::new(FakeService {
        delay: Duration::from_millis(100),
        ..FakeService::default()
    });
    let input = concat!(
        r#"{"jsonrpc":"2.0","id":77,"method":"tools/call","params":{"name":"remember","arguments":{"action":"record","idempotency_key":"deadline/77","kind":"fact","text":"durable"}}}"#,
        "\n"
    );
    let responses =
        duplex_exchange_with_deadline(server(&fake), input, Duration::from_millis(5)).await;

    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0]["id"], 77);
    assert_eq!(responses[0]["error"]["code"], codes::INTERNAL_ERROR);
    assert_eq!(responses[0]["error"]["data"]["outcome"], "unknown");
    assert!(
        responses[0]["error"]["data"]["retry"]
            .as_str()
            .unwrap()
            .contains("same idempotency_key")
    );
}

#[tokio::test]
async fn backend_remember_failures_report_bounded_unknown_outcome_and_safe_retry() {
    for (id, failure, expected_kind) in [
        (78, RememberFailure::Unavailable, "unavailable"),
        (79, RememberFailure::Internal, "internal"),
    ] {
        let fake = Arc::new(FakeService {
            remember_failure: Some(failure),
            ..FakeService::default()
        });
        let key = format!("backend-failure/{id}");
        let input = format!(
            "{}\n",
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "tools/call",
                "params": {
                    "name": "remember",
                    "arguments": {
                        "action": "record",
                        "idempotency_key": key,
                        "kind": "fact",
                        "text": "durable",
                    }
                }
            })
        );
        let responses = duplex_exchange(server(&fake), &input).await;
        let result = &responses[0]["result"];

        assert_eq!(result["isError"], true);
        assert_eq!(result["structuredContent"]["data"]["outcome"], "unknown");
        assert_eq!(
            result["structuredContent"]["data"]["receipt"]["idempotency_key"],
            key
        );
        assert!(result["structuredContent"]["data"]["receipt"]["committed"].is_null());
        assert_eq!(
            result["structuredContent"]["diagnostics"]["failure_kind"],
            expected_kind
        );
        let retry = result["structuredContent"]["data"]["retry"]["instruction"]
            .as_str()
            .unwrap();
        assert!(retry.contains("identical full remember request"));
        assert!(retry.contains("same idempotency_key"));
        let encoded = serde_json::to_vec(result).unwrap();
        assert!(encoded.len() < 4_096);
        assert!(!String::from_utf8(encoded).unwrap().contains("sensitive"));
    }
}

#[tokio::test]
async fn duplex_handshake_lists_exactly_two_tools_and_pings() {
    let fake = Arc::new(FakeService::default());
    let input = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":"tools","method":"tools/list"}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":3,"method":"ping"}"#,
        "\n"
    );
    let responses = duplex_exchange(server(&fake), input).await;

    assert_eq!(responses.len(), 3, "notification must not produce a frame");
    assert_eq!(responses[0]["result"]["protocolVersion"], PROTOCOL_VERSION);
    assert_eq!(
        responses[0]["result"]["serverInfo"]["name"],
        "ostk-fleet-recall"
    );
    let tools = responses[1]["result"]["tools"].as_array().unwrap();
    let names: Vec<_> = tools
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["recall", "remember"]);
    assert_eq!(responses[2]["result"], json!({}));
}

#[tokio::test]
async fn duplex_calls_keep_read_and_write_paths_separate() {
    let fake = Arc::new(FakeService::default());
    let input = concat!(
        r#"{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"recall","arguments":{"action":"search","scope":{"project":"default-project","agent":"default-agent","session_id":"turn-a"},"query":"fleet memory"}}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"remember","arguments":{"action":"record","idempotency_key":"turn-11/fact-1","kind":"fact","text":"durable"}}}"#,
        "\n"
    );
    let responses = duplex_exchange(server(&fake), input).await;

    assert_eq!(responses.len(), 2);
    let recall = &responses[0]["result"];
    assert_eq!(recall["isError"], false);
    assert_eq!(recall["structuredContent"]["schema_version"], 2);
    assert_eq!(recall["structuredContent"]["tool"], "recall");
    assert_eq!(recall["structuredContent"]["action"], "search");
    assert_eq!(
        recall["structuredContent"]["data"]["hits"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let fallback = recall["content"][0]["text"].as_str().unwrap();
    assert!(fallback.starts_with("recall.search: completed; 1 hits"));
    assert!(fallback.contains("Full result is in structuredContent"));
    assert!(!fallback.contains("chunk-7"), "fallback duplicated payload");

    let remember = &responses[1]["result"];
    assert_eq!(remember["structuredContent"]["tool"], "remember");
    assert_eq!(
        remember["structuredContent"]["data"]["receipt"]["idempotency_key"],
        "turn-11/fact-1"
    );

    let calls = fake.calls();
    assert_eq!(calls.len(), 2);
    match &calls[0] {
        ObservedCall::Recall {
            scope,
            action,
            arguments,
        } => {
            assert_eq!(action, "search");
            assert_eq!(scope.tenant_id, tenant_id());
            assert_eq!(scope.project, "default-project");
            assert_eq!(scope.agent, "default-agent");
            assert_eq!(scope.session_id.as_deref(), Some("turn-a"));
            assert!(
                !arguments.contains_key("scope"),
                "untrusted wire scope reached the service request"
            );
        }
        ObservedCall::Remember { .. } => panic!("recall reached write path"),
    }
    match &calls[1] {
        ObservedCall::Remember {
            scope,
            action,
            idempotency_key,
            arguments,
        } => {
            assert_eq!(action, "record");
            assert_eq!(scope.tenant_id, tenant_id());
            assert_eq!(scope.project, "default-project");
            assert_eq!(scope.agent, "default-agent");
            assert_eq!(
                scope.session_id.as_deref(),
                Some("default-session"),
                "unspecified session inherits trusted default"
            );
            assert_eq!(idempotency_key.as_deref(), Some("turn-11/fact-1"));
            assert!(
                !arguments.contains_key("scope"),
                "untrusted wire scope reached the service request"
            );
        }
        ObservedCall::Recall { .. } => panic!("remember reached read path"),
    }
}

#[tokio::test]
async fn scope_inherits_identity_and_selects_session() {
    let fake = Arc::new(FakeService::default());
    let requests = [
        json!({
            "jsonrpc": "2.0", "id": 40, "method": "tools/call",
            "params": {"name": "recall", "arguments": {
                "action": "search", "query": "inherited"
            }}
        }),
        json!({
            "jsonrpc": "2.0", "id": 41, "method": "tools/call",
            "params": {"name": "recall", "arguments": {
                "action": "search",
                "scope": {"project": "default-project", "agent": "default-agent"},
                "query": "matching identity"
            }}
        }),
        json!({
            "jsonrpc": "2.0", "id": 42, "method": "tools/call",
            "params": {"name": "recall", "arguments": {
                "action": "search",
                "scope": {"session_id": "turn-session"},
                "query": "session selected"
            }}
        }),
        json!({
            "jsonrpc": "2.0", "id": 43, "method": "tools/call",
            "params": {"name": "recall", "arguments": {
                "action": "search",
                "scope": {"privacy_tier": "t1_project"},
                "query": "matching privacy assertion"
            }}
        }),
    ];

    for request in requests {
        let response = server(&fake).handle_value(request).await.unwrap();
        assert!(response.error.is_none());
    }

    let calls = fake.calls();
    assert_eq!(calls.len(), 4);
    let expected = [
        (Some("default-session"), PrivacyTier::T1Project),
        (Some("default-session"), PrivacyTier::T1Project),
        (Some("turn-session"), PrivacyTier::T1Project),
        (Some("default-session"), PrivacyTier::T1Project),
    ];
    for (call, (session, privacy_tier)) in calls.iter().zip(expected) {
        let ObservedCall::Recall {
            scope, arguments, ..
        } = call
        else {
            panic!("recall request reached write path")
        };
        assert_eq!(scope.tenant_id, tenant_id());
        assert_eq!(scope.project, "default-project");
        assert_eq!(scope.agent, "default-agent");
        assert_eq!(scope.session_id.as_deref(), session);
        assert_eq!(scope.privacy_tier, privacy_tier);
        assert!(!arguments.contains_key("scope"));
    }
}

#[tokio::test]
async fn matching_actor_is_a_transport_assertion_not_backend_authority() {
    let fake = Arc::new(FakeService::default());
    let response = server(&fake)
        .handle_value(json!({
            "jsonrpc": "2.0", "id": 44, "method": "tools/call",
            "params": {"name": "remember", "arguments": {
                "action": "record",
                "idempotency_key": "actor-assertion/44",
                "kind": "fact",
                "text": "trusted provenance",
                "actor": "default-agent"
            }}
        }))
        .await
        .expect("request has an id");

    assert!(response.error.is_none());
    let calls = fake.calls();
    assert_eq!(calls.len(), 1);
    let ObservedCall::Remember {
        scope, arguments, ..
    } = &calls[0]
    else {
        panic!("remember request reached read path")
    };
    assert_eq!(scope.agent, "default-agent");
    assert!(
        !arguments.contains_key("actor"),
        "untrusted actor assertion reached the service request"
    );

    let rejected = server(&fake)
        .handle_value(json!({
            "jsonrpc": "2.0", "id": 45, "method": "tools/call",
            "params": {"name": "remember", "arguments": {
                "action": "record",
                "idempotency_key": "actor-mismatch/45",
                "kind": "fact",
                "text": "must not run",
                "actor": "impersonated-agent"
            }}
        }))
        .await
        .expect("request has an id");
    assert_eq!(
        rejected.error.expect("mismatch must fail").code,
        codes::INVALID_PARAMS
    );
    assert_eq!(fake.calls().len(), 1, "mismatched actor reached service");
}

#[tokio::test]
async fn privacy_assertion_must_exactly_match_deployment_tier() {
    let fake = Arc::new(FakeService::default());
    for (id, privacy_tier) in [(46, "t0_private"), (47, "t2_trusted"), (48, "t3_public")] {
        let response = server(&fake)
            .handle_value(json!({
                "jsonrpc": "2.0", "id": id, "method": "tools/call",
                "params": {"name": "recall", "arguments": {
                    "action": "search", "query": "must not run",
                    "scope": {"privacy_tier": privacy_tier}
                }}
            }))
            .await
            .expect("request has an id");
        assert_eq!(
            response.error.expect("mismatch must fail").code,
            codes::INVALID_PARAMS
        );
    }
    assert!(fake.calls().is_empty());
}

#[tokio::test]
async fn notification_shaped_tool_call_never_executes_a_hidden_mutation() {
    let fake = Arc::new(FakeService::default());
    let input = concat!(
        r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"remember","arguments":{"action":"record","idempotency_key":"invisible","text":"must not run"}}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":12,"method":"ping"}"#,
        "\n"
    );
    let responses = duplex_exchange(server(&fake), input).await;

    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0]["id"], 12);
    assert!(fake.calls().is_empty());
}

#[tokio::test]
async fn oversized_frame_without_newline_is_bounded_and_rejected() {
    let fake = Arc::new(FakeService::default());
    let input = "x".repeat(super::server::MAX_MCP_FRAME_BYTES + 128);
    let responses = duplex_exchange(server(&fake), &input).await;
    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0]["error"]["code"], codes::INVALID_REQUEST);
    assert!(fake.calls().is_empty());
}

#[tokio::test]
async fn tenant_injection_and_invalid_scope_are_rejected_before_service() {
    let fake = Arc::new(FakeService::default());
    let overlong = "x".repeat(257);
    let requests = [
        json!({
            "jsonrpc": "2.0", "id": 20, "method": "tools/call",
            "params": {"name": "recall", "arguments": {
                "action": "search", "tenant_id": Uuid::now_v7(), "query": "x"
            }}
        }),
        json!({
            "jsonrpc": "2.0", "id": 21, "method": "tools/call",
            "params": {"name": "recall", "arguments": {
                "action": "search", "scope": {"tenant": "other", "project": "x"}
            }}
        }),
        json!({
            "jsonrpc": "2.0", "id": 22, "method": "tools/call",
            "params": {"name": "remember", "arguments": {
                "action": "record", "scope": {"project": "   "}, "text": "x"
            }}
        }),
        json!({
            "jsonrpc": "2.0", "id": 23, "method": "tools/call",
            "params": {"name": "recall", "arguments": {
                "action": "search", "scope": {"agent": overlong}
            }}
        }),
        json!({
            "jsonrpc": "2.0", "id": 24, "method": "tools/call",
            "params": {"name": "remember", "arguments": {
                "action": "record", "idempotency_key": " ", "text": "x"
            }}
        }),
        json!({
            "jsonrpc": "2.0", "id": 241, "method": "tools/call",
            "params": {"name": "remember", "arguments": {
                "action": "record", "idempotency_key": " padded ", "kind": "fact", "text": "x"
            }}
        }),
        json!({
            "jsonrpc": "2.0", "id": 25, "method": "tools/call",
            "params": {"name": "recall", "arguments": {
                "action": "search", "scope": {"project": "other-project"}
            }}
        }),
        json!({
            "jsonrpc": "2.0", "id": 26, "method": "tools/call",
            "params": {"name": "remember", "arguments": {
                "action": "record", "scope": {"agent": "impersonated-agent"}, "text": "x"
            }}
        }),
        json!({
            "jsonrpc": "2.0", "id": 29, "method": "tools/call",
            "params": {"name": "recall", "arguments": {
                "action": "search", "project": "other-project"
            }}
        }),
        json!({
            "jsonrpc": "2.0", "id": 30, "method": "tools/call",
            "params": {"name": "remember", "arguments": {
                "action": "record", "agent": "impersonated-agent", "text": "x"
            }}
        }),
        json!({
            "jsonrpc": "2.0", "id": 31, "method": "tools/call",
            "params": {"name": "recall", "arguments": {
                "action": "search", "scope": {"session_id": " padded-session "}
            }}
        }),
        json!({
            "jsonrpc": "2.0", "id": 32, "method": "tools/call",
            "params": {"name": "remember", "arguments": {
                "action": "record", "scope": {"tenant_id": Uuid::now_v7()}, "text": "x"
            }}
        }),
        json!({
            "jsonrpc": "2.0", "id": 33, "method": "tools/call",
            "params": {"name": "recall", "arguments": {
                "action": "search", "tenantId": Uuid::now_v7()
            }}
        }),
    ];

    for request in requests {
        let response = server(&fake).handle_value(request).await.unwrap();
        assert_eq!(response.error.unwrap().code, codes::INVALID_PARAMS);
    }
    assert!(fake.calls().is_empty());
}

#[tokio::test]
async fn duplex_returns_parse_request_method_and_param_errors() {
    let fake = Arc::new(FakeService::default());
    let input = concat!(
        "{not-json\n",
        "[]\n",
        r#"{"jsonrpc":"1.0","id":31,"method":"ping"}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":32,"method":"fleet/unknown"}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":33,"method":"tools/call","params":{}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":34,"method":"tools/call","params":{"name":"legacy_recall","arguments":{}}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":35,"method":"tools/call","params":{"name":"recall","arguments":{"action":"write"}}}"#,
        "\n"
    );
    let responses = duplex_exchange(server(&fake), input).await;
    let codes_seen: Vec<_> = responses
        .iter()
        .map(|response| response["error"]["code"].as_i64().unwrap())
        .collect();

    assert_eq!(
        codes_seen,
        [
            codes::PARSE_ERROR,
            codes::INVALID_REQUEST,
            codes::INVALID_REQUEST,
            codes::METHOD_NOT_FOUND,
            codes::INVALID_PARAMS,
            codes::INVALID_PARAMS,
            codes::INVALID_PARAMS,
        ]
    );
    assert_eq!(responses[0]["id"], Value::Null);
    assert_eq!(responses[2]["id"], 31);
    assert!(fake.calls().is_empty());
}

#[tokio::test]
async fn explicit_null_id_is_answered_while_absent_id_is_not() {
    let fake = Arc::new(FakeService::default());
    let input = concat!(
        r#"{"jsonrpc":"2.0","id":null,"method":"ping"}"#,
        "\n",
        r#"{"jsonrpc":"2.0","method":"ping"}"#,
        "\n"
    );
    let responses = duplex_exchange(server(&fake), input).await;

    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0]["id"], Value::Null);
    assert_eq!(responses[0]["result"], json!({}));
}
