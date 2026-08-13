//! MCP 2025-06-18 newline-delimited JSON-RPC server.

use std::{fmt::Write as _, sync::Arc};

use serde::Deserialize;
use serde_json::{Map, Value, json};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

use crate::context::RequestedScope;
use crate::service::{
    FleetMemoryService, RecallAction, RecallRequest, RecallResult, RememberAction, RememberRequest,
    RememberResult, ServiceError,
};
use crate::{FleetScope, Result};

use super::protocol::{JsonRpcError, JsonRpcRequest, JsonRpcResponse};
use super::tools::tool_list;

pub const PROTOCOL_VERSION: &str = "2025-06-18";
pub(super) const MAX_MCP_FRAME_BYTES: usize = 1_048_576;
const MAX_MCP_TOOL_RESULT_BYTES: usize = 786_432;
const MAX_MCP_RESPONSE_BYTES: usize = 1_048_576;
const REQUEST_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

/// Transport-only request. The untrusted scope is consumed at the MCP edge and
/// is never embedded in the service request passed to a backend.
#[derive(Debug, Deserialize)]
struct WireRecallRequest {
    action: RecallAction,
    #[serde(default)]
    scope: RequestedScope,
    #[serde(flatten)]
    arguments: Map<String, Value>,
}

/// Transport-only mutation request; see [`WireRecallRequest`].
#[derive(Debug, Deserialize)]
struct WireRememberRequest {
    action: RememberAction,
    #[serde(default)]
    scope: RequestedScope,
    #[serde(default)]
    idempotency_key: Option<String>,
    /// Optional caller assertion only. Stored provenance is derived from the
    /// trusted deployment scope, so this value never reaches a backend.
    #[serde(default)]
    actor: Option<String>,
    #[serde(flatten)]
    arguments: Map<String, Value>,
}

/// Backend-neutral MCP edge for a single trusted tenant/default scope.
pub struct McpServer {
    service: Arc<dyn FleetMemoryService>,
    trusted_scope: FleetScope,
}

impl McpServer {
    /// Construct a protocol server. The trusted scope is validated once here
    /// and every caller refinement is validated again before dispatch.
    pub fn new(service: Arc<dyn FleetMemoryService>, trusted_scope: FleetScope) -> Result<Self> {
        trusted_scope.validate()?;
        Ok(Self {
            service,
            trusted_scope,
        })
    }

    /// Serve newline-delimited MCP over the process stdin/stdout pair.
    pub async fn run_stdio(&self) -> std::io::Result<()> {
        self.serve(tokio::io::stdin(), tokio::io::stdout()).await
    }

    /// Serve one newline-delimited JSON-RPC stream.
    ///
    /// Processing is deliberately sequential. It preserves request ordering
    /// and prevents concurrent `remember` calls on one agent connection from
    /// surprising a client, while the shared service remains free to execute
    /// independent connections concurrently.
    pub async fn serve<R, W>(&self, reader: R, mut writer: W) -> std::io::Result<()>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        self.serve_with_deadline(reader, &mut writer, REQUEST_DEADLINE)
            .await
    }

    pub(super) async fn serve_with_deadline<R, W>(
        &self,
        reader: R,
        mut writer: W,
        deadline: std::time::Duration,
    ) -> std::io::Result<()>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut reader = BufReader::new(reader);
        loop {
            let mut frame = Vec::with_capacity(8_192);
            let mut oversize = false;
            loop {
                let available = reader.fill_buf().await?;
                if available.is_empty() {
                    if frame.is_empty() {
                        return Ok(());
                    }
                    break;
                }
                let newline = available.iter().position(|byte| *byte == b'\n');
                let take = newline.map_or(available.len(), |index| index + 1);
                if !oversize {
                    let remaining = MAX_MCP_FRAME_BYTES
                        .saturating_add(1)
                        .saturating_sub(frame.len());
                    frame.extend_from_slice(&available[..take.min(remaining)]);
                    oversize = frame.len() > MAX_MCP_FRAME_BYTES;
                }
                reader.consume(take);
                if newline.is_some() {
                    break;
                }
            }
            if frame.last() == Some(&b'\n') {
                frame.pop();
                if frame.last() == Some(&b'\r') {
                    frame.pop();
                }
            }
            if frame.iter().all(u8::is_ascii_whitespace) && !oversize {
                continue;
            }
            let response = if oversize {
                Some(JsonRpcResponse::error(
                    Value::Null,
                    JsonRpcError::invalid_request(format!(
                        "MCP frame exceeds {MAX_MCP_FRAME_BYTES} bytes"
                    )),
                ))
            } else {
                match String::from_utf8(frame) {
                    Ok(line) => match parse_request_line(&line) {
                        Ok(request) if request.is_notification() => None,
                        Ok(request) => {
                            let id = request.id.clone().unwrap_or(Value::Null);
                            let remember = is_remember_tool_call(&request);
                            tokio::time::timeout(deadline, self.dispatch_request(request))
                                .await
                                .unwrap_or_else(|_| Some(deadline_response(id, remember)))
                        }
                        Err(response) => Some(*response),
                    },
                    Err(_) => Some(JsonRpcResponse::error(
                        Value::Null,
                        JsonRpcError::parse("parse error: MCP frame is not valid UTF-8"),
                    )),
                }
            };
            if let Some(response) = response {
                let encoded = encode_bounded_response(&response)?;
                writer.write_all(&encoded).await?;
                writer.flush().await?;
            }
        }
    }

    /// Parse and dispatch one wire record.
    pub async fn handle_line(&self, line: &str) -> Option<JsonRpcResponse> {
        match parse_request_line(line) {
            Ok(request) => self.dispatch_request(request).await,
            Err(response) => Some(*response),
        }
    }

    /// Dispatch one decoded JSON-RPC value.
    pub async fn handle_value(&self, value: Value) -> Option<JsonRpcResponse> {
        let request = match JsonRpcRequest::from_value(&value) {
            Ok(request) => request,
            Err(response) => return Some(*response),
        };
        self.dispatch_request(request).await
    }

    async fn dispatch_request(&self, request: JsonRpcRequest) -> Option<JsonRpcResponse> {
        // MCP notifications are one-way. In particular, never execute a
        // notification-shaped tools/call: a hidden `remember` mutation would
        // have no receipt and would violate the deliberate-write boundary.
        if request.is_notification() {
            return None;
        }

        let id = request.id.unwrap_or(Value::Null);
        let result = match request.method.as_str() {
            "initialize" => Ok(initialize_result()),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({ "tools": tool_list() })),
            "tools/call" => self.handle_tools_call(request.params).await,
            method => Err(JsonRpcError::method_not_found(method)),
        };

        Some(match result {
            Ok(result) => JsonRpcResponse::success(id, result),
            Err(error) => JsonRpcResponse::error(id, error),
        })
    }

    async fn handle_tools_call(&self, params: Value) -> std::result::Result<Value, JsonRpcError> {
        let params = params
            .as_object()
            .ok_or_else(|| JsonRpcError::invalid_params("tools/call params must be an object"))?;
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| JsonRpcError::invalid_params("missing or invalid tool name"))?;
        let arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| Value::Object(Map::new()));
        if !arguments.is_object() {
            return Err(JsonRpcError::invalid_params(
                "tool arguments must be an object",
            ));
        }
        reject_reserved_scope_fields(&arguments)?;

        match name {
            "recall" => self.call_recall(arguments).await,
            "remember" => self.call_remember(arguments).await,
            other => Err(JsonRpcError::invalid_params(format!(
                "unknown tool: {}",
                bounded_untrusted_label(other)
            ))),
        }
    }

    async fn call_recall(&self, arguments: Value) -> std::result::Result<Value, JsonRpcError> {
        let wire: WireRecallRequest = serde_json::from_value(arguments).map_err(|error| {
            JsonRpcError::invalid_params(format!("invalid recall request: {error}"))
        })?;
        let scope = self.resolve_scope(&wire.scope)?;
        let action = wire.action.as_str();
        let request = RecallRequest::new(wire.action, wire.arguments);

        match self.service.recall(scope, request).await {
            Ok(result) => {
                let envelope = recall_envelope(action, &result);
                Ok(successful_recall_tool_result(&envelope))
            }
            Err(ServiceError::InvalidRequest(message)) => {
                Err(JsonRpcError::invalid_params(message))
            }
            Err(error) => Ok(failed_tool_result("recall", action, &error)),
        }
    }

    async fn call_remember(&self, arguments: Value) -> std::result::Result<Value, JsonRpcError> {
        let wire: WireRememberRequest = serde_json::from_value(arguments).map_err(|error| {
            JsonRpcError::invalid_params(format!("invalid remember request: {error}"))
        })?;
        validate_idempotency_key(wire.idempotency_key.as_deref())?;
        let scope = self.resolve_scope(&wire.scope)?;
        validate_actor_assertion(wire.actor.as_deref(), &scope.agent)?;
        let action = wire.action.as_str();
        let idempotency_key = wire.idempotency_key.clone();
        let request = RememberRequest::new(wire.action, wire.idempotency_key, wire.arguments);

        match self.service.remember(scope, request).await {
            Ok(result) => {
                let envelope = remember_envelope(action, &result, idempotency_key.as_deref());
                Ok(successful_remember_tool_result(&envelope))
            }
            Err(ServiceError::InvalidRequest(message)) => {
                Err(JsonRpcError::invalid_params(message))
            }
            Err(error) => Ok(failed_remember_tool_result(
                action,
                &error,
                idempotency_key.as_deref(),
            )),
        }
    }

    fn resolve_scope(
        &self,
        requested: &RequestedScope,
    ) -> std::result::Result<FleetScope, JsonRpcError> {
        self.trusted_scope
            .resolve_requested(requested)
            .map_err(|error| JsonRpcError::invalid_params(error.to_string()))
    }
}

fn validate_actor_assertion(
    actor: Option<&str>,
    trusted_agent: &str,
) -> std::result::Result<(), JsonRpcError> {
    if actor.is_some_and(|actor| actor != trusted_agent) {
        return Err(JsonRpcError::invalid_params(
            "actor must exactly match the deployment-bound trusted agent",
        ));
    }
    Ok(())
}

fn initialize_result() -> Value {
    json!({
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {
            "tools": { "listChanged": false }
        },
        "serverInfo": {
            "name": "ostk-fleet-recall",
            "version": env!("CARGO_PKG_VERSION")
        }
    })
}

fn validate_idempotency_key(key: Option<&str>) -> std::result::Result<(), JsonRpcError> {
    let Some(key) = key else { return Ok(()) };
    if key.trim().is_empty() {
        return Err(JsonRpcError::invalid_params(
            "idempotency_key must not be empty",
        ));
    }
    if key.len() > 256 {
        return Err(JsonRpcError::invalid_params(
            "idempotency_key exceeds 256 bytes",
        ));
    }
    if key != key.trim() || key.chars().any(char::is_control) {
        return Err(JsonRpcError::invalid_params(
            "idempotency_key must be trimmed and contain no control characters",
        ));
    }
    Ok(())
}

fn reject_reserved_scope_fields(arguments: &Value) -> std::result::Result<(), JsonRpcError> {
    let object = arguments.as_object().expect("arguments checked by caller");
    for forbidden in ["tenant", "tenant_id", "tenantId"] {
        if object.contains_key(forbidden) {
            return Err(JsonRpcError::invalid_params(format!(
                "`{forbidden}` is deployment-controlled and must not appear in tool arguments"
            )));
        }
    }
    for reserved in ["project", "agent", "session_id", "privacy_tier"] {
        if object.contains_key(reserved) {
            return Err(JsonRpcError::invalid_params(format!(
                "`{reserved}` is a scope field and must appear only under `scope`"
            )));
        }
    }
    if let Some(scope) = object.get("scope").and_then(Value::as_object) {
        for forbidden in ["tenant", "tenant_id", "tenantId"] {
            if scope.contains_key(forbidden) {
                return Err(JsonRpcError::invalid_params(format!(
                    "`scope.{forbidden}` is deployment-controlled and must not appear in tool arguments"
                )));
            }
        }
    }
    Ok(())
}

fn recall_envelope(action: &str, result: &RecallResult) -> Value {
    json!({
        "schema_version": 2,
        "tool": "recall",
        "action": action,
        "data": result.data,
        "conflicts": result.conflicts,
        "conflict_coverage": result.conflict_coverage,
        "warnings": result.warnings,
        "diagnostics": result.diagnostics,
    })
}

fn remember_envelope(
    action: &str,
    result: &RememberResult,
    idempotency_key: Option<&str>,
) -> Value {
    let mut data = result.data.clone();
    if let Some(data) = data.as_object_mut() {
        let idempotent_replay = data
            .get("idempotent_replay")
            .and_then(Value::as_bool)
            .or_else(|| {
                data.get("receipt")
                    .and_then(|receipt| receipt.get("replayed"))
                    .and_then(Value::as_bool)
            })
            .unwrap_or(false);
        data.insert(
            "receipt".into(),
            json!({
                "idempotency_key": idempotency_key,
                "committed": true,
                "idempotent_replay": idempotent_replay,
            }),
        );
    }
    json!({
        "schema_version": 2,
        "tool": "remember",
        "action": action,
        "data": data,
        "conflicts": result.conflicts,
        "conflict_coverage": result.conflict_coverage,
        "warnings": result.warnings,
        "diagnostics": result.diagnostics,
    })
}

fn successful_recall_tool_result(envelope: &Value) -> Value {
    let result = successful_tool_result(envelope);
    if result_within_budget(&result) {
        return result;
    }
    tracing::warn!(
        limit = MAX_MCP_TOOL_RESULT_BYTES,
        "MCP recall result exceeded the bounded response budget"
    );
    json!({
        "content": [{
            "type": "text",
            "text": "memory read produced too much output; narrow the query or lower its limit"
        }],
        "isError": true,
    })
}

fn successful_remember_tool_result(envelope: &Value) -> Value {
    let result = successful_tool_result(envelope);
    if result_within_budget(&result) {
        return result;
    }
    tracing::warn!(
        limit = MAX_MCP_TOOL_RESULT_BYTES,
        "MCP remember result projection exceeded the bounded response budget"
    );
    let compact_envelope = compact_committed_remember_envelope(envelope);
    let compact = successful_tool_result(&compact_envelope);
    debug_assert!(result_within_budget(&compact));
    compact
}

fn successful_tool_result(envelope: &Value) -> Value {
    let text = compact_summary(envelope);
    json!({
        "content": [{ "type": "text", "text": text }],
        "structuredContent": envelope,
        "isError": false,
    })
}

fn result_within_budget(result: &Value) -> bool {
    serde_json::to_vec(result).is_ok_and(|bytes| bytes.len() <= MAX_MCP_TOOL_RESULT_BYTES)
}

fn compact_committed_remember_envelope(envelope: &Value) -> Value {
    let data = &envelope["data"];
    let claim = &data["claim"];
    json!({
        "schema_version": envelope["schema_version"],
        "tool": "remember",
        "action": envelope["action"],
        "data": {
            "operation": data["operation"],
            "claim": {
                "id": claim["id"],
                "state": claim["state"],
                "revision": claim["revision"],
            },
            "idempotent_replay": data["idempotent_replay"],
            "conflicts_opened": data["conflicts_opened"],
            "conflicts_resolved": data["conflicts_resolved"],
            "receipt": data["receipt"],
        },
        "conflicts": [],
        "conflict_coverage": {
            "status": "partial",
            "complete": false,
            "reason": "output_projection_truncated",
        },
        "warnings": [{
            "code": "output_projection_truncated",
            "message": "the mutation committed, but its response projection exceeded the output budget; the durable receipt and mutation coordinates are preserved"
        }],
        "diagnostics": {
            "transaction": envelope.pointer("/diagnostics/transaction"),
            "output_truncated": true,
        },
    })
}

fn parse_request_line(line: &str) -> std::result::Result<JsonRpcRequest, Box<JsonRpcResponse>> {
    let value = serde_json::from_str::<Value>(line).map_err(|error| {
        Box::new(JsonRpcResponse::error(
            Value::Null,
            JsonRpcError::parse(format!("parse error: {error}")),
        ))
    })?;
    JsonRpcRequest::from_value(&value)
}

fn is_remember_tool_call(request: &JsonRpcRequest) -> bool {
    request.method == "tools/call"
        && request.params.get("name").and_then(Value::as_str) == Some("remember")
}

fn deadline_response(id: Value, remember: bool) -> JsonRpcResponse {
    let mut error = JsonRpcError::internal("request deadline exceeded");
    if remember {
        error.data = Some(json!({
            "outcome": "unknown",
            "retry": "retry the same remember request with the same idempotency_key to obtain its durable receipt"
        }));
    }
    JsonRpcResponse::error(id, error)
}

fn bounded_untrusted_label(value: &str) -> String {
    const MAX_CHARS: usize = 128;
    if value.chars().count() <= MAX_CHARS {
        value.to_owned()
    } else {
        format!("{}…", value.chars().take(MAX_CHARS).collect::<String>())
    }
}

fn encode_bounded_response(response: &JsonRpcResponse) -> std::io::Result<Vec<u8>> {
    let id = response.id.clone();
    let mut encoded = serde_json::to_vec(&response).map_err(std::io::Error::other)?;
    if encoded.len() > MAX_MCP_RESPONSE_BYTES {
        tracing::warn!(
            limit = MAX_MCP_RESPONSE_BYTES,
            size = encoded.len(),
            "JSON-RPC response exceeded the transport budget"
        );
        encoded = serde_json::to_vec(&JsonRpcResponse::error(
            id,
            JsonRpcError::internal("response exceeded the transport budget"),
        ))
        .map_err(std::io::Error::other)?;
    }
    encoded.push(b'\n');
    Ok(encoded)
}

fn failed_tool_result(tool: &str, action: &str, error: &ServiceError) -> Value {
    let kind = match error {
        ServiceError::InvalidRequest(_) => "invalid_request",
        ServiceError::Unavailable(_) => "unavailable",
        ServiceError::Internal(_) => "internal",
    };
    let public_message = match error {
        ServiceError::InvalidRequest(message) => message.as_str(),
        ServiceError::Unavailable(_) => "memory service temporarily unavailable",
        ServiceError::Internal(_) => "memory operation failed",
    };
    json!({
        "content": [{
            "type": "text",
            "text": format!("{tool}.{action}: failed ({kind}): {public_message}")
        }],
        "isError": true,
    })
}

/// A backend failure can race with transaction commit or loss of the commit
/// acknowledgement. Conservatively report an unknown mutation outcome and
/// direct the caller to replay the exact request/key, which is safe under the
/// ledger's durable idempotency contract.
fn failed_remember_tool_result(
    action: &str,
    error: &ServiceError,
    idempotency_key: Option<&str>,
) -> Value {
    let kind = match error {
        ServiceError::InvalidRequest(_) => "invalid_request",
        ServiceError::Unavailable(_) => "unavailable",
        ServiceError::Internal(_) => "internal",
    };
    let public_message = match error {
        ServiceError::InvalidRequest(message) => message.as_str(),
        ServiceError::Unavailable(_) => "memory service temporarily unavailable",
        ServiceError::Internal(_) => "memory operation failed",
    };
    let retry = "retry the identical full remember request with the same idempotency_key to obtain its durable receipt";
    let envelope = json!({
        "schema_version": 2,
        "tool": "remember",
        "action": action,
        "data": {
            "outcome": "unknown",
            "receipt": {
                "idempotency_key": idempotency_key,
                "committed": null,
                "idempotent_replay": null,
            },
            "retry": {
                "instruction": retry,
                "idempotency_key": idempotency_key,
            },
        },
        "conflicts": [],
        "conflict_coverage": { "status": "not_evaluated" },
        "warnings": [{
            "code": "mutation_outcome_unknown",
            "message": "the service could not determine whether the mutation committed; retry only the identical full request with the same idempotency_key"
        }],
        "diagnostics": { "failure_kind": kind },
    });
    let result = json!({
        "content": [{
            "type": "text",
            "text": format!(
                "remember.{action}: failed ({kind}): {public_message}; outcome unknown; {retry}"
            )
        }],
        "structuredContent": envelope,
        "isError": true,
    });
    debug_assert!(result_within_budget(&result));
    result
}

fn compact_summary(envelope: &Value) -> String {
    let tool = envelope["tool"].as_str().unwrap_or("tool");
    let action = envelope["action"].as_str().unwrap_or("action");
    let data = &envelope["data"];
    let outcome = match (
        data.get("applied").and_then(Value::as_bool),
        data.get("status").and_then(Value::as_str),
    ) {
        (Some(true), _) => "applied".to_owned(),
        (Some(false), Some(status)) => format!("not applied ({status})"),
        (Some(false), None) => "not applied".to_owned(),
        (None, Some(status)) => status.to_owned(),
        (None, None) => "completed".to_owned(),
    };

    let mut counts = Vec::new();
    for (key, label) in [
        ("hits", "hits"),
        ("claims", "claims"),
        ("active_claims", "active claims"),
        ("records", "records"),
    ] {
        if let Some(count) = data.get(key).and_then(Value::as_array).map(Vec::len) {
            counts.push(format!("{count} {label}"));
        }
    }
    if let Some(count) = envelope["conflicts"].as_array().map(Vec::len)
        && count > 0
    {
        counts.push(format!("{count} conflicts"));
    }

    let mut summary = format!("{tool}.{action}: {outcome}");
    if !counts.is_empty() {
        summary.push_str("; ");
        summary.push_str(&counts.join(", "));
    }
    if let Some(status @ ("unavailable" | "not_evaluated")) = envelope
        .pointer("/conflict_coverage/status")
        .and_then(Value::as_str)
    {
        let _ = write!(summary, "; conflict coverage {status}");
    }
    summary.push_str(". Full result is in structuredContent.");
    summary
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_is_compact_not_a_json_mirror() {
        let envelope = json!({
            "tool": "recall",
            "action": "search",
            "data": { "hits": [{"large": "payload"}] },
            "conflicts": [],
            "conflict_coverage": {"status": "complete"}
        });
        let summary = compact_summary(&envelope);
        assert_eq!(
            summary,
            "recall.search: completed; 1 hits. Full result is in structuredContent."
        );
        assert!(!summary.contains("large"));
    }

    #[test]
    fn oversized_tool_result_is_replaced_with_a_bounded_error() {
        let envelope = json!({
            "tool": "recall",
            "action": "search",
            "data": { "hits": [{ "text": "x".repeat(MAX_MCP_TOOL_RESULT_BYTES) }] },
            "conflicts": [],
            "conflict_coverage": {"status": "not_evaluated"}
        });
        let result = successful_recall_tool_result(&envelope);
        assert_eq!(result["isError"], true);
        assert!(result.get("structuredContent").is_none());
        assert!(serde_json::to_vec(&result).unwrap().len() < 1_024);
    }

    #[test]
    fn oversized_remember_preserves_a_successful_durable_receipt() {
        let result = RememberResult::new(json!({
            "operation": "record",
            "claim": {
                "id": 42,
                "state": "active",
                "revision": 1,
                "text": "x".repeat(MAX_MCP_TOOL_RESULT_BYTES),
            },
            "idempotent_replay": false,
            "conflicts_opened": [],
            "conflicts_resolved": [],
        }));
        let envelope = remember_envelope("record", &result, Some("turn-7/decision-42"));
        let response = successful_remember_tool_result(&envelope);

        assert_eq!(response["isError"], false);
        assert_eq!(response["structuredContent"]["data"]["claim"]["id"], 42);
        assert_eq!(
            response["structuredContent"]["data"]["receipt"]["idempotency_key"],
            "turn-7/decision-42"
        );
        assert_eq!(
            response["structuredContent"]["diagnostics"]["output_truncated"],
            true
        );
        assert!(serde_json::to_vec(&response).unwrap().len() < 4_096);
    }

    #[test]
    fn every_json_rpc_response_has_a_final_transport_bound() {
        let response = JsonRpcResponse::error(
            json!(91),
            JsonRpcError::invalid_params("x".repeat(MAX_MCP_RESPONSE_BYTES)),
        );
        let encoded = encode_bounded_response(&response).unwrap();
        assert!(encoded.len() < 1_024);
        let value: Value = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(value["id"], 91);
        assert_eq!(
            value["error"]["message"],
            "response exceeded the transport budget"
        );
    }
}
