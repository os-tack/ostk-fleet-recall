//! Fixed, payload-free labels at the MCP boundary.

use serde_json::Value;

use crate::service::{RecallAction, RememberAction};
use crate::telemetry::{self, Outcome};

use super::protocol::{JsonRpcRequest, JsonRpcResponse, codes};

/// Untrusted protocol names are never copied into telemetry. Deserializing the
/// action alone also keeps the label vocabulary tied to the service contract.
pub(super) fn operation(request: &JsonRpcRequest) -> &'static str {
    if request.is_notification() {
        return "notification";
    }
    match request.method.as_str() {
        "initialize" => "initialize",
        "server/discover" => "server.discover",
        "ping" => "ping",
        "tools/list" => "tools.list",
        "tools/call" => {
            let action = request.params.pointer("/arguments/action");
            match request.params.get("name").and_then(Value::as_str) {
                Some("recall") => action
                    .and_then(|action| serde_json::from_value(action.clone()).ok())
                    .map_or("recall.unknown", recall_operation),
                Some("remember") => action
                    .and_then(|action| serde_json::from_value(action.clone()).ok())
                    .map_or("remember.unknown", remember_operation),
                _ => "tools.call.unknown",
            }
        }
        _ => "protocol.unknown",
    }
}

const fn recall_operation(action: RecallAction) -> &'static str {
    match action {
        RecallAction::Search => "recall.search",
        RecallAction::Get => "recall.get",
        RecallAction::Surface => "recall.surface",
        RecallAction::Discover => "recall.discover",
        RecallAction::Conflicts => "recall.conflicts",
        RecallAction::Synthesize => "recall.synthesize",
        RecallAction::Status => "recall.status",
        RecallAction::Audit => "recall.audit",
        RecallAction::Discrepancies => "recall.discrepancies",
        RecallAction::Brief => "recall.brief",
    }
}

const fn remember_operation(action: RememberAction) -> &'static str {
    match action {
        RememberAction::Record => "remember.record",
        RememberAction::Assert => "remember.assert",
        RememberAction::Supersede => "remember.supersede",
        RememberAction::Retract => "remember.retract",
        RememberAction::Forget => "remember.forget",
        RememberAction::Restore => "remember.restore",
        RememberAction::Resolve => "remember.resolve",
        RememberAction::Relate => "remember.relate",
        RememberAction::Split => "remember.split",
        RememberAction::Focus => "remember.focus",
        RememberAction::Track => "remember.track",
        RememberAction::Consolidate => "remember.consolidate",
        RememberAction::Acknowledge => "remember.acknowledge",
        RememberAction::Dismiss => "remember.dismiss",
        RememberAction::Waive => "remember.waive",
        RememberAction::Capture => "remember.capture",
    }
}

pub(super) fn outcome(response: Option<&JsonRpcResponse>) -> Outcome {
    let Some(response) = response else {
        // Notifications are intentionally ignored, including tool-shaped
        // notifications, so they must not claim a successful mutation.
        return Outcome::Skipped;
    };
    if let Some(error) = &response.error {
        if error.code == codes::INVALID_PARAMS
            && error
                .data
                .as_ref()
                .and_then(|data| data.get("outcome"))
                .and_then(Value::as_str)
                == Some("not_applied")
        {
            return Outcome::Refused;
        }
        return match error.code {
            codes::PARSE_ERROR
            | codes::INVALID_REQUEST
            | codes::METHOD_NOT_FOUND
            | codes::INVALID_PARAMS
            | codes::HEADER_MISMATCH
            | codes::UNSUPPORTED_PROTOCOL_VERSION => Outcome::Invalid,
            _ => Outcome::Error,
        };
    }
    if response
        .result
        .as_ref()
        .and_then(|result| result.get("isError"))
        .and_then(Value::as_bool)
        == Some(true)
    {
        return Outcome::Error;
    }
    Outcome::Success
}

pub(super) fn record_invalid(response: &JsonRpcResponse) {
    let operation = if response.error.as_ref().map(|error| error.code) == Some(codes::PARSE_ERROR) {
        "protocol.parse"
    } else {
        "protocol.invalid"
    };
    telemetry::start("mcp", operation).finish(Outcome::Invalid);
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::mcp::JsonRpcError;

    fn request(method: &str, params: Value) -> JsonRpcRequest {
        JsonRpcRequest {
            id: Some(json!("private-request-id")),
            method: method.into(),
            params,
        }
    }

    #[test]
    fn protocol_and_tool_labels_never_include_arbitrary_input() {
        for private in ["secret-query", "tenant/private", &"x".repeat(10_000)] {
            assert_eq!(operation(&request(private, json!({}))), "protocol.unknown");
            assert_eq!(
                operation(&request("tools/call", json!({"name": private}))),
                "tools.call.unknown"
            );
            for (tool, expected) in [
                ("recall", "recall.unknown"),
                ("remember", "remember.unknown"),
            ] {
                assert_eq!(
                    operation(&request(
                        "tools/call",
                        json!({
                            "name": tool, "arguments": {"action": private, "query": private}
                        })
                    )),
                    expected
                );
            }
        }
        assert_eq!(
            operation(&request(
                "tools/call",
                json!({
                    "name": "recall", "arguments": {"action": "search", "query": "private"}
                })
            )),
            "recall.search"
        );
        assert_eq!(
            operation(&request(
                "tools/call",
                json!({
                    "name": "remember", "arguments": {"action": "capture", "text": "private"}
                })
            )),
            "remember.capture"
        );
        assert_eq!(
            operation(&request(
                "tools/call",
                json!({
                    "name": "recall", "arguments": {"action": {"private": "data"}}
                })
            )),
            "recall.unknown"
        );
    }

    #[test]
    fn notifications_and_failures_have_honest_outcomes() {
        let mut notification = request(
            "tools/call",
            json!({
                "name": "remember", "arguments": {"action": "record"}
            }),
        );
        notification.id = None;
        assert_eq!(operation(&notification), "notification");
        assert_eq!(outcome(None), Outcome::Skipped);
        for code in [
            codes::PARSE_ERROR,
            codes::INVALID_REQUEST,
            codes::METHOD_NOT_FOUND,
            codes::INVALID_PARAMS,
            codes::HEADER_MISMATCH,
            codes::UNSUPPORTED_PROTOCOL_VERSION,
        ] {
            assert_eq!(
                outcome(Some(&JsonRpcResponse::error(
                    Value::Null,
                    JsonRpcError::new(code, "private")
                ))),
                Outcome::Invalid
            );
        }
        let mut refusal = JsonRpcError::invalid_params("private refusal");
        refusal.data = Some(json!({"outcome": "not_applied", "code": "private"}));
        assert_eq!(
            outcome(Some(&JsonRpcResponse::error(Value::Null, refusal))),
            Outcome::Refused
        );
        assert_eq!(
            outcome(Some(&JsonRpcResponse::error(
                Value::Null,
                JsonRpcError::internal("private")
            ))),
            Outcome::Error
        );
        for (result, expected) in [
            (
                json!({"isError": true, "content": [{"text": "private"}]}),
                Outcome::Error,
            ),
            (json!({"isError": false}), Outcome::Success),
            (json!({}), Outcome::Success),
        ] {
            assert_eq!(
                outcome(Some(&JsonRpcResponse::success(Value::Null, result))),
                expected
            );
        }
    }
}
