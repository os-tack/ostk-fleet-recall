//! Minimal JSON-RPC 2.0 types and validation for MCP stdio.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A validated JSON-RPC request. `None` means the `id` member was absent and
/// the message is a notification; `Some(Value::Null)` remains a request whose
/// response id is JSON null.
#[derive(Debug, Clone)]
pub struct JsonRpcRequest {
    pub id: Option<Value>,
    pub method: String,
    pub params: Value,
}

impl JsonRpcRequest {
    /// Validate the JSON-RPC envelope while retaining the request id for any
    /// invalid-request response.
    pub fn from_value(value: &Value) -> Result<Self, Box<JsonRpcResponse>> {
        let Some(object) = value.as_object() else {
            return Err(Box::new(JsonRpcResponse::error(
                Value::Null,
                JsonRpcError::invalid_request("request must be a JSON object"),
            )));
        };

        let response_id = object
            .get("id")
            .filter(|id| valid_id(id))
            .cloned()
            .unwrap_or(Value::Null);

        if object.get("jsonrpc") != Some(&Value::String("2.0".into())) {
            return Err(Box::new(JsonRpcResponse::error(
                response_id,
                JsonRpcError::invalid_request("`jsonrpc` must be \"2.0\""),
            )));
        }

        let Some(method) = object.get("method").and_then(Value::as_str) else {
            return Err(Box::new(JsonRpcResponse::error(
                response_id,
                JsonRpcError::invalid_request("`method` must be a string"),
            )));
        };
        if method.is_empty() {
            return Err(Box::new(JsonRpcResponse::error(
                response_id,
                JsonRpcError::invalid_request("`method` must not be empty"),
            )));
        }

        let id = match object.get("id") {
            Some(id) if valid_id(id) => Some(id.clone()),
            Some(_) => {
                return Err(Box::new(JsonRpcResponse::error(
                    Value::Null,
                    JsonRpcError::invalid_request("`id` must be a string, number, or null"),
                )));
            }
            None => None,
        };

        let params = object
            .get("params")
            .cloned()
            .unwrap_or_else(|| Value::Object(serde_json::Map::new()));
        if !params.is_null() && !params.is_object() && !params.is_array() {
            return Err(Box::new(JsonRpcResponse::error(
                id.unwrap_or(Value::Null),
                JsonRpcError::invalid_request("`params` must be an object or array"),
            )));
        }

        Ok(Self {
            id,
            method: method.to_owned(),
            params,
        })
    }

    #[must_use]
    pub const fn is_notification(&self) -> bool {
        self.id.is_none()
    }
}

fn valid_id(value: &Value) -> bool {
    value.is_string() || value.is_number() || value.is_null()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JsonRpcResponse {
    pub jsonrpc: &'static str,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

impl JsonRpcResponse {
    #[must_use]
    pub const fn success(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: Some(result),
            error: None,
        }
    }

    #[must_use]
    pub const fn error(id: Value, error: JsonRpcError) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(error),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl JsonRpcError {
    #[must_use]
    pub fn new(code: i64, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    #[must_use]
    pub fn parse(message: impl Into<String>) -> Self {
        Self::new(codes::PARSE_ERROR, message)
    }

    #[must_use]
    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self::new(codes::INVALID_REQUEST, message)
    }

    #[must_use]
    pub fn method_not_found(method: &str) -> Self {
        let method = bounded_untrusted_label(method);
        Self::new(
            codes::METHOD_NOT_FOUND,
            format!("method not found: {method}"),
        )
    }

    #[must_use]
    pub fn invalid_params(message: impl Into<String>) -> Self {
        Self::new(codes::INVALID_PARAMS, message)
    }

    #[must_use]
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(codes::INTERNAL_ERROR, message)
    }
}

fn bounded_untrusted_label(value: &str) -> String {
    const MAX_CHARS: usize = 128;
    if value.chars().count() <= MAX_CHARS {
        value.to_owned()
    } else {
        format!("{}…", value.chars().take(MAX_CHARS).collect::<String>())
    }
}

pub mod codes {
    pub const PARSE_ERROR: i64 = -32_700;
    pub const INVALID_REQUEST: i64 = -32_600;
    pub const METHOD_NOT_FOUND: i64 = -32_601;
    pub const INVALID_PARAMS: i64 = -32_602;
    pub const INTERNAL_ERROR: i64 = -32_603;
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn distinguishes_null_id_from_notification() {
        let value = json!({
            "jsonrpc": "2.0",
            "id": null,
            "method": "ping"
        });
        let request = JsonRpcRequest::from_value(&value).unwrap();
        assert_eq!(request.id, Some(Value::Null));
        assert!(!request.is_notification());

        let value = json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        });
        let notification = JsonRpcRequest::from_value(&value).unwrap();
        assert!(notification.is_notification());
    }

    #[test]
    fn invalid_request_keeps_a_valid_id() {
        let value = json!({
            "jsonrpc": "1.0",
            "id": "client-4",
            "method": "ping"
        });
        let response = JsonRpcRequest::from_value(&value).unwrap_err();
        assert_eq!(response.id, json!("client-4"));
        assert_eq!(response.error.unwrap().code, codes::INVALID_REQUEST);
    }
}
