//! Bounded, sequential stdio-to-HTTP MCP client for sandbox harnesses.

use std::{path::Path, time::Duration};

use anyhow::{Context as _, ensure};
use reqwest::{Client, StatusCode, Url, header::HeaderValue};
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _, BufReader};

use crate::encoding::base64;
use crate::mcp::protocol::{
    Frame, JsonRpcError, JsonRpcRequest, JsonRpcResponse, PROTOCOL_VERSION_META, read_frame,
};
use crate::mcp::{MAX_MCP_FRAME_BYTES, PROTOCOL_VERSION};

/// Credentials are deliberately excluded from Debug and diagnostics.
pub struct Shim {
    client: Client,
    url: Url,
    authorization: HeaderValue,
}

impl Shim {
    pub fn new(endpoint: &str, token: &str, allow_http: bool) -> anyhow::Result<Self> {
        Self::new_with_ca(endpoint, token, allow_http, None)
    }

    pub fn new_with_ca(
        endpoint: &str,
        token: &str,
        allow_http: bool,
        ca_path: Option<&Path>,
    ) -> anyhow::Result<Self> {
        let url = Url::parse(endpoint).context("invalid MCP endpoint URL")?;
        ensure!(
            url.has_host()
                && url.username().is_empty()
                && url.password().is_none()
                && url.fragment().is_none(),
            "MCP URL must have a host and no credentials or fragment"
        );
        ensure!(
            url.scheme() == "https" || (url.scheme() == "http" && allow_http),
            "MCP requires HTTPS; --allow-http explicitly permits a private development endpoint"
        );
        ensure!(
            !token.is_empty()
                && token.len() <= 16_384
                && !token.bytes().any(|byte| byte.is_ascii_whitespace()),
            "invalid or missing FLEET_RECALL_TOKEN"
        );
        let mut authorization = HeaderValue::from_str(&format!("Bearer {token}"))
            .context("invalid FLEET_RECALL_TOKEN")?;
        authorization.set_sensitive(true);
        let builder = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(35));
        let client = crate::client_tls::with_ca_bundle(builder, ca_path)?.build()?;
        Ok(Self {
            client,
            url,
            authorization,
        })
    }

    pub async fn serve<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
        &self,
        reader: R,
        mut writer: W,
    ) -> std::io::Result<()> {
        let mut reader = BufReader::new(reader);
        while let Some(frame) = read_frame(&mut reader).await? {
            let response = match frame {
                Frame::Oversize => Some(serde_json::to_value(JsonRpcResponse::error(
                    Value::Null,
                    JsonRpcError::invalid_request(format!(
                        "MCP frame exceeds {MAX_MCP_FRAME_BYTES} bytes"
                    )),
                ))?),
                Frame::Data(bytes) if bytes.iter().all(u8::is_ascii_whitespace) => continue,
                Frame::Data(bytes) => self.forward_frame(&bytes).await,
            };
            if let Some(response) = response {
                let mut bytes = encode_bounded(&response)?;
                bytes.push(b'\n');
                writer.write_all(&bytes).await?;
                writer.flush().await?;
            }
        }
        Ok(())
    }

    async fn forward_frame(&self, bytes: &[u8]) -> Option<Value> {
        let value: Value = match serde_json::from_slice(bytes) {
            Ok(value) => value,
            Err(_) => {
                return Some(
                    serde_json::json!({"jsonrpc":"2.0", "id":null, "error":{"code":-32700,"message":"parse error: invalid MCP JSON"}}),
                );
            }
        };
        let request = match JsonRpcRequest::from_value(&value) {
            Ok(request) => request,
            Err(response) => return serde_json::to_value(response).ok(),
        };
        if let Ok(value) = self.post(&request, &value).await {
            value
        } else {
            // No retry: a timed-out write may already have committed.
            tracing::warn!("remote MCP request failed; mutation outcome may be unknown");
            request.id.map(|id| serde_json::json!({"jsonrpc":"2.0", "id":id,
                    "error":{"code":-32603,"message":"remote MCP request failed; mutation outcome may be unknown"}}))
        }
    }

    async fn post(&self, request: &JsonRpcRequest, value: &Value) -> Result<Option<Value>, ()> {
        let version = request
            .params
            .get("_meta")
            .and_then(|meta| meta.get(PROTOCOL_VERSION_META))
            .and_then(Value::as_str)
            .unwrap_or(PROTOCOL_VERSION);
        let mut builder = self
            .client
            .post(self.url.clone())
            .header(reqwest::header::AUTHORIZATION, self.authorization.clone())
            .header(
                reqwest::header::ACCEPT,
                "application/json, text/event-stream",
            )
            .header("MCP-Protocol-Version", version)
            .header("Mcp-Method", &request.method)
            .json(value);
        let name = match request.method.as_str() {
            "tools/call" | "prompts/get" => request.params.get("name"),
            "resources/read" => request.params.get("uri"),
            _ => None,
        }
        .and_then(Value::as_str);
        if let Some(name) = name {
            builder = builder.header("Mcp-Name", header_name(name));
        }
        let mut response = builder.send().await.map_err(|_| ())?;
        let status = response.status();
        if response.status() == StatusCode::ACCEPTED && request.is_notification() {
            return Ok(None);
        }
        // Notifications never produce a JSON-RPC reply, even on transport errors.
        if request.is_notification() || response.status().is_redirection() {
            return Err(());
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_MCP_FRAME_BYTES as u64)
        {
            return Err(());
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| ())? {
            if bytes.len().saturating_add(chunk.len()) > MAX_MCP_FRAME_BYTES {
                return Err(());
            }
            bytes.extend_from_slice(&chunk);
        }
        let value: Value = serde_json::from_slice(&bytes).map_err(|_| ())?;
        if value.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
            || value.get("id") != request.id.as_ref()
            || (value.get("result").is_some() == value.get("error").is_some())
        {
            return Err(());
        }
        // Only 200 carries a successful result. Fleet's scoped tool refusals
        // can use 403 with an MCP isError result; protocol errors may use 4xx.
        if status != StatusCode::OK
            && value.get("error").is_none()
            && !(status == StatusCode::FORBIDDEN
                && value
                    .get("result")
                    .and_then(|result| result.get("isError"))
                    .and_then(Value::as_bool)
                    == Some(true))
        {
            return Err(());
        }
        Ok(Some(value))
    }
}

fn encode_bounded(response: &Value) -> std::io::Result<Vec<u8>> {
    let bytes = serde_json::to_vec(&response)?;
    if bytes.len() <= MAX_MCP_FRAME_BYTES {
        return Ok(bytes);
    }
    let mut fallback = serde_json::json!({"jsonrpc":"2.0","id":response.get("id").cloned().unwrap_or(Value::Null),
        "error":{"code":-32603,"message":"response exceeded the transport budget"}});
    let bytes = serde_json::to_vec(&fallback)?;
    if bytes.len() <= MAX_MCP_FRAME_BYTES {
        return Ok(bytes);
    }
    fallback["id"] = Value::Null;
    serde_json::to_vec(&fallback).map_err(std::io::Error::other)
}

fn header_name(name: &str) -> String {
    if name.trim() != name
        || name.starts_with("=?base64?")
        || !name.bytes().all(|byte| (b' '..=b'~').contains(&byte))
    {
        format!("=?base64?{}?=", base64::encode(name.as_bytes()))
    } else {
        name.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Json, Router, extract::State, http::HeaderMap, routing::post};
    use std::sync::Arc;
    use tokio::sync::Mutex;

    #[test]
    fn secrets_and_http_need_explicit_configuration() {
        assert!(Shim::new("http://example.com/mcp", "test", false).is_err());
        assert!(Shim::new("http://127.0.0.1/mcp", "test", false).is_err());
        assert!(Shim::new("http://localhost/mcp", "test", false).is_err());
        assert!(Shim::new("https://user:pass@example.com/mcp", "test", false).is_err());
        assert!(Shim::new("http://127.0.0.1/mcp", "test\r\nfoo", true).is_err());
        assert_eq!(header_name("recall"), "recall");
        assert_eq!(
            header_name(" λ "),
            format!("=?base64?{}?=", base64::encode(" λ ".as_bytes()))
        );
        assert!(header_name("=?base64?a?=").starts_with("=?base64?PT9"));
        let encoded = encode_bounded(
            &serde_json::json!({"id":"x".repeat(MAX_MCP_FRAME_BYTES),"error":{"message":"failed"}}),
        )
        .unwrap();
        assert!(encoded.len() < MAX_MCP_FRAME_BYTES);
        assert!(serde_json::from_slice::<Value>(&encoded).unwrap()["id"].is_null());
    }

    #[tokio::test]
    async fn private_ca_shim_sends_bearer_only_after_verified_tls() {
        use crate::client_tls::tests::{CA_FIRST, KEY_FIRST, SERVER_FIRST, serve_tls};
        use std::sync::atomic::{AtomicUsize, Ordering};

        let seen = Arc::new(AtomicUsize::new(0));
        let requests = seen.clone();
        let app = Router::new().route("/mcp", post(move |headers: HeaderMap, Json(body): Json<Value>| {
            assert_eq!(headers["authorization"], "Bearer test-tls-grant");
            requests.fetch_add(1, Ordering::SeqCst);
            async move { Json(serde_json::json!({"jsonrpc":"2.0","id":body["id"],"result":{}})) }
        }));
        let (base, task) = serve_tls(app, SERVER_FIRST, KEY_FIRST).await;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("ca.pem");
        std::fs::write(&path, CA_FIRST).unwrap();
        let input = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"server/discover\"}\n";
        for (base, trust, accepted) in [
            (base.clone(), None, false),
            (
                base.replace("localhost", "127.0.0.1"),
                Some(path.as_path()),
                false,
            ),
            (base, Some(path.as_path()), true),
        ] {
            let shim =
                Shim::new_with_ca(&format!("{base}/mcp"), "test-tls-grant", false, trust).unwrap();
            let mut output = Vec::new();
            shim.serve(input.as_slice(), &mut output).await.unwrap();
            let response: Value = serde_json::from_slice(&output).unwrap();
            assert_eq!(response.get("result").is_some(), accepted);
            assert!(
                !String::from_utf8(output)
                    .unwrap()
                    .contains("test-tls-grant")
            );
        }
        assert_eq!(seen.load(Ordering::SeqCst), 1);
        task.abort();
    }

    #[tokio::test]
    async fn preserves_frames_ids_headers_and_notification_silence() {
        type Calls = Arc<Mutex<Vec<(HeaderMap, Value)>>>;
        async fn handler(
            State(calls): State<Calls>,
            headers: HeaderMap,
            Json(value): Json<Value>,
        ) -> axum::response::Response {
            use axum::response::IntoResponse as _;
            calls.lock().await.push((headers, value.clone()));
            value.get("id").map_or_else(
                || StatusCode::ACCEPTED.into_response(),
                |id| {
                    Json(serde_json::json!({"jsonrpc":"2.0","id":id,"result":{"ok":true}}))
                        .into_response()
                },
            )
        }
        let calls = Calls::default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = Router::new()
            .route("/mcp", post(handler))
            .with_state(calls.clone());
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let shim = Shim::new(&format!("http://{addr}/mcp"), "test-only", true).unwrap();
        let input = concat!(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n",
            "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":\"two\",\"method\":\"tools/call\",\"params\":{\"name\":\"λ\",\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\"}}}\n"
        );
        let mut output = Vec::new();
        shim.serve(input.as_bytes(), &mut output).await.unwrap();
        let replies: Vec<Value> = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(replies.len(), 2);
        assert_eq!(replies[1]["id"], "two");
        let calls = calls.lock().await;
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0].0["authorization"], "Bearer test-only");
        assert_eq!(calls[0].0["mcp-protocol-version"], PROTOCOL_VERSION);
        assert_eq!(calls[2].0["mcp-protocol-version"], "2026-07-28");
        assert_eq!(calls[2].0["mcp-name"], header_name("λ"));
        drop(calls);
        task.abort();
    }

    #[tokio::test]
    async fn rejects_redirects_without_retry_and_drains_oversized_frames() {
        use axum::response::IntoResponse as _;
        use std::sync::atomic::{AtomicUsize, Ordering};
        let posts = Arc::new(AtomicUsize::new(0));
        let leaked = Arc::new(AtomicUsize::new(0));
        let post_count = posts.clone();
        let leak_count = leaked.clone();
        let router = Router::new()
            .route(
                "/mcp",
                post(move || {
                    post_count.fetch_add(1, Ordering::SeqCst);
                    async {
                        (StatusCode::TEMPORARY_REDIRECT, [("location", "/other")]).into_response()
                    }
                }),
            )
            .route(
                "/other",
                post(move || {
                    leak_count.fetch_add(1, Ordering::SeqCst);
                    async { StatusCode::OK }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let shim = Shim::new(&format!("http://{addr}/mcp"), "never-forward-me", true).unwrap();
        let mut input = vec![b'x'; MAX_MCP_FRAME_BYTES + 10];
        input.extend_from_slice(b"\n{\"jsonrpc\":\"2.0\",\"id\":null,\"method\":\"tools/call\",\"params\":{\"name\":\"remember\"}}\n");
        let mut output = Vec::new();
        shim.serve(input.as_slice(), &mut output).await.unwrap();
        let replies: Vec<Value> = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(replies.len(), 2);
        assert_eq!(replies[0]["error"]["code"], -32600);
        assert_eq!(replies[1]["error"]["code"], -32603);
        assert!(replies[1]["id"].is_null());
        assert_eq!(posts.load(Ordering::SeqCst), 1);
        assert_eq!(leaked.load(Ordering::SeqCst), 0);
        task.abort();
    }
}
