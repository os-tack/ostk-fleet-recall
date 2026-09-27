//! Authenticated, bounded Streamable HTTP MCP transport (ADR 0009).
//!
//! The backend owns identity verification and authorization. No HTTP field
//! supplies a trusted scope. Every POST independently resolves its bearer to
//! a scoped MCP edge, including legacy clients that use `initialize`.

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use axum::body::{Body, to_bytes};
use axum::extract::{Path, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde_json::{Value, json};
use tokio::sync::Semaphore;

use crate::encoding::base64;
use crate::transcripts::{
    TranscriptAuthorization, TranscriptError, TranscriptReceiver, TranscriptUpload,
};
use crate::{FleetError, Result};

use super::protocol::{
    CLIENT_CAPABILITIES_META, JsonRpcRequest, PROTOCOL_VERSION_META, codes, unsupported_version,
};
use super::server::bound_response;
use super::{
    JsonRpcError, JsonRpcResponse, MAX_MCP_FRAME_BYTES, MODERN_PROTOCOL_VERSION, McpServer,
    PROTOCOL_VERSION, REQUEST_DEADLINE,
};

/// Public failures contain only fixed, safe codes; backend diagnostics belong
/// in server logs and must never disclose credentials or database details.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HttpError {
    #[error("invalid_token")]
    Unauthorized,
    #[error("insufficient_scope")]
    Forbidden,
    #[error("{0}")]
    BadRequest(&'static str),
    #[error("{0}")]
    Unavailable(&'static str),
    #[error("{0}")]
    NotFound(&'static str),
}

/// The runtime supplies authorization, grants, and scoped services. Grant and
/// AWS payloads must be decoded with `deny_unknown_fields` by the backend.
#[async_trait]
pub trait HttpBackend: Send + Sync {
    async fn authenticate(&self, bearer: &str) -> std::result::Result<Arc<McpServer>, HttpError>;
    async fn issue_grant(
        &self,
        bearer: &str,
        request: Value,
    ) -> std::result::Result<Value, HttpError>;
    async fn revoke_grant(&self, bearer: &str, jti: &str) -> std::result::Result<(), HttpError>;
    async fn exchange_aws(&self, request: Value) -> std::result::Result<Value, HttpError>;
    async fn transcript_receiver(
        &self,
        _bearer: &str,
        _instance: &str,
    ) -> std::result::Result<(Arc<TranscriptReceiver>, TranscriptAuthorization), HttpError> {
        Err(HttpError::Forbidden)
    }
}

#[derive(Debug, Clone)]
pub struct HttpConfig {
    pub resource_url: String,
    pub authorization_servers: Vec<String>,
    pub scopes_supported: Vec<String>,
    /// Additional exact serialized origins; the resource's origin is always
    /// allowed. Requests without Origin are allowed for native MCP clients.
    pub allowed_origins: Vec<String>,
    pub max_inflight: usize,
    pub request_deadline: Duration,
}

impl HttpConfig {
    #[must_use]
    pub fn new(resource_url: String, authorization_servers: Vec<String>) -> Self {
        Self {
            resource_url,
            authorization_servers,
            scopes_supported: vec!["fleet-recall".into()],
            allowed_origins: Vec::new(),
            max_inflight: 64,
            request_deadline: REQUEST_DEADLINE,
        }
    }
}

#[derive(Clone)]
struct HttpState {
    backend: Arc<dyn HttpBackend>,
    config: HttpConfig,
    metadata: Value,
    invalid_token_challenge: HeaderValue,
    insufficient_scope_challenge: HeaderValue,
    inflight: Arc<Semaphore>,
}

/// Build the remote plane router. TLS termination and graceful shutdown are
/// supplied by the binary's listener.
///
/// # Errors
///
/// Returns a configuration error for invalid URLs, origins, or bounds.
pub fn router(mut config: HttpConfig, backend: Arc<dyn HttpBackend>) -> Result<Router> {
    let resource = configured_url(&config.resource_url)?;
    if resource.path() != "/mcp" || resource.query().is_some() {
        return Err(configuration(
            "the HTTP resource URL must end in /mcp without a query",
        ));
    }
    for issuer in &config.authorization_servers {
        configured_url(issuer)?;
    }
    for origin in &config.allowed_origins {
        if configured_url(origin)?.origin().ascii_serialization() != *origin {
            return Err(configuration(
                "HTTP allowed origins must be exact URL origins",
            ));
        }
    }
    if !(1..=65_536).contains(&config.max_inflight)
        || config.request_deadline.is_zero()
        || config.request_deadline > Duration::from_secs(300)
    {
        return Err(configuration(
            "invalid HTTP concurrency or request deadline limit",
        ));
    }
    let resource_origin = resource.origin().ascii_serialization();
    if !config.allowed_origins.contains(&resource_origin) {
        config.allowed_origins.push(resource_origin.clone());
    }
    let metadata_url = format!("{resource_origin}/.well-known/oauth-protected-resource/mcp");
    let challenge = |error| {
        HeaderValue::from_str(&format!(
            "Bearer resource_metadata=\"{metadata_url}\", error=\"{error}\""
        ))
        .map_err(|_| configuration("invalid HTTP metadata challenge URL"))
    };
    let state = HttpState {
        metadata: json!({
            "resource": config.resource_url,
            "authorization_servers": config.authorization_servers,
            "scopes_supported": config.scopes_supported,
            "bearer_methods_supported": ["header"],
        }),
        invalid_token_challenge: challenge("invalid_token")?,
        insufficient_scope_challenge: challenge("insufficient_scope")?,
        inflight: Arc::new(Semaphore::new(config.max_inflight)),
        config,
        backend,
    };
    Ok(Router::new()
        .route(
            "/mcp",
            post(mcp).get(mcp_unsupported).delete(mcp_unsupported),
        )
        .route("/.well-known/oauth-protected-resource", get(metadata))
        .route("/.well-known/oauth-protected-resource/mcp", get(metadata))
        .route("/v1/grants", post(issue_grant))
        .route("/v1/grants/{jti}", delete(revoke_grant))
        .route("/v1/auth/aws", post(exchange_aws))
        .route(
            "/v1/transcripts/{instance}/{file}",
            get(transcript).put(transcript),
        )
        .route("/healthz", get(health))
        .layer(middleware::from_fn_with_state(state.clone(), guard))
        .with_state(state))
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct TranscriptQuery {
    #[serde(default)]
    offset: u64,
}

async fn transcript(
    State(state): State<HttpState>,
    Path((instance, file)): Path<(String, String)>,
    Query(query): Query<TranscriptQuery>,
    request: Request,
) -> Response {
    let (parts, body) = request.into_parts();
    let token = match bearer(&parts.headers) {
        Ok(token) => token,
        Err(error) => return backend_error(&state, error),
    };
    let authorized = tokio::time::timeout(
        state.config.request_deadline,
        state.backend.transcript_receiver(token, &instance),
    )
    .await;
    let (receiver, auth) = match authorized {
        Ok(Ok(bound)) => bound,
        Ok(Err(error)) => return backend_error(&state, error),
        Err(_) => return backend_error(&state, HttpError::Unavailable("authentication_timeout")),
    };
    let upload = (|| {
        let header = |name| single_header(&parts.headers, name).ok().flatten().ok_or(());
        let source = base64::decode_url(header("x-transcript-source")?).ok_or(())?;
        if source.len() > 1024 {
            return Err(());
        }
        let source = String::from_utf8(source).map_err(|_| ())?;
        let format = match header("x-transcript-format")? {
            "claude-code" => crate::connectors::transcript::TranscriptFormat::ClaudeCode,
            "codex" => crate::connectors::transcript::TranscriptFormat::Codex,
            _ => return Err(()),
        };
        Ok(TranscriptUpload {
            instance,
            file,
            source,
            format,
            first_line_sha256: header("x-transcript-first-line-sha256")?.into(),
            offset: query.offset,
        })
    })();
    let Ok(upload): std::result::Result<TranscriptUpload, ()> = upload else {
        return error_json(StatusCode::BAD_REQUEST, "invalid_transcript_metadata");
    };
    let bytes = if parts.method == axum::http::Method::PUT {
        if parts.headers.contains_key(header::CONTENT_ENCODING)
            || single_header(&parts.headers, "content-type").ok().flatten()
                != Some("application/octet-stream")
        {
            return error_json(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "transcript_content_type_required",
            );
        }
        match tokio::time::timeout(
            state.config.request_deadline,
            to_bytes(body, receiver.window_bytes()),
        )
        .await
        {
            Ok(Ok(bytes)) => Some(bytes.to_vec()),
            Ok(Err(_)) => {
                return error_json(StatusCode::PAYLOAD_TOO_LARGE, "transcript_window_too_large");
            }
            Err(_) => return error_json(StatusCode::REQUEST_TIMEOUT, "request_body_timeout"),
        }
    } else {
        None
    };
    match receiver.receive(auth, upload, bytes).await {
        Ok(progress) => Json(progress).into_response(),
        Err(TranscriptError::Conflict(length)) => (
            StatusCode::CONFLICT,
            Json(json!({"error":"transcript_offset_conflict","length":length})),
        )
            .into_response(),
        Err(TranscriptError::Invalid) => {
            error_json(StatusCode::BAD_REQUEST, "invalid_transcript_request")
        }
        Err(TranscriptError::Quota) => {
            error_json(StatusCode::PAYLOAD_TOO_LARGE, "transcript_quota_exceeded")
        }
        Err(TranscriptError::Io(_)) => error_json(
            StatusCode::SERVICE_UNAVAILABLE,
            "transcript_spool_unavailable",
        ),
    }
}

fn configuration(message: &str) -> FleetError {
    FleetError::Configuration(message.into())
}

fn configured_url(value: &str) -> Result<reqwest::Url> {
    let parsed =
        reqwest::Url::parse(value).map_err(|_| configuration("invalid HTTP configuration URL"))?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return Err(configuration(
            "HTTP configuration URLs require http(s), a host, and no credentials or fragment",
        ));
    }
    Ok(parsed)
}

async fn guard(State(state): State<HttpState>, request: Request, next: Next) -> Response {
    let mut response = match single_header(request.headers(), "origin") {
        Ok(None) => guarded_request(&state, request, next).await,
        Ok(Some(origin))
            if state
                .config
                .allowed_origins
                .iter()
                .any(|allowed| allowed == origin) =>
        {
            guarded_request(&state, request, next).await
        }
        _ => error_json(StatusCode::FORBIDDEN, "invalid_origin"),
    };
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

async fn guarded_request(state: &HttpState, request: Request, next: Next) -> Response {
    let Ok(_permit) = state.inflight.try_acquire() else {
        let mut response = error_json(StatusCode::SERVICE_UNAVAILABLE, "server_busy");
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        return response;
    };
    next.run(request).await
}

async fn health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

async fn metadata(State(state): State<HttpState>) -> Json<Value> {
    Json(state.metadata)
}

async fn mcp_unsupported(State(state): State<HttpState>, headers: HeaderMap) -> Response {
    match authenticate(&state, &headers).await {
        Ok(_) => {
            let mut response = StatusCode::METHOD_NOT_ALLOWED.into_response();
            response
                .headers_mut()
                .insert(header::ALLOW, HeaderValue::from_static("POST"));
            response
        }
        Err(error) => backend_error(&state, error),
    }
}

async fn authenticate(
    state: &HttpState,
    headers: &HeaderMap,
) -> std::result::Result<Arc<McpServer>, HttpError> {
    let token = bearer(headers)?;
    tokio::time::timeout(
        state.config.request_deadline,
        state.backend.authenticate(token),
    )
    .await
    .unwrap_or(Err(HttpError::Unavailable("authentication_timeout")))
}

fn bearer(headers: &HeaderMap) -> std::result::Result<&str, HttpError> {
    let value = single_header(headers, "authorization")
        .map_err(|()| HttpError::Unauthorized)?
        .ok_or(HttpError::Unauthorized)?;
    let (scheme, token) = value.split_once(' ').ok_or(HttpError::Unauthorized)?;
    if !scheme.eq_ignore_ascii_case("bearer")
        || token.is_empty()
        || token.len() > 16_384
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b',')
    {
        return Err(HttpError::Unauthorized);
    }
    Ok(token)
}

async fn mcp(State(state): State<HttpState>, request: Request) -> Response {
    let server = match authenticate(&state, request.headers()).await {
        Ok(server) => server,
        Err(error) => return backend_error(&state, error),
    };
    let (parts, body) = request.into_parts();
    let value = match read_json(&state, &parts.headers, body).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    let parsed = match JsonRpcRequest::from_value(&value) {
        Ok(parsed) => parsed,
        Err(response) => return rpc_response(StatusCode::BAD_REQUEST, *response),
    };
    if let Err(error) = validate_headers(&parts.headers, &parsed) {
        return rpc_response(
            StatusCode::BAD_REQUEST,
            JsonRpcResponse::error(parsed.id.unwrap_or(Value::Null), error),
        );
    }
    if !scope_permitted(&server, &parsed) {
        return backend_error(&state, HttpError::Forbidden);
    }
    // Never dispatch notification-shaped tools/call: a write must have a
    // request id and a durable receipt the client can observe.
    let Some(response) = server
        .handle_value_with_deadline(value, state.config.request_deadline)
        .await
    else {
        return StatusCode::ACCEPTED.into_response();
    };
    let status = response
        .error
        .as_ref()
        .map_or(StatusCode::OK, |error| match error.code {
            codes::INVALID_PARAMS
                if error
                    .data
                    .as_ref()
                    .and_then(|data| data.get("code"))
                    .and_then(Value::as_str)
                    == Some("role_forbids_action") =>
            {
                StatusCode::FORBIDDEN
            }
            codes::METHOD_NOT_FOUND => StatusCode::NOT_FOUND,
            codes::PARSE_ERROR
            | codes::INVALID_REQUEST
            | codes::INVALID_PARAMS
            | codes::HEADER_MISMATCH
            | codes::UNSUPPORTED_PROTOCOL_VERSION => StatusCode::BAD_REQUEST,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        });
    let mut response = rpc_response(status, response);
    if status == StatusCode::FORBIDDEN {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, state.insufficient_scope_challenge);
    }
    response
}

fn scope_permitted(server: &McpServer, request: &JsonRpcRequest) -> bool {
    if request.method != "tools/call"
        || !matches!(
            request.params.get("name").and_then(Value::as_str),
            Some("recall" | "remember")
        )
    {
        return true;
    }
    let Some(arguments) = request.params.get("arguments") else {
        return true;
    };
    if arguments.get("tenant_id").is_some()
        || arguments
            .get("scope")
            .is_some_and(|scope| scope.get("tenant_id").is_some())
    {
        return false;
    }
    arguments
        .get("scope")
        .and_then(|scope| serde_json::from_value(scope.clone()).ok())
        .is_none_or(|scope| server.permits_requested_scope(&scope))
}

fn validate_headers(
    headers: &HeaderMap,
    request: &JsonRpcRequest,
) -> std::result::Result<(), JsonRpcError> {
    let metadata = request.params.get("_meta");
    let body_version = metadata.and_then(|meta| meta.get(PROTOCOL_VERSION_META));
    let header_version =
        single_header(headers, "mcp-protocol-version").map_err(|()| header_mismatch())?;
    let modern = body_version.is_some();
    if let Some(body_version) = body_version {
        let version = body_version
            .as_str()
            .ok_or_else(|| JsonRpcError::invalid_params("protocolVersion must be a string"))?;
        if header_version != Some(version) {
            return Err(header_mismatch());
        }
    } else if header_version == Some(MODERN_PROTOCOL_VERSION)
        || metadata.is_some_and(|meta| meta.get(CLIENT_CAPABILITIES_META).is_some())
    {
        return Err(JsonRpcError::invalid_params(
            "missing protocolVersion metadata",
        ));
    } else if let Some(version) = header_version
        && !matches!(
            version,
            "2024-11-05" | "2025-03-26" | PROTOCOL_VERSION | "2025-11-25"
        )
    {
        return Err(unsupported_version(version));
    }
    // Version/capability failures identify a modern peer before applying the
    // remaining header rules of the supported revision.
    request.validate_protocol()?;
    let method_header = single_header(headers, "mcp-method").map_err(|()| header_mismatch())?;
    if method_header.is_some_and(|method| method != request.method)
        || (modern && !request.is_notification() && method_header.is_none())
    {
        return Err(header_mismatch());
    }
    let name_header = single_header(headers, "mcp-name").map_err(|()| header_mismatch())?;
    let name = match request.method.as_str() {
        "tools/call" | "prompts/get" => request.params.get("name").and_then(Value::as_str),
        "resources/read" => request.params.get("uri").and_then(Value::as_str),
        _ => None,
    };
    if let Some(encoded) = name_header {
        let decoded = decode_name(encoded)?;
        if name != Some(decoded.as_str()) {
            return Err(header_mismatch());
        }
    } else if modern
        && !request.is_notification()
        && matches!(
            request.method.as_str(),
            "tools/call" | "prompts/get" | "resources/read"
        )
    {
        return Err(header_mismatch());
    }
    Ok(())
}

fn header_mismatch() -> JsonRpcError {
    JsonRpcError::new(
        codes::HEADER_MISMATCH,
        "required MCP headers are missing, malformed, or disagree with the request body",
    )
}

fn decode_name(value: &str) -> std::result::Result<String, JsonRpcError> {
    if let Some(encoded) = value
        .strip_prefix("=?base64?")
        .and_then(|value| value.strip_suffix("?="))
    {
        return base64::decode(encoded)
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .ok_or_else(header_mismatch);
    }
    if value.trim() != value
        || !value
            .bytes()
            .all(|byte| byte == b'\t' || (b' '..=b'~').contains(&byte))
    {
        return Err(header_mismatch());
    }
    Ok(value.to_owned())
}

fn single_header<'a>(
    headers: &'a HeaderMap,
    name: &str,
) -> std::result::Result<Option<&'a str>, ()> {
    let mut values = headers.get_all(name).iter();
    let first = values.next();
    if values.next().is_some() {
        return Err(());
    }
    first
        .map(|value| value.to_str().map_err(|_| ()))
        .transpose()
}

async fn read_json(
    state: &HttpState,
    headers: &HeaderMap,
    body: Body,
) -> std::result::Result<Value, Response> {
    let content_type = single_header(headers, "content-type").ok().flatten();
    if !content_type.is_some_and(|value| {
        value
            .split(';')
            .next()
            .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"))
    }) {
        return Err(error_json(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "content_type_must_be_application_json",
        ));
    }
    let bytes = tokio::time::timeout(
        state.config.request_deadline,
        to_bytes(body, MAX_MCP_FRAME_BYTES),
    )
    .await
    .map_err(|_| error_json(StatusCode::REQUEST_TIMEOUT, "request_body_timeout"))?
    .map_err(|error| {
        // Axum preserves a length-limit error in its source chain. Avoid
        // returning implementation diagnostics to an unauthenticated peer.
        let too_large = std::error::Error::source(&error)
            .is_some_and(|source| source.to_string().contains("length limit"));
        if too_large {
            error_json(StatusCode::PAYLOAD_TOO_LARGE, "request_body_too_large")
        } else {
            error_json(StatusCode::BAD_REQUEST, "invalid_request_body")
        }
    })?;
    serde_json::from_slice(&bytes).map_err(|_| {
        rpc_response(
            StatusCode::BAD_REQUEST,
            JsonRpcResponse::error(
                Value::Null,
                JsonRpcError::parse("invalid JSON request body"),
            ),
        )
    })
}

async fn issue_grant(State(state): State<HttpState>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let token = match bearer(&parts.headers) {
        Ok(token) => token,
        Err(error) => return backend_error(&state, error),
    };
    let value = match read_json(&state, &parts.headers, body).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    match tokio::time::timeout(
        state.config.request_deadline,
        state.backend.issue_grant(token, value),
    )
    .await
    {
        Ok(Ok(value)) => (StatusCode::CREATED, Json(value)).into_response(),
        Ok(Err(error)) => backend_error(&state, error),
        Err(_) => backend_error(&state, HttpError::Unavailable("grant_issue_timeout")),
    }
}

async fn revoke_grant(
    State(state): State<HttpState>,
    Path(jti): Path<String>,
    headers: HeaderMap,
) -> Response {
    let token = match bearer(&headers) {
        Ok(token) => token,
        Err(error) => return backend_error(&state, error),
    };
    if jti.len() > 256
        || jti.is_empty()
        || !jti
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return backend_error(&state, HttpError::BadRequest("invalid_grant_id"));
    }
    match tokio::time::timeout(
        state.config.request_deadline,
        state.backend.revoke_grant(token, &jti),
    )
    .await
    {
        Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err(error)) => backend_error(&state, error),
        Err(_) => backend_error(&state, HttpError::Unavailable("grant_revoke_timeout")),
    }
}

async fn exchange_aws(State(state): State<HttpState>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let value = match read_json(&state, &parts.headers, body).await {
        Ok(value) => value,
        Err(response) => return response,
    };
    match tokio::time::timeout(
        state.config.request_deadline,
        state.backend.exchange_aws(value),
    )
    .await
    {
        Ok(Ok(value)) => Json(value).into_response(),
        Ok(Err(error)) => backend_error(&state, error),
        Err(_) => backend_error(&state, HttpError::Unavailable("aws_exchange_timeout")),
    }
}

fn rpc_response(status: StatusCode, response: JsonRpcResponse) -> Response {
    (status, Json(bound_response(response))).into_response()
}

fn error_json(status: StatusCode, error: &str) -> Response {
    (status, Json(json!({ "error": error }))).into_response()
}

fn backend_error(state: &HttpState, error: HttpError) -> Response {
    let status = match error {
        HttpError::Unauthorized => StatusCode::UNAUTHORIZED,
        HttpError::Forbidden => StatusCode::FORBIDDEN,
        HttpError::BadRequest(_) => StatusCode::BAD_REQUEST,
        HttpError::Unavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
        HttpError::NotFound(_) => StatusCode::NOT_FOUND,
    };
    let mut response = error_json(status, &error.to_string());
    let challenge = match error {
        HttpError::Unauthorized => Some(&state.invalid_token_challenge),
        HttpError::Forbidden => Some(&state.insufficient_scope_challenge),
        _ => None,
    };
    if let Some(challenge) = challenge {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, challenge.clone());
    }
    response
}

#[cfg(test)]
mod tests;
