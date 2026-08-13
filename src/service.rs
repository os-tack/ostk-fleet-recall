//! Backend-neutral service contract for fleet memory.
//!
//! The MCP edge depends only on this module. `CockroachDB` repositories implement
//! the contract behind the service boundary; protocol code never receives a
//! connection, transaction, or SQL-shaped type.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::FleetScope;

/// Read-only operations exposed through the canonical `recall` tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecallAction {
    Search,
    Get,
    Surface,
    Discover,
    Conflicts,
    Synthesize,
    Status,
    Audit,
}

impl RecallAction {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Search => "search",
            Self::Get => "get",
            Self::Surface => "surface",
            Self::Discover => "discover",
            Self::Conflicts => "conflicts",
            Self::Synthesize => "synthesize",
            Self::Status => "status",
            Self::Audit => "audit",
        }
    }
}

/// Deliberate mutations exposed through the canonical `remember` tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RememberAction {
    Record,
    Supersede,
    Retract,
    Forget,
    Restore,
    Resolve,
    Relate,
    Split,
    Focus,
    Track,
    Consolidate,
}

impl RememberAction {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Record => "record",
            Self::Supersede => "supersede",
            Self::Retract => "retract",
            Self::Forget => "forget",
            Self::Restore => "restore",
            Self::Resolve => "resolve",
            Self::Relate => "relate",
            Self::Split => "split",
            Self::Focus => "focus",
            Self::Track => "track",
            Self::Consolidate => "consolidate",
        }
    }
}

/// Sanitized canonical read request.
///
/// Action-specific fields remain an extensible JSON object. Scope is
/// intentionally absent: a protocol adapter resolves untrusted attention
/// input into the separate [`FleetScope`] before constructing this value.
#[derive(Debug, Clone)]
pub struct RecallRequest {
    pub action: RecallAction,
    pub arguments: Map<String, Value>,
}

impl RecallRequest {
    #[must_use]
    pub const fn new(action: RecallAction, arguments: Map<String, Value>) -> Self {
        Self { action, arguments }
    }

    #[must_use]
    pub fn argument(&self, name: &str) -> Option<&Value> {
        self.arguments.get(name)
    }
}

/// Canonical write request.
///
/// `idempotency_key` is a first-class field rather than an opaque argument so
/// every backend implementation has an explicit replay-safety signal. Some
/// actions can derive natural idempotency, so the transport does not require a
/// key globally; implementations may require it for individual actions.
#[derive(Debug, Clone)]
pub struct RememberRequest {
    pub action: RememberAction,
    pub idempotency_key: Option<String>,
    pub arguments: Map<String, Value>,
}

impl RememberRequest {
    #[must_use]
    pub const fn new(
        action: RememberAction,
        idempotency_key: Option<String>,
        arguments: Map<String, Value>,
    ) -> Self {
        Self {
            action,
            idempotency_key,
            arguments,
        }
    }

    #[must_use]
    pub fn argument(&self, name: &str) -> Option<&Value> {
        self.arguments.get(name)
    }
}

/// Conflict coverage attached to every canonical result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConflictCoverage {
    pub status: String,
    #[serde(flatten)]
    pub details: Map<String, Value>,
}

impl ConflictCoverage {
    #[must_use]
    pub fn new(status: impl Into<String>) -> Self {
        Self {
            status: status.into(),
            details: Map::new(),
        }
    }

    #[must_use]
    pub fn not_evaluated() -> Self {
        Self::new("not_evaluated")
    }
}

impl Default for ConflictCoverage {
    fn default() -> Self {
        Self::not_evaluated()
    }
}

/// Backend result for a non-mutating recall operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecallResult {
    pub data: Value,
    #[serde(default)]
    pub conflicts: Vec<Value>,
    #[serde(default)]
    pub conflict_coverage: ConflictCoverage,
    #[serde(default)]
    pub warnings: Vec<Value>,
    #[serde(default)]
    pub diagnostics: Map<String, Value>,
}

impl RecallResult {
    #[must_use]
    pub fn new(data: Value) -> Self {
        Self {
            data,
            conflicts: Vec::new(),
            conflict_coverage: ConflictCoverage::default(),
            warnings: Vec::new(),
            diagnostics: Map::new(),
        }
    }
}

/// Backend result for a deliberate remember mutation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RememberResult {
    pub data: Value,
    #[serde(default)]
    pub conflicts: Vec<Value>,
    #[serde(default)]
    pub conflict_coverage: ConflictCoverage,
    #[serde(default)]
    pub warnings: Vec<Value>,
    #[serde(default)]
    pub diagnostics: Map<String, Value>,
}

impl RememberResult {
    #[must_use]
    pub fn new(data: Value) -> Self {
        Self {
            data,
            conflicts: Vec::new(),
            conflict_coverage: ConflictCoverage::default(),
            warnings: Vec::new(),
            diagnostics: Map::new(),
        }
    }
}

/// Backend-neutral service failure.
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error("invalid memory request: {0}")]
    InvalidRequest(String),
    #[error("memory service unavailable: {0}")]
    Unavailable(String),
    #[error("memory operation failed: {0}")]
    Internal(String),
}

pub type ServiceResult<T> = std::result::Result<T, ServiceError>;

/// Semantic service boundary used by protocol adapters.
///
/// Separate read and write methods make it impossible for `recall` dispatch to
/// reach a mutating handler accidentally. `scope` has already been resolved
/// against the server's trusted tenant/default context before either method is
/// called.
#[async_trait]
pub trait FleetMemoryService: Send + Sync {
    async fn recall(
        &self,
        scope: FleetScope,
        request: RecallRequest,
    ) -> ServiceResult<RecallResult>;

    async fn remember(
        &self,
        scope: FleetScope,
        request: RememberRequest,
    ) -> ServiceResult<RememberResult>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitized_recall_request_has_no_scope_field() {
        let request = RecallRequest::new(
            RecallAction::Search,
            Map::from_iter([("query".into(), Value::String("distributed memory".into()))]),
        );

        assert_eq!(request.action, RecallAction::Search);
        assert_eq!(
            request.argument("query"),
            Some(&Value::String("distributed memory".into()))
        );
    }

    #[test]
    fn remember_preserves_idempotency_key() {
        let request = RememberRequest::new(
            RememberAction::Record,
            Some("turn-17/fact-2".into()),
            Map::from_iter([
                ("kind".into(), Value::String("fact".into())),
                (
                    "text".into(),
                    Value::String("CockroachDB is the fleet substrate".into()),
                ),
            ]),
        );

        assert_eq!(request.action, RememberAction::Record);
        assert_eq!(request.idempotency_key.as_deref(), Some("turn-17/fact-2"));
        assert_eq!(
            request.argument("kind"),
            Some(&Value::String("fact".into()))
        );
    }
}
