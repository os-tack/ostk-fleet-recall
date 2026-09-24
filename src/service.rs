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
    /// Event-first ingestion beside the byte-identical legacy [`Self::Record`]
    /// path (ADR 0002 D3). An accepted `assert` appends `memory.claim.accepted`
    /// to the Stage-4 evidence ledger and writes the legacy claim projection in
    /// one serializable transaction. The route fails closed with a typed error
    /// until the deployment carries the writer-authority configuration D4
    /// requires; `record` is unaffected either way.
    Assert,
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
            Self::Assert => "assert",
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

/// A typed, caller-correctable refusal of a memory mutation.
///
/// Unlike [`ServiceError::Unavailable`] or [`ServiceError::Internal`], a
/// refusal is decided before commit: nothing was written and the request's
/// idempotency key was not consumed, so the caller can re-read and send a
/// corrected request, even with the same key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// Stable snake-case code, e.g. `stale_revision` or `not_owner`.
    pub code: &'static str,
    pub message: String,
    pub details: Value,
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
    #[error("memory mutation refused ({}): {}", .0.code, .0.message)]
    Refused(Refusal),
}

pub type ServiceResult<T> = std::result::Result<T, ServiceError>;

/// Which `remember` actions a service instance serves.
///
/// The MCP edge advertises exactly this surface in `tools/list`, and the
/// service refuses anything outside it before any I/O. [`Self::RECORD_ONLY`]
/// is the historical surface and produces the historical tool schema
/// byte-for-byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
pub struct RememberSurface {
    /// Owner lifecycle of authored claims (`retract` and `supersede`).
    pub claim_lifecycle: bool,
}

impl RememberSurface {
    pub const RECORD_ONLY: Self = Self {
        claim_lifecycle: false,
    };

    /// Whether this surface serves `action`. `record` is always served; the
    /// remaining non-lifecycle actions keep their own dispatch outcome.
    #[must_use]
    pub const fn allows(self, action: RememberAction) -> bool {
        match action {
            RememberAction::Record => true,
            RememberAction::Retract | RememberAction::Supersede => self.claim_lifecycle,
            _ => false,
        }
    }
}

/// Refuse a lifecycle action the surface does not serve, before any I/O.
///
/// Actions outside the lifecycle vocabulary pass through unchanged so their
/// existing outcomes (for example the fenced `assert` route) are preserved.
pub fn authorize_surface(surface: RememberSurface, action: RememberAction) -> ServiceResult<()> {
    let lifecycle_action = matches!(
        action,
        RememberAction::Retract | RememberAction::Supersede | RememberAction::Resolve
    );
    if !lifecycle_action || surface.allows(action) {
        return Ok(());
    }
    Err(ServiceError::Refused(Refusal {
        code: "lifecycle_unavailable",
        message: format!(
            "remember({}) is not served by this deployment",
            action.as_str()
        ),
        details: serde_json::json!({ "action": action.as_str() }),
    }))
}

/// Recall-only capability used by publication adapters.
///
/// A public router holding this trait object has no method through which it can
/// invoke `remember`, even when the underlying private implementation also
/// serves MCP writers. The blanket adapter preserves the existing writer trait
/// and its protocol consumers without widening this capability.
#[async_trait]
pub trait FleetRecallService: Send + Sync {
    async fn recall(
        &self,
        scope: FleetScope,
        request: RecallRequest,
    ) -> ServiceResult<RecallResult>;
}

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

    /// The `remember` actions this instance serves; see [`RememberSurface`].
    fn remember_surface(&self) -> RememberSurface {
        RememberSurface::RECORD_ONLY
    }
}

#[async_trait]
impl<T> FleetRecallService for T
where
    T: FleetMemoryService + ?Sized,
{
    async fn recall(
        &self,
        scope: FleetScope,
        request: RecallRequest,
    ) -> ServiceResult<RecallResult> {
        FleetMemoryService::recall(self, scope, request).await
    }
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
    fn assert_action_wire_string_round_trips() {
        // The event-first action deserializes from its snake_case wire label so
        // an MCP `remember` call with `"action":"assert"` reaches the disabled
        // route rather than being silently coerced into `record` (ADR 0002 D3).
        let decoded: RememberAction = serde_json::from_str("\"assert\"").unwrap();
        assert_eq!(decoded, RememberAction::Assert);
        assert_eq!(RememberAction::Assert.as_str(), "assert");
        assert_ne!(RememberAction::Assert, RememberAction::Record);
        assert_eq!(
            serde_json::to_value(RememberAction::Assert).unwrap(),
            Value::String("assert".into())
        );
    }

    #[test]
    fn authorize_surface_refuses_before_io() {
        for action in [
            RememberAction::Retract,
            RememberAction::Supersede,
            RememberAction::Resolve,
        ] {
            let Err(ServiceError::Refused(refusal)) =
                authorize_surface(RememberSurface::RECORD_ONLY, action)
            else {
                panic!(
                    "{} must be refused on the record-only surface",
                    action.as_str()
                );
            };
            assert_eq!(refusal.code, "lifecycle_unavailable");
            assert_eq!(refusal.details["action"], action.as_str());
        }
        let lifecycle = RememberSurface {
            claim_lifecycle: true,
        };
        assert!(authorize_surface(lifecycle, RememberAction::Retract).is_ok());
        assert!(authorize_surface(lifecycle, RememberAction::Supersede).is_ok());
        // Conflict resolve is not served by this surface yet.
        assert!(authorize_surface(lifecycle, RememberAction::Resolve).is_err());
        // Record and non-lifecycle actions keep their own dispatch outcome.
        for surface in [RememberSurface::RECORD_ONLY, lifecycle] {
            for action in [
                RememberAction::Record,
                RememberAction::Assert,
                RememberAction::Forget,
            ] {
                assert!(authorize_surface(surface, action).is_ok());
            }
        }
        assert_eq!(RememberSurface::default(), RememberSurface::RECORD_ONLY);
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
