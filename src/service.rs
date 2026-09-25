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
    /// Spec-nonconformance episodes and every active spec's latest check
    /// (ADR 0007); served only where [`RecallSurface::discrepancies`] is.
    Discrepancies,
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
            Self::Discrepancies => "discrepancies",
        }
    }
}

/// Deliberate mutations exposed through the canonical `remember` tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RememberAction {
    Record,
    /// Event-first ingestion beside the byte-identical legacy [`Self::Record`]
    /// path (ADR 0002 D3, ADR 0005). An accepted `assert` appends
    /// `memory.claim.accepted` to the evidence ledger and writes the legacy
    /// claim projection, the conflict detector, and the receipt in one
    /// serializable transaction. It is served, and advertised, only where the
    /// writer-authority pins verified at startup
    /// ([`RememberSurface::assert`]); anywhere else it is refused before any
    /// I/O as `assert_unavailable`. `record` is unaffected either way.
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
    /// Acknowledge the current episode of a conflict (ADR 0004). Overlay
    /// metadata only: it never changes the conflict or any claim.
    Acknowledge,
    /// Dismiss a conflict as not a real disagreement, by an adjudicator that
    /// authored none of its members (ADR 0004 D5). Off unless the deployment
    /// enables adjudication.
    Dismiss,
    /// Waive a conflict's current episode until an expiry, by an adjudicator
    /// that authored none of its members (ADR 0004 D5). Off unless the
    /// deployment enables adjudication.
    Waive,
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
            Self::Acknowledge => "acknowledge",
            Self::Dismiss => "dismiss",
            Self::Waive => "waive",
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
#[allow(clippy::struct_excessive_bools)] // independent capabilities, reported as-is in recall(status)
pub struct RememberSurface {
    /// Owner lifecycle of authored claims (`retract` and `supersede`).
    pub claim_lifecycle: bool,
    /// Conflict lifecycle (`acknowledge` and concession `resolve`), served
    /// only when the startup probe found the migration-29 lifecycle log and
    /// its grants.
    pub conflict_lifecycle: bool,
    /// Adjudication (`dismiss` and `waive` by an agent that authored none of
    /// a conflict's members), served only with the conflict lifecycle and
    /// `FLEET_RECALL_CONFLICT_ADJUDICATION=enabled`.
    pub adjudication: bool,
    /// Event-first `assert` (ADR 0005), served only when the writer-authority
    /// pins verified at startup and the active package routes an assertion.
    /// Independent of the lifecycle: a writer may serve `record` and `assert`
    /// alone. Omitted from JSON when off, so every surface without it
    /// serializes exactly as before.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub assert: bool,
}

impl RememberSurface {
    pub const RECORD_ONLY: Self = Self {
        claim_lifecycle: false,
        conflict_lifecycle: false,
        adjudication: false,
        assert: false,
    };

    /// Whether any lifecycle is served: the claim lifecycle, the conflict
    /// lifecycle, or both. Gates `recall(get, kind=conflict)`, the
    /// `remember_surface` block in `recall(status)`, and the lifecycle
    /// wording of the recall tool. Adjudication alone serves nothing: it
    /// needs the conflict lifecycle beneath it.
    #[must_use]
    pub const fn lifecycle_served(self) -> bool {
        self.claim_lifecycle || self.conflict_lifecycle
    }

    /// Whether `dismiss` and `waive` are served: adjudication needs the
    /// conflict lifecycle beneath it.
    #[must_use]
    pub const fn serves_adjudication(self) -> bool {
        self.conflict_lifecycle && self.adjudication
    }

    /// Whether this surface serves `action`. `record` is always served; the
    /// remaining unlisted actions keep their own dispatch outcome.
    #[must_use]
    pub const fn allows(self, action: RememberAction) -> bool {
        match action {
            RememberAction::Record => true,
            RememberAction::Assert => self.assert,
            RememberAction::Retract | RememberAction::Supersede => self.claim_lifecycle,
            RememberAction::Acknowledge | RememberAction::Resolve => self.conflict_lifecycle,
            RememberAction::Dismiss | RememberAction::Waive => self.serves_adjudication(),
            _ => false,
        }
    }
}

/// Which optional `recall` capabilities a service instance serves.
///
/// The MCP edge advertises exactly this surface beside the
/// [`RememberSurface`] in `tools/list`. [`Self::NONE`] adds nothing, so the
/// historical recall schema stays byte-for-byte what it was.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
pub struct RecallSurface {
    /// `recall(kind=evidence)` over connector evidence, with readiness,
    /// per-source coverage and an absence verdict.
    pub evidence: bool,
    /// `recall(action=discrepancies)` over spec-nonconformance episodes and
    /// the latest spec checks.
    pub discrepancies: bool,
}

impl RecallSurface {
    pub const NONE: Self = Self {
        evidence: false,
        discrepancies: false,
    };
}

/// Refuse an action the surface does not serve, before any I/O.
///
/// An unserved `assert` is refused as `assert_unavailable`. `dismiss` and
/// `waive` on a writer that serves the conflict lifecycle but not
/// adjudication are refused as `adjudication_disabled`; every other unserved
/// lifecycle action as `lifecycle_unavailable`. Actions outside both
/// vocabularies pass through unchanged so their existing outcomes are
/// preserved.
pub fn authorize_surface(surface: RememberSurface, action: RememberAction) -> ServiceResult<()> {
    if action == RememberAction::Assert && !surface.assert {
        return Err(ServiceError::Refused(Refusal {
            code: "assert_unavailable",
            message: "remember(assert) is not served by this deployment: its writer-authority \
                      pins are not configured or did not verify at startup; \
                      recall(status).remember_assert says why when they are configured"
                .into(),
            details: serde_json::json!({ "action": action.as_str() }),
        }));
    }
    let adjudication_action = matches!(action, RememberAction::Dismiss | RememberAction::Waive);
    let lifecycle_action = adjudication_action
        || matches!(
            action,
            RememberAction::Retract
                | RememberAction::Supersede
                | RememberAction::Resolve
                | RememberAction::Acknowledge
        );
    if !lifecycle_action || surface.allows(action) {
        return Ok(());
    }
    let details = serde_json::json!({ "action": action.as_str() });
    if adjudication_action && surface.conflict_lifecycle {
        return Err(ServiceError::Refused(Refusal {
            code: "adjudication_disabled",
            message: format!(
                "remember({}) is not enabled on this deployment: conflict adjudication is off",
                action.as_str()
            ),
            details,
        }));
    }
    Err(ServiceError::Refused(Refusal {
        code: "lifecycle_unavailable",
        message: format!(
            "remember({}) is not served by this deployment",
            action.as_str()
        ),
        details,
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

    /// The optional `recall` capabilities this instance serves; see
    /// [`RecallSurface`].
    fn recall_surface(&self) -> RecallSurface {
        RecallSurface::NONE
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
        // an MCP `remember` call with `"action":"assert"` reaches the assert
        // route (or its refusal) rather than being silently coerced into
        // `record` (ADR 0002 D3).
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
    fn discrepancies_action_wire_string_round_trips() {
        let decoded: RecallAction = serde_json::from_str("\"discrepancies\"").unwrap();
        assert_eq!(decoded, RecallAction::Discrepancies);
        assert_eq!(
            serde_json::to_value(decoded).unwrap(),
            Value::String(decoded.as_str().into())
        );
    }

    #[test]
    fn authorize_surface_refuses_before_io() {
        for action in [
            RememberAction::Retract,
            RememberAction::Supersede,
            RememberAction::Resolve,
            RememberAction::Acknowledge,
            RememberAction::Dismiss,
            RememberAction::Waive,
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
            ..RememberSurface::RECORD_ONLY
        };
        assert!(authorize_surface(lifecycle, RememberAction::Retract).is_ok());
        assert!(authorize_surface(lifecycle, RememberAction::Supersede).is_ok());
        // The conflict actions need the probed conflict-lifecycle capability.
        for action in [
            RememberAction::Resolve,
            RememberAction::Acknowledge,
            RememberAction::Dismiss,
            RememberAction::Waive,
        ] {
            let Err(ServiceError::Refused(refusal)) = authorize_surface(lifecycle, action) else {
                panic!("{} needs the conflict lifecycle", action.as_str());
            };
            assert_eq!(refusal.code, "lifecycle_unavailable");
        }
        let conflicts = RememberSurface {
            conflict_lifecycle: true,
            ..lifecycle
        };
        for action in [
            RememberAction::Retract,
            RememberAction::Supersede,
            RememberAction::Resolve,
            RememberAction::Acknowledge,
        ] {
            assert!(authorize_surface(conflicts, action).is_ok());
        }
        // Adjudication is off by default: a writer serving the conflict
        // lifecycle refuses dismiss and waive as disabled, not unavailable.
        for action in [RememberAction::Dismiss, RememberAction::Waive] {
            let Err(ServiceError::Refused(refusal)) = authorize_surface(conflicts, action) else {
                panic!("{} needs adjudication enabled", action.as_str());
            };
            assert_eq!(refusal.code, "adjudication_disabled");
            assert_eq!(refusal.details["action"], action.as_str());
        }
        let adjudicating = RememberSurface {
            adjudication: true,
            ..conflicts
        };
        for action in [RememberAction::Dismiss, RememberAction::Waive] {
            assert!(authorize_surface(adjudicating, action).is_ok());
        }
        // The switch alone never serves adjudication without the lifecycle log.
        let switch_only = RememberSurface {
            adjudication: true,
            ..lifecycle
        };
        assert!(!switch_only.serves_adjudication());
        assert!(authorize_surface(switch_only, RememberAction::Dismiss).is_err());
        // Record and the actions outside both vocabularies keep their own
        // dispatch outcome.
        for surface in [
            RememberSurface::RECORD_ONLY,
            lifecycle,
            conflicts,
            adjudicating,
        ] {
            for action in [RememberAction::Record, RememberAction::Forget] {
                assert!(authorize_surface(surface, action).is_ok());
            }
        }
        assert_eq!(RememberSurface::default(), RememberSurface::RECORD_ONLY);
    }

    #[test]
    fn assert_is_refused_unless_served() {
        let claim = RememberSurface {
            claim_lifecycle: true,
            ..RememberSurface::RECORD_ONLY
        };
        let adjudicating = RememberSurface {
            conflict_lifecycle: true,
            adjudication: true,
            ..claim
        };
        // No lifecycle implies assert: every surface without it refuses.
        for surface in [RememberSurface::RECORD_ONLY, claim, adjudicating] {
            let Err(ServiceError::Refused(refusal)) =
                authorize_surface(surface, RememberAction::Assert)
            else {
                panic!("{surface:?} does not serve assert");
            };
            assert_eq!(refusal.code, "assert_unavailable");
            assert_eq!(refusal.details["action"], "assert");
        }
        // Assert is served alone or beside any lifecycle, and it serves no
        // lifecycle action by itself.
        let assert_only = RememberSurface {
            assert: true,
            ..RememberSurface::RECORD_ONLY
        };
        for surface in [
            assert_only,
            RememberSurface {
                assert: true,
                ..adjudicating
            },
        ] {
            assert!(authorize_surface(surface, RememberAction::Assert).is_ok());
            assert!(authorize_surface(surface, RememberAction::Record).is_ok());
        }
        assert!(!assert_only.lifecycle_served());
        for action in [
            RememberAction::Retract,
            RememberAction::Supersede,
            RememberAction::Resolve,
            RememberAction::Acknowledge,
            RememberAction::Dismiss,
            RememberAction::Waive,
        ] {
            let Err(ServiceError::Refused(refusal)) = authorize_surface(assert_only, action) else {
                panic!("assert alone does not serve {}", action.as_str());
            };
            assert_eq!(refusal.code, "lifecycle_unavailable");
        }
    }

    #[test]
    fn surface_json_names_assert_only_when_served() {
        let conflicts = RememberSurface {
            claim_lifecycle: true,
            conflict_lifecycle: true,
            adjudication: false,
            assert: false,
        };
        assert_eq!(
            serde_json::to_value(conflicts).unwrap(),
            serde_json::json!({
                "claim_lifecycle": true,
                "conflict_lifecycle": true,
                "adjudication": false,
            })
        );
        let asserting = RememberSurface {
            assert: true,
            ..conflicts
        };
        assert_eq!(serde_json::to_value(asserting).unwrap()["assert"], true);
    }

    #[test]
    fn lifecycle_served_matches_every_reachable_surface() {
        // Serve composes the claim lifecycle first, the probed conflict
        // lifecycle on top, and adjudication only above the conflict
        // lifecycle; on each of those surfaces "a lifecycle is served" and
        // "the surface is not record-only" agree.
        let claim = RememberSurface {
            claim_lifecycle: true,
            ..RememberSurface::RECORD_ONLY
        };
        let conflicts = RememberSurface {
            conflict_lifecycle: true,
            ..claim
        };
        let adjudicating = RememberSurface {
            adjudication: true,
            ..conflicts
        };
        for surface in [RememberSurface::RECORD_ONLY, claim, conflicts, adjudicating] {
            assert_eq!(
                surface.lifecycle_served(),
                surface != RememberSurface::RECORD_ONLY,
                "{surface:?}"
            );
        }
        // The adjudication switch without a lifecycle beneath it serves none.
        let switch_only = RememberSurface {
            adjudication: true,
            ..RememberSurface::RECORD_ONLY
        };
        assert!(!switch_only.lifecycle_served());
        assert!(!switch_only.serves_adjudication());
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
