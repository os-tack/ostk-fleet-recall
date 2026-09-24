//! Canonical Recall-compatible MCP tool descriptions.

use serde_json::{Map, Value, json};

use crate::service::RememberSurface;

/// Claim-shaped `remember` properties that a non-record action must not carry.
const CLAIM_FIELDS: [&str; 11] = [
    "kind",
    "text",
    "subject",
    "predicate",
    "value",
    "support",
    "origin",
    "polarity",
    "confidence",
    "valid_from",
    "valid_to",
];
/// Owner-lifecycle `remember` properties that `record` must not carry.
const CLAIM_LIFECYCLE_FIELDS: [&str; 3] = ["claim_id", "expected_revision", "reason"];

fn output_schema(tool: &str) -> Value {
    json!({
        "type": "object",
        "description": "Authoritative result returned in structuredContent; content text is a compact fallback.",
        "properties": {
            "schema_version": { "type": "integer", "const": 2 },
            "tool": { "type": "string", "const": tool },
            "action": { "type": "string" },
            "data": {},
            "conflicts": { "type": "array" },
            "conflict_coverage": { "type": "object" },
            "warnings": { "type": "array" },
            "diagnostics": { "type": "object" }
        },
        "required": [
            "schema_version",
            "tool",
            "action",
            "data",
            "conflicts",
            "conflict_coverage",
            "warnings",
            "diagnostics"
        ],
        "additionalProperties": false
    })
}

fn scope_schema() -> Value {
    json!({
        "type": "object",
        "description": "Optional assertions and session refinement within the deployment-bound tenant, project, agent, and privacy tier. Project, agent, and privacy tier, when present, must exactly match deployment identity. Tenant identity is never accepted here.",
        "properties": {
            "project": {
                "type": "string",
                "minLength": 1,
                "maxLength": 256,
                "description": "Optional assertion that must exactly match the deployment-bound project."
            },
            "session_id": {
                "type": "string",
                "minLength": 1,
                "maxLength": 256,
                "description": "Caller-selected session within the deployment-bound agent identity."
            },
            "agent": {
                "type": "string",
                "minLength": 1,
                "maxLength": 256,
                "description": "Optional assertion that must exactly match the deployment-bound agent."
            },
            "privacy_tier": {
                "type": "string",
                "enum": ["t0_private", "t1_project", "t2_trusted", "t3_public"],
                "description": "Optional compatibility assertion that must exactly match the deployment-bound privacy tier; privacy narrowing is not available until owner/tier visibility is enforced in the durable data plane."
            }
        },
        "additionalProperties": false
    })
}

#[must_use]
pub fn recall_tool() -> Value {
    json!({
        "name": "recall",
        "description": "Read fleet memory without changing semantic state. Search combines lexical and dense retrieval and reports conflict coverage.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["search", "get", "conflicts", "status"]
                },
                "scope": scope_schema(),
                "query": { "type": "string", "minLength": 1, "maxLength": 100_000 },
                "source": { "type": "string" },
                "limit": { "type": "integer", "default": 10, "minimum": 1, "maximum": 100 },
                "max_per_source_id": { "type": "integer", "default": 3, "minimum": 0 },
                "min_score": { "type": "number", "default": 0.0 },
                "kind": { "type": "string", "enum": ["chunk", "claim", "assertion"] },
                "id": {},
                "include_history": {
                    "type": "boolean",
                    "default": false,
                    "description": "Include inactive historical claims. Valid only for kind=claim or kind=assertion."
                },
                "include_resolved": { "type": "boolean", "default": false },
                "intent": { "type": "string", "enum": ["symbol", "narrative", "trace", "general"], "default": "general" }
            },
            "required": ["action"],
            "additionalProperties": false,
            "allOf": [
                { "if": { "properties": { "action": { "const": "search" } } }, "then": { "required": ["query"] } },
                { "if": { "properties": { "action": { "const": "get" } } }, "then": { "required": ["id"] } },
                {
                    "if": {
                        "properties": { "include_history": { "const": true } },
                        "required": ["include_history"]
                    },
                    "then": {
                        "properties": {
                            "action": { "const": "search" },
                            "kind": { "enum": ["claim", "assertion"] }
                        },
                        "required": ["kind"]
                    }
                }
            ]
        },
        "outputSchema": output_schema("recall")
    })
}

#[must_use]
pub fn remember_tool() -> Value {
    let support_schema = json!({
        "type": "array",
        "maxItems": 32,
        "description": "Exact source evidence snapshots.",
        "items": {
            "type": "object",
            "properties": {
                "source_config_id": { "type": "string", "minLength": 1, "maxLength": 256 },
                "source": { "type": "string", "minLength": 1, "maxLength": 256 },
                "source_id": { "type": "string", "minLength": 1, "maxLength": 4096 },
                "chunk_id": { "type": "string" },
                "content_sha256": { "type": "string" },
                "excerpt": { "type": "string", "maxLength": 8000 },
                "relation": { "type": "string", "default": "supports", "maxLength": 64 }
            },
            "required": ["source_config_id", "source", "source_id"],
            "additionalProperties": false
        }
    });
    json!({
        "name": "remember",
        "description": "Deliberately record fleet memory. Writes are scoped, audited, revision-aware, and replay-safe.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["record"]
                },
                "scope": scope_schema(),
                "idempotency_key": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 256,
                    "description": "Stable tenant-wide key that permits at most one committed mutation for an identical canonical request; retry the same key when the outcome is unknown."
                },
                "kind": { "type": "string", "enum": ["observation", "note", "decision", "fact", "constraint", "preference", "procedure", "open_question"] },
                "text": { "type": "string", "minLength": 1, "maxLength": 100_000 },
                "subject": { "type": "string", "maxLength": 1024 },
                "predicate": { "type": "string", "maxLength": 1024 },
                "value": {},
                "support": support_schema,
                "origin": { "type": "string", "const": "operator_asserted", "default": "operator_asserted" },
                "actor": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 256,
                    "description": "Optional provenance assertion that must exactly match the deployment-bound trusted agent. The service derives stored actor provenance from that trusted identity."
                },
                "polarity": { "type": "integer", "enum": [-1, 1], "default": 1 },
                "confidence": { "type": "number", "minimum": 0, "maximum": 1, "default": 1 },
                "valid_from": { "type": "string", "format": "date-time" },
                "valid_to": { "type": "string", "format": "date-time" }
            },
            "required": ["action", "idempotency_key", "kind", "text"],
            "additionalProperties": false
        },
        "outputSchema": output_schema("remember")
    })
}

/// The entire agent-facing surface. Compatibility aliases are intentionally
/// absent: tool discovery is part of the cognitive footprint.
#[must_use]
pub fn tool_list() -> Vec<Value> {
    vec![recall_tool(), remember_tool()]
}

/// `recall` as served beside the given remember surface. The record-only
/// surface is exactly [`recall_tool`]; a lifecycle surface adds
/// `get` with `kind=conflict`.
#[must_use]
pub fn recall_tool_for(surface: RememberSurface) -> Value {
    let mut tool = recall_tool();
    if surface == RememberSurface::RECORD_ONLY {
        return tool;
    }
    tool["description"] = json!(
        "Read fleet memory without changing semantic state. Search combines lexical and dense retrieval and reports conflict coverage. get with kind=conflict returns one conflict by id in any state, with its members."
    );
    let schema = &mut tool["inputSchema"];
    schema["properties"]["kind"]["enum"] = json!(["chunk", "claim", "assertion", "conflict"]);
    if let Some(all_of) = schema["allOf"].as_array_mut() {
        all_of.push(json!({
            "if": {
                "properties": { "kind": { "const": "conflict" } },
                "required": ["kind"]
            },
            "then": { "properties": { "action": { "const": "get" } } }
        }));
    }
    tool
}

/// `remember` restricted to the actions the surface serves. The record-only
/// surface is exactly [`remember_tool`].
#[must_use]
pub fn remember_tool_for(surface: RememberSurface) -> Value {
    let mut tool = remember_tool();
    if !surface.claim_lifecycle {
        return tool;
    }
    tool["description"] = json!(
        "Deliberately record fleet memory or retract claims you authored. Writes are scoped, audited, revision-checked, and replay-safe. A refused write returns invalid_params with data.outcome=\"not_applied\" and does not consume the idempotency_key."
    );
    let schema = &mut tool["inputSchema"];
    schema["properties"]["action"]["enum"] = json!(["record", "retract"]);
    if let Some(properties) = schema["properties"].as_object_mut() {
        properties.insert(
            "claim_id".into(),
            json!({
                "type": "integer",
                "minimum": 1,
                "maximum": 9_007_199_254_740_991_i64,
                "description": "retract: a claim you authored (origin operator_asserted) in state active or disputed."
            }),
        );
        properties.insert(
            "expected_revision".into(),
            json!({
                "type": "integer",
                "minimum": 1,
                "maximum": 9_007_199_254_740_991_i64,
                "description": "retract: the claim revision you last read; a stale value is refused, not retried."
            }),
        );
        properties.insert(
            "reason".into(),
            json!({
                "type": "string",
                "minLength": 1,
                "maxLength": 1000,
                "description": "Optional private audit note for retract."
            }),
        );
    }
    let properties = schema["properties"]
        .as_object()
        .cloned()
        .unwrap_or_default();
    schema["required"] = json!(["action", "idempotency_key"]);
    schema["allOf"] = json!([
        {
            "if": { "properties": { "action": { "const": "record" } } },
            "then": {
                "required": ["kind", "text"],
                "properties": forbid(&properties, &CLAIM_LIFECYCLE_FIELDS)
            }
        },
        {
            "if": { "properties": { "action": { "const": "retract" } } },
            "then": {
                "required": ["claim_id", "expected_revision"],
                "properties": forbid(&properties, &CLAIM_FIELDS)
            }
        }
    ]);
    tool
}

/// The agent-facing surface for one remember surface. The record-only
/// surface is exactly [`tool_list`].
#[must_use]
pub fn tool_list_for(surface: RememberSurface) -> Vec<Value> {
    if surface == RememberSurface::RECORD_ONLY {
        return tool_list();
    }
    vec![recall_tool_for(surface), remember_tool_for(surface)]
}

/// `{name: false}` for each named property this schema actually declares.
fn forbid(properties: &Map<String, Value>, names: &[&str]) -> Value {
    Value::Object(
        names
            .iter()
            .filter(|name| properties.contains_key(**name))
            .map(|name| ((*name).to_owned(), Value::Bool(false)))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advertises_exactly_two_semantic_tools() {
        let tools = tool_list();
        let names: Vec<_> = tools
            .iter()
            .map(|tool| tool["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["recall", "remember"]);
        assert_eq!(
            tools[1]["inputSchema"]["properties"]["idempotency_key"]["type"],
            "string"
        );
        assert!(tools.iter().all(|tool| {
            tool["inputSchema"]["properties"]["scope"]["properties"]
                .get("tenant_id")
                .is_none()
        }));
        for tool in &tools {
            let privacy = &tool["inputSchema"]["properties"]["scope"]["properties"]["privacy_tier"];
            assert_eq!(
                privacy["enum"],
                json!(["t0_private", "t1_project", "t2_trusted", "t3_public"])
            );
            assert!(
                privacy["description"]
                    .as_str()
                    .is_some_and(|description| description.contains("exactly match"))
            );
        }
        let actor = &tools[1]["inputSchema"]["properties"]["actor"];
        assert_eq!(actor["type"], "string");
        assert_eq!(actor["maxLength"], 256);
        assert!(
            actor["description"]
                .as_str()
                .is_some_and(|description| description.contains("exactly match"))
        );
        assert!(tools[0]["inputSchema"]["properties"].get("actor").is_none());
        assert_eq!(
            tools[0]["inputSchema"]["properties"]["action"]["enum"],
            json!(["search", "get", "conflicts", "status"])
        );
        let history_constraint = &tools[0]["inputSchema"]["allOf"][2];
        assert_eq!(
            history_constraint["if"]["properties"]["include_history"]["const"],
            true
        );
        assert_eq!(
            history_constraint["then"]["properties"]["kind"]["enum"],
            json!(["claim", "assertion"])
        );
        assert_eq!(
            history_constraint["then"]["properties"]["action"]["const"],
            "search"
        );
        assert_eq!(history_constraint["then"]["required"], json!(["kind"]));
        assert_eq!(
            tools[1]["inputSchema"]["properties"]["action"]["enum"],
            json!(["record"])
        );
    }

    fn lifecycle_surface() -> RememberSurface {
        RememberSurface {
            claim_lifecycle: true,
        }
    }

    #[test]
    fn record_only_surface_is_byte_identical() {
        let historical = tool_list();
        let gated = tool_list_for(RememberSurface::RECORD_ONLY);
        assert_eq!(gated, historical);
        assert_eq!(
            serde_json::to_vec(&gated).unwrap(),
            serde_json::to_vec(&historical).unwrap()
        );
        assert_eq!(recall_tool_for(RememberSurface::RECORD_ONLY), recall_tool());
        assert_eq!(
            remember_tool_for(RememberSurface::RECORD_ONLY),
            remember_tool()
        );
        assert_ne!(tool_list_for(lifecycle_surface()), historical);
    }

    #[test]
    fn claim_lifecycle_surface_branches_are_exact() {
        let tool = remember_tool_for(lifecycle_surface());
        let schema = &tool["inputSchema"];
        let properties = schema["properties"].as_object().unwrap();
        assert_eq!(
            schema["properties"]["action"]["enum"],
            json!(["record", "retract"])
        );
        assert_eq!(schema["required"], json!(["action", "idempotency_key"]));
        assert_eq!(schema["additionalProperties"], false);
        for field in CLAIM_LIFECYCLE_FIELDS {
            assert!(properties.contains_key(field), "{field} is declared");
        }
        // Later-slice conflict actions are not advertised on this surface.
        for absent in ["conflict_id", "expected_member_count", "retract_claim_ids"] {
            assert!(!properties.contains_key(absent), "{absent} is not served");
        }

        let branches = schema["allOf"].as_array().unwrap();
        assert_eq!(branches.len(), 2);
        let record = &branches[0];
        assert_eq!(record["if"]["properties"]["action"]["const"], "record");
        assert_eq!(record["then"]["required"], json!(["kind", "text"]));
        assert_eq!(
            record["then"]["properties"],
            json!({ "claim_id": false, "expected_revision": false, "reason": false })
        );
        let retract = &branches[1];
        assert_eq!(retract["if"]["properties"]["action"]["const"], "retract");
        assert_eq!(
            retract["then"]["required"],
            json!(["claim_id", "expected_revision"])
        );
        let forbidden = retract["then"]["properties"].as_object().unwrap();
        assert_eq!(forbidden.len(), CLAIM_FIELDS.len());
        for field in CLAIM_FIELDS {
            assert_eq!(forbidden[field], false, "retract forbids {field}");
        }
        // The transport-only actor assertion and scope stay valid on retract.
        assert!(!forbidden.contains_key("actor"));
        assert!(!forbidden.contains_key("scope"));
        // Every branch names only declared properties.
        for branch in branches {
            for name in branch["then"]["properties"].as_object().unwrap().keys() {
                assert!(properties.contains_key(name), "{name} is undeclared");
            }
        }
    }

    #[test]
    fn recall_conflict_kind_is_get_only() {
        let tool = recall_tool_for(lifecycle_surface());
        let schema = &tool["inputSchema"];
        assert_eq!(
            schema["properties"]["kind"]["enum"],
            json!(["chunk", "claim", "assertion", "conflict"])
        );
        let branches = schema["allOf"].as_array().unwrap();
        assert_eq!(
            branches[..3],
            recall_tool()["inputSchema"]["allOf"].as_array().unwrap()[..]
        );
        let conflict = &branches[3];
        assert_eq!(conflict["if"]["properties"]["kind"]["const"], "conflict");
        assert_eq!(conflict["if"]["required"], json!(["kind"]));
        assert_eq!(conflict["then"]["properties"]["action"]["const"], "get");
        assert_eq!(
            schema["properties"]["action"]["enum"],
            recall_tool()["inputSchema"]["properties"]["action"]["enum"]
        );
    }
}
