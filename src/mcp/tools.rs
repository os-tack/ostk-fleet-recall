//! Canonical Recall-compatible MCP tool descriptions.

use serde_json::{Value, json};

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
                "include_history": { "type": "boolean", "default": false },
                "include_resolved": { "type": "boolean", "default": false },
                "intent": { "type": "string", "enum": ["symbol", "narrative", "trace", "general"], "default": "general" }
            },
            "required": ["action"],
            "additionalProperties": false,
            "allOf": [
                { "if": { "properties": { "action": { "const": "search" } } }, "then": { "required": ["query"] } },
                { "if": { "properties": { "action": { "const": "get" } } }, "then": { "required": ["id"] } }
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
        "description": "Deliberately mutate fleet memory or working focus. Writes are scoped, audited, revision-aware, and replay-safe.",
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
        assert_eq!(
            tools[1]["inputSchema"]["properties"]["action"]["enum"],
            json!(["record"])
        );
    }
}
