#!/bin/sh
set -eu

output_json=0
case "${1:-}" in
    '') ;;
    --json) output_json=1 ;;
    *)
        echo "usage: $0 [--json]" >&2
        exit 64
        ;;
esac

for command_name in docker jq; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "required command not found: $command_name" >&2
        exit 69
    fi
done

# Discover the one healthy demo container without evaluating Compose's secret
# and model interpolations again. `smoke.sh` creates this fixed project name.
app_container=$(docker ps \
    --filter label=com.docker.compose.project=ostk-fleet-recall-local \
    --filter label=com.docker.compose.service=app \
    --filter status=running \
    --format '{{.ID}}')
case "$app_container" in
    '')
        echo "the LocalStack Fleet Recall app is not running; start it with smoke.sh and KEEP_LOCALSTACK=1" >&2
        exit 69
        ;;
    *"
"*)
        echo "more than one LocalStack Fleet Recall app container is running" >&2
        exit 69
        ;;
esac

run_id=${FLEET_RECALL_SCENARIO_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$$}
case "$run_id" in
    ''|*[!A-Za-z0-9._:-]*)
        echo "FLEET_RECALL_SCENARIO_ID may contain only letters, digits, dot, underscore, colon, and hyphen" >&2
        exit 64
        ;;
esac

run_agent() {
    agent=$1
    docker exec --interactive \
        --env "FLEET_RECALL_AGENT=$agent" \
        "$app_container" \
        /bin/sh /localstack/app-entrypoint.sh serve
}

initialize_request() {
    client_name=$1
    jq -cn --arg client "$client_name" '{
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
            protocolVersion: "2025-06-18",
            capabilities: {},
            clientInfo: {name: $client, version: "1.0.0"}
        }
    }'
    jq -cn '{
        jsonrpc: "2.0",
        method: "notifications/initialized",
        params: {}
    }'
}

as_array() {
    jq -s '.'
}

agent_a_output=$(
    {
        initialize_request fleet-demo-agent-a
        jq -cn --arg run "$run_id" '{
            jsonrpc: "2.0",
            id: 2,
            method: "tools/call",
            params: {
                name: "remember",
                arguments: {
                    action: "record",
                    scope: {agent: "agent-a", session_id: "architecture"},
                    idempotency_key: ("fleet-demo/" + $run + "/migration-decision"),
                    kind: "decision",
                    text: "Fleet schema migration runs through one dedicated migrator before serving traffic.",
                    subject: ("fleet deployment " + $run),
                    predicate: "migration strategy",
                    value: "single dedicated migrator",
                    actor: "agent-a"
                }
            }
        }'
        jq -cn --arg run "$run_id" '{
            jsonrpc: "2.0",
            id: 3,
            method: "tools/call",
            params: {
                name: "remember",
                arguments: {
                    action: "record",
                    scope: {agent: "agent-a", session_id: "architecture"},
                    idempotency_key: ("fleet-demo/" + $run + "/migration-decision"),
                    kind: "decision",
                    text: "Fleet schema migration runs through one dedicated migrator before serving traffic.",
                    subject: ("fleet deployment " + $run),
                    predicate: "migration strategy",
                    value: "single dedicated migrator",
                    actor: "agent-a"
                }
            }
        }'
    } | run_agent agent-a
)
agent_a_responses=$(printf '%s\n' "$agent_a_output" | as_array)
claim_a_id=$(printf '%s' "$agent_a_responses" | jq -er '
    ([.[] | select(.id == 2)][0].result.structuredContent) as $record |
    ([.[] | select(.id == 3)][0].result.structuredContent) as $replay |
    if $record.data.receipt.committed == true and
       $record.data.receipt.idempotent_replay == false and
       $replay.data.receipt.committed == true and
       $replay.data.receipt.idempotent_replay == true and
       $record.data.claim.id == $replay.data.claim.id
    then $record.data.claim.id
    else error("Agent A mutation/replay invariant failed")
    end')

agent_b_output=$(
    {
        initialize_request fleet-demo-agent-b
        jq -cn '{
            jsonrpc: "2.0",
            id: 2,
            method: "tools/call",
            params: {
                name: "recall",
                arguments: {
                    action: "search",
                    scope: {agent: "agent-b", session_id: "review"},
                    query: "How should workers coordinate database schema changes?",
                    kind: "chunk",
                    limit: 10
                }
            }
        }'
        jq -cn '{
            jsonrpc: "2.0",
            id: 3,
            method: "tools/call",
            params: {
                name: "recall",
                arguments: {
                    action: "search",
                    scope: {project: "another-project", agent: "agent-b"},
                    query: "attempted scope escape",
                    limit: 1
                }
            }
        }'
    } | run_agent agent-b
)
agent_b_responses=$(printf '%s\n' "$agent_b_output" | as_array)
printf '%s' "$agent_b_responses" | jq -e --argjson claim_id "$claim_a_id" '
    ([.[] | select(.id == 2)][0].result.structuredContent) as $recall |
    ([.[] | select(.id == 3)][0]) as $escape |
    $recall.diagnostics.retrieval.lanes == ["lexical", "dense"] and
    $recall.diagnostics.retrieval.fusion == "rrf" and
    any($recall.data.hits[]; .extra.claim_id == $claim_id) and
    $escape.error.code == -32602
' >/dev/null

agent_b_action_output=$(
    {
        initialize_request fleet-demo-agent-b-action
        jq -cn --arg run "$run_id" --argjson based_on_claim_id "$claim_a_id" '{
            jsonrpc: "2.0",
            id: 2,
            method: "tools/call",
            params: {
                name: "remember",
                arguments: {
                    action: "record",
                    scope: {agent: "agent-b", session_id: "review"},
                    idempotency_key: ("fleet-demo/" + $run + "/recalled-action"),
                    kind: "procedure",
                    text: "Agent B will hold application workers until the dedicated schema migrator completes.",
                    subject: ("fleet deployment " + $run),
                    predicate: "rollout action",
                    value: {
                        action: "hold workers until migration completes",
                        based_on_claim_id: $based_on_claim_id
                    },
                    actor: "agent-b"
                }
            }
        }'
    } | run_agent agent-b
)
agent_b_action_responses=$(printf '%s\n' "$agent_b_action_output" | as_array)
agent_b_action_id=$(printf '%s' "$agent_b_action_responses" | jq -er \
    --argjson based_on_claim_id "$claim_a_id" '
    ([.[] | select(.id == 2)][0].result.structuredContent) as $mutation |
    if $mutation.data.receipt.committed == true and
       $mutation.data.claim.state == "active" and
       $mutation.data.claim.actor == "agent-b" and
       $mutation.data.claim.value.action == "hold workers until migration completes" and
       $mutation.data.claim.value.based_on_claim_id == $based_on_claim_id
    then $mutation.data.claim.id
    else error("Agent B did not persist the execution plan selected after recall")
    end')

agent_c_output=$(
    {
        initialize_request fleet-demo-agent-c
        jq -cn --arg run "$run_id" '{
            jsonrpc: "2.0",
            id: 2,
            method: "tools/call",
            params: {
                name: "remember",
                arguments: {
                    action: "record",
                    scope: {agent: "agent-c", session_id: "implementation"},
                    idempotency_key: ("fleet-demo/" + $run + "/conflicting-decision"),
                    kind: "decision",
                    text: "Every worker should run schema migration independently when it starts.",
                    subject: ("fleet deployment " + $run),
                    predicate: "migration strategy",
                    value: "every worker migrates independently",
                    actor: "agent-c"
                }
            }
        }'
    } | run_agent agent-c
)
agent_c_responses=$(printf '%s\n' "$agent_c_output" | as_array)
claim_c_id=$(printf '%s' "$agent_c_responses" | jq -er --argjson claim_a_id "$claim_a_id" '
    ([.[] | select(.id == 2)][0].result.structuredContent) as $mutation |
    ([$mutation.conflicts[] |
        select(.member_count == 2) |
        select(.members_truncated == false) |
        select((.members | length) == 2) |
        select(any(.members[]; .id == $claim_a_id and .state == "disputed")) |
        select(any(.members[]; .id == $mutation.data.claim.id and .state == "disputed"))
    ][0]) as $conflict |
    if $mutation.data.claim.state == "disputed" and $conflict != null
    then $mutation.data.claim.id
    else error("Agent C conflict transition was not surfaced")
    end')

conflict_output=$(
    {
        initialize_request fleet-demo-agent-b-conflicts
        jq -cn '{
            jsonrpc: "2.0",
            id: 2,
            method: "tools/call",
            params: {
                name: "recall",
                arguments: {
                    action: "conflicts",
                    scope: {agent: "agent-b", session_id: "review"},
                    limit: 10,
                    include_resolved: false
                }
            }
        }'
    } | run_agent agent-b
)
conflict_responses=$(printf '%s\n' "$conflict_output" | as_array)
conflict_id=$(printf '%s' "$conflict_responses" | jq -er \
    --argjson claim_a_id "$claim_a_id" --argjson claim_c_id "$claim_c_id" '
    ([.[] | select(.id == 2)][0].result.structuredContent) as $result |
    [$result.conflicts[] |
        select(.state == "open") |
        select(.member_count == 2) |
        select(.members_truncated == false) |
        select((.members | length) == 2) |
        select(any(.members[]; .id == $claim_a_id and .state == "disputed")) |
        select(any(.members[]; .id == $claim_c_id and .state == "disputed"))
    ][0].id')

agent_b_escalation_output=$(
    {
        initialize_request fleet-demo-agent-b-escalation
        jq -cn --arg run "$run_id" --argjson conflict_id "$conflict_id" '{
            jsonrpc: "2.0",
            id: 2,
            method: "tools/call",
            params: {
                name: "remember",
                arguments: {
                    action: "record",
                    scope: {agent: "agent-b", session_id: "review"},
                    idempotency_key: ("fleet-demo/" + $run + "/conflict-escalation"),
                    kind: "open_question",
                    text: "Agent B paused rollout and escalated the incompatible migration strategies for operator review.",
                    subject: ("fleet deployment " + $run),
                    predicate: "escalation status",
                    value: {
                        action: "pause rollout",
                        conflict_id: $conflict_id,
                        next_step: "operator review"
                    },
                    actor: "agent-b"
                }
            }
        }'
    } | run_agent agent-b
)
agent_b_escalation_responses=$(printf '%s\n' "$agent_b_escalation_output" | as_array)
agent_b_escalation_id=$(printf '%s' "$agent_b_escalation_responses" | jq -er \
    --argjson conflict_id "$conflict_id" '
    ([.[] | select(.id == 2)][0].result.structuredContent) as $mutation |
    if $mutation.data.receipt.committed == true and
       $mutation.data.claim.state == "active" and
       $mutation.data.claim.actor == "agent-b" and
       $mutation.data.claim.value.action == "pause rollout" and
       $mutation.data.claim.value.conflict_id == $conflict_id
    then $mutation.data.claim.id
    else error("Agent B did not persist the conflict-driven escalation")
    end')

summary=$(jq -cn \
    --arg run_id "$run_id" \
    --argjson claim_a_id "$claim_a_id" \
    --argjson agent_b_action_id "$agent_b_action_id" \
    --argjson agent_b_escalation_id "$agent_b_escalation_id" \
    --argjson claim_c_id "$claim_c_id" \
    --argjson conflict_id "$conflict_id" \
    '{
        scenario: $run_id,
        agent_a: {
            claim_id: $claim_a_id,
            committed: true,
            replay_deduplicated: true
        },
        agent_b: {
            recalled_claim_id: $claim_a_id,
            retrieval_lanes: ["lexical", "dense"],
            fusion: "rrf",
            cross_project_request_rejected: true,
            action_claim_id: $agent_b_action_id,
            action: "hold workers until migration completes",
            action_based_on_claim_id: $claim_a_id,
            escalation_claim_id: $agent_b_escalation_id,
            escalation: "pause rollout for operator review",
            escalation_conflict_id: $conflict_id
        },
        agent_c: {
            claim_id: $claim_c_id,
            incompatible_value_recorded: true
        },
        conflict: {
            id: $conflict_id,
            state: "open",
            member_claim_ids: [$claim_a_id, $claim_c_id]
        }
    }')

if [ "$output_json" -eq 1 ]; then
    printf '%s\n' "$summary"
else
    printf '%s\n' 'OSTK Fleet Recall — three-agent CockroachDB scenario'
    printf '  Agent A recorded claim %s; identical replay returned the same durable receipt.\n' "$claim_a_id"
    printf '  Agent B found claim %s through lexical+dense RRF, then recorded execution plan %s.\n' "$claim_a_id" "$agent_b_action_id"
    printf '%s\n' '  Cross-project injection was rejected.'
    printf '  Agent C recorded incompatible claim %s.\n' "$claim_c_id"
    printf '  Open conflict %s contains both claims and remains queryable by the fleet.\n' "$conflict_id"
    printf '  Agent B paused rollout and persisted escalation %s for operator review.\n' "$agent_b_escalation_id"
fi
