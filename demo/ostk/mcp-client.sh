#!/bin/sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=demo/ostk/lib.sh
. "$script_dir/lib.sh"

case "${1:-}" in
    recall|remember) tool_name=$1 ;;
    *)
        printf 'usage: %s recall|remember < arguments.json\n' "$0" >&2
        exit 64
        ;;
esac
[ "$#" -eq 1 ] || ostk_demo_usage_error 'the MCP client accepts exactly one tool name'

ostk_demo_require_command docker
ostk_demo_require_command jq

agent=${OSTK_AGENT:-}
[ -n "$agent" ] || \
    ostk_demo_usage_error 'OSTK_AGENT is required; the MCP bridge never accepts agent identity as an argument'
ostk_demo_validate_token "$agent" OSTK_AGENT

arguments=$(jq -ce 'if type == "object" then . else error("MCP arguments must be an object") end') || \
    ostk_demo_usage_error 'stdin must contain one JSON object'

compose_project=${OSTK_DEMO_COMPOSE_PROJECT:-ostk-fleet-recall-local}
ostk_demo_validate_token "$compose_project" OSTK_DEMO_COMPOSE_PROJECT
app_container=$(docker ps \
    --filter "label=com.docker.compose.project=$compose_project" \
    --filter label=com.docker.compose.service=app \
    --filter status=running \
    --format '{{.ID}}')
case "$app_container" in
    '') ostk_demo_die 'the LocalStack Fleet Recall app container is not running' ;;
    *"
"*) ostk_demo_die 'more than one LocalStack Fleet Recall app container is running' ;;
esac

rpc_output=$(
    {
        jq -cn --arg client "$agent" '{
            jsonrpc: "2.0",
            id: 1,
            method: "initialize",
            params: {
                protocolVersion: "2025-06-18",
                capabilities: {},
                clientInfo: {name: $client, version: "ostk-bridge-1"}
            }
        }'
        jq -cn '{
            jsonrpc: "2.0",
            method: "notifications/initialized",
            params: {}
        }'
        jq -cn --arg tool "$tool_name" --argjson arguments "$arguments" '{
            jsonrpc: "2.0",
            id: 2,
            method: "tools/call",
            params: {name: $tool, arguments: $arguments}
        }'
    } | docker exec --interactive \
        --env "FLEET_RECALL_AGENT=$agent" \
        "$app_container" \
        /bin/sh /localstack/app-entrypoint.sh serve
)

printf '%s\n' "$rpc_output" | jq -s -e '
    ([.[] | select(.id == 2)][0]) as $response |
    if $response == null then
        error("MCP server returned no tools/call response")
    elif $response.error != null then
        error("MCP tools/call failed: code=\($response.error.code)")
    elif ($response.result.structuredContent | type) != "object" then
        error("MCP tools/call returned no structuredContent object")
    else
        $response.result.structuredContent
    end
'
