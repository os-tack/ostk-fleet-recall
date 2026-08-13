#!/bin/sh
set -eu

test_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$test_dir/../../.." && pwd)
temporary=$(mktemp -d "${TMPDIR:-/tmp}/ostk-mcp-client-test.XXXXXX")
cleanup() {
    rm -rf "$temporary"
}
trap cleanup EXIT HUP INT TERM
mkdir -p "$temporary/bin"

cat >"$temporary/bin/docker" <<'FAKE_DOCKER'
#!/bin/sh
set -eu
case "$1" in
    ps)
        printf '%s\n' fake-app-container
        ;;
    exec)
        printf '%s\n' "$*" >"$FAKE_DOCKER_LOG"
        request=$(cat)
        printf '%s\n' "$request" >"$FAKE_MCP_REQUEST"
        printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"fake","version":"1"}}}'
        printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"content":[],"structuredContent":{"probe":true}}}'
        ;;
    *) exit 2 ;;
esac
FAKE_DOCKER
chmod 700 "$temporary/bin/docker"

export PATH="$temporary/bin:$PATH"
export FAKE_DOCKER_LOG="$temporary/docker.log"
export FAKE_MCP_REQUEST="$temporary/request.jsonl"
export OSTK_AGENT=ostk-recall-a-client-test

result=$(printf '%s\n' '{"action":"status"}' | "$repo_root/demo/ostk/mcp-client.sh" recall)
printf '%s\n' "$result" | jq -e '.probe == true' >/dev/null
jq -s -e '
    any(.[]; .method == "initialize" and .params.clientInfo.name == "ostk-recall-a-client-test") and
    any(.[]; .method == "tools/call" and .params.name == "recall" and .params.arguments.action == "status")
' "$temporary/request.jsonl" >/dev/null
grep -F -- '--env FLEET_RECALL_AGENT=ostk-recall-a-client-test' "$temporary/docker.log" >/dev/null

if printf '%s\n' '[]' | "$repo_root/demo/ostk/mcp-client.sh" recall >/dev/null 2>&1; then
    printf '%s\n' 'MCP client accepted non-object arguments' >&2
    exit 1
fi

printf '%s\n' 'mcp-client: fake stdio transport and identity mapping passed'
