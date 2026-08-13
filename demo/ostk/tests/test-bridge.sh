#!/bin/sh
set -eu

test_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$test_dir/../../.." && pwd)
temporary=$(mktemp -d "${TMPDIR:-/tmp}/ostk-bridge-test.XXXXXX")
run_id=unit-flow-$$
state_path=$repo_root/target/ostk-demo/$run_id
cleanup() {
    rm -f \
        "$state_path/a-record.json" \
        "$state_path/b-action.json" \
        "$state_path/c-conflict.json" \
        "$state_path/b-pause.json" \
        "$state_path/final.json"
    rmdir "$state_path" 2>/dev/null || true
    rm -rf "$temporary"
}
trap cleanup EXIT HUP INT TERM
mkdir -p "$temporary/bin" "$temporary/s3"

cat >"$temporary/fake-mcp" <<'FAKE_MCP'
#!/bin/sh
set -eu
tool=$1
payload=$(cat)
agent=$OSTK_AGENT
action=$(printf '%s\n' "$payload" | jq -r '.action')
case "$tool:$action" in
    remember:record)
        value=$(printf '%s\n' "$payload" | jq -r '.value')
        case "$value" in
            'single dedicated migrator')
                jq -cn --arg agent "$agent" '{
                    data: {
                        receipt: {committed: true},
                        claim: {id: 101, actor: $agent, state: "active", value: "single dedicated migrator"}
                    },
                    conflicts: [],
                    diagnostics: {}
                }'
                ;;
            'every worker migrates independently')
                jq -cn --arg agent "$agent" '{
                    data: {
                        receipt: {committed: true},
                        claim: {id: 202, actor: $agent, state: "disputed", value: "every worker migrates independently"}
                    },
                    conflicts: [{
                        id: 303,
                        state: "open",
                        member_count: 2,
                        members_truncated: false,
                        members: [
                            {id: 101, state: "disputed"},
                            {id: 202, state: "disputed"}
                        ]
                    }],
                    diagnostics: {}
                }'
                ;;
            *) exit 3 ;;
        esac
        ;;
    recall:search)
        jq -cn '{
            data: {hits: [{extra: {claim_id: 101}}]},
            conflicts: [],
            diagnostics: {retrieval: {lanes: ["lexical", "dense"], fusion: "rrf"}}
        }'
        ;;
    recall:conflicts)
        jq -cn '{
            data: {},
            conflicts: [{
                id: 303,
                state: "open",
                member_count: 2,
                members_truncated: false,
                members: [
                    {id: 101, state: "disputed"},
                    {id: 202, state: "disputed"}
                ]
            }],
            diagnostics: {}
        }'
        ;;
    *) exit 4 ;;
esac
FAKE_MCP
chmod 700 "$temporary/fake-mcp"

cat >"$temporary/bin/aws" <<'FAKE_AWS'
#!/bin/sh
set -eu
while [ "$#" -gt 0 ]; do
    case "$1" in
        --endpoint-url|--region) shift 2 ;;
        *) break ;;
    esac
done
service=$1
operation=$2
shift 2
bucket=
key=
body=
destination=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --bucket) bucket=$2; shift 2 ;;
        --key) key=$2; shift 2 ;;
        --body) body=$2; shift 2 ;;
        --content-type) shift 2 ;;
        --*) shift ;;
        *) destination=$1; shift ;;
    esac
done
[ "$service" = s3api ]
case "$operation" in
    put-object)
        target="$FAKE_S3_ROOT/$bucket/$key"
        mkdir -p "$(dirname -- "$target")"
        cp "$body" "$target"
        printf '%s\n' '{"ETag":"fake"}'
        ;;
    get-object)
        cp "$FAKE_S3_ROOT/$bucket/$key" "$destination"
        printf '%s\n' '{"ContentType":"application/json"}'
        ;;
    head-bucket) printf '%s\n' '{}' ;;
    *) exit 5 ;;
esac
FAKE_AWS
chmod 700 "$temporary/bin/aws"

export PATH="$temporary/bin:$PATH"
export OSTK_DEMO_TESTING=1
export OSTK_DEMO_MCP_CLIENT="$temporary/fake-mcp"
export OSTK_DEMO_AWS_BIN="$temporary/bin/aws"
export FAKE_S3_ROOT="$temporary/s3"
unset OSTK_DEMO_RUN_ID OSTK_DEMO_STATE_ROOT

for unsafe_endpoint in \
    'http://127.0.0.1:4566@evil.example' \
    'http://localhost:4566/path' \
    'http://localhost:4566?query' \
    'http://localhost:0' \
    'http://localhost:65536'; do
    if OSTK_DEMO_AWS_ENDPOINT_URL=$unsafe_endpoint \
        sh -c '. "$1"; ostk_demo_aws_endpoint >/dev/null' \
        sh "$repo_root/demo/ostk/lib.sh" >/dev/null 2>&1; then
        printf '%s\n' "unsafe LocalStack endpoint was accepted: $unsafe_endpoint" >&2
        exit 1
    fi
done
OSTK_DEMO_AWS_ENDPOINT_URL=http://127.0.0.1:4566 \
    sh -c '. "$1"; ostk_demo_aws_endpoint' sh "$repo_root/demo/ostk/lib.sh" |
    grep -Fx 'http://127.0.0.1:4566' >/dev/null

OSTK_AGENT=ostk-recall-a-$run_id \
    "$repo_root/demo/ostk/bridge.sh" --run-id "$run_id" record-decision >/dev/null
OSTK_AGENT=ostk-recall-b-$run_id \
    "$repo_root/demo/ostk/bridge.sh" --run-id "$run_id" recall-and-act >/dev/null
OSTK_AGENT=ostk-recall-c-$run_id \
    "$repo_root/demo/ostk/bridge.sh" --run-id "$run_id" record-conflict >/dev/null
OSTK_AGENT=ostk-recall-b-$run_id \
    "$repo_root/demo/ostk/bridge.sh" --run-id "$run_id" recall-conflict-and-pause >/dev/null
summary=$("$repo_root/demo/ostk/verify.sh" --run-id "$run_id")

printf '%s\n' "$summary" | jq -e '
    .verified == true and
    .orchestrator.required_cli_version == "7.7.7" and
    .memory.recalled_claim_id == 101 and
    .memory.incompatible_claim_id == 202 and
    .memory.open_conflict_id == 303 and
    (.actions | length) == 2
' >/dev/null

if OSTK_AGENT=ostk-recall-b-$run_id \
    "$repo_root/demo/ostk/bridge.sh" --run-id "$run_id" record-conflict >/dev/null 2>&1; then
    printf '%s\n' 'role-confused OSTK identity was accepted' >&2
    exit 1
fi

[ -f "$state_path/final.json" ] || {
    printf '%s\n' 'explicit run ID did not resolve to repo-local state' >&2
    exit 1
}

printf '%s\n' 'bridge: daemon-like empty launcher env and repo-local evidence passed'
