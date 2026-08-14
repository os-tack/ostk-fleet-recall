#!/bin/sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$script_dir/../../.." && pwd)
test_root=$(mktemp -d "${TMPDIR:-/tmp}/fleet-seed-wrapper.XXXXXX")

cleanup() {
    rm -rf "$test_root"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$test_root/bin"

cat >"$test_root/bin/terraform" <<'EOF'
#!/bin/sh
cat <<'JSON'
{"region":"us-east-1","cluster":"fleet","task_definition":"fleet-seed:9","container_name":"memory","log_group":"/ecs/fleet","subnets":["subnet-a","subnet-b"],"security_groups":["sg-app"],"assign_public_ip":"DISABLED"}
JSON
EOF

cat >"$test_root/bin/aws" <<'EOF'
#!/bin/sh
case "$*" in
    *'ecs run-task'*)
        while [ "$#" -gt 0 ]; do
            if [ "$1" = "--overrides" ]; then
                shift
                printf '%s' "$1" >"$FLEET_SEED_TEST_OVERRIDES"
                break
            fi
            shift
        done
        printf '%s\n' '{"tasks":[{"taskArn":"arn:aws:ecs:us-east-1:000000000000:task/fleet/task-1"}],"failures":[]}'
        ;;
    *'ecs wait tasks-stopped'*) ;;
    *'ecs describe-tasks'*)
        printf '%s\n' '{"tasks":[{"containers":[{"name":"memory","exitCode":0,"reason":""}],"stoppedReason":"EssentialContainerExited"}]}'
        ;;
    *)
        printf 'unexpected aws invocation: %s\n' "$*" >&2
        exit 70
        ;;
esac
EOF

chmod 755 "$test_root/bin/terraform" "$test_root/bin/aws"

run_case() {
    expected=$1
    shift
    capture=$test_root/overrides.json
    : >"$capture"
    PATH="$test_root/bin:$PATH" FLEET_SEED_TEST_OVERRIDES="$capture" \
        "$repo_root/deploy/aws/run-seed.sh" "$@" >/dev/null
    jq -e --arg expected "$expected" '
        .containerOverrides == [{
            name: "memory",
            command: ["ingest", "--input", $expected]
        }]
    ' "$capture" >/dev/null
}

run_case /opt/ostk/demo/demo.ndjson
run_case /opt/ostk/demo/rich-demo.ndjson --rich-demo

if "$repo_root/deploy/aws/run-seed.sh" --unknown >/dev/null 2>&1; then
    printf '%s\n' 'seed wrapper accepted an unknown corpus selector' >&2
    exit 1
fi

printf '%s\n' 'seed wrapper corpus selection verified'
