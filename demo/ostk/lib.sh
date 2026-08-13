#!/bin/sh

# Shared, side-effect-free helpers for the opt-in OSTK/LocalStack demo.

ostk_demo_die() {
    printf 'ostk-fleet-recall demo: %s\n' "$*" >&2
    exit 1
}

ostk_demo_usage_error() {
    printf 'ostk-fleet-recall demo: %s\n' "$*" >&2
    exit 64
}

ostk_demo_require_command() {
    command -v "$1" >/dev/null 2>&1 || \
        ostk_demo_die "required command not found: $1"
}

ostk_demo_validate_token() {
    token_value=$1
    token_label=$2
    case "$token_value" in
        ''|*[!A-Za-z0-9._-]*)
            ostk_demo_usage_error "$token_label may contain only letters, digits, dot, underscore, and hyphen"
            ;;
    esac
    if [ "${#token_value}" -gt 80 ]; then
        ostk_demo_usage_error "$token_label must be at most 80 characters"
    fi
}

ostk_demo_validate_run_id() {
    run_id_value=$1
    case "$run_id_value" in
        ''|*[!A-Za-z0-9_-]*)
            ostk_demo_usage_error 'run ID may contain only letters, digits, underscore, and hyphen'
            ;;
    esac
    if [ "${#run_id_value}" -gt 48 ]; then
        ostk_demo_usage_error 'run ID must be at most 48 characters'
    fi
}

ostk_demo_repo_root() {
    helper_dir=$(CDPATH='' cd -- "$(dirname -- "$1")" && pwd)
    CDPATH='' cd -- "$helper_dir/../.." && pwd -P
}

ostk_demo_state_root() {
    repo_root=$1
    printf '%s/target/ostk-demo\n' "${repo_root%/}"
}

ostk_demo_run_dir() {
    repo_root=$1
    run_id=$2
    ostk_demo_validate_run_id "$run_id"
    state_root=$(ostk_demo_state_root "$repo_root")
    for checked_path in "$repo_root/target" "$state_root" "$state_root/$run_id"; do
        [ ! -L "$checked_path" ] || \
            ostk_demo_die "refusing symlink in repo-local state path: $checked_path"
    done
    printf '%s/%s\n' "${state_root%/}" "$run_id"
}

ostk_demo_agent_name() {
    role=$1
    run_id=$2
    printf 'ostk-recall-%s-%s\n' "$role" "$run_id"
}

ostk_demo_require_agent_role() {
    expected_role=$1
    run_id=$2
    expected_agent=$(ostk_demo_agent_name "$expected_role" "$run_id")
    actual_agent=${OSTK_AGENT:-}
    [ -n "$actual_agent" ] || \
        ostk_demo_usage_error 'OSTK_AGENT is required; invoke this helper from an OSTK agent session'
    ostk_demo_validate_token "$actual_agent" OSTK_AGENT
    [ "$actual_agent" = "$expected_agent" ] || \
        ostk_demo_die "step requires OSTK agent $expected_agent (received $actual_agent)"
    printf '%s\n' "$actual_agent"
}

ostk_demo_write_json() {
    destination=$1
    json_value=$2
    destination_dir=$(dirname -- "$destination")
    mkdir -p "$destination_dir"
    temporary=$(mktemp "$destination_dir/.evidence.XXXXXX") || \
        ostk_demo_die "could not create evidence file in $destination_dir"
    if ! printf '%s\n' "$json_value" | jq -e . >"$temporary"; then
        rm -f "$temporary"
        ostk_demo_die 'refusing to persist invalid JSON evidence'
    fi
    chmod 600 "$temporary"
    mv -f "$temporary" "$destination"
}

ostk_demo_aws_endpoint() {
    endpoint=${OSTK_DEMO_AWS_ENDPOINT_URL:-http://127.0.0.1:${LOCALSTACK_PORT:-4566}}
    case "$endpoint" in
        http://127.0.0.1:*) port=${endpoint#http://127.0.0.1:} ;;
        http://localhost:*) port=${endpoint#http://localhost:} ;;
        *)
            ostk_demo_usage_error 'OSTK_DEMO_AWS_ENDPOINT_URL must be a loopback HTTP LocalStack endpoint'
            ;;
    esac
    case "$port" in
        ''|*[!0-9]*)
            ostk_demo_usage_error 'OSTK_DEMO_AWS_ENDPOINT_URL must contain only a numeric loopback port'
            ;;
    esac
    [ "${#port}" -le 5 ] || \
        ostk_demo_usage_error 'OSTK_DEMO_AWS_ENDPOINT_URL port must be between 1 and 65535'
    if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        ostk_demo_usage_error 'OSTK_DEMO_AWS_ENDPOINT_URL port must be between 1 and 65535'
    fi
    printf '%s\n' "$endpoint"
}

ostk_demo_aws() {
    endpoint=$(ostk_demo_aws_endpoint)
    aws_binary=${OSTK_DEMO_AWS_BIN:-aws}
    AWS_ACCESS_KEY_ID=test \
    AWS_SECRET_ACCESS_KEY=test \
    AWS_SESSION_TOKEN='' \
    AWS_DEFAULT_REGION=us-east-1 \
    AWS_REGION=us-east-1 \
    AWS_EC2_METADATA_DISABLED=true \
    AWS_PAGER='' \
        "$aws_binary" --endpoint-url "$endpoint" --region us-east-1 "$@"
}

ostk_demo_timestamp() {
    date -u +%Y-%m-%dT%H:%M:%SZ
}
