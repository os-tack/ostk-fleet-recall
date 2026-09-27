#!/usr/bin/env bash
# Shared helpers for deploy/local/bootstrap.sh. Sourced, not executed.

log() { printf '\033[1;34m==>\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

need() {
    local missing=()
    for tool in "$@"; do
        command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
    done
    [ "${#missing[@]}" -eq 0 ] || die "missing tools: ${missing[*]}"
}

# Apply a secret or config map idempotently from a `kubectl create` command.
kube_upsert() {
    kubectl "$@" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
}

# Wait for a Job to reach succeeded or failed. Prints the logs on failure.
wait_job() {
    local ns=$1 name=$2 timeout=${3:-600} waited=0 succeeded failed
    while :; do
        succeeded=$(kubectl -n "$ns" get job "$name" -o jsonpath='{.status.succeeded}' 2>/dev/null || true)
        failed=$(kubectl -n "$ns" get job "$name" -o jsonpath='{.status.failed}' 2>/dev/null || true)
        if [ "${succeeded:-0}" -ge 1 ]; then
            return 0
        fi
        if [ "${failed:-0}" -ge 1 ]; then
            kubectl -n "$ns" logs "job/$name" --all-containers --tail=200 >&2 || true
            die "job $ns/$name failed"
        fi
        # Fail fast on conditions that never resolve on their own.
        local stuck
        stuck=$(kubectl -n "$ns" get pods -l "job-name=$name" \
            -o jsonpath='{range .items[*].status.containerStatuses[*]}{.state.waiting.reason}{"\n"}{end}' 2>/dev/null \
            | grep -E 'CreateContainerConfigError|ErrImagePull|ImagePullBackOff|ErrImageNeverPull|InvalidImageName|CrashLoopBackOff' | head -n1 || true)
        if [ -n "$stuck" ]; then
            kubectl -n "$ns" describe pods -l "job-name=$name" 2>/dev/null | grep -E 'Warning|Error|Failed' | tail -n5 >&2 || true
            die "job $ns/$name is stuck: $stuck"
        fi
        if [ "$waited" -ge "$timeout" ]; then
            kubectl -n "$ns" describe job "$name" >&2 || true
            kubectl -n "$ns" logs "job/$name" --all-containers --tail=200 >&2 || true
            die "job $ns/$name did not finish within ${timeout}s"
        fi
        sleep 3
        waited=$((waited + 3))
    done
}

# Resolve the LocalStack auth token without printing it: the environment
# first, then the repository .env under either spelling smoke.sh accepts.
resolve_localstack_token() {
    local repo=$1 token=${LOCALSTACK_AUTH_TOKEN:-}
    if [ -z "$token" ] && [ -f "$repo/.env" ]; then
        token=$(sed -n 's/^LOCALSTACK_AUTH_TOKEN=//p' "$repo/.env" | head -n1 | tr -d '"'"'")
    fi
    if [ -z "$token" ] && [ -f "$repo/.env" ]; then
        token=$(sed -n 's/^LOCAL_STACK_API_KEY=//p' "$repo/.env" | head -n1 | tr -d '"'"'")
    fi
    [ -n "$token" ] || die "no LocalStack auth token: set LOCALSTACK_AUTH_TOKEN or LOCAL_STACK_API_KEY in .env"
    printf '%s' "$token"
}

random_hex() { openssl rand -hex "${1:-24}"; }

# Read one key from a KEY=VALUE file.
env_value() { sed -n "s/^$2=//p" "$1" | head -n1; }

check() {
    local label=$1
    shift
    if "$@" >/dev/null 2>&1; then
        printf '  PASS  %s\n' "$label"
        return 0
    fi
    printf '  FAIL  %s\n' "$label"
    return 1
}
