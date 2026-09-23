#!/bin/sh
set -eu

# Bring up the LocalStack emulation of the AWS topology (S3 model delivery,
# Secrets Manager, and separate migrator, writer, and publication database
# identities), check the public demo, and run the three-agent fleet scenario.
# The stack is torn down on exit unless KEEP_LOCALSTACK=1.
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH='' cd -- "$script_dir/../.." && pwd)
compose_file=$script_dir/compose.yaml
model_bundle=${FLEET_RECALL_MODEL_BUNDLE:-${1:-}}
demo_port=${FLEET_RECALL_DEMO_PORT:-8088}
localstack_port=${LOCALSTACK_PORT:-4566}

fail() {
    echo "LocalStack smoke failed: $*" >&2
    exit 1
}

# Accept the name the project originally used without asking callers to expose
# it in their shell history a second time. If neither name is exported, inspect
# only exact token assignments in the repository .env: never source/eval it.
# Disable inherited xtrace before any secret value is assigned.
case "$-" in
    *x*) set +x ;;
esac
if [ -z "${LOCALSTACK_AUTH_TOKEN:-}" ] && [ -n "${LOCAL_STACK_API_KEY:-}" ]; then
    LOCALSTACK_AUTH_TOKEN=$LOCAL_STACK_API_KEY
fi
if [ -z "${LOCALSTACK_AUTH_TOKEN:-}" ] && [ -f "$repo_dir/.env" ]; then
    env_auth_token=
    env_api_key=
    carriage_return=$(printf '\r')
    while IFS= read -r env_line || [ -n "$env_line" ]; do
        env_line=${env_line%"$carriage_return"}
        env_name=
        env_value=
        case "$env_line" in
            LOCALSTACK_AUTH_TOKEN=*)
                env_name=auth
                env_value=${env_line#LOCALSTACK_AUTH_TOKEN=}
                ;;
            'export LOCALSTACK_AUTH_TOKEN='*)
                env_name=auth
                env_value=${env_line#export LOCALSTACK_AUTH_TOKEN=}
                ;;
            LOCAL_STACK_API_KEY=*)
                env_name='alias'
                env_value=${env_line#LOCAL_STACK_API_KEY=}
                ;;
            'export LOCAL_STACK_API_KEY='*)
                env_name='alias'
                env_value=${env_line#export LOCAL_STACK_API_KEY=}
                ;;
        esac
        case "$env_value" in
            \"*\")
                env_value=${env_value#\"}
                env_value=${env_value%\"}
                ;;
            \'*\')
                env_value=${env_value#\'}
                env_value=${env_value%\'}
                ;;
        esac
        if [ "$env_name" = auth ] && [ -n "$env_value" ]; then
            env_auth_token=$env_value
        elif [ "$env_name" = alias ] && [ -n "$env_value" ]; then
            env_api_key=$env_value
        fi
    done <"$repo_dir/.env"
    if [ -n "$env_auth_token" ]; then
        LOCALSTACK_AUTH_TOKEN=$env_auth_token
    elif [ -n "$env_api_key" ]; then
        LOCALSTACK_AUTH_TOKEN=$env_api_key
    fi
    unset env_auth_token env_api_key env_line env_name env_value carriage_return
fi
export LOCALSTACK_AUTH_TOKEN

compose() {
    # Prevent Compose from independently loading the repository .env. Every
    # value used by this script is passed through the explicit environment.
    docker compose --env-file /dev/null --file "$compose_file" "$@"
}

for command_name in curl docker git jq; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "required command not found: $command_name" >&2
        exit 69
    fi
done

if [ -z "${LOCALSTACK_AUTH_TOKEN:-}" ]; then
    echo "LOCALSTACK_AUTH_TOKEN is required by current LocalStack images" >&2
    exit 64
fi
if [ -z "$model_bundle" ]; then
    echo "usage: FLEET_RECALL_MODEL_BUNDLE=/absolute/model/path $0" >&2
    exit 64
fi
case "$model_bundle" in
    /*) ;;
    *)
        echo "FLEET_RECALL_MODEL_BUNDLE must be an absolute path" >&2
        exit 64
        ;;
esac
for name in config.json model.safetensors tokenizer.json; do
    if [ ! -f "$model_bundle/$name" ] || [ -L "$model_bundle/$name" ]; then
        echo "model entry must be a regular non-symlink file: $name" >&2
        exit 65
    fi
done

if ! docker info >/dev/null 2>&1; then
    echo "Docker daemon is unavailable" >&2
    exit 69
fi

vcs_ref=${FLEET_RECALL_VCS_REF:-$(git -C "$repo_dir" rev-parse HEAD)}

export FLEET_RECALL_MODEL_BUNDLE="$model_bundle"
export FLEET_RECALL_DEMO_PORT="$demo_port"
export FLEET_RECALL_VCS_REF="$vcs_ref"
export LOCALSTACK_PORT="$localstack_port"
# Compose requires this interpolation even for an early-failure `down`. No
# service starts before the production image computes and replaces the sentinel.
export FLEET_RECALL_EMBEDDING_MODEL_SHA256=not-computed-for-cleanup

cleanup_on_exit() {
    exit_status=$?
    trap - EXIT HUP INT TERM
    if [ "${KEEP_LOCALSTACK:-0}" != 1 ]; then
        if ! compose down --volumes --remove-orphans >/dev/null 2>&1; then
            echo "LocalStack teardown failed; inspect it with docker compose ps" >&2
            [ "$exit_status" -ne 0 ] || exit_status=1
        fi
    fi
    exit "$exit_status"
}

if ! existing_project_containers=$(compose ps --all --quiet); then
    fail "the LocalStack Compose project could not be inspected"
fi
if [ -n "$existing_project_containers" ]; then
    fail "the LocalStack Compose project already has containers; tear it down first"
fi
unset existing_project_containers

trap cleanup_on_exit EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

docker build --quiet --target production \
    --build-arg "VCS_REF=$vcs_ref" \
    --tag ostk-fleet-recall:localstack-production "$repo_dir" >/dev/null
docker build --quiet --target localstack \
    --build-arg "VCS_REF=$vcs_ref" \
    --tag ostk-fleet-recall:localstack-private "$repo_dir" >/dev/null

embedding_digest=$(docker run --rm \
    --user "$(id -u):$(id -g)" \
    --volume "$model_bundle:/model:ro" \
    --entrypoint /usr/local/bin/ostk-fleet-recall \
    ostk-fleet-recall:localstack-production model-digest /model)
printf '%s\n' "$embedding_digest" | grep -Eqx '[0-9a-f]{64}' || \
    fail "production image returned a noncanonical model digest"
export FLEET_RECALL_EMBEDDING_MODEL_SHA256="$embedding_digest"

if ! compose up --detach --wait app >/dev/null; then
    echo "LocalStack stack failed to become ready; recent logs follow" >&2
    compose logs --no-color --tail 200 \
        localstack cockroach database-bootstrap migrate database-boundary \
        ingest writer publication-secret app >&2 || true
    exit 1
fi

health=$(curl --fail --silent --show-error \
    "http://127.0.0.1:$demo_port/healthz")
printf '%s' "$health" | jq -e '.status == "ready"' >/dev/null || \
    fail "the public demo is not ready"

status=$(curl --fail --silent --show-error \
    "http://127.0.0.1:$demo_port/api/status")
printf '%s' "$status" | jq -e '
    .data.database.vector_index_enabled == true and
    .data.database.conflict_membership_index_enabled == true
' >/dev/null || fail "the public demo does not report its CockroachDB indexes"

recall_url="http://127.0.0.1:$demo_port/api/recall"
curl --fail --silent --show-error \
    --header 'content-type: application/json' \
    --data '{"query":"durable shared semantic memory across restarts","limit":5}' \
    "$recall_url" | jq -e '.data.hits | length >= 1' >/dev/null || \
    fail "the public demo did not recall the seeded corpus"

# Three agents record, recall, act, conflict, and escalate over MCP stdio in the
# private writer container; the public demo must then recall Agent A's claim.
fleet_scenario=$("$script_dir/fleet-demo.sh" --json)
fleet_claim_id=$(printf '%s' "$fleet_scenario" | jq -er '.agent_a.claim_id')
curl --fail --silent --show-error \
    --header 'content-type: application/json' \
    --data '{"query":"How should workers coordinate database schema changes?","limit":10}' \
    "$recall_url" | jq -e --argjson claim_id "$fleet_claim_id" \
    'any(.data.hits[]; .extra.claim_id == $claim_id)' >/dev/null || \
    fail "the public demo did not recall the fleet scenario claim"

printf '%s\n' 'LocalStack smoke passed.'
if [ "${KEEP_LOCALSTACK:-0}" = 1 ]; then
    printf 'The stack remains up; the demo is at http://127.0.0.1:%s.\n' "$demo_port"
fi
