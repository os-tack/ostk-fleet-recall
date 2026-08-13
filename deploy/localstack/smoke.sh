#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/../.." && pwd)
compose_file=$script_dir/compose.yaml
model_bundle=${FLEET_RECALL_MODEL_BUNDLE:-${1:-}}
demo_port=${FLEET_RECALL_DEMO_PORT:-8088}
localstack_port=${LOCALSTACK_PORT:-4566}

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
                env_name=alias
                env_value=${env_line#LOCAL_STACK_API_KEY=}
                ;;
            'export LOCAL_STACK_API_KEY='*)
                env_name=alias
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
    done < "$repo_dir/.env"
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
    # value used by this harness is passed through the explicit environment.
    docker compose --env-file /dev/null --file "$compose_file" "$@"
}

for command_name in aws curl docker jq; do
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

docker build --quiet --tag ostk-fleet-recall:localstack "$repo_dir" >/dev/null
docker run --rm --entrypoint /bin/sh ostk-fleet-recall:localstack -c '
    test -r /opt/ostk/demo/demo.ndjson &&
    test "$(wc -l < /opt/ostk/demo/demo.ndjson)" -eq 3
'
embedding_digest=$(docker run --rm \
    --user "$(id -u):$(id -g)" \
    --volume "$model_bundle:/model:ro" \
    --entrypoint /usr/local/bin/ostk-fleet-recall \
    ostk-fleet-recall:localstack model-digest /model)

export FLEET_RECALL_MODEL_BUNDLE=$model_bundle
export FLEET_RECALL_EMBEDDING_MODEL_SHA256=$embedding_digest
export FLEET_RECALL_DEMO_PORT=$demo_port
export LOCALSTACK_PORT=$localstack_port

cleanup() {
    if [ "${KEEP_LOCALSTACK:-0}" != "1" ]; then
        compose down --volumes --remove-orphans
    fi
}
trap cleanup EXIT HUP INT TERM

if ! compose up --detach --wait app; then
    echo "LocalStack stack failed to become ready; recent emulator/database logs follow" >&2
    compose logs --no-color --tail 200 localstack cockroach >&2 || true
    exit 1
fi

aws_args="--endpoint-url http://127.0.0.1:$localstack_port --region us-east-1"
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1

# shellcheck disable=SC2086 # aws_args is intentionally a fixed option vector.
secret_value=$(aws $aws_args secretsmanager get-secret-value \
    --secret-id ostk-fleet-recall/local/database-url \
    --query SecretString --output text)
case "$secret_value" in
    postgresql://root@cockroach:26257/*) ;;
    *)
        echo "unexpected Secrets Manager contract value" >&2
        exit 1
        ;;
esac
unset secret_value

for name in config.json model.safetensors tokenizer.json; do
    # shellcheck disable=SC2086 # aws_args is intentionally a fixed option vector.
    aws $aws_args s3api head-object \
        --bucket fleet-recall-local-models \
        --key "bundles/demo/$name" >/dev/null
done

health=$(curl --fail --silent --show-error "http://127.0.0.1:$demo_port/healthz")
printf '%s' "$health" | jq -e '.status == "ready"' >/dev/null

status=$(curl --fail --silent --show-error "http://127.0.0.1:$demo_port/api/status")
printf '%s' "$status" | jq -e '.data.database.vector_index_enabled == true' >/dev/null
printf '%s' "$status" | jq -e '.data.database.conflict_membership_index_enabled == true' >/dev/null

recall_url="http://127.0.0.1:$demo_port/api/recall"
assert_demo_recall() {
    recall_response=$(curl --fail --silent --show-error \
        --header 'content-type: application/json' \
        --data '{"query":"durable shared semantic memory across restarts","limit":5}' \
        "$recall_url")
    printf '%s' "$recall_response" | jq -e '.data.hits | length >= 1' >/dev/null
    unset recall_response
}

assert_demo_recall
fleet_scenario=$("$script_dir/fleet-demo.sh" --json)
fleet_claim_id=$(printf '%s' "$fleet_scenario" | jq -er '.agent_a.claim_id')
unset fleet_scenario

assert_fleet_claim_recall() {
    fleet_recall_response=$(curl --fail --silent --show-error \
        --header 'content-type: application/json' \
        --data '{"query":"How should workers coordinate database schema changes?","limit":10}' \
        "$recall_url")
    printf '%s' "$fleet_recall_response" | jq -e \
        --argjson claim_id "$fleet_claim_id" \
        'any(.data.hits[]; .extra.claim_id == $claim_id)' >/dev/null
    unset fleet_recall_response
}

assert_fleet_claim_recall
app_container_before=$(compose ps --quiet app)
compose up --detach --no-deps --force-recreate --wait app >/dev/null
app_container_after=$(compose ps --quiet app)
if [ -z "$app_container_before" ] || [ -z "$app_container_after" ] || \
    [ "$app_container_before" = "$app_container_after" ]; then
    echo "app container replacement was not observed" >&2
    exit 1
fi
assert_demo_recall
assert_fleet_claim_recall

printf 'LocalStack AWS contracts, migration, model delivery, three-identity recall/action/conflict flow, and recall after app replacement passed.\n'
if [ "${KEEP_LOCALSTACK:-0}" = "1" ]; then
    printf 'Demo remains at http://127.0.0.1:%s (KEEP_LOCALSTACK=1).\n' "$demo_port"
fi
