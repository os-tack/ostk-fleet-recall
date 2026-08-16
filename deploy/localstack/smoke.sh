#!/bin/sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH='' cd -- "$script_dir/../.." && pwd)
compose_file=$script_dir/compose.yaml
policy=$repo_dir/deploy/cockroach/publication-reader-role-grants.sql
expected_policy_sha256=ff3ada75aba9443875efb1f430a14829ef864b3f7409ae5d23f7bd381cb65226
model_bundle=${FLEET_RECALL_MODEL_BUNDLE:-${1:-}}
demo_port=${FLEET_RECALL_DEMO_PORT:-8088}
localstack_port=${LOCALSTACK_PORT:-4566}

fail() {
    echo "LocalStack PUBLIC-03 smoke failed: $*" >&2
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
    # value used by this harness is passed through the explicit environment.
    docker compose --env-file /dev/null --file "$compose_file" "$@"
}

for command_name in aws curl docker git jq shasum; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "required command not found: $command_name" >&2
        exit 69
    fi
done
if ! docker buildx version >/dev/null 2>&1; then
    echo "Docker Buildx is required to capture the image manifest digest" >&2
    exit 69
fi

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

head_revision=$(git -C "$repo_dir" rev-parse HEAD)
vcs_ref=${FLEET_RECALL_VCS_REF:-$head_revision}
case "$vcs_ref" in
    [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;
    *)
        echo "FLEET_RECALL_VCS_REF must be one lowercase 40-hex commit" >&2
        exit 64
        ;;
esac
if [ "$vcs_ref" != "$head_revision" ]; then
    fail "FLEET_RECALL_VCS_REF does not equal the checked-out commit"
fi
source_status=$(git -C "$repo_dir" status --porcelain --untracked-files=all)
if [ -n "$source_status" ]; then
    fail "source tree is dirty; commit the coherent candidate before producing evidence"
fi
unset source_status

if ! policy_hash_output=$(shasum -a 256 "$policy"); then
    fail "publication reader policy could not be hashed"
fi
policy_sha256=$(printf '%s\n' "$policy_hash_output" | awk '{print $1}')
if [ "$policy_sha256" != "$expected_policy_sha256" ]; then
    fail "publication reader policy differs from the reviewed digest"
fi

proof_tmp=$(mktemp -d "${TMPDIR:-/tmp}/fleet-localstack-publication.XXXXXX")
case "$proof_tmp" in
    "${TMPDIR:-/tmp}"/fleet-localstack-publication.*) ;;
    *) fail "temporary proof directory escaped its fixed prefix" ;;
esac

export FLEET_RECALL_MODEL_BUNDLE="$model_bundle"
export FLEET_RECALL_DEMO_PORT="$demo_port"
export FLEET_RECALL_VCS_REF="$vcs_ref"
export LOCALSTACK_PORT="$localstack_port"
# Compose requires this interpolation even for an early-failure `down`. No
# service starts before the production image computes and replaces the sentinel.
export FLEET_RECALL_EMBEDDING_MODEL_SHA256=not-computed-for-cleanup

cleanup_attempted=0
cleanup_succeeded=0
preserve_proof=0
cleanup_on_exit() {
    exit_status=$?
    trap - EXIT HUP INT TERM
    if [ "${KEEP_LOCALSTACK:-0}" != 1 ] &&
       [ "$cleanup_attempted" -ne 1 ]; then
        cleanup_attempted=1
        if ! compose down --volumes --remove-orphans \
            >"$proof_tmp/exit-teardown.log" 2>&1; then
            preserve_proof=1
            [ "$exit_status" -ne 0 ] || exit_status=1
            printf '%s\n' \
                'LocalStack exit cleanup failed; no verified receipt is valid.' >&2
        fi
    fi
    if [ "$preserve_proof" -eq 1 ]; then
        printf 'LocalStack cleanup evidence is preserved at %s.\n' \
            "$proof_tmp" >&2
    else
        case "$proof_tmp" in
            "${TMPDIR:-/tmp}"/fleet-localstack-publication.*)
                rm -rf -- "$proof_tmp"
                ;;
        esac
    fi
    exit "$exit_status"
}
trap cleanup_on_exit EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if [ -n "$(compose ps --all --quiet 2>/dev/null || true)" ]; then
    fail "the fixed LocalStack Compose project already has containers; tear it down before a source-bound run"
fi

production_metadata=$proof_tmp/production-metadata.json
private_metadata=$proof_tmp/private-metadata.json
docker buildx build --load --quiet --target production \
    --build-arg "VCS_REF=$vcs_ref" \
    --metadata-file "$production_metadata" \
    --tag ostk-fleet-recall:localstack-production "$repo_dir" >/dev/null
docker buildx build --load --quiet --target localstack \
    --build-arg "VCS_REF=$vcs_ref" \
    --metadata-file "$private_metadata" \
    --tag ostk-fleet-recall:localstack-private "$repo_dir" >/dev/null

production_manifest_digest=$(jq -er \
    '."containerimage.digest" // ."containerimage.descriptor".digest' \
    "$production_metadata")
private_manifest_digest=$(jq -er \
    '."containerimage.digest" // ."containerimage.descriptor".digest' \
    "$private_metadata")
production_config_digest=$(docker image inspect \
    --format '{{.Id}}' ostk-fleet-recall:localstack-production)
private_config_digest=$(docker image inspect \
    --format '{{.Id}}' ostk-fleet-recall:localstack-private)
for digest in \
    "$production_manifest_digest" "$private_manifest_digest" \
    "$production_config_digest" "$private_config_digest"; do
    case "$digest" in
        sha256:*) hex_digest=${digest#sha256:} ;;
        *) fail "image build omitted a canonical sha256 digest" ;;
    esac
    case "$hex_digest" in
        ''|*[!0-9a-f]*) fail "image build omitted a canonical sha256 digest" ;;
    esac
    [ "${#hex_digest}" -eq 64 ] || \
        fail "image build omitted a canonical sha256 digest"
done
unset digest hex_digest

production_inspect=$proof_tmp/production-inspect.json
private_inspect=$proof_tmp/private-inspect.json
docker image inspect ostk-fleet-recall:localstack-production >"$production_inspect"
docker image inspect ostk-fleet-recall:localstack-private >"$private_inspect"
jq -e --arg revision "$vcs_ref" '
    length == 1 and
    .[0].Config.User == "10001:10001" and
    .[0].Config.Entrypoint == ["/usr/local/bin/container-entrypoint"] and
    .[0].Config.Cmd == ["demo", "--listen", "0.0.0.0:8080"] and
    .[0].Config.Labels["org.opencontainers.image.revision"] == $revision and
    all(.[0].Config.Env[]; split("=")[0] |
        IN("FLEET_RECALL_DATABASE_URL",
           "FLEET_RECALL_PUBLICATION_DATABASE_URL",
           "FLEET_RECALL_CONTROL_DATABASE_URL",
           "FLEET_RECALL_REGISTRY_DATABASE_URL",
           "FLEET_RECALL_SUCCESSOR_DATABASE_URL",
           "FLEET_RECALL_RECONCILIATION_DATABASE_URL",
           "FLEET_RECALL_TEST_DATABASE_URL",
           "FLEET_RECONCILIATION_TEST_DATABASE_URL",
           "FLEET_RECALL_PUBLICATION_TEST_ADMIN_DATABASE_URL",
           "FLEET_RECALL_DATABASE_SECRET_ID",
           "FLEET_RECALL_PRIVATE_DATABASE_KIND") | not)
' "$production_inspect" >/dev/null || fail "production image config boundary failed"
jq -e --arg revision "$vcs_ref" '
    length == 1 and
    .[0].Config.User == "10001:10001" and
    .[0].Config.Labels["org.opencontainers.image.revision"] == $revision
' "$private_inspect" >/dev/null || fail "private helper image source boundary failed"
docker run --rm --entrypoint /bin/sh \
    ostk-fleet-recall:localstack-production -c '
        test ! -e /usr/local/bin/aws &&
        test -x /usr/local/bin/ostk-fleet-recall &&
        test -x /usr/local/bin/s5cmd &&
        test "$(id -u):$(id -g)" = 10001:10001
    '
docker run --rm --entrypoint /bin/sh \
    ostk-fleet-recall:localstack-private -c '
        test -x /usr/local/bin/aws &&
        test "$(id -u):$(id -g)" = 10001:10001
    '

embedding_digest=$(docker run --rm \
    --user "$(id -u):$(id -g)" \
    --volume "$model_bundle:/model:ro" \
    --entrypoint /usr/local/bin/ostk-fleet-recall \
    ostk-fleet-recall:localstack-production model-digest /model)
case "$embedding_digest" in
    [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;
    ''|*[!0-9a-f]*) fail "production image returned a noncanonical model digest" ;;
    *) ;;
esac
[ "${#embedding_digest}" -eq 64 ] || \
    fail "production image returned a noncanonical model digest"
export FLEET_RECALL_EMBEDDING_MODEL_SHA256="$embedding_digest"

if ! compose up --detach --wait app >/dev/null; then
    echo "LocalStack stack failed to become ready; recent logs follow" >&2
    compose logs --no-color --tail 200 \
        localstack cockroach database-bootstrap migrate database-boundary \
        ingest writer publication-secret app >&2 || true
    exit 1
fi

aws_args="--endpoint-url http://127.0.0.1:$localstack_port --region us-east-1"
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1

get_secret() {
    # shellcheck disable=SC2086 # aws_args is intentionally a fixed option vector.
    aws $aws_args secretsmanager get-secret-value \
        --secret-id "$1" --query SecretString --output text
}

assert_secret_identity() {
    secret_id=$1
    expected_user=$2
    secret_value=$(get_secret "$secret_id")
    case "$secret_value" in
        "postgresql://$expected_user:"?*"@cockroach:26257/fleet_recall?sslmode=disable") ;;
        *) fail "Secrets Manager identity contract failed for $secret_id" ;;
    esac
    unset secret_value
}

assert_secret_identity \
    ostk-fleet-recall/local/migrator-database-url fleet_migrator
assert_secret_identity \
    ostk-fleet-recall/local/writer-database-url fleet_writer
assert_secret_identity \
    ostk-fleet-recall/local/publication-database-url fleet_publication

for name in config.json model.safetensors tokenizer.json; do
    # shellcheck disable=SC2086 # aws_args is intentionally a fixed option vector.
    aws $aws_args s3api head-object \
        --bucket fleet-recall-local-models \
        --key "bundles/demo/$name" >/dev/null
done

app_container=$(compose ps --quiet app)
writer_container=$(compose ps --quiet writer)
cockroach_container=$(compose ps --quiet cockroach)
for container_id in "$app_container" "$writer_container" "$cockroach_container"; do
    [ -n "$container_id" ] || fail "a required runtime container is missing"
done

app_image_id=$(docker inspect --format '{{.Image}}' "$app_container")
[ "$app_image_id" = "$production_config_digest" ] || \
    fail "public app is not running the reviewed production image config"
publication_secret_file_state=$(docker exec "$app_container" stat \
    --format '%a:%u:%g:%F' /run/fleet-recall-publication/database-url)
[ "$publication_secret_file_state" = '400:10001:10001:regular file' ] || \
    fail "publication secret handoff is not an exact mode-0400 UID-10001 file"
writer_image_id=$(docker inspect --format '{{.Image}}' "$writer_container")
[ "$writer_image_id" = "$private_config_digest" ] || \
    fail "writer is not running the reviewed private helper image config"
writer_published_ports=$(docker inspect --format '{{json .HostConfig.PortBindings}}' \
    "$writer_container")
case "$writer_published_ports" in
    '{}'|'null') ;;
    *) fail "private writer unexpectedly publishes a port" ;;
esac

if ! app_config_env=$(docker inspect \
    --format '{{range .Config.Env}}{{println .}}{{end}}' "$app_container"); then
    fail "public app Docker config could not be inspected"
fi
app_config_env_names=$(printf '%s\n' "$app_config_env" | \
    sed 's/=.*//' | LC_ALL=C sort)
for forbidden_name in \
    FLEET_RECALL_DATABASE_URL \
    FLEET_RECALL_PUBLICATION_DATABASE_URL \
    FLEET_RECALL_CONTROL_DATABASE_URL \
    FLEET_RECALL_REGISTRY_DATABASE_URL \
    FLEET_RECALL_SUCCESSOR_DATABASE_URL \
    FLEET_RECALL_RECONCILIATION_DATABASE_URL \
    FLEET_RECALL_TEST_DATABASE_URL \
    FLEET_RECONCILIATION_TEST_DATABASE_URL \
    FLEET_RECALL_PUBLICATION_TEST_ADMIN_DATABASE_URL \
    FLEET_RECALL_DATABASE_SECRET_ID \
    FLEET_RECALL_PRIVATE_DATABASE_KIND; do
    if printf '%s\n' "$app_config_env_names" | grep -Fxq "$forbidden_name"; then
        fail "public app Docker config contains forbidden database input $forbidden_name"
    fi
done

app_process_env_names=$(docker exec "$app_container" /bin/sh -c \
    'tr "\000" "\n" </proc/1/environ | sed "s/=.*//" | LC_ALL=C sort')
printf '%s\n' "$app_process_env_names" | \
    grep -Fxq FLEET_RECALL_PUBLICATION_DATABASE_URL || \
    fail "public process did not receive its publication URL"
for forbidden_name in \
    FLEET_RECALL_DATABASE_URL \
    FLEET_RECALL_CONTROL_DATABASE_URL \
    FLEET_RECALL_REGISTRY_DATABASE_URL \
    FLEET_RECALL_SUCCESSOR_DATABASE_URL \
    FLEET_RECALL_RECONCILIATION_DATABASE_URL \
    FLEET_RECALL_TEST_DATABASE_URL \
    FLEET_RECONCILIATION_TEST_DATABASE_URL \
    FLEET_RECALL_PUBLICATION_TEST_ADMIN_DATABASE_URL \
    FLEET_RECALL_DATABASE_SECRET_ID \
    FLEET_RECALL_PRIVATE_DATABASE_KIND; do
    if printf '%s\n' "$app_process_env_names" | grep -Fxq "$forbidden_name"; then
        fail "public process contains forbidden private database input $forbidden_name"
    fi
done

root_query() {
    compose exec --no-TTY cockroach cockroach sql \
        --insecure --host=localhost:26257 --database=fleet_recall \
        --format=tsv --execute="$1"
}

root_scalar() {
    if ! root_output=$(root_query "$1"); then
        fail "CockroachDB scalar evidence query failed"
    fi
    printf '%s\n' "$root_output" | tail -n 1
}

root_rows() {
    if ! root_output=$(root_query "$1"); then
        fail "CockroachDB row evidence query failed"
    fi
    printf '%s\n' "$root_output" | tail -n +2
}

sha256_text() {
    if ! text_hash_output=$(printf '%s\n' "$1" | shasum -a 256); then
        fail "canonical evidence rows could not be hashed"
    fi
    printf '%s\n' "$text_hash_output" | awk '{print $1}'
}

migration_summary=$(root_scalar "
SELECT count(*)::STRING || ':' || min(version)::STRING || ':' ||
       max(version)::STRING || ':' ||
       (count(*) FILTER (WHERE success))::STRING
FROM public._sqlx_migrations
WHERE version BETWEEN 1 AND 17;
")
[ "$migration_summary" = '17:1:17:17' ] || \
    fail "migration prefix terminal summary is not 17:1:17:17"
migration_rows=$(root_rows "
SELECT version::STRING || '|' || description || '|' ||
       encode(checksum, 'hex') || '|' || success::STRING
FROM public._sqlx_migrations
WHERE version BETWEEN 1 AND 17
ORDER BY version;
")
[ "$(printf '%s\n' "$migration_rows" | wc -l | tr -d ' ')" = 17 ] || \
    fail "migration prefix fingerprint input is not exactly 17 rows"
migration_fingerprint=$(sha256_text "$migration_rows")

publication_grant_rows=$(root_rows "
SELECT object_type || '|' || COALESCE(database_name, '') || '|' ||
       COALESCE(schema_name, '') || '|' || COALESCE(object_name, '') || '|' ||
       privilege_type || '|' ||
       CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END
FROM [SHOW GRANTS FOR fleet_publication_reader]
WHERE grantee = 'fleet_publication_reader'
ORDER BY object_type, database_name, schema_name, object_name, privilege_type;
")
expected_publication_grant_rows='database|fleet_recall|||CONNECT|not_grantable
schema|fleet_recall|public||USAGE|not_grantable
table|fleet_recall|public|_sqlx_migrations|SELECT|not_grantable
table|fleet_recall|public|memory_chunks|SELECT|not_grantable
table|fleet_recall|public|memory_claim_embeddings|SELECT|not_grantable
table|fleet_recall|public|memory_claim_support|SELECT|not_grantable
table|fleet_recall|public|memory_claims|SELECT|not_grantable
table|fleet_recall|public|memory_conflict_members|SELECT|not_grantable
table|fleet_recall|public|memory_conflicts|SELECT|not_grantable
table|fleet_recall|public|memory_corpus_models|SELECT|not_grantable'
[ "$publication_grant_rows" = "$expected_publication_grant_rows" ] || \
    fail "publication grant rows differ from the exact ten-row contract"
publication_grant_fingerprint=$(sha256_text "$publication_grant_rows")

publication_terminal=$(root_scalar "
SELECT
    (SELECT count(*)::STRING FROM [SHOW GRANTS FOR fleet_publication]
      WHERE grantee = 'fleet_publication') || ':' ||
    (SELECT count(*)::STRING FROM [SHOW SYSTEM GRANTS]
      WHERE grantee IN ('public', 'fleet_publication_reader', 'fleet_publication')) || ':' ||
    (SELECT count(*)::STRING FROM [SHOW GRANTS ON ROLE]
      WHERE role_name = 'fleet_publication_reader'
        AND member = 'fleet_publication'
        AND NOT is_admin) || ':' ||
    (SELECT count(*)::STRING FROM [SHOW USERS]
      WHERE username = 'fleet_publication' AND options::STRING = '{}');
")
[ "$publication_terminal" = '0:0:1:1' ] || \
    fail "publication principal terminal state is not 0:0:1:1"

identity_terminal=$(root_scalar "
SELECT
    (SELECT count(*)::STRING FROM [SHOW USERS]
      WHERE username = 'fleet_migrator'
        AND options::STRING = '{NOLOGIN}') || ':' ||
    (SELECT count(*)::STRING FROM [SHOW USERS]
      WHERE username = 'fleet_writer'
        AND options::STRING = '{}') || ':' ||
    (SELECT count(*)::STRING FROM [SHOW USERS]
      WHERE username = 'fleet_publication'
        AND options::STRING = '{}') || ':' ||
    (SELECT count(*)::STRING FROM [SHOW GRANTS ON ROLE admin]
      WHERE member IN (
        'fleet_migrator', 'fleet_writer', 'fleet_publication'
      )) || ':' ||
    (SELECT count(*)::STRING FROM [SHOW SYSTEM GRANTS]
      WHERE grantee IN (
        'fleet_migrator', 'fleet_writer', 'fleet_publication'
      ));
")
[ "$identity_terminal" = '1:1:1:0:0' ] || \
    fail "migrator/writer/publication identity terminal state is not 1:1:1:0:0"

publication_database_url=$(get_secret \
    ostk-fleet-recall/local/publication-database-url)
publication_sql() {
    compose exec --no-TTY cockroach cockroach sql \
        --url "$publication_database_url" --format=tsv --execute="$1"
}

if ! publication_identity_output=$(publication_sql \
    "SELECT pg_catalog.current_user() || ':' || pg_catalog.current_database();"); then
    fail "direct publication identity query failed"
fi
publication_identity=$(printf '%s\n' "$publication_identity_output" | tail -n 1)
[ "$publication_identity" = 'fleet_publication:fleet_recall' ] || \
    fail "direct publication connection used the wrong identity"
publication_sql \
    'SELECT count(*) FROM public._sqlx_migrations WHERE version BETWEEN 1 AND 17;' \
    >/dev/null

expect_publication_sql_denied() {
    label=$1
    statement=$2
    denial_output=$proof_tmp/direct-denial.out
    if publication_sql "$statement" >"$denial_output" 2>&1; then
        fail "$label unexpectedly succeeded"
    fi
    if ! grep -Eiq 'permission denied|does not have.*privilege|insufficient privilege' \
        "$denial_output"; then
        fail "$label did not fail with a privilege denial"
    fi
    : >"$denial_output"
}

expect_publication_sql_denied 'publication DELETE' \
    'DELETE FROM public.memory_chunks WHERE false'
expect_publication_sql_denied 'publication schema DDL' \
    'CREATE TABLE public.publication_smoke_escape (id INT8 PRIMARY KEY)'
expect_publication_sql_denied 'publication role delegation' \
    'GRANT fleet_publication_reader TO fleet_writer'
unset publication_database_url

app_denial_output=$proof_tmp/app-denial.out
if docker exec "$app_container" /bin/sh /localstack/publication-entrypoint.sh serve \
    >"$app_denial_output" 2>&1; then
    fail "public app wrapper unexpectedly launched the writer protocol"
fi
grep -Fq 'can launch only the bounded demo' "$app_denial_output" || \
    fail "public app wrapper denial was not explicit"
if docker exec "$app_container" /usr/local/bin/container-entrypoint serve \
    </dev/null >"$app_denial_output" 2>&1; then
    fail "public production container unexpectedly acquired writer configuration"
fi
grep -Fq 'FLEET_RECALL_DATABASE_URL is required' "$app_denial_output" || \
    fail "public binary write path did not fail on the absent private URL"
: >"$app_denial_output"

health=$(curl --fail --silent --show-error \
    "http://127.0.0.1:$demo_port/healthz")
printf '%s' "$health" | jq -e '.status == "ready"' >/dev/null

status=$(curl --fail --silent --show-error \
    "http://127.0.0.1:$demo_port/api/status")
printf '%s' "$status" | jq -e '
    .data.database.vector_index_enabled == true and
    .data.database.conflict_membership_index_enabled == true
' >/dev/null

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
printf '%s' "$fleet_scenario" | jq -e \
    '.verified == true and .capture == "live" and .provenance.backend == "cockroachdb"' \
    >/dev/null
fleet_claim_id=$(printf '%s' "$fleet_scenario" | jq -er '.agent_a.claim_id')

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
app_container_before=$app_container
cockroach_container_before=$cockroach_container
compose up --detach --no-deps --force-recreate --wait app >/dev/null
app_container_after=$(compose ps --quiet app)
cockroach_container_after=$(compose ps --quiet cockroach)
if [ -z "$app_container_after" ] || [ "$app_container_before" = "$app_container_after" ]; then
    fail "app container replacement was not observed"
fi
[ "$cockroach_container_before" = "$cockroach_container_after" ] || \
    fail "CockroachDB changed during stateless app replacement"
replacement_image_id=$(docker inspect --format '{{.Image}}' "$app_container_after")
[ "$replacement_image_id" = "$production_config_digest" ] || \
    fail "replacement app is not the reviewed production image"
assert_demo_recall
assert_fleet_claim_recall

replacement_process_env_names=$(docker exec "$app_container_after" /bin/sh -c \
    'tr "\000" "\n" </proc/1/environ | sed "s/=.*//" | LC_ALL=C sort')
printf '%s\n' "$replacement_process_env_names" | \
    grep -Fxq FLEET_RECALL_PUBLICATION_DATABASE_URL || \
    fail "replacement public process omitted its publication URL"
for forbidden_name in \
    FLEET_RECALL_DATABASE_URL \
    FLEET_RECALL_CONTROL_DATABASE_URL \
    FLEET_RECALL_REGISTRY_DATABASE_URL \
    FLEET_RECALL_SUCCESSOR_DATABASE_URL \
    FLEET_RECALL_RECONCILIATION_DATABASE_URL \
    FLEET_RECALL_TEST_DATABASE_URL \
    FLEET_RECONCILIATION_TEST_DATABASE_URL \
    FLEET_RECALL_PUBLICATION_TEST_ADMIN_DATABASE_URL \
    FLEET_RECALL_DATABASE_SECRET_ID \
    FLEET_RECALL_PRIVATE_DATABASE_KIND; do
    if printf '%s\n' "$replacement_process_env_names" | \
        grep -Fxq "$forbidden_name"; then
        fail "replacement public process acquired private database input $forbidden_name"
    fi
done

end_revision=$(git -C "$repo_dir" rev-parse HEAD)
end_source_status=$(git -C "$repo_dir" status --porcelain --untracked-files=all)
if [ "$end_revision" != "$vcs_ref" ] || [ -n "$end_source_status" ]; then
    fail "source changed during the evidence run"
fi
unset end_source_status

if [ "${KEEP_LOCALSTACK:-0}" = 1 ]; then
    printf '%s\n' \
        'KEEP_LOCALSTACK=1 is interactive only; the stack remains and no verified receipt is emitted.' >&2
    printf 'Demo remains at http://127.0.0.1:%s.\n' "$demo_port" >&2
    exit 0
fi

# A release-grade PASS is deferred until teardown itself succeeds. Preserve a
# bounded diagnostic capture if teardown fails, and do not let the EXIT trap
# retry/remove the failing state before an operator can inspect it.
compose ps --all >"$proof_tmp/pre-teardown-compose-ps.txt" 2>&1 || true
compose logs --no-color \
    localstack cockroach database-bootstrap migrate database-boundary \
    ingest writer publication-secret app \
    >"$proof_tmp/pre-teardown-compose.log" 2>&1 || true
cleanup_attempted=1
if ! compose down --volumes --remove-orphans \
    >"$proof_tmp/teardown.log" 2>&1; then
    preserve_proof=1
    fail "Compose teardown failed; no verified receipt was emitted"
fi

if ! remaining_project_containers=$(docker ps --all --quiet \
    --filter label=com.docker.compose.project=ostk-fleet-recall-local); then
    preserve_proof=1
    fail "fixed-project container residue could not be inspected after teardown"
fi
if [ -n "$remaining_project_containers" ]; then
    printf '%s\n' "$remaining_project_containers" \
        >"$proof_tmp/remaining-project-containers.txt"
    preserve_proof=1
    fail "fixed-project containers remain after teardown"
fi
unset remaining_project_containers

if ! remaining_volume_names=$(docker volume ls --quiet); then
    preserve_proof=1
    fail "Docker volume residue could not be inspected after teardown"
fi
if printf '%s\n' "$remaining_volume_names" | \
    grep -Fxq ostk-fleet-recall-local-publication-secret; then
    printf '%s\n' "$remaining_volume_names" \
        >"$proof_tmp/post-teardown-volume-names.txt"
    preserve_proof=1
    fail "publication-secret volume remains after teardown"
fi
unset remaining_volume_names
cleanup_succeeded=1

release_revision=$(git -C "$repo_dir" rev-parse HEAD)
release_source_status=$(git -C "$repo_dir" status --porcelain --untracked-files=all)
if [ "$release_revision" != "$vcs_ref" ] || [ -n "$release_source_status" ]; then
    preserve_proof=1
    fail "source changed before the deferred verified receipt"
fi
unset release_source_status

generated_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
receipt=$(jq -cn \
    --arg generated_at "$generated_at" \
    --arg vcs_ref "$vcs_ref" \
    --arg production_config_digest "$production_config_digest" \
    --arg production_manifest_digest "$production_manifest_digest" \
    --arg private_config_digest "$private_config_digest" \
    --arg private_manifest_digest "$private_manifest_digest" \
    --arg embedding_digest "$embedding_digest" \
    --arg policy_sha256 "$policy_sha256" \
    --arg migration_fingerprint "$migration_fingerprint" \
    --arg publication_grant_fingerprint "$publication_grant_fingerprint" \
    --argjson fleet_scenario "$fleet_scenario" '
    {
      schema: "fleet-localstack-publication-proof-v1",
      verified: true,
      capture: "live-local-emulator",
      generated_at: $generated_at,
      source: {vcs_ref: $vcs_ref, tracked_tree_clean: true},
      cleanup: {
        mode: "release",
        fixed_project_containers_absent: true,
        publication_secret_volume_absent: true
      },
      images: {
        public_production: {
          target: "production",
          config_digest: $production_config_digest,
          manifest_digest: $production_manifest_digest,
          uid_gid: "10001:10001",
          aws_cli_absent: true
        },
        private_helper: {
          target: "localstack",
          config_digest: $private_config_digest,
          manifest_digest: $private_manifest_digest,
          externally_reachable: false
        }
      },
      database: {
        engine: "CockroachDB v26.2.3",
        transport: "insecure-local-only",
        migration_prefix: {
          first: 1, last: 17, successful_rows: 17,
          fingerprint_sha256: $migration_fingerprint
        },
        publication_policy_sha256: $policy_sha256,
        publication_grant_fingerprint_sha256: $publication_grant_fingerprint,
        publication_principal: "fleet_publication",
        publication_role: "fleet_publication_reader",
        direct_read_succeeded: true,
        direct_dml_ddl_delegation_denied: true
      },
      model_bundle_sha256: $embedding_digest,
      public_app: {
        database_input: "FLEET_RECALL_PUBLICATION_DATABASE_URL",
        private_database_inputs_absent: true,
        status_and_recall_succeeded: true,
        writer_command_denied: true,
        replacement_preserved_recall: true
      },
      writer_scenario: $fleet_scenario,
      limitations: {
        aws_apply_performed: false,
        tls_proved: false,
        iam_enforcement_proved: false,
        fargate_proved: false,
        iam_policy_body_gate: "separate deploy/aws Terraform tests; not executed by this harness"
      }
    }
    ')
printf '%s\n' "$receipt" | jq -e \
    '.verified == true and
     .source.tracked_tree_clean == true and
     .cleanup == {
       mode: "release",
       fixed_project_containers_absent: true,
       publication_secret_volume_absent: true
     }' >/dev/null
[ "$cleanup_succeeded" -eq 1 ] || \
    fail "verified receipt reached emission before successful cleanup"
printf '%s\n' "$receipt"
