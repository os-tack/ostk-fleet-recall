#!/usr/bin/env bash
# The M1 verification checklist. Every check prints PASS or FAIL; the script
# exits non-zero if any check failed. Run from the Mac after `bootstrap.sh up`.
set -uo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
state=${FLEET_LOCAL_STATE:-$here/.state}
# shellcheck source=../lib.sh
. "$here/lib.sh"
export KUBECONFIG="$state/kubeconfig"
VM=${FLEET_LOCAL_VM:-k0s}
NS=fleet-recall
CRDB_IMAGE=cockroachdb/cockroach:v26.2.3
failures=0
fail() { failures=$((failures + 1)); }
export state CRDB_IMAGE

crdb_sql() {
    docker run --rm --network host -v "$state/certs:/certs:ro" "$CRDB_IMAGE" \
        sql --certs-dir=/certs --host=127.0.0.1:26258 --format=tsv "$@"
}
export -f crdb_sql

image_imported() {
    local tag
    tag=$(cat "$state/image.tag") || return 1
    limactl shell "$VM" sudo k0s ctr images ls | grep -F "ostk-fleet-recall:$tag" >/dev/null
}

# Inspect variable names inside the container, never print secret values.
no_pg_environment() {
    kubectl -n "$NS" exec "deploy/$1" -- /bin/sh -c \
        'if env | cut -d= -f1 | grep -qi "^PG"; then exit 1; fi'
}

service_links_disabled() {
    kubectl -n "$NS" get deploy/writer deploy/demo deploy/ingress cronjob/worker -o json |
        jq -e 'all(.items[]; (.spec.template.spec // .spec.jobTemplate.spec.template.spec).enableServiceLinks == false)'
}

mcp_recall() {
    printf '%s\n' \
        '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"verify","version":"0"}}}' \
        '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
        '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
        '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"recall","arguments":{"action":"search","query":"deployment","limit":3}}}' |
        kubectl -n "$NS" exec -i deploy/writer -- /usr/local/bin/container-entrypoint serve 2>/dev/null |
        jq -se 'any(.[]; .id == 2 and any(.result.tools[]?; .name == "recall")) and
            any(.[]; .id == 3 and .error == null and .result.isError == false and
                (.result.structuredContent.data.hits | type == "array" and length > 0))'
}

# A 201 response and usable public client prove registration is enabled, rather
# than only advertised. Never print the registration access token or client body.
hydra_registration() {
    local response status body
    response=$(curl -sS --max-time 30 -w '\n%{http_code}' -X POST http://localhost:4444/oauth2/register \
        -H 'content-type: application/json' \
        -d '{"client_name":"fleet-recall verify","redirect_uris":["http://localhost:43110/callback"],"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"none","scope":"openid fleet-recall"}') || return 1
    status=${response##*$'\n'}
    body=${response%$'\n'*}
    [ "$status" = 201 ] || return 1
    printf '%s' "$body" | jq -e '(.client_id | type == "string" and length > 0) and .token_endpoint_auth_method == "none"'
}

localstack_ready() {
    curl -sf --connect-timeout 2 --max-time 5 http://127.0.0.1:4566/_localstack/health |
        jq -e 'all([.services.s3,.services.sts][]; . == "available" or . == "running")'
}

skip_localstack() {
    printf '  SKIP  %s\n' "STS GetCallerIdentity" "S3 bundle contents" "S3-only model download and health"
}

# Derive the production model-download probe from the deployed writer identity
# and image. A fresh emptyDir replaces every hostPath; the model subdirectory is
# initially absent, so container-entrypoint must download and verify the S3 bundle.
s3_model_health() {
    local manifest job
    manifest=$(kubectl -n "$NS" get deploy writer -o json | jq '
        .spec.template.spec as $pod |
        {apiVersion:"batch/v1", kind:"Job", metadata:{generateName:"verify-s3-health-", namespace:"fleet-recall"},
         spec:{backoffLimit:0, activeDeadlineSeconds:600, ttlSecondsAfterFinished:3600,
          template:{metadata:{labels:{app:"verify-s3-health"}}, spec:($pod |
            .restartPolicy = "Never" |
            .enableServiceLinks = false |
            .automountServiceAccountToken = false |
            .securityContext.fsGroup = 10001 |
            .volumes = ([.volumes[]? | select(has("hostPath") | not) | select(.name != "model")] + [{name:"model-download",emptyDir:{}}]) |
            .containers = [.containers[0] |
                .name = "health" |
                .command = ["/usr/local/bin/container-entrypoint"] |
                .args = ["health"] |
                del(.readinessProbe,.livenessProbe,.startupProbe) |
                .volumeMounts = ([.volumeMounts[]? | select(.name != "model")] + [{name:"model-download",mountPath:"/tmp/verify-model"}]) |
                .env = ((.env // [] | map(select(.name as $name | ["FLEET_RECALL_EMBEDDING_MODEL_PATH","FLEET_RECALL_MODEL_S3_URI","FLEET_RECALL_AWS_ENDPOINT_URL","AWS_ACCESS_KEY_ID","AWS_SECRET_ACCESS_KEY","AWS_REGION"] | index($name) | not))) + [
                    {name:"FLEET_RECALL_EMBEDDING_MODEL_PATH",value:"/tmp/verify-model/bundle"},
                    {name:"FLEET_RECALL_MODEL_S3_URI",value:"s3://fleet-recall-local-models/bundles/demo"},
                    {name:"FLEET_RECALL_AWS_ENDPOINT_URL",value:"http://localstack.localstack.svc:4566"},
                    {name:"AWS_ACCESS_KEY_ID",value:"test"},
                    {name:"AWS_SECRET_ACCESS_KEY",value:"test"},
                    {name:"AWS_REGION",value:"us-east-1"}])])}}}') || return 1
    printf '%s' "$manifest" | jq -e 'all(.spec.template.spec.volumes[]; has("hostPath") | not)' >/dev/null || return 1
    job=$(printf '%s' "$manifest" | kubectl create -f - -o name) || return 1
    # wait_job calls die on failure; isolate it so the checklist can continue.
    (wait_job "$NS" "${job#job.batch/}" 600)
}

echo "VM and cluster"
check "/dev/kvm present in the guest" limactl shell "$VM" test -e /dev/kvm || fail
# shellcheck disable=SC2016 # The child shell expands its positional arguments.
check "guest user is in the kvm group" bash -o pipefail -c 'limactl shell "$1" id -nG | tr " " "\n" | grep -x kvm' _ "$VM" || fail
check "exactly one node, Ready" bash -o pipefail -c 'kubectl get nodes -o json | jq -e '\''(.items | length) == 1 and all(.items[]; any(.status.conditions[]; .type == "Ready" and .status == "True"))'\''' || fail
check "image imported into k0s containerd" image_imported || fail

echo "CockroachDB (secure, from the Mac)"
check "verify-full SQL lists fleet_recall, hydra, kratos" bash -o pipefail -c "dbs=\$(crdb_sql --execute='SHOW DATABASES' | cut -f1) || exit 1; for d in fleet_recall hydra kratos; do echo \"\$dbs\" | grep -qx \$d || exit 1; done" || fail
check "38 successful migrations, max version 39" bash -o pipefail -c "crdb_sql -d fleet_recall --execute='SELECT count(*), max(version) FROM _sqlx_migrations WHERE success' | tail -n1 | grep -qE '^38[[:space:]]+39\$'" || fail
check "migrator is NOLOGIN" bash -o pipefail -c "crdb_sql --execute=\"SELECT options FROM [SHOW USERS] WHERE username = 'fleet_migrator'\" | tail -n1 | grep -q NOLOGIN" || fail
check "writer, publication, ingress, enrollment can log in" bash -o pipefail -c "crdb_sql --execute=\"SELECT username FROM [SHOW USERS] WHERE username IN ('fleet_writer','fleet_publication','fleet_ingress','fleet_enrollment') AND NOT ('NOLOGIN' = ANY(options))\" | tail -n +2 | wc -l | tr -d ' ' | grep -qx 4" || fail
check "role edges are exactly enrollment/runtime/reader/receiver" bash -o pipefail -c "crdb_sql --execute=\"SELECT role_name, member FROM [SHOW GRANTS ON ROLE] WHERE member LIKE 'fleet_%' ORDER BY 1\" | tail -n +2 | tr '\t' '>' | paste -sd, - | grep -qx 'fleet_enrollment_manager>fleet_enrollment,fleet_ingress_receiver>fleet_ingress,fleet_publication_reader>fleet_publication,fleet_runtime>fleet_writer'" || fail

echo "Jobs and pods"
for j in db-bootstrap migrate boundary ory-db-bootstrap seed; do
    check "job $j complete" kubectl -n "$NS" wait --for=condition=Complete "job/$j" --timeout=1s || fail
done
check "service-link variables disabled for every recall workload" service_links_disabled || fail
for d in writer demo ingress; do
    check "deployment $d available" kubectl -n "$NS" wait --for=condition=Available "deploy/$d" --timeout=5s || fail
    check "no PG* variables in the $d pod" no_pg_environment "$d" || fail
done

echo "Recall surfaces"
check "demo /healthz ready" bash -o pipefail -c "curl -sf --max-time 40 127.0.0.1:8088/healthz | jq -e '.status == \"ready\"'" || fail
check "demo /api/status has a vector index" bash -o pipefail -c "curl -sf --max-time 40 127.0.0.1:8088/api/status | jq -e '.data.database.vector_index_enabled == true'" || fail
check "demo /api/recall returns hits" bash -o pipefail -c "curl -sf --max-time 40 -X POST 127.0.0.1:8088/api/recall -H 'content-type: application/json' -d '{\"query\":\"deployment\",\"limit\":3}' | jq -e '.data.hits | type == \"array\" and length > 0'" || fail
check "ingress refuses an unsigned webhook (401)" bash -c "[ \"\$(curl -s --max-time 30 -o /dev/null -w '%{http_code}' -X POST 127.0.0.1:8787/v1/hooks/slack.local -H 'content-type: application/json' -d '{}')\" = 401 ]" || fail
check "stdio MCP lists tools and returns recall hits through the writer pod" mcp_recall || fail

echo "Worker"
worker_job=$(kubectl -n "$NS" create job "verify-worker-$(date +%s)-$$" --from=cronjob/worker -o name 2>/dev/null)
if [ -n "$worker_job" ] && kubectl -n "$NS" patch "$worker_job" --type=merge -p '{"spec":{"ttlSecondsAfterFinished":3600,"activeDeadlineSeconds":600}}' >/dev/null 2>&1 && (wait_job "$NS" "${worker_job#job.batch/}" 600) >/dev/null 2>&1; then
    # shellcheck disable=SC2016 # The child shell expands its positional arguments.
    check "worker bodies, lexical, dense are all ok" bash -o pipefail -c 'kubectl -n "$1" logs "$2" | tail -n1 | jq -e '\''[.steps.bodies.status,.steps.lexical.status,.steps.dense.status] == ["ok","ok","ok"]'\''' _ "$NS" "$worker_job" || fail
    kubectl -n "$NS" logs "$worker_job" | tail -n1 | jq -c '.steps | with_entries(.value |= .status)' 2>/dev/null | sed 's/^/        /'
else
    printf '  FAIL  %s\n' "worker tick did not complete"; fail
fi

echo "Ory"
check "Hydra discovery issuer" bash -o pipefail -c "curl -sf --max-time 30 localhost:4444/.well-known/openid-configuration | jq -e '.issuer == \"http://localhost:4444/\"'" || fail
check "Hydra advertises dynamic registration" bash -o pipefail -c "curl -sf --max-time 30 localhost:4444/.well-known/openid-configuration | jq -e '.registration_endpoint == \"http://localhost:4444/oauth2/register\"'" || fail
check "Hydra dynamically registers a public client (201)" hydra_registration || fail
check "Hydra JWKS served" bash -o pipefail -c "curl -sf --max-time 30 localhost:4444/.well-known/jwks.json | jq -e '(.keys | length) >= 1'" || fail
check "Kratos public ready" bash -o pipefail -c "curl -sf --max-time 30 localhost:4433/health/ready | jq -e '.status == \"ok\"'" || fail
check "Kratos UI answers" curl -sfL -b '' --max-time 30 -o /dev/null localhost:4455/registration || fail

echo "LocalStack"
if [ "${FLEET_LOCAL_SKIP_LOCALSTACK:-0}" = 1 ]; then
    echo "        LocalStack coverage omitted by FLEET_LOCAL_SKIP_LOCALSTACK=1"
    skip_localstack
elif check "LocalStack S3 and STS ready" localstack_ready; then
    check "STS GetCallerIdentity" bash -o pipefail -c "AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_MAX_ATTEMPTS=1 AWS_PAGER='' aws --cli-connect-timeout 3 --cli-read-timeout 10 --region us-east-1 --endpoint-url http://127.0.0.1:4566 sts get-caller-identity | jq -e '.Account == \"000000000000\"'" || fail
    check "model bucket holds the three bundle files" bash -o pipefail -c "AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_MAX_ATTEMPTS=1 AWS_PAGER='' aws --cli-connect-timeout 3 --cli-read-timeout 10 --region us-east-1 --endpoint-url http://127.0.0.1:4566 s3api list-objects-v2 --bucket fleet-recall-local-models --prefix bundles/demo/ | jq -e '[.Contents[].Key] | sort == [\"bundles/demo/config.json\",\"bundles/demo/model.safetensors\",\"bundles/demo/tokenizer.json\"]'" || fail
    check "health succeeds after S3 model download with no hostPath" s3_model_health || fail
else
    fail
    echo "        LocalStack is unavailable; dependent checks were not run"
    skip_localstack
fi

echo "Sandbox reachability (docker backend)"
check "OrbStack container reaches the demo through host.docker.internal" docker run --rm curlimages/curl:8.10.1 -sf --max-time 30 http://host.docker.internal:8088/healthz || fail

if [ "$failures" -eq 0 ]; then
    echo "all executed checks passed"
else
    echo "$failures check(s) failed"
    exit 1
fi
