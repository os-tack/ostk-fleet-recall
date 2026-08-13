#!/bin/sh
set -eu

mock_state=${MOCK_STATE_DIR:-}
mock_scenario=${MOCK_SCENARIO:-success}

argument_value() {
    wanted=$1
    shift
    while [ "$#" -gt 0 ]; do
        if [ "$1" = "$wanted" ]; then
            [ "$#" -ge 2 ] || exit 96
            printf '%s\n' "$2"
            return 0
        fi
        shift
    done
    return 1
}

mock_terraform() {
    case " $* " in
        *' output -raw aws_region '*) printf '%s' us-east-1 ;;
        *' output -raw cluster_name '*) printf '%s' fleet-cluster ;;
        *' output -raw service_name '*) printf '%s' fleet-service ;;
        *' output -raw demo_url '*) printf '%s' https://fleet.example.test ;;
        *) echo "unexpected terraform arguments: $*" >&2; exit 96 ;;
    esac
}

mock_aws() {
    service=$1
    operation=$2
    shift 2
    [ "$service" = ecs ] || exit 96
    case "$operation" in
        wait)
            [ "$1" = services-stable ] || exit 96
            ;;
        describe-services)
            requested=$(argument_value --services "$@")
            [ "$requested" = fleet-service ] || exit 96
            jq -cn '{
                failures: [],
                services: [{
                    serviceName: "fleet-service",
                    status: "ACTIVE",
                    desiredCount: 2,
                    runningCount: 2,
                    pendingCount: 0,
                    taskDefinition: "arn:aws:ecs:us-east-1:123456789012:task-definition/fleet-app:9",
                    deployments: [{status: "PRIMARY", rolloutState: "COMPLETED"}]
                }]
            }'
            ;;
        list-tasks)
            prefix=old
            if [ -f "$mock_state/updated" ]; then
                prefix=new
                [ "$mock_scenario" != overlap ] || prefix=old
            fi
            jq -cn --arg prefix "$prefix" '{taskArns: [
                "arn:aws:ecs:us-east-1:123456789012:task/fleet-cluster/" + $prefix + "-1",
                "arn:aws:ecs:us-east-1:123456789012:task/fleet-cluster/" + $prefix + "-2"
            ]}'
            ;;
        update-service)
            : > "$mock_state/updated"
            printf '%s\n' '{"service":{"serviceName":"fleet-service"}}'
            ;;
        *) echo "unexpected aws operation: $operation" >&2; exit 96 ;;
    esac
}

mock_curl() {
    url=
    data=
    want_data=0
    for argument do
        if [ "$want_data" -eq 1 ]; then
            data=$argument
            want_data=0
            continue
        fi
        case "$argument" in
            --data) want_data=1 ;;
            https://*) url=$argument ;;
        esac
    done
    case "$url" in
        https://fleet.example.test/healthz)
            printf '%s\n' '{"status":"ready"}'
            ;;
        https://fleet.example.test/api/recall)
            query=$(printf '%s' "$data" | jq -er '.query')
            case "$query" in
                *'hold application workers until dedicated schema migrator completes'*) claim_id=102 ;;
                *'pause rollout incompatible migration strategies operator review'*) claim_id=104 ;;
                *) exit 96 ;;
            esac
            if [ "$mock_scenario" = missing-after ] && [ -f "$mock_state/updated" ]; then
                claim_id=999
            fi
            jq -cn --argjson claim_id "$claim_id" '{
                data: {hits: [{extra: {claim_id: $claim_id}}]},
                diagnostics: {retrieval: {lanes: ["lexical", "dense"], fusion: "rrf"}}
            }'
            ;;
        *) echo "unexpected curl URL: $url" >&2; exit 96 ;;
    esac
}

case "$(basename -- "$0")" in
    aws) mock_aws "$@"; exit ;;
    curl) mock_curl "$@"; exit ;;
    terraform) mock_terraform "$@"; exit ;;
esac

for command_name in jq sed; do
    command -v "$command_name" >/dev/null 2>&1 || exit 69
done

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
wrapper=$script_dir/../run-replacement-proof.sh
verifier=$script_dir/../verify-publication-receipts.sh
test_root=$(mktemp -d "${TMPDIR:-/tmp}/fleet-replacement-proof-test.XXXXXX")
trap 'rm -rf "$test_root"' EXIT HUP INT TERM
mock_bin=$test_root/bin
mkdir -p "$mock_bin"
self=$script_dir/$(basename -- "$0")
ln -s "$self" "$mock_bin/aws"
ln -s "$self" "$mock_bin/curl"
ln -s "$self" "$mock_bin/terraform"

reference=$test_root/reference.json
jq -cn '{
    schema: "fleet-reference-agent-run-v1",
    verified: true,
    deployment: "amazon-ecs-fargate",
    run_id: "mock-run-1",
    project: "fleet-project",
    agents: ["agent-a", "agent-b", "agent-c"],
    memory: {
        recalled_claim_id: 101,
        incompatible_claim_id: 103,
        open_conflict_id: 501,
        retrieval_lanes: ["lexical", "dense"],
        fusion: "rrf"
    },
    actions: [
        {claim_id: 102, action: "hold workers until migration completes", based_on_claim_id: 101},
        {claim_id: 104, action: "pause rollout for operator review", based_on_conflict_id: 501}
    ],
    aws: {
        region: "us-east-1",
        cluster: "fleet-cluster",
        task_definition: "fleet-reference-agent:7",
        log_stream_prefix: "fleet/fleet-recall",
        tasks: [
            {step: "record_decision", agent: "agent-a", task_id: "agent-1", log_stream_suffix: "fleet-recall/agent-1", stopped_at: "2026-08-13T19:00:00Z"},
            {step: "recall_and_act", agent: "agent-b", task_id: "agent-2", log_stream_suffix: "fleet-recall/agent-2", stopped_at: "2026-08-13T19:01:00+00:00"},
            {step: "record_conflict", agent: "agent-c", task_id: "agent-3", log_stream_suffix: "fleet-recall/agent-3", stopped_at: null},
            {step: "recall_conflict_and_escalate", agent: "agent-b", task_id: "agent-4", log_stream_suffix: "fleet-recall/agent-4", stopped_at: "2026-08-13T19:03:00Z"}
        ]
    },
    public_demo: {
        url: "https://fleet.example.test",
        health: "ready",
        read_only_verification: true,
        exact_claim_ids_observed: [102, 104],
        retrieval_lanes: ["lexical", "dense"],
        fusion: "rrf",
        database: "CockroachDB",
        cockroachdb_version: "CockroachDB CCL v26.2.0",
        embedding_model: "minishlab/potion-retrieval-32M",
        cockroachdb_capabilities: {
            vector_index_enabled: true,
            lexical_index_enabled: true,
            conflict_membership_index_enabled: true,
            cosine_distance_supported: true,
            schema_version: 1,
            embedding_dimension: 512
        }
    }
}' > "$reference"

"$verifier" "$reference" > "$test_root/reference-validation.json"
jq -e '.verified == true and .receipts == ["reference-agent"]' \
    "$test_root/reference-validation.json" >/dev/null

success_state=$test_root/success
mkdir -p "$success_state"
PATH="$mock_bin:$PATH" MOCK_STATE_DIR="$success_state" MOCK_SCENARIO=success \
    "$wrapper" "$reference" > "$test_root/replacement.json" 2> "$test_root/replacement.err"
"$verifier" "$reference" "$test_root/replacement.json" > "$test_root/validation.json"
jq -e '
    .schema == "fleet-ecs-replacement-run-v1" and
    .verified == true and
    .run_id == "mock-run-1" and
    .aws.task_definition == "fleet-app:9" and
    .aws.tasks_before == ["old-1", "old-2"] and
    .aws.tasks_after == ["new-1", "new-2"] and
    .persistence.exact_claim_ids_survived == [102, 104]
' "$test_root/replacement.json" >/dev/null
if grep -Eq 'arn:|[0-9]{12}|postgres(ql)?://' "$test_root/replacement.json"; then
    echo "replacement receipt leaked a prohibited coordinate" >&2
    exit 1
fi
jq -e '.verified == true and .validation_only == true and
    .receipts == ["reference-agent", "ecs-replacement"]' \
    "$test_root/validation.json" >/dev/null

overlap_state=$test_root/overlap
mkdir -p "$overlap_state"
if PATH="$mock_bin:$PATH" MOCK_STATE_DIR="$overlap_state" MOCK_SCENARIO=overlap \
    "$wrapper" "$reference" > "$test_root/overlap.out" 2> "$test_root/overlap.err"; then
    echo "replacement proof accepted an unchanged serving task set" >&2
    exit 1
fi
grep -F 'pre-deployment serving task remained' "$test_root/overlap.err" >/dev/null

missing_state=$test_root/missing
mkdir -p "$missing_state"
if PATH="$mock_bin:$PATH" MOCK_STATE_DIR="$missing_state" MOCK_SCENARIO=missing-after \
    "$wrapper" "$reference" > "$test_root/missing.out" 2> "$test_root/missing.err"; then
    echo "replacement proof accepted missing post-replacement claims" >&2
    exit 1
fi
grep -F 'did not return exact action claim 102' "$test_root/missing.err" >/dev/null

jq '.aws.task_arn = "arn:aws:ecs:us-east-1:123456789012:task/example"' \
    "$test_root/replacement.json" > "$test_root/leaky.json"
if "$verifier" "$reference" "$test_root/leaky.json" \
    > "$test_root/leaky.out" 2> "$test_root/leaky.err"; then
    echo "publication verifier accepted an ARN/account ID" >&2
    exit 1
fi
grep -F 'prohibited secret or unsanitized infrastructure coordinate' \
    "$test_root/leaky.err" >/dev/null

jq '.run_id = "different-run"' "$test_root/replacement.json" > "$test_root/mismatch.json"
if "$verifier" "$reference" "$test_root/mismatch.json" \
    > "$test_root/mismatch.out" 2> "$test_root/mismatch.err"; then
    echo "publication verifier accepted cross-run receipts" >&2
    exit 1
fi
grep -F 'do not describe one deployment/run' "$test_root/mismatch.err" >/dev/null

printf '%s\n' 'replacement proof and publication receipt mock tests passed'
