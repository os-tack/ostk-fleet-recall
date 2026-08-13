#!/bin/sh
set -eu

mock_state=${MOCK_STATE_DIR:-}
mock_scenario=${MOCK_SCENARIO:-success}

case "$(basename -- "$0")" in
    aws|curl|terraform) ;;
    *)
        for command_name in jq sed; do
            if ! command -v "$command_name" >/dev/null 2>&1; then
                echo "required test command not found: $command_name" >&2
                exit 69
            fi
        done
        ;;
esac

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
        *' output -json reference_agent_task '*)
            printf '%s\n' '{
              "region":"us-east-1",
              "cluster":"fleet-cluster",
              "task_definition":"arn:aws:ecs:us-east-1:123456789012:task-definition/fleet-reference-agent:7",
              "container_name":"fleet-recall",
              "subnets":["subnet-a","subnet-b"],
              "security_groups":["sg-fleet"],
              "assign_public_ip":"ENABLED",
              "log_group":"/ecs/fleet-recall"
            }'
            ;;
        *' output -raw demo_url '*)
            if [ "$mock_scenario" = insecure-demo ]; then
                printf '%s' 'http://fleet.example.test'
            else
                printf '%s' 'https://fleet.example.test'
            fi
            ;;
        *)
            echo "unexpected terraform mock arguments: $*" >&2
            exit 96
            ;;
    esac
}

mock_curl() {
    [ -n "$mock_state" ] || exit 96
    call_file=$mock_state/curl-count
    call_count=0
    [ ! -f "$call_file" ] || read -r call_count < "$call_file"
    call_count=$((call_count + 1))
    printf '%s\n' "$call_count" > "$call_file"

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
            http://*|https://*) url=$argument ;;
        esac
    done
    case "$url" in
        https://fleet.example.test/healthz)
            printf '%s\n' '{"status":"ready"}'
            ;;
        https://fleet.example.test/api/status)
            printf '%s\n' '{
              "data": {
                "status":"ready",
                "database": {
                  "version":"CockroachDB CCL v26.2.0",
                  "vector_index_enabled":true,
                  "lexical_index_enabled":true,
                  "conflict_membership_index_enabled":true,
                  "cosine_distance_supported":true,
                  "schema_version":12
                },
                "embedding_model":"minishlab/potion-retrieval-32M",
                "embedding_dimension":512
              }
            }'
            ;;
        https://fleet.example.test/api/recall)
            query=$(printf '%s' "$data" | jq -er '.query')
            case "$query" in
                *'hold application workers until dedicated schema migrator completes'*)
                    claim_id=102
                    ;;
                *'pause rollout incompatible migration strategies operator review'*)
                    claim_id=104
                    if [ "$mock_scenario" = demo-mismatch ]; then
                        claim_id=999
                    fi
                    ;;
                *)
                    echo "unexpected public recall query: $query" >&2
                    exit 96
                    ;;
            esac
            jq -cn --argjson claim_id "$claim_id" '{
                data: {hits: [{extra: {claim_id: $claim_id}}]},
                diagnostics: {retrieval: {lanes: ["lexical", "dense"], fusion: "rrf"}}
            }'
            ;;
        *)
            echo "unexpected curl mock URL: $url" >&2
            exit 96
            ;;
    esac
}

mock_run_task() {
    overrides=$(argument_value --overrides "$@")
    cluster=$(argument_value --cluster "$@")
    task_definition=$(argument_value --task-definition "$@")
    launch_type=$(argument_value --launch-type "$@")
    count=$(argument_value --count "$@")
    [ "$cluster" = fleet-cluster ] || exit 96
    [ "$task_definition" = 'arn:aws:ecs:us-east-1:123456789012:task-definition/fleet-reference-agent:7' ] || exit 96
    [ "$launch_type" = FARGATE ] || exit 96
    [ "$count" = 1 ] || exit 96

    step=$(printf '%s' "$overrides" | jq -er '.containerOverrides[0].command[2]')
    run_id=$(printf '%s' "$overrides" | jq -er '.containerOverrides[0].command[4]')
    agent=$(printf '%s' "$overrides" | jq -er \
        '.containerOverrides[0].environment[] | select(.name == "FLEET_RECALL_AGENT") | .value')

    count_file=$mock_state/run-count
    run_count=0
    [ ! -f "$count_file" ] || read -r run_count < "$count_file"
    run_count=$((run_count + 1))
    printf '%s\n' "$run_count" > "$count_file"
    case "$run_count:$step:$agent" in
        1:record-decision:agent-a|2:recall-and-act:agent-b|3:record-conflict:agent-c|4:recall-conflict-and-escalate:agent-b) ;;
        *)
            echo "unexpected reference-agent sequence: $run_count:$step:$agent" >&2
            exit 96
            ;;
    esac

    task_id=task-$run_count
    printf '%s\n' "$step" > "$mock_state/$task_id.step"
    printf '%s\n' "$run_id" > "$mock_state/$task_id.run"
    printf '%s\n' "$agent" > "$mock_state/$task_id.agent"
    task_arn=arn:aws:ecs:us-east-1:123456789012:task/fleet-cluster/$task_id
    jq -cn \
        --arg arn "$task_arn" \
        --arg task_definition "$task_definition" \
        --argjson overrides "$overrides" '{
        failures: [],
        tasks: [{
            taskArn: $arn,
            taskDefinitionArn: $task_definition,
            launchType: "FARGATE",
            overrides: $overrides
        }]
    }'
}

mock_describe_tasks() {
    task_arn=$(argument_value --tasks "$@")
    task_id=${task_arn##*/}
    step=$(sed -n '1p' "$mock_state/$task_id.step")
    exit_code=0
    reason=
    stopped_reason='Essential container in task exited'
    if [ "$mock_scenario" = task-failure ] && [ "$step" = recall-and-act ]; then
        exit_code=23
        reason='policy invariant failed'
    fi
    jq -cn \
        --arg arn "$task_arn" \
        --arg reason "$reason" \
        --arg stopped_reason "$stopped_reason" \
        --argjson exit_code "$exit_code" '{
        failures: [],
        tasks: [{
            taskArn: $arn,
            taskDefinitionArn: "arn:aws:ecs:us-east-1:123456789012:task-definition/fleet-reference-agent:7",
            launchType: "FARGATE",
            lastStatus: "STOPPED",
            stoppedAt: "2026-08-13T19:00:00Z",
            stoppedReason: $stopped_reason,
            containers: [{name: "fleet-recall", exitCode: $exit_code, reason: $reason}]
        }]
    }'
}

mock_log_events() {
    log_stream=$(argument_value --log-stream-name "$@")
    task_id=${log_stream##*/}
    step=$(sed -n '1p' "$mock_state/$task_id.step")
    run_id=$(sed -n '1p' "$mock_state/$task_id.run")
    agent=$(sed -n '1p' "$mock_state/$task_id.agent")
    case "$step" in
        record-decision)
            evidence_step=record_decision
            result='{"claim_id":101,"committed":true,"first_was_replay":false,"replay_deduplicated":true}'
            ;;
        recall-and-act)
            evidence_step=recall_and_act
            result='{"recalled_claim_id":101,"retrieval_lanes":["lexical","dense"],"fusion":"rrf","action":"hold workers until migration completes","action_claim_id":102,"based_on_claim_id":101}'
            if [ "$mock_scenario" = chain-mismatch ]; then
                result='{"recalled_claim_id":101,"retrieval_lanes":["lexical","dense"],"fusion":"rrf","action":"hold workers until migration completes","action_claim_id":102,"based_on_claim_id":999}'
            fi
            ;;
        record-conflict)
            evidence_step=record_conflict
            result='{"claim_id":103,"incompatible_value_recorded":true,"conflict_id":501,"member_claim_ids":[101,103],"decision_claim_id":101,"incompatible_claim_id":103}'
            ;;
        recall-conflict-and-escalate)
            evidence_step=recall_conflict_and_escalate
            result='{"conflict_id":501,"member_claim_ids":[103,101],"decision_claim_id":101,"incompatible_claim_id":103,"action":"pause rollout for operator review","escalation_claim_id":104,"based_on_conflict_id":501}'
            ;;
        *) exit 96 ;;
    esac
    evidence=$(jq -cn \
        --arg run "$run_id" \
        --arg step "$evidence_step" \
        --arg agent "$agent" \
        --argjson result "$result" '{
        schema: "fleet-reference-agent-evidence-v1",
        run_id: $run,
        step: $step,
        agent: $agent,
        project: "fleet-project",
        policy: "bounded-schema-migration-safety-v1",
        result: $result
    }')
    if [ "$mock_scenario" = duplicate-evidence ] && [ "$step" = recall-and-act ]; then
        jq -cn --arg message "$evidence" '{events: [{message: $message}, {message: $message}]}'
    else
        jq -cn --arg message "$evidence" '{events: [{message: "ordinary log"}, {message: $message}]}'
    fi
}

mock_aws() {
    [ -n "$mock_state" ] || exit 96
    service=$1
    operation=$2
    shift 2
    case "$service:$operation" in
        ecs:run-task) mock_run_task "$@" ;;
        ecs:wait) : ;;
        ecs:describe-tasks) mock_describe_tasks "$@" ;;
        logs:get-log-events) mock_log_events "$@" ;;
        *)
            echo "unexpected aws mock operation: $service $operation" >&2
            exit 96
            ;;
    esac
}

case "$(basename -- "$0")" in
    aws) mock_aws "$@"; exit ;;
    curl) mock_curl "$@"; exit ;;
    terraform) mock_terraform "$@"; exit ;;
esac

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
wrapper=$script_dir/../run-reference-agent.sh
test_root=$(mktemp -d "${TMPDIR:-/tmp}/fleet-reference-agent-test.XXXXXX")
trap 'rm -rf "$test_root"' EXIT HUP INT TERM
mock_bin=$test_root/bin
mkdir -p "$mock_bin"
self=$script_dir/$(basename -- "$0")
ln -s "$self" "$mock_bin/aws"
ln -s "$self" "$mock_bin/curl"
ln -s "$self" "$mock_bin/terraform"

run_mock() {
    state=$1
    scenario=$2
    run=$3
    mkdir -p "$state"
    PATH="$mock_bin:$PATH" MOCK_STATE_DIR="$state" MOCK_SCENARIO="$scenario" \
        "$wrapper" "$run"
}

success_state=$test_root/success
run_mock "$success_state" success mock-run-1 \
    > "$test_root/success.json" 2> "$test_root/success.err"
jq -e '
    .schema == "fleet-reference-agent-run-v1" and
    .verified == true and
    .deployment == "amazon-ecs-fargate" and
    .run_id == "mock-run-1" and
    .project == "fleet-project" and
    .agents == ["agent-a", "agent-b", "agent-c"] and
    .memory == {
        recalled_claim_id: 101,
        incompatible_claim_id: 103,
        open_conflict_id: 501,
        retrieval_lanes: ["lexical", "dense"],
        fusion: "rrf"
    } and
    [.actions[].claim_id] == [102, 104] and
    (.aws.tasks | length) == 4 and
    [.aws.tasks[].step] == [
        "record_decision", "recall_and_act", "record_conflict",
        "recall_conflict_and_escalate"
    ] and
    .aws.task_definition == "fleet-reference-agent:7" and
    .aws.log_stream_prefix == "fleet/fleet-recall" and
    all(.aws.tasks[]; (.task_id | startswith("task-")) and
        (.log_stream_suffix | startswith("fleet-recall/task-"))) and
    .public_demo.url == "https://fleet.example.test" and
    .public_demo.health == "ready" and
    .public_demo.read_only_verification == true and
    .public_demo.exact_claim_ids_observed == [102, 104] and
    .public_demo.database == "CockroachDB" and
    .public_demo.cockroachdb_version == "CockroachDB CCL v26.2.0" and
    .public_demo.embedding_model == "minishlab/potion-retrieval-32M" and
    .public_demo.cockroachdb_capabilities == {
        vector_index_enabled: true,
        lexical_index_enabled: true,
        conflict_membership_index_enabled: true,
        cosine_distance_supported: true,
        schema_version: 12,
        embedding_dimension: 512
    }
' "$test_root/success.json" >/dev/null
if grep -Eq 'arn:|[0-9]{12}' "$test_root/success.json"; then
    echo "successful evidence leaked an AWS ARN or account ID" >&2
    exit 1
fi
[ "$(sed -n '1p' "$success_state/run-count")" = 4 ]
[ "$(sed -n '1p' "$success_state/curl-count")" = 4 ]

if run_mock "$test_root/invalid-run" success -clap-option \
    > "$test_root/invalid-run.out" 2> "$test_root/invalid-run.err"; then
    echo "wrapper accepted a run id that Clap would parse as an option" >&2
    exit 1
fi
grep -F 'cannot start with hyphen' "$test_root/invalid-run.err" >/dev/null

if run_mock "$test_root/insecure-demo" insecure-demo mock-run-http \
    > "$test_root/insecure-demo.out" 2> "$test_root/insecure-demo.err"; then
    echo "wrapper accepted an HTTP URL as publishable AWS evidence" >&2
    exit 1
fi
grep -F 'demo_url must be an HTTPS URL' "$test_root/insecure-demo.err" >/dev/null

failure_state=$test_root/task-failure
if run_mock "$failure_state" task-failure mock-run-2 \
    > "$test_root/task-failure.out" 2> "$test_root/task-failure.err"; then
    echo "wrapper accepted a nonzero reference-agent task exit" >&2
    exit 1
fi
grep -F 'reference-agent step recall-and-act failed (exit=23)' \
    "$test_root/task-failure.err" >/dev/null
[ "$(sed -n '1p' "$failure_state/run-count")" = 2 ]

duplicate_state=$test_root/duplicate
if run_mock "$duplicate_state" duplicate-evidence mock-run-3 \
    > "$test_root/duplicate.out" 2> "$test_root/duplicate.err"; then
    echo "wrapper accepted duplicate evidence in one exact log stream" >&2
    exit 1
fi
grep -F 'multiple reference-agent evidence events were found' \
    "$test_root/duplicate.err" >/dev/null
[ "$(sed -n '1p' "$duplicate_state/run-count")" = 2 ]

chain_state=$test_root/chain-mismatch
if run_mock "$chain_state" chain-mismatch mock-run-4 \
    > "$test_root/chain-mismatch.out" 2> "$test_root/chain-mismatch.err"; then
    echo "wrapper accepted an action citing a different recalled claim" >&2
    exit 1
fi
grep -F 'reference-agent steps did not form one correlated memory/action/conflict chain' \
    "$test_root/chain-mismatch.err" >/dev/null
[ "$(sed -n '1p' "$chain_state/run-count")" = 4 ]
[ "$(sed -n '1p' "$chain_state/curl-count")" = 2 ]

mismatch_state=$test_root/demo-mismatch
if run_mock "$mismatch_state" demo-mismatch mock-run-5 \
    > "$test_root/demo-mismatch.out" 2> "$test_root/demo-mismatch.err"; then
    echo "wrapper accepted a public demo response without the exact escalation claim" >&2
    exit 1
fi
grep -F 'public demo did not surface exact escalation claim 104' \
    "$test_root/demo-mismatch.err" >/dev/null
[ "$(sed -n '1p' "$mismatch_state/run-count")" = 4 ]
[ "$(sed -n '1p' "$mismatch_state/curl-count")" = 4 ]

printf '%s\n' 'reference-agent AWS wrapper mock tests passed'
