#!/bin/sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)

for command_name in aws curl jq terraform; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "required command not found: $command_name" >&2
        exit 69
    fi
done

fail() {
    echo "$1" >&2
    exit "${2:-70}"
}

run_id=${1:-$(date -u +%Y%m%dT%H%M%SZ)-$$}
case "$run_id" in
    ''|-*|*[!A-Za-z0-9._-]*)
        fail "run id must contain only ASCII letters, digits, dot, underscore, or hyphen and cannot start with hyphen" 64
        ;;
esac
if [ "${#run_id}" -gt 64 ]; then
    fail "run id must be at most 64 characters" 64
fi

task=$(terraform -chdir="$script_dir" output -json reference_agent_task)
if ! printf '%s' "$task" | jq -e '
    type == "object" and
    (.region | type == "string" and length > 0) and
    (.cluster | type == "string" and length > 0) and
    (.task_definition | type == "string" and length > 0) and
    (.container_name | type == "string" and length > 0) and
    (.log_group | type == "string" and length > 0) and
    (.subnets | type == "array" and length > 0 and
        all(.[]; type == "string" and length > 0)) and
    (.security_groups | type == "array" and length > 0 and
        all(.[]; type == "string" and length > 0)) and
    (.assign_public_ip == "ENABLED" or .assign_public_ip == "DISABLED")
' >/dev/null; then
    fail "Terraform reference_agent_task output is missing required deployment fields"
fi

region=$(printf '%s' "$task" | jq -er '.region')
cluster=$(printf '%s' "$task" | jq -er '.cluster')
task_definition=$(printf '%s' "$task" | jq -er '.task_definition')
container_name=$(printf '%s' "$task" | jq -er '.container_name')
log_group=$(printf '%s' "$task" | jq -er '.log_group')
task_definition_coordinate=${task_definition##*/}
case "$task_definition_coordinate" in
    ''|*[!A-Za-z0-9._:/+=,@-]*)
        fail "Terraform returned an invalid reference-agent task definition coordinate"
        ;;
esac
network_configuration=$(printf '%s' "$task" | jq -cer '{
    awsvpcConfiguration: {
        subnets: .subnets,
        securityGroups: .security_groups,
        assignPublicIp: .assign_public_ip
    }
}')
unset task

demo_url=$(terraform -chdir="$script_dir" output -raw demo_url)
demo_url=${demo_url%/}
if ! jq -en --arg url "$demo_url" '
    $url | test("^https://[^[:space:]@/#]+(?::[0-9]+)?(?:/[^[:space:]#]*)?$")
' >/dev/null; then
    fail "Terraform demo_url must be an HTTPS URL without credentials or a fragment"
fi

curl_get() {
    curl --fail --silent --show-error \
        --connect-timeout 5 --max-time 10 \
        --retry 4 --retry-all-errors --retry-delay 1 --retry-max-time 30 \
        "$1"
}

curl_post_json() {
    curl --fail --silent --show-error \
        --connect-timeout 5 --max-time 15 \
        --retry 4 --retry-all-errors --retry-delay 1 --retry-max-time 30 \
        --header 'content-type: application/json' \
        --data "$1" "$2"
}

if ! health=$(curl_get "$demo_url/healthz"); then
    fail "public demo health check failed before the reference-agent run: $demo_url/healthz"
fi
if ! printf '%s' "$health" | jq -e '.status == "ready"' >/dev/null; then
    fail "public demo was reachable but not ready before the reference-agent run"
fi
unset health

if ! status=$(curl_get "$demo_url/api/status"); then
    fail "public demo status probe failed before the reference-agent run: $demo_url/api/status"
fi
if ! status_receipt=$(printf '%s' "$status" | jq -ce '
    select(
        .data.status == "ready" and
        (.data.database.version | type == "string" and
            (ascii_downcase | contains("cockroachdb"))) and
        .data.database.vector_index_enabled == true and
        .data.database.lexical_index_enabled == true and
        .data.database.conflict_membership_index_enabled == true and
        .data.database.claim_support_chunk_index_enabled == true and
        .data.database.cosine_distance_supported == true and
        .data.database.schema_version == 2 and
        (.data.embedding_model | type == "string" and length > 0) and
        .data.embedding_dimension == 512
    ) |
    {
        cockroachdb_version: .data.database.version,
        vector_index_enabled: .data.database.vector_index_enabled,
        lexical_index_enabled: .data.database.lexical_index_enabled,
        conflict_membership_index_enabled:
            .data.database.conflict_membership_index_enabled,
        claim_support_chunk_index_enabled:
            .data.database.claim_support_chunk_index_enabled,
        cosine_distance_supported: .data.database.cosine_distance_supported,
        schema_version: .data.database.schema_version,
        embedding_model: .data.embedding_model,
        embedding_dimension: .data.embedding_dimension
    }
' 2>/dev/null); then
    fail "public demo status did not prove the required CockroachDB retrieval capabilities"
fi
capability_evidence=$(printf '%s' "$status_receipt" | jq -c 'del(.cockroachdb_version, .embedding_model)')
cockroachdb_version=$(printf '%s' "$status_receipt" | jq -er '.cockroachdb_version')
embedding_model=$(printf '%s' "$status_receipt" | jq -er '.embedding_model')
unset status status_receipt

describe_failure() {
    step=$1
    description=$2
    exit_code=$(printf '%s' "$description" | jq -r --arg name "$container_name" \
        '[.tasks[0].containers[]? | select(.name == $name) | .exitCode] | first // empty' \
        2>/dev/null || true)
    reason=$(printf '%s' "$description" | jq -r --arg name "$container_name" \
        '[.tasks[0].containers[]? | select(.name == $name) | .reason] | first // empty' \
        2>/dev/null || true)
    stopped_reason=$(printf '%s' "$description" | jq -r \
        '.tasks[0].stoppedReason // empty' 2>/dev/null || true)
    echo "reference-agent step $step failed (exit=${exit_code:-missing})" >&2
    [ -z "$reason" ] || echo "container reason: $reason" >&2
    [ -z "$stopped_reason" ] || echo "task stopped reason: $stopped_reason" >&2
}

run_step() {
    step=$1
    evidence_step=$2
    agent=$3
    overrides=$(jq -cn \
        --arg name "$container_name" \
        --arg step "$step" \
        --arg run "$run_id" \
        --arg agent "$agent" '{
        containerOverrides: [{
            name: $name,
            command: ["reference-agent", "--step", $step, "--run-id", $run],
            environment: [{name: "FLEET_RECALL_AGENT", value: $agent}]
        }]
    }')

    if ! run_result=$(aws ecs run-task \
        --region "$region" \
        --cluster "$cluster" \
        --task-definition "$task_definition" \
        --launch-type FARGATE \
        --count 1 \
        --network-configuration "$network_configuration" \
        --overrides "$overrides" \
        --output json); then
        fail "ECS run-task failed for reference-agent step $step"
    fi
    if ! printf '%s' "$run_result" | jq -e \
        --arg name "$container_name" \
        --arg step "$step" \
        --arg run "$run_id" \
        --arg agent "$agent" \
        --arg task_definition "$task_definition" '
        (.failures // [] | length) == 0 and
        (.tasks | type == "array" and length == 1) and
        (.tasks[0].taskArn | type == "string" and length > 0) and
        .tasks[0].taskDefinitionArn == $task_definition and
        .tasks[0].launchType == "FARGATE" and
        ([.tasks[0].overrides.containerOverrides[]? | select(.name == $name)] | length) == 1 and
        ([.tasks[0].overrides.containerOverrides[]? | select(.name == $name)][0].command ==
            ["reference-agent", "--step", $step, "--run-id", $run]) and
        ([.tasks[0].overrides.containerOverrides[]? | select(.name == $name)][0].environment |
            any(.name == "FLEET_RECALL_AGENT" and .value == $agent))
    ' >/dev/null; then
        echo "ECS did not accept the exact reference-agent override for step $step" >&2
        printf '%s' "$run_result" | jq -c '{failures: (.failures // []), tasks: [.tasks[]? | {taskArn, taskDefinitionArn, launchType}]}' >&2 || true
        exit 70
    fi
    task_arn=$(printf '%s' "$run_result" | jq -er '.tasks[0].taskArn')
    task_id=${task_arn##*/}
    case "$task_id" in
        ''|*[!A-Za-z0-9_-]*) fail "ECS returned an invalid task id for step $step" ;;
    esac
    unset run_result overrides

    echo "waiting for reference-agent step $step ($task_id)" >&2
    if ! aws ecs wait tasks-stopped \
        --region "$region" --cluster "$cluster" --tasks "$task_arn"; then
        fail "ECS waiter failed before reference-agent step $step reached STOPPED"
    fi
    if ! description=$(aws ecs describe-tasks \
        --region "$region" --cluster "$cluster" --tasks "$task_arn" --output json); then
        fail "ECS describe-tasks failed for reference-agent step $step"
    fi
    if ! printf '%s' "$description" | jq -e \
        --arg arn "$task_arn" \
        --arg name "$container_name" \
        --arg task_definition "$task_definition" '
        (.failures // [] | length) == 0 and
        (.tasks | type == "array" and length == 1) and
        .tasks[0].taskArn == $arn and
        .tasks[0].taskDefinitionArn == $task_definition and
        .tasks[0].launchType == "FARGATE" and
        .tasks[0].lastStatus == "STOPPED" and
        ([.tasks[0].containers[]? | select(.name == $name)] | length) == 1 and
        ([.tasks[0].containers[]? | select(.name == $name)][0].exitCode == 0)
    ' >/dev/null; then
        describe_failure "$step" "$description"
        echo "logs: aws logs tail '$log_group' --region '$region' --since 30m" >&2
        exit 70
    fi
    stopped_at=$(printf '%s' "$description" | jq -r '.tasks[0].stoppedAt // empty')
    unset description

    log_stream=fleet/$container_name/$task_id
    attempt=0
    last_log_error=
    evidence=
    while [ "$attempt" -lt 20 ]; do
        if events=$(aws logs get-log-events \
            --region "$region" \
            --log-group-name "$log_group" \
            --log-stream-name "$log_stream" \
            --start-from-head \
            --output json 2>&1); then
            last_log_error=
            candidates=$(printf '%s' "$events" | jq -c \
                --arg run "$run_id" '
                [.events[]?.message | fromjson? |
                 select(.schema == "fleet-reference-agent-evidence-v1" and .run_id == $run)]
            ' 2>/dev/null || printf '%s' '[]')
            candidate_count=$(printf '%s' "$candidates" | jq -r 'length')
            if [ "$candidate_count" -gt 1 ]; then
                fail "multiple reference-agent evidence events were found in exact stream $log_stream"
            fi
            if [ "$candidate_count" -eq 1 ]; then
                evidence=$(printf '%s' "$candidates" | jq -ce \
                    --arg step "$evidence_step" \
                    --arg agent "$agent" '
                    .[0] |
                    select(
                        .step == $step and
                        .agent == $agent and
                        (.project | type == "string" and length > 0) and
                        .policy == "bounded-schema-migration-safety-v1" and
                        (.result | type == "object")
                    )
                ' 2>/dev/null || true)
                if [ -z "$evidence" ]; then
                    fail "reference-agent evidence in $log_stream did not match the expected step, agent, project, and policy"
                fi
                break
            fi
        else
            last_log_error=$events
        fi
        attempt=$((attempt + 1))
        [ "$attempt" -ge 20 ] || sleep 2
    done
    if [ -z "$evidence" ]; then
        echo "reference-agent evidence was not found in exact stream $log_stream" >&2
        [ -z "$last_log_error" ] || echo "last CloudWatch error: $last_log_error" >&2
        exit 70
    fi

    jq -cn \
        --arg step "$evidence_step" \
        --arg agent "$agent" \
        --arg task_id "$task_id" \
        --arg log_stream_suffix "$container_name/$task_id" \
        --arg stopped_at "$stopped_at" \
        --argjson evidence "$evidence" '{
            step: $step,
            agent: $agent,
            task_id: $task_id,
            log_stream_suffix: $log_stream_suffix,
            stopped_at: (if $stopped_at == "" then null else $stopped_at end),
            evidence: $evidence
        }'
}

record_receipt=$(run_step record-decision record_decision agent-a)
action_receipt=$(run_step recall-and-act recall_and_act agent-b)
conflict_receipt=$(run_step record-conflict record_conflict agent-c)
escalation_receipt=$(run_step \
    recall-conflict-and-escalate recall_conflict_and_escalate agent-b)

record=$(printf '%s' "$record_receipt" | jq -c '.evidence')
action=$(printf '%s' "$action_receipt" | jq -c '.evidence')
conflict=$(printf '%s' "$conflict_receipt" | jq -c '.evidence')
escalation=$(printf '%s' "$escalation_receipt" | jq -c '.evidence')

if ! chain=$(jq -cen \
    --arg run "$run_id" \
    --argjson record "$record" \
    --argjson action "$action" \
    --argjson conflict "$conflict" \
    --argjson escalation "$escalation" '
    def positive_integer: type == "number" and . > 0 and . == floor;
    def same_project:
        $record.project == $action.project and
        $record.project == $conflict.project and
        $record.project == $escalation.project;
    if
        same_project and
        ($record.result.claim_id | positive_integer) and
        $record.result.committed == true and
        ($record.result.first_was_replay | type) == "boolean" and
        $record.result.replay_deduplicated == true and
        ($action.result.action_claim_id | positive_integer) and
        $action.result.action == "hold workers until migration completes" and
        $action.result.retrieval_lanes == ["lexical", "dense"] and
        $action.result.fusion == "rrf" and
        $action.result.recalled_claim_id == $record.result.claim_id and
        $action.result.based_on_claim_id == $record.result.claim_id and
        ($conflict.result.claim_id | positive_integer) and
        $conflict.result.incompatible_value_recorded == true and
        ($conflict.result.conflict_id | positive_integer) and
        $conflict.result.decision_claim_id == $record.result.claim_id and
        $conflict.result.incompatible_claim_id == $conflict.result.claim_id and
        ($conflict.result.member_claim_ids | sort) ==
            ([$record.result.claim_id, $conflict.result.claim_id] | sort) and
        ($escalation.result.escalation_claim_id | positive_integer) and
        $escalation.result.action == "pause rollout for operator review" and
        $escalation.result.conflict_id == $conflict.result.conflict_id and
        $escalation.result.based_on_conflict_id == $conflict.result.conflict_id and
        $escalation.result.decision_claim_id == $record.result.claim_id and
        $escalation.result.incompatible_claim_id == $conflict.result.claim_id and
        ($escalation.result.member_claim_ids | sort) ==
            ($conflict.result.member_claim_ids | sort) and
        ([$record.result.claim_id, $action.result.action_claim_id,
          $conflict.result.claim_id, $escalation.result.escalation_claim_id] |
            unique | length) == 4
    then {
        run_id: $run,
        project: $record.project,
        recalled_claim_id: $record.result.claim_id,
        incompatible_claim_id: $conflict.result.incompatible_claim_id,
        action_claim_id: $action.result.action_claim_id,
        escalation_claim_id: $escalation.result.escalation_claim_id,
        conflict_id: $conflict.result.conflict_id,
        retrieval_lanes: $action.result.retrieval_lanes,
        fusion: $action.result.fusion,
        action: $action.result.action,
        escalation: $escalation.result.action
    }
    else error("reference-agent steps did not form one correlated memory/action/conflict chain")
    end
'); then
    fail "reference-agent steps did not form one correlated memory/action/conflict chain"
fi

verify_public_claim() {
    claim_kind=$1
    claim_id=$2
    query=$3
    request=$(jq -cn --arg query "$query" '{query: $query, limit: 20}')
    if ! response=$(curl_post_json "$request" "$demo_url/api/recall"); then
        fail "public demo recall failed while checking $claim_kind claim $claim_id"
    fi
    if ! printf '%s' "$response" | jq -e --argjson claim_id "$claim_id" '
        (.data.hits | type == "array") and
        any(.data.hits[]; .extra.claim_id == $claim_id) and
        .diagnostics.retrieval.lanes == ["lexical", "dense"] and
        .diagnostics.retrieval.fusion == "rrf"
    ' >/dev/null; then
        fail "public demo did not surface exact $claim_kind claim $claim_id through lexical+dense RRF"
    fi
    unset request response
}

action_claim_id=$(printf '%s' "$chain" | jq -er '.action_claim_id')
escalation_claim_id=$(printf '%s' "$chain" | jq -er '.escalation_claim_id')
verify_public_claim action "$action_claim_id" \
    "fleet deployment $run_id hold application workers until dedicated schema migrator completes"
verify_public_claim escalation "$escalation_claim_id" \
    "fleet deployment $run_id pause rollout incompatible migration strategies operator review"

jq -cen \
    --arg run "$run_id" \
    --arg region "$region" \
    --arg cluster "$cluster" \
    --arg task_definition "$task_definition_coordinate" \
    --arg log_stream_prefix "fleet/$container_name" \
    --arg demo_url "$demo_url" \
    --arg cockroachdb_version "$cockroachdb_version" \
    --arg embedding_model "$embedding_model" \
    --argjson capabilities "$capability_evidence" \
    --argjson chain "$chain" \
    --argjson record "$record_receipt" \
    --argjson action "$action_receipt" \
    --argjson conflict "$conflict_receipt" \
    --argjson escalation "$escalation_receipt" '{
    schema: "fleet-reference-agent-run-v1",
    verified: true,
    deployment: "amazon-ecs-fargate",
    run_id: $run,
    project: $chain.project,
    agents: ["agent-a", "agent-b", "agent-c"],
    memory: {
        recalled_claim_id: $chain.recalled_claim_id,
        incompatible_claim_id: $chain.incompatible_claim_id,
        open_conflict_id: $chain.conflict_id,
        retrieval_lanes: $chain.retrieval_lanes,
        fusion: $chain.fusion
    },
    actions: [
        {
            claim_id: $chain.action_claim_id,
            action: $chain.action,
            based_on_claim_id: $chain.recalled_claim_id
        },
        {
            claim_id: $chain.escalation_claim_id,
            action: $chain.escalation,
            based_on_conflict_id: $chain.conflict_id
        }
    ],
    aws: {
        region: $region,
        cluster: $cluster,
        task_definition: $task_definition,
        log_stream_prefix: $log_stream_prefix,
        tasks: [$record, $action, $conflict, $escalation] |
            map(del(.evidence))
    },
    public_demo: {
        url: $demo_url,
        health: "ready",
        read_only_verification: true,
        exact_claim_ids_observed: [$chain.action_claim_id, $chain.escalation_claim_id],
        retrieval_lanes: ["lexical", "dense"],
        fusion: "rrf",
        database: "CockroachDB",
        cockroachdb_version: $cockroachdb_version,
        embedding_model: $embedding_model,
        cockroachdb_capabilities: $capabilities
    }
}'
