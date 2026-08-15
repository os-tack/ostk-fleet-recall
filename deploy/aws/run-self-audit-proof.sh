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
if ! jq -en --arg region "$region" --arg cluster "$cluster" --arg name "$container_name" '
    ($region | test("^[a-z]{2}(?:-gov)?-[a-z]+-[0-9]+$")) and
    ($cluster | test("^[A-Za-z0-9._+=,@-]+$")) and
    ($name | test("^[A-Za-z0-9._+=,@-]+$"))
' >/dev/null; then
    fail "Terraform returned an invalid region, cluster, or container coordinate"
fi
task_definition_coordinate=${task_definition##*/}
if ! jq -en --arg value "$task_definition_coordinate" '
    $value | test("^[A-Za-z0-9._+=,@-]+:[1-9][0-9]*$")
' >/dev/null; then
    fail "Terraform returned an invalid reference-agent task definition coordinate"
fi
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
    fail "public demo health check failed before the self-audit run: $demo_url/healthz"
fi
if ! printf '%s' "$health" | jq -e '.status == "ready"' >/dev/null; then
    fail "public demo was reachable but not ready before the self-audit run"
fi
unset health

if ! status=$(curl_get "$demo_url/api/status"); then
    fail "public demo status probe failed before the self-audit run: $demo_url/api/status"
fi
if ! capabilities=$(printf '%s' "$status" | jq -ce '
    select(
        .data.status == "ready" and
        (.data.database.version | type == "string" and
            (ascii_downcase | contains("cockroachdb"))) and
        .data.database.vector_index_enabled == true and
        .data.database.lexical_index_enabled == true and
        .data.database.conflict_membership_index_enabled == true and
        .data.database.claim_support_chunk_index_enabled == true and
        .data.database.cosine_distance_supported == true and
        .data.database.schema_version >= 2
    ) |
    {
        vector_index_enabled: .data.database.vector_index_enabled,
        lexical_index_enabled: .data.database.lexical_index_enabled,
        conflict_membership_index_enabled:
            .data.database.conflict_membership_index_enabled,
        claim_support_chunk_index_enabled:
            .data.database.claim_support_chunk_index_enabled,
        cosine_distance_supported: .data.database.cosine_distance_supported,
        schema_version: .data.database.schema_version
    }
' 2>/dev/null); then
    fail "public demo status did not prove CockroachDB schema 2 or newer and source-conflict projection capabilities"
fi
unset status

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
    echo "self-audit step $step failed (exit=${exit_code:-missing})" >&2
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
        fail "ECS run-task failed for self-audit step $step"
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
        (.tasks[0].overrides.containerOverrides | type == "array" and length == 1) and
        .tasks[0].overrides.containerOverrides[0].name == $name and
        .tasks[0].overrides.containerOverrides[0].command ==
            ["reference-agent", "--step", $step, "--run-id", $run] and
        .tasks[0].overrides.containerOverrides[0].environment ==
            [{"name": "FLEET_RECALL_AGENT", "value": $agent}]
    ' >/dev/null; then
        fail "ECS did not accept the exact self-audit override for step $step"
    fi
    task_arn=$(printf '%s' "$run_result" | jq -er '.tasks[0].taskArn')
    task_id=${task_arn##*/}
    case "$task_id" in
        ''|*[!A-Za-z0-9_-]*) fail "ECS returned an invalid task id for step $step" ;;
    esac
    unset run_result overrides

    echo "waiting for self-audit step $step ($task_id)" >&2
    if ! aws ecs wait tasks-stopped \
        --region "$region" --cluster "$cluster" --tasks "$task_arn"; then
        fail "ECS waiter failed before self-audit step $step reached STOPPED"
    fi
    if ! description=$(aws ecs describe-tasks \
        --region "$region" --cluster "$cluster" --tasks "$task_arn" --output json); then
        fail "ECS describe-tasks failed for self-audit step $step"
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
        exit 70
    fi
    stopped_at=$(printf '%s' "$description" | jq -r '.tasks[0].stoppedAt // empty')
    if [ -n "$stopped_at" ] && ! jq -en --arg value "$stopped_at" '
        $value | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+(?:Z|[+-][0-9]{2}:[0-9]{2})$")
    ' >/dev/null; then
        fail "ECS returned an invalid stopped timestamp for step $step"
    fi
    unset description

    log_stream=fleet/$container_name/$task_id
    attempt=0
    evidence=
    while [ "$attempt" -lt 20 ]; do
        if events=$(aws logs get-log-events \
            --region "$region" \
            --log-group-name "$log_group" \
            --log-stream-name "$log_stream" \
            --start-from-head \
            --output json 2>/dev/null); then
            candidates=$(printf '%s' "$events" | jq -c '
                [.events[]?.message | fromjson? |
                 select(.schema == "fleet-reference-agent-evidence-v1")]
            ' 2>/dev/null || printf '%s' '[]')
            candidate_count=$(printf '%s' "$candidates" | jq -r 'length')
            if [ "$candidate_count" -gt 1 ]; then
                fail "multiple structured reference-agent evidence events were found for self-audit step $step"
            fi
            if [ "$candidate_count" -eq 1 ]; then
                evidence=$(printf '%s' "$candidates" | jq -ce \
                    --arg run "$run_id" \
                    --arg step "$evidence_step" \
                    --arg agent "$agent" '
                    .[0] |
                    select(
                        .schema == "fleet-reference-agent-evidence-v1" and
                        .run_id == $run and
                        .step == $step and
                        .agent == $agent and
                        (.project | type == "string" and length > 0 and length <= 128 and
                            test("^[^[:cntrl:]]+$")) and
                        .policy == "source-backed-mcp-contract-self-audit-v1" and
                        (.result | type == "object")
                    )
                ' 2>/dev/null || true)
                if [ -z "$evidence" ]; then
                    fail "self-audit evidence did not match the exact schema, run, step, agent, project, and policy"
                fi
                break
            fi
        fi
        attempt=$((attempt + 1))
        [ "$attempt" -ge 20 ] || sleep 2
    done
    if [ -z "$evidence" ]; then
        fail "structured self-audit evidence was not found for step $step"
    fi

    jq -cn \
        --arg step "$evidence_step" \
        --arg agent "$agent" \
        --arg task_id "$task_id" \
        --arg stopped_at "$stopped_at" \
        --argjson evidence "$evidence" '{
        step: $step,
        agent: $agent,
        task_id: $task_id,
        stopped_at: (if $stopped_at == "" then null else $stopped_at end),
        evidence: $evidence
    }'
}

spec_receipt=$(run_step \
    record-retraction-spec-claim record_retraction_spec_claim agent-a)
implementation_receipt=$(run_step \
    record-retraction-implementation-claim \
    record_retraction_implementation_claim agent-c)

spec_task_id=$(printf '%s' "$spec_receipt" | jq -er '.task_id')
implementation_task_id=$(printf '%s' "$implementation_receipt" | jq -er '.task_id')
[ "$spec_task_id" != "$implementation_task_id" ] || \
    fail "self-audit steps unexpectedly reused one ECS task"

spec=$(printf '%s' "$spec_receipt" | jq -c '.evidence')
implementation=$(printf '%s' "$implementation_receipt" | jq -c '.evidence')

if ! chain=$(jq -cen \
    --arg run "$run_id" \
    --argjson spec "$spec" \
    --argjson implementation "$implementation" '
    def positive_integer: type == "number" and . > 0 and . == floor;
    def coordinate:
        type == "object" and
        (keys == ["chunk_id", "content_sha256", "source", "source_config_id", "source_id"]) and
        (.chunk_id | type == "string" and length > 0 and length <= 256 and
            test("^[A-Za-z0-9._:@/+,-]+$")) and
        (.content_sha256 | type == "string" and test("^[0-9a-f]{64}$"));
    def has_coordinate($source; $source_id; $config):
        any(.[];
            coordinate and
            .source == $source and
            .source_id == $source_id and
            .source_config_id == $config);
    if
        $spec.run_id == $run and
        $implementation.run_id == $run and
        $spec.project == $implementation.project and
        ($spec.result.claim_id | positive_integer) and
        $spec.result.value == true and
        $spec.result.retrieval_lanes == ["lexical", "dense"] and
        $spec.result.fusion == "rrf" and
        ($spec.result.source_coordinates | type == "array" and length == 1 and
            has_coordinate("markdown"; "examples/README.md"; "rich-demo:docs:v1")) and
        ($implementation.result.claim_id | positive_integer) and
        $implementation.result.claim_id != $spec.result.claim_id and
        $implementation.result.value == false and
        $implementation.result.retrieval_lanes == ["lexical", "dense"] and
        $implementation.result.fusion == "rrf" and
        ($implementation.result.source_coordinates |
            type == "array" and length == 2 and
            has_coordinate("code"; "src/mcp/tools.rs"; "rich-demo:self-audit:v1") and
            has_coordinate("code"; "src/application.rs"; "rich-demo:self-audit:v1") and
            ([.[].chunk_id] | unique | length) == 2) and
        ($implementation.result.conflict_id | positive_integer) and
        $implementation.result.spec_claim_id == $spec.result.claim_id and
        $implementation.result.implementation_claim_id ==
            $implementation.result.claim_id and
        ($implementation.result.member_claim_ids | type == "array" and length == 2 and
            sort == ([$spec.result.claim_id, $implementation.result.claim_id] | sort))
    then {
        run_id: $run,
        project: $spec.project,
        spec_claim_id: $spec.result.claim_id,
        implementation_claim_id: $implementation.result.claim_id,
        conflict_id: $implementation.result.conflict_id,
        member_claim_ids: ($implementation.result.member_claim_ids | sort),
        source_coordinates:
            ($spec.result.source_coordinates + $implementation.result.source_coordinates)
    }
    else error("self-audit steps did not form one source-backed Boolean conflict")
    end
'); then
    fail "self-audit steps did not form one source-backed Boolean conflict"
fi

query='Does MCP remember support deliberate retractions?'
request=$(jq -cn --arg query "$query" '{query: $query, limit: 8}')
if ! response=$(curl_post_json "$request" "$demo_url/api/recall"); then
    fail "public semantic recall failed after the self-audit run"
fi
if ! public_observation=$(printf '%s' "$response" | jq -ce \
    --argjson chain "$chain" '
    def positive_integer: type == "number" and . > 0 and . == floor;
    . as $response |
    ($chain.source_coordinates | map({
        chunk_id: .chunk_id,
        source: .source,
        source_id: .source_id
    })) as $coordinates |
    ([.data.hits[]? as $hit | $coordinates[] |
        select(
            $hit.chunk_id == .chunk_id and
            $hit.source == .source and
            $hit.source_id == .source_id
        )] | unique_by(.chunk_id)) as $surfaced |
    ([.conflicts[]? |
        select(
            .id == $chain.conflict_id and
            .state == "open" and
            .member_count == 2 and
            .members_truncated == false and
            .member_values_elided == false and
            (.members | type == "array" and length == 2) and
            ([.members[].id] | sort) == ($chain.member_claim_ids | sort) and
            (any(.members[];
                .id == $chain.spec_claim_id and .actor == "agent-a" and
                .kind == "fact" and .value == true)) and
            (any(.members[];
                .id == $chain.implementation_claim_id and .actor == "agent-c" and
                .kind == "fact" and .value == false))
        )]) as $matching_conflicts |
    select(
        (.data.hits | type == "array" and length > 0) and
        ($surfaced | length) > 0 and
        ($matching_conflicts | length) == 1 and
        (.diagnostics.retrieval.support_claims_matched | positive_integer) and
        .diagnostics.retrieval.support_claims_truncated == false and
        .diagnostics.retrieval.lanes == ["lexical", "dense"] and
        .diagnostics.retrieval.fusion == "rrf"
    ) |
    {
        retrieval_lanes: .diagnostics.retrieval.lanes,
        fusion: .diagnostics.retrieval.fusion,
        support_claims_matched: .diagnostics.retrieval.support_claims_matched,
        support_claims_truncated: .diagnostics.retrieval.support_claims_truncated,
        surfaced_source_chunks: $surfaced,
        conflict_state: $matching_conflicts[0].state,
        conflict_member_count: $matching_conflicts[0].member_count
    }
' 2>/dev/null); then
    fail "public semantic recall did not project the exact open source-backed two-member conflict"
fi
unset request response

receipt=$(jq -cen \
    --arg run "$run_id" \
    --arg region "$region" \
    --arg cluster "$cluster" \
    --arg task_definition "$task_definition_coordinate" \
    --arg demo_url "$demo_url" \
    --arg query "$query" \
    --argjson capabilities "$capabilities" \
    --argjson chain "$chain" \
    --argjson spec "$spec_receipt" \
    --argjson implementation "$implementation_receipt" \
    --argjson observation "$public_observation" '{
    schema: "fleet-source-conflict-self-audit-run-v1",
    verified: true,
    deployment: "amazon-ecs-fargate",
    run_id: $run,
    project: $chain.project,
    evidence_schema: "fleet-reference-agent-evidence-v1",
    policy: "source-backed-mcp-contract-self-audit-v1",
    claims: {
        spec: {
            claim_id: $chain.spec_claim_id,
            actor: "agent-a",
            value: true,
            source_coordinates: $spec.evidence.result.source_coordinates
        },
        implementation: {
            claim_id: $chain.implementation_claim_id,
            actor: "agent-c",
            value: false,
            source_coordinates: $implementation.evidence.result.source_coordinates
        }
    },
    conflict: {
        conflict_id: $chain.conflict_id,
        state: $observation.conflict_state,
        member_count: $observation.conflict_member_count,
        member_claim_ids: $chain.member_claim_ids,
        surfaced_by_semantic_recall: true
    },
    retrieval: ($observation + {query: $query}),
    cockroachdb_capabilities: $capabilities,
    aws: {
        region: $region,
        cluster: $cluster,
        task_definition: $task_definition,
        tasks: [$spec, $implementation] | map(del(.evidence))
    },
    public_demo: {
        url: $demo_url,
        health: "ready",
        read_only_verification: true
    }
}')

# Fail closed if a future edit accidentally publishes a raw cloud/log/secret
# coordinate. Source hashes and bounded task IDs are intentional evidence.
# This is deliberately one positive "safe receipt" predicate: a jq parse or
# compilation error therefore rejects the artifact instead of bypassing it.
if ! printf '%s' "$receipt" | jq -e '
    . as $root |
    (type == "object") and
    all(paths(strings);
        . as $path |
        ($root | getpath($path)) as $value |
        (($value | test("arn:(aws|aws-us-gov|aws-cn):"; "i")) | not) and
        (($path[-1] | tostring) == "content_sha256" or
            (($value | test("(^|[^0-9])[0-9]{12}([^0-9]|$)")) | not)) and
        (($value | test("postgres(?:ql)?://"; "i")) | not) and
        (($value | test("[a-z][a-z0-9+.-]*://[^/@[:space:]]+@"; "i")) | not) and
        (($value | test("(^|[^A-Z0-9])(AKIA|ASIA)[A-Z0-9]{16}([^A-Z0-9]|$)")) | not)) and
    all(paths(scalars);
        ((.[-1] | tostring | ascii_downcase |
            test("^(password|passwd|database_url|secret_arn|task_arn|task_definition_arn|log_group|log_stream|log_stream_prefix|log_stream_suffix|access_key|secret_access_key|session_token|authorization)$")) | not))
' >/dev/null; then
    fail "self-audit receipt contains a prohibited secret or unsanitized infrastructure/log coordinate"
fi

printf '%s\n' "$receipt"
