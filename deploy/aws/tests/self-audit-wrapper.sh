#!/bin/sh
set -eu

mock_state=${MOCK_STATE_DIR:-}
mock_scenario=${MOCK_SCENARIO:-success}

case "$(basename -- "$0")" in
    aws|curl|terraform) ;;
    *)
        for command_name in grep jq sed; do
            command -v "$command_name" >/dev/null 2>&1 || exit 69
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
              "task_definition":"arn:aws:ecs:us-east-1:123456789012:task-definition/fleet-reference-agent:8",
              "container_name":"fleet-recall",
              "subnets":["subnet-a","subnet-b"],
              "security_groups":["sg-fleet"],
              "assign_public_ip":"ENABLED",
              "log_group":"/ecs/fleet-recall"
            }'
            ;;
        *' output -raw demo_url '*) printf '%s' 'https://fleet.example.test' ;;
        *) echo "unexpected terraform mock arguments: $*" >&2; exit 96 ;;
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
        https://fleet.example.test/api/status)
            schema_version=2
            [ "$mock_scenario" != schema-mismatch ] || schema_version=1
            jq -cn --argjson schema_version "$schema_version" '{
                data: {
                    status: "ready",
                    database: {
                        version: "CockroachDB CCL v26.2.5",
                        vector_index_enabled: true,
                        lexical_index_enabled: true,
                        conflict_membership_index_enabled: true,
                        claim_support_chunk_index_enabled: true,
                        cosine_distance_supported: true,
                        schema_version: $schema_version
                    }
                }
            }'
            ;;
        https://fleet.example.test/api/recall)
            [ "$(printf '%s' "$data" | jq -er '.query')" = \
                'Does MCP remember support deliberate retractions?' ] || exit 96
            [ "$(printf '%s' "$data" | jq -er '.limit')" -eq 8 ] || exit 96
            conflict_state=open
            [ "$mock_scenario" != closed-conflict ] || conflict_state=resolved
            jq -cn --arg state "$conflict_state" '{
                data: {hits: [
                    {
                        chunk_id: "docs-retraction-1",
                        project: "fleet-project",
                        source: "markdown",
                        source_id: "examples/README.md",
                        snippet: "Use MCP remember for deliberate retractions"
                    },
                    {
                        chunk_id: "tools-record-only-1",
                        project: "fleet-project",
                        source: "code",
                        source_id: "src/mcp/tools.rs",
                        snippet: "remember action enum record only"
                    }
                ]},
                conflicts: [{
                    id: 501,
                    project: "fleet-project",
                    claim_key: "fleet-recall-self-audit-mock-run-1::mcp-remember-supports-deliberate-retractions",
                    kind: "fact",
                    state: $state,
                    member_count: 2,
                    members_truncated: false,
                    member_values_elided: false,
                    members: [
                        {id: 101, actor: "agent-a", kind: "fact", value: true},
                        {id: 102, actor: "agent-c", kind: "fact", value: false}
                    ]
                }],
                diagnostics: {retrieval: {
                    lanes: ["lexical", "dense"],
                    fusion: "rrf",
                    support_claims_matched: 2,
                    support_claims_truncated: false
                }}
            }'
            ;;
        *) echo "unexpected curl mock URL: $url" >&2; exit 96 ;;
    esac
}

mock_run_task() {
    overrides=$(argument_value --overrides "$@")
    [ "$(argument_value --cluster "$@")" = fleet-cluster ] || exit 96
    [ "$(argument_value --task-definition "$@")" = \
        'arn:aws:ecs:us-east-1:123456789012:task-definition/fleet-reference-agent:8' ] || exit 96
    [ "$(argument_value --launch-type "$@")" = FARGATE ] || exit 96
    [ "$(argument_value --count "$@")" = 1 ] || exit 96

    step=$(printf '%s' "$overrides" | jq -er '.containerOverrides[0].command[2]')
    run_id=$(printf '%s' "$overrides" | jq -er '.containerOverrides[0].command[4]')
    agent=$(printf '%s' "$overrides" | jq -er \
        '.containerOverrides[0].environment[] | select(.name == "FLEET_RECALL_AGENT") | .value')
    if ! printf '%s' "$overrides" | jq -e \
        --arg step "$step" --arg run "$run_id" --arg agent "$agent" '
        . == {containerOverrides: [{
            name: "fleet-recall",
            command: ["reference-agent", "--step", $step, "--run-id", $run],
            environment: [{name: "FLEET_RECALL_AGENT", value: $agent}]
        }]}
    ' >/dev/null; then
        echo "wrapper sent a non-exact container override" >&2
        exit 96
    fi

    count_file=$mock_state/run-count
    run_count=0
    [ ! -f "$count_file" ] || read -r run_count < "$count_file"
    run_count=$((run_count + 1))
    printf '%s\n' "$run_count" > "$count_file"
    case "$run_count:$step:$agent" in
        1:record-retraction-spec-claim:agent-a) ;;
        2:record-retraction-implementation-claim:agent-c) ;;
        *) echo "unexpected self-audit sequence: $run_count:$step:$agent" >&2; exit 96 ;;
    esac

    task_id=self-audit-$run_count
    printf '%s\n' "$step" > "$mock_state/$task_id.step"
    printf '%s\n' "$run_id" > "$mock_state/$task_id.run"
    printf '%s\n' "$agent" > "$mock_state/$task_id.agent"
    task_arn=arn:aws:ecs:us-east-1:123456789012:task/fleet-cluster/$task_id
    jq -cn \
        --arg arn "$task_arn" \
        --argjson overrides "$overrides" '{
        failures: [],
        tasks: [{
            taskArn: $arn,
            taskDefinitionArn: "arn:aws:ecs:us-east-1:123456789012:task-definition/fleet-reference-agent:8",
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
    if [ "$mock_scenario" = task-failure ] && \
        [ "$step" = record-retraction-implementation-claim ]; then
        exit_code=23
        reason='self-audit invariant failed'
    fi
    jq -cn \
        --arg arn "$task_arn" \
        --arg reason "$reason" \
        --argjson exit_code "$exit_code" '{
        failures: [],
        tasks: [{
            taskArn: $arn,
            taskDefinitionArn: "arn:aws:ecs:us-east-1:123456789012:task-definition/fleet-reference-agent:8",
            launchType: "FARGATE",
            lastStatus: "STOPPED",
            stoppedAt: "2026-08-14T12:00:00Z",
            stoppedReason: "Essential container in task exited",
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
    a_hash=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    b_hash=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
    c_hash=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
    case "$step" in
        record-retraction-spec-claim)
            evidence_step=record_retraction_spec_claim
            source_id=examples/README.md
            [ "$mock_scenario" != source-mismatch ] || source_id=docs/wrong.md
            result=$(jq -cn \
                --arg source_id "$source_id" --arg hash "$a_hash" '{
                claim_id: 101,
                value: true,
                retrieval_lanes: ["lexical", "dense"],
                fusion: "rrf",
                source_coordinates: [{
                    source_config_id: "rich-demo:docs:v1",
                    source: "markdown",
                    source_id: $source_id,
                    chunk_id: "docs-retraction-1",
                    content_sha256: $hash
                }]
            }')
            ;;
        record-retraction-implementation-claim)
            evidence_step=record_retraction_implementation_claim
            spec_claim_id=101
            [ "$mock_scenario" != chain-mismatch ] || spec_claim_id=999
            result=$(jq -cn \
                --arg ahash "$b_hash" --arg bhash "$c_hash" \
                --argjson spec_claim_id "$spec_claim_id" '{
                claim_id: 102,
                value: false,
                retrieval_lanes: ["lexical", "dense"],
                fusion: "rrf",
                source_coordinates: [
                    {
                        source_config_id: "rich-demo:self-audit:v1",
                        source: "code",
                        source_id: "src/mcp/tools.rs",
                        chunk_id: "tools-record-only-1",
                        content_sha256: $ahash
                    },
                    {
                        source_config_id: "rich-demo:self-audit:v1",
                        source: "code",
                        source_id: "src/application.rs",
                        chunk_id: "application-record-only-1",
                        content_sha256: $bhash
                    }
                ],
                conflict_id: 501,
                member_claim_ids: [$spec_claim_id, 102],
                spec_claim_id: $spec_claim_id,
                implementation_claim_id: 102
            }')
            ;;
        *) exit 96 ;;
    esac
    policy=source-backed-mcp-contract-self-audit-v1
    if [ "$mock_scenario" = policy-mismatch ] && \
        [ "$step" = record-retraction-implementation-claim ]; then
        policy=untrusted-policy
    fi
    evidence=$(jq -cn \
        --arg run "$run_id" \
        --arg step "$evidence_step" \
        --arg agent "$agent" \
        --arg policy "$policy" \
        --argjson result "$result" '{
        schema: "fleet-reference-agent-evidence-v1",
        run_id: $run,
        step: $step,
        agent: $agent,
        project: "fleet-project",
        policy: $policy,
        result: $result
    }')
    if [ "$mock_scenario" = duplicate-evidence ] && \
        [ "$step" = record-retraction-implementation-claim ]; then
        jq -cn --arg message "$evidence" \
            '{events: [{message: $message}, {message: $message}]}'
    else
        jq -cn --arg message "$evidence" \
            '{events: [{message: "ordinary log"}, {message: $message}]}'
    fi
}

mock_aws() {
    service=$1
    operation=$2
    shift 2
    case "$service:$operation" in
        ecs:run-task) mock_run_task "$@" ;;
        ecs:wait) [ "$1" = tasks-stopped ] || exit 96 ;;
        ecs:describe-tasks) mock_describe_tasks "$@" ;;
        logs:get-log-events) mock_log_events "$@" ;;
        *) echo "unexpected aws mock operation: $service $operation" >&2; exit 96 ;;
    esac
}

case "$(basename -- "$0")" in
    aws) mock_aws "$@"; exit ;;
    curl) mock_curl "$@"; exit ;;
    terraform) mock_terraform "$@"; exit ;;
esac

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
wrapper=$script_dir/../run-self-audit-proof.sh
test_root=$(mktemp -d "${TMPDIR:-/tmp}/fleet-self-audit-wrapper-test.XXXXXX")
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
    mkdir -p "$state"
    PATH="$mock_bin:$PATH" MOCK_STATE_DIR="$state" MOCK_SCENARIO="$scenario" \
        "$wrapper" mock-run-1
}

success_state=$test_root/success
run_mock "$success_state" success \
    > "$test_root/success.json" 2> "$test_root/success.err"
jq -e '
    .schema == "fleet-source-conflict-self-audit-run-v1" and
    .verified == true and
    .deployment == "amazon-ecs-fargate" and
    .run_id == "mock-run-1" and
    .project == "fleet-project" and
    .evidence_schema == "fleet-reference-agent-evidence-v1" and
    .policy == "source-backed-mcp-contract-self-audit-v1" and
    .claims.spec == {
        claim_id: 101,
        actor: "agent-a",
        value: true,
        source_coordinates: [{
            source_config_id: "rich-demo:docs:v1",
            source: "markdown",
            source_id: "examples/README.md",
            chunk_id: "docs-retraction-1",
            content_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }]
    } and
    .claims.implementation.claim_id == 102 and
    .claims.implementation.actor == "agent-c" and
    .claims.implementation.value == false and
    [.claims.implementation.source_coordinates[].source_id] ==
        ["src/mcp/tools.rs", "src/application.rs"] and
    .conflict == {
        conflict_id: 501,
        state: "open",
        member_count: 2,
        member_claim_ids: [101, 102],
        surfaced_by_semantic_recall: true
    } and
    .retrieval.query == "Does MCP remember support deliberate retractions?" and
    .retrieval.retrieval_lanes == ["lexical", "dense"] and
    .retrieval.fusion == "rrf" and
    .retrieval.support_claims_matched == 2 and
    .retrieval.support_claims_truncated == false and
    [.retrieval.surfaced_source_chunks[].chunk_id] ==
        ["docs-retraction-1", "tools-record-only-1"] and
    .cockroachdb_capabilities.schema_version == 2 and
    .cockroachdb_capabilities.claim_support_chunk_index_enabled == true and
    .aws.task_definition == "fleet-reference-agent:8" and
    [.aws.tasks[].step] == [
        "record_retraction_spec_claim",
        "record_retraction_implementation_claim"
    ] and
    [.aws.tasks[].agent] == ["agent-a", "agent-c"] and
    .public_demo.read_only_verification == true
' "$test_root/success.json" >/dev/null
if grep -Eiq \
    'arn:|(^|[^0-9])[0-9]{12}([^0-9]|$)|postgres(ql)?://|log_(group|stream)|secret|password|session_token' \
    "$test_root/success.json"; then
    echo "self-audit receipt leaked a prohibited coordinate or secret" >&2
    exit 1
fi

expect_failure() {
    scenario=$1
    message=$2
    state=$test_root/$scenario
    if run_mock "$state" "$scenario" \
        > "$test_root/$scenario.out" 2> "$test_root/$scenario.err"; then
        echo "self-audit wrapper accepted scenario $scenario" >&2
        exit 1
    fi
    grep -F "$message" "$test_root/$scenario.err" >/dev/null
}

expect_failure schema-mismatch \
    'status did not prove CockroachDB schema 2'
expect_failure task-failure \
    'record-retraction-implementation-claim failed (exit=23)'
expect_failure duplicate-evidence \
    'multiple structured reference-agent evidence events were found'
expect_failure policy-mismatch \
    'evidence did not match the exact schema, run, step, agent, project, and policy'
expect_failure source-mismatch \
    'self-audit steps did not form one source-backed Boolean conflict'
expect_failure chain-mismatch \
    'self-audit steps did not form one source-backed Boolean conflict'
expect_failure closed-conflict \
    'public semantic recall did not project the exact open source-backed two-member conflict'

invalid_state=$test_root/invalid-run
mkdir -p "$invalid_state"
if PATH="$mock_bin:$PATH" MOCK_STATE_DIR="$invalid_state" MOCK_SCENARIO=success \
    "$wrapper" '../invalid' > "$test_root/invalid.out" 2> "$test_root/invalid.err"; then
    echo "self-audit wrapper accepted an unsafe run id" >&2
    exit 1
fi
grep -F 'run id must contain only ASCII letters' "$test_root/invalid.err" >/dev/null
[ ! -f "$invalid_state/run-count" ] || {
    echo "self-audit wrapper mutated ECS before rejecting an unsafe run id" >&2
    exit 1
}

printf '%s\n' 'self-audit source-conflict wrapper mock tests passed'
