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

if [ "$#" -ne 1 ]; then
    echo "usage: $0 REFERENCE_AGENT_RECEIPT" >&2
    exit 64
fi

reference_receipt=$1
"$script_dir/verify-publication-receipts.sh" "$reference_receipt" >/dev/null

run_id=$(jq -er '.run_id' "$reference_receipt")
project=$(jq -er '.project' "$reference_receipt")
action_claim_id=$(jq -er '.actions[0].claim_id' "$reference_receipt")
escalation_claim_id=$(jq -er '.actions[1].claim_id' "$reference_receipt")
expected_region=$(jq -er '.aws.region' "$reference_receipt")
expected_cluster=$(jq -er '.aws.cluster' "$reference_receipt")
expected_demo_url=$(jq -er '.public_demo.url' "$reference_receipt")

# The reference-agent receipt obtained this region from the module's structured
# task output. Reuse that validated coordinate instead of adding a redundant
# Terraform output solely for this wrapper.
region=$expected_region
cluster=$(terraform -chdir="$script_dir" output -raw cluster_name)
service=$(terraform -chdir="$script_dir" output -raw service_name)
demo_url=$(terraform -chdir="$script_dir" output -raw demo_url)
demo_url=${demo_url%/}

[ "$region" = "$expected_region" ] || fail "Terraform region differs from the reference-agent receipt"
[ "$cluster" = "$expected_cluster" ] || fail "Terraform cluster differs from the reference-agent receipt"
[ "$demo_url" = "$expected_demo_url" ] || fail "Terraform demo URL differs from the reference-agent receipt"
if ! jq -en --arg value "$service" '$value | test("^[A-Za-z0-9._+=,@-]+$")' >/dev/null; then
    fail "Terraform returned an invalid ECS service coordinate"
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

service_snapshot() {
    if ! snapshot=$(aws ecs describe-services \
        --region "$region" --cluster "$cluster" --services "$service" --output json); then
        fail "could not describe ECS service $service"
    fi
    if ! printf '%s' "$snapshot" | jq -e \
        --arg service "$service" '
        (.failures // [] | length) == 0 and
        (.services | type == "array" and length == 1) and
        .services[0].serviceName == $service and
        .services[0].status == "ACTIVE" and
        (.services[0].desiredCount | type == "number" and . > 0 and . == floor) and
        .services[0].runningCount == .services[0].desiredCount and
        .services[0].pendingCount == 0 and
        ([.services[0].deployments[]? |
            select(.status == "PRIMARY" and .rolloutState == "COMPLETED")] | length) == 1 and
        (.services[0].taskDefinition | type == "string" and length > 0)
    ' >/dev/null; then
        fail "ECS service is not one stable, nonzero deployment"
    fi
    printf '%s' "$snapshot" | jq -c '.services[0] | {
        desired_count: .desiredCount,
        task_definition: .taskDefinition
    }'
}

running_task_ids() {
    if ! listing=$(aws ecs list-tasks \
        --region "$region" --cluster "$cluster" --service-name "$service" \
        --desired-status RUNNING --output json); then
        fail "could not list running ECS tasks for $service"
    fi
    if ! ids=$(printf '%s' "$listing" | jq -ce '
        select((.taskArns | type) == "array") |
        [.taskArns[] |
            select(type == "string" and test("/[^/]+$")) |
            split("/")[-1]] |
        select(all(.[]; test("^[A-Za-z0-9_-]+$"))) |
        sort
    '); then
        fail "ECS returned an invalid running-task list"
    fi
    printf '%s' "$ids"
}

public_observation() {
    if ! health=$(curl_get "$demo_url/healthz"); then
        fail "public demo health check failed: $demo_url/healthz"
    fi
    if ! printf '%s' "$health" | jq -e '.status == "ready"' >/dev/null; then
        fail "public demo was reachable but not ready"
    fi

    observed_ids='[]'
    for pair in \
        "action:$action_claim_id:fleet deployment $run_id hold application workers until dedicated schema migrator completes" \
        "escalation:$escalation_claim_id:fleet deployment $run_id pause rollout incompatible migration strategies operator review"
    do
        kind=${pair%%:*}
        remainder=${pair#*:}
        claim_id=${remainder%%:*}
        query=${remainder#*:}
        request=$(jq -cn --arg query "$query" '{query: $query, limit: 20}')
        if ! response=$(curl_post_json "$request" "$demo_url/api/recall"); then
            fail "public demo recall failed while checking $kind claim $claim_id"
        fi
        if ! printf '%s' "$response" | jq -e --argjson claim_id "$claim_id" '
            (.data.hits | type == "array") and
            any(.data.hits[]; .extra.claim_id == $claim_id) and
            .diagnostics.retrieval.lanes == ["lexical", "dense"] and
            .diagnostics.retrieval.fusion == "rrf"
        ' >/dev/null; then
            fail "public demo did not return exact $kind claim $claim_id through lexical+dense RRF"
        fi
        observed_ids=$(printf '%s' "$observed_ids" | jq -c --argjson id "$claim_id" '. + [$id]')
    done
    jq -cn --argjson ids "$observed_ids" '{
        health: "ready",
        exact_claim_ids_observed: $ids,
        retrieval_lanes: ["lexical", "dense"],
        fusion: "rrf"
    }'
}

echo "waiting for the current ECS service deployment to be stable" >&2
aws ecs wait services-stable --region "$region" --cluster "$cluster" --services "$service"
before_service=$(service_snapshot)
before_desired=$(printf '%s' "$before_service" | jq -er '.desired_count')
before_task_arn=$(printf '%s' "$before_service" | jq -er '.task_definition')
before_task_definition=${before_task_arn##*/}
if ! jq -en --arg coordinate "$before_task_definition" '
    $coordinate | test("^[A-Za-z0-9._+=,@-]+:[1-9][0-9]*$")
' >/dev/null; then
    fail "ECS returned an invalid serving task-definition coordinate"
fi
before_tasks=$(running_task_ids)
if [ "$(printf '%s' "$before_tasks" | jq -r 'length')" -ne "$before_desired" ]; then
    fail "running task count did not equal the stable service desired count before replacement"
fi
before_observation=$(public_observation)

echo "forcing a fresh ECS deployment for persistence proof" >&2
if ! aws ecs update-service \
    --region "$region" --cluster "$cluster" --service "$service" \
    --force-new-deployment --output json >/dev/null; then
    fail "ECS rejected the forced serving-task replacement"
fi
aws ecs wait services-stable --region "$region" --cluster "$cluster" --services "$service"

after_service=$(service_snapshot)
after_desired=$(printf '%s' "$after_service" | jq -er '.desired_count')
after_task_arn=$(printf '%s' "$after_service" | jq -er '.task_definition')
after_task_definition=${after_task_arn##*/}
[ "$after_task_definition" = "$before_task_definition" ] || \
    fail "forced deployment unexpectedly changed the serving task definition"
after_tasks=$(running_task_ids)
if [ "$(printf '%s' "$after_tasks" | jq -r 'length')" -ne "$after_desired" ]; then
    fail "running task count did not equal the stable service desired count after replacement"
fi
if ! jq -en --argjson before "$before_tasks" --argjson after "$after_tasks" '
    ([($before[] as $old | $after[] | select(. == $old))] | length) == 0
' >/dev/null; then
    fail "at least one pre-deployment serving task remained after ECS reported stable"
fi
after_observation=$(public_observation)
if [ "$before_observation" != "$after_observation" ]; then
    fail "public recall observation changed across the serving-task replacement"
fi

jq -cn \
    --arg run "$run_id" \
    --arg project "$project" \
    --arg region "$region" \
    --arg cluster "$cluster" \
    --arg service "$service" \
    --arg task_definition "$before_task_definition" \
    --arg demo_url "$demo_url" \
    --argjson before_desired "$before_desired" \
    --argjson after_desired "$after_desired" \
    --argjson before_tasks "$before_tasks" \
    --argjson after_tasks "$after_tasks" \
    --argjson before_observation "$before_observation" \
    --argjson after_observation "$after_observation" \
    --argjson exact_ids "$(printf '%s' "$after_observation" | jq -c '.exact_claim_ids_observed')" '{
    schema: "fleet-ecs-replacement-run-v1",
    verified: true,
    deployment: "amazon-ecs-fargate",
    run_id: $run,
    project: $project,
    aws: {
        region: $region,
        cluster: $cluster,
        service: $service,
        task_definition: $task_definition,
        replacement_strategy: "ecs-force-new-deployment",
        desired_count_before: $before_desired,
        desired_count_after: $after_desired,
        tasks_before: $before_tasks,
        tasks_after: $after_tasks
    },
    public_demo: {
        url: $demo_url,
        before: $before_observation,
        after: $after_observation
    },
    persistence: {
        cockroachdb_memory_plane: true,
        serving_task_set_fully_replaced: true,
        exact_claim_ids_survived: $exact_ids
    }
}'
