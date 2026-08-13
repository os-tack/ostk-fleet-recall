#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

for command_name in aws jq terraform; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "required command not found: $command_name" >&2
        exit 69
    fi
done

seed=$(terraform -chdir="$script_dir" output -json seed_task)
region=$(printf '%s' "$seed" | jq -er '.region')
cluster=$(printf '%s' "$seed" | jq -er '.cluster')
task_definition=$(printf '%s' "$seed" | jq -er '.task_definition')
container_name=$(printf '%s' "$seed" | jq -er '.container_name')
log_group=$(printf '%s' "$seed" | jq -er '.log_group')

network_configuration=$(printf '%s' "$seed" | jq -cer '{
    awsvpcConfiguration: {
        subnets: .subnets,
        securityGroups: .security_groups,
        assignPublicIp: .assign_public_ip
    }
}')
overrides=$(jq -cn --arg name "$container_name" '{
    containerOverrides: [{
        name: $name,
        command: ["ingest", "--input", "/opt/ostk/demo/demo.ndjson"]
    }]
}')

run_result=$(aws ecs run-task \
    --region "$region" \
    --cluster "$cluster" \
    --task-definition "$task_definition" \
    --launch-type FARGATE \
    --count 1 \
    --network-configuration "$network_configuration" \
    --overrides "$overrides" \
    --output json)
task_arn=$(printf '%s' "$run_result" | jq -r '.tasks[0].taskArn // empty')

if [ -z "$task_arn" ]; then
    echo "ECS did not start the seed task" >&2
    printf '%s' "$run_result" | jq -c '.failures // []' >&2
    exit 70
fi
unset run_result

echo "waiting for the idempotent demo-corpus seed task: $task_arn"
aws ecs wait tasks-stopped --region "$region" --cluster "$cluster" --tasks "$task_arn"

description=$(aws ecs describe-tasks \
    --region "$region" \
    --cluster "$cluster" \
    --tasks "$task_arn" \
    --output json)
exit_code=$(printf '%s' "$description" | jq -r --arg name "$container_name" \
    '.tasks[0].containers[] | select(.name == $name) | (.exitCode // empty)')
reason=$(printf '%s' "$description" | jq -r --arg name "$container_name" \
    '.tasks[0].containers[] | select(.name == $name) | (.reason // "")')
stopped_reason=$(printf '%s' "$description" | jq -r '.tasks[0].stoppedReason // ""')

if [ -n "$exit_code" ]; then
    echo "seed task exit code: $exit_code"
else
    echo "seed task did not report a container exit code" >&2
fi
if [ -n "$reason" ]; then
    echo "seed task reason: $reason"
fi
if [ -n "$stopped_reason" ]; then
    echo "seed task stopped reason: $stopped_reason"
fi
echo "logs: aws logs tail '$log_group' --region '$region' --since 30m"

if [ -z "$exit_code" ]; then
    exit 70
fi
if [ "$exit_code" -ne 0 ]; then
    exit "$exit_code"
fi
