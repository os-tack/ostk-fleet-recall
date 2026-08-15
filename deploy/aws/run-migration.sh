#!/bin/sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)

for command_name in aws jq terraform; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "required command not found: $command_name" >&2
        exit 69
    fi
done

migration=$(terraform -chdir="$script_dir" output -json migration_task)
region=$(printf '%s' "$migration" | jq -er '.region')
cluster=$(printf '%s' "$migration" | jq -er '.cluster')
task_definition=$(printf '%s' "$migration" | jq -er '.task_definition')
container_name=$(printf '%s' "$migration" | jq -er '.container_name')
log_group=$(printf '%s' "$migration" | jq -er '.log_group')

network_configuration=$(printf '%s' "$migration" | jq -cer '{
    awsvpcConfiguration: {
        subnets: .subnets,
        securityGroups: .security_groups,
        assignPublicIp: .assign_public_ip
    }
}')
overrides=$(jq -cn --arg name "$container_name" '{
    containerOverrides: [{name: $name, command: ["migrate"]}]
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
    echo "ECS did not start the migration task" >&2
    printf '%s' "$run_result" | jq -c '.failures // []' >&2
    exit 70
fi
unset run_result

echo "waiting for the single migration task: $task_arn"
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
    echo "migration task exit code: $exit_code"
else
    echo "migration task did not report a container exit code" >&2
fi
if [ -n "$reason" ]; then
    echo "migration task reason: $reason"
fi
if [ -n "$stopped_reason" ]; then
    echo "migration task stopped reason: $stopped_reason"
fi
echo "logs: aws logs tail '$log_group' --region '$region' --since 30m"

if [ -z "$exit_code" ]; then
    exit 70
fi
if [ "$exit_code" -ne 0 ]; then
    exit "$exit_code"
fi
