#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

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

task_arn=$(aws ecs run-task \
    --region "$region" \
    --cluster "$cluster" \
    --task-definition "$task_definition" \
    --launch-type FARGATE \
    --count 1 \
    --network-configuration "$network_configuration" \
    --overrides "$overrides" \
    --query 'tasks[0].taskArn' \
    --output text)

if [ -z "$task_arn" ] || [ "$task_arn" = "None" ]; then
    echo "ECS did not start the migration task; inspect the run-task failures array" >&2
    exit 70
fi

echo "waiting for the single migration task: $task_arn"
aws ecs wait tasks-stopped --region "$region" --cluster "$cluster" --tasks "$task_arn"

description=$(aws ecs describe-tasks \
    --region "$region" \
    --cluster "$cluster" \
    --tasks "$task_arn" \
    --output json)
exit_code=$(printf '%s' "$description" | jq -er --arg name "$container_name" \
    '.tasks[0].containers[] | select(.name == $name) | .exitCode')
reason=$(printf '%s' "$description" | jq -r --arg name "$container_name" \
    '.tasks[0].containers[] | select(.name == $name) | (.reason // "")')

echo "migration task exit code: $exit_code"
if [ -n "$reason" ]; then
    echo "migration task reason: $reason"
fi
echo "logs: aws logs tail '$log_group' --region '$region' --since 30m"

if [ "$exit_code" -ne 0 ]; then
    exit "$exit_code"
fi
