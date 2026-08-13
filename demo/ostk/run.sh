#!/bin/sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=demo/ostk/lib.sh
. "$script_dir/lib.sh"
repo_root=$(ostk_demo_repo_root "$0")

mode=run
requested_run_id=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --plan)
            mode=plan
            ;;
        --run-id)
            shift
            [ "$#" -gt 0 ] || ostk_demo_usage_error '--run-id requires a value'
            requested_run_id=$1
            ;;
        -h|--help)
            printf 'usage: %s [--plan] [--run-id ID]\n' "$0"
            exit 0
            ;;
        *) ostk_demo_usage_error "unknown option: $1" ;;
    esac
    shift
done

model=${OSTK_DEMO_MODEL:-}
budget=${OSTK_DEMO_BUDGET_USD:-}
ostk_demo_require_command jq
[ -n "$model" ] || ostk_demo_usage_error 'OSTK_DEMO_MODEL is required; there is no default model'
case "$model" in
    -*|*[!A-Za-z0-9._:/-]*)
        ostk_demo_usage_error 'OSTK_DEMO_MODEL contains unsupported characters'
        ;;
esac
[ "${#model}" -le 160 ] || ostk_demo_usage_error 'OSTK_DEMO_MODEL must be at most 160 characters'
[ -n "$budget" ] || ostk_demo_usage_error 'OSTK_DEMO_BUDGET_USD is required; there is no default budget'
printf '%s\n' "$budget" | jq -eR '
    test("^(0\\.[0-9]*[1-9][0-9]*|[1-9][0-9]*(\\.[0-9]+)?)$") and
    ((tonumber) > 0)
' >/dev/null 2>&1 || ostk_demo_usage_error 'OSTK_DEMO_BUDGET_USD must be a finite positive decimal USD amount'

ostk_binary=${OSTK_DEMO_OSTK_BIN:-ostk}
ostk_demo_require_command "$ostk_binary"
version_output=$("$ostk_binary" --version 2>/dev/null) || ostk_demo_die 'could not read OSTK CLI version'
case "$version_output" in
    'ostk 7.7.7'|'ostk 7.7.7+'*) ;;
    *) ostk_demo_die "this demo requires ostk 7.7.7 (found: $version_output)" ;;
esac

if [ -n "$requested_run_id" ]; then
    run_id=$requested_run_id
else
    run_id=$(date -u +%Y%m%dT%H%M%SZ)-$$
fi
ostk_demo_validate_run_id "$run_id"
agent_a=$(ostk_demo_agent_name a "$run_id")
agent_b=$(ostk_demo_agent_name b "$run_id")
agent_c=$(ostk_demo_agent_name c "$run_id")
run_dir=$(ostk_demo_run_dir "$repo_root" "$run_id")
prompt_dir=$run_dir/prompts

max_authorized=$(jq -cn --arg budget "$budget" '$budget | tonumber * 4')
if [ "$mode" = plan ]; then
    jq -cn \
        --arg version "$version_output" \
        --arg model "$model" \
        --arg budget "$budget" \
        --argjson maximum "$max_authorized" \
        --arg run "$run_id" \
        --arg a "$agent_a" \
        --arg b "$agent_b" \
        --arg c "$agent_c" \
        --arg root "$repo_root" \
        '{
            mode: "plan-only",
            launches_agents: false,
            cli: $version,
            run_id: $run,
            model: $model,
            budget_usd_per_invocation: ($budget | tonumber),
            conservative_max_authorized_usd: $maximum,
            invocations: [
                {
                    command: "ostk agent",
                    name: $a,
                    prompt_file: ($root + "/target/ostk-demo/" + $run + "/prompts/agent-a.md"),
                    bridge_argv: ["./demo/ostk/bridge.sh", "--run-id", $run, "record-decision"]
                },
                {
                    command: "ostk agent",
                    name: $b,
                    prompt_file: ($root + "/target/ostk-demo/" + $run + "/prompts/agent-b.md"),
                    bridge_argv: ["./demo/ostk/bridge.sh", "--run-id", $run, "recall-and-act"]
                },
                {
                    command: "ostk agent",
                    name: $c,
                    prompt_file: ($root + "/target/ostk-demo/" + $run + "/prompts/agent-c.md"),
                    bridge_argv: ["./demo/ostk/bridge.sh", "--run-id", $run, "record-conflict"]
                },
                {
                    command: "ostk agent resume",
                    name: $b,
                    bridge_argv: ["./demo/ostk/bridge.sh", "--run-id", $run, "recall-conflict-and-pause"]
                }
            ]
        }'
    exit 0
fi

[ "${OSTK_DEMO_ALLOW_BILLING:-}" = I_UNDERSTAND_FOUR_AGENT_RUNS_MAY_BILL ] || \
    ostk_demo_usage_error 'set OSTK_DEMO_ALLOW_BILLING=I_UNDERSTAND_FOUR_AGENT_RUNS_MAY_BILL to launch agents'

# OSTK is an optional demo adapter, not a Fleet Recall prerequisite. Require an
# explicitly initialized project at this repository root so `ostk agent` cannot
# silently bind to an unrelated ancestor or user-level OS instance.
ostk_state=$repo_root/.ostk
[ ! -L "$ostk_state" ] && [ -d "$ostk_state" ] || \
    ostk_demo_die 'optional live OSTK demo is not initialized here; Fleet Recall and the VHS rehearsal do not require OSTK (see docs/OSTK_DEMO.md)'
for state_file in .language .primefile version; do
    [ -f "$ostk_state/$state_file" ] && [ ! -L "$ostk_state/$state_file" ] || \
        ostk_demo_die "optional live OSTK project is incomplete: $ostk_state/$state_file"
done

for required_command in docker jq "${OSTK_DEMO_AWS_BIN:-aws}"; do
    ostk_demo_require_command "$required_command"
done
if ! docker info >/dev/null 2>&1; then
    ostk_demo_die 'Docker daemon is unavailable'
fi
app_container=$(docker ps \
    --filter label=com.docker.compose.project=ostk-fleet-recall-local \
    --filter label=com.docker.compose.service=app \
    --filter status=running \
    --format '{{.ID}}')
case "$app_container" in
    '') ostk_demo_die 'LocalStack Fleet Recall is not running; use smoke.sh with KEEP_LOCALSTACK=1' ;;
    *"
"*) ostk_demo_die 'more than one LocalStack Fleet Recall app container is running' ;;
esac
ostk_demo_aws s3api head-bucket --bucket fleet-recall-local-actions >/dev/null || \
    ostk_demo_die 'the LocalStack action-evidence bucket is unavailable'

[ ! -e "$run_dir" ] || ostk_demo_die "run state already exists: $run_dir"
mkdir -p "$run_dir/ostk" "$prompt_dir"
chmod 700 "$run_dir" "$run_dir/ostk" "$prompt_dir"

write_prompt() {
    role=$1
    step=$2
    destination=$3
    temporary=$(mktemp "$prompt_dir/.prompt.XXXXXX") || \
        ostk_demo_die "could not create prompt in $prompt_dir"
    {
        printf 'You are Agent %s in a bounded Fleet Recall demonstration.\n\n' "$role"
        printf '%s' 'Use Bash to run exactly `./demo/ostk/bridge.sh --run-id '
        printf '%s %s' "$run_id" "$step"
        printf '%s' '` once. '
        printf "%s\n" "Do not inspect or modify any other file, and do not print environment variables or credentials. If it succeeds, return its JSON stdout unchanged. If it fails, report only the command's safe error message."
    } >"$temporary"
    chmod 600 "$temporary"
    mv -f "$temporary" "$destination"
}

write_prompt A record-decision "$prompt_dir/agent-a.md"
write_prompt B recall-and-act "$prompt_dir/agent-b.md"
write_prompt C record-conflict "$prompt_dir/agent-c.md"

started_agents=
run_succeeded=0
cleanup_agents() {
    status=$?
    trap - EXIT HUP INT TERM
    if [ "$run_succeeded" -ne 1 ]; then
        for started_agent in $started_agents; do
            "$ostk_binary" agent stop "$started_agent" --grace 2 >/dev/null 2>&1 || true
        done
    fi
    exit "$status"
}
trap cleanup_agents EXIT
trap 'exit 130' HUP INT TERM

cd "$repo_root"

spawn_and_await() {
    role=$1
    agent_name=$2
    prompt_file=$3
    evidence_file=$4
    printf 'Launching OSTK agent %s with model %s and USD %s cap.\n' "$agent_name" "$model" "$budget" >&2
    "$ostk_binary" agent "$agent_name" \
        --prompt-file "$prompt_file" \
        --model "$model" \
        --budget "$budget" \
        --lifetime job >"$run_dir/ostk/$role.spawn.log" 2>&1
    started_agents="$started_agents $agent_name"
    "$ostk_binary" agent await "$agent_name" --timeout "${OSTK_DEMO_AWAIT_SECONDS:-300}" \
        >"$run_dir/ostk/$role.await.log" 2>&1
    [ -f "$run_dir/$evidence_file" ] || \
        ostk_demo_die "agent $agent_name finished without producing $evidence_file"
}

spawn_and_await a "$agent_a" "$prompt_dir/agent-a.md" a-record.json
spawn_and_await b "$agent_b" "$prompt_dir/agent-b.md" b-action.json
spawn_and_await c "$agent_c" "$prompt_dir/agent-c.md" c-conflict.json

resume_prompt="Use Bash to run exactly ./demo/ostk/bridge.sh --run-id $run_id recall-conflict-and-pause once. Return its JSON stdout unchanged and do nothing else."
printf 'Resuming OSTK agent %s with USD %s cap for conflict handling.\n' "$agent_b" "$budget" >&2
"$ostk_binary" agent resume "$agent_b" \
    --budget "$budget" \
    -p "$resume_prompt" >"$run_dir/ostk/b-resume.spawn.log" 2>&1
"$ostk_binary" agent await "$agent_b" --timeout "${OSTK_DEMO_AWAIT_SECONDS:-300}" \
    >"$run_dir/ostk/b-resume.await.log" 2>&1
[ -f "$run_dir/b-pause.json" ] || \
    ostk_demo_die "resumed agent $agent_b finished without producing b-pause.json"

"$script_dir/verify.sh" --run-id "$run_id"
run_succeeded=1
