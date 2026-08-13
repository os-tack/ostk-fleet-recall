#!/bin/sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=demo/ostk/lib.sh
. "$script_dir/lib.sh"

if [ "${1:-}" != --run-id ] || [ "$#" -ne 2 ]; then
    printf 'usage: %s --run-id ID\n' "$0" >&2
    exit 64
fi
run_id=$2
ostk_demo_validate_run_id "$run_id"

ostk_demo_require_command jq
ostk_demo_require_command "${OSTK_DEMO_AWS_BIN:-aws}"
repo_root=$(ostk_demo_repo_root "$0")
run_dir=$(ostk_demo_run_dir "$repo_root" "$run_id")

for evidence_name in a-record.json b-action.json c-conflict.json b-pause.json; do
    [ -f "$run_dir/$evidence_name" ] || \
        ostk_demo_die "missing evidence file: $run_dir/$evidence_name"
done

action_bucket=$(jq -er '.s3.bucket' "$run_dir/b-action.json")
action_key=$(jq -er '.s3.key' "$run_dir/b-action.json")
pause_bucket=$(jq -er '.s3.bucket' "$run_dir/b-pause.json")
pause_key=$(jq -er '.s3.key' "$run_dir/b-pause.json")
[ "$action_bucket" = fleet-recall-local-actions ] || ostk_demo_die 'unexpected action receipt bucket'
[ "$pause_bucket" = fleet-recall-local-actions ] || ostk_demo_die 'unexpected pause receipt bucket'

download_dir=$(mktemp -d "${TMPDIR:-/tmp}/ostk-recall-verify.XXXXXX") || \
    ostk_demo_die 'could not create verification directory'
cleanup() {
    rm -f "$download_dir/b-action.json" "$download_dir/b-pause.json"
    rmdir "$download_dir" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM

ostk_demo_aws s3api get-object \
    --bucket "$action_bucket" \
    --key "$action_key" \
    "$download_dir/b-action.json" >/dev/null
ostk_demo_aws s3api get-object \
    --bucket "$pause_bucket" \
    --key "$pause_key" \
    "$download_dir/b-pause.json" >/dev/null

expected_a=$(ostk_demo_agent_name a "$run_id")
expected_b=$(ostk_demo_agent_name b "$run_id")
expected_c=$(ostk_demo_agent_name c "$run_id")
summary=$(jq -e -s \
    --arg run "$run_id" \
    --arg expected_a "$expected_a" \
    --arg expected_b "$expected_b" \
    --arg expected_c "$expected_c" '
    .[0] as $a |
    .[1] as $action |
    .[2] as $c |
    .[3] as $pause |
    .[4] as $s3_action |
    .[5] as $s3_pause |
    def positive_integer:
        type == "number" and isfinite and . > 0 and . == floor;
    if
        ($a.schema_version == 1 and $a.step == "agent_a_record" and
         $a.run_id == $run and $a.ostk_agent == $expected_a and
         $a.committed == true and ($a.claim_id | positive_integer)) and
        ($action.schema_version == 1 and $action.step == "agent_b_recall_action" and
         $action.run_id == $run and $action.ostk_agent == $expected_b and
         $action.action == "hold workers until migration completes" and
         $action.based_on_claim_id == $a.claim_id and
         $action.retrieval == {lanes: ["lexical", "dense"], fusion: "rrf"} and
         $action.s3 == {
             bucket: "fleet-recall-local-actions",
             key: ("ostk-demo/" + $run + "/agent-b/hold-workers.json")
         }) and
        ($c.schema_version == 1 and $c.step == "agent_c_conflict" and
         $c.run_id == $run and $c.ostk_agent == $expected_c and
         ($c.claim_id | positive_integer) and $c.claim_id != $a.claim_id and
         ($c.conflict_id | positive_integer) and
         $c.incompatible_with_claim_id == $a.claim_id and $c.state == "open" and
         $c.member_count == 2 and $c.members_disputed == true) and
        ($pause.schema_version == 1 and $pause.step == "agent_b_conflict_pause" and
         $pause.run_id == $run and $pause.ostk_agent == $expected_b and
         $pause.action == "pause rollout and escalate for operator review" and
         $pause.based_on_conflict_id == $c.conflict_id and
         $pause.conflict_member_count == 2 and
         (($pause.disputed_claim_ids | sort) == ([$a.claim_id, $c.claim_id] | sort)) and
         $pause.s3 == {
             bucket: "fleet-recall-local-actions",
             key: ("ostk-demo/" + $run + "/agent-b/pause-rollout.json")
         }) and
        ($s3_action == $action) and ($s3_pause == $pause)
    then {
        schema_version: 1,
        verified: true,
        run_id: $run,
        orchestrator: {
            product: "ostk",
            required_cli_version: "7.7.7",
            sessions: [$expected_a, $expected_b, $expected_c],
            resumed_session: $expected_b
        },
        bridge: "OSTK Bash tool to Fleet Recall stdio MCP (non-native)",
        memory: {
            recalled_claim_id: $a.claim_id,
            incompatible_claim_id: $c.claim_id,
            open_conflict_id: $c.conflict_id,
            retrieval_lanes: $action.retrieval.lanes,
            fusion: $action.retrieval.fusion
        },
        actions: [
            {
                action: $action.action,
                based_on_claim_id: $action.based_on_claim_id,
                receipt: ("s3://" + $action.s3.bucket + "/" + $action.s3.key)
            },
            {
                action: $pause.action,
                based_on_conflict_id: $pause.based_on_conflict_id,
                receipt: ("s3://" + $pause.s3.bucket + "/" + $pause.s3.key)
            }
        ]
    } else
        error("OSTK fleet evidence does not satisfy the end-to-end contract")
    end
    ' \
    "$run_dir/a-record.json" \
    "$run_dir/b-action.json" \
    "$run_dir/c-conflict.json" \
    "$run_dir/b-pause.json" \
    "$download_dir/b-action.json" \
    "$download_dir/b-pause.json")

ostk_demo_write_json "$run_dir/final.json" "$summary"
printf '%s\n' "$summary"
