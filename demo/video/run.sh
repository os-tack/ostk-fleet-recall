#!/bin/sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$script_dir/../.." && pwd)

usage() {
    cat >&2 <<'EOF'
usage: demo/video/run.sh --rehearsal [--headless]
       demo/video/run.sh --live [RUN_ID] [--headless]

--rehearsal renders the checked-in sanitized LocalStack/MCP evidence.
--live requires a verified target/ostk-demo/RUN_ID/final.json.
EOF
    exit 64
}

mode=
run_id=
headless=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --rehearsal)
            [ -z "$mode" ] || usage
            mode=rehearsal
            ;;
        --live)
            [ -z "$mode" ] || usage
            mode=live
            if [ "$#" -gt 1 ]; then
                case "$2" in
                    -*) ;;
                    *) run_id=$2; shift ;;
                esac
            fi
            ;;
        --headless)
            headless=1
            ;;
        -h|--help)
            usage
            ;;
        *)
            usage
            ;;
    esac
    shift
done

[ -n "$mode" ] || usage
for command_name in jq tmux; do
    command -v "$command_name" >/dev/null 2>&1 || {
        printf 'video demo: required command not found: %s\n' "$command_name" >&2
        exit 1
    }
done

case "$mode" in
    rehearsal)
        evidence_rel=docs/evidence/local-fleet-scenario.json
        evidence_path=$repo_root/$evidence_rel
        jq -e '
            def positive_integer:
                type == "number" and isfinite and . > 0 and . == floor;
            . as $root |
            .scenario == "local-evidence-v1" and
            .agent_a.committed == true and
            .agent_a.replay_deduplicated == true and
            (.agent_a.claim_id | positive_integer) and
            (.agent_b.action_claim_id | positive_integer) and
            (.agent_b.escalation_claim_id | positive_integer) and
            (.agent_c.claim_id | positive_integer) and
            (.conflict.id | positive_integer) and
            ([
                .agent_a.claim_id,
                .agent_b.action_claim_id,
                .agent_c.claim_id,
                .agent_b.escalation_claim_id
            ] | unique | length) == 4 and
            .agent_b.cross_project_request_rejected == true and
            .agent_b.retrieval_lanes == ["lexical", "dense"] and
            .agent_b.fusion == "rrf" and
            .agent_b.recalled_claim_id == .agent_a.claim_id and
            .agent_b.action_based_on_claim_id == .agent_a.claim_id and
            .agent_b.action == "hold workers until migration completes" and
            .agent_b.escalation == "pause rollout for operator review" and
            .agent_b.escalation_conflict_id == .conflict.id and
            .agent_c.incompatible_value_recorded == true and
            .conflict.state == "open" and
            (.conflict.member_claim_ids | type == "array" and length == 2) and
            ((.conflict.member_claim_ids | sort) ==
                ([$root.agent_a.claim_id, $root.agent_c.claim_id] | sort))
        ' "$evidence_path" >/dev/null || {
            printf 'video demo: rehearsal evidence failed its contract\n' >&2
            exit 1
        }
        ;;
    live)
        run_id=${run_id:-${OSTK_DEMO_RUN_ID:-}}
        case "$run_id" in
            ''|*[!A-Za-z0-9_-]*)
                printf 'video demo: --live requires a safe OSTK run ID\n' >&2
                exit 64
                ;;
        esac
        [ "${#run_id}" -le 48 ] || {
            printf 'video demo: OSTK run ID must be at most 48 characters\n' >&2
            exit 64
        }
        evidence_rel=target/ostk-demo/$run_id/final.json
        evidence_path=$repo_root/$evidence_rel
        jq -e --arg requested_run "$run_id" '
            def positive_integer:
                type == "number" and isfinite and . > 0 and . == floor;
            .run_id as $run |
            .schema_version == 1 and
            .verified == true and
            .run_id == $requested_run and
            ($run | type == "string" and test("^[A-Za-z0-9_-]{1,48}$")) and
            .orchestrator.product == "ostk" and
            .orchestrator.required_cli_version == "7.7.7" and
            .orchestrator.sessions == [
                ("ostk-recall-a-" + $run),
                ("ostk-recall-b-" + $run),
                ("ostk-recall-c-" + $run)
            ] and
            .orchestrator.resumed_session == .orchestrator.sessions[1] and
            (.memory.recalled_claim_id | positive_integer) and
            (.memory.incompatible_claim_id | positive_integer) and
            (.memory.open_conflict_id | positive_integer) and
            .memory.recalled_claim_id != .memory.incompatible_claim_id and
            .memory.retrieval_lanes == ["lexical", "dense"] and
            .memory.fusion == "rrf" and
            (.actions | type == "array" and length == 2) and
            .actions[0].action == "hold workers until migration completes" and
            .actions[1].action == "pause rollout and escalate for operator review" and
            .actions[0].based_on_claim_id == .memory.recalled_claim_id and
            .actions[1].based_on_conflict_id == .memory.open_conflict_id and
            .actions[0].receipt == (
                "s3://fleet-recall-local-actions/ostk-demo/" + $run +
                "/agent-b/hold-workers.json"
            ) and
            .actions[1].receipt == (
                "s3://fleet-recall-local-actions/ostk-demo/" + $run +
                "/agent-b/pause-rollout.json"
            )
        ' "$evidence_path" >/dev/null || {
            printf 'video demo: live evidence is missing or is not a verified OSTK final.json\n' >&2
            exit 1
        }
        ;;
esac

# Exercise every renderer before opening tmux. This prevents a late jq or
# projection failure from reaching the final VERIFIED footer.
cd "$repo_root"
for role in agent-a agent-b agent-c agent-b-resume; do
    FLEET_VIDEO_FAST=1 "$script_dir/pane.sh" "$role" "$mode" "$evidence_rel" >/dev/null
done
"$script_dir/footer.sh" verified "$mode" "$evidence_rel" >/dev/null

session=fleet-video-$$
controller_pid=
cleanup() {
    status=$?
    trap - EXIT HUP INT TERM
    if [ -n "$controller_pid" ]; then
        kill "$controller_pid" >/dev/null 2>&1 || true
        wait "$controller_pid" >/dev/null 2>&1 || true
    fi
    tmux kill-session -t "$session" >/dev/null 2>&1 || true
    exit "$status"
}
trap cleanup EXIT HUP INT TERM

pane_shell='stty -echo; env PS1= /bin/sh -i'
main_pane=$(tmux new-session -d -P -F '#{pane_id}' \
    -s "$session" -n fleet -x 178 -y 48 -c "$repo_root" "$pane_shell")
tmux set-option -t "$session" status off
tmux set-option -t "$session" remain-on-exit on
tmux set-option -t "$session" allow-rename off
tmux set-option -t "$session" pane-border-status top
tmux set-option -t "$session" pane-border-style 'fg=#45475a'
tmux set-option -t "$session" pane-active-border-style 'fg=#89b4fa,bold'
tmux set-option -t "$session" pane-border-format \
    '#[fg=#6c7086] #{?pane_active,#[fg=#89b4fa]●,○} #[fg=#cdd6f4,bold]#{pane_title} '
tmux set-option -t "$session" window-size latest

footer_pane=$(tmux split-window -v -l 7 -t "$main_pane" -c "$repo_root" \
    -P -F '#{pane_id}' "$pane_shell")
right_pane=$(tmux split-window -h -t "$main_pane" -c "$repo_root" \
    -P -F '#{pane_id}' "$pane_shell")
agent_c_pane=$(tmux split-window -v -t "$main_pane" -c "$repo_root" \
    -P -F '#{pane_id}' "$pane_shell")
agent_b_resume_pane=$(tmux split-window -v -t "$right_pane" -c "$repo_root" \
    -P -F '#{pane_id}' "$pane_shell")

tmux select-pane -t "$main_pane" -T 'AGENT A  •  MEMORY WRITER'
tmux select-pane -t "$right_pane" -T 'AGENT B  •  RETRIEVER + ACTOR'
tmux select-pane -t "$agent_c_pane" -T 'AGENT C  •  CONFLICTING WRITER'
tmux select-pane -t "$agent_b_resume_pane" -T 'AGENT B  •  RESUMED LINEAGE'
tmux select-pane -t "$footer_pane" -T 'FLEET RECALL  •  PROVENANCE + STATUS'
tmux select-pane -t "$footer_pane"

display_mode=attach
[ "$headless" -eq 0 ] || display_mode=headless
if [ "${FLEET_VIDEO_VHS:-0}" = 1 ]; then
    display_mode=vhs
fi

"$script_dir/choreograph.sh" \
    "$session" "$mode" "$evidence_rel" "$display_mode" \
    "$main_pane" "$right_pane" "$agent_c_pane" \
    "$agent_b_resume_pane" "$footer_pane" &
controller_pid=$!

if [ "$headless" -eq 1 ]; then
    wait "$controller_pid"
    controller_pid=
    for pane in "$main_pane" "$right_pane" "$agent_c_pane" \
        "$agent_b_resume_pane" "$footer_pane"; do
        tmux capture-pane -p -S - -t "$pane"
    done
else
    tmux attach-session -t "$session"
    wait "$controller_pid"
    controller_pid=
fi
