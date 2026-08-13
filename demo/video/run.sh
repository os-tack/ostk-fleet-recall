#!/bin/sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$script_dir/../.." && pwd)

usage() {
    cat >&2 <<'EOF'
usage: demo/video/run.sh --rehearsal [--headless]
       demo/video/run.sh --fleet-live [RUN_ID] [--headless]
       demo/video/run.sh --ostk-live [RUN_ID] [--headless]

--rehearsal renders the checked-in sanitized LocalStack/MCP evidence.
--fleet-live renders fresh target/fleet-demo/RUN_ID/final.json evidence.
--ostk-live renders an optional target/ostk-demo/RUN_ID/final.json run.
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
        --fleet-live)
            [ -z "$mode" ] || usage
            mode=fleet-live
            if [ "$#" -gt 1 ]; then
                case "$2" in
                    -*) ;;
                    *) run_id=$2; shift ;;
                esac
            fi
            ;;
        --ostk-live)
            [ -z "$mode" ] || usage
            mode=ostk-live
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

require_real_directory() {
    directory=$1
    [ -d "$directory" ] && [ ! -L "$directory" ] || {
        printf 'video demo: evidence directory is missing or symlinked\n' >&2
        exit 1
    }
}

case "$mode" in
    rehearsal)
        evidence_rel=docs/evidence/local-fleet-scenario.json
        evidence_path=$repo_root/$evidence_rel
        "$script_dir/verify.sh" rehearsal "$evidence_path"
        ;;
    fleet-live)
        run_id=${run_id:-${FLEET_VIDEO_RUN_ID:-}}
        case "$run_id" in
            ''|*[!A-Za-z0-9_-]*)
                printf 'video demo: --fleet-live requires a safe run ID\n' >&2
                exit 64
                ;;
        esac
        [ "${#run_id}" -le 48 ] || {
            printf 'video demo: run ID must be at most 48 characters\n' >&2
            exit 64
        }
        evidence_rel=target/fleet-demo/$run_id/final.json
        evidence_path=$repo_root/$evidence_rel
        require_real_directory "$repo_root/target"
        require_real_directory "$repo_root/target/fleet-demo"
        require_real_directory "$repo_root/target/fleet-demo/$run_id"
        "$script_dir/verify.sh" fleet-live "$evidence_path" "$run_id"
        ;;
    ostk-live)
        run_id=${run_id:-${FLEET_VIDEO_RUN_ID:-}}
        case "$run_id" in
            ''|*[!A-Za-z0-9_-]*)
                printf 'video demo: --ostk-live requires a safe OSTK run ID\n' >&2
                exit 64
                ;;
        esac
        [ "${#run_id}" -le 48 ] || {
            printf 'video demo: OSTK run ID must be at most 48 characters\n' >&2
            exit 64
        }
        evidence_rel=target/ostk-demo/$run_id/final.json
        evidence_path=$repo_root/$evidence_rel
        require_real_directory "$repo_root/target"
        require_real_directory "$repo_root/target/ostk-demo"
        require_real_directory "$repo_root/target/ostk-demo/$run_id"
        "$script_dir/verify.sh" ostk-live "$evidence_path" "$run_id"
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

wait_for_pane_ready() {
    pane=$1
    previous_command=
    stable_polls=0
    attempt=0
    while [ "$attempt" -lt 100 ]; do
        current_command=$(tmux display-message -p -t "$pane" '#{pane_current_command}')
        if [ -n "$current_command" ] && [ "$current_command" = "$previous_command" ]; then
            stable_polls=$((stable_polls + 1))
        else
            stable_polls=0
            previous_command=$current_command
        fi
        [ "$stable_polls" -ge 3 ] && break
        attempt=$((attempt + 1))
        sleep 0.05
    done
    [ "$stable_polls" -ge 3 ] || {
        printf 'video demo: pane shell did not stabilize\n' >&2
        exit 1
    }

    tmux send-keys -t "$pane" -l -- "printf '%s\\n' __FLEET_VIDEO_PANE_READY__"
    tmux send-keys -t "$pane" Enter
    attempt=0
    while ! tmux capture-pane -p -t "$pane" | \
        grep -F '__FLEET_VIDEO_PANE_READY__' >/dev/null; do
        attempt=$((attempt + 1))
        [ "$attempt" -lt 100 ] || {
            printf 'video demo: pane shell did not accept input\n' >&2
            exit 1
        }
        sleep 0.05
    done

    tmux send-keys -t "$pane" -l -- "printf '\\033[2J\\033[H'"
    tmux send-keys -t "$pane" Enter
    attempt=0
    while tmux capture-pane -p -t "$pane" | \
        grep -F '__FLEET_VIDEO_PANE_READY__' >/dev/null; do
        attempt=$((attempt + 1))
        [ "$attempt" -lt 100 ] || {
            printf 'video demo: pane shell did not clear readiness marker\n' >&2
            exit 1
        }
        sleep 0.05
    done
}

for pane in "$main_pane" "$right_pane" "$agent_c_pane" \
    "$agent_b_resume_pane" "$footer_pane"; do
    wait_for_pane_ready "$pane"
done

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
