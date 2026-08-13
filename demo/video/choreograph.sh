#!/bin/sh
set -eu

[ "$#" -eq 9 ] || {
    printf 'usage: choreograph.sh SESSION MODE EVIDENCE DISPLAY A B C B2 FOOTER\n' >&2
    exit 64
}

session=$1
mode=$2
evidence=$3
display_mode=$4
agent_a=$5
agent_b=$6
agent_c=$7
agent_b_resume=$8
footer=$9

pause() {
    if [ "${FLEET_VIDEO_FAST:-0}" = 1 ]; then
        sleep 0.1
    else
        sleep "$1"
    fi
}

wait_for_text() {
    target=$1
    expected=$2
    [ "${FLEET_VIDEO_FAST:-0}" = 1 ] || return 0
    attempt=0
    while ! tmux capture-pane -p -t "$target" | grep -F "$expected" >/dev/null; do
        attempt=$((attempt + 1))
        [ "$attempt" -lt 100 ] || {
            printf 'video choreography: pane did not render expected text: %s\n' "$expected" >&2
            return 1
        }
        sleep 0.05
    done
}

send_command() {
    target=$1
    shift
    command_text=$*
    tmux select-pane -t "$target"
    tmux send-keys -t "$target" C-l
    tmux send-keys -t "$target" -l -- "$command_text"
    tmux send-keys -t "$target" Enter
}

show_footer() {
    stage=$1
    send_command "$footer" "./demo/video/footer.sh $stage $mode $evidence"
}

show_footer intro
wait_for_text "$footer" READY
pause 3

show_footer write
send_command "$agent_a" "./demo/video/pane.sh agent-a $mode $evidence"
wait_for_text "$agent_a" COMMITTED
pause 8

show_footer recall
send_command "$agent_b" "./demo/video/pane.sh agent-b $mode $evidence"
wait_for_text "$agent_b" ACTION
pause 10

show_footer conflict
send_command "$agent_c" "./demo/video/pane.sh agent-c $mode $evidence"
wait_for_text "$agent_c" INCOMPATIBLE
pause 8

show_footer resume
send_command "$agent_b_resume" "./demo/video/pane.sh agent-b-resume $mode $evidence"
wait_for_text "$agent_b_resume" 'SAFE HANDOFF'
pause 10

show_footer verified
wait_for_text "$footer" 'SCENARIO VERIFIED'
tmux select-pane -t "$footer"
pause 6

if [ "$display_mode" = attach ]; then
    tmux detach-client -s "$session" >/dev/null 2>&1 || true
fi
