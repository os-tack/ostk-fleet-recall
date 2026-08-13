#!/bin/sh
set -eu

[ "$#" -eq 3 ] || {
    printf 'usage: pane.sh ROLE MODE EVIDENCE\n' >&2
    exit 64
}
role=$1
mode=$2
evidence=$3

case "$evidence" in
    /*|*..*|*[!A-Za-z0-9._/-]*)
        printf 'video pane: unsafe evidence path\n' >&2
        exit 64
        ;;
esac
[ -f "$evidence" ] || {
    printf 'video pane: evidence not found\n' >&2
    exit 1
}

blue='\033[38;2;137;180;250m'
green='\033[38;2;166;227;161m'
yellow='\033[38;2;249;226;175m'
red='\033[38;2;243;139;168m'
lavender='\033[38;2;180;190;254m'
muted='\033[38;2;147;153;178m'
white='\033[38;2;205;214;244m'
bold='\033[1m'
reset='\033[0m'

printf '\033[2J\033[H\033[?25l'

line() {
    printf '%b\n' "$1"
    if [ "${FLEET_VIDEO_FAST:-0}" = 1 ]; then
        sleep 0.02
    else
        sleep 0.42
    fi
}

label() {
    printf '%b%-14s%b %s' "$muted" "$1" "$reset" "$2"
}

case "$mode" in
rehearsal|fleet-live)
    claim_a=$(jq -er '.agent_a.claim_id' "$evidence")
    action=$(jq -er '.agent_b.action' "$evidence")
    action_claim=$(jq -er '.agent_b.action_claim_id' "$evidence")
    claim_c=$(jq -er '.agent_c.claim_id' "$evidence")
    conflict=$(jq -er '.conflict.id' "$evidence")
    members=$(jq -er '.conflict.member_claim_ids | map("#" + tostring) | join(" + ")' "$evidence")
    escalation=$(jq -er '.agent_b.escalation' "$evidence")
    escalation_claim=$(jq -er '.agent_b.escalation_claim_id' "$evidence")
    agent_a_name=$(jq -er '.identities.writer' "$evidence")
    agent_b_name=$(jq -er '.identities.retriever' "$evidence")
    agent_c_name=$(jq -er '.identities.conflicting_writer' "$evidence")
    ;;
ostk-live)
    claim_a=$(jq -er '.memory.recalled_claim_id' "$evidence")
    action=$(jq -er '.actions[0].action' "$evidence")
    action_claim=receipt
    claim_c=$(jq -er '.memory.incompatible_claim_id' "$evidence")
    conflict=$(jq -er '.memory.open_conflict_id' "$evidence")
    members=\#$claim_a' + #'$claim_c
    escalation=$(jq -er '.actions[1].action' "$evidence")
    escalation_claim=receipt
    agent_a_name=$(jq -er '.orchestrator.sessions[0]' "$evidence")
    agent_b_name=$(jq -er '.orchestrator.sessions[1]' "$evidence")
    agent_c_name=$(jq -er '.orchestrator.sessions[2]' "$evidence")
    ;;
*)
    printf 'video pane: unknown mode: %s\n' "$mode" >&2
    exit 64
    ;;
esac

case "$role" in
    agent-a)
        line "${blue}${bold}\$ recall remember${reset}  ${muted}identity: $agent_a_name${reset}"
        line "$(label kind "${white}decision${reset}")"
        line "$(label subject "${white}fleet schema migration${reset}")"
        line "$(label value "${yellow}single dedicated migrator${reset}")"
        line ""
        line "${green}${bold}✓ COMMITTED${reset}      claim ${green}#$claim_a${reset}"
        if [ "$mode" != ostk-live ]; then
            line "${blue}\$ retry${reset}          same idempotency key"
            line "${green}${bold}✓ DEDUPLICATED${reset}  same claim ${green}#$claim_a${reset}; no duplicate"
        else
            line "${muted}live final.json proves commit; replay is not asserted${reset}"
        fi
        ;;
    agent-b)
        line "${blue}${bold}\$ recall search${reset}    ${muted}identity: $agent_b_name${reset}"
        line "${white}“How should workers coordinate schema changes?”${reset}"
        line ""
        line "$(label lanes "${lavender}lexical + dense${reset}")"
        line "$(label fusion "${lavender}reciprocal-rank (RRF)${reset}")"
        line "$(label best-hit "${green}claim #$claim_a${reset}")"
        if [ "$mode" != ostk-live ]; then
            line "${green}✓ tenant/project boundary enforced${reset}"
        else
            line "${muted}scope injection: separate deterministic gate${reset}"
        fi
        line ""
        line "${yellow}${bold}ACTION${reset}  $action"
        line "$(label citation "${green}claim #$claim_a${reset}")"
        line "$(label persisted "${green}$action_claim${reset}")"
        ;;
    agent-c)
        line "${blue}${bold}\$ recall remember${reset}  ${muted}identity: $agent_c_name${reset}"
        line "$(label kind "${white}decision${reset}")"
        line "$(label subject "${white}fleet schema migration${reset}")"
        line "$(label value "${red}every worker migrates${reset}")"
        line ""
        line "${green}✓ claim #$claim_c committed${reset}"
        line "${red}${bold}! INCOMPATIBLE${reset} with claim #$claim_a"
        line "$(label conflict "${red}#$conflict · OPEN${reset}")"
        line "$(label members "${white}$members${reset}")"
        ;;
    agent-b-resume)
        line "${blue}${bold}\$ recall conflicts${reset} ${muted}resumed: $agent_b_name${reset}"
        line "$(label state "${red}OPEN${reset}")"
        line "$(label conflict "${red}#$conflict${reset}")"
        line "$(label disputed "${white}$members${reset}")"
        line ""
        line "${yellow}${bold}ACTION${reset}  $escalation"
        line "$(label citation "${red}conflict #$conflict${reset}")"
        line "$(label persisted "${green}$escalation_claim${reset}")"
        line "${green}${bold}✓ SAFE HANDOFF${reset}  operator review required"
        ;;
    *)
        printf 'video pane: unknown role: %s\n' "$role" >&2
        exit 64
        ;;
esac
