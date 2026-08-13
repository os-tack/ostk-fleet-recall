#!/bin/sh
set -eu

[ "$#" -eq 3 ] || {
    printf 'usage: footer.sh STAGE MODE EVIDENCE\n' >&2
    exit 64
}
stage=$1
mode=$2
evidence=$3

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
if [ "$mode" = rehearsal ]; then
    provenance="${yellow}REHEARSAL${reset} · sanitized evidence · no cloud/LLM calls"
    source_name=docs/evidence/local-fleet-scenario.json
else
    run_id=$(jq -er '.run_id' "$evidence")
    provenance="${green}LIVE EVIDENCE${reset} · verified OSTK 7.7.7 run ${white}$run_id${reset}"
    source_name=target/ostk-demo/RUN_ID/final.json
fi

case "$stage" in
    intro) status="${blue}READY${reset} · A writes/replays → B recalls/acts → C conflicts → B resumes" ;;
    write) status="${blue}1/4${reset} · durable, idempotent memory write" ;;
    recall) status="${lavender}2/4${reset} · lexical + dense retrieval changes Agent B’s action" ;;
    conflict) status="${red}3/4${reset} · typed incompatibility becomes an open conflict" ;;
    resume) status="${yellow}4/4${reset} · resumed B pauses rollout and escalates with a citation" ;;
    verified) status="${green}${bold}✓ SCENARIO VERIFIED${reset} · memory → action → conflict → safe handoff" ;;
    *) printf 'video footer: unknown stage\n' >&2; exit 64 ;;
esac

printf '%b\n' "${bold}${white}OSTK FLEET RECALL${reset}  │  $provenance"
printf '%b\n' "${muted}CockroachDB 26.2${reset}  │  ${lavender}C-SPANN vector + lexical → RRF${reset}  │  $status"
if [ "$stage" = verified ]; then
    printf '%b\n' "${muted}fixture: $source_name · separate smoke gate: S3 + Secrets + task replacement${reset}"
else
    printf '%b\n' "${muted}fixture: $source_name · deployment-bound identities · scoped tenant/project corpus${reset}"
fi
