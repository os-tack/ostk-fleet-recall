#!/bin/sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$script_dir/../.." && pwd)

usage() {
    printf 'usage: demo/video/capture-fleet.sh [RUN_ID]\n' >&2
    exit 64
}

[ "$#" -le 1 ] || usage
run_id=${1:-fleet-$(date -u +%Y%m%dT%H%M%SZ)-$$}
case "$run_id" in
    ''|*[!A-Za-z0-9_-]*) usage ;;
esac
[ "${#run_id}" -le 48 ] || usage

evidence_dir=$repo_root/target/fleet-demo/$run_id
evidence_path=$evidence_dir/final.json
evidence_base=$repo_root/target/fleet-demo
umask 077
[ ! -L "$repo_root/target" ] || {
    printf 'fleet evidence: refusing symlinked target directory\n' >&2
    exit 1
}
mkdir -p "$evidence_base"
[ -d "$evidence_base" ] && [ ! -L "$evidence_base" ] || {
    printf 'fleet evidence: target/fleet-demo must be a real directory\n' >&2
    exit 1
}
if [ -e "$evidence_dir" ] || [ -L "$evidence_dir" ]; then
    printf 'fleet evidence: refusing existing run destination %s\n' \
        "target/fleet-demo/$run_id" >&2
    exit 1
fi
# Directory creation is the per-run lock. Two captures cannot both claim the
# same run ID, and no successful or interrupted artifact is overwritten.
mkdir "$evidence_dir"
created_evidence_dir=1
[ ! -e "$evidence_path" ] && [ ! -L "$evidence_path" ] || exit 1

temporary=$(mktemp "$evidence_dir/.final.json.XXXXXX")
cleanup() {
    rm -f "$temporary"
    if [ "${created_evidence_dir:-0}" -eq 1 ]; then
        rmdir "$evidence_dir" 2>/dev/null || true
    fi
}
trap cleanup EXIT HUP INT TERM

FLEET_RECALL_SCENARIO_ID=$run_id \
    "$repo_root/deploy/localstack/fleet-demo.sh" --json >"$temporary"
"$script_dir/verify.sh" fleet-live "$temporary" "$run_id"
mv "$temporary" "$evidence_path"
trap - EXIT HUP INT TERM

printf 'Verified standalone Fleet Recall evidence: %s\n' \
    "target/fleet-demo/$run_id/final.json"
printf 'Preview: ./demo/video/run.sh --fleet-live %s\n' "$run_id"
printf 'Render:  ./demo/video/render.sh --fleet-live %s\n' "$run_id"
