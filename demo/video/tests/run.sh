#!/bin/sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$script_dir/../../.." && pwd)
cd "$repo_root"

for script in demo/video/run.sh demo/video/choreograph.sh \
    demo/video/pane.sh demo/video/footer.sh demo/video/render.sh; do
    sh -n "$script"
done

vhs validate 'demo/video/*.tape' >/dev/null

capture=$(FLEET_VIDEO_FAST=1 ./demo/video/run.sh --rehearsal --headless)
for expected in \
    'DEDUPLICATED' \
    'lexical + dense' \
    'ACTION' \
    'INCOMPATIBLE' \
    'SAFE HANDOFF' \
    'SCENARIO VERIFIED' \
    'sanitized evidence'; do
    printf '%s\n' "$capture" | grep -F "$expected" >/dev/null || {
        printf 'video test: expected rendered text missing: %s\n' "$expected" >&2
        exit 1
    }
done

if OSTK_DEMO_RUN_ID=missing-run ./demo/video/run.sh --live --headless \
    >/dev/null 2>&1; then
    printf 'video test: live mode accepted missing evidence\n' >&2
    exit 1
fi
for unsafe_run in '..' 'contains.dot' \
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'; do
    if ./demo/video/run.sh --live "$unsafe_run" --headless >/dev/null 2>&1; then
        printf 'video test: live mode accepted unsafe OSTK run ID: %s\n' "$unsafe_run" >&2
        exit 1
    fi
done

live_run=video-live-test-$$
live_dir=target/ostk-demo/$live_run
cleanup() {
    rm -f "$live_dir/final.json"
    rmdir "$live_dir" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM
mkdir -p "$live_dir"
jq -cn --arg run "$live_run" '{
    schema_version: 1,
    verified: true,
    run_id: $run,
    orchestrator: {
        product: "ostk",
        required_cli_version: "7.7.7",
        sessions: [
            ("ostk-recall-a-" + $run),
            ("ostk-recall-b-" + $run),
            ("ostk-recall-c-" + $run)
        ],
        resumed_session: ("ostk-recall-b-" + $run)
    },
    memory: {
        recalled_claim_id: 101,
        incompatible_claim_id: 202,
        open_conflict_id: 303,
        retrieval_lanes: ["lexical", "dense"],
        fusion: "rrf"
    },
    actions: [
        {
            action: "hold workers until migration completes",
            based_on_claim_id: 101,
            receipt: (
                "s3://fleet-recall-local-actions/ostk-demo/" + $run +
                "/agent-b/hold-workers.json"
            )
        },
        {
            action: "pause rollout and escalate for operator review",
            based_on_conflict_id: 303,
            receipt: (
                "s3://fleet-recall-local-actions/ostk-demo/" + $run +
                "/agent-b/pause-rollout.json"
            )
        }
    ]
}' >"$live_dir/final.json"

live_capture=$(FLEET_VIDEO_FAST=1 ./demo/video/run.sh --live "$live_run" --headless)
for expected in \
    'LIVE EVIDENCE' \
    'replay is not asserted' \
    'scope injection: separate deterministic gate' \
    'SCENARIO VERIFIED'; do
    printf '%s\n' "$live_capture" | grep -F "$expected" >/dev/null || {
        printf 'video test: expected live text missing: %s\n' "$expected" >&2
        exit 1
    }
done

jq '.memory.recalled_claim_id = null | .actions[0].based_on_claim_id = null' \
    "$live_dir/final.json" >"$live_dir/final.invalid"
mv "$live_dir/final.invalid" "$live_dir/final.json"
if FLEET_VIDEO_FAST=1 ./demo/video/run.sh --live "$live_run" --headless \
    >/dev/null 2>&1; then
    printf 'video test: live mode accepted null correlated identifiers\n' >&2
    exit 1
fi

printf 'video rehearsal contract, tapes, shell syntax, and tmux choreography passed.\n'
