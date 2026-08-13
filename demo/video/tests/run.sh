#!/bin/sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$script_dir/../../.." && pwd)
cd "$repo_root"

for script in demo/video/capture-fleet.sh demo/video/run.sh \
    demo/video/choreograph.sh demo/video/pane.sh demo/video/footer.sh \
    demo/video/render.sh demo/video/verify.sh; do
    sh -n "$script"
done
sh -n deploy/localstack/fleet-demo.sh

vhs validate 'demo/video/*.tape' >/dev/null

assert_contains() {
    output=$1
    expected=$2
    label=$3
    printf '%s\n' "$output" | grep -F "$expected" >/dev/null || {
        printf 'video test: %s missing rendered text: %s\n' "$label" "$expected" >&2
        exit 1
    }
}

assert_rejected() {
    label=$1
    shift
    if "$@" >/dev/null 2>&1; then
        printf 'video test: invalid evidence accepted: %s\n' "$label" >&2
        exit 1
    fi
}

rehearsal_evidence=docs/evidence/local-fleet-scenario.json
./demo/video/verify.sh rehearsal "$rehearsal_evidence"
rehearsal_capture=$(FLEET_VIDEO_FAST=1 ./demo/video/run.sh --rehearsal --headless)
for expected in \
    'DEDUPLICATED' \
    'lexical + dense' \
    'ACTION' \
    'INCOMPATIBLE' \
    'SAFE HANDOFF' \
    'SCENARIO VERIFIED' \
    'sanitized evidence'; do
    assert_contains "$rehearsal_capture" "$expected" rehearsal
done

fleet_run=video-fleet-test-$$
ostk_run=video-ostk-test-$$
test_root=target/video-tests-$$
fleet_dir=target/fleet-demo/$fleet_run
ostk_dir=target/ostk-demo/$ostk_run
symlink_dir=
cleanup() {
    rm -f "$fleet_dir/final.json" "$ostk_dir/final.json"
    rm -f "$test_root"/*.json "$test_root"/linked.json
    if [ -n "$symlink_dir" ]; then
        rm -f "$symlink_dir"
    fi
    rmdir "$fleet_dir" "$ostk_dir" "$test_root" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM
mkdir -p "$fleet_dir" "$ostk_dir" "$test_root"

assert_rejected 'ambiguous legacy --live flag' \
    ./demo/video/run.sh --live "$fleet_run" --headless
assert_rejected 'capture helper unsafe run ID' \
    ./demo/video/capture-fleet.sh 'contains.dot'
for mode in fleet-live ostk-live; do
    assert_rejected "$mode missing evidence" \
        ./demo/video/run.sh "--$mode" missing-run --headless
    for unsafe_run in '..' 'contains.dot' \
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'; do
        assert_rejected "$mode unsafe run ID $unsafe_run" \
            ./demo/video/run.sh "--$mode" "$unsafe_run" --headless
    done
done

jq --arg run "$fleet_run" '
    .capture = "live" |
    .run_id = $run |
    .scenario = $run |
    .generated_at = "2026-08-13T12:34:56Z"
' "$rehearsal_evidence" >"$fleet_dir/final.json"

./demo/video/verify.sh fleet-live "$fleet_dir/final.json" "$fleet_run"
assert_rejected 'capture helper refuses existing run destination' \
    ./demo/video/capture-fleet.sh "$fleet_run"
fleet_capture=$(FLEET_VIDEO_FAST=1 \
    ./demo/video/run.sh --fleet-live "$fleet_run" --headless)
for expected in \
    'LOCAL LIVE MCP EVIDENCE' \
    'local CockroachDB run' \
    'NO AWS/CLOUD' \
    'no OSTK/LLM' \
    'DEDUPLICATED' \
    'tenant/project boundary enforced' \
    'SCENARIO VERIFIED'; do
    assert_contains "$fleet_capture" "$expected" fleet-live
done
if printf '%s\n' "$fleet_capture" | grep -F 'OPTIONAL OSTK EVIDENCE' >/dev/null; then
    printf 'video test: standalone Fleet Recall evidence was labeled as OSTK\n' >&2
    exit 1
fi

tamper_fleet() {
    label=$1
    filter=$2
    path=$test_root/fleet-tampered.json
    jq "$filter" "$fleet_dir/final.json" >"$path"
    assert_rejected "$label" \
        ./demo/video/verify.sh fleet-live "$path" "$fleet_run"
}
tamper_fleet 'unverified standalone summary' '.verified = false'
tamper_fleet 'OSTK attribution injected into standalone run' \
    '.provenance.ostk_used = true'
tamper_fleet 'broken recall/action citation' \
    '.agent_b.action_based_on_claim_id = .agent_c.claim_id'
tamper_fleet 'non-exact conflict membership' \
    '.conflict.member_claim_ids += [.agent_b.action_claim_id]'
tamper_fleet 'malformed capture timestamp' '.generated_at = "now"'
assert_rejected 'standalone requested-run mismatch' \
    ./demo/video/verify.sh fleet-live "$fleet_dir/final.json" another-run

ln -s "$(pwd)/$fleet_dir/final.json" "$test_root/linked.json"
assert_rejected 'symlinked standalone evidence' \
    ./demo/video/verify.sh fleet-live "$test_root/linked.json" "$fleet_run"
rm -f "$test_root/linked.json"

symlink_run=capture-symlink-test-$$
symlink_dir=target/fleet-demo/$symlink_run
jq --arg run "$symlink_run" '.run_id = $run | .scenario = $run' \
    "$fleet_dir/final.json" >"$test_root/final.json"
ln -s "$(pwd)/$test_root" "$symlink_dir"
assert_rejected 'capture helper symlinked run directory' \
    ./demo/video/capture-fleet.sh "$symlink_run"
assert_rejected 'renderer symlinked run directory' \
    ./demo/video/run.sh --fleet-live "$symlink_run" --headless
rm -f "$symlink_dir"
symlink_dir=

jq -cn --arg run "$ostk_run" '{
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
}' >"$ostk_dir/final.json"

./demo/video/verify.sh ostk-live "$ostk_dir/final.json" "$ostk_run"
ostk_capture=$(FLEET_VIDEO_FAST=1 \
    ./demo/video/run.sh --ostk-live "$ostk_run" --headless)
for expected in \
    'OPTIONAL OSTK EVIDENCE' \
    'replay is not asserted' \
    'scope injection: separate deterministic gate' \
    'SCENARIO VERIFIED'; do
    assert_contains "$ostk_capture" "$expected" ostk-live
done

jq '.memory.recalled_claim_id = null | .actions[0].based_on_claim_id = null' \
    "$ostk_dir/final.json" >"$test_root/ostk-tampered.json"
assert_rejected 'null OSTK correlated identifiers' \
    ./demo/video/verify.sh ostk-live "$test_root/ostk-tampered.json" "$ostk_run"

assert_rejected 'standalone evidence presented as OSTK evidence' \
    ./demo/video/verify.sh ostk-live "$fleet_dir/final.json" "$fleet_run"
assert_rejected 'OSTK evidence presented as standalone evidence' \
    ./demo/video/verify.sh fleet-live "$ostk_dir/final.json" "$ostk_run"

printf '%s\n' \
    'video rehearsal, standalone Fleet Recall, optional OSTK, tapes, and tmux contracts passed.'
