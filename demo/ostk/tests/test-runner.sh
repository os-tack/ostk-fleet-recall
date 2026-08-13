#!/bin/sh
set -eu

test_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$test_dir/../../.." && pwd)
temporary=$(mktemp -d "${TMPDIR:-/tmp}/ostk-runner-test.XXXXXX")
cleanup() {
    rm -rf "$temporary"
}
trap cleanup EXIT HUP INT TERM

cat >"$temporary/ostk" <<'FAKE_OSTK'
#!/bin/sh
set -eu
printf '%s\n' "$*" >>"$FAKE_OSTK_LOG"
if [ "${1:-}" = --version ]; then
    printf '%s\n' "${FAKE_OSTK_VERSION:-ostk 7.7.7}"
    exit 0
fi
exit 97
FAKE_OSTK
chmod 700 "$temporary/ostk"
export FAKE_OSTK_LOG="$temporary/ostk.log"

plan=$(OSTK_DEMO_MODEL=test/model \
    OSTK_DEMO_BUDGET_USD=0.05 \
    OSTK_DEMO_OSTK_BIN="$temporary/ostk" \
    "$repo_root/demo/ostk/run.sh" --plan --run-id unit-plan)
printf '%s\n' "$plan" | jq -e '
    .mode == "plan-only" and
    .launches_agents == false and
    .cli == "ostk 7.7.7" and
    .budget_usd_per_invocation == 0.05 and
    .conservative_max_authorized_usd == 0.2 and
    (.invocations | length) == 4 and
    all(.invocations[]; .bridge_argv[1:3] == ["--run-id", "unit-plan"]) and
    .invocations[0].bridge_argv[3] == "record-decision" and
    .invocations[1].bridge_argv[3] == "recall-and-act" and
    .invocations[2].bridge_argv[3] == "record-conflict" and
    .invocations[3].command == "ostk agent resume" and
    .invocations[3].name == "ostk-recall-b-unit-plan" and
    .invocations[3].bridge_argv[3] == "recall-conflict-and-pause" and
    all(.invocations[0:3][]; .prompt_file | contains("/target/ostk-demo/unit-plan/prompts/"))
' >/dev/null
[ "$(wc -l <"$temporary/ostk.log" | tr -d ' ')" -eq 1 ]
grep -Fx -- '--version' "$temporary/ostk.log" >/dev/null

if OSTK_DEMO_MODEL=test/model \
    OSTK_DEMO_BUDGET_USD=0.05 \
    OSTK_DEMO_OSTK_BIN="$temporary/ostk" \
    "$repo_root/demo/ostk/run.sh" --run-id no-consent >/dev/null 2>&1; then
    printf '%s\n' 'runner launched without explicit billing consent' >&2
    exit 1
fi

if OSTK_DEMO_ALLOW_BILLING=I_UNDERSTAND_FOUR_AGENT_RUNS_MAY_BILL \
    OSTK_DEMO_MODEL=test/model \
    OSTK_DEMO_BUDGET_USD=0.05 \
    OSTK_DEMO_OSTK_BIN="$temporary/ostk" \
    "$repo_root/demo/ostk/run.sh" --run-id no-local-project >/dev/null 2>&1; then
    printf '%s\n' 'runner accepted an ancestor OSTK project without repo-local opt-in' >&2
    exit 1
fi
[ "$(wc -l <"$temporary/ostk.log" | tr -d ' ')" -eq 3 ]

if FAKE_OSTK_VERSION='ostk 7.7.8' \
    OSTK_DEMO_MODEL=test/model \
    OSTK_DEMO_BUDGET_USD=0.05 \
    OSTK_DEMO_OSTK_BIN="$temporary/ostk" \
    "$repo_root/demo/ostk/run.sh" --plan --run-id wrong-version >/dev/null 2>&1; then
    printf '%s\n' 'runner accepted an unsupported OSTK semantic version' >&2
    exit 1
fi

if OSTK_DEMO_MODEL=test/model \
    OSTK_DEMO_BUDGET_USD=0.05 \
    OSTK_DEMO_OSTK_BIN="$temporary/ostk" \
    "$repo_root/demo/ostk/run.sh" --plan --run-id invalid.dot >/dev/null 2>&1; then
    printf '%s\n' 'runner accepted an OSTK-incompatible run ID' >&2
    exit 1
fi

printf '%s\n' 'runner: fake OSTK 7.7.7 plan and billing gate passed'
