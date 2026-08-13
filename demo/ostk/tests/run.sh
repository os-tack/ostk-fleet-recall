#!/bin/sh
set -eu

test_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$test_dir/../../.." && pwd)

find "$repo_root/demo/ostk" -type f -name '*.sh' -exec sh -n {} \;

if command -v shellcheck >/dev/null 2>&1; then
    find "$repo_root/demo/ostk" -type f -name '*.sh' -print0 | \
        xargs -0 shellcheck --shell=sh --external-sources
else
    printf '%s\n' 'shellcheck not installed; syntax and behavior gates still run' >&2
fi

if rg -n '(^|[ ;])eval([ ;]|$)' "$repo_root/demo/ostk" --glob '*.sh' >/dev/null; then
    printf '%s\n' 'unsafe dynamic shell execution found in OSTK demo scripts' >&2
    exit 1
fi

for test_script in \
    "$test_dir/test-mcp-client.sh" \
    "$test_dir/test-bridge.sh" \
    "$test_dir/test-runner.sh"
do
    "$test_script"
done

printf '%s\n' 'OSTK bridge static and fake-backed tests passed.'
