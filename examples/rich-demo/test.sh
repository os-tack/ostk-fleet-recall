#!/bin/sh
set -eu

export LC_ALL=C
export TZ=UTC

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)

for command_name in cmp jq mktemp; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        printf 'required command not found: %s\n' "$command_name" >&2
        exit 69
    fi
done

test_root=$(mktemp -d "${TMPDIR:-/tmp}/fleet-rich-demo-test.XXXXXX")
case $test_root in
    "${TMPDIR:-/tmp}"/fleet-rich-demo-test.*) ;;
    *)
        printf 'unexpected temporary directory: %s\n' "$test_root" >&2
        exit 70
        ;;
esac

cleanup() {
    rm -rf "$test_root"
}
trap cleanup EXIT HUP INT TERM

first=$test_root/first.ndjson
second=$test_root/second.ndjson
duplicate=$test_root/duplicate.ndjson
authority=$test_root/authority.ndjson
sensitive=$test_root/sensitive.ndjson
unsafe_source=$test_root/unsafe-source.ndjson
malformed=$test_root/malformed.ndjson
whitespace_facet=$test_root/whitespace-facet.ndjson
control_facet=$test_root/control-facet.ndjson
broken_supersession=$test_root/broken-supersession.ndjson
blank_text=$test_root/blank-text.ndjson
escaped_sensitive=$test_root/escaped-sensitive.ndjson
dead_source=$test_root/dead-source.ndjson

"$script_dir/generate.sh" > "$first"
"$script_dir/generate.sh" > "$second"
"$script_dir/verify.sh" "$first"

if ! cmp -s "$first" "$second"; then
    printf 'rich demo verification failed: generator output is not deterministic\n' >&2
    exit 1
fi

jq -s -c '. + [.[0]] | .[]' "$first" > "$duplicate"
if "$script_dir/verify.sh" "$duplicate" >/dev/null 2>&1; then
    printf 'rich demo verification failed: verifier accepted duplicate coordinates\n' >&2
    exit 1
fi

jq -s -c '.[0].project = "caller-controlled" | .[]' "$first" > "$authority"
if "$script_dir/verify.sh" "$authority" >/dev/null 2>&1; then
    printf 'rich demo verification failed: verifier accepted an authority field\n' >&2
    exit 1
fi

jq -s -c '.[0].text += (" AK" + "IA" + ("0" * 16)) | .[]' "$first" > "$sensitive"
if "$script_dir/verify.sh" "$sensitive" >/dev/null 2>&1; then
    printf 'rich demo verification failed: verifier accepted a credential-like pattern\n' >&2
    exit 1
fi

jq -s -c '.[0].source_id = "docs/../README.md" | .[]' "$first" > "$unsafe_source"
if "$script_dir/verify.sh" "$unsafe_source" >/dev/null 2>&1; then
    printf 'rich demo verification failed: verifier accepted an unsafe source path\n' >&2
    exit 1
fi

sed '1s/$/ trailing-data/' "$first" > "$malformed"
if "$script_dir/verify.sh" "$malformed" >/dev/null 2>&1; then
    printf 'rich demo verification failed: verifier accepted malformed NDJSON\n' >&2
    exit 1
fi

jq -s -c '.[0].facets.tags[0] = " documentation " | .[]' "$first" > "$whitespace_facet"
if "$script_dir/verify.sh" "$whitespace_facet" >/dev/null 2>&1; then
    printf 'rich demo verification failed: verifier accepted facet whitespace\n' >&2
    exit 1
fi

jq -s -c '.[0].facets.tags[0] = "doc\u0085umentation" | .[]' "$first" > "$control_facet"
if "$script_dir/verify.sh" "$control_facet" >/dev/null 2>&1; then
    printf 'rich demo verification failed: verifier accepted a facet control character\n' >&2
    exit 1
fi

jq -s -c '
    map(if .source_id == "rich-demo/operations/week-02/supersession"
        then .facets.scenario = ["unrelated prior decision"]
        else .
        end)
    | .[]
' "$first" > "$broken_supersession"
if "$script_dir/verify.sh" "$broken_supersession" >/dev/null 2>&1; then
    printf 'rich demo verification failed: verifier accepted a mismatched supersession\n' >&2
    exit 1
fi

jq -s -c '.[0].text = (" " * 40) | .[]' "$first" > "$blank_text"
if "$script_dir/verify.sh" "$blank_text" >/dev/null 2>&1; then
    printf 'rich demo verification failed: verifier accepted blank text\n' >&2
    exit 1
fi

awk '
    BEGIN {
        marker = "\\u0041KIA"
        for (digit = 0; digit < 16; digit++) {
            marker = marker "0"
        }
    }
    NR == 1 {
        location = index($0, "\"text\":\"")
        if (location == 0) {
            exit 2
        }
        $0 = substr($0, 1, location + 7) marker " " substr($0, location + 8)
    }
    { print }
' "$first" > "$escaped_sensitive"
if "$script_dir/verify.sh" "$escaped_sensitive" >/dev/null 2>&1; then
    printf 'rich demo verification failed: verifier accepted an encoded credential-like pattern\n' >&2
    exit 1
fi

jq -s -c '
    map(if .source_id == "README.md"
        then .source_id = "docs/nonexistent-rich-demo-source.md"
        else .
        end)
    | .[]
' "$first" > "$dead_source"
if "$script_dir/verify.sh" "$dead_source" >/dev/null 2>&1; then
    printf 'rich demo verification failed: verifier accepted a dead documentation source\n' >&2
    exit 1
fi

printf '%s\n' 'rich demo generator is deterministic'
