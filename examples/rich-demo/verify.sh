#!/bin/sh
set -eu

export LC_ALL=C

if [ "$#" -ne 1 ]; then
    printf 'usage: %s PATH_TO_NDJSON\n' "$0" >&2
    exit 64
fi

input=$1

fail() {
    printf 'rich demo verification failed: %s\n' "$1" >&2
    exit 1
}

for command_name in awk grep jq wc; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        printf 'required command not found: %s\n' "$command_name" >&2
        exit 69
    fi
done

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
manifest=$script_dir/documents.txt

if [ ! -f "$manifest" ] || [ -L "$manifest" ]; then
    fail "document manifest must be a regular, non-symlink file"
fi

if [ ! -f "$input" ] || [ -L "$input" ]; then
    fail "input must be a regular, non-symlink file"
fi

line_count=$(wc -l < "$input" | tr -d '[:space:]')
case $line_count in
    ''|*[!0-9]*) fail "line count is not numeric" ;;
esac
if [ "$line_count" -lt 500 ] || [ "$line_count" -gt 1000 ]; then
    fail "record count must be between 500 and 1000 (found $line_count)"
fi

if awk 'length($0) > 16384 { exit 1 }' "$input"; then
    :
else
    fail "a physical NDJSON line exceeds 16,384 bytes"
fi

if grep -Eq '^[[:space:]]*$' "$input"; then
    fail "blank physical lines are not allowed"
fi

if ! jq -Rse '
    endswith("\n")
    and (split("\n")[:-1] as $lines
        | ($lines | length) > 0
        and all($lines[]; try (fromjson | type == "object") catch false))
' "$input" >/dev/null; then
    fail "input is not valid one-object-per-line JSON"
fi

if ! jq -s -e '
    def ingest_control_codepoint:
        . < 32 or (. >= 127 and . <= 159);
    def ingest_trim_whitespace:
        . == 9 or (. >= 10 and . <= 13) or . == 32 or . == 133 or . == 160
        or . == 5760 or (. >= 8192 and . <= 8202) or . == 8232 or . == 8233
        or . == 8239 or . == 8287 or . == 12288;

    all(.[];
        type == "object"
        and ((keys_unsorted - [
            "source", "source_id", "source_config_id", "chunk_index",
            "text", "role", "facets"
        ]) | length) == 0
        and .source == "markdown"
        and (.source_id | type == "string" and length <= 4096)
        and (.source_config_id == "rich-demo:docs:v1" or .source_config_id == "rich-demo:operations:v1")
        and (if .source_config_id == "rich-demo:docs:v1"
            then ((.source_id | test("^(README[.]md|docs/[A-Za-z0-9._/-]+|deploy/[A-Za-z0-9._/-]+)$"))
                and (.source_id | contains("//") | not)
                and (.source_id | split("/") | all(.[]; . != "." and . != "..")))
            else (.source_id | test("^rich-demo/operations/week-[0-9]{2}/[a-z0-9_-]+$"))
            end)
        and (.chunk_index | type == "number" and floor == . and . >= 0 and . < 10000)
        and (.text
            | type == "string"
            and length >= 40
            and length <= 2000
            and (contains("\u0000") | not)
            and (explode | any(.[]; ingest_trim_whitespace | not)))
        and (.role == "primary" or .role == "evolution" or .role == "usage")
        and (.facets | type == "object")
        and ((.facets | keys_unsorted) - [
            "dataset", "record_kind", "source_area", "event_type",
            "week", "scenario", "status", "tags"
        ] | length) == 0
        and all(.facets[];
            type == "array"
            and length > 0
            and length <= 16
            and all(.[];
                type == "string"
                and length > 0
                and length <= 256
                and (explode as $points
                    | ($points[0] | ingest_trim_whitespace | not)
                    and ($points[-1] | ingest_trim_whitespace | not)
                    and all($points[]; ingest_control_codepoint | not))
            )
        )
        and .facets.dataset == ["rich-demo"]
        and (if .source_config_id == "rich-demo:docs:v1"
            then (.facets.record_kind == ["documentation"]
                and (.facets.source_area | length) == 1
                and (.facets.tags | index("documentation")) != null)
            else (.facets.record_kind == ["operations_narrative"]
                and .facets.source_area == ["fleet_operations"]
                and (.facets.event_type | length) == 1
                and (.facets.week | length) == 1
                and (.facets.week[0] | test("^week-(0[1-9]|1[0-2])$"))
                and (. as $record
                    | $record.source_id
                    | startswith("rich-demo/operations/" + $record.facets.week[0] + "/"))
                and (.facets.scenario | length) == 1
                and (.facets.status | length) == 1
                and (.facets.tags | length) >= 2)
            end)
    )
' "$input" >/dev/null; then
    fail "records violate the bounded publication-safe ingest schema"
fi

if ! jq -s -e '
    [.[] | [.source, .source_id, .source_config_id, (.chunk_index | tostring)] | join("|")] as $coordinates
    | ($coordinates | length) == ($coordinates | unique | length)
' "$input" >/dev/null; then
    fail "source coordinates are not unique"
fi

if ! jq -s -e '
    [.[] | select(.source_config_id == "rich-demo:docs:v1")]
    | group_by(.source_id)
    | all(.[];
        length as $count
        | (map(.chunk_index) | sort) == [range(0; $count)]
    )
' "$input" >/dev/null; then
    fail "document chunk indexes are not contiguous and zero-based"
fi

if ! jq -s -e --rawfile document_manifest "$manifest" '
    ($document_manifest
        | split("\n")
        | map(select(length > 0 and (startswith("#") | not)))
        | map(split("|")[0])
        | sort) as $expected_doc_sources
    | ($expected_doc_sources | length) == 10
    and
    ([.[] | select(.source_config_id == "rich-demo:docs:v1")] | length) >= 300
    and ([.[] | select(.source_config_id == "rich-demo:operations:v1")] | length) == 204
    and ([.[] | select(.source_config_id == "rich-demo:docs:v1") | .source_id] | unique | sort)
        == $expected_doc_sources
    and ([.[] | select(.source_config_id == "rich-demo:operations:v1") | .source_id] | unique | length) == 204
    and all(.[] | select(.source_config_id == "rich-demo:operations:v1"); .chunk_index == 0)
    and ([.[] | .facets.source_area[]] | unique | length) >= 11
    and ([.[] | .role] | unique | sort) == ["evolution", "primary", "usage"]
' "$input" >/dev/null; then
    fail "documentation and operations content mix is incomplete"
fi

if ! jq -s -e '
    def week_id($week):
        "week-" + (if $week < 10 then "0" else "" end) + ($week | tostring);

    [.[] | select(.source_config_id == "rich-demo:operations:v1")] as $operations
    | ([$operations[] | select(.facets.event_type == ["conflict_scenario"]) | .facets.scenario[0]] | unique) as $conflicts
    | ([$operations[] | select(.facets.event_type == ["conflict_resolution"]) | .facets.scenario[0]] | unique) as $resolutions
    | ([$operations[] | .facets.week[0]] | unique | length) == 12
    and ([$operations[] | select(.facets.event_type == ["decision"])] | length) == 24
    and ([$operations[] | select(.facets.event_type == ["supersession"])] | length) == 11
    and ([$operations[] | select(.facets.event_type == ["retraction"])] | length) == 1
    and ([$operations[] | select(.facets.event_type == ["conflict_scenario"])] | length) == 8
    and ([$operations[] | select(.facets.event_type == ["conflict_resolution"])] | length) == 3
    and ($conflicts | length) == 8
    and ($resolutions | length) == 3
    and (($conflicts - $resolutions) | length) == 5
    and all($resolutions[]; . as $scenario | ($conflicts | index($scenario)) != null)
    and all($operations[] | select(.facets.event_type == ["conflict_scenario"]); .facets.status == ["open"])
    and all($operations[] | select(.facets.event_type == ["conflict_resolution"]); .facets.status == ["resolved"])
    and all($operations[] | select(.facets.event_type == ["supersession"]); .text | test("supersed"; "i"))
    and all($operations[] | select(.facets.event_type == ["supersession"]);
        .text | contains("The replacement instruction is to ") and contains(" because "))
    and all($operations[] | select(.facets.event_type == ["supersession"]);
        . as $supersession
        | ($supersession.facets.week[0]
            | capture("^week-(?<number>[0-9]{2})$").number
            | tonumber) as $week
        | ([$operations[]
            | select(
                .source_id == ("rich-demo/operations/" + week_id($week - 1) + "/decision-primary")
                and .facets.event_type == ["decision"]
                and .facets.status == ["accepted"]
                and .facets.scenario == $supersession.facets.scenario
                and .facets.tags[2] == $supersession.facets.tags[2]
            )]) as $prior
        | ($prior | length) == 1
        and (($prior[0].text
                | capture(" will (?<choice>.+)[.] The recorded rationale is").choice) as $old_choice
            | $supersession.text
            | contains("superseded the prior-week instruction: " + $old_choice + ".")))
    and all($operations[] | select(.facets.event_type == ["retraction"]); .text | test("retract"; "i"))
    and all($operations[] | select(.facets.event_type == ["retraction"]);
        . as $retraction
        | ([$operations[]
            | select(
                .source_id == "rich-demo/operations/week-06/telemetry-assertion-latency"
                and .facets.event_type == ["telemetry_assertion"]
                and .facets.status == ["provisional"]
                and .facets.scenario == $retraction.facets.scenario
            )]
            | length) == 1)
    and all($operations[] | select(.facets.event_type == ["conflict_scenario"]);
        .text | contains("Importing this narrative does not create typed claims or conflict state."))
' "$input" >/dev/null; then
    fail "multi-week decision, supersession, retraction, or conflict mix is incomplete"
fi

sensitive_pattern='(AKIA|ASIA)[A-Z0-9]{16}|-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|postgres(ql)?://[^[:space:]/:@]+:[^[:space:]@]+@|(sk|rk)-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{20,}|eyJ[A-Za-z0-9_-]{10,}[.]eyJ[A-Za-z0-9_-]{10,}|[Aa]uthorization:[[:space:]]*[Bb]earer[[:space:]]+[A-Za-z0-9._~-]{16,}|arn:aws:[^:[:space:]]*:[^:[:space:]]*:[0-9]{12}:'
if grep -Eiq "$sensitive_pattern" "$input"; then
    fail "input contains a credential, private-key, account-ARN, or token-like pattern"
fi
if jq -r '.. | strings' "$input" | grep -Eiq "$sensitive_pattern"; then
    fail "input contains an encoded credential, account-ARN, or token-like string"
fi

jq -s -r '
    ([.[] | select(.source_config_id == "rich-demo:docs:v1")] | length) as $docs
    | ([.[] | select(.source_config_id == "rich-demo:operations:v1")] | length) as $operations
    | "verified rich demo: \(length) chunks (\($docs) documentation, \($operations) operations)"
' "$input"
