#!/bin/sh
set -eu

export LC_ALL=C

if [ "$#" -ne 1 ]; then
    printf 'usage: %s PATH_TO_NDJSON\n' "$0" >&2
    exit 64
fi

input=$1
expected_source_revision=${RICH_DEMO_EXPECTED_SOURCE_REVISION:-}

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

if [ -n "$expected_source_revision" ]; then
    case $expected_source_revision in
        *[!0-9a-f]*)
            printf 'RICH_DEMO_EXPECTED_SOURCE_REVISION must be exactly 40 lowercase hexadecimal characters\n' >&2
            exit 65
            ;;
    esac
    if [ "${#expected_source_revision}" -ne 40 ]; then
        printf 'RICH_DEMO_EXPECTED_SOURCE_REVISION must be exactly 40 lowercase hexadecimal characters\n' >&2
        exit 65
    fi
fi

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$script_dir/../.." && pwd)
manifest=$script_dir/documents.txt
repository_manifest=$script_dir/repository-files.txt

if [ ! -f "$manifest" ] || [ -L "$manifest" ]; then
    fail "document manifest must be a regular, non-symlink file"
fi

if [ ! -f "$repository_manifest" ] || [ -L "$repository_manifest" ]; then
    fail "repository manifest must be a regular, non-symlink file"
fi

if [ ! -f "$input" ] || [ -L "$input" ]; then
    fail "input must be a regular, non-symlink file"
fi

extract_tools_excerpt() {
    awk '
        {
            lines[NR] = $0
            candidate = $0
            sub(/^[[:space:]]*/, "", candidate)
            sub(/[[:space:]]*$/, "", candidate)
            if (candidate == "\"enum\": [\"record\"]") {
                marker_count++
                marker_line = NR
            }
        }
        END {
            if (marker_count != 1 || marker_line < 3 || marker_line + 1 > NR) {
                exit 1
            }
            for (line = marker_line - 2; line <= marker_line + 1; line++) {
                print lines[line]
            }
        }
    ' "$1"
}

extract_tools_coordinates() {
    awk '
        {
            candidate = $0
            sub(/^[[:space:]]*/, "", candidate)
            sub(/[[:space:]]*$/, "", candidate)
            if (candidate == "\"enum\": [\"record\"]") {
                marker_count++
                marker_line = NR
            }
        }
        END {
            if (marker_count != 1 || marker_line < 3 || marker_line + 1 > NR) {
                exit 1
            }
            print marker_line - 2, marker_line + 1
        }
    ' "$1"
}

extract_application_excerpt() {
    awk '
        {
            lines[NR] = $0
            candidate = $0
            sub(/^[[:space:]]*/, "", candidate)
            sub(/[[:space:]]*$/, "", candidate)
            if (candidate == "RememberAction::Record => self.remember_record(&scope, request).await,") {
                record_count++
                record_line = NR
            }
            if (candidate == "\"remember({}) is outside the hackathon vertical slice\",") {
                marker_count++
                marker_line = NR
            }
        }
        END {
            if (record_count != 1 || marker_count != 1 || record_line != marker_line - 2 ||
                    marker_line < 4 || marker_line + 3 > NR) {
                exit 1
            }
            for (line = marker_line - 3; line <= marker_line + 3; line++) {
                print lines[line]
            }
        }
    ' "$1"
}

extract_application_coordinates() {
    awk '
        {
            candidate = $0
            sub(/^[[:space:]]*/, "", candidate)
            sub(/[[:space:]]*$/, "", candidate)
            if (candidate == "RememberAction::Record => self.remember_record(&scope, request).await,") {
                record_count++
                record_line = NR
            }
            if (candidate == "\"remember({}) is outside the hackathon vertical slice\",") {
                marker_count++
                marker_line = NR
            }
        }
        END {
            if (record_count != 1 || marker_count != 1 || record_line != marker_line - 2 ||
                    marker_line < 4 || marker_line + 3 > NR) {
                exit 1
            }
            print marker_line - 3, marker_line + 3
        }
    ' "$1"
}

tools_file=$repo_root/src/mcp/tools.rs
application_file=$repo_root/src/application.rs
for source_file in "$tools_file" "$application_file"; do
    if [ ! -f "$source_file" ] || [ -L "$source_file" ]; then
        fail "self-audit source must be a regular, non-symlink file: $source_file"
    fi
done
if ! tools_excerpt=$(extract_tools_excerpt "$tools_file"); then
    fail "src/mcp/tools.rs must contain exactly one expected remember action marker"
fi
if ! application_excerpt=$(extract_application_excerpt "$application_file"); then
    fail "src/application.rs must contain exactly one adjacent remember dispatch and rejection marker pair"
fi
if ! tools_coordinates=$(extract_tools_coordinates "$tools_file"); then
    fail "could not locate exact src/mcp/tools.rs source coordinates"
fi
if ! application_coordinates=$(extract_application_coordinates "$application_file"); then
    fail "could not locate exact src/application.rs source coordinates"
fi
tools_line_start=${tools_coordinates%% *}
tools_line_end=${tools_coordinates#* }
application_line_start=${application_coordinates%% *}
application_line_end=${application_coordinates#* }

line_count=$(wc -l < "$input" | tr -d '[:space:]')
case $line_count in
    ''|*[!0-9]*) fail "line count is not numeric" ;;
esac
if [ "$line_count" -ne 4382 ]; then
    fail "record count must be exactly 4382 (found $line_count)"
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

    def valid_facet_value:
        type == "string"
        and length > 0
        and length <= 256
        and (explode as $points
            | ($points[0] | ingest_trim_whitespace | not)
            and ($points[-1] | ingest_trim_whitespace | not)
            and all($points[]; ingest_control_codepoint | not));
    def valid_facet_array:
        type == "array"
        and length > 0
        and length <= 16
        and (map(valid_facet_value) | all);
    def valid_facets:
        type == "object"
        and ((keys_unsorted - [
            "dataset", "record_kind", "source_area", "event_type",
            "week", "scenario", "status", "document_status", "tags"
        ]) | length) == 0
        and ([.[] | valid_facet_array] | all);
    def valid_source_coordinates:
        type == "object"
        and ((keys_unsorted - [
            "source_revision", "source_line_start", "source_line_end"
        ]) | length) == 0
        and (.source_revision
            | type == "string" and test("^[0-9a-f]{40}$"))
        and (.source_line_start
            | type == "number" and floor == . and . >= 1 and . <= 1000000)
        and (.source_line_end
            | type == "number" and floor == . and . >= 1 and . <= 1000000)
        and .source_line_end >= .source_line_start
        and (.source_line_end - .source_line_start) <= 10000;
    def valid_record:
        . as $record
        | type == "object"
        and ((keys_unsorted - [
            "source", "source_id", "source_config_id", "chunk_index",
            "text", "role", "facets", "extra"
        ]) | length) == 0
        and ((($record.source_config_id == "rich-demo:self-audit:v1"
                or $record.source_config_id == "rich-demo:repository:v1")
                and $record.source == "code")
            or (($record.source_config_id != "rich-demo:self-audit:v1"
                    and $record.source_config_id != "rich-demo:repository:v1")
                and $record.source == "markdown"))
        and (($record.source_id | type) == "string" and ($record.source_id | length) <= 4096)
        and ($record.source_config_id == "rich-demo:docs:v1"
            or $record.source_config_id == "rich-demo:self-audit:v1"
            or $record.source_config_id == "rich-demo:repository:v1"
            or $record.source_config_id == "rich-demo:operations:v1")
        and (if $record.source_config_id == "rich-demo:docs:v1"
            then (($record.source_id | test("^(README[.]md|contracts/[A-Za-z0-9._/-]+|docs/[A-Za-z0-9._/-]+|deploy/[A-Za-z0-9._/-]+|examples/[A-Za-z0-9._/-]+)$"))
                and ($record.source_id | contains("//") | not)
                and ($record.source_id | split("/") | all(.[]; . != "." and . != "..")))
            elif $record.source_config_id == "rich-demo:self-audit:v1"
            then ($record.source_id == "src/mcp/tools.rs" or $record.source_id == "src/application.rs")
            elif $record.source_config_id == "rich-demo:repository:v1"
            then (($record.source_id | test("^[A-Za-z0-9._/-]+$"))
                and ($record.source_id | contains("//") | not)
                and ($record.source_id | split("/") | all(.[]; . != "" and . != "." and . != "..")))
            else ($record.source_id | test("^rich-demo/operations/week-[0-9]{2}/[a-z0-9_-]+$"))
            end)
        and ($record.chunk_index | type == "number" and floor == . and . >= 0 and . < 10000)
        and ($record.text
            | type == "string"
            and length >= 40
            and length <= 2000
            and (explode | index(0) | not)
            and (explode | any(.[]; ingest_trim_whitespace | not)))
        and ($record.role == "primary" or $record.role == "evolution" or $record.role == "usage")
        and (if $record.source_config_id == "rich-demo:operations:v1"
            then ($record | has("extra") | not)
            else ($record.extra | valid_source_coordinates)
            end)
        and ($record.facets | valid_facets)
        and $record.facets.dataset == ["rich-demo"]
        and (if $record.source_config_id == "rich-demo:docs:v1"
            then ($record.facets.record_kind == ["documentation"]
                and ($record.facets.source_area | length) == 1
                and ($record.facets.tags | index("documentation")) != null)
            elif $record.source_config_id == "rich-demo:self-audit:v1"
            then ($record.facets.record_kind == ["source_code"]
                and $record.facets.source_area == ["source_code"]
                and $record.facets.tags[0:2] == ["self_audit", "rust"]
                and ($record.facets.tags | length) == 3)
            elif $record.source_config_id == "rich-demo:repository:v1"
            then ($record.facets.record_kind == ["source_code"]
                and ($record.facets.source_area | length) == 1
                and ($record.facets.tags | length) == 3
                and $record.facets.tags[0] == "repository"
                and $record.facets.tags[2] == $record.facets.source_area[0])
            else ($record.facets.record_kind == ["operations_narrative"]
                and $record.facets.source_area == ["fleet_operations"]
                and ($record.facets.event_type | length) == 1
                and ($record.facets.week | length) == 1
                and ($record.facets.week[0] | test("^week-(0[1-9]|1[0-2])$"))
                and ($record.source_id
                    | startswith("rich-demo/operations/" + $record.facets.week[0] + "/"))
                and ($record.facets.scenario | length) == 1
                and ($record.facets.status | length) == 1
                and ($record.facets.tags | length) >= 2)
            end);

    # `map` materializes one Boolean per record. This avoids the jq 1.6
    # generator-context behavior of `all(.[]; complex | expressions)` while
    # retaining the exact same bounded schema predicate.
    map(valid_record) | all
' "$input" >/dev/null; then
    fail "records violate the bounded publication-safe ingest schema"
fi

if [ -n "$expected_source_revision" ] && ! jq -s -e \
    --arg expected_source_revision "$expected_source_revision" '
    all(.[] | select(.source_config_id != "rich-demo:operations:v1");
        .extra.source_revision == $expected_source_revision)
' "$input" >/dev/null; then
    fail "repository source revisions do not match the expected build revision"
fi

if ! jq -s -e '
    [.[] | [.source, .source_id, .source_config_id, (.chunk_index | tostring)] | join("|")] as $coordinates
    | ($coordinates | length) == ($coordinates | unique | length)
' "$input" >/dev/null; then
    fail "source coordinates are not unique"
fi

if ! jq -s -e '
    [.[] | select(.source_config_id != "rich-demo:operations:v1")]
    | group_by([.source_config_id, .source_id])
    | all(.[];
        length as $count
        | (map(.chunk_index) | sort) == [range(0; $count)]
    )
' "$input" >/dev/null; then
    fail "repository source chunk indexes are not contiguous and zero-based"
fi

if ! jq -s -e \
    --rawfile document_manifest "$manifest" \
    --rawfile repository_manifest "$repository_manifest" \
    --arg expected_tools_excerpt "$tools_excerpt" \
    --arg expected_application_excerpt "$application_excerpt" \
    --argjson expected_tools_line_start "$tools_line_start" \
    --argjson expected_tools_line_end "$tools_line_end" \
    --argjson expected_application_line_start "$application_line_start" \
    --argjson expected_application_line_end "$application_line_end" '
    ($document_manifest
        | split("\n")
        | map(select(length > 0 and (startswith("#") | not)))
        | map(split("|")[0])
        | sort) as $expected_doc_sources
    | ($repository_manifest
        | split("\n")
        | map(select(length > 0 and (startswith("#") | not)))
        | map(split("|")[0])
        | sort) as $expected_repository_sources
    | ($expected_doc_sources | length) == 32
    and ($expected_repository_sources | length) == 235
    and
    ([.[] | select(.source_config_id == "rich-demo:docs:v1")] | length) == 848
    and ([.[] | select(.source_config_id == "rich-demo:self-audit:v1")] | length) == 2
    and ([.[] | select(.source_config_id == "rich-demo:repository:v1")] | length) == 3328
    and ([.[] | select(.source_config_id == "rich-demo:operations:v1")] | length) == 204
    and ([.[] | select(.source_config_id == "rich-demo:docs:v1") | .source_id] | unique | sort)
        == $expected_doc_sources
    and ([.[] | select(.source_config_id == "rich-demo:repository:v1") | .source_id] | unique | sort)
        == $expected_repository_sources
    and ([.[] | select(
            .source_config_id == "rich-demo:repository:v1"
            and .source_id == "src/bin/ostk-control-bootstrap.rs"
        )] | length) == 11
    and ([.[] | select(
            .source_config_id == "rich-demo:repository:v1"
            and .source_id == "src/bin/ostk-registry-activate.rs"
        )] | length) == 22
    and ([.[] | select(
            .source_config_id == "rich-demo:repository:v1"
            and .source_id == "src/bin/ostk-registry-successor-activate.rs"
        )] | length) == 62
    and ([.[] | select(
            .source_config_id == "rich-demo:repository:v1"
            and .source_id == "src/bin/ostk-conflict-reconcile.rs"
        )] | length) == 26
    and ([.[] | select(
            .source_config_id == "rich-demo:repository:v1"
            and .source_id == "src/ledger/reconciliation.rs"
        )] | length) == 135
    and ([.[] | select(
            .source_config_id == "rich-demo:repository:v1"
            and .source_id == "deploy/cockroach/conflict-reconciliation-role-grants.sql"
        )] | length) == 27
    and ([.[] | select(
            .source_config_id == "rich-demo:repository:v1"
            and .source_id == "deploy/cockroach/publication-reader-role-grants.sql"
        )] | length) == 30
    and ([.[] | select(
            .source_config_id == "rich-demo:repository:v1"
            and .source_id == "deploy/cockroach/successor-activation-role-grants.sql"
        )] | length) == 23
    and ([.[] | select(
            .source_config_id == "rich-demo:repository:v1"
            and .source_id == "deploy/cockroach/tests/conflict-reconciliation-role-grants.sh"
        )] | length) == 95
    and ([.[] | select(
            .source_config_id == "rich-demo:repository:v1"
            and .source_id == "deploy/cockroach/tests/publication-reader-role-grants.sh"
        )] | length) == 130
    and ([.[] | select(
            .source_config_id == "rich-demo:repository:v1"
            and .source_id == "deploy/cockroach/runtime-role-grants.sql"
        )] | length) == 29
    and ([.[] | select(
            .source_config_id == "rich-demo:repository:v1"
            and .source_id == "deploy/cockroach/tests/runtime-role-grants.sh"
        )] | length) == 101
    and ([.[] | select(
            .source_config_id == "rich-demo:repository:v1"
            and .source_id == "deploy/cockroach/tests/successor-activation-role-grants.sh"
        )] | length) == 77
    and ([.[] | select(
            .source_config_id == "rich-demo:repository:v1"
            and .source_id == "migrations/0015_conflict_detector_uniqueness.sql"
        )] | length) == 5
    and ([.[] | select(
            .source_config_id == "rich-demo:repository:v1"
            and .source_id == "migrations/0016_claim_transition_provenance_index.sql"
        )] | length) == 3
    and ([.[] | select(
            .source_config_id == "rich-demo:repository:v1"
            and .source_id == "migrations/0017_conflict_detector_projection_index.sql"
        )] | length) == 3
    and ([.[] | select(
            .source_config_id == "rich-demo:repository:v1"
            and .source_id == "src/private_postgres.rs"
        )] | length) == 24
    and ([.[] | select(
            .source_config_id == "rich-demo:repository:v1"
            and .source_id == "tests/publication_reader_live.rs"
        )] | length) == 16
    and ([.[] | select(.source_id == "src/config.rs")] | length) == 0
    and ([.[] | select(.source_config_id == "rich-demo:operations:v1") | .source_id] | unique | length) == 204
    and ([.[] | select(.source_config_id == "rich-demo:self-audit:v1") | .source_id] | sort)
        == ["src/application.rs", "src/mcp/tools.rs"]
    and all(.[] | select(.source_config_id == "rich-demo:self-audit:v1"); .chunk_index == 0)
    and all(.[] | select(.source_config_id == "rich-demo:operations:v1"); .chunk_index == 0)
    and ([.[] | select(.source_config_id != "rich-demo:operations:v1") | .extra.source_revision]
        | unique | length) == 1
    and ([.[] | select(
            .source_config_id == "rich-demo:repository:v1"
            and .source_id == "src/mcp/server.rs"
            and (.text | test("mcp"; "i"))
        )] | length) >= 1
    and ([.[] | select(
            .source_config_id == "rich-demo:repository:v1"
            and .source_id == "deploy/aws/main.tf"
            and (.text | test("aws_(ecs|cloudfront|lb|wafv2)"))
        )] | length) >= 1
    and ([.[] | select(
            .source_config_id == "rich-demo:docs:v1"
            and .source_id == "examples/README.md"
            and (.text | contains("Use MCP `remember` for deliberate claims"))
            and (.text | contains("retractions, and conflicts"))
            and (.text | contains("provenance and transaction semantics are actually exercised"))
        )] | length) == 1
    and ([.[] | select(
            .source_config_id == "rich-demo:docs:v1"
            and .source_id == "docs/PROJECT_PRIMER.md"
            and (.text | contains("Fleet Recall gives replaceable agents a shared memory plane"))
        )] | length) == 1
    and ([.[] | select(
            .source_config_id == "rich-demo:docs:v1"
            and .source_id == "docs/PROJECT_PRIMER.md"
            and (.text | contains("SQLx 0.8 with its PostgreSQL driver"))
            and (.text | contains("Tokio async runtime"))
            and (.text | contains("Rustls TLS support"))
        )] | length) == 1
    and ([.[] | select(
            .source_config_id == "rich-demo:docs:v1"
            and .source_id == "docs/PROJECT_PRIMER.md"
            and (.text | contains("serializable transactions"))
            and (.text | contains("C-SPANN indexes"))
            and (.text | contains("`TSVECTOR` lexical index"))
        )] | length) == 1
    and ([.[] | select(
            .source_config_id == "rich-demo:docs:v1"
            and .source_id == "docs/DYNAMIC_MEMORY_ARCHITECTURE.md"
        )] | length) > 0
    and all(.[] | select(
            .source_config_id == "rich-demo:docs:v1"
            and .source_id == "docs/DYNAMIC_MEMORY_ARCHITECTURE.md"
        );
        (.text | startswith("Draft target architecture; not implemented. "))
        and .facets.document_status == ["draft_target"]
        and (.facets.tags | index("draft_target")) != null
    )
    and ([.[] | select(
            .source_config_id == "rich-demo:self-audit:v1"
            and .source_id == "src/mcp/tools.rs"
            and .text == $expected_tools_excerpt
            and .extra.source_line_start == $expected_tools_line_start
            and .extra.source_line_end == $expected_tools_line_end
            and (.text | contains("\"enum\": [\"record\"]"))
            and .facets.tags == ["self_audit", "rust", "mcp_contract"]
        )] | length) == 1
    and ([.[] | select(
            .source_config_id == "rich-demo:self-audit:v1"
            and .source_id == "src/application.rs"
            and .text == $expected_application_excerpt
            and .extra.source_line_start == $expected_application_line_start
            and .extra.source_line_end == $expected_application_line_end
            and (.text | contains("RememberAction::Record => self.remember_record"))
            and (.text | contains("remember({}) is outside the hackathon vertical slice"))
            and .facets.tags == ["self_audit", "rust", "service_dispatch"]
        )] | length) == 1
    and ([.[] | .facets.source_area[]] | unique | length) >= 13
    and ([.[] | .role] | unique | sort) == ["evolution", "primary", "usage"]
' "$input" >/dev/null; then
    fail "documentation, self-audit source, and operations content mix is incomplete"
fi

# Every repository-document coordinate must be the minimal inclusive physical
# line range containing the normalized chunk body. This checks the metadata
# against the checked-in source itself: widening either edge, shifting the
# range, or pointing past EOF fails even when the JSON shape remains valid.
while IFS='|' read -r relative_path _; do
    case $relative_path in
        ''|'#'*) continue ;;
    esac
    document=$repo_root/$relative_path
    if [ ! -f "$document" ] || [ -L "$document" ]; then
        fail "manifest entry must be a regular, non-symlink file: $relative_path"
    fi
    if ! jq -s -e \
        --arg source_id "$relative_path" \
        --rawfile source_text "$document" '
        def clean_source:
            gsub("\r"; "")
            | gsub("\t"; " ")
            | gsub("[[:space:]]+"; " ")
            | sub("^ "; "")
            | sub(" $"; "");
        def normalized_slice($lines; $start; $finish):
            $lines[($start - 1):$finish] | join(" ") | clean_source;
        def section_at($lines; $start):
            reduce range(0; $start - 1) as $index (
                {section: "Overview", in_fence: false};
                ($lines[$index] | sub("\r$"; "")) as $line
                | if ($line | test("^[[:space:]]*(```|~~~)")) then
                    .in_fence = (.in_fence | not)
                elif (.in_fence | not)
                    and ($line | test("^#+[[:space:]]")) then
                    .section = ($line
                        | sub("^#+[[:space:]]+"; "")
                        | clean_source)
                else
                    .
                end
            )
            | .section;
        def exact_source_bounds($lines):
            . as $record
            | $record.extra.source_line_start as $start
            | $record.extra.source_line_end as $finish
            | section_at($lines; $start) as $section
            | ((if $record.source_id == "docs/DYNAMIC_MEMORY_ARCHITECTURE.md"
                then "Draft target architecture; not implemented. "
                else ""
                end)
                + "Source document " + $record.source_id
                + "; section " + $section + ". ") as $prefix
            | ($record.text | startswith($prefix)) as $prefix_matches
            | $record.text[($prefix | length):] as $body
            | normalized_slice($lines; $start; $finish) as $slice
            | $prefix_matches
            and $finish <= ($lines | length)
            and ($body | length) > 0
            and ($slice | contains($body))
            and ($start == $finish
                or (normalized_slice($lines; $start + 1; $finish)
                    | contains($body) | not))
            and ($start == $finish
                or (normalized_slice($lines; $start; $finish - 1)
                    | contains($body) | not));

        ($source_text | split("\n")) as $source_lines
        | [.[] | select(
            .source_config_id == "rich-demo:docs:v1"
            and .source_id == $source_id
        ) | exact_source_bounds($source_lines)]
        | length > 0 and all
    ' "$input" >/dev/null; then
        fail "documentation source coordinates do not exactly bound $relative_path"
    fi
done < "$manifest"

# Repository-code/configuration records use the same minimal-bound guarantee as
# documents. Their normalized body must come from the linked source slice, and
# the path-derived semantic metadata must exactly match the checked-in manifest.
while IFS='|' read -r relative_path source_area language; do
    case $relative_path in
        ''|'#'*) continue ;;
    esac
    case $relative_path in
        /*|*'..'*) fail "unsafe repository path in manifest: $relative_path" ;;
    esac
    for facet_value in "$source_area" "$language"; do
        case $facet_value in
            ''|*[!a-z0-9_]*) fail "invalid repository facet for $relative_path" ;;
        esac
    done

    source_file=$repo_root/$relative_path
    if [ ! -f "$source_file" ] || [ -L "$source_file" ]; then
        fail "repository manifest entry must be a regular, non-symlink file: $relative_path"
    fi
    if ! jq -s -e \
        --arg source_id "$relative_path" \
        --arg source_area "$source_area" \
        --arg language "$language" \
        --rawfile source_text "$source_file" '
        def clean_source:
            gsub("\r"; "")
            | gsub("\t"; " ")
            | gsub("[[:space:]]+"; " ")
            | sub("^ "; "")
            | sub(" $"; "");
        def normalized_slice($lines; $start; $finish):
            $lines[($start - 1):$finish] | join(" ") | clean_source;
        def exact_source_bounds($lines):
            . as $record
            | $record.extra.source_line_start as $start
            | $record.extra.source_line_end as $finish
            | ("Repository source " + $record.source_id
                + "; area " + $source_area
                + "; language " + $language + ". ") as $prefix
            | ($record.text | startswith($prefix)) as $prefix_matches
            | $record.text[($prefix | length):] as $body
            | normalized_slice($lines; $start; $finish) as $slice
            | $prefix_matches
            and $finish <= ($lines | length)
            and ($body | length) > 0
            and ($slice | contains($body))
            and ($start == $finish
                or (normalized_slice($lines; $start + 1; $finish)
                    | contains($body) | not))
            and ($start == $finish
                or (normalized_slice($lines; $start; $finish - 1)
                    | contains($body) | not));

        ($source_text | split("\n")) as $source_lines
        | [.[] | select(
            .source_config_id == "rich-demo:repository:v1"
            and .source_id == $source_id
        )]
        | length > 0
        and all(.[];
            .facets.source_area == [$source_area]
            and .facets.tags == ["repository", $language, $source_area]
            and exact_source_bounds($source_lines))
    ' "$input" >/dev/null; then
        fail "repository source coordinates or metadata do not exactly bound $relative_path"
    fi
done < "$repository_manifest"

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

sensitive_projection() {
    jq -c '
        def scrub_public_postgres_fixtures:
            [
                ("postgresql://" + "writer:secret@" + "db.example:26257/fleet_recall?sslmode=verify-full"),
                ("postgresql://" + "writer:secret@" + "127.0.0.1:26257/fleet_recall?sslmode=disable"),
                ("postgresql://" + "writer:secret@" + "%2Fvar%2Frun%2Fpostgres:26257/fleet_recall?sslmode=verify-full"),
                ("postgresql://" + "writer:secret@" + "db.example:26257/fleet_recall?sslmode=verify-full&options=-csearch_path%3Dattacker"),
                ("postgresql://" + "writer:secret@" + "db.example/fleet_recall?sslmode=verify-full"),
                ("postgresql://" + "writer:secret@" + "db.example:0/fleet_recall?sslmode=verify-full"),
                ("postgresql://" + "writer:secret@" + "db.example:26257/?sslmode=verify-full"),
                ("postgresql://" + "fleet_publication:secret@" + "db.example:26257/fleet_recall?sslmode=verify-full"),
                ("postgresql://" + "%66leet_publication:secret@" + "db.example:26257/fleet_recall?sslmode=verify-full"),
                ("postgresql://" + "fleet_publication:do-not-print@" + "db.example:26257/other?sslmode=verify-full"),
                ("postgresql://" + "writer_identity_42:wrong-user-secret-42@" + "db.example:26257/fleet_recall?sslmode=verify-full"),
                ("postgresql://" + "%66leet_writer_43:encoded-wrong-secret-43@" + "db.example:26257/fleet_recall?sslmode=verify-full"),
                ("postgresql://" + "fleet_writer:secret@" + "db.example:26257/fleet_recall?sslmode=verify-full"),
                ("postgresql://" + "fleet_migrator:secret@" + "db.example:26257/fleet_recall?sslmode=verify-full"),
                ("postgresql://" + "%66leet_migrator:secret@" + "db.example:26257/fleet_recall?sslmode=verify-full"),
                ("postgresql://" + "fleet_writer:runtime-secret-42@" + "db.example:26257/other?sslmode=verify-full"),
                ("postgresql://" + "fleet_writer:socket-secret-42@" + "%2Fvar%2Frun%2Fpostgres:26257/fleet_recall?sslmode=verify-full"),
                ("postgresql://" + "fleet_migrator:options-secret-43@" + "db.example:26257/fleet_recall?sslmode=verify-full&options=-csearch_path%3Dattacker")
            ] as $fixtures
            | reduce $fixtures[] as $fixture (
                .;
                split($fixture) | join("postgresql://public-test-fixture")
            );
        def scrub_public_successor_postgres_fixture:
            split(
                "postgresql://" + "successor:explicit-secret@"
                + "cluster.example:26257/fleet_recall?sslmode=verify-full"
            )
            | join("postgresql://public-test-fixture");
        def scrub_public_reconciliation_postgres_fixture:
            split(
                "postgresql://" + "reconciler:explicit-secret@"
                + "cluster.example:26257/fleet_recall?sslmode=verify-full"
            )
            | join("postgresql://public-test-fixture");

        if .source_config_id == "rich-demo:repository:v1"
            and .source_id == "src/private_postgres.rs"
        then .text |= scrub_public_postgres_fixtures
        elif .source_config_id == "rich-demo:repository:v1"
            and .source_id == "src/bin/ostk-registry-successor-activate.rs"
        then .text |= scrub_public_successor_postgres_fixture
        elif .source_config_id == "rich-demo:repository:v1"
            and .source_id == "src/bin/ostk-conflict-reconcile.rs"
        then .text |= scrub_public_reconciliation_postgres_fixture
        else .
        end
    ' "$input"
}

sensitive_pattern='(AKIA|ASIA)[A-Z0-9]{16}|-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|postgres(ql)?://[^[:space:]/:@]+:[^[:space:]@]+@|(sk|rk)-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{20,}|eyJ[A-Za-z0-9_-]{10,}[.]eyJ[A-Za-z0-9_-]{10,}|[Aa]uthorization:[[:space:]]*[Bb]earer[[:space:]]+[A-Za-z0-9._~-]{16,}|arn:aws:[^:[:space:]]*:[^:[:space:]]*:[0-9]{12}:'
if sensitive_projection | grep -Eiq "$sensitive_pattern"; then
    fail "input contains a credential, private-key, account-ARN, or token-like pattern"
fi
if sensitive_projection | jq -r '.. | strings' | grep -Eiq "$sensitive_pattern"; then
    fail "input contains an encoded credential, account-ARN, or token-like string"
fi

jq -s -r '
    ([.[] | select(.source_config_id == "rich-demo:docs:v1")] | length) as $docs
    | ([.[] | select(.source_config_id == "rich-demo:self-audit:v1")] | length) as $audit
    | ([.[] | select(.source_config_id == "rich-demo:repository:v1")] | length) as $repository
    | ([.[] | select(.source_config_id == "rich-demo:operations:v1")] | length) as $operations
    | "verified rich demo: \(length) chunks (\($docs) documentation, \($audit) self-audit source, \($repository) repository source, \($operations) operations)"
' "$input"
