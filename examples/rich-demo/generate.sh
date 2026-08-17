#!/bin/sh
set -eu

export LC_ALL=C
export TZ=UTC

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$script_dir/../.." && pwd)
manifest=$script_dir/documents.txt
repository_manifest=$script_dir/repository-files.txt
zero_revision=0000000000000000000000000000000000000000
source_revision=${RICH_DEMO_SOURCE_REVISION:-$zero_revision}

if [ "$#" -ne 0 ]; then
    printf 'usage: %s > rich-demo.ndjson\n' "$0" >&2
    exit 64
fi

for command_name in awk jq; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        printf 'required command not found: %s\n' "$command_name" >&2
        exit 69
    fi
done

case $source_revision in
    *[!0-9a-f]*|'')
        printf 'RICH_DEMO_SOURCE_REVISION must be exactly 40 lowercase hexadecimal characters\n' >&2
        exit 65
        ;;
esac
if [ "${#source_revision}" -ne 40 ]; then
    printf 'RICH_DEMO_SOURCE_REVISION must be exactly 40 lowercase hexadecimal characters\n' >&2
    exit 65
fi

if [ ! -f "$manifest" ] || [ -L "$manifest" ]; then
    printf 'document manifest must be a regular, non-symlink file: %s\n' "$manifest" >&2
    exit 66
fi

if [ ! -f "$repository_manifest" ] || [ -L "$repository_manifest" ]; then
    printf 'repository manifest must be a regular, non-symlink file: %s\n' "$repository_manifest" >&2
    exit 66
fi

emit_document_chunks() {
    while IFS='|' read -r relative_path source_area; do
        case $relative_path in
            ''|'#'*) continue ;;
        esac
        case $relative_path in
            /*|*'..'*)
                printf 'unsafe document path in manifest: %s\n' "$relative_path" >&2
                exit 65
                ;;
        esac
        case $source_area in
            ''|*[!a-z0-9_]*)
                printf 'invalid source area in manifest: %s\n' "$source_area" >&2
                exit 65
                ;;
        esac

        document=$repo_root/$relative_path
        if [ ! -f "$document" ] || [ -L "$document" ]; then
            printf 'manifest entry must be a regular, non-symlink file: %s\n' "$relative_path" >&2
            exit 66
        fi

        document_status=
        status_prefix=
        if [ "$relative_path" = "docs/DYNAMIC_MEMORY_ARCHITECTURE.md" ]; then
            document_status=partial_target
            status_prefix='Target architecture; stages 1-3 frozen; stage 4 partially implemented; stages 5-10 contract vectors in progress. '
        fi

        awk -v source_path="$relative_path" -v status_prefix="$status_prefix" -v max_chars=1500 '
            function clean(value) {
                gsub(/\r/, "", value)
                gsub(/\t/, " ", value)
                gsub(/[[:space:]]+/, " ", value)
                sub(/^ /, "", value)
                sub(/ $/, "", value)
                return value
            }

            function track_line(value, source_line, count, words, i) {
                value = clean(value)
                if (value == "") {
                    return
                }
                count = split(value, words, " ")
                for (i = 1; i <= count; i++) {
                    if (paragraph_lines == "") {
                        paragraph_lines = source_line
                    } else {
                        paragraph_lines = paragraph_lines " " source_line
                    }
                }
            }

            function emit_paragraph(value, coordinates, count, coordinate_count, words, word_lines, prefix, start, end, i, remaining, current) {
                value = clean(value)
                coordinates = clean(coordinates)
                if (value == "") {
                    return
                }

                prefix = status_prefix "Source document " source_path
                if (section != "") {
                    prefix = prefix "; section " section
                }
                prefix = prefix ". "
                count = split(value, words, " ")
                coordinate_count = split(coordinates, word_lines, " ")
                if (coordinate_count != count) {
                    exit 2
                }

                start = 1
                while (start <= count) {
                    current = prefix
                    end = start - 1
                    while (end < count && length(current) + length(words[end + 1]) + 1 <= max_chars) {
                        end++
                        if (current == prefix) {
                            current = current words[end]
                        } else {
                            current = current " " words[end]
                        }
                    }

                    if (end < start) {
                        end = start
                        current = prefix words[start]
                    }

                    if (end < count) {
                        remaining = length(prefix)
                        for (i = end + 1; i <= count; i++) {
                            remaining += length(words[i]) + 1
                        }
                        while (remaining < 240 && end > start) {
                            remaining += length(words[end]) + 1
                            end--
                        }
                        current = prefix words[start]
                        for (i = start + 1; i <= end; i++) {
                            current = current " " words[i]
                        }
                    }

                    print chunk_index "\t" word_lines[start] "\t" word_lines[end] "\t" current
                    chunk_index++
                    start = end + 1
                }
            }

            function flush() {
                paragraph = clean(paragraph)
                if (paragraph == "") {
                    return
                }
                if (length(paragraph) < 120) {
                    if (pending == "") {
                        pending = paragraph
                        pending_lines = paragraph_lines
                    } else {
                        pending = pending " " paragraph
                        pending_lines = pending_lines " " paragraph_lines
                    }
                } else {
                    if (pending != "") {
                        paragraph = pending " " paragraph
                        paragraph_lines = pending_lines " " paragraph_lines
                        pending = ""
                        pending_lines = ""
                    }
                    emit_paragraph(paragraph, paragraph_lines)
                }
                paragraph = ""
                paragraph_lines = ""
            }

            function flush_pending() {
                if (pending != "") {
                    emit_paragraph(pending, pending_lines)
                    pending = ""
                    pending_lines = ""
                }
            }

            BEGIN {
                chunk_index = 0
                paragraph = ""
                paragraph_lines = ""
                pending = ""
                pending_lines = ""
                section = "Overview"
                in_fence = 0
            }

            {
                line = $0
                sub(/\r$/, "", line)
                if (line ~ /^[[:space:]]*```/ || line ~ /^[[:space:]]*~~~/) {
                    track_line(line, NR)
                    if (paragraph == "") {
                        paragraph = line
                    } else {
                        paragraph = paragraph " " line
                    }
                    in_fence = !in_fence
                    next
                }
                if (!in_fence && line ~ /^#+[[:space:]]/) {
                    flush()
                    flush_pending()
                    section = line
                    sub(/^#+[[:space:]]+/, "", section)
                    section = clean(section)
                    next
                }
                if (line ~ /^[[:space:]]*$/) {
                    flush()
                    next
                }
                gsub(/\t/, " ", line)
                track_line(line, NR)
                if (paragraph == "") {
                    paragraph = line
                } else {
                    paragraph = paragraph " " line
                }
            }

            END {
                flush()
                flush_pending()
            }
        ' "$document" |
            jq -Rc \
                --arg source_id "$relative_path" \
                --arg source_area "$source_area" \
                --arg document_status "$document_status" \
                --arg source_revision "$source_revision" '
                    split("\t") as $fields
                    | {
                        source: "markdown",
                        source_id: $source_id,
                        source_config_id: "rich-demo:docs:v1",
                        chunk_index: ($fields[0] | tonumber),
                        text: ($fields[3:] | join("\t")),
                        role: "usage",
                        extra: {
                            source_revision: $source_revision,
                            source_line_start: ($fields[1] | tonumber),
                            source_line_end: ($fields[2] | tonumber)
                        },
                        facets: {
                            dataset: ["rich-demo"],
                            record_kind: ["documentation"],
                            source_area: [$source_area],
                            tags: ["documentation", $source_area]
                        }
                    }
                    | if $document_status == "" then . else
                        .facets.document_status = [$document_status]
                        | .facets.tags += [$document_status]
                      end
                '
    done < "$manifest"
}

emit_repository_chunks() {
    while IFS='|' read -r relative_path source_area language; do
        case $relative_path in
            ''|'#'*) continue ;;
        esac
        case $relative_path in
            /*|*'..'*)
                printf 'unsafe repository path in manifest: %s\n' "$relative_path" >&2
                exit 65
                ;;
        esac
        for facet_value in "$source_area" "$language"; do
            case $facet_value in
                ''|*[!a-z0-9_]*)
                    printf 'invalid repository facet in manifest for %s: %s\n' \
                        "$relative_path" "$facet_value" >&2
                    exit 65
                    ;;
            esac
        done

        source_file=$repo_root/$relative_path
        if [ ! -f "$source_file" ] || [ -L "$source_file" ]; then
            printf 'repository manifest entry must be a regular, non-symlink file: %s\n' \
                "$relative_path" >&2
            exit 66
        fi

        awk \
            -v source_path="$relative_path" \
            -v source_area="$source_area" \
            -v language="$language" \
            -v max_chars=1500 '
            function clean(value) {
                gsub(/\r/, "", value)
                gsub(/\t/, " ", value)
                gsub(/[[:space:]]+/, " ", value)
                sub(/^ /, "", value)
                sub(/ $/, "", value)
                return value
            }

            function track_line(value, source_line, count, words, i) {
                value = clean(value)
                if (value == "") {
                    return
                }
                count = split(value, words, " ")
                for (i = 1; i <= count; i++) {
                    if (block_lines == "") {
                        block_lines = source_line
                    } else {
                        block_lines = block_lines " " source_line
                    }
                }
            }

            function emit_block(value, coordinates, count, coordinate_count, words, word_lines, prefix, start, end, i, remaining, current, max_body, token, token_offset, token_end) {
                value = clean(value)
                coordinates = clean(coordinates)
                if (value == "") {
                    return
                }

                prefix = "Repository source " source_path "; area " source_area "; language " language ". "
                count = split(value, words, " ")
                coordinate_count = split(coordinates, word_lines, " ")
                if (coordinate_count != count) {
                    exit 2
                }

                start = 1
                while (start <= count) {
                    current = prefix
                    end = start - 1
                    while (end < count && length(current) + length(words[end + 1]) + 1 <= max_chars) {
                        end++
                        if (current == prefix) {
                            current = current words[end]
                        } else {
                            current = current " " words[end]
                        }
                    }

                    if (end < start) {
                        # A canonical JSON record can be one whitespace-free
                        # token larger than a normal chunk. Split only this
                        # fallback case, preserving the same physical source
                        # line for every fragment. LC_ALL=C makes offsets byte
                        # based; retreat from a UTF-8 continuation byte so a
                        # fragment never cuts a code point.
                        max_body = max_chars - length(prefix)
                        if (max_body < 4) {
                            exit 3
                        }
                        token = words[start]
                        token_offset = 1
                        while (token_offset <= length(token)) {
                            token_end = token_offset + max_body - 1
                            if (token_end > length(token)) {
                                token_end = length(token)
                            } else {
                                while (token_end >= token_offset &&
                                        substr(token, token_end + 1, 1) ~ /^[\200-\277]$/) {
                                    token_end--
                                }
                            }
                            if (token_end < token_offset) {
                                exit 3
                            }
                            current = prefix substr(token, token_offset, token_end - token_offset + 1)
                            print chunk_index "\t" word_lines[start] "\t" word_lines[start] "\t" current
                            chunk_index++
                            token_offset = token_end + 1
                        }
                        start++
                        continue
                    }

                    if (end < count) {
                        remaining = length(prefix)
                        for (i = end + 1; i <= count; i++) {
                            remaining += length(words[i]) + 1
                        }
                        while (remaining < 240 && end > start) {
                            remaining += length(words[end]) + 1
                            end--
                        }
                        current = prefix words[start]
                        for (i = start + 1; i <= end; i++) {
                            current = current " " words[i]
                        }
                    }

                    print chunk_index "\t" word_lines[start] "\t" word_lines[end] "\t" current
                    chunk_index++
                    start = end + 1
                }
            }

            function flush() {
                block = clean(block)
                if (block == "") {
                    return
                }
                if (length(block) < 480) {
                    if (pending == "") {
                        pending = block
                        pending_lines = block_lines
                    } else {
                        pending = pending " " block
                        pending_lines = pending_lines " " block_lines
                    }
                    if (length(pending) >= 900) {
                        emit_block(pending, pending_lines)
                        pending = ""
                        pending_lines = ""
                    }
                } else {
                    if (pending != "") {
                        block = pending " " block
                        block_lines = pending_lines " " block_lines
                        pending = ""
                        pending_lines = ""
                    }
                    emit_block(block, block_lines)
                }
                block = ""
                block_lines = ""
            }

            BEGIN {
                chunk_index = 0
                block = ""
                block_lines = ""
                pending = ""
                pending_lines = ""
            }

            {
                line = $0
                sub(/\r$/, "", line)
                if (line ~ /^[[:space:]]*$/) {
                    flush()
                    next
                }
                gsub(/\t/, " ", line)
                track_line(line, NR)
                if (block == "") {
                    block = line
                } else {
                    block = block " " line
                }
            }

            END {
                flush()
                if (pending != "") {
                    emit_block(pending, pending_lines)
                }
            }
        ' "$source_file" |
            jq -Rc \
                --arg source_id "$relative_path" \
                --arg source_area "$source_area" \
                --arg language "$language" \
                --arg source_revision "$source_revision" '
                    split("\t") as $fields
                    | {
                        source: "code",
                        source_id: $source_id,
                        source_config_id: "rich-demo:repository:v1",
                        chunk_index: ($fields[0] | tonumber),
                        text: ($fields[3:] | join("\t")),
                        role: "usage",
                        extra: {
                            source_revision: $source_revision,
                            source_line_start: ($fields[1] | tonumber),
                            source_line_end: ($fields[2] | tonumber)
                        },
                        facets: {
                            dataset: ["rich-demo"],
                            record_kind: ["source_code"],
                            source_area: [$source_area],
                            tags: ["repository", $language, $source_area]
                        }
                    }
                '
    done < "$repository_manifest"
}

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

emit_self_audit_sources() {
    tools_path=src/mcp/tools.rs
    application_path=src/application.rs
    tools_file=$repo_root/$tools_path
    application_file=$repo_root/$application_path

    for source_file in "$tools_file" "$application_file"; do
        if [ ! -f "$source_file" ] || [ -L "$source_file" ]; then
            printf 'self-audit source must be a regular, non-symlink file: %s\n' "$source_file" >&2
            exit 66
        fi
    done

    if ! tools_excerpt=$(extract_tools_excerpt "$tools_file"); then
        printf 'src/mcp/tools.rs must contain exactly one expected remember action marker\n' >&2
        exit 65
    fi
    if ! application_excerpt=$(extract_application_excerpt "$application_file"); then
        printf 'src/application.rs must contain exactly one adjacent remember dispatch and rejection marker pair\n' >&2
        exit 65
    fi
    if ! tools_coordinates=$(extract_tools_coordinates "$tools_file"); then
        printf 'could not locate exact src/mcp/tools.rs source coordinates\n' >&2
        exit 65
    fi
    if ! application_coordinates=$(extract_application_coordinates "$application_file"); then
        printf 'could not locate exact src/application.rs source coordinates\n' >&2
        exit 65
    fi
    tools_line_start=${tools_coordinates%% *}
    tools_line_end=${tools_coordinates#* }
    application_line_start=${application_coordinates%% *}
    application_line_end=${application_coordinates#* }

    jq -cn \
        --arg source_id "$tools_path" \
        --arg text "$tools_excerpt" \
        --arg source_revision "$source_revision" \
        --argjson source_line_start "$tools_line_start" \
        --argjson source_line_end "$tools_line_end" '
            {
                source: "code",
                source_id: $source_id,
                source_config_id: "rich-demo:self-audit:v1",
                chunk_index: 0,
                text: $text,
                role: "usage",
                extra: {
                    source_revision: $source_revision,
                    source_line_start: $source_line_start,
                    source_line_end: $source_line_end
                },
                facets: {
                    dataset: ["rich-demo"],
                    record_kind: ["source_code"],
                    source_area: ["source_code"],
                    tags: ["self_audit", "rust", "mcp_contract"]
                }
            }
        '
    jq -cn \
        --arg source_id "$application_path" \
        --arg text "$application_excerpt" \
        --arg source_revision "$source_revision" \
        --argjson source_line_start "$application_line_start" \
        --argjson source_line_end "$application_line_end" '
            {
                source: "code",
                source_id: $source_id,
                source_config_id: "rich-demo:self-audit:v1",
                chunk_index: 0,
                text: $text,
                role: "usage",
                extra: {
                    source_revision: $source_revision,
                    source_line_start: $source_line_start,
                    source_line_end: $source_line_end
                },
                facets: {
                    dataset: ["rich-demo"],
                    record_kind: ["source_code"],
                    source_area: ["source_code"],
                    tags: ["self_audit", "rust", "service_dispatch"]
                }
            }
        '
}

emit_operations_narrative() {
    jq -cn '
        def week_id($week):
            "week-" + (if $week < 10 then "0" else "" end) + ($week | tostring);

        def record($week; $slug; $event_type; $status; $role; $scenario; $text; $tags):
            {
                source: "markdown",
                source_id: ("rich-demo/operations/" + week_id($week) + "/" + $slug),
                source_config_id: "rich-demo:operations:v1",
                chunk_index: 0,
                text: ("Synthetic fleet operations narrative, " + week_id($week) + ". " + $text),
                role: $role,
                facets: {
                    dataset: ["rich-demo"],
                    record_kind: ["operations_narrative"],
                    source_area: ["fleet_operations"],
                    event_type: [$event_type],
                    week: [week_id($week)],
                    scenario: [$scenario],
                    status: [$status],
                    tags: $tags
                }
            };

        (
        [
            "catalog-api", "checkout-worker", "identity-gateway", "search-indexer",
            "billing-ledger", "notification-router", "inventory-sync", "audit-exporter",
            "recommendation-api", "workflow-scheduler", "support-console", "metrics-pipeline"
        ] as $services
        | [
            "us-east", "us-west", "eu-central", "ap-southeast"
        ] as $regions
        | [
            {topic:"migration ownership", choice:"one dedicated migrator runs before workers", alternative:"each worker attempts migration at startup", reason:"separating DDL from serving traffic makes rollout order observable"},
            {topic:"canary allocation", choice:"start at five percent and hold for two health windows", alternative:"start at twenty-five percent for faster signal", reason:"a smaller first step limits exposure while preserving useful telemetry"},
            {topic:"cache policy", choice:"enable bounded caching only for immutable catalog reads", alternative:"disable all caching during the release", reason:"selective caching protects freshness-sensitive paths"},
            {topic:"rollback trigger", choice:"rollback on sustained error-rate breach", alternative:"rollback on a single latency spike", reason:"a sustained window rejects transient noise"},
            {topic:"schema compatibility gate", choice:"require dual-read compatibility before cutover", alternative:"drain all workers before applying schema", reason:"dual-read support permits replacement without a global pause"},
            {topic:"regional rollout order", choice:"begin in us-east and follow measured demand", alternative:"begin in us-west where traffic is lower", reason:"starting near the operations team shortens response time"},
            {topic:"queue scheduling", choice:"retain FIFO within each tenant partition", alternative:"use global priority scheduling", reason:"partition-local order prevents one tenant from starving another"},
            {topic:"diagnostic retention", choice:"retain redacted diagnostics for seven days", alternative:"retain full diagnostics for thirty days", reason:"short redacted retention minimizes exposure"},
            {topic:"feature activation", choice:"require an operator-approved feature flag", alternative:"enable automatically after deploy", reason:"approval keeps activation separate from artifact delivery"},
            {topic:"failover authority", choice:"require operator confirmation for cross-region failover", alternative:"fail over automatically on one failed probe", reason:"multiple signals avoid a split-brain response"},
            {topic:"model bundle selection", choice:"use the reviewed content-addressed bundle", alternative:"download the newest compatible model at startup", reason:"an immutable digest makes every task reproducible"},
            {topic:"backfill pacing", choice:"cap backfill at one quarter of spare capacity", alternative:"consume all spare capacity until complete", reason:"a fixed reserve protects interactive traffic"}
        ] as $decisions
        | range(1; 13) as $week
        | ($services[($week - 1) % ($services | length)]) as $service
        | ($services[$week % ($services | length)]) as $peer
        | ($regions[($week - 1) % ($regions | length)]) as $region
        | ($decisions[($week - 1) % ($decisions | length)]) as $decision
        | (
          record($week; "decision-primary"; "decision"; "accepted"; "primary"; $decision.topic;
            "The release coordinator decided that " + $service + " will " + $decision.choice + ". The recorded rationale is that " + $decision.reason + ". The decision is intended to guide the next independently started worker.";
            ["decision", "rollout", $service]),
          record($week; "decision-contingency"; "decision"; "contingency"; "primary"; $decision.topic;
            "The reliability agent documented a contingency for " + $decision.topic + ": " + $decision.alternative + ". It is not the active choice and requires fresh operator approval before use; preserving it makes later disagreement explainable.";
            ["decision", "contingency", $service]),
          record($week; "evidence-review"; "evidence"; "observed"; "usage"; "health evidence";
            "Agents reviewed error rate, saturation, queue age, and restart continuity for " + $service + " in " + $region + ". The evidence window contained two clean replacement cycles and no loss of durable rollout context.";
            ["evidence", "health", $region]),
          record($week; "change-window"; "change"; "completed"; "usage"; "bounded rollout";
            "The deployment agent applied the approved bounded change to " + $service + " while " + $peer + " remained available. Progress advanced only after health, memory recall, and dependency checks agreed.";
            ["change", "deployment", $service]),
          record($week; "verification"; "verification"; "passed"; "usage"; "post-change verification";
            "The verification agent recalled the current decision, checked its cited evidence, and confirmed that a replacement task for " + $service + " returned the same operational context. It recorded the verification result without changing the decision.";
            ["verification", "durability", $service]),
          record($week; "incident"; "incident"; "contained"; "usage"; "degraded dependency";
            "A synthetic dependency slowdown increased queue age for " + $peer + " in " + $region + ". The incident agent bounded concurrency, preserved incoming work, and attached measurements instead of inferring a root cause.";
            ["incident", "queue", $peer]),
          record($week; "mitigation"; "mitigation"; "completed"; "usage"; "degraded dependency";
            "The fleet reduced nonessential work for " + $peer + ", verified recovery over three windows, and left the durable decision untouched. The mitigation was reversible and cited the incident evidence that triggered it.";
            ["mitigation", "recovery", $peer]),
          record($week; "handoff"; "handoff"; "accepted"; "usage"; "operator handoff";
            "The outgoing agent handed " + $service + " to the next shift with the active choice, contingency, observed risks, and exact follow-up checks. The receiving agent acknowledged the handoff before taking action.";
            ["handoff", "operations", $service]),
          record($week; "capacity"; "capacity_review"; "observed"; "usage"; "capacity reserve";
            "Capacity review found enough reserve in " + $region + " for one overlapping task replacement and a bounded backfill. The plan kept an explicit reserve for interactive requests and database retries.";
            ["capacity", "resilience", $region]),
          record($week; "security"; "security_review"; "passed"; "usage"; "least privilege";
            "The security agent confirmed that serving tasks for " + $service + " retained read and runtime-write privileges only, while schema changes remained isolated to the dedicated migration identity. No credential values entered the narrative.";
            ["security", "least_privilege", $service]),
          record($week; "retrospective"; "retrospective"; "completed"; "usage"; "learning loop";
            "The weekly retrospective separated observed facts from operator choices for " + $service + ". It preserved superseded context for auditability and promoted only reproducible checks into the next runbook revision.";
            ["retrospective", "learning", $service]),
          record($week; "next-week-plan"; "plan"; "proposed"; "usage"; "next iteration";
            "The next iteration will rehearse a task replacement for " + $peer + ", compare lexical and semantic recall, and require operator review for any incompatible same-key proposals before rollout continues.";
            ["plan", "recall", $peer]),
          record($week; "dependency-contract"; "dependency_review"; "confirmed"; "usage"; "dependency contract";
            "The dependency review confirmed timeout, retry, and ownership expectations between " + $service + " and " + $peer + ". Operators recorded the contract separately from observed health so a later replacement can distinguish policy from evidence.";
            ["dependency", "contract", $service, $peer]),
          record($week; "replacement-rehearsal"; "resilience_drill"; "passed"; "usage"; "task replacement";
            "A replacement rehearsal stopped one synthetic " + $service + " task in " + $region + " and started a clean successor. The successor recalled the current decision and cited the same evidence before the old task was considered drained.";
            ["resilience", "replacement", $service]),
          record($week; "runbook-review"; "runbook_review"; "approved"; "usage"; "operational procedure";
            "Operators reviewed the " + $decision.topic + " procedure after the weekly evidence window. They kept the active choice explicit, marked the contingency as noncurrent, and assigned one owner for the next verification.";
            ["runbook", "review", $service])
          )
        ),

        (
        [
            "catalog-api", "checkout-worker", "identity-gateway", "search-indexer",
            "billing-ledger", "notification-router", "inventory-sync", "audit-exporter",
            "recommendation-api", "workflow-scheduler", "support-console", "metrics-pipeline"
        ] as $services
        | [
            "migration ownership", "canary allocation", "cache policy", "rollback trigger",
            "schema compatibility gate", "regional rollout order", "queue scheduling",
            "diagnostic retention", "feature activation", "failover authority",
            "model bundle selection", "backfill pacing"
        ] as $topics
        | [
            {old:"one dedicated migrator runs before workers", new:"run one lease-elected migrator with a pre-authorized standby", reason:"lease ownership preserves one writer while adding a tested failover path"},
            {old:"start at five percent and hold for two health windows", new:"start at ten percent and hold for three health windows", reason:"the longer observation window offsets the moderately larger first step"},
            {old:"enable bounded caching only for immutable catalog reads", new:"bypass caching until invalidation lag stays below target", reason:"freshness telemetry no longer supports the earlier selective-cache assumption"},
            {old:"rollback on sustained error-rate breach", new:"require a sustained error-rate breach plus saturation evidence", reason:"the added signal separates application faults from dependency pressure"},
            {old:"require dual-read compatibility before cutover", new:"use expand-contract with an explicit version gate", reason:"the version gate made compatibility measurable across two release trains"},
            {old:"begin in us-east and follow measured demand", new:"begin in us-west under the staffed response team", reason:"on-call coverage moved before the new change window"},
            {old:"retain FIFO within each tenant partition", new:"use weighted tenant queues while preserving per-tenant order", reason:"measured starvation required bounded cross-tenant weighting"},
            {old:"retain redacted diagnostics for seven days", new:"retain redacted diagnostics for three days", reason:"the shorter window still covers the incident review cycle"},
            {old:"require an operator-approved feature flag", new:"require approval from both the operator and service owner", reason:"the feature now crosses a service ownership boundary"},
            {old:"require operator confirmation for cross-region failover", new:"permit automatic failover after three independent health signals", reason:"the rehearsed signal quorum met the documented safety threshold"},
            {old:"use the reviewed content-addressed bundle", new:"promote the newly reviewed content-addressed bundle", reason:"the replacement digest passed reproducibility and rollback checks"}
        ] as $changes
        | range(2; 13) as $week
        | ($services[($week - 2) % ($services | length)]) as $service
        | ($topics[($week - 2) % ($topics | length)]) as $topic
        | ($changes[($week - 2) % ($changes | length)]) as $change
        | record($week; "supersession"; "supersession"; "superseding"; "evolution"; $topic;
            "For " + $topic + " on " + $service + ", the fleet superseded the prior-week instruction: " + $change.old + ". The replacement instruction is to " + $change.new + " because " + $change.reason + ". The old decision remains historical and discoverable.";
            ["supersession", "decision_history", $service])
        ),

        record(6; "telemetry-assertion-latency"; "telemetry_assertion"; "provisional"; "evolution"; "checkout latency attribution";
            "The observability agent provisionally attributed elevated checkout latency to database saturation after comparing host clocks and queue samples. The assertion is preserved as a specific evidence claim so any later correction can identify exactly what changed.";
            ["telemetry_assertion", "latency", "checkout-worker"]),

        record(7; "retraction-invalid-latency-assertion"; "retraction"; "retracted"; "evolution"; "checkout latency attribution";
            "The observability agent retracts its week-06 assertion that checkout latency came from database saturation. A clock-skew defect invalidated that measurement, so the assertion must not guide action. This synthetic narrative contains exactly one retraction, and the correction preserves why the earlier statement was withdrawn.";
            ["retraction", "correction", "telemetry"]),

        (
        [
            {name:"migration_owner", left_actor:"release agent", left:"one dedicated migrator runs before workers", right_actor:"worker agent", right:"every worker migrates independently at startup", impact:"both instructions would contend for schema ownership"},
            {name:"canary_percentage", left_actor:"safety agent", left:"begin at five percent", right_actor:"delivery agent", right:"begin at twenty-five percent", impact:"one rollout cannot begin at both allocations"},
            {name:"maintenance_window", left_actor:"regional agent", left:"Tuesday at 02:00 UTC", right_actor:"dependency agent", right:"Thursday at 04:00 UTC", impact:"the dependency freeze permits only one window"},
            {name:"cache_policy", left_actor:"performance agent", left:"enable immutable-read caching", right_actor:"freshness agent", right:"disable all caching", impact:"the same route cannot be both cached and uncached"},
            {name:"rollback_trigger", left_actor:"reliability agent", left:"use sustained error rate", right_actor:"latency agent", right:"use one latency spike", impact:"the triggers produce incompatible rollback behavior"},
            {name:"schema_gate", left_actor:"database agent", left:"require dual-read compatibility", right_actor:"operations agent", right:"drain every worker before schema change", impact:"the rollout order and availability guarantees differ"},
            {name:"region_priority", left_actor:"traffic agent", left:"start in us-east", right_actor:"risk agent", right:"start in us-west", impact:"the first deployment region must be singular"},
            {name:"queue_mode", left_actor:"fairness agent", left:"use tenant-partitioned FIFO", right_actor:"priority agent", right:"use one global priority queue", impact:"the schedulers impose different ordering"}
        ] as $conflicts
        | [
            "compare migration logs and preserve the dedicated owner",
            "review exposure limits and select the smaller canary",
            "consult the dependency calendar and publish one window"
        ] as $resolutions
        | range(0; $conflicts | length) as $index
        | ($index + 1) as $week
        | ($conflicts[$index]) as $conflict
        | (
          record($week; "conflict-" + $conflict.name; "conflict_scenario"; "open"; "evolution"; $conflict.name;
            "Synthetic disagreement: the " + $conflict.left_actor + " proposed " + $conflict.left + ", while the " + $conflict.right_actor + " proposed " + $conflict.right + ". The proposals require operator review because " + $conflict.impact + ". Importing this narrative does not create typed claims or conflict state.";
            ["conflict_scenario", "operator_review", $conflict.name]),
          (if $index < ($resolutions | length) then
            record($week; "conflict-resolution-" + $conflict.name; "conflict_resolution"; "resolved"; "evolution"; $conflict.name;
              "Synthetic resolution: operators chose to " + $resolutions[$index] + ". The resolution cites the disagreement and preserves both proposals for audit. Importing this narrative still does not resolve or mutate claim-ledger conflict state.";
              ["conflict_resolution", "operator_review", $conflict.name])
          else empty end)
          )
        )
    '
}

emit_document_chunks
emit_self_audit_sources
emit_repository_chunks
emit_operations_narrative
