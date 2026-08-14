#!/bin/sh
set -eu

export LC_ALL=C
export TZ=UTC

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$script_dir/../.." && pwd)
model_dir=$repo_root/.models/potion-retrieval-32M/hf-6fc8051fab2a1e0ee76689cf08c853792ac285e7
demo_port=${FLEET_RECALL_RELEVANCE_PORT:-18088}

for command_name in cargo curl docker jq mktemp sed; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        printf 'required command not found: %s\n' "$command_name" >&2
        exit 69
    fi
done
case $demo_port in
    ''|*[!0-9]*)
        printf 'FLEET_RECALL_RELEVANCE_PORT must be numeric\n' >&2
        exit 64
        ;;
esac
if [ "$demo_port" -lt 1024 ] || [ "$demo_port" -gt 65535 ]; then
    printf 'FLEET_RECALL_RELEVANCE_PORT must be between 1024 and 65535\n' >&2
    exit 64
fi
for model_file in config.json model.safetensors tokenizer.json; do
    if [ ! -f "$model_dir/$model_file" ] || [ -L "$model_dir/$model_file" ]; then
        printf 'pinned model file is missing or unsafe: %s\n' "$model_dir/$model_file" >&2
        exit 66
    fi
done

test_root=$(mktemp -d "${TMPDIR:-/tmp}/fleet-seeded-relevance.XXXXXX")
case $test_root in
    "${TMPDIR:-/tmp}"/fleet-seeded-relevance.*) ;;
    *)
        printf 'unexpected temporary directory: %s\n' "$test_root" >&2
        exit 70
        ;;
esac
container_name=fleet-seeded-relevance-$$
demo_pid=
container_started=0

cleanup() {
    status=$?
    trap - EXIT HUP INT TERM
    if [ -n "$demo_pid" ]; then
        kill "$demo_pid" 2>/dev/null || true
        wait "$demo_pid" 2>/dev/null || true
    fi
    if [ "$container_started" -eq 1 ]; then
        docker stop "$container_name" >/dev/null 2>&1 || true
    fi
    if [ "$status" -ne 0 ] && [ -f "$test_root/demo.log" ]; then
        printf '%s\n' '--- demo log tail ---' >&2
        tail -80 "$test_root/demo.log" >&2 || true
    fi
    if [ "$status" -ne 0 ]; then
        for result_name in spec migration architecture implementation purpose libraries off_domain; do
            result_file=$test_root/$result_name.json
            if [ -f "$result_file" ]; then
                jq -c --arg case "$result_name" '{
                    case: $case,
                    hits: [.data.hits[]? | {source_id, snippet, extra}],
                    conflict_count: (.conflicts | length),
                    retrieval: .diagnostics.retrieval
                }' "$result_file" >&2 || true
            fi
        done
    fi
    rm -rf "$test_root"
    exit "$status"
}
trap cleanup EXIT HUP INT TERM

cd "$repo_root"
cargo build --quiet --bin ostk-fleet-recall
fleet_bin=$repo_root/target/debug/ostk-fleet-recall
model_digest=$("$fleet_bin" model-digest "$model_dir")
case $model_digest in
    *[!0-9a-f]*|'')
        printf 'model digest was not lowercase hexadecimal\n' >&2
        exit 1
        ;;
esac
if [ "${#model_digest}" -ne 64 ]; then
    printf 'model digest had unexpected length\n' >&2
    exit 1
fi

corpus=$test_root/rich-demo.ndjson
"$repo_root/examples/rich-demo/generate.sh" > "$corpus"
"$repo_root/examples/rich-demo/verify.sh" "$corpus" >/dev/null
corpus_rows=$(jq -s 'length' "$corpus")
if [ "$corpus_rows" -ne 548 ]; then
    printf 'expected 548 generated corpus rows, found %s\n' "$corpus_rows" >&2
    exit 1
fi

docker run --rm -d \
    --name "$container_name" \
    --memory=2g \
    -p 127.0.0.1::26257 \
    cockroachdb/cockroach:v26.2.3 \
    start-single-node --insecure --store=type=mem,size=768MiB > "$test_root/container-id"
container_started=1

database_ready=0
attempt=1
while [ "$attempt" -le 60 ]; do
    if docker exec "$container_name" cockroach sql \
        --insecure --host=127.0.0.1:26257 --execute='SELECT 1' >/dev/null 2>&1; then
        database_ready=1
        break
    fi
    sleep 1
    attempt=$((attempt + 1))
done
if [ "$database_ready" -ne 1 ]; then
    printf 'disposable CockroachDB did not become ready\n' >&2
    exit 1
fi
database_endpoint=$(docker port "$container_name" 26257/tcp)
database_port=${database_endpoint##*:}
case $database_port in
    ''|*[!0-9]*)
        printf 'Docker returned an invalid CockroachDB port: %s\n' "$database_endpoint" >&2
        exit 1
        ;;
esac

export FLEET_RECALL_DATABASE_URL="postgresql://root@127.0.0.1:$database_port/defaultdb?sslmode=disable"
export FLEET_RECALL_ALLOW_INSECURE_LOCAL_DATABASE=1
export FLEET_RECALL_TENANT_ID=0198a849-f6ae-7d61-9800-000000000071
export FLEET_RECALL_PROJECT=seeded-relevance-gate
export FLEET_RECALL_AGENT=gate-reader
export FLEET_RECALL_MAX_CONNECTIONS=4
export FLEET_RECALL_EMBEDDING_MODEL=minishlab/potion-retrieval-32M
export FLEET_RECALL_EMBEDDING_MODEL_PATH="$model_dir"
export FLEET_RECALL_EMBEDDING_MODEL_SHA256="$model_digest"
export RUST_LOG=ostk_fleet_recall=warn

"$fleet_bin" migrate > "$test_root/migrate.json"
"$fleet_bin" ingest --input "$corpus" > "$test_root/ingest.json"
jq -e '.upserted == 548' "$test_root/ingest.json" >/dev/null

run_id=seeded-relevance-v1
FLEET_RECALL_AGENT=agent-a "$fleet_bin" reference-agent \
    --step record-retraction-spec-claim --run-id "$run_id" > "$test_root/spec-claim.json"
FLEET_RECALL_AGENT=agent-c "$fleet_bin" reference-agent \
    --step record-retraction-implementation-claim --run-id "$run_id" \
    > "$test_root/implementation-claim.json"
jq -e '.result.conflict_id > 0 and (.result.member_claim_ids | length == 2)' \
    "$test_root/implementation-claim.json" >/dev/null

FLEET_RECALL_AGENT=agent-a "$fleet_bin" reference-agent \
    --step record-decision --run-id "$run_id" > "$test_root/migration-decision.json"
FLEET_RECALL_AGENT=agent-c "$fleet_bin" reference-agent \
    --step record-conflict --run-id "$run_id" > "$test_root/migration-conflict.json"
jq -e '.result.conflict_id > 0 and (.result.member_claim_ids | length == 2)' \
    "$test_root/migration-conflict.json" >/dev/null

FLEET_RECALL_AGENT=gate-reader "$fleet_bin" demo --listen "127.0.0.1:$demo_port" \
    > "$test_root/demo.log" 2>&1 &
demo_pid=$!
demo_ready=0
attempt=1
while [ "$attempt" -le 120 ]; do
    if curl --fail --silent "http://127.0.0.1:$demo_port/healthz" >/dev/null 2>&1; then
        demo_ready=1
        break
    fi
    if ! kill -0 "$demo_pid" 2>/dev/null; then
        wait "$demo_pid"
        exit 1
    fi
    sleep 1
    attempt=$((attempt + 1))
done
if [ "$demo_ready" -ne 1 ]; then
    printf 'local demo did not become ready\n' >&2
    exit 1
fi

recall() {
    name=$1
    query=$2
    payload=$(jq -cn --arg query "$query" '{query: $query, limit: 8}')
    curl --fail --silent --show-error \
        --header 'content-type: application/json' \
        --header 'accept: application/json' \
        --data "$payload" \
        "http://127.0.0.1:$demo_port/api/recall" > "$test_root/$name.json"
    jq -e '
        (.data.hits | type == "array") and
        (.conflicts | type == "array") and
        (.diagnostics.retrieval.lanes == ["lexical", "dense"]) and
        (.diagnostics.retrieval.fusion == "rrf") and
        (.diagnostics.retrieval.dense_min_cosine_similarity >= 0.179) and
        (.diagnostics.retrieval.dense_min_cosine_similarity <= 0.181) and
        (.diagnostics.retrieval.stratified_code_prefetch == 0) and
        (.diagnostics.retrieval.support_coordinates_truncated == false)
    ' "$test_root/$name.json" >/dev/null
}

assert_no_conflict() {
    jq -e '
        (.conflicts | length == 0) and
        (.diagnostics.retrieval.conflict_matches | length == 0)
    ' "$1" >/dev/null
}

recall spec 'Does MCP remember support deliberate retractions?'
jq -e '
    . as $root |
    (.conflicts | length == 1) and
    (.diagnostics.retrieval.conflict_matches | length == 1) and
    (.diagnostics.retrieval.conflict_matches[0].best_fused_hit_rank >= 1) and
    (.diagnostics.retrieval.conflict_matches[0].best_fused_hit_rank <= 8) and
    (.diagnostics.retrieval.conflict_matches[0].direct_claim_ids | length >= 1) and
    any(.diagnostics.retrieval.conflict_matches[0].source_support[];
        .chunk_id as $chunk |
        any($root.data.hits[];
            .chunk_id == $chunk and
            (.source_id == "examples/README.md" or
             .source_id == "src/mcp/tools.rs" or
             .source_id == "src/application.rs")))
' "$test_root/spec.json" >/dev/null

recall migration 'How are conflicting migration strategies represented and escalated?'
jq -e '
    . as $root |
    (.conflicts | length >= 1) and
    (.diagnostics.retrieval.conflict_matches | length == ($root.conflicts | length)) and
    any(.diagnostics.retrieval.conflict_matches[];
        .direct_claim_ids | length > 0)
' "$test_root/migration.json" >/dev/null

recall architecture 'Why does Fleet Recall use CockroachDB for shared agent memory?'
assert_no_conflict "$test_root/architecture.json"
jq -e '
    any(.data.hits[]; .source_id == "docs/PROJECT_PRIMER.md") and
    any(.data.hits[0:3][];
        ((.snippet | ascii_downcase) | contains("cockroachdb")) and
        (((.snippet | ascii_downcase) | contains("shared sql transactions")) or
         ((.snippet | ascii_downcase) | contains("memory plane")) or
         ((.snippet | ascii_downcase) | contains("durable fleet plane"))))
' "$test_root/architecture.json" >/dev/null

recall implementation 'How does Rust write memories to CockroachDB?'
assert_no_conflict "$test_root/implementation.json"
jq -e '
    any(.data.hits[]; .source_id == "docs/PROJECT_PRIMER.md") and
    any(.data.hits[0:3][];
        ((.snippet | ascii_downcase) | contains("sqlx")) or
        ((.snippet | ascii_downcase) | contains("pgpool")) or
        ((.snippet | ascii_downcase) | contains("serializable")) or
        ((.snippet | ascii_downcase) | contains("remember_record")))
' "$test_root/implementation.json" >/dev/null

recall purpose 'Why does this project exist?'
assert_no_conflict "$test_root/purpose.json"
jq -e '
    any(.data.hits[]; .source_id == "docs/PROJECT_PRIMER.md") and
    any(.data.hits[0:3][];
        ((.snippet | ascii_downcase) | contains("why fleet recall exists")) or
        ((.snippet | ascii_downcase) | contains("inference call is temporary")) or
        ((.snippet | ascii_downcase) | contains("agents are replaceable")))
' "$test_root/purpose.json" >/dev/null

recall libraries 'what libraries are used to write to the datastore?'
assert_no_conflict "$test_root/libraries.json"
jq -e '
    any(.data.hits[]; .source_id == "docs/PROJECT_PRIMER.md") and
    any(.data.hits[0:3][];
        ((.snippet | ascii_downcase) | contains("sqlx")) or
        ((.snippet | ascii_downcase) | contains("tokio")) or
        ((.snippet | ascii_downcase) | contains("rustls")))
' "$test_root/libraries.json" >/dev/null

# The public limiter allows six immediate recalls and then replenishes one
# token per interval. Exercise the seventh query through the same route after
# one deterministic refill rather than bypassing the production rate policy.
sleep 5
recall off_domain 'quantum chromodynamics penguins'
assert_no_conflict "$test_root/off_domain.json"
jq -e '.data.hits | length == 0' "$test_root/off_domain.json" >/dev/null

printf '%s\n' \
    'seeded relevance gate passed: 4 UI samples, 2 user probes, 1 off-domain query; 2 exact conflicts'
