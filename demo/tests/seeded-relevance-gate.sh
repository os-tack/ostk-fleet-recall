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
case $corpus_rows in
    ''|*[!0-9]*|0)
        printf 'generated corpus row count is invalid: %s\n' "$corpus_rows" >&2
        exit 1
        ;;
esac

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

root_sql() {
    database=$1
    shift
    docker exec -i "$container_name" cockroach sql \
        --insecure --host=127.0.0.1:26257 --database="$database" "$@"
}

root_scalar() {
    database=$1
    statement=$2
    if ! scalar_output=$(root_sql "$database" --format=tsv --execute="$statement"); then
        printf 'root scalar query failed in %s\n' "$database" >&2
        exit 1
    fi
    printf '%s\n' "$scalar_output" | tail -n 1
}

root_sql defaultdb --execute='CREATE DATABASE IF NOT EXISTS fleet_recall' >/dev/null
writer_database_url="postgresql://root@127.0.0.1:$database_port/fleet_recall?sslmode=disable"
export FLEET_RECALL_DATABASE_URL="$writer_database_url"
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
jq -e --argjson expected "$corpus_rows" \
    '.upserted == $expected' "$test_root/ingest.json" >/dev/null

run_id=seeded-relevance-v1
FLEET_RECALL_AGENT=agent-a "$fleet_bin" reference-agent \
    --step record-retraction-spec-claim --run-id "$run_id" > "$test_root/spec-claim.json"
FLEET_RECALL_AGENT=agent-c "$fleet_bin" reference-agent \
    --step record-retraction-implementation-claim --run-id "$run_id" \
    > "$test_root/implementation-claim.json"
spec_claim_id=$(jq -er '.result.claim_id' "$test_root/spec-claim.json")
implementation_claim_id=$(jq -er '.result.claim_id' \
    "$test_root/implementation-claim.json")
spec_conflict_id=$(jq -er '.result.conflict_id' \
    "$test_root/implementation-claim.json")
jq -e \
    --argjson spec_claim_id "$spec_claim_id" \
    --argjson implementation_claim_id "$implementation_claim_id" \
    --argjson conflict_id "$spec_conflict_id" '
    .result.conflict_id == $conflict_id and
    (.result.member_claim_ids | sort) ==
        ([$spec_claim_id, $implementation_claim_id] | sort) and
    (.result.source_coordinates | map(.source_id) | sort) ==
        (["src/application.rs", "src/mcp/tools.rs"] | sort)
' "$test_root/implementation-claim.json" >/dev/null
jq -e '
    (.result.source_coordinates | map(.source_id)) == ["examples/README.md"]
' "$test_root/spec-claim.json" >/dev/null

FLEET_RECALL_AGENT=agent-a "$fleet_bin" reference-agent \
    --step record-decision --run-id "$run_id" > "$test_root/migration-decision.json"
FLEET_RECALL_AGENT=agent-c "$fleet_bin" reference-agent \
    --step record-conflict --run-id "$run_id" > "$test_root/migration-conflict.json"
jq -e '.result.conflict_id > 0 and (.result.member_claim_ids | length == 2)' \
    "$test_root/migration-conflict.json" >/dev/null

# The dedicated policy proofs own the full cross-database PUBLIC-03 lifecycle.
# This relevance gate independently installs the same terminal reader matrix on
# its fresh, single-purpose database so the public demo cannot reuse the
# migration/ingest root URL.
root_sql fleet_recall --execute="
CREATE USER IF NOT EXISTS fleet_publication;
ALTER USER fleet_publication WITH NOLOGIN NOCREATEDB NOCREATEROLE;
REVOKE admin FROM fleet_publication;
REVOKE SYSTEM ALL FROM fleet_publication;

CREATE ROLE IF NOT EXISTS fleet_publication_reader;
ALTER ROLE fleet_publication_reader WITH NOLOGIN NOCREATEDB NOCREATEROLE;
REVOKE admin FROM fleet_publication_reader;
REVOKE SYSTEM ALL FROM fleet_publication_reader;

REVOKE ALL ON DATABASE fleet_recall
    FROM public, fleet_publication_reader;
REVOKE ALL ON SCHEMA public
    FROM public, fleet_publication_reader;
REVOKE ALL ON ALL TABLES IN SCHEMA public
    FROM public, fleet_publication_reader;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public
    FROM public, fleet_publication_reader;

GRANT CONNECT ON DATABASE fleet_recall TO fleet_publication_reader;
GRANT USAGE ON SCHEMA public TO fleet_publication_reader;
GRANT SELECT ON TABLE
    public._sqlx_migrations,
    public.memory_corpus_models,
    public.memory_chunks,
    public.memory_claim_embeddings,
    public.memory_claim_support,
    public.memory_claims,
    public.memory_conflict_members,
    public.memory_conflicts
TO fleet_publication_reader;
GRANT fleet_publication_reader TO fleet_publication;
ALTER USER fleet_publication WITH LOGIN NOCREATEDB NOCREATEROLE;
" >/dev/null

publication_terminal=$(root_scalar fleet_recall "
SELECT
    (SELECT count(*)::STRING FROM [SHOW GRANTS FOR fleet_publication_reader]
      WHERE grantee = 'fleet_publication_reader') || ':' ||
    (SELECT count(*)::STRING FROM [SHOW GRANTS FOR fleet_publication]
      WHERE grantee = 'fleet_publication') || ':' ||
    (SELECT count(*)::STRING FROM [SHOW GRANTS ON ROLE]
      WHERE role_name = 'fleet_publication_reader'
        AND member = 'fleet_publication'
        AND NOT is_admin) || ':' ||
    (SELECT count(*)::STRING FROM [SHOW USERS]
      WHERE username = 'fleet_publication_reader'
        AND options::STRING = '{NOLOGIN}') || ':' ||
    (SELECT count(*)::STRING FROM [SHOW USERS]
      WHERE username = 'fleet_publication'
        AND options::STRING = '{}');
")
if [ "$publication_terminal" != '10:0:1:1:1' ]; then
    printf 'publication terminal state differs from 10:0:1:1:1: %s\n' \
        "$publication_terminal" >&2
    exit 1
fi

unset FLEET_RECALL_DATABASE_URL
unset FLEET_RECALL_CONTROL_DATABASE_URL
unset FLEET_RECALL_REGISTRY_DATABASE_URL
unset FLEET_RECALL_SUCCESSOR_DATABASE_URL
unset FLEET_RECALL_RECONCILIATION_DATABASE_URL
unset FLEET_RECALL_TEST_DATABASE_URL
unset FLEET_RECONCILIATION_TEST_DATABASE_URL
unset FLEET_RECALL_PUBLICATION_TEST_ADMIN_DATABASE_URL
unset FLEET_RECALL_DATABASE_SECRET_ID
unset FLEET_RECALL_PRIVATE_DATABASE_KIND
# The nonempty password field satisfies the application's closed URL shape.
# CockroachDB insecure mode neither stores nor authenticates this fixture value.
publication_scheme=postgresql
publication_fixture_password=local-seeded-publication-only
export FLEET_RECALL_PUBLICATION_DATABASE_URL="${publication_scheme}://fleet_publication:${publication_fixture_password}@127.0.0.1:$database_port/fleet_recall?sslmode=disable"

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
jq -e \
    --argjson spec_claim_id "$spec_claim_id" \
    --argjson implementation_claim_id "$implementation_claim_id" \
    --argjson conflict_id "$spec_conflict_id" '
    (.conflicts | length == 1) and
    (.conflicts[0].id == $conflict_id) and
    (.diagnostics.retrieval.conflict_matches | length == 1) and
    (.diagnostics.retrieval.conflict_matches[0].conflict_id == $conflict_id) and
    (.diagnostics.retrieval.conflict_matches[0].best_fused_hit_rank >= 1) and
    (.diagnostics.retrieval.conflict_matches[0].best_fused_hit_rank <= 8) and
    (.diagnostics.retrieval.conflict_matches[0].direct_claim_ids | sort) ==
        ([$spec_claim_id, $implementation_claim_id] | sort) and
    any(.data.hits[];
        .source_id == ("claim/" + ($spec_claim_id | tostring))) and
    any(.data.hits[];
        .source_id == ("claim/" + ($implementation_claim_id | tostring)))
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
    any(.data.hits[];
        (.source_id == "docs/ARCHITECTURE.md" or
         .source_id == "docs/PROJECT_PRIMER.md" or
         .source_id == "src/lib.rs" or
         .source_id == "docs/SUBMISSION.md") and
        (((.snippet | ascii_downcase) | contains("cockroachdb")) or
         ((.snippet | ascii_downcase) | contains("shared"))) and
        (((.snippet | ascii_downcase) | contains("memory plane")) or
         ((.snippet | ascii_downcase) | contains("durable")) or
         ((.snippet | ascii_downcase) | contains("fleet"))))
' "$test_root/architecture.json" >/dev/null

recall implementation 'How does Rust write memories to CockroachDB?'
assert_no_conflict "$test_root/implementation.json"
jq -e '
    any(.data.hits[];
        (.source_id == "docs/PROJECT_PRIMER.md" or
         .source_id == "src/store/mod.rs" or
         .source_id == "src/store/cockroach.rs" or
         .source_id == "src/ledger/cockroach.rs" or
         .source_id == "src/main.rs") and
        (((.snippet | ascii_downcase) | contains("sqlx")) or
         ((.snippet | ascii_downcase) | contains("pgpool")) or
         ((.snippet | ascii_downcase) | contains("serializable")) or
         ((.snippet | ascii_downcase) | contains("remember_record")) or
         ((.snippet | ascii_downcase) | contains("cockroach"))))
' "$test_root/implementation.json" >/dev/null

recall purpose 'Why does this project exist?'
assert_no_conflict "$test_root/purpose.json"
jq -e '
    any(.data.hits[];
        (.source_id == "README.md" or
         .source_id == "docs/ARCHITECTURE.md" or
         .source_id == "docs/PROJECT_PRIMER.md" or
         .source_id == "docs/SUBMISSION.md" or
         .source_id == "src/lib.rs") and
        (((.snippet | ascii_downcase) | contains("inference call is temporary")) or
         ((.snippet | ascii_downcase) | contains("agents are replaceable")) or
         ((.snippet | ascii_downcase) | contains("shared")) or
         ((.snippet | ascii_downcase) | contains("fleet"))))
' "$test_root/purpose.json" >/dev/null

recall libraries 'what libraries are used to write to the datastore?'
assert_no_conflict "$test_root/libraries.json"
jq -e '
    any(.data.hits[];
        (.source_id == "Cargo.toml" or
         .source_id == "docs/PROJECT_PRIMER.md" or
         .source_id == "src/store/cockroach.rs" or
         .source_id == "src/private_postgres.rs") and
        (((.snippet | ascii_downcase) | contains("sqlx")) or
         ((.snippet | ascii_downcase) | contains("tokio")) or
         ((.snippet | ascii_downcase) | contains("rustls")) or
         ((.snippet | ascii_downcase) | contains("pgpool"))))
' "$test_root/libraries.json" >/dev/null

# The public limiter allows six immediate recalls and then replenishes one
# token per interval. Split the seventh query literal after one refill so the
# repository-backed corpus cannot index the complete probe.
sleep 5
recall off_domain 'quan''tum chrom''odynamics pen''guins'
assert_no_conflict "$test_root/off_domain.json"
jq -e '.data.hits | length == 0' "$test_root/off_domain.json" >/dev/null

printf 'seeded relevance gate passed: %s current corpus rows; 4 UI samples, 2 user probes, 1 off-domain query; 2 exact conflicts\n' \
    "$corpus_rows"
