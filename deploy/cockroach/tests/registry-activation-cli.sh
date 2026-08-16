#!/usr/bin/env bash
set -euo pipefail

# This is the authoritative connected correctness proof. It uses the exact
# official CockroachDB binary, runs all three live repository suites plus the
# conflict-contract matrix, and exercises both currently wired private CLI
# state machines on one secure local server.
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$script_dir/../../.." && pwd)
expected_crdb_build_tag=v26.2.3
crdb=${FLEET_RECALL_CRDB_BINARY:-}
if test -z "$crdb"; then
    crdb=$(command -v cockroach || true)
fi
test -n "$crdb" && test -x "$crdb" || {
    echo "official-binary correctness proof requires CockroachDB $expected_crdb_build_tag via FLEET_RECALL_CRDB_BINARY or PATH" >&2
    exit 1
}
actual_crdb_build_tag=$("$crdb" version --build-tag)
test "$actual_crdb_build_tag" = "$expected_crdb_build_tag" || {
    echo "official-binary correctness proof requires exact CockroachDB $expected_crdb_build_tag (found $actual_crdb_build_tag)" >&2
    exit 1
}

proof_dir=$(mktemp -d "${TMPDIR:-/tmp}/ostk-registry-cli.XXXXXX")
cert_dir="$proof_dir/certs"
store_dir="$proof_dir/store"
artifact_dir="$proof_dir/artifacts"
url_file="$proof_dir/listening-url"
pid_file="$proof_dir/cockroach.pid"
root_default_url=''
control_password='local-control-member-proof-password'
activation_password='local-activation-member-proof-password'
runtime_password='local-runtime-member-proof-password'

cleanup() {
    server_pid=''
    if test -f "$pid_file"; then
        server_pid=$(sed -n '1p' "$pid_file")
    fi
    drained=0
    if test -n "$root_default_url"; then
        if "$crdb" node drain --self --shutdown --url="$root_default_url" \
            --drain-wait=10s >/dev/null 2>&1; then
            drained=1
        fi
    fi
    case "$server_pid" in
        ''|*[!0-9]*) ;;
        *)
            if test "$drained" -eq 0 && kill -0 "$server_pid" >/dev/null 2>&1; then
                kill -TERM "$server_pid" >/dev/null 2>&1 || true
            fi
            for _ in $(seq 1 120); do
                if ! kill -0 "$server_pid" >/dev/null 2>&1; then
                    break
                fi
                sleep 0.25
            done
            if kill -0 "$server_pid" >/dev/null 2>&1; then
                kill -KILL "$server_pid" >/dev/null 2>&1 || true
            fi
            ;;
    esac
    case "$proof_dir" in
        */ostk-registry-cli.*)
            for _ in $(seq 1 20); do
                rm -rf -- "$proof_dir" 2>/dev/null || true
                test ! -e "$proof_dir" && break
                sleep 0.1
            done
            if test -e "$proof_dir"; then
                echo "could not remove registry proof directory: $proof_dir" >&2
                return 1
            fi
            ;;
        *) echo "refusing to remove unexpected proof directory" >&2 ;;
    esac
}
trap cleanup EXIT INT TERM

fail() {
    echo "registry activation CLI proof failed: $*" >&2
    exit 1
}

root_scalar() {
    "$crdb" sql --url="$root_url" --format=tsv --execute="$1" | tail -n +2
}

assert_root_scalar() {
    local label=$1
    local statement=$2
    local expected=$3
    local actual
    actual=$(root_scalar "$statement")
    if test "$actual" != "$expected"; then
        printf '%s\n' "unexpected $label" \
            "expected: $expected" "actual: $actual" >&2
        fail "$label did not match the authoritative schema state"
    fi
}

mkdir -p "$artifact_dir"
"$crdb" cert create-ca --certs-dir="$cert_dir" \
    --ca-key="$proof_dir/ca.key" >/dev/null
"$crdb" cert create-node localhost 127.0.0.1 ::1 \
    --certs-dir="$cert_dir" --ca-key="$proof_dir/ca.key" >/dev/null
"$crdb" cert create-client root --certs-dir="$cert_dir" \
    --ca-key="$proof_dir/ca.key" >/dev/null
"$crdb" start-single-node \
    --certs-dir="$cert_dir" \
    --store="$store_dir" \
    --listen-addr=127.0.0.1:0 \
    --sql-addr=127.0.0.1:0 \
    --http-addr=127.0.0.1:0 \
    --listening-url-file="$url_file" \
    --pid-file="$pid_file" \
    --background \
    --log-dir="$proof_dir/logs" \
    --logtostderr=NONE >"$proof_dir/server-stdout" 2>"$proof_dir/server-stderr"

ready=0
for _ in $(seq 1 120); do
    if test -s "$url_file"; then
        IFS= read -r root_default_url < "$url_file"
        if "$crdb" sql --url="$root_default_url" --execute='SELECT 1' \
            >/dev/null 2>&1; then
            ready=1
            break
        fi
    fi
    sleep 0.25
done
test "$ready" -eq 1 || fail "CockroachDB did not become ready"

root_url=$(printf '%s\n' "$root_default_url" | sed 's#/defaultdb?#/fleet_recall?#')
"$crdb" sql --url="$root_default_url" \
    --execute='CREATE DATABASE fleet_recall' >/dev/null

# Apply the exact embedded migration chain under root certificate authority,
# then run all three connected repository matrices. Together they cover
# bootstrap durability plus genesis and successor activation races, replays,
# timing, scope isolation, corruption, and bounded query plans.
FLEET_RECALL_TEST_DATABASE_URL="$root_url" \
    cargo test --locked --test control_log_live -- --nocapture
FLEET_RECALL_TEST_DATABASE_URL="$root_url" \
    cargo test --locked --test registry_activation_live -- --nocapture
successor_live_test=live_first_successor_activation_when_configured
successor_live_listing=$(cargo test --locked --test successor_activation_live -- --list)
grep -Fxq "$successor_live_test: test" <<<"$successor_live_listing" \
    || fail "successor live proof test was not discovered"
FLEET_RECALL_TEST_DATABASE_URL="$root_url" \
    cargo test --locked --test successor_activation_live \
        "$successor_live_test" -- --exact --nocapture
conflict_live_test=ledger::cockroach::tests::live_conflict_polarity_matrix_when_configured
conflict_live_listing=$(cargo test --locked --lib -- --list)
grep -Fxq "$conflict_live_test: test" <<<"$conflict_live_listing" \
    || fail "conflict polarity live proof test was not discovered"
FLEET_RECALL_TEST_DATABASE_URL="$root_url" \
    cargo test --locked --lib "$conflict_live_test" -- --exact --nocapture
FLEET_RECALL_TEST_DATABASE_URL="$root_url" \
    cargo test --locked --lib \
        store::cockroach::tests::live_transactional_migration_rolls_back_ddl_on_history_conflict_when_configured \
        -- --exact --nocapture

# Freeze the authoritative schema independently of the two Stage-2/Stage-3
# command preflights. The database must have exactly the successful embedded
# migration chain through 14 and all three successor authority tables.
assert_root_scalar "exact successful migration prefix 1 through 14" '
    SELECT CASE WHEN count(*) = 14
                          AND min(version) = 1
                          AND max(version) = 14
                          AND COALESCE(bool_and(success), false)
                     THEN '\''ready'\'' ELSE '\''not_ready'\'' END
    FROM _sqlx_migrations' 'ready'
assert_root_scalar "successor authority table set" '
    SELECT string_agg(table_name, '\''|'\'' ORDER BY table_name)
    FROM information_schema.tables
    WHERE table_schema = '\''public'\''
      AND table_name IN (
          '\''memory_registry_transitions'\'',
          '\''memory_registry_genesis_bridge_consumptions'\'',
          '\''memory_registry_current_heads_v2'\''
      )' 'memory_registry_current_heads_v2|memory_registry_genesis_bridge_consumptions|memory_registry_transitions'
assert_root_scalar "exact successor root index set" '
    SELECT string_agg(tablename || '\'':'\'' || indexname, '\''|'\'' ORDER BY tablename)
    FROM pg_catalog.pg_indexes
    WHERE schemaname = '\''public'\''
      AND indexname IN (
          '\''memory_registry_heads_genesis_root_idx'\'',
          '\''memory_registry_activations_genesis_root_idx'\''
      )' 'memory_registry_activations:memory_registry_activations_genesis_root_idx|memory_registry_heads:memory_registry_heads_genesis_root_idx'

# Migrations 10 and 11 are the intentionally resumable online-index phase.
# Replaying their exact bytes must accept the existing exact indexes without
# changing SQLx history or silently accepting a same-name/different-shape index.
"$crdb" sql --url="$root_url" \
    < "$repo_root/migrations/0010_registry_genesis_head_root_index.sql" >/dev/null
"$crdb" sql --url="$root_url" \
    < "$repo_root/migrations/0011_registry_genesis_activation_root_index.sql" >/dev/null
assert_root_scalar "migration history after exact index replay" \
    'SELECT count(*)::STRING FROM _sqlx_migrations' '14'

# Demonstrate why MAX(successful version) is not a readiness check: version 14
# remains successful while a failed version 12 makes the complete-prefix gate
# false. Restore the row before exercising either v9-compatible private CLI.
"$crdb" sql --url="$root_url" \
    --execute='UPDATE _sqlx_migrations SET success = false WHERE version = 12' >/dev/null
assert_root_scalar "later success remains visible during failed migration 12" \
    'SELECT max(version)::STRING FROM _sqlx_migrations WHERE success' '14'
assert_root_scalar "failed migration 12 is not masked by version 14" '
    SELECT CASE WHEN count(*) = 14
                          AND min(version) = 1
                          AND max(version) = 14
                          AND COALESCE(bool_and(success), false)
                     THEN '\''ready'\'' ELSE '\''not_ready'\'' END
    FROM _sqlx_migrations' 'not_ready'
"$crdb" sql --url="$root_url" \
    --execute='UPDATE _sqlx_migrations SET success = true WHERE version = 12' >/dev/null
assert_root_scalar "restored successful migration prefix 1 through 14" '
    SELECT CASE WHEN count(*) = 14 AND COALESCE(bool_and(success), false)
                     THEN '\''ready'\'' ELSE '\''not_ready'\'' END
    FROM _sqlx_migrations
    WHERE version BETWEEN 1 AND 14' 'ready'

"$crdb" sql --url="$root_url" \
    < "$repo_root/deploy/cockroach/control-role-grants.sql" >/dev/null
"$crdb" sql --url="$root_url" \
    < "$repo_root/deploy/cockroach/registry-activation-role-grants.sql" >/dev/null
"$crdb" sql --url="$root_url" \
    < "$repo_root/deploy/cockroach/successor-schema-quarantine-grants.sql" >/dev/null

# Login identities are distinct from the non-login logical roles. Neither
# private credential is the root/migrator or the serving credential.
"$crdb" sql --url="$root_url" --execute="
    CREATE USER proof_control_cli WITH PASSWORD '$control_password';
    CREATE USER proof_activation_cli WITH PASSWORD '$activation_password';
    CREATE USER proof_runtime_cli WITH PASSWORD '$runtime_password';
    GRANT fleet_control_bootstrap TO proof_control_cli;
    GRANT fleet_registry_activation TO proof_activation_cli;
    GRANT fleet_runtime TO proof_runtime_cli;
" >/dev/null

host_port=$(printf '%s\n' "$root_default_url" | sed -E 's#.*@([^/]+)/.*#\1#')
case "$host_port" in
    127.0.0.1:[0-9]*) ;;
    *) fail "CockroachDB returned an unexpected loopback SQL address" ;;
esac
ca_path="$cert_dir/ca.crt"
control_url="postgresql://proof_control_cli:${control_password}@${host_port}/fleet_recall?sslmode=verify-full&sslrootcert=${ca_path}"
activation_url="postgresql://proof_activation_cli:${activation_password}@${host_port}/fleet_recall?sslmode=verify-full&sslrootcert=${ca_path}"
runtime_url="postgresql://proof_runtime_cli:${runtime_password}@${host_port}/fleet_recall?sslmode=verify-full&sslrootcert=${ca_path}"

cargo build --locked --bin ostk-control-bootstrap --bin ostk-registry-activate >/dev/null

bootstrap_receipt="$repo_root/contracts/dynamic-memory/v1/bootstrap-receipt.jsonl"
genesis_package="$repo_root/contracts/dynamic-memory/v1/genesis-registry-package.jsonl"
registry_test_result="$repo_root/contracts/dynamic-memory/v1/genesis-activation/registry-test-result.jsonl"
frozen_statement="$repo_root/contracts/dynamic-memory/v1/genesis-activation/activation-statement.jsonl"
frozen_approvals="$repo_root/contracts/dynamic-memory/v1/genesis-activation/activation-approval-set.jsonl"
statement_path="$frozen_statement"
approval_path="$frozen_approvals"
tenant_id='0198a849-f6ae-7d61-9800-000000000001'
physical_project='private-registry-cli-proof'
receipt_digest='084ee06ea7ebf3b1d592d6e5843584485144c0ee5720fcc2124a61a7fcde48f0'
test_result_digest='e91e08070250a722446195b76ee685a9697298b9fdce9809027f120c829b679d'
runner_artifact_digest='c2e5b0653471d35e54600a8d3fbe5613aff4c04e911787c09a25e2b327d4bbbd'
runner_configuration_digest='1d12aabe349fd0013389f93bf1917b0de6bbd5d2bd7156c85faff0b97360686d'
package_digest='5a931fd5551bec47f83adb019f3e794d1b6a759f4501e7ea26a83076d9518177'
policy_digest='6f92f99ff35969845f08f9b64cee7d86fa42dc6165ebc617d950be8960b86968'

run_bootstrap() {
    local operation=$1
    FLEET_RECALL_CONTROL_DATABASE_URL="$control_url" \
    FLEET_RECALL_TENANT_ID="$tenant_id" \
    FLEET_RECALL_PROJECT="$physical_project" \
    FLEET_RECALL_CONTROL_TENANT_NAMESPACE='tenant.fixture' \
    FLEET_RECALL_CONTROL_PROJECT_NAMESPACE='project.fixture' \
    FLEET_RECALL_BOOTSTRAP_RECEIPT_DIGEST="$receipt_digest" \
        "$repo_root/target/debug/ostk-control-bootstrap" "$operation" \
        --receipt "$bootstrap_receipt" \
        --genesis-package "$genesis_package"
}

run_activation() {
    local operation=$1
    local database_url=${PROOF_REGISTRY_DATABASE_URL:-$activation_url}
    local bootstrap_pin=${PROOF_BOOTSTRAP_RECEIPT_DIGEST:-$receipt_digest}
    local statement=${PROOF_ACTIVATION_STATEMENT:-$statement_path}
    local approvals=${PROOF_ACTIVATION_APPROVAL_SET:-$approval_path}
    FLEET_RECALL_REGISTRY_DATABASE_URL="$database_url" \
    FLEET_RECALL_REGISTRY_TENANT_ID="$tenant_id" \
    FLEET_RECALL_REGISTRY_PROJECT="$physical_project" \
    FLEET_RECALL_REGISTRY_TENANT_NAMESPACE='tenant.fixture' \
    FLEET_RECALL_REGISTRY_PROJECT_NAMESPACE='project.fixture' \
    FLEET_RECALL_REGISTRY_BOOTSTRAP_RECEIPT_DIGEST="$bootstrap_pin" \
    FLEET_RECALL_REGISTRY_TEST_RESULT_DIGEST="$test_result_digest" \
    FLEET_RECALL_REGISTRY_TEST_RUNNER_ARTIFACT_DIGEST="$runner_artifact_digest" \
    FLEET_RECALL_REGISTRY_TEST_RUNNER_CONFIGURATION_DIGEST="$runner_configuration_digest" \
    FLEET_RECALL_REGISTRY_PROPOSER_PRINCIPAL_ID='principal.operator' \
    FLEET_RECALL_REGISTRY_PACKAGE_AUTHOR_PRINCIPAL_ID='principal.author' \
        "$repo_root/target/debug/ostk-registry-activate" "$operation" \
        --bootstrap-receipt "$bootstrap_receipt" \
        --genesis-package "$genesis_package" \
        --registry-test-result "$registry_test_result" \
        --activation-statement "$statement" \
        --activation-approval-set "$approvals"
}

scope_shape() {
    root_scalar "
        SELECT
          (SELECT count(*) FROM memory_control_events
             WHERE tenant_id = '$tenant_id' AND project = '$physical_project')::STRING || '|' ||
          (SELECT count(*) FROM memory_registry_activations
             WHERE tenant_id = '$tenant_id' AND project = '$physical_project')::STRING || '|' ||
          (SELECT count(*) FROM memory_registry_heads
             WHERE tenant_id = '$tenant_id' AND project = '$physical_project')::STRING"
}

# Offline authority must win over transport: a bad pin and a syntactically
# valid but unreachable URL reports only the pin mismatch, never connect.
unreachable_url="postgresql://proof_activation_cli:${activation_password}@127.0.0.1:1/fleet_recall?sslmode=verify-full&sslrootcert=${ca_path}"
if bad_pin=$(PROOF_REGISTRY_DATABASE_URL="$unreachable_url" \
    PROOF_BOOTSTRAP_RECEIPT_DIGEST="$(printf '0%.0s' {1..64})" \
    run_activation inspect 2>&1); then
    fail "bad receipt pin unexpectedly reached the database"
fi
grep -Fq 'bootstrap receipt does not match the deployment pin' <<<"$bad_pin" \
    || fail "artifact verification did not precede connection"
if grep -Fqi 'connect private registry activation database' <<<"$bad_pin"; then
    fail "bad authority attempted a database connection"
fi

# With schema present but no Stage-2 predecessor, the repository preserves its
# closed NotReady classification through the private CLI.
if not_ready=$(run_activation inspect 2>&1); then
    fail "activation inspect unexpectedly succeeded without Stage-2 bootstrap"
fi
grep -Fq 'requires a complete durable bootstrap' <<<"$not_ready" \
    || fail "missing bootstrap did not retain NotReady classification"

bootstrap_absent=$(run_bootstrap inspect)
jq -e --arg receipt "$receipt_digest" '
    .operation == "inspect" and .state == "absent" and
    .receipt_digest == $receipt
' <<<"$bootstrap_absent" >/dev/null || fail "dedicated control login did not inspect absent state"

bootstrap_inserted=$(run_bootstrap apply)
jq -e --arg receipt "$receipt_digest" '
    .operation == "apply" and .state == "inserted" and
    .receipt_digest == $receipt and .committed_offset == "1"
' <<<"$bootstrap_inserted" >/dev/null || fail "dedicated control login did not bootstrap"

bootstrap_complete=$(run_bootstrap inspect)
jq -e --arg receipt "$receipt_digest" '
    .operation == "inspect" and .state == "complete" and
    .receipt_digest == $receipt and .committed_offset == "1"
' <<<"$bootstrap_complete" >/dev/null || fail "dedicated control login did not inspect complete state"

bootstrap_replay=$(run_bootstrap apply)
jq -e --arg receipt "$receipt_digest" '
    .operation == "apply" and .state == "exact_replay" and
    .receipt_digest == $receipt and .committed_offset == "1"
' <<<"$bootstrap_replay" >/dev/null || fail "dedicated control login did not exact-replay bootstrap"

# The frozen vector is intentionally historical. It verifies offline but is
# rejected against this fresh durable bootstrap with the closed Timing error.
if timing=$(run_activation inspect 2>&1); then
    fail "historical effective_from unexpectedly activated a fresh bootstrap"
fi
grep -Fq 'timing failed: effective_from precedes durable bootstrap acceptance' <<<"$timing" \
    || fail "historical statement did not retain Timing classification"

effective_from=$(root_scalar \
    "SELECT to_char(statement_timestamp(), 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"000Z\"')")
stale_effective_from=$(root_scalar \
    "SELECT to_char(statement_timestamp() + INTERVAL '1 microsecond', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"000Z\"')")
case "$effective_from:$stale_effective_from" in
    ????-??-??T??:??:??.?????????Z:????-??-??T??:??:??.?????????Z) ;;
    *) fail "database did not return canonical ceremony timestamps" ;;
esac
FLEET_RECALL_REGISTRY_CLI_FIXTURE_DIR="$artifact_dir" \
FLEET_RECALL_REGISTRY_CLI_EFFECTIVE_FROM="$effective_from" \
FLEET_RECALL_REGISTRY_CLI_STALE_EFFECTIVE_FROM="$stale_effective_from" \
    cargo test --locked --bin ostk-registry-activate \
        tests::emit_time_bound_ceremony_for_connected_proof -- --exact >/dev/null
statement_path="$artifact_dir/activation-statement.jsonl"
approval_path="$artifact_dir/activation-approval-set.jsonl"

# A failed intermediate migration cannot be masked by successful version 9,
# and the preflight must occur before any activation/event/head write.
before_failed_prefix=$(scope_shape)
"$crdb" sql --url="$root_url" \
    --execute='UPDATE _sqlx_migrations SET success = false WHERE version = 8' >/dev/null
if failed_prefix=$(run_activation inspect 2>&1); then
    fail "failed schema prefix was masked by successful migration 9"
fi
grep -Fq 'requires the complete successful schema prefix through 9' <<<"$failed_prefix" \
    || fail "failed schema prefix did not retain its closed error"
after_failed_prefix=$(scope_shape)
test "$before_failed_prefix" = "$after_failed_prefix" \
    || fail "failed schema preflight changed durable state"
"$crdb" sql --url="$root_url" \
    --execute='UPDATE _sqlx_migrations SET success = true WHERE version = 8' >/dev/null

pinned=$(run_activation inspect)
jq -e --arg receipt "$receipt_digest" '
    .operation == "inspect" and .state == "pinned_inactive" and
    .bootstrap_receipt_digest == $receipt and
    .bootstrap_event_id == "ca530fad9338a7a35ce7aad78e016f53b88a21846d4a1f53fecdcb1cabbdabe0" and
    .epoch_id == "d35655f3297e1c5eb4503443befb956f93dc5210b46cdc1a4d7d9f2746b8fab2"
' <<<"$pinned" >/dev/null || fail "inspect did not report exact pinned-inactive receipt"

inserted=$(run_activation apply)
jq -e --arg receipt "$receipt_digest" --arg package "$package_digest" --arg policy "$policy_digest" '
    .operation == "apply" and .state == "inserted" and
    .bootstrap_receipt_digest == $receipt and
    .registry_head.activation_id == .activation_id and
    .registry_head.package_digest == $package and
    .registry_head.activation_policy_digest == $policy and
    (.committed_offset | type) == "string" and
    (.committed_offset | test("^[1-9][0-9]*$"))
' <<<"$inserted" >/dev/null || fail "first activation did not return exact inserted receipt"

accepted=$(run_activation inspect)
activation_id=$(jq -r '.activation_id' <<<"$inserted")
statement_id=$(jq -r '.statement_id' <<<"$inserted")
accepted_event_id=$(jq -r '.accepted_event_id' <<<"$inserted")
control_shard=$(jq -r '.control_shard' <<<"$inserted")
committed_offset=$(jq -r '.committed_offset' <<<"$inserted")
jq -e \
    --arg activation "$activation_id" \
    --arg statement "$statement_id" \
    --arg event "$accepted_event_id" \
    --arg offset "$committed_offset" '
    .operation == "inspect" and .state == "accepted" and
    .activation_id == $activation and .statement_id == $statement and
    .accepted_event_id == $event and .committed_offset == $offset
' <<<"$accepted" >/dev/null || fail "post-activation inspect did not return accepted receipt"

replay=$(run_activation apply)
jq -e \
    --arg activation "$activation_id" \
    --arg statement "$statement_id" \
    --arg event "$accepted_event_id" \
    --arg offset "$committed_offset" '
    .operation == "apply" and .state == "exact_replay" and
    .activation_id == $activation and .statement_id == $statement and
    .accepted_event_id == $event and .committed_offset == $offset
' <<<"$replay" >/dev/null || fail "second activation was not an exact replay"

# Same statement with a second valid approval ceremony is Conflict; a second
# valid statement after the winner is Stale. Neither path mutates state.
shape_before_losers=$(scope_shape)
if conflict=$(PROOF_ACTIVATION_APPROVAL_SET="$artifact_dir/activation-approval-set-alternate.jsonl" \
    run_activation apply 2>&1); then
    fail "changed approval ceremony unexpectedly replayed"
fi
grep -Fq 'conflict: the same activation statement already has a different approval ceremony' \
    <<<"$conflict" || fail "changed approvals did not retain Conflict classification"
if stale=$(PROOF_ACTIVATION_STATEMENT="$artifact_dir/activation-statement-stale.jsonl" \
    PROOF_ACTIVATION_APPROVAL_SET="$artifact_dir/activation-approval-set-stale.jsonl" \
    run_activation apply 2>&1); then
    fail "distinct activation statement unexpectedly replaced the winner"
fi
grep -Fq 'stale because another statement already won' <<<"$stale" \
    || fail "distinct proposal did not retain Stale classification"
test "$shape_before_losers" = "$(scope_shape)" \
    || fail "conflict or stale loser changed durable state"

# Audit exact physical scope, row cardinality, projection identity, source
# coordinate, and the one database acceptance timestamp.
test "$(root_scalar "SELECT count(*)::INT8 FROM memory_control_bootstraps WHERE tenant_id = '$tenant_id' AND project = '$physical_project'")" = '1' \
    || fail "bootstrap scope cardinality changed"
test "$(root_scalar "SELECT count(*)::INT8 FROM memory_control_log_epochs WHERE tenant_id = '$tenant_id' AND project = '$physical_project'")" = '1' \
    || fail "epoch scope cardinality changed"
test "$(root_scalar "SELECT count(*)::INT8 FROM memory_control_shard_heads WHERE tenant_id = '$tenant_id' AND project = '$physical_project'")" = '16' \
    || fail "control head cardinality changed"
test "$(root_scalar "SELECT count(*)::INT8 FROM memory_control_events WHERE tenant_id = '$tenant_id' AND project = '$physical_project'")" = '2' \
    || fail "control event cardinality changed"
test "$(root_scalar "SELECT count(*)::INT8 FROM memory_registry_activations WHERE tenant_id = '$tenant_id' AND project = '$physical_project'")" = '1' \
    || fail "activation row cardinality changed"
test "$(root_scalar "SELECT count(*)::INT8 FROM memory_registry_heads WHERE tenant_id = '$tenant_id' AND project = '$physical_project'")" = '1' \
    || fail "registry head cardinality changed"

stored_receipt=$(root_scalar "
    SELECT encode(a.statement_id, 'hex') || '|' || encode(a.activation_id, 'hex') || '|' ||
           encode(a.accepted_event_id, 'hex') || '|' || a.control_shard::STRING || '|' ||
           a.control_committed_offset::STRING || '|' || encode(h.activation_id, 'hex') || '|' ||
           h.source_shard::STRING || '|' || h.source_committed_offset::STRING || '|' ||
           encode(e.event_id, 'hex') || '|' || e.event_kind
    FROM memory_registry_activations AS a
    JOIN memory_registry_heads AS h ON h.tenant_id = a.tenant_id AND h.project = a.project
    JOIN memory_control_events AS e ON e.tenant_id = a.tenant_id AND e.project = a.project
      AND e.epoch_id = a.control_epoch_id AND e.shard = a.control_shard
      AND e.committed_offset = a.control_committed_offset
    WHERE a.tenant_id = '$tenant_id' AND a.project = '$physical_project'")
expected_receipt="$statement_id|$activation_id|$accepted_event_id|$control_shard|$committed_offset|$activation_id|$control_shard|$committed_offset|$accepted_event_id|registry.genesis.activated"
test "$stored_receipt" = "$expected_receipt" \
    || fail "stored activation projections do not match the CLI receipt"

single_time=$(root_scalar "
    SELECT CASE WHEN a.accepted_at = e.accepted_at
                     AND a.accepted_at = h.activated_at
                     AND a.accepted_at = s.advanced_at
                THEN 'match' ELSE 'mismatch' END
    FROM memory_registry_activations AS a
    JOIN memory_registry_heads AS h ON h.tenant_id = a.tenant_id AND h.project = a.project
    JOIN memory_control_events AS e ON e.tenant_id = a.tenant_id AND e.project = a.project
      AND e.event_id = a.accepted_event_id
    JOIN memory_control_shard_heads AS s ON s.tenant_id = a.tenant_id AND s.project = a.project
      AND s.epoch_id = a.control_epoch_id AND s.shard = a.control_shard
    WHERE a.tenant_id = '$tenant_id' AND a.project = '$physical_project'")
test "$single_time" = 'match' || fail "activation projections did not share one database time"

# Prove the URLs identify separate member logins and the control member cannot
# inherit the Stage-3 surface.
test "$("$crdb" sql --url="$activation_url" --format=tsv \
    --execute='SELECT current_user' | tail -n +2)" = 'proof_activation_cli' \
    || fail "activation URL did not authenticate the activation member login"
if control_registry_read=$("$crdb" sql --url="$control_url" \
    --execute='SELECT count(*) FROM memory_registry_heads' 2>&1); then
    fail "control member unexpectedly inherited registry activation reads"
fi
grep -Eiq 'privilege|permission' <<<"$control_registry_read" \
    || fail "control member registry denial was not an authorization failure"
if runtime_registry_read=$("$crdb" sql --url="$runtime_url" \
    --execute='SELECT count(*) FROM memory_registry_heads' 2>&1); then
    fail "runtime member unexpectedly inherited registry activation reads"
fi
grep -Eiq 'privilege|permission' <<<"$runtime_registry_read" \
    || fail "runtime member registry denial was not an authorization failure"

# Neither bounded JSON nor closed errors may disclose credentials, URLs,
# signatures, or canonical ceremony bytes.
for output in \
    "$bad_pin" "$not_ready" "$bootstrap_absent" "$bootstrap_inserted" \
    "$bootstrap_complete" "$bootstrap_replay" "$timing" "$failed_prefix" \
    "$pinned" "$inserted" "$accepted" "$replay" "$conflict" "$stale" \
    "$control_registry_read" "$runtime_registry_read"
do
    for secret in "$control_password" "$activation_password" "$runtime_password"; do
        if grep -Fq "$secret" <<<"$output"; then
            fail "CLI output disclosed a database credential"
        fi
    done
    if grep -Eqi 'postgres(ql)?://|"signature"|canonical_(statement|approval|receipt|event)' \
        <<<"$output"; then
        fail "CLI output disclosed a URL or canonical authority material"
    fi
done

# Query plan proof for the complete-prefix gate used before every repository
# operation. CockroachDB must retain a bounded primary-key span over 1..9.
prefix_explain=$("$crdb" sql --url="$activation_url" --format=tsv --execute="
    EXPLAIN SELECT count(*) = 9 AND COALESCE(bool_and(success), false)
    FROM _sqlx_migrations WHERE version BETWEEN 1 AND 9")
if ! grep -Eq '_sqlx_migrations@(_sqlx_migrations_pkey|primary)' \
    <<<"$prefix_explain"; then
    printf '%s\n' "$prefix_explain" >&2
    fail "migration-prefix preflight did not use the primary index"
fi
if ! grep -Eq 'span(s)?:.*\[/1[^]]*-[[:space:]]*/9\]' <<<"$prefix_explain"; then
    printf '%s\n' "$prefix_explain" >&2
    fail "migration-prefix preflight did not retain the bounded 1..9 span"
fi

printf '%s\n' \
    "private control bootstrap receipts:" \
    "$bootstrap_absent" \
    "$bootstrap_inserted" \
    "$bootstrap_complete" \
    "$bootstrap_replay" \
    "private registry activation receipts:" \
    "$pinned" \
    "$inserted" \
    "$accepted" \
    "$replay" \
    "official-binary connected correctness proof passed"
