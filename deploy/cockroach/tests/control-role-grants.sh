#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$script_dir/../../.." && pwd)
image=${FLEET_RECALL_CRDB_IMAGE:-cockroachdb/cockroach:v26.2.3}
container="ostk-control-grants-$$"

cleanup() {
    docker rm --force "$container" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

fail() {
    echo "control-role grant proof failed: $*" >&2
    exit 1
}

root_sql() {
    docker exec "$container" cockroach sql \
        --insecure \
        --database fleet_recall \
        --format tsv \
        --execute "$1"
}

sql_as() {
    local user=$1
    local statement=$2
    docker exec "$container" cockroach sql \
        --insecure \
        --database fleet_recall \
        --user "$user" \
        --format tsv \
        --execute "$statement"
}

expect_allowed() {
    local user=$1
    local label=$2
    local statement=$3
    sql_as "$user" "$statement" >/dev/null || fail "$label should be allowed for $user"
}

expect_denied() {
    local user=$1
    local label=$2
    local statement=$3
    local output
    if output=$(sql_as "$user" "$statement" 2>&1); then
        fail "$label unexpectedly succeeded for $user"
    fi
    if ! grep -Eiq 'privilege|permission|not have.*grant' <<<"$output"; then
        echo "$output" >&2
        fail "$label failed for a reason other than authorization"
    fi
}

assert_exact() {
    local label=$1
    local actual=$2
    local expected=$3
    if test "$actual" != "$expected"; then
        printf '%s\n' "unexpected $label" "expected:" "$expected" "actual:" "$actual" >&2
        fail "$label does not match the frozen privilege set"
    fi
}

docker run --detach --name "$container" "$image" \
    start-single-node --insecure --listen-addr=localhost:26257 >/dev/null

ready=0
for _ in $(seq 1 60); do
    if docker exec "$container" cockroach sql --insecure --execute 'SELECT 1' >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 1
done
test "$ready" -eq 1 || fail "CockroachDB did not become ready"

docker exec "$container" cockroach sql --insecure \
    --execute 'CREATE DATABASE fleet_recall' >/dev/null
docker exec -i "$container" cockroach sql --insecure --database fleet_recall \
    < "$repo_root/migrations/0003_control_event_ledger.sql" >/dev/null

# A stand-in legacy table proves that the private bootstrap role cannot read or
# mutate the existing corpus/claim surface.
root_sql 'CREATE TABLE memory_chunks (id INT8 PRIMARY KEY)' >/dev/null
root_sql 'CREATE TABLE _sqlx_migrations (version INT8 PRIMARY KEY, success BOOL NOT NULL); INSERT INTO _sqlx_migrations VALUES (3, true)' \
    >/dev/null
root_sql 'CREATE USER proof_runtime; CREATE USER proof_bootstrap; CREATE USER proof_public' \
    >/dev/null
docker exec -i "$container" cockroach sql --insecure --database fleet_recall \
    < "$repo_root/deploy/cockroach/control-role-grants.sql" >/dev/null
root_sql 'GRANT fleet_runtime TO proof_runtime; GRANT fleet_control_bootstrap TO proof_bootstrap' \
    >/dev/null

control_grants=$(root_sql "
SELECT table_name || ':' || grantee || ':' || privilege_type || ':' ||
       CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END AS normalized
FROM [SHOW GRANTS ON TABLE
    memory_control_bootstraps,
    memory_control_log_epochs,
    memory_control_shard_heads,
    memory_control_events]
WHERE grantee IN ('public', 'fleet_runtime', 'fleet_control_bootstrap')
ORDER BY table_name, privilege_type" | tail -n +2)
expected_control_grants='memory_control_bootstraps:fleet_control_bootstrap:INSERT:not_grantable
memory_control_bootstraps:fleet_control_bootstrap:SELECT:not_grantable
memory_control_events:fleet_control_bootstrap:INSERT:not_grantable
memory_control_events:fleet_control_bootstrap:SELECT:not_grantable
memory_control_log_epochs:fleet_control_bootstrap:INSERT:not_grantable
memory_control_log_epochs:fleet_control_bootstrap:SELECT:not_grantable
memory_control_shard_heads:fleet_control_bootstrap:INSERT:not_grantable
memory_control_shard_heads:fleet_control_bootstrap:SELECT:not_grantable
memory_control_shard_heads:fleet_control_bootstrap:UPDATE:not_grantable'
assert_exact "control-table grants" "$control_grants" "$expected_control_grants"

migration_grants=$(root_sql "
SELECT table_name || ':' || grantee || ':' || privilege_type || ':' ||
       CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END AS normalized
FROM [SHOW GRANTS ON TABLE _sqlx_migrations]
WHERE grantee IN ('public', 'fleet_runtime', 'fleet_control_bootstrap')
ORDER BY grantee, privilege_type" | tail -n +2)
expected_migration_grants='_sqlx_migrations:fleet_control_bootstrap:SELECT:not_grantable
_sqlx_migrations:fleet_runtime:SELECT:not_grantable'
assert_exact "migration-table grants" "$migration_grants" "$expected_migration_grants"

database_grants=$(root_sql "
SELECT database_name || ':' || grantee || ':' || privilege_type || ':' ||
       CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END AS normalized
FROM [SHOW GRANTS ON DATABASE fleet_recall]
WHERE grantee IN ('public', 'fleet_runtime', 'fleet_control_bootstrap')
ORDER BY grantee, privilege_type" | tail -n +2)
expected_database_grants='fleet_recall:fleet_control_bootstrap:CONNECT:not_grantable
fleet_recall:fleet_runtime:CONNECT:not_grantable'
assert_exact "database grants" "$database_grants" "$expected_database_grants"

schema_grants=$(root_sql "
SELECT schema_name || ':' || grantee || ':' || privilege_type || ':' ||
       CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END AS normalized
FROM [SHOW GRANTS ON SCHEMA public]
WHERE grantee IN ('public', 'fleet_runtime', 'fleet_control_bootstrap')
ORDER BY grantee, privilege_type" | tail -n +2)
expected_schema_grants='public:fleet_control_bootstrap:USAGE:not_grantable
public:fleet_runtime:USAGE:not_grantable'
assert_exact "schema grants" "$schema_grants" "$expected_schema_grants"

# The runtime and an otherwise unprivileged login cannot see the control plane.
expect_denied proof_runtime "runtime control read" \
    'SELECT count(*) FROM memory_control_bootstraps'
expect_denied proof_runtime "runtime control write" \
    "INSERT INTO memory_control_bootstraps (tenant_id) VALUES ('0198a849-f6ae-7d61-9800-000000000001')"
expect_denied proof_public "public control read" \
    'SELECT count(*) FROM memory_control_events'
expect_allowed proof_runtime "runtime schema-version read" \
    'SELECT EXISTS (SELECT 1 FROM _sqlx_migrations WHERE version = 3 AND success)'
expect_allowed proof_bootstrap "bootstrap schema-version preflight" \
    'SELECT EXISTS (SELECT 1 FROM _sqlx_migrations WHERE version = 3 AND success)'
expect_denied proof_bootstrap "migration-history write" \
    'UPDATE _sqlx_migrations SET success = false WHERE version = 3'

# Synthetic values satisfy only the database shape. They are not contract
# fixtures and never pass through the application bootstrap verifier.
expect_allowed proof_bootstrap "bootstrap reservation insert" "
INSERT INTO memory_control_bootstraps (
    tenant_id, project, contract_tenant_namespace, contract_project_namespace,
    receipt_digest, statement_id, bootstrap_event_id, profile_id, profile_digest,
    vector_manifest_digest, genesis_registry_package_digest, signer_policy_digest,
    signer_count, approval_threshold, epoch_id, shard_count, bootstrap_shard,
    bootstrap_offset, canonical_receipt, canonical_genesis_package
) VALUES (
    '0198a849-f6ae-7d61-9800-000000000001', 'grant-proof',
    'tenant.proof', 'project.proof',
    decode(repeat('11', 32), 'hex'), decode(repeat('22', 32), 'hex'),
    decode(repeat('33', 32), 'hex'), 'ostk-canonical-json-v1',
    decode(repeat('44', 32), 'hex'), decode(repeat('55', 32), 'hex'),
    decode(repeat('66', 32), 'hex'), decode(repeat('77', 32), 'hex'),
    3, 2, decode(repeat('88', 32), 'hex'), 2, 0, 1,
    decode('7b7d', 'hex'), decode('7b7d', 'hex')
)"
expect_allowed proof_bootstrap "epoch insert" "
INSERT INTO memory_control_log_epochs (
    tenant_id, project, epoch_id, bootstrap_receipt_digest, canonical_epoch,
    partition_recipe_id, partition_recipe_version, partition_algorithm,
    partition_seed, shard_count
) VALUES (
    '0198a849-f6ae-7d61-9800-000000000001', 'grant-proof',
    decode(repeat('88', 32), 'hex'), decode(repeat('11', 32), 'hex'),
    decode('7b7d', 'hex'), 'ostk.partition.sha256_prefix64_modulo', 1,
    'sha256_prefix64_modulo', decode(repeat('99', 32), 'hex'), 2
)"
expect_allowed proof_bootstrap "head insert" "
INSERT INTO memory_control_shard_heads (
    tenant_id, project, epoch_id, shard, shard_count, last_committed_offset, chain_digest
) VALUES
    ('0198a849-f6ae-7d61-9800-000000000001', 'grant-proof',
     decode(repeat('88', 32), 'hex'), 0, 2, 0, decode(repeat('aa', 32), 'hex')),
    ('0198a849-f6ae-7d61-9800-000000000001', 'grant-proof',
     decode(repeat('88', 32), 'hex'), 1, 2, 0, decode(repeat('bb', 32), 'hex'))"
expect_allowed proof_bootstrap "event insert" "
INSERT INTO memory_control_events (
    tenant_id, project, epoch_id, shard, committed_offset, event_id,
    event_schema_version, event_kind, semantic_object_digest, consistency_family,
    consistency_key_digest, canonical_event, previous_chain_digest, chain_digest
) VALUES (
    '0198a849-f6ae-7d61-9800-000000000001', 'grant-proof',
    decode(repeat('88', 32), 'hex'), 0, 1, decode(repeat('33', 32), 'hex'),
    1, 'control.bootstrap.accepted', decode(repeat('11', 32), 'hex'),
    'control.bootstrap', decode(repeat('22', 32), 'hex'),
    decode('7b7d', 'hex'), decode(repeat('aa', 32), 'hex'),
    decode(repeat('cc', 32), 'hex')
)"
expect_allowed proof_bootstrap "head compare-and-swap" "
UPDATE memory_control_shard_heads
SET last_committed_offset = 1, chain_digest = decode(repeat('cc', 32), 'hex')
WHERE tenant_id = '0198a849-f6ae-7d61-9800-000000000001'
  AND project = 'grant-proof' AND shard = 0
  AND last_committed_offset = 0
  AND chain_digest = decode(repeat('aa', 32), 'hex')"
expect_allowed proof_bootstrap "complete shape inspection" '
SELECT
    (SELECT count(*) FROM memory_control_bootstraps),
    (SELECT count(*) FROM memory_control_log_epochs),
    (SELECT count(*) FROM memory_control_shard_heads),
    (SELECT count(*) FROM memory_control_events)'

expect_denied proof_bootstrap "immutable bootstrap update" \
    "UPDATE memory_control_bootstraps SET project = 'changed' WHERE project = 'grant-proof'"
expect_denied proof_bootstrap "immutable bootstrap deletion" \
    "DELETE FROM memory_control_bootstraps WHERE project = 'grant-proof'"
expect_denied proof_bootstrap "immutable epoch update" \
    "UPDATE memory_control_log_epochs SET shard_count = 1 WHERE project = 'grant-proof'"
expect_denied proof_bootstrap "immutable epoch deletion" \
    "DELETE FROM memory_control_log_epochs WHERE project = 'grant-proof'"
expect_denied proof_bootstrap "immutable event update" \
    "UPDATE memory_control_events SET event_kind = 'changed' WHERE project = 'grant-proof'"
expect_denied proof_bootstrap "immutable event deletion" \
    "DELETE FROM memory_control_events WHERE project = 'grant-proof'"
expect_denied proof_bootstrap "head deletion" \
    "DELETE FROM memory_control_shard_heads WHERE project = 'grant-proof'"
expect_denied proof_bootstrap "schema creation" \
    'CREATE TABLE bootstrap_escape (id INT8 PRIMARY KEY)'
expect_denied proof_bootstrap "legacy corpus read" \
    'SELECT count(*) FROM memory_chunks'
expect_denied proof_bootstrap "grant delegation" \
    'GRANT SELECT ON TABLE memory_control_events TO proof_public'

echo "verified effective bootstrap grants:"
root_sql "SHOW GRANTS ON TABLE
    memory_control_bootstraps,
    memory_control_log_epochs,
    memory_control_shard_heads,
    memory_control_events
    FOR fleet_control_bootstrap"
echo "control-role grant proof passed"
