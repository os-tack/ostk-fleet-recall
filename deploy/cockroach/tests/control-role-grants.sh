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

expect_scalar() {
    local user=$1
    local label=$2
    local statement=$3
    local expected=$4
    local actual
    actual=$(sql_as "$user" "$statement" | tail -n +2)
    if test "$actual" != "$expected"; then
        printf '%s\n' "unexpected $label for $user" \
            "expected: $expected" "actual: $actual" >&2
        fail "$label returned the wrong value"
    fi
}

expect_denied() {
    local user=$1
    local label=$2
    local statement=$3
    local output
    if output=$(sql_as "$user" "$statement" 2>&1); then
        fail "$label unexpectedly succeeded for $user"
    fi
    if ! grep -Eiq \
        'privilege|permission|not have.*grant|must have.*(CREATEROLE|admin option)' \
        <<<"$output"; then
        echo "$output" >&2
        fail "$label failed for a reason other than authorization"
    fi
}

expect_constraint() {
    local user=$1
    local label=$2
    local constraint=$3
    local statement=$4
    local output
    if output=$(sql_as "$user" "$statement" 2>&1); then
        fail "$label unexpectedly succeeded for $user"
    fi
    if ! grep -Fq "$constraint" <<<"$output"; then
        echo "$output" >&2
        fail "$label did not fail on $constraint"
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

# Freeze the Stage-2 command's deliberately older compatibility gate. The
# current proof database reaches version 9, but bootstrap authority is complete
# at the uninterrupted successful prefix 1 through 3.
control_required_schema_version=$(sed -n \
    's/^const REQUIRED_SCHEMA_VERSION: i64 = \([0-9][0-9]*\);$/\1/p' \
    "$repo_root/src/bin/ostk-control-bootstrap.rs")
assert_exact "control bootstrap required schema version" \
    "$control_required_schema_version" '3'
# shellcheck disable=SC2016 # Match the literal Rust bind placeholder.
control_schema_preflight=$(sed -n \
    '/^const CONTROL_SCHEMA_READY_SQL:/,/^     FROM _sqlx_migrations WHERE version BETWEEN 1 AND \$1";$/p' \
    "$repo_root/src/bin/ostk-control-bootstrap.rs")
# shellcheck disable=SC2016 # Rust bind placeholders are intentional literals.
expected_control_schema_preflight='const CONTROL_SCHEMA_READY_SQL: &str = "SELECT count(*) = $1 \
     AND COALESCE(bool_and(success), false) \
     FROM _sqlx_migrations WHERE version BETWEEN 1 AND $1";'
assert_exact "control bootstrap complete-prefix preflight" \
    "$control_schema_preflight" "$expected_control_schema_preflight"

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
for migration in \
    0003_control_event_ledger.sql \
    0004_genesis_registry_activation.sql \
    0005_control_ledger_invariants.sql \
    0006_control_bootstrap_explicit_acceptance_time.sql \
    0007_control_epoch_explicit_creation_time.sql \
    0008_control_head_explicit_advance_time.sql \
    0009_control_event_explicit_acceptance_time.sql
do
    docker exec -i "$container" cockroach sql --insecure --database fleet_recall \
        < "$repo_root/migrations/$migration" >/dev/null
done

# A stand-in legacy table and sequence prove that the private bootstrap role
# cannot read, mutate, or allocate from the existing corpus/claim surface.
root_sql '
CREATE TABLE memory_chunks (id INT8 PRIMARY KEY);
CREATE SEQUENCE memory_claim_id_seq START 1 MINVALUE 1 MAXVALUE 9007199254740991;
' >/dev/null
root_sql 'CREATE TABLE _sqlx_migrations (version INT8 PRIMARY KEY, success BOOL NOT NULL); INSERT INTO _sqlx_migrations SELECT version, true FROM generate_series(1, 9) AS version' \
    >/dev/null
root_sql '
CREATE USER proof_database_owner;
CREATE USER proof_runtime;
CREATE USER proof_bootstrap;
CREATE USER proof_public;
ALTER DATABASE fleet_recall OWNER TO proof_database_owner;
' \
    >/dev/null
docker exec -i "$container" cockroach sql --insecure --database fleet_recall \
    < "$repo_root/deploy/cockroach/control-role-grants.sql" >/dev/null

# Database ownership is not cluster security authority. The deterministic
# option, admin-membership, and SYSTEM cleanup requires the stronger operator
# documented in the policy header.
expect_denied proof_database_owner "database owner role-option hardening" \
    'ALTER ROLE fleet_runtime WITH NOLOGIN NOCREATEROLE NOCREATEDB'
expect_denied proof_database_owner "database owner admin-membership cleanup" \
    'REVOKE admin FROM fleet_runtime'
expect_denied proof_database_owner "database owner system-grant cleanup" \
    'REVOKE SYSTEM ALL FROM fleet_runtime'

# Inject direct, inherited, role-option, SYSTEM, and PUBLIC drift, then prove
# one application restores the exact Stage-2 boundary.
root_sql '
ALTER ROLE fleet_runtime WITH LOGIN CREATEROLE CREATEDB;
ALTER ROLE fleet_control_bootstrap WITH LOGIN CREATEROLE CREATEDB;
GRANT admin TO fleet_runtime, fleet_control_bootstrap;
GRANT fleet_runtime TO fleet_control_bootstrap;
GRANT SYSTEM CREATEROLE TO fleet_runtime, fleet_control_bootstrap;
GRANT ALL ON DATABASE fleet_recall TO public, fleet_control_bootstrap;
GRANT ALL ON SCHEMA public TO public, fleet_control_bootstrap;
GRANT SELECT ON TABLE memory_chunks TO public, fleet_control_bootstrap;
GRANT ALL ON SEQUENCE memory_claim_id_seq TO public, fleet_control_bootstrap;
GRANT DELETE ON TABLE memory_control_events
    TO public, fleet_runtime, fleet_control_bootstrap;
' >/dev/null
docker exec -i "$container" cockroach sql --insecure --database fleet_recall \
    < "$repo_root/deploy/cockroach/control-role-grants.sql" >/dev/null

# Exercise the reverse cross-role edge separately because CockroachDB rejects a
# membership cycle before the policy can repair it.
root_sql 'GRANT fleet_control_bootstrap TO fleet_runtime' >/dev/null
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

bootstrap_current_object_grants=$(root_sql "
SELECT object_type || ':' || object_name || ':' || privilege_type || ':' ||
       CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END AS normalized
FROM [SHOW GRANTS FOR fleet_control_bootstrap]
WHERE database_name = 'fleet_recall'
  AND schema_name = 'public'
  AND object_type IN ('table', 'sequence')
ORDER BY object_type, object_name, privilege_type" | tail -n +2)
expected_bootstrap_current_object_grants='table:_sqlx_migrations:SELECT:not_grantable
table:memory_control_bootstraps:INSERT:not_grantable
table:memory_control_bootstraps:SELECT:not_grantable
table:memory_control_events:INSERT:not_grantable
table:memory_control_events:SELECT:not_grantable
table:memory_control_log_epochs:INSERT:not_grantable
table:memory_control_log_epochs:SELECT:not_grantable
table:memory_control_shard_heads:INSERT:not_grantable
table:memory_control_shard_heads:SELECT:not_grantable
table:memory_control_shard_heads:UPDATE:not_grantable'
assert_exact "bootstrap full current table/sequence grants" \
    "$bootstrap_current_object_grants" "$expected_bootstrap_current_object_grants"

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

public_application_object_grants=$(root_sql "
SELECT object_type || ':' || object_name || ':' || privilege_type || ':' ||
       CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END AS normalized
FROM [SHOW GRANTS FOR public]
WHERE database_name = 'fleet_recall'
  AND schema_name = 'public'
  AND object_type IN ('table', 'sequence')
ORDER BY object_type, object_name, privilege_type" | tail -n +2)
assert_exact "PUBLIC application table/sequence grants" \
    "$public_application_object_grants" ''

system_grants=$(root_sql "
SELECT grantee || ':' || privilege_type AS normalized
FROM [SHOW SYSTEM GRANTS]
WHERE grantee IN ('fleet_runtime', 'fleet_control_bootstrap')
ORDER BY grantee, privilege_type" | tail -n +2)
assert_exact "runtime/bootstrap system grants" "$system_grants" ''

role_options=$(root_sql "
SELECT username || ':' || options::STRING AS normalized
FROM [SHOW USERS]
WHERE username IN ('fleet_runtime', 'fleet_control_bootstrap')
ORDER BY username" | tail -n +2)
expected_role_options='fleet_control_bootstrap:{NOLOGIN}
fleet_runtime:{NOLOGIN}'
assert_exact "runtime/bootstrap role options" "$role_options" "$expected_role_options"

role_edges=$(root_sql "
SELECT role_name || ':' || member || ':' ||
       CASE WHEN is_admin THEN 'admin_option' ELSE 'no_admin_option' END AS normalized
FROM [SHOW GRANTS ON ROLE]
WHERE member IN ('fleet_runtime', 'fleet_control_bootstrap', 'proof_runtime', 'proof_bootstrap')
   OR role_name IN ('fleet_runtime', 'fleet_control_bootstrap')
ORDER BY role_name, member" | tail -n +2)
expected_role_edges='fleet_control_bootstrap:proof_bootstrap:no_admin_option
fleet_runtime:proof_runtime:no_admin_option'
assert_exact "runtime/bootstrap role membership edges" \
    "$role_edges" "$expected_role_edges"

# The policy resets current objects and creates no future-object rule. Freeze
# the schema creator's relevant defaults; production repeats this exact audit
# while authenticated as the actual migrator identity.
default_privileges=$(root_sql "
SELECT COALESCE(role, 'ALL') || ':' || object_type || ':' || grantee || ':' ||
       privilege_type || ':' ||
       CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END AS normalized
FROM [SHOW DEFAULT PRIVILEGES]
WHERE object_type IN ('tables', 'sequences')
  AND grantee IN ('public', 'fleet_runtime', 'fleet_control_bootstrap')
ORDER BY role, object_type, grantee, privilege_type" | tail -n +2)
assert_exact "schema-creator table/sequence default privileges" \
    "$default_privileges" ''

# Freeze the current post-v9 schema independently of the Stage-2 command's
# intentionally older compatibility preflight.
control_timestamp_defaults=$(root_sql "
SELECT table_name || ':' || column_name || ':' ||
       COALESCE(column_default, 'NULL') AS normalized
FROM information_schema.columns
WHERE (table_name, column_name) IN (
    ('memory_control_bootstraps', 'accepted_at'),
    ('memory_control_log_epochs', 'created_at'),
    ('memory_control_shard_heads', 'advanced_at'),
    ('memory_control_events', 'accepted_at')
)
ORDER BY table_name, column_name" | tail -n +2)
expected_control_timestamp_defaults='memory_control_bootstraps:accepted_at:NULL
memory_control_events:accepted_at:NULL
memory_control_log_epochs:created_at:NULL
memory_control_shard_heads:advanced_at:NULL'
assert_exact "post-v9 control timestamp defaults" \
    "$control_timestamp_defaults" "$expected_control_timestamp_defaults"

predecessor_index=$(root_sql "
SELECT index_name || ':' ||
       CASE WHEN non_unique THEN 'non_unique' ELSE 'unique' END || ':' ||
       seq_in_index::STRING || ':' || column_name AS normalized
FROM [SHOW INDEXES FROM memory_control_events]
WHERE index_name = 'memory_control_events_predecessor_unique_idx'
  AND NOT implicit
ORDER BY seq_in_index" | tail -n +2)
expected_predecessor_index='memory_control_events_predecessor_unique_idx:unique:1:tenant_id
memory_control_events_predecessor_unique_idx:unique:2:project
memory_control_events_predecessor_unique_idx:unique:3:epoch_id
memory_control_events_predecessor_unique_idx:unique:4:shard
memory_control_events_predecessor_unique_idx:unique:5:previous_chain_digest'
assert_exact "scoped predecessor index" \
    "$predecessor_index" "$expected_predecessor_index"

# The runtime and an otherwise unprivileged login cannot see the control plane.
expect_denied proof_runtime "runtime control read" \
    'SELECT count(*) FROM memory_control_bootstraps'
expect_denied proof_runtime "runtime control write" \
    "INSERT INTO memory_control_bootstraps (tenant_id) VALUES ('0198a849-f6ae-7d61-9800-000000000001')"
expect_denied proof_public "public control read" \
    'SELECT count(*) FROM memory_control_events'
expect_scalar proof_runtime "current successful migration prefix" \
    'SELECT count(*) = 9 AND COALESCE(bool_and(success), false)
     FROM _sqlx_migrations WHERE version BETWEEN 1 AND 9' \
    't'
expect_scalar proof_bootstrap "Stage-2 complete-prefix preflight" \
    'SELECT count(*) = 3 AND COALESCE(bool_and(success), false)
     FROM _sqlx_migrations WHERE version BETWEEN 1 AND 3' \
    't'
root_sql 'UPDATE _sqlx_migrations SET success = false WHERE version = 2' >/dev/null
expect_scalar proof_bootstrap "failed Stage-2 prerequisite is not masked by v9" \
    'SELECT count(*) = 3 AND COALESCE(bool_and(success), false)
     FROM _sqlx_migrations WHERE version BETWEEN 1 AND 3' \
    'f'
root_sql 'UPDATE _sqlx_migrations SET success = true WHERE version = 2' >/dev/null
expect_allowed proof_bootstrap "Stage-2 preflight plan" \
    'EXPLAIN SELECT count(*) = 3 AND COALESCE(bool_and(success), false)
     FROM _sqlx_migrations WHERE version BETWEEN 1 AND 3'
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
    bootstrap_offset, canonical_receipt, canonical_genesis_package, accepted_at
) VALUES (
    '0198a849-f6ae-7d61-9800-000000000001', 'grant-proof',
    'tenant.proof', 'project.proof',
    decode(repeat('11', 32), 'hex'), decode(repeat('22', 32), 'hex'),
    decode(repeat('33', 32), 'hex'), 'ostk-canonical-json-v1',
    decode(repeat('44', 32), 'hex'), decode(repeat('55', 32), 'hex'),
    decode(repeat('66', 32), 'hex'), decode(repeat('77', 32), 'hex'),
    3, 2, decode(repeat('88', 32), 'hex'), 2, 0, 1,
    decode('7b7d', 'hex'), decode('7b7d', 'hex'),
    '2026-08-15 12:00:00+00'
)"
expect_allowed proof_bootstrap "epoch insert" "
INSERT INTO memory_control_log_epochs (
    tenant_id, project, epoch_id, bootstrap_receipt_digest, canonical_epoch,
    partition_recipe_id, partition_recipe_version, partition_algorithm,
    partition_seed, shard_count, created_at
) VALUES (
    '0198a849-f6ae-7d61-9800-000000000001', 'grant-proof',
    decode(repeat('88', 32), 'hex'), decode(repeat('11', 32), 'hex'),
    decode('7b7d', 'hex'), 'ostk.partition.sha256_prefix64_modulo', 1,
    'sha256_prefix64_modulo', decode(repeat('99', 32), 'hex'), 2,
    '2026-08-15 12:00:00+00'
)"
expect_allowed proof_bootstrap "head insert" "
INSERT INTO memory_control_shard_heads (
    tenant_id, project, epoch_id, shard, shard_count, last_committed_offset,
    chain_digest, advanced_at
) VALUES
    ('0198a849-f6ae-7d61-9800-000000000001', 'grant-proof',
     decode(repeat('88', 32), 'hex'), 0, 2, 0, decode(repeat('aa', 32), 'hex'),
     '2026-08-15 12:00:00+00'),
    ('0198a849-f6ae-7d61-9800-000000000001', 'grant-proof',
     decode(repeat('88', 32), 'hex'), 1, 2, 0, decode(repeat('bb', 32), 'hex'),
     '2026-08-15 12:00:00+00')"
expect_allowed proof_bootstrap "event insert" "
INSERT INTO memory_control_events (
    tenant_id, project, epoch_id, shard, committed_offset, event_id,
    event_schema_version, event_kind, semantic_object_digest, consistency_family,
    consistency_key_digest, canonical_event, previous_chain_digest, chain_digest,
    accepted_at
) VALUES (
    '0198a849-f6ae-7d61-9800-000000000001', 'grant-proof',
    decode(repeat('88', 32), 'hex'), 0, 1, decode(repeat('33', 32), 'hex'),
    1, 'control.bootstrap.accepted', decode(repeat('11', 32), 'hex'),
    'control.bootstrap', decode(repeat('22', 32), 'hex'),
    decode('7b7d', 'hex'), decode(repeat('aa', 32), 'hex'),
    decode(repeat('cc', 32), 'hex'), '2026-08-15 12:00:00+00'
)"
expect_constraint proof_bootstrap "duplicate predecessor insert" \
    memory_control_events_predecessor_unique_idx "
INSERT INTO memory_control_events (
    tenant_id, project, epoch_id, shard, committed_offset, event_id,
    event_schema_version, event_kind, semantic_object_digest, consistency_family,
    consistency_key_digest, canonical_event, previous_chain_digest, chain_digest,
    accepted_at
) VALUES (
    '0198a849-f6ae-7d61-9800-000000000001', 'grant-proof',
    decode(repeat('88', 32), 'hex'), 0, 2, decode(repeat('34', 32), 'hex'),
    1, 'test.detached', decode(repeat('12', 32), 'hex'),
    'test.detached', decode(repeat('23', 32), 'hex'),
    decode('7b7d', 'hex'), decode(repeat('aa', 32), 'hex'),
    decode(repeat('cd', 32), 'hex'), '2026-08-15 12:00:01+00'
)"
expect_allowed proof_bootstrap "head compare-and-swap" "
UPDATE memory_control_shard_heads
SET last_committed_offset = 1,
    chain_digest = decode(repeat('cc', 32), 'hex'),
    advanced_at = '2026-08-15 12:00:00+00'
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
expect_denied proof_bootstrap "legacy sequence use" \
    "SELECT nextval('memory_claim_id_seq')"
expect_denied proof_bootstrap "database creation" \
    'CREATE DATABASE bootstrap_escape'
expect_denied proof_bootstrap "role creation" \
    'CREATE ROLE bootstrap_escape'
expect_denied proof_bootstrap "grant delegation" \
    'GRANT SELECT ON TABLE memory_control_events TO proof_public'
expect_denied proof_bootstrap "role-membership delegation" \
    'GRANT fleet_control_bootstrap TO proof_public'

echo "verified effective bootstrap grants:"
root_sql "SHOW GRANTS ON TABLE
    memory_control_bootstraps,
    memory_control_log_epochs,
    memory_control_shard_heads,
    memory_control_events
    FOR fleet_control_bootstrap"
echo "control-role grant proof passed"
