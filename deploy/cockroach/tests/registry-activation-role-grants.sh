#!/usr/bin/env bash
set -euo pipefail

# Secondary Docker parity only: this preserves the image-level activation RBAC
# proof, but cannot substitute for the official-binary correctness lane.
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$script_dir/../../.." && pwd)
image=${FLEET_RECALL_CRDB_IMAGE:-cockroachdb/cockroach:v26.2.3}
expected_crdb_build_tag=v26.2.3
container="ostk-registry-activation-grants-$$"

cleanup() {
    docker rm --force "$container" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

fail() {
    echo "registry-activation grant proof failed: $*" >&2
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

# CockroachDB 26.2 does not accept column targets in GRANT UPDATE, so the table
# grant below is the narrowest engine-enforced shape. Freeze the only activation
# repository UPDATE statement to prove the credential is used solely for the
# scoped head CAS and never to mutate epoch, shard, or shard-count identity.
application_head_update=$(sed -n \
    '/^const ADVANCE_CONTROL_HEAD_SQL:/,/^     RETURNING last_committed_offset, chain_digest";$/p' \
    "$repo_root/src/registry_activation/cockroach.rs")
# shellcheck disable=SC2016 # Rust bind placeholders are intentional literals.
expected_application_head_update='const ADVANCE_CONTROL_HEAD_SQL: &str = "UPDATE memory_control_shard_heads \
     SET last_committed_offset = $5, chain_digest = $6, advanced_at = $7 \
     WHERE tenant_id = $1 AND project = $2 AND epoch_id = $3 AND shard = $4 \
       AND last_committed_offset = $8 AND chain_digest = $9 \
     RETURNING last_committed_offset, chain_digest";'
assert_exact "activation repository shard-head CAS" \
    "$application_head_update" "$expected_application_head_update"
application_head_update_count=$(grep -Ec \
    '^const [A-Z_]+: &str = "UPDATE memory_control_shard_heads' \
    "$repo_root/src/registry_activation/cockroach.rs")
assert_exact "activation repository shard-head UPDATE count" \
    "$application_head_update_count" '1'

activation_event_kind=$(sed -n \
    's/^const ACTIVATION_EVENT_KIND: &str = "\([^"]*\)";$/\1/p' \
    "$repo_root/src/registry_activation/cockroach.rs")
assert_exact "activation repository event kind" \
    "$activation_event_kind" 'registry.genesis.activated'

activation_schema_preflight=$(sed -n \
    '/^const REQUIRE_ACTIVATION_SCHEMA_SQL:/,/^     FROM _sqlx_migrations WHERE version BETWEEN 1 AND 9";$/p' \
    "$repo_root/src/registry_activation/cockroach.rs")
expected_activation_schema_preflight='const REQUIRE_ACTIVATION_SCHEMA_SQL: &str = "SELECT count(*) = 9 \
     AND COALESCE(bool_and(success), false) \
     FROM _sqlx_migrations WHERE version BETWEEN 1 AND 9";'
assert_exact "activation repository complete migration prefix" \
    "$activation_schema_preflight" "$expected_activation_schema_preflight"

deny_table_dml() {
    local user=$1
    local table=$2
    expect_denied "$user" "$table SELECT" \
        "SELECT count(*) FROM $table"
    expect_denied "$user" "$table INSERT" \
        "INSERT INTO $table (tenant_id) VALUES ('0198a849-f6ae-7d61-9800-000000000099')"
    expect_denied "$user" "$table UPDATE" \
        "UPDATE $table SET project = project WHERE false"
    expect_denied "$user" "$table DELETE" \
        "DELETE FROM $table WHERE false"
}

apply_successor_quarantine() {
    docker exec -i "$container" cockroach sql \
        --insecure --database fleet_recall \
        < "$repo_root/deploy/cockroach/successor-schema-quarantine-grants.sql"
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
server_build_tag=$(docker exec "$container" cockroach version --build-tag)
test "$server_build_tag" = "$expected_crdb_build_tag" \
    || fail "Docker server must be exact CockroachDB $expected_crdb_build_tag (found $server_build_tag)"

docker exec "$container" cockroach sql --insecure \
    --execute 'CREATE DATABASE fleet_recall' >/dev/null
for migration in \
    0003_control_event_ledger.sql \
    0004_genesis_registry_activation.sql \
    0005_control_ledger_invariants.sql \
    0006_control_bootstrap_explicit_acceptance_time.sql \
    0007_control_epoch_explicit_creation_time.sql \
    0008_control_head_explicit_advance_time.sql \
    0009_control_event_explicit_acceptance_time.sql \
    0010_registry_genesis_head_root_index.sql \
    0011_registry_genesis_activation_root_index.sql \
    0012_registry_transition_history.sql \
    0013_registry_genesis_bridge_consumption.sql \
    0014_registry_current_head_v2.sql
do
    docker exec -i "$container" cockroach sql --insecure --database fleet_recall \
        < "$repo_root/migrations/$migration" >/dev/null
done

# SQLx's bookkeeping table plus one stand-in legacy corpus table and sequence
# are sufficient to prove the activation role's preflight and legacy isolation
# without loading the much larger vector schema.
root_sql '
CREATE TABLE _sqlx_migrations (
    version INT8 PRIMARY KEY,
    success BOOL NOT NULL
);
INSERT INTO _sqlx_migrations
SELECT version, true FROM generate_series(1, 14) AS version;
CREATE TABLE memory_chunks (id INT8 PRIMARY KEY);
INSERT INTO memory_chunks VALUES (1);
CREATE SEQUENCE memory_claim_id_seq START 1 MINVALUE 1 MAXVALUE 9007199254740991;
CREATE USER fleet_registry_activation WITH CREATEROLE CREATEDB;
CREATE USER proof_database_owner;
CREATE USER proof_runtime;
CREATE USER proof_bootstrap;
CREATE USER proof_activation;
CREATE USER proof_public;
ALTER DATABASE fleet_recall OWNER TO proof_database_owner;
' >/dev/null

docker exec -i "$container" cockroach sql --insecure --database fleet_recall \
    < "$repo_root/deploy/cockroach/control-role-grants.sql" >/dev/null
docker exec -i "$container" cockroach sql --insecure --database fleet_recall \
    < "$repo_root/deploy/cockroach/registry-activation-role-grants.sql" >/dev/null

# A later success cannot mask failed migration 12 at the dedicated post-14
# quarantine boundary. Restore it only after the policy fails closed.
root_sql 'UPDATE _sqlx_migrations SET success = false WHERE version = 12' >/dev/null
if quarantine_failure=$(apply_successor_quarantine 2>&1); then
    fail "successor quarantine accepted a failed migration 12"
fi
grep -Fq 'requires the complete successful migration prefix through 14' \
    <<<"$quarantine_failure" \
    || fail "successor quarantine did not retain its exact-prefix failure"
root_sql 'UPDATE _sqlx_migrations SET success = true WHERE version = 12' >/dev/null
apply_successor_quarantine >/dev/null

# Owning the database does not authorize cluster role/options, membership, or
# SYSTEM cleanup. The full policy must run under the stronger security operator
# described in its header.
expect_denied proof_database_owner "database owner role-option hardening" \
    'ALTER ROLE fleet_registry_activation WITH NOLOGIN NOCREATEROLE NOCREATEDB'
expect_denied proof_database_owner "database owner admin-membership cleanup" \
    'REVOKE admin FROM fleet_registry_activation'
expect_denied proof_database_owner "database owner system-grant cleanup" \
    'REVOKE SYSTEM ALL FROM fleet_registry_activation'

# Prove reapplication normalizes a drifted login-capable role, removes its
# inherited roles/direct privileges, and reasserts PUBLIC isolation across the
# dedicated database's current tables and sequences.
root_sql '
ALTER ROLE fleet_registry_activation WITH LOGIN CREATEROLE CREATEDB;
GRANT admin, fleet_runtime, fleet_control_bootstrap
    TO fleet_registry_activation;
GRANT SYSTEM CREATEROLE TO fleet_registry_activation;
GRANT CREATE ON DATABASE fleet_recall TO fleet_registry_activation;
GRANT CREATE ON SCHEMA public TO fleet_registry_activation;
GRANT UPDATE ON TABLE _sqlx_migrations TO fleet_registry_activation;
GRANT INSERT ON TABLE memory_control_bootstraps TO fleet_registry_activation;
GRANT DELETE ON TABLE memory_registry_activations TO fleet_registry_activation;
GRANT SELECT ON TABLE memory_chunks TO fleet_registry_activation;
GRANT ALL ON SEQUENCE memory_claim_id_seq TO fleet_registry_activation;
GRANT ALL ON DATABASE fleet_recall TO public;
GRANT ALL ON SCHEMA public TO public;
GRANT SELECT ON TABLE memory_chunks TO public;
GRANT ALL ON SEQUENCE memory_claim_id_seq TO public;
GRANT SELECT ON TABLE memory_registry_heads
    TO public, fleet_runtime, fleet_control_bootstrap;
GRANT ALL ON TABLE
    memory_registry_transitions,
    memory_registry_genesis_bridge_consumptions,
    memory_registry_current_heads_v2
TO public;
GRANT ALL ON TABLE
    memory_registry_transitions,
    memory_registry_genesis_bridge_consumptions,
    memory_registry_current_heads_v2
TO
    fleet_runtime,
    fleet_control_bootstrap,
    fleet_registry_activation
WITH GRANT OPTION;
' >/dev/null
docker exec -i "$container" cockroach sql --insecure --database fleet_recall \
    < "$repo_root/deploy/cockroach/registry-activation-role-grants.sql" >/dev/null
apply_successor_quarantine >/dev/null
apply_successor_quarantine >/dev/null

# The reverse membership direction is a separate acyclic drift case: older
# application roles must not inherit the activation role's private surface.
root_sql '
GRANT fleet_registry_activation
    TO fleet_runtime, fleet_control_bootstrap;
' >/dev/null
docker exec -i "$container" cockroach sql --insecure --database fleet_recall \
    < "$repo_root/deploy/cockroach/registry-activation-role-grants.sql" >/dev/null

root_sql '
GRANT fleet_runtime TO proof_runtime;
GRANT fleet_control_bootstrap TO proof_bootstrap;
GRANT fleet_registry_activation TO proof_activation;
' >/dev/null

control_grants=$(root_sql "
SELECT table_name || ':' || grantee || ':' || privilege_type || ':' ||
       CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END AS normalized
FROM [SHOW GRANTS ON TABLE
    memory_control_bootstraps,
    memory_control_log_epochs,
    memory_control_shard_heads,
    memory_control_events]
WHERE grantee IN (
    'public',
    'fleet_runtime',
    'fleet_control_bootstrap',
    'fleet_registry_activation'
)
ORDER BY table_name, grantee, privilege_type" | tail -n +2)
expected_control_grants='memory_control_bootstraps:fleet_control_bootstrap:INSERT:not_grantable
memory_control_bootstraps:fleet_control_bootstrap:SELECT:not_grantable
memory_control_bootstraps:fleet_registry_activation:SELECT:not_grantable
memory_control_events:fleet_control_bootstrap:INSERT:not_grantable
memory_control_events:fleet_control_bootstrap:SELECT:not_grantable
memory_control_events:fleet_registry_activation:INSERT:not_grantable
memory_control_events:fleet_registry_activation:SELECT:not_grantable
memory_control_log_epochs:fleet_control_bootstrap:INSERT:not_grantable
memory_control_log_epochs:fleet_control_bootstrap:SELECT:not_grantable
memory_control_log_epochs:fleet_registry_activation:SELECT:not_grantable
memory_control_shard_heads:fleet_control_bootstrap:INSERT:not_grantable
memory_control_shard_heads:fleet_control_bootstrap:SELECT:not_grantable
memory_control_shard_heads:fleet_control_bootstrap:UPDATE:not_grantable
memory_control_shard_heads:fleet_registry_activation:SELECT:not_grantable
memory_control_shard_heads:fleet_registry_activation:UPDATE:not_grantable'
assert_exact "control-table grants" "$control_grants" "$expected_control_grants"

registry_grants=$(root_sql "
SELECT table_name || ':' || grantee || ':' || privilege_type || ':' ||
       CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END AS normalized
FROM [SHOW GRANTS ON TABLE memory_registry_activations, memory_registry_heads]
WHERE grantee IN (
    'public',
    'fleet_runtime',
    'fleet_control_bootstrap',
    'fleet_registry_activation'
)
ORDER BY table_name, grantee, privilege_type" | tail -n +2)
expected_registry_grants='memory_registry_activations:fleet_registry_activation:INSERT:not_grantable
memory_registry_activations:fleet_registry_activation:SELECT:not_grantable
memory_registry_heads:fleet_registry_activation:INSERT:not_grantable
memory_registry_heads:fleet_registry_activation:SELECT:not_grantable'
assert_exact "registry-table grants" "$registry_grants" "$expected_registry_grants"

successor_grants=$(root_sql "
SELECT table_name || ':' || grantee || ':' || privilege_type || ':' ||
       CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END AS normalized
FROM [SHOW GRANTS ON TABLE
    memory_registry_transitions,
    memory_registry_genesis_bridge_consumptions,
    memory_registry_current_heads_v2]
WHERE grantee IN (
    'public',
    'fleet_runtime',
    'fleet_control_bootstrap',
    'fleet_registry_activation'
)
ORDER BY table_name, grantee, privilege_type" | tail -n +2)
assert_exact "successor-table quarantine grants" "$successor_grants" ''

migration_grants=$(root_sql "
SELECT table_name || ':' || grantee || ':' || privilege_type || ':' ||
       CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END AS normalized
FROM [SHOW GRANTS ON TABLE _sqlx_migrations]
WHERE grantee IN (
    'public',
    'fleet_runtime',
    'fleet_control_bootstrap',
    'fleet_registry_activation'
)
ORDER BY grantee, privilege_type" | tail -n +2)
expected_migration_grants='_sqlx_migrations:fleet_control_bootstrap:SELECT:not_grantable
_sqlx_migrations:fleet_registry_activation:SELECT:not_grantable
_sqlx_migrations:fleet_runtime:SELECT:not_grantable'
assert_exact "migration-table grants" "$migration_grants" "$expected_migration_grants"

activation_current_object_grants=$(root_sql "
SELECT object_type || ':' || object_name || ':' || privilege_type || ':' ||
       CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END AS normalized
FROM [SHOW GRANTS FOR fleet_registry_activation]
WHERE database_name = 'fleet_recall'
  AND schema_name = 'public'
  AND object_type IN ('table', 'sequence')
ORDER BY object_type, object_name, privilege_type" | tail -n +2)
expected_activation_current_object_grants='table:_sqlx_migrations:SELECT:not_grantable
table:memory_control_bootstraps:SELECT:not_grantable
table:memory_control_events:INSERT:not_grantable
table:memory_control_events:SELECT:not_grantable
table:memory_control_log_epochs:SELECT:not_grantable
table:memory_control_shard_heads:SELECT:not_grantable
table:memory_control_shard_heads:UPDATE:not_grantable
table:memory_registry_activations:INSERT:not_grantable
table:memory_registry_activations:SELECT:not_grantable
table:memory_registry_heads:INSERT:not_grantable
table:memory_registry_heads:SELECT:not_grantable'
assert_exact "activation full current table/sequence grants" \
    "$activation_current_object_grants" "$expected_activation_current_object_grants"

database_grants=$(root_sql "
SELECT database_name || ':' || grantee || ':' || privilege_type || ':' ||
       CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END AS normalized
FROM [SHOW GRANTS ON DATABASE fleet_recall]
WHERE grantee IN (
    'public',
    'fleet_runtime',
    'fleet_control_bootstrap',
    'fleet_registry_activation'
)
ORDER BY grantee, privilege_type" | tail -n +2)
expected_database_grants='fleet_recall:fleet_control_bootstrap:CONNECT:not_grantable
fleet_recall:fleet_registry_activation:CONNECT:not_grantable
fleet_recall:fleet_runtime:CONNECT:not_grantable'
assert_exact "database grants" "$database_grants" "$expected_database_grants"

schema_grants=$(root_sql "
SELECT schema_name || ':' || grantee || ':' || privilege_type || ':' ||
       CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END AS normalized
FROM [SHOW GRANTS ON SCHEMA public]
WHERE grantee IN (
    'public',
    'fleet_runtime',
    'fleet_control_bootstrap',
    'fleet_registry_activation'
)
ORDER BY grantee, privilege_type" | tail -n +2)
expected_schema_grants='public:fleet_control_bootstrap:USAGE:not_grantable
public:fleet_registry_activation:USAGE:not_grantable
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
WHERE grantee IN (
    'fleet_runtime',
    'fleet_control_bootstrap',
    'fleet_registry_activation'
)
ORDER BY grantee, privilege_type" | tail -n +2)
assert_exact "application-role system grants" "$system_grants" ''

application_role_options=$(root_sql "
SELECT username || ':' || options::STRING AS normalized
FROM [SHOW USERS]
WHERE username IN (
    'fleet_runtime',
    'fleet_control_bootstrap',
    'fleet_registry_activation'
)
ORDER BY username" | tail -n +2)
expected_application_role_options='fleet_control_bootstrap:{NOLOGIN}
fleet_registry_activation:{NOLOGIN}
fleet_runtime:{NOLOGIN}'
assert_exact "application role options" \
    "$application_role_options" "$expected_application_role_options"

application_role_edges=$(root_sql "
SELECT role_name || ':' || member || ':' ||
       CASE WHEN is_admin THEN 'admin_option' ELSE 'no_admin_option' END AS normalized
FROM [SHOW GRANTS ON ROLE]
WHERE member IN (
    'fleet_runtime',
    'fleet_control_bootstrap',
    'fleet_registry_activation',
    'proof_runtime',
    'proof_bootstrap',
    'proof_activation'
)
   OR role_name IN (
       'fleet_runtime',
       'fleet_control_bootstrap',
       'fleet_registry_activation'
   )
ORDER BY role_name, member" | tail -n +2)
expected_application_role_edges='fleet_control_bootstrap:proof_bootstrap:no_admin_option
fleet_registry_activation:proof_activation:no_admin_option
fleet_runtime:proof_runtime:no_admin_option'
assert_exact "application role membership edges" \
    "$application_role_edges" "$expected_application_role_edges"

# Current-object policies create no future-object defaults. Freeze the schema
# creator's table/sequence defaults; deployment repeats this audit while
# authenticated as the actual migrator identity.
default_privileges=$(root_sql "
SELECT COALESCE(role, 'ALL') || ':' || object_type || ':' || grantee || ':' ||
       privilege_type || ':' ||
       CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END AS normalized
FROM [SHOW DEFAULT PRIVILEGES]
WHERE object_type IN ('tables', 'sequences')
  AND grantee IN (
      'public',
      'fleet_runtime',
      'fleet_control_bootstrap',
      'fleet_registry_activation'
  )
ORDER BY role, object_type, grantee, privilege_type" | tail -n +2)
assert_exact "schema-creator table/sequence default privileges" \
    "$default_privileges" ''

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

# Seed exact Stage-2 anchors as the owner. A second bootstrap without an epoch
# makes the denied epoch INSERT structurally valid; the two-shard base epoch
# makes the denied head INSERT structurally valid as well.
root_sql "
INSERT INTO memory_control_bootstraps (
    tenant_id, project, contract_tenant_namespace, contract_project_namespace,
    receipt_digest, statement_id, bootstrap_event_id, profile_id, profile_digest,
    vector_manifest_digest, genesis_registry_package_digest, signer_policy_digest,
    signer_count, approval_threshold, epoch_id, shard_count, bootstrap_shard,
    bootstrap_offset, canonical_receipt, canonical_genesis_package, accepted_at
) VALUES
(
    '0198a849-f6ae-7d61-9800-000000000001', 'grant-proof',
    'tenant.proof', 'project.proof',
    decode(repeat('11', 32), 'hex'), decode(repeat('22', 32), 'hex'),
    decode(repeat('33', 32), 'hex'), 'ostk-canonical-json-v1',
    decode(repeat('44', 32), 'hex'), decode(repeat('55', 32), 'hex'),
    decode(repeat('66', 32), 'hex'), decode(repeat('77', 32), 'hex'),
    3, 2, decode(repeat('88', 32), 'hex'), 2, 0, 1,
    decode('7b7d', 'hex'), decode('7b7d', 'hex'),
    '2026-08-15 12:00:00+00'
),
(
    '0198a849-f6ae-7d61-9800-000000000002', 'epoch-deny-proof',
    'tenant.epoch-deny', 'project.epoch-deny',
    decode(repeat('12', 32), 'hex'), decode(repeat('23', 32), 'hex'),
    decode(repeat('34', 32), 'hex'), 'ostk-canonical-json-v1',
    decode(repeat('45', 32), 'hex'), decode(repeat('56', 32), 'hex'),
    decode(repeat('67', 32), 'hex'), decode(repeat('78', 32), 'hex'),
    3, 2, decode(repeat('89', 32), 'hex'), 1, 0, 1,
    decode('7b7d', 'hex'), decode('7b7d', 'hex'),
    '2026-08-15 12:00:00+00'
);

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
);

INSERT INTO memory_control_shard_heads (
    tenant_id, project, epoch_id, shard, shard_count, last_committed_offset,
    chain_digest, advanced_at
) VALUES (
    '0198a849-f6ae-7d61-9800-000000000001', 'grant-proof',
    decode(repeat('88', 32), 'hex'), 0, 2, 1,
    decode(repeat('aa', 32), 'hex'), '2026-08-15 12:00:01+00'
);
" >/dev/null

for failed_version in 4 5 9; do
    root_sql "UPDATE _sqlx_migrations SET success = false WHERE version = $failed_version" \
        >/dev/null
    expect_scalar proof_activation \
        "failed migration-$failed_version is not masked by other successes" \
        'SELECT CASE WHEN (
             SELECT count(*) = 9 AND COALESCE(bool_and(success), false)
             FROM _sqlx_migrations WHERE version BETWEEN 1 AND 9
         ) THEN '\''ready'\'' ELSE '\''not_ready'\'' END' \
        'not_ready'
    root_sql "UPDATE _sqlx_migrations SET success = true WHERE version = $failed_version" \
        >/dev/null
done
expect_scalar proof_activation "complete successful migration prefix 1 through 9" \
    'SELECT CASE WHEN (
         SELECT count(*) = 9 AND COALESCE(bool_and(success), false)
         FROM _sqlx_migrations WHERE version BETWEEN 1 AND 9
     ) THEN '\''ready'\'' ELSE '\''not_ready'\'' END' \
    'ready'
expect_allowed proof_activation "migration-prefix preflight plan" \
    'EXPLAIN SELECT count(*) = 9 AND COALESCE(bool_and(success), false)
     FROM _sqlx_migrations WHERE version BETWEEN 1 AND 9'
expect_denied proof_activation "migration-history insert" \
    'INSERT INTO _sqlx_migrations VALUES (9999, true)'
expect_denied proof_activation "migration-history update" \
    'UPDATE _sqlx_migrations SET success = false WHERE version = 9'
expect_denied proof_activation "migration-history delete" \
    'DELETE FROM _sqlx_migrations WHERE version = 9'

expect_allowed proof_activation "bootstrap anchor read" \
    'SELECT count(*) FROM memory_control_bootstraps'
expect_allowed proof_activation "epoch anchor read" \
    'SELECT count(*) FROM memory_control_log_epochs'
expect_allowed proof_activation "shard-head read" \
    'SELECT count(*) FROM memory_control_shard_heads'
expect_allowed proof_activation "control-event read" \
    'SELECT count(*) FROM memory_control_events'

expect_denied proof_activation "bootstrap insert" "
INSERT INTO memory_control_bootstraps (
    tenant_id, project, contract_tenant_namespace, contract_project_namespace,
    receipt_digest, statement_id, bootstrap_event_id, profile_id, profile_digest,
    vector_manifest_digest, genesis_registry_package_digest, signer_policy_digest,
    signer_count, approval_threshold, epoch_id, shard_count, bootstrap_shard,
    bootstrap_offset, canonical_receipt, canonical_genesis_package, accepted_at
) VALUES (
    '0198a849-f6ae-7d61-9800-000000000003', 'bootstrap-deny-proof',
    'tenant.bootstrap-deny', 'project.bootstrap-deny',
    decode(repeat('13', 32), 'hex'), decode(repeat('24', 32), 'hex'),
    decode(repeat('35', 32), 'hex'), 'ostk-canonical-json-v1',
    decode(repeat('46', 32), 'hex'), decode(repeat('57', 32), 'hex'),
    decode(repeat('68', 32), 'hex'), decode(repeat('79', 32), 'hex'),
    3, 2, decode(repeat('8a', 32), 'hex'), 1, 0, 1,
    decode('7b7d', 'hex'), decode('7b7d', 'hex'),
    '2026-08-15 12:00:00+00'
)"
expect_denied proof_activation "epoch insert" "
INSERT INTO memory_control_log_epochs (
    tenant_id, project, epoch_id, bootstrap_receipt_digest, canonical_epoch,
    partition_recipe_id, partition_recipe_version, partition_algorithm,
    partition_seed, shard_count, created_at
) VALUES (
    '0198a849-f6ae-7d61-9800-000000000002', 'epoch-deny-proof',
    decode(repeat('89', 32), 'hex'), decode(repeat('12', 32), 'hex'),
    decode('7b7d', 'hex'), 'ostk.partition.sha256_prefix64_modulo', 1,
    'sha256_prefix64_modulo', decode(repeat('9a', 32), 'hex'), 1,
    '2026-08-15 12:00:00+00'
)"
expect_denied proof_activation "shard-head insert" "
INSERT INTO memory_control_shard_heads (
    tenant_id, project, epoch_id, shard, shard_count, last_committed_offset,
    chain_digest, advanced_at
) VALUES (
    '0198a849-f6ae-7d61-9800-000000000001', 'grant-proof',
    decode(repeat('88', 32), 'hex'), 1, 2, 0, decode(repeat('a1', 32), 'hex'),
    '2026-08-15 12:00:00+00'
)"

expect_allowed proof_activation "accepted control-event insert" "
INSERT INTO memory_control_events (
    tenant_id, project, epoch_id, shard, committed_offset, event_id,
    event_schema_version, event_kind, semantic_object_digest, consistency_family,
    consistency_key_digest, canonical_event, previous_chain_digest, chain_digest,
    accepted_at
) VALUES (
    '0198a849-f6ae-7d61-9800-000000000001', 'grant-proof',
    decode(repeat('88', 32), 'hex'), 0, 2, decode(repeat('bb', 32), 'hex'),
    1, 'registry.genesis.activated', decode(repeat('cc', 32), 'hex'),
    'registry.activation', decode(repeat('cd', 32), 'hex'),
    decode('7b7d', 'hex'), decode(repeat('aa', 32), 'hex'),
    decode(repeat('dd', 32), 'hex'), '2026-08-15 12:00:02+00'
)"
expect_constraint proof_activation "duplicate predecessor insert" \
    memory_control_events_predecessor_unique_idx "
INSERT INTO memory_control_events (
    tenant_id, project, epoch_id, shard, committed_offset, event_id,
    event_schema_version, event_kind, semantic_object_digest, consistency_family,
    consistency_key_digest, canonical_event, previous_chain_digest, chain_digest,
    accepted_at
) VALUES (
    '0198a849-f6ae-7d61-9800-000000000001', 'grant-proof',
    decode(repeat('88', 32), 'hex'), 0, 3, decode(repeat('bc', 32), 'hex'),
    1, 'test.detached', decode(repeat('ce', 32), 'hex'),
    'test.detached', decode(repeat('cf', 32), 'hex'),
    decode('7b7d', 'hex'), decode(repeat('aa', 32), 'hex'),
    decode(repeat('de', 32), 'hex'), '2026-08-15 12:00:03+00'
)"
expect_allowed proof_activation "shard-head compare-and-swap" "
UPDATE memory_control_shard_heads
SET last_committed_offset = 2,
    chain_digest = decode(repeat('dd', 32), 'hex'),
    advanced_at = '2026-08-15 12:00:02+00'
WHERE tenant_id = '0198a849-f6ae-7d61-9800-000000000001'
  AND project = 'grant-proof'
  AND epoch_id = decode(repeat('88', 32), 'hex')
  AND shard = 0
  AND last_committed_offset = 1
  AND chain_digest = decode(repeat('aa', 32), 'hex')"

expect_allowed proof_activation "registry activation insert" "
INSERT INTO memory_registry_activations (
    tenant_id, project, activation_id, statement_id,
    bootstrap_statement_id, bootstrap_receipt_digest, bootstrap_event_id,
    genesis_epoch_id, genesis_package_digest, bootstrap_signer_policy_digest,
    profile_id, profile_digest, vector_manifest_digest,
    contract_tenant_namespace, contract_project_namespace,
    activated_package_digest, activated_policy_digest, test_result_digest,
    proposer_principal_id, package_author_principal_id, approval_ids_packed,
    approval_count, required_threshold, separation_of_duty_satisfied,
    bootstrap_accepted_at, effective_from, effective_until, accepted_at,
    accepted_event_id, control_epoch_id, control_shard,
    control_committed_offset, canonical_statement, canonical_approval_set,
    canonical_test_result, canonical_receipt, canonical_event
) VALUES (
    '0198a849-f6ae-7d61-9800-000000000001', 'grant-proof',
    decode(repeat('cc', 32), 'hex'), decode(repeat('ee', 32), 'hex'),
    decode(repeat('22', 32), 'hex'), decode(repeat('11', 32), 'hex'),
    decode(repeat('33', 32), 'hex'), decode(repeat('88', 32), 'hex'),
    decode(repeat('66', 32), 'hex'), decode(repeat('77', 32), 'hex'),
    'ostk-canonical-json-v1', decode(repeat('44', 32), 'hex'),
    decode(repeat('55', 32), 'hex'), 'tenant.proof', 'project.proof',
    decode(repeat('66', 32), 'hex'), decode(repeat('ab', 32), 'hex'),
    decode(repeat('ad', 32), 'hex'), 'principal.proposer', 'principal.author',
    decode(repeat('ae', 32), 'hex'), 1, 1, true,
    '2026-08-15 12:00:00+00', '2026-08-15 12:00:01+00', NULL,
    '2026-08-15 12:00:02+00', decode(repeat('bb', 32), 'hex'),
    decode(repeat('88', 32), 'hex'), 0, 2,
    decode('7b7d', 'hex'), decode('7b7d', 'hex'), decode('7b7d', 'hex'),
    decode('7b7d', 'hex'), decode('7b7d', 'hex')
)"
expect_allowed proof_activation "registry head insert" "
INSERT INTO memory_registry_heads (
    tenant_id, project, head_state, activation_id, package_digest,
    activation_policy_digest, source_event_id, source_epoch_id, source_shard,
    source_committed_offset, activated_at, canonical_head
) VALUES (
    '0198a849-f6ae-7d61-9800-000000000001', 'grant-proof', 'active',
    decode(repeat('cc', 32), 'hex'), decode(repeat('66', 32), 'hex'),
    decode(repeat('ab', 32), 'hex'), decode(repeat('bb', 32), 'hex'),
    decode(repeat('88', 32), 'hex'), 0, 2, '2026-08-15 12:00:02+00',
    decode('7b7d', 'hex')
)"
expect_allowed proof_activation "registry activation read" \
    'SELECT count(*) FROM memory_registry_activations'
expect_allowed proof_activation "registry head read" \
    'SELECT count(*) FROM memory_registry_heads'

# Every non-head control table is immutable. Shard heads may update but cannot
# be inserted by activation or deleted. Nonmatching predicates ensure an
# accidentally granted privilege would still make the statement succeed.
expect_denied proof_activation "immutable bootstrap update" \
    'UPDATE memory_control_bootstraps SET canonical_receipt = canonical_receipt WHERE false'
expect_denied proof_activation "immutable bootstrap delete" \
    'DELETE FROM memory_control_bootstraps WHERE false'
expect_denied proof_activation "immutable epoch update" \
    'UPDATE memory_control_log_epochs SET canonical_epoch = canonical_epoch WHERE false'
expect_denied proof_activation "immutable epoch delete" \
    'DELETE FROM memory_control_log_epochs WHERE false'
expect_denied proof_activation "immutable control-event update" \
    'UPDATE memory_control_events SET event_kind = event_kind WHERE false'
expect_denied proof_activation "immutable control-event delete" \
    'DELETE FROM memory_control_events WHERE false'
expect_denied proof_activation "shard-head delete" \
    'DELETE FROM memory_control_shard_heads WHERE false'
expect_denied proof_activation "immutable registry activation update" \
    'UPDATE memory_registry_activations SET project = project WHERE false'
expect_denied proof_activation "immutable registry activation delete" \
    'DELETE FROM memory_registry_activations WHERE false'
expect_denied proof_activation "immutable registry head update" \
    'UPDATE memory_registry_heads SET project = project WHERE false'
expect_denied proof_activation "immutable registry head delete" \
    'DELETE FROM memory_registry_heads WHERE false'

expect_denied proof_activation "legacy corpus read" \
    'SELECT count(*) FROM memory_chunks'
expect_denied proof_activation "legacy corpus insert" \
    'INSERT INTO memory_chunks VALUES (2)'
expect_denied proof_activation "legacy corpus update" \
    'UPDATE memory_chunks SET id = id WHERE false'
expect_denied proof_activation "legacy corpus delete" \
    'DELETE FROM memory_chunks WHERE false'
expect_denied proof_activation "legacy sequence use" \
    "SELECT nextval('memory_claim_id_seq')"
expect_denied proof_activation "schema creation" \
    'CREATE TABLE registry_activation_escape (id INT8 PRIMARY KEY)'
expect_denied proof_activation "database creation" \
    'CREATE DATABASE registry_activation_escape'
expect_denied proof_activation "role creation" \
    'CREATE ROLE registry_activation_escape'
expect_denied proof_activation "grant delegation" \
    'GRANT SELECT ON TABLE memory_registry_activations TO proof_public'
expect_denied proof_activation "role-membership delegation" \
    'GRANT fleet_registry_activation TO proof_public'

# Runtime, bootstrap, and an otherwise unprivileged login have no effective
# DML path to either Stage-3 table.
for user in proof_runtime proof_bootstrap proof_public; do
    deny_table_dml "$user" memory_registry_activations
    deny_table_dml "$user" memory_registry_heads
done

# New successor storage stays quarantined from every pre-successor principal,
# including the genesis-only activation role.
for user in proof_runtime proof_bootstrap proof_activation proof_public; do
    deny_table_dml "$user" memory_registry_transitions
    deny_table_dml "$user" memory_registry_genesis_bridge_consumptions
    deny_table_dml "$user" memory_registry_current_heads_v2
done

echo "verified effective registry-activation grants:"
root_sql "SHOW GRANTS ON TABLE
    memory_control_bootstraps,
    memory_control_log_epochs,
    memory_control_shard_heads,
    memory_control_events,
    memory_registry_activations,
    memory_registry_heads,
    memory_registry_transitions,
    memory_registry_genesis_bridge_consumptions,
    memory_registry_current_heads_v2
    FOR fleet_registry_activation"
echo "secondary Docker registry-activation grant parity proof passed"
