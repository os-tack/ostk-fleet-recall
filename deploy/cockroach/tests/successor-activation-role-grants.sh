#!/usr/bin/env bash
set -euo pipefail

# Secondary Docker parity only: this preserves the image-level successor
# activation RBAC proof, but cannot substitute for the checksum-pinned official-
# binary correctness lane. Policy applications run as root, matching the
# cluster-admin-only operator contract.
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$script_dir/../../.." && pwd)
image=${FLEET_RECALL_CRDB_IMAGE:-cockroachdb/cockroach:v26.2.3}
expected_crdb_build_tag=v26.2.3
container="ostk-successor-activation-grants-$$"

cleanup() {
    docker rm --force "$container" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

fail() {
    echo "successor-activation grant proof failed: $*" >&2
    exit 1
}

root_sql() {
    docker exec "$container" cockroach sql \
        --insecure \
        --database fleet_recall \
        --format tsv \
        --execute "$1"
}

root_sql_in_database() {
    local database=$1
    local statement=$2
    docker exec "$container" cockroach sql \
        --insecure \
        --database "$database" \
        --format tsv \
        --execute "$statement"
}

# The SQL policy is intentionally database-local. This read-only deployment
# preflight enumerates every other database for direct target grants and
# ownership that an admin must clean before applying or using the role.
audit_other_database_target_authority() {
    local databases
    local database
    local grant_rows
    local ownership_rows
    local row
    if ! databases=$(root_sql \
        'SELECT database_name FROM [SHOW DATABASES] ORDER BY database_name' \
        | tail -n +2); then
        fail "external target audit could not enumerate databases"
    fi
    while IFS= read -r database; do
        test -n "$database" || continue
        test "$database" != 'fleet_recall' || continue
        if ! grant_rows=$(root_sql_in_database "$database" "
            SELECT 'grant:' || object_type || ':' ||
                   COALESCE(schema_name, '') || ':' ||
                   COALESCE(object_name, '') || ':' || privilege_type || ':' ||
                   CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END
            FROM [SHOW GRANTS FOR fleet_registry_successor_activation]
            WHERE grantee = 'fleet_registry_successor_activation'
              AND database_name = pg_catalog.current_database()
            ORDER BY object_type, schema_name, object_name, privilege_type
        " | tail -n +2); then
            fail "external target audit could not inspect grants in $database"
        fi
        while IFS= read -r row; do
            test -n "$row" || continue
            printf '%s:%s\n' "$database" "$row"
        done <<<"$grant_rows"
        if ! ownership_rows=$(root_sql_in_database "$database" "
            SELECT object_kind || ':' || schema_name || ':' || object_name
            FROM (
                SELECT 'database_owner' AS object_kind,
                       '' AS schema_name,
                       database_object.datname AS object_name
                FROM pg_catalog.pg_database AS database_object
                JOIN pg_catalog.pg_roles AS owner_role
                  ON owner_role.oid = database_object.datdba
                WHERE database_object.datname = pg_catalog.current_database()
                  AND owner_role.rolname = 'fleet_registry_successor_activation'
                UNION ALL
                SELECT 'schema_owner', schema_object.nspname, ''
                FROM pg_catalog.pg_namespace AS schema_object
                JOIN pg_catalog.pg_roles AS owner_role
                  ON owner_role.oid = schema_object.nspowner
                WHERE owner_role.rolname = 'fleet_registry_successor_activation'
                UNION ALL
                SELECT 'relation_owner', relation_schema.nspname,
                       relation_object.relname
                FROM pg_catalog.pg_class AS relation_object
                JOIN pg_catalog.pg_namespace AS relation_schema
                  ON relation_schema.oid = relation_object.relnamespace
                JOIN pg_catalog.pg_roles AS owner_role
                  ON owner_role.oid = relation_object.relowner
                WHERE relation_object.relkind IN ('r', 'S', 'v', 'm', 'p')
                  AND owner_role.rolname = 'fleet_registry_successor_activation'
                UNION ALL
                SELECT 'function_owner', function_schema.nspname,
                       function_object.proname
                FROM pg_catalog.pg_proc AS function_object
                JOIN pg_catalog.pg_namespace AS function_schema
                  ON function_schema.oid = function_object.pronamespace
                JOIN pg_catalog.pg_roles AS owner_role
                  ON owner_role.oid = function_object.proowner
                WHERE owner_role.rolname = 'fleet_registry_successor_activation'
                UNION ALL
                SELECT 'type_owner', type_schema.nspname, type_object.typname
                FROM pg_catalog.pg_type AS type_object
                JOIN pg_catalog.pg_namespace AS type_schema
                  ON type_schema.oid = type_object.typnamespace
                JOIN pg_catalog.pg_roles AS owner_role
                  ON owner_role.oid = type_object.typowner
                WHERE owner_role.rolname = 'fleet_registry_successor_activation'
            ) AS owned_object
            ORDER BY object_kind, schema_name, object_name
        " | tail -n +2); then
            fail "external target audit could not inspect ownership in $database"
        fi
        while IFS= read -r row; do
            test -n "$row" || continue
            printf '%s:%s\n' "$database" "$row"
        done <<<"$ownership_rows"
    done <<<"$databases"
}

# PUBLIC is inherited by every role. Ignore ordinary cross-database
# CONNECT/TEMPORARY/schema-USAGE and exact virtual/system fallbacks, but expose
# application-object or DDL authority that needs an explicit cluster-wide pass.
inventory_other_database_public_application_authority() {
    local databases
    local database
    local public_rows
    local row
    if ! databases=$(root_sql \
        'SELECT database_name FROM [SHOW DATABASES] ORDER BY database_name' \
        | tail -n +2); then
        fail "external PUBLIC inventory could not enumerate databases"
    fi
    while IFS= read -r database; do
        test -n "$database" || continue
        test "$database" != 'fleet_recall' || continue
        if ! public_rows=$(root_sql_in_database "$database" "
            SELECT object_type || ':' || COALESCE(schema_name, '') || ':' ||
                   COALESCE(object_name, '') || ':' || privilege_type || ':' ||
                   CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END
            FROM [SHOW GRANTS FOR public]
            WHERE grantee = 'public'
              AND database_name = pg_catalog.current_database()
              AND NOT (
                  (object_type = 'database'
                      AND privilege_type IN ('CONNECT', 'TEMPORARY')
                      AND NOT is_grantable)
                  OR (object_type = 'schema'
                      AND schema_name = 'public'
                      AND object_name IS NULL
                      AND privilege_type = 'USAGE'
                      AND NOT is_grantable)
                  OR (
                      schema_name IN (
                          'crdb_internal', 'information_schema',
                          'pg_catalog', 'pg_extension'
                      )
                      AND NOT is_grantable
                      AND (
                          (object_type = 'schema'
                              AND object_name IS NULL
                              AND privilege_type = 'USAGE')
                          OR (object_type = 'table'
                              AND object_name IS NOT NULL
                              AND privilege_type = 'SELECT')
                          OR (object_type = 'type'
                              AND schema_name = 'pg_catalog'
                              AND object_name IS NOT NULL
                              AND privilege_type = 'USAGE')
                      )
                  )
                  OR (
                      pg_catalog.current_database() = 'system'
                      AND NOT is_grantable
                      AND (
                          (object_type = 'schema'
                              AND schema_name = 'public'
                              AND object_name IS NULL
                              AND privilege_type = 'CREATE')
                          OR (object_type = 'table'
                              AND schema_name = 'public'
                              AND object_name = 'comments'
                              AND privilege_type = 'SELECT')
                      )
                  )
              )
            ORDER BY object_type, schema_name, object_name, privilege_type
        " | tail -n +2); then
            fail "external PUBLIC inventory could not inspect $database"
        fi
        while IFS= read -r row; do
            test -n "$row" || continue
            printf '%s:%s\n' "$database" "$row"
        done <<<"$public_rows"
    done <<<"$databases"
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

apply_successor_policy() {
    docker exec -i "$container" cockroach sql \
        --insecure --database fleet_recall \
        < "$repo_root/deploy/cockroach/successor-activation-role-grants.sql"
}

apply_successor_policy_in_database() {
    local database=$1
    docker exec -i "$container" cockroach sql \
        --insecure --database "$database" \
        < "$repo_root/deploy/cockroach/successor-activation-role-grants.sql"
}

apply_successor_policy_with_valid_temp_prefix() {
    {
        printf '%s\n' '
SET experimental_enable_temp_tables = on;
CREATE TEMP TABLE _sqlx_migrations (
    version INT8 PRIMARY KEY,
    success BOOL NOT NULL
);
INSERT INTO _sqlx_migrations
SELECT version, true FROM generate_series(1, 14) AS version;
'
        sed -n '1,$p' \
            "$repo_root/deploy/cockroach/successor-activation-role-grants.sql"
    } | docker exec -i "$container" cockroach sql \
        --insecure --database fleet_recall
}

apply_successor_policy_with_temp_shadows() {
    {
        printf '%s\n' '
SET experimental_enable_temp_tables = on;
CREATE TEMP TABLE _sqlx_migrations (
    version INT8 PRIMARY KEY,
    success BOOL NOT NULL
);
INSERT INTO _sqlx_migrations VALUES (1, false);
CREATE TEMP TABLE memory_control_bootstraps (id INT8 PRIMARY KEY);
CREATE TEMP TABLE memory_control_events (id INT8 PRIMARY KEY);
CREATE TEMP TABLE memory_control_log_epochs (id INT8 PRIMARY KEY);
CREATE TEMP TABLE memory_control_shard_heads (id INT8 PRIMARY KEY);
CREATE TEMP TABLE memory_registry_activations (id INT8 PRIMARY KEY);
CREATE TEMP TABLE memory_registry_current_heads_v2 (id INT8 PRIMARY KEY);
CREATE TEMP TABLE memory_registry_genesis_bridge_consumptions (id INT8 PRIMARY KEY);
CREATE TEMP TABLE memory_registry_heads (id INT8 PRIMARY KEY);
CREATE TEMP TABLE memory_registry_transitions (id INT8 PRIMARY KEY);
'
        sed -n '1,$p' \
            "$repo_root/deploy/cockroach/successor-activation-role-grants.sql"
        printf '%s\n' '
SELECT IF(
    count(*) = 2
        AND count(DISTINCT privilege_type) = 2
        AND COALESCE(bool_and(
            database_name = '\''fleet_recall'\''
            AND object_type = '\''schema'\''
            AND object_name IS NULL
            AND privilege_type IN ('\''CREATE'\'', '\''USAGE'\'')
            AND NOT is_grantable
        ), false),
    1:::INT8,
    CAST(concat(
        '\''temporary PUBLIC schema baseline differs from exact CREATE/USAGE: observed='\'',
        count(*)::STRING
    ) AS INT8)
) AS successor_activation_temp_public_baseline_postcondition
FROM [SHOW GRANTS FOR public]
WHERE grantee = '\''public'\''
  AND schema_name LIKE '\''pg_temp_%'\'';

SELECT IF(
    count(*) = 0,
    1:::INT8,
    CAST(concat(
        '\''temporary repository shadow received successor grants: observed='\'',
        count(*)::STRING
    ) AS INT8)
) AS successor_activation_temp_shadow_postcondition
FROM [SHOW GRANTS FOR fleet_registry_successor_activation]
WHERE grantee = '\''fleet_registry_successor_activation'\''
  AND schema_name LIKE '\''pg_temp_%'\'';
'
    } | docker exec -i "$container" cockroach sql \
        --insecure --database fleet_recall
}

assert_exact() {
    local label=$1
    local actual=$2
    local expected=$3
    if test "$actual" != "$expected"; then
        printf '%s\n' "unexpected $label" "expected:" "$expected" "actual:" "$actual" >&2
        fail "$label does not match the frozen contract"
    fi
}

assert_root_scalar() {
    local label=$1
    local statement=$2
    local expected=$3
    local actual
    actual=$(root_sql "$statement" | tail -n +2)
    assert_exact "$label" "$actual" "$expected"
}

expect_allowed() {
    local user=$1
    local label=$2
    local statement=$3
    sql_as "$user" "$statement" >/dev/null \
        || fail "$label should be allowed for $user"
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

assert_show_gate_sqlstate() {
    local label=$1
    local output=$2
    if ! grep -Fq 'SQLSTATE: 22P02' <<<"$output"; then
        echo "$output" >&2
        fail "$label did not use the supported top-level SHOW assertion failure"
    fi
}

expect_policy_prefix_failure() {
    local label=$1
    local output
    if output=$(apply_successor_policy 2>&1); then
        fail "$label unexpectedly admitted the successor policy"
    fi
    grep -Fq \
        'successor activation role requires the complete successful migration prefix through 14' \
        <<<"$output" || { echo "$output" >&2; fail "$label prefix diagnostic"; }
    grep -Fq 'SQLSTATE: 55000' <<<"$output" \
        || { echo "$output" >&2; fail "$label prefix SQLSTATE"; }
}

expect_policy_prefix_failure_with_valid_temp() {
    local label=$1
    local output
    if output=$(apply_successor_policy_with_valid_temp_prefix 2>&1); then
        fail "$label unexpectedly admitted a valid temporary prefix"
    fi
    grep -Fq \
        'successor activation role requires the complete successful migration prefix through 14' \
        <<<"$output" || { echo "$output" >&2; fail "$label public prefix diagnostic"; }
    grep -Fq 'SQLSTATE: 55000' <<<"$output" \
        || { echo "$output" >&2; fail "$label public prefix SQLSTATE"; }
}

expect_policy_database_failure() {
    local output
    if output=$(apply_successor_policy_in_database defaultdb 2>&1); then
        fail "wrong database unexpectedly admitted the successor policy"
    fi
    grep -Fq 'successor activation policy must run in fleet_recall' <<<"$output" \
        || { echo "$output" >&2; fail "wrong-database diagnostic"; }
    grep -Fq 'SQLSTATE: 55000' <<<"$output" \
        || { echo "$output" >&2; fail "wrong-database SQLSTATE"; }
}

expect_policy_show_failure() {
    local label=$1
    local diagnostic=$2
    local output
    if output=$(apply_successor_policy 2>&1); then
        fail "$label unexpectedly admitted the successor policy"
    fi
    grep -Fq "$diagnostic" <<<"$output" \
        || { echo "$output" >&2; fail "$label diagnostic"; }
    assert_show_gate_sqlstate "$label" "$output"
}

expect_policy_do_failure() {
    local label=$1
    local diagnostic=$2
    local output
    if output=$(apply_successor_policy 2>&1); then
        fail "$label unexpectedly admitted the successor policy"
    fi
    grep -Fq "$diagnostic" <<<"$output" \
        || { echo "$output" >&2; fail "$label diagnostic"; }
    grep -Fq 'SQLSTATE: 55000' <<<"$output" \
        || { echo "$output" >&2; fail "$label SQLSTATE"; }
}

# Freeze the production successor SQL surface beside its grants. Test-only Rust
# is excluded. The successor module supplies direct DML; the shared control-log
# witness supplies the two additional read-only tables.
successor_source=$(sed '/^#\[cfg(test)\]/,$d' \
    "$repo_root/src/registry_activation/successor_cockroach.rs")
successor_source_flat=$(tr '\n' ' ' <<<"$successor_source")

repository_sql_tables=$(grep -Eo \
    '(FROM|JOIN|INTO|UPDATE)[[:space:]\\]+public\.memory_[a-z0-9_]+' \
    <<<"$successor_source_flat" \
    | sed -E 's/.*public\.(memory_[a-z0-9_]+)$/\1/' \
    | sort -u)
expected_repository_sql_tables='memory_control_events
memory_control_shard_heads
memory_registry_activations
memory_registry_current_heads_v2
memory_registry_genesis_bridge_consumptions
memory_registry_heads
memory_registry_transitions'
assert_exact "successor direct SQL table surface" \
    "$repository_sql_tables" "$expected_repository_sql_tables"

repository_select_targets=$(grep -Eo \
    '(FROM|JOIN)[[:space:]\\]+public\.memory_[a-z0-9_]+' \
    <<<"$successor_source_flat" \
    | sed -E 's/.*public\.(memory_[a-z0-9_]+)$/\1/' \
    | sort -u)
assert_exact "successor direct SELECT targets" \
    "$repository_select_targets" "$expected_repository_sql_tables"

repository_insert_targets=$(grep -Eo \
    'INTO[[:space:]\\]+public\.memory_[a-z0-9_]+' \
    <<<"$successor_source_flat" \
    | sed -E 's/.*public\.(memory_[a-z0-9_]+)$/\1/' \
    | sort -u)
expected_repository_insert_targets='memory_control_events
memory_registry_current_heads_v2
memory_registry_genesis_bridge_consumptions
memory_registry_transitions'
assert_exact "successor INSERT targets" \
    "$repository_insert_targets" "$expected_repository_insert_targets"

repository_update_targets=$(grep -Eo \
    'UPDATE[[:space:]\\]+public\.memory_[a-z0-9_]+' \
    <<<"$successor_source_flat" \
    | sed -E 's/.*public\.(memory_[a-z0-9_]+)$/\1/' \
    | sort -u)
expected_repository_update_targets='memory_control_shard_heads
memory_registry_current_heads_v2'
assert_exact "successor UPDATE targets" \
    "$repository_update_targets" "$expected_repository_update_targets"

repository_delete_targets=$(grep -Eio \
    'DELETE[[:space:]\\]+FROM[[:space:]\\]+public\.memory_[a-z0-9_]+' \
    <<<"$successor_source_flat" || true)
assert_exact "successor DELETE targets" "$repository_delete_targets" ''

shared_control_source=$(sed '/^#\[cfg(test)\]/,$d' \
    "$repo_root/src/control_log/cockroach.rs")
shared_successor_read_targets=$(printf '%s\n' "$shared_control_source" \
    | grep -Eo 'FROM public\.memory_control_(bootstraps|log_epochs)' \
    | sed -E 's/^FROM public\.//' \
    | sort -u)
expected_shared_successor_read_targets='memory_control_bootstraps
memory_control_log_epochs'
assert_exact "shared successor witness-only SELECT additions" \
    "$shared_successor_read_targets" "$expected_shared_successor_read_targets"

schema_preflight=$(sed -n \
    '/^const REQUIRE_SUCCESSOR_SCHEMA_SQL:/,/version BETWEEN 1 AND 14";$/p' \
    "$repo_root/src/registry_activation/successor_cockroach.rs")
expected_schema_preflight='const REQUIRE_SUCCESSOR_SCHEMA_SQL: &str = "SELECT pg_catalog.current_database() = '\''fleet_recall'\'' \
     AND count(*) = 14 \
     AND COALESCE(bool_and(success), false) \
     FROM public._sqlx_migrations WHERE version BETWEEN 1 AND 14";'
assert_exact "database/schema-first successor prefix preflight bytes" \
    "$schema_preflight" "$expected_schema_preflight"

production_authority_source=$(for source_file in \
    "$repo_root/src/registry_activation/successor_cockroach.rs" \
    "$repo_root/src/registry_activation/cockroach.rs" \
    "$repo_root/src/registry_activation/genesis_audit.rs" \
    "$repo_root/src/control_log/cockroach.rs"; do
        sed '/^#\[cfg(test)\]/,$d' "$source_file"
    done)
unqualified_authority_references=$(grep -En \
    '(FROM|JOIN|INTO|UPDATE)[[:space:]\\]+(_sqlx_migrations|memory_(control|registry)_[a-z0-9_]+)' \
    <<<"$production_authority_source" || true)
assert_exact "unqualified reachable successor authority references" \
    "$unqualified_authority_references" ''

unqualified_builtin_references=$(grep -En \
    '(^|[^.[:alnum:]_])(current_database|statement_timestamp)\(\)' \
    <<<"$production_authority_source" || true)
assert_exact "unqualified reachable successor built-ins" \
    "$unqualified_builtin_references" ''

operator_preflight_helpers=$(sed -n \
    '/^audit_other_database_target_authority()/,/^sql_as()/p' \
    "$script_dir/successor-activation-role-grants.sh")
unqualified_preflight_current_database=$(grep -En \
    '(^|[^.[:alnum:]_])current_database\(\)' \
    <<<"$operator_preflight_helpers" || true)
assert_exact "unqualified operator-preflight current_database calls" \
    "$unqualified_preflight_current_database" ''
qualified_preflight_current_database_count=$(grep -Eo \
    'pg_catalog\.current_database\(\)' \
    <<<"$operator_preflight_helpers" | wc -l | tr -d ' ')
assert_exact "qualified operator-preflight current_database call count" \
    "$qualified_preflight_current_database_count" '4'

sequence_function_references=$(grep -En \
    '(^|[^[:alnum:]_])(nextval|currval|setval)\(' \
    <<<"$production_authority_source" || true)
assert_exact "successor sequence-function dependencies" \
    "$sequence_function_references" ''

role_option_hardening=$(sed -n \
    '/^ALTER ROLE fleet_registry_successor_activation WITH$/,/^    NOVIEWCLUSTERSETTING;$/p' \
    "$repo_root/deploy/cockroach/successor-activation-role-grants.sql")
expected_role_option_hardening='ALTER ROLE fleet_registry_successor_activation WITH
    NOBYPASSRLS
    NOCANCELQUERY
    NOCONTROLCHANGEFEED
    NOCONTROLJOB
    NOCREATEDB
    NOCREATELOGIN
    NOCREATEROLE
    NOLOGIN
    NOMODIFYCLUSTERSETTING
    NOREPLICATION
    SQLLOGIN
    NOVIEWACTIVITY
    NOVIEWACTIVITYREDACTED
    NOVIEWCLUSTERSETTING;'
assert_exact "complete v26.2 direct role-option hardening" \
    "$role_option_hardening" "$expected_role_option_hardening"

policy_first_statement=$(awk '
    /^[[:space:]]*--/ || /^[[:space:]]*$/ { next }
    { print; exit }
' "$repo_root/deploy/cockroach/successor-activation-role-grants.sql")
assert_exact "successor policy first statement" \
    "$policy_first_statement" 'SET search_path = pg_catalog, public, pg_temp;'

unqualified_policy_application_references=$(sed -E 's/--.*$//' \
    "$repo_root/deploy/cockroach/successor-activation-role-grants.sql" \
    | grep -En \
        '(FROM|ON TABLE)[[:space:]]+(_sqlx_migrations|memory_(control|registry)_[a-z0-9_]+)([^[:alnum:]_]|$)' \
        || true)
assert_exact "unqualified successor policy application references" \
    "$unqualified_policy_application_references" ''

qualified_policy_application_references=$(sed -E 's/--.*$//' \
    "$repo_root/deploy/cockroach/successor-activation-role-grants.sql" \
    | grep -Eo \
        'public\.(_sqlx_migrations|memory_(control_(bootstraps|events|log_epochs|shard_heads)|registry_(activations|current_heads_v2|genesis_bridge_consumptions|heads|transitions)))' \
    | sort \
    | uniq -c \
    | awk '{ print $1 ":" $2 }')
expected_qualified_policy_application_references='2:public._sqlx_migrations
1:public.memory_control_bootstraps
1:public.memory_control_events
1:public.memory_control_log_epochs
1:public.memory_control_shard_heads
1:public.memory_registry_activations
2:public.memory_registry_current_heads_v2
2:public.memory_registry_genesis_bridge_consumptions
1:public.memory_registry_heads
2:public.memory_registry_transitions'
assert_exact "fully qualified successor policy application references" \
    "$qualified_policy_application_references" \
    "$expected_qualified_policy_application_references"

policy_current_database_preflight=$(grep -F \
    "IF pg_catalog.current_database() <> 'fleet_recall' THEN" \
    "$repo_root/deploy/cockroach/successor-activation-role-grants.sql")
assert_exact "fleet_recall policy current-database preflight" \
    "$policy_current_database_preflight" \
    "    IF pg_catalog.current_database() <> 'fleet_recall' THEN"

forbidden_policy_grants=$(sed -E 's/--.*$//' \
    "$repo_root/deploy/cockroach/successor-activation-role-grants.sql" \
    | grep -Ein \
        'GRANT[[:space:]]+.*(DELETE|CREATE|DROP|MAINTAIN)|GRANT[[:space:]]+.*ON[[:space:]]+SEQUENCE|GRANT[[:space:]]+SYSTEM' \
        || true)
assert_exact "forbidden successor policy grants" "$forbidden_policy_grants" ''

unsupported_query_in_function_body=$(awk '
    /^DO \$\$/ { in_function_body = 1 }
    in_function_body && ($0 ~ /\[SHOW[[:space:]]/ || $0 ~ /^[[:space:]]*SHOW[[:space:]]/ || $0 ~ /crdb_internal\./ || $0 ~ /information_schema\./) { print NR ":" $0 }
    in_function_body && /^\$\$;$/ { in_function_body = 0 }
' "$repo_root/deploy/cockroach/successor-activation-role-grants.sql")
assert_exact "SHOW/virtual-table-free successor policy function bodies" \
    "$unsupported_query_in_function_body" ''

docker run --detach --name "$container" "$image" \
    start-single-node --insecure --listen-addr=localhost:26257 >/dev/null

ready=0
for _ in $(seq 1 60); do
    if docker exec "$container" cockroach sql --insecure \
        --execute 'SELECT 1' >/dev/null 2>&1; then
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

# Privilege-shaped stand-ins keep this proof focused on the role boundary. Every
# authority relation has a primary key and enough columns to exercise all four
# table operations independently.
root_sql '
CREATE TABLE _sqlx_migrations (
    version INT8 PRIMARY KEY,
    success BOOL NOT NULL
);
CREATE TABLE memory_control_bootstraps (id INT8 PRIMARY KEY, value INT8 NOT NULL DEFAULT 0);
CREATE TABLE memory_control_events (id INT8 PRIMARY KEY, value INT8 NOT NULL DEFAULT 0);
CREATE TABLE memory_control_log_epochs (id INT8 PRIMARY KEY, value INT8 NOT NULL DEFAULT 0);
CREATE TABLE memory_control_shard_heads (id INT8 PRIMARY KEY, value INT8 NOT NULL DEFAULT 0);
CREATE TABLE memory_registry_activations (id INT8 PRIMARY KEY, value INT8 NOT NULL DEFAULT 0);
CREATE TABLE memory_registry_current_heads_v2 (id INT8 PRIMARY KEY, value INT8 NOT NULL DEFAULT 0);
CREATE TABLE memory_registry_genesis_bridge_consumptions (id INT8 PRIMARY KEY, value INT8 NOT NULL DEFAULT 0);
CREATE TABLE memory_registry_heads (id INT8 PRIMARY KEY, value INT8 NOT NULL DEFAULT 0);
CREATE TABLE memory_registry_transitions (id INT8 PRIMARY KEY, value INT8 NOT NULL DEFAULT 0);
CREATE TABLE memory_unrelated (id INT8 PRIMARY KEY);
CREATE SEQUENCE memory_unrelated_seq;

INSERT INTO memory_control_bootstraps VALUES (1, 0);
INSERT INTO memory_control_events VALUES (1, 0);
INSERT INTO memory_control_log_epochs VALUES (1, 0);
INSERT INTO memory_control_shard_heads VALUES (1, 0);
INSERT INTO memory_registry_activations VALUES (1, 0);
INSERT INTO memory_registry_current_heads_v2 VALUES (1, 0);
INSERT INTO memory_registry_genesis_bridge_consumptions VALUES (1, 0);
INSERT INTO memory_registry_heads VALUES (1, 0);
INSERT INTO memory_registry_transitions VALUES (1, 0);

CREATE ROLE fleet_runtime;
CREATE ROLE fleet_control_bootstrap;
ALTER ROLE fleet_runtime WITH NOLOGIN NOCREATEROLE NOCREATEDB;
ALTER ROLE fleet_control_bootstrap WITH NOLOGIN NOCREATEROLE NOCREATEDB;

CREATE USER proof_database_owner;
CREATE USER proof_runtime;
CREATE USER proof_bootstrap;
CREATE USER proof_activation;
CREATE USER proof_successor;
CREATE USER proof_select_only;
CREATE USER proof_public;
ALTER DATABASE fleet_recall OWNER TO proof_database_owner;

GRANT CONNECT ON DATABASE fleet_recall TO
    fleet_runtime, fleet_control_bootstrap,
    proof_select_only, proof_public;
GRANT USAGE ON SCHEMA public TO
    fleet_runtime, fleet_control_bootstrap,
    proof_select_only, proof_public;
GRANT SELECT ON TABLE memory_unrelated TO fleet_runtime;
GRANT INSERT ON TABLE memory_control_bootstraps TO fleet_control_bootstrap;
GRANT SELECT ON TABLE memory_control_shard_heads TO proof_select_only;

-- Explicit forbidden drift on the exact successor quarantine surface must be
-- preserved by failed schema gates and removed by the successful policy.
GRANT DELETE ON TABLE
    memory_registry_transitions,
    memory_registry_genesis_bridge_consumptions,
    memory_registry_current_heads_v2
TO public, fleet_runtime, fleet_control_bootstrap;
GRANT SELECT ON TABLE memory_unrelated TO public;

INSERT INTO _sqlx_migrations
SELECT version, true FROM generate_series(1, 13) AS version;
' >/dev/null

# The first persistent gate binds the policy to fleet_recall. A wrong-database
# attempt may change only its session search_path; it cannot create the role or
# mutate the stock defaultdb PUBLIC grant.
expect_policy_database_failure
assert_root_scalar "wrong-database target role creation" \
    "SELECT count(*)::STRING FROM [SHOW USERS]
     WHERE username = 'fleet_registry_successor_activation'" '0'
wrong_database_public_grant=$(
    root_sql_in_database defaultdb \
        "SELECT count(*)::STRING FROM [SHOW GRANTS ON SCHEMA public]
         WHERE grantee = 'public' AND privilege_type = 'CREATE'" \
        | tail -n +2
)
assert_exact "wrong-database PUBLIC grant preservation" \
    "$wrong_database_public_grant" '1'

# Prefix 13, then failed 14 accompanied by successful later rows through the
# current release 17, both fail before target creation or any grant repair. A
# valid temporary migration history cannot mask the real public table.
expect_policy_prefix_failure "prefix 13"
expect_policy_prefix_failure_with_valid_temp "prefix 13 with temp prefix 14"
assert_root_scalar "prefix-13 role creation" \
    "SELECT count(*)::STRING FROM [SHOW USERS]
     WHERE username = 'fleet_registry_successor_activation'" '0'
assert_root_scalar "prefix-13 PUBLIC drift preservation" \
    "SELECT count(*)::STRING FROM [SHOW GRANTS ON TABLE memory_unrelated]
     WHERE grantee = 'public' AND privilege_type = 'SELECT'" '1'

root_sql '
INSERT INTO _sqlx_migrations VALUES (14, false), (15, true), (16, true), (17, true);
' >/dev/null
expect_policy_prefix_failure "failed migration 14 with later 15 through 17"
expect_policy_prefix_failure_with_valid_temp \
    "failed migration 14 with later rows and valid temp prefix"
assert_root_scalar "failed-14 role creation" \
    "SELECT count(*)::STRING FROM [SHOW USERS]
     WHERE username = 'fleet_registry_successor_activation'" '0'
assert_root_scalar "failed-14 quarantine drift preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW GRANTS ON TABLE memory_registry_transitions]
     WHERE grantee IN ('public', 'fleet_runtime', 'fleet_control_bootstrap')
       AND privilege_type = 'DELETE'" '3'

root_sql 'UPDATE _sqlx_migrations SET success = true WHERE version = 14' >/dev/null
expect_policy_show_failure \
    "missing registry-activation prerequisite" \
    'successor activation role requires the three hardened prior application roles'
assert_root_scalar "missing-prerequisite target role creation" \
    "SELECT count(*)::STRING FROM [SHOW USERS]
     WHERE username = 'fleet_registry_successor_activation'" '0'

root_sql '
CREATE ROLE fleet_registry_activation;
ALTER ROLE fleet_registry_activation WITH LOGIN CREATEROLE;
GRANT CONNECT ON DATABASE fleet_recall TO fleet_registry_activation;
GRANT USAGE ON SCHEMA public TO fleet_registry_activation;
GRANT ALL ON TABLE
    memory_registry_transitions,
    memory_registry_genesis_bridge_consumptions,
    memory_registry_current_heads_v2
TO fleet_registry_activation;
' >/dev/null
expect_policy_show_failure \
    "drifted registry-activation prerequisite" \
    'successor activation role requires the three hardened prior application roles'
assert_root_scalar "drifted prerequisite option preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW USERS] AS prior_role
     CROSS JOIN LATERAL unnest(prior_role.options) AS role_option(option_name)
     WHERE prior_role.username = 'fleet_registry_activation'
       AND role_option.option_name = 'CREATEROLE'" '1'
root_sql 'ALTER ROLE fleet_registry_activation WITH NOLOGIN NOCREATEROLE NOCREATEDB' \
    >/dev/null

# Establish the documented clean v26.2.3 PUBLIC routine-default baseline for
# every fixture identity before any successful policy application.
root_sql '
GRANT
    fleet_runtime,
    fleet_control_bootstrap,
    fleet_registry_activation,
    proof_database_owner,
    proof_runtime,
    proof_bootstrap,
    proof_activation,
    proof_successor,
    proof_select_only,
    proof_public
TO root;
ALTER DEFAULT PRIVILEGES FOR ROLE
    root,
    admin,
    fleet_runtime,
    fleet_control_bootstrap,
    fleet_registry_activation,
    proof_database_owner,
    proof_runtime,
    proof_bootstrap,
    proof_activation,
    proof_successor,
    proof_select_only,
    proof_public
REVOKE EXECUTE ON ROUTINES FROM public;
ALTER DEFAULT PRIVILEGES FOR ALL ROLES
    REVOKE EXECUTE ON ROUTINES FROM public;
REVOKE
    fleet_runtime,
    fleet_control_bootstrap,
    fleet_registry_activation,
    proof_database_owner,
    proof_runtime,
    proof_bootstrap,
    proof_activation,
    proof_successor,
    proof_select_only,
    proof_public
FROM root;
' >/dev/null
assert_root_scalar "temporary default-cleanup memberships" \
    "SELECT count(*)::STRING
     FROM [SHOW GRANTS ON ROLE]
     WHERE member = 'root'
       AND role_name IN (
           'fleet_runtime', 'fleet_control_bootstrap',
           'fleet_registry_activation', 'proof_database_owner',
           'proof_runtime', 'proof_bootstrap', 'proof_activation',
           'proof_successor', 'proof_select_only', 'proof_public'
       )" '0'
assert_root_scalar "intrinsic all-roles routine default" \
    "SELECT COALESCE(role, '<all_roles>') || ':' ||
            CASE WHEN for_all_roles THEN 'all_roles' ELSE 'single_role' END || ':' ||
            object_type || ':' || grantee || ':' || privilege_type || ':' ||
            CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END
     FROM (
         SELECT role, for_all_roles, object_type, grantee, privilege_type,
                is_grantable
         FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE public]
         UNION
         SELECT role, for_all_roles, object_type, grantee, privilege_type,
                is_grantable
         FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE public IN SCHEMA public]
     ) AS public_default
     WHERE object_type = 'routines'
       AND grantee = 'public'
       AND privilege_type = 'EXECUTE'" \
    '<all_roles>:all_roles:routines:public:EXECUTE:not_grantable'

root_sql 'GRANT SYSTEM CREATEROLE TO public' >/dev/null
expect_policy_show_failure \
    "PUBLIC system privilege" \
    'successor activation policy requires PUBLIC to have no system privileges'
assert_root_scalar "PUBLIC system-grant preservation" \
    "SELECT count(*)::STRING FROM [SHOW SYSTEM GRANTS]
     WHERE grantee = 'public' AND privilege_type = 'CREATEROLE'" '1'
assert_root_scalar "PUBLIC-system target role creation" \
    "SELECT count(*)::STRING FROM [SHOW USERS]
     WHERE username = 'fleet_registry_successor_activation'" '0'
root_sql 'REVOKE SYSTEM CREATEROLE FROM public' >/dev/null

sql_as proof_database_owner '
ALTER DEFAULT PRIVILEGES FOR ROLE proof_database_owner
    GRANT SELECT ON TABLES TO public;
ALTER DEFAULT PRIVILEGES FOR ROLE proof_database_owner
    GRANT EXECUTE ON ROUTINES TO public;
' >/dev/null
expect_policy_show_failure \
    "arbitrary-grantor PUBLIC defaults" \
    'successor activation policy permits only intrinsic PUBLIC type USAGE/all-roles routine EXECUTE, target PUBLIC routine EXECUTE, and target self-owner ALL future defaults'
assert_root_scalar "PUBLIC default preflight preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE public]
     WHERE role = 'proof_database_owner'
       AND NOT for_all_roles
       AND grantee = 'public'
       AND object_type IN ('tables', 'routines')" '2'
sql_as proof_database_owner '
ALTER DEFAULT PRIVILEGES FOR ROLE proof_database_owner
    REVOKE SELECT ON TABLES FROM public;
ALTER DEFAULT PRIVILEGES FOR ROLE proof_database_owner
    REVOKE EXECUTE ON ROUTINES FROM public;
' >/dev/null

# Freeze and remove the stock cross-database PUBLIC CREATE rows before the first
# successful application. The target role is still absent, so its audit is
# vacuous and cannot accidentally hide a pre-existing role.
assert_root_scalar "external-audit bootstrap target absence" \
    "SELECT count(*)::STRING FROM [SHOW USERS]
     WHERE username = 'fleet_registry_successor_activation'" '0'
initial_outside_public=$(inventory_other_database_public_application_authority)
expected_initial_outside_public='defaultdb:schema:public::CREATE:not_grantable
postgres:schema:public::CREATE:not_grantable'
assert_exact "initial external PUBLIC inventory" \
    "$initial_outside_public" "$expected_initial_outside_public"
root_sql_in_database defaultdb \
    'REVOKE CREATE ON SCHEMA public FROM public' >/dev/null
root_sql_in_database postgres \
    'REVOKE CREATE ON SCHEMA public FROM public' >/dev/null
hardened_initial_outside_public=$(inventory_other_database_public_application_authority)
assert_exact "hardened initial external PUBLIC inventory" \
    "$hardened_initial_outside_public" ''

# The first successful application occurs at current release prefix 17 while
# retaining the narrower bounded 1..14 gate. Reapply twice for idempotence.
apply_successor_policy >/dev/null
apply_successor_policy >/dev/null
assert_root_scalar "current-17 target creation" \
    "SELECT count(*)::STRING FROM [SHOW USERS]
     WHERE username = 'fleet_registry_successor_activation'
       AND options::STRING = '{NOLOGIN}'" '1'
assert_root_scalar "optional reconciliation role remains absent" \
    "SELECT count(*)::STRING FROM [SHOW USERS]
     WHERE username = 'fleet_conflict_reconciliation'" '0'
post_create_outside_target=$(audit_other_database_target_authority)
assert_exact "post-create external target audit" \
    "$post_create_outside_target" ''

# A failed temporary history cannot reject the valid public prefix or redirect
# any fully qualified grant to a temporary namesake.
apply_successor_policy_with_temp_shadows >/dev/null
assert_root_scalar "temp-shadow public migration grant" \
    "SELECT count(*)::STRING
     FROM [SHOW GRANTS ON TABLE public._sqlx_migrations]
     WHERE grantee = 'fleet_registry_successor_activation'
       AND privilege_type = 'SELECT'
       AND NOT is_grantable" '1'

# Database ownership alone is not enough to alter the cluster role boundary.
expect_denied proof_database_owner "database owner role-option hardening" \
    'ALTER ROLE fleet_registry_successor_activation WITH NOLOGIN NOCREATEROLE NOCREATEDB'
expect_denied proof_database_owner "database owner membership cleanup" \
    'REVOKE admin FROM fleet_registry_successor_activation'
expect_denied proof_database_owner "database owner system cleanup" \
    'REVOKE SYSTEM ALL FROM fleet_registry_successor_activation'

# VALID UNTIL cannot be normalized portably. Prove identity drift fails before
# an unrelated CONTROLJOB option is changed, then replace the invalid role and
# reapply. Exact NOLOGIN remains the portable stale-password defense.
root_sql "
ALTER ROLE fleet_registry_successor_activation WITH
    CONTROLJOB
    VALID UNTIL '2035-01-01 00:00:00+00:00';
" >/dev/null
expect_policy_show_failure \
    "VALID UNTIL identity drift" \
    'successor activation role has a forbidden validity or provisioned-identity option'
assert_root_scalar "identity-option preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW USERS] AS target_role
     CROSS JOIN LATERAL unnest(target_role.options) AS role_option(option_name)
     WHERE target_role.username = 'fleet_registry_successor_activation'
       AND (
           role_option.option_name = 'CONTROLJOB'
           OR role_option.option_name LIKE 'VALID UNTIL=%'
       )" '2'
root_sql '
REVOKE ALL ON DATABASE fleet_recall FROM fleet_registry_successor_activation;
REVOKE ALL ON SCHEMA public FROM fleet_registry_successor_activation;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM fleet_registry_successor_activation;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM fleet_registry_successor_activation;
DROP ROLE fleet_registry_successor_activation;
' >/dev/null
apply_successor_policy >/dev/null

# Inject every direct role-option category (including REPLICATION/NOSQLLOGIN),
# system/object/grant-option drift, PUBLIC drift, mandatory bidirectional-role
# drift, and a failed bounded migration after the target already exists. The
# prefix gate must preserve all drift; restoration plus two applies normalizes
# it exactly and reasserts the successor quarantine for all older roles.
root_sql '
ALTER ROLE fleet_registry_successor_activation WITH
    LOGIN
    BYPASSRLS
    CANCELQUERY
    CONTROLCHANGEFEED
    CONTROLJOB
    CREATEDB
    CREATELOGIN
    CREATEROLE
    MODIFYCLUSTERSETTING
    REPLICATION
    NOSQLLOGIN
    VIEWACTIVITY
    VIEWACTIVITYREDACTED
    VIEWCLUSTERSETTING;
GRANT admin, fleet_runtime, fleet_control_bootstrap, fleet_registry_activation
    TO fleet_registry_successor_activation;
GRANT SYSTEM CREATEROLE TO fleet_registry_successor_activation;
GRANT ALL ON DATABASE fleet_recall TO fleet_registry_successor_activation;
GRANT ALL ON SCHEMA public TO fleet_registry_successor_activation;
GRANT DELETE ON TABLE memory_control_bootstraps
    TO fleet_registry_successor_activation WITH GRANT OPTION;
GRANT SELECT ON TABLE memory_unrelated
    TO fleet_registry_successor_activation WITH GRANT OPTION;
GRANT SELECT ON SEQUENCE memory_unrelated_seq
    TO fleet_registry_successor_activation WITH GRANT OPTION;
GRANT ALL ON DATABASE fleet_recall TO public;
GRANT ALL ON SCHEMA public TO public;
GRANT ALL ON ALL TABLES IN SCHEMA public TO public;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO public;
UPDATE _sqlx_migrations SET success = false WHERE version = 14;
' >/dev/null
expect_policy_prefix_failure "existing drift with failed 14 and later rows"
assert_root_scalar "failed-gate LOGIN preservation" \
    "SELECT count(*)::STRING FROM [SHOW USERS]
     WHERE username = 'fleet_registry_successor_activation'
       AND 'NOLOGIN' != ALL(options)" '1'
assert_root_scalar "failed-gate REPLICATION preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW USERS] AS target_role
     CROSS JOIN LATERAL unnest(target_role.options) AS role_option(option_name)
     WHERE target_role.username = 'fleet_registry_successor_activation'
       AND role_option.option_name = 'REPLICATION'" '1'
assert_root_scalar "failed-gate grant-option preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW GRANTS ON TABLE memory_control_bootstraps]
     WHERE grantee = 'fleet_registry_successor_activation'
       AND privilege_type = 'DELETE'
       AND is_grantable" '1'
root_sql 'UPDATE _sqlx_migrations SET success = true WHERE version = 14' >/dev/null
apply_successor_policy >/dev/null
apply_successor_policy >/dev/null

# Repairable mandatory-role inheritance drift is normalized in both directions.
root_sql '
GRANT fleet_registry_successor_activation
    TO fleet_runtime, fleet_control_bootstrap, fleet_registry_activation;
' >/dev/null
apply_successor_policy >/dev/null

# Future-object drift from an independent database owner fails before current
# role options or grants change. Cover database/schema scopes and every relevant
# object class, including a grantable type default.
root_sql 'ALTER ROLE fleet_registry_successor_activation WITH CONTROLJOB' >/dev/null
sql_as proof_database_owner '
ALTER DEFAULT PRIVILEGES FOR ROLE proof_database_owner
    GRANT USAGE ON SCHEMAS TO fleet_registry_successor_activation;
ALTER DEFAULT PRIVILEGES FOR ROLE proof_database_owner IN SCHEMA public
    GRANT SELECT ON TABLES TO fleet_registry_successor_activation;
ALTER DEFAULT PRIVILEGES FOR ROLE proof_database_owner IN SCHEMA public
    GRANT SELECT ON SEQUENCES TO fleet_registry_successor_activation;
ALTER DEFAULT PRIVILEGES FOR ROLE proof_database_owner IN SCHEMA public
    GRANT EXECUTE ON ROUTINES TO fleet_registry_successor_activation;
ALTER DEFAULT PRIVILEGES FOR ROLE proof_database_owner IN SCHEMA public
    GRANT USAGE ON TYPES TO fleet_registry_successor_activation WITH GRANT OPTION;
' >/dev/null
expect_policy_show_failure \
    "target future-object defaults" \
    'successor activation policy permits only intrinsic PUBLIC type USAGE/all-roles routine EXECUTE, target PUBLIC routine EXECUTE, and target self-owner ALL future defaults'
assert_root_scalar "target default preservation" \
    "SELECT count(*)::STRING FROM (
         SELECT role, object_type, grantee, privilege_type, is_grantable
         FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE fleet_registry_successor_activation]
         UNION ALL
         SELECT role, object_type, grantee, privilege_type, is_grantable
         FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE fleet_registry_successor_activation
               IN SCHEMA public]
     ) AS target_default
     WHERE role = 'proof_database_owner'
       AND grantee = 'fleet_registry_successor_activation'
       AND object_type IN ('schemas', 'tables', 'sequences', 'routines', 'types')" '5'
assert_root_scalar "default-gate role-option preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW USERS] AS target_role
     CROSS JOIN LATERAL unnest(target_role.options) AS role_option(option_name)
     WHERE target_role.username = 'fleet_registry_successor_activation'
       AND role_option.option_name = 'CONTROLJOB'" '1'
sql_as proof_database_owner '
ALTER DEFAULT PRIVILEGES FOR ROLE proof_database_owner
    REVOKE USAGE ON SCHEMAS FROM fleet_registry_successor_activation;
ALTER DEFAULT PRIVILEGES FOR ROLE proof_database_owner IN SCHEMA public
    REVOKE SELECT ON TABLES FROM fleet_registry_successor_activation;
ALTER DEFAULT PRIVILEGES FOR ROLE proof_database_owner IN SCHEMA public
    REVOKE SELECT ON SEQUENCES FROM fleet_registry_successor_activation;
ALTER DEFAULT PRIVILEGES FOR ROLE proof_database_owner IN SCHEMA public
    REVOKE EXECUTE ON ROUTINES FROM fleet_registry_successor_activation;
ALTER DEFAULT PRIVILEGES FOR ROLE proof_database_owner IN SCHEMA public
    REVOKE USAGE ON TYPES FROM fleet_registry_successor_activation;
' >/dev/null
apply_successor_policy >/dev/null

# The later reconciliation role is optional: absence was already admitted.
# Once it exists as an exact hardened role, no-edge coexistence succeeds. Since
# v26.2 has no supported conditional privilege DDL, edges in either direction
# fail before mutation and require explicit cluster-admin cleanup.
root_sql '
CREATE ROLE fleet_conflict_reconciliation;
ALTER ROLE fleet_conflict_reconciliation WITH NOLOGIN NOCREATEROLE NOCREATEDB;
' >/dev/null
assert_root_scalar "reconciliation creator-scoped PUBLIC routine default" \
    "SELECT count(*)::STRING
     FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE public]
     WHERE role = 'fleet_conflict_reconciliation'
       AND NOT for_all_roles
       AND object_type = 'routines'
       AND grantee = 'public'
       AND privilege_type = 'EXECUTE'
       AND NOT is_grantable" '1'
root_sql 'ALTER ROLE fleet_registry_successor_activation WITH CONTROLJOB' >/dev/null
expect_policy_show_failure \
    "optional reconciliation creator-default cleanup prerequisite" \
    'successor activation policy permits only intrinsic PUBLIC type USAGE/all-roles routine EXECUTE, target PUBLIC routine EXECUTE, and target self-owner ALL future defaults'
assert_root_scalar "reconciliation-default gate target option preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW USERS] AS target_role
     CROSS JOIN LATERAL unnest(target_role.options) AS role_option(option_name)
     WHERE target_role.username = 'fleet_registry_successor_activation'
       AND role_option.option_name = 'CONTROLJOB'" '1'
root_sql '
ALTER DEFAULT PRIVILEGES FOR ROLE fleet_conflict_reconciliation
    REVOKE EXECUTE ON ROUTINES FROM public;
ALTER DEFAULT PRIVILEGES FOR ROLE fleet_conflict_reconciliation IN SCHEMA public
    REVOKE EXECUTE ON ROUTINES FROM public;
' >/dev/null
assert_root_scalar "cleaned reconciliation PUBLIC routine defaults" \
    "SELECT count(*)::STRING FROM (
         SELECT role, for_all_roles, object_type, grantee, privilege_type
         FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE public]
         UNION
         SELECT role, for_all_roles, object_type, grantee, privilege_type
         FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE public IN SCHEMA public]
     ) AS public_default
     WHERE role = 'fleet_conflict_reconciliation'
       AND NOT for_all_roles
       AND object_type = 'routines'
       AND grantee = 'public'
       AND privilege_type = 'EXECUTE'" '0'
assert_root_scalar "admin cleanup introduced no reconciliation membership" \
    "SELECT count(*)::STRING FROM [SHOW GRANTS ON ROLE]
     WHERE role_name = 'fleet_conflict_reconciliation'
       AND member = 'root'" '0'
apply_successor_policy >/dev/null

root_sql '
GRANT fleet_conflict_reconciliation
    TO fleet_registry_successor_activation;
' >/dev/null
expect_policy_show_failure \
    "successor inherits optional reconciliation" \
    'successor activation role has an unexpected NOLOGIN, reconciliation, or admin-option inheritance edge'
assert_root_scalar "outbound reconciliation edge preservation" \
    "SELECT count(*)::STRING FROM [SHOW GRANTS ON ROLE]
     WHERE role_name = 'fleet_conflict_reconciliation'
       AND member = 'fleet_registry_successor_activation'" '1'
root_sql '
REVOKE fleet_conflict_reconciliation
    FROM fleet_registry_successor_activation;
GRANT fleet_registry_successor_activation
    TO fleet_conflict_reconciliation;
' >/dev/null
expect_policy_show_failure \
    "optional reconciliation inherits successor" \
    'successor activation role has an unexpected NOLOGIN, reconciliation, or admin-option inheritance edge'
assert_root_scalar "inbound reconciliation edge preservation" \
    "SELECT count(*)::STRING FROM [SHOW GRANTS ON ROLE]
     WHERE role_name = 'fleet_registry_successor_activation'
       AND member = 'fleet_conflict_reconciliation'" '1'
root_sql '
REVOKE fleet_registry_successor_activation
    FROM fleet_conflict_reconciliation;
' >/dev/null
apply_successor_policy >/dev/null

# Unknown NOLOGIN edges and external ADMIN OPTION edges fail closed rather than
# being silently hidden. Clean each exact edge before proceeding.
root_sql '
CREATE ROLE proof_unexpected_authority;
GRANT proof_unexpected_authority TO root;
ALTER DEFAULT PRIVILEGES FOR ROLE proof_unexpected_authority
    REVOKE EXECUTE ON ROUTINES FROM public;
REVOKE proof_unexpected_authority FROM root;
GRANT proof_unexpected_authority TO fleet_registry_successor_activation;
' >/dev/null
expect_policy_show_failure \
    "unexpected inherited NOLOGIN role" \
    'successor activation role has an unexpected NOLOGIN, reconciliation, or admin-option inheritance edge'
assert_root_scalar "unknown outbound edge preservation" \
    "SELECT count(*)::STRING FROM [SHOW GRANTS ON ROLE]
     WHERE role_name = 'proof_unexpected_authority'
       AND member = 'fleet_registry_successor_activation'" '1'
root_sql '
REVOKE proof_unexpected_authority FROM fleet_registry_successor_activation;
CREATE ROLE proof_unexpected_holder;
GRANT proof_unexpected_holder TO root;
ALTER DEFAULT PRIVILEGES FOR ROLE proof_unexpected_holder
    REVOKE EXECUTE ON ROUTINES FROM public;
REVOKE proof_unexpected_holder FROM root;
GRANT fleet_registry_successor_activation TO proof_unexpected_holder;
' >/dev/null
expect_policy_show_failure \
    "unexpected inheriting NOLOGIN role" \
    'successor activation role has an unexpected NOLOGIN, reconciliation, or admin-option inheritance edge'
assert_root_scalar "unknown inbound edge preservation" \
    "SELECT count(*)::STRING FROM [SHOW GRANTS ON ROLE]
     WHERE role_name = 'fleet_registry_successor_activation'
       AND member = 'proof_unexpected_holder'" '1'
root_sql '
REVOKE fleet_registry_successor_activation FROM proof_unexpected_holder;
GRANT fleet_registry_successor_activation TO proof_successor WITH ADMIN OPTION;
' >/dev/null
expect_policy_show_failure \
    "external successor member with admin option" \
    'successor activation role has an unexpected NOLOGIN, reconciliation, or admin-option inheritance edge'
assert_root_scalar "external admin-option preservation" \
    "SELECT count(*)::STRING FROM [SHOW GRANTS ON ROLE]
     WHERE role_name = 'fleet_registry_successor_activation'
       AND member = 'proof_successor'
       AND is_admin" '1'
root_sql 'REVOKE fleet_registry_successor_activation FROM proof_successor' >/dev/null

# Additional application schemas, current-database type grants, cluster-global
# PUBLIC external connections, and current-database ownership all fail closed
# before independently injected role-option drift is normalized.
root_sql '
CREATE SCHEMA proof_cross_schema;
CREATE TABLE proof_cross_schema.outside_public (id INT8 PRIMARY KEY);
GRANT USAGE ON SCHEMA proof_cross_schema
    TO fleet_registry_successor_activation;
GRANT SELECT ON TABLE proof_cross_schema.outside_public
    TO fleet_registry_successor_activation;
' >/dev/null
expect_policy_do_failure \
    "unexpected application schema" \
    'successor activation policy requires public to be the only application schema'
assert_root_scalar "schema-boundary drift preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW GRANTS FOR fleet_registry_successor_activation]
     WHERE grantee = 'fleet_registry_successor_activation'
       AND database_name = 'fleet_recall'
       AND schema_name = 'proof_cross_schema'" '2'
root_sql "
REVOKE SELECT ON TABLE proof_cross_schema.outside_public
    FROM fleet_registry_successor_activation;
REVOKE USAGE ON SCHEMA proof_cross_schema
    FROM fleet_registry_successor_activation;
DROP TABLE proof_cross_schema.outside_public;
DROP SCHEMA proof_cross_schema;
CREATE TYPE proof_boundary_type AS ENUM ('proof');
REVOKE USAGE ON TYPE proof_boundary_type FROM public;
GRANT USAGE ON TYPE proof_boundary_type
    TO fleet_registry_successor_activation;
" >/dev/null
expect_policy_show_failure \
    "unexpected successor type grant" \
    'successor activation policy found a grant outside the repairable fleet_recall.public boundary'
assert_root_scalar "target type-grant preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW GRANTS FOR fleet_registry_successor_activation]
     WHERE grantee = 'fleet_registry_successor_activation'
       AND database_name = 'fleet_recall'
       AND schema_name = 'public'
       AND object_type = 'type'
       AND object_name = 'proof_boundary_type'
       AND privilege_type = 'USAGE'" '1'
root_sql '
REVOKE USAGE ON TYPE proof_boundary_type
    FROM fleet_registry_successor_activation;
GRANT USAGE ON TYPE proof_boundary_type TO public;
' >/dev/null
expect_policy_show_failure \
    "unexpected PUBLIC type grant" \
    'successor activation policy found a grant outside the repairable fleet_recall.public boundary'
root_sql "
REVOKE USAGE ON TYPE proof_boundary_type FROM public;
DROP TYPE proof_boundary_type;
ALTER ROLE fleet_registry_successor_activation WITH CONTROLJOB;
CREATE EXTERNAL CONNECTION proof_successor_external
    AS 'nodelocal://1/proof-successor-external';
GRANT USAGE, DROP ON EXTERNAL CONNECTION proof_successor_external TO public;
" >/dev/null
expect_policy_show_failure \
    "PUBLIC external-connection grants" \
    'successor activation policy found a grant outside the repairable fleet_recall.public boundary'
assert_root_scalar "external-connection grant preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW GRANTS FOR public]
     WHERE grantee = 'public'
       AND database_name IS NULL
       AND schema_name IS NULL
       AND object_type = 'external_connection'
       AND object_name = 'proof_successor_external'
       AND privilege_type IN ('DROP', 'USAGE')" '2'
assert_root_scalar "external gate option preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW USERS] AS target_role
     CROSS JOIN LATERAL unnest(target_role.options) AS role_option(option_name)
     WHERE target_role.username = 'fleet_registry_successor_activation'
       AND role_option.option_name = 'CONTROLJOB'" '1'
root_sql '
REVOKE USAGE, DROP ON EXTERNAL CONNECTION proof_successor_external FROM public;
DROP EXTERNAL CONNECTION proof_successor_external;
' >/dev/null
apply_successor_policy >/dev/null

root_sql '
CREATE TABLE proof_owned_by_successor (id INT8 PRIMARY KEY);
GRANT CREATE ON SCHEMA public TO fleet_registry_successor_activation;
ALTER TABLE proof_owned_by_successor
    OWNER TO fleet_registry_successor_activation;
REVOKE CREATE ON SCHEMA public FROM fleet_registry_successor_activation;
' >/dev/null
expect_policy_do_failure \
    "unexpected successor ownership" \
    'successor activation role must not own database, schema, relation, function, or type objects'
assert_root_scalar "ownership preservation" \
    "SELECT count(*)::STRING
     FROM pg_catalog.pg_class AS relation_object
     JOIN pg_catalog.pg_namespace AS relation_schema
       ON relation_schema.oid = relation_object.relnamespace
     JOIN pg_catalog.pg_roles AS owner_role
       ON owner_role.oid = relation_object.relowner
     WHERE relation_schema.nspname = 'public'
       AND relation_object.relname = 'proof_owned_by_successor'
       AND owner_role.rolname = 'fleet_registry_successor_activation'" '1'
root_sql '
ALTER TABLE proof_owned_by_successor OWNER TO root;
DROP TABLE proof_owned_by_successor;
' >/dev/null
apply_successor_policy >/dev/null

# Exercise the required read-only external deployment audit against another
# database. It exposes target grants, implicit ownership, and PUBLIC application
# authority without changing them; the operator cleans exact rows before apply.
root_sql 'CREATE DATABASE proof_other_database' >/dev/null
root_sql_in_database proof_other_database '
CREATE TABLE proof_other_ledger (id INT8 PRIMARY KEY);
CREATE TABLE proof_other_owned (id INT8 PRIMARY KEY);
GRANT SELECT ON TABLE proof_other_ledger
    TO fleet_registry_successor_activation, public;
GRANT CREATE ON SCHEMA public TO fleet_registry_successor_activation;
ALTER TABLE proof_other_owned OWNER TO fleet_registry_successor_activation;
REVOKE CREATE ON SCHEMA public FROM fleet_registry_successor_activation;
' >/dev/null
outside_target=$(audit_other_database_target_authority)
expected_outside_target='proof_other_database:grant:table:public:proof_other_ledger:SELECT:not_grantable
proof_other_database:grant:table:public:proof_other_owned:ALL:grantable
proof_other_database:relation_owner:public:proof_other_owned
proof_other_database:type_owner:public:proof_other_owned'
assert_exact "external target-authority audit" \
    "$outside_target" "$expected_outside_target"
outside_public=$(inventory_other_database_public_application_authority)
expected_outside_public='proof_other_database:schema:public::CREATE:not_grantable
proof_other_database:table:public:proof_other_ledger:SELECT:not_grantable'
assert_exact "external PUBLIC application inventory" \
    "$outside_public" "$expected_outside_public"
other_database_grants_after_audit=$(root_sql_in_database proof_other_database "
SELECT grantee || ':' || privilege_type
FROM [SHOW GRANTS ON TABLE proof_other_ledger]
WHERE grantee IN ('fleet_registry_successor_activation', 'public')
  AND privilege_type = 'SELECT'
ORDER BY grantee" | tail -n +2)
assert_exact "read-only external audit preservation" \
    "$other_database_grants_after_audit" \
    'fleet_registry_successor_activation:SELECT
public:SELECT'
root_sql_in_database proof_other_database '
ALTER TABLE proof_other_owned OWNER TO root;
REVOKE SELECT ON TABLE proof_other_ledger
    FROM fleet_registry_successor_activation, public;
REVOKE CREATE ON SCHEMA public FROM public;
' >/dev/null
clean_outside_target=$(audit_other_database_target_authority)
assert_exact "clean external target precondition" \
    "$clean_outside_target" ''
clean_outside_public=$(inventory_other_database_public_application_authority)
assert_exact "clean external PUBLIC precondition" \
    "$clean_outside_public" ''
apply_successor_policy >/dev/null

# Provision the one short-lived external LOGIN member. Reapplication preserves
# membership without ADMIN OPTION; final teardown removes membership and disables
# the login after all operation checks below.
root_sql '
GRANT fleet_registry_successor_activation TO proof_successor;
GRANT fleet_runtime TO proof_runtime;
GRANT fleet_control_bootstrap TO proof_bootstrap;
GRANT fleet_registry_activation TO proof_activation;
' >/dev/null
apply_successor_policy >/dev/null

# Freeze the exact current-object matrix: 16 non-grantable table rows, no
# sequence row, sole database CONNECT, and sole public-schema USAGE.
successor_object_grants=$(root_sql "
SELECT schema_name || ':' || object_type || ':' || object_name || ':' || privilege_type || ':' ||
       CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END AS normalized
FROM [SHOW GRANTS FOR fleet_registry_successor_activation]
WHERE grantee = 'fleet_registry_successor_activation'
  AND database_name = 'fleet_recall'
  AND object_type IN ('table', 'sequence')
ORDER BY schema_name, object_type, object_name, privilege_type" | tail -n +2)
expected_successor_object_grants='public:table:_sqlx_migrations:SELECT:not_grantable
public:table:memory_control_bootstraps:SELECT:not_grantable
public:table:memory_control_events:INSERT:not_grantable
public:table:memory_control_events:SELECT:not_grantable
public:table:memory_control_log_epochs:SELECT:not_grantable
public:table:memory_control_shard_heads:SELECT:not_grantable
public:table:memory_control_shard_heads:UPDATE:not_grantable
public:table:memory_registry_activations:SELECT:not_grantable
public:table:memory_registry_current_heads_v2:INSERT:not_grantable
public:table:memory_registry_current_heads_v2:SELECT:not_grantable
public:table:memory_registry_current_heads_v2:UPDATE:not_grantable
public:table:memory_registry_genesis_bridge_consumptions:INSERT:not_grantable
public:table:memory_registry_genesis_bridge_consumptions:SELECT:not_grantable
public:table:memory_registry_heads:SELECT:not_grantable
public:table:memory_registry_transitions:INSERT:not_grantable
public:table:memory_registry_transitions:SELECT:not_grantable'
assert_exact "successor full table/sequence grants" \
    "$successor_object_grants" "$expected_successor_object_grants"
successor_object_grant_count=$(
    printf '%s\n' "$successor_object_grants" | wc -l | tr -d ' '
)
assert_exact "successor exact table/sequence grant row count" \
    "$successor_object_grant_count" '16'
assert_root_scalar "successor zero sequence grants" \
    "SELECT count(*)::STRING
     FROM [SHOW GRANTS FOR fleet_registry_successor_activation]
     WHERE grantee = 'fleet_registry_successor_activation'
       AND object_type = 'sequence'" '0'

database_grants=$(root_sql "
SELECT database_name || ':' || grantee || ':' || privilege_type || ':' ||
       CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END
FROM [SHOW GRANTS ON DATABASE fleet_recall]
WHERE grantee IN ('public', 'fleet_registry_successor_activation')
ORDER BY grantee, privilege_type" | tail -n +2)
assert_exact "successor database grants" "$database_grants" \
    'fleet_recall:fleet_registry_successor_activation:CONNECT:not_grantable'

schema_grants=$(root_sql "
SELECT schema_name || ':' || grantee || ':' || privilege_type || ':' ||
       CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END
FROM [SHOW GRANTS ON SCHEMA public]
WHERE grantee IN ('public', 'fleet_registry_successor_activation')
ORDER BY grantee, privilege_type" | tail -n +2)
assert_exact "successor schema grants" "$schema_grants" \
    'public:fleet_registry_successor_activation:USAGE:not_grantable'

# PUBLIC has no application table/sequence authority, and the three prior roles
# retain no direct grant on any successor table after quarantine reassertion.
public_application_grants=$(root_sql "
SELECT object_type || ':' || object_name || ':' || privilege_type
FROM [SHOW GRANTS FOR public]
WHERE grantee = 'public'
  AND database_name = 'fleet_recall'
  AND schema_name = 'public'
  AND object_type IN ('table', 'sequence')
ORDER BY object_type, object_name, privilege_type" | tail -n +2)
assert_exact "PUBLIC application table/sequence grants" \
    "$public_application_grants" ''

prior_successor_grants=$(root_sql "
SELECT grantee || ':' || object_name || ':' || privilege_type
FROM [SHOW GRANTS FOR
    fleet_runtime, fleet_control_bootstrap, fleet_registry_activation]
WHERE grantee IN (
    'fleet_runtime', 'fleet_control_bootstrap', 'fleet_registry_activation'
)
  AND database_name = 'fleet_recall'
  AND schema_name = 'public'
  AND object_name IN (
      'memory_registry_transitions',
      'memory_registry_genesis_bridge_consumptions',
      'memory_registry_current_heads_v2'
  )
ORDER BY grantee, object_name, privilege_type" | tail -n +2)
assert_exact "prior roles denied successor authority tables" \
    "$prior_successor_grants" ''

# Freeze v26.2.3's exact non-grantable PUBLIC visibility in its four reserved
# virtual schemas. Any other shape was rejected by the policy preflight.
public_virtual_schema_grants=$(root_sql "
SELECT schema_name || ':' || object_type || ':' || privilege_type || ':' ||
       CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END || ':' ||
       count(*)::STRING
FROM [SHOW GRANTS FOR public]
WHERE grantee = 'public'
  AND database_name = 'fleet_recall'
  AND schema_name IN (
      'crdb_internal', 'information_schema', 'pg_catalog', 'pg_extension'
  )
GROUP BY schema_name, object_type, privilege_type, is_grantable
ORDER BY schema_name, object_type, privilege_type, is_grantable" | tail -n +2)
expected_public_virtual_schema_grants='crdb_internal:schema:USAGE:not_grantable:1
crdb_internal:table:SELECT:not_grantable:116
information_schema:schema:USAGE:not_grantable:1
information_schema:table:SELECT:not_grantable:89
pg_catalog:schema:USAGE:not_grantable:1
pg_catalog:table:SELECT:not_grantable:129
pg_catalog:type:USAGE:not_grantable:98
pg_extension:schema:USAGE:not_grantable:1
pg_extension:table:SELECT:not_grantable:3'
assert_exact "v26.2.3 PUBLIC virtual-schema fallback grants" \
    "$public_virtual_schema_grants" "$expected_public_virtual_schema_grants"

application_schemas=$(root_sql "
SELECT nspname
FROM pg_catalog.pg_namespace
WHERE nspname NOT LIKE 'pg_temp_%'
ORDER BY nspname" | tail -n +2)
expected_application_schemas='crdb_internal
information_schema
pg_catalog
pg_extension
public'
assert_exact "dedicated database schema boundary" \
    "$application_schemas" "$expected_application_schemas"

system_grants=$(root_sql "
SELECT grantee || ':' || privilege_type
FROM [SHOW SYSTEM GRANTS]
WHERE grantee IN (
    'fleet_runtime',
    'fleet_control_bootstrap',
    'fleet_registry_activation',
    'fleet_registry_successor_activation',
    'fleet_conflict_reconciliation',
    'public'
)
ORDER BY grantee, privilege_type" | tail -n +2)
assert_exact "application-role and PUBLIC system grants" "$system_grants" ''

application_role_options=$(root_sql "
SELECT username || ':' || options::STRING
FROM [SHOW USERS]
WHERE username IN (
    'fleet_runtime',
    'fleet_control_bootstrap',
    'fleet_registry_activation',
    'fleet_registry_successor_activation',
    'fleet_conflict_reconciliation'
)
ORDER BY username" | tail -n +2)
expected_application_role_options='fleet_conflict_reconciliation:{NOLOGIN}
fleet_control_bootstrap:{NOLOGIN}
fleet_registry_activation:{NOLOGIN}
fleet_registry_successor_activation:{NOLOGIN}
fleet_runtime:{NOLOGIN}'
assert_exact "application role options including NOREPLICATION normalization" \
    "$application_role_options" "$expected_application_role_options"

successor_role_edges=$(root_sql "
SELECT role_name || ':' || member || ':' ||
       CASE WHEN is_admin THEN 'admin_option' ELSE 'no_admin_option' END
FROM [SHOW GRANTS ON ROLE]
WHERE role_name = 'fleet_registry_successor_activation'
   OR member = 'fleet_registry_successor_activation'
ORDER BY role_name, member" | tail -n +2)
assert_exact "complete successor role edges" "$successor_role_edges" \
    'fleet_registry_successor_activation:proof_successor:no_admin_option'

target_public_routine_defaults=$(root_sql "
SELECT role || ':' || object_type || ':' || grantee || ':' || privilege_type || ':' ||
       CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END
FROM (
    SELECT role, for_all_roles, object_type, grantee, privilege_type, is_grantable
    FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE public]
    UNION
    SELECT role, for_all_roles, object_type, grantee, privilege_type, is_grantable
    FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE public IN SCHEMA public]
) AS public_default
WHERE role = 'fleet_registry_successor_activation'
  AND NOT for_all_roles
  AND object_type = 'routines'
  AND grantee = 'public'
  AND privilege_type = 'EXECUTE'
  AND NOT is_grantable" | tail -n +2)
assert_exact "target creator-scoped PUBLIC routine default" \
    "$target_public_routine_defaults" \
    'fleet_registry_successor_activation:routines:public:EXECUTE:not_grantable'

default_privilege_drift=$(root_sql "
SELECT COALESCE(role, 'ALL') || ':' || object_type || ':' || grantee || ':' ||
       privilege_type || ':' ||
       CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END
FROM (
    SELECT role, for_all_roles, object_type, grantee, privilege_type, is_grantable
    FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE public]
    UNION
    SELECT role, for_all_roles, object_type, grantee, privilege_type, is_grantable
    FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE public IN SCHEMA public]
    UNION
    SELECT role, for_all_roles, object_type, grantee, privilege_type, is_grantable
    FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE fleet_registry_successor_activation]
    UNION
    SELECT role, for_all_roles, object_type, grantee, privilege_type, is_grantable
    FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE fleet_registry_successor_activation
          IN SCHEMA public]
) AS forbidden_default
WHERE object_type IN ('schemas', 'routines', 'tables', 'sequences', 'types')
  AND grantee IN ('public', 'fleet_registry_successor_activation')
  AND NOT (
      role = 'fleet_registry_successor_activation'
      AND NOT for_all_roles
      AND grantee = 'fleet_registry_successor_activation'
      AND privilege_type = 'ALL'
      AND is_grantable
  )
  AND NOT (
      grantee = 'public'
      AND object_type = 'types'
      AND privilege_type = 'USAGE'
      AND NOT is_grantable
  )
  AND NOT (
      role IS NULL
      AND for_all_roles
      AND grantee = 'public'
      AND object_type = 'routines'
      AND privilege_type = 'EXECUTE'
      AND NOT is_grantable
  )
  AND NOT (
      role = 'fleet_registry_successor_activation'
      AND NOT for_all_roles
      AND grantee = 'public'
      AND object_type = 'routines'
      AND privilege_type = 'EXECUTE'
      AND NOT is_grantable
  )
ORDER BY role, object_type, grantee, privilege_type" | tail -n +2)
assert_exact "non-intrinsic successor/PUBLIC defaults" \
    "$default_privilege_drift" ''

final_outside_target=$(audit_other_database_target_authority)
assert_exact "final external target-authority audit" \
    "$final_outside_target" ''
final_outside_public=$(inventory_other_database_public_application_authority)
assert_exact "final external PUBLIC application inventory" \
    "$final_outside_public" ''
assert_root_scalar "secondary database retained for final audit" \
    "SELECT count(*)::STRING FROM [SHOW DATABASES]
     WHERE database_name = 'proof_other_database'" '1'

# The member can evaluate only the bounded 1..14 schema gate even with later
# rows through 17 present. SQLx history remains immutable.
expect_allowed proof_successor "database/schema migration preflight" \
    "SELECT pg_catalog.current_database() = 'fleet_recall'
        AND count(*) = 14
        AND COALESCE(bool_and(success), false)
     FROM public._sqlx_migrations
     WHERE version BETWEEN 1 AND 14"
expect_allowed proof_successor "migration preflight plan" \
    "EXPLAIN SELECT pg_catalog.current_database() = 'fleet_recall'
        AND count(*) = 14
        AND COALESCE(bool_and(success), false)
     FROM public._sqlx_migrations
     WHERE version BETWEEN 1 AND 14"
expect_denied proof_successor "migration-history insert" \
    'INSERT INTO public._sqlx_migrations VALUES (18, true)'
expect_denied proof_successor "migration-history update" \
    'UPDATE public._sqlx_migrations SET success = false WHERE version = 14'
expect_denied proof_successor "migration-history delete" \
    'DELETE FROM public._sqlx_migrations WHERE version = 14'

# Exercise every allowed raw operation. INSERT/UPDATE are table-level residual
# capabilities, so this deliberately proves what a misused short-lived
# credential could do outside the reviewed repository.
for table in \
    memory_control_bootstraps \
    memory_control_events \
    memory_control_log_epochs \
    memory_control_shard_heads \
    memory_registry_activations \
    memory_registry_current_heads_v2 \
    memory_registry_genesis_bridge_consumptions \
    memory_registry_heads \
    memory_registry_transitions; do
    expect_allowed proof_successor "$table read" \
        "SELECT count(*) FROM public.$table"
done

expect_allowed proof_successor "control-event raw insert" \
    'INSERT INTO public.memory_control_events VALUES (2, 0)'
expect_allowed proof_successor "current-head raw insert" \
    'INSERT INTO public.memory_registry_current_heads_v2 VALUES (2, 0)'
expect_allowed proof_successor "bridge raw insert" \
    'INSERT INTO public.memory_registry_genesis_bridge_consumptions VALUES (2, 0)'
expect_allowed proof_successor "transition raw insert" \
    'INSERT INTO public.memory_registry_transitions VALUES (2, 0)'
expect_allowed proof_successor "control-head raw update" \
    'UPDATE public.memory_control_shard_heads SET value = value WHERE id = 1'
expect_allowed proof_successor "current-head raw update" \
    'UPDATE public.memory_registry_current_heads_v2 SET value = value WHERE id = 1'

# CockroachDB v26.2 requires UPDATE for the repository's control-head FOR UPDATE
# lock. A SELECT-only principal is denied the same lock while the successor
# member is allowed, freezing the dependency independently of the direct
# current-head UPDATE statement and grant matrix.
expect_denied proof_select_only "SELECT-only control-head lock" \
    'BEGIN; SELECT id FROM public.memory_control_shard_heads WHERE id = 1 FOR UPDATE; ROLLBACK'
expect_allowed proof_successor "successor control-head lock" \
    'BEGIN; SELECT id FROM public.memory_control_shard_heads WHERE id = 1 FOR UPDATE; ROLLBACK'

# Deny every non-granted DML category on each table.
expect_denied proof_successor "bootstrap insert" \
    'INSERT INTO public.memory_control_bootstraps VALUES (2, 0)'
expect_denied proof_successor "bootstrap update" \
    'UPDATE public.memory_control_bootstraps SET value = value WHERE false'
expect_denied proof_successor "bootstrap delete" \
    'DELETE FROM public.memory_control_bootstraps WHERE false'
expect_denied proof_successor "control-event update" \
    'UPDATE public.memory_control_events SET value = value WHERE false'
expect_denied proof_successor "control-event delete" \
    'DELETE FROM public.memory_control_events WHERE false'
expect_denied proof_successor "epoch insert" \
    'INSERT INTO public.memory_control_log_epochs VALUES (2, 0)'
expect_denied proof_successor "epoch update" \
    'UPDATE public.memory_control_log_epochs SET value = value WHERE false'
expect_denied proof_successor "epoch delete" \
    'DELETE FROM public.memory_control_log_epochs WHERE false'
expect_denied proof_successor "control-head insert" \
    'INSERT INTO public.memory_control_shard_heads VALUES (2, 0)'
expect_denied proof_successor "control-head delete" \
    'DELETE FROM public.memory_control_shard_heads WHERE false'
expect_denied proof_successor "genesis activation insert" \
    'INSERT INTO public.memory_registry_activations VALUES (2, 0)'
expect_denied proof_successor "genesis activation update" \
    'UPDATE public.memory_registry_activations SET value = value WHERE false'
expect_denied proof_successor "genesis activation delete" \
    'DELETE FROM public.memory_registry_activations WHERE false'
expect_denied proof_successor "current-head delete" \
    'DELETE FROM public.memory_registry_current_heads_v2 WHERE false'
expect_denied proof_successor "bridge update" \
    'UPDATE public.memory_registry_genesis_bridge_consumptions SET value = value WHERE false'
expect_denied proof_successor "bridge delete" \
    'DELETE FROM public.memory_registry_genesis_bridge_consumptions WHERE false'
expect_denied proof_successor "genesis head insert" \
    'INSERT INTO public.memory_registry_heads VALUES (2, 0)'
expect_denied proof_successor "genesis head update" \
    'UPDATE public.memory_registry_heads SET value = value WHERE false'
expect_denied proof_successor "genesis head delete" \
    'DELETE FROM public.memory_registry_heads WHERE false'
expect_denied proof_successor "transition update" \
    'UPDATE public.memory_registry_transitions SET value = value WHERE false'
expect_denied proof_successor "transition delete" \
    'DELETE FROM public.memory_registry_transitions WHERE false'

expect_denied proof_successor "unrelated table read" \
    'SELECT count(*) FROM public.memory_unrelated'
expect_denied proof_successor "unrelated sequence use" \
    "SELECT nextval('public.memory_unrelated_seq')"
expect_denied proof_successor "unrelated sequence state read" \
    'SELECT last_value FROM public.memory_unrelated_seq'
expect_denied proof_successor "schema creation" \
    'CREATE TABLE public.successor_escape (id INT8 PRIMARY KEY)'
expect_denied proof_successor "database creation" \
    'CREATE DATABASE successor_escape'
expect_denied proof_successor "role creation" \
    'CREATE ROLE successor_escape'
expect_denied proof_successor "grant delegation" \
    'GRANT SELECT ON TABLE public.memory_control_events TO proof_public'
expect_denied proof_successor "role-membership delegation" \
    'GRANT fleet_registry_successor_activation TO proof_public'

# Older roles retain their unrelated purpose but neither inherit nor directly
# hold successor-table authority. PUBLIC remains unprivileged.
expect_allowed proof_runtime "runtime unrelated separation" \
    'SELECT count(*) FROM public.memory_unrelated'
expect_allowed proof_bootstrap "bootstrap control separation" \
    'INSERT INTO public.memory_control_bootstraps VALUES (3, 0)'
for user in proof_runtime proof_bootstrap proof_activation proof_public; do
    expect_denied "$user" "older role successor transition read" \
        'SELECT count(*) FROM public.memory_registry_transitions'
    expect_denied "$user" "older role successor current-head insert" \
        'INSERT INTO public.memory_registry_current_heads_v2 VALUES (99, 0)'
done

# End the one-shot identity lifecycle: revoke membership, disable all login
# methods, prove the edge and exact options are gone, then prove authentication
# itself fails for the disabled identity.
root_sql '
REVOKE fleet_registry_successor_activation FROM proof_successor;
ALTER USER proof_successor WITH NOLOGIN;
' >/dev/null
assert_root_scalar "removed successor member edge" \
    "SELECT count(*)::STRING FROM [SHOW GRANTS ON ROLE]
     WHERE role_name = 'fleet_registry_successor_activation'
       AND member = 'proof_successor'" '0'
assert_root_scalar "disabled successor login options" \
    "SELECT options::STRING FROM [SHOW USERS]
     WHERE username = 'proof_successor'" '{NOLOGIN}'
if disabled_auth=$(sql_as proof_successor 'SELECT current_user' 2>&1); then
    fail "disabled successor login unexpectedly authenticated"
fi
grep -Eiq 'does not have login privilege|NOLOGIN|authentication' \
    <<<"$disabled_auth" \
    || { echo "$disabled_auth" >&2; fail "disabled login failed unexpectedly"; }

post_lifecycle_edges=$(root_sql "
SELECT role_name || ':' || member
FROM [SHOW GRANTS ON ROLE]
WHERE role_name = 'fleet_registry_successor_activation'
   OR member = 'fleet_registry_successor_activation'
ORDER BY role_name, member" | tail -n +2)
assert_exact "post-lifecycle successor role edges" \
    "$post_lifecycle_edges" ''

echo "verified effective successor-activation grants:"
root_sql "SHOW GRANTS FOR fleet_registry_successor_activation"
echo "secondary Docker successor-activation grant parity proof passed"
