#!/usr/bin/env bash
set -euo pipefail

# Secondary Docker parity only: this preserves the image-level reconciliation
# RBAC proof, but cannot substitute for the checksum-pinned official-binary
# correctness lane. Policy applications run as root, matching its cluster-admin-
# only operator contract.
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$script_dir/../../.." && pwd)
image=${FLEET_RECALL_CRDB_IMAGE:-cockroachdb/cockroach:v26.2.3}
expected_crdb_build_tag=v26.2.3
container="ostk-conflict-reconciliation-grants-$$"

cleanup() {
    docker rm --force "$container" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

fail() {
    echo "conflict-reconciliation grant proof failed: $*" >&2
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
# preflight iterates every other database for direct target grants and ownership
# that an admin must clean before applying or using the role. Production must
# freeze concurrent security/DDL changes across this snapshot and policy/use;
# this disposable proof is single-threaded.
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
            FROM [SHOW GRANTS FOR fleet_conflict_reconciliation]
            WHERE grantee = 'fleet_conflict_reconciliation'
              AND database_name = current_database()
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
                WHERE database_object.datname = current_database()
                  AND owner_role.rolname = 'fleet_conflict_reconciliation'
                UNION ALL
                SELECT 'schema_owner', schema_object.nspname, ''
                FROM pg_catalog.pg_namespace AS schema_object
                JOIN pg_catalog.pg_roles AS owner_role
                  ON owner_role.oid = schema_object.nspowner
                WHERE owner_role.rolname = 'fleet_conflict_reconciliation'
                UNION ALL
                SELECT 'relation_owner', relation_schema.nspname,
                       relation_object.relname
                FROM pg_catalog.pg_class AS relation_object
                JOIN pg_catalog.pg_namespace AS relation_schema
                  ON relation_schema.oid = relation_object.relnamespace
                JOIN pg_catalog.pg_roles AS owner_role
                  ON owner_role.oid = relation_object.relowner
                WHERE relation_object.relkind IN ('r', 'S', 'v', 'm', 'p')
                  AND owner_role.rolname = 'fleet_conflict_reconciliation'
                UNION ALL
                SELECT 'function_owner', function_schema.nspname,
                       function_object.proname
                FROM pg_catalog.pg_proc AS function_object
                JOIN pg_catalog.pg_namespace AS function_schema
                  ON function_schema.oid = function_object.pronamespace
                JOIN pg_catalog.pg_roles AS owner_role
                  ON owner_role.oid = function_object.proowner
                WHERE owner_role.rolname = 'fleet_conflict_reconciliation'
                UNION ALL
                SELECT 'type_owner', type_schema.nspname, type_object.typname
                FROM pg_catalog.pg_type AS type_object
                JOIN pg_catalog.pg_namespace AS type_schema
                  ON type_schema.oid = type_object.typnamespace
                JOIN pg_catalog.pg_roles AS owner_role
                  ON owner_role.oid = type_object.typowner
                WHERE owner_role.rolname = 'fleet_conflict_reconciliation'
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

# PUBLIC is inherited by every role. This inventory intentionally ignores the
# ordinary other-database CONNECT/TEMPORARY/schema-USAGE and virtual-schema
# fallback surface, but exposes application-object/DDL authority that a cluster
# admin must assess for exclusive database confinement.
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
              AND database_name = current_database()
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
                      current_database() = 'system'
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

apply_reconciliation_policy() {
    docker exec -i "$container" cockroach sql \
        --insecure --database fleet_recall \
        < "$repo_root/deploy/cockroach/conflict-reconciliation-role-grants.sql"
}

apply_reconciliation_policy_in_database() {
    local database=$1
    docker exec -i "$container" cockroach sql \
        --insecure --database "$database" \
        < "$repo_root/deploy/cockroach/conflict-reconciliation-role-grants.sql"
}

apply_reconciliation_policy_with_valid_temp_prefix() {
    {
        printf '%s\n' '
SET experimental_enable_temp_tables = on;
CREATE TEMP TABLE _sqlx_migrations (
    version INT8 PRIMARY KEY,
    success BOOL NOT NULL
);
INSERT INTO _sqlx_migrations
SELECT version, true FROM generate_series(1, 16) AS version;
'
        sed -n '1,$p' \
            "$repo_root/deploy/cockroach/conflict-reconciliation-role-grants.sql"
    } | docker exec -i "$container" cockroach sql \
        --insecure --database fleet_recall
}

apply_reconciliation_policy_with_temp_shadows() {
    {
        printf '%s\n' '
SET experimental_enable_temp_tables = on;
CREATE TEMP TABLE _sqlx_migrations (
    version INT8 PRIMARY KEY,
    success BOOL NOT NULL
);
INSERT INTO _sqlx_migrations VALUES (1, false);
CREATE TEMP TABLE memory_conflicts (id INT8 PRIMARY KEY);
CREATE TEMP TABLE memory_conflict_members (id INT8 PRIMARY KEY);
CREATE TEMP TABLE memory_claims (id INT8 PRIMARY KEY);
CREATE TEMP TABLE memory_claim_events (id INT8 PRIMARY KEY);
CREATE TEMP TABLE memory_claim_links (id INT8 PRIMARY KEY);
CREATE TEMP TABLE memory_mutation_receipts (id INT8 PRIMARY KEY);
CREATE TEMP TABLE memory_events (id INT8 PRIMARY KEY);
CREATE TEMP SEQUENCE memory_conflict_id_seq;
'
        sed -n '1,$p' \
            "$repo_root/deploy/cockroach/conflict-reconciliation-role-grants.sql"
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
    CAST(
        concat(
            '\''temporary PUBLIC schema baseline differs from exact CREATE/USAGE: observed='\'',
            count(*)::STRING
        )
        AS INT8
    )
) AS conflict_reconciliation_temp_public_baseline_postcondition
FROM [SHOW GRANTS FOR public]
WHERE grantee = '\''public'\''
  AND schema_name LIKE '\''pg_temp_%'\'';

SELECT IF(
    count(*) = 0,
    1:::INT8,
    CAST(
        concat(
            '\''temporary repository shadow received reconciliation grants: observed='\'',
            count(*)::STRING
        )
        AS INT8
    )
) AS conflict_reconciliation_temp_shadow_postcondition
FROM [SHOW GRANTS FOR fleet_conflict_reconciliation]
WHERE grantee = '\''fleet_conflict_reconciliation'\''
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

expect_policy_gate_failure() {
    local label=$1
    local output
    if output=$(apply_reconciliation_policy 2>&1); then
        fail "$label unexpectedly admitted the reconciliation policy"
    fi
    if ! grep -Fq \
        'conflict reconciliation role requires the complete successful migration prefix through 16' \
        <<<"$output"; then
        echo "$output" >&2
        fail "$label did not retain the exact prefix-16 failure"
    fi
}

expect_policy_gate_failure_with_valid_temp_prefix() {
    local label=$1
    local output
    if output=$(apply_reconciliation_policy_with_valid_temp_prefix 2>&1); then
        fail "$label unexpectedly admitted a valid temporary migration prefix"
    fi
    if ! grep -Fq \
        'conflict reconciliation role requires the complete successful migration prefix through 16' \
        <<<"$output"; then
        echo "$output" >&2
        fail "$label did not retain the exact public prefix-16 failure"
    fi
    if ! grep -Fq 'SQLSTATE: 55000' <<<"$output"; then
        echo "$output" >&2
        fail "$label did not retain the public prefix-gate SQLSTATE"
    fi
}

expect_policy_database_failure() {
    local label=$1
    local output
    if output=$(apply_reconciliation_policy_in_database defaultdb 2>&1); then
        fail "$label unexpectedly admitted the policy in the wrong database"
    fi
    if ! grep -Fq \
        'conflict reconciliation policy must run in fleet_recall' \
        <<<"$output"; then
        echo "$output" >&2
        fail "$label did not fail on the exact current-database preflight"
    fi
    if ! grep -Fq 'SQLSTATE: 55000' <<<"$output"; then
        echo "$output" >&2
        fail "$label did not retain the database-preflight SQLSTATE"
    fi
}

expect_policy_prerequisite_failure() {
    local label=$1
    local output
    if output=$(apply_reconciliation_policy 2>&1); then
        fail "$label unexpectedly admitted missing prior role policies"
    fi
    if ! grep -Fq \
        'conflict reconciliation role requires the three hardened prior application roles' \
        <<<"$output"; then
        echo "$output" >&2
        fail "$label did not fail on the exact prior-role preflight"
    fi
    assert_show_gate_sqlstate "$label" "$output"
}

expect_policy_default_privilege_failure() {
    local label=$1
    local output
    if output=$(apply_reconciliation_policy 2>&1); then
        fail "$label unexpectedly admitted future-object privilege drift"
    fi
    if ! grep -Fq \
        'conflict reconciliation policy permits only intrinsic PUBLIC type USAGE/all-roles routine EXECUTE, target PUBLIC routine EXECUTE, and target self-owner ALL future defaults' \
        <<<"$output"; then
        echo "$output" >&2
        fail "$label did not fail on the exact default-privilege preflight"
    fi
    assert_show_gate_sqlstate "$label" "$output"
}

expect_policy_public_system_failure() {
    local label=$1
    local output
    if output=$(apply_reconciliation_policy 2>&1); then
        fail "$label unexpectedly admitted a PUBLIC system privilege"
    fi
    if ! grep -Fq \
        'conflict reconciliation policy requires PUBLIC to have no system privileges' \
        <<<"$output"; then
        echo "$output" >&2
        fail "$label did not fail on the exact PUBLIC system-grant preflight"
    fi
    assert_show_gate_sqlstate "$label" "$output"
}

expect_policy_schema_boundary_failure() {
    local label=$1
    local output
    if output=$(apply_reconciliation_policy 2>&1); then
        fail "$label unexpectedly admitted an additional application schema"
    fi
    if ! grep -Fq \
        'conflict reconciliation policy requires public to be the only application schema' \
        <<<"$output"; then
        echo "$output" >&2
        fail "$label did not fail on the exact application-schema preflight"
    fi
}

expect_policy_grant_boundary_failure() {
    local label=$1
    local output
    if output=$(apply_reconciliation_policy 2>&1); then
        fail "$label unexpectedly admitted authority outside fleet_recall.public"
    fi
    if ! grep -Fq \
        'conflict reconciliation policy found a grant outside the repairable fleet_recall.public boundary' \
        <<<"$output"; then
        echo "$output" >&2
        fail "$label did not fail on the exact object-grant boundary preflight"
    fi
    assert_show_gate_sqlstate "$label" "$output"
}

expect_policy_role_edge_failure() {
    local label=$1
    local output
    if output=$(apply_reconciliation_policy 2>&1); then
        fail "$label unexpectedly admitted an unknown NOLOGIN role edge"
    fi
    if ! grep -Fq \
        'conflict reconciliation role has an unexpected NOLOGIN or admin-option inheritance edge' \
        <<<"$output"; then
        echo "$output" >&2
        fail "$label did not fail on the exact role-edge preflight"
    fi
    assert_show_gate_sqlstate "$label" "$output"
}

expect_policy_ownership_failure() {
    local label=$1
    local output
    if output=$(apply_reconciliation_policy 2>&1); then
        fail "$label unexpectedly admitted implicit owner authority"
    fi
    if ! grep -Fq \
        'conflict reconciliation role must not own database, schema, relation, function, or type objects' \
        <<<"$output"; then
        echo "$output" >&2
        fail "$label did not fail on the exact ownership preflight"
    fi
}

expect_policy_identity_option_failure() {
    local label=$1
    local output
    if output=$(apply_reconciliation_policy 2>&1); then
        fail "$label unexpectedly admitted a validity/provisioning role option"
    fi
    if ! grep -Fq \
        'conflict reconciliation role has a forbidden validity or provisioned-identity option' \
        <<<"$output"; then
        echo "$output" >&2
        fail "$label did not fail on the exact identity-option preflight"
    fi
    assert_show_gate_sqlstate "$label" "$output"
}

# Freeze the repository's schema dependency and SQL table surface beside the
# grants. Test-only fixture SQL is deliberately excluded from this extraction.
required_schema_version=$(sed -n \
    's/^const REQUIRED_SCHEMA_VERSION: i64 = \([0-9][0-9]*\);$/\1/p' \
    "$repo_root/src/ledger/reconciliation.rs")
assert_exact "reconciliation repository schema prefix" \
    "$required_schema_version" '16'

repository_schema_preflight=$(sed -n \
    '/^const REQUIRED_SCHEMA_PREFIX_SQL:/,/^";$/p' \
    "$repo_root/src/ledger/reconciliation.rs")
# shellcheck disable=SC2016 # Rust bind placeholders are intentional literals.
expected_repository_schema_preflight='const REQUIRED_SCHEMA_PREFIX_SQL: &str = r"
SELECT count(*) = $1
   AND min(version) = 1
   AND max(version) = $1
   AND coalesce(bool_and(success), false)
FROM _sqlx_migrations
WHERE version BETWEEN 1 AND $1
";'
assert_exact "reconciliation repository complete-prefix preflight" \
    "$repository_schema_preflight" "$expected_repository_schema_preflight"

repository_sql_tables=$(sed '/^#\[cfg(test)\]/,$d' \
    "$repo_root/src/ledger/reconciliation.rs" \
    | grep -Eio '(FROM|JOIN|INTO|UPDATE)[[:space:]\\]+memory_[a-z_]+' \
    | sed -E 's/.*[[:space:]\\]+(memory_[a-z_]+)$/\1/' \
    | sort -u)
expected_repository_sql_tables='memory_claim_events
memory_claims
memory_conflict_members
memory_conflicts
memory_events
memory_mutation_receipts'
assert_exact "reconciliation repository SQL table surface" \
    "$repository_sql_tables" "$expected_repository_sql_tables"

# CockroachDB v26.2.3 initializes every outbound-FK parent authorization while
# planning the receipt reservation INSERT, before it short-circuits omitted
# nullable keys. Freeze all three migration-defined parents: claims and
# conflicts are already direct repository reads, while links is the one exact
# indirect SELECT dependency.
receipt_fk_tables=$(sed -n \
    '/^CREATE TABLE memory_mutation_receipts (/,/^);$/p' \
    "$repo_root/migrations/0001_fleet_memory.sql" \
    | grep -Eo 'REFERENCES[[:space:]]+memory_[a-z_]+' \
    | sed -E 's/^REFERENCES[[:space:]]+//' \
    | sort -u)
expected_receipt_fk_tables='memory_claim_links
memory_claims
memory_conflicts'
assert_exact "reconciliation receipt outbound-FK SELECT dependencies" \
    "$receipt_fk_tables" "$expected_receipt_fk_tables"

repository_select_targets=$(sed '/^#\[cfg(test)\]/,$d' \
    "$repo_root/src/ledger/reconciliation.rs" \
    | grep -Eio '(FROM|JOIN)[[:space:]\\]+memory_[a-z_]+' \
    | sed -E 's/.*[[:space:]\\]+(memory_[a-z_]+)$/\1/' \
    | sort -u)
expected_repository_select_targets='memory_claim_events
memory_claims
memory_conflict_members
memory_conflicts
memory_mutation_receipts'
assert_exact "reconciliation repository direct SELECT targets" \
    "$repository_select_targets" "$expected_repository_select_targets"

repository_insert_targets=$(sed '/^#\[cfg(test)\]/,$d' \
    "$repo_root/src/ledger/reconciliation.rs" \
    | grep -Eio 'INTO[[:space:]\\]+memory_[a-z_]+' \
    | sed -E 's/.*[[:space:]\\]+(memory_[a-z_]+)$/\1/' \
    | sort -u)
expected_repository_insert_targets='memory_claim_events
memory_conflict_members
memory_conflicts
memory_events
memory_mutation_receipts'
assert_exact "reconciliation repository INSERT targets" \
    "$repository_insert_targets" "$expected_repository_insert_targets"

repository_update_targets=$(sed '/^#\[cfg(test)\]/,$d' \
    "$repo_root/src/ledger/reconciliation.rs" \
    | grep -Eio 'UPDATE[[:space:]\\]+memory_[a-z_]+' \
    | sed -E 's/.*[[:space:]\\]+(memory_[a-z_]+)$/\1/' \
    | sort -u)
expected_repository_update_targets='memory_claims
memory_mutation_receipts'
assert_exact "reconciliation repository UPDATE targets" \
    "$repository_update_targets" "$expected_repository_update_targets"

repository_delete_targets=$(sed '/^#\[cfg(test)\]/,$d' \
    "$repo_root/src/ledger/reconciliation.rs" \
    | { grep -Eio 'DELETE[[:space:]\\]+FROM[[:space:]\\]+memory_[a-z_]+' || true; } \
    | sed -E 's/.*[[:space:]\\]+(memory_[a-z_]+)$/\1/' \
    | sort -u)
assert_exact "reconciliation repository DELETE targets" \
    "$repository_delete_targets" ''

role_option_hardening=$(sed -n \
    '/^ALTER ROLE fleet_conflict_reconciliation WITH$/,/^    NOVIEWCLUSTERSETTING;$/p' \
    "$repo_root/deploy/cockroach/conflict-reconciliation-role-grants.sql")
expected_role_option_hardening='ALTER ROLE fleet_conflict_reconciliation WITH
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

# The policy must pin built-in resolution before any gate, and every
# repository relation reference must remain schema-qualified even though
# pg_temp is explicitly placed last. This freezes both defenses against a
# reused administrator session with temporary shadow objects.
policy_first_statement=$(awk '
    /^[[:space:]]*--/ || /^[[:space:]]*$/ { next }
    { print; exit }
' "$repo_root/deploy/cockroach/conflict-reconciliation-role-grants.sql")
assert_exact "reconciliation policy first statement" \
    "$policy_first_statement" 'SET search_path = pg_catalog, public, pg_temp;'

unqualified_policy_application_references=$(sed -E 's/--.*$//' \
    "$repo_root/deploy/cockroach/conflict-reconciliation-role-grants.sql" \
    | grep -En \
        '(FROM|ON TABLE|ON SEQUENCE)[[:space:]]+(_sqlx_migrations|memory_(claims|claim_events|claim_links|conflicts|conflict_members|mutation_receipts|events|conflict_id_seq))([^[:alnum:]_]|$)' \
        || true)
assert_exact "unqualified reconciliation policy application references" \
    "$unqualified_policy_application_references" ''

qualified_policy_application_references=$(sed -E 's/--.*$//' \
    "$repo_root/deploy/cockroach/conflict-reconciliation-role-grants.sql" \
    | grep -Eo \
        '(FROM|ON TABLE|ON SEQUENCE)[[:space:]]+public\.(_sqlx_migrations|memory_(claims|claim_events|claim_links|conflicts|conflict_members|mutation_receipts|events|conflict_id_seq))' \
    | sed -E 's/^(FROM|ON TABLE|ON SEQUENCE)[[:space:]]+//' \
    | sort)
expected_qualified_policy_application_references='public._sqlx_migrations
public._sqlx_migrations
public.memory_claim_events
public.memory_claim_links
public.memory_claims
public.memory_conflict_id_seq
public.memory_conflict_members
public.memory_conflicts
public.memory_events
public.memory_mutation_receipts'
assert_exact "fully qualified reconciliation policy application references" \
    "$qualified_policy_application_references" \
    "$expected_qualified_policy_application_references"

current_database_preflight=$(grep -F \
    "IF pg_catalog.current_database() <> 'fleet_recall' THEN" \
    "$repo_root/deploy/cockroach/conflict-reconciliation-role-grants.sql")
assert_exact "fleet_recall current-database preflight" \
    "$current_database_preflight" \
    "    IF pg_catalog.current_database() <> 'fleet_recall' THEN"

# CockroachDB v26.2 rejects delegated SHOW statements inside PL/pgSQL function
# bodies. Keep every SHOW-backed gate at statement scope; catalog-only DO
# blocks remain valid and retain their explicit SQLSTATE 55000 failures.
unsupported_query_in_function_body=$(awk '
    /^DO \$\$/ { in_function_body = 1 }
    in_function_body && ($0 ~ /\[SHOW[[:space:]]/ || $0 ~ /^[[:space:]]*SHOW[[:space:]]/ || $0 ~ /crdb_internal\./ || $0 ~ /information_schema\./) { print NR ":" $0 }
    in_function_body && /^\$\$;$/ { in_function_body = 0 }
' "$repo_root/deploy/cockroach/conflict-reconciliation-role-grants.sql")
assert_exact "SHOW/virtual-table-free reconciliation policy function bodies" \
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

# Privilege-shaped minimal stand-ins keep this proof focused on the role
# boundary; this script does not claim repository-correctness execution. The
# current indexes used by reconciliation are present, while
# unrelated control, registry, successor, and corpus objects make denial and
# drift-repair assertions concrete.
root_sql '
CREATE TABLE _sqlx_migrations (
    version INT8 PRIMARY KEY,
    success BOOL NOT NULL
);

CREATE SEQUENCE memory_claim_id_seq START 1 MINVALUE 1 MAXVALUE 9007199254740991;
CREATE SEQUENCE memory_conflict_id_seq START 1 MINVALUE 1 MAXVALUE 9007199254740991;

CREATE TABLE memory_claims (
    tenant_id UUID NOT NULL,
    project STRING NOT NULL,
    id INT8 NOT NULL DEFAULT nextval('"'"'memory_claim_id_seq'"'"'),
    claim_key STRING,
    state STRING NOT NULL DEFAULT '"'"'active'"'"',
    revision INT8 NOT NULL DEFAULT 1,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, project, id)
);
CREATE INDEX memory_claims_scope_key_idx
    ON memory_claims (tenant_id, project, claim_key, state);

CREATE TABLE memory_conflicts (
    tenant_id UUID NOT NULL,
    project STRING NOT NULL,
    id INT8 NOT NULL DEFAULT nextval('"'"'memory_conflict_id_seq'"'"'),
    claim_key STRING NOT NULL,
    kind STRING NOT NULL DEFAULT '"'"'contradiction'"'"',
    state STRING NOT NULL DEFAULT '"'"'open'"'"',
    detector STRING NOT NULL,
    rationale STRING NOT NULL,
    revision INT8 NOT NULL DEFAULT 1,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at TIMESTAMPTZ,
    resolution_kind STRING,
    resolution_reason STRING,
    PRIMARY KEY (tenant_id, project, id)
);
CREATE UNIQUE INDEX memory_conflicts_scope_key_detector_unique_idx
    ON memory_conflicts (tenant_id, project, claim_key, detector);

CREATE TABLE memory_conflict_members (
    tenant_id UUID NOT NULL,
    project STRING NOT NULL,
    conflict_id INT8 NOT NULL,
    claim_id INT8 NOT NULL,
    role STRING NOT NULL DEFAULT '"'"'claim'"'"',
    PRIMARY KEY (tenant_id, project, conflict_id, claim_id),
    FOREIGN KEY (tenant_id, project, conflict_id)
        REFERENCES memory_conflicts (tenant_id, project, id),
    FOREIGN KEY (tenant_id, project, claim_id)
        REFERENCES memory_claims (tenant_id, project, id)
);
CREATE INDEX memory_conflict_members_claim_idx
    ON memory_conflict_members (tenant_id, project, claim_id, conflict_id);

CREATE TABLE memory_claim_events (
    tenant_id UUID NOT NULL,
    project STRING NOT NULL,
    event_id UUID NOT NULL DEFAULT gen_random_uuid(),
    claim_id INT8 NOT NULL,
    event_kind STRING NOT NULL,
    actor STRING,
    reason STRING,
    from_state STRING,
    to_state STRING,
    payload JSONB NOT NULL DEFAULT '"'"'{}'"'"'::JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, project, event_id),
    FOREIGN KEY (tenant_id, project, claim_id)
        REFERENCES memory_claims (tenant_id, project, id)
);
CREATE INDEX memory_claim_events_transition_provenance_idx
    ON memory_claim_events (
        tenant_id, project, claim_id, event_kind, created_at DESC, event_id DESC
    ) STORING (reason, from_state, to_state, payload);

CREATE TABLE memory_claim_links (
    tenant_id UUID NOT NULL,
    project STRING NOT NULL,
    id INT8 NOT NULL,
    PRIMARY KEY (tenant_id, project, id)
);

CREATE TABLE memory_mutation_receipts (
    tenant_id UUID NOT NULL,
    idempotency_key STRING NOT NULL,
    project STRING NOT NULL,
    request JSONB NOT NULL,
    operation STRING NOT NULL,
    claim_id INT8,
    conflict_id INT8,
    link_id INT8,
    response JSONB,
    PRIMARY KEY (tenant_id, idempotency_key),
    FOREIGN KEY (tenant_id, project, claim_id)
        REFERENCES memory_claims (tenant_id, project, id),
    FOREIGN KEY (tenant_id, project, conflict_id)
        REFERENCES memory_conflicts (tenant_id, project, id),
    FOREIGN KEY (tenant_id, project, link_id)
        REFERENCES memory_claim_links (tenant_id, project, id)
);

CREATE TABLE memory_events (
    tenant_id UUID NOT NULL,
    project STRING NOT NULL,
    event_id UUID NOT NULL DEFAULT gen_random_uuid(),
    agent STRING NOT NULL,
    session_id STRING,
    event_kind STRING NOT NULL,
    entity_kind STRING NOT NULL,
    entity_id STRING NOT NULL,
    idempotency_key STRING,
    payload JSONB NOT NULL DEFAULT '"'"'{}'"'"'::JSONB,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, project, event_id)
);

CREATE TABLE memory_chunks (id INT8 PRIMARY KEY);
CREATE TABLE memory_corpus_models (id INT8 PRIMARY KEY);
CREATE TABLE memory_control_events (id INT8 PRIMARY KEY);
CREATE TABLE memory_registry_activations (id INT8 PRIMARY KEY);
CREATE TABLE memory_registry_transitions (id INT8 PRIMARY KEY);
CREATE TABLE memory_registry_genesis_bridge_consumptions (id INT8 PRIMARY KEY);
CREATE TABLE memory_registry_current_heads_v2 (id INT8 PRIMARY KEY);

CREATE ROLE fleet_runtime;
CREATE ROLE fleet_control_bootstrap;
ALTER ROLE fleet_runtime WITH NOLOGIN NOCREATEROLE NOCREATEDB;
ALTER ROLE fleet_control_bootstrap WITH NOLOGIN NOCREATEROLE NOCREATEDB;

CREATE USER proof_database_owner;
CREATE USER proof_runtime;
CREATE USER proof_bootstrap;
CREATE USER proof_activation;
CREATE USER proof_reconciliation;
CREATE USER proof_public;
ALTER DATABASE fleet_recall OWNER TO proof_database_owner;

GRANT CONNECT ON DATABASE fleet_recall
    TO fleet_runtime, fleet_control_bootstrap, proof_public;
GRANT USAGE ON SCHEMA public
    TO fleet_runtime, fleet_control_bootstrap, proof_public;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE
    memory_claims,
    memory_claim_events,
    memory_conflicts,
    memory_conflict_members,
    memory_claim_links,
    memory_mutation_receipts,
    memory_events
TO fleet_runtime;
GRANT SELECT ON TABLE _sqlx_migrations TO fleet_runtime;
GRANT USAGE, SELECT ON SEQUENCE
    memory_claim_id_seq,
    memory_conflict_id_seq
TO fleet_runtime;
GRANT SELECT ON TABLE memory_chunks TO fleet_runtime;
GRANT INSERT ON TABLE memory_control_events TO fleet_control_bootstrap;

INSERT INTO _sqlx_migrations
SELECT version, true FROM generate_series(1, 15) AS version;
INSERT INTO memory_claims (tenant_id, project, id, claim_key, state, revision)
VALUES (
    '"'"'0198a849-f6ae-7d61-9800-000000000001'"'"',
    '"'"'reconciliation-grant-proof'"'"', 1, '"'"'fleet-store::database-choice'"'"',
    '"'"'active'"'"', 1
);
GRANT SELECT ON TABLE memory_chunks TO public;
' >/dev/null

# Snapshot the representative deployed runtime overlap. Reconciliation is the
# supported least-privilege one-shot credential, but the serving role keeps its
# direct legacy-ledger DML because remember depends on it.
runtime_ledger_grants_before=$(root_sql "
SELECT object_type || ':' || object_name || ':' || privilege_type || ':' ||
       CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END AS normalized
FROM [SHOW GRANTS FOR fleet_runtime]
WHERE database_name = 'fleet_recall'
  AND schema_name = 'public'
  AND object_name IN (
      '_sqlx_migrations',
      'memory_claims',
      'memory_claim_events',
      'memory_conflicts',
      'memory_conflict_members',
      'memory_claim_links',
      'memory_mutation_receipts',
      'memory_events',
      'memory_claim_id_seq',
      'memory_conflict_id_seq'
  )
ORDER BY object_type, object_name, privilege_type" | tail -n +2)

# The policy's first persistent gate binds every catalog/default/reset query to
# fleet_recall. Running it in another database may change only that SQL
# session's search_path; it must neither create the target role nor touch the
# pre-existing database-local PUBLIC grant.
expect_policy_database_failure "wrong current database"
assert_root_scalar "wrong-database target role creation" \
    "SELECT count(*)::STRING FROM [SHOW USERS]
     WHERE username = 'fleet_conflict_reconciliation'" '0'
wrong_database_public_grant_after_failure=$(
    root_sql_in_database defaultdb \
        "SELECT count(*)::STRING FROM [SHOW GRANTS ON SCHEMA public]
         WHERE grantee = 'public'
           AND privilege_type = 'CREATE'" \
        | tail -n +2
)
assert_exact "wrong-database PUBLIC grant preservation" \
    "$wrong_database_public_grant_after_failure" '1'

# Prefix 15 and a present-but-failed migration 16 both fail before the role is
# created or the pre-existing PUBLIC drift is touched. A valid temporary
# migration-history shadow cannot mask either bad real public prefix.
expect_policy_gate_failure "prefix 15"
expect_policy_gate_failure_with_valid_temp_prefix \
    "prefix 15 with valid temporary prefix"
assert_root_scalar "prefix-15 role creation" \
    "SELECT count(*)::STRING FROM [SHOW USERS]
     WHERE username = 'fleet_conflict_reconciliation'" '0'
assert_root_scalar "prefix-15 PUBLIC grant preservation" \
    "SELECT count(*)::STRING FROM [SHOW GRANTS ON TABLE memory_chunks]
     WHERE grantee = 'public' AND privilege_type = 'SELECT'" '1'

root_sql 'INSERT INTO _sqlx_migrations VALUES (16, false)' >/dev/null
expect_policy_gate_failure "failed migration 16"
expect_policy_gate_failure_with_valid_temp_prefix \
    "failed migration 16 with valid temporary prefix"
assert_root_scalar "failed-16 role creation" \
    "SELECT count(*)::STRING FROM [SHOW USERS]
     WHERE username = 'fleet_conflict_reconciliation'" '0'
assert_root_scalar "failed-16 PUBLIC grant preservation" \
    "SELECT count(*)::STRING FROM [SHOW GRANTS ON TABLE memory_chunks]
     WHERE grantee = 'public' AND privilege_type = 'SELECT'" '1'

root_sql 'UPDATE _sqlx_migrations SET success = true WHERE version = 16' >/dev/null
expect_policy_prerequisite_failure "missing registry-activation role policy"
assert_root_scalar "missing-prerequisite role creation" \
    "SELECT count(*)::STRING FROM [SHOW USERS]
     WHERE username = 'fleet_conflict_reconciliation'" '0'
root_sql '
CREATE ROLE fleet_registry_activation;
ALTER ROLE fleet_registry_activation WITH LOGIN CREATEROLE;
GRANT CONNECT ON DATABASE fleet_recall TO fleet_registry_activation;
GRANT USAGE ON SCHEMA public TO fleet_registry_activation;
GRANT INSERT ON TABLE memory_registry_activations TO fleet_registry_activation;
' >/dev/null
expect_policy_prerequisite_failure "drifted registry-activation role options"
assert_root_scalar "drifted prerequisite option preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW USERS] AS prior_role
     CROSS JOIN LATERAL unnest(prior_role.options) AS role_option(option_name)
     WHERE prior_role.username = 'fleet_registry_activation'
       AND role_option.option_name = 'CREATEROLE'" '1'
assert_root_scalar "drifted-prerequisite target role creation" \
    "SELECT count(*)::STRING FROM [SHOW USERS]
     WHERE username = 'fleet_conflict_reconciliation'" '0'
root_sql '
ALTER ROLE fleet_registry_activation WITH NOLOGIN NOCREATEROLE NOCREATEDB;
' >/dev/null

# CockroachDB release-26.2 synthesizes PUBLIC routine EXECUTE for every role
# and FOR ALL ROLES. Enumerate every pre-existing fixture role as the operator
# precondition; temporary root membership supplies the authority to alter each
# role's defaults and is removed before any reconciliation policy call. The
# attempted all-roles revoke is intentionally retained: with the clean fixture
# descriptor, v26.2.3 accepts it and synthesizes one exact non-grantable row,
# which is frozen below.
root_sql '
GRANT
    fleet_runtime,
    fleet_control_bootstrap,
    fleet_registry_activation,
    proof_database_owner,
    proof_runtime,
    proof_bootstrap,
    proof_activation,
    proof_reconciliation,
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
    proof_reconciliation,
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
    proof_reconciliation,
    proof_public
FROM root;
' >/dev/null
assert_root_scalar "temporary default-cleanup memberships" \
    "SELECT count(*)::STRING
     FROM [SHOW GRANTS ON ROLE]
     WHERE member = 'root'
       AND role_name IN (
           'fleet_runtime',
           'fleet_control_bootstrap',
           'fleet_registry_activation',
           'proof_database_owner',
           'proof_runtime',
           'proof_bootstrap',
           'proof_activation',
           'proof_reconciliation',
           'proof_public'
       )" '0'
assert_root_scalar "fixture intrinsic all-roles routine default" \
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
expect_policy_public_system_failure "PUBLIC CREATEROLE system grant"
assert_root_scalar "PUBLIC-system target role creation" \
    "SELECT count(*)::STRING FROM [SHOW USERS]
     WHERE username = 'fleet_conflict_reconciliation'" '0'
assert_root_scalar "failed PUBLIC-system preflight preservation" \
    "SELECT count(*)::STRING FROM [SHOW SYSTEM GRANTS]
     WHERE grantee = 'public'
       AND privilege_type = 'CREATEROLE'
       AND NOT is_grantable" '1'
root_sql 'REVOKE SYSTEM CREATEROLE FROM public' >/dev/null
sql_as proof_database_owner '
ALTER DEFAULT PRIVILEGES FOR ROLE proof_database_owner
    GRANT SELECT ON TABLES TO public;
ALTER DEFAULT PRIVILEGES FOR ROLE proof_database_owner
    GRANT EXECUTE ON ROUTINES TO public;
' >/dev/null
expect_policy_default_privilege_failure \
    "grantor-specific PUBLIC table and routine defaults"
assert_root_scalar "default-privilege target role creation" \
    "SELECT count(*)::STRING FROM [SHOW USERS]
     WHERE username = 'fleet_conflict_reconciliation'" '0'
assert_root_scalar "failed default-privilege preflight preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE public]
     WHERE role = 'proof_database_owner'
       AND NOT for_all_roles
       AND object_type = 'tables'
       AND grantee = 'public'
       AND privilege_type = 'SELECT'" '1'
assert_root_scalar "failed PUBLIC routine-default preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE public]
     WHERE role = 'proof_database_owner'
       AND NOT for_all_roles
       AND object_type = 'routines'
       AND grantee = 'public'
       AND privilege_type = 'EXECUTE'
       AND NOT is_grantable" '1'
sql_as proof_database_owner '
ALTER DEFAULT PRIVILEGES FOR ROLE proof_database_owner
    REVOKE SELECT ON TABLES FROM public;
ALTER DEFAULT PRIVILEGES FOR ROLE proof_database_owner
    REVOKE EXECUTE ON ROUTINES FROM public;
' >/dev/null

# The SQL file can normalize object authority only in fleet_recall. Before its
# first successful apply, freeze and remove the stock cluster's out-of-contract
# PUBLIC DDL/data authority so the fixture does not silently filter ambient
# rows. Direct target authority is vacuous while the target role is absent.
assert_root_scalar "external-audit bootstrap target absence" \
    "SELECT count(*)::STRING FROM [SHOW USERS]
     WHERE username = 'fleet_conflict_reconciliation'" '0'
initial_outside_public_application_authority=$(
    inventory_other_database_public_application_authority
)
expected_initial_outside_public_application_authority='defaultdb:schema:public::CREATE:not_grantable
postgres:schema:public::CREATE:not_grantable'
assert_exact "initial external PUBLIC application-authority inventory" \
    "$initial_outside_public_application_authority" \
    "$expected_initial_outside_public_application_authority"
root_sql_in_database defaultdb \
    'REVOKE CREATE ON SCHEMA public FROM public' >/dev/null
root_sql_in_database postgres \
    'REVOKE CREATE ON SCHEMA public FROM public' >/dev/null
hardened_initial_outside_public_application_authority=$(
    inventory_other_database_public_application_authority
)
assert_exact "hardened initial external PUBLIC application inventory" \
    "$hardened_initial_outside_public_application_authority" ''

apply_reconciliation_policy >/dev/null
assert_root_scalar "clean first-apply target creation" \
    "SELECT count(*)::STRING FROM [SHOW USERS]
     WHERE username = 'fleet_conflict_reconciliation'
       AND options::STRING = '{NOLOGIN}'" '1'
bootstrap_outside_target_authority=$(audit_other_database_target_authority)
assert_exact "post-create external target-authority audit" \
    "$bootstrap_outside_target_authority" ''
bootstrap_outside_public_application_authority=$(
    inventory_other_database_public_application_authority
)
assert_exact "post-create external PUBLIC application inventory" \
    "$bootstrap_outside_public_application_authority" ''

# The SQL file can normalize object authority only in fleet_recall. Model the
# required cluster-admin deployment preflight against a second database: direct
# target and inherited PUBLIC application grants are both inventoried without
# mutation, then explicitly cleaned before policy reapplication or role use.
root_sql 'CREATE DATABASE proof_other_database' >/dev/null
root_sql_in_database proof_other_database '
CREATE TABLE proof_other_ledger (id INT8 PRIMARY KEY);
CREATE TABLE proof_other_owned (id INT8 PRIMARY KEY);
GRANT SELECT ON TABLE proof_other_ledger
    TO fleet_conflict_reconciliation, public;
GRANT CREATE ON SCHEMA public TO fleet_conflict_reconciliation;
ALTER TABLE proof_other_owned OWNER TO fleet_conflict_reconciliation;
REVOKE CREATE ON SCHEMA public FROM fleet_conflict_reconciliation;
' >/dev/null
outside_target_authority=$(audit_other_database_target_authority)
assert_exact "external target-authority audit" \
    "$outside_target_authority" \
    'proof_other_database:grant:table:public:proof_other_ledger:SELECT:not_grantable
proof_other_database:grant:table:public:proof_other_owned:ALL:grantable
proof_other_database:relation_owner:public:proof_other_owned
proof_other_database:type_owner:public:proof_other_owned'
outside_public_application_authority=$(
    inventory_other_database_public_application_authority
)
assert_exact "external PUBLIC application-authority inventory" \
    "$outside_public_application_authority" \
    'proof_other_database:schema:public::CREATE:not_grantable
proof_other_database:table:public:proof_other_ledger:SELECT:not_grantable'
other_database_drift_after_audit=$(root_sql_in_database proof_other_database "
SELECT grantee || ':' || privilege_type
FROM [SHOW GRANTS ON TABLE proof_other_ledger]
WHERE grantee IN ('fleet_conflict_reconciliation', 'public')
  AND privilege_type = 'SELECT'
ORDER BY grantee" | tail -n +2)
assert_exact "read-only external audit preservation" \
    "$other_database_drift_after_audit" \
    'fleet_conflict_reconciliation:SELECT
public:SELECT'
other_database_ownership_after_audit=$(root_sql_in_database proof_other_database "
SELECT count(*)::STRING
FROM pg_catalog.pg_class AS relation_object
JOIN pg_catalog.pg_namespace AS relation_schema
  ON relation_schema.oid = relation_object.relnamespace
JOIN pg_catalog.pg_roles AS owner_role
  ON owner_role.oid = relation_object.relowner
WHERE relation_object.relkind = 'r'
  AND relation_schema.nspname = 'public'
  AND relation_object.relname = 'proof_other_owned'
  AND owner_role.rolname = 'fleet_conflict_reconciliation'" | tail -n +2)
assert_exact "read-only external ownership audit preservation" \
    "$other_database_ownership_after_audit" '1'
root_sql_in_database proof_other_database '
ALTER TABLE proof_other_owned OWNER TO root;
REVOKE SELECT ON TABLE proof_other_ledger
    FROM fleet_conflict_reconciliation, public;
REVOKE CREATE ON SCHEMA public FROM public;
' >/dev/null
clean_outside_target_authority=$(audit_other_database_target_authority)
assert_exact "clean external target-authority precondition" \
    "$clean_outside_target_authority" ''
clean_outside_public_application_authority=$(
    inventory_other_database_public_application_authority
)
assert_exact "clean external PUBLIC application inventory" \
    "$clean_outside_public_application_authority" ''
apply_reconciliation_policy >/dev/null

# Reapply in one reused session whose temporary schema shadows migration
# history and every repository grant target. The deliberately failed temporary
# history must not reject the valid public prefix, no grant may land on a temp
# object, and the real public migration table must retain its exact grant.
apply_reconciliation_policy_with_temp_shadows >/dev/null
assert_root_scalar "temp-shadow public migration-history grant" \
    "SELECT count(*)::STRING
     FROM [SHOW GRANTS ON TABLE public._sqlx_migrations]
     WHERE grantee = 'fleet_conflict_reconciliation'
       AND privilege_type = 'SELECT'
       AND NOT is_grantable" '1'

# Database ownership alone cannot modify the cluster role boundary.
expect_denied proof_database_owner "database owner role-option hardening" \
    'ALTER ROLE fleet_conflict_reconciliation WITH NOLOGIN NOCREATEROLE NOCREATEDB'
expect_denied proof_database_owner "database owner membership cleanup" \
    'REVOKE admin FROM fleet_conflict_reconciliation'
expect_denied proof_database_owner "database owner system-grant cleanup" \
    'REVOKE SYSTEM ALL FROM fleet_conflict_reconciliation'

# VALID UNTIL is visible but has no portable exact-value reset, and provisioned
# identity options are system-managed and unremovable. The policy fails before
# normalizing an independently injected CONTROLJOB option. This fixture resolves
# the invalid logical identity by removing its grants, replacing the role, and
# reapplying. PASSWORD drift cannot be created on an insecure server; NOLOGIN's
# all-authentication-method denial is frozen by the final exact option audit.
root_sql "
ALTER ROLE fleet_conflict_reconciliation WITH
    CONTROLJOB
    VALID UNTIL '2035-01-01 00:00:00+00:00';
" >/dev/null
expect_policy_identity_option_failure "VALID UNTIL role drift"
assert_root_scalar "failed identity-option preflight preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW USERS] AS target_role
     CROSS JOIN LATERAL unnest(target_role.options) AS role_option(option_name)
     WHERE target_role.username = 'fleet_conflict_reconciliation'
       AND (
           role_option.option_name = 'CONTROLJOB'
           OR role_option.option_name LIKE 'VALID UNTIL=%'
       )" '2'
root_sql '
REVOKE ALL ON DATABASE fleet_recall FROM fleet_conflict_reconciliation;
REVOKE ALL ON SCHEMA public FROM fleet_conflict_reconciliation;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM fleet_conflict_reconciliation;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM fleet_conflict_reconciliation;
DROP ROLE fleet_conflict_reconciliation;
' >/dev/null
apply_reconciliation_policy >/dev/null

# Inject direct privilege/grant-option drift and the first inheritance direction.
# Mark migration 16 failed once more after the role exists to prove the gate
# still leaves every drifted property untouched.
root_sql '
ALTER ROLE fleet_conflict_reconciliation WITH
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
    TO fleet_conflict_reconciliation;
GRANT SYSTEM CREATEROLE TO fleet_conflict_reconciliation;
GRANT ALL ON DATABASE fleet_recall TO fleet_conflict_reconciliation;
GRANT ALL ON SCHEMA public TO fleet_conflict_reconciliation;
GRANT DELETE ON TABLE memory_conflicts
    TO fleet_conflict_reconciliation WITH GRANT OPTION;
GRANT SELECT ON TABLE memory_chunks
    TO fleet_conflict_reconciliation WITH GRANT OPTION;
GRANT SELECT ON SEQUENCE memory_claim_id_seq
    TO fleet_conflict_reconciliation WITH GRANT OPTION;
GRANT ALL ON DATABASE fleet_recall TO public;
GRANT ALL ON SCHEMA public TO public;
GRANT ALL ON ALL TABLES IN SCHEMA public TO public;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO public;
UPDATE _sqlx_migrations SET success = false WHERE version = 16;
' >/dev/null
expect_policy_gate_failure "drifted role with failed migration 16"
assert_root_scalar "failed-gate LOGIN drift preservation" \
    "SELECT count(*)::STRING FROM [SHOW USERS]
     WHERE username = 'fleet_conflict_reconciliation'
       AND 'NOLOGIN' != ALL(options)" '1'
assert_root_scalar "failed-gate direct role-option preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW USERS] AS target_role
     CROSS JOIN LATERAL unnest(target_role.options) AS role_option(option_name)
     WHERE target_role.username = 'fleet_conflict_reconciliation'
       AND role_option.option_name IN (
           'BYPASSRLS',
           'CANCELQUERY',
           'CONTROLCHANGEFEED',
           'CONTROLJOB',
           'CREATEDB',
           'CREATELOGIN',
           'CREATEROLE',
           'MODIFYCLUSTERSETTING',
           'REPLICATION',
           'NOSQLLOGIN',
           'VIEWACTIVITY',
           'VIEWACTIVITYREDACTED',
           'VIEWCLUSTERSETTING'
       )" '13'
assert_root_scalar "failed-gate grant-option preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW GRANTS ON TABLE memory_conflicts]
     WHERE grantee = 'fleet_conflict_reconciliation'
       AND privilege_type = 'DELETE'
       AND is_grantable" '1'

# A later migration 17 does not mask a failed prerequisite, but it is admitted
# once the exact prefix through 16 is restored. Reapply twice for idempotence.
root_sql '
UPDATE _sqlx_migrations SET success = true WHERE version = 16;
INSERT INTO _sqlx_migrations VALUES (17, true);
' >/dev/null
apply_reconciliation_policy >/dev/null
apply_reconciliation_policy >/dev/null

# Future-object drift is checked across grantors before target-role options or
# current-object grants are touched. Remove the exact default row, then reapply
# to normalize the independently injected CONTROLJOB option.
root_sql '
ALTER ROLE fleet_conflict_reconciliation WITH CONTROLJOB;
' >/dev/null
sql_as proof_database_owner '
ALTER DEFAULT PRIVILEGES FOR ROLE proof_database_owner IN SCHEMA public
    GRANT SELECT ON SEQUENCES TO fleet_conflict_reconciliation;
' >/dev/null
expect_policy_default_privilege_failure "reconciliation sequence default privilege"
assert_root_scalar "target default-privilege preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE fleet_conflict_reconciliation
           IN SCHEMA public]
     WHERE role = 'proof_database_owner'
       AND NOT for_all_roles
       AND object_type = 'sequences'
       AND grantee = 'fleet_conflict_reconciliation'
       AND privilege_type = 'SELECT'" '1'
assert_root_scalar "default-gate role-option preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW USERS] AS target_role
     CROSS JOIN LATERAL unnest(target_role.options) AS role_option(option_name)
     WHERE target_role.username = 'fleet_conflict_reconciliation'
       AND role_option.option_name = 'CONTROLJOB'" '1'
sql_as proof_database_owner '
ALTER DEFAULT PRIVILEGES FOR ROLE proof_database_owner IN SCHEMA public
    REVOKE SELECT ON SEQUENCES FROM fleet_conflict_reconciliation;
' >/dev/null
apply_reconciliation_policy >/dev/null

# New-schema access, routine execution, and noncanonical type usage are future
# authority too. Inject all three from the independently authenticated database
# owner, including public-schema routine/type defaults, and prove the gate
# preserves unrelated role-option drift before the operator removes exact rows.
root_sql 'ALTER ROLE fleet_conflict_reconciliation WITH CONTROLJOB' >/dev/null
sql_as proof_database_owner '
ALTER DEFAULT PRIVILEGES FOR ROLE proof_database_owner
    GRANT USAGE ON SCHEMAS TO fleet_conflict_reconciliation;
ALTER DEFAULT PRIVILEGES FOR ROLE proof_database_owner IN SCHEMA public
    GRANT EXECUTE ON ROUTINES TO fleet_conflict_reconciliation;
ALTER DEFAULT PRIVILEGES FOR ROLE proof_database_owner IN SCHEMA public
    GRANT USAGE ON TYPES TO fleet_conflict_reconciliation WITH GRANT OPTION;
' >/dev/null
expect_policy_default_privilege_failure \
    "arbitrary-grantor schema and routine default privileges"
assert_root_scalar "schema default-privilege preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE fleet_conflict_reconciliation]
     WHERE role = 'proof_database_owner'
       AND NOT for_all_roles
       AND object_type = 'schemas'
       AND grantee = 'fleet_conflict_reconciliation'
       AND privilege_type = 'USAGE'
       AND NOT is_grantable" '1'
assert_root_scalar "routine default-privilege preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE fleet_conflict_reconciliation
           IN SCHEMA public]
     WHERE role = 'proof_database_owner'
       AND NOT for_all_roles
       AND object_type = 'routines'
       AND grantee = 'fleet_conflict_reconciliation'
       AND privilege_type = 'EXECUTE'
       AND NOT is_grantable" '1'
assert_root_scalar "target type default-privilege preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE fleet_conflict_reconciliation
           IN SCHEMA public]
     WHERE role = 'proof_database_owner'
       AND NOT for_all_roles
       AND object_type = 'types'
       AND grantee = 'fleet_conflict_reconciliation'
       AND privilege_type = 'USAGE'
       AND is_grantable" '1'
assert_root_scalar "future-object gate role-option preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW USERS] AS target_role
     CROSS JOIN LATERAL unnest(target_role.options) AS role_option(option_name)
     WHERE target_role.username = 'fleet_conflict_reconciliation'
       AND role_option.option_name = 'CONTROLJOB'" '1'
sql_as proof_database_owner '
ALTER DEFAULT PRIVILEGES FOR ROLE proof_database_owner
    REVOKE USAGE ON SCHEMAS FROM fleet_conflict_reconciliation;
ALTER DEFAULT PRIVILEGES FOR ROLE proof_database_owner IN SCHEMA public
    REVOKE EXECUTE ON ROUTINES FROM fleet_conflict_reconciliation;
ALTER DEFAULT PRIVILEGES FOR ROLE proof_database_owner IN SCHEMA public
    REVOKE USAGE ON TYPES FROM fleet_conflict_reconciliation;
' >/dev/null
apply_reconciliation_policy >/dev/null

# The reverse named inheritance direction is acyclic after the first repair and
# must also be removed on reapplication.
root_sql '
GRANT fleet_conflict_reconciliation
    TO fleet_runtime, fleet_control_bootstrap, fleet_registry_activation;
' >/dev/null
apply_reconciliation_policy >/dev/null

# Unknown NOLOGIN edges fail closed in both directions. The policy cannot
# safely construct arbitrary role or object identifiers for dynamic REVOKE in
# v26.2, so an operator must remove each exact edge/grant and reapply. Direct
# target-role and PUBLIC authority elsewhere in the current fleet_recall
# database, and current-database ownership drift, are equivalent fail-closed
# preconditions. Other databases are covered by the external audit above.
root_sql '
CREATE ROLE proof_unexpected_authority;
GRANT proof_unexpected_authority TO root;
ALTER DEFAULT PRIVILEGES FOR ROLE proof_unexpected_authority
    REVOKE EXECUTE ON ROUTINES FROM public;
REVOKE proof_unexpected_authority FROM root;
GRANT SELECT ON TABLE memory_corpus_models TO proof_unexpected_authority;
GRANT proof_unexpected_authority TO fleet_conflict_reconciliation;
' >/dev/null
expect_policy_role_edge_failure "unexpected inherited authority role"
assert_root_scalar "failed outbound role-edge preservation" \
    "SELECT count(*)::STRING FROM [SHOW GRANTS ON ROLE]
     WHERE role_name = 'proof_unexpected_authority'
       AND member = 'fleet_conflict_reconciliation'" '1'
root_sql '
REVOKE proof_unexpected_authority FROM fleet_conflict_reconciliation;
CREATE ROLE proof_unexpected_holder;
GRANT proof_unexpected_holder TO root;
ALTER DEFAULT PRIVILEGES FOR ROLE proof_unexpected_holder
    REVOKE EXECUTE ON ROUTINES FROM public;
REVOKE proof_unexpected_holder FROM root;
GRANT fleet_conflict_reconciliation TO proof_unexpected_holder;
' >/dev/null
expect_policy_role_edge_failure "unexpected inheriting NOLOGIN role"
assert_root_scalar "failed inbound role-edge preservation" \
    "SELECT count(*)::STRING FROM [SHOW GRANTS ON ROLE]
     WHERE role_name = 'fleet_conflict_reconciliation'
       AND member = 'proof_unexpected_holder'" '1'
root_sql '
REVOKE fleet_conflict_reconciliation FROM proof_unexpected_holder;
GRANT fleet_conflict_reconciliation TO proof_reconciliation WITH ADMIN OPTION;
' >/dev/null
expect_policy_role_edge_failure "external login with admin option"
assert_root_scalar "failed admin-option edge preservation" \
    "SELECT count(*)::STRING FROM [SHOW GRANTS ON ROLE]
     WHERE role_name = 'fleet_conflict_reconciliation'
       AND member = 'proof_reconciliation'
       AND is_admin" '1'
root_sql '
REVOKE fleet_conflict_reconciliation FROM proof_reconciliation;
CREATE SCHEMA proof_cross_schema;
CREATE TABLE proof_cross_schema.owned_outside_public (id INT8 PRIMARY KEY);
GRANT USAGE ON SCHEMA proof_cross_schema
    TO fleet_conflict_reconciliation;
GRANT SELECT ON TABLE proof_cross_schema.owned_outside_public
    TO fleet_conflict_reconciliation;
' >/dev/null
expect_policy_schema_boundary_failure "unexpected application schema"
assert_root_scalar "failed schema-boundary preflight preservation" \
    "SELECT count(*)::STRING FROM pg_catalog.pg_namespace
     WHERE nspname = 'proof_cross_schema'" '1'
assert_root_scalar "failed schema-boundary grant preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW GRANTS FOR fleet_conflict_reconciliation]
     WHERE grantee = 'fleet_conflict_reconciliation'
       AND database_name = 'fleet_recall'
       AND schema_name = 'proof_cross_schema'
       AND (
           (object_type = 'schema' AND privilege_type = 'USAGE')
           OR (object_type = 'table'
               AND object_name = 'owned_outside_public'
               AND privilege_type = 'SELECT')
       )" '2'
root_sql "
REVOKE SELECT ON TABLE proof_cross_schema.owned_outside_public
    FROM fleet_conflict_reconciliation;
REVOKE USAGE ON SCHEMA proof_cross_schema
    FROM fleet_conflict_reconciliation;
DROP TABLE proof_cross_schema.owned_outside_public;
DROP SCHEMA proof_cross_schema;
CREATE TYPE proof_boundary_type AS ENUM ('proof');
REVOKE USAGE ON TYPE proof_boundary_type FROM public;
GRANT USAGE ON TYPE proof_boundary_type TO fleet_conflict_reconciliation;
" >/dev/null
expect_policy_grant_boundary_failure "unexpected reconciliation type grant"
assert_root_scalar "failed target grant-boundary preflight preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW GRANTS FOR fleet_conflict_reconciliation]
     WHERE grantee = 'fleet_conflict_reconciliation'
       AND database_name = 'fleet_recall'
       AND schema_name = 'public'
       AND object_type = 'type'
       AND object_name = 'proof_boundary_type'
       AND privilege_type = 'USAGE'" '1'
root_sql '
REVOKE USAGE ON TYPE proof_boundary_type FROM fleet_conflict_reconciliation;
GRANT USAGE ON TYPE proof_boundary_type TO public;
' >/dev/null
expect_policy_grant_boundary_failure "unexpected PUBLIC type grant"
assert_root_scalar "failed PUBLIC grant-boundary preflight preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW GRANTS FOR public]
     WHERE grantee = 'public'
       AND database_name = 'fleet_recall'
       AND schema_name = 'public'
       AND object_type = 'type'
       AND object_name = 'proof_boundary_type'
       AND privilege_type = 'USAGE'" '1'
root_sql "
REVOKE USAGE ON TYPE proof_boundary_type FROM public;
DROP TYPE proof_boundary_type;
ALTER ROLE fleet_conflict_reconciliation WITH CONTROLJOB;
CREATE EXTERNAL CONNECTION proof_reconciliation_external
    AS 'nodelocal://1/proof-reconciliation-external';
GRANT USAGE, DROP ON EXTERNAL CONNECTION proof_reconciliation_external
    TO public;
" >/dev/null
expect_policy_grant_boundary_failure \
    "unexpected cluster-global PUBLIC external-connection grants"
assert_root_scalar "failed PUBLIC external-connection preflight preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW GRANTS FOR public]
     WHERE grantee = 'public'
       AND database_name IS NULL
       AND schema_name IS NULL
       AND object_type = 'external_connection'
       AND object_name = 'proof_reconciliation_external'
       AND privilege_type IN ('DROP', 'USAGE')
       AND NOT is_grantable" '2'
assert_root_scalar "external-connection gate role-option preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW USERS] AS target_role
     CROSS JOIN LATERAL unnest(target_role.options) AS role_option(option_name)
     WHERE target_role.username = 'fleet_conflict_reconciliation'
       AND role_option.option_name = 'CONTROLJOB'" '1'
root_sql '
REVOKE USAGE, DROP ON EXTERNAL CONNECTION proof_reconciliation_external
    FROM public;
DROP EXTERNAL CONNECTION proof_reconciliation_external;
' >/dev/null
apply_reconciliation_policy >/dev/null
root_sql '
CREATE TABLE proof_owned_by_reconciliation (id INT8 PRIMARY KEY);
GRANT CREATE ON SCHEMA public TO fleet_conflict_reconciliation;
ALTER TABLE proof_owned_by_reconciliation
    OWNER TO fleet_conflict_reconciliation;
REVOKE CREATE ON SCHEMA public FROM fleet_conflict_reconciliation;
' >/dev/null
expect_policy_ownership_failure "unexpected public table ownership"
assert_root_scalar "failed ownership preflight preservation" \
    "SELECT count(*)::STRING
     FROM pg_catalog.pg_class AS relation_object
     JOIN pg_catalog.pg_namespace AS relation_schema
       ON relation_schema.oid = relation_object.relnamespace
     JOIN pg_catalog.pg_roles AS owner_role
       ON owner_role.oid = relation_object.relowner
     WHERE relation_schema.nspname = 'public'
       AND relation_object.relname = 'proof_owned_by_reconciliation'
       AND owner_role.rolname = 'fleet_conflict_reconciliation'" '1'
root_sql '
ALTER TABLE proof_owned_by_reconciliation OWNER TO root;
DROP TABLE proof_owned_by_reconciliation;
GRANT fleet_conflict_reconciliation TO proof_reconciliation;
' >/dev/null

# LOGIN membership is externally provisioned identity state, not a role bundle.
# It survives reapplication and is audited in full below.
apply_reconciliation_policy >/dev/null

root_sql '
GRANT fleet_runtime TO proof_runtime;
GRANT fleet_control_bootstrap TO proof_bootstrap;
GRANT fleet_registry_activation TO proof_activation;
' >/dev/null

reconciliation_object_grants=$(root_sql "
SELECT schema_name || ':' || object_type || ':' || object_name || ':' || privilege_type || ':' ||
       CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END AS normalized
FROM [SHOW GRANTS FOR fleet_conflict_reconciliation]
WHERE grantee = 'fleet_conflict_reconciliation'
  AND database_name = 'fleet_recall'
  AND object_type IN ('table', 'sequence')
ORDER BY schema_name, object_type, object_name, privilege_type" | tail -n +2)
expected_reconciliation_object_grants='public:sequence:memory_conflict_id_seq:USAGE:not_grantable
public:table:_sqlx_migrations:SELECT:not_grantable
public:table:memory_claim_events:INSERT:not_grantable
public:table:memory_claim_events:SELECT:not_grantable
public:table:memory_claim_links:SELECT:not_grantable
public:table:memory_claims:SELECT:not_grantable
public:table:memory_claims:UPDATE:not_grantable
public:table:memory_conflict_members:INSERT:not_grantable
public:table:memory_conflict_members:SELECT:not_grantable
public:table:memory_conflict_members:UPDATE:not_grantable
public:table:memory_conflicts:INSERT:not_grantable
public:table:memory_conflicts:SELECT:not_grantable
public:table:memory_conflicts:UPDATE:not_grantable
public:table:memory_events:INSERT:not_grantable
public:table:memory_mutation_receipts:INSERT:not_grantable
public:table:memory_mutation_receipts:SELECT:not_grantable
public:table:memory_mutation_receipts:UPDATE:not_grantable'
assert_exact "reconciliation full current table/sequence grants" \
    "$reconciliation_object_grants" "$expected_reconciliation_object_grants"
assert_exact "reconciliation table/sequence grant row count" \
    "$(printf '%s\n' "$reconciliation_object_grants" | wc -l | tr -d ' ')" '17'

database_grants=$(root_sql "
SELECT database_name || ':' || grantee || ':' || privilege_type || ':' ||
       CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END AS normalized
FROM [SHOW GRANTS ON DATABASE fleet_recall]
WHERE grantee IN ('public', 'fleet_conflict_reconciliation')
ORDER BY grantee, privilege_type" | tail -n +2)
expected_database_grants='fleet_recall:fleet_conflict_reconciliation:CONNECT:not_grantable'
assert_exact "reconciliation database grants" \
    "$database_grants" "$expected_database_grants"

schema_grants=$(root_sql "
SELECT schema_name || ':' || grantee || ':' || privilege_type || ':' ||
       CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END AS normalized
FROM [SHOW GRANTS ON SCHEMA public]
WHERE grantee IN ('public', 'fleet_conflict_reconciliation')
ORDER BY grantee, privilege_type" | tail -n +2)
expected_schema_grants='public:fleet_conflict_reconciliation:USAGE:not_grantable'
assert_exact "reconciliation schema grants" \
    "$schema_grants" "$expected_schema_grants"

public_application_object_grants=$(root_sql "
SELECT object_type || ':' || object_name || ':' || privilege_type || ':' ||
       CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END AS normalized
FROM [SHOW GRANTS FOR public]
WHERE grantee = 'public'
  AND database_name = 'fleet_recall'
  AND schema_name = 'public'
  AND object_type IN ('table', 'sequence')
ORDER BY object_type, object_name, privilege_type" | tail -n +2)
assert_exact "PUBLIC application table/sequence grants" \
    "$public_application_object_grants" ''

# Freeze the exact v26.2.3 PUBLIC fallback on its four unmodifiable virtual
# schemas. These rows are not application authority: Cockroach rejects object
# creation/shadowing there, and the policy admits no grantable/different shape.
public_virtual_schema_grants=$(root_sql "
SELECT schema_name || ':' || object_type || ':' || privilege_type || ':' ||
       CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END || ':' ||
       count(*)::STRING AS normalized
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

out_of_boundary_grants=$(root_sql "
SELECT grantee || ':' || COALESCE(database_name, '') || ':' ||
       COALESCE(schema_name, '') || ':' || object_type || ':' || object_name || ':' ||
       privilege_type || ':' ||
       CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END AS normalized
FROM (
    SELECT database_name, schema_name, object_type, object_name, grantee,
           privilege_type, is_grantable
    FROM [SHOW GRANTS FOR fleet_conflict_reconciliation]
    WHERE grantee = 'fleet_conflict_reconciliation'
      AND NOT (
        (object_type = 'database' AND database_name = 'fleet_recall')
        OR (object_type = 'schema'
            AND database_name = 'fleet_recall' AND schema_name = 'public')
        OR (object_type IN ('table', 'sequence')
            AND database_name = 'fleet_recall' AND schema_name = 'public')
    )
    UNION ALL
    SELECT database_name, schema_name, object_type, object_name, grantee,
           privilege_type, is_grantable
    FROM [SHOW GRANTS FOR public]
    WHERE grantee = 'public'
      AND (
          object_type = 'external_connection'
          OR (
              database_name = 'fleet_recall'
              AND NOT (
                  object_type = 'database'
                  OR (object_type = 'schema' AND schema_name = 'public')
                  OR (object_type IN ('table', 'sequence')
                      AND schema_name = 'public')
                  OR (
                      object_type = 'schema'
                      AND schema_name LIKE 'pg_temp_%'
                      AND object_name IS NULL
                      AND privilege_type IN ('CREATE', 'USAGE')
                      AND NOT is_grantable
                  )
                  OR (
                      schema_name IN (
                          'crdb_internal',
                          'information_schema',
                          'pg_catalog',
                          'pg_extension'
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
              )
          )
      )
) AS forbidden_grant
ORDER BY grantee, database_name, schema_name, object_type, object_name, privilege_type" \
    | tail -n +2)
assert_exact "out-of-boundary reconciliation/PUBLIC grants" \
    "$out_of_boundary_grants" ''

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
SELECT grantee || ':' || privilege_type AS normalized
FROM [SHOW SYSTEM GRANTS]
WHERE grantee IN (
    'fleet_runtime',
    'fleet_control_bootstrap',
    'fleet_registry_activation',
    'fleet_conflict_reconciliation',
    'public'
)
ORDER BY grantee, privilege_type" | tail -n +2)
assert_exact "application-role and inherited PUBLIC system grants" \
    "$system_grants" ''

application_role_options=$(root_sql "
SELECT username || ':' || options::STRING AS normalized
FROM [SHOW USERS]
WHERE username IN (
    'fleet_runtime',
    'fleet_control_bootstrap',
    'fleet_registry_activation',
    'fleet_conflict_reconciliation'
)
ORDER BY username" | tail -n +2)
expected_application_role_options='fleet_conflict_reconciliation:{NOLOGIN}
fleet_control_bootstrap:{NOLOGIN}
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
    'fleet_conflict_reconciliation',
    'proof_runtime',
    'proof_bootstrap',
    'proof_activation',
    'proof_reconciliation'
)
   OR role_name IN (
       'fleet_runtime',
       'fleet_control_bootstrap',
       'fleet_registry_activation',
       'fleet_conflict_reconciliation'
   )
ORDER BY role_name, member" | tail -n +2)
expected_application_role_edges='fleet_conflict_reconciliation:proof_reconciliation:no_admin_option
fleet_control_bootstrap:proof_bootstrap:no_admin_option
fleet_registry_activation:proof_activation:no_admin_option
fleet_runtime:proof_runtime:no_admin_option'
assert_exact "application role membership edges" \
    "$application_role_edges" "$expected_application_role_edges"

reconciliation_role_edges=$(root_sql "
SELECT role_name || ':' || member || ':' ||
       CASE WHEN is_admin THEN 'admin_option' ELSE 'no_admin_option' END AS normalized
FROM [SHOW GRANTS ON ROLE]
WHERE role_name = 'fleet_conflict_reconciliation'
   OR member = 'fleet_conflict_reconciliation'
ORDER BY role_name, member" | tail -n +2)
expected_reconciliation_role_edges='fleet_conflict_reconciliation:proof_reconciliation:no_admin_option'
assert_exact "complete reconciliation role edges" \
    "$reconciliation_role_edges" "$expected_reconciliation_role_edges"

# The release-26.2 engine source synthesizes non-grantable PUBLIC routine
# EXECUTE and type USAGE rows. All named pre-existing routine rows are an
# operator-cleanup prerequisite; the exact clean-engine all-roles row was frozen
# above, and CREATE ROLE contributes exactly the inert target-grantor row here.
# https://github.com/cockroachdb/cockroach/blob/v26.2.3/pkg/sql/logictest/testdata/logic_test/show_default_privileges
target_public_routine_defaults=$(root_sql "
SELECT role || ':' || object_type || ':' || grantee || ':' || privilege_type || ':' ||
       CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END AS normalized
FROM (
    SELECT role, for_all_roles, object_type, grantee, privilege_type, is_grantable
    FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE public]
    UNION
    SELECT role, for_all_roles, object_type, grantee, privilege_type, is_grantable
    FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE public IN SCHEMA public]
) AS public_default
WHERE role = 'fleet_conflict_reconciliation'
  AND NOT for_all_roles
  AND object_type = 'routines'
  AND grantee = 'public'
  AND privilege_type = 'EXECUTE'
  AND NOT is_grantable
ORDER BY role, object_type, grantee, privilege_type" | tail -n +2)
expected_target_public_routine_defaults='fleet_conflict_reconciliation:routines:public:EXECUTE:not_grantable'
assert_exact "target creator-scoped PUBLIC routine default" \
    "$target_public_routine_defaults" \
    "$expected_target_public_routine_defaults"

# The final supported four-SHOW audit excludes only the exact clean-engine
# all-roles routine row, the exact target routine row, PUBLIC's intrinsic type
# USAGE, and target self-owner ALL.
default_privileges=$(root_sql "
SELECT COALESCE(role, 'ALL') || ':' || object_type || ':' || grantee || ':' ||
       privilege_type || ':' ||
       CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END AS normalized
FROM (
    SELECT role, for_all_roles, object_type, grantee, privilege_type, is_grantable
    FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE public]
    UNION
    SELECT role, for_all_roles, object_type, grantee, privilege_type, is_grantable
    FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE public IN SCHEMA public]
    UNION
    SELECT role, for_all_roles, object_type, grantee, privilege_type, is_grantable
    FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE fleet_conflict_reconciliation]
    UNION
    SELECT role, for_all_roles, object_type, grantee, privilege_type, is_grantable
    FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE fleet_conflict_reconciliation
          IN SCHEMA public]
) AS forbidden_default
WHERE object_type IN ('schemas', 'routines', 'tables', 'sequences', 'types')
  AND grantee IN ('public', 'fleet_conflict_reconciliation')
  AND NOT (
      role = 'fleet_conflict_reconciliation'
      AND NOT for_all_roles
      AND grantee = 'fleet_conflict_reconciliation'
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
      role = 'fleet_conflict_reconciliation'
      AND NOT for_all_roles
      AND grantee = 'public'
      AND object_type = 'routines'
      AND privilege_type = 'EXECUTE'
      AND NOT is_grantable
  )
ORDER BY role, object_type, grantee, privilege_type" | tail -n +2)
assert_exact "non-intrinsic reconciliation/PUBLIC future-object defaults" \
    "$default_privileges" ''

# Re-run the external admin audit after all policy/drift cycles. The helper
# enumerates every SHOW DATABASES row; direct target grants/ownership must be
# absent outside fleet_recall. PUBLIC's ordinary other-database ambient baseline
# remains outside this local policy, while application-object drift is empty in
# the parity fixture.
final_outside_target_authority=$(audit_other_database_target_authority)
assert_exact "final external target-authority audit" \
    "$final_outside_target_authority" ''
final_outside_public_application_authority=$(
    inventory_other_database_public_application_authority
)
assert_exact "final external PUBLIC application-authority inventory" \
    "$final_outside_public_application_authority" ''
assert_exact "secondary database retained for final external audit" \
    "$(root_sql "SELECT count(*)::STRING FROM [SHOW DATABASES]
                  WHERE database_name = 'proof_other_database'" | tail -n +2)" '1'

# The repository principal can evaluate only the prefix-16 gate, even with a
# later row 17 present, and cannot mutate SQLx history.
expect_allowed proof_reconciliation "migration-prefix preflight" \
    "SELECT count(*) = 16
        AND min(version) = 1
        AND max(version) = 16
        AND COALESCE(bool_and(success), false)
     FROM _sqlx_migrations
     WHERE version BETWEEN 1 AND 16"
expect_allowed proof_reconciliation "migration-prefix preflight plan" \
    "EXPLAIN SELECT count(*) = 16
        AND min(version) = 1
        AND max(version) = 16
        AND COALESCE(bool_and(success), false)
     FROM _sqlx_migrations
     WHERE version BETWEEN 1 AND 16"
expect_denied proof_reconciliation "migration-history insert" \
    'INSERT INTO _sqlx_migrations VALUES (18, true)'
expect_denied proof_reconciliation "migration-history update" \
    'UPDATE _sqlx_migrations SET success = false WHERE version = 16'
expect_denied proof_reconciliation "migration-history delete" \
    'DELETE FROM _sqlx_migrations WHERE version = 16'

# Exercise every allowed table operation using the same shapes as the reviewed
# repository. The first conflict consumes sequence value 1.
expect_allowed proof_reconciliation "v2 conflict insert" "
INSERT INTO memory_conflicts (
    tenant_id, project, claim_key, kind, state, detector, rationale
) VALUES (
    '0198a849-f6ae-7d61-9800-000000000001',
    'reconciliation-grant-proof', 'fleet-store::database-choice',
    'contradiction', 'dismissed', 'same_key_functional_value_v2',
    'same-key functional typed-value proposition contradiction'
)"
expect_allowed proof_reconciliation "v2 conflict read" \
    'SELECT count(*) FROM memory_conflicts'
expect_allowed proof_reconciliation "conflict lineage lock" \
    "BEGIN; SELECT id FROM memory_conflicts
     WHERE tenant_id = '0198a849-f6ae-7d61-9800-000000000001'
       AND project = 'reconciliation-grant-proof'
       AND id = 1
     FOR UPDATE; ROLLBACK"
expect_allowed proof_reconciliation "v2 member insert" "
INSERT INTO memory_conflict_members (
    tenant_id, project, conflict_id, claim_id, role
) VALUES (
    '0198a849-f6ae-7d61-9800-000000000001',
    'reconciliation-grant-proof', 1, 1, 'claim'
)"
expect_allowed proof_reconciliation "v2 member read" \
    'SELECT count(*) FROM memory_conflict_members'
expect_allowed proof_reconciliation "legacy membership lock" \
    "BEGIN; SELECT claim_id FROM memory_conflict_members
     WHERE tenant_id = '0198a849-f6ae-7d61-9800-000000000001'
       AND project = 'reconciliation-grant-proof'
       AND conflict_id = 1
     FOR UPDATE; ROLLBACK"
expect_allowed proof_reconciliation "claim read" \
    'SELECT count(*) FROM memory_claims'
expect_allowed proof_reconciliation "claim lifecycle update" "
UPDATE memory_claims
SET state = 'disputed', revision = revision + 1, updated_at = now()
WHERE tenant_id = '0198a849-f6ae-7d61-9800-000000000001'
  AND project = 'reconciliation-grant-proof'
  AND id = 1
  AND state = 'active'"
expect_allowed proof_reconciliation "claim transition insert" "
INSERT INTO memory_claim_events (
    tenant_id, project, claim_id, event_kind, actor, reason,
    from_state, to_state, payload
) VALUES (
    '0198a849-f6ae-7d61-9800-000000000001',
    'reconciliation-grant-proof', 1, 'state_transition', 'proof',
    'conflict_detector_reconciled_v2', 'active', 'disputed', '{}'::JSONB
)"
expect_allowed proof_reconciliation "claim transition read" \
    'SELECT count(*) FROM memory_claim_events'
expect_allowed proof_reconciliation "receipt-FK link parent read" \
    'SELECT count(*) FROM memory_claim_links'
expect_allowed proof_reconciliation "receipt reserve" "
INSERT INTO memory_mutation_receipts (
    tenant_id, idempotency_key, project, request, operation
) VALUES (
    '0198a849-f6ae-7d61-9800-000000000001', 'grant-proof-key',
    'reconciliation-grant-proof', '{}'::JSONB, 'reconcile_conflict_detector_v2'
)"
expect_allowed proof_reconciliation "receipt read" \
    'SELECT count(*) FROM memory_mutation_receipts'
expect_allowed proof_reconciliation "receipt completion" "
UPDATE memory_mutation_receipts
SET conflict_id = 1, response = '{}'::JSONB
WHERE tenant_id = '0198a849-f6ae-7d61-9800-000000000001'
  AND idempotency_key = 'grant-proof-key'"
expect_allowed proof_reconciliation "aggregate audit insert" "
INSERT INTO memory_events (
    tenant_id, project, agent, session_id, event_kind, entity_kind,
    entity_id, idempotency_key, payload
) VALUES (
    '0198a849-f6ae-7d61-9800-000000000001',
    'reconciliation-grant-proof', 'proof', 'proof-session',
    'conflict_detector_reconciled', 'conflict', '1', 'grant-proof-key',
    '{}'::JSONB
)"
expect_allowed proof_reconciliation "conflict sequence use and session-local state" \
    "SELECT nextval('memory_conflict_id_seq');
     SELECT currval('memory_conflict_id_seq');
     SELECT lastval()"

# The exact grants exclude destructive rewrites, unrelated object surfaces,
# DDL, privilege delegation, and sequence inspection/mutation. UPDATE on the two
# locked conflict tables is the documented engine residual; freeze its inert
# capability beside the source assertion that the repository never uses it.
expect_allowed proof_reconciliation "conflict lock-residual update" \
    'UPDATE memory_conflicts SET state = state WHERE false'
expect_denied proof_reconciliation "conflict delete" \
    'DELETE FROM memory_conflicts WHERE false'
expect_allowed proof_reconciliation "member lock-residual update" \
    'UPDATE memory_conflict_members SET role = role WHERE false'
expect_denied proof_reconciliation "member delete" \
    'DELETE FROM memory_conflict_members WHERE false'
expect_denied proof_reconciliation "claim insert" "
INSERT INTO memory_claims (tenant_id, project, id, claim_key)
VALUES (
    '0198a849-f6ae-7d61-9800-000000000001',
    'reconciliation-grant-proof', 2, 'denied'
)"
expect_denied proof_reconciliation "claim delete" \
    'DELETE FROM memory_claims WHERE false'
expect_denied proof_reconciliation "claim-event update" \
    'UPDATE memory_claim_events SET reason = reason WHERE false'
expect_denied proof_reconciliation "claim-event delete" \
    'DELETE FROM memory_claim_events WHERE false'
expect_denied proof_reconciliation "claim-link insert" "
INSERT INTO memory_claim_links (tenant_id, project, id)
VALUES (
    '0198a849-f6ae-7d61-9800-000000000001',
    'reconciliation-grant-proof', 1
)"
expect_denied proof_reconciliation "claim-link update" \
    'UPDATE memory_claim_links SET id = id WHERE false'
expect_denied proof_reconciliation "claim-link delete" \
    'DELETE FROM memory_claim_links WHERE false'
expect_denied proof_reconciliation "receipt delete" \
    'DELETE FROM memory_mutation_receipts WHERE false'
expect_denied proof_reconciliation "aggregate audit read" \
    'SELECT count(*) FROM memory_events'
expect_denied proof_reconciliation "aggregate audit update" \
    'UPDATE memory_events SET payload = payload WHERE false'
expect_denied proof_reconciliation "aggregate audit delete" \
    'DELETE FROM memory_events WHERE false'
expect_denied proof_reconciliation "conflict sequence set" \
    "SELECT setval('memory_conflict_id_seq', 99)"
expect_denied proof_reconciliation "conflict sequence state read" \
    'SELECT last_value FROM memory_conflict_id_seq'
expect_denied proof_reconciliation "legacy claim sequence use" \
    "SELECT nextval('memory_claim_id_seq')"

expect_denied proof_reconciliation "corpus authority" \
    'SELECT count(*) FROM memory_chunks'
expect_denied proof_reconciliation "corpus model authority" \
    'SELECT count(*) FROM memory_corpus_models'
expect_denied proof_reconciliation "control authority" \
    'SELECT count(*) FROM memory_control_events'
expect_denied proof_reconciliation "genesis registry authority" \
    'SELECT count(*) FROM memory_registry_activations'
expect_denied proof_reconciliation "successor transition authority" \
    'SELECT count(*) FROM memory_registry_transitions'
expect_denied proof_reconciliation "successor bridge authority" \
    'SELECT count(*) FROM memory_registry_genesis_bridge_consumptions'
expect_denied proof_reconciliation "successor head authority" \
    'SELECT count(*) FROM memory_registry_current_heads_v2'
expect_denied proof_reconciliation "schema creation" \
    'CREATE TABLE reconciliation_escape (id INT8 PRIMARY KEY)'
expect_denied proof_reconciliation "database creation" \
    'CREATE DATABASE reconciliation_escape'
expect_denied proof_reconciliation "role creation" \
    'CREATE ROLE reconciliation_escape'
expect_denied proof_reconciliation "grant delegation" \
    'GRANT SELECT ON TABLE memory_conflicts TO proof_public'
expect_denied proof_reconciliation "role-membership delegation" \
    'GRANT fleet_conflict_reconciliation TO proof_public'

# Runtime already has broad direct legacy-ledger DML for remember. Prove the
# reconciliation policy did not silently revoke it and did not add an inherited
# role edge. The dedicated credential is the supported least-privilege path,
# not an engine claim that runtime cannot issue equivalent raw table DML.
runtime_ledger_grants_after=$(root_sql "
SELECT object_type || ':' || object_name || ':' || privilege_type || ':' ||
       CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END AS normalized
FROM [SHOW GRANTS FOR fleet_runtime]
WHERE database_name = 'fleet_recall'
  AND schema_name = 'public'
  AND object_name IN (
      '_sqlx_migrations',
      'memory_claims',
      'memory_claim_events',
      'memory_conflicts',
      'memory_conflict_members',
      'memory_claim_links',
      'memory_mutation_receipts',
      'memory_events',
      'memory_claim_id_seq',
      'memory_conflict_id_seq'
  )
ORDER BY object_type, object_name, privilege_type" | tail -n +2)
assert_exact "runtime direct ledger grants preserved" \
    "$runtime_ledger_grants_after" "$runtime_ledger_grants_before"
expect_allowed proof_runtime "runtime corpus separation" \
    'SELECT count(*) FROM memory_chunks'
expect_allowed proof_runtime "runtime direct conflict read remains" \
    'SELECT count(*) FROM memory_conflicts'
expect_allowed proof_runtime "runtime direct receipt insert remains" \
    "INSERT INTO memory_mutation_receipts (
         tenant_id, idempotency_key, project, request, operation
     ) VALUES (
         '0198a849-f6ae-7d61-9800-000000000001', 'runtime-overlap-proof',
         'reconciliation-grant-proof', '{}'::JSONB,
         'reconcile_conflict_detector_v2'
     )"

# Bootstrap, genesis activation, and an otherwise unprivileged login neither
# have direct legacy-ledger DML nor inherit the reconciliation bundle.
expect_allowed proof_bootstrap "bootstrap control separation" \
    'INSERT INTO memory_control_events VALUES (1)'
expect_allowed proof_activation "activation registry separation" \
    'INSERT INTO memory_registry_activations VALUES (1)'
for user in proof_bootstrap proof_activation proof_public; do
    expect_denied "$user" "old-role conflict read" \
        'SELECT count(*) FROM memory_conflicts'
    expect_denied "$user" "old-role receipt insert" \
        "INSERT INTO memory_mutation_receipts (
             tenant_id, idempotency_key, project, request, operation
         ) VALUES (
             '0198a849-f6ae-7d61-9800-000000000001', 'old-role-denied',
             'reconciliation-grant-proof', '{}'::JSONB,
             'reconcile_conflict_detector_v2'
         )"
done

echo "verified effective conflict-reconciliation grants:"
root_sql "SHOW GRANTS FOR fleet_conflict_reconciliation"
echo "secondary Docker conflict-reconciliation grant parity proof passed"
