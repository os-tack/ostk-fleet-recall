#!/usr/bin/env bash
set -euo pipefail

# Secondary Docker parity only. Static policy/source-shape assertions run
# before the first Docker command. A caller must separately authorize the
# connected portion after reviewing the frozen file hashes.
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$script_dir/../../.." && pwd)
policy="$repo_root/deploy/cockroach/runtime-role-grants.sql"
main_source="$repo_root/src/main.rs"
image=${FLEET_RECALL_CRDB_IMAGE:-cockroachdb/cockroach:v26.2.3}
expected_crdb_build_tag=v26.2.3
container=''

fail() {
    echo "runtime-role grant proof failed: $*" >&2
    exit 1
}

assert_exact() {
    local label=$1
    local actual=$2
    local expected=$3
    if test "$actual" != "$expected"; then
        printf '%s\n' "unexpected $label" "expected:" "$expected" \
            "actual:" "$actual" >&2
        fail "$label does not match the frozen contract"
    fi
}

root_sql() {
    docker exec "$container" cockroach sql \
        --insecure --database fleet_recall --format tsv --execute "$1"
}

root_sql_in_database() {
    local database=$1
    local statement=$2
    docker exec "$container" cockroach sql \
        --insecure --database "$database" --format tsv --execute "$statement"
}

sql_as_writer() {
    docker exec "$container" cockroach sql \
        --insecure --database fleet_recall --user fleet_writer \
        --format tsv --execute "$1"
}

apply_policy() {
    docker exec -i "$container" cockroach sql \
        --insecure --database fleet_recall < "$policy"
}

apply_policy_in_database() {
    local database=$1
    docker exec -i "$container" cockroach sql \
        --insecure --database "$database" < "$policy"
}

apply_policy_with_valid_temp_prefix() {
    {
        printf '%s\n' '
SET experimental_enable_temp_tables = on;
CREATE TEMP TABLE _sqlx_migrations (
    version INT8 PRIMARY KEY,
    success BOOL NOT NULL
);
INSERT INTO _sqlx_migrations
SELECT version, true FROM generate_series(1, 18) AS version;
'
        sed -n '1,$p' "$policy"
    } | docker exec -i "$container" cockroach sql \
        --insecure --database fleet_recall
}

assert_root_scalar() {
    local label=$1
    local statement=$2
    local expected=$3
    local actual
    actual=$(root_sql "$statement" | tail -n +2) \
        || fail "$label SQL assertion could not execute"
    assert_exact "$label" "$actual" "$expected"
}

assert_database_scalar() {
    local database=$1
    local label=$2
    local statement=$3
    local expected=$4
    local actual
    actual=$(root_sql_in_database "$database" "$statement" | tail -n +2) \
        || fail "$label SQL assertion could not execute in $database"
    assert_exact "$label" "$actual" "$expected"
}

expect_allowed() {
    local label=$1
    local statement=$2
    sql_as_writer "$statement" >/dev/null \
        || fail "$label should be allowed for fleet_writer"
}

expect_denied() {
    local label=$1
    local statement=$2
    local output
    if output=$(sql_as_writer "$statement" 2>&1); then
        fail "$label unexpectedly succeeded for fleet_writer"
    fi
    if ! grep -Eiq \
        'privilege|permission|not have.*grant|must have.*(CREATEROLE|admin option)|must be owner' \
        <<<"$output"; then
        echo "$output" >&2
        fail "$label failed for a reason other than authorization"
    fi
}

expect_foreign_key_rejection() {
    local label=$1
    local statement=$2
    local constraint=$3
    local output
    if output=$(sql_as_writer "$statement" 2>&1); then
        fail "$label unexpectedly succeeded for fleet_writer"
    fi
    if ! grep -Fq "$constraint" <<<"$output"; then
        echo "$output" >&2
        fail "$label failed for a reason other than $constraint"
    fi
    if ! grep -Fq 'foreign key' <<<"$output"; then
        echo "$output" >&2
        fail "$label was not rejected by a foreign key check"
    fi
}

expect_claim_link_parent_denied() {
    local label=$1
    local statement=$2
    local output
    if output=$(sql_as_writer "$statement" 2>&1); then
        fail "$label unexpectedly succeeded for fleet_writer"
    fi
    grep -Fq 'SQLSTATE: 42501' <<<"$output" \
        || { echo "$output" >&2; fail "$label did not fail with 42501"; }
    grep -Fq 'memory_claim_links' <<<"$output" \
        || { echo "$output" >&2; fail "$label did not name memory_claim_links"; }
}

expect_policy_failure() {
    local label=$1
    local message=$2
    local sqlstate=$3
    local output
    if output=$(apply_policy 2>&1); then
        fail "$label unexpectedly admitted the policy"
    fi
    if ! grep -Fq "$message" <<<"$output"; then
        echo "$output" >&2
        fail "$label did not retain its contract diagnostic"
    fi
    if ! grep -Fq "SQLSTATE: $sqlstate" <<<"$output"; then
        echo "$output" >&2
        fail "$label did not retain SQLSTATE $sqlstate"
    fi
}

# The SQL policy is database-local. This read-only deployment preflight
# enumerates every other database and application schema for direct grants,
# ownership, and non-intrinsic future defaults held by either fixed subject.
audit_other_database_runtime_authority() {
    local databases
    local database
    local schemas
    local schema_name
    local schema_identifier
    local rows
    local row
    rows=$(root_sql "
        WITH subject_grant AS (
            SELECT * FROM [SHOW GRANTS FOR fleet_runtime]
            UNION ALL
            SELECT * FROM [SHOW GRANTS FOR fleet_writer]
        )
        SELECT 'cluster_grant:' || grantee || ':' || object_type || ':' ||
               COALESCE(object_name, '') || ':' || privilege_type || ':' ||
               CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END
        FROM subject_grant
        WHERE grantee IN ('fleet_runtime', 'fleet_writer')
          AND database_name IS NULL
        ORDER BY 1
    " | tail -n +2) \
        || fail "external runtime audit could not inspect cluster-global grants"
    while IFS= read -r row; do
        test -n "$row" || continue
        printf '%s\n' "$row"
    done <<<"$rows"
    databases=$(root_sql \
        'SELECT database_name FROM [SHOW DATABASES] ORDER BY database_name' \
        | tail -n +2) || fail "external runtime audit could not enumerate databases"
    while IFS= read -r database; do
        test -n "$database" || continue
        test "$database" != 'fleet_recall' || continue
        rows=$(root_sql_in_database "$database" "
            WITH subject_grant AS (
                SELECT * FROM [SHOW GRANTS FOR fleet_runtime]
                UNION ALL
                SELECT * FROM [SHOW GRANTS FOR fleet_writer]
            )
            SELECT 'grant:' || grantee || ':' || object_type || ':' ||
                   COALESCE(schema_name, '') || ':' ||
                   COALESCE(object_name, '') || ':' || privilege_type || ':' ||
                   CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END
            FROM subject_grant
            WHERE grantee IN ('fleet_runtime', 'fleet_writer')
              AND database_name = pg_catalog.current_database()
            UNION ALL
            SELECT 'database_owner:' || owner_role.rolname || '::' ||
                   database_object.datname || ':OWNER:owner'
            FROM pg_catalog.pg_database AS database_object
            JOIN pg_catalog.pg_roles AS owner_role
              ON owner_role.oid = database_object.datdba
            WHERE database_object.datname = pg_catalog.current_database()
              AND owner_role.rolname IN (
                  'fleet_runtime', 'fleet_writer'
              )
            UNION ALL
            SELECT 'schema_owner:' || owner_role.rolname || ':' ||
                   schema_object.nspname || '::OWNER:owner'
            FROM pg_catalog.pg_namespace AS schema_object
            JOIN pg_catalog.pg_roles AS owner_role
              ON owner_role.oid = schema_object.nspowner
            WHERE owner_role.rolname IN (
                'fleet_runtime', 'fleet_writer'
            )
            UNION ALL
            SELECT 'relation_owner:' || owner_role.rolname || ':' ||
                   relation_schema.nspname || ':' ||
                   relation_object.relname || ':OWNER:owner'
            FROM pg_catalog.pg_class AS relation_object
            JOIN pg_catalog.pg_namespace AS relation_schema
              ON relation_schema.oid = relation_object.relnamespace
            JOIN pg_catalog.pg_roles AS owner_role
              ON owner_role.oid = relation_object.relowner
            WHERE relation_object.relkind IN ('r', 'S', 'v', 'm', 'p')
              AND owner_role.rolname IN (
                  'fleet_runtime', 'fleet_writer'
              )
            UNION ALL
            SELECT 'function_owner:' || owner_role.rolname || ':' ||
                   function_schema.nspname || ':' ||
                   function_object.proname || ':OWNER:owner'
            FROM pg_catalog.pg_proc AS function_object
            JOIN pg_catalog.pg_namespace AS function_schema
              ON function_schema.oid = function_object.pronamespace
            JOIN pg_catalog.pg_roles AS owner_role
              ON owner_role.oid = function_object.proowner
            WHERE owner_role.rolname IN (
                'fleet_runtime', 'fleet_writer'
            )
            UNION ALL
            SELECT 'type_owner:' || owner_role.rolname || ':' ||
                   type_schema.nspname || ':' ||
                   type_object.typname || ':OWNER:owner'
            FROM pg_catalog.pg_type AS type_object
            JOIN pg_catalog.pg_namespace AS type_schema
              ON type_schema.oid = type_object.typnamespace
            JOIN pg_catalog.pg_roles AS owner_role
              ON owner_role.oid = type_object.typowner
            WHERE owner_role.rolname IN (
                'fleet_runtime', 'fleet_writer'
            )
            ORDER BY 1
        " | tail -n +2) \
            || fail "external runtime audit could not inspect $database"
        while IFS= read -r row; do
            test -n "$row" || continue
            printf '%s:%s\n' "$database" "$row"
        done <<<"$rows"

        # v26.2.3 rejects ALTER DEFAULT PRIVILEGES and CREATE SCHEMA in the
        # system database. Its default rows are synthesized engine baselines,
        # so keep current grants/ownership audited above and skip only defaults.
        test "$database" != 'system' || continue

        rows=$(root_sql_in_database "$database" "
            WITH subject_default AS (
                SELECT 'fleet_runtime' AS subject,
                       role, for_all_roles, object_type, grantee,
                       privilege_type, is_grantable
                FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE
                      fleet_runtime]
                UNION ALL
                SELECT 'fleet_writer' AS subject,
                       role, for_all_roles, object_type, grantee,
                       privilege_type, is_grantable
                FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE fleet_writer]
            )
            SELECT 'default:database:' || subject || ':' ||
                   COALESCE(role, '') || ':' || for_all_roles::STRING || ':' ||
                   object_type || ':' || grantee || ':' || privilege_type || ':' ||
                   CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END
            FROM subject_default
            WHERE object_type IN (
                'schemas', 'routines', 'tables', 'sequences', 'types'
            )
              AND (
                  role = subject
                  AND NOT for_all_roles
                  AND grantee = subject
                  AND privilege_type = 'ALL'
                  AND is_grantable
              ) IS NOT TRUE
            ORDER BY 1
        " | tail -n +2) \
            || fail "external runtime audit could not inspect database defaults in $database"
        while IFS= read -r row; do
            test -n "$row" || continue
            printf '%s:%s\n' "$database" "$row"
        done <<<"$rows"

        schemas=$(root_sql_in_database "$database" "
            SELECT nspname, quote_ident(nspname)
            FROM pg_catalog.pg_namespace
            WHERE nspname NOT IN (
                'pg_catalog', 'information_schema',
                'crdb_internal', 'pg_extension'
            )
              AND nspname NOT LIKE 'pg_temp_%'
            ORDER BY nspname
        " | tail -n +2) \
            || fail "external runtime audit could not enumerate schemas in $database"
        while IFS=$'\t' read -r schema_name schema_identifier; do
            test -n "$schema_name" || continue
            test -n "$schema_identifier" \
                || fail "external runtime audit found an unquotable schema in $database"
            rows=$(root_sql_in_database "$database" "
                WITH subject_default AS (
                    SELECT 'fleet_runtime' AS subject,
                           role, for_all_roles, object_type, grantee,
                           privilege_type, is_grantable
                    FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE
                          fleet_runtime IN SCHEMA $schema_identifier]
                    UNION ALL
                    SELECT 'fleet_writer' AS subject,
                           role, for_all_roles, object_type, grantee,
                           privilege_type, is_grantable
                    FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE
                          fleet_writer IN SCHEMA $schema_identifier]
                )
                SELECT subject || ':' || COALESCE(role, '') || ':' ||
                       for_all_roles::STRING || ':' || object_type || ':' ||
                       grantee || ':' || privilege_type || ':' ||
                       CASE WHEN is_grantable
                            THEN 'grantable' ELSE 'not_grantable' END
                FROM subject_default
                WHERE object_type IN (
                    'schemas', 'routines', 'tables', 'sequences', 'types'
                )
                  AND (
                      role = subject
                      AND NOT for_all_roles
                      AND grantee = subject
                      AND privilege_type = 'ALL'
                      AND is_grantable
                  ) IS NOT TRUE
                ORDER BY 1
            " | tail -n +2) \
                || fail "external runtime audit could not inspect $database.$schema_name defaults"
            while IFS= read -r row; do
                test -n "$row" || continue
                printf '%s:default:schema:%s:%s\n' \
                    "$database" "$schema_name" "$row"
            done <<<"$rows"
        done <<<"$schemas"
    done <<<"$databases"
}

# Bootstrap variant used while the logical role is intentionally absent. It
# covers the fixed principal's direct, ownership, and future-default authority
# without issuing an invalid named SHOW for the not-yet-created target.
audit_other_database_principal_authority() {
    local databases
    local database
    local schemas
    local schema_name
    local schema_identifier
    local rows
    local row
    rows=$(root_sql "
        SELECT 'cluster_grant:' || object_type || ':' ||
               COALESCE(object_name, '') || ':' || privilege_type || ':' ||
               CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END
        FROM [SHOW GRANTS FOR fleet_writer]
        WHERE grantee = 'fleet_writer'
          AND database_name IS NULL
        ORDER BY 1
    " | tail -n +2) \
        || fail "bootstrap principal audit could not inspect cluster-global grants"
    while IFS= read -r row; do
        test -n "$row" || continue
        printf '%s\n' "$row"
    done <<<"$rows"
    databases=$(root_sql \
        'SELECT database_name FROM [SHOW DATABASES] ORDER BY database_name' \
        | tail -n +2) \
        || fail "bootstrap principal audit could not enumerate databases"
    while IFS= read -r database; do
        test -n "$database" || continue
        test "$database" != 'fleet_recall' || continue
        rows=$(root_sql_in_database "$database" "
            SELECT 'grant:' || object_type || ':' ||
                   COALESCE(schema_name, '') || ':' ||
                   COALESCE(object_name, '') || ':' || privilege_type || ':' ||
                   CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END
            FROM [SHOW GRANTS FOR fleet_writer]
            WHERE grantee = 'fleet_writer'
              AND database_name = pg_catalog.current_database()
            UNION ALL
            SELECT 'database_owner::' || database_object.datname || ':OWNER:owner'
            FROM pg_catalog.pg_database AS database_object
            JOIN pg_catalog.pg_roles AS owner_role
              ON owner_role.oid = database_object.datdba
            WHERE database_object.datname = pg_catalog.current_database()
              AND owner_role.rolname = 'fleet_writer'
            UNION ALL
            SELECT 'schema_owner:' || schema_object.nspname || '::OWNER:owner'
            FROM pg_catalog.pg_namespace AS schema_object
            JOIN pg_catalog.pg_roles AS owner_role
              ON owner_role.oid = schema_object.nspowner
            WHERE owner_role.rolname = 'fleet_writer'
            UNION ALL
            SELECT 'relation_owner:' || relation_schema.nspname || ':' ||
                   relation_object.relname || ':OWNER:owner'
            FROM pg_catalog.pg_class AS relation_object
            JOIN pg_catalog.pg_namespace AS relation_schema
              ON relation_schema.oid = relation_object.relnamespace
            JOIN pg_catalog.pg_roles AS owner_role
              ON owner_role.oid = relation_object.relowner
            WHERE relation_object.relkind IN ('r', 'S', 'v', 'm', 'p')
              AND owner_role.rolname = 'fleet_writer'
            UNION ALL
            SELECT 'function_owner:' || function_schema.nspname || ':' ||
                   function_object.proname || ':OWNER:owner'
            FROM pg_catalog.pg_proc AS function_object
            JOIN pg_catalog.pg_namespace AS function_schema
              ON function_schema.oid = function_object.pronamespace
            JOIN pg_catalog.pg_roles AS owner_role
              ON owner_role.oid = function_object.proowner
            WHERE owner_role.rolname = 'fleet_writer'
            UNION ALL
            SELECT 'type_owner:' || type_schema.nspname || ':' ||
                   type_object.typname || ':OWNER:owner'
            FROM pg_catalog.pg_type AS type_object
            JOIN pg_catalog.pg_namespace AS type_schema
              ON type_schema.oid = type_object.typnamespace
            JOIN pg_catalog.pg_roles AS owner_role
              ON owner_role.oid = type_object.typowner
            WHERE owner_role.rolname = 'fleet_writer'
            ORDER BY 1
        " | tail -n +2) \
            || fail "bootstrap principal audit could not inspect $database"
        while IFS= read -r row; do
            test -n "$row" || continue
            printf '%s:%s\n' "$database" "$row"
        done <<<"$rows"

        # The system database is immutable for user defaults/schema DDL; its
        # current principal grants and ownership were still audited above.
        test "$database" != 'system' || continue

        rows=$(root_sql_in_database "$database" "
            SELECT COALESCE(role, '') || ':' || for_all_roles::STRING || ':' ||
                   object_type || ':' || grantee || ':' || privilege_type || ':' ||
                   CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END
            FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE fleet_writer]
            WHERE object_type IN (
                'schemas', 'routines', 'tables', 'sequences', 'types'
            )
              AND (
                  role = 'fleet_writer'
                  AND NOT for_all_roles
                  AND grantee = 'fleet_writer'
                  AND privilege_type = 'ALL'
                  AND is_grantable
              ) IS NOT TRUE
            ORDER BY 1
        " | tail -n +2) \
            || fail "bootstrap principal audit could not inspect $database defaults"
        while IFS= read -r row; do
            test -n "$row" || continue
            printf '%s:default:database:%s\n' "$database" "$row"
        done <<<"$rows"

        schemas=$(root_sql_in_database "$database" "
            SELECT nspname, quote_ident(nspname)
            FROM pg_catalog.pg_namespace
            WHERE nspname NOT IN (
                'pg_catalog', 'information_schema',
                'crdb_internal', 'pg_extension'
            )
              AND nspname NOT LIKE 'pg_temp_%'
            ORDER BY nspname
        " | tail -n +2) \
            || fail "bootstrap principal audit could not enumerate schemas in $database"
        while IFS=$'\t' read -r schema_name schema_identifier; do
            test -n "$schema_name" || continue
            test -n "$schema_identifier" \
                || fail "bootstrap principal audit found an unquotable schema in $database"
            rows=$(root_sql_in_database "$database" "
                SELECT COALESCE(role, '') || ':' || for_all_roles::STRING || ':' ||
                       object_type || ':' || grantee || ':' || privilege_type || ':' ||
                       CASE WHEN is_grantable
                            THEN 'grantable' ELSE 'not_grantable' END
                FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE fleet_writer
                      IN SCHEMA $schema_identifier]
                WHERE object_type IN (
                    'schemas', 'routines', 'tables', 'sequences', 'types'
                )
                  AND (
                      role = 'fleet_writer'
                      AND NOT for_all_roles
                      AND grantee = 'fleet_writer'
                      AND privilege_type = 'ALL'
                      AND is_grantable
                  ) IS NOT TRUE
                ORDER BY 1
            " | tail -n +2) \
                || fail "bootstrap principal audit could not inspect $database.$schema_name defaults"
            while IFS= read -r row; do
                test -n "$row" || continue
                printf '%s:default:schema:%s:%s\n' \
                    "$database" "$schema_name" "$row"
            done <<<"$rows"
        done <<<"$schemas"
    done <<<"$databases"
}

# PUBLIC is inherited by every role. Ignore only ordinary other-database
# CONNECT/TEMPORARY/public-schema-USAGE and synthetic virtual/system fallbacks.
# Report all current application authority and every non-intrinsic database- or
# application-schema-scoped future default.
inventory_other_database_public_authority() {
    local databases
    local database
    local schemas
    local schema_name
    local schema_identifier
    local rows
    local row
    rows=$(root_sql "
        SELECT 'cluster_grant:' || object_type || ':' ||
               COALESCE(object_name, '') || ':' || privilege_type || ':' ||
               CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END
        FROM [SHOW GRANTS FOR public]
        WHERE grantee = 'public'
          AND database_name IS NULL
        ORDER BY 1
    " | tail -n +2) \
        || fail "external PUBLIC audit could not inspect cluster-global grants"
    while IFS= read -r row; do
        test -n "$row" || continue
        printf '%s\n' "$row"
    done <<<"$rows"
    databases=$(root_sql \
        'SELECT database_name FROM [SHOW DATABASES] ORDER BY database_name' \
        | tail -n +2) || fail "external PUBLIC audit could not enumerate databases"
    while IFS= read -r database; do
        test -n "$database" || continue
        test "$database" != 'fleet_recall' || continue
        rows=$(root_sql_in_database "$database" "
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
        " | tail -n +2) \
            || fail "external PUBLIC audit could not inspect $database"
        while IFS= read -r row; do
            test -n "$row" || continue
            printf '%s:%s\n' "$database" "$row"
        done <<<"$rows"

        # The system database is immutable for user defaults/schema DDL; its
        # exact current PUBLIC exceptions were still audited above.
        test "$database" != 'system' || continue

        rows=$(root_sql_in_database "$database" "
            SELECT 'default:database:' || COALESCE(role, '') || ':' ||
                   for_all_roles::STRING || ':' || object_type || ':' ||
                   grantee || ':' || privilege_type || ':' ||
                   CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END
            FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE public]
            WHERE object_type IN (
                'schemas', 'routines', 'tables', 'sequences', 'types'
            )
              AND (
                  grantee = 'public'
                  AND NOT is_grantable
                  AND object_type = 'types'
                  AND privilege_type = 'USAGE'
              ) IS NOT TRUE
              AND (
                  role IS NULL
                  AND for_all_roles
                  AND grantee = 'public'
                  AND object_type = 'routines'
                  AND privilege_type = 'EXECUTE'
                  AND NOT is_grantable
              ) IS NOT TRUE
              AND (
                  role = 'fleet_runtime'
                  AND NOT for_all_roles
                  AND grantee = 'public'
                  AND object_type = 'routines'
                  AND privilege_type = 'EXECUTE'
                  AND NOT is_grantable
              ) IS NOT TRUE
            ORDER BY 1
        " | tail -n +2) \
            || fail "external PUBLIC audit could not inspect database defaults in $database"
        while IFS= read -r row; do
            test -n "$row" || continue
            printf '%s:%s\n' "$database" "$row"
        done <<<"$rows"

        schemas=$(root_sql_in_database "$database" "
            SELECT nspname, quote_ident(nspname)
            FROM pg_catalog.pg_namespace
            WHERE nspname NOT IN (
                'pg_catalog', 'information_schema',
                'crdb_internal', 'pg_extension'
            )
              AND nspname NOT LIKE 'pg_temp_%'
            ORDER BY nspname
        " | tail -n +2) \
            || fail "external PUBLIC audit could not enumerate schemas in $database"
        while IFS=$'\t' read -r schema_name schema_identifier; do
            test -n "$schema_name" || continue
            test -n "$schema_identifier" \
                || fail "external PUBLIC audit found an unquotable schema in $database"
            rows=$(root_sql_in_database "$database" "
                SELECT COALESCE(role, '') || ':' || for_all_roles::STRING || ':' ||
                       object_type || ':' || grantee || ':' || privilege_type || ':' ||
                       CASE WHEN is_grantable
                            THEN 'grantable' ELSE 'not_grantable' END
                FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE public
                      IN SCHEMA $schema_identifier]
                WHERE object_type IN (
                    'schemas', 'routines', 'tables', 'sequences', 'types'
                )
                  AND (
                      grantee = 'public'
                      AND NOT is_grantable
                      AND object_type = 'types'
                      AND privilege_type = 'USAGE'
                  ) IS NOT TRUE
                  AND (
                      role IS NULL
                      AND for_all_roles
                      AND grantee = 'public'
                      AND object_type = 'routines'
                      AND privilege_type = 'EXECUTE'
                      AND NOT is_grantable
                  ) IS NOT TRUE
                  AND (
                      role = 'fleet_runtime'
                      AND NOT for_all_roles
                      AND grantee = 'public'
                      AND object_type = 'routines'
                      AND privilege_type = 'EXECUTE'
                      AND NOT is_grantable
                  ) IS NOT TRUE
                ORDER BY 1
            " | tail -n +2) \
                || fail "external PUBLIC audit could not inspect $database.$schema_name defaults"
            while IFS= read -r row; do
                test -n "$row" || continue
                printf '%s:default:schema:%s:%s\n' \
                    "$database" "$schema_name" "$row"
            done <<<"$rows"
        done <<<"$schemas"
    done <<<"$databases"
}

assert_empty_audit() {
    local label=$1
    local audit_function=$2
    local actual
    actual=$("$audit_function") \
        || fail "$label helper execution failed"
    assert_exact "$label" "$actual" ''
}

external_application_schema_set() {
    local databases
    local database
    local schemas
    local schema_name
    databases=$(root_sql \
        'SELECT database_name FROM [SHOW DATABASES] ORDER BY database_name' \
        | tail -n +2) || fail "topology audit could not enumerate databases"
    while IFS= read -r database; do
        test -n "$database" || continue
        schemas=$(root_sql_in_database "$database" "
            SELECT nspname
            FROM pg_catalog.pg_namespace
            WHERE nspname NOT IN (
                'pg_catalog', 'information_schema',
                'crdb_internal', 'pg_extension'
            )
              AND nspname NOT LIKE 'pg_temp_%'
            ORDER BY nspname
        " | tail -n +2) \
            || fail "topology audit could not enumerate schemas in $database"
        while IFS= read -r schema_name; do
            test -n "$schema_name" || continue
            printf '%s:%s\n' "$database" "$schema_name"
        done <<<"$schemas"
    done <<<"$databases"
}

assert_external_topology() {
    local databases
    local schemas
    databases=$(root_sql \
        'SELECT database_name FROM [SHOW DATABASES] ORDER BY database_name' \
        | tail -n +2) || fail "topology audit could not read database set"
    assert_exact "audited database set" "$databases" 'defaultdb
fleet_recall
postgres
proof_runtime_other_database
system'
    schemas=$(external_application_schema_set) \
        || fail "topology audit could not read application-schema set"
    assert_exact "audited application-schema set" "$schemas" 'defaultdb:public
fleet_recall:public
postgres:public
proof_runtime_other_database:proof_application
proof_runtime_other_database:public
system:public'
}

enable_audited_writer_login() {
    assert_external_topology
    assert_empty_audit "pre-LOGIN external runtime/writer authority" \
        audit_other_database_runtime_authority
    assert_empty_audit "pre-LOGIN external PUBLIC authority" \
        inventory_other_database_public_authority
    assert_root_scalar "pre-LOGIN direct writer authority" \
        "SELECT count(*)::STRING FROM [SHOW GRANTS FOR fleet_writer]
         WHERE grantee = 'fleet_writer'" '0'
    assert_root_scalar "pre-LOGIN exact runtime leaf" \
        "SELECT count(*)::STRING FROM [SHOW GRANTS ON ROLE]
         WHERE role_name = 'fleet_runtime'
           AND member = 'fleet_writer'
           AND NOT is_admin" '1'
    assert_root_scalar "pre-LOGIN system authority" \
        "SELECT count(*)::STRING FROM [SHOW SYSTEM GRANTS]
         WHERE grantee IN ('fleet_runtime', 'fleet_writer', 'public')" '0'
    assert_root_scalar "pre-LOGIN quiesced writer" \
        "SELECT count(*)::STRING FROM [SHOW USERS]
         WHERE username = 'fleet_writer'
           AND options::STRING = '{NOLOGIN}'" '1'
    root_sql 'ALTER USER fleet_writer WITH LOGIN' >/dev/null \
        || fail "audited writer LOGIN transition failed"
}

# Static proof: this entire section must finish before the first Docker command.
bash -n "$0"

policy_first_statement=$(awk '
    /^[[:space:]]*--/ || /^[[:space:]]*$/ { next }
    { print; exit }
' "$policy") || fail "could not extract the policy first statement"
assert_exact "runtime policy first statement" \
    "$policy_first_statement" 'SET search_path = pg_catalog, public, pg_temp;'

role_option_hardening=$(sed -n \
    '/^ALTER ROLE fleet_runtime WITH$/,/^    NOVIEWCLUSTERSETTING;$/p' \
    "$policy") || fail "could not extract runtime role-option hardening"
expected_role_option_hardening='ALTER ROLE fleet_runtime WITH
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
assert_exact "complete v26.2 runtime role-option hardening" \
    "$role_option_hardening" "$expected_role_option_hardening"

policy_grant_statements=$(awk '
    {
        line = $0
        sub(/--.*$/, "", line)
        if (!in_grant && line ~ /^[[:space:]]*GRANT[[:space:]]/) {
            in_grant = 1
            statement = line
        } else if (in_grant) {
            statement = statement " " line
        }
        if (in_grant && line ~ /;/) {
            gsub(/[[:space:]]+/, " ", statement)
            sub(/^ /, "", statement)
            sub(/ $/, "", statement)
            print statement
            in_grant = 0
            statement = ""
        }
    }
    END { if (in_grant) exit 2 }
' "$policy") || fail "could not extract the policy GRANT statements"
expected_policy_grant_statements='GRANT CONNECT ON DATABASE fleet_recall TO fleet_runtime;
GRANT USAGE ON SCHEMA public TO fleet_runtime;
GRANT SELECT ON TABLE public._sqlx_migrations, public.memory_corpus_models, public.memory_chunks, public.memory_chunk_history, public.memory_claims, public.memory_claim_embeddings, public.memory_claim_support, public.memory_conflict_members, public.memory_conflicts, public.memory_claim_links, public.memory_mutation_receipts TO fleet_runtime;
GRANT INSERT ON TABLE public.memory_corpus_models, public.memory_chunks, public.memory_claims, public.memory_claim_embeddings, public.memory_claim_support, public.memory_claim_events, public.memory_conflict_members, public.memory_conflicts, public.memory_mutation_receipts, public.memory_events TO fleet_runtime;
GRANT UPDATE ON TABLE public.memory_chunks, public.memory_claims, public.memory_conflicts, public.memory_mutation_receipts TO fleet_runtime;
GRANT DELETE ON TABLE public.memory_chunk_history TO fleet_runtime;
GRANT SELECT, INSERT ON TABLE public.memory_evidence_events, public.memory_evidence_quarantine, public.memory_content_objects TO fleet_runtime;
GRANT SELECT, INSERT, UPDATE ON TABLE public.memory_evidence_shard_heads, public.memory_relation_projection_v1, public.memory_relation_projection_watermarks_v1 TO fleet_runtime;
GRANT SELECT ON TABLE public.memory_writer_authority_v1 TO fleet_runtime;
GRANT USAGE ON SEQUENCE public.memory_claim_id_seq, public.memory_claim_support_id_seq, public.memory_conflict_id_seq TO fleet_runtime;
GRANT fleet_runtime TO fleet_writer;'
assert_exact "complete runtime GRANT allowlist" \
    "$policy_grant_statements" "$expected_policy_grant_statements"

if grep -Eq '^[[:space:]]*GRANT[[:space:]].*ON[[:space:]]+ALL' "$policy"; then
    fail "runtime policy installs an ON ALL future/current-object grant"
fi
if grep -Eq '^[[:space:]]*ALTER[[:space:]]+DEFAULT[[:space:]]+PRIVILEGES' "$policy"; then
    fail "runtime policy installs a future-object grant"
fi
for forbidden_grant_object in \
    memory_attention \
    memory_claim_link_events \
    memory_claim_link_id_seq
do
    if grep -Fq "$forbidden_grant_object" <<<"$policy_grant_statements"; then
        fail "$forbidden_grant_object leaked into the runtime GRANT allowlist"
    fi
done
if grep -Eq '^GRANT (TRUNCATE|REFERENCES|CREATE)' \
    <<<"$policy_grant_statements"; then
    fail "runtime policy grants a forbidden write or DDL verb"
fi

for required_policy_shape in \
    "pg_catalog.current_database() <> 'fleet_recall'" \
    'count(*) = 18' \
    'min(version) = 1' \
    'max(version) = 18' \
    'COALESCE(bool_and(success), false)' \
    "options::STRING = '{NOLOGIN}'" \
    'SHOW DEFAULT PRIVILEGES FOR GRANTEE public' \
    'SHOW DEFAULT PRIVILEGES FOR GRANTEE fleet_writer' \
    'SHOW DEFAULT PRIVILEGES FOR GRANTEE fleet_runtime' \
    'SHOW SYSTEM GRANTS' \
    'SHOW GRANTS ON ROLE' \
    'REVOKE SYSTEM ALL FROM fleet_runtime' \
    'REVOKE ALL ON ALL TABLES IN SCHEMA public' \
    'REVOKE ALL ON ALL SEQUENCES IN SCHEMA public' \
    'count(*) = 47'
do
    grep -Fq "$required_policy_shape" "$policy" \
        || fail "runtime policy lost required shape: $required_policy_shape"
done

unqualified_current_database=$(awk '
    {
        line = $0
        gsub(/pg_catalog[.]current_database[(][)]/, "", line)
        needle = "current_" "database("
        if (index(line, needle)) {
            print FILENAME ":" FNR ":" line
        }
    }
' "$policy" "$0") || fail "could not audit current_database qualification"
assert_exact "zero unqualified current_database calls" \
    "$unqualified_current_database" ''

# These hashes freeze the reviewed command/call/SQL/connection snapshot behind
# the matrix. The semantic reachability assertions below explain the one narrow
# keyed history DELETE (and the SELECT CockroachDB requires to evaluate its
# WHERE clause); any source change requires a new privilege review.
reviewed_source_manifest=$(shasum -a 256 \
    "$repo_root/src/config.rs" \
    "$repo_root/src/main.rs" \
    "$repo_root/src/private_postgres.rs" \
    "$repo_root/src/store/cockroach.rs" \
    "$repo_root/src/ledger/cockroach.rs" \
    "$repo_root/src/service.rs" \
    "$repo_root/src/application.rs" \
    "$repo_root/src/reference_agent.rs") \
    || fail "could not hash the reviewed runtime source snapshot"
expected_reviewed_source_manifest="5ddd1e204c55dce12b0f22c94557c5271d7e559c0668d4cc46907d8cb2422f45  $repo_root/src/config.rs
76224d95199b19cf12b52f623ece802b9c5d57abc57833c17de2ccd336db16be  $repo_root/src/main.rs
7718c15393872a139956732629c472d813a2a014395f943a5382191966162745  $repo_root/src/private_postgres.rs
586f6c9c935140de9580e4b4490df3fc24a9f30e9f4c6c6bf1e194c6e6fc9d1e  $repo_root/src/store/cockroach.rs
b8c3ffbd3dfe7a74f76a06815f317db3e79b3129adaa14e2da5bea43f60b069f  $repo_root/src/ledger/cockroach.rs
6f0c6874072baed1070204063ac65df0761eda2da862e51775ba85cc5a34b522  $repo_root/src/service.rs
5c1707702371016d7d35a58ffe8179e6015d48564e12e36df81cfc8b2c5f5e70  $repo_root/src/application.rs
2bfc742926ef753ee90458a294bb59dbddf2afa2e9983484548f2fe0b7b77d26  $repo_root/src/reference_agent.rs"
assert_exact "reviewed runtime source manifest" \
    "$reviewed_source_manifest" "$expected_reviewed_source_manifest"

# Freeze the reason that dormant library history/delete capability is excluded:
# the only production upsert caller is ingest, every constructed row is active,
# and archive parents are rejected before ScopedChunk construction. That active
# branch deletes a namesake history row before UPSERT, explaining the one exact
# history DELETE. Tests below cfg(test) deliberately exercise the wider library
# API and do not widen the long-lived executable role.
main_production=$(sed '/^#\[cfg(test)\]/,$d' "$main_source") \
    || fail "could not extract the production main source"
production_upsert_count=$(awk '
    index($0, ".upsert_chunk(") { count += 1 }
    END { print count + 0 }
' <<<"$main_production") || fail "could not count production upsert callers"
assert_exact "production upsert caller count" "$production_upsert_count" '1'
production_active_chunk_count=$(awk '
    index($0, "stale: false") { count += 1 }
    END { print count + 0 }
' <<<"$main_production") \
    || fail "could not count production active ScopedChunk values"
assert_exact "production active ScopedChunk count" \
    "$production_active_chunk_count" '1'
production_stale_chunk_count=$(awk '
    index($0, "stale: true") { count += 1 }
    END { print count + 0 }
' <<<"$main_production") \
    || fail "could not count production stale ScopedChunk values"
assert_exact "production stale ScopedChunk count" \
    "$production_stale_chunk_count" '0'
grep -Fq 'archive-parent chunks are not accepted by active corpus ingestion' \
    <<<"$main_production" \
    || fail "production ingest lost its archive-parent rejection"
if grep -rEq --include='*.rs' '\.upsert_chunk\(' "$repo_root/src/bin"; then
    fail "a private CLI gained an unreviewed chunk-upsert caller"
fi
write_chunk_transaction=$(sed -n \
    '/^async fn write_chunk_transaction(/,/^async fn ensure_active_model(/p' \
    "$repo_root/src/store/cockroach.rs") \
    || fail "could not extract write_chunk_transaction"
active_history_delete_count=$(awk '
    index($0, "DELETE FROM memory_chunk_history") { count += 1 }
    END { print count + 0 }
' <<<"$write_chunk_transaction") \
    || fail "could not count active history deletes"
assert_exact "active upsert history DELETE count" \
    "$active_history_delete_count" '1'
if grep -Eq \
    '^[[:space:]]*"?\$\((root_sql|root_sql_in_database|sql_as_writer|apply_policy|grep|awk|sed|rg)' \
    "$0"; then
    fail "SQL helper call is nested inside an assertion/test substitution"
fi
writer_login_transition_count=$(awk '
    BEGIN { needle = "ALTER USER fleet_writer WITH " "LOGIN" }
    index($0, needle) { count += 1 }
    END { print count + 0 }
' "$0") || fail "could not audit writer LOGIN transitions"
assert_exact "centralized audited writer LOGIN transition count" \
    "$writer_login_transition_count" '1'
audited_login_helper=$(sed -n \
    '/^enable_audited_writer_login() {$/,/^}$/p' "$0") \
    || fail "could not extract the audited LOGIN helper"
writer_login_sql=$(printf '%s%s' \
    'ALTER USER fleet_writer WITH ' 'LOGIN') \
    || fail "could not construct the audited LOGIN statement"
grep -Fq "root_sql '$writer_login_sql'" \
    <<<"$audited_login_helper" \
    || fail "fleet_writer LOGIN is not owned by the audited helper"

# CockroachDB retains creator-scoped default-privilege dependencies on a role.
# Every proof role that is dropped must first restore PUBLIC's intrinsic routine
# default in every mutable database that exists at that point. Freeze the exact
# restore-before-DROP ordering so a failed adversary cleanup cannot recur.
runtime_edge_drop_lifecycle=$(awk '
    $0 == "# temporary-role drop lifecycle: runtime_edge_probe begin" {
        starts += 1
        capture = 1
        next
    }
    $0 == "# temporary-role drop lifecycle: runtime_edge_probe end" {
        ends += 1
        capture = 0
        next
    }
    capture { print }
    END { if (starts != 1 || ends != 1 || capture) exit 2 }
' "$0") || fail "could not extract runtime_edge_probe drop lifecycle"
expected_runtime_edge_drop_lifecycle="root_sql 'REVOKE runtime_edge_probe FROM fleet_writer' >/dev/null
root_sql 'GRANT runtime_edge_probe TO root' >/dev/null
for database in fleet_recall defaultdb postgres; do
    root_sql_in_database \"\$database\" '
ALTER DEFAULT PRIVILEGES FOR ROLE runtime_edge_probe
    GRANT EXECUTE ON ROUTINES TO public;
' >/dev/null
done
root_sql 'REVOKE runtime_edge_probe FROM root' >/dev/null
root_sql 'DROP ROLE runtime_edge_probe' >/dev/null"
assert_exact "runtime_edge_probe restore-before-DROP lifecycle" \
    "$runtime_edge_drop_lifecycle" "$expected_runtime_edge_drop_lifecycle"

runtime_target_drop_lifecycle=$(awk '
    $0 == "# temporary-role drop lifecycle: fleet_runtime begin" {
        starts += 1
        capture = 1
        next
    }
    $0 == "# temporary-role drop lifecycle: fleet_runtime end" {
        ends += 1
        capture = 0
        next
    }
    capture { print }
    END { if (starts != 1 || ends != 1 || capture) exit 2 }
' "$0") || fail "could not extract fleet_runtime drop lifecycle"
expected_runtime_target_drop_lifecycle="root_sql 'GRANT fleet_runtime TO root' >/dev/null
for database in fleet_recall defaultdb postgres proof_runtime_other_database; do
    root_sql_in_database \"\$database\" '
ALTER DEFAULT PRIVILEGES FOR ROLE fleet_runtime
    GRANT EXECUTE ON ROUTINES TO public;
' >/dev/null
done
root_sql 'REVOKE fleet_runtime FROM root' >/dev/null
root_sql '
REVOKE fleet_runtime FROM fleet_writer;
REVOKE ALL ON DATABASE fleet_recall FROM fleet_runtime;
REVOKE ALL ON SCHEMA public FROM fleet_runtime;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM fleet_runtime;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM fleet_runtime;
DROP ROLE fleet_runtime;
' >/dev/null"
assert_exact "fleet_runtime restore-before-DROP lifecycle" \
    "$runtime_target_drop_lifecycle" "$expected_runtime_target_drop_lifecycle"

connected_drop_roles=$(awk '
    $0 == "# Connected parity starts only after every static assertion above." {
        connected = 1
        next
    }
    connected && index($0, "DROP ROLE ") {
        role_name = $0
        sub(/^.*DROP ROLE[[:space:]]+/, "", role_name)
        sub(/[^[:alnum:]_].*$/, "", role_name)
        print role_name
    }
' "$0") || fail "could not inventory connected DROP ROLE statements"
assert_exact "complete temporary-role DROP inventory" \
    "$connected_drop_roles" 'runtime_edge_probe
fleet_runtime'

if test "${FLEET_RECALL_RUNTIME_RBAC_STATIC_ONLY:-0}" = '1'; then
    echo "runtime-role static checks complete"
    exit 0
fi

# Connected parity starts only after every static assertion above.
container="ostk-runtime-role-grants-$$"
cleanup() {
    test -n "$container" || return 0
    docker rm --force "$container" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM
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
server_build_tag=$(docker exec "$container" cockroach version --build-tag) \
    || fail "could not read Docker server build tag"
assert_exact "Docker server build tag" \
    "$server_build_tag" "$expected_crdb_build_tag"

docker exec "$container" cockroach sql --insecure \
    --execute 'CREATE DATABASE fleet_recall' >/dev/null

# Privilege-shaped stand-ins make each positive and negative edge executable.
# The receipt has all three nullable production parent FKs because v26.2.3
# checks SELECT on every referenced parent during INSERT.
root_sql '
CREATE TABLE public._sqlx_migrations (
    version INT8 PRIMARY KEY,
    success BOOL NOT NULL
);
CREATE TABLE public.memory_corpus_models (
    id INT8 PRIMARY KEY,
    value INT8 NOT NULL DEFAULT 0
);
CREATE TABLE public.memory_chunks (
    id INT8 PRIMARY KEY,
    value INT8 NOT NULL DEFAULT 0
);
CREATE TABLE public.memory_chunk_history (
    id INT8 PRIMARY KEY,
    value INT8 NOT NULL DEFAULT 0
);
CREATE SEQUENCE public.memory_claim_id_seq;
CREATE TABLE public.memory_claims (
    tenant_id UUID NOT NULL DEFAULT '\''0198a849-f6ae-7d61-9800-000000000001'\'',
    project STRING NOT NULL DEFAULT '\''runtime-proof'\'',
    id INT8 NOT NULL DEFAULT nextval('\''public.memory_claim_id_seq'\''),
    value INT8 NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, project, id)
);
CREATE SEQUENCE public.memory_claim_support_id_seq;
CREATE TABLE public.memory_claim_support (
    id INT8 PRIMARY KEY DEFAULT nextval('\''public.memory_claim_support_id_seq'\''),
    value INT8 NOT NULL DEFAULT 0
);
CREATE TABLE public.memory_claim_embeddings (
    id INT8 PRIMARY KEY,
    value INT8 NOT NULL DEFAULT 0
);
CREATE TABLE public.memory_claim_events (
    id INT8 PRIMARY KEY,
    value INT8 NOT NULL DEFAULT 0
);
CREATE SEQUENCE public.memory_conflict_id_seq;
CREATE TABLE public.memory_conflicts (
    tenant_id UUID NOT NULL DEFAULT '\''0198a849-f6ae-7d61-9800-000000000001'\'',
    project STRING NOT NULL DEFAULT '\''runtime-proof'\'',
    id INT8 NOT NULL DEFAULT nextval('\''public.memory_conflict_id_seq'\''),
    value INT8 NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, project, id)
);
CREATE TABLE public.memory_conflict_members (
    id INT8 PRIMARY KEY,
    value INT8 NOT NULL DEFAULT 0
);
CREATE SEQUENCE public.memory_claim_link_id_seq;
CREATE TABLE public.memory_claim_links (
    tenant_id UUID NOT NULL DEFAULT '\''0198a849-f6ae-7d61-9800-000000000001'\'',
    project STRING NOT NULL DEFAULT '\''runtime-proof'\'',
    id INT8 NOT NULL DEFAULT nextval('\''public.memory_claim_link_id_seq'\''),
    value INT8 NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, project, id)
);
CREATE TABLE public.memory_claim_link_events (
    id INT8 PRIMARY KEY,
    value INT8 NOT NULL DEFAULT 0
);
CREATE TABLE public.memory_attention (
    id INT8 PRIMARY KEY,
    value INT8 NOT NULL DEFAULT 0
);
CREATE TABLE public.memory_mutation_receipts (
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
        REFERENCES public.memory_claims (tenant_id, project, id),
    FOREIGN KEY (tenant_id, project, conflict_id)
        REFERENCES public.memory_conflicts (tenant_id, project, id),
    FOREIGN KEY (tenant_id, project, link_id)
        REFERENCES public.memory_claim_links (tenant_id, project, id)
);
CREATE TABLE public.memory_events (
    id INT8 PRIMARY KEY,
    value INT8 NOT NULL DEFAULT 0
);
CREATE TABLE public.memory_control_bootstraps (id INT8 PRIMARY KEY);
CREATE TABLE public.memory_control_events (id INT8 PRIMARY KEY);
CREATE TABLE public.memory_control_log_epochs (id INT8 PRIMARY KEY);
CREATE TABLE public.memory_control_shard_heads (id INT8 PRIMARY KEY);
CREATE TABLE public.memory_registry_activations (id INT8 PRIMARY KEY);
CREATE TABLE public.memory_registry_current_heads_v2 (id INT8 PRIMARY KEY);
CREATE TABLE public.memory_registry_genesis_bridge_consumptions (id INT8 PRIMARY KEY);
CREATE TABLE public.memory_registry_heads (id INT8 PRIMARY KEY);
CREATE TABLE public.memory_registry_transitions (id INT8 PRIMARY KEY);
CREATE TABLE public.memory_evidence_quarantine (
    id INT8 PRIMARY KEY,
    value INT8 NOT NULL DEFAULT 0
);
CREATE TABLE public.memory_content_objects (
    id INT8 PRIMARY KEY,
    value INT8 NOT NULL DEFAULT 0
);
CREATE TABLE public.memory_relation_projection_v1 (
    id INT8 PRIMARY KEY,
    value INT8 NOT NULL DEFAULT 0
);
CREATE TABLE public.memory_relation_projection_watermarks_v1 (
    id INT8 PRIMARY KEY,
    value INT8 NOT NULL DEFAULT 0
);
CREATE VIEW public.memory_writer_authority_v1 AS
    SELECT id FROM public.memory_control_bootstraps;
'

# The evidence ledger's three appendable relations are created from the REAL
# migration-0018 text, not from a stand-in. A stand-in without the epoch and
# head foreign keys cannot express the failure this proof exists to catch: on
# CockroachDB v26.2.3 a foreign-key check is evaluated with the INSERTING
# role's privileges, so a head whose FK points at a control-plane parent is
# unappendable by a role that ADR 0002 D2 denies every memory_control_* grant
# (SQLSTATE 42501). Extracting the definitions keeps this fixture from drifting
# away from the migration it claims to model.
migration_0018="$repo_root/migrations/0018_stage4_evidence_ledger.sql"
extract_migration_table() {
    local table=$1
    local definition
    definition=$(awk -v table="$table" '
        $0 == "CREATE TABLE IF NOT EXISTS " table " (" { capturing = 1 }
        capturing { print }
        capturing && $0 == ");" { exit }
    ' "$migration_0018") || return 1
    test -n "$definition" || return 1
    printf '%s\n' "$definition"
}
if grep -Fq 'REFERENCES memory_control_' "$migration_0018"; then
    fail "migration 0018 points an evidence foreign key at a control-plane table"
fi
evidence_plane_fixture=''
for evidence_plane_table in \
    memory_evidence_shard_heads \
    memory_evidence_events
do
    evidence_plane_definition=$(extract_migration_table "$evidence_plane_table") \
        || fail "could not extract $evidence_plane_table from migration 0018"
    evidence_plane_fixture="$evidence_plane_fixture$evidence_plane_definition
"
done
root_sql "$evidence_plane_fixture" >/dev/null

# Wrong database and incomplete/failed real prefix gates precede target creation.
wrong_database_output=''
if wrong_database_output=$(apply_policy_in_database defaultdb 2>&1); then
    fail "runtime policy unexpectedly ran in defaultdb"
fi
grep -Fq 'runtime writer policy must run in fleet_recall' \
    <<<"$wrong_database_output" \
    || fail "wrong-database gate lost its stable diagnostic"
grep -Fq 'SQLSTATE: 55000' <<<"$wrong_database_output" \
    || fail "wrong-database gate lost SQLSTATE 55000"

root_sql '
INSERT INTO public._sqlx_migrations
SELECT version, true FROM generate_series(1, 17) AS version;
' >/dev/null
expect_policy_failure "missing migration 18" \
    'runtime writer role requires the complete successful migration prefix through 18' \
    '55000'
if temp_prefix_output=$(apply_policy_with_valid_temp_prefix 2>&1); then
    fail "valid temporary prefix masked the incomplete public prefix"
fi
grep -Fq 'runtime writer role requires the complete successful migration prefix through 18' \
    <<<"$temp_prefix_output" \
    || fail "temporary-prefix gate did not read public._sqlx_migrations"
assert_root_scalar "prefix-failure target creation" \
    "SELECT count(*)::STRING FROM [SHOW USERS]
     WHERE username = 'fleet_runtime'" '0'

root_sql '
INSERT INTO public._sqlx_migrations VALUES (18, false), (19, true);
' >/dev/null
expect_policy_failure "failed migration 18 with later success" \
    'runtime writer role requires the complete successful migration prefix through 18' \
    '55000'
root_sql 'UPDATE public._sqlx_migrations SET success = true WHERE version = 18' \
    >/dev/null

# The fixed externally provisioned login must exist but be drained and exactly
# NOLOGIN while policy and external cross-database audits run.
expect_policy_failure "missing fixed writer principal" \
    'runtime writer policy requires exact quiesced principal fleet_writer with options {NOLOGIN}' \
    '22P02'
root_sql 'CREATE USER fleet_writer' >/dev/null
expect_policy_failure "writer principal left LOGIN" \
    'runtime writer policy requires exact quiesced principal fleet_writer with options {NOLOGIN}' \
    '22P02'
root_sql 'ALTER USER fleet_writer WITH NOLOGIN' >/dev/null

# Establish the documented clean v26.2 PUBLIC routine-default baseline.
root_sql '
GRANT fleet_writer TO root;
ALTER DEFAULT PRIVILEGES FOR ROLE root, admin, fleet_writer
    REVOKE EXECUTE ON ROUTINES FROM public;
ALTER DEFAULT PRIVILEGES FOR ALL ROLES
    REVOKE EXECUTE ON ROUTINES FROM public;
REVOKE fleet_writer FROM root;
' >/dev/null

# Fail-before-mutation adversaries. Each preflight leaves the logical role
# absent and preserves the hostile edge until the operator removes it.
root_sql 'GRANT SELECT ON TABLE public.memory_chunks TO fleet_writer' >/dev/null
expect_policy_failure "fixed writer direct grant" \
    'runtime writer principal must have no direct object grants' '22P02'
assert_root_scalar "direct-grant target creation" \
    "SELECT count(*)::STRING FROM [SHOW USERS]
     WHERE username = 'fleet_runtime'" '0'
assert_root_scalar "direct writer grant preservation" \
    "SELECT count(*)::STRING FROM [SHOW GRANTS FOR fleet_writer]
     WHERE grantee = 'fleet_writer'
       AND object_name = 'memory_chunks'
       AND privilege_type = 'SELECT'" '1'
root_sql 'REVOKE SELECT ON TABLE public.memory_chunks FROM fleet_writer' \
    >/dev/null

root_sql 'GRANT SYSTEM VIEWACTIVITY TO fleet_writer' >/dev/null
expect_policy_failure "fixed writer system grant" \
    'runtime writer principal must have no system privileges' '22P02'
assert_root_scalar "writer system grant preservation" \
    "SELECT count(*)::STRING FROM [SHOW SYSTEM GRANTS]
     WHERE grantee = 'fleet_writer'
       AND privilege_type = 'VIEWACTIVITY'" '1'
root_sql 'REVOKE SYSTEM VIEWACTIVITY FROM fleet_writer' >/dev/null

root_sql 'CREATE SCHEMA runtime_adversary' >/dev/null
expect_policy_failure "unexpected application schema" \
    'runtime writer policy requires public to be the only application schema' \
    '55000'
assert_root_scalar "schema-gate target creation" \
    "SELECT count(*)::STRING FROM [SHOW USERS]
     WHERE username = 'fleet_runtime'" '0'
root_sql 'DROP SCHEMA runtime_adversary' >/dev/null

root_sql 'GRANT SYSTEM CREATEROLE TO public' >/dev/null
expect_policy_failure "PUBLIC system grant" \
    'runtime writer policy requires PUBLIC to have no system privileges' \
    '22P02'
assert_root_scalar "PUBLIC system grant preservation" \
    "SELECT count(*)::STRING FROM [SHOW SYSTEM GRANTS]
     WHERE grantee = 'public'
       AND privilege_type = 'CREATEROLE'" '1'
root_sql 'REVOKE SYSTEM CREATEROLE FROM public' >/dev/null

root_sql '
ALTER DEFAULT PRIVILEGES FOR ROLE root IN SCHEMA public
    GRANT SELECT ON TABLES TO public;
' >/dev/null
expect_policy_failure "PUBLIC table future default" \
    'runtime writer policy permits only intrinsic PUBLIC type USAGE' '22P02'
assert_root_scalar "PUBLIC default preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE public IN SCHEMA public]
     WHERE role = 'root'
       AND object_type = 'tables'
       AND privilege_type = 'SELECT'" '1'
root_sql '
ALTER DEFAULT PRIVILEGES FOR ROLE root IN SCHEMA public
    REVOKE SELECT ON TABLES FROM public;
' >/dev/null

# Non-repairable PUBLIC function, type, and cluster-global external authority
# each fails before target creation and remains present until explicit cleanup.
root_sql '
CREATE FUNCTION public.runtime_public_probe()
RETURNS INT8 LANGUAGE SQL AS '\''SELECT 1'\'';
GRANT EXECUTE ON FUNCTION public.runtime_public_probe() TO public;
' >/dev/null
expect_policy_failure "PUBLIC function grant" \
    'runtime writer policy found an unsafe PUBLIC grant before target creation' \
    '22P02'
assert_root_scalar "PUBLIC-function target creation" \
    "SELECT count(*)::STRING FROM [SHOW USERS]
     WHERE username = 'fleet_runtime'" '0'
root_sql '
REVOKE EXECUTE ON FUNCTION public.runtime_public_probe() FROM public;
DROP FUNCTION public.runtime_public_probe();
' >/dev/null

root_sql '
CREATE TYPE public.runtime_public_type AS ENUM ('\''private'\'');
REVOKE USAGE ON TYPE public.runtime_public_type FROM public;
GRANT USAGE ON TYPE public.runtime_public_type TO public;
' >/dev/null
expect_policy_failure "PUBLIC type grant" \
    'runtime writer policy found an unsafe PUBLIC grant before target creation' \
    '22P02'
assert_root_scalar "PUBLIC-type target creation" \
    "SELECT count(*)::STRING FROM [SHOW USERS]
     WHERE username = 'fleet_runtime'" '0'
root_sql '
REVOKE USAGE ON TYPE public.runtime_public_type FROM public;
DROP TYPE public.runtime_public_type;
' >/dev/null

root_sql "
CREATE EXTERNAL CONNECTION runtime_public_external
    AS 'nodelocal://1/runtime-public-external';
GRANT USAGE, DROP ON EXTERNAL CONNECTION runtime_public_external TO public;
" >/dev/null
expect_policy_failure "PUBLIC external-connection grant" \
    'runtime writer policy found an unsafe PUBLIC grant before target creation' \
    '22P02'
assert_root_scalar "PUBLIC external grant preservation" \
    "SELECT count(*)::STRING FROM [SHOW GRANTS FOR public]
     WHERE grantee = 'public'
       AND database_name IS NULL
       AND object_type = 'external_connection'
       AND object_name = 'runtime_public_external'
       AND privilege_type IN ('DROP', 'USAGE')" '2'
root_sql '
REVOKE USAGE, DROP ON EXTERNAL CONNECTION runtime_public_external FROM public;
DROP EXTERNAL CONNECTION runtime_public_external;
' >/dev/null

root_sql '
ALTER DEFAULT PRIVILEGES FOR ROLE root IN SCHEMA public
    GRANT INSERT ON TABLES TO fleet_writer;
' >/dev/null
expect_policy_failure "fixed writer future default" \
    'runtime writer principal has non-intrinsic future-default authority' \
    '22P02'
root_sql '
ALTER DEFAULT PRIVILEGES FOR ROLE root IN SCHEMA public
    REVOKE INSERT ON TABLES FROM fleet_writer;
' >/dev/null

root_sql '
CREATE TABLE public.writer_owned_probe (id INT8 PRIMARY KEY);
GRANT fleet_writer TO root;
GRANT CREATE ON SCHEMA public TO fleet_writer;
ALTER TABLE public.writer_owned_probe OWNER TO fleet_writer;
REVOKE CREATE ON SCHEMA public FROM fleet_writer;
' >/dev/null
expect_policy_failure "fixed writer table ownership" \
    'runtime writer principal must not own database, schema, relation, function, or type objects' \
    '55000'
assert_root_scalar "writer ownership preservation" \
    "SELECT count(*)::STRING
     FROM pg_catalog.pg_class AS relation_object
     JOIN pg_catalog.pg_roles AS owner_role
       ON owner_role.oid = relation_object.relowner
     WHERE relation_object.relname = 'writer_owned_probe'
       AND owner_role.rolname = 'fleet_writer'" '1'
root_sql '
ALTER TABLE public.writer_owned_probe OWNER TO root;
DROP TABLE public.writer_owned_probe;
REVOKE fleet_writer FROM root;
' >/dev/null

root_sql '
CREATE ROLE runtime_edge_probe;
ALTER ROLE runtime_edge_probe WITH NOLOGIN;
GRANT runtime_edge_probe TO root;
ALTER DEFAULT PRIVILEGES FOR ROLE runtime_edge_probe
    REVOKE EXECUTE ON ROUTINES FROM public;
REVOKE runtime_edge_probe FROM root;
GRANT runtime_edge_probe TO fleet_writer;
' >/dev/null
expect_policy_failure "mixed writer role edge" \
    'runtime writer/principal role graph is not an exact leaf edge' '22P02'
assert_root_scalar "unexpected edge preservation" \
    "SELECT count(*)::STRING FROM [SHOW GRANTS ON ROLE]
     WHERE role_name = 'runtime_edge_probe'
       AND member = 'fleet_writer'" '1'
# temporary-role drop lifecycle: runtime_edge_probe begin
root_sql 'REVOKE runtime_edge_probe FROM fleet_writer' >/dev/null
root_sql 'GRANT runtime_edge_probe TO root' >/dev/null
for database in fleet_recall defaultdb postgres; do
    root_sql_in_database "$database" '
ALTER DEFAULT PRIVILEGES FOR ROLE runtime_edge_probe
    GRANT EXECUTE ON ROUTINES TO public;
' >/dev/null
done
root_sql 'REVOKE runtime_edge_probe FROM root' >/dev/null
root_sql 'DROP ROLE runtime_edge_probe' >/dev/null
# temporary-role drop lifecycle: runtime_edge_probe end

# Normalize every mutable stock other-database default before target creation.
# The exhaustive bootstrap inventories still inspect current system-database
# grants and ownership while skipping only unsupported system defaults/schema.
root_sql 'GRANT fleet_writer TO root' >/dev/null
for database in defaultdb postgres; do
    root_sql_in_database "$database" '
ALTER DEFAULT PRIVILEGES FOR ROLE root, admin, fleet_writer
    REVOKE EXECUTE ON ROUTINES FROM public;
ALTER DEFAULT PRIVILEGES FOR ALL ROLES
    REVOKE EXECUTE ON ROUTINES FROM public;
' >/dev/null
done
root_sql 'REVOKE fleet_writer FROM root' >/dev/null
root_sql_in_database defaultdb \
    'REVOKE CREATE ON SCHEMA public FROM public' >/dev/null
root_sql_in_database postgres \
    'REVOKE CREATE ON SCHEMA public FROM public' >/dev/null
assert_empty_audit "bootstrap external writer authority" \
    audit_other_database_principal_authority
assert_empty_audit "bootstrap external PUBLIC authority" \
    inventory_other_database_public_authority

# Ordinary PUBLIC drift inside the resettable application boundary is repaired;
# it is not confused with the unsafe preconditions above.
root_sql '
GRANT ALL ON DATABASE fleet_recall TO public;
GRANT ALL ON SCHEMA public TO public;
GRANT SELECT ON TABLE public.memory_chunks TO public;
GRANT ALL ON SEQUENCE public.memory_claim_link_id_seq TO public;
' >/dev/null
apply_policy >/dev/null

# Freeze the exact direct role matrix, principal leaf, role options, absence of
# system authority, and absence of current PUBLIC application grants.
actual_runtime_grants=$(root_sql "
    SELECT object_type || ':' || COALESCE(database_name, '') || ':' ||
           COALESCE(schema_name, '') || ':' || COALESCE(object_name, '') || ':' ||
           privilege_type || ':' ||
           CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END
    FROM [SHOW GRANTS FOR fleet_runtime]
    WHERE grantee = 'fleet_runtime'
    ORDER BY object_type, database_name, schema_name, object_name, privilege_type
" | tail -n +2) || fail "could not read connected runtime grant matrix"
expected_runtime_grants='database:fleet_recall:::CONNECT:not_grantable
schema:fleet_recall:public::USAGE:not_grantable
sequence:fleet_recall:public:memory_claim_id_seq:USAGE:not_grantable
sequence:fleet_recall:public:memory_claim_support_id_seq:USAGE:not_grantable
sequence:fleet_recall:public:memory_conflict_id_seq:USAGE:not_grantable
table:fleet_recall:public:_sqlx_migrations:SELECT:not_grantable
table:fleet_recall:public:memory_chunk_history:DELETE:not_grantable
table:fleet_recall:public:memory_chunk_history:SELECT:not_grantable
table:fleet_recall:public:memory_chunks:INSERT:not_grantable
table:fleet_recall:public:memory_chunks:SELECT:not_grantable
table:fleet_recall:public:memory_chunks:UPDATE:not_grantable
table:fleet_recall:public:memory_claim_embeddings:INSERT:not_grantable
table:fleet_recall:public:memory_claim_embeddings:SELECT:not_grantable
table:fleet_recall:public:memory_claim_events:INSERT:not_grantable
table:fleet_recall:public:memory_claim_links:SELECT:not_grantable
table:fleet_recall:public:memory_claim_support:INSERT:not_grantable
table:fleet_recall:public:memory_claim_support:SELECT:not_grantable
table:fleet_recall:public:memory_claims:INSERT:not_grantable
table:fleet_recall:public:memory_claims:SELECT:not_grantable
table:fleet_recall:public:memory_claims:UPDATE:not_grantable
table:fleet_recall:public:memory_conflict_members:INSERT:not_grantable
table:fleet_recall:public:memory_conflict_members:SELECT:not_grantable
table:fleet_recall:public:memory_conflicts:INSERT:not_grantable
table:fleet_recall:public:memory_conflicts:SELECT:not_grantable
table:fleet_recall:public:memory_conflicts:UPDATE:not_grantable
table:fleet_recall:public:memory_content_objects:INSERT:not_grantable
table:fleet_recall:public:memory_content_objects:SELECT:not_grantable
table:fleet_recall:public:memory_corpus_models:INSERT:not_grantable
table:fleet_recall:public:memory_corpus_models:SELECT:not_grantable
table:fleet_recall:public:memory_events:INSERT:not_grantable
table:fleet_recall:public:memory_evidence_events:INSERT:not_grantable
table:fleet_recall:public:memory_evidence_events:SELECT:not_grantable
table:fleet_recall:public:memory_evidence_quarantine:INSERT:not_grantable
table:fleet_recall:public:memory_evidence_quarantine:SELECT:not_grantable
table:fleet_recall:public:memory_evidence_shard_heads:INSERT:not_grantable
table:fleet_recall:public:memory_evidence_shard_heads:SELECT:not_grantable
table:fleet_recall:public:memory_evidence_shard_heads:UPDATE:not_grantable
table:fleet_recall:public:memory_mutation_receipts:INSERT:not_grantable
table:fleet_recall:public:memory_mutation_receipts:SELECT:not_grantable
table:fleet_recall:public:memory_mutation_receipts:UPDATE:not_grantable
table:fleet_recall:public:memory_relation_projection_v1:INSERT:not_grantable
table:fleet_recall:public:memory_relation_projection_v1:SELECT:not_grantable
table:fleet_recall:public:memory_relation_projection_v1:UPDATE:not_grantable
table:fleet_recall:public:memory_relation_projection_watermarks_v1:INSERT:not_grantable
table:fleet_recall:public:memory_relation_projection_watermarks_v1:SELECT:not_grantable
table:fleet_recall:public:memory_relation_projection_watermarks_v1:UPDATE:not_grantable
table:fleet_recall:public:memory_writer_authority_v1:SELECT:not_grantable'
assert_exact "connected runtime direct grant matrix" \
    "$actual_runtime_grants" "$expected_runtime_grants"
assert_root_scalar "logical and writer exact NOLOGIN" \
    "SELECT count(*)::STRING FROM [SHOW USERS]
     WHERE username IN ('fleet_runtime', 'fleet_writer')
       AND options::STRING = '{NOLOGIN}'" '2'
assert_root_scalar "exact non-admin leaf edge" \
    "SELECT count(*)::STRING FROM [SHOW GRANTS ON ROLE]
     WHERE (role_name IN ('fleet_runtime', 'fleet_writer')
            OR member IN ('fleet_runtime', 'fleet_writer'))
       AND role_name = 'fleet_runtime'
       AND member = 'fleet_writer'
       AND NOT is_admin" '1'
assert_root_scalar "writer direct grants" \
    "SELECT count(*)::STRING FROM [SHOW GRANTS FOR fleet_writer]
     WHERE grantee = 'fleet_writer'" '0'
assert_root_scalar "runtime/writer/PUBLIC system grants" \
    "SELECT count(*)::STRING FROM [SHOW SYSTEM GRANTS]
     WHERE grantee IN ('fleet_runtime', 'fleet_writer', 'public')" '0'
assert_root_scalar "PUBLIC current application grants" \
    "SELECT count(*)::STRING FROM [SHOW GRANTS FOR public]
     WHERE grantee = 'public'
       AND database_name = 'fleet_recall'
       AND (object_type = 'database'
            OR (schema_name = 'public'
                AND object_type IN ('schema', 'table', 'sequence')))" '0'

root_sql 'CREATE DATABASE proof_runtime_other_database' >/dev/null
root_sql 'GRANT fleet_runtime, fleet_writer TO root' >/dev/null
root_sql_in_database proof_runtime_other_database '
ALTER DEFAULT PRIVILEGES FOR ROLE root, admin, fleet_writer
    REVOKE EXECUTE ON ROUTINES FROM public;
ALTER DEFAULT PRIVILEGES FOR ALL ROLES
    REVOKE EXECUTE ON ROUTINES FROM public;
REVOKE CREATE ON SCHEMA public FROM public;
ALTER DEFAULT PRIVILEGES FOR ROLE root REVOKE USAGE ON TYPES FROM public;
CREATE TABLE public.proof_runtime_grant (id INT8 PRIMARY KEY);
CREATE TABLE public.proof_runtime_owned (id INT8 PRIMARY KEY);
CREATE TABLE public.proof_principal_owned (id INT8 PRIMARY KEY);
CREATE SEQUENCE public.proof_runtime_owned_sequence;
CREATE FUNCTION public.proof_writer_owned_function()
RETURNS INT8 LANGUAGE SQL AS '\''SELECT 1'\'';
REVOKE EXECUTE ON FUNCTION public.proof_writer_owned_function() FROM public;
CREATE TYPE public.proof_runtime_owned_type AS ENUM ('\''owned'\'');
ALTER DEFAULT PRIVILEGES FOR ROLE root GRANT USAGE ON TYPES TO public;
CREATE SCHEMA proof_application;
CREATE SCHEMA proof_writer_owned_schema;
ALTER ROLE fleet_runtime WITH CREATEDB;
GRANT CREATE ON DATABASE proof_runtime_other_database
    TO fleet_runtime, fleet_writer;
GRANT CREATE ON SCHEMA public TO fleet_runtime, fleet_writer;
ALTER TABLE public.proof_runtime_owned OWNER TO fleet_runtime;
ALTER TABLE public.proof_principal_owned OWNER TO fleet_writer;
ALTER SEQUENCE public.proof_runtime_owned_sequence OWNER TO fleet_runtime;
ALTER FUNCTION public.proof_writer_owned_function() OWNER TO fleet_writer;
ALTER TYPE public.proof_runtime_owned_type OWNER TO fleet_runtime;
ALTER SCHEMA proof_writer_owned_schema OWNER TO fleet_writer;
ALTER DATABASE proof_runtime_other_database OWNER TO fleet_runtime;
REVOKE CREATE ON SCHEMA public FROM fleet_runtime, fleet_writer;
REVOKE CREATE ON DATABASE proof_runtime_other_database
    FROM fleet_runtime, fleet_writer;
ALTER ROLE fleet_runtime WITH NOCREATEDB;
GRANT SELECT ON TABLE public.proof_runtime_grant
    TO fleet_runtime, fleet_writer, public;
ALTER DEFAULT PRIVILEGES FOR ROLE root
    GRANT INSERT ON TABLES
    TO fleet_runtime, fleet_writer, public;
ALTER DEFAULT PRIVILEGES FOR ROLE root IN SCHEMA proof_application
    GRANT UPDATE ON TABLES
    TO fleet_runtime, fleet_writer, public;
' >/dev/null
root_sql 'REVOKE fleet_runtime, fleet_writer FROM root' >/dev/null
assert_database_scalar proof_runtime_other_database \
    "cross-database owner CREATE cleanup" \
    "SELECT count(*)::STRING
     FROM [SHOW GRANTS ON SCHEMA public]
     WHERE grantee IN ('fleet_runtime', 'fleet_writer')
       AND privilege_type = 'CREATE'" '0'
assert_database_scalar proof_runtime_other_database \
    "cross-database owner effective CREATE cleanup" \
    "SELECT (pg_catalog.has_schema_privilege(
                 'fleet_runtime', 'public', 'CREATE'
             ) OR pg_catalog.has_schema_privilege(
                 'fleet_writer', 'public', 'CREATE'
             ))::STRING" 'false'
assert_database_scalar proof_runtime_other_database \
    "cross-database exact transferred owners" \
    "SELECT count(*)::STRING
     FROM pg_catalog.pg_class AS relation_object
     JOIN pg_catalog.pg_namespace AS schema_object
       ON schema_object.oid = relation_object.relnamespace
     JOIN pg_catalog.pg_roles AS owner_role
       ON owner_role.oid = relation_object.relowner
     WHERE schema_object.nspname = 'public'
       AND ((relation_object.relname = 'proof_runtime_owned'
             AND owner_role.rolname = 'fleet_runtime')
            OR (relation_object.relname = 'proof_principal_owned'
                AND owner_role.rolname = 'fleet_writer'))" '2'
root_sql_in_database proof_runtime_other_database \
    'GRANT CREATE ON SCHEMA public TO public' >/dev/null

outside_runtime_authority=$(audit_other_database_runtime_authority) \
    || fail "cross-database runtime adversary inventory could not execute"
test -n "$outside_runtime_authority" \
    || fail "cross-database runtime adversary inventory was unexpectedly empty"
grep -Fq \
    'proof_runtime_other_database:grant:fleet_runtime:table:public:proof_runtime_grant:SELECT:not_grantable' \
    <<<"$outside_runtime_authority" \
    || fail "external audit missed the cross-database runtime grant"
grep -Fq \
    'proof_runtime_other_database:grant:fleet_writer:table:public:proof_runtime_grant:SELECT:not_grantable' \
    <<<"$outside_runtime_authority" \
    || fail "external audit missed the cross-database principal grant"
grep -Fq \
    'proof_runtime_other_database:relation_owner:fleet_runtime:public:proof_runtime_owned:OWNER:owner' \
    <<<"$outside_runtime_authority" \
    || fail "external audit missed cross-database runtime ownership"
grep -Fq \
    'proof_runtime_other_database:relation_owner:fleet_writer:public:proof_principal_owned:OWNER:owner' \
    <<<"$outside_runtime_authority" \
    || fail "external audit missed cross-database principal ownership"
grep -Fq \
    'proof_runtime_other_database:database_owner:fleet_runtime::proof_runtime_other_database:OWNER:owner' \
    <<<"$outside_runtime_authority" \
    || fail "external audit missed cross-database database ownership"
grep -Fq \
    'proof_runtime_other_database:schema_owner:fleet_writer:proof_writer_owned_schema::OWNER:owner' \
    <<<"$outside_runtime_authority" \
    || fail "external audit missed cross-database schema ownership"
grep -Fq \
    'proof_runtime_other_database:relation_owner:fleet_runtime:public:proof_runtime_owned_sequence:OWNER:owner' \
    <<<"$outside_runtime_authority" \
    || fail "external audit missed cross-database sequence ownership"
grep -Fq \
    'proof_runtime_other_database:function_owner:fleet_writer:public:proof_writer_owned_function:OWNER:owner' \
    <<<"$outside_runtime_authority" \
    || fail "external audit missed cross-database function ownership"
grep -Fq \
    'proof_runtime_other_database:type_owner:fleet_runtime:public:proof_runtime_owned_type:OWNER:owner' \
    <<<"$outside_runtime_authority" \
    || fail "external audit missed cross-database type ownership"
grep -Fq \
    'proof_runtime_other_database:default:database:fleet_runtime:root:false:tables:fleet_runtime:INSERT:not_grantable' \
    <<<"$outside_runtime_authority" \
    || fail "external audit missed the cross-database runtime default"
grep -Fq \
    'proof_runtime_other_database:default:schema:proof_application:fleet_writer:root:false:tables:fleet_writer:UPDATE:not_grantable' \
    <<<"$outside_runtime_authority" \
    || fail "external audit missed the cross-database principal schema default"
outside_public_authority=$(inventory_other_database_public_authority) \
    || fail "cross-database PUBLIC adversary inventory could not execute"
test -n "$outside_public_authority" \
    || fail "cross-database PUBLIC adversary inventory was unexpectedly empty"
grep -Fq \
    'proof_runtime_other_database:table:public:proof_runtime_grant:SELECT:not_grantable' \
    <<<"$outside_public_authority" \
    || fail "external audit missed cross-database PUBLIC data authority"
grep -Fq \
    'proof_runtime_other_database:schema:public::CREATE:not_grantable' \
    <<<"$outside_public_authority" \
    || fail "external audit missed cross-database PUBLIC DDL authority"
grep -Fq \
    'proof_runtime_other_database:default:database:root:false:tables:public:INSERT:not_grantable' \
    <<<"$outside_public_authority" \
    || fail "external audit missed the cross-database PUBLIC default"
grep -Fq \
    'proof_runtime_other_database:default:schema:proof_application:root:false:tables:public:UPDATE:not_grantable' \
    <<<"$outside_public_authority" \
    || fail "external audit missed the cross-database PUBLIC schema default"

assert_root_scalar "cross-database runtime audit is read-only" \
    "SELECT count(*)::STRING
     FROM [SHOW GRANTS ON TABLE proof_runtime_other_database.public.proof_runtime_grant]
     WHERE grantee = 'fleet_runtime'
       AND privilege_type = 'SELECT'" '1'
assert_root_scalar "cross-database PUBLIC DDL audit is read-only" \
    "SELECT count(*)::STRING
     FROM [SHOW GRANTS ON SCHEMA proof_runtime_other_database.public]
     WHERE grantee = 'public'
       AND privilege_type = 'CREATE'
       AND NOT is_grantable" '1'
root_sql_in_database proof_runtime_other_database '
ALTER DATABASE proof_runtime_other_database OWNER TO root;
ALTER SCHEMA proof_writer_owned_schema OWNER TO root;
ALTER TABLE public.proof_runtime_owned OWNER TO root;
ALTER TABLE public.proof_principal_owned OWNER TO root;
ALTER SEQUENCE public.proof_runtime_owned_sequence OWNER TO root;
ALTER FUNCTION public.proof_writer_owned_function() OWNER TO root;
ALTER TYPE public.proof_runtime_owned_type OWNER TO root;
REVOKE SELECT ON TABLE public.proof_runtime_grant
    FROM fleet_runtime, fleet_writer, public;
REVOKE CREATE ON SCHEMA public FROM public;
ALTER DEFAULT PRIVILEGES FOR ROLE root
    REVOKE INSERT ON TABLES
    FROM fleet_runtime, fleet_writer, public;
ALTER DEFAULT PRIVILEGES FOR ROLE root IN SCHEMA proof_application
    REVOKE UPDATE ON TABLES
    FROM fleet_runtime, fleet_writer, public;
DROP SCHEMA proof_writer_owned_schema;
DROP SEQUENCE public.proof_runtime_owned_sequence;
DROP FUNCTION public.proof_writer_owned_function();
DROP TYPE public.proof_runtime_owned_type;
CREATE TABLE public.proof_future_private (id INT8 PRIMARY KEY);
CREATE TABLE proof_application.proof_future_private (id INT8 PRIMARY KEY);
' >/dev/null
assert_root_scalar "cross-database future defaults cleaned" \
    "SELECT count(*)::STRING
     FROM [SHOW GRANTS ON TABLE
           proof_runtime_other_database.public.proof_future_private]
     WHERE grantee IN (
         'fleet_runtime', 'fleet_writer', 'public'
     )" '0'
assert_root_scalar "cross-database schema future defaults cleaned" \
    "SELECT count(*)::STRING
     FROM [SHOW GRANTS ON TABLE
           proof_runtime_other_database.proof_application.proof_future_private]
     WHERE grantee IN (
         'fleet_runtime', 'fleet_writer', 'public'
     )" '0'
assert_empty_audit "clean external runtime authority" \
    audit_other_database_runtime_authority
assert_empty_audit "clean external PUBLIC application authority" \
    inventory_other_database_public_authority

# Current function/type/external grants sit outside the repairable local reset.
# Exercise target and fixed-principal variants independently and preserve
# unrelated CONTROLJOB drift across each failed preflight.
root_sql '
CREATE FUNCTION public.runtime_private_function()
RETURNS INT8 LANGUAGE SQL AS '\''SELECT 1'\'';
REVOKE EXECUTE ON FUNCTION public.runtime_private_function() FROM public;
GRANT EXECUTE ON FUNCTION public.runtime_private_function() TO fleet_runtime;
ALTER ROLE fleet_runtime WITH CONTROLJOB;
' >/dev/null
expect_policy_failure "runtime function grant" \
    'runtime writer policy found a grant outside the repairable fleet_recall.public boundary' \
    '22P02'
assert_root_scalar "function-boundary option preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW USERS] AS target
     CROSS JOIN LATERAL unnest(target.options) AS option_name
     WHERE target.username = 'fleet_runtime'
       AND option_name = 'CONTROLJOB'" '1'
root_sql '
REVOKE EXECUTE ON FUNCTION public.runtime_private_function() FROM fleet_runtime;
GRANT EXECUTE ON FUNCTION public.runtime_private_function() TO fleet_writer;
' >/dev/null
expect_policy_failure "writer function grant" \
    'runtime writer principal must have no direct object grants' '22P02'
root_sql '
REVOKE EXECUTE ON FUNCTION public.runtime_private_function() FROM fleet_writer;
DROP FUNCTION public.runtime_private_function();
' >/dev/null
apply_policy >/dev/null

root_sql '
ALTER DEFAULT PRIVILEGES FOR ROLE root REVOKE USAGE ON TYPES FROM public;
CREATE TYPE public.runtime_private_type AS ENUM ('\''private'\'');
ALTER DEFAULT PRIVILEGES FOR ROLE root GRANT USAGE ON TYPES TO public;
GRANT USAGE ON TYPE public.runtime_private_type TO fleet_runtime;
ALTER ROLE fleet_runtime WITH CONTROLJOB;
' >/dev/null
expect_policy_failure "runtime type grant" \
    'runtime writer policy found a grant outside the repairable fleet_recall.public boundary' \
    '22P02'
assert_root_scalar "type-boundary option preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW USERS] AS target
     CROSS JOIN LATERAL unnest(target.options) AS option_name
     WHERE target.username = 'fleet_runtime'
       AND option_name = 'CONTROLJOB'" '1'
root_sql '
REVOKE USAGE ON TYPE public.runtime_private_type FROM fleet_runtime;
GRANT USAGE ON TYPE public.runtime_private_type TO fleet_writer;
' >/dev/null
expect_policy_failure "writer type grant" \
    'runtime writer principal must have no direct object grants' '22P02'
root_sql '
REVOKE USAGE ON TYPE public.runtime_private_type FROM fleet_writer;
DROP TYPE public.runtime_private_type;
' >/dev/null
apply_policy >/dev/null

root_sql "
CREATE EXTERNAL CONNECTION runtime_private_external
    AS 'nodelocal://1/runtime-private-external';
GRANT USAGE, DROP ON EXTERNAL CONNECTION runtime_private_external
    TO fleet_runtime;
ALTER ROLE fleet_runtime WITH CONTROLJOB;
" >/dev/null
expect_policy_failure "runtime external-connection grant" \
    'runtime writer policy found a grant outside the repairable fleet_recall.public boundary' \
    '22P02'
assert_root_scalar "external-boundary option preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW USERS] AS target
     CROSS JOIN LATERAL unnest(target.options) AS option_name
     WHERE target.username = 'fleet_runtime'
       AND option_name = 'CONTROLJOB'" '1'
root_sql '
REVOKE USAGE, DROP ON EXTERNAL CONNECTION runtime_private_external
    FROM fleet_runtime;
GRANT USAGE, DROP ON EXTERNAL CONNECTION runtime_private_external
    TO fleet_writer;
' >/dev/null
expect_policy_failure "writer external-connection grant" \
    'runtime writer principal must have no direct object grants' '22P02'
root_sql '
REVOKE USAGE, DROP ON EXTERNAL CONNECTION runtime_private_external
    FROM fleet_writer;
DROP EXTERNAL CONNECTION runtime_private_external;
' >/dev/null
apply_policy >/dev/null

# VALID UNTIL has no portable exact reset. The identity gate must preserve
# unrelated drift; cleanup replaces only the logical role, never fleet_writer.
root_sql "
ALTER ROLE fleet_runtime WITH
    CONTROLJOB
    VALID UNTIL '2035-01-01 00:00:00+00:00';
" >/dev/null
expect_policy_failure "runtime VALID UNTIL identity drift" \
    'runtime writer role has a forbidden validity or provisioned-identity option' \
    '22P02'
assert_root_scalar "identity-option preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW USERS] AS target
     CROSS JOIN LATERAL unnest(target.options) AS option_name
     WHERE target.username = 'fleet_runtime'
       AND (option_name = 'CONTROLJOB'
            OR option_name LIKE 'VALID UNTIL=%')" '2'
# temporary-role drop lifecycle: fleet_runtime begin
root_sql 'GRANT fleet_runtime TO root' >/dev/null
for database in fleet_recall defaultdb postgres proof_runtime_other_database; do
    root_sql_in_database "$database" '
ALTER DEFAULT PRIVILEGES FOR ROLE fleet_runtime
    GRANT EXECUTE ON ROUTINES TO public;
' >/dev/null
done
root_sql 'REVOKE fleet_runtime FROM root' >/dev/null
root_sql '
REVOKE fleet_runtime FROM fleet_writer;
REVOKE ALL ON DATABASE fleet_recall FROM fleet_runtime;
REVOKE ALL ON SCHEMA public FROM fleet_runtime;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM fleet_runtime;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM fleet_runtime;
DROP ROLE fleet_runtime;
' >/dev/null
# temporary-role drop lifecycle: fleet_runtime end
apply_policy >/dev/null
root_sql 'GRANT fleet_runtime TO root' >/dev/null
for database in defaultdb postgres proof_runtime_other_database; do
    root_sql_in_database "$database" '
ALTER DEFAULT PRIVILEGES FOR ROLE fleet_runtime
    REVOKE EXECUTE ON ROUTINES FROM public;
' >/dev/null
done
root_sql 'REVOKE fleet_runtime FROM root' >/dev/null
assert_empty_audit "post-identity external runtime authority" \
    audit_other_database_runtime_authority
assert_empty_audit "post-identity external PUBLIC authority" \
    inventory_other_database_public_authority

# Every incident edge except fleet_runtime -> fleet_writer (non-admin) fails
# before unrelated target drift is normalized: outbound, inbound, named-admin,
# mixed-principal, and reverse-principal propagation are distinct vectors.
root_sql '
CREATE ROLE proof_runtime_inbound;
CREATE ROLE proof_runtime_outbound;
ALTER ROLE proof_runtime_inbound WITH NOLOGIN;
ALTER ROLE proof_runtime_outbound WITH NOLOGIN;
GRANT proof_runtime_inbound, proof_runtime_outbound TO root;
' >/dev/null
for database in fleet_recall defaultdb postgres proof_runtime_other_database; do
    root_sql_in_database "$database" '
ALTER DEFAULT PRIVILEGES FOR ROLE proof_runtime_inbound, proof_runtime_outbound
    REVOKE EXECUTE ON ROUTINES FROM public;
' >/dev/null
done
root_sql 'REVOKE proof_runtime_inbound, proof_runtime_outbound FROM root' \
    >/dev/null

root_sql '
ALTER ROLE fleet_runtime WITH CONTROLJOB;
GRANT proof_runtime_outbound TO fleet_runtime;
' >/dev/null
expect_policy_failure "runtime outbound inheritance edge" \
    'runtime writer/principal role graph is not an exact leaf edge' '22P02'
assert_root_scalar "outbound-edge option preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW USERS] AS target
     CROSS JOIN LATERAL unnest(target.options) AS option_name
     WHERE target.username = 'fleet_runtime'
       AND option_name = 'CONTROLJOB'" '1'
root_sql 'REVOKE proof_runtime_outbound FROM fleet_runtime' >/dev/null
apply_policy >/dev/null

root_sql '
ALTER ROLE fleet_runtime WITH CONTROLJOB;
GRANT fleet_runtime TO proof_runtime_inbound;
' >/dev/null
expect_policy_failure "runtime inbound member edge" \
    'runtime writer/principal role graph is not an exact leaf edge' '22P02'
assert_root_scalar "inbound-edge option preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW USERS] AS target
     CROSS JOIN LATERAL unnest(target.options) AS option_name
     WHERE target.username = 'fleet_runtime'
       AND option_name = 'CONTROLJOB'" '1'
root_sql 'REVOKE fleet_runtime FROM proof_runtime_inbound' >/dev/null
apply_policy >/dev/null

root_sql '
ALTER ROLE fleet_runtime WITH CONTROLJOB;
GRANT fleet_runtime TO fleet_writer WITH ADMIN OPTION;
' >/dev/null
expect_policy_failure "fixed runtime edge admin option" \
    'runtime writer/principal role graph is not an exact leaf edge' '22P02'
assert_root_scalar "admin-edge option preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW USERS] AS target
     CROSS JOIN LATERAL unnest(target.options) AS option_name
     WHERE target.username = 'fleet_runtime'
       AND option_name = 'CONTROLJOB'" '1'
root_sql 'REVOKE fleet_runtime FROM fleet_writer' >/dev/null
apply_policy >/dev/null

root_sql '
ALTER ROLE fleet_runtime WITH CONTROLJOB;
GRANT proof_runtime_outbound TO fleet_writer;
' >/dev/null
expect_policy_failure "writer mixed outbound edge" \
    'runtime writer/principal role graph is not an exact leaf edge' '22P02'
assert_root_scalar "mixed-edge option preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW USERS] AS target
     CROSS JOIN LATERAL unnest(target.options) AS option_name
     WHERE target.username = 'fleet_runtime'
       AND option_name = 'CONTROLJOB'" '1'
root_sql 'REVOKE proof_runtime_outbound FROM fleet_writer' >/dev/null
apply_policy >/dev/null

root_sql '
ALTER ROLE fleet_runtime WITH CONTROLJOB;
GRANT fleet_writer TO proof_runtime_inbound;
' >/dev/null
expect_policy_failure "reverse writer propagation edge" \
    'runtime writer/principal role graph is not an exact leaf edge' '22P02'
assert_root_scalar "reverse-edge option preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW USERS] AS target
     CROSS JOIN LATERAL unnest(target.options) AS option_name
     WHERE target.username = 'fleet_runtime'
       AND option_name = 'CONTROLJOB'" '1'
root_sql 'REVOKE fleet_writer FROM proof_runtime_inbound' >/dev/null
apply_policy >/dev/null
assert_empty_audit "post-edge external runtime authority" \
    audit_other_database_runtime_authority
assert_empty_audit "post-edge external PUBLIC authority" \
    inventory_other_database_public_authority

# Enable externally managed authentication only for the representative writer
# window. Every positive dependency and every denied adjacent verb is executed.
root_sql '
INSERT INTO public.memory_chunk_history VALUES (90, 0);
INSERT INTO public.memory_claim_links (id, value) VALUES (700, 0);
INSERT INTO public.memory_claim_link_events VALUES (701, 0);
INSERT INTO public.memory_attention VALUES (702, 0);
INSERT INTO public.memory_control_bootstraps VALUES (800);
INSERT INTO public.memory_control_events VALUES (801);
INSERT INTO public.memory_control_log_epochs VALUES (802);
INSERT INTO public.memory_control_shard_heads VALUES (803);
INSERT INTO public.memory_registry_activations VALUES (900);
INSERT INTO public.memory_registry_current_heads_v2 VALUES (901);
INSERT INTO public.memory_registry_genesis_bridge_consumptions VALUES (902);
INSERT INTO public.memory_registry_heads VALUES (903);
INSERT INTO public.memory_registry_transitions VALUES (904);
' >/dev/null
enable_audited_writer_login

expect_allowed "migration status SELECT" \
    'SELECT count(*) FROM public._sqlx_migrations'
expect_denied "migration ledger INSERT" \
    'INSERT INTO public._sqlx_migrations VALUES (19, true)'
expect_denied "migration ledger UPDATE" \
    'UPDATE public._sqlx_migrations SET success = success WHERE version = 1'
expect_denied "migration ledger DELETE" \
    'DELETE FROM public._sqlx_migrations WHERE version = 18'

expect_allowed "corpus model INSERT" \
    'INSERT INTO public.memory_corpus_models VALUES (1, 0)'
expect_allowed "corpus model SELECT" \
    'SELECT value FROM public.memory_corpus_models WHERE id = 1'
expect_denied "corpus model UPDATE" \
    'UPDATE public.memory_corpus_models SET value = 1 WHERE id = 1'
expect_denied "corpus model DELETE" \
    'DELETE FROM public.memory_corpus_models WHERE id = 1'

expect_allowed "active chunk INSERT" \
    'INSERT INTO public.memory_chunks VALUES (1, 0)'
expect_allowed "active chunk SELECT" \
    'SELECT value FROM public.memory_chunks WHERE id = 1'
expect_allowed "active chunk UPDATE" \
    'UPDATE public.memory_chunks SET value = 1 WHERE id = 1'
expect_denied "active chunk DELETE" \
    'DELETE FROM public.memory_chunks WHERE id = 1'
expect_allowed "chunk history SELECT" \
    'SELECT value FROM public.memory_chunk_history WHERE id = 90'
expect_denied "chunk history INSERT" \
    'INSERT INTO public.memory_chunk_history VALUES (91, 0)'
expect_denied "chunk history UPDATE" \
    'UPDATE public.memory_chunk_history SET value = 1 WHERE id = 90'
expect_allowed "active upsert history DELETE" \
    'DELETE FROM public.memory_chunk_history WHERE id = 90'
assert_root_scalar "history DELETE effect" \
    'SELECT count(*)::STRING FROM public.memory_chunk_history WHERE id = 90' '0'

expect_allowed "claim INSERT with sequence" \
    'INSERT INTO public.memory_claims (value) VALUES (0)'
expect_allowed "claim SELECT" \
    'SELECT value FROM public.memory_claims WHERE id = 1'
expect_allowed "claim UPDATE" \
    'UPDATE public.memory_claims SET value = 1 WHERE id = 1'
expect_denied "claim DELETE" \
    'DELETE FROM public.memory_claims WHERE id = 1'

expect_allowed "support INSERT with sequence" \
    'INSERT INTO public.memory_claim_support (value) VALUES (0)'
expect_allowed "support SELECT" \
    'SELECT value FROM public.memory_claim_support WHERE id = 1'
expect_denied "support UPDATE" \
    'UPDATE public.memory_claim_support SET value = 1 WHERE id = 1'
expect_denied "support DELETE" \
    'DELETE FROM public.memory_claim_support WHERE id = 1'

expect_allowed "claim embedding INSERT" \
    'INSERT INTO public.memory_claim_embeddings VALUES (1, 0)'
expect_allowed "claim embedding SELECT" \
    'SELECT value FROM public.memory_claim_embeddings WHERE id = 1'
expect_denied "claim embedding UPDATE" \
    'UPDATE public.memory_claim_embeddings SET value = 1 WHERE id = 1'
expect_denied "claim embedding DELETE" \
    'DELETE FROM public.memory_claim_embeddings WHERE id = 1'

expect_allowed "claim event INSERT" \
    'INSERT INTO public.memory_claim_events VALUES (1, 0)'
expect_denied "claim event SELECT" \
    'SELECT value FROM public.memory_claim_events WHERE id = 1'
expect_denied "claim event UPDATE" \
    'UPDATE public.memory_claim_events SET value = 1 WHERE id = 1'
expect_denied "claim event DELETE" \
    'DELETE FROM public.memory_claim_events WHERE id = 1'

expect_allowed "conflict INSERT with sequence" \
    'INSERT INTO public.memory_conflicts (value) VALUES (0)'
expect_allowed "conflict SELECT" \
    'SELECT value FROM public.memory_conflicts WHERE id = 1'
expect_allowed "conflict UPDATE" \
    'UPDATE public.memory_conflicts SET value = 1 WHERE id = 1'
expect_denied "conflict DELETE" \
    'DELETE FROM public.memory_conflicts WHERE id = 1'

expect_allowed "conflict member INSERT" \
    'INSERT INTO public.memory_conflict_members VALUES (1, 0)'
expect_allowed "conflict member SELECT" \
    'SELECT value FROM public.memory_conflict_members WHERE id = 1'
expect_denied "conflict member UPDATE" \
    'UPDATE public.memory_conflict_members SET value = 1 WHERE id = 1'
expect_denied "conflict member DELETE" \
    'DELETE FROM public.memory_conflict_members WHERE id = 1'

expect_allowed "claim link indirect-FK SELECT" \
    'SELECT value FROM public.memory_claim_links WHERE id = 700'
expect_denied "claim link INSERT" \
    'INSERT INTO public.memory_claim_links (id, value) VALUES (701, 0)'
expect_denied "claim link UPDATE" \
    'UPDATE public.memory_claim_links SET value = 1 WHERE id = 700'
expect_denied "claim link DELETE" \
    'DELETE FROM public.memory_claim_links WHERE id = 700'

# Exact production reservation shape: all nullable FK keys are omitted. On
# v26.2.3 the INSERT still authorizes SELECT on every referenced parent table.
receipt_reservation_sql="INSERT INTO public.memory_mutation_receipts (
    tenant_id, idempotency_key, project, request, operation
) VALUES (
    '0198a849-f6ae-7d61-9800-000000000001',
    'runtime-reservation', 'runtime-proof', '{}'::JSONB, 'record'
) ON CONFLICT (tenant_id, idempotency_key) DO NOTHING
RETURNING idempotency_key"
expect_allowed "omitted-key receipt reservation" "$receipt_reservation_sql"
root_sql "DELETE FROM public.memory_mutation_receipts
          WHERE tenant_id = '0198a849-f6ae-7d61-9800-000000000001'
            AND idempotency_key = 'runtime-reservation';
          REVOKE SELECT ON TABLE public.memory_claim_links FROM fleet_runtime" \
    >/dev/null
expect_claim_link_parent_denied \
    "omitted-key receipt requires claim-link parent SELECT" \
    "$receipt_reservation_sql"
assert_root_scalar "denied omitted-key reservation residue" \
    "SELECT count(*)::STRING FROM public.memory_mutation_receipts
     WHERE tenant_id = '0198a849-f6ae-7d61-9800-000000000001'
       AND idempotency_key = 'runtime-reservation'" '0'
root_sql 'ALTER USER fleet_writer WITH NOLOGIN' >/dev/null
apply_policy >/dev/null
enable_audited_writer_login
expect_allowed "reapplied omitted-key receipt reservation" \
    "$receipt_reservation_sql"
expect_allowed "receipt SELECT" \
    "SELECT response FROM public.memory_mutation_receipts
     WHERE tenant_id = '0198a849-f6ae-7d61-9800-000000000001'
       AND idempotency_key = 'runtime-reservation'"
expect_allowed "receipt UPDATE" \
    "UPDATE public.memory_mutation_receipts SET response = '{}'::JSONB
     WHERE tenant_id = '0198a849-f6ae-7d61-9800-000000000001'
       AND idempotency_key = 'runtime-reservation'"
expect_denied "receipt DELETE" \
    "DELETE FROM public.memory_mutation_receipts
     WHERE tenant_id = '0198a849-f6ae-7d61-9800-000000000001'
       AND idempotency_key = 'runtime-reservation'"

# ADR 0002 D2/D4 and EVID-01: the writer appends to the general ledger,
# advances only its own heads, and reads registry authority ONLY through the
# migrator-owned view. No UPDATE or DELETE on the accepted envelope.
# The whole append seam, executed against the REAL migration-0018 relations
# and their real foreign keys: bind the epoch, seed the head lazily at offset
# 0 exactly as ADR 0002 D1 prescribes, append one accepted event, then advance
# the head by CAS. Every one of these statements authorizes a foreign-key
# check, and every referenced parent lives in the evidence plane, so the role
# ADR 0002 D2 describes can execute all of them with zero control-plane grants.
evidence_scope_epoch="decode(sha256('runtime-proof-epoch'), 'hex')"
evidence_scope_tenant="'0198a849-f6ae-7d61-9800-000000000001'"
expect_allowed "evidence shard head lazy seed" \
    "INSERT INTO public.memory_evidence_shard_heads (
        tenant_id, project, epoch_id, shard, shard_count,
        last_committed_offset, chain_digest, advanced_at
    ) VALUES (
        $evidence_scope_tenant, 'runtime-proof', $evidence_scope_epoch, 3, 16,
        0, decode(sha256('runtime-proof-genesis'), 'hex'), now()
    ) ON CONFLICT DO NOTHING"
expect_allowed "evidence shard head SELECT" \
    'SELECT last_committed_offset FROM public.memory_evidence_shard_heads'
expect_allowed "evidence event INSERT" \
    "INSERT INTO public.memory_evidence_events (
        tenant_id, project, epoch_id, shard, committed_offset, event_id,
        event_schema_version, event_kind, semantic_object_digest,
        consistency_family, consistency_key_digest, canonical_event,
        previous_chain_digest, chain_digest, accepted_at
    ) VALUES (
        $evidence_scope_tenant, 'runtime-proof', $evidence_scope_epoch, 3, 1,
        decode(sha256('runtime-proof-event'), 'hex'), 1, 'evidence.accepted',
        decode(sha256('runtime-proof-semantic'), 'hex'), 'evidence',
        decode(sha256('runtime-proof-consistency'), 'hex'), b'{}',
        decode(sha256('runtime-proof-genesis'), 'hex'),
        decode(sha256('runtime-proof-chain'), 'hex'), now()
    )"
expect_allowed "evidence event SELECT" \
    'SELECT committed_offset FROM public.memory_evidence_events'
expect_denied "evidence event UPDATE" \
    'UPDATE public.memory_evidence_events SET shard = shard WHERE false'
expect_denied "evidence event DELETE" \
    'DELETE FROM public.memory_evidence_events WHERE false'

# The events -> heads foreign key is the evidence plane's only foreign key and
# it is real: an event under an unseeded head is rejected by the engine, not by
# a stand-in. ADR 0002 D1's amendment forbids any foreign key from this plane to
# a control/registry table precisely because CockroachDB v26.2.3 would then
# require a control-table SELECT grant for the append above.
expect_foreign_key_rejection "event under an unseeded evidence head" \
    "INSERT INTO public.memory_evidence_events (
        tenant_id, project, epoch_id, shard, committed_offset, event_id,
        event_schema_version, event_kind, semantic_object_digest,
        consistency_family, consistency_key_digest, canonical_event,
        previous_chain_digest, chain_digest, accepted_at
    ) VALUES (
        $evidence_scope_tenant, 'runtime-proof', $evidence_scope_epoch, 9, 1,
        decode(sha256('runtime-proof-unseeded'), 'hex'), 1,
        'evidence.accepted', decode(sha256('runtime-proof-semantic'), 'hex'),
        'evidence', decode(sha256('runtime-proof-consistency'), 'hex'), b'{}',
        decode(sha256('runtime-proof-genesis'), 'hex'),
        decode(sha256('runtime-proof-chain'), 'hex'), now()
    )" 'memory_evidence_event_head_fk'

expect_allowed "evidence shard head CAS advance" \
    "UPDATE public.memory_evidence_shard_heads
     SET last_committed_offset = 1,
         chain_digest = decode(sha256('runtime-proof-chain'), 'hex'),
         advanced_at = now()
     WHERE tenant_id = $evidence_scope_tenant
       AND project = 'runtime-proof'
       AND epoch_id = $evidence_scope_epoch
       AND shard = 3
       AND last_committed_offset = 0"
assert_root_scalar "evidence head CAS effect" \
    "SELECT COALESCE(max(last_committed_offset), -1)::STRING
     FROM public.memory_evidence_shard_heads" '1'
expect_denied "evidence shard head DELETE" \
    'DELETE FROM public.memory_evidence_shard_heads WHERE false'

expect_allowed "content object INSERT" \
    'INSERT INTO public.memory_content_objects VALUES (1, 0)'
expect_allowed "content object SELECT" \
    'SELECT value FROM public.memory_content_objects WHERE id = 1'
expect_denied "content object UPDATE" \
    'UPDATE public.memory_content_objects SET value = 1 WHERE id = 1'
expect_denied "content object DELETE" \
    'DELETE FROM public.memory_content_objects WHERE id = 1'

expect_allowed "writer authority view SELECT" \
    'SELECT count(*) FROM public.memory_writer_authority_v1'
assert_root_scalar "writer authority view grant set" \
    "SELECT COALESCE(string_agg(privilege_type, '|' ORDER BY privilege_type), '')
     FROM [SHOW GRANTS ON TABLE public.memory_writer_authority_v1]
     WHERE grantee IN ('fleet_runtime', 'fleet_writer', 'public')" 'SELECT'

# ADR 0002 D2 amendment: the ingress quarantine writer and the relation
# projector run in the same runtime process and the same serializable
# transaction as the append, so they are the same identity. Both projection
# relations are rebuildable from memory_evidence_events (REPLAY-01), so UPDATE
# there advances a disposable projection; nothing here can rewrite an accepted
# envelope, and DELETE stays denied everywhere.
expect_allowed "evidence quarantine INSERT" \
    'INSERT INTO public.memory_evidence_quarantine VALUES (1, 0)'
expect_allowed "evidence quarantine SELECT" \
    'SELECT value FROM public.memory_evidence_quarantine WHERE id = 1'
expect_denied "evidence quarantine UPDATE" \
    'UPDATE public.memory_evidence_quarantine SET value = 1 WHERE id = 1'
expect_denied "evidence quarantine DELETE" \
    'DELETE FROM public.memory_evidence_quarantine WHERE id = 1'

for relation_projection_table in \
    memory_relation_projection_v1 \
    memory_relation_projection_watermarks_v1
do
    expect_allowed "$relation_projection_table INSERT" \
        "INSERT INTO public.$relation_projection_table VALUES (1, 0)"
    expect_allowed "$relation_projection_table SELECT" \
        "SELECT value FROM public.$relation_projection_table WHERE id = 1"
    expect_allowed "$relation_projection_table UPDATE" \
        "UPDATE public.$relation_projection_table SET value = 1 WHERE id = 1"
    expect_denied "$relation_projection_table DELETE" \
        "DELETE FROM public.$relation_projection_table WHERE id = 1"
done

expect_allowed "event INSERT" \
    'INSERT INTO public.memory_events VALUES (1, 0)'
expect_denied "event SELECT" \
    'SELECT value FROM public.memory_events WHERE id = 1'
expect_denied "event UPDATE" \
    'UPDATE public.memory_events SET value = 1 WHERE id = 1'
expect_denied "event DELETE" \
    'DELETE FROM public.memory_events WHERE id = 1'

for allowed_sequence in \
    memory_claim_id_seq \
    memory_claim_support_id_seq \
    memory_conflict_id_seq
do
    expect_allowed "$allowed_sequence nextval USAGE" \
        "SELECT nextval('public.$allowed_sequence')"
    expect_denied "$allowed_sequence relation SELECT" \
        "SELECT last_value FROM public.$allowed_sequence"
    expect_denied "$allowed_sequence setval UPDATE" \
        "SELECT setval('public.$allowed_sequence', 1000)"
done
expect_denied "claim-link sequence USAGE" \
    "SELECT nextval('public.memory_claim_link_id_seq')"

for private_table in memory_claim_link_events memory_attention; do
    expect_denied "$private_table SELECT" \
        "SELECT count(*) FROM public.$private_table"
    expect_denied "$private_table INSERT" \
        "INSERT INTO public.$private_table VALUES (9999, 0)"
    expect_denied "$private_table UPDATE" \
        "UPDATE public.$private_table SET value = value WHERE false"
    expect_denied "$private_table DELETE" \
        "DELETE FROM public.$private_table WHERE false"
done

for authority_table in \
    memory_control_bootstraps \
    memory_control_events \
    memory_control_log_epochs \
    memory_control_shard_heads \
    memory_registry_activations \
    memory_registry_current_heads_v2 \
    memory_registry_genesis_bridge_consumptions \
    memory_registry_heads \
    memory_registry_transitions
do
    expect_denied "$authority_table SELECT" \
        "SELECT count(*) FROM public.$authority_table"
    expect_denied "$authority_table INSERT" \
        "INSERT INTO public.$authority_table VALUES (9999)"
    expect_denied "$authority_table UPDATE" \
        "UPDATE public.$authority_table SET id = id WHERE false"
    expect_denied "$authority_table DELETE" \
        "DELETE FROM public.$authority_table WHERE false"
done

expect_denied "table DDL" \
    'CREATE TABLE public.writer_ddl_probe (id INT8 PRIMARY KEY)'
expect_denied "schema DDL" 'CREATE SCHEMA writer_schema_probe'
expect_denied "database DDL" 'CREATE DATABASE writer_database_probe'
expect_denied "role DDL" 'CREATE ROLE writer_role_probe'
expect_denied "role grant authority" 'GRANT admin TO fleet_writer'
expect_denied "system grant authority" \
    'GRANT SYSTEM VIEWACTIVITY TO fleet_writer'
expect_denied "cluster-setting authority" \
    "SET CLUSTER SETTING sql.defaults.vectorize = 'off'"
expect_denied "table ownership/alter authority" \
    'ALTER TABLE public.memory_chunks ADD COLUMN forbidden INT8'

# Quiesce before every reapply. A failed prefix must preserve all target and
# PUBLIC drift; a restored prefix lets two applications normalize idempotently.
root_sql '
ALTER USER fleet_writer WITH NOLOGIN;
ALTER ROLE fleet_runtime WITH LOGIN CREATEDB CONTROLJOB;
GRANT SYSTEM CONTROLJOB TO fleet_runtime;
GRANT DELETE ON TABLE public.memory_chunks TO fleet_runtime;
GRANT SELECT ON SEQUENCE public.memory_claim_link_id_seq TO fleet_runtime;
GRANT SELECT ON TABLE public.memory_chunks TO public;
UPDATE public._sqlx_migrations SET success = false WHERE version = 18;
' >/dev/null
expect_policy_failure "failed prefix preserves target drift" \
    'runtime writer role requires the complete successful migration prefix through 18' \
    '55000'
# SHOW USERS lists only non-default role options, so LOGIN drift is visible
# only as the absence of NOLOGIN.
assert_root_scalar "failed-prefix target option preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW USERS] AS target
     CROSS JOIN LATERAL unnest(target.options) AS option_name
     WHERE target.username = 'fleet_runtime'
       AND option_name IN ('CREATEDB', 'CONTROLJOB')" '2'
assert_root_scalar "failed-prefix target LOGIN drift preservation" \
    "SELECT count(*)::STRING FROM [SHOW USERS]
     WHERE username = 'fleet_runtime'
       AND options::STRING NOT LIKE '%NOLOGIN%'" '1'
assert_root_scalar "failed-prefix DELETE preservation" \
    "SELECT count(*)::STRING FROM [SHOW GRANTS FOR fleet_runtime]
     WHERE grantee = 'fleet_runtime'
       AND object_name = 'memory_chunks'
       AND privilege_type = 'DELETE'" '1'
root_sql 'UPDATE public._sqlx_migrations SET success = true WHERE version = 18' \
    >/dev/null
apply_policy >/dev/null
apply_policy >/dev/null
assert_root_scalar "normalized exact direct grant count" \
    "SELECT count(*)::STRING FROM [SHOW GRANTS FOR fleet_runtime]
     WHERE grantee = 'fleet_runtime'" '47'
assert_root_scalar "normalized forbidden adjacent grants" \
    "SELECT count(*)::STRING FROM [SHOW GRANTS FOR fleet_runtime]
     WHERE grantee = 'fleet_runtime'
       AND ((object_name = 'memory_chunks' AND privilege_type = 'DELETE')
            OR object_name = 'memory_claim_link_id_seq')" '0'
assert_root_scalar "normalized exact target options" \
    "SELECT count(*)::STRING FROM [SHOW USERS]
     WHERE username = 'fleet_runtime'
       AND options::STRING = '{NOLOGIN}'" '1'

# Target future authority and ownership cannot be repaired by a current-object
# reset, so each blocks before unrelated CONTROLJOB drift is normalized.
root_sql '
ALTER ROLE fleet_runtime WITH CONTROLJOB;
ALTER DEFAULT PRIVILEGES FOR ROLE root IN SCHEMA public
    GRANT INSERT ON TABLES TO fleet_runtime;
' >/dev/null
expect_policy_failure "runtime role future default" \
    'runtime role has non-intrinsic future-default authority' '22P02'
assert_root_scalar "target-default drift preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW USERS] AS target
     CROSS JOIN LATERAL unnest(target.options) AS option_name
     WHERE target.username = 'fleet_runtime'
       AND option_name = 'CONTROLJOB'" '1'
root_sql '
ALTER DEFAULT PRIVILEGES FOR ROLE root IN SCHEMA public
    REVOKE INSERT ON TABLES FROM fleet_runtime;
' >/dev/null
apply_policy >/dev/null

root_sql '
ALTER DEFAULT PRIVILEGES FOR ROLE root REVOKE USAGE ON TYPES FROM public;
CREATE TABLE public.runtime_owned_probe (id INT8 PRIMARY KEY);
CREATE SEQUENCE public.runtime_owned_sequence;
CREATE FUNCTION public.runtime_owned_function()
RETURNS INT8 LANGUAGE SQL AS '\''SELECT 1'\'';
REVOKE EXECUTE ON FUNCTION public.runtime_owned_function() FROM public;
CREATE TYPE public.runtime_owned_type AS ENUM ('\''owned'\'');
ALTER DEFAULT PRIVILEGES FOR ROLE root GRANT USAGE ON TYPES TO public;
GRANT fleet_runtime TO root;
ALTER ROLE fleet_runtime WITH CREATEDB;
GRANT CREATE ON DATABASE fleet_recall TO fleet_runtime;
GRANT CREATE ON SCHEMA public TO fleet_runtime;
ALTER TABLE public.runtime_owned_probe OWNER TO fleet_runtime;
ALTER SEQUENCE public.runtime_owned_sequence OWNER TO fleet_runtime;
ALTER FUNCTION public.runtime_owned_function() OWNER TO fleet_runtime;
ALTER TYPE public.runtime_owned_type OWNER TO fleet_runtime;
ALTER SCHEMA public OWNER TO fleet_runtime;
ALTER DATABASE fleet_recall OWNER TO fleet_runtime;
REVOKE CREATE ON SCHEMA public FROM fleet_runtime;
REVOKE CREATE ON DATABASE fleet_recall FROM fleet_runtime;
REVOKE fleet_runtime FROM root;
ALTER ROLE fleet_runtime WITH CONTROLJOB;
' >/dev/null
assert_root_scalar "runtime database ownership fixture" \
    "SELECT count(*)::STRING
     FROM pg_catalog.pg_database AS database_object
     JOIN pg_catalog.pg_roles AS owner_role
       ON owner_role.oid = database_object.datdba
     WHERE database_object.datname = 'fleet_recall'
       AND owner_role.rolname = 'fleet_runtime'" '1'
assert_root_scalar "runtime schema ownership fixture" \
    "SELECT count(*)::STRING
     FROM pg_catalog.pg_namespace AS schema_object
     JOIN pg_catalog.pg_roles AS owner_role
       ON owner_role.oid = schema_object.nspowner
     WHERE schema_object.nspname = 'public'
       AND owner_role.rolname = 'fleet_runtime'" '1'
assert_root_scalar "runtime table/sequence ownership fixture" \
    "SELECT count(*)::STRING
     FROM pg_catalog.pg_class AS relation_object
     JOIN pg_catalog.pg_roles AS owner_role
       ON owner_role.oid = relation_object.relowner
     WHERE relation_object.relname IN (
         'runtime_owned_probe', 'runtime_owned_sequence'
     )
       AND owner_role.rolname = 'fleet_runtime'" '2'
assert_root_scalar "runtime function ownership fixture" \
    "SELECT count(*)::STRING
     FROM pg_catalog.pg_proc AS function_object
     JOIN pg_catalog.pg_roles AS owner_role
       ON owner_role.oid = function_object.proowner
     WHERE function_object.proname = 'runtime_owned_function'
       AND owner_role.rolname = 'fleet_runtime'" '1'
assert_root_scalar "runtime type ownership fixture" \
    "SELECT count(*)::STRING
     FROM pg_catalog.pg_type AS type_object
     JOIN pg_catalog.pg_roles AS owner_role
       ON owner_role.oid = type_object.typowner
     WHERE type_object.typname = 'runtime_owned_type'
       AND owner_role.rolname = 'fleet_runtime'" '1'
expect_policy_failure "runtime role multi-class ownership" \
    'runtime writer role must not own database, schema, relation, function, or type objects' \
    '55000'
assert_root_scalar "target-ownership drift preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW USERS] AS target
     CROSS JOIN LATERAL unnest(target.options) AS option_name
     WHERE target.username = 'fleet_runtime'
       AND option_name = 'CONTROLJOB'" '1'
root_sql '
GRANT fleet_runtime TO root;
ALTER DATABASE fleet_recall OWNER TO root;
ALTER SCHEMA public OWNER TO root;
ALTER TABLE public.runtime_owned_probe OWNER TO root;
ALTER SEQUENCE public.runtime_owned_sequence OWNER TO root;
ALTER FUNCTION public.runtime_owned_function() OWNER TO root;
ALTER TYPE public.runtime_owned_type OWNER TO root;
DROP TABLE public.runtime_owned_probe;
DROP SEQUENCE public.runtime_owned_sequence;
DROP FUNCTION public.runtime_owned_function();
DROP TYPE public.runtime_owned_type;
REVOKE fleet_runtime FROM root;
' >/dev/null
apply_policy >/dev/null

# No future-object privilege is installed. Both the logical role and PUBLIC
# remain absent from a table created after the final clean policy application.
root_sql 'CREATE TABLE public.future_runtime_probe (id INT8 PRIMARY KEY)' \
    >/dev/null
assert_root_scalar "future runtime/PUBLIC table grants" \
    "SELECT count(*)::STRING FROM [SHOW GRANTS ON TABLE public.future_runtime_probe]
     WHERE grantee IN ('fleet_runtime', 'fleet_writer', 'public')" '0'
enable_audited_writer_login
expect_denied "future table SELECT" \
    'SELECT count(*) FROM public.future_runtime_probe'
root_sql 'ALTER USER fleet_writer WITH NOLOGIN' >/dev/null

# The sole terminal boundary begins only after two clean idempotent reapplies.
apply_policy >/dev/null
apply_policy >/dev/null
terminal_runtime_grants=$(root_sql "
    SELECT object_type || ':' || COALESCE(database_name, '') || ':' ||
           COALESCE(schema_name, '') || ':' || COALESCE(object_name, '') || ':' ||
           privilege_type || ':' ||
           CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END
    FROM [SHOW GRANTS FOR fleet_runtime]
    WHERE grantee = 'fleet_runtime'
    ORDER BY object_type, database_name, schema_name, object_name, privilege_type
" | tail -n +2) || fail "terminal sorted runtime matrix could not execute"
assert_exact "terminal exact sorted runtime matrix" \
    "$terminal_runtime_grants" "$expected_runtime_grants"

# Terminal residue: the only incident edge is runtime -> fixed writer, both
# subjects are NOLOGIN, the writer is direct-authority-free, and the runtime
# surface is still exactly forty-seven rows after every adversary and reapply.
assert_root_scalar "terminal direct grant count" \
    "SELECT count(*)::STRING FROM [SHOW GRANTS FOR fleet_runtime]
     WHERE grantee = 'fleet_runtime'" '47'
assert_root_scalar "terminal direct writer grants" \
    "SELECT count(*)::STRING FROM [SHOW GRANTS FOR fleet_writer]
     WHERE grantee = 'fleet_writer'" '0'
assert_root_scalar "terminal subject options" \
    "SELECT count(*)::STRING FROM [SHOW USERS]
     WHERE username IN ('fleet_runtime', 'fleet_writer')
       AND options::STRING = '{NOLOGIN}'" '2'
assert_root_scalar "terminal incident role edges" \
    "SELECT count(*)::STRING FROM [SHOW GRANTS ON ROLE]
     WHERE role_name IN ('fleet_runtime', 'fleet_writer')
        OR member IN ('fleet_runtime', 'fleet_writer')" '1'
assert_root_scalar "terminal system authority" \
    "SELECT count(*)::STRING FROM [SHOW SYSTEM GRANTS]
     WHERE grantee IN ('fleet_runtime', 'fleet_writer', 'public')" '0'

assert_root_scalar "terminal principal direct grants" \
    "SELECT count(*)::STRING
     FROM [SHOW GRANTS FOR fleet_writer]
     WHERE grantee = 'fleet_writer'" '0'
assert_root_scalar "terminal PUBLIC application/external grants" \
    "SELECT count(*)::STRING
     FROM [SHOW GRANTS FOR public]
     WHERE grantee = 'public'
       AND (
           object_type = 'external_connection'
           OR (
               database_name = 'fleet_recall'
               AND NOT (
                   (object_type = 'schema'
                       AND schema_name LIKE 'pg_temp_%'
                       AND object_name IS NULL
                       AND privilege_type IN ('CREATE', 'USAGE')
                       AND NOT is_grantable)
                   OR (schema_name IN (
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
                       ))
               )
           )
       )" '0'
assert_root_scalar "terminal system grants" \
    "SELECT count(*)::STRING FROM [SHOW SYSTEM GRANTS]
     WHERE grantee IN (
         'fleet_runtime', 'fleet_writer', 'public'
     )" '0'
assert_root_scalar "terminal exact NOLOGIN subjects" \
    "SELECT count(*)::STRING FROM [SHOW USERS]
     WHERE username IN ('fleet_runtime', 'fleet_writer')
       AND options::STRING = '{NOLOGIN}'" '2'
assert_root_scalar "terminal exact leaf role graph" \
    "SELECT count(*)::STRING FROM [SHOW GRANTS ON ROLE]
     WHERE (
         role_name IN ('fleet_runtime', 'fleet_writer')
         OR member IN ('fleet_runtime', 'fleet_writer')
     )
       AND role_name = 'fleet_runtime'
       AND member = 'fleet_writer'
       AND NOT is_admin" '1'
assert_root_scalar "terminal incident role-edge count" \
    "SELECT count(*)::STRING FROM [SHOW GRANTS ON ROLE]
     WHERE role_name IN ('fleet_runtime', 'fleet_writer')
        OR member IN ('fleet_runtime', 'fleet_writer')" '1'
assert_root_scalar "terminal current-database ownership" \
    "SELECT count(*)::STRING
     FROM (
         SELECT 1
         FROM pg_catalog.pg_database AS database_object
         JOIN pg_catalog.pg_roles AS owner_role
           ON owner_role.oid = database_object.datdba
         WHERE database_object.datname = 'fleet_recall'
           AND owner_role.rolname IN (
               'fleet_runtime', 'fleet_writer'
           )
         UNION ALL
         SELECT 1
         FROM pg_catalog.pg_namespace AS schema_object
         JOIN pg_catalog.pg_roles AS owner_role
           ON owner_role.oid = schema_object.nspowner
         WHERE owner_role.rolname IN (
             'fleet_runtime', 'fleet_writer'
         )
         UNION ALL
         SELECT 1
         FROM pg_catalog.pg_class AS relation_object
         JOIN pg_catalog.pg_roles AS owner_role
           ON owner_role.oid = relation_object.relowner
         WHERE relation_object.relkind IN ('r', 'S', 'v', 'm', 'p')
           AND owner_role.rolname IN (
               'fleet_runtime', 'fleet_writer'
           )
         UNION ALL
         SELECT 1
         FROM pg_catalog.pg_proc AS function_object
         JOIN pg_catalog.pg_roles AS owner_role
           ON owner_role.oid = function_object.proowner
         WHERE owner_role.rolname IN (
             'fleet_runtime', 'fleet_writer'
         )
         UNION ALL
         SELECT 1
         FROM pg_catalog.pg_type AS type_object
         JOIN pg_catalog.pg_roles AS owner_role
           ON owner_role.oid = type_object.typowner
         WHERE owner_role.rolname IN (
             'fleet_runtime', 'fleet_writer'
         )
     ) AS owned" '0'
assert_root_scalar "terminal subject future defaults" \
    "SELECT count(*)::STRING
     FROM (
         SELECT 'fleet_runtime' AS subject,
                role, for_all_roles, object_type, grantee,
                privilege_type, is_grantable
         FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE
               fleet_runtime]
         UNION ALL
         SELECT 'fleet_runtime' AS subject,
                role, for_all_roles, object_type, grantee,
                privilege_type, is_grantable
         FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE
               fleet_runtime IN SCHEMA public]
         UNION ALL
         SELECT 'fleet_writer' AS subject,
                role, for_all_roles, object_type, grantee,
                privilege_type, is_grantable
         FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE fleet_writer]
         UNION ALL
         SELECT 'fleet_writer' AS subject,
                role, for_all_roles, object_type, grantee,
                privilege_type, is_grantable
         FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE
               fleet_writer IN SCHEMA public]
     ) AS subject_default
     WHERE object_type IN (
         'schemas', 'routines', 'tables', 'sequences', 'types'
     )
       AND (
           role = subject
           AND NOT for_all_roles
           AND grantee = subject
           AND privilege_type = 'ALL'
           AND is_grantable
       ) IS NOT TRUE" '0'
assert_root_scalar "terminal PUBLIC future defaults" \
    "SELECT count(*)::STRING
     FROM (
         SELECT role, for_all_roles, object_type, grantee,
                privilege_type, is_grantable
         FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE public]
         UNION
         SELECT role, for_all_roles, object_type, grantee,
                privilege_type, is_grantable
         FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE public IN SCHEMA public]
     ) AS public_default
     WHERE object_type IN (
         'schemas', 'routines', 'tables', 'sequences', 'types'
     )
       AND (
           grantee = 'public'
           AND NOT is_grantable
           AND object_type = 'types'
           AND privilege_type = 'USAGE'
       ) IS NOT TRUE
       AND (
           role IS NULL
           AND for_all_roles
           AND grantee = 'public'
           AND object_type = 'routines'
           AND privilege_type = 'EXECUTE'
           AND NOT is_grantable
       ) IS NOT TRUE
       AND (
           role = 'fleet_runtime'
           AND NOT for_all_roles
           AND grantee = 'public'
           AND object_type = 'routines'
           AND privilege_type = 'EXECUTE'
           AND NOT is_grantable
       ) IS NOT TRUE" '0'
assert_root_scalar "terminal dedicated schema boundary" \
    "SELECT count(*)::STRING
     FROM pg_catalog.pg_namespace
     WHERE nspname NOT IN (
         'public', 'pg_catalog', 'information_schema',
         'crdb_internal', 'pg_extension'
     )
       AND nspname NOT LIKE 'pg_temp_%'" '0'
assert_root_scalar "terminal future table authority" \
    "SELECT count(*)::STRING
     FROM [SHOW GRANTS ON TABLE public.future_runtime_probe]
     WHERE grantee IN (
         'fleet_runtime', 'fleet_writer', 'public'
     )" '0'
assert_empty_audit "terminal external runtime/principal authority" \
    audit_other_database_runtime_authority
assert_empty_audit "terminal external PUBLIC authority" \
    inventory_other_database_public_authority
assert_external_topology
echo "runtime-role grant proof passed on $server_build_tag"
