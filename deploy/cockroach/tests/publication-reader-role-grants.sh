#!/usr/bin/env bash
set -euo pipefail

# Secondary Docker parity only. Static policy-shape assertions run before any
# Docker command. The caller must separately authorize the connected portion
# after reviewing frozen file hashes. Policy applications run as root, matching
# the cluster-admin-only operator contract.
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$script_dir/../../.." && pwd)
policy="$repo_root/deploy/cockroach/publication-reader-role-grants.sql"
image=${FLEET_RECALL_CRDB_IMAGE:-cockroachdb/cockroach:v26.2.3}
expected_crdb_build_tag=v26.2.3
container="ostk-publication-reader-grants-$$"

cleanup() {
    docker rm --force "$container" >/dev/null 2>&1 || true
}

fail() {
    echo "publication-reader grant proof failed: $*" >&2
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

apply_reader_policy() {
    docker exec -i "$container" cockroach sql \
        --insecure --database fleet_recall < "$policy"
}

apply_reader_policy_in_database() {
    local database=$1
    docker exec -i "$container" cockroach sql \
        --insecure --database "$database" < "$policy"
}

apply_reader_policy_with_valid_temp_prefix() {
    {
        printf '%s\n' '
SET experimental_enable_temp_tables = on;
CREATE TEMP TABLE _sqlx_migrations (
    version INT8 PRIMARY KEY,
    success BOOL NOT NULL
);
INSERT INTO _sqlx_migrations
SELECT version, true FROM generate_series(1, 17) AS version;
'
        sed -n '1,$p' "$policy"
    } | docker exec -i "$container" cockroach sql \
        --insecure --database fleet_recall
}

apply_reader_policy_with_temp_shadows() {
    {
        printf '%s\n' '
SET experimental_enable_temp_tables = on;
CREATE TEMP TABLE _sqlx_migrations (id INT8 PRIMARY KEY);
CREATE TEMP TABLE memory_corpus_models (id INT8 PRIMARY KEY);
CREATE TEMP TABLE memory_chunks (id INT8 PRIMARY KEY);
CREATE TEMP TABLE memory_claim_embeddings (id INT8 PRIMARY KEY);
CREATE TEMP TABLE memory_claim_support (id INT8 PRIMARY KEY);
CREATE TEMP TABLE memory_claims (id INT8 PRIMARY KEY);
CREATE TEMP TABLE memory_conflict_members (id INT8 PRIMARY KEY);
CREATE TEMP TABLE memory_conflicts (id INT8 PRIMARY KEY);
'
        sed -n '1,$p' "$policy"
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
        '\''temporary PUBLIC schema baseline differs: observed='\'',
        count(*)::STRING
    ) AS INT8)
) AS publication_reader_temp_public_baseline_postcondition
FROM [SHOW GRANTS FOR public]
WHERE grantee = '\''public'\''
  AND schema_name LIKE '\''pg_temp_%'\'';

SELECT IF(
    count(*) = 0,
    1:::INT8,
    CAST(concat(
        '\''temporary reader shadow received grants: observed='\'',
        count(*)::STRING
    ) AS INT8)
) AS publication_reader_temp_shadow_postcondition
FROM [SHOW GRANTS FOR fleet_publication_reader]
WHERE grantee = '\''fleet_publication_reader'\''
  AND schema_name LIKE '\''pg_temp_%'\'';
'
    } | docker exec -i "$container" cockroach sql \
        --insecure --database fleet_recall
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
        'privilege|permission|not have.*grant|must have.*(CREATEROLE|admin option)|must be owner' \
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
    if output=$(apply_reader_policy 2>&1); then
        fail "$label unexpectedly admitted the publication reader policy"
    fi
    if ! grep -Fq \
        'publication reader role requires the complete successful migration prefix through 17' \
        <<<"$output"; then
        echo "$output" >&2
        fail "$label did not retain the exact prefix-17 failure"
    fi
    if ! grep -Fq 'SQLSTATE: 55000' <<<"$output"; then
        echo "$output" >&2
        fail "$label did not retain the prefix-gate SQLSTATE"
    fi
}

expect_policy_prefix_failure_with_temp() {
    local label=$1
    local output
    if output=$(apply_reader_policy_with_valid_temp_prefix 2>&1); then
        fail "$label unexpectedly admitted a valid temporary migration prefix"
    fi
    if ! grep -Fq \
        'publication reader role requires the complete successful migration prefix through 17' \
        <<<"$output"; then
        echo "$output" >&2
        fail "$label did not retain the exact public prefix-17 failure"
    fi
    if ! grep -Fq 'SQLSTATE: 55000' <<<"$output"; then
        echo "$output" >&2
        fail "$label did not retain the public prefix-gate SQLSTATE"
    fi
}

expect_policy_database_failure() {
    local label=$1
    local output
    if output=$(apply_reader_policy_in_database defaultdb 2>&1); then
        fail "$label unexpectedly admitted the policy in the wrong database"
    fi
    if ! grep -Fq 'publication reader policy must run in fleet_recall' \
        <<<"$output"; then
        echo "$output" >&2
        fail "$label did not fail on the current-database preflight"
    fi
    if ! grep -Fq 'SQLSTATE: 55000' <<<"$output"; then
        echo "$output" >&2
        fail "$label did not retain the database-preflight SQLSTATE"
    fi
}

expect_policy_principal_failure() {
    local label=$1
    local output
    if output=$(apply_reader_policy 2>&1); then
        fail "$label unexpectedly admitted the publication principal"
    fi
    if ! grep -Fq \
        'publication reader policy requires exact quiesced principal fleet_publication with options {NOLOGIN}' \
        <<<"$output"; then
        echo "$output" >&2
        fail "$label did not fail on the fixed-principal preflight"
    fi
    assert_show_gate_sqlstate "$label" "$output"
}

expect_policy_default_failure() {
    local label=$1
    local output
    if output=$(apply_reader_policy 2>&1); then
        fail "$label unexpectedly admitted future-object privilege drift"
    fi
    if ! grep -Fq \
        'publication reader policy permits only intrinsic PUBLIC type USAGE/all-roles routine EXECUTE, target PUBLIC routine EXECUTE, and target self-owner ALL future defaults' \
        <<<"$output"; then
        echo "$output" >&2
        fail "$label did not fail on the default-privilege preflight"
    fi
    assert_show_gate_sqlstate "$label" "$output"
}

expect_policy_principal_default_failure() {
    local label=$1
    local output
    if output=$(apply_reader_policy 2>&1); then
        fail "$label unexpectedly admitted principal future authority"
    fi
    if ! grep -Fq \
        'publication principal has non-intrinsic future-default authority' \
        <<<"$output"; then
        echo "$output" >&2
        fail "$label did not fail on the principal default preflight"
    fi
    assert_show_gate_sqlstate "$label" "$output"
}

expect_policy_public_system_failure() {
    local label=$1
    local output
    if output=$(apply_reader_policy 2>&1); then
        fail "$label unexpectedly admitted a PUBLIC system privilege"
    fi
    if ! grep -Fq \
        'publication reader policy requires PUBLIC to have no system privileges' \
        <<<"$output"; then
        echo "$output" >&2
        fail "$label did not fail on the PUBLIC system-grant preflight"
    fi
    assert_show_gate_sqlstate "$label" "$output"
}

expect_policy_principal_system_failure() {
    local label=$1
    local output
    if output=$(apply_reader_policy 2>&1); then
        fail "$label unexpectedly admitted a principal system privilege"
    fi
    if ! grep -Fq \
        'publication principal must have no system privileges' \
        <<<"$output"; then
        echo "$output" >&2
        fail "$label did not fail on the principal system-grant preflight"
    fi
    assert_show_gate_sqlstate "$label" "$output"
}

expect_policy_schema_failure() {
    local label=$1
    local output
    if output=$(apply_reader_policy 2>&1); then
        fail "$label unexpectedly admitted an additional application schema"
    fi
    if ! grep -Fq \
        'publication reader policy requires public to be the only application schema' \
        <<<"$output"; then
        echo "$output" >&2
        fail "$label did not fail on the application-schema preflight"
    fi
}

expect_policy_grant_boundary_failure() {
    local label=$1
    local output
    if output=$(apply_reader_policy 2>&1); then
        fail "$label unexpectedly admitted out-of-boundary object authority"
    fi
    if ! grep -Fq \
        'publication reader policy found a grant outside the repairable fleet_recall.public boundary' \
        <<<"$output"; then
        echo "$output" >&2
        fail "$label did not fail on the object-grant boundary preflight"
    fi
    assert_show_gate_sqlstate "$label" "$output"
}

expect_policy_public_grant_failure() {
    local label=$1
    local output
    if output=$(apply_reader_policy 2>&1); then
        fail "$label unexpectedly admitted unsafe PUBLIC authority"
    fi
    if ! grep -Fq \
        'publication reader policy found an unsafe PUBLIC grant before target creation' \
        <<<"$output"; then
        echo "$output" >&2
        fail "$label did not fail on the pre-create PUBLIC grant boundary"
    fi
    assert_show_gate_sqlstate "$label" "$output"
}

expect_policy_principal_grant_failure() {
    local label=$1
    local output
    if output=$(apply_reader_policy 2>&1); then
        fail "$label unexpectedly admitted direct principal authority"
    fi
    if ! grep -Fq \
        'publication principal must have no direct object grants' \
        <<<"$output"; then
        echo "$output" >&2
        fail "$label did not fail on the principal direct-grant preflight"
    fi
    assert_show_gate_sqlstate "$label" "$output"
}

expect_policy_role_edge_failure() {
    local label=$1
    local output
    if output=$(apply_reader_policy 2>&1); then
        fail "$label unexpectedly admitted an unsafe role edge"
    fi
    if ! grep -Fq \
        'publication reader/principal role graph is not an exact leaf edge' \
        <<<"$output"; then
        echo "$output" >&2
        fail "$label did not fail on the role-edge preflight"
    fi
    assert_show_gate_sqlstate "$label" "$output"
}

expect_policy_identity_failure() {
    local label=$1
    local output
    if output=$(apply_reader_policy 2>&1); then
        fail "$label unexpectedly admitted target identity-option drift"
    fi
    if ! grep -Fq \
        'publication reader role has a forbidden validity or provisioned-identity option' \
        <<<"$output"; then
        echo "$output" >&2
        fail "$label did not fail on the target identity-option preflight"
    fi
    assert_show_gate_sqlstate "$label" "$output"
}

expect_policy_ownership_failure() {
    local label=$1
    local output
    if output=$(apply_reader_policy 2>&1); then
        fail "$label unexpectedly admitted reader ownership"
    fi
    if ! grep -Fq \
        'publication reader role must not own database, schema, relation, function, or type objects' \
        <<<"$output"; then
        echo "$output" >&2
        fail "$label did not fail on the ownership preflight"
    fi
}

expect_policy_principal_ownership_failure() {
    local label=$1
    local output
    if output=$(apply_reader_policy 2>&1); then
        fail "$label unexpectedly admitted principal ownership"
    fi
    if ! grep -Fq \
        'publication principal must not own database, schema, relation, function, or type objects' \
        <<<"$output"; then
        echo "$output" >&2
        fail "$label did not fail on the principal ownership preflight"
    fi
}

# The SQL policy is database-local. This read-only deployment preflight
# enumerates every other database and application schema for direct grants,
# ownership, and non-intrinsic future defaults held by either fixed subject.
audit_other_database_reader_authority() {
    local databases
    local database
    local schemas
    local schema_name
    local schema_identifier
    local rows
    local row
    rows=$(root_sql "
        WITH subject_grant AS (
            SELECT * FROM [SHOW GRANTS FOR fleet_publication_reader]
            UNION ALL
            SELECT * FROM [SHOW GRANTS FOR fleet_publication]
        )
        SELECT 'cluster_grant:' || grantee || ':' || object_type || ':' ||
               COALESCE(object_name, '') || ':' || privilege_type || ':' ||
               CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END
        FROM subject_grant
        WHERE grantee IN ('fleet_publication_reader', 'fleet_publication')
          AND database_name IS NULL
        ORDER BY 1
    " | tail -n +2) \
        || fail "external reader audit could not inspect cluster-global grants"
    while IFS= read -r row; do
        test -n "$row" || continue
        printf '%s\n' "$row"
    done <<<"$rows"
    databases=$(root_sql \
        'SELECT database_name FROM [SHOW DATABASES] ORDER BY database_name' \
        | tail -n +2) || fail "external reader audit could not enumerate databases"
    while IFS= read -r database; do
        test -n "$database" || continue
        test "$database" != 'fleet_recall' || continue
        rows=$(root_sql_in_database "$database" "
            WITH subject_grant AS (
                SELECT * FROM [SHOW GRANTS FOR fleet_publication_reader]
                UNION ALL
                SELECT * FROM [SHOW GRANTS FOR fleet_publication]
            )
            SELECT 'grant:' || grantee || ':' || object_type || ':' ||
                   COALESCE(schema_name, '') || ':' ||
                   COALESCE(object_name, '') || ':' || privilege_type || ':' ||
                   CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END
            FROM subject_grant
            WHERE grantee IN ('fleet_publication_reader', 'fleet_publication')
              AND database_name = pg_catalog.current_database()
            UNION ALL
            SELECT 'database_owner:' || owner_role.rolname || '::' ||
                   database_object.datname || ':OWNER:owner'
            FROM pg_catalog.pg_database AS database_object
            JOIN pg_catalog.pg_roles AS owner_role
              ON owner_role.oid = database_object.datdba
            WHERE database_object.datname = pg_catalog.current_database()
              AND owner_role.rolname IN (
                  'fleet_publication_reader', 'fleet_publication'
              )
            UNION ALL
            SELECT 'schema_owner:' || owner_role.rolname || ':' ||
                   schema_object.nspname || '::OWNER:owner'
            FROM pg_catalog.pg_namespace AS schema_object
            JOIN pg_catalog.pg_roles AS owner_role
              ON owner_role.oid = schema_object.nspowner
            WHERE owner_role.rolname IN (
                'fleet_publication_reader', 'fleet_publication'
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
                  'fleet_publication_reader', 'fleet_publication'
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
                'fleet_publication_reader', 'fleet_publication'
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
                'fleet_publication_reader', 'fleet_publication'
            )
            ORDER BY 1
        " | tail -n +2) \
            || fail "external reader audit could not inspect $database"
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
                SELECT 'fleet_publication_reader' AS subject,
                       role, for_all_roles, object_type, grantee,
                       privilege_type, is_grantable
                FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE
                      fleet_publication_reader]
                UNION ALL
                SELECT 'fleet_publication' AS subject,
                       role, for_all_roles, object_type, grantee,
                       privilege_type, is_grantable
                FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE fleet_publication]
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
            || fail "external reader audit could not inspect database defaults in $database"
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
            || fail "external reader audit could not enumerate schemas in $database"
        while IFS=$'\t' read -r schema_name schema_identifier; do
            test -n "$schema_name" || continue
            test -n "$schema_identifier" \
                || fail "external reader audit found an unquotable schema in $database"
            rows=$(root_sql_in_database "$database" "
                WITH subject_default AS (
                    SELECT 'fleet_publication_reader' AS subject,
                           role, for_all_roles, object_type, grantee,
                           privilege_type, is_grantable
                    FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE
                          fleet_publication_reader IN SCHEMA $schema_identifier]
                    UNION ALL
                    SELECT 'fleet_publication' AS subject,
                           role, for_all_roles, object_type, grantee,
                           privilege_type, is_grantable
                    FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE
                          fleet_publication IN SCHEMA $schema_identifier]
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
                || fail "external reader audit could not inspect $database.$schema_name defaults"
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
        FROM [SHOW GRANTS FOR fleet_publication]
        WHERE grantee = 'fleet_publication'
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
            FROM [SHOW GRANTS FOR fleet_publication]
            WHERE grantee = 'fleet_publication'
              AND database_name = pg_catalog.current_database()
            UNION ALL
            SELECT 'database_owner::' || database_object.datname || ':OWNER:owner'
            FROM pg_catalog.pg_database AS database_object
            JOIN pg_catalog.pg_roles AS owner_role
              ON owner_role.oid = database_object.datdba
            WHERE database_object.datname = pg_catalog.current_database()
              AND owner_role.rolname = 'fleet_publication'
            UNION ALL
            SELECT 'schema_owner:' || schema_object.nspname || '::OWNER:owner'
            FROM pg_catalog.pg_namespace AS schema_object
            JOIN pg_catalog.pg_roles AS owner_role
              ON owner_role.oid = schema_object.nspowner
            WHERE owner_role.rolname = 'fleet_publication'
            UNION ALL
            SELECT 'relation_owner:' || relation_schema.nspname || ':' ||
                   relation_object.relname || ':OWNER:owner'
            FROM pg_catalog.pg_class AS relation_object
            JOIN pg_catalog.pg_namespace AS relation_schema
              ON relation_schema.oid = relation_object.relnamespace
            JOIN pg_catalog.pg_roles AS owner_role
              ON owner_role.oid = relation_object.relowner
            WHERE relation_object.relkind IN ('r', 'S', 'v', 'm', 'p')
              AND owner_role.rolname = 'fleet_publication'
            UNION ALL
            SELECT 'function_owner:' || function_schema.nspname || ':' ||
                   function_object.proname || ':OWNER:owner'
            FROM pg_catalog.pg_proc AS function_object
            JOIN pg_catalog.pg_namespace AS function_schema
              ON function_schema.oid = function_object.pronamespace
            JOIN pg_catalog.pg_roles AS owner_role
              ON owner_role.oid = function_object.proowner
            WHERE owner_role.rolname = 'fleet_publication'
            UNION ALL
            SELECT 'type_owner:' || type_schema.nspname || ':' ||
                   type_object.typname || ':OWNER:owner'
            FROM pg_catalog.pg_type AS type_object
            JOIN pg_catalog.pg_namespace AS type_schema
              ON type_schema.oid = type_object.typnamespace
            JOIN pg_catalog.pg_roles AS owner_role
              ON owner_role.oid = type_object.typowner
            WHERE owner_role.rolname = 'fleet_publication'
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
            FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE fleet_publication]
            WHERE object_type IN (
                'schemas', 'routines', 'tables', 'sequences', 'types'
            )
              AND (
                  role = 'fleet_publication'
                  AND NOT for_all_roles
                  AND grantee = 'fleet_publication'
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
                FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE fleet_publication
                      IN SCHEMA $schema_identifier]
                WHERE object_type IN (
                    'schemas', 'routines', 'tables', 'sequences', 'types'
                )
                  AND (
                      role = 'fleet_publication'
                      AND NOT for_all_roles
                      AND grantee = 'fleet_publication'
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
                  role = 'fleet_publication_reader'
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
                      role = 'fleet_publication_reader'
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

# Static proof runs before the first Docker command.
bash -n "$0"

policy_first_statement=$(awk '
    /^[[:space:]]*--/ || /^[[:space:]]*$/ { next }
    { print; exit }
' "$policy")
assert_exact "publication policy first statement" \
    "$policy_first_statement" 'SET search_path = pg_catalog, public, pg_temp;'

role_option_hardening=$(sed -n \
    '/^ALTER ROLE fleet_publication_reader WITH$/,/^    NOVIEWCLUSTERSETTING;$/p' \
    "$policy")
expected_role_option_hardening='ALTER ROLE fleet_publication_reader WITH
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
assert_exact "complete v26.2 publication role-option hardening" \
    "$role_option_hardening" "$expected_role_option_hardening"

reader_table_grants=$(sed -n \
    '/^GRANT SELECT ON TABLE$/,/^TO fleet_publication_reader;$/p' "$policy" \
    | grep -Eo 'public\.[_a-z]+' \
    | sort -u)
expected_reader_table_grants='public._sqlx_migrations
public.memory_chunks
public.memory_claim_embeddings
public.memory_claim_support
public.memory_claims
public.memory_conflict_members
public.memory_conflicts
public.memory_corpus_models'
assert_exact "exact publication reader table set" \
    "$reader_table_grants" "$expected_reader_table_grants"
assert_exact "publication reader table count" \
    "$(printf '%s\n' "$reader_table_grants" | wc -l | tr -d ' ')" '8'

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
' "$policy")
expected_policy_grant_statements='GRANT CONNECT ON DATABASE fleet_recall TO fleet_publication_reader;
GRANT USAGE ON SCHEMA public TO fleet_publication_reader;
GRANT SELECT ON TABLE public._sqlx_migrations, public.memory_corpus_models, public.memory_chunks, public.memory_claim_embeddings, public.memory_claim_support, public.memory_claims, public.memory_conflict_members, public.memory_conflicts TO fleet_publication_reader;
GRANT fleet_publication_reader TO fleet_publication;'
assert_exact "complete publication GRANT allowlist" \
    "$policy_grant_statements" "$expected_policy_grant_statements"

forbidden_grant_authority=$(awk '
    {
        line = $0
        sub(/--.*$/, "", line)
        if (line ~ /WITH[[:space:]]+GRANT[[:space:]]+OPTION/ || line ~ /^[[:space:]]*GRANT[[:space:]].*ON[[:space:]]+(SEQUENCE|ALL[[:space:]]+SEQUENCES)/) {
            print NR ":" line
        }
    }
' "$policy")
assert_exact "no publication DML/DDL/sequence/grant-option grants" \
    "$forbidden_grant_authority" ''

unqualified_policy_tables=$(awk '
    {
        line = $0
        sub(/--.*$/, "", line)
        if (line ~ /(FROM|ON TABLE)[[:space:]]+(_sqlx_migrations|memory_(corpus_models|chunks|claim_embeddings|claim_support|claims|conflict_members|conflicts))([^[:alnum:]_]|$)/) {
            print NR ":" line
        }
    }
' "$policy")
assert_exact "unqualified publication policy application tables" \
    "$unqualified_policy_tables" ''

assert_exact "fleet_recall current-database preflight" \
    "$(grep -F "IF pg_catalog.current_database() <> 'fleet_recall' THEN" "$policy")" \
    "    IF pg_catalog.current_database() <> 'fleet_recall' THEN"

unsupported_query_in_function_body=$(awk '
    /^DO \$\$/ { in_function_body = 1 }
    in_function_body && ($0 ~ /\[SHOW[[:space:]]/ || $0 ~ /^[[:space:]]*SHOW[[:space:]]/ || $0 ~ /crdb_internal\./ || $0 ~ /information_schema\./) { print NR ":" $0 }
    in_function_body && /^\$\$;$/ { in_function_body = 0 }
' "$policy")
assert_exact "SHOW/virtual-table-free publication policy function bodies" \
    "$unsupported_query_in_function_body" ''

for identity_option in 'VALID UNTIL=%' 'PROVISIONSRC=%' 'SUBJECT=%'; do
    assert_exact "$identity_option identity-gate reference count" \
        "$(grep -Fc "$identity_option" "$policy")" '1'
done

assert_exact "fixed principal role-grant count" \
    "$(grep -Fc 'GRANT fleet_publication_reader TO fleet_publication;' "$policy")" \
    '1'

system_read_only_audit_skip_count=$(awk '
    /^[[:space:]]+test "\$database" != .system. \|\| continue$/ { count++ }
    END { print count + 0 }
' "$0")
assert_exact "system read-only external-audit skip count" \
    "$system_read_only_audit_skip_count" '3'
system_default_mutation_target=$(awk '
    /^trap cleanup EXIT INT TERM$/ { in_connected_proof = 1 }
    in_connected_proof && /^for database in .*system.*; do$/ {
        print NR ":" $0
    }
    in_connected_proof &&
        /root_sql_in_database[[:space:]]+system([[:space:]]|$)/ {
        print NR ":" $0
    }
' "$0")
assert_exact "no system default-privilege mutation target" \
    "$system_default_mutation_target" ''
assert_exact "mutable stock-database normalization loop" \
    "$(grep -Fxc 'for database in defaultdb postgres; do' "$0")" \
    '1'

cross_database_public_create_lifecycle=$(awk '
    /^trap cleanup EXIT INT TERM$/ { in_connected_proof = 1 }
    !in_connected_proof { next }
    /root_sql_in_database proof_reader_other_database / { fixture_block++ }
    fixture_block == 1 &&
        /REVOKE CREATE ON SCHEMA public FROM public;/ {
        print "premature_revoke"
    }
    /external audit missed cross-database PUBLIC DDL authority/ {
        print "detected"
    }
    /cross-database PUBLIC DDL audit is read-only/ { print "preserved" }
    fixture_block >= 2 &&
        /REVOKE CREATE ON SCHEMA public FROM public;/ { print "cleaned" }
    /clean external PUBLIC application authority/ { print "empty" }
' "$0")
expected_cross_database_public_create_lifecycle='detected
preserved
cleaned
empty'
assert_exact "cross-database PUBLIC CREATE lifecycle" \
    "$cross_database_public_create_lifecycle" \
    "$expected_cross_database_public_create_lifecycle"

failed_prefix_public_all_lifecycle=$(awk '
    /^trap cleanup EXIT INT TERM$/ { in_connected_proof = 1 }
    !in_connected_proof { next }
    /GRANT ALL ON ALL TABLES IN SCHEMA public TO public;/ {
        print "injected"
    }
    /expect_policy_prefix_failure "drifted role with failed migration 17"/ {
        print "failed"
    }
    /failed-prefix PUBLIC ALL preservation/ {
        preservation_seen = 1
        print "preserved"
    }
    preservation_seen &&
        /UPDATE public\._sqlx_migrations SET success = true WHERE version = 17/ {
        print "restored"
    }
    preservation_seen && /^apply_reader_policy >\/dev\/null$/ &&
        reapply_count < 2 {
        reapply_count++
        print "reapplied"
    }
    /repaired-prefix PUBLIC table normalization/ { print "normalized" }
' "$0") \
    || fail "failed-prefix PUBLIC ALL lifecycle scan failed"
expected_failed_prefix_public_all_lifecycle='injected
failed
preserved
restored
reapplied
reapplied
normalized'
assert_exact "failed-prefix PUBLIC ALL lifecycle" \
    "$failed_prefix_public_all_lifecycle" \
    "$expected_failed_prefix_public_all_lifecycle"

expected_late_default_grantors='proof_external
proof_public
proof_nologin
fleet_runtime
fleet_control_bootstrap
fleet_registry_activation
fleet_registry_successor_activation
fleet_conflict_reconciliation'
late_created_default_grantors=$(awk '
    /^# Create auxiliary identities and role-edge adversaries/ {
        in_late_identity_phase = 1
    }
    in_late_identity_phase && /^CREATE (USER|ROLE) / {
        identity = $3
        sub(/;$/, "", identity)
        print identity
    }
' "$0") \
    || fail "late-created grantor inventory scan failed"
assert_exact "exact late-created default grantors" \
    "$late_created_default_grantors" "$expected_late_default_grantors"

late_default_cleanup_grantors=$(awk '
    /^for database in fleet_recall defaultdb postgres proof_reader_other_database; do$/ {
        in_late_cleanup_loop = 1
        next
    }
    in_late_cleanup_loop && /^ALTER DEFAULT PRIVILEGES FOR ROLE$/ {
        in_late_cleanup_roles = 1
        next
    }
    in_late_cleanup_roles && /^REVOKE EXECUTE ON ROUTINES FROM public;$/ {
        exit
    }
    in_late_cleanup_roles {
        identity = $0
        gsub(/^[[:space:]]+|[[:space:],]+$/, "", identity)
        print identity
    }
' "$0") \
    || fail "late-grantor default-cleanup inventory scan failed"
assert_exact "exact late-grantor default-cleanup set" \
    "$late_default_cleanup_grantors" "$expected_late_default_grantors"
late_default_cleanup_statement_shapes=$(awk '
    /^for database in fleet_recall defaultdb postgres proof_reader_other_database; do$/ {
        in_late_cleanup_loop = 1
        next
    }
    in_late_cleanup_loop && /^done$/ { exit }
    in_late_cleanup_loop &&
        (/ALTER DEFAULT PRIVILEGES/ || /FOR ALL ROLES/ || /IN SCHEMA/ ||
         /ON (ROUTINES|TYPES)/) {
        statement = $0
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", statement)
        print statement
    }
' "$0") \
    || fail "late-grantor default-cleanup statement-shape scan failed"
expected_late_default_cleanup_statement_shapes='ALTER DEFAULT PRIVILEGES FOR ROLE
REVOKE EXECUTE ON ROUTINES FROM public;'
assert_exact "exact late-grantor default-cleanup statement shapes" \
    "$late_default_cleanup_statement_shapes" \
    "$expected_late_default_cleanup_statement_shapes"
late_default_cleanup_database_loop_count=$(grep -Fxc \
    'for database in fleet_recall defaultdb postgres proof_reader_other_database; do' \
    "$0") \
    || fail "late-grantor mutable-database loop scan failed"
assert_exact "exact late-grantor mutable-database loop" \
    "$late_default_cleanup_database_loop_count" '1'

late_default_cleanup_lifecycle=$(awk '
    /^trap cleanup EXIT INT TERM$/ { in_connected_proof = 1 }
    !in_connected_proof { next }
    /^# Create auxiliary identities and role-edge adversaries/ {
        in_late_identity_phase = 1
    }
    in_late_identity_phase && /^CREATE USER proof_external;$/ {
        print "created"
    }
    in_late_identity_phase && !external_cleanup_proven &&
        (/^apply_reader_policy/ || /^expect_policy_/ ||
         /^(sql_as|expect_allowed|expect_denied) fleet_publication /) {
        print "premature_apply_or_use"
    }
    in_late_identity_phase && /^TO root;$/ { print "memberships_granted" }
    /assert_exact "late-grantor pre-clean external PUBLIC routine defaults"/ {
        print "external_twenty_four"
    }
    /^for database in fleet_recall defaultdb postgres proof_reader_other_database; do$/ {
        print "mutable_databases"
    }
    /"late-grantor pre-clean PUBLIC routine defaults in \$database"/ {
        print "preclean_eight"
    }
    in_late_identity_phase && /^ALTER DEFAULT PRIVILEGES FOR ROLE$/ {
        print "defaults_revoked"
    }
    /"late-grantor post-clean PUBLIC routine defaults in \$database"/ {
        print "postclean_zero"
    }
    in_late_identity_phase && /^FROM root;$/ { print "memberships_revoked" }
    /assert_root_scalar "temporary default-cleanup memberships"/ {
        print "memberships_zero"
    }
    /assert_root_scalar "late-grantor current PUBLIC routine defaults cleaned"/ {
        print "current_zero"
    }
    /assert_empty_audit "late-grantor external PUBLIC routine defaults cleaned"/ {
        print "external_zero"
        external_cleanup_proven = 1
    }
' "$0") \
    || fail "late-grantor default-cleanup lifecycle scan failed"
expected_late_default_cleanup_lifecycle='created
memberships_granted
external_twenty_four
mutable_databases
preclean_eight
defaults_revoked
postclean_zero
memberships_revoked
memberships_zero
current_zero
external_zero'
assert_exact "late-grantor default-cleanup lifecycle" \
    "$late_default_cleanup_lifecycle" \
    "$expected_late_default_cleanup_lifecycle"

# CockroachDB v26.2.3 requires a proposed table owner to hold CREATE on the
# table's schema. Freeze both ownership adversaries so that the setup-only
# privilege is granted solely for the transfer, revoked before unrelated drift
# or a policy apply, and proved absent both directly and effectively while the
# intended ownership remains present. The fixtures are fully dismantled after
# their fail-closed gates.
ownership_fixture_lifecycle=$(awk '
    function event(name) { print subject ":" name }
    /^trap cleanup EXIT INT TERM$/ { in_connected_proof = 1 }
    !in_connected_proof { next }

    /^CREATE TABLE public\.principal_owned_table \(id INT8 PRIMARY KEY\);$/ {
        if (subject != "") print "overlapping_fixture"
        subject = "fleet_publication"
        fixture_label = "principal"
        table_name = "principal_owned_table"
        stage = 1
        event("created")
        next
    }
    /^CREATE TABLE public\.reader_owned_table \(id INT8 PRIMARY KEY\);$/ {
        if (subject != "") print "overlapping_fixture"
        subject = "fleet_publication_reader"
        fixture_label = "reader"
        table_name = "reader_owned_table"
        stage = 2
        event("created")
        next
    }
    subject == "fleet_publication" && stage == 1 &&
        /^GRANT fleet_publication TO root;$/ {
        stage = 2
        event("temporary_membership_granted")
        next
    }
    subject != "" && stage == 2 &&
        $0 == "GRANT CREATE ON SCHEMA public TO " subject ";" {
        stage = 3
        event("temporary_create_granted")
        next
    }
    subject != "" && stage == 3 &&
        $0 == "ALTER TABLE public." table_name " OWNER TO " subject ";" {
        stage = 4
        event("ownership_transferred")
        next
    }
    subject != "" && stage == 4 &&
        $0 == "REVOKE CREATE ON SCHEMA public FROM " subject ";" {
        stage = 5
        event("temporary_create_revoked")
        next
    }
    subject != "" && stage == 5 &&
        $0 == "assert_root_scalar \"" fixture_label " ownership fixture direct CREATE cleanup\" \\" {
        stage = 6
        event("direct_create_absent")
        next
    }
    subject != "" && stage == 6 &&
        $0 == "assert_root_scalar \"" fixture_label " ownership fixture effective CREATE cleanup\" \\" {
        stage = 7
        event("effective_create_absent")
        next
    }
    subject != "" && stage == 7 &&
        $0 == "assert_root_scalar \"" fixture_label " ownership fixture table owner\" \\" {
        stage = 8
        event("ownership_proved")
        next
    }
    subject != "" && stage == 8 &&
        /^root_sql .ALTER ROLE fleet_publication_reader WITH CONTROLJOB. >\/dev\/null$/ {
        stage = 9
        event("unrelated_drift_injected")
        next
    }
    subject == "fleet_publication" && stage == 9 &&
        /^expect_policy_principal_ownership_failure "fixed principal table ownership"$/ {
        stage = 10
        event("gate_failed_closed")
        next
    }
    subject == "fleet_publication_reader" && stage == 9 &&
        /^expect_policy_ownership_failure "reader-owned public table"$/ {
        stage = 10
        event("gate_failed_closed")
        next
    }
    subject == "fleet_publication" && stage == 10 &&
        /^assert_root_scalar "principal-ownership target preservation"/ {
        stage = 11
        event("drift_preserved")
        next
    }
    subject == "fleet_publication_reader" && stage == 10 &&
        /^assert_root_scalar "ownership-gate option preservation"/ {
        stage = 11
        event("drift_preserved")
        next
    }
    subject != "" && stage == 11 &&
        $0 == "ALTER TABLE public." table_name " OWNER TO root;" {
        stage = 12
        event("ownership_returned")
        next
    }
    subject != "" && stage == 12 &&
        $0 == "DROP TABLE public." table_name ";" {
        if (subject == "fleet_publication") stage = 13
        else stage = 14
        event("table_dropped")
        next
    }
    subject == "fleet_publication" && stage == 13 &&
        /^REVOKE fleet_publication FROM root;$/ {
        stage = 14
        event("temporary_membership_revoked")
        next
    }
    subject != "" && stage == 14 && /^apply_reader_policy >\/dev\/null$/ {
        event("policy_reapplied")
        subject = ""
        fixture_label = ""
        table_name = ""
        stage = 0
        next
    }
    subject != "" && stage < 8 &&
        (/^apply_reader_policy/ || /^expect_policy_/ || /CONTROLJOB/) {
        event("premature_gate_or_apply")
    }
    END { if (subject != "") print subject ":incomplete" }
' "$0") \
    || fail "ownership-fixture lifecycle scan failed"
expected_ownership_fixture_lifecycle='fleet_publication:created
fleet_publication:temporary_membership_granted
fleet_publication:temporary_create_granted
fleet_publication:ownership_transferred
fleet_publication:temporary_create_revoked
fleet_publication:direct_create_absent
fleet_publication:effective_create_absent
fleet_publication:ownership_proved
fleet_publication:unrelated_drift_injected
fleet_publication:gate_failed_closed
fleet_publication:drift_preserved
fleet_publication:ownership_returned
fleet_publication:table_dropped
fleet_publication:temporary_membership_revoked
fleet_publication:policy_reapplied
fleet_publication_reader:created
fleet_publication_reader:temporary_create_granted
fleet_publication_reader:ownership_transferred
fleet_publication_reader:temporary_create_revoked
fleet_publication_reader:direct_create_absent
fleet_publication_reader:effective_create_absent
fleet_publication_reader:ownership_proved
fleet_publication_reader:unrelated_drift_injected
fleet_publication_reader:gate_failed_closed
fleet_publication_reader:drift_preserved
fleet_publication_reader:ownership_returned
fleet_publication_reader:table_dropped
fleet_publication_reader:policy_reapplied'
assert_exact "exact ownership-fixture CREATE lifecycle" \
    "$ownership_fixture_lifecycle" \
    "$expected_ownership_fixture_lifecycle"
ownership_fixture_effective_create_checks=$(awk '
    /^trap cleanup EXIT INT TERM$/ { in_connected_proof = 1 }
    in_connected_proof &&
        /^    "SELECT pg_catalog\.has_schema_privilege\($/ {
        print
        if (getline <= 0) exit 2
        print
        if (getline <= 0) exit 2
        print
    }
' "$0") \
    || fail "ownership-fixture effective-CREATE source scan failed"
expected_ownership_fixture_effective_create_checks="    \"SELECT pg_catalog.has_schema_privilege(
         'fleet_publication', 'public', 'CREATE'
     )::STRING\" 'false'
    \"SELECT pg_catalog.has_schema_privilege(
         'fleet_publication_reader', 'public', 'CREATE'
     )::STRING\" 'false'"
assert_exact "exact ownership-fixture effective CREATE checks" \
    "$ownership_fixture_effective_create_checks" \
    "$expected_ownership_fixture_effective_create_checks"

# CockroachDB v26.2.3 creates a separately granted implicit array descriptor
# for every enum, but that alias cannot be the target of a direct REVOKE. Freeze
# the late type adversary's narrow creator-default window: root's PUBLIC type
# default is absent only while both descriptors are created, is restored before
# any grant/gate, and both reader/PUBLIC grant shapes are proved exactly before
# their respective fail-closed policy applications.
reader_type_fixture_lifecycle=$(awk '
    /^trap cleanup EXIT INT TERM$/ { in_connected_proof = 1 }
    !in_connected_proof { next }
    /^assert_root_scalar "reader type root PUBLIC default baseline"/ {
        if (in_fixture) print "overlapping_fixture"
        in_fixture = 1
        print "default_baseline"
    }
    in_fixture && /^    REVOKE USAGE ON TYPES FROM public;$/ {
        default_quiesced = 1; print "default_revoked"
    }
    in_fixture && /^assert_root_scalar "reader type root PUBLIC default quiesced"/ {
        print "default_absence_proved"
    }
    in_fixture && /^CREATE TYPE public\.reader_private_type AS ENUM/ {
        print "type_pair_created"
    }
    in_fixture && /^    GRANT USAGE ON TYPES TO public;$/ {
        default_quiesced = 0; print "default_restored"
    }
    in_fixture && /^assert_root_scalar "reader type root PUBLIC default restored"/ {
        print "default_restoration_proved"
    }
    in_fixture && /^assert_root_scalar "reader type exact base and implicit array descriptors"/ {
        print "exact_type_pair_proved"
    }
    in_fixture && /^assert_root_scalar "reader type fixture initial PUBLIC grants"/ {
        print "initial_public_empty"
    }
    in_fixture && /^GRANT USAGE ON TYPE public\.reader_private_type TO fleet_publication_reader;$/ {
        print "reader_grant_injected"
    }
    in_fixture && /^assert_root_scalar "reader type fixture exact reader grant"/ {
        print "exact_reader_grant_proved"
    }
    in_fixture && /^expect_policy_grant_boundary_failure "reader type grant"$/ {
        print "reader_gate_failed_closed"
    }
    in_fixture && /^REVOKE USAGE ON TYPE public\.reader_private_type FROM fleet_publication_reader;$/ {
        print "reader_grant_revoked"
    }
    in_fixture && /^GRANT USAGE ON TYPE public\.reader_private_type TO public;$/ {
        print "public_grant_injected"
    }
    in_fixture && /^assert_root_scalar "reader type fixture reader grant cleanup"/ {
        print "reader_grant_absence_proved"
    }
    in_fixture && /^assert_root_scalar "reader type fixture exact PUBLIC grant"/ {
        print "exact_public_grant_proved"
    }
    in_fixture && /^expect_policy_public_grant_failure "PUBLIC type grant"$/ {
        print "public_gate_failed_closed"
    }
    in_fixture && /^REVOKE USAGE ON TYPE public\.reader_private_type FROM public;$/ {
        print "public_grant_revoked"
    }
    in_fixture && /^DROP TYPE public\.reader_private_type;$/ {
        print "type_pair_dropped"
    }
    in_fixture && /^assert_root_scalar "reader type fixture descriptor cleanup"/ {
        print "descriptor_cleanup_proved"
    }
    in_fixture && /^assert_root_scalar "reader type root PUBLIC default final restoration"/ {
        ready_for_reapply = 1; print "final_default_restoration_proved"
    }
    in_fixture && default_quiesced &&
        (/^apply_reader_policy/ || /^expect_policy_/ ||
         /^(sql_as|expect_allowed|expect_denied) /) {
        print "premature_default_window_use"
    }
    in_fixture && /^apply_reader_policy >\/dev\/null$/ {
        if (!ready_for_reapply) print "premature_policy_reapply"
        else {
            print "policy_reapplied"
            in_fixture = 0
        }
    }
    END {
        if (in_fixture || default_quiesced) print "incomplete_fixture"
    }
' "$0") \
    || fail "reader-type fixture lifecycle scan failed"
expected_reader_type_fixture_lifecycle='default_baseline
default_revoked
default_absence_proved
type_pair_created
default_restored
default_restoration_proved
exact_type_pair_proved
initial_public_empty
reader_grant_injected
exact_reader_grant_proved
reader_gate_failed_closed
reader_grant_revoked
public_grant_injected
reader_grant_absence_proved
exact_public_grant_proved
public_gate_failed_closed
public_grant_revoked
type_pair_dropped
descriptor_cleanup_proved
final_default_restoration_proved
policy_reapplied'
assert_exact "exact reader-type default/grant lifecycle" \
    "$reader_type_fixture_lifecycle" \
    "$expected_reader_type_fixture_lifecycle"

reader_type_fixture_source_counts=$(awk '
    /^trap cleanup EXIT INT TERM$/ { in_connected_proof = 1 }
    !in_connected_proof { next }
    /REVOKE USAGE ON TYPES FROM public;/ { default_revoke++ }
    /GRANT USAGE ON TYPES TO public;/ { default_restore++ }
    /reader type root PUBLIC default (baseline|quiesced|restored|final restoration)/ {
        default_assertion++
    }
    /'\''reader_private_type'\'', '\''_reader_private_type'\''/ {
        exact_type_pair++
    }
    /'\''reader_private_type:USAGE:false'\''/ { exact_grant_oracle++ }
    /^[[:space:]]*(GRANT|REVOKE|DROP|ALTER).*public\._reader_private_type/ {
        direct_array_mutation++
    }
    END {
        print "default_revoke=" (default_revoke + 0)
        print "default_restore=" (default_restore + 0)
        print "default_assertions=" (default_assertion + 0)
        print "exact_type_pair_filters=" (exact_type_pair + 0)
        print "exact_grant_oracles=" (exact_grant_oracle + 0)
        print "direct_array_mutations=" (direct_array_mutation + 0)
    }
' "$0") \
    || fail "reader-type fixture source-count scan failed"
expected_reader_type_fixture_source_counts='default_revoke=1
default_restore=1
default_assertions=4
exact_type_pair_filters=6
exact_grant_oracles=2
direct_array_mutations=0'
assert_exact "exact reader-type fixture source counts" \
    "$reader_type_fixture_source_counts" \
    "$expected_reader_type_fixture_source_counts"

if test "${FLEET_RECALL_RBAC_STATIC_ONLY:-0}" = '1'; then
    echo "publication-reader static grant proof passed"
    exit 0
fi

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
server_build_tag=$(docker exec "$container" cockroach version --build-tag)
test "$server_build_tag" = "$expected_crdb_build_tag" \
    || fail "Docker server must be exact CockroachDB $expected_crdb_build_tag (found $server_build_tag)"

docker exec "$container" cockroach sql --insecure \
    --execute 'CREATE DATABASE fleet_recall' >/dev/null

# Privilege-shaped stand-ins retain the columns and indexes used by public
# startup/status, chunk retrieval, support projection, claim ANN, and conflict
# hydration. Private objects make negative authorization checks concrete.
root_sql '
CREATE TABLE public._sqlx_migrations (
    version INT8 PRIMARY KEY,
    success BOOL NOT NULL
);

CREATE TABLE public.memory_corpus_models (
    tenant_id UUID NOT NULL,
    project STRING NOT NULL,
    embedding_model STRING NOT NULL,
    PRIMARY KEY (tenant_id, project)
);

CREATE TABLE public.memory_chunks (
    tenant_id UUID NOT NULL,
    project STRING NOT NULL,
    chunk_id STRING NOT NULL,
    source STRING NOT NULL,
    source_id STRING NOT NULL,
    source_config_id STRING NOT NULL,
    text STRING NOT NULL,
    content_sha256 BYTES NOT NULL,
    embedding VECTOR(512) NOT NULL,
    search_document TSVECTOR NOT NULL,
    links JSONB NOT NULL DEFAULT '\''{}'\''::JSONB,
    extra JSONB NOT NULL DEFAULT '\''{}'\''::JSONB,
    PRIMARY KEY (tenant_id, project, chunk_id),
    INDEX memory_chunks_semantic_idx (tenant_id, project, chunk_id),
    INDEX memory_chunks_source_semantic_idx (tenant_id, project, source, chunk_id),
    INDEX memory_chunks_lexical_idx (tenant_id, project, source_id, chunk_id)
);

CREATE TABLE public.memory_claim_embeddings (
    tenant_id UUID NOT NULL,
    project STRING NOT NULL,
    claim_id INT8 NOT NULL,
    passage_index INT8 NOT NULL,
    passage_text STRING NOT NULL,
    model STRING NOT NULL,
    vector VECTOR(512) NOT NULL,
    PRIMARY KEY (tenant_id, project, claim_id, passage_index),
    INDEX memory_claim_embeddings_semantic_idx (
        tenant_id, project, model, claim_id, passage_index
    )
);

CREATE TABLE public.memory_claim_support (
    id INT8 PRIMARY KEY,
    tenant_id UUID NOT NULL,
    project STRING NOT NULL,
    claim_id INT8 NOT NULL,
    chunk_id STRING NOT NULL,
    source_config_id STRING NOT NULL,
    source STRING NOT NULL,
    source_id STRING NOT NULL,
    content_sha256 BYTES,
    state STRING NOT NULL,
    INDEX memory_claim_support_chunk_idx (
        tenant_id, project, chunk_id, state, claim_id
    )
);

CREATE TABLE public.memory_claims (
    tenant_id UUID NOT NULL,
    project STRING NOT NULL,
    id INT8 NOT NULL,
    claim_key STRING,
    text STRING NOT NULL,
    state STRING NOT NULL,
    PRIMARY KEY (tenant_id, project, id),
    INDEX memory_claims_scope_key_idx (tenant_id, project, claim_key, id)
);

CREATE TABLE public.memory_conflicts (
    tenant_id UUID NOT NULL,
    project STRING NOT NULL,
    id INT8 NOT NULL,
    claim_key STRING NOT NULL,
    detector STRING NOT NULL,
    state STRING NOT NULL,
    rationale STRING NOT NULL,
    PRIMARY KEY (tenant_id, project, id),
    UNIQUE INDEX memory_conflicts_scope_key_detector_unique_idx (
        tenant_id, project, claim_key, detector
    )
);

CREATE TABLE public.memory_conflict_members (
    tenant_id UUID NOT NULL,
    project STRING NOT NULL,
    conflict_id INT8 NOT NULL,
    claim_id INT8 NOT NULL,
    PRIMARY KEY (tenant_id, project, conflict_id, claim_id),
    INDEX memory_conflict_members_claim_idx (
        tenant_id, project, claim_id, conflict_id
    )
);

CREATE SEQUENCE public.memory_claim_id_seq;
CREATE TABLE public.memory_control_events (id INT8 PRIMARY KEY);
CREATE TABLE public.memory_registry_heads (id INT8 PRIMARY KEY);
CREATE TABLE public.memory_mutation_receipts (id UUID PRIMARY KEY);
CREATE TABLE public.memory_events (id UUID PRIMARY KEY);
CREATE TABLE public.memory_evidence_events (id INT8 PRIMARY KEY);
CREATE TABLE public.memory_evidence_shard_heads (id INT8 PRIMARY KEY);
CREATE TABLE public.memory_evidence_quarantine (id INT8 PRIMARY KEY);
CREATE TABLE public.memory_content_objects (id INT8 PRIMARY KEY);
CREATE TABLE public.memory_relation_projection_v1 (id INT8 PRIMARY KEY);
CREATE TABLE public.memory_relation_projection_watermarks_v1 (id INT8 PRIMARY KEY);
CREATE VIEW public.memory_writer_authority_v1 AS
    SELECT id FROM public.memory_control_events;

INSERT INTO public._sqlx_migrations
SELECT version, true FROM generate_series(1, 16) AS version;

INSERT INTO public.memory_corpus_models VALUES (
    '\''0198a849-f6ae-7d61-9800-000000000001'\'',
    '\''publication-proof'\'',
    '\''proof-model'\''
);
INSERT INTO public.memory_chunks (
    tenant_id, project, chunk_id, source, source_id, source_config_id,
    text, content_sha256, embedding, search_document, links, extra
) VALUES (
    '\''0198a849-f6ae-7d61-9800-000000000001'\'',
    '\''publication-proof'\'', '\''chunk-1'\'', '\''markdown'\'', '\''doc-1'\'',
    '\''source-config-1'\'', '\''reader proof evidence'\'',
    decode(repeat('\''11'\'', 32), '\''hex'\''),
    ('\''[0'\'' || repeat('\'',0'\'', 511) || '\'']'\'')::VECTOR(512),
    to_tsvector('\''english'\'', '\''reader proof evidence'\''),
    '\''{"claim_id": 1}'\''::JSONB,
    '\''{"published": true}'\''::JSONB
);
INSERT INTO public.memory_claims VALUES (
    '\''0198a849-f6ae-7d61-9800-000000000001'\'',
    '\''publication-proof'\'', 1, '\''subject|predicate'\'',
    '\''reader claim'\'', '\''disputed'\''
);
INSERT INTO public.memory_claim_embeddings VALUES (
    '\''0198a849-f6ae-7d61-9800-000000000001'\'',
    '\''publication-proof'\'', 1, 0, '\''reader claim'\'', '\''proof-model'\'',
    ('\''[0'\'' || repeat('\'',0'\'', 511) || '\'']'\'')::VECTOR(512)
);
INSERT INTO public.memory_claim_support VALUES (
    1, '\''0198a849-f6ae-7d61-9800-000000000001'\'',
    '\''publication-proof'\'', 1, '\''chunk-1'\'', '\''source-config-1'\'',
    '\''markdown'\'', '\''doc-1'\'', decode(repeat('\''11'\'', 32), '\''hex'\''),
    '\''current'\''
);
INSERT INTO public.memory_conflicts VALUES (
    '\''0198a849-f6ae-7d61-9800-000000000001'\'',
    '\''publication-proof'\'', 1, '\''subject|predicate'\'',
    '\''same_key_functional_value_v2'\'', '\''open'\'', '\''proof conflict'\''
);
INSERT INTO public.memory_conflict_members VALUES (
    '\''0198a849-f6ae-7d61-9800-000000000001'\'',
    '\''publication-proof'\'', 1, 1
);
' >/dev/null

# Wrong-database and prefix failures precede target creation and preserve
# unrelated PUBLIC drift. A valid temporary history cannot mask a bad real
# public prefix, and a later successful row cannot mask failed migration 17.
expect_policy_database_failure "wrong current database"
assert_root_scalar "wrong-database target role creation" \
    "SELECT count(*)::STRING FROM [SHOW USERS]
     WHERE username = 'fleet_publication_reader'" '0'

root_sql 'GRANT SELECT ON TABLE public.memory_chunks TO public' >/dev/null
expect_policy_prefix_failure "prefix 16"
expect_policy_prefix_failure_with_temp "temporary prefix masks real prefix 16"
assert_root_scalar "prefix-16 target role creation" \
    "SELECT count(*)::STRING FROM [SHOW USERS]
     WHERE username = 'fleet_publication_reader'" '0'
assert_root_scalar "prefix-16 PUBLIC drift preservation" \
    "SELECT count(*)::STRING FROM [SHOW GRANTS ON TABLE public.memory_chunks]
     WHERE grantee = 'public' AND privilege_type = 'SELECT'" '1'

root_sql '
INSERT INTO public._sqlx_migrations VALUES (17, false), (18, true);
' >/dev/null
expect_policy_prefix_failure "failed migration 17 with later success"
expect_policy_prefix_failure_with_temp \
    "temporary prefix masks failed real migration 17"
assert_root_scalar "failed-17 target role creation" \
    "SELECT count(*)::STRING FROM [SHOW USERS]
     WHERE username = 'fleet_publication_reader'" '0'
assert_root_scalar "failed-17 PUBLIC drift preservation" \
    "SELECT count(*)::STRING FROM [SHOW GRANTS ON TABLE public.memory_chunks]
     WHERE grantee = 'public' AND privilege_type = 'SELECT'" '1'
root_sql \
    'UPDATE public._sqlx_migrations SET success = true WHERE version = 17' \
    >/dev/null

# A complete prefix still cannot create the logical role until the exact fixed
# principal exists in its externally managed quiesced state.
expect_policy_principal_failure "missing fixed publication principal"
assert_root_scalar "missing-principal target role creation" \
    "SELECT count(*)::STRING FROM [SHOW USERS]
     WHERE username = 'fleet_publication_reader'" '0'
root_sql '
CREATE USER fleet_publication;
ALTER USER fleet_publication WITH NOLOGIN;
' >/dev/null
assert_root_scalar "fixed principal exact initial options" \
    "SELECT count(*)::STRING FROM [SHOW USERS]
     WHERE username = 'fleet_publication'
       AND options::STRING = '{NOLOGIN}'" '1'

# Establish the documented v26.2 PUBLIC routine-default baseline before any
# successful apply. The engine retains one exact non-grantable all-roles row.
root_sql '
GRANT fleet_publication TO root;
ALTER DEFAULT PRIVILEGES FOR ROLE root, admin, fleet_publication
    REVOKE EXECUTE ON ROUTINES FROM public;
ALTER DEFAULT PRIVILEGES FOR ALL ROLES
    REVOKE EXECUTE ON ROUTINES FROM public;
REVOKE fleet_publication FROM root;
' >/dev/null
assert_root_scalar "principal default-cleanup membership" \
    "SELECT count(*)::STRING FROM [SHOW GRANTS ON ROLE]
     WHERE role_name = 'fleet_publication'
       AND member = 'root'" '0'
assert_root_scalar "clean-engine all-roles routine default" \
    "SELECT count(*)::STRING
     FROM (
         SELECT role, for_all_roles, object_type, grantee, privilege_type,
                is_grantable
         FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE public]
         UNION
         SELECT role, for_all_roles, object_type, grantee, privilege_type,
                is_grantable
         FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE public IN SCHEMA public]
     ) AS public_default
     WHERE role IS NULL
       AND for_all_roles
       AND object_type = 'routines'
       AND grantee = 'public'
       AND privilege_type = 'EXECUTE'
       AND NOT is_grantable" '1'

# Unsafe schema, PUBLIC system, and PUBLIC future-default drift all fail before
# target creation or normalization. Each exact drift is externally cleaned.
root_sql 'CREATE SCHEMA unsafe_publication_schema' >/dev/null
expect_policy_schema_failure "unexpected application schema before creation"
assert_root_scalar "schema-gate target role creation" \
    "SELECT count(*)::STRING FROM [SHOW USERS]
     WHERE username = 'fleet_publication_reader'" '0'
root_sql 'DROP SCHEMA unsafe_publication_schema' >/dev/null

root_sql 'GRANT SYSTEM CREATEROLE TO public' >/dev/null
expect_policy_public_system_failure "PUBLIC CREATEROLE before creation"
assert_root_scalar "PUBLIC-system target role creation" \
    "SELECT count(*)::STRING FROM [SHOW USERS]
     WHERE username = 'fleet_publication_reader'" '0'
assert_root_scalar "PUBLIC-system drift preservation" \
    "SELECT count(*)::STRING FROM [SHOW SYSTEM GRANTS]
     WHERE grantee = 'public' AND privilege_type = 'CREATEROLE'" '1'
root_sql 'REVOKE SYSTEM CREATEROLE FROM public' >/dev/null

root_sql '
ALTER DEFAULT PRIVILEGES FOR ROLE root IN SCHEMA public
    GRANT SELECT ON TABLES TO public;
' >/dev/null
expect_policy_default_failure "PUBLIC table default before creation"
assert_root_scalar "PUBLIC-default target role creation" \
    "SELECT count(*)::STRING FROM [SHOW USERS]
     WHERE username = 'fleet_publication_reader'" '0'
assert_root_scalar "PUBLIC default preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE public IN SCHEMA public]
     WHERE role = 'root'
       AND NOT for_all_roles
       AND object_type = 'tables'
       AND grantee = 'public'
       AND privilege_type = 'SELECT'" '1'
root_sql '
ALTER DEFAULT PRIVILEGES FOR ROLE root IN SCHEMA public
    REVOKE SELECT ON TABLES FROM public;
' >/dev/null

# Non-repairable PUBLIC function/type/external authority is rejected before the
# logical target exists, so each failed preflight must leave it absent.
root_sql '
CREATE FUNCTION public.fleet_publication_function()
RETURNS INT8 LANGUAGE SQL AS '\''SELECT 1'\'';
GRANT EXECUTE ON FUNCTION public.fleet_publication_function() TO public;
' >/dev/null
expect_policy_public_grant_failure "PUBLIC function grant before creation"
assert_root_scalar "PUBLIC-function target role creation" \
    "SELECT count(*)::STRING FROM [SHOW USERS]
     WHERE username = 'fleet_publication_reader'" '0'
root_sql '
REVOKE EXECUTE ON FUNCTION public.fleet_publication_function() FROM public;
DROP FUNCTION public.fleet_publication_function();
' >/dev/null

root_sql '
CREATE TYPE public.fleet_publication_type AS ENUM ('\''private'\'');
REVOKE USAGE ON TYPE public.fleet_publication_type FROM public;
GRANT USAGE ON TYPE public.fleet_publication_type TO public;
' >/dev/null
expect_policy_public_grant_failure "PUBLIC type grant before creation"
assert_root_scalar "PUBLIC-type target role creation" \
    "SELECT count(*)::STRING FROM [SHOW USERS]
     WHERE username = 'fleet_publication_reader'" '0'
root_sql '
REVOKE USAGE ON TYPE public.fleet_publication_type FROM public;
DROP TYPE public.fleet_publication_type;
' >/dev/null

root_sql "
CREATE EXTERNAL CONNECTION fleet_publication_external
    AS 'nodelocal://1/proof-publication-external';
GRANT USAGE, DROP ON EXTERNAL CONNECTION fleet_publication_external TO public;
" >/dev/null
expect_policy_public_grant_failure \
    "PUBLIC external-connection grants before creation"
assert_root_scalar "PUBLIC-external target role creation" \
    "SELECT count(*)::STRING FROM [SHOW USERS]
     WHERE username = 'fleet_publication_reader'" '0'
assert_root_scalar "PUBLIC external grant preservation" \
    "SELECT count(*)::STRING FROM [SHOW GRANTS FOR public]
     WHERE grantee = 'public'
       AND database_name IS NULL
       AND object_type = 'external_connection'
       AND object_name = 'fleet_publication_external'
       AND privilege_type IN ('DROP', 'USAGE')" '2'
root_sql '
REVOKE USAGE, DROP ON EXTERNAL CONNECTION fleet_publication_external FROM public;
DROP EXTERNAL CONNECTION fleet_publication_external;
' >/dev/null

# Bootstrap the mutable stock other-database baseline while the logical target
# is still absent. The system database stays read-only and is current-state
# audited by the inventories before the first role-creating apply.
root_sql 'GRANT fleet_publication TO root' >/dev/null
for database in defaultdb postgres; do
    root_sql_in_database "$database" '
ALTER DEFAULT PRIVILEGES FOR ROLE root, admin, fleet_publication
    REVOKE EXECUTE ON ROUTINES FROM public;
ALTER DEFAULT PRIVILEGES FOR ALL ROLES
    REVOKE EXECUTE ON ROUTINES FROM public;
' >/dev/null
done
root_sql 'REVOKE fleet_publication FROM root' >/dev/null
root_sql_in_database defaultdb \
    'REVOKE CREATE ON SCHEMA public FROM public' >/dev/null
root_sql_in_database postgres \
    'REVOKE CREATE ON SCHEMA public FROM public' >/dev/null
assert_root_scalar "bootstrap target remains absent" \
    "SELECT count(*)::STRING FROM [SHOW USERS]
     WHERE username = 'fleet_publication_reader'" '0'
assert_empty_audit "bootstrap external principal authority" \
    audit_other_database_principal_authority
assert_empty_audit "bootstrap external PUBLIC application authority" \
    inventory_other_database_public_authority

# First clean apply creates the logical role, removes repairable PUBLIC table
# drift, and installs only the exact eight-table SELECT boundary.
apply_reader_policy >/dev/null
assert_root_scalar "clean first-apply target creation" \
    "SELECT count(*)::STRING FROM [SHOW USERS]
     WHERE username = 'fleet_publication_reader'
       AND options::STRING = '{NOLOGIN}'" '1'
assert_root_scalar "first-apply PUBLIC table cleanup" \
    "SELECT count(*)::STRING
     FROM [SHOW GRANTS ON TABLE public.memory_chunks]
     WHERE grantee = 'public'" '0'
assert_root_scalar "first-apply exact fixed membership" \
    "SELECT count(*)::STRING FROM [SHOW GRANTS ON ROLE]
     WHERE role_name = 'fleet_publication_reader'
       AND member = 'fleet_publication'
       AND NOT is_admin" '1'

# Immediately expand the same frozen inventory to both subjects after creation.
assert_empty_audit "post-create external reader/principal authority" \
    audit_other_database_reader_authority
assert_empty_audit "post-create external PUBLIC application authority" \
    inventory_other_database_public_authority

root_sql 'CREATE DATABASE proof_reader_other_database' >/dev/null
root_sql 'GRANT fleet_publication TO root' >/dev/null
root_sql_in_database proof_reader_other_database '
ALTER DEFAULT PRIVILEGES FOR ROLE root, admin, fleet_publication
    REVOKE EXECUTE ON ROUTINES FROM public;
ALTER DEFAULT PRIVILEGES FOR ALL ROLES
    REVOKE EXECUTE ON ROUTINES FROM public;
CREATE TABLE public.proof_reader_grant (id INT8 PRIMARY KEY);
CREATE TABLE public.proof_reader_owned (id INT8 PRIMARY KEY);
CREATE TABLE public.proof_principal_owned (id INT8 PRIMARY KEY);
CREATE SCHEMA proof_application;
GRANT SELECT ON TABLE public.proof_reader_grant
    TO fleet_publication_reader, fleet_publication, public;
ALTER TABLE public.proof_reader_owned OWNER TO fleet_publication_reader;
ALTER TABLE public.proof_principal_owned OWNER TO fleet_publication;
ALTER DEFAULT PRIVILEGES FOR ROLE root
    GRANT INSERT ON TABLES
    TO fleet_publication_reader, fleet_publication, public;
ALTER DEFAULT PRIVILEGES FOR ROLE root IN SCHEMA proof_application
    GRANT UPDATE ON TABLES
    TO fleet_publication_reader, fleet_publication, public;
' >/dev/null
root_sql 'REVOKE fleet_publication FROM root' >/dev/null

outside_reader_authority=$(audit_other_database_reader_authority)
grep -Fq \
    'proof_reader_other_database:grant:fleet_publication_reader:table:public:proof_reader_grant:SELECT:not_grantable' \
    <<<"$outside_reader_authority" \
    || fail "external audit missed the cross-database reader grant"
grep -Fq \
    'proof_reader_other_database:grant:fleet_publication:table:public:proof_reader_grant:SELECT:not_grantable' \
    <<<"$outside_reader_authority" \
    || fail "external audit missed the cross-database principal grant"
grep -Fq \
    'proof_reader_other_database:relation_owner:fleet_publication_reader:public:proof_reader_owned:OWNER:owner' \
    <<<"$outside_reader_authority" \
    || fail "external audit missed cross-database reader ownership"
grep -Fq \
    'proof_reader_other_database:relation_owner:fleet_publication:public:proof_principal_owned:OWNER:owner' \
    <<<"$outside_reader_authority" \
    || fail "external audit missed cross-database principal ownership"
grep -Fq \
    'proof_reader_other_database:default:database:fleet_publication_reader:root:false:tables:fleet_publication_reader:INSERT:not_grantable' \
    <<<"$outside_reader_authority" \
    || fail "external audit missed the cross-database reader default"
grep -Fq \
    'proof_reader_other_database:default:schema:proof_application:fleet_publication:root:false:tables:fleet_publication:UPDATE:not_grantable' \
    <<<"$outside_reader_authority" \
    || fail "external audit missed the cross-database principal schema default"
outside_public_authority=$(inventory_other_database_public_authority)
grep -Fq \
    'proof_reader_other_database:table:public:proof_reader_grant:SELECT:not_grantable' \
    <<<"$outside_public_authority" \
    || fail "external audit missed cross-database PUBLIC data authority"
grep -Fq \
    'proof_reader_other_database:schema:public::CREATE:not_grantable' \
    <<<"$outside_public_authority" \
    || fail "external audit missed cross-database PUBLIC DDL authority"
grep -Fq \
    'proof_reader_other_database:default:database:root:false:tables:public:INSERT:not_grantable' \
    <<<"$outside_public_authority" \
    || fail "external audit missed the cross-database PUBLIC default"
grep -Fq \
    'proof_reader_other_database:default:schema:proof_application:root:false:tables:public:UPDATE:not_grantable' \
    <<<"$outside_public_authority" \
    || fail "external audit missed the cross-database PUBLIC schema default"

assert_root_scalar "cross-database reader audit is read-only" \
    "SELECT count(*)::STRING
     FROM [SHOW GRANTS ON TABLE proof_reader_other_database.public.proof_reader_grant]
     WHERE grantee = 'fleet_publication_reader'
       AND privilege_type = 'SELECT'" '1'
assert_root_scalar "cross-database PUBLIC DDL audit is read-only" \
    "SELECT count(*)::STRING
     FROM [SHOW GRANTS ON SCHEMA proof_reader_other_database.public]
     WHERE grantee = 'public'
       AND privilege_type = 'CREATE'
       AND NOT is_grantable" '1'
root_sql_in_database proof_reader_other_database '
ALTER TABLE public.proof_reader_owned OWNER TO root;
ALTER TABLE public.proof_principal_owned OWNER TO root;
REVOKE SELECT ON TABLE public.proof_reader_grant
    FROM fleet_publication_reader, fleet_publication, public;
REVOKE CREATE ON SCHEMA public FROM public;
ALTER DEFAULT PRIVILEGES FOR ROLE root
    REVOKE INSERT ON TABLES
    FROM fleet_publication_reader, fleet_publication, public;
ALTER DEFAULT PRIVILEGES FOR ROLE root IN SCHEMA proof_application
    REVOKE UPDATE ON TABLES
    FROM fleet_publication_reader, fleet_publication, public;
CREATE TABLE public.proof_future_private (id INT8 PRIMARY KEY);
CREATE TABLE proof_application.proof_future_private (id INT8 PRIMARY KEY);
' >/dev/null
assert_root_scalar "cross-database future defaults cleaned" \
    "SELECT count(*)::STRING
     FROM [SHOW GRANTS ON TABLE
           proof_reader_other_database.public.proof_future_private]
     WHERE grantee IN (
         'fleet_publication_reader', 'fleet_publication', 'public'
     )" '0'
assert_root_scalar "cross-database schema future defaults cleaned" \
    "SELECT count(*)::STRING
     FROM [SHOW GRANTS ON TABLE
           proof_reader_other_database.proof_application.proof_future_private]
     WHERE grantee IN (
         'fleet_publication_reader', 'fleet_publication', 'public'
     )" '0'
assert_empty_audit "clean external reader authority" \
    audit_other_database_reader_authority
assert_empty_audit "clean external PUBLIC application authority" \
    inventory_other_database_public_authority

# A deliberately malformed temporary history and eight namesake temporary
# tables cannot redirect the fully qualified prefix query or final grants.
apply_reader_policy_with_temp_shadows >/dev/null
assert_root_scalar "temp-shadow exact public table grants" \
    "SELECT count(*)::STRING
     FROM [SHOW GRANTS FOR fleet_publication_reader]
     WHERE grantee = 'fleet_publication_reader'
       AND database_name = 'fleet_recall'
       AND schema_name = 'public'
       AND object_type = 'table'
       AND privilege_type = 'SELECT'" '8'

# Create auxiliary identities and role-edge adversaries after the independent
# reader policy has succeeded. CockroachDB synthesizes their creator-scoped
# PUBLIC routine defaults in every database, so clean every mutable database
# under temporary root membership before any later policy apply or member use.
root_sql '
CREATE USER proof_external;
CREATE USER proof_public;
CREATE ROLE proof_nologin;
CREATE ROLE fleet_runtime;
CREATE ROLE fleet_control_bootstrap;
CREATE ROLE fleet_registry_activation;
CREATE ROLE fleet_registry_successor_activation;
CREATE ROLE fleet_conflict_reconciliation;

GRANT
    proof_external,
    proof_public,
    proof_nologin,
    fleet_runtime,
    fleet_control_bootstrap,
    fleet_registry_activation,
    fleet_registry_successor_activation,
    fleet_conflict_reconciliation
TO root;
' >/dev/null
late_grantor_public_routine_default_query="
SELECT count(*)::STRING
FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE public]
WHERE role IN (
    'proof_external',
    'proof_public',
    'proof_nologin',
    'fleet_runtime',
    'fleet_control_bootstrap',
    'fleet_registry_activation',
    'fleet_registry_successor_activation',
    'fleet_conflict_reconciliation'
)
  AND NOT for_all_roles
  AND grantee = 'public'
  AND object_type = 'routines'
  AND privilege_type = 'EXECUTE'
  AND NOT is_grantable
"
late_grantor_external_public_defaults=$(
    inventory_other_database_public_authority
) || fail "late-grantor pre-clean external PUBLIC audit failed"
expected_late_grantor_external_public_defaults=''
for database in defaultdb postgres proof_reader_other_database; do
    for late_grantor in \
        fleet_conflict_reconciliation \
        fleet_control_bootstrap \
        fleet_registry_activation \
        fleet_registry_successor_activation \
        fleet_runtime \
        proof_external \
        proof_nologin \
        proof_public; do
        late_grantor_default_row="${database}:default:database:${late_grantor}:false:routines:public:EXECUTE:not_grantable"
        if test -z "$expected_late_grantor_external_public_defaults"; then
            expected_late_grantor_external_public_defaults=$late_grantor_default_row
        else
            expected_late_grantor_external_public_defaults="${expected_late_grantor_external_public_defaults}
${late_grantor_default_row}"
        fi
    done
done
assert_exact "late-grantor pre-clean external PUBLIC routine defaults" \
    "$late_grantor_external_public_defaults" \
    "$expected_late_grantor_external_public_defaults"
for database in fleet_recall defaultdb postgres proof_reader_other_database; do
    late_grantor_public_routine_default_count=$(
        root_sql_in_database \
            "$database" "$late_grantor_public_routine_default_query" \
            | tail -n +2
    ) || fail "late-grantor pre-clean default audit failed in $database"
    assert_exact \
        "late-grantor pre-clean PUBLIC routine defaults in $database" \
        "$late_grantor_public_routine_default_count" '8'
    root_sql_in_database "$database" '
ALTER DEFAULT PRIVILEGES FOR ROLE
    proof_external,
    proof_public,
    proof_nologin,
    fleet_runtime,
    fleet_control_bootstrap,
    fleet_registry_activation,
    fleet_registry_successor_activation,
    fleet_conflict_reconciliation
REVOKE EXECUTE ON ROUTINES FROM public;
' >/dev/null
    late_grantor_public_routine_default_count=$(
        root_sql_in_database \
            "$database" "$late_grantor_public_routine_default_query" \
            | tail -n +2
    ) || fail "late-grantor post-clean default audit failed in $database"
    assert_exact \
        "late-grantor post-clean PUBLIC routine defaults in $database" \
        "$late_grantor_public_routine_default_count" '0'
done
root_sql '
REVOKE
    proof_external,
    proof_public,
    proof_nologin,
    fleet_runtime,
    fleet_control_bootstrap,
    fleet_registry_activation,
    fleet_registry_successor_activation,
    fleet_conflict_reconciliation
FROM root;
' >/dev/null
assert_root_scalar "temporary default-cleanup memberships" \
    "SELECT count(*)::STRING
     FROM [SHOW GRANTS ON ROLE]
     WHERE member = 'root'
       AND role_name IN (
           'proof_external',
           'proof_public',
           'proof_nologin',
           'fleet_runtime',
           'fleet_control_bootstrap',
           'fleet_registry_activation',
           'fleet_registry_successor_activation',
           'fleet_conflict_reconciliation'
       )" '0'
assert_root_scalar "late-grantor current PUBLIC routine defaults cleaned" \
    "SELECT count(*)::STRING
     FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE public]
     WHERE role IN (
         'proof_external',
         'proof_public',
         'proof_nologin',
         'fleet_runtime',
         'fleet_control_bootstrap',
         'fleet_registry_activation',
         'fleet_registry_successor_activation',
         'fleet_conflict_reconciliation'
     )
       AND NOT for_all_roles
       AND grantee = 'public'
       AND object_type = 'routines'
       AND privilege_type = 'EXECUTE'
       AND NOT is_grantable" '0'
assert_empty_audit "late-grantor external PUBLIC routine defaults cleaned" \
    inventory_other_database_public_authority

# VALID UNTIL is visible but has no portable exact reset. Prove the identity
# gate preserves unrelated drift, then replace only the logical bundle; the
# fixed principal and its external authentication material remain untouched.
root_sql "
ALTER ROLE fleet_publication_reader WITH
    CONTROLJOB
    VALID UNTIL '2035-01-01 00:00:00+00:00';
" >/dev/null
expect_policy_identity_failure "reader VALID UNTIL identity drift"
assert_root_scalar "identity-option preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW USERS] AS target_role
     CROSS JOIN LATERAL unnest(target_role.options) AS role_option(option_name)
     WHERE target_role.username = 'fleet_publication_reader'
       AND (
           role_option.option_name = 'CONTROLJOB'
           OR role_option.option_name LIKE 'VALID UNTIL=%'
       )" '2'
root_sql '
REVOKE fleet_publication_reader FROM fleet_publication;
REVOKE ALL ON DATABASE fleet_recall FROM fleet_publication_reader;
REVOKE ALL ON SCHEMA public FROM fleet_publication_reader;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM fleet_publication_reader;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM fleet_publication_reader;
DROP ROLE fleet_publication_reader;
' >/dev/null
apply_reader_policy >/dev/null

# Inject the complete v26.2 option/system/object/grant-option surface plus
# repairable PUBLIC drift. A failed migration 17 leaves every property intact;
# restoring the prefix lets two applications normalize it idempotently.
root_sql '
ALTER ROLE fleet_publication_reader WITH
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
GRANT SYSTEM CREATEROLE TO fleet_publication_reader;
GRANT ALL ON DATABASE fleet_recall TO fleet_publication_reader;
GRANT ALL ON SCHEMA public TO fleet_publication_reader;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.memory_chunks
    TO fleet_publication_reader WITH GRANT OPTION;
GRANT SELECT ON SEQUENCE public.memory_claim_id_seq
    TO fleet_publication_reader WITH GRANT OPTION;
GRANT ALL ON DATABASE fleet_recall TO public;
GRANT ALL ON SCHEMA public TO public;
GRANT ALL ON ALL TABLES IN SCHEMA public TO public;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO public;
UPDATE public._sqlx_migrations SET success = false WHERE version = 17;
' >/dev/null
expect_policy_prefix_failure "drifted role with failed migration 17"
assert_root_scalar "failed-prefix role-option preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW USERS] AS target_role
     CROSS JOIN LATERAL unnest(target_role.options) AS role_option(option_name)
     WHERE target_role.username = 'fleet_publication_reader'
       AND role_option.option_name IN (
           'BYPASSRLS', 'CANCELQUERY', 'CONTROLCHANGEFEED', 'CONTROLJOB',
           'CREATEDB', 'CREATELOGIN', 'CREATEROLE',
           'MODIFYCLUSTERSETTING', 'REPLICATION', 'NOSQLLOGIN',
           'VIEWACTIVITY', 'VIEWACTIVITYREDACTED', 'VIEWCLUSTERSETTING'
       )" '13'
assert_root_scalar "failed-prefix grant-option preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW GRANTS ON TABLE public.memory_chunks]
     WHERE grantee = 'fleet_publication_reader'
       AND privilege_type = 'INSERT'
       AND is_grantable" '1'
assert_root_scalar "failed-prefix PUBLIC ALL preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW GRANTS ON TABLE public.memory_chunks]
     WHERE grantee = 'public'
       AND privilege_type = 'ALL'
       AND NOT is_grantable" '1'

root_sql \
    'UPDATE public._sqlx_migrations SET success = true WHERE version = 17' \
    >/dev/null
apply_reader_policy >/dev/null
apply_reader_policy >/dev/null
assert_root_scalar "repaired-prefix PUBLIC table normalization" \
    "SELECT count(*)::STRING
     FROM [SHOW GRANTS ON TABLE public.memory_chunks]
     WHERE grantee = 'public'" '0'

assert_terminal_publication_state() {
# Terminal residue audit after the final two clean reapplies. This is the sole
# connected success boundary and covers every direct/inherited/default/owner,
# PUBLIC, system, external, and cross-database surface used by the contract.
assert_root_scalar "terminal exact reader grant count" \
    "SELECT count(*)::STRING
     FROM [SHOW GRANTS FOR fleet_publication_reader]
     WHERE grantee = 'fleet_publication_reader'" '10'
assert_root_scalar "terminal forbidden reader grants" \
    "SELECT count(*)::STRING
     FROM [SHOW GRANTS FOR fleet_publication_reader]
     WHERE grantee = 'fleet_publication_reader'
       AND NOT (
           (object_type = 'database'
               AND database_name = 'fleet_recall'
               AND privilege_type = 'CONNECT'
               AND NOT is_grantable)
           OR (object_type = 'schema'
               AND database_name = 'fleet_recall'
               AND schema_name = 'public'
               AND privilege_type = 'USAGE'
               AND NOT is_grantable)
           OR (object_type = 'table'
               AND database_name = 'fleet_recall'
               AND schema_name = 'public'
               AND object_name IN (
                   '_sqlx_migrations',
                   'memory_corpus_models',
                   'memory_chunks',
                   'memory_claim_embeddings',
                   'memory_claim_support',
                   'memory_claims',
                   'memory_conflict_members',
                   'memory_conflicts'
               )
               AND privilege_type = 'SELECT'
               AND NOT is_grantable)
       )" '0'
assert_root_scalar "terminal principal direct grants" \
    "SELECT count(*)::STRING
     FROM [SHOW GRANTS FOR fleet_publication]
     WHERE grantee = 'fleet_publication'" '0'
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
         'fleet_publication_reader', 'fleet_publication', 'public'
     )" '0'
assert_root_scalar "terminal exact NOLOGIN subjects" \
    "SELECT count(*)::STRING FROM [SHOW USERS]
     WHERE username IN ('fleet_publication_reader', 'fleet_publication')
       AND options::STRING = '{NOLOGIN}'" '2'
assert_root_scalar "terminal exact leaf role graph" \
    "SELECT count(*)::STRING FROM [SHOW GRANTS ON ROLE]
     WHERE (
         role_name IN ('fleet_publication_reader', 'fleet_publication')
         OR member IN ('fleet_publication_reader', 'fleet_publication')
     )
       AND role_name = 'fleet_publication_reader'
       AND member = 'fleet_publication'
       AND NOT is_admin" '1'
assert_root_scalar "terminal incident role-edge count" \
    "SELECT count(*)::STRING FROM [SHOW GRANTS ON ROLE]
     WHERE role_name IN ('fleet_publication_reader', 'fleet_publication')
        OR member IN ('fleet_publication_reader', 'fleet_publication')" '1'
assert_root_scalar "terminal current-database ownership" \
    "SELECT count(*)::STRING
     FROM (
         SELECT 1
         FROM pg_catalog.pg_database AS database_object
         JOIN pg_catalog.pg_roles AS owner_role
           ON owner_role.oid = database_object.datdba
         WHERE database_object.datname = 'fleet_recall'
           AND owner_role.rolname IN (
               'fleet_publication_reader', 'fleet_publication'
           )
         UNION ALL
         SELECT 1
         FROM pg_catalog.pg_namespace AS schema_object
         JOIN pg_catalog.pg_roles AS owner_role
           ON owner_role.oid = schema_object.nspowner
         WHERE owner_role.rolname IN (
             'fleet_publication_reader', 'fleet_publication'
         )
         UNION ALL
         SELECT 1
         FROM pg_catalog.pg_class AS relation_object
         JOIN pg_catalog.pg_roles AS owner_role
           ON owner_role.oid = relation_object.relowner
         WHERE relation_object.relkind IN ('r', 'S', 'v', 'm', 'p')
           AND owner_role.rolname IN (
               'fleet_publication_reader', 'fleet_publication'
           )
         UNION ALL
         SELECT 1
         FROM pg_catalog.pg_proc AS function_object
         JOIN pg_catalog.pg_roles AS owner_role
           ON owner_role.oid = function_object.proowner
         WHERE owner_role.rolname IN (
             'fleet_publication_reader', 'fleet_publication'
         )
         UNION ALL
         SELECT 1
         FROM pg_catalog.pg_type AS type_object
         JOIN pg_catalog.pg_roles AS owner_role
           ON owner_role.oid = type_object.typowner
         WHERE owner_role.rolname IN (
             'fleet_publication_reader', 'fleet_publication'
         )
     ) AS owned" '0'
assert_root_scalar "terminal subject future defaults" \
    "SELECT count(*)::STRING
     FROM (
         SELECT 'fleet_publication_reader' AS subject,
                role, for_all_roles, object_type, grantee,
                privilege_type, is_grantable
         FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE
               fleet_publication_reader]
         UNION ALL
         SELECT 'fleet_publication_reader' AS subject,
                role, for_all_roles, object_type, grantee,
                privilege_type, is_grantable
         FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE
               fleet_publication_reader IN SCHEMA public]
         UNION ALL
         SELECT 'fleet_publication' AS subject,
                role, for_all_roles, object_type, grantee,
                privilege_type, is_grantable
         FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE fleet_publication]
         UNION ALL
         SELECT 'fleet_publication' AS subject,
                role, for_all_roles, object_type, grantee,
                privilege_type, is_grantable
         FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE
               fleet_publication IN SCHEMA public]
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
           role = 'fleet_publication_reader'
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
     FROM [SHOW GRANTS ON TABLE public.future_private_table]
     WHERE grantee IN (
         'fleet_publication_reader', 'fleet_publication', 'public'
     )" '0'
assert_empty_audit "terminal external reader/principal authority" \
    audit_other_database_reader_authority
assert_empty_audit "terminal external PUBLIC authority" \
    inventory_other_database_public_authority
}

# Freeze the final direct grant, role, default, ownership, schema, and external
# audit postconditions before exercising queries through the member login.
reader_object_grants=$(root_sql "
SELECT schema_name || ':' || object_type || ':' || object_name || ':' ||
       privilege_type || ':' ||
       CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END
FROM [SHOW GRANTS FOR fleet_publication_reader]
WHERE grantee = 'fleet_publication_reader'
  AND database_name = 'fleet_recall'
  AND object_type IN ('table', 'sequence')
ORDER BY schema_name, object_type, object_name, privilege_type" | tail -n +2)
expected_reader_object_grants='public:table:_sqlx_migrations:SELECT:not_grantable
public:table:memory_chunks:SELECT:not_grantable
public:table:memory_claim_embeddings:SELECT:not_grantable
public:table:memory_claim_support:SELECT:not_grantable
public:table:memory_claims:SELECT:not_grantable
public:table:memory_conflict_members:SELECT:not_grantable
public:table:memory_conflicts:SELECT:not_grantable
public:table:memory_corpus_models:SELECT:not_grantable'
assert_exact "publication reader current object grants" \
    "$reader_object_grants" "$expected_reader_object_grants"
assert_exact "publication reader object grant count" \
    "$(printf '%s\n' "$reader_object_grants" | wc -l | tr -d ' ')" '8'

database_grants=$(root_sql "
SELECT database_name || ':' || grantee || ':' || privilege_type || ':' ||
       CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END
FROM [SHOW GRANTS ON DATABASE fleet_recall]
WHERE grantee IN ('public', 'fleet_publication_reader')
ORDER BY grantee, privilege_type" | tail -n +2)
assert_exact "publication reader database grants" \
    "$database_grants" \
    'fleet_recall:fleet_publication_reader:CONNECT:not_grantable'

schema_grants=$(root_sql "
SELECT schema_name || ':' || grantee || ':' || privilege_type || ':' ||
       CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END
FROM [SHOW GRANTS ON SCHEMA public]
WHERE grantee IN ('public', 'fleet_publication_reader')
ORDER BY grantee, privilege_type" | tail -n +2)
assert_exact "publication reader schema grants" \
    "$schema_grants" \
    'public:fleet_publication_reader:USAGE:not_grantable'

assert_root_scalar "PUBLIC application table/sequence grants" \
    "SELECT count(*)::STRING
     FROM [SHOW GRANTS FOR public]
     WHERE grantee = 'public'
       AND database_name = 'fleet_recall'
       AND schema_name = 'public'
       AND object_type IN ('table', 'sequence')" '0'
assert_root_scalar "reader/PUBLIC system grants" \
    "SELECT count(*)::STRING FROM [SHOW SYSTEM GRANTS]
     WHERE grantee IN ('fleet_publication_reader', 'public')" '0'
assert_root_scalar "reader exact NOLOGIN options" \
    "SELECT count(*)::STRING FROM [SHOW USERS]
     WHERE username = 'fleet_publication_reader'
       AND options::STRING = '{NOLOGIN}'" '1'

reader_role_edges=$(root_sql "
SELECT role_name || ':' || member || ':' ||
       CASE WHEN is_admin THEN 'admin_option' ELSE 'no_admin_option' END
FROM [SHOW GRANTS ON ROLE]
WHERE role_name = 'fleet_publication_reader'
   OR member = 'fleet_publication_reader'
ORDER BY role_name, member" | tail -n +2)
assert_exact "complete publication reader role edges" \
    "$reader_role_edges" \
    'fleet_publication_reader:fleet_publication:no_admin_option'

assert_root_scalar "known application role edges" \
    "SELECT count(*)::STRING FROM [SHOW GRANTS ON ROLE]
     WHERE (
         role_name = 'fleet_publication_reader'
         AND member IN (
             'fleet_runtime',
             'fleet_control_bootstrap',
             'fleet_registry_activation',
             'fleet_registry_successor_activation',
             'fleet_conflict_reconciliation'
         )
     ) OR (
         member = 'fleet_publication_reader'
         AND role_name IN (
             'fleet_runtime',
             'fleet_control_bootstrap',
             'fleet_registry_activation',
             'fleet_registry_successor_activation',
             'fleet_conflict_reconciliation'
         )
     )" '0'

assert_root_scalar "reader current-database ownership" \
    "SELECT count(*)::STRING
     FROM (
         SELECT 1
         FROM pg_catalog.pg_database AS database_object
         JOIN pg_catalog.pg_roles AS owner_role
           ON owner_role.oid = database_object.datdba
         WHERE database_object.datname = 'fleet_recall'
           AND owner_role.rolname = 'fleet_publication_reader'
         UNION ALL
         SELECT 1
         FROM pg_catalog.pg_namespace AS schema_object
         JOIN pg_catalog.pg_roles AS owner_role
           ON owner_role.oid = schema_object.nspowner
         WHERE owner_role.rolname = 'fleet_publication_reader'
         UNION ALL
         SELECT 1
         FROM pg_catalog.pg_class AS relation_object
         JOIN pg_catalog.pg_roles AS owner_role
           ON owner_role.oid = relation_object.relowner
         WHERE relation_object.relkind IN ('r', 'S', 'v', 'm', 'p')
           AND owner_role.rolname = 'fleet_publication_reader'
         UNION ALL
         SELECT 1
         FROM pg_catalog.pg_proc AS function_object
         JOIN pg_catalog.pg_roles AS owner_role
           ON owner_role.oid = function_object.proowner
         WHERE owner_role.rolname = 'fleet_publication_reader'
         UNION ALL
         SELECT 1
         FROM pg_catalog.pg_type AS type_object
         JOIN pg_catalog.pg_roles AS owner_role
           ON owner_role.oid = type_object.typowner
         WHERE owner_role.rolname = 'fleet_publication_reader'
     ) AS owned" '0'

assert_root_scalar "non-intrinsic reader future defaults" \
    "SELECT count(*)::STRING
     FROM (
         SELECT role, for_all_roles, object_type, grantee, privilege_type,
                is_grantable
         FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE fleet_publication_reader]
         UNION
         SELECT role, for_all_roles, object_type, grantee, privilege_type,
                is_grantable
         FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE fleet_publication_reader
               IN SCHEMA public]
     ) AS reader_default
     WHERE object_type IN ('schemas', 'routines', 'tables', 'sequences', 'types')
       AND (
           role = 'fleet_publication_reader'
           AND NOT for_all_roles
           AND grantee = 'fleet_publication_reader'
           AND privilege_type = 'ALL'
           AND is_grantable
       ) IS NOT TRUE" '0'

assert_root_scalar "non-intrinsic PUBLIC future defaults" \
    "SELECT count(*)::STRING
     FROM (
         SELECT role, for_all_roles, object_type, grantee, privilege_type,
                is_grantable
         FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE public]
         UNION
         SELECT role, for_all_roles, object_type, grantee, privilege_type,
                is_grantable
         FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE public IN SCHEMA public]
     ) AS public_default
     WHERE object_type IN ('schemas', 'routines', 'tables', 'sequences', 'types')
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
           role = 'fleet_publication_reader'
           AND NOT for_all_roles
           AND grantee = 'public'
           AND object_type = 'routines'
           AND privilege_type = 'EXECUTE'
           AND NOT is_grantable
       ) IS NOT TRUE" '0'

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
assert_empty_audit "final external reader authority" \
    audit_other_database_reader_authority
assert_empty_audit "final external PUBLIC application authority" \
    inventory_other_database_public_authority

# Authentication remains externally managed. Enable the exact audited principal
# only for the representative query window, then quiesce it again before every
# later policy reapplication.
root_sql 'ALTER USER fleet_publication WITH LOGIN' >/dev/null
# Representative allowed reads model every direct public query dependency.
expect_allowed fleet_publication "database version read" \
    'SELECT version()'
expect_allowed fleet_publication "complete migration-prefix read" \
    "SELECT count(*) = 17
       AND min(version) = 1
       AND max(version) = 17
       AND COALESCE(bool_and(success), false)
     FROM public._sqlx_migrations
     WHERE version BETWEEN 1 AND 17"
expect_allowed fleet_publication "startup index capability reads" \
    "SELECT
         (SELECT count(*) FROM [SHOW INDEXES FROM public.memory_chunks]) > 0,
         (SELECT count(*) FROM [SHOW INDEXES FROM public.memory_claim_embeddings]) > 0,
         (SELECT count(*) FROM [SHOW INDEXES FROM public.memory_claim_support]) > 0,
         (SELECT count(*) FROM [SHOW INDEXES FROM public.memory_conflict_members]) > 0"
expect_allowed fleet_publication "active model read" \
    "SELECT embedding_model
     FROM public.memory_corpus_models
     WHERE tenant_id = '0198a849-f6ae-7d61-9800-000000000001'
       AND project = 'publication-proof'"
expect_allowed fleet_publication "scoped health read" \
    "SELECT EXISTS(
         SELECT 1 FROM public.memory_chunks
         WHERE tenant_id = '0198a849-f6ae-7d61-9800-000000000001'
           AND project = 'publication-proof'
         LIMIT 1
     )"
expect_allowed fleet_publication "chunk vector lane" \
    "SELECT chunk_id
     FROM public.memory_chunks
     WHERE tenant_id = '0198a849-f6ae-7d61-9800-000000000001'
       AND project = 'publication-proof'
     ORDER BY embedding <=>
         ('[0' || repeat(',0', 511) || ']')::VECTOR(512)
     LIMIT 20"
expect_allowed fleet_publication "chunk lexical lane" \
    "SELECT chunk_id,
            ts_rank(search_document, plainto_tsquery('english', 'reader'))
     FROM public.memory_chunks
     WHERE tenant_id = '0198a849-f6ae-7d61-9800-000000000001'
       AND project = 'publication-proof'
       AND search_document @@ plainto_tsquery('english', 'reader')
     ORDER BY chunk_id LIMIT 20"
expect_allowed fleet_publication "bounded chunk metadata hydration" \
    "SELECT chunk_id,
            CASE WHEN octet_length(links::STRING) <= 8192
                 THEN links ELSE '{}'::JSONB END,
            CASE WHEN octet_length(extra::STRING) <= 8192
                 THEN extra ELSE '{}'::JSONB END
     FROM public.memory_chunks
     WHERE tenant_id = '0198a849-f6ae-7d61-9800-000000000001'
       AND project = 'publication-proof'
       AND chunk_id = ANY(ARRAY['chunk-1'])"
expect_allowed fleet_publication "support-to-chunk projection" \
    "SELECT DISTINCT support.claim_id, support.chunk_id
     FROM public.memory_claim_support AS support
     JOIN public.memory_chunks AS chunk
       ON chunk.tenant_id = support.tenant_id
      AND chunk.project = support.project
      AND chunk.source_config_id = support.source_config_id
      AND chunk.source = support.source
      AND chunk.source_id = support.source_id
      AND chunk.chunk_id = support.chunk_id
      AND chunk.content_sha256 = support.content_sha256
     WHERE support.tenant_id = '0198a849-f6ae-7d61-9800-000000000001'
       AND support.project = 'publication-proof'
       AND support.state = 'current'"
expect_allowed fleet_publication "claim ANN lane" \
    "SELECT claim_id, passage_index,
            1.0 - (vector <=>
                ('[0' || repeat(',0', 511) || ']')::VECTOR(512)) AS similarity
     FROM public.memory_claim_embeddings
     WHERE tenant_id = '0198a849-f6ae-7d61-9800-000000000001'
       AND project = 'publication-proof'
       AND model = 'proof-model'
     ORDER BY vector <=>
         ('[0' || repeat(',0', 511) || ']')::VECTOR(512)
     LIMIT 20"
expect_allowed fleet_publication "claim projection and conflict lineage" \
    "SELECT claim.id, claim.text, conflict.id AS conflict_id
     FROM public.memory_claims AS claim
     LEFT JOIN public.memory_conflicts AS conflict
       ON conflict.tenant_id = claim.tenant_id
      AND conflict.project = claim.project
      AND conflict.claim_key = claim.claim_key
     WHERE claim.tenant_id = '0198a849-f6ae-7d61-9800-000000000001'
       AND claim.project = 'publication-proof'
       AND claim.id = ANY(ARRAY[1]::INT8[])"
expect_allowed fleet_publication "conflict membership hydration" \
    "SELECT member.conflict_id, member.claim_id, conflict.detector, claim.text
     FROM public.memory_conflict_members AS member
     JOIN public.memory_conflicts AS conflict
       ON conflict.tenant_id = member.tenant_id
      AND conflict.project = member.project
      AND conflict.id = member.conflict_id
     JOIN public.memory_claims AS claim
       ON claim.tenant_id = member.tenant_id
      AND claim.project = member.project
      AND claim.id = member.claim_id
     WHERE member.tenant_id = '0198a849-f6ae-7d61-9800-000000000001'
       AND member.project = 'publication-proof'"

# The member cannot mutate even allowed tables, touch a sequence, create temp
# shadows, issue DDL or grants, or read private control/registry/reconciliation
# surfaces. A login without the logical role inherits no application SELECT.
expect_denied fleet_publication "migration-history insert" \
    'INSERT INTO public._sqlx_migrations VALUES (19, true)'
expect_denied fleet_publication "model insert" \
    "INSERT INTO public.memory_corpus_models VALUES (
         '0198a849-f6ae-7d61-9800-000000000001',
         'forbidden-write', 'proof-model'
     )"
expect_denied fleet_publication "model update" \
    "UPDATE public.memory_corpus_models
     SET embedding_model = 'forbidden'
     WHERE project = 'publication-proof'"
expect_denied fleet_publication "model delete" \
    "DELETE FROM public.memory_corpus_models
     WHERE project = 'publication-proof'"
expect_denied fleet_publication "model truncate" \
    'TRUNCATE TABLE public.memory_corpus_models'
expect_denied fleet_publication "application table creation" \
    'CREATE TABLE public.reader_forbidden_table (id INT8 PRIMARY KEY)'
expect_denied fleet_publication "temporary shadow creation" \
    'SET experimental_enable_temp_tables = on; CREATE TEMP TABLE memory_chunks (id INT8 PRIMARY KEY)'
expect_denied fleet_publication "search-path temporary shadow" \
    'SET experimental_enable_temp_tables = on; SET search_path = pg_temp, public; CREATE TEMP TABLE memory_claims (id INT8 PRIMARY KEY)'
expect_denied fleet_publication "application table alteration" \
    'ALTER TABLE public.memory_chunks ADD COLUMN forbidden BOOL'
expect_denied fleet_publication "application table drop" \
    'DROP TABLE public.memory_chunks'
expect_denied fleet_publication "claim sequence use" \
    "SELECT nextval('public.memory_claim_id_seq')"
expect_denied fleet_publication "control table read" \
    'SELECT id FROM public.memory_control_events'
expect_denied fleet_publication "registry table read" \
    'SELECT id FROM public.memory_registry_heads'
expect_denied fleet_publication "reconciliation receipt read" \
    'SELECT id FROM public.memory_mutation_receipts'
expect_denied fleet_publication "private event read" \
    'SELECT id FROM public.memory_events'
# PUBLIC-03/PUBLIC-04: migration 18 adds evidence-plane, governed-content,
# relation-projection, and writer-authority relations. None of them is one of
# the reader's eight publication tables, and the reader holds no privilege on
# any of them.
for stage4_private_relation in \
    memory_evidence_events \
    memory_evidence_shard_heads \
    memory_evidence_quarantine \
    memory_content_objects \
    memory_relation_projection_v1 \
    memory_relation_projection_watermarks_v1 \
    memory_writer_authority_v1
do
    expect_denied fleet_publication "$stage4_private_relation read" \
        "SELECT id FROM public.$stage4_private_relation"
    assert_root_scalar "$stage4_private_relation reader grants" \
        "SELECT count(*)::STRING
         FROM [SHOW GRANTS ON TABLE public.$stage4_private_relation]
         WHERE grantee IN (
             'fleet_publication', 'fleet_publication_reader', 'public'
         )" '0'
done
expect_denied fleet_publication "database creation" \
    'CREATE DATABASE publication_reader_forbidden'
expect_denied fleet_publication "role creation" \
    'CREATE ROLE publication_reader_forbidden'
expect_denied fleet_publication "table grant delegation" \
    'GRANT SELECT ON TABLE public.memory_chunks TO proof_public'
expect_denied fleet_publication "role-membership delegation" \
    'GRANT fleet_publication_reader TO proof_public'
expect_denied proof_public "PUBLIC application read" \
    'SELECT chunk_id FROM public.memory_chunks LIMIT 1'

root_sql 'ALTER USER fleet_publication WITH NOLOGIN' >/dev/null
assert_root_scalar "principal requiesced after query window" \
    "SELECT count(*)::STRING FROM [SHOW USERS]
     WHERE username = 'fleet_publication'
       AND options::STRING = '{NOLOGIN}'" '1'
assert_root_scalar "normalized exact reader options" \
    "SELECT count(*)::STRING FROM [SHOW USERS]
     WHERE username = 'fleet_publication_reader'
       AND options::STRING = '{NOLOGIN}'" '1'
assert_root_scalar "normalized reader system grants" \
    "SELECT count(*)::STRING FROM [SHOW SYSTEM GRANTS]
     WHERE grantee = 'fleet_publication_reader'" '0'

# Every incident edge except the exact reader-to-fixed-principal membership
# fails before unrelated target drift is normalized. This covers reader
# inheritance, alternate members, mixed principal authority, and transitive
# propagation through the principal in either direction.
root_sql '
ALTER ROLE fleet_publication_reader WITH CONTROLJOB;
GRANT fleet_runtime TO fleet_publication_reader;
' >/dev/null
expect_policy_role_edge_failure "reader inherits writer role"
assert_root_scalar "outbound-edge option preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW USERS] AS target_role
     CROSS JOIN LATERAL unnest(target_role.options) AS role_option(option_name)
     WHERE target_role.username = 'fleet_publication_reader'
       AND role_option.option_name = 'CONTROLJOB'" '1'
root_sql 'REVOKE fleet_runtime FROM fleet_publication_reader' >/dev/null
apply_reader_policy >/dev/null

root_sql '
ALTER ROLE fleet_runtime WITH LOGIN;
ALTER ROLE fleet_publication_reader WITH CONTROLJOB;
GRANT fleet_publication_reader TO fleet_runtime;
' >/dev/null
expect_policy_role_edge_failure "alternate LOGIN role inherits reader"
assert_root_scalar "known-edge option preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW USERS] AS target_role
     CROSS JOIN LATERAL unnest(target_role.options) AS role_option(option_name)
     WHERE target_role.username = 'fleet_publication_reader'
       AND role_option.option_name = 'CONTROLJOB'" '1'
root_sql '
REVOKE fleet_publication_reader FROM fleet_runtime;
ALTER ROLE fleet_runtime WITH NOLOGIN;
' >/dev/null
apply_reader_policy >/dev/null

root_sql '
ALTER ROLE fleet_publication_reader WITH CONTROLJOB;
GRANT fleet_publication_reader TO proof_nologin;
' >/dev/null
expect_policy_role_edge_failure "unknown NOLOGIN role inherits reader"
root_sql 'REVOKE fleet_publication_reader FROM proof_nologin' >/dev/null
apply_reader_policy >/dev/null

root_sql '
ALTER ROLE fleet_publication_reader WITH CONTROLJOB;
GRANT fleet_publication_reader TO proof_external;
' >/dev/null
expect_policy_role_edge_failure "alternate LOGIN member without admin option"
root_sql 'REVOKE fleet_publication_reader FROM proof_external' >/dev/null
apply_reader_policy >/dev/null

root_sql '
ALTER ROLE fleet_publication_reader WITH CONTROLJOB;
GRANT fleet_publication_reader TO fleet_publication WITH ADMIN OPTION;
' >/dev/null
expect_policy_role_edge_failure "fixed membership has admin option"
root_sql 'REVOKE fleet_publication_reader FROM fleet_publication' >/dev/null
apply_reader_policy >/dev/null

root_sql '
ALTER ROLE fleet_publication_reader WITH CONTROLJOB;
GRANT fleet_runtime TO fleet_publication;
' >/dev/null
expect_policy_role_edge_failure "fixed principal also inherits writer role"
assert_root_scalar "mixed-principal option preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW USERS] AS target_role
     CROSS JOIN LATERAL unnest(target_role.options) AS role_option(option_name)
     WHERE target_role.username = 'fleet_publication_reader'
       AND role_option.option_name = 'CONTROLJOB'" '1'
root_sql 'REVOKE fleet_runtime FROM fleet_publication' >/dev/null
apply_reader_policy >/dev/null

root_sql '
ALTER ROLE fleet_publication_reader WITH CONTROLJOB;
GRANT fleet_publication TO proof_external;
' >/dev/null
expect_policy_role_edge_failure "fixed principal transitively propagates reader"
root_sql 'REVOKE fleet_publication FROM proof_external' >/dev/null
apply_reader_policy >/dev/null

# A missing expected edge is the only repairable graph state.
root_sql 'REVOKE fleet_publication_reader FROM fleet_publication' >/dev/null
apply_reader_policy >/dev/null
assert_root_scalar "reinstalled exact fixed membership" \
    "SELECT count(*)::STRING FROM [SHOW GRANTS ON ROLE]
     WHERE role_name = 'fleet_publication_reader'
       AND member = 'fleet_publication'
       AND NOT is_admin" '1'

# The fixed principal must be quiesced and authority-free before every apply.
# Each principal gate runs before unrelated logical-role normalization.
root_sql '
ALTER ROLE fleet_publication_reader WITH CONTROLJOB;
ALTER USER fleet_publication WITH LOGIN;
' >/dev/null
expect_policy_principal_failure "fixed principal LOGIN drift"
assert_root_scalar "principal-option target preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW USERS] AS target_role
     CROSS JOIN LATERAL unnest(target_role.options) AS role_option(option_name)
     WHERE target_role.username = 'fleet_publication_reader'
       AND role_option.option_name = 'CONTROLJOB'" '1'
root_sql 'ALTER USER fleet_publication WITH NOLOGIN' >/dev/null
apply_reader_policy >/dev/null

root_sql '
ALTER ROLE fleet_publication_reader WITH CONTROLJOB;
GRANT SYSTEM VIEWACTIVITY TO fleet_publication;
' >/dev/null
expect_policy_principal_system_failure "fixed principal system drift"
assert_root_scalar "principal-system target preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW USERS] AS target_role
     CROSS JOIN LATERAL unnest(target_role.options) AS role_option(option_name)
     WHERE target_role.username = 'fleet_publication_reader'
       AND role_option.option_name = 'CONTROLJOB'" '1'
root_sql 'REVOKE SYSTEM VIEWACTIVITY FROM fleet_publication' >/dev/null
apply_reader_policy >/dev/null

root_sql '
ALTER ROLE fleet_publication_reader WITH CONTROLJOB;
ALTER DEFAULT PRIVILEGES FOR ROLE root IN SCHEMA public
    GRANT INSERT ON TABLES TO fleet_publication;
' >/dev/null
expect_policy_principal_default_failure "fixed principal table default"
assert_root_scalar "principal-default target preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW USERS] AS target_role
     CROSS JOIN LATERAL unnest(target_role.options) AS role_option(option_name)
     WHERE target_role.username = 'fleet_publication_reader'
       AND role_option.option_name = 'CONTROLJOB'" '1'
root_sql '
ALTER DEFAULT PRIVILEGES FOR ROLE root IN SCHEMA public
    REVOKE INSERT ON TABLES FROM fleet_publication;
' >/dev/null
apply_reader_policy >/dev/null

root_sql '
ALTER ROLE fleet_publication_reader WITH CONTROLJOB;
ALTER DEFAULT PRIVILEGES FOR ALL ROLES
    GRANT UPDATE ON TABLES TO fleet_publication;
' >/dev/null
expect_policy_principal_default_failure \
    "fixed principal FOR ALL ROLES table default"
root_sql '
ALTER DEFAULT PRIVILEGES FOR ALL ROLES
    REVOKE UPDATE ON TABLES FROM fleet_publication;
' >/dev/null
apply_reader_policy >/dev/null

root_sql '
ALTER ROLE fleet_publication_reader WITH CONTROLJOB;
GRANT SELECT ON TABLE public.memory_chunks TO fleet_publication;
' >/dev/null
expect_policy_principal_grant_failure "fixed principal direct table grant"
assert_root_scalar "principal-grant target preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW USERS] AS target_role
     CROSS JOIN LATERAL unnest(target_role.options) AS role_option(option_name)
     WHERE target_role.username = 'fleet_publication_reader'
       AND role_option.option_name = 'CONTROLJOB'" '1'
root_sql 'REVOKE SELECT ON TABLE public.memory_chunks FROM fleet_publication' \
    >/dev/null
apply_reader_policy >/dev/null

root_sql '
CREATE TABLE public.principal_owned_table (id INT8 PRIMARY KEY);
GRANT fleet_publication TO root;
GRANT CREATE ON SCHEMA public TO fleet_publication;
ALTER TABLE public.principal_owned_table OWNER TO fleet_publication;
REVOKE CREATE ON SCHEMA public FROM fleet_publication;
' >/dev/null
assert_root_scalar "principal ownership fixture direct CREATE cleanup" \
    "SELECT count(*)::STRING
     FROM [SHOW GRANTS ON SCHEMA public]
     WHERE grantee = 'fleet_publication'
       AND privilege_type = 'CREATE'" '0'
assert_root_scalar "principal ownership fixture effective CREATE cleanup" \
    "SELECT pg_catalog.has_schema_privilege(
         'fleet_publication', 'public', 'CREATE'
     )::STRING" 'false'
assert_root_scalar "principal ownership fixture table owner" \
    "SELECT count(*)::STRING
     FROM pg_catalog.pg_class AS relation_object
     JOIN pg_catalog.pg_namespace AS schema_object
       ON schema_object.oid = relation_object.relnamespace
     JOIN pg_catalog.pg_roles AS owner_role
       ON owner_role.oid = relation_object.relowner
     WHERE schema_object.nspname = 'public'
       AND relation_object.relname = 'principal_owned_table'
       AND relation_object.relkind = 'r'
       AND owner_role.rolname = 'fleet_publication'" '1'
root_sql 'ALTER ROLE fleet_publication_reader WITH CONTROLJOB' >/dev/null
expect_policy_principal_ownership_failure "fixed principal table ownership"
assert_root_scalar "principal-ownership target preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW USERS] AS target_role
     CROSS JOIN LATERAL unnest(target_role.options) AS role_option(option_name)
     WHERE target_role.username = 'fleet_publication_reader'
       AND role_option.option_name = 'CONTROLJOB'" '1'
root_sql '
ALTER TABLE public.principal_owned_table OWNER TO root;
DROP TABLE public.principal_owned_table;
REVOKE fleet_publication FROM root;
' >/dev/null
apply_reader_policy >/dev/null

# Target and PUBLIC future-object grants fail before unrelated CONTROLJOB drift
# is normalized. After exact cleanup, a future table receives no reader grant.
root_sql '
ALTER ROLE fleet_publication_reader WITH CONTROLJOB;
ALTER DEFAULT PRIVILEGES FOR ROLE root IN SCHEMA public
    GRANT INSERT ON TABLES TO fleet_publication_reader;
' >/dev/null
expect_policy_default_failure "target table default"
assert_root_scalar "target-default option preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW USERS] AS target_role
     CROSS JOIN LATERAL unnest(target_role.options) AS role_option(option_name)
     WHERE target_role.username = 'fleet_publication_reader'
       AND role_option.option_name = 'CONTROLJOB'" '1'
assert_root_scalar "target default preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE fleet_publication_reader
           IN SCHEMA public]
     WHERE role = 'root'
       AND object_type = 'tables'
       AND privilege_type = 'INSERT'" '1'
root_sql '
ALTER DEFAULT PRIVILEGES FOR ROLE root IN SCHEMA public
    REVOKE INSERT ON TABLES FROM fleet_publication_reader;
' >/dev/null
apply_reader_policy >/dev/null

root_sql '
ALTER ROLE fleet_publication_reader WITH CONTROLJOB;
ALTER DEFAULT PRIVILEGES FOR ALL ROLES
    GRANT DELETE ON TABLES TO fleet_publication_reader;
' >/dev/null
expect_policy_default_failure "target FOR ALL ROLES table default"
root_sql '
ALTER DEFAULT PRIVILEGES FOR ALL ROLES
    REVOKE DELETE ON TABLES FROM fleet_publication_reader;
' >/dev/null
apply_reader_policy >/dev/null

root_sql '
ALTER ROLE fleet_publication_reader WITH CONTROLJOB;
ALTER DEFAULT PRIVILEGES FOR ROLE root IN SCHEMA public
    GRANT SELECT ON TABLES TO public;
' >/dev/null
expect_policy_default_failure "PUBLIC table default after creation"
assert_root_scalar "PUBLIC-default option preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW USERS] AS target_role
     CROSS JOIN LATERAL unnest(target_role.options) AS role_option(option_name)
     WHERE target_role.username = 'fleet_publication_reader'
       AND role_option.option_name = 'CONTROLJOB'" '1'
root_sql '
ALTER DEFAULT PRIVILEGES FOR ROLE root IN SCHEMA public
    REVOKE SELECT ON TABLES FROM public;
' >/dev/null
apply_reader_policy >/dev/null
root_sql 'CREATE TABLE public.future_private_table (id INT8 PRIMARY KEY)' \
    >/dev/null
assert_root_scalar "future table received no reader grant" \
    "SELECT count(*)::STRING
     FROM [SHOW GRANTS ON TABLE public.future_private_table]
     WHERE grantee IN (
         'fleet_publication_reader', 'fleet_publication', 'public'
     )" '0'
root_sql 'ALTER USER fleet_publication WITH LOGIN' >/dev/null
expect_denied fleet_publication "future table read" \
    'SELECT id FROM public.future_private_table'
root_sql 'ALTER USER fleet_publication WITH NOLOGIN' >/dev/null

# PUBLIC system authority, an extra application schema, implicit ownership,
# and direct function/type authority are all unsafe preconditions. Each gate
# preserves CONTROLJOB drift and requires exact external cleanup.
root_sql '
ALTER ROLE fleet_publication_reader WITH CONTROLJOB;
GRANT SYSTEM CREATEROLE TO public;
' >/dev/null
expect_policy_public_system_failure "PUBLIC system drift after creation"
assert_root_scalar "PUBLIC-system option preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW USERS] AS target_role
     CROSS JOIN LATERAL unnest(target_role.options) AS role_option(option_name)
     WHERE target_role.username = 'fleet_publication_reader'
       AND role_option.option_name = 'CONTROLJOB'" '1'
root_sql 'REVOKE SYSTEM CREATEROLE FROM public' >/dev/null
apply_reader_policy >/dev/null

root_sql '
ALTER ROLE fleet_publication_reader WITH CONTROLJOB;
CREATE SCHEMA unsafe_publication_schema;
' >/dev/null
expect_policy_schema_failure "unexpected application schema after creation"
assert_root_scalar "schema-gate option preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW USERS] AS target_role
     CROSS JOIN LATERAL unnest(target_role.options) AS role_option(option_name)
     WHERE target_role.username = 'fleet_publication_reader'
       AND role_option.option_name = 'CONTROLJOB'" '1'
root_sql 'DROP SCHEMA unsafe_publication_schema' >/dev/null
apply_reader_policy >/dev/null

root_sql '
CREATE TABLE public.reader_owned_table (id INT8 PRIMARY KEY);
GRANT CREATE ON SCHEMA public TO fleet_publication_reader;
ALTER TABLE public.reader_owned_table OWNER TO fleet_publication_reader;
REVOKE CREATE ON SCHEMA public FROM fleet_publication_reader;
' >/dev/null
assert_root_scalar "reader ownership fixture direct CREATE cleanup" \
    "SELECT count(*)::STRING
     FROM [SHOW GRANTS ON SCHEMA public]
     WHERE grantee = 'fleet_publication_reader'
       AND privilege_type = 'CREATE'" '0'
assert_root_scalar "reader ownership fixture effective CREATE cleanup" \
    "SELECT pg_catalog.has_schema_privilege(
         'fleet_publication_reader', 'public', 'CREATE'
     )::STRING" 'false'
assert_root_scalar "reader ownership fixture table owner" \
    "SELECT count(*)::STRING
     FROM pg_catalog.pg_class AS relation_object
     JOIN pg_catalog.pg_namespace AS schema_object
       ON schema_object.oid = relation_object.relnamespace
     JOIN pg_catalog.pg_roles AS owner_role
       ON owner_role.oid = relation_object.relowner
     WHERE schema_object.nspname = 'public'
       AND relation_object.relname = 'reader_owned_table'
       AND relation_object.relkind = 'r'
       AND owner_role.rolname = 'fleet_publication_reader'" '1'
root_sql 'ALTER ROLE fleet_publication_reader WITH CONTROLJOB' >/dev/null
expect_policy_ownership_failure "reader-owned public table"
assert_root_scalar "ownership-gate option preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW USERS] AS target_role
     CROSS JOIN LATERAL unnest(target_role.options) AS role_option(option_name)
     WHERE target_role.username = 'fleet_publication_reader'
       AND role_option.option_name = 'CONTROLJOB'" '1'
root_sql '
ALTER TABLE public.reader_owned_table OWNER TO root;
DROP TABLE public.reader_owned_table;
' >/dev/null
apply_reader_policy >/dev/null

assert_root_scalar "reader type root PUBLIC default baseline" \
    "SELECT count(*)::STRING
     FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE public]
     WHERE role = 'root'
       AND NOT for_all_roles
       AND object_type = 'types'
       AND grantee = 'public'
       AND privilege_type = 'USAGE'
       AND NOT is_grantable" '1'
root_sql '
ALTER DEFAULT PRIVILEGES FOR ROLE root
    REVOKE USAGE ON TYPES FROM public;
' >/dev/null
assert_root_scalar "reader type root PUBLIC default quiesced" \
    "SELECT count(*)::STRING
     FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE public]
     WHERE role = 'root'
       AND NOT for_all_roles
       AND object_type = 'types'
       AND grantee = 'public'
       AND privilege_type = 'USAGE'
       AND NOT is_grantable" '0'
root_sql '
CREATE TYPE public.reader_private_type AS ENUM ('\''private'\'');
ALTER DEFAULT PRIVILEGES FOR ROLE root
    GRANT USAGE ON TYPES TO public;
' >/dev/null
assert_root_scalar "reader type root PUBLIC default restored" \
    "SELECT count(*)::STRING
     FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE public]
     WHERE role = 'root'
       AND NOT for_all_roles
       AND object_type = 'types'
       AND grantee = 'public'
       AND privilege_type = 'USAGE'
       AND NOT is_grantable" '1'
assert_root_scalar "reader type exact base and implicit array descriptors" \
    "SELECT type_object.typname
     FROM pg_catalog.pg_type AS type_object
     JOIN pg_catalog.pg_namespace AS schema_object
       ON schema_object.oid = type_object.typnamespace
     WHERE schema_object.nspname = 'public'
       AND type_object.typname IN (
           'reader_private_type', '_reader_private_type'
       )
     ORDER BY type_object.typname" \
    '_reader_private_type
reader_private_type'
assert_root_scalar "reader type fixture initial PUBLIC grants" \
    "SELECT object_name || ':' || privilege_type || ':' ||
            is_grantable::STRING
     FROM [SHOW GRANTS FOR public]
     WHERE grantee = 'public'
       AND database_name = 'fleet_recall'
       AND schema_name = 'public'
       AND object_type = 'type'
       AND object_name IN (
           'reader_private_type', '_reader_private_type'
       )
     ORDER BY object_name, privilege_type, is_grantable" ''
root_sql '
GRANT USAGE ON TYPE public.reader_private_type TO fleet_publication_reader;
ALTER ROLE fleet_publication_reader WITH CONTROLJOB;
' >/dev/null
assert_root_scalar "reader type fixture exact reader grant" \
    "SELECT object_name || ':' || privilege_type || ':' ||
            is_grantable::STRING
     FROM [SHOW GRANTS FOR fleet_publication_reader]
     WHERE grantee = 'fleet_publication_reader'
       AND database_name = 'fleet_recall'
       AND schema_name = 'public'
       AND object_type = 'type'
       AND object_name IN (
           'reader_private_type', '_reader_private_type'
       )
     ORDER BY object_name, privilege_type, is_grantable" \
    'reader_private_type:USAGE:false'
expect_policy_grant_boundary_failure "reader type grant"
assert_root_scalar "grant-boundary option preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW USERS] AS target_role
     CROSS JOIN LATERAL unnest(target_role.options) AS role_option(option_name)
     WHERE target_role.username = 'fleet_publication_reader'
       AND role_option.option_name = 'CONTROLJOB'" '1'
root_sql '
REVOKE USAGE ON TYPE public.reader_private_type FROM fleet_publication_reader;
GRANT USAGE ON TYPE public.reader_private_type TO public;
' >/dev/null
assert_root_scalar "reader type fixture reader grant cleanup" \
    "SELECT object_name || ':' || privilege_type || ':' ||
            is_grantable::STRING
     FROM [SHOW GRANTS FOR fleet_publication_reader]
     WHERE grantee = 'fleet_publication_reader'
       AND database_name = 'fleet_recall'
       AND schema_name = 'public'
       AND object_type = 'type'
       AND object_name IN (
           'reader_private_type', '_reader_private_type'
       )
     ORDER BY object_name, privilege_type, is_grantable" ''
assert_root_scalar "reader type fixture exact PUBLIC grant" \
    "SELECT object_name || ':' || privilege_type || ':' ||
            is_grantable::STRING
     FROM [SHOW GRANTS FOR public]
     WHERE grantee = 'public'
       AND database_name = 'fleet_recall'
       AND schema_name = 'public'
       AND object_type = 'type'
       AND object_name IN (
           'reader_private_type', '_reader_private_type'
       )
     ORDER BY object_name, privilege_type, is_grantable" \
    'reader_private_type:USAGE:false'
expect_policy_public_grant_failure "PUBLIC type grant"
assert_root_scalar "PUBLIC-type option preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW USERS] AS target_role
     CROSS JOIN LATERAL unnest(target_role.options) AS role_option(option_name)
     WHERE target_role.username = 'fleet_publication_reader'
       AND role_option.option_name = 'CONTROLJOB'" '1'
root_sql '
REVOKE USAGE ON TYPE public.reader_private_type FROM public;
DROP TYPE public.reader_private_type;
' >/dev/null
assert_root_scalar "reader type fixture descriptor cleanup" \
    "SELECT count(*)::STRING
     FROM pg_catalog.pg_type AS type_object
     JOIN pg_catalog.pg_namespace AS schema_object
       ON schema_object.oid = type_object.typnamespace
     WHERE schema_object.nspname = 'public'
       AND type_object.typname IN (
           'reader_private_type', '_reader_private_type'
       )" '0'
assert_root_scalar "reader type root PUBLIC default final restoration" \
    "SELECT count(*)::STRING
     FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE public]
     WHERE role = 'root'
       AND NOT for_all_roles
       AND object_type = 'types'
       AND grantee = 'public'
       AND privilege_type = 'USAGE'
       AND NOT is_grantable" '1'
apply_reader_policy >/dev/null

root_sql '
CREATE FUNCTION public.reader_private_function()
RETURNS INT8 LANGUAGE SQL AS '\''SELECT 1'\'';
REVOKE EXECUTE ON FUNCTION public.reader_private_function() FROM public;
GRANT EXECUTE ON FUNCTION public.reader_private_function()
    TO fleet_publication_reader;
ALTER ROLE fleet_publication_reader WITH CONTROLJOB;
' >/dev/null
expect_policy_grant_boundary_failure "reader function grant"
assert_root_scalar "function-boundary option preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW USERS] AS target_role
     CROSS JOIN LATERAL unnest(target_role.options) AS role_option(option_name)
     WHERE target_role.username = 'fleet_publication_reader'
       AND role_option.option_name = 'CONTROLJOB'" '1'
root_sql '
REVOKE EXECUTE ON FUNCTION public.reader_private_function()
    FROM fleet_publication_reader;
GRANT EXECUTE ON FUNCTION public.reader_private_function()
    TO fleet_publication;
' >/dev/null
expect_policy_principal_grant_failure "principal function grant"
root_sql '
REVOKE EXECUTE ON FUNCTION public.reader_private_function()
    FROM fleet_publication;
DROP FUNCTION public.reader_private_function();
' >/dev/null
apply_reader_policy >/dev/null

root_sql "
CREATE EXTERNAL CONNECTION reader_private_external
    AS 'nodelocal://1/reader-private-external';
GRANT USAGE, DROP ON EXTERNAL CONNECTION reader_private_external
    TO fleet_publication_reader;
ALTER ROLE fleet_publication_reader WITH CONTROLJOB;
" >/dev/null
expect_policy_grant_boundary_failure "reader external-connection grant"
assert_root_scalar "external-boundary option preservation" \
    "SELECT count(*)::STRING
     FROM [SHOW USERS] AS target_role
     CROSS JOIN LATERAL unnest(target_role.options) AS role_option(option_name)
     WHERE target_role.username = 'fleet_publication_reader'
       AND role_option.option_name = 'CONTROLJOB'" '1'
root_sql '
REVOKE USAGE, DROP ON EXTERNAL CONNECTION reader_private_external
    FROM fleet_publication_reader;
GRANT USAGE, DROP ON EXTERNAL CONNECTION reader_private_external
    TO fleet_publication;
' >/dev/null
expect_policy_principal_grant_failure "principal external-connection grant"
root_sql '
REVOKE USAGE, DROP ON EXTERNAL CONNECTION reader_private_external
    FROM fleet_publication;
DROP EXTERNAL CONNECTION reader_private_external;
' >/dev/null
apply_reader_policy >/dev/null
apply_reader_policy >/dev/null
assert_terminal_publication_state

echo "publication-reader grant proof passed"
