#!/usr/bin/env bash
set -euo pipefail

# This is the authoritative connected correctness proof. It uses the exact
# official CockroachDB binary, discovers and runs every named opt-in live test
# in this authoritative matrix, and exercises the four private CLIs included
# in this proof (control bootstrap, genesis activation, successor activation,
# and conflict reconciliation) on one secure local server. The one server and
# its result are never Docker parity evidence.
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

proof_tmp_root=${TMPDIR:-/tmp}
case "$proof_tmp_root" in
    *[[:space:]]*)
        echo "official-binary proof requires a whitespace-free temporary root" >&2
        exit 1
        ;;
esac
proof_dir=$(mktemp -d "$proof_tmp_root/ostk-registry-cli.XXXXXX")
cert_dir="$proof_dir/certs"
store_dir="$proof_dir/store"
artifact_dir="$proof_dir/artifacts"
url_file="$proof_dir/listening-url"
pid_file="$proof_dir/cockroach.pid"
root_default_url=''
owned_server_pid=''
server_was_spawned=0
server_pid_was_validated=0
proof_body_completed=0
control_password='local-control-member-proof-password'
activation_password='local-activation-member-proof-password'
runtime_password='local-runtime-member-proof-password'
reconciliation_password='local-conflict-reconciliation-member-proof-password'
successor_password='local-successor-activation-member-proof-password'

server_pid_exists() {
    local pid=$1
    case "$pid" in
        ''|0|*[!0-9]*) return 1 ;;
    esac
    kill -0 "$pid" >/dev/null 2>&1
}

server_pid_is_zombie() {
    local pid=$1
    local state
    state=$(ps -p "$pid" -o stat= 2>/dev/null) || return 1
    case "$state" in
        *Z*) return 0 ;;
        *) return 1 ;;
    esac
}

shell_owned_server_job_state() {
    local pid=$1
    local snapshot="$proof_dir/.owned-server-active-jobs"
    : > "$snapshot" 2>/dev/null || return 2
    jobs -pr >> "$snapshot" 2>/dev/null || return 2
    jobs -ps >> "$snapshot" 2>/dev/null || return 2
    grep -Fxq "$pid" "$snapshot" && return 0
    return 1
}

owned_server_pid_matches() {
    local pid=$1
    local command
    server_pid_exists "$pid" || return 1
    server_pid_is_zombie "$pid" && return 1
    command=$(ps -ww -p "$pid" -o command= 2>/dev/null) || return 1
    case " $command " in
        *" start-single-node "*) ;;
        *) return 1 ;;
    esac
    case " $command " in
        *" --store=$store_dir "*) return 0 ;;
        *) return 1 ;;
    esac
}

cleanup() {
    local original_status=$?
    local cleanup_failed=0
    local drained=0
    local job_state=1
    local process_stop_proven=1
    trap - EXIT
    trap '' INT TERM
    set +e
    if test "$server_was_spawned" -eq 1 \
        && test "$server_pid_was_validated" -ne 1; then
        echo "spawned CockroachDB did not publish its exact shell-owned PID" >&2
        cleanup_failed=1
    fi
    if test -n "$root_default_url"; then
        if "$crdb" node drain --self --shutdown --url="$root_default_url" \
            --drain-wait=10s >/dev/null 2>&1; then
            drained=1
        fi
    fi
    case "$owned_server_pid" in
        ''|0|*[!0-9]*)
            if test "$server_was_spawned" -eq 1; then
                echo "spawned CockroachDB has no positive shell-owned PID" >&2
                cleanup_failed=1
            fi
            ;;
        *)
            if test "$server_was_spawned" -eq 1; then
                process_stop_proven=0
                shell_owned_server_job_state "$owned_server_pid"
                job_state=$?
                if test "$job_state" -eq 0; then
                    if test "$drained" -eq 0; then
                        kill -TERM "$owned_server_pid" >/dev/null 2>&1 || true
                    fi
                    for _ in $(seq 1 120); do
                        shell_owned_server_job_state "$owned_server_pid"
                        job_state=$?
                        if test "$job_state" -ne 0; then
                            break
                        fi
                        sleep 0.25
                    done
                    if test "$job_state" -eq 0; then
                        kill -KILL "$owned_server_pid" >/dev/null 2>&1 || true
                        for _ in $(seq 1 40); do
                            shell_owned_server_job_state "$owned_server_pid"
                            job_state=$?
                            if test "$job_state" -ne 0; then
                                break
                            fi
                            sleep 0.25
                        done
                    fi
                fi

                if test "$job_state" -eq 1; then
                    wait "$owned_server_pid" >/dev/null 2>&1 || true
                    process_stop_proven=1
                elif test "$job_state" -eq 0; then
                    echo "could not stop shell-owned CockroachDB PID: $owned_server_pid" >&2
                    cleanup_failed=1
                else
                    echo "could not determine shell-owned CockroachDB job state" >&2
                    cleanup_failed=1
                fi
            fi
            ;;
    esac
    if test "$server_was_spawned" -eq 1 \
        && test "$process_stop_proven" -ne 1; then
        echo "preserving proof directory after unproven server stop: $proof_dir" >&2
        cleanup_failed=1
    else
        case "$proof_dir" in
            */ostk-registry-cli.*)
                for _ in $(seq 1 20); do
                    rm -rf -- "$proof_dir" 2>/dev/null || true
                    test ! -e "$proof_dir" && break
                    sleep 0.1
                done
                if test -e "$proof_dir"; then
                    echo "could not remove registry proof directory: $proof_dir" >&2
                    cleanup_failed=1
                fi
                ;;
            *)
                echo "refusing to remove unexpected proof directory" >&2
                cleanup_failed=1
                ;;
        esac
    fi
    if test "$cleanup_failed" -ne 0; then
        exit 1
    fi
    if test "$original_status" -eq 0; then
        if test "$proof_body_completed" -ne 1; then
            echo "official-binary proof body ended before its final checkpoint" >&2
            exit 1
        fi
        printf '%s\n' "official-binary connected correctness proof passed" \
            || exit 1
    fi
    exit "$original_status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

fail() {
    echo "registry activation CLI proof failed: $*" >&2
    exit 1
}

require_discovered_test() {
    local listing=$1
    local exact_test=$2
    grep -Fxq "$exact_test: test" <<<"$listing" \
        || fail "$exact_test was not discovered"
}

root_scalar() {
    "$crdb" sql --url="$root_url" --format=tsv --execute="$1" | tail -n +2
}

# CockroachDB's TSV reporter CSV-quotes fields containing double quotes. Use
# its JSON envelope for JSON-valued strings, then require one named object.
root_json_object() {
    "$crdb" sql --url="$root_url" --format=json --execute="$1" |
        jq -sce '
            if length == 1
               and (.[0] | type) == "array"
               and (.[0] | length) == 1
               and (.[0][0] | type) == "object"
               and (.[0][0] | keys) == ["json_value"]
               and (.[0][0].json_value | type) == "string"
            then
                (.[0][0].json_value | fromjson) as $decoded
                | if ($decoded | type) == "object"
                  then $decoded
                  else error("SQL JSON scalar was not an object")
                  end
            else
                error("SQL JSON query did not return exactly one named scalar")
            end
        '
}

root_sql_in_database() {
    local database=$1
    local statement=$2
    "$crdb" sql --url="$root_default_url" --database="$database" \
        --format=tsv --execute="$statement"
}

assert_exact() {
    local label=$1
    local actual=$2
    local expected=$3
    if test "$actual" != "$expected"; then
        printf '%s\n' "unexpected $label" \
            "expected:" "$expected" "actual:" "$actual" >&2
        fail "$label did not match the authoritative contract"
    fi
}

assert_root_scalar() {
    local label=$1
    local statement=$2
    local expected=$3
    local actual
    actual=$(root_scalar "$statement")
    assert_exact "$label" "$actual" "$expected"
}

assert_public_routine_defaults() {
    local phase=$1
    local expected=$2
    assert_root_scalar "$phase PUBLIC routine defaults" "
        SELECT COALESCE(string_agg(
            'role=' || COALESCE(role, 'ALL') || ',' ||
            for_all_roles::STRING || ',' || object_type || ',' || grantee || ',' ||
            privilege_type || ',' || is_grantable::STRING,
            '|' ORDER BY for_all_roles DESC, COALESCE(role, ''), object_type, grantee,
                         privilege_type, is_grantable
        ), '')
        FROM (
            SELECT role, for_all_roles, object_type, grantee,
                   privilege_type, is_grantable
            FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE public]
            UNION
            SELECT role, for_all_roles, object_type, grantee,
                   privilege_type, is_grantable
            FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE public
                  IN SCHEMA public]
        ) AS public_default
        WHERE object_type = 'routines'
          AND grantee = 'public'" "$expected"
}

apply_reconciliation_policy() {
    "$crdb" sql --url="$root_url" < "$reconciliation_policy"
}

apply_successor_policy() {
    "$crdb" sql --url="$root_url" < "$successor_policy"
}

apply_successor_policy_in_database() {
    local database=$1
    "$crdb" sql --url="$root_default_url" --database="$database" \
        < "$successor_policy"
}

# Reapply the successor policy in a session where a failed temporary migration
# history and every grant target shadow the real public relations. The policy
# must pin its search path, read public history, and grant only on public
# objects. The two exact non-grantable temporary-schema PUBLIC grants are the
# CockroachDB v26.2.3 session baseline, not application authority.
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
        sed -n '1,$p' "$successor_policy"
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
    } | "$crdb" sql --url="$root_url"
}

# Reapply the policy in one session whose temporary schema shadows migration
# history and every repository grant target. The policy must read the real
# public history, grant only on fully qualified public objects, and admit only
# CockroachDB's exact non-grantable temporary-schema fallback.
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
        sed -n '1,$p' "$reconciliation_policy"
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
    } | "$crdb" sql --url="$root_url"
}

# The successor policy is intentionally fleet_recall-local. This read-only
# deployment audit enumerates every other database for direct target grants and
# ownership. The proof is single-threaded, so its audit/reapply/use interval is
# the runbook's required role/grant/default/ownership and schema-DDL freeze.
audit_other_database_successor_authority() {
    local databases
    local database
    local grant_rows
    local ownership_rows
    local row
    if ! databases=$(root_sql_in_database fleet_recall \
        'SELECT database_name FROM [SHOW DATABASES] ORDER BY database_name' \
        | tail -n +2); then
        fail "external successor target audit could not enumerate databases"
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
            fail "external successor target audit could not inspect grants in $database"
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
            fail "external successor target audit could not inspect ownership in $database"
        fi
        while IFS= read -r row; do
            test -n "$row" || continue
            printf '%s:%s\n' "$database" "$row"
        done <<<"$ownership_rows"
    done <<<"$databases"
}

# The reconciliation policy is intentionally fleet_recall-local. This read-only
# deployment audit enumerates every other database for direct target grants and
# ownership. It is called only after the first policy apply has created the
# target role. The proof is single-threaded, so its audit/reapply/use interval
# is the runbook's required change freeze.
audit_other_database_target_authority() {
    local databases
    local database
    local grant_rows
    local ownership_rows
    local row
    if ! databases=$(root_sql_in_database fleet_recall \
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

# PUBLIC is inherited by every role. Ordinary other-database CONNECT,
# TEMPORARY, public-schema USAGE, and the engine's virtual/system fallbacks remain
# ambient cluster state; this inventory exposes only application-object or DDL
# authority that must be explicitly assessed and cleaned for this proof.
inventory_other_database_public_application_authority() {
    local databases
    local database
    local public_rows
    local row
    if ! databases=$(root_sql_in_database fleet_recall \
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

# Both one-shot policies are safe in a reused administrator session only if
# they pin built-in resolution first, bind themselves to fleet_recall, fully
# qualify every application relation, and clear the complete v26.2 role-option
# surface. Keep these static gates in the official wrapper so its connected
# result cannot be credited to a weakened policy file.
successor_policy="$repo_root/deploy/cockroach/successor-activation-role-grants.sql"
successor_policy_first_statement=$(awk '
    /^[[:space:]]*--/ || /^[[:space:]]*$/ { next }
    { print; exit }
' "$successor_policy")
assert_exact "successor policy first statement" \
    "$successor_policy_first_statement" \
    'SET search_path = pg_catalog, public, pg_temp;'

successor_current_database_preflight=$(grep -F \
    "IF pg_catalog.current_database() <> 'fleet_recall' THEN" \
    "$successor_policy")
assert_exact "successor fleet_recall current-database preflight" \
    "$successor_current_database_preflight" \
    "    IF pg_catalog.current_database() <> 'fleet_recall' THEN"

unqualified_successor_policy_references=$(sed -E 's/--.*$//' \
    "$successor_policy" \
    | grep -En \
        '(FROM|ON TABLE)[[:space:]]+(_sqlx_migrations|memory_(control|registry)_[a-z0-9_]+)([^[:alnum:]_]|$)' \
        || true)
assert_exact "unqualified successor policy application references" \
    "$unqualified_successor_policy_references" ''

qualified_successor_policy_references=$(sed -E 's/--.*$//' \
    "$successor_policy" \
    | grep -Eo \
        'public\.(_sqlx_migrations|memory_(control_(bootstraps|events|log_epochs|shard_heads)|registry_(activations|current_heads_v2|genesis_bridge_consumptions|heads|transitions)))' \
    | sort \
    | uniq -c \
    | awk '{ print $1 ":" $2 }')
expected_qualified_successor_policy_references='2:public._sqlx_migrations
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
    "$qualified_successor_policy_references" \
    "$expected_qualified_successor_policy_references"

successor_role_option_hardening=$(sed -n \
    '/^ALTER ROLE fleet_registry_successor_activation WITH$/,/^    NOVIEWCLUSTERSETTING;$/p' \
    "$successor_policy")
expected_successor_role_option_hardening='ALTER ROLE fleet_registry_successor_activation WITH
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
assert_exact "complete successor v26.2 direct role-option hardening" \
    "$successor_role_option_hardening" \
    "$expected_successor_role_option_hardening"

forbidden_successor_policy_grants=$(sed -E 's/--.*$//' \
    "$successor_policy" \
    | grep -Ein \
        'GRANT[[:space:]]+.*(DELETE|CREATE|DROP|MAINTAIN)|GRANT[[:space:]]+.*ON[[:space:]]+SEQUENCE|GRANT[[:space:]]+SYSTEM' \
        || true)
assert_exact "forbidden successor policy grants" \
    "$forbidden_successor_policy_grants" ''

unsupported_successor_query_in_function_body=$(awk '
    /^DO \$\$/ { in_function_body = 1 }
    in_function_body && ($0 ~ /\[SHOW[[:space:]]/ ||
        $0 ~ /^[[:space:]]*SHOW[[:space:]]/ ||
        $0 ~ /crdb_internal\./ || $0 ~ /information_schema\./) {
        print NR ":" $0
    }
    in_function_body && /^\$\$;$/ { in_function_body = 0 }
' "$successor_policy")
assert_exact "SHOW/virtual-table-free successor policy function bodies" \
    "$unsupported_successor_query_in_function_body" ''

# The reconciliation policy has the same safe-session requirements: it pins
# built-in resolution first, binds itself to fleet_recall, fully qualifies every
# repository relation, and clears the complete v26.2 role-option surface. Keep
# these static gates in the official wrapper so its connected result cannot be
# credited to a weakened policy file.
reconciliation_policy="$repo_root/deploy/cockroach/conflict-reconciliation-role-grants.sql"
policy_first_statement=$(awk '
    /^[[:space:]]*--/ || /^[[:space:]]*$/ { next }
    { print; exit }
' "$reconciliation_policy")
assert_exact "reconciliation policy first statement" \
    "$policy_first_statement" 'SET search_path = pg_catalog, public, pg_temp;'

current_database_preflight=$(grep -F \
    "IF pg_catalog.current_database() <> 'fleet_recall' THEN" \
    "$reconciliation_policy")
assert_exact "fleet_recall current-database preflight" \
    "$current_database_preflight" \
    "    IF pg_catalog.current_database() <> 'fleet_recall' THEN"

unqualified_policy_application_references=$(sed -E 's/--.*$//' \
    "$reconciliation_policy" \
    | grep -En \
        '(FROM|ON TABLE|ON SEQUENCE)[[:space:]]+(_sqlx_migrations|memory_(claims|claim_events|claim_links|conflicts|conflict_members|mutation_receipts|events|conflict_id_seq))([^[:alnum:]_]|$)' \
        || true)
assert_exact "unqualified reconciliation policy application references" \
    "$unqualified_policy_application_references" ''

qualified_policy_application_references=$(sed -E 's/--.*$//' \
    "$reconciliation_policy" \
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

role_option_hardening=$(sed -n \
    '/^ALTER ROLE fleet_conflict_reconciliation WITH$/,/^    NOVIEWCLUSTERSETTING;$/p' \
    "$reconciliation_policy")
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

unsupported_query_in_function_body=$(awk '
    /^DO \$\$/ { in_function_body = 1 }
    in_function_body && ($0 ~ /\[SHOW[[:space:]]/ ||
        $0 ~ /^[[:space:]]*SHOW[[:space:]]/ ||
        $0 ~ /crdb_internal\./ || $0 ~ /information_schema\./) {
        print NR ":" $0
    }
    in_function_body && /^\$\$;$/ { in_function_body = 0 }
' "$reconciliation_policy")
assert_exact "SHOW/virtual-table-free reconciliation policy function bodies" \
    "$unsupported_query_in_function_body" ''

# Helpers whose output is evidence must finish in a standalone assignment.
# Passing a substitution directly to assert_exact can mask a failed helper when
# its expected value is empty, so freeze that source-level fail-closed seam.
masked_evidence_helper_assertions=$(grep -En \
    '^[[:space:]]*"[$][(](audit_other_database_successor_authority|inventory_other_database_public_application_authority|reconciliation_table_fingerprints|successor_table_fingerprints|legacy_registry_fingerprints)[)]"' \
    "$script_dir/registry-activation-cli.sh" || true)
assert_exact "standalone evidence helper assignments" \
    "$masked_evidence_helper_assertions" ''

external_authority_helper_source=$(awk '
    /^(audit_other_database_successor_authority|audit_other_database_target_authority|inventory_other_database_public_application_authority)\(\) \{/ {
        capture = 1
    }
    capture { print }
    capture && /^}$/ { capture = 0 }
' "$script_dir/registry-activation-cli.sh")
unqualified_external_audit_current_database=$(grep -En \
    '(^|[^[:alnum:]_.])current_database[(][)]' \
    <<<"$external_authority_helper_source" || true)
assert_exact "qualified external-audit current_database calls" \
    "$unqualified_external_audit_current_database" ''
qualified_external_audit_current_database_count=$(grep -Eo \
    'pg_catalog[.]current_database[(][)]' \
    <<<"$external_authority_helper_source" | wc -l | tr -d ' ')
assert_exact "complete external-audit current_database qualification" \
    "$qualified_external_audit_current_database_count" '6'

mkdir -p "$artifact_dir"
"$crdb" cert create-ca --certs-dir="$cert_dir" \
    --ca-key="$proof_dir/ca.key" >/dev/null
"$crdb" cert create-node localhost 127.0.0.1 ::1 \
    --certs-dir="$cert_dir" --ca-key="$proof_dir/ca.key" >/dev/null
"$crdb" cert create-client root --certs-dir="$cert_dir" \
    --ca-key="$proof_dir/ca.key" >/dev/null
# Close the signal window between spawning the foreground child and capturing
# $!. Signals are restored immediately after the shell-owned PID is durable.
trap '' INT TERM
"$crdb" start-single-node \
    --certs-dir="$cert_dir" \
    --store="$store_dir" \
    --listen-addr=127.0.0.1:0 \
    --sql-addr=127.0.0.1:0 \
    --http-addr=127.0.0.1:0 \
    --listening-url-file="$url_file" \
    --pid-file="$pid_file" \
    --log-dir="$proof_dir/logs" \
    --logtostderr=NONE >"$proof_dir/server-stdout" 2>"$proof_dir/server-stderr" &
owned_server_pid=$!
server_was_spawned=1
trap 'exit 130' INT
trap 'exit 143' TERM

# The shell owns the foreground server PID even if CockroachDB fails before
# publishing either sidecar. Before any readiness probe, bind that PID to both
# the CockroachDB subcommand and this proof's unique store path. Then require
# the pid-file's one positive numeric row to equal the shell child exactly.
owned_pid_ready=0
for _ in $(seq 1 120); do
    if owned_server_pid_matches "$owned_server_pid"; then
        owned_pid_ready=1
        break
    fi
    if ! kill -0 "$owned_server_pid" >/dev/null 2>&1; then
        break
    fi
    sleep 0.25
done
test "$owned_pid_ready" -eq 1 \
    || fail "CockroachDB shell child did not match the owned subcommand and store"

pid_ready=0
published_server_pid=''
for _ in $(seq 1 120); do
    if test -r "$pid_file" && test -s "$pid_file"; then
        if published_server_pid=$(awk '
            NR == 1 && $0 ~ /^[1-9][0-9]*$/ { pid = $0; next }
            { invalid = 1 }
            END {
                if (NR != 1 || invalid || pid == "") exit 1
                print pid
            }
        ' "$pid_file"); then
            pid_ready=1
            break
        fi
    fi
    sleep 0.25
done
test "$pid_ready" -eq 1 \
    || fail "CockroachDB start did not publish exactly one positive numeric PID"
test "$published_server_pid" = "$owned_server_pid" \
    || fail "CockroachDB pid-file did not match the shell-owned server PID"
server_pid_was_validated=1

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
# then run every connected proof by its discovered exact harness name. Setting
# the URL on every invocation makes an environment-skipped zero-test run
# impossible to report as connected success.
control_live_test=live_stage2_genesis_repository_when_configured
control_live_listing=$(cargo test --locked --test control_log_live -- --list)
require_discovered_test "$control_live_listing" "$control_live_test"
FLEET_RECALL_TEST_DATABASE_URL="$root_url" \
    cargo test --locked --test control_log_live "$control_live_test" \
        -- --exact --nocapture

genesis_live_test=live_genesis_registry_activation_when_configured
genesis_live_listing=$(cargo test --locked --test registry_activation_live -- --list)
require_discovered_test "$genesis_live_listing" "$genesis_live_test"
FLEET_RECALL_TEST_DATABASE_URL="$root_url" \
    cargo test --locked --test registry_activation_live "$genesis_live_test" \
        -- --exact --nocapture

successor_live_test=live_first_successor_activation_when_configured
successor_live_listing=$(cargo test --locked --test successor_activation_live -- --list)
require_discovered_test "$successor_live_listing" "$successor_live_test"
FLEET_RECALL_TEST_DATABASE_URL="$root_url" \
    cargo test --locked --test successor_activation_live "$successor_live_test" \
        -- --exact --nocapture

current_retry_live_test=ledger::cockroach::tests::live_current_projection_whole_unit_retry_when_configured
current_snapshot_live_test=ledger::cockroach::tests::live_current_projection_snapshot_race_when_configured
conflict_live_test=ledger::cockroach::tests::live_conflict_polarity_matrix_when_configured
reconciliation_live_test=ledger::reconciliation::tests::live_reconciliation_is_inert_without_its_exact_database_url
online_index_live_test=store::cockroach::tests::live_online_index_migrations_recover_and_reject_drift_when_configured
rollback_live_test=store::cockroach::tests::live_transactional_migration_rolls_back_ddl_on_history_conflict_when_configured
library_live_listing=$(cargo test --locked --lib -- --list)
for exact_test in \
    "$current_retry_live_test" \
    "$current_snapshot_live_test" \
    "$conflict_live_test" \
    "$reconciliation_live_test" \
    "$online_index_live_test" \
    "$rollback_live_test"
do
    require_discovered_test "$library_live_listing" "$exact_test"
done

for exact_test in \
    "$current_retry_live_test" \
    "$current_snapshot_live_test" \
    "$conflict_live_test" \
    "$online_index_live_test" \
    "$rollback_live_test"
do
    FLEET_RECALL_TEST_DATABASE_URL="$root_url" \
        cargo test --locked --lib "$exact_test" -- --exact --nocapture
done
FLEET_RECONCILIATION_TEST_DATABASE_URL="$root_url" \
    cargo test --locked --lib "$reconciliation_live_test" \
        -- --exact --nocapture

# Freeze the authoritative schema independently of the two Stage-2/Stage-3
# command preflights. The database must have exactly the successful embedded
# migration chain through 17 and all three successor authority tables.
assert_root_scalar "exact successful migration prefix 1 through 17" '
    SELECT CASE WHEN count(*) = 17
                          AND min(version) = 1
                          AND max(version) = 17
                          AND COALESCE(bool_and(success), false)
                     THEN '\''ready'\'' ELSE '\''not_ready'\'' END
    FROM _sqlx_migrations' 'ready'
assert_root_scalar "exact current successor authority table set" '
    SELECT string_agg(table_name, '\''|'\'' ORDER BY table_name)
    FROM information_schema.tables
    WHERE table_schema = '\''public'\''
      AND table_type = '\''BASE TABLE'\''
      AND table_name IN (
          '\''memory_registry_transitions'\'',
          '\''memory_registry_genesis_bridge_consumptions'\'',
          '\''memory_registry_current_heads_v2'\''
      )' 'memory_registry_current_heads_v2|memory_registry_genesis_bridge_consumptions|memory_registry_transitions'
assert_root_scalar "exact current release index set" '
    SELECT string_agg(
        tablename || '\'':'\'' || indexname,
        '\''|'\'' ORDER BY tablename, indexname
    )
    FROM pg_catalog.pg_indexes
    WHERE schemaname = '\''public'\''
      AND indexname IN (
          '\''memory_claim_events_transition_provenance_idx'\'',
          '\''memory_conflicts_scope_detector_state_recency_idx'\'',
          '\''memory_conflicts_scope_key_detector_unique_idx'\'',
          '\''memory_registry_heads_genesis_root_idx'\'',
          '\''memory_registry_activations_genesis_root_idx'\''
      )' 'memory_claim_events:memory_claim_events_transition_provenance_idx|memory_conflicts:memory_conflicts_scope_detector_state_recency_idx|memory_conflicts:memory_conflicts_scope_key_detector_unique_idx|memory_registry_activations:memory_registry_activations_genesis_root_idx|memory_registry_heads:memory_registry_heads_genesis_root_idx'
assert_root_scalar "retired conflict uniqueness index is absent" '
    SELECT count(*)::STRING
    FROM pg_catalog.pg_indexes
    WHERE schemaname = '\''public'\''
      AND tablename = '\''memory_conflicts'\''
      AND indexname = '\''memory_conflicts_tenant_id_project_claim_key_key'\''' '0'

# Migrations 10, 11, and 15 through 17 are intentionally resumable online
# index transitions. Replaying their exact bytes must accept the existing exact
# indexes without changing SQLx history or silently accepting catalog drift.
for migration_path in \
    "$repo_root/migrations/0010_registry_genesis_head_root_index.sql" \
    "$repo_root/migrations/0011_registry_genesis_activation_root_index.sql" \
    "$repo_root/migrations/0015_conflict_detector_uniqueness.sql" \
    "$repo_root/migrations/0016_claim_transition_provenance_index.sql" \
    "$repo_root/migrations/0017_conflict_detector_projection_index.sql"
do
    "$crdb" sql --url="$root_url" < "$migration_path" >/dev/null
done
assert_root_scalar "migration history after exact index replay" \
    'SELECT count(*)::STRING FROM _sqlx_migrations' '17'

# Demonstrate why MAX(successful version) is not a readiness check: version 17
# remains successful while a failed version 12 makes the complete-prefix gate
# false. Restore the row before exercising the v3/v9-compatible private CLIs.
"$crdb" sql --url="$root_url" \
    --execute='UPDATE _sqlx_migrations SET success = false WHERE version = 12' >/dev/null
assert_root_scalar "later success remains visible during failed migration 12" \
    'SELECT max(version)::STRING FROM _sqlx_migrations WHERE success' '17'
assert_root_scalar "failed migration 12 is not masked by version 17" '
    SELECT CASE WHEN count(*) = 17
                          AND min(version) = 1
                          AND max(version) = 17
                          AND COALESCE(bool_and(success), false)
                     THEN '\''ready'\'' ELSE '\''not_ready'\'' END
    FROM _sqlx_migrations' 'not_ready'
"$crdb" sql --url="$root_url" \
    --execute='UPDATE _sqlx_migrations SET success = true WHERE version = 12' >/dev/null
assert_root_scalar "restored successful migration prefix 1 through 17" '
    SELECT CASE WHEN count(*) = 17 AND COALESCE(bool_and(success), false)
                     THEN '\''ready'\'' ELSE '\''not_ready'\'' END
    FROM _sqlx_migrations
    WHERE version BETWEEN 1 AND 17' 'ready'

"$crdb" sql --url="$root_url" \
    < "$repo_root/deploy/cockroach/control-role-grants.sql" >/dev/null
"$crdb" sql --url="$root_url" \
    < "$repo_root/deploy/cockroach/registry-activation-role-grants.sql" >/dev/null
"$crdb" sql --url="$root_url" \
    < "$repo_root/deploy/cockroach/successor-schema-quarantine-grants.sql" >/dev/null

# Login identities are distinct from the non-login logical roles. Create every
# proof user before the default-privilege cleanup so role creation cannot
# silently reintroduce a PUBLIC routine default after the pre-policy audit.
"$crdb" sql --url="$root_url" --execute="
    CREATE USER proof_control_cli WITH PASSWORD '$control_password';
    CREATE USER proof_activation_cli WITH PASSWORD '$activation_password';
    CREATE USER proof_runtime_cli WITH PASSWORD '$runtime_password';
    CREATE USER proof_successor WITH PASSWORD '$successor_password';
    CREATE USER proof_reconciliation_cli WITH PASSWORD '$reconciliation_password';
" >/dev/null

# CockroachDB v26.2 seeds database-level PUBLIC EXECUTE defaults for routines
# under every role, and role-specific cleanup requires membership in the
# grantor. Root and admin are cleaned directly; temporarily inherit the eight
# custom grantors while removing all ten named-grantor rows, then attempt the
# ALL-ROLES revoke whose exact intrinsic row v26.2.3 synthesizes back. Revoke and
# audit those edges before the reconciliation policy creates its target role.
# Its one creator-scoped PUBLIC row is harmless because the target cannot CREATE
# or own.
"$crdb" sql --url="$root_url" --execute='
    GRANT
        fleet_runtime,
        fleet_control_bootstrap,
        fleet_registry_activation,
        proof_control_cli,
        proof_activation_cli,
        proof_runtime_cli,
        proof_successor,
        proof_reconciliation_cli
    TO root;
    ALTER DEFAULT PRIVILEGES FOR ROLE
        root,
        admin,
        fleet_runtime,
        fleet_control_bootstrap,
        fleet_registry_activation,
        proof_control_cli,
        proof_activation_cli,
        proof_runtime_cli,
        proof_successor,
        proof_reconciliation_cli
        REVOKE EXECUTE ON ROUTINES FROM public;
    ALTER DEFAULT PRIVILEGES FOR ALL ROLES
        REVOKE EXECUTE ON ROUTINES FROM public;
    REVOKE
        fleet_runtime,
        fleet_control_bootstrap,
        fleet_registry_activation,
        proof_control_cli,
        proof_activation_cli,
        proof_runtime_cli,
        proof_successor,
        proof_reconciliation_cli
    FROM root;
' >/dev/null
assert_root_scalar "removed temporary default-privilege cleanup role edges" \
    "SELECT count(*)::STRING
     FROM [SHOW GRANTS ON ROLE]
     WHERE member = 'root'
       AND role_name IN (
           'fleet_runtime',
           'fleet_control_bootstrap',
           'fleet_registry_activation',
           'proof_control_cli',
           'proof_activation_cli',
           'proof_runtime_cli',
           'proof_successor',
           'proof_reconciliation_cli'
       )" '0'
assert_public_routine_defaults "before one-shot policies" \
    'role=ALL,true,routines,public,EXECUTE,false'

# Neither one-shot target exists during bootstrap. Prove that the successor
# policy's first persistent gate rejects the wrong database before it can create
# its role or mutate an object grant. Then inventory inherited PUBLIC authority
# in every other database and explicitly remove the two stock application-
# schema CREATE rows before either successful policy application.
assert_root_scalar "successor external-audit bootstrap target absence" \
    "SELECT count(*)::STRING FROM [SHOW USERS]
     WHERE username = 'fleet_registry_successor_activation'" '0'
if wrong_database_successor_policy=$(
    apply_successor_policy_in_database defaultdb 2>&1
); then
    fail "wrong database unexpectedly admitted the successor policy"
fi
grep -Fq 'successor activation policy must run in fleet_recall' \
    <<<"$wrong_database_successor_policy" \
    || fail "wrong-database successor policy did not retain its closed error"
assert_root_scalar "wrong-database successor target creation" \
    "SELECT count(*)::STRING FROM [SHOW USERS]
     WHERE username = 'fleet_registry_successor_activation'" '0'

# The reconciliation target must also be absent during bootstrap. Before the
# first apply, inventory
# inherited PUBLIC authority in every other database and explicitly remove the
# two stock application-schema CREATE rows. Ordinary CONNECT, TEMPORARY,
# public-schema USAGE, and the engine's system/virtual fallbacks remain truthful
# ambient cluster state and are deliberately not claimed as confinement.
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

# Create and normalize the successor role only after the complete external
# PUBLIC inventory is clean. Reapply for idempotence, then prove a failed
# temporary migration table and temporary namesakes cannot redirect its prefix
# gate or any grant away from fleet_recall.public.
apply_successor_policy >/dev/null
apply_successor_policy >/dev/null
assert_root_scalar "clean successor target creation" \
    "SELECT count(*)::STRING FROM [SHOW USERS]
     WHERE username = 'fleet_registry_successor_activation'
       AND options::STRING = '{NOLOGIN}'" '1'
assert_root_scalar "initial successor target remains memberless" \
    "SELECT count(*)::STRING FROM [SHOW GRANTS ON ROLE]
     WHERE role_name = 'fleet_registry_successor_activation'
        OR member = 'fleet_registry_successor_activation'" '0'
post_create_outside_successor_target_authority=$(
    audit_other_database_successor_authority
)
assert_exact "post-create external successor target-authority audit" \
    "$post_create_outside_successor_target_authority" ''
apply_successor_policy_with_temp_shadows >/dev/null
assert_root_scalar "successor temp-shadow public migration-history grant" \
    "SELECT count(*)::STRING
     FROM [SHOW GRANTS ON TABLE public._sqlx_migrations]
     WHERE grantee = 'fleet_registry_successor_activation'
       AND privilege_type = 'SELECT'
       AND NOT is_grantable" '1'

# Prove the successor external audit detects direct grants and ownership while
# the independent PUBLIC inventory exposes inherited application authority.
# Both helpers are read-only: the adversarial rows survive until the operator
# explicitly cleans them, after which a normal policy reapply succeeds.
"$crdb" sql --url="$root_url" \
    --execute='CREATE DATABASE proof_successor_other_database' >/dev/null
root_sql_in_database proof_successor_other_database '
CREATE TABLE proof_successor_other_ledger (id INT8 PRIMARY KEY);
CREATE TABLE proof_successor_other_owned (id INT8 PRIMARY KEY);
GRANT SELECT ON TABLE proof_successor_other_ledger
    TO fleet_registry_successor_activation, public;
GRANT CREATE ON SCHEMA public TO fleet_registry_successor_activation;
ALTER TABLE proof_successor_other_owned
    OWNER TO fleet_registry_successor_activation;
REVOKE CREATE ON SCHEMA public FROM fleet_registry_successor_activation;
' >/dev/null
outside_successor_target_authority=$(audit_other_database_successor_authority)
assert_exact "external successor target-authority audit" \
    "$outside_successor_target_authority" \
    'proof_successor_other_database:grant:table:public:proof_successor_other_ledger:SELECT:not_grantable
proof_successor_other_database:grant:table:public:proof_successor_other_owned:ALL:grantable
proof_successor_other_database:relation_owner:public:proof_successor_other_owned
proof_successor_other_database:type_owner:public:proof_successor_other_owned'
outside_successor_public_authority=$(
    inventory_other_database_public_application_authority
)
assert_exact "external successor PUBLIC application-authority inventory" \
    "$outside_successor_public_authority" \
    'proof_successor_other_database:schema:public::CREATE:not_grantable
proof_successor_other_database:table:public:proof_successor_other_ledger:SELECT:not_grantable'
successor_external_grants_after_audit=$(
    root_sql_in_database proof_successor_other_database "
        SELECT grantee || ':' || privilege_type
        FROM [SHOW GRANTS ON TABLE proof_successor_other_ledger]
        WHERE grantee IN ('fleet_registry_successor_activation', 'public')
          AND privilege_type = 'SELECT'
        ORDER BY grantee" | tail -n +2
)
assert_exact "read-only successor external grant audit preservation" \
    "$successor_external_grants_after_audit" \
    'fleet_registry_successor_activation:SELECT
public:SELECT'
root_sql_in_database proof_successor_other_database '
ALTER TABLE proof_successor_other_owned OWNER TO root;
REVOKE SELECT ON TABLE proof_successor_other_ledger
    FROM fleet_registry_successor_activation, public;
REVOKE CREATE ON SCHEMA public FROM public;
' >/dev/null
clean_outside_successor_target_authority=$(
    audit_other_database_successor_authority
)
assert_exact "clean external successor target precondition" \
    "$clean_outside_successor_target_authority" ''
clean_outside_successor_public_authority=$(
    inventory_other_database_public_application_authority
)
assert_exact "clean external successor PUBLIC precondition" \
    "$clean_outside_successor_public_authority" ''
apply_successor_policy >/dev/null

# Freeze the complete successor current-object surface before any membership:
# sixteen non-grantable table rows, zero sequences, sole database CONNECT, sole
# public-schema USAGE, no PUBLIC application object or system authority, and no
# lingering grant on the three successor tables for any older application role.
successor_object_grants=$(root_scalar "
    SELECT schema_name || ':' || object_type || ':' || object_name || ':' ||
           privilege_type || ':' ||
           CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END
    FROM [SHOW GRANTS FOR fleet_registry_successor_activation]
    WHERE grantee = 'fleet_registry_successor_activation'
      AND database_name = 'fleet_recall'
      AND object_type IN ('table', 'sequence')
    ORDER BY schema_name, object_type, object_name, privilege_type")
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
assert_root_scalar "successor zero sequence grants" \
    "SELECT count(*)::STRING
     FROM [SHOW GRANTS FOR fleet_registry_successor_activation]
     WHERE grantee = 'fleet_registry_successor_activation'
       AND object_type = 'sequence'" '0'
assert_root_scalar "successor database grants" \
    "SELECT database_name || ':' || grantee || ':' || privilege_type || ':' ||
            CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END
     FROM [SHOW GRANTS ON DATABASE fleet_recall]
     WHERE grantee IN ('public', 'fleet_registry_successor_activation')
     ORDER BY grantee, privilege_type" \
    'fleet_recall:fleet_registry_successor_activation:CONNECT:not_grantable'
assert_root_scalar "successor schema grants" \
    "SELECT schema_name || ':' || grantee || ':' || privilege_type || ':' ||
            CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END
     FROM [SHOW GRANTS ON SCHEMA public]
     WHERE grantee IN ('public', 'fleet_registry_successor_activation')
     ORDER BY grantee, privilege_type" \
    'public:fleet_registry_successor_activation:USAGE:not_grantable'
assert_root_scalar "successor PUBLIC application table/sequence grants" \
    "SELECT count(*)::STRING FROM [SHOW GRANTS FOR public]
     WHERE grantee = 'public'
       AND database_name = 'fleet_recall'
       AND schema_name = 'public'
       AND object_type IN ('table', 'sequence')" '0'
assert_root_scalar "prior roles denied successor authority tables" \
    "SELECT count(*)::STRING
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
       )" '0'
assert_root_scalar "successor role and inherited PUBLIC system grants" \
    "SELECT count(*)::STRING FROM [SHOW SYSTEM GRANTS]
     WHERE grantee IN ('fleet_registry_successor_activation', 'public')" '0'
assert_root_scalar "successor and prior logical role options" \
    "SELECT username || ':' || options::STRING
     FROM [SHOW USERS]
     WHERE username IN (
         'fleet_runtime',
         'fleet_control_bootstrap',
         'fleet_registry_activation',
         'fleet_registry_successor_activation'
     )
     ORDER BY username" \
    'fleet_control_bootstrap:{NOLOGIN}
fleet_registry_activation:{NOLOGIN}
fleet_registry_successor_activation:{NOLOGIN}
fleet_runtime:{NOLOGIN}'
assert_root_scalar "local successor ownership" \
    "SELECT count(*)::STRING
     FROM (
         SELECT 1
         FROM pg_catalog.pg_database AS database_object
         JOIN pg_catalog.pg_roles AS owner_role
           ON owner_role.oid = database_object.datdba
         WHERE database_object.datname = 'fleet_recall'
           AND owner_role.rolname = 'fleet_registry_successor_activation'
         UNION ALL
         SELECT 1 FROM pg_catalog.pg_namespace AS object
         JOIN pg_catalog.pg_roles AS owner_role ON owner_role.oid = object.nspowner
         WHERE owner_role.rolname = 'fleet_registry_successor_activation'
         UNION ALL
         SELECT 1 FROM pg_catalog.pg_class AS object
         JOIN pg_catalog.pg_roles AS owner_role ON owner_role.oid = object.relowner
         WHERE object.relkind IN ('r', 'S', 'v', 'm', 'p')
           AND owner_role.rolname = 'fleet_registry_successor_activation'
         UNION ALL
         SELECT 1 FROM pg_catalog.pg_proc AS object
         JOIN pg_catalog.pg_roles AS owner_role ON owner_role.oid = object.proowner
         WHERE owner_role.rolname = 'fleet_registry_successor_activation'
         UNION ALL
         SELECT 1 FROM pg_catalog.pg_type AS object
         JOIN pg_catalog.pg_roles AS owner_role ON owner_role.oid = object.typowner
         WHERE owner_role.rolname = 'fleet_registry_successor_activation'
     ) AS owned_object" '0'

# A target role created by v26.2.3 receives one creator-scoped non-grantable
# PUBLIC routine default. Audit its exact shape, then remove it explicitly so
# the later reconciliation policy sees its own documented clean baseline.
assert_root_scalar "successor creator-scoped PUBLIC routine default" \
    "SELECT role || ':' || object_type || ':' || grantee || ':' ||
            privilege_type || ':' ||
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
     WHERE role = 'fleet_registry_successor_activation'
       AND NOT for_all_roles
       AND object_type = 'routines'
       AND grantee = 'public'
       AND privilege_type = 'EXECUTE'
       AND NOT is_grantable" \
    'fleet_registry_successor_activation:routines:public:EXECUTE:not_grantable'
assert_root_scalar "non-intrinsic successor/PUBLIC future-object defaults" \
    "SELECT COALESCE(role, 'ALL') || ':' || object_type || ':' || grantee || ':' ||
            privilege_type || ':' ||
            CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END
     FROM (
         SELECT role, for_all_roles, object_type, grantee, privilege_type,
                is_grantable
         FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE public]
         UNION
         SELECT role, for_all_roles, object_type, grantee, privilege_type,
                is_grantable
         FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE public IN SCHEMA public]
         UNION
         SELECT role, for_all_roles, object_type, grantee, privilege_type,
                is_grantable
         FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE fleet_registry_successor_activation]
         UNION
         SELECT role, for_all_roles, object_type, grantee, privilege_type,
                is_grantable
         FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE fleet_registry_successor_activation
               IN SCHEMA public]
     ) AS default_privilege
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
     ORDER BY role, object_type, grantee, privilege_type" ''
"$crdb" sql --url="$root_url" --execute='
    GRANT fleet_registry_successor_activation TO root;
    ALTER DEFAULT PRIVILEGES FOR ROLE fleet_registry_successor_activation
        REVOKE EXECUTE ON ROUTINES FROM public;
    REVOKE fleet_registry_successor_activation FROM root;
' >/dev/null
assert_root_scalar "successor default-cleanup membership removal" \
    "SELECT count(*)::STRING FROM [SHOW GRANTS ON ROLE]
     WHERE role_name = 'fleet_registry_successor_activation'
        OR member = 'fleet_registry_successor_activation'" '0'
assert_public_routine_defaults "before conflict reconciliation policy" \
    'role=ALL,true,routines,public,EXECUTE,false'

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

# Prove the cross-database audit detects both direct grants and ownership, while
# the separate PUBLIC inventory detects inherited application authority. Both
# helpers are read-only: verify the adversarial rows survive the audit, then
# clean them explicitly before any reapply or member use.
"$crdb" sql --url="$root_url" \
    --execute='CREATE DATABASE proof_other_database' >/dev/null
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
assert_exact "read-only external grant audit preservation" \
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

# Reapply once with temporary shadows, audit every external database again, and
# perform the final normal reapply. No reconciliation membership exists during
# this audit/reapply interval.
apply_reconciliation_policy_with_temp_shadows >/dev/null
assert_root_scalar "temp-shadow public migration-history grant" \
    "SELECT count(*)::STRING
     FROM [SHOW GRANTS ON TABLE public._sqlx_migrations]
     WHERE grantee = 'fleet_conflict_reconciliation'
       AND privilege_type = 'SELECT'
       AND NOT is_grantable" '1'
final_outside_target_authority=$(audit_other_database_target_authority)
assert_exact "final external target-authority precondition" \
    "$final_outside_target_authority" ''
final_outside_public_application_authority=$(
    inventory_other_database_public_application_authority
)
assert_exact "final external PUBLIC application inventory" \
    "$final_outside_public_application_authority" ''
apply_reconciliation_policy >/dev/null

assert_root_scalar "conflict policy current database" \
    'SELECT pg_catalog.current_database()' 'fleet_recall'
assert_public_routine_defaults "after conflict reconciliation policy" \
    'role=ALL,true,routines,public,EXECUTE,false|role=fleet_conflict_reconciliation,false,routines,public,EXECUTE,false'
assert_root_scalar "non-intrinsic reconciliation/PUBLIC future-object defaults" \
    "SELECT COALESCE(role, 'ALL') || ':' || object_type || ':' || grantee || ':' ||
            privilege_type || ':' ||
            CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END
     FROM (
         SELECT role, for_all_roles, object_type, grantee, privilege_type,
                is_grantable
         FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE public]
         UNION
         SELECT role, for_all_roles, object_type, grantee, privilege_type,
                is_grantable
         FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE public IN SCHEMA public]
         UNION
         SELECT role, for_all_roles, object_type, grantee, privilege_type,
                is_grantable
         FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE fleet_conflict_reconciliation]
         UNION
         SELECT role, for_all_roles, object_type, grantee, privilege_type,
                is_grantable
         FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE fleet_conflict_reconciliation
               IN SCHEMA public]
     ) AS default_privilege
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
     ORDER BY role, object_type, grantee, privilege_type" ''

# Freeze the complete six-table direct repository surface plus the one
# read-only receipt-FK parent before provisioning the one-shot membership:
# seventeen table/sequence rows, sole database CONNECT, sole schema USAGE, no
# inherited PUBLIC application grants, and no target/PUBLIC system authority.
assert_root_scalar "reconciliation table/sequence grant row count" \
    "SELECT count(*)::STRING
     FROM [SHOW GRANTS FOR fleet_conflict_reconciliation]
     WHERE grantee = 'fleet_conflict_reconciliation'
       AND database_name = 'fleet_recall'
       AND object_type IN ('table', 'sequence')" '17'
assert_root_scalar "reconciliation full current table/sequence grants" \
    "SELECT schema_name || ':' || object_type || ':' || object_name || ':' ||
            privilege_type || ':' ||
            CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END
     FROM [SHOW GRANTS FOR fleet_conflict_reconciliation]
     WHERE grantee = 'fleet_conflict_reconciliation'
       AND database_name = 'fleet_recall'
       AND object_type IN ('table', 'sequence')
     ORDER BY schema_name, object_type, object_name, privilege_type" \
    'public:sequence:memory_conflict_id_seq:USAGE:not_grantable
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
assert_root_scalar "reconciliation database grants" \
    "SELECT database_name || ':' || grantee || ':' || privilege_type || ':' ||
            CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END
     FROM [SHOW GRANTS ON DATABASE fleet_recall]
     WHERE grantee IN ('public', 'fleet_conflict_reconciliation')
     ORDER BY grantee, privilege_type" \
    'fleet_recall:fleet_conflict_reconciliation:CONNECT:not_grantable'
assert_root_scalar "reconciliation schema grants" \
    "SELECT schema_name || ':' || grantee || ':' || privilege_type || ':' ||
            CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END
     FROM [SHOW GRANTS ON SCHEMA public]
     WHERE grantee IN ('public', 'fleet_conflict_reconciliation')
     ORDER BY grantee, privilege_type" \
    'public:fleet_conflict_reconciliation:USAGE:not_grantable'
assert_root_scalar "PUBLIC application table/sequence grants" \
    "SELECT count(*)::STRING
     FROM [SHOW GRANTS FOR public]
     WHERE grantee = 'public'
       AND database_name = 'fleet_recall'
       AND schema_name = 'public'
       AND object_type IN ('table', 'sequence')" '0'
assert_root_scalar "reconciliation and inherited PUBLIC system grants" \
    "SELECT count(*)::STRING
     FROM [SHOW SYSTEM GRANTS]
     WHERE grantee IN ('fleet_conflict_reconciliation', 'public')" '0'

# The exact v26.2.3 virtual-schema fallback is non-grantable and cannot be used
# to create or shadow application objects. Freezing its grouped shapes/counts
# distinguishes that engine baseline from an unexpected PUBLIC grant.
assert_root_scalar "v26.2.3 PUBLIC virtual-schema fallback grants" \
    "SELECT schema_name || ':' || object_type || ':' || privilege_type || ':' ||
            CASE WHEN is_grantable THEN 'grantable' ELSE 'not_grantable' END || ':' ||
            count(*)::STRING
     FROM [SHOW GRANTS FOR public]
     WHERE grantee = 'public'
       AND database_name = 'fleet_recall'
       AND schema_name IN (
           'crdb_internal', 'information_schema', 'pg_catalog', 'pg_extension'
       )
     GROUP BY schema_name, object_type, privilege_type, is_grantable
     ORDER BY schema_name, object_type, privilege_type, is_grantable" \
    'crdb_internal:schema:USAGE:not_grantable:1
crdb_internal:table:SELECT:not_grantable:116
information_schema:schema:USAGE:not_grantable:1
information_schema:table:SELECT:not_grantable:89
pg_catalog:schema:USAGE:not_grantable:1
pg_catalog:table:SELECT:not_grantable:129
pg_catalog:type:USAGE:not_grantable:98
pg_extension:schema:USAGE:not_grantable:1
pg_extension:table:SELECT:not_grantable:3'

assert_root_scalar "local reconciliation ownership" \
    "SELECT count(*)::STRING
     FROM (
         SELECT 1
         FROM pg_catalog.pg_database AS database_object
         JOIN pg_catalog.pg_roles AS owner_role
           ON owner_role.oid = database_object.datdba
         WHERE database_object.datname = 'fleet_recall'
           AND owner_role.rolname = 'fleet_conflict_reconciliation'
         UNION ALL
         SELECT 1 FROM pg_catalog.pg_namespace AS object
         JOIN pg_catalog.pg_roles AS owner_role ON owner_role.oid = object.nspowner
         WHERE owner_role.rolname = 'fleet_conflict_reconciliation'
         UNION ALL
         SELECT 1 FROM pg_catalog.pg_class AS object
         JOIN pg_catalog.pg_roles AS owner_role ON owner_role.oid = object.relowner
         WHERE object.relkind IN ('r', 'S', 'v', 'm', 'p')
           AND owner_role.rolname = 'fleet_conflict_reconciliation'
         UNION ALL
         SELECT 1 FROM pg_catalog.pg_proc AS object
         JOIN pg_catalog.pg_roles AS owner_role ON owner_role.oid = object.proowner
         WHERE owner_role.rolname = 'fleet_conflict_reconciliation'
         UNION ALL
         SELECT 1 FROM pg_catalog.pg_type AS object
         JOIN pg_catalog.pg_roles AS owner_role ON owner_role.oid = object.typowner
         WHERE owner_role.rolname = 'fleet_conflict_reconciliation'
     ) AS owned_object" '0'
assert_root_scalar "pre-membership reconciliation role edges" \
    "SELECT count(*)::STRING FROM [SHOW GRANTS ON ROLE]
     WHERE role_name = 'fleet_conflict_reconciliation'
        OR member = 'fleet_conflict_reconciliation'" '0'

# Provision the three pre-existing CLI memberships. Keep the reconciliation
# login outside its logical role until an immediate pre-use external audit and
# policy reapply later in this script. No private credential is the
# root/migrator or another application's serving credential.
"$crdb" sql --url="$root_url" --execute="
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
successor_url="postgresql://proof_successor:${successor_password}@${host_port}/fleet_recall?sslmode=verify-full&sslrootcert=${ca_path}"
reconciliation_url="postgresql://proof_reconciliation_cli:${reconciliation_password}@${host_port}/fleet_recall?sslmode=verify-full&sslrootcert=${ca_path}"

cargo build --locked \
    --bin ostk-control-bootstrap \
    --bin ostk-registry-activate \
    --bin ostk-registry-successor-activate \
    --bin ostk-conflict-reconcile >/dev/null
successor_binary="$repo_root/target/debug/ostk-registry-successor-activate"
test -x "$successor_binary" \
    || fail "locked build did not produce the successor activation CLI"
successor_emitter_test_name='tests::emit_dynamic_successor_fixture_for_connected_proof'
successor_emitter_listing=$(cargo test --locked \
    --bin ostk-registry-successor-activate -- --list)
successor_emitter_discovery=$(grep -Fx \
    "$successor_emitter_test_name: test" \
    <<<"$successor_emitter_listing" || true)
assert_exact "exact successor fixture emitter test discovery" \
    "$successor_emitter_discovery" "$successor_emitter_test_name: test"
successor_emitter_build=$(cargo test --locked \
    --bin ostk-registry-successor-activate --no-run --message-format=json)
successor_emitter_test_binary=$(jq -rsc \
    --arg target_name 'ostk-registry-successor-activate' '
    [
        .[]
        | select(
            .reason == "compiler-artifact"
            and .target.name == $target_name
            and .target.kind == ["bin"]
            and .profile.test == true
            and (.executable | type) == "string"
        )
        | .executable
    ]
    | if length == 1 then .[0] else empty end
' <<<"$successor_emitter_build")
test -n "$successor_emitter_test_binary" \
    || fail "locked successor emitter build did not expose exactly one test executable"
successor_emitter_test_binary_dir=$(CDPATH='' cd -- \
    "$(dirname -- "$successor_emitter_test_binary")" && pwd)
successor_emitter_test_binary="$successor_emitter_test_binary_dir/$(
    basename -- "$successor_emitter_test_binary"
)"
test -x "$successor_emitter_test_binary" \
    || fail "locked successor emitter test executable is unavailable"
reconciliation_binary="$repo_root/target/debug/ostk-conflict-reconcile"
test -x "$reconciliation_binary" \
    || fail "locked build did not produce the conflict reconciliation CLI"

bootstrap_receipt="$repo_root/contracts/dynamic-memory/v1/bootstrap-receipt.jsonl"
genesis_package="$repo_root/contracts/dynamic-memory/v1/genesis-registry-package.jsonl"
registry_test_result="$repo_root/contracts/dynamic-memory/v1/genesis-activation/registry-test-result.jsonl"
frozen_statement="$repo_root/contracts/dynamic-memory/v1/genesis-activation/activation-statement.jsonl"
frozen_approvals="$repo_root/contracts/dynamic-memory/v1/genesis-activation/activation-approval-set.jsonl"
successor_genesis_test_result="$registry_test_result"
successor_target_package="$repo_root/contracts/dynamic-memory/v2/stage4-successor/registry-package.jsonl"
successor_target_test_result="$repo_root/contracts/dynamic-memory/v2/successor-activation/registry-test-result.jsonl"
successor_bridge="$repo_root/contracts/dynamic-memory/v2/successor-policy/genesis-successor-key-bridge-v1.jsonl"
successor_statement="$repo_root/contracts/dynamic-memory/v2/successor-activation/activation-statement.jsonl"
successor_approvals="$repo_root/contracts/dynamic-memory/v2/successor-activation/activation-approval-set.jsonl"
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
successor_target_test_result_digest='e6783b2a018957a5861fe4e0670f55613d1ace35e381a6a9f5190ea9d7fbff8d'
successor_target_runner_artifact_digest='a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1'
successor_target_runner_configuration_digest='a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2'
successor_bridge_digest='e15309eba5118e21996a7cee6b3780c1a237982bdf4f22460bca4da189ef6592'
successor_target_package_digest='16f98d5df93b74dab5b2188274cbd1da21d089ff7a64cd8fc29679946e7fe2c9'
successor_target_policy_digest='5611a4fea75d0a8132395bf6e3040ce97638a3447e290f5cabc183c1bb9faa6c'
reconciliation_tenant_id='0198a849-f6ae-7d61-9800-0000000000c1'
reconciliation_project='private-conflict-reconciliation-cli-proof'
reconciliation_claim_key='fleet-store::official-tls-reconciliation-open'
reconciliation_left_claim_id='8000000000000101'
reconciliation_right_claim_id='8000000000000102'
reconciliation_compatible_claim_id='8000000000000103'
reconciliation_legacy_conflict_id='8000000000000201'
reconciliation_idempotency_key='official-tls-reconcile-8000000000000201-r7-v1'

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

run_successor() {
    local operation=$1
    local database_url=${PROOF_SUCCESSOR_DATABASE_URL:-$successor_url}
    local bridge=${PROOF_SUCCESSOR_BRIDGE:-$successor_bridge}
    local bridge_digest=${PROOF_SUCCESSOR_BRIDGE_DIGEST:-$successor_bridge_digest}
    local statement=${PROOF_SUCCESSOR_STATEMENT:-$successor_statement}
    local approvals=${PROOF_SUCCESSOR_APPROVAL_SET:-$successor_approvals}
    env -i \
        FLEET_RECALL_SUCCESSOR_DATABASE_URL="$database_url" \
        FLEET_RECALL_SUCCESSOR_TENANT_ID="$tenant_id" \
        FLEET_RECALL_SUCCESSOR_PROJECT="$physical_project" \
        FLEET_RECALL_SUCCESSOR_TENANT_NAMESPACE='tenant.fixture' \
        FLEET_RECALL_SUCCESSOR_PROJECT_NAMESPACE='project.fixture' \
        FLEET_RECALL_SUCCESSOR_BOOTSTRAP_RECEIPT_DIGEST="$receipt_digest" \
        FLEET_RECALL_SUCCESSOR_GENESIS_TEST_RESULT_DIGEST="$test_result_digest" \
        FLEET_RECALL_SUCCESSOR_GENESIS_TEST_RUNNER_ARTIFACT_DIGEST="$runner_artifact_digest" \
        FLEET_RECALL_SUCCESSOR_GENESIS_TEST_RUNNER_CONFIGURATION_DIGEST="$runner_configuration_digest" \
        FLEET_RECALL_SUCCESSOR_TARGET_TEST_RESULT_DIGEST="$successor_target_test_result_digest" \
        FLEET_RECALL_SUCCESSOR_TARGET_TEST_RUNNER_ARTIFACT_DIGEST="$successor_target_runner_artifact_digest" \
        FLEET_RECALL_SUCCESSOR_TARGET_TEST_RUNNER_CONFIGURATION_DIGEST="$successor_target_runner_configuration_digest" \
        FLEET_RECALL_SUCCESSOR_GENESIS_KEY_BRIDGE_DIGEST="$bridge_digest" \
        FLEET_RECALL_SUCCESSOR_GENESIS_PROPOSER_PRINCIPAL_ID='principal.operator' \
        FLEET_RECALL_SUCCESSOR_GENESIS_PACKAGE_AUTHOR_PRINCIPAL_ID='principal.author' \
        FLEET_RECALL_SUCCESSOR_PROPOSER_PRINCIPAL_ID='principal.proposer' \
        FLEET_RECALL_SUCCESSOR_PACKAGE_AUTHOR_PRINCIPAL_ID='principal.author' \
        "$successor_binary" "$operation" \
            --bootstrap-receipt "$bootstrap_receipt" \
            --genesis-package "$genesis_package" \
            --genesis-test-result "$successor_genesis_test_result" \
            --target-package "$successor_target_package" \
            --target-test-result "$successor_target_test_result" \
            --genesis-key-bridge "$bridge" \
            --activation-statement "$statement" \
            --activation-approval-set "$approvals"
}

run_reconciliation() {
    env -i \
        FLEET_RECALL_RECONCILIATION_DATABASE_URL="$reconciliation_url" \
        FLEET_RECALL_RECONCILIATION_TENANT_ID="$reconciliation_tenant_id" \
        FLEET_RECALL_RECONCILIATION_PROJECT="$reconciliation_project" \
        "$reconciliation_binary" apply \
            --legacy-conflict-id "$reconciliation_legacy_conflict_id" \
            --expected-legacy-revision 7 \
            --idempotency-key "$reconciliation_idempotency_key"
}

reconciliation_table_fingerprints() {
    local fingerprint
    local table_name
    for table_name in \
        memory_claims \
        memory_claim_events \
        memory_conflicts \
        memory_conflict_members \
        memory_mutation_receipts \
        memory_events
    do
        if ! fingerprint=$(root_scalar "
            SELECT *
            FROM [SHOW EXPERIMENTAL_FINGERPRINTS FROM TABLE $table_name]
            ORDER BY 1, 2"); then
            fail "could not fingerprint reconciliation table $table_name"
        fi
        printf '%s\n' "$table_name"
        printf '%s\n' "$fingerprint"
    done
}

# These seven tables are the successor repository's direct SQL surface. Whole-
# table CockroachDB fingerprints cover every index and make failed preflights,
# stale requests, and exact replays prove their no-write claim independently of
# scoped row counts.
successor_table_fingerprints() {
    local fingerprint
    local table_name
    for table_name in \
        memory_control_events \
        memory_control_shard_heads \
        memory_registry_activations \
        memory_registry_current_heads_v2 \
        memory_registry_genesis_bridge_consumptions \
        memory_registry_heads \
        memory_registry_transitions
    do
        if ! fingerprint=$(root_scalar "
            SELECT *
            FROM [SHOW EXPERIMENTAL_FINGERPRINTS FROM TABLE $table_name]
            ORDER BY 1, 2"); then
            fail "could not fingerprint successor table $table_name"
        fi
        printf '%s\n' "$table_name"
        printf '%s\n' "$fingerprint"
    done
}

legacy_registry_fingerprints() {
    local fingerprint
    local table_name
    for table_name in memory_registry_activations memory_registry_heads; do
        if ! fingerprint=$(root_scalar "
            SELECT *
            FROM [SHOW EXPERIMENTAL_FINGERPRINTS FROM TABLE $table_name]
            ORDER BY 1, 2"); then
            fail "could not fingerprint legacy registry table $table_name"
        fi
        printf '%s\n' "$table_name"
        printf '%s\n' "$fingerprint"
    done
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

# The conflict role was created after the first successor policy application,
# so remove its exact creator-scoped PUBLIC routine default before the first
# pre-genesis audit/reapply/use interval. Neither one-shot role has a member
# while this cluster-wide default and external-authority cleanup is performed.
"$crdb" sql --url="$root_url" --execute='
    GRANT fleet_conflict_reconciliation TO root;
    ALTER DEFAULT PRIVILEGES FOR ROLE fleet_conflict_reconciliation
        REVOKE EXECUTE ON ROUTINES FROM public;
    REVOKE fleet_conflict_reconciliation FROM root;
' >/dev/null
assert_root_scalar "one-shot roles remain memberless after default cleanup" \
    "SELECT count(*)::STRING FROM [SHOW GRANTS ON ROLE]
     WHERE role_name IN (
         'fleet_registry_successor_activation',
         'fleet_conflict_reconciliation'
     )
        OR member IN (
            'fleet_registry_successor_activation',
            'fleet_conflict_reconciliation'
        )" '0'
assert_public_routine_defaults "pre-genesis one-shot cleanup" \
    'role=ALL,true,routines,public,EXECUTE,false'
pre_genesis_outside_successor_target_authority=$(
    audit_other_database_successor_authority
)
assert_exact "pre-genesis external successor target audit" \
    "$pre_genesis_outside_successor_target_authority" ''
pre_genesis_outside_successor_public_authority=$(
    inventory_other_database_public_application_authority
)
assert_exact "pre-genesis external PUBLIC inventory" \
    "$pre_genesis_outside_successor_public_authority" ''
apply_successor_policy >/dev/null
assert_root_scalar "pre-genesis successor policy current database" \
    'SELECT pg_catalog.current_database()' 'fleet_recall'
assert_root_scalar "pre-genesis one-shot role option set" \
    "SELECT username || ':' || options::STRING
     FROM [SHOW USERS]
     WHERE username IN (
         'fleet_registry_successor_activation',
         'fleet_conflict_reconciliation'
     )
     ORDER BY username" \
    'fleet_conflict_reconciliation:{NOLOGIN}
fleet_registry_successor_activation:{NOLOGIN}'
assert_root_scalar "pre-genesis successor role remains memberless" \
    "SELECT count(*)::STRING FROM [SHOW GRANTS ON ROLE]
     WHERE role_name = 'fleet_registry_successor_activation'
        OR member = 'fleet_registry_successor_activation'" '0'
# Offline approval binding must win before membership and transport. Cross-wire
# the set-level statement ID and every embedded approval ID to the same other
# canonical digest, exactly as the bin's unit seam does. An otherwise complete
# environment uses an unreachable verify-full URL and must never connect.
altered_successor_approvals="$artifact_dir/altered-successor-approval-set.jsonl"
other_successor_statement_id=$(printf 'aa%.0s' {1..32})
jq -c --arg statement_id "$other_successor_statement_id" '
    .statement_id = $statement_id
    | .approvals = [.approvals[] | .statement_id = $statement_id]
' \
    "$successor_approvals" > "$altered_successor_approvals"
unreachable_successor_url="postgresql://proof_successor:${successor_password}@127.0.0.1:1/fleet_recall?sslmode=verify-full&sslrootcert=${ca_path}"
if altered_successor_approval=$( \
    PROOF_SUCCESSOR_DATABASE_URL="$unreachable_successor_url" \
    PROOF_SUCCESSOR_APPROVAL_SET="$altered_successor_approvals" \
        run_successor inspect 2>&1
); then
    fail "altered successor approval unexpectedly reached transport"
fi
grep -Fq 'successor approval set does not bind the exact statement and bridge' \
    <<<"$altered_successor_approval" \
    || fail "cross-wired successor approval did not fail in offline binding"
if grep -Fqi 'connect private successor activation database' \
    <<<"$altered_successor_approval"; then
    fail "altered successor approval attempted a database connection"
fi

# Open the first narrow role window only for the two pre-genesis repository
# classifications. The external identity has no direct or system grant, its
# only edge is non-admin membership in the exact logical role, and its URL is
# bound to fleet_recall.
"$crdb" sql --url="$root_url" --execute='
    ALTER USER proof_successor WITH LOGIN;
    GRANT fleet_registry_successor_activation TO proof_successor;
' >/dev/null
assert_root_scalar "first-window successor login enabled" \
    "SELECT ('NOLOGIN' = ANY(options))::STRING FROM [SHOW USERS]
     WHERE username = 'proof_successor'" 'false'
first_window_successor_identity=$("$crdb" sql --url="$successor_url" --format=tsv \
    --execute="SELECT pg_catalog.current_database() || ':' || current_user" \
    | tail -n +2)
assert_exact "first-window successor authenticated identity" \
    "$first_window_successor_identity" 'fleet_recall:proof_successor'
assert_root_scalar "complete first-window successor role edges" \
    "SELECT role_name || ':' || member || ':' ||
            CASE WHEN is_admin THEN 'admin_option' ELSE 'no_admin_option' END
     FROM [SHOW GRANTS ON ROLE]
     WHERE role_name IN (
         'fleet_registry_successor_activation',
         'proof_successor'
     )
        OR member IN (
            'fleet_registry_successor_activation',
            'proof_successor'
        )
     ORDER BY role_name, member" \
    'fleet_registry_successor_activation:proof_successor:no_admin_option'
assert_root_scalar "first-window successor member direct grants" \
    "SELECT count(*)::STRING FROM [SHOW GRANTS FOR proof_successor]
     WHERE grantee = 'proof_successor'" '0'
assert_root_scalar "first-window successor member direct system grants" \
    "SELECT count(*)::STRING FROM [SHOW SYSTEM GRANTS]
     WHERE grantee = 'proof_successor'" '0'

# Before the genesis ceremony, the fully verified checked-in successor
# authority reaches the repository and retains the exact closed NotReady state.
successor_before_not_ready=$(successor_table_fingerprints)
if successor_not_ready=$(run_successor inspect 2>&1); then
    fail "successor inspect unexpectedly succeeded before genesis"
fi
grep -Fq 'requires a complete audited genesis activation' \
    <<<"$successor_not_ready" \
    || fail "pre-genesis successor inspect did not retain NotReady"
successor_after_not_ready=$(successor_table_fingerprints)
assert_exact "NotReady successor inspect seven-table fingerprints" \
    "$successor_after_not_ready" "$successor_before_not_ready"

# A failed migration 14 cannot be masked by successful rows 15 through 17. The
# database/schema preflight must happen before any write to all seven tables in
# the successor repository's direct SQL surface.
successor_before_failed_prefix=$(successor_table_fingerprints)
"$crdb" sql --url="$root_url" \
    --execute='UPDATE _sqlx_migrations SET success = false WHERE version = 14' \
    >/dev/null
assert_root_scalar "successor later successful migrations remain visible" \
    "SELECT string_agg(version::STRING, '|' ORDER BY version)
     FROM _sqlx_migrations
     WHERE version BETWEEN 15 AND 17 AND success" '15|16|17'
successor_failed_prefix_succeeded=0
if successor_failed_prefix=$(run_successor inspect 2>&1); then
    successor_failed_prefix_succeeded=1
fi
"$crdb" sql --url="$root_url" \
    --execute='UPDATE _sqlx_migrations SET success = true WHERE version = 14' \
    >/dev/null
test "$successor_failed_prefix_succeeded" -eq 0 \
    || fail "failed migration 14 was masked by later successful rows"
grep -Fq 'requires the complete successful schema prefix through 14' \
    <<<"$successor_failed_prefix" \
    || fail "failed migration 14 did not retain SchemaUnavailable"
successor_after_failed_prefix=$(successor_table_fingerprints)
assert_exact "failed successor prefix seven-table fingerprints" \
    "$successor_after_failed_prefix" "$successor_before_failed_prefix"
assert_root_scalar "restored successful successor prefix 1 through 14" \
    "SELECT CASE WHEN count(*) = 14
                          AND min(version) = 1
                          AND max(version) = 14
                          AND COALESCE(bool_and(success), false)
                     THEN 'ready' ELSE 'not_ready' END
     FROM _sqlx_migrations
     WHERE version BETWEEN 1 AND 14" 'ready'

# Close the first role window before any control/bootstrap/genesis work. The
# LOGIN identity retains no direct grant and has no usable application role
# during the complete genesis ceremony or dynamic fixture generation.
"$crdb" sql --url="$root_url" --execute='
    REVOKE fleet_registry_successor_activation FROM proof_successor;
    ALTER USER proof_successor WITH NOLOGIN;
' >/dev/null
assert_root_scalar "closed first-window successor role edges" \
    "SELECT count(*)::STRING FROM [SHOW GRANTS ON ROLE]
     WHERE role_name IN (
         'fleet_registry_successor_activation',
         'proof_successor'
     )
        OR member IN (
            'fleet_registry_successor_activation',
            'proof_successor'
        )" '0'
assert_root_scalar "inter-window successor login disabled" \
    "SELECT options::STRING FROM [SHOW USERS]
     WHERE username = 'proof_successor'" '{NOLOGIN}'
if successor_interwindow_auth=$("$crdb" sql --url="$successor_url" \
    --execute='SELECT current_user' 2>&1); then
    fail "inter-window successor login unexpectedly authenticated"
fi
grep -Eiq 'authentication|password|nologin|login' \
    <<<"$successor_interwindow_auth" \
    || fail "inter-window successor login failed for an unexpected reason"

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

# Emit a fresh successor bridge plus current/stale ceremonies from the durable
# genesis head. The ignored test harness is the only emitter surface: its empty
# environment contains exactly the seven reviewed inputs and must create the
# exact six-file closed output set in a new disposable directory.
successor_artifact_dir="$artifact_dir/successor"
mkdir "$successor_artifact_dir"
successor_artifact_dir=$(CDPATH='' cd -- "$successor_artifact_dir" && pwd)
genesis_effective_from=$(jq -r '.effective_from' <<<"$inserted")
successor_effective_from=$(root_scalar \
    "SELECT to_char(statement_timestamp(), 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"000Z\"')")
successor_stale_effective_from=$(root_scalar \
    "SELECT to_char(statement_timestamp() + INTERVAL '1 microsecond', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"000Z\"')")
case "$genesis_effective_from:$successor_effective_from:$successor_stale_effective_from" in
    ????-??-??T??:??:??.?????????Z:????-??-??T??:??:??.?????????Z:????-??-??T??:??:??.?????????Z) ;;
    *) fail "database did not return canonical successor ceremony timestamps" ;;
esac
(
    cd "$repo_root"
    env -i \
        FLEET_RECALL_SUCCESSOR_CLI_FIXTURE_DIR="$successor_artifact_dir" \
        FLEET_RECALL_SUCCESSOR_CLI_GENESIS_ACTIVATION_ID="$activation_id" \
        FLEET_RECALL_SUCCESSOR_CLI_GENESIS_PACKAGE_DIGEST="$package_digest" \
        FLEET_RECALL_SUCCESSOR_CLI_GENESIS_ACTIVATION_POLICY_DIGEST="$policy_digest" \
        FLEET_RECALL_SUCCESSOR_CLI_GENESIS_EFFECTIVE_FROM="$genesis_effective_from" \
        FLEET_RECALL_SUCCESSOR_CLI_EFFECTIVE_FROM="$successor_effective_from" \
        FLEET_RECALL_SUCCESSOR_CLI_STALE_EFFECTIVE_FROM="$successor_stale_effective_from" \
        "$successor_emitter_test_binary" \
            "$successor_emitter_test_name" --exact --ignored >/dev/null
)
successor_emitted_files=$(
    for emitted_path in "$successor_artifact_dir"/*; do
        test -f "$emitted_path" || fail "successor emitter created a non-file output"
        basename "$emitted_path"
    done | sort
)
expected_successor_emitted_files='activation-approval-set-stale.jsonl
activation-approval-set.jsonl
activation-statement-stale.jsonl
activation-statement.jsonl
genesis-successor-key-bridge-digest.txt
genesis-successor-key-bridge.jsonl'
assert_exact "dynamic successor emitter six-file output set" \
    "$successor_emitted_files" "$expected_successor_emitted_files"
successor_emitted_entry_count=$(find "$successor_artifact_dir" -print \
    | wc -l | tr -d ' ')
assert_exact "dynamic successor emitter total entry count" \
    "$successor_emitted_entry_count" '7'
successor_bridge="$successor_artifact_dir/genesis-successor-key-bridge.jsonl"
successor_statement="$successor_artifact_dir/activation-statement.jsonl"
successor_approvals="$successor_artifact_dir/activation-approval-set.jsonl"
successor_stale_statement="$successor_artifact_dir/activation-statement-stale.jsonl"
successor_stale_approvals="$successor_artifact_dir/activation-approval-set-stale.jsonl"
successor_bridge_digest_file="$successor_artifact_dir/genesis-successor-key-bridge-digest.txt"
successor_bridge_digest=$(awk '
    NR == 1 && length($0) == 64 && $0 ~ /^[0-9a-f]+$/ {
        digest = $0
        next
    }
    { invalid = 1 }
    END {
        if (NR != 1 || invalid || digest == "") exit 1
        print digest
    }
' "$successor_bridge_digest_file") \
    || fail "successor emitter did not publish exactly one canonical bridge digest"

# Re-establish the full one-shot deployment boundary after genesis and fixture
# generation, while both logical roles remain memberless. Re-clean the optional
# reconciliation role's creator default, repeat both cross-database audits,
# reapply the frozen successor policy, and only then open the second narrow
# member window for Ready/Inserted/Accepted/ExactReplay/Stale.
"$crdb" sql --url="$root_url" --execute='
    GRANT fleet_conflict_reconciliation TO root;
    ALTER DEFAULT PRIVILEGES FOR ROLE fleet_conflict_reconciliation
        REVOKE EXECUTE ON ROUTINES FROM public;
    REVOKE fleet_conflict_reconciliation FROM root;
' >/dev/null
assert_root_scalar "post-emitter one-shot roles remain memberless" \
    "SELECT count(*)::STRING FROM [SHOW GRANTS ON ROLE]
     WHERE role_name IN (
         'fleet_registry_successor_activation',
         'fleet_conflict_reconciliation'
     )
        OR member IN (
            'fleet_registry_successor_activation',
            'fleet_conflict_reconciliation'
        )" '0'
assert_public_routine_defaults "post-emitter one-shot default cleanup" \
    'role=ALL,true,routines,public,EXECUTE,false'
final_outside_successor_target_authority=$(
    audit_other_database_successor_authority
)
assert_exact "post-emitter external successor target audit" \
    "$final_outside_successor_target_authority" ''
final_outside_successor_public_authority=$(
    inventory_other_database_public_application_authority
)
assert_exact "post-emitter external PUBLIC inventory" \
    "$final_outside_successor_public_authority" ''
apply_successor_policy >/dev/null
assert_root_scalar "post-emitter successor policy current database" \
    'SELECT pg_catalog.current_database()' 'fleet_recall'
assert_root_scalar "post-emitter one-shot role option set" \
    "SELECT username || ':' || options::STRING
     FROM [SHOW USERS]
     WHERE username IN (
         'fleet_registry_successor_activation',
         'fleet_conflict_reconciliation'
     )
     ORDER BY username" \
    'fleet_conflict_reconciliation:{NOLOGIN}
fleet_registry_successor_activation:{NOLOGIN}'
assert_root_scalar "post-emitter successor role remains memberless" \
    "SELECT count(*)::STRING FROM [SHOW GRANTS ON ROLE]
     WHERE role_name = 'fleet_registry_successor_activation'
        OR member = 'fleet_registry_successor_activation'" '0'
"$crdb" sql --url="$root_url" --execute='
    ALTER USER proof_successor WITH LOGIN;
    GRANT fleet_registry_successor_activation TO proof_successor;
' >/dev/null
assert_root_scalar "second-window successor login enabled" \
    "SELECT ('NOLOGIN' = ANY(options))::STRING FROM [SHOW USERS]
     WHERE username = 'proof_successor'" 'false'
second_window_successor_identity=$("$crdb" sql --url="$successor_url" --format=tsv \
    --execute="SELECT pg_catalog.current_database() || ':' || current_user" \
    | tail -n +2)
assert_exact "second-window successor authenticated identity" \
    "$second_window_successor_identity" 'fleet_recall:proof_successor'
assert_root_scalar "complete second-window successor role edges" \
    "SELECT role_name || ':' || member || ':' ||
            CASE WHEN is_admin THEN 'admin_option' ELSE 'no_admin_option' END
     FROM [SHOW GRANTS ON ROLE]
     WHERE role_name IN (
         'fleet_registry_successor_activation',
         'proof_successor'
     )
        OR member IN (
            'fleet_registry_successor_activation',
            'proof_successor'
        )
     ORDER BY role_name, member" \
    'fleet_registry_successor_activation:proof_successor:no_admin_option'
assert_root_scalar "second-window successor member direct grants" \
    "SELECT count(*)::STRING FROM [SHOW GRANTS FOR proof_successor]
     WHERE grantee = 'proof_successor'" '0'
assert_root_scalar "second-window successor member direct system grants" \
    "SELECT count(*)::STRING FROM [SHOW SYSTEM GRANTS]
     WHERE grantee = 'proof_successor'" '0'

# The emitted authority is closed over the actual genesis head. Inspect is
# Ready without writing either the mutable successor projection or immutable
# legacy registry tables; apply then returns the exact bounded Inserted receipt.
legacy_registry_before_successor=$(legacy_registry_fingerprints)
successor_before_ready_inspect=$(successor_table_fingerprints)
successor_ready=$(run_successor inspect)
jq -e --argjson genesis "$inserted" --arg bridge "$successor_bridge_digest" '
    (keys | sort) == [
        "genesis_head",
        "genesis_key_bridge_digest",
        "operation",
        "state"
    ] and
    (.genesis_head | keys | sort) == [
        "activation_id",
        "activation_policy_digest",
        "effective_from",
        "effective_until",
        "package_digest"
    ] and
    .operation == "inspect" and .state == "ready" and
    .genesis_head.activation_id == $genesis.registry_head.activation_id and
    .genesis_head.package_digest == $genesis.registry_head.package_digest and
    .genesis_head.activation_policy_digest ==
        $genesis.registry_head.activation_policy_digest and
    .genesis_head.effective_from == $genesis.effective_from and
    .genesis_head.effective_until == null and
    .genesis_key_bridge_digest == $bridge
' <<<"$successor_ready" >/dev/null \
    || fail "fresh successor inspect did not return exact Ready output"
successor_after_ready_inspect=$(successor_table_fingerprints)
assert_exact "Ready successor inspect seven-table fingerprints" \
    "$successor_after_ready_inspect" "$successor_before_ready_inspect"

successor_inserted=$(run_successor apply)
jq -e \
    --arg package "$successor_target_package_digest" \
    --arg policy "$successor_target_policy_digest" \
    --arg effective "$successor_effective_from" \
    --arg bridge "$successor_bridge_digest" '
    (keys | sort) == [
        "accepted_at",
        "accepted_event_id",
        "activation_id",
        "committed_offset",
        "control_shard",
        "epoch_id",
        "genesis_key_bridge_digest",
        "operation",
        "registry_head",
        "state",
        "statement_id"
    ] and
    (.registry_head | keys | sort) == [
        "activation_id",
        "activation_policy_digest",
        "effective_from",
        "effective_until",
        "package_digest"
    ] and
    .operation == "apply" and .state == "inserted" and
    .registry_head.activation_id == .activation_id and
    .registry_head.package_digest == $package and
    .registry_head.activation_policy_digest == $policy and
    .registry_head.effective_from == $effective and
    .registry_head.effective_until == null and
    .genesis_key_bridge_digest == $bridge and
    (.control_shard | type) == "number" and
    (.committed_offset | type) == "string" and
    (.committed_offset | test("^[1-9][0-9]*$"))
' <<<"$successor_inserted" >/dev/null \
    || fail "first successor apply did not return exact Inserted output"

# Accepted inspection and identical apply replay normalize to the exact same
# durable receipt. Whole-table fingerprints prove both read/replay paths write
# nothing.
successor_before_accepted_inspect=$(successor_table_fingerprints)
successor_accepted=$(run_successor inspect)
jq -e --argjson inserted "$successor_inserted" '
    .operation == "inspect" and .state == "accepted" and
    (del(.operation, .state) == ($inserted | del(.operation, .state)))
' <<<"$successor_accepted" >/dev/null \
    || fail "post-successor inspect did not return exact Accepted output"
successor_after_accepted_inspect=$(successor_table_fingerprints)
assert_exact "Accepted successor inspect seven-table fingerprints" \
    "$successor_after_accepted_inspect" "$successor_before_accepted_inspect"
successor_before_replay=$(successor_table_fingerprints)
successor_replay=$(run_successor apply)
jq -e --argjson inserted "$successor_inserted" '
    .operation == "apply" and .state == "exact_replay" and
    (del(.operation, .state) == ($inserted | del(.operation, .state)))
' <<<"$successor_replay" >/dev/null \
    || fail "identical successor apply was not an exact normalized replay"
successor_after_replay=$(successor_table_fingerprints)
assert_exact "ExactReplay successor seven-table fingerprints" \
    "$successor_after_replay" "$successor_before_replay"

# The emitter's second ceremony is a distinct, freshly signed valid statement,
# not an alternate approval set for the winning statement. It must classify
# exactly Stale, never Conflict, and make no durable write.
successor_before_stale=$(successor_table_fingerprints)
if successor_stale=$( \
    PROOF_SUCCESSOR_STATEMENT="$successor_stale_statement" \
    PROOF_SUCCESSOR_APPROVAL_SET="$successor_stale_approvals" \
        run_successor apply 2>&1
); then
    fail "distinct fresh successor statement unexpectedly replaced the winner"
fi
grep -Fq 'successor registry activation is stale because another statement already won' \
    <<<"$successor_stale" \
    || fail "distinct fresh successor statement did not classify exactly Stale"
if grep -Fqi 'conflict' <<<"$successor_stale"; then
    fail "distinct fresh successor statement was incorrectly described as Conflict"
fi
successor_after_stale=$(successor_table_fingerprints)
assert_exact "Stale successor seven-table fingerprints" \
    "$successor_after_stale" "$successor_before_stale"

# Freeze the exact accepted graph independently of the CLI's own transactional
# audit: generations are exactly 0/1, the one bridge consumes 0 -> 1, current
# points only at generation 1, the successor control event and shard head carry
# the CLI coordinate, all six projections share one database timestamp, and
# the two legacy generation-zero tables remain byte-for-byte unchanged.
successor_statement_id=$(jq -r '.statement_id' <<<"$successor_inserted")
successor_activation_id=$(jq -r '.activation_id' <<<"$successor_inserted")
successor_event_id=$(jq -r '.accepted_event_id' <<<"$successor_inserted")
successor_epoch_id=$(jq -r '.epoch_id' <<<"$successor_inserted")
successor_control_shard=$(jq -r '.control_shard' <<<"$successor_inserted")
successor_committed_offset=$(jq -r '.committed_offset' <<<"$successor_inserted")
successor_accepted_at=$(jq -r '.accepted_at' <<<"$successor_inserted")
assert_root_scalar "exact successor transition generations" \
    "SELECT string_agg(generation::STRING, '|' ORDER BY generation)
     FROM memory_registry_transitions
     WHERE tenant_id = '$tenant_id' AND project = '$physical_project'" '0|1'
assert_root_scalar "exact successor bridge/current cardinalities" \
    "SELECT
         (SELECT count(*) FROM memory_registry_genesis_bridge_consumptions
          WHERE tenant_id = '$tenant_id' AND project = '$physical_project')::STRING
         || '|' ||
         (SELECT count(*) FROM memory_registry_current_heads_v2
          WHERE tenant_id = '$tenant_id' AND project = '$physical_project')::STRING" \
    '1|1'
assert_root_scalar "successor preserves legacy registry cardinalities" \
    "SELECT
         (SELECT count(*) FROM memory_registry_activations
          WHERE tenant_id = '$tenant_id' AND project = '$physical_project')::STRING
         || '|' ||
         (SELECT count(*) FROM memory_registry_heads
          WHERE tenant_id = '$tenant_id' AND project = '$physical_project')::STRING" \
    '1|1'
assert_root_scalar "exact successor generation/bridge/current/control graph" \
    "SELECT CASE WHEN count(*) = 1
                       AND COALESCE(bool_and(
                           g.generation = 0
                           AND encode(g.activation_id, 'hex') = '$activation_id'
                           AND g.activation_id = a.activation_id
                           AND g.statement_id = a.statement_id
                           AND g.package_digest = a.activated_package_digest
                           AND g.activation_policy_digest = a.activated_policy_digest
                           AND g.test_result_digest = a.test_result_digest
                           AND g.profile_id = a.profile_id
                           AND g.profile_digest = a.profile_digest
                           AND g.vector_manifest_digest = a.vector_manifest_digest
                           AND g.contract_tenant_namespace = a.contract_tenant_namespace
                           AND g.contract_project_namespace = a.contract_project_namespace
                           AND g.effective_from = a.effective_from
                           AND g.accepted_at = a.accepted_at
                           AND g.source_event_id = a.accepted_event_id
                           AND g.source_epoch_id = a.control_epoch_id
                           AND g.source_shard = a.control_shard
                           AND g.source_committed_offset = a.control_committed_offset
                           AND g.root_activation_id = g.activation_id
                           AND g.root_package_digest = g.package_digest
                           AND g.root_activation_policy_digest = g.activation_policy_digest
                           AND g.root_profile_id = g.profile_id
                           AND g.root_profile_digest = g.profile_digest
                           AND g.root_vector_manifest_digest = g.vector_manifest_digest
                           AND g.root_contract_tenant_namespace = g.contract_tenant_namespace
                           AND g.root_contract_project_namespace = g.contract_project_namespace
                           AND g.root_effective_from = g.effective_from
                           AND g.root_accepted_at = g.accepted_at
                           AND g.root_source_event_id = g.source_event_id
                           AND g.root_source_epoch_id = g.source_epoch_id
                           AND g.root_source_shard = g.source_shard
                           AND g.root_source_committed_offset = g.source_committed_offset
                           AND g.predecessor_generation IS NULL
                           AND g.predecessor_activation_id IS NULL
                           AND g.predecessor_package_digest IS NULL
                           AND g.predecessor_activation_policy_digest IS NULL
                           AND g.predecessor_profile_id IS NULL
                           AND g.predecessor_profile_digest IS NULL
                           AND g.predecessor_vector_manifest_digest IS NULL
                           AND g.predecessor_contract_tenant_namespace IS NULL
                           AND g.predecessor_contract_project_namespace IS NULL
                           AND g.predecessor_effective_from IS NULL
                           AND g.predecessor_accepted_at IS NULL
                           AND g.predecessor_source_event_id IS NULL
                           AND g.predecessor_source_epoch_id IS NULL
                           AND g.predecessor_source_shard IS NULL
                           AND g.predecessor_source_committed_offset IS NULL
                           AND h.activation_id = g.activation_id
                           AND h.package_digest = g.package_digest
                           AND h.activation_policy_digest = g.activation_policy_digest
                           AND h.source_event_id = g.source_event_id
                           AND h.source_epoch_id = g.source_epoch_id
                           AND h.source_shard = g.source_shard
                           AND h.source_committed_offset = g.source_committed_offset
                           AND h.activated_at = g.accepted_at
                           AND s.generation = 1
                           AND encode(s.statement_id, 'hex') = '$successor_statement_id'
                           AND encode(s.activation_id, 'hex') = '$successor_activation_id'
                           AND encode(s.package_digest, 'hex') = '$successor_target_package_digest'
                           AND encode(s.activation_policy_digest, 'hex') = '$successor_target_policy_digest'
                           AND encode(s.test_result_digest, 'hex') = '$successor_target_test_result_digest'
                           AND to_char(
                               s.effective_from,
                               'YYYY-MM-DD\"T\"HH24:MI:SS.US\"000Z\"'
                           ) = '$successor_effective_from'
                           AND encode(s.source_event_id, 'hex') = '$successor_event_id'
                           AND encode(s.source_epoch_id, 'hex') = '$successor_epoch_id'
                           AND s.source_shard = $successor_control_shard
                           AND s.source_committed_offset = $successor_committed_offset
                           AND s.source_committed_offset = g.source_committed_offset + 1
                           AND s.root_activation_id = g.root_activation_id
                           AND s.root_package_digest = g.root_package_digest
                           AND s.root_activation_policy_digest = g.root_activation_policy_digest
                           AND s.root_profile_id = g.root_profile_id
                           AND s.root_profile_digest = g.root_profile_digest
                           AND s.root_vector_manifest_digest = g.root_vector_manifest_digest
                           AND s.root_contract_tenant_namespace = g.root_contract_tenant_namespace
                           AND s.root_contract_project_namespace = g.root_contract_project_namespace
                           AND s.root_effective_from = g.root_effective_from
                           AND s.root_accepted_at = g.root_accepted_at
                           AND s.root_source_event_id = g.root_source_event_id
                           AND s.root_source_epoch_id = g.root_source_epoch_id
                           AND s.root_source_shard = g.root_source_shard
                           AND s.root_source_committed_offset = g.root_source_committed_offset
                           AND s.predecessor_generation = g.generation
                           AND s.predecessor_activation_id = g.activation_id
                           AND s.predecessor_package_digest = g.package_digest
                           AND s.predecessor_activation_policy_digest = g.activation_policy_digest
                           AND s.predecessor_profile_id = g.profile_id
                           AND s.predecessor_profile_digest = g.profile_digest
                           AND s.predecessor_vector_manifest_digest = g.vector_manifest_digest
                           AND s.predecessor_contract_tenant_namespace = g.contract_tenant_namespace
                           AND s.predecessor_contract_project_namespace = g.contract_project_namespace
                           AND s.predecessor_effective_from = g.effective_from
                           AND s.predecessor_accepted_at = g.accepted_at
                           AND s.predecessor_source_event_id = g.source_event_id
                           AND s.predecessor_source_epoch_id = g.source_epoch_id
                           AND s.predecessor_source_shard = g.source_shard
                           AND s.predecessor_source_committed_offset = g.source_committed_offset
                           AND b.from_generation = 0
                           AND b.to_generation = 1
                           AND encode(b.bridge_digest, 'hex') = '$successor_bridge_digest'
                           AND b.genesis_activation_id = g.activation_id
                           AND b.genesis_package_digest = g.package_digest
                           AND b.genesis_activation_policy_digest = g.activation_policy_digest
                           AND b.genesis_profile_id = g.profile_id
                           AND b.genesis_profile_digest = g.profile_digest
                           AND b.genesis_vector_manifest_digest = g.vector_manifest_digest
                           AND b.genesis_contract_tenant_namespace = g.contract_tenant_namespace
                           AND b.genesis_contract_project_namespace = g.contract_project_namespace
                           AND b.genesis_effective_from = g.effective_from
                           AND b.genesis_accepted_at = g.accepted_at
                           AND b.genesis_source_event_id = g.source_event_id
                           AND b.genesis_source_epoch_id = g.source_epoch_id
                           AND b.genesis_source_shard = g.source_shard
                           AND b.genesis_source_committed_offset = g.source_committed_offset
                           AND b.successor_activation_id = s.activation_id
                           AND b.successor_package_digest = s.package_digest
                           AND b.successor_activation_policy_digest = s.activation_policy_digest
                           AND b.successor_profile_id = s.profile_id
                           AND b.successor_profile_digest = s.profile_digest
                           AND b.successor_vector_manifest_digest = s.vector_manifest_digest
                           AND b.successor_contract_tenant_namespace = s.contract_tenant_namespace
                           AND b.successor_contract_project_namespace = s.contract_project_namespace
                           AND b.successor_effective_from = s.effective_from
                           AND b.successor_source_event_id = s.source_event_id
                           AND b.successor_source_epoch_id = s.source_epoch_id
                           AND b.successor_source_shard = s.source_shard
                           AND b.successor_source_committed_offset = s.source_committed_offset
                           AND c.head_state = 'active'
                           AND c.generation = 1
                           AND c.activation_id = s.activation_id
                           AND c.package_digest = s.package_digest
                           AND c.activation_policy_digest = s.activation_policy_digest
                           AND c.profile_id = s.profile_id
                           AND c.profile_digest = s.profile_digest
                           AND c.vector_manifest_digest = s.vector_manifest_digest
                           AND c.contract_tenant_namespace = s.contract_tenant_namespace
                           AND c.contract_project_namespace = s.contract_project_namespace
                           AND c.effective_from = s.effective_from
                           AND c.source_event_id = s.source_event_id
                           AND c.source_epoch_id = s.source_epoch_id
                           AND c.source_shard = s.source_shard
                           AND c.source_committed_offset = s.source_committed_offset
                           AND c.canonical_head = s.canonical_head
                           AND e.event_schema_version = 1
                           AND e.event_kind = 'registry.successor.activated'
                           AND e.event_id = s.source_event_id
                           AND e.epoch_id = s.source_epoch_id
                           AND e.shard = s.source_shard
                           AND e.committed_offset = s.source_committed_offset
                           AND e.semantic_object_digest = s.activation_id
                           AND e.consistency_family = 'registry.activation'
                           AND e.canonical_event = s.canonical_event
                           AND sh.last_committed_offset = s.source_committed_offset
                           AND sh.chain_digest = e.chain_digest
                           AND s.accepted_at = b.successor_accepted_at
                           AND s.accepted_at = b.consumed_at
                           AND s.accepted_at = c.accepted_at
                           AND s.accepted_at = e.accepted_at
                           AND s.accepted_at = sh.advanced_at
                           AND to_char(
                               s.accepted_at,
                               'YYYY-MM-DD\"T\"HH24:MI:SS.US\"000Z\"'
                           ) = '$successor_accepted_at'
                       ), false)
                 THEN 'match' ELSE 'mismatch' END
     FROM memory_registry_transitions AS g
     JOIN memory_registry_transitions AS s
       ON s.tenant_id = g.tenant_id
      AND s.project = g.project
      AND s.generation = 1
     JOIN memory_registry_genesis_bridge_consumptions AS b
       ON b.tenant_id = g.tenant_id AND b.project = g.project
     JOIN memory_registry_current_heads_v2 AS c
       ON c.tenant_id = g.tenant_id AND c.project = g.project
     JOIN memory_registry_activations AS a
       ON a.tenant_id = g.tenant_id AND a.project = g.project
     JOIN memory_registry_heads AS h
       ON h.tenant_id = g.tenant_id AND h.project = g.project
     JOIN memory_control_events AS e
       ON e.tenant_id = g.tenant_id
      AND e.project = g.project
      AND e.event_id = s.source_event_id
     JOIN memory_control_shard_heads AS sh
       ON sh.tenant_id = g.tenant_id
      AND sh.project = g.project
      AND sh.epoch_id = s.source_epoch_id
      AND sh.shard = s.source_shard
     WHERE g.tenant_id = '$tenant_id'
       AND g.project = '$physical_project'
       AND g.generation = 0" 'match'
assert_root_scalar "exact genesis/successor registry control stream" \
    "SELECT string_agg(
         encode(event_id, 'hex') || ':' || committed_offset::STRING,
         '|' ORDER BY committed_offset
     )
     FROM memory_control_events
     WHERE tenant_id = '$tenant_id'
       AND project = '$physical_project'
       AND epoch_id = decode('$successor_epoch_id', 'hex')
       AND shard = $successor_control_shard
       AND consistency_family = 'registry.activation'" \
    "$accepted_event_id:$committed_offset|$successor_event_id:$successor_committed_offset"
legacy_registry_after_successor=$(legacy_registry_fingerprints)
assert_exact "successor preserved legacy table fingerprints" \
    "$legacy_registry_after_successor" "$legacy_registry_before_successor"

# The member's query plan must retain the repository's bounded primary-key span
# over exactly migration versions 1 through 14 even though 15 through 17 exist.
successor_prefix_explain=$("$crdb" sql --url="$successor_url" \
    --format=tsv --execute="
    EXPLAIN SELECT pg_catalog.current_database() = 'fleet_recall'
               AND count(*) = 14
               AND COALESCE(bool_and(success), false)
    FROM public._sqlx_migrations
    WHERE version BETWEEN 1 AND 14")
if ! grep -Eq '_sqlx_migrations@(_sqlx_migrations_pkey|primary)' \
    <<<"$successor_prefix_explain"; then
    printf '%s\n' "$successor_prefix_explain" >&2
    fail "successor migration-prefix preflight did not use the primary index"
fi
if ! grep -Eq 'span(s)?:.*\[/1[^]]*-[[:space:]]*/14\]' \
    <<<"$successor_prefix_explain"; then
    printf '%s\n' "$successor_prefix_explain" >&2
    fail "successor migration-prefix preflight did not retain bounded 1..14"
fi

# End the successor's one-shot lifecycle immediately after its exact replay,
# stale loser, graph audit, and plan proof. Remove the sole edge, disable LOGIN,
# clear the password, prove a fresh TLS authentication fails, and leave no edge
# or member option other than exact NOLOGIN behind.
"$crdb" sql --url="$root_url" --execute="
    REVOKE fleet_registry_successor_activation FROM proof_successor;
    ALTER USER proof_successor WITH NOLOGIN PASSWORD NULL;
" >/dev/null
assert_root_scalar "removed successor member edge" \
    "SELECT count(*)::STRING FROM [SHOW GRANTS ON ROLE]
     WHERE role_name = 'fleet_registry_successor_activation'
        OR member = 'fleet_registry_successor_activation'" '0'
assert_root_scalar "disabled successor login options" \
    "SELECT options::STRING FROM [SHOW USERS]
     WHERE username = 'proof_successor'" '{NOLOGIN}'
if successor_disabled_auth=$("$crdb" sql --url="$successor_url" \
    --execute='SELECT current_user' 2>&1); then
    fail "disabled successor login unexpectedly authenticated"
fi
grep -Eiq 'authentication|password|nologin|login' \
    <<<"$successor_disabled_auth" \
    || fail "disabled successor login failed for an unexpected reason"
assert_root_scalar "post-lifecycle successor role residue" \
    "SELECT count(*)::STRING FROM [SHOW GRANTS ON ROLE]
     WHERE role_name IN (
         'fleet_registry_successor_activation',
         'proof_successor'
     )
        OR member IN (
            'fleet_registry_successor_activation',
            'proof_successor'
        )" '0'

# The apply-only reconciliation CLI validates its durable coordinate before it
# parses deployment configuration or can open a socket. Exercise that ordering
# under an empty environment and an otherwise valid, unreachable TLS URL.
unreachable_reconciliation_url="postgresql://proof_reconciliation_cli:${reconciliation_password}@127.0.0.1:1/fleet_recall?sslmode=verify-full&sslrootcert=${ca_path}"
if invalid_reconciliation=$(env -i \
    FLEET_RECALL_RECONCILIATION_DATABASE_URL="$unreachable_reconciliation_url" \
    FLEET_RECALL_RECONCILIATION_TENANT_ID="$reconciliation_tenant_id" \
    FLEET_RECALL_RECONCILIATION_PROJECT="$reconciliation_project" \
    "$reconciliation_binary" apply \
        --legacy-conflict-id 0 \
        --expected-legacy-revision 7 \
        --idempotency-key "$reconciliation_idempotency_key" 2>&1); then
    fail "invalid reconciliation coordinate unexpectedly reached transport"
fi
grep -Fq -- '--legacy-conflict-id must be a positive signed 64-bit integer' \
    <<<"$invalid_reconciliation" \
    || fail "invalid reconciliation coordinate did not retain its closed error"
if grep -Fq 'connect private conflict reconciliation database failed' \
    <<<"$invalid_reconciliation"; then
    fail "invalid reconciliation coordinate attempted a database connection"
fi

# Repeat the full external audit immediately before enable/use, then reapply the
# local policy while the target has no members. This is the final read-only
# deployment snapshot in the proof's single-threaded security/DDL change freeze.
pre_use_outside_target_authority=$(audit_other_database_target_authority)
assert_exact "pre-use external target-authority audit" \
    "$pre_use_outside_target_authority" ''
pre_use_outside_public_application_authority=$(
    inventory_other_database_public_application_authority
)
assert_exact "pre-use external PUBLIC application inventory" \
    "$pre_use_outside_public_application_authority" ''
apply_reconciliation_policy >/dev/null
assert_root_scalar "pre-use reconciliation role remains memberless" \
    "SELECT count(*)::STRING FROM [SHOW GRANTS ON ROLE]
     WHERE role_name = 'fleet_conflict_reconciliation'
        OR member = 'fleet_conflict_reconciliation'" '0'
"$crdb" sql --url="$root_url" \
    --execute='GRANT fleet_conflict_reconciliation TO proof_reconciliation_cli' \
    >/dev/null

# Freeze the dedicated TLS identity before the mutation. The logical role is
# exactly NOLOGIN and its sole edge is the ephemeral member without admin
# option; it neither inherits nor delegates another role.
test "$("$crdb" sql --url="$reconciliation_url" --format=tsv \
    --execute='SELECT current_user' | tail -n +2)" = 'proof_reconciliation_cli' \
    || fail "reconciliation URL did not authenticate the dedicated member login"
assert_root_scalar "conflict reconciliation logical role options" \
    "SELECT options::STRING FROM [SHOW USERS]
     WHERE username = 'fleet_conflict_reconciliation'" '{NOLOGIN}'
assert_root_scalar "complete conflict reconciliation role edges" \
    "SELECT role_name || ':' || member || ':' ||
            CASE WHEN is_admin THEN 'admin_option' ELSE 'no_admin_option' END
     FROM [SHOW GRANTS ON ROLE]
     WHERE role_name IN (
         'fleet_conflict_reconciliation',
         'proof_reconciliation_cli'
     )
        OR member IN (
            'fleet_conflict_reconciliation',
            'proof_reconciliation_cli'
        )
     ORDER BY role_name, member" \
    'fleet_conflict_reconciliation:proof_reconciliation_cli:no_admin_option'

if reconciliation_event_read=$("$crdb" sql --url="$reconciliation_url" \
    --execute='SELECT count(*) FROM memory_events' 2>&1); then
    fail "reconciliation member unexpectedly received aggregate-event reads"
fi
grep -Eiq 'privilege|permission' <<<"$reconciliation_event_read" \
    || fail "reconciliation aggregate-event denial was not authorization"
if reconciliation_registry_read=$("$crdb" sql --url="$reconciliation_url" \
    --execute='SELECT count(*) FROM memory_registry_heads' 2>&1); then
    fail "reconciliation member unexpectedly inherited registry reads"
fi
grep -Eiq 'privilege|permission' <<<"$reconciliation_registry_read" \
    || fail "reconciliation registry denial was not authorization"

# The seventh application table is an FK-planning dependency, not a mutation
# target. Prove its one allowed operation and all three denied DML operations
# against the real migration schema before the CLI reserves its receipt.
if ! "$crdb" sql --url="$reconciliation_url" \
    --execute='SELECT count(*) FROM memory_claim_links' >/dev/null; then
    fail "reconciliation member could not read the receipt-FK link parent"
fi
if reconciliation_claim_link_insert=$("$crdb" sql --url="$reconciliation_url" \
    --execute="
        INSERT INTO memory_claim_links (
            tenant_id, project, id, from_claim_id, to_claim_id, relation
        )
        SELECT
            '$reconciliation_tenant_id'::UUID,
            '$reconciliation_project', 1, 2, 3, 'supports'
        WHERE false
    " 2>&1); then
    fail "reconciliation member unexpectedly received claim-link INSERT"
fi
grep -Eiq 'privilege|permission' <<<"$reconciliation_claim_link_insert" \
    || fail "reconciliation claim-link INSERT denial was not authorization"
if reconciliation_claim_link_update=$("$crdb" sql --url="$reconciliation_url" \
    --execute='UPDATE memory_claim_links SET state = state WHERE false' 2>&1); then
    fail "reconciliation member unexpectedly received claim-link UPDATE"
fi
grep -Eiq 'privilege|permission' <<<"$reconciliation_claim_link_update" \
    || fail "reconciliation claim-link UPDATE denial was not authorization"
if reconciliation_claim_link_delete=$("$crdb" sql --url="$reconciliation_url" \
    --execute='DELETE FROM memory_claim_links WHERE false' 2>&1); then
    fail "reconciliation member unexpectedly received claim-link DELETE"
fi
grep -Eiq 'privilege|permission' <<<"$reconciliation_claim_link_delete" \
    || fail "reconciliation claim-link DELETE denial was not authorization"

# Seed the exact three-candidate open graph as root. Two positive decisions
# disagree and are the immutable legacy endpoints; the negative MySQL claim is
# proposition-compatible with both and therefore remains outside the v2 graph.
"$crdb" sql --url="$root_url" --execute="
BEGIN;
INSERT INTO memory_claims (
    tenant_id, project, id, kind, claim_key, subject, predicate, value, text,
    polarity, state, origin, actor, confidence, valid_from, valid_to,
    superseded_by, revision, conflict_eligible, created_at, updated_at
) VALUES
    (
        '$reconciliation_tenant_id', '$reconciliation_project',
        $reconciliation_left_claim_id, 'decision', '$reconciliation_claim_key',
        'fleet-store', 'database-choice', '\"cockroachdb\"'::JSONB,
        '\"cockroachdb\"', 1, 'active', 'operator_asserted',
        NULL, 1.0, NULL, NULL, NULL, 1, true,
        '2026-08-15T09:00:00Z'::TIMESTAMPTZ,
        '2026-08-15T09:00:00Z'::TIMESTAMPTZ
    ),
    (
        '$reconciliation_tenant_id', '$reconciliation_project',
        $reconciliation_right_claim_id, 'decision', '$reconciliation_claim_key',
        'fleet-store', 'database-choice', '\"postgresql\"'::JSONB,
        '\"postgresql\"', 1, 'active', 'operator_asserted',
        NULL, 1.0, NULL, NULL, NULL, 1, true,
        '2026-08-15T09:00:00Z'::TIMESTAMPTZ,
        '2026-08-15T09:00:00Z'::TIMESTAMPTZ
    ),
    (
        '$reconciliation_tenant_id', '$reconciliation_project',
        $reconciliation_compatible_claim_id, 'decision', '$reconciliation_claim_key',
        'fleet-store', 'database-choice', '\"mysql\"'::JSONB,
        '\"mysql\"', -1, 'active', 'operator_asserted',
        NULL, 1.0, NULL, NULL, NULL, 1, true,
        '2026-08-15T09:00:00Z'::TIMESTAMPTZ,
        '2026-08-15T09:00:00Z'::TIMESTAMPTZ
    );
INSERT INTO memory_conflicts (
    tenant_id, project, id, claim_key, kind, state, detector, rationale,
    revision, detected_at, last_seen_at, resolved_at, resolution_kind,
    resolution_reason
) VALUES (
    '$reconciliation_tenant_id', '$reconciliation_project',
    $reconciliation_legacy_conflict_id, '$reconciliation_claim_key',
    'contradiction', 'open', 'same_key_typed_value',
    'preserved open legacy fixture', 7,
    '2026-08-15T09:01:00Z'::TIMESTAMPTZ,
    '2026-08-15T09:01:00Z'::TIMESTAMPTZ,
    NULL, NULL, NULL
);
INSERT INTO memory_conflict_members (
    tenant_id, project, conflict_id, claim_id, role
) VALUES
    (
        '$reconciliation_tenant_id', '$reconciliation_project',
        $reconciliation_legacy_conflict_id, $reconciliation_left_claim_id,
        'claim'
    ),
    (
        '$reconciliation_tenant_id', '$reconciliation_project',
        $reconciliation_legacy_conflict_id, $reconciliation_right_claim_id,
        'claim'
    );
COMMIT;
" >/dev/null

legacy_conflict_before=$(root_scalar "
    SELECT jsonb_build_object(
        'tenant_id', tenant_id::STRING,
        'project', project,
        'id', id,
        'claim_key', claim_key,
        'kind', kind,
        'state', state,
        'detector', detector,
        'rationale', rationale,
        'revision', revision,
        'detected_at', detected_at::STRING,
        'last_seen_at', last_seen_at::STRING,
        'resolved_at', resolved_at::STRING,
        'resolution_kind', resolution_kind,
        'resolution_reason', resolution_reason
    )::STRING
    FROM memory_conflicts
    WHERE tenant_id = '$reconciliation_tenant_id'
      AND project = '$reconciliation_project'
      AND id = $reconciliation_legacy_conflict_id")
legacy_members_before=$(root_scalar "
    SELECT string_agg(claim_id::STRING || ':' || role, '|' ORDER BY claim_id)
    FROM memory_conflict_members
    WHERE tenant_id = '$reconciliation_tenant_id'
      AND project = '$reconciliation_project'
      AND conflict_id = $reconciliation_legacy_conflict_id")
expected_legacy_members="$reconciliation_left_claim_id:claim|$reconciliation_right_claim_id:claim"
test "$legacy_members_before" = "$expected_legacy_members" \
    || fail "seeded legacy membership graph was not exact"

reconciliation_materialized=$(run_reconciliation)
jq -e --arg legacy "$reconciliation_legacy_conflict_id" '
    (keys | sort) == [
        "candidate_count",
        "conflict_id",
        "incompatibility_pair_count",
        "legacy_conflict_id",
        "legacy_conflict_revision",
        "newly_disputed_claim_count",
        "operation",
        "provenance_ambiguous_claim_count",
        "reconciliation_event_id",
        "restored_claim_count",
        "retained_disputed_claim_count",
        "state",
        "v2_member_count",
        "v2_state"
    ] and
    .operation == "apply" and .state == "materialized" and
    .legacy_conflict_id == $legacy and .legacy_conflict_revision == "7" and
    (.conflict_id | type) == "string" and
    (.conflict_id | test("^[1-9][0-9]*$")) and .conflict_id != $legacy and
    (.reconciliation_event_id |
        test("^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")) and
    .v2_state == "open" and .candidate_count == 3 and
    .incompatibility_pair_count == 1 and .v2_member_count == 2 and
    .newly_disputed_claim_count == 2 and .restored_claim_count == 0 and
    .retained_disputed_claim_count == 0 and
    .provenance_ambiguous_claim_count == 0
' <<<"$reconciliation_materialized" >/dev/null \
    || fail "first reconciliation did not return the exact 14-key materialized receipt"
reconciliation_conflict_id=$(jq -r '.conflict_id' <<<"$reconciliation_materialized")
reconciliation_event_id=$(jq -r '.reconciliation_event_id' <<<"$reconciliation_materialized")

test "$(root_scalar "
    SELECT jsonb_build_object(
        'tenant_id', tenant_id::STRING,
        'project', project,
        'id', id,
        'claim_key', claim_key,
        'kind', kind,
        'state', state,
        'detector', detector,
        'rationale', rationale,
        'revision', revision,
        'detected_at', detected_at::STRING,
        'last_seen_at', last_seen_at::STRING,
        'resolved_at', resolved_at::STRING,
        'resolution_kind', resolution_kind,
        'resolution_reason', resolution_reason
    )::STRING
    FROM memory_conflicts
    WHERE tenant_id = '$reconciliation_tenant_id'
      AND project = '$reconciliation_project'
      AND id = $reconciliation_legacy_conflict_id")" = "$legacy_conflict_before" \
    || fail "reconciliation changed immutable legacy conflict bytes"
test "$(root_scalar "
    SELECT string_agg(claim_id::STRING || ':' || role, '|' ORDER BY claim_id)
    FROM memory_conflict_members
    WHERE tenant_id = '$reconciliation_tenant_id'
      AND project = '$reconciliation_project'
      AND conflict_id = $reconciliation_legacy_conflict_id")" = "$legacy_members_before" \
    || fail "reconciliation changed immutable legacy memberships"

assert_root_scalar "reconciled three-candidate lifecycle projection" \
    "SELECT string_agg(
         id::STRING || ':' || state || ':' || revision::STRING,
         '|' ORDER BY id
     )
     FROM memory_claims
     WHERE tenant_id = '$reconciliation_tenant_id'
       AND project = '$reconciliation_project'" \
    "$reconciliation_left_claim_id:disputed:2|$reconciliation_right_claim_id:disputed:2|$reconciliation_compatible_claim_id:active:1"
assert_root_scalar "exact reconciliation conflict lineage count" \
    "SELECT count(*)::STRING
     FROM memory_conflicts
     WHERE tenant_id = '$reconciliation_tenant_id'
       AND project = '$reconciliation_project'" '2'
assert_root_scalar "exact v2 reconciliation lineage cardinality" \
    "SELECT count(*)::STRING
     FROM memory_conflicts
     WHERE tenant_id = '$reconciliation_tenant_id'
       AND project = '$reconciliation_project'
       AND detector = 'same_key_functional_value_v2'" '1'
assert_root_scalar "exact v2 reconciliation lineage" \
    "SELECT claim_key || '|' || kind || '|' || state || '|' || detector || '|' ||
            rationale || '|' || revision::STRING || '|' ||
            CASE WHEN resolved_at IS NULL THEN 'null' ELSE 'set' END || '|' ||
            COALESCE(resolution_kind, 'null') || '|' ||
            COALESCE(resolution_reason, 'null')
     FROM memory_conflicts
     WHERE tenant_id = '$reconciliation_tenant_id'
       AND project = '$reconciliation_project'
       AND id = $reconciliation_conflict_id" \
    "$reconciliation_claim_key|contradiction|open|same_key_functional_value_v2|overlapping lifecycle-current functional-key claims affirm different values or affirm and negate the same value|1|null|null|null"
assert_root_scalar "exact v2 endpoint graph" \
    "SELECT string_agg(claim_id::STRING || ':' || role, '|' ORDER BY claim_id)
     FROM memory_conflict_members
     WHERE tenant_id = '$reconciliation_tenant_id'
       AND project = '$reconciliation_project'
       AND conflict_id = $reconciliation_conflict_id" \
    "$expected_legacy_members"
assert_root_scalar "complete reconciliation membership graph" \
    "SELECT string_agg(
         conflict_id::STRING || ':' || claim_id::STRING || ':' || role,
         '|' ORDER BY
             CASE WHEN conflict_id = $reconciliation_legacy_conflict_id
                  THEN 1 ELSE 2 END,
             conflict_id,
             claim_id
     )
     FROM memory_conflict_members
     WHERE tenant_id = '$reconciliation_tenant_id'
       AND project = '$reconciliation_project'" \
    "$reconciliation_legacy_conflict_id:$reconciliation_left_claim_id:claim|$reconciliation_legacy_conflict_id:$reconciliation_right_claim_id:claim|$reconciliation_conflict_id:$reconciliation_left_claim_id:claim|$reconciliation_conflict_id:$reconciliation_right_claim_id:claim"

assert_root_scalar "exact reconciliation receipt coordinate" \
    "SELECT CASE WHEN count(*) = 1
                       AND COALESCE(bool_and(
                           project = '$reconciliation_project'
                           AND idempotency_key = '$reconciliation_idempotency_key'
                           AND request = jsonb_build_object(
                               'version', 1,
                               'legacy_conflict_id', $reconciliation_legacy_conflict_id,
                               'expected_legacy_revision', 7
                           )
                           AND operation = 'reconcile_conflict_detector_v2'
                           AND claim_id IS NULL
                           AND conflict_id = $reconciliation_conflict_id
                           AND link_id IS NULL
                           AND response IS NOT NULL
                       ), false)
                 THEN 'match' ELSE 'mismatch' END
     FROM memory_mutation_receipts
     WHERE tenant_id = '$reconciliation_tenant_id'
       AND project = '$reconciliation_project'" 'match'
stored_reconciliation_response=$(root_json_object "
    SELECT response::STRING AS json_value
    FROM memory_mutation_receipts
    WHERE tenant_id = '$reconciliation_tenant_id'
      AND project = '$reconciliation_project'
      AND idempotency_key = '$reconciliation_idempotency_key'")
jq -e \
    --arg event "$reconciliation_event_id" \
    --argjson legacy "$reconciliation_legacy_conflict_id" \
    --argjson conflict "$reconciliation_conflict_id" \
    --argjson left "$reconciliation_left_claim_id" \
    --argjson right "$reconciliation_right_claim_id" '
    . == {
        operation: "reconcile_conflict_detector_v2",
        request_version: 1,
        legacy_conflict_id: $legacy,
        legacy_conflict_revision: 7,
        conflict_id: $conflict,
        reconciliation_event_id: $event,
        v2_state: "open",
        candidate_count: 3,
        incompatibility_pair_count: 1,
        v2_member_ids: [$left, $right],
        newly_disputed_claim_ids: [$left, $right],
        restored_claim_ids: [],
        retained_disputed_claim_ids: [],
        provenance_ambiguous_claim_ids: [],
        idempotent_replay: false
    }
' <<<"$stored_reconciliation_response" >/dev/null \
    || fail "stored reconciliation response was not the exact durable receipt"

assert_root_scalar "exact reconciliation aggregate event coordinate" \
    "SELECT CASE WHEN count(*) = 1
                       AND COALESCE(bool_and(
                           event_id = '$reconciliation_event_id'::UUID
                           AND agent = 'private-conflict-reconciliation'
                           AND session_id IS NULL
                           AND event_kind = 'conflict_detector_reconciled'
                           AND entity_kind = 'conflict'
                           AND entity_id = '$reconciliation_conflict_id'
                           AND idempotency_key = '$reconciliation_idempotency_key'
                       ), false)
                 THEN 'match' ELSE 'mismatch' END
     FROM memory_events
     WHERE tenant_id = '$reconciliation_tenant_id'
       AND project = '$reconciliation_project'" 'match'
reconciliation_audit=$(root_json_object "
    SELECT payload::STRING AS json_value
    FROM memory_events
    WHERE tenant_id = '$reconciliation_tenant_id'
      AND project = '$reconciliation_project'
      AND event_id = '$reconciliation_event_id'::UUID")
jq -e \
    --argjson legacy "$reconciliation_legacy_conflict_id" \
    --argjson conflict "$reconciliation_conflict_id" \
    --argjson left "$reconciliation_left_claim_id" \
    --argjson right "$reconciliation_right_claim_id" \
    --argjson compatible "$reconciliation_compatible_claim_id" '
    . == {
        version: 1,
        legacy: {
            conflict_id: $legacy,
            detector: "same_key_typed_value",
            revision: 7,
            state: "open",
            members: [
                {
                    claim_id: $left,
                    role: "claim",
                    state: "active",
                    classification: "current_candidate"
                },
                {
                    claim_id: $right,
                    role: "claim",
                    state: "active",
                    classification: "current_candidate"
                }
            ]
        },
        v2: {
            conflict_id: $conflict,
            detector: "same_key_functional_value_v2",
            state: "open"
        },
        candidates: [
            {
                id: $left,
                revision: 1,
                state: "active",
                polarity: 1,
                valid_from: null,
                valid_to: null,
                conflict_eligible: true,
                legacy_member: true,
                value_sha256: "cd5d639316c4be5bb52ba9a53a5a43f4fd8a9b5e0ffc14c8962ebf75305e18a0"
            },
            {
                id: $right,
                revision: 1,
                state: "active",
                polarity: 1,
                valid_from: null,
                valid_to: null,
                conflict_eligible: true,
                legacy_member: true,
                value_sha256: "5f079352cb473c849b19a27938b2d33074d3318ca7e225ff4f9e8831cbc49fa6"
            },
            {
                id: $compatible,
                revision: 1,
                state: "active",
                polarity: -1,
                valid_from: null,
                valid_to: null,
                conflict_eligible: true,
                legacy_member: false,
                value_sha256: "9ceb3f77795b4cf445581edb91f2a4aecd12fbb04832c63eefe169f275e09a40"
            }
        ],
        incompatibility_pairs: [
            {left_claim_id: $left, right_claim_id: $right}
        ],
        v2_member_ids: [$left, $right],
        newly_disputed: [$left, $right],
        restored: [],
        retained_disputed: [],
        provenance_ambiguous: [],
        restoration_provenance: [],
        bounds: {
            max_current_claims: 256,
            candidate_query_limit: 257,
            max_legacy_members: 256,
            legacy_member_query_limit: 257,
            legacy_member_count: 2,
            max_pre_v2_memberships_per_legacy_member: 1,
            legacy_member_inverse_query_limit_per_claim: 2,
            max_legacy_member_inverse_rows: 512,
            max_unordered_pairs: 32640,
            candidate_count: 3,
            pair_count: 1,
            max_transition_evidence_per_restoration_candidate: 2,
            max_transition_provenance_rows: 512,
            restoration_candidate_count: 0,
            transition_evidence_count: 0
        }
    }
' <<<"$reconciliation_audit" >/dev/null \
    || fail "aggregate reconciliation event did not preserve the exact bounded pair graph"

assert_root_scalar "exact reconciliation claim transition events" \
    "SELECT CASE WHEN count(*) = 2
                       AND count(DISTINCT claim_id) = 2
                       AND string_agg(claim_id::STRING, '|' ORDER BY claim_id) =
                           '$reconciliation_left_claim_id|$reconciliation_right_claim_id'
                       AND COALESCE(bool_and(
                           event_id IS NOT NULL
                           AND event_kind = 'state_transition'
                           AND actor = 'private-conflict-reconciliation'
                           AND reason = 'conflict_detector_reconciled_v2'
                           AND from_state = 'active'
                           AND to_state = 'disputed'
                           AND payload = jsonb_build_object(
                               'reconciliation_event_id', '$reconciliation_event_id'::UUID,
                               'legacy_conflict', jsonb_build_object(
                                   'id', $reconciliation_legacy_conflict_id,
                                   'detector', 'same_key_typed_value'
                               ),
                               'v2_conflict', jsonb_build_object(
                                   'id', $reconciliation_conflict_id,
                                   'detector', 'same_key_functional_value_v2'
                               )
                           )
                       ), false)
                 THEN 'match' ELSE 'mismatch' END
     FROM memory_claim_events
     WHERE tenant_id = '$reconciliation_tenant_id'
       AND project = '$reconciliation_project'" 'match'

# A replay reads the one tenant-wide receipt and changes none of the six direct
# writable reconciliation tables. The SELECT-only receipt-FK link parent is not
# a mutation target. CockroachDB fingerprints cover every index in each direct
# table, so equality freezes more than the scoped row-count footprint.
reconciliation_snapshot_before_replay=$(reconciliation_table_fingerprints)
reconciliation_replay=$(run_reconciliation)
jq -e --argjson first "$reconciliation_materialized" '
    (keys | sort) == [
        "candidate_count",
        "conflict_id",
        "incompatibility_pair_count",
        "legacy_conflict_id",
        "legacy_conflict_revision",
        "newly_disputed_claim_count",
        "operation",
        "provenance_ambiguous_claim_count",
        "reconciliation_event_id",
        "restored_claim_count",
        "retained_disputed_claim_count",
        "state",
        "v2_member_count",
        "v2_state"
    ] and
    .state == "exact_replay" and
    (del(.state) == ($first | del(.state)))
' <<<"$reconciliation_replay" >/dev/null \
    || fail "second reconciliation was not the exact durable replay"
reconciliation_snapshot_after_replay=$(reconciliation_table_fingerprints)
test "$reconciliation_snapshot_after_replay" = \
    "$reconciliation_snapshot_before_replay" \
    || fail "exact reconciliation replay changed a durable table fingerprint"

# Reconciliation retains its own prefix-16 gate while the existing control,
# genesis, and successor state machines keep their distinct 3/9/14 floors.
reconciliation_prefix_explain=$("$crdb" sql --url="$reconciliation_url" \
    --format=tsv --execute="
    EXPLAIN SELECT count(*) = 16
               AND min(version) = 1
               AND max(version) = 16
               AND COALESCE(bool_and(success), false)
    FROM _sqlx_migrations
    WHERE version BETWEEN 1 AND 16")
if ! grep -Eq '_sqlx_migrations@(_sqlx_migrations_pkey|primary)' \
    <<<"$reconciliation_prefix_explain"; then
    printf '%s\n' "$reconciliation_prefix_explain" >&2
    fail "reconciliation prefix preflight did not use the primary index"
fi
if ! grep -Eq 'span(s)?:.*\[/1[^]]*-[[:space:]]*/16\]' \
    <<<"$reconciliation_prefix_explain"; then
    printf '%s\n' "$reconciliation_prefix_explain" >&2
    fail "reconciliation prefix preflight did not retain the bounded 1..16 span"
fi

# The one-shot identity is disabled immediately after its exact replay. Remove
# the sole membership edge, prohibit login, clear the password, and prove that
# a fresh TLS authentication cannot use the old credential.
"$crdb" sql --url="$root_url" --execute="
    REVOKE fleet_conflict_reconciliation FROM proof_reconciliation_cli;
    ALTER USER proof_reconciliation_cli WITH NOLOGIN PASSWORD NULL;
" >/dev/null
assert_root_scalar "removed reconciliation member edge" \
    "SELECT count(*)::STRING
     FROM [SHOW GRANTS ON ROLE]
     WHERE role_name IN (
         'fleet_conflict_reconciliation',
         'proof_reconciliation_cli'
     )
        OR member IN (
            'fleet_conflict_reconciliation',
            'proof_reconciliation_cli'
        )" '0'
assert_root_scalar "disabled reconciliation login options" \
    "SELECT options::STRING FROM [SHOW USERS]
     WHERE username = 'proof_reconciliation_cli'" '{NOLOGIN}'
if reconciliation_disabled_auth=$("$crdb" sql --url="$reconciliation_url" \
    --execute='SELECT current_user' 2>&1); then
    fail "disabled reconciliation login unexpectedly authenticated"
fi
grep -Eiq 'authentication|password|nologin|login' \
    <<<"$reconciliation_disabled_auth" \
    || fail "disabled reconciliation login failed for an unexpected reason"

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
    "$altered_successor_approval" "$successor_not_ready" \
    "$successor_failed_prefix" "$successor_ready" "$successor_inserted" \
    "$successor_accepted" "$successor_replay" "$successor_stale" \
    "$successor_interwindow_auth" "$successor_disabled_auth" \
    "$invalid_reconciliation" "$reconciliation_materialized" \
    "$reconciliation_replay" "$reconciliation_event_read" \
    "$reconciliation_registry_read" "$reconciliation_claim_link_insert" \
    "$reconciliation_claim_link_update" "$reconciliation_claim_link_delete" \
    "$reconciliation_disabled_auth" \
    "$control_registry_read" "$runtime_registry_read"
do
    for secret in \
        "$control_password" \
        "$activation_password" \
        "$runtime_password" \
        "$successor_password" \
        "$reconciliation_password"
    do
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
    "private successor registry activation receipts:" \
    "$successor_ready" \
    "$successor_inserted" \
    "$successor_accepted" \
    "$successor_replay" \
    "private conflict reconciliation receipts:" \
    "$reconciliation_materialized" \
    "$reconciliation_replay"
proof_body_completed=1
