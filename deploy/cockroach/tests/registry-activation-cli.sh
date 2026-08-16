#!/usr/bin/env bash
set -euo pipefail

# This is the authoritative connected correctness proof. It uses the exact
# official CockroachDB binary, discovers and runs every named opt-in live test
# in this authoritative matrix, and exercises the three private CLIs included
# in this proof (control bootstrap, genesis activation, and conflict
# reconciliation) on one secure local server. The one server and its result are
# never Docker parity evidence.
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

# The policy is safe in a reused administrator session only if it pins built-in
# resolution first, binds itself to fleet_recall, fully qualifies every
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
        '(FROM|ON TABLE|ON SEQUENCE)[[:space:]]+(_sqlx_migrations|memory_(claims|claim_events|conflicts|conflict_members|mutation_receipts|events|conflict_id_seq))([^[:alnum:]_]|$)' \
        || true)
assert_exact "unqualified reconciliation policy application references" \
    "$unqualified_policy_application_references" ''

qualified_policy_application_references=$(sed -E 's/--.*$//' \
    "$reconciliation_policy" \
    | grep -Eo \
        '(FROM|ON TABLE|ON SEQUENCE)[[:space:]]+public\.(_sqlx_migrations|memory_(claims|claim_events|conflicts|conflict_members|mutation_receipts|events|conflict_id_seq))' \
    | sed -E 's/^(FROM|ON TABLE|ON SEQUENCE)[[:space:]]+//' \
    | sort)
expected_qualified_policy_application_references='public._sqlx_migrations
public._sqlx_migrations
public.memory_claim_events
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
    CREATE USER proof_reconciliation_cli WITH PASSWORD '$reconciliation_password';
" >/dev/null

# CockroachDB v26.2 seeds database-level PUBLIC EXECUTE defaults for routines
# under every role, and role-specific cleanup requires membership in the
# grantor. Root and admin are cleaned directly; temporarily inherit the seven
# custom grantors while removing all nine named-grantor rows, then attempt the
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
           'proof_reconciliation_cli'
       )" '0'
assert_public_routine_defaults "before conflict reconciliation policy" \
    'role=ALL,true,routines,public,EXECUTE,false'

# The target must be absent during bootstrap. Before the first apply, inventory
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
    'SELECT current_database()' 'fleet_recall'
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

# Freeze the complete direct repository surface before provisioning the
# one-shot membership: sixteen table/sequence rows, sole database CONNECT, sole
# schema USAGE, no inherited PUBLIC application grants, and no target/PUBLIC
# system authority.
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
reconciliation_url="postgresql://proof_reconciliation_cli:${reconciliation_password}@${host_port}/fleet_recall?sslmode=verify-full&sslrootcert=${ca_path}"

cargo build --locked \
    --bin ostk-control-bootstrap \
    --bin ostk-registry-activate \
    --bin ostk-conflict-reconcile >/dev/null
reconciliation_binary="$repo_root/target/debug/ostk-conflict-reconcile"
test -x "$reconciliation_binary" \
    || fail "locked build did not produce the conflict reconciliation CLI"

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
    local table_name
    for table_name in \
        memory_claims \
        memory_claim_events \
        memory_conflicts \
        memory_conflict_members \
        memory_mutation_receipts \
        memory_events
    do
        printf '%s\n' "$table_name"
        root_scalar "
            SELECT *
            FROM [SHOW EXPERIMENTAL_FINGERPRINTS FROM TABLE $table_name]
            ORDER BY 1, 2"
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
stored_reconciliation_response=$(root_scalar "
    SELECT response::STRING
    FROM memory_mutation_receipts
    WHERE tenant_id = '$reconciliation_tenant_id'
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
reconciliation_audit=$(root_scalar "
    SELECT payload::STRING
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

# A replay reads the one tenant-wide receipt and changes none of the six
# reconciliation tables. CockroachDB fingerprints cover every index in each
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
    "$invalid_reconciliation" "$reconciliation_materialized" \
    "$reconciliation_replay" "$reconciliation_event_read" \
    "$reconciliation_registry_read" "$reconciliation_disabled_auth" \
    "$control_registry_read" "$runtime_registry_read"
do
    for secret in \
        "$control_password" \
        "$activation_password" \
        "$runtime_password" \
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
    "private conflict reconciliation receipts:" \
    "$reconciliation_materialized" \
    "$reconciliation_replay"
proof_body_completed=1
