#!/bin/sh
set -eu

runtime_policy=/localstack/runtime-role-grants.sql
expected_runtime_policy_sha256=f9fcf11f8b9cb6df83a245b2843f099bdd00352c274d1e37f6983992847b06cf
publication_policy=/localstack/publication-reader-role-grants.sql
expected_publication_policy_sha256=ff3ada75aba9443875efb1f430a14829ef864b3f7409ae5d23f7bd381cb65226

verify_policy_digest() {
    policy_file=$1
    expected_digest=$2
    policy_label=$3
    if ! policy_hash_output=$(sha256sum "$policy_file"); then
        echo "$policy_label policy could not be hashed" >&2
        exit 66
    fi
    actual_digest=$(printf '%s\n' "$policy_hash_output" | awk '{print $1}')
    if [ "$actual_digest" != "$expected_digest" ]; then
        echo "$policy_label policy does not match its reviewed digest" >&2
        exit 65
    fi
}

verify_policy_digest \
    "$runtime_policy" "$expected_runtime_policy_sha256" 'runtime writer'
verify_policy_digest \
    "$publication_policy" "$expected_publication_policy_sha256" \
    'publication reader'

root_sql() {
    database_name=$1
    shift
    cockroach sql --insecure --host=cockroach:26257 \
        --database="$database_name" "$@"
}

run_root_sql() {
    operation_label=$1
    database_name=$2
    shift 2
    if ! root_sql "$database_name" "$@"; then
        echo "database boundary operation failed in $database_name: $operation_label" >&2
        exit 1
    fi
}

root_scalar() {
    database_name=$1
    statement=$2
    if ! scalar_output=$(root_sql "$database_name" \
        --format=tsv --execute="$statement"); then
        echo "database boundary audit query failed in $database_name" >&2
        exit 1
    fi
    printf '%s\n' "$scalar_output" | tail -n 1
}

assert_value() {
    label=$1
    expected=$2
    actual=$3
    if [ "$actual" != "$expected" ]; then
        echo "database boundary audit differs for $label: expected $expected, observed $actual" >&2
        exit 1
    fi
}

assert_zero() {
    assert_value "$1" 0 "$2"
}

runtime_policy_apply_count=0
publication_policy_apply_count=0
apply_runtime_policy() {
    runtime_policy_apply_count=$((runtime_policy_apply_count + 1))
    run_root_sql 'runtime writer policy apply' fleet_recall \
        --file="$runtime_policy" >/dev/null
}

apply_publication_policy() {
    publication_policy_apply_count=$((publication_policy_apply_count + 1))
    run_root_sql 'publication reader policy apply' fleet_recall \
        --file="$publication_policy" >/dev/null
}

# In insecure mode the URL password fields remain application-boundary
# fixtures, but the database identities and role graph are real. Quiesce both
# long-lived principals before any policy apply, retire the one-shot migrator,
# and remove the former direct writer surface so a rerun cannot inherit it.
run_root_sql 'quiesce principals and retire migrator' fleet_recall --execute="
CREATE USER IF NOT EXISTS fleet_writer;
ALTER USER fleet_writer WITH NOLOGIN NOCREATEDB NOCREATEROLE;
REVOKE admin FROM fleet_writer;
REVOKE SYSTEM ALL FROM fleet_writer;

CREATE USER IF NOT EXISTS fleet_publication;
ALTER USER fleet_publication WITH NOLOGIN NOCREATEDB NOCREATEROLE;
REVOKE admin FROM fleet_publication;
REVOKE SYSTEM ALL FROM fleet_publication;

ALTER USER fleet_migrator WITH NOLOGIN NOCREATEDB NOCREATEROLE;
REVOKE admin FROM fleet_migrator;
REVOKE SYSTEM ALL FROM fleet_migrator;

REVOKE ALL ON DATABASE fleet_recall FROM fleet_writer, fleet_publication;
REVOKE ALL ON SCHEMA public FROM fleet_writer, fleet_publication;
REVOKE ALL ON ALL TABLES IN SCHEMA public
    FROM fleet_writer, fleet_publication;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public
    FROM fleet_writer, fleet_publication;
" >/dev/null

# The one-shot migrator is intentionally different from both long-lived
# subjects: it remains the owner of the SQLx migration ledger and migration-
# created objects so ownership is not reassigned implicitly, but it has no
# usable login, admin membership, or system privilege after retirement.
migrator_retirement_state=$(root_scalar fleet_recall "
SELECT
    (SELECT count(*)::STRING FROM [SHOW USERS]
      WHERE username = 'fleet_migrator'
        AND options::STRING = '{NOLOGIN}') || ':' ||
    (SELECT count(*)::STRING FROM [SHOW GRANTS ON ROLE admin]
      WHERE member = 'fleet_migrator') || ':' ||
    (SELECT count(*)::STRING FROM [SHOW SYSTEM GRANTS]
      WHERE grantee = 'fleet_migrator') || ':' ||
    (SELECT count(*)::STRING FROM [SHOW GRANTS ON ROLE]
      WHERE role_name = 'fleet_migrator'
         OR member = 'fleet_migrator') || ':' ||
    (SELECT count(*)::STRING
       FROM pg_catalog.pg_class AS relation_object
       JOIN pg_catalog.pg_namespace AS schema_object
         ON schema_object.oid = relation_object.relnamespace
       JOIN pg_catalog.pg_roles AS owner_role
         ON owner_role.oid = relation_object.relowner
      WHERE schema_object.nspname = 'public'
        AND relation_object.relname = '_sqlx_migrations'
        AND relation_object.relkind = 'r'
        AND owner_role.rolname = 'fleet_migrator');
")
assert_value 'retired migrator NOLOGIN/admin/system/edge/ledger-owner state' \
    '1:0:0:0:1' "$migrator_retirement_state"

# Role creation synthesizes creator-scoped PUBLIC routine defaults in each
# mutable database. Establish the clean-engine baseline for every role that
# exists before either target role is created, then remove the temporary root
# memberships before the first fail-closed policy gate.
run_root_sql 'install initial temporary default-cleanup memberships' \
    fleet_recall --execute="
GRANT fleet_migrator, fleet_writer, fleet_publication TO root;
" >/dev/null
for database_name in fleet_recall defaultdb postgres; do
    run_root_sql 'clean initial PUBLIC creator defaults' \
        "$database_name" --execute="
ALTER DEFAULT PRIVILEGES FOR ROLE
    root, admin, fleet_migrator, fleet_writer, fleet_publication
    REVOKE EXECUTE ON ROUTINES FROM public;
ALTER DEFAULT PRIVILEGES FOR ALL ROLES
    REVOKE EXECUTE ON ROUTINES FROM public;
REVOKE CREATE ON SCHEMA public FROM public;
" >/dev/null
done
run_root_sql 'remove initial temporary default-cleanup memberships' \
    fleet_recall --execute="
REVOKE fleet_migrator, fleet_writer, fleet_publication FROM root;
" >/dev/null

# The runtime policy creates and normalizes fleet_runtime, installs its exact
# forty-seven-row grant matrix, and adds only fleet_runtime -> fleet_writer. The
# principal stays NOLOGIN throughout the policy and the following cleanup.
apply_runtime_policy

# Clean the newly created runtime role's creator-scoped PUBLIC routine rows in
# every mutable database before the publication policy inspects PUBLIC.
run_root_sql 'install runtime target default-cleanup membership' \
    fleet_recall --execute="GRANT fleet_runtime TO root;" >/dev/null
for database_name in fleet_recall defaultdb postgres; do
    run_root_sql 'clean runtime target PUBLIC creator defaults' \
        "$database_name" --execute="
ALTER DEFAULT PRIVILEGES FOR ROLE fleet_runtime
    REVOKE EXECUTE ON ROUTINES FROM public;
ALTER DEFAULT PRIVILEGES FOR ALL ROLES
    REVOKE EXECUTE ON ROUTINES FROM public;
REVOKE CREATE ON SCHEMA public FROM public;
" >/dev/null
done
run_root_sql 'remove runtime target default-cleanup membership' \
    fleet_recall --execute="REVOKE fleet_runtime FROM root;" >/dev/null

# The publication policy can now create its logical reader against the same
# clean inherited-PUBLIC baseline. Its fixed principal also remains NOLOGIN.
apply_publication_policy

# Both targets now exist. Remove creator-scoped PUBLIC routine defaults for
# both target/principal pairs in every mutable database. No temporary root
# membership survives this block, so the subsequent role-graph audit observes
# only the two intended leaf edges.
run_root_sql 'install final default-cleanup memberships' \
    fleet_recall --execute="
GRANT fleet_migrator, fleet_runtime, fleet_writer,
      fleet_publication_reader, fleet_publication TO root;
" >/dev/null
for database_name in fleet_recall defaultdb postgres; do
    run_root_sql 'clean all runtime/publication PUBLIC creator defaults' \
        "$database_name" --execute="
ALTER DEFAULT PRIVILEGES FOR ROLE
    root, admin, fleet_migrator, fleet_runtime, fleet_writer,
    fleet_publication_reader, fleet_publication
    REVOKE EXECUTE ON ROUTINES FROM public;
ALTER DEFAULT PRIVILEGES FOR ALL ROLES
    REVOKE EXECUTE ON ROUTINES FROM public;
REVOKE CREATE ON SCHEMA public FROM public;
" >/dev/null
done
run_root_sql 'remove final default-cleanup memberships' \
    fleet_recall --execute="
REVOKE fleet_migrator, fleet_runtime, fleet_writer,
       fleet_publication_reader, fleet_publication FROM root;
" >/dev/null

audit_complete_boundary() {
    database_list=$(root_scalar defaultdb \
        "SELECT string_agg(database_name, ',' ORDER BY database_name)
         FROM [SHOW DATABASES]")
    assert_value 'exact database inventory' \
        'defaultdb,fleet_recall,postgres,system' "$database_list"

    for database_name in defaultdb fleet_recall postgres system; do
        if [ "$database_name" = fleet_recall ]; then
            # Logical-role grants are checked exactly inside each policy and by
            # the smoke fingerprint. Fixed principals are always direct-grant
            # free, including in the target database.
            assert_zero "$database_name direct principal grants" \
                "$(root_scalar "$database_name" "
                    SELECT count(*)
                    FROM (
                        SELECT * FROM [SHOW GRANTS FOR fleet_writer]
                        UNION ALL
                        SELECT * FROM [SHOW GRANTS FOR fleet_publication]
                    ) AS subject_grant
                    WHERE grantee IN ('fleet_writer', 'fleet_publication')
                      AND database_name = pg_catalog.current_database()
                ")"
        else
            assert_zero "$database_name direct runtime/publication grants" \
                "$(root_scalar "$database_name" "
                    SELECT count(*)
                    FROM (
                        SELECT * FROM [SHOW GRANTS FOR fleet_runtime]
                        UNION ALL
                        SELECT * FROM [SHOW GRANTS FOR fleet_writer]
                        UNION ALL
                        SELECT * FROM [SHOW GRANTS FOR fleet_publication_reader]
                        UNION ALL
                        SELECT * FROM [SHOW GRANTS FOR fleet_publication]
                    ) AS subject_grant
                    WHERE grantee IN (
                        'fleet_runtime', 'fleet_writer',
                        'fleet_publication_reader', 'fleet_publication'
                    )
                      AND database_name = pg_catalog.current_database()
                ")"
        fi

        # The retired fleet_migrator deliberately remains the owner of objects
        # it created. This ownership denial is exact only for the two logical
        # long-lived roles and their fixed external principals.
        assert_zero "$database_name runtime/publication ownership" \
            "$(root_scalar "$database_name" "
                SELECT count(*)
                FROM (
                    SELECT database_object.datdba AS owner_oid
                    FROM pg_catalog.pg_database AS database_object
                    WHERE database_object.datname = pg_catalog.current_database()
                    UNION ALL
                    SELECT schema_object.nspowner
                    FROM pg_catalog.pg_namespace AS schema_object
                    UNION ALL
                    SELECT relation_object.relowner
                    FROM pg_catalog.pg_class AS relation_object
                    WHERE relation_object.relkind IN ('r', 'S', 'v', 'm', 'p')
                    UNION ALL
                    SELECT function_object.proowner
                    FROM pg_catalog.pg_proc AS function_object
                    UNION ALL
                    SELECT type_object.typowner
                    FROM pg_catalog.pg_type AS type_object
                ) AS owned_object
                JOIN pg_catalog.pg_roles AS owner_role
                  ON owner_role.oid = owned_object.owner_oid
                WHERE owner_role.rolname IN (
                    'fleet_runtime', 'fleet_writer',
                    'fleet_publication_reader', 'fleet_publication'
                )
            ")"

        # PUBLIC is inherited. The target database admits only built-in
        # virtual/temporary fallback rows. Other databases may retain ordinary
        # CONNECT/TEMPORARY and public-schema USAGE; system has two immutable
        # documented exceptions.
        assert_zero "$database_name inherited PUBLIC current authority" \
            "$(root_scalar "$database_name" "
                SELECT count(*)
                FROM [SHOW GRANTS FOR public]
                WHERE grantee = 'public'
                  AND database_name = pg_catalog.current_database()
                  AND NOT (
                      (pg_catalog.current_database() <> 'fleet_recall'
                          AND object_type = 'database'
                          AND privilege_type IN ('CONNECT', 'TEMPORARY')
                          AND NOT is_grantable)
                      OR (pg_catalog.current_database() <> 'fleet_recall'
                          AND object_type = 'schema'
                          AND schema_name = 'public'
                          AND object_name IS NULL
                          AND privilege_type = 'USAGE'
                          AND NOT is_grantable)
                      OR (object_type = 'schema'
                          AND schema_name LIKE 'pg_temp_%'
                          AND object_name IS NULL
                          AND privilege_type IN ('CREATE', 'USAGE')
                          AND NOT is_grantable)
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
            ")"

        # The system database is immutable for user defaults. Current grants
        # and ownership were checked above; every mutable database must have
        # exactly one application schema and no non-intrinsic subject default.
        [ "$database_name" != system ] || continue

        application_schemas=$(root_scalar "$database_name" "
            SELECT string_agg(nspname, ',' ORDER BY nspname)
            FROM pg_catalog.pg_namespace
            WHERE nspname NOT IN (
                'pg_catalog',
                'information_schema',
                'crdb_internal',
                'pg_extension'
            )
              AND nspname NOT LIKE 'pg_temp_%'
        ")
        assert_value "$database_name exact application schema inventory" \
            public "$application_schemas"

        assert_zero "$database_name runtime/publication subject defaults" \
            "$(root_scalar "$database_name" "
                SELECT count(*)
                FROM (
                    SELECT role, for_all_roles, object_type, grantee,
                           privilege_type, is_grantable
                    FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE fleet_runtime]
                    UNION ALL
                    SELECT role, for_all_roles, object_type, grantee,
                           privilege_type, is_grantable
                    FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE fleet_runtime IN SCHEMA public]
                    UNION ALL
                    SELECT role, for_all_roles, object_type, grantee,
                           privilege_type, is_grantable
                    FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE fleet_writer]
                    UNION ALL
                    SELECT role, for_all_roles, object_type, grantee,
                           privilege_type, is_grantable
                    FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE fleet_writer IN SCHEMA public]
                    UNION ALL
                    SELECT role, for_all_roles, object_type, grantee,
                           privilege_type, is_grantable
                    FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE fleet_publication_reader]
                    UNION ALL
                    SELECT role, for_all_roles, object_type, grantee,
                           privilege_type, is_grantable
                    FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE fleet_publication_reader IN SCHEMA public]
                    UNION ALL
                    SELECT role, for_all_roles, object_type, grantee,
                           privilege_type, is_grantable
                    FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE fleet_publication]
                    UNION ALL
                    SELECT role, for_all_roles, object_type, grantee,
                           privilege_type, is_grantable
                    FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE fleet_publication IN SCHEMA public]
                ) AS subject_default
                WHERE object_type IN (
                    'schemas', 'routines', 'tables', 'sequences', 'types'
                )
                  AND (
                      role = grantee
                      AND role IN (
                          'fleet_runtime', 'fleet_writer',
                          'fleet_publication_reader', 'fleet_publication'
                      )
                      AND NOT for_all_roles
                      AND privilege_type = 'ALL'
                      AND is_grantable
                  ) IS NOT TRUE
            ")"

        # Final composition permits only intrinsic type USAGE and the one
        # clean-engine all-roles routine row. In particular, neither target nor
        # principal may retain creator-scoped PUBLIC routine EXECUTE defaults.
        assert_zero "$database_name inherited PUBLIC defaults" \
            "$(root_scalar "$database_name" "
                SELECT count(*)
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
            ")"
    done

    assert_zero 'cluster-global runtime/publication direct authority' \
        "$(root_scalar fleet_recall "
            SELECT count(*)
            FROM (
                SELECT * FROM [SHOW GRANTS FOR fleet_runtime]
                UNION ALL
                SELECT * FROM [SHOW GRANTS FOR fleet_writer]
                UNION ALL
                SELECT * FROM [SHOW GRANTS FOR fleet_publication_reader]
                UNION ALL
                SELECT * FROM [SHOW GRANTS FOR fleet_publication]
            ) AS subject_grant
            WHERE grantee IN (
                'fleet_runtime', 'fleet_writer',
                'fleet_publication_reader', 'fleet_publication'
            )
              AND database_name IS NULL
        ")"

    assert_zero 'cluster-global PUBLIC authority' \
        "$(root_scalar fleet_recall "
            SELECT count(*)
            FROM [SHOW GRANTS FOR public]
            WHERE grantee = 'public' AND database_name IS NULL
        ")"

    assert_zero 'runtime/publication/PUBLIC system authority' \
        "$(root_scalar fleet_recall "
            SELECT count(*)
            FROM [SHOW SYSTEM GRANTS]
            WHERE grantee IN (
                'public', 'fleet_runtime', 'fleet_writer',
                'fleet_publication_reader', 'fleet_publication'
            )
        ")"

    role_edge_state=$(root_scalar fleet_recall "
        SELECT count(*)::STRING || ':' ||
               (count(*) FILTER (
                   WHERE role_name = 'fleet_runtime'
                     AND member = 'fleet_writer'
                     AND NOT is_admin
               ))::STRING || ':' ||
               (count(*) FILTER (
                   WHERE role_name = 'fleet_publication_reader'
                     AND member = 'fleet_publication'
                     AND NOT is_admin
               ))::STRING
        FROM [SHOW GRANTS ON ROLE]
        WHERE role_name IN (
                'fleet_runtime', 'fleet_writer',
                'fleet_publication_reader', 'fleet_publication'
              )
           OR member IN (
                'fleet_runtime', 'fleet_writer',
                'fleet_publication_reader', 'fleet_publication'
              )
    ")
    assert_value 'exact two disjoint non-admin leaf edges' '2:1:1' \
        "$role_edge_state"

    quiesced_state=$(root_scalar fleet_recall "
        SELECT count(*)::STRING || ':' ||
               (count(*) FILTER (WHERE options::STRING = '{NOLOGIN}'))::STRING
        FROM [SHOW USERS]
        WHERE username IN (
            'fleet_runtime', 'fleet_writer',
            'fleet_publication_reader', 'fleet_publication'
        )
    ")
    assert_value 'all logical roles and principals quiesced' '4:4' \
        "$quiesced_state"
}

# Audit after both target roles exist and after all creator-default cleanup.
# Reapply both checksum-pinned policies under the same Compose dependency
# freeze, then repeat the complete audit so re-enable is conditional on their
# final composed state rather than on an earlier snapshot.
audit_complete_boundary
apply_runtime_policy
apply_publication_policy
audit_complete_boundary
assert_value 'exact runtime policy apply count' 2 \
    "$runtime_policy_apply_count"
assert_value 'exact publication policy apply count' 2 \
    "$publication_policy_apply_count"

# Authentication is the final state change. Both principals become LOGIN only
# after their policies, cross-database/default/ownership audit, exact edge
# graph, and final reapply have all succeeded.
run_root_sql 'enable exact long-lived principals' fleet_recall --execute="
ALTER USER fleet_writer WITH LOGIN NOCREATEDB NOCREATEROLE;
ALTER USER fleet_publication WITH LOGIN NOCREATEDB NOCREATEROLE;
" >/dev/null

if ! terminal_output=$(root_sql fleet_recall --format=tsv --execute="
SELECT
    (SELECT count(*)::STRING FROM public._sqlx_migrations
      WHERE version BETWEEN 1 AND 17 AND success) || ':' ||
    (SELECT count(*)::STRING FROM [SHOW USERS]
      WHERE username = 'fleet_migrator'
        AND options::STRING = '{NOLOGIN}') || ':' ||
    (SELECT count(*)::STRING FROM [SHOW GRANTS ON ROLE admin]
      WHERE member = 'fleet_migrator') || ':' ||
    (SELECT count(*)::STRING FROM [SHOW SYSTEM GRANTS]
      WHERE grantee = 'fleet_migrator') || ':' ||
    (SELECT count(*)::STRING FROM [SHOW GRANTS ON ROLE]
      WHERE role_name = 'fleet_migrator'
         OR member = 'fleet_migrator') || ':' ||
    (SELECT count(*)::STRING
       FROM pg_catalog.pg_class AS relation_object
       JOIN pg_catalog.pg_namespace AS schema_object
         ON schema_object.oid = relation_object.relnamespace
       JOIN pg_catalog.pg_roles AS owner_role
         ON owner_role.oid = relation_object.relowner
      WHERE schema_object.nspname = 'public'
        AND relation_object.relname = '_sqlx_migrations'
        AND relation_object.relkind = 'r'
        AND owner_role.rolname = 'fleet_migrator') || ':' ||
    (SELECT count(*)::STRING FROM [SHOW GRANTS FOR fleet_runtime]
      WHERE grantee = 'fleet_runtime') || ':' ||
    (SELECT count(*)::STRING FROM [SHOW GRANTS FOR fleet_writer]
      WHERE grantee = 'fleet_writer') || ':' ||
    (SELECT count(*)::STRING FROM [SHOW GRANTS ON ROLE]
      WHERE role_name = 'fleet_runtime'
        AND member = 'fleet_writer' AND NOT is_admin) || ':' ||
    (SELECT count(*)::STRING FROM [SHOW GRANTS FOR fleet_publication_reader]
      WHERE grantee = 'fleet_publication_reader') || ':' ||
    (SELECT count(*)::STRING FROM [SHOW GRANTS FOR fleet_publication]
      WHERE grantee = 'fleet_publication') || ':' ||
    (SELECT count(*)::STRING FROM [SHOW GRANTS ON ROLE]
      WHERE role_name = 'fleet_publication_reader'
        AND member = 'fleet_publication' AND NOT is_admin) || ':' ||
    (SELECT count(*)::STRING FROM [SHOW USERS]
      WHERE username IN ('fleet_runtime', 'fleet_publication_reader')
        AND options::STRING = '{NOLOGIN}') || ':' ||
    (SELECT count(*)::STRING FROM [SHOW USERS]
      WHERE username IN ('fleet_writer', 'fleet_publication')
        AND options::STRING = '{}') || ':' ||
    (SELECT count(*)::STRING FROM [SHOW SYSTEM GRANTS]
      WHERE grantee IN (
        'public', 'fleet_runtime', 'fleet_writer',
        'fleet_publication_reader', 'fleet_publication'
      ));
"); then
    echo "database boundary terminal assertion query failed" >&2
    exit 1
fi
terminal_state=$(printf '%s\n' "$terminal_output" | tail -n 1)
assert_value 'terminal runtime/publication state' \
    '17:1:0:0:0:1:47:0:1:10:0:1:2:2:0' "$terminal_state"

printf '%s\n' \
    'Migration prefix 17 and exact runtime/publication database boundaries are ready.'
