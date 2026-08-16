#!/bin/sh
set -eu

policy=/localstack/publication-reader-role-grants.sql
expected_policy_sha256=ff3ada75aba9443875efb1f430a14829ef864b3f7409ae5d23f7bd381cb65226

if ! policy_hash_output=$(sha256sum "$policy"); then
    echo "publication reader policy could not be hashed" >&2
    exit 66
fi
actual_policy_sha256=$(printf '%s\n' "$policy_hash_output" | awk '{print $1}')
if [ "$actual_policy_sha256" != "$expected_policy_sha256" ]; then
    echo "publication reader policy does not match the reviewed PUBLIC-03 digest" >&2
    exit 65
fi

root_sql() {
    database=$1
    shift
    cockroach sql --insecure --host=cockroach:26257 --database="$database" "$@"
}

root_scalar() {
    database=$1
    statement=$2
    if ! scalar_output=$(root_sql "$database" --format=tsv --execute="$statement"); then
        echo "database boundary audit query failed in $database" >&2
        exit 1
    fi
    printf '%s\n' "$scalar_output" | tail -n 1
}

assert_zero() {
    label=$1
    actual=$2
    if [ "$actual" != 0 ]; then
        echo "database boundary audit is nonzero for $label: $actual" >&2
        exit 1
    fi
}

# Provision the long-lived writer and fixed publication principal. CockroachDB
# insecure mode does not store or authenticate passwords; the distinct URL
# credential fields are application-boundary fixtures only. Retire the one-shot
# migrator before adding either runtime privilege surface.
root_sql fleet_recall --execute="
CREATE USER IF NOT EXISTS fleet_writer;
ALTER USER fleet_writer WITH LOGIN NOCREATEDB NOCREATEROLE;
REVOKE admin FROM fleet_writer;
REVOKE SYSTEM ALL FROM fleet_writer;

CREATE USER IF NOT EXISTS fleet_publication;
ALTER USER fleet_publication WITH NOLOGIN NOCREATEDB NOCREATEROLE;
REVOKE admin FROM fleet_publication;
REVOKE SYSTEM ALL FROM fleet_publication;

ALTER USER fleet_migrator WITH NOLOGIN NOCREATEDB NOCREATEROLE;
REVOKE admin FROM fleet_migrator;
REVOKE SYSTEM ALL FROM fleet_migrator;
" >/dev/null

# Role creation synthesizes PUBLIC routine defaults in each mutable database.
# Establish the policy's documented clean-engine baseline everywhere before
# the first target-role creation, then remove the temporary root memberships.
root_sql fleet_recall --execute="
GRANT fleet_migrator, fleet_writer, fleet_publication TO root;
" >/dev/null
for database in fleet_recall defaultdb postgres; do
    root_sql "$database" --execute="
ALTER DEFAULT PRIVILEGES FOR ROLE
    root, admin, fleet_migrator, fleet_writer, fleet_publication
    REVOKE EXECUTE ON ROUTINES FROM public;
ALTER DEFAULT PRIVILEGES FOR ALL ROLES
    REVOKE EXECUTE ON ROUTINES FROM public;
REVOKE CREATE ON SCHEMA public FROM public;
" >/dev/null
done
root_sql fleet_recall --execute="
REVOKE fleet_migrator, fleet_writer, fleet_publication FROM root;
" >/dev/null

# The writer is DML-only on the current migrated object set. There are no
# future-object defaults: every later migration must run quiesced and reapply
# this boundary before serving resumes.
root_sql fleet_recall --execute="
REVOKE ALL ON DATABASE fleet_recall FROM fleet_writer;
REVOKE ALL ON SCHEMA public FROM fleet_writer;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM fleet_writer;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM fleet_writer;
GRANT CONNECT ON DATABASE fleet_recall TO fleet_writer;
GRANT USAGE ON SCHEMA public TO fleet_writer;
GRANT SELECT, INSERT, UPDATE, DELETE
    ON ALL TABLES IN SCHEMA public TO fleet_writer;
GRANT SELECT, USAGE, UPDATE
    ON ALL SEQUENCES IN SCHEMA public TO fleet_writer;
" >/dev/null

# The reviewed policy requires the external principal to remain NOLOGIN for
# its full apply. The first application creates the logical reader; keep the
# principal quiesced while the now-complete subject and inherited-PUBLIC
# surfaces are audited in every other local database.
root_sql fleet_recall --file="$policy" >/dev/null

database_list=$(root_scalar defaultdb \
    "SELECT string_agg(database_name, ',' ORDER BY database_name)
     FROM [SHOW DATABASES]")
if [ "$database_list" != 'defaultdb,fleet_recall,postgres,system' ]; then
    echo "database boundary cannot audit an unexpected database set" >&2
    exit 1
fi

for database in defaultdb postgres system; do
    # Neither subject may own or hold a direct grant on another database. SHOW
    # GRANTS FOR is evaluated inside each database and also exposes any
    # cluster-global external-connection grant.
    assert_zero "$database direct reader/principal grants" \
        "$(root_scalar "$database" "
            SELECT count(*)
            FROM (
                SELECT * FROM [SHOW GRANTS FOR fleet_publication_reader]
                UNION ALL
                SELECT * FROM [SHOW GRANTS FOR fleet_publication]
            ) AS subject_grant
            WHERE grantee IN ('fleet_publication_reader', 'fleet_publication')
              AND database_name = pg_catalog.current_database()
        ")"
    assert_zero "$database reader/principal ownership" \
        "$(root_scalar "$database" "
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
                'fleet_publication_reader', 'fleet_publication'
            )
        ")"

    # PUBLIC is inherited. Permit only ordinary other-database
    # CONNECT/TEMPORARY/public-schema-USAGE, built-in virtual catalog rows, and
    # the exact immutable system-database exceptions documented by the proof.
    assert_zero "$database inherited PUBLIC current authority" \
        "$(root_scalar "$database" "
            SELECT count(*)
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
        ")"

    # The system database is immutable for user defaults. Its current grants
    # and ownership were audited above; defaults are audited in both mutable
    # non-target databases below.
    [ "$database" != system ] || continue

    application_schemas=$(root_scalar "$database" "
        SELECT string_agg(nspname, ',' ORDER BY nspname)
        FROM pg_catalog.pg_namespace
        WHERE nspname NOT IN (
            'pg_catalog', 'information_schema',
            'crdb_internal', 'pg_extension'
        )
          AND nspname NOT LIKE 'pg_temp_%'
    ")
    if [ "$application_schemas" != public ]; then
        echo "database boundary found an unexpected application schema in $database" >&2
        exit 1
    fi

    assert_zero "$database reader/principal database defaults" \
        "$(root_scalar "$database" "
            SELECT count(*)
            FROM (
                SELECT role, for_all_roles, object_type, grantee,
                       privilege_type, is_grantable
                FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE fleet_publication_reader]
                UNION ALL
                SELECT role, for_all_roles, object_type, grantee,
                       privilege_type, is_grantable
                FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE fleet_publication]
            ) AS subject_default
            WHERE object_type IN (
                'schemas', 'routines', 'tables', 'sequences', 'types'
            )
              AND (
                  role = grantee
                  AND role IN (
                      'fleet_publication_reader', 'fleet_publication'
                  )
                  AND NOT for_all_roles
                  AND privilege_type = 'ALL'
                  AND is_grantable
              ) IS NOT TRUE
        ")"
    assert_zero "$database reader/principal public-schema defaults" \
        "$(root_scalar "$database" "
            SELECT count(*)
            FROM (
                SELECT role, for_all_roles, object_type, grantee,
                       privilege_type, is_grantable
                FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE
                      fleet_publication_reader IN SCHEMA public]
                UNION ALL
                SELECT role, for_all_roles, object_type, grantee,
                       privilege_type, is_grantable
                FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE
                      fleet_publication IN SCHEMA public]
            ) AS subject_default
            WHERE object_type IN (
                'schemas', 'routines', 'tables', 'sequences', 'types'
            )
              AND (
                  role = grantee
                  AND role IN (
                      'fleet_publication_reader', 'fleet_publication'
                  )
                  AND NOT for_all_roles
                  AND privilege_type = 'ALL'
                  AND is_grantable
              ) IS NOT TRUE
        ")"
    assert_zero "$database inherited PUBLIC database defaults" \
        "$(root_scalar "$database" "
            SELECT count(*)
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
        ")"
    assert_zero "$database inherited PUBLIC public-schema defaults" \
        "$(root_scalar "$database" "
            SELECT count(*)
            FROM [SHOW DEFAULT PRIVILEGES FOR GRANTEE public IN SCHEMA public]
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
        ")"
done

assert_zero 'cluster-global reader/principal authority' \
    "$(root_scalar fleet_recall "
        SELECT count(*)
        FROM (
            SELECT * FROM [SHOW GRANTS FOR fleet_publication_reader]
            UNION ALL
            SELECT * FROM [SHOW GRANTS FOR fleet_publication]
        ) AS subject_grant
        WHERE grantee IN ('fleet_publication_reader', 'fleet_publication')
          AND database_name IS NULL
    ")"

assert_zero 'cluster-global PUBLIC authority' \
    "$(root_scalar fleet_recall "
        SELECT count(*)
        FROM [SHOW GRANTS FOR public]
        WHERE grantee = 'public' AND database_name IS NULL
    ")"

# Reapply under the same Compose dependency freeze, then enable the sole public
# login. This second application makes the cross-database audit an explicit
# precondition of use rather than a post-hoc observation.
root_sql fleet_recall --file="$policy" >/dev/null
root_sql fleet_recall --execute="
ALTER USER fleet_publication WITH LOGIN NOCREATEDB NOCREATEROLE;
" >/dev/null

# Leave a narrow, stable terminal assertion in the bootstrap itself. The smoke
# harness independently fingerprints the complete migration and grant rows.
if ! terminal_output=$(root_sql fleet_recall --format=tsv --execute="
SELECT
    (SELECT count(*)::STRING FROM public._sqlx_migrations
      WHERE version BETWEEN 1 AND 17 AND success) || ':' ||
    (SELECT count(*)::STRING FROM [SHOW GRANTS FOR fleet_publication_reader]
      WHERE grantee = 'fleet_publication_reader') || ':' ||
    (SELECT count(*)::STRING FROM [SHOW GRANTS FOR fleet_publication]
      WHERE grantee = 'fleet_publication') || ':' ||
    (SELECT count(*)::STRING FROM [SHOW GRANTS ON ROLE]
      WHERE role_name = 'fleet_publication_reader'
        AND member = 'fleet_publication'
        AND NOT is_admin);
" ); then
    echo "database boundary terminal assertion query failed" >&2
    exit 1
fi
terminal_state=$(printf '%s\n' "$terminal_output" | tail -n 1)
if [ "$terminal_state" != '17:10:0:1' ]; then
    echo "database boundary terminal state differs from 17:10:0:1" >&2
    exit 1
fi

printf '%s\n' 'Migration prefix 17 and publication/writer database boundaries are ready.'
