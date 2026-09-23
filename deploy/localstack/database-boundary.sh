#!/bin/sh
set -eu

# Provision the long-lived writer and publication principals after migration:
# quiesce them, retire the one-shot migrator, apply the runtime and publication
# policies from deploy/cockroach with the PUBLIC-default cleanup each needs, and
# only then enable both logins. The policies fail closed on their own
# preconditions.
runtime_policy=/localstack/runtime-role-grants.sql
publication_policy=/localstack/publication-reader-role-grants.sql

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

apply_runtime_policy() {
    run_root_sql 'runtime writer policy apply' fleet_recall \
        --file="$runtime_policy" >/dev/null
}

apply_publication_policy() {
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

# The runtime policy creates and normalizes fleet_runtime, installs its grant
# matrix, and adds only fleet_runtime -> fleet_writer. The principal stays
# NOLOGIN throughout the policy and the following cleanup.
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
# membership survives this block.
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

# Authentication is the final state change. Both principals become LOGIN only
# after both policies and the PUBLIC-default cleanup have succeeded.
run_root_sql 'enable exact long-lived principals' fleet_recall --execute="
ALTER USER fleet_writer WITH LOGIN NOCREATEDB NOCREATEROLE;
ALTER USER fleet_publication WITH LOGIN NOCREATEDB NOCREATEROLE;
" >/dev/null

printf '%s\n' 'Runtime and publication database boundaries are ready.'
