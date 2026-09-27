#!/bin/sh
# Port of deploy/localstack/database-boundary.sh and ingress-boundary.sh for
# the secure cluster. Same order: quiesce the long-lived principals and retire
# the migrator, clean the creator-scoped PUBLIC routine defaults, apply the
# runtime policy, clean, apply the publication policy, clean, enable the writer
# and publication logins; then the same dance for the ingress receiver. The
# cleanup covers every role the cluster knows (SHOW ROLES) instead of a static
# list, so a rerun after Ory's roles exist still satisfies the policies' gates.
# Every policy fails closed on its own preconditions.
set -eu
host=${CRDB_HOST:?}
policies=/policies

root_sql() {
    database_name=$1
    shift
    cockroach sql --certs-dir=/certs --host="$host" --database="$database_name" "$@"
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

# Comma-separated list of every role except the internal ones, for the
# temporary root memberships that let root alter their default privileges.
grantable_roles() {
    root_sql fleet_recall --format=tsv --execute="
SELECT username FROM [SHOW ROLES]
WHERE username NOT IN ('root', 'admin', 'node', 'public')
ORDER BY username" | tail -n +2 | paste -sd, -
}

clean_public_defaults() {
    operation_label=$1
    roles=$(grantable_roles)
    if [ -n "$roles" ]; then
        run_root_sql "install default-cleanup memberships ($operation_label)" fleet_recall \
            --execute="GRANT $roles TO root;" >/dev/null
    fi
    for_role="root, admin"
    if [ -n "$roles" ]; then
        for_role="root, admin, $roles"
    fi
    for database_name in fleet_recall defaultdb postgres; do
        run_root_sql "$operation_label" "$database_name" --execute="
ALTER DEFAULT PRIVILEGES FOR ROLE $for_role
    REVOKE EXECUTE ON ROUTINES FROM public;
ALTER DEFAULT PRIVILEGES FOR ALL ROLES
    REVOKE EXECUTE ON ROUTINES FROM public;
REVOKE CREATE ON SCHEMA public FROM public;
" >/dev/null
    done
    if [ -n "$roles" ]; then
        run_root_sql "remove default-cleanup memberships ($operation_label)" fleet_recall \
            --execute="REVOKE $roles FROM root;" >/dev/null
    fi
}

quiesce() {
    principal=$1
    run_root_sql "quiesce $principal" fleet_recall --execute="
CREATE USER IF NOT EXISTS $principal;
ALTER USER $principal WITH NOLOGIN NOCREATEDB NOCREATEROLE;
REVOKE admin FROM $principal;
REVOKE SYSTEM ALL FROM $principal;
REVOKE ALL ON DATABASE fleet_recall FROM $principal;
REVOKE ALL ON SCHEMA public FROM $principal;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM $principal;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM $principal;
" >/dev/null
}

quiesce fleet_writer
quiesce fleet_publication
quiesce fleet_ingress
quiesce fleet_enrollment
run_root_sql 'retire the migrator' fleet_recall --execute="
ALTER USER fleet_migrator WITH NOLOGIN NOCREATEDB NOCREATEROLE;
REVOKE admin FROM fleet_migrator;
REVOKE SYSTEM ALL FROM fleet_migrator;
" >/dev/null

clean_public_defaults 'baseline before the runtime policy'
run_root_sql 'runtime writer policy apply' fleet_recall \
    --file="$policies/runtime-role-grants.sql" >/dev/null
clean_public_defaults 'after the runtime policy'
run_root_sql 'publication reader policy apply' fleet_recall \
    --file="$policies/publication-reader-role-grants.sql" >/dev/null
clean_public_defaults 'after the publication policy'
clean_public_defaults 'baseline before the ingress policy'
run_root_sql 'ingress receiver policy apply' fleet_recall \
    --file="$policies/ingress-receiver-role-grants.sql" >/dev/null
clean_public_defaults 'after the ingress policy'
run_root_sql 'enrollment manager policy apply' fleet_recall \
    --file="$policies/enrollment-role-grants.sql" >/dev/null
clean_public_defaults 'after the enrollment policy'
run_root_sql 'enable the runtime logins after every policy passed' fleet_recall --execute="
ALTER USER fleet_writer WITH LOGIN NOCREATEDB NOCREATEROLE;
ALTER USER fleet_publication WITH LOGIN NOCREATEDB NOCREATEROLE;
ALTER USER fleet_ingress WITH LOGIN NOCREATEDB NOCREATEROLE;
" >/dev/null

printf '%s\n' 'runtime, publication, ingress and enrollment database boundaries are ready; enrollment remains NOLOGIN until the workstation enables it'
