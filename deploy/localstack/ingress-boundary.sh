#!/bin/sh
set -eu

# Provision the webhook receiver's principal after migration and after
# database-boundary.sh (ADR 0008 D12): quiesce fleet_ingress, clean the
# creator-scoped PUBLIC routine defaults its creation synthesized, apply the
# ingress-receiver policy from deploy/cockroach, clean the defaults of the
# role it creates, and only then enable the login. The policy fails closed on
# its own preconditions (the migration 1..36 gate among them).
ingress_policy=/localstack/ingress-receiver-role-grants.sql

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
        echo "ingress boundary operation failed in $database_name: $operation_label" >&2
        exit 1
    fi
}

clean_public_defaults() {
    operation_label=$1
    roles=$2
    for database_name in fleet_recall defaultdb postgres; do
        run_root_sql "$operation_label" "$database_name" --execute="
ALTER DEFAULT PRIVILEGES FOR ROLE $roles
    REVOKE EXECUTE ON ROUTINES FROM public;
ALTER DEFAULT PRIVILEGES FOR ALL ROLES
    REVOKE EXECUTE ON ROUTINES FROM public;
REVOKE CREATE ON SCHEMA public FROM public;
" >/dev/null
    done
}

# The principal exists NOLOGIN (its password or identity binding is set
# outside this helper); quiesce it and strip any direct authority a rerun
# could inherit.
run_root_sql 'quiesce the ingress principal' fleet_recall --execute="
CREATE USER IF NOT EXISTS fleet_ingress;
ALTER USER fleet_ingress WITH NOLOGIN NOCREATEDB NOCREATEROLE;
REVOKE admin FROM fleet_ingress;
REVOKE SYSTEM ALL FROM fleet_ingress;
REVOKE ALL ON DATABASE fleet_recall FROM fleet_ingress;
REVOKE ALL ON SCHEMA public FROM fleet_ingress;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM fleet_ingress;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM fleet_ingress;
" >/dev/null

# Creating the principal synthesized creator-scoped PUBLIC routine defaults in
# each mutable database; remove them before the policy's PUBLIC gate.
run_root_sql 'install principal default-cleanup membership' fleet_recall \
    --execute="GRANT fleet_ingress TO root;" >/dev/null
clean_public_defaults 'clean principal PUBLIC creator defaults' fleet_ingress
run_root_sql 'remove principal default-cleanup membership' fleet_recall \
    --execute="REVOKE fleet_ingress FROM root;" >/dev/null

run_root_sql 'ingress receiver policy apply' fleet_recall \
    --file="$ingress_policy" >/dev/null

# The policy created fleet_ingress_receiver; clean its creator-scoped PUBLIC
# routine defaults too. No temporary root membership survives this block.
run_root_sql 'install final default-cleanup memberships' fleet_recall \
    --execute="GRANT fleet_ingress_receiver, fleet_ingress TO root;" >/dev/null
clean_public_defaults 'clean ingress PUBLIC creator defaults' \
    'fleet_ingress_receiver, fleet_ingress'
run_root_sql 'remove final default-cleanup memberships' fleet_recall \
    --execute="REVOKE fleet_ingress_receiver, fleet_ingress FROM root;" >/dev/null

# Authentication is the final state change.
run_root_sql 'enable the ingress principal' fleet_recall --execute="
ALTER USER fleet_ingress WITH LOGIN NOCREATEDB NOCREATEROLE;
" >/dev/null

printf '%s\n' 'Ingress receiver database boundary is ready.'
