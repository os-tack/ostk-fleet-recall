#!/bin/sh
# Port of deploy/localstack/database-bootstrap.sh for the secure cluster: the
# database, the one-shot migrator with admin, and the long-lived principals
# created quiesced (NOLOGIN) with their passwords. The boundary Job enables
# them after the policies apply.
set -eu
host=${CRDB_HOST:?}
sql() {
    cockroach sql --certs-dir=/certs --host="$host" --database=defaultdb "$@"
}
sql --execute="
CREATE DATABASE IF NOT EXISTS fleet_recall;
CREATE USER IF NOT EXISTS fleet_migrator;
ALTER USER fleet_migrator WITH PASSWORD '${MIGRATOR_PASSWORD:?}' LOGIN NOCREATEDB NOCREATEROLE;
GRANT admin TO fleet_migrator;
CREATE USER IF NOT EXISTS fleet_writer;
ALTER USER fleet_writer WITH PASSWORD '${WRITER_PASSWORD:?}' NOLOGIN NOCREATEDB NOCREATEROLE;
CREATE USER IF NOT EXISTS fleet_publication;
ALTER USER fleet_publication WITH PASSWORD '${PUBLICATION_PASSWORD:?}' NOLOGIN NOCREATEDB NOCREATEROLE;
CREATE USER IF NOT EXISTS fleet_ingress;
ALTER USER fleet_ingress WITH PASSWORD '${INGRESS_PASSWORD:?}' NOLOGIN NOCREATEDB NOCREATEROLE;
" >/dev/null
printf '%s\n' 'database, migrator, and quiesced principals are ready'
