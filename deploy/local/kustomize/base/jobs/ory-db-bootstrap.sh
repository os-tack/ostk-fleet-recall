#!/bin/sh
# Databases and owners for Ory Hydra and Kratos on the shared cluster. Runs
# after the boundary so the new roles never trip the policies' PUBLIC gates on
# first apply; a boundary rerun cleans them dynamically.
set -eu
host=${CRDB_HOST:?}
sql() {
    cockroach sql --certs-dir=/certs --host="$host" --database=defaultdb "$@"
}
sql --execute="
CREATE DATABASE IF NOT EXISTS hydra;
CREATE USER IF NOT EXISTS hydra;
ALTER USER hydra WITH PASSWORD '${HYDRA_DB_PASSWORD:?}' LOGIN NOCREATEDB NOCREATEROLE;
ALTER DATABASE hydra OWNER TO hydra;
CREATE DATABASE IF NOT EXISTS kratos;
CREATE USER IF NOT EXISTS kratos;
ALTER USER kratos WITH PASSWORD '${KRATOS_DB_PASSWORD:?}' LOGIN NOCREATEDB NOCREATEROLE;
ALTER DATABASE kratos OWNER TO kratos;
" >/dev/null
printf '%s\n' 'hydra and kratos databases are ready'
