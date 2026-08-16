#!/bin/sh
set -eu

# Bootstrap only what must exist before the dedicated migrator connects. The
# later database-boundary step revokes this temporary admin membership and
# provisions the writer/publication identities after migration 17 succeeds.
cockroach sql --insecure --host=cockroach:26257 --database=defaultdb \
    --execute="
CREATE DATABASE IF NOT EXISTS fleet_recall;
CREATE USER IF NOT EXISTS fleet_migrator;
ALTER USER fleet_migrator WITH LOGIN NOCREATEDB NOCREATEROLE;
GRANT admin TO fleet_migrator;
" >/dev/null

printf '%s\n' 'Local database and dedicated migrator principal are ready.'
