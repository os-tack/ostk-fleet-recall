#!/bin/sh
set -eu

secret_file=/run/fleet-recall-publication/database-url

if [ "${1:-}" != demo ]; then
    echo "the public production container can launch only the bounded demo" >&2
    exit 64
fi

# Reject every private database surface before reading the dedicated handoff.
# The Rust PublicationConfig repeats this gate inside the process boundary.
if [ "${FLEET_RECALL_DATABASE_URL+set}" = set ] ||
   [ "${FLEET_RECALL_CONTROL_DATABASE_URL+set}" = set ] ||
   [ "${FLEET_RECALL_REGISTRY_DATABASE_URL+set}" = set ] ||
   [ "${FLEET_RECALL_SUCCESSOR_DATABASE_URL+set}" = set ] ||
   [ "${FLEET_RECALL_RECONCILIATION_DATABASE_URL+set}" = set ] ||
   [ "${FLEET_RECALL_TEST_DATABASE_URL+set}" = set ] ||
   [ "${FLEET_RECONCILIATION_TEST_DATABASE_URL+set}" = set ] ||
   [ "${FLEET_RECALL_PUBLICATION_TEST_ADMIN_DATABASE_URL+set}" = set ] ||
   [ "${FLEET_RECALL_DATABASE_SECRET_ID+set}" = set ] ||
   [ "${FLEET_RECALL_PRIVATE_DATABASE_KIND+set}" = set ]; then
    echo "the public production container forbids private database configuration" >&2
    exit 64
fi

if [ ! -f "$secret_file" ] || [ -L "$secret_file" ] || [ ! -r "$secret_file" ]; then
    echo "publication database secret handoff is not a readable regular file" >&2
    exit 66
fi
if [ "$(wc -l <"$secret_file" | tr -d ' ')" != 1 ]; then
    echo "publication database secret handoff must contain exactly one line" >&2
    exit 65
fi

database_url=$(sed -n '1p' "$secret_file")
case "$database_url" in
    postgresql://fleet_publication:?*@cockroach:26257/fleet_recall\?sslmode=disable) ;;
    *)
        echo "publication database secret handoff violates its fixed identity" >&2
        exit 65
        ;;
esac

export FLEET_RECALL_PUBLICATION_DATABASE_URL="$database_url"
unset database_url

exec /usr/local/bin/container-entrypoint "$@"
