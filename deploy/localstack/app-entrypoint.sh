#!/bin/sh
set -eu

# This wrapper is private to the LocalStack migrator/writer image. The public
# production image uses publication-entrypoint.sh and this file rejects demo
# even if it is invoked manually.
case "${1:-}" in
    migrate)
        expected_kind=migrator
        expected_secret_id=ostk-fleet-recall/local/migrator-database-url
        expected_user=fleet_migrator
        ;;
    serve|health|ingest|reference-agent|localstack-writer-idle)
        expected_kind=writer
        expected_secret_id=ostk-fleet-recall/local/writer-database-url
        expected_user=fleet_writer
        ;;
    demo)
        echo "the private LocalStack entrypoint cannot launch the public demo" >&2
        exit 64
        ;;
    model-digest|-h|--help|-V|--version)
        exec /usr/local/bin/container-entrypoint "$@"
        ;;
    *)
        echo "unsupported private LocalStack command" >&2
        exit 64
        ;;
esac

if [ "${FLEET_RECALL_PUBLICATION_DATABASE_URL+set}" = set ]; then
    echo "the private LocalStack entrypoint forbids the publication database URL" >&2
    exit 64
fi

database_kind=${FLEET_RECALL_PRIVATE_DATABASE_KIND:-}
secret_id=${FLEET_RECALL_DATABASE_SECRET_ID:-}
endpoint_url=${FLEET_RECALL_AWS_ENDPOINT_URL:-}
if [ "$database_kind" != "$expected_kind" ] || [ "$secret_id" != "$expected_secret_id" ]; then
    echo "private database command and secret identity do not match" >&2
    exit 64
fi
if [ "$endpoint_url" != 'http://localstack:4566' ]; then
    echo "private database secret resolution requires the fixed LocalStack endpoint" >&2
    exit 64
fi

attempt=1
database_url=
while [ "$attempt" -le 30 ]; do
    database_url=$(aws --endpoint-url "$endpoint_url" \
        secretsmanager get-secret-value \
        --secret-id "$secret_id" \
        --query SecretString \
        --output text 2>/dev/null || true)
    if [ -n "$database_url" ] && [ "$database_url" != "None" ]; then
        break
    fi
    sleep 1
    attempt=$((attempt + 1))
done

if [ -z "$database_url" ] || [ "$database_url" = "None" ]; then
    echo "private database URL was not available from Secrets Manager" >&2
    exit 69
fi

case "$database_url" in
    "postgresql://$expected_user:"?*"@cockroach:26257/fleet_recall?sslmode=disable") ;;
    *)
        echo "private database secret violates its fixed LocalStack identity" >&2
        exit 65
        ;;
esac

export FLEET_RECALL_DATABASE_URL="$database_url"
unset database_url

if [ "$1" = localstack-writer-idle ]; then
    /usr/local/bin/container-entrypoint health
    exec sleep infinity
fi

exec /usr/local/bin/container-entrypoint "$@"
