#!/bin/sh
set -eu

secret_id=${FLEET_RECALL_DATABASE_SECRET_ID:-}
endpoint_url=${FLEET_RECALL_AWS_ENDPOINT_URL:-}
if [ -z "$secret_id" ]; then
    echo "FLEET_RECALL_DATABASE_SECRET_ID is required" >&2
    exit 64
fi

attempt=1
while [ "$attempt" -le 30 ]; do
    if [ -n "$endpoint_url" ]; then
        database_url=$(aws --endpoint-url "$endpoint_url" \
            secretsmanager get-secret-value \
            --secret-id "$secret_id" \
            --query SecretString \
            --output text 2>/dev/null || true)
    else
        database_url=$(aws secretsmanager get-secret-value \
            --secret-id "$secret_id" \
            --query SecretString \
            --output text 2>/dev/null || true)
    fi
    if [ -n "$database_url" ] && [ "$database_url" != "None" ]; then
        break
    fi
    sleep 1
    attempt=$((attempt + 1))
done

if [ -z "${database_url:-}" ] || [ "$database_url" = "None" ]; then
    echo "database URL was not available from the configured Secrets Manager endpoint" >&2
    exit 69
fi

case "$database_url" in
    postgresql://*|postgres://*) ;;
    *)
        echo "database secret must contain a PostgreSQL connection URL" >&2
        exit 65
        ;;
esac

export FLEET_RECALL_DATABASE_URL=$database_url
unset database_url

exec /usr/local/bin/container-entrypoint "$@"
