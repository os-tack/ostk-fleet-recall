#!/bin/sh
set -eu

secret_id=${FLEET_RECALL_DATABASE_SECRET_ID:-}
endpoint_url=${FLEET_RECALL_AWS_ENDPOINT_URL:-}
destination=/run/fleet-recall-publication/database-url

if [ "$secret_id" != 'ostk-fleet-recall/local/publication-database-url' ]; then
    echo "publication secret resolver requires its exact secret identifier" >&2
    exit 64
fi
if [ "$endpoint_url" != 'http://localstack:4566' ]; then
    echo "publication secret resolution requires the fixed LocalStack endpoint" >&2
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
    if [ -n "$database_url" ] && [ "$database_url" != None ]; then
        break
    fi
    sleep 1
    attempt=$((attempt + 1))
done

case "$database_url" in
    postgresql://fleet_publication:?*@cockroach:26257/fleet_recall\?sslmode=disable) ;;
    *)
        echo "publication secret violates its fixed LocalStack identity" >&2
        exit 65
        ;;
esac

umask 077
temporary="$destination.tmp.$$"
trap 'rm -f -- "$temporary"' EXIT HUP INT TERM
printf '%s\n' "$database_url" >"$temporary"
chown 10001:10001 "$temporary"
chmod 0400 "$temporary"
mv -f -- "$temporary" "$destination"
trap - EXIT HUP INT TERM
unset database_url

printf '%s\n' 'Publication database secret handoff is ready.'
