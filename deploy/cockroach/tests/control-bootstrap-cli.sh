#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$script_dir/../../.." && pwd)
image=${FLEET_RECALL_CRDB_IMAGE:-cockroachdb/cockroach:v26.2.3}
container="ostk-control-cli-$$"
cert_dir=$(mktemp -d "${TMPDIR:-/tmp}/ostk-control-cli.XXXXXX")
admin_password='local-admin-proof-password'
bootstrap_password='local-bootstrap-proof-password'

cleanup() {
    case "$container" in
        ostk-control-cli-*) docker rm --force "$container" >/dev/null 2>&1 || true ;;
        *) echo "refusing to remove unexpected container name" >&2 ;;
    esac
    case "$cert_dir" in
        */ostk-control-cli.*) rm -rf -- "$cert_dir" ;;
        *) echo "refusing to remove unexpected certificate path" >&2 ;;
    esac
}
trap cleanup EXIT INT TERM

fail() {
    echo "control bootstrap CLI proof failed: $*" >&2
    exit 1
}

docker run --detach \
    --name "$container" \
    --hostname roach-control-cli \
    --publish 127.0.0.1::26257 \
    --env COCKROACH_DATABASE=fleet_recall \
    --env COCKROACH_USER=proof_admin \
    --env "COCKROACH_PASSWORD=$admin_password" \
    "$image" start-single-node --http-addr=roach-control-cli:8080 >/dev/null

ready=0
for _ in $(seq 1 90); do
    if docker exec "$container" cockroach sql \
        --certs-dir=/cockroach/certs \
        --host=127.0.0.1 \
        --execute 'SELECT 1' >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 1
done
test "$ready" -eq 1 || fail "CockroachDB did not become ready"

mapping=$(docker port "$container" 26257/tcp)
port=${mapping##*:}
case "$port" in
    ''|*[!0-9]*) fail "Docker returned an invalid SQL port" ;;
esac
docker cp "$container:/cockroach/certs/ca.crt" "$cert_dir/ca.crt" >/dev/null

admin_url="postgresql://proof_admin:${admin_password}@127.0.0.1:${port}/fleet_recall?sslmode=verify-full&sslrootcert=${cert_dir}/ca.crt"
FLEET_RECALL_TEST_DATABASE_URL="$admin_url" \
    cargo test --locked --test control_log_live -- --nocapture

docker exec -i "$container" cockroach sql \
    --certs-dir=/cockroach/certs \
    --host=127.0.0.1 \
    --user=proof_admin \
    --database=fleet_recall \
    < "$repo_root/deploy/cockroach/control-role-grants.sql" >/dev/null
docker exec "$container" cockroach sql \
    --certs-dir=/cockroach/certs \
    --host=127.0.0.1 \
    --user=proof_admin \
    --database=fleet_recall \
    --execute "ALTER ROLE fleet_control_bootstrap WITH LOGIN PASSWORD '$bootstrap_password'" \
    >/dev/null

bootstrap_url="postgresql://fleet_control_bootstrap:${bootstrap_password}@127.0.0.1:${port}/fleet_recall?sslmode=verify-full&sslrootcert=${cert_dir}/ca.crt"
cargo build --locked --bin ostk-control-bootstrap

run_cli() {
    FLEET_RECALL_DATABASE_URL="$bootstrap_url" \
    FLEET_RECALL_TENANT_ID='0198a849-f6ae-7d61-9800-000000000001' \
    FLEET_RECALL_PROJECT='private-cli-proof' \
    FLEET_RECALL_CONTROL_TENANT_NAMESPACE='tenant.fixture' \
    FLEET_RECALL_CONTROL_PROJECT_NAMESPACE='project.fixture' \
    FLEET_RECALL_BOOTSTRAP_RECEIPT_DIGEST='084ee06ea7ebf3b1d592d6e5843584485144c0ee5720fcc2124a61a7fcde48f0' \
        "$repo_root/target/debug/ostk-control-bootstrap" "$1" \
        --receipt "$repo_root/contracts/dynamic-memory/v1/bootstrap-receipt.jsonl" \
        --genesis-package "$repo_root/contracts/dynamic-memory/v1/genesis-registry-package.jsonl"
}

# A later successful row cannot mask a failed required migration.
docker exec "$container" cockroach sql \
    --certs-dir=/cockroach/certs \
    --host=127.0.0.1 \
    --user=proof_admin \
    --database=fleet_recall \
    --execute "
        UPDATE _sqlx_migrations SET success = false WHERE version = 3;
        INSERT INTO _sqlx_migrations
            (version, description, installed_on, success, checksum, execution_time)
        SELECT 4, 'synthetic later success', installed_on, true, checksum, execution_time
        FROM _sqlx_migrations WHERE version = 3" >/dev/null
if invalid_schema=$(run_cli inspect 2>&1); then
    fail "failed migration 3 was masked by successful migration 4"
fi
grep -q 'requires successful database migration 3' <<<"$invalid_schema" \
    || fail "failed migration 3 did not produce the bounded preflight error"
docker exec "$container" cockroach sql \
    --certs-dir=/cockroach/certs \
    --host=127.0.0.1 \
    --user=proof_admin \
    --database=fleet_recall \
    --execute "
        DELETE FROM _sqlx_migrations WHERE version = 4;
        UPDATE _sqlx_migrations SET success = true WHERE version = 3" >/dev/null

absent=$(run_cli inspect)
jq -e '
    .operation == "inspect" and
    .state == "absent" and
    .receipt_digest == "084ee06ea7ebf3b1d592d6e5843584485144c0ee5720fcc2124a61a7fcde48f0"
' <<<"$absent" >/dev/null || fail "fresh inspect did not report absent"

inserted=$(run_cli apply)
jq -e '
    .operation == "apply" and
    .state == "inserted" and
    .receipt_digest == "084ee06ea7ebf3b1d592d6e5843584485144c0ee5720fcc2124a61a7fcde48f0" and
    .epoch_id == "d35655f3297e1c5eb4503443befb956f93dc5210b46cdc1a4d7d9f2746b8fab2" and
    .accepted_event_id == "ca530fad9338a7a35ce7aad78e016f53b88a21846d4a1f53fecdcb1cabbdabe0" and
    .shard_count == 16 and .head_count == 16 and .event_shard == 5 and
    .committed_offset == "1"
' <<<"$inserted" >/dev/null || fail "first apply did not report the exact insert receipt"

complete=$(run_cli inspect)
jq -e '.operation == "inspect" and .state == "complete" and .committed_offset == "1"' \
    <<<"$complete" >/dev/null || fail "post-apply inspect did not report complete"

replay=$(run_cli apply)
jq -e '.operation == "apply" and .state == "exact_replay" and .committed_offset == "1"' \
    <<<"$replay" >/dev/null || fail "second apply did not report exact replay"

explain=$(docker exec "$container" cockroach sql \
    --url "postgresql://fleet_control_bootstrap:${bootstrap_password}@127.0.0.1:26257/fleet_recall?sslmode=verify-full&sslrootcert=/cockroach/certs/ca.crt" \
    --format=tsv \
    --execute 'EXPLAIN SELECT EXISTS (SELECT 1 FROM _sqlx_migrations WHERE version = 3 AND success)')
grep -q '_sqlx_migrations' <<<"$explain" || fail "schema-version EXPLAIN missed migration metadata"

printf '%s\n' \
    "private CLI receipts:" \
    "$absent" \
    "$inserted" \
    "$complete" \
    "$replay" \
    "schema-version EXPLAIN:" \
    "$explain" \
    "control bootstrap CLI proof passed"
