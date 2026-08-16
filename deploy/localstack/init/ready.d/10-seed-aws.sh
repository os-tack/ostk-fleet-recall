#!/bin/sh
set -eu

bucket=fleet-recall-local-models
action_bucket=fleet-recall-local-actions
prefix=bundles/demo

awslocal s3api create-bucket --bucket "$bucket" >/dev/null
awslocal s3api create-bucket --bucket "$action_bucket" >/dev/null

for name in config.json model.safetensors tokenizer.json; do
    test -f "/seed-model/$name"
    test ! -L "/seed-model/$name"
    awslocal s3api put-object \
        --bucket "$bucket" \
        --key "$prefix/$name" \
        --body "/seed-model/$name" >/dev/null
done

# Create all raw URL secrets only after the model objects exist. Each URL has a
# distinct fixed database user and an explicit nonempty local-only password.
awslocal secretsmanager create-secret \
    --name ostk-fleet-recall/local/migrator-database-url \
    --secret-string 'postgresql://fleet_migrator:local-migrator-only@cockroach:26257/fleet_recall?sslmode=disable' >/dev/null
awslocal secretsmanager create-secret \
    --name ostk-fleet-recall/local/writer-database-url \
    --secret-string 'postgresql://fleet_writer:local-writer-only@cockroach:26257/fleet_recall?sslmode=disable' >/dev/null
awslocal secretsmanager create-secret \
    --name ostk-fleet-recall/local/publication-database-url \
    --secret-string 'postgresql://fleet_publication:local-publication-only@cockroach:26257/fleet_recall?sslmode=disable' >/dev/null
