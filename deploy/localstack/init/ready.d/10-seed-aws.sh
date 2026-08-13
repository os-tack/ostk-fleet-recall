#!/bin/sh
set -eu

bucket=fleet-recall-local-models
action_bucket=fleet-recall-local-actions
prefix=bundles/demo
secret_id=ostk-fleet-recall/local/database-url

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

# Creating the secret last makes it a readiness gate for all three objects.
awslocal secretsmanager create-secret \
    --name "$secret_id" \
    --secret-string 'postgresql://root@cockroach:26257/defaultdb?sslmode=disable' >/dev/null
