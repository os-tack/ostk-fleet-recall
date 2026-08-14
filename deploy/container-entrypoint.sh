#!/bin/sh
set -eu

binary=/usr/local/bin/ostk-fleet-recall

# These commands do not open the database or load the deployed model.
case "${1:-}" in
    model-digest|-h|--help|-V|--version)
        exec "$binary" "$@"
        ;;
esac

bundle_path=${FLEET_RECALL_EMBEDDING_MODEL_PATH:-/opt/ostk/models/potion-retrieval-32M}
expected_digest=${FLEET_RECALL_EMBEDDING_MODEL_SHA256:-}

case "$bundle_path" in
    /*) ;;
    *)
        echo "FLEET_RECALL_EMBEDDING_MODEL_PATH must be absolute" >&2
        exit 64
        ;;
esac

case "$expected_digest" in
    ''|*[!0-9a-fA-F]*)
        echo "FLEET_RECALL_EMBEDDING_MODEL_SHA256 must be a hexadecimal digest" >&2
        exit 64
        ;;
esac

if [ "${#expected_digest}" -ne 64 ]; then
    echo "FLEET_RECALL_EMBEDDING_MODEL_SHA256 must contain 64 hexadecimal characters" >&2
    exit 64
fi

expected_digest=$(printf '%s' "$expected_digest" | tr 'A-F' 'a-f')

if [ ! -d "$bundle_path" ]; then
    model_s3_uri=${FLEET_RECALL_MODEL_S3_URI:-}
    case "$model_s3_uri" in
        s3://*) ;;
        *)
            echo "model bundle is absent and FLEET_RECALL_MODEL_S3_URI is not an s3:// URI" >&2
            exit 64
            ;;
    esac

    bundle_parent=$(dirname "$bundle_path")
    mkdir -p "$bundle_parent"
    staging=$(mktemp -d "$bundle_parent/.model-download.XXXXXX")
    aws_region=${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}
    cleanup() {
        rm -rf -- "$staging"
    }
    trap cleanup EXIT HUP INT TERM

    for name in config.json model.safetensors tokenizer.json; do
        if [ -n "${FLEET_RECALL_AWS_ENDPOINT_URL:-}" ]; then
            s5cmd --log error --endpoint-url "$FLEET_RECALL_AWS_ENDPOINT_URL" \
                cp --raw --source-region "$aws_region" \
                "${model_s3_uri%/}/$name" "$staging/$name"
        else
            s5cmd --log error cp --raw --source-region "$aws_region" \
                "${model_s3_uri%/}/$name" "$staging/$name"
        fi
    done

    actual_digest=$("$binary" model-digest "$staging")
    if [ "$actual_digest" != "$expected_digest" ]; then
        echo "downloaded model bundle digest does not match the deployment pin" >&2
        exit 65
    fi

    mv "$staging" "$bundle_path"
    trap - EXIT HUP INT TERM
fi

actual_digest=$("$binary" model-digest "$bundle_path")
if [ "$actual_digest" != "$expected_digest" ]; then
    echo "local model bundle digest does not match the deployment pin" >&2
    exit 65
fi

exec "$binary" "$@"
