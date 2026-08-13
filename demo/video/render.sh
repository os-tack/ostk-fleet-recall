#!/bin/sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$script_dir/../.." && pwd)

command -v vhs >/dev/null 2>&1 || {
    printf 'video render: VHS is required (https://github.com/charmbracelet/vhs)\n' >&2
    exit 1
}

case "${1:---rehearsal}" in
    --rehearsal)
        [ "$#" -le 1 ] || exit 64
        tape=$script_dir/rehearsal.tape
        ;;
    --live)
        [ "$#" -eq 2 ] || {
            printf 'usage: demo/video/render.sh --live RUN_ID\n' >&2
            exit 64
        }
        export OSTK_DEMO_RUN_ID=$2
        tape=$script_dir/live.tape
        ;;
    *)
        printf 'usage: demo/video/render.sh [--rehearsal | --live RUN_ID]\n' >&2
        exit 64
        ;;
esac

cd "$repo_root"
vhs "$tape"
