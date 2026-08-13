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
        preflight_mode=rehearsal
        ;;
    --fleet-live)
        [ "$#" -eq 2 ] || {
            printf 'usage: demo/video/render.sh --fleet-live RUN_ID\n' >&2
            exit 64
        }
        export FLEET_VIDEO_RUN_ID=$2
        tape=$script_dir/fleet-live.tape
        preflight_mode=fleet-live
        ;;
    --ostk-live)
        [ "$#" -eq 2 ] || {
            printf 'usage: demo/video/render.sh --ostk-live RUN_ID\n' >&2
            exit 64
        }
        export FLEET_VIDEO_RUN_ID=$2
        tape=$script_dir/ostk-live.tape
        preflight_mode=ostk-live
        ;;
    *)
        printf 'usage: demo/video/render.sh [--rehearsal | --fleet-live RUN_ID | --ostk-live RUN_ID]\n' >&2
        exit 64
        ;;
esac

cd "$repo_root"
case "$preflight_mode" in
    rehearsal)
        FLEET_VIDEO_FAST=1 "$script_dir/run.sh" --rehearsal --headless >/dev/null
        ;;
    fleet-live)
        FLEET_VIDEO_FAST=1 "$script_dir/run.sh" \
            --fleet-live "$FLEET_VIDEO_RUN_ID" --headless >/dev/null
        ;;
    ostk-live)
        FLEET_VIDEO_FAST=1 "$script_dir/run.sh" \
            --ostk-live "$FLEET_VIDEO_RUN_ID" --headless >/dev/null
        ;;
esac
vhs "$tape"
