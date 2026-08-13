#!/bin/sh

set -eu

die() {
  printf 'media verification failed: %s\n' "$*" >&2
  exit 1
}

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)

verify_png() {
  path=$1
  expected_dimensions=$2
  max_bytes=$3

  [ -f "$path" ] || die "missing $path"

  description=$(file -b "$path")
  case "$description" in
    "PNG image data, $expected_dimensions,"*) ;;
    *) die "$path is not the expected $expected_dimensions PNG ($description)" ;;
  esac

  bytes=$(wc -c <"$path" | tr -d '[:space:]')
  [ "$bytes" -lt "$max_bytes" ] ||
    die "$path is $bytes bytes; expected less than $max_bytes"

  printf 'verified %s: %s, %s bytes\n' "$(basename -- "$path")" \
    "$expected_dimensions" "$bytes"
}

verify_final_video() {
  path=$1

  [ -f "$path" ] || die "missing final video $path"
  command -v ffprobe >/dev/null 2>&1 ||
    die "ffprobe is required to verify a final video"

  video_stream=$(ffprobe -v error -select_streams v:0 \
    -show_entries stream=codec_name,width,height,pix_fmt \
    -of csv=p=0 "$path")
  [ -n "$video_stream" ] || die "$path has no video stream"

  codec=${video_stream%%,*}
  video_stream_rest=${video_stream#*,}
  width=${video_stream_rest%%,*}
  video_stream_rest=${video_stream_rest#*,}
  height=${video_stream_rest%%,*}
  pixel_format=${video_stream_rest#*,}
  [ "$codec,$width,$height,$pixel_format" = "$video_stream" ] &&
    [ "$pixel_format" != "$video_stream_rest" ] &&
    [ "${pixel_format#*,}" = "$pixel_format" ] ||
    die "could not parse video stream: $video_stream"

  [ "$codec" = h264 ] || die "expected H.264 video, found $codec"
  [ "$pixel_format" = yuv420p ] ||
    die "expected yuv420p for broad playback compatibility, found $pixel_format"
  [ "$width" -ge 1280 ] && [ "$height" -ge 720 ] ||
    die "expected at least 1280x720, found ${width}x${height}"
  [ $((width * 9)) -eq $((height * 16)) ] ||
    die "expected a 16:9 frame, found ${width}x${height}"

  duration=$(ffprobe -v error -show_entries format=duration \
    -of default=noprint_wrappers=1:nokey=1 "$path")
  awk -v value="$duration" 'BEGIN { exit !(value > 0 && value < 180) }' ||
    die "duration must be greater than zero and less than 180 seconds; found $duration"

  audio_codec=$(ffprobe -v error -select_streams a:0 \
    -show_entries stream=codec_name -of default=noprint_wrappers=1:nokey=1 \
    "$path")
  [ -n "$audio_codec" ] ||
    die "final video has no audio stream; add narration or an accessible equivalent"

  printf 'verified final video: %sx%s %s/%s, %ss, audio=%s\n' \
    "$width" "$height" "$codec" "$pixel_format" "$duration" "$audio_codec"
}

command -v file >/dev/null 2>&1 || die "file(1) is required"

# Devpost's gallery upload limit is 5 MB. Use decimal megabytes here so the
# check is conservative on services that describe the limit without units.
verify_png "$script_dir/devpost-thumbnail-v2.png" "1536 x 1024" 5000000
verify_png "$script_dir/architecture.png" "1568 x 1018" 5000000

case $# in
  0) ;;
  2)
    [ "$1" = --final-video ] ||
      die "usage: $0 [--final-video PATH]"
    verify_final_video "$2"
    ;;
  *) die "usage: $0 [--final-video PATH]" ;;
esac

printf 'media verification passed.\n'
