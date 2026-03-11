#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
target_id=""
rootfs=""
output_dir=""

usage() {
  cat <<'EOF'
Usage: generate_sbom.sh --target <target-id> --rootfs <path> --output-dir <path>
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)
      target_id="${2:-}"
      shift 2
      ;;
    --rootfs)
      rootfs="${2:-}"
      shift 2
      ;;
    --output-dir)
      output_dir="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "$target_id" || -z "$rootfs" || -z "$output_dir" ]]; then
  echo "--target, --rootfs, and --output-dir are required" >&2
  exit 1
fi

if ! command -v syft >/dev/null 2>&1; then
  echo "syft is required to generate image SBOMs" >&2
  exit 1
fi

mkdir -p "$output_dir"
syft "dir:$rootfs" -o "spdx-json=$output_dir/${target_id}-rootfs.spdx.json"
syft "dir:$rootfs" -o "cyclonedx-json=$output_dir/${target_id}-rootfs.cyclonedx.json"
