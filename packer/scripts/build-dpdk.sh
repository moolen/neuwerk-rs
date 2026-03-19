#!/usr/bin/env bash
set -euo pipefail

repo_dir="${NEUWERK_REPO_DIR:-}"
target_id="${NEUWERK_TARGET:-}"
use_prebuilt="${NEUWERK_USE_PREBUILT_ARTIFACTS:-false}"

if [[ -z "$repo_dir" || -z "$target_id" ]]; then
  echo "NEUWERK_REPO_DIR and NEUWERK_TARGET are required" >&2
  exit 1
fi

case "$use_prebuilt" in
  1|true|TRUE|yes|YES)
    target_json="$(python3 "$repo_dir/packaging/scripts/resolve_target.py" --target "$target_id")"
    target_dpdk_version="$(printf '%s\n' "$target_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["dpdk"]["version"])')"
    dpdk_dir="$repo_dir/third_party/dpdk/install/$target_dpdk_version"
    if [[ ! -d "$dpdk_dir" ]]; then
      echo "prebuilt DPDK install prefix not found: $dpdk_dir" >&2
      exit 1
    fi
    echo "Using prebuilt DPDK at $dpdk_dir"
    exit 0
    ;;
esac

"$repo_dir/packaging/scripts/build_dpdk.sh" --target "$target_id"
