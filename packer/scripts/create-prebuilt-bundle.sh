#!/usr/bin/env bash
set -euo pipefail

repo_root="${NEUWERK_REPO_ROOT:-}"
bundle_output="${NEUWERK_PREBUILT_BUNDLE_OUTPUT:-}"
target_id="${NEUWERK_TARGET:-}"
use_prebuilt="${NEUWERK_USE_PREBUILT_ARTIFACTS:-false}"

if [[ -z "$repo_root" || -z "$bundle_output" || -z "$target_id" ]]; then
  echo "NEUWERK_REPO_ROOT, NEUWERK_PREBUILT_BUNDLE_OUTPUT, and NEUWERK_TARGET are required" >&2
  exit 1
fi

mkdir -p "$(dirname "$bundle_output")"

case "$use_prebuilt" in
  1|true|TRUE|yes|YES)
    ;;
  *)
    temp_dir="$(mktemp -d)"
    trap 'rm -rf "$temp_dir"' EXIT
    tar -C "$temp_dir" -czf "$bundle_output" .
    exit 0
    ;;
esac

target_json="$(python3 "$repo_root/packaging/scripts/resolve_target.py" --target "$target_id")"
dpdk_version="$(printf '%s\n' "$target_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["dpdk"]["version"])')"

binary_path="$repo_root/target/release/neuwerk"
ui_dist_path="$repo_root/ui/dist"
dpdk_install_path="$repo_root/third_party/dpdk/install/$dpdk_version"

for required_path in "$binary_path" "$ui_dist_path" "$dpdk_install_path"; do
  if [[ ! -e "$required_path" ]]; then
    echo "prebuilt artifact missing: $required_path" >&2
    exit 1
  fi
done

tar \
  -czf "$bundle_output" \
  -C "$repo_root" \
  target/release/neuwerk \
  ui/dist \
  "third_party/dpdk/install/$dpdk_version"
