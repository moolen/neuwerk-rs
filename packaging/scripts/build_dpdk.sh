#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
target_id=""

usage() {
  cat <<'EOF'
Usage: build_dpdk.sh --target <target-id>

Build the vendored DPDK version required by the target manifest.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)
      target_id="${2:-}"
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

if [[ -z "$target_id" ]]; then
  echo "--target is required" >&2
  usage >&2
  exit 1
fi

target_json="$(python3 "$root_dir/packaging/scripts/resolve_target.py" --target "$target_id")"
target_dpdk_version="$(printf '%s\n' "$target_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["dpdk"]["version"])')"
target_disable_drivers="$(printf '%s\n' "$target_json" | python3 -c 'import json,sys; print(",".join(json.load(sys.stdin)["dpdk"]["disable_drivers"]))')"
repo_dpdk_version="$(<"$root_dir/third_party/dpdk/VERSION")"

if [[ "$target_dpdk_version" != "$repo_dpdk_version" ]]; then
  echo "target $target_id requires DPDK $target_dpdk_version but repository is pinned to $repo_dpdk_version" >&2
  exit 1
fi

export DPDK_DISABLE_DRIVERS="$target_disable_drivers"
"$root_dir/scripts/build-dpdk.sh"
