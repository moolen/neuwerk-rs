#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
target_id=""
profile="release"
build_ui="1"
repo_dir="$root_dir"

usage() {
  cat <<'EOF'
Usage: build_firewall.sh --target <target-id> [--profile debug|release] [--skip-ui] [--repo-dir <path>]
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)
      target_id="${2:-}"
      shift 2
      ;;
    --profile)
      profile="${2:-}"
      shift 2
      ;;
    --skip-ui)
      build_ui="0"
      shift
      ;;
    --repo-dir)
      repo_dir="${2:-}"
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
  exit 1
fi

if [[ -f "$HOME/.cargo/env" ]]; then
  # rustup installs cargo here on pristine builder images
  # shellcheck disable=SC1090
  source "$HOME/.cargo/env"
fi

target_json="$(python3 "$root_dir/packaging/scripts/resolve_target.py" --target "$target_id")"
target_dpdk_version="$(printf '%s\n' "$target_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["dpdk"]["version"])')"
dpdk_dir="$repo_dir/third_party/dpdk/install/$target_dpdk_version"
pkg_config_path="$dpdk_dir/lib/pkgconfig:$dpdk_dir/lib/x86_64-linux-gnu/pkgconfig:$dpdk_dir/lib64/pkgconfig"

if [[ ! -d "$dpdk_dir" ]]; then
  echo "DPDK install prefix not found: $dpdk_dir" >&2
  echo "Run packaging/scripts/build_dpdk.sh --target $target_id first." >&2
  exit 1
fi

if [[ "$build_ui" == "1" ]]; then
  npm --prefix "$repo_dir/ui" ci
  npm --prefix "$repo_dir/ui" test
  npm --prefix "$repo_dir/ui" run build
fi

build_args=(cargo build --all-features)
if [[ "$profile" == "release" ]]; then
  build_args+=(--release)
elif [[ "$profile" != "debug" ]]; then
  echo "unsupported profile: $profile" >&2
  exit 1
fi

(
  cd "$repo_dir"
  DPDK_DIR="$dpdk_dir" \
  PKG_CONFIG_PATH="$pkg_config_path" \
  "${build_args[@]}"
)
