#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
target_id=""
profile="release"
repo_dir="$root_dir"
output_root=""
runtime_template_dir="$root_dir/packaging/runtime"

usage() {
  cat <<'EOF'
Usage: stage_runtime.sh --target <target-id> --output-root <path> [--profile debug|release] [--repo-dir <path>]
EOF
}

join_root() {
  local root="$1"
  local absolute="$2"
  printf '%s%s\n' "$root" "$absolute"
}

copy_matches() {
  local source_root="$1"
  local destination_root="$2"
  shift 2
  local pattern=""
  shopt -s nullglob
  for pattern in "$@"; do
    local matches=("$source_root"/$pattern)
    local match=""
    for match in "${matches[@]}"; do
      local rel="${match#"$source_root"/}"
      local dest="$destination_root/$rel"
      install -d "$(dirname "$dest")"
      cp -a "$match" "$dest"
    done
  done
  shopt -u nullglob
}

render_template() {
  local template_path="$1"
  local destination_path="$2"
  shift 2
  python3 - "$template_path" "$destination_path" "$@" <<'PY'
from __future__ import annotations

import sys
from pathlib import Path

template_path = Path(sys.argv[1])
destination_path = Path(sys.argv[2])
replacements: dict[str, str] = {}
for entry in sys.argv[3:]:
    key, value = entry.split("=", 1)
    replacements[key] = value

content = template_path.read_text(encoding="utf-8")
for key, value in replacements.items():
    content = content.replace(key, value)

destination_path.parent.mkdir(parents=True, exist_ok=True)
destination_path.write_text(content, encoding="utf-8")
PY
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
    --repo-dir)
      repo_dir="${2:-}"
      shift 2
      ;;
    --output-root)
      output_root="${2:-}"
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

if [[ -z "$target_id" || -z "$output_root" ]]; then
  echo "--target and --output-root are required" >&2
  exit 1
fi

target_json="$(python3 "$root_dir/packaging/scripts/resolve_target.py" --target "$target_id")"
manifest_env_file="$(mktemp)"
python3 - "$manifest_env_file" "$target_json" <<'PY'
import json
import shlex
import sys

data = json.loads(sys.argv[2])
runtime = data["runtime"]
dpdk = data["dpdk"]
output = sys.argv[1]

with open(output, "w", encoding="utf-8") as handle:
    handle.write(f"TARGET_DPDK_VERSION={shlex.quote(dpdk['version'])}\n")
    handle.write(f"RUNTIME_PREFIX={shlex.quote(runtime['prefix'])}\n")
    handle.write(f"RUNTIME_BINARY_DIR={shlex.quote(runtime['binary_dir'])}\n")
    handle.write(f"RUNTIME_UI_DIR={shlex.quote(runtime['ui_dir'])}\n")
    handle.write(f"RUNTIME_CONFIG_FILE={shlex.quote(runtime['config_file'])}\n")
    handle.write(f"RUNTIME_SERVICE_FILE={shlex.quote(runtime['service_file'])}\n")
    handle.write(f"RUNTIME_LINK_NAME={shlex.quote(runtime['link_name'])}\n")
    for index, value in enumerate(runtime["dpdk_library_globs"]):
        handle.write(f"RUNTIME_LIB_GLOB_{index}={shlex.quote(value)}\n")
    handle.write(f"RUNTIME_LIB_GLOB_COUNT={len(runtime['dpdk_library_globs'])}\n")
    for index, value in enumerate(runtime["dpdk_pmd_globs"]):
        handle.write(f"RUNTIME_PMD_GLOB_{index}={shlex.quote(value)}\n")
    handle.write(f"RUNTIME_PMD_GLOB_COUNT={len(runtime['dpdk_pmd_globs'])}\n")
PY
# shellcheck disable=SC1090
source "$manifest_env_file"
rm -f "$manifest_env_file"

binary_path="$repo_dir/target/$profile/neuwerk"
ui_dist="$repo_dir/ui/dist"
dpdk_prefix="$repo_dir/third_party/dpdk/install/$TARGET_DPDK_VERSION"

if [[ ! -x "$binary_path" ]]; then
  echo "built neuwerk binary not found: $binary_path" >&2
  exit 1
fi
if [[ ! -d "$ui_dist" ]]; then
  echo "UI dist not found: $ui_dist" >&2
  exit 1
fi
if [[ ! -d "$dpdk_prefix" ]]; then
  echo "DPDK install prefix not found: $dpdk_prefix" >&2
  exit 1
fi

install -d "$output_root"
install -d "$(join_root "$output_root" "$RUNTIME_BINARY_DIR")"
install -d "$(join_root "$output_root" "$RUNTIME_UI_DIR")"
install -d "$(dirname "$(join_root "$output_root" "$RUNTIME_CONFIG_FILE")")"
install -d "$(dirname "$(join_root "$output_root" "$RUNTIME_SERVICE_FILE")")"
install -d "$(dirname "$(join_root "$output_root" "$RUNTIME_LINK_NAME")")"

install -m 0755 "$binary_path" "$(join_root "$output_root" "$RUNTIME_BINARY_DIR")/neuwerk"
cp -a "$ui_dist/." "$(join_root "$output_root" "$RUNTIME_UI_DIR")/"

runtime_dpdk_dir="$(join_root "$output_root" "$RUNTIME_PREFIX")/dpdk/$TARGET_DPDK_VERSION"
install -d "$runtime_dpdk_dir"
runtime_globs=()
for (( index=0; index<RUNTIME_LIB_GLOB_COUNT; index++ )); do
  var_name="RUNTIME_LIB_GLOB_${index}"
  runtime_globs+=("${!var_name}")
done
for (( index=0; index<RUNTIME_PMD_GLOB_COUNT; index++ )); do
  var_name="RUNTIME_PMD_GLOB_${index}"
  runtime_globs+=("${!var_name}")
done
copy_matches "$dpdk_prefix" "$runtime_dpdk_dir" "${runtime_globs[@]}"
ln -sfn "dpdk/$TARGET_DPDK_VERSION" "$(join_root "$output_root" "$RUNTIME_PREFIX")/current"

install -m 0644 \
  "$runtime_template_dir/config.yaml" \
  "$(join_root "$output_root" "$RUNTIME_CONFIG_FILE")"

render_template \
  "$runtime_template_dir/neuwerk.service.in" \
  "$(join_root "$output_root" "$RUNTIME_SERVICE_FILE")" \
  "__RUNTIME_BINARY_DIR__=$RUNTIME_BINARY_DIR" \
  "__RUNTIME_PREFIX__=$RUNTIME_PREFIX"
chmod 0644 "$(join_root "$output_root" "$RUNTIME_SERVICE_FILE")"

ln -sfn "$RUNTIME_BINARY_DIR/neuwerk" "$(join_root "$output_root" "$RUNTIME_LINK_NAME")"
