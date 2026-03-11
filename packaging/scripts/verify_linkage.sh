#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
target_id=""
binary_path=""
output_json=""

usage() {
  cat <<'EOF'
Usage: verify_linkage.sh --target <target-id> --binary <path> [--output-json <path>]
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)
      target_id="${2:-}"
      shift 2
      ;;
    --binary)
      binary_path="${2:-}"
      shift 2
      ;;
    --output-json)
      output_json="${2:-}"
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

if [[ -z "$target_id" || -z "$binary_path" ]]; then
  echo "--target and --binary are required" >&2
  exit 1
fi

target_json="$(python3 "$root_dir/packaging/scripts/resolve_target.py" --target "$target_id")"
expected_abi="$(printf '%s\n' "$target_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["dpdk"]["abi"])')"
runtime_prefix="$(printf '%s\n' "$target_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["runtime"]["prefix"])')"

if [[ ! -x "$binary_path" ]]; then
  echo "binary not found or not executable: $binary_path" >&2
  exit 1
fi

runtime_ld_library_path="${runtime_prefix}/current/lib:${runtime_prefix}/current/lib/x86_64-linux-gnu:${runtime_prefix}/current/lib64"
if [[ -n "${LD_LIBRARY_PATH:-}" ]]; then
  runtime_ld_library_path="${runtime_ld_library_path}:${LD_LIBRARY_PATH}"
fi

ldd_output="$(env LD_LIBRARY_PATH="$runtime_ld_library_path" ldd "$binary_path")"
if grep -Fq "not found" <<<"$ldd_output"; then
  echo "$ldd_output" >&2
  echo "unresolved shared libraries detected" >&2
  exit 1
fi

if ! grep -Eq "lib(dpdk|rte_eal)\.${expected_abi//./\\.}" <<<"$ldd_output"; then
  echo "$ldd_output" >&2
  echo "expected a DPDK linkage entry ending in ${expected_abi}" >&2
  exit 1
fi

if [[ -n "$output_json" ]]; then
  mkdir -p "$(dirname "$output_json")"
  python3 - "$binary_path" "$expected_abi" "$output_json" "$runtime_ld_library_path" <<'PY'
import json
import os
import subprocess
import sys

binary = sys.argv[1]
expected_abi = sys.argv[2]
output_path = sys.argv[3]
ld_library_path = sys.argv[4]
env = dict(os.environ)
env["LD_LIBRARY_PATH"] = ld_library_path
ldd_output = subprocess.check_output(["ldd", binary], text=True, env=env)
payload = {
    "binary": binary,
    "expected_dpdk_abi": expected_abi,
    "ldd": [line for line in ldd_output.splitlines() if line.strip()],
}
with open(output_path, "w", encoding="utf-8") as handle:
    json.dump(payload, handle, indent=2, sort_keys=True)
PY
fi
