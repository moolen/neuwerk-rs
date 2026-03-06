#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)
TF_DIR="${TF_DIR:-${ROOT_DIR}/terraform}"
KEY_PATH="${KEY_PATH:-${ROOT_DIR}/../.secrets/ssh/azure_e2e}"
RUN_SCRIPT="${SCRIPT_DIR}/http-perf-run.sh"
SETUP_SCRIPT="${SCRIPT_DIR}/http-perf-setup.sh"

HTTP_PERF_SCENARIOS="${HTTP_PERF_SCENARIOS:-l34_allow_webhooks,l34_mixed_allow_deny,tls_sni_allow_only,tls_intercept_http_path}"
RPS_TIERS="${RPS_TIERS:-500,1500,3000}"
CONTINUE_ON_ERROR="${CONTINUE_ON_ERROR:-1}"
MATRIX_ARTIFACT_DIR="${MATRIX_ARTIFACT_DIR:-${ROOT_DIR}/artifacts/http-perf-matrix-$(date -u +%Y%m%dT%H%M%SZ)}"

source "${ROOT_DIR}/../common/lib.sh"

require_bin terraform
require_bin jq
require_bin python3
require_bin ssh

if [ ! -f "$KEY_PATH" ]; then
  echo "missing SSH key at ${KEY_PATH}" >&2
  exit 1
fi

mkdir -p "$MATRIX_ARTIFACT_DIR"

echo "running matrix setup"
TF_DIR="$TF_DIR" KEY_PATH="$KEY_PATH" "$SETUP_SCRIPT"

IFS=',' read -r -a scenarios <<< "$HTTP_PERF_SCENARIOS"
IFS=',' read -r -a tiers <<< "$RPS_TIERS"

declare -a result_files=()
failed=0

for scenario in "${scenarios[@]}"; do
  scenario="$(echo "$scenario" | xargs)"
  [ -z "$scenario" ] && continue
  for tier in "${tiers[@]}"; do
    tier="$(echo "$tier" | xargs)"
    [ -z "$tier" ] && continue
    run_dir="${MATRIX_ARTIFACT_DIR}/${scenario}/rps-${tier}"
    mkdir -p "$run_dir"
    echo "scenario=${scenario} rps=${tier} dir=${run_dir}"
    if TF_DIR="$TF_DIR" KEY_PATH="$KEY_PATH" SKIP_SETUP=1 SCENARIO="$scenario" RPS="$tier" ARTIFACT_DIR="$run_dir" "$RUN_SCRIPT"; then
      :
    else
      failed=1
      if [ "$CONTINUE_ON_ERROR" != "1" ]; then
        echo "run failed and CONTINUE_ON_ERROR=0" >&2
        exit 1
      fi
    fi
    if [ -f "${run_dir}/result.json" ]; then
      result_files+=("${run_dir}/result.json")
    fi
  done
done

if [ "${#result_files[@]}" -eq 0 ]; then
  echo "no result.json files produced" >&2
  exit 1
fi

python3 - "$MATRIX_ARTIFACT_DIR/matrix-summary.json" "${result_files[@]}" <<'PY'
import json
import sys
from datetime import datetime, timezone

if len(sys.argv) < 3:
    raise SystemExit("usage: matrix_summary <out> <result1> [result2...]")

out_path = sys.argv[1]
result_paths = sys.argv[2:]

results = []
for path in result_paths:
    with open(path, "r", encoding="utf-8") as f:
        payload = json.load(f)
    payload["_path"] = path
    results.append(payload)

highest = {}
for item in results:
    scenario = item.get("scenario", "unknown")
    if item.get("status") != "pass":
        continue
    tier = int(item.get("rps_target", 0))
    prev = highest.get(scenario, 0)
    if tier > prev:
        highest[scenario] = tier

summary = {
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "run_count": len(results),
    "results": results,
    "highest_tier_reached": highest,
}

with open(out_path, "w", encoding="utf-8") as out:
    json.dump(summary, out, indent=2, sort_keys=True)
    out.write("\n")
PY

echo "matrix summary: ${MATRIX_ARTIFACT_DIR}/matrix-summary.json"

if [ "$failed" -ne 0 ]; then
  exit 1
fi
