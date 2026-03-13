#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)

source "${SCRIPT_DIR}/lib.sh"

require_bin jq
require_bin python3

RUN_SCRIPT="${RUN_SCRIPT:-${SCRIPT_DIR}/http-perf-run.sh}"
SETUP_SCRIPT="${SETUP_SCRIPT:-${SCRIPT_DIR}/http-perf-setup.sh}"

if [ ! -x "$RUN_SCRIPT" ]; then
  echo "missing executable run script: ${RUN_SCRIPT}" >&2
  exit 1
fi
if [ ! -x "$SETUP_SCRIPT" ]; then
  echo "missing executable setup script: ${SETUP_SCRIPT}" >&2
  exit 1
fi

: "${JUMPBOX_IP:?missing JUMPBOX_IP}"
: "${UPSTREAM_VIP:?missing UPSTREAM_VIP}"
: "${UPSTREAM_IP:?missing UPSTREAM_IP}"
: "${CONSUMER_IPS:?missing CONSUMER_IPS}"
: "${FW_MGMT_IPS:?missing FW_MGMT_IPS}"
: "${KEY_PATH:?missing KEY_PATH}"
: "${POLICY_DIR:?missing POLICY_DIR}"
: "${CONFIGURE_POLICY_SCRIPT:?missing CONFIGURE_POLICY_SCRIPT}"
: "${MINT_API_TOKEN:?missing MINT_API_TOKEN}"

HTTP_PERF_SCENARIOS="${HTTP_PERF_SCENARIOS:-http_l34_allow,https_l34_allow,tls_intercept_http_path}"
RPS_TIERS="${RPS_TIERS:-500,1500,3000}"
PAYLOAD_TIERS="${PAYLOAD_TIERS:-1024,32768}"
CONNECTION_MODES="${CONNECTION_MODES:-keep_alive,new_connection_heavy}"
HTTP_REPEATS="${HTTP_REPEATS:-3}"
CONTINUE_ON_ERROR="${CONTINUE_ON_ERROR:-1}"
MATRIX_ARTIFACT_DIR="${MATRIX_ARTIFACT_DIR:-${ROOT_DIR}/artifacts/http-perf-matrix-$(date -u +%Y%m%dT%H%M%SZ)}"

mkdir -p "$MATRIX_ARTIFACT_DIR"

echo "running matrix setup"
JUMPBOX_IP="$JUMPBOX_IP" \
UPSTREAM_VIP="$UPSTREAM_VIP" \
UPSTREAM_IP="$UPSTREAM_IP" \
CONSUMER_IPS="$CONSUMER_IPS" \
FW_MGMT_IPS="$FW_MGMT_IPS" \
KEY_PATH="$KEY_PATH" \
DNS_ZONE="${DNS_ZONE:-upstream.test}" \
SSH_USER="${SSH_USER:-ubuntu}" \
"$SETUP_SCRIPT"

IFS=',' read -r -a scenarios <<< "$HTTP_PERF_SCENARIOS"
IFS=',' read -r -a tiers <<< "$RPS_TIERS"
IFS=',' read -r -a payloads <<< "$PAYLOAD_TIERS"
IFS=',' read -r -a conn_modes <<< "$CONNECTION_MODES"

failed=0
combo_index=0

for scenario in "${scenarios[@]}"; do
  scenario="$(echo "$scenario" | xargs)"
  [ -z "$scenario" ] && continue
  for payload in "${payloads[@]}"; do
    payload="$(echo "$payload" | xargs)"
    [ -z "$payload" ] && continue
    for conn_mode in "${conn_modes[@]}"; do
      conn_mode="$(echo "$conn_mode" | xargs)"
      [ -z "$conn_mode" ] && continue
      for tier in "${tiers[@]}"; do
        tier="$(echo "$tier" | xargs)"
        [ -z "$tier" ] && continue

        combo_index=$((combo_index + 1))
        combo_dir="${MATRIX_ARTIFACT_DIR}/${scenario}/payload-${payload}/${conn_mode}/rps-${tier}"
        mkdir -p "$combo_dir"
        echo "combo=${combo_index} scenario=${scenario} payload=${payload} conn_mode=${conn_mode} rps=${tier}"

        repeat_failed=0
        for repeat in $(seq 1 "$HTTP_REPEATS"); do
          run_dir="${combo_dir}/repeat-${repeat}"
          mkdir -p "$run_dir"
          echo "  repeat=${repeat}/${HTTP_REPEATS} dir=${run_dir}"

          if JUMPBOX_IP="$JUMPBOX_IP" \
             UPSTREAM_VIP="$UPSTREAM_VIP" \
             UPSTREAM_IP="$UPSTREAM_IP" \
             CONSUMER_IPS="$CONSUMER_IPS" \
             FW_MGMT_IPS="$FW_MGMT_IPS" \
             KEY_PATH="$KEY_PATH" \
             SSH_USER="${SSH_USER:-ubuntu}" \
             CLOUD_PROVIDER="${CLOUD_PROVIDER:-unknown}" \
             DNS_ZONE="${DNS_ZONE:-upstream.test}" \
             MINT_API_TOKEN="$MINT_API_TOKEN" \
             CONFIGURE_POLICY_SCRIPT="$CONFIGURE_POLICY_SCRIPT" \
             POLICY_DIR="$POLICY_DIR" \
             K6_SCRIPT_LOCAL="${K6_SCRIPT_LOCAL:-${SCRIPT_DIR}/http-perf/k6/webhook.js}" \
             SETUP_SCRIPT="$SETUP_SCRIPT" \
             COLLECT_SCRIPT="${COLLECT_SCRIPT:-${SCRIPT_DIR}/http-perf-collect.sh}" \
             REGION="${REGION:-unknown}" \
             RESOURCE_GROUP="${RESOURCE_GROUP:-unknown}" \
             FW_INSTANCE_TYPE="${FW_INSTANCE_TYPE:-unknown}" \
             CONSUMER_INSTANCE_TYPE="${CONSUMER_INSTANCE_TYPE:-unknown}" \
             UPSTREAM_INSTANCE_TYPE="${UPSTREAM_INSTANCE_TYPE:-unknown}" \
             SCENARIO="$scenario" \
             RPS="$tier" \
             PAYLOAD_BYTES="$payload" \
             CONNECTION_MODE="$conn_mode" \
             SKIP_SETUP=1 \
             ARTIFACT_DIR="$run_dir" \
             "$RUN_SCRIPT"; then
            :
          else
            repeat_failed=1
            failed=1
            if [ "$CONTINUE_ON_ERROR" != "1" ]; then
              echo "run failed and CONTINUE_ON_ERROR=0" >&2
              exit 1
            fi
          fi
        done

        python3 - "$combo_dir" "$scenario" "$payload" "$conn_mode" "$tier" "$HTTP_REPEATS" "$repeat_failed" <<'PY'
import glob
import json
import os
import statistics
import sys

combo_dir, scenario, payload, conn_mode, rps, repeats, repeat_failed = sys.argv[1:]
expected_repeats = int(repeats)
repeat_failed_i = int(repeat_failed)

result_files = sorted(glob.glob(os.path.join(combo_dir, "repeat-*", "result.json")))
results = []
for path in result_files:
    with open(path, "r", encoding="utf-8") as f:
        payload_j = json.load(f)
    payload_j["_path"] = os.path.relpath(path, combo_dir)
    results.append(payload_j)

status_list = [r.get("status") for r in results]
pass_count = sum(1 for s in status_list if s == "pass")
invalid_count = sum(1 for s in status_list if s == "invalid")
fail_count = sum(1 for s in status_list if s == "fail")

values = {
    "effective_rps": [],
    "latency_p95_ms_max": [],
    "latency_p99_ms_max": [],
    "error_rate": [],
    "firewall_cpu_peak_pct": [],
}

for item in results:
    r = item.get("results", {})
    for key in list(values.keys()):
        v = r.get(key)
        if isinstance(v, (int, float)):
            values[key].append(float(v))

agg = {
    "scenario": scenario,
    "payload_bytes": int(payload),
    "connection_mode": conn_mode,
    "rps_target": int(rps),
    "expected_repeats": expected_repeats,
    "observed_repeats": len(results),
    "pass_count": pass_count,
    "fail_count": fail_count,
    "invalid_count": invalid_count,
    "status": (
        "pass"
        if pass_count > 0 and fail_count == 0 and invalid_count == 0 and repeat_failed_i == 0
        else "invalid"
        if invalid_count > 0 and pass_count == 0 and fail_count == 0 and repeat_failed_i == 0
        else "fail"
    ),
    "median": {},
    "runs": results,
}

for key, items in values.items():
    agg["median"][key] = statistics.median(items) if items else None

with open(os.path.join(combo_dir, "combo-result.json"), "w", encoding="utf-8") as out:
    json.dump(agg, out, indent=2, sort_keys=True)
    out.write("\n")
PY
      done
    done
  done
done

python3 - "$MATRIX_ARTIFACT_DIR" <<'PY'
import glob
import json
import os
import sys

matrix_dir = sys.argv[1]
combo_files = sorted(glob.glob(os.path.join(matrix_dir, "**", "combo-result.json"), recursive=True))
if not combo_files:
    raise SystemExit("no combo-result.json files produced")

combos = []
for path in combo_files:
    with open(path, "r", encoding="utf-8") as f:
        payload = json.load(f)
    payload["_path"] = os.path.relpath(path, matrix_dir)
    combos.append(payload)

highest = {}
for item in combos:
    if item.get("status") != "pass":
      continue
    key = f"{item.get('scenario')}|payload={item.get('payload_bytes')}|mode={item.get('connection_mode')}"
    tier = int(item.get("rps_target", 0))
    if key not in highest or tier > highest[key]["rps_target"]:
        highest[key] = {
            "scenario": item.get("scenario"),
            "payload_bytes": item.get("payload_bytes"),
            "connection_mode": item.get("connection_mode"),
            "rps_target": tier,
            "effective_rps_median": item.get("median", {}).get("effective_rps"),
            "latency_p99_ms_max_median": item.get("median", {}).get("latency_p99_ms_max"),
            "error_rate_median": item.get("median", {}).get("error_rate"),
        }

summary = {
    "scenario": "http_https_dpi_matrix",
    "combo_count": len(combos),
    "pass_count": sum(1 for item in combos if item.get("status") == "pass"),
    "fail_count": sum(1 for item in combos if item.get("status") == "fail"),
    "invalid_count": sum(1 for item in combos if item.get("status") == "invalid"),
    "combos": combos,
    "highest_tier_reached": sorted(highest.values(), key=lambda x: (x["scenario"], x["payload_bytes"], x["connection_mode"])),
}

with open(os.path.join(matrix_dir, "matrix-summary.json"), "w", encoding="utf-8") as out:
    json.dump(summary, out, indent=2, sort_keys=True)
    out.write("\n")
PY

echo "http perf matrix complete: ${MATRIX_ARTIFACT_DIR}"

if [ "$failed" -ne 0 ]; then
  exit 1
fi
