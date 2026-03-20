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
RPS_TIERS="${RPS_TIERS:-500,1500}"
PAYLOAD_TIERS="${PAYLOAD_TIERS:-1024}"
CONNECTION_MODES="${CONNECTION_MODES:-keep_alive,new_connection_heavy}"
HTTP_REPEATS="${HTTP_REPEATS:-1}"
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
             RAMP_SECONDS="${RAMP_SECONDS:-30}" \
             STEADY_SECONDS="${STEADY_SECONDS:-45}" \
             PRE_ALLOCATED_VUS="${PRE_ALLOCATED_VUS:-0}" \
             MAX_VUS="${MAX_VUS:-0}" \
             CONTROLPLANE_WORKER_THREADS="${CONTROLPLANE_WORKER_THREADS:-4}" \
             TLS_INTERCEPT_IO_TIMEOUT_SECS="${TLS_INTERCEPT_IO_TIMEOUT_SECS:-10}" \
             TLS_INTERCEPT_H2_BODY_TIMEOUT_SECS="${TLS_INTERCEPT_H2_BODY_TIMEOUT_SECS:-30}" \
             TLS_H2_MAX_CONCURRENT_STREAMS="${TLS_H2_MAX_CONCURRENT_STREAMS:-}" \
             TLS_H2_MAX_REQUESTS_PER_CONNECTION="${TLS_H2_MAX_REQUESTS_PER_CONNECTION:-}" \
             TLS_H2_POOL_SHARDS="${TLS_H2_POOL_SHARDS:-}" \
             TLS_H2_DETAILED_METRICS="${TLS_H2_DETAILED_METRICS:-}" \
             TLS_H2_SELECTION_INFLIGHT_WEIGHT="${TLS_H2_SELECTION_INFLIGHT_WEIGHT:-}" \
             TLS_INTERCEPT_LISTEN_BACKLOG="${TLS_INTERCEPT_LISTEN_BACKLOG:-4096}" \
             NEUWERK_THREAD_CPU_MONITOR="${NEUWERK_THREAD_CPU_MONITOR:-}" \
             COLLECT_NEUWERK_METRICS="${COLLECT_NEUWERK_METRICS:-}" \
             COLLECT_CONSUMER_SOCKET_DIAG="${COLLECT_CONSUMER_SOCKET_DIAG:-}" \
             DPDK_WORKERS="${DPDK_WORKERS:-}" \
             DPDK_ALLOW_AZURE_MULTIWORKER="${DPDK_ALLOW_AZURE_MULTIWORKER:-}" \
             DPDK_SINGLE_QUEUE_MODE="${DPDK_SINGLE_QUEUE_MODE:-}" \
             DPDK_FORCE_SHARED_RX_DEMUX="${DPDK_FORCE_SHARED_RX_DEMUX:-}" \
             DPDK_HOUSEKEEPING_INTERVAL_PACKETS="${DPDK_HOUSEKEEPING_INTERVAL_PACKETS:-}" \
             DPDK_HOUSEKEEPING_INTERVAL_US="${DPDK_HOUSEKEEPING_INTERVAL_US:-}" \
             DPDK_PERF_MODE="${DPDK_PERF_MODE:-}" \
             DPDK_PIN_HTTPS_OWNER="${DPDK_PIN_HTTPS_OWNER:-}" \
             DPDK_SHARED_RX_OWNER_ONLY="${DPDK_SHARED_RX_OWNER_ONLY:-}" \
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
from collections import defaultdict

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
    "neuwerk_cpu_peak_pct": [],
}

status_reason_counts = {}
generator_limit_counts = {}
generator_limited_runs = 0
worker_failure_runs = 0

per_consumer_acc = {}
tls_client_accept_acc = defaultdict(list)
thread_hotspot_top_cpu_max_values = []
thread_hotspot_imbalance_values = []

for item in results:
    status_reason = item.get("status_reason")
    if isinstance(status_reason, str) and status_reason:
        status_reason_counts[status_reason] = status_reason_counts.get(status_reason, 0) + 1

    load_generator = item.get("load_generator", {})
    if isinstance(load_generator, dict):
        if load_generator.get("generator_limited"):
            generator_limited_runs += 1
        worker_failures = load_generator.get("worker_failures")
        if isinstance(worker_failures, int) and worker_failures > 0:
            worker_failure_runs += 1
        limit_counts = load_generator.get("generator_limit_counts", {})
        if isinstance(limit_counts, dict):
            for reason, value in limit_counts.items():
                if isinstance(reason, str) and isinstance(value, (int, float)):
                    generator_limit_counts[reason] = generator_limit_counts.get(reason, 0) + int(value)

    run_results = item.get("results", {})
    per_consumer = run_results.get("per_consumer", [])
    if isinstance(per_consumer, list):
        for consumer_item in per_consumer:
            if not isinstance(consumer_item, dict):
                continue
            consumer_ip = consumer_item.get("consumer")
            if not isinstance(consumer_ip, str):
                continue
            acc = per_consumer_acc.setdefault(
                consumer_ip,
                {
                    "offered_rps_target_values": [],
                    "effective_rps_steady_values": [],
                    "effective_rps_overall_values": [],
                    "error_rate_values": [],
                },
            )
            offered = consumer_item.get("offered_rps_target")
            if isinstance(offered, (int, float)):
                acc["offered_rps_target_values"].append(float(offered))
            steady = consumer_item.get("effective_rps_steady")
            if isinstance(steady, (int, float)):
                acc["effective_rps_steady_values"].append(float(steady))
            overall = consumer_item.get("effective_rps_overall")
            if isinstance(overall, (int, float)):
                acc["effective_rps_overall_values"].append(float(overall))
            error_rate = consumer_item.get("error_rate")
            if isinstance(error_rate, (int, float)):
                acc["error_rate_values"].append(float(error_rate))

    diagnostics = item.get("diagnostics", {})
    if isinstance(diagnostics, dict):
        tls_by_instance = diagnostics.get("tls_client_accept_by_neuwerk_instance", {})
        if isinstance(tls_by_instance, dict):
            for ip, value in tls_by_instance.items():
                if isinstance(ip, str) and isinstance(value, (int, float)):
                    tls_client_accept_acc[ip].append(float(value))
        thread_hotspot = diagnostics.get("thread_hotspot", {})
        if isinstance(thread_hotspot, dict):
            top_cpu = thread_hotspot.get("max_top_thread_cpu_pct_max")
            if isinstance(top_cpu, (int, float)):
                thread_hotspot_top_cpu_max_values.append(float(top_cpu))
            imbalance = thread_hotspot.get("max_dpdk_worker_cpu_imbalance_ratio")
            if isinstance(imbalance, (int, float)):
                thread_hotspot_imbalance_values.append(float(imbalance))

for item in results:
    r = item.get("results", {})
    for key in list(values.keys()):
        v = r.get(key)
        if isinstance(v, (int, float)):
            values[key].append(float(v))

if pass_count > 0 and fail_count == 0 and invalid_count == 0 and repeat_failed_i == 0:
    combo_status = "pass"
elif invalid_count > 0 and pass_count == 0 and fail_count == 0 and repeat_failed_i == 0:
    combo_status = "invalid"
else:
    combo_status = "fail"

classification = {"kind": combo_status}
if combo_status == "invalid":
    if generator_limited_runs > 0:
        classification["kind"] = "generator_limited"
        classification["generator_limit_counts"] = generator_limit_counts
    elif status_reason_counts:
        top_reason = max(status_reason_counts.items(), key=lambda kv: kv[1])[0]
        classification["kind"] = top_reason
elif combo_status == "fail" and status_reason_counts:
    classification["primary_reason"] = max(status_reason_counts.items(), key=lambda kv: kv[1])[0]

per_consumer_summary = []
for consumer_ip, acc in sorted(per_consumer_acc.items()):
    per_consumer_summary.append(
        {
            "consumer": consumer_ip,
            "offered_rps_target_median": (
                statistics.median(acc["offered_rps_target_values"])
                if acc["offered_rps_target_values"]
                else None
            ),
            "effective_rps_steady_median": (
                statistics.median(acc["effective_rps_steady_values"])
                if acc["effective_rps_steady_values"]
                else None
            ),
            "effective_rps_overall_median": (
                statistics.median(acc["effective_rps_overall_values"])
                if acc["effective_rps_overall_values"]
                else None
            ),
            "error_rate_median": (
                statistics.median(acc["error_rate_values"])
                if acc["error_rate_values"]
                else None
            ),
        }
    )

tls_client_accept_median_by_neuwerk_instance = {
    ip: statistics.median(values) for ip, values in sorted(tls_client_accept_acc.items()) if values
}

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
    "status": combo_status,
    "classification": classification,
    "status_reason_counts": status_reason_counts,
    "generator_limited_runs": generator_limited_runs,
    "worker_failure_runs": worker_failure_runs,
    "generator_limit_counts": generator_limit_counts,
    "per_consumer_summary": per_consumer_summary,
    "tls_client_accept_median_by_neuwerk_instance": tls_client_accept_median_by_neuwerk_instance,
    "median": {},
    "runs": results,
}

for key, items in values.items():
    agg["median"][key] = statistics.median(items) if items else None
agg["median"]["max_thread_cpu_pct_max"] = (
    statistics.median(thread_hotspot_top_cpu_max_values) if thread_hotspot_top_cpu_max_values else None
)
agg["median"]["max_dpdk_worker_cpu_imbalance_ratio"] = (
    statistics.median(thread_hotspot_imbalance_values) if thread_hotspot_imbalance_values else None
)

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
    "generator_limited_combo_count": sum(
        1
        for item in combos
        if isinstance(item.get("classification"), dict)
        and item.get("classification", {}).get("kind") == "generator_limited"
    ),
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
