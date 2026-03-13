#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)
REPO_DIR=$(cd "${ROOT_DIR}/.." && pwd)

source "${SCRIPT_DIR}/lib.sh"

require_bin ssh
require_bin ssh-keygen
require_bin python3
require_bin jq

: "${JUMPBOX_IP:?missing JUMPBOX_IP}"
: "${CONSUMER_IP:?missing CONSUMER_IP}"
: "${UPSTREAM_IP:?missing UPSTREAM_IP}"
: "${KEY_PATH:?missing KEY_PATH}"
: "${FW_MGMT_IPS:?missing FW_MGMT_IPS}"

if [ ! -f "${KEY_PATH}" ]; then
  echo "missing SSH key at ${KEY_PATH}" >&2
  exit 1
fi

CLOUD_PROVIDER="${CLOUD_PROVIDER:-unknown}"
FW_VCPU="${FW_VCPU:-4}"
STREAMS_LIST="${STREAMS_LIST:-1,4,8,16,32}"
RUN_SECONDS="${RUN_SECONDS:-60}"
WARMUP_SECONDS="${WARMUP_SECONDS:-15}"
REPEATS="${REPEATS:-5}"
IPERF_PORT="${IPERF_PORT:-5201}"
ENABLE_TCP="${ENABLE_TCP:-1}"
ENABLE_UDP="${ENABLE_UDP:-1}"
CPU_INVALID_AVG="${CPU_INVALID_AVG:-80}"
CPU_INVALID_MAX="${CPU_INVALID_MAX:-90}"
SSH_USER="${SSH_USER:-ubuntu}"
UPSTREAM_VIP="${UPSTREAM_VIP:-${UPSTREAM_IP}}"
RESOURCE_GROUP="${RESOURCE_GROUP:-}"
FIREWALL_INSTANCE_TYPE="${FIREWALL_INSTANCE_TYPE:-}"
CONSUMER_INSTANCE_TYPE="${CONSUMER_INSTANCE_TYPE:-}"
UPSTREAM_INSTANCE_TYPE="${UPSTREAM_INSTANCE_TYPE:-}"

ARTIFACT_DIR="${ARTIFACT_DIR:-${ROOT_DIR}/artifacts/throughput-matrix-$(date -u +%Y%m%dT%H%M%SZ)}"
RAW_DIR="${ARTIFACT_DIR}/raw"
RUNS_DIR="${ARTIFACT_DIR}/runs"
mkdir -p "${RAW_DIR}" "${RUNS_DIR}"

parse_csv_list() {
  local csv="$1"
  local -n out_ref="$2"
  IFS=',' read -r -a tmp <<< "$csv"
  out_ref=()
  local item
  for item in "${tmp[@]}"; do
    item="$(echo "$item" | xargs)"
    [ -z "$item" ] && continue
    out_ref+=("$item")
  done
}

declare -a streams=()
parse_csv_list "$STREAMS_LIST" streams
if [ "${#streams[@]}" -eq 0 ]; then
  echo "STREAMS_LIST produced no entries" >&2
  exit 1
fi

protocols=()
if [ "$ENABLE_TCP" = "1" ]; then
  protocols+=("tcp")
fi
if [ "$ENABLE_UDP" = "1" ]; then
  protocols+=("udp")
fi
if [ "${#protocols[@]}" -eq 0 ]; then
  echo "at least one of ENABLE_TCP/ENABLE_UDP must be 1" >&2
  exit 1
fi

remote_require_iperf3() {
  local host="$1"
  if ! ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$host" "command -v iperf3 >/dev/null 2>&1"; then
    echo "iperf3 is missing on host ${host}" >&2
    exit 1
  fi
}

ensure_upstream_iperf_server() {
  ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$UPSTREAM_IP" \
    "bash -lc 'if pgrep -f \"iperf3 -s -p ${IPERF_PORT}\" >/dev/null 2>&1; then exit 0; fi; iperf3 -s -p ${IPERF_PORT} -D >/tmp/iperf3-server-${IPERF_PORT}.log 2>&1; sleep 1; pgrep -f \"iperf3 -s -p ${IPERF_PORT}\" >/dev/null 2>&1'"
}

collect_fw_dpdk_bytes() {
  local out_file="$1"
  : > "$out_file"
  local ip metrics rx tx
  for ip in $FW_MGMT_IPS; do
    metrics="$(ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$ip" \
      "bash -lc 'METRICS_HOST=\$(grep \"^MGMT_IP=\" /etc/neuwerk/firewall.env 2>/dev/null | cut -d= -f2); [ -z \"\$METRICS_HOST\" ] && METRICS_HOST=127.0.0.1; curl -fsS http://\${METRICS_HOST}:8080/metrics'" 2>/dev/null || true)"
    rx="$(echo "$metrics" | awk '/^dpdk_rx_bytes_total /{print $2}' | tail -n1)"
    tx="$(echo "$metrics" | awk '/^dpdk_tx_bytes_total /{print $2}' | tail -n1)"
    [ -z "$rx" ] && rx=0
    [ -z "$tx" ] && tx=0
    echo "$ip $rx $tx" >> "$out_file"
  done
}

declare -a cpu_pids=()
start_cpu_monitor() {
  local role="$1"
  local ip="$2"
  local run_id="$3"
  local secs="$4"
  local safe_ip="${ip//./_}"
  local out_file="${RAW_DIR}/cpu.${run_id}.${role}.${safe_ip}.log"
  local err_file="${RAW_DIR}/cpu.${run_id}.${role}.${safe_ip}.err"
  (
    ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$ip" \
      "bash -lc 'if command -v mpstat >/dev/null 2>&1; then timeout ${secs} mpstat 1; else timeout ${secs} vmstat 1; fi'"
  ) >"$out_file" 2>"$err_file" &
  cpu_pids+=("$!")
}

wait_cpu_monitors() {
  local pid
  for pid in "${cpu_pids[@]}"; do
    wait "$pid" || true
  done
  cpu_pids=()
}

run_warmup() {
  local proto="$1"
  local streams="$2"
  local out_json="${RAW_DIR}/iperf.warmup.${proto}.p${streams}.json"
  local err_file="${RAW_DIR}/iperf.warmup.${proto}.p${streams}.err"
  local cmd
  if [ "$proto" = "udp" ]; then
    cmd="iperf3 -c ${UPSTREAM_IP} -p ${IPERF_PORT} -u -b 0 -t ${WARMUP_SECONDS} -P ${streams} --connect-timeout 5000 -J"
  else
    cmd="iperf3 -c ${UPSTREAM_IP} -p ${IPERF_PORT} -t ${WARMUP_SECONDS} -P ${streams} --connect-timeout 5000 -J"
  fi
  ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$CONSUMER_IP" "$cmd" >"$out_json" 2>"$err_file" || true
}

run_measured() {
  local proto="$1"
  local streams="$2"
  local repeat="$3"
  local run_id="${proto}.p${streams}.r${repeat}"
  local out_json="${RAW_DIR}/iperf.${run_id}.json"
  local err_file="${RAW_DIR}/iperf.${run_id}.err"
  local rc_file="${RAW_DIR}/iperf.${run_id}.rc"
  local pre_file="${RAW_DIR}/fw-metrics.${run_id}.pre.txt"
  local post_file="${RAW_DIR}/fw-metrics.${run_id}.post.txt"
  local run_result="${RUNS_DIR}/run.${run_id}.json"
  local cmd

  collect_fw_dpdk_bytes "$pre_file"

  local cpu_secs=$((RUN_SECONDS + 10))
  local ip
  for ip in $FW_MGMT_IPS; do
    start_cpu_monitor "firewall" "$ip" "$run_id" "$cpu_secs"
  done
  start_cpu_monitor "consumer" "$CONSUMER_IP" "$run_id" "$cpu_secs"
  start_cpu_monitor "upstream" "$UPSTREAM_IP" "$run_id" "$cpu_secs"

  if [ "$proto" = "udp" ]; then
    cmd="iperf3 -c ${UPSTREAM_IP} -p ${IPERF_PORT} -u -b 0 -t ${RUN_SECONDS} -P ${streams} --connect-timeout 5000 -J"
  else
    cmd="iperf3 -c ${UPSTREAM_IP} -p ${IPERF_PORT} -t ${RUN_SECONDS} -P ${streams} --connect-timeout 5000 -J"
  fi

  set +e
  ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$CONSUMER_IP" "$cmd" >"$out_json" 2>"$err_file"
  local rc=$?
  set -e
  echo "$rc" >"$rc_file"

  collect_fw_dpdk_bytes "$post_file"
  wait_cpu_monitors

  python3 - "$proto" "$streams" "$repeat" "$run_id" "$out_json" "$rc" "$pre_file" "$post_file" "$RAW_DIR" "$FW_VCPU" "$RUN_SECONDS" "$CPU_INVALID_AVG" "$CPU_INVALID_MAX" "$run_result" <<'PY'
import glob
import json
import os
import statistics
import sys

(
    proto,
    streams,
    repeat,
    run_id,
    iperf_path,
    rc,
    pre_path,
    post_path,
    raw_dir,
    fw_vcpu,
    run_seconds,
    cpu_invalid_avg,
    cpu_invalid_max,
    out_path,
) = sys.argv[1:]

streams_i = int(streams)
repeat_i = int(repeat)
rc_i = int(rc)
fw_vcpu_i = int(fw_vcpu)
run_seconds_i = int(run_seconds)
cpu_invalid_avg_f = float(cpu_invalid_avg)
cpu_invalid_max_f = float(cpu_invalid_max)

def parse_fw_totals(path):
    total_rx = 0.0
    total_tx = 0.0
    entries = {}
    if not os.path.exists(path):
        return entries, total_rx, total_tx
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) != 3:
                continue
            ip, rx, tx = parts
            try:
                rv = float(rx)
            except ValueError:
                rv = 0.0
            try:
                tv = float(tx)
            except ValueError:
                tv = 0.0
            entries[ip] = (rv, tv)
            total_rx += rv
            total_tx += tv
    return entries, total_rx, total_tx

def parse_cpu_used_samples(log_path):
    vals = []
    if not os.path.exists(log_path):
        return vals
    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            s = raw.strip()
            if not s:
                continue
            parts = s.split()
            if "Average:" in s and " all " in f" {s} ":
                try:
                    idle = float(parts[-1])
                    vals.append(max(0.0, min(100.0, 100.0 - idle)))
                except (ValueError, IndexError):
                    pass
                continue
            if len(parts) >= 3 and ":" in parts[0] and parts[1] == "all":
                try:
                    idle = float(parts[-1])
                    vals.append(max(0.0, min(100.0, 100.0 - idle)))
                except ValueError:
                    pass
                continue
            # vmstat fallback
            if len(parts) >= 15 and parts[0].isdigit() and parts[1].isdigit():
                try:
                    idle = float(parts[14])
                    vals.append(max(0.0, min(100.0, 100.0 - idle)))
                except ValueError:
                    pass
    return vals

def percentile(values, p):
    if not values:
        return None
    data = sorted(values)
    if len(data) == 1:
        return data[0]
    k = (len(data) - 1) * p
    f = int(k)
    c = min(f + 1, len(data) - 1)
    if f == c:
        return data[f]
    return data[f] + (data[c] - data[f]) * (k - f)

iperf_ok = False
throughput_bps = None
throughput_gbps = None
throughput_gbps_per_core = None
retransmits = None
udp_lost_percent = None
udp_jitter_ms = None

if rc_i == 0 and os.path.exists(iperf_path):
    try:
        with open(iperf_path, "r", encoding="utf-8") as f:
            payload = json.load(f)
        end = payload.get("end", {}) if isinstance(payload, dict) else {}
        if proto == "tcp":
            sum_received = end.get("sum_received", {}) if isinstance(end, dict) else {}
            sum_sent = end.get("sum_sent", {}) if isinstance(end, dict) else {}
            bps = sum_received.get("bits_per_second")
            if bps is None:
                bps = sum_sent.get("bits_per_second")
            if bps is not None:
                throughput_bps = float(bps)
                throughput_gbps = throughput_bps / 1_000_000_000.0
                throughput_gbps_per_core = (
                    throughput_gbps / fw_vcpu_i if fw_vcpu_i > 0 else None
                )
            if isinstance(sum_sent, dict):
                rtx = sum_sent.get("retransmits")
                if rtx is not None:
                    retransmits = float(rtx)
        else:
            udp_sum = end.get("sum", {}) if isinstance(end, dict) else {}
            bps = udp_sum.get("bits_per_second")
            if bps is None:
                bps = end.get("sum_received", {}).get("bits_per_second") if isinstance(end.get("sum_received", {}), dict) else None
            if bps is not None:
                throughput_bps = float(bps)
                throughput_gbps = throughput_bps / 1_000_000_000.0
                throughput_gbps_per_core = (
                    throughput_gbps / fw_vcpu_i if fw_vcpu_i > 0 else None
                )
            lp = udp_sum.get("lost_percent")
            if lp is not None:
                udp_lost_percent = float(lp)
            jm = udp_sum.get("jitter_ms")
            if jm is not None:
                udp_jitter_ms = float(jm)
        iperf_ok = throughput_bps is not None
    except Exception:
        iperf_ok = False

pre_map, pre_rx, pre_tx = parse_fw_totals(pre_path)
post_map, post_rx, post_tx = parse_fw_totals(post_path)
fw_rx_delta = post_rx - pre_rx
fw_tx_delta = post_tx - pre_tx

per_fw = []
for ip in sorted(set(pre_map.keys()) | set(post_map.keys())):
    prv = pre_map.get(ip, (0.0, 0.0))
    pov = post_map.get(ip, (0.0, 0.0))
    per_fw.append(
        {
            "instance": ip,
            "rx_bytes_delta": pov[0] - prv[0],
            "tx_bytes_delta": pov[1] - prv[1],
        }
    )

cpu_files = sorted(glob.glob(os.path.join(raw_dir, f"cpu.{run_id}.*.log")))
cpu_hosts = []
role_values = {}
for path in cpu_files:
    name = os.path.basename(path)
    prefix = f"cpu.{run_id}."
    suffix = ".log"
    if not name.startswith(prefix) or not name.endswith(suffix):
        continue
    middle = name[len(prefix):-len(suffix)]
    chunks = middle.split(".", 1)
    if len(chunks) != 2:
        continue
    role, ip_raw = chunks
    ip = ip_raw.replace("_", ".")
    vals = parse_cpu_used_samples(path)
    host = {
        "role": role,
        "instance": ip,
        "samples": len(vals),
        "cpu_used_pct_avg": round(statistics.fmean(vals), 3) if vals else None,
        "cpu_used_pct_max": round(max(vals), 3) if vals else None,
    }
    cpu_hosts.append(host)
    role_values.setdefault(role, {"avg": [], "max": []})
    if host["cpu_used_pct_avg"] is not None:
        role_values[role]["avg"].append(host["cpu_used_pct_avg"])
    if host["cpu_used_pct_max"] is not None:
        role_values[role]["max"].append(host["cpu_used_pct_max"])

cpu_role_summary = {}
for role, values in role_values.items():
    avg_vals = values["avg"]
    max_vals = values["max"]
    cpu_role_summary[role] = {
        "instances": len([h for h in cpu_hosts if h.get("role") == role]),
        "cpu_used_pct_avg_mean": round(statistics.fmean(avg_vals), 3) if avg_vals else None,
        "cpu_used_pct_avg_p95": round(percentile(avg_vals, 0.95), 3) if avg_vals else None,
        "cpu_used_pct_max_max": round(max(max_vals), 3) if max_vals else None,
    }

invalidation_reasons = []
for role in ("consumer", "upstream"):
    summary = cpu_role_summary.get(role, {})
    avg_mean = summary.get("cpu_used_pct_avg_mean")
    max_max = summary.get("cpu_used_pct_max_max")
    if avg_mean is not None and avg_mean > cpu_invalid_avg_f:
        invalidation_reasons.append(
            f"{role}_avg_cpu_gt_{cpu_invalid_avg_f:g}"
        )
    if max_max is not None and max_max > cpu_invalid_max_f:
        invalidation_reasons.append(
            f"{role}_max_cpu_gt_{cpu_invalid_max_f:g}"
        )

valid_for_recommendation = iperf_ok and not invalidation_reasons

result = {
    "run_id": run_id,
    "protocol": proto,
    "streams": streams_i,
    "repeat": repeat_i,
    "run_seconds": run_seconds_i,
    "status": "pass" if iperf_ok else "fail",
    "valid_for_recommendation": valid_for_recommendation,
    "invalidation_reasons": invalidation_reasons,
    "throughput_bps": throughput_bps,
    "throughput_gbps": throughput_gbps,
    "throughput_gbps_per_core": throughput_gbps_per_core,
    "tcp_retransmits": retransmits,
    "udp_lost_percent": udp_lost_percent,
    "udp_jitter_ms": udp_jitter_ms,
    "firewall_dpdk": {
        "rx_bytes_delta_total": fw_rx_delta,
        "tx_bytes_delta_total": fw_tx_delta,
        "per_instance": per_fw,
    },
    "cpu": {
        "hosts": cpu_hosts,
        "roles": cpu_role_summary,
    },
}

with open(out_path, "w", encoding="utf-8") as out:
    json.dump(result, out, indent=2, sort_keys=True)
    out.write("\n")
PY
}

remote_require_iperf3 "$CONSUMER_IP"
remote_require_iperf3 "$UPSTREAM_IP"
ensure_upstream_iperf_server

consumer_iperf3_version="$(ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$CONSUMER_IP" "iperf3 --version | head -n1" || echo unknown)"
upstream_iperf3_version="$(ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$UPSTREAM_IP" "iperf3 --version | head -n1" || echo unknown)"

git_sha="$(git -C "${REPO_DIR}" rev-parse --short HEAD 2>/dev/null || echo unknown)"

jq -n \
  --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg cloud_provider "$CLOUD_PROVIDER" \
  --arg git_commit "$git_sha" \
  --arg jumpbox_ip "$JUMPBOX_IP" \
  --arg consumer_ip "$CONSUMER_IP" \
  --arg upstream_ip "$UPSTREAM_IP" \
  --arg upstream_vip "$UPSTREAM_VIP" \
  --arg fw_mgmt_ips "$FW_MGMT_IPS" \
  --arg resource_group "$RESOURCE_GROUP" \
  --arg firewall_instance_type "$FIREWALL_INSTANCE_TYPE" \
  --arg consumer_instance_type "$CONSUMER_INSTANCE_TYPE" \
  --arg upstream_instance_type "$UPSTREAM_INSTANCE_TYPE" \
  --arg consumer_iperf3_version "$consumer_iperf3_version" \
  --arg upstream_iperf3_version "$upstream_iperf3_version" \
  ' {
    generated_at: $generated_at,
    cloud_provider: $cloud_provider,
    git_commit: $git_commit,
    hosts: {
      jumpbox_ip: $jumpbox_ip,
      consumer_ip: $consumer_ip,
      upstream_ip: $upstream_ip,
      upstream_vip: $upstream_vip,
      firewall_mgmt_ips: ($fw_mgmt_ips | split(" ") | map(select(length > 0)))
    },
    cloud_context: {
      resource_group: (if $resource_group == "" then null else $resource_group end),
      firewall_instance_type: (if $firewall_instance_type == "" then null else $firewall_instance_type end),
      consumer_instance_type: (if $consumer_instance_type == "" then null else $consumer_instance_type end),
      upstream_instance_type: (if $upstream_instance_type == "" then null else $upstream_instance_type end)
    },
    tool_versions: {
      consumer_iperf3: $consumer_iperf3_version,
      upstream_iperf3: $upstream_iperf3_version
    }
  }' > "${ARTIFACT_DIR}/context.json"

jq -n \
  --argjson fw_vcpu "$FW_VCPU" \
  --arg streams_csv "$STREAMS_LIST" \
  --argjson run_seconds "$RUN_SECONDS" \
  --argjson warmup_seconds "$WARMUP_SECONDS" \
  --argjson repeats "$REPEATS" \
  --argjson iperf_port "$IPERF_PORT" \
  --argjson enable_tcp "$ENABLE_TCP" \
  --argjson enable_udp "$ENABLE_UDP" \
  --argjson cpu_invalid_avg "$CPU_INVALID_AVG" \
  --argjson cpu_invalid_max "$CPU_INVALID_MAX" \
  '{
    scenario: "raw_ip_throughput_per_core",
    fw_vcpu: $fw_vcpu,
    streams: ($streams_csv | split(",") | map(gsub("^\\s+|\\s+$"; "") | tonumber)),
    run_seconds: $run_seconds,
    warmup_seconds: $warmup_seconds,
    repeats: $repeats,
    iperf_port: $iperf_port,
    protocols: ([if $enable_tcp == 1 then "tcp" else empty end, if $enable_udp == 1 then "udp" else empty end]),
    invalidation_thresholds: {
      consumer_or_upstream_avg_cpu_pct_gt: $cpu_invalid_avg,
      consumer_or_upstream_max_cpu_pct_gt: $cpu_invalid_max
    }
  }' > "${ARTIFACT_DIR}/workload.json"

echo "artifact dir: ${ARTIFACT_DIR}"
echo "warming up"
for proto in "${protocols[@]}"; do
  for stream in "${streams[@]}"; do
    echo "warmup proto=${proto} streams=${stream}"
    run_warmup "$proto" "$stream"
  done
done

echo "running measured matrix"
for proto in "${protocols[@]}"; do
  for stream in "${streams[@]}"; do
    for repeat in $(seq 1 "$REPEATS"); do
      echo "run proto=${proto} streams=${stream} repeat=${repeat}/${REPEATS}"
      run_measured "$proto" "$stream" "$repeat"
    done
  done
done

python3 - "$RUNS_DIR" "$ARTIFACT_DIR" <<'PY'
import glob
import json
import os
import statistics
import sys

runs_dir, artifact_dir = sys.argv[1:]
run_files = sorted(glob.glob(os.path.join(runs_dir, "run.*.json")))
if not run_files:
    raise SystemExit("no run result files found")

runs = []
for path in run_files:
    with open(path, "r", encoding="utf-8") as f:
        payload = json.load(f)
    payload["_path"] = os.path.relpath(path, artifact_dir)
    runs.append(payload)

valid_runs = [r for r in runs if r.get("valid_for_recommendation")]

def percentile(values, p):
    if not values:
        return None
    data = sorted(values)
    if len(data) == 1:
        return data[0]
    k = (len(data) - 1) * p
    f = int(k)
    c = min(f + 1, len(data) - 1)
    if f == c:
        return data[f]
    return data[f] + (data[c] - data[f]) * (k - f)

groups = {}
for run in valid_runs:
    key = (run.get("protocol"), int(run.get("streams", 0)))
    groups.setdefault(key, []).append(run)

matrix = []
for (protocol, streams), items in sorted(groups.items(), key=lambda x: (x[0][0], x[0][1])):
    gbps = [float(i["throughput_gbps"]) for i in items if i.get("throughput_gbps") is not None]
    gbps_pc = [
        float(i["throughput_gbps_per_core"]) for i in items if i.get("throughput_gbps_per_core") is not None
    ]
    row = {
        "protocol": protocol,
        "streams": streams,
        "valid_run_count": len(items),
        "throughput_gbps_median": round(statistics.median(gbps), 6) if gbps else None,
        "throughput_gbps_p95": round(percentile(gbps, 0.95), 6) if gbps else None,
        "throughput_gbps_per_core_median": round(statistics.median(gbps_pc), 6) if gbps_pc else None,
        "throughput_gbps_per_core_p95": round(percentile(gbps_pc, 0.95), 6) if gbps_pc else None,
    }
    if protocol == "tcp":
        rtx = [float(i["tcp_retransmits"]) for i in items if i.get("tcp_retransmits") is not None]
        row["tcp_retransmits_median"] = round(statistics.median(rtx), 3) if rtx else None
    if protocol == "udp":
        loss = [float(i["udp_lost_percent"]) for i in items if i.get("udp_lost_percent") is not None]
        jitter = [float(i["udp_jitter_ms"]) for i in items if i.get("udp_jitter_ms") is not None]
        row["udp_lost_percent_median"] = round(statistics.median(loss), 6) if loss else None
        row["udp_jitter_ms_median"] = round(statistics.median(jitter), 6) if jitter else None
    matrix.append(row)

def find_best(protocol):
    candidates = [r for r in matrix if r.get("protocol") == protocol and r.get("throughput_gbps_median") is not None]
    if not candidates:
        return None
    return max(candidates, key=lambda r: r.get("throughput_gbps_median", 0.0))

best_tcp = find_best("tcp")
best_udp = find_best("udp")

result = {
    "scenario": "raw_ip_throughput_per_core",
    "status": "pass" if matrix else "fail",
    "valid_run_count": len(valid_runs),
    "total_run_count": len(runs),
    "max_tcp_gbps": best_tcp.get("throughput_gbps_median") if best_tcp else None,
    "max_udp_gbps": best_udp.get("throughput_gbps_median") if best_udp else None,
    "max_tcp_gbps_per_core": best_tcp.get("throughput_gbps_per_core_median") if best_tcp else None,
    "max_udp_gbps_per_core": best_udp.get("throughput_gbps_per_core_median") if best_udp else None,
    "selected_streams": {
        "tcp": best_tcp.get("streams") if best_tcp else None,
        "udp": best_udp.get("streams") if best_udp else None,
    },
}

matrix_summary = {
    "scenario": "raw_ip_throughput_per_core",
    "runs": runs,
    "valid_runs": valid_runs,
    "groups": matrix,
}

with open(os.path.join(artifact_dir, "result.json"), "w", encoding="utf-8") as out:
    json.dump(result, out, indent=2, sort_keys=True)
    out.write("\n")

with open(os.path.join(artifact_dir, "matrix-summary.json"), "w", encoding="utf-8") as out:
    json.dump(matrix_summary, out, indent=2, sort_keys=True)
    out.write("\n")
PY

echo "throughput matrix complete: ${ARTIFACT_DIR}"
