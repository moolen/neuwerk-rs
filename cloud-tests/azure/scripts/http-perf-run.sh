#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)
TF_DIR="${TF_DIR:-${ROOT_DIR}/terraform}"
KEY_PATH="${KEY_PATH:-${ROOT_DIR}/../.secrets/ssh/azure_e2e}"
DNS_ZONE="${DNS_ZONE:-upstream.test}"
RESOLVE_FW_IPS="${ROOT_DIR}/scripts/resolve-firewall-mgmt-ips.sh"
CONFIGURE_POLICY_SCRIPT="${ROOT_DIR}/scripts/configure-policy.sh"
MINT_API_TOKEN="${ROOT_DIR}/scripts/mint-api-token.sh"
SETUP_SCRIPT="${SCRIPT_DIR}/http-perf-setup.sh"
COLLECT_SCRIPT="${SCRIPT_DIR}/http-perf-collect.sh"
K6_SCRIPT_LOCAL="${ROOT_DIR}/http-perf/k6/webhook.js"
POLICY_DIR="${ROOT_DIR}/policies/http-perf"

SCENARIO="${SCENARIO:-l34_allow_webhooks}"
RPS="${RPS:-500}"
RAMP_SECONDS="${RAMP_SECONDS:-30}"
STEADY_SECONDS="${STEADY_SECONDS:-45}"
PAYLOAD_BYTES="${PAYLOAD_BYTES:-32768}"
PRE_ALLOCATED_VUS="${PRE_ALLOCATED_VUS:-0}"
MAX_VUS="${MAX_VUS:-0}"
SKIP_SETUP="${SKIP_SETUP:-0}"
ARTIFACT_DIR="${ARTIFACT_DIR:-${ROOT_DIR}/artifacts/http-perf-${SCENARIO}-rps${RPS}-$(date -u +%Y%m%dT%H%M%SZ)}"
TARGET_URLS_OVERRIDE="${TARGET_URLS_OVERRIDE:-}"
REQUEST_PATH_OVERRIDE="${REQUEST_PATH_OVERRIDE:-}"
TEMP_POLICY_FILE=""

cleanup() {
  if [ -n "${TEMP_POLICY_FILE}" ]; then
    rm -f "${TEMP_POLICY_FILE}" || true
  fi
}
trap cleanup EXIT

source "${ROOT_DIR}/../common/lib.sh"

require_bin terraform
require_bin az
require_bin jq
require_bin ssh
require_bin python3
require_bin openssl

if [ ! -f "${KEY_PATH}" ]; then
  echo "missing SSH key at ${KEY_PATH}" >&2
  exit 1
fi

if [ ! -x "${CONFIGURE_POLICY_SCRIPT}" ]; then
  echo "missing policy script: ${CONFIGURE_POLICY_SCRIPT}" >&2
  exit 1
fi

if [ ! -x "${MINT_API_TOKEN}" ]; then
  echo "missing token script: ${MINT_API_TOKEN}" >&2
  exit 1
fi

if [ ! -x "${COLLECT_SCRIPT}" ]; then
  echo "missing collect script: ${COLLECT_SCRIPT}" >&2
  exit 1
fi

if [ ! -f "${K6_SCRIPT_LOCAL}" ]; then
  echo "missing k6 script: ${K6_SCRIPT_LOCAL}" >&2
  exit 1
fi

az account show >/dev/null 2>&1 || {
  echo "az login required" >&2
  exit 1
}

mkdir -p "${ARTIFACT_DIR}/raw"

if [ "${SKIP_SETUP}" != "1" ]; then
  echo "running setup before scenario run"
  TF_DIR="$TF_DIR" KEY_PATH="$KEY_PATH" DNS_ZONE="$DNS_ZONE" "$SETUP_SCRIPT"
fi

pushd "$TF_DIR" >/dev/null
RG="$(terraform output -raw resource_group)"
JUMPBOX_IP="$(terraform output -raw jumpbox_public_ip)"
UPSTREAM_VIP="$(terraform output -raw upstream_vip)"
UPSTREAM_IP="$(terraform output -raw upstream_private_ip)"
mapfile -t CONSUMERS < <(terraform output -json consumer_private_ips | jq -r '.[]')
popd >/dev/null

if [ -z "$RG" ] || [ -z "$JUMPBOX_IP" ] || [ -z "$UPSTREAM_VIP" ] || [ -z "$UPSTREAM_IP" ] || [ "${#CONSUMERS[@]}" -eq 0 ]; then
  echo "missing terraform outputs for run context" >&2
  exit 1
fi

REGION="$(az group show -n "$RG" --query location -o tsv 2>/dev/null || echo unknown)"

if ! [[ "$PRE_ALLOCATED_VUS" =~ ^[0-9]+$ ]]; then
  PRE_ALLOCATED_VUS=0
fi
if ! [[ "$MAX_VUS" =~ ^[0-9]+$ ]]; then
  MAX_VUS=0
fi

if [ "$PRE_ALLOCATED_VUS" -le 0 ]; then
  PRE_ALLOCATED_VUS=$((RPS / 2))
  if [ "$PRE_ALLOCATED_VUS" -lt 100 ]; then
    PRE_ALLOCATED_VUS=100
  fi
fi
if [ "$MAX_VUS" -le 0 ]; then
  MAX_VUS=$((RPS * 2))
  if [ "$MAX_VUS" -lt 400 ]; then
    MAX_VUS=400
  fi
fi

FW_MGMT_IPS="$(TF_DIR="$TF_DIR" "$RESOLVE_FW_IPS")"
FW_MGMT_IP="$(echo "$FW_MGMT_IPS" | head -n1)"
if [ -z "$FW_MGMT_IP" ]; then
  echo "no firewall management IP found" >&2
  exit 1
fi

POLICY_FILE=""
REQUEST_PATH=""
TARGET_URLS=""
DENY_CHECK_URL=""
DENY_CHECK_EXPECT_FAIL=0
NEEDS_TLS_INTERCEPT_CA=0

case "$SCENARIO" in
  l34_allow_webhooks)
    POLICY_FILE="${POLICY_DIR}/l34-allow.json"
    REQUEST_PATH="/webhooks/allowed/l34"
    TARGET_URLS="https://${UPSTREAM_VIP}:443,https://${UPSTREAM_IP}:8443,https://${UPSTREAM_IP}:9443"
    ;;
  l34_mixed_allow_deny)
    POLICY_FILE="${POLICY_DIR}/l34-mixed.json"
    REQUEST_PATH="/webhooks/allowed/mixed"
    TARGET_URLS="https://${UPSTREAM_VIP}:443,https://${UPSTREAM_IP}:8443"
    DENY_CHECK_URL="https://${UPSTREAM_IP}:9443/webhooks/allowed/deny-check"
    DENY_CHECK_EXPECT_FAIL=1
    ;;
  tls_sni_allow_only)
    POLICY_FILE="${POLICY_DIR}/tls-sni.json"
    REQUEST_PATH="/webhooks/allowed/sni"
    # Keep SNI benchmark targets on DNS-routed endpoints that are reachable
    # through the current Azure topology. 8443 on ${DNS_ZONE} can time out
    # because only :443 is published via the DNS-routed VIP path.
    TARGET_URLS="https://${DNS_ZONE}:443"
    ;;
  tls_intercept_http_path)
    POLICY_FILE="${POLICY_DIR}/tls-intercept-path.json"
    REQUEST_PATH="/webhooks/allowed/intercept"
    TARGET_URLS="https://${DNS_ZONE}:443"
    DENY_CHECK_URL="https://${DNS_ZONE}:443/webhooks/blocked/deny-check"
    DENY_CHECK_EXPECT_FAIL=1
    NEEDS_TLS_INTERCEPT_CA=1
    ;;
  *)
    echo "unknown SCENARIO=${SCENARIO}" >&2
    exit 1
    ;;
esac

if [ -n "${TARGET_URLS_OVERRIDE}" ]; then
  TARGET_URLS="${TARGET_URLS_OVERRIDE}"
fi

if [ -n "${REQUEST_PATH_OVERRIDE}" ]; then
  REQUEST_PATH="${REQUEST_PATH_OVERRIDE}"
fi

if [ ! -f "$POLICY_FILE" ]; then
  echo "missing policy file: $POLICY_FILE" >&2
  exit 1
fi

if [ "$SCENARIO" = "tls_intercept_http_path" ]; then
  TEMP_POLICY_FILE="$(mktemp)"
  python3 - "$POLICY_FILE" "$TEMP_POLICY_FILE" "${UPSTREAM_VIP}" <<'PY'
import json
import sys

src, dst, upstream_vip = sys.argv[1:]
target_ip = upstream_vip

with open(src, "r", encoding="utf-8") as f:
    data = json.load(f)

groups = data.get("policy", {}).get("source_groups", [])
for group in groups:
    rules = group.get("rules", [])
    for rule in rules:
        match = rule.get("match") or {}
        tls = match.get("tls") or {}
        if tls.get("mode") == "intercept":
            match["dst_ips"] = [target_ip]
            rule["match"] = match

with open(dst, "w", encoding="utf-8") as out:
    json.dump(data, out)
    out.write("\n")
PY
  POLICY_FILE="${TEMP_POLICY_FILE}"
fi

wait_ready() {
  local ip="$1"
  local deadline=$((SECONDS + 600))
  while [ "$SECONDS" -lt "$deadline" ]; do
    if ssh -n -o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes -i "$KEY_PATH" \
      "${SSH_USER:-ubuntu}@${JUMPBOX_IP}" \
      "curl -skf https://${ip}:8443/ready >/dev/null"; then
      return 0
    fi
    sleep 5
  done
  return 1
}

ensure_tls_intercept_upstream_insecure() {
  local ip
  for ip in $FW_MGMT_IPS; do
    echo "ensuring TLS intercept upstream verification mode is insecure on ${ip}"
    if ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$ip" \
      "set -e; current=\$(sudo systemctl show firewall.service --property=Environment --value || true); if echo \"\$current\" | grep -q 'NEUWERK_TLS_INTERCEPT_UPSTREAM_VERIFY=insecure'; then exit 0; fi; sudo mkdir -p /etc/systemd/system/firewall.service.d; cat <<'EOF' | sudo tee /etc/systemd/system/firewall.service.d/10-tls-intercept-upstream-verify.conf >/dev/null
[Service]
Environment=NEUWERK_TLS_INTERCEPT_UPSTREAM_VERIFY=insecure
EOF
sudo systemctl daemon-reload
sudo systemctl restart firewall.service"; then
      :
    else
      echo "failed to configure TLS intercept upstream verify mode on ${ip}" >&2
      exit 1
    fi
  done
}

ensure_tls_intercept_ca() {
  local ip token ca_status configured status_code deadline
  local put_status tmp_dir ca_cert ca_key payload
  for ip in $FW_MGMT_IPS; do
    echo "ensuring TLS intercept CA exists on ${ip}"
    token="$($MINT_API_TOKEN "$JUMPBOX_IP" "$KEY_PATH" "$ip" "http-perf")"
    ca_status="$(ssh -o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes -i "$KEY_PATH" \
      "${SSH_USER:-ubuntu}@${JUMPBOX_IP}" \
      "curl -sk -H 'Authorization: Bearer ${token}' https://${ip}:8443/api/v1/settings/tls-intercept-ca" || true)"
    configured="$(echo "$ca_status" | jq -r '.configured // false' 2>/dev/null || echo false)"
    if [ "$configured" != "true" ]; then
      status_code="$(ssh -o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes -i "$KEY_PATH" \
        "${SSH_USER:-ubuntu}@${JUMPBOX_IP}" \
        "curl -sk -o /dev/null -w '%{http_code}' -X POST -H 'Authorization: Bearer ${token}' https://${ip}:8443/api/v1/settings/tls-intercept-ca/generate")"
      if [ "$status_code" = "405" ] || [ "$status_code" = "404" ]; then
        tmp_dir="$(mktemp -d)"
        ca_cert="${tmp_dir}/intercept-ca.crt"
        ca_key="${tmp_dir}/intercept-ca.key"
        openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
          -days 3650 \
          -subj "/CN=Neuwerk DPI Root CA/" \
          -keyout "${ca_key}" \
          -out "${ca_cert}" >/dev/null 2>&1
        payload="$(jq -n \
          --rawfile cert "${ca_cert}" \
          --rawfile key "${ca_key}" \
          '{ca_cert_pem: $cert, ca_key_pem: $key}')"
        put_status="$(
          ssh -o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes -i "$KEY_PATH" \
            "${SSH_USER:-ubuntu}@${JUMPBOX_IP}" \
            "curl -sk -o /dev/null -w '%{http_code}' -X PUT -H 'Authorization: Bearer ${token}' -H 'Content-Type: application/json' --data-binary @- https://${ip}:8443/api/v1/settings/tls-intercept-ca" \
            <<<"$payload"
        )"
        rm -rf "${tmp_dir}"
        case "$put_status" in
          200|201|204|409)
            ;;
          *)
            echo "failed to upload TLS intercept CA on ${ip}: http ${put_status}" >&2
            exit 1
            ;;
        esac
      else
        case "$status_code" in
          200|201|204|409)
            ;;
          *)
            echo "failed to generate TLS intercept CA on ${ip}: http ${status_code}" >&2
            exit 1
            ;;
        esac
      fi
    fi

    deadline=$((SECONDS + 120))
    configured=false
    while [ "$SECONDS" -lt "$deadline" ]; do
      ca_status="$(ssh -o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes -i "$KEY_PATH" \
        "${SSH_USER:-ubuntu}@${JUMPBOX_IP}" \
        "curl -sk -H 'Authorization: Bearer ${token}' https://${ip}:8443/api/v1/settings/tls-intercept-ca" || true)"
      configured="$(echo "$ca_status" | jq -r '.configured // false' 2>/dev/null || echo false)"
      if [ "$configured" = "true" ]; then
        break
      fi
      sleep 2
    done
    if [ "$configured" != "true" ]; then
      echo "TLS intercept CA not ready on ${ip} after generation" >&2
      exit 1
    fi
  done
}

if [ "$NEEDS_TLS_INTERCEPT_CA" = "1" ]; then
  ensure_tls_intercept_upstream_insecure
fi

echo "waiting for firewall readiness"
for ip in $FW_MGMT_IPS; do
  echo "ready check: ${ip}"
  if ! wait_ready "$ip"; then
    echo "firewall not ready: ${ip}" >&2
    exit 1
  fi
done

if [ "$NEEDS_TLS_INTERCEPT_CA" = "1" ]; then
  ensure_tls_intercept_ca
fi

echo "pushing scenario policy ${POLICY_FILE}"
TF_DIR="$TF_DIR" KEY_PATH="$KEY_PATH" "$CONFIGURE_POLICY_SCRIPT" "$POLICY_FILE"

FIRST_CONSUMER="${CONSUMERS[0]}"
FIRST_TARGET="$(echo "$TARGET_URLS" | awk -F',' '{print $1}')"
echo "allow-path probe from consumer ${FIRST_CONSUMER}"
ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$FIRST_CONSUMER" \
  "set -e; for _ in 1 2 3 4 5 6; do if curl -skf --max-time 20 -X POST -H 'Content-Type: application/json' --data '{\"probe\":true}' '${FIRST_TARGET}${REQUEST_PATH}' >/dev/null; then exit 0; fi; sleep 2; done; exit 1"

if [ "$DENY_CHECK_EXPECT_FAIL" = "1" ] && [ -n "$DENY_CHECK_URL" ]; then
  echo "deny-path probe from consumer ${FIRST_CONSUMER}"
  ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$FIRST_CONSUMER" \
    "set -e; for _ in 1 2 3 4 5 6; do if curl -skf --max-time 20 -X POST -H 'Content-Type: application/json' --data '{\"probe\":true}' '${DENY_CHECK_URL}' >/dev/null; then sleep 2; continue; fi; exit 0; done; echo 'deny probe unexpectedly succeeded' >&2; exit 1"
fi

echo "collecting pre-run metrics"
TF_DIR="$TF_DIR" KEY_PATH="$KEY_PATH" "$COLLECT_SCRIPT" pre "$ARTIFACT_DIR"

run_id="${SCENARIO}-rps${RPS}-$(date -u +%Y%m%dT%H%M%SZ)"
cpu_monitor_seconds=$((RAMP_SECONDS + STEADY_SECONDS + 10))
declare -a cpu_pids=()
declare -a cpu_labels=()

start_cpu_monitor() {
  local label="$1"
  local ip="$2"
  local safe_ip="${ip//./_}"
  (
    ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$ip" \
      "bash -lc 'if command -v mpstat >/dev/null 2>&1; then timeout ${cpu_monitor_seconds} mpstat 1; else timeout ${cpu_monitor_seconds} vmstat 1; fi'"
  ) > "${ARTIFACT_DIR}/raw/cpu-during.${label}.${safe_ip}.log" \
    2> "${ARTIFACT_DIR}/raw/cpu-during.${label}.${safe_ip}.err" &
  cpu_pids+=("$!")
  cpu_labels+=("${label}:${ip}")
}

for ip in $FW_MGMT_IPS; do
  start_cpu_monitor "firewall" "$ip"
done
for ip in "${CONSUMERS[@]}"; do
  start_cpu_monitor "consumer" "$ip"
done
start_cpu_monitor "upstream" "$UPSTREAM_IP"

consumer_count="${#CONSUMERS[@]}"
base_rps=$((RPS / consumer_count))
extra_rps=$((RPS % consumer_count))

declare -a load_pids=()
declare -a load_hosts=()
declare -a load_rc_files=()

for idx in "${!CONSUMERS[@]}"; do
  host="${CONSUMERS[$idx]}"
  rps_for_host="$base_rps"
  if [ "$idx" -lt "$extra_rps" ]; then
    rps_for_host=$((rps_for_host + 1))
  fi
  if [ "$rps_for_host" -le 0 ]; then
    continue
  fi

  remote_script="/tmp/http-perf-webhook.js"
  remote_summary="/tmp/${run_id}.${idx}.summary.json"
  out_file="${ARTIFACT_DIR}/raw/${host}.k6.out"
  err_file="${ARTIFACT_DIR}/raw/${host}.k6.err"
  rc_file="${ARTIFACT_DIR}/raw/${host}.k6.rc"

  ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$host" "cat > ${remote_script}" < "$K6_SCRIPT_LOCAL"

  (
    set +e
    ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$host" \
      "env TARGET_URLS='${TARGET_URLS}' REQUEST_PATH='${REQUEST_PATH}' REQUEST_METHOD='POST' PAYLOAD_BYTES='${PAYLOAD_BYTES}' RPS='${rps_for_host}' RAMP_SECONDS='${RAMP_SECONDS}' STEADY_SECONDS='${STEADY_SECONDS}' TLS_INSECURE='1' SCENARIO_LABEL='${SCENARIO}' PRE_ALLOCATED_VUS='${PRE_ALLOCATED_VUS}' MAX_VUS='${MAX_VUS}' ENFORCE_THRESHOLDS='0' K6_SUMMARY_TREND_STATS='avg,min,med,max,p(90),p(95),p(99)' k6 run --summary-export '${remote_summary}' '${remote_script}'" \
      > "$out_file" 2> "$err_file"
    rc=$?
    set -e
    echo "$rc" > "$rc_file"
    if ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$host" "[ -f '${remote_summary}' ]"; then
      ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$host" "cat '${remote_summary}'" > "${ARTIFACT_DIR}/load-summary.${host}.json"
    fi
    ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$host" "rm -f '${remote_summary}' '${remote_script}'" >/dev/null 2>&1 || true
    exit "$rc"
  ) &
  load_pids+=("$!")
  load_hosts+=("$host")
  load_rc_files+=("$rc_file")
done

load_failed=0
for pid in "${load_pids[@]}"; do
  if ! wait "$pid"; then
    load_failed=1
  fi
done

summary_count="$(find "${ARTIFACT_DIR}" -maxdepth 1 -name 'load-summary.*.json' | wc -l | tr -d ' ')"
if [ "${summary_count}" -eq 0 ]; then
  echo "no load summaries produced" >&2
  load_failed=1
fi

for pid in "${cpu_pids[@]}"; do
  wait "$pid" || true
done

echo "collecting post-run metrics"
TF_DIR="$TF_DIR" KEY_PATH="$KEY_PATH" "$COLLECT_SCRIPT" post "$ARTIFACT_DIR"

python3 - "${ARTIFACT_DIR}" <<'PY'
import glob
import json
import os
import statistics
import sys

artifact_dir = sys.argv[1]
pre_prom = os.path.join(artifact_dir, "firewall-metrics-pre.prom")
post_prom = os.path.join(artifact_dir, "firewall-metrics-post.prom")

def read_prom_totals(path):
    totals = {}
    if not os.path.exists(path):
        return totals
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if " " not in line:
                continue
            left, right = line.rsplit(" ", 1)
            metric = left.split("{", 1)[0]
            try:
                value = float(right)
            except ValueError:
                continue
            totals[metric] = totals.get(metric, 0.0) + value
    return totals

pre = read_prom_totals(pre_prom)
post = read_prom_totals(post_prom)
keys = sorted(set(pre) | set(post))
delta = {k: post.get(k, 0.0) - pre.get(k, 0.0) for k in keys}

selected_prefixes = ("dp_", "dpdk_", "dns_")
selected = {k: v for k, v in delta.items() if k.startswith(selected_prefixes)}

with open(os.path.join(artifact_dir, "firewall-metrics-delta.json"), "w", encoding="utf-8") as out:
    json.dump(
        {
            "pre_totals": pre,
            "post_totals": post,
            "delta_totals": delta,
            "selected_delta_totals": selected,
        },
        out,
        indent=2,
        sort_keys=True,
    )
    out.write("\n")

cpu_samples = []
for path in sorted(glob.glob(os.path.join(artifact_dir, "raw", "cpu-during.*.log"))):
    base = os.path.basename(path).replace("cpu-during.", "").replace(".log", "")
    parts = base.split(".", 1)
    if len(parts) == 2:
        role, ip_raw = parts[0], parts[1]
    else:
        role, ip_raw = "unknown", parts[0]
    ip = ip_raw.replace("_", ".")
    values = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            line = raw.strip()
            if not line:
                continue
            if "Average:" in line and " all " in f" {line} ":
                parts = line.split()
                try:
                    idle = float(parts[-1])
                    values.append(max(0.0, min(100.0, 100.0 - idle)))
                except ValueError:
                    pass
                continue
            parts = line.split()
            if len(parts) >= 3 and ":" in parts[0] and parts[1] == "all":
                try:
                    idle = float(parts[-1])
                    values.append(max(0.0, min(100.0, 100.0 - idle)))
                except ValueError:
                    pass
                continue
            if len(parts) >= 15 and parts[0].isdigit() and parts[1].isdigit():
                try:
                    idle = float(parts[14])
                    values.append(max(0.0, min(100.0, 100.0 - idle)))
                except ValueError:
                    pass
    entry = {"role": role, "instance": ip, "samples": len(values)}
    if values:
        entry["cpu_used_pct_avg"] = round(statistics.fmean(values), 3)
        entry["cpu_used_pct_max"] = round(max(values), 3)
    else:
        entry["cpu_used_pct_avg"] = None
        entry["cpu_used_pct_max"] = None
    cpu_samples.append(entry)

with open(os.path.join(artifact_dir, "cpu-all-during.json"), "w", encoding="utf-8") as out:
    json.dump(cpu_samples, out, indent=2, sort_keys=True)
    out.write("\n")

cpu_firewall_samples = [item for item in cpu_samples if item.get("role") == "firewall"]
role_summary = {}
for item in cpu_samples:
    role = item.get("role", "unknown")
    role_summary.setdefault(role, {"instances": 0, "cpu_used_pct_avg_mean": None, "cpu_used_pct_max_max": None})
    role_summary[role]["instances"] += 1

for role, summary in role_summary.items():
    avgs = [i.get("cpu_used_pct_avg") for i in cpu_samples if i.get("role") == role and i.get("cpu_used_pct_avg") is not None]
    peaks = [i.get("cpu_used_pct_max") for i in cpu_samples if i.get("role") == role and i.get("cpu_used_pct_max") is not None]
    if avgs:
        summary["cpu_used_pct_avg_mean"] = round(statistics.fmean(avgs), 3)
    if peaks:
        summary["cpu_used_pct_max_max"] = round(max(peaks), 3)

with open(os.path.join(artifact_dir, "cpu-firewall-during.json"), "w", encoding="utf-8") as out:
    json.dump(cpu_firewall_samples, out, indent=2, sort_keys=True)
    out.write("\n")

with open(os.path.join(artifact_dir, "cpu-role-summary.json"), "w", encoding="utf-8") as out:
    json.dump(role_summary, out, indent=2, sort_keys=True)
    out.write("\n")
PY

python3 - "${ARTIFACT_DIR}" "${SCENARIO}" "${RPS}" "${RAMP_SECONDS}" "${STEADY_SECONDS}" "${UPSTREAM_VIP}" "${UPSTREAM_IP}" "${DNS_ZONE}" "${PAYLOAD_BYTES}" <<'PY'
import glob
import json
import os
import statistics
import sys

artifact_dir, scenario, rps_target, ramp_secs, steady_secs, upstream_vip, upstream_ip, dns_zone, payload_bytes = sys.argv[1:]
rps_target_i = int(rps_target)
ramp_i = int(ramp_secs)
steady_i = int(steady_secs)
payload_i = int(payload_bytes)

summary_files = sorted(glob.glob(os.path.join(artifact_dir, "load-summary.*.json")))
req_count_total = 0.0
req_rate_total = 0.0
error_fails = 0.0
error_passes = 0.0
error_rate_values = []
p95_values = []
p99_values = []

def metric_values(metrics, name):
    metric = metrics.get(name, {})
    if not isinstance(metric, dict):
        return {}
    values = metric.get("values")
    if isinstance(values, dict):
        return values
    return metric

for path in summary_files:
    with open(path, "r", encoding="utf-8") as f:
        payload = json.load(f)
    metrics = payload.get("metrics", {})

    http_reqs = metric_values(metrics, "http_reqs")
    req_count_total += float(http_reqs.get("count", 0.0))
    req_rate_total += float(http_reqs.get("rate", 0.0))

    failed = metric_values(metrics, "http_req_failed")
    if "value" in failed:
        try:
            error_rate_values.append(float(failed.get("value", 0.0)))
        except (TypeError, ValueError):
            pass
    else:
        error_fails += float(failed.get("fails", 0.0))
        error_passes += float(failed.get("passes", 0.0))

    duration = metric_values(metrics, "http_req_duration")
    if "p(95)" in duration:
        p95_values.append(float(duration["p(95)"]))
    if "p(99)" in duration:
        p99_values.append(float(duration["p(99)"]))

cpu_peak = None
cpu_file = os.path.join(artifact_dir, "cpu-firewall-during.json")
if os.path.exists(cpu_file):
    with open(cpu_file, "r", encoding="utf-8") as f:
        cpu_payload = json.load(f)
    peaks = [item.get("cpu_used_pct_max") for item in cpu_payload if item.get("cpu_used_pct_max") is not None]
    if peaks:
        cpu_peak = max(peaks)

if error_rate_values:
    error_rate = statistics.fmean(error_rate_values)
else:
    error_total = error_fails + error_passes
    error_rate = (error_fails / error_total) if error_total > 0 else 0.0

result = {
    "scenario": scenario,
    "rps_target": rps_target_i,
    "ramp_seconds": ramp_i,
    "steady_seconds": steady_i,
    "payload_bytes": payload_i,
    "target_context": {
        "upstream_vip": upstream_vip,
        "upstream_ip": upstream_ip,
        "dns_zone": dns_zone,
    },
    "results": {
        "requests_total": req_count_total,
        "effective_rps": req_rate_total,
        "latency_p95_ms_max": max(p95_values) if p95_values else None,
        "latency_p99_ms_max": max(p99_values) if p99_values else None,
        "error_rate": error_rate,
        "firewall_cpu_peak_pct": cpu_peak,
    },
    "status": "pass",
}

with open(os.path.join(artifact_dir, "result.json"), "w", encoding="utf-8") as out:
    json.dump(result, out, indent=2, sort_keys=True)
    out.write("\n")
PY

if [ "$load_failed" -ne 0 ]; then
  echo "one or more k6 workers failed" >&2
  python3 - "${ARTIFACT_DIR}/result.json" <<'PY'
import json
import sys
path = sys.argv[1]
with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)
data["status"] = "fail"
with open(path, "w", encoding="utf-8") as out:
    json.dump(data, out, indent=2, sort_keys=True)
    out.write("\n")
PY
  exit 1
fi

git_sha="$(git -C "${ROOT_DIR}/../.." rev-parse --short HEAD 2>/dev/null || echo unknown)"
jq -n \
  --arg scenario "$SCENARIO" \
  --arg policy_file "$POLICY_FILE" \
  --arg target_urls "$TARGET_URLS" \
  --arg request_path "$REQUEST_PATH" \
  --arg dns_zone "$DNS_ZONE" \
  --arg jumpbox_ip "$JUMPBOX_IP" \
  --arg upstream_vip "$UPSTREAM_VIP" \
  --arg upstream_ip "$UPSTREAM_IP" \
  --arg region "$REGION" \
  --arg commit "$git_sha" \
  --argjson consumers "$(printf '%s\n' "${CONSUMERS[@]}" | jq -R . | jq -s .)" \
  --argjson firewalls "$(printf '%s\n' $FW_MGMT_IPS | jq -R . | jq -s .)" \
  --argjson rps "$RPS" \
  --argjson ramp "$RAMP_SECONDS" \
  --argjson steady "$STEADY_SECONDS" \
  --argjson payload "$PAYLOAD_BYTES" \
  '{
    generated_at: (now | todateiso8601),
    scenario: $scenario,
    policy_file: $policy_file,
    target_urls: ($target_urls | split(",")),
    request_path: $request_path,
    dns_zone: $dns_zone,
    region: $region,
    commit: $commit,
    jumpbox_ip: $jumpbox_ip,
    upstream_vip: $upstream_vip,
    upstream_ip: $upstream_ip,
    consumers: $consumers,
    firewalls: $firewalls,
    rps_target: $rps,
    ramp_seconds: $ramp,
    steady_seconds: $steady,
    payload_bytes: $payload
  }' > "${ARTIFACT_DIR}/context.json"

echo "http perf run complete: ${ARTIFACT_DIR}"
