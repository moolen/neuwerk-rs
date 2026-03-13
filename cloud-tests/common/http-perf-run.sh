#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)

source "${SCRIPT_DIR}/lib.sh"

require_bin jq
require_bin ssh
require_bin python3
require_bin openssl

: "${JUMPBOX_IP:?missing JUMPBOX_IP}"
: "${UPSTREAM_VIP:?missing UPSTREAM_VIP}"
: "${UPSTREAM_IP:?missing UPSTREAM_IP}"
: "${CONSUMER_IPS:?missing CONSUMER_IPS}"
: "${FW_MGMT_IPS:?missing FW_MGMT_IPS}"
: "${KEY_PATH:?missing KEY_PATH}"

DNS_ZONE="${DNS_ZONE:-upstream.test}"
CLOUD_PROVIDER="${CLOUD_PROVIDER:-unknown}"
SCENARIO="${SCENARIO:-l34_allow_webhooks}"
RPS="${RPS:-500}"
RAMP_SECONDS="${RAMP_SECONDS:-30}"
STEADY_SECONDS="${STEADY_SECONDS:-45}"
PAYLOAD_BYTES="${PAYLOAD_BYTES:-32768}"
PRE_ALLOCATED_VUS="${PRE_ALLOCATED_VUS:-0}"
MAX_VUS="${MAX_VUS:-0}"
K6_NOFILE="${K6_NOFILE:-1048576}"
CONNECTION_MODE="${CONNECTION_MODE:-keep_alive}"
CONSUMER_LOCAL_IPS_JSON="${CONSUMER_LOCAL_IPS_JSON:-}"
FIREWALL_THREAD_CPU_MONITOR="${FIREWALL_THREAD_CPU_MONITOR:-1}"
THREAD_MONITOR_INTERVAL_SECS="${THREAD_MONITOR_INTERVAL_SECS:-1}"
SKIP_SETUP="${SKIP_SETUP:-0}"
SETUP_SCRIPT="${SETUP_SCRIPT:-${SCRIPT_DIR}/http-perf-setup.sh}"
COLLECT_SCRIPT="${COLLECT_SCRIPT:-${SCRIPT_DIR}/http-perf-collect.sh}"
MINT_API_TOKEN="${MINT_API_TOKEN:?missing MINT_API_TOKEN}"
CONFIGURE_POLICY_SCRIPT="${CONFIGURE_POLICY_SCRIPT:?missing CONFIGURE_POLICY_SCRIPT}"
POLICY_DIR="${POLICY_DIR:?missing POLICY_DIR}"
K6_SCRIPT_LOCAL="${K6_SCRIPT_LOCAL:-${SCRIPT_DIR}/http-perf/k6/webhook.js}"
TARGET_URLS_OVERRIDE="${TARGET_URLS_OVERRIDE:-}"
REQUEST_PATH_OVERRIDE="${REQUEST_PATH_OVERRIDE:-}"
REGION="${REGION:-unknown}"
RESOURCE_GROUP="${RESOURCE_GROUP:-unknown}"
FW_INSTANCE_TYPE="${FW_INSTANCE_TYPE:-unknown}"
CONSUMER_INSTANCE_TYPE="${CONSUMER_INSTANCE_TYPE:-unknown}"
UPSTREAM_INSTANCE_TYPE="${UPSTREAM_INSTANCE_TYPE:-unknown}"
TLS_INTERCEPT_IO_TIMEOUT_SECS="${TLS_INTERCEPT_IO_TIMEOUT_SECS:-10}"
TLS_INTERCEPT_H2_BODY_TIMEOUT_SECS="${TLS_INTERCEPT_H2_BODY_TIMEOUT_SECS:-30}"
TLS_INTERCEPT_LISTEN_BACKLOG="${TLS_INTERCEPT_LISTEN_BACKLOG:-4096}"
CONTROLPLANE_WORKER_THREADS="${CONTROLPLANE_WORKER_THREADS:-4}"
DPDK_WORKERS="${DPDK_WORKERS:-}"
DPDK_ALLOW_AZURE_MULTIWORKER="${DPDK_ALLOW_AZURE_MULTIWORKER:-}"
DPDK_SINGLE_QUEUE_MODE="${DPDK_SINGLE_QUEUE_MODE:-}"
DPDK_FORCE_SHARED_RX_DEMUX="${DPDK_FORCE_SHARED_RX_DEMUX:-}"
DPDK_HOUSEKEEPING_INTERVAL_PACKETS="${DPDK_HOUSEKEEPING_INTERVAL_PACKETS:-}"
DPDK_HOUSEKEEPING_INTERVAL_US="${DPDK_HOUSEKEEPING_INTERVAL_US:-}"
DPDK_PERF_MODE="${DPDK_PERF_MODE:-}"
DPDK_PIN_HTTPS_OWNER="${DPDK_PIN_HTTPS_OWNER:-}"
DPDK_SHARED_RX_OWNER_ONLY="${DPDK_SHARED_RX_OWNER_ONLY:-}"

ARTIFACT_DIR="${ARTIFACT_DIR:-${ROOT_DIR}/artifacts/http-perf-${SCENARIO}-${CONNECTION_MODE}-payload${PAYLOAD_BYTES}-rps${RPS}-$(date -u +%Y%m%dT%H%M%SZ)}"
TEMP_POLICY_FILE=""

cleanup() {
  if [ -n "${TEMP_POLICY_FILE}" ]; then
    rm -f "${TEMP_POLICY_FILE}" || true
  fi
}
trap cleanup EXIT

if [ ! -f "${KEY_PATH}" ]; then
  echo "missing SSH key at ${KEY_PATH}" >&2
  exit 1
fi

if [ ! -x "${CONFIGURE_POLICY_SCRIPT}" ]; then
  echo "missing executable configure policy script: ${CONFIGURE_POLICY_SCRIPT}" >&2
  exit 1
fi

if [ ! -x "${MINT_API_TOKEN}" ]; then
  echo "missing executable token script: ${MINT_API_TOKEN}" >&2
  exit 1
fi

if [ ! -x "${COLLECT_SCRIPT}" ]; then
  echo "missing executable collect script: ${COLLECT_SCRIPT}" >&2
  exit 1
fi

if [ ! -x "${SETUP_SCRIPT}" ]; then
  echo "missing executable setup script: ${SETUP_SCRIPT}" >&2
  exit 1
fi

if [ ! -f "${K6_SCRIPT_LOCAL}" ]; then
  echo "missing k6 script: ${K6_SCRIPT_LOCAL}" >&2
  exit 1
fi

mkdir -p "${ARTIFACT_DIR}/raw"

if [ "${SKIP_SETUP}" != "1" ]; then
  echo "running setup before scenario run"
  JUMPBOX_IP="$JUMPBOX_IP" \
  UPSTREAM_VIP="$UPSTREAM_VIP" \
  UPSTREAM_IP="$UPSTREAM_IP" \
  CONSUMER_IPS="$CONSUMER_IPS" \
  FW_MGMT_IPS="$FW_MGMT_IPS" \
  KEY_PATH="$KEY_PATH" \
  DNS_ZONE="$DNS_ZONE" \
  SSH_USER="${SSH_USER:-ubuntu}" \
  "$SETUP_SCRIPT"
fi

declare -a CONSUMERS=()
for ip in $CONSUMER_IPS; do
  CONSUMERS+=("$ip")
done
if [ "${#CONSUMERS[@]}" -eq 0 ]; then
  echo "no consumer IPs provided" >&2
  exit 1
fi

if [ -n "${CONSUMER_LOCAL_IPS_JSON}" ]; then
  if ! jq -e --argjson count "${#CONSUMERS[@]}" '
      type == "array"
      and length == $count
      and all(.[]; type == "array" and all(.[]; type == "string"))
    ' <<<"${CONSUMER_LOCAL_IPS_JSON}" >/dev/null; then
    echo "CONSUMER_LOCAL_IPS_JSON must be a JSON array aligned with CONSUMER_IPS" >&2
    exit 1
  fi
else
  CONSUMER_LOCAL_IPS_JSON="$(
    printf '%s\n' "${CONSUMERS[@]}" \
      | jq -R 'select(length > 0) | [.]' \
      | jq -s '.'
  )"
fi

per_consumer_source_ips_json="$(
  jq -cn \
    --argjson consumers "$(printf '%s\n' "${CONSUMERS[@]}" | jq -R . | jq -s '.')" \
    --argjson source_ip_sets "${CONSUMER_LOCAL_IPS_JSON}" '
      [range(0; ($consumers | length)) as $idx
       | {
           ip: $consumers[$idx],
           source_ips: (($source_ip_sets[$idx] // [$consumers[$idx]]) | map(select(type == "string" and length > 0)) | unique)
         }]
    '
)"
printf '%s\n' "${per_consumer_source_ips_json}" > "${ARTIFACT_DIR}/consumer-source-ips.json"

if ! [[ "$PRE_ALLOCATED_VUS" =~ ^[0-9]+$ ]]; then
  PRE_ALLOCATED_VUS=0
fi
if ! [[ "$MAX_VUS" =~ ^[0-9]+$ ]]; then
  MAX_VUS=0
fi

POLICY_FILE=""
REQUEST_PATH=""
TARGET_URLS=""
DENY_CHECK_URL=""
DENY_CHECK_EXPECT_FAIL=0
NEEDS_TLS_INTERCEPT_CA=0

case "$SCENARIO" in
  http_l34_allow)
    POLICY_FILE="${POLICY_DIR}/http-l34-allow.json"
    REQUEST_PATH="/webhooks/allowed/http"
    TARGET_URLS="http://${UPSTREAM_VIP}:80,http://${UPSTREAM_IP}:80"
    ;;
  https_l34_allow|l34_allow_webhooks)
    POLICY_FILE="${POLICY_DIR}/https-l34-allow.json"
    if [ ! -f "$POLICY_FILE" ]; then
      POLICY_FILE="${POLICY_DIR}/l34-allow.json"
    fi
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
  python3 - "$POLICY_FILE" "$TEMP_POLICY_FILE" "$UPSTREAM_VIP" <<'PY'
import json
import sys

src, dst, upstream_vip = sys.argv[1:]

with open(src, "r", encoding="utf-8") as f:
    data = json.load(f)

groups = data.get("policy", {}).get("source_groups", [])
for group in groups:
    for rule in group.get("rules", []):
        match = rule.get("match") or {}
        tls = match.get("tls") or {}
        if tls.get("mode") == "intercept":
            match["dst_ips"] = [upstream_vip]
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
    ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$ip" \
      "set -e; current=\$(sudo systemctl show firewall.service --property=Environment --value || true); if echo \"\$current\" | grep -q 'NEUWERK_TLS_INTERCEPT_UPSTREAM_VERIFY=insecure'; then exit 0; fi; sudo mkdir -p /etc/systemd/system/firewall.service.d; cat <<'EOC' | sudo tee /etc/systemd/system/firewall.service.d/10-tls-intercept-upstream-verify.conf >/dev/null
[Service]
Environment=NEUWERK_TLS_INTERCEPT_UPSTREAM_VERIFY=insecure
EOC
sudo systemctl daemon-reload
sudo systemctl restart firewall.service"
  done
}

ensure_tls_intercept_runtime_tuning() {
  local ip
  for ip in $FW_MGMT_IPS; do
    echo "ensuring TLS intercept runtime tuning on ${ip}"
    ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$ip" \
      "env CONTROLPLANE_WORKER_THREADS='${CONTROLPLANE_WORKER_THREADS}' TLS_INTERCEPT_IO_TIMEOUT_SECS='${TLS_INTERCEPT_IO_TIMEOUT_SECS}' TLS_INTERCEPT_H2_BODY_TIMEOUT_SECS='${TLS_INTERCEPT_H2_BODY_TIMEOUT_SECS}' TLS_INTERCEPT_LISTEN_BACKLOG='${TLS_INTERCEPT_LISTEN_BACKLOG}' DPDK_WORKERS='${DPDK_WORKERS}' DPDK_ALLOW_AZURE_MULTIWORKER='${DPDK_ALLOW_AZURE_MULTIWORKER}' DPDK_SINGLE_QUEUE_MODE='${DPDK_SINGLE_QUEUE_MODE}' DPDK_FORCE_SHARED_RX_DEMUX='${DPDK_FORCE_SHARED_RX_DEMUX}' DPDK_HOUSEKEEPING_INTERVAL_PACKETS='${DPDK_HOUSEKEEPING_INTERVAL_PACKETS}' DPDK_HOUSEKEEPING_INTERVAL_US='${DPDK_HOUSEKEEPING_INTERVAL_US}' DPDK_PERF_MODE='${DPDK_PERF_MODE}' DPDK_PIN_HTTPS_OWNER='${DPDK_PIN_HTTPS_OWNER}' DPDK_SHARED_RX_OWNER_ONLY='${DPDK_SHARED_RX_OWNER_ONLY}' bash -s" <<'EOS'
set -euo pipefail
path="/etc/systemd/system/firewall.service.d/11-tls-intercept-runtime-tuning.conf"
env_file="/etc/neuwerk/firewall.env"
dpdk_env_regex='^(NEUWERK_DPDK_WORKERS|NEUWERK_DPDK_ALLOW_AZURE_MULTIWORKER|NEUWERK_DPDK_SINGLE_QUEUE_MODE|NEUWERK_DPDK_FORCE_SHARED_RX_DEMUX|NEUWERK_DPDK_HOUSEKEEPING_INTERVAL_PACKETS|NEUWERK_DPDK_HOUSEKEEPING_INTERVAL_US|NEUWERK_DPDK_PERF_MODE|NEUWERK_DPDK_PIN_HTTPS_OWNER|NEUWERK_DPDK_SHARED_RX_OWNER_ONLY)='
sudo mkdir -p /etc/systemd/system/firewall.service.d
desired="$(cat <<EOC
[Service]
Environment=NEUWERK_CONTROLPLANE_WORKER_THREADS=${CONTROLPLANE_WORKER_THREADS}
Environment=NEUWERK_TLS_IO_TIMEOUT_SECS=${TLS_INTERCEPT_IO_TIMEOUT_SECS}
Environment=NEUWERK_TLS_H2_BODY_TIMEOUT_SECS=${TLS_INTERCEPT_H2_BODY_TIMEOUT_SECS}
Environment=NEUWERK_TLS_INTERCEPT_LISTEN_BACKLOG=${TLS_INTERCEPT_LISTEN_BACKLOG}
EOC
)"
if [ -n "${DPDK_WORKERS}" ]; then
  desired="${desired}"$'\n'"Environment=NEUWERK_DPDK_WORKERS=${DPDK_WORKERS}"
fi
if [ -n "${DPDK_ALLOW_AZURE_MULTIWORKER}" ]; then
  desired="${desired}"$'\n'"Environment=NEUWERK_DPDK_ALLOW_AZURE_MULTIWORKER=${DPDK_ALLOW_AZURE_MULTIWORKER}"
fi
if [ -n "${DPDK_SINGLE_QUEUE_MODE}" ]; then
  desired="${desired}"$'\n'"Environment=NEUWERK_DPDK_SINGLE_QUEUE_MODE=${DPDK_SINGLE_QUEUE_MODE}"
fi
if [ -n "${DPDK_FORCE_SHARED_RX_DEMUX}" ]; then
  desired="${desired}"$'\n'"Environment=NEUWERK_DPDK_FORCE_SHARED_RX_DEMUX=${DPDK_FORCE_SHARED_RX_DEMUX}"
fi
if [ -n "${DPDK_HOUSEKEEPING_INTERVAL_PACKETS}" ]; then
  desired="${desired}"$'\n'"Environment=NEUWERK_DPDK_HOUSEKEEPING_INTERVAL_PACKETS=${DPDK_HOUSEKEEPING_INTERVAL_PACKETS}"
fi
if [ -n "${DPDK_HOUSEKEEPING_INTERVAL_US}" ]; then
  desired="${desired}"$'\n'"Environment=NEUWERK_DPDK_HOUSEKEEPING_INTERVAL_US=${DPDK_HOUSEKEEPING_INTERVAL_US}"
fi
if [ -n "${DPDK_PERF_MODE}" ]; then
  desired="${desired}"$'\n'"Environment=NEUWERK_DPDK_PERF_MODE=${DPDK_PERF_MODE}"
fi
if [ -n "${DPDK_PIN_HTTPS_OWNER}" ]; then
  desired="${desired}"$'\n'"Environment=NEUWERK_DPDK_PIN_HTTPS_OWNER=${DPDK_PIN_HTTPS_OWNER}"
fi
if [ -n "${DPDK_SHARED_RX_OWNER_ONLY}" ]; then
  desired="${desired}"$'\n'"Environment=NEUWERK_DPDK_SHARED_RX_OWNER_ONLY=${DPDK_SHARED_RX_OWNER_ONLY}"
fi
current="$(sudo cat "$path" 2>/dev/null || true)"

env_tmp="$(mktemp)"
cleanup() {
  rm -f "$env_tmp"
}
trap cleanup EXIT

has_dpdk_overrides=0
if [ -n "${DPDK_WORKERS}" ] \
  || [ -n "${DPDK_ALLOW_AZURE_MULTIWORKER}" ] \
  || [ -n "${DPDK_SINGLE_QUEUE_MODE}" ] \
  || [ -n "${DPDK_FORCE_SHARED_RX_DEMUX}" ] \
  || [ -n "${DPDK_HOUSEKEEPING_INTERVAL_PACKETS}" ] \
  || [ -n "${DPDK_HOUSEKEEPING_INTERVAL_US}" ] \
  || [ -n "${DPDK_PERF_MODE}" ] \
  || [ -n "${DPDK_PIN_HTTPS_OWNER}" ] \
  || [ -n "${DPDK_SHARED_RX_OWNER_ONLY}" ]; then
  has_dpdk_overrides=1
fi

if [ "${has_dpdk_overrides}" = "1" ]; then
  if sudo test -f "$env_file"; then
    sudo awk '!/'"$dpdk_env_regex"'/' "$env_file" > "$env_tmp"
  fi
  if [ -n "${DPDK_WORKERS}" ]; then
    printf '%s\n' "NEUWERK_DPDK_WORKERS=${DPDK_WORKERS}" >> "$env_tmp"
  fi
  if [ -n "${DPDK_ALLOW_AZURE_MULTIWORKER}" ]; then
    printf '%s\n' "NEUWERK_DPDK_ALLOW_AZURE_MULTIWORKER=${DPDK_ALLOW_AZURE_MULTIWORKER}" >> "$env_tmp"
  fi
  if [ -n "${DPDK_SINGLE_QUEUE_MODE}" ]; then
    printf '%s\n' "NEUWERK_DPDK_SINGLE_QUEUE_MODE=${DPDK_SINGLE_QUEUE_MODE}" >> "$env_tmp"
  fi
  if [ -n "${DPDK_FORCE_SHARED_RX_DEMUX}" ]; then
    printf '%s\n' "NEUWERK_DPDK_FORCE_SHARED_RX_DEMUX=${DPDK_FORCE_SHARED_RX_DEMUX}" >> "$env_tmp"
  fi
  if [ -n "${DPDK_HOUSEKEEPING_INTERVAL_PACKETS}" ]; then
    printf '%s\n' "NEUWERK_DPDK_HOUSEKEEPING_INTERVAL_PACKETS=${DPDK_HOUSEKEEPING_INTERVAL_PACKETS}" >> "$env_tmp"
  fi
  if [ -n "${DPDK_HOUSEKEEPING_INTERVAL_US}" ]; then
    printf '%s\n' "NEUWERK_DPDK_HOUSEKEEPING_INTERVAL_US=${DPDK_HOUSEKEEPING_INTERVAL_US}" >> "$env_tmp"
  fi
  if [ -n "${DPDK_PERF_MODE}" ]; then
    printf '%s\n' "NEUWERK_DPDK_PERF_MODE=${DPDK_PERF_MODE}" >> "$env_tmp"
  fi
  if [ -n "${DPDK_PIN_HTTPS_OWNER}" ]; then
    printf '%s\n' "NEUWERK_DPDK_PIN_HTTPS_OWNER=${DPDK_PIN_HTTPS_OWNER}" >> "$env_tmp"
  fi
  if [ -n "${DPDK_SHARED_RX_OWNER_ONLY}" ]; then
    printf '%s\n' "NEUWERK_DPDK_SHARED_RX_OWNER_ONLY=${DPDK_SHARED_RX_OWNER_ONLY}" >> "$env_tmp"
  fi
fi

env_current="$(sudo cat "$env_file" 2>/dev/null || true)"
if [ "${has_dpdk_overrides}" = "1" ]; then
  env_desired="$(cat "$env_tmp" 2>/dev/null || true)"
else
  env_desired="${env_current}"
fi
changed=0

if [ "$current" != "$desired" ]; then
  printf '%s\n' "$desired" | sudo tee "$path" >/dev/null
  changed=1
fi

if [ "${has_dpdk_overrides}" = "1" ] && [ "$env_current" != "$env_desired" ]; then
  sudo install -m 0644 "$env_tmp" "$env_file"
  changed=1
fi

if [ "$changed" = "1" ]; then
  sudo systemctl daemon-reload
  sudo systemctl restart firewall.service
fi

pid=""
for _ in $(seq 1 30); do
  pid="$(pgrep -xo firewall || true)"
  if [ -n "$pid" ]; then
    break
  fi
  sleep 1
done
if [ -z "$pid" ]; then
  echo "firewall process not found after runtime tuning update" >&2
  exit 1
fi

verify_runtime_var() {
  local key="$1"
  local expected="$2"
  local actual
  actual="$(sudo cat "/proc/${pid}/environ" | tr '\0' '\n' | awk -F= -v key="$key" '$1 == key {print substr($0, length(key) + 2)}' | tail -n1)"
  if [ "$actual" != "$expected" ]; then
    echo "firewall runtime env mismatch for ${key}: expected '${expected}', got '${actual}'" >&2
    exit 1
  fi
}

if [ -n "${DPDK_WORKERS}" ]; then
  verify_runtime_var "NEUWERK_DPDK_WORKERS" "${DPDK_WORKERS}"
fi
if [ -n "${DPDK_ALLOW_AZURE_MULTIWORKER}" ]; then
  verify_runtime_var "NEUWERK_DPDK_ALLOW_AZURE_MULTIWORKER" "${DPDK_ALLOW_AZURE_MULTIWORKER}"
fi
if [ -n "${DPDK_SINGLE_QUEUE_MODE}" ]; then
  verify_runtime_var "NEUWERK_DPDK_SINGLE_QUEUE_MODE" "${DPDK_SINGLE_QUEUE_MODE}"
fi
if [ -n "${DPDK_FORCE_SHARED_RX_DEMUX}" ]; then
  verify_runtime_var "NEUWERK_DPDK_FORCE_SHARED_RX_DEMUX" "${DPDK_FORCE_SHARED_RX_DEMUX}"
fi
if [ -n "${DPDK_PERF_MODE}" ]; then
  verify_runtime_var "NEUWERK_DPDK_PERF_MODE" "${DPDK_PERF_MODE}"
fi
if [ -n "${DPDK_PIN_HTTPS_OWNER}" ]; then
  verify_runtime_var "NEUWERK_DPDK_PIN_HTTPS_OWNER" "${DPDK_PIN_HTTPS_OWNER}"
fi
if [ -n "${DPDK_SHARED_RX_OWNER_ONLY}" ]; then
  verify_runtime_var "NEUWERK_DPDK_SHARED_RX_OWNER_ONLY" "${DPDK_SHARED_RX_OWNER_ONLY}"
fi
EOS
  done
}

ensure_tls_intercept_ca() {
  local ip token ca_status configured status_code deadline put_status tmp_dir ca_cert ca_key payload
  for ip in $FW_MGMT_IPS; do
    echo "ensuring TLS intercept CA exists on ${ip}"
    token="$($MINT_API_TOKEN "$JUMPBOX_IP" "$KEY_PATH" "$ip" "http-perf-${CLOUD_PROVIDER}")"
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
        payload="$(jq -n --rawfile cert "${ca_cert}" --rawfile key "${ca_key}" '{ca_cert_pem: $cert, ca_key_pem: $key}')"
        put_status="$({
          ssh -o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes -i "$KEY_PATH" \
            "${SSH_USER:-ubuntu}@${JUMPBOX_IP}" \
            "curl -sk -o /dev/null -w '%{http_code}' -X PUT -H 'Authorization: Bearer ${token}' -H 'Content-Type: application/json' --data-binary @- https://${ip}:8443/api/v1/settings/tls-intercept-ca" \
            <<<"$payload"
        } || true)"
        rm -rf "${tmp_dir}"
        case "$put_status" in
          200|201|204|409) ;;
          *) echo "failed to upload TLS intercept CA on ${ip}: http ${put_status}" >&2; exit 1 ;;
        esac
      else
        case "$status_code" in
          200|201|204|409) ;;
          *) echo "failed to generate TLS intercept CA on ${ip}: http ${status_code}" >&2; exit 1 ;;
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
  ensure_tls_intercept_runtime_tuning
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
KEY_PATH="$KEY_PATH" TF_DIR="${TF_DIR:-}" SSH_USER="${SSH_USER:-ubuntu}" \
  "$CONFIGURE_POLICY_SCRIPT" "$POLICY_FILE"

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
JUMPBOX_IP="$JUMPBOX_IP" KEY_PATH="$KEY_PATH" FW_MGMT_IPS="$FW_MGMT_IPS" SSH_USER="${SSH_USER:-ubuntu}" \
  "$COLLECT_SCRIPT" pre "$ARTIFACT_DIR"

run_id="${SCENARIO}-${CONNECTION_MODE}-p${PAYLOAD_BYTES}-rps${RPS}-$(date -u +%Y%m%dT%H%M%SZ)"
cpu_monitor_seconds=$((RAMP_SECONDS + STEADY_SECONDS + 10))
declare -a cpu_pids=()

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
}

start_firewall_thread_cpu_monitor() {
  local ip="$1"
  local safe_ip="${ip//./_}"
  if [ "${FIREWALL_THREAD_CPU_MONITOR}" != "1" ]; then
    return 0
  fi
  (
    ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$ip" \
      "env MONITOR_SECS='${cpu_monitor_seconds}' MONITOR_INTERVAL_SECS='${THREAD_MONITOR_INTERVAL_SECS}' bash -s" <<'EOS'
set -euo pipefail
pid="$(sudo systemctl show firewall.service --property MainPID --value 2>/dev/null || true)"
if [ -z "$pid" ] || [ "$pid" = "0" ]; then
  pid="$(pgrep -xo firewall || true)"
fi
if [ -z "$pid" ] || [ "$pid" = "0" ]; then
  exit 0
fi

end=$((SECONDS + MONITOR_SECS))
while [ "$SECONDS" -lt "$end" ]; do
  ts="$(date -u +%s)"
  sudo ps -L -p "$pid" -o tid=,psr=,pcpu=,stat=,comm= 2>/dev/null \
    | awk -v ts="$ts" 'NF >= 5 {print ts "\t" $1 "\t" $2 "\t" $3 "\t" $4 "\t" $5}'
  sleep "$MONITOR_INTERVAL_SECS"
done
EOS
  ) > "${ARTIFACT_DIR}/raw/thread-cpu-during.firewall.${safe_ip}.tsv" \
    2> "${ARTIFACT_DIR}/raw/thread-cpu-during.firewall.${safe_ip}.err" &
  cpu_pids+=("$!")
}

for ip in $FW_MGMT_IPS; do
  start_cpu_monitor "firewall" "$ip"
  start_firewall_thread_cpu_monitor "$ip"
done
for ip in "${CONSUMERS[@]}"; do
  start_cpu_monitor "consumer" "$ip"
done
start_cpu_monitor "upstream" "$UPSTREAM_IP"

collect_consumer_socket_diag() {
  local phase="$1"
  local idx host safe_host local_ips_csv
  for idx in "${!CONSUMERS[@]}"; do
    host="${CONSUMERS[$idx]}"
    safe_host="${host//./_}"
    local_ips_csv="$(jq -r --argjson idx "$idx" '.[$idx] // [] | map(select(type == "string" and length > 0)) | unique | join(",")' <<<"${CONSUMER_LOCAL_IPS_JSON}")"
    if [ -z "${local_ips_csv}" ]; then
      local_ips_csv="${host}"
    fi
    ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$host" "env DIAG_PHASE='${phase}' EXPECTED_SOURCE_IPS='${local_ips_csv}' bash -s" > "${ARTIFACT_DIR}/raw/${phase}.consumer-sockets.${safe_host}.json" <<'EOS'
set -euo pipefail
primary_iface="$(ip route show default | awk '/default/ {print $5; exit}')"
if [ -z "$primary_iface" ]; then
  primary_iface="$(ip -4 -o addr show | awk '$2 != "lo" {print $2; exit}')"
fi
local_ips_json="$(ip -4 -j addr show dev "$primary_iface" scope global 2>/dev/null | jq '[.[0].addr_info[]? | select(.family == "inet") | .local]')"
sockstat="$(cat /proc/net/sockstat 2>/dev/null || true)"
sockstat6="$(cat /proc/net/sockstat6 2>/dev/null || true)"
ss_summary="$(ss -s 2>/dev/null || true)"
nstat_output="$(nstat -az 2>/dev/null || true)"
tcp_timewait="$(ss -tan state time-wait 2>/dev/null | awk 'NR > 1 {count++} END {print count + 0}')"
tcp_established="$(ss -tan state established 2>/dev/null | awk 'NR > 1 {count++} END {print count + 0}')"
jq -n \
  --arg phase "${DIAG_PHASE}" \
  --arg hostname "$(hostname)" \
  --arg iface "${primary_iface}" \
  --arg expected_source_ips "${EXPECTED_SOURCE_IPS}" \
  --arg ip_local_port_range "$(cat /proc/sys/net/ipv4/ip_local_port_range 2>/dev/null || true)" \
  --arg nofile_soft_limit "$(ulimit -n 2>/dev/null || true)" \
  --arg ip_addr "$(ip -4 -o addr show dev "${primary_iface}" scope global 2>/dev/null || true)" \
  --arg ip_route "$(ip route show 2>/dev/null || true)" \
  --arg ss_summary "${ss_summary}" \
  --arg sockstat "${sockstat}" \
  --arg sockstat6 "${sockstat6}" \
  --arg nstat "${nstat_output}" \
  --argjson local_ips "${local_ips_json}" \
  --argjson tcp_timewait "${tcp_timewait}" \
  --argjson tcp_established "${tcp_established}" '
  {
    phase: $phase,
    hostname: $hostname,
    primary_interface: $iface,
    expected_source_ips: ($expected_source_ips | split(",") | map(select(length > 0))),
    local_ips: $local_ips,
    local_ip_count: ($local_ips | length),
    ip_local_port_range: $ip_local_port_range,
    nofile_soft_limit: $nofile_soft_limit,
    ip_addr: $ip_addr,
    ip_route: $ip_route,
    ss_summary: $ss_summary,
    sockstat: $sockstat,
    sockstat6: $sockstat6,
    nstat: $nstat,
    tcp_timewait: $tcp_timewait,
    tcp_established: $tcp_established
  }'
EOS
  done
}

echo "collecting pre-run consumer socket diagnostics"
collect_consumer_socket_diag pre

consumer_count="${#CONSUMERS[@]}"
base_rps=$((RPS / consumer_count))
extra_rps=$((RPS % consumer_count))

if [ "$CONNECTION_MODE" = "new_connection_heavy" ] && [ "$consumer_count" -lt 2 ]; then
  echo "warning: new_connection_heavy is running with a single consumer; results may be generator-limited" >&2
fi

per_consumer_rps_json="$(
  for idx in "${!CONSUMERS[@]}"; do
    host="${CONSUMERS[$idx]}"
    rps_for_host="$base_rps"
    if [ "$idx" -lt "$extra_rps" ]; then
      rps_for_host=$((rps_for_host + 1))
    fi
    printf '%s\t%s\n' "$host" "$rps_for_host"
  done | jq -R 'split("\t") | select(length == 2) | {ip: .[0], rps_target: (.[1] | tonumber)}' | jq -s '.'
)"

declare -a load_pids=()

for idx in "${!CONSUMERS[@]}"; do
  host="${CONSUMERS[$idx]}"
  rps_for_host="$base_rps"
  if [ "$idx" -lt "$extra_rps" ]; then
    rps_for_host=$((rps_for_host + 1))
  fi
  if [ "$rps_for_host" -le 0 ]; then
    continue
  fi

  pre_allocated_for_host="$PRE_ALLOCATED_VUS"
  max_vus_for_host="$MAX_VUS"
  if [ "$pre_allocated_for_host" -le 0 ]; then
    if [ "$CONNECTION_MODE" = "new_connection_heavy" ]; then
      pre_allocated_for_host="$rps_for_host"
      if [ "$pre_allocated_for_host" -lt 250 ]; then
        pre_allocated_for_host=250
      fi
    else
      pre_allocated_for_host=$((rps_for_host / 2))
      if [ "$pre_allocated_for_host" -lt 100 ]; then
        pre_allocated_for_host=100
      fi
    fi
  fi
  if [ "$max_vus_for_host" -le 0 ]; then
    if [ "$CONNECTION_MODE" = "new_connection_heavy" ]; then
      max_vus_for_host=$((rps_for_host * 4))
      if [ "$max_vus_for_host" -lt 1000 ]; then
        max_vus_for_host=1000
      fi
    else
      max_vus_for_host=$((rps_for_host * 2))
      if [ "$max_vus_for_host" -lt 400 ]; then
        max_vus_for_host=400
      fi
    fi
  fi

  remote_script="/tmp/http-perf-webhook.js"
  remote_summary="/tmp/${run_id}.${idx}.summary.json"
  out_file="${ARTIFACT_DIR}/raw/${host}.k6.out"
  err_file="${ARTIFACT_DIR}/raw/${host}.k6.err"
  rc_file="${ARTIFACT_DIR}/raw/${host}.k6.rc"
  local_ips_csv="$(jq -r --argjson idx "$idx" '.[$idx] // [] | map(select(type == "string" and length > 0)) | unique | join(",")' <<<"${CONSUMER_LOCAL_IPS_JSON}")"
  if [ -z "${local_ips_csv}" ]; then
    local_ips_csv="${host}"
  fi

  ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$host" "cat > ${remote_script}" < "$K6_SCRIPT_LOCAL"

  (
    set +e
    ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$host" \
      "env TARGET_URLS='${TARGET_URLS}' REQUEST_PATH='${REQUEST_PATH}' REQUEST_METHOD='POST' PAYLOAD_BYTES='${PAYLOAD_BYTES}' RPS='${rps_for_host}' RAMP_SECONDS='${RAMP_SECONDS}' STEADY_SECONDS='${STEADY_SECONDS}' TLS_INSECURE='1' SCENARIO_LABEL='${SCENARIO}' PRE_ALLOCATED_VUS='${pre_allocated_for_host}' MAX_VUS='${max_vus_for_host}' CONNECTION_MODE='${CONNECTION_MODE}' ENFORCE_THRESHOLDS='0' K6_SUMMARY_TREND_STATS='avg,min,med,max,p(90),p(95),p(99)' LOCAL_IPS_CSV='${local_ips_csv}' REMOTE_SUMMARY='${remote_summary}' REMOTE_SCRIPT='${remote_script}' K6_NOFILE='${K6_NOFILE}' bash -s" <<'EOS' \
      > "$out_file" 2> "$err_file"
set -euo pipefail
ulimit -n "${K6_NOFILE}" 2>/dev/null || true
k6_args=(run)
if [ -n "${LOCAL_IPS_CSV:-}" ]; then
  k6_args+=(--local-ips "${LOCAL_IPS_CSV}")
fi
k6_args+=(--summary-export "${REMOTE_SUMMARY}" "${REMOTE_SCRIPT}")
k6 "${k6_args[@]}"
EOS
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

echo "collecting post-run consumer socket diagnostics"
collect_consumer_socket_diag post

echo "collecting post-run metrics"
JUMPBOX_IP="$JUMPBOX_IP" KEY_PATH="$KEY_PATH" FW_MGMT_IPS="$FW_MGMT_IPS" SSH_USER="${SSH_USER:-ubuntu}" \
  "$COLLECT_SCRIPT" post "$ARTIFACT_DIR"

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
selected = {k: v for k, v in delta.items() if k.startswith(("dp_", "dpdk_", "dns_"))}

with open(os.path.join(artifact_dir, "firewall-metrics-delta.json"), "w", encoding="utf-8") as out:
    json.dump({
        "pre_totals": pre,
        "post_totals": post,
        "delta_totals": delta,
        "selected_delta_totals": selected,
    }, out, indent=2, sort_keys=True)
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
    item = {"role": role, "instance": ip, "samples": len(values)}
    if values:
        item["cpu_used_pct_avg"] = round(statistics.fmean(values), 3)
        item["cpu_used_pct_max"] = round(max(values), 3)
    else:
        item["cpu_used_pct_avg"] = None
        item["cpu_used_pct_max"] = None
    cpu_samples.append(item)

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

thread_summaries = []
thread_summary_file = os.path.join(artifact_dir, "firewall-thread-cpu-during.json")
for path in sorted(glob.glob(os.path.join(artifact_dir, "raw", "thread-cpu-during.firewall.*.tsv"))):
    ip = os.path.basename(path).replace("thread-cpu-during.firewall.", "").replace(".tsv", "").replace("_", ".")
    threads = {}
    timestamps = set()
    snapshot_sizes = {}
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            line = raw.strip()
            if not line:
                continue
            parts = line.split("\t")
            if len(parts) != 6:
                continue
            ts, tid, psr, pcpu, stat, comm = parts
            try:
                cpu = float(pcpu)
            except ValueError:
                continue
            timestamps.add(ts)
            snapshot_sizes[ts] = snapshot_sizes.get(ts, 0) + 1
            entry = threads.setdefault(
                tid,
                {
                    "tid": int(tid),
                    "comm": comm,
                    "samples": 0,
                    "cpu_pct_sum": 0.0,
                    "cpu_pct_max": 0.0,
                    "last_psr": psr,
                    "last_stat": stat,
                },
            )
            entry["samples"] += 1
            entry["cpu_pct_sum"] += cpu
            entry["cpu_pct_max"] = max(entry["cpu_pct_max"], cpu)
            entry["last_psr"] = psr
            entry["last_stat"] = stat

    top_threads = []
    for entry in threads.values():
        samples = entry["samples"] or 1
        top_threads.append(
            {
                "tid": entry["tid"],
                "comm": entry["comm"],
                "samples": entry["samples"],
                "cpu_pct_avg": round(entry["cpu_pct_sum"] / samples, 3),
                "cpu_pct_max": round(entry["cpu_pct_max"], 3),
                "last_psr": entry["last_psr"],
                "last_stat": entry["last_stat"],
            }
        )
    top_threads.sort(key=lambda item: (-item["cpu_pct_max"], -item["cpu_pct_avg"], item["tid"]))

    thread_summaries.append(
        {
            "instance": ip,
            "sample_timestamps": len(timestamps),
            "thread_count_peak": max(snapshot_sizes.values()) if snapshot_sizes else 0,
            "thread_count_avg": (
                round(statistics.fmean(snapshot_sizes.values()), 3)
                if snapshot_sizes
                else None
            ),
            "top_threads": top_threads[:12],
        }
    )

with open(thread_summary_file, "w", encoding="utf-8") as out:
    json.dump(thread_summaries, out, indent=2, sort_keys=True)
    out.write("\n")

thread_role_summary = {
    "instances": len(thread_summaries),
    "top_thread_cpu_pct_max": None,
    "top_thread_cpu_pct_avg_max": None,
}
top_thread_peaks = []
top_thread_avgs = []
for item in thread_summaries:
    if not item.get("top_threads"):
        continue
    top_thread_peaks.append(item["top_threads"][0]["cpu_pct_max"])
    top_thread_avgs.append(item["top_threads"][0]["cpu_pct_avg"])
if top_thread_peaks:
    thread_role_summary["top_thread_cpu_pct_max"] = round(max(top_thread_peaks), 3)
if top_thread_avgs:
    thread_role_summary["top_thread_cpu_pct_avg_max"] = round(max(top_thread_avgs), 3)

with open(os.path.join(artifact_dir, "firewall-thread-cpu-summary.json"), "w", encoding="utf-8") as out:
    json.dump(thread_role_summary, out, indent=2, sort_keys=True)
    out.write("\n")

consumer_socket_summary = []
pre_files = sorted(glob.glob(os.path.join(artifact_dir, "raw", "pre.consumer-sockets.*.json")))
for pre_path in pre_files:
    host = os.path.basename(pre_path).replace("pre.consumer-sockets.", "").replace(".json", "").replace("_", ".")
    post_path = os.path.join(artifact_dir, "raw", f"post.consumer-sockets.{host.replace('.', '_')}.json")
    with open(pre_path, "r", encoding="utf-8") as f:
        pre_diag = json.load(f)
    post_diag = None
    if os.path.exists(post_path):
        with open(post_path, "r", encoding="utf-8") as f:
            post_diag = json.load(f)

    port_count = None
    port_range = pre_diag.get("ip_local_port_range")
    if isinstance(port_range, str):
        parts = port_range.split()
        if len(parts) == 2:
            try:
                port_count = int(parts[1]) - int(parts[0]) + 1
            except ValueError:
                port_count = None

    local_ip_count = pre_diag.get("local_ip_count")
    tuple_budget = None
    if isinstance(local_ip_count, int) and isinstance(port_count, int):
        tuple_budget = local_ip_count * port_count

    consumer_socket_summary.append(
        {
            "consumer": host,
            "expected_source_ips": pre_diag.get("expected_source_ips"),
            "pre_local_ips": pre_diag.get("local_ips"),
            "pre_local_ip_count": local_ip_count,
            "post_local_ip_count": None if post_diag is None else post_diag.get("local_ip_count"),
            "pre_tcp_timewait": pre_diag.get("tcp_timewait"),
            "post_tcp_timewait": None if post_diag is None else post_diag.get("tcp_timewait"),
            "pre_tcp_established": pre_diag.get("tcp_established"),
            "post_tcp_established": None if post_diag is None else post_diag.get("tcp_established"),
            "ip_local_port_range": port_range,
            "ephemeral_port_count": port_count,
            "tuple_budget_estimate_per_target": tuple_budget,
        }
    )

with open(os.path.join(artifact_dir, "consumer-socket-summary.json"), "w", encoding="utf-8") as out:
    json.dump(consumer_socket_summary, out, indent=2, sort_keys=True)
    out.write("\n")
PY

python3 - "${ARTIFACT_DIR}" "${SCENARIO}" "${RPS}" "${RAMP_SECONDS}" "${STEADY_SECONDS}" "${UPSTREAM_VIP}" "${UPSTREAM_IP}" "${DNS_ZONE}" "${PAYLOAD_BYTES}" "${CONNECTION_MODE}" <<'PY'
import glob
import json
import os
import statistics
import sys

artifact_dir, scenario, rps_target, ramp_secs, steady_secs, upstream_vip, upstream_ip, dns_zone, payload_bytes, connection_mode = sys.argv[1:]
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

limit_needles = {
    "ephemeral_ports_exhausted": "cannot assign requested address",
    "insufficient_vus": "Insufficient VUs",
    "nofile_limit": "too many open files",
}


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

generator_limit_counts = {}
worker_limit_counts = []
worker_limit_index = {}
for path in sorted(glob.glob(os.path.join(artifact_dir, "raw", "*.k6.err")) + glob.glob(os.path.join(artifact_dir, "raw", "*.k6.out"))):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()
    detected = {}
    for reason, needle in limit_needles.items():
        count = content.count(needle)
        if count:
            detected[reason] = count
            generator_limit_counts[reason] = generator_limit_counts.get(reason, 0) + count
    if detected:
        worker = os.path.basename(path).replace(".k6.err", "").replace(".k6.out", "")
        entry = worker_limit_index.setdefault(worker, {})
        for reason, count in detected.items():
            entry[reason] = entry.get(reason, 0) + count

for worker, detected in sorted(worker_limit_index.items()):
    worker_limit_counts.append({"worker": worker, "detected": detected})

worker_failures = 0
worker_failure_details = []
for path in sorted(glob.glob(os.path.join(artifact_dir, "raw", "*.k6.rc"))):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        raw = f.read().strip() or "0"
    try:
        rc = int(raw)
    except ValueError:
        rc = -1
    if rc != 0:
        worker_failures += 1
        worker_failure_details.append(
            {
                "worker": os.path.basename(path).replace(".k6.rc", ""),
                "rc": rc,
            }
        )

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

status = "pass"
status_reason = "ok"
generator_limited = bool(generator_limit_counts)
if generator_limited:
    status = "invalid"
    status_reason = "generator_limited"
elif worker_failures > 0:
    status = "fail"
    status_reason = "load_worker_failure"
elif error_rate >= 0.01:
    status = "fail"
    status_reason = "error_rate_gate"
elif p99_values and max(p99_values) >= 200.0:
    status = "fail"
    status_reason = "latency_gate"

load_generator = {
    "worker_count": len(summary_files),
    "worker_failures": worker_failures,
    "worker_failure_details": worker_failure_details,
    "generator_limited": generator_limited,
    "generator_limit_counts": generator_limit_counts,
    "worker_generator_limit_counts": worker_limit_counts,
}

with open(os.path.join(artifact_dir, "load-generator-analysis.json"), "w", encoding="utf-8") as out:
    json.dump(load_generator, out, indent=2, sort_keys=True)
    out.write("\n")

result = {
    "scenario": scenario,
    "rps_target": rps_target_i,
    "ramp_seconds": ramp_i,
    "steady_seconds": steady_i,
    "payload_bytes": payload_i,
    "connection_mode": connection_mode,
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
    "load_generator": load_generator,
    "status": status,
    "status_reason": status_reason,
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

git_sha="$(git -C "${ROOT_DIR}/.." rev-parse --short HEAD 2>/dev/null || echo unknown)"
jq -n \
  --arg cloud_provider "$CLOUD_PROVIDER" \
  --arg scenario "$SCENARIO" \
  --arg policy_file "$POLICY_FILE" \
  --arg target_urls "$TARGET_URLS" \
  --arg request_path "$REQUEST_PATH" \
  --arg dns_zone "$DNS_ZONE" \
  --arg jumpbox_ip "$JUMPBOX_IP" \
  --arg upstream_vip "$UPSTREAM_VIP" \
  --arg upstream_ip "$UPSTREAM_IP" \
  --arg region "$REGION" \
  --arg resource_group "$RESOURCE_GROUP" \
  --arg commit "$git_sha" \
  --arg fw_instance_type "$FW_INSTANCE_TYPE" \
  --arg consumer_instance_type "$CONSUMER_INSTANCE_TYPE" \
  --arg upstream_instance_type "$UPSTREAM_INSTANCE_TYPE" \
  --argjson per_consumer_rps "$per_consumer_rps_json" \
  --argjson per_consumer_source_ips "$per_consumer_source_ips_json" \
  --arg connection_mode "$CONNECTION_MODE" \
  --argjson consumers "$(printf '%s\n' "${CONSUMERS[@]}" | jq -R . | jq -s .)" \
  --argjson firewalls "$(printf '%s\n' $FW_MGMT_IPS | jq -R . | jq -s .)" \
  --argjson rps "$RPS" \
  --argjson ramp "$RAMP_SECONDS" \
  --argjson steady "$STEADY_SECONDS" \
  --argjson payload "$PAYLOAD_BYTES" \
  --argjson pre_allocated_vus "$PRE_ALLOCATED_VUS" \
  --argjson max_vus "$MAX_VUS" \
  --argjson controlplane_worker_threads "$CONTROLPLANE_WORKER_THREADS" \
  --argjson tls_intercept_io_timeout_secs "$TLS_INTERCEPT_IO_TIMEOUT_SECS" \
  --argjson tls_intercept_h2_body_timeout_secs "$TLS_INTERCEPT_H2_BODY_TIMEOUT_SECS" \
  --argjson tls_intercept_listen_backlog "$TLS_INTERCEPT_LISTEN_BACKLOG" \
  --arg dpdk_workers "$DPDK_WORKERS" \
  --arg dpdk_allow_azure_multiworker "$DPDK_ALLOW_AZURE_MULTIWORKER" \
  --arg dpdk_single_queue_mode "$DPDK_SINGLE_QUEUE_MODE" \
  --arg dpdk_force_shared_rx_demux "$DPDK_FORCE_SHARED_RX_DEMUX" \
  --arg dpdk_perf_mode "$DPDK_PERF_MODE" \
  --arg dpdk_housekeeping_interval_packets "$DPDK_HOUSEKEEPING_INTERVAL_PACKETS" \
  --arg dpdk_housekeeping_interval_us "$DPDK_HOUSEKEEPING_INTERVAL_US" \
  --arg dpdk_pin_https_owner "$DPDK_PIN_HTTPS_OWNER" \
  --arg dpdk_shared_rx_owner_only "$DPDK_SHARED_RX_OWNER_ONLY" \
  '{
    generated_at: (now | todateiso8601),
    cloud_provider: $cloud_provider,
    scenario: $scenario,
    policy_file: $policy_file,
    target_urls: ($target_urls | split(",")),
    request_path: $request_path,
    dns_zone: $dns_zone,
    region: $region,
    resource_group: $resource_group,
    commit: $commit,
    jumpbox_ip: $jumpbox_ip,
    upstream_vip: $upstream_vip,
    upstream_ip: $upstream_ip,
    consumers: $consumers,
    per_consumer_rps_targets: $per_consumer_rps,
    per_consumer_source_ips: $per_consumer_source_ips,
    firewalls: $firewalls,
    connection_mode: $connection_mode,
    rps_target: $rps,
    ramp_seconds: $ramp,
    steady_seconds: $steady,
    payload_bytes: $payload,
    pre_allocated_vus: $pre_allocated_vus,
    max_vus: $max_vus,
    runtime_tuning: {
      controlplane_worker_threads: $controlplane_worker_threads,
      tls_intercept_io_timeout_secs: $tls_intercept_io_timeout_secs,
      tls_intercept_h2_body_timeout_secs: $tls_intercept_h2_body_timeout_secs,
      tls_intercept_listen_backlog: $tls_intercept_listen_backlog,
      dpdk_workers: ($dpdk_workers | if . == "" then null else tonumber end),
      dpdk_allow_azure_multiworker: ($dpdk_allow_azure_multiworker | if . == "" then null else . end),
      dpdk_single_queue_mode: ($dpdk_single_queue_mode | if . == "" then null else . end),
      dpdk_force_shared_rx_demux: ($dpdk_force_shared_rx_demux | if . == "" then null else . end),
      dpdk_perf_mode: ($dpdk_perf_mode | if . == "" then null else . end),
      dpdk_housekeeping_interval_packets: ($dpdk_housekeeping_interval_packets | if . == "" then null else tonumber end),
      dpdk_housekeeping_interval_us: ($dpdk_housekeeping_interval_us | if . == "" then null else tonumber end),
      dpdk_pin_https_owner: ($dpdk_pin_https_owner | if . == "" then null else . end),
      dpdk_shared_rx_owner_only: ($dpdk_shared_rx_owner_only | if . == "" then null else . end)
    },
    instance_types: {
      firewall: $fw_instance_type,
      consumer: $consumer_instance_type,
      upstream: $upstream_instance_type
    }
  }' > "${ARTIFACT_DIR}/context.json"

echo "http perf run complete: ${ARTIFACT_DIR}"
