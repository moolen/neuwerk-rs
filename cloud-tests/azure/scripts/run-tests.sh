#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)
TF_DIR="${TF_DIR:-${ROOT_DIR}/terraform}"
KEY_PATH="${KEY_PATH:-${ROOT_DIR}/../.secrets/ssh/azure_e2e}"
DNS_ZONE="${DNS_ZONE:-upstream.test}"
POLICY_FILE="${POLICY_FILE:-${ROOT_DIR}/policies/allow-upstream.json}"
RESOLVE_FW_IPS="${ROOT_DIR}/scripts/resolve-neuwerk-mgmt-ips.sh"
LONG_THROUGHPUT="${LONG_THROUGHPUT:-1}"
LONG_THROUGHPUT_GIB="${LONG_THROUGHPUT_GIB:-100}"
LONG_THROUGHPUT_STREAMS="${LONG_THROUGHPUT_STREAMS:-16}"
LONG_THROUGHPUT_TIMEOUT_SECS="${LONG_THROUGHPUT_TIMEOUT_SECS:-7200}"
LONG_THROUGHPUT_MODE="${LONG_THROUGHPUT_MODE:-iperf3}"
LONG_THROUGHPUT_CPU="${LONG_THROUGHPUT_CPU:-1}"
LONG_THROUGHPUT_CPU_SECS="${LONG_THROUGHPUT_CPU_SECS:-600}"
WAIT_BG="${WAIT_BG:-0}"

source "${ROOT_DIR}/../common/lib.sh"

require_bin terraform
require_bin az
require_bin jq
require_bin ssh

if [ "${SKIP_POLICY:-}" != "1" ]; then
  export TF_DIR KEY_PATH
  echo "configuring policy from ${POLICY_FILE}"
  "${ROOT_DIR}/scripts/configure-policy.sh" "${POLICY_FILE}"
fi

pushd "$TF_DIR" >/dev/null
RG=$(terraform output -raw resource_group)
JUMPBOX_IP=$(terraform output -raw jumpbox_public_ip)
UPSTREAM_VIP=$(terraform output -raw upstream_vip)
UPSTREAM_IP=$(terraform output -raw upstream_private_ip)
CONSUMERS=$(terraform output -json consumer_private_ips | jq -r '.[]')
popd >/dev/null

FW_MGMT_IPS=$(TF_DIR="$TF_DIR" "$RESOLVE_FW_IPS")
FW_MGMT_IP=$(echo "$FW_MGMT_IPS" | head -n1)
DNS_TARGET="${DNS_TARGET:-$FW_MGMT_IP}"
IPERF_TARGET="${IPERF_TARGET:-$UPSTREAM_IP}"

if [ -z "$CONSUMERS" ]; then
  echo "no consumer IPs found" >&2
  exit 1
fi

for ip in $CONSUMERS; do
  echo "DNS test from ${ip}"
  ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$ip" "dig +time=2 +tries=1 @${DNS_TARGET} ${DNS_ZONE}"

done

for ip in $CONSUMERS; do
  echo "DNS TCP test from ${ip}"
  ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$ip" "dig +tcp +time=2 +tries=1 @${DNS_TARGET} ${DNS_ZONE}"

done

for ip in $CONSUMERS; do
  echo "HTTP test from ${ip}"
  ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$ip" \
    "curl -s --max-time 20 --connect-timeout 10 --retry 3 --retry-delay 1 --retry-all-errors --resolve ${DNS_ZONE}:80:${UPSTREAM_VIP} http://${DNS_ZONE}"

done

for ip in $CONSUMERS; do
  echo "HTTPS test from ${ip}"
  ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$ip" \
    "curl -sk --max-time 20 --connect-timeout 10 --retry 3 --retry-delay 1 --retry-all-errors --resolve ${DNS_ZONE}:443:${UPSTREAM_VIP} https://${DNS_ZONE}"

done

for ip in $CONSUMERS; do
  echo "HTTPS allow-path smoke from ${ip}"
  ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$ip" \
    "curl -skf --max-time 20 --connect-timeout 10 --retry 3 --retry-delay 1 --retry-all-errors --resolve ${DNS_ZONE}:443:${UPSTREAM_VIP} https://${DNS_ZONE}/external-secrets/external-secrets"

done

for ip in $CONSUMERS; do
  echo "HTTPS deny-path RST smoke from ${ip}"
  ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$ip" \
    "set -e; out=\$(curl -sk --max-time 10 --connect-timeout 5 --resolve ${DNS_ZONE}:443:${UPSTREAM_VIP} https://${DNS_ZONE}/moolen 2>&1 >/dev/null || true); echo \"\$out\" | egrep -qi 'reset|refused|empty reply' || { echo \"expected reset/refused for deny path\" >&2; exit 1; }"
done

echo "starting long-lived connection on first consumer"
FIRST_CONSUMER=$(echo "$CONSUMERS" | head -n1)
ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$FIRST_CONSUMER" "timeout 60 socat - TCP:${UPSTREAM_VIP}:9000" &

sleep 2

for ip in $CONSUMERS; do
  echo "short-lived burst from ${ip}"
  ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$ip" \
    "for i in \$(seq 1 10); do curl -s --max-time 20 --connect-timeout 10 --retry 3 --retry-delay 1 --retry-all-errors --resolve ${DNS_ZONE}:80:${UPSTREAM_VIP} http://${DNS_ZONE} >/dev/null; done"

done

echo "throughput smoke test from first consumer (iperf3 target=${IPERF_TARGET})"
ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$FIRST_CONSUMER" \
  "timeout 60 iperf3 -c ${IPERF_TARGET} -p 5201 -t 5 -P 2 --connect-timeout 5000"

collect_dpdk_metrics() {
  local out_file="$1"
  : > "$out_file"
  for ip in $FW_MGMT_IPS; do
    metrics=$(ssh -o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes -i "$KEY_PATH" \
      "${SSH_USER:-ubuntu}@${JUMPBOX_IP}" \
      "curl -s http://${ip}:8080/metrics | egrep '^dpdk_(rx|tx)_bytes_total '") || true
    rx=$(echo "$metrics" | awk '/^dpdk_rx_bytes_total /{print $2}' | tail -n1)
    tx=$(echo "$metrics" | awk '/^dpdk_tx_bytes_total /{print $2}' | tail -n1)
    if [ -z "$rx" ]; then rx=0; fi
    if [ -z "$tx" ]; then tx=0; fi
    echo "$ip $rx $tx" >> "$out_file"
  done
}

collect_dpdk_detail_metrics() {
  local out_file="$1"
  : > "$out_file"
  for ip in $FW_MGMT_IPS; do
    metrics=$(ssh -o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes -i "$KEY_PATH" \
      "${SSH_USER:-ubuntu}@${JUMPBOX_IP}" \
      "curl -s http://${ip}:8080/metrics | egrep '^(dpdk_(rx|tx)_(bytes|packets)_queue_total|dpdk_health_probe_packets_total|dp_state_lock_(wait_seconds_sum|wait_seconds_count|contended_total))'") || true
    if [ -n "$metrics" ]; then
      while IFS= read -r line; do
        [ -z "$line" ] && continue
        echo "$ip $line" >> "$out_file"
      done <<< "$metrics"
    fi
  done
}

summarize_dpdk_detail_deltas() {
  local pre_file="$1"
  local post_file="$2"
  python3 - "$pre_file" "$post_file" <<'PY'
import re
import sys

if len(sys.argv) != 3:
    raise SystemExit("usage: summarize <pre> <post>")

pre_path, post_path = sys.argv[1], sys.argv[2]

metric_re = re.compile(r'^(?P<ip>\S+)\s+(?P<metric>\w+)(?:\{queue="(?P<queue>[^"]+)"\})?\s+(?P<value>[-+0-9.eE]+)\s*$')

def load(path):
    data = {}
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            m = metric_re.match(line)
            if not m:
                continue
            ip = m.group("ip")
            metric = m.group("metric")
            queue = m.group("queue") or "-"
            try:
                value = float(m.group("value"))
            except ValueError:
                value = 0.0
            data[(ip, metric, queue)] = value
    return data

pre = load(pre_path)
post = load(post_path)

def delta(ip, metric, queue):
    return post.get((ip, metric, queue), 0.0) - pre.get((ip, metric, queue), 0.0)

ips = sorted({key[0] for key in set(pre) | set(post)})

for ip in ips:
    print(f"---- dpdk per-queue deltas {ip} ----")
    queues = sorted({key[2] for key in set(pre) | set(post) if key[0] == ip and key[2] != "-"})
    for q in queues:
        rx_bytes = delta(ip, "dpdk_rx_bytes_queue_total", q)
        tx_bytes = delta(ip, "dpdk_tx_bytes_queue_total", q)
        rx_pkts = delta(ip, "dpdk_rx_packets_queue_total", q)
        tx_pkts = delta(ip, "dpdk_tx_packets_queue_total", q)
        print(f"queue={q} rx_bytes_delta={int(rx_bytes)} tx_bytes_delta={int(tx_bytes)} rx_pkts_delta={int(rx_pkts)} tx_pkts_delta={int(tx_pkts)}")
    contended = delta(ip, "dp_state_lock_contended_total", "-")
    wait_sum = delta(ip, "dp_state_lock_wait_seconds_sum", "-")
    wait_count = delta(ip, "dp_state_lock_wait_seconds_count", "-")
    print(f"state_lock_contended_delta={int(contended)} wait_seconds_sum_delta={wait_sum:.6f} wait_count_delta={int(wait_count)}")
PY
}

start_cpu_monitors() {
  local label="$1"
  if [ "$LONG_THROUGHPUT_CPU" != "1" ]; then
    return 0
  fi
  for ip in $FW_MGMT_IPS; do
    ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$ip" \
      "bash -lc 'if command -v mpstat >/dev/null 2>&1; then timeout ${LONG_THROUGHPUT_CPU_SECS} mpstat 1 > /tmp/cpu_${label}.log; else timeout ${LONG_THROUGHPUT_CPU_SECS} vmstat 1 > /tmp/cpu_${label}.log; fi'" &
  done
  ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$FIRST_CONSUMER" \
    "bash -lc 'if command -v mpstat >/dev/null 2>&1; then timeout ${LONG_THROUGHPUT_CPU_SECS} mpstat 1 > /tmp/cpu_${label}.log; else timeout ${LONG_THROUGHPUT_CPU_SECS} vmstat 1 > /tmp/cpu_${label}.log; fi'" &
  ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$UPSTREAM_IP" \
    "bash -lc 'if command -v mpstat >/dev/null 2>&1; then timeout ${LONG_THROUGHPUT_CPU_SECS} mpstat 1 > /tmp/cpu_${label}.log; else timeout ${LONG_THROUGHPUT_CPU_SECS} vmstat 1 > /tmp/cpu_${label}.log; fi'" || true &
}

collect_cpu_logs() {
  local label="$1"
  if [ "$LONG_THROUGHPUT_CPU" != "1" ]; then
    return 0
  fi
  for ip in $FW_MGMT_IPS; do
    echo "---- CPU ${label} ${ip} ----"
    ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$ip" "tail -n 5 /tmp/cpu_${label}.log || true"
  done
  echo "---- CPU ${label} ${FIRST_CONSUMER} ----"
  ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$FIRST_CONSUMER" "tail -n 5 /tmp/cpu_${label}.log || true"
  echo "---- CPU ${label} ${UPSTREAM_IP} ----"
  ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$UPSTREAM_IP" "tail -n 5 /tmp/cpu_${label}.log || true" || true
}

if [ "$LONG_THROUGHPUT" = "1" ]; then
  echo "long throughput test from first consumer (${LONG_THROUGHPUT_GIB} GiB total, ${LONG_THROUGHPUT_STREAMS} streams, mode=${LONG_THROUGHPUT_MODE}, target=${IPERF_TARGET})"
  pre_file=$(mktemp)
  post_file=$(mktemp)
  pre_detail=$(mktemp)
  post_detail=$(mktemp)
  long_status=0
  start_ns=$(date +%s%N)
  collect_dpdk_metrics "$pre_file"
  collect_dpdk_detail_metrics "$pre_detail"
  start_cpu_monitors "long"

  if [ "$LONG_THROUGHPUT_MODE" = "iperf3" ]; then
    if ! ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$FIRST_CONSUMER" \
    "STREAMS=${LONG_THROUGHPUT_STREAMS} GIB_TOTAL=${LONG_THROUGHPUT_GIB} VIP=${IPERF_TARGET} TIMEOUT_SECS=${LONG_THROUGHPUT_TIMEOUT_SECS} bash -s" <<'EOF'
set -euo pipefail
streams=${STREAMS}
gib_total=${GIB_TOTAL}
timeout_secs=${TIMEOUT_SECS}
total_mib=$((gib_total * 1024))
if [ $total_mib -le 0 ]; then
  echo "invalid total MiB: ${total_mib}" >&2
  exit 1
fi
start_ns=$(date +%s%N)
if ! command -v iperf3 >/dev/null 2>&1; then
  echo "iperf3 not found on consumer" >&2
  exit 1
fi
total_bytes=$((total_mib * 1024 * 1024))
timeout "$timeout_secs" iperf3 -c "${VIP}" -p 5201 -n "${total_mib}M" -P "${streams}" --connect-timeout 5000
end_ns=$(date +%s%N)
elapsed_ns=$((end_ns-start_ns))
if [ "$elapsed_ns" -le 0 ]; then elapsed_ns=1; fi
mbps=$((total_bytes * 8 * 1000 / elapsed_ns))
echo "sent ${total_bytes} bytes in ${elapsed_ns} ns (~${mbps} Mbps)"
exit 0
EOF
    then
      long_status=1
    fi
  else
    if ! ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$FIRST_CONSUMER" \
      "STREAMS=${LONG_THROUGHPUT_STREAMS} GIB_TOTAL=${LONG_THROUGHPUT_GIB} VIP=${UPSTREAM_VIP} TIMEOUT_SECS=${LONG_THROUGHPUT_TIMEOUT_SECS} bash -s" <<'EOF'
set -euo pipefail
streams=${STREAMS}
gib_total=${GIB_TOTAL}
timeout_secs=${TIMEOUT_SECS}
total_mib=$((gib_total * 1024))
base_mib=$((total_mib / streams))
extra_mib=$((total_mib % streams))
if [ $base_mib -le 0 ]; then
  echo "invalid MiB per stream: ${base_mib}" >&2
  exit 1
fi
total_bytes=$((total_mib * 1024 * 1024))
start_ns=$(date +%s%N)
pids=()
for i in $(seq 1 $streams); do
  mib=$base_mib
  if [ $extra_mib -gt 0 ]; then
    mib=$((mib + 1))
    extra_mib=$((extra_mib - 1))
  fi
  (timeout "$timeout_secs" bash -lc "dd if=/dev/zero bs=1M count=${mib} status=none | socat -u -T 60 - TCP:${VIP}:9000 >/dev/null") &
  pids+=("$!")
done
status=0
for pid in "${pids[@]}"; do
  if ! wait "$pid"; then status=1; fi
done
end_ns=$(date +%s%N)
elapsed_ns=$((end_ns-start_ns))
if [ "$elapsed_ns" -le 0 ]; then elapsed_ns=1; fi
mbps=$((total_bytes * 8 * 1000 / elapsed_ns))
echo "sent ${total_bytes} bytes in ${elapsed_ns} ns (~${mbps} Mbps)"
exit $status
EOF
    then
      long_status=1
    fi
  fi

  collect_dpdk_metrics "$post_file"
  collect_dpdk_detail_metrics "$post_detail"
  end_ns=$(date +%s%N)
  elapsed_ns=$((end_ns - start_ns))
  if [ "$elapsed_ns" -le 0 ]; then elapsed_ns=1; fi
  echo "---- dpdk metrics delta ----"
  total_rx=0
  total_tx=0
  while read -r ip rx tx; do
    pre_rx=$(awk -v ip="$ip" '$1==ip{print $2}' "$pre_file" | tail -n1)
    pre_tx=$(awk -v ip="$ip" '$1==ip{print $3}' "$pre_file" | tail -n1)
    if [ -z "$pre_rx" ]; then pre_rx=0; fi
    if [ -z "$pre_tx" ]; then pre_tx=0; fi
    delta_rx=$((rx - pre_rx))
    delta_tx=$((tx - pre_tx))
    total_rx=$((total_rx + delta_rx))
    total_tx=$((total_tx + delta_tx))
    echo "$ip rx_bytes_delta=$delta_rx tx_bytes_delta=$delta_tx"
  done < "$post_file"
  mbps_rx=$((total_rx * 8 * 1000 / elapsed_ns))
  mbps_tx=$((total_tx * 8 * 1000 / elapsed_ns))
  echo "total_rx_bytes_delta=$total_rx"
  echo "total_tx_bytes_delta=$total_tx"
  echo "metrics_window_ns=$elapsed_ns (~$((elapsed_ns/1000000000)) s)"
  echo "aggregate_metrics_rx_mbps=~${mbps_rx}"
  echo "aggregate_metrics_tx_mbps=~${mbps_tx}"
  summarize_dpdk_detail_deltas "$pre_detail" "$post_detail"
  collect_cpu_logs "long"
  rm -f "$pre_file" "$post_file" "$pre_detail" "$post_detail"
  if [ "$long_status" -ne 0 ]; then
    echo "long throughput test failed (see output above)" >&2
    exit "$long_status"
  fi
fi

if [ "$WAIT_BG" = "1" ]; then
  wait || true
fi
