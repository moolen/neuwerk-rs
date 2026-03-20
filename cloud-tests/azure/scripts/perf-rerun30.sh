#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TF_DIR="$ROOT/azure/terraform"
KEY="$ROOT/.secrets/ssh/azure_e2e"
RESOLVE="$ROOT/azure/scripts/resolve-neuwerk-mgmt-ips.sh"
SUFFIX="${1:-manual}"

JUMP="$(cd "$TF_DIR" && terraform output -raw jumpbox_public_ip)"
VIP="$(cd "$TF_DIR" && terraform output -raw upstream_vip)"
CONSUMER="$(cd "$TF_DIR" && terraform output -json consumer_private_ips | jq -r '.[0]')"
mapfile -t FWS < <(TF_DIR="$TF_DIR" "$RESOLVE")

TS="$(date -u +%Y%m%dT%H%M%SZ)"
ART="$ROOT/azure/artifacts/perf30-${SUFFIX}-${TS}"
mkdir -p "$ART/raw"

printf 'timestamp=%s\n' "$TS" > "$ART/context.txt"
printf 'suffix=%s\n' "$SUFFIX" >> "$ART/context.txt"
printf 'jumpbox=%s\n' "$JUMP" >> "$ART/context.txt"
printf 'consumer=%s\n' "$CONSUMER" >> "$ART/context.txt"
printf 'vip=%s\n' "$VIP" >> "$ART/context.txt"
printf 'neuwerk_nodes=%s\n' "${FWS[*]}" >> "$ART/context.txt"

echo "artifact_dir=$ART"

cat > "$ART/remote_perf.sh" <<'EOS'
set -euo pipefail
TS="${TS:?}"
OUT="/tmp/neuwerk-perf30-${TS}"
rm -rf "$OUT"
mkdir -p "$OUT"

hostname > "$OUT/hostname.txt"
uname -r > "$OUT/kernel.txt"
date -u +%Y-%m-%dT%H:%M:%SZ > "$OUT/date.txt"

pid="$(pgrep -n neuwerk || true)"
if [ -z "$pid" ]; then
  echo "missing neuwerk process" > "$OUT/error.txt"
  tar -C "$OUT" -czf - .
  exit 0
fi

echo "$pid" > "$OUT/pid.txt"
awk '/Cpus_allowed_list|Mems_allowed_list/' "/proc/$pid/status" > "$OUT/proc_affinity.txt" || true

PERF_BIN="/usr/lib/linux-azure-6.17-tools-6.17.0-1008/perf"
if [ ! -x "$PERF_BIN" ]; then
  PERF_BIN="$(ls -1 /usr/lib/linux-*-tools-*/perf 2>/dev/null | sort -V | tail -n1 || true)"
fi
echo "$PERF_BIN" > "$OUT/perf_bin.txt"
EVENTS="task-clock,context-switches,cpu-migrations,page-faults,cpu-clock,cycles,instructions,cache-references,cache-misses,branches,branch-misses"

if [ -n "$PERF_BIN" ] && [ -x "$PERF_BIN" ]; then
  if LC_ALL=C sudo -n "$PERF_BIN" stat --no-big-num -x, -e "$EVENTS" -p "$pid" -- sleep 30 >/dev/null 2>"$OUT/perf.csv"; then
    echo "sudo" > "$OUT/perf.mode"
  else
    echo "failed" > "$OUT/perf.mode"
  fi
else
  echo "missing" > "$OUT/perf.mode"
fi

tar -C "$OUT" -czf - .
EOS
chmod +x "$ART/remote_perf.sh"

ssh_proxy=(ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes -i "$KEY" -o ProxyCommand="ssh -o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes -i $KEY -W %h:%p ubuntu@$JUMP")

for ip in "${FWS[@]}"; do
  "${ssh_proxy[@]}" ubuntu@"$ip" "bash -lc 'METRICS_HOST=\$(grep \"^MGMT_IP=\" /etc/neuwerk/neuwerk.env 2>/dev/null | cut -d= -f2); [ -z \"\$METRICS_HOST\" ] && METRICS_HOST=127.0.0.1; curl -s http://\${METRICS_HOST}:8080/metrics | grep -E \"^dpdk_(rx|tx)_(packets|bytes)_total \" || true'" > "$ART/$ip.metrics.pre" || true
done

collector_pids=()
for ip in "${FWS[@]}"; do
  (
    "${ssh_proxy[@]}" ubuntu@"$ip" "TS=$TS bash -s" < "$ART/remote_perf.sh" > "$ART/raw/$ip.tgz" 2> "$ART/raw/$ip.stderr"
  ) &
  collector_pids+=("$!")
done

sleep 2
set +e
"${ssh_proxy[@]}" ubuntu@"$CONSUMER" "timeout 45 iperf3 -c $VIP -p 5201 -t 30 -P 32 --connect-timeout 5000 -J" > "$ART/iperf.json" 2> "$ART/iperf.stderr"
IPERF_RC=$?
set -e
echo "iperf_rc=$IPERF_RC" > "$ART/iperf.rc"

for pid in "${collector_pids[@]}"; do
  wait "$pid"
done

for ip in "${FWS[@]}"; do
  mkdir -p "$ART/$ip"
  if [ -s "$ART/raw/$ip.tgz" ]; then
    tar -xzf "$ART/raw/$ip.tgz" -C "$ART/$ip" || true
  fi
  "${ssh_proxy[@]}" ubuntu@"$ip" "bash -lc 'METRICS_HOST=\$(grep \"^MGMT_IP=\" /etc/neuwerk/neuwerk.env 2>/dev/null | cut -d= -f2); [ -z \"\$METRICS_HOST\" ] && METRICS_HOST=127.0.0.1; curl -s http://\${METRICS_HOST}:8080/metrics | grep -E \"^dpdk_(rx|tx)_(packets|bytes)_total \" || true'" > "$ART/$ip.metrics.post" || true
done

metric_from_file() {
  local file="$1"
  local name="$2"
  awk -v n="$name" '$1==n {print $2; exit}' "$file" 2>/dev/null || true
}
perf_val() {
  local file="$1"
  local event="$2"
  awk -F, -v ev="$event" '$3==ev {gsub(/ /, "", $1); print $1; exit}' "$file" 2>/dev/null || true
}

summary="$ART/SUMMARY.txt"
: > "$summary"
if [ -s "$ART/iperf.json" ]; then
  jq -r '["iperf_end_sum_sent_bps=" + ((.end.sum_sent.bits_per_second // 0)|tostring), "iperf_end_sum_received_bps=" + ((.end.sum_received.bits_per_second // 0)|tostring)][]' "$ART/iperf.json" >> "$summary" || true
else
  echo "iperf_end_sum_sent_bps=N/A" >> "$summary"
  echo "iperf_end_sum_received_bps=N/A" >> "$summary"
fi
echo "----" >> "$summary"

for ip in "${FWS[@]}"; do
  host="$(cat "$ART/$ip/hostname.txt" 2>/dev/null || echo unknown)"
  pid="$(cat "$ART/$ip/pid.txt" 2>/dev/null || echo unknown)"
  cpus_allowed="$(awk -F':\t' '/Cpus_allowed_list/ {print $2; exit}' "$ART/$ip/proc_affinity.txt" 2>/dev/null || true)"
  perf_bin="$(cat "$ART/$ip/perf_bin.txt" 2>/dev/null || echo missing)"
  perf_mode="$(cat "$ART/$ip/perf.mode" 2>/dev/null || echo missing)"
  task_clock="$(perf_val "$ART/$ip/perf.csv" task-clock)"
  cycles="$(perf_val "$ART/$ip/perf.csv" cycles)"
  instr="$(perf_val "$ART/$ip/perf.csv" instructions)"
  cache_ref="$(perf_val "$ART/$ip/perf.csv" cache-references)"
  cache_miss="$(perf_val "$ART/$ip/perf.csv" cache-misses)"
  branches="$(perf_val "$ART/$ip/perf.csv" branches)"
  branch_miss="$(perf_val "$ART/$ip/perf.csv" branch-misses)"
  rx_pre="$(metric_from_file "$ART/$ip.metrics.pre" dpdk_rx_packets_total)"
  rx_post="$(metric_from_file "$ART/$ip.metrics.post" dpdk_rx_packets_total)"
  tx_pre="$(metric_from_file "$ART/$ip.metrics.pre" dpdk_tx_packets_total)"
  tx_post="$(metric_from_file "$ART/$ip.metrics.post" dpdk_tx_packets_total)"
  rx_delta="N/A"; tx_delta="N/A"
  [[ -n "$rx_pre" && -n "$rx_post" ]] && rx_delta="$((rx_post-rx_pre))"
  [[ -n "$tx_pre" && -n "$tx_post" ]] && tx_delta="$((tx_post-tx_pre))"
  ipc="N/A"; cache_rate="N/A"; branch_rate="N/A"
  if [[ -n "$cycles" && -n "$instr" ]] && awk "BEGIN{exit !($cycles+0>0)}" >/dev/null 2>&1; then
    ipc="$(awk -v i="$instr" -v c="$cycles" 'BEGIN{printf "%.3f", i/c}')"
  fi
  if [[ -n "$cache_ref" && -n "$cache_miss" ]] && awk "BEGIN{exit !($cache_ref+0>0)}" >/dev/null 2>&1; then
    cache_rate="$(awk -v m="$cache_miss" -v r="$cache_ref" 'BEGIN{printf "%.2f", 100.0*m/r}')"
  fi
  if [[ -n "$branches" && -n "$branch_miss" ]] && awk "BEGIN{exit !($branches+0>0)}" >/dev/null 2>&1; then
    branch_rate="$(awk -v m="$branch_miss" -v b="$branches" 'BEGIN{printf "%.2f", 100.0*m/b}')"
  fi
  {
    echo "host: $ip"
    echo "hostname: $host"
    echo "pid: $pid"
    echo "cpus_allowed_list: ${cpus_allowed:-unknown}"
    echo "perf_bin: $perf_bin"
    echo "perf_mode: $perf_mode"
    echo "task_clock: ${task_clock:-N/A}"
    echo "ipc: $ipc"
    echo "cache_miss_rate_pct: $cache_rate"
    echo "branch_miss_rate_pct: $branch_rate"
    echo "dpdk_rx_packets_delta_30s: $rx_delta"
    echo "dpdk_tx_packets_delta_30s: $tx_delta"
    echo "----"
  } >> "$summary"
done

echo "SUMMARY=$summary"
cat "$summary"
