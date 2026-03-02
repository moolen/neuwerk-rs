set -euo pipefail
TS="${TS:?}"
OUT="/tmp/neuwerk-perf30-${TS}"
rm -rf "$OUT"
mkdir -p "$OUT"

hostname > "$OUT/hostname.txt"
uname -r > "$OUT/kernel.txt"
date -u +%Y-%m-%dT%H:%M:%SZ > "$OUT/date.txt"

pid="$(pgrep -n firewall || true)"
if [ -z "$pid" ]; then
  echo "missing firewall process" > "$OUT/error.txt"
  tar -C "$OUT" -czf - .
  exit 0
fi

echo "$pid" > "$OUT/pid.txt"
tr '\0' ' ' < "/proc/$pid/cmdline" > "$OUT/cmdline.txt" || true
awk '/Cpus_allowed_list|Mems_allowed_list/' "/proc/$pid/status" > "$OUT/proc_affinity.txt" || true
ps -T -p "$pid" -o pid,tid,psr,pcpu,comm,args > "$OUT/threadmap.txt" || true
ps -T -p "$pid" -o tid,comm --no-headers | awk '$2 ~ /dpdk-worker/ {print $1}' > "$OUT/pmd_tids.txt" || true

PERF_BIN=""
if [ -x "/usr/lib/linux-tools-$(uname -r)/perf" ]; then
  PERF_BIN="/usr/lib/linux-tools-$(uname -r)/perf"
elif command -v perf >/dev/null 2>&1; then
  PERF_BIN="$(command -v perf)"
fi
echo "$PERF_BIN" > "$OUT/perf_bin.txt"

EVENTS="cycles,instructions,cache-references,cache-misses,branches,branch-misses,task-clock,context-switches,cpu-migrations"

run_perf() {
  local target_pid="$1"
  local mode="$2"
  if [ -z "$PERF_BIN" ]; then
    echo "missing perf binary" > "$OUT/perf_${mode}.err"
    return 0
  fi
  if LC_ALL=C "$PERF_BIN" stat --no-big-num -x, -e "$EVENTS" -p "$target_pid" -- sleep 30 >/dev/null 2>"$OUT/perf_${mode}.csv"; then
    echo "plain" > "$OUT/perf_${mode}.mode"
    return 0
  fi
  if command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
    if LC_ALL=C sudo -n "$PERF_BIN" stat --no-big-num -x, -e "$EVENTS" -p "$target_pid" -- sleep 30 >/dev/null 2>"$OUT/perf_${mode}.csv"; then
      echo "sudo" > "$OUT/perf_${mode}.mode"
      return 0
    fi
  fi
  echo "failed" > "$OUT/perf_${mode}.mode"
}

run_perf "$pid" "proc"

tar -C "$OUT" -czf - .
