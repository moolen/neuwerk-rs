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
