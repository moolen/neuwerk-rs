#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCENARIO="${NEUWERK_HOTLOOP_SCENARIO:-unique-source-no-snat}"
ITERATIONS="${NEUWERK_HOTLOOP_ITERATIONS:-5000000}"
POOL_SIZE="${NEUWERK_HOTLOOP_POOL_SIZE:-}"
CORE="${NEUWERK_HOTLOOP_CORE:-}"
NICE_LEVEL="${NEUWERK_HOTLOOP_NICE_LEVEL:-}"
PERF_RECORD="${NEUWERK_HOTLOOP_PERF_RECORD:-0}"
PERF_SECONDS="${NEUWERK_HOTLOOP_PERF_SECONDS:-10}"
PERF_DELAY_MS="${NEUWERK_HOTLOOP_PERF_DELAY_MS:-1000}"
LOG_DIR="${NEUWERK_HOTLOOP_LOG_DIR:-$ROOT_DIR/target/hotloop-runs}"

if [[ -z "$POOL_SIZE" ]]; then
  if [[ "$PERF_RECORD" == "1" ]]; then
    POOL_SIZE=49152
  else
    POOL_SIZE=4096
  fi
fi

next_power_of_two() {
  local n="$1"
  local p=1
  while (( p < n )); do
    p=$(( p << 1 ))
  done
  printf '%s\n' "$p"
}

auto_table_capacity() {
  local active_entries="$1"
  local required=$(( (active_entries * 100 + 69) / 70 ))
  next_power_of_two "$required"
}

FLOW_TABLE_CAPACITY="${NEUWERK_FLOW_TABLE_CAPACITY:-}"
NAT_TABLE_CAPACITY="${NEUWERK_NAT_TABLE_CAPACITY:-}"

if [[ "$PERF_RECORD" == "1" ]]; then
  if [[ -z "$FLOW_TABLE_CAPACITY" ]]; then
    FLOW_TABLE_CAPACITY="$(auto_table_capacity "$POOL_SIZE")"
  fi
  if [[ -z "$NAT_TABLE_CAPACITY" ]]; then
    NAT_TABLE_CAPACITY="$(auto_table_capacity "$POOL_SIZE")"
  fi
fi

if [[ "${1:-}" == "--help" ]]; then
  cat <<'EOF'
Usage: scripts/profile-dataplane-hotloop.sh

Environment variables:
  NEUWERK_HOTLOOP_SCENARIO       Scenario: unique-source-no-snat | shared-source-no-snat | snat-metrics
  NEUWERK_HOTLOOP_ITERATIONS     Iteration count for direct timing mode. Default: 5000000
  NEUWERK_HOTLOOP_POOL_SIZE      Packet/state recycle pool size. Default: 4096 for timing, 49152 for perf
  NEUWERK_HOTLOOP_CORE           Optional CPU affinity, passed to taskset -c
  NEUWERK_HOTLOOP_NICE_LEVEL     Optional nice level, passed to nice -n
  NEUWERK_HOTLOOP_PERF_RECORD    Set to 1 to run perf record/report instead of direct timing
  NEUWERK_HOTLOOP_PERF_SECONDS   profile-time used for perf mode. Default: 10
  NEUWERK_HOTLOOP_PERF_DELAY_MS  Delay before perf sampling starts. Default: 1000
  NEUWERK_HOTLOOP_LOG_DIR        Output directory. Default: target/hotloop-runs
  NEUWERK_FLOW_TABLE_CAPACITY    Optional flow table capacity override; auto-sized in perf mode
  NEUWERK_NAT_TABLE_CAPACITY     Optional NAT table capacity override; auto-sized in perf mode

Examples:
  scripts/profile-dataplane-hotloop.sh
  NEUWERK_HOTLOOP_SCENARIO=snat-metrics scripts/profile-dataplane-hotloop.sh
  NEUWERK_HOTLOOP_PERF_RECORD=1 NEUWERK_HOTLOOP_CORE=2 scripts/profile-dataplane-hotloop.sh
EOF
  exit 0
fi

mkdir -p "$LOG_DIR"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"

prefix=()
if [[ -n "$CORE" ]]; then
  command -v taskset >/dev/null 2>&1 || {
    echo "error: taskset is required when NEUWERK_HOTLOOP_CORE is set" >&2
    exit 1
  }
  prefix+=(taskset -c "$CORE")
fi

if [[ -n "$NICE_LEVEL" ]]; then
  command -v nice >/dev/null 2>&1 || {
    echo "error: nice is required when NEUWERK_HOTLOOP_NICE_LEVEL is set" >&2
    exit 1
  }
  prefix+=(nice -n "$NICE_LEVEL")
fi

(
  cd "$ROOT_DIR"
  cargo build --release --bin dataplane_hotloop >/dev/null
)

bin="$ROOT_DIR/target/release/dataplane_hotloop"

if [[ "$PERF_RECORD" == "1" ]]; then
  perf_data="$LOG_DIR/${SCENARIO}-${timestamp}.perf.data"
  perf_report="$LOG_DIR/${SCENARIO}-${timestamp}.perf.report.txt"
  perf_stderr="$LOG_DIR/${SCENARIO}-${timestamp}.perf.stderr.txt"

  env \
    NEUWERK_FLOW_TABLE_CAPACITY="$FLOW_TABLE_CAPACITY" \
    NEUWERK_NAT_TABLE_CAPACITY="$NAT_TABLE_CAPACITY" \
    "${prefix[@]}" perf record --delay "$PERF_DELAY_MS" -o "$perf_data" -g -- \
    "$bin" "$SCENARIO" --iterations "$(( PERF_SECONDS * 1000000 ))" --pool-size "$POOL_SIZE" \
    >/dev/null 2>"$perf_stderr"

  perf report --stdio --sort symbol -i "$perf_data" >"$perf_report"

  cat <<EOF
perf_data=$perf_data
perf_report=$perf_report
perf_stderr=$perf_stderr
EOF
  exit 0
fi

log_file="$LOG_DIR/${SCENARIO}-${timestamp}.txt"

(
  cd "$ROOT_DIR"
  "${prefix[@]}" "$bin" "$SCENARIO" --iterations "$ITERATIONS" --pool-size "$POOL_SIZE"
) | tee "$log_file"

echo
echo "hotloop log written to $log_file"
