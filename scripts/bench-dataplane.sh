#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BENCH_NAME="${NEUWERK_BENCH_NAME:-dataplane}"
SAMPLE_SIZE="${NEUWERK_BENCH_SAMPLE_SIZE:-30}"
WARM_UP_SECS="${NEUWERK_BENCH_WARM_UP_SECS:-1}"
CORE="${NEUWERK_BENCH_CORE:-}"
NICE_LEVEL="${NEUWERK_BENCH_NICE_LEVEL:-}"
LOG_DIR="${NEUWERK_BENCH_LOG_DIR:-$ROOT_DIR/target/criterion-runs}"
SAVE_BASELINE="${NEUWERK_BENCH_SAVE_BASELINE:-}"
COMPARE_BASELINE="${NEUWERK_BENCH_COMPARE_BASELINE:-}"

if [[ "${1:-}" == "--help" ]]; then
  cat <<'EOF'
Usage: scripts/bench-dataplane.sh

Environment variables:
  NEUWERK_BENCH_NAME               Criterion bench target name. Default: dataplane
  NEUWERK_BENCH_SAMPLE_SIZE        Criterion sample size. Default: 30
  NEUWERK_BENCH_WARM_UP_SECS       Criterion warm-up duration in seconds. Default: 1
  NEUWERK_BENCH_CORE               Optional CPU core affinity, passed to taskset -c
  NEUWERK_BENCH_NICE_LEVEL         Optional nice level, passed to nice -n
  NEUWERK_BENCH_LOG_DIR            Log output directory. Default: target/criterion-runs
  NEUWERK_BENCH_SAVE_BASELINE      Save a Criterion baseline with this name
  NEUWERK_BENCH_COMPARE_BASELINE   Compare against a saved Criterion baseline

Examples:
  make bench.dataplane
  NEUWERK_BENCH_CORE=2 NEUWERK_BENCH_SAVE_BASELINE=before make bench.dataplane
  NEUWERK_BENCH_CORE=2 NEUWERK_BENCH_COMPARE_BASELINE=before make bench.dataplane
EOF
  exit 0
fi

mkdir -p "$LOG_DIR"

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
log_file="$LOG_DIR/${BENCH_NAME}-${timestamp}.log"

cmd=(cargo bench --bench "$BENCH_NAME" -- --sample-size "$SAMPLE_SIZE" --warm-up-time "$WARM_UP_SECS")

if [[ -n "$SAVE_BASELINE" && -n "$COMPARE_BASELINE" ]]; then
  echo "error: set only one of NEUWERK_BENCH_SAVE_BASELINE or NEUWERK_BENCH_COMPARE_BASELINE" >&2
  exit 1
fi

if [[ -n "$SAVE_BASELINE" ]]; then
  cmd+=(--save-baseline "$SAVE_BASELINE")
fi

if [[ -n "$COMPARE_BASELINE" ]]; then
  cmd+=(--baseline "$COMPARE_BASELINE")
fi

prefix=()

if [[ -n "$CORE" ]]; then
  if ! command -v taskset >/dev/null 2>&1; then
    echo "error: taskset is required when NEUWERK_BENCH_CORE is set" >&2
    exit 1
  fi
  prefix+=(taskset -c "$CORE")
fi

if [[ -n "$NICE_LEVEL" ]]; then
  if ! command -v nice >/dev/null 2>&1; then
    echo "error: nice is required when NEUWERK_BENCH_NICE_LEVEL is set" >&2
    exit 1
  fi
  prefix+=(nice -n "$NICE_LEVEL")
fi

{
  echo "bench_name=$BENCH_NAME"
  echo "timestamp_utc=$timestamp"
  echo "sample_size=$SAMPLE_SIZE"
  echo "warm_up_secs=$WARM_UP_SECS"
  echo "core=${CORE:-unbound}"
  echo "nice_level=${NICE_LEVEL:-default}"
  echo "save_baseline=${SAVE_BASELINE:-none}"
  echo "compare_baseline=${COMPARE_BASELINE:-none}"
  echo "command=${prefix[*]} ${cmd[*]}"
  echo
} | tee "$log_file"

(
  cd "$ROOT_DIR"
  "${prefix[@]}" "${cmd[@]}"
) 2>&1 | tee -a "$log_file"

echo
echo "bench log written to $log_file"
