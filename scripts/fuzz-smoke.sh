#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FUZZ_DIR="$ROOT_DIR/fuzz"
FUZZ_CMD=(cargo +nightly fuzz)

if ! cargo fuzz --help >/dev/null 2>&1; then
  if [[ "${NEUWERK_FUZZ_REQUIRED:-0}" == "1" ]]; then
    echo "error: cargo-fuzz is required but not installed" >&2
    exit 1
  fi
  echo "warning: cargo-fuzz not installed; skipping fuzz smoke run" >&2
  exit 0
fi

if ! "${FUZZ_CMD[@]}" --help >/dev/null 2>&1; then
  if [[ "${NEUWERK_FUZZ_REQUIRED:-0}" == "1" ]]; then
    echo "error: nightly toolchain is required for fuzz smoke (cargo +nightly fuzz)" >&2
    exit 1
  fi
  echo "warning: nightly toolchain unavailable; skipping fuzz smoke run" >&2
  exit 0
fi

RUNS="${NEUWERK_FUZZ_SMOKE_RUNS:-500}"
SEED="${NEUWERK_FUZZ_SEED:-1337}"

run_target() {
  local target="$1"
  local corpus_dir="$FUZZ_DIR/corpus/$target"
  mkdir -p "$corpus_dir"
  echo "fuzz-smoke: running $target (runs=$RUNS seed=$SEED)"
  (
    cd "$FUZZ_DIR"
    "${FUZZ_CMD[@]}" run "$target" "$corpus_dir" -- -runs="$RUNS" -seed="$SEED" -detect_leaks=1
  )
}

run_target "packet_parse"
run_target "overlay_decap"
run_target "tls_reassembly"

echo "fuzz-smoke: all targets completed"
