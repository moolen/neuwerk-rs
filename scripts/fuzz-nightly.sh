#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FUZZ_DIR="$ROOT_DIR/fuzz"
FUZZ_CMD=(cargo +nightly fuzz)

if ! cargo fuzz --help >/dev/null 2>&1; then
  echo "error: cargo-fuzz is required for nightly fuzz lane" >&2
  exit 1
fi

if ! "${FUZZ_CMD[@]}" --help >/dev/null 2>&1; then
  echo "error: nightly toolchain is required for nightly fuzz lane (cargo +nightly fuzz)" >&2
  exit 1
fi

MAX_TOTAL_TIME="${NEUWERK_FUZZ_NIGHTLY_MAX_TIME:-900}"
SEED="${NEUWERK_FUZZ_SEED:-1337}"
SANITIZERS="${NEUWERK_FUZZ_NIGHTLY_SANITIZERS:-address undefined}"

run_target() {
  local sanitizer="$1"
  local target="$2"
  local corpus_dir="$FUZZ_DIR/corpus/$target"
  mkdir -p "$corpus_dir"
  echo "fuzz-nightly: sanitizer=$sanitizer target=$target max_time=${MAX_TOTAL_TIME}s seed=$SEED"
  (
    cd "$FUZZ_DIR"
    "${FUZZ_CMD[@]}" run --sanitizer "$sanitizer" "$target" "$corpus_dir" -- -max_total_time="$MAX_TOTAL_TIME" -seed="$SEED" -detect_leaks=1
  )
}

for sanitizer in $SANITIZERS; do
  run_target "$sanitizer" "packet_parse"
  run_target "$sanitizer" "overlay_decap"
  run_target "$sanitizer" "tls_reassembly"
done

echo "fuzz-nightly: completed all targets"
