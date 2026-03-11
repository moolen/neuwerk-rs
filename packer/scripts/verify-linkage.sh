#!/usr/bin/env bash
set -euo pipefail

repo_dir="${NEUWERK_REPO_DIR:-}"
target_id="${NEUWERK_TARGET:-}"
artifact_dir="${NEUWERK_RELEASE_ARTIFACT_DIR:-}"

export PATH="$HOME/.local/bin:$PATH"

if [[ -z "$repo_dir" || -z "$target_id" || -z "$artifact_dir" ]]; then
  echo "NEUWERK_REPO_DIR, NEUWERK_TARGET, and NEUWERK_RELEASE_ARTIFACT_DIR are required" >&2
  exit 1
fi

mkdir -p "$artifact_dir"
"$repo_dir/packaging/scripts/verify_linkage.sh" \
  --target "$target_id" \
  --binary "$repo_dir/target/release/firewall" \
  --output-json "$artifact_dir/linkage.json"

if command -v syft >/dev/null 2>&1; then
  "$repo_dir/packaging/scripts/generate_sbom.sh" \
    --target "$target_id" \
    --rootfs "$artifact_dir/rootfs" \
    --output-dir "$artifact_dir"
fi
