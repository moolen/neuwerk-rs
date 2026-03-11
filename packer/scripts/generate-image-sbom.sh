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

if ! command -v syft >/dev/null 2>&1; then
  echo "syft is required to generate image SBOMs" >&2
  exit 1
fi

mkdir -p "$artifact_dir"
syft dir:/ \
  --exclude './proc/**' \
  --exclude './sys/**' \
  --exclude './dev/**' \
  --exclude './run/**' \
  --exclude './tmp/**' \
  -o "spdx-json=$artifact_dir/${target_id}-image.spdx.json"
syft dir:/ \
  --exclude './proc/**' \
  --exclude './sys/**' \
  --exclude './dev/**' \
  --exclude './run/**' \
  --exclude './tmp/**' \
  -o "cyclonedx-json=$artifact_dir/${target_id}-image.cyclonedx.json"
