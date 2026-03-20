#!/usr/bin/env bash
set -euo pipefail

repo_dir="${NEUWERK_REPO_DIR:-}"
target_id="${NEUWERK_TARGET:-}"
artifact_dir="${NEUWERK_RELEASE_ARTIFACT_DIR:-}"

if [[ -z "$repo_dir" || -z "$target_id" || -z "$artifact_dir" ]]; then
  echo "NEUWERK_REPO_DIR, NEUWERK_TARGET, and NEUWERK_RELEASE_ARTIFACT_DIR are required" >&2
  exit 1
fi

mkdir -p "$artifact_dir/rootfs"
sudo bash "$repo_dir/packaging/scripts/stage_runtime.sh" \
  --target "$target_id" \
  --profile release \
  --repo-dir "$repo_dir" \
  --output-root /

sudo install -d -m 0755 /etc/neuwerk /var/lib/neuwerk
sudo systemctl daemon-reload
sudo systemctl enable neuwerk.service

bash "$repo_dir/packaging/scripts/stage_runtime.sh" \
  --target "$target_id" \
  --profile release \
  --repo-dir "$repo_dir" \
  --output-root "$artifact_dir/rootfs"
