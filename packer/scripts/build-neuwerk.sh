#!/usr/bin/env bash
set -euo pipefail

repo_dir="${NEUWERK_REPO_DIR:-}"
target_id="${NEUWERK_TARGET:-}"

if [[ -z "$repo_dir" || -z "$target_id" ]]; then
  echo "NEUWERK_REPO_DIR and NEUWERK_TARGET are required" >&2
  exit 1
fi

"$repo_dir/packaging/scripts/build_neuwerk.sh" --target "$target_id" --profile release --repo-dir "$repo_dir"
