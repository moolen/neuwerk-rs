#!/usr/bin/env bash
set -euo pipefail

repo_dir="${NEUWERK_REPO_DIR:-}"
target_id="${NEUWERK_TARGET:-}"

if [[ -z "$repo_dir" || -z "$target_id" ]]; then
  echo "NEUWERK_REPO_DIR and NEUWERK_TARGET are required" >&2
  exit 1
fi

build_packages="$(python3 "$repo_dir/packaging/scripts/resolve_target.py" --target "$target_id" | python3 -c 'import json,sys; print(" ".join(json.load(sys.stdin)["packages"]["build"]))')"

sudo DEBIAN_FRONTEND=noninteractive apt-get purge -y $build_packages || true
sudo DEBIAN_FRONTEND=noninteractive apt-get autoremove -y --purge || true
sudo apt-get clean
sudo rm -rf /var/lib/apt/lists/*
rm -rf \
  "$HOME/.cargo" \
  "$HOME/.rustup" \
  "$HOME/.npm" \
  "$HOME/.cache" \
  "$repo_dir" \
  /tmp/neuwerk-source.tar.gz
