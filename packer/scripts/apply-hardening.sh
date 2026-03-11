#!/usr/bin/env bash
set -euo pipefail

repo_dir="${NEUWERK_REPO_DIR:-}"
target_id="${NEUWERK_TARGET:-}"

if [[ -z "$repo_dir" || -z "$target_id" ]]; then
  echo "NEUWERK_REPO_DIR and NEUWERK_TARGET are required" >&2
  exit 1
fi

cd "$repo_dir/packer/ansible"
sudo ansible-playbook \
  -i 'localhost,' \
  -c local \
  -e "neuwerk_repo_dir=$repo_dir" \
  -e "neuwerk_target=$target_id" \
  playbook.yml
