#!/usr/bin/env bash
set -euo pipefail

repo_dir="${NEUWERK_REPO_DIR:-}"
target_id="${NEUWERK_TARGET:-}"

if [[ -z "$repo_dir" || -z "$target_id" ]]; then
  echo "NEUWERK_REPO_DIR and NEUWERK_TARGET are required" >&2
  exit 1
fi

packages_json="$(python3 "$repo_dir/packaging/scripts/resolve_target.py" --target "$target_id")"
build_packages="$(printf '%s\n' "$packages_json" | python3 -c 'import json,sys; print(" ".join(json.load(sys.stdin)["packages"]["build"]))')"
runtime_packages="$(printf '%s\n' "$packages_json" | python3 -c 'import json,sys; print(" ".join(json.load(sys.stdin)["packages"]["runtime"]))')"

sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y $build_packages $runtime_packages

if ! command -v node >/dev/null 2>&1 || [[ "$(node -p 'process.versions.node.split(`.`)[0]' 2>/dev/null || printf 0)" -lt 20 ]]; then
  curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y nodejs
fi

if ! command -v cargo >/dev/null 2>&1; then
  curl https://sh.rustup.rs -sSf | sh -s -- -y
fi

if [[ -f "$HOME/.cargo/env" ]]; then
  # shellcheck disable=SC1090
  source "$HOME/.cargo/env"
fi

if ! command -v syft >/dev/null 2>&1; then
  curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b "$HOME/.local/bin"
fi

export PATH="$HOME/.local/bin:$PATH"
