#!/usr/bin/env bash
set -euo pipefail

repo_dir="${NEUWERK_REPO_DIR:-}"
target_id="${NEUWERK_TARGET:-}"
use_prebuilt="${NEUWERK_USE_PREBUILT_ARTIFACTS:-false}"

if [[ -z "$repo_dir" || -z "$target_id" ]]; then
  echo "NEUWERK_REPO_DIR and NEUWERK_TARGET are required" >&2
  exit 1
fi

packages_json="$(python3 "$repo_dir/packaging/scripts/resolve_target.py" --target "$target_id")"
build_packages="$(printf '%s\n' "$packages_json" | python3 -c 'import json,sys; print(" ".join(json.load(sys.stdin)["packages"]["build"]))')"
runtime_packages="$(printf '%s\n' "$packages_json" | python3 -c 'import json,sys; print(" ".join(json.load(sys.stdin)["packages"]["runtime"]))')"

purge_if_installed() {
  local packages=("$@")
  local installed=()
  local pkg=""

  for pkg in "${packages[@]}"; do
    if dpkg-query -W -f='${db:Status-Status}\n' "$pkg" 2>/dev/null | grep -qx installed; then
      installed+=("$pkg")
    fi
  done

  if [[ "${#installed[@]}" -gt 0 ]]; then
    sudo DEBIAN_FRONTEND=noninteractive apt-get purge -y "${installed[@]}"
  fi
}

filter_packages() {
  local source_name="$1"
  local exclude_name="$2"
  local output_name="$3"
  local source_ref="$source_name[@]"
  local exclude_ref="$exclude_name[@]"
  local output_ref="$output_name[@]"
  local source=("${!source_ref}")
  local exclude=("${!exclude_ref}")
  local filtered=()
  local pkg=""

  for pkg in "${source[@]}"; do
    if [[ -z "$pkg" ]]; then
      continue
    fi
    if [[ " ${exclude[*]} " == *" $pkg "* ]]; then
      continue
    fi
    filtered+=("$pkg")
  done

  printf -v "$output_name" '%s\n' "${filtered[@]}"
}

read -r -a build_package_array <<<"$build_packages"
read -r -a runtime_package_array <<<"$runtime_packages"

keep_packages=(
  ca-certificates
  curl
  python3
  zstd
)
purge_candidates=()

case "$use_prebuilt" in
  1|true|TRUE|yes|YES)
    purge_candidates=(
      ansible
      ansible-core
      nodejs
      npm
    )
    ;;
  *)
    purge_candidates=("${build_package_array[@]}" nodejs npm)
    ;;
esac

filter_packages purge_candidates runtime_package_array filtered_purge_candidates_raw
readarray -t filtered_purge_candidates <<<"$filtered_purge_candidates_raw"
filter_packages filtered_purge_candidates keep_packages filtered_purge_candidates_raw
readarray -t filtered_purge_candidates <<<"$filtered_purge_candidates_raw"

sudo apt-mark manual "${runtime_package_array[@]}" "${keep_packages[@]}" >/dev/null 2>&1 || true
purge_if_installed "${filtered_purge_candidates[@]}"
sudo DEBIAN_FRONTEND=noninteractive apt-get autoremove -y --purge || true
sudo apt-get clean
sudo rm -rf /var/lib/apt/lists/*
sed -i '\|\.cargo/env|d' "$HOME/.profile" "$HOME/.bashrc" 2>/dev/null || true
rm -rf \
  "$HOME/.cargo" \
  "$HOME/.local/bin/syft" \
  "$HOME/.local/share/syft" \
  "$HOME/.rustup" \
  "$HOME/.npm" \
  "$HOME/.cache" \
  "$repo_dir" \
  /tmp/neuwerk-source.tar.gz
