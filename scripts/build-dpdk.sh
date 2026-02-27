#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dpdk_root="$root_dir/third_party/dpdk"
version_file="$dpdk_root/VERSION"

if [[ ! -f "$version_file" ]]; then
  echo "DPDK version file missing: $version_file" >&2
  exit 1
fi

version="$(cat "$version_file")"
src_base="$dpdk_root/src"
src_dir=""
tarball="$src_base/dpdk-$version.tar.xz"
build_dir="$dpdk_root/build/$version"
install_dir="$dpdk_root/install/$version"

if [[ -d "$install_dir/lib" || -d "$install_dir/lib64" ]]; then
  if [[ "${DPDK_FORCE_REBUILD:-0}" != "1" ]]; then
    echo "DPDK already installed at $install_dir (set DPDK_FORCE_REBUILD=1 to rebuild)"
    exit 0
  fi
  echo "Rebuilding DPDK at $install_dir"
fi

for tool in meson ninja python3; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "Missing required tool: $tool" >&2
    exit 1
  fi
done

if ! python3 -c "import elftools" >/dev/null 2>&1; then
  echo "Missing python module: pyelftools (required for DPDK PMD info generation)" >&2
  echo "Install via your package manager (eg: python-pyelftools / python3-pyelftools) or 'pip3 install --user pyelftools'." >&2
  exit 1
fi

mkdir -p "$src_base" "$dpdk_root/build" "$dpdk_root/install"

for candidate in "$src_base/dpdk-$version" "$src_base/dpdk-stable-$version"; do
  if [[ -d "$candidate" ]]; then
    src_dir="$candidate"
    break
  fi
done
if [[ -z "$src_dir" ]]; then
  candidate="$(find "$src_base" -maxdepth 1 -type d -name "dpdk*${version}" | head -n 1 || true)"
  if [[ -n "$candidate" ]]; then
    src_dir="$candidate"
  fi
fi

if [[ -z "$src_dir" ]]; then
  if [[ ! -f "$tarball" ]]; then
    url="https://fast.dpdk.org/rel/dpdk-$version.tar.xz"
    echo "Downloading $url"
    if command -v curl >/dev/null 2>&1; then
      curl -L -o "$tarball" "$url"
    elif command -v wget >/dev/null 2>&1; then
      wget -O "$tarball" "$url"
    else
      echo "Missing downloader: curl or wget" >&2
      exit 1
    fi
  fi
  echo "Extracting $tarball"
  tar -C "$src_base" -xf "$tarball"
  for candidate in "$src_base/dpdk-$version" "$src_base/dpdk-stable-$version"; do
    if [[ -d "$candidate" ]]; then
      src_dir="$candidate"
      break
    fi
  done
  if [[ -z "$src_dir" ]]; then
    candidate="$(find "$src_base" -maxdepth 1 -type d -name "dpdk*${version}" | head -n 1 || true)"
    if [[ -n "$candidate" ]]; then
      src_dir="$candidate"
    fi
  fi
fi

if [[ -z "$src_dir" ]]; then
  echo "Unable to locate DPDK source directory under $src_base" >&2
  exit 1
fi

patch_dir="$dpdk_root/patches"
if [[ -d "$patch_dir" ]]; then
  for patch_file in "$patch_dir"/*.patch; do
    if [[ -f "$patch_file" ]]; then
      (cd "$src_dir" && patch -p1 --forward --silent < "$patch_file") || true
    fi
  done
fi

meson_args=(
  "-Ddefault_library=shared"
  "-Dbuildtype=release"
  "-Dtests=false"
  "-Dexamples="
)

disable_drivers="${DPDK_DISABLE_DRIVERS:-net/ionic}"
if [[ -n "$disable_drivers" ]]; then
  meson_args+=("-Ddisable_drivers=${disable_drivers}")
fi

if [[ -n "${DPDK_MESON_ARGS:-}" ]]; then
  # shellcheck disable=SC2206
  meson_args+=( ${DPDK_MESON_ARGS} )
fi

if [[ -d "$build_dir" ]]; then
  meson setup --reconfigure "$build_dir" "$src_dir" --prefix "$install_dir" "${meson_args[@]}"
else
  meson setup "$build_dir" "$src_dir" --prefix "$install_dir" "${meson_args[@]}"
fi

ninja -C "$build_dir"
ninja -C "$build_dir" install

echo "DPDK installed at $install_dir"
