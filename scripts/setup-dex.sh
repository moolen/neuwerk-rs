#!/usr/bin/env bash
set -euo pipefail

DEX_VERSION="${DEX_VERSION:-2.45.1}"
INSTALL_DIR="${1:-${PWD}/.bin}"

os="linux"
arch_raw="$(uname -m)"
case "$arch_raw" in
  x86_64|amd64) arch="amd64" ;;
  aarch64|arm64) arch="arm64" ;;
  *)
    echo "Unsupported architecture: $arch_raw" >&2
    exit 1
    ;;
esac

mkdir -p "$INSTALL_DIR"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

version_tag="$DEX_VERSION"
if [[ "$version_tag" != v* ]]; then
  version_tag="v$version_tag"
fi

archive="dex-${version_tag}-${os}-${arch}.tar.gz"
download_url="https://github.com/dexidp/dex/releases/download/${version_tag}/${archive}"

echo "Installing Dex ${version_tag} (${os}/${arch})..."
if curl -fsSL "$download_url" -o "$tmpdir/$archive"; then
  tar -xzf "$tmpdir/$archive" -C "$tmpdir"
  if [[ ! -f "$tmpdir/dex" ]]; then
    echo "Dex archive did not contain dex binary" >&2
    exit 1
  fi
else
  echo "No release binary found for ${version_tag}; building dex from source..." >&2
  if ! command -v go >/dev/null 2>&1; then
    echo "go is required to build Dex when release binaries are unavailable" >&2
    exit 1
  fi
  if ! command -v git >/dev/null 2>&1; then
    echo "git is required to build Dex when release binaries are unavailable" >&2
    exit 1
  fi
  git clone --depth 1 --branch "${version_tag}" https://github.com/dexidp/dex "$tmpdir/dex-src"
  (
    cd "$tmpdir/dex-src"
    GOFLAGS="${GOFLAGS:-} -buildvcs=false" go build -o "$tmpdir/dex" ./cmd/dex
  )
  if [[ ! -f "$tmpdir/dex" ]]; then
    echo "go build completed without producing dex binary" >&2
    exit 1
  fi
fi

install -m 0755 "$tmpdir/dex" "$INSTALL_DIR/dex"
echo "Dex installed at: $INSTALL_DIR/dex"
