#!/usr/bin/env bash
set -euo pipefail

repo_root="${NEUWERK_REPO_ROOT:-}"
bundle_output="${NEUWERK_BUNDLE_OUTPUT:-}"

if [[ -z "$repo_root" || -z "$bundle_output" ]]; then
  echo "NEUWERK_REPO_ROOT and NEUWERK_BUNDLE_OUTPUT are required" >&2
  exit 1
fi

mkdir -p "$(dirname "$bundle_output")"
tar \
  --exclude='.git' \
  --exclude='.bin' \
  --exclude='artifacts' \
  --exclude='cloud-tests' \
  --exclude='demo/vagrant/.vagrant' \
  --exclude='fuzz/target' \
  --exclude='target-*' \
  --exclude='target' \
  --exclude='ui/node_modules' \
  --exclude='www/dist' \
  --exclude='www/node_modules' \
  --exclude='third_party/dpdk/src' \
  --exclude='third_party/dpdk/build' \
  --exclude='third_party/dpdk/install' \
  --exclude='.terraform' \
  --exclude='*.tfstate' \
  -czf "$bundle_output" \
  -C "$repo_root" \
  .
