#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  sign_github_release_checksums.sh \
    --artifact-dir <artifact-dir> \
    --signing-key <public-key-file>
EOF
}

require_cmd() {
  local tool="$1"
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "missing required tool: $tool" >&2
    exit 1
  fi
}

require_env() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "missing required environment variable: $name" >&2
    exit 1
  fi
}

require_file() {
  local path="$1"
  local kind="${2:-file}"
  if [[ ! -f "$path" ]]; then
    echo "missing required ${kind}: $path" >&2
    exit 1
  fi
}

artifact_dir=""
signing_key=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --artifact-dir)
      artifact_dir="$2"
      shift 2
      ;;
    --signing-key)
      signing_key="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "$artifact_dir" || -z "$signing_key" ]]; then
  usage >&2
  exit 1
fi

require_cmd gpg
require_cmd mktemp
require_file "$artifact_dir/SHA256SUMS" "checksum file"
require_file "$signing_key" "signing key"
require_env GPG_PRIVATE_KEY
require_env GPG_PASSPHRASE
require_env GPG_KEY_ID

keyring_dir="$(mktemp -d)"
chmod 0700 "$keyring_dir"
cleanup() {
  rm -rf "$keyring_dir"
}
trap cleanup EXIT

checksum_path="$artifact_dir/SHA256SUMS"
signature_path="$artifact_dir/SHA256SUMS.sig"
public_key_output="$artifact_dir/$(basename "$signing_key")"

GNUPGHOME="$keyring_dir" gpg --batch --import <<EOF
${GPG_PRIVATE_KEY}
EOF

GNUPGHOME="$keyring_dir" gpg \
  --batch \
  --yes \
  --pinentry-mode loopback \
  --passphrase "$GPG_PASSPHRASE" \
  --local-user "$GPG_KEY_ID" \
  --output "$signature_path" \
  --detach-sign \
  "$checksum_path"

if [[ ! -s "$signature_path" ]]; then
  echo "failed to create checksum signature: $signature_path" >&2
  exit 1
fi

cp "$signing_key" "$public_key_output"
