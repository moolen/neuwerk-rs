#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  build_terraform_provider_release_assets.sh \
    --release-version <version> \
    --output-dir <output-dir>

Optional:
  --provider-dir <dir>   Provider source directory. Default: terraform-provider-neuwerk
  --provider-name <name> Provider artifact prefix. Default: terraform-provider-neuwerk
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

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
provider_dir="terraform-provider-neuwerk"
provider_name="terraform-provider-neuwerk"
release_version=""
output_dir=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --provider-dir)
      provider_dir="$2"
      shift 2
      ;;
    --provider-name)
      provider_name="$2"
      shift 2
      ;;
    --release-version)
      release_version="$2"
      shift 2
      ;;
    --output-dir)
      output_dir="$2"
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

if [[ -z "$release_version" || -z "$output_dir" ]]; then
  usage >&2
  exit 1
fi

require_cmd go
require_cmd gpg
require_cmd mktemp
require_cmd python3
require_cmd sha256sum

require_env GPG_PRIVATE_KEY
require_env GPG_PASSPHRASE
require_env GPG_KEY_ID

cd "$repo_root"

version="${release_version#v}"
provider_dir_path="$provider_dir"
output_dir_path="$output_dir"

rm -rf "$output_dir_path"
mkdir -p "$output_dir_path"

targets=(
  "linux amd64"
  "linux arm64"
  "darwin amd64"
  "darwin arm64"
  "windows amd64"
)

for target in "${targets[@]}"; do
  read -r goos goarch <<<"$target"
  ext=""
  if [[ "$goos" == "windows" ]]; then
    ext=".exe"
  fi

  bin_name="${provider_name}_v${version}${ext}"
  archive_name="${provider_name}_${version}_${goos}_${goarch}.zip"
  archive_path="${output_dir_path}/${archive_name}"
  stage_dir="$(mktemp -d)"

  (
    cd "$provider_dir_path"
    GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 \
      go build -trimpath -ldflags="-s -w -X main.version=${release_version}" \
      -o "${stage_dir}/${bin_name}" .
  )

  STAGE_DIR="$stage_dir" ARCHIVE_PATH="$archive_path" python3 - <<'PY'
import os
import pathlib
import zipfile

stage = pathlib.Path(os.environ["STAGE_DIR"])
archive = pathlib.Path(os.environ["ARCHIVE_PATH"])

with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
    for path in sorted(stage.iterdir()):
        zf.write(path, path.name)
PY

  rm -rf "$stage_dir"
done

(
  cd "$output_dir_path"
  sha256sum ./*.zip > "${provider_name}_${version}_SHA256SUMS"
)

keyring_dir="$(mktemp -d)"
chmod 0700 "$keyring_dir"
cleanup() {
  rm -rf "$keyring_dir"
}
trap cleanup EXIT

checksum_path="${output_dir_path}/${provider_name}_${version}_SHA256SUMS"
signature_path="${checksum_path}.sig"

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
  echo "failed to create provider checksum signature: $signature_path" >&2
  exit 1
fi
