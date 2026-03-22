#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"

require_file() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    echo "missing required file: $path" >&2
    exit 1
  fi
}

required_paths=(
  "$repo_root/LICENSE"
  "$repo_root/SECURITY.md"
  "$repo_root/CONTRIBUTING.md"
  "$repo_root/docs/operations/release-readiness.md"
  "$repo_root/www/src/content/docs/community/release-process.mdx"
  "$repo_root/www/src/content/docs/community/contributing.mdx"
  "$repo_root/www/src/content/docs/community/security.mdx"
  "$repo_root/.github/workflows/image-release.yml"
  "$repo_root/.github/workflows/terraform-provider-release.yml"
  "$repo_root/packaging/release-signing/neuwerk-release-signing-key.asc"
  "$repo_root/packaging/scripts/sign_github_release_checksums.sh"
)

for path in "${required_paths[@]}"; do
  require_file "$path"
done

echo "oss launch surface ok"
