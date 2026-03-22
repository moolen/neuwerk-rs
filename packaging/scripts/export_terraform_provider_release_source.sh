#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  export_terraform_provider_release_source.sh --output-dir <output-dir>

The exported tree is a flat provider-only release-source repository:
- provider Go module at repository root
- provider docs and examples included
- public release-repo templates overlaid
- unrelated monorepo files omitted
EOF
}

require_dir() {
  local path="$1"
  if [[ ! -d "$path" ]]; then
    echo "missing required directory: $path" >&2
    exit 1
  fi
}

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
provider_dir="$repo_root/terraform-provider-neuwerk"
template_dir="$repo_root/packaging/terraform-provider-release-source"
output_dir=""

while [[ $# -gt 0 ]]; do
  case "$1" in
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

if [[ -z "$output_dir" ]]; then
  usage >&2
  exit 1
fi

if [[ "$output_dir" == "/" ]]; then
  echo "refusing to export into /" >&2
  exit 1
fi

require_dir "$provider_dir"
require_dir "$template_dir"

rm -rf "$output_dir"
mkdir -p "$output_dir"

cp -R "$provider_dir"/. "$output_dir"/
cp -R "$template_dir"/. "$output_dir"/
