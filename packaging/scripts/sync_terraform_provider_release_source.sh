#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  sync_terraform_provider_release_source.sh --repo-dir <path> [--remote-url <url>] [--branch <name>] [--push]

Sync the exported Terraform provider release-source tree into a working repository.

Examples:
  bash packaging/scripts/sync_terraform_provider_release_source.sh \
    --repo-dir "$HOME/src/terraform-provider-neuwerk" \
    --remote-url git@github.com:moolen/terraform-provider-neuwerk.git

  bash packaging/scripts/sync_terraform_provider_release_source.sh \
    --repo-dir "$HOME/src/terraform-provider-neuwerk" \
    --push
EOF
}

require_cmd() {
  local tool="$1"
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "missing required tool: $tool" >&2
    exit 1
  fi
}

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
repo_dir=""
remote_url=""
branch="main"
push_changes="0"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo-dir)
      repo_dir="$2"
      shift 2
      ;;
    --remote-url)
      remote_url="$2"
      shift 2
      ;;
    --branch)
      branch="$2"
      shift 2
      ;;
    --push)
      push_changes="1"
      shift
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

if [[ -z "$repo_dir" ]]; then
  usage >&2
  exit 1
fi

require_cmd git
require_cmd mktemp

if [[ ! -d "$repo_dir/.git" ]]; then
  if [[ -z "$remote_url" ]]; then
    echo "target repo does not exist yet; --remote-url is required to clone it" >&2
    exit 1
  fi
  git clone "$remote_url" "$repo_dir"
fi

if [[ ! -d "$repo_dir/.git" ]]; then
  echo "target path is not a git repository: $repo_dir" >&2
  exit 1
fi

if [[ -n "$(git -C "$repo_dir" status --short)" ]]; then
  echo "target repo has uncommitted changes: $repo_dir" >&2
  exit 1
fi

if ! git -C "$repo_dir" rev-parse --verify "$branch" >/dev/null 2>&1; then
  if git -C "$repo_dir" rev-parse --verify HEAD >/dev/null 2>&1; then
    git -C "$repo_dir" checkout -b "$branch"
  else
    git -C "$repo_dir" checkout --orphan "$branch"
  fi
else
  git -C "$repo_dir" checkout "$branch"
fi

tmp_export_dir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp_export_dir"
}
trap cleanup EXIT

bash "$repo_root/packaging/scripts/export_terraform_provider_release_source.sh" \
  --output-dir "$tmp_export_dir"

find "$repo_dir" -mindepth 1 -maxdepth 1 ! -name '.git' -exec rm -rf {} +
cp -R "$tmp_export_dir"/. "$repo_dir"/

git -C "$repo_dir" add -A

if git -C "$repo_dir" diff --cached --quiet; then
  echo "release-source repo already up to date: $repo_dir"
  exit 0
fi

git -C "$repo_dir" commit -m "release-source: sync from firewall"

if [[ "$push_changes" == "1" ]]; then
  git -C "$repo_dir" push -u origin "$branch"
fi
