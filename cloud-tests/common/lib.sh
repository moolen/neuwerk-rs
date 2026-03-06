#!/usr/bin/env bash
set -euo pipefail

require_bin() {
  local bin="$1"
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo "missing required binary: $bin" >&2
    exit 1
  fi
}

ssh_jump() {
  local jump_host="$1"
  local key_path="$2"
  local target_host="$3"
  shift 3
  local ssh_user="${SSH_USER:-ubuntu}"
  local user_known_hosts="${SSH_USER_KNOWN_HOSTS_FILE:-/dev/null}"
  ssh-keygen -R "$jump_host" >/dev/null 2>&1 || true
  ssh-keygen -R "$target_host" >/dev/null 2>&1 || true
  ssh -o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes -i "$key_path" \
    -o UserKnownHostsFile="$user_known_hosts" \
    -o ProxyCommand="ssh -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=${user_known_hosts} -o IdentitiesOnly=yes -i ${key_path} -W %h:%p ${ssh_user}@${jump_host}" \
    "${ssh_user}@${target_host}" "$@"
}
