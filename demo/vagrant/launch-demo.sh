#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
VAGRANT_DIR="${SCRIPT_DIR}"
REPO_ROOT="$(cd -- "${VAGRANT_DIR}/../.." && pwd)"

YES=0

usage() {
  cat <<'EOF'
Usage: launch-demo.sh [--yes]

Launches the Neuwerk Vagrant demo with an automatically selected bridged uplink.

Options:
  -y, --yes    Skip the interactive confirmation prompt.
  -h, --help   Show this help text.
EOF
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

parse_args() {
  while (($# > 0)); do
    case "$1" in
      -y|--yes)
        YES=1
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        echo "unknown argument: $1" >&2
        usage >&2
        exit 2
        ;;
    esac
    shift
  done
}

host_default_iface() {
  ip -4 route show default 2>/dev/null | awk 'NR==1 {print $5; exit}'
}

host_default_gateway() {
  ip -4 route show default 2>/dev/null | awk 'NR==1 {print $3; exit}'
}

iface_ipv4() {
  local iface="$1"
  ip -o -4 addr show dev "${iface}" scope global | awk 'NR==1 {split($4, a, "/"); print a[1]}'
}

available_bridges() {
  VBoxManage list bridgedifs | awk '
    /^Name:[[:space:]]+/ {
      sub(/^Name:[[:space:]]+/, "", $0)
      print
    }
  '
}

github_repo_from_remote() {
  local url=""
  if command -v git >/dev/null 2>&1; then
    url="$(git -C "${REPO_ROOT}" config --get remote.origin.url 2>/dev/null || true)"
  fi
  case "${url}" in
    git@github.com:*.git)
      printf '%s\n' "${url#git@github.com:}" | sed 's/\.git$//'
      ;;
    https://github.com/*.git)
      printf '%s\n' "${url#https://github.com/}" | sed 's/\.git$//'
      ;;
    https://github.com/*)
      printf '%s\n' "${url#https://github.com/}"
      ;;
    *)
      return 1
      ;;
  esac
}

resolve_release_repo() {
  if [[ -n "${NEUWERK_RELEASE_REPO:-}" ]]; then
    printf '%s\n' "${NEUWERK_RELEASE_REPO}"
    return 0
  fi
  github_repo_from_remote || printf '%s\n' 'moolen/neuwerk-rs'
}

latest_release_tag() {
  local repo="$1"
  curl -fsSL \
    -H 'Accept: application/vnd.github+json' \
    "https://api.github.com/repos/${repo}/releases/latest" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["tag_name"])'
}

resolve_release_version() {
  local repo="$1"
  if [[ -n "${NEUWERK_BOX_URL:-}" && -z "${NEUWERK_RELEASE_VERSION:-}" ]]; then
    printf '%s\n' 'custom'
    return 0
  fi
  if [[ -n "${NEUWERK_RELEASE_VERSION:-}" ]]; then
    printf '%s\n' "${NEUWERK_RELEASE_VERSION}"
    return 0
  fi
  latest_release_tag "${repo}"
}

box_asset_name() {
  local target="$1"
  local version="$2"
  printf 'neuwerk-%s-%s-virtualbox.box\n' "${target}" "${version}"
}

metadata_asset_name() {
  local target="$1"
  local version="$2"
  printf 'neuwerk-%s-%s-virtualbox.metadata.json\n' "${target}" "${version}"
}

resolve_bridge_iface() {
  if [[ -n "${NEUWERK_BRIDGED_IFACE:-}" ]]; then
    printf '%s\n' "${NEUWERK_BRIDGED_IFACE}"
    return 0
  fi
  host_default_iface
}

check_permissions() {
  if ! VBoxManage list bridgedifs >/dev/null 2>&1; then
    echo "unable to query VirtualBox bridged interfaces" >&2
    exit 1
  fi

  if command -v getent >/dev/null 2>&1 && getent group vboxusers >/dev/null 2>&1; then
    if ! id -nG | tr ' ' '\n' | grep -qx 'vboxusers'; then
      echo "note: current user is not in vboxusers, but VirtualBox access is working" >&2
    fi
  fi

  if [[ ! -r "${SSH_KEY}" ]]; then
    echo "SSH key not readable: ${SSH_KEY}" >&2
    exit 1
  fi

  if ! curl -fsIL "${BOX_METADATA_URL}" >/dev/null 2>&1; then
    echo "unable to access release box metadata: ${BOX_METADATA_URL}" >&2
    exit 1
  fi
}

confirm_launch() {
  if (( YES == 1 )); then
    return 0
  fi
  if [[ ! -t 0 ]]; then
    echo "interactive confirmation required; rerun with --yes to skip it" >&2
    exit 1
  fi
  printf 'Proceed with this configuration? [y/N] '
  read -r reply
  case "${reply}" in
    y|Y|yes|YES)
      ;;
    *)
      echo "aborted"
      exit 1
      ;;
  esac
}

wait_for_health() {
  local url="$1"
  local attempts="${2:-120}"
  local delay_secs="${3:-1}"
  local i
  for ((i = 0; i < attempts; i += 1)); do
    if curl -skf "${url}" >/dev/null 2>&1; then
      return 0
    fi
    sleep "${delay_secs}"
  done
  return 1
}

read_admin_token() {
  ssh \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -i "${SSH_KEY}" \
    "${SSH_USER}@${MGMT_IP}" \
    '
      set -euo pipefail
      sudo systemctl restart neuwerk-demo-token.service >/dev/null 2>&1 || true
      for _ in $(seq 1 30); do
        if [[ -s /var/lib/neuwerk-demo/admin.token ]]; then
          cat /var/lib/neuwerk-demo/admin.token
          exit 0
        fi
        sleep 1
      done
      exit 1
    '
}

parse_args "$@"

for cmd in awk curl grep id ip python3 sed ssh vagrant VBoxManage; do
  require_cmd "${cmd}"
done

MGMT_IP="${NEUWERK_MGMT_IP:-192.168.57.10}"
CLIENT_GATEWAY_IP="${NEUWERK_CLIENT_GATEWAY_IP:-192.168.56.10}"
SSH_USER="${NEUWERK_SSH_USERNAME:-ubuntu}"
SSH_KEY="${NEUWERK_SSH_PRIVATE_KEY:-${HOME}/.vagrant.d/insecure_private_key}"
BOX_TARGET="${NEUWERK_BOX_TARGET:-ubuntu-24.04-minimal-amd64}"
RELEASE_REPO="$(resolve_release_repo)"
RELEASE_VERSION="$(resolve_release_version "${RELEASE_REPO}")"
BOX_ASSET_NAME="$(box_asset_name "${BOX_TARGET}" "${RELEASE_VERSION}")"
BOX_METADATA_NAME="$(metadata_asset_name "${BOX_TARGET}" "${RELEASE_VERSION}")"
BOX_RELEASE_BASE_URL="https://github.com/${RELEASE_REPO}/releases/download/${RELEASE_VERSION}"
BOX_METADATA_URL="${NEUWERK_BOX_URL:-${BOX_RELEASE_BASE_URL}/${BOX_METADATA_NAME}}"
BRIDGE_IFACE="$(resolve_bridge_iface)"
HOST_DEFAULT_IFACE="$(host_default_iface)"
HOST_DEFAULT_GW="$(host_default_gateway)"
HOST_BRIDGE_IP="$(iface_ipv4 "${BRIDGE_IFACE}" || true)"

check_permissions

if [[ -z "${BRIDGE_IFACE}" ]]; then
  echo "could not determine a host uplink interface" >&2
  exit 1
fi
if ! available_bridges | grep -Fxq "${BRIDGE_IFACE}"; then
  echo "host interface ${BRIDGE_IFACE} is not available as a VirtualBox bridge target" >&2
  echo "available bridge targets:" >&2
  available_bridges | sed 's/^/  - /' >&2
  exit 1
fi

cat <<EOF
Neuwerk Vagrant launch

Resolved host uplink:
  bridge interface: ${BRIDGE_IFACE}
  host IPv4: ${HOST_BRIDGE_IP:-unknown}
  host default gateway: ${HOST_DEFAULT_GW:-unknown}
  host default route iface: ${HOST_DEFAULT_IFACE:-unknown}

Demo networking:
  management IP: ${MGMT_IP}
  client gateway IP: ${CLIENT_GATEWAY_IP}

Release-backed box:
  repository: ${RELEASE_REPO}
  release version: ${RELEASE_VERSION}
  target: ${BOX_TARGET}
  box asset: ${BOX_ASSET_NAME}
  metadata URL: ${BOX_METADATA_URL}

Checks:
  VirtualBox bridged interface access: OK
  Vagrant CLI access: OK
  Release asset access: OK
  SSH key: ${SSH_KEY}
EOF

confirm_launch

(
  cd "${VAGRANT_DIR}"
  NEUWERK_BRIDGED_IFACE="${BRIDGE_IFACE}" \
  NEUWERK_LOCAL_BOX_TARGET="${BOX_TARGET}" \
  NEUWERK_BOX_URL="${BOX_METADATA_URL}" \
    vagrant validate
  NEUWERK_BRIDGED_IFACE="${BRIDGE_IFACE}" \
  NEUWERK_LOCAL_BOX_TARGET="${BOX_TARGET}" \
  NEUWERK_BOX_URL="${BOX_METADATA_URL}" \
    vagrant up --provision
)

HEALTH_URL="https://${MGMT_IP}:8443/health"
if ! wait_for_health "${HEALTH_URL}" 120 1; then
  echo "demo UI did not become healthy at ${HEALTH_URL}" >&2
  exit 1
fi

TOKEN="$(read_admin_token)"

cat <<EOF

Neuwerk demo is ready.

UI:
  https://${MGMT_IP}:8443

Admin token:
${TOKEN}
EOF
