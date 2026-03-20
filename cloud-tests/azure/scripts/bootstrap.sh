#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)
TF_DIR="${TF_DIR:-${ROOT_DIR}/terraform}"
KEY_PATH="${KEY_PATH:-${ROOT_DIR}/../.secrets/ssh/azure_e2e}"
RESOLVE_FW_IPS="${ROOT_DIR}/scripts/resolve-neuwerk-mgmt-ips.sh"

source "${ROOT_DIR}/../common/lib.sh"

require_bin terraform
require_bin az
require_bin jq
require_bin ssh

if [ ! -f "${KEY_PATH}" ]; then
  echo "missing SSH key at ${KEY_PATH}" >&2
  exit 1
fi

pushd "$TF_DIR" >/dev/null
RG=$(terraform output -raw resource_group)
JUMPBOX_IP=$(terraform output -raw jumpbox_public_ip)
popd >/dev/null

if [ -z "$RG" ] || [ -z "$JUMPBOX_IP" ] || [ -z "$FW_VMSS" ]; then
  echo "missing terraform outputs" >&2
  exit 1
fi

wait_ready() {
  local ip="$1"
  local deadline=$((SECONDS + 600))
  while [ $SECONDS -lt $deadline ]; do
    if ssh -o StrictHostKeyChecking=accept-new -i "$KEY_PATH" "ubuntu@${JUMPBOX_IP}" \
      "curl -fsS http://${ip}:8080/ready >/dev/null"; then
      echo "ready: ${ip}"
      return 0
    fi
    sleep 5
  done
  echo "timeout waiting for ${ip}" >&2
  return 1
}

FW_MGMT_IPS=$(TF_DIR="$TF_DIR" "$RESOLVE_FW_IPS")
if [ -z "$FW_MGMT_IPS" ]; then
  echo "no neuwerk management IPs found yet" >&2
  exit 1
fi

for ip in $FW_MGMT_IPS; do
  wait_ready "$ip"
 done

echo "jumpbox: ${JUMPBOX_IP}"
