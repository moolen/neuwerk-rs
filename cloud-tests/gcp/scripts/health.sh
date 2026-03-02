#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)
TF_DIR="${TF_DIR:-${ROOT_DIR}/terraform}"
KEY_PATH="${KEY_PATH:-${ROOT_DIR}/../.secrets/ssh/gcp_e2e}"
RESOLVE_FW_IPS="${ROOT_DIR}/scripts/resolve-firewall-mgmt-ips.sh"

source "${ROOT_DIR}/../common/lib.sh"

require_bin terraform
require_bin gcloud
require_bin jq
require_bin ssh
require_bin ssh-keygen

if ! gcloud auth application-default print-access-token >/dev/null 2>&1; then
  echo "gcloud application-default auth required (run: gcloud auth application-default login)" >&2
  exit 1
fi

if [ ! -f "$KEY_PATH" ]; then
  echo "missing SSH key at ${KEY_PATH}" >&2
  exit 1
fi

pushd "$TF_DIR" >/dev/null
JUMPBOX_IP=$(terraform output -raw jumpbox_public_ip)
popd >/dev/null

if [ -z "$JUMPBOX_IP" ]; then
  echo "missing jumpbox_public_ip output" >&2
  exit 1
fi

ssh-keygen -R "$JUMPBOX_IP" >/dev/null 2>&1 || true

FW_MGMT_IPS=$(TF_DIR="$TF_DIR" "$RESOLVE_FW_IPS")

for ip in $FW_MGMT_IPS; do
  echo "checking ${ip}"
  ssh-keygen -R "$ip" >/dev/null 2>&1 || true
  ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -o IdentitiesOnly=yes -i "$KEY_PATH" "${SSH_USER:-ubuntu}@${JUMPBOX_IP}" \
    "curl -skf --connect-timeout 5 --max-time 10 https://${ip}:8443/health >/dev/null"
  ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -o IdentitiesOnly=yes -i "$KEY_PATH" "${SSH_USER:-ubuntu}@${JUMPBOX_IP}" \
    "curl -skf --connect-timeout 5 --max-time 10 https://${ip}:8443/ready >/dev/null"
  echo "ok: ${ip}"
 done
