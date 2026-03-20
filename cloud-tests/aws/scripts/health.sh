#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)
TF_DIR="${TF_DIR:-${ROOT_DIR}/terraform}"
KEY_PATH="${KEY_PATH:-${ROOT_DIR}/../.secrets/ssh/aws_e2e}"
RESOLVE_FW_IPS="${ROOT_DIR}/scripts/resolve-neuwerk-mgmt-ips.sh"

source "${ROOT_DIR}/../common/lib.sh"

require_bin terraform
require_bin aws
require_bin ssh
require_bin ssh-keygen

if ! aws sts get-caller-identity >/dev/null 2>&1; then
  echo "aws credentials are required (aws sts get-caller-identity failed)" >&2
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

FW_MGMT_IPS=$(TF_DIR="$TF_DIR" "$RESOLVE_FW_IPS")
HEALTH_RETRIES="${HEALTH_RETRIES:-80}"
HEALTH_SLEEP_SECS="${HEALTH_SLEEP_SECS:-15}"

for ip in $FW_MGMT_IPS; do
  echo "checking $ip"
  ok=0
  for attempt in $(seq 1 "$HEALTH_RETRIES"); do
    if ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$ip" "curl -skf https://${ip}:8443/health >/dev/null" \
      && ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$ip" "curl -skf https://${ip}:8443/ready >/dev/null"; then
      ok=1
      break
    fi
    sleep "$HEALTH_SLEEP_SECS"
  done
  if [ "$ok" -ne 1 ]; then
    echo "health/ready check failed for ${ip} after ${HEALTH_RETRIES} attempts" >&2
    exit 1
  fi
  echo "ok: $ip"
done
