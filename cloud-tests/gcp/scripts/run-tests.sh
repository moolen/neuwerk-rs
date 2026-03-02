#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)
TF_DIR="${TF_DIR:-${ROOT_DIR}/terraform}"
KEY_PATH="${KEY_PATH:-${ROOT_DIR}/../.secrets/ssh/gcp_e2e}"
DNS_ZONE="${DNS_ZONE:-upstream.test}"
POLICY_FILE="${POLICY_FILE:-${ROOT_DIR}/policies/allow-upstream.json}"
RESOLVE_FW_IPS="${ROOT_DIR}/scripts/resolve-firewall-mgmt-ips.sh"

source "${ROOT_DIR}/../common/lib.sh"

require_bin terraform
require_bin gcloud
require_bin jq
require_bin ssh

if ! gcloud auth application-default print-access-token >/dev/null 2>&1; then
  echo "gcloud application-default auth required (run: gcloud auth application-default login)" >&2
  exit 1
fi

if [ ! -f "$KEY_PATH" ]; then
  echo "missing SSH key at ${KEY_PATH}" >&2
  exit 1
fi

if [ "${SKIP_POLICY:-}" != "1" ]; then
  export TF_DIR KEY_PATH
  echo "configuring policy from ${POLICY_FILE}"
  "${ROOT_DIR}/scripts/configure-policy.sh" "${POLICY_FILE}"
fi

pushd "$TF_DIR" >/dev/null
JUMPBOX_IP=$(terraform output -raw jumpbox_public_ip)
UPSTREAM_VIP=$(terraform output -raw upstream_vip)
UPSTREAM_IP=$(terraform output -raw upstream_private_ip)
CONSUMERS=$(terraform output -json consumer_private_ips | jq -r '.[]')
INSTANCE_SIZES=$(terraform output -json instance_sizes)
popd >/dev/null

FW_MGMT_IPS=$(TF_DIR="$TF_DIR" "$RESOLVE_FW_IPS" | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g' | sed 's/^ //; s/ $//')
FW_MGMT_IP=$(echo "$FW_MGMT_IPS" | awk '{print $1}')
DNS_TARGET="${DNS_TARGET:-$FW_MGMT_IP}"
UPSTREAM_UDP_TARGET="${UPSTREAM_UDP_TARGET:-$UPSTREAM_IP}"

if [ -z "$CONSUMERS" ]; then
  echo "no consumer IPs found" >&2
  exit 1
fi

FIRST_CONSUMER=$(echo "$CONSUMERS" | head -n1)

echo "running shared cloud policy smoke"
JUMPBOX_IP="$JUMPBOX_IP" \
CONSUMER_IP="$FIRST_CONSUMER" \
FW_MGMT_IP="$FW_MGMT_IP" \
FW_MGMT_IPS="$FW_MGMT_IPS" \
UPSTREAM_VIP="$UPSTREAM_VIP" \
UPSTREAM_IP="$UPSTREAM_IP" \
DNS_SERVER="$DNS_TARGET" \
DNS_ZONE="$DNS_ZONE" \
UPSTREAM_UDP_TARGET="$UPSTREAM_UDP_TARGET" \
KEY_PATH="$KEY_PATH" \
SSH_USER="${SSH_USER:-ubuntu}" \
LONG_THROUGHPUT="${LONG_THROUGHPUT:-0}" \
"${ROOT_DIR}/../common/run-policy-smoke.sh"

echo "running explicit throughput check (iperf3)"
THROUGHPUT_OUT=$(ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$FIRST_CONSUMER" \
  "iperf3 -c ${UPSTREAM_IP} -p 5201 -t ${IPERF_SECS:-20} -P ${IPERF_STREAMS:-4} --connect-timeout 5000")

echo "$THROUGHPUT_OUT"

echo "instance sizes:"
echo "$INSTANCE_SIZES" | jq .
