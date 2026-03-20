#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)
TF_DIR="${TF_DIR:-${ROOT_DIR}/terraform}"
KEY_PATH="${KEY_PATH:-${ROOT_DIR}/../.secrets/ssh/aws_e2e}"
DNS_ZONE="${DNS_ZONE:-upstream.test}"
POLICY_FILE="${POLICY_FILE:-${ROOT_DIR}/policies/allow-upstream.json}"
RESOLVE_FW_IPS="${ROOT_DIR}/scripts/resolve-neuwerk-mgmt-ips.sh"
RUN_THROUGHPUT="${RUN_THROUGHPUT:-1}"
DEFAULT_RUNNER_TESTS="cidr_port_allow,cidr_port_deny,tls_sni_allow,tls_sni_deny,tls13_uninspectable_deny,policy_recheck_existing_flow,metrics_allow_deny_counters,udp_allow_5201,udp_deny_5201,tcp_allow_udp_deny_same_port,udp_policy_swap_allow_to_deny,icmp_echo_allow,icmp_echo_deny,policy_consistency_all_neuwerk_nodes,metrics_protocol_specific_validation,dns_allowlist_allow,dns_allowlist_allow_tcp,dns_allowlist_deny,dns_allowlist_reset_on_rebuild"

if [ -z "${RUNNER_ARGS:-}" ]; then
  RUNNER_ARGS="--tests ${AWS_RUNNER_TESTS:-$DEFAULT_RUNNER_TESTS}"
fi

source "${ROOT_DIR}/../common/lib.sh"

require_bin terraform
require_bin aws
require_bin jq
require_bin ssh

if ! aws sts get-caller-identity >/dev/null 2>&1; then
  echo "aws credentials are required (aws sts get-caller-identity failed)" >&2
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
TRAFFIC_ARCHITECTURE=$(terraform output -raw traffic_architecture)
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

echo "traffic architecture: ${TRAFFIC_ARCHITECTURE}"
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
RUNNER_ARGS="$RUNNER_ARGS" \
"${ROOT_DIR}/../common/run-policy-smoke.sh"

if [ "$RUN_THROUGHPUT" = "1" ]; then
  echo "running explicit throughput check (iperf3)"
  THROUGHPUT_OUT=$(ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$FIRST_CONSUMER" \
    "iperf3 -c ${UPSTREAM_IP} -p 5201 -t ${IPERF_SECS:-20} -P ${IPERF_STREAMS:-4} --connect-timeout 5000")
  echo "$THROUGHPUT_OUT"
fi

echo "instance sizes:"
echo "$INSTANCE_SIZES" | jq .
