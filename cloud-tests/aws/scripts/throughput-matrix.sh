#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)
TF_DIR="${TF_DIR:-${ROOT_DIR}/terraform}"
KEY_PATH="${KEY_PATH:-${ROOT_DIR}/../.secrets/ssh/aws_e2e}"
RESOLVE_FW_IPS="${ROOT_DIR}/scripts/resolve-neuwerk-mgmt-ips.sh"
COMMON_MATRIX_RUNNER="${ROOT_DIR}/../common/run-throughput-matrix.sh"
CONFIGURE_POLICY_SCRIPT="${ROOT_DIR}/scripts/configure-policy.sh"
POLICY_FILE="${POLICY_FILE:-${ROOT_DIR}/policies/allow-upstream.json}"
SKIP_POLICY="${SKIP_POLICY:-0}"

FW_VCPU="${FW_VCPU:-4}"
ARTIFACT_DIR="${ARTIFACT_DIR:-${ROOT_DIR}/artifacts/throughput-matrix-$(date -u +%Y%m%dT%H%M%SZ)}"

# AWS baseline sizes (overridable)
NEUWERK_INSTANCE_TYPE="${NEUWERK_INSTANCE_TYPE:-c6in.xlarge}"
CONSUMER_INSTANCE_TYPE="${CONSUMER_INSTANCE_TYPE:-c6in.4xlarge}"
UPSTREAM_INSTANCE_TYPE="${UPSTREAM_INSTANCE_TYPE:-c6in.4xlarge}"

source "${ROOT_DIR}/../common/lib.sh"

require_bin terraform
require_bin aws
require_bin jq
require_bin ssh

if [ ! -f "$KEY_PATH" ]; then
  echo "missing SSH key at ${KEY_PATH}" >&2
  exit 1
fi

if [ ! -x "$COMMON_MATRIX_RUNNER" ]; then
  echo "missing executable common runner at ${COMMON_MATRIX_RUNNER}" >&2
  exit 1
fi

if ! aws sts get-caller-identity >/dev/null 2>&1; then
  echo "aws credentials are required (aws sts get-caller-identity failed)" >&2
  exit 1
fi

pushd "$TF_DIR" >/dev/null
REGION="$(terraform output -raw region 2>/dev/null || true)"
TRAFFIC_ARCHITECTURE="$(terraform output -raw traffic_architecture 2>/dev/null || true)"
JUMPBOX_IP="$(terraform output -raw jumpbox_public_ip)"
UPSTREAM_IP_DEFAULT="$(terraform output -raw upstream_private_ip)"
UPSTREAM_VIP_DEFAULT="$(terraform output -raw upstream_vip)"
mapfile -t CONSUMERS < <(terraform output -json consumer_private_ips | jq -r '.[]')
INSTANCE_SIZES_JSON="$(terraform output -json instance_sizes 2>/dev/null || echo '{}')"
popd >/dev/null

UPSTREAM_IP="${UPSTREAM_IP_OVERRIDE:-$UPSTREAM_IP_DEFAULT}"
UPSTREAM_VIP="${UPSTREAM_VIP_OVERRIDE:-$UPSTREAM_VIP_DEFAULT}"

if [ -z "$JUMPBOX_IP" ] || [ -z "$UPSTREAM_IP" ] || [ "${#CONSUMERS[@]}" -eq 0 ]; then
  echo "missing required terraform outputs for throughput matrix" >&2
  exit 1
fi

FIRST_CONSUMER="${CONSUMERS[0]}"
FW_MGMT_IPS="$(TF_DIR="$TF_DIR" "$RESOLVE_FW_IPS" | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g' | sed 's/^ //; s/ $//')"
if [ -z "$FW_MGMT_IPS" ]; then
  echo "no neuwerk management IPs resolved" >&2
  exit 1
fi

# Prefer actual deployed sizes from terraform output when present.
if [ -n "$INSTANCE_SIZES_JSON" ] && [ "$INSTANCE_SIZES_JSON" != "null" ]; then
  tf_fw="$(echo "$INSTANCE_SIZES_JSON" | jq -r '.neuwerk // empty' 2>/dev/null || true)"
  tf_consumer="$(echo "$INSTANCE_SIZES_JSON" | jq -r '.consumer // empty' 2>/dev/null || true)"
  tf_upstream="$(echo "$INSTANCE_SIZES_JSON" | jq -r '.upstream // empty' 2>/dev/null || true)"
  [ -n "$tf_fw" ] && NEUWERK_INSTANCE_TYPE="$tf_fw"
  [ -n "$tf_consumer" ] && CONSUMER_INSTANCE_TYPE="$tf_consumer"
  [ -n "$tf_upstream" ] && UPSTREAM_INSTANCE_TYPE="$tf_upstream"
fi

RESOURCE_GROUP="aws:${REGION:-unknown}:${TRAFFIC_ARCHITECTURE:-unknown}"

if [ "$SKIP_POLICY" != "1" ]; then
  if [ ! -x "$CONFIGURE_POLICY_SCRIPT" ]; then
    echo "missing executable policy script: ${CONFIGURE_POLICY_SCRIPT}" >&2
    exit 1
  fi
  echo "configuring policy from ${POLICY_FILE}"
  TF_DIR="$TF_DIR" KEY_PATH="$KEY_PATH" SSH_USER="${SSH_USER:-ubuntu}" \
    "$CONFIGURE_POLICY_SCRIPT" "$POLICY_FILE"
fi

CLOUD_PROVIDER="aws" \
ARTIFACT_DIR="$ARTIFACT_DIR" \
FW_VCPU="$FW_VCPU" \
JUMPBOX_IP="$JUMPBOX_IP" \
CONSUMER_IP="$FIRST_CONSUMER" \
UPSTREAM_IP="$UPSTREAM_IP" \
UPSTREAM_VIP="$UPSTREAM_VIP" \
FW_MGMT_IPS="$FW_MGMT_IPS" \
KEY_PATH="$KEY_PATH" \
SSH_USER="${SSH_USER:-ubuntu}" \
RESOURCE_GROUP="$RESOURCE_GROUP" \
NEUWERK_INSTANCE_TYPE="$NEUWERK_INSTANCE_TYPE" \
CONSUMER_INSTANCE_TYPE="$CONSUMER_INSTANCE_TYPE" \
UPSTREAM_INSTANCE_TYPE="$UPSTREAM_INSTANCE_TYPE" \
CLIENT_BIND_IP="${CLIENT_BIND_IP:-}" \
"$COMMON_MATRIX_RUNNER"

echo "aws throughput matrix artifacts: ${ARTIFACT_DIR}"
