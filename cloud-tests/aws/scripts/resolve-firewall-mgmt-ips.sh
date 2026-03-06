#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)
TF_DIR="${TF_DIR:-${ROOT_DIR}/terraform}"

require_bin() {
  local bin="$1"
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo "missing required binary: $bin" >&2
    exit 1
  fi
}

require_bin terraform
require_bin aws
require_bin jq

if ! aws sts get-caller-identity >/dev/null 2>&1; then
  echo "aws credentials are required (aws sts get-caller-identity failed)" >&2
  exit 1
fi

pushd "$TF_DIR" >/dev/null
VPC_ID=$(terraform output -raw vpc_id 2>/dev/null || true)
IPS_JSON=$(terraform output -json firewall_mgmt_ips 2>/dev/null || true)
popd >/dev/null

ips=""
if [ -n "$IPS_JSON" ] && [ "$IPS_JSON" != "null" ]; then
  ips=$(echo "$IPS_JSON" | jq -r '.[]?' | awk 'NF' | sort -u || true)
fi

if [ -z "$ips" ] && [ -n "$VPC_ID" ]; then
  ips=$(aws ec2 describe-network-interfaces \
    --filters \
      "Name=vpc-id,Values=${VPC_ID}" \
      "Name=tag:neuwerk.io/management,Values=true" \
      "Name=status,Values=in-use" \
    --query 'NetworkInterfaces[].PrivateIpAddress' \
    --output text 2>/dev/null | tr '\t' '\n' | awk 'NF' | sort -u || true)
fi

if [ -z "$ips" ]; then
  echo "no firewall management IPs found" >&2
  exit 1
fi

printf "%s\n" "$ips"
