#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)
TF_DIR="${TF_DIR:-${ROOT_DIR}/terraform}"
KEY_PATH="${KEY_PATH:-${ROOT_DIR}/../.secrets/ssh/azure_e2e}"
RESOLVE_FW_IPS="${ROOT_DIR}/scripts/resolve-firewall-mgmt-ips.sh"
COMMON_RUN="${ROOT_DIR}/../common/http-perf-run.sh"
COMMON_SETUP="${ROOT_DIR}/../common/http-perf-setup.sh"
COMMON_COLLECT="${ROOT_DIR}/../common/http-perf-collect.sh"
K6_SCRIPT_LOCAL="${K6_SCRIPT_LOCAL:-${ROOT_DIR}/../common/http-perf/k6/webhook.js}"
POLICY_DIR="${POLICY_DIR:-${ROOT_DIR}/policies/http-perf}"
CONFIGURE_POLICY_SCRIPT="${CONFIGURE_POLICY_SCRIPT:-${ROOT_DIR}/scripts/configure-policy.sh}"
MINT_API_TOKEN="${MINT_API_TOKEN:-${ROOT_DIR}/scripts/mint-api-token.sh}"

source "${ROOT_DIR}/../common/lib.sh"

require_bin terraform
require_bin az
require_bin jq
require_bin ssh

if [ ! -f "$KEY_PATH" ]; then
  echo "missing SSH key at ${KEY_PATH}" >&2
  exit 1
fi
if [ ! -x "$COMMON_RUN" ]; then
  echo "missing executable common run script: ${COMMON_RUN}" >&2
  exit 1
fi
az account show >/dev/null 2>&1 || {
  echo "az login required" >&2
  exit 1
}

pushd "$TF_DIR" >/dev/null
RESOURCE_GROUP="$(terraform output -raw resource_group 2>/dev/null || echo unknown)"
JUMPBOX_IP="$(terraform output -raw jumpbox_public_ip)"
UPSTREAM_VIP="$(terraform output -raw upstream_vip)"
UPSTREAM_IP="$(terraform output -raw upstream_private_ip)"
mapfile -t CONSUMERS < <(terraform output -json consumer_private_ips | jq -r '.[]')
CONSUMER_LOCAL_IPS_JSON="$(terraform output -json consumer_all_private_ips 2>/dev/null | jq -c . 2>/dev/null || true)"
popd >/dev/null

if [ -z "$JUMPBOX_IP" ] || [ -z "$UPSTREAM_VIP" ] || [ -z "$UPSTREAM_IP" ] || [ "${#CONSUMERS[@]}" -eq 0 ]; then
  echo "missing terraform outputs for run context" >&2
  exit 1
fi

FW_MGMT_IPS="$(TF_DIR="$TF_DIR" "$RESOLVE_FW_IPS" | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g' | sed 's/^ //; s/ $//')"
CONSUMER_IPS="$(printf '%s ' "${CONSUMERS[@]}")"
if ! jq -e --argjson count "${#CONSUMERS[@]}" 'type == "array" and length == $count' <<<"${CONSUMER_LOCAL_IPS_JSON:-}" >/dev/null 2>&1; then
  CONSUMER_LOCAL_IPS_JSON=""
fi
REGION="$(az group show -n "$RESOURCE_GROUP" --query location -o tsv 2>/dev/null || echo unknown)"

JUMPBOX_IP="$JUMPBOX_IP" \
UPSTREAM_VIP="$UPSTREAM_VIP" \
UPSTREAM_IP="$UPSTREAM_IP" \
CONSUMER_IPS="$CONSUMER_IPS" \
CONSUMER_LOCAL_IPS_JSON="$CONSUMER_LOCAL_IPS_JSON" \
FW_MGMT_IPS="$FW_MGMT_IPS" \
KEY_PATH="$KEY_PATH" \
DNS_ZONE="${DNS_ZONE:-upstream.test}" \
SSH_USER="${SSH_USER:-ubuntu}" \
CLOUD_PROVIDER="azure" \
SCENARIO="${SCENARIO:-http_l34_allow}" \
RPS="${RPS:-500}" \
RAMP_SECONDS="${RAMP_SECONDS:-30}" \
STEADY_SECONDS="${STEADY_SECONDS:-45}" \
PAYLOAD_BYTES="${PAYLOAD_BYTES:-32768}" \
CONNECTION_MODE="${CONNECTION_MODE:-keep_alive}" \
SKIP_SETUP="${SKIP_SETUP:-0}" \
ARTIFACT_DIR="${ARTIFACT_DIR:-${ROOT_DIR}/artifacts/http-perf-${SCENARIO:-http_l34_allow}-$(date -u +%Y%m%dT%H%M%SZ)}" \
SETUP_SCRIPT="$COMMON_SETUP" \
COLLECT_SCRIPT="$COMMON_COLLECT" \
K6_SCRIPT_LOCAL="$K6_SCRIPT_LOCAL" \
POLICY_DIR="$POLICY_DIR" \
CONFIGURE_POLICY_SCRIPT="$CONFIGURE_POLICY_SCRIPT" \
MINT_API_TOKEN="$MINT_API_TOKEN" \
REGION="$REGION" \
RESOURCE_GROUP="$RESOURCE_GROUP" \
FW_INSTANCE_TYPE="${FW_INSTANCE_TYPE:-unknown}" \
CONSUMER_INSTANCE_TYPE="${CONSUMER_INSTANCE_TYPE:-unknown}" \
UPSTREAM_INSTANCE_TYPE="${UPSTREAM_INSTANCE_TYPE:-unknown}" \
"$COMMON_RUN"
