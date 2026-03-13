#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)
TF_DIR="${TF_DIR:-${ROOT_DIR}/terraform}"
KEY_PATH="${KEY_PATH:-${ROOT_DIR}/../.secrets/ssh/gcp_e2e}"
RESOLVE_FW_IPS="${ROOT_DIR}/scripts/resolve-firewall-mgmt-ips.sh"
COMMON_MATRIX_RUNNER="${ROOT_DIR}/../common/run-throughput-matrix.sh"
CONFIGURE_POLICY_SCRIPT="${ROOT_DIR}/scripts/configure-policy.sh"
POLICY_FILE="${POLICY_FILE:-${ROOT_DIR}/policies/allow-upstream.json}"
SKIP_POLICY="${SKIP_POLICY:-0}"

FW_VCPU="${FW_VCPU:-4}"
ARTIFACT_DIR="${ARTIFACT_DIR:-${ROOT_DIR}/artifacts/throughput-matrix-$(date -u +%Y%m%dT%H%M%SZ)}"

# GCP baseline sizes (overridable)
FIREWALL_INSTANCE_TYPE="${FIREWALL_INSTANCE_TYPE:-n2-standard-4}"
CONSUMER_INSTANCE_TYPE="${CONSUMER_INSTANCE_TYPE:-n2-standard-16}"
UPSTREAM_INSTANCE_TYPE="${UPSTREAM_INSTANCE_TYPE:-n2-standard-16}"

source "${ROOT_DIR}/../common/lib.sh"

require_bin terraform
require_bin gcloud
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

if ! gcloud auth application-default print-access-token >/dev/null 2>&1; then
  echo "gcloud application-default auth required (run: gcloud auth application-default login)" >&2
  exit 1
fi

pushd "$TF_DIR" >/dev/null
PROJECT_ID="$(terraform output -raw project_id 2>/dev/null || true)"
REGION="$(terraform output -raw region 2>/dev/null || true)"
ZONE="$(terraform output -raw zone 2>/dev/null || true)"
JUMPBOX_IP="$(terraform output -raw jumpbox_public_ip)"
UPSTREAM_IP="$(terraform output -raw upstream_private_ip)"
UPSTREAM_VIP="$(terraform output -raw upstream_vip)"
mapfile -t CONSUMERS < <(terraform output -json consumer_private_ips | jq -r '.[]')
INSTANCE_SIZES_JSON="$(terraform output -json instance_sizes 2>/dev/null || echo '{}')"
popd >/dev/null

if [ -z "$JUMPBOX_IP" ] || [ -z "$UPSTREAM_IP" ] || [ "${#CONSUMERS[@]}" -eq 0 ]; then
  echo "missing required terraform outputs for throughput matrix" >&2
  exit 1
fi

FIRST_CONSUMER="${CONSUMERS[0]}"
FW_MGMT_IPS="$(TF_DIR="$TF_DIR" "$RESOLVE_FW_IPS" | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g' | sed 's/^ //; s/ $//')"
if [ -z "$FW_MGMT_IPS" ]; then
  echo "no firewall management IPs resolved" >&2
  exit 1
fi

if [ -n "$INSTANCE_SIZES_JSON" ] && [ "$INSTANCE_SIZES_JSON" != "null" ]; then
  tf_fw="$(echo "$INSTANCE_SIZES_JSON" | jq -r '.firewall // empty' 2>/dev/null || true)"
  tf_consumer="$(echo "$INSTANCE_SIZES_JSON" | jq -r '.consumer // empty' 2>/dev/null || true)"
  tf_upstream="$(echo "$INSTANCE_SIZES_JSON" | jq -r '.upstream // empty' 2>/dev/null || true)"
  [ -n "$tf_fw" ] && FIREWALL_INSTANCE_TYPE="$tf_fw"
  [ -n "$tf_consumer" ] && CONSUMER_INSTANCE_TYPE="$tf_consumer"
  [ -n "$tf_upstream" ] && UPSTREAM_INSTANCE_TYPE="$tf_upstream"
fi

RESOURCE_GROUP="gcp:${PROJECT_ID:-unknown}:${REGION:-unknown}:${ZONE:-unknown}"

if [ "$SKIP_POLICY" != "1" ]; then
  if [ ! -x "$CONFIGURE_POLICY_SCRIPT" ]; then
    echo "missing executable policy script: ${CONFIGURE_POLICY_SCRIPT}" >&2
    exit 1
  fi
  echo "configuring policy from ${POLICY_FILE}"
  TF_DIR="$TF_DIR" KEY_PATH="$KEY_PATH" SSH_USER="${SSH_USER:-ubuntu}" \
    "$CONFIGURE_POLICY_SCRIPT" "$POLICY_FILE"
fi

CLOUD_PROVIDER="gcp" \
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
FIREWALL_INSTANCE_TYPE="$FIREWALL_INSTANCE_TYPE" \
CONSUMER_INSTANCE_TYPE="$CONSUMER_INSTANCE_TYPE" \
UPSTREAM_INSTANCE_TYPE="$UPSTREAM_INSTANCE_TYPE" \
"$COMMON_MATRIX_RUNNER"

echo "gcp throughput matrix artifacts: ${ARTIFACT_DIR}"
