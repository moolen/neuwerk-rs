#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)
TF_DIR="${TF_DIR:-${ROOT_DIR}/terraform}"
KEY_PATH="${KEY_PATH:-${ROOT_DIR}/../.secrets/ssh/azure_e2e}"
RESOLVE_FW_IPS="${ROOT_DIR}/scripts/resolve-neuwerk-mgmt-ips.sh"
OFFSET="${OFFSET:-30m}"
ARTIFACT_DIR="${ARTIFACT_DIR:-${ROOT_DIR}/artifacts/probe-debug-$(date -u +%Y%m%dT%H%M%SZ)}"

source "${ROOT_DIR}/../common/lib.sh"

require_bin terraform
require_bin az
require_bin jq
require_bin ssh

mkdir -p "${ARTIFACT_DIR}"

pushd "$TF_DIR" >/dev/null
RG=$(terraform output -raw resource_group)
JUMPBOX_IP=$(terraform output -raw jumpbox_public_ip)
popd >/dev/null

FW_MGMT_IPS=$(TF_DIR="$TF_DIR" "$RESOLVE_FW_IPS")
if [ -z "$FW_MGMT_IPS" ]; then
  echo "no neuwerk management IPs resolved" >&2
  exit 1
fi

LB_JSON=$(az network lb list -g "$RG" --query "[?contains(name,'dataplane-lb')]|[0]" -o json)
LB_ID=$(echo "$LB_JSON" | jq -r '.id // empty')
LB_NAME=$(echo "$LB_JSON" | jq -r '.name // empty')
if [ -z "$LB_ID" ] || [ -z "$LB_NAME" ]; then
  echo "failed to resolve dataplane LB in ${RG}" >&2
  exit 1
fi

echo "resource_group=${RG}" | tee "${ARTIFACT_DIR}/summary.txt"
echo "jumpbox_ip=${JUMPBOX_IP}" | tee -a "${ARTIFACT_DIR}/summary.txt"
echo "dataplane_lb_name=${LB_NAME}" | tee -a "${ARTIFACT_DIR}/summary.txt"
echo "dataplane_lb_id=${LB_ID}" | tee -a "${ARTIFACT_DIR}/summary.txt"

for ip in $FW_MGMT_IPS; do
  out="${ARTIFACT_DIR}/${ip}.probe.txt"
  {
    ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$ip" \
      "set -euo pipefail
       echo \"== host ==\"
       hostname -f || hostname
       echo \"== timestamp_utc ==\"
       date -u +%Y-%m-%dT%H:%M:%SZ
       echo \"== neuwerk_cmdline ==\"
       tr '\\0' ' ' </proc/\$(pgrep -x neuwerk | head -n1)/cmdline || true
       echo
       echo \"== listeners_8080_8443 ==\"
       ss -lntp | egrep '(:8080|:8443)|State' || true
       echo \"== route_168_63_129_16 ==\"
       ip route get 168.63.129.16 || true
       echo \"== ip_brief ==\"
       ip -br a || true
       echo \"== neuwerk_config ==\"
       sudo cat /etc/neuwerk/config.yaml || true
      "
    echo "== probe_metrics =="
    fetch_neuwerk_metrics "$JUMPBOX_IP" "$KEY_PATH" "$ip" \
      | egrep '^dpdk_health_probe_packets_total|^dpdk_(rx|tx)_(packets|bytes)_total' || true
  } >"$out"
  echo "wrote ${out}"
done

az monitor metrics list \
  --resource "$LB_ID" \
  --metric DipAvailability \
  --interval PT1M \
  --aggregation Average \
  --offset "$OFFSET" \
  --query "value[0].timeseries[0].data[].{timestamp:timeStamp,average:average}" \
  -o tsv > "${ARTIFACT_DIR}/dip-availability.tsv"

echo "wrote ${ARTIFACT_DIR}/dip-availability.tsv"
echo "artifacts=${ARTIFACT_DIR}"
