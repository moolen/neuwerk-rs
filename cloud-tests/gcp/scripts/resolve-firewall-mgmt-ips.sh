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
require_bin gcloud
require_bin jq

if ! gcloud auth application-default print-access-token >/dev/null 2>&1; then
  echo "gcloud application-default auth required (run: gcloud auth application-default login)" >&2
  exit 1
fi

pushd "$TF_DIR" >/dev/null
PROJECT=$(terraform output -raw project_id 2>/dev/null || true)
ZONE=$(terraform output -raw zone 2>/dev/null || true)
FW_IGM=$(terraform output -json firewall_igm 2>/dev/null | jq -r '.name // empty')
MGMT_SUBNET=$(terraform output -raw mgmt_subnet_name 2>/dev/null || true)
popd >/dev/null

if [ -z "$PROJECT" ] || [ -z "$ZONE" ] || [ -z "$FW_IGM" ]; then
  echo "missing terraform outputs for project_id/zone/firewall_igm" >&2
  exit 1
fi

instances=$(gcloud compute instance-groups managed list-instances "$FW_IGM" \
  --project "$PROJECT" \
  --zone "$ZONE" \
  --filter='instanceStatus=RUNNING' \
  --format='value(name)' 2>/dev/null || true)

if [ -z "$instances" ]; then
  echo "no firewall instances found in MIG $FW_IGM" >&2
  exit 1
fi

ips=""
for name in $instances; do
  desc=$(gcloud compute instances describe "$name" \
    --project "$PROJECT" \
    --zone "$ZONE" \
    --format=json)

  ip=$(echo "$desc" | jq -r --arg subnet "$MGMT_SUBNET" '
    .networkInterfaces[]
    | select((.subnetwork // "") | endswith("/" + $subnet))
    | .networkIP
  ' | head -n1)

  if [ -z "$ip" ] || [ "$ip" = "null" ]; then
    ip=$(echo "$desc" | jq -r '.networkInterfaces[1].networkIP // empty')
  fi

  if [ -n "$ip" ]; then
    ips+="$ip\n"
  fi
 done

ips=$(printf "%b" "$ips" | awk 'NF' | sort -u)
if [ -z "$ips" ]; then
  echo "no firewall management IPs found" >&2
  exit 1
fi

printf "%s\n" "$ips"
