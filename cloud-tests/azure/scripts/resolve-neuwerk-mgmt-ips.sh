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
require_bin az
require_bin jq
require_bin python3

if ! az account show >/dev/null 2>&1; then
  echo "az login required" >&2
  exit 1
fi

pushd "$TF_DIR" >/dev/null
RG=$(terraform output -raw resource_group 2>/dev/null || true)
FW_VMSS="$(
  {
    terraform output -json neuwerk_vmss 2>/dev/null \
      || terraform output -json firewall_vmss 2>/dev/null \
      || true
  } | jq -r '.name // empty' 2>/dev/null || true
)"
MGMT_SUBNET_ID=$(terraform output -raw mgmt_subnet_id 2>/dev/null || true)
MGMT_SUBNET_CIDR=$(terraform output -raw mgmt_subnet_cidr 2>/dev/null || true)
popd >/dev/null

if [ -z "$RG" ] || [ -z "$FW_VMSS" ] || [ "$FW_VMSS" = "null" ]; then
  echo "missing terraform outputs for neuwerk_vmss/resource_group" >&2
  exit 1
fi

filter_prefix() {
  local prefix="$1"
  if [ -z "$prefix" ] || [ "$prefix" = "null" ]; then
    cat
    return 0
  fi
  MGMT_PREFIX="$prefix" python3 -c $'import ipaddress, os, sys\nprefix=os.environ.get("MGMT_PREFIX") or ""\ntry:\n    net=ipaddress.ip_network(prefix, strict=False)\nexcept ValueError:\n    net=None\nfor token in sys.stdin.read().split():\n    try:\n        ip=ipaddress.ip_address(token)\n    except ValueError:\n        continue\n    if net is None or ip in net:\n        print(ip)'
}

ips=""

if az vmss list-instance-connection-info -g "$RG" -n "$FW_VMSS" -o json >/dev/null 2>&1; then
  ips=$(az vmss list-instance-connection-info -g "$RG" -n "$FW_VMSS" -o json 2>/dev/null | \
    jq -r '.[]? | .privateIpAddress // empty' | sort -u || true)
fi

if [ -z "$ips" ]; then
  ips=$(az vmss nic list -g "$RG" --vmss-name "$FW_VMSS" -o json 2>/dev/null | \
    jq -r '.[] | .ipConfigurations[]? | select(.name=="mgmt-ipcfg" or .primary==true) | .privateIPAddress' | sort -u || true)
fi

if [ -z "$ips" ] && [ -n "$MGMT_SUBNET_ID" ] && [ "$MGMT_SUBNET_ID" != "null" ]; then
  ips=$(az network nic list -g "$RG" -o json | \
    jq -r --arg subnet "$MGMT_SUBNET_ID" '.[] | .ipConfigurations[]? | select(.subnet.id == $subnet) | .privateIPAddress' | sort -u)
fi

if [ -z "$ips" ]; then
  ips=$(az network nic list -g "$RG" -o json | \
    jq -r --arg vmss "$FW_VMSS" '.[] | select((.virtualMachine.id? // "" | contains($vmss)) or (.name? // "" | contains("mgmt0")) or (.name? // "" | contains($vmss))) | .ipConfigurations[]? | select(.name=="mgmt-ipcfg" or .primary==true) | .privateIPAddress' | sort -u)
fi

if [ -z "$ips" ]; then
  ips=$(az network nic list -g "$RG" -o json | \
    jq -r '.[] | select((.name? // "" | contains("mgmt0")) or (.tags["neuwerk.io.management"]=="true") or (.tags["neuwerk.io/management"]=="true")) | .ipConfigurations[]? | select(.name=="mgmt-ipcfg" or .primary==true) | .privateIPAddress' | sort -u)
fi

if [ -z "$ips" ] && [ -n "$MGMT_SUBNET_CIDR" ] && [ "$MGMT_SUBNET_CIDR" != "null" ]; then
  ips=$(az vm list-ip-addresses -g "$RG" -o json | \
    jq -r --arg vmss "$FW_VMSS" '.[] | select(.virtualMachine.name? // "" | startswith($vmss)) | .virtualMachine.network.privateIpAddresses[]?' | \
    filter_prefix "$MGMT_SUBNET_CIDR" | sort -u)
fi

if [ -n "$MGMT_SUBNET_CIDR" ] && [ "$MGMT_SUBNET_CIDR" != "null" ] && [ -n "$ips" ]; then
  ips=$(printf "%s\n" "$ips" | filter_prefix "$MGMT_SUBNET_CIDR" | sort -u)
fi

if [ -z "$ips" ]; then
  echo "no neuwerk management IPs found" >&2
  exit 1
fi

printf "%s\n" "$ips"
