#!/usr/bin/env bash
set -euo pipefail

env_file="__RUNTIME_ENV_FILE__"
if [[ -f "$env_file" ]]; then
  # shellcheck disable=SC1090
  source "$env_file"
fi
if [[ -n "${LD_LIBRARY_PATH:-}" ]]; then
  export LD_LIBRARY_PATH
fi
if [[ -n "${RTE_EAL_PMD_PATH:-}" ]]; then
  export RTE_EAL_PMD_PATH
fi

require_value() {
  local name="$1"
  local value="${!name:-}"
  if [[ -z "$value" ]]; then
    echo "missing required runtime setting: $name" >&2
    exit 1
  fi
}

append_csv_flags() {
  local flag="$1"
  local csv="$2"
  local entry=""
  IFS=',' read -r -a values <<<"$csv"
  for entry in "${values[@]}"; do
    entry="${entry#"${entry%%[![:space:]]*}"}"
    entry="${entry%"${entry##*[![:space:]]}"}"
    if [[ -n "$entry" ]]; then
      args+=("$flag" "$entry")
    fi
  done
}

require_value NEUWERK_MANAGEMENT_INTERFACE
require_value NEUWERK_DATA_PLANE_INTERFACE
require_value NEUWERK_DATA_PLANE_MODE
require_value NEUWERK_DNS_TARGET_IPS
require_value NEUWERK_DNS_UPSTREAMS

binary="__RUNTIME_BINARY_DIR__/firewall"
args=(
  "$binary"
  "--management-interface" "$NEUWERK_MANAGEMENT_INTERFACE"
  "--data-plane-interface" "$NEUWERK_DATA_PLANE_INTERFACE"
  "--data-plane-mode" "${NEUWERK_DATA_PLANE_MODE:-dpdk}"
  "--default-policy" "${NEUWERK_DEFAULT_POLICY:-deny}"
  "--snat" "${NEUWERK_SNAT_MODE:-auto}"
  "--cloud-provider" "${NEUWERK_CLOUD_PROVIDER:-none}"
)

append_csv_flags "--dns-target-ip" "$NEUWERK_DNS_TARGET_IPS"
append_csv_flags "--dns-upstream" "$NEUWERK_DNS_UPSTREAMS"

if [[ -n "${NEUWERK_HTTP_BIND:-}" ]]; then
  args+=("--http-bind" "$NEUWERK_HTTP_BIND")
fi
if [[ -n "${NEUWERK_HTTP_ADVERTISE:-}" ]]; then
  args+=("--http-advertise" "$NEUWERK_HTTP_ADVERTISE")
fi
if [[ -n "${NEUWERK_HTTP_EXTERNAL_URL:-}" ]]; then
  args+=("--http-external-url" "$NEUWERK_HTTP_EXTERNAL_URL")
fi
if [[ -n "${NEUWERK_METRICS_BIND:-}" ]]; then
  args+=("--metrics-bind" "$NEUWERK_METRICS_BIND")
fi
if [[ -n "${NEUWERK_INTERNAL_CIDR:-}" ]]; then
  args+=("--internal-cidr" "$NEUWERK_INTERNAL_CIDR")
fi
if [[ -n "${NEUWERK_INTEGRATION_MODE:-}" ]]; then
  args+=("--integration" "$NEUWERK_INTEGRATION_MODE")
fi
if [[ -n "${NEUWERK_INTEGRATION_ROUTE_NAME:-}" ]]; then
  args+=("--integration-route-name" "$NEUWERK_INTEGRATION_ROUTE_NAME")
fi
if [[ -n "${NEUWERK_INTEGRATION_DRAIN_TIMEOUT_SECS:-}" ]]; then
  args+=("--integration-drain-timeout-secs" "$NEUWERK_INTEGRATION_DRAIN_TIMEOUT_SECS")
fi
if [[ -n "${NEUWERK_INTEGRATION_RECONCILE_INTERVAL_SECS:-}" ]]; then
  args+=("--integration-reconcile-interval-secs" "$NEUWERK_INTEGRATION_RECONCILE_INTERVAL_SECS")
fi
if [[ -n "${NEUWERK_INTEGRATION_CLUSTER_NAME:-}" ]]; then
  args+=("--integration-cluster-name" "$NEUWERK_INTEGRATION_CLUSTER_NAME")
fi
if [[ -n "${NEUWERK_AZURE_SUBSCRIPTION_ID:-}" ]]; then
  args+=("--azure-subscription-id" "$NEUWERK_AZURE_SUBSCRIPTION_ID")
fi
if [[ -n "${NEUWERK_AZURE_RESOURCE_GROUP:-}" ]]; then
  args+=("--azure-resource-group" "$NEUWERK_AZURE_RESOURCE_GROUP")
fi
if [[ -n "${NEUWERK_AZURE_VMSS_NAME:-}" ]]; then
  args+=("--azure-vmss-name" "$NEUWERK_AZURE_VMSS_NAME")
fi
if [[ -n "${NEUWERK_AWS_REGION:-}" ]]; then
  args+=("--aws-region" "$NEUWERK_AWS_REGION")
fi
if [[ -n "${NEUWERK_AWS_VPC_ID:-}" ]]; then
  args+=("--aws-vpc-id" "$NEUWERK_AWS_VPC_ID")
fi
if [[ -n "${NEUWERK_AWS_ASG_NAME:-}" ]]; then
  args+=("--aws-asg-name" "$NEUWERK_AWS_ASG_NAME")
fi
if [[ -n "${NEUWERK_GCP_PROJECT:-}" ]]; then
  args+=("--gcp-project" "$NEUWERK_GCP_PROJECT")
fi
if [[ -n "${NEUWERK_GCP_REGION:-}" ]]; then
  args+=("--gcp-region" "$NEUWERK_GCP_REGION")
fi
if [[ -n "${NEUWERK_GCP_IG_NAME:-}" ]]; then
  args+=("--gcp-ig-name" "$NEUWERK_GCP_IG_NAME")
fi

if [[ -n "${NEUWERK_ENCAP_MODE:-}" ]]; then
  args+=("--encap" "$NEUWERK_ENCAP_MODE")
fi
if [[ -n "${NEUWERK_ENCAP_VNI:-}" ]]; then
  args+=("--encap-vni" "$NEUWERK_ENCAP_VNI")
fi
if [[ -n "${NEUWERK_ENCAP_VNI_INTERNAL:-}" ]]; then
  args+=("--encap-vni-internal" "$NEUWERK_ENCAP_VNI_INTERNAL")
fi
if [[ -n "${NEUWERK_ENCAP_VNI_EXTERNAL:-}" ]]; then
  args+=("--encap-vni-external" "$NEUWERK_ENCAP_VNI_EXTERNAL")
fi
if [[ -n "${NEUWERK_ENCAP_UDP_PORT:-}" ]]; then
  args+=("--encap-udp-port" "$NEUWERK_ENCAP_UDP_PORT")
fi
if [[ -n "${NEUWERK_ENCAP_UDP_PORT_INTERNAL:-}" ]]; then
  args+=("--encap-udp-port-internal" "$NEUWERK_ENCAP_UDP_PORT_INTERNAL")
fi
if [[ -n "${NEUWERK_ENCAP_UDP_PORT_EXTERNAL:-}" ]]; then
  args+=("--encap-udp-port-external" "$NEUWERK_ENCAP_UDP_PORT_EXTERNAL")
fi
if [[ -n "${NEUWERK_ENCAP_MTU:-}" ]]; then
  args+=("--encap-mtu" "$NEUWERK_ENCAP_MTU")
fi

if [[ -n "${NEUWERK_EXTRA_ARGS:-}" ]]; then
  # Intentional shell-style expansion for operator-provided advanced flags.
  # shellcheck disable=SC2206
  extra_args=( ${NEUWERK_EXTRA_ARGS} )
  args+=("${extra_args[@]}")
fi

exec "${args[@]}"
