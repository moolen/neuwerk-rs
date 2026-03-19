#!/usr/bin/env bash
set -euo pipefail

runtime_env_file="__RUNTIME_ENV_FILE__"
appliance_env_file="__APPLIANCE_ENV_FILE__"
runtime_prefix="__RUNTIME_PREFIX__"
passthrough_tmp=""

cleanup() {
  if [[ -n "$passthrough_tmp" && -f "$passthrough_tmp" ]]; then
    rm -f "$passthrough_tmp"
  fi
}
trap cleanup EXIT

if [[ -f "$appliance_env_file" ]]; then
  # shellcheck disable=SC1090
  source "$appliance_env_file"
fi

trim() {
  local value="${1:-}"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s\n' "$value"
}

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

metadata_get() {
  local provider="$1"
  local path="$2"
  case "$provider" in
    aws)
      local token=""
      token="$(
        curl -fsS -X PUT "http://169.254.169.254/latest/api/token" \
          -H "X-aws-ec2-metadata-token-ttl-seconds: 60" \
          --connect-timeout 1 \
          --max-time 2 2>/dev/null || true
      )"
      if [[ -z "$token" ]]; then
        return 1
      fi
      curl -fsS \
        -H "X-aws-ec2-metadata-token: $token" \
        --connect-timeout 1 \
        --max-time 2 \
        "http://169.254.169.254/latest/${path}"
      ;;
    azure)
      curl -fsS \
        -H "Metadata: true" \
        --connect-timeout 1 \
        --max-time 2 \
        "http://169.254.169.254/metadata/${path}"
      ;;
    gcp)
      curl -fsS \
        -H "Metadata-Flavor: Google" \
        --connect-timeout 1 \
        --max-time 2 \
        "http://169.254.169.254/computeMetadata/v1/${path}"
      ;;
    *)
      return 1
      ;;
  esac
}

detect_cloud_provider() {
  if [[ -n "${NEUWERK_BOOTSTRAP_CLOUD_PROVIDER:-}" ]]; then
    printf '%s\n' "$(trim "$NEUWERK_BOOTSTRAP_CLOUD_PROVIDER" | tr '[:upper:]' '[:lower:]')"
    return 0
  fi
  if metadata_get azure "instance?api-version=2021-02-01" >/dev/null 2>&1; then
    printf 'azure\n'
    return 0
  fi
  if metadata_get gcp "instance/id" >/dev/null 2>&1; then
    printf 'gcp\n'
    return 0
  fi
  if metadata_get aws "meta-data/instance-id" >/dev/null 2>&1; then
    printf 'aws\n'
    return 0
  fi
  printf 'none\n'
}

iface_exists() {
  local iface="$1"
  ip link show "$iface" >/dev/null 2>&1
}

default_route_iface() {
  ip -4 route show default 2>/dev/null | awk '{print $5; exit}'
}

first_non_loopback_iface() {
  ip -o link show | awk -F': ' '$2 != "lo" {print $2}' | cut -d@ -f1 | head -n1
}

second_non_loopback_iface() {
  local skip="$1"
  ip -o link show | awk -F': ' '$2 != "lo" {print $2}' | cut -d@ -f1 | while read -r iface; do
    if [[ "$iface" != "$skip" ]]; then
      printf '%s\n' "$iface"
      break
    fi
  done
}

resolve_management_iface() {
  if [[ -n "${NEUWERK_BOOTSTRAP_MANAGEMENT_INTERFACE:-}" ]]; then
    printf '%s\n' "$(trim "$NEUWERK_BOOTSTRAP_MANAGEMENT_INTERFACE")"
    return 0
  fi
  if iface_exists "mgmt0"; then
    printf 'mgmt0\n'
    return 0
  fi
  local iface=""
  iface="$(default_route_iface || true)"
  if [[ -n "$iface" ]]; then
    printf '%s\n' "$iface"
    return 0
  fi
  first_non_loopback_iface
}

resolve_dataplane_iface() {
  local mgmt_iface="$1"
  if [[ -n "${NEUWERK_BOOTSTRAP_DATA_INTERFACE:-}" ]]; then
    printf '%s\n' "$(trim "$NEUWERK_BOOTSTRAP_DATA_INTERFACE")"
    return 0
  fi
  if iface_exists "data0" && [[ "data0" != "$mgmt_iface" ]]; then
    printf 'data0\n'
    return 0
  fi
  second_non_loopback_iface "$mgmt_iface"
}

iface_ipv4() {
  local iface="$1"
  ip -4 -o addr show dev "$iface" scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1
}

iface_mac() {
  local iface="$1"
  cat "/sys/class/net/$iface/address" 2>/dev/null | tr '[:upper:]' '[:lower:]'
}

iface_driver() {
  local iface="$1"
  readlink -f "/sys/class/net/$iface/device/driver" 2>/dev/null | awk -F/ '{print $NF}'
}

resolve_data_plane_mode() {
  printf '%s\n' "$(trim "${NEUWERK_BOOTSTRAP_DATA_PLANE_MODE:-dpdk}")"
}

resolve_data_plane_selector() {
  local provider="$1"
  local data_iface="$2"
  local mode="$3"
  if [[ -n "${NEUWERK_BOOTSTRAP_DATA_PLANE_SELECTOR:-}" ]]; then
    printf '%s\n' "$(trim "$NEUWERK_BOOTSTRAP_DATA_PLANE_SELECTOR")"
    return 0
  fi
  if [[ "$mode" != "dpdk" ]]; then
    printf '%s\n' "$data_iface"
    return 0
  fi
  local driver=""
  local mac=""
  driver="$(iface_driver "$data_iface" || true)"
  mac="$(iface_mac "$data_iface" || true)"
  if [[ "$provider" == "azure" || "$driver" == "hv_netvsc" || "$driver" == "mana" ]]; then
    if [[ -n "$mac" ]]; then
      printf 'mac:%s\n' "$mac"
      return 0
    fi
  fi
  printf '%s\n' "$data_iface"
}

resolve_dns_target_ips() {
  local mgmt_ip="$1"
  if [[ -n "${NEUWERK_BOOTSTRAP_DNS_TARGET_IPS:-}" ]]; then
    printf '%s\n' "$(trim "$NEUWERK_BOOTSTRAP_DNS_TARGET_IPS")"
    return 0
  fi
  printf '%s\n' "$mgmt_ip"
}

resolve_dns_upstreams() {
  if [[ -n "${NEUWERK_BOOTSTRAP_DNS_UPSTREAMS:-}" ]]; then
    printf '%s\n' "$(trim "$NEUWERK_BOOTSTRAP_DNS_UPSTREAMS")"
    return 0
  fi
  awk '
    $1 == "nameserver" && $2 !~ /^127\./ && $2 != "::1" {
      if (!seen[$2]++) {
        entries[++count] = $2 ":53"
      }
    }
    END {
      for (idx = 1; idx <= count; idx++) {
        printf "%s%s", entries[idx], (idx < count ? "," : "")
      }
      printf "\n"
    }
  ' /etc/resolv.conf
}

resolve_bootstrap_default() {
  local value="$1"
  local fallback="$2"
  if [[ -n "$value" ]]; then
    printf '%s\n' "$(trim "$value")"
  else
    printf '%s\n' "$fallback"
  fi
}

write_passthrough_env() {
  local excluded_regex='^(NEUWERK_MANAGEMENT_INTERFACE|NEUWERK_DATA_PLANE_INTERFACE|NEUWERK_DATA_PLANE_MODE|NEUWERK_DNS_TARGET_IPS|NEUWERK_DNS_UPSTREAMS|NEUWERK_DEFAULT_POLICY|NEUWERK_SNAT_MODE|NEUWERK_CLOUD_PROVIDER|NEUWERK_HTTP_BIND|NEUWERK_METRICS_BIND|MGMT_IP|NEUWERK_RUNTIME_PREFIX|NEUWERK_DPDK_VERSION|LD_LIBRARY_PATH|RTE_EAL_PMD_PATH)='
  if [[ ! -f "$appliance_env_file" ]]; then
    return 0
  fi
  passthrough_tmp="$(mktemp)"
  awk '
    /^[[:space:]]*#/ { next }
    /^[[:space:]]*$/ { next }
    /^[[:space:]]*NEUWERK_BOOTSTRAP_/ { next }
    /^[[:space:]]*export[[:space:]]+/ { sub(/^[[:space:]]*export[[:space:]]+/, "", $0) }
    /^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*=/ { print }
  ' "$appliance_env_file" | while IFS= read -r line; do
    line="$(trim "$line")"
    if [[ -n "$line" && ! "$line" =~ $excluded_regex ]]; then
      printf '%s\n' "$line" >>"$passthrough_tmp"
    fi
  done
}

main() {
  local provider=""
  local mgmt_iface=""
  local data_iface=""
  local mgmt_ip=""
  local data_mode=""
  local data_selector=""
  local dns_target_ips=""
  local dns_upstreams=""
  local default_policy=""
  local snat_mode=""
  local http_bind=""
  local metrics_bind=""

  provider="$(detect_cloud_provider)"
  mgmt_iface="$(resolve_management_iface)"
  if [[ -z "$mgmt_iface" || ! -d "/sys/class/net/$mgmt_iface" ]]; then
    echo "unable to resolve management interface" >&2
    exit 1
  fi

  data_mode="$(resolve_data_plane_mode)"
  data_iface="$(resolve_dataplane_iface "$mgmt_iface")"
  if [[ -z "$data_iface" ]]; then
    echo "unable to resolve dataplane interface" >&2
    exit 1
  fi
  if [[ "$data_mode" == "dpdk" && ! -d "/sys/class/net/$data_iface" ]]; then
    echo "unable to resolve dataplane interface" >&2
    exit 1
  fi
  if [[ "$mgmt_iface" == "$data_iface" ]]; then
    echo "management and dataplane interfaces resolved to the same device: $mgmt_iface" >&2
    exit 1
  fi

  mgmt_ip="$(iface_ipv4 "$mgmt_iface")"
  if [[ -z "$mgmt_ip" ]]; then
    echo "unable to resolve IPv4 address for management interface $mgmt_iface" >&2
    exit 1
  fi

  data_selector="$(resolve_data_plane_selector "$provider" "$data_iface" "$data_mode")"
  dns_target_ips="$(resolve_dns_target_ips "$mgmt_ip")"
  dns_upstreams="$(resolve_dns_upstreams)"
  if [[ -z "$dns_upstreams" ]]; then
    echo "unable to resolve DNS upstreams; set NEUWERK_BOOTSTRAP_DNS_UPSTREAMS in $appliance_env_file" >&2
    exit 1
  fi

  default_policy="$(resolve_bootstrap_default "${NEUWERK_BOOTSTRAP_DEFAULT_POLICY:-}" "deny")"
  snat_mode="$(resolve_bootstrap_default "${NEUWERK_BOOTSTRAP_SNAT_MODE:-}" "auto")"
  http_bind="$(resolve_bootstrap_default "${NEUWERK_BOOTSTRAP_HTTP_BIND:-}" "${mgmt_ip}:8443")"
  metrics_bind="$(resolve_bootstrap_default "${NEUWERK_BOOTSTRAP_METRICS_BIND:-}" "0.0.0.0:8080")"

  write_passthrough_env

  install -d -m 0755 "$(dirname "$runtime_env_file")"
  cat >"$runtime_env_file" <<EOF
# Generated by __RUNTIME_BINARY_DIR__/firewall-bootstrap.
# Persist operator overrides in $appliance_env_file.
NEUWERK_RUNTIME_PREFIX=$runtime_prefix
NEUWERK_DPDK_VERSION=__TARGET_DPDK_VERSION__
LD_LIBRARY_PATH=$runtime_prefix/current/lib:$runtime_prefix/current/lib/x86_64-linux-gnu:$runtime_prefix/current/lib64
RTE_EAL_PMD_PATH=$runtime_prefix/current/lib/dpdk
MGMT_IP=$mgmt_ip
NEUWERK_MANAGEMENT_INTERFACE=$mgmt_iface
NEUWERK_DATA_PLANE_INTERFACE=$data_selector
NEUWERK_DATA_PLANE_MODE=$data_mode
NEUWERK_DNS_TARGET_IPS=$dns_target_ips
NEUWERK_DNS_UPSTREAMS=$dns_upstreams
NEUWERK_DEFAULT_POLICY=$default_policy
NEUWERK_SNAT_MODE=$snat_mode
NEUWERK_CLOUD_PROVIDER=$provider
NEUWERK_HTTP_BIND=$http_bind
NEUWERK_METRICS_BIND=$metrics_bind
EOF
  if [[ -n "$passthrough_tmp" && -s "$passthrough_tmp" ]]; then
    cat "$passthrough_tmp" >>"$runtime_env_file"
  fi
  chmod 0640 "$runtime_env_file"
}

main "$@"
