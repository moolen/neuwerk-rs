#!/usr/bin/env bash
set -euo pipefail

readonly REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly INVENTORY_HOSTS_CSV="192.168.178.76,192.168.178.83,192.168.178.84"
readonly DEFAULT_ROLLOUT_HOSTS=("192.168.178.83" "192.168.178.84" "192.168.178.76")
readonly REMOTE_BINARY_FIREWALL="/usr/local/bin/firewall"
readonly REMOTE_BINARY_NEUWERK="/usr/local/bin/neuwerk"
readonly REMOTE_WRAPPER="/usr/local/libexec/neuwerk-firewall-start.sh"
readonly REMOTE_HOME="/home/ubuntu"
readonly REMOTE_TMP_BINARY="${REMOTE_HOME}/neuwerk.new"
readonly REMOTE_TMP_WRAPPER="${REMOTE_HOME}/neuwerk-firewall-start.sh.new"
readonly SYSTEMD_UNIT="firewall"

USER_NAME="ubuntu"
BUILD_ARTIFACTS=1
ROLLOUT_HOSTS=("${DEFAULT_ROLLOUT_HOSTS[@]}")
VENDORED_DPDK_VERSION="$(<"${REPO_ROOT}/third_party/dpdk/VERSION")"
VENDORED_DPDK_DIR="${REPO_ROOT}/third_party/dpdk/install/${VENDORED_DPDK_VERSION}"
PKG_CONFIG_PATH_VALUE="${VENDORED_DPDK_DIR}/lib/pkgconfig:${VENDORED_DPDK_DIR}/lib/x86_64-linux-gnu/pkgconfig:${VENDORED_DPDK_DIR}/lib64/pkgconfig"
BINARY_PATH="${REPO_ROOT}/target/release/neuwerk"
WRAPPER_STAGING_PATH=""

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Build the UI and the Neuwerk release binary against vendored DPDK ${VENDORED_DPDK_VERSION},
then roll the result across the homelab ${SYSTEMD_UNIT} service.

Inventory hosts: ${INVENTORY_HOSTS_CSV}
Default rollout order: ${DEFAULT_ROLLOUT_HOSTS[*]}
Remote SSH user: ${USER_NAME}
Systemd unit: ${SYSTEMD_UNIT}

Options:
  --hosts <csv>        Override rollout order, for example: 192.168.178.83,192.168.178.84,192.168.178.76
  --user <name>        Override SSH user (default: ${USER_NAME})
  --skip-build         Reuse the existing ${BINARY_PATH} and ui/dist
  --help               Show this help
EOF
}

log() {
  printf '[deploy-homelab] %s\n' "$*"
}

die() {
  printf '[deploy-homelab] ERROR: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  if [[ -n "${WRAPPER_STAGING_PATH}" && -f "${WRAPPER_STAGING_PATH}" ]]; then
    rm -f "${WRAPPER_STAGING_PATH}"
  fi
}

trap cleanup EXIT

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --hosts)
        [[ $# -ge 2 ]] || die "--hosts requires a CSV value"
        IFS=',' read -r -a ROLLOUT_HOSTS <<<"$2"
        shift 2
        ;;
      --user)
        [[ $# -ge 2 ]] || die "--user requires a value"
        USER_NAME="$2"
        shift 2
        ;;
      --skip-build)
        BUILD_ARTIFACTS=0
        shift
        ;;
      --help|-h)
        usage
        exit 0
        ;;
      *)
        die "unknown argument: $1"
        ;;
    esac
  done
}

require_commands() {
  local cmd=""
  for cmd in bash cargo npm ssh scp curl sha256sum readelf; do
    command -v "$cmd" >/dev/null 2>&1 || die "missing required command: $cmd"
  done
}

require_local_dpdk() {
  [[ -d "${VENDORED_DPDK_DIR}" ]] || die "missing vendored DPDK install: ${VENDORED_DPDK_DIR}"
  [[ -f "${VENDORED_DPDK_DIR}/lib/pkgconfig/libdpdk.pc" ]] || die "missing vendored libdpdk.pc under ${VENDORED_DPDK_DIR}"
  [[ -f "${VENDORED_DPDK_DIR}/lib/librte_eal.so.24" || -f "${VENDORED_DPDK_DIR}/lib/x86_64-linux-gnu/librte_eal.so.24" ]] \
    || die "vendored DPDK ${VENDORED_DPDK_VERSION} does not expose librte_eal.so.24"
}

check_remote_dpdk() {
  local host="$1"
  local output=""
  output="$(
    ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new "${USER_NAME}@${host}" \
      "dpkg-query -W -f='\${Version}\n' dpdk 2>/dev/null; ldconfig -p | grep -q 'librte_eal.so.24'"
  )" || die "remote DPDK probe failed on ${host}"

  local package_version=""
  package_version="$(printf '%s\n' "${output}" | head -n1)"
  [[ -n "${package_version}" ]] || die "host ${host} does not report an installed dpdk package"
  [[ "${package_version}" == 23.11.* ]] || die "host ${host} has incompatible dpdk package version: ${package_version}"
}

check_remote_dpdk_fleet() {
  local host=""
  for host in "${ROLLOUT_HOSTS[@]}"; do
    log "Checking remote DPDK runtime on ${host}"
    check_remote_dpdk "${host}"
  done
}

build_ui_and_binary() {
  if [[ "${BUILD_ARTIFACTS}" -eq 0 ]]; then
    [[ -x "${BINARY_PATH}" ]] || die "--skip-build requested but ${BINARY_PATH} is missing"
    [[ -d "${REPO_ROOT}/ui/dist" ]] || die "--skip-build requested but ${REPO_ROOT}/ui/dist is missing"
    return
  fi

  log "Running UI tests"
  npm --prefix "${REPO_ROOT}/ui" test

  log "Building UI"
  npm --prefix "${REPO_ROOT}/ui" run build

  log "Building Neuwerk against vendored DPDK ${VENDORED_DPDK_VERSION}"
  (
    cd "${REPO_ROOT}"
    DPDK_DIR="${VENDORED_DPDK_DIR}" \
    PKG_CONFIG_PATH="${PKG_CONFIG_PATH_VALUE}" \
    cargo build --release --bin neuwerk --all-features
  )

  [[ -x "${BINARY_PATH}" ]] || die "expected built binary at ${BINARY_PATH}"

  local needed=""
  needed="$(readelf -d "${BINARY_PATH}" | grep 'Shared library' || true)"
  [[ "${needed}" == *"librte_eal.so.24"* ]] || die "built binary does not link against DPDK soname .24"
}

write_wrapper_template() {
  WRAPPER_STAGING_PATH="$(mktemp)"
  cat >"${WRAPPER_STAGING_PATH}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

MGMT_IFACE="${MGMT_IFACE:-mgmt0}"
DATA_IFACE="${DATA_IFACE:-fwdp0}"
DATA_MODE="${DATA_MODE:-tun}"
DNS_TARGET_IP="${DNS_TARGET_IP:-}"
DNS_UPSTREAMS="${DNS_UPSTREAMS:-192.168.178.254:53}"
DEFAULT_POLICY="${DEFAULT_POLICY:-deny}"
SNAT_MODE="${SNAT_MODE:-auto}"
IDLE_TIMEOUT_SECS="${IDLE_TIMEOUT_SECS:-300}"
DNS_ALLOWLIST_GC_INTERVAL_SECS="${DNS_ALLOWLIST_GC_INTERVAL_SECS:-30}"
HTTP_BIND="${HTTP_BIND:-}"
METRICS_BIND="${METRICS_BIND:-}"
CLUSTER_BIND="${CLUSTER_BIND:-}"
CLUSTER_JOIN_BIND="${CLUSTER_JOIN_BIND:-}"
CLUSTER_ADVERTISE="${CLUSTER_ADVERTISE:-}"
JOIN_SEED="${JOIN_SEED:-}"
CLUSTER_MIGRATE_FROM_LOCAL="${CLUSTER_MIGRATE_FROM_LOCAL:-0}"
CLUSTER_MIGRATE_FORCE="${CLUSTER_MIGRATE_FORCE:-0}"
CLUSTER_MIGRATE_VERIFY="${CLUSTER_MIGRATE_VERIFY:-0}"
INTERNAL_CIDR="${INTERNAL_CIDR:-}"
NEUWERK_DPDK_WORKERS="${NEUWERK_DPDK_WORKERS:-}"
NEUWERK_DPDK_STATIC_IP="${NEUWERK_DPDK_STATIC_IP:-}"
NEUWERK_DPDK_STATIC_PREFIX="${NEUWERK_DPDK_STATIC_PREFIX:-}"
NEUWERK_DPDK_STATIC_GATEWAY="${NEUWERK_DPDK_STATIC_GATEWAY:-}"
NEUWERK_DPDK_STATIC_MAC="${NEUWERK_DPDK_STATIC_MAC:-}"

if [[ -z "$DNS_TARGET_IP" ]]; then
  DNS_TARGET_IP="$(ip -4 -o addr show dev "$MGMT_IFACE" | awk '{print $4}' | cut -d/ -f1 | head -n1)"
fi

if [[ -z "$DNS_TARGET_IP" ]]; then
  echo "failed to resolve DNS target IP from ${MGMT_IFACE}" >&2
  exit 1
fi

if [[ -z "$HTTP_BIND" ]]; then
  HTTP_BIND="${DNS_TARGET_IP}:8443"
fi
if [[ -z "$METRICS_BIND" ]]; then
  METRICS_BIND="${DNS_TARGET_IP}:8080"
fi
if [[ -z "$CLUSTER_BIND" ]]; then
  CLUSTER_BIND="${DNS_TARGET_IP}:9600"
fi
if [[ -z "$CLUSTER_JOIN_BIND" ]]; then
  CLUSTER_JOIN_BIND="${DNS_TARGET_IP}:9601"
fi
if [[ -z "$CLUSTER_ADVERTISE" ]]; then
  CLUSTER_ADVERTISE="$CLUSTER_BIND"
fi

sudo mkdir -p /etc/neuwerk
cfg_tmp="$(mktemp /etc/neuwerk/config.yaml.XXXXXX)"
{
  echo "version: 1"
  echo "bootstrap:"
  echo "  management_interface: $MGMT_IFACE"
  echo "  data_interface: $DATA_IFACE"
  echo "  cloud_provider: none"
  echo "  data_plane_mode: $DATA_MODE"
  echo "dns:"
  echo "  target_ips:"
  echo "    - $DNS_TARGET_IP"
  echo "  upstreams:"
  IFS=',' read -ra upstreams <<< "$DNS_UPSTREAMS"
  for upstream in "${upstreams[@]}"; do
    echo "    - ${upstream}"
  done
  echo "policy:"
  echo "  default: $DEFAULT_POLICY"
  if [[ -n "$INTERNAL_CIDR" ]]; then
    echo "  internal_cidr: $INTERNAL_CIDR"
  fi
  echo "http:"
  echo "  bind: $HTTP_BIND"
  echo "  advertise: $HTTP_BIND"
  echo "  tls_dir: /var/lib/neuwerk/http-tls"
  echo "metrics:"
  echo "  bind: $METRICS_BIND"
  echo "  allow_public_bind: true"
  echo "cluster:"
  echo "  bind: $CLUSTER_BIND"
  echo "  join_bind: $CLUSTER_JOIN_BIND"
  echo "  advertise: $CLUSTER_ADVERTISE"
  echo "  data_dir: /var/lib/neuwerk/cluster"
  echo "  node_id_path: /var/lib/neuwerk/node_id"
  echo "  token_path: /var/lib/neuwerk/bootstrap-token"
  if [[ -n "$JOIN_SEED" ]]; then
    echo "  join_seed: $JOIN_SEED"
  fi
  if [[ "$CLUSTER_MIGRATE_FROM_LOCAL" == "1" ]]; then
    echo "  migrate_from_local: true"
  fi
  if [[ "$CLUSTER_MIGRATE_FORCE" == "1" ]]; then
    echo "  migrate_force: true"
  fi
  if [[ "$CLUSTER_MIGRATE_VERIFY" == "1" ]]; then
    echo "  migrate_verify: true"
  fi
  echo "dataplane:"
  echo "  idle_timeout_secs: $IDLE_TIMEOUT_SECS"
  echo "  dns_allowlist_gc_interval_secs: $DNS_ALLOWLIST_GC_INTERVAL_SECS"
  echo "  snat:"
  case "$SNAT_MODE" in
    auto|AUTO)
      echo "    mode: auto"
      ;;
    none|NONE)
      echo "    mode: none"
      ;;
    *)
      echo "    mode: static"
      echo "    ip: $SNAT_MODE"
      ;;
  esac
  if [[ "$DATA_MODE" == "dpdk" ]]; then
    echo "dpdk:"
    if [[ -n "$NEUWERK_DPDK_STATIC_IP" ]]; then
      echo "  static_ip: $NEUWERK_DPDK_STATIC_IP"
    fi
    if [[ -n "$NEUWERK_DPDK_STATIC_PREFIX" ]]; then
      echo "  static_prefix_len: $NEUWERK_DPDK_STATIC_PREFIX"
    fi
    if [[ -n "$NEUWERK_DPDK_STATIC_GATEWAY" ]]; then
      echo "  static_gateway: $NEUWERK_DPDK_STATIC_GATEWAY"
    fi
    if [[ -n "$NEUWERK_DPDK_STATIC_MAC" ]]; then
      echo "  static_mac: $NEUWERK_DPDK_STATIC_MAC"
    fi
    if [[ -n "$NEUWERK_DPDK_WORKERS" ]]; then
      echo "  workers: $NEUWERK_DPDK_WORKERS"
    fi
  fi
} > "$cfg_tmp"
sudo install -m 0644 "$cfg_tmp" /etc/neuwerk/config.yaml
rm -f "$cfg_tmp"

exec /usr/local/bin/firewall
EOF
  chmod 0755 "${WRAPPER_STAGING_PATH}"
}

local_binary_sha() {
  sha256sum "${BINARY_PATH}" | awk '{print $1}'
}

local_wrapper_sha() {
  sha256sum "${WRAPPER_STAGING_PATH}" | awk '{print $1}'
}

wait_for_https_health() {
  local host="$1"
  local h=""
  local r=""
  local ok=0
  local i=""

  for i in $(seq 1 60); do
    h="$(curl -sk -o /dev/null -w '%{http_code}' "https://${host}:8443/health" || true)"
    r="$(curl -sk -o /dev/null -w '%{http_code}' "https://${host}:8443/ready" || true)"
    if [[ "${h}" == '200' && "${r}" == '200' ]]; then
      log "Health checks passed on ${host} (health=${h} ready=${r} iter=${i})"
      ok=1
      break
    fi
    sleep 2
  done

  [[ "${ok}" == '1' ]] || die "timed out waiting for health and ready on ${host} (last health=${h:-000} ready=${r:-000})"
}

deploy_host() {
  local host="$1"
  local binary_sha=""
  local wrapper_sha=""

  binary_sha="$(local_binary_sha)"
  wrapper_sha="$(local_wrapper_sha)"

  log "Uploading artifacts to ${host}"
  scp -o StrictHostKeyChecking=accept-new "${BINARY_PATH}" "${USER_NAME}@${host}:${REMOTE_TMP_BINARY}"
  scp -o StrictHostKeyChecking=accept-new "${WRAPPER_STAGING_PATH}" "${USER_NAME}@${host}:${REMOTE_TMP_WRAPPER}"

  log "Installing artifacts and restarting ${SYSTEMD_UNIT} on ${host}"
  ssh -o StrictHostKeyChecking=accept-new "${USER_NAME}@${host}" bash <<EOF
set -euo pipefail
ts=\$(date +%Y%m%dT%H%M%SZ)
sudo cp -a '${REMOTE_BINARY_FIREWALL}' '${REMOTE_BINARY_FIREWALL}.bak.'"\${ts}"
sudo cp -a '${REMOTE_BINARY_NEUWERK}' '${REMOTE_BINARY_NEUWERK}.bak.'"\${ts}"
sudo cp -a '${REMOTE_WRAPPER}' '${REMOTE_WRAPPER}.bak.'"\${ts}"
sudo install -m 0755 '${REMOTE_TMP_BINARY}' '${REMOTE_BINARY_FIREWALL}'
sudo install -m 0755 '${REMOTE_TMP_BINARY}' '${REMOTE_BINARY_NEUWERK}'
sudo install -m 0755 '${REMOTE_TMP_WRAPPER}' '${REMOTE_WRAPPER}'
sudo systemctl restart '${SYSTEMD_UNIT}'
actual_bin_sha=\$(sha256sum '${REMOTE_BINARY_FIREWALL}' | awk '{print \$1}')
actual_wrapper_sha=\$(sha256sum '${REMOTE_WRAPPER}' | awk '{print \$1}')
[[ "\${actual_bin_sha}" == '${binary_sha}' ]]
[[ "\${actual_wrapper_sha}" == '${wrapper_sha}' ]]
sudo systemctl is-active '${SYSTEMD_UNIT}' >/dev/null
printf 'BIN_SHA=%s\nWRAP_SHA=%s\n' "\${actual_bin_sha}" "\${actual_wrapper_sha}"
EOF

  wait_for_https_health "${host}"
}

postcheck_host() {
  local host="$1"
  local remote_meta=""
  local health_code=""
  local ready_code=""

  remote_meta="$(
    ssh -o StrictHostKeyChecking=accept-new "${USER_NAME}@${host}" bash <<EOF
set -euo pipefail
printf 'sha=%s ' "\$(sha256sum '${REMOTE_BINARY_FIREWALL}' | awk '{print \$1}')"
printf 'wrap=%s' "\$(sha256sum '${REMOTE_WRAPPER}' | awk '{print \$1}')"
EOF
  )"

  health_code="$(curl -sk -o /dev/null -w '%{http_code}' "https://${host}:8443/health" || true)"
  ready_code="$(curl -sk -o /dev/null -w '%{http_code}' "https://${host}:8443/ready" || true)"
  printf '%s %s health=%s ready=%s\n' "${host}" "${remote_meta}" "${health_code}" "${ready_code}"
}

main() {
  parse_args "$@"
  require_commands
  require_local_dpdk
  check_remote_dpdk_fleet
  build_ui_and_binary
  write_wrapper_template

  local host=""
  for host in "${ROLLOUT_HOSTS[@]}"; do
    deploy_host "${host}"
  done

  log "Final fleet health"
  for host in "${ROLLOUT_HOSTS[@]}"; do
    postcheck_host "${host}"
  done
}

main "$@"
