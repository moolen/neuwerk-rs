#!/usr/bin/env bash
set -euo pipefail

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

export DEBIAN_FRONTEND=noninteractive

for cmd in apt-get awk curl install ip python3 systemctl; do
  require_cmd "$cmd"
done

MGMT_IP="${NEUWERK_VAGRANT_MGMT_IP:?missing NEUWERK_VAGRANT_MGMT_IP}"
MGMT_PREFIX="${NEUWERK_VAGRANT_MGMT_PREFIX:-24}"
CLIENT_GW_IP="${NEUWERK_VAGRANT_CLIENT_GATEWAY_IP:?missing NEUWERK_VAGRANT_CLIENT_GATEWAY_IP}"
CLIENT_PREFIX="${NEUWERK_VAGRANT_CLIENT_PREFIX:-24}"
UPLINK_BRIDGE="${NEUWERK_VAGRANT_UPLINK_BRIDGE:-}"
DEMO_DIR="/opt/neuwerk/demo"
STATE_DIR="/var/lib/neuwerk-demo"
CONFIG_DIR="/etc/neuwerk-demo"
RUNTIME_ENV="${CONFIG_DIR}/runtime.env"
CONFIG_FILE="/etc/neuwerk/config.yaml"
VAGRANT_INSECURE_PUBLIC_KEY='ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEA6NF8iallvQVp22WDkTkyrtvp9eWW6A8YVr+kz4TjGYe7gHzIw+niNltGEFHzD8+v1I2YJ6oXevct1YeS0o9HZyN1Q9qgCgzUFtdOKLv6IedplqoPkcmF0aYet2PkEDo3MlTBckFXPITAMzF8dJSIFo9D8HfdOV0IAdx4O7PtixWKn5y2hMNG0zQPyUecp4pzC6kivAIhyfHilFR61RGL+GPXQ2MWZWFYbAGjyiYJnAmCP3NOTd0jMZEnDkbUvxhMmBYSdETk1rRgm+R4LOzFUGaHqHDLKLX+FIPKcF96hrucXzcWyLbIbEgE98OHlnVYCzRdK8jlqm8tehUc9c9WhQ=='

if ! command -v python3 >/dev/null 2>&1; then
  apt-get update
  apt-get install -y python3
fi

install -d -m 0755 "${DEMO_DIR}" "${STATE_DIR}" "${CONFIG_DIR}" /usr/local/bin /etc/profile.d
sed -i '\|\.cargo/env|d' /home/ubuntu/.profile /home/ubuntu/.bashrc 2>/dev/null || true
install -d -m 0700 /home/ubuntu/.ssh
touch /home/ubuntu/.ssh/authorized_keys
grep -qxF "${VAGRANT_INSECURE_PUBLIC_KEY}" /home/ubuntu/.ssh/authorized_keys || printf '%s\n' "${VAGRANT_INSECURE_PUBLIC_KEY}" >> /home/ubuntu/.ssh/authorized_keys
chmod 0600 /home/ubuntu/.ssh/authorized_keys
chown -R ubuntu:ubuntu /home/ubuntu/.ssh

sshd_config = Path("/etc/ssh/sshd_config")
if sshd_config.exists():
    sshd_text = sshd_config.read_text(encoding="utf-8")
    for key, value in (
        ("PasswordAuthentication", "yes"),
        ("KbdInteractiveAuthentication", "no"),
        ("PubkeyAuthentication", "yes"),
        ("UsePAM", "yes"),
    ):
        lines = sshd_text.splitlines()
        replaced = False
        updated = []
        import re
        pattern = re.compile(rf"^\s*#?\s*{re.escape(key)}\s+.*$", re.IGNORECASE)
        for line in lines:
            if pattern.match(line):
                if not replaced:
                    updated.append(f"{key} {value}")
                    replaced = True
                continue
            updated.append(line)
        if not replaced:
            if updated and updated[-1] != "":
                updated.append("")
            updated.append(f"{key} {value}")
        sshd_text = "\n".join(updated) + "\n"
    sshd_config.write_text(sshd_text, encoding="utf-8")
PY

systemctl restart ssh.service 2>/dev/null || systemctl restart sshd.service 2>/dev/null || true

cat >"${CONFIG_DIR}/vagrant.env" <<EOF
NEUWERK_VAGRANT_MGMT_IP=${MGMT_IP}
NEUWERK_VAGRANT_MGMT_PREFIX=${MGMT_PREFIX}
NEUWERK_VAGRANT_CLIENT_GATEWAY_IP=${CLIENT_GW_IP}
NEUWERK_VAGRANT_CLIENT_PREFIX=${CLIENT_PREFIX}
NEUWERK_VAGRANT_UPLINK_BRIDGE=${UPLINK_BRIDGE}
EOF
chmod 0644 "${CONFIG_DIR}/vagrant.env"

cat >/usr/local/bin/neuwerk-demo-configure <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

CONFIG_DIR="/etc/neuwerk-demo"
STATE_DIR="/var/lib/neuwerk-demo"
VAGRANT_ENV="${CONFIG_DIR}/vagrant.env"
RUNTIME_ENV="${CONFIG_DIR}/runtime.env"
CONFIG_FILE="/etc/neuwerk/config.yaml"

if [[ ! -f "${VAGRANT_ENV}" ]]; then
  echo "missing Vagrant env file: ${VAGRANT_ENV}" >&2
  exit 1
fi

# shellcheck disable=SC1090
source "${VAGRANT_ENV}"

UPLINK_BRIDGE="${NEUWERK_VAGRANT_UPLINK_BRIDGE:-}"

iface_for_ip() {
  local ip="$1"
  ip -o -4 addr show | awk -v want="${ip}" '$4 ~ (want "/") { print $2; exit }'
}

default_route_iface() {
  ip -4 route show default 2>/dev/null | awk '{print $5; exit}'
}

iface_ipv4() {
  local iface="$1"
  ip -o -4 addr show dev "${iface}" scope global | awk 'NR==1 {split($4, a, "/"); print a[1]}'
}

iface_default_gateway() {
  local iface="$1"
  ip -4 route show default dev "${iface}" 2>/dev/null | awk 'NR==1 {print $3}'
}

wait_for_global_ipv4() {
  local iface="$1"
  local attempts="$2"
  local sleep_secs="$3"
  local i
  for ((i = 0; i < attempts; i += 1)); do
    if ip -o -4 addr show dev "${iface}" scope global | grep -q .; then
      return 0
    fi
    if (( i == 10 )); then
      networkctl reconfigure "${iface}" >/dev/null 2>&1 || true
    fi
    if (( i == 30 )); then
      networkctl renew "${iface}" >/dev/null 2>&1 || true
    fi
    sleep "${sleep_secs}"
  done
  return 1
}

candidate_uplink_ifaces() {
  local iface
  for iface in $(ip -o link show | awk -F': ' '{print $2}' | cut -d@ -f1); do
    case "${iface}" in
      lo|dp0|svc0)
        continue
        ;;
    esac
    if [[ "${iface}" == "${MGMT_IFACE}" || "${iface}" == "${CLIENT_IFACE}" ]]; then
      continue
    fi
    printf '%s\n' "${iface}"
  done
}

is_virtualbox_nat_iface() {
  local iface="$1"
  local iface_ip
  local iface_gw
  iface_ip="$(iface_ipv4 "${iface}")"
  iface_gw="$(iface_default_gateway "${iface}")"
  [[ "${iface_ip}" == 10.0.2.* || "${iface_gw}" == "10.0.2.2" ]]
}

resolve_uplink_iface() {
  local default_iface="$1"
  local candidates=()
  local non_nat=()
  local iface
  while IFS= read -r iface; do
    [[ -n "${iface}" ]] || continue
    candidates+=("${iface}")
    if ! is_virtualbox_nat_iface "${iface}"; then
      non_nat+=("${iface}")
    fi
  done < <(candidate_uplink_ifaces)

  if (( ${#non_nat[@]} == 1 )); then
    printf '%s\n' "${non_nat[0]}"
    return 0
  fi
  if (( ${#non_nat[@]} > 1 )); then
    for iface in "${non_nat[@]}"; do
      if [[ "${iface}" != "${default_iface}" ]]; then
        printf '%s\n' "${iface}"
        return 0
      fi
    done
    printf '%s\n' "${non_nat[0]}"
    return 0
  fi
  if (( ${#candidates[@]} == 1 )); then
    printf '%s\n' "${candidates[0]}"
    return 0
  fi
  if (( ${#candidates[@]} > 1 )); then
    for iface in "${candidates[@]}"; do
      if [[ "${iface}" != "${default_iface}" ]]; then
        printf '%s\n' "${iface}"
        return 0
      fi
    done
  fi
  return 1
}

cidr_network() {
  python3 - "$1" "$2" <<'PY'
import ipaddress
import sys

iface = ipaddress.IPv4Interface(f"{sys.argv[1]}/{sys.argv[2]}")
print(iface.network.network_address)
PY
}

MGMT_IFACE="$(iface_for_ip "${NEUWERK_VAGRANT_MGMT_IP}" || true)"
CLIENT_IFACE="$(iface_for_ip "${NEUWERK_VAGRANT_CLIENT_GATEWAY_IP}" || true)"
DEFAULT_IFACE="$(default_route_iface || true)"
UPLINK_IFACE="$(resolve_uplink_iface "${DEFAULT_IFACE}" || true)"

if [[ -z "${UPLINK_IFACE}" || -z "${MGMT_IFACE}" || -z "${CLIENT_IFACE}" ]]; then
  echo "could not resolve uplink, management, or client interface" >&2
  exit 1
fi

if [[ "${MGMT_IFACE}" == "${CLIENT_IFACE}" || "${UPLINK_IFACE}" == "${CLIENT_IFACE}" || "${UPLINK_IFACE}" == "${MGMT_IFACE}" ]]; then
  echo "expected three distinct interfaces but resolved: uplink=${UPLINK_IFACE} mgmt=${MGMT_IFACE} client=${CLIENT_IFACE}" >&2
  exit 1
fi

if ! wait_for_global_ipv4 "${UPLINK_IFACE}" 180 1; then
  echo "timed out waiting for a global IPv4 on uplink interface ${UPLINK_IFACE}" >&2
  exit 1
fi

UPLINK_IP="$(ip -o -4 addr show dev "${UPLINK_IFACE}" scope global | awk 'NR==1 {split($4, a, "/"); print a[1]}')"
UPLINK_PREFIX="$(ip -o -4 addr show dev "${UPLINK_IFACE}" scope global | awk 'NR==1 {split($4, a, "/"); print a[2]}')"
UPLINK_GW="$(ip -4 route show default dev "${UPLINK_IFACE}" 2>/dev/null | awk 'NR==1 {print $3}')"
if [[ -z "${UPLINK_IP}" ]]; then
  echo "could not determine uplink IPv4 for ${UPLINK_IFACE}" >&2
  exit 1
fi
if [[ -z "${UPLINK_PREFIX}" ]]; then
  echo "could not determine uplink prefix for ${UPLINK_IFACE}" >&2
  exit 1
fi
if [[ -z "${UPLINK_GW}" ]]; then
  echo "could not determine uplink gateway for ${UPLINK_IFACE}" >&2
  exit 1
fi

CLIENT_NET="$(cidr_network "${NEUWERK_VAGRANT_CLIENT_GATEWAY_IP}" "${NEUWERK_VAGRANT_CLIENT_PREFIX}")"
SNAT_IP="${UPLINK_IP}"

install -d -m 0755 "${CONFIG_DIR}" "${STATE_DIR}" /etc/neuwerk

cat >"${RUNTIME_ENV}" <<RUNTIME
NEUWERK_DEMO_UPLINK_IFACE=${UPLINK_IFACE}
NEUWERK_DEMO_UPLINK_IP=${UPLINK_IP}
NEUWERK_DEMO_UPLINK_PREFIX=${UPLINK_PREFIX}
NEUWERK_DEMO_UPLINK_GW=${UPLINK_GW}
NEUWERK_DEMO_UPLINK_BRIDGE=${UPLINK_BRIDGE}
NEUWERK_DEMO_SNAT_IP=${SNAT_IP}
NEUWERK_DEMO_MGMT_IFACE=${MGMT_IFACE}
NEUWERK_DEMO_MGMT_IP=${NEUWERK_VAGRANT_MGMT_IP}
NEUWERK_DEMO_CLIENT_IFACE=${CLIENT_IFACE}
NEUWERK_DEMO_CLIENT_GW_IP=${NEUWERK_VAGRANT_CLIENT_GATEWAY_IP}
NEUWERK_DEMO_CLIENT_NET=${CLIENT_NET}
NEUWERK_DEMO_CLIENT_PREFIX=${NEUWERK_VAGRANT_CLIENT_PREFIX}
NEUWERK_DEMO_DATAPLANE_INTERFACE=dp0
NEUWERK_DEMO_ADMIN_TOKEN_PATH=${STATE_DIR}/admin.token
RUNTIME

cat >"${CONFIG_FILE}" <<CONFIG
version: 1
bootstrap:
  management_interface: ${MGMT_IFACE}
  data_interface: dp0
  cloud_provider: none
  data_plane_mode: tun
dns:
  target_ips:
    - ${NEUWERK_VAGRANT_MGMT_IP}
  upstreams:
    - 1.1.1.1:53
    - 8.8.8.8:53
policy:
  default: allow
  internal_cidr: ${CLIENT_NET}/${NEUWERK_VAGRANT_CLIENT_PREFIX}
http:
  bind: ${NEUWERK_VAGRANT_MGMT_IP}:8443
  advertise: ${NEUWERK_VAGRANT_MGMT_IP}:8443
  external_url: https://${NEUWERK_VAGRANT_MGMT_IP}:8443
  tls_san:
    - localhost
    - 127.0.0.1
    - ${NEUWERK_VAGRANT_MGMT_IP}
metrics:
  bind: ${NEUWERK_VAGRANT_MGMT_IP}:8080
dataplane:
  snat: ${SNAT_IP}
CONFIG
EOF
chmod 0755 /usr/local/bin/neuwerk-demo-configure

cat >/usr/local/bin/neuwerk-demo-topology <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

RUNTIME_ENV="/etc/neuwerk-demo/runtime.env"

if [[ ! -f "${RUNTIME_ENV}" ]]; then
  echo "missing runtime env file: ${RUNTIME_ENV}" >&2
  exit 1
fi

# shellcheck disable=SC1090
source "${RUNTIME_ENV}"

wait_for_link() {
  local link="$1"
  local attempts="$2"
  local sleep_secs="$3"
  local i
  for ((i = 0; i < attempts; i += 1)); do
    if ip link show "${link}" >/dev/null 2>&1; then
      return 0
    fi
    sleep "${sleep_secs}"
  done
  return 1
}

write_sysctl() {
  local path="$1"
  local value="$2"
  printf '%s' "${value}" >"/proc/sys/${path}"
}

cleanup() {
  delete_pref 50
  delete_pref 51
  delete_pref 100
  delete_pref 101
  delete_pref 102
  delete_pref 200
  if ip rule show | grep -q '^0:.*iif lo lookup local$'; then
    delete_pref 0
  fi
  ip route flush table 100 2>/dev/null || true
  ip route flush table 110 2>/dev/null || true
  ensure_default_local_rule
}

delete_pref() {
  local pref="$1"
  while ip rule del pref "${pref}" 2>/dev/null; do
    :
  done
}

ensure_default_local_rule() {
  if ! ip rule show | grep -q '^0:.*lookup local$'; then
    ip rule add pref 0 lookup local
  fi
}

setup() {
  cleanup
  write_sysctl net/ipv4/ip_forward 1
  write_sysctl net/ipv4/conf/all/rp_filter 0
  write_sysctl net/ipv4/conf/default/rp_filter 0
  write_sysctl "net/ipv4/conf/${NEUWERK_DEMO_CLIENT_IFACE}/rp_filter" 0
  write_sysctl "net/ipv4/conf/${NEUWERK_DEMO_UPLINK_IFACE}/rp_filter" 0

  if ! wait_for_link "${NEUWERK_DEMO_DATAPLANE_INTERFACE}" 80 0.25; then
    echo "timed out waiting for ${NEUWERK_DEMO_DATAPLANE_INTERFACE}" >&2
    exit 1
  fi

  ip link set "${NEUWERK_DEMO_DATAPLANE_INTERFACE}" up
  write_sysctl "net/ipv4/conf/${NEUWERK_DEMO_DATAPLANE_INTERFACE}/rp_filter" 0
  ip route replace table 100 default dev "${NEUWERK_DEMO_DATAPLANE_INTERFACE}"
  ip route replace table 110 default via "${NEUWERK_DEMO_UPLINK_GW}" dev "${NEUWERK_DEMO_UPLINK_IFACE}"
  delete_pref 0
  ip rule add pref 0 iif lo lookup local
  ip rule add pref 50 iif "${NEUWERK_DEMO_MGMT_IFACE}" lookup local
  ip rule add pref 51 iif "${NEUWERK_DEMO_CLIENT_IFACE}" lookup local
  ip rule add iif "${NEUWERK_DEMO_CLIENT_IFACE}" pref 100 lookup 100 2>/dev/null || true
  ip rule add iif "${NEUWERK_DEMO_UPLINK_IFACE}" to "${NEUWERK_DEMO_SNAT_IP}/32" pref 101 lookup 100 2>/dev/null || true
  ip rule add iif "${NEUWERK_DEMO_DATAPLANE_INTERFACE}" from "${NEUWERK_DEMO_SNAT_IP}/32" pref 102 lookup 110 2>/dev/null || true
  ip rule add pref 200 lookup local
}

case "${1:-up}" in
  up)
    setup
    ;;
  down)
    cleanup
    ;;
  *)
    echo "usage: $0 [up|down]" >&2
    exit 2
    ;;
esac
EOF
chmod 0755 /usr/local/bin/neuwerk-demo-topology

cat >/usr/local/bin/neuwerk-demo-mint-token <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

RUNTIME_ENV="/etc/neuwerk-demo/runtime.env"

if [[ -f "${RUNTIME_ENV}" ]]; then
  # shellcheck disable=SC1090
  source "${RUNTIME_ENV}"
fi

TOKEN_PATH="${NEUWERK_DEMO_ADMIN_TOKEN_PATH:-/var/lib/neuwerk-demo/admin.token}"
HTTP_TLS_DIR="${NEUWERK_DEMO_HTTP_TLS_DIR:-/var/lib/neuwerk/http-tls}"
HEALTH_URL="${NEUWERK_DEMO_HEALTH_URL:-https://${NEUWERK_DEMO_MGMT_IP:-127.0.0.1}:8443/health}"

install -d -m 0755 "$(dirname "${TOKEN_PATH}")"

for _ in $(seq 1 90); do
  if curl -skf "${HEALTH_URL}" >/dev/null 2>&1; then
    if neuwerk auth token mint \
      --sub demo-admin \
      --roles admin \
      --http-tls-dir "${HTTP_TLS_DIR}" >"${TOKEN_PATH}.tmp" 2>/dev/null; then
      mv "${TOKEN_PATH}.tmp" "${TOKEN_PATH}"
      chmod 0644 "${TOKEN_PATH}"
      exit 0
    fi
  fi
  sleep 1
done

echo "failed to mint demo admin token" >&2
exit 1
EOF
chmod 0755 /usr/local/bin/neuwerk-demo-mint-token

cat >/etc/systemd/system/neuwerk-demo-configure.service <<'EOF'
[Unit]
Description=Neuwerk Demo Runtime Configuration
Before=neuwerk.service
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/neuwerk-demo-configure
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

cat >/etc/systemd/system/neuwerk-demo-topology.service <<'EOF'
[Unit]
Description=Neuwerk Demo Gateway Topology
After=neuwerk.service
Requires=neuwerk.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/neuwerk-demo-topology up
ExecStop=/usr/local/bin/neuwerk-demo-topology down

[Install]
WantedBy=multi-user.target
EOF

cat >/etc/systemd/system/neuwerk-demo-token.service <<'EOF'
[Unit]
Description=Neuwerk Demo Admin Token
After=neuwerk.service
Wants=neuwerk.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/neuwerk-demo-mint-token
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

cat >/etc/profile.d/neuwerk-demo.sh <<'EOF'
#!/usr/bin/env bash
if [[ -n "${PS1:-}" ]]; then
  if [[ -f /etc/neuwerk-demo/vagrant.env ]]; then
    # shellcheck disable=SC1091
    source /etc/neuwerk-demo/vagrant.env
  fi
  cat <<MSG

Neuwerk gateway demo helpers:
  UI: https://${NEUWERK_VAGRANT_MGMT_IP:-192.168.57.10}:8443
  token: cat /var/lib/neuwerk-demo/admin.token
  gateway: ${NEUWERK_VAGRANT_CLIENT_GATEWAY_IP:-192.168.56.10}
MSG
fi
EOF
chmod 0644 /etc/profile.d/neuwerk-demo.sh

systemctl daemon-reload
wait_for_file() {
  local path="$1"
  local attempts="${2:-90}"
  local delay_secs="${3:-1}"
  local i
  for ((i = 0; i < attempts; i += 1)); do
    if [[ -f "${path}" ]]; then
      return 0
    fi
    sleep "${delay_secs}"
  done
  return 1
}

wait_for_health() {
  local url="$1"
  local attempts="${2:-90}"
  local delay_secs="${3:-1}"
  local i
  for ((i = 0; i < attempts; i += 1)); do
    if curl -skf "${url}" >/dev/null 2>&1; then
      return 0
    fi
    if systemctl is-failed --quiet neuwerk.service; then
      return 1
    fi
    sleep "${delay_secs}"
  done
  return 1
}

print_firewall_failure() {
  systemctl status neuwerk.service --no-pager || true
  journalctl -u neuwerk.service --no-pager -n 200 || true
}

start_demo_runtime() {
  rm -rf \
    /var/lib/neuwerk/cluster \
    /var/lib/neuwerk/tls-intercept \
    /var/lib/neuwerk/http-tls \
    /var/lib/neuwerk/node_id
  rm -f \
    /var/lib/neuwerk-demo/admin.token
  systemctl restart neuwerk-demo-configure.service
  systemctl reset-failed neuwerk.service >/dev/null 2>&1 || true
  systemctl start neuwerk.service
  wait_for_file /var/lib/neuwerk/http-tls/api-auth.json 90 1 || return 1
  wait_for_health "https://${MGMT_IP}:8443/health" 90 1 || return 1
}

systemctl stop neuwerk-demo-token.service neuwerk-demo-topology.service neuwerk.service 2>/dev/null || true
systemctl enable neuwerk-demo-configure.service neuwerk.service neuwerk-demo-topology.service neuwerk-demo-token.service
rm -f /var/lib/neuwerk-demo/admin.token

if ! start_demo_runtime; then
  print_firewall_failure
  exit 1
fi

systemctl restart neuwerk-demo-topology.service
systemctl restart neuwerk-demo-token.service
