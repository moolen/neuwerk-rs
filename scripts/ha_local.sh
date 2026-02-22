#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE_DIR="${STATE_DIR:-/tmp/neuwerk-ha}"
LOG_DIR="${STATE_DIR}/logs"

WAN_IFACE="${WAN_IFACE:-wlan0}"
FW_BIN="${FW_BIN:-${ROOT_DIR}/target/debug/firewall}"
DEFAULT_POLICY="${DEFAULT_POLICY:-allow}"

MGMT_BR="${MGMT_BR:-nw-br-mgmt}"
MGMT_NET_CIDR="${MGMT_NET_CIDR:-192.168.100.0/24}"
MGMT_HOST_IP="${MGMT_HOST_IP:-192.168.100.254}"
FW1_MGMT_IP="${FW1_MGMT_IP:-192.168.100.11}"
FW2_MGMT_IP="${FW2_MGMT_IP:-192.168.100.12}"
FW3_MGMT_IP="${FW3_MGMT_IP:-192.168.100.13}"

DP_NET_CIDR="${DP_NET_CIDR:-10.0.0.0/24}"
HOST_IN_IP="${HOST_IN_IP:-10.0.0.2}"
FW1_IN_IP="${FW1_IN_IP:-10.0.0.1}"

UP_NET_CIDR="${UP_NET_CIDR:-198.51.100.0/24}"
HOST_UP_IP="${HOST_UP_IP:-198.51.100.1}"
FW1_UP_IP="${FW1_UP_IP:-198.51.100.2}"

FW1_NS="fw1"
FW2_NS="fw2"
FW3_NS="fw3"

FW1_MGMT_IF="nw-veth-fw1-m"
FW2_MGMT_IF="nw-veth-fw2-m"
FW3_MGMT_IF="nw-veth-fw3-m"
HOST_FW1_MGMT_IF="nw-veth-host-fw1-m"
HOST_FW2_MGMT_IF="nw-veth-host-fw2-m"
HOST_FW3_MGMT_IF="nw-veth-host-fw3-m"

FW1_IN_IF="nw-veth-fw1-in"
HOST_IN_IF="nw-veth-host-in"
FW1_UP_IF="nw-veth-fw1-up"
HOST_UP_IF="nw-veth-host-up"

die() {
  echo "error: $*" >&2
  exit 1
}

require_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    die "run as root (sudo)"
  fi
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

ensure_dirs() {
  mkdir -p "$STATE_DIR" "$LOG_DIR"
  mkdir -p "$STATE_DIR/node1/cluster" "$STATE_DIR/node2/cluster" "$STATE_DIR/node3/cluster"
  mkdir -p "$STATE_DIR/node1/http-tls" "$STATE_DIR/node2/http-tls" "$STATE_DIR/node3/http-tls"
}

save_default_route() {
  if [[ ! -f "${STATE_DIR}/default_route" ]]; then
    ip route show default | head -n1 > "${STATE_DIR}/default_route"
  fi
}

save_ip_forward() {
  if [[ ! -f "${STATE_DIR}/ip_forward" ]]; then
    cat /proc/sys/net/ipv4/ip_forward > "${STATE_DIR}/ip_forward"
  fi
}

restore_default_route() {
  if [[ -s "${STATE_DIR}/default_route" ]]; then
    ip route del default >/dev/null 2>&1 || true
    ip route replace $(cat "${STATE_DIR}/default_route")
  fi
}

restore_ip_forward() {
  if [[ -s "${STATE_DIR}/ip_forward" ]]; then
    local value
    value="$(cat "${STATE_DIR}/ip_forward")"
    sysctl -w "net.ipv4.ip_forward=${value}" >/dev/null
  fi
}

gen_bootstrap_token() {
  if [[ ! -f "${STATE_DIR}/bootstrap.json" ]]; then
    local token
    token="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    cat > "${STATE_DIR}/bootstrap.json" <<JSON
{"tokens":[{"kid":"local","token":"hex:${token}"}]}
JSON
  fi
}

create_netns() {
  local ns="$1"
  ip netns add "$ns"
  ip netns exec "$ns" ip link set lo up
}

create_veth_pair() {
  local ns="$1" ns_if="$2" host_if="$3"
  ip link add "$ns_if" type veth peer name "$host_if"
  ip link set "$ns_if" netns "$ns"
}

wait_link() {
  local ns="$1" iface="$2"
  for _ in $(seq 1 60); do
    if ip netns exec "$ns" ip link show "$iface" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

start_fw1() {
  local log="${LOG_DIR}/fw1.log"
  ip netns exec "$FW1_NS" "$FW_BIN" \
    --management-interface "$FW1_MGMT_IF" \
    --data-plane-interface "dp0" \
    --data-plane-mode tun \
    --default-policy "$DEFAULT_POLICY" \
    --dns-upstream "8.8.8.8:53" \
    --dns-listen "${FW1_MGMT_IP}:53" \
    --snat-ip "${FW1_UP_IP}" \
    --http-bind "${FW1_MGMT_IP}:8443" \
    --metrics-bind "${FW1_MGMT_IP}:8080" \
    --cluster-bind "${FW1_MGMT_IP}:9600" \
    --cluster-join-bind "${FW1_MGMT_IP}:9601" \
    --cluster-advertise "${FW1_MGMT_IP}:9600" \
    --cluster-data-dir "${STATE_DIR}/node1/cluster" \
    --node-id-path "${STATE_DIR}/node1/node_id" \
    --bootstrap-token-path "${STATE_DIR}/bootstrap.json" \
    --http-tls-dir "${STATE_DIR}/node1/http-tls" \
    >"$log" 2>&1 &
  echo $! >> "${STATE_DIR}/pids"
}

start_fw2() {
  local log="${LOG_DIR}/fw2.log"
  ip netns exec "$FW2_NS" "$FW_BIN" \
    --management-interface "$FW2_MGMT_IF" \
    --data-plane-interface "dp0" \
    --data-plane-mode tun \
    --default-policy "$DEFAULT_POLICY" \
    --dns-upstream "8.8.8.8:53" \
    --dns-listen "${FW2_MGMT_IP}:53" \
    --http-bind "${FW2_MGMT_IP}:8443" \
    --metrics-bind "${FW2_MGMT_IP}:8080" \
    --cluster-bind "${FW2_MGMT_IP}:9600" \
    --cluster-join-bind "${FW2_MGMT_IP}:9601" \
    --cluster-advertise "${FW2_MGMT_IP}:9600" \
    --join "${FW1_MGMT_IP}:9600" \
    --cluster-data-dir "${STATE_DIR}/node2/cluster" \
    --node-id-path "${STATE_DIR}/node2/node_id" \
    --bootstrap-token-path "${STATE_DIR}/bootstrap.json" \
    --http-tls-dir "${STATE_DIR}/node2/http-tls" \
    >"$log" 2>&1 &
  echo $! >> "${STATE_DIR}/pids"
}

start_fw3() {
  local log="${LOG_DIR}/fw3.log"
  ip netns exec "$FW3_NS" "$FW_BIN" \
    --management-interface "$FW3_MGMT_IF" \
    --data-plane-interface "dp0" \
    --data-plane-mode tun \
    --default-policy "$DEFAULT_POLICY" \
    --dns-upstream "8.8.8.8:53" \
    --dns-listen "${FW3_MGMT_IP}:53" \
    --http-bind "${FW3_MGMT_IP}:8443" \
    --metrics-bind "${FW3_MGMT_IP}:8080" \
    --cluster-bind "${FW3_MGMT_IP}:9600" \
    --cluster-join-bind "${FW3_MGMT_IP}:9601" \
    --cluster-advertise "${FW3_MGMT_IP}:9600" \
    --join "${FW1_MGMT_IP}:9600" \
    --cluster-data-dir "${STATE_DIR}/node3/cluster" \
    --node-id-path "${STATE_DIR}/node3/node_id" \
    --bootstrap-token-path "${STATE_DIR}/bootstrap.json" \
    --http-tls-dir "${STATE_DIR}/node3/http-tls" \
    >"$log" 2>&1 &
  echo $! >> "${STATE_DIR}/pids"
}

up() {
  require_root
  need_cmd ip
  need_cmd iptables
  [[ -x "$FW_BIN" ]] || die "firewall binary not found: $FW_BIN (run cargo build)"

  if [[ -f "${STATE_DIR}/active" ]]; then
    die "state exists at ${STATE_DIR} (run ./scripts/ha_local.sh down first)"
  fi

  ensure_dirs
  save_default_route
  save_ip_forward
  gen_bootstrap_token

  sysctl -w net.ipv4.ip_forward=1 >/dev/null

  ip link add "$MGMT_BR" type bridge >/dev/null 2>&1 || true
  if ! ip addr show dev "$MGMT_BR" | grep -q "${MGMT_HOST_IP}/24"; then
    ip addr add "${MGMT_HOST_IP}/24" dev "$MGMT_BR"
  fi
  ip link set "$MGMT_BR" up

  create_netns "$FW1_NS"
  create_netns "$FW2_NS"
  create_netns "$FW3_NS"

  create_veth_pair "$FW1_NS" "$FW1_MGMT_IF" "$HOST_FW1_MGMT_IF"
  create_veth_pair "$FW2_NS" "$FW2_MGMT_IF" "$HOST_FW2_MGMT_IF"
  create_veth_pair "$FW3_NS" "$FW3_MGMT_IF" "$HOST_FW3_MGMT_IF"

  ip link set "$HOST_FW1_MGMT_IF" master "$MGMT_BR"
  ip link set "$HOST_FW2_MGMT_IF" master "$MGMT_BR"
  ip link set "$HOST_FW3_MGMT_IF" master "$MGMT_BR"
  ip link set "$HOST_FW1_MGMT_IF" up
  ip link set "$HOST_FW2_MGMT_IF" up
  ip link set "$HOST_FW3_MGMT_IF" up

  ip netns exec "$FW1_NS" ip addr add "${FW1_MGMT_IP}/24" dev "$FW1_MGMT_IF"
  ip netns exec "$FW2_NS" ip addr add "${FW2_MGMT_IP}/24" dev "$FW2_MGMT_IF"
  ip netns exec "$FW3_NS" ip addr add "${FW3_MGMT_IP}/24" dev "$FW3_MGMT_IF"
  ip netns exec "$FW1_NS" ip link set "$FW1_MGMT_IF" up
  ip netns exec "$FW2_NS" ip link set "$FW2_MGMT_IF" up
  ip netns exec "$FW3_NS" ip link set "$FW3_MGMT_IF" up

  create_veth_pair "$FW1_NS" "$FW1_IN_IF" "$HOST_IN_IF"
  create_veth_pair "$FW1_NS" "$FW1_UP_IF" "$HOST_UP_IF"

  ip addr add "${HOST_IN_IP}/24" dev "$HOST_IN_IF"
  ip link set "$HOST_IN_IF" up
  ip addr add "${HOST_UP_IP}/24" dev "$HOST_UP_IF"
  ip link set "$HOST_UP_IF" up

  ip netns exec "$FW1_NS" ip addr add "${FW1_IN_IP}/24" dev "$FW1_IN_IF"
  ip netns exec "$FW1_NS" ip link set "$FW1_IN_IF" up
  ip netns exec "$FW1_NS" ip addr add "${FW1_UP_IP}/24" dev "$FW1_UP_IF"
  ip netns exec "$FW1_NS" ip link set "$FW1_UP_IF" up

  ip netns exec "$FW1_NS" sysctl -w net.ipv4.ip_forward=1 >/dev/null
  ip netns exec "$FW1_NS" sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
  ip netns exec "$FW1_NS" sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null
  ip netns exec "$FW1_NS" ip route replace default via "$MGMT_HOST_IP" dev "$FW1_MGMT_IF"

  ip netns exec "$FW2_NS" ip route replace default via "$MGMT_HOST_IP" dev "$FW2_MGMT_IF"
  ip netns exec "$FW3_NS" ip route replace default via "$MGMT_HOST_IP" dev "$FW3_MGMT_IF"

  : > "${STATE_DIR}/pids"
  start_fw1
  start_fw2
  start_fw3

  if ! wait_link "$FW1_NS" "dp0"; then
    die "dp0 did not appear in ${FW1_NS} (check ${LOG_DIR}/fw1.log)"
  fi
  ip netns exec "$FW1_NS" ip link set "dp0" up
  ip netns exec "$FW1_NS" ip route replace default dev "dp0" table 100
  ip netns exec "$FW1_NS" ip route replace default dev "dp0" table 101
  ip netns exec "$FW1_NS" ip rule add iif "$FW1_IN_IF" lookup 100 priority 100 || true
  ip netns exec "$FW1_NS" ip rule add iif "$FW1_UP_IF" lookup 101 priority 101 || true

  iptables -t nat -C POSTROUTING -s "$UP_NET_CIDR" -o "$WAN_IFACE" -j MASQUERADE 2>/dev/null \
    || iptables -t nat -A POSTROUTING -s "$UP_NET_CIDR" -o "$WAN_IFACE" -j MASQUERADE
  iptables -C FORWARD -i "$WAN_IFACE" -o "$HOST_UP_IF" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null \
    || iptables -A FORWARD -i "$WAN_IFACE" -o "$HOST_UP_IF" -m state --state RELATED,ESTABLISHED -j ACCEPT
  iptables -C FORWARD -i "$HOST_UP_IF" -o "$WAN_IFACE" -j ACCEPT 2>/dev/null \
    || iptables -A FORWARD -i "$HOST_UP_IF" -o "$WAN_IFACE" -j ACCEPT

  ip route replace default via "$FW1_IN_IP" dev "$HOST_IN_IF"

  touch "${STATE_DIR}/active"

  cat <<EOF
HA lab up.
- UI: https://${FW1_MGMT_IP}:8443/
- Health: https://${FW1_MGMT_IP}:8443/health
- Logs: ${LOG_DIR}
- Default policy: ${DEFAULT_POLICY}
EOF
}

down() {
  require_root
  need_cmd ip
  need_cmd iptables

  if [[ -f "${STATE_DIR}/pids" ]]; then
    while read -r pid; do
      [[ -n "$pid" ]] || continue
      kill "$pid" >/dev/null 2>&1 || true
    done < "${STATE_DIR}/pids"
  fi

  iptables -t nat -D POSTROUTING -s "$UP_NET_CIDR" -o "$WAN_IFACE" -j MASQUERADE 2>/dev/null || true
  iptables -D FORWARD -i "$WAN_IFACE" -o "$HOST_UP_IF" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
  iptables -D FORWARD -i "$HOST_UP_IF" -o "$WAN_IFACE" -j ACCEPT 2>/dev/null || true

  ip netns del "$FW1_NS" 2>/dev/null || true
  ip netns del "$FW2_NS" 2>/dev/null || true
  ip netns del "$FW3_NS" 2>/dev/null || true

  ip link del "$HOST_IN_IF" 2>/dev/null || true
  ip link del "$HOST_UP_IF" 2>/dev/null || true
  ip link del "$HOST_FW1_MGMT_IF" 2>/dev/null || true
  ip link del "$HOST_FW2_MGMT_IF" 2>/dev/null || true
  ip link del "$HOST_FW3_MGMT_IF" 2>/dev/null || true
  ip link del "$MGMT_BR" 2>/dev/null || true

  restore_default_route
  restore_ip_forward

  rm -f "${STATE_DIR}/active" "${STATE_DIR}/pids" "${STATE_DIR}/default_route" "${STATE_DIR}/ip_forward"

  echo "HA lab down."
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  *)
    echo "usage: $0 up|down"
    exit 2
    ;;
esac
