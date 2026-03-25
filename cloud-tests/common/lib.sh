#!/usr/bin/env bash
set -euo pipefail

require_bin() {
  local bin="$1"
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo "missing required binary: $bin" >&2
    exit 1
  fi
}

ssh_jump() {
  local jump_host="$1"
  local key_path="$2"
  local target_host="$3"
  shift 3
  local ssh_user="${SSH_USER:-ubuntu}"
  local user_known_hosts="${SSH_USER_KNOWN_HOSTS_FILE:-/dev/null}"
  local connect_timeout_secs="${SSH_CONNECT_TIMEOUT_SECS:-10}"
  local server_alive_interval_secs="${SSH_SERVER_ALIVE_INTERVAL_SECS:-5}"
  local server_alive_count_max="${SSH_SERVER_ALIVE_COUNT_MAX:-3}"
  ssh-keygen -R "$jump_host" >/dev/null 2>&1 || true
  ssh-keygen -R "$target_host" >/dev/null 2>&1 || true
  ssh -o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes -i "$key_path" \
    -o BatchMode=yes \
    -o ConnectTimeout="$connect_timeout_secs" \
    -o ServerAliveInterval="$server_alive_interval_secs" \
    -o ServerAliveCountMax="$server_alive_count_max" \
    -o UserKnownHostsFile="$user_known_hosts" \
    -o ProxyCommand="ssh -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=${user_known_hosts} -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=${connect_timeout_secs} -o ServerAliveInterval=${server_alive_interval_secs} -o ServerAliveCountMax=${server_alive_count_max} -i ${key_path} -W %h:%p ${ssh_user}@${jump_host}" \
    "${ssh_user}@${target_host}" "$@"
}

wait_for_neuwerk_health() {
  local jump_host="$1"
  local key_path="$2"
  local target_host="$3"
  local attempts="${4:-60}"
  local sleep_secs="${5:-2}"
  local code
  local attempt

  for attempt in $(seq 1 "$attempts"); do
    code="$(ssh_jump "$jump_host" "$key_path" "$target_host" \
      "curl -sk -o /dev/null -w '%{http_code}' --connect-timeout 3 --max-time 8 https://${target_host}:8443/health" \
      2>/dev/null || true)"
    code="$(echo "$code" | tail -n1 | tr -d '\r')"
    if [ "$code" = "200" ]; then
      return 0
    fi
    sleep "$sleep_secs"
  done

  return 1
}

ensure_neuwerk_dpdk_runtime_overrides() {
  local jump_host="$1"
  local key_path="$2"
  local fw_mgmt_ips="$3"

  local dpdk_workers="${DPDK_WORKERS:-}"
  local dpdk_allow_azure_multiworker="${DPDK_ALLOW_AZURE_MULTIWORKER:-}"
  local dpdk_allow_retaless_multi_queue="${DPDK_ALLOW_RETALESS_MULTI_QUEUE:-}"
  local dpdk_single_queue_mode="${DPDK_SINGLE_QUEUE_MODE:-}"
  local dpdk_force_shared_rx_demux="${DPDK_FORCE_SHARED_RX_DEMUX:-}"
  local dpdk_housekeeping_interval_packets="${DPDK_HOUSEKEEPING_INTERVAL_PACKETS:-}"
  local dpdk_housekeeping_interval_us="${DPDK_HOUSEKEEPING_INTERVAL_US:-}"
  local dpdk_perf_mode="${DPDK_PERF_MODE:-}"
  local dpdk_disable_service_lane="${DPDK_DISABLE_SERVICE_LANE:-}"
  local dpdk_pin_https_owner="${DPDK_PIN_HTTPS_OWNER:-}"
  local dpdk_pin_state_shard_guard="${DPDK_PIN_STATE_SHARD_GUARD:-}"
  local dpdk_pin_state_shard_burst="${DPDK_PIN_STATE_SHARD_BURST:-}"
  local dpdk_shared_rx_owner_only="${DPDK_SHARED_RX_OWNER_ONLY:-}"
  local dpdk_lockless_qpw="${DPDK_LOCKLESS_QPW:-}"
  local dpdk_rx_ring_size="${DPDK_RX_RING_SIZE:-}"
  local dpdk_tx_ring_size="${DPDK_TX_RING_SIZE:-}"
  local dpdk_mbuf_pool_size="${DPDK_MBUF_POOL_SIZE:-}"
  local dpdk_syn_only_table="${DPDK_SYN_ONLY_TABLE:-}"
  local flow_table_capacity="${NEUWERK_FLOW_TABLE_CAPACITY:-}"
  local flow_incomplete_tcp_idle_timeout_secs="${NEUWERK_FLOW_INCOMPLETE_TCP_IDLE_TIMEOUT_SECS:-}"
  local flow_incomplete_tcp_syn_sent_idle_timeout_secs="${NEUWERK_FLOW_INCOMPLETE_TCP_SYN_SENT_IDLE_TIMEOUT_SECS:-}"
  local dp_max_active_flows="${NEUWERK_DP_MAX_ACTIVE_FLOWS:-}"
  local dp_max_active_nat_entries="${NEUWERK_DP_MAX_ACTIVE_NAT_ENTRIES:-}"
  local dp_max_pending_tls_flows="${NEUWERK_DP_MAX_PENDING_TLS_FLOWS:-}"
  local dp_max_active_flows_per_source_group="${NEUWERK_DP_MAX_ACTIVE_FLOWS_PER_SOURCE_GROUP:-}"
  local dpdk_gateway_mac="${NEUWERK_DPDK_GATEWAY_MAC:-}"
  local dpdk_dhcp_server_ip="${NEUWERK_DPDK_DHCP_SERVER_IP:-}"
  local dpdk_dhcp_server_mac="${NEUWERK_DPDK_DHCP_SERVER_MAC:-}"

  local ip env_dump
  for ip in $fw_mgmt_ips; do
    echo "ensuring DPDK runtime overrides on ${ip}"
    ssh_jump "$jump_host" "$key_path" "$ip" \
      "env DPDK_WORKERS='${dpdk_workers}' DPDK_ALLOW_AZURE_MULTIWORKER='${dpdk_allow_azure_multiworker}' DPDK_ALLOW_RETALESS_MULTI_QUEUE='${dpdk_allow_retaless_multi_queue}' DPDK_SINGLE_QUEUE_MODE='${dpdk_single_queue_mode}' DPDK_FORCE_SHARED_RX_DEMUX='${dpdk_force_shared_rx_demux}' DPDK_HOUSEKEEPING_INTERVAL_PACKETS='${dpdk_housekeeping_interval_packets}' DPDK_HOUSEKEEPING_INTERVAL_US='${dpdk_housekeeping_interval_us}' DPDK_PERF_MODE='${dpdk_perf_mode}' DPDK_DISABLE_SERVICE_LANE='${dpdk_disable_service_lane}' DPDK_PIN_HTTPS_OWNER='${dpdk_pin_https_owner}' DPDK_PIN_STATE_SHARD_GUARD='${dpdk_pin_state_shard_guard}' DPDK_PIN_STATE_SHARD_BURST='${dpdk_pin_state_shard_burst}' DPDK_SHARED_RX_OWNER_ONLY='${dpdk_shared_rx_owner_only}' DPDK_LOCKLESS_QPW='${dpdk_lockless_qpw}' DPDK_RX_RING_SIZE='${dpdk_rx_ring_size}' DPDK_TX_RING_SIZE='${dpdk_tx_ring_size}' DPDK_MBUF_POOL_SIZE='${dpdk_mbuf_pool_size}' DPDK_SYN_ONLY_TABLE='${dpdk_syn_only_table}' NEUWERK_FLOW_TABLE_CAPACITY='${flow_table_capacity}' NEUWERK_FLOW_INCOMPLETE_TCP_IDLE_TIMEOUT_SECS='${flow_incomplete_tcp_idle_timeout_secs}' NEUWERK_FLOW_INCOMPLETE_TCP_SYN_SENT_IDLE_TIMEOUT_SECS='${flow_incomplete_tcp_syn_sent_idle_timeout_secs}' NEUWERK_DP_MAX_ACTIVE_FLOWS='${dp_max_active_flows}' NEUWERK_DP_MAX_ACTIVE_NAT_ENTRIES='${dp_max_active_nat_entries}' NEUWERK_DP_MAX_PENDING_TLS_FLOWS='${dp_max_pending_tls_flows}' NEUWERK_DP_MAX_ACTIVE_FLOWS_PER_SOURCE_GROUP='${dp_max_active_flows_per_source_group}' NEUWERK_DPDK_GATEWAY_MAC='${dpdk_gateway_mac}' NEUWERK_DPDK_DHCP_SERVER_IP='${dpdk_dhcp_server_ip}' NEUWERK_DPDK_DHCP_SERVER_MAC='${dpdk_dhcp_server_mac}' bash -s" <<'EOS'
set -euo pipefail

path="/etc/systemd/system/neuwerk.service.d/95-benchmark-dpdk.conf"
env_file="/etc/neuwerk/neuwerk.env"
sudo mkdir -p /etc/systemd/system/neuwerk.service.d

desired="$(cat <<'EOC'
[Service]
EOC
)"

has_overrides=0
append_env() {
  local key="$1"
  local value="$2"
  if [ -n "$value" ]; then
    desired="${desired}"$'\n'"Environment=${key}=${value}"
    has_overrides=1
  fi
}

append_env "NEUWERK_DPDK_WORKERS" "${DPDK_WORKERS}"
append_env "NEUWERK_DPDK_ALLOW_AZURE_MULTIWORKER" "${DPDK_ALLOW_AZURE_MULTIWORKER}"
append_env "NEUWERK_DPDK_ALLOW_RETALESS_MULTI_QUEUE" "${DPDK_ALLOW_RETALESS_MULTI_QUEUE}"
append_env "NEUWERK_DPDK_SINGLE_QUEUE_MODE" "${DPDK_SINGLE_QUEUE_MODE}"
append_env "NEUWERK_DPDK_FORCE_SHARED_RX_DEMUX" "${DPDK_FORCE_SHARED_RX_DEMUX}"
append_env "NEUWERK_DPDK_HOUSEKEEPING_INTERVAL_PACKETS" "${DPDK_HOUSEKEEPING_INTERVAL_PACKETS}"
append_env "NEUWERK_DPDK_HOUSEKEEPING_INTERVAL_US" "${DPDK_HOUSEKEEPING_INTERVAL_US}"
append_env "NEUWERK_DPDK_PERF_MODE" "${DPDK_PERF_MODE}"
append_env "NEUWERK_DPDK_DISABLE_SERVICE_LANE" "${DPDK_DISABLE_SERVICE_LANE}"
append_env "NEUWERK_DPDK_PIN_HTTPS_OWNER" "${DPDK_PIN_HTTPS_OWNER}"
append_env "NEUWERK_DPDK_PIN_STATE_SHARD_GUARD" "${DPDK_PIN_STATE_SHARD_GUARD}"
append_env "NEUWERK_DPDK_PIN_STATE_SHARD_BURST" "${DPDK_PIN_STATE_SHARD_BURST}"
append_env "NEUWERK_DPDK_SHARED_RX_OWNER_ONLY" "${DPDK_SHARED_RX_OWNER_ONLY}"
append_env "NEUWERK_DPDK_LOCKLESS_QPW" "${DPDK_LOCKLESS_QPW}"
append_env "NEUWERK_DPDK_RX_RING_SIZE" "${DPDK_RX_RING_SIZE}"
append_env "NEUWERK_DPDK_TX_RING_SIZE" "${DPDK_TX_RING_SIZE}"
append_env "NEUWERK_DPDK_MBUF_POOL_SIZE" "${DPDK_MBUF_POOL_SIZE}"
append_env "NEUWERK_DPDK_SYN_ONLY_TABLE" "${DPDK_SYN_ONLY_TABLE}"
append_env "NEUWERK_FLOW_TABLE_CAPACITY" "${NEUWERK_FLOW_TABLE_CAPACITY}"
append_env "NEUWERK_FLOW_INCOMPLETE_TCP_IDLE_TIMEOUT_SECS" "${NEUWERK_FLOW_INCOMPLETE_TCP_IDLE_TIMEOUT_SECS}"
append_env "NEUWERK_FLOW_INCOMPLETE_TCP_SYN_SENT_IDLE_TIMEOUT_SECS" "${NEUWERK_FLOW_INCOMPLETE_TCP_SYN_SENT_IDLE_TIMEOUT_SECS}"
append_env "NEUWERK_DP_MAX_ACTIVE_FLOWS" "${NEUWERK_DP_MAX_ACTIVE_FLOWS}"
append_env "NEUWERK_DP_MAX_ACTIVE_NAT_ENTRIES" "${NEUWERK_DP_MAX_ACTIVE_NAT_ENTRIES}"
append_env "NEUWERK_DP_MAX_PENDING_TLS_FLOWS" "${NEUWERK_DP_MAX_PENDING_TLS_FLOWS}"
append_env "NEUWERK_DP_MAX_ACTIVE_FLOWS_PER_SOURCE_GROUP" "${NEUWERK_DP_MAX_ACTIVE_FLOWS_PER_SOURCE_GROUP}"
append_env "NEUWERK_DPDK_GATEWAY_MAC" "${NEUWERK_DPDK_GATEWAY_MAC}"
append_env "NEUWERK_DPDK_DHCP_SERVER_IP" "${NEUWERK_DPDK_DHCP_SERVER_IP}"
append_env "NEUWERK_DPDK_DHCP_SERVER_MAC" "${NEUWERK_DPDK_DHCP_SERVER_MAC}"

current="$(sudo cat "$path" 2>/dev/null || true)"
changed=0

if [ -n "${DPDK_WORKERS}" ] && sudo test -f "$env_file"; then
  current_worker_line="$(sudo grep -E '^NEUWERK_DPDK_WORKERS=' "$env_file" 2>/dev/null || true)"
  desired_worker_line="NEUWERK_DPDK_WORKERS=${DPDK_WORKERS}"
  if [ "$current_worker_line" != "$desired_worker_line" ]; then
    tmp_env="$(mktemp)"
    sudo cat "$env_file" > "$tmp_env"
    if grep -q '^NEUWERK_DPDK_WORKERS=' "$tmp_env"; then
      sed -i "s/^NEUWERK_DPDK_WORKERS=.*/${desired_worker_line}/" "$tmp_env"
    else
      printf '\n%s\n' "$desired_worker_line" >> "$tmp_env"
    fi
    sudo install -m 0644 "$tmp_env" "$env_file"
    rm -f "$tmp_env"
    changed=1
  fi
fi

if [ "$has_overrides" = "1" ]; then
  if [ "$current" != "$desired" ]; then
    printf '%s\n' "$desired" | sudo tee "$path" >/dev/null
    changed=1
  fi
else
  if sudo test -f "$path"; then
    sudo rm -f "$path"
    changed=1
  fi
fi

if [ "$changed" = "1" ]; then
  sudo systemctl daemon-reload
  sudo systemctl reset-failed neuwerk.service || true
  sudo systemctl restart neuwerk.service
fi
EOS

    if ! wait_for_neuwerk_health "$jump_host" "$key_path" "$ip"; then
      echo "neuwerk health check failed after DPDK runtime override on ${ip}" >&2
      ssh_jump "$jump_host" "$key_path" "$ip" \
        "sudo systemctl status neuwerk.service --no-pager -n 80; sudo journalctl -u neuwerk.service -n 120 --no-pager" \
        || true
      return 1
    fi

    env_dump="$(ssh_jump "$jump_host" "$key_path" "$ip" "sudo systemctl show neuwerk.service -p Environment --value" 2>/dev/null || true)"
    if [ -n "$dpdk_workers" ] && ! grep -q "NEUWERK_DPDK_WORKERS=${dpdk_workers}" <<<"$env_dump"; then
      echo "runtime override verification failed on ${ip}: missing NEUWERK_DPDK_WORKERS=${dpdk_workers}" >&2
      echo "$env_dump" >&2
      return 1
    fi
    if [ -n "$dpdk_allow_azure_multiworker" ] && ! grep -q "NEUWERK_DPDK_ALLOW_AZURE_MULTIWORKER=${dpdk_allow_azure_multiworker}" <<<"$env_dump"; then
      echo "runtime override verification failed on ${ip}: missing NEUWERK_DPDK_ALLOW_AZURE_MULTIWORKER=${dpdk_allow_azure_multiworker}" >&2
      echo "$env_dump" >&2
      return 1
    fi
    if [ -n "$dpdk_allow_retaless_multi_queue" ] && ! grep -q "NEUWERK_DPDK_ALLOW_RETALESS_MULTI_QUEUE=${dpdk_allow_retaless_multi_queue}" <<<"$env_dump"; then
      echo "runtime override verification failed on ${ip}: missing NEUWERK_DPDK_ALLOW_RETALESS_MULTI_QUEUE=${dpdk_allow_retaless_multi_queue}" >&2
      echo "$env_dump" >&2
      return 1
    fi
    if [ -n "$dpdk_single_queue_mode" ] && ! grep -q "NEUWERK_DPDK_SINGLE_QUEUE_MODE=${dpdk_single_queue_mode}" <<<"$env_dump"; then
      echo "runtime override verification failed on ${ip}: missing NEUWERK_DPDK_SINGLE_QUEUE_MODE=${dpdk_single_queue_mode}" >&2
      echo "$env_dump" >&2
      return 1
    fi
    if [ -n "$dpdk_force_shared_rx_demux" ] && ! grep -q "NEUWERK_DPDK_FORCE_SHARED_RX_DEMUX=${dpdk_force_shared_rx_demux}" <<<"$env_dump"; then
      echo "runtime override verification failed on ${ip}: missing NEUWERK_DPDK_FORCE_SHARED_RX_DEMUX=${dpdk_force_shared_rx_demux}" >&2
      echo "$env_dump" >&2
      return 1
    fi
    if [ -n "$dpdk_housekeeping_interval_packets" ] && ! grep -q "NEUWERK_DPDK_HOUSEKEEPING_INTERVAL_PACKETS=${dpdk_housekeeping_interval_packets}" <<<"$env_dump"; then
      echo "runtime override verification failed on ${ip}: missing NEUWERK_DPDK_HOUSEKEEPING_INTERVAL_PACKETS=${dpdk_housekeeping_interval_packets}" >&2
      echo "$env_dump" >&2
      return 1
    fi
    if [ -n "$dpdk_housekeeping_interval_us" ] && ! grep -q "NEUWERK_DPDK_HOUSEKEEPING_INTERVAL_US=${dpdk_housekeeping_interval_us}" <<<"$env_dump"; then
      echo "runtime override verification failed on ${ip}: missing NEUWERK_DPDK_HOUSEKEEPING_INTERVAL_US=${dpdk_housekeeping_interval_us}" >&2
      echo "$env_dump" >&2
      return 1
    fi
    if [ -n "$dpdk_perf_mode" ] && ! grep -q "NEUWERK_DPDK_PERF_MODE=${dpdk_perf_mode}" <<<"$env_dump"; then
      echo "runtime override verification failed on ${ip}: missing NEUWERK_DPDK_PERF_MODE=${dpdk_perf_mode}" >&2
      echo "$env_dump" >&2
      return 1
    fi
    if [ -n "$dpdk_disable_service_lane" ] && ! grep -q "NEUWERK_DPDK_DISABLE_SERVICE_LANE=${dpdk_disable_service_lane}" <<<"$env_dump"; then
      echo "runtime override verification failed on ${ip}: missing NEUWERK_DPDK_DISABLE_SERVICE_LANE=${dpdk_disable_service_lane}" >&2
      echo "$env_dump" >&2
      return 1
    fi
    if [ -n "$dpdk_pin_https_owner" ] && ! grep -q "NEUWERK_DPDK_PIN_HTTPS_OWNER=${dpdk_pin_https_owner}" <<<"$env_dump"; then
      echo "runtime override verification failed on ${ip}: missing NEUWERK_DPDK_PIN_HTTPS_OWNER=${dpdk_pin_https_owner}" >&2
      echo "$env_dump" >&2
      return 1
    fi
    if [ -n "$dpdk_pin_state_shard_guard" ] && ! grep -q "NEUWERK_DPDK_PIN_STATE_SHARD_GUARD=${dpdk_pin_state_shard_guard}" <<<"$env_dump"; then
      echo "runtime override verification failed on ${ip}: missing NEUWERK_DPDK_PIN_STATE_SHARD_GUARD=${dpdk_pin_state_shard_guard}" >&2
      echo "$env_dump" >&2
      return 1
    fi
    if [ -n "$dpdk_pin_state_shard_burst" ] && ! grep -q "NEUWERK_DPDK_PIN_STATE_SHARD_BURST=${dpdk_pin_state_shard_burst}" <<<"$env_dump"; then
      echo "runtime override verification failed on ${ip}: missing NEUWERK_DPDK_PIN_STATE_SHARD_BURST=${dpdk_pin_state_shard_burst}" >&2
      echo "$env_dump" >&2
      return 1
    fi
    if [ -n "$dpdk_shared_rx_owner_only" ] && ! grep -q "NEUWERK_DPDK_SHARED_RX_OWNER_ONLY=${dpdk_shared_rx_owner_only}" <<<"$env_dump"; then
      echo "runtime override verification failed on ${ip}: missing NEUWERK_DPDK_SHARED_RX_OWNER_ONLY=${dpdk_shared_rx_owner_only}" >&2
      echo "$env_dump" >&2
      return 1
    fi
    if [ -n "$dpdk_lockless_qpw" ] && ! grep -q "NEUWERK_DPDK_LOCKLESS_QPW=${dpdk_lockless_qpw}" <<<"$env_dump"; then
      echo "runtime override verification failed on ${ip}: missing NEUWERK_DPDK_LOCKLESS_QPW=${dpdk_lockless_qpw}" >&2
      echo "$env_dump" >&2
      return 1
    fi
    if [ -n "$dpdk_rx_ring_size" ] && ! grep -q "NEUWERK_DPDK_RX_RING_SIZE=${dpdk_rx_ring_size}" <<<"$env_dump"; then
      echo "runtime override verification failed on ${ip}: missing NEUWERK_DPDK_RX_RING_SIZE=${dpdk_rx_ring_size}" >&2
      echo "$env_dump" >&2
      return 1
    fi
    if [ -n "$dpdk_tx_ring_size" ] && ! grep -q "NEUWERK_DPDK_TX_RING_SIZE=${dpdk_tx_ring_size}" <<<"$env_dump"; then
      echo "runtime override verification failed on ${ip}: missing NEUWERK_DPDK_TX_RING_SIZE=${dpdk_tx_ring_size}" >&2
      echo "$env_dump" >&2
      return 1
    fi
    if [ -n "$dpdk_mbuf_pool_size" ] && ! grep -q "NEUWERK_DPDK_MBUF_POOL_SIZE=${dpdk_mbuf_pool_size}" <<<"$env_dump"; then
      echo "runtime override verification failed on ${ip}: missing NEUWERK_DPDK_MBUF_POOL_SIZE=${dpdk_mbuf_pool_size}" >&2
      echo "$env_dump" >&2
      return 1
    fi
    if [ -n "$dpdk_syn_only_table" ] && ! grep -q "NEUWERK_DPDK_SYN_ONLY_TABLE=${dpdk_syn_only_table}" <<<"$env_dump"; then
      echo "runtime override verification failed on ${ip}: missing NEUWERK_DPDK_SYN_ONLY_TABLE=${dpdk_syn_only_table}" >&2
      echo "$env_dump" >&2
      return 1
    fi
    if [ -n "$flow_table_capacity" ] && ! grep -q "NEUWERK_FLOW_TABLE_CAPACITY=${flow_table_capacity}" <<<"$env_dump"; then
      echo "runtime override verification failed on ${ip}: missing NEUWERK_FLOW_TABLE_CAPACITY=${flow_table_capacity}" >&2
      echo "$env_dump" >&2
      return 1
    fi
    if [ -n "$flow_incomplete_tcp_idle_timeout_secs" ] && ! grep -q "NEUWERK_FLOW_INCOMPLETE_TCP_IDLE_TIMEOUT_SECS=${flow_incomplete_tcp_idle_timeout_secs}" <<<"$env_dump"; then
      echo "runtime override verification failed on ${ip}: missing NEUWERK_FLOW_INCOMPLETE_TCP_IDLE_TIMEOUT_SECS=${flow_incomplete_tcp_idle_timeout_secs}" >&2
      echo "$env_dump" >&2
      return 1
    fi
    if [ -n "$flow_incomplete_tcp_syn_sent_idle_timeout_secs" ] && ! grep -q "NEUWERK_FLOW_INCOMPLETE_TCP_SYN_SENT_IDLE_TIMEOUT_SECS=${flow_incomplete_tcp_syn_sent_idle_timeout_secs}" <<<"$env_dump"; then
      echo "runtime override verification failed on ${ip}: missing NEUWERK_FLOW_INCOMPLETE_TCP_SYN_SENT_IDLE_TIMEOUT_SECS=${flow_incomplete_tcp_syn_sent_idle_timeout_secs}" >&2
      echo "$env_dump" >&2
      return 1
    fi
  done
}
