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

neuwerk_runtime_config_overrides_active() {
  local var
  for var in \
    DPDK_WORKERS \
    DPDK_ALLOW_AZURE_MULTIWORKER \
    DPDK_ALLOW_RETALESS_MULTI_QUEUE \
    DPDK_SINGLE_QUEUE_MODE \
    DPDK_FORCE_SHARED_RX_DEMUX \
    DPDK_HOUSEKEEPING_INTERVAL_PACKETS \
    DPDK_HOUSEKEEPING_INTERVAL_US \
    DPDK_PERF_MODE \
    DPDK_DISABLE_SERVICE_LANE \
    DPDK_PIN_HTTPS_OWNER \
    DPDK_PIN_STATE_SHARD_GUARD \
    DPDK_PIN_STATE_SHARD_BURST \
    DPDK_SHARED_RX_OWNER_ONLY \
    DPDK_LOCKLESS_QPW \
    DPDK_RX_RING_SIZE \
    DPDK_TX_RING_SIZE \
    DPDK_MBUF_POOL_SIZE \
    DPDK_SYN_ONLY_TABLE \
    NEUWERK_FLOW_TABLE_CAPACITY \
    NEUWERK_FLOW_INCOMPLETE_TCP_IDLE_TIMEOUT_SECS \
    NEUWERK_FLOW_INCOMPLETE_TCP_SYN_SENT_IDLE_TIMEOUT_SECS \
    NEUWERK_DP_MAX_ACTIVE_FLOWS \
    NEUWERK_DP_MAX_ACTIVE_NAT_ENTRIES \
    NEUWERK_DP_MAX_PENDING_TLS_FLOWS \
    NEUWERK_DP_MAX_ACTIVE_FLOWS_PER_SOURCE_GROUP \
    NEUWERK_DPDK_GATEWAY_MAC \
    NEUWERK_DPDK_DHCP_SERVER_IP \
    NEUWERK_DPDK_DHCP_SERVER_MAC \
    CONTROLPLANE_WORKER_THREADS \
    TLS_INTERCEPT_UPSTREAM_VERIFY \
    TLS_INTERCEPT_IO_TIMEOUT_SECS \
    TLS_INTERCEPT_H2_BODY_TIMEOUT_SECS \
    TLS_H2_MAX_CONCURRENT_STREAMS \
    TLS_H2_MAX_REQUESTS_PER_CONNECTION \
    TLS_H2_POOL_SHARDS \
    TLS_H2_DETAILED_METRICS \
    TLS_H2_SELECTION_INFLIGHT_WEIGHT \
    TLS_INTERCEPT_LISTEN_BACKLOG; do
    if [ -n "${!var:-}" ]; then
      return 0
    fi
  done
  return 1
}

fail_on_removed_runtime_override_knobs() {
  return 0
}

render_neuwerk_runtime_config_override() {
  local base_config="$1"
  local out_config="$2"

  BASE_CONFIG="$base_config" OUT_CONFIG="$out_config" python3 - <<'PY'
import os
from pathlib import Path

import yaml

base_path = Path(os.environ["BASE_CONFIG"])
out_path = Path(os.environ["OUT_CONFIG"])
data = yaml.safe_load(base_path.read_text(encoding="utf-8")) or {}
if not isinstance(data, dict):
    raise SystemExit("expected mapping at top level of config.yaml")


def env(name: str):
    value = os.environ.get(name)
    if value is None:
        return None
    value = value.strip()
    return value if value else None


def ensure_path(parts):
    cursor = data
    for part in parts:
        child = cursor.get(part)
        if not isinstance(child, dict):
            child = {}
            cursor[part] = child
        cursor = child
    return cursor


def set_path(parts, value):
    cursor = ensure_path(parts[:-1])
    cursor[parts[-1]] = value


def parse_bool(name: str):
    raw = env(name)
    if raw is None:
      return None
    lowered = raw.lower()
    if lowered in {"1", "true", "yes", "on"}:
        return True
    if lowered in {"0", "false", "no", "off"}:
        return False
    raise SystemExit(f"unsupported boolean for {name}: {raw}")


def parse_int(name: str):
    raw = env(name)
    if raw is None:
        return None
    return int(raw, 10)


workers = env("DPDK_WORKERS")
if workers is not None:
    set_path(["dpdk", "workers"], workers if workers.lower() == "auto" else int(workers, 10))

for name, path in [
    ("DPDK_ALLOW_AZURE_MULTIWORKER", ["dpdk", "allow_azure_multiworker"]),
    ("DPDK_ALLOW_RETALESS_MULTI_QUEUE", ["dpdk", "allow_retaless_multi_queue"]),
    ("DPDK_FORCE_SHARED_RX_DEMUX", ["dpdk", "force_shared_rx_demux"]),
    ("DPDK_DISABLE_SERVICE_LANE", ["dpdk", "disable_service_lane"]),
    ("DPDK_PIN_HTTPS_OWNER", ["dpdk", "pin_https_demux_owner"]),
    ("DPDK_PIN_STATE_SHARD_GUARD", ["dpdk", "pin_state_shard_guard"]),
    ("DPDK_SHARED_RX_OWNER_ONLY", ["dpdk", "shared_rx_owner_only"]),
    ("DPDK_LOCKLESS_QPW", ["dpdk", "lockless_queue_per_worker"]),
    ("DPDK_SYN_ONLY_TABLE", ["dataplane", "syn_only_enabled"]),
    ("TLS_H2_DETAILED_METRICS", ["tls_intercept", "h2", "detailed_metrics"]),
]:
    value = parse_bool(name)
    if value is not None:
        set_path(path, value)

for name, path in [
    ("DPDK_SINGLE_QUEUE_MODE", ["dpdk", "single_queue_mode"]),
    ("DPDK_PERF_MODE", ["dpdk", "perf_mode"]),
    ("NEUWERK_DPDK_GATEWAY_MAC", ["dpdk", "gateway_mac"]),
    ("NEUWERK_DPDK_DHCP_SERVER_IP", ["dpdk", "dhcp_server_ip"]),
    ("NEUWERK_DPDK_DHCP_SERVER_MAC", ["dpdk", "dhcp_server_mac"]),
    ("TLS_INTERCEPT_UPSTREAM_VERIFY", ["tls_intercept", "upstream_verify"]),
]:
    value = env(name)
    if value is not None:
        set_path(path, value)

for name, path in [
    ("DPDK_HOUSEKEEPING_INTERVAL_PACKETS", ["dpdk", "housekeeping_interval_packets"]),
    ("DPDK_HOUSEKEEPING_INTERVAL_US", ["dpdk", "housekeeping_interval_us"]),
    ("DPDK_PIN_STATE_SHARD_BURST", ["dpdk", "pin_state_shard_burst"]),
    ("DPDK_RX_RING_SIZE", ["dpdk", "rx_ring_size"]),
    ("DPDK_TX_RING_SIZE", ["dpdk", "tx_ring_size"]),
    ("DPDK_MBUF_POOL_SIZE", ["dpdk", "mbuf_pool_size"]),
    ("NEUWERK_FLOW_TABLE_CAPACITY", ["dataplane", "flow_table_capacity"]),
    ("NEUWERK_FLOW_INCOMPLETE_TCP_IDLE_TIMEOUT_SECS", ["dataplane", "flow_incomplete_tcp_idle_timeout_secs"]),
    ("NEUWERK_FLOW_INCOMPLETE_TCP_SYN_SENT_IDLE_TIMEOUT_SECS", ["dataplane", "flow_incomplete_tcp_syn_sent_idle_timeout_secs"]),
    ("NEUWERK_DP_MAX_ACTIVE_FLOWS", ["dataplane", "admission", "max_active_flows"]),
    ("NEUWERK_DP_MAX_ACTIVE_NAT_ENTRIES", ["dataplane", "admission", "max_active_nat_entries"]),
    ("NEUWERK_DP_MAX_PENDING_TLS_FLOWS", ["dataplane", "admission", "max_pending_tls_flows"]),
    ("NEUWERK_DP_MAX_ACTIVE_FLOWS_PER_SOURCE_GROUP", ["dataplane", "admission", "max_active_flows_per_source_group"]),
    ("CONTROLPLANE_WORKER_THREADS", ["runtime", "controlplane_worker_threads"]),
    ("TLS_INTERCEPT_IO_TIMEOUT_SECS", ["tls_intercept", "io_timeout_secs"]),
    ("TLS_INTERCEPT_H2_BODY_TIMEOUT_SECS", ["tls_intercept", "h2", "body_timeout_secs"]),
    ("TLS_H2_MAX_CONCURRENT_STREAMS", ["tls_intercept", "h2", "max_concurrent_streams"]),
    ("TLS_H2_MAX_REQUESTS_PER_CONNECTION", ["tls_intercept", "h2", "max_requests_per_connection"]),
    ("TLS_H2_POOL_SHARDS", ["tls_intercept", "h2", "pool_shards"]),
    ("TLS_H2_SELECTION_INFLIGHT_WEIGHT", ["tls_intercept", "h2", "selection_inflight_weight"]),
    ("TLS_INTERCEPT_LISTEN_BACKLOG", ["tls_intercept", "listen_backlog"]),
]:
    value = parse_int(name)
    if value is not None:
        set_path(path, value)

out_path.write_text(
    yaml.safe_dump(data, sort_keys=False, default_flow_style=False),
    encoding="utf-8",
)
PY
}

apply_neuwerk_runtime_config_overrides_host() {
  local jump_host="$1"
  local key_path="$2"
  local target_host="$3"
  local remote_state_dir="/var/lib/neuwerk/cloud-tests"
  local remote_base_config="${remote_state_dir}/base-config.yaml"
  local remote_config="/etc/neuwerk/config.yaml"
  local remote_tmp_config="/var/tmp/neuwerk-config-override-$$.yaml"
  local local_base
  local local_current
  local local_target
  local changed=0

  fail_on_removed_runtime_override_knobs

  local_base="$(mktemp)"
  local_current="$(mktemp)"
  local_target="$(mktemp)"
  cleanup_neuwerk_config_override_tmp() {
    rm -f "$local_base" "$local_current" "$local_target"
  }
  trap cleanup_neuwerk_config_override_tmp RETURN

  if neuwerk_runtime_config_overrides_active; then
    ssh_jump "$jump_host" "$key_path" "$target_host" \
      "sudo mkdir -p '${remote_state_dir}'; if [ ! -f '${remote_base_config}' ]; then sudo cp '${remote_config}' '${remote_base_config}'; fi"
    ssh_jump "$jump_host" "$key_path" "$target_host" "sudo cat '${remote_base_config}'" >"$local_base"
    render_neuwerk_runtime_config_override "$local_base" "$local_target"
  else
    if ! ssh_jump "$jump_host" "$key_path" "$target_host" "sudo test -f '${remote_base_config}'"; then
      return 0
    fi
    ssh_jump "$jump_host" "$key_path" "$target_host" "sudo cat '${remote_base_config}'" >"$local_target"
  fi

  ssh_jump "$jump_host" "$key_path" "$target_host" "sudo cat '${remote_config}'" >"$local_current"
  if ! cmp -s "$local_current" "$local_target"; then
    ssh_jump "$jump_host" "$key_path" "$target_host" "cat > '${remote_tmp_config}'" <"$local_target"
    ssh_jump "$jump_host" "$key_path" "$target_host" \
      "sudo install -m 0644 '${remote_tmp_config}' '${remote_config}'; rm -f '${remote_tmp_config}'"
    changed=1
  fi

  if neuwerk_runtime_config_overrides_active; then
    :
  else
    ssh_jump "$jump_host" "$key_path" "$target_host" "sudo rm -f '${remote_base_config}'"
  fi

  if [ "$changed" = "1" ]; then
    ssh_jump "$jump_host" "$key_path" "$target_host" \
      "sudo systemctl reset-failed neuwerk.service || true; sudo systemctl restart neuwerk.service"
  fi

  if ! wait_for_neuwerk_health "$jump_host" "$key_path" "$target_host"; then
    echo "neuwerk health check failed after runtime config override on ${target_host}" >&2
    ssh_jump "$jump_host" "$key_path" "$target_host" \
      "sudo systemctl status neuwerk.service --no-pager -n 80; sudo journalctl -u neuwerk.service -n 120 --no-pager" \
      || true
    return 1
  fi

  ssh_jump "$jump_host" "$key_path" "$target_host" "sudo cat '${remote_config}'" >"$local_current"
  if ! cmp -s "$local_current" "$local_target"; then
    echo "runtime config verification failed on ${target_host}: ${remote_config} does not match rendered override" >&2
    diff -u "$local_target" "$local_current" >&2 || true
    return 1
  fi
}

ensure_neuwerk_runtime_config_overrides() {
  local jump_host="$1"
  local key_path="$2"
  local fw_mgmt_ips="$3"

  local ip
  for ip in $fw_mgmt_ips; do
    echo "ensuring runtime config overrides on ${ip}"
    apply_neuwerk_runtime_config_overrides_host "$jump_host" "$key_path" "$ip"
  done
}

ensure_neuwerk_dpdk_runtime_overrides() {
  ensure_neuwerk_runtime_config_overrides "$@"
}

fetch_neuwerk_metrics() {
  local jump_host="$1"
  local key_path="$2"
  local target_host="$3"

  ssh_jump "$jump_host" "$key_path" "$target_host" "bash -s" <<'EOS'
set -euo pipefail

candidate_urls() {
  local listener
  listener="$(ss -lntH '( sport = :8080 )' 2>/dev/null | awk 'NR == 1 {print $4; exit}')"
  if [ -n "$listener" ]; then
    case "$listener" in
      0.0.0.0:*)
        printf 'http://127.0.0.1:%s/metrics\n' "${listener##*:}"
        ;;
      \*:* )
        printf 'http://127.0.0.1:%s/metrics\n' "${listener##*:}"
        ;;
      \[*\]:*)
        case "$listener" in
          "[::]:"*)
            printf 'http://[::1]:%s/metrics\n' "${listener##*:}"
            ;;
          *)
            printf 'http://%s/metrics\n' "$listener"
            ;;
        esac
        ;;
      *)
        printf 'http://%s/metrics\n' "$listener"
        ;;
    esac
  fi

  local config="/etc/neuwerk/config.yaml"
  if [ -f "$config" ]; then
    local metrics_bind
    local mgmt_iface
    local mgmt_ip
    metrics_bind="$(awk '
      $0 ~ /^metrics:[[:space:]]*$/ { in_metrics=1; next }
      in_metrics && $0 ~ /^[^[:space:]]/ { in_metrics=0 }
      in_metrics && $1 == "bind:" { print $2; exit }
    ' "$config")"
    if [ -n "$metrics_bind" ]; then
      case "$metrics_bind" in
        0.0.0.0:*)
          printf 'http://127.0.0.1:%s/metrics\n' "${metrics_bind##*:}"
          ;;
        \[*\]:*)
          case "$metrics_bind" in
            "[::]:"*)
              printf 'http://[::1]:%s/metrics\n' "${metrics_bind##*:}"
              ;;
            *)
              printf 'http://%s/metrics\n' "$metrics_bind"
              ;;
          esac
          ;;
        *)
          printf 'http://%s/metrics\n' "$metrics_bind"
          ;;
      esac
    fi
    mgmt_iface="$(awk '
      $0 ~ /^bootstrap:[[:space:]]*$/ { in_bootstrap=1; next }
      in_bootstrap && $0 ~ /^[^[:space:]]/ { in_bootstrap=0 }
      in_bootstrap && $1 == "management_interface:" { print $2; exit }
    ' "$config")"
    if [ -n "$mgmt_iface" ]; then
      mgmt_ip="$(ip -4 -o addr show dev "$mgmt_iface" 2>/dev/null | awk '{split($4, cidr, "/"); print cidr[1]; exit}')"
      if [ -n "$mgmt_ip" ]; then
        printf 'http://%s:8080/metrics\n' "$mgmt_ip"
      fi
    fi
  fi

  printf '%s\n' "http://127.0.0.1:8080/metrics"
}

while IFS= read -r url; do
  [ -z "$url" ] && continue
  if curl -fsS "$url" 2>/dev/null; then
    exit 0
  fi
done < <(candidate_urls | awk '!seen[$0]++')

exit 1
EOS
}
