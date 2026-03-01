#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)
TF_DIR="${TF_DIR:-${ROOT_DIR}/terraform}"
KEY_PATH="${KEY_PATH:-${ROOT_DIR}/../.secrets/ssh/azure_e2e}"
POLICY_FILE="${POLICY_FILE:-${ROOT_DIR}/policies/allow-upstream.json}"
RESOLVE_FW_IPS="${ROOT_DIR}/scripts/resolve-firewall-mgmt-ips.sh"
CONSUMER_SCRIPT_LOCAL="${SCRIPT_DIR}/lifecycle-consumer-http.sh"
ARTIFACT_DIR="${ARTIFACT_DIR:-${ROOT_DIR}/artifacts/lifecycle-termdrain-$(date -u +%Y%m%dT%H%M%SZ)}"
ROLLING_TIMEOUT_SECS="${ROLLING_TIMEOUT_SECS:-1800}"
ROLLING_POLL_SECS="${ROLLING_POLL_SECS:-10}"
WORKERS_PER_CLASS="${WORKERS_PER_CLASS:-2}"
TARGET_PORT="${TARGET_PORT:-9000}"
REQUEST_PATH="${REQUEST_PATH:-/delay/5}"
DELAY_MAX_TIME_SECS="${DELAY_MAX_TIME_SECS:-25}"
DELAY_CONNECT_TIMEOUT_SECS="${DELAY_CONNECT_TIMEOUT_SECS:-8}"
DNS_ZONE="${DNS_ZONE:-upstream.test}"
POST_EVENT_OBSERVE_SECS="${POST_EVENT_OBSERVE_SECS:-120}"
TRIGGER_ACTION="${TRIGGER_ACTION:-terminate}"
ENABLE_TRAFFIC="${ENABLE_TRAFFIC:-0}"
REMOTE_STOP_FILE="/tmp/neuwerk-lifecycle-stop"
REMOTE_CONSUMER_SCRIPT="/tmp/neuwerk-lifecycle-consumer-http.sh"

source "${ROOT_DIR}/../common/lib.sh"

require_bin terraform
require_bin az
require_bin jq
require_bin ssh
require_bin awk

if [ ! -x "$CONSUMER_SCRIPT_LOCAL" ]; then
  echo "consumer script is missing or not executable: $CONSUMER_SCRIPT_LOCAL" >&2
  exit 1
fi

if [ ! -f "${KEY_PATH}" ]; then
  echo "missing SSH key at ${KEY_PATH}" >&2
  exit 1
fi

mkdir -p "$ARTIFACT_DIR"
echo "artifact directory: ${ARTIFACT_DIR}"

pushd "$TF_DIR" >/dev/null
RG="$(terraform output -raw resource_group)"
JUMPBOX_IP="$(terraform output -raw jumpbox_public_ip)"
UPSTREAM_IP="$(terraform output -raw upstream_private_ip)"
UPSTREAM_VIP="$(terraform output -raw upstream_vip)"
CONSUMERS="$(terraform output -json consumer_private_ips | jq -r '.[]')"
FW_VMSS="$(terraform output -json firewall_vmss | jq -r '.name')"
popd >/dev/null

if [ -z "$RG" ] || [ -z "$JUMPBOX_IP" ] || [ -z "$UPSTREAM_IP" ] || [ -z "$UPSTREAM_VIP" ] || [ -z "$FW_VMSS" ]; then
  echo "missing terraform outputs (resource_group/jumpbox/upstream/upstream_vip/firewall_vmss)" >&2
  exit 1
fi

FIRST_CONSUMER="$(echo "$CONSUMERS" | head -n1)"
if [ -z "$FIRST_CONSUMER" ]; then
  echo "no consumer instances found" >&2
  exit 1
fi

az account show >/dev/null 2>&1 || {
  echo "az login required" >&2
  exit 1
}

wait_ready() {
  local ip="$1"
  local deadline=$((SECONDS + 900))
  while [ "$SECONDS" -lt "$deadline" ]; do
    if ssh -n -o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes -i "$KEY_PATH" \
      "${SSH_USER:-ubuntu}@${JUMPBOX_IP}" \
      "curl -skf https://${ip}:8443/ready >/dev/null"; then
      return 0
    fi
    sleep 5
  done
  return 1
}

wait_all_firewalls_ready() {
  local ips
  ips="$(TF_DIR="$TF_DIR" "$RESOLVE_FW_IPS")"
  if [ -z "$ips" ]; then
    echo "no firewall management IPs resolved" >&2
    return 1
  fi
  for ip in $ips; do
    echo "waiting for ready: $ip"
    if ! wait_ready "$ip"; then
      echo "timeout waiting for ready: $ip" >&2
      return 1
    fi
  done
}

configure_policy_with_retry() {
  local attempts="${POLICY_PUSH_RETRIES:-5}"
  local delay_secs="${POLICY_PUSH_RETRY_DELAY_SECS:-5}"
  local i
  for i in $(seq 1 "$attempts"); do
    if TF_DIR="$TF_DIR" KEY_PATH="$KEY_PATH" "${ROOT_DIR}/scripts/configure-policy.sh" "${POLICY_FILE}"; then
      return 0
    fi
    if [ "$i" -lt "$attempts" ]; then
      echo "policy push failed (attempt ${i}/${attempts}); retrying in ${delay_secs}s"
      sleep "$delay_secs"
      wait_all_firewalls_ready || true
    fi
  done
  echo "policy push failed after ${attempts} attempts" >&2
  return 1
}

vmss_instances_json() {
  local sub
  local uri
  sub="$(az account show --query id -o tsv)"
  uri="https://management.azure.com/subscriptions/${sub}/resourceGroups/${RG}/providers/Microsoft.Compute/virtualMachineScaleSets/${FW_VMSS}/virtualMachines?api-version=2023-09-01"
  az rest --method get --uri "$uri" --query 'value[].{name:name,instance_id:instanceId}' -o json
}

vmss_instance_names() {
  vmss_instances_json | jq -r '.[] | select(.name != null) | .name' | sort
}

vmss_instance_id_for_name() {
  local name="$1"
  vmss_instances_json \
    | jq -r --arg name "$name" '.[] | select(.name == $name) | .instance_id' \
    | head -n1
}

vmss_capacity() {
  local sub
  local vmss_id
  sub="$(az account show --query id -o tsv)"
  vmss_id="/subscriptions/${sub}/resourceGroups/${RG}/providers/Microsoft.Compute/virtualMachineScaleSets/${FW_VMSS}"
  az resource show --ids "$vmss_id" --api-version 2023-09-01 --query 'sku.capacity' -o tsv
}

wait_for_vmss_capacity() {
  local want="$1"
  local deadline="$2"
  while true; do
    local have
    have="$(vmss_capacity)"
    if [ "$have" = "$want" ]; then
      return 0
    fi
    if [ "$SECONDS" -ge "$deadline" ]; then
      echo "timed out waiting for VMSS capacity=${want} (have=${have})" >&2
      return 1
    fi
    sleep "$ROLLING_POLL_SECS"
  done
}

wait_for_instance_absent() {
  local name="$1"
  local deadline="$2"
  while true; do
    if ! vmss_instance_names | grep -qx "$name"; then
      return 0
    fi
    if [ "$SECONDS" -ge "$deadline" ]; then
      echo "timed out waiting for instance removal: ${name}" >&2
      return 1
    fi
    sleep "$ROLLING_POLL_SECS"
  done
}

vmss_instance_mgmt_ip() {
  local name="$1"
  az network nic list \
    -g "$RG" \
    --query "[?starts_with(name, 'mgmt0-') && ends_with(virtualMachine.id, '/${name}')].ipConfigurations[0].privateIPAddress" \
    -o tsv | head -n1
}

setup_upstream_delay_http() {
  echo "configuring upstream delayed HTTP service on ${UPSTREAM_IP}:${TARGET_PORT}"
  ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$UPSTREAM_IP" "bash -s" <<'EOF'
set -euo pipefail
sudo tee /usr/local/bin/neuwerk-delay-http.py >/dev/null <<'PY'
#!/usr/bin/env python3
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if not self.path.startswith("/delay/"):
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"not found\n")
            return
        try:
            delay = int(self.path.rsplit("/", 1)[1])
        except Exception:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"invalid delay\n")
            return
        # Keep test delays bounded and deterministic.
        delay = max(1, min(delay, 60))
        time.sleep(float(delay))
        body = b"delay ok\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        return

if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", 9000), Handler)
    server.serve_forever()
PY
sudo chmod +x /usr/local/bin/neuwerk-delay-http.py
sudo tee /etc/systemd/system/neuwerk-delay-http.service >/dev/null <<'UNIT'
[Unit]
Description=Neuwerk delayed HTTP test server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/neuwerk-delay-http.py
Restart=always

[Install]
WantedBy=multi-user.target
UNIT
sudo systemctl daemon-reload
sudo pkill -f neuwerk-delay-http.py || true
sudo pkill -f 'socat -u TCP-LISTEN:9000' || true
sudo systemctl disable --now longtcp.service || true
sudo systemctl reset-failed neuwerk-delay-http.service || true
sudo systemctl enable --now neuwerk-delay-http.service
sudo systemctl is-active --quiet neuwerk-delay-http.service
EOF
}

restore_upstream_services() {
  ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$UPSTREAM_IP" "bash -s" <<'EOF'
set -euo pipefail
sudo pkill -f neuwerk-delay-http.py || true
sudo systemctl disable --now neuwerk-delay-http.service || true
sudo pkill -f 'socat -u TCP-LISTEN:9000' || true
sudo systemctl enable --now longtcp.service || true
sudo systemctl is-active --quiet longtcp.service || true
EOF
}

start_consumer_traffic() {
  ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$FIRST_CONSUMER" \
    "cat > ${REMOTE_CONSUMER_SCRIPT} && chmod +x ${REMOTE_CONSUMER_SCRIPT}" \
    <"$CONSUMER_SCRIPT_LOCAL"
  ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$FIRST_CONSUMER" "rm -f ${REMOTE_STOP_FILE}"
  echo "starting delayed-flow traffic on ${FIRST_CONSUMER}"
  ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$FIRST_CONSUMER" \
    "UPSTREAM_VIP=${UPSTREAM_VIP} DNS_ZONE=${DNS_ZONE} HTTP_HOST=${DNS_ZONE} DELAY_TARGET_IP=${UPSTREAM_IP} DELAY_TARGET_PORT=${TARGET_PORT} DELAY_REQUEST_PATH=${REQUEST_PATH} DELAY_MAX_TIME_SECS=${DELAY_MAX_TIME_SECS} DELAY_CONNECT_TIMEOUT_SECS=${DELAY_CONNECT_TIMEOUT_SECS} STOP_FILE=${REMOTE_STOP_FILE} WORKERS_PER_CLASS=${WORKERS_PER_CLASS} ENABLE_DNS_UDP=0 ENABLE_DNS_TCP=0 ENABLE_HTTP=0 ENABLE_HTTPS=0 ENABLE_DELAYED_HTTP=1 ${REMOTE_CONSUMER_SCRIPT}" \
    >"${ARTIFACT_DIR}/consumer_traffic.log" 2>&1 &
  CONSUMER_SSH_PID="$!"
}

stop_consumer_traffic() {
  ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$FIRST_CONSUMER" "touch ${REMOTE_STOP_FILE}" || true
  if [ -n "${CONSUMER_SSH_PID:-}" ]; then
    wait "$CONSUMER_SSH_PID"
  fi
}

read_target_metrics_local() {
  local ip="$1"
  local out
  out="$(ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$ip" "curl -fsS http://127.0.0.1:8080/metrics" 2>/dev/null || true)"
  if [ -z "$out" ]; then
    return 1
  fi
  local events
  local complete
  local drain_start_count
  events="$(echo "$out" | awk '/^integration_termination_events_total /{print $2; exit}')"
  complete="$(echo "$out" | awk '/^integration_termination_complete_total /{print $2; exit}')"
  drain_start_count="$(echo "$out" | awk '/^integration_termination_drain_start_seconds_count /{print $2; exit}')"
  if [ -z "$events" ]; then events=0; fi
  if [ -z "$complete" ]; then complete=0; fi
  if [ -z "$drain_start_count" ]; then drain_start_count=0; fi
  echo "${events} ${complete} ${drain_start_count}"
}

start_target_metric_stream() {
  local ip="$1"
  TARGET_METRIC_STREAM_LOG="${ARTIFACT_DIR}/target_metrics_stream.log"
  : >"$TARGET_METRIC_STREAM_LOG"
  ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$ip" "bash -s" <<'EOF' >"$TARGET_METRIC_STREAM_LOG" 2>&1 &
set -euo pipefail
while true; do
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  metrics="$(curl -fsS http://127.0.0.1:8080/metrics 2>/dev/null || true)"
  if [ -z "$metrics" ]; then
    echo "ts=${ts} metrics_unavailable=1"
    sleep 1
    continue
  fi
  events="$(echo "$metrics" | awk '/^integration_termination_events_total /{print $2; exit}')"
  complete="$(echo "$metrics" | awk '/^integration_termination_complete_total /{print $2; exit}')"
  drain_start="$(echo "$metrics" | awk '/^integration_termination_drain_start_seconds_count /{print $2; exit}')"
  [ -z "$events" ] && events=0
  [ -z "$complete" ] && complete=0
  [ -z "$drain_start" ] && drain_start=0
  echo "ts=${ts} events=${events} complete=${complete} drain_start_count=${drain_start}"
  sleep 1
done
EOF
  TARGET_METRIC_STREAM_PID="$!"
}

stop_target_metric_stream() {
  if [ -n "${TARGET_METRIC_STREAM_PID:-}" ]; then
    if kill -0 "$TARGET_METRIC_STREAM_PID" >/dev/null 2>&1; then
      kill "$TARGET_METRIC_STREAM_PID" >/dev/null 2>&1 || true
    fi
    wait "$TARGET_METRIC_STREAM_PID" >/dev/null 2>&1 || true
  fi
}

trigger_instance_event() {
  local action="$1"
  local target_name="$2"
  local target_instance_id="$3"
  local capacity="$4"
  local deadline="$5"

  case "$action" in
    terminate)
      echo "surge scale-out to $((capacity + 1)) before deleting ${target_name} (instance_id=${target_instance_id})"
      az vmss scale \
        --resource-group "$RG" \
        --name "$FW_VMSS" \
        --new-capacity "$((capacity + 1))" \
        >/dev/null
      wait_for_vmss_capacity "$((capacity + 1))" "$deadline"
      wait_all_firewalls_ready

      echo "deleting target instance ${target_name} (instance_id=${target_instance_id})"
      az vmss delete-instances \
        --resource-group "$RG" \
        --name "$FW_VMSS" \
        --instance-ids "$target_instance_id" \
        >/dev/null
      ;;
    reboot)
      echo "restarting target instance ${target_name} (instance_id=${target_instance_id})"
      az vmss restart \
        --resource-group "$RG" \
        --name "$FW_VMSS" \
        --instance-ids "$target_instance_id" \
        >/dev/null
      ;;
    *)
      echo "unsupported TRIGGER_ACTION=${action} (supported: terminate, reboot)" >&2
      return 1
      ;;
  esac
}

cleanup() {
  local status="$1"
  set +e
  if [ "${CONSUMER_STARTED:-0}" = "1" ]; then
    ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$FIRST_CONSUMER" "touch ${REMOTE_STOP_FILE}" >/dev/null 2>&1 || true
    if [ -n "${CONSUMER_SSH_PID:-}" ]; then
      wait "$CONSUMER_SSH_PID" >/dev/null 2>&1 || true
    fi
  fi
  stop_target_metric_stream
  if [ "${UPSTREAM_DELAY_ENABLED:-0}" = "1" ]; then
    restore_upstream_services >/dev/null 2>&1 || true
  fi
  trap - EXIT
  exit "$status"
}

trap 'cleanup $?' EXIT

wait_all_firewalls_ready
echo "configuring policy from ${POLICY_FILE}"
configure_policy_with_retry

if [ "$ENABLE_TRAFFIC" = "1" ]; then
  setup_upstream_delay_http
  UPSTREAM_DELAY_ENABLED=1
  start_consumer_traffic
  CONSUMER_STARTED=1
  sleep 5
fi

target_name="$(vmss_instance_names | head -n1)"
if [ -z "$target_name" ]; then
  echo "failed to select target instance for termination test" >&2
  exit 1
fi
target_instance_id="$(vmss_instance_id_for_name "$target_name")"
if [ -z "$target_instance_id" ] || [ "$target_instance_id" = "null" ]; then
  echo "failed to resolve instance_id for ${target_name}" >&2
  exit 1
fi
target_ip="$(vmss_instance_mgmt_ip "$target_name")"
if [ -z "$target_ip" ]; then
  echo "failed to resolve target management IP for ${target_name}" >&2
  exit 1
fi
echo "selected target instance: ${target_name} (instance_id=${target_instance_id}, mgmt_ip=${target_ip}, trigger=${TRIGGER_ACTION})"

baseline="$(read_target_metrics_local "$target_ip" || true)"
if [ -z "$baseline" ]; then
  echo "failed to read target metrics before termination from ${target_ip}" >&2
  exit 1
fi
baseline_events="$(echo "$baseline" | awk '{print $1}')"
baseline_complete="$(echo "$baseline" | awk '{print $2}')"
baseline_drain_start="$(echo "$baseline" | awk '{print $3}')"
echo "target baseline metrics events=${baseline_events} complete=${baseline_complete} drain_start_count=${baseline_drain_start}"

max_events="$baseline_events"
max_complete="$baseline_complete"
max_drain_start="$baseline_drain_start"

start_target_metric_stream "$target_ip"
sleep 3

deadline=$((SECONDS + ROLLING_TIMEOUT_SECS))
capacity="$(vmss_capacity)"
if [ -z "$capacity" ] || [ "$capacity" -lt 1 ]; then
  echo "invalid VMSS capacity: ${capacity}" >&2
  exit 1
fi

trigger_instance_event "$TRIGGER_ACTION" "$target_name" "$target_instance_id" "$capacity" "$deadline"

sleep "$POST_EVENT_OBSERVE_SECS"

if [ "$TRIGGER_ACTION" = "terminate" ]; then
  wait_for_instance_absent "$target_name" "$deadline"
  wait_for_vmss_capacity "$capacity" "$deadline"
fi
wait_all_firewalls_ready

stop_target_metric_stream

if [ -n "${TARGET_METRIC_STREAM_LOG:-}" ] && [ -f "$TARGET_METRIC_STREAM_LOG" ]; then
  max_events_stream="$(awk 'BEGIN{max=0} {for(i=1;i<=NF;i++){if($i ~ /^events=/){split($i,a,"="); if((a[2]+0)>max) max=(a[2]+0)}}} END{print max}' "$TARGET_METRIC_STREAM_LOG")"
  max_complete_stream="$(awk 'BEGIN{max=0} {for(i=1;i<=NF;i++){if($i ~ /^complete=/){split($i,a,"="); if((a[2]+0)>max) max=(a[2]+0)}}} END{print max}' "$TARGET_METRIC_STREAM_LOG")"
  max_drain_stream="$(awk 'BEGIN{max=0} {for(i=1;i<=NF;i++){if($i ~ /^drain_start_count=/){split($i,a,"="); if((a[2]+0)>max) max=(a[2]+0)}}} END{print max}' "$TARGET_METRIC_STREAM_LOG")"
  if [ "$max_events_stream" -gt "$max_events" ]; then max_events="$max_events_stream"; fi
  if [ "$max_complete_stream" -gt "$max_complete" ]; then max_complete="$max_complete_stream"; fi
  if [ "$max_drain_stream" -gt "$max_drain_start" ]; then max_drain_start="$max_drain_stream"; fi
fi

if [ "${CONSUMER_STARTED:-0}" = "1" ]; then
  stop_consumer_traffic
fi

echo "target max metrics events=${max_events} complete=${max_complete} drain_start_count=${max_drain_start}"
if [ "$max_events" -le "$baseline_events" ]; then
  echo "termination drain test failed: integration_termination_events_total did not increase for target ${target_name}" >&2
  exit 1
fi
if [ "$max_drain_start" -le "$baseline_drain_start" ]; then
  echo "termination drain test failed: integration_termination_drain_start_seconds_count did not increase for target ${target_name}" >&2
  exit 1
fi

echo "termination drain test passed; artifacts in ${ARTIFACT_DIR}"
