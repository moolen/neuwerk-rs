#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)
TF_DIR="${TF_DIR:-${ROOT_DIR}/terraform}"
KEY_PATH="${KEY_PATH:-${ROOT_DIR}/../.secrets/ssh/azure_e2e}"
POLICY_FILE="${POLICY_FILE:-${ROOT_DIR}/policies/allow-upstream.json}"
RESOLVE_FW_IPS="${ROOT_DIR}/scripts/resolve-neuwerk-mgmt-ips.sh"
CONSUMER_SCRIPT_LOCAL="${SCRIPT_DIR}/lifecycle-consumer-http.sh"
ARTIFACT_DIR="${ARTIFACT_DIR:-${ROOT_DIR}/artifacts/lifecycle-$(date -u +%Y%m%dT%H%M%SZ)}"
ROLLING_TIMEOUT_SECS="${ROLLING_TIMEOUT_SECS:-2400}"
ROLLING_POLL_SECS="${ROLLING_POLL_SECS:-15}"
WORKERS="${WORKERS:-4}"
WORKERS_PER_CLASS="${WORKERS_PER_CLASS:-1}"
POST_ROLLOUT_SECS="${POST_ROLLOUT_SECS:-45}"
TARGET_PORT="${TARGET_PORT:-9000}"
REQUEST_PATH="${REQUEST_PATH:-/delay/5}"
DELAY_MAX_TIME_SECS="${DELAY_MAX_TIME_SECS:-25}"
DELAY_CONNECT_TIMEOUT_SECS="${DELAY_CONNECT_TIMEOUT_SECS:-8}"
DNS_ZONE="${DNS_ZONE:-upstream.test}"
ENABLE_DNS_TCP="${ENABLE_DNS_TCP:-0}"
REMOTE_STOP_FILE="/tmp/neuwerk-lifecycle-stop"
REMOTE_CONSUMER_SCRIPT="/tmp/neuwerk-lifecycle-consumer-http.sh"

source "${ROOT_DIR}/../common/lib.sh"

require_bin terraform
require_bin az
require_bin jq
require_bin ssh

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
FW_VMSS="$(terraform output -json neuwerk_vmss | jq -r '.name')"
popd >/dev/null

if [ -z "$RG" ] || [ -z "$JUMPBOX_IP" ] || [ -z "$UPSTREAM_IP" ] || [ -z "$UPSTREAM_VIP" ] || [ -z "$FW_VMSS" ]; then
  echo "missing terraform outputs (resource_group/jumpbox/upstream/upstream_vip/neuwerk_vmss)" >&2
  exit 1
fi
DNS_TARGET="${DNS_TARGET:-$UPSTREAM_VIP}"

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
  local deadline=$((SECONDS + 600))
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

wait_all_neuwerk_nodes_ready() {
  local ips
  ips="$(TF_DIR="$TF_DIR" "$RESOLVE_FW_IPS")"
  if [ -z "$ips" ]; then
    echo "no neuwerk management IPs resolved" >&2
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

collect_metrics_snapshot() {
  local label="$1"
  local out="${ARTIFACT_DIR}/metrics_${label}.txt"
  local ips
  ips="$(TF_DIR="$TF_DIR" "$RESOLVE_FW_IPS")"
  : >"$out"
  for ip in $ips; do
    {
      echo "### instance=${ip} label=${label} ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
      metrics="$(ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$ip" "bash -lc 'METRICS_HOST=\$(grep \"^MGMT_IP=\" /etc/neuwerk/neuwerk.env 2>/dev/null | cut -d= -f2); [ -z \"\$METRICS_HOST\" ] && METRICS_HOST=127.0.0.1; curl -fsS http://\${METRICS_HOST}:8080/metrics'" || true)"
      if [ -z "$metrics" ]; then
        echo "metrics_unavailable=1"
      else
        echo "$metrics" | egrep '^(integration_(termination_events_total|termination_complete_total|termination_poll_errors_total|termination_publish_errors_total|termination_complete_errors_total|drain_duration_seconds_(sum|count)|termination_drain_start_seconds_(sum|count))|dpdk_(rx|tx)_bytes_total|dp_active_flows )' || true
      fi
      echo
    } >>"$out"
  done
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
  echo "starting consumer traffic on ${FIRST_CONSUMER}"
  ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$FIRST_CONSUMER" \
    "UPSTREAM_VIP=${UPSTREAM_VIP} DNS_TARGET=${DNS_TARGET} DNS_ZONE=${DNS_ZONE} HTTP_HOST=${DNS_ZONE} DELAY_TARGET_IP=${UPSTREAM_IP} DELAY_TARGET_PORT=${TARGET_PORT} DELAY_REQUEST_PATH=${REQUEST_PATH} DELAY_MAX_TIME_SECS=${DELAY_MAX_TIME_SECS} DELAY_CONNECT_TIMEOUT_SECS=${DELAY_CONNECT_TIMEOUT_SECS} STOP_FILE=${REMOTE_STOP_FILE} WORKERS_PER_CLASS=${WORKERS_PER_CLASS} ENABLE_DNS_TCP=${ENABLE_DNS_TCP} ${REMOTE_CONSUMER_SCRIPT}" \
    >"${ARTIFACT_DIR}/consumer_traffic.log" 2>&1 &
  CONSUMER_SSH_PID="$!"
}

stop_consumer_traffic() {
  ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$FIRST_CONSUMER" "touch ${REMOTE_STOP_FILE}" || true
  if [ -n "${CONSUMER_SSH_PID:-}" ]; then
    wait "$CONSUMER_SSH_PID"
  fi
}

trigger_rolling_update() {
  local run_id
  local deadline
  local sub
  local vmss_id
  local existing_tags
  local body
  local capacity
  local initial_list
  local instance_pairs
  run_id="$(date -u +%Y%m%dT%H%M%SZ)"
  deadline=$((SECONDS + ROLLING_TIMEOUT_SECS))

  echo "patching VMSS model tag for rollout marker=${run_id}"
  sub="$(az account show --query id -o tsv)"
  vmss_id="/subscriptions/${sub}/resourceGroups/${RG}/providers/Microsoft.Compute/virtualMachineScaleSets/${FW_VMSS}"
  existing_tags="$(az resource show --ids "$vmss_id" --api-version 2023-09-01 --query tags -o json)"
  body="$(jq -n --argjson tags "$existing_tags" --arg run "$run_id" '{tags: (($tags // {}) + {lifecycle_test_run: $run})}')"
  az rest \
    --method PATCH \
    --uri "https://management.azure.com${vmss_id}?api-version=2023-09-01" \
    --headers Content-Type=application/json \
    --body "$body" \
    >/dev/null

  capacity="$(vmss_capacity)"
  if [ -z "$capacity" ] || [ "$capacity" -lt 1 ]; then
    echo "invalid VMSS capacity: ${capacity}" >&2
    return 1
  fi

  instance_pairs="$(vmss_instances_json | jq -r '.[] | select(.name != null and .instance_id != null) | [.name, .instance_id] | @tsv' | sort)"
  initial_list="$(echo "$instance_pairs" | awk -F'\t' '{print $1}')"
  if [ -z "$initial_list" ]; then
    echo "no VMSS instances discovered for rollout" >&2
    return 1
  fi

  echo "starting VMSS rolling replacement for flexible mode (baseline capacity=${capacity})"
  while IFS=$'\t' read -r name instance_id; do
    [ -z "$name" ] && continue
    if [ -z "$instance_id" ] || [ "$instance_id" = "null" ]; then
      echo "skipping ${name}: missing instance_id" >&2
      continue
    fi
    echo "surge scale-out to $((capacity + 1)) before replacing ${name}"
    az vmss scale \
      --resource-group "$RG" \
      --name "$FW_VMSS" \
      --new-capacity "$((capacity + 1))" \
      >/dev/null
    wait_for_vmss_capacity "$((capacity + 1))" "$deadline"
    wait_all_neuwerk_nodes_ready

    echo "deleting VMSS instance ${name} (instance_id=${instance_id}, capacity should settle back to ${capacity})"
    az vmss delete-instances \
      --resource-group "$RG" \
      --name "$FW_VMSS" \
      --instance-ids "$instance_id" \
      >/dev/null
    wait_for_instance_absent "$name" "$deadline"
    wait_for_vmss_capacity "$capacity" "$deadline"
    wait_all_neuwerk_nodes_ready
  done <<<"$instance_pairs"

  echo "rolling replacement completed"
}

cleanup() {
  local status="$1"
  set +e
  ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$FIRST_CONSUMER" "touch ${REMOTE_STOP_FILE}" >/dev/null 2>&1 || true
  if [ -n "${CONSUMER_SSH_PID:-}" ]; then
    wait "$CONSUMER_SSH_PID" >/dev/null 2>&1 || true
  fi
  restore_upstream_services >/dev/null 2>&1 || true
  trap - EXIT
  exit "$status"
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
      wait_all_neuwerk_nodes_ready || true
    fi
  done
  echo "policy push failed after ${attempts} attempts" >&2
  return 1
}

trap 'cleanup $?' EXIT

wait_all_neuwerk_nodes_ready
if [ "${SKIP_POLICY:-}" != "1" ]; then
  echo "configuring policy from ${POLICY_FILE}"
  configure_policy_with_retry
fi

collect_metrics_snapshot "pre"
setup_upstream_delay_http
start_consumer_traffic
sleep 5
trigger_rolling_update
wait_all_neuwerk_nodes_ready
echo "collecting post-rollout traffic for ${POST_ROLLOUT_SECS}s"
sleep "$POST_ROLLOUT_SECS"
collect_metrics_snapshot "post"
stop_consumer_traffic

echo "lifecycle rollout test passed; artifacts in ${ARTIFACT_DIR}"
