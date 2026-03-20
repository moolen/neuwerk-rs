#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)

source "${SCRIPT_DIR}/lib.sh"

require_bin ssh
require_bin ssh-keygen

: "${JUMPBOX_IP:?missing JUMPBOX_IP}"
: "${UPSTREAM_VIP:?missing UPSTREAM_VIP}"
: "${UPSTREAM_IP:?missing UPSTREAM_IP}"
: "${CONSUMER_IPS:?missing CONSUMER_IPS}"
: "${FW_MGMT_IPS:?missing FW_MGMT_IPS}"
: "${KEY_PATH:?missing KEY_PATH}"

DNS_ZONE="${DNS_ZONE:-upstream.test}"
K6_VERSION="${K6_VERSION:-0.49.0}"
UPSTREAM_CONFIGURE_SCRIPT="${UPSTREAM_CONFIGURE_SCRIPT:-${SCRIPT_DIR}/http-perf-upstream-configure.sh}"

if [ ! -f "${KEY_PATH}" ]; then
  echo "missing SSH key at ${KEY_PATH}" >&2
  exit 1
fi

if [ ! -x "${UPSTREAM_CONFIGURE_SCRIPT}" ]; then
  echo "missing executable upstream configure script: ${UPSTREAM_CONFIGURE_SCRIPT}" >&2
  exit 1
fi

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

echo "waiting for all neuwerk instances to become ready"
local_any=0
for ip in $FW_MGMT_IPS; do
  local_any=1
  echo "ready check: ${ip}"
  if ! wait_ready "$ip"; then
    echo "timeout waiting for neuwerk readiness on ${ip}" >&2
    exit 1
  fi
done
if [ "$local_any" -eq 0 ]; then
  echo "no neuwerk management IPs supplied" >&2
  exit 1
fi

JUMPBOX_IP="$JUMPBOX_IP" UPSTREAM_IP="$UPSTREAM_IP" KEY_PATH="$KEY_PATH" SSH_USER="${SSH_USER:-ubuntu}" \
  "$UPSTREAM_CONFIGURE_SCRIPT"

for consumer in $CONSUMER_IPS; do
  echo "preparing consumer ${consumer}"
  ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$consumer" "bash -s" <<EOS
set -euo pipefail
if ! grep -qE '^[[:space:]]*${UPSTREAM_VIP//./\\.}[[:space:]]+${DNS_ZONE//./\\.}([[:space:]]|$)' /etc/hosts; then
  echo '${UPSTREAM_VIP} ${DNS_ZONE}' | sudo tee -a /etc/hosts >/dev/null
fi

cat <<'EOC' | sudo tee /etc/sysctl.d/60-neuwerk-http-perf.conf >/dev/null
fs.file-max = 1048576
net.core.somaxconn = 65535
net.ipv4.ip_local_port_range = 10240 65535
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_tw_reuse = 1
EOC
sudo sysctl --system >/dev/null

cat <<'EOC' | sudo tee /etc/security/limits.d/60-neuwerk-http-perf.conf >/dev/null
ubuntu soft nofile 1048576
ubuntu hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOC

if ! command -v k6 >/dev/null 2>&1; then
  arch=\$(uname -m)
  case "\$arch" in
    x86_64|amd64) k6_arch="amd64" ;;
    aarch64|arm64) k6_arch="arm64" ;;
    *) echo "unsupported k6 architecture: \$arch" >&2; exit 1 ;;
  esac
  tmp_dir=\$(mktemp -d)
  trap 'rm -rf "\$tmp_dir"' EXIT
  k6_url="https://github.com/grafana/k6/releases/download/v${K6_VERSION}/k6-v${K6_VERSION}-linux-\${k6_arch}.tar.gz"
  curl -fsSL "\$k6_url" -o "\$tmp_dir/k6.tgz"
  tar -xzf "\$tmp_dir/k6.tgz" -C "\$tmp_dir"
  sudo install -m 0755 "\$tmp_dir/k6-v${K6_VERSION}-linux-\${k6_arch}/k6" /usr/local/bin/k6
fi

ulimit -n 1048576 2>/dev/null || true
k6 version
if ! k6 run --help | grep -q -- '--local-ips'; then
  echo "installed k6 does not support --local-ips" >&2
  exit 1
fi
ip -4 -o addr show
EOS
done

echo "http perf setup complete"
