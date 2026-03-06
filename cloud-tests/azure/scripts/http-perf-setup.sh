#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)
TF_DIR="${TF_DIR:-${ROOT_DIR}/terraform}"
KEY_PATH="${KEY_PATH:-${ROOT_DIR}/../.secrets/ssh/azure_e2e}"
K6_VERSION="${K6_VERSION:-0.49.0}"
DNS_ZONE="${DNS_ZONE:-upstream.test}"
RESOLVE_FW_IPS="${ROOT_DIR}/scripts/resolve-firewall-mgmt-ips.sh"

source "${ROOT_DIR}/../common/lib.sh"

require_bin terraform
require_bin az
require_bin jq
require_bin ssh

if [ ! -f "${KEY_PATH}" ]; then
  echo "missing SSH key at ${KEY_PATH}" >&2
  exit 1
fi

az account show >/dev/null 2>&1 || {
  echo "az login required" >&2
  exit 1
}

pushd "$TF_DIR" >/dev/null
JUMPBOX_IP="$(terraform output -raw jumpbox_public_ip)"
UPSTREAM_VIP="$(terraform output -raw upstream_vip)"
mapfile -t CONSUMERS < <(terraform output -json consumer_private_ips | jq -r '.[]')
popd >/dev/null

if [ -z "$JUMPBOX_IP" ] || [ -z "$UPSTREAM_VIP" ] || [ "${#CONSUMERS[@]}" -eq 0 ]; then
  echo "missing terraform outputs for jumpbox/upstream_vip/consumers" >&2
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

echo "waiting for all firewall instances to become ready"
FW_MGMT_IPS="$(TF_DIR="$TF_DIR" "$RESOLVE_FW_IPS")"
for ip in $FW_MGMT_IPS; do
  echo "ready check: ${ip}"
  if ! wait_ready "$ip"; then
    echo "timeout waiting for firewall readiness on ${ip}" >&2
    exit 1
  fi
done

echo "configuring upstream webhook listeners"
TF_DIR="$TF_DIR" KEY_PATH="$KEY_PATH" "${SCRIPT_DIR}/http-perf-upstream-configure.sh"

for consumer in "${CONSUMERS[@]}"; do
  echo "preparing consumer ${consumer}"
  ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$consumer" "bash -s" <<EOF
set -euo pipefail
if ! grep -qE '^[[:space:]]*${UPSTREAM_VIP//./\\.}[[:space:]]+${DNS_ZONE//./\\.}([[:space:]]|\$)' /etc/hosts; then
  echo '${UPSTREAM_VIP} ${DNS_ZONE}' | sudo tee -a /etc/hosts >/dev/null
fi

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

k6 version
EOF
done

echo "http perf setup complete"
