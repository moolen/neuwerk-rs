#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)
TF_DIR="${TF_DIR:-${ROOT_DIR}/terraform}"
KEY_PATH="${KEY_PATH:-${ROOT_DIR}/../.secrets/ssh/azure_e2e}"

source "${ROOT_DIR}/../common/lib.sh"

require_bin terraform
require_bin jq
require_bin ssh

if [ ! -f "${KEY_PATH}" ]; then
  echo "missing SSH key at ${KEY_PATH}" >&2
  exit 1
fi

pushd "$TF_DIR" >/dev/null
JUMPBOX_IP="$(terraform output -raw jumpbox_public_ip)"
UPSTREAM_IP="$(terraform output -raw upstream_private_ip)"
popd >/dev/null

if [ -z "$JUMPBOX_IP" ] || [ -z "$UPSTREAM_IP" ]; then
  echo "missing terraform outputs for jumpbox/upstream" >&2
  exit 1
fi

echo "configuring upstream webhook listeners on ${UPSTREAM_IP}"

ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$UPSTREAM_IP" "bash -s" <<'EOF'
set -euo pipefail
sudo tee /etc/nginx/sites-available/default >/dev/null <<'NGINX'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name upstream.test;

    location = /healthz {
        return 200 "ok\n";
    }
    location ^~ /webhooks/allowed/ {
        return 200 "accepted\n";
    }
    location ^~ /webhooks/blocked/ {
        return 403 "blocked\n";
    }
    location / {
        return 200 "upstream ok\n";
    }
}

server {
    listen 443 ssl http2 default_server;
    listen [::]:443 ssl http2 default_server;
    listen 8443 ssl http2;
    listen [::]:8443 ssl http2;
    listen 9443 ssl http2;
    listen [::]:9443 ssl http2;
    server_name upstream.test;

    ssl_certificate /etc/nginx/ssl.crt;
    ssl_certificate_key /etc/nginx/ssl.key;

    location = /healthz {
        return 200 "ok\n";
    }
    location ^~ /webhooks/allowed/ {
        return 200 "accepted tls\n";
    }
    location ^~ /webhooks/blocked/ {
        return 403 "blocked tls\n";
    }
    location / {
        return 200 "upstream tls ok\n";
    }
}
NGINX

sudo nginx -t
sudo systemctl reload nginx
EOF

echo "upstream webhook listeners ready"
