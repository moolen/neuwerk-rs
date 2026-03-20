#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)

source "${SCRIPT_DIR}/lib.sh"

require_bin ssh
require_bin ssh-keygen

: "${JUMPBOX_IP:?missing JUMPBOX_IP}"
: "${UPSTREAM_IP:?missing UPSTREAM_IP}"
: "${KEY_PATH:?missing KEY_PATH}"
UPSTREAM_KEEPALIVE_TIMEOUT="${UPSTREAM_KEEPALIVE_TIMEOUT:-120s}"
UPSTREAM_KEEPALIVE_REQUESTS="${UPSTREAM_KEEPALIVE_REQUESTS:-100000}"
UPSTREAM_HTTP2_MAX_CONCURRENT_STREAMS="${UPSTREAM_HTTP2_MAX_CONCURRENT_STREAMS:-1024}"

if [ ! -f "${KEY_PATH}" ]; then
  echo "missing SSH key at ${KEY_PATH}" >&2
  exit 1
fi

echo "configuring upstream webhook listeners on ${UPSTREAM_IP}"

ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$UPSTREAM_IP" \
  "env UPSTREAM_KEEPALIVE_TIMEOUT='${UPSTREAM_KEEPALIVE_TIMEOUT}' UPSTREAM_KEEPALIVE_REQUESTS='${UPSTREAM_KEEPALIVE_REQUESTS}' UPSTREAM_HTTP2_MAX_CONCURRENT_STREAMS='${UPSTREAM_HTTP2_MAX_CONCURRENT_STREAMS}' bash -s" <<'EOS'
set -euo pipefail
sudo tee /etc/nginx/sites-available/default >/dev/null <<NGINX
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
    # Favor long-lived upstream HTTP/2 sessions during DPI load tests.
    keepalive_timeout ${UPSTREAM_KEEPALIVE_TIMEOUT};
    keepalive_requests ${UPSTREAM_KEEPALIVE_REQUESTS};
    http2_max_concurrent_streams ${UPSTREAM_HTTP2_MAX_CONCURRENT_STREAMS};

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
EOS

echo "upstream webhook listeners ready"
