#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)

source "${SCRIPT_DIR}/lib.sh"

require_bin ssh
require_bin ssh-keygen
require_bin python3
require_bin openssl
require_bin cargo

: "${JUMPBOX_IP:?missing JUMPBOX_IP}"
: "${CONSUMER_IP:?missing CONSUMER_IP}"
: "${UPSTREAM_VIP:?missing UPSTREAM_VIP}"
UPSTREAM_IP="${UPSTREAM_IP:-${UPSTREAM_VIP}}"
: "${DNS_SERVER:?missing DNS_SERVER}"
: "${DNS_ZONE:?missing DNS_ZONE}"
: "${KEY_PATH:?missing KEY_PATH}"

FW_MGMT_IPS="${FW_MGMT_IPS:-${FW_MGMT_IP:-}}"
if [ -z "$FW_MGMT_IPS" ]; then
  echo "missing FW_MGMT_IPS or FW_MGMT_IP" >&2
  exit 1
fi
FW_MGMT_IP="${FW_MGMT_IP:-$(echo "$FW_MGMT_IPS" | awk '{print $1}')}"

if [ ! -f "${KEY_PATH}" ]; then
  echo "missing SSH key at ${KEY_PATH}" >&2
  exit 1
fi

NEUWERK_POLICY_API_BASE="${NEUWERK_POLICY_API_BASE:-https://${FW_MGMT_IP}:8443}"
NEUWERK_POLICY_API_BASES="${NEUWERK_POLICY_API_BASES:-}"
NEUWERK_POLICY_API_INSECURE="${NEUWERK_POLICY_API_INSECURE:-1}"
NEUWERK_TEST_TIMEOUT_SECS="${NEUWERK_TEST_TIMEOUT_SECS:-300}"
if [ -z "$NEUWERK_POLICY_API_BASES" ]; then
  base_csv=""
  for ip in $FW_MGMT_IPS; do
    entry="https://${ip}:8443"
    if [ -n "$base_csv" ]; then
      base_csv="${base_csv},${entry}"
    else
      base_csv="${entry}"
    fi
  done
  NEUWERK_POLICY_API_BASES="$base_csv"
fi

TOKEN="${NEUWERK_POLICY_API_TOKEN:-}"
mint_token_for_ip() {
  local ip="$1"
  local keyset_json
  keyset_json=$(ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$ip" \
    "sudo cat /var/lib/neuwerk/http-tls/api-auth.json")
  KEYSET_JSON="$keyset_json" python3 - <<'PY'
import base64
import json
import os
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

data = json.loads(os.environ["KEYSET_JSON"])
kid = data["active_kid"]
key = next((k for k in data["keys"] if k["kid"] == kid), data["keys"][0])
priv_b64 = key["private_key"]
priv_bytes = base64.b64decode(priv_b64)

now = int(time.time())
header = {"alg": "EdDSA", "kid": kid, "typ": "JWT"}
claims = {
    "iss": "neuwerk-api",
    "aud": "neuwerk-api",
    "sub": "cloud-policy-smoke",
    "exp": now + 3600,
    "iat": now,
    "jti": str(uuid.uuid4()),
    "roles": ["admin"],
}

def b64url(payload: bytes) -> str:
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")

header_b64 = b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
claims_b64 = b64url(json.dumps(claims, separators=(",", ":")).encode("utf-8"))
signing_input = f"{header_b64}.{claims_b64}"

with tempfile.TemporaryDirectory() as td:
    td_path = Path(td)
    key_der = td_path / "key.der"
    key_pem = td_path / "key.pem"
    msg = td_path / "msg"
    sig = td_path / "sig"
    key_der.write_bytes(priv_bytes)
    subprocess.check_call(
        ["openssl", "pkey", "-inform", "DER", "-in", str(key_der), "-out", str(key_pem)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    msg.write_text(signing_input)
    subprocess.check_call(
        [
            "openssl",
            "pkeyutl",
            "-sign",
            "-rawin",
            "-in",
            str(msg),
            "-inkey",
            str(key_pem),
            "-out",
            str(sig),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    sig_b64 = b64url(sig.read_bytes())

token = f"{signing_input}.{sig_b64}"
print(token)
PY
}

if [ -z "${NEUWERK_POLICY_API_ENDPOINTS:-}" ]; then
  endpoint_csv=""
  first_token=""
  for ip in $FW_MGMT_IPS; do
    ip_token="$(mint_token_for_ip "$ip")"
    entry="https://${ip}:8443|${ip_token}"
    if [ -n "$endpoint_csv" ]; then
      endpoint_csv="${endpoint_csv},${entry}"
    else
      endpoint_csv="${entry}"
    fi
    if [ -z "$first_token" ]; then
      first_token="$ip_token"
    fi
  done
  NEUWERK_POLICY_API_ENDPOINTS="$endpoint_csv"
  if [ -z "$TOKEN" ]; then
    TOKEN="$first_token"
  fi
fi

if [ -z "$TOKEN" ]; then
  TOKEN="$(echo "$NEUWERK_POLICY_API_ENDPOINTS" | awk -F'|' '{print $2}' | awk -F',' '{print $1}')"
fi

RUNNER_DIR="${RUNNER_DIR:-${ROOT_DIR}/runner}"
RUNNER_BIN="${RUNNER_BIN:-${RUNNER_DIR}/target/release/cloud-policy-smoke}"
REMOTE_BIN="${REMOTE_BIN:-/tmp/cloud-policy-smoke-$$}"
SKIP_RUNNER_BUILD="${SKIP_RUNNER_BUILD:-0}"
RUNNER_ARGS="${RUNNER_ARGS:-}"

if [ "$SKIP_RUNNER_BUILD" != "1" ]; then
  echo "building runner"
  cargo build --manifest-path "${RUNNER_DIR}/Cargo.toml" --release
fi

ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$CONSUMER_IP" "cat > ${REMOTE_BIN}" < "$RUNNER_BIN"
ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$CONSUMER_IP" "chmod +x ${REMOTE_BIN}"

# Clean up per-run remote copy to avoid stale binary collisions between concurrent runs.
cleanup_remote_runner() {
  ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$CONSUMER_IP" "rm -f ${REMOTE_BIN}" >/dev/null 2>&1 || true
}
trap cleanup_remote_runner EXIT

ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$CONSUMER_IP" \
  "NEUWERK_POLICY_API_BASE='${NEUWERK_POLICY_API_BASE}' \
   NEUWERK_POLICY_API_BASES='${NEUWERK_POLICY_API_BASES}' \
   NEUWERK_POLICY_API_ENDPOINTS='${NEUWERK_POLICY_API_ENDPOINTS}' \
   NEUWERK_POLICY_API_TOKEN='${TOKEN}' \
   NEUWERK_POLICY_API_INSECURE='${NEUWERK_POLICY_API_INSECURE}' \
   NEUWERK_UPSTREAM_VIP='${UPSTREAM_VIP}' \
   NEUWERK_UPSTREAM_IP='${UPSTREAM_IP}' \
   NEUWERK_UPSTREAM_UDP_TARGET='${UPSTREAM_UDP_TARGET:-${UPSTREAM_VIP}}' \
   NEUWERK_DNS_SERVER='${DNS_SERVER}' \
   NEUWERK_DNS_ZONE='${DNS_ZONE}' \
   NEUWERK_TEST_TIMEOUT_SECS='${NEUWERK_TEST_TIMEOUT_SECS}' \
   ${REMOTE_BIN} ${RUNNER_ARGS}"
