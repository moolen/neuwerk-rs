#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)
TF_DIR="${TF_DIR:-${ROOT_DIR}/terraform}"
POLICY_FILE="${1:-${ROOT_DIR}/policies/allow-upstream.json}"
KEY_PATH="${KEY_PATH:-${ROOT_DIR}/../.secrets/ssh/gcp_e2e}"
RESOLVE_FW_IPS="${ROOT_DIR}/scripts/resolve-firewall-mgmt-ips.sh"

source "${ROOT_DIR}/../common/lib.sh"

require_bin terraform
require_bin gcloud
require_bin jq
require_bin curl
require_bin ssh
require_bin python3
require_bin openssl

if [ ! -f "$POLICY_FILE" ]; then
  echo "policy file not found: $POLICY_FILE" >&2
  exit 1
fi

if ! gcloud auth application-default print-access-token >/dev/null 2>&1; then
  echo "gcloud application-default auth required (run: gcloud auth application-default login)" >&2
  exit 1
fi

pushd "$TF_DIR" >/dev/null
JUMPBOX_IP=$(terraform output -raw jumpbox_public_ip)
popd >/dev/null

if [ -z "$JUMPBOX_IP" ]; then
  echo "missing jumpbox_public_ip output" >&2
  exit 1
fi

ssh-keygen -R "$JUMPBOX_IP" >/dev/null 2>&1 || true

if [ ! -f "$KEY_PATH" ]; then
  echo "missing SSH key at ${KEY_PATH}" >&2
  exit 1
fi

FW_MGMT_IPS=$(TF_DIR="$TF_DIR" "$RESOLVE_FW_IPS")

for ip in $FW_MGMT_IPS; do
  echo "pushing policy to ${ip}"
  KEYSET_JSON=$(ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$ip" \
    "sudo cat /var/lib/neuwerk/http-tls/api-auth.json")
  TOKEN=$(KEYSET_JSON="$KEYSET_JSON" python3 - <<'PY'
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
    "sub": "gcp-e2e",
    "exp": now + 3600,
    "iat": now,
    "jti": str(uuid.uuid4()),
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
        ["openssl", "pkeyutl", "-sign", "-rawin", "-in", str(msg), "-inkey", str(key_pem), "-out", str(sig)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    sig_b64 = b64url(sig.read_bytes())

token = f"{signing_input}.{sig_b64}"
print(token)
PY
)
  ssh -o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes -i "$KEY_PATH" \
    "${SSH_USER:-ubuntu}@${JUMPBOX_IP}" \
    "curl -skf --connect-timeout 5 --max-time 15 --retry 5 --retry-delay 2 \
      -X POST https://${ip}:8443/api/v1/policies \
      -H 'Content-Type: application/json' \
      -H 'Authorization: Bearer ${TOKEN}' \
      --data-binary @-" < "$POLICY_FILE" >/dev/null
 done
