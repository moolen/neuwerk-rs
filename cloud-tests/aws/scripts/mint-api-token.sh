#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 3 ]; then
  echo "usage: $0 <jumpbox-ip> <ssh-key-path> <neuwerk-mgmt-ip> [sub]" >&2
  exit 2
fi

JUMPBOX_IP="$1"
KEY_PATH="$2"
NEUWERK_IP="$3"
SUBJECT="${4:-aws-ui-port-forward}"
SSH_USER="${SSH_USER:-ubuntu}"

if [ ! -f "$KEY_PATH" ]; then
  echo "missing SSH key at ${KEY_PATH}" >&2
  exit 1
fi

for bin in ssh openssl python3; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo "missing required binary: $bin" >&2
    exit 1
  fi
done

KEYSET_JSON=$(
  ssh -o LogLevel=ERROR -o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes -i "$KEY_PATH" \
    -o ProxyCommand="ssh -o LogLevel=ERROR -o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes -i ${KEY_PATH} -W %h:%p ${SSH_USER}@${JUMPBOX_IP}" \
    "${SSH_USER}@${NEUWERK_IP}" \
    "sudo cat /var/lib/neuwerk/http-tls/api-auth.json"
)

KEYSET_JSON="$KEYSET_JSON" SUBJECT="$SUBJECT" python3 - <<'PY'
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
priv_bytes = base64.b64decode(key["private_key"])
subject = os.environ["SUBJECT"]

now = int(time.time())
header = {"alg": "EdDSA", "kid": kid, "typ": "JWT"}
claims = {
    "iss": "neuwerk-api",
    "aud": "neuwerk-api",
    "sub": subject,
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

print(f"{signing_input}.{sig_b64}")
PY
