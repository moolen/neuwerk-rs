#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)
TF_DIR="${TF_DIR:-${ROOT_DIR}/terraform}"
POLICY_FILE="${1:-${ROOT_DIR}/policies/allow-upstream.json}"
KEY_PATH="${KEY_PATH:-${ROOT_DIR}/../.secrets/ssh/azure_e2e}"
RESOLVE_FW_IPS="${ROOT_DIR}/scripts/resolve-neuwerk-mgmt-ips.sh"

source "${ROOT_DIR}/../common/lib.sh"

require_bin terraform
require_bin az
require_bin jq
require_bin curl
require_bin ssh
require_bin python3
require_bin openssl

if [ ! -f "$POLICY_FILE" ]; then
  echo "policy file not found: $POLICY_FILE" >&2
  exit 1
fi

pushd "$TF_DIR" >/dev/null
RG=$(terraform output -raw resource_group)
JUMPBOX_IP=$(terraform output -raw jumpbox_public_ip)
FW_VMSS=$(terraform output -json neuwerk_vmss | jq -r '.name')
CONSUMER_PUBLIC_IPS=$(terraform output -json consumer_public_ips 2>/dev/null | jq -r '.[]?' || true)
popd >/dev/null

if [ -z "$JUMPBOX_IP" ]; then
  echo "missing jumpbox_public_ip output" >&2
  exit 1
fi

if [ ! -f "$KEY_PATH" ]; then
  echo "missing SSH key at ${KEY_PATH}" >&2
  exit 1
fi

FW_MGMT_IPS=$(TF_DIR="$TF_DIR" "$RESOLVE_FW_IPS")

POLICY_PAYLOAD="$POLICY_FILE"
TEMP_POLICY=""
if [ -n "$CONSUMER_PUBLIC_IPS" ]; then
  TEMP_POLICY=$(mktemp)
  CONSUMER_PUBLIC_IPS="$CONSUMER_PUBLIC_IPS" python3 - <<'PY' "$POLICY_FILE" "$TEMP_POLICY"
import json
import os
import sys

src = sys.argv[1]
dst = sys.argv[2]
ips = [line.strip() for line in os.environ.get("CONSUMER_PUBLIC_IPS", "").splitlines() if line.strip()]
with open(src, "r", encoding="utf-8") as fh:
    data = json.load(fh)

groups = data.get("policy", {}).get("source_groups", [])
for group in groups:
    if group.get("id") != "consumers":
        continue
    sources = group.setdefault("sources", {})
    cidrs = sources.setdefault("cidrs", [])
    for addr in ips:
        cidr = f"{addr}/32"
        if cidr not in cidrs:
            cidrs.append(cidr)
    cidrs.sort()

with open(dst, "w", encoding="utf-8") as fh:
    json.dump(data, fh)
    fh.write("\n")
PY
  POLICY_PAYLOAD="$TEMP_POLICY"
fi

for ip in $FW_MGMT_IPS; do
  echo "pushing policy to ${ip}"
  success=0
  for attempt in $(seq 1 45); do
    KEYSET_JSON="$(ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$ip" \
      "sudo cat /var/lib/neuwerk/http-tls/api-auth.json 2>/dev/null || true" || true)"
    TOKEN=""
    if [ -n "$KEYSET_JSON" ]; then
      TOKEN="$(KEYSET_JSON="$KEYSET_JSON" python3 - <<'PY'
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
    "sub": "azure-e2e",
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
        ["openssl", "pkeyutl", "-sign", "-rawin", "-in", str(msg), "-inkey", str(key_pem), "-out", str(sig)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    sig_b64 = b64url(sig.read_bytes())

token = f"{signing_input}.{sig_b64}"
print(token)
PY
)" || TOKEN=""
    fi
    AUTH_HEADER=""
    if [ -n "$TOKEN" ]; then
      AUTH_HEADER="-H 'Authorization: Bearer ${TOKEN}'"
    fi
    status="$(
      ssh -o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes -i "$KEY_PATH" \
        "${SSH_USER:-ubuntu}@${JUMPBOX_IP}" \
        "curl -sk -o /tmp/neuwerk-policy.response -w '%{http_code}' \
          --connect-timeout 5 --max-time 15 --retry 2 --retry-delay 1 \
          -X POST https://${ip}:8443/api/v1/policies \
          -H 'Content-Type: application/json' \
          ${AUTH_HEADER} \
          --data-binary @-" < "$POLICY_PAYLOAD" || true
    )"
    status="$(echo "$status" | tail -n1 | tr -d '\r')"
    if [[ "$status" =~ ^2[0-9][0-9]$ ]]; then
      success=1
      break
    fi
    if [ "$attempt" -eq 1 ] || [ "$attempt" -eq 10 ] || [ "$attempt" -eq 20 ] || [ "$attempt" -eq 30 ] || [ "$attempt" -eq 45 ]; then
      token_state="absent"
      if [ -n "$TOKEN" ]; then
        token_state="present"
      fi
      echo "policy push retry ${attempt}/45 for ${ip} (http_status=${status:-none}, token=${token_state})"
    fi
    sleep 2
  done
  if [ "$success" -ne 1 ]; then
    echo "failed to push policy to ${ip} after retries" >&2
    exit 1
  fi
 done

if [ -n "$TEMP_POLICY" ]; then
  rm -f "$TEMP_POLICY"
fi
