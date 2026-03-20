#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <stage> <artifact-dir>" >&2
  exit 2
fi

STAGE="$1"
ARTIFACT_DIR="$2"

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)
TF_DIR="${TF_DIR:-${ROOT_DIR}/terraform}"
KEY_PATH="${KEY_PATH:-${ROOT_DIR}/../.secrets/ssh/azure_e2e}"
RESOLVE_FW_IPS="${ROOT_DIR}/scripts/resolve-neuwerk-mgmt-ips.sh"

source "${ROOT_DIR}/../common/lib.sh"

require_bin terraform
require_bin jq
require_bin ssh
require_bin python3

if [ ! -f "${KEY_PATH}" ]; then
  echo "missing SSH key at ${KEY_PATH}" >&2
  exit 1
fi

mkdir -p "${ARTIFACT_DIR}/raw"

pushd "$TF_DIR" >/dev/null
JUMPBOX_IP="$(terraform output -raw jumpbox_public_ip)"
popd >/dev/null

if [ -z "$JUMPBOX_IP" ]; then
  echo "missing jumpbox_public_ip output" >&2
  exit 1
fi

FW_MGMT_IPS="$(TF_DIR="$TF_DIR" "$RESOLVE_FW_IPS")"
if [ -z "$FW_MGMT_IPS" ]; then
  echo "no neuwerk management IPs found" >&2
  exit 1
fi

combined_prom="${ARTIFACT_DIR}/neuwerk-metrics-${STAGE}.prom"
cpu_tsv="${ARTIFACT_DIR}/raw/cpu-${STAGE}.tsv"
: > "$combined_prom"
: > "$cpu_tsv"

for ip in $FW_MGMT_IPS; do
  safe_ip="${ip//./_}"
  metrics_file="${ARTIFACT_DIR}/raw/${STAGE}.${safe_ip}.metrics.prom"
  cpu_log="${ARTIFACT_DIR}/raw/${STAGE}.${safe_ip}.cpu.log"

  metrics="$(ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$ip" \
    "bash -lc 'METRICS_HOST=\$(grep \"^MGMT_IP=\" /etc/neuwerk/neuwerk.env 2>/dev/null | cut -d= -f2); [ -z \"\$METRICS_HOST\" ] && METRICS_HOST=127.0.0.1; curl -fsS http://\${METRICS_HOST}:8080/metrics'" || true)"
  printf "%s\n" "$metrics" > "$metrics_file"

  {
    echo "# instance=${ip} stage=${STAGE}"
    cat "$metrics_file"
    echo
  } >> "$combined_prom"

  cpu_out="$(ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$ip" "bash -lc 'if command -v mpstat >/dev/null 2>&1; then mpstat 1 1; else vmstat 1 2; fi'" || true)"
  printf "%s\n" "$cpu_out" > "$cpu_log"
  printf "%s\t%s\n" "$ip" "$cpu_log" >> "$cpu_tsv"
done

python3 - "$cpu_tsv" "${ARTIFACT_DIR}/cpu-neuwerk-${STAGE}.json" <<'PY'
import json
import re
import statistics
import sys

if len(sys.argv) != 3:
    raise SystemExit("usage: parse_cpu <cpu-tsv> <out-json>")

cpu_tsv, out_json = sys.argv[1], sys.argv[2]

entries = []
with open(cpu_tsv, "r", encoding="utf-8") as f:
    for row in f:
        row = row.strip()
        if not row:
            continue
        ip, log_path = row.split("\t", 1)
        samples = []
        with open(log_path, "r", encoding="utf-8", errors="replace") as cpu_log:
            for line in cpu_log:
                s = line.strip()
                if not s:
                    continue
                if "Average:" in s and " all " in f" {s} ":
                    parts = s.split()
                    try:
                        idle = float(parts[-1])
                        samples.append(max(0.0, min(100.0, 100.0 - idle)))
                    except ValueError:
                        pass
                    continue
                if re.match(r"^\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+", s):
                    parts = s.split()
                    try:
                        idle = float(parts[14])
                        samples.append(max(0.0, min(100.0, 100.0 - idle)))
                    except ValueError:
                        pass
        item = {"instance": ip, "samples": len(samples)}
        if samples:
            item["cpu_used_pct_avg"] = round(statistics.fmean(samples), 3)
            item["cpu_used_pct_max"] = round(max(samples), 3)
        else:
            item["cpu_used_pct_avg"] = None
            item["cpu_used_pct_max"] = None
        entries.append(item)

with open(out_json, "w", encoding="utf-8") as out:
    json.dump(entries, out, indent=2, sort_keys=True)
    out.write("\n")
PY

echo "collected stage=${STAGE} metrics into ${ARTIFACT_DIR}"
