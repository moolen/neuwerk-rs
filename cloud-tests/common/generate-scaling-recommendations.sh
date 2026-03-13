#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 3 ]; then
  echo "usage: $0 <throughput-result.json> <http-matrix-summary.json> <out-dir>" >&2
  exit 2
fi

THROUGHPUT_RESULT="$1"
HTTP_MATRIX_SUMMARY="$2"
OUT_DIR="$3"
CLUSTER_NODE_COUNTS="${CLUSTER_NODE_COUNTS:-1,2,3}"

if [ ! -f "$THROUGHPUT_RESULT" ]; then
  echo "missing throughput result: $THROUGHPUT_RESULT" >&2
  exit 1
fi
if [ ! -f "$HTTP_MATRIX_SUMMARY" ]; then
  echo "missing http matrix summary: $HTTP_MATRIX_SUMMARY" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"

python3 - "$THROUGHPUT_RESULT" "$HTTP_MATRIX_SUMMARY" "$OUT_DIR/recommendations.json" "$OUT_DIR/recommendations.md" "$CLUSTER_NODE_COUNTS" <<'PY'
import json
import statistics
import sys
from datetime import datetime, timezone

throughput_path, http_path, out_json, out_md, cluster_counts_csv = sys.argv[1:]

with open(throughput_path, "r", encoding="utf-8") as f:
    throughput = json.load(f)
with open(http_path, "r", encoding="utf-8") as f:
    http = json.load(f)

cluster_counts = []
for raw in cluster_counts_csv.split(","):
    raw = raw.strip()
    if not raw:
        continue
    try:
        val = int(raw)
    except ValueError:
        continue
    if val > 0:
        cluster_counts.append(val)
if not cluster_counts:
    cluster_counts = [1, 2, 3]

highest = http.get("highest_tier_reached", [])

# Single-node recommendation baseline scenarios.
def pick(scenario):
    return [item for item in highest if item.get("scenario") == scenario]

http_rows = pick("http_l34_allow")
https_rows = pick("https_l34_allow")
dpi_rows = pick("tls_intercept_http_path")

single_node = {
    "raw_ip": {
        "max_tcp_gbps": throughput.get("max_tcp_gbps"),
        "max_udp_gbps": throughput.get("max_udp_gbps"),
        "max_tcp_gbps_per_core": throughput.get("max_tcp_gbps_per_core"),
        "max_udp_gbps_per_core": throughput.get("max_udp_gbps_per_core"),
    },
    "http": sorted(http_rows, key=lambda x: (x.get("payload_bytes", 0), x.get("connection_mode", ""))),
    "https": sorted(https_rows, key=lambda x: (x.get("payload_bytes", 0), x.get("connection_mode", ""))),
    "https_dpi": sorted(dpi_rows, key=lambda x: (x.get("payload_bytes", 0), x.get("connection_mode", ""))),
}

cluster_capacity = []
for nodes in cluster_counts:
    entry = {
        "nodes": nodes,
        "raw_ip": {
            "tcp_gbps": single_node["raw_ip"].get("max_tcp_gbps") * nodes if single_node["raw_ip"].get("max_tcp_gbps") is not None else None,
            "udp_gbps": single_node["raw_ip"].get("max_udp_gbps") * nodes if single_node["raw_ip"].get("max_udp_gbps") is not None else None,
        },
        "http": [],
        "https": [],
        "https_dpi": [],
    }

    for key in ("http", "https", "https_dpi"):
        for row in single_node[key]:
            row_copy = dict(row)
            eff = row_copy.get("effective_rps_median")
            row_copy["effective_rps_cluster_estimate"] = eff * nodes if isinstance(eff, (int, float)) else None
            entry[key].append(row_copy)

    cluster_capacity.append(entry)

payload = {
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "methodology": {
        "aggregation": "median",
        "cluster_scaling_model": "linear_estimate",
        "notes": [
            "Cluster numbers assume near-linear scaling and should be validated under real load-balancing behavior.",
            "HTTP/HTTPS recommendations are scenario-based and derived from highest passing RPS tier with median effective RPS.",
        ],
    },
    "inputs": {
        "throughput_result": throughput_path,
        "http_matrix_summary": http_path,
    },
    "single_node": single_node,
    "cluster_capacity_estimates": cluster_capacity,
}

with open(out_json, "w", encoding="utf-8") as f:
    json.dump(payload, f, indent=2, sort_keys=True)
    f.write("\n")

lines = []
lines.append("# Scaling Recommendations")
lines.append("")
lines.append(f"Generated at: {payload['generated_at']}")
lines.append("")
lines.append("## Single Node")
lines.append("")
raw = single_node["raw_ip"]
lines.append("### Raw IP")
lines.append("")
lines.append("| Metric | Value |")
lines.append("|---|---:|")
lines.append(f"| Max TCP Gbps | {raw.get('max_tcp_gbps')} |")
lines.append(f"| Max UDP Gbps | {raw.get('max_udp_gbps')} |")
lines.append(f"| Max TCP Gbps/core | {raw.get('max_tcp_gbps_per_core')} |")
lines.append(f"| Max UDP Gbps/core | {raw.get('max_udp_gbps_per_core')} |")
lines.append("")

for title, key in (("HTTP", "http"), ("HTTPS", "https"), ("HTTPS + DPI", "https_dpi")):
    rows = single_node[key]
    lines.append(f"### {title}")
    lines.append("")
    lines.append("| Payload (bytes) | Connection Mode | Target RPS Tier | Effective RPS Median | P99 Median (ms) | Error Median |")
    lines.append("|---:|---|---:|---:|---:|---:|")
    if rows:
        for r in rows:
            lines.append(
                f"| {r.get('payload_bytes')} | {r.get('connection_mode')} | {r.get('rps_target')} | {r.get('effective_rps_median')} | {r.get('latency_p99_ms_max_median')} | {r.get('error_rate_median')} |"
            )
    else:
        lines.append("| - | - | - | - | - | - |")
    lines.append("")

lines.append("## Cluster Capacity Estimates")
lines.append("")
for c in cluster_capacity:
    lines.append(f"### {c['nodes']} Nodes")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|---|---:|")
    lines.append(f"| TCP Gbps (estimate) | {c['raw_ip'].get('tcp_gbps')} |")
    lines.append(f"| UDP Gbps (estimate) | {c['raw_ip'].get('udp_gbps')} |")
    lines.append("")

lines.append("## Notes")
lines.append("")
lines.append("- Aggregation is median-based across measured runs.")
lines.append("- Cluster numbers are linear estimates and need validation in each environment.")

with open(out_md, "w", encoding="utf-8") as f:
    f.write("\n".join(lines) + "\n")
PY

echo "recommendations written: ${OUT_DIR}/recommendations.{json,md}"
