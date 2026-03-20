#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)
TF_DIR="${TF_DIR:-${ROOT_DIR}/terraform}"
KEY_PATH="${KEY_PATH:-${ROOT_DIR}/../.secrets/ssh/aws_e2e}"
POLICY_FILE="${POLICY_FILE:-${ROOT_DIR}/policies/allow-upstream.json}"
ARTIFACT_DIR="${ARTIFACT_DIR:-${ROOT_DIR}/artifacts}"

DURATION_SECS="${DURATION_SECS:-240}"
WARMUP_SECS="${WARMUP_SECS:-30}"
CONCURRENCY="${CONCURRENCY:-24}"
REQUEST_TIMEOUT_SECS="${REQUEST_TIMEOUT_SECS:-8}"
REFRESH_INSTANCE_WARMUP_SECS="${REFRESH_INSTANCE_WARMUP_SECS:-120}"
REFRESH_TIMEOUT_SECS="${REFRESH_TIMEOUT_SECS:-1800}"
POLL_SECS="${POLL_SECS:-15}"

source "${ROOT_DIR}/../common/lib.sh"

require_bin terraform
require_bin aws
require_bin jq
require_bin ssh
require_bin awk

if ! aws sts get-caller-identity >/dev/null 2>&1; then
  echo "aws credentials are required (aws sts get-caller-identity failed)" >&2
  exit 1
fi

if [ ! -f "$KEY_PATH" ]; then
  echo "missing SSH key at ${KEY_PATH}" >&2
  exit 1
fi

if [ "${SKIP_POLICY:-0}" != "1" ]; then
  TF_DIR="$TF_DIR" KEY_PATH="$KEY_PATH" "${ROOT_DIR}/scripts/configure-policy.sh" "$POLICY_FILE"
fi

pushd "$TF_DIR" >/dev/null
REGION=$(terraform output -raw region)
ASG_NAME=$(terraform output -raw neuwerk_asg_name)
JUMPBOX_IP=$(terraform output -raw jumpbox_public_ip)
UPSTREAM_VIP=$(terraform output -raw upstream_vip)
CONSUMER_IP=$(terraform output -json consumer_private_ips | jq -r '.[0]')
popd >/dev/null

if [ -z "$ASG_NAME" ] || [ "$ASG_NAME" = "null" ]; then
  echo "neuwerk_asg_name output is empty; this bench is not running ASG-backed neuwerk nodes" >&2
  exit 1
fi

if [ -z "$CONSUMER_IP" ] || [ "$CONSUMER_IP" = "null" ]; then
  echo "no consumer IP found in terraform outputs" >&2
  exit 1
fi

run_id="aws-connectivity-rollout-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$ARTIFACT_DIR"
log_file="${ARTIFACT_DIR}/${run_id}.log"
flow_file="${ARTIFACT_DIR}/${run_id}.consumer-flow.log"
result_file="${ARTIFACT_DIR}/${run_id}.result.json"

workload_pid=""
cleanup() {
  if [ -n "${workload_pid}" ] && kill -0 "${workload_pid}" >/dev/null 2>&1; then
    kill "${workload_pid}" >/dev/null 2>&1 || true
    wait "${workload_pid}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

{
  echo "context: region=${REGION} asg=${ASG_NAME} jumpbox=${JUMPBOX_IP} consumer=${CONSUMER_IP} upstream_vip=${UPSTREAM_VIP}"
  echo "params: duration_secs=${DURATION_SECS} warmup_secs=${WARMUP_SECS} concurrency=${CONCURRENCY} req_timeout_secs=${REQUEST_TIMEOUT_SECS}"
} | tee -a "$log_file"

ssh_jump "$JUMPBOX_IP" "$KEY_PATH" "$CONSUMER_IP" \
  "UPSTREAM_VIP='${UPSTREAM_VIP}' DURATION_SECS='${DURATION_SECS}' CONCURRENCY='${CONCURRENCY}' REQUEST_TIMEOUT_SECS='${REQUEST_TIMEOUT_SECS}' bash -s" \
  >"$flow_file" 2>>"$log_file" <<'EOF' &
set -euo pipefail
deadline=$(( $(date +%s) + DURATION_SECS ))
worker() {
  while [ "$(date +%s)" -lt "$deadline" ]; do
    ts=$(date +%s%3N)
    if curl -fsS --connect-timeout 3 --max-time "$REQUEST_TIMEOUT_SECS" "http://${UPSTREAM_VIP}/" >/dev/null; then
      echo "ok $ts"
    else
      echo "fail $ts"
    fi
  done
}
for _ in $(seq 1 "$CONCURRENCY"); do
  worker &
done
wait
EOF
workload_pid=$!
echo "workload started pid=${workload_pid}; warmup=${WARMUP_SECS}s" | tee -a "$log_file"

sleep "$WARMUP_SECS"

rollout_start_ms=$(date +%s%3N)
refresh_id=$(aws autoscaling start-instance-refresh \
  --region "$REGION" \
  --auto-scaling-group-name "$ASG_NAME" \
  --strategy Rolling \
  --preferences "{\"MinHealthyPercentage\":100,\"InstanceWarmup\":${REFRESH_INSTANCE_WARMUP_SECS}}" \
  --query 'InstanceRefreshId' \
  --output text)
echo "started instance refresh: id=${refresh_id}" | tee -a "$log_file"

refresh_deadline=$(( $(date +%s) + REFRESH_TIMEOUT_SECS ))
while true; do
  status=$(aws autoscaling describe-instance-refreshes \
    --region "$REGION" \
    --auto-scaling-group-name "$ASG_NAME" \
    --query "InstanceRefreshes[?InstanceRefreshId=='${refresh_id}']|[0].Status" \
    --output text)
  pct=$(aws autoscaling describe-instance-refreshes \
    --region "$REGION" \
    --auto-scaling-group-name "$ASG_NAME" \
    --query "InstanceRefreshes[?InstanceRefreshId=='${refresh_id}']|[0].PercentageComplete" \
    --output text)
  echo "refresh status=${status} percent=${pct}" >>"$log_file"

  case "$status" in
    Successful)
      break
      ;;
    Failed|Cancelled|RollbackFailed)
      echo "instance refresh ended with status=${status}" | tee -a "$log_file"
      exit 1
      ;;
    *)
      ;;
  esac

  if [ "$(date +%s)" -ge "$refresh_deadline" ]; then
    echo "instance refresh timed out after ${REFRESH_TIMEOUT_SECS}s" | tee -a "$log_file"
    exit 1
  fi
  sleep "$POLL_SECS"
done

# Ensure the group has converged after refresh.
while true; do
  desired=$(aws autoscaling describe-auto-scaling-groups \
    --region "$REGION" \
    --auto-scaling-group-names "$ASG_NAME" \
    --query 'AutoScalingGroups[0].DesiredCapacity' \
    --output text)
  in_service=$(aws autoscaling describe-auto-scaling-groups \
    --region "$REGION" \
    --auto-scaling-group-names "$ASG_NAME" \
    --query 'length(AutoScalingGroups[0].Instances[?LifecycleState==`InService`])' \
    --output text)
  echo "asg convergence desired=${desired} in_service=${in_service}" >>"$log_file"
  if [ "${in_service}" -ge "${desired}" ]; then
    break
  fi
  sleep "$POLL_SECS"
done

rollout_end_ms=$(date +%s%3N)
echo "rollout window: ${rollout_start_ms}..${rollout_end_ms}" | tee -a "$log_file"

wait "$workload_pid"
workload_pid=""

read ok fail total fail_before fail_during fail_after < <(
  awk -v rollout_start="$rollout_start_ms" -v rollout_end="$rollout_end_ms" '
    $1=="ok" {
      ok += 1;
      total += 1;
      next;
    }
    $1=="fail" {
      fail += 1;
      total += 1;
      ts = $2 + 0;
      if (ts < rollout_start) {
        fail_before += 1;
      } else if (ts <= rollout_end) {
        fail_during += 1;
      } else {
        fail_after += 1;
      }
    }
    END {
      printf "%d %d %d %d %d %d\n", ok + 0, fail + 0, total + 0, fail_before + 0, fail_during + 0, fail_after + 0;
    }
  ' "$flow_file"
)

fail_pct=$(awk -v f="$fail" -v t="$total" 'BEGIN { if (t == 0) { printf "0.000000"; } else { printf "%.6f", (f * 100.0) / t; } }')
summary_line="ok=${ok} fail=${fail} total=${total} fail_pct=${fail_pct}"

jq -n \
  --arg run_id "$run_id" \
  --arg region "$REGION" \
  --arg asg_name "$ASG_NAME" \
  --argjson duration_secs "$DURATION_SECS" \
  --argjson concurrency "$CONCURRENCY" \
  --argjson rollout_start_ms "$rollout_start_ms" \
  --argjson rollout_end_ms "$rollout_end_ms" \
  --arg summary_line "$summary_line" \
  --argjson ok "$ok" \
  --argjson fail "$fail" \
  --argjson total "$total" \
  --argjson fail_pct "$fail_pct" \
  --argjson fail_before "$fail_before" \
  --argjson fail_during "$fail_during" \
  --argjson fail_after "$fail_after" \
  '{
    run_id: $run_id,
    region: $region,
    asg_name: $asg_name,
    duration_secs: $duration_secs,
    concurrency: $concurrency,
    rollout_start_ms: $rollout_start_ms,
    rollout_end_ms: $rollout_end_ms,
    summary_line: $summary_line,
    counts: {
      ok: $ok,
      fail: $fail,
      total: $total,
      fail_pct: $fail_pct
    },
    failures: {
      before: $fail_before,
      during: $fail_during,
      after: $fail_after
    }
  }' >"$result_file"

{
  echo "RESULT: ${summary_line}%"
  echo "RESULT: fail_before=${fail_before} fail_during=${fail_during} fail_after=${fail_after}"
  echo "artifact_log=${log_file}"
  echo "artifact_flow=${flow_file}"
  echo "artifact_result=${result_file}"
} | tee -a "$log_file"

if [ "$fail_during" -gt 0 ]; then
  exit 1
fi
