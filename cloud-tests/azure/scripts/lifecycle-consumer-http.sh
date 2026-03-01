#!/usr/bin/env bash
set -euo pipefail

UPSTREAM_VIP="${UPSTREAM_VIP:-}"
DNS_TARGET="${DNS_TARGET:-${UPSTREAM_VIP}}"
DNS_ZONE="${DNS_ZONE:-upstream.test}"
HTTP_HOST="${HTTP_HOST:-${DNS_ZONE}}"
HTTP_REQUEST_PATH="${HTTP_REQUEST_PATH:-/}"
HTTPS_REQUEST_PATH="${HTTPS_REQUEST_PATH:-/}"
DELAY_TARGET_IP="${DELAY_TARGET_IP:-${TARGET_IP:-}}"
DELAY_TARGET_PORT="${DELAY_TARGET_PORT:-${TARGET_PORT:-9000}}"
DELAY_REQUEST_PATH="${DELAY_REQUEST_PATH:-${REQUEST_PATH:-/delay/5}}"
STOP_FILE="${STOP_FILE:-/tmp/neuwerk-lifecycle-stop}"
WORKERS_PER_CLASS="${WORKERS_PER_CLASS:-${WORKERS:-4}}"
MAX_TIME_SECS="${MAX_TIME_SECS:-15}"
CONNECT_TIMEOUT_SECS="${CONNECT_TIMEOUT_SECS:-5}"
DIG_TIMEOUT_SECS="${DIG_TIMEOUT_SECS:-3}"
DIG_TRIES="${DIG_TRIES:-2}"
DELAY_MAX_TIME_SECS="${DELAY_MAX_TIME_SECS:-25}"
DELAY_CONNECT_TIMEOUT_SECS="${DELAY_CONNECT_TIMEOUT_SECS:-8}"
ENABLE_DNS_UDP="${ENABLE_DNS_UDP:-1}"
ENABLE_DNS_TCP="${ENABLE_DNS_TCP:-1}"
ENABLE_HTTP="${ENABLE_HTTP:-1}"
ENABLE_HTTPS="${ENABLE_HTTPS:-1}"
ENABLE_DELAYED_HTTP="${ENABLE_DELAYED_HTTP:-1}"

if ! [[ "$WORKERS_PER_CLASS" =~ ^[0-9]+$ ]] || [ "$WORKERS_PER_CLASS" -lt 1 ]; then
  echo "WORKERS_PER_CLASS must be >= 1" >&2
  exit 2
fi

RESULTS_FILE="$(mktemp /tmp/neuwerk-lifecycle-results.XXXXXX)"
PIDS_FILE="$(mktemp /tmp/neuwerk-lifecycle-pids.XXXXXX)"
trap 'rm -f "$RESULTS_FILE" "$PIDS_FILE"' EXIT

for bin in curl dig date awk grep tr cut seq; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo "missing required binary: $bin" >&2
    exit 2
  fi
done

CLASSES=()
if [ "$ENABLE_DNS_UDP" = "1" ]; then
  if [ -z "$DNS_TARGET" ]; then
    echo "DNS_TARGET is required when ENABLE_DNS_UDP=1" >&2
    exit 2
  fi
  CLASSES+=("dns_udp")
fi
if [ "$ENABLE_DNS_TCP" = "1" ]; then
  if [ -z "$DNS_TARGET" ]; then
    echo "DNS_TARGET is required when ENABLE_DNS_TCP=1" >&2
    exit 2
  fi
  CLASSES+=("dns_tcp")
fi
if [ "$ENABLE_HTTP" = "1" ]; then
  if [ -z "$UPSTREAM_VIP" ]; then
    echo "UPSTREAM_VIP is required when ENABLE_HTTP=1" >&2
    exit 2
  fi
  CLASSES+=("http")
fi
if [ "$ENABLE_HTTPS" = "1" ]; then
  if [ -z "$UPSTREAM_VIP" ]; then
    echo "UPSTREAM_VIP is required when ENABLE_HTTPS=1" >&2
    exit 2
  fi
  CLASSES+=("https")
fi
if [ "$ENABLE_DELAYED_HTTP" = "1" ]; then
  if [ -z "$DELAY_TARGET_IP" ]; then
    echo "DELAY_TARGET_IP is required when ENABLE_DELAYED_HTTP=1" >&2
    exit 2
  fi
  CLASSES+=("delayed_http")
fi
if [ "${#CLASSES[@]}" -eq 0 ]; then
  echo "no traffic classes enabled" >&2
  exit 2
fi

touch "$RESULTS_FILE"
rm -f "$STOP_FILE"

sanitize_error() {
  local err_file="$1"
  tr '\n' ' ' <"$err_file" | tr -s ' ' | cut -c1-220
}

sanitize_value() {
  tr '\n' ' ' | tr -s ' ' | cut -c1-120
}

worker() {
  local class="$1"
  local idx="$2"
  local err_file
  err_file="$(mktemp /tmp/neuwerk-lifecycle-err.${class}.${idx}.XXXXXX)"
  trap 'rm -f "$err_file"' RETURN
  while [ ! -f "$STOP_FILE" ]; do
    local started
    local finished
    local ms
    local rc
    local code
    local output
    local err
    local sample
    local safe_output
    rc=0
    code=""
    output=""
    err=""
    sample=""
    started="$(date +%s%3N)"
    case "$class" in
      dns_udp)
        set +e
        output="$(dig +time="${DIG_TIMEOUT_SECS}" +tries="${DIG_TRIES}" +short @"${DNS_TARGET}" "${DNS_ZONE}" A 2>"${err_file}")"
        rc=$?
        set -e
        sample="$(echo "$output" | awk 'NF{print; exit}')"
        if [ "$rc" -eq 0 ] && [ -n "$sample" ]; then
          code="ok"
        else
          code="fail"
        fi
        ;;
      dns_tcp)
        set +e
        output="$(dig +tcp +time="${DIG_TIMEOUT_SECS}" +tries="${DIG_TRIES}" +short @"${DNS_TARGET}" "${DNS_ZONE}" A 2>"${err_file}")"
        rc=$?
        set -e
        sample="$(echo "$output" | awk 'NF{print; exit}')"
        if [ "$rc" -eq 0 ] && [ -n "$sample" ]; then
          code="ok"
        else
          code="fail"
        fi
        ;;
      http)
        set +e
        output="$(curl -sS -o /dev/null \
          --write-out "%{http_code}" \
          --max-time "$MAX_TIME_SECS" \
          --connect-timeout "$CONNECT_TIMEOUT_SECS" \
          --resolve "${HTTP_HOST}:80:${UPSTREAM_VIP}" \
          "http://${HTTP_HOST}${HTTP_REQUEST_PATH}" 2>"${err_file}")"
        rc=$?
        set -e
        if [ "$rc" -eq 0 ] && [ "$output" = "200" ]; then
          code="ok"
        else
          code="fail"
        fi
        ;;
      https)
        set +e
        output="$(curl -ksS -o /dev/null \
          --write-out "%{http_code}" \
          --max-time "$MAX_TIME_SECS" \
          --connect-timeout "$CONNECT_TIMEOUT_SECS" \
          --resolve "${HTTP_HOST}:443:${UPSTREAM_VIP}" \
          "https://${HTTP_HOST}${HTTPS_REQUEST_PATH}" 2>"${err_file}")"
        rc=$?
        set -e
        if [ "$rc" -eq 0 ] && [ "$output" = "200" ]; then
          code="ok"
        else
          code="fail"
        fi
        ;;
      delayed_http)
        set +e
        output="$(curl -sS -o /dev/null \
          --write-out "%{http_code}" \
          --max-time "$DELAY_MAX_TIME_SECS" \
          --connect-timeout "$DELAY_CONNECT_TIMEOUT_SECS" \
          "http://${DELAY_TARGET_IP}:${DELAY_TARGET_PORT}${DELAY_REQUEST_PATH}" 2>"${err_file}")"
        rc=$?
        set -e
        if [ "$rc" -eq 0 ] && [ "$output" = "200" ]; then
          code="ok"
        else
          code="fail"
        fi
        ;;
      *)
        echo "unknown class: ${class}" >&2
        exit 2
        ;;
    esac
    finished="$(date +%s%3N)"
    ms=$((finished - started))
    if [ "$code" = "ok" ]; then
      printf "ok class=%s worker=%s latency_ms=%s\n" "$class" "$idx" "$ms" >>"$RESULTS_FILE"
    else
      err="$(sanitize_error "$err_file")"
      if [ -z "$err" ] && [ -n "$sample" ]; then
        err="$sample"
      fi
      safe_output="$(printf "%s" "${output:-none}" | sanitize_value)"
      printf "fail class=%s worker=%s latency_ms=%s rc=%s code=%s err=\"%s\"\n" "$class" "$idx" "$ms" "${rc}" "${safe_output}" "${err}" >>"$RESULTS_FILE"
    fi
  done
}

for class in "${CLASSES[@]}"; do
  for idx in $(seq 1 "$WORKERS_PER_CLASS"); do
    worker "$class" "$idx" &
    echo "$!" >>"$PIDS_FILE"
  done
done

while [ ! -f "$STOP_FILE" ]; do
  sleep 1
done

while read -r pid; do
  wait "$pid" || true
done <"$PIDS_FILE"

total="$(wc -l <"$RESULTS_FILE" | tr -d ' ')"
fails="$(grep -c '^fail ' "$RESULTS_FILE" || true)"
oks=$((total - fails))

for class in "${CLASSES[@]}"; do
  class_total="$(grep -c " class=${class} " "$RESULTS_FILE" || true)"
  class_fail="$(grep -c "^fail class=${class} " "$RESULTS_FILE" || true)"
  class_ok=$((class_total - class_fail))
  echo "lifecycle_consumer_class_summary class=${class} total=${class_total} ok=${class_ok} fail=${class_fail}"
done
echo "lifecycle_consumer_summary total=${total} ok=${oks} fail=${fails}"
if [ "$fails" -gt 0 ]; then
  echo "lifecycle_consumer_first_failure:"
  grep '^fail ' "$RESULTS_FILE" | head -n1
  exit 1
fi
