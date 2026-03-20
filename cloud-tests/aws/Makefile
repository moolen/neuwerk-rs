SHELL := /usr/bin/env bash
.SHELLFLAGS := -euo pipefail -c
MAKEFLAGS += --no-print-directory

TF_DIR ?= $(CURDIR)/terraform
KEY_PATH ?= $(CURDIR)/../.secrets/ssh/aws_e2e
SSH_USER ?= ubuntu
INDEX ?= 0
RESOLVE_FW_IPS ?= $(CURDIR)/scripts/resolve-neuwerk-mgmt-ips.sh
MINT_API_TOKEN ?= $(CURDIR)/scripts/mint-api-token.sh

.PHONY: ssh.jumpbox ssh.consumer ssh.upstream ssh.neuwerk health policy-smoke performance.scenario run-tests lifecycle-rollout throughput.matrix cps.matrix connscale.matrix http-perf.setup http-perf.run http-perf.quick scaling.report

ssh.jumpbox:
	@command -v terraform >/dev/null || { echo "terraform is required" >&2; exit 1; }
	@command -v ssh >/dev/null || { echo "ssh is required" >&2; exit 1; }
	@command -v ssh-keygen >/dev/null || { echo "ssh-keygen is required" >&2; exit 1; }
	@if [ ! -f "$(KEY_PATH)" ]; then echo "missing SSH key at $(KEY_PATH)" >&2; exit 1; fi
	@jump_ip=$$(cd "$(TF_DIR)" && terraform output -raw jumpbox_public_ip); \
	if [ -z "$$jump_ip" ]; then echo "missing jumpbox_public_ip output" >&2; exit 1; fi; \
	ssh-keygen -R "$$jump_ip" >/dev/null 2>&1 || true; \
	exec ssh -o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes -i "$(KEY_PATH)" "$(SSH_USER)@$$jump_ip"

ssh.upstream:
	@command -v terraform >/dev/null || { echo "terraform is required" >&2; exit 1; }
	@command -v ssh >/dev/null || { echo "ssh is required" >&2; exit 1; }
	@command -v ssh-keygen >/dev/null || { echo "ssh-keygen is required" >&2; exit 1; }
	@if [ ! -f "$(KEY_PATH)" ]; then echo "missing SSH key at $(KEY_PATH)" >&2; exit 1; fi
	@jump_ip=$$(cd "$(TF_DIR)" && terraform output -raw jumpbox_public_ip); \
	upstream_ip=$$(cd "$(TF_DIR)" && terraform output -raw upstream_private_ip); \
	if [ -z "$$jump_ip" ] || [ -z "$$upstream_ip" ]; then echo "missing terraform outputs" >&2; exit 1; fi; \
	ssh-keygen -R "$$jump_ip" >/dev/null 2>&1 || true; \
	ssh-keygen -R "$$upstream_ip" >/dev/null 2>&1 || true; \
	exec ssh -o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes -i "$(KEY_PATH)" \
		-o ProxyCommand="ssh -o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes -i $(KEY_PATH) -W %h:%p $(SSH_USER)@$$jump_ip" \
		"$(SSH_USER)@$$upstream_ip"

ssh.consumer:
	@command -v terraform >/dev/null || { echo "terraform is required" >&2; exit 1; }
	@command -v ssh >/dev/null || { echo "ssh is required" >&2; exit 1; }
	@command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
	@command -v ssh-keygen >/dev/null || { echo "ssh-keygen is required" >&2; exit 1; }
	@if [ ! -f "$(KEY_PATH)" ]; then echo "missing SSH key at $(KEY_PATH)" >&2; exit 1; fi
	@index="$(INDEX)"; \
	if [ -z "$$index" ]; then index=0; fi; \
	jump_ip=$$(cd "$(TF_DIR)" && terraform output -raw jumpbox_public_ip); \
	consumer_ip=$$(cd "$(TF_DIR)" && terraform output -json consumer_private_ips | \
		jq -r --arg idx "$$index" '.[($$idx|tonumber)]'); \
	if [ -z "$$jump_ip" ] || [ -z "$$consumer_ip" ] || [ "$$consumer_ip" = "null" ]; then \
		echo "missing consumer IP for INDEX=$$index" >&2; exit 1; \
	fi; \
	ssh-keygen -R "$$jump_ip" >/dev/null 2>&1 || true; \
	ssh-keygen -R "$$consumer_ip" >/dev/null 2>&1 || true; \
	exec ssh -o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes -i "$(KEY_PATH)" \
		-o ProxyCommand="ssh -o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes -i $(KEY_PATH) -W %h:%p $(SSH_USER)@$$jump_ip" \
		"$(SSH_USER)@$$consumer_ip"

ssh.neuwerk:
	@command -v terraform >/dev/null || { echo "terraform is required" >&2; exit 1; }
	@command -v ssh >/dev/null || { echo "ssh is required" >&2; exit 1; }
	@command -v ssh-keygen >/dev/null || { echo "ssh-keygen is required" >&2; exit 1; }
	@if [ ! -f "$(KEY_PATH)" ]; then echo "missing SSH key at $(KEY_PATH)" >&2; exit 1; fi
	@index="$(INDEX)"; \
	if [ -z "$$index" ]; then index=0; fi; \
	jump_ip=$$(cd "$(TF_DIR)" && terraform output -raw jumpbox_public_ip); \
	if [ -z "$$jump_ip" ]; then echo "missing jumpbox_public_ip output" >&2; exit 1; fi; \
	ips=$$(TF_DIR="$(TF_DIR)" "$(RESOLVE_FW_IPS)"); \
	idx=$$(( $$index + 1 )); \
	ip=$$(echo "$$ips" | sort -u | sed -n "$$idx"'p'); \
	if [ -z "$$ip" ]; then echo "missing neuwerk IP for INDEX=$$index" >&2; exit 1; fi; \
	ssh-keygen -R "$$jump_ip" >/dev/null 2>&1 || true; \
	ssh-keygen -R "$$ip" >/dev/null 2>&1 || true; \
	exec ssh -o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes -i "$(KEY_PATH)" \
		-o ProxyCommand="ssh -o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes -i $(KEY_PATH) -W %h:%p $(SSH_USER)@$$jump_ip" \
		"$(SSH_USER)@$$ip"

health:
	@TF_DIR="$(TF_DIR)" KEY_PATH="$(KEY_PATH)" SSH_USER="$(SSH_USER)" \
		"$(CURDIR)/scripts/health.sh"

policy-smoke:
	@command -v terraform >/dev/null || { echo "terraform is required" >&2; exit 1; }
	@command -v aws >/dev/null || { echo "aws CLI is required" >&2; exit 1; }
	@command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
	@command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }
	@command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 1; }
	@command -v cargo >/dev/null || { echo "cargo is required" >&2; exit 1; }
	@if [ ! -f "$(KEY_PATH)" ]; then echo "missing SSH key at $(KEY_PATH)" >&2; exit 1; fi
	@TF_DIR="$(TF_DIR)" KEY_PATH="$(KEY_PATH)" SSH_USER="$(SSH_USER)" RUN_THROUGHPUT=0 \
		"$(CURDIR)/scripts/run-tests.sh"

performance.scenario:
	@command -v terraform >/dev/null || { echo "terraform is required" >&2; exit 1; }
	@command -v aws >/dev/null || { echo "aws CLI is required" >&2; exit 1; }
	@command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
	@if [ ! -f "$(KEY_PATH)" ]; then echo "missing SSH key at $(KEY_PATH)" >&2; exit 1; fi
	@TF_DIR="$(TF_DIR)" KEY_PATH="$(KEY_PATH)" SSH_USER="$(SSH_USER)" \
		PERF_PATHS="$(PERF_PATHS)" \
		PERF_ENABLE_THROUGHPUT="$(PERF_ENABLE_THROUGHPUT)" \
		PERF_ENABLE_CPS="$(PERF_ENABLE_CPS)" \
		PERF_ENABLE_NAT="$(PERF_ENABLE_NAT)" \
		PERF_ENABLE_TLS_DPI="$(PERF_ENABLE_TLS_DPI)" \
		PERF_CPS_WORKERS_LIST="$(PERF_CPS_WORKERS_LIST)" \
		PERF_HTTP_SCENARIOS="$(PERF_HTTP_SCENARIOS)" \
		PERF_ARTIFACT_DIR="$(PERF_ARTIFACT_DIR)" \
		WORKERS_LIST="$(WORKERS_LIST)" \
		HTTP_PERF_SCENARIOS="$(HTTP_PERF_SCENARIOS)" \
		bash "$(CURDIR)/scripts/performance-scenario.sh"

run-tests:
	@TF_DIR="$(TF_DIR)" KEY_PATH="$(KEY_PATH)" SSH_USER="$(SSH_USER)" \
		"$(CURDIR)/scripts/run-tests.sh"

lifecycle-rollout:
	@TF_DIR="$(TF_DIR)" KEY_PATH="$(KEY_PATH)" SSH_USER="$(SSH_USER)" \
		"$(CURDIR)/scripts/lifecycle-rollout.sh"

throughput.matrix:
	@command -v terraform >/dev/null || { echo "terraform is required" >&2; exit 1; }
	@command -v ssh >/dev/null || { echo "ssh is required" >&2; exit 1; }
	@command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
	@command -v aws >/dev/null || { echo "aws CLI is required" >&2; exit 1; }
	@if [ ! -f "$(KEY_PATH)" ]; then echo "missing SSH key at $(KEY_PATH)" >&2; exit 1; fi
	@TF_DIR="$(TF_DIR)" KEY_PATH="$(KEY_PATH)" SSH_USER="$(SSH_USER)" \
		"$(CURDIR)/scripts/throughput-matrix.sh"

cps.matrix:
	@command -v terraform >/dev/null || { echo "terraform is required" >&2; exit 1; }
	@command -v aws >/dev/null || { echo "aws CLI is required" >&2; exit 1; }
	@command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
	@if [ ! -f "$(KEY_PATH)" ]; then echo "missing SSH key at $(KEY_PATH)" >&2; exit 1; fi
	@TF_DIR="$(TF_DIR)" KEY_PATH="$(KEY_PATH)" SSH_USER="$(SSH_USER)" \
		TARGET_HOST="$(TARGET_HOST)" TARGET_HOSTS="$(TARGET_HOSTS)" TARGET_PORT="$(TARGET_PORT)" TARGET_PORTS="$(TARGET_PORTS)" \
		WORKERS_LIST="$(WORKERS_LIST)" RUN_SECONDS="$(RUN_SECONDS)" WARMUP_SECONDS="$(WARMUP_SECONDS)" REPEATS="$(REPEATS)" \
		CONNECT_TIMEOUT_MS="$(CONNECT_TIMEOUT_MS)" CPS_CLIENT_BACKEND="$(CPS_CLIENT_BACKEND)" \
		CPS_RUST_TCP_CPS_PER_WORKER="$(CPS_RUST_TCP_CPS_PER_WORKER)" CPS_RUST_TCP_MAX_CPS="$(CPS_RUST_TCP_MAX_CPS)" \
		CPS_SOURCE_IPS_CSV_OVERRIDE="$(CPS_SOURCE_IPS_CSV_OVERRIDE)" \
		bash "$(CURDIR)/scripts/cps-matrix.sh"

connscale.matrix:
	@command -v terraform >/dev/null || { echo "terraform is required" >&2; exit 1; }
	@command -v aws >/dev/null || { echo "aws CLI is required" >&2; exit 1; }
	@command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
	@if [ ! -f "$(KEY_PATH)" ]; then echo "missing SSH key at $(KEY_PATH)" >&2; exit 1; fi
	@TF_DIR="$(TF_DIR)" KEY_PATH="$(KEY_PATH)" SSH_USER="$(SSH_USER)" \
		TARGET_HOST="$(TARGET_HOST)" TARGET_PORT="$(TARGET_PORT)" CONNECTION_TIERS="$(CONNECTION_TIERS)" \
		OPEN_WORKERS="$(OPEN_WORKERS)" CONNECT_TIMEOUT_MS="$(CONNECT_TIMEOUT_MS)" HOLD_SECONDS="$(HOLD_SECONDS)" REPEATS="$(REPEATS)" \
		CONNS_SOURCE_IPS_CSV="$(CONNS_SOURCE_IPS_CSV)" \
		bash "$(CURDIR)/scripts/connscale-matrix.sh"

http-perf.setup:
	@command -v terraform >/dev/null || { echo "terraform is required" >&2; exit 1; }
	@command -v ssh >/dev/null || { echo "ssh is required" >&2; exit 1; }
	@command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
	@command -v aws >/dev/null || { echo "aws CLI is required" >&2; exit 1; }
	@if [ ! -f "$(KEY_PATH)" ]; then echo "missing SSH key at $(KEY_PATH)" >&2; exit 1; fi
	@TF_DIR="$(TF_DIR)" KEY_PATH="$(KEY_PATH)" SSH_USER="$(SSH_USER)" \
		"$(CURDIR)/scripts/http-perf-setup.sh"

http-perf.run:
	@command -v terraform >/dev/null || { echo "terraform is required" >&2; exit 1; }
	@command -v ssh >/dev/null || { echo "ssh is required" >&2; exit 1; }
	@command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
	@command -v aws >/dev/null || { echo "aws CLI is required" >&2; exit 1; }
	@if [ ! -f "$(KEY_PATH)" ]; then echo "missing SSH key at $(KEY_PATH)" >&2; exit 1; fi
	@TF_DIR="$(TF_DIR)" KEY_PATH="$(KEY_PATH)" SSH_USER="$(SSH_USER)" \
		RAMP_SECONDS="$(RAMP_SECONDS)" \
		STEADY_SECONDS="$(STEADY_SECONDS)" \
		PRE_ALLOCATED_VUS="$(PRE_ALLOCATED_VUS)" \
		MAX_VUS="$(MAX_VUS)" \
		CONTROLPLANE_WORKER_THREADS="$(CONTROLPLANE_WORKER_THREADS)" \
		TLS_INTERCEPT_IO_TIMEOUT_SECS="$(TLS_INTERCEPT_IO_TIMEOUT_SECS)" \
		TLS_INTERCEPT_H2_BODY_TIMEOUT_SECS="$(TLS_INTERCEPT_H2_BODY_TIMEOUT_SECS)" \
		TLS_H2_MAX_CONCURRENT_STREAMS="$(TLS_H2_MAX_CONCURRENT_STREAMS)" \
		TLS_H2_MAX_REQUESTS_PER_CONNECTION="$(TLS_H2_MAX_REQUESTS_PER_CONNECTION)" \
		TLS_H2_POOL_SHARDS="$(TLS_H2_POOL_SHARDS)" \
		TLS_H2_DETAILED_METRICS="$(TLS_H2_DETAILED_METRICS)" \
		TLS_H2_SELECTION_INFLIGHT_WEIGHT="$(TLS_H2_SELECTION_INFLIGHT_WEIGHT)" \
		TLS_INTERCEPT_LISTEN_BACKLOG="$(TLS_INTERCEPT_LISTEN_BACKLOG)" \
		DPDK_WORKERS="$(DPDK_WORKERS)" \
		DPDK_ALLOW_AZURE_MULTIWORKER="$(DPDK_ALLOW_AZURE_MULTIWORKER)" \
		DPDK_SINGLE_QUEUE_MODE="$(DPDK_SINGLE_QUEUE_MODE)" \
		DPDK_FORCE_SHARED_RX_DEMUX="$(DPDK_FORCE_SHARED_RX_DEMUX)" \
		DPDK_HOUSEKEEPING_INTERVAL_PACKETS="$(DPDK_HOUSEKEEPING_INTERVAL_PACKETS)" \
		DPDK_HOUSEKEEPING_INTERVAL_US="$(DPDK_HOUSEKEEPING_INTERVAL_US)" \
		DPDK_PERF_MODE="$(DPDK_PERF_MODE)" \
		DPDK_PIN_HTTPS_OWNER="$(DPDK_PIN_HTTPS_OWNER)" \
		DPDK_SHARED_RX_OWNER_ONLY="$(DPDK_SHARED_RX_OWNER_ONLY)" \
		"$(CURDIR)/scripts/http-perf-matrix.sh"

http-perf.quick:
	@command -v terraform >/dev/null || { echo "terraform is required" >&2; exit 1; }
	@command -v ssh >/dev/null || { echo "ssh is required" >&2; exit 1; }
	@command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
	@command -v aws >/dev/null || { echo "aws CLI is required" >&2; exit 1; }
	@if [ ! -f "$(KEY_PATH)" ]; then echo "missing SSH key at $(KEY_PATH)" >&2; exit 1; fi
	@TF_DIR="$(TF_DIR)" KEY_PATH="$(KEY_PATH)" SSH_USER="$(SSH_USER)" \
		HTTP_PERF_SCENARIOS="$${HTTP_PERF_SCENARIOS:-http_l34_allow}" \
		RPS_TIERS="$${RPS_TIERS:-500}" \
		PAYLOAD_TIERS="$${PAYLOAD_TIERS:-1024}" \
		CONNECTION_MODES="$${CONNECTION_MODES:-keep_alive}" \
		HTTP_REPEATS="$${HTTP_REPEATS:-1}" \
		RAMP_SECONDS="$(RAMP_SECONDS)" \
		STEADY_SECONDS="$(STEADY_SECONDS)" \
		PRE_ALLOCATED_VUS="$(PRE_ALLOCATED_VUS)" \
		MAX_VUS="$(MAX_VUS)" \
		CONTROLPLANE_WORKER_THREADS="$(CONTROLPLANE_WORKER_THREADS)" \
		TLS_INTERCEPT_IO_TIMEOUT_SECS="$(TLS_INTERCEPT_IO_TIMEOUT_SECS)" \
		TLS_INTERCEPT_H2_BODY_TIMEOUT_SECS="$(TLS_INTERCEPT_H2_BODY_TIMEOUT_SECS)" \
		TLS_H2_MAX_CONCURRENT_STREAMS="$(TLS_H2_MAX_CONCURRENT_STREAMS)" \
		TLS_H2_MAX_REQUESTS_PER_CONNECTION="$(TLS_H2_MAX_REQUESTS_PER_CONNECTION)" \
		TLS_H2_POOL_SHARDS="$(TLS_H2_POOL_SHARDS)" \
		TLS_H2_DETAILED_METRICS="$(TLS_H2_DETAILED_METRICS)" \
		TLS_H2_SELECTION_INFLIGHT_WEIGHT="$(TLS_H2_SELECTION_INFLIGHT_WEIGHT)" \
		TLS_INTERCEPT_LISTEN_BACKLOG="$(TLS_INTERCEPT_LISTEN_BACKLOG)" \
		DPDK_WORKERS="$(DPDK_WORKERS)" \
		DPDK_ALLOW_AZURE_MULTIWORKER="$(DPDK_ALLOW_AZURE_MULTIWORKER)" \
		DPDK_SINGLE_QUEUE_MODE="$(DPDK_SINGLE_QUEUE_MODE)" \
		DPDK_FORCE_SHARED_RX_DEMUX="$(DPDK_FORCE_SHARED_RX_DEMUX)" \
		DPDK_HOUSEKEEPING_INTERVAL_PACKETS="$(DPDK_HOUSEKEEPING_INTERVAL_PACKETS)" \
		DPDK_HOUSEKEEPING_INTERVAL_US="$(DPDK_HOUSEKEEPING_INTERVAL_US)" \
		DPDK_PERF_MODE="$(DPDK_PERF_MODE)" \
		DPDK_PIN_HTTPS_OWNER="$(DPDK_PIN_HTTPS_OWNER)" \
		DPDK_SHARED_RX_OWNER_ONLY="$(DPDK_SHARED_RX_OWNER_ONLY)" \
		"$(CURDIR)/scripts/http-perf-matrix.sh"

scaling.report:
	@command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }
	@command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
	@if [ -z "$${THROUGHPUT_RESULT:-}" ] || [ -z "$${HTTP_MATRIX_SUMMARY:-}" ]; then \
		echo "set THROUGHPUT_RESULT and HTTP_MATRIX_SUMMARY" >&2; exit 1; \
	fi
	@OUT_DIR="$${OUT_DIR:-$(CURDIR)/artifacts/scaling-report-$$(date -u +%Y%m%dT%H%M%SZ)}"; \
	"$(CURDIR)/../common/generate-scaling-recommendations.sh" "$${THROUGHPUT_RESULT}" "$${HTTP_MATRIX_SUMMARY}" "$$OUT_DIR"; \
	echo "report dir: $$OUT_DIR"
