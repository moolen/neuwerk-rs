SHELL := /usr/bin/env bash
.SHELLFLAGS := -euo pipefail -c
MAKEFLAGS += --no-print-directory

TF_DIR ?= $(CURDIR)/terraform
KEY_PATH ?= $(CURDIR)/../.secrets/ssh/azure_e2e
SSH_USER ?= ubuntu
INDEX ?= 0
UI_LOCAL_PORT ?= 9443
RESOLVE_FW_IPS ?= $(CURDIR)/scripts/resolve-neuwerk-mgmt-ips.sh
MINT_API_TOKEN ?= $(CURDIR)/scripts/mint-api-token.sh
NEUWERK_BINARY_PATH ?=

.PHONY: ssh.jumpbox ssh.consumer ssh.upstream ssh.neuwerk ui.port-forward health policy-smoke performance.scenario lifecycle-rollout lifecycle-termination-drain http-perf.setup http-perf.run http-perf.quick throughput.matrix pps.matrix cps.matrix cps.instance-matrix cps.instance-matrix.netopt-path shape.netopt-path.apply connscale.matrix scaling.benchmark scaling.report

ssh.jumpbox:
	@command -v terraform >/dev/null || { echo "terraform is required" >&2; exit 1; }
	@command -v ssh >/dev/null || { echo "ssh is required" >&2; exit 1; }
	@command -v ssh-keygen >/dev/null || { echo "ssh-keygen is required" >&2; exit 1; }
	@if [ ! -f "$(KEY_PATH)" ]; then echo "missing SSH key at $(KEY_PATH)" >&2; exit 1; fi
	@jump_ip=$$(cd "$(TF_DIR)" && terraform output -raw jumpbox_public_ip); \
	if [ -z "$$jump_ip" ]; then echo "missing jumpbox_public_ip output" >&2; exit 1; fi; \
	ssh-keygen -R "$$jump_ip" >/dev/null 2>&1 || true; \
	exec ssh -o StrictHostKeyChecking=accept-new -i "$(KEY_PATH)" "$(SSH_USER)@$$jump_ip"

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
	index="$(INDEX)"; \
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
	@command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
	@command -v az >/dev/null || { echo "az is required" >&2; exit 1; }
	@command -v ssh-keygen >/dev/null || { echo "ssh-keygen is required" >&2; exit 1; }
	@if [ ! -f "$(KEY_PATH)" ]; then echo "missing SSH key at $(KEY_PATH)" >&2; exit 1; fi
	index="$(INDEX)"; \
	if [ -z "$$index" ]; then index=0; fi; \
	az account show >/dev/null 2>&1 || { echo "az login required" >&2; exit 1; }; \
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

ui.port-forward:
	@command -v terraform >/dev/null || { echo "terraform is required" >&2; exit 1; }
	@command -v ssh >/dev/null || { echo "ssh is required" >&2; exit 1; }
	@command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
	@command -v az >/dev/null || { echo "az is required" >&2; exit 1; }
	@command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }
	@command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 1; }
	@if [ ! -f "$(KEY_PATH)" ]; then echo "missing SSH key at $(KEY_PATH)" >&2; exit 1; fi
	@if [ ! -x "$(MINT_API_TOKEN)" ]; then echo "missing executable token script: $(MINT_API_TOKEN)" >&2; exit 1; fi
	@index="$(INDEX)"; \
	if [ -z "$$index" ]; then index=0; fi; \
	local_port="$(UI_LOCAL_PORT)"; \
	az account show >/dev/null 2>&1 || { echo "az login required" >&2; exit 1; }; \
	jump_ip=$$(cd "$(TF_DIR)" && terraform output -raw jumpbox_public_ip); \
	if [ -z "$$jump_ip" ]; then echo "missing jumpbox_public_ip output" >&2; exit 1; fi; \
	ips=$$(TF_DIR="$(TF_DIR)" "$(RESOLVE_FW_IPS)"); \
	idx=$$(( $$index + 1 )); \
	ip=$$(echo "$$ips" | sort -u | sed -n "$$idx"'p'); \
	if [ -z "$$ip" ]; then echo "missing neuwerk IP for INDEX=$$index" >&2; exit 1; fi; \
	token=$$($(MINT_API_TOKEN) "$$jump_ip" "$(KEY_PATH)" "$$ip" "azure-ui"); \
	echo "UI: https://127.0.0.1:$$local_port"; \
	echo "JWT: $$token"; \
	echo "UI available on https://127.0.0.1:$$local_port"; \
	exec ssh -N -L "$$local_port:$$ip:8443" \
		-o LogLevel=ERROR -o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes -i "$(KEY_PATH)" \
		-o ProxyCommand="ssh -o LogLevel=ERROR -o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes -i $(KEY_PATH) -W %h:%p $(SSH_USER)@$$jump_ip" \
		"$(SSH_USER)@$$ip"

health:
	@command -v terraform >/dev/null || { echo "terraform is required" >&2; exit 1; }
	@command -v ssh >/dev/null || { echo "ssh is required" >&2; exit 1; }
	@command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
	@command -v az >/dev/null || { echo "az is required" >&2; exit 1; }
	@command -v ssh-keygen >/dev/null || { echo "ssh-keygen is required" >&2; exit 1; }
	@if [ ! -f "$(KEY_PATH)" ]; then echo "missing SSH key at $(KEY_PATH)" >&2; exit 1; fi
	az account show >/dev/null 2>&1 || { echo "az login required" >&2; exit 1; }; \
	jump_ip=$$(cd "$(TF_DIR)" && terraform output -raw jumpbox_public_ip); \
	if [ -z "$$jump_ip" ]; then echo "missing jumpbox_public_ip output" >&2; exit 1; fi; \
	ssh-keygen -R "$$jump_ip" >/dev/null 2>&1 || true; \
	ips=$$(TF_DIR="$(TF_DIR)" "$(RESOLVE_FW_IPS)"); \
	for ip in $$ips; do \
		echo "checking $$ip"; \
		ssh-keygen -R "$$ip" >/dev/null 2>&1 || true; \
		if ! ssh -o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes -i "$(KEY_PATH)" "$(SSH_USER)@$$jump_ip" \
			"curl -skf https://$$ip:8443/health >/dev/null"; then \
			echo "health check failed for $$ip" >&2; exit 1; \
		fi; \
		if ! ssh -o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes -i "$(KEY_PATH)" "$(SSH_USER)@$$jump_ip" \
			"curl -skf https://$$ip:8443/ready >/dev/null"; then \
			echo "ready check failed for $$ip" >&2; exit 1; \
		fi; \
		echo "ok: $$ip"; \
	done

policy-smoke:
	@command -v terraform >/dev/null || { echo "terraform is required" >&2; exit 1; }
	@command -v ssh >/dev/null || { echo "ssh is required" >&2; exit 1; }
	@command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
	@command -v az >/dev/null || { echo "az is required" >&2; exit 1; }
	@command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }
	@command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 1; }
	@command -v cargo >/dev/null || { echo "cargo is required" >&2; exit 1; }
	@if [ ! -f "$(KEY_PATH)" ]; then echo "missing SSH key at $(KEY_PATH)" >&2; exit 1; fi
	az account show >/dev/null 2>&1 || { echo "az login required" >&2; exit 1; }; \
	jump_ip=$$(cd "$(TF_DIR)" && terraform output -raw jumpbox_public_ip); \
	upstream_vip=$$(cd "$(TF_DIR)" && terraform output -raw upstream_vip); \
	upstream_ip=$$(cd "$(TF_DIR)" && terraform output -raw upstream_private_ip); \
	consumer_ip=$$(cd "$(TF_DIR)" && terraform output -json consumer_private_ips | jq -r '.[0]'); \
	if [ -z "$$jump_ip" ] || [ -z "$$upstream_vip" ] || [ -z "$$upstream_ip" ] || [ -z "$$consumer_ip" ] || [ "$$consumer_ip" = "null" ]; then \
		echo "missing terraform outputs for policy smoke" >&2; exit 1; \
	fi; \
	fw_mgmt_ips=$$(TF_DIR="$(TF_DIR)" "$(RESOLVE_FW_IPS)" | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g' | sed 's/^ //; s/ $$//'); \
	fw_mgmt_ip=$$(echo "$$fw_mgmt_ips" | awk '{print $$1}'); \
	if [ -z "$$fw_mgmt_ip" ]; then echo "missing neuwerk mgmt ip" >&2; exit 1; fi; \
	dns_server="$$fw_mgmt_ip"; \
	JUMPBOX_IP=$$jump_ip CONSUMER_IP=$$consumer_ip FW_MGMT_IP=$$fw_mgmt_ip FW_MGMT_IPS="$$fw_mgmt_ips" UPSTREAM_VIP=$$upstream_vip UPSTREAM_IP=$$upstream_ip DNS_SERVER=$$dns_server \
	DNS_ZONE=$${DNS_ZONE:-upstream.test} KEY_PATH="$(KEY_PATH)" SSH_USER="$(SSH_USER)" \
	"$(CURDIR)/../common/run-policy-smoke.sh"

performance.scenario:
	@command -v terraform >/dev/null || { echo "terraform is required" >&2; exit 1; }
	@command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
	@command -v az >/dev/null || { echo "az is required" >&2; exit 1; }
	@if [ ! -f "$(KEY_PATH)" ]; then echo "missing SSH key at $(KEY_PATH)" >&2; exit 1; fi
	@TF_DIR="$(TF_DIR)" KEY_PATH="$(KEY_PATH)" SSH_USER="$(SSH_USER)" \
		PERF_THROUGHPUT_MODE="$${PERF_THROUGHPUT_MODE:-imix_pps}" \
		PERF_PATHS="$(PERF_PATHS)" \
		PERF_ENABLE_THROUGHPUT="$(PERF_ENABLE_THROUGHPUT)" \
		PERF_ENABLE_CPS="$(PERF_ENABLE_CPS)" \
		PERF_ENABLE_NAT="$(PERF_ENABLE_NAT)" \
		PERF_ENABLE_TLS_DPI="$(PERF_ENABLE_TLS_DPI)" \
		PERF_CPS_WORKERS_LIST="$${PERF_CPS_WORKERS_LIST:-2,8,16,32}" \
		PERF_HTTP_SCENARIOS="$(PERF_HTTP_SCENARIOS)" \
		PERF_ARTIFACT_DIR="$(PERF_ARTIFACT_DIR)" \
		WORKERS_LIST="$${WORKERS_LIST:-2,8,16,32}" \
		PPS_PROFILES="$${PPS_PROFILES:-64:18,570:542,1500:1472}" \
		IMIX_WEIGHTS="$${IMIX_WEIGHTS:-64:58,570:33,1500:9}" \
		STREAMS_LIST="$${STREAMS_LIST:-8}" \
		RUN_SECONDS="$${RUN_SECONDS:-10}" \
		WARMUP_SECONDS="$${WARMUP_SECONDS:-3}" \
		REPEATS="$${REPEATS:-1}" \
		CONNECTION_TIERS="$${CONNECTION_TIERS:-2000,10000,20000}" \
		HOLD_SECONDS="$${HOLD_SECONDS:-10}" \
		HTTP_PERF_SCENARIOS="$(HTTP_PERF_SCENARIOS)" \
		RPS_TIERS="$${RPS_TIERS:-1500}" \
		PAYLOAD_TIERS="$${PAYLOAD_TIERS:-1024}" \
		CONNECTION_MODES="$${CONNECTION_MODES:-keep_alive,new_connection_heavy}" \
		HTTP_REPEATS="$${HTTP_REPEATS:-1}" \
		RAMP_SECONDS="$${RAMP_SECONDS:-5}" \
		STEADY_SECONDS="$${STEADY_SECONDS:-10}" \
		NEUWERK_THREAD_CPU_MONITOR="$${NEUWERK_THREAD_CPU_MONITOR:-0}" \
		COLLECT_NEUWERK_METRICS="$${COLLECT_NEUWERK_METRICS:-0}" \
		COLLECT_CONSUMER_SOCKET_DIAG="$${COLLECT_CONSUMER_SOCKET_DIAG:-0}" \
		bash "$(CURDIR)/scripts/performance-scenario.sh"

lifecycle-rollout:
	@command -v terraform >/dev/null || { echo "terraform is required" >&2; exit 1; }
	@command -v ssh >/dev/null || { echo "ssh is required" >&2; exit 1; }
	@command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
	@command -v az >/dev/null || { echo "az is required" >&2; exit 1; }
	@if [ ! -f "$(KEY_PATH)" ]; then echo "missing SSH key at $(KEY_PATH)" >&2; exit 1; fi
	@TF_DIR="$(TF_DIR)" KEY_PATH="$(KEY_PATH)" SSH_USER="$(SSH_USER)" \
		"$(CURDIR)/scripts/lifecycle-rollout.sh"

lifecycle-termination-drain:
	@command -v terraform >/dev/null || { echo "terraform is required" >&2; exit 1; }
	@command -v ssh >/dev/null || { echo "ssh is required" >&2; exit 1; }
	@command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
	@command -v az >/dev/null || { echo "az is required" >&2; exit 1; }
	@if [ ! -f "$(KEY_PATH)" ]; then echo "missing SSH key at $(KEY_PATH)" >&2; exit 1; fi
	@TF_DIR="$(TF_DIR)" KEY_PATH="$(KEY_PATH)" SSH_USER="$(SSH_USER)" \
		"$(CURDIR)/scripts/lifecycle-termination-drain.sh"

http-perf.setup:
	@command -v terraform >/dev/null || { echo "terraform is required" >&2; exit 1; }
	@command -v ssh >/dev/null || { echo "ssh is required" >&2; exit 1; }
	@command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
	@command -v az >/dev/null || { echo "az is required" >&2; exit 1; }
	@if [ ! -f "$(KEY_PATH)" ]; then echo "missing SSH key at $(KEY_PATH)" >&2; exit 1; fi
	@TF_DIR="$(TF_DIR)" KEY_PATH="$(KEY_PATH)" SSH_USER="$(SSH_USER)" \
		"$(CURDIR)/scripts/http-perf-setup.sh"

http-perf.run:
	@command -v terraform >/dev/null || { echo "terraform is required" >&2; exit 1; }
	@command -v ssh >/dev/null || { echo "ssh is required" >&2; exit 1; }
	@command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
	@command -v az >/dev/null || { echo "az is required" >&2; exit 1; }
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
		DPDK_ALLOW_RETALESS_MULTI_QUEUE="$(DPDK_ALLOW_RETALESS_MULTI_QUEUE)" \
		DPDK_SINGLE_QUEUE_MODE="$(DPDK_SINGLE_QUEUE_MODE)" \
		DPDK_FORCE_SHARED_RX_DEMUX="$(DPDK_FORCE_SHARED_RX_DEMUX)" \
		DPDK_HOUSEKEEPING_INTERVAL_PACKETS="$(DPDK_HOUSEKEEPING_INTERVAL_PACKETS)" \
		DPDK_HOUSEKEEPING_INTERVAL_US="$(DPDK_HOUSEKEEPING_INTERVAL_US)" \
		DPDK_PERF_MODE="$(DPDK_PERF_MODE)" \
		DPDK_DISABLE_SERVICE_LANE="$(DPDK_DISABLE_SERVICE_LANE)" \
		DPDK_PIN_HTTPS_OWNER="$(DPDK_PIN_HTTPS_OWNER)" \
		DPDK_SHARED_RX_OWNER_ONLY="$(DPDK_SHARED_RX_OWNER_ONLY)" \
		"$(CURDIR)/scripts/http-perf-matrix.sh"

http-perf.quick:
	@command -v terraform >/dev/null || { echo "terraform is required" >&2; exit 1; }
	@command -v ssh >/dev/null || { echo "ssh is required" >&2; exit 1; }
	@command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
	@command -v az >/dev/null || { echo "az is required" >&2; exit 1; }
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

throughput.matrix:
	@command -v terraform >/dev/null || { echo "terraform is required" >&2; exit 1; }
	@command -v ssh >/dev/null || { echo "ssh is required" >&2; exit 1; }
	@command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
	@command -v az >/dev/null || { echo "az is required" >&2; exit 1; }
	@if [ ! -f "$(KEY_PATH)" ]; then echo "missing SSH key at $(KEY_PATH)" >&2; exit 1; fi
	@TF_DIR="$(TF_DIR)" KEY_PATH="$(KEY_PATH)" SSH_USER="$(SSH_USER)" \
		"$(CURDIR)/scripts/throughput-matrix.sh"

pps.matrix:
	@command -v terraform >/dev/null || { echo "terraform is required" >&2; exit 1; }
	@command -v ssh >/dev/null || { echo "ssh is required" >&2; exit 1; }
	@command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
	@command -v az >/dev/null || { echo "az is required" >&2; exit 1; }
	@if [ ! -f "$(KEY_PATH)" ]; then echo "missing SSH key at $(KEY_PATH)" >&2; exit 1; fi
	@TF_DIR="$(TF_DIR)" KEY_PATH="$(KEY_PATH)" SSH_USER="$(SSH_USER)" \
		FW_VCPU="$(FW_VCPU)" \
		PPS_PROFILES="$(PPS_PROFILES)" \
		STREAMS_LIST="$(STREAMS_LIST)" \
		RUN_SECONDS="$(RUN_SECONDS)" \
		WARMUP_SECONDS="$(WARMUP_SECONDS)" \
		REPEATS="$(REPEATS)" \
		UDP_TARGET_BPS="$(UDP_TARGET_BPS)" \
		UDP_LOSS_INVALID_PCT="$(UDP_LOSS_INVALID_PCT)" \
		IMIX_WEIGHTS="$(IMIX_WEIGHTS)" \
		"$(CURDIR)/scripts/pps-matrix.sh"

cps.matrix:
	@command -v terraform >/dev/null || { echo "terraform is required" >&2; exit 1; }
	@command -v ssh >/dev/null || { echo "ssh is required" >&2; exit 1; }
	@command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
	@command -v az >/dev/null || { echo "az is required" >&2; exit 1; }
	@if [ ! -f "$(KEY_PATH)" ]; then echo "missing SSH key at $(KEY_PATH)" >&2; exit 1; fi
	@TF_DIR="$(TF_DIR)" KEY_PATH="$(KEY_PATH)" SSH_USER="$(SSH_USER)" \
		FW_VCPU="$(FW_VCPU)" \
		TARGET_HOST="$(TARGET_HOST)" \
		TARGET_HOSTS="$(TARGET_HOSTS)" \
		TARGET_PORT="$(TARGET_PORT)" \
		TARGET_PORTS="$(TARGET_PORTS)" \
		WORKERS_LIST="$(WORKERS_LIST)" \
		RUN_SECONDS="$(RUN_SECONDS)" \
		WARMUP_SECONDS="$(WARMUP_SECONDS)" \
		REPEATS="$(REPEATS)" \
		CONNECT_TIMEOUT_MS="$(CONNECT_TIMEOUT_MS)" \
		MIN_SUCCESS_RATIO="$(MIN_SUCCESS_RATIO)" \
		CPS_CLIENT_MODE="$(CPS_CLIENT_MODE)" \
		CPS_CLIENT_PROCESSES="$(CPS_CLIENT_PROCESSES)" \
		CPS_CLOSE_MODE="$(CPS_CLOSE_MODE)" \
		CPS_CLIENT_BACKEND="$(CPS_CLIENT_BACKEND)" \
		CPS_RUST_TCP_DRIVER_MANIFEST_PATH="$(CPS_RUST_TCP_DRIVER_MANIFEST_PATH)" \
		CPS_RUST_TCP_CPS_PER_WORKER="$(CPS_RUST_TCP_CPS_PER_WORKER)" \
		CPS_RUST_TCP_MAX_CPS="$(CPS_RUST_TCP_MAX_CPS)" \
		CPS_RUST_TCP_WAIT_FOR_PEER_CLOSE="$(CPS_RUST_TCP_WAIT_FOR_PEER_CLOSE)" \
		CPS_RUST_TCP_RAMP_UP_SECONDS="$(CPS_RUST_TCP_RAMP_UP_SECONDS)" \
		CPS_RUST_TCP_REQUEST_MODE="$(CPS_RUST_TCP_REQUEST_MODE)" \
		CPS_RUST_TCP_HTTP_HOST_HEADER="$(CPS_RUST_TCP_HTTP_HOST_HEADER)" \
		CPS_RUST_TCP_HTTP_PATH="$(CPS_RUST_TCP_HTTP_PATH)" \
		CPS_RUST_TCP_RESPONSE_TIMEOUT_SECONDS="$(CPS_RUST_TCP_RESPONSE_TIMEOUT_SECONDS)" \
		CPS_SOURCE_IPS_MAX="$(CPS_SOURCE_IPS_MAX)" \
		CPS_SOURCE_IPS_CSV_OVERRIDE="$(CPS_SOURCE_IPS_CSV_OVERRIDE)" \
		CPS_MIN_SOURCE_IP_COUNT_WARN="$(CPS_MIN_SOURCE_IP_COUNT_WARN)" \
		CPS_APPLY_BENCHMARK_SYSCTLS="$(CPS_APPLY_BENCHMARK_SYSCTLS)" \
		CPS_IP_LOCAL_PORT_RANGE="$(CPS_IP_LOCAL_PORT_RANGE)" \
		CPS_TCP_TW_REUSE="$(CPS_TCP_TW_REUSE)" \
		CPS_TCP_FIN_TIMEOUT="$(CPS_TCP_FIN_TIMEOUT)" \
		CPS_TCP_MAX_TW_BUCKETS="$(CPS_TCP_MAX_TW_BUCKETS)" \
		CPS_TUNE_UPSTREAM_LISTEN="$(CPS_TUNE_UPSTREAM_LISTEN)" \
		CPS_UPSTREAM_SOMAXCONN="$(CPS_UPSTREAM_SOMAXCONN)" \
		CPS_UPSTREAM_TCP_MAX_SYN_BACKLOG="$(CPS_UPSTREAM_TCP_MAX_SYN_BACKLOG)" \
		CPS_VALIDATE_SOURCE_ROUTE="$(CPS_VALIDATE_SOURCE_ROUTE)" \
		CPS_AUTO_FIX_SOURCE_ROUTE="$(CPS_AUTO_FIX_SOURCE_ROUTE)" \
		CPS_SOURCE_ROUTE_TABLE_ID="$(CPS_SOURCE_ROUTE_TABLE_ID)" \
		DPDK_WORKERS="$(DPDK_WORKERS)" \
		DPDK_ALLOW_AZURE_MULTIWORKER="$(DPDK_ALLOW_AZURE_MULTIWORKER)" \
		DPDK_SINGLE_QUEUE_MODE="$(DPDK_SINGLE_QUEUE_MODE)" \
		DPDK_FORCE_SHARED_RX_DEMUX="$(DPDK_FORCE_SHARED_RX_DEMUX)" \
		DPDK_HOUSEKEEPING_INTERVAL_PACKETS="$(DPDK_HOUSEKEEPING_INTERVAL_PACKETS)" \
		DPDK_HOUSEKEEPING_INTERVAL_US="$(DPDK_HOUSEKEEPING_INTERVAL_US)" \
		DPDK_PERF_MODE="$(DPDK_PERF_MODE)" \
		DPDK_PIN_HTTPS_OWNER="$(DPDK_PIN_HTTPS_OWNER)" \
		DPDK_PIN_STATE_SHARD_GUARD="$(DPDK_PIN_STATE_SHARD_GUARD)" \
		DPDK_PIN_STATE_SHARD_BURST="$(DPDK_PIN_STATE_SHARD_BURST)" \
		DPDK_SHARED_RX_OWNER_ONLY="$(DPDK_SHARED_RX_OWNER_ONLY)" \
		DPDK_LOCKLESS_QPW="$(DPDK_LOCKLESS_QPW)" \
		DPDK_RX_RING_SIZE="$(DPDK_RX_RING_SIZE)" \
		DPDK_TX_RING_SIZE="$(DPDK_TX_RING_SIZE)" \
		DPDK_MBUF_POOL_SIZE="$(DPDK_MBUF_POOL_SIZE)" \
		DPDK_SYN_ONLY_TABLE="$(DPDK_SYN_ONLY_TABLE)" \
		NEUWERK_FLOW_TABLE_CAPACITY="$(NEUWERK_FLOW_TABLE_CAPACITY)" \
		"$(CURDIR)/scripts/cps-matrix.sh"

cps.instance-matrix:
	@command -v terraform >/dev/null || { echo "terraform is required" >&2; exit 1; }
	@command -v ssh >/dev/null || { echo "ssh is required" >&2; exit 1; }
	@command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
	@command -v az >/dev/null || { echo "az is required" >&2; exit 1; }
	@if [ ! -f "$(KEY_PATH)" ]; then echo "missing SSH key at $(KEY_PATH)" >&2; exit 1; fi
	@TF_DIR="$(TF_DIR)" KEY_PATH="$(KEY_PATH)" SSH_USER="$(SSH_USER)" \
		ARTIFACT_DIR="$(ARTIFACT_DIR)" \
		INSTANCE_MATRIX="$(INSTANCE_MATRIX)" \
		INSTANCE_MATRIX_MODE="$(INSTANCE_MATRIX_MODE)" \
		APPLY_ONLY="$(APPLY_ONLY)" \
		SKIP_TERRAFORM_APPLY="$(SKIP_TERRAFORM_APPLY)" \
		CONTINUE_ON_CASE_ERROR="$(CONTINUE_ON_CASE_ERROR)" \
		FORCE_VMSS_INSTANCE_ROLLOUT="$(FORCE_VMSS_INSTANCE_ROLLOUT)" \
		VMSS_ROLLOUT_WAIT_SECONDS="$(VMSS_ROLLOUT_WAIT_SECONDS)" \
		FW_IP_DISCOVERY_RETRIES="$(FW_IP_DISCOVERY_RETRIES)" \
		FW_IP_DISCOVERY_SLEEP_SECONDS="$(FW_IP_DISCOVERY_SLEEP_SECONDS)" \
		NEUWERK_INSTANCE_COUNT="$(NEUWERK_INSTANCE_COUNT)" \
		CONSUMER_COUNT="$(CONSUMER_COUNT)" \
		CONSUMER_SECONDARY_PRIVATE_IP_COUNT="$(CONSUMER_SECONDARY_PRIVATE_IP_COUNT)" \
		NEUWERK_DPDK_WORKERS="$(NEUWERK_DPDK_WORKERS)" \
		NEUWERK_BINARY_PATH="$(NEUWERK_BINARY_PATH)" \
		TF_VAR_neuwerk_image_id="$(TF_VAR_neuwerk_image_id)" \
		FW_VCPU="$(FW_VCPU)" \
		TARGET_PORT="$(TARGET_PORT)" \
		TARGET_PORTS="$(TARGET_PORTS)" \
		WORKERS_LIST="$(WORKERS_LIST)" \
		RUN_SECONDS="$(RUN_SECONDS)" \
		WARMUP_SECONDS="$(WARMUP_SECONDS)" \
		REPEATS="$(REPEATS)" \
		CONNECT_TIMEOUT_MS="$(CONNECT_TIMEOUT_MS)" \
		MIN_SUCCESS_RATIO="$(MIN_SUCCESS_RATIO)" \
		CPS_CLIENT_MODE="$(CPS_CLIENT_MODE)" \
		CPS_CLIENT_PROCESSES="$(CPS_CLIENT_PROCESSES)" \
		CPS_CLOSE_MODE="$(CPS_CLOSE_MODE)" \
		CPS_CLIENT_BACKEND="$(CPS_CLIENT_BACKEND)" \
		CPS_RUST_TCP_DRIVER_MANIFEST_PATH="$(CPS_RUST_TCP_DRIVER_MANIFEST_PATH)" \
		CPS_RUST_TCP_CPS_PER_WORKER="$(CPS_RUST_TCP_CPS_PER_WORKER)" \
		CPS_RUST_TCP_MAX_CPS="$(CPS_RUST_TCP_MAX_CPS)" \
		CPS_RUST_TCP_WAIT_FOR_PEER_CLOSE="$(CPS_RUST_TCP_WAIT_FOR_PEER_CLOSE)" \
		CPS_RUST_TCP_SHARD_COUNT="$(CPS_RUST_TCP_SHARD_COUNT)" \
		CPS_RUST_TCP_MAX_INFLIGHT_MULTIPLIER="$(CPS_RUST_TCP_MAX_INFLIGHT_MULTIPLIER)" \
		CPS_RUST_TCP_RAMP_UP_SECONDS="$(CPS_RUST_TCP_RAMP_UP_SECONDS)" \
		CPS_RUST_TCP_REQUEST_MODE="$(CPS_RUST_TCP_REQUEST_MODE)" \
		CPS_RUST_TCP_HTTP_HOST_HEADER="$(CPS_RUST_TCP_HTTP_HOST_HEADER)" \
		CPS_RUST_TCP_HTTP_PATH="$(CPS_RUST_TCP_HTTP_PATH)" \
		CPS_RUST_TCP_RESPONSE_TIMEOUT_SECONDS="$(CPS_RUST_TCP_RESPONSE_TIMEOUT_SECONDS)" \
		CPS_SOURCE_IPS_MAX="$(CPS_SOURCE_IPS_MAX)" \
		CPS_SOURCE_IPS_CSV_OVERRIDE="$(CPS_SOURCE_IPS_CSV_OVERRIDE)" \
		CPS_MIN_SOURCE_IP_COUNT_WARN="$(CPS_MIN_SOURCE_IP_COUNT_WARN)" \
		CPS_APPLY_BENCHMARK_SYSCTLS="$(CPS_APPLY_BENCHMARK_SYSCTLS)" \
		CPS_IP_LOCAL_PORT_RANGE="$(CPS_IP_LOCAL_PORT_RANGE)" \
		CPS_TCP_TW_REUSE="$(CPS_TCP_TW_REUSE)" \
		CPS_TCP_FIN_TIMEOUT="$(CPS_TCP_FIN_TIMEOUT)" \
		CPS_TCP_MAX_TW_BUCKETS="$(CPS_TCP_MAX_TW_BUCKETS)" \
		CPS_TUNE_UPSTREAM_LISTEN="$(CPS_TUNE_UPSTREAM_LISTEN)" \
		CPS_UPSTREAM_SOMAXCONN="$(CPS_UPSTREAM_SOMAXCONN)" \
		CPS_UPSTREAM_TCP_MAX_SYN_BACKLOG="$(CPS_UPSTREAM_TCP_MAX_SYN_BACKLOG)" \
		CPS_VALIDATE_SOURCE_ROUTE="$(CPS_VALIDATE_SOURCE_ROUTE)" \
		CPS_AUTO_FIX_SOURCE_ROUTE="$(CPS_AUTO_FIX_SOURCE_ROUTE)" \
		CPS_SOURCE_ROUTE_TABLE_ID="$(CPS_SOURCE_ROUTE_TABLE_ID)" \
		DPDK_WORKERS="$(DPDK_WORKERS)" \
		DPDK_ALLOW_AZURE_MULTIWORKER="$(DPDK_ALLOW_AZURE_MULTIWORKER)" \
		DPDK_ALLOW_RETALESS_MULTI_QUEUE="$(DPDK_ALLOW_RETALESS_MULTI_QUEUE)" \
		DPDK_SINGLE_QUEUE_MODE="$(DPDK_SINGLE_QUEUE_MODE)" \
		DPDK_FORCE_SHARED_RX_DEMUX="$(DPDK_FORCE_SHARED_RX_DEMUX)" \
		DPDK_HOUSEKEEPING_INTERVAL_PACKETS="$(DPDK_HOUSEKEEPING_INTERVAL_PACKETS)" \
		DPDK_HOUSEKEEPING_INTERVAL_US="$(DPDK_HOUSEKEEPING_INTERVAL_US)" \
		DPDK_PERF_MODE="$(DPDK_PERF_MODE)" \
		DPDK_PIN_HTTPS_OWNER="$(DPDK_PIN_HTTPS_OWNER)" \
		DPDK_PIN_STATE_SHARD_GUARD="$(DPDK_PIN_STATE_SHARD_GUARD)" \
		DPDK_PIN_STATE_SHARD_BURST="$(DPDK_PIN_STATE_SHARD_BURST)" \
		DPDK_SHARED_RX_OWNER_ONLY="$(DPDK_SHARED_RX_OWNER_ONLY)" \
		DPDK_LOCKLESS_QPW="$(DPDK_LOCKLESS_QPW)" \
		DPDK_RX_RING_SIZE="$(DPDK_RX_RING_SIZE)" \
		DPDK_TX_RING_SIZE="$(DPDK_TX_RING_SIZE)" \
		DPDK_MBUF_POOL_SIZE="$(DPDK_MBUF_POOL_SIZE)" \
		DPDK_SYN_ONLY_TABLE="$(DPDK_SYN_ONLY_TABLE)" \
		"$(CURDIR)/scripts/cps-instance-matrix.sh"

cps.instance-matrix.netopt-path:
	@$(MAKE) cps.instance-matrix \
		INSTANCE_MATRIX_MODE=path_v6_netopt \
		APPLY_ONLY=0

shape.netopt-path.apply:
	@$(MAKE) cps.instance-matrix \
		INSTANCE_MATRIX_MODE=path_v6_netopt_only \
		APPLY_ONLY=1

connscale.matrix:
	@command -v terraform >/dev/null || { echo "terraform is required" >&2; exit 1; }
	@command -v ssh >/dev/null || { echo "ssh is required" >&2; exit 1; }
	@command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
	@command -v az >/dev/null || { echo "az is required" >&2; exit 1; }
	@if [ ! -f "$(KEY_PATH)" ]; then echo "missing SSH key at $(KEY_PATH)" >&2; exit 1; fi
	@TF_DIR="$(TF_DIR)" KEY_PATH="$(KEY_PATH)" SSH_USER="$(SSH_USER)" \
		TARGET_PORT="$(TARGET_PORT)" \
		CONNECTION_TIERS="$(CONNECTION_TIERS)" \
		OPEN_WORKERS="$(OPEN_WORKERS)" \
		CONNECT_TIMEOUT_MS="$(CONNECT_TIMEOUT_MS)" \
		HOLD_SECONDS="$(HOLD_SECONDS)" \
		REPEATS="$(REPEATS)" \
		MIN_OPEN_RATIO="$(MIN_OPEN_RATIO)" \
		"$(CURDIR)/scripts/connscale-matrix.sh"

scaling.benchmark:
	@command -v terraform >/dev/null || { echo "terraform is required" >&2; exit 1; }
	@command -v az >/dev/null || { echo "az is required" >&2; exit 1; }
	@command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
	@if [ ! -f "$(KEY_PATH)" ]; then echo "missing SSH key at $(KEY_PATH)" >&2; exit 1; fi
	@TF_DIR="$(TF_DIR)" KEY_PATH="$(KEY_PATH)" SSH_USER="$(SSH_USER)" \
		NEUWERK_BINARY_PATH="$(NEUWERK_BINARY_PATH)" \
		"$(CURDIR)/scripts/scaling-benchmark.sh"

scaling.report:
	@command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }
	@command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
	@if [ -z "$${THROUGHPUT_RESULT:-}" ] || [ -z "$${HTTP_MATRIX_SUMMARY:-}" ]; then \
		echo "set THROUGHPUT_RESULT and HTTP_MATRIX_SUMMARY" >&2; exit 1; \
	fi
	@OUT_DIR="$${OUT_DIR:-$(CURDIR)/artifacts/scaling-report-$$(date -u +%Y%m%dT%H%M%SZ)}"; \
	"$(CURDIR)/../common/generate-scaling-recommendations.sh" "$${THROUGHPUT_RESULT}" "$${HTTP_MATRIX_SUMMARY}" "$$OUT_DIR"; \
	echo "report dir: $$OUT_DIR"
