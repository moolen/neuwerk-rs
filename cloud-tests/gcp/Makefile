SHELL := /usr/bin/env bash
.SHELLFLAGS := -euo pipefail -c
MAKEFLAGS += --no-print-directory

TF_DIR ?= $(CURDIR)/terraform
KEY_PATH ?= $(CURDIR)/../.secrets/ssh/gcp_e2e
SSH_USER ?= ubuntu
INDEX ?= 0
RESOLVE_FW_IPS ?= $(CURDIR)/scripts/resolve-firewall-mgmt-ips.sh
MINT_API_TOKEN ?= $(CURDIR)/scripts/mint-api-token.sh

.PHONY: ssh.jumpbox ssh.consumer ssh.upstream ssh.firewall health policy-smoke run-tests throughput.matrix http-perf.setup http-perf.run http-perf.quick scaling.report

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

ssh.firewall:
	@command -v terraform >/dev/null || { echo "terraform is required" >&2; exit 1; }
	@command -v ssh >/dev/null || { echo "ssh is required" >&2; exit 1; }
	@command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
	@command -v gcloud >/dev/null || { echo "gcloud is required" >&2; exit 1; }
	@command -v ssh-keygen >/dev/null || { echo "ssh-keygen is required" >&2; exit 1; }
	@if [ ! -f "$(KEY_PATH)" ]; then echo "missing SSH key at $(KEY_PATH)" >&2; exit 1; fi
	@index="$(INDEX)"; \
	if [ -z "$$index" ]; then index=0; fi; \
	jump_ip=$$(cd "$(TF_DIR)" && terraform output -raw jumpbox_public_ip); \
	if [ -z "$$jump_ip" ]; then echo "missing jumpbox_public_ip output" >&2; exit 1; fi; \
	ips=$$(TF_DIR="$(TF_DIR)" "$(RESOLVE_FW_IPS)"); \
	idx=$$(( $$index + 1 )); \
	ip=$$(echo "$$ips" | sort -u | sed -n "$$idx"'p'); \
	if [ -z "$$ip" ]; then echo "missing firewall IP for INDEX=$$index" >&2; exit 1; fi; \
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
	@command -v gcloud >/dev/null || { echo "gcloud is required" >&2; exit 1; }
	@command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
	@command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }
	@command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 1; }
	@command -v cargo >/dev/null || { echo "cargo is required" >&2; exit 1; }
	@if [ ! -f "$(KEY_PATH)" ]; then echo "missing SSH key at $(KEY_PATH)" >&2; exit 1; fi
	@TF_DIR="$(TF_DIR)" KEY_PATH="$(KEY_PATH)" SSH_USER="$(SSH_USER)" LONG_THROUGHPUT="0" \
		"$(CURDIR)/scripts/run-tests.sh"

run-tests:
	@TF_DIR="$(TF_DIR)" KEY_PATH="$(KEY_PATH)" SSH_USER="$(SSH_USER)" \
		"$(CURDIR)/scripts/run-tests.sh"

throughput.matrix:
	@command -v terraform >/dev/null || { echo "terraform is required" >&2; exit 1; }
	@command -v ssh >/dev/null || { echo "ssh is required" >&2; exit 1; }
	@command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
	@command -v gcloud >/dev/null || { echo "gcloud is required" >&2; exit 1; }
	@if [ ! -f "$(KEY_PATH)" ]; then echo "missing SSH key at $(KEY_PATH)" >&2; exit 1; fi
	@TF_DIR="$(TF_DIR)" KEY_PATH="$(KEY_PATH)" SSH_USER="$(SSH_USER)" \
		"$(CURDIR)/scripts/throughput-matrix.sh"

http-perf.setup:
	@command -v terraform >/dev/null || { echo "terraform is required" >&2; exit 1; }
	@command -v ssh >/dev/null || { echo "ssh is required" >&2; exit 1; }
	@command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
	@command -v gcloud >/dev/null || { echo "gcloud is required" >&2; exit 1; }
	@if [ ! -f "$(KEY_PATH)" ]; then echo "missing SSH key at $(KEY_PATH)" >&2; exit 1; fi
	@TF_DIR="$(TF_DIR)" KEY_PATH="$(KEY_PATH)" SSH_USER="$(SSH_USER)" \
		"$(CURDIR)/scripts/http-perf-setup.sh"

http-perf.run:
	@command -v terraform >/dev/null || { echo "terraform is required" >&2; exit 1; }
	@command -v ssh >/dev/null || { echo "ssh is required" >&2; exit 1; }
	@command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
	@command -v gcloud >/dev/null || { echo "gcloud is required" >&2; exit 1; }
	@if [ ! -f "$(KEY_PATH)" ]; then echo "missing SSH key at $(KEY_PATH)" >&2; exit 1; fi
	@TF_DIR="$(TF_DIR)" KEY_PATH="$(KEY_PATH)" SSH_USER="$(SSH_USER)" \
		"$(CURDIR)/scripts/http-perf-matrix.sh"

http-perf.quick:
	@command -v terraform >/dev/null || { echo "terraform is required" >&2; exit 1; }
	@command -v ssh >/dev/null || { echo "ssh is required" >&2; exit 1; }
	@command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
	@command -v gcloud >/dev/null || { echo "gcloud is required" >&2; exit 1; }
	@if [ ! -f "$(KEY_PATH)" ]; then echo "missing SSH key at $(KEY_PATH)" >&2; exit 1; fi
	@TF_DIR="$(TF_DIR)" KEY_PATH="$(KEY_PATH)" SSH_USER="$(SSH_USER)" \
		HTTP_PERF_SCENARIOS="$${HTTP_PERF_SCENARIOS:-http_l34_allow}" \
		RPS_TIERS="$${RPS_TIERS:-500}" \
		PAYLOAD_TIERS="$${PAYLOAD_TIERS:-1024}" \
		CONNECTION_MODES="$${CONNECTION_MODES:-keep_alive}" \
		HTTP_REPEATS="$${HTTP_REPEATS:-1}" \
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
