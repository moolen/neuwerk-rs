SHELL := /usr/bin/env bash
.SHELLFLAGS := -euo pipefail -c
MAKEFLAGS += --no-print-directory

TF_DIR ?= $(CURDIR)/terraform
KEY_PATH ?= $(CURDIR)/../.secrets/ssh/azure_e2e
SSH_USER ?= ubuntu
INDEX ?= 0
UI_LOCAL_PORT ?= 9443
RESOLVE_FW_IPS ?= $(CURDIR)/scripts/resolve-firewall-mgmt-ips.sh
MINT_API_TOKEN ?= $(CURDIR)/scripts/mint-api-token.sh

.PHONY: ssh.jumpbox ssh.consumer ssh.upstream ssh.firewall ui.port-forward health policy-smoke lifecycle-rollout lifecycle-termination-drain http-perf.setup http-perf.run http-perf.quick

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

ssh.firewall:
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
	if [ -z "$$ip" ]; then echo "missing firewall IP for INDEX=$$index" >&2; exit 1; fi; \
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
	if [ -z "$$ip" ]; then echo "missing firewall IP for INDEX=$$index" >&2; exit 1; fi; \
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
	if [ -z "$$fw_mgmt_ip" ]; then echo "missing firewall mgmt ip" >&2; exit 1; fi; \
	dns_server="$$fw_mgmt_ip"; \
	JUMPBOX_IP=$$jump_ip CONSUMER_IP=$$consumer_ip FW_MGMT_IP=$$fw_mgmt_ip FW_MGMT_IPS="$$fw_mgmt_ips" UPSTREAM_VIP=$$upstream_vip UPSTREAM_IP=$$upstream_ip DNS_SERVER=$$dns_server \
	DNS_ZONE=$${DNS_ZONE:-upstream.test} KEY_PATH="$(KEY_PATH)" SSH_USER="$(SSH_USER)" \
	"$(CURDIR)/../common/run-policy-smoke.sh"

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
		"$(CURDIR)/scripts/http-perf-matrix.sh"

http-perf.quick:
	@command -v terraform >/dev/null || { echo "terraform is required" >&2; exit 1; }
	@command -v ssh >/dev/null || { echo "ssh is required" >&2; exit 1; }
	@command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
	@command -v az >/dev/null || { echo "az is required" >&2; exit 1; }
	@if [ ! -f "$(KEY_PATH)" ]; then echo "missing SSH key at $(KEY_PATH)" >&2; exit 1; fi
	@TF_DIR="$(TF_DIR)" KEY_PATH="$(KEY_PATH)" SSH_USER="$(SSH_USER)" \
		HTTP_PERF_SCENARIOS="$${HTTP_PERF_SCENARIOS:-l34_allow_webhooks}" \
		RPS_TIERS="$${RPS_TIERS:-500}" \
		"$(CURDIR)/scripts/http-perf-matrix.sh"
