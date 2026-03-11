.PHONY: build test test.clippy test.integration test.integration.sso test.security fuzz.check fuzz.smoke fuzz.nightly ha.up ha.down dpdk.prepare

DPDK_VERSION := $(shell cat third_party/dpdk/VERSION 2>/dev/null)
DPDK_INSTALL := third_party/dpdk/install/$(DPDK_VERSION)
DPDK_DIR_ABS := $(abspath $(DPDK_INSTALL))
DPDK_PKG_CONFIG_PATH := $(DPDK_DIR_ABS)/lib/pkgconfig:$(DPDK_DIR_ABS)/lib/x86_64-linux-gnu/pkgconfig:$(DPDK_DIR_ABS)/lib64/pkgconfig
DPDK_LD_LIBRARY_PATH := $(DPDK_DIR_ABS)/lib:$(DPDK_DIR_ABS)/lib/x86_64-linux-gnu:$(DPDK_DIR_ABS)/lib64
SUDO := $(shell if [ "$$(id -u)" -eq 0 ]; then printf ""; else printf "sudo"; fi)

build: build.ui dpdk.prepare
	DPDK_DIR=$(DPDK_DIR_ABS) PKG_CONFIG_PATH=$(DPDK_PKG_CONFIG_PATH) cargo build --all-features

build.release:
	DPDK_DIR=$(DPDK_DIR_ABS) PKG_CONFIG_PATH=$(DPDK_PKG_CONFIG_PATH) cargo build --release --all-features

dpdk.prepare:
	@if [ -z "$(DPDK_VERSION)" ]; then echo "Missing third_party/dpdk/VERSION"; exit 1; fi
	@if [ ! -d "$(DPDK_INSTALL)" ] || [ "$$DPDK_FORCE_REBUILD" = "1" ]; then ./scripts/build-dpdk.sh; fi

build.ui:
	@echo "Building UI..."
	@cd ui && npm install && npm run build

test:
	cargo test

test.clippy:
	cargo clippy --workspace --all-targets --no-default-features --no-deps -- -D warnings

test.integration: build
	DPDK_DIR=$(DPDK_DIR_ABS) PKG_CONFIG_PATH=$(DPDK_PKG_CONFIG_PATH) cargo build --bin e2e_harness --all-features
	$(SUDO) env PATH="$(PATH)" LD_LIBRARY_PATH="$(DPDK_LD_LIBRARY_PATH)$${LD_LIBRARY_PATH:+:$$LD_LIBRARY_PATH}" target/debug/e2e_harness
	DPDK_DIR=$(DPDK_DIR_ABS) PKG_CONFIG_PATH=$(DPDK_PKG_CONFIG_PATH) LD_LIBRARY_PATH="$(DPDK_LD_LIBRARY_PATH)$${LD_LIBRARY_PATH:+:$$LD_LIBRARY_PATH}" cargo run --bin e2e_kind_harness --all-features

test.integration.sso:
	cargo test --test http_api sso_oidc_cases -- --nocapture

test.security:
	cargo audit
	npm --prefix ui audit --omit=dev --audit-level=high

fuzz.check:
	cargo check --manifest-path fuzz/Cargo.toml

fuzz.smoke:
	NEUWERK_FUZZ_REQUIRED=1 ./scripts/fuzz-smoke.sh

fuzz.nightly:
	./scripts/fuzz-nightly.sh

test.readiness.fuzz: fuzz.check fuzz.smoke

ha.up: build
	@echo "run with: DEFAULT_POLICY=deny WAN_IFACE=<iface> make ha.up"
	sudo ./scripts/ha_local.sh up

ha.down:
	sudo ./scripts/ha_local.sh down

.PHONY: azure.%
azure.%:
	$(MAKE) -C cloud-tests/azure $*

.PHONY: gcp.%
gcp.%:
	$(MAKE) -C cloud-tests/gcp $*

.PHONY: aws.%
aws.%:
	$(MAKE) -C cloud-tests/aws $*
