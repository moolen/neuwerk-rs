.PHONY: build test test.integration ha.up ha.down build.dpdk

DPDK_VERSION := $(shell cat third_party/dpdk/VERSION 2>/dev/null)
DPDK_INSTALL := third_party/dpdk/install/$(DPDK_VERSION)

build:
	cargo build

build.release:
	cargo build --release

build.dpdk:
	@if [ -z "$(DPDK_VERSION)" ]; then echo "Missing third_party/dpdk/VERSION"; exit 1; fi
	@if [ ! -d "$(DPDK_INSTALL)" ] || [ "$$DPDK_FORCE_REBUILD" = "1" ]; then ./scripts/build-dpdk.sh; fi
	DPDK_DIR=$(abspath $(DPDK_INSTALL)) PKG_CONFIG_PATH=$(abspath $(DPDK_INSTALL))/lib/pkgconfig:$(abspath $(DPDK_INSTALL))/lib64/pkgconfig cargo build --release --features dpdk

test:
	cargo test

test.integration: build
	cargo run --bin e2e_harness

ha.up: build
	sudo ./scripts/ha_local.sh up

ha.down:
	sudo ./scripts/ha_local.sh down

.PHONY: azure.%
azure.%:
	$(MAKE) -C cloud-tests/azure $*
