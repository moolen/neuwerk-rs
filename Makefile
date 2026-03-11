.PHONY: build test test.clippy test.integration test.integration.sso test.security fuzz.check fuzz.smoke fuzz.nightly ha.up ha.down dpdk.prepare package.target.validate package.image.bundle package.image.prebuilt-bundle package.image.qemu-key package.image.validate package.image.build.qemu package.image.build.aws package.image.build.azure package.image.build.gcp package.image.release-manifest package.image.release-assets

DPDK_VERSION := $(shell cat third_party/dpdk/VERSION 2>/dev/null)
DPDK_INSTALL := third_party/dpdk/install/$(DPDK_VERSION)
DPDK_DIR_ABS := $(abspath $(DPDK_INSTALL))
DPDK_PKG_CONFIG_PATH := $(DPDK_DIR_ABS)/lib/pkgconfig:$(DPDK_DIR_ABS)/lib/x86_64-linux-gnu/pkgconfig:$(DPDK_DIR_ABS)/lib64/pkgconfig
DPDK_LD_LIBRARY_PATH := $(DPDK_DIR_ABS)/lib:$(DPDK_DIR_ABS)/lib/x86_64-linux-gnu:$(DPDK_DIR_ABS)/lib64
TARGET ?= ubuntu-24.04-amd64
PACKER ?= packer
PACKER_DIR ?= $(CURDIR)/packer
PACKER_ARTIFACT_DIR ?= $(CURDIR)/artifacts/image-build
GITHUB_RELEASE_ARTIFACT_DIR ?= $(PACKER_ARTIFACT_DIR)/github-release/$(TARGET)
QEMU_SSH_KEY_DIR ?= $(PACKER_ARTIFACT_DIR)/qemu-keys
QEMU_SSH_PRIVATE_KEY ?= $(QEMU_SSH_KEY_DIR)/id_ed25519
QEMU_SSH_PUBLIC_KEY ?= $(QEMU_SSH_KEY_DIR)/id_ed25519.pub
QEMU_ACCELERATOR ?=
USE_PREBUILT_ARTIFACTS ?=
RELEASE_VERSION ?= dev
GIT_REVISION ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || printf "unknown")
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

package.target.validate:
	python3 packaging/scripts/validate_target.py --target $(TARGET)

package.image.bundle: package.target.validate
	NEUWERK_REPO_ROOT=$(CURDIR) \
	NEUWERK_BUNDLE_OUTPUT=$(PACKER_ARTIFACT_DIR)/source/$(TARGET).tar.gz \
		packer/scripts/create-source-bundle.sh

package.image.prebuilt-bundle: package.target.validate
	NEUWERK_REPO_ROOT=$(CURDIR) \
	NEUWERK_PREBUILT_BUNDLE_OUTPUT=$(PACKER_ARTIFACT_DIR)/source/$(TARGET)-prebuilt.tar.gz \
	NEUWERK_TARGET=$(TARGET) \
	NEUWERK_USE_PREBUILT_ARTIFACTS=$(if $(USE_PREBUILT_ARTIFACTS),$(USE_PREBUILT_ARTIFACTS),false) \
		packer/scripts/create-prebuilt-bundle.sh

package.image.qemu-key:
	@mkdir -p $(QEMU_SSH_KEY_DIR)
	@if [ ! -f "$(QEMU_SSH_PRIVATE_KEY)" ]; then \
		ssh-keygen -q -t ed25519 -N "" -C "neuwerk-packer-qemu" -f "$(QEMU_SSH_PRIVATE_KEY)"; \
	fi

package.image.validate: package.target.validate
	@command -v $(PACKER) >/dev/null || { echo "packer is required" >&2; exit 1; }
	$(PACKER) fmt -check $(PACKER_DIR)
	$(PACKER) init $(PACKER_DIR)
	$(PACKER) validate -syntax-only \
		-var "target=$(TARGET)" \
		-var "artifact_dir=$(PACKER_ARTIFACT_DIR)" \
		-var "release_version=$(RELEASE_VERSION)" \
		-var "git_revision=$(GIT_REVISION)" \
		$(PACKER_DIR)

package.image.build.qemu: package.image.bundle package.image.prebuilt-bundle package.image.qemu-key
	@command -v $(PACKER) >/dev/null || { echo "packer is required" >&2; exit 1; }
	rm -rf $(PACKER_ARTIFACT_DIR)/qemu/$(TARGET)
	$(PACKER) init $(PACKER_DIR)
	$(PACKER) build \
		-only=ubuntu-2404-amd64.qemu.ubuntu_2404_amd64 \
		-var "target=$(TARGET)" \
		-var "artifact_dir=$(PACKER_ARTIFACT_DIR)" \
		-var "release_version=$(RELEASE_VERSION)" \
		-var "git_revision=$(GIT_REVISION)" \
		$(if $(QEMU_ACCELERATOR),-var "qemu_accelerator=$(QEMU_ACCELERATOR)") \
		$(if $(USE_PREBUILT_ARTIFACTS),-var "use_prebuilt_artifacts=$(USE_PREBUILT_ARTIFACTS)") \
		-var "qemu_ssh_private_key_file=$(QEMU_SSH_PRIVATE_KEY)" \
		-var "qemu_ssh_public_key=$$(cat $(QEMU_SSH_PUBLIC_KEY))" \
		$(PACKER_DIR)

package.image.build.aws: package.image.bundle
	@command -v $(PACKER) >/dev/null || { echo "packer is required" >&2; exit 1; }
	$(PACKER) init $(PACKER_DIR)
	$(PACKER) build \
		-only=ubuntu-2404-amd64.amazon-ebs.ubuntu_2404_amd64 \
		-var "target=$(TARGET)" \
		-var "artifact_dir=$(PACKER_ARTIFACT_DIR)" \
		-var "release_version=$(RELEASE_VERSION)" \
		-var "git_revision=$(GIT_REVISION)" \
		$(PACKER_DIR)

package.image.build.azure: package.image.bundle
	@command -v $(PACKER) >/dev/null || { echo "packer is required" >&2; exit 1; }
	$(PACKER) init $(PACKER_DIR)
	$(PACKER) build \
		-only=ubuntu-2404-amd64.azure-arm.ubuntu_2404_amd64 \
		-var "target=$(TARGET)" \
		-var "artifact_dir=$(PACKER_ARTIFACT_DIR)" \
		-var "release_version=$(RELEASE_VERSION)" \
		-var "git_revision=$(GIT_REVISION)" \
		$(PACKER_DIR)

package.image.build.gcp: package.image.bundle
	@command -v $(PACKER) >/dev/null || { echo "packer is required" >&2; exit 1; }
	$(PACKER) init $(PACKER_DIR)
	$(PACKER) build \
		-only=ubuntu-2404-amd64.googlecompute.ubuntu_2404_amd64 \
		-var "target=$(TARGET)" \
		-var "artifact_dir=$(PACKER_ARTIFACT_DIR)" \
		-var "release_version=$(RELEASE_VERSION)" \
		-var "git_revision=$(GIT_REVISION)" \
		$(PACKER_DIR)

package.image.release-manifest: package.target.validate
	python3 packaging/scripts/generate_release_manifest.py \
		--target $(TARGET) \
		--provider qemu \
		--release-version $(RELEASE_VERSION) \
		--git-revision $(GIT_REVISION) \
		--output $(PACKER_ARTIFACT_DIR)/release/$(TARGET)/manifest.json

package.image.release-assets: package.target.validate
	bash packaging/scripts/prepare_github_release.sh \
		--target $(TARGET) \
		--artifact-dir $(PACKER_ARTIFACT_DIR) \
		--release-version $(RELEASE_VERSION) \
		--git-revision $(GIT_REVISION) \
		--output-dir $(GITHUB_RELEASE_ARTIFACT_DIR)

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
