# Packer Image Build

Last updated: 2026-03-11
Owner: firewall team
Scope: build and release immutable Ubuntu 24.04 LTS firewall images for cloud platforms and `qcow2`, with deterministic DPDK linkage, CIS Level 2 hardening, and attachable SBOMs.

## Current Implementation Status

The initial implementation is now in-tree:

- target manifests and DPDK profile catalog scaffolding exist under `packaging/`
- the Packer build chain builds vendored DPDK and the firewall inside Ubuntu 24.04
- staged runtime now includes `firewall-bootstrap`, `firewall-launch`, `appliance.env`, and `firewall.service`
- release artifacts are produced inside the guest under `/tmp/neuwerk-release/<target>` and downloaded back to the host
- a local Ansible hardening pass applies the current open/custom CIS-oriented baseline
- rootfs and image SBOM generation paths exist when `syft` is available during the build
- GitHub release asset preparation now exists as a separate packaging step under `packaging/scripts/prepare_github_release.sh`
- manual-only GitHub release automation exists under `.github/workflows/image-release.yml`

Remaining work is mostly validation depth, waiver refinement, and migration of cloud e2e flows to consume published image IDs by default.

## Current Artifact Size Snapshot

From the latest successful local `ubuntu-24.04-amd64` qemu build:

- raw `qcow2`: `8.6G` (`9169534976` bytes)
- staged `rootfs/`: `380M`
- image SPDX SBOM: `67M`
- image CycloneDX SBOM: `31M`
- rootfs SPDX SBOM: `68K`
- rootfs CycloneDX SBOM: `442` bytes
- `linkage.json`: `1819` bytes
- `packer-manifest.json`: `436` bytes

This confirms the raw `qcow2` is too large to upload directly as one GitHub Release asset, so the release path must package it as a compressed multi-part archive.

## Clarified Decisions

- Phase 1 artifacts:
  - Cloud-native images.
  - A generic `qcow2` artifact.
- Target OS:
  - Ubuntu 24.04 LTS only for now.
- Target architecture:
  - `x86_64` only for now.
- Deployment priority:
  - Cloud first.
- Compliance target:
  - CIS Ubuntu 24.04 Level 2.
- Hardening path:
  - Open/custom path only.
  - No Ubuntu Pro / Canonical USG dependency in phase 1.
- Runtime footprint:
  - Minimal runtime image, not an operator toolbox image.
- NIC/PMD coverage:
  - Cloud NIC set plus a broader generic PMD set.
- Build environment:
  - Internet access is available during image builds.

## Problem Statement

Today the repository has three competing runtime stories:

1. Local builds pin vendored DPDK `23.11.2`.
2. AWS/Azure cloud flows mostly expect Ubuntu 24.04 packaged DPDK ABI `.so.24`.
3. GCP defaults still reference a separate `dpdk-runtime-26` bundle.

That drift is acceptable for short-lived e2e bootstrapping, but not for a user-facing appliance image. For image publishing we need one explicit compatibility contract per target:

- OS family and version.
- Base image lineage.
- Kernel expectations.
- DPDK version and enabled PMDs.
- Firewall binary build environment.
- Runtime library layout.
- Hardening profile and waivers.
- SBOM and release metadata.

## Recommendation

Use a target-manifest-driven image factory:

1. Packer HCL2 is the top-level image orchestrator.
2. Each supported target is declared by a small manifest, for example `ubuntu-24.04-amd64`.
3. The firewall binary is built inside the target OS family, not on the developer or generic CI host.
4. DPDK is vendored from source and built per target manifest into a private runtime prefix.
5. The image bakes the firewall binary, DPDK runtime, systemd units, hardening, and metadata.
6. Cloud-native images are published by provider-specific Packer builders; `qcow2` is produced by the `qemu` builder from the same provisioning chain.
7. SBOMs are generated from the staged root filesystem and attached to releases together with image manifests, checksums, and provenance metadata.

This keeps the image deterministic, removes ABI drift, and makes it easy to add more Ubuntu releases or additional OS families later by adding new target manifests instead of rewriting the pipeline.

## Explicit Non-Recommendations

Do not use these as the primary phase-1 strategy:

1. Rely on distro DPDK packages as the compatibility contract.
   - Pros:
     - Less custom build logic.
     - Easier to receive distro security updates.
   - Cons:
     - ABI and PMD availability differ by provider and release.
     - Reproducing exact runtime behavior becomes difficult.
     - The repository already shows drift between `.so.24` and `.so.26` assumptions.
   - Verdict:
     - Keep package-based DPDK only for temporary e2e bootstrap paths until the image pipeline replaces them.

2. Build one firewall binary on a generic CI host and reuse it everywhere.
   - Pros:
     - Fast and simple.
   - Cons:
     - Glibc and linker compatibility become fragile.
     - DPDK ABI and PMD selection are not target-owned.
     - Reproducing image contents becomes harder.
   - Verdict:
     - Not acceptable for a regulated appliance image.

3. Statically link all DPDK content into the firewall binary.
   - Pros:
     - Fewer runtime files.
   - Cons:
     - Larger binary.
     - More awkward PMD handling.
     - Harder upgrade and provenance story.
     - Increases risk of over-coupling build and runtime.
   - Verdict:
     - Avoid in phase 1.

## DPDK Strategy

### Options

#### Option A: Distro DPDK per OS release

- Build against Ubuntu 24.04 package DPDK.
- Ship package-managed runtime libraries in the image.

Use when:
- Fast bootstrap matters more than strict reproducibility.

Main drawbacks:
- We inherit Ubuntu package choices and PMD splits.
- Future Ubuntu releases will force ABI changes on our schedule.
- Cross-cloud parity is weaker.

#### Option B: Vendored DPDK source per target manifest

- Track DPDK source tarballs and patches explicitly.
- Build shared libraries for each target manifest.
- Ship only the selected runtime libs and PMDs in the image.

Use when:
- Image determinism and compatibility ownership matter.

Main drawbacks:
- More build time.
- We own DPDK CVE tracking and rebuild cadence.

#### Option C: Hybrid

- Use vendored DPDK for the image factory.
- Keep existing distro-package e2e flows temporarily until cloud tests are migrated.

Use when:
- We need low migration risk.

### Recommended Path

Choose Option C immediately, with Option B as the end state.

That means:

1. The new image pipeline uses vendored DPDK source.
2. Existing e2e cloud bootstraps may continue using package/runtime-bundle flows until image-based deployment replaces them.
3. The cloud test stacks should later consume published image IDs instead of uploading the raw firewall binary at boot.

### Recommended DPDK Ownership Model

Add a target catalog outside the current single-version file:

```text
packaging/
  dpdk/
    catalog/
      23.11.2/
        source.lock.json
        patches/
        profiles/
          generic.meson
          aws-ena.meson
          azure-mana.meson
          gcp-gve.meson
    targets/
      ubuntu-24.04-amd64.yaml
```

The target manifest owns:

- `dpdk_version`
- `dpdk_profile`
- enabled PMDs
- disabled PMDs
- extra build args
- runtime library include list
- expected soname ABI

Example target manifest:

```yaml
id: ubuntu-24.04-amd64
os:
  family: ubuntu
  version: "24.04"
  arch: amd64
base_images:
  aws: ubuntu-noble-24.04
  azure: canonical-ubuntu-24_04-lts-server
  gcp: ubuntu-2404-lts-amd64
  qemu: ubuntu-24.04-server-cloudimg-amd64.img
dpdk:
  version: 23.11.2
  profile: generic-cloud
  abi: so.24
  disable_drivers:
    - net/ionic
  enable_pmd_sets:
    - generic
    - aws-ena
    - azure-mana
    - gcp-gve
runtime:
  prefix: /opt/neuwerk/runtime
hardening:
  profile: cis-l2
  waiver_file: cis/waivers/ubuntu-24.04-amd64.yaml
sbom:
  formats:
    - spdx-json
    - cyclonedx-json
```

### Concrete DPDK Build Rules

1. Build DPDK from vendored source inside the target OS builder.
2. Install to a private prefix, for example:
   - `/opt/neuwerk/runtime/dpdk/23.11.2`
3. Compile the firewall against that prefix.
4. Do not depend on `/usr/lib` or distro `ldconfig` state for DPDK lookup.
5. Prefer an embedded `RUNPATH` or a tightly scoped systemd `Environment=LD_LIBRARY_PATH=...` over global linker configuration.
6. Fail the build if:
   - `ldd` shows unresolved libraries.
   - the resolved DPDK ABI does not match the target manifest.
   - a required PMD is missing.
7. Produce a machine-readable linkage manifest, for example:
   - `artifacts/linkage/ubuntu-24.04-amd64.json`

### Generic and Cloud PMD Set

Phase 1 should build one DPDK runtime profile that includes:

- Generic:
  - `virtio`
  - `vmxnet3`
  - `ixgbe`
  - `i40e`
  - `ice`
  - `mlx5` only if the dependency story is acceptable
- Cloud:
  - AWS `ena`
  - Azure `mana`
  - GCP `gve`

We should keep the runtime PMD list explicit and small. A minimal runtime image should not include every available DPDK driver.

## Image Factory Architecture

### Packer Layout

```text
packer/
  plugins.pkr.hcl
  variables.pkr.hcl
  locals.pkr.hcl
  common.pkr.hcl
  sources/
    aws-ubuntu-2404-amd64.pkr.hcl
    azure-ubuntu-2404-amd64.pkr.hcl
    gcp-ubuntu-2404-amd64.pkr.hcl
    qemu-ubuntu-2404-amd64.pkr.hcl
  builds/
    ubuntu-2404-amd64.pkr.hcl
  scripts/
    install-build-deps.sh
    build-dpdk.sh
    build-firewall.sh
    stage-runtime.sh
    verify-linkage.sh
    cleanup-image.sh
  ansible/
    playbook.yml
    group_vars/
    roles/
      neuwerk_base/
      neuwerk_runtime/
      neuwerk_hardening/
      neuwerk_cleanup/
  cis/
    overrides/
    waivers/
  metadata/
    release-manifest.schema.json
```

### Build Graph

1. Resolve target manifest.
2. Resolve provider-specific base image.
3. Launch builder instance or VM with Packer.
4. Install build prerequisites.
5. Build vendored DPDK into private prefix.
6. Build UI and Rust firewall binary inside the target OS.
7. Stage runtime files into final prefix.
8. Install systemd units, tmpfiles, sysctl, netplan templates, and image metadata.
9. Apply CIS Level 2 hardening.
10. Apply appliance-specific waivers and cloud exceptions.
11. Run verification suite.
12. Generate SBOMs and checksums.
13. Publish provider-native image or local `qcow2`.
14. Emit one release manifest that records every artifact ID and digest.

### Build Stages

### Stage 0: Resolve Inputs

Inputs:

- Git revision.
- target manifest ID.
- provider.
- release version.
- DPDK catalog version.
- hardening profile version.

Outputs:

- immutable build context record.

### Stage 1: Builder Preparation

Install:

- Rust toolchain.
- Node toolchain.
- Packer prerequisites.
- DPDK build dependencies.
- Syft.
- hardening and audit dependencies.

### Stage 2: Application Build

Run:

- `npm --prefix ui ci`
- `npm --prefix ui test`
- `npm --prefix ui run build`
- Rust unit and relevant integration gates
- target-owned firewall release build

Prefer a dedicated packaging entrypoint, for example:

```text
make package.image.build TARGET=ubuntu-24.04-amd64 PROVIDER=aws
```

### Stage 3: Runtime Staging

Stage only:

- firewall binary
- UI dist
- DPDK shared libraries
- selected PMDs
- systemd unit files
- config directories
- trust store dependencies
- required cloud/boot agents

Remove:

- compilers
- headers
- cargo registry
- node modules used only for build
- package caches
- temporary credentials

### Stage 4: Hardening

Apply open-source CIS automation plus repo-local overlays:

1. baseline remediation role
2. appliance exceptions
3. audit run
4. waiver export

### Stage 5: Verification and Publish

Run verification before artifact publication:

- boot check
- service enablement check
- linkage check
- CIS audit check
- package inventory export
- SBOM generation
- checksum generation
- image publish

## CIS Level 2 Hardening Strategy

### Approach

Use a layered hardening model:

1. Open-source CIS remediation role as the baseline.
2. Repo-local override role for appliance-specific behavior.
3. Repo-local waiver file mapped to CIS control IDs with rationale.
4. A separate audit step that runs after cleanup and before publication.

### Why Waivers Are Mandatory

This appliance will intentionally violate or tailor some generic CIS expectations because it is:

- multi-NIC
- DHCP-dependent on dataplane
- metadata-service-dependent during bootstrap
- cloud-image-based
- DPDK and hugepage aware
- designed for unattended boot in cloud environments

Likely waiver categories:

- metadata endpoint reachability
- DHCP and netplan specifics
- cloud-init retention during first boot
- hugepages and IOMMU kernel args
- package manager state during image creation only
- firewall host firewall controls if they conflict with dataplane operation
- logging and audit retention tuning on small disks

### Recommended Tooling Direction

1. Baseline:
   - `ansible-lockdown/UBUNTU24-CIS`
2. Audit:
   - `ansible-lockdown/UBUNTU24-CIS-Audit`
3. Repo-local overlay:
   - `packer/ansible/roles/neuwerk_hardening`

We should vendor exact upstream role versions into a lock file and treat updates like dependency updates, not like ad hoc scripting.

### Hardening Output Artifacts

Publish:

- rendered hardening variable set
- waiver file
- audit result summary
- control failures, if any

These should be part of the release evidence set even if only the SBOMs are attached as primary user-facing assets.

## SBOM Strategy

### Goal

Produce an SBOM that describes the shipped OS image, not only the Rust crate graph.

### Recommended SBOM Outputs

For each built target:

1. `image-rootfs.spdx.json`
2. `image-rootfs.cyclonedx.json`
3. `image-packages.json`
4. `image-manifest.json`

Optional later:

5. `firewall-source.spdx.json`
6. provenance and signature attestations

### Recommended Generation Flow

1. Generate SBOM from the staged root filesystem before final packaging.
2. Generate or verify a second SBOM from the final `qcow2` mount or unpacked artifact.
3. Record:
   - OS packages
   - vendored DPDK artifacts
   - Rust binary
   - UI bundle
   - config and unit files
4. Include the target manifest metadata in the release manifest.

### Suggested Tooling

- Primary SBOM generator:
  - Syft
- Formats:
  - SPDX JSON for ecosystem interoperability
  - CycloneDX JSON for richer downstream supply-chain usage

### Release Attachment Policy

Attach to each release:

- SBOMs
- checksums
- release manifest
- hardening summary
- split compressed `qcow2` archive parts

Do not attach:

- provider-native image payloads

Instead publish provider image references in the release manifest:

- AWS AMI IDs by region
- Azure image definition or gallery version IDs
- GCP image names and family references

## GitHub Release Strategy

GitHub Releases are suitable for this feature, but only if we are disciplined about artifact size.

Rules:

1. Release assets should be metadata-first.
2. Cloud-native images should be referenced by ID, not exported and uploaded as giant blobs.
3. The raw `qcow2` should never be uploaded directly; package it as a compressed archive and split it below the GitHub per-file asset ceiling.
4. The GitHub Release should also include:
   - checksum manifest
   - restore script
   - SBOMs
   - provenance metadata
5. Cloud-native images still belong in provider registries, with only their image references attached to the GitHub release metadata.

### Recommended Release Asset Set

Per release:

- `manifest.json`
- `SHA256SUMS`
- `restore-qcow2.sh`
- `packer-manifest.json`
- `linkage.json`
- `ubuntu-24.04-amd64-image.spdx.json`
- `ubuntu-24.04-amd64-image.cyclonedx.json`
- `ubuntu-24.04-amd64-rootfs.spdx.json`
- `ubuntu-24.04-amd64-rootfs.cyclonedx.json`
- `neuwerk-ubuntu-24.04-amd64-rootfs.tar.zst`
- `neuwerk-ubuntu-24.04-amd64-source.tar.gz`
- `neuwerk-ubuntu-24.04-amd64.qcow2.zst.part-*`

## Repository Changes

### New Top-Level Areas

```text
packer/
packaging/
docs/operations/image-build.md
docs/operations/image-hardening.md
docs/operations/image-release.md
```

### Existing Areas To Change

- `Makefile`
  - Add packaging and image targets.
- `.github/workflows/`
  - Add image validation and release workflows.
- `cloud-tests/aws/terraform/`
  - Migrate from binary-upload bootstrap to image-ID consumption.
- `cloud-tests/azure/terraform/`
  - Migrate from blob-upload bootstrap to image-ID consumption.
- `cloud-tests/gcp/terraform/`
  - Migrate from object-upload bootstrap to image-ID consumption.
- `scripts/build-dpdk.sh`
  - Refactor or wrap for target-manifest-aware DPDK builds.
- `third_party/dpdk/`
  - Keep as one source of truth until catalog split is introduced.

### Required Build-System Changes

1. Add a packaging-aware build command that compiles inside the target OS.
2. Add a target-manifest parser and validation step.
3. Add a runtime staging script that copies only the required libs and PMDs.
4. Add a linkage verifier that fails on unexpected sonames.
5. Add a release manifest generator.

### Required Runtime Changes

1. Ensure the service unit does not rely on ambient host library state.
2. Ensure the firewall can discover runtime assets from a fixed prefix.
3. Keep management-plane and dataplane separation unchanged.
4. Ensure minimal runtime paths and file permissions comply with hardening decisions.

## Verification Plan

### Build-Time Verification

- `packer fmt -check`
- `packer validate`
- target manifest schema validation
- DPDK build smoke
- firewall release build
- linkage verification
- hardening dry-run
- SBOM generation dry-run

### Artifact Verification

For each built artifact:

- boot successfully
- `firewall.service` enabled and starts
- `ldd` matches expected runtime prefix
- `/health` and `/ready` pass in a lab boot
- expected DPDK PMDs exist
- CIS audit result exported
- SBOM generated and checksummed

### Integration Verification

1. Image-based AWS deploy path.
2. Image-based Azure deploy path.
3. Image-based GCP deploy path.
4. `qcow2` boot in local `qemu` smoke lab.

## Migration Plan

### Phase 1: Design and Skeleton

- Create `packer/` layout and target manifest schema.
- Add a single `ubuntu-24.04-amd64` target manifest.
- Add `qemu` builder first because it is the easiest local validation path.
- Add a packaging Make target and validation scripts.

### Phase 2: Deterministic Build and Runtime

- Build DPDK from vendored source inside the image builder.
- Build firewall release binary inside the target OS.
- Stage runtime into a private prefix.
- Add linkage verification and runtime manifest generation.

### Phase 3: CIS Hardening and Waivers

- Integrate open-source CIS Level 2 remediation.
- Add repo-local overlay and waiver files.
- Export hardening and audit reports.

### Phase 4: SBOM and Release Metadata

- Integrate Syft-based rootfs SBOM generation.
- Generate release manifests and checksums.
- Add GitHub release asset upload for metadata and split `qcow2` archive parts.

### Phase 5: Cloud-Native Publishing

- Add AWS AMI build and publish path.
- Add Azure image build and publish path.
- Add GCP image build and publish path.
- Export provider image references into the release manifest.

### Phase 6: Cloud Test Migration

- Update AWS/Azure/GCP Terraform to consume image IDs instead of raw binary uploads.
- Remove temporary runtime bundle assumptions where possible.
- Deprecate `dpdk-runtime-26` cloud-only bundle handling.

## Initial Task Breakdown

1. Create target manifest schema and one Ubuntu 24.04 target definition.
2. Add `packer/` HCL2 skeleton with shared variables, one `qemu` source, and a manifest post-processor.
3. Add packaging scripts:
   - target resolve
   - DPDK build
   - firewall build
   - runtime stage
   - linkage verify
4. Add a minimal systemd runtime image install path.
5. Add hardening integration and a first waiver file.
6. Add SBOM generation and release-manifest export.
7. Add GitHub Actions validation workflow.
8. Add manual `workflow_dispatch` release workflow.
9. Migrate one cloud test stack first, then the other two.

## CI and Release Workflow

### Validation Workflow

Trigger:

- pull requests touching `packer/`, `packaging/`, `third_party/dpdk/`, image workflows, or runtime packaging logic

Run:

- manifest schema validation
- `packer validate`
- `qemu` image smoke build
- linkage verification
- SBOM generation smoke

### Release Workflow

Trigger:

- manual workflow dispatch only

Run:

1. Build `qemu` image.
2. Prepare compressed and split GitHub-safe release assets.
3. Generate SBOMs, checksums, restore script, and release metadata.
4. Create or update GitHub Release.
5. Upload metadata assets and split `qcow2` archive parts.

## Risks

1. CIS Level 2 controls may conflict with cloud-init, DHCP, metadata access, or first-boot behavior.
2. DPDK PMD dependency trimming may accidentally remove a required cloud driver.
3. Building inside target OS increases build time.
4. `qcow2` size will exceed GitHub Release single-file policy unless it is split.
5. Provider image publication auth will require careful CI secret handling.

## Risk Mitigations

1. Treat waivers as first-class versioned artifacts.
2. Add PMD-presence and `ldd` verification gates.
3. Use a two-stage build flow and cache DPDK source tarballs.
4. Keep cloud-native images metadata-only in GitHub releases, and split only the generic `qcow2` release payload.
5. Start with `qemu` and one cloud provider if CI runtime becomes excessive.

## Success Criteria

Phase 1 is successful when all of the following are true:

1. A single command can build an Ubuntu 24.04 `qemu` image and emit:
   - firewall image artifact
   - SBOMs
   - checksums
   - release manifest
2. The image boots and starts the firewall service without unresolved DPDK libraries.
3. CIS Level 2 audit results are exported with explicit waivers.
4. One cloud-native image can be published from the same target manifest and provisioning logic.
5. Cloud tests can begin migrating from binary upload to image-based deployment.

## Deferred Items

- `arm64` images.
- Additional Ubuntu releases.
- Non-Ubuntu OS families.
- Signed provenance attestations.
- Offline build support.
- FIPS mode.
- Full replacement of package-based DPDK in existing e2e paths.
