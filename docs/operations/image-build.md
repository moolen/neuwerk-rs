# Image Build

The image factory uses target manifests under `packaging/targets/` and Packer templates under `packer/`.

For operators consuming a published appliance image, see [Appliance Image Usage](./appliance-image-usage.md).
This document remains build-facing and covers how Neuwerk image artifacts are produced.

## Current Targets

- `ubuntu-24.04-minimal-amd64`

## Local VM Demo Direction

The current local-image release flow produces a `qcow2` appliance artifact.

For the laptop demo workflow, the preferred direction is a separate Vagrant-oriented VM artifact
published as a provider-native box. See [local-vm-demo.md](/home/moritz/dev/neuwerk-rs/firewall/docs/operations/local-vm-demo.md).

If a provider-native `.box` has already been built and staged, generate a Vagrant `metadata.json`
for release packaging with:

```bash
make package.vagrant.metadata \
  TARGET=ubuntu-24.04-minimal-amd64 \
  RELEASE_VERSION=v0.1.0 \
  VAGRANT_BOX_URL='<box-url>' \
  VAGRANT_BOX_CHECKSUM='<sha256>'
```

This writes metadata under `artifacts/image-build/vagrant/<target>/`. The existing
`package.image.release-assets` target will include any staged Vagrant metadata or box artifacts in
the GitHub release asset directory.

## Build A Local Vagrant Box

The current Vagrant packaging path is a post-processing step over an existing local `qemu` build.
It requires:

- an existing `qcow2` from `make package.image.build.qemu`
- `VBoxManage`
- `qemu-img`

Build the VirtualBox provider box with:

```bash
make package.vagrant.box \
  TARGET=ubuntu-24.04-minimal-amd64 \
  RELEASE_VERSION=dev
```

This writes:

- `artifacts/image-build/vagrant/<target>/*.box`
- `artifacts/image-build/vagrant/<target>/*.box.sha256`

If you already know the eventual download URL, generate Vagrant `metadata.json` in the same step:

```bash
make package.vagrant.box \
  TARGET=ubuntu-24.04-minimal-amd64 \
  RELEASE_VERSION=v0.1.0 \
  VAGRANT_BOX_URL='<box-download-url>'
```

That also writes:

- `artifacts/image-build/vagrant/<target>/metadata.json`

## Validate The Pipeline

```bash
make package.target.validate
make package.image.validate
```

This validates:

- the target manifest shape
- shell and Python packaging helper syntax
- Packer HCL formatting and syntax

## What The Build Produces

The `ubuntu-24.04-minimal-amd64` build produces:

- a vendored DPDK `23.11.2` runtime under `/opt/neuwerk/runtime`
- a release-mode Neuwerk binary compiled against that vendored DPDK
- the built UI under `/opt/neuwerk/ui`
- a generated runtime bootstrap flow:
  - `/opt/neuwerk/bin/neuwerk-bootstrap`
  - `/opt/neuwerk/bin/neuwerk-launch`
  - `/etc/neuwerk/appliance.env`
  - `/etc/neuwerk/neuwerk.env`
- a systemd service at `/etc/systemd/system/neuwerk.service`
- release-side metadata artifacts downloaded from the guest into `artifacts/image-build/release/<target>/`

The build also preserves a staged `rootfs/` copy in the release artifact directory for linkage inspection and rootfs SBOM generation.

## Build A Local `qcow2`

```bash
make package.image.build.qemu TARGET=ubuntu-24.04-minimal-amd64 RELEASE_VERSION=dev
```

By default this writes artifacts under `artifacts/image-build/`.

The `qemu` target now removes any previous per-target output directory before invoking Packer so reruns do not require manual cleanup.

On GitHub-hosted runners you should set `QEMU_ACCELERATOR=none`. A KVM-backed self-hosted runner can override that with `QEMU_ACCELERATOR=kvm`.

## Build Cloud Images

```bash
make package.image.build.aws TARGET=ubuntu-24.04-minimal-amd64 RELEASE_VERSION=v0.1.0
make package.image.build.azure TARGET=ubuntu-24.04-minimal-amd64 RELEASE_VERSION=v0.1.0
make package.image.build.gcp TARGET=ubuntu-24.04-minimal-amd64 RELEASE_VERSION=v0.1.0
```

Cloud builds require the usual provider credentials for Packer.
These provider build targets are manual/optional build workflows and are not the canonical automated distribution path for published Ubuntu 24.04 appliance releases.

## Release Metadata

Generate a release-manifest skeleton for a built target:

```bash
make package.image.release-manifest TARGET=ubuntu-24.04-minimal-amd64 RELEASE_VERSION=v0.1.0
```

Prepare GitHub-safe release assets from an existing local qemu build:

```bash
make package.image.release-assets TARGET=ubuntu-24.04-minimal-amd64 RELEASE_VERSION=v0.1.0
```

Distribution contract for Ubuntu 24.04 appliance images:

- GitHub Releases is the canonical distribution channel for Ubuntu 24.04 appliance images.
- The published release artifacts are intended for manual import into AWS, Azure, and GCP.
- Provider-native image publication is not automated in this phase.

This creates `artifacts/image-build/github-release/<target>/` with:

- split compressed `qcow2` parts below the per-file GitHub Release limit
- `restore-qcow2.sh`
- `SHA256SUMS`
- `manifest.json`
- `linkage.json`
- `packer-manifest.json`
- image and rootfs SBOMs
- a compressed `rootfs` archive
- the source bundle used for the build
- `release-notes.md`

## Manual GitHub Release Workflow

The repository now includes a manual-only workflow at `.github/workflows/image-release.yml`.

In this phase, it follows the same Ubuntu 24.04 distribution contract documented above in [Release Metadata](#release-metadata).

It is intentionally not triggered on push or merge. Use GitHub Actions `workflow_dispatch` with:

- `release_version`, for example `v0.1.0`
- `target`, `ubuntu-24.04-minimal-amd64`
- `draft` / `prerelease`
- `runner`, default `ubuntu-latest`
- `qemu_accelerator`, default `none`

The workflow:

1. validates the Packer/image configuration
2. builds and caches the release binary, UI, and vendored DPDK on the host runner
3. builds the qemu image and reuses those prebuilt artifacts inside the guest when enabled
4. packages GitHub-safe release assets
5. creates or updates the GitHub Release for the requested tag

This host-prebuild path exists to avoid compiling DPDK and the Rust workspace inside a software-emulated guest on GitHub-hosted runners. Local builds still default to the original in-guest compile path unless `USE_PREBUILT_ARTIFACTS=true` is passed to `make package.image.build.qemu`.

## Current Artifact Sizes

From the current local Ubuntu 24.04 qemu build:

- raw `qcow2`: `8.6G` (`9169534976` bytes)
- staged `rootfs/`: `380M`
- image SPDX SBOM: `67M`
- image CycloneDX SBOM: `31M`
- rootfs SPDX SBOM: `68K`
- rootfs CycloneDX SBOM: `442` bytes
- `linkage.json`: `1819` bytes
- `packer-manifest.json`: `436` bytes

## Runtime Bootstrap Model

The baked image is not tied to fixed interface names or DNS values at image-build time.

At service start:

- `neuwerk-bootstrap` detects the cloud provider from metadata when possible
- management and dataplane interfaces are derived from `mgmt0`/`data0` when present, otherwise from the system routing view
- Azure dataplane selection prefers `mac:<addr>` selectors so the runtime can map MANA/NetVSC correctly
- DNS target IPs default to the management IPv4 address
- DNS upstreams default to non-loopback resolvers from `/etc/resolv.conf`
- `/etc/neuwerk/neuwerk.env` is regenerated from `/etc/neuwerk/appliance.env`

Operator overrides belong in `/etc/neuwerk/appliance.env`. Use `NEUWERK_BOOTSTRAP_*` keys for derived runtime settings and plain `NEUWERK_*` keys for advanced passthrough runtime variables.

## Hardening

The image currently applies an open/custom CIS-oriented baseline through local Ansible during the Packer build. The current role covers:

- login defaults and password quality policy
- faillock policy
- SSH daemon hardening
- sysctl hardening
- audit rules for critical system and Neuwerk files
- account database permissions
- packaged CIS waiver installation under `/var/lib/neuwerk/compliance/cis-waivers.txt`

This is a practical baseline, not a claim of complete CIS Level 2 coverage. Remaining controls that conflict with cloud-init, DHCP, or appliance runtime expectations should continue to be tracked as explicit waivers or follow-up work.

## SBOMs

The build currently emits two SBOM layers when `syft` is available in the guest:

- rootfs SBOMs from the staged runtime tree:
  - `<target>-rootfs.spdx.json`
  - `<target>-rootfs.cyclonedx.json`
- image SBOMs from the hardened guest filesystem:
  - `<target>-image.spdx.json`
  - `<target>-image.cyclonedx.json`

These are downloaded back to `artifacts/image-build/release/<target>/` by the Packer file provisioner.

## Notes

- The image target pins vendored DPDK `23.11.2` and expects ABI `.so.24`.
- Existing cloud test stacks can now accept Neuwerk-specific custom image IDs while the old binary-upload bootstrap path remains available during migration.
- The release workflow currently publishes the `qcow2` as a compressed multi-part archive so the artifact can stay inside GitHub Release per-file limits.
