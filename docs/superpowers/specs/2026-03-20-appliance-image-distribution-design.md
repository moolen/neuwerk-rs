# Neuwerk Appliance Image Distribution Design

Date: 2026-03-20

## Summary

Neuwerk will distribute appliance images for Ubuntu 24.04 through GitHub Releases.
The release artifact remains the existing `qemu`-built appliance image, with operators
responsible for importing or converting it for their target cloud platform.

This design keeps the current packaging model intact and makes it operator-facing:

- GitHub Releases becomes the canonical distribution channel.
- Ubuntu 24.04 is the only supported appliance base in this phase.
- AWS, Azure, and GCP are supported as manual import targets.
- Provider-native publication is deferred.
- The release workflow and release artifacts are updated to read as a supported
  appliance distribution pipeline rather than an internal build pipeline.

## Goals

- Define a clear appliance-image distribution model for Neuwerk.
- Keep the current `qcow2`-based image build path and reuse the existing packaging
  pipeline.
- Add concrete operator documentation for importing and using the appliance on AWS,
  Azure, and GCP.
- Update the GitHub Actions image release workflow so the published assets and release
  notes match the supported appliance distribution contract.
- Keep future LTS expansion possible without redesigning the release model.

## Non-Goals

- Publishing AMIs, Azure gallery images, Azure managed images, or GCP image families
  directly from CI.
- Supporting Ubuntu 22.04 in this phase.
- Designing a `.deb` or APT repository distribution path.
- Automating Terraform-based image import flows for cloud users.
- Changing the existing Neuwerk runtime contract, DPDK vendoring model, or service
  bootstrap model.

## Current State

The repository already has an image-oriented packaging model:

- Ubuntu 24.04 image targets exist for standard and minimal variants.
- The image build stages a Neuwerk runtime tree under `/opt/neuwerk`, including the
  release binary, UI assets, vendored DPDK runtime, bootstrap scripts, and systemd
  unit.
- A manual GitHub Actions workflow builds a `qemu` appliance image, optional Vagrant
  assets, release metadata, and GitHub release assets.
- Existing operator-facing image documentation is mostly build-oriented rather than
  usage-oriented.

The gap is not the build capability. The gap is the absence of an explicit supported
distribution contract for operators who want to consume Neuwerk as an appliance image.

## Decision

Neuwerk will use an artifact-first appliance distribution model.

For each release:

- GitHub Releases is the canonical distribution surface.
- The primary distribution artifact is the Ubuntu 24.04 appliance image produced from
  the existing `qemu` build pipeline.
- Operators import or convert that release artifact into AWS, Azure, or GCP using the
  manual image-import path supported by each provider.
- Neuwerk documentation treats those platforms as supported import targets, not as
  natively published image catalogs.

This is intentionally conservative. It minimizes changes to the current packaging
pipeline while creating a clear user-facing support model.

## Supported Matrix

### Supported in this phase

- Appliance base OS: Ubuntu 24.04 LTS
- Distribution channel: GitHub Releases
- Import targets:
  - AWS
  - Azure
  - GCP
- Local/lab target:
  - Vagrant box for `ubuntu-24.04-minimal-amd64`

### Deferred

- Future Ubuntu LTS appliance variants
- Provider-native image publication
- Auto-import workflows

Future LTS images should fit the same overall release model: release artifacts remain
the source of truth, while the supported appliance matrix expands by target manifest.

## Release Artifact Contract

Each appliance release must publish a stable, operator-facing artifact set.

### Required artifacts

- appliance image artifact from the existing `qemu` build
- `restore-qcow2.sh`
- `SHA256SUMS`
- release manifest
- Packer manifest
- provenance/source bundle
- image and rootfs SBOMs
- release notes

### Optional artifacts

- Vagrant `.box`
- Vagrant metadata for the minimal target

### Contract wording

Release notes and manifest data must describe the image as:

- a Neuwerk Ubuntu 24.04 appliance image
- intended for operator import into supported clouds
- built with the existing vendored runtime contract
- not published as a provider-native image catalog entry

The artifact set should remain stable across releases so operators can script against it.

## Documentation Changes

Add a new operator-facing appliance usage guide under `docs/operations/`.

### Purpose

Document the supported path after an operator downloads a release asset.

### Scope

The guide should cover:

- which release artifacts to download
- how to verify checksums
- how to restore the appliance image if split/compressed
- how to import or convert the image for AWS, Azure, and GCP
- the first-boot expectations for the appliance
- how to configure `/etc/neuwerk/appliance.env`
- how to start and verify `neuwerk.service`
- how to troubleshoot common startup and configuration problems

### Platform sections

Each platform section should document a manual operator path:

- AWS:
  import the release image into an AWS-usable image flow and instantiate from the
  imported image
- Azure:
  upload the release image and create an Azure image resource from it
- GCP:
  create a custom GCP image from the release artifact and instantiate from it

The guide should be concrete and task-oriented, but it does not need to provide an
automated Terraform workflow in this phase.

### Relationship to existing docs

- `docs/operations/image-build.md` remains build-facing.
- The new appliance guide becomes usage-facing.
- Existing image-build docs should link to the usage guide where appropriate.

## Workflow Changes

Update `.github/workflows/image-release.yml` so it behaves as an appliance distribution
workflow rather than only an internal image build workflow.

### Required changes

- Keep `workflow_dispatch` as the trigger model.
- Keep the current Ubuntu 24.04 target set.
- Keep the existing `qemu` build path and optional Vagrant asset generation.
- Generate release metadata that matches the appliance distribution contract.
- Ensure release notes clearly state:
  - Ubuntu 24.04 is the supported appliance base
  - AWS, Azure, and GCP are supported manual import targets
  - provider-native publication is not yet automated
- Ensure the uploaded GitHub Release asset set is intentional and stable.
- Rename or reframe workflow steps where needed so the pipeline reads as an appliance
  release pipeline.

### Explicit non-changes

- No cloud credentials added for provider image publication
- No direct AMI/gallery/image-family publication logic
- No cloud import execution in GitHub Actions

## Implementation Shape

The implementation is expected to stay within three areas:

### 1. Documentation

- add the new appliance usage guide
- update image-build documentation to point to the operator guide

### 2. Release workflow

- update the image release workflow step framing and release-note generation
- add or refine release-manifest generation if needed so it reflects the supported
  import-oriented contract

### 3. Release metadata content

- make the release output self-describing for operators
- keep the artifact names and release structure predictable

This scope should remain small enough for a single implementation plan.

## Risks and Mitigations

### Risk: operators misunderstand import support as native publication

Mitigation:
state the support model explicitly in the new guide and in release notes.

### Risk: release assets are technically complete but operationally unclear

Mitigation:
make the usage guide concrete and task-oriented, and align release-note wording with it.

### Risk: workflow changes imply support for platforms beyond Ubuntu 24.04

Mitigation:
keep all wording explicit that only Ubuntu 24.04 is supported in this phase.

### Risk: future LTS additions require rework

Mitigation:
frame the design around a target-manifest-driven appliance matrix so later LTS images
extend the model instead of replacing it.

## Validation Expectations

Before considering the implementation complete:

- the new usage guide exists and is linked from the relevant existing docs
- the image release workflow clearly produces appliance distribution assets
- release notes or release metadata communicate the supported import model
- the design remains limited to Ubuntu 24.04 and manual cloud import

## Open Questions Resolved

- Distribution model:
  keep the current artifact-first approach and let operators convert/import for their
  target platform
- OS support:
  Ubuntu 24.04 only for now
- Future expansion:
  add future Ubuntu LTS appliance images later within the same distribution model
