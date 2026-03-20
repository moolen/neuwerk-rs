# Neuwerk Minimal-Only Appliance Target Design

Date: 2026-03-20

## Summary

Neuwerk will stop supporting the standard Ubuntu 24.04 appliance target and will
exclusively target `ubuntu-24.04-minimal-amd64` for appliance packaging,
documentation, defaults, and release workflows.

This change removes the full Ubuntu target manifest, scrubs support-signaling
references to it, makes the minimal target the only documented and releaseable
appliance target, and verifies the result by dispatching the real GitHub Actions
image release workflow for `v0.2.1` as a normal release.

## Goals

- Make `ubuntu-24.04-minimal-amd64` the only supported Ubuntu appliance target.
- Delete the legacy `ubuntu-24.04-amd64` target manifest.
- Change repo defaults, docs, and release workflow inputs so they no longer point to
  the full Ubuntu target.
- Update Vagrant-adjacent docs and packaging paths so minimal is the supported
  appliance base, not merely a preference.
- Verify the final state by running the real `Image Release` GitHub Actions workflow
  for `release_version=v0.2.1` as a normal release against the minimal target.

## Non-Goals

- Introducing a new target beyond `ubuntu-24.04-minimal-amd64`.
- Changing the existing Ubuntu 24.04 / vendored DPDK runtime contract.
- Changing the published release artifact structure beyond what is needed to remove
  the full target.
- Adding provider-native image publication.
- Cleaning up unrelated user changes, test artifacts, or unrelated docs.

## Decision

Neuwerk will treat `ubuntu-24.04-minimal-amd64` as the sole appliance target.

This means:

- the full Ubuntu target manifest is removed from `packaging/targets/`
- packaging defaults switch to the minimal target
- the manual GitHub release workflow exposes only the minimal target
- build-facing and operator-facing documentation describe only the minimal target
- Vagrant/local-demo wording treats minimal as the supported appliance base
- the final validation includes a real GitHub Actions release workflow run for
  `v0.2.1`

## Scope

### Remove

- `packaging/targets/ubuntu-24.04-amd64.json`

### Update defaults and support surface

- `Makefile` default target
- `.github/workflows/image-release.yml` default target and allowed target options
- packaging helper text and examples that still name `ubuntu-24.04-amd64`
- build docs, operator docs, and local-demo/Vagrant-adjacent docs
- internal `docs/superpowers/` specs and plans added in the prior distribution work
  where they still reference the full target as supported

### Keep

- `ubuntu-24.04-minimal-amd64` target manifest
- existing qemu build path
- optional Vagrant asset generation for the minimal target
- existing release asset contract
- existing runtime/bootstrap model

## Expected Repository Changes

### Packaging and defaults

- `TARGET ?=` in `Makefile` changes to `ubuntu-24.04-minimal-amd64`
- helper text that says “for example ubuntu-24.04-amd64” changes to the minimal
  target
- schema/validation continues to work with only the minimal target manifest present

### Workflow

The manual image release workflow changes so:

- `target` defaults to `ubuntu-24.04-minimal-amd64`
- `target` options only include `ubuntu-24.04-minimal-amd64`
- wording remains appliance-oriented
- the workflow still builds qemu artifacts, optional Vagrant assets, and publishes a
  GitHub Release from generated `release-notes.md`

### Documentation

All operator/build docs should describe only the minimal target:

- `docs/operations/image-build.md`
- `docs/operations/appliance-image-usage.md`
- `docs/operations/local-vm-demo.md`

Where the docs previously described minimal as preferred or optional, they should now
describe it as the supported appliance base.

### Internal superpowers docs

The internal design/plan docs created during the prior appliance-distribution change
should be scrubbed so they do not keep stale references to `ubuntu-24.04-amd64` as a
supported or default target.

## Release Verification

Verification has two layers.

### Local validation before release

Before dispatching the hosted workflow:

- validate target/schema state
- validate packer/image syntax
- regenerate release assets for `ubuntu-24.04-minimal-amd64`
- verify docs and workflow wording for the minimal-only target model

### Real hosted workflow run

Dispatch the actual GitHub Actions `Image Release` workflow with:

- `release_version=v0.2.1`
- `target=ubuntu-24.04-minimal-amd64`
- `draft=false`
- `prerelease=false`

This is a normal published release run, not a draft or prerelease.

For this design, `v0.2.1` is treated as the new release version created by this
change set. At design time, there is no existing GitHub Release or remote Git tag for
`v0.2.1`, so this version is available for the verification run.

The hosted workflow dispatch is expected to be triggered from this implementation
session using the already-authenticated GitHub CLI credentials that have `repo` and
`workflow` scope.

## Risks and Mitigations

### Risk: stale references to the removed full target remain in the repo

Mitigation:
perform a repo-wide search for `ubuntu-24.04-amd64` and scrub support-signaling
references, including internal `docs/superpowers/` docs.

### Risk: workflow UI still exposes the removed target

Mitigation:
remove the full target from workflow defaults and options, not just from docs.

### Risk: Vagrant/local-demo docs drift from the new support policy

Mitigation:
update local-demo/Vagrant-adjacent wording in the same change set.

### Risk: the hosted release workflow fails after target removal

Mitigation:
run local validation first, then treat the real hosted workflow run as the final proof
point. If it fails, fix the repo and rerun.

### Risk: real release verification publishes an incorrect release

Mitigation:
ensure the workflow is updated first and use the intended final target and release
settings before dispatch.

## Validation Expectations

The change is complete only when:

- `ubuntu-24.04-amd64.json` is removed
- local/default target selection points only to `ubuntu-24.04-minimal-amd64`
- docs and workflow no longer advertise the full target
- local packaging validation passes for the minimal target
- a real `v0.2.1` GitHub Actions image release run is successfully dispatched and
  completes for `ubuntu-24.04-minimal-amd64`

## Open Questions Resolved

- Support policy:
  remove the full target entirely, not just deprecate it
- Release verification:
  use the real GitHub Actions release workflow, not a local simulation
- Release type:
  publish `v0.2.1` as a normal release, not a draft or prerelease
