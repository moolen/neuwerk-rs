# Appliance Customization Docs Design

## Goal

Add a dedicated how-to page that explains how operators can customize the released Neuwerk appliance
image at first boot, especially by supplying environment variables through
`/etc/neuwerk/appliance.env` and by using cloud-init to install extra packages, files, or helper
scripts.

## Why This Change

The new cloud-first onboarding docs already explain:

- how to import the released image into AWS, Azure, or GCP
- how to write `/etc/neuwerk/appliance.env`
- how to understand cloud rollout integration

What is still missing is explicit guidance for operators who want to customize the released image
without building a bespoke image first. The main use cases are:

- supplying extra `NEUWERK_BOOTSTRAP_*` or `NEUWERK_*` values
- dropping certificates, helper files, or service overrides at first boot
- installing cloud- or environment-specific packages via cloud-init

This belongs in a dedicated how-to page so the quickstart stays focused on first boot and rollout
docs stay focused on lifecycle behavior.

## Audience

Primary audience:

- operators deploying the released image in cloud environments and using cloud-init or equivalent
  startup metadata

Secondary audience:

- operators adapting the released image for internal CA bundles, monitoring agents, bootstrap
  scripts, or environment-specific system packages

## Scope

In scope:

- customizing the released image at first boot
- writing `/etc/neuwerk/appliance.env` through cloud-init
- installing extra packages through cloud-init
- writing additional files or scripts through cloud-init
- documenting safe boundaries around customization

Out of scope:

- rebuilding the Neuwerk image pipeline
- replacing Neuwerk's packaged runtime contract
- provider-specific Terraform walkthroughs
- generic cloud-init documentation

## Proposed Information Architecture

Add one new how-to page:

- `how-to/customize-the-appliance-image-at-first-boot`

Link to it from:

- `tutorials/launch-from-released-cloud-image`
- `architecture/cloud-rollout-integration`
- `docsNavigation.ts` in the How-To Guides section

This keeps:

- getting started focused on import + first boot
- concepts focused on lifecycle model
- customization guidance in one operator-facing task page

## Proposed Page Shape

### Title

`Customize The Appliance Image At First Boot`

### Purpose

Show operators how to use cloud-init or equivalent startup metadata to adapt the released image
without forking the image build immediately.

### Core Sections

1. `When To Customize`
   - explain when `appliance.env` is enough
   - explain when cloud-init file writes are enough
   - explain when package installation is appropriate
   - warn against casually mutating Neuwerk's packaged runtime contract

2. `Customize Runtime Settings`
   - explain `/etc/neuwerk/appliance.env`
   - explain `NEUWERK_BOOTSTRAP_*` vs plain `NEUWERK_*`
   - show a cloud-init `write_files` example
   - show an example of adding integration/runtime pass-through values

3. `Install Extra Packages`
   - show a cloud-init `packages:` example
   - optionally show a `runcmd` example when package install ordering matters
   - explain that extra packages are fine for host integration, CA tooling, or local agents, but
     should not silently replace Neuwerk's shipped runtime assumptions

4. `Add Files, Certificates, Or Scripts`
   - show `write_files` examples for:
     - CA bundles
     - helper scripts
     - service drop-ins or adjacent config
   - explain restart ordering: write files first, then restart `neuwerk.service`

5. `Customization Boundaries`
   - do:
     - add env vars
     - add supporting packages
     - add files and helper scripts
   - avoid:
     - replacing packaged DPDK/runtime libs casually
     - pushing giant opaque shell command lines when declarative config will do
     - mixing first-boot mutation and unmanaged in-place drift across a managed fleet

6. `Related Pages`
   - link back to:
     - `Launch Neuwerk From The Released Cloud Image`
     - `Cloud Rollout Integration`
     - `Requirements`

## Content Direction

The page should be practical and copy-paste friendly.

It should show:

- one concise env-var customization example
- one package-install example
- one file/script customization example

The examples should remain generic enough to work across AWS, Azure, and GCP, because the actual
cloud-init primitives are shared even if the provider-specific metadata plumbing differs.

## Key Guidance To Preserve

The docs should reinforce these points:

- prefer declarative `appliance.env` settings over large one-off command lines
- use `NEUWERK_BOOTSTRAP_*` for intent the bootstrap resolves
- use plain `NEUWERK_*` for direct runtime pass-through
- first-boot customization is different from maintaining long-lived pet VMs
- managed-group fleets should keep customization reproducible through startup metadata

## Files Likely To Change

- `www/src/content/docs/how-to/customize-the-appliance-image-at-first-boot.mdx` (new)
- `www/src/content/docs/tutorials/launch-from-released-cloud-image.mdx`
- `www/src/content/docs/architecture/cloud-rollout-integration.mdx`
- `www/src/data/docsNavigation.ts`
- `www/tests/cloud-onboarding-docs.test.mjs`

## Success Criteria

The change is successful if:

1. A cloud operator can find a dedicated page for appliance customization from the main docs flow.
2. The page clearly explains how to supply env vars through `appliance.env`.
3. The page clearly explains how to install extra packages through cloud-init.
4. The docs preserve a clear boundary between supported runtime customization and unsupported
   ad hoc runtime drift.
5. The quickstart and rollout concept pages point readers to this new how-to instead of trying to
   absorb all customization details themselves.
