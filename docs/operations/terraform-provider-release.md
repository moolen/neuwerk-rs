# Terraform Provider Release

This repository publishes the Terraform provider from the monorepo with:

- `.github/workflows/terraform-provider-release.yml`

The provider source address is:

- `neuwerk/neuwerk`

Current publication model:

- signed GitHub Release assets are published from this monorepo
- public Terraform Registry onboarding remains follow-up work

For the public Registry publication path, see `docs/operations/terraform-provider-registry-publication.md`.

## Prerequisites

Configure these repository secrets before attempting a provider release:

- `TERRAFORM_PROVIDER_GPG_PRIVATE_KEY`
- `TERRAFORM_PROVIDER_GPG_PASSPHRASE`
- `TERRAFORM_PROVIDER_GPG_KEY_ID`

Unsigned provider releases are intentionally unsupported. The workflow fails before publication if
any signing secret is missing.

## Registry Status

This monorepo release workflow is enough for signed GitHub Release assets and manual installation.
Public Terraform Registry publication still requires a registry-detectable public repository for
the provider release source. Until that exists, treat GitHub Releases as the supported provider
distribution channel.

## Workflow Inputs

Run the workflow manually with:

- `release_version`
  A tag such as `v0.1.0`
- `draft`
  Whether to keep the GitHub Release in draft state
- `prerelease`
  Whether to mark the GitHub Release as a prerelease
- `runner`
  The GitHub Actions runner label, default `ubuntu-24.04`

If the tag does not already exist as a GitHub Release, the workflow creates it. If the release
already exists, the workflow updates the provider assets in place and does not replace the existing
release notes body.

## What The Workflow Verifies

Before uploading release artifacts, the workflow:

1. checks that the signing secrets are configured
2. runs `go test ./... -count=1` in `terraform-provider-neuwerk/`
3. runs the Rust Terraform provider contract suite
4. builds signed provider archives plus checksum artifacts

CI also exercises the signed packaging path on pull requests with an ephemeral GPG key so the
release packaging contract stays current.

## Published Assets

The workflow uploads:

- platform archives for supported targets
- `terraform-provider-neuwerk_<version>_SHA256SUMS`
- `terraform-provider-neuwerk_<version>_SHA256SUMS.sig`

These assets are attached to the GitHub Release for the requested tag. They are separate from the
appliance image release workflow.
