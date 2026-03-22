# Terraform Provider Release

This repository keeps the Terraform provider release contract under test with:

- `.github/workflows/terraform-provider-release.yml`

The provider source address is:

- `moolen/neuwerk`

Current publication model:

- public provider releases are published from `moolen/terraform-provider-neuwerk`
- this monorepo workflow remains the packaging and contract-validation source of truth
- public Terraform Registry onboarding remains follow-up work

For the public release-source repository and Registry publication path, see
`docs/operations/terraform-provider-registry-publication.md`.

## Prerequisites

Configure these repository secrets before attempting a provider release:

- `TERRAFORM_PROVIDER_GPG_PRIVATE_KEY`
- `TERRAFORM_PROVIDER_GPG_PASSPHRASE`
- `TERRAFORM_PROVIDER_GPG_KEY_ID`

Unsigned provider releases are intentionally unsupported. The workflow fails before publication if
any signing secret is missing.

## Registry Status

The public release-source repository exists and signed GitHub Releases are live from
`moolen/terraform-provider-neuwerk`. Public Terraform Registry publication is still a separate,
manual onboarding step. Until that happens, treat signed GitHub Releases as the supported
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
- `terraform-provider-neuwerk-signing-key.asc`
- `terraform-provider-neuwerk_<version>_SHA256SUMS`
- `terraform-provider-neuwerk_<version>_SHA256SUMS.sig`

Signing fingerprint:

- `DC34EB84D498D1445B68CB405E6B936CF37928C3`

These assets are attached to the GitHub Release for the requested tag. They are separate from the
appliance image release workflow. Public releases should come from
`moolen/terraform-provider-neuwerk`; this monorepo workflow exists to keep the asset contract
verified and reproducible.
