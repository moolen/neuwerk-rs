# Terraform Provider Release

This repository is the packaging and contract-validation source of truth for the Terraform provider.
The public release artifacts are published from `moolen/terraform-provider-neuwerk`, while the
provider source address remains `moolen/neuwerk`.

Related provider docs:

- `terraform-provider-neuwerk/docs/index.md`
- `terraform-provider-neuwerk/docs/provider.md`
- `docs/operations/terraform-provider-registry-publication.md`

## Release Model

- `firewall` is the development repository
- `moolen/terraform-provider-neuwerk` is the public release-source repository
- GitHub Releases in the public repository are the supported distribution channel
- Terraform Registry onboarding is separate and does not change the provider source address

## Prerequisites

Configure these repository secrets before attempting a signed provider release:

- `TERRAFORM_PROVIDER_GPG_PRIVATE_KEY`
- `TERRAFORM_PROVIDER_GPG_PASSPHRASE`
- `TERRAFORM_PROVIDER_GPG_KEY_ID`

Unsigned provider releases are intentionally unsupported. The workflow fails before publication if
any signing secret is missing.

Current signing fingerprint:

- `DC34EB84D498D1445B68CB405E6B936CF37928C3`

## What The Workflow Verifies

Before uploading release artifacts, `.github/workflows/terraform-provider-release.yml`:

1. checks that the signing secrets are configured
2. runs `go test ./... -count=1` in `terraform-provider-neuwerk/`
3. runs the Rust Terraform provider contract suite
4. builds signed provider archives for the supported platforms
5. emits Registry-compatible checksum artifacts

Pull requests also exercise the signed packaging path with an ephemeral GPG key so the release
contract stays current before merge.

## Published Assets

The workflow uploads only the Terraform Registry-compatible release assets:

- `terraform-provider-neuwerk_<version>_darwin_amd64.zip`
- `terraform-provider-neuwerk_<version>_darwin_arm64.zip`
- `terraform-provider-neuwerk_<version>_linux_amd64.zip`
- `terraform-provider-neuwerk_<version>_linux_arm64.zip`
- `terraform-provider-neuwerk_<version>_windows_amd64.zip`
- `terraform-provider-neuwerk_<version>_SHA256SUMS`
- `terraform-provider-neuwerk_<version>_SHA256SUMS.sig`

Do not attach extra release assets such as release notes files or the armored public key. Terraform
Registry expects only the provider archives plus the checksum files.

The armored public signing key remains tracked in the repository root as
`terraform-provider-neuwerk-signing-key.asc` and should be configured in Terraform Registry
settings rather than uploaded as a GitHub Release asset.

## Release Checklist

1. Verify the provider docs and release docs are up to date in this monorepo.
2. Run `go test ./... -count=1` in `terraform-provider-neuwerk/`.
3. Sync the public release-source repository from this monorepo.
4. Trigger the public repository release workflow with the target tag.
5. Inspect the resulting GitHub Release asset list to confirm the expected archives, checksum file,
   and checksum signature are present.

## Workflow Inputs

Run the workflow manually with:

- `release_version`
  Tag such as `v0.1.3`
- `draft`
  Whether to keep the GitHub Release in draft state
- `prerelease`
  Whether to mark the GitHub Release as a prerelease
- `runner`
  GitHub Actions runner label, default `ubuntu-24.04`

If the tag does not already exist as a GitHub Release, the workflow creates it. If the release
already exists, the workflow refreshes the provider assets in place and preserves the existing
release notes body.
