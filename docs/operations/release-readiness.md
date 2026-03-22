# Release Readiness

This page tracks the current OSS launch surface for Neuwerk.

## Ready

- Apache 2.0 license is present in the repository root.
- Appliance image releases are published through GitHub Releases with signed `SHA256SUMS`, a published public key, release notes, SBOMs, provenance metadata, and CI coverage for the release asset contract.
- Terraform provider release assets are published as signed GitHub Releases from `moolen/terraform-provider-neuwerk`.
- CI verifies the Terraform provider release-source export and the appliance release packaging contract on pull requests.
- Operator-facing docs exist for appliance image distribution and Terraform provider release/publication flow.

## Pending

- Public Terraform Registry onboarding for `moolen/neuwerk` is still manual and not complete.
- The appliance image release workflow requires `RELEASE_GPG_PRIVATE_KEY`, `RELEASE_GPG_PASSPHRASE`, and `RELEASE_GPG_KEY_ID` before the first signed image release can be published from GitHub Actions.

## Repository Surface

- Security contact: [`SECURITY.md`](../../SECURITY.md)
- Contribution guide: [`CONTRIBUTING.md`](../../CONTRIBUTING.md)
- Appliance release docs: [`docs/operations/appliance-image-usage.md`](./appliance-image-usage.md), [`docs/operations/image-build.md`](./image-build.md)
- Terraform provider release docs: [`docs/operations/terraform-provider-release.md`](./terraform-provider-release.md), [`docs/operations/terraform-provider-registry-publication.md`](./terraform-provider-registry-publication.md)
