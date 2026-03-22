# Terraform Provider Registry Publication

Public Terraform Registry publication uses a two-repository model:

- `firewall` stays the development repository
- `moolen/terraform-provider-neuwerk` becomes the public provider release-source repository

The public repository exists to satisfy Terraform Registry publication requirements. Provider code,
tests, and docs still originate in this monorepo and are exported into the public repository.

## Prerequisites

Before creating the public repository:

- commit the Apache 2.0 `LICENSE` in this monorepo
- create the public GitHub repository `moolen/terraform-provider-neuwerk`
- configure these repository secrets in that public repository:
  - `TERRAFORM_PROVIDER_GPG_PRIVATE_KEY`
  - `TERRAFORM_PROVIDER_GPG_PASSPHRASE`
  - `TERRAFORM_PROVIDER_GPG_KEY_ID`

Unsigned provider releases are intentionally unsupported.

## Bootstrap The Public Repository

Export the provider release-source tree from this monorepo:

```bash
make package.terraform-provider.release-source OUTPUT_DIR=/tmp/terraform-provider-neuwerk
```

Push that exported tree to the public repository:

```bash
cd /tmp/terraform-provider-neuwerk
git init
git remote add origin git@github.com:moolen/terraform-provider-neuwerk.git
git checkout -b main
git add .
git commit -m "release-source: sync from firewall"
git push -u origin main
```

That public repository should stay a release-source mirror. Functional provider changes should land
in `firewall` first, then be re-exported and pushed.

## Publish A Provider Release

1. export a fresh release-source tree from this monorepo
2. push the updated tree to `moolen/terraform-provider-neuwerk`
3. run the public repository workflow `.github/workflows/release.yml`
4. provide a tag such as `v0.1.0`

The public repository workflow builds signed provider archives, publishes `SHA256SUMS`, and uploads
the detached checksum signature. It uses the same provider source address:

- `moolen/neuwerk`

## Registry Onboarding

Registry onboarding starts only after:

- the public repository exists
- signed provider releases are being published from that repository
- the repository name and release layout are stable

Treat GitHub Releases and Registry publication as separate concerns:

- GitHub Releases provides the signed provider artifacts
- Terraform Registry provides provider discovery and installation metadata
