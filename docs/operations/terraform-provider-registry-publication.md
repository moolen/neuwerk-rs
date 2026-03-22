# Terraform Provider Registry Publication

Public Terraform Registry publication uses a two-repository model:

- `firewall` remains the development repository
- `moolen/terraform-provider-neuwerk` is the public release-source repository

Provider code, tests, and docs originate in this monorepo and are exported into the public
repository for release and Registry ingestion. The provider source address stays `moolen/neuwerk`.

## Prerequisites

Before onboarding the provider in Terraform Registry:

- keep the Apache 2.0 `LICENSE` committed in this monorepo
- keep the public repository `moolen/terraform-provider-neuwerk` in sync with the exported
  release-source tree
- configure these repository secrets in the public repository:
  - `TERRAFORM_PROVIDER_GPG_PRIVATE_KEY`
  - `TERRAFORM_PROVIDER_GPG_PASSPHRASE`
  - `TERRAFORM_PROVIDER_GPG_KEY_ID`
- keep the armored public signing key in the public repository root as
  `terraform-provider-neuwerk-signing-key.asc`

Unsigned provider releases are intentionally unsupported.

## Sync The Public Repository

Export and sync the public release-source tree from this monorepo:

```bash
bash packaging/scripts/sync_terraform_provider_release_source.sh \
  --repo-dir "$HOME/src/terraform-provider-neuwerk" \
  --push
```

If you need to bootstrap a fresh clone first:

```bash
bash packaging/scripts/sync_terraform_provider_release_source.sh \
  --repo-dir "$HOME/src/terraform-provider-neuwerk" \
  --remote-url git@github.com:moolen/terraform-provider-neuwerk.git \
  --push
```

That script exports the release-source tree, replaces the public repository contents, creates a
`release-source: sync from firewall` commit when changes are present, and optionally pushes it.

## Release Requirements

Each public GitHub Release must contain only:

- the supported platform archives
- `terraform-provider-neuwerk_<version>_SHA256SUMS`
- `terraform-provider-neuwerk_<version>_SHA256SUMS.sig`

Terraform Registry uses those filenames to ingest a provider release. Extra release assets can
cause Registry parsing failures.

The public signing key should be configured in Terraform Registry signing-key settings, not
attached to the GitHub Release.

Current signing fingerprint:

- `DC34EB84D498D1445B68CB405E6B936CF37928C3`

## Publish A Provider Release

1. Sync the public release-source repository from this monorepo.
2. Trigger `.github/workflows/release.yml` in `moolen/terraform-provider-neuwerk`.
3. Supply the release tag, such as `v0.1.3`.
4. Verify the resulting asset list matches the Registry-compatible filenames.

The public repository workflow builds signed provider archives, publishes `SHA256SUMS`, and uploads
the detached checksum signature for the same provider source address:

- `moolen/neuwerk`

## Registry Onboarding

Registry onboarding is a one-time manual step after the public repository and signed releases are
stable:

1. Sign in to Terraform Registry with the GitHub account that owns
   `moolen/terraform-provider-neuwerk`.
2. Add `terraform-provider-neuwerk-signing-key.asc` under Registry signing keys.
3. Open `Publish -> Provider`.
4. Choose namespace `moolen`.
5. Choose repository `terraform-provider-neuwerk`.
6. Confirm publication.

That flow installs the Registry webhook on the GitHub repository. Future GitHub Releases in the
public repository should then be ingested automatically as long as the asset contract stays stable.

## Status Check

The quickest Registry status check is:

```bash
curl -fsSL https://registry.terraform.io/v1/providers/moolen/neuwerk
```

If that returns `404`, Registry onboarding has not happened yet or Registry has not ingested the
release metadata.
