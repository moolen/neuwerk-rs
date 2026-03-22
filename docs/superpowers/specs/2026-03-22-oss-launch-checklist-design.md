# OSS Launch Checklist Design

## Goal

Add a canonical OSS launch checklist to the docs site and a small repo-side preflight that verifies
the expected public launch surface is present before launch work begins.

## Scope

In scope:

- add a docs-site page for the OSS launch checklist under the bottom `Community` section
- add a small script that verifies the expected repo launch surface
- add test or CI coverage for that preflight

Out of scope:

- creating a changelog
- publishing a release
- completing Terraform Registry onboarding
- configuring missing GitHub secrets

## Design

### Docs Site

Add a new page under:

- `www/src/content/docs/community/launch-checklist.mdx`

That page should be concise and operator-facing. It should cover:

- repository surface
  - `LICENSE`
  - `SECURITY.md`
  - `CONTRIBUTING.md`
- appliance release surface
  - image release workflow
  - release signing public key
  - signed checksum path
  - docs pages for appliance verification
- Terraform provider surface
  - public release-source repository path
  - signed provider release path
  - Registry onboarding still pending
- manual launch blockers
  - appliance signing secrets
  - Terraform Registry publish step

The page should be added to the bottom `Community` sidebar group.

### Repo Preflight

Add a script under `packaging/scripts/` that checks for the presence of:

- `LICENSE`
- `SECURITY.md`
- `CONTRIBUTING.md`
- `docs/operations/release-readiness.md`
- `www/src/content/docs/community/release-process.mdx`
- `www/src/content/docs/community/release-readiness.mdx`
- `www/src/content/docs/community/contributing.mdx`
- `www/src/content/docs/community/security.mdx`
- `www/src/content/docs/community/launch-checklist.mdx`
- `.github/workflows/image-release.yml`
- `.github/workflows/terraform-provider-release.yml`
- `packaging/release-signing/neuwerk-release-signing-key.asc`
- `packaging/scripts/sign_github_release_checksums.sh`

The script should fail with explicit missing-file messages.

### Validation

Add one focused test that executes the preflight script successfully from the repo root.

Add the new `Community` nav entry to the existing docs-site navigation test coverage.

## Success Criteria

- the docs site has a `Community -> Launch Checklist` page
- the repo preflight script passes in the current launch-ready worktree
- CI can execute that preflight without special credentials
- the checklist clearly distinguishes ready surfaces from still-manual launch steps
