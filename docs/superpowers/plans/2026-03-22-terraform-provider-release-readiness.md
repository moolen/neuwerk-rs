# Terraform Provider Release Readiness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Terraform provider release path registry-ready from the monorepo by switching to `neuwerk/neuwerk`, adding a hard signing gate, producing signed checksum artifacts, and adding provider-facing install/reference docs.

**Architecture:** Keep the existing monorepo release workflow and custom provider asset builder, but harden the provider-specific contract around it. Treat signing as a required release input, migrate all provider source references to `neuwerk/neuwerk`, and add a minimal first-party docs tree under `terraform-provider-neuwerk/docs/` for registry/manual install readiness.

**Tech Stack:** Go provider entrypoint, Rust Terraform contract harness, GitHub Actions, Bash release scripts, Markdown docs

---

## File Map

- Modify: `terraform-provider-neuwerk/main.go`
  Responsibility: update provider registry address to `registry.terraform.io/neuwerk/neuwerk`.
- Modify: `terraform-provider-neuwerk/examples/basic/main.tf`
  Responsibility: update required provider source address.
- Modify: `tests/terraform_provider_e2e.rs`
  Responsibility: update local mirror path and install config from `moolen/neuwerk` to `neuwerk/neuwerk`.
- Modify: `packaging/scripts/build_terraform_provider_release_assets.sh`
  Responsibility: require GPG inputs, sign the generated SHA256SUMS file, and fail hard if signing prerequisites are absent.
- Modify: `.github/workflows/image-release.yml`
  Responsibility: add signing-env checks, pass signing inputs to the provider release asset build step, and keep release blocked until signing is configured.
- Create: `terraform-provider-neuwerk/docs/index.md`
  Responsibility: top-level provider docs entry with install guidance and links.
- Create: `terraform-provider-neuwerk/docs/provider.md`
  Responsibility: provider configuration, `neuwerk/neuwerk` source address, and manual-install guidance from GitHub Releases.
- Create: `terraform-provider-neuwerk/docs/resources/*.md`
  Responsibility: concise resource references covering arguments, computed fields, import IDs, and secret lifecycle notes.
- Modify: `terraform-provider-neuwerk/README.md`
  Responsibility: align provider source address and link to the new docs tree.
- Modify: `www/src/content/docs/interfaces/terraform-provider.mdx`
  Responsibility: align public docs with `neuwerk/neuwerk` source and release/install story.

### Task 1: Migrate The Provider Source Address

**Files:**
- Modify: `terraform-provider-neuwerk/main.go`
- Modify: `terraform-provider-neuwerk/examples/basic/main.tf`
- Modify: `tests/terraform_provider_e2e.rs`
- Modify: `terraform-provider-neuwerk/README.md`
- Modify: `www/src/content/docs/interfaces/terraform-provider.mdx`

- [ ] **Step 1: Add failing address checks**

Add or update targeted tests in `tests/terraform_provider_e2e.rs` so the local Terraform mirror points at:

- `registry.terraform.io/neuwerk/neuwerk`

and no longer references `moolen/neuwerk`.

- [ ] **Step 2: Run the targeted contract test and confirm failure**

Run:

```bash
cargo test --test terraform_provider_e2e terraform_provider_golden_contract_suite -- --test-threads=1
```

Expected: FAIL until the provider source/address references are updated consistently.

- [ ] **Step 3: Update provider address references**

Change:

- `providerserver.ServeOpts.Address`
- Terraform example `required_providers`
- contract-test local mirror include/exclude strings
- README and website references that show the provider source

- [ ] **Step 4: Re-run the targeted contract test**

Run:

```bash
cargo test --test terraform_provider_e2e terraform_provider_golden_contract_suite -- --test-threads=1
```

Expected: PASS.

### Task 2: Add A Hard Signing Gate And Signed Checksum Artifact

**Files:**
- Modify: `packaging/scripts/build_terraform_provider_release_assets.sh`
- Modify: `.github/workflows/image-release.yml`

- [ ] **Step 1: Add a failing script-level signing check**

Update `build_terraform_provider_release_assets.sh` so it expects:

- `GPG_PRIVATE_KEY`
- `GPG_PASSPHRASE`
- `GPG_KEY_ID`

and fails with a clear error if any are missing.

- [ ] **Step 2: Add a failing workflow-level preflight**

Update `.github/workflows/image-release.yml` with a preflight step that fails before release publication if the signing secrets are not configured.

- [ ] **Step 3: Implement checksum signing**

After generating `terraform-provider-neuwerk_<version>_SHA256SUMS`, import the armored private key into a temporary keyring and produce:

- `terraform-provider-neuwerk_<version>_SHA256SUMS.sig`

Use detached binary signing and fail if the signature file is not created.

- [ ] **Step 4: Pass signing inputs from the workflow**

Wire the release workflow to export the signing secrets into the provider asset build step.

- [ ] **Step 5: Verify the script contract locally without secrets**

Run:

```bash
bash packaging/scripts/build_terraform_provider_release_assets.sh --release-version v0.1.0 --output-dir /tmp/neuwerk-provider-test
```

Expected: FAIL with a clear signing-prerequisite error.

### Task 3: Add Minimal Provider Docs Tree For Registry/Manual Install Readiness

**Files:**
- Create: `terraform-provider-neuwerk/docs/index.md`
- Create: `terraform-provider-neuwerk/docs/provider.md`
- Create: `terraform-provider-neuwerk/docs/resources/policy.md`
- Create: `terraform-provider-neuwerk/docs/resources/kubernetes_integration.md`
- Create: `terraform-provider-neuwerk/docs/resources/tls_intercept_ca.md`
- Create: `terraform-provider-neuwerk/docs/resources/service_account.md`
- Create: `terraform-provider-neuwerk/docs/resources/service_account_token.md`
- Create: `terraform-provider-neuwerk/docs/resources/sso_provider_google.md`
- Create: `terraform-provider-neuwerk/docs/resources/sso_provider_github.md`
- Create: `terraform-provider-neuwerk/docs/resources/sso_provider_generic_oidc.md`
- Modify: `terraform-provider-neuwerk/README.md`

- [ ] **Step 1: Add provider docs index and install guidance**

Write concise docs that cover:

- provider source `neuwerk/neuwerk`
- GitHub Releases manual-install path
- signed checksum verification expectation
- pointer to the per-resource docs

- [ ] **Step 2: Add concise resource reference docs**

Each resource doc should cover:

- resource purpose
- key arguments
- computed/read-only fields
- import identifier
- secret lifecycle caveats where relevant

- [ ] **Step 3: Align README with the docs tree**

Keep the README minimal, but update it to:

- use `neuwerk/neuwerk`
- point readers to `terraform-provider-neuwerk/docs/`

### Task 4: Final Verification

**Files:**
- Modify: all files above

- [ ] **Step 1: Run provider unit tests**

Run:

```bash
cd terraform-provider-neuwerk
go test ./... -count=1
```

Expected: PASS.

- [ ] **Step 2: Run the Terraform contract suite**

Run:

```bash
cargo test --test terraform_provider_e2e -- --test-threads=1
```

Expected: PASS.

- [ ] **Step 3: Run docs build verification**

Run:

```bash
npm --prefix www run build
```

Expected: PASS.

- [ ] **Step 4: Run diff hygiene verification**

Run:

```bash
git diff --check
```

Expected: no output.
