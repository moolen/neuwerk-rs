# Terraform Identity Contract Coverage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add end-to-end Terraform contract coverage for service accounts, service-account tokens, and all three SSO provider resources.

**Architecture:** Extend the existing golden-fixture contract harness rather than introducing a second test framework. Add one identity-focused fixture, then add focused HTTP API verification helpers and a single new contract case that covers apply, import, plan-clean, and destroy for the missing identity resources.

**Tech Stack:** Rust test harness, Terraform CLI, Go-built provider binary, Neuwerk HTTP API, golden `.tf.tmpl` fixtures

---

## File Map

- Create: `tests/terraform_provider_golden/identity_resources_importable/main.tf.tmpl`
  Responsibility: define one Terraform fixture that creates the service account, service-account token, and three SSO providers.
- Modify: `tests/terraform_provider_e2e.rs`
  Responsibility: add HTTP verification helpers, add the new identity contract case, and include it in the suite.

### Task 1: Add The Failing Identity Fixture And Contract Case

**Files:**
- Create: `tests/terraform_provider_golden/identity_resources_importable/main.tf.tmpl`
- Modify: `tests/terraform_provider_e2e.rs`

- [ ] **Step 1: Add the new fixture**

Create `tests/terraform_provider_golden/identity_resources_importable/main.tf.tmpl` with:

- provider config using `{{PROVIDER_VERSION}}`, `{{ENDPOINT}}`, `{{TOKEN}}`, and `{{CA_CERT_FILE}}`
- `neuwerk_service_account.identity`
- `neuwerk_service_account_token.identity`
- `neuwerk_sso_provider_google.google`
- `neuwerk_sso_provider_github.github`
- `neuwerk_sso_provider_generic_oidc.oidc`

- [ ] **Step 2: Add the failing contract case**

Add a new `run_identity_resources_import_case()` in `tests/terraform_provider_e2e.rs` that:

- creates a workspace from `identity_resources_importable`
- runs `init`, `apply`, and `expect_plan_clean`
- verifies service-account and SSO state through the HTTP API
- creates a second workspace
- imports all five resources
- runs `apply` and `expect_plan_clean`
- destroys the imported workspace
- verifies service-account and SSO state is gone

- [ ] **Step 3: Wire the new case into the suite**

Call the new case from `terraform_provider_golden_contract_suite()`.

- [ ] **Step 4: Run the targeted contract test and confirm the new case fails**

Run:

```bash
cargo test --test terraform_provider_e2e terraform_provider_golden_contract_suite -- --test-threads=1
```

Expected: FAIL because the new fixture/assertions are incomplete.

### Task 2: Implement API Verification Helpers

**Files:**
- Modify: `tests/terraform_provider_e2e.rs`

- [ ] **Step 1: Add service-account verification helpers**

Add helpers that:

- list `/api/v1/service-accounts`
- find a service account by `name`
- verify expected `role`
- verify absence after destroy

- [ ] **Step 2: Add token verification helpers**

Add helpers that:

- list `/api/v1/service-accounts/{id}/tokens`
- find a token by `name`
- verify expected `role`
- verify `status` is active
- verify absence after destroy

- [ ] **Step 3: Add SSO verification helpers**

Add helpers that:

- list `/api/v1/settings/sso/providers`
- find a provider by `name`
- verify `kind`
- verify `client_secret_configured = true`
- verify explicit Generic OIDC endpoints
- verify absence after destroy

- [ ] **Step 4: Re-run the targeted test and verify it passes**

Run:

```bash
cargo test --test terraform_provider_e2e terraform_provider_golden_contract_suite -- --test-threads=1
```

Expected: PASS.

### Task 3: Final Verification

**Files:**
- Modify: `tests/terraform_provider_e2e.rs`
- Create: `tests/terraform_provider_golden/identity_resources_importable/main.tf.tmpl`

- [ ] **Step 1: Run formatting-sensitive verification**

Run:

```bash
git diff --check
```

Expected: no output.

- [ ] **Step 2: Run the full targeted Terraform provider contract test again**

Run:

```bash
cargo test --test terraform_provider_e2e terraform_provider_golden_contract_suite -- --test-threads=1
```

Expected: PASS.
