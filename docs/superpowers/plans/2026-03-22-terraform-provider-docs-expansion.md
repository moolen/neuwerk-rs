# Terraform Provider Docs Expansion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expand the Neuwerk Terraform provider docs into example-first, field-complete reference pages and ship them in the next public provider release.

**Architecture:** Keep the provider behavior unchanged and raise the docs quality bar entirely in the checked-in markdown surface under `terraform-provider-neuwerk/docs/` plus the matching monorepo release docs. Add a lightweight Go regression test that reads those markdown files directly and enforces the required example/reference/install structure so future schema work cannot silently regress the docs.

**Tech Stack:** Go 1.25 provider tests, Markdown docs, GitHub Actions release workflows, Terraform provider packaging scripts

---

## File Map

- Modify: `terraform-provider-neuwerk/docs/index.md`
  - Expand the landing page into install, quick start, references, and next-step guidance for first-time users.
- Modify: `terraform-provider-neuwerk/docs/provider.md`
  - Convert provider configuration docs into example-first field-level reference docs.
- Modify: `terraform-provider-neuwerk/docs/resources/policy.md`
  - Document the policy resource in detail, including nested blocks and the `document_json` escape hatch.
- Modify: `terraform-provider-neuwerk/docs/resources/kubernetes_integration.md`
  - Add a complete example, argument reference, attribute reference, import, and caveats.
- Modify: `terraform-provider-neuwerk/docs/resources/tls_intercept_ca.md`
  - Document generated and uploaded-CA flows plus replacement and sensitivity caveats.
- Modify: `terraform-provider-neuwerk/docs/resources/service_account.md`
  - Add CRUD-oriented service account docs with example and field-level explanations.
- Modify: `terraform-provider-neuwerk/docs/resources/service_account_token.md`
  - Document token minting, one-time secret handling, replacement semantics, and import behavior.
- Modify: `terraform-provider-neuwerk/docs/resources/sso_provider_google.md`
  - Add example-first docs for the Google SSO resource and all shared SSO fields.
- Modify: `terraform-provider-neuwerk/docs/resources/sso_provider_github.md`
  - Add example-first docs for the GitHub SSO resource and all shared SSO fields.
- Modify: `terraform-provider-neuwerk/docs/resources/sso_provider_generic_oidc.md`
  - Add example-first docs for the generic OIDC SSO resource, including required endpoint fields.
- Create: `terraform-provider-neuwerk/internal/provider/docs_reference_test.go`
  - Add regression coverage that validates the required headings and source/install markers in the docs surface.
- Modify: `docs/operations/terraform-provider-release.md`
  - Align the release process doc with the improved provider docs wording and current release contract.
- Modify: `docs/operations/terraform-provider-registry-publication.md`
  - Align Registry/publication docs with the current release-source repo, source address, and onboarding flow.

### Task 1: Add Docs Regression Coverage

**Files:**
- Create: `terraform-provider-neuwerk/internal/provider/docs_reference_test.go`
- Test: `terraform-provider-neuwerk/internal/provider/docs_reference_test.go`

- [ ] **Step 1: Write the failing docs regression test**

```go
func TestTerraformDocsReferenceLayout(t *testing.T) {
	t.Parallel()

	resourceDocs := []string{
		"../../docs/resources/policy.md",
		"../../docs/resources/kubernetes_integration.md",
		"../../docs/resources/tls_intercept_ca.md",
		"../../docs/resources/service_account.md",
		"../../docs/resources/service_account_token.md",
		"../../docs/resources/sso_provider_google.md",
		"../../docs/resources/sso_provider_github.md",
		"../../docs/resources/sso_provider_generic_oidc.md",
	}

	for _, path := range resourceDocs {
		body := mustReadFile(t, path)
		assertContains(t, body, "## Example Usage")
		assertContains(t, body, "## Argument Reference")
		assertContains(t, body, "## Attribute Reference")
	}

	indexBody := mustReadFile(t, "../../docs/index.md")
	assertContains(t, indexBody, `source = "moolen/neuwerk"`)
	assertContains(t, indexBody, "moolen/terraform-provider-neuwerk")

	providerBody := mustReadFile(t, "../../docs/provider.md")
	assertContains(t, providerBody, `source = "moolen/neuwerk"`)
	assertContains(t, providerBody, "## Manual Install")
}
```

- [ ] **Step 2: Run the targeted test and verify it fails for the current shallow docs**

Run: `cd terraform-provider-neuwerk && go test ./internal/provider -run TestTerraformDocsReferenceLayout -count=1`
Expected: FAIL because one or more resource docs do not yet contain `## Example Usage`, `## Argument Reference`, or `## Attribute Reference`.

- [ ] **Step 3: Implement the minimal test helper code**

```go
func mustReadFile(t *testing.T, path string) string {
	t.Helper()

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(body)
}

func assertContains(t *testing.T, body, needle string) {
	t.Helper()
	if !strings.Contains(body, needle) {
		t.Fatalf("expected %q in document", needle)
	}
}
```

- [ ] **Step 4: Re-run the targeted test to confirm it still fails for the right reason**

Run: `cd terraform-provider-neuwerk && go test ./internal/provider -run TestTerraformDocsReferenceLayout -count=1`
Expected: FAIL on missing headings or provider install/source markers, proving the regression test is guarding the intended docs contract before the markdown is updated.

- [ ] **Step 5: Commit the red test**

```bash
git add terraform-provider-neuwerk/internal/provider/docs_reference_test.go
git commit -m "test(terraform): guard provider docs reference layout"
```

### Task 2: Expand The Provider Landing And Configuration Docs

**Files:**
- Modify: `terraform-provider-neuwerk/docs/index.md`
- Modify: `terraform-provider-neuwerk/docs/provider.md`
- Test: `terraform-provider-neuwerk/internal/provider/docs_reference_test.go`

- [ ] **Step 1: Rewrite the landing page with quick start and install guidance**

Add a short provider description, a `terraform` block that uses `source = "moolen/neuwerk"`, a minimal provider-and-resource quick start example, install verification steps, and direct links to the provider/resource reference pages plus the example configurations.

- [ ] **Step 2: Rewrite the provider page in example-first format**

Add:

```md
## Example Usage
## Argument Reference
## Manual Install
## Notes
```

Document every provider argument from `internal/provider/provider.go`, including defaults, mutual exclusivity for `ca_cert_pem` and `ca_cert_file`, timeout semantics, and endpoint failover behavior.

- [ ] **Step 3: Run the targeted docs test**

Run: `cd terraform-provider-neuwerk && go test ./internal/provider -run TestTerraformDocsReferenceLayout -count=1`
Expected: still FAIL until the resource pages are brought up to the same structure.

- [ ] **Step 4: Commit the provider docs refresh**

```bash
git add terraform-provider-neuwerk/docs/index.md terraform-provider-neuwerk/docs/provider.md
git commit -m "docs(terraform): expand provider install and configuration reference"
```

### Task 3: Expand The Policy And Integration Resource Docs

**Files:**
- Modify: `terraform-provider-neuwerk/docs/resources/policy.md`
- Modify: `terraform-provider-neuwerk/docs/resources/kubernetes_integration.md`
- Modify: `terraform-provider-neuwerk/docs/resources/tls_intercept_ca.md`
- Test: `terraform-provider-neuwerk/internal/provider/docs_reference_test.go`

- [ ] **Step 1: Rewrite `policy.md` with a realistic nested example**

The example should show `source_group`, `sources`, a Kubernetes selector, and at least one `rule` with DNS and TLS request matching so first-time users can copy a full shape instead of reverse-engineering the schema.

- [ ] **Step 2: Add a field-complete policy reference**

Document top-level arguments and attributes, then add dedicated nested block sections for:

```md
## Nested Block Reference
### source_group
### source_group.sources
### source_group.sources.kubernetes_selector
### source_group.sources.kubernetes_selector.pod_selector
### source_group.sources.kubernetes_selector.node_selector
### source_group.rule
### source_group.rule.dns
### source_group.rule.destination
### source_group.rule.tls
### source_group.rule.tls.request
### source_group.rule.tls.request.target
### source_group.rule.tls.response
```

Include `document_json` as the low-level escape hatch and call out that it is mutually exclusive with nested authoring.

- [ ] **Step 3: Rewrite `kubernetes_integration.md`**

Add an example that wires an API server URL, cluster CA, and service account token; explain sensitive handling of `service_account_token`, the `token_configured` readback behavior, and import-by-name semantics.

- [ ] **Step 4: Rewrite `tls_intercept_ca.md`**

Add one generated-CA example and one uploaded-CA example, explain the `generate` vs. uploaded-material exclusivity rules, sensitive key handling, and singleton import behavior.

- [ ] **Step 5: Run the targeted docs test**

Run: `cd terraform-provider-neuwerk && go test ./internal/provider -run TestTerraformDocsReferenceLayout -count=1`
Expected: still FAIL until the remaining service-account and SSO pages are updated.

- [ ] **Step 6: Commit the policy/integration docs refresh**

```bash
git add terraform-provider-neuwerk/docs/resources/policy.md terraform-provider-neuwerk/docs/resources/kubernetes_integration.md terraform-provider-neuwerk/docs/resources/tls_intercept_ca.md
git commit -m "docs(terraform): expand policy and integration references"
```

### Task 4: Expand The Service Account Resource Docs

**Files:**
- Modify: `terraform-provider-neuwerk/docs/resources/service_account.md`
- Modify: `terraform-provider-neuwerk/docs/resources/service_account_token.md`
- Test: `terraform-provider-neuwerk/internal/provider/docs_reference_test.go`

- [ ] **Step 1: Rewrite `service_account.md`**

Add a simple automation-account example, field-level argument and attribute descriptions, import by UUID, and notes about machine identities and delete semantics.

- [ ] **Step 2: Rewrite `service_account_token.md`**

Add a token minting example that references a service account, document `ttl`, `eternal`, and `role`, and explicitly call out that the computed `token` secret is returned only on create and all configurable fields force replacement.

- [ ] **Step 3: Run the targeted docs test**

Run: `cd terraform-provider-neuwerk && go test ./internal/provider -run TestTerraformDocsReferenceLayout -count=1`
Expected: still FAIL until the SSO resource docs are updated.

- [ ] **Step 4: Commit the service-account docs refresh**

```bash
git add terraform-provider-neuwerk/docs/resources/service_account.md terraform-provider-neuwerk/docs/resources/service_account_token.md
git commit -m "docs(terraform): expand service account resource references"
```

### Task 5: Expand The SSO Resource Docs

**Files:**
- Modify: `terraform-provider-neuwerk/docs/resources/sso_provider_google.md`
- Modify: `terraform-provider-neuwerk/docs/resources/sso_provider_github.md`
- Modify: `terraform-provider-neuwerk/docs/resources/sso_provider_generic_oidc.md`
- Test: `terraform-provider-neuwerk/internal/provider/docs_reference_test.go`

- [ ] **Step 1: Write the Google SSO docs**

Add a Google-specific example, then document all shared SSO fields from `resource_sso_provider_shared.go`, including defaults/computed behavior for `enabled`, `display_order`, claim mappings, access-control sets, and session TTL.

- [ ] **Step 2: Write the GitHub SSO docs**

Mirror the same structure, but call out that endpoint URLs are API-defaulted/computed for this provider kind.

- [ ] **Step 3: Write the generic OIDC SSO docs**

Add an example that includes explicit `authorization_url`, `token_url`, and `userinfo_url`, and call out that those endpoint fields are required for the generic OIDC kind.

- [ ] **Step 4: Run the targeted docs test and verify it passes**

Run: `cd terraform-provider-neuwerk && go test ./internal/provider -run TestTerraformDocsReferenceLayout -count=1`
Expected: PASS

- [ ] **Step 5: Commit the SSO docs refresh**

```bash
git add terraform-provider-neuwerk/docs/resources/sso_provider_google.md terraform-provider-neuwerk/docs/resources/sso_provider_github.md terraform-provider-neuwerk/docs/resources/sso_provider_generic_oidc.md
git commit -m "docs(terraform): expand sso resource references"
```

### Task 6: Align Monorepo Release And Registry Docs

**Files:**
- Modify: `docs/operations/terraform-provider-release.md`
- Modify: `docs/operations/terraform-provider-registry-publication.md`

- [ ] **Step 1: Refresh the release doc wording**

Keep the provider source address, signing requirements, and public repo workflow accurate, but update the copy so it matches the install story presented in `terraform-provider-neuwerk/docs/index.md` and `terraform-provider-neuwerk/docs/provider.md`.

- [ ] **Step 2: Refresh the Registry/publication doc wording**

Ensure the public release-source repo flow, signing-key handling, and Registry onboarding instructions match the current fixed release asset layout and the `moolen/neuwerk` source address.

- [ ] **Step 3: Commit the aligned release docs**

```bash
git add docs/operations/terraform-provider-release.md docs/operations/terraform-provider-registry-publication.md
git commit -m "docs(terraform): align release and registry publication docs"
```

### Task 7: Full Verification

**Files:**
- Test: `terraform-provider-neuwerk/internal/provider/docs_reference_test.go`
- Test: `terraform-provider-neuwerk/internal/provider/*.go`

- [ ] **Step 1: Run the provider Go test suite**

Run: `cd terraform-provider-neuwerk && go test ./... -count=1`
Expected: PASS

- [ ] **Step 2: Run the repo diff hygiene check**

Run: `git diff --check`
Expected: no output

- [ ] **Step 3: Inspect the resulting docs surface**

Run: `git diff -- terraform-provider-neuwerk/docs docs/operations`
Expected: every provider/resource page uses the example-first reference layout and the release docs reflect the same install/publication model.

- [ ] **Step 4: Commit the verification-safe final state if any fixups were needed**

```bash
git add terraform-provider-neuwerk docs
git commit -m "docs(terraform): polish provider reference surface"
```

### Task 8: Sync The Public Release-Source Repo And Cut The Release

**Files:**
- Modify via sync export: public repo working tree produced by `packaging/scripts/sync_terraform_provider_release_source.sh`

- [ ] **Step 1: Sync the public release-source repository**

Run:

```bash
bash packaging/scripts/sync_terraform_provider_release_source.sh \
  --repo-dir "$HOME/src/terraform-provider-neuwerk" \
  --push
```

Expected: a `release-source: sync from firewall` commit is created or the script reports that the public repo is already up to date.

- [ ] **Step 2: Determine the next release version from the public repo tags**

Run: `git -C "$HOME/src/terraform-provider-neuwerk" tag --sort=version:refname`
Expected: identify the next version after the latest existing public tag.

- [ ] **Step 3: Trigger the public provider release workflow**

Run:

```bash
gh workflow run "Terraform Provider Release" \
  -R moolen/terraform-provider-neuwerk \
  -f release_version=v0.1.3 \
  -f draft=false \
  -f prerelease=false
```

Expected: the public repo builds signed provider archives and uploads Registry-compatible checksum assets for the new version.

- [ ] **Step 4: Verify the published release assets**

Run:

```bash
gh release view v0.1.3 \
  -R moolen/terraform-provider-neuwerk \
  --json tagName,isDraft,isPrerelease,assets
```

Expected: each supported platform archive is present along with `terraform-provider-neuwerk_0.1.3_SHA256SUMS` and `terraform-provider-neuwerk_0.1.3_SHA256SUMS.sig`, with no extra release assets that would confuse Terraform Registry.

- [ ] **Step 5: Commit the completed implementation branch**

```bash
git status --short
```

Expected: no unexpected local changes remain in the monorepo worktree after the sync and release work.
