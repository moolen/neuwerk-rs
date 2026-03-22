# OSS Launch Checklist Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a canonical docs-site launch checklist and a repo-side preflight that verifies the expected OSS launch surface.

**Architecture:** Keep the launch checklist split between a human-facing docs page in `www` and a machine-facing shell preflight in `packaging/scripts/`. Reuse the existing `Community` docs section and existing repo release/readiness files rather than inventing a parallel launch system.

**Tech Stack:** MDX docs pages, TypeScript docs navigation, Bash preflight script, Node test runner, existing CI/docs build tooling

---

## File Map

- Create: `www/src/content/docs/community/launch-checklist.mdx`
  Responsibility: canonical docs-site OSS launch checklist page.
- Modify: `www/src/data/docsNavigation.ts`
  Responsibility: add `Launch Checklist` to the bottom `Community` section.
- Modify: `www/src/pages/docs/index.astro`
  Responsibility: keep the docs landing-page section descriptions aligned with the new `Community` entry set.
- Modify: `www/tests/community-docs-nav.test.mjs`
  Responsibility: assert the `Community` section includes the launch checklist page.
- Create: `packaging/scripts/check_oss_launch_surface.sh`
  Responsibility: fail fast when required OSS launch-surface files are missing.
- Create: `tests/oss_launch_surface.rs`
  Responsibility: execute the preflight script successfully from the repo root.

## Preconditions

- Use the approved spec at `docs/superpowers/specs/2026-03-22-oss-launch-checklist-design.md`.
- Keep the checklist concise and limited to launch-surface verification, not release execution.

### Task 1: Add Failing Coverage For The Launch Checklist Surface

**Files:**
- Modify: `www/tests/community-docs-nav.test.mjs`
- Create: `tests/oss_launch_surface.rs`

- [ ] **Step 1: Extend the docs-site nav test with a missing launch-checklist expectation**

Update `www/tests/community-docs-nav.test.mjs` so it expects:

- `/docs/community/launch-checklist`
- label `Launch Checklist`
- the page file `www/src/content/docs/community/launch-checklist.mdx`

- [ ] **Step 2: Run the docs-site nav test to verify it fails**

Run:

```bash
node --test www/tests/community-docs-nav.test.mjs
```

Expected: FAIL because the launch-checklist page and nav entry do not exist yet.

- [ ] **Step 3: Add a missing preflight test**

Create `tests/oss_launch_surface.rs` with a single test that runs:

```text
bash packaging/scripts/check_oss_launch_surface.sh
```

and expects success.

- [ ] **Step 4: Run the preflight test to verify it fails**

Run:

```bash
cargo test --test oss_launch_surface check_oss_launch_surface_reports_success -- --exact
```

Expected: FAIL because the preflight script does not exist yet.

### Task 2: Implement The Launch Checklist Page And Sidebar Entry

**Files:**
- Create: `www/src/content/docs/community/launch-checklist.mdx`
- Modify: `www/src/data/docsNavigation.ts`
- Modify: `www/src/pages/docs/index.astro`

- [ ] **Step 1: Add the launch checklist page**

Create `www/src/content/docs/community/launch-checklist.mdx` with:

- title `Launch Checklist`
- short description
- concise sections for:
  - repository surface
  - appliance release surface
  - Terraform provider surface
  - manual launch blockers

The page should link to:

- `/docs/community/release-process`
- `/docs/community/release-readiness`
- `/docs/community/security`
- `/docs/community/contributing`

- [ ] **Step 2: Add the page to the bottom `Community` nav group**

Update `www/src/data/docsNavigation.ts` so the `Community` items include:

- `Launch Checklist`

Place it first in that section.

- [ ] **Step 3: Keep the docs index section description aligned**

Update `www/src/pages/docs/index.astro` only if needed so the `Community` description still reads correctly with the added checklist page.

- [ ] **Step 4: Run the docs-site nav test to verify it passes**

Run:

```bash
node --test www/tests/community-docs-nav.test.mjs
```

Expected: PASS.

### Task 3: Implement The Repo Preflight

**Files:**
- Create: `packaging/scripts/check_oss_launch_surface.sh`
- Test: `tests/oss_launch_surface.rs`

- [ ] **Step 1: Write the preflight script**

Create a shell script that checks for these required files:

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

The script should print explicit `missing required file:` errors and exit non-zero on the first missing file.

- [ ] **Step 2: Add the Rust test**

Implement `tests/oss_launch_surface.rs` so it executes the script from the repo root and asserts success.

- [ ] **Step 3: Run the preflight test to verify it passes**

Run:

```bash
cargo test --test oss_launch_surface check_oss_launch_surface_reports_success -- --exact
```

Expected: PASS.

### Task 4: Final Verification

**Files:**
- Verify: `www/src/content/docs/community/launch-checklist.mdx`
- Verify: `packaging/scripts/check_oss_launch_surface.sh`
- Verify: `tests/oss_launch_surface.rs`

- [ ] **Step 1: Run all `www` node tests**

Run:

```bash
node --test www/tests/*.test.mjs
```

Expected: PASS.

- [ ] **Step 2: Build the docs site**

Run:

```bash
npm --prefix www run build
```

Expected: PASS.

- [ ] **Step 3: Run the targeted Rust preflight test**

Run:

```bash
cargo test --test oss_launch_surface -- --exact
```

Expected: PASS.

- [ ] **Step 4: Check diff hygiene**

Run:

```bash
git diff --check
```

Expected: no output.
