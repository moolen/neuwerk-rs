# Terraform Provider Public Registry Publication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish the Neuwerk Terraform provider on the public Terraform Registry without moving provider source-of-truth out of this monorepo.

**Architecture:** Keep `firewall` as the authoritative development repository. Export a flat, provider-only release-source tree from this monorepo into a separate public repository named `terraform-provider-neuwerk`, and run provider release publication from that public repository. Validate the export contract in monorepo CI so provider release-source drift is caught on pull requests.

**Tech Stack:** Go, Bash, GitHub Actions, Markdown docs, Terraform Registry, GitHub Releases

---

## File Map

- Create: `packaging/scripts/export_terraform_provider_release_source.sh`
  Responsibility: assemble a flat provider-only repository tree from this monorepo into a target directory.
- Create: `packaging/terraform-provider-release-source/README.md`
  Responsibility: template README for the public release-source repository root.
- Create: `packaging/terraform-provider-release-source/LICENSE`
  Responsibility: carry the chosen OSS license into the public release-source repository root.
- Create: `packaging/terraform-provider-release-source/.gitignore`
  Responsibility: ignore build outputs in the public release-source repository.
- Create: `packaging/terraform-provider-release-source/.github/workflows/release.yml`
  Responsibility: release workflow template for the public provider repository.
- Create: `packaging/terraform-provider-release-source/.github/workflows/ci.yml`
  Responsibility: CI workflow template for the public provider repository.
- Modify: `Makefile`
  Responsibility: add a stable local entrypoint for exporting the provider release-source tree.
- Modify: `.github/workflows/ci.yml`
  Responsibility: validate the export script on pull requests and confirm the generated tree still builds and tests.
- Modify: `docs/operations/terraform-provider-release.md`
  Responsibility: distinguish the current signed GitHub Release path from the future public Registry publication path.
- Create: `docs/operations/terraform-provider-registry-publication.md`
  Responsibility: maintainer runbook for creating, updating, and releasing the public `terraform-provider-neuwerk` repository.

## External Repository Contract

The target public repository is:

- `neuwerk/terraform-provider-neuwerk`

That repository should contain:

- the flattened contents of `terraform-provider-neuwerk/` at repository root
- copied provider docs and examples
- a root `LICENSE` file matching the OSS license chosen for Neuwerk
- a release workflow that builds signed release archives from the public repo root
- a CI workflow that runs `go test ./... -count=1`
- a repository README that states this repo is generated from the monorepo and points contributors back to `firewall`

The public repository should not become a second development surface. Edits should continue to land in
this monorepo first.

### Task 1: Export A Flat Provider Release-Source Tree

**Files:**
- Create: `packaging/scripts/export_terraform_provider_release_source.sh`
- Create: `packaging/terraform-provider-release-source/README.md`
- Create: `packaging/terraform-provider-release-source/LICENSE`
- Create: `packaging/terraform-provider-release-source/.gitignore`
- Modify: `Makefile`

- [ ] **Step 1: Write the export contract into the script header**

Document in `packaging/scripts/export_terraform_provider_release_source.sh` that the output tree must:

- place the provider Go module at repository root
- preserve the `neuwerk/neuwerk` provider source address
- include `docs/` and `examples/`
- include a root `LICENSE` file
- omit unrelated monorepo code

- [ ] **Step 2: Implement deterministic export into a target directory**

Make the script accept:

```bash
bash packaging/scripts/export_terraform_provider_release_source.sh --output-dir /tmp/terraform-provider-neuwerk
```

Expected output layout:

- `/tmp/terraform-provider-neuwerk/main.go`
- `/tmp/terraform-provider-neuwerk/go.mod`
- `/tmp/terraform-provider-neuwerk/internal/provider/...`
- `/tmp/terraform-provider-neuwerk/docs/...`
- `/tmp/terraform-provider-neuwerk/examples/...`

- [ ] **Step 3: Overlay public-repo template files**

Copy:

- `packaging/terraform-provider-release-source/README.md`
- `packaging/terraform-provider-release-source/.gitignore`

into the exported tree after flattening the provider module.

- [ ] **Step 4: Add a stable make target**

Add:

```bash
make package.terraform-provider.release-source OUTPUT_DIR=/tmp/terraform-provider-neuwerk
```

Expected: the make target calls the export script and produces the same tree as the direct script
invocation.

- [ ] **Step 5: Run the export locally**

Run:

```bash
make package.terraform-provider.release-source OUTPUT_DIR=/tmp/terraform-provider-neuwerk
find /tmp/terraform-provider-neuwerk -maxdepth 2 -type f | sort
```

Expected: a flat provider repository tree with provider code at root and no unrelated monorepo
directories such as `src/`, `ui/`, or `packer/`.

### Task 2: Make The Export First-Class In Monorepo CI

**Files:**
- Modify: `.github/workflows/ci.yml`
- Create: `packaging/terraform-provider-release-source/.github/workflows/ci.yml`

- [ ] **Step 1: Add a monorepo CI job that exercises the export**

Extend `.github/workflows/ci.yml` with a job that runs:

```bash
make package.terraform-provider.release-source OUTPUT_DIR="$RUNNER_TEMP/terraform-provider-neuwerk"
```

- [ ] **Step 2: Verify the exported tree builds and tests from its own root**

In the same job, run:

```bash
cd "$RUNNER_TEMP/terraform-provider-neuwerk"
go test ./... -count=1
```

Expected: PASS.

- [ ] **Step 3: Verify release metadata files are present**

Add checks for:

- `README.md`
- `LICENSE`
- `.github/workflows/release.yml`
- `.github/workflows/ci.yml`

Expected: all required release-source files exist in the exported tree.

- [ ] **Step 4: Keep public-repo CI minimal**

Write the public repo CI template so it only runs:

```bash
go test ./... -count=1
```

This is enough for the thin release-source repository because the contract suite remains owned by
the monorepo.

### Task 3: Add The Public Release-Source Repository Templates

**Files:**
- Create: `packaging/terraform-provider-release-source/.github/workflows/release.yml`
- Create: `packaging/terraform-provider-release-source/.github/workflows/ci.yml`
- Create: `packaging/terraform-provider-release-source/README.md`
- Create: `packaging/terraform-provider-release-source/LICENSE`
- Create: `packaging/terraform-provider-release-source/.gitignore`

- [ ] **Step 1: Template the public repository README**

State clearly that:

- the repository publishes provider releases for source address `neuwerk/neuwerk`
- development happens in the `firewall` monorepo
- pull requests against the public repo should be limited to release plumbing or be redirected

- [ ] **Step 2: Add the chosen OSS license to the template**

Create `packaging/terraform-provider-release-source/LICENSE` from the final Neuwerk OSS license text.
Do not create the public repository before the license decision is made.

- [ ] **Step 3: Template the public repository CI workflow**

Create a root-repo CI workflow that:

- checks out the repo
- sets up Go from `go.mod`
- runs `go test ./... -count=1`

- [ ] **Step 4: Template the public repository release workflow**

Create a root-repo release workflow that:

- blocks until provider signing secrets are configured
- builds signed provider archives from repository root
- uploads assets to the requested GitHub Release tag

Reuse the current provider release behavior where possible, but adapt the paths from
`terraform-provider-neuwerk/` to repository root.

- [ ] **Step 5: Keep template ownership one-way**

Document in the template comments that these files are generated from the monorepo export and
should not become the primary authoring surface.

### Task 4: Write The Maintainer Runbook For Registry Publication

**Files:**
- Create: `docs/operations/terraform-provider-registry-publication.md`
- Modify: `docs/operations/terraform-provider-release.md`

- [ ] **Step 1: Document the two-repository model**

Explain:

- `firewall` stays the development repo
- `terraform-provider-neuwerk` is the public release-source repo
- signed GitHub Releases continue to be required

- [ ] **Step 2: Document the bootstrap steps for the public repo**

Include:

1. create public GitHub repository `neuwerk/terraform-provider-neuwerk`
2. export the release-source tree from this monorepo
3. push the exported tree to the public repo default branch
4. configure the provider signing secrets in the public repo

- [ ] **Step 3: Document the release steps**

Include exact maintainer commands:

```bash
make package.terraform-provider.release-source OUTPUT_DIR=/tmp/terraform-provider-neuwerk
cd /tmp/terraform-provider-neuwerk
git init
git remote add origin git@github.com:neuwerk/terraform-provider-neuwerk.git
git checkout -b main
git add .
git commit -m "release-source: sync from firewall"
git push -u origin main
```

Then direct maintainers to run the public repo release workflow for a tag such as `v0.1.0`.

- [ ] **Step 4: Document Registry onboarding separately from asset publication**

Call out that Registry publication happens after the public repo exists and release assets are
coming from that repo. Keep the runbook honest about what is manual versus automated.

### Task 5: Final Verification

**Files:**
- Modify: all files above

- [ ] **Step 1: Run the monorepo provider tests**

Run:

```bash
cd terraform-provider-neuwerk
go test ./... -count=1
```

Expected: PASS.

- [ ] **Step 2: Run the export locally and test the exported tree**

Run:

```bash
make package.terraform-provider.release-source OUTPUT_DIR=/tmp/terraform-provider-neuwerk
cd /tmp/terraform-provider-neuwerk
go test ./... -count=1
```

Expected: PASS.

- [ ] **Step 3: Run website/docs verification**

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
