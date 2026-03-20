# Appliance Image Distribution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship an operator-facing Ubuntu 24.04 appliance-image distribution path by adding a concrete AWS/Azure/GCP usage guide, aligning existing image-build docs to that guide, and updating the release metadata/workflow to present GitHub Releases as the canonical manual-import distribution channel.

**Architecture:** Keep the existing `qcow2`-based packaging path and Vagrant sidecar intact. Make the distribution contract visible in three places: operator documentation, release metadata produced by packaging scripts, and the manual GitHub Actions release workflow. Avoid provider-native publication logic or new cloud credentials.

**Tech Stack:** Markdown docs, GitHub Actions workflow YAML, Bash packaging helpers, Python release-manifest generator, existing Packer/Makefile packaging targets

---

## File Map

- Create: `docs/operations/appliance-image-usage.md`
  Responsibility: operator-facing guide for downloading, verifying, restoring, importing, bootstrapping, and validating the Ubuntu 24.04 appliance on AWS, Azure, and GCP.
- Modify: `docs/operations/image-build.md`
  Responsibility: keep image-build content build-facing while linking to the new usage guide and clarifying the artifact-first distribution contract.
- Modify: `packaging/scripts/generate_release_manifest.py`
  Responsibility: add explicit distribution metadata to `manifest.json` so release artifacts describe the manual-import support model.
- Modify: `packaging/scripts/prepare_github_release.sh`
  Responsibility: generate operator-facing release notes that call out Ubuntu 24.04 support, manual import targets, artifact restoration, and the new usage guide.
- Modify: `.github/workflows/image-release.yml`
  Responsibility: present the workflow as an appliance release pipeline with stable operator-facing outputs, without adding provider-native image publication.

## Preconditions

- Use the approved spec at `docs/superpowers/specs/2026-03-20-appliance-image-distribution-design.md` as the source of truth.
- Reuse the existing local packaging artifacts under `artifacts/image-build/` for release-asset verification. If those artifacts are missing, build them once with:

```bash
make package.image.build.qemu TARGET=ubuntu-24.04-amd64 RELEASE_VERSION=dev-plan
```

### Task 1: Create the Operator Appliance Usage Guide

**Files:**
- Create: `docs/operations/appliance-image-usage.md`

- [ ] **Step 1: Verify the guide does not already exist with the required sections**

Run:

```bash
rg -n "## AWS|## Azure|## GCP|/etc/neuwerk/appliance.env|restore-qcow2" docs/operations/appliance-image-usage.md
```

Expected: command fails because the file does not exist yet.

- [ ] **Step 2: Write the guide skeleton with the supported operator flow**

Create `docs/operations/appliance-image-usage.md` with these top-level sections:

```markdown
# Appliance Image Usage

## Supported Scope
## Download And Verify Release Assets
## Restore The qcow2 Appliance Image
## AWS Import Flow
## Azure Import Flow
## GCP Import Flow
## First Boot And Appliance Configuration
## Start And Verify Neuwerk
## Troubleshooting
```

Use this content contract inside the guide:

```markdown
- State that Ubuntu 24.04 is the only supported appliance base today.
- State that GitHub Releases is the canonical distribution channel.
- State that AWS, Azure, and GCP are supported as manual import targets.
- List the required download set for operators:
  `neuwerk-<target>.qcow2.zst.part-*`, `restore-qcow2.sh`, `SHA256SUMS`,
  `manifest.json`, and `release-notes.md`.
- Show `sha256sum -c SHA256SUMS` and `bash ./restore-qcow2.sh`.
- Explain that `/etc/neuwerk/appliance.env` is the supported place for operator overrides.
- Show `systemctl status neuwerk.service`, `journalctl -u neuwerk.service`, and a simple post-boot validation flow.
```

- [ ] **Step 3: Fill in the cloud sections with concrete manual import guidance**

Include cloud-specific sections with short operator checklists and example commands:

```markdown
## AWS Import Flow
- Convert the restored `qcow2` to a raw image:
  `qemu-img convert -f qcow2 -O raw neuwerk-<target>.qcow2 neuwerk-<target>.raw`
- Upload the restored image to S3.
- Use the EC2 VM import path to create an EBS-backed image.
- Launch a VM from the imported image and verify networking before enabling traffic.

## Azure Import Flow
- Convert the restored `qcow2` to a fixed VHD:
  `qemu-img convert -f qcow2 -O vpc -o subformat=fixed neuwerk-<target>.qcow2 neuwerk-<target>.vhd`
- Upload the converted VHD to Azure storage.
- Create a managed image from the uploaded VHD-compatible artifact path you prepared.
- Boot a VM from that image and verify NIC placement and service health.

## GCP Import Flow
- Convert the restored `qcow2` to a raw image:
  `qemu-img convert -f qcow2 -O raw neuwerk-<target>.qcow2 neuwerk-<target>.img`
- Package the raw image for import:
  `tar --format=oldgnu -Sczf neuwerk-<target>.img.tar.gz neuwerk-<target>.img`
- Upload the packaged image to Cloud Storage.
- Create a custom Compute Engine image from the uploaded artifact.
- Launch a VM from the custom image and verify service health.
```

Keep the guide concrete, but do not add Terraform automation or provider-native publication instructions.

- [ ] **Step 4: Verify the guide contains the required sections and commands**

Run:

```bash
rg -n "^## Supported Scope|^## Download And Verify Release Assets|^## Restore The qcow2 Appliance Image|^## AWS Import Flow|^## Azure Import Flow|^## GCP Import Flow|/etc/neuwerk/appliance.env|systemctl status neuwerk.service|journalctl -u neuwerk.service" docs/operations/appliance-image-usage.md
```

Expected: all required sections and operational commands are present.

- [ ] **Step 5: Commit the guide**

```bash
git add docs/operations/appliance-image-usage.md
git commit -m "docs: add appliance image usage guide"
```

### Task 2: Link the Build Docs to the Operator Guide

**Files:**
- Modify: `docs/operations/image-build.md`

- [ ] **Step 1: Verify the current build doc does not link to the new usage guide**

Run:

```bash
rg -n "appliance-image-usage|manual import targets|canonical distribution channel" docs/operations/image-build.md
```

Expected: no matches.

- [ ] **Step 2: Add build-vs-usage framing near the top of the document**

Update the introduction so it clearly separates build-facing and usage-facing docs. Add wording like:

```markdown
For operators consuming a published appliance image, see [Appliance Image Usage](./appliance-image-usage.md).
This document remains build-facing and covers how Neuwerk image artifacts are produced.
```

- [ ] **Step 3: Update the release-assets and workflow sections to match the distribution contract**

Adjust the sections that describe `package.image.release-assets` and `.github/workflows/image-release.yml` so they say:

```markdown
- GitHub Releases is the canonical distribution channel for Ubuntu 24.04 appliance images.
- The published release artifacts are intended for manual import into AWS, Azure, and GCP.
- Provider-native image publication is not automated in this phase.
```

- [ ] **Step 4: Verify the new guide link and contract wording are present**

Run:

```bash
rg -n "appliance-image-usage|GitHub Releases is the canonical distribution channel|manual import into AWS, Azure, and GCP|not automated in this phase" docs/operations/image-build.md
```

Expected: all new references are present.

- [ ] **Step 5: Commit the build-doc updates**

```bash
git add docs/operations/image-build.md
git commit -m "docs: align image build docs with appliance distribution"
```

### Task 3: Add Distribution Metadata to the Release Manifest and Release Notes

**Files:**
- Modify: `packaging/scripts/generate_release_manifest.py`
- Modify: `packaging/scripts/prepare_github_release.sh`

- [ ] **Step 1: Write a failing manifest verification**

Run:

```bash
tmpdir="$(mktemp -d)"
printf 'sample\n' > "$tmpdir/sample.bin"
python3 packaging/scripts/generate_release_manifest.py \
  --target ubuntu-24.04-amd64 \
  --provider qemu \
  --release-version v0.0.0 \
  --git-revision testrev \
  --artifact "$tmpdir/sample.bin" \
  --output "$tmpdir/manifest.json"
python3 - "$tmpdir/manifest.json" <<'PY'
import json
import pathlib
import sys

data = json.loads(pathlib.Path(sys.argv[1]).read_text())
distribution = data["distribution"]
assert distribution["channel"] == "github-release"
assert distribution["support_model"] == "manual-import"
assert distribution["supported_platforms"] == ["aws", "azure", "gcp"]
assert distribution["supported_os"] == {"family": "ubuntu", "version": "24.04"}
PY
```

Expected: the Python assertion step fails with `KeyError: 'distribution'`.

- [ ] **Step 2: Add explicit distribution metadata to the manifest generator**

Update `packaging/scripts/generate_release_manifest.py` so the JSON payload includes a block like:

```python
"distribution": {
    "channel": "github-release",
    "artifact_type": "appliance-image",
    "support_model": "manual-import",
    "supported_platforms": ["aws", "azure", "gcp"],
    "supported_os": {
        "family": target_data["os"]["family"],
        "version": target_data["os"]["version"],
    },
    "runtime_contract": {
        "dpdk_mode": "vendored",
        "summary": "built with the existing vendored Neuwerk runtime contract",
    },
}
```

Do not remove the existing `target`, `provider`, `image_reference`, or `artifacts` data.

- [ ] **Step 3: Write a failing release-notes verification**

Run:

```bash
make package.image.release-assets TARGET=ubuntu-24.04-amd64 RELEASE_VERSION=dev-plan GIT_REVISION="$(git rev-parse --short=12 HEAD)"
rg -n "Ubuntu 24.04|manual import targets|AWS|Azure|GCP|docs/operations/appliance-image-usage.md" artifacts/image-build/github-release/ubuntu-24.04-amd64/release-notes.md
```

Expected: the `rg` command fails because the current release notes do not yet describe the appliance support model.

- [ ] **Step 4: Update the generated release notes to be operator-facing**

Modify `packaging/scripts/prepare_github_release.sh` so `release-notes.md` includes content like:

```bash
echo "## Supported Appliance Contract"
echo
echo "- Ubuntu 24.04 is the supported appliance base for this release."
echo "- GitHub Releases is the canonical distribution channel."
echo "- AWS, Azure, and GCP are supported as manual import targets."
echo "- The image is built with the existing vendored Neuwerk runtime contract."
echo "- Provider-native image publication is not automated in this phase."
echo "- See \`docs/operations/appliance-image-usage.md\` for the operator guide."
```

Keep the existing asset inventory and `restore-qcow2.sh` instructions.

- [ ] **Step 5: Re-run the manifest and release-note verification**

Run:

```bash
tmpdir="$(mktemp -d)"
printf 'sample\n' > "$tmpdir/sample.bin"
python3 packaging/scripts/generate_release_manifest.py \
  --target ubuntu-24.04-amd64 \
  --provider qemu \
  --release-version v0.0.0 \
  --git-revision testrev \
  --artifact "$tmpdir/sample.bin" \
  --output "$tmpdir/manifest.json"
python3 - "$tmpdir/manifest.json" <<'PY'
import json
import pathlib
import sys

data = json.loads(pathlib.Path(sys.argv[1]).read_text())
distribution = data["distribution"]
assert distribution["channel"] == "github-release"
assert distribution["artifact_type"] == "appliance-image"
assert distribution["support_model"] == "manual-import"
assert distribution["supported_platforms"] == ["aws", "azure", "gcp"]
assert distribution["supported_os"] == {"family": "ubuntu", "version": "24.04"}
runtime_contract = distribution["runtime_contract"]
assert runtime_contract["dpdk_mode"] == "vendored"
assert runtime_contract["summary"] == "built with the existing vendored Neuwerk runtime contract"
PY
make package.image.release-assets TARGET=ubuntu-24.04-amd64 RELEASE_VERSION=dev-plan GIT_REVISION="$(git rev-parse --short=12 HEAD)"
rg -n "Ubuntu 24.04|GitHub Releases is the canonical distribution channel|AWS, Azure, and GCP are supported as manual import targets|vendored Neuwerk runtime contract|docs/operations/appliance-image-usage.md" artifacts/image-build/github-release/ubuntu-24.04-amd64/release-notes.md
```

Expected: the manifest assertions pass and the release-notes `rg` command returns matching lines.

- [ ] **Step 6: Commit the release-metadata changes**

```bash
git add packaging/scripts/generate_release_manifest.py packaging/scripts/prepare_github_release.sh
git commit -m "packaging: describe appliance distribution metadata"
```

### Task 4: Reframe the GitHub Actions Workflow as an Appliance Release Pipeline

**Files:**
- Modify: `.github/workflows/image-release.yml`

- [ ] **Step 1: Verify the workflow does not yet use appliance-oriented wording**

Run:

```bash
rg -n "Validate appliance|Build appliance|Prepare appliance distribution assets|Publish appliance release|manual import targets" .github/workflows/image-release.yml
```

Expected: no matches.

- [ ] **Step 2: Rename workflow steps and update input descriptions where wording should reflect the supported contract**

Update `.github/workflows/image-release.yml` so the user-facing step names read like an appliance release workflow. Use wording in this direction:

```yaml
- name: Validate appliance image configuration
- name: Build appliance host artifacts
- name: Prepare appliance distribution assets
- name: Publish GitHub appliance release
```

Also tighten the `workflow_dispatch` input descriptions so they refer to appliance images rather than generic image targets where appropriate, for example:

```yaml
target:
  description: Appliance image target manifest id
```

Keep the current behavior:

```yaml
- manual workflow_dispatch trigger
- Ubuntu 24.04 targets only
- qemu build path
- optional Vagrant asset generation for the minimal target
- GitHub Release publication from generated release-notes.md
```

Do not add cloud import jobs, provider-native publication, or provider credentials.

- [ ] **Step 3: Verify the workflow reflects the new pipeline framing**

Run:

```bash
rg -n "Validate appliance image configuration|Build appliance host artifacts|Prepare appliance distribution assets|Publish GitHub appliance release" .github/workflows/image-release.yml
```

Expected: all renamed steps are present.

- [ ] **Step 4: Commit the workflow update**

```bash
git add .github/workflows/image-release.yml
git commit -m "ci: frame image release as appliance distribution"
```

### Task 5: Run Final Verification Across Docs, Scripts, and Packaging Validation

**Files:**
- Modify: none
- Verify: `docs/operations/appliance-image-usage.md`
- Verify: `docs/operations/image-build.md`
- Verify: `packaging/scripts/generate_release_manifest.py`
- Verify: `packaging/scripts/prepare_github_release.sh`
- Verify: `.github/workflows/image-release.yml`

- [ ] **Step 1: Run script and packaging validation**

Run:

```bash
python3 -m py_compile packaging/scripts/*.py
bash -n packaging/scripts/prepare_github_release.sh
make package.target.validate TARGET=ubuntu-24.04-amd64
make package.image.validate TARGET=ubuntu-24.04-amd64 PACKER=packer RELEASE_VERSION=dev-plan
```

Expected: all commands pass.

- [ ] **Step 2: Rebuild release assets and inspect the operator-facing outputs**

Run:

```bash
make package.image.release-assets TARGET=ubuntu-24.04-amd64 RELEASE_VERSION=dev-plan GIT_REVISION="$(git rev-parse --short=12 HEAD)"
rg -n "Ubuntu 24.04|manual import targets|docs/operations/appliance-image-usage.md" artifacts/image-build/github-release/ubuntu-24.04-amd64/release-notes.md
python3 - <<'PY'
import json
from pathlib import Path

data = json.loads(Path("artifacts/image-build/github-release/ubuntu-24.04-amd64/manifest.json").read_text())
distribution = data["distribution"]
assert distribution["channel"] == "github-release"
assert distribution["artifact_type"] == "appliance-image"
assert distribution["support_model"] == "manual-import"
assert distribution["supported_platforms"] == ["aws", "azure", "gcp"]
print("manifest distribution metadata verified")
PY
```

Expected: release notes contain the operator-facing contract and manifest verification prints `manifest distribution metadata verified`.

- [ ] **Step 3: Run a final whitespace and staged-diff check**

Run:

```bash
git diff --check
git status --short
```

Expected: no whitespace errors; only the intended doc, script, and workflow files are modified.

- [ ] **Step 4: Commit the final verification state if needed**

```bash
git status --short
```

If any verification-only file drift needs cleanup, resolve it before the final implementation handoff commit. Otherwise, no extra commit is required here.
