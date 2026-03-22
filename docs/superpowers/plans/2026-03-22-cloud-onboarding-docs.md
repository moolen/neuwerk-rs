# Cloud Onboarding Docs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the obsolete single-node and two-node getting-started flow with a cloud-first quickstart that teaches released-image import, first-boot bootstrap, and the cloud rollout integration model for upgrades.

**Architecture:** Keep the published website docs as the canonical onboarding path. Add one new getting-started guide for released cloud images and one new concepts page for ASG/VMSS/MIG rollout behavior, then retarget navigation and compatibility pages so old URLs still help users instead of becoming dead ends.

**Tech Stack:** Astro docs site, MDX content pages, TypeScript nav data, Node `node:test`, Astro `check` and `build`

---

### Task 1: Add Navigation And Link Regression Coverage

**Files:**
- Create: `www/tests/cloud-onboarding-docs.test.mjs`
- Modify: `www/tests/community-docs-nav.test.mjs`
- Test: `www/tests/cloud-onboarding-docs.test.mjs`

- [ ] **Step 1: Write the failing tests for the new onboarding entry points**

```js
import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';

test('docs nav promotes the released cloud image guide and cloud rollout concept', () => {
  const nav = readFileSync(new URL('../src/data/docsNavigation.ts', import.meta.url), 'utf8');

  assert.match(nav, /\/docs\/tutorials\/launch-from-released-cloud-image/);
  assert.match(nav, /\/docs\/architecture\/cloud-rollout-integration/);
  assert.doesNotMatch(nav, /label: 'Deploy A Single Node'/);
  assert.doesNotMatch(nav, /label: 'Build A Two-Node Cluster'/);
});

test('site entry points and docs pages point at the new cloud-first path', () => {
  const index = readFileSync(new URL('../src/pages/docs/index.astro', import.meta.url), 'utf8');
  const footer = readFileSync(new URL('../src/components/common/Footer.astro', import.meta.url), 'utf8');
  const requirements = readFileSync(new URL('../src/content/docs/deployment/requirements.mdx', import.meta.url), 'utf8');
  const releaseProcess = readFileSync(new URL('../src/content/docs/community/release-process.mdx', import.meta.url), 'utf8');
  const upgrade = readFileSync(new URL('../src/content/docs/how-to/upgrade-a-cluster.mdx', import.meta.url), 'utf8');

  assert.match(index, /launch-from-released-cloud-image/);
  assert.match(index, /cloud-rollout-integration/);
  assert.match(footer, /\/docs\/tutorials\/launch-from-released-cloud-image/);
  assert.match(requirements, /\/docs\/tutorials\/launch-from-released-cloud-image/);
  assert.match(releaseProcess, /\/docs\/tutorials\/launch-from-released-cloud-image/);
  assert.match(upgrade, /\/docs\/architecture\/cloud-rollout-integration/);
});

test('new docs pages exist', () => {
  assert.equal(existsSync(new URL('../src/content/docs/tutorials/launch-from-released-cloud-image.mdx', import.meta.url)), true);
  assert.equal(existsSync(new URL('../src/content/docs/architecture/cloud-rollout-integration.mdx', import.meta.url)), true);
});
```

- [ ] **Step 2: Run the new docs regression tests and verify they fail**

Run: `node --test www/tests/cloud-onboarding-docs.test.mjs`
Expected: FAIL because the new guide, concepts page, and updated links do not exist yet.

- [ ] **Step 3: Extend the existing nav test to cover the updated Getting Started shape**

```js
assert.match(navSource, /href: '\/docs\/tutorials\/launch-from-released-cloud-image', label: 'Launch Neuwerk From The Released Cloud Image'/);
assert.doesNotMatch(navSource, /label: 'Deploy A Single Node'/);
assert.doesNotMatch(navSource, /label: 'Build A Two-Node Cluster'/);
```

- [ ] **Step 4: Run the nav test and verify it fails for the old nav layout**

Run: `node --test www/tests/community-docs-nav.test.mjs`
Expected: FAIL because the nav still references the obsolete tutorials.

- [ ] **Step 5: Commit the failing-test baseline**

```bash
git add www/tests/cloud-onboarding-docs.test.mjs www/tests/community-docs-nav.test.mjs
git commit -m "test(docs): add cloud onboarding coverage"
```

### Task 2: Publish The New Cloud-First Guide And Concepts Page

**Files:**
- Create: `www/src/content/docs/tutorials/launch-from-released-cloud-image.mdx`
- Create: `www/src/content/docs/architecture/cloud-rollout-integration.mdx`
- Test: `www/tests/cloud-onboarding-docs.test.mjs`

- [ ] **Step 1: Write the new getting-started guide frontmatter and outline**

```mdx
---
title: Launch Neuwerk From The Released Cloud Image
description: Download the signed release artifact, convert and import it into AWS, Azure, or GCP, then bootstrap first boot with appliance.env and cloud-init.
order: 1
---
```

- [ ] **Step 2: Add the released-image workflow to the guide**

````mdx
## Download And Verify The Release

```bash
gpg --import neuwerk-release-signing-key.asc
gpg --verify SHA256SUMS.sig SHA256SUMS
sha256sum -c SHA256SUMS
```

## Restore The Published `qcow2`

```bash
bash ./restore-qcow2.sh
```
````

- [ ] **Step 3: Add provider-specific conversion and import commands**

````mdx
## AWS

```bash
qemu-img convert -f qcow2 -O raw neuwerk-ubuntu-24.04-minimal-amd64.qcow2 neuwerk-ubuntu-24.04-minimal-amd64.raw
aws s3 cp neuwerk-ubuntu-24.04-minimal-amd64.raw s3://<bucket>/neuwerk-ubuntu-24.04-minimal-amd64.raw
aws ec2 import-image --description "Neuwerk ubuntu-24.04-minimal-amd64" --disk-containers "Format=raw,UserBucket={S3Bucket=<bucket>,S3Key=neuwerk-ubuntu-24.04-minimal-amd64.raw}"
```
````

- [ ] **Step 4: Add the first-boot bootstrap section using `appliance.env` and cloud-init**

````mdx
## Configure First Boot

```yaml
#cloud-config
write_files:
  - path: /etc/neuwerk/appliance.env
    permissions: '0644'
    content: |
      NEUWERK_BOOTSTRAP_CLOUD_PROVIDER=aws
      NEUWERK_BOOTSTRAP_MANAGEMENT_INTERFACE=eth0
      NEUWERK_BOOTSTRAP_DATA_INTERFACE=eth1
      NEUWERK_BOOTSTRAP_DNS_UPSTREAMS=10.0.0.2:53,10.0.0.3:53
      NEUWERK_INTEGRATION_MODE=aws-asg
      NEUWERK_AWS_REGION=eu-central-1
      NEUWERK_AWS_VPC_ID=vpc-0123456789abcdef0
      NEUWERK_AWS_ASG_NAME=neuwerk-asg
runcmd:
  - systemctl restart neuwerk.service
```
````

- [ ] **Step 5: Add the cloud rollout concepts page**

```mdx
---
title: Cloud Rollout Integration
description: Understand how Neuwerk integrates with AWS ASGs, Azure VMSS, and GCP MIG-style replacements, including drain, readiness, and upgrade behavior.
order: 6
---
```

- [ ] **Step 6: Explain the provider integration contract and upgrade model**

```mdx
- `NEUWERK_INTEGRATION_MODE=aws-asg` pairs Neuwerk drain behavior with ASG lifecycle replacement.
- `NEUWERK_INTEGRATION_MODE=azure-vmss` pairs Neuwerk drain behavior with VMSS replacement.
- `NEUWERK_INTEGRATION_MODE=gcp-mig` pairs Neuwerk drain behavior with managed instance group replacement.
```

- [ ] **Step 7: Run the new regression tests and verify the new files satisfy existence checks**

Run: `node --test www/tests/cloud-onboarding-docs.test.mjs`
Expected: still FAIL because nav and linked entry points have not been updated yet, but file-existence assertions should now pass.

- [ ] **Step 8: Commit the new docs pages**

```bash
git add www/src/content/docs/tutorials/launch-from-released-cloud-image.mdx www/src/content/docs/architecture/cloud-rollout-integration.mdx
git commit -m "docs: add cloud-first onboarding guides"
```

### Task 3: Retarget Navigation, Landing Copy, And Compatibility URLs

**Files:**
- Modify: `www/src/data/docsNavigation.ts`
- Modify: `www/src/pages/docs/index.astro`
- Modify: `www/src/components/common/Footer.astro`
- Modify: `www/src/content/docs/tutorials/deploy-a-single-node.mdx`
- Modify: `www/src/content/docs/tutorials/build-a-two-node-cluster.mdx`
- Test: `www/tests/cloud-onboarding-docs.test.mjs`
- Test: `www/tests/community-docs-nav.test.mjs`

- [ ] **Step 1: Replace the Getting Started nav items**

```ts
{
  title: 'Getting Started',
  items: [
    { href: '/docs/tutorials/run-the-vagrant-demo-box', label: 'Run The Vagrant Demo Box' },
    { href: '/docs/tutorials/launch-from-released-cloud-image', label: 'Launch Neuwerk From The Released Cloud Image' },
    { href: '/docs/tutorials/create-your-first-policy', label: 'Create Your First Policy' },
  ],
}
```

- [ ] **Step 2: Add the new concepts page to the Concepts section**

```ts
{ href: '/docs/architecture/cloud-rollout-integration', label: 'Cloud Rollout Integration' },
```

- [ ] **Step 3: Rewrite the docs index copy around the cloud-first path**

```astro
<p>
  If you want a local demo first, begin with <a href="/docs/tutorials/run-the-vagrant-demo-box">Run The Vagrant Demo Box</a>.
  For production-style onboarding, continue with <a href="/docs/tutorials/launch-from-released-cloud-image">Launch Neuwerk From The Released Cloud Image</a>,
  then <a href="/docs/tutorials/create-your-first-policy">Create Your First Policy</a>.
  Read <a href="/docs/architecture/cloud-rollout-integration">Cloud Rollout Integration</a> before adopting ASG, VMSS, or MIG-based rollouts.
</p>
```

- [ ] **Step 4: Point the site footer Getting Started link at the new guide**

```ts
{ href: '/docs/tutorials/launch-from-released-cloud-image', label: 'Getting Started' },
```

- [ ] **Step 5: Rewrite the old tutorial pages as compatibility notes**

```mdx
This tutorial is obsolete for first-time cloud onboarding.

Use [Launch Neuwerk From The Released Cloud Image](/docs/tutorials/launch-from-released-cloud-image) for the supported released-image flow.
```

- [ ] **Step 6: Run the focused tests and verify they now pass**

Run: `node --test www/tests/cloud-onboarding-docs.test.mjs www/tests/community-docs-nav.test.mjs`
Expected: PASS

- [ ] **Step 7: Commit the nav and compatibility-page changes**

```bash
git add \
  www/src/data/docsNavigation.ts \
  www/src/pages/docs/index.astro \
  www/src/components/common/Footer.astro \
  www/src/content/docs/tutorials/deploy-a-single-node.mdx \
  www/src/content/docs/tutorials/build-a-two-node-cluster.mdx
git commit -m "docs: retarget onboarding navigation"
```

### Task 4: Update Related Docs To Match The New Onboarding Model

**Files:**
- Modify: `www/src/content/docs/deployment/requirements.mdx`
- Modify: `www/src/content/docs/how-to/upgrade-a-cluster.mdx`
- Modify: `www/src/content/docs/community/release-process.mdx`
- Test: `www/tests/cloud-onboarding-docs.test.mjs`

- [ ] **Step 1: Update Requirements to send users to the new guide**

```mdx
## Related Pages

- [Launch Neuwerk From The Released Cloud Image](/docs/tutorials/launch-from-released-cloud-image)
- [Run A Single Node](/docs/deployment/single-node)
- [Run An HA Cluster](/docs/deployment/high-availability)
```

- [ ] **Step 2: Update Upgrade A Cluster to link to the cloud rollout concept**

```mdx
If your deployment is backed by an Auto Scaling Group, VM Scale Set, or managed instance group style
replacement workflow, read [Cloud Rollout Integration](/docs/architecture/cloud-rollout-integration)
before starting the rollout.
```

- [ ] **Step 3: Replace the broken release-process operator link with the new published guide**

```mdx
The detailed operator-facing artifact and verification flow is documented in:

- [Launch Neuwerk From The Released Cloud Image](/docs/tutorials/launch-from-released-cloud-image)
```

- [ ] **Step 4: Run the cloud onboarding regression test again**

Run: `node --test www/tests/cloud-onboarding-docs.test.mjs`
Expected: PASS

- [ ] **Step 5: Commit the related-doc updates**

```bash
git add \
  www/src/content/docs/deployment/requirements.mdx \
  www/src/content/docs/how-to/upgrade-a-cluster.mdx \
  www/src/content/docs/community/release-process.mdx
git commit -m "docs: align cloud onboarding cross-links"
```

### Task 5: Final Verification

**Files:**
- Verify: `www/src/content/docs/tutorials/launch-from-released-cloud-image.mdx`
- Verify: `www/src/content/docs/architecture/cloud-rollout-integration.mdx`
- Verify: `www/src/data/docsNavigation.ts`
- Verify: `www/src/pages/docs/index.astro`
- Verify: `www/src/components/common/Footer.astro`
- Verify: `www/src/content/docs/tutorials/deploy-a-single-node.mdx`
- Verify: `www/src/content/docs/tutorials/build-a-two-node-cluster.mdx`
- Verify: `www/src/content/docs/deployment/requirements.mdx`
- Verify: `www/src/content/docs/how-to/upgrade-a-cluster.mdx`
- Verify: `www/src/content/docs/community/release-process.mdx`
- Verify: `www/tests/cloud-onboarding-docs.test.mjs`
- Verify: `www/tests/community-docs-nav.test.mjs`

- [ ] **Step 1: Run the focused Node tests**

Run: `node --test www/tests/cloud-onboarding-docs.test.mjs www/tests/community-docs-nav.test.mjs`
Expected: PASS

- [ ] **Step 2: Run Astro type/content validation**

Run: `npm --prefix www run check`
Expected: PASS

- [ ] **Step 3: Run a production docs build**

Run: `npm --prefix www run build`
Expected: PASS with generated docs routes for the new guide and concept page.

- [ ] **Step 4: Inspect git diff for accidental scope creep**

Run: `git log --stat --oneline --max-count 5 -- www/src www/tests`
Expected: only docs-site content, nav, footer, and test files related to cloud onboarding appear in the recent docs commits.

- [ ] **Step 5: Commit final verification-only fixes if needed**

```bash
git add www
git commit -m "chore(docs): finalize cloud onboarding verification"
```
