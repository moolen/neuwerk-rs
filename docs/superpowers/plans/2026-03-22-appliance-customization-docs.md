# Appliance Customization Docs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a dedicated how-to page for customizing the released Neuwerk appliance image at first boot, including `appliance.env` overrides, cloud-init package installation, and safe file/script customization patterns.

**Architecture:** Keep cloud-image onboarding focused on import and first boot, keep rollout docs focused on lifecycle behavior, and add a single task-oriented customization page linked from both surfaces. Regression coverage should prove the page exists, is discoverable from the docs flow, and contains the expected customization examples.

**Tech Stack:** Astro docs site, MDX content pages, TypeScript navigation data, Node `node:test`, Astro static build

---

### Task 1: Add Regression Coverage For Appliance Customization Docs

**Files:**
- Modify: `www/tests/cloud-onboarding-docs.test.mjs`
- Test: `www/tests/cloud-onboarding-docs.test.mjs`

- [ ] **Step 1: Add failing tests for discoverability and core content**

```js
test('how-to navigation includes the appliance customization page', () => {
  const navSource = readFileSync(new URL('../src/data/docsNavigation.ts', import.meta.url), 'utf8');
  const howToStart = navSource.indexOf("title: 'How-To Guides'");
  const conceptsStart = navSource.indexOf("title: 'Concepts'");
  const howToSection = navSource.slice(howToStart, conceptsStart);

  assert.match(
    howToSection,
    /href: '\/docs\/how-to\/customize-the-appliance-image-at-first-boot'/,
    'expected How-To Guides to include the appliance customization page',
  );
});

test('quickstart and rollout concept page link to the customization guide', () => {
  const quickstart = readFileSync(new URL('../src/content/docs/tutorials/launch-from-released-cloud-image.mdx', import.meta.url), 'utf8');
  const rollout = readFileSync(new URL('../src/content/docs/architecture/cloud-rollout-integration.mdx', import.meta.url), 'utf8');

  assertMdxLink(
    quickstart,
    '/docs/how-to/customize-the-appliance-image-at-first-boot',
    'expected quickstart to link to the customization guide',
  );
  assertMdxLink(
    rollout,
    '/docs/how-to/customize-the-appliance-image-at-first-boot',
    'expected rollout concept page to link to the customization guide',
  );
});

test('customization guide exists and includes env vars, packages, and file/script examples', () => {
  const source = readFileSync(
    new URL('../src/content/docs/how-to/customize-the-appliance-image-at-first-boot.mdx', import.meta.url),
    'utf8',
  );

  assert.match(source, /\/etc\/neuwerk\/appliance\.env/);
  assert.match(source, /NEUWERK_BOOTSTRAP_/);
  assert.match(source, /NEUWERK_INTEGRATION_MODE/);
  assert.match(source, /^packages:/m);
  assert.match(source, /write_files:/);
});
```

- [ ] **Step 2: Run the focused regression test and verify it fails**

Run: `node --test www/tests/cloud-onboarding-docs.test.mjs`
Expected: FAIL because the new page and links do not exist yet.

- [ ] **Step 3: Commit the failing-test baseline**

```bash
git add www/tests/cloud-onboarding-docs.test.mjs
git commit -m "test(docs): add appliance customization coverage"
```

### Task 2: Add The Appliance Customization How-To Page

**Files:**
- Create: `www/src/content/docs/how-to/customize-the-appliance-image-at-first-boot.mdx`
- Test: `www/tests/cloud-onboarding-docs.test.mjs`

- [ ] **Step 1: Add the new page frontmatter and purpose**

```mdx
---
title: Customize The Appliance Image At First Boot
description: Use cloud-init or equivalent startup metadata to supply env vars, install extra packages, and add supporting files to the released Neuwerk appliance image.
order: 4
---
```

- [ ] **Step 2: Add `When To Customize` and `Customize Runtime Settings` sections**

````mdx
## When To Customize

- use `/etc/neuwerk/appliance.env` when env vars are enough
- use cloud-init file writes when you need adjacent config, scripts, or certificates
- use package installation only for supporting host integration, not to casually replace Neuwerk's runtime contract

## Customize Runtime Settings

```yaml
#cloud-config
write_files:
  - path: /etc/neuwerk/appliance.env
    owner: root:root
    permissions: "0644"
    content: |
      NEUWERK_BOOTSTRAP_MANAGEMENT_INTERFACE=eth0
      NEUWERK_BOOTSTRAP_DATA_INTERFACE=eth1
      NEUWERK_BOOTSTRAP_DNS_UPSTREAMS=10.20.0.2:53,10.20.0.3:53
      NEUWERK_INTEGRATION_MODE=aws-asg
      NEUWERK_AWS_REGION=eu-central-1
      NEUWERK_AWS_VPC_ID=vpc-0123456789abcdef0
      NEUWERK_AWS_ASG_NAME=neuwerk-prod-asg
```
````

- [ ] **Step 3: Add `Install Extra Packages` guidance with cloud-init example**

````mdx
## Install Extra Packages

```yaml
#cloud-config
packages:
  - ca-certificates
  - jq
  - collectd
runcmd:
  - systemctl restart neuwerk.service
```
````

- [ ] **Step 4: Add `Add Files, Certificates, Or Scripts` and `Customization Boundaries`**

````mdx
## Add Files, Certificates, Or Scripts

```yaml
#cloud-config
write_files:
  - path: /usr/local/share/ca-certificates/internal-root.crt
    permissions: "0644"
    content: |
      -----BEGIN CERTIFICATE-----
      ...
      -----END CERTIFICATE-----
  - path: /usr/local/bin/neuwerk-post-bootstrap.sh
    permissions: "0755"
    content: |
      #!/usr/bin/env bash
      set -euo pipefail
      update-ca-certificates
runcmd:
  - /usr/local/bin/neuwerk-post-bootstrap.sh
  - systemctl restart neuwerk.service
```

## Customization Boundaries

- do add env vars, files, and supporting packages declaratively
- do not replace bundled DPDK/runtime libraries casually
- do not turn managed fleets into hand-tuned pet VMs
````

- [ ] **Step 5: Add related links back to the main onboarding flow**

```mdx
## Related Pages

- [Launch Neuwerk From The Released Cloud Image](/docs/tutorials/launch-from-released-cloud-image)
- [Cloud Rollout Integration](/docs/architecture/cloud-rollout-integration)
- [Requirements](/docs/deployment/requirements)
```

- [ ] **Step 6: Run the focused regression test**

Run: `node --test www/tests/cloud-onboarding-docs.test.mjs`
Expected: still FAIL because navigation and cross-links are not updated yet, but the page-existence/content checks should pass.

- [ ] **Step 7: Commit the new page**

```bash
git add www/src/content/docs/how-to/customize-the-appliance-image-at-first-boot.mdx
git commit -m "docs: add appliance customization how-to"
```

### Task 3: Link The New How-To Into The Cloud Onboarding Flow

**Files:**
- Modify: `www/src/content/docs/tutorials/launch-from-released-cloud-image.mdx`
- Modify: `www/src/content/docs/architecture/cloud-rollout-integration.mdx`
- Modify: `www/src/data/docsNavigation.ts`
- Test: `www/tests/cloud-onboarding-docs.test.mjs`

- [ ] **Step 1: Add the how-to page to the How-To Guides nav**

```ts
{ href: '/docs/how-to/customize-the-appliance-image-at-first-boot', label: 'Customize The Appliance Image At First Boot' },
```

- [ ] **Step 2: Link the quickstart to the customization guide**

```mdx
- read [Customize The Appliance Image At First Boot](/docs/how-to/customize-the-appliance-image-at-first-boot) if you need to supply extra env vars, packages, files, or scripts through cloud-init
```

- [ ] **Step 3: Link the rollout concept page to the customization guide**

```mdx
For first-boot customization patterns, see [Customize The Appliance Image At First Boot](/docs/how-to/customize-the-appliance-image-at-first-boot).
```

- [ ] **Step 4: Run the focused regression test and verify it passes**

Run: `node --test www/tests/cloud-onboarding-docs.test.mjs`
Expected: PASS

- [ ] **Step 5: Commit the flow integration changes**

```bash
git add \
  www/src/content/docs/tutorials/launch-from-released-cloud-image.mdx \
  www/src/content/docs/architecture/cloud-rollout-integration.mdx \
  www/src/data/docsNavigation.ts
git commit -m "docs: link appliance customization into cloud onboarding"
```

### Task 4: Final Verification

**Files:**
- Verify: `www/src/content/docs/how-to/customize-the-appliance-image-at-first-boot.mdx`
- Verify: `www/src/content/docs/tutorials/launch-from-released-cloud-image.mdx`
- Verify: `www/src/content/docs/architecture/cloud-rollout-integration.mdx`
- Verify: `www/src/data/docsNavigation.ts`
- Verify: `www/tests/cloud-onboarding-docs.test.mjs`

- [ ] **Step 1: Run the focused docs regression test**

Run: `node --test www/tests/cloud-onboarding-docs.test.mjs`
Expected: PASS

- [ ] **Step 2: Run the broader docs regression tests**

Run: `node --test www/tests/cloud-onboarding-docs.test.mjs www/tests/community-docs-nav.test.mjs`
Expected: PASS

- [ ] **Step 3: Run a production docs build**

Run: `npm --prefix www run build`
Expected: PASS with a generated route for `/docs/how-to/customize-the-appliance-image-at-first-boot/`.

- [ ] **Step 4: Inspect recent docs-only history for accidental scope creep**

Run: `git log --stat --oneline --max-count 6 -- www/src www/tests`
Expected: only the new customization how-to, its links, nav entry, and related tests appear.

- [ ] **Step 5: Note the `astro check` limitation**

Run: `npm --prefix www run check`
Expected: interactive prompt for missing `@astrojs/check`; document that this repo-level tooling gap remains and is not introduced by this change.
