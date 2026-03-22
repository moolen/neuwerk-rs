# Cloud Onboarding Docs Redesign

## Goal

Replace the obsolete single-node and two-node getting-started tutorials with one cloud-first guide
that walks operators through importing the released Neuwerk image into AWS, Azure, or GCP,
configuring first boot with cloud-init or equivalent instance metadata, and then points them to a
new concepts page that explains cloud rollout and upgrade behavior in autoscaling environments.

## Why This Change

The current published docs split first-time operators across:

- a single-node tutorial that assumes direct CLI startup flags
- a two-node tutorial that assumes manual cluster bootstrapping
- a lower-level appliance image usage runbook outside the published website docs

That structure no longer matches the primary user journey:

- cloud users consume the released image artifact, not a raw binary
- cloud users need image conversion and import commands on day one
- cloud users need to understand replacement-based upgrades early, especially when running behind
  AWS Auto Scaling Groups, Azure VM Scale Sets, or GCP managed instance groups

## Audience

Primary audience:

- operators deploying Neuwerk from the published image artifact in AWS, Azure, or GCP

Secondary audience:

- evaluators who want to understand the supported cloud deployment contract before adopting
  Neuwerk

Out of scope:

- local Vagrant evaluation, except as an alternate path
- provider-specific Terraform walkthroughs
- image build pipeline internals

## Problems In The Current Information Architecture

1. Getting Started is still organized around deployment shapes rather than the actual distribution
   artifact.
2. The cloud import commands exist in repo docs but not in the published docs entry path.
3. Upgrade guidance does not clearly teach the difference between:
   - a standalone VM restart or replacement
   - a cloud-managed replacement rollout through ASG, VMSS, or MIG primitives
4. Cloud integration settings exist in runtime examples and cloud-test templates, but not as a
   stable published concept for operators.

## Proposed User Journey

The intended cloud-user path becomes:

1. Read `Requirements`
2. Follow `Launch Neuwerk From The Released Cloud Image`
3. Continue to `Get Admin Access`
4. Continue to `Create Your First Policy`
5. Read `Cloud Rollout Integration`
6. Use `Upgrade A Cluster` and `Upgrade, Rollback & DR` for day-2 operations

The Vagrant demo remains available for local evaluation, but it is no longer the default production
onboarding path.

## Proposed Published Docs Changes

### 1. Replace Obsolete Getting Started Tutorials

Remove these pages from the primary onboarding flow:

- `tutorials/deploy-a-single-node`
- `tutorials/build-a-two-node-cluster`

Add one new page in Getting Started:

- `tutorials/launch-from-released-cloud-image`

This page becomes the cloud-first onboarding guide.

### 2. Add A New Concepts Page

Add:

- `concepts/cloud-rollout-integration`

This page explains the cloud-specific integration model without turning Getting Started into a
large operations manual.

### 3. Refresh The Docs Landing Page And Navigation

Update the docs index and sidebar navigation so they say:

- cloud image deployment is the primary production path
- Vagrant is the local demo path
- the new concepts page is the place to learn restart, rollout, and replacement behavior in cloud
  environments

### 4. Tighten Upgrade Cross-Links

Update `Upgrade A Cluster` so it explicitly links to the new concepts page when the deployment is
backed by ASG, VMSS, or MIG replacement workflows.

## New Guide: `Launch Neuwerk From The Released Cloud Image`

### Positioning

This page should assume the user wants a first supported cloud deployment from the released image,
not a hand-built binary install.

### Core Outcomes

By the end of the guide, the user should have:

- downloaded and verified a release
- restored the published `qcow2`
- converted and imported that image into AWS, Azure, or GCP
- launched one Neuwerk VM with separate management and dataplane NICs
- configured `/etc/neuwerk/appliance.env` or equivalent cloud-init content
- restarted `neuwerk.service`
- verified health, readiness, and first admin access
- understood where to read next before adopting autoscaling or rolling replacement

### Required Content Sections

1. `Before You Start`
   - release assets
   - tooling requirements: `qemu-img`, provider CLI, checksum tooling
   - two-NIC expectation
   - reminder that the image is the primary artifact

2. `Download And Verify The Release`
   - reuse the existing signing and checksum flow

3. `Restore The Published qcow2`
   - reuse `restore-qcow2.sh`

4. `Choose Your Cloud`
   - AWS import commands
   - Azure fixed-VHD conversion and import commands
   - GCP raw-disk packaging and image creation commands

5. `Configure First Boot`
   - explain `/etc/neuwerk/appliance.env`
   - explain when to use `NEUWERK_BOOTSTRAP_*`
   - provide a cloud-init friendly example
   - explain that cloud-init or startup metadata should write operator intent, not a fully expanded
     Neuwerk command line

6. `Start And Verify Neuwerk`
   - `systemctl restart neuwerk.service`
   - `journalctl`
   - `/health`
   - `/ready`
   - first admin token or link to `Get Admin Access`

7. `What To Read Before Production Rollout`
   - link to `Cloud Rollout Integration`
   - link to `Upgrade A Cluster`
   - link to `High Availability`

### Content Strategy

The provider conversion and import commands should be in this page, not hidden behind a separate
operations runbook. The quickstart must answer the first real operator question: "How do I turn the
released artifact into a bootable cloud image?"

## New Concepts Page: `Cloud Rollout Integration`

### Purpose

Explain the operational model for cloud-managed restarts and replacements so users understand the
upgrade contract before they adopt ASGs, VMSS, or MIGs.

### Core Topics

1. `What The Integration Does`
   - readiness becomes false while draining
   - termination notices trigger drain behavior when supported
   - the integration coordinates with cloud replacement workflows rather than doing in-place OS
     upgrades

2. `Standalone VM Versus Managed Group`
   - standalone VM: operator controls restarts and replacements directly
   - managed group: operator updates the image/model and lets the cloud platform replace instances

3. `Provider Mapping`
   - AWS: `--integration aws-asg`, lifecycle hook expectations, ASG replacement behavior
   - Azure: `--integration azure-vmss`, VMSS replacement behavior
   - GCP: `--integration gcp-mig`, MIG-based replacement behavior

4. `How To Configure Appliance Bootstrap`
   - use cloud-init, user data, custom data, or startup metadata to write:
     - `NEUWERK_BOOTSTRAP_*` values for derived runtime settings
     - plain `NEUWERK_*` values for integration-specific pass-through values
   - examples:
     - `NEUWERK_INTEGRATION_MODE`
     - `NEUWERK_AWS_REGION`
     - `NEUWERK_AWS_VPC_ID`
     - `NEUWERK_AWS_ASG_NAME`
     - `NEUWERK_AZURE_SUBSCRIPTION_ID`
     - `NEUWERK_AZURE_RESOURCE_GROUP`
     - `NEUWERK_AZURE_VMSS_NAME`
     - `NEUWERK_GCP_PROJECT`
     - `NEUWERK_GCP_REGION`
     - `NEUWERK_GCP_IG_NAME`

5. `Recommended Upgrade Model`
   - publish/import the new image
   - update the launch template, image reference, or instance template
   - roll replacements gradually
   - watch readiness and drain-related signals during the rollout

6. `What Not To Do`
   - do not treat cloud-managed fleets like pet VMs
   - do not assume in-place package upgrades are the primary supported path
   - do not rely on a single NIC layout

### Tone

This page should be explanatory, not step-by-step. It should teach the model that the how-to pages
and upgrade runbooks depend on.

## Bootstrap Configuration Guidance

The docs should explicitly teach this split:

- `NEUWERK_BOOTSTRAP_*` is for operator intent that the appliance derives at service start
- plain `NEUWERK_*` is for advanced runtime pass-through settings, including cloud integration
  identifiers

That distinction is already present in the packaged runtime examples and should become a first-class
published concept.

The cloud-first guide should include one generic example showing how cloud-init writes
`/etc/neuwerk/appliance.env`, and the concepts page should explain why that pattern is preferred in
replacement-based rollouts.

## Existing Content To Reuse Or Fold In

Primary source material already exists in:

- `docs/operations/appliance-image-usage.md`
- `www/src/content/docs/deployment/requirements.mdx`
- `www/src/content/docs/how-to/upgrade-a-cluster.mdx`
- `packaging/runtime/appliance.env`
- `packaging/runtime/neuwerk-bootstrap.sh`
- `packaging/runtime/neuwerk-launch.sh`

The implementation should reuse that language where possible rather than inventing a second model.

## Navigation Changes

### Getting Started

Keep:

- `Run The Vagrant Demo Box`
- `Create Your First Policy`

Replace:

- `Deploy A Single Node`
- `Build A Two-Node Cluster`

With:

- `Launch Neuwerk From The Released Cloud Image`

### Concepts

Add:

- `Cloud Rollout Integration`

### Docs Index Copy

Revise the homepage summary so it no longer says most operators continue through the obsolete
single-node and two-node tutorials. It should instead describe:

- local demo path
- cloud-first production path
- where to learn rollout/upgrade behavior

## URL And Compatibility Considerations

If the old pages are already linked externally, prefer one of these:

- keep short stub pages that redirect users to the new cloud-first guide and relevant deployment
  pages
- or keep the URLs but rewrite their content into short compatibility notes

Avoid silently deleting well-known entry points without replacement.

## Review Criteria

The final docs change is successful if:

1. A new cloud operator can reach image import commands from the published Getting Started path in
   one click.
2. The guide clearly distinguishes first-boot setup from cloud-managed replacement rollout.
3. The docs teach how to express runtime intent through `appliance.env` and cloud-init rather than
   ad hoc manual command lines.
4. The docs landing page and nav no longer steer operators into obsolete single-node or two-node
   onboarding flows.
5. Upgrade docs link to the cloud integration concept instead of assuming only manual rolling node
   restarts.

## Implementation Notes

The implementation should stay documentation-only. No runtime behavior changes are required.

Likely edited files:

- `www/src/content/docs/tutorials/deploy-a-single-node.mdx`
- `www/src/content/docs/tutorials/build-a-two-node-cluster.mdx`
- `www/src/content/docs/tutorials/launch-from-released-cloud-image.mdx` (new)
- `www/src/content/docs/architecture/cloud-rollout-integration.mdx` or equivalent concepts path
  (new)
- `www/src/content/docs/how-to/upgrade-a-cluster.mdx`
- `www/src/pages/docs/index.astro`
- `www/src/data/docsNavigation.ts`

## Inline Review Notes

This design intentionally does not create separate AWS, Azure, and GCP getting-started guides
because that would duplicate most of the image and bootstrap contract. Provider-specific commands
belong inside one guide; provider-specific operational behavior belongs in one concepts page.
