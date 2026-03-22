import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';

test('docs navigation promotes cloud onboarding and removes obsolete getting started entries', () => {
  const navSource = readFileSync(new URL('../src/data/docsNavigation.ts', import.meta.url), 'utf8');

  assert.match(
    navSource,
    /href: '\/docs\/tutorials\/launch-from-released-cloud-image', label: 'Launch Neuwerk From The Released Cloud Image'/,
  );
  assert.match(
    navSource,
    /href: '\/docs\/architecture\/cloud-rollout-integration', label: 'Cloud Rollout Integration'/,
  );
  assert.doesNotMatch(navSource, /label: 'Deploy A Single Node'/);
  assert.doesNotMatch(navSource, /label: 'Build A Two-Node Cluster'/);
});

test('site entry points and docs pages link to the cloud-first onboarding path', () => {
  const docsIndex = readFileSync(new URL('../src/pages/docs/index.astro', import.meta.url), 'utf8');
  assert.match(
    docsIndex,
    /\/docs\/tutorials\/launch-from-released-cloud-image/,
    'expected docs index to reference /docs/tutorials/launch-from-released-cloud-image',
  );
  assert.match(
    docsIndex,
    /\/docs\/architecture\/cloud-rollout-integration/,
    'expected docs index to reference /docs/architecture/cloud-rollout-integration',
  );

  const footer = readFileSync(new URL('../src/components/common/Footer.astro', import.meta.url), 'utf8');
  assert.match(
    footer,
    /\/docs\/tutorials\/launch-from-released-cloud-image/,
    'expected footer to reference /docs/tutorials/launch-from-released-cloud-image',
  );

  const requirements = readFileSync(new URL('../src/content/docs/deployment/requirements.mdx', import.meta.url), 'utf8');
  assert.match(
    requirements,
    /\/docs\/tutorials\/launch-from-released-cloud-image/,
    'expected deployment requirements to reference /docs/tutorials/launch-from-released-cloud-image',
  );

  const releaseProcess = readFileSync(new URL('../src/content/docs/community/release-process.mdx', import.meta.url), 'utf8');
  assert.match(
    releaseProcess,
    /\/docs\/tutorials\/launch-from-released-cloud-image/,
    'expected release process to reference /docs/tutorials/launch-from-released-cloud-image',
  );

  const upgradeCluster = readFileSync(new URL('../src/content/docs/how-to/upgrade-a-cluster.mdx', import.meta.url), 'utf8');
  assert.match(
    upgradeCluster,
    /\/docs\/architecture\/cloud-rollout-integration/,
    'expected upgrade a cluster to reference /docs/architecture/cloud-rollout-integration',
  );
});

test('new cloud onboarding docs pages exist', () => {
  const expectedPages = [
    '../src/content/docs/tutorials/launch-from-released-cloud-image.mdx',
    '../src/content/docs/architecture/cloud-rollout-integration.mdx',
  ];

  for (const relativePath of expectedPages) {
    const fileUrl = new URL(relativePath, import.meta.url);
    assert.equal(existsSync(fileUrl), true, `expected ${relativePath} to exist`);
  }
});
