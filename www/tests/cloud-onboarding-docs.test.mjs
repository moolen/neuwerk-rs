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
  const expectedCloudPath = '/docs/tutorials/launch-from-released-cloud-image';
  const filesToCheck = [
    '../src/pages/docs/index.astro',
    '../src/components/common/Footer.astro',
    '../src/content/docs/deployment/requirements.mdx',
    '../src/content/docs/community/release-process.mdx',
    '../src/content/docs/how-to/upgrade-a-cluster.mdx',
  ];

  for (const relativePath of filesToCheck) {
    const source = readFileSync(new URL(relativePath, import.meta.url), 'utf8');
    assert.match(source, new RegExp(expectedCloudPath.replaceAll('/', '\\/')), `expected ${relativePath} to reference ${expectedCloudPath}`);
  }
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
