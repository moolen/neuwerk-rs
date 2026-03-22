import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';

test('docs navigation promotes cloud onboarding and removes obsolete getting started entries', () => {
  const navSource = readFileSync(new URL('../src/data/docsNavigation.ts', import.meta.url), 'utf8');
  const gettingStartedStart = navSource.indexOf("title: 'Getting Started'");
  const howToStart = navSource.indexOf("title: 'How-To Guides'");
  const conceptsStart = navSource.indexOf("title: 'Concepts'");
  const referenceStart = navSource.indexOf("title: 'Reference'");

  assert.notEqual(gettingStartedStart, -1, 'expected Getting Started section');
  assert.notEqual(howToStart, -1, 'expected How-To Guides section');
  assert.notEqual(conceptsStart, -1, 'expected Concepts section');
  assert.notEqual(referenceStart, -1, 'expected Reference section');
  assert.ok(gettingStartedStart < howToStart, 'expected Getting Started before How-To Guides');
  assert.ok(conceptsStart < referenceStart, 'expected Concepts before Reference');

  const gettingStartedSection = navSource.slice(gettingStartedStart, howToStart);
  const conceptsSection = navSource.slice(conceptsStart, referenceStart);

  assert.match(
    gettingStartedSection,
    /href: '\/docs\/tutorials\/launch-from-released-cloud-image'/,
    'expected Getting Started section to include /docs/tutorials/launch-from-released-cloud-image',
  );
  assert.match(
    conceptsSection,
    /href: '\/docs\/architecture\/cloud-rollout-integration'/,
    'expected Concepts section to include /docs/architecture/cloud-rollout-integration',
  );
  assert.doesNotMatch(navSource, /href: '\/docs\/tutorials\/deploy-a-single-node'/);
  assert.doesNotMatch(navSource, /href: '\/docs\/tutorials\/build-a-two-node-cluster'/);
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
