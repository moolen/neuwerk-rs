import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function assertAstroHref(source, href, message) {
  const escapedHref = escapeRegex(href);
  assert.match(source, new RegExp(`href\\s*=\\s*"${escapedHref}"`), message);
}

function assertAstroFrontmatterHref(source, href, message) {
  const escapedHref = escapeRegex(href);
  assert.match(source, new RegExp(`href\\s*:\\s*'${escapedHref}'`), message);
}

function assertMdxLink(source, href, message) {
  const escapedHref = escapeRegex(href);
  assert.match(
    source,
    new RegExp(`(\\[[^\\]]+\\]\\(${escapedHref}\\)|<a\\s+[^>]*href\\s*=\\s*["']${escapedHref}["'][^>]*>)`),
    message,
  );
}

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
  assert.doesNotMatch(
    navSource,
    /href: '\/docs\/tutorials\/deploy-a-single-node'/,
    'expected /docs/tutorials/deploy-a-single-node to be removed from navigation',
  );
  assert.doesNotMatch(
    navSource,
    /href: '\/docs\/tutorials\/build-a-two-node-cluster'/,
    'expected /docs/tutorials/build-a-two-node-cluster to be removed from navigation',
  );
});

test('docs index links to cloud-first onboarding and rollout concepts pages', () => {
  const docsIndex = readFileSync(new URL('../src/pages/docs/index.astro', import.meta.url), 'utf8');
  assertAstroHref(
    docsIndex,
    '/docs/tutorials/launch-from-released-cloud-image',
    'expected docs index to reference /docs/tutorials/launch-from-released-cloud-image',
  );
  assertAstroHref(
    docsIndex,
    '/docs/architecture/cloud-rollout-integration',
    'expected docs index to reference /docs/architecture/cloud-rollout-integration',
  );
});

test('footer links to cloud-first onboarding path', () => {
  const footer = readFileSync(new URL('../src/components/common/Footer.astro', import.meta.url), 'utf8');
  assertAstroFrontmatterHref(
    footer,
    '/docs/tutorials/launch-from-released-cloud-image',
    'expected footer to reference /docs/tutorials/launch-from-released-cloud-image',
  );
});

test('deployment requirements page links to cloud-first onboarding path', () => {
  const requirements = readFileSync(new URL('../src/content/docs/deployment/requirements.mdx', import.meta.url), 'utf8');
  assertMdxLink(
    requirements,
    '/docs/tutorials/launch-from-released-cloud-image',
    'expected deployment requirements to reference /docs/tutorials/launch-from-released-cloud-image',
  );
});

test('release process page links to cloud-first onboarding path', () => {
  const releaseProcess = readFileSync(new URL('../src/content/docs/community/release-process.mdx', import.meta.url), 'utf8');
  assertMdxLink(
    releaseProcess,
    '/docs/tutorials/launch-from-released-cloud-image',
    'expected release process to reference /docs/tutorials/launch-from-released-cloud-image',
  );
});

test('upgrade-a-cluster page links to cloud rollout integration page', () => {
  const upgradeCluster = readFileSync(new URL('../src/content/docs/how-to/upgrade-a-cluster.mdx', import.meta.url), 'utf8');
  assertMdxLink(
    upgradeCluster,
    '/docs/architecture/cloud-rollout-integration',
    'expected upgrade a cluster to reference /docs/architecture/cloud-rollout-integration',
  );
});

test('launch-from-released-cloud-image docs page exists', () => {
  const fileUrl = new URL('../src/content/docs/tutorials/launch-from-released-cloud-image.mdx', import.meta.url);
  assert.equal(existsSync(fileUrl), true, 'expected tutorials/launch-from-released-cloud-image.mdx to exist');
});

test('cloud-rollout-integration docs page exists', () => {
  const fileUrl = new URL('../src/content/docs/architecture/cloud-rollout-integration.mdx', import.meta.url);
  assert.equal(existsSync(fileUrl), true, 'expected architecture/cloud-rollout-integration.mdx to exist');
});
