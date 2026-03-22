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
  assert.doesNotMatch(
    docsIndex,
    /href\s*=\s*"\/docs\/tutorials\/deploy-a-single-node"/,
    'expected docs index to exclude /docs/tutorials/deploy-a-single-node',
  );
  assert.doesNotMatch(
    docsIndex,
    /href\s*=\s*"\/docs\/tutorials\/build-a-two-node-cluster"/,
    'expected docs index to exclude /docs/tutorials/build-a-two-node-cluster',
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

test('legacy tutorials are kept as compatibility pages and point to the cloud-first path', () => {
  const singleNode = readFileSync(
    new URL('../src/content/docs/tutorials/deploy-a-single-node.mdx', import.meta.url),
    'utf8',
  );
  const twoNode = readFileSync(
    new URL('../src/content/docs/tutorials/build-a-two-node-cluster.mdx', import.meta.url),
    'utf8',
  );

  assert.match(
    singleNode,
    /obsolete/i,
    'expected deploy-a-single-node tutorial to call out obsolete onboarding status',
  );
  assert.match(
    twoNode,
    /obsolete/i,
    'expected build-a-two-node-cluster tutorial to call out obsolete onboarding status',
  );
  assertMdxLink(
    singleNode,
    '/docs/tutorials/launch-from-released-cloud-image',
    'expected deploy-a-single-node tutorial to reference /docs/tutorials/launch-from-released-cloud-image',
  );
  assertMdxLink(
    twoNode,
    '/docs/tutorials/launch-from-released-cloud-image',
    'expected build-a-two-node-cluster tutorial to reference /docs/tutorials/launch-from-released-cloud-image',
  );
  assertMdxLink(
    twoNode,
    '/docs/tutorials/create-your-first-policy',
    'expected build-a-two-node-cluster tutorial to reference /docs/tutorials/create-your-first-policy',
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
