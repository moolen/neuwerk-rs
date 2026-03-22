import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';

test('docs navigation includes a bottom community section with release and community pages', () => {
  const navSource = readFileSync(new URL('../src/data/docsNavigation.ts', import.meta.url), 'utf8');

  assert.match(navSource, /title: 'Community'/);
  assert.match(navSource, /href: '\/docs\/community\/launch-checklist', label: 'Launch Checklist'/);
  assert.match(navSource, /href: '\/docs\/community\/release-process', label: 'Release Process'/);
  assert.match(navSource, /href: '\/docs\/community\/release-readiness', label: 'OSS Release Readiness'/);
  assert.match(navSource, /href: '\/docs\/community\/contributing', label: 'Contributing'/);
  assert.match(navSource, /href: '\/docs\/community\/security', label: 'Security'/);

  const referenceIndex = navSource.indexOf("title: 'Reference'");
  const communityIndex = navSource.indexOf("title: 'Community'");
  assert.notEqual(referenceIndex, -1, 'expected Reference section');
  assert.notEqual(communityIndex, -1, 'expected Community section');
  assert.ok(communityIndex > referenceIndex, 'expected Community to appear after Reference');
});

test('community docs pages exist and repo markdown points to canonical docs pages', () => {
  const communityPages = [
    '../src/content/docs/community/launch-checklist.mdx',
    '../src/content/docs/community/release-process.mdx',
    '../src/content/docs/community/release-readiness.mdx',
    '../src/content/docs/community/contributing.mdx',
    '../src/content/docs/community/security.mdx',
  ];

  for (const relativePath of communityPages) {
    const fileUrl = new URL(relativePath, import.meta.url);
    assert.equal(existsSync(fileUrl), true, `expected ${relativePath} to exist`);
  }

  const contributing = readFileSync(new URL('../../CONTRIBUTING.md', import.meta.url), 'utf8');
  const security = readFileSync(new URL('../../SECURITY.md', import.meta.url), 'utf8');
  assert.match(contributing, /\/docs\/community\/contributing/);
  assert.match(security, /\/docs\/community\/security/);
});
