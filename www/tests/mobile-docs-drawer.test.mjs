import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';

test('docs layout uses a mobile browse-docs drawer while keeping the desktop sidebar', () => {
  const layout = readFileSync(new URL('../src/layouts/DocsLayout.astro', import.meta.url), 'utf8');
  const sidebar = readFileSync(new URL('../src/components/docs/DocsSidebar.astro', import.meta.url), 'utf8');
  const mobileNavUrl = new URL('../src/components/docs/DocsMobileNav.astro', import.meta.url);

  assert.match(layout, /import DocsMobileNav from '\.\.\/components\/docs\/DocsMobileNav\.astro';/);
  assert.match(layout, /<DocsMobileNav currentPath=\{currentPath\} \/>/);
  assert.match(sidebar, /hidden lg:block/);
  assert.match(layout, /pt-6 pb-12 [^"]*lg:py-12/);
  assert.equal(existsSync(mobileNavUrl), true, 'expected a dedicated DocsMobileNav component');

  const mobileNav = readFileSync(mobileNavUrl, 'utf8');
  assert.match(mobileNav, /sticky top-20 [^"]*px-4 py-3/);
  assert.doesNotMatch(mobileNav, /sticky top-20 [^"]*border-b/);
  assert.doesNotMatch(mobileNav, /sticky top-20 [^"]*bg-\[var\(--bg\)\]/);
  assert.match(mobileNav, />\s*Browse docs\s*</);
  assert.match(mobileNav, /aria-controls="docs-mobile-drawer"/);
  assert.match(mobileNav, /role="dialog"/);
  assert.match(mobileNav, /bg-\[var\(--bg\)\]/);
});
