import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

test('marketing surface points at the current repo and describes Neuwerk TLS interception correctly', () => {
  const repoUrl = 'https://github.com/moolen/neuwerk-rs';

  const comparison = readFileSync(
    new URL('../src/components/marketing/ComparisonTable.astro', import.meta.url),
    'utf8',
  );
  assert.match(comparison, /approach: 'Neuwerk'[\s\S]*tlsInspection: 'Optional'/);

  const repoLinkedFiles = [
    '../src/components/common/Header.astro',
    '../src/components/common/Footer.astro',
    '../src/components/marketing/Hero.astro',
    '../src/components/marketing/OpenSourceSection.astro',
    '../src/components/marketing/CTASection.astro',
    '../src/components/marketing/GettingStarted.astro',
    '../src/components/marketing/PricingSection.astro',
  ];

  for (const relativePath of repoLinkedFiles) {
    const source = readFileSync(new URL(relativePath, import.meta.url), 'utf8');
    assert.match(source, new RegExp(repoUrl.replaceAll('/', '\\/')));
    assert.doesNotMatch(source, /https:\/\/github\.com\/moolen\/neuwerk(?!-rs)/);
  }
});
