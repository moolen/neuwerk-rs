import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

test('policy code area is width constrained and scrolls horizontally inside the code pane', () => {
  const source = readFileSync(new URL('../src/components/marketing/DNSEnforcement.astro', import.meta.url), 'utf8');

  assert.match(source, /<!-- Policy example -->\s*<div class="min-w-0">/s);
  assert.match(source, /<div class="[^"]*max-w-full[^"]*overflow-hidden[^"]*bg-slate-900[^"]*">/);
  assert.match(source, /<div class="code-block[^"]*max-w-full[^"]*overflow-x-auto[^"]*overflow-y-hidden[^"]*"/);
});
