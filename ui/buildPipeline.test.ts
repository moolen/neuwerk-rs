import { execFileSync } from 'node:child_process';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, test } from 'vitest';

const uiDir = new URL('.', import.meta.url).pathname;
const distAssetsDir = join(uiDir, 'dist', 'assets');
const distHtmlPath = join(uiDir, 'dist', 'index.html');

function buildUi() {
  execFileSync('npm', ['run', 'build'], {
    cwd: uiDir,
    stdio: 'pipe',
  });
}

function readBundledCss(): string {
  const cssFile = readdirSync(distAssetsDir).find((name) => name.endsWith('.css'));
  if (!cssFile) {
    throw new Error('expected a bundled CSS asset');
  }
  return readFileSync(join(distAssetsDir, cssFile), 'utf8');
}

describe('UI build pipeline', () => {
  test('emits local utility CSS required by the layout shell', () => {
    buildUi();

    const html = readFileSync(distHtmlPath, 'utf8');
    const css = readBundledCss();

    expect(html).toContain('/assets/');
    expect(css).toMatch(/\.flex\{display:flex/);
    expect(css).toMatch(/\.h-screen\{height:100vh/);
  }, 20000);
});
