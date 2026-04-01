import { execFileSync } from 'node:child_process';
import { mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, expect, test } from 'vitest';

const uiDir = new URL('.', import.meta.url).pathname;

function buildUi(outDir: string) {
  execFileSync('npm', ['run', 'build', '--', '--outDir', outDir, '--emptyOutDir'], {
    cwd: uiDir,
    stdio: 'pipe',
  });
}

function readBundledCss(outDir: string): string {
  const distAssetsDir = join(outDir, 'assets');
  const cssFile = readdirSync(distAssetsDir).find((name) => name.endsWith('.css'));
  if (!cssFile) {
    throw new Error('expected a bundled CSS asset');
  }
  return readFileSync(join(distAssetsDir, cssFile), 'utf8');
}

describe('UI build pipeline', () => {
  test('emits local utility CSS required by the layout shell', () => {
    const outDir = mkdtempSync(join(tmpdir(), 'neuwerk-ui-build-'));

    try {
      buildUi(outDir);

      const html = readFileSync(join(outDir, 'index.html'), 'utf8');
      const css = readBundledCss(outDir);

      expect(html).toContain('/assets/');
      expect(css).toMatch(/\.flex\{display:flex/);
      expect(css).toMatch(/\.h-screen\{height:100vh/);
    } finally {
      rmSync(outDir, { recursive: true, force: true });
    }
  }, 20000);
});
