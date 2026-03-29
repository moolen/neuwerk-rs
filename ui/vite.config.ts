import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import { neuwerkDevMockPlugin } from './dev-mock/plugin';

export default defineConfig(({ command }) => ({
  plugins: [react(), command === 'serve' ? neuwerkDevMockPlugin() : null].filter(
    (plugin): plugin is NonNullable<typeof plugin> => plugin !== null
  ),
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
  test: {
    environment: 'node',
    include: ['**/*.test.ts', '**/*.test.tsx'],
  },
}));
