import type { Plugin } from 'vite';

import { createMockRouter } from './router';

export function neuwerkDevMockPlugin(): Plugin {
  return {
    name: 'neuwerk-dev-mock',
    apply: 'serve',
    configureServer(server) {
      const router = createMockRouter();
      server.middlewares.use(async (req, res, next) => {
        const handled = await router.handleNodeRequest(req, res);
        if (!handled) {
          next();
        }
      });
    },
  };
}
