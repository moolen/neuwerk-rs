import type { IncomingMessage, ServerResponse } from 'node:http';

import { jsonResponse } from './http';
import { createIntegrationRoutes } from './routes/integrations';
import { createPolicyRoutes } from './routes/policies';
import { createServiceAccountRoutes } from './routes/serviceAccounts';
import { createSettingsWriteRoutes } from './routes/settings-write';
import { createSsoRoutes } from './routes/sso';
import { createWiretapRoutes } from './routes/wiretap';
import { createReadDomainRoutes } from './seed';
import { createMockState } from './state';
import type {
  MockIncomingRequest,
  MockRequest,
  MockResponse,
  MockRoute,
  MockRouter,
  MockRouterOptions,
} from './types';

const API_PREFIX = '/api/v1';

function normalizeHeaders(headers: IncomingMessage['headers']): Record<string, string> {
  const normalized: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    if (typeof value === 'string') {
      normalized[key.toLowerCase()] = value;
      continue;
    }
    if (Array.isArray(value)) {
      normalized[key.toLowerCase()] = value.join(', ');
    }
  }
  return normalized;
}

function readBody(req: IncomingMessage): Promise<Buffer | undefined> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk) => {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    });
    req.on('end', () => {
      resolve(chunks.length > 0 ? Buffer.concat(chunks) : undefined);
    });
    req.on('error', reject);
  });
}

function writeNodeResponse(
  req: IncomingMessage,
  res: ServerResponse,
  response: MockResponse
): void {
  res.statusCode = response.status;
  for (const [name, value] of Object.entries(response.headers)) {
    res.setHeader(name, value);
  }

  if (response.kind === 'json') {
    res.end(JSON.stringify(response.json ?? null));
    return;
  }
  if (response.kind === 'blob') {
    res.end(response.body ? Buffer.from(response.body) : Buffer.alloc(0));
    return;
  }
  if (response.kind === 'sse-stream') {
    response.stream?.(req, res);
    return;
  }
  res.end(response.text ?? '');
}

function routeKey(method: string, pathname: string): string {
  return `${method.toUpperCase()} ${pathname}`;
}

function escapeRegex(input: string): string {
  return input.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function compilePattern(pathname: string): RegExp | undefined {
  if (!pathname.includes(':')) {
    return undefined;
  }
  const parts = pathname.split('/').map((segment) => {
    if (segment.startsWith(':')) {
      return '[^/]+';
    }
    return escapeRegex(segment);
  });
  return new RegExp(`^${parts.join('/')}$`);
}

function normalizeRequest(raw: MockIncomingRequest): MockRequest {
  const parsed = new URL(raw.url, 'http://neuwerk.dev');
  return {
    ...raw,
    method: raw.method.toUpperCase(),
    headers: normalizeHeaders(raw.headers),
    pathname: parsed.pathname,
  };
}

function isApiPath(pathname: string): boolean {
  return pathname === API_PREFIX || pathname.startsWith(`${API_PREFIX}/`);
}

export function createMockRouter(options: MockRouterOptions = {}): MockRouter {
  const exactRoutes = new Map<string, MockRoute>();
  const patternRoutes: Array<{ method: string; pattern: RegExp; route: MockRoute }> = [];
  const state = createMockState();

  function addRoute(route: MockRoute): void {
    const pattern = compilePattern(route.pathname);
    if (pattern) {
      const method = route.method.toUpperCase();
      const index = patternRoutes.findIndex(
        (entry) => entry.method === method && entry.route.pathname === route.pathname
      );
      if (index >= 0) {
        patternRoutes.splice(index, 1);
      }
      patternRoutes.push({ method, pattern, route });
      return;
    }
    exactRoutes.set(routeKey(route.method, route.pathname), route);
  }

  for (const route of [
    ...createReadDomainRoutes(state),
    ...createPolicyRoutes(state),
    ...createIntegrationRoutes(state),
    ...createServiceAccountRoutes(state),
    ...createSettingsWriteRoutes(state),
    ...createSsoRoutes(state),
    ...createWiretapRoutes(),
  ]) {
    addRoute(route);
  }
  for (const route of options.routes ?? []) {
    addRoute(route);
  }

  return {
    async handle(request: MockIncomingRequest): Promise<MockResponse | undefined> {
      const normalized = normalizeRequest(request);

      if (!isApiPath(normalized.pathname)) {
        return undefined;
      }

      let route = exactRoutes.get(routeKey(normalized.method, normalized.pathname));
      if (!route) {
        route = patternRoutes.find(
          (entry) =>
            entry.method === normalized.method &&
            entry.pattern.test(normalized.pathname)
        )?.route;
      }
      if (!route) {
        return jsonResponse({ error: 'Not found' }, { status: 404 });
      }

      return route.handler(normalized);
    },

    async handleNodeRequest(req: IncomingMessage, res: ServerResponse): Promise<boolean> {
      const pathname = new URL(req.url ?? '/', 'http://neuwerk.dev').pathname;
      if (!isApiPath(pathname)) {
        return false;
      }

      const response = await this.handle({
        method: req.method ?? 'GET',
        url: req.url ?? '/',
        headers: normalizeHeaders(req.headers),
        body: await readBody(req),
      });

      if (!response) {
        return false;
      }

      writeNodeResponse(req, res, response);
      return true;
    },
  };
}
