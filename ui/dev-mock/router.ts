import type { IncomingMessage, ServerResponse } from 'node:http';

import { jsonResponse } from './http';
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

function writeNodeResponse(res: ServerResponse, response: MockResponse): void {
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
  res.end(response.text ?? '');
}

function routeKey(method: string, pathname: string): string {
  return `${method.toUpperCase()} ${pathname}`;
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

export function createMockRouter(options: MockRouterOptions = {}): MockRouter {
  const routes = new Map<string, MockRoute>();
  for (const route of options.routes ?? []) {
    routes.set(routeKey(route.method, route.pathname), route);
  }

  return {
    async handle(request: MockIncomingRequest): Promise<MockResponse | undefined> {
      const normalized = normalizeRequest(request);

      if (
        normalized.pathname !== API_PREFIX &&
        !normalized.pathname.startsWith(`${API_PREFIX}/`)
      ) {
        return undefined;
      }

      const route = routes.get(routeKey(normalized.method, normalized.pathname));
      if (!route) {
        return jsonResponse({ error: 'Not found' }, { status: 404 });
      }

      return route.handler(normalized);
    },

    async handleNodeRequest(req: IncomingMessage, res: ServerResponse): Promise<boolean> {
      const response = await this.handle({
        method: req.method ?? 'GET',
        url: req.url ?? '/',
        headers: normalizeHeaders(req.headers),
        body: await readBody(req),
      });

      if (!response) {
        return false;
      }

      writeNodeResponse(res, response);
      return true;
    },
  };
}
