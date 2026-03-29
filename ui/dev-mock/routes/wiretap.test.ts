import { createServer, request as httpRequest } from 'node:http';
import { EventEmitter, once } from 'node:events';

import { afterEach, describe, expect, it, vi } from 'vitest';

import { createMockRouter } from '../router';
import { createWiretapRoutes } from './wiretap';

function streamBodyUntil(
  body: NodeJS.ReadableStream,
  predicate: (buffer: string) => boolean
): Promise<string> {
  return new Promise((resolve, reject) => {
    let buffer = '';
    const timeout = setTimeout(() => {
      cleanup();
      reject(new Error('Timed out waiting for SSE chunks'));
    }, 2_500);

    const onData = (chunk: Buffer | string) => {
      buffer += chunk.toString();
      if (predicate(buffer)) {
        cleanup();
        resolve(buffer);
      }
    };

    const onError = (error: Error) => {
      cleanup();
      reject(error);
    };

    const cleanup = () => {
      clearTimeout(timeout);
      body.off('data', onData);
      body.off('error', onError);
    };

    body.on('data', onData);
    body.on('error', onError);
  });
}

describe('dev mock wiretap stream route', () => {
  const openServers = new Set<ReturnType<typeof createServer>>();

  afterEach(async () => {
    await Promise.all(
      Array.from(openServers, async (server) => {
        await new Promise<void>((resolve, reject) => {
          server.close((error) => {
            if (error) {
              reject(error);
              return;
            }
            resolve();
          });
        });
      })
    );
    openServers.clear();
  });

  it('opens event stream and emits flow + flow_end payloads in wiretap shape', async () => {
    const router = createMockRouter();
    const server = createServer(async (req, res) => {
      const handled = await router.handleNodeRequest(req, res);
      if (!handled) {
        res.statusCode = 404;
        res.end('not found');
      }
    });
    openServers.add(server);

    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    const address = server.address();
    if (!address || typeof address === 'string') {
      throw new Error('Expected tcp server address');
    }

    const response = await new Promise<import('node:http').IncomingMessage>(
      (resolve, reject) => {
        const req = httpRequest(
          {
            method: 'GET',
            host: '127.0.0.1',
            port: address.port,
            path: '/api/v1/wiretap/stream',
          },
          resolve
        );
        req.on('error', reject);
        req.end();
      }
    );

    const contentType = Array.isArray(response.headers['content-type'])
      ? response.headers['content-type'].join(', ')
      : response.headers['content-type'];
    expect(contentType).toContain('text/event-stream');

    const firstChunk = await streamBodyUntil(
      response,
      (buffer) => buffer.includes('event: flow') && buffer.includes('event: flow_end')
    );

    expect(firstChunk).toContain('event: flow');
    expect(firstChunk).toContain('event: flow_end');
    expect(firstChunk).toContain('data:');

    const flowMatch = firstChunk.match(/event: flow\ndata: ([^\n]+)\n\n/);
    const flowEndMatch = firstChunk.match(/event: flow_end\ndata: ([^\n]+)\n\n/);
    expect(flowMatch).toBeTruthy();
    expect(flowEndMatch).toBeTruthy();

    const flow = JSON.parse(flowMatch?.[1] ?? '{}');
    const flowEnd = JSON.parse(flowEndMatch?.[1] ?? '{}');
    for (const event of [flow, flowEnd]) {
      expect(event).toMatchObject({
        flow_id: expect.any(String),
        src_ip: expect.any(String),
        dst_ip: expect.any(String),
        src_port: expect.any(Number),
        dst_port: expect.any(Number),
        proto: expect.any(Number),
        packets_in: expect.any(Number),
        packets_out: expect.any(Number),
        last_seen: expect.any(Number),
        node_id: expect.any(String),
      });
    }

    response.destroy();
  });

  it('cleans up interval writes after client disconnect', async () => {
    vi.useFakeTimers();
    try {
      const [route] = createWiretapRoutes();
      const response = await route.handler({
        method: 'GET',
        url: '/api/v1/wiretap/stream',
        headers: {},
        body: undefined,
        pathname: '/api/v1/wiretap/stream',
      });
      expect(response.kind).toBe('sse-stream');

      const req = new EventEmitter();
      const res = new EventEmitter() as EventEmitter & {
        write: ReturnType<typeof vi.fn>;
        end: ReturnType<typeof vi.fn>;
        writableEnded: boolean;
      };
      res.write = vi.fn();
      res.end = vi.fn(() => {
        res.writableEnded = true;
      });
      res.writableEnded = false;

      response.stream?.(req as never, res as never);
      expect(res.write).toHaveBeenCalled();

      const writesAfterStart = res.write.mock.calls.length;
      vi.advanceTimersByTime(3_000);
      expect(res.write.mock.calls.length).toBeGreaterThan(writesAfterStart);

      req.emit('close');
      const writesAtDisconnect = res.write.mock.calls.length;
      vi.advanceTimersByTime(6_000);
      expect(res.write.mock.calls.length).toBe(writesAtDisconnect);
      expect(res.end).toHaveBeenCalledOnce();
    } finally {
      vi.useRealTimers();
    }
  });

  it('stops writing after response stream errors', async () => {
    vi.useFakeTimers();
    try {
      const [route] = createWiretapRoutes();
      const response = await route.handler({
        method: 'GET',
        url: '/api/v1/wiretap/stream',
        headers: {},
        body: undefined,
        pathname: '/api/v1/wiretap/stream',
      });
      expect(response.kind).toBe('sse-stream');

      const req = new EventEmitter();
      const res = new EventEmitter() as EventEmitter & {
        write: ReturnType<typeof vi.fn>;
        end: ReturnType<typeof vi.fn>;
        writableEnded: boolean;
        destroyed: boolean;
      };
      res.write = vi.fn();
      res.end = vi.fn(() => {
        res.writableEnded = true;
      });
      res.writableEnded = false;
      res.destroyed = false;

      response.stream?.(req as never, res as never);
      const writesAfterStart = res.write.mock.calls.length;

      vi.advanceTimersByTime(3_000);
      expect(res.write.mock.calls.length).toBeGreaterThan(writesAfterStart);

      res.emit('error', new Error('socket hang up'));
      const writesAtError = res.write.mock.calls.length;

      vi.advanceTimersByTime(9_000);
      expect(res.write.mock.calls.length).toBe(writesAtError);
      expect(res.end).toHaveBeenCalledOnce();
    } finally {
      vi.useRealTimers();
    }
  });
});
