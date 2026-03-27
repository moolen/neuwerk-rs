import type { MockResponse, MockResponseInit } from './types';

function normalizeHeaders(
  headers: Record<string, string | undefined> = {}
): Record<string, string> {
  const normalized: Record<string, string> = {};
  for (const [name, value] of Object.entries(headers)) {
    if (typeof value === 'string') {
      normalized[name.toLowerCase()] = value;
    }
  }
  return normalized;
}

function createResponse(
  kind: MockResponse['kind'],
  init: MockResponseInit = {}
): Pick<MockResponse, 'status' | 'headers' | 'kind'> {
  return {
    status: init.status ?? 200,
    headers: normalizeHeaders(init.headers),
    kind,
  };
}

export function jsonResponse(
  body: unknown,
  init: MockResponseInit = {}
): MockResponse {
  return {
    ...createResponse('json', init),
    headers: {
      'content-type': 'application/json; charset=utf-8',
      ...normalizeHeaders(init.headers),
    },
    json: body,
  };
}

export function textResponse(
  body: string,
  init: MockResponseInit = {}
): MockResponse {
  return {
    ...createResponse('text', init),
    headers: {
      'content-type': 'text/plain; charset=utf-8',
      ...normalizeHeaders(init.headers),
    },
    text: body,
  };
}

export function blobResponse(
  body: Uint8Array,
  init: MockResponseInit = {}
): MockResponse {
  return {
    ...createResponse('blob', init),
    headers: {
      'content-type': 'application/octet-stream',
      ...normalizeHeaders(init.headers),
    },
    body,
  };
}

export function sseResponse(body: string, init: MockResponseInit = {}): MockResponse {
  return {
    ...createResponse('sse', init),
    headers: {
      'cache-control': 'no-cache',
      connection: 'keep-alive',
      'content-type': 'text/event-stream; charset=utf-8',
      ...normalizeHeaders(init.headers),
    },
    text: body,
  };
}
