import { describe, expect, it } from 'vitest';

import { jsonResponse } from './http';
import { createMockRouter } from './router';

describe('createMockRouter', () => {
  it('falls through for non-api routes', async () => {
    const router = createMockRouter();
    const response = await router.handle({
      method: 'GET',
      url: '/healthz',
      headers: {},
      body: undefined,
    });

    expect(response).toBeUndefined();
  });

  it('returns 404 for unknown api routes', async () => {
    const router = createMockRouter();
    const response = await router.handle({
      method: 'GET',
      url: '/api/v1/does-not-exist',
      headers: {},
      body: undefined,
    });

    expect(response?.status).toBe(404);
    expect(response?.json).toEqual({ error: 'Not found' });
  });

  it('returns handler status headers and json body through shared helper', async () => {
    const router = createMockRouter({
      routes: [
        {
          method: 'POST',
          pathname: '/api/v1/example',
          handler: async () =>
            jsonResponse(
              { ok: true },
              {
                status: 201,
                headers: {
                  'x-neuwerk-mock': 'yes',
                },
              }
            ),
        },
      ],
    });

    const response = await router.handle({
      method: 'POST',
      url: '/api/v1/example',
      headers: {},
      body: undefined,
    });

    expect(response).toMatchObject({
      status: 201,
      headers: {
        'content-type': 'application/json; charset=utf-8',
        'x-neuwerk-mock': 'yes',
      },
      json: { ok: true },
    });
  });
});
