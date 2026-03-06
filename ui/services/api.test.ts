import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { APIError, loginWithToken, logout, subscribeToWiretap, whoAmI } from './api';

describe('api auth transport behavior', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('uses same-origin credentials for whoAmI', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ sub: 'user-1' }),
    });
    vi.stubGlobal('fetch', fetchMock);

    await whoAmI();

    expect(fetchMock).toHaveBeenCalledWith('/api/v1/auth/whoami', {
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
    });
  });

  it('sends logout via same-origin credentials', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 204,
      json: async () => ({}),
    });
    vi.stubGlobal('fetch', fetchMock);

    await logout();

    expect(fetchMock).toHaveBeenCalledWith('/api/v1/auth/logout', {
      credentials: 'same-origin',
      method: 'POST',
    });
  });

  it('does not persist token client-side during token login', async () => {
    const setItem = vi.fn();
    vi.stubGlobal('localStorage', { setItem });
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ sub: 'user-2' }),
    });
    vi.stubGlobal('fetch', fetchMock);

    await loginWithToken('test-token');

    expect(setItem).not.toHaveBeenCalled();
  });

  it('uses same-origin credentials for token login', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ sub: 'user-2' }),
    });
    vi.stubGlobal('fetch', fetchMock);

    await loginWithToken('test-token');

    expect(fetchMock).toHaveBeenCalledWith('/api/v1/auth/token-login', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: 'test-token' }),
    });
  });

  it('parses backend error field from JSON responses', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: false,
      status: 403,
      statusText: 'Forbidden',
      json: async () => ({ error: 'access denied' }),
    });
    vi.stubGlobal('fetch', fetchMock);

    await expect(whoAmI()).rejects.toMatchObject({
      name: 'APIError',
      status: 403,
      message: 'access denied',
    } satisfies Partial<APIError>);
  });

  it('falls back to message field for auth login failures', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: false,
      status: 401,
      statusText: 'Unauthorized',
      json: async () => ({ message: 'bad token' }),
    });
    vi.stubGlobal('fetch', fetchMock);

    await expect(loginWithToken('bad-token')).rejects.toMatchObject({
      name: 'APIError',
      status: 401,
      message: 'bad token',
    } satisfies Partial<APIError>);
  });
});

describe('wiretap stream auth transport', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('uses credentialed EventSource without query token and closes cleanly', () => {
    const close = vi.fn();
    const addEventListener = vi.fn();
    const eventSourceCtor = vi.fn(() => ({
      addEventListener,
      close,
      onerror: null,
      onmessage: null,
    }));
    vi.stubGlobal('EventSource', eventSourceCtor);

    const unsubscribe = subscribeToWiretap(() => undefined);
    const [url, options] = eventSourceCtor.mock.calls[0];

    expect(url).toBe('/api/v1/wiretap/stream');
    expect(url).not.toContain('access_token=');
    expect(options).toEqual({ withCredentials: true });
    expect(addEventListener).toHaveBeenCalledTimes(2);

    unsubscribe();
    expect(close).toHaveBeenCalledOnce();
  });
});
