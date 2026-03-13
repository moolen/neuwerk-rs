import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  APIError,
  buildSsoStartPath,
  createServiceAccount,
  createServiceAccountToken,
  createSsoProvider,
  downloadClusterSysdump,
  listSupportedSsoProviders,
  loginWithToken,
  logout,
  subscribeToWiretap,
  updateServiceAccount,
  whoAmI,
} from './api';

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

  it('builds SSO start path with encoded next path', () => {
    expect(buildSsoStartPath('provider-1', '/policies?tab=active')).toBe(
      '/api/v1/auth/sso/provider-1/start?next=%2Fpolicies%3Ftab%3Dactive'
    );
  });

  it('loads supported SSO providers via GET', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => [{ id: 'p1', name: 'Google', kind: 'google' }],
    });
    vi.stubGlobal('fetch', fetchMock);

    const providers = await listSupportedSsoProviders();

    expect(providers).toEqual([{ id: 'p1', name: 'Google', kind: 'google' }]);
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/auth/sso/providers', {
      method: 'GET',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
    });
  });

  it('creates SSO providers via POST', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ id: 'p1', name: 'Google', kind: 'google' }),
    });
    vi.stubGlobal('fetch', fetchMock);

    await createSsoProvider({
      name: 'Google',
      kind: 'google',
      client_id: 'cid',
      client_secret: 'secret',
    });

    expect(fetchMock).toHaveBeenCalledWith('/api/v1/settings/sso/providers', {
      method: 'POST',
      body: JSON.stringify({
        name: 'Google',
        kind: 'google',
        client_id: 'cid',
        client_secret: 'secret',
      }),
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
    });
  });
});

describe('service account transport behavior', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('creates service accounts with role in the payload', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ id: 'sa-1', name: 'ci', role: 'readonly' }),
    });
    vi.stubGlobal('fetch', fetchMock);

    await createServiceAccount({
      name: 'ci',
      description: 'pipeline',
      role: 'readonly',
    });

    expect(fetchMock).toHaveBeenCalledWith('/api/v1/service-accounts', {
      method: 'POST',
      body: JSON.stringify({
        name: 'ci',
        description: 'pipeline',
        role: 'readonly',
      }),
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
    });
  });

  it('updates service accounts with role in the payload', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ id: 'sa-1', name: 'ci', role: 'admin' }),
    });
    vi.stubGlobal('fetch', fetchMock);

    await updateServiceAccount('sa-1', {
      name: 'ci',
      description: 'pipeline',
      role: 'admin',
    });

    expect(fetchMock).toHaveBeenCalledWith('/api/v1/service-accounts/sa-1', {
      method: 'PUT',
      body: JSON.stringify({
        name: 'ci',
        description: 'pipeline',
        role: 'admin',
      }),
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
    });
  });

  it('creates service account tokens with role in the payload', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        token: 'jwt',
        token_meta: { id: 'tok-1', role: 'readonly' },
      }),
    });
    vi.stubGlobal('fetch', fetchMock);

    await createServiceAccountToken('sa-1', {
      name: 'reader',
      ttl: '90d',
      eternal: false,
      role: 'readonly',
    });

    expect(fetchMock).toHaveBeenCalledWith('/api/v1/service-accounts/sa-1/tokens', {
      method: 'POST',
      body: JSON.stringify({
        name: 'reader',
        ttl: '90d',
        eternal: false,
        role: 'readonly',
      }),
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
    });
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

describe('support bundle download transport', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('downloads the cluster sysdump with same-origin credentials and filename parsing', async () => {
    const blob = new Blob(['sysdump'], { type: 'application/gzip' });
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      blob: async () => blob,
      headers: {
        get: (name: string) =>
          name.toLowerCase() === 'content-disposition'
            ? 'attachment; filename="neuwerk-cluster-sysdump.tar.gz"'
            : null,
      },
    });
    vi.stubGlobal('fetch', fetchMock);

    const result = await downloadClusterSysdump();

    expect(result).toEqual({
      blob,
      filename: 'neuwerk-cluster-sysdump.tar.gz',
    });
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/support/sysdump/cluster', {
      method: 'POST',
      credentials: 'same-origin',
      headers: {},
    });
  });

  it('surfaces text error bodies for cluster sysdump download failures', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: false,
      status: 503,
      statusText: 'Service Unavailable',
      text: async () => 'cluster sysdump requires cluster mode',
    });
    vi.stubGlobal('fetch', fetchMock);

    await expect(downloadClusterSysdump()).rejects.toMatchObject({
      name: 'APIError',
      status: 503,
      message: 'cluster sysdump requires cluster mode',
    } satisfies Partial<APIError>);
  });
});
