import { jsonResponse } from '../http';
import type { MockState } from '../state';
import type { MockRequest, MockRoute } from '../types';
import type {
  CreateServiceAccountRequest,
  CreateServiceAccountTokenRequest,
  CreateServiceAccountTokenResponse,
  ServiceAccount,
  ServiceAccountToken,
  UpdateServiceAccountRequest,
} from '../../types';

function parseJsonBody(request: MockRequest): unknown {
  if (!request.body || request.body.length === 0) {
    return undefined;
  }
  try {
    return JSON.parse(request.body.toString('utf-8'));
  } catch {
    return undefined;
  }
}

function readId(pathname: string): string | null {
  const prefix = '/api/v1/service-accounts/';
  if (!pathname.startsWith(prefix)) {
    return null;
  }
  const tail = pathname.slice(prefix.length);
  if (!tail || tail.includes('/')) {
    return null;
  }
  try {
    return decodeURIComponent(tail);
  } catch {
    return tail;
  }
}

function readTokenListId(pathname: string): string | null {
  const prefix = '/api/v1/service-accounts/';
  const suffix = '/tokens';
  if (!pathname.startsWith(prefix) || !pathname.endsWith(suffix)) {
    return null;
  }
  const value = pathname.slice(prefix.length, pathname.length - suffix.length);
  if (!value || value.includes('/')) {
    return null;
  }
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function readTokenPath(pathname: string): { accountId: string; tokenId: string } | null {
  const prefix = '/api/v1/service-accounts/';
  const marker = '/tokens/';
  if (!pathname.startsWith(prefix)) {
    return null;
  }
  const remainder = pathname.slice(prefix.length);
  const parts = remainder.split(marker);
  if (parts.length !== 2) {
    return null;
  }
  const [accountPart, tokenPart] = parts;
  if (!accountPart || !tokenPart || tokenPart.includes('/')) {
    return null;
  }
  try {
    return {
      accountId: decodeURIComponent(accountPart),
      tokenId: decodeURIComponent(tokenPart),
    };
  } catch {
    return {
      accountId: accountPart,
      tokenId: tokenPart,
    };
  }
}

function findServiceAccount(state: MockState, id: string): ServiceAccount | undefined {
  return state.serviceAccounts.find((item) => item.id === id);
}

function makeMockJwt(accountId: string, tokenId: string): string {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(
    JSON.stringify({
      sub: accountId,
      jti: tokenId,
      iat: Math.floor(Date.now() / 1000),
    })
  ).toString('base64url');
  const signature = Buffer.from(`mock-signature-${tokenId}`).toString('base64url');
  return `${header}.${payload}.${signature}`;
}

export function createServiceAccountRoutes(state: MockState): MockRoute[] {
  let nextAccountId = state.serviceAccounts.length + 1;
  let nextTokenId = 1;

  return [
    {
      method: 'GET',
      pathname: '/api/v1/service-accounts',
      handler: () => jsonResponse(state.serviceAccounts),
    },
    {
      method: 'POST',
      pathname: '/api/v1/service-accounts',
      handler: (request) => {
        const payload = parseJsonBody(request) as CreateServiceAccountRequest | undefined;
        if (!payload?.name?.trim()) {
          return jsonResponse({ error: 'Name is required' }, { status: 400 });
        }
        const created: ServiceAccount = {
          id: `sa-${nextAccountId++}`,
          name: payload.name.trim(),
          description: payload.description ?? null,
          created_at: new Date().toISOString(),
          created_by: state.authUser.sub,
          role: payload.role,
          status: 'active',
        };
        state.serviceAccounts.unshift(created);
        state.serviceAccountTokens[created.id] = [];
        return jsonResponse(created, { status: 201 });
      },
    },
    {
      method: 'PUT',
      pathname: '/api/v1/service-accounts/:id',
      handler: (request) => {
        const id = readId(request.pathname);
        if (!id) {
          return jsonResponse({ error: 'Not found' }, { status: 404 });
        }
        const existing = findServiceAccount(state, id);
        if (!existing) {
          return jsonResponse({ error: 'Not found' }, { status: 404 });
        }
        const payload = parseJsonBody(request) as UpdateServiceAccountRequest | undefined;
        if (!payload?.name?.trim()) {
          return jsonResponse({ error: 'Name is required' }, { status: 400 });
        }

        const updated: ServiceAccount = {
          ...existing,
          name: payload.name.trim(),
          description: payload.description ?? null,
          role: payload.role,
        };
        const index = state.serviceAccounts.findIndex((item) => item.id === id);
        state.serviceAccounts[index] = updated;
        return jsonResponse(updated);
      },
    },
    {
      method: 'DELETE',
      pathname: '/api/v1/service-accounts/:id',
      handler: (request) => {
        const id = readId(request.pathname);
        if (!id) {
          return jsonResponse({ error: 'Not found' }, { status: 404 });
        }
        const existing = findServiceAccount(state, id);
        if (!existing) {
          return jsonResponse({ error: 'Not found' }, { status: 404 });
        }
        existing.status = 'disabled';
        return jsonResponse(undefined, { status: 204 });
      },
    },
    {
      method: 'GET',
      pathname: '/api/v1/service-accounts/:id/tokens',
      handler: (request) => {
        const id = readTokenListId(request.pathname);
        if (!id || !findServiceAccount(state, id)) {
          return jsonResponse({ error: 'Not found' }, { status: 404 });
        }
        return jsonResponse(state.serviceAccountTokens[id] ?? []);
      },
    },
    {
      method: 'POST',
      pathname: '/api/v1/service-accounts/:id/tokens',
      handler: (request) => {
        const id = readTokenListId(request.pathname);
        if (!id) {
          return jsonResponse({ error: 'Not found' }, { status: 404 });
        }
        const account = findServiceAccount(state, id);
        if (!account) {
          return jsonResponse({ error: 'Not found' }, { status: 404 });
        }
        const payload = parseJsonBody(request) as CreateServiceAccountTokenRequest | undefined;
        const tokenId = `sat-${nextTokenId++}`;
        const createdAt = new Date().toISOString();
        const tokenMeta: ServiceAccountToken = {
          id: tokenId,
          service_account_id: id,
          name: payload?.name?.trim() || null,
          created_at: createdAt,
          created_by: state.authUser.sub,
          expires_at: payload?.eternal ? null : null,
          revoked_at: null,
          last_used_at: null,
          kid: `kid-${tokenId}`,
          role: payload?.role ?? account.role,
          status: 'active',
        };
        if (!state.serviceAccountTokens[id]) {
          state.serviceAccountTokens[id] = [];
        }
        state.serviceAccountTokens[id].unshift(tokenMeta);

        const response: CreateServiceAccountTokenResponse = {
          token: makeMockJwt(id, tokenId),
          token_meta: tokenMeta,
        };
        return jsonResponse(response, { status: 201 });
      },
    },
    {
      method: 'DELETE',
      pathname: '/api/v1/service-accounts/:id/tokens/:tokenId',
      handler: (request) => {
        const ids = readTokenPath(request.pathname);
        if (!ids) {
          return jsonResponse({ error: 'Not found' }, { status: 404 });
        }
        const tokens = state.serviceAccountTokens[ids.accountId];
        if (!tokens) {
          return jsonResponse({ error: 'Not found' }, { status: 404 });
        }
        const token = tokens.find((entry) => entry.id === ids.tokenId);
        if (!token) {
          return jsonResponse({ error: 'Not found' }, { status: 404 });
        }
        token.status = 'revoked';
        token.revoked_at = new Date().toISOString();
        return jsonResponse(undefined, { status: 204 });
      },
    },
  ];
}
