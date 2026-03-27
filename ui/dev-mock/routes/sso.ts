import { jsonResponse } from '../http';
import type { MockState } from '../state';
import type { MockRequest, MockRoute } from '../types';
import type {
  SsoProviderCreateRequest,
  SsoProviderPatchRequest,
  SsoProviderTestResult,
  SsoProviderView,
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

function readProviderId(pathname: string): string | null {
  const prefix = '/api/v1/settings/sso/providers/';
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

function readProviderTestId(pathname: string): string | null {
  const prefix = '/api/v1/settings/sso/providers/';
  const suffix = '/test';
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

function findProvider(state: MockState, id: string): SsoProviderView | undefined {
  return state.ssoProviders.find((provider) => provider.id === id);
}

export function createSsoRoutes(state: MockState): MockRoute[] {
  let nextId = state.ssoProviders.length + 1;

  return [
    {
      method: 'GET',
      pathname: '/api/v1/settings/sso/providers',
      handler: () => jsonResponse(state.ssoProviders),
    },
    {
      method: 'POST',
      pathname: '/api/v1/settings/sso/providers',
      handler: (request) => {
        const payload = parseJsonBody(request) as SsoProviderCreateRequest | undefined;
        if (!payload?.name?.trim()) {
          return jsonResponse({ error: 'Name is required' }, { status: 400 });
        }
        if (!payload.client_id?.trim()) {
          return jsonResponse({ error: 'Client ID is required' }, { status: 400 });
        }
        if (!payload.client_secret?.trim()) {
          return jsonResponse({ error: 'Client secret is required' }, { status: 400 });
        }

        const now = new Date().toISOString();
        const created: SsoProviderView = {
          id: `sso-provider-${String(nextId++).padStart(3, '0')}`,
          created_at: now,
          updated_at: now,
          name: payload.name.trim(),
          kind: payload.kind,
          enabled: payload.enabled ?? true,
          display_order: payload.display_order ?? 0,
          issuer_url: payload.issuer_url ?? null,
          authorization_url: payload.authorization_url ?? null,
          token_url: payload.token_url ?? null,
          userinfo_url: payload.userinfo_url ?? null,
          client_id: payload.client_id.trim(),
          client_secret_configured: true,
          scopes: payload.scopes ?? ['openid', 'profile', 'email'],
          pkce_required: payload.pkce_required ?? true,
          subject_claim: payload.subject_claim ?? 'sub',
          email_claim: payload.email_claim ?? 'email',
          groups_claim: payload.groups_claim ?? null,
          default_role: payload.default_role ?? 'readonly',
          admin_subjects: payload.admin_subjects ?? [],
          admin_groups: payload.admin_groups ?? [],
          admin_email_domains: payload.admin_email_domains ?? [],
          readonly_subjects: payload.readonly_subjects ?? [],
          readonly_groups: payload.readonly_groups ?? [],
          readonly_email_domains: payload.readonly_email_domains ?? [],
          allowed_email_domains: payload.allowed_email_domains ?? [],
          session_ttl_secs: payload.session_ttl_secs ?? 8 * 60 * 60,
        };

        state.ssoProviders.unshift(created);
        return jsonResponse(created, { status: 201 });
      },
    },
    {
      method: 'GET',
      pathname: '/api/v1/settings/sso/providers/:id',
      handler: (request) => {
        const id = readProviderId(request.pathname);
        if (!id) {
          return jsonResponse({ error: 'Not found' }, { status: 404 });
        }
        const provider = findProvider(state, id);
        if (!provider) {
          return jsonResponse({ error: 'Not found' }, { status: 404 });
        }
        return jsonResponse(provider);
      },
    },
    {
      method: 'PUT',
      pathname: '/api/v1/settings/sso/providers/:id',
      handler: (request) => {
        const id = readProviderId(request.pathname);
        if (!id) {
          return jsonResponse({ error: 'Not found' }, { status: 404 });
        }
        const provider = findProvider(state, id);
        if (!provider) {
          return jsonResponse({ error: 'Not found' }, { status: 404 });
        }
        const payload = parseJsonBody(request) as SsoProviderPatchRequest | undefined;
        if (payload?.name !== undefined && !payload.name.trim()) {
          return jsonResponse({ error: 'Name is required' }, { status: 400 });
        }
        if (payload?.client_id !== undefined && !payload.client_id.trim()) {
          return jsonResponse({ error: 'Client ID is required' }, { status: 400 });
        }

        const updated: SsoProviderView = {
          ...provider,
          updated_at: new Date().toISOString(),
          name: payload?.name?.trim() ?? provider.name,
          enabled: payload?.enabled ?? provider.enabled,
          display_order: payload?.display_order ?? provider.display_order,
          issuer_url: payload?.issuer_url ?? provider.issuer_url,
          authorization_url: payload?.authorization_url ?? provider.authorization_url,
          token_url: payload?.token_url ?? provider.token_url,
          userinfo_url: payload?.userinfo_url ?? provider.userinfo_url,
          client_id: payload?.client_id?.trim() ?? provider.client_id,
          client_secret_configured:
            provider.client_secret_configured || Boolean(payload?.client_secret?.trim()),
          scopes: payload?.scopes ?? provider.scopes,
          pkce_required: payload?.pkce_required ?? provider.pkce_required,
          subject_claim: payload?.subject_claim ?? provider.subject_claim,
          email_claim: payload?.email_claim ?? provider.email_claim,
          groups_claim: payload?.groups_claim ?? provider.groups_claim,
          default_role: payload?.default_role ?? provider.default_role,
          admin_subjects: payload?.admin_subjects ?? provider.admin_subjects,
          admin_groups: payload?.admin_groups ?? provider.admin_groups,
          admin_email_domains: payload?.admin_email_domains ?? provider.admin_email_domains,
          readonly_subjects: payload?.readonly_subjects ?? provider.readonly_subjects,
          readonly_groups: payload?.readonly_groups ?? provider.readonly_groups,
          readonly_email_domains:
            payload?.readonly_email_domains ?? provider.readonly_email_domains,
          allowed_email_domains:
            payload?.allowed_email_domains ?? provider.allowed_email_domains,
          session_ttl_secs: payload?.session_ttl_secs ?? provider.session_ttl_secs,
        };
        const index = state.ssoProviders.findIndex((item) => item.id === id);
        state.ssoProviders[index] = updated;
        return jsonResponse(updated);
      },
    },
    {
      method: 'DELETE',
      pathname: '/api/v1/settings/sso/providers/:id',
      handler: (request) => {
        const id = readProviderId(request.pathname);
        if (!id) {
          return jsonResponse({ error: 'Not found' }, { status: 404 });
        }
        const index = state.ssoProviders.findIndex((provider) => provider.id === id);
        if (index < 0) {
          return jsonResponse({ error: 'Not found' }, { status: 404 });
        }
        state.ssoProviders.splice(index, 1);
        return jsonResponse(undefined, { status: 204 });
      },
    },
    {
      method: 'POST',
      pathname: '/api/v1/settings/sso/providers/:id/test',
      handler: (request) => {
        const id = readProviderTestId(request.pathname);
        if (!id) {
          return jsonResponse({ error: 'Not found' }, { status: 404 });
        }
        const provider = findProvider(state, id);
        if (!provider) {
          return jsonResponse({ error: 'Not found' }, { status: 404 });
        }

        const response: SsoProviderTestResult = {
          ok: true,
          details: `Provider ${provider.name} configuration looks valid`,
        };
        return jsonResponse(response);
      },
    },
  ];
}
