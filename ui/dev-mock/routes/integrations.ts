import { jsonResponse } from '../http';
import type { MockState } from '../state';
import type { MockRequest, MockRoute } from '../types';
import type {
  IntegrationCreateRequest,
  IntegrationUpdateRequest,
  IntegrationView,
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

function readName(pathname: string): string | null {
  const prefix = '/api/v1/integrations/';
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

function findIntegration(state: MockState, name: string): IntegrationView | undefined {
  return state.integrations.find((item) => item.name === name);
}

export function createIntegrationRoutes(state: MockState): MockRoute[] {
  let nextId = state.integrations.length + 1;

  return [
    {
      method: 'GET',
      pathname: '/api/v1/integrations',
      handler: () => jsonResponse(state.integrations),
    },
    {
      method: 'POST',
      pathname: '/api/v1/integrations',
      handler: (request) => {
        const payload = parseJsonBody(request) as IntegrationCreateRequest | undefined;
        if (!payload?.name?.trim()) {
          return jsonResponse({ error: 'Name is required' }, { status: 400 });
        }
        if (!payload.api_server_url?.trim()) {
          return jsonResponse({ error: 'API server URL is required' }, { status: 400 });
        }
        if (findIntegration(state, payload.name.trim())) {
          return jsonResponse({ error: 'Integration already exists' }, { status: 409 });
        }

        const created: IntegrationView = {
          id: `integration-${nextId++}`,
          created_at: new Date().toISOString(),
          name: payload.name.trim(),
          kind: payload.kind,
          api_server_url: payload.api_server_url.trim(),
          ca_cert_pem: payload.ca_cert_pem ?? '',
          auth_type: 'service-account-token',
          token_configured: Boolean(payload.service_account_token?.trim()),
        };
        state.integrations.unshift(created);
        return jsonResponse(created, { status: 201 });
      },
    },
    {
      method: 'GET',
      pathname: '/api/v1/integrations/:name',
      handler: (request) => {
        const name = readName(request.pathname);
        if (!name) {
          return jsonResponse({ error: 'Not found' }, { status: 404 });
        }
        const integration = findIntegration(state, name);
        if (!integration) {
          return jsonResponse({ error: 'Not found' }, { status: 404 });
        }
        return jsonResponse(integration);
      },
    },
    {
      method: 'PUT',
      pathname: '/api/v1/integrations/:name',
      handler: (request) => {
        const name = readName(request.pathname);
        if (!name) {
          return jsonResponse({ error: 'Not found' }, { status: 404 });
        }
        const existing = findIntegration(state, name);
        if (!existing) {
          return jsonResponse({ error: 'Not found' }, { status: 404 });
        }
        const payload = parseJsonBody(request) as IntegrationUpdateRequest | undefined;
        if (!payload?.api_server_url?.trim()) {
          return jsonResponse({ error: 'API server URL is required' }, { status: 400 });
        }

        const updated: IntegrationView = {
          ...existing,
          api_server_url: payload.api_server_url.trim(),
          ca_cert_pem: payload.ca_cert_pem ?? '',
          token_configured: Boolean(payload.service_account_token?.trim()),
        };
        const index = state.integrations.findIndex((item) => item.name === name);
        state.integrations[index] = updated;
        return jsonResponse(updated);
      },
    },
    {
      method: 'DELETE',
      pathname: '/api/v1/integrations/:name',
      handler: (request) => {
        const name = readName(request.pathname);
        if (!name) {
          return jsonResponse({ error: 'Not found' }, { status: 404 });
        }
        const index = state.integrations.findIndex((item) => item.name === name);
        if (index < 0) {
          return jsonResponse({ error: 'Not found' }, { status: 404 });
        }
        state.integrations.splice(index, 1);
        return jsonResponse(undefined, { status: 204 });
      },
    },
  ];
}
