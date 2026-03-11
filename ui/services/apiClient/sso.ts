import type {
  SsoProviderCreateRequest,
  SsoProviderPatchRequest,
  SsoProviderTestResult,
  SsoProviderView,
  SsoSupportedProvider,
} from '../../types';
import { fetchJSON } from './transport';

export function buildSsoStartPath(providerId: string, nextPath?: string): string {
  const base = `/api/v1/auth/sso/${encodeURIComponent(providerId)}/start`;
  if (!nextPath) {
    return base;
  }
  return `${base}?next=${encodeURIComponent(nextPath)}`;
}

export async function listSupportedSsoProviders(): Promise<SsoSupportedProvider[]> {
  return fetchJSON<SsoSupportedProvider[]>('/auth/sso/providers', { method: 'GET' });
}

export async function listSsoProviders(): Promise<SsoProviderView[]> {
  return fetchJSON<SsoProviderView[]>('/settings/sso/providers', { method: 'GET' });
}

export async function getSsoProvider(id: string): Promise<SsoProviderView> {
  return fetchJSON<SsoProviderView>(`/settings/sso/providers/${encodeURIComponent(id)}`, {
    method: 'GET',
  });
}

export async function createSsoProvider(
  payload: SsoProviderCreateRequest
): Promise<SsoProviderView> {
  return fetchJSON<SsoProviderView>('/settings/sso/providers', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

export async function updateSsoProvider(
  id: string,
  payload: SsoProviderPatchRequest
): Promise<SsoProviderView> {
  return fetchJSON<SsoProviderView>(`/settings/sso/providers/${encodeURIComponent(id)}`, {
    method: 'PUT',
    body: JSON.stringify(payload),
  });
}

export async function deleteSsoProvider(id: string): Promise<void> {
  await fetchJSON<void>(`/settings/sso/providers/${encodeURIComponent(id)}`, {
    method: 'DELETE',
  });
}

export async function testSsoProvider(id: string): Promise<SsoProviderTestResult> {
  return fetchJSON<SsoProviderTestResult>(
    `/settings/sso/providers/${encodeURIComponent(id)}/test`,
    {
      method: 'POST',
    }
  );
}
