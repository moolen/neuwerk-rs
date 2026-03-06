import type {
  CreateServiceAccountRequest,
  CreateServiceAccountTokenRequest,
  CreateServiceAccountTokenResponse,
  ServiceAccount,
  ServiceAccountToken,
} from '../../types';
import { fetchJSON } from './transport';

export async function getServiceAccounts(): Promise<ServiceAccount[]> {
  return fetchJSON<ServiceAccount[]>('/service-accounts');
}

export async function createServiceAccount(req: CreateServiceAccountRequest): Promise<ServiceAccount> {
  return fetchJSON<ServiceAccount>('/service-accounts', {
    method: 'POST',
    body: JSON.stringify(req),
  });
}

export async function revokeServiceAccount(id: string): Promise<void> {
  await fetchJSON<void>(`/service-accounts/${encodeURIComponent(id)}`, {
    method: 'DELETE',
  });
}

export async function getServiceAccountTokens(id: string): Promise<ServiceAccountToken[]> {
  return fetchJSON<ServiceAccountToken[]>(`/service-accounts/${encodeURIComponent(id)}/tokens`);
}

export async function createServiceAccountToken(
  id: string,
  req: CreateServiceAccountTokenRequest
): Promise<CreateServiceAccountTokenResponse> {
  return fetchJSON<CreateServiceAccountTokenResponse>(`/service-accounts/${encodeURIComponent(id)}/tokens`, {
    method: 'POST',
    body: JSON.stringify(req),
  });
}

export async function revokeServiceAccountToken(id: string, tokenId: string): Promise<void> {
  await fetchJSON<void>(
    `/service-accounts/${encodeURIComponent(id)}/tokens/${encodeURIComponent(tokenId)}`,
    { method: 'DELETE' }
  );
}
