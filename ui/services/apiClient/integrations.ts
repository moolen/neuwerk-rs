import type {
  IntegrationCreateRequest,
  IntegrationUpdateRequest,
  IntegrationView,
} from '../../types';
import { fetchJSON } from './transport';

export async function listIntegrations(): Promise<IntegrationView[]> {
  return fetchJSON<IntegrationView[]>('/integrations');
}

export async function getIntegration(name: string): Promise<IntegrationView> {
  return fetchJSON<IntegrationView>(`/integrations/${encodeURIComponent(name)}`);
}

export async function createIntegration(req: IntegrationCreateRequest): Promise<IntegrationView> {
  return fetchJSON<IntegrationView>('/integrations', {
    method: 'POST',
    body: JSON.stringify(req),
  });
}

export async function updateIntegration(
  name: string,
  req: IntegrationUpdateRequest
): Promise<IntegrationView> {
  return fetchJSON<IntegrationView>(`/integrations/${encodeURIComponent(name)}`, {
    method: 'PUT',
    body: JSON.stringify(req),
  });
}

export async function deleteIntegration(name: string): Promise<void> {
  await fetchJSON<void>(`/integrations/${encodeURIComponent(name)}`, {
    method: 'DELETE',
  });
}
