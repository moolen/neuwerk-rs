import type { PolicyCreateRequest, PolicyRecord } from '../../types';
import { fetchJSON, fetchText } from './transport';

export async function listPolicies(): Promise<PolicyRecord[]> {
  return fetchJSON<PolicyRecord[]>('/policies');
}

export async function getPolicy(id: string): Promise<PolicyRecord> {
  return fetchJSON<PolicyRecord>(`/policies/${encodeURIComponent(id)}`);
}

export async function getPolicyYaml(id: string): Promise<string> {
  return fetchText(`/policies/${encodeURIComponent(id)}?format=yaml`);
}

export async function createPolicy(req: PolicyCreateRequest): Promise<PolicyRecord> {
  return fetchJSON<PolicyRecord>('/policies', {
    method: 'POST',
    body: JSON.stringify(req),
  });
}

export async function updatePolicy(id: string, req: PolicyCreateRequest): Promise<PolicyRecord> {
  return fetchJSON<PolicyRecord>(`/policies/${encodeURIComponent(id)}`, {
    method: 'PUT',
    body: JSON.stringify(req),
  });
}

export async function deletePolicy(id: string): Promise<void> {
  await fetchJSON<void>(`/policies/${encodeURIComponent(id)}`, {
    method: 'DELETE',
  });
}
