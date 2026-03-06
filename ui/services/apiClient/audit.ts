import type { AuditQueryResponse } from '../../types';
import { fetchJSON } from './transport';

export interface AuditFindingsParams {
  policy_id?: string;
  finding_type?: string[];
  source_group?: string[];
  since?: number;
  until?: number;
  limit?: number;
}

export async function getAuditFindings(params: AuditFindingsParams = {}): Promise<AuditQueryResponse> {
  const query = new URLSearchParams();
  if (params.policy_id) query.set('policy_id', params.policy_id);
  for (const findingType of params.finding_type ?? []) {
    query.append('finding_type', findingType);
  }
  for (const sourceGroup of params.source_group ?? []) {
    query.append('source_group', sourceGroup);
  }
  if (typeof params.since === 'number') query.set('since', String(params.since));
  if (typeof params.until === 'number') query.set('until', String(params.until));
  if (typeof params.limit === 'number') query.set('limit', String(params.limit));
  const suffix = query.toString();
  return fetchJSON<AuditQueryResponse>(`/audit/findings${suffix ? `?${suffix}` : ''}`);
}
