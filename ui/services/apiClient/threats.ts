import type {
  ThreatFeedStatusResponse,
  ThreatFindingQueryResponse,
  ThreatIndicatorType,
  ThreatSilenceEntry,
  ThreatSilenceKind,
  ThreatSilenceListResponse,
} from '../../types';
import { fetchJSON } from './transport';

export interface ThreatFindingsParams {
  indicator_type?: string[];
  severity?: string[];
  source_group?: string[];
  observation_layer?: string[];
  feed?: string[];
  match_source?: string[];
  alertable?: boolean;
  since?: number;
  until?: number;
  limit?: number;
}

export interface CreateThreatSilenceRequest {
  kind: ThreatSilenceKind;
  indicator_type?: ThreatIndicatorType;
  value: string;
  reason?: string;
}

export async function getThreatFindings(
  params: ThreatFindingsParams = {}
): Promise<ThreatFindingQueryResponse> {
  const query = new URLSearchParams();
  for (const value of params.indicator_type ?? []) {
    query.append('indicator_type', value);
  }
  for (const value of params.severity ?? []) {
    query.append('severity', value);
  }
  for (const value of params.source_group ?? []) {
    query.append('source_group', value);
  }
  for (const value of params.observation_layer ?? []) {
    query.append('observation_layer', value);
  }
  for (const value of params.feed ?? []) {
    query.append('feed', value);
  }
  for (const value of params.match_source ?? []) {
    query.append('match_source', value);
  }
  if (typeof params.alertable === 'boolean') {
    query.set('alertable', String(params.alertable));
  }
  if (typeof params.since === 'number') {
    query.set('since', String(params.since));
  }
  if (typeof params.until === 'number') {
    query.set('until', String(params.until));
  }
  if (typeof params.limit === 'number') {
    query.set('limit', String(params.limit));
  }
  const suffix = query.toString();
  return fetchJSON<ThreatFindingQueryResponse>(`/threats/findings${suffix ? `?${suffix}` : ''}`);
}

export async function getThreatFeedStatus(): Promise<ThreatFeedStatusResponse> {
  return fetchJSON<ThreatFeedStatusResponse>('/threats/feeds/status');
}

export async function listThreatSilences(): Promise<ThreatSilenceListResponse> {
  return fetchJSON<ThreatSilenceListResponse>('/threats/silences');
}

export async function createThreatSilence(
  request: CreateThreatSilenceRequest
): Promise<ThreatSilenceEntry> {
  return fetchJSON<ThreatSilenceEntry>('/threats/silences', {
    method: 'POST',
    body: JSON.stringify(request),
  });
}

export async function deleteThreatSilence(id: string): Promise<void> {
  await fetchJSON<void>(`/threats/silences/${id}`, {
    method: 'DELETE',
  });
}
