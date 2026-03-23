import type { ThreatSilenceEntry } from '../../types';
import type { ThreatFilters } from './helpers';

export function buildServerFilterKey(filters: ThreatFilters): string {
  return JSON.stringify({
    sourceGroup: filters.sourceGroup,
    selectedFeeds: filters.selectedFeeds,
    selectedSeverities: filters.selectedSeverities,
    selectedLayers: filters.selectedLayers,
    selectedIndicatorTypes: filters.selectedIndicatorTypes,
    selectedMatchSources: filters.selectedMatchSources,
    timeRange: filters.timeRange,
    alertableOnly: filters.alertableOnly,
  });
}

export function buildSearchFromFilters(filters: ThreatFilters): string {
  const params = new URLSearchParams();

  if (filters.indicatorQuery.trim()) {
    params.set('indicator', filters.indicatorQuery.trim());
  }
  if (filters.sourceGroup.trim()) {
    params.set('source_group', filters.sourceGroup.trim());
  }
  if (filters.auditKey) {
    params.set('audit_key', filters.auditKey);
  }
  if (!filters.alertableOnly) {
    params.set('alertable', 'all');
  }
  if (filters.timeRange !== '24h') {
    params.set('range', filters.timeRange);
  }
  for (const item of filters.selectedFeeds) {
    params.append('feed', item);
  }
  for (const item of filters.selectedSeverities) {
    params.append('severity', item);
  }
  for (const item of filters.selectedLayers) {
    params.append('layer', item);
  }
  for (const item of filters.selectedIndicatorTypes) {
    params.append('indicator_type', item);
  }
  for (const item of filters.selectedMatchSources) {
    params.append('match_source', item);
  }

  const query = params.toString();
  return query ? `?${query}` : '';
}

export function sortSilences(items: ThreatSilenceEntry[]): ThreatSilenceEntry[] {
  return [...items].sort((left, right) => right.created_at - left.created_at);
}
