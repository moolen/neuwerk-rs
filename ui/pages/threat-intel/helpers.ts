import type {
  ThreatFinding,
  ThreatIndicatorType,
  ThreatMatchSource,
  ThreatObservationLayer,
  ThreatSeverity,
} from '../../types';
import type { ThreatFindingsParams } from '../../services/api';

export type ThreatTimeRange = '1h' | '24h' | '7d' | '30d' | 'all';

export interface ThreatFilters {
  indicatorQuery: string;
  sourceGroup: string;
  selectedFeeds: string[];
  selectedSeverities: ThreatSeverity[];
  selectedLayers: ThreatObservationLayer[];
  selectedIndicatorTypes: ThreatIndicatorType[];
  selectedMatchSources: ThreatMatchSource[];
  timeRange: ThreatTimeRange;
  alertableOnly: boolean;
  auditKey: string | null;
}

const TIME_RANGE_SECONDS: Record<Exclude<ThreatTimeRange, 'all'>, number> = {
  '1h': 60 * 60,
  '24h': 24 * 60 * 60,
  '7d': 7 * 24 * 60 * 60,
  '30d': 30 * 24 * 60 * 60,
};

function trimOrNull(value: string | null): string | null {
  const trimmed = value?.trim() ?? '';
  return trimmed.length > 0 ? trimmed : null;
}

export function createDefaultThreatFilters(search: string): ThreatFilters {
  const params = new URLSearchParams(search);
  const auditKey = trimOrNull(params.get('audit_key'));
  const indicatorQuery = trimOrNull(params.get('indicator')) ?? '';
  const sourceGroup = trimOrNull(params.get('source_group')) ?? '';
  const timeRange = params.get('range');

  return {
    indicatorQuery,
    sourceGroup,
    selectedFeeds: params.getAll('feed').filter(Boolean),
    selectedSeverities: params.getAll('severity') as ThreatSeverity[],
    selectedLayers: params.getAll('layer') as ThreatObservationLayer[],
    selectedIndicatorTypes: params.getAll('indicator_type') as ThreatIndicatorType[],
    selectedMatchSources: params.getAll('match_source') as ThreatMatchSource[],
    timeRange:
      timeRange === '1h' || timeRange === '24h' || timeRange === '7d' || timeRange === '30d'
        ? timeRange
        : '24h',
    alertableOnly: auditKey === null,
    auditKey,
  };
}

export function buildThreatFindingsParams(
  filters: ThreatFilters,
  nowMs: number,
): ThreatFindingsParams {
  const params: ThreatFindingsParams = {
    limit: 1000,
  };

  if (filters.alertableOnly) {
    params.alertable = true;
  }
  if (filters.sourceGroup.trim()) {
    params.source_group = [filters.sourceGroup.trim()];
  }
  if (filters.selectedFeeds.length > 0) {
    params.feed = filters.selectedFeeds;
  }
  if (filters.selectedSeverities.length > 0) {
    params.severity = filters.selectedSeverities;
  }
  if (filters.selectedLayers.length > 0) {
    params.observation_layer = filters.selectedLayers;
  }
  if (filters.selectedIndicatorTypes.length > 0) {
    params.indicator_type = filters.selectedIndicatorTypes;
  }
  if (filters.selectedMatchSources.length > 0) {
    params.match_source = filters.selectedMatchSources;
  }
  if (filters.timeRange !== 'all') {
    params.since = Math.max(0, Math.floor(nowMs / 1000) - TIME_RANGE_SECONDS[filters.timeRange]);
  }

  return params;
}

export function filterThreatItems(items: ThreatFinding[], filters: ThreatFilters): ThreatFinding[] {
  const query = filters.indicatorQuery.trim().toLowerCase();
  const auditKey = filters.auditKey;

  return items.filter((item) => {
    if (auditKey !== null && !item.audit_links.includes(auditKey)) {
      return false;
    }
    if (query.length > 0 && !item.indicator.toLowerCase().includes(query)) {
      return false;
    }
    return true;
  });
}
