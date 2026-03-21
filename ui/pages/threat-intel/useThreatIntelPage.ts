import { useEffect, useMemo, useState } from 'react';

import { getThreatFeedStatus, getThreatFindings } from '../../services/api';
import type {
  ThreatFeedStatusResponse,
  ThreatFinding,
  ThreatNodeError,
} from '../../types';
import {
  buildThreatFindingsParams,
  createDefaultThreatFilters,
  filterThreatItems,
  type ThreatFilters,
} from './helpers';

function buildServerFilterKey(filters: ThreatFilters): string {
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

function buildSearchFromFilters(filters: ThreatFilters): string {
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

export function useThreatIntelPage() {
  const [rawItems, setRawItems] = useState<ThreatFinding[]>([]);
  const [feedStatus, setFeedStatus] = useState<ThreatFeedStatusResponse | null>(null);
  const [filters, setFilters] = useState<ThreatFilters>(() =>
    createDefaultThreatFilters(window.location.search),
  );
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [partial, setPartial] = useState(false);
  const [nodeErrors, setNodeErrors] = useState<ThreatNodeError[]>([]);
  const [nodesQueried, setNodesQueried] = useState(0);
  const [nodesResponded, setNodesResponded] = useState(0);
  const serverFilterKey = buildServerFilterKey(filters);

  const load = async (activeFilters: ThreatFilters = filters) => {
    setLoading(true);
    setError(null);

    try {
      const [feeds, findings] = await Promise.all([
        getThreatFeedStatus(),
        getThreatFindings(buildThreatFindingsParams(activeFilters, Date.now())),
      ]);
      setFeedStatus(feeds);
      setRawItems(findings.items);
      setPartial(findings.partial);
      setNodeErrors(findings.node_errors);
      setNodesQueried(findings.nodes_queried);
      setNodesResponded(findings.nodes_responded);
    } catch (err) {
      console.error('Failed to load threat intel data:', err);
      setError(err instanceof Error ? err.message : 'Failed to load threat intel data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load(filters);
  }, [serverFilterKey]);

  useEffect(() => {
    window.history.replaceState(
      window.history.state,
      '',
      `/threats${buildSearchFromFilters(filters)}`,
    );
  }, [filters]);

  const items = useMemo(() => filterThreatItems(rawItems, filters), [filters, rawItems]);

  const availableFeeds = useMemo(() => {
    const values = new Set<string>();
    for (const item of rawItems) {
      for (const hit of item.feed_hits) {
        values.add(hit.feed);
      }
    }
    for (const feed of feedStatus?.feeds ?? []) {
      values.add(feed.feed);
    }
    return Array.from(values).sort();
  }, [feedStatus, rawItems]);

  const availableSourceGroups = useMemo(
    () => Array.from(new Set(rawItems.map((item) => item.source_group))).sort(),
    [rawItems],
  );

  const updateFilters = (patch: Partial<ThreatFilters>) => {
    setFilters((current) => ({ ...current, ...patch }));
  };

  return {
    items,
    rawItems,
    feedStatus,
    filters,
    availableFeeds,
    availableSourceGroups,
    loading,
    error,
    partial,
    nodeErrors,
    nodesQueried,
    nodesResponded,
    load: () => load(filters),
    updateFilters,
  };
}
