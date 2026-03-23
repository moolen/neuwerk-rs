import { useEffect, useMemo, useState } from 'react';

import { createThreatSilence, getThreatFindings } from '../../services/api';
import type { CreateThreatSilenceRequest } from '../../services/apiClient/threats';
import type { ThreatFinding, ThreatNodeError } from '../../types';
import {
  buildThreatFindingsParams,
  createDefaultThreatFilters,
  filterThreatItems,
  type ThreatFilters,
} from './helpers';
import { buildSearchFromFilters, buildServerFilterKey } from './state';

export function useThreatFindingsPage() {
  const [rawItems, setRawItems] = useState<ThreatFinding[]>([]);
  const [filters, setFilters] = useState<ThreatFilters>(() =>
    createDefaultThreatFilters(window.location.search),
  );
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [partial, setPartial] = useState(false);
  const [nodeErrors, setNodeErrors] = useState<ThreatNodeError[]>([]);
  const [nodesQueried, setNodesQueried] = useState(0);
  const [nodesResponded, setNodesResponded] = useState(0);
  const [disabled, setDisabled] = useState(false);
  const [silenceSaving, setSilenceSaving] = useState(false);
  const serverFilterKey = buildServerFilterKey(filters);

  const load = async (activeFilters: ThreatFilters = filters) => {
    setLoading(true);
    setError(null);

    try {
      const findings = await getThreatFindings(buildThreatFindingsParams(activeFilters, Date.now()));
      setRawItems(findings.items);
      setPartial(findings.partial);
      setNodeErrors(findings.node_errors);
      setNodesQueried(findings.nodes_queried);
      setNodesResponded(findings.nodes_responded);
      setDisabled(Boolean(findings.disabled));
    } catch (err) {
      console.error('Failed to load threat findings data:', err);
      setError(err instanceof Error ? err.message : 'Failed to load threat findings data');
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
      `/threats/findings${buildSearchFromFilters(filters)}`,
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
    return Array.from(values).sort();
  }, [rawItems]);

  const availableSourceGroups = useMemo(
    () => Array.from(new Set(rawItems.map((item) => item.source_group))).sort(),
    [rawItems],
  );

  const updateFilters = (patch: Partial<ThreatFilters>) => {
    setFilters((current) => ({ ...current, ...patch }));
  };

  const createSilence = async (request: CreateThreatSilenceRequest) => {
    try {
      setSilenceSaving(true);
      setError(null);
      await createThreatSilence(request);
      await load(filters);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create threat silence');
      throw err;
    } finally {
      setSilenceSaving(false);
    }
  };

  return {
    items,
    rawItems,
    filters,
    availableFeeds,
    availableSourceGroups,
    loading,
    error,
    partial,
    nodeErrors,
    nodesQueried,
    nodesResponded,
    disabled,
    silenceSaving,
    load: () => load(filters),
    updateFilters,
    createSilence,
  };
}
