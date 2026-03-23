import { useEffect, useState } from 'react';

import { getThreatFeedStatus, getThreatFindings } from '../../services/api';
import type { ThreatFeedStatusResponse, ThreatFinding, ThreatNodeError } from '../../types';
import { buildThreatFindingsParams, createDefaultThreatFilters } from './helpers';

export function useThreatOverviewPage() {
  const [feedStatus, setFeedStatus] = useState<ThreatFeedStatusResponse | null>(null);
  const [rawItems, setRawItems] = useState<ThreatFinding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [partial, setPartial] = useState(false);
  const [nodeErrors, setNodeErrors] = useState<ThreatNodeError[]>([]);
  const [nodesQueried, setNodesQueried] = useState(0);
  const [nodesResponded, setNodesResponded] = useState(0);
  const [disabled, setDisabled] = useState(false);
  const defaultFilters = createDefaultThreatFilters('');

  const refresh = async () => {
    setLoading(true);
    setError(null);

    try {
      const [feeds, findings] = await Promise.all([
        getThreatFeedStatus(),
        getThreatFindings(buildThreatFindingsParams(defaultFilters, Date.now())),
      ]);
      setFeedStatus(feeds);
      setRawItems(findings.items);
      setPartial(findings.partial);
      setNodeErrors(findings.node_errors);
      setNodesQueried(findings.nodes_queried);
      setNodesResponded(findings.nodes_responded);
      setDisabled(Boolean(findings.disabled || feeds.disabled));
    } catch (err) {
      console.error('Failed to load threat overview data:', err);
      setError(err instanceof Error ? err.message : 'Failed to load threat overview data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void refresh();
  }, []);

  return {
    feedStatus,
    disabled,
    partial,
    nodeErrors,
    nodesQueried,
    nodesResponded,
    findingsCount: rawItems.length,
    loading,
    error,
    refresh,
  };
}
