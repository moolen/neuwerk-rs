import { useEffect, useState } from 'react';
import { getAuditFindings } from '../../services/api';
import type { AuditFinding, AuditFindingType } from '../../types';

export function useAuditPage() {
  const [items, setItems] = useState<AuditFinding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [partial, setPartial] = useState(false);
  const [nodes, setNodes] = useState<{ queried: number; responded: number }>({ queried: 0, responded: 0 });
  const [nodeErrors, setNodeErrors] = useState<Array<{ node_id: string; error: string }>>([]);
  const [typeFilter, setTypeFilter] = useState<AuditFindingType | 'all'>('all');
  const [sourceGroup, setSourceGroup] = useState('');
  const [policyId, setPolicyId] = useState('');

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await getAuditFindings({
        finding_type: typeFilter === 'all' ? [] : [typeFilter],
        source_group: sourceGroup.trim() ? [sourceGroup.trim()] : [],
        policy_id: policyId.trim() || undefined,
        limit: 1000,
      });
      setItems(response.items);
      setPartial(response.partial);
      setNodes({ queried: response.nodes_queried, responded: response.nodes_responded });
      setNodeErrors(response.node_errors ?? []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load audit findings');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load();
  }, []);

  return {
    items,
    loading,
    error,
    partial,
    nodes,
    nodeErrors,
    typeFilter,
    setTypeFilter,
    sourceGroup,
    setSourceGroup,
    policyId,
    setPolicyId,
    load,
  };
}
