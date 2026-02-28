import React, { useEffect, useMemo, useState } from 'react';
import { getAuditFindings } from '../services/api';
import type { AuditFinding, AuditFindingType } from '../types';

const FINDING_TYPES: AuditFindingType[] = ['dns_deny', 'l4_deny', 'tls_deny', 'icmp_deny'];

export const AuditPage: React.FC = () => {
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

  const filtered = useMemo(() => {
    return items;
  }, [items]);

  const formatTimestamp = (ts: number): string => new Date(ts * 1000).toLocaleString();

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold" style={{ color: 'var(--text)' }}>Audit</h1>
        <p className="text-sm mt-1" style={{ color: 'var(--text-muted)' }}>
          Persisted policy deny findings (cluster-aggregated, deduplicated).
        </p>
      </div>

      <div className="rounded-xl p-4 grid grid-cols-1 md:grid-cols-5 gap-3" style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-glass)' }}>
        <select
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value as AuditFindingType | 'all')}
          className="rounded-lg px-3 py-2 text-sm"
          style={{ background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
        >
          <option value="all">All types</option>
          {FINDING_TYPES.map((t) => (
            <option key={t} value={t}>{t}</option>
          ))}
        </select>
        <input
          value={sourceGroup}
          onChange={(e) => setSourceGroup(e.target.value)}
          placeholder="Source group"
          className="rounded-lg px-3 py-2 text-sm"
          style={{ background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
        />
        <input
          value={policyId}
          onChange={(e) => setPolicyId(e.target.value)}
          placeholder="Policy ID"
          className="rounded-lg px-3 py-2 text-sm md:col-span-2"
          style={{ background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
        />
        <button
          onClick={load}
          disabled={loading}
          className="px-4 py-2 text-white rounded-lg font-medium"
          style={{ background: loading ? 'var(--text-muted)' : 'var(--accent)' }}
        >
          {loading ? 'Loading...' : 'Refresh'}
        </button>
      </div>

      {error && (
        <div className="rounded-lg p-4" style={{ background: 'var(--red-bg)', border: '1px solid var(--red-border)', color: 'var(--red)' }}>
          {error}
        </div>
      )}

      {partial && (
        <div className="rounded-lg p-4" style={{ background: 'var(--yellow-bg, rgba(245, 158, 11, 0.12))', border: '1px solid var(--yellow-border, rgba(245, 158, 11, 0.4))', color: 'var(--text)' }}>
          Partial results: {nodes.responded}/{nodes.queried} nodes responded.
        </div>
      )}

      {nodeErrors.length > 0 && (
        <div className="rounded-lg p-4" style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-glass)' }}>
          <div className="text-sm font-semibold mb-2" style={{ color: 'var(--text)' }}>Node Errors</div>
          <div className="space-y-1">
            {nodeErrors.map((entry, idx) => (
              <div key={`${entry.node_id}-${idx}`} className="text-xs font-mono" style={{ color: 'var(--text-muted)' }}>
                {entry.node_id}: {entry.error}
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="text-sm" style={{ color: 'var(--text-muted)' }}>
        {filtered.length} findings
      </div>

      <div className="rounded-xl overflow-x-auto" style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-glass)' }}>
        <table className="w-full">
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border-glass)' }}>
              <th className="text-left py-3 px-4 text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>Type</th>
              <th className="text-left py-3 px-4 text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>Source Group</th>
              <th className="text-left py-3 px-4 text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>Destination</th>
              <th className="text-left py-3 px-4 text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>Signals</th>
              <th className="text-left py-3 px-4 text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>Count</th>
              <th className="text-left py-3 px-4 text-sm font-medium" style={{ color: 'var(--text-secondary)' }}>Last Seen</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={6} className="py-12 text-center" style={{ color: 'var(--text-muted)' }}>
                  No audit findings yet.
                </td>
              </tr>
            ) : (
              filtered.map((item, idx) => (
                <tr key={`${item.finding_type}-${idx}`} style={{ borderBottom: '1px solid var(--border-glass-subtle, var(--border-glass))' }}>
                  <td className="py-3 px-4 text-xs font-mono" style={{ color: 'var(--text-secondary)' }}>{item.finding_type}</td>
                  <td className="py-3 px-4 text-xs" style={{ color: 'var(--text-secondary)' }}>{item.source_group}</td>
                  <td className="py-3 px-4 text-xs font-mono" style={{ color: 'var(--text-secondary)' }}>
                    {item.dst_ip ? `${item.dst_ip}${item.dst_port ? `:${item.dst_port}` : ''}` : (item.hostname || '-')}
                  </td>
                  <td className="py-3 px-4 text-xs" style={{ color: 'var(--text-muted)' }}>
                    {item.fqdn || item.sni || (item.icmp_type !== null && item.icmp_type !== undefined ? `icmp ${item.icmp_type}/${item.icmp_code ?? '-'}` : '-')}
                  </td>
                  <td className="py-3 px-4 text-xs font-mono" style={{ color: 'var(--text-secondary)' }}>{item.count}</td>
                  <td className="py-3 px-4 text-xs" style={{ color: 'var(--text-muted)' }}>{formatTimestamp(item.last_seen)}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
