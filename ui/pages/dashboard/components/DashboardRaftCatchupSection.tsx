import React from 'react';
import type { ClusterStats } from '../../../types';
import { formatNumber } from '../helpers';
import { DashboardSectionCard } from './DashboardSectionCard';

interface DashboardRaftCatchupSectionProps {
  cluster: ClusterStats;
}

export const DashboardRaftCatchupSection: React.FC<DashboardRaftCatchupSectionProps> = ({
  cluster,
}) => (
  <DashboardSectionCard
    title="Raft Catch-up"
    description="Follower replication lag and catch-up status across the cluster."
  >
    {!cluster.nodes.length ? (
      <div className="text-sm" style={{ color: 'var(--text-muted)' }}>
        Cluster node details unavailable.
      </div>
    ) : (
      <div className="overflow-x-auto">
        <table className="min-w-full text-sm">
          <thead>
            <tr style={{ color: 'var(--text-muted)' }}>
              <th className="text-left pb-2 pr-3">Node ID</th>
              <th className="text-left pb-2 pr-3">Role</th>
              <th className="text-left pb-2 pr-3">Address</th>
              <th className="text-left pb-2 pr-3">Matched Index</th>
              <th className="text-left pb-2 pr-3">Lag</th>
              <th className="text-left pb-2">Status</th>
            </tr>
          </thead>
          <tbody>
            {cluster.nodes.map((node) => (
              <tr
                key={node.node_id}
                style={{
                  color: 'var(--text)',
                  borderTop: '1px solid var(--border-glass-subtle, var(--border-glass))',
                }}
              >
                <td className="py-3 pr-3 font-mono">{node.node_id}</td>
                <td className="py-2 pr-3">{node.role}</td>
                <td className="py-2 pr-3 font-mono">{node.addr}</td>
                <td className="py-2 pr-3">
                  {node.matched_index == null ? 'n/a' : formatNumber(node.matched_index)}
                </td>
                <td className="py-2 pr-3">
                  {node.lag_entries == null ? 'n/a' : formatNumber(node.lag_entries)}
                </td>
                <td className="py-2">
                  {node.caught_up ? (
                    <span
                      className="inline-flex px-2.5 py-1 rounded-full text-xs font-semibold"
                      style={{ color: 'var(--green)', background: 'var(--green-bg)', border: '1px solid var(--green-border)' }}
                    >
                      caught up
                    </span>
                  ) : (
                    <span
                      className="inline-flex px-2.5 py-1 rounded-full text-xs font-semibold"
                      style={{ color: 'var(--red)', background: 'var(--red-bg)', border: '1px solid var(--red-border)' }}
                    >
                      lagging
                    </span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    )}
  </DashboardSectionCard>
);
