import React from 'react';
import type { StatsResponse } from '../../../types';
import { DashboardBytesSection } from './DashboardBytesSection';
import { DashboardControlPlaneSection } from './DashboardControlPlaneSection';
import { DashboardDataplaneSection } from './DashboardDataplaneSection';
import { DashboardOverviewCards } from './DashboardOverviewCards';
import { DashboardRaftCatchupSection } from './DashboardRaftCatchupSection';
import { DashboardSystemSection } from './DashboardSystemSection';

interface DashboardStatsViewProps {
  stats: StatsResponse;
}

export const DashboardStatsView: React.FC<DashboardStatsViewProps> = ({ stats }) => {
  const followerSummary =
    stats.cluster.follower_count === 0
      ? 'Standalone node'
      : `${stats.cluster.followers_caught_up}/${stats.cluster.follower_count} followers caught up`;

  return (
    <div className="space-y-6">
      <section
        className="rounded-[1.5rem] p-5 space-y-4"
        style={{
          background: 'var(--bg-glass)',
          border: '1px solid var(--border-glass)',
          boxShadow: 'var(--shadow-glass)',
        }}
      >
        <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
          <div>
            <div className="text-[11px] uppercase tracking-[0.26em]" style={{ color: 'var(--text-muted)' }}>
              Cluster posture
            </div>
            <h2 className="mt-2 text-lg font-semibold" style={{ color: 'var(--text)' }}>
              Health signals across dataplane and replication
            </h2>
            <p className="mt-1 text-sm max-w-[44rem]" style={{ color: 'var(--text-secondary)' }}>
              Start with overall concurrency, leadership, and follower state before drilling into subsystem counters.
            </p>
          </div>
          <div
            className="self-start px-3 py-2 rounded-[1rem] text-sm"
            style={{ background: 'var(--bg-glass-subtle)', border: '1px solid var(--border-glass)', color: 'var(--text-secondary)' }}
          >
            {stats.cluster.is_leader ? 'This node is leader' : 'Follower observing cluster state'}
          </div>
        </div>

        <div className="flex flex-wrap gap-2">
          <span
            className="px-2.5 py-1 rounded-full text-xs font-semibold"
            style={{ color: 'var(--text-secondary)', background: 'var(--bg-glass-subtle)', border: '1px solid var(--border-glass)' }}
          >
            Nodes: {stats.cluster.node_count}
          </span>
          <span
            className="px-2.5 py-1 rounded-full text-xs font-semibold"
            style={{ color: 'var(--text-secondary)', background: 'var(--bg-glass-subtle)', border: '1px solid var(--border-glass)' }}
          >
            {followerSummary}
          </span>
          <span
            className="px-2.5 py-1 rounded-full text-xs font-semibold"
            style={{ color: 'var(--text-secondary)', background: 'var(--bg-glass-subtle)', border: '1px solid var(--border-glass)' }}
          >
            DHCP lease {stats.dhcp.lease_active ? 'active' : 'inactive'}
          </span>
          <span
            className="px-2.5 py-1 rounded-full text-xs font-semibold"
            style={{ color: 'var(--text-secondary)', background: 'var(--bg-glass-subtle)', border: '1px solid var(--border-glass)' }}
          >
            NAT port use {(stats.dataplane.nat_port_utilization * 100).toFixed(1)}%
          </span>
        </div>
      </section>

      <section className="space-y-4">
        <div className="space-y-1">
          <div className="text-[11px] uppercase tracking-[0.24em]" style={{ color: 'var(--text-muted)' }}>
            Traffic and policy
          </div>
          <h2 className="text-lg font-semibold" style={{ color: 'var(--text)' }}>
            Fast operational counters
          </h2>
        </div>
        <DashboardOverviewCards dataplane={stats.dataplane} dns={stats.dns} />
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <DashboardDataplaneSection dataplane={stats.dataplane} />
          <DashboardBytesSection dataplane={stats.dataplane} />
        </div>
      </section>

      <section className="space-y-4">
        <div className="space-y-1">
          <div className="text-[11px] uppercase tracking-[0.24em]" style={{ color: 'var(--text-muted)' }}>
            Control-plane state
          </div>
          <h2 className="text-lg font-semibold" style={{ color: 'var(--text)' }}>
            DNS, TLS, DHCP, and leadership signals
          </h2>
        </div>
        <DashboardControlPlaneSection
          dns={stats.dns}
          tls={stats.tls}
          dhcp={stats.dhcp}
          cluster={stats.cluster}
        />
      </section>

      <section className="space-y-4">
        <div className="space-y-1">
          <div className="text-[11px] uppercase tracking-[0.24em]" style={{ color: 'var(--text-muted)' }}>
            Replication and system
          </div>
          <h2 className="text-lg font-semibold" style={{ color: 'var(--text)' }}>
            Consensus progress and node catch-up
          </h2>
        </div>
        <div className="grid grid-cols-1 xl:grid-cols-[minmax(18rem,24rem)_minmax(0,1fr)] gap-6">
          <DashboardSystemSection cluster={stats.cluster} />
          <DashboardRaftCatchupSection cluster={stats.cluster} />
        </div>
      </section>
    </div>
  );
};
