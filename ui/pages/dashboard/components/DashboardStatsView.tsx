import React from 'react';
import type { StatsResponse } from '../../../types';
import { DashboardBytesSection } from './DashboardBytesSection';
import { DashboardControlPlaneSection } from './DashboardControlPlaneSection';
import { DashboardDataplaneSection } from './DashboardDataplaneSection';
import { DashboardHeader } from './DashboardHeader';
import { DashboardOverviewCards } from './DashboardOverviewCards';
import { DashboardRaftCatchupSection } from './DashboardRaftCatchupSection';
import { DashboardSystemSection } from './DashboardSystemSection';

interface DashboardStatsViewProps {
  stats: StatsResponse;
}

export const DashboardStatsView: React.FC<DashboardStatsViewProps> = ({ stats }) => {
  return (
    <div className="space-y-6">
      <DashboardHeader />
      <DashboardOverviewCards dataplane={stats.dataplane} dns={stats.dns} />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <DashboardDataplaneSection dataplane={stats.dataplane} />
        <DashboardControlPlaneSection
          dns={stats.dns}
          tls={stats.tls}
          dhcp={stats.dhcp}
          cluster={stats.cluster}
        />
      </div>

      <DashboardBytesSection dataplane={stats.dataplane} />
      <DashboardSystemSection cluster={stats.cluster} />
      <DashboardRaftCatchupSection cluster={stats.cluster} />
    </div>
  );
};
