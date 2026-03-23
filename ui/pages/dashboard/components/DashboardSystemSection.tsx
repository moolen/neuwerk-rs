import React from 'react';
import type { ClusterStats } from '../../../types';
import { formatNumber } from '../helpers';
import { DashboardSectionCard } from './DashboardSectionCard';
import { Metric } from './Metric';

interface DashboardSystemSectionProps {
  cluster: ClusterStats;
}

export const DashboardSystemSection: React.FC<DashboardSystemSectionProps> = ({ cluster }) => (
  <DashboardSectionCard
    title="System"
    titleMarginClassName="mb-4"
    description="Replication progress and local state machine advancement."
  >
    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-sm">
      <Metric label="Last applied log index" value={formatNumber(cluster.last_applied)} />
      <Metric label="Last log index" value={formatNumber(cluster.last_log_index)} />
    </div>
  </DashboardSectionCard>
);
