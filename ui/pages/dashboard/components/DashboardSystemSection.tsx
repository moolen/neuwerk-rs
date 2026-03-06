import React from 'react';
import type { ClusterStats } from '../../../types';
import { formatNumber } from '../helpers';
import { DashboardSectionCard } from './DashboardSectionCard';

interface DashboardSystemSectionProps {
  cluster: ClusterStats;
}

export const DashboardSystemSection: React.FC<DashboardSystemSectionProps> = ({ cluster }) => (
  <DashboardSectionCard title="System" titleMarginClassName="mb-2">
    <div className="text-sm" style={{ color: 'var(--text-muted)' }}>
      Last applied log index: {formatNumber(cluster.last_applied)} • Last log index:{' '}
      {formatNumber(cluster.last_log_index)}
    </div>
  </DashboardSectionCard>
);
