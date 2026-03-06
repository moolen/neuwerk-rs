import React from 'react';
import { DashboardStatsView } from './dashboard/components/DashboardStatsView';
import { useDashboardStats } from './dashboard/useDashboardStats';

export const Dashboard: React.FC = () => {
  const { stats, error, loading } = useDashboardStats();

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div style={{ color: 'var(--text-muted)' }}>Loading...</div>
      </div>
    );
  }

  if (error || !stats) {
    return (
      <div
        className="rounded-lg p-4"
        style={{ background: 'var(--red-bg)', border: '1px solid var(--red-border)', color: 'var(--red)' }}
      >
        {error || 'Stats unavailable'}
      </div>
    );
  }

  return <DashboardStatsView stats={stats} />;
};
