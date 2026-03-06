import React from 'react';

export const DashboardHeader: React.FC = () => (
  <div className="flex items-center justify-between">
    <h1 className="text-2xl font-bold" style={{ color: 'var(--text)' }}>
      Dashboard
    </h1>
    <div className="text-xs" style={{ color: 'var(--text-muted)' }}>
      Updated every 5s
    </div>
  </div>
);
