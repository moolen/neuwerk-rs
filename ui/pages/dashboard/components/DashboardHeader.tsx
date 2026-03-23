import React from 'react';

export const DashboardHeader: React.FC = () => (
  <div
    className="rounded-full px-3 py-1.5 text-xs font-medium flex items-center gap-2"
    style={{
      color: 'var(--text-muted)',
      background: 'var(--bg-input)',
      border: '1px solid var(--border-subtle)',
    }}
  >
    <span
      className="inline-block w-2 h-2 rounded-full"
      style={{ background: 'var(--green)' }}
    />
    Updated every 5s
  </div>
);
