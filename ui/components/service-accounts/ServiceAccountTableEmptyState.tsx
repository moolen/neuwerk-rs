import React from 'react';

export const ServiceAccountTableEmptyState: React.FC = () => (
  <div
    className="rounded-xl border p-12 text-center"
    style={{ background: 'var(--bg-glass)', borderColor: 'var(--border-glass)' }}
  >
    <p style={{ color: 'var(--text-muted)' }}>
      No service accounts yet. Click 'Create Service Account' to get started.
    </p>
  </div>
);
