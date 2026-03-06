import React from 'react';

export const StringListMapEmptyState: React.FC = () => (
  <div
    className="text-xs py-2 px-2 rounded"
    style={{ color: 'var(--text-muted)', border: '1px dashed var(--border-subtle)' }}
  >
    No entries configured.
  </div>
);
