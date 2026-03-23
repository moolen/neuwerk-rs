import React from 'react';

export const SourceGroupRulesEmptyState: React.FC = () => (
  <div
    className="text-sm py-4 px-4 rounded-xl"
    style={{
      color: 'var(--text-muted)',
      border: '1px dashed var(--border-subtle)',
      background: 'var(--bg-glass-subtle)',
    }}
  >
    No rules configured. Add the first rule to define what happens after this source group matches.
  </div>
);
