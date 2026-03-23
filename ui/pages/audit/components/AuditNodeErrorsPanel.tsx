import React from 'react';

interface AuditNodeErrorsPanelProps {
  nodeErrors: Array<{ node_id: string; error: string }>;
}

export const AuditNodeErrorsPanel: React.FC<AuditNodeErrorsPanelProps> = ({ nodeErrors }) => {
  if (nodeErrors.length === 0) return null;
  return (
    <div
      className="rounded-[1.2rem] p-4 space-y-3"
      style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-glass)', boxShadow: 'var(--shadow-glass)' }}
    >
      <div>
        <div className="text-sm font-semibold" style={{ color: 'var(--text)' }}>
          Node errors
        </div>
        <div className="mt-1 text-xs" style={{ color: 'var(--text-muted)' }}>
          Some cluster members did not return a clean audit response for this refresh.
        </div>
      </div>
      <div className="space-y-2">
        {nodeErrors.map((entry, idx) => (
          <div
            key={`${entry.node_id}-${idx}`}
            className="rounded-xl p-3 text-xs font-mono"
            style={{ color: 'var(--text-muted)', background: 'var(--bg-glass-subtle)', border: '1px solid var(--border-glass)' }}
          >
            {entry.node_id}: {entry.error}
          </div>
        ))}
      </div>
    </div>
  );
};
