import React from 'react';

interface AuditNodeErrorsPanelProps {
  nodeErrors: Array<{ node_id: string; error: string }>;
}

export const AuditNodeErrorsPanel: React.FC<AuditNodeErrorsPanelProps> = ({ nodeErrors }) => {
  if (nodeErrors.length === 0) return null;
  return (
    <div className="rounded-lg p-4" style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-glass)' }}>
      <div className="text-sm font-semibold mb-2" style={{ color: 'var(--text)' }}>
        Node Errors
      </div>
      <div className="space-y-1">
        {nodeErrors.map((entry, idx) => (
          <div key={`${entry.node_id}-${idx}`} className="text-xs font-mono" style={{ color: 'var(--text-muted)' }}>
            {entry.node_id}: {entry.error}
          </div>
        ))}
      </div>
    </div>
  );
};
