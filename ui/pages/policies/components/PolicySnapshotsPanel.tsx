import React from 'react';

import type { PolicyRecord } from '../../../types';
import { PolicySnapshotRow } from './PolicySnapshotRow';

interface PolicySnapshotsPanelProps {
  loading: boolean;
  policies: PolicyRecord[];
  selectedId: string | null;
  onSelect: (id: string) => void;
  onDelete: (id: string) => void;
}

export const PolicySnapshotsPanel: React.FC<PolicySnapshotsPanelProps> = ({
  loading,
  policies,
  selectedId,
  onSelect,
  onDelete,
}) => (
  <div
    className="rounded-[1.5rem] overflow-hidden"
    style={{
      background: 'linear-gradient(180deg, var(--bg-glass-strong), rgba(255,255,255,0.04))',
      border: '1px solid var(--border-glass)',
      boxShadow: 'var(--shadow-glass)',
    }}
  >
    <div
      className="px-4 py-4"
      style={{ color: 'var(--text-secondary)', borderBottom: '1px solid var(--border-glass)' }}
    >
      <div className="text-xs uppercase tracking-[0.24em]" style={{ color: 'var(--text-muted)' }}>
        Policies
      </div>
      <div className="mt-1 text-sm font-semibold" style={{ color: 'var(--text)' }}>
        Snapshot rail
      </div>
      <div className="mt-1 text-sm" style={{ color: 'var(--text-secondary)' }}>
        Jump between saved policies and reopen an editor target without losing context.
      </div>
    </div>
    {loading ? (
      <div className="p-6 text-sm" style={{ color: 'var(--text-muted)' }}>
        Loading policies...
      </div>
    ) : policies.length === 0 ? (
      <div className="p-6 text-sm" style={{ color: 'var(--text-muted)' }}>
        No policies found.
      </div>
    ) : (
      <div className="divide-y" style={{ borderColor: 'var(--border-glass)' }}>
        {policies.map((policy) => (
          <PolicySnapshotRow
            key={policy.id}
            policy={policy}
            selectedId={selectedId}
            onSelect={onSelect}
            onDelete={onDelete}
          />
        ))}
      </div>
    )}
  </div>
);
