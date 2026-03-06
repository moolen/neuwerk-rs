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
    className="rounded-xl overflow-hidden"
    style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-glass)' }}
  >
    <div
      className="px-4 py-3 text-sm font-semibold"
      style={{ color: 'var(--text-secondary)', borderBottom: '1px solid var(--border-glass)' }}
    >
      Policies
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
