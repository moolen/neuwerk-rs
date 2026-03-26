import React from 'react';

import type { PolicyRecord } from '../../../types';
import { policyDisplayName } from './policySnapshotHelpers';

interface PolicySnapshotRowProps {
  policy: PolicyRecord;
  selectedId: string | null;
  onSelect: (id: string) => void;
}

export const PolicySnapshotRow: React.FC<PolicySnapshotRowProps> = ({
  policy,
  selectedId,
  onSelect,
}) => {
  const modeBadgeStyle =
    policy.mode === 'enforce'
      ? { background: 'var(--green-bg)', color: 'var(--green)', border: '1px solid var(--green-border)' }
      : policy.mode === 'audit'
        ? { background: 'var(--amber-bg)', color: 'var(--amber)', border: '1px solid var(--amber-border)' }
        : { background: 'var(--red-bg)', color: 'var(--red)', border: '1px solid var(--red-border)' };
  const selected = selectedId === policy.id;

  return (
    <div
      className="p-4 cursor-pointer transition-colors"
      style={{
        background: selected
          ? 'linear-gradient(145deg, rgba(79,110,247,0.14), rgba(79,110,247,0.05))'
          : 'transparent',
        border: selected ? '1px solid rgba(79,110,247,0.22)' : '1px solid transparent',
        boxShadow: selected ? 'var(--shadow-glass)' : 'none',
      }}
      onClick={() => onSelect(policy.id)}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="text-sm font-semibold truncate" style={{ color: 'var(--text)' }}>
            {policyDisplayName(policy)}
          </div>
        </div>
        <div
          className="text-xs px-2.5 py-1 rounded-full font-semibold capitalize border shrink-0"
          style={modeBadgeStyle}
        >
          {policy.mode}
        </div>
      </div>
    </div>
  );
};
