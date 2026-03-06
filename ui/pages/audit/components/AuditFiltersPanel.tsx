import React from 'react';
import { FINDING_TYPES } from '../constants';
import type { AuditFindingType } from '../../../types';

interface AuditFiltersPanelProps {
  typeFilter: AuditFindingType | 'all';
  sourceGroup: string;
  policyId: string;
  loading: boolean;
  onTypeFilterChange: (value: AuditFindingType | 'all') => void;
  onSourceGroupChange: (value: string) => void;
  onPolicyIdChange: (value: string) => void;
  onRefresh: () => void;
}

export const AuditFiltersPanel: React.FC<AuditFiltersPanelProps> = ({
  typeFilter,
  sourceGroup,
  policyId,
  loading,
  onTypeFilterChange,
  onSourceGroupChange,
  onPolicyIdChange,
  onRefresh,
}) => (
  <div
    className="rounded-xl p-4 grid grid-cols-1 md:grid-cols-5 gap-3"
    style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-glass)' }}
  >
    <select
      value={typeFilter}
      onChange={(e) => onTypeFilterChange(e.target.value as AuditFindingType | 'all')}
      className="rounded-lg px-3 py-2 text-sm"
      style={{ background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
    >
      <option value="all">All types</option>
      {FINDING_TYPES.map((t) => (
        <option key={t} value={t}>
          {t}
        </option>
      ))}
    </select>
    <input
      value={sourceGroup}
      onChange={(e) => onSourceGroupChange(e.target.value)}
      placeholder="Source group"
      className="rounded-lg px-3 py-2 text-sm"
      style={{ background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
    />
    <input
      value={policyId}
      onChange={(e) => onPolicyIdChange(e.target.value)}
      placeholder="Policy ID"
      className="rounded-lg px-3 py-2 text-sm md:col-span-2"
      style={{ background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
    />
    <button
      onClick={onRefresh}
      disabled={loading}
      className="px-4 py-2 text-white rounded-lg font-medium"
      style={{ background: loading ? 'var(--text-muted)' : 'var(--accent)' }}
    >
      {loading ? 'Loading...' : 'Refresh'}
    </button>
  </div>
);
