import React from 'react';
import { FINDING_TYPES } from '../constants';
import type { AuditFindingType } from '../../../types';

interface AuditFiltersPanelProps {
  typeFilter: AuditFindingType | 'all';
  sourceGroup: string;
  policyId: string;
  loading: boolean;
  disabled?: boolean;
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
  disabled = false,
  onTypeFilterChange,
  onSourceGroupChange,
  onPolicyIdChange,
  onRefresh,
}) => (
  <div
    className="rounded-[1.4rem] p-4 md:p-5 space-y-4"
    style={{ background: 'var(--bg-glass)', border: '1px solid var(--border-glass)', boxShadow: 'var(--shadow-glass)' }}
  >
    <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
      <div>
        <div className="text-sm font-semibold" style={{ color: 'var(--text)' }}>
          Refine the review queue
        </div>
        <div className="mt-1 text-xs" style={{ color: 'var(--text-muted)' }}>
          Filter persisted deny findings by type, source group, and policy before refreshing the cluster snapshot.
        </div>
      </div>
      <div className="flex flex-wrap gap-2">
        <span
          className="px-2.5 py-1 rounded-full text-xs font-semibold"
          style={{
            color: disabled ? 'var(--amber)' : 'var(--text-secondary)',
            background: disabled ? 'var(--amber-bg)' : 'var(--bg-glass-subtle)',
            border: disabled ? '1px solid var(--amber-border)' : '1px solid var(--border-glass)',
          }}
        >
          {disabled ? 'Audit unavailable' : 'Filters active'}
        </span>
      </div>
    </div>

    <div className="grid grid-cols-1 gap-3 md:grid-cols-[minmax(10rem,13rem)_minmax(11rem,15rem)_minmax(0,1fr)_auto]">
      <label className="text-sm" style={{ color: 'var(--text-secondary)' }}>
        Finding type
        <select
          value={typeFilter}
          onChange={(e) => onTypeFilterChange(e.target.value as AuditFindingType | 'all')}
          disabled={disabled}
          className="mt-1 w-full rounded-xl px-3 py-2 text-sm"
          style={{ background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
        >
          <option value="all">All types</option>
          {FINDING_TYPES.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>
      </label>
      <label className="text-sm" style={{ color: 'var(--text-secondary)' }}>
        Source group
        <input
          value={sourceGroup}
          onChange={(e) => onSourceGroupChange(e.target.value)}
          disabled={disabled}
          placeholder="homenet"
          className="mt-1 w-full rounded-xl px-3 py-2 text-sm"
          style={{ background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
        />
      </label>
      <label className="text-sm" style={{ color: 'var(--text-secondary)' }}>
        Policy ID
        <input
          value={policyId}
          onChange={(e) => onPolicyIdChange(e.target.value)}
          disabled={disabled}
          placeholder="policy-uuid"
          className="mt-1 w-full rounded-xl px-3 py-2 text-sm"
          style={{ background: 'var(--bg-input)', border: '1px solid var(--border-subtle)', color: 'var(--text)' }}
        />
      </label>
      <button
        onClick={onRefresh}
        disabled={loading || disabled}
        className="px-4 py-2 text-white rounded-xl font-medium self-end"
        style={{ background: loading || disabled ? 'var(--text-muted)' : 'var(--accent)' }}
      >
        {loading ? 'Loading...' : 'Refresh'}
      </button>
    </div>
  </div>
);
