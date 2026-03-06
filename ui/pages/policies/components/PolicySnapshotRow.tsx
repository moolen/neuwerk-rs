import React from 'react';

import type { PolicyRecord } from '../../../types';
import {
  policyDisplayName,
  policyHasDpi,
  policyRuleCount,
  snapshotShortId,
  summarizePolicyDestinations,
  summarizePolicySources,
} from './policySnapshotHelpers';

interface PolicySnapshotRowProps {
  policy: PolicyRecord;
  selectedId: string | null;
  onSelect: (id: string) => void;
  onDelete: (id: string) => void;
}

export const PolicySnapshotRow: React.FC<PolicySnapshotRowProps> = ({
  policy,
  selectedId,
  onSelect,
  onDelete,
}) => {
  const modeBadgeStyle =
    policy.mode === 'enforce'
      ? { background: 'var(--green-bg)', color: 'var(--green)', border: '1px solid var(--green-border)' }
      : policy.mode === 'audit'
        ? { background: 'var(--amber-bg)', color: 'var(--amber)', border: '1px solid var(--amber-border)' }
        : { background: 'var(--red-bg)', color: 'var(--red)', border: '1px solid var(--red-border)' };
  const ruleCount = policyRuleCount(policy);
  const sourceGroupCount = policy.policy.source_groups.length;
  const sourceSummary = summarizePolicySources(policy);
  const targetSummary = summarizePolicyDestinations(policy);
  const hasDpi = policyHasDpi(policy);

  return (
    <div
      className="p-4 cursor-pointer"
      style={{
        background: selectedId === policy.id ? 'var(--bg-glass-strong)' : 'transparent',
      }}
      onClick={() => onSelect(policy.id)}
    >
      <div className="flex items-center justify-between">
        <div>
          <div className="text-sm font-semibold" style={{ color: 'var(--text)' }}>
            {policyDisplayName(policy)}
          </div>
          <div className="text-xs" style={{ color: 'var(--text-muted)' }}>
            id {snapshotShortId(policy.id)}
          </div>
        </div>
        <div
          className="text-xs px-2.5 py-1 rounded-full font-semibold capitalize border"
          style={modeBadgeStyle}
        >
          {policy.mode}
        </div>
      </div>
      <div className="mt-3 flex flex-wrap gap-2 text-xs">
        <div
          className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full border"
          style={{ background: 'var(--accent-light)', color: 'var(--accent)', borderColor: 'var(--border-subtle)' }}
        >
          <span className="font-semibold">Groups</span>
          <span>{sourceGroupCount}</span>
        </div>
        <div
          className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full border"
          style={{ background: 'var(--bg-input)', color: 'var(--text-secondary)', borderColor: 'var(--border-subtle)' }}
        >
          <span className="font-semibold">Rules</span>
          <span>{ruleCount}</span>
        </div>
        <div
          className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full border"
          style={
            hasDpi
              ? { background: 'var(--green-bg)', color: 'var(--green)', borderColor: 'var(--green-border)' }
              : { background: 'var(--red-bg)', color: 'var(--red)', borderColor: 'var(--red-border)' }
          }
        >
          <span className="font-semibold">DPI</span>
          <span>{hasDpi ? 'on' : 'off'}</span>
        </div>
        <div
          className="inline-flex min-w-0 max-w-full items-center gap-1 px-2.5 py-1 rounded-full border"
          style={{ background: 'var(--purple-light)', color: 'var(--purple)', borderColor: 'var(--border-subtle)' }}
          title={sourceSummary}
        >
          <span className="font-semibold shrink-0">Sources</span>
          <span className="truncate">{sourceSummary}</span>
        </div>
        <div
          className="inline-flex min-w-0 max-w-full items-center gap-1 px-2.5 py-1 rounded-full border"
          style={{ background: 'var(--amber-bg)', color: 'var(--amber)', borderColor: 'var(--amber-border)' }}
          title={targetSummary}
        >
          <span className="font-semibold shrink-0">Targets</span>
          <span className="truncate">{targetSummary}</span>
        </div>
      </div>
      <div className="mt-3 flex items-center gap-2">
        <button
          onClick={(e) => {
            e.stopPropagation();
            onSelect(policy.id);
          }}
          className="px-2 py-1 text-xs rounded-lg"
          style={{ background: 'var(--bg-input)', color: 'var(--text-secondary)' }}
        >
          Edit
        </button>
        <button
          onClick={(e) => {
            e.stopPropagation();
            onDelete(policy.id);
          }}
          className="px-2 py-1 text-xs rounded-lg"
          style={{ background: 'var(--red-bg)', color: 'var(--red)' }}
        >
          Delete
        </button>
      </div>
    </div>
  );
};
