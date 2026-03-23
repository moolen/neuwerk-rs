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
  const selected = selectedId === policy.id;
  const statStyle: React.CSSProperties = {
    background: 'var(--bg-glass-subtle)',
    border: '1px solid var(--border-subtle)',
  };

  return (
    <div
      className="p-4 cursor-pointer space-y-4"
      style={{
        background: selected ? 'var(--bg-glass-strong)' : 'transparent',
      }}
      onClick={() => onSelect(policy.id)}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="space-y-1 min-w-0">
          <div className="text-sm font-semibold truncate" style={{ color: 'var(--text)' }}>
            {policyDisplayName(policy)}
          </div>
          <div className="text-xs uppercase tracking-[0.2em]" style={{ color: 'var(--text-muted)' }}>
            Snapshot {snapshotShortId(policy.id)}
          </div>
        </div>
        <div
          className="text-xs px-2.5 py-1 rounded-full font-semibold capitalize border shrink-0"
          style={modeBadgeStyle}
        >
          {policy.mode}
        </div>
      </div>

      <div className="grid grid-cols-3 gap-2 text-xs">
        <div
          className="rounded-xl px-3 py-2 space-y-1"
          style={{ ...statStyle, background: 'var(--accent-light)', color: 'var(--accent)' }}
        >
          <div className="uppercase tracking-[0.16em]" style={{ color: 'var(--text-muted)' }}>
            Groups
          </div>
          <div className="text-sm font-semibold">{sourceGroupCount}</div>
        </div>
        <div
          className="rounded-xl px-3 py-2 space-y-1"
          style={{ ...statStyle, color: 'var(--text-secondary)' }}
        >
          <div className="uppercase tracking-[0.16em]" style={{ color: 'var(--text-muted)' }}>
            Rules
          </div>
          <div className="text-sm font-semibold" style={{ color: 'var(--text)' }}>
            {ruleCount}
          </div>
        </div>
        <div
          className="rounded-xl px-3 py-2 space-y-1"
          style={
            hasDpi
              ? { ...statStyle, background: 'var(--green-bg)', color: 'var(--green)' }
              : { ...statStyle, background: 'var(--red-bg)', color: 'var(--red)' }
          }
        >
          <div className="uppercase tracking-[0.16em]" style={{ color: 'var(--text-muted)' }}>
            DPI
          </div>
          <div className="text-sm font-semibold">{hasDpi ? 'on' : 'off'}</div>
        </div>
      </div>

      <div className="space-y-3">
        <div
          className="rounded-xl px-3 py-2 space-y-1"
          style={{ background: 'var(--purple-light)', border: '1px solid var(--border-subtle)' }}
          title={sourceSummary}
        >
          <div className="text-xs uppercase tracking-[0.18em]" style={{ color: 'var(--text-muted)' }}>
            Source scope
          </div>
          <div className="text-sm truncate" style={{ color: 'var(--purple)' }}>
            {sourceSummary}
          </div>
        </div>
        <div
          className="rounded-xl px-3 py-2 space-y-1"
          style={{ background: 'var(--amber-bg)', border: '1px solid var(--amber-border)' }}
          title={targetSummary}
        >
          <div className="text-xs uppercase tracking-[0.18em]" style={{ color: 'var(--text-muted)' }}>
            Target profile
          </div>
          <div className="text-sm truncate" style={{ color: 'var(--amber)' }}>
            {targetSummary}
          </div>
        </div>
      </div>

      <div className="flex items-center gap-2">
        <button
          onClick={(e) => {
            e.stopPropagation();
            onSelect(policy.id);
          }}
          className="px-3 py-1.5 text-xs rounded-lg"
          style={{ background: 'var(--bg-input)', color: 'var(--text-secondary)' }}
        >
          Open
        </button>
        <button
          onClick={(e) => {
            e.stopPropagation();
            onDelete(policy.id);
          }}
          className="px-3 py-1.5 text-xs rounded-lg"
          style={{ background: 'var(--red-bg)', color: 'var(--red)' }}
        >
          Delete
        </button>
      </div>
    </div>
  );
};
