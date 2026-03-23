import React from 'react';

import type { PolicyCreateRequest } from '../../../types';
import type { SetDraft } from './formTypes';

interface PolicyBasicsSectionProps {
  draft: PolicyCreateRequest;
  setDraft: SetDraft;
}

export const PolicyBasicsSection: React.FC<PolicyBasicsSectionProps> = ({ draft, setDraft }) => (
  <div className="grid grid-cols-1 gap-4">
    <div>
      <label className="block text-xs mb-1 uppercase tracking-[0.22em]" style={{ color: 'var(--text-muted)' }}>
        Enforcement Mode
      </label>
      <select
        value={draft.mode}
        onChange={(e) =>
          setDraft((prev) => ({
            ...prev,
            mode: e.target.value as PolicyCreateRequest['mode'],
          }))
        }
        className="w-full px-3.5 py-3 rounded-xl text-sm"
        style={{
          background: 'var(--bg-input)',
          border: '1px solid var(--border-subtle)',
          color: 'var(--text)',
        }}
      >
        <option value="enforce">enforce</option>
        <option value="audit">audit</option>
        <option value="disabled">disabled</option>
      </select>
      <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
        Enforce blocks traffic by rule decisions. Audit records deny outcomes but still allows traffic.
      </p>
    </div>
    <div>
      <label className="block text-xs mb-1 uppercase tracking-[0.22em]" style={{ color: 'var(--text-muted)' }}>
        Global Fallback Action
      </label>
      <select
        value={draft.policy.default_policy ?? 'deny'}
        onChange={(e) =>
          setDraft((prev) => ({
            ...prev,
            policy: {
              ...prev.policy,
              default_policy: e.target.value as 'allow' | 'deny',
            },
          }))
        }
        className="w-full px-3.5 py-3 rounded-xl text-sm"
        style={{
          background: 'var(--bg-input)',
          border: '1px solid var(--border-subtle)',
          color: 'var(--text)',
        }}
      >
        <option value="deny">deny</option>
        <option value="allow">allow</option>
      </select>
      <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
        Used only when no source group or rule yields a decision.
      </p>
    </div>
    <div
      className="rounded-xl p-3 text-xs leading-6"
      style={{
        border: '1px solid var(--border-subtle)',
        color: 'var(--text-muted)',
        background: 'var(--bg-glass-subtle)',
      }}
    >
      Effective decision path: rule action -&gt; group fallback -&gt; global fallback -&gt; audit override
    </div>
  </div>
);
