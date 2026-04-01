import React from 'react';

import type { PolicyCreateRequest } from '../../../types';
import type { SetDraft } from './formTypes';

interface PolicyBasicsSectionProps {
  draft: PolicyCreateRequest;
  setDraft: SetDraft;
}

const chipBaseStyle: React.CSSProperties = {
  background: 'var(--bg)',
  color: 'var(--text-muted)',
  border: '1px solid var(--border-subtle)',
};

export const PolicyBasicsSection: React.FC<PolicyBasicsSectionProps> = ({ draft, setDraft }) => (
  <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
    <div
      className="rounded-xl p-3 text-xs leading-6"
      style={{
        border: '1px solid var(--border-subtle)',
        color: 'var(--text-muted)',
        background: 'var(--bg-glass-subtle)',
      }}
    >
      <div className="text-xs mb-1 uppercase tracking-[0.22em]">Always-active singleton policy</div>
      <p>
        The top-level policy mode is gone. Use each source group&apos;s mode as the default rollout
        posture, and override specific rules only when they need stricter or softer handling.
      </p>
    </div>
    <div className="space-y-2">
      <label className="block text-xs mb-1 uppercase tracking-[0.22em]" style={{ color: 'var(--text-muted)' }}>
        Global Fallback Action
      </label>
      <div className="flex flex-wrap gap-2">
        {(['deny', 'allow'] as const).map((action) => {
          const selected = (draft.policy.default_policy ?? 'deny') === action;
          const selectedStyle =
            action === 'allow'
              ? {
                  background: 'var(--green-bg)',
                  color: 'var(--green)',
                  border: '1px solid var(--green-border)',
                }
              : {
                  background: 'var(--red-bg)',
                  color: 'var(--red)',
                  border: '1px solid var(--red-border)',
                };

          return (
            <button
              key={action}
              type="button"
              aria-pressed={selected}
              onClick={() =>
                setDraft((prev) => ({
                  ...prev,
                  policy: {
                    ...prev.policy,
                    default_policy: action,
                  },
                }))
              }
              className="px-3 py-1.5 rounded-xl text-sm font-medium capitalize"
              style={selected ? selectedStyle : chipBaseStyle}
            >
              {action}
            </button>
          );
        })}
      </div>
      <p className="text-xs mt-1" style={{ color: 'var(--text-muted)' }}>
        Used only when no source group or rule yields a decision.
      </p>
    </div>
    <div
      className="rounded-xl p-3 text-xs leading-6 sm:col-span-2"
      style={{
        border: '1px solid var(--border-subtle)',
        color: 'var(--text-muted)',
        background: 'var(--bg-glass-subtle)',
      }}
    >
      Effective decision path: source-group mode -&gt; optional rule mode override -&gt; rule action
      or group fallback -&gt; global fallback
    </div>
  </div>
);
