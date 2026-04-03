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
  <div className="space-y-4">
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
    <p className="text-xs leading-6" style={{ color: 'var(--text-muted)' }}>
      Effective decision path: source-group mode → optional rule mode override → rule action or group fallback → global fallback
    </p>
  </div>
);
